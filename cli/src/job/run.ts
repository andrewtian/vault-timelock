// cli/src/job/run.ts — `vt job run <id> [--chain eth|sol|btc] --backup-eth <file> --backup-sol <file> --backup-btc <file>`: the CLI executor
// (spec §3.1, §7.3, §8; plan Task C6). It runs inside the executor sandbox (bin/vt; src/args.ts): this network's relay
// and API ports only, /dev/tty, no file writes; it reads the backup files and $VT_HOME/<network>/api.token.
// SECURITY-CRITICAL: this is where keys are decrypted and transactions signed outside the browser.
//
// In order (nothing is decrypted before step 5, nothing is signed before step 7):
//   1. stdin and /dev/tty are a terminal (vt.tty-required): the passphrase comes from the terminal only;
//   2. MAINNET IS REFUSED WHILE THE JOB-SEND LOCK IS ON (C2 assertJobSendAllowed: release.mainnet-locked), before anything
//      is read; the API (every intent) and the relay (every send) enforce it again;
//   3. the job, the API and this command are on one network (executor.network-mismatch); which chains run (--chain, or
//      every chain of the job that is not settled), each with its --backup-<chain>;
//   4. each backup file is read once (vt.backup-format: a regular file, ≤ 1 MiB, the age header) BEFORE any passphrase
//      is asked;
//   5. the passphrase, from /dev/tty with no echo (readPassphrase); one entered for an earlier chain is tried first, so one
//      passphrase for both backups is asked once. core loadBackup decrypts in memory: backup.decrypt (wrong passphrase),
//      backup.chain, backup.inconsistent, backup.address-mismatch (the decrypted address is not the job's keyAddress);
//   6. the backup's network (R71): another network than the job's is REFUSED (backup.network); a prototype backup that
//      records none needs the word `again` typed at the terminal (else backup.network);
//   7. E3's executor per chain (createExecutor, holder 'cli', the node adapter's clock and CSPRNG): the network and key
//      checks, the lease (a second executor gets lease.held), reconcile-first, honest worst-case fees, the declared
//      nonce / blockhash every ticket binds (q, f), Stop between parts, positive-evidence reconcile — all core's.
//
// Before step 1 (review m-4): no debugger can reach this process (vt.inspector): bin/vt starts it as
// `node --disable-sigusr1` (so SIGUSR1 never opens an inspector), and any other node option, NODE_OPTIONS or an open
// inspector refuses before anything is read.
//
// While it runs: one progress line per change of a chain's view (phase, copy, part; the countdown as M:SS), and the
// job's journal events (SSE) through C4's printer (IP literals redacted, terminal control sequences escaped). Keys:
//   · `s` during the countdown: Skip (POST /jobs/<id>/skip, every chain of the job), asked once;
//   · Ctrl-C (or SIGINT / SIGTERM / SIGHUP from outside): requestStop() on every executor — "stopping after the in-flight
//     transaction…". Ctrl-C DETACHES (controller ruling R79): each chain lets its in-flight transaction resolve, signs nothing new,
//     journals nothing final (no `stopped`: the job keeps running, and the next `vt job run` or Run here continues it), and vt
//     exits only once EVERY outcome is settled. `vt job stop` is what stops the job. A second Ctrl-C prints a warning and changes
//     nothing. Two things end the process with a
//     transaction in flight: a SIGKILL, and the last resort below (an uncaught exception or unhandled rejection); the
//     next holder then reconciles it from the chain before anything new (nothing is sent twice).
// Keys are dropped (the SOL secret bytes zeroed, every reference released) when the command returns or throws, and by
// the last resort. A SIGKILL, or SIGINT / SIGTERM / SIGHUP while a prompt is open before the executors start (nothing is
// in flight then), end the process without it: the OS frees its memory. JavaScript strings (the passphrase, the ETH
// key's hex inside viem's account, the BTC key's secret hex) cannot be wiped; they die with the process.
// ★ Never printed, logged or stored by vt: a key (hex or base58), a passphrase, decrypted backup bytes, an IP. Every line
//   vt prints passes C4's printer and a last check against the loaded keys' secret text (withheld if it were ever
//   there); an error vt did not expect is never printed as such (the last resort prints a fixed line instead).
import type { Chain, ChainRunView, JobDef, JobState, JournalClient, Network, RelayClient, RunOutcome } from '@vault-timelock/core/contracts'
import { PORTS, isRefusal, refuse } from '@vault-timelock/core/contracts'
import { createExecutor, httpJournalClient, httpRelayClient } from '@vault-timelock/core/executor'
import type { ExecutorKey, Fetch } from '@vault-timelock/core/executor'
import { nodeAdapter } from '@vault-timelock/core/executor/node'
import { loadBackup } from '@vault-timelock/core/gates/backup.ts'
import { NETWORK } from '@vault-timelock/core/chains/constants.js'
import { assertJobSendAllowed } from 'vt-broadcast/src/config.ts'
import { request } from 'node:http'
import { url as inspectorUrl } from 'node:inspector'
import { basename, resolve } from 'node:path'
import { Readable } from 'node:stream'
import { UsageError } from '../args.ts'
import { readKeyBackup } from '../ops/backup.ts'
import { assertNetworks } from './arm.ts'
import type { JobIo } from './client.ts'
import { assertTerminal, chainArg, jobIdArg, parseFlags, printLines, readApiToken } from './client.ts'
import { renderEvent } from './status.ts'
import type { Key, Signals, TtyIo } from './tty.ts'
import { STOP_SIGNALS, processSignals, processTty } from './tty.ts'

const USAGE = 'usage: vt job run <id> [--chain eth|sol|btc] --backup-eth <file> --backup-sol <file> --backup-btc <file>  (a backup for each chain that runs)'
const CHAINS: readonly Chain[] = ['eth', 'sol', 'btc']

// Test seams (src/main.ts never passes any; the stub and the in-process tests do).
export interface RunDeps {
  tty?: TtyIo                                                          // default: /dev/tty (processTty)
  signals?: Signals                                                    // default: the process
  assertSendAllowed?: (n: Network) => void                             // default: C2's assertJobSendAllowed
  token?: string                                                       // default: $VT_HOME/<network>/api.token
  clients?: (token: string) => { journal: JournalClient; relay: RelayClient } // default: HTTP over this network's ports
  adapter?: { clock: { now(): number; sleep(ms: number): Promise<void> }; random: { int(maxExclusive: number): number } }
  poll?: number
  passiveWaitMs?: number
  onKey?: (k: ExecutorKey) => void                                    // tests: each key as it is loaded (to see it dropped)
  proc?: ProcFacts                                                     // default: this process (processFacts; vt.inspector)
  faults?: Faults                                                      // default: the process (the last resort)
  // TEST-ONLY fault hook (review m-1): called once the keys are loaded ('keys') and after each intent this run journaled
  // ('intent'); the job stub's own hook throws from there. Refused unless NODE_ENV=test (vt.test-fault).
  fault?: (at: FaultPoint) => void
}

// ---- no debugger can reach a key (review m-4)

// What vt.inspector checks. bin/vt starts node under env -i as `node --disable-sigusr1 src/main.ts`: SIGUSR1 then never
// opens an inspector (Node's default does, on a loopback port, for any process that can signal this one). So: exactly
// that one node option (no --inspect*, --debug*, preload or anything else), no NODE_OPTIONS at all, and no inspector
// already open.
export interface ProcFacts { execArgv: readonly string[]; nodeOptions: string | undefined; inspector: string | undefined }
export const NODE_FLAGS: readonly string[] = ['--disable-sigusr1', '--no-addons']
export const processFacts = (): ProcFacts => ({ execArgv: [...process.execArgv], nodeOptions: process.env.NODE_OPTIONS, inspector: inspectorUrl() })
export function assertNoInspector(f: ProcFacts): void {
  const ok = f.execArgv.length === NODE_FLAGS.length && NODE_FLAGS.every((x, i) => f.execArgv[i] === x) && f.nodeOptions === undefined && f.inspector === undefined
  if (!ok) refuse('vt.inspector', 'this command decrypts keys: it runs only as bin/vt starts it (node --disable-sigusr1, no other node option, no NODE_OPTIONS, no inspector open), so no debugger can attach to it; nothing was read') // @guard:vt.inspector
}

// ---- the test-only fault hook (review m-1)

export type FaultPoint = 'keys' | 'intent'
function assertTestFault(ok: boolean): void {
  if (!ok) refuse('vt.test-fault', 'a fault hook is for the tests only (NODE_ENV=test); vt never sets one; nothing was read') // @guard:vt.test-fault
}

// ---- the backup's network (R71)

function assertBackupNetwork(ok: boolean, why: string): void {
  if (!ok) refuse('backup.network', why) // @guard:backup.network
}

// ---- the btc lane is local only (E7b): the executor refuses it elsewhere too; vt says so before anything is read

function assertBtcLocal(ok: boolean, why: string): void {
  if (!ok) refuse('executor.chain-unsupported', why) // @guard:executor.chain-unsupported
}

// ---- loopback HTTP: this network's relay and API only

// fetch over node:http to 127.0.0.1, for the executor's clients. URLs name the network's FIXED ports (PORTS[n]), which
// is also the Host header the API and the relay require; the connection goes to `ports` (the same numbers outside the
// tests, which run a stack on ephemeral ports). Any other URL is refused. A transport error's own text (it can name an
// address) never reaches the caller: "fetch failed".
export function loopbackFetch(n: Network, ports: { api: number; relay: number }, o: { idleMs?: number } = {}): Fetch {
  const map = new Map<number, number>([[PORTS[n].api, ports.api], [PORTS[n].relay, ports.relay]])
  return (url, init) => new Promise<Response>((done, fail) => {
    let u: URL
    try { u = new URL(url) } catch { fail(new TypeError('fetch failed: not a URL')); return }
    const port = map.get(Number(u.port))
    if (u.protocol !== 'http:' || u.hostname !== '127.0.0.1' || port === undefined || u.username !== '' || u.password !== '') {
      fail(new TypeError('fetch failed: only this network\'s relay and API are reachable'))
      return
    }
    const headers: Record<string, string> = {}
    new Headers(init?.headers).forEach((v, k) => { headers[k] = v })
    headers.host = `127.0.0.1:${u.port}`
    const b = init?.body
    const body = b === undefined || b === null ? null : typeof b === 'string' ? Buffer.from(b, 'utf8') : b instanceof Uint8Array ? Buffer.from(b) : null
    if (b !== undefined && b !== null && body === null) { fail(new TypeError('fetch failed: a body vt does not send')); return }
    if (body !== null) headers['content-length'] = String(body.length)
    const signal = init?.signal ?? undefined
    if (signal?.aborted === true) { fail(new DOMException('aborted', 'AbortError')); return }
    const req = request({ host: '127.0.0.1', port, method: init?.method ?? 'GET', path: `${u.pathname}${u.search}`, headers, setHost: false, agent: false, ...(signal ? { signal } : {}) }, (res) => {
      const h = new Headers()
      for (const [k, v] of Object.entries(res.headers)) { if (typeof v === 'string') h.set(k, v); else if (Array.isArray(v)) for (const x of v) h.append(k, x) }
      const status = res.statusCode ?? 502
      done(new Response(status === 204 || status === 304 ? null : (Readable.toWeb(res) as unknown as ReadableStream<Uint8Array>), { status, headers: h }))
    })
    req.setTimeout(o.idleMs ?? 120_000, () => req.destroy(new Error('idle')))
    req.on('error', () => fail(new TypeError('fetch failed')))
    req.end(body ?? undefined)
  })
}

export function executorClients(n: Network, ports: { api: number; relay: number }, token: string): { journal: JournalClient; relay: RelayClient } {
  const f = loopbackFetch(n, ports)
  return {
    journal: httpJournalClient({ base: `http://127.0.0.1:${PORTS[n].api}`, fetch: f, token }),
    relay: httpRelayClient({ base: `http://127.0.0.1:${PORTS[n].relay}`, fetch: f }),
  }
}

// ---- output: C4's printer, plus a last check against the loaded keys' secret text

export interface Out {
  line(text: string): void                                             // stdout
  note(text: string): void                                             // stderr (prompts' context, warnings)
  forbid(k: ExecutorKey): void
  clear(): void
  scrub(text: string): string
}
const HIDDEN_LINE = '(a line was withheld: it held key material)'
// The textual forms of a key's secret that must never be printed (compared case-insensitively).
function secretForms(handle: unknown): string[] {
  const s = (handle as { secret?: unknown } | null)?.secret
  if (typeof s !== 'string' || s.length < 32) return []
  const low = s.toLowerCase()
  return low.startsWith('0x') ? [low, low.slice(2)] : [low]
}
export function printer(io: JobIo): Out {
  let secrets: string[] = []
  const scrub = (t: string): string => t.split('\n').map((l) => { const low = l.toLowerCase(); return secrets.some((s) => low.includes(s)) ? HIDDEN_LINE : l }).join('\n')
  const emit = (t: string, toErr: boolean): void => { try { printLines(io, scrub(t), toErr) } catch { /* the terminal is gone: the run goes on */ } }
  return {
    line: (t) => emit(t, false),
    note: (t) => emit(t, true),
    forbid(k) { secrets.push(...secretForms(k.handle)) },
    clear() { secrets = [] },
    scrub,
  }
}

// ---- keys: read, decrypt, check; dropped on exit

export type Keys = Map<Chain, ExecutorKey>

// Zero what can be zeroed (the SOL Keypair's secret bytes) and drop every reference. Called once every executor using
// the keys has settled (never while one runs).
export function dropKeys(keys: Keys): void {
  for (const k of keys.values()) {
    const kp = (k.handle as { kp?: { _keypair?: { secretKey?: Uint8Array } } } | null)?.kp
    try { kp?._keypair?.secretKey?.fill(0) } catch { /* nothing to zero */ }
  }
  keys.clear()
}

// What a session holds that close() and the last resort release: the loaded keys, the passphrases typed so far, the
// chains this command covers, and the chains this run journaled an intent on (or tried to: noted before the append).
export interface Held { keys: Keys; passphrases: string[]; chains: Chain[]; sent: Set<Chain> }
export type Command = 'run' | 'clawback'

// ---- the last resort (review m-1)
// An uncaught exception or an unhandled rejection while a key may be in memory. Nothing in vt or core is known to raise
// one, but Node's default would print the raw error and its stack (past the printer: an address or key text included)
// and exit with the keys as they are. Armed by openSession before anything is read or decrypted, removed by close().
// On fire, once:
//   1. the keys are dropped (the SOL secret bytes zeroed, every reference released), and the passphrases typed so far;
//   2. ONE line through the printer that says what happened: never the error's text or its stack;
//   3. for each chain: "stopped unexpectedly after sending — run `vt job run` again to reconcile (nothing will be sent
//      twice)" when this run journaled an intent on it, "did not run" only when it provably did not;
//   4. exit 1 at once. A transaction in flight is left to the chain; the next run reconciles it before anything new.
export type FaultEvent = 'uncaughtException' | 'unhandledRejection'
export interface Faults { on(ev: FaultEvent, fn: (e: unknown) => void): void; off(ev: FaultEvent, fn: (e: unknown) => void): void; exit(code: number): void }
export const processFaults: Faults = {
  on: (ev, fn) => { process.on(ev, fn) },
  off: (ev, fn) => { process.off(ev, fn) },
  exit: (code) => { process.exit(code) },
}
export const CRASH_EXIT = 1
export const afterSending = (what: Command): string => `stopped unexpectedly after sending — run \`vt job ${what}\` again to reconcile (nothing will be sent twice)`
const NOTHING_SENT = 'did not run — nothing was sent'

export function lastResort(o: { out: Out; held: Held; what: Command; faults: Faults }): () => void {
  let fired = false
  const fire = (ev: FaultEvent) => (e: unknown): void => {
    try {
      if (fired) return
      fired = true
      dropKeys(o.held.keys)
      o.held.passphrases.length = 0
      const name = e instanceof Error && /^[A-Za-z]{1,40}$/.test(e.name) ? ` (${e.name})` : ''
      o.out.note(`vt job ${o.what}: an unexpected internal error${name}, ${ev === 'uncaughtException' ? 'an uncaught exception' : 'an unhandled rejection'}, ended this process; its text is withheld (it could hold an address or key material); the keys were dropped`)
      const { chains, sent } = o.held
      if (chains.length === 0) o.out.note(sent.size > 0 ? afterSending(o.what) : NOTHING_SENT)
      for (const c of chains) o.out.note(`${c}: ${sent.has(c) ? afterSending(o.what) : NOTHING_SENT}`)
      o.out.clear()
    } finally {
      o.faults.exit(CRASH_EXIT)
    }
  }
  const onException = fire('uncaughtException'), onRejection = fire('unhandledRejection')
  o.faults.on('uncaughtException', onException)
  o.faults.on('unhandledRejection', onRejection)
  return () => {
    o.faults.off('uncaughtException', onException)
    o.faults.off('unhandledRejection', onRejection)
  }
}

export async function loadKeys(o: { io: JobIo; tty: TtyIo; out: Out; def: JobDef; jobId: string; chains: readonly Chain[]; files: Partial<Record<Chain, string>>; held: Held; onKey?: (k: ExecutorKey) => void }): Promise<Keys> {
  const { io, tty, out, def } = o
  // 4. every backup file read and checked before any passphrase is asked
  const bytes = new Map<Chain, Uint8Array>()
  for (const c of o.chains) bytes.set(c, readKeyBackup(resolve(io.cwd, o.files[c]!))) // vt.backup-format
  const keys: Keys = o.held.keys
  const tried: string[] = o.held.passphrases
  try {
    for (const c of o.chains) {
      const expect = { address: def.chains[c]!.keyAddress, network: def.network }
      let got: Awaited<ReturnType<typeof loadBackup>> | null = null
      for (const p of tried) {
        try { got = await loadBackup(bytes.get(c)!, p, c, expect); break } catch (e) { if (!(isRefusal(e) && e.guardId === 'backup.decrypt')) throw e }
      }
      if (got === null) {
        // 5. the passphrase: /dev/tty only, not echoed
        out.note(`${c}: the passphrase of the key backup ${basename(o.files[c]!)} (asked next, at the terminal)`)
        const p = await tty.passphrase(c)
        tried.push(p)
        got = await loadBackup(bytes.get(c)!, p, c, expect) // backup.decrypt, backup.chain, backup.inconsistent, backup.address-mismatch
      }
      const k: ExecutorKey = { chain: c, address: got.key.address, network: got.network, handle: got.key }
      keys.set(c, k)
      o.onKey?.(k)
      out.forbid(k)
      // 6. the backup's network
      if (got.network !== null) {
        assertBackupNetwork(got.network === def.network, `the ${c} key backup was made on ${got.network}, and job ${o.jobId} is a ${def.network} job: a key backup is never used on another network; nothing was signed`)
      } else {
        const w = await tty.word(`The ${c} key backup records no network (a backup made before networks were recorded). Type again to use it on ${def.network}: `, 'again')
        assertBackupNetwork(w === 'again', `the ${c} key backup records no network and its use on ${def.network} was not confirmed (the word again, typed at the terminal); nothing was signed`)
      }
      out.note(`${c}: key ${k.address} loaded (it stays in this process's memory only)`)
    }
  } catch (e) {
    dropKeys(keys)
    throw e
  } finally {
    tried.length = 0
    for (const b of bytes.values()) b.fill(0)
  }
  return keys
}

// ---- the session every executor command opens first (run, clawback)

// The journal as this run uses it: an intent is noted in `sent` BEFORE it is appended (an unexpected end can then tell
// "after sending" from a provable "did not run"); the test-only fault hook is called after each one.
function tracked(j: JournalClient, sent: Set<Chain>, fault: ((at: FaultPoint) => void) | undefined): JournalClient {
  return {
    status: () => j.status(),
    job: (id) => j.job(id),
    message: (sha) => j.message(sha),
    lease: (id, c, op, holder, gen) => j.lease(id, c, op, holder, gen),
    async append(id, c, gen, type, data, o) {
      const intent = type === 'intent' || type === 'clawback-intent'
      if (intent) sent.add(c)
      const r = await j.append(id, c, gen, type, data, o)
      if (intent) fault?.('intent')
      return r
    },
    ticket: (id, c, gen, txId) => j.ticket(id, c, gen, txId),
    skip: (id) => j.skip(id),
    stream: (id, from, on) => j.stream(id, from, on),
  }
}

// close(): drop the keys and passphrases, forget the printer's secrets, remove the last resort. Called once, when the
// command returns or throws (runCommand, clawbackCommand), or by openSession itself when it fails.
export interface Session { n: Network; tty: TtyIo; out: Out; journal: JournalClient; relay: RelayClient; def: JobDef; state: JobState; seq: number; held: Held; close(): void }

export async function openSession(io: JobIo, id: string, deps: RunDeps, what: Command): Promise<Session> {
  // 0. no debugger can reach this process; a fault hook only in the tests
  assertNoInspector(deps.proc ?? processFacts())
  if (deps.fault !== undefined) assertTestFault(io.env.NODE_ENV === 'test')
  const n = io.network
  const tty = deps.tty ?? processTty()
  // 1. the terminal
  assertTerminal(tty.available(), `vt job ${what} reads the key backup's passphrase from the terminal only: stdin and /dev/tty must be a terminal (never a pipe, a file, argv or the environment); nothing was read`)
  // 2. the mainnet job-send lock, before anything is read
  ;(deps.assertSendAllowed ?? ((x: Network) => { assertJobSendAllowed(x) }))(n)
  const out = printer(io)
  // the last resort, before anything is read or decrypted
  const held: Held = { keys: new Map(), passphrases: [], chains: [], sent: new Set() }
  const disarm = lastResort({ out, held, what, faults: deps.faults ?? processFaults })
  const close = (): void => { dropKeys(held.keys); held.passphrases.length = 0; out.clear(); disarm() }
  try {
    const token = deps.token ?? readApiToken(io.env, n)
    const clients = deps.clients?.(token) ?? executorClients(n, io.ports, token)
    const journal = tracked(clients.journal, held.sent, deps.fault)
    // 3. one network
    const st = await journal.status()
    assertNetworks(st.network === n, `the jobs API on the ${n} port serves ${String(st.network)}; nothing was read or signed`)
    const job = await journal.job(id)
    assertNetworks(job.def.network === n, `job ${id} is a ${String(job.def.network)} job; this is the ${n} stack (a job never runs on another network)`)
    return { n, tty, out, journal, relay: clients.relay, def: job.def, state: job.state, seq: job.seq, held, close }
  } catch (e) {
    close()
    throw e
  }
}

// ---- progress

export const mmss = (ms: number): string => { const s = Math.max(0, Math.ceil(ms / 1000)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}` }

// One chain's view as a line (progress() decides which countdown seconds are shown).
export function viewLine(c: Chain, v: ChainRunView, o: { skipHint?: boolean } = {}): string {
  if (v.phase === 'countdown' && v.startsInMs !== null) {
    return `${c}  countdown ${mmss(v.startsInMs)}${v.note ? `  ${v.note}` : ''}${o.skipHint === false ? '' : '  (s = skip the countdown, Ctrl-C = detach: nothing is stopped; vt job stop <id> stops)'}`
  }
  const at = v.copy !== null ? `  copy ${v.copy}${v.part !== null ? ` part ${v.part}${v.parts !== null ? `/${v.parts}` : ''}` : ''}` : ''
  return `${c}  ${v.phase}${at}${v.note ? `  ${v.note}` : ''}`
}

// Prints a chain's view when its phase, copy or part changes, a note at most every 5 s, the countdown every 10 s and
// each of its last 10 seconds.
export function progress(out: Out, now: () => number): (c: Chain, v: ChainRunView) => void {
  const last = new Map<Chain, { key: string; text: string; at: number; second: number | null }>()
  return (c, v) => {
    const prev = last.get(c)
    if (v.phase === 'countdown' && v.startsInMs !== null) {
      const s = Math.max(0, Math.ceil(v.startsInMs / 1000))
      if (prev?.second === s) return
      const first = prev === undefined || prev.second === null
      last.set(c, { key: 'countdown', text: '', at: now(), second: s })
      if (first || s % 10 === 0 || s <= 10) out.line(viewLine(c, v))
      return
    }
    const key = `${v.phase}|${v.copy}|${v.part}`
    const text = viewLine(c, v)
    if (prev !== undefined && prev.text === text) return
    if (prev !== undefined && prev.key === key && now() - prev.at < 5_000) return
    last.set(c, { key, text, at: now(), second: null })
    out.line(text)
  }
}

// ---- the run

const SETTLED_PHASES = new Set(['DRAINED', 'COPIES_DONE', 'STOPPED', 'CLAWED_BACK', 'DONE', 'SKIPPED'])
const GOOD: ReadonlySet<RunOutcome> = new Set<RunOutcome>(['drained', 'copies-done', 'stopped', 'clawed-back'])

interface RunArgs { id: string; chain: Chain | null; backups: Partial<Record<Chain, string>> }
function parseRunArgs(args: readonly string[]): RunArgs {
  const { flags, pos } = parseFlags(args, { valued: ['--chain', '--backup-eth', '--backup-sol', '--backup-btc'], bool: [], usage: USAGE })
  if (pos.length !== 1) throw new UsageError(USAGE)
  const id = jobIdArg(pos[0], USAGE)
  const c = flags.get('--chain')
  const backups: Partial<Record<Chain, string>> = {}
  for (const x of CHAINS) { const f = flags.get(`--backup-${x}`); if (typeof f === 'string') backups[x] = f }
  return { id, chain: c === undefined ? null : chainArg(typeof c === 'string' ? c : undefined, USAGE), backups }
}

// The interrupt / Skip handlers of a running command, and their wiring to the terminal and the signals.
export function controls(o: { out: Out; tty: TtyIo; signals: Signals; stop: () => void; skip?: () => Promise<void> | null; btc?: boolean }): () => void {
  let interrupts = 0, skipping = false, skipped = false
  const onInterrupt = (): void => {
    interrupts++
    if (interrupts === 1) {
      o.stop()
      o.out.note(`stopping after the in-flight transaction… (each chain lets the transaction it has in flight resolve, then vt detaches: nothing final is journaled, the job keeps running — run vt job run again to continue it, or vt job stop to stop it${o.btc === true ? '; a btc copy is a commit and its reveal: vt waits for the reveal of a commit that is out, never abandons it' : ''})`)
    } else {
      o.out.note('still waiting: a transaction that may land is never abandoned. vt exits once every in-flight transaction has resolved; Ctrl-C again changes nothing')
    }
  }
  const onSkip = (): void => {
    if (o.skip === undefined) return
    if (skipped) { o.out.note('Skip: already done'); return }
    if (skipping) return
    const p = o.skip()
    if (p === null) { o.out.note('Skip: only during the countdown'); return }
    skipping = true
    p.then(() => { skipped = true; o.out.note('Skip: the countdown ends now, for every chain of this job') },
      (e: unknown) => { o.out.note(`Skip refused: ${isRefusal(e) ? `${e.guardId}: ${e.message}` : 'the jobs API did not answer'}`) })
      .finally(() => { skipping = false })
  }
  const stopKeys = o.tty.keys((k: Key) => (k === 'skip' ? onSkip() : onInterrupt()))
  for (const s of STOP_SIGNALS) o.signals.on(s, onInterrupt)
  const quiet = (): void => {}
  process.stdout.on('error', quiet)
  process.stderr.on('error', quiet)
  return () => {
    stopKeys()
    for (const s of STOP_SIGNALS) o.signals.off(s, onInterrupt)
    process.stdout.off('error', quiet)
    process.stderr.off('error', quiet)
  }
}

export async function runCommand(args: readonly string[], io: JobIo, deps: RunDeps = {}): Promise<number> {
  const a = parseRunArgs(args)
  const s = await openSession(io, a.id, deps, 'run')
  try { return await runSession(a, s, io, deps) } finally { s.close() }
}

async function runSession(a: RunArgs, s: Session, io: JobIo, deps: RunDeps): Promise<number> {
  const { def, out } = s
  const defChains = CHAINS.filter((c) => def.chains[c] !== undefined)
  if (a.chain !== null && !defChains.includes(a.chain)) throw new UsageError(`job ${a.id} has no ${a.chain} chain (--chain)`)
  for (const c of CHAINS) if (a.backups[c] !== undefined && !defChains.includes(c)) throw new UsageError(`job ${a.id} has no ${c} chain (--backup-${c})`)
  const wanted = a.chain === null ? defChains : [a.chain]
  // R79 (c): a STOPPED chain whose stop latch the operator's `vt job resume` lifted is not settled: the executor reopens it.
  // M5c: the executor's own rule (executor.ts reopens): only a RESUMABLE stop (ChainState.stopClass; absent = final, fail closed)
  const reopens = (c: Chain): boolean => { const cs = s.state.chains[c]!; return cs.phase === 'STOPPED' && cs.stopLatched !== true && cs.stopRequested !== true && cs.stopClass === 'resumable' }
  const settled = wanted.filter((c) => SETTLED_PHASES.has(s.state.chains[c]!.phase) && s.state.chains[c]!.openIntents.length === 0 && !reopens(c))
  for (const c of settled) out.line(`${c}: ${s.state.chains[c]!.phase} — nothing to run${c === 'btc' ? '' : ` (claw back: vt job clawback ${a.id} --chain ${c} …)`}`)
  const chains = wanted.filter((c) => !settled.includes(c))
  if (chains.length === 0) return 0
  assertBtcLocal(!chains.includes('btc') || s.n === 'local', `the btc lane runs on the local network only (a regtest); this is the ${s.n} stack, and ${s.n} bitcoin is not supported: nothing was read or signed`)
  for (const c of chains) if (a.backups[c] === undefined) throw new UsageError(`${USAGE} (${c} runs: --backup-${c} <file> names its key backup)`)
  const regime = NETWORK[s.n] as { label: string; sub: string }
  out.line(`vt job run ${a.id} "${def.name}" on ${regime.label}: ${regime.sub}; chains ${chains.join(', ')}`)

  s.held.chains.push(...chains)
  const keys = await loadKeys({ io, tty: s.tty, out, def, jobId: a.id, chains, files: a.backups, held: s.held, ...(deps.onKey ? { onKey: deps.onKey } : {}) })
  deps.fault?.('keys')
  const execs = new Map<Chain, ReturnType<typeof createExecutor>>()
  try {
    const { clock, random } = deps.adapter ?? nodeAdapter()
    const show = progress(out, () => io.now())
    for (const c of chains) {
      execs.set(c, createExecutor({ jobId: a.id, chain: c, key: keys.get(c)!, holder: 'cli', deps: {
        journal: s.journal, relay: s.relay, clock, random, onView: (v) => show(c, v),
        ...(deps.poll !== undefined ? { poll: deps.poll } : {}), ...(deps.passiveWaitMs !== undefined ? { passiveWaitMs: deps.passiveWaitMs } : {}),
      } }))
    }
    const stopAll = (): void => { for (const e of execs.values()) e.requestStop() }
    const release = controls({ out, tty: s.tty, signals: deps.signals ?? processSignals, stop: stopAll, btc: chains.includes('btc'), skip: () => {
      const x = [...execs.values()].find((e) => e.view().phase === 'countdown')
      return x === undefined ? null : x.skip()
    } })
    // the journal as it grows (progress only: a stream that fails changes nothing)
    let unstream = (): void => {}
    try { unstream = s.journal.stream(a.id, s.seq + 1, (e) => { if (e.chain === null || chains.includes(e.chain)) out.line(renderEvent(e as unknown as Record<string, unknown>)) }) } catch { /* no stream */ }
    out.line('running: Ctrl-C detaches after the in-flight transaction (the job keeps running; vt job stop stops it); s skips the countdown')
    let results: Array<PromiseSettledResult<RunOutcome>>
    try {
      results = await Promise.allSettled(chains.map((c) => execs.get(c)!.start().catch((e: unknown) => { stopAll(); throw e })))
    } finally {
      release()
      unstream()
    }
    let refusal: unknown = null, code = 0
    chains.forEach((c, i) => {
      const r = results[i]
      const note = execs.get(c)!.view().note
      if (r.status === 'fulfilled') {
        out.line(`${c}: ${r.value}${note ? ` — ${note}` : ''}`)
        if (!GOOD.has(r.value)) code = 1
      } else {
        code = 1
        if (refusal === null && isRefusal(r.reason)) refusal = r.reason
        // review m-2: "did not run" only when this run provably journaled no intent on the chain
        const why = isRefusal(r.reason) ? `refused ${r.reason.guardId}` : out.scrub(r.reason instanceof Error ? r.reason.message : String(r.reason))
        out.line(s.held.sent.has(c) ? `${c}: ${afterSending('run')}; the error: ${why}` : `${c}: did not run — ${why}`)
      }
    })
    if (refusal !== null) throw refusal
    return code
  } finally {
    execs.clear() // the keys, the passphrases and the printer's secrets: s.close() (runCommand)
  }
}

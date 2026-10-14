// test/integration/harness/stack.ts — a whole LOCAL vt stack for the E4 scenarios (not a test file). Synthetic data only.
//
//   startStack(t, { network: 'local', ethRpc, solRpc }) → { api, relay, page, home, stop() }:
//     · S4's REAL relay (api/relay/relay.mjs) under C1's relayProfile('local', <the chain ports>), reaching the harness's
//       OWN chains (or the SOL pressure filter in front of one) through the local-only VT_TEST_ETH_RPC / VT_TEST_SOL_RPC
//       overrides, on an ephemeral port (--port 0, NODE_ENV=test), with the local price fixture;
//     · S2's REAL jobs API (api/src/main.ts) under C1's apiProfile(<state dir>, <$OUT>) (no outbound at all; writes only
//       its state dir; reads $OUT), on an ephemeral port, over a temp VT_HOME and a temp $OUT;
//     · S3's REAL page server (api/serve/serve.mjs) under C1's loopbackProfile([relay, api]) (the executor page's
//       origin: it proxies /api/* with the token and /relay/*), on an ephemeral port, over a temp page root.
//   The API can be killed and restarted over the same state dir (crash matrix): the page server follows it.
//   · the API's FRONT (ports.front): a plain HTTP forwarder in this process, in front of the API, that the executor
//     processes reach instead of the API port. It follows the API across a restart, and its hooks (s.front) let a test
//     kill the API at an exact request of an exact job: before it is answered, or after the API answered (the answer
//     then dropped, as if the API died between its fsync and its reply).
// The fetch shims (Node's fetch cannot set Host, the only reason for them):
//   · s.fetch — what the CLI executor's nodeClients reach (the fixed PORTS.local.api / .relay → this stack), with
//     hooks: a test may hold a request (before), or kill the API after it answered and drop the answer (after);
//   · s.pageFetch() — what the page's browserClients reach: the page origin http://127.0.0.1:5180 → this stack's page
//     server, with the headers a browser sends to its own origin (Host, Origin on writes, Sec-Fetch-Site same-origin).
// ★ engine/rpc.js keeps ONE relay client per process (E3 concern 6): every in-process executor of a test file uses
//   s.fetch, so the process-wide client is always this shim; an executor that must take the page's path (the browser
//   adapter) runs in its own process (harness/executor-proc.ts), confined to the page port.
import { mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, request } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { join } from 'node:path'
import { PORTS } from '../../../packages/core/src/contracts/index.ts'
import type { ArmCap, Chain, Holder, JobDef, JobState, JournalEvent } from '../../../packages/core/src/contracts/index.ts'
import { createExecutor } from '../../../packages/core/src/executor/executor.ts'
import { nodeAdapter, nodeClients } from '../../../packages/core/src/executor/adapters/node.ts'
import { formatUnits } from '../../../packages/core/src/chains/plan.js'
import { apiProfile, denyProtectedFiles, denyTerminals, hardening, loopbackProfile, readAllowList, relayProfile } from '../../../cli/src/ops/sandbox.ts'
import { scopeFor } from '../../../cli/src/ops/scope.ts'
import { TOKEN, makeHome, tempDir } from '../../../api/test/helpers.ts'
import { REPO, HARNESS, baseEnv, child, readyLine, sha256, waitFor } from './chains.ts'
import type { Child, T } from './chains.ts'
import { runInPty } from './pty.ts'
import { nodeShim, pageShim } from './shims.ts'
import type { Crash, Fetch, Hooks, Req } from './shims.ts'

export { nodeShim, pageShim, PAGE_ORIGIN } from './shims.ts'
export type { Crash, Fetch, Hooks, Req } from './shims.ts'

export { TOKEN }
const RELAY = join(REPO, 'api/relay/relay.mjs'), API_MAIN = join(REPO, 'api/src/main.ts'), SERVE = join(REPO, 'api/serve/serve.mjs')
export interface Stack {
  network: 'local'; dir: string; home: string; state: string; out: string
  ports: { api: number; relay: number; page: number | null; front: number }
  relay: Child; api: Child; page: Child | null
  hooks: Hooks
  front: Hooks
  fetch: Fetch
  pageFetch(): Fetch
  killApi(): Promise<void>
  restartApi(): Promise<void>
  stop(): Promise<void>
}

// ---- the stack

export async function startStack(t: T, o: { network?: 'local'; ethRpc: string | null; solRpc: string | null; page?: boolean; relay?: boolean; build?: string }): Promise<Stack> {
  if ((o.network ?? 'local') !== 'local') throw new Error('the harness stack is local only')
  const { dir, cleanup } = tempDir('vt-e4-stack-')
  t.after(cleanup)
  const home = join(dir, 'home')
  const state = makeHome(home, 'local')                 // <home>/local: a synthetic api.token and relay-ticket.key
  const out = join(dir, 'out')
  mkdirSync(out, { mode: 0o700 })
  const build = o.build ?? 'e4'
  const chainPorts = [o.ethRpc, o.solRpc].filter((x): x is string => x !== null).map((x) => Number(new URL(x).port))
  const ports: Stack['ports'] = { api: 0, relay: 0, page: null, front: 0 }
  let relay: Child | null = null
  if (o.relay !== false) {
    // a chain without an RPC points at a loopback port the relay's sandbox denies: its identity fails closed (disabled)
    const env: Record<string, string> = { ...baseEnv(home), NODE_ENV: 'test', VT_TEST_ETH_RPC: o.ethRpc ?? 'http://127.0.0.1:9', VT_TEST_SOL_RPC: o.solRpc ?? 'http://127.0.0.1:9' }
    relay = child('/usr/bin/sandbox-exec', ['-p', relayProfile('local', chainPorts), process.execPath, RELAY, '--network', 'local', '--home', home, '--build', build,
      '--port', '0', '--price-fixture', 'SOL=150,ETH=3000'], env)
    t.after(() => relay!.stop())
    ports.relay = Number((await readyLine(relay, /^vt-relay ready network=local port=(\d+)$/, 'relay'))[1])
  }
  const realState = realpathSync(state), realOut = realpathSync(out)
  const spawnApi = async (): Promise<Child> => {
    const c = child('/usr/bin/sandbox-exec', ['-p', apiProfile(realState, realOut), process.execPath, API_MAIN, '--network', 'local', '--home', home, '--build', build, '--port', '0'],
      { ...baseEnv(home), NODE_ENV: 'test', VAULT_TIMELOCK_DIR: out })
    t.after(() => c.stop())
    ports.api = Number((await readyLine(c, new RegExp(`^vt-api ready network=local port=(\\d+) build=${build}$`), 'api'))[1])
    return c
  }
  let api = await spawnApi()
  const root = join(dir, 'page')
  mkdirSync(root)
  writeFileSync(join(root, 'index.html'), '<!doctype html><title>vt</title>\n')
  const spawnPage = async (): Promise<Child> => {
    const c = child('/usr/bin/sandbox-exec', ['-p', loopbackProfile([ports.relay, ports.api]), process.execPath, SERVE, '--network', 'local', '--home', home, '--root', root,
      '--build', build, '--port', '0', '--relay-port', String(ports.relay), '--api-port', String(ports.api)], { ...baseEnv(home), NODE_ENV: 'test' })
    t.after(() => c.stop())
    ports.page = Number((await readyLine(c, /^vt-page ready network=local port=(\d+)$/, 'page'))[1])
    return c
  }
  let page = o.page === false || relay === null ? null : await spawnPage()
  const hooks: Hooks = {}, front: Hooks = {}
  const fs = createServer((req, res) => { void forward(req, res, () => ports.api, front) })
  await new Promise<void>((r) => fs.listen(0, '127.0.0.1', () => r()))
  ports.front = (fs.address() as { port: number }).port
  t.after(() => new Promise<void>((r) => { fs.closeAllConnections(); fs.close(() => r()) }))
  const s: Stack = {
    network: 'local', dir, home, state, out, ports, relay: relay as Child, api, page, hooks, front,
    fetch: nodeShim(ports, hooks),
    pageFetch: () => pageShim(() => ports.page ?? 0),
    async killApi() { await s.api.stop('SIGKILL') },
    async restartApi() {
      await s.api.stop('SIGKILL')
      api = await spawnApi(); s.api = api
      if (page !== null) { await page.stop(); page = await spawnPage(); s.page = page }
    },
    async stop() { await page?.stop(); await s.api.stop(); await relay?.stop() },
  }
  return s
}

// The front: forwards one request to the API's current port; hooks may hold it, or kill the API and fail it (before), or
// drop the API's answer (after: the caller sees the connection reset). SSE streams pass through unhooked.
async function forward(req: IncomingMessage, res: ServerResponse, port: () => number, hooks: Hooks): Promise<void> {
  const chunks: Buffer[] = []
  for await (const c of req) chunks.push(c as Buffer)
  const body = Buffer.concat(chunks)
  let parsed: unknown = null
  try { parsed = body.length > 0 ? JSON.parse(body.toString('utf8')) : null } catch { parsed = null }
  const r: Req = { target: 'api', method: req.method ?? 'GET', path: req.url ?? '/', body: parsed }
  const sse = r.method === 'GET' && /\/events(\?|$)/.test(new URL(r.path, 'http://127.0.0.1').pathname)
  try { if (!sse) await hooks.before?.(r) } catch { res.destroy(); return }
  const up = request({ host: '127.0.0.1', port: port(), method: r.method, path: r.path, headers: req.headers }, (u) => {
    if (sse || hooks.after === undefined) { res.writeHead(u.statusCode ?? 502, u.headers); u.pipe(res); return }
    const cs: Buffer[] = []
    u.on('data', (d: Buffer) => cs.push(d))
    u.on('error', () => res.destroy())
    u.on('end', () => {
      const answer = Buffer.concat(cs)
      void Promise.resolve().then(() => hooks.after!(r, u.statusCode ?? 502, answer.toString('utf8'))).then((v) => v, () => 'drop' as const).then((v) => {
        if (v === 'drop') { res.destroy(); return }
        res.writeHead(u.statusCode ?? 502, u.headers); res.end(answer)
      })
    })
  })
  up.on('error', () => res.destroy())
  res.on('close', () => { if (!res.writableFinished) up.destroy() })
  up.end(body)
}

// ---- the test's own API calls (never hooked)

export async function apiCall(s: Stack, method: 'GET' | 'POST' | 'PUT', path: string, body?: unknown, raw?: string): Promise<{ status: number; json: any; text: string }> {
  const f = nodeShim(s.ports)
  const r = await f(`http://127.0.0.1:${PORTS.local.api}${path}`, { method, headers: { authorization: `Bearer ${TOKEN}`, ...(body === undefined && raw === undefined ? {} : { 'content-type': raw !== undefined ? 'text/plain; charset=utf-8' : 'application/json' }) },
    ...(raw !== undefined ? { body: raw } : body === undefined ? {} : { body: JSON.stringify(body) }) })
  const text = await r.text()
  let json: unknown = null
  try { json = JSON.parse(text) } catch { /* not JSON */ }
  return { status: r.status, json, text }
}
export async function jobOf(s: Stack, id: string): Promise<{ def: JobDef; state: JobState; seq: number; leases: Record<string, unknown>; serverNowMs: number }> {
  const r = await apiCall(s, 'GET', `/jobs/${id}`)
  if (r.status !== 200) throw new Error(`GET /jobs/${id}: ${r.status} ${r.text.slice(0, 200)}`)
  return r.json
}
export function journalOf(s: Stack, id: string): JournalEvent[] {
  return readFileSync(join(s.state, 'jobs', id, 'journal.jsonl'), 'utf8').split('\n').filter((l) => l !== '').map((l) => JSON.parse(l) as JournalEvent)
}
export async function createJob(s: Stack, input: Record<string, unknown>): Promise<{ id: string; def: JobDef }> {
  const r = await apiCall(s, 'POST', '/jobs', input)
  if (r.status !== 201) throw new Error(`POST /jobs: ${r.status} ${r.text.slice(0, 300)}`)
  return { id: r.json.id, def: r.json.def }
}
// POST /jobs is capped at 64 KiB: long texts go up first (PUT /messages/:sha256), the job names them by digest.
export async function uploadMessage(s: Stack, text: string): Promise<{ messageSha256: string; messageBytes: number }> {
  const b = Buffer.from(text, 'utf8'), h = sha256(b)
  const r = await apiCall(s, 'PUT', `/messages/${h}`, undefined, text)
  if (r.status !== 201) throw new Error(`PUT /messages: ${r.status} ${r.text.slice(0, 200)}`)
  return { messageSha256: h, messageBytes: b.length }
}
export async function waitChains(s: Stack, id: string, pred: (st: JobState) => boolean, ms: number, what: string): Promise<JobState> {
  return waitFor(async () => { const j = await jobOf(s, id); return pred(j.state) ? j.state : null }, ms, `${id}: ${what}`, 500)
}
export const waitReady = (s: Stack, id: string, chains: Chain[], ms = 180_000): Promise<JobState> =>
  waitChains(s, id, (st) => chains.every((c) => st.chains[c]?.phase === 'READY'), ms, `${chains.join('+')} READY`)
export const DECIMALS: Record<Chain, number> = { eth: 18, sol: 9, btc: 8 }
export const capOf = (chain: Chain, nativeCap: bigint, overCap = false): ArmCap => ({ nativeCap: String(nativeCap), usd: 0, priceAt: null, overCap, planned: formatUnits(nativeCap, DECIMALS[chain]) })
export async function arm(s: Stack, id: string, caps: Partial<Record<Chain, ArmCap>>, o: { countdownSec?: number } = {}): Promise<{ status: number; json: any }> {
  const chains = Object.keys(caps) as Chain[]
  const amounts: Record<string, string> = {}
  for (const c of chains) if (caps[c]!.overCap) amounts[c] = caps[c]!.planned
  return apiCall(s, 'POST', `/jobs/${id}/arm`, { chains, confirm: { typed: null, amounts }, caps, countdownSec: o.countdownSec ?? 5, stagger: [0, 0] })
}
export async function armOk(s: Stack, id: string, caps: Partial<Record<Chain, ArmCap>>, o: { countdownSec?: number } = {}): Promise<void> {
  const r = await arm(s, id, caps, o)
  if (r.status !== 200) throw new Error(`arm ${id}: ${r.status} ${JSON.stringify(r.json).slice(0, 300)}`)
}

// ---- executors

export type KeyHandle = { chain: Chain; address: string; secret: string; account?: unknown; kp?: unknown }
// In this process, the CLI's adapter (node) over s.fetch (hookable). One relay client per process: see the header.
export function executor(s: Stack, o: { jobId: string; chain: Chain; key: KeyHandle; holder?: Holder; clawbackConfirm?: { amount: string }; poll?: number }) {
  const { journal, relay } = nodeClients({ network: 'local', token: TOKEN, fetch: s.fetch })
  const { clock, random } = nodeAdapter()
  return createExecutor({ jobId: o.jobId, chain: o.chain, key: { chain: o.chain, address: o.key.address, network: 'local', handle: o.key }, holder: o.holder ?? 'cli',
    deps: { journal, relay, clock, random, poll: o.poll ?? 500, ...(o.clawbackConfirm !== undefined ? { clawbackConfirm: o.clawbackConfirm } : {}) } })
}

// An executor in its own process (harness/executor-proc.ts) — the page's adapter (browser: jsdom origin, the page
// server, confined to the page port) or the CLI's (node: nodeClients + the API token file, confined to the API's front
// and the relay port). Key secrets travel only through its stdin (memory).
export function spawnExecutor(s: Stack, o: { adapter: 'browser' | 'node'; jobId: string; keys: KeyHandle[]; crash?: Crash; poll?: number; mode?: 'run' | 'clawback'; to?: string; clawbackConfirm?: { amount: string } }): Child {
  const allowed = o.adapter === 'browser' ? [s.ports.page!] : [s.ports.front, s.ports.relay]
  const cfg = { adapter: o.adapter, jobId: o.jobId, ports: { api: s.ports.front, relay: s.ports.relay, page: s.ports.page }, chains: o.keys.map((k) => k.chain), poll: o.poll ?? 500, mode: o.mode ?? 'run',
    ...(o.crash ? { crash: o.crash } : {}), ...(o.to ? { to: o.to } : {}), ...(o.clawbackConfirm ? { clawbackConfirm: o.clawbackConfirm } : {}) }
  const c = child('/usr/bin/sandbox-exec', ['-p', loopbackProfile(allowed), process.execPath, join(HARNESS, 'executor-proc.ts')],
    { ...baseEnv(s.home), NODE_ENV: 'test', VT_HOME: s.home, VT_E4_PROC: JSON.stringify(cfg) },
    { stdin: `${JSON.stringify({ secrets: Object.fromEntries(o.keys.map((k) => [k.chain, k.secret])) })}\n` })
  return c
}
export async function outcomesOf(c: Child, chains: Chain[], ms: number): Promise<Record<string, string>> {
  return waitFor(() => {
    const out: Record<string, string> = {}
    for (const l of c.lines) { const m = /^outcome (eth|sol) (\S+)$/.exec(l); if (m) out[m[1]] = m[2] }
    if (chains.every((ch) => out[ch] !== undefined)) return out
    if (c.proc.exitCode !== null || c.proc.signalCode !== null) throw Object.assign(new Error(`executor process ended without every outcome: ${c.tail(8)}`), { fatal: true })
    return null
  }, ms, `outcomes ${chains.join('+')}`, 300)
}

// The REAL `vt job run` / `vt job clawback` (cli/src/main.ts through cli/test/fixtures/vt-entry.ts: main()'s test-only
// ports seam, NODE_ENV=test, local, a development tree) on a fresh pseudo-terminal, as bin/vt would start it: an explicit
// environment (env -i: PATH HOME LANG TERM VT_HOME VAULT_TIMELOCK_DIR VT_NETWORK) and, since the TTY-less round (M5e glue),
// through the unsandboxed broker (cli/src/ops/broker.ts: it owns the pty, asks the prompts, filters the output; it sets
// VT_CONFINED=1, VT_BROKER=1 and VT_TTY), which starts a launcher script (bin/vt hands the broker its own script as the
// launcher; the broker's prompt policy reads the vt arguments after it) that execs `node --disable-sigusr1 --no-addons vt-entry.ts …`, inside the
// executor's FULL profile as commandProfile builds it (the same pieces, in the same order: no terminal, the read allow-list
// plus vt-entry.ts, the protected-file denies, the exec/IPC hardening, the terminal denies), so main()'s strict start-up
// proof passes, but for this stack's two ports (the API's front and the relay) in place of the network's fixed ones (vt
// still sends the fixed ports as Host). The key comes from its ENCRYPTED backup file (written 0600 in a 0700 dir under the
// stack's temp dir, removed after the run; handed as its real path, as bin/vt rewrites it), the passphrase is typed at the
// broker's prompt (never echoed), the API token is $VT_HOME/local/api.token. A claw-back over the armed cap: `typed` (base
// units; '' = an empty answer) is typed at the broker's prompt in the chain's unit, in full precision.
// A chain another executor still holds (lease.held: a dead tab, until its lease lapses) makes vt exit refused; like an
// operator, the harness runs it again after 1 s (each run asks the passphrase again) and notes `waiting: lease.held`.
// Result: outcome = the RunOutcome vt printed (`<chain>: <outcome>`), or `refused:<guard id>` (note = its message).
const VT_ENTRY = join(REPO, 'cli/test/fixtures/vt-entry.ts'), BROKER = join(REPO, 'cli/src/ops/broker.ts')
const DEC: Record<Chain, number> = { eth: 18, sol: 9, btc: 8 }
let cliRuns = 0
export async function runCli(s: Stack, o: { jobId: string; chain: Chain; address: string; backup: Uint8Array; passphrase: string; mode?: 'run' | 'clawback'; to?: string; typed?: string; timeoutMs?: number }): Promise<{ out: string; code: number | null; outcome: string | null; note: string; ms: number }> {
  const t0 = Date.now()
  const kdir = join(s.dir, 'cli-keys', `run${++cliRuns}`)
  mkdirSync(kdir, { recursive: true, mode: 0o700 })
  const file = join(realpathSync(kdir), `vt-${o.chain}-key.age`)
  writeFileSync(file, o.backup, { mode: 0o600 })
  const args = (o.mode ?? 'run') === 'clawback'
    ? ['job', 'clawback', o.jobId, '--chain', o.chain, '--to', o.to!, `--backup-${o.chain}`, file]
    : ['job', 'run', o.jobId, '--chain', o.chain, `--backup-${o.chain}`, file]
  const steps = [{ waitFor: 'Passphrase: ', send: `${o.passphrase}\r` },
    ...(o.typed !== undefined ? [{ waitFor: 'type the planned amount exactly', send: `${o.typed === '' ? '' : formatUnits(BigInt(o.typed), DEC[o.chain])}\r` }] : [])]
  const env = { ...baseEnv(s.home), TERM: 'xterm', VT_HOME: s.home, VAULT_TIMELOCK_DIR: s.out, VT_NETWORK: 'local',
    NODE_ENV: 'test', VT_TEST_PORTS: `api=${s.ports.front},relay=${s.ports.relay}` }
  const home = realpathSync(s.home), outDir = realpathSync(s.out), entry = realpathSync(VT_ENTRY), node = realpathSync(process.execPath)
  // The sandboxed command is a launcher script, as in bin/vt (the broker is given <launcher> <vt args…>, so its prompt policy sees `job run …` as its first words)
  const shim = join(s.dir, 'vt-launcher.sh')
  writeFileSync(shim, `#!/bin/sh\nexec '${node}' --disable-sigusr1 --no-addons '${entry}' "$@"\n`, { mode: 0o755 })
  const shimReal = realpathSync(shim)
  const scope0 = scopeFor(args, env)
  const scope = { ...scope0, launcher: shimReal, treeFiles: [...scope0.treeFiles, entry, shimReal] }
  const profile = loopbackProfile([s.ports.front, s.ports.relay], { tty: false, noListen: true }) + readAllowList(home, ['local'], scope, outDir, false)
    + denyProtectedFiles(home, outDir, ['local'], scope.userHomes ?? scope.userHome) + hardening(scope, false) + denyTerminals()
  // from `/`, as bin/vt starts it (`cd /`: the profile lets the sandboxed process list no directory above the ones it reads)
  const argv = ['/bin/sh', '-c', 'cd / && exec "$@"', 'sh', process.execPath, '--disable-sigusr1', BROKER, '/usr/bin/sandbox-exec', profile, shimReal, ...args]
  let out = ''
  try {
    for (let i = 0; ; i++) {
      const r = await runInPty(argv, { env, steps, timeoutMs: o.timeoutMs ?? 600_000 })
      out += r.out
      // `<chain>: <outcome>[ — <note>]` (the pty output is read as latin1: the dash is not matched literally)
      const done = /^(?:eth|sol): (drained|copies-done|stopped|clawed-back|lease-lost|failed)(?:[ \t]+\S+[ \t]+(.*?))?\r?$/m.exec(r.out)
      const refused = /^refused ([a-z0-9-]+\.[a-z0-9.-]+): (.*?)\r?$/m.exec(r.out)
      if (done === null && refused?.[1] === 'lease.held' && i < 120) {
        if (i === 0) out += 'waiting: lease.held (another executor holds this chain; its lease lapses within 15 s)\n'
        await new Promise((res) => setTimeout(res, 1_000))
        continue
      }
      const outcome = done !== null ? done[1] : refused !== null ? `refused:${refused[1]}` : null
      return { out, code: r.code, outcome, note: done !== null ? (done[2] ?? '') : (refused?.[2] ?? ''), ms: Date.now() - t0 }
    }
  } finally {
    rmSync(kdir, { recursive: true, force: true })
  }
}

// ---- report evidence (one JSON line per fact; the report is built from these)

export function evidence(scenario: string, what: string, data: Record<string, unknown>): void {
  console.log(`E4-EVIDENCE ${JSON.stringify({ scenario, what, ...data }, (_k, v) => (typeof v === 'bigint' ? String(v) : v))}`)
}

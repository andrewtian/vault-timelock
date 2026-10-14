// cli/src/ops/confine.ts — proves that this process runs inside its vt sandbox (canonical vt spec §3.1 "startup
// self-proofs"; plan Task C1).
//
// bin/vt re-runs itself under sandbox-exec with VT_CONFINED=1 for every client and executor command. That variable
// is only a hint, anyone can set it, so src/main.ts calls assertConfined() whenever VT_CONFINED=1 is set and for
// every command args.ts sandboxes. It makes two direct TCP connection attempts and a write probe (below) and accepts ONLY EPERM, the errno the
// sandbox returns at connect() (about 1 ms; broadcast/feasibility/F5.txt):
//   1. loopback port 9, a port no vt profile allows. Outside a sandbox, or inside a looser one (the test suite's
//      "every loopback port"), it answers ECONNREFUSED: this process could reach any local service.
//   2. 192.0.2.1:9 (TEST-NET-1, RFC 5737, never routed): proves the sandbox also denies the internet.
//   3. a file write: O_CREAT|O_EXCL of a fresh name in the temp dir (and $VT_HOME when set) must give EPERM too; a
//      create that succeeds is deleted again and refused. The executor has no file writes (spec §3.1), and a sandbox
//      that only denies the network would otherwise pass the proof.
// Order matters: the TEST-NET-1 attempt runs only after loopback port 9 was denied, so a process that is plainly not
// sandboxed is refused without a single packet leaving the machine. Anything but EPERM for both (a timeout, a
// connect, ECONNREFUSED, ENETUNREACH, …) means "not proven": vt.not-confined. The refusal names no address.
import { randomBytes } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { closeSync, constants, existsSync, openSync, readdirSync, readFileSync, unlinkSync } from 'node:fs'
import { connect } from 'node:net'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { refuse } from '@vault-timelock/core/contracts'

const LOOPBACK_PROBE = { host: '127.0.0.1', port: 9 } as const
const INTERNET_PROBE = { host: '192.0.2.1', port: 9 } as const
const PROBE_TIMEOUT_MS = 2_000
const DENIED = 'EPERM'

// The outcome of one direct connect attempt: an errno code, 'connected', 'timeout' or 'error'.
function directConnect(target: { readonly host: string; readonly port: number }, timeoutMs: number): Promise<string> {
  return new Promise<string>((resolve) => {
    let done = false
    const finish = (outcome: string): void => {
      if (done) return
      done = true
      clearTimeout(timer)
      s.destroy()
      resolve(outcome)
    }
    const s = connect({ host: target.host, port: target.port }) // confinement probe
    const timer = setTimeout(() => finish('timeout'), timeoutMs)
    s.on('connect', () => finish('connected'))
    s.on('error', (e: NodeJS.ErrnoException) => finish(typeof e.code === 'string' ? e.code : 'error'))
  })
}

async function attempt(target: { readonly host: string; readonly port: number }, ms: number): Promise<string> {
  try { return await directConnect(target, ms) } catch { return 'error' }
}

// A write probe: O_CREAT|O_EXCL of a fresh name in `dir`. 'EPERM' = the sandbox denies it (what a vt client or executor
// profile does everywhere but /dev/null and /dev/tty). Anything that succeeds is deleted again. 'skipped' = no such
// directory (nothing to prove there).
function writeProbe(dir: string): string {
  if (!existsSync(dir)) return 'skipped'
  const file = join(dir, `.vt-confine-probe-${process.pid}-${randomBytes(6).toString('hex')}`)
  try {
    closeSync(openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600))
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code
    return typeof code === 'string' ? code : 'error'
  }
  try { unlinkSync(file) } catch { /* best effort: the refusal below is what matters */ }
  return 'created'
}

// TTY-less round (sandbox review M-1): the strict proof also covers what the client/executor profiles take away besides the network and writes:
//   · reads: a file and a directory OUTSIDE the read allow-list (/etc/hosts and the home directory's listing: never their contents are used) must give EPERM;
//   · exec: /usr/bin/true must not run (only the launcher chain may);
//   · tty: /dev/tty must not open (EPERM; ENXIO would mean the denies are not there but there is no terminal either: not proven).
// A sandbox-exec earlier on PATH that applies only a network and write deny therefore no longer passes. Outcomes only; no path is reported.
export function strictProbes(): { readFile: string; readDir: string; exec: string; tty: string } {
  const code = (f: () => unknown): string => { try { f(); return 'allowed' } catch (e) { const c = (e as NodeJS.ErrnoException).code; return typeof c === 'string' ? c : 'error' } }
  const execOutcome = (): string => {
    const r = spawnSync('/usr/bin/true', [], { stdio: 'ignore', timeout: 5_000 })
    return r.error === undefined ? 'allowed' : typeof (r.error as NodeJS.ErrnoException).code === 'string' ? (r.error as NodeJS.ErrnoException).code as string : 'error'
  }
  return {
    readFile: code(() => readFileSync('/etc/hosts')),
    readDir: code(() => readdirSync(homedir())),
    exec: execOutcome(),
    tty: code(() => closeSync(openSync('/dev/tty', constants.O_RDWR | constants.O_NOCTTY))),
  }
}

export interface ConfineProbes {
  readonly strict?: boolean
  readonly loopback: { readonly host: string; readonly port: number }
  readonly internet: { readonly host: string; readonly port: number }
  readonly writeDirs: readonly string[]
}

// The proof against explicit probe targets (assertConfined passes the real ones; test/confine.test.ts passes a
// listener as the "internet" so the not-denied arm runs without a packet leaving the machine).
export async function assertConfinedWith(probes: ConfineProbes, ms: number): Promise<void> {
  const loopback = await attempt(probes.loopback, ms)
  const internet = loopback === DENIED ? await attempt(probes.internet, ms) : 'not tried'
  const networkDenied = loopback === DENIED && internet === DENIED
  // File writes are probed only once the network is proven denied, and report the outcomes only (never a path).
  const writes = networkDenied ? probes.writeDirs.map(writeProbe) : []
  const writesDenied = writes.every((w) => w === DENIED || w === 'skipped')
  const writeOutcome = !networkDenied ? 'not tried' : writes.length === 0 ? 'none' : [...new Set(writes)].join(',').slice(0, 40)
  const strict = networkDenied && writesDenied && probes.strict === true ? strictProbes() : null
  const strictOk = strict === null ? true : [strict.readFile, strict.readDir, strict.exec, strict.tty].every((o) => o === DENIED)
  const strictNote = strict === null ? '' : `; reads: ${strict.readFile},${strict.readDir}; exec: ${strict.exec}; tty: ${strict.tty}`
  const confined = networkDenied && writesDenied && strictOk
  if (!confined) refuse('vt.not-confined', `this process is not inside its vt sandbox (loopback port 9: ${loopback.slice(0, 20)}; TEST-NET-1: ${internet.slice(0, 20)}; file writes: ${writeOutcome}${strictNote}); run it through bin/vt, and never set VT_CONFINED by hand`) // @guard:vt.not-confined
}

// opts.timeoutMs can only shorten the 2 s budget per attempt. opts.writeDirs adds directories to the write probe
// (main.ts passes $VT_HOME); the temp dir is always probed.
export async function assertConfined(opts: { timeoutMs?: number; writeDirs?: readonly string[]; strict?: boolean } = {}): Promise<void> {
  const t = opts.timeoutMs
  const ms = typeof t === 'number' && Number.isInteger(t) && t > 0 ? Math.min(t, PROBE_TIMEOUT_MS) : PROBE_TIMEOUT_MS
  await assertConfinedWith({ loopback: LOOPBACK_PROBE, internet: INTERNET_PROBE, writeDirs: [tmpdir(), ...(opts.writeDirs ?? [])], strict: opts.strict === true }, ms)
}

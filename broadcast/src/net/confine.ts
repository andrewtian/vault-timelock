// Confinement self-check (spec B s6.1 "OS-level confinement", C s6.1; Task 7, strengthened in 7b).
//
// bin/vt-broadcast re-execs Node under
//   sandbox-exec -p '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:9050"))'
// (plus explicitly allowed loopback ports), and sets VT_CONFINED=1. That variable is only a hint:
// anyone can set it. Every networked command therefore PROVES confinement first, with two direct TCP
// connection attempts, and accepts only EPERM, the errno the sandbox returns at connect() (measured,
// feasibility/F5.txt: EPERM in ~1 ms under the profile):
//   1. 192.0.2.1:9 (TEST-NET-1, RFC 5737, never routed). Outside a sandbox the SYN goes unanswered;
//      anything but EPERM means no sandbox denies the internet: confine.not-sandboxed.
//   2. loopback port 9, a port no run configures. A sandbox that denies the internet but opens every
//      loopback port (the offline test suite's profile, say) answers ECONNREFUSED here: it is not
//      the broadcaster's narrow profile, so this process could reach any local service (and through
//      one, the internet): confine.loopback-open. A run that widened port 9 itself
//      (--rpc x=http://127.0.0.1:9) is refused the same way: fail closed.
// Both are needed: the first alone accepts any internet-denying sandbox, the second alone accepts a
// sandbox that only blocks loopback. A timeout, ETIMEDOUT, EHOSTUNREACH, ENETUNREACH, ECONNREFUSED,
// a connect, or any other outcome means "not proven": refuse.
//
// This is the only non-SOCKS socket to a non-loopback address in src/ (the static scan allows
// exactly this one connect reference here, and one in socks-probe.ts).
import { connect } from 'node:net'
import { refuse } from '../guard.ts'

const INTERNET_PROBE = { host: '192.0.2.1', port: 9 } as const
const LOOPBACK_PROBE = { host: '127.0.0.1', port: 9 } as const
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
    const s = connect({ host: target.host, port: target.port }) // net-scan:ok confinement probe
    const timer = setTimeout(() => finish('timeout'), timeoutMs)
    s.on('connect', () => finish('connected'))
    s.on('error', (e: NodeJS.ErrnoException) => finish(typeof e.code === 'string' ? e.code : 'error'))
  })
}

async function attempt(target: { readonly host: string; readonly port: number }, ms: number): Promise<string> {
  try { return await directConnect(target, ms) } catch { return 'error' }
}

// opts.timeoutMs can only shorten the 2 s budget per attempt (EPERM arrives in about 1 ms).
export async function assertConfined(opts: { timeoutMs?: number } = {}): Promise<void> {
  const t = opts.timeoutMs
  const ms = typeof t === 'number' && Number.isInteger(t) && t > 0 ? Math.min(t, PROBE_TIMEOUT_MS) : PROBE_TIMEOUT_MS
  const internet = await attempt(INTERNET_PROBE, ms)
  const internetDenied = internet === DENIED
  if (!internetDenied) refuse('confine.not-sandboxed', `this process is not confined: a direct connection attempt to TEST-NET-1 was not denied by the sandbox (${internet.slice(0, 20)}); run it through bin/vt-broadcast`) // @guard:confine.not-sandboxed
  const loopback = await attempt(LOOPBACK_PROBE, ms)
  const loopbackDenied = loopback === DENIED
  if (!loopbackDenied) refuse('confine.loopback-open', `this process is not in the broadcaster's sandbox: loopback port 9, which no run configures, was not denied (${loopback.slice(0, 20)}); run it through bin/vt-broadcast, without a loopback override on port 9`) // @guard:confine.loopback-open
}

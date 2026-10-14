// api/src/confine.ts — the API proves its own confinement before it listens (spec §3.1; api.not-confined → exit 2).
//
// `vt up` starts the API under C1's apiProfile(stateDir):
//   (version 1)(allow default)(deny network-outbound)(deny file-write*)(allow file-write* (subpath "<stateDir>") (literal "/dev/null"))
// so the API has NO outbound network at all, and writes only under its state dir. That is a claim; this module
// measures it. Every probe must come back EPERM, the errno the sandbox returns (a timeout, ECONNREFUSED,
// EHOSTUNREACH, a connect, a successful write or anything else is "not proven"):
//   1. a write probe outside the state dir: /private/tmp/vt-api-probe-<random> (removed at once if it was created); then, when
//      the state dir is known, a write probe BESIDE it, in its parent where the other networks' state dirs live (S1 review m5:
//      a profile that allows $VT_HOME instead of $VT_HOME/<network> would let this API write another network's state);
//   2. loopback port 9 (no service), the relay's loopback port, and Tor's SOCKS port 9050: a profile that opens
//      loopback (the test suite's, say) is not the API's;
//   3. the mDNSResponder socket (DNS);
//   4. TEST-NET-1 (RFC 5737, never routed) ports 9, 443 and 80: the internet.
// The probes run in this order and stop at the first that is not EPERM, so a process that is not confined never sends
// a packet off the machine: it is stopped by a local probe first. Refusals name the probe, never an address.
import { closeSync, openSync, unlinkSync } from 'node:fs'
import { connect } from 'node:net'
import { randomBytes } from 'node:crypto'
import { dirname, join } from 'node:path'
import { refuse } from 'vt-broadcast/src/guard.ts'

export const DENIED = 'EPERM'
const PROBE_TIMEOUT_MS = 2_000

export type Probe =
  | { label: string; kind: 'write'; path: string }
  | { label: string; kind: 'tcp'; host: string; port: number }
  | { label: string; kind: 'unix'; path: string }

export interface ProbeResult { label: string; outcome: string }

export function probePlan(relayPort: number, stateDir?: string): Probe[] {
  const testNet = '192.0.2.1'
  return [
    { label: 'write outside the state dir', kind: 'write', path: `/private/tmp/vt-api-probe-${randomBytes(8).toString('hex')}` },
    ...(stateDir === undefined ? [] : [{ label: 'write beside the state dir', kind: 'write' as const, path: join(dirname(stateDir), `vt-api-probe-${randomBytes(8).toString('hex')}`) }]),
    { label: 'loopback port 9', kind: 'tcp', host: '127.0.0.1', port: 9 },
    { label: 'the relay port', kind: 'tcp', host: '127.0.0.1', port: relayPort },
    { label: 'the Tor SOCKS port', kind: 'tcp', host: '127.0.0.1', port: 9050 },
    { label: 'the DNS socket', kind: 'unix', path: '/var/run/mDNSResponder' },
    { label: 'TEST-NET-1 port 9', kind: 'tcp', host: testNet, port: 9 },
    { label: 'TEST-NET-1 port 443', kind: 'tcp', host: testNet, port: 443 },
    { label: 'TEST-NET-1 port 80', kind: 'tcp', host: testNet, port: 80 },
  ]
}

function writeProbe(path: string): string {
  try {
    const fd = openSync(path, 'wx', 0o600)
    closeSync(fd)
    try { unlinkSync(path) } catch { /* the outcome stands: the write was allowed */ }
    return 'written'
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code
    return typeof code === 'string' ? code : 'error'
  }
}

function connectProbe(target: { host: string; port: number } | { path: string }): Promise<string> {
  return new Promise<string>((resolve) => {
    let done = false
    const finish = (outcome: string): void => {
      if (done) return
      done = true
      clearTimeout(timer)
      s.destroy()
      resolve(outcome)
    }
    const s = connect(target) // net-scan:ok confinement probe
    const timer = setTimeout(() => finish('timeout'), PROBE_TIMEOUT_MS)
    s.on('connect', () => finish('connected'))
    s.on('error', (e: NodeJS.ErrnoException) => finish(typeof e.code === 'string' ? e.code : 'error'))
  })
}

// Runs the probes in order, stopping after the first that is not EPERM.
export async function runProbes(plan: readonly Probe[]): Promise<ProbeResult[]> {
  const results: ProbeResult[] = []
  for (const p of plan) {
    let outcome: string
    try {
      outcome = p.kind === 'write' ? writeProbe(p.path)
        : await connectProbe(p.kind === 'tcp' ? { host: p.host, port: p.port } : { path: p.path })
    } catch {
      outcome = 'error'
    }
    results.push({ label: p.label, outcome })
    if (outcome !== DENIED) break
  }
  return results
}

// Confined only when every planned probe ran and every one was denied.
export function assertConfined(plan: readonly Probe[], results: readonly ProbeResult[]): void {
  const failed = results.find((r) => r.outcome !== DENIED)
  const ok = plan.length > 0 && results.length === plan.length && failed === undefined
  if (!ok) refuse('api.not-confined', `the API is not confined (${failed === undefined ? 'probes missing' : `${failed.label}: ${failed.outcome.slice(0, 20)}`}); start it through vt up, under the API sandbox profile`) // @guard:api.not-confined
}

export async function proveConfined(relayPort: number, stateDir?: string): Promise<void> {
  const plan = probePlan(relayPort, stateDir)
  assertConfined(plan, await runProbes(plan))
}

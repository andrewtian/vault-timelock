// cli/test/fixtures/fault-hook.ts — TEST ONLY (never in a release: cli/test is excluded, and test/release.test.ts checks
// that this file and its marker reach no release). The test-only fault hook of review m-1: it makes the executor process
// end the way nothing in vt or core is known to, with an uncaught exception or an unhandled rejection, at a chosen point
// (src/job/run.ts RunDeps.fault, which src refuses unless NODE_ENV=test: vt.test-fault). The error's message holds a
// canary IP (TEST-NET-3) and a canary 64-hex key: neither may ever reach the terminal.
//   VT_JOB_STUB_FAULT=<point>:<kind>   point keys | intent, kind rejection | exception (test/fixtures/job-stub.ts)
export const FAULT_CANARY_IP = '203.0.113.7'
export const FAULT_CANARY_KEY = 'ca11ab1e'.repeat(8)
export const FAULT_MARKER = 'vt-fault-hook'

export type FaultPoint = 'keys' | 'intent'
export interface FaultSpec { at: FaultPoint; kind: 'rejection' | 'exception' }

export function parseFault(v: string | undefined): FaultSpec | null {
  const m = /^(keys|intent):(rejection|exception)$/.exec(v ?? '')
  return m === null ? null : { at: m[1] as FaultPoint, kind: m[2] as FaultSpec['kind'] }
}

export const faultError = (): Error => new Error(`${FAULT_MARKER}: the relay at ${FAULT_CANARY_IP} answered with the key 0x${FAULT_CANARY_KEY}`)

// The hook: at the first call at its point, an unhandled rejection (now) or an uncaught exception (from a timer). It
// returns at once, so the caller goes on until the process ends.
export function faultHook(spec: FaultSpec): (at: FaultPoint) => void {
  let done = false
  return (at) => {
    if (done || at !== spec.at) return
    done = true
    const e = faultError()
    if (spec.kind === 'rejection') void Promise.reject(e)
    else setImmediate(() => { throw e })
  }
}

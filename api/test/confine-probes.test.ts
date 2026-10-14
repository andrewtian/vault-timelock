// The confinement proof's judgement (api.not-confined), without applying a sandbox (so the mutation runner can map it):
// every planned probe must have run and come back EPERM. Run inside the suite sandbox (test-root.sh phase A), the
// real probes are NOT all EPERM (the suite lets this process write to /private/tmp and open loopback), so the real
// proof refuses too. The process-level proofs (unsandboxed exit 2, the API profile → ready) are in confine.test.ts.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync } from 'node:fs'
import { join } from 'node:path'
import { assertConfined, probePlan, proveConfined, runProbes } from '../src/confine.ts'
import type { ProbeResult } from '../src/confine.ts'
import { tempDir } from './helpers.ts'

const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/
const refusal = async (fn: () => unknown): Promise<{ guardId: string; message: string }> => {
  try { await fn() } catch (e) { return e as { guardId: string; message: string } }
  assert.fail('expected a refusal')
}

test('the plan: write probe first, then loopback 9, the relay port, 9050, the DNS socket, TEST-NET-1 9/443/80', () => {
  const plan = probePlan(5191)
  assert.deepEqual(plan.map((p) => p.kind), ['write', 'tcp', 'tcp', 'tcp', 'unix', 'tcp', 'tcp', 'tcp'])
  assert.match((plan[0] as { path: string }).path, /^\/private\/tmp\/vt-api-probe-[0-9a-f]{16}$/)
  assert.notEqual((plan[0] as { path: string }).path, (probePlan(5191)[0] as { path: string }).path)
  assert.deepEqual(plan.filter((p) => p.kind === 'tcp').map((p) => (p as { host: string; port: number }).port), [9, 5191, 9050, 9, 443, 80])
  assert.deepEqual(plan.filter((p) => p.kind === 'tcp').map((p) => (p as { host: string }).host), ['127.0.0.1', '127.0.0.1', '127.0.0.1', '192.0.2.1', '192.0.2.1', '192.0.2.1'])
})

test('with the state dir known (S1 review m5) a second write probe sits BESIDE it, in the parent where the other networks\' state lives', async () => {
  const plan = probePlan(5191, '/Users/someone/.vt/local')
  assert.deepEqual(plan.map((p) => p.kind), ['write', 'write', 'tcp', 'tcp', 'tcp', 'unix', 'tcp', 'tcp', 'tcp'])
  assert.deepEqual(plan.slice(0, 2).map((p) => p.label), ['write outside the state dir', 'write beside the state dir'])
  assert.match((plan[1] as { path: string }).path, /^\/Users\/someone\/\.vt\/vt-api-probe-[0-9a-f]{16}$/)
  assert.notEqual((plan[1] as { path: string }).path, (probePlan(5191, '/Users/someone/.vt/local')[1] as { path: string }).path)
  // without it the plan is exactly as before
  assert.equal(probePlan(5191).length, 8)
  // the beside-probe being allowed ('written') while the first was denied is "not confined", naming the probe
  const eperm: ProbeResult[] = plan.map((p) => ({ label: p.label, outcome: 'EPERM' }))
  assertConfined(plan, eperm)
  const e = await refusal(() => assertConfined(plan, [eperm[0], { label: plan[1].label, outcome: 'written' }]))
  assert.equal(e.guardId, 'api.not-confined')
  assert.ok(e.message.includes('write beside the state dir: written') && !IPV4.test(e.message))
  // runProbes writes (and removes) the beside-probe in a real directory
  const { dir, cleanup } = tempDir('vt-beside-')
  try {
    const state = join(dir, 'local')
    const results = await runProbes(probePlan(5191, state).filter((p) => p.label === 'write beside the state dir'))
    assert.deepEqual(results, [{ label: 'write beside the state dir', outcome: 'written' }])
    assert.deepEqual(readdirSync(dir), [], 'the probe file was removed at once')
  } finally { cleanup() }
})

test('all EPERM → confined; any other outcome, or a missing probe → api.not-confined (naming the probe, no address)', async () => {
  const plan = probePlan(5181)
  const eperm: ProbeResult[] = plan.map((p) => ({ label: p.label, outcome: 'EPERM' }))
  assertConfined(plan, eperm)
  for (let i = 0; i < plan.length; i++) {
    for (const outcome of ['ECONNREFUSED', 'timeout', 'connected', 'written', 'EHOSTUNREACH', 'error']) {
      const results = eperm.slice(0, i + 1).map((r, k) => (k === i ? { ...r, outcome } : r))
      const e = await refusal(() => assertConfined(plan, results))
      assert.equal(e.guardId, 'api.not-confined')
      assert.ok(e.message.includes(plan[i].label) && !IPV4.test(e.message))
    }
  }
  assert.equal((await refusal(() => assertConfined(plan, eperm.slice(0, -1)))).guardId, 'api.not-confined')
  assert.equal((await refusal(() => assertConfined(plan, []))).guardId, 'api.not-confined')
  assert.equal((await refusal(() => assertConfined([], []))).guardId, 'api.not-confined')
})

test('runProbes stops at the first probe that is not EPERM (here: the write, allowed by the suite sandbox)', async () => {
  const results = await runProbes(probePlan(5181))
  assert.equal(results.length, 1)
  assert.deepEqual(results[0], { label: 'write outside the state dir', outcome: 'written' })
})

test('proveConfined in the suite sandbox → api.not-confined', async () => {
  const e = await refusal(() => proveConfined(5181))
  assert.equal(e.guardId, 'api.not-confined')
  assert.ok(!IPV4.test(e.message))
})

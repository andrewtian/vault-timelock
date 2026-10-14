// MERGE GATE (PF-E fix round 2, review I-2 × lane-s): an ETH job attempt journaled STUCK at an UNUSED nonce n (PF-E's passive / Stop /
// rebuild-mismatch paths) and resolved mark-failed by the operator must leave the chain where vt can still move the funds:
//   · a claw-back intent at that same nonce n is ACCEPTED by the API (event.family: it opens the claw-back family of n — only one of the
//     two can land there; the ledger counts both, the job attempt's worst case plus the claw-back's value + worst-case fee, as core's
//     CapLedger does), and nothing else may reuse n (no job intent: the chain is STOPPED);
//   · a close is ACCEPTED (nothing in flight that the chain can still land, by the operator's word).
// The API rules: the claw-back at n is lane-s's (PF-S fix round 4: "after a journaled resolve mark-failed of every open attempt at nonce n
// on a chain, a claw-back intent at nonce n is accepted in the claw-back family; nothing else may reuse n"); the close is M5's (api
// ledger.ts openInFlight: a close is accepted once every open attempt is marked failed or settled; the cap keeps counting the
// marked-failed attempt). This file was *.gate.ts until the M5 merge, where it passed against the merged api/ and was renamed so the
// integration suite runs it. The engine side (lane-e): the claw-back signs at the agreed `latest` nonce, which is n (core:
// test/executor/settled-rerun.test.ts I-1 (a) runs it end to end on the fake API).
//
// The journal sequence the engine writes (cli, its gen), then the operator's resolve and the claw-back:
//   intent {txId A, copy 1, part 1, eth {nonce n, …}} → sent {A, unknown} → [a takeover: reconcile {A, adopted}]
//   → stuck {A, reason "… not known to every verified endpoint … after 3 windows …" | "… cannot be sent again (…)" | "stopped by the operator while …"}
//   → stopped {reason "stuck: …"}                                  (the chain: STUCK over STOPPED)
//   → resolved {A, mark-failed} (operator)                          (STOPPED, nothing open)
//   → clawback-intent {txId C, to, value, eth {nonce n, …}} → clawback-sent {C, …} → clawback-included {C, value, fee} → clawback-readback
// ALL DATA IS SYNTHETIC. The in-process API listens on 127.0.0.1 port 0 only (helpers.startApi), as ledger-equivalence does.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { JournalEvent } from '../../packages/core/src/contracts/index.ts'
import { laneConfigOf } from '../../packages/core/src/executor/executor.ts'
import { planLaneCopy } from '../../packages/core/src/engine/lane.js'
import { ethGasLimit } from '../../packages/core/src/chains/plan.js'
import { sha256Hex } from '../../packages/core/src/job/canonical.ts'
import { CLAWBACK_TO, JOB2, JOB2_INPUT, armed, call, ethTx, rawOf, startApi } from '../../api/test/helpers.ts'

process.env.NODE_ENV = 'test'
const NULL = '0x0000000000000000000000000000000000000000'
type T = { after(fn: () => Promise<void> | void): void }

async function stuckThenMarkFailed(t: T) {
  const a = await startApi({ jobs: [JOB2_INPUT] })
  t.after(() => a.close())
  await armed(a, JOB2, ['eth', 'sol'])
  const job = await a.api.registry.load(JOB2)
  const text = (JOB2_INPUT as { message: string }).message
  const part = planLaneCopy(laneConfigOf('eth', job.def.chains.eth!, text), 1)[0].payload   // the part the API plans too (PF-S I-1)
  const append = async (type: string, data: Record<string, unknown>, by: 'cli' | 'operator' = 'cli'): Promise<string | null> => {
    try { await job.journal.append({ chain: 'eth', by, gen: by === 'operator' ? null : 1, type: type as JournalEvent['type'], data }) } catch (e) {
      const g = (e as { guardId?: string }).guardId
      if (g === undefined) throw e
      return g
    }
    return null
  }
  const A = ethTx(1), nonce = 0
  const ok = async (type: string, data: Record<string, unknown>) => assert.equal(await append(type, data), null, `${type} accepted`)
  await ok('intent', { txId: A, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: rawOf(1), payloadSha256: sha256Hex(part), reserved: '1',
    eth: { nonce, tip: '1', maxFee: '1000000000', gas: String(ethGasLimit(part.length, 0n, { amsterdam: false, toSelf: false })), to: NULL } })
  await ok('sent', { txId: A, outcome: 'unknown', reason: 'timeout' })
  await ok('stuck', { txId: A, reason: 'not known to every verified endpoint after 3 windows of 25 blocks of same-bytes rebroadcasts, its nonce unused' })
  await ok('stopped', { reason: 'stuck: (synthetic)' })
  const r = await call(a.port, { path: `/jobs/${JOB2}/chains/eth/resolve`, body: { txId: A, action: 'mark-failed', typed: null } })
  assert.equal(r.status, 200, `vt job resolve mark-failed: ${r.text}`)
  return { a, append, nonce }
}

test('MERGE GATE I-2: after stuck + resolve mark-failed of the open attempt at nonce n, a claw-back at nonce n is accepted; no job intent may reuse n', async (t) => {
  const { append, nonce } = await stuckThenMarkFailed(t)
  assert.notEqual(await append('intent', { txId: ethTx(3), copy: 1, part: 1, parts: 1, attempt: 2, replaces: ethTx(1), rawSha256: rawOf(3), payloadSha256: 'ab'.repeat(32), reserved: '1',
    eth: { nonce, tip: '2', maxFee: '2000000000', gas: '30000', to: NULL } }), null, 'nothing else reuses n: no job intent on the stopped chain')
  const claw = { txId: ethTx(2), to: CLAWBACK_TO, value: '1000000000000000', rawSha256: rawOf(2), eth: { nonce, tip: '1', maxFee: '1000000000', gas: '21000', to: CLAWBACK_TO } }
  assert.equal(await append('clawback-intent', claw), null, 'the claw-back at the same nonce n is accepted (lane-s rule; today: event.family)')
})

test('MERGE GATE I-1: after stuck + resolve mark-failed, the chain can be closed', async (t) => {
  const { a } = await stuckThenMarkFailed(t)
  const r = await call(a.port, { path: `/jobs/${JOB2}/close`, body: { chain: 'eth' } })
  assert.equal(r.status, 200, `close: ${r.text}`)
})

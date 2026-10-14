// Eminors (E7-fix2 m-3): "a btc commit without its reveal" has ONE definition (job/reduce.ts btcCommitStranded). The reducer's btcStranded accessor,
// the JobState view (intent.ts), the lane's copyInFlight and the executor's pre-start check all use it; this table pins it, and pins that the
// reducer and the JobState view agree on every attempt state of the commit. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { STRANDING_ATTEMPT, btcCommitStranded, btcStrandedIn, createReducer } from '../../src/job/index.ts'
import type { AttemptState, JobDef, JournalEvent } from '../../src/contracts/index.ts'
import { BOTH, journal, H } from './helpers.ts'

const STATES: AttemptState[] = ['intent', 'sent', 'unknown', 'rejected', 'superseded', 'included', 'expired', 'nonce-consumed', 'adopted', 'resolved-done', 'resolved-failed']
const STRANDS: Record<string, boolean> = { intent: true, sent: true, unknown: true, rejected: true, adopted: true, included: true, 'resolved-done': true,
  superseded: false, expired: false, 'nonce-consumed': false, 'resolved-failed': false }

test('the stranding table: open, rejected and landed commit attempts strand a copy; dead ones never do', () => {
  assert.deepEqual(Object.fromEntries(STATES.map((s) => [s, STRANDING_ATTEMPT.has(s)])), STRANDS)
  for (const s of STATES) {
    const commit = { copy: 1, part: 1, attempts: [{ state: s }] }
    assert.equal(btcCommitStranded([commit], () => false), STRANDS[s], `commit ${s}`)
    assert.equal(btcCommitStranded([commit], () => true), false, `commit ${s}, reveal landed`)
    assert.equal(btcCommitStranded([commit], () => false, 2), false, `commit ${s}, other copy asked`)
    assert.equal(btcCommitStranded([commit], () => false, 1), STRANDS[s], `commit ${s}, this copy asked`)
    assert.equal(btcCommitStranded([{ copy: 1, part: 2, attempts: [{ state: s }] }], () => false), false, `a reveal group never strands (${s})`)
  }
  assert.equal(btcCommitStranded([], () => false), false)
  assert.equal(btcCommitStranded([{ copy: 1, part: 1, attempts: [{ state: 'expired' }, { state: 'sent' }] }], () => false), true, 'any attempt of the group counts')
  assert.equal(btcCommitStranded([{ copy: 1, part: 1, attempts: [{ state: 'sent' }] }, { copy: 2, part: 1, attempts: [{ state: 'expired' }] }], (c) => c === 1), false, 'copy 1 revealed, copy 2 dead')
  assert.equal(btcStrandedIn([{ copy: 1, part: 1, parts: 2, state: 'open', attempts: [{ txId: 'a', gen: 1, state: 'sent' }], landedId: null, block: null, fee: null, readback: null }, { copy: 1, part: 2, parts: 2, state: 'included', attempts: [], landedId: 'b', block: '1', fee: '0', readback: true }]), false)
})

test('the reducer accessor and the JobState view agree on every commit attempt state (same journal)', () => {
  const btcDef = { ...BOTH, chains: { btc: { ...(BOTH.chains.eth as object) } } } as unknown as JobDef
  for (const state of ['intent', 'sent', 'rejected', 'included', 'expired', 'nonce-consumed', 'resolved-failed'] as const) {
    const j = journal(btcDef)
    j.ready('btc'); j.arm(['btc'])
    const txId = 'ab'.repeat(32)
    j.ex('btc', 'intent', { txId, copy: 1, part: 1, parts: 2, attempt: 1, replaces: null, rawSha256: H, payloadSha256: H, reserved: '10', btc: { kind: 'commit', pubkey: `02${'11'.repeat(32)}`, fee: '1', value: '9', inputs: [`${'cd'.repeat(32)}:0`] } })
    if (state === 'sent') j.ex('btc', 'sent', { txId, outcome: 'accepted', reason: null })
    if (state === 'rejected') j.ex('btc', 'sent', { txId, outcome: 'rejected', reason: 'x' })
    if (state === 'included') j.ex('btc', 'included', { txId, copy: 1, part: 1, attempt: 1, block: '1', fee: '1', ms: 0 })
    if (state === 'expired') j.ex('btc', 'reconcile', { txId, outcome: 'expired' })
    if (state === 'nonce-consumed') j.ex('btc', 'reconcile', { txId, outcome: 'nonce-consumed' })
    if (state === 'resolved-failed') { j.ex('btc', 'stuck', { txId, reason: 'x' }); j.api('resolved', { txId, action: 'mark-failed', typed: null }, 'btc') }
    const view = j.state().chains.btc!
    const reducer = createReducer(btcDef)
    for (const e of j.evs as JournalEvent[]) reducer.apply(e)
    assert.equal(btcStrandedIn(view.txs), reducer.btcStranded('btc'), `${state}: view ${view.txs[0]?.attempts[0]?.state} vs reducer`)
    assert.equal(reducer.btcStranded('btc'), STRANDS[view.txs[0].attempts[0].state], `${state} -> ${view.txs[0].attempts[0].state}`)
  }
})

// assertIntentAllowed (E1 review X-1): the API refuses an intent or claw-back intent the arm did not allow. Every
// refusal is job.state. ALL DATA IS SYNTHETIC. The builder arms with releaseAt 15 000 and offsets 0 s / 30 s.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { assertIntentAllowed, reduce } from '../../src/job/index.ts'
import type { Chain, JobDef, JobState } from '../../src/contracts/index.ts'
import { BOTH, ethTx, guardOf, H, journal, readJson, refusalOf, solSig } from './helpers.ts'

const DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
const START = 15_000
const ok = (s: JobState, c: Chain, now: number, kind: 'intent' | 'clawback-intent' = 'intent', target?: { copy: number; part: number }, def: JobDef = BOTH): string | null =>
  guardOf(() => assertIntentAllowed(def, s, c, now, kind, target))
const clawIntent = (txId: string, nonce: number) => ({ txId, to: DEST, value: '5', rawSha256: H, eth: { nonce, tip: '1', maxFee: '2', gas: '21000', to: DEST } })

test('not armed: no intent and no claw-back before the armed event', () => {
  const j = journal()
  j.ready('eth'); j.ready('sol')
  for (const kind of ['intent', 'clawback-intent'] as const) {
    assert.equal(ok(j.state(), 'eth', 10 ** 12, kind), 'job.state', kind)
  }
  assert.match(refusalOf(() => assertIntentAllowed(BOTH, j.state(), 'eth', 10 ** 12, 'intent')).message, /not armed/)
})

test('a chain outside the arm order (SKIPPED) or outside the def is refused', () => {
  const j = journal()
  j.ready('eth'); j.ready('sol'); j.arm(['eth'])
  assert.equal(j.state().chains.sol!.phase, 'SKIPPED')
  assert.equal(ok(j.state(), 'sol', 10 ** 12), 'job.state')
  assert.equal(ok(j.state(), 'sol', 10 ** 12, 'clawback-intent'), 'job.state')
  assert.equal(ok(j.state(), 'eth', 10 ** 12), null)
  assert.match(refusalOf(() => assertIntentAllowed(BOTH, j.state(), 'sol', 10 ** 12, 'intent')).message, /skipped at arm/)
  // a state not produced by reduce (sol RUNNING but not in the order) is still refused: the order is checked itself
  const forged: JobState = { ...j.state(), chains: { ...j.state().chains, sol: { ...j.state().chains.sol!, phase: 'RUNNING', reason: null } } }
  assert.equal(ok(forged, 'sol', 10 ** 12), 'job.state')
  assert.match(refusalOf(() => assertIntentAllowed(BOTH, forged, 'sol', 10 ** 12, 'intent')).message, /not armed in this job/)
  const ethOnly = readJson<JobDef>('journals/01-created.def.json')
  const k = journal(ethOnly)
  k.ready('eth'); k.arm(['eth'])
  assert.equal(ok(k.state(), 'sol', 10 ** 12, 'intent', undefined, ethOnly), 'job.state', 'sol is not in this def')
  assert.equal(ok(j.state(), 'sol', 10 ** 12, 'intent', undefined, ethOnly), 'job.state', 'a state with sol, judged against a def without it')
  assert.match(refusalOf(() => assertIntentAllowed(ethOnly, j.state(), 'sol', 10 ** 12, 'intent')).message, /not in this job/)
})

test('the countdown, the stagger and a Skip bind the send: nothing before startAt', () => {
  const j = journal()
  j.ready('eth'); j.ready('sol'); j.arm(['sol', 'eth'])           // sol at +0 s, eth at +30 s
  assert.equal(ok(j.state(), 'sol', START - 1), 'job.state', 'countdown not over')
  assert.match(refusalOf(() => assertIntentAllowed(BOTH, j.state(), 'sol', START - 1, 'intent')).message, /not started/)
  assert.equal(ok(j.state(), 'sol', START), null, 'at release')
  assert.equal(ok(j.state(), 'eth', START), 'job.state', 'the second chain waits for its stagger')
  assert.equal(ok(j.state(), 'eth', START + 29_999), 'job.state')
  assert.equal(ok(j.state(), 'eth', START + 30_000), null)
  j.api('skip', { releaseAt: 5_000 })
  assert.equal(ok(j.state(), 'sol', 5_000), null, 'Skip moves the release')
  assert.equal(ok(j.state(), 'eth', 5_000), 'job.state', 'but keeps the stagger')
  assert.equal(ok(j.state(), 'eth', 35_000), null)
  assert.equal(ok(j.state(), 'sol', Number.NaN), 'job.state', 'no clock, no send')
})

test('send phases: ARMED, RUNNING and PAUSED allow an intent; STUCK, settled, clawing-back and terminal phases refuse', () => {
  const j = journal()
  j.ready('eth'); j.arm(['eth'])
  const now = 10 ** 12
  assert.equal(j.state().chains.eth!.phase, 'ARMED'); assert.equal(ok(j.state(), 'eth', now), null)
  j.intent('eth', ethTx(1), 1, 1, 1)
  assert.equal(j.state().chains.eth!.phase, 'RUNNING'); assert.equal(ok(j.state(), 'eth', now), null)
  j.ex('eth', 'paused', { reason: 'tip cap' })
  assert.equal(j.state().chains.eth!.phase, 'PAUSED'); assert.equal(ok(j.state(), 'eth', now), null)
  j.ex('eth', 'stuck', { txId: ethTx(1), reason: 'outcome unknowable' })
  assert.equal(j.state().chains.eth!.phase, 'STUCK'); assert.equal(ok(j.state(), 'eth', now), 'job.state')
  j.api('resolved', { txId: ethTx(1), action: 'mark-done', typed: 'done' }, 'eth')
  j.ex('eth', 'resumed', { reason: 'resolved' })
  assert.equal(ok(j.state(), 'eth', now), null)
  for (const [type, data, phase] of [
    ['drained', { balance: '1', nextCost: '9', copy: 2 }, 'DRAINED'],
    ['copies-done', { copies: 1 }, 'COPIES_DONE'],
    ['stopped', { reason: 'operator' }, 'STOPPED'],
  ] as const) {
    const k = journal(); k.ready('eth'); k.arm(['eth']); k.intent('eth', ethTx(1), 1, 1, 1); k.land('eth', ethTx(1), 1, 1)
    k.ex('eth', type, data)
    assert.equal(k.state().chains.eth!.phase, phase)
    assert.equal(ok(k.state(), 'eth', now), 'job.state', phase)
    k.ex('eth', 'clawback-intent', clawIntent(ethTx(9), 2))
    assert.equal(k.state().chains.eth!.phase, 'CLAWING_BACK'); assert.equal(ok(k.state(), 'eth', now), 'job.state', 'CLAWING_BACK')
    k.ex('eth', 'clawback-included', { txId: ethTx(9), value: '5', fee: '1' })
    assert.equal(k.state().chains.eth!.phase, 'CLAWED_BACK'); assert.equal(ok(k.state(), 'eth', now), 'job.state', 'CLAWED_BACK')
  }
  const d = journal(); d.ready('eth'); d.arm(['eth']); d.api('close', { chain: 'eth' }, 'eth')
  assert.equal(d.state().chains.eth!.phase, 'DONE'); assert.equal(ok(d.state(), 'eth', now), 'job.state', 'DONE')
})

test('a landed part is never sent again; a replacement for an open part is allowed', () => {
  const j = journal()
  j.ready('sol'); j.arm(['sol'])
  const now = 10 ** 12
  j.intent('sol', solSig(1), 1, 1, 2); j.land('sol', solSig(1), 1, 1)
  j.intent('sol', solSig(2), 1, 2, 2)
  assert.equal(ok(j.state(), 'sol', now, 'intent', { copy: 1, part: 1 }), 'job.state')
  assert.match(refusalOf(() => assertIntentAllowed(BOTH, j.state(), 'sol', now, 'intent', { copy: 1, part: 1 })).message, /already landed/)
  assert.equal(ok(j.state(), 'sol', now, 'intent', { copy: 1, part: 2 }), null, 'a re-sign of the open part 2')
  assert.equal(ok(j.state(), 'sol', now, 'intent', { copy: 2, part: 1 }), null, 'the next copy')
  j.api('resolved', { txId: solSig(2), action: 'mark-done', typed: 'done' }, 'sol')
  assert.equal(ok(j.state(), 'sol', now, 'intent', { copy: 1, part: 2 }), 'job.state', 'resolved done counts as landed')
})

test('claw-back: only a settled chain with nothing in flight, or a replacement while one is open', () => {
  const now = 10 ** 12
  const j = journal()
  j.ready('eth'); j.arm(['eth'])
  assert.equal(ok(j.state(), 'eth', now, 'clawback-intent'), 'job.state', 'ARMED is not settled')
  j.intent('eth', ethTx(1), 1, 1, 2); j.land('eth', ethTx(1), 1, 1)
  assert.deepEqual([j.state().chains.eth!.phase, j.state().chains.eth!.openIntents], ['RUNNING', []])
  assert.equal(ok(j.state(), 'eth', now, 'clawback-intent'), 'job.state', 'RUNNING is not settled, even with nothing open')
  j.intent('eth', ethTx(2), 1, 2, 2)
  j.api('stopped', { reason: 'operator' }, 'eth')
  assert.equal(j.state().chains.eth!.phase, 'STOPPED')
  assert.equal(ok(j.state(), 'eth', now, 'clawback-intent'), 'job.state', 'an open job attempt is still in flight')
  assert.match(refusalOf(() => assertIntentAllowed(BOTH, j.state(), 'eth', now, 'clawback-intent')).message, /nothing is in flight/)
  j.ex('eth', 'reconcile', { txId: ethTx(2), outcome: 'expired' })
  assert.equal(ok(j.state(), 'eth', now, 'clawback-intent'), null, 'STOPPED, nothing open')
  j.ex('eth', 'clawback-intent', clawIntent(ethTx(9), 1))
  assert.equal(ok(j.state(), 'eth', now, 'clawback-intent'), null, 'a fee bump replaces the open claw-back')
  j.ex('eth', 'clawback-failed', { txId: ethTx(9), reason: 'rejected' })
  assert.equal(j.state().chains.eth!.phase, 'STOPPED')
  assert.equal(ok(j.state(), 'eth', now, 'clawback-intent'), null, 'a failed claw-back may be retried')
  j.ex('eth', 'clawback-intent', clawIntent(ethTx(10), 1)); j.ex('eth', 'clawback-included', { txId: ethTx(10), value: '5', fee: '1' })
  assert.equal(ok(j.state(), 'eth', now, 'clawback-intent'), 'job.state', 'CLAWED_BACK is terminal')
})

test('claw-back: a stuck job attempt also counts as in flight (a state not produced by reduce, which overlays STUCK)', () => {
  const j = journal()
  j.ready('eth'); j.arm(['eth']); j.intent('eth', ethTx(1), 1, 1, 1); j.ex('eth', 'stopped', { reason: 'operator' })
  j.ex('eth', 'reconcile', { txId: ethTx(1), outcome: 'expired' })
  const s = j.state()
  assert.equal(ok(s, 'eth', 10 ** 12, 'clawback-intent'), null)
  const cs = s.chains.eth!
  const forged: JobState = { ...s, chains: { ...s.chains, eth: { ...cs, txs: cs.txs.map((t) => ({ ...t, state: 'stuck' as const })) } } }
  assert.equal(ok(forged, 'eth', 10 ** 12, 'clawback-intent'), 'job.state')
})

test('a corrupt journal refuses every intent', () => {
  const j = journal()
  j.ready('eth'); j.arm(['eth'])
  const s = { ...j.state(), phase: 'CORRUPT' as const, corrupt: 'bad hash link at seq 3' }
  assert.equal(ok(s, 'eth', 10 ** 12), 'job.state')
  assert.equal(ok(s, 'eth', 10 ** 12, 'clawback-intent'), 'job.state')
  assert.deepEqual(reduce(BOTH, j.evs).corrupt, null)
})

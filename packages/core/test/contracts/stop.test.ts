// R79b: the stop-reason classes (contracts/stop.ts) — one table, every lane reads it; a missing or unknown code is FINAL; a FINAL fact
// of the journal makes any stop FINAL; the reducer carries the code while the base is STOPPED; the event shape takes a known code only.
// ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  FINAL_STOP_WAY_OUT, STOP_CODES, STOP_CODE_FACT, STOP_CODE_LIST, finalStopText, httpStatusFor, isGuardId, isStopCode, stopClassOf, stopCodeClass,
} from '../../src/contracts/index.ts'
import type { ChainState, JobState, StopFacts } from '../../src/contracts/index.ts'
import { eventRefusal } from '../../src/job/index.ts'
import { validateEvent } from '../../src/job/events.ts'
import { BOTH, ethTx, journal } from '../job/helpers.ts'

test('R79b: the table — exactly these codes, RESUMABLE only for what the operator can fix and then continue', () => {
  assert.deepEqual(Object.fromEntries(STOP_CODE_LIST.map((c) => [c, STOP_CODES[c].cls])), {
    'operator-stop': 'resumable', 'start-check': 'resumable', 'rpc-unavailable': 'resumable',
    'readback-mismatch': 'final', reverted: 'final', 'reassembly-mismatch': 'final', eip7702: 'final', 'spend-cap': 'final',
    stuck: 'final', 'tx-failed': 'final', exhausted: 'final', integrity: 'final',
  })
  for (const c of STOP_CODE_LIST) { assert.ok(isStopCode(c)); assert.ok(STOP_CODES[c].what.length > 10, c) }
  // fail closed: anything else is FINAL
  for (const x of [undefined, null, '', 'operator', 'OPERATOR-STOP', 'toString', '__proto__', 'constructor', 1, true, {}]) {
    assert.equal(isStopCode(x), false, String(x)); assert.equal(stopCodeClass(x), 'final', String(x))
  }
  assert.equal(stopCodeClass('operator-stop'), 'resumable')
  assert.equal(stopCodeClass('spend-cap'), 'final')
})

test('R79b: resume.final-stop is in the union, 409', () => {
  assert.ok(isGuardId('resume.final-stop'))
  assert.equal(httpStatusFor('resume.final-stop'), 409)
  assert.equal(isGuardId('resume.final'), false)
})

const facts = (o: Partial<StopFacts> = {}): StopFacts => ({ txs: [], reassembled: [], ...o })
const tx = (o: Partial<ChainState['txs'][number]> = {}): ChainState['txs'][number] =>
  ({ copy: 1, part: 1, parts: 1, attempts: [{ txId: ethTx(1), gen: 1, state: 'included' }], state: 'included', landedId: ethTx(1), block: '7', fee: '1', readback: true, ...o })

test('R79b: stopClassOf — a FINAL code, then the FINAL facts of the journal, then a RESUMABLE code; anything else FINAL', () => {
  assert.deepEqual(stopClassOf(facts({ stopCode: 'operator-stop' })), { cls: 'resumable', code: 'operator-stop', why: STOP_CODES['operator-stop'].what })
  assert.deepEqual(stopClassOf(facts({ stopCode: 'readback-mismatch' })), { cls: 'final', code: 'readback-mismatch', why: STOP_CODES['readback-mismatch'].what })
  const none = stopClassOf(facts())
  assert.equal(none.cls, 'final'); assert.equal(none.code, null); assert.match(none.why, /no reason code/)
  assert.equal(stopClassOf(facts({ stopCode: 'nope' as never })).cls, 'final', 'an unknown code is FINAL')
  // a RESUMABLE code with a FINAL fact is FINAL, the fact named
  const cases: Array<[string, Partial<StopFacts>, RegExp]> = [
    ['delegated', { delegated: true }, /EIP-7702/],
    ['readback false', { txs: [tx({ readback: false })] }, /does not read back/],
    ['reassembly', { reassembled: [{ copy: 1, ok: false }] }, /did not reassemble/],
    ['mark-failed', { txs: [tx({ state: 'open', landedId: null, readback: null, attempts: [{ txId: ethTx(2), gen: 1, state: 'resolved-failed' }] })] }, /mark-failed/],
    ['stuck', { txs: [tx({ state: 'stuck', landedId: null, readback: null, attempts: [{ txId: ethTx(3), gen: 1, state: 'sent' }] })] }, /stuck/],
  ]
  for (const [name, o, why] of cases) {
    const v = stopClassOf(facts({ stopCode: 'operator-stop', ...o }))
    assert.equal(v.cls, 'final', name); assert.equal(v.code, 'operator-stop', name); assert.match(v.why, why, name)
  }
  // facts that are not FINAL: a landed part read back, a part whose attempts all expired (re-signed at the resume), a readback not yet read
  for (const o of [{ txs: [tx()] }, { txs: [tx({ state: 'failed', landedId: null, readback: null, attempts: [{ txId: ethTx(4), gen: 1, state: 'expired' }] })] },
    { txs: [tx({ readback: null })] }, { reassembled: [{ copy: 1, ok: true }] }]) {
    assert.equal(stopClassOf(facts({ stopCode: 'start-check', ...o })).cls, 'resumable', JSON.stringify(o))
  }
  const t = finalStopText('eth', stopClassOf(facts({ stopCode: 'spend-cap' })))
  assert.ok(t.startsWith('eth is stopped for good: '), t); assert.ok(t.includes('(spend-cap)'), t); assert.ok(t.endsWith(FINAL_STOP_WAY_OUT), t)
})

const chainOf = (s: JobState): ChainState => s.chains.eth!
const mk = () => { const j = journal(); j.ready('eth'); j.arm(['eth']); return j }

test('R79b: the reducer carries the journaled code while the base is STOPPED; a later phase event or a settle clears it', () => {
  const j = mk(); j.ex('eth', 'stopped', { reason: 'r', code: 'operator-stop' })
  assert.equal(chainOf(j.state()).stopCode, 'operator-stop')
  assert.equal(chainOf(j.state()).stopClass, 'resumable')
  assert.equal(stopClassOf(chainOf(j.state())).cls, 'resumable')
  const old = mk(); old.ex('eth', 'stopped', { reason: 'r' })
  assert.equal('stopCode' in chainOf(old.state()), false, 'a journal from before R79b: no code')
  assert.equal(chainOf(old.state()).stopClass, 'final', 'no code: final (fail closed)')
  const fin = mk(); fin.intent('eth', ethTx(1), 1, 1, 1); fin.land('eth', ethTx(1), 1, 1, '10', false); fin.ex('eth', 'stopped', { reason: 'readback mismatch', code: 'readback-mismatch' })
  assert.equal(chainOf(fin.state()).stopCode, 'readback-mismatch'); assert.equal(chainOf(fin.state()).stopClass, 'final')
  // a resumable code over a FINAL fact of the journal: final (a part read back not ok, then an operator stop)
  const ff = mk(); ff.intent('eth', ethTx(1), 1, 1, 1); ff.land('eth', ethTx(1), 1, 1, '10', false); ff.ex('eth', 'stopped', { reason: 'r', code: 'operator-stop' })
  assert.equal(chainOf(ff.state()).stopCode, 'operator-stop'); assert.equal(chainOf(ff.state()).stopClass, 'final')
  // only a chain whose base is STOPPED has them
  const run = mk(); run.intent('eth', ethTx(1), 1, 1, 1)
  assert.equal('stopClass' in chainOf(run.state()), false); assert.equal('stopCode' in chainOf(run.state()), false)
  // the operator's resume keeps the code (the class is the stop's); `resumed` moves the base on and clears it
  const r = mk(); r.ex('eth', 'stopped', { reason: 'r', code: 'operator-stop' }); r.api('resume-requested', { chain: 'eth' }, 'eth')
  assert.equal(chainOf(r.state()).stopCode, 'operator-stop')
  assert.equal(chainOf(r.state()).stopClass, 'resumable')
  r.ex('eth', 'resumed', { reason: 'operator' })
  assert.equal(chainOf(r.state()).phase, 'RUNNING'); assert.equal('stopCode' in chainOf(r.state()), false); assert.equal('stopClass' in chainOf(r.state()), false)
  // a latched stop: phase events are refused by the gate and do not move the base, so the code stays
  const l = mk(); l.ex('eth', 'stopped', { reason: 'r', code: 'spend-cap' }); l.ex('eth', 'paused', { reason: 'x' })
  assert.equal(chainOf(l.state()).stopCode, 'spend-cap')
  // settled: a close (DONE) shows no code
  const d = mk(); d.ex('eth', 'stopped', { reason: 'r', code: 'operator-stop' }); d.api('close', { chain: 'eth' }, 'eth')
  assert.equal(chainOf(d.state()).phase, 'DONE'); assert.equal('stopCode' in chainOf(d.state()), false); assert.equal('stopClass' in chainOf(d.state()), false)
  // the gate takes a `stopped` with a code on a running chain like one without
  const g = mk(); g.intent('eth', ethTx(1), 1, 1, 1); g.land('eth', ethTx(1), 1, 1)
  assert.equal(eventRefusal(BOTH, g.state(), { chain: 'eth', type: 'stopped', data: { reason: 'r', code: 'readback-mismatch' } }), null)
})

test('R79b: the `stopped` event shape takes a known code (optional), nothing else', () => {
  const v = (data: Record<string, unknown>): string | null => { try { validateEvent('stopped', data, 'cli'); return null } catch (e) { return (e as { guardId?: string }).guardId ?? 'thrown' } }
  for (const c of STOP_CODE_LIST) assert.equal(v({ reason: 'x', code: c }), null, c)
  assert.equal(v({ reason: 'x' }), null, 'optional: journals from before R79b replay')
  assert.equal(v({ reason: 'x', code: 'operator-stop', delegated: true }), null)
  for (const bad of ['', 'nope', 'OPERATOR-STOP', null, 1, true]) assert.equal(v({ reason: 'x', code: bad }), 'event.shape', String(bad))
})

test('final round m-4: which FINAL codes a journal fact backs — with the code swapped for a resumable one, a backed stop stays final from the journal; an unbacked one is final only by its code (pinned by the lane code tests)', () => {
  // each cause as the engine journals it, then its stop journaled with the RESUMABLE code operator-stop (a regression's mapping)
  const facts: Record<string, (j: ReturnType<typeof mk>) => void> = {
    'readback-mismatch': (j) => { j.intent('eth', ethTx(1), 1, 1, 1); j.land('eth', ethTx(1), 1, 1, '10', false) },
    reverted: (j) => { j.intent('eth', ethTx(1), 1, 1, 1); j.land('eth', ethTx(1), 1, 1, '10', false) },   // status 0: readback not ok (ethFinish)
    'reassembly-mismatch': (j) => { j.intent('eth', ethTx(1), 1, 1, 1); j.land('eth', ethTx(1), 1, 1); j.ex('eth', 'reassembled', { copy: 1, ok: false, sha256: 'b'.repeat(64) }) },
    stuck: (j) => { j.intent('eth', ethTx(1), 1, 1, 1); j.ex('eth', 'sent', { txId: ethTx(1), outcome: 'unknown', reason: 'timeout' }); j.ex('eth', 'stuck', { txId: ethTx(1), reason: 'not known' }) },
  }
  for (const code of STOP_CODE_LIST) {
    const backed = STOP_CODE_FACT[code] !== null
    const j = mk()
    facts[code]?.(j)
    j.ex('eth', 'stopped', { reason: 'r', code: 'operator-stop', ...(code === 'eip7702' ? { delegated: true } : {}) })
    const cls = chainOf(j.state()).stopClass
    if (STOP_CODES[code].cls === 'resumable') assert.equal(backed, false, code)
    else if (backed) assert.equal(cls, 'final', `${code}: final from the journal's fact (${STOP_CODE_FACT[code]})`)
    else assert.equal(cls, 'resumable', `${code}: no journal fact — its class rests on the code (lane: test/engine/stop-codes.test.ts; API: lane S)`)
  }
  assert.deepEqual(STOP_CODE_LIST.filter((c) => STOP_CODES[c].cls === 'final' && STOP_CODE_FACT[c] === null), ['spend-cap', 'tx-failed', 'exhausted', 'integrity'])
})

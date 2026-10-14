// reduce(def, events) → JobState and isChainTerminal (spec §4.2; semantics in src/contracts/types.ts). The reducer
// is a pure fold. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { isChainTerminal, jobId, reduce, startAt } from '../../src/job/index.ts'
import type { Chain, ChainState, JobDef, JobState, JournalEvent } from '../../src/contracts/index.ts'
import { BOTH, CAP, deepFreeze, ethTx, fixture, H, journal, readJson, solSig } from './helpers.ts'

const index = readJson<{ vectors: Array<{ name: string }> }>('journals/index.json')
const eventsOf = (name: string): JournalEvent[] => readFileSync(fixture(`journals/${name}.jsonl`), 'utf8').split('\n').filter((l) => l !== '').map((l) => JSON.parse(l) as JournalEvent)

test('there are at least the 14 planned vectors (plus the split and SKIPPED ones)', () => {
  assert.ok(index.vectors.length >= 14)
  for (const n of ['01-created', '04-intent', '06-eth-replacement', '08-takeover', '09a-stuck', '12-clawback', '13-resume-part', '14-stopped', '15a-skipped']) {
    assert.ok(index.vectors.some((v) => v.name === n), n)
  }
})

for (const { name } of index.vectors) {
  test(`journal vector ${name}: reduce deep-equals the pinned state; isChainTerminal agrees`, () => {
    const def = readJson<JobDef>(`journals/${name}.def.json`)
    const evs = eventsOf(name)
    assert.equal(jobId(def), (evs[0].data as { jobId: string }).jobId)
    const state = reduce(deepFreeze(def), deepFreeze(evs))
    assert.deepEqual(state, readJson<JobState>(`journals/${name}.state.json`))
    for (const cs of Object.values(state.chains)) {
      const terminal = (cs!.phase === 'DONE' || cs!.phase === 'CLAWED_BACK' || cs!.phase === 'SKIPPED') && cs!.openIntents.length === 0
      assert.equal(isChainTerminal(cs!), terminal, cs!.phase)
    }
    assert.deepEqual(reduce(def, evs), state, 'deterministic')
  })
}

// ---- the rules the vectors do not reach (journal builder in helpers.ts) ----------------------------------------
const chain = (s: JobState, c: Chain): ChainState => s.chains[c]!

test('job phase DONE only when every chain is terminal (DONE, CLAWED_BACK, SKIPPED; not STOPPED) with no open intents', () => {
  const j = journal()
  j.ready('eth'); j.ready('sol'); j.arm(['eth', 'sol'])
  j.intent('eth', ethTx(1), 1, 1, 1); j.land('eth', ethTx(1), 1, 1); j.ex('eth', 'copies-done', { copies: 1 }); j.api('close', { chain: 'eth' }, 'eth')
  j.intent('sol', solSig(1), 1, 1, 1)
  assert.equal(chain(j.state(), 'eth').phase, 'DONE')
  assert.equal(isChainTerminal(chain(j.state(), 'eth')), true)
  assert.equal(j.state().phase, 'RUNNING', 'sol is still running')
  j.land('sol', solSig(1), 1, 1); j.ex('sol', 'paused', { reason: 'waiting' })
  assert.equal(j.state().phase, 'RUNNING', 'PAUSED counts as RUNNING')
  j.ex('sol', 'stopped', { reason: 'stopped by the operator' })
  assert.equal(chain(j.state(), 'sol').phase, 'STOPPED')
  assert.equal(isChainTerminal(chain(j.state(), 'sol')), false, 'STOPPED keeps the key busy (ruling 5)')
  assert.equal(j.state().phase, 'ARMED', 'final round F18-2: a STOPPED chain is not terminal — the job is not DONE (it was DONE before)')
  j.api('close', { chain: 'sol' }, 'sol')
  assert.equal(j.state().phase, 'DONE', 'every chain terminal: DONE')
})

test('final round F18-2: the job phase through a stop / resume cycle — DONE only when every chain is terminal; a stopped chain reads the same (ARMED) before and after the resume, as COPIES_DONE does', () => {
  const j = journal(readJson<JobDef>('journals/05b-closed.def.json'))   // eth only
  j.ready('eth'); j.arm(['eth'])
  const seen: Array<[string, string]> = []
  const look = (what: string): void => { seen.push([what, `${j.state().phase}/${chain(j.state(), 'eth').phase}`]) }
  look('armed')
  j.intent('eth', ethTx(1), 1, 1, 1); j.land('eth', ethTx(1), 1, 1); look('running')
  j.api('stop-requested', { chain: 'eth' }, 'eth'); j.ex('eth', 'stopped', { reason: 'stopped by the operator', code: 'operator-stop' }); look('stopped')
  j.api('resume-requested', { chain: 'eth' }, null); look('resumed (not reopened yet)')
  j.ex('eth', 'resumed', { reason: 'operator' }); look('reopened')
  j.ex('eth', 'stopped', { reason: 'stopped again', code: 'operator-stop' }); look('stopped again')
  j.api('resume-requested', { chain: 'eth' }, null); j.ex('eth', 'resumed', { reason: 'operator' }); j.ex('eth', 'copies-done', { copies: 1 }); look('copies done')
  j.api('close', { chain: 'eth' }, 'eth'); look('closed')
  assert.deepEqual(seen, [
    ['armed', 'ARMED/ARMED'], ['running', 'RUNNING/RUNNING'], ['stopped', 'ARMED/STOPPED'], ['resumed (not reopened yet)', 'ARMED/STOPPED'],
    ['reopened', 'RUNNING/RUNNING'], ['stopped again', 'ARMED/STOPPED'], ['copies done', 'ARMED/COPIES_DONE'], ['closed', 'DONE/DONE'],
  ])
  // a FINAL stop is not terminal either (claw back or close first)
  const f = journal(readJson<JobDef>('journals/05b-closed.def.json'))
  f.ready('eth'); f.arm(['eth']); f.intent('eth', ethTx(1), 1, 1, 1); f.land('eth', ethTx(1), 1, 1, '10', false); f.ex('eth', 'stopped', { reason: 'readback mismatch', code: 'readback-mismatch' })
  assert.deepEqual([f.state().phase, chain(f.state(), 'eth').stopClass], ['ARMED', 'final'])
  assert.equal(isChainTerminal(chain(f.state(), 'eth')), false)
})

test('a chain closed while an intent is still open is not terminal, and the job is not DONE', () => {
  const j = journal(readJson<JobDef>('journals/05b-closed.def.json'))
  j.ready('eth'); j.arm(['eth'])
  j.intent('eth', ethTx(1), 1, 1, 1); j.ex('eth', 'sent', { txId: ethTx(1), outcome: 'accepted', reason: null })
  j.api('close', { chain: 'eth' }, 'eth')
  const s = j.state()
  assert.equal(chain(s, 'eth').phase, 'DONE')
  assert.deepEqual(chain(s, 'eth').openIntents, [ethTx(1)])
  assert.equal(isChainTerminal(chain(s, 'eth')), false)
  assert.notEqual(s.phase, 'DONE')
})

test('copiesIncluded counts only copies whose parts all have included + readback ok', () => {
  const j = journal()
  j.ready('sol'); j.arm(['sol'])
  j.intent('sol', solSig(11), 1, 1, 2); j.land('sol', solSig(11), 1, 1)
  j.intent('sol', solSig(12), 1, 2, 2); j.land('sol', solSig(12), 1, 2)            // copy 1: both parts read back
  j.intent('sol', solSig(21), 2, 1, 2); j.land('sol', solSig(21), 2, 1)
  j.intent('sol', solSig(22), 2, 2, 2); j.land('sol', solSig(22), 2, 2, '10', false) // copy 2: part 2 read back NOT ok
  j.intent('sol', solSig(31), 3, 1, 2); j.land('sol', solSig(31), 3, 1)
  j.intent('sol', solSig(32), 3, 2, 2); j.land('sol', solSig(32), 3, 2, '10', null)  // copy 3: part 2 never read back
  let s = chain(j.state(), 'sol')
  assert.equal(s.copiesIncluded, 1)
  assert.deepEqual(s.resume, { copy: 3, nextPart: 2 })
  assert.equal(s.spent, '60')
  j.ex('sol', 'readback', { txId: solSig(32), ok: true, detail: 'payload bytes match' })
  s = chain(j.state(), 'sol')
  assert.equal(s.copiesIncluded, 2)
  assert.equal(s.resume, null, 'the current copy is complete')
})

test('a resolved mark-done part counts as landed but not as read back (no copy credit, resume stays)', () => {
  const j = journal()
  j.ready('eth'); j.arm(['eth'])
  j.intent('eth', ethTx(1), 1, 1, 1); j.ex('eth', 'sent', { txId: ethTx(1), outcome: 'unknown', reason: null })
  j.ex('eth', 'stuck', { txId: ethTx(1), reason: 'unknowable' })
  assert.equal(chain(j.state(), 'eth').phase, 'STUCK')
  assert.equal(chain(j.state(), 'eth').reason, 'unknowable')
  j.api('resolved', { txId: ethTx(1), action: 'mark-done', typed: null }, 'eth')
  const s = chain(j.state(), 'eth')
  assert.equal(s.phase, 'RUNNING')
  assert.equal(s.reason, null)
  assert.equal(s.copiesIncluded, 0)
  assert.deepEqual(s.resume, { copy: 1, nextPart: 1 })
  assert.equal(s.txs[0].state, 'included')
  assert.equal(s.txs[0].fee, null)
  assert.equal(s.spent, '42000', 'CC-2a: no journaled fee → its worst case gas × maxFee (21000 × 2), never 0')
})

test('attempt states: rejected closes, adopted stays open, reconcile included lands with its fee, mark-failed closes', () => {
  const j = journal()
  j.ready('eth'); j.arm(['eth'])
  j.intent('eth', ethTx(1), 1, 1, 1); j.ex('eth', 'sent', { txId: ethTx(1), outcome: 'rejected', reason: 'nonce too low' })
  let s = chain(j.state(), 'eth')
  assert.equal(s.txs[0].attempts[0].state, 'rejected')
  assert.equal(s.txs[0].state, 'failed')
  assert.deepEqual(s.openIntents, [])
  j.intent('eth', ethTx(2), 2, 1, 1, 1, 1); j.ex('eth', 'sent', { txId: ethTx(2), outcome: 'accepted', reason: null })
  j.ex('eth', 'reconcile', { txId: ethTx(2), outcome: 'adopted' }, 2)
  s = chain(j.state(), 'eth')
  assert.equal(s.txs[1].attempts[0].state, 'adopted')
  assert.deepEqual(s.openIntents, [ethTx(2)])
  j.ex('eth', 'reconcile', { txId: ethTx(2), outcome: 'included', block: '9', fee: '77' }, 2)
  s = chain(j.state(), 'eth')
  assert.equal(s.txs[1].state, 'included')
  assert.equal(s.txs[1].block, '9')
  assert.equal(s.spent, '77')
  assert.deepEqual(s.openIntents, [])
  j.intent('eth', ethTx(3), 3, 1, 1); j.ex('eth', 'sent', { txId: ethTx(3), outcome: 'unknown', reason: null })
  j.api('resolved', { txId: ethTx(3), action: 'mark-failed', typed: null }, 'eth')
  s = chain(j.state(), 'eth')
  assert.equal(s.txs[2].attempts[0].state, 'resolved-failed')
  assert.equal(s.txs[2].state, 'failed')
  assert.deepEqual(s.openIntents, [])
  assert.deepEqual([s.copy, s.attempt], [3, 1])
})

test('expired and nonce-consumed attempts are closed; a later sibling still lands', () => {
  const j = journal()
  j.ready('eth'); j.arm(['eth'])
  j.intent('eth', ethTx(1), 1, 1, 1); j.ex('eth', 'reconcile', { txId: ethTx(1), outcome: 'nonce-consumed' })
  let s = chain(j.state(), 'eth')
  assert.equal(s.txs[0].state, 'failed')
  assert.deepEqual(s.openIntents, [])
  j.intent('eth', ethTx(2), 1, 1, 1, 2)
  s = chain(j.state(), 'eth')
  assert.deepEqual(s.txs[0].attempts.map((a) => a.state), ['nonce-consumed', 'intent'])
  assert.equal(s.txs[0].state, 'open')
  assert.deepEqual(s.openIntents, [ethTx(2)])
})

test('claw-back: failed returns to the settled phase (ok false); a reconcile other than adopted closes the open claw-back intent', () => {
  const j = journal()
  j.ready('eth'); j.arm(['eth'])
  j.intent('eth', ethTx(1), 1, 1, 1); j.land('eth', ethTx(1), 1, 1); j.ex('eth', 'drained', { balance: '1', nextCost: '9', copy: 2 })
  j.ex('eth', 'clawback-intent', { txId: ethTx(9), to: '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6', value: '5', rawSha256: H, eth: { nonce: 2, tip: '1', maxFee: '2', gas: '21000', to: '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6' } })
  let s = chain(j.state(), 'eth')
  assert.equal(s.phase, 'CLAWING_BACK')
  assert.equal(j.state().phase, 'RUNNING')
  assert.deepEqual(s.openIntents, [ethTx(9)])
  assert.deepEqual(s.clawback, { txId: ethTx(9), to: '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6', value: '5', ok: null, landed: false })
  j.ex('eth', 'clawback-failed', { txId: ethTx(9), reason: 'replaced' })
  s = chain(j.state(), 'eth')
  assert.equal(s.phase, 'DRAINED')
  assert.equal(s.clawback!.ok, false)
  assert.deepEqual(s.openIntents, [])
  j.ex('eth', 'clawback-intent', { txId: ethTx(10), to: '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6', value: '4', rawSha256: H, eth: { nonce: 2, tip: '2', maxFee: '3', gas: '21000', to: '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6' } })
  j.ex('eth', 'reconcile', { txId: ethTx(10), outcome: 'adopted' })
  assert.deepEqual(chain(j.state(), 'eth').openIntents, [ethTx(10)], 'adopted stays open')
  j.ex('eth', 'reconcile', { txId: ethTx(10), outcome: 'expired' })
  assert.deepEqual(chain(j.state(), 'eth').openIntents, [])
})

// ---- CC-2a: chain evidence wins (E2 re-review D-1), spend without a journaled fee, the claw-back family (D-2) ----
const DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
const clawIntent = (txId: string, value: string, maxFee = '2') => ({ txId, to: DEST, value, rawSha256: H, eth: { nonce: 2, tip: '1', maxFee, gas: '21000', to: DEST } })
const drained = () => {
  const j = journal()
  j.ready('eth'); j.arm(['eth'])
  j.intent('eth', ethTx(1), 1, 1, 1); j.land('eth', ethTx(1), 1, 1); j.ex('eth', 'drained', { balance: '1', nextCost: '9', copy: 2 })
  return j
}

test('D-1: an inclusion lands an attempt journaled expired, nonce-consumed, rejected or resolved-failed; the open sibling is superseded; never re-sent', () => {
  for (const before of [{ type: 'reconcile', d: { outcome: 'expired' } }, { type: 'reconcile', d: { outcome: 'nonce-consumed' } }, { type: 'sent', d: { outcome: 'rejected', reason: 'x' } }, { type: 'resolved', d: { action: 'mark-failed', typed: null } }] as const) {
    for (const how of ['included', 'reconcile', 'mark-done'] as const) {
      const j = journal()
      j.ready('sol'); j.arm(['sol'])
      j.intent('sol', solSig(1), 1, 1, 1)
      if (before.type === 'resolved') j.api('resolved', { txId: solSig(1), ...before.d }, 'sol')
      else j.ex('sol', before.type as JournalEvent['type'], { txId: solSig(1), ...before.d })
      j.intent('sol', solSig(2), 1, 1, 1, 2)                                     // the re-sign, still open
      if (how === 'included') j.ex('sol', 'included', { txId: solSig(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '5000', ms: 1 })
      else if (how === 'reconcile') j.ex('sol', 'reconcile', { txId: solSig(1), outcome: 'included', block: '9', fee: '5000' })
      else j.api('resolved', { txId: solSig(1), action: 'mark-done', typed: null }, 'sol')
      const s = chain(j.state(), 'sol'), tag = `${before.type} ${JSON.stringify(before.d)} → ${how}`
      assert.deepEqual(s.txs[0].attempts.map((a) => a.state), [how === 'mark-done' ? 'resolved-done' : 'included', 'superseded'], tag)
      assert.equal(s.txs[0].state, 'included', tag); assert.equal(s.txs[0].landedId, solSig(1), tag)
      assert.equal(s.spent, '5000', `${tag}: the fee (or the worst case, 5000) is spent`)
      assert.deepEqual(s.openIntents, [], tag)
    }
  }
})

test('D-1: a second attempt that also lands is landed and paid too; the TxView keeps the first landing', () => {
  const j = journal()
  j.ready('sol'); j.arm(['sol'])
  j.intent('sol', solSig(1), 1, 1, 1); j.ex('sol', 'reconcile', { txId: solSig(1), outcome: 'expired' })
  j.intent('sol', solSig(2), 1, 1, 1, 2)
  j.ex('sol', 'included', { txId: solSig(2), copy: 1, part: 1, attempt: 2, block: '10', fee: '6000', ms: 1 })
  j.ex('sol', 'included', { txId: solSig(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '5000', ms: 1 })
  const s = chain(j.state(), 'sol')
  assert.deepEqual(s.txs[0].attempts.map((a) => a.state), ['included', 'included'])
  assert.deepEqual([s.txs[0].landedId, s.txs[0].block, s.txs[0].fee], [solSig(2), '10', '6000'])
  assert.equal(s.spent, '11000', 'both were paid')
  j.ex('sol', 'included', { txId: solSig(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '5000', ms: 1 })
  assert.equal(chain(j.state(), 'sol').spent, '11000', 'an inclusion journaled twice is paid once')
})

test('spent: a landed attempt without a journaled fee (mark-done, reconcile included without fee) counts its worst case', () => {
  const j = journal()
  j.ready('eth'); j.arm(['eth'])
  j.intent('eth', ethTx(1), 1, 1, 1); j.ex('eth', 'reconcile', { txId: ethTx(1), outcome: 'included', block: '3' })
  assert.equal(chain(j.state(), 'eth').spent, '42000')
  assert.equal(chain(j.state(), 'eth').txs[0].fee, null, 'the TxView does not invent a fee')
})

test('D-2: every member of the claw-back dead and none landed → it fails by itself (ok false, settled phase, nothing open)', () => {
  const j = drained()
  j.ex('eth', 'clawback-intent', clawIntent(ethTx(9), '5')); j.ex('eth', 'clawback-sent', { txId: ethTx(9), outcome: 'unknown' })
  j.ex('eth', 'clawback-intent', clawIntent(ethTx(10), '4', '3'))
  let s = chain(j.state(), 'eth')
  assert.deepEqual([s.phase, s.openIntents, s.clawback!.txId, s.clawback!.ok, s.clawback!.landed], ['CLAWING_BACK', [ethTx(9), ethTx(10)], ethTx(10), null, false])
  j.ex('eth', 'reconcile', { txId: ethTx(9), outcome: 'nonce-consumed' })
  s = chain(j.state(), 'eth')
  assert.deepEqual([s.phase, s.openIntents], ['CLAWING_BACK', [ethTx(10)]], 'one member still open')
  j.ex('eth', 'reconcile', { txId: ethTx(9), outcome: 'adopted' })
  assert.deepEqual(chain(j.state(), 'eth').openIntents, [ethTx(10)], 'a dead member is never re-opened')
  j.ex('eth', 'reconcile', { txId: ethTx(10), outcome: 'expired' })
  s = chain(j.state(), 'eth')
  assert.deepEqual([s.phase, s.openIntents, s.clawback!.ok, s.clawback!.landed, s.spent], ['DRAINED', [], false, false, '10'], 'failed by itself; no fee')
  // a new claw-back may start afterwards (a new family)
  j.ex('eth', 'clawback-intent', clawIntent(ethTx(11), '3'))
  s = chain(j.state(), 'eth')
  assert.deepEqual([s.phase, s.openIntents, s.clawback!.txId], ['CLAWING_BACK', [ethTx(11)], ethTx(11)])
})

test('D-2: the operator exit — resolve mark-failed of the last open (stuck) member fails the claw-back; mark-done is not chain evidence and changes nothing', () => {
  for (const action of ['mark-failed', 'mark-done'] as const) {
    const j = drained()
    j.ex('eth', 'clawback-intent', clawIntent(ethTx(9), '5')); j.ex('eth', 'stuck', { txId: ethTx(9), reason: 'nonce used, no receipt' })
    assert.equal(chain(j.state(), 'eth').phase, 'STUCK')
    const before = j.state()
    j.api('resolved', { txId: ethTx(9), action, typed: null }, 'eth')
    const s = chain(j.state(), 'eth')
    if (action === 'mark-failed') assert.deepEqual([s.phase, s.openIntents, s.clawback!.ok, s.clawback!.landed, s.spent], ['DRAINED', [], false, false, '10'])
    else assert.deepEqual({ ...j.state(), seq: before.seq }, before, 'fail closed: still STUCK, still open, nothing spent')
  }
})

test('claw-back family: a reconcile included of a member lands it (the value its intent signed); a landed claw-back is final', () => {
  const j = drained()
  j.ex('eth', 'clawback-intent', clawIntent(ethTx(9), '5')); j.ex('eth', 'clawback-intent', clawIntent(ethTx(10), '4', '3'))
  j.ex('eth', 'reconcile', { txId: ethTx(9), outcome: 'included', block: '20', fee: '30' })
  let s = chain(j.state(), 'eth')
  assert.deepEqual([s.phase, s.openIntents, s.clawback!.txId, s.clawback!.value, s.clawback!.ok, s.clawback!.landed, s.spent], ['CLAWED_BACK', [], ethTx(9), '5', true, true, '40'])
  j.ex('eth', 'clawback-included', { txId: ethTx(9), value: '5', fee: '30' })
  j.ex('eth', 'clawback-included', { txId: ethTx(10), value: '4', fee: '31' })
  j.ex('eth', 'clawback-intent', clawIntent(ethTx(12), '1'))
  s = chain(j.state(), 'eth')
  assert.deepEqual([s.phase, s.openIntents, s.clawback!.txId, s.clawback!.value, s.spent], ['CLAWED_BACK', [], ethTx(9), '5', '40'], 'no second landing, no new member after the landing')
  j.ex('eth', 'clawback-failed', { txId: ethTx(10), reason: 'x', fee: '31' })
  s = chain(j.state(), 'eth')
  assert.deepEqual([s.phase, s.clawback!.txId, s.spent], ['CLAWED_BACK', ethTx(9), '71'], 'a fee charged on chain is spent even after the landing (fail closed)')
})

test('fail closed: an unknown reconcile outcome or resolve action changes nothing (a STUCK attempt stays STUCK)', () => {
  const j = journal()
  j.ready('eth'); j.arm(['eth'])
  j.intent('eth', ethTx(1), 1, 1, 1); j.ex('eth', 'stuck', { txId: ethTx(1), reason: 'unknowable' })
  const before = j.state()
  j.ex('eth', 'reconcile', { txId: ethTx(1), outcome: 'bogus' }); j.api('resolved', { txId: ethTx(1), action: 'bogus', typed: null }, 'eth')
  j.ex('eth', 'reconcile', { txId: ethTx(77), outcome: 'included', fee: '5' })
  assert.deepEqual({ ...j.state(), seq: before.seq }, before)
})

test('fail closed: a readback counts only for an attempt that landed (a readback before the inclusion completes nothing)', () => {
  const j = journal()
  j.ready('sol'); j.arm(['sol'])
  j.intent('sol', solSig(1), 1, 1, 1)
  j.ex('sol', 'readback', { txId: solSig(1), ok: true, detail: 'early' })
  j.ex('sol', 'included', { txId: solSig(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '5000', ms: 1 })
  const s = chain(j.state(), 'sol')
  assert.deepEqual([s.txs[0].readback, s.copiesIncluded, s.resume], [null, 0, { copy: 1, nextPart: 1 }])
})

test('fail closed: a claw-back intent without a value never defaults to 0; a readback of a member that did not land changes nothing', () => {
  const j = drained()
  const noValue: Record<string, unknown> = clawIntent(ethTx(9), '5'); delete noValue.value
  j.ex('eth', 'clawback-intent', noValue)
  j.ex('eth', 'clawback-readback', { txId: ethTx(9), ok: true, destReceived: '5', laneBalance: '0' })
  const s = chain(j.state(), 'eth')
  assert.deepEqual([s.clawback!.value, s.clawback!.ok, s.phase, s.openIntents], ['', null, 'CLAWING_BACK', [ethTx(9)]])
})

test('claw-back family: chain evidence wins over a failed family (a member found landed afterwards lands it)', () => {
  const j = drained()
  j.ex('eth', 'clawback-intent', clawIntent(ethTx(9), '5')); j.ex('eth', 'reconcile', { txId: ethTx(9), outcome: 'expired' })
  assert.equal(chain(j.state(), 'eth').phase, 'DRAINED')
  j.ex('eth', 'clawback-included', { txId: ethTx(9), value: '5', fee: '7' })
  const s = chain(j.state(), 'eth')
  assert.deepEqual([s.phase, s.clawback!.landed, s.clawback!.ok, s.spent], ['CLAWED_BACK', true, true, '17'])
})

test('skip moves releaseAt and armed.releaseAt, so startAt follows; stop/resume requests apply per chain or to all', () => {
  const j = journal()
  j.ready('eth'); j.ready('sol'); j.arm(['sol', 'eth'])
  j.api('skip', { releaseAt: 5_000 })
  let s = j.state()
  assert.equal(s.releaseAt, 5_000)
  assert.equal(s.armed!.releaseAt, 5_000)
  assert.equal(startAt(s.armed!, 'eth'), 5_000 + 30_000)
  assert.equal(j.evs[j.evs.length - 2].type, 'armed')
  assert.equal((j.evs[j.evs.length - 2].data as { releaseAt: number }).releaseAt, 15_000, 'the event itself is not mutated')
  j.api('stop-requested', { chain: null })
  s = j.state()
  assert.deepEqual([chain(s, 'eth').stopRequested, chain(s, 'sol').stopRequested], [true, true])
  j.api('resume-requested', { chain: 'sol' }, 'sol')
  s = j.state()
  assert.deepEqual([chain(s, 'eth').stopRequested, chain(s, 'sol').stopRequested], [true, false])
})

test('SKIPPED absorbs: an un-armed chain stays SKIPPED whatever follows', () => {
  const j = journal()
  j.ready('eth'); j.arm(['eth'])
  j.ready('sol'); j.intent('sol', solSig(1), 1, 1, 1)
  const s = chain(j.state(), 'sol')
  assert.equal(s.phase, 'SKIPPED')
  assert.equal(s.reason, 'not armed')
  assert.equal(isChainTerminal(s), false, 'an open intent keeps even a skipped chain busy')
})

test('key-loaded and funds never move a chain backwards; reassembled keeps one entry per copy', () => {
  const j = journal()
  j.ex('eth', 'funds', { balance: '0', affordable: true, nextCopyCost: '1' })
  assert.equal(chain(j.state(), 'eth').phase, 'AWAITING_KEY', 'funds before the key move nothing')
  j.ex('eth', 'key-loaded', { address: BOTH.chains.eth!.keyAddress })
  assert.equal(chain(j.state(), 'eth').phase, 'AWAITING_FUNDS')
  j.ex('eth', 'funds', { balance: '0', affordable: false, nextCopyCost: '1' })
  assert.equal(chain(j.state(), 'eth').phase, 'AWAITING_FUNDS')
  j.ex('eth', 'funds', { balance: '9', affordable: true, nextCopyCost: '1' })
  assert.equal(chain(j.state(), 'eth').phase, 'READY')
  j.ex('eth', 'funds', { balance: '0', affordable: false, nextCopyCost: '1' })
  assert.equal(chain(j.state(), 'eth').phase, 'AWAITING_FUNDS')
  j.ready('eth'); j.arm(['eth']); j.intent('eth', ethTx(1), 1, 1, 1)
  j.ex('eth', 'key-loaded', { address: BOTH.chains.eth!.keyAddress }); j.ex('eth', 'funds', { balance: '0', affordable: false, nextCopyCost: '1' })
  assert.equal(chain(j.state(), 'eth').phase, 'RUNNING', 'a takeover re-loading the key does not reset the phase')
  j.ex('eth', 'reassembled', { copy: 1, ok: false, sha256: H }); j.ex('eth', 'reassembled', { copy: 2, ok: true, sha256: H }); j.ex('eth', 'reassembled', { copy: 1, ok: true, sha256: H })
  assert.deepEqual(chain(j.state(), 'eth').reassembled, [{ copy: 1, ok: true }, { copy: 2, ok: true }])
})

test('events for a chain the def does not have, lease events and notes change nothing; seq is the last folded', () => {
  const def = readJson<JobDef>('journals/01-created.def.json') // eth only
  const j = journal(def)
  j.api('created', { jobId: jobId(def), defSha256: H })
  const before = j.state()
  j.ex('sol', 'key-loaded', { address: '9xx7qC7uwTAeaSo7T5Gk9canYBosFh1pMQaDmQEa83Tb' })
  j.add('eth', 'api', 'lease-acquired', { gen: 1, holder: 'browser', ttlMs: 15_000 }, 1)
  j.api('note', { text: 'hello' })
  const after = j.state()
  assert.deepEqual(Object.keys(after.chains), ['eth'])
  assert.deepEqual({ ...after, seq: 0 }, { ...before, seq: 0 })
  assert.equal(after.seq, 3)
  assert.deepEqual(reduce(def, []), { phase: 'DEFINED', armed: null, releaseAt: null, seq: 0, corrupt: null, chains: { eth: chain(before, 'eth') } })
})

test('I-1: the first armed event wins — a second one never re-arms, moves releaseAt or SKIPs a running chain', () => {
  const j = journal()
  j.ready('eth'); j.ready('sol'); j.arm(['eth', 'sol'])
  j.intent('eth', ethTx(1), 1, 1, 2); j.land('eth', ethTx(1), 1, 1)
  const before = j.state()
  assert.equal(chain(before, 'eth').phase, 'RUNNING')
  assert.deepEqual(chain(before, 'eth').resume, { copy: 1, nextPart: 2 })
  // a second armed naming only sol, with another release time
  j.api('armed', { armedAt: 50_000, releaseAt: 65_000, countdownSec: 15, schedule: { order: ['sol'], offsetSec: { sol: 0 } }, caps: { sol: CAP }, sources: {} })
  const after = j.state()
  assert.equal(chain(after, 'eth').phase, 'RUNNING', 'eth stays RUNNING (part 1 of 2 landed)')
  assert.equal(isChainTerminal(chain(after, 'eth')), false, 'and keeps its key')
  assert.deepEqual(after.armed, before.armed)
  assert.equal(after.releaseAt, 15_000)
  assert.deepEqual(after.armed!.schedule.order, ['eth', 'sol'])
  assert.equal(chain(after, 'sol').phase, 'ARMED')
  assert.equal(after.phase, 'RUNNING')
})

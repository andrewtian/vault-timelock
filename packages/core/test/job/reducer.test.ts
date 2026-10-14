// S2 review I-1 (core side) and I-3: terminal phases are absorbing for executor events, assertEventAllowed refuses
// what would revive a settled chain or fold evidence about an unknown tx, and createReducer folds one event at a time
// with the same result as reduce (random sequences, every contract vector) and O(1) accessors that agree with the
// state. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { assertEventAllowed, assertIntentAllowed, createReducer, eventRefusal, intentRefusal, isChainTerminal, reduce } from '../../src/job/index.ts'
import type { Chain, ChainState, JobDef, JobState, JournalEvent } from '../../src/contracts/index.ts'
import { CapLedger } from '../../src/gates/caps.ts'
import { BOTH, ethTx, fixture, guardOf, H, journal, readJson, seeded, solSig } from './helpers.ts'

const DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
const clawIntent = (txId: string, value = '5') => ({ txId, to: DEST, value, rawSha256: H, eth: { nonce: 2, tip: '1', maxFee: '2', gas: '21000', to: DEST } })
const chain = (s: JobState, c: Chain): ChainState => s.chains[c]!
const PHASE_EVENTS: Array<[JournalEvent['type'], Record<string, unknown>]> = [
  ['paused', { reason: 'tip cap' }], ['resumed', { reason: 'operator' }], ['drained', { balance: '1', nextCost: '9', copy: 2 }],
  ['copies-done', { copies: 1 }], ['stopped', { reason: 'operator' }],
]

// eth: copy 1 landed and read back, then settled (drained); returns the builder
function settled() {
  const j = journal()
  j.ready('eth'); j.arm(['eth'])
  j.intent('eth', ethTx(1), 1, 1, 1); j.land('eth', ethTx(1), 1, 1); j.ex('eth', 'drained', { balance: '1', nextCost: '9', copy: 2 })
  return j
}
const terminal = {
  DONE: () => { const j = settled(); j.api('close', { chain: 'eth' }, 'eth'); return j },
  CLAWED_BACK: () => { const j = settled(); j.ex('eth', 'clawback-intent', clawIntent(ethTx(9))); j.ex('eth', 'clawback-included', { txId: ethTx(9), value: '5', fee: '7' }); return j },
  CLAWING_BACK: () => { const j = settled(); j.ex('eth', 'clawback-intent', clawIntent(ethTx(9))); return j },
} as const

test('Eminors: a stopped event with delegated:true sets ChainState.delegated while the chain is unsettled; any later phase event or a settle clears it', () => {
  const mk = () => { const j = journal(); j.ready('eth'); j.arm(['eth']); return j }
  const plain = mk(); plain.ex('eth', 'stopped', { reason: 'engine.eip7702: x' })
  assert.equal('delegated' in chain(plain.state(), 'eth'), false, 'text alone sets nothing: the key is absent, not false')
  const j = mk(); j.ex('eth', 'stopped', { reason: 'engine.eip7702: x', delegated: true })
  assert.equal(chain(j.state(), 'eth').delegated, true)
  assert.equal(chain(j.state(), 'eth').phase, 'STOPPED')
  j.ex('eth', 'clawback-intent', clawIntent(ethTx(9)))
  assert.equal(chain(j.state(), 'eth').delegated, true, 'still delegated while the claw-back is open')
  j.ex('eth', 'clawback-included', { txId: ethTx(9), value: '5', fee: '7' })
  assert.equal(chain(j.state(), 'eth').phase, 'CLAWED_BACK')
  assert.equal('delegated' in chain(j.state(), 'eth'), false, 'settled: gone')
  // PF-S fix round 5 (R34-1): the stop latch — no executor phase event moves a stopped chain until the operator's resume; after it,
  // any later phase event moves the chain on and clears the flag
  for (const [type, data] of PHASE_EVENTS.filter(([t]) => t !== 'stopped')) {
    const k = mk(); k.ex('eth', 'stopped', { reason: 'engine.eip7702: x', delegated: true }); k.ex('eth', type, data)
    assert.deepEqual([chain(k.state(), 'eth').phase, chain(k.state(), 'eth').delegated, chain(k.state(), 'eth').stopLatched], ['STOPPED', true, true], `${type}: latched`)
    const r = mk(); r.ex('eth', 'stopped', { reason: 'engine.eip7702: x', delegated: true }); r.api('resume-requested', { chain: 'eth' }, 'eth'); r.ex('eth', type, data)
    assert.equal('delegated' in chain(r.state(), 'eth'), false, `${type} after the operator's resume clears it`)
    assert.equal('stopLatched' in chain(r.state(), 'eth'), false, 'the resume cleared the latch')
  }
  // Eminors fix 1 (m-6): DONE (close) hides it, a new intent clears it, SKIPPED hides it
  const dn = mk(); dn.ex('eth', 'stopped', { reason: 'engine.eip7702: x', delegated: true }); dn.api('close', { chain: 'eth' }, 'eth')
  assert.equal(chain(dn.state(), 'eth').phase, 'DONE'); assert.equal('delegated' in chain(dn.state(), 'eth'), false, 'DONE: gone')
  const sk = journal(); sk.ready('eth'); sk.ex('eth', 'stopped', { reason: 'engine.eip7702: x', delegated: true }); sk.arm(['sol'])
  assert.equal(chain(sk.state(), 'eth').phase, 'SKIPPED'); assert.equal('delegated' in chain(sk.state(), 'eth'), false, 'SKIPPED: gone')
  const ni = mk(); ni.ex('eth', 'stopped', { reason: 'engine.eip7702: x', delegated: true }); ni.api('resume-requested', { chain: 'eth' }, 'eth'); ni.intent('eth', ethTx(70), 1, 1, 1)
  assert.equal('delegated' in chain(ni.state(), 'eth'), false, 'after the operator\'s resume, an intent (the chain runs again) clears it')
  const k = mk(); k.ex('eth', 'stopped', { reason: 'engine.eip7702: x', delegated: true }); k.ex('eth', 'stopped', { reason: 'operator' })
  assert.equal('delegated' in chain(k.state(), 'eth'), false, 'a later plain stop clears it')
})

test('I-1: DONE, CLAWED_BACK and CLAWING_BACK are absorbing for executor phase events and job intents', () => {
  for (const [phase, make] of Object.entries(terminal)) {
    for (const [type, data] of PHASE_EVENTS) {
      const j = make()
      assert.equal(chain(j.state(), 'eth').phase, phase)
      j.ex('eth', type, data)
      assert.equal(chain(j.state(), 'eth').phase, phase, `${type} never moves ${phase}`)
    }
    const j = make()
    j.intent('eth', ethTx(50), 3, 1, 1)
    const cs = chain(j.state(), 'eth')
    assert.equal(cs.phase, phase, `an intent never revives ${phase}`)
    assert.ok(cs.openIntents.includes(ethTx(50)), 'but the attempt is tracked (it may land): fail closed')
    assert.equal(isChainTerminal(cs), false, 'and keeps the key busy')
  }
  const d = terminal.DONE()
  d.ex('eth', 'clawback-intent', clawIntent(ethTx(60)))
  const cs = chain(d.state(), 'eth')
  assert.deepEqual([cs.phase, cs.openIntents, isChainTerminal(cs)], ['DONE', [ethTx(60)], false], 'a claw-back intent never moves a closed chain; it is tracked')
})

test('I-1: assertEventAllowed refuses every executor phase event on DONE, CLAWED_BACK, CLAWING_BACK, SKIPPED and settled chains (JobState and reducer views)', () => {
  const views = (j: ReturnType<typeof journal>, def: JobDef = BOTH) => {
    const r = createReducer(def); for (const e of j.evs) r.apply(e)
    return [j.state(), { reducer: r, corrupt: null }] as const
  }
  for (const [phase, make] of Object.entries(terminal)) {
    for (const v of views(make())) for (const [type, data] of [...PHASE_EVENTS, ['copy-built', { copy: 3, parts: 1, bytes: [10], tight: false, level: 0 }]] as const) {
      assert.equal(guardOf(() => assertEventAllowed(BOTH, v, { chain: 'eth', type, data })), 'job.state', `${type} on ${phase}`)
    }
  }
  const sk = journal(); sk.ready('eth'); sk.ready('sol'); sk.arm(['eth'])
  for (const v of views(sk)) assert.equal(guardOf(() => assertEventAllowed(BOTH, v, { chain: 'sol', type: 'resumed', data: { reason: 'x' } })), 'job.state', 'SKIPPED')
  for (const v of views(settled())) assert.equal(guardOf(() => assertEventAllowed(BOTH, v, { chain: 'eth', type: 'resumed', data: { reason: 'x' } })), 'job.state', 'DRAINED')
  const run = journal(); run.ready('eth'); run.arm(['eth']); run.intent('eth', ethTx(1), 1, 1, 1)
  for (const v of views(run)) for (const [type, data] of PHASE_EVENTS) assert.equal(guardOf(() => assertEventAllowed(BOTH, v, { chain: 'eth', type, data })), null, `${type} while RUNNING`)
})

test('fail closed: evidence for an unknown txId, another (copy, part), a non-landed attempt or a non-member is refused (JobState and reducer views)', () => {
  const j = settled()
  j.intent('eth', ethTx(2), 2, 1, 1)                                      // open (an anomaly here, but a known attempt)
  j.ex('eth', 'clawback-intent', clawIntent(ethTx(9)))
  const r = createReducer(BOTH); for (const e of j.evs) r.apply(e)
  const cases: Array<[string, Record<string, unknown>, string | null]> = [
    ['sent', { txId: ethTx(2), outcome: 'unknown', reason: null }, null],
    ['sent', { txId: ethTx(77), outcome: 'unknown', reason: null }, 'job.state'],
    ['included', { txId: ethTx(2), copy: 2, part: 1, attempt: 1, block: '1', fee: '1', ms: 1 }, null],
    ['included', { txId: ethTx(2), copy: 1, part: 1, attempt: 1, block: '1', fee: '1', ms: 1 }, 'job.state'],
    ['included', { txId: ethTx(77), copy: 2, part: 1, attempt: 1, block: '1', fee: '1', ms: 1 }, 'job.state'],
    ['readback', { txId: ethTx(1), ok: true, detail: 'd' }, null],
    ['readback', { txId: ethTx(2), ok: true, detail: 'd' }, 'job.state'],
    ['reconcile', { txId: ethTx(2), outcome: 'adopted' }, null],
    ['reconcile', { txId: ethTx(9), outcome: 'adopted' }, null],
    ['reconcile', { txId: ethTx(77), outcome: 'included', fee: '1' }, 'job.state'],
    ['stuck', { txId: ethTx(2), reason: 'r' }, null],
    ['stuck', { txId: ethTx(1), reason: 'r' }, 'job.state'],
    ['replaced', { txId: ethTx(2), prevId: ethTx(1), reason: 'x' }, 'job.state'],
    ['clawback-sent', { txId: ethTx(9), outcome: 'unknown' }, null],
    ['clawback-included', { txId: ethTx(2), value: '1', fee: '1' }, 'job.state'],
    ['clawback-failed', { txId: ethTx(77), reason: 'x' }, 'job.state'],
    ['clawback-readback', { txId: ethTx(9), ok: true, destReceived: '1', laneBalance: '0' }, 'job.state'],
    ['reassembled', { copy: 1, ok: true, sha256: H }, null],
    ['reassembled', { copy: 2, ok: true, sha256: H }, 'job.state'],
    ['armed', {}, 'job.state'],
    ['resolved', { txId: ethTx(2), action: 'mark-done', typed: null }, 'job.state'],
    ['teleport', {}, 'job.state'],
    ['note', { text: 'x' }, null],
  ]
  for (const v of [j.state(), { reducer: r, corrupt: null }]) {
    for (const [type, data, want] of cases) assert.equal(guardOf(() => assertEventAllowed(BOTH, v, { chain: 'eth', type, data })), want, `${type} ${JSON.stringify(data).slice(0, 60)}`)
    assert.equal(guardOf(() => assertEventAllowed(BOTH, v, { chain: 'btc', type: 'note', data: { text: 'x' } })), 'job.state', 'no such chain')
  }
  assert.match(eventRefusal(BOTH, { reducer: r, corrupt: 'bad hash link' }, { chain: 'eth', type: 'note', data: { text: 'x' } }) ?? '', /corrupt/)
  // the reducer knows every claw-back member; the JobState view only the open and the latest / landed one
  const k = settled()
  k.ex('eth', 'clawback-intent', clawIntent(ethTx(9))); k.ex('eth', 'reconcile', { txId: ethTx(9), outcome: 'nonce-consumed' }); k.ex('eth', 'clawback-intent', clawIntent(ethTx(10)))
  const rk = createReducer(BOTH); for (const e of k.evs) rk.apply(e)
  const lateFee = { chain: 'eth', type: 'clawback-failed', data: { txId: ethTx(9), reason: 'landed with an error', fee: '3' } }
  assert.equal(guardOf(() => assertEventAllowed(BOTH, { reducer: rk, corrupt: null }, lateFee)), null, 'a dead earlier member is known to the reducer')
  assert.equal(guardOf(() => assertEventAllowed(BOTH, k.state(), lateFee)), 'job.state', 'unknown to a bare JobState: fail closed')
  const f = settled()
  f.ex('eth', 'clawback-intent', clawIntent(ethTx(9))); f.ex('eth', 'reconcile', { txId: ethTx(9), outcome: 'expired' })
  const rf = createReducer(BOTH); for (const e of f.evs) rf.apply(e)
  const rb = { chain: 'eth', type: 'clawback-readback', data: { txId: ethTx(9), ok: true, destReceived: '5', laneBalance: '0' } }
  for (const v of [f.state(), { reducer: rf, corrupt: null }]) assert.equal(guardOf(() => assertEventAllowed(BOTH, v, rb)), 'job.state', 'a failed claw-back has no landed member')
})

// ---- the incremental reducer ----
function randomJournal(seed: number, n: number) {
  const rnd = seeded(seed), pick = <T>(xs: readonly T[]): T => xs[rnd(xs.length)]
  const j = journal(), c: Chain = seed % 2 === 0 ? 'eth' : 'sol', other: Chain = c === 'eth' ? 'sol' : 'eth'
  j.ready('eth'); j.ready('sol'); j.arm(seed % 5 === 0 ? [c] : ['eth', 'sol'])
  const atts: Array<{ id: string; copy: number; part: number }> = [], members: string[] = []
  const id = (k: number): string => (c === 'eth' ? ethTx(k) : solSig(k % 250 + 1))
  let k = 100
  for (let i = 0; i < n; i++) {
    const r = rnd(100)
    if (r < 20 || atts.length === 0) { const t = { id: id(++k), copy: 1 + rnd(3), part: 1 + rnd(2) }; atts.push(t); j.intent(c, t.id, t.copy, t.part, 2, 1 + rnd(3), 1 + rnd(2)) }
    else if (r < 70) {
      const a = pick(atts), tx = rnd(12) === 0 ? id(++k) : a.id
      switch (rnd(9)) {
        case 0: j.ex(c, 'sent', { txId: tx, outcome: pick(['accepted', 'unknown', 'rejected', 'bogus']), reason: null }); break
        case 1: j.ex(c, 'reconcile', { txId: tx, outcome: pick(['expired', 'nonce-consumed', 'adopted', 'included', 'bogus']), ...(rnd(2) ? { fee: String(rnd(50)) } : {}) }); break
        case 2: j.ex(c, 'included', { txId: tx, copy: rnd(6) === 0 ? a.copy + 1 : a.copy, part: a.part, attempt: 1, block: '1', fee: String(rnd(50)), ms: 1 }); break
        case 3: j.api('resolved', { txId: tx, action: pick(['mark-done', 'mark-failed', 'bogus']), typed: null }, c); break
        case 4: j.ex(c, 'stuck', { txId: tx, reason: `r${i}` }); break
        case 5: j.ex(c, 'readback', { txId: tx, ok: rnd(3) !== 0, detail: 'd' }); break
        case 6: j.ex(c, 'reassembled', { copy: a.copy, ok: rnd(2) === 0, sha256: H }); break
        case 7: j.ex(c, pick(['paused', 'resumed', 'drained', 'copies-done', 'stopped']) as JournalEvent['type'], { reason: 'x', balance: '1', nextCost: '1', copy: 1, copies: 1 }); break
        default: j.ex(c, 'reconcile', { txId: tx, outcome: 'expired' }); j.ex(c, 'included', { txId: tx, copy: a.copy, part: a.part, attempt: 1, block: '2', fee: '9', ms: 1 })   // D-1
      }
    } else if (r < 92) {
      if (members.length === 0 || rnd(4) === 0) { const m = id(++k); members.push(m); j.ex(c, 'clawback-intent', { ...clawIntent(m, String(rnd(90))), ...(c === 'sol' ? { eth: undefined, sol: { blockhash: solSig(1).slice(0, 44), lastValidBlockHeight: 1, cuPrice: 0, cuLimit: 1, rung: null, fee: '5000' } } : {}) }); continue }
      const m = rnd(12) === 0 ? id(++k) : pick(members)
      switch (rnd(8)) {
        case 0: j.ex(c, 'clawback-included', { txId: m, value: String(rnd(90)), fee: String(rnd(20)) }); break
        case 1: j.ex(c, 'clawback-failed', { txId: m, reason: 'x', ...(rnd(2) ? { fee: String(rnd(20)) } : {}) }); break
        case 2: j.ex(c, 'reconcile', { txId: m, outcome: pick(['expired', 'nonce-consumed', 'adopted', 'included']) }); break
        case 3: j.api('resolved', { txId: m, action: pick(['mark-done', 'mark-failed']), typed: null }, c); break
        case 4: j.ex(c, 'stuck', { txId: m, reason: `c${i}` }); break
        case 5: j.ex(c, 'clawback-readback', { txId: m, ok: rnd(2) === 0, destReceived: '1', laneBalance: '0' }); break
        case 6: for (const x of members) j.ex(c, 'reconcile', { txId: x, outcome: 'expired' }); break   // D-2
        default: j.ex(c, 'clawback-sent', { txId: m, outcome: 'unknown' })
      }
    } else {
      switch (rnd(6)) {
        case 0: j.api('close', { chain: c }, c); break
        case 1: j.api('stop-requested', { chain: pick([c, null]) }); break
        case 2: j.api('resume-requested', { chain: c }); break
        case 3: j.api('skip', { releaseAt: 20_000 + i }); break
        case 4: j.intent(other, other === 'eth' ? ethTx(++k) : solSig(++k % 250 + 1), 1, 1, 1); break
        default: j.api('armed', { armedAt: 0, releaseAt: 1, countdownSec: 5, schedule: { order: [c], offsetSec: { [c]: 0 } }, caps: {}, sources: {} })   // a second armed: ignored
      }
    }
  }
  return { evs: j.evs, chain: c }
}

// the cap's hold (S2 2fea217, gates/caps.ts): open attempts, and claims (rejected, resolved-failed) of a part not landed
const holdOracle = (cs: ChainState): bigint => {
  let h = 0n
  for (const t of cs.txs) {
    let m = 0n
    for (const a of t.attempts) if (['intent', 'sent', 'unknown', 'adopted'].includes(a.state) || (t.state !== 'included' && ['rejected', 'resolved-failed'].includes(a.state))) {
      const w = a.eth ? BigInt(a.eth.gas) * BigInt(a.eth.maxFee) : a.sol ? BigInt(a.sol.fee) : 0n
      if (w > m) m = w
    }
    h += m
  }
  return h
}

test('I-3: createReducer applied one event at a time equals reduce(prefix) after EVERY event; the O(1) accessors agree with the state', () => {
  let steps = 0, viewed = 0
  for (let seed = 1; seed <= 120; seed++) {
    const { evs, chain: c } = randomJournal(seed, 60)
    const r = createReducer(BOTH)
    for (let i = 0; i < evs.length; i++) {
      r.apply(evs[i])
      const want = reduce(BOTH, evs.slice(0, i + 1)), got = r.state()
      assert.deepEqual(got, want, `seed ${seed} event ${i} (${evs[i].type})`)
      assert.equal(r.length, i + 1)
      for (const ch of ['eth', 'sol'] as const) {
        const cs = want.chains[ch]!
        assert.equal(r.phase(ch), cs.phase, `phase ${ch}`)
        assert.equal(r.inFlight(ch), cs.txs.some((t) => t.state === 'open' || t.state === 'stuck'), `inFlight ${ch}`)
        assert.equal(r.openIntents(ch), cs.openIntents.length, `openIntents ${ch}`)
        assert.equal(r.spent(ch), BigInt(cs.spent), `spent ${ch}`)
        const claw = cs.clawback !== null && cs.openIntents.some((id) => !cs.txs.some((t) => t.attempts.some((a) => a.txId === id)))
        if (!claw) assert.equal(r.held(ch), holdOracle(cs), `held ${ch}`)
        for (const t of cs.txs) {
          assert.equal(r.landed(ch, t.copy, t.part), t.state === 'included')
          assert.equal(r.copyLanded(ch, t.copy), cs.txs.some((x) => x.copy === t.copy && x.state === 'included'))
          for (const a of t.attempts) { const f = r.tx(ch, a.txId); assert.ok(f !== null && f.kind === 'job' && f.state === a.state && f.copy === t.copy && f.part === t.part) }
        }
      }
      steps++
    }
    // the cap ledger reads the same numbers from the reducer's state (E3 review m-1: with the job's own key, and any
    // refusal fails the test — it is skipped only where the ledger has nothing to read: not armed, or a claw-back open)
    const st = r.state(), cs = st.chains[c]!
    const armedHere = st.armed !== null && st.armed.schedule.order.includes(c) && typeof st.armed.caps[c]?.nativeCap === 'string'
    const clawOpen = cs.openIntents.some((id) => !cs.txs.some((t) => t.attempts.some((a) => a.txId === id)))
    if (armedHere && !clawOpen) {
      const v = CapLedger.view(st, c, BOTH.chains[c]!.keyAddress)
      assert.equal(v.held, r.held(c), `seed ${seed}: the ledger's hold = the reducer's held()`)
      assert.equal(v.spent, r.spent(c) + (cs.clawback?.landed ? BigInt(cs.clawback.value) : 0n))
      viewed++
    }
  }
  assert.ok(steps > 5_000)
  assert.ok(viewed > 50, `the ledger comparison ran (${viewed} journals)`)
})

test('I-3: every contract journal vector applied one event at a time gives the pinned state; state() is memoized until the next apply', () => {
  const index = readJson<{ vectors: Array<{ name: string }> }>('journals/index.json')
  for (const { name } of index.vectors) {
    const def = readJson<JobDef>(`journals/${name}.def.json`)
    const evs = readFileSync(fixture(`journals/${name}.jsonl`), 'utf8').split('\n').filter((l) => l !== '').map((l) => JSON.parse(l) as JournalEvent)
    const r = createReducer(def)
    for (const e of evs) r.apply(e)
    assert.deepEqual(r.state(), readJson<JobState>(`journals/${name}.state.json`), name)
    assert.equal(r.state(), r.state(), 'memoized')
  }
  const r = createReducer(BOTH), j = journal()
  j.ready('eth'); for (const e of j.evs) r.apply(e)
  const a = r.state(); r.apply({ ...j.evs[0], seq: 99, type: 'note', data: { text: 'x' } }); assert.notEqual(r.state(), a, 'a new state after apply')
  assert.equal(r.state().seq, 99)
  const armedCopy = createReducer(BOTH); const k = journal(); k.ready('eth'); k.arm(['eth']); for (const e of k.evs) armedCopy.apply(e)
  armedCopy.armed()!.releaseAt = 1; armedCopy.state().armed!.releaseAt = 2
  assert.equal(armedCopy.armed()!.releaseAt, 15_000, 'accessors and states never alias the reducer\'s own records')
})

test('E3 review m-1: held() counts what the cap ledger holds — claims until evidence, and the open claw-back family (value + worst-case fee of its largest member)', () => {
  const j = journal()
  j.ready('eth'); j.arm(['eth'])
  j.intent('eth', ethTx(1), 1, 1, 1)                                   // gas × maxFee of the helper's intent
  const r0 = createReducer(BOTH); for (const e of j.evs) r0.apply(e)
  const one = r0.held('eth')
  assert.ok(one > 0n)
  j.ex('eth', 'sent', { txId: ethTx(1), outcome: 'rejected', reason: 'x' })
  const r1 = createReducer(BOTH); for (const e of j.evs) r1.apply(e)
  assert.equal(r1.held('eth'), one, 'a rejected attempt is a claim: still held')
  j.ex('eth', 'reconcile', { txId: ethTx(1), outcome: 'nonce-consumed' })
  const r2 = createReducer(BOTH); for (const e of j.evs) r2.apply(e)
  assert.equal(r2.held('eth'), 0n, 'evidence frees it')
  j.ex('eth', 'drained', { balance: '1', nextCost: '9', copy: 1 })
  j.ex('eth', 'clawback-intent', clawIntent(ethTx(9), '1000'))         // 1000 + 21000 × 2
  j.ex('eth', 'clawback-intent', { ...clawIntent(ethTx(10), '900'), eth: { nonce: 2, tip: '1', maxFee: '7', gas: '21000', to: DEST } })   // 900 + 21000 × 7
  const r3 = createReducer(BOTH); for (const e of j.evs) r3.apply(e)
  assert.equal(r3.held('eth'), 900n + 21_000n * 7n, 'the family holds its largest member')
  j.ex('eth', 'reconcile', { txId: ethTx(10), outcome: 'nonce-consumed' })
  const r4 = createReducer(BOTH); for (const e of j.evs) r4.apply(e)
  assert.equal(r4.held('eth'), 1000n + 21_000n * 2n, 'a dead member no longer counts')
})

test('PF-S fix round 5 (R34-1): the stop latch — a journaled `stopped` holds through STUCK and every executor event until the operator\'s resume; the gate refuses phase events and job intents meanwhile, evidence and claw-backs still apply', () => {
  const j = journal(); j.ready('eth'); j.arm(['eth'])
  j.intent('eth', ethTx(1), 1, 1, 1)
  j.ex('eth', 'sent', { txId: ethTx(1), outcome: 'unknown', reason: 'timeout' })
  j.ex('eth', 'stopped', { reason: 'Ctrl-C' })                                   // no stop request: Ctrl-C / the page's Stop
  const st = () => chain(j.state(), 'eth')
  const view = () => { const rr = createReducer(BOTH); for (const e of j.evs) rr.apply(e); return { reducer: rr, corrupt: null } }
  assert.deepEqual([st().phase, st().stopLatched, st().stopRequested], ['STOPPED', true, false])
  // evidence about the existing attempt is taken (stuck: STUCK over STOPPED); phase events are refused by the gate and, journaled
  // anyway, move nothing: the base stays STOPPED
  assert.equal(eventRefusal(BOTH, view(), { chain: 'eth', type: 'stuck', data: { txId: ethTx(1), reason: 'unseen' } }), null)
  j.ex('eth', 'stuck', { txId: ethTx(1), reason: 'unseen' })
  assert.deepEqual([st().phase, st().stopLatched], ['STUCK', true])
  for (const [type, data] of PHASE_EVENTS.filter(([t]) => t !== 'stopped')) {
    assert.match(String(eventRefusal(BOTH, view(), { chain: 'eth', type, data })), /stays stopped until the operator resumes it/, type)
  }
  assert.equal(eventRefusal(BOTH, view(), { chain: 'eth', type: 'reconcile', data: { txId: ethTx(1), outcome: 'adopted' } }), null)
  j.ex('eth', 'resumed', { reason: 'executor' })                                  // journaled anyway (a journal the gate never saw)
  j.ex('eth', 'reconcile', { txId: ethTx(1), outcome: 'adopted' })               // clears the stuck flag
  assert.deepEqual([st().phase, st().stopLatched], ['STOPPED', true], 'never revived by executor events')
  j.intent('eth', ethTx(2), 2, 1, 1)
  assert.equal(st().phase, 'STOPPED', 'nor by a job intent')
  for (const v of [view(), j.state()]) {
    assert.match(String(intentRefusal(BOTH, v, 'eth', 20_000, 'intent', { copy: 3, part: 1 })), /was stopped: no new intent until the operator resumes it/)
  }
  // the operator's resume (resume-requested, an API event) clears it: an executor `resumed` then moves the chain on
  j.api('resume-requested', { chain: 'eth' }, 'eth')
  assert.equal('stopLatched' in st(), false)
  j.ex('eth', 'resumed', { reason: 'executor' })
  assert.equal(st().phase, 'RUNNING')
  // an all-chain resume (chain null) clears it too; a stop request alone does not set it; close (DONE) hides it
  const k = journal(); k.ready('eth'); k.arm(['eth']); k.api('stop-requested', { chain: 'eth' }, 'eth')
  assert.equal('stopLatched' in chain(k.state(), 'eth'), false, 'a stop request is not the latch')
  k.ex('eth', 'stopped', { reason: 'x' }); assert.equal(chain(k.state(), 'eth').stopLatched, true)
  k.api('resume-requested', { chain: null }); assert.equal('stopLatched' in chain(k.state(), 'eth'), false)
  const c = journal(); c.ready('eth'); c.arm(['eth']); c.ex('eth', 'stopped', { reason: 'x' }); c.api('close', { chain: 'eth' }, 'eth')
  assert.deepEqual([chain(c.state(), 'eth').phase, 'stopLatched' in chain(c.state(), 'eth')], ['DONE', false])
  // a claw-back stays allowed on a latched (STOPPED) chain with nothing in flight
  const w = journal(); w.ready('eth'); w.arm(['eth']); w.ex('eth', 'stopped', { reason: 'x' })
  assert.equal(intentRefusal(BOTH, w.state(), 'eth', 20_000, 'clawback-intent'), null)
})

test('PF-S fix round 6: phase events are judged on the BASE phase (both views): STUCK over DRAINED / COPIES_DONE / a latched STOPPED refuses them, STUCK over RUNNING takes them; the reducer never moves a settled base on an executor event; stuckBase shows the base', () => {
  const views = (j: ReturnType<typeof journal>) => { const r = createReducer(BOTH); for (const e of j.evs) r.apply(e); return [j.state(), { reducer: r, corrupt: null }] as const }
  const withOpen = (settle: (j: ReturnType<typeof journal>) => void) => {
    const j = journal(); j.ready('eth'); j.arm(['eth'])
    j.intent('eth', ethTx(1), 1, 1, 1); j.ex('eth', 'sent', { txId: ethTx(1), outcome: 'unknown', reason: 'timeout' })
    settle(j)
    j.ex('eth', 'stuck', { txId: ethTx(1), reason: 'unseen' })
    return j
  }
  const bases: Record<string, (j: ReturnType<typeof journal>) => void> = {
    DRAINED: (j) => j.ex('eth', 'drained', { balance: '1', nextCost: '9', copy: 2 }),
    COPIES_DONE: (j) => j.ex('eth', 'copies-done', { copies: 1 }),
    STOPPED: (j) => j.ex('eth', 'stopped', { reason: 'Ctrl-C' }),
  }
  const moves = [...PHASE_EVENTS, ['copy-built', { copy: 2, parts: 1, bytes: [10], tight: false, level: 0 }]] as const
  for (const [base, settle] of Object.entries(bases)) {
    const j = withOpen(settle)
    assert.deepEqual([chain(j.state(), 'eth').phase, chain(j.state(), 'eth').stuckBase], ['STUCK', base], base)
    for (const v of views(j)) for (const [type, data] of moves) {
      assert.equal(guardOf(() => assertEventAllowed(BOTH, v, { chain: 'eth', type, data })), 'job.state', `${type} on STUCK over ${base} (${'reducer' in v ? 'reducer' : 'state'} view)`)
      assert.equal(guardOf(() => assertIntentAllowed(BOTH, v, 'eth', 20_000, 'intent', { copy: 2, part: 1 })), 'job.state', `an intent on STUCK over ${base}`)
    }
    // journaled anyway (a journal the gate never saw): the base never moves
    for (const [type, data] of moves) j.ex('eth', type, data)
    j.ex('eth', 'reconcile', { txId: ethTx(1), outcome: 'adopted' })
    j.intent('eth', ethTx(2), 2, 1, 1)
    assert.equal(chain(j.state(), 'eth').phase, base, `${base} never moves`)
    assert.equal('stuckBase' in chain(j.state(), 'eth'), false, 'shown only while STUCK')
  }
  // STUCK over RUNNING: phase events still apply (both views)
  const run = journal(); run.ready('eth'); run.arm(['eth']); run.intent('eth', ethTx(1), 1, 1, 1)
  run.ex('eth', 'sent', { txId: ethTx(1), outcome: 'unknown', reason: 'timeout' }); run.ex('eth', 'stuck', { txId: ethTx(1), reason: 'unseen' })
  assert.equal(chain(run.state(), 'eth').stuckBase, 'RUNNING')
  for (const v of views(run)) for (const [type, data] of moves) assert.equal(guardOf(() => assertEventAllowed(BOTH, v, { chain: 'eth', type, data })), null, `${type} on STUCK over RUNNING`)
  // a JobState without stuckBase under STUCK (an older producer) reads as STUCK: refused (fail closed)
  const bare = run.state()
  const { stuckBase: _b, ...eth } = chain(bare, 'eth')
  assert.equal(guardOf(() => assertEventAllowed(BOTH, { ...bare, chains: { ...bare.chains, eth } }, { chain: 'eth', type: 'resumed', data: { reason: 'x' } })), 'job.state')
})

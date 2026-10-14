// Security review "cap-ledger drift" (+ E2 re-review D-1, D-2 and the mark-done minor): the cap ledger equals what the
// journal and the chain evidence it records imply, at all times. A reservation is released or converted exactly once;
// a bump family is held at its largest attempt; a ledger rebuilt from the journal equals the live one (random event
// sequences, adversarial events included); stuck and unknown attempts keep their hold with a named exit; nothing in
// flight never leaves a lane locked. Base units (bigint) only. ALL DATA IS SYNTHETIC; relays are fake fetch functions.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { base58 } from '@scure/base'
import { Keypair } from '@solana/web3.js'
import { solTx } from '../../src/engine/engine.js'
import { clawbackSol } from '../../src/engine/lane.js'
import { CapLedger } from '../../src/gates/caps.ts'
import { intentRefusal, reduce } from '../../src/job/index.ts'
import type { Chain as ContractChain, JobDef, JobState } from '../../src/contracts/index.ts'
type Chain = Exclude<ContractChain, 'btc'> // CC-7: the engine's lanes
import { utf8 } from '../../src/chains/plan.js'
import { guardOf, readJson, seeded } from '../job/helpers.ts'
import { armedEvent, armedLedger, armedState, asJournal, fakeClock, fakeRelay, fakeSolChain, recordingJournal } from './fakes.ts'
import type { Ev } from './fakes.ts'

const ETH_DEF = readJson<JobDef>('journals/01-created.def.json')       // eth only
const SOL_DEF = readJson<JobDef>('journals/07-sol-expired.def.json')   // sol only
const H = 'ab'.repeat(32), DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6', BH = base58.encode(new Uint8Array(32).fill(3))
const CAP = 10_000n
const data = (chain: Chain, worst: number | bigint) => (chain === 'eth'
  ? { eth: { nonce: 0, tip: '1', maxFee: String(worst), gas: '1', to: DEST } }
  : { sol: { blockhash: BH, lastValidBlockHeight: 1, cuPrice: 0, cuLimit: 1, rung: null, fee: String(worst) } })
const intent = (chain: Chain, txId: string, copy: number, part: number, worst: number | bigint): Ev =>
  ({ type: 'intent', chain, txId, copy, part, parts: 2, attempt: 1, replaces: null, rawSha256: H, payloadSha256: H, reserved: '1', ...data(chain, worst) })
const claw = (chain: Chain, txId: string, value: number, fee: number): Ev => ({ type: 'clawback-intent', chain, txId, to: DEST, value: String(value), rawSha256: H, ...data(chain, fee) })
const ev = (chain: Chain, type: string, d: Record<string, unknown>): Ev => ({ type, chain, ...d })
const stateOf = (chain: Chain, evs: Ev[], cap = CAP): JobState => reduce(chain === 'eth' ? ETH_DEF : SOL_DEF, asJournal([armedEvent([chain], cap)], evs))
let keys = 0
const ledgerOf = (chain: Chain, evs: Ev[] = [], cap = CAP): CapLedger => CapLedger.fromArmed(stateOf(chain, evs, cap), chain, `drift-key-${++keys}`)
const viewOf = (chain: Chain, evs: Ev[], cap = CAP) => CapLedger.view(stateOf(chain, evs, cap), chain, `drift-view-${++keys}`)
// live (built at `split`, then observing the rest) and rebuilt (from the whole journal) agree
function agree(chain: Chain, evs: Ev[], split = 0, msg = ''): CapLedger {
  const live = ledgerOf(chain, evs.slice(0, split))
  for (const e of evs.slice(split)) live.observe(e)
  const rebuilt = viewOf(chain, evs)
  assert.deepEqual([live.spent, live.held], [rebuilt.spent, rebuilt.held], `live = rebuilt ${msg}`)
  return live
}

// ---- each transition ----
test('a landed attempt: its reservation becomes its ACTUAL fee (the journaled receipt fee), not the worst case', () => {
  const l = ledgerOf('eth')
  l.reserve({ copy: 1, part: 1 }, 1000n); assert.equal(l.held, 1000n)
  const evs = [intent('eth', 'A', 1, 1, 1000), ev('eth', 'sent', { txId: 'A', outcome: 'accepted', reason: null }), ev('eth', 'included', { txId: 'A', copy: 1, part: 1, attempt: 1, block: '7', fee: '400', ms: 1 })]
  for (const e of evs) l.observe(e)
  assert.deepEqual([l.spent, l.held, l.remaining], [400n, 0n, CAP - 400n])
  assert.deepEqual([l.spent, l.held], [viewOf('eth', evs).spent, viewOf('eth', evs).held]); l.close()
})

test('only CHAIN EVIDENCE frees an attempt\'s hold (S2 2fea217): reconcile expired / nonce-consumed release it; `sent rejected` and resolve mark-failed are claims and keep it', () => {
  for (const dead of [ev('eth', 'reconcile', { txId: 'A', outcome: 'expired' }), ev('eth', 'reconcile', { txId: 'A', outcome: 'nonce-consumed' })]) {
    const l = agree('eth', [intent('eth', 'A', 1, 1, 700), dead], 0, String(dead.outcome))
    assert.deepEqual([l.spent, l.held, l.idle], [0n, 0n, true], `${dead.outcome}: released, nothing in flight`); l.close()
  }
  for (const claim of [ev('eth', 'sent', { txId: 'A', outcome: 'rejected', reason: 'nonce too low' }), ev('eth', 'resolved', { txId: 'A', action: 'mark-failed', typed: null })]) {
    const l = agree('eth', [intent('eth', 'A', 1, 1, 700), claim], 0, String(claim.type))
    assert.deepEqual([l.held, l.idle], [700n, false], `${claim.type}: still held`); l.close()
    const r = agree('eth', [intent('eth', 'A', 1, 1, 700), claim, ev('eth', 'reconcile', { txId: 'A', outcome: 'nonce-consumed' })], 0, `${claim.type} then evidence`)
    assert.deepEqual([r.held, r.idle], [0n, true]); r.close()
    const landed = agree('eth', [intent('eth', 'A', 1, 1, 700), claim, intent('eth', 'B', 1, 1, 800), ev('eth', 'included', { txId: 'B', copy: 1, part: 1, attempt: 2, block: '1', fee: '500', ms: 1 })], 0, `${claim.type} then a replacement landed`)
    assert.deepEqual([landed.spent, landed.held], [500n, 0n], 'a landing in the group frees the claims'); landed.close()
  }
})

test('a reservation becomes the attempt\'s own hold at its intent; when that attempt dies, nothing of it stays held', () => {
  for (const chain of ['eth', 'sol'] as const) {
    const l = ledgerOf(chain), t = { copy: 2, part: 1 }
    l.reserve(t, 800n); l.observe(intent(chain, 'A', 2, 1, 800))
    assert.equal(l.held, 800n)
    l.observe(ev(chain, 'reconcile', { txId: 'A', outcome: 'expired' }))
    assert.deepEqual([l.held, l.idle], [0n, true], `${chain}: released exactly once`)
    l.reserve(t, 900n); assert.equal(l.held, 900n, 'the re-sign reserves afresh'); l.close()
  }
})

test('an attempt still open in a landed group (the API refuses such an intent) stays held: fail closed', () => {
  const evs = [intent('eth', 'A', 1, 1, 100), ev('eth', 'included', { txId: 'A', copy: 1, part: 1, attempt: 1, block: '1', fee: '90', ms: 1 }), intent('eth', 'B', 1, 1, 300)]
  const l = agree('eth', evs); assert.deepEqual([l.spent, l.held], [90n, 300n]); l.close()
})

test('stuck, unknown and adopted keep their reservation (fail closed); the refusal names the exit (reconcile, or the operator resolve)', () => {
  for (const keep of [ev('eth', 'stuck', { txId: 'A', reason: 'nonce used, no receipt' }), ev('eth', 'sent', { txId: 'A', outcome: 'unknown', reason: 'timeout' }), ev('eth', 'reconcile', { txId: 'A', outcome: 'adopted' })]) {
    const l = agree('eth', [intent('eth', 'A', 1, 1, 7000), keep], 0, String(keep.type))
    assert.equal(l.held, 7000n)
    const why = (() => { try { l.check(3001n) } catch (e) { return (e as Error).message } return '' })()
    assert.match(why, /held by attempt\(s\) that may still land \(A\)/); assert.match(why, /reconcile/); assert.match(why, /vt job resolve/)
    l.close()
  }
})

test('bump family: held at the LARGEST attempt, never the sum; once one lands the others are released; a rebuilt ledger agrees at every step', () => {
  const evs = [intent('eth', 'A', 1, 1, 1000), intent('eth', 'B', 1, 1, 1125), intent('eth', 'C', 1, 1, 1266), ev('eth', 'included', { txId: 'B', copy: 1, part: 1, attempt: 2, block: '9', fee: '900', ms: 1 })]
  for (let k = 0; k <= evs.length; k++) for (let split = 0; split <= k; split++) agree('eth', evs.slice(0, k), split, `k=${k} split=${split}`).close()
  const l = agree('eth', evs.slice(0, 3)); assert.equal(l.held, 1266n); l.close()
  const m = agree('eth', evs); assert.deepEqual([m.spent, m.held], [900n, 0n]); m.close()
})

test('double release and double count: an inclusion journaled twice spends once; a dead attempt released twice stays released', () => {
  const inc = ev('sol', 'included', { txId: 'A', copy: 1, part: 1, attempt: 1, block: '7', fee: '5000', ms: 1 })
  const l = agree('sol', [intent('sol', 'A', 1, 1, 5000), inc, inc, inc])
  assert.deepEqual([l.spent, l.held], [5000n, 0n]); l.close()
  const d = agree('sol', [intent('sol', 'A', 1, 1, 5000), intent('sol', 'B', 2, 1, 6000), ev('sol', 'reconcile', { txId: 'A', outcome: 'expired' }), ev('sol', 'reconcile', { txId: 'A', outcome: 'expired' }), ev('sol', 'sent', { txId: 'A', outcome: 'rejected', reason: 'x' })])
  assert.deepEqual([d.spent, d.held], [0n, 6000n], 'only B is held'); d.close()
})

test('D-1: a signature included after its expiry was journaled (and a re-sign was made): spent, the part landed, never signed again', () => {
  const evs = [intent('sol', 'A1', 1, 1, 5000), ev('sol', 'reconcile', { txId: 'A1', outcome: 'expired' }), intent('sol', 'A2', 1, 1, 5000),
    ev('sol', 'included', { txId: 'A1', copy: 1, part: 1, attempt: 1, block: '9', fee: '5000', ms: 1 })]
  for (let split = 0; split <= evs.length; split++) agree('sol', evs, split, `split ${split}`).close()
  const l = agree('sol', evs)
  assert.deepEqual([l.spent, l.held, l.landed({ copy: 1, part: 1 })], [5000n, 0n, true])
  assert.throws(() => l.reserve({ copy: 1, part: 1 }, 1n), /already landed/)
  const st = stateOf('sol', evs)
  assert.match(intentRefusal(SOL_DEF, st, 'sol', Number.MAX_SAFE_INTEGER, 'intent', { copy: 1, part: 1 }) ?? '', /already landed/, 'the API refuses it too')
  // the later sibling lands as well (two real landings: both paid, progress counted once)
  const both = agree('sol', [...evs, ev('sol', 'included', { txId: 'A2', copy: 1, part: 1, attempt: 2, block: '10', fee: '5000', ms: 1 })])
  assert.equal(both.spent, 10_000n); both.close(); l.close()
})

test('a landed attempt without a journaled fee (resolve mark-done, reconcile included without fee) keeps its worst case as spent, never 0', () => {
  for (const land of [ev('eth', 'resolved', { txId: 'A', action: 'mark-done', typed: null }), ev('eth', 'reconcile', { txId: 'A', outcome: 'included' })]) {
    const l = agree('eth', [intent('eth', 'A', 1, 1, 777), land])
    assert.deepEqual([l.spent, l.held], [777n, 0n], String(land.type)); l.close()
  }
})

test('evidence for an unknown txId or another (copy, part) moves nothing (fail closed)', () => {
  const evs = [intent('eth', 'A', 1, 1, 500), ev('eth', 'included', { txId: 'Z', copy: 1, part: 1, attempt: 1, block: '1', fee: '1', ms: 1 }),
    ev('eth', 'included', { txId: 'A', copy: 2, part: 1, attempt: 1, block: '1', fee: '1', ms: 1 }), ev('eth', 'reconcile', { txId: 'A', outcome: 'bogus' }),
    ev('eth', 'resolved', { txId: 'Z', action: 'mark-done', typed: null }), ev('eth', 'clawback-included', { txId: 'A', value: '9', fee: '9' })]
  const l = agree('eth', evs)
  assert.deepEqual([l.spent, l.held, l.landed({ copy: 1, part: 1 })], [0n, 500n, false]); l.close()
  const st = stateOf('eth', evs).chains.eth!
  assert.deepEqual([st.txs[0].state, st.spent, st.openIntents], ['open', '0', ['A']])
})

// ---- claw-back ----
test('claw-back: value + worst-case fee reserved; landed → the chain\'s value + fee spent; failed on chain → its fee; every member dead → released', () => {
  const l = ledgerOf('eth')
  l.reserveClawback(900n + 21n); assert.equal(l.held, 921n)
  l.observe(claw('eth', 'C1', 900, 21)); assert.equal(l.held, 921n)
  l.observe(claw('eth', 'C2', 880, 41)); assert.equal(l.held, 921n, 'a bump: the family is held at its largest member (value + fee constant)')
  l.observe(ev('eth', 'clawback-included', { txId: 'C1', value: '900', fee: '17' }))
  assert.deepEqual([l.spent, l.held], [917n, 0n], 'the chain\'s value + fee'); l.close()
  const settled = viewOf('eth', [claw('eth', 'C1', 900, 21), claw('eth', 'C2', 880, 41), ev('eth', 'clawback-included', { txId: 'C1', value: '900', fee: '17' })])
  assert.deepEqual([settled.spent, settled.held], [917n, 0n], 'rebuilt: the same')
  const failed = [claw('eth', 'C1', 900, 21), ev('eth', 'clawback-failed', { txId: 'C1', reason: 'landed with an error', fee: '19' })]
  const f = agree('eth', failed); assert.deepEqual([f.spent, f.held, f.idle], [19n, 0n, true]); f.close()
  const dead = [claw('sol', 'S1', 900, 5000), ev('sol', 'reconcile', { txId: 'S1', outcome: 'expired' })]
  const d = agree('sol', dead); assert.deepEqual([d.spent, d.held, d.idle], [0n, 0n, true]); d.close()
})

test('claw-back: a member that failed on chain while another is open keeps the family open (CLAWING_BACK) until every member is dead', () => {
  const evs = [claw('sol', 'S1', 900, 5000), ev('sol', 'reconcile', { txId: 'S1', outcome: 'expired' }), claw('sol', 'S2', 890, 5000)]
  const open = [...evs, ev('sol', 'clawback-failed', { txId: 'S1', reason: 'x', fee: '5000' })]
  const st = stateOf('sol', [ev('sol', 'stopped', { reason: 'operator' }), ...open]).chains.sol!
  assert.deepEqual([st.phase, st.openIntents, st.clawback!.ok], ['CLAWING_BACK', ['S2'], null], 'S2 may still land')
  assert.equal(guardOf(() => CapLedger.fromArmed(stateOf('sol', open), 'sol', 'claw-open-s2')), 'engine.cap-armed')
  const all = [...open, ev('sol', 'reconcile', { txId: 'S2', outcome: 'expired' })]
  const st2 = stateOf('sol', [ev('sol', 'stopped', { reason: 'operator' }), ...all]).chains.sol!
  assert.deepEqual([st2.phase, st2.openIntents, st2.clawback!.ok, st2.spent], ['STOPPED', [], false, '5000'])
  const l = ledgerOf('sol', all); assert.deepEqual([l.spent, l.held], [5000n, 0n]); l.close()
})

test('D-2: every member dead and none landed → never locked; fromArmed keys on an OPEN member, and its refusal names the exits', () => {
  const st = stateOf('sol', [claw('sol', 'S1', 900, 5000)])
  const why = (() => { try { CapLedger.fromArmed(st, 'sol', 'd2-open') } catch (e) { return (e as Error).message } return '' })()
  assert.match(why, /claw-back is in progress \(open: S1\)/); assert.match(why, /vt job resolve/); assert.match(why, /clawback-failed/)
  const l = ledgerOf('sol', [claw('sol', 'S1', 900, 5000), ev('sol', 'reconcile', { txId: 'S1', outcome: 'expired' })])
  assert.deepEqual([l.idle, l.remaining], [true, CAP]); l.reserveClawback(CAP); l.close()
})

test('fromArmed keys on an OPEN claw-back member, not on ok === null: a family with nothing open never locks the lane', () => {
  const st = armedState('sol', 1000n, { clawback: { txId: 'S9', to: 'x', value: '5', ok: null, landed: false }, openIntents: [] })
  const l = CapLedger.fromArmed(st, 'sol', 'no-open-member'); assert.deepEqual([l.idle, l.remaining], [true, 1000n]); l.close()
  const open = armedState('sol', 1000n, { clawback: { txId: 'S9', to: 'x', value: '5', ok: null, landed: false }, openIntents: ['S9'] })
  assert.equal(guardOf(() => CapLedger.fromArmed(open, 'sol', 'one-open-member')), 'engine.cap-armed')
})

test('the typed claw-back amount: over the cap only with exactly value + fee; a mismatched amount refuses even when it fits; never carried over', () => {
  const l = ledgerOf('eth', [], 1000n)
  assert.equal(guardOf(() => l.reserveClawback(1001n)), 'engine.cap-clawback')
  assert.equal(guardOf(() => l.reserveClawback(1001n, { amount: '1000' })), 'engine.cap-clawback')
  assert.equal(guardOf(() => l.reserveClawback(500n, { amount: '499' })), 'engine.cap-clawback', 'a typed amount must match what is signed')
  assert.equal(guardOf(() => l.reserveClawback(1001n, { amount: '1001', extra: 1 } as never)), 'engine.cap-clawback')
  const why = (() => { try { l.reserveClawback(1001n) } catch (e) { return (e as Error).message } return '' })()
  assert.match(why, /type exactly 1001/)
  l.reserveClawback(1001n, { amount: '1001' })
  l.observe(claw('eth', 'C1', 980, 21))
  assert.equal(guardOf(() => l.reserveClawback(1001n)), 'engine.cap-clawback', 'a bump needs the typed amount again')
  l.reserveClawback(1001n, { amount: '1001' }); l.close()
})

test('a ledger that sees an event it cannot account for (an earlier failed claw-back landing later) refuses from then on (fail closed)', () => {
  const l = ledgerOf('eth', [claw('eth', 'C1', 900, 21), ev('eth', 'reconcile', { txId: 'C1', outcome: 'nonce-consumed' })])
  assert.equal(l.poisoned, null)
  l.observe(ev('eth', 'clawback-included', { txId: 'C1', value: '900', fee: '21' }))
  assert.match(l.poisoned ?? '', /cannot account for/)
  assert.equal(guardOf(() => l.check(0n)), 'engine.cap-copy'); assert.throws(() => l.reserve({ copy: 1, part: 1 }, 0n), /poisoned/)
  const rebuilt = viewOf('eth', [claw('eth', 'C1', 900, 21), ev('eth', 'reconcile', { txId: 'C1', outcome: 'nonce-consumed' }), ev('eth', 'clawback-included', { txId: 'C1', value: '900', fee: '21' })])
  assert.deepEqual([rebuilt.spent, rebuilt.held], [921n, 0n], 'a new ledger from the journal is exact'); l.close()
})

test('hardening: the cap cannot be changed at run time; a corrupt journal or another key\'s state refuses; one signer per (copy, part)', () => {
  const l = ledgerOf('eth')
  assert.throws(() => { (l as unknown as { cap: bigint }).cap = 10n ** 30n }, TypeError)
  assert.equal(l.cap, CAP)
  const t1 = { copy: 1, part: 1 }, t2 = { copy: 1, part: 1 }
  l.reserve(t1, 10n)
  assert.equal(guardOf(() => l.reserve(t2, 10n)), 'engine.cap-busy', 'a second signer of the same part')
  l.reserve(t1, 20n); assert.equal(l.held, 20n, 'the same signer replaces its reservation'); l.close()
  const st = stateOf('eth', []); st.corrupt = 'bad hash link'
  assert.equal(guardOf(() => CapLedger.fromArmed(st, 'eth', 'k-corrupt')), 'engine.cap-armed')
  const other = stateOf('eth', []); other.chains.eth!.address = '0x1111111111111111111111111111111111111111'
  assert.equal(guardOf(() => CapLedger.fromArmed(other, 'eth', '0x2222222222222222222222222222222222222222')), 'engine.cap-armed')
  CapLedger.fromArmed(other, 'eth', '0x1111111111111111111111111111111111111111').close()
  const noFee = { ...intent('eth', 'A', 1, 1, 1) }; delete noFee.eth
  const p = ledgerOf('eth'); p.observe(noFee); assert.match(p.poisoned ?? '', /without fee data/); p.close()
})

// ---- random sequences: live = rebuilt ----
function sequence(seed: number, chain: Chain, n: number): Ev[] {
  const rnd = seeded(seed), pick = <T>(xs: readonly T[]): T => xs[rnd(xs.length)]
  const out: Ev[] = [], atts: Array<{ id: string; copy: number; part: number }> = [], members: string[] = []
  let k = 0
  for (let i = 0; i < n; i++) {
    const r = rnd(100)
    if (r < 22 || atts.length === 0) {
      const t = { id: `T${++k}`, copy: 1 + rnd(3), part: 1 + rnd(2) }
      atts.push(t); out.push(intent(chain, t.id, t.copy, t.part, 1 + rnd(60)))
    } else if (r < 78) {
      const a = pick(atts), tx = rnd(12) === 0 ? `U${++k}` : a.id                      // adversarial: an unknown txId
      switch (rnd(8)) {
        case 0: out.push(ev(chain, 'sent', { txId: tx, outcome: pick(['accepted', 'unknown', 'rejected', 'bogus']), reason: null })); break
        case 1: out.push(ev(chain, 'reconcile', { txId: tx, outcome: pick(['expired', 'nonce-consumed', 'adopted', 'bogus']) })); break
        case 2: out.push(ev(chain, 'reconcile', { txId: tx, outcome: 'included', ...(rnd(2) ? { fee: String(rnd(40)) } : {}) })); break
        case 3: out.push(ev(chain, 'included', { txId: tx, copy: rnd(5) === 0 ? a.copy + 1 : a.copy, part: a.part, attempt: 1, block: '1', fee: String(rnd(40)), ms: 1 })); break
        case 4: out.push(ev(chain, 'resolved', { txId: tx, action: pick(['mark-done', 'mark-failed', 'bogus']), typed: null })); break
        case 5: out.push(ev(chain, 'stuck', { txId: tx, reason: 'r' })); break
        case 6: out.push(ev(chain, 'readback', { txId: tx, ok: rnd(2) === 0, detail: 'd' })); break
        default: out.push(ev(chain, 'reconcile', { txId: tx, outcome: 'expired' }), ev(chain, 'included', { txId: tx, copy: a.copy, part: a.part, attempt: 1, block: '2', fee: String(rnd(40)), ms: 1 }))   // D-1
      }
    } else {
      if (members.length === 0 || rnd(4) === 0) { const m = `C${++k}`; members.push(m); out.push(claw(chain, m, rnd(100), 1 + rnd(30))); continue }
      const m = rnd(12) === 0 ? `V${++k}` : pick(members)
      switch (rnd(9)) {
        case 0: out.push(ev(chain, 'clawback-sent', { txId: m, outcome: pick(['accepted', 'unknown', 'rejected']) })); break
        case 1: out.push(ev(chain, 'clawback-included', { txId: m, value: String(rnd(100)), fee: String(rnd(30)) })); break
        case 2: out.push(ev(chain, 'clawback-failed', { txId: m, reason: 'x', ...(rnd(2) ? { fee: String(rnd(30)) } : {}) })); break
        case 3: out.push(ev(chain, 'reconcile', { txId: m, outcome: pick(['expired', 'nonce-consumed', 'adopted', 'bogus']) })); break
        case 4: out.push(ev(chain, 'reconcile', { txId: m, outcome: 'included', ...(rnd(2) ? { fee: String(rnd(30)) } : {}) })); break
        case 5: out.push(ev(chain, 'resolved', { txId: m, action: pick(['mark-done', 'mark-failed']), typed: null })); break
        case 6: out.push(ev(chain, 'stuck', { txId: m, reason: 'r' })); break
        case 7: out.push(ev(chain, 'clawback-readback', { txId: m, ok: rnd(2) === 0, destReceived: '1', laneBalance: '0' })); break
        default: for (const x of members) out.push(ev(chain, 'reconcile', { txId: x, outcome: 'expired' }))   // D-2: every member dead
      }
    }
  }
  return out
}

test('random sequences (D-1, D-2, bump families, adversarial events): a live ledger built at any split and observing the rest equals the rebuilt one', () => {
  let compared = 0, poisoned = 0, inProgress = 0
  for (let seed = 1; seed <= 240; seed++) {
    const chain: Chain = seed % 2 === 0 ? 'eth' : 'sol', evs = sequence(seed, chain, 40 + (seed % 30))
    const full = stateOf(chain, evs, 10n ** 9n)
    let rebuilt: { spent: bigint; held: bigint } | null = null
    try { rebuilt = CapLedger.view(full, chain, `rnd-${seed}`) } catch (e) { if ((e as { guardId?: string }).guardId !== 'engine.cap-armed') throw e }
    const cs = full.chains[chain]!
    const oracle = BigInt(cs.spent) + (cs.clawback?.landed === true ? BigInt(cs.clawback.value) : 0n)
    if (rebuilt !== null) assert.equal(rebuilt.spent, oracle, `seed ${seed}: spent = journal spent + a landed claw-back's value`)
    const rnd = seeded(seed * 7919)
    for (const split of new Set([0, evs.length, rnd(evs.length + 1), rnd(evs.length + 1), rnd(evs.length + 1)])) {
      let live: CapLedger
      try { live = CapLedger.fromArmed(stateOf(chain, evs.slice(0, split), 10n ** 9n), chain, `rnd-live-${seed}-${split}`) } catch (e) {
        if ((e as { guardId?: string }).guardId === 'engine.cap-armed') continue                // a claw-back in progress at the split: reconcile first
        throw e
      }
      for (const e of evs.slice(split)) live.observe(e)
      if (live.poisoned !== null) { poisoned++; assert.equal(guardOf(() => live.check(0n)), 'engine.cap-copy', 'fail closed'); live.close(); continue }
      assert.equal(live.spent, oracle, `seed ${seed} split ${split}: spent`)
      if (rebuilt === null) inProgress++
      else { assert.equal(live.held, rebuilt.held, `seed ${seed} split ${split}: held`); compared++ }
      live.close()
    }
  }
  assert.ok(compared >= 300, `compared ${compared} (poisoned ${poisoned}, a claw-back in progress at the end ${inProgress})`)
})

// ---- the engine paths (fake clock: the SOL expiry proof runs instantly) ----
test('D-1 (engine): the first signature shows up after its expiry was journaled and a re-sign was sent → included, spent once, the part never re-sent', { timeout: 30_000 }, async () => {
  const base = fakeSolChain()
  let prepares = 0, first = ''
  const relay = fakeRelay({ sol: (m, p) => {
    if (m === 'getLatestBlockhash') {
      if (p[0]?.commitment === 'finalized') return { context: { slot: 900 }, value: { blockhash: BH, lastValidBlockHeight: 2_150 } }   // finalized height 2,000 > 1,000
      prepares++; return { context: { slot: 500 }, value: { blockhash: base58.encode(new Uint8Array(32).fill(prepares)), lastValidBlockHeight: 1_000 } }
    }
    if (m === 'isBlockhashValid') return { context: { slot: 1_000 }, value: false }   // Efix3: the blockhash has expired
    if (m === 'getSignatureStatuses') {
      const late = relay.sends().length >= 2                                   // A1 appears once A2 was sent
      return { context: { slot: 1_000 }, value: (p[0] as string[]).map((s) => (late && s === first ? { slot: 501, confirmations: 1, err: null, confirmationStatus: 'confirmed' } : null)) }
    }
    const r = base.handler(m, p)
    if (m === 'sendTransaction' && first === '') first = r as string
    return r
  } })
  const { journal, events } = recordingJournal()
  const ledger = armedLedger('sol', 10n ** 9n), t: Record<string, any> = { copy: 1, part: 1, parts: 1, payload: utf8('late memo') }
  const r = await solTx(t, { kp: Keypair.generate(), notify: async () => {}, alive: () => true, poll: 1, rent: 890_880n, used: new Map(), journal, ledger, clock: fakeClock(), solEndpoints: 1,
    lane: { txs: [] }, payerFloor: 890_880n, cuPriceCap: 2_000_000, policy: { price: async () => ({ lamports: 0, rung: 0 }) } })
  assert.equal(r, 'confirmed'); assert.equal(t.landedId, first)
  assert.deepEqual(events.map((e) => e.type), ['intent', 'sent', 'reconcile', 'intent', 'replaced', 'sent', 'included', 'readback'])
  assert.equal(events[6].txId, first)
  const st = reduce(SOL_DEF, asJournal([armedEvent(['sol'], 10n ** 9n)], events))
  const cs = st.chains.sol!
  assert.deepEqual(cs.txs[0].attempts.map((a) => a.state), ['included', 'superseded']); assert.equal(cs.spent, '5000'); assert.equal(cs.resume, null)
  assert.deepEqual([ledger.spent, ledger.held], [5000n, 0n])
  const rebuilt = CapLedger.view(st, 'sol', 'd1-engine'); assert.deepEqual([rebuilt.spent, rebuilt.held], [5000n, 0n])
  assert.throws(() => ledger.reserve(t as { copy: number; part: number }, 1n), /already landed/); ledger.close()
})

test('D-2 (engine): a SOL claw-back member proven expired, then the next try throws → the claw-back failed by itself; the next ledger builds, idle', { timeout: 30_000 }, async () => {
  const base = fakeSolChain()
  let confirmed = 0
  const relay = fakeRelay({ sol: (m, p) => {
    if (m === 'getLatestBlockhash') {
      if (p[0]?.commitment === 'finalized') return { context: { slot: 900 }, value: { blockhash: BH, lastValidBlockHeight: 2_150 } }
      if (++confirmed > 1) throw new Error('upstream unreachable')            // the second try's fee read fails
      return { context: { slot: 500 }, value: { blockhash: base58.encode(new Uint8Array(32).fill(9)), lastValidBlockHeight: 1_000 } }
    }
    if (m === 'isBlockhashValid') return { context: { slot: 1_000 }, value: false }   // Efix3: the blockhash has expired
    if (m === 'getSignatureStatuses') return { context: { slot: 1_000 }, value: (p[0] as string[]).map(() => null) }
    return base.handler(m, p)
  } })
  const { journal, events } = recordingJournal()
  const kp = Keypair.generate(), dest = Keypair.generate().publicKey.toBase58()
  const settled = [ev('sol', 'stopped', { reason: 'operator' })]
  await assert.rejects(clawbackSol({ chain: 'sol', kp }, dest, { journal, network: 'local', poll: 1, alive: () => true, notify: async () => {}, clock: fakeClock(), solEndpoints: 1, state: armedState('sol', 10n ** 12n) }), /upstream unreachable/)
  assert.deepEqual(events.map((e) => [e.type, e.outcome ?? null]), [['clawback-intent', null], ['clawback-sent', 'accepted'], ['reconcile', 'expired']])
  assert.equal(relay.sends().length, 1)
  const st = reduce(SOL_DEF, asJournal([armedEvent(['sol'], 10n ** 12n)], [...settled, ...events]))
  const cs = st.chains.sol!
  assert.deepEqual([cs.phase, cs.openIntents, cs.clawback!.ok, cs.clawback!.landed], ['STOPPED', [], false, false], 'every member dead, none landed: failed by itself')
  const next = CapLedger.fromArmed(st, 'sol', 'd2-engine')
  assert.deepEqual([next.idle, next.spent], [true, 0n]); next.close()
})

test('the lane runner stops when an adapter reports a tx confirmed without a journaled inclusion (the cap counts only journaled spend)', async () => {
  const { runDrain, newLaneState } = await import('../../src/engine/lane.js')
  const ledger = armedLedger('eth', 10n ** 9n)
  const A = { planCopy: () => [{ i: 1, n: 1, chunk: new Uint8Array(1), payload: Uint8Array.from([1]) }], startLevel: async () => ({ label: 'L0', level: 0 }), balance: async () => 100n,
    decide: async () => ({ send: true, cost: 1n, spend: 1n }), sendTx: async (t: any) => { t.actual = 1n; t.readback = { ok: true }; return 'confirmed' }, learn: () => {} }
  const { journal, events } = recordingJournal()
  const lane = newLaneState({ chain: 'eth', mode: 'drain', startCopy: 1 })
  assert.equal(await runDrain(lane, A, { journal, ledger, sleep: async () => {} }), 'failed')
  assert.match(lane.reason, /without a journaled inclusion/); assert.equal(events.at(-1)!.type, 'stopped'); ledger.close()
})

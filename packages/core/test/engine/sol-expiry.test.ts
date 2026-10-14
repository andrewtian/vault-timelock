// Efix3 (E4 parked / E3 ruling 3): a SOL attempt is re-signed only after PROVEN expiry, and the proof is isBlockhashValid on
// every verified endpoint (not block-height reasoning). Valid → wait (the same bytes are rebroadcast, never a new tx);
// invalid (+ absent from history) → expired → re-sign; an RPC error or an ambiguous answer → NOT proof, no re-sign.
// ALL DATA IS SYNTHETIC; the relay is a fake fetch function; the clock is virtual.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { base58 } from '@scure/base'
import { Keypair } from '@solana/web3.js'
import { solTx } from '../../src/engine/engine.js'
import { assertStatusAnswer } from '../../src/gates/sol-expiry.ts'
import { utf8 } from '../../src/chains/plan.js'
import { armedLedger, fakeClock, fakeRelay, fakeSolChain, recordingJournal } from './fakes.ts'

type Answer = (bh: string, ep: string | null, firstBh: string) => unknown
async function run(answer: Answer, endpoints = 1, windowMs = 120_000, finalizedPast: boolean | ((ep: string | null) => boolean) = true, histSlot = 1_000, hist?: (ids: string[], ep: string | null) => unknown, finAnswer?: unknown) {
  const base = fakeSolChain()
  let prepares = 0, firstBh = ''
  const relay = fakeRelay({ sol: (m, p, ep) => {
    if (m === 'getLatestBlockhash' && p[0]?.commitment === 'finalized' && finAnswer !== undefined) return finAnswer
    if (m === 'getLatestBlockhash' && p[0]?.commitment === 'finalized') return { context: { slot: 900 }, value: { blockhash: base58.encode(new Uint8Array(32).fill(250)), lastValidBlockHeight: (typeof finalizedPast === 'function' ? finalizedPast(ep) : finalizedPast) ? 2_150 : 900 } }   // finalized height 2,000 (past) or 750
    if (m === 'getLatestBlockhash') { prepares++; return { context: { slot: 500 }, value: { blockhash: base58.encode(new Uint8Array(32).fill(prepares)), lastValidBlockHeight: 1_000 } } }
    if (m === 'isBlockhashValid') { if (firstBh === '') firstBh = p[0] as string; return answer(p[0] as string, ep, firstBh) }
    if (m === 'getSignatureStatuses' && hist) return hist(p[0] as string[], ep)
    if (m === 'getSignatureStatuses') return { context: { slot: histSlot }, value: (p[0] as string[]).map(() => null) }   // never lands
    return base.handler(m, p)
  } })
  const { journal, events } = recordingJournal()
  const clock = fakeClock(), end = clock.now() + windowMs
  const ledger = armedLedger('sol', 10n ** 9n), t: Record<string, any> = { copy: 1, part: 1, parts: 1, payload: utf8('expiry memo') }
  const r = await solTx(t, { kp: Keypair.generate(), notify: async () => {}, alive: () => clock.now() < end, poll: 1, rent: 890_880n, used: new Map(), journal, ledger, clock, solEndpoints: endpoints,
    lane: { txs: [] }, payerFloor: 890_880n, cuPriceCap: 2_000_000, policy: { price: async () => ({ lamports: 0, rung: 0 }) } })
  ledger.close()
  return { r, t, relay, types: events.map((e) => e.type), intents: events.filter((e) => e.type === 'intent').length }
}
const ok = (valid: boolean, slot = 1_000) => ({ context: { slot }, value: valid })

test('valid blockhash → wait: nothing is declared expired, nothing is re-signed, the same bytes are rebroadcast', { timeout: 30_000 }, async () => {
  const x = await run(() => ok(true))
  assert.equal(x.r, 'aborted'); assert.equal(x.intents, 1)
  assert.ok(!x.types.includes('reconcile') && !x.types.includes('replaced'))
  assert.ok(x.relay.sends().length > 5, 'rebroadcasts of the one signature')
})

test('invalid blockhash (and no signature in history) → expired → one re-sign with a new blockhash', { timeout: 30_000 }, async () => {
  const x = await run((bh, _ep, first) => ok(bh !== first))   // the first blockhash is dead, the new one is valid
  assert.equal(x.intents, 2)
  const i = x.types.indexOf('reconcile'); assert.ok(i >= 0 && x.types.indexOf('intent', i) > i, 'reconcile expired is journaled BEFORE the re-sign')
  assert.ok(x.types.includes('replaced'))
})

test('invalid on ONE of two endpoints only → not expired, no re-sign', { timeout: 30_000 }, async () => {
  const x = await run((_bh, ep) => ok(ep === '0'), 2)
  assert.equal(x.intents, 1); assert.ok(!x.types.includes('reconcile'))
})

test('RPC error from isBlockhashValid → no proof: never expired, never re-signed (fail closed)', { timeout: 30_000 }, async () => {
  const x = await run(() => { throw new Error('upstream unreachable') })
  assert.equal(x.intents, 1); assert.ok(!x.types.includes('reconcile') && !x.types.includes('replaced'))
  assert.ok(x.relay.sends().length > 5, 'Eminors (m-2): an unreadable validity answer does not stop the same-bytes rebroadcast')
  const stale = await run(() => ok(false, 400))
  assert.ok(stale.relay.sends().length > 5, 'nor does a stale one')
})

test('ambiguous isBlockhashValid answers (null, no value, string value, no slot, undefined) → no proof, no re-sign', { timeout: 60_000 }, async () => {
  for (const a of [null, { context: { slot: 1_000 } }, { context: { slot: 1_000 }, value: 'false' }, { context: { slot: 1_000 }, value: 0 }, { value: false }, undefined]) {
    const x = await run(() => a, 1, 30_000)
    assert.equal(x.intents, 1, JSON.stringify(a)); assert.ok(!x.types.includes('reconcile'), JSON.stringify(a))
  }
})

test('a node whose bank is older than the blockhash fetch slot cannot prove expiry', { timeout: 30_000 }, async () => {
  const x = await run(() => ok(false, 400))   // fetched at slot 500
  assert.equal(x.intents, 1); assert.ok(!x.types.includes('reconcile'))
  assert.match(String(x.t.note), /older than the slot the blockhash was fetched/, 'refused by the stale gate')
})

test('single-endpoint trust: invalid everywhere but the finalized height NOT past the signature\'s lastValidBlockHeight -> no expiry (the old rule is kept)', { timeout: 30_000 }, async () => {
  const x = await run((bh, _ep, first) => ok(bh !== first), 1, 120_000, false)
  assert.equal(x.intents, 1); assert.ok(!x.types.includes('reconcile'))
})
test('single-endpoint trust: two endpoints, one lies "invalid", the other says valid -> no re-sign (either order)', { timeout: 30_000 }, async () => {
  for (const liar of ['0', '1']) {
    const x = await run((bh, ep, first) => ok(ep === null ? bh !== first : ep !== liar), 2)   // the preferred route says invalid: the per-endpoint loop decides
    assert.equal(x.intents, 1, `liar ${liar}`); assert.ok(!x.types.includes('reconcile'))
  }
})
test('single-endpoint trust: two endpoints, one errors -> no re-sign (either order)', { timeout: 30_000 }, async () => {
  for (const bad of ['0', '1']) {
    const x = await run((bh, ep, first) => { if (ep === bad) throw new Error('timeout'); return ok(bh !== first) }, 2)
    assert.equal(x.intents, 1, `bad ${bad}`); assert.ok(!x.types.includes('reconcile'))
  }
})
test('single-endpoint trust: two endpoints both invalid and no landing -> exactly one re-sign', { timeout: 30_000 }, async () => {
  const x = await run((bh, _ep, first) => ok(bh !== first), 2)
  assert.equal(x.intents, 2); assert.equal(x.types.filter((t) => t === 'reconcile').length, 1)
})
test('single-endpoint trust: the signature landed on ANY endpoint (even with every blockhash invalid) -> reconciled as landed, no re-sign', { timeout: 30_000 }, async () => {
  for (const seer of ['0', '1']) {
    const base = fakeSolChain()
    let sig = ''
    const relay = fakeRelay({ sol: (m, p, ep) => {
      if (m === 'getLatestBlockhash' && p[0]?.commitment === 'finalized') return { context: { slot: 900 }, value: { blockhash: base58.encode(new Uint8Array(32).fill(250)), lastValidBlockHeight: 2_150 } }
      if (m === 'isBlockhashValid') return ok(false)
      if (m === 'sendTransaction') { const r = base.handler(m, p) as string; sig = r; return r }
      if (m === 'getSignatureStatuses') {
        const asked = p[1]?.searchTransactionHistory === true
        return { context: { slot: 1_000 }, value: (p[0] as string[]).map((x) => (asked && ep === seer && x === sig ? { slot: 501, confirmations: 1, err: null, confirmationStatus: 'confirmed' } : null)) }
      }
      if (m === 'getTransaction') return base.handler(m, p)
      return base.handler(m, p)
    } })
    void relay
    const { journal, events } = recordingJournal()
    const clock = fakeClock(), end = clock.now() + 120_000
    const ledger = armedLedger('sol', 10n ** 9n), t: Record<string, any> = { copy: 1, part: 1, parts: 1, payload: utf8('expiry memo') }
    const r = await solTx(t, { kp: Keypair.generate(), notify: async () => {}, alive: () => clock.now() < end, poll: 1, rent: 890_880n, used: new Map(), journal, ledger, clock, solEndpoints: 2,
      lane: { txs: [] }, payerFloor: 890_880n, cuPriceCap: 2_000_000, policy: { price: async () => ({ lamports: 0, rung: 0 }) } })
    assert.equal(r, 'confirmed', `seer ${seer}`)
    assert.equal(events.filter((e) => e.type === 'intent').length, 1, 'never re-signed'); assert.ok(events.some((e) => e.type === 'included'))
    assert.ok(!events.some((e) => e.type === 'reconcile' && e.outcome === 'expired'))
    ledger.close()
  }
})

test('single-endpoint trust: the finalized height is past on ONE of two endpoints only -> no re-sign (either order)', { timeout: 30_000 }, async () => {
  for (const past of ['0', '1']) {
    const x = await run((bh, _ep, first) => ok(bh !== first), 2, 120_000, (ep) => ep === null || ep === past)   // preferred route past: the per-endpoint height check decides
    assert.equal(x.intents, 1, `past on ${past} only`); assert.ok(!x.types.includes('reconcile'))
  }
})
test('single-endpoint trust: history older than the validity answer / the finalized slot -> no re-sign', { timeout: 30_000 }, async () => {
  for (const [hist, valid] of [[999, 1_000], [800, 1_000]] as const) {   // finalized slot 900, validity slot 1,000
    const x = await run((bh, _ep, first) => ok(bh !== first, valid), 1, 120_000, true, hist)
    assert.equal(x.intents, 1, `history slot ${hist}`); assert.ok(!x.types.includes('reconcile'))
  }
})

// m-1: history fresher than the validity answer but older than the finalized bank (finalized slot 900)
test('m-1: history slot >= validity slot but < the finalized slot -> no re-sign', { timeout: 30_000 }, async () => {
  const x = await run((bh, _ep, first) => ok(bh !== first, 800), 1, 120_000, true, 850)
  assert.equal(x.intents, 1); assert.ok(!x.types.includes('reconcile'))
})
test('m-3: a validity answer older than the finalized bank cannot prove expiry', { timeout: 30_000 }, async () => {
  const x = await run((bh, _ep, first) => ok(bh !== first, 850), 1, 120_000, true, 1_000)
  assert.equal(x.intents, 1); assert.ok(!x.types.includes('reconcile'))
})
// m-B: the gate itself refuses a status answer without a context slot (the engine's slot comparisons are not what catches it)
test('m-B: assertStatusAnswer refuses a missing context / slot / non-integer slot directly', () => {
  const refusal = (f: () => unknown) => { try { f() } catch (e) { return (e as { guardId?: string }).guardId } return null }
  for (const bad of [{ value: [null] }, { context: {}, value: [null] }, { context: { slot: '5' }, value: [null] }, { context: { slot: 1.5 }, value: [null] }, { context: null, value: [null] }])
    assert.equal(refusal(() => assertStatusAnswer(bad, ['x'])), 'engine.sol-expiry-status', JSON.stringify(bad))
  assert.deepEqual(assertStatusAnswer({ context: { slot: 7 }, value: [null] }, ['x']), { slot: 7, value: [null] })
})

// I-1: a garbled history answer is not "absent"
const GARBLED: Array<[string, (ids: string[]) => unknown]> = [
  ['value null', () => ({ context: { slot: 1_000 }, value: null })],
  ['value []', () => ({ context: { slot: 1_000 }, value: [] })],
  ['value missing', () => ({ context: { slot: 1_000 } })],
  ['context missing', (ids) => ({ value: ids.map(() => null) })],
  ['slot missing', (ids) => ({ context: {}, value: ids.map(() => null) })],
  ['answer null', () => null],
  ['wrong length', (ids) => ({ context: { slot: 1_000 }, value: [...ids, null] })],
]
test('I-1: a garbled history answer on 1 or on 2 endpoints (or on one of two) -> no re-sign, no expired', { timeout: 120_000 }, async () => {
  for (const [name, g] of GARBLED) for (const [eps, bad] of [[1, () => true], [2, () => true], [2, (ep: string | null) => ep === '1']] as const) {
    const x = await run((bh, _ep, first) => ok(bh !== first), eps, 30_000, true, 1_000, (ids, ep) => (bad(ep) ? g(ids) : { context: { slot: 1_000 }, value: ids.map(() => null) }))
    assert.equal(x.intents, 1, `${name} eps=${eps}`); assert.ok(!x.types.includes('reconcile'), `${name} eps=${eps}`)
  }
})

test('I-1: a finalized-bank answer without a context slot (or lastValidBlockHeight) is no proof (never slot 0)', { timeout: 60_000 }, async () => {
  for (const bad of [{ value: { blockhash: 'x', lastValidBlockHeight: 2_150 } }, { context: { slot: 900 }, value: {} }, null]) {
    const x = await run((bh, _ep, first) => ok(bh !== first), 1, 30_000, true, 1_000, undefined, bad)
    assert.equal(x.intents, 1, JSON.stringify(bad)); assert.ok(!x.types.includes('reconcile'))
    assert.match(String(x.t.note), /lastValidBlockHeight|context slot/, 'refused by the shape gate, not by a later comparison')
  }
})

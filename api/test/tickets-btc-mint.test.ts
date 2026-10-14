// CC-8 / S6b fix round 1 (I-2): the API mints a btc ticket ONLY from values it computes. ticketBinding('btc', …) takes the
// executor's intent (lane pubkey, a fee and a value under the caps, the lane outpoints, the commit's vout) and the API's own
// context (the network, the body sliced from the STORED message, the journaled commit's txid) and returns the binding, or
// null (the API then refuses the intent before journaling it). Cross-checked against the contract's tickets-btc.json: the
// builder (gen-fixtures), the API and the relay agree on every address.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { pubECDSA } from '@scure/btc-signer/utils.js'
import { BTC_POSTAGE, commitAddress, laneAddresses, maxCommitFee, maxCommitValue, maxRevealFee, revealDestination } from '@vault-timelock/core/chains/btc-ord.ts'
import type { Network, TicketPayload } from '@vault-timelock/core/contracts'
import { isTicketPayload, ticketBinding } from '../src/tickets.ts'
import { fixture } from './helpers.ts'

const seed = (label: string): Buffer => createHash('sha256').update(`vt-fixture:${label}`).digest()
const sha = (b: Uint8Array | string): string => createHash('sha256').update(b).digest('hex')
const PUB = Buffer.from(pubECDSA(seed('ticket btc lane'))).toString('hex')
const OTHER_PUB = Buffer.from(pubECDSA(seed('ticket btc other'))).toString('hex')
const BODY = new TextEncoder().encode('[1/1 ticket] A synthetic vt ticket vector part.\n')
const LANE = (n: Network) => laneAddresses(n, Buffer.from(PUB, 'hex'))!
const O1 = `${'11'.repeat(32)}:0`, O2 = `${'22'.repeat(32)}:3`
const COMMIT_TX = 'cd'.repeat(32)
const ctx = (network: Network = 'local', o: { body?: Uint8Array | null; commitTxId?: string | null } = {}) => ({ network, body: o.body === undefined ? BODY : o.body, commitTxId: o.commitTxId === undefined ? COMMIT_TX : o.commitTxId })
const commitData = (o: Record<string, unknown> = {}, btc: Record<string, unknown> = {}): Record<string, unknown> =>
  ({ txId: '00'.repeat(32), payloadSha256: sha(BODY), btc: { kind: 'commit', pubkey: PUB, fee: '306', value: '846', inputs: [O1], ...btc }, ...o })
const revealData = (o: Record<string, unknown> = {}, btc: Record<string, unknown> = {}): Record<string, unknown> =>
  ({ txId: '00'.repeat(32), payloadSha256: sha(BODY), btc: { kind: 'reveal', pubkey: PUB, fee: '300', commitVout: 0, ...btc }, ...o })
const A = (n: Network = 'local'): string => LANE(n).p2wpkh

test('a commit: every field is the API\'s own — a = the key address, p = sha256(stored body), to = the NUMS inscription address, q = the lane outpoints', () => {
  for (const n of ['local', 'testnet', 'mainnet'] as const) {
    const b = ticketBinding('btc', 'intent', commitData(), A(n), ctx(n))!
    assert.deepEqual(b, { a: A(n), k: 'commit', p: sha(BODY), to: commitAddress(n, LANE(n).xonly, BODY), value: '846', f: '306', q: O1, x: null })
    const two = ticketBinding('btc', 'intent', commitData({}, { inputs: [O1, O2] }), A(n), ctx(n))!
    assert.equal(two.q, `${O1},${O2}`)
    // the result is a valid ticket payload shape
    assert.ok(isTicketPayload({ j: 'e3d45f73cf65abaa', w: n, c: 'btc', g: 1, t: '00'.repeat(32), r: '11'.repeat(32), ...b, e: 1, n: '0123456789abcdef' } satisfies TicketPayload))
    // PF-S fix round 2: a btc ticket carries no fee members (x null); any x is malformed
    for (const x of ['30000:0', '21000:1:2', '', undefined]) {
      assert.ok(!isTicketPayload({ j: 'e3d45f73cf65abaa', w: n, c: 'btc', g: 1, t: '00'.repeat(32), r: '11'.repeat(32), ...b, x, e: 1, n: '0123456789abcdef' }), String(x))
    }
  }
})

test('a reveal: q = the journaled commit txid : vout, to = the lane\'s p2tr, value = the postage', () => {
  for (const n of ['local', 'testnet', 'mainnet'] as const) {
    const b = ticketBinding('btc', 'intent', revealData({}, { commitVout: 1 }), A(n), ctx(n))!
    assert.deepEqual(b, { a: A(n), k: 'reveal', p: sha(BODY), to: revealDestination(n, LANE(n).xonly), value: String(BTC_POSTAGE), f: '300', q: `${COMMIT_TX}:1`, x: null })
  }
  // the lane's p2tr is NOT a key address (review m-1): the reveal's postage lands there, and a commit must never be able to spend it back
  assert.equal(ticketBinding('btc', 'intent', revealData(), LANE('local').p2tr, ctx()), null)
  assert.equal(ticketBinding('btc', 'intent', commitData(), LANE('local').p2tr, ctx()), null)
})

test('agreement with the contract vectors: the fixture\'s commit address and reveal destination are exactly what the API computes', () => {
  const V = fixture<{ valid: Array<{ payload: TicketPayload }> }>('tickets-btc.json')
  for (const v of V.valid) {
    const p = v.payload
    if (p.k !== 'commit' && p.k !== 'reveal') continue
    const inputs = p.k === 'commit' ? p.q.split(',') : null
    const data = p.k === 'commit' ? commitData({}, { value: p.value, fee: p.f, inputs }) : revealData({}, { fee: p.f, commitVout: Number(p.q.split(':')[1]) })
    const b = ticketBinding('btc', 'intent', data, p.a, ctx(p.w, { commitTxId: p.q.split(':')[0] }))
    assert.deepEqual(b, { a: p.a, k: p.k, p: p.p, to: p.to, value: p.value, f: p.f, q: p.q, x: null }, `${p.w} ${p.k}`)
    assert.equal(p.x, null, 'btc tickets carry no fee members (PF-S fix round 2)')
  }
})

test('refused (null) unless every field is the API\'s: no context, no body, wrong kind of intent, a foreign lane key', () => {
  const ok = (d: Record<string, unknown>, a: string | null = A(), c: ReturnType<typeof ctx> | null = ctx(), type = 'intent'): unknown => ticketBinding('btc', type, d, a, c ?? undefined)
  assert.notEqual(ok(commitData()), null)
  assert.equal(ok(commitData(), A(), null), null, 'no API context')
  assert.equal(ok(commitData(), A(), ctx('local', { body: null })), null, 'no stored message')
  assert.equal(ok(commitData({ payloadSha256: sha(new Uint8Array(0)) }), A(), ctx('local', { body: new Uint8Array(0) })), null, 'an empty body')
  assert.equal(ok(commitData(), null), null, 'no key address')
  assert.equal(ok(commitData(), A(), ctx(), 'clawback-intent'), null, 'btc has no claw-back ticket')
  assert.equal(ok(commitData({ eth: {} })), null); assert.equal(ok(commitData({ sol: {} })), null)
  assert.equal(ok({ ...commitData(), btc: undefined }), null); assert.equal(ok({ ...commitData(), btc: [] }), null)
  // the key
  assert.equal(ok(commitData({}, { pubkey: OTHER_PUB })), null, 'another key: hash160 differs from a')
  assert.equal(ok(commitData(), A('testnet')), null, 'a is another network\'s address')
  assert.equal(ok(commitData(), LANE('local').p2wpkh.toUpperCase()), null)
  for (const pk of ['', PUB.slice(2), `04${PUB.slice(2)}`, PUB.toUpperCase(), `02${'ff'.repeat(32)}`, 5, null]) assert.equal(ok(commitData({}, { pubkey: pk })), null, String(pk).slice(0, 12))
  // the body: the intent's payloadSha256 must be the hash of the stored message's bytes
  assert.equal(ok(commitData({ payloadSha256: sha('other text') })), null)
  assert.equal(ok(commitData({ payloadSha256: undefined })), null)
  assert.equal(ok(commitData(), A(), ctx('local', { body: Uint8Array.from([...BODY, 10]) })), null, 'the stored body is not the one the intent hashed')
})

test('commit caps and shapes: value in [postage, postage + reveal fee cap], fee under the cap, 1..8 ascending lane outpoints; extra members refused', () => {
  const c = (btc: Record<string, unknown>): unknown => ticketBinding('btc', 'intent', commitData({}, btc), A(), ctx())
  const maxV = maxCommitValue(BODY.length), maxF = maxCommitFee(1)
  assert.notEqual(c({ value: String(maxV) }), null); assert.equal(c({ value: String(maxV + 1n) }), null)
  assert.notEqual(c({ value: '546' }), null); assert.equal(c({ value: '545' }), null)
  assert.equal(c({ value: '5000000000' }), null, 'the whole lane balance to the inscription address')
  assert.notEqual(c({ fee: String(maxF) }), null); assert.equal(c({ fee: String(maxF + 1n) }), null)
  for (const v of [0, '0', '', '0846', '-1', 846, '1e3', null]) assert.equal(c({ value: v }), null, `value ${String(v)}`)
  for (const f of [0, '0', '', '0306', 306, null]) assert.equal(c({ fee: f }), null, `fee ${String(f)}`)
  const many = Array.from({ length: 9 }, (_, i) => `${String(i).repeat(64)}:0`)
  assert.notEqual(c({ inputs: many.slice(0, 8), fee: String(maxCommitFee(8)) }), null); assert.equal(c({ inputs: many }), null)
  for (const inputs of [[], [O2, O1], [O1, O1], [`${'AA'.repeat(32)}:0`], [`${'11'.repeat(32)}:00`], [`${'11'.repeat(32)}`], 'x', null, [5], [`${O1},${O2}`]]) assert.equal(c({ inputs }), null, JSON.stringify(inputs).slice(0, 40))
  assert.equal(ticketBinding('btc', 'intent', commitData({}, { extra: 1 }), A(), ctx()), null)
  assert.equal(ticketBinding('btc', 'intent', commitData({}, { commitVout: 0 }), A(), ctx()), null)
  assert.equal(ticketBinding('btc', 'intent', commitData({}, { kind: 'publish' }), A(), ctx()), null)
  // a value the executor could pick cannot move `to`: to is the same whatever the value
  assert.equal(ticketBinding('btc', 'intent', commitData({}, { value: '600' }), A(), ctx())!.to, ticketBinding('btc', 'intent', commitData(), A(), ctx())!.to)
})

test('the intent\'s members are a SET: any key order is accepted, a missing or extra member is not (m-3); a pubkey off the curve is refused, not thrown (m-2)', () => {
  const rev = { fee: '300', commitVout: 0, pubkey: PUB, kind: 'reveal' }, com = { inputs: [O1], value: '846', fee: '306', pubkey: PUB, kind: 'commit' }
  assert.notEqual(ticketBinding('btc', 'intent', { ...revealData(), btc: rev }, A(), ctx()), null)
  assert.notEqual(ticketBinding('btc', 'intent', { ...commitData(), btc: com }, A(), ctx()), null)
  assert.equal(ticketBinding('btc', 'intent', { ...commitData(), btc: { ...com, commitVout: 0 } }, A(), ctx()), null)
  assert.equal(ticketBinding('btc', 'intent', { ...commitData(), btc: { kind: 'commit', pubkey: PUB, fee: '306', inputs: [O1] } }, A(), ctx()), null)
  for (const x of ['05', '07', '09', '0a', '0b']) assert.equal(ticketBinding('btc', 'intent', commitData({}, { pubkey: `02${'00'.repeat(31)}${x}` }), A(), ctx()), null, x)
})

test('reveal shapes: needs the journaled commit txid; the vout is a small integer; the fee is under the cap; no value, no inputs, no destination of the executor\'s', () => {
  const r = (btc: Record<string, unknown>, c = ctx()): unknown => ticketBinding('btc', 'intent', revealData({}, btc), A(), c)
  assert.equal(r({}, ctx('local', { commitTxId: null })), null)
  for (const t of ['', 'CD'.repeat(32), 'cd'.repeat(31), `${COMMIT_TX}:0`]) assert.equal(r({}, ctx('local', { commitTxId: t })), null, t.slice(0, 12))
  for (const v of [-1, 1.5, '0', 1e10, null, NaN]) assert.equal(r({ commitVout: v }), null, String(v))
  const maxF = maxRevealFee(BODY.length)
  assert.notEqual(r({ fee: String(maxF) }), null); assert.equal(r({ fee: String(maxF + 1n) }), null)
  for (const extra of [{ value: '546' }, { to: LANE('local').p2tr }, { inputs: [O1] }, { q: O1 }]) assert.equal(r(extra), null, Object.keys(extra)[0])
})

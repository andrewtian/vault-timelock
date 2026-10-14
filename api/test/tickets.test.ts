// Send tickets (CC-3: vt-ticket/2): the tickets.json vectors exactly; expired (at e and after) → relay.ticket-expired; a
// MAC flip, a MAC that differs only in its base64url padding bits, a wrong key, a bad format, a malformed v2 field or a
// v1 ticket (no downgrade) → relay.send-ticket. ticketBinding / worstCaseFee: the v2 fields the API binds.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { TICKET_PREFIX } from '@vault-timelock/core/contracts'
import type { TicketPayload } from '@vault-timelock/core/contracts'
import { base58Decode, base58Encode, encodeTicket, isSolAddress, issueTicket, ticketBinding, verifyTicket, worstCaseFee } from '../src/tickets.ts'
import { TICKET_KEY, fixture } from './helpers.ts'

interface Valid { payload: TicketPayload; issuedAt: number; ticket: string; now: number }
interface Negative { name: string; ticket: string; now: number; guard: string }
const V = fixture<{ format: string; key: string; ttlMs: number; valid: Valid[]; negatives: Negative[] }>('tickets.json')
const S1_GUARDS = new Set(['relay.send-ticket', 'relay.ticket-expired'])
const guardOf = (fn: () => unknown): string => {
  try { fn() } catch (e) { return (e as { guardId: string }).guardId }
  assert.fail('expected a refusal')
}
const b64 = (s: string): string => Buffer.from(s, 'utf8').toString('base64url')
const P = TICKET_PREFIX
const sign = (key: Uint8Array, p64: string, prefix = P): string => `${prefix}${p64}.${createHmac('sha256', key).update(`${prefix}${p64}`).digest('base64url')}`
const S1_NAMES = ['bad-mac', 'mac-non-canonical', 'wrong-key', 'v1-ticket', 'v1-payload-under-v2', 'bad-format-version', 'bad-format-parts', 'v2-key-order',
  'v2-extra-key', 'v2-kind-unknown', 'v2-job-without-p', 'v2-job-without-to', 'v2-job-with-value', 'v2-clawback-with-p', 'v2-clawback-value-0',
  'v2-clawback-without-to', 'v2-fee-0', 'v2-fee-leading-zero', 'v2-fee-number', 'v2-sender-checksummed', 'v2-sender-sol-on-eth',
  'v2-nonce-missing', 'v2-nonce-leading-zero', 'v2-nonce-number', 'v2-nonce-blockhash-on-eth', 'v2-fee-members-missing', 'v2-fee-members-two', 'v2-blockhash-nonce-on-sol', 'v2-sol-job-with-to', 'expired-at-e', 'expired-after-e']

test('valid vectors: encodeTicket reproduces each ticket byte for byte, and verifyTicket returns its payload', () => {
  assert.equal(P, 'vt-ticket/2.')
  assert.equal(V.valid.length, 10)
  for (const v of V.valid) {
    assert.equal(encodeTicket(TICKET_KEY, v.payload), v.ticket)
    assert.deepEqual(verifyTicket(TICKET_KEY, v.ticket, v.now), v.payload)
    assert.deepEqual(verifyTicket(TICKET_KEY, v.ticket, v.payload.e - 1), v.payload)
    assert.equal(v.payload.e, v.issuedAt + V.ttlMs)
  }
})

test('negative vectors: S1\'s guards exactly; the relay-gate defects (S3) are valid tickets here', () => {
  for (const n of V.negatives) {
    if (S1_GUARDS.has(n.guard)) assert.equal(guardOf(() => verifyTicket(TICKET_KEY, n.ticket, n.now)), n.guard, n.name)
    else assert.equal(verifyTicket(TICKET_KEY, n.ticket, n.now).j, 'e3d45f73cf65abaa', n.name)
  }
  const names = V.negatives.filter((n) => S1_GUARDS.has(n.guard)).map((n) => n.name)
  assert.deepEqual(names, S1_NAMES)
})

test('expired: now == e and now > e → relay.ticket-expired; now = e - 1 is valid', () => {
  const v = V.valid[0]
  assert.equal(guardOf(() => verifyTicket(TICKET_KEY, v.ticket, v.payload.e)), 'relay.ticket-expired')
  assert.equal(guardOf(() => verifyTicket(TICKET_KEY, v.ticket, v.payload.e + 86_400_000)), 'relay.ticket-expired')
  assert.equal(guardOf(() => verifyTicket(TICKET_KEY, v.ticket, Number.NaN)), 'relay.ticket-expired')
  assert.equal(verifyTicket(TICKET_KEY, v.ticket, v.payload.e - 1).n, v.payload.n)
})

test('a flip anywhere in the MAC or the payload → relay.send-ticket', () => {
  const v = V.valid[1]
  const dot = v.ticket.lastIndexOf('.')
  for (let i = P.length; i < v.ticket.length; i++) {
    if (i === dot) continue
    const c = v.ticket[i]
    const flipped = v.ticket.slice(0, i) + (c === 'A' ? 'B' : 'A') + v.ticket.slice(i + 1)
    assert.equal(guardOf(() => verifyTicket(TICKET_KEY, flipped, v.now)), 'relay.send-ticket', `position ${i}`)
  }
})

test('MAC padding bits: every non-canonical spelling of the right MAC is refused', () => {
  const v = V.valid[2]
  const last = v.ticket.at(-1)!
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
  const idx = alphabet.indexOf(last)
  let tried = 0
  for (let bits = 1; bits < 4; bits++) {
    const alt = alphabet[(idx & ~3) | ((idx & 3) ^ bits)]
    const t = v.ticket.slice(0, -1) + alt
    assert.deepEqual(Buffer.from(t.split('.').at(-1)!, 'base64url'), Buffer.from(v.ticket.split('.').at(-1)!, 'base64url')) // same bytes
    assert.equal(guardOf(() => verifyTicket(TICKET_KEY, t, v.now)), 'relay.send-ticket')
    tried++
  }
  assert.equal(tried, 3)
})

test('format: anything but prefix + two canonical base64url parts with a signed canonical payload → relay.send-ticket', () => {
  const v = V.valid[0]
  const [, p64, m64] = v.ticket.split('.')
  assert.equal(`${P}${p64}.${m64}`, v.ticket)
  const otherKey = Buffer.alloc(32, 7)
  // Correctly signed with the right key, but not a canonical, well-formed payload.
  const signedButOdd = [
    b64(JSON.stringify({ ...v.payload, extra: 1 })),
    b64(JSON.stringify({ w: v.payload.w, j: v.payload.j, c: v.payload.c, g: v.payload.g, t: v.payload.t, r: v.payload.r, a: v.payload.a, k: v.payload.k, p: v.payload.p,
      to: v.payload.to, value: v.payload.value, f: v.payload.f, q: v.payload.q, e: v.payload.e, n: v.payload.n })),
    b64(JSON.stringify({ j: v.payload.j, w: v.payload.w, c: v.payload.c, g: v.payload.g, t: v.payload.t, r: v.payload.r, e: v.payload.e, n: v.payload.n })),   // v1 keys
    b64(JSON.stringify({ ...v.payload, a: v.payload.a.toUpperCase().replace('0X', '0x') })),
    b64(JSON.stringify({ ...v.payload, k: 'clawback' })),
    b64(JSON.stringify({ ...v.payload, p: 'AB'.repeat(32) })),
    b64(JSON.stringify({ ...v.payload, f: '1e18' })),
    b64(JSON.stringify({ ...v.payload, f: `${'9'.repeat(79)}` })),
    b64(JSON.stringify({ ...v.payload, q: '-1' })),
    b64(JSON.stringify({ ...v.payload, q: '9'.repeat(21) })),
    b64(JSON.stringify({ ...v.payload, q: '0x7' })),
    b64(JSON.stringify({ ...v.payload, q: null })),
    b64(JSON.stringify(v.payload, null, 1)),
    b64(JSON.stringify({ ...v.payload, g: 0 })),
    b64(JSON.stringify({ ...v.payload, n: 'B0A72112431B05FE' })),
    b64(JSON.stringify({ ...v.payload, w: 'devnet' })),
    b64(JSON.stringify({ ...v.payload, t: 'not-a-tx' })),
    b64('not json'),
    Buffer.from([0xff, 0xfe]).toString('base64url'),
  ].map((p) => sign(TICKET_KEY, p))
  // A non-canonical payload spelling (padding bits set) signed as text: the bytes decode to the same JSON.
  const lastP = p64.at(-1)!
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
  if (p64.length % 4 !== 0) {
    const i = alphabet.indexOf(lastP)
    signedButOdd.push(sign(TICKET_KEY, p64.slice(0, -1) + alphabet[i ^ 1]))
  }
  const bad: unknown[] = [
    '', P, `${P}${p64}`, `${P}${p64}.${m64}.x`, `${P}${p64}=.${m64}`, `${P}${p64}.${m64}=`,
    `VT-TICKET/2.${p64}.${m64}`, ` ${v.ticket}`, `${v.ticket}\n`, `${P}${p64}.`, `${P}..${m64}`,
    `${P}${p64}.${m64}`.replace(p64, `${p64}A`), sign(otherKey, p64), `${P}${'A'.repeat(3000)}.${m64}`,
    `vt-ticket/1.${p64}.${m64}`, sign(TICKET_KEY, p64, 'vt-ticket/1.'),                                          // a v2 payload under v1: no downgrade
    undefined, null, 42, ...signedButOdd,
  ]
  for (const tk of bad) assert.equal(guardOf(() => verifyTicket(TICKET_KEY, tk as string, v.now)), 'relay.send-ticket', String(tk).slice(0, 60))
})

test('issueTicket: e = now + 120 s, n = 16 fresh hex, keys in order; verifies; never signs a malformed payload', () => {
  const v = V.valid[0]
  const { e: _e, n: _n, ...base } = v.payload
  const now = 1791504030000
  const a = issueTicket(TICKET_KEY, base, now)
  const b = issueTicket(TICKET_KEY, base, now)
  assert.notEqual(a, b)
  const p = verifyTicket(TICKET_KEY, a, now + 119_999)
  assert.deepEqual(Object.keys(p), ['j', 'w', 'c', 'g', 't', 'r', 'a', 'k', 'p', 'to', 'value', 'f', 'q', 'x', 'e', 'n'])
  assert.equal(p.e, now + 120_000)
  assert.match(p.n, /^[0-9a-f]{16}$/)
  assert.deepEqual({ ...p, n: v.payload.n }, { ...v.payload, e: now + 120_000 })
  assert.equal(guardOf(() => verifyTicket(TICKET_KEY, a, now + 120_000)), 'relay.ticket-expired')
  assert.throws(() => issueTicket(TICKET_KEY, { ...base, r: 'nothex' }, now))
  assert.throws(() => issueTicket(TICKET_KEY, { ...base, f: '0' }, now))
  assert.throws(() => issueTicket(TICKET_KEY, { ...base, k: 'clawback' }, now))
  assert.throws(() => issueTicket(TICKET_KEY, { ...base, q: '' }, now))
  // PF-S fix round 2 (R1-1): x is the chain's fee members, exactly (ETH gas:tip:maxFee, SOL cuLimit:cuPrice, btc null)
  for (const x of [null, undefined, '', '1:2', '1:2:3:4', '0:1:1', '1:01:1', '1:1:0', '30000:0', 'a:b:c', 1]) assert.throws(() => issueTicket(TICKET_KEY, { ...base, x } as never, now), String(x))
  const sbase = V.valid.find((x) => x.payload.c === 'sol')!.payload
  for (const x of [null, '0:0', '1400001:0', '30000', '30000:01', '30000:18446744073709551616', '1:2:3']) assert.throws(() => issueTicket(TICKET_KEY, { ...sbase, x } as never, now), String(x))
  assert.doesNotThrow(() => issueTicket(TICKET_KEY, { ...sbase, x: '1400000:18446744073709551615' }, now))
  assert.throws(() => issueTicket(Buffer.alloc(31), base, now))
  assert.throws(() => verifyTicket(Buffer.alloc(16), a, now))
})

// ---- the v2 binding (CC-3)

const ETH_A = '0x8739Eb87B3d11f221Df63454F8D229a1A4F4049C'
const SOL_A = 'J1iD84DGodSrY6VWvufemX4Y1axuRKEZvxUuDXqxQ1Tq'
const SOL_B = '8pUq7jxkLxNpHg6M9KxzRtNEC4pNEHsr4kDTLSE5uVRW'
const NULL_ETH = '0x0000000000000000000000000000000000000000'
const ethIntent = (o: Record<string, unknown> = {}): Record<string, unknown> => ({ txId: '0x' + 'ab'.repeat(32), copy: 1, part: 1, parts: 1, rawSha256: 'cd'.repeat(32), payloadSha256: 'ef'.repeat(32),
  eth: { nonce: 1, tip: '1000000', maxFee: '3000000000', gas: '60000', to: NULL_ETH }, ...o })
const solIntent = (o: Record<string, unknown> = {}): Record<string, unknown> => ({ txId: '5'.repeat(88), copy: 1, part: 1, parts: 1, rawSha256: 'cd'.repeat(32), payloadSha256: 'ef'.repeat(32),
  sol: { blockhash: SOL_B, lastValidBlockHeight: 9, cuPrice: 12_500, cuLimit: 30_000, rung: null, fee: '5375' }, ...o })
// PF-S I-1: the API's plan of the intent's copy (the planned parts' sha256, the recipient)
const ETH_PLAN = { digests: ['ef'.repeat(32)], to: NULL_ETH }
const SOL_PLAN = { digests: ['ef'.repeat(32)], to: null }

test('worstCaseFee: ETH gas × maxFee; SOL max(declared fee, 5000 + ⌈cuLimit × cuPrice / 10⁶⌉); malformed → null', () => {
  assert.equal(worstCaseFee('eth', ethIntent()), 180_000_000_000_000n)
  assert.equal(worstCaseFee('sol', solIntent()), 5_375n)
  assert.equal(worstCaseFee('sol', solIntent({ sol: { cuPrice: 12_500, cuLimit: 30_000, fee: '0' } })), 5_375n)          // an understated fee never lowers it
  assert.equal(worstCaseFee('sol', solIntent({ sol: { cuPrice: 0, cuLimit: 30_000, fee: '1' } })), 5_000n)
  assert.equal(worstCaseFee('sol', solIntent({ sol: { cuPrice: 1, cuLimit: 1, fee: '7000' } })), 7_000n)                // a higher declared fee is kept
  assert.equal(worstCaseFee('sol', solIntent({ sol: { cuPrice: 27_778, cuLimit: 450, fee: '0' } })), 5_013n)             // ⌈12.5001⌉
  for (const bad of [{ eth: { gas: '0', maxFee: '5' } }, { eth: { gas: '21000', maxFee: '0' } }, { eth: { gas: '021000', maxFee: '5' } }, { eth: { gas: 21000, maxFee: '5' } },
    { eth: null }, {}, { eth: { gas: '1', maxFee: '1' }, sol: {} }]) assert.equal(worstCaseFee('eth', bad as Record<string, unknown>), null, JSON.stringify(bad))
  for (const bad of [{ sol: { cuPrice: -1, cuLimit: 1, fee: '5000' } }, { sol: { cuPrice: 1.5, cuLimit: 1, fee: '5000' } }, { sol: { cuPrice: 1, cuLimit: 1, fee: 5000 } },
    { sol: { cuPrice: 1, cuLimit: 1 } }, {}, { sol: { cuPrice: 1, cuLimit: 1, fee: '1' }, eth: {} }]) assert.equal(worstCaseFee('sol', bad as Record<string, unknown>), null, JSON.stringify(bad))
})

test('ticketBinding: job → { a (ETH lower case), k job, p, to (ETH the planned recipient, SOL null), value null, f, q }; claw-back → { k clawback, to, value, p null, f, q }; anything missing → null', () => {
  assert.deepEqual(ticketBinding('eth', 'intent', ethIntent(), ETH_A, ETH_PLAN), { a: ETH_A.toLowerCase(), k: 'job', p: 'ef'.repeat(32), to: NULL_ETH, value: null, f: '180000000000000', q: '1', x: '60000:1000000:3000000000' })
  const claw = { txId: '0x' + 'ab'.repeat(32), rawSha256: 'cd'.repeat(32), to: '0x1111111111111111111111111111111111111111', value: '5', eth: { nonce: 2, tip: '1', maxFee: '2', gas: '21000', to: '0x1111111111111111111111111111111111111111' } }
  assert.deepEqual(ticketBinding('eth', 'clawback-intent', claw, ETH_A), { a: ETH_A.toLowerCase(), k: 'clawback', p: null, to: '0x1111111111111111111111111111111111111111', value: '5', f: '42000', q: '2', x: '21000:1:2' })
  assert.deepEqual(ticketBinding('sol', 'intent', solIntent(), SOL_A, SOL_PLAN), { a: SOL_A, k: 'job', p: 'ef'.repeat(32), to: null, value: null, f: '5375', q: SOL_B, x: '30000:12500' })
  assert.equal(ticketBinding('eth', 'intent', ethIntent({ eth: { ...(ethIntent().eth as object), nonce: 0 } }), ETH_A, ETH_PLAN)?.q, '0')
  // eth.calldata.self: the recipient is the lane key (any case in, lower case out)
  assert.equal(ticketBinding('eth', 'intent', ethIntent({ eth: { ...(ethIntent().eth as object), to: ETH_A } }), ETH_A, { digests: ETH_PLAN.digests, to: ETH_A })?.to, ETH_A.toLowerCase())
  const sclaw = { txId: '5'.repeat(88), rawSha256: 'cd'.repeat(32), to: SOL_B, value: '987', sol: { blockhash: SOL_B, lastValidBlockHeight: 9, cuPrice: 0, cuLimit: 1, rung: null, fee: '5000' } }
  assert.deepEqual(ticketBinding('sol', 'clawback-intent', sclaw, SOL_A), { a: SOL_A, k: 'clawback', p: null, to: SOL_B, value: '987', f: '5000', q: SOL_B, x: '1:0' })
  const nulls: Array<[string, string, Record<string, unknown>, string | null, unknown?]> = [
    ['eth', 'intent', ethIntent(), null], ['eth', 'intent', ethIntent(), SOL_A], ['eth', 'intent', ethIntent(), '0x123'], ['sol', 'intent', solIntent(), ETH_A],
    ['sol', 'intent', solIntent(), `${SOL_A}1`], ['eth', 'intent', ethIntent({ payloadSha256: 'EF'.repeat(32) }), ETH_A], ['eth', 'intent', ethIntent({ payloadSha256: undefined }), ETH_A],
    ['eth', 'intent', ethIntent({ eth: undefined }), ETH_A], ['eth', 'intent', solIntent(), ETH_A], ['eth', 'sent', ethIntent(), ETH_A],
    ['eth', 'clawback-intent', { ...claw, value: '0' }, ETH_A], ['eth', 'clawback-intent', { ...claw, value: '05' }, ETH_A], ['eth', 'clawback-intent', { ...claw, to: '0x12' }, ETH_A],
    ['sol', 'clawback-intent', { ...sclaw, to: ETH_A }, SOL_A], ['sol', 'clawback-intent', { ...sclaw, value: 987 }, SOL_A],
    // CC-3a: no declared nonce / blockhash, no ticket
    ['eth', 'intent', ethIntent({ eth: { ...(ethIntent().eth as object), nonce: undefined } }), ETH_A], ['eth', 'intent', ethIntent({ eth: { ...(ethIntent().eth as object), nonce: -1 } }), ETH_A],
    ['eth', 'intent', ethIntent({ eth: { ...(ethIntent().eth as object), nonce: 1.5 } }), ETH_A], ['eth', 'intent', ethIntent({ eth: { ...(ethIntent().eth as object), nonce: '1' } }), ETH_A],
    ['sol', 'intent', solIntent({ sol: { ...(solIntent().sol as object), blockhash: undefined } }), SOL_A], ['sol', 'intent', solIntent({ sol: { ...(solIntent().sol as object), blockhash: `1${SOL_B}` } }), SOL_A],
    ['sol', 'clawback-intent', { ...sclaw, sol: { ...sclaw.sol, blockhash: 'nope' } }, SOL_A],
    // PF-S fix round 2 (R1-1): no well-formed fee members (x), no ticket
    ['eth', 'intent', ethIntent({ eth: { ...(ethIntent().eth as object), tip: undefined } }), ETH_A], ['eth', 'intent', ethIntent({ eth: { ...(ethIntent().eth as object), tip: 1000000 } }), ETH_A],
    ['eth', 'intent', ethIntent({ eth: { ...(ethIntent().eth as object), tip: '01' } }), ETH_A],
    ['sol', 'intent', solIntent({ sol: { ...(solIntent().sol as object), cuLimit: 0 } }), SOL_A], ['sol', 'intent', solIntent({ sol: { ...(solIntent().sol as object), cuLimit: 1_400_001 } }), SOL_A],
    ['sol', 'intent', solIntent({ sol: { ...(solIntent().sol as object), cuPrice: undefined } }), SOL_A], ['sol', 'intent', solIntent({ sol: { ...(solIntent().sol as object), cuLimit: '30000' } }), SOL_A],
    ['sol', 'clawback-intent', { ...sclaw, sol: { ...sclaw.sol, cuLimit: 0 } }, SOL_A],
  ]
  const planOf = (c: string): unknown => (c === 'eth' ? ETH_PLAN : SOL_PLAN)
  for (const [c, type, data, key] of nulls) assert.equal(ticketBinding(c as 'eth' | 'sol', type, data, key, planOf(c) as never), null, `${c} ${type} ${JSON.stringify(data).slice(0, 60)} ${key}`)
  // PF-S I-1: a job intent binds only to the API's plan of its copy — no plan, another part's digest, a wrong part count or part, or
  // (eth) another recipient: no binding, so no ticket
  const other = 'ab'.repeat(32), two = { digests: ['ef'.repeat(32), other], to: NULL_ETH }
  const planNulls: Array<[string, Record<string, unknown>, string, unknown]> = [
    ['eth', ethIntent(), ETH_A, undefined], ['sol', solIntent(), SOL_A, undefined],
    ['eth', ethIntent(), ETH_A, { digests: [], to: NULL_ETH }], ['eth', ethIntent(), ETH_A, { digests: ['EF'.repeat(32)], to: NULL_ETH }],
    ['eth', ethIntent({ payloadSha256: other }), ETH_A, ETH_PLAN], ['sol', solIntent({ payloadSha256: other }), SOL_A, SOL_PLAN],
    ['eth', ethIntent({ parts: 2 }), ETH_A, ETH_PLAN], ['eth', ethIntent(), ETH_A, two], ['sol', solIntent({ parts: 2 }), SOL_A, SOL_PLAN],
    ['eth', ethIntent({ part: 2, parts: 2 }), ETH_A, two], ['eth', ethIntent({ part: 0 }), ETH_A, ETH_PLAN], ['eth', ethIntent({ part: 3, parts: 2 }), ETH_A, two],
    ['eth', ethIntent({ part: '1' }), ETH_A, ETH_PLAN], ['eth', ethIntent({ parts: '1' }), ETH_A, ETH_PLAN],
    ['eth', ethIntent({ eth: { ...(ethIntent().eth as object), to: ETH_A } }), ETH_A, ETH_PLAN],            // self under a null-mode plan
    ['eth', ethIntent(), ETH_A, { digests: ETH_PLAN.digests, to: ETH_A }],                                // null under a self-mode plan
    ['eth', ethIntent(), ETH_A, { digests: ETH_PLAN.digests, to: null }], ['eth', ethIntent({ eth: { ...(ethIntent().eth as object), to: undefined } }), ETH_A, ETH_PLAN],
    ['sol', solIntent(), SOL_A, { digests: SOL_PLAN.digests, to: SOL_B }],
  ]
  for (const [c, data, key, plan] of planNulls) assert.equal(ticketBinding(c as 'eth' | 'sol', 'intent', data, key, plan as never), null, `${c} ${JSON.stringify(data).slice(0, 80)} ${JSON.stringify(plan)}`)
  assert.deepEqual(ticketBinding('eth', 'intent', ethIntent({ part: 2, parts: 2, payloadSha256: other }), ETH_A, two)?.p, other)   // part 2 of 2: its own digest
  // claw-backs carry no payload: no plan needed (and one given changes nothing)
  assert.deepEqual(ticketBinding('eth', 'clawback-intent', claw, ETH_A, ETH_PLAN), ticketBinding('eth', 'clawback-intent', claw, ETH_A))
})

test('base58: round trips with leading zero bytes; canonical 32-byte Solana addresses only', () => {
  for (const b of [Uint8Array.of(0), Uint8Array.of(0, 0, 1), Buffer.from('ff'.repeat(64), 'hex'), Buffer.concat([Buffer.alloc(3), Buffer.from('abc')])]) {
    assert.deepEqual(base58Decode(base58Encode(b)), Uint8Array.from(b))
  }
  assert.equal(base58Encode(new Uint8Array(32)), '11111111111111111111111111111111')
  assert.equal(base58Decode(''), null)
  assert.equal(isSolAddress(SOL_A), true)
  assert.equal(isSolAddress('11111111111111111111111111111111'), true)
  const b31 = base58Encode(new Uint8Array(31).fill(5)), b33 = base58Encode(new Uint8Array(33).fill(5))
  for (const bad of ['', '0OIl', `${SOL_A}x`, b31, b33, `1${SOL_A}`, ETH_A, '1'.repeat(91), 42, null]) assert.equal(isSolAddress(bad), false, String(bad))
})

test('btc (CC-7): no worst-case fee, identity or binding exists until E7, so a btc intent is refused before it is journaled', () => {
  assert.equal(worstCaseFee('btc', { fee: '1' }), null)
  assert.equal(ticketBinding('btc', 'intent', { btc: { fee: '1' } }, 'bc1qsynthetic'), null)
  assert.equal(ticketBinding('btc', 'clawback-intent', { btc: { fee: '1' } }, null), null)
})

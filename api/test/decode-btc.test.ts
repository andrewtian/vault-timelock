// CC-8 / S6b decode verification of a BTC send (api/src/decode.ts btcMismatch, through relay-gate.ts checkSend):
//   · the contract's tickets-btc.json: every valid vector decodes clean and passes the whole gate (mainnet: the job-send lock
//     refuses first); every decode vector (one defect each) refuses its own guard for its own reason; the format negatives
//     keep relay.send-ticket;
//   · the chain read for the input values (BtcPrevouts) is the relay's: absent, throwing or not finding an outpoint refuses
//     relay.btc-prevout; it is never called before the structural checks pass, nor when the ticket, the network, the bytes
//     or the lock already refuse (no read for a send that is going to be refused);
//   · each ticket field tampered one at a time with genuine bytes is refused; malformed, truncated and oversized bytes are
//     refused without throwing; a fuzz of random byte flips never passes.
// Synthetic keys and data only; nothing leaves the process.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import type { Network, TicketPayload } from '@vault-timelock/core/contracts'
import * as btc from '@scure/btc-signer'
import { pubECDSA } from '@scure/btc-signer/utils.js'
import { btcNetwork } from '@vault-timelock/core/chains/btc-ord.ts'
import { GENESIS } from 'vt-broadcast/src/config.ts'
import { BTC_RAW_MAX, decodeMismatch } from '../src/decode.ts'
import type { BtcPrevout, BtcPrevouts } from '../src/decode.ts'
import { JOB_SEND_METHODS, checkSend, rawBytes } from '../src/relay-gate.ts'
import type { SendCheck } from '../src/relay-gate.ts'
import { encodeTicket, isTicketPayload, ticketBinding } from '../src/tickets.ts'
import { TICKET_KEY, fixture } from './helpers.ts'

type Prevouts = Record<string, { value: string; script: string }>
interface Ctx { network: Network; chain: 'btc'; raw: { encoding: 'hex'; value: string }; prevouts: Prevouts }
interface Vector { name: string; ticket: string; now: number; context: Ctx; guard?: string; defect?: string }
interface Valid extends Vector { payload: TicketPayload }
const V = fixture<{ lane: Record<string, string>; fee: Record<string, string>; valid: Valid[]; negatives: Vector[]; decode: Vector[] }>('tickets-btc.json')

const sha = (b: Uint8Array | string): string => createHash('sha256').update(b).digest('hex')
const payloadOf = (ticket: string): TicketPayload => JSON.parse(Buffer.from(ticket.split('.')[1], 'base64url').toString('utf8')) as TicketPayload
const OBSERVED: Record<Network, string> = { local: GENESIS.btc.regtest, testnet: GENESIS.btc.testnet4, mainnet: GENESIS.btc.mainnet }
const bytesOf = (c: Ctx): Buffer => Buffer.from(c.raw.value, 'hex')

// What the relay's chain read returns for this vector's context; `calls` counts the reads.
function readerOf(prevouts: Prevouts): BtcPrevouts & { calls: string[] } {
  const calls: string[] = []
  const f = async (txid: string, vout: number): Promise<BtcPrevout | null> => {
    calls.push(`${txid}:${vout}`)
    const p = prevouts[`${txid}:${vout}`]
    return p === undefined ? null : { value: BigInt(p.value), script: Buffer.from(p.script, 'hex') }
  }
  return Object.assign(f, { calls })
}
const sendOf = (c: Ctx, ticket: string, now: number, reader: BtcPrevouts | null = readerOf(c.prevouts)): SendCheck => ({
  network: c.network, chain: 'btc', method: JOB_SEND_METHODS.btc, params: [c.raw.value], ticketHeader: ticket, key: TICKET_KEY, now, observedId: OBSERVED[c.network],
  ...(reader === null ? {} : { btcPrevouts: reader }),
})
async function guardOf(p: Promise<unknown>): Promise<string> {
  try { await p } catch (e) {
    const g = (e as { guardId?: unknown }).guardId
    assert.equal(typeof g, 'string', `not a refusal: ${String(e)}`)
    return g as string
  }
  return 'passed'
}

// ---- the contract vectors

// Each decode vector's own reason (the token decodeMismatch returns): removing any one check lets its vector through.
const REASON: Readonly<Record<string, string>> = {
  'btc-commit-extra-input': 'btc.inputs', 'btc-commit-missing-input': 'btc.inputs', 'btc-commit-other-input': 'btc.inputs',
  'btc-commit-extra-output': 'btc.outputs', 'btc-commit-change-foreign': 'btc.outputs', 'btc-commit-two-change-outputs': 'btc.outputs', 'btc-commit-value': 'btc.to', 'btc-commit-value-less': 'btc.to',
  'btc-commit-to': 'btc.to', 'btc-commit-fee': 'btc.fee', 'btc-commit-fee-no-change': 'btc.fee', 'btc-commit-outputs-exceed-inputs': 'btc.fee',
  'btc-commit-input-not-lane': 'btc.input-owner', 'btc-commit-to-not-taproot': 'btc.to', 'btc-commit-to-is-lane': 'btc.to',
  'btc-commit-duplicate-to': 'btc.to', 'btc-commit-locktime': 'btc.locktime', 'btc-commit-unsigned': 'btc.unsigned', 'btc-commit-tx-id': 'btc.tx-id',
  'btc-commit-trailing-byte': 'btc.decode', 'btc-commit-empty-witness-marker': 'btc.decode', 'btc-commit-reveal-bytes': 'btc.to', 'btc-commit-sighash-none': 'btc.sighash', 'btc-commit-sighash-none-anyonecanpay': 'btc.sighash',
  'btc-commit-sighash-single': 'btc.sighash', 'btc-commit-sighash-single-anyonecanpay': 'btc.sighash', 'btc-commit-sighash-all-anyonecanpay': 'btc.sighash',
  'btc-commit-prevout-missing': 'btc.prevout', 'btc-commit-prevout-one-of-two-missing': 'btc.prevout',
  'btc-reveal-body': 'btc.payload', 'btc-reveal-body-empty': 'btc.payload', 'btc-reveal-content-type-bare': 'btc.content-type',
  'btc-reveal-content-type-html': 'btc.content-type', 'btc-reveal-content-type-case': 'btc.content-type', 'btc-reveal-no-content-type': 'btc.tags',
  'btc-reveal-extra-tag': 'btc.tags', 'btc-reveal-two-inscriptions': 'btc.inscription', 'btc-reveal-cursed': 'btc.tags', 'btc-reveal-parser-op0-mid-body': 'btc.envelope', 'btc-reveal-parser-hidden-first-envelope': 'btc.envelope',
  'btc-reveal-parser-split-content-type': 'btc.envelope', 'btc-reveal-body-two-pushes': 'btc.envelope', 'btc-reveal-body-pushdata1': 'btc.envelope', 'btc-reveal-trailing-op': 'btc.inscription',
  'btc-reveal-leaf-without-checksig': 'btc.envelope', 'btc-reveal-foreign-key': 'btc.destination', 'btc-reveal-internal-key': 'btc.control', 'btc-reveal-annex': 'btc.decode', 'btc-reveal-other-outpoint': 'btc.inputs',
  'btc-reveal-extra-input': 'btc.inputs', 'btc-reveal-extra-output': 'btc.outputs', 'btc-reveal-destination': 'btc.to', 'btc-reveal-value': 'btc.to',
  'btc-reveal-fee': 'btc.fee', 'btc-reveal-outputs-exceed-input': 'btc.fee', 'btc-reveal-p2wpkh-spend': 'btc.decode',
  'btc-reveal-locktime': 'btc.locktime', 'btc-reveal-unsigned': 'btc.unsigned', 'btc-reveal-commit-bytes': 'btc.to', 'btc-reveal-kind-p': 'btc.payload',
  'btc-reveal-prevout-missing': 'btc.prevout',
}

test('contract: every valid vector decodes clean and passes the whole gate (mainnet: the job-send lock refuses first)', async () => {
  assert.ok(V.valid.length >= 6)
  for (const v of V.valid) {
    assert.equal(await decodeMismatch(v.payload, bytesOf(v.context), v.context.network, { btcPrevouts: readerOf(v.context.prevouts) }), null, v.name)
    const want = v.context.network === 'mainnet' ? 'release.mainnet-locked' : 'passed'
    assert.equal(await guardOf(checkSend(sendOf(v.context, v.ticket, v.now))), want, v.name)
  }
  // with the lock aside (decode alone), the mainnet vector is a clean tx for mainnet only: another network's address spelling is a mismatch
  const m = V.valid.find((v) => v.context.network === 'mainnet')!
  assert.equal(await decodeMismatch(m.payload, bytesOf(m.context), 'mainnet', { btcPrevouts: readerOf(m.context.prevouts) }), null)
  assert.equal(await decodeMismatch(m.payload, bytesOf(m.context), 'testnet', { btcPrevouts: readerOf(m.context.prevouts) }), 'btc.address')
})

test('contract: every decode vector (one defect each) refuses its guard through checkSend, each for its own reason', async () => {
  assert.deepEqual(V.decode.map((d) => d.name).sort(), Object.keys(REASON).sort())
  for (const d of V.decode) {
    const want = REASON[d.name] === 'btc.prevout' ? 'relay.btc-prevout' : 'relay.decode-mismatch'
    assert.equal(d.guard, want, d.name)
    assert.equal(await guardOf(checkSend(sendOf(d.context, d.ticket, d.now))), want, d.name)
    assert.equal(await decodeMismatch(payloadOf(d.ticket), bytesOf(d.context), d.context.network, { btcPrevouts: readerOf(d.context.prevouts) }), REASON[d.name], d.name)
  }
})

test('contract: the format negatives keep relay.send-ticket (kinds, addresses, txid, outpoint lists)', async () => {
  assert.ok(V.negatives.length >= 20)
  for (const n of V.negatives) {
    assert.equal(n.guard, 'relay.send-ticket', n.name)
    assert.equal(await guardOf(checkSend(sendOf(n.context, n.ticket, n.now))), 'relay.send-ticket', n.name)
  }
})

test('the chain read: absent, throwing, failing late or finding nothing refuses relay.btc-prevout; nothing is forwarded either way', async () => {
  for (const v of V.valid.filter((x) => x.context.network !== 'mainnet')) {
    const c = v.context
    assert.equal(await guardOf(checkSend(sendOf(c, v.ticket, v.now, null))), 'relay.btc-prevout', `${v.name}: no reader`)
    assert.equal(await guardOf(checkSend(sendOf(c, v.ticket, v.now, async () => { throw new Error('upstream down') }))), 'relay.btc-prevout', `${v.name}: throwing`)
    assert.equal(await guardOf(checkSend(sendOf(c, v.ticket, v.now, (() => { throw new Error('sync') }) as unknown as BtcPrevouts))), 'relay.btc-prevout', `${v.name}: sync throw`)
    assert.equal(await guardOf(checkSend(sendOf(c, v.ticket, v.now, async () => null))), 'relay.btc-prevout', `${v.name}: nothing found`)
  }
})

test('the chain read is the relay\'s: a caller-side value cannot raise the fee budget (the fee uses the read value, not the ticket)', async () => {
  const v = V.valid[0]
  const dear: Prevouts = Object.fromEntries(Object.entries(v.context.prevouts).map(([k, p]) => [k, { ...p, value: String(BigInt(p.value) + BigInt(v.payload.f) + 1n) }]))
  assert.equal(await guardOf(checkSend(sendOf(v.context, v.ticket, v.now, readerOf(dear)))), 'relay.decode-mismatch')
  // fee exactly f passes, f + 1 does not (the value read, not the ticket, decides)
  const tx = Object.keys(v.context.prevouts)[0]
  const sumOut = BigInt(v.context.prevouts[tx].value) - BigInt(v.payload.f)   // fee == f for this vector (valid[0] has f = the fee)
  assert.ok(sumOut > 0n)
  const plus1: Prevouts = { [tx]: { ...v.context.prevouts[tx], value: String(BigInt(v.context.prevouts[tx].value) + 1n) } }
  assert.equal(await decodeMismatch(v.payload, bytesOf(v.context), v.context.network, { btcPrevouts: readerOf(plus1) }), 'btc.fee')
})

test('no chain read for a send that is refused anyway: bad ticket, network, route chain, bytes, lock, and every structural mismatch', async () => {
  const v = V.valid[0], d = (n: string) => V.decode.find((x) => x.name === n)!
  const probe = async (o: SendCheck, want: string, name: string): Promise<void> => {
    const r = readerOf(v.context.prevouts)
    assert.equal(await guardOf(checkSend({ ...o, btcPrevouts: r })), want, name)
    assert.deepEqual(r.calls, [], name)
  }
  await probe(sendOf(v.context, v.ticket.slice(0, -2), v.now), 'relay.send-ticket', 'bad MAC')
  await probe(sendOf(v.context, v.ticket, payloadOf(v.ticket).e), 'relay.ticket-expired', 'expired')
  await probe({ ...sendOf(v.context, v.ticket, v.now), network: 'testnet' }, 'relay.ticket-network', 'another network')
  await probe({ ...sendOf(v.context, v.ticket, v.now), chain: 'eth', method: 'eth_sendRawTransaction' }, 'relay.ticket-chain', 'the eth route')
  await probe({ ...sendOf(v.context, v.ticket, v.now), params: [`${v.context.raw.value}00`] }, 'relay.ticket-raw', 'other bytes')
  const m = V.valid.find((x) => x.context.network === 'mainnet')!
  await probe(sendOf(m.context, m.ticket, m.now), 'release.mainnet-locked', 'mainnet lock')
  await probe({ ...sendOf(v.context, v.ticket, v.now), observedId: GENESIS.btc.mainnet }, 'release.mainnet-locked', 'a mainnet identity')
  await probe({ ...sendOf(v.context, v.ticket, v.now), observedId: GENESIS.btc.testnet4 }, 'config.identity-mismatch', 'a foreign identity')
  for (const n of ['btc-commit-extra-input', 'btc-commit-extra-output', 'btc-commit-to', 'btc-commit-locktime', 'btc-commit-unsigned']) {
    const x = d(n); await probe(sendOf(x.context, x.ticket, x.now), 'relay.decode-mismatch', n)
  }
})

test('each ticket field tampered one at a time, with the genuine bytes, is refused', async () => {
  for (const base of V.valid.filter((x) => x.context.network === 'local')) {
    const p = base.payload, c = base.context
    const ok = async (over: Partial<TicketPayload>): Promise<string> => {
      const t = encodeTicket(TICKET_KEY, { ...p, ...over })
      return guardOf(checkSend(sendOf(c, t, base.now)))
    }
    assert.equal(await ok({}), 'passed', base.name)                                   // re-encoding the same payload passes
    const oc = V.valid.find((x) => x.context.network === 'local' && x.payload.k !== p.k)!.payload
    assert.equal(await ok({ t: oc.t }), 'relay.decode-mismatch', `${base.name}: t`)
    assert.equal(await ok({ k: p.k === 'commit' ? 'reveal' : 'commit' }), 'relay.decode-mismatch', `${base.name}: k`)
    assert.equal(await ok({ value: String(BigInt(p.value!) + 1n) }), 'relay.decode-mismatch', `${base.name}: value`)
    assert.equal(await ok({ f: String(BigInt(p.f) - 1n) }), 'relay.decode-mismatch', `${base.name}: f - 1`)
    assert.equal(await ok({ q: oc.q }), 'relay.decode-mismatch', `${base.name}: q`)
    // `a` binds the commit (its change and the owner of every input); a reveal's only input is the commit's own output, so `a` constrains nothing there
    if (p.k === 'commit') assert.equal(await ok({ a: oc.to! }), 'relay.decode-mismatch', `${base.name}: a`)
    else assert.equal(await ok({ a: oc.to! }), 'passed', `${base.name}: a is not constrained on a reveal`)
    assert.equal(await ok({ to: V.lane.local }), 'relay.decode-mismatch', `${base.name}: to = a`)
    if (p.k === 'reveal') assert.equal(await ok({ p: sha('another body') }), 'relay.decode-mismatch', `${base.name}: p`)
  }
})

test('a fee of exactly f passes; one sat more is refused (the commit and the reveal)', async () => {
  for (const v of V.valid.filter((x) => x.context.network === 'local')) {
    const p = v.payload
    const fee = BigInt(p.f)
    assert.equal(await guardOf(checkSend(sendOf(v.context, encodeTicket(TICKET_KEY, { ...p, f: String(fee) }), v.now))), 'passed', v.name)
    assert.equal(await guardOf(checkSend(sendOf(v.context, encodeTicket(TICKET_KEY, { ...p, f: String(fee - 1n) }), v.now))), 'relay.decode-mismatch', v.name)
  }
})

test('malformed, truncated and oversized bytes are refused without throwing; random byte flips never pass', async () => {
  const v = V.valid[0], t = v.payload
  const raw = bytesOf(v.context)
  const reader = readerOf(v.context.prevouts)
  for (const [name, bytes] of [['empty', Buffer.alloc(0)], ['one byte', Buffer.from([2])], ['truncated', raw.subarray(0, raw.length - 3)], ['half', raw.subarray(0, raw.length >> 1)],
    ['oversized', Buffer.alloc(BTC_RAW_MAX + 1, 1)], ['zeros', Buffer.alloc(raw.length)]] as const) {
    const why = await decodeMismatch(t, bytes, 'local', { btcPrevouts: reader })
    assert.equal(typeof why, 'string', name)
  }
  assert.equal(await decodeMismatch(t, Buffer.alloc(BTC_RAW_MAX + 1, 1), 'local', { btcPrevouts: reader }), 'btc.size')
  // a deterministic fuzz through the whole gate: every single-byte flip of the genuine txs is refused (a witness byte keeps the
  // txid but changes r = sha256(raw): relay.ticket-raw; any other byte changes the structure or the txid), and decoding never throws
  for (const g of V.valid.filter((x) => x.context.network === 'local')) {
    const b = bytesOf(g.context)
    for (let i = 0; i < b.length; i++) {
      const bad = Buffer.from(b); bad[i] ^= 0x01
      await decodeMismatch(g.payload, bad, 'local', { btcPrevouts: readerOf(g.context.prevouts) })   // never throws
      const c = { ...g.context, raw: { encoding: 'hex' as const, value: bad.toString('hex') } }
      assert.notEqual(await guardOf(checkSend(sendOf(c, g.ticket, g.now))), 'passed', `${g.name} byte ${i}`)
    }
  }
})

test('the addresses are decoded canonically for this network: an uppercase spelling or another network\'s address is a mismatch', async () => {
  const v = V.valid[0], r = bytesOf(v.context), reader = { btcPrevouts: readerOf(v.context.prevouts) }
  assert.equal(await decodeMismatch(v.payload, r, 'local', reader), null)
  assert.equal(await decodeMismatch({ ...v.payload, to: v.payload.to!.toUpperCase() }, r, 'local', reader), 'btc.address')
  assert.equal(await decodeMismatch({ ...v.payload, a: v.payload.a.toUpperCase() }, r, 'local', reader), 'btc.address')
  assert.equal(await decodeMismatch({ ...v.payload, to: V.valid[2].payload.to }, r, 'local', reader), 'btc.address')
})

test('a commit that pays the lane address itself is refused even when the lane is a taproot address (to is never a)', async () => {
  const net = { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef }
  const x = btc.p2tr(Uint8Array.from({ length: 32 }, (_, i) => (i === 0 ? 2 : 1)).fill(7, 1), undefined, net)
  const t = new btc.Transaction()
  t.addInput({ txid: 'aa'.repeat(32), index: 0, witnessUtxo: { script: x.script, amount: 100_000n } })
  t.addOutput({ script: x.script, amount: 5_000n })
  t.updateInput(0, { finalScriptWitness: [new Uint8Array(64)] })
  const raw = t.extract()
  const payload: TicketPayload = { ...V.valid[0].payload, t: t.id, r: sha(raw), a: x.address!, to: x.address!, value: '5000', f: '100000', q: `${'aa'.repeat(32)}:0` }
  const reader = readerOf({ [`${'aa'.repeat(32)}:0`]: { value: '100000', script: Buffer.from(x.script).toString('hex') } })
  assert.equal(await decodeMismatch(payload, raw, 'local', { btcPrevouts: reader }), 'btc.to')
})

test('sighash (I-3): p2wpkh needs [DER‖0x01, the lane pubkey]; p2tr key path exactly one 64-byte signature; anything else is btc.sighash', async () => {
  const { inputSighashMismatch: bad } = await import('@vault-timelock/core/chains/btc-ord.ts')
  const v = V.valid[0], tx = btc.Transaction.fromRaw(bytesOf(v.context))
  const [sig, pk] = tx.getInput(0).finalScriptWitness!
  const spk = Buffer.from(Object.values(v.context.prevouts)[0].script, 'hex')
  assert.equal(sig[sig.length - 1], 0x01)
  assert.equal(bad(spk, [sig, pk], new Uint8Array(0)), null)
  for (const last of [0x00, 0x02, 0x03, 0x81, 0x82, 0x83]) assert.equal(bad(spk, [Uint8Array.from([...sig.subarray(0, -1), last]), pk], undefined), 'btc.sighash', `0x${last.toString(16)}`)
  assert.equal(bad(spk, [sig, pk], Uint8Array.from([1])), 'btc.sighash', 'a scriptSig')
  assert.equal(bad(spk, [sig], undefined), 'btc.sighash'); assert.equal(bad(spk, [sig, pk, pk], undefined), 'btc.sighash'); assert.equal(bad(spk, undefined, undefined), 'btc.sighash')
  assert.equal(bad(spk, [sig.subarray(0, 8), pk], undefined), 'btc.sighash', 'too short'); assert.equal(bad(spk, [Uint8Array.from([0x31, ...sig.subarray(1)]), pk], undefined), 'btc.sighash', 'not a DER sequence')
  assert.equal(bad(spk, [sig, Uint8Array.from([...pk.subarray(0, 32), pk[32] ^ 1])], undefined), 'btc.sighash', 'a pubkey that is not the lane\'s')
  assert.equal(bad(spk, [sig, pk.subarray(1)], undefined), 'btc.sighash')
  const tr = Buffer.from(`5120${'ab'.repeat(32)}`, 'hex')
  assert.equal(bad(tr, [new Uint8Array(64)], undefined), null)
  for (const w of [[new Uint8Array(65).fill(1)], [Uint8Array.from([...new Uint8Array(64), 0x01])], [new Uint8Array(63)], [], [new Uint8Array(64), new Uint8Array(64)]]) assert.equal(bad(tr, w, undefined), 'btc.sighash', String(w.length))
  assert.equal(bad(Buffer.from(`a914${'00'.repeat(20)}87`, 'hex'), [], Uint8Array.from([1])), 'btc.sighash', 'a p2sh input is no lane input')
  assert.equal(bad(Buffer.from(`a914${'00'.repeat(20)}87`, 'hex'), [], new Uint8Array(0)), 'btc.sighash', 'no other input type is a lane input, even unsigned-looking')
})

test('sighash (fix round 2 review m-3, HM4): in a commit of TWO inputs, a later input that is not SIGHASH_ALL is btc.sighash although input 0 is ALL', async () => {
  const lanePriv = createHash('sha256').update('vt-fixture:ticket btc lane').digest()          // the contract fixtures' synthetic lane key
  const base = V.valid.find((v) => v.payload.k === 'commit' && v.payload.w === 'local')!
  const lane = btc.p2wpkh(pubECDSA(lanePriv), btcNetwork('local'))
  assert.equal(lane.address, base.payload.a, 'the fixture lane')
  const outs = [`${'aa'.repeat(32)}:0`, `${'bb'.repeat(32)}:0`]
  const prevouts: Prevouts = Object.fromEntries(outs.map((o) => [o, { value: '100000', script: Buffer.from(lane.script).toString('hex') }]))
  const build = (second: number): { raw: Uint8Array; payload: TicketPayload } => {
    const t = new btc.Transaction()
    outs.forEach((o, i) => t.addInput({ txid: o.split(':')[0], index: 0, witnessUtxo: { script: lane.script, amount: 100_000n }, ...(i === 1 ? { sighashType: second } : {}) }))
    t.addOutputAddress(base.payload.to!, 846n, btcNetwork('local'))
    t.addOutputAddress(lane.address!, 200_000n - 846n - 300n, btcNetwork('local'))
    t.sign(lanePriv, [btc.SigHash.ALL, second]); t.finalize()
    const raw = t.extract()
    return { raw, payload: { ...base.payload, t: t.id, r: sha(raw), value: '846', f: '400', q: outs.join(',') } }
  }
  const ok = build(btc.SigHash.ALL)
  assert.equal(await decodeMismatch(ok.payload, ok.raw, 'local', { btcPrevouts: readerOf(prevouts) }), null, 'both inputs ALL: clean')
  for (const sh of [btc.SigHash.NONE_ANYONECANPAY, btc.SigHash.SINGLE_ANYONECANPAY, btc.SigHash.NONE, btc.SigHash.ALL_ANYONECANPAY]) {
    const x = build(sh)
    assert.equal(await decodeMismatch(x.payload, x.raw, 'local', { btcPrevouts: readerOf(prevouts) }), 'btc.sighash', `input 1 ${sh}`)
  }
})

test('rawBytes (btc): lowercase hex, the only param, at most BTC_RAW_MAX bytes', () => {
  assert.deepEqual(rawBytes('btc', ['00ff']), Buffer.from([0, 255]))
  for (const params of [[], ['00FF'], ['0x00ff'], ['0'], ['00f'], ['00ff', 1], [1], [null], ['zz'], 'ab', { 0: 'ab' }, [''], [`${'00'.repeat(BTC_RAW_MAX)}00`]]) assert.equal(rawBytes('btc', params), null, JSON.stringify(params).slice(0, 40))
  assert.equal(rawBytes('btc', ['00'.repeat(BTC_RAW_MAX)])?.length, BTC_RAW_MAX)
})

test('ticket format: a btc payload is valid only in its own shape; the API still cannot bind a btc intent (ticketBinding is null)', () => {
  const p = V.valid[0].payload
  assert.ok(isTicketPayload(p))
  for (const bad of [{ k: 'job' }, { k: 'clawback' }, { p: null }, { to: null }, { value: null }, { value: '0' }, { f: '0' }, { t: `0x${p.t}` }, { a: p.a.toUpperCase() },
    { a: V.lane.testnet }, { to: V.valid[4].payload.to }, { q: '7' }, { q: `${p.q},` }, { q: '' }, { c: 'eth' }, { c: 'sol' }]) assert.ok(!isTicketPayload({ ...p, ...bad }), JSON.stringify(bad).slice(0, 50))
  assert.ok(!isTicketPayload({ ...V.valid[1].payload, q: `${V.valid[1].payload.q},${V.valid[0].payload.q}` }), 'a reveal names exactly one outpoint')
  assert.equal(ticketBinding('btc', 'intent', { payloadSha256: sha('x'), btc: {} }, p.a), null)
})

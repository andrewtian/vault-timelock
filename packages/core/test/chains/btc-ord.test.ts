// chains/btc-ord.ts: the one derivation of a BTC text inscription. Byte vectors (synthetic lane key = the ticket fixtures'
// "ticket btc lane" seed, never funded) pin the leaf, the commit and reveal addresses; the leaf is also assembled by hand here
// from raw script bytes, so the library call and the documented layout agree. readReveal pins what the relay accepts.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import * as btc from '@scure/btc-signer'
import { pubECDSA, pubSchnorr } from '@scure/btc-signer/utils.js'
import { OutOrdinalReveal } from 'micro-ordinals'
import {
  BTC_CONTENT_TYPE, BTC_MAX_FEE_RATE, BTC_NUMS, BTC_POSTAGE, commitAddress, commitOutput, commitVsizeBound, inscriptionLeaf, laneAddresses, laneOwns,
  maxCommitFee, maxCommitValue, maxRevealFee, readReveal, revealDestination, revealVsizeBound, xonlyOf,
} from '../../src/chains/btc-ord.ts'

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex')
const priv = createHash('sha256').update('vt-fixture:ticket btc lane').digest()
const pub = pubECDSA(priv)
const x = pubSchnorr(priv)
const body = new TextEncoder().encode('[1/1 ticket] A synthetic vt ticket vector part.\n')

test('constants', () => {
  assert.equal(BTC_CONTENT_TYPE, 'text/plain;charset=utf-8')
  assert.equal(BTC_POSTAGE, 546n)
  assert.equal(BTC_MAX_FEE_RATE, 500n)
  assert.equal(hex(BTC_NUMS), '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')
})

test('byte vectors: lane addresses, the leaf, the commit script and addresses, the reveal destination', () => {
  assert.equal(hex(pub), '0335505471799de8efdefb1a96edb871139c2de0a702fe9097e940ed13efa5c232')
  assert.deepEqual(laneAddresses('local', pub) && { ...laneAddresses('local', pub)!, xonly: hex(laneAddresses('local', pub)!.xonly) }, {
    p2wpkh: 'bcrt1qx095dcjchzt39x547jtdndwkjahpk23vwfskg9', p2tr: 'bcrt1p99h73cm4vldyyqtnvwxnppvpzgsakrfxxs72030x8v7gmz37am7q2caxcz',
    xonly: '35505471799de8efdefb1a96edb871139c2de0a702fe9097e940ed13efa5c232' })
  assert.equal(laneAddresses('testnet', pub)!.p2wpkh, 'tb1qx095dcjchzt39x547jtdndwkjahpk23vvqfmlv')
  assert.equal(laneAddresses('mainnet', pub)!.p2wpkh, 'bc1qx095dcjchzt39x547jtdndwkjahpk23vxxjgyl')
  const leaf = '2035505471799de8efdefb1a96edb871139c2de0a702fe9097e940ed13efa5c232ac0063036f7264010118746578742f706c61696e3b636861727365743d7574662d3800305b312f31207469636b65745d20412073796e746865746963207674207469636b657420766563746f7220706172742e0a68'
  assert.equal(hex(inscriptionLeaf(x, body)), leaf)
  // by hand: <push x> CHECKSIG OP_0 OP_IF <push "ord"> <push 01> <push content type> OP_0 <push body> OP_ENDIF
  const push = (b: Uint8Array | number[]): number[] => [b.length, ...b]
  const T = (s: string): number[] => Array.from(new TextEncoder().encode(s))
  assert.equal(hex(Uint8Array.from([...push(x), 0xac, 0x00, 0x63, ...push(T('ord')), ...push([1]), ...push(T(BTC_CONTENT_TYPE)), 0x00, ...push(body), 0x68])), leaf)
  assert.equal(hex(commitOutput('local', x, body).script), '512067688f6dac3e21b79018d18e63df2a5467ad5d855900c8013b556fa231e2b6f7')
  assert.equal(commitAddress('local', x, body), 'bcrt1pva5g7mdv8csm0yqc6x8x8he223n66hv9tyqvsqfm24h6yv0zkmmsnsxn56')
  assert.equal(commitAddress('testnet', x, body), 'tb1pva5g7mdv8csm0yqc6x8x8he223n66hv9tyqvsqfm24h6yv0zkmms7fv4pq')
  assert.equal(commitAddress('mainnet', x, body), 'bc1pva5g7mdv8csm0yqc6x8x8he223n66hv9tyqvsqfm24h6yv0zkmmsfp66m0')
  assert.equal(revealDestination('local', x), 'bcrt1p99h73cm4vldyyqtnvwxnppvpzgsakrfxxs72030x8v7gmz37am7q2caxcz')
  assert.equal(revealDestination('testnet', x), 'tb1p99h73cm4vldyyqtnvwxnppvpzgsakrfxxs72030x8v7gmz37am7q8phqdc')
  assert.equal(revealDestination('mainnet', x), 'bc1p99h73cm4vldyyqtnvwxnppvpzgsakrfxxs72030x8v7gmz37am7qsfp0hh')
  // another body or another key is another commit address
  assert.notEqual(commitAddress('local', x, Uint8Array.from([...body, 1])), commitAddress('local', x, body))
  assert.notEqual(commitAddress('local', pubSchnorr(createHash('sha256').update('other').digest()), body), commitAddress('local', x, body))
})

test('the lane: the pubkey owns exactly its p2wpkh and p2tr addresses; invalid keys are refused', () => {
  const l = laneAddresses('local', pub)!
  assert.ok(laneOwns('local', pub, l.p2wpkh) && laneOwns('local', pub, l.p2tr))
  assert.ok(!laneOwns('testnet', pub, l.p2wpkh), 'another network')
  assert.ok(!laneOwns('local', pub, laneAddresses('local', pubECDSA(createHash('sha256').update('x').digest()))!.p2wpkh))
  assert.ok(!laneOwns('local', pub, l.p2wpkh.toUpperCase()))
  assert.equal(xonlyOf(pub.subarray(1)), null)                       // 32 bytes: not a compressed key
  assert.equal(xonlyOf(Uint8Array.from([4, ...pub.subarray(1)])), null)
  assert.equal(xonlyOf(Uint8Array.from([2, ...new Uint8Array(32).fill(0xff)])), null)   // x is not on the curve
  assert.equal(laneAddresses('local', new Uint8Array(33)), null)
  for (const v of [5, 7, 9, 10, 11]) assert.equal(laneAddresses('local', Uint8Array.from([2, ...new Uint8Array(31), v])), null, `x = ${v} is not on the curve`)
})

test('caps: vsize bounds and the value / fee limits a ticket may bind', () => {
  assert.deepEqual([revealVsizeBound(0), revealVsizeBound(1000), revealVsizeBound(100000), commitVsizeBound(1), commitVsizeBound(8)], [350n, 602n, 25495n, 170n, 660n])
  assert.equal(maxCommitValue(47), 546n + revealVsizeBound(47) * 500n)
  assert.equal(maxRevealFee(47), revealVsizeBound(47) * 500n)
  assert.equal(maxCommitFee(2), commitVsizeBound(2) * 500n)
  // the bound really bounds: a real reveal of a 100 kB body weighs less
  const big = new Uint8Array(100_000).fill(0x61)
  const out = commitOutput('local', x, big)
  const t = new btc.Transaction({ customScripts: [OutOrdinalReveal] })
  t.addInput({ ...out, txid: '11'.repeat(32), index: 0, witnessUtxo: { script: out.script, amount: 1_000_000n } })
  t.addOutputAddress(revealDestination('local', x), 546n, { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef })
  t.sign(priv, undefined, new Uint8Array(32)); t.finalize()
  assert.ok(BigInt(t.vsize) <= revealVsizeBound(big.length), `${t.vsize}`)
})

// ---- readReveal
function reveal(b: Uint8Array = body): Uint8Array[] {
  const out = commitOutput('local', x, b)
  const t = new btc.Transaction({ customScripts: [OutOrdinalReveal] })
  t.addInput({ ...out, txid: '11'.repeat(32), index: 0, witnessUtxo: { script: out.script, amount: 2000n } })
  t.addOutputAddress(revealDestination('local', x), 546n, { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef })
  t.sign(priv, undefined, new Uint8Array(32)); t.finalize()
  return t.getInput(0).finalScriptWitness!
}
test('readReveal: the builder\'s witness reads back its body and key; every deviation has a reason', () => {
  const w = reveal()
  const ok = readReveal(w)
  assert.ok(ok.ok && hex(ok.body) === hex(body) && hex(ok.xonly) === hex(x))
  assert.ok(readReveal(reveal(new Uint8Array(1300).fill(7))).ok, 'a body in several 520-byte pushes')
  const bad = (witness: Uint8Array[] | undefined, reason: string): void => { const r = readReveal(witness); assert.deepEqual(r.ok ? null : r.reason, reason) }
  bad(undefined, 'btc.witness'); bad([], 'btc.witness'); bad(w.slice(0, 2), 'btc.witness'); bad([...w, Uint8Array.from([0x50, 1])], 'btc.witness')
  bad([w[0].subarray(0, 63), w[1], w[2]], 'btc.witness'); bad([new Uint8Array(65), w[1], w[2]], 'btc.witness')
  bad([w[0], w[1], w[2].subarray(0, 32)], 'btc.control'); bad([w[0], w[1], Uint8Array.from([0xc2, ...w[2].subarray(1)])], 'btc.control')
  bad([w[0], w[1], Uint8Array.from([w[2][0], ...x])], 'btc.control')                          // the lane key as internal key
  bad([w[0], w[1], Uint8Array.from([...w[2], 0])], 'btc.control')                             // two leaves' worth
  const leaf = w[1]
  bad([w[0], Uint8Array.from([...leaf, 0x61]), w[2]], 'btc.inscription')                      // a trailing opcode
  bad([w[0], leaf.subarray(0, leaf.length - 1), w[2]], 'btc.inscription')                          // no OP_ENDIF
  bad([w[0], Uint8Array.from([0x51, ...leaf.subarray(1)]), w[2]], 'btc.envelope')               // not a key push
  bad([w[0], new Uint8Array(0), w[2]], 'btc.envelope')
})

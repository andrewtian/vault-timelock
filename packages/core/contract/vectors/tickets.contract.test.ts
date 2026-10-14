// CC-3 (ticket v2) + CC-3a (q): the tickets.json vectors are self-consistent and every valid raw is a GENUINE signed transaction.
// This pins the generator, independently of any relay: each ticket's MAC holds under the fixture key and the v2 prefix,
// its payload keys are in the contract order, r = sha256(raw), and for the valid vectors t = the tx id and the
// signature is by `signers` (ETH: viem recovers the sender; SOL: ed25519 over the message by the fee payer). The decode
// vectors' defects are judged by the relay's own tests (api/test/decode.test.ts); here only their tickets are checked.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, createHmac, createPublicKey, verify } from 'node:crypto'
import { VersionedTransaction } from '@solana/web3.js'
import { base58, base64, base64urlnopad } from '@scure/base'
import { hexToBytes, keccak256, parseTransaction, recoverTransactionAddress, serializeTransaction } from 'viem'
import type { TransactionSerializedEIP1559 } from 'viem'
import { TICKET_PREFIX } from '../../src/contracts/index.ts'
import type { TicketPayload } from '../../src/contracts/index.ts'
import { readJson } from './job-module.ts'

type Raw = { encoding: 'hex' | 'base64'; value: string }
interface Vector { name: string; ticket: string; now: number; context: { network: string; chain: 'eth' | 'sol'; raw: Raw }; guard?: string }
interface Valid extends Vector { payload: TicketPayload; issuedAt: number; raw: Raw }
const V = readJson<{ format: string; key: string; signers: { eth: string; sol: string }; valid: Valid[]; negatives: Vector[]; decode: Vector[] }>('tickets.json')
const KEY = Buffer.from(V.key, 'hex')
const ORDER = 'j,w,c,g,t,r,a,k,p,to,value,f,q,x,e,n'   // PF-S fix round 2: x, the declared fee members
const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex')
const bytesOf = (r: Raw): Uint8Array => (r.encoding === 'hex' ? hexToBytes(r.value as `0x${string}`) : base64.decode(r.value))

function open(ticket: string): Record<string, unknown> {
  assert.ok(ticket.startsWith(TICKET_PREFIX))
  const [body, mac] = ticket.slice(TICKET_PREFIX.length).split('.')
  assert.equal(base64urlnopad.encode(createHmac('sha256', KEY).update(`${TICKET_PREFIX}${body}`).digest()), mac)
  return JSON.parse(new TextDecoder().decode(base64urlnopad.decode(body))) as Record<string, unknown>
}

test('format: vt-ticket/2., the key is 32 bytes; every valid and decode ticket is MAC\'d under the v2 prefix with the contract key order', () => {
  assert.equal(V.format, 'vt-ticket/2.')
  assert.equal(TICKET_PREFIX, 'vt-ticket/2.')
  assert.equal(KEY.length, 32)
  assert.ok(V.valid.length >= 10 && V.decode.length >= 50)
  for (const v of [...V.valid, ...V.decode]) {
    const p = open(v.ticket)
    assert.equal(Object.keys(p).join(','), ORDER, v.name)
    assert.equal(p.r, sha(bytesOf(v.context.raw)), v.name)
    assert.equal(p.w, v.context.network, v.name)
    assert.equal(p.c, v.context.chain, v.name)
    assert.ok(v.now < (p.e as number), v.name)
  }
  for (const v of V.valid) assert.deepEqual(open(v.ticket), v.payload, v.name)
  for (const v of V.decode) assert.equal(v.guard, 'relay.decode-mismatch', v.name)
  assert.deepEqual(new Set(V.valid.map((v) => `${v.payload.c} ${v.payload.k}`)), new Set(['eth job', 'eth clawback', 'sol job', 'sol clawback']))
})

test('the valid ETH raws are genuine EIP-1559 txs: canonical, signed by signers.eth, t = keccak256(raw)', async () => {
  for (const v of V.valid.filter((x) => x.payload.c === 'eth')) {
    const hex = v.raw.value as TransactionSerializedEIP1559
    const tx = parseTransaction(hex)
    assert.equal(tx.type, 'eip1559', v.name)
    assert.equal(serializeTransaction(tx), hex, v.name)
    assert.equal((await recoverTransactionAddress({ serializedTransaction: hex })).toLowerCase(), V.signers.eth, v.name)
    assert.equal(v.payload.a, V.signers.eth, v.name)
    assert.equal(keccak256(hex), v.payload.t, v.name)
    assert.equal(String(tx.nonce), v.payload.q, v.name)                                                  // CC-3a
    assert.ok((tx.gas ?? 0n) * (tx.maxFeePerGas ?? 0n) <= BigInt(v.payload.f), v.name)
    assert.equal(`${tx.gas}:${tx.maxPriorityFeePerGas}:${tx.maxFeePerGas}`, v.payload.x, v.name)       // PF-S fix round 2: the fee members, exactly
  }
})

test('the valid SOL raws are genuine: canonical, one ed25519 signature by the fee payer = signers.sol, t = base58(signature)', () => {
  for (const v of V.valid.filter((x) => x.payload.c === 'sol')) {
    const raw = bytesOf(v.raw)
    const tx = VersionedTransaction.deserialize(raw)
    assert.deepEqual(tx.serialize(), raw, v.name)
    const payer = tx.message.staticAccountKeys[0]
    assert.equal(payer.toBase58(), V.signers.sol, v.name)
    assert.equal(tx.signatures.length, 1, v.name)
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(payer.toBytes()).toString('base64url') }, format: 'jwk' })
    assert.ok(verify(null, raw.subarray(65), key, tx.signatures[0]), v.name)
    assert.equal(base58.encode(tx.signatures[0]), v.payload.t, v.name)
    assert.equal(tx.message.recentBlockhash, v.payload.q, v.name)                                        // CC-3a
    // PF-S fix round 2: a legacy message whose ComputeBudget values are x's ("<cuLimit>:<cuPrice>"): a job always sets the limit
    // and sets the price only when > 0; a claw-back sets both or neither (neither: price 0)
    assert.equal(tx.version, 'legacy', v.name)
    const cb = tx.message.compiledInstructions.filter((ix) => tx.message.staticAccountKeys[ix.programIdIndex].toBase58() === 'ComputeBudget111111111111111111111111111111')
    const le = (b: Uint8Array): bigint => b.reduceRight((acc, x) => acc * 256n + BigInt(x), 0n)
    const limit = cb.find((ix) => ix.data[0] === 2), price = cb.find((ix) => ix.data[0] === 3)
    const [xLimit, xPrice] = (v.payload.x as string).split(':').map(BigInt)
    assert.equal(price === undefined ? 0n : le(price.data.subarray(1)), xPrice, v.name)
    if (v.payload.k === 'job') assert.equal(limit === undefined ? null : le(limit.data.subarray(1)), xLimit, v.name)
    else assert.equal(limit === undefined ? (xPrice === 0n ? 'none' : 'missing') : le(limit.data.subarray(1)) === xLimit && xPrice > 0n ? 'both' : 'mismatch', xPrice === 0n ? 'none' : 'both', v.name)
  }
})

test('no downgrade: the v1 negatives are a correctly MAC\'d v1 ticket and a v1 payload under the v2 prefix', () => {
  const v1 = V.negatives.find((n) => n.name === 'v1-ticket')!
  assert.ok(v1.ticket.startsWith('vt-ticket/1.'))
  const [body, mac] = v1.ticket.slice('vt-ticket/1.'.length).split('.')
  assert.equal(base64urlnopad.encode(createHmac('sha256', KEY).update(`vt-ticket/1.${body}`).digest()), mac)
  assert.equal(Object.keys(JSON.parse(new TextDecoder().decode(base64urlnopad.decode(body))) as object).join(','), 'j,w,c,g,t,r,e,n')
  const under = V.negatives.find((n) => n.name === 'v1-payload-under-v2')!
  assert.equal(Object.keys(open(under.ticket)).join(','), 'j,w,c,g,t,r,e,n')
  for (const n of [v1, under]) assert.equal(n.guard, 'relay.send-ticket')
})

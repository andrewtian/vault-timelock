// S4 decode verification (api/src/decode.ts, through relay-gate.ts checkSend): the relay forwards a send only if the
// signed bytes are exactly what the API ticketed (CC-3 ticket v2), including the worst-case fee.
//   · the contract's tickets.json: every valid vector decodes clean; every decode vector (one defect each) refuses
//     relay.decode-mismatch, each for its own reason (so every check is pinned by a vector of its own);
//   · genuine txs built by the ENGINE's own builders (packages/core chains/eth.js sign / signClawback, chains/sol.js
//     buildTx / buildTransfer / sign) pass on every network; the fixture's synchronous ETH signer equals viem's;
//   · each ticket field tampered, one at a time, with genuine bytes → refused;
//   · malformed, truncated and oversized bytes are refused without throwing; a fuzz of random byte flips never passes.
// Synthetic keys and data only; nothing leaves the process.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { ComputeBudgetProgram, Keypair, Message, MessageV0, PublicKey, TransactionInstruction, TransactionMessage, VersionedTransaction } from '@solana/web3.js'
import { hexToBytes, keccak256, parseTransaction, toHex } from 'viem'
import type { Hex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import type { Network, TicketPayload } from '@vault-timelock/core/contracts'
import { sign as engineEthSign, signClawback as engineEthClawback } from '@vault-timelock/core/chains/eth.js'
import { buildTransfer as engineSolTransfer, buildTx as engineSolTx, sign as engineSolSign } from '@vault-timelock/core/chains/sol.js'
import { GENESIS, chainId } from 'vt-broadcast/src/config.ts'
import { ETH_RAW_MAX, SOL_RAW_MAX, assertDecodedMatches, decodeMismatch } from '../src/decode.ts'
import { checkSend } from '../src/relay-gate.ts'
import type { SendCheck } from '../src/relay-gate.ts'
import { base58Encode, encodeTicket } from '../src/tickets.ts'
import { CANARY, TICKET_KEY, fixture } from './helpers.ts'

type Raw = { encoding: 'hex' | 'base64'; value: string }
interface Ctx { network: Network; chain: 'eth' | 'sol'; raw: Raw }
interface Vector { name: string; ticket: string; now: number; context: Ctx; guard?: string; defect?: string }
interface Valid extends Vector { payload: TicketPayload }
const V = fixture<{ signers: { eth: string; sol: string }; valid: Valid[]; negatives: Vector[]; decode: Vector[] }>('tickets.json')

const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex')
const seed = (label: string): Buffer => createHash('sha256').update(`vt-fixture:${label}`).digest() // the generator's seed()
const bytesOf = (r: Raw): Uint8Array => (r.encoding === 'hex' ? hexToBytes(r.value as Hex) : Buffer.from(r.value, 'base64'))
const rawOf = (chain: 'eth' | 'sol', b: Uint8Array): Raw => (chain === 'eth' ? { encoding: 'hex', value: toHex(b) } : { encoding: 'base64', value: Buffer.from(b).toString('base64') })
const txIdOf = (chain: 'eth' | 'sol', b: Uint8Array): string => (chain === 'eth' ? keccak256(b) : base58Encode(b.subarray(1, 65)))
const payloadOf = (ticket: string): TicketPayload => JSON.parse(Buffer.from(ticket.split('.')[1], 'base64url').toString('utf8')) as TicketPayload
const OBSERVED: Record<Network, Record<'eth' | 'sol', string>> = {
  local: { eth: '0x7a69', sol: '8pUq7jxkLxNpHg6M9KxzRtNEC4pNEHsr4kDTLSE5uVRW' },
  testnet: { eth: '0xaa36a7', sol: GENESIS.sol.devnet },
  mainnet: { eth: '0x1', sol: GENESIS.sol.mainnet },
}
const sendOf = (c: Ctx, ticket: string, now: number): SendCheck => ({
  network: c.network, chain: c.chain, method: c.chain === 'eth' ? 'eth_sendRawTransaction' : 'sendTransaction',
  params: c.chain === 'eth' ? [c.raw.value] : [c.raw.value, { encoding: 'base64' }], ticketHeader: ticket, key: TICKET_KEY, now, observedId: OBSERVED[c.network][c.chain],
})
async function guardOf(p: Promise<unknown>): Promise<string> {
  try { await p } catch (e) {
    const g = (e as { guardId?: unknown }).guardId
    assert.equal(typeof g, 'string', `not a refusal: ${String(e)}`)
    return g as string
  }
  return 'passed'
}
// A payload exactly like the API issues: t and r follow the bytes; the binding as given.
const NOW = 1_791_504_100_000
function issued(w: Network, c: 'eth' | 'sol', raw: Uint8Array, b: Pick<TicketPayload, 'a' | 'k' | 'p' | 'to' | 'value' | 'f' | 'q' | 'x'>): TicketPayload {
  return { j: 'e3d45f73cf65abaa', w, c, g: 1, t: txIdOf(c, raw), r: sha(raw), ...b, e: NOW + 120_000, n: '0123456789abcdef' }
}

// ---- the contract vectors

// Each decode vector's own reason: removing any one check lets its vector through (hand mutants, report).
const REASON: Readonly<Record<string, string>> = {
  'eth-type-legacy': 'eth.type', 'eth-type-2930': 'eth.type', 'eth-type-blob': 'eth.type', 'eth-type-7702': 'eth.type',
  'eth-chain-id': 'eth.chain-id', 'eth-sender': 'eth.from', 'eth-fee-gas': 'eth.fee', 'eth-fee-max': 'eth.fee', 'eth-gas-zero': 'eth.gas',
  'eth-max-fee-zero': 'eth.max-fee', 'eth-tip-over-max': 'eth.decode' /* viem's parser already refuses tip > maxFee */,
  'eth-job-value': 'eth.value', 'eth-job-to': 'eth.to', 'eth-job-create': 'eth.to', 'eth-job-payload': 'eth.payload',
  'eth-job-to-self-under-null': 'eth.to', 'eth-job-to-null-under-self': 'eth.to',   // PF-S I-1: one recipient, never "either"
  'eth-access-list': 'eth.access-list', 'eth-clawback-to': 'eth.to', 'eth-clawback-value': 'eth.value', 'eth-clawback-data': 'eth.data',
  'eth-kind': 'eth.value', 'eth-tx-id': 'eth.tx-id', 'eth-high-s': 'eth.signature', 'eth-non-canonical-rlp': 'eth.canonical',
  'eth-trailing-byte': 'eth.decode', 'eth-nonce': 'eth.nonce', 'eth-clawback-nonce': 'eth.nonce',
  'sol-fee-payer': 'sol.fee-payer', 'sol-signature': 'sol.signature', 'sol-tx-id': 'sol.tx-id', 'sol-fee-price': 'sol.fee', 'sol-fee-limit': 'sol.fee',
  'sol-price-without-limit': 'sol.fee', 'sol-compute-budget-twice': 'sol.compute-budget', 'sol-heap-frame': 'sol.compute-budget',
  'sol-other-program': 'sol.program', 'sol-job-transfer': 'sol.transfer', 'sol-job-payload': 'sol.payload', 'sol-job-two-memos': 'sol.memo',
  'sol-job-writable': 'sol.memo', 'sol-two-signers': 'sol.signers', 'sol-lookup-table': 'sol.lookup-table', 'sol-clawback-to': 'sol.to',
  'sol-clawback-value': 'sol.value', 'sol-clawback-memo': 'sol.memo', 'sol-clawback-two-transfers': 'sol.transfer', 'sol-kind': 'sol.memo',
  'sol-trailing-byte': 'sol.canonical', 'sol-blockhash': 'sol.blockhash', 'sol-clawback-blockhash': 'sol.blockhash',
  'sol-price-without-limit-at-default-minus-1': 'sol.fee',
  'sol-job-extra-key': 'sol.extra-account', 'sol-clawback-extra-key': 'sol.extra-account',   // PF-S fix round 1 (N-1)
  // PF-S fix round 2 (R1-1): the fee members are the declared ones; the SOL message is exactly vt's builder's
  'eth-gas-members': 'eth.fee-members', 'eth-tip-members': 'eth.fee-members', 'eth-max-fee-members': 'eth.fee-members',
  'sol-job-v0': 'sol.layout', 'sol-job-order': 'sol.layout', 'sol-job-cu-limit-members': 'sol.layout', 'sol-job-price-without-limit': 'sol.layout',
  'sol-job-limit-zero': 'sol.layout', 'sol-clawback-limit-without-price': 'sol.layout',
}

// M2 FLIP (applied, operator R78): the mainnet vector now passes the whole gate (the job-send lock is lifted); behind an identity that is
// not mainnet's it is still refused, and its bytes are a clean tx for mainnet only.
test('contract: every valid vector decodes clean and passes the whole gate (mainnet too, the job-send lock lifted; a non-mainnet identity still refuses it)', async () => {
  assert.ok(V.valid.length >= 10)
  for (const v of V.valid) {
    assert.equal(await decodeMismatch(v.payload, bytesOf(v.context.raw), v.context.network), null, v.name)
    assert.equal(await guardOf(checkSend(sendOf(v.context, v.ticket, v.now))), 'passed', v.name)
  }
  const m = V.valid.find((v) => v.context.network === 'mainnet')!
  for (const id of ['0xaa36a7', '0x7a69', '']) assert.equal(await guardOf(checkSend({ ...sendOf(m.context, m.ticket, m.now), observedId: id })), 'config.identity-mismatch', id)
  assert.equal(await decodeMismatch(m.payload, bytesOf(m.context.raw), 'mainnet'), null)
  assert.equal(await decodeMismatch(m.payload, bytesOf(m.context.raw), 'testnet'), 'eth.chain-id')
})

test('contract: every decode vector (one defect each) → relay.decode-mismatch through checkSend, each for its own reason', async () => {
  assert.deepEqual(V.decode.map((d) => d.name).sort(), Object.keys(REASON).sort())
  for (const d of V.decode) {
    assert.equal(d.guard, 'relay.decode-mismatch')
    assert.equal(await guardOf(checkSend(sendOf(d.context, d.ticket, d.now))), 'relay.decode-mismatch', d.name)
    assert.equal(await decodeMismatch(payloadOf(d.ticket), bytesOf(d.context.raw), d.context.network), REASON[d.name], d.name)
  }
})

test('contract: the format and binding negatives keep their guards (v1 tickets and v1 payloads refused: no downgrade)', async () => {
  for (const n of V.negatives) assert.equal(await guardOf(checkSend(sendOf(n.context, n.ticket, n.now))), n.guard, n.name)
  assert.ok(V.negatives.some((n) => n.name === 'v1-ticket' && n.guard === 'relay.send-ticket'))
})

test('the fixture\'s synchronous ETH signer is byte-identical to viem\'s signTransaction (same key, same fields)', async () => {
  const account = privateKeyToAccount(toHex(seed('ticket eth signer')))
  assert.equal(account.address.toLowerCase(), V.signers.eth)
  for (const v of V.valid.filter((x) => x.context.chain === 'eth')) {
    const { r: _r, s: _s, v: _v, yParity: _y, ...fields } = parseTransaction(v.context.raw.value as Hex)
    assert.equal(await account.signTransaction(fields as Parameters<typeof account.signTransaction>[0]), v.context.raw.value, v.name)
  }
  assert.equal(Keypair.fromSeed(seed('ticket sol signer')).publicKey.toBase58(), V.signers.sol)
})

// ---- genuine txs from the engine's own builders

const PAYLOAD = new TextEncoder().encode('[1/2 1a2b3c4d] engine-built part one of a synthetic text.\n')
const NULL_ADDRESS = '0x0000000000000000000000000000000000000000'
const ETH_KEY = privateKeyToAccount(toHex(seed('s4 engine eth key')))
const ETH_DEST = privateKeyToAccount(toHex(seed('s4 engine eth destination'))).address
const SOL_KEY = Keypair.fromSeed(seed('s4 engine sol key'))
const SOL_DEST = Keypair.fromSeed(seed('s4 engine sol destination')).publicKey.toBase58()
const BLOCKHASH = new PublicKey(seed('s4 blockhash')).toBase58()
const solFee = (limit: number, price: number): string => String(5_000n + (BigInt(limit) * BigInt(price) + 999_999n) / 1_000_000n)

interface Built { name: string; network: Network; chain: 'eth' | 'sol'; raw: Uint8Array; payload: TicketPayload }
async function engineBuilt(): Promise<Built[]> {
  const out: Built[] = []
  const a = ETH_KEY.address.toLowerCase(), s = SOL_KEY.publicKey.toBase58()
  for (const network of ['local', 'testnet', 'mainnet'] as const) {
    const id = chainId(network, 'eth')
    const job = { nonce: 4, data: toHex(PAYLOAD), gas: 53_480n, maxFee: 2_000_001_000n, tip: 1_000_000n }
    for (const to of [NULL_ADDRESS, ETH_KEY.address]) {
      const raw = hexToBytes((await engineEthSign(ETH_KEY, id, { ...job, to })).raw as Hex)
      out.push({ name: `${network} eth job to ${to === NULL_ADDRESS ? 'null' : 'self'}`, network, chain: 'eth', raw,
        payload: issued(network, 'eth', raw, { a, k: 'job', p: sha(PAYLOAD), to: to.toLowerCase(), value: null, f: String(job.gas * job.maxFee), q: '4', x: `${job.gas}:${job.tip}:${job.maxFee}` }) })
    }
    const claw = await engineEthClawback(ETH_KEY, { chainId: id, nonce: 5, to: ETH_DEST, value: 3_141_592_653_589_793n, maxFee: 1_500_000_000n, tip: 1_000_000n })
    const craw = hexToBytes(claw.raw as Hex)
    out.push({ name: `${network} eth claw-back`, network, chain: 'eth', raw: craw,
      payload: issued(network, 'eth', craw, { a, k: 'clawback', p: null, to: ETH_DEST.toLowerCase(), value: '3141592653589793', f: String(parseTransaction(claw.raw as Hex).gas! * 1_500_000_000n), q: '5',
        x: `${parseTransaction(claw.raw as Hex).gas!}:1000000:1500000000` }) })
    for (const [cuLimit, cuPrice] of [[33_000, 0], [33_000, 12_500], [1_400_000, 1]] as const) {
      const signed = engineSolSign(SOL_KEY, { tx: engineSolTx(SOL_KEY.publicKey, PAYLOAD, BLOCKHASH, { cuLimit, cuPrice }) })
      const raw = Buffer.from(signed.raw, 'base64')
      assert.equal(signed.id, base58Encode(raw.subarray(1, 65)))
      out.push({ name: `${network} sol job limit ${cuLimit} price ${cuPrice}`, network, chain: 'sol', raw,
        payload: issued(network, 'sol', raw, { a: s, k: 'job', p: sha(PAYLOAD), to: null, value: null, f: solFee(cuLimit, cuPrice), q: BLOCKHASH, x: `${cuLimit}:${cuPrice}` }) })
    }
    const st = engineSolSign(SOL_KEY, { tx: engineSolTransfer(SOL_KEY.publicKey, SOL_DEST, 987_654_321n, BLOCKHASH) })
    const sraw = Buffer.from(st.raw, 'base64')
    out.push({ name: `${network} sol claw-back`, network, chain: 'sol', raw: sraw,
      payload: issued(network, 'sol', sraw, { a: s, k: 'clawback', p: null, to: SOL_DEST, value: '987654321', f: '5000', q: BLOCKHASH, x: '200000:0' }) })
  }
  return out
}

// M2 FLIP (applied, operator R78): the mainnet ones pass the whole gate too (the job-send lock is lifted); behind a non-mainnet identity they
// are still refused (config.identity-mismatch).
test('genuine txs built by the engine\'s own builders pass on every network (mainnet too, the job-send lock lifted; a non-mainnet identity still refuses)', async () => {
  const all = await engineBuilt()
  assert.equal(all.length, 3 * 7)
  for (const b of all) {
    assert.equal(await decodeMismatch(b.payload, b.raw, b.network), null, b.name)
    const ticket = encodeTicket(TICKET_KEY, b.payload)
    const send = sendOf({ network: b.network, chain: b.chain, raw: rawOf(b.chain, b.raw) }, ticket, NOW)
    assert.equal(await guardOf(checkSend(send)), 'passed', b.name)
    if (b.network === 'mainnet') assert.equal(await guardOf(checkSend({ ...send, observedId: OBSERVED.testnet[b.chain] })), 'config.identity-mismatch', b.name)
  }
  assert.equal(all.filter((b) => b.network === 'mainnet').length, 7)
})

test('each ticket field tampered, one at a time, against genuine bytes → refused, each for its reason', async () => {
  const all = await engineBuilt()
  const pick = (name: string): Built => all.find((b) => b.name === name)!
  const other = { eth: privateKeyToAccount(toHex(seed('s4 other'))).address.toLowerCase(), sol: Keypair.fromSeed(seed('s4 other')).publicKey.toBase58() }
  const a0 = ETH_KEY.address.toLowerCase()
  const cases: Array<[string, Partial<TicketPayload>, string]> = [
    ['local eth job to null', { a: other.eth }, 'eth.from'],
    ['local eth job to null', { t: keccak256(PAYLOAD) }, 'eth.tx-id'],
    ['local eth job to null', { p: sha(Buffer.from('another payload')) }, 'eth.payload'],
    ['local eth job to null', { f: String(53_480n * 2_000_001_000n - 1n) }, 'eth.fee'],
    ['local eth job to null', { k: 'clawback', p: null, to: NULL_ADDRESS, value: '1' }, 'eth.value'],
    ['local eth job to self', { a: other.eth }, 'eth.from'],
    // PF-S I-1: the ticket names ONE recipient; a job tx to the other one (or anywhere else) is refused
    ['local eth job to null', { to: a0 }, 'eth.to'],
    ['local eth job to self', { to: NULL_ADDRESS }, 'eth.to'],
    ['local eth job to null', { to: other.eth }, 'eth.to'],
    ['testnet eth claw-back', { to: other.eth }, 'eth.to'],
    ['testnet eth claw-back', { value: '3141592653589792' }, 'eth.value'],
    ['testnet eth claw-back', { value: '3141592653589794' }, 'eth.value'],
    ['testnet eth claw-back', { k: 'job', p: sha(PAYLOAD), to: ETH_DEST.toLowerCase(), value: null }, 'eth.value'],
    ['testnet eth claw-back', { f: String(21_000n * 1_500_000_000n - 1n) }, 'eth.fee'],
    ['testnet sol job limit 33000 price 12500', { a: other.sol }, 'sol.fee-payer'],
    ['testnet sol job limit 33000 price 12500', { t: base58Encode(new Uint8Array(64).fill(7)) }, 'sol.tx-id'],
    ['testnet sol job limit 33000 price 12500', { p: sha(Buffer.from('another payload')) }, 'sol.payload'],
    ['testnet sol job limit 33000 price 12500', { f: String(BigInt(solFee(33_000, 12_500)) - 1n) }, 'sol.fee'],
    ['testnet sol job limit 33000 price 12500', { k: 'clawback', p: null, to: SOL_DEST, value: '1' }, 'sol.memo'],
    ['local sol job limit 33000 price 0', { f: '4999' }, 'sol.fee'],
    ['local sol claw-back', { to: other.sol }, 'sol.to'],
    ['local sol claw-back', { value: '987654320' }, 'sol.value'],
    ['local sol claw-back', { a: other.sol }, 'sol.fee-payer'],
    ['local sol claw-back', { f: '4999' }, 'sol.fee'],
    ['local sol claw-back', { k: 'job', p: sha(PAYLOAD), to: null, value: null }, 'sol.transfer'],
    // CC-3a: the declared nonce / blockhash (review I-1: a "bump" of the nonce-4 family signed at another nonce)
    ['local eth job to null', { q: '5' }, 'eth.nonce'],
    ['local eth job to null', { q: '3' }, 'eth.nonce'],
    ['testnet eth job to self', { q: '40' }, 'eth.nonce'],
    ['testnet eth claw-back', { q: '6' }, 'eth.nonce'],
    ['testnet sol job limit 33000 price 12500', { q: new PublicKey(seed('s4 other blockhash')).toBase58() }, 'sol.blockhash'],
    ['local sol claw-back', { q: new PublicKey(seed('s4 other blockhash')).toBase58() }, 'sol.blockhash'],
    // PF-S fix round 2 (R1-1): the declared fee members x — each member off by one, or missing / malformed
    ['local eth job to null', { x: '53481:1000000:2000001000' }, 'eth.fee-members'],
    ['local eth job to null', { x: '53480:1000001:2000001000' }, 'eth.fee-members'],
    ['local eth job to null', { x: '53480:999999:2000001000' }, 'eth.fee-members'],
    ['local eth job to null', { x: '53480:1000000:2000000999' }, 'eth.fee-members'],
    ['testnet eth claw-back', { x: '21000:1000000:1500000001' }, 'eth.fee-members'],
    ['testnet sol job limit 33000 price 12500', { x: '33001:12500' }, 'sol.layout'],
    ['testnet sol job limit 33000 price 12500', { x: '33000:12499' }, 'sol.layout'],
    ['testnet sol job limit 33000 price 12500', { x: '33000:0' }, 'sol.layout'],
    ['local sol job limit 33000 price 0', { x: '33000:1' }, 'sol.layout'],
    ['local sol job limit 33000 price 0', { x: '32999:0' }, 'sol.layout'],
    ['local sol claw-back', { x: '450:1' }, 'sol.layout'],
  ]
  for (const [name, over, reason] of cases) {
    const b = pick(name)
    const t = { ...b.payload, ...over } as TicketPayload
    assert.equal(await decodeMismatch(t, b.raw, b.network), reason, `${name} ${JSON.stringify(over)}`)
    const ctx: Ctx = { network: b.network, chain: b.chain, raw: rawOf(b.chain, b.raw) }
    assert.equal(await guardOf(checkSend(sendOf(ctx, encodeTicket(TICKET_KEY, t), NOW))), 'relay.decode-mismatch', `${name} ${JSON.stringify(over)}`)
  }
  // a missing or malformed x never gets a ticket (encodeTicket / isTicketPayload refuse it); decode refuses it on its own too
  for (const [name, x, reason] of [['local eth job to null', null, 'eth.fee-members'], ['local eth job to null', '53480:1000000', 'eth.fee-members'],
    ['local eth job to null', '53480:1000000:2000001000:1', 'eth.fee-members'], ['local eth job to null', '53480:01000000:2000001000', 'eth.fee-members'],
    ['local sol job limit 33000 price 0', null, 'sol.layout'], ['local sol job limit 33000 price 0', '33000', 'sol.layout'],
    ['local sol job limit 33000 price 0', '0:0', 'sol.layout'], ['local sol claw-back', null, 'sol.layout']] as Array<[string, string | null, string]>) {
    const b = pick(name)
    assert.equal(await decodeMismatch({ ...b.payload, x }, b.raw, b.network), reason, `${name} x ${String(x)}`)
    assert.throws(() => encodeTicket(TICKET_KEY, { ...b.payload, x }), /malformed ticket payload/, `${name} x ${String(x)}`)
  }
  // the network: a genuine local tx at the testnet relay (its own ticket) → eth.chain-id
  const l = pick('local eth job to null')
  assert.equal(await decodeMismatch({ ...l.payload, w: 'testnet' }, l.raw, 'testnet'), 'eth.chain-id')
})

// ---- hand-built SOL messages for the checks web3.js' compiler never produces

function solSigned(message: Message | MessageV0, signers: Keypair[] = [SOL_KEY]): Uint8Array {
  const tx = new VersionedTransaction(message)
  tx.sign(signers)
  return tx.serialize()
}
const CB = new PublicKey('ComputeBudget111111111111111111111111111111')
const MEMO = new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr')
test('SOL header and account rules: an unused account (writable or read-only), a duplicate key, a readonly fee payer → refused', async () => {
  const s = SOL_KEY.publicKey.toBase58()
  const extra = Keypair.fromSeed(seed('s4 extra')).publicKey
  const job = (raw: Uint8Array, f = '5000', x = '10000:0'): TicketPayload => issued('local', 'sol', raw, { a: s, k: 'job', p: sha(PAYLOAD), to: null, value: null, f, q: BLOCKHASH, x })
  const limitData = Buffer.from([2, 0x10, 0x27, 0, 0]) // SetComputeUnitLimit 10,000
  // an extra writable account that no instruction names
  const unused = solSigned(new Message({ header: { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 2 },
    accountKeys: [SOL_KEY.publicKey, extra, CB, MEMO], recentBlockhash: BLOCKHASH,
    instructions: [{ programIdIndex: 2, accounts: [], data: base58Encode(limitData) }, { programIdIndex: 3, accounts: [], data: base58Encode(PAYLOAD) }] }))
  assert.equal(await decodeMismatch(job(unused), unused, 'local'), 'sol.writable')
  // PF-S fix round 1 (N-1): the same message with the extra account READ-ONLY is refused too — every key must be one the tx uses
  // (32 executor-chosen bytes per extra key would be published with the tx)
  const ro = solSigned(new Message({ header: { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 3 },
    accountKeys: [SOL_KEY.publicKey, extra, CB, MEMO], recentBlockhash: BLOCKHASH,
    instructions: [{ programIdIndex: 2, accounts: [], data: base58Encode(limitData) }, { programIdIndex: 3, accounts: [], data: base58Encode(PAYLOAD) }] }))
  assert.equal(await decodeMismatch(job(ro), ro, 'local'), 'sol.extra-account')
  // ... and so is the ComputeBudget program without a CU instruction, or a key appended after the programs
  const cbUnused = solSigned(new Message({ header: { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 2 },
    accountKeys: [SOL_KEY.publicKey, CB, MEMO], recentBlockhash: BLOCKHASH, instructions: [{ programIdIndex: 2, accounts: [], data: base58Encode(PAYLOAD) }] }))
  assert.equal(await decodeMismatch(job(cbUnused), cbUnused, 'local'), 'sol.extra-account')
  const tail = solSigned(new Message({ header: { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 2 },
    accountKeys: [SOL_KEY.publicKey, MEMO, extra], recentBlockhash: BLOCKHASH, instructions: [{ programIdIndex: 1, accounts: [], data: base58Encode(PAYLOAD) }] }))
  assert.equal(await decodeMismatch(job(tail), tail, 'local'), 'sol.extra-account')
  // the exact key set: the fee payer and Memo v2 alone passes every key rule, and (PF-S fix round 2, R1-1) is still refused — vt's
  // builder always sets the CU limit, so a memo-only job is not the message the ticket declares; with the ComputeBudget program its
  // instruction uses (the builder's SetComputeUnitLimit 10,000, x '10000:0') it passes
  const exact = solSigned(new Message({ header: { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 1 },
    accountKeys: [SOL_KEY.publicKey, MEMO], recentBlockhash: BLOCKHASH, instructions: [{ programIdIndex: 1, accounts: [], data: base58Encode(PAYLOAD) }] }))
  assert.equal(await decodeMismatch(job(exact), exact, 'local'), 'sol.layout')
  const exactCb = solSigned(new Message({ header: { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 2 },
    accountKeys: [SOL_KEY.publicKey, CB, MEMO], recentBlockhash: BLOCKHASH,
    instructions: [{ programIdIndex: 1, accounts: [], data: base58Encode(limitData) }, { programIdIndex: 2, accounts: [], data: base58Encode(PAYLOAD) }] }))
  assert.equal(await decodeMismatch(job(exactCb), exactCb, 'local'), null)
  // a claw-back whose message marks a third account writable (no instruction names it)
  const SYS = new PublicKey('11111111111111111111111111111111'), dest = new PublicKey(SOL_DEST)
  const transferData = Buffer.alloc(12); transferData.writeUInt32LE(2, 0); transferData.writeBigUInt64LE(77n, 4)
  const clawOf = (readonlyUnsigned: number): Uint8Array => solSigned(new Message({ header: { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: readonlyUnsigned },
    accountKeys: [SOL_KEY.publicKey, dest, extra, SYS], recentBlockhash: BLOCKHASH, instructions: [{ programIdIndex: 3, accounts: [0, 1], data: base58Encode(transferData) }] }))
  const claw = (raw: Uint8Array): TicketPayload => issued('local', 'sol', raw, { a: s, k: 'clawback', p: null, to: SOL_DEST, value: '77', f: '5000', q: BLOCKHASH, x: '200000:0' })
  const c3 = clawOf(1)                                                                                // dest and extra writable
  assert.equal(await decodeMismatch(claw(c3), c3, 'local'), 'sol.writable')
  const c2 = clawOf(2)                                                                                // dest writable only, the extra key read-only
  assert.equal(await decodeMismatch(claw(c2), c2, 'local'), 'sol.extra-account')                      // N-1: an unused key, even read-only
  const cbClaw = solSigned(new Message({ header: { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 2 },
    accountKeys: [SOL_KEY.publicKey, dest, SYS, CB], recentBlockhash: BLOCKHASH, instructions: [{ programIdIndex: 2, accounts: [0, 1], data: base58Encode(transferData) }] }))
  assert.equal(await decodeMismatch(claw(cbClaw), cbClaw, 'local'), 'sol.extra-account')              // ComputeBudget without its instruction
  const c1 = clawOf(3)                                                                                // dest readonly: the transfer could never credit it
  assert.equal(await decodeMismatch(claw(c1), c1, 'local'), 'sol.writable')
  // the System instruction must be exactly a transfer (tag 2, 12 bytes, two accounts) from the fee payer
  const sysIx = (data: Buffer, accounts: number[], keys = [SOL_KEY.publicKey, dest, SYS], readonlyUnsigned = 1): Uint8Array => solSigned(new Message({
    header: { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: readonlyUnsigned }, accountKeys: keys, recentBlockhash: BLOCKHASH,
    instructions: [{ programIdIndex: keys.length - 1, accounts, data: base58Encode(data) }] }))
  const tagged = (tag: number, extra = 0): Buffer => { const d = Buffer.alloc(12 + extra); d.writeUInt32LE(tag, 0); d.writeBigUInt64LE(77n, 4); return d }
  assert.equal(await decodeMismatch(claw(sysIx(tagged(2), [0, 1])), sysIx(tagged(2), [0, 1]), 'local'), null)          // the genuine shape passes
  for (const [name, raw] of [['tag 1 (assign) shaped like a transfer', sysIx(tagged(1), [0, 1])], ['tag 11 (transfer with seed)', sysIx(tagged(11), [0, 1])],
    ['13 data bytes', sysIx(tagged(2, 1), [0, 1])], ['three accounts', sysIx(tagged(2), [0, 1, 1])], ['one account', sysIx(tagged(2), [0])],
    ['from the destination, not the payer', sysIx(tagged(2), [1, 1])]] as Array<[string, Uint8Array]>) {
    assert.equal(await decodeMismatch(claw(raw), raw, 'local'), 'sol.transfer', name)
  }
  // a duplicate account key
  const dup = solSigned(new Message({ header: { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 2 },
    accountKeys: [SOL_KEY.publicKey, MEMO, MEMO], recentBlockhash: BLOCKHASH, instructions: [{ programIdIndex: 2, accounts: [], data: base58Encode(PAYLOAD) }] }))
  assert.equal(await decodeMismatch(job(dup), dup, 'local'), 'sol.accounts')
  // a readonly fee payer, and readonly counts beyond the key list
  for (const header of [{ numRequiredSignatures: 1, numReadonlySignedAccounts: 1, numReadonlyUnsignedAccounts: 1 }, { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 5 }]) {
    const bad = solSigned(new Message({ header, accountKeys: [SOL_KEY.publicKey, MEMO], recentBlockhash: BLOCKHASH, instructions: [{ programIdIndex: 1, accounts: [], data: base58Encode(PAYLOAD) }] }))
    assert.equal(await decodeMismatch(job(bad), bad, 'local'), 'sol.signers', JSON.stringify(header))
  }
  // a ComputeBudget instruction with an account, a SetComputeUnitLimit of the wrong length, a memo naming the payer
  const ixs = (...x: TransactionInstruction[]): Uint8Array => solSigned(new TransactionMessage({ payerKey: SOL_KEY.publicKey, recentBlockhash: BLOCKHASH, instructions: x }).compileToLegacyMessage())
  const cbAcct = ixs(new TransactionInstruction({ programId: CB, keys: [{ pubkey: SOL_KEY.publicKey, isSigner: false, isWritable: false }], data: limitData }), new TransactionInstruction({ programId: MEMO, keys: [], data: Buffer.from(PAYLOAD) }))
  assert.equal(await decodeMismatch(job(cbAcct), cbAcct, 'local'), 'sol.compute-budget')
  const cbLen = ixs(new TransactionInstruction({ programId: CB, keys: [], data: Buffer.concat([limitData, Buffer.from([0])]) }), new TransactionInstruction({ programId: MEMO, keys: [], data: Buffer.from(PAYLOAD) }))
  assert.equal(await decodeMismatch(job(cbLen), cbLen, 'local'), 'sol.compute-budget')
  const twoLimits = ixs(ComputeBudgetProgram.setComputeUnitLimit({ units: 10_000 }), ComputeBudgetProgram.setComputeUnitLimit({ units: 1 }), new TransactionInstruction({ programId: MEMO, keys: [], data: Buffer.from(PAYLOAD) }))
  assert.equal(await decodeMismatch(job(twoLimits), twoLimits, 'local'), 'sol.compute-budget')
  const memoSigner = ixs(ComputeBudgetProgram.setComputeUnitLimit({ units: 10_000 }), new TransactionInstruction({ programId: MEMO, keys: [{ pubkey: SOL_KEY.publicKey, isSigner: true, isWritable: false }], data: Buffer.from(PAYLOAD) }))
  assert.equal(await decodeMismatch(job(memoSigner), memoSigner, 'local'), 'sol.memo')
  // a transfer whose source is not the fee payer (claw-back)
  const from = Keypair.fromSeed(seed('s4 from'))
  const notPayer = solSigned(new TransactionMessage({ payerKey: SOL_KEY.publicKey, recentBlockhash: BLOCKHASH,
    instructions: [(await import('@solana/web3.js')).SystemProgram.transfer({ fromPubkey: from.publicKey, toPubkey: new PublicKey(SOL_DEST), lamports: 5n })] }).compileToLegacyMessage(), [SOL_KEY, from])
  assert.equal(await decodeMismatch(issued('local', 'sol', notPayer, { a: s, k: 'clawback', p: null, to: SOL_DEST, value: '5', f: '10000', q: BLOCKHASH, x: '200000:0' }), notPayer, 'local'), 'sol.signers')
})

test('ETH signature rules: r or s zero, s ≥ n/2 + 1, yParity 2 → refused (never recovered as some other sender)', async () => {
  const b = (await engineBuilt()).find((x) => x.name === 'local eth job to null')!
  const tx = parseTransaction(toHex(b.raw) as Hex)
  const { serializeTransaction } = await import('viem')
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
  const variants: Array<[string, { r: Hex; s: Hex; yParity: number }]> = [
    ['r 0', { r: '0x0', s: tx.s!, yParity: tx.yParity! }],
    ['s 0', { r: tx.r!, s: '0x0', yParity: tx.yParity! }],
    ['s = n/2 + 1', { r: tx.r!, s: toHex((N >> 1n) + 1n), yParity: tx.yParity! }],
    ['s = n', { r: tx.r!, s: toHex(N), yParity: tx.yParity! }],
    ['r = n', { r: toHex(N), s: tx.s!, yParity: tx.yParity! }],
  ]
  const seen: string[] = []
  for (const [name, sig] of variants) {
    const raw = hexToBytes(serializeTransaction({ ...tx, r: undefined, s: undefined, v: undefined, yParity: undefined } as never, sig as never))
    seen.push(`${name}: ${await decodeMismatch({ ...b.payload, t: keccak256(raw), r: sha(raw) }, raw, 'local')}`)
  }
  assert.deepEqual(seen, ['r 0: eth.signature', 's 0: eth.signature', 's = n/2 + 1: eth.signature', 's = n: eth.signature', 'r = n: eth.signature'])
  // yParity 2, hand-patched into the RLP (the byte right after the access list)
  const hex = toHex(b.raw)
  const at = hex.lastIndexOf('c080a0') >= 0 ? hex.lastIndexOf('c080a0') : hex.lastIndexOf('c001a0')
  assert.ok(at > 0)
  const y2 = hexToBytes(`${hex.slice(0, at + 2)}02${hex.slice(at + 4)}` as Hex)
  assert.notEqual(await decodeMismatch({ ...b.payload, t: keccak256(y2), r: sha(y2) }, y2, 'local'), null)
})

// ---- review m-1: the missing-CU-limit default is exactly 1,400,000

// PF-S fix round 2 (R1-1): vt never signs a price without a limit, so such bytes are refused at any f ('sol.layout' once the fee fits);
// the fee accounting itself still counts them at 1.4M CU (refused 'sol.fee' at f − 1), and the explicit 1.4M limit passes at f.
test('a CU price without a CU limit is counted at exactly 1,400,000 CU: the fee fits at f = 5000 + ⌈1.4M × price / 10⁶⌉ (then sol.layout), sol.fee at f − 1', async () => {
  const s = SOL_KEY.publicKey.toBase58()
  const memo = new TransactionInstruction({ programId: MEMO, keys: [], data: Buffer.from(PAYLOAD) })
  for (const price of [1, 7, 12_500, 999_999, 1_000_000]) {
    const priced = solSigned(new TransactionMessage({ payerKey: SOL_KEY.publicKey, recentBlockhash: BLOCKHASH,
      instructions: [ComputeBudgetProgram.setComputeUnitPrice({ microLamports: price }), memo] }).compileToLegacyMessage())
    const f = 5_000n + (1_400_000n * BigInt(price) + 999_999n) / 1_000_000n
    const t = (fee: bigint): TicketPayload => issued('local', 'sol', priced, { a: s, k: 'job', p: sha(PAYLOAD), to: null, value: null, f: String(fee), q: BLOCKHASH, x: `1400000:${price}` })
    assert.equal(await decodeMismatch(t(f), priced, 'local'), 'sol.layout', `price ${price} at f ${f}`)
    assert.equal(await decodeMismatch(t(f - 1n), priced, 'local'), 'sol.fee', `price ${price} at f − 1`)
    // the same bytes with an explicit 1,400,000 limit are charged the same
    const limited = solSigned(new TransactionMessage({ payerKey: SOL_KEY.publicKey, recentBlockhash: BLOCKHASH,
      instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }), ComputeBudgetProgram.setComputeUnitPrice({ microLamports: price }), memo] }).compileToLegacyMessage())
    const tl = (fee: bigint): TicketPayload => issued('local', 'sol', limited, { a: s, k: 'job', p: sha(PAYLOAD), to: null, value: null, f: String(fee), q: BLOCKHASH, x: `1400000:${price}` })
    assert.deepEqual([await decodeMismatch(tl(f), limited, 'local'), await decodeMismatch(tl(f - 1n), limited, 'local')], [null, 'sol.fee'], `price ${price} limit 1.4M`)
  }
})

// ---- malformed, oversized, fuzz

// A deterministic PRNG (sha256 in counter mode) so a failure is reproducible.
function prng(label: string): () => number {
  let i = 0, buf = Buffer.alloc(0)
  return () => {
    if (buf.length < 4) { buf = createHash('sha256').update(`${label}:${i++}`).digest(); }
    const x = buf.readUInt32LE(0); buf = buf.subarray(4); return x
  }
}

test('malformed and oversized bytes are refused without throwing (empty, junk, truncated at every length, over the size caps)', async () => {
  const eth = V.valid.find((v) => v.context.chain === 'eth' && v.context.network === 'local')!
  const sol = V.valid.find((v) => v.context.chain === 'sol')!
  const eb = bytesOf(eth.context.raw), sb = bytesOf(sol.context.raw)
  const reasons = new Set<string>()
  const expectRefused = async (t: TicketPayload, raw: Uint8Array, network: Network, label: string): Promise<void> => {
    const why = await decodeMismatch({ ...t, t: t.c === 'eth' ? keccak256(raw) : t.t, r: sha(raw) }, raw, network)
    assert.notEqual(why, null, label)
    assert.match(why!, /^(?:eth|sol)\.[a-z-]+$/, label)
    reasons.add(why!)
    await assert.rejects(assertDecodedMatches(t, raw, network), (e: { guardId?: string }) => e.guardId === 'relay.decode-mismatch', label)
  }
  for (const raw of [new Uint8Array(0), Uint8Array.of(0x02), Uint8Array.of(0x02, 0xc0), Uint8Array.of(0xff), Buffer.from('not a transaction')]) {
    await expectRefused(eth.payload, raw, 'local', `eth ${toHex(raw)}`)
    await expectRefused(sol.payload, raw, 'testnet', `sol ${toHex(raw)}`)
  }
  for (let n = 1; n < eb.length; n++) await expectRefused(eth.payload, eb.subarray(0, n), 'local', `eth truncated to ${n}`)
  for (let n = 1; n < sb.length; n++) await expectRefused(sol.payload, sb.subarray(0, n), 'testnet', `sol truncated to ${n}`)
  const bigEth = new Uint8Array(ETH_RAW_MAX + 1); bigEth[0] = 2
  await expectRefused(eth.payload, bigEth, 'local', 'eth over 128 KiB')
  assert.equal(await decodeMismatch(eth.payload, bigEth, 'local'), 'eth.size')
  const bigSol = new Uint8Array(SOL_RAW_MAX + 1); bigSol.set(sb)
  assert.equal(await decodeMismatch(sol.payload, bigSol, 'testnet'), 'sol.size')
  assert.equal(await decodeMismatch(sol.payload, new Uint8Array(0), 'testnet'), 'sol.size')
  assert.equal(await decodeMismatch(eth.payload, new Uint8Array(0), 'local'), 'eth.size')
  // a large valid-looking ETH tx under the cap still decodes (size alone is not a refusal)
  const prand = prng('junk')
  for (let k = 0; k < 200; k++) {
    const len = 1 + (prand() % 400)
    const junk = Uint8Array.from({ length: len }, () => prand() & 0xff)
    if (k % 2 === 0) junk[0] = 0x02
    await expectRefused(eth.payload, junk, 'local', `eth junk ${k}`)
    await expectRefused(sol.payload, junk, 'testnet', `sol junk ${k}`)
  }
  assert.ok(reasons.has('eth.decode') && reasons.has('sol.decode') && reasons.has('eth.size') && reasons.has('sol.size'))
})

test('fuzz: random byte flips of every genuine tx never pass, even when the ticket is re-made for the flipped bytes', async () => {
  const genuine = [
    ...V.valid.map((v) => ({ name: v.name, payload: v.payload, raw: bytesOf(v.context.raw), network: v.context.network })),
    ...(await engineBuilt()).map((b) => ({ name: b.name, payload: b.payload, raw: b.raw, network: b.network })),
  ]
  const rand = prng('flips')
  let runs = 0
  for (const g of genuine) {
    for (let k = 0; k < 40; k++) {
      const m = Uint8Array.from(g.raw)
      const flips = 1 + (rand() % 3)
      for (let f = 0; f < flips; f++) m[rand() % m.length] ^= 1 + (rand() % 255)
      if (Buffer.from(m).equals(Buffer.from(g.raw))) continue
      // the worst case for the relay: a ticket whose t and r follow the flipped bytes
      const t: TicketPayload = { ...g.payload, t: g.payload.c === 'eth' ? keccak256(m) : base58Encode(m.subarray(1, 65)), r: sha(m) }
      const why = await decodeMismatch(t, m, g.network)
      assert.notEqual(why, null, `${g.name}: flipped bytes passed (${toHex(m)})`)
      runs++
    }
  }
  assert.ok(runs > 1_000, String(runs))
})

test('fail closed on a kind or chain this relay does not know (a future ticket field it was not built for)', async () => {
  for (const v of V.valid.filter((x) => x.context.network !== 'mainnet')) {
    assert.equal(await decodeMismatch({ ...v.payload, k: 'publish' as never }, bytesOf(v.context.raw), v.context.network), 'kind', v.name)
  }
  const v = V.valid[0]
  assert.equal(await decodeMismatch({ ...v.payload, c: 'ltc' as never }, bytesOf(v.context.raw), v.context.network), 'chain')
  // btc is a chain since CC-8, with its own kinds: an eth/sol kind (job, clawback) under a btc ticket is a mismatch of kind
  assert.equal(await decodeMismatch({ ...v.payload, c: 'btc' as never }, bytesOf(v.context.raw), v.context.network), 'kind')
})

test('the refusal names a fixed reason, never a value from the bytes or the ticket; checkSend rejects (async), it never throws synchronously', async () => {
  const d = V.decode.find((x) => x.name === 'eth-sender')!
  let msg = ''
  try { await assertDecodedMatches(payloadOf(d.ticket), bytesOf(d.context.raw), 'local') } catch (e) { msg = (e as Error).message }
  assert.match(msg, /\(eth\.from\)/)
  for (const leak of [V.signers.eth, V.signers.eth.slice(2), d.context.raw.value.slice(2, 40), CANARY]) assert.ok(!msg.toLowerCase().includes(leak.toLowerCase()), leak)
  let threw = false, p: Promise<unknown> | null = null
  try { p = checkSend(sendOf(d.context, d.ticket, d.now)) } catch { threw = true }
  assert.equal(threw, false)
  assert.ok(p instanceof Promise)
  assert.equal(await guardOf(p!), 'relay.decode-mismatch')
})

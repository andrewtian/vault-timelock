// The relay's gates (api/src/relay-gate.ts): the send ticket bound to network, chain and raw bytes, the job-send lock
// with the identity the relay verified, the S4 decode verification (decode.ts; its own suite is decode.test.ts),
// requestAirdrop per network, and the Host / Origin / Sec-Fetch-Site / repeat checks. The contract's tickets.json
// vectors run through checkSend with their context. checkSend is async (S4): every send case awaits it. A case that
// must PASS carries a genuine signed tx (decode verification); a case refused earlier may carry any bytes.
// Synthetic keys and data only.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import type { Network, TicketPayload } from '@vault-timelock/core/contracts'
import { GENESIS } from 'vt-broadcast/src/config.ts'
import {
  JOB_SEND_METHODS, READ_METHODS, SEND_METHODS, checkMethodForNetwork, checkRelayHeaders, checkSend, classifyMethod, rawBytes, relayHosts, relayOrigins,
} from '../src/relay-gate.ts'
import type { SendCheck } from '../src/relay-gate.ts'
import { encodeTicket } from '../src/tickets.ts'
import type { TicketBinding } from '../src/tickets.ts'
import * as core from '../relay/relay-core.mjs'
import { ANY_BINDING, genuineEth, genuineSol, txIdOf } from './genuine.ts'
import { CANARY, TICKET_KEY, fixture } from './helpers.ts'

interface Raw { encoding: 'hex' | 'base64'; value: string }
interface Ctx { network: Network; chain: 'eth' | 'sol'; raw: Raw }
interface Valid { payload: TicketPayload; ticket: string; now: number; context: Ctx }
interface Negative { name: string; ticket: string; now: number; guard: string; context: Ctx }
const V = fixture<{ valid: Valid[]; negatives: Negative[]; decode: Negative[] }>('tickets.json')

const OBSERVED: Record<Network, Record<'eth' | 'sol', string>> = {
  local: { eth: '0x7a69', sol: '8pUq7jxkLxNpHg6M9KxzRtNEC4pNEHsr4kDTLSE5uVRW' },
  testnet: { eth: '0xaa36a7', sol: GENESIS.sol.devnet },
  mainnet: { eth: '0x1', sol: GENESIS.sol.mainnet },
}
const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex')
const paramsOf = (raw: Raw): unknown[] => (raw.encoding === 'hex' ? [raw.value] : [raw.value, { encoding: 'base64' }])
const methodOf = (chain: 'eth' | 'sol'): string => (chain === 'eth' ? 'eth_sendRawTransaction' : 'sendTransaction')
function send(c: Ctx, ticket: string | null | undefined, now: number, over: Partial<SendCheck> = {}): SendCheck {
  return {
    network: c.network, chain: c.chain, method: methodOf(c.chain), params: paramsOf(c.raw), ticketHeader: ticket,
    key: TICKET_KEY, now, observedId: OBSERVED[c.network][c.chain], ...over,
  }
}
function guardOf(fn: () => unknown): string {
  try { fn() } catch (e) {
    const g = (e as { guardId?: unknown }).guardId
    assert.equal(typeof g, 'string', `not a refusal: ${String(e)}`)
    return g as string
  }
  return 'passed'
}
// checkSend is async (S4): its refusals are rejections.
async function sendGuard(o: SendCheck): Promise<string> {
  try { await checkSend(o) } catch (e) {
    const g = (e as { guardId?: unknown }).guardId
    assert.equal(typeof g, 'string', `not a refusal: ${String(e)}`)
    return g as string
  }
  return 'passed'
}
async function messageOf(p: Promise<unknown>): Promise<string> {
  try { await p } catch (e) { return (e as Error).message }
  return ''
}

// A fresh ticket for these raw bytes (the API would issue it after journaling the intent). With a binding the bytes are
// genuine and t is their tx id; without one, the bytes are refused before decoding, and t and the binding are fillers.
function ticketFor(o: { network: Network; chain: 'eth' | 'sol'; raw: Uint8Array; e?: number; binding?: TicketBinding }): { ticket: string; payload: TicketPayload } {
  const t = o.binding !== undefined ? txIdOf(o.chain, o.raw)
    : o.chain === 'eth' ? `0x${'ab'.repeat(32)}` : '4nFJ19CY7VzhcJt9CEThokVbZVgtBDVgzJFz65YQQwTKYYYXLEu3e6yRMFGT8WG3FuUG8i7VjS7He77vbinmLEpC'
  const payload: TicketPayload = { j: 'e3d45f73cf65abaa', w: o.network, c: o.chain, g: 1, t, r: sha(o.raw), ...(o.binding ?? ANY_BINDING[o.chain]), e: o.e ?? 2_000_000, n: '0123456789abcdef' }
  return { ticket: encodeTicket(TICKET_KEY, payload), payload }
}
const NOW = 1_000_000

// M2 FLIP (applied, operator R78): the mainnet vector passes too (the job-send lock is lifted); behind an identity that is not mainnet's,
// or at another network's relay, it is still refused.
test('contract vectors: the valid tickets pass the gate (mainnet too: the job-send lock is lifted; a non-mainnet identity or relay still refuses it); each negative and decode vector gets its guard', async () => {
  assert.equal(V.valid.length, 10)
  for (const v of V.valid) assert.equal(await sendGuard(send(v.context, v.ticket, v.now)), 'passed', v.context.network)
  const mainnet = V.valid.filter((v) => v.context.network === 'mainnet')
  assert.equal(mainnet.length, 1)
  const mv = mainnet[0]
  for (const id of ['0xaa36a7', '0x7a69', '0xa4b1', '', 'x']) assert.equal(await sendGuard(send(mv.context, mv.ticket, mv.now, { observedId: id })), 'config.identity-mismatch', id)
  for (const n of ['testnet', 'local'] as const) assert.equal(await sendGuard(send({ ...mv.context, network: n }, mv.ticket, mv.now)), 'relay.ticket-network', n)
  assert.equal(V.negatives.length, 34)
  for (const n of V.negatives) assert.equal(await sendGuard(send(n.context, n.ticket, n.now)), n.guard, n.name)
  assert.ok(V.decode.length >= 40)
  for (const d of V.decode) assert.equal(await sendGuard(send(d.context, d.ticket, d.now)), 'relay.decode-mismatch', d.name)
})

test('eth_sendRawTransaction or sendTransaction without the header (or with an empty, garbage or v1 one) → relay.send-ticket', async () => {
  const c = V.valid[0].context
  for (const h of [undefined, null, '', 'vt-ticket/1.', 'vt-ticket/2.', `Bearer ${CANARY}`, V.valid[0].ticket.toUpperCase(), V.negatives.find((n) => n.name === 'v1-ticket')!.ticket]) {
    assert.equal(await sendGuard(send(c, h, V.valid[0].now)), 'relay.send-ticket')
  }
  const s = V.valid[1].context
  assert.equal(await sendGuard(send(s, undefined, V.valid[1].now)), 'relay.send-ticket')
})

test('a valid ticket whose r is not the sha256 of the raw bytes → relay.ticket-raw', async () => {
  const { raw, binding } = await genuineEth('local')
  const { ticket } = ticketFor({ network: 'local', chain: 'eth', raw, binding })
  const ok: Ctx = { network: 'local', chain: 'eth', raw: { encoding: 'hex', value: `0x${raw.toString('hex')}` } }
  assert.equal(await sendGuard(send(ok, ticket, NOW)), 'passed')
  const other = Buffer.from(raw); other[7] ^= 1
  assert.equal(await sendGuard(send({ ...ok, raw: { encoding: 'hex', value: `0x${other.toString('hex')}` } }, ticket, NOW)), 'relay.ticket-raw')
  // upper-case hex is the same bytes (geth decodes either case)
  assert.equal(await sendGuard(send({ ...ok, raw: { encoding: 'hex', value: `0x${raw.toString('hex').toUpperCase()}` } }, ticket, NOW)), 'passed')
})

test('raw bytes must be unambiguous: exact 0x-hex alone (ETH); canonical base64 with encoding base64 (SOL)', async () => {
  const ge = await genuineEth('testnet'), gs = genuineSol({ mod3: 1 })                   // ≡ 1 (mod 3): base64 ends in '=='
  const hex = `0x${ge.raw.toString('hex')}`, b64 = gs.raw.toString('base64')
  const raw = gs.raw
  const eth = ticketFor({ network: 'testnet', chain: 'eth', raw: ge.raw, binding: ge.binding }).ticket
  const sol = ticketFor({ network: 'testnet', chain: 'sol', raw: gs.raw, binding: gs.binding }).ticket
  const e = (params: unknown): Promise<string> => sendGuard({ ...send({ network: 'testnet', chain: 'eth', raw: { encoding: 'hex', value: hex } }, eth, NOW), params })
  const s = (params: unknown): Promise<string> => sendGuard({ ...send({ network: 'testnet', chain: 'sol', raw: { encoding: 'base64', value: b64 } }, sol, NOW), params })
  assert.equal(await e([hex]), 'passed')
  for (const bad of [[hex, 'extra'], [hex.slice(2)], [`${hex}0`], [`${hex}zz`], [`0X${hex.slice(2)}`], ['0x'], [], {}, null, [ge.raw.toString('base64')], [Number(1)]]) {
    assert.equal(await e(bad), 'relay.ticket-raw', JSON.stringify(bad))
  }
  assert.equal(await s([b64, { encoding: 'base64' }]), 'passed')
  assert.equal(await s([b64, { encoding: 'base64', skipPreflight: true, maxRetries: 0 }]), 'passed')
  // the same bytes with the last character's unused bits set: Node decodes it, Solana's decoder refuses it
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  const nonCanonical = `${b64.slice(0, -3)}${A[A.indexOf(b64.at(-3) ?? 'A') | 1]}==`
  assert.ok(nonCanonical !== b64 && Buffer.from(nonCanonical, 'base64').equals(raw))
  for (const bad of [[b64], [b64, { encoding: 'base58' }], [b64, {}], [b64, { encoding: 'base64' }, 'x'], [b64.replace(/=+$/, ''), { encoding: 'base64' }],
    [nonCanonical, { encoding: 'base64' }], [Buffer.from(raw).toString('base64url'), { encoding: 'base64' }], ['', { encoding: 'base64' }], [`${b64}\n`, { encoding: 'base64' }]]) {
    assert.equal(await s(bad), 'relay.ticket-raw', JSON.stringify(bad))
  }
  assert.equal(rawBytes('sol', [b64, { encoding: 'base64' }])?.equals(raw), true)
  assert.equal(rawBytes('eth', [hex])?.equals(ge.raw), true)
})

test('w: a mainnet ticket at a testnet relay → relay.ticket-network (and a testnet ticket at the local relay)', async () => {
  const raw = randomBytes(40)
  const value = `0x${raw.toString('hex')}`
  const m = ticketFor({ network: 'mainnet', chain: 'eth', raw }).ticket
  assert.equal(await sendGuard(send({ network: 'testnet', chain: 'eth', raw: { encoding: 'hex', value } }, m, NOW)), 'relay.ticket-network')
  const t = ticketFor({ network: 'testnet', chain: 'eth', raw }).ticket
  assert.equal(await sendGuard(send({ network: 'local', chain: 'eth', raw: { encoding: 'hex', value } }, t, NOW)), 'relay.ticket-network')
})

test('expired: at e and after → relay.ticket-expired; just before e → valid', async () => {
  const { raw, binding } = await genuineEth('local')
  const c: Ctx = { network: 'local', chain: 'eth', raw: { encoding: 'hex', value: `0x${raw.toString('hex')}` } }
  const { ticket, payload } = ticketFor({ network: 'local', chain: 'eth', raw, binding })
  assert.equal(await sendGuard(send(c, ticket, payload.e)), 'relay.ticket-expired')
  assert.equal(await sendGuard(send(c, ticket, payload.e + 1)), 'relay.ticket-expired')
  assert.equal(await sendGuard(send(c, ticket, payload.e - 1)), 'passed')
})

test('an eth ticket on /relay/sol → relay.ticket-chain (and a sol ticket on /relay/eth)', async () => {
  const raw = randomBytes(64)
  const eth = ticketFor({ network: 'testnet', chain: 'eth', raw }).ticket
  assert.equal(await sendGuard(send({ network: 'testnet', chain: 'sol', raw: { encoding: 'base64', value: raw.toString('base64') } }, eth, NOW)), 'relay.ticket-chain')
  const sol = ticketFor({ network: 'testnet', chain: 'sol', raw }).ticket
  assert.equal(await sendGuard(send({ network: 'testnet', chain: 'eth', raw: { encoding: 'hex', value: `0x${raw.toString('hex')}` } }, sol, NOW)), 'relay.ticket-chain')
})

// M2 FLIP (applied, operator R78): the job-send lock no longer refuses a mainnet ETH / SOL send; every other check still does.
test('mainnet send (M2 flip: the job-send lock lifted): genuine bytes with their ticket pass on both chains; other bytes, an expired ticket or a non-mainnet identity are still refused', async () => {
  const raw = randomBytes(64)
  for (const chain of ['eth', 'sol'] as const) {
    const c: Ctx = { network: 'mainnet', chain, raw: chain === 'eth' ? { encoding: 'hex', value: `0x${raw.toString('hex')}` } : { encoding: 'base64', value: raw.toString('base64') } }
    assert.equal(await sendGuard(send(c, ticketFor({ network: 'mainnet', chain, raw }).ticket, NOW)), 'relay.decode-mismatch', chain)
  }
  const g = await genuineEth('mainnet')
  const c: Ctx = { network: 'mainnet', chain: 'eth', raw: { encoding: 'hex', value: `0x${g.raw.toString('hex')}` } }
  const t = ticketFor({ network: 'mainnet', chain: 'eth', raw: g.raw, binding: g.binding }).ticket
  assert.equal(await sendGuard(send(c, t, NOW)), 'passed')
  for (const id of ['0xaa36a7', '0x7a69', '0xa4b1', ' 1 ', '']) assert.equal(await sendGuard(send(c, t, NOW, { observedId: id })), 'config.identity-mismatch', id)
  assert.equal(await sendGuard(send(c, ticketFor({ network: 'mainnet', chain: 'eth', raw: g.raw, binding: g.binding, e: NOW }).ticket, NOW)), 'relay.ticket-expired')
  assert.equal(await sendGuard(send(c, ticketFor({ network: 'testnet', chain: 'eth', raw: g.raw, binding: g.binding }).ticket, NOW)), 'relay.ticket-network')
  assert.equal(await sendGuard(send(c, ticketFor({ network: 'mainnet', chain: 'eth', raw: g.raw, binding: { ...g.binding, p: 'ab'.repeat(32) } }).ticket, NOW)), 'relay.decode-mismatch')
  const tg = await genuineEth('testnet')   // testnet-signed bytes under a mainnet ticket: the chain id refuses them
  assert.equal(await sendGuard(send({ ...c, raw: { encoding: 'hex', value: `0x${tg.raw.toString('hex')}` } }, ticketFor({ network: 'mainnet', chain: 'eth', raw: tg.raw, binding: tg.binding }).ticket, NOW)), 'relay.decode-mismatch')
  const gs = genuineSol()
  const s: Ctx = { network: 'mainnet', chain: 'sol', raw: { encoding: 'base64', value: gs.raw.toString('base64') } }
  const ts = ticketFor({ network: 'mainnet', chain: 'sol', raw: gs.raw, binding: gs.binding }).ticket
  assert.equal(await sendGuard(send(s, ts, NOW)), 'passed')
  for (const id of [GENESIS.sol.devnet, GENESIS.sol.testnet, '8pUq7jxkLxNpHg6M9KxzRtNEC4pNEHsr4kDTLSE5uVRW', '']) assert.equal(await sendGuard(send(s, ts, NOW, { observedId: id })), 'config.identity-mismatch', id)
  // PF-S M-1: a mainnet BTC send stays refused by the all-scope lock (relay-btc-send.test.ts, unedited), which the flip never lifts
})

test('the observed identity: a mainnet identity behind a testnet or local relay → release.mainnet-locked; a foreign one → config.identity-mismatch', async () => {
  const g = await genuineEth('testnet')
  const c: Ctx = { network: 'testnet', chain: 'eth', raw: { encoding: 'hex', value: `0x${g.raw.toString('hex')}` } }
  const t = ticketFor({ network: 'testnet', chain: 'eth', raw: g.raw, binding: g.binding }).ticket
  assert.equal(await sendGuard(send(c, t, NOW)), 'passed')
  assert.equal(await sendGuard(send(c, t, NOW, { observedId: '0x1' })), 'release.mainnet-locked')
  assert.equal(await sendGuard(send(c, t, NOW, { observedId: '0x7a69' })), 'config.identity-mismatch')
  assert.equal(await sendGuard(send(c, t, NOW, { observedId: '' })), 'config.identity-mismatch')
  const gs = genuineSol()
  const s: Ctx = { network: 'local', chain: 'sol', raw: { encoding: 'base64', value: gs.raw.toString('base64') } }
  const ts = ticketFor({ network: 'local', chain: 'sol', raw: gs.raw, binding: gs.binding }).ticket
  assert.equal(await sendGuard(send(s, ts, NOW)), 'passed')                                             // a random local genesis
  assert.equal(await sendGuard(send(s, ts, NOW, { observedId: GENESIS.sol.mainnet })), 'release.mainnet-locked')
  assert.equal(await sendGuard(send(s, ts, NOW, { observedId: GENESIS.sol.devnet })), 'config.identity-mismatch')
})

test('an identical-bytes SOL rebroadcast within the TTL is allowed again and again on /relay/sol (tickets are stateless until e there; endpoint routes: relay-endpoints.test.ts)', async () => {
  const { raw, binding } = genuineSol()
  const c: Ctx = { network: 'testnet', chain: 'sol', raw: { encoding: 'base64', value: raw.toString('base64') } }
  const { ticket, payload } = ticketFor({ network: 'testnet', chain: 'sol', raw, binding, e: NOW + 120_000 })
  for (let t = NOW; t < payload.e; t += 2_000) assert.equal(await sendGuard(send(c, ticket, t)), 'passed')
  assert.equal(await sendGuard(send(c, ticket, payload.e)), 'relay.ticket-expired')
})

test('S4: genuine bytes whose ticket binds another payload, sender or a lower fee → relay.decode-mismatch (after every earlier check)', async () => {
  const g = await genuineEth('local')
  const c: Ctx = { network: 'local', chain: 'eth', raw: { encoding: 'hex', value: `0x${g.raw.toString('hex')}` } }
  for (const over of [{ p: 'ab'.repeat(32) }, { a: `0x${'22'.repeat(20)}` }, { f: String(BigInt(g.binding.f) - 1n) }, { q: String(g.nonce + 1) }] as Array<Partial<TicketBinding>>) {
    const t = ticketFor({ network: 'local', chain: 'eth', raw: g.raw, binding: { ...g.binding, ...over } }).ticket
    assert.equal(await sendGuard(send(c, t, NOW)), 'relay.decode-mismatch', JSON.stringify(over))
    assert.equal(await sendGuard(send({ ...c, network: 'mainnet' }, t, NOW)), 'relay.ticket-network')
  }
  const gs = genuineSol()
  const s: Ctx = { network: 'testnet', chain: 'sol', raw: { encoding: 'base64', value: gs.raw.toString('base64') } }
  assert.equal(await sendGuard(send(s, ticketFor({ network: 'testnet', chain: 'sol', raw: gs.raw, binding: { ...gs.binding, f: '4999' } }).ticket, NOW)), 'relay.decode-mismatch')
  assert.equal(await sendGuard(send(s, ticketFor({ network: 'testnet', chain: 'sol', raw: gs.raw, binding: { ...gs.binding, q: '11111111111111111111111111111111' } }).ticket, NOW)), 'relay.decode-mismatch')
  // random bytes with a ticket for exactly them: decoding fails → refused, never forwarded
  const junk = randomBytes(150)
  assert.equal(await sendGuard(send({ network: 'local', chain: 'eth', raw: { encoding: 'hex', value: `0x${junk.toString('hex')}` } }, ticketFor({ network: 'local', chain: 'eth', raw: junk }).ticket, NOW)), 'relay.decode-mismatch')
})

test('reads need no ticket; the send set is the relay core\'s', async () => {
  for (const n of ['local', 'testnet', 'mainnet'] as const) {
    for (const chain of ['eth', 'sol'] as const) {
      for (const method of READ_METHODS[n][chain]) {
        assert.equal(await sendGuard({ network: n, chain, method, params: [], ticketHeader: undefined, key: TICKET_KEY, now: NOW, observedId: OBSERVED[n][chain] }), 'passed', `${n} ${chain} ${method}`)
      }
    }
  }
  assert.deepEqual([...SEND_METHODS].sort(), [...core.SEND_METHODS].sort())
  assert.deepEqual([...SEND_METHODS].sort(), ['eth_sendRawTransaction', 'sendTransaction'])
})

// ---- the method table (S3 review I-1): exact, so adding or moving a method is a change to this test

const ETH_READS = ['eth_chainId', 'eth_blockNumber', 'eth_getBalance', 'eth_getTransactionCount', 'eth_estimateGas', 'eth_call', 'eth_feeHistory',
  'eth_maxPriorityFeePerGas', 'eth_getBlockByNumber', 'eth_getTransactionReceipt', 'eth_getTransactionByHash', 'eth_getCode']
const SOL_READS = ['getGenesisHash', 'getLatestBlockhash', 'getBalance', 'getFeeForMessage', 'simulateTransaction', 'getSignatureStatuses',
  'getTransaction', 'getMinimumBalanceForRentExemption', 'getRecentPrioritizationFees', 'getSignaturesForAddress',
  'getAccountInfo', 'isBlockhashValid']                                       // I3: E3's preflight and expiry reads
// S6: the local regtest bitcoind (reads only; testnet4 and mainnet BTC reads are Esplora GET routes, relay-breadth.test.ts)
const BTC_LOCAL_READS = ['getblockchaininfo', 'getblockcount', 'getbestblockhash', 'getblockhash', 'getblockheader', 'getblock',
  'getrawtransaction', 'gettxout', 'getmempoolentry', 'estimatesmartfee', 'testmempoolaccept', 'scantxoutset']
test('the read lists are pinned exactly, per network and chain; the job sends are exactly one per chain', () => {
  assert.deepEqual(READ_METHODS, {
    local: { eth: ETH_READS, sol: [...SOL_READS, 'requestAirdrop'], btc: BTC_LOCAL_READS },
    testnet: { eth: ETH_READS, sol: [...SOL_READS, 'requestAirdrop'], btc: [] as string[] },
    mainnet: { eth: ETH_READS, sol: SOL_READS, btc: [] as string[] },
  })
  assert.deepEqual(JOB_SEND_METHODS, { eth: 'eth_sendRawTransaction', sol: 'sendTransaction', btc: 'btc_send' })   // S6b: btc_send names POST /relay/btc/send, not a JSON-RPC method
  assert.ok(Object.isFrozen(READ_METHODS) && Object.isFrozen(READ_METHODS.mainnet) && Object.isFrozen(READ_METHODS.mainnet.eth) && Object.isFrozen(JOB_SEND_METHODS))
  assert.ok(Object.isFrozen(READ_METHODS.local.btc) && Object.isFrozen(READ_METHODS.mainnet.btc))
  for (const n of ['local', 'testnet', 'mainnet'] as const) {
    for (const chain of ['eth', 'sol', 'btc'] as const) {
      for (const m of READ_METHODS[n][chain]) assert.doesNotMatch(m, /send|submit|broadcast|bundle|push|publish|relay/i, `${n} ${chain}: a send-like name on a read list`)
      assert.ok(!READ_METHODS[n][chain].includes(JOB_SEND_METHODS.eth) && !READ_METHODS[n][chain].includes(JOB_SEND_METHODS.sol))
    }
  }
})

// Send-like and odd names a future edit might let through. None is a read anywhere; only the chain's job send is a send.
const NOT_LISTED = ['eth_sendRawTransactionSync', 'eth_sendTransaction', 'eth_sendBundle', 'mev_sendBundle', 'eth_sendPrivateTransaction',
  'eth_sendRawTransactionConditional', 'sendBundle', 'sendRawTransaction', 'pushTransaction', 'publishTx', 'eth_accounts', 'eth_sign',
  'eth_signTransaction', 'personal_sendTransaction', 'debug_setHead', 'anvil_setBalance', 'eth_subscribe', 'ETH_SENDRAWTRANSACTION',
  'eth_SendRawTransaction', 'SendTransaction', 'eth_sendRawTransaction ', ' sendTransaction', '__proto__', 'constructor', 'toString', 'hasOwnProperty', '']
test('default deny: every method not on the read list and not the chain\'s job send → relay.method, with or without a ticket', async () => {
  for (const n of ['local', 'testnet', 'mainnet'] as const) {
    for (const chain of ['eth', 'sol'] as const) {
      for (const m of NOT_LISTED) assert.equal(guardOf(() => classifyMethod(n, chain, m)), 'relay.method', `${n} ${chain} ${JSON.stringify(m)}`)
      const other = chain === 'eth' ? 'sendTransaction' : 'eth_sendRawTransaction'                 // the other chain's send
      assert.equal(guardOf(() => classifyMethod(n, chain, other)), 'relay.method')
      assert.equal(classifyMethod(n, chain, JOB_SEND_METHODS[chain]), 'send')
    }
    assert.equal(guardOf(() => classifyMethod(n, 'eth', 'requestAirdrop')), 'relay.method')
  }
  assert.equal(guardOf(() => classifyMethod('mainnet', 'sol', 'requestAirdrop')), 'relay.method')   // the faucet is a read on local + testnet only
  // the reviewer's probe (EIP-7966): a send by another name, with a ticket that is valid for its bytes, is still refused
  const raw = randomBytes(64)
  const hex = `0x${raw.toString('hex')}`
  for (const n of ['local', 'testnet', 'mainnet'] as const) {
    const t = ticketFor({ network: n, chain: 'eth', raw }).ticket
    for (const method of ['eth_sendRawTransactionSync', 'eth_sendRawTransactionConditional', 'eth_sendTransaction']) {
      assert.equal(await sendGuard({ network: n, chain: 'eth', method, params: [hex], ticketHeader: t, key: TICKET_KEY, now: NOW, observedId: OBSERVED[n].eth }), 'relay.method', `${n} ${method}`)
    }
  }
})

test('requestAirdrop: the sol route of local and testnet only → relay.airdrop-network elsewhere', () => {
  assert.equal(guardOf(() => checkMethodForNetwork('local', 'sol', 'requestAirdrop')), 'passed')
  assert.equal(guardOf(() => checkMethodForNetwork('testnet', 'sol', 'requestAirdrop')), 'passed')
  assert.equal(guardOf(() => checkMethodForNetwork('mainnet', 'sol', 'requestAirdrop')), 'relay.airdrop-network')
  for (const n of ['local', 'testnet', 'mainnet'] as const) {
    assert.equal(guardOf(() => checkMethodForNetwork(n, 'eth', 'requestAirdrop')), 'relay.airdrop-network')
    for (const m of ['getBalance', 'sendTransaction', 'eth_chainId']) assert.equal(guardOf(() => checkMethodForNetwork(n, 'sol', m)), 'passed')
  }
})

// raw headers as Node gives them: [name, value, name, value, …]
const H = (...pairs: Array<[string, string]>): string[] => pairs.flat()
test('headers: Host is this network\'s relay or page port on 127.0.0.1 (the dev port on local only) → relay.host', () => {
  assert.deepEqual(relayHosts('local'), ['127.0.0.1:5181', '127.0.0.1:5180', '127.0.0.1:5183'])
  assert.deepEqual(relayHosts('testnet'), ['127.0.0.1:5191', '127.0.0.1:5190'])
  assert.deepEqual(relayHosts('mainnet'), ['127.0.0.1:5201', '127.0.0.1:5200'])
  for (const n of ['local', 'testnet', 'mainnet'] as const) for (const h of relayHosts(n)) assert.equal(guardOf(() => checkRelayHeaders(H(['Host', h]), n)), 'passed')
  const bad: Array<[Network, string[]]> = [
    ['local', []], ['local', H(['host', 'localhost:5181'])], ['local', H(['host', `${CANARY}:5181`])], ['local', H(['host', 'evil.example:5181'])],
    ['testnet', H(['host', '127.0.0.1:5181'])], ['testnet', H(['host', '127.0.0.1:5183'])], ['mainnet', H(['host', '127.0.0.1:5191'])],
    ['local', H(['host', '127.0.0.1:5181 '])], ['local', H(['host', '127.0.0.1'])],
  ]
  for (const [n, raw] of bad) assert.equal(guardOf(() => checkRelayHeaders(raw, n)), 'relay.host', `${n} ${raw.join(' ')}`)
})

test('headers: Origin absent or this network\'s page (local also the Vite dev page) → relay.origin', () => {
  assert.deepEqual(relayOrigins('local'), ['http://127.0.0.1:5180', 'http://127.0.0.1:5183'])
  assert.deepEqual(relayOrigins('testnet'), ['http://127.0.0.1:5190'])
  const host = (n: Network): [string, string] => ['host', relayHosts(n)[0]]
  for (const n of ['local', 'testnet', 'mainnet'] as const) {
    for (const o of relayOrigins(n)) assert.equal(guardOf(() => checkRelayHeaders(H(host(n), ['Origin', o]), n)), 'passed')
  }
  for (const [n, o] of [['local', 'http://evil.example'], ['local', 'null'], ['local', 'http://localhost:5180'], ['testnet', 'http://127.0.0.1:5183'],
    ['testnet', 'http://127.0.0.1:5180'], ['mainnet', 'http://127.0.0.1:5190'], ['local', 'http://127.0.0.1:5180/'], ['local', `http://${CANARY}`]] as const) {
    assert.equal(guardOf(() => checkRelayHeaders(H(host(n), ['origin', o]), n)), 'relay.origin', `${n} ${o}`)
  }
})

test('headers: Sec-Fetch-Site cross-site / same-site → relay.fetch-site; a header sent twice → relay.header-repeated', () => {
  const h: [string, string] = ['host', '127.0.0.1:5181']
  for (const s of ['same-origin', 'none']) assert.equal(guardOf(() => checkRelayHeaders(H(h, ['Sec-Fetch-Site', s]), 'local')), 'passed')
  for (const s of ['cross-site', 'same-site', '']) assert.equal(guardOf(() => checkRelayHeaders(H(h, ['sec-fetch-site', s]), 'local')), 'relay.fetch-site', s)
  for (const twice of [H(h, h), H(h, ['HOST', 'evil.example']), H(h, ['origin', 'http://127.0.0.1:5180'], ['Origin', 'http://127.0.0.1:5180']),
    H(h, ['x-vt-send-ticket', 'a'], ['X-VT-Send-Ticket', 'b']), H(h, ['content-type', 'application/json'], ['content-type', 'text/plain'])]) {
    assert.equal(guardOf(() => checkRelayHeaders(twice, 'local')), 'relay.header-repeated')
  }
})

test('refusal messages never echo a header, a ticket, a param or an address', async () => {
  const raw = randomBytes(64)
  const c: Ctx = { network: 'testnet', chain: 'eth', raw: { encoding: 'hex', value: `0x${raw.toString('hex')}` } }
  const syncMessage = (fn: () => unknown): string => { try { fn() } catch (e) { return (e as Error).message } return '' }
  const g = await genuineEth('testnet', { payload: Buffer.from(CANARY) })
  const gc: Ctx = { network: 'testnet', chain: 'eth', raw: { encoding: 'hex', value: `0x${g.raw.toString('hex')}` } }
  const msgs = [
    syncMessage(() => checkRelayHeaders(H(['host', `${CANARY}:5181`]), 'local')),
    syncMessage(() => checkRelayHeaders(H(['host', '127.0.0.1:5181'], ['origin', `http://${CANARY}`]), 'local')),
    await messageOf(checkSend(send(c, `vt-ticket/2.${CANARY}`, NOW))),
    await messageOf(checkSend({ ...send(c, ticketFor({ network: 'testnet', chain: 'eth', raw }).ticket, NOW), params: [`0x${Buffer.from(CANARY).toString('hex')}`] })),
    await messageOf(checkSend(send(c, ticketFor({ network: 'testnet', chain: 'eth', raw }).ticket, NOW, { observedId: CANARY }))),
    await messageOf(checkSend(send(gc, ticketFor({ network: 'testnet', chain: 'eth', raw: g.raw, binding: { ...g.binding, p: 'ab'.repeat(32) } }).ticket, NOW))),   // decode-mismatch, payload = the canary
  ]
  for (const m of msgs) {
    assert.ok(m.length > 0)
    assert.ok(!m.includes(CANARY) && !m.includes(Buffer.from(CANARY).toString('hex')), m)
  }
})

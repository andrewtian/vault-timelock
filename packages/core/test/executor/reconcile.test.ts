// The takeover reconcile (reconcile.ts): chain evidence decides every attempt that may still land before anything new is
// signed; what the chain cannot decide stays open (adopted and watched) or is journaled stuck. Only evidence frees the
// cap (S2 2fea217): reconcile expired / nonce-consumed, or a landing. ALL DATA IS SYNTHETIC; virtual time.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { base58 } from '@scure/base'
import { toHex } from 'viem'
import * as eth from '../../src/chains/eth.js'
import { useRelayClient } from '../../src/engine/rpc.js'
import { reconcileChain } from '../../src/executor/reconcile.ts'
import type { EngineJournal } from '../../src/executor/reconcile.ts'
import type { Chain } from '../../src/contracts/index.ts'
import { CapLedger } from '../../src/gates/caps.ts'
import { createLease } from '../../src/executor/lease.ts'
import { recentBlockhashOf, stack } from './helpers.ts'

const NULL = '0x0000000000000000000000000000000000000000', DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
const GW = 10n ** 9n

// gen 2 wrote the given lines, then died; gen 3 (cli) holds the lease now
async function takeover(s: ReturnType<typeof stack>, chain: Chain, lines: Array<[string, Record<string, unknown>]>) {
  await s.j.client.lease(s.j.id, chain, 'acquire', 'browser')
  for (const [type, data] of lines) s.j.asHolder(2, 'browser', chain, type as never, data)
  s.j.expire(chain)
  const lease = createLease({ journal: s.j.client, jobId: s.j.id, chain, holder: 'cli', clock: s.clock })   // the heartbeat keeps gen 3 alive
  const grant = await lease.acquire()
  const ej: EngineJournal = {
    append: async (ev) => { const { type, chain: c, ...data } = ev; await s.j.client.append(s.j.id, c, grant.gen, type, data) },
    intent: async () => { throw new Error('no intent in a reconcile') },
  }
  useRelayClient(s.relay.client)
  const run = async (o: { rounds?: number; endpoints?: number; alive?: () => boolean; pendingPolls?: number; stopRequested?: () => boolean; detach?: () => boolean } = {}) => {
    try { return await reconcileChain({ chain, state: s.j.state(), grant, journal: ej, clock: s.clock, poll: 1_000, alive: o.alive ?? (() => true), address: s.key.address, network: 'local', solEndpoints: o.endpoints ?? 1, payloadOf: () => new TextEncoder().encode('data:,x'), rounds: o.rounds ?? 3,
      ...(o.pendingPolls !== undefined ? { pendingPolls: o.pendingPolls } : {}), ...(o.stopRequested !== undefined ? { stopRequested: o.stopRequested } : {}), ...(o.detach !== undefined ? { detach: o.detach } : {}) }) } finally { lease.stop() }
  }
  return { grant, ej, run }
}
const ethIntent = (txId: string, nonce: number, attempt = 1, replaces: string | null = null, maxFee = 3n * GW) => ['intent', { txId, copy: 1, part: 1, parts: 1, attempt, replaces, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '1', eth: { nonce, tip: String(GW), maxFee: String(maxFee), gas: '30000', to: NULL } }] as [string, Record<string, unknown>]
async function signed(s: ReturnType<typeof stack>, nonce: number, data: `0x${string}` = '0x646174613a2c78', o: { to?: string; value?: bigint } = {}) {
  const x = o.value !== undefined ? await eth.signClawback(s.key.handle.account, { chainId: 31337, nonce, to: o.to!, value: o.value, maxFee: 3n * GW, tip: GW, gas: 21_000n })
    : await eth.sign(s.key.handle.account, 31337, { nonce, to: NULL, data, gas: 30_000n, maxFee: 3n * GW, tip: GW })
  return { raw: x.raw, id: x.id.toLowerCase() }
}
const mine = (s: ReturnType<typeof stack>) => s.j.events.filter((e) => e.gen === 3 && e.by === 'cli').map((e) => [e.type, e.data.txId, e.data.outcome ?? null])

test('ETH: a receipt of any attempt → reconcile included {block, fee} and its readback; nothing adopted', async () => {
  const s = stack('eth', { startIn: 0 })
  useRelayClient(s.relay.client)
  const a = await signed(s, 0, toHex(new TextEncoder().encode('data:,x')))
  await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [a.raw])
  const t = await takeover(s, 'eth', [ethIntent(a.id, 0)])
  const r = await t.run()
  assert.deepEqual(r, { ok: true, adopted: null, journaled: 2 })
  assert.deepEqual(mine(s), [['reconcile', a.id, 'included'], ['readback', a.id, null]])
  const inc = s.j.events.find((e) => e.type === 'reconcile')!
  assert.match(String(inc.data.fee), /^[1-9][0-9]*$/)
  assert.equal(s.j.state().chains.eth!.txs[0].state, 'included')
})

test('ETH: the nonce not used yet → reconcile adopted for the open attempts (never a rejected one); the lane gets them back, the bump replaces the highest fee', async () => {
  const s = stack('eth', { startIn: 0 })
  const a = await signed(s, 0), b = await signed(s, 0, '0x646174613a2c79')
  const t = await takeover(s, 'eth', [ethIntent(a.id, 0), ['sent', { txId: a.id, outcome: 'rejected', reason: 'x' }], ethIntent(b.id, 0, 2, a.id, 4n * GW)])
  const r = await t.run()
  assert.equal(r.ok, true)
  assert.deepEqual(mine(s), [['reconcile', b.id, 'adopted']], 'the rejected attempt is never adopted (S2 rule)')
  if (!r.ok) return
  assert.equal(r.adopted!.nonce, 0); assert.deepEqual(r.adopted!.attempts.map((x) => x.id), [a.id, b.id], 'the highest fee last: the bump replaces it')
})

test('ETH: the nonce went to a tx this executor never signed → reconcile nonce-consumed for every attempt that may still land (rejected too), then the lane stops (fail closed)', async () => {
  const s = stack('eth', { startIn: 0 })
  useRelayClient(s.relay.client)
  const ours = await signed(s, 0), ours2 = await signed(s, 0, '0x646174613a2c79'), foreign = await signed(s, 0, '0x646174613a2c7a')
  await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [foreign.raw])
  const t = await takeover(s, 'eth', [ethIntent(ours.id, 0), ['sent', { txId: ours.id, outcome: 'rejected', reason: 'nonce too low' }], ethIntent(ours2.id, 0, 2, ours.id, 4n * GW)])
  const r = await t.run()
  assert.equal(r.ok, false); assert.match((r as { why: string }).why, /did not sign/)
  assert.deepEqual(mine(s), [['reconcile', ours.id, 'nonce-consumed'], ['reconcile', ours2.id, 'nonce-consumed']])
  const l = CapLedger.fromArmed(s.j.state(), 'eth', s.key.address); assert.equal(l.held, 0n, 'only evidence freed the hold'); l.close()
})

test('ETH: the nonce is used and an attempt is known but has no receipt (an index lagging) for every round → stuck, the operator resolves', async () => {
  const s = stack('eth', { startIn: 0, eth: (m, p, base) => {
    if (m === 'eth_getTransactionCount' && p[1] === 'latest') return '0x1'
    if (m === 'eth_getTransactionByHash') return { hash: p[0], blockNumber: '0x5' }
    if (m === 'eth_getTransactionReceipt') return null
    return base(m, p)
  } })
  const a = await signed(s, 0)
  const t = await takeover(s, 'eth', [ethIntent(a.id, 0)])
  const r = await t.run({ rounds: 3 })
  assert.equal(r.ok, false)
  assert.deepEqual(mine(s), [['stuck', a.id, null]])
  assert.equal(s.j.state().chains.eth!.phase, 'STUCK')
})

test('SOL: a signature status found → reconcile included (the fee the chain charged) + readback; an expiry proven on every endpoint → reconcile expired', async () => {
  const s = stack('sol', { startIn: 0 })
  useRelayClient(s.relay.client)
  const { Keypair } = await import('@solana/web3.js')
  void Keypair
  // landed: a real signed memo on the fake validator
  const sol = await import('../../src/chains/sol.js')
  const p = await sol.prepare(s.key.handle.kp.publicKey, new TextEncoder().encode('memo'), { priorityLamports: 0, cuPriceCap: 2_000_000 })
  const sg = sol.sign(s.key.handle.kp, p)
  await s.relay.client.rpc('sol', 'sendTransaction', [sg.raw, { encoding: 'base64' }])
  const t = await takeover(s, 'sol', [['intent', { txId: sg.id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '5000', sol: { blockhash: p.blockhash, lastValidBlockHeight: 1_000, cuPrice: 0, cuLimit: p.cuLimit, rung: 0, fee: '5000' } }]])
  const r = await t.run()
  assert.equal(r.ok, true)
  assert.deepEqual(mine(s).map((x) => [x[0], x[2]]), [['reconcile', 'included'], ['readback', null]])
  assert.equal(s.j.events.find((e) => e.type === 'reconcile')!.data.fee, '5000')

  let expired = false
  const old = base58.encode(new Uint8Array(64).fill(42))
  const s2 = stack('sol', { startIn: 0, endpoints: 2, sol: (m, pp, _ep, base) => {
    if (m === 'getLatestBlockhash' && pp[0]?.commitment === 'finalized') return { context: { slot: 900 }, value: { blockhash: base58.encode(new Uint8Array(32).fill(9)), lastValidBlockHeight: (expired ? 1_200 : 900) + 150 } }
    if (m === 'isBlockhashValid' && pp[0] === base58.encode(new Uint8Array(32).fill(3))) return { context: { slot: 900 }, value: !expired }
    if (m === 'getSignatureStatuses') return { context: { slot: 1_000 }, value: (pp[0] as string[]).map(() => null) }
    return base(m, pp)
  } })
  const t2 = await takeover(s2, 'sol', [['intent', { txId: old, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '5000', sol: { blockhash: base58.encode(new Uint8Array(32).fill(3)), lastValidBlockHeight: 1_000, cuPrice: 0, cuLimit: 30_000, rung: 0, fee: '5000' } }]])
  const run = t2.run({ endpoints: 2 })
  for (let i = 0; i < 10; i++) await s2.clock.sleep(1_000)
  assert.equal(mine(s2).length, 0, 'nothing while the blockhash is valid')
  expired = true
  const r2 = await run
  assert.equal(r2.ok, true)
  assert.deepEqual(mine(s2), [['reconcile', old, 'expired']])
  assert.ok(s2.relay.calls.some((c) => c.ep === 1), 'both endpoints proved it')
})

test('ETH claw-back members: one landed → clawback-included (the chain\'s value and fee) + readback; one landed with status 0 → clawback-failed {fee} then every member reconciled nonce-consumed', async () => {
  for (const status of ['0x1', '0x0']) {
    let landedId = ''
    const s = stack('eth', { startIn: 0, eth: (m, p, base) => {
      if (m === 'eth_getTransactionReceipt' && p[0] === landedId) { const r = base(m, p) as Record<string, string>; return r ? { ...r, status } : r }
      return base(m, p)
    } })
    useRelayClient(s.relay.client)
    const c1 = await signed(s, 0, '0x', { to: DEST, value: 10n ** 15n }), c2 = await signed(s, 0, '0x', { to: DEST, value: 10n ** 15n - 1n })
    await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [c1.raw])
    landedId = c1.id
    const claw = (id: string, value: bigint) => ['clawback-intent', { txId: id, to: DEST, value: String(value), rawSha256: 'ab'.repeat(32), eth: { nonce: 0, tip: String(GW), maxFee: String(3n * GW), gas: '21000', to: DEST } }] as [string, Record<string, unknown>]
    const t = await takeover(s, 'eth', [['drained', { balance: '1', nextCost: '9', copy: 1 }], claw(c1.id, 10n ** 15n), claw(c2.id, 10n ** 15n - 1n)])
    const r = await t.run()
    assert.equal(r.ok, true, status)
    const cs = s.j.state().chains.eth!
    if (status === '0x1') {
      assert.deepEqual(mine(s).map((x) => [x[0], x[1]]), [['clawback-included', c1.id], ['clawback-readback', c1.id]])
      assert.deepEqual([cs.phase, cs.clawback!.landed, cs.clawback!.txId, cs.clawback!.value], ['CLAWED_BACK', true, c1.id, String(10n ** 15n)])
    } else {
      assert.deepEqual(mine(s), [['clawback-failed', c1.id, null], ['reconcile', c1.id, 'nonce-consumed'], ['reconcile', c2.id, 'nonce-consumed']])
      assert.deepEqual([cs.phase, cs.clawback!.ok, cs.clawback!.landed, cs.openIntents], ['DRAINED', false, false, []])
    }
  }
})

test('ETH: chain evidence over a claim — an attempt journaled `sent rejected` whose receipt exists is reconciled included (every attempt is checked, not only the open ones)', async () => {
  const s = stack('eth', { startIn: 0 })
  useRelayClient(s.relay.client)
  const a = await signed(s, 0, toHex(new TextEncoder().encode('data:,x'))), b = await signed(s, 0, '0x646174613a2c79')
  await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [a.raw])          // the "rejected" one reached a block anyway
  const t = await takeover(s, 'eth', [ethIntent(a.id, 0), ['sent', { txId: a.id, outcome: 'rejected', reason: 'timeout at the relay' }], ethIntent(b.id, 0, 2, a.id, 4n * GW)])
  const r = await t.run()
  assert.deepEqual(r, { ok: true, adopted: null, journaled: 2 })
  assert.deepEqual(mine(s), [['reconcile', a.id, 'included'], ['readback', a.id, null]])
  assert.equal(s.j.state().chains.eth!.txs[0].landedId, a.id)
})

const memoIntent = (txId: string, blockhash: string, cuLimit: number) => ['intent', { txId, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '5000', sol: { blockhash, lastValidBlockHeight: 1_000, cuPrice: 0, cuLimit, rung: 0, fee: '5000' } }] as [string, Record<string, unknown>]

test('SOL: a signature only `processed` is not landed (it may be on a dropped fork): nothing is journaled until it is confirmed, then reconcile included', async () => {
  let confirmed = false
  const s = stack('sol', { startIn: 0, sol: (m, pp, _ep, base) => {
    if (m === 'getSignatureStatuses' && !confirmed) { const r = base(m, pp) as { context: unknown; value: Array<Record<string, unknown> | null> }; return { ...r, value: r.value.map((x) => (x === null ? null : { ...x, confirmationStatus: 'processed' })) } }
    return base(m, pp)
  } })
  useRelayClient(s.relay.client)
  const sol = await import('../../src/chains/sol.js')
  const p = await sol.prepare(s.key.handle.kp.publicKey, new TextEncoder().encode('data:,x'), { priorityLamports: 0, cuPriceCap: 2_000_000 })
  const sg = sol.sign(s.key.handle.kp, p)
  await s.relay.client.rpc('sol', 'sendTransaction', [sg.raw, { encoding: 'base64' }])
  const t = await takeover(s, 'sol', [memoIntent(sg.id, p.blockhash, p.cuLimit)])
  const run = t.run()
  for (let i = 0; i < 20; i++) await s.clock.sleep(1_000)
  assert.deepEqual(mine(s), [], 'processed is not evidence: nothing journaled, nothing re-signed')
  confirmed = true
  const r = await run
  assert.equal(r.ok, true)
  assert.deepEqual(mine(s).map((x) => [x[0], x[2]]), [['reconcile', 'included'], ['readback', null]])
})

test('SOL: the lease lost while the expiry is being proven → the reconcile stops, and NO expired is journaled without the proof', async () => {
  const old = base58.encode(new Uint8Array(64).fill(43))
  const s = stack('sol', { startIn: 0, endpoints: 2, sol: (m, pp, _ep, base) => {
    if (m === 'getSignatureStatuses') return { context: { slot: 1_000 }, value: (pp[0] as string[]).map(() => null) }
    return base(m, pp)
  } })
  const t = await takeover(s, 'sol', [memoIntent(old, base58.encode(new Uint8Array(32).fill(3)), 30_000)])
  const until = s.clock.now() + 6_000
  const r = await t.run({ endpoints: 2, alive: () => s.clock.now() < until })
  assert.equal(r.ok, false); assert.match((r as { why: string }).why, /lease was lost/)
  assert.deepEqual(mine(s), [], 'no reconcile expired')
  assert.deepEqual(s.j.state().chains.sol!.openIntents, [old], 'still open: the next holder reconciles it')
})

test('SOL: a DECLARED lastValidBlockHeight is not evidence (the relay binds the blockhash, not the height): while the blockhash is still in the queue, nothing expires — on every endpoint it must be gone', async () => {
  let gone: boolean[] = [false, false]
  const oldBh = base58.encode(new Uint8Array(32).fill(5)), old = base58.encode(new Uint8Array(64).fill(44))
  const asked = new Set<number | null>()
  const s = stack('sol', { startIn: 0, endpoints: 2, sol: (m, pp, ep, base) => {
    if (m === 'getSignatureStatuses') return { context: { slot: 1_000 }, value: (pp[0] as string[]).map(() => null) }
    if (m === 'isBlockhashValid' && pp[0] === oldBh) { asked.add(ep); return { context: { slot: 900 }, value: !gone[ep ?? 0] } }
    return base(m, pp)
  } })
  // the earlier holder declared lastValidBlockHeight 100: the finalized height (850) is far past it
  const t = await takeover(s, 'sol', [['intent', { txId: old, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '5000', sol: { blockhash: oldBh, lastValidBlockHeight: 100, cuPrice: 0, cuLimit: 30_000, rung: 0, fee: '5000' } }]])
  const run = t.run({ endpoints: 2 })
  for (let i = 0; i < 20; i++) await s.clock.sleep(1_000)
  assert.deepEqual(mine(s), [], 'the declared height alone never proves expiry')
  gone = [true, false]
  for (let i = 0; i < 20; i++) await s.clock.sleep(1_000)
  assert.deepEqual(mine(s), [], 'gone on ONE endpoint is not enough')
  gone = [true, true]
  const r = await run
  assert.equal(r.ok, true)
  assert.deepEqual(mine(s), [['reconcile', old, 'expired']])
  assert.deepEqual([...asked].sort(), [0, 1, null], 'both endpoints (and the preferred route, for the rebroadcast gate) were asked about the blockhash')
})

test('Efix3 m-A: an ADOPTED attempt (no fetch slot): a validity answer from a bank older than the finalized bank is no proof; the same answer from a bank at the finalized slot is', async () => {
  let validSlot = 850
  const oldBh = base58.encode(new Uint8Array(32).fill(5)), old = base58.encode(new Uint8Array(64).fill(47))
  const s = stack('sol', { startIn: 0, endpoints: 1, sol: (m, pp, _ep, base) => {
    if (m === 'getLatestBlockhash' && pp[0]?.commitment === 'finalized') return { context: { slot: 900 }, value: { blockhash: base58.encode(new Uint8Array(32).fill(9)), lastValidBlockHeight: 2_150 } }   // finalized slot 900, height past
    if (m === 'getSignatureStatuses') return { context: { slot: 1_000 }, value: (pp[0] as string[]).map(() => null) }     // the history is fresh and clean
    if (m === 'isBlockhashValid' && pp[0] === oldBh) return { context: { slot: validSlot }, value: false }
    return base(m, pp)
  } })
  const t = await takeover(s, 'sol', [['intent', { txId: old, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '5000', sol: { blockhash: oldBh, lastValidBlockHeight: 100, cuPrice: 0, cuLimit: 30_000, rung: 0, fee: '5000' } }]])
  const run = t.run({ endpoints: 1 })
  for (let i = 0; i < 20; i++) await s.clock.sleep(1_000)
  assert.deepEqual(mine(s), [], 'validity slot 850 < finalized slot 900: no proof')
  validSlot = 900
  const r = await run
  assert.equal(r.ok, true)
  assert.deepEqual(mine(s), [['reconcile', old, 'expired']])
})

test('I-1: a garbled history answer (null value, [], missing context) on the takeover reconcile is NOT "absent": no reconcile expired, on 1 and on 2 endpoints', { timeout: 120_000 }, async () => {
  const garbles: Array<(ids: string[]) => unknown> = [() => ({ context: { slot: 1_000 }, value: null }), () => ({ context: { slot: 1_000 }, value: [] }), (ids) => ({ value: ids.map(() => null) })]
  for (const [gi, g] of garbles.entries()) for (const endpoints of [1, 2]) {
    const oldBh = base58.encode(new Uint8Array(32).fill(5)), old = base58.encode(new Uint8Array(64).fill(44 + gi))
    const s = stack('sol', { startIn: 0, endpoints, sol: (m, pp, _ep, base) => {
      if (m === 'getSignatureStatuses') return g(pp[0] as string[])
      if (m === 'isBlockhashValid' && pp[0] === oldBh) return { context: { slot: 900 }, value: false }   // an aged-out blockhash: true for a tx that LANDED too
      return base(m, pp)
    } })
    const t = await takeover(s, 'sol', [['intent', { txId: old, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '5000', sol: { blockhash: oldBh, lastValidBlockHeight: 100, cuPrice: 0, cuLimit: 30_000, rung: 0, fee: '5000' } }]])
    const run = t.run({ endpoints }).then((r) => r, () => ({ ok: false }))
    for (let i = 0; i < 20; i++) await s.clock.sleep(1_000)
    assert.deepEqual(mine(s), [], `garble ${gi} endpoints ${endpoints}: no reconcile expired`)
    assert.deepEqual(s.j.state().chains.sol!.openIntents, [old])
    s.j.expire('sol'); void run
  }
})

test('m-2: a pending ETH claw-back at takeover is watched for a bounded time, then journaled stuck with the exit named; a Stop ends the wait', async () => {
  for (const how of ['bounded', 'stop'] as const) {
    const s = stack('eth', { startIn: 0, eth: (m, p, base) => (m === 'eth_getTransactionReceipt' ? null : base(m, p)) })
    useRelayClient(s.relay.client)
    const c = await signed(s, 0, '0x', { to: DEST, value: 10n ** 15n })
    const t = await takeover(s, 'eth', [['drained', { balance: '1', nextCost: '9', copy: 1 }], ['clawback-intent', { txId: c.id, to: DEST, value: String(10n ** 15n), rawSha256: 'ab'.repeat(32), eth: { nonce: 0, tip: String(GW), maxFee: String(3n * GW), gas: '21000', to: DEST } }]])
    let polls = 0
    const r = await t.run({ pendingPolls: 5, stopRequested: () => how === 'stop' && ++polls > 2 })
    assert.equal(r.ok, false)
    if (how === 'bounded') {
      assert.deepEqual(mine(s).map((x) => [x[0], x[1]]), [['reconcile', c.id], ['stuck', c.id]])
      assert.match(String(s.j.events.at(-1)!.data.reason), /still pending.*mark-failed.*claw back again/)
    } else {
      assert.match((r as { why: string }).why, /^stopped while watching/)
      assert.deepEqual(mine(s).map((x) => x[0]), ['reconcile'], 'adopted, then the Stop: nothing else journaled')
    }
  }
})

test('I-2 defence in depth (SOL): a part whose attempts were all journaled dead is re-checked on EVERY endpoint before it can be signed again — a landing seen by one endpoint is recorded', async () => {
  const sol = await import('../../src/chains/sol.js')
  let sigSeenBy1 = ''
  const s = stack('sol', { startIn: 0, endpoints: 2, sol: (m, pp, ep, base) => {
    if (m === 'getSignatureStatuses') { const r = base(m, pp) as { context: unknown; value: unknown[] }; return { ...r, value: (pp[0] as string[]).map((x, i) => (x === sigSeenBy1 && ep !== 1 ? null : r.value[i])) } }   // only endpoint 1 has it
    return base(m, pp)
  } })
  useRelayClient(s.relay.client)
  const p = await sol.prepare(s.key.handle.kp.publicKey, new TextEncoder().encode('data:,x'), { priorityLamports: 0, cuPriceCap: 2_000_000 })
  const sg = sol.sign(s.key.handle.kp, p)
  await s.relay.client.rpc('sol', 'sendTransaction', [sg.raw, { encoding: 'base64' }])
  sigSeenBy1 = sg.id
  const t = await takeover(s, 'sol', [memoIntent(sg.id, p.blockhash, p.cuLimit), ['reconcile', { txId: sg.id, outcome: 'expired' }]])
  assert.equal(s.j.state().chains.sol!.txs[0].state, 'failed')
  const r = await t.run({ endpoints: 2 })
  assert.equal(r.ok, true)
  assert.deepEqual(mine(s).map((x) => [x[0], x[2]]), [['reconcile', 'included'], ['readback', null]])
  assert.equal(s.j.state().chains.sol!.txs[0].state, 'included')
})

test('ETH: attempts of one part that declare different nonces are refused (fail closed), nothing journaled', async () => {
  const s = stack('eth', { startIn: 0 })
  const a = await signed(s, 0), b = await signed(s, 1, '0x646174613a2c79')
  const t = await takeover(s, 'eth', [ethIntent(a.id, 0), ethIntent(b.id, 1, 2, a.id, 4n * GW)])
  const r = await t.run()
  assert.equal(r.ok, false); assert.match((r as { why: string }).why, /different nonces/)
  assert.deepEqual(mine(s), [])
})

test('ETH positive evidence on a longer chain: the tx at the journaled nonce is found by the block search (back-off + binary search) and named when it is not ours', async () => {
  const s = stack('eth', { startIn: 0 })
  useRelayClient(s.relay.client)
  const foreign: string[] = []
  for (let k = 0; k < 10; k++) { const x = await signed(s, k, toHex(new TextEncoder().encode(`data:,other ${k}`))); foreign.push(x.id); await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [x.raw]) }   // nonces 0..9 in blocks 101..110
  const ours = await signed(s, 3, toHex(new TextEncoder().encode('data:,ours')))
  const t = await takeover(s, 'eth', [ethIntent(ours.id, 3)])
  const r = await t.run()
  assert.equal(r.ok, false)
  assert.ok((r as { why: string }).why.includes(foreign[3]), 'the tx that took nonce 3 is named')
  assert.match((r as { why: string }).why, /block 104/)
  assert.deepEqual(mine(s), [['reconcile', ours.id, 'nonce-consumed']])
})

test('PF-E fix round 2 (M-4): a takeover reconcile of a SOL attempt after a Stop, with one verified endpoint failing its reads, ends in bounded time: stuck with the reason, nothing proven expired', async () => {
  const sol = await import('../../src/chains/sol.js')
  const { CANON } = await import('../../src/chains/constants.js')
  void sol
  const s = stack('sol', { startIn: 0, endpoints: 2, sol: (m, p, ep, base) => {
    if (m === 'getSignatureStatuses') return { context: { slot: 2_000 }, value: (p[0] as string[]).map(() => null) }
    if (m === 'isBlockhashValid') { if (ep === 1) throw new Error('endpoint 1 unreachable (test)'); return { context: { slot: 2_000 }, value: false } }
    if (m === 'getLatestBlockhash' && p[0]?.commitment === 'finalized') { const r = base(m, p) as { context: unknown; value: { lastValidBlockHeight: number } }; return { ...r, context: { slot: 1_900 }, value: { ...r.value, lastValidBlockHeight: 2_100 } } }
    return base(m, p)
  } })
  const sig = base58.encode(new Uint8Array(64).fill(9)), bh = base58.encode(new Uint8Array(32).fill(4))
  const t = await takeover(s, 'sol', [['intent', { txId: sig, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '5000', sol: { blockhash: bh, lastValidBlockHeight: 1_000, cuPrice: 0, cuLimit: 30_000, rung: 0, fee: '5000' } }]])
  const t0 = s.clock.now()
  const r = await t.run({ endpoints: 2, stopRequested: () => true })
  assert.equal(r.ok, false)
  assert.ok(s.clock.now() - t0 <= CANON.SOL_STOP_PROOF_MS + 30_000, `bounded (${s.clock.now() - t0} ms)`)
  assert.deepEqual(mine(s).map((x) => [x[0], x[1]]), [['stuck', sig]], 'stuck, never reconcile expired')
  assert.match(String(s.j.events.at(-1)!.data.reason), /neither confirmed nor proven expired on every verified endpoint/)
  // R79: the same wait under a DETACH (requestStop alone) is bounded too, and escalates nothing
  const u = stack('sol', { startIn: 0, endpoints: 2, sol: (m, p, ep, base) => {
    if (m === 'getSignatureStatuses') return { context: { slot: 2_000 }, value: (p[0] as string[]).map(() => null) }
    if (m === 'isBlockhashValid') { if (ep === 1) throw new Error('endpoint 1 unreachable (test)'); return { context: { slot: 2_000 }, value: false } }
    if (m === 'getLatestBlockhash' && p[0]?.commitment === 'finalized') { const r = base(m, p) as { context: unknown; value: { lastValidBlockHeight: number } }; return { ...r, context: { slot: 1_900 }, value: { ...r.value, lastValidBlockHeight: 2_100 } } }
    return base(m, p)
  } })
  const t2 = await takeover(u, 'sol', [['intent', { txId: sig, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '5000', sol: { blockhash: bh, lastValidBlockHeight: 1_000, cuPrice: 0, cuLimit: 30_000, rung: 0, fee: '5000' } }]])
  const r2 = await t2.run({ endpoints: 2, stopRequested: () => true, detach: () => true })
  assert.equal(r2.ok, false)
  assert.deepEqual(mine(u), [], 'a detach journals nothing')
})

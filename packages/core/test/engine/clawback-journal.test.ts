// Claw-back journal integrity (security review on a6e1493/dbb0ef0): the journal never claims a claw-back outcome the chain
// has not proven. Any member of the ETH bump family that lands settles the claw-back, with that txId and the chain's
// value and fee; ambiguous outcomes stay open, so a takeover reconciles first and never sends a second claw-back; the
// cap ledger reserves value + fee and counts the fee of a claw-back that failed on chain. ALL DATA IS SYNTHETIC; the
// relay is a fake fetch, nothing is broadcast anywhere.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { base58, base64 } from '@scure/base'
import { Keypair, VersionedTransaction } from '@solana/web3.js'
import { keccak256, parseTransaction } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { clawbackEth, clawbackSol } from '../../src/engine/lane.js'
import { CapLedger } from '../../src/gates/caps.ts'
import { reduce } from '../../src/job/index.ts'
import type { JobDef } from '../../src/contracts/index.ts'
import { guardOf, readJson } from '../job/helpers.ts'
import { armedEvent, armedState, asJournal, fakeClock, fakeRelay, fakeSolChain, recordingJournal } from './fakes.ts'
import type { Ev } from './fakes.ts'

const ETH_DEF = readJson<JobDef>('journals/01-created.def.json')            // eth only
const BOTH_DEF = readJson<JobDef>('journals/15a-skipped.def.json')         // eth + sol
const DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
const CAP = 10n ** 18n, LANE = 10n ** 16n
const hx = (n: bigint | number): string => `0x${BigInt(n).toString(16)}`
const stopped: Ev = { type: 'stopped', chain: 'eth', reason: 'operator' }
const ethState = (evs: Ev[]) => reduce(ETH_DEF, asJournal([armedEvent(['eth'], CAP)], [stopped, ...evs]))
const guardIdOf = (e: unknown): string | undefined => (e as { guardId?: string }).guardId

// A fake Ethereum for one claw-back: blocks advance on every eth_blockNumber; o.land(sent) names the sent index that has
// a receipt (or null); o.status is that receipt's status; o.nonceAfterSend makes the nonce used by an invisible tx.
function clawChain(o: { land?: (sent: string[]) => number | null; status?: string; reject?: (n: number) => string | null; nonceAfterSend?: boolean } = {}) {
  let block = 10
  const sent: string[] = []
  const byHash = (h: string): string | undefined => sent.find((r) => keccak256(r as `0x${string}`) === h)
  const handler = (m: string, p: any[]): unknown => {
    switch (m) {
      case 'eth_getTransactionCount': return String(p[0]).toLowerCase() === DEST.toLowerCase() ? '0x3' : o.nonceAfterSend && sent.length ? '0x1' : '0x0'
      case 'eth_getBalance': return String(p[0]).toLowerCase() === DEST.toLowerCase() ? '0x5' : hx(LANE)
      case 'eth_getCode': return '0x'
      case 'eth_feeHistory': { const n = Number(BigInt(p[0])); return { oldestBlock: hx(block - n + 1), baseFeePerGas: Array.from({ length: n + 1 }, () => hx(10n ** 9n)), reward: Array.from({ length: n }, () => [hx(10n ** 9n)]) } }
      case 'eth_estimateGas': return hx(21_000)
      case 'eth_blockNumber': return hx(block++)
      case 'eth_sendRawTransaction': {
        const why = o.reject?.(sent.length + 1) ?? null
        if (why) throw new Error(why)
        sent.push(String(p[0])); return keccak256(p[0] as `0x${string}`)
      }
      case 'eth_getTransactionReceipt': {
        const i = o.land?.(sent) ?? null, raw = i === null ? undefined : sent[i]
        return raw && keccak256(raw as `0x${string}`) === p[0] ? { transactionHash: p[0], blockNumber: hx(block), gasUsed: hx(21_000), effectiveGasPrice: hx(2n * 10n ** 9n), status: o.status ?? '0x1' } : null
      }
      case 'eth_getTransactionByHash': { const raw = byHash(String(p[0])); if (!raw) return null; const t = parseTransaction(raw as `0x${string}`); return { hash: p[0], to: t.to, value: hx(t.value ?? 0n), input: '0x', blockNumber: hx(block) } }
      default: return undefined
    }
  }
  return { handler, sent }
}
const run = (chain: ReturnType<typeof clawChain>, state = armedState('eth', CAP)) => {
  const relay = fakeRelay({ eth: chain.handler }), { journal, events } = recordingJournal()
  const key = { account: privateKeyToAccount(generatePrivateKey()) }
  return { relay, events, key, go: (st = state) => clawbackEth(key, DEST, { journal, network: 'local', chainId: 31337, poll: 1, state: st }) }
}

test('ETH bump family: the FIRST attempt lands after a bump was sent — clawback-included names it, with the chain\'s value and fee', { timeout: 30_000 }, async () => {
  const chain = clawChain({ land: (sent) => (sent.length >= 2 ? 0 : null) })
  const r = run(chain)
  const res = await r.go()
  const intents = r.events.filter((e) => e.type === 'clawback-intent')
  assert.equal(intents.length, 2, 'one bump was sent before the first attempt landed')
  const [A, B] = intents
  assert.notEqual(A.value, B.value, 'the two members carry different values')
  const inc = r.events.find((e) => e.type === 'clawback-included')!
  assert.equal(inc.txId, A.txId, 'the member that landed, not the latest bump')
  assert.equal(inc.value, A.value, 'its value as the chain recorded it')
  assert.equal(inc.fee, String(21_000n * 2n * 10n ** 9n), 'its fee from the receipt')
  const rb = r.events.find((e) => e.type === 'clawback-readback')!
  assert.equal(rb.txId, A.txId); assert.equal(rb.destReceived, A.value); assert.equal(rb.laneBalance, String(LANE), 'the measured lane balance')
  assert.equal(res.id, A.txId)
  // the reducer settles from that earlier member although a later bump exists
  const st = ethState(r.events).chains.eth!
  assert.equal(st.phase, 'CLAWED_BACK'); assert.equal(st.clawback!.txId, A.txId); assert.equal(st.clawback!.value, A.value)
  assert.deepEqual(st.openIntents, []); assert.equal(st.spent, String(21_000n * 2n * 10n ** 9n))
})

test('reducer: the family stays open until a member lands; a reconcile closes one member only; fees count once', () => {
  const H = 'ab'.repeat(32), A = `0x${'a'.repeat(64)}`, B = `0x${'b'.repeat(64)}`
  const intent = (txId: string, value: string): Ev => ({ type: 'clawback-intent', chain: 'eth', txId, to: DEST, value, rawSha256: H, eth: { nonce: 1, tip: '1', maxFee: '2', gas: '21000', to: DEST } })
  let st = ethState([intent(A, '900'), intent(B, '800')]).chains.eth!
  assert.equal(st.phase, 'CLAWING_BACK'); assert.deepEqual(st.openIntents, [A, B]); assert.equal(st.clawback!.txId, B)
  st = ethState([intent(A, '900'), intent(B, '800'), { type: 'reconcile', chain: 'eth', txId: B, outcome: 'nonce-consumed' }]).chains.eth!
  assert.deepEqual(st.openIntents, [A], 'B closed, A still open')
  st = ethState([intent(A, '900'), intent(B, '800'), { type: 'clawback-included', chain: 'eth', txId: A, value: '900', fee: '7' }, { type: 'clawback-included', chain: 'eth', txId: A, value: '900', fee: '7' },
    { type: 'clawback-failed', chain: 'eth', txId: B, reason: 'late' }]).chains.eth!
  assert.equal(st.phase, 'CLAWED_BACK'); assert.equal(st.clawback!.txId, A); assert.equal(st.clawback!.ok, true); assert.equal(st.spent, '7', 'once; a later failed of another member changes nothing')
  st = ethState([intent(A, '900'), { type: 'clawback-failed', chain: 'eth', txId: A, reason: 'landed with an error', fee: '5' }]).chains.eth!
  assert.equal(st.phase, 'STOPPED'); assert.equal(st.clawback!.ok, false); assert.equal(st.spent, '5', 'the fee of a failed-on-chain claw-back is spent')
  const failedTwice = ethState([intent(A, '900'), { type: 'clawback-failed', chain: 'eth', txId: A, reason: 'x', fee: '5' }, { type: 'clawback-failed', chain: 'eth', txId: A, reason: 'x', fee: '5' }])
  assert.equal(failedTwice.chains.eth!.spent, '5', 'a failed fee journaled twice is spent once')
})

test('ledger: a claw-back in progress refuses a new ledger even when its latest member is closed and an earlier one is open', () => {
  const H = 'ab'.repeat(32), A = `0x${'a'.repeat(64)}`, B = `0x${'b'.repeat(64)}`
  const intent = (txId: string): Ev => ({ type: 'clawback-intent', chain: 'eth', txId, to: DEST, value: '1', rawSha256: H, eth: { nonce: 1, tip: '1', maxFee: '2', gas: '21000', to: DEST } })
  const state = ethState([intent(A), intent(B), { type: 'reconcile', chain: 'eth', txId: B, outcome: 'nonce-consumed' }])
  assert.equal(state.chains.eth!.clawback!.txId, B); assert.deepEqual(state.chains.eth!.openIntents, [A])
  assert.equal(guardOf(() => CapLedger.fromArmed(state, 'eth', 'claw-earlier-open')), 'engine.cap-armed')
})

test('ETH claw-back landed with an error: clawback-failed with the fee charged; the ledger and the journal count it', { timeout: 30_000 }, async () => {
  const chain = clawChain({ land: (sent) => (sent.length ? 0 : null), status: '0x0' })
  const r = run(chain)
  await assert.rejects(r.go(), /landed with an error/)
  const failed = r.events.find((e) => e.type === 'clawback-failed')!
  assert.equal(failed.fee, String(21_000n * 2n * 10n ** 9n))
  assert.equal(r.events.some((e) => e.type === 'clawback-included'), false, 'never claimed as included')
  const st = ethState(r.events).chains.eth!
  assert.equal(st.phase, 'STOPPED'); assert.equal(st.spent, failed.fee); assert.equal(st.clawback!.ok, false)
  const l = CapLedger.fromArmed(ethState(r.events), 'eth', 'after-failed'); assert.equal(l.spent, BigInt(failed.fee as string)); l.close()
})

test('ETH claw-back: the FIRST member lands with an error after a bump was sent → clawback-failed (its fee) and the bump reconciled nonce-consumed: the family failed, nothing open', { timeout: 30_000 }, async () => {
  const chain = clawChain({ land: (sent) => (sent.length >= 2 ? 0 : null), status: '0x0' })
  const r = run(chain)
  await assert.rejects(r.go(), /landed with an error/)
  const ids = r.events.filter((e) => e.type === 'clawback-intent').map((e) => e.txId)
  assert.equal(ids.length, 2)
  assert.deepEqual(r.events.slice(-3).map((e) => [e.type, e.txId, e.outcome ?? null]), [['clawback-failed', ids[0], null], ['reconcile', ids[0], 'nonce-consumed'], ['reconcile', ids[1], 'nonce-consumed']])
  const st = ethState(r.events).chains.eth!
  assert.deepEqual([st.phase, st.openIntents, st.clawback!.ok, st.clawback!.landed], ['STOPPED', [], false, false])
  const l = CapLedger.fromArmed(ethState(r.events), 'eth', 'claw-first-failed'); assert.deepEqual([l.idle, l.spent], [true, 21_000n * 2n * 10n ** 9n]); l.close()
})

test('ETH: the nonce is used but no receipt of ours shows up → stuck, open; a takeover is refused (never a second claw-back)', { timeout: 30_000 }, async () => {
  const chain = clawChain({ nonceAfterSend: true })
  const r = run(chain)
  await assert.rejects(r.go(), /stuck/)
  assert.deepEqual(r.events.map((e) => e.type), ['clawback-intent', 'clawback-sent', 'stuck'])
  const state = ethState(r.events)
  assert.equal(state.chains.eth!.phase, 'STUCK'); assert.equal(state.chains.eth!.openIntents.length, 1); assert.equal(state.chains.eth!.clawback!.ok, null)
  const before = r.relay.sends().length
  await assert.rejects(r.go(state), (e) => guardIdOf(e) === 'engine.cap-armed', 'reconcile the open claw-back first')
  assert.equal(r.relay.sends().length, before, 'nothing sent by the takeover')
})

test('ETH: the first attempt rejected for a used nonce is provably dead (no attempt of ours exists) → reconcile nonce-consumed (the family fails by itself); a bump rejected so is not', { timeout: 30_000 }, async () => {
  const first = run(clawChain({ reject: (n) => (n === 1 ? 'nonce too low' : null) }))
  await assert.rejects(first.go(), /nonce too low/)
  assert.deepEqual(first.events.map((e) => [e.type, e.outcome ?? null]), [['clawback-intent', null], ['clawback-sent', 'rejected'], ['reconcile', 'nonce-consumed']])
  const st0 = ethState(first.events).chains.eth!
  assert.deepEqual([st0.phase, st0.clawback!.ok, st0.openIntents], ['STOPPED', false, []], 'every member dead: failed by itself (S2 2fea217: only evidence frees the cap)')
  // a bump rejected "nonce too low": an earlier member may have taken the nonce — its receipt shows up, so it settles the family
  let rejected = false
  const r = run(clawChain({ reject: (n) => (n === 2 ? ((rejected = true), 'nonce too low') : null), land: () => (rejected ? 0 : null) }))
  const res = await r.go()
  const intents = r.events.filter((e) => e.type === 'clawback-intent')
  assert.equal(intents.length, 2)
  assert.deepEqual(r.events.filter((e) => e.type === 'clawback-sent').map((e) => e.outcome), ['accepted', 'rejected'])
  assert.equal(res.id, intents[0].txId, 'the first member settled the family')
  assert.equal(r.events.some((e) => e.type === 'clawback-failed'), false, 'a rejected bump never fails the family')
  assert.equal(ethState(r.events).chains.eth!.phase, 'CLAWED_BACK')
})

test('ETH: a non-dead rejection and "max bumps" leave the claw-back open (no clawback-failed); the ledger reserved value + fee', { timeout: 30_000 }, async () => {
  const r = run(clawChain({ reject: () => 'replacement transaction underpriced' }))
  await assert.rejects(r.go(), /stays open/)
  assert.deepEqual(r.events.map((e) => [e.type, e.outcome ?? null]), [['clawback-intent', null], ['clawback-sent', 'unknown']])
  const state = ethState(r.events)
  assert.equal(state.chains.eth!.clawback!.ok, null); assert.equal(state.chains.eth!.openIntents.length, 1)
  assert.equal(guardOf(() => CapLedger.fromArmed(state, 'eth', 'open-claw')), 'engine.cap-armed')
  const never = run(clawChain())                                         // never mined, never answered otherwise
  await assert.rejects(never.go(), /maximum bumps — still open/)
  assert.equal(never.events.some((e) => e.type === 'clawback-failed'), false)
  assert.equal(ethState(never.events).chains.eth!.openIntents.length, never.events.filter((e) => e.type === 'clawback-intent').length, 'every member open')
})

// ---- SOL ----
// SOL fake for a claw-back: the transfer's own record (pre/post balances) can differ from the plan; o.err = landed with an error.
function solClaw(o: { err?: unknown; received?: (planned: bigint) => bigint } = {}) {
  const base = fakeSolChain(), sent = new Map<string, Uint8Array>()
  const handler = (m: string, p: any[]): unknown => {
    if (m === 'sendTransaction') { const raw = base64.decode(String(p[0])), sig = base58.encode(VersionedTransaction.deserialize(raw).signatures[0]); sent.set(sig, raw); return sig }
    if (m === 'getSignatureStatuses') return { context: { slot: 600 }, value: (p[0] as string[]).map((s) => (sent.has(s) ? { slot: 501, confirmations: 1, err: o.err ?? null, confirmationStatus: 'confirmed' } : null)) }
    if (m === 'getTransaction') {
      const raw = sent.get(String(p[0])); if (!raw) return null
      const msg = VersionedTransaction.deserialize(raw).message, keys = msg.staticAccountKeys.map((k) => k.toBase58())
      const lamports = new DataView(msg.compiledInstructions[0].data.buffer, msg.compiledInstructions[0].data.byteOffset).getBigUint64(4, true)
      const got = o.err ? 0n : (o.received ? o.received(lamports) : lamports)
      return { slot: 501, meta: { err: o.err ?? null, fee: 5000, preBalances: keys.map(() => 1_000), postBalances: keys.map((_k, i) => (i === 1 ? 1_000 + Number(got) : 1_000)) }, transaction: { message: { accountKeys: keys } } }
    }
    return base.handler(m, p)
  }
  return { handler, sent }
}
const solRun = (chain: ReturnType<typeof solClaw>, st?: unknown) => {
  const relay = fakeRelay({ sol: chain.handler }), { journal, events } = recordingJournal()
  const kp = Keypair.generate(), dest = Keypair.generate().publicKey.toBase58()
  return { relay, events, go: (s = st ?? armedState('sol', 10n ** 12n)) => clawbackSol({ chain: 'sol', kp }, dest, { journal, network: 'local', poll: 1, alive: () => true, notify: async () => {}, state: s }) }
}
const solState = (evs: Ev[]) => reduce(BOTH_DEF, asJournal([armedEvent(['sol'], 10n ** 12n)], [{ type: 'stopped', chain: 'sol', reason: 'operator' }, ...evs]))

test('SOL claw-back landed with an error: clawback-failed with the fee charged (counted in spent and by the ledger)', { timeout: 30_000 }, async () => {
  const r = solRun(solClaw({ err: { InstructionError: [0, 'Custom'] } }))
  await assert.rejects(r.go(), /landed with an error/)
  const failed = r.events.find((e) => e.type === 'clawback-failed')!
  assert.equal(failed.fee, '5000')
  assert.equal(r.events.some((e) => e.type === 'clawback-included'), false)
  const st = solState(r.events)
  assert.equal(st.chains.sol!.spent, '5000'); assert.equal(st.chains.sol!.phase, 'STOPPED')
  const l = CapLedger.fromArmed(st, 'sol', 'sol-failed'); assert.equal(l.spent, 5000n); l.close()
})

test('SOL claw-back: clawback-included carries what the chain recorded the destination received, not the plan', { timeout: 30_000 }, async () => {
  const r = solRun(solClaw({ received: (planned) => planned - 7n }))
  const res = await r.go()
  const intent = r.events.find((e) => e.type === 'clawback-intent')!, inc = r.events.find((e) => e.type === 'clawback-included')!
  assert.equal(inc.value, String(BigInt(intent.value as string) - 7n)); assert.equal(inc.fee, '5000')
  const rb = r.events.find((e) => e.type === 'clawback-readback')!
  assert.equal(rb.destReceived, inc.value); assert.equal(rb.ok, false, 'not what was planned')
  assert.equal(res.ok, false)
  const st = solState(r.events).chains.sol!
  assert.equal(st.phase, 'CLAWED_BACK'); assert.equal(st.clawback!.value, inc.value); assert.equal(st.spent, '5000')
})

test('SOL: a preflight rejection or an aborted wait leaves the claw-back open; the takeover is refused until reconciled', { timeout: 30_000 }, async () => {
  const rejecting = solClaw(), relay = fakeRelay({ sol: (m, p) => { if (m === 'sendTransaction') throw new Error('Transaction simulation failed: Blockhash not found'); return rejecting.handler(m, p) } })
  const { journal, events } = recordingJournal()
  const kp = Keypair.generate(), dest = Keypair.generate().publicKey.toBase58()
  await assert.rejects(clawbackSol({ chain: 'sol', kp }, dest, { journal, network: 'local', poll: 1, alive: () => true, notify: async () => {}, state: armedState('sol', 10n ** 12n) }), /still open/)
  assert.deepEqual(events.map((e) => [e.type, e.outcome ?? null]), [['clawback-intent', null], ['clawback-sent', 'unknown']])
  const st = solState(events)
  assert.equal(st.chains.sol!.clawback!.ok, null); assert.equal(st.chains.sol!.openIntents.length, 1)
  const sends = relay.sends().length
  await assert.rejects(clawbackSol({ chain: 'sol', kp }, dest, { journal, network: 'local', poll: 1, alive: () => true, notify: async () => {}, state: st }), (e) => guardIdOf(e) === 'engine.cap-armed')
  assert.equal(relay.sends().length, sends, 'no second claw-back')
})

test('SOL: every claw-back attempt proven expired → each reconciled expired, the claw-back fails by itself (no clawback-failed: that is for one that failed on chain); minutes of proofs run instantly through the clock seam (E2 concern 4)', { timeout: 30_000 }, async () => {
  const base = fakeSolChain()
  let n = 0
  const relay = fakeRelay({ sol: (m, p) => {
    if (m === 'getLatestBlockhash') return p[0]?.commitment === 'finalized'
      ? { context: { slot: 900 }, value: { blockhash: base58.encode(new Uint8Array(32).fill(1)), lastValidBlockHeight: 1_300 } }      // finalized height 1,150 > 1,000
      : { context: { slot: 500 }, value: { blockhash: base58.encode(new Uint8Array(32).fill(++n % 250 + 2)), lastValidBlockHeight: 1_000 } }
    if (m === 'isBlockhashValid') return { context: { slot: 1_000 }, value: false }   // Efix3: the blockhash has expired
    if (m === 'getSignatureStatuses') return { context: { slot: 2_000 }, value: (p[0] as string[]).map(() => null) }
    return base.handler(m, p)
  } })
  const { journal, events } = recordingJournal()
  const kp = Keypair.generate(), dest = Keypair.generate().publicKey.toBase58()
  const t0 = performance.now()
  await assert.rejects(clawbackSol({ chain: 'sol', kp }, dest, { journal, network: 'local', poll: 1, alive: () => true, notify: async () => {}, clock: fakeClock(), solEndpoints: 1, state: armedState('sol', 10n ** 12n) }), /every attempt expired/)
  assert.ok(performance.now() - t0 < 10_000, 'the 10 expiry proofs (≥ 6 s each on the wall clock) ran on the fake clock')
  const intents = events.filter((e) => e.type === 'clawback-intent')
  assert.equal(intents.length, 10, 'SOL.MAX_ATTEMPTS re-signs, each only after a proven expiry')
  assert.equal(relay.sends().length, 10)
  assert.deepEqual(events.filter((e) => e.type === 'reconcile').map((e) => [e.txId, e.outcome]), intents.map((e) => [e.txId, 'expired']))
  assert.equal(events.some((e) => e.type === 'clawback-failed'), false)
  const st = solState(events).chains.sol!
  assert.deepEqual([st.phase, st.clawback!.ok, st.clawback!.landed, st.openIntents, st.spent], ['STOPPED', false, false, [], '0'])
  const l = CapLedger.fromArmed(solState(events), 'sol', kp.publicKey.toBase58()); assert.deepEqual([l.idle, l.spent], [true, 0n]); l.close()
})

// The executor's claw-back deps carry no `notify` (executor.ts clawback): the SOL wait must not need one. Found by E5's
// integration run under load (scenario clawback K2 and local-job job A: "notify is not a function" when the first status
// poll, 2 s after the send, did not yet show the transfer confirmed — the claw-back failed with its tx in flight).
test('SOL claw-back with the executor\'s deps (no notify): a first status poll that is not yet confirmed waits and rebroadcasts; it never crashes', { timeout: 30_000 }, async () => {
  const c = solClaw()
  let hide = 2
  const relay = fakeRelay({ sol: (m, p) => (m === 'getSignatureStatuses' && hide-- > 0 ? { context: { slot: 600 }, value: (p[0] as string[]).map(() => null) } : c.handler(m, p)) })
  const { journal, events } = recordingJournal()
  const kp = Keypair.generate(), dest = Keypair.generate().publicKey.toBase58()
  await clawbackSol({ chain: 'sol', kp }, dest, { journal, network: 'local', poll: 1, alive: () => true, clock: fakeClock(), state: armedState('sol', 10n ** 12n) })
  assert.deepEqual(events.map((e) => e.type), ['clawback-intent', 'clawback-sent', 'clawback-included', 'clawback-readback'])
  assert.ok(relay.sends().some((x) => (x.params[1] as { skipPreflight?: boolean }).skipPreflight === true), 'the same bytes were rebroadcast while waiting')
})

test('SOL claw-back with the executor\'s deps (no notify) that landed with an error: clawback-failed with its fee, not a crash', { timeout: 30_000 }, async () => {
  const r = solClaw({ err: { InstructionError: [0, 'Custom'] } })
  fakeRelay({ sol: r.handler })
  const { journal, events } = recordingJournal()
  const kp = Keypair.generate(), dest = Keypair.generate().publicKey.toBase58()
  await assert.rejects(clawbackSol({ chain: 'sol', kp }, dest, { journal, network: 'local', poll: 1, alive: () => true, clock: fakeClock(), state: armedState('sol', 10n ** 12n) }), /landed with an error/)
  assert.equal(events.find((e) => e.type === 'clawback-failed')?.fee, '5000')
})

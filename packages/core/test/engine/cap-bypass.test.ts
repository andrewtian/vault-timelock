// The R60 spend cap on every signing path (E2 security fix: cap bypass). The cap comes only from the ARMED job state;
// cumulative spend (journal spend + held worst cases of open intents + this signature) never exceeds it; every refusal
// happens before signing. ALL DATA IS SYNTHETIC; the relay is a fake fetch, nothing is broadcast anywhere.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { CapLedger } from '../../src/gates/caps.ts'
import { ethTx, solTx } from '../../src/engine/engine.js'
import { Keypair } from '@solana/web3.js'
import { clawbackEth, clawbackSol, ethAdapter, newLaneState, runCopiesLane, runDrainLane, validateLaneConfig } from '../../src/engine/lane.js'
import { ETH } from '../../src/chains/constants.js'
import { ethGasBudget, ethParts, utf8 } from '../../src/chains/plan.js'
import { reduce } from '../../src/job/index.ts'
import type { JobDef, JournalEvent } from '../../src/contracts/index.ts'
import { guardOf, readJson } from '../job/helpers.ts'
import { armedEvent, armedLedger, armedState, asJournal, fakeEthChain, fakeRelay, fakeSolChain, recordingJournal } from './fakes.ts'
import type { Ev } from './fakes.ts'

const GWEI = 10n ** 9n
const RULE = { amsterdam: false, toSelf: false }
const PAYLOAD = utf8('data:,cap test')
const R = (21000n + 40n * BigInt(PAYLOAD.length)) * 3n * GWEI          // gasLimit × maxFee (2 × 1 gwei base + 1 gwei tip)
const key = () => ({ chain: 'eth', account: privateKeyToAccount(generatePrivateKey()) })
const tx = (nonce = 0): Record<string, any> => ({ copy: nonce + 1, part: 1, parts: 1, payload: PAYLOAD, nonce })
const opts = (journal: unknown, ledger: unknown, extra: Record<string, unknown> = {}) => ({
  account: key().account, chainId: 31337, notify: async () => {}, alive: () => true, poll: 1, tipCap: 3n * GWEI, journal, ledger,
  lane: { txs: [] }, gasRule: RULE, to: ETH.NULL_ADDRESS, ...extra,
})
async function guardOfAsync(p: Promise<unknown>): Promise<string | null> {
  try { await p } catch (e) { const id = (e as { guardId?: unknown }).guardId; if (typeof id === 'string') return id; throw e }
  return null
}

// ---- the ledger itself ----
test('the ledger is built only from the armed job state: no constructor, no armed cap → engine.cap-armed', () => {
  assert.throws(() => new (CapLedger as any)(Symbol('x'), 'eth', 10n ** 30n, 0n, new Map(), 'k'), TypeError)
  const st = armedState('eth', 100n)
  assert.equal(guardOf(() => CapLedger.fromArmed({ ...st, armed: null }, 'eth', 'k-armed-1')), 'engine.cap-armed', 'not armed')
  assert.equal(guardOf(() => CapLedger.fromArmed(armedState('sol', 100n), 'eth', 'k-armed-2')), 'engine.cap-armed', 'this chain not in the order')
  const bad = (cap: string) => { const s = armedState('eth', 100n); s.armed.caps.eth.nativeCap = cap; return s }
  for (const cap of ['', '-1', '1e30', '01', 'NaN']) assert.equal(guardOf(() => CapLedger.fromArmed(bad(cap), 'eth', `k-bad-${cap}`)), 'engine.cap-armed', cap)
  const spent = armedState('eth', 100n); spent.chains.eth.spent = 'x'
  assert.equal(guardOf(() => CapLedger.fromArmed(spent, 'eth', 'k-armed-3')), 'engine.cap-armed', 'malformed spend')
  const claw = armedState('eth', 100n, { clawback: { txId: 't', to: 'x', value: '1', ok: null }, openIntents: ['t'] })
  assert.equal(guardOf(() => CapLedger.fromArmed(claw, 'eth', 'k-armed-4')), 'engine.cap-armed', 'an open claw-back must be reconciled first')
  assert.equal(guardOf(() => CapLedger.fromArmed(st, 'eth', '')), 'engine.cap-armed', 'a key address is required')
  const l = CapLedger.fromArmed(armedState('eth', 100n, { spent: 30n }), 'eth', 'k-armed-ok')
  assert.deepEqual([l.cap, l.spent, l.held, l.remaining], [100n, 30n, 0n, 70n]); l.close()
})

test('the lane config has no cap field: capBase is refused; a free deps.cap or deps.ledger never replaces the armed cap', { timeout: 30_000 }, async () => {
  assert.match(validateLaneConfig({ chain: 'eth', text: 'x', capBase: '999999999999999999999' }).errors.join(), /unknown field "capBase"/)
  const chain = fakeEthChain({ balance: 10n ** 15n }), relay = fakeRelay({ eth: chain.handler })   // a finite balance: a lane that ignored the cap would drain it and end
  const { journal } = recordingJournal()
  const cfg = validateLaneConfig({ chain: 'eth', text: 'one copy', mode: 'drain', feeStrategy: 'economy' }).cfg
  const wide = armedLedger('eth', 10n ** 30n)
  const lane = newLaneState(cfg)
  const r = await runDrainLane(cfg, key(), lane, { journal, network: 'local', chainId: 31337, poll: 1, alive: () => true, notify: async () => {}, sleep: async () => {}, state: armedState('eth', 1n), cap: 10n ** 30n, ledger: wide })
  assert.equal(r, 'stopped'); assert.match(lane.reason, /spend cap/)
  assert.equal(relay.sends().length, 0, 'the armed cap (1 wei) applied, not the wide one the caller passed')
  wide.close()
})

test('reservations: one (copy, part) holds the largest of its attempts; the journaled inclusion spends once; malformed amounts refuse', () => {
  const l = armedLedger('eth', 1000n)
  const t = { copy: 1, part: 1 }
  const intent = (txId: string, copy: number, worst: bigint) => ({ type: 'intent', chain: 'eth', txId, copy, part: 1, parts: 1, eth: { nonce: copy, tip: '1', maxFee: String(worst), gas: '1', to: ETH.NULL_ADDRESS } })
  l.reserve(t, 400n); l.observe(intent('A', 1, 400n))
  l.reserve(t, 600n); l.observe(intent('B', 1, 600n))
  l.reserve(t, 500n); l.observe(intent('C', 1, 500n))
  assert.equal(l.held, 600n, 'a bump family is held at its largest attempt; at most one attempt of a nonce lands')
  assert.equal(guardOf(() => l.reserve({ copy: 2, part: 1 }, 401n)), 'engine.cap', 'another tx must fit beside the held one')
  l.reserve({ copy: 2, part: 1 }, 400n); l.observe(intent('D', 2, 400n))
  assert.equal(guardOf(() => l.check(1n)), 'engine.cap-copy')
  const inc = { type: 'included', chain: 'eth', txId: 'A', copy: 1, part: 1, attempt: 1, block: '9', fee: '550', ms: 1 }
  l.observe(inc); l.observe(inc)
  assert.deepEqual([l.spent, l.held, l.remaining], [550n, 400n, 50n], 'spent once; the family released (B and C superseded)')
  for (const bad of [-1n, 1 as unknown as bigint, undefined as unknown as bigint]) assert.equal(guardOf(() => l.reserve({ copy: 3, part: 1 }, bad)), 'engine.cap')
  assert.equal(guardOf(() => l.check(-1n)), 'engine.cap-copy')
  assert.equal(guardOf(() => l.reserveClawback(51n)), 'engine.cap-clawback')
  l.reserveClawback(50n)
  assert.equal(l.remaining, 0n)
  assert.throws(() => l.reserve(t, 1n), /already landed/, 'a landed part is never signed again')
  l.close()
})

// ---- every signing path ----
test('ETH signature: a worst case (gasLimit × maxFee) one wei over the cap is refused before signing; at the cap it is sent', { timeout: 30_000 }, async () => {
  const chain = fakeEthChain(), relay = fakeRelay({ eth: chain.handler })
  const { journal, events } = recordingJournal()
  const t = tx()
  assert.equal(await ethTx(t, opts(journal, armedLedger('eth', R - 1n))), 'exhausted')
  assert.match(t.reason, /spend cap/)
  assert.deepEqual([relay.sends().length, events.length, t.attempts.length], [0, 0, 0], 'nothing signed, journaled or sent')
  const ledger = armedLedger('eth', R), t2 = tx()
  assert.equal(await ethTx(t2, opts(journal, ledger)), 'confirmed')
  assert.equal(relay.sends().length, 1)
  assert.deepEqual([ledger.spent, ledger.held], [t2.actual, 0n], 'the engine settles the actual fee and releases the reservation')
  assert.ok(t2.actual < R && ledger.remaining === R - t2.actual)
  ledger.close()
})

test('SOL signature: the exact fee is reserved before signing and settled at inclusion; over the cap nothing is signed', { timeout: 30_000 }, async () => {
  const chain = fakeSolChain(), relay = fakeRelay({ sol: chain.handler })
  const { journal } = recordingJournal()
  const o = (ledger: unknown) => ({ kp: Keypair.generate(), notify: async () => {}, alive: () => true, poll: 1, rent: 890_880n, used: new Map(), journal, ledger,
    lane: { txs: [] }, payerFloor: 890_880n, cuPriceCap: 2_000_000, policy: { price: async () => ({ lamports: 0, rung: 0 }) } })
  const t: Record<string, any> = { copy: 1, part: 1, parts: 1, payload: utf8('cap memo') }
  assert.equal(await solTx(t, o(armedLedger('sol', 4_999n))), 'exhausted')
  assert.match(t.reason, /spend cap/); assert.equal(relay.sends().length, 0)
  const ledger = armedLedger('sol', 5_000n)
  assert.equal(await solTx({ copy: 1, part: 1, parts: 1, payload: utf8('cap memo') }, o(ledger)), 'confirmed')
  assert.deepEqual([ledger.spent, ledger.held, relay.sends().length], [5_000n, 0n, 1])
  ledger.close()
})

test('ETH same-nonce replacement: the ×1.125 bump is checked at its own worst case and refused before signing', { timeout: 30_000 }, async () => {
  let live = true
  const chain = fakeEthChain({ mine: false }), relay = fakeRelay({ eth: chain.handler })
  const { journal, events } = recordingJournal()
  const t = tx(), ledger = armedLedger('eth', R + R / 10n)            // the first attempt fits; 1.125 × R does not
  assert.equal(await ethTx(t, opts(journal, ledger, { alive: () => live })), 'exhausted')
  live = false
  assert.match(t.reason, /spend cap/)
  assert.equal(relay.sends().length, 1, 'only the first attempt was ever sent')
  assert.deepEqual(events.filter((e) => e.type === 'intent').length, 1, 'no replacement intent')
  assert.equal(ledger.held, R, 'the in-flight attempt stays held: it may still land')
})

test('ETH multi-part copy: every part is checked at its own signature (fees rose after part 1 → part 2 refused before signing)', { timeout: 30_000 }, async () => {
  const text = 'x'.repeat(100_000), parts = ethParts(utf8(text))
  assert.equal(parts.length, 2)
  const copyWorst = parts.reduce((a, p) => a + ethGasBudget(p.payload.length, RULE) * 3n * GWEI, 0n)
  const chain = fakeEthChain({ afterSend: () => chain.setBase(100n * GWEI) }), relay = fakeRelay({ eth: chain.handler })
  const { journal, events } = recordingJournal()
  const cfg = validateLaneConfig({ chain: 'eth', text, mode: 'copies', copies: 1, feeStrategy: 'economy' }).cfg
  const lane = newLaneState(cfg)
  const r = await runCopiesLane(cfg, key(), lane, { journal, network: 'local', chainId: 31337, poll: 1, alive: () => true, notify: async () => {}, sleep: async () => {}, state: armedState('eth', copyWorst) })
  assert.equal(r, 'failed'); assert.match(lane.reason, /spend cap/)
  assert.equal(relay.sends().length, 1, 'part 1 only')
  assert.deepEqual(events.filter((e) => e.type === 'intent').map((e) => e.part), [1])
})

test('drain: the next copy\'s worst case is checked before it starts (engine.cap-copy), with the journal\'s spend counted', { timeout: 30_000 }, async () => {
  const chain = fakeEthChain(), relay = fakeRelay({ eth: chain.handler })
  const cfg = validateLaneConfig({ chain: 'eth', text: 'drain me', mode: 'drain', feeStrategy: 'economy', distinct: false }).cfg
  const n = ethParts(utf8(cfg.text))[0].payload.length, copyWorst = ethGasBudget(n, RULE) * 3n * GWEI
  const { journal, events } = recordingJournal()
  const lane = newLaneState(cfg)
  const d = { journal, network: 'local', chainId: 31337, poll: 1, alive: () => true, notify: async () => {}, sleep: async () => {} }
  const actual = BigInt(21000 + 40 * n) * 2n * GWEI                    // what a copy really costs (fake: base 1 + tip 1 gwei)
  assert.ok(actual + copyWorst <= 2n * copyWorst && 2n * actual + copyWorst > 2n * copyWorst, 'the cap below fits exactly two copies')
  assert.equal(await runDrainLane(cfg, key(), lane, { ...d, state: armedState('eth', 2n * copyWorst) }), 'stopped')
  assert.match(lane.reason, /next copy's worst case/)
  assert.equal(relay.sends().length, 2, 'copy 3 never started')
  assert.equal(events.at(-1)!.type, 'stopped')
  assert.equal(events.at(-1)!.code, 'spend-cap', 'R79b: the cap stop is final (a resume cannot add cap)')
  // a resumed run (takeover, reload) cannot reset the spend: the journal's spend is counted
  const again = newLaneState(cfg)
  assert.equal(await runDrainLane(cfg, key(), again, { ...d, state: armedState('eth', 2n * copyWorst, { spent: copyWorst + 1n }), resume: { copy: 3, nextPart: 1 } }), 'stopped')
  assert.equal(relay.sends().length, 2, 'nothing more was sent')
})

test('open intents in the journal stay held whatever the event order (an inclusion journaled before its intent)', () => {
  const def = readJson<JobDef>('journals/01-created.def.json')       // eth only
  const ev = (seq: number, type: string, data: Record<string, unknown>, chain: 'eth' | null = 'eth', by: JournalEvent['by'] = 'cli'): JournalEvent =>
    ({ v: 1, seq, at: seq, prev: '', chain, by, gen: chain ? 1 : null, type: type as JournalEvent['type'], data })
  const H = 'ab'.repeat(32), A = `0x${'a'.repeat(64)}`, B = `0x${'b'.repeat(64)}`
  const intent = (txId: string, copy: number) => ({ txId, copy, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: H, payloadSha256: H, reserved: '1', eth: { nonce: copy, tip: '1', maxFee: '2000000000', gas: '21240', to: ETH.NULL_ADDRESS } })
  const events = [
    ev(0, 'armed', { armedAt: 0, releaseAt: 1, countdownSec: 5, schedule: { order: ['eth'], offsetSec: { eth: 0 } }, caps: { eth: { nativeCap: '100000000000000', usd: 0, priceAt: null, overCap: false, planned: '0' } }, sources: {} }, null, 'api'),
    ev(1, 'included', { txId: B, copy: 2, part: 1, attempt: 1, block: '9', fee: '5', ms: 1 }),   // before its intent: ignored by reduce
    ev(2, 'intent', intent(A, 1)), ev(3, 'intent', intent(B, 2)),
  ]
  const state = reduce(def, events)
  const l = CapLedger.fromArmed(state, 'eth', 'k-order')
  assert.equal(l.held, 2n * 21_240n * 2_000_000_000n, 'both open intents are held at gas × maxFee')
  assert.equal(l.remaining, 100_000_000_000_000n - l.held)
  l.close()
})

test('ETH claw-back: its value + worst-case fee must fit the armed cap with the journal\'s spend (engine.cap-clawback), refused before signing', { timeout: 30_000 }, async () => {
  const hx = (n: bigint): string => `0x${n.toString(16)}`
  const chain = fakeEthChain(), relay = fakeRelay({ eth: (m, p) => (m === 'eth_getCode' ? '0x' : m === 'eth_getBalance' ? hx(10n ** 16n) : chain.handler(m, p)) })
  const intents: unknown[] = []
  const { journal } = recordingJournal({ intent: async (e) => { intents.push(e); throw new Error('stop at the intent') } })
  const k = key(), DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
  const whole = 10n ** 16n                                              // value + worst-case fee = the lane's balance
  const d = (spent: bigint) => ({ journal, network: 'local', chainId: 31337, poll: 1, state: armedState('eth', 10n ** 17n, { spent }) })
  await assert.rejects(clawbackEth(k, DEST, d(10n ** 17n - whole + 1n)), (e: Error & { guardId?: string }) => e.guardId === 'engine.cap-clawback')
  assert.deepEqual([intents.length, relay.sends().length], [0, 0])
  await assert.rejects(clawbackEth(k, DEST, d(10n ** 17n - whole)), /not acked/, 'at the cap: it reaches the intent')
  assert.equal(intents.length, 1)
  await assert.rejects(clawbackEth(k, DEST, { ...d(0n), state: undefined }), (e: Error & { guardId?: string }) => e.guardId === 'engine.cap-armed')
})

test('the live tip cap is not a spend cap: raising it never lets a signature exceed the armed cap', { timeout: 30_000 }, async () => {
  const chain = fakeEthChain({ tip: 50n * GWEI }), relay = fakeRelay({ eth: chain.handler })
  const { journal } = recordingJournal()
  const cfg = validateLaneConfig({ chain: 'eth', text: 'tip cap', mode: 'drain', feeStrategy: 'economy', tipCapGwei: '3' }).cfg
  const ledger = armedLedger('eth', 10n * R)
  const k = key(), lane = newLaneState(cfg)
  const A = ethAdapter(cfg, k, { journal, network: 'local', chainId: 31337, poll: 1, alive: () => true, notify: async () => {}, lane, ledger, getTipCapGwei: () => '100' })
  await A.reconcile(lane, async () => {})
  const t: Record<string, any> = { copy: 1, part: 1, parts: 1, payload: A.planCopy(1)[0].payload }
  assert.equal(await A.sendTx(t, { tight: false }), 'exhausted')
  assert.match(t.reason, /spend cap/)
  assert.equal(relay.sends().length, 0)
  ledger.close()
})

// ---- concurrency ----
test('concurrent signatures on one ledger cannot jointly exceed the cap; a second lane for the same key is refused (engine.cap-busy)', { timeout: 30_000 }, async () => {
  const chain = fakeEthChain(), relay = fakeRelay({ eth: chain.handler })
  const { journal } = recordingJournal()
  const ledger = armedLedger('eth', R + R / 2n)                       // room for one worst case, not two
  const o = opts(journal, ledger), r = await Promise.all([ethTx(tx(0), o), ethTx(tx(1), o)])
  assert.deepEqual([...r].sort(), ['confirmed', 'exhausted'])
  assert.equal(relay.sends().length, 1)
  ledger.close()
  const st = armedState('eth', 10n ** 18n)
  const a = CapLedger.fromArmed(st, 'eth', '0xAbC')
  assert.equal(guardOf(() => CapLedger.fromArmed(st, 'eth', '0xabc')), 'engine.cap-busy', 'the same key, any case')
  a.close()
  CapLedger.fromArmed(st, 'eth', '0xabc').close()
  // two lanes started at once on one key: the second is refused before anything is planned or signed
  const cfg = validateLaneConfig({ chain: 'eth', text: 'twice', mode: 'copies', copies: 1, feeStrategy: 'economy' }).cfg
  const k = key(), d = { journal, network: 'local', chainId: 31337, poll: 1, alive: () => true, notify: async () => {}, sleep: async () => {}, state: armedState('eth', 10n ** 18n) }
  const both = await Promise.allSettled([runCopiesLane(cfg, k, newLaneState(cfg), d), runCopiesLane(cfg, k, newLaneState(cfg), d)])
  assert.equal(both[0].status, 'fulfilled')
  assert.equal(both[1].status === 'rejected' && (both[1].reason as { guardId?: string }).guardId, 'engine.cap-busy')
  assert.equal(await guardOfAsync(runCopiesLane(cfg, k, newLaneState(cfg), d)), null, 'released when the first lane ended')
})

test('every signing entry point needs the ledger (engine.cap-ledger): ethTx without one signs nothing', async () => {
  const chain = fakeEthChain(), relay = fakeRelay({ eth: chain.handler })
  const { journal } = recordingJournal()
  assert.equal(await guardOfAsync(ethTx(tx(), opts(journal, undefined, { cap: 10n ** 30n }))), 'engine.cap-ledger')
  assert.equal(relay.sends().length, 0)
})

// ---- E2 review I-2: the SOL claw-back call site, the takeover holds, the ETH bump gas ----
const ETH_DEF = readJson<JobDef>('journals/01-created.def.json')          // eth only
const HX = 'ab'.repeat(32)
const intentEv = (txId: string, attempt: number, maxFee: bigint, replaces: string | null = null): Ev => ({ type: 'intent', chain: 'eth', txId, copy: 1, part: 1, parts: 1, attempt, replaces,
  rawSha256: HX, payloadSha256: HX, reserved: '1', eth: { nonce: 0, tip: '1', maxFee: String(maxFee), gas: '21000', to: ETH.NULL_ADDRESS } })
const stateOf = (evs: Ev[]) => reduce(ETH_DEF, asJournal([armedEvent(['eth'], 10n ** 18n)], evs))

test('SOL claw-back: its value + fee must fit the armed cap with the journal\'s spend (engine.cap-clawback); one lamport over → no intent, no send', { timeout: 30_000 }, async () => {
  const chain = fakeSolChain(), relay = fakeRelay({ sol: chain.handler })
  const intents: Ev[] = []
  const { journal } = recordingJournal({ intent: async (e) => { intents.push(e); throw new Error('stop at the intent') } })
  const kp = Keypair.generate(), dest = Keypair.generate().publicKey.toBase58(), cap = 10n ** 10n, whole = 10n ** 9n   // amount + fee = the balance
  const d = (spent: bigint) => ({ journal, network: 'local', poll: 1, state: armedState('sol', cap, { spent }) })
  await assert.rejects(clawbackSol({ chain: 'sol', kp }, dest, d(cap - whole + 1n)), (e: Error & { guardId?: string }) => e.guardId === 'engine.cap-clawback')
  assert.deepEqual([intents.length, relay.sends().length], [0, 0], 'refused before signing')
  await assert.rejects(clawbackSol({ chain: 'sol', kp }, dest, d(cap - whole)), /not acked/, 'exactly at the cap: it reaches the intent')
  assert.equal(intents.length, 1); assert.equal((intents[0].sol as Record<string, unknown>).fee, '5000'); assert.equal(relay.sends().length, 0)
})

test('takeover holds: the largest open attempt of a group, adopted and stuck attempts are held; an open attempt without fee data refuses', () => {
  const A = `0x${'a'.repeat(64)}`, B = `0x${'b'.repeat(64)}`
  const two = stateOf([intentEv(A, 1, 1000n), { type: 'sent', chain: 'eth', txId: A, outcome: 'unknown', reason: null },
    intentEv(B, 2, 1125n, A), { type: 'sent', chain: 'eth', txId: B, outcome: 'unknown', reason: null }])
  assert.deepEqual(two.chains.eth!.openIntents, [A, B])
  let l = CapLedger.fromArmed(two, 'eth', 'hold-max'); assert.equal(l.held, 21_000n * 1125n, 'the 1.125 attempt: not the 1.0, not the sum'); l.close()
  const adopted = stateOf([intentEv(A, 1, 1000n), { type: 'reconcile', chain: 'eth', txId: A, outcome: 'adopted' }])
  assert.equal(adopted.chains.eth!.txs[0].attempts[0].state, 'adopted')
  l = CapLedger.fromArmed(adopted, 'eth', 'hold-adopted'); assert.equal(l.held, 21_000n * 1000n); l.close()
  const stuck = stateOf([intentEv(A, 1, 1000n), { type: 'stuck', chain: 'eth', txId: A, reason: 'outcome unknowable' }])
  assert.equal(stuck.chains.eth!.txs[0].state, 'stuck')
  l = CapLedger.fromArmed(stuck, 'eth', 'hold-stuck'); assert.equal(l.held, 21_000n * 1000n); l.close()
  const bare = intentEv(A, 1, 1000n); delete bare.eth
  const noFee = stateOf([bare])
  assert.deepEqual(noFee.chains.eth!.openIntents, [A])
  assert.equal(guardOf(() => CapLedger.fromArmed(noFee, 'eth', 'hold-bare')), 'engine.cap-armed', 'an open attempt whose worst case is unknown is not ignored')
})

test('ETH bump with a falling estimate: the replacement keeps the first gas limit, and its reservation is prev.gas × maxFee′', { timeout: 30_000 }, async () => {
  let live = true, estimates = 0
  const chain = fakeEthChain({ mine: false, afterSend: () => { if (relay.sends().length >= 2) live = false } })
  const relay = fakeRelay({ eth: (m, p) => {
    const r = chain.handler(m, p)
    if (m === 'eth_estimateGas') { estimates++; return estimates === 1 ? `0x${(BigInt(r as string) + 300n).toString(16)}` : r }   // +300 first (within the tolerance), exact later
    return r
  } })
  const { journal, events } = recordingJournal()
  const ledger = armedLedger('eth', 10n ** 18n), t: Record<string, any> = { copy: 1, part: 1, parts: 1, payload: utf8('data:,falling'), nonce: 0 }
  assert.equal(await ethTx(t, opts(journal, ledger, { alive: () => live })), 'aborted')
  const intents = events.filter((e) => e.type === 'intent').map((e) => e.eth as Record<string, string>)
  assert.equal(intents.length, 2, 'one same-nonce replacement')
  const g = 21_000n + 40n * BigInt(t.payload.length)
  assert.equal(intents[0].gas, String(g + 300n)); assert.equal(intents[1].gas, String(g + 300n), 'the replacement keeps prev.gas')
  assert.equal(ledger.held, (g + 300n) * BigInt(intents[1].maxFee), 'reserved at prev.gas × maxFee′, not the lower new estimate')
  ledger.close()
})

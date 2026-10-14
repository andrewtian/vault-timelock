// E5 endpoint agreement (MQ's parked M11; gates/agree.ts, engine.js postSol, lane.js): the nonce an ETH lane starts from
// (and a claw-back signs at) is read from EVERY verified endpoint and must agree (engine.nonce-disagree: the lane pauses,
// nothing is signed); a lane never signs from an account with code (engine.eip7702: an EIP-7702 delegation); every SOL
// send and rebroadcast goes to every verified endpoint (/relay/sol/ep/<i>) with the same ticket — one txId.
// ALL DATA IS SYNTHETIC: generated keys, fake chains behind a fake relay; nothing listens on a port, nothing is broadcast.
import { afterEach, test } from 'node:test'
import assert from 'node:assert/strict'
import { base58, base64 } from '@scure/base'
import { Keypair, VersionedTransaction } from '@solana/web3.js'
import { keccak256, parseTransaction, toHex } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { assertCodeAgreement, assertNoDelegation, assertNonceAgreement } from '../../src/gates/agree.ts'
import { postSol } from '../../src/engine/engine.js'
import { RelayRefused, RpcError, TransportError } from '../../src/engine/rpc.js'
import { clawbackEth, clawbackSol, ethAdapter, newLaneState, runCopiesLane, validateLaneConfig } from '../../src/engine/lane.js'
import { createExecutor, laneConfigOf } from '../../src/executor/executor.ts'
import { useRelayClient } from '../../src/engine/rpc.js'
import * as eth from '../../src/chains/eth.js'
import { planLaneCopy } from '../../src/engine/lane.js'
import { TICKET_PREFIX } from '../../src/contracts/index.ts'
import { guardOf, refusalOf } from '../job/helpers.ts'
import { deps as exDeps, sendViolations, stack } from '../executor/helpers.ts'
import { armedState, fakeClock, fakeEthChain, fakeRelay, fakeSolChain, recordingJournal, relayRefusal, ticketFor, transportFailure } from './fakes.ts'
import type { Ev } from './fakes.ts'

const hx = (n: bigint | number): string => `0x${BigInt(n).toString(16)}`
const DELEGATED = `0xef0100${'ab'.repeat(20)}`                               // EIP-7702: 0xef0100 ‖ a 20-byte delegate
const DELEGATED2 = `0xef0100${'cd'.repeat(20)}`                              // another delegate
const guardIdOf = (e: unknown): string | undefined => (e as { guardId?: string }).guardId
const cfgOf = (chain: 'eth' | 'sol', extra: Record<string, unknown>, text: string) => { const v = validateLaneConfig({ chain, text, ...extra }); assert.equal(v.ok, true, v.errors.join()); return v.cfg }
const ethKey = () => ({ chain: 'eth', account: privateKeyToAccount(generatePrivateKey()) })
const solKey = () => ({ chain: 'sol', kp: Keypair.generate() })
const types = (evs: Ev[]): string[] => evs.map((e) => e.type)

afterEach(() => { assert.deepEqual(sendViolations.splice(0), [], 'every ticketed send was exactly its journaled intent') })

// ---------------- the gates ----------------

test('assertNonceAgreement: equal answers pass and give the pair; any difference, a missing quorum or nonsense refuses engine.nonce-disagree', () => {
  assert.deepEqual(assertNonceAgreement([5, 5], [5, 5]), { latest: 5, pending: 5 })
  assert.deepEqual(assertNonceAgreement([5, 5, 5], [6, 6, 6], 3), { latest: 5, pending: 6 })
  assert.deepEqual(assertNonceAgreement([7], [7], 1), { latest: 7, pending: 7 }, 'a relay with one verified endpoint: its answer')
  assert.deepEqual(assertNonceAgreement([0, 0], [0, 0], 3), { latest: 0, pending: 0 }, '2 of 3 answered and agree: the quorum')
  for (const [latest, pending, eps, why] of [
    [[5, 6], [6, 6], 2, 'latest differs'],
    [[5, 5], [5, 6], 2, 'pending differs (a pending tx one endpoint hides)'],
    [[5, 5, 4], [5, 5, 5], 3, 'one of three lags'],
    [[5], [5], 2, 'the relay verified 2, one answered'],
    [[5], [5], 3, 'the relay verified 3, one answered'],
    [[], [], 1, 'nothing answered'],
    [[5, 5], [5], 2, 'a pending answer missing'],
    [[5, 5], [4, 4], 2, 'pending below latest'],
    [[5.5, 5.5], [6, 6], 2, 'not an integer'],
    [[-1, -1], [0, 0], 2, 'negative'],
    [[NaN, NaN], [1, 1], 2, 'NaN'],
  ] as Array<[number[], number[], number, string]>) {
    assert.equal(guardOf(() => assertNonceAgreement(latest, pending, eps)), 'engine.nonce-disagree', why)
  }
  const e = refusalOf(() => assertNonceAgreement([5, 6], [5, 6], 2))
  assert.match(e.message, /2 of 2 answered, 2 needed; latest 5, 6; pending 5, 6/)
  assert.match(e.message, /nothing is signed until they agree/)
})

test('assertNoDelegation: exactly 0x passes; an EIP-7702 delegation (0xef0100…), any other code or a malformed answer refuses engine.eip7702', () => {
  assert.equal(guardOf(() => assertNoDelegation('0x')), null)
  assert.match(refusalOf(() => assertNoDelegation(DELEGATED)).message, /EIP-7702 delegation/)
  assert.match(refusalOf(() => assertNoDelegation(`0xEF0100${'CD'.repeat(20)}`)).message, /EIP-7702 delegation/)
  for (const code of [DELEGATED, '0x6080604052', '0x00', '0x0', '', 'null', `0xef0100${'ab'.repeat(19)}`]) {
    assert.equal(guardOf(() => assertNoDelegation(code)), 'engine.eip7702', code)
  }
  assert.doesNotMatch(refusalOf(() => assertNoDelegation(DELEGATED)).message, /abab/, 'the delegate address is not echoed')
})

test('fix round 2 — assertCodeAgreement: one clear state (all 0x, or all the same delegation) passes; a disagreement, too few answers or an agreed non-delegation code refuses engine.code-disagree', () => {
  assert.equal(assertCodeAgreement(['0x', '0x']), '0x')
  assert.equal(assertCodeAgreement(['0x'], 1), '0x', 'one verified endpoint: its answer')
  assert.equal(assertCodeAgreement([DELEGATED, DELEGATED, DELEGATED], 3), DELEGATED)
  assert.equal(assertCodeAgreement([DELEGATED, DELEGATED.toUpperCase().replace('0X', '0x')], 2), DELEGATED, 'the same designator in another case')
  assert.equal(assertCodeAgreement(['0x', '0x'], 3), '0x', '2 of 3 answered and agree: the quorum')
  for (const [codes, eps, why] of [
    [['0x', DELEGATED], 2, 'one endpoint says delegated, one says no code'],
    [[DELEGATED, '0x', '0x'], 3, 'one of three'],
    [[DELEGATED, DELEGATED2], 2, 'two different delegations'],
    [[DELEGATED], 2, 'the relay verified 2, one answered'],
    [['0x'], 2, 'no code, but one answer of 2'],
    [[], 1, 'nothing answered'],
    [['0x6080604052', '0x6080604052'], 2, 'agreed contract code: not a delegation'],
    [['0x0', '0x0'], 2, 'agreed malformed answer'],
    [['null', 'null'], 2, 'agreed nonsense'],
  ] as Array<[string[], number, string]>) {
    assert.equal(guardOf(() => assertCodeAgreement(codes, eps)), 'engine.code-disagree', why)
  }
  const e = refusalOf(() => assertCodeAgreement(['0x', DELEGATED, DELEGATED2], 3))
  assert.match(e.message, /3 of 3 answered, 2 needed: 1 no code, 2 an EIP-7702 delegation — different ones, 0 other/)
  assert.doesNotMatch(e.message, /abab|cdcd/, 'no code or delegate address echoed')
})

// ---------------- the ETH lane: nonce quorum and the delegation check at the start ----------------

// A fake ETH chain behind two verified endpoints: ep(i) answers eth_getTransactionCount / eth_getCode for ep '0' / '1'
// (null: the preferred route); everything else is the one fake chain.
function ethTwo(o: { latest?: (ep: string | null, real: number) => number | 'down'; code?: (ep: string | null) => string } = {}) {
  const chain = fakeEthChain()
  const reads: Array<{ ep: string | null; tag: string }> = []
  let sendsSeen = 0
  const relay = fakeRelay({ eth: (m, p, ep) => {
    if (m === 'eth_getTransactionCount' && (p[1] === 'latest' || p[1] === 'pending')) {
      reads.push({ ep, tag: p[1] })
      const real = Number(BigInt(chain.handler(m, p) as string)), v = o.latest ? o.latest(ep, real) : real
      if (v === 'down') throw transportFailure()
      return hx(v)
    }
    if (m === 'eth_getCode' && o.code) return o.code(ep)
    if (m === 'eth_sendRawTransaction') sendsSeen++
    return chain.handler(m, p)
  } })
  return { chain, relay, reads, sends: () => sendsSeen }
}
const ethDeps = (journal: unknown, extra: Record<string, unknown> = {}) => ({ journal, network: 'local', chainId: 31337, state: armedState('eth', 10n ** 17n), poll: 1, alive: () => true, notify: async () => {}, clock: fakeClock(), ...extra })
const ETH_CFG = () => cfgOf('eth', { mode: 'copies', copies: 1, distinct: true, feeStrategy: 'economy' }, 'Endpoint agreement test.')

test('two fake endpoints disagree on the nonce → the lane pauses with engine.nonce-disagree, signs nothing, and resumes once they agree', async () => {
  let disagreeing = 3, lastBad = -1
  const f = ethTwo({ latest: (ep, real) => { if (ep === '1' && disagreeing > 0) { lastBad = f.relay.calls.length; return real + 1 } return real } })
  const { journal, events } = recordingJournal()
  const cfg = ETH_CFG()
  const d = ethDeps(journal, { ethEndpoints: 2 })
  const tick = d.clock.sleep
  d.clock.sleep = async (ms: number) => { disagreeing--; await tick(ms) }
  assert.equal(await runCopiesLane(cfg, ethKey(), newLaneState(cfg), d), 'copies-done')
  const ts = types(events)
  assert.equal(ts[0], 'paused', 'paused before anything else')
  assert.match(String(events[0].reason), /^engine\.nonce-disagree: the verified ETH endpoints do not agree/)
  assert.equal(ts.filter((t) => t === 'paused').length, 1, 'journaled once, not per read')
  const resumed = ts.indexOf('resumed'), intent = ts.indexOf('intent')
  assert.ok(resumed > 0 && intent > resumed, 'the first intent comes after the endpoints agree')
  const firstSend = f.relay.calls.findIndex((c) => c.method === 'eth_sendRawTransaction')
  assert.ok(lastBad >= 0 && firstSend > lastBad, 'nothing was sent while they disagreed')
  assert.equal(f.sends(), 1)
  assert.deepEqual([...new Set(f.reads.map((r) => r.ep))].filter((x) => x !== null).sort(), ['0', '1'], 'the start read asked each verified endpoint')
  assert.equal(parseTransaction(f.chain.mined.values().next().value!.raw as `0x${string}`).nonce, 0, 'signed at the agreed nonce')
})

test('a Stop while the endpoints disagree: stopped during reconcile — no intent, no send', async () => {
  const f = ethTwo({ latest: (ep, real) => (ep === '1' ? real + 1 : real) })
  const { journal, events } = recordingJournal()
  const cfg = ETH_CFG()
  let rounds = 0
  const d = ethDeps(journal, { ethEndpoints: 2, stopRequested: () => events.some((e) => e.type === 'paused'), alive: () => ++rounds < 200 })   // bounded: a mutant without the Stop fails, never hangs
  assert.equal(await runCopiesLane(cfg, ethKey(), newLaneState(cfg), d), 'stopped')
  assert.deepEqual(types(events), ['paused', 'stopped'])
  assert.equal(f.sends(), 0)
})

test('a lost lease while the endpoints disagree: the lane aborts (nothing journaled after the pause, nothing sent)', async () => {
  const f = ethTwo({ latest: (ep, real) => (ep === '1' ? real + 1 : real) })
  const { journal, events } = recordingJournal()
  const cfg = ETH_CFG()
  const d = ethDeps(journal, { ethEndpoints: 2, alive: () => !events.some((e) => e.type === 'paused') })
  const lane = newLaneState(cfg)
  assert.equal(await runCopiesLane(cfg, ethKey(), lane, d), 'aborted')
  assert.deepEqual(types(events), ['paused'])
  assert.equal(f.sends(), 0)
})

test('the relay verified 2 endpoints and only 1 answers → paused (2 needed), resumed when the second answers again', async () => {
  let down = 2
  const f = ethTwo({ latest: (ep, real) => (ep === '1' && down > 0 ? 'down' : real) })
  const { journal, events } = recordingJournal()
  const cfg = ETH_CFG()
  const d = ethDeps(journal, { ethEndpoints: 2 })
  const tick = d.clock.sleep
  d.clock.sleep = async (ms: number) => { down--; await tick(ms) }
  assert.equal(await runCopiesLane(cfg, ethKey(), newLaneState(cfg), d), 'copies-done')
  assert.equal(events[0].type, 'paused')
  assert.match(String(events[0].reason), /1 of 2 answered, 2 needed/)
  assert.ok(types(events).indexOf('resumed') < types(events).indexOf('intent'))
  assert.equal(f.sends(), 1)
})

test('no endpoint can be read (the agreement read THROWS, not "disagree"): the lane pauses and re-reads — nothing signed — and resumes when they answer', async () => {
  let down = 3
  const f = ethTwo({ latest: (_ep, real) => (down > 0 ? 'down' : real) })
  const { journal, events } = recordingJournal()
  const cfg = ETH_CFG()
  const d = ethDeps(journal, { ethEndpoints: 2 })
  const tick = d.clock.sleep
  d.clock.sleep = async (ms: number) => { down--; await tick(ms) }
  assert.equal(await runCopiesLane(cfg, ethKey(), newLaneState(cfg), d), 'copies-done')
  assert.equal(events[0].type, 'paused')
  assert.match(String(events[0].reason), /could not be read/)
  assert.ok(types(events).indexOf('resumed') < types(events).indexOf('intent'))
  assert.equal(f.sends(), 1)
})

test('planE5 m-1: no endpoint can be read for retryMax rounds: the run ends `stopped` (the chain is not left PAUSED), nothing signed, and the test is bounded', async () => {
  const f = ethTwo({ latest: () => 'down' })
  const { journal, events } = recordingJournal()
  const cfg = ETH_CFG()
  const d = ethDeps(journal, { ethEndpoints: 2, retryMax: 4 })
  const tick = d.clock.sleep
  let sleeps = 0
  d.clock.sleep = async (ms: number) => { if (++sleeps > 12) throw new Error('unbounded: the read loop ignored retryMax'); await tick(ms) }   // a mutant that drops the bound fails here instead of hanging
  const lane = newLaneState(cfg)
  assert.equal(await runCopiesLane(cfg, ethKey(), lane, d), 'stopped')
  assert.deepEqual(types(events), ['paused', 'stopped'])
  assert.match(String(events[1].reason), /could not be read for 4 rounds/)
  assert.equal(lane.state, 'stopped')
  assert.equal(f.sends(), 0)
})

test('planE5 m-1 (security finding): with an ADOPTED attempt still open, retryMax ends the run with the read error (no `stopped` over an open attempt)', async () => {
  ethTwo({ latest: () => 'down' })
  const { journal, events } = recordingJournal()
  const cfg = ETH_CFG()
  const d = ethDeps(journal, { ethEndpoints: 2, retryMax: 4, resume: { copy: 1, nextPart: 1, adopted: { copy: 1, part: 1, nonce: 0, attempts: [] } } })
  const tick = d.clock.sleep
  let sleeps = 0
  d.clock.sleep = async (ms: number) => { if (++sleeps > 12) throw new Error('unbounded'); await tick(ms) }
  await assert.rejects(runCopiesLane(cfg, ethKey(), newLaneState(cfg), d), TransportError)
  assert.deepEqual(types(events), ['paused'])
})

test('one verified endpoint (the relay\'s count, or none passed): the preferred route alone, no pause', async () => {
  for (const extra of [{ ethEndpoints: 1 }, {}]) {
    const f = ethTwo()
    const { journal, events } = recordingJournal()
    const cfg = ETH_CFG()
    assert.equal(await runCopiesLane(cfg, ethKey(), newLaneState(cfg), ethDeps(journal, extra)), 'copies-done')
    assert.ok(!types(events).includes('paused'))
    assert.ok(f.reads.length > 0 && f.reads.every((r) => r.ep === null), 'no /ep route with one endpoint')
  }
})

test('an AGREED EIP-7702 delegation (every answering endpoint, the quorum met) → engine.eip7702: nothing signed, nothing sent', async () => {
  for (const [code, extra] of [
    [() => DELEGATED, {}],
    [() => DELEGATED, { ethEndpoints: 2 }],
    [(ep: string | null) => (ep === '1' ? DELEGATED.toUpperCase().replace('0X', '0x') : DELEGATED), { ethEndpoints: 3 }],
  ] as Array<[(ep: string | null) => string, Record<string, unknown>]>) {
    const f = ethTwo({ code })
    const { journal, events } = recordingJournal()
    const cfg = ETH_CFG()
    await assert.rejects(runCopiesLane(cfg, ethKey(), newLaneState(cfg), ethDeps(journal, extra)), (e: unknown) => guardIdOf(e) === 'engine.eip7702')
    assert.ok(!types(events).includes('intent'), 'no intent')
    assert.equal(f.sends(), 0, 'no send')
  }
})

test('fix round 2: endpoints that DISAGREE about the code (or too few answer, or agree on a non-delegation) PAUSE with engine.code-disagree — nothing signed; a Stop ends it with that reason', async () => {
  for (const [why, o, eps] of [
    ['(c1) one of two says delegated, the other 0x', { code: (ep: string | null) => (ep === '1' ? DELEGATED : '0x') }, 2],
    ['one of three says delegated', { code: (ep: string | null) => (ep === '0' ? DELEGATED : '0x') }, 3],
    ['(c3) two different delegations', { code: (ep: string | null) => (ep === '0' ? DELEGATED : DELEGATED2) }, 2],
    ['agreed contract code', { code: () => '0x6080604052' }, 2],
    ['one of two answered, delegated', { code: () => DELEGATED, latest: (ep: string | null, real: number) => (ep === '1' ? 'down' as const : real) }, 2],
  ] as Array<[string, Parameters<typeof ethTwo>[0], number]>) {
    const f = ethTwo(o)
    const { journal, events } = recordingJournal()
    const cfg = ETH_CFG()
    let rounds = 0
    const d = ethDeps(journal, { ethEndpoints: eps, stopRequested: () => events.some((e) => e.type === 'paused'), alive: () => ++rounds < 200 })
    assert.equal(await runCopiesLane(cfg, ethKey(), newLaneState(cfg), d), 'stopped', why)
    assert.deepEqual(types(events), ['paused', 'stopped'], why)
    assert.match(String(events[0].reason), /^engine\.code-disagree: the verified ETH endpoints do not agree on this key's account code/, why)
    assert.match(String(events[1].reason), /^stopped during reconcile — engine\.code-disagree: /, `${why}: the Stop names what was found`)
    assert.equal(f.sends(), 0, why)
  }
})

// The adapter's start read with an attempt adopted at a takeover (nonce 4): every endpoint's latest is 4; pending per endpoint.
async function adoptedStart(pending: Record<string, number>, o: { stopAfterPause?: boolean } = {}) {
  const chain = fakeEthChain()
  fakeRelay({ eth: (m, p, ep) => (m === 'eth_getTransactionCount' ? hx(p[1] === 'latest' ? 4 : pending[String(ep)]) : chain.handler(m, p)) })
  const emitted: Array<Record<string, unknown>> = []
  let rounds = 0
  const d = ethDeps(recordingJournal().journal, { ethEndpoints: 2, resume: { copy: 1, nextPart: 1, adopted: { copy: 1, part: 1, nonce: 4, attempts: [] } },
    ...(o.stopAfterPause ? { stopRequested: () => emitted.length > 0, alive: () => ++rounds < 200 } : { alive: () => emitted.length === 0 }) })
  const r = await ethAdapter(ETH_CFG(), ethKey(), d).reconcile(newLaneState(ETH_CFG()), async (e: Record<string, unknown>) => { emitted.push(e) })
  return { r, emitted }
}

test('an adopted attempt (nonce n) in one endpoint\'s pool and not the other\'s: they agree; a tx beyond it does not', async () => {
  const one = await adoptedStart({ 0: 5, 1: 4 })
  assert.equal(one.r, 'ok'); assert.deepEqual(one.emitted, [], 'pending n + 1 on one endpoint, n on the other: our attempt, the same')
  assert.equal((await adoptedStart({ 0: 5, 1: 5 })).r, 'ok')
  const beyond = await adoptedStart({ 0: 5, 1: 6 })
  assert.equal(beyond.emitted[0]?.type, 'paused')
  assert.match(String(beyond.emitted[0]?.reason), /engine\.nonce-disagree/)
  assert.equal(beyond.r, 'aborted', 'the lease check ends the pause')
})

test('an adopted attempt in flight: a Stop ends the disagreement pause (stopped, nothing signed; the attempt stays open for the next reconcile) — the operator always has a way out', async () => {
  const x = await adoptedStart({ 0: 5, 1: 7 }, { stopAfterPause: true })
  assert.match(String((x.r as { stopped?: string }).stopped), /^stopped during reconcile — engine\.nonce-disagree: /)
  assert.deepEqual(x.emitted.map((e) => e.type), ['paused'])
})

// ---------------- the ETH claw-back: the nonce quorum; no engine.eip7702 (the rescue path) ----------------

const DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
function clawTwo(o: { latest?: (ep: string | null) => number; laneCode?: string; laneCodeAt?: (ep: string | null) => string }) {
  let block = 10
  const sent: string[] = [], reads: Array<string | null> = []
  const isDest = (a: unknown): boolean => String(a).toLowerCase() === DEST.toLowerCase()
  const relay = fakeRelay({ eth: (m, p, ep) => {
    switch (m) {
      case 'eth_getTransactionCount': if (isDest(p[0])) return '0x3'; reads.push(ep); return hx(o.latest ? o.latest(ep) : 0)
      case 'eth_getBalance': return isDest(p[0]) ? '0x5' : hx(10n ** 16n)
      case 'eth_getCode': return isDest(p[0]) ? '0x' : o.laneCodeAt ? o.laneCodeAt(ep) : o.laneCode ?? '0x'
      case 'eth_feeHistory': { const n = Number(BigInt(p[0])); return { oldestBlock: hx(block - n + 1), baseFeePerGas: Array.from({ length: n + 1 }, () => hx(10n ** 9n)), reward: Array.from({ length: n }, () => [hx(10n ** 9n)]) } }
      case 'eth_estimateGas': return hx(21_000)
      case 'eth_blockNumber': return hx(block++)
      case 'eth_sendRawTransaction': sent.push(String(p[0])); return keccak256(p[0] as `0x${string}`)
      case 'eth_getTransactionReceipt': return sent[0] && keccak256(sent[0] as `0x${string}`) === p[0] ? { transactionHash: p[0], blockNumber: hx(block), gasUsed: hx(21_000), effectiveGasPrice: hx(2n * 10n ** 9n), status: '0x1' } : null
      case 'eth_getTransactionByHash': { const raw = sent.find((r) => keccak256(r as `0x${string}`) === p[0]); if (!raw) return null; const t = parseTransaction(raw as `0x${string}`); return { hash: p[0], to: t.to, value: hx(t.value ?? 0n), input: '0x', blockNumber: hx(block) } }
      default: return undefined
    }
  } })
  const { journal, events } = recordingJournal()
  const key = { account: privateKeyToAccount(generatePrivateKey()) }
  return { relay, events, sent, reads, go: (delegated?: (w: string) => void) => clawbackEth(key, DEST, { ...(delegated ? { delegated } : {}), journal, network: 'local', chainId: 31337, poll: 1, state: armedState('eth', 10n ** 18n), ethEndpoints: 2 }) }
}

function clawTwoPending(o: { latest?: (ep: string | null) => number; laneCode?: string; laneCodeAt?: (ep: string | null) => string } = { laneCode: DELEGATED }) {
  let block = 10
  const sent: string[] = [], reads: Array<string | null> = []
  const isDest = (a: unknown): boolean => String(a).toLowerCase() === DEST.toLowerCase()
  const relay = fakeRelay({ eth: (m, p, ep) => {
    switch (m) {
      case 'eth_getTransactionCount': if (isDest(p[0])) return '0x3'; reads.push(ep); return p[1] === 'pending' ? '0x1' : '0x0'
      case 'eth_getBalance': return isDest(p[0]) ? '0x5' : hx(10n ** 16n)
      case 'eth_getCode': return isDest(p[0]) ? '0x' : o.laneCodeAt ? o.laneCodeAt(ep) : o.laneCode ?? '0x'
      case 'eth_feeHistory': { const n = Number(BigInt(p[0])); return { oldestBlock: hx(block - n + 1), baseFeePerGas: Array.from({ length: n + 1 }, () => hx(10n ** 9n)), reward: Array.from({ length: n }, () => [hx(10n ** 9n)]) } }
      case 'eth_estimateGas': return hx(21_000)
      case 'eth_blockNumber': return hx(block++)
      case 'eth_sendRawTransaction': sent.push(String(p[0])); return keccak256(p[0] as `0x${string}`)
      case 'eth_getTransactionReceipt': return sent[0] && keccak256(sent[0] as `0x${string}`) === p[0] ? { transactionHash: p[0], blockNumber: hx(block), gasUsed: hx(21_000), effectiveGasPrice: hx(2n * 10n ** 9n), status: '0x1' } : null
      case 'eth_getTransactionByHash': { const raw = sent.find((r) => keccak256(r as `0x${string}`) === p[0]); if (!raw) return null; const t = parseTransaction(raw as `0x${string}`); return { hash: p[0], to: t.to, value: hx(t.value ?? 0n), input: '0x', blockNumber: hx(block) } }
      default: return undefined
    }
  } })
  const { journal, events } = recordingJournal()
  const key = { account: privateKeyToAccount(generatePrivateKey()) }
  return { relay, events, sent, reads, go: (delegated?: (w: string) => void) => clawbackEth(key, DEST, { ...(delegated ? { delegated } : {}), journal, network: 'local', chainId: 31337, poll: 1, state: armedState('eth', 10n ** 18n), ethEndpoints: 2 }) }
}

test('ETH claw-back: the endpoints disagree on the nonce → refused engine.nonce-disagree, nothing signed or sent', async () => {
  const c = clawTwo({ latest: (ep) => (ep === '1' ? 1 : 0) })
  await assert.rejects(c.go(), (e: unknown) => guardIdOf(e) === 'engine.nonce-disagree')
  assert.ok(!c.events.some((e) => e.type === 'clawback-intent'))
  assert.equal(c.sent.length, 0)
  assert.deepEqual([...new Set(c.reads)].sort(), ['0', '1'])
})

test('ETH claw-back from a delegated account is NOT refused (a transfer FROM it runs none of its code): it signs at the agreed nonce and lands', async () => {
  const c = clawTwo({ laneCode: DELEGATED })
  const res = await c.go()
  assert.equal(res.ok, true)
  assert.equal(c.sent.length, 1)
  assert.equal(parseTransaction(c.sent[0] as `0x${string}`).nonce, 0)
  assert.deepEqual(c.events.map((e) => e.type), ['note', 'clawback-intent', 'clawback-sent', 'clawback-included', 'clawback-readback'])
  // planE5 ruling C2 (core side): the delegated claw-back carries the warning (journal note + result) and a boolean the CLI/page can show
  assert.equal(res.delegated, true)
  assert.equal(res.warning, 'this key is delegated (EIP-7702); someone holding the authorization may move funds — claw back now')
  assert.equal(c.events[0].text, res.warning)
})

test('planE5 C2: a claw-back from a key with NO delegation has delegated=false, no warning, no note', async () => {
  const c = clawTwo({})
  const res = await c.go()
  assert.equal(res.ok, true); assert.equal(res.delegated, false); assert.equal(res.warning, '')
  assert.ok(!c.events.some((e) => e.type === 'note'))
})

test('planE5 C2: ONE of two endpoints showing the delegation is enough to warn (the claw-back still goes ahead)', async () => {
  const c = clawTwo({ laneCodeAt: (ep) => (ep === '1' ? DELEGATED : '0x') })
  const res = await c.go()
  assert.equal(res.delegated, true); assert.equal(res.ok, true)
})

// ---------------- SOL: every send and rebroadcast to every verified endpoint, one ticket, one txId ----------------

function solTwo(o: { hideStatuses?: number } = {}) {
  const chain = fakeSolChain()
  const answered: Array<[string | null, unknown]> = []
  let hide = o.hideStatuses ?? 0
  const relay = fakeRelay({ sol: (m, p, ep) => {
    if (m === 'getSignatureStatuses' && hide > 0) { hide--; return { context: { slot: 600 }, value: (p[0] as string[]).map(() => null) } }
    const r = chain.handler(m, p)
    if (m === 'sendTransaction') answered.push([ep, r])
    return r
  } })
  return { chain, relay, answered }
}
const solRun = async (s: ReturnType<typeof solTwo>, extra: Record<string, unknown>) => {
  const { journal, events } = recordingJournal()
  const cfg = cfgOf('sol', { mode: 'copies', copies: 1, distinct: true, feeStrategy: 'passive' }, 'Endpoint agreement, Solana.')
  const r = await runCopiesLane(cfg, solKey(), newLaneState(cfg), { journal, network: 'local', state: armedState('sol', 10n ** 9n), poll: 1, alive: () => true, notify: async () => {}, clock: fakeClock(), reconciled: true, ...extra })
  return { r, events }
}
test('Eminors (Efix3 m-4): a SOL lane started without the executor reconcile on an address that already sent memo txs fails closed (no one-endpoint wait heuristic); an address with none starts', { timeout: 30_000 }, async () => {
  const kp = solKey()
  for (const sent of [true, false]) {
    const chain = fakeSolChain()
    fakeRelay({ sol: (m, p) => {
      if (m === 'getSignaturesForAddress') return sent ? [{ signature: 'S'.repeat(88), memo: '[1] earlier' }] : []
      if (m === 'getTransaction' && p[0] === 'S'.repeat(88)) return { transaction: { message: { accountKeys: [kp.kp.publicKey.toBase58()] } } }
      return chain.handler(m, p)
    } })
    const { journal } = recordingJournal()
    const cfg = cfgOf('sol', { mode: 'copies', copies: 1, distinct: true, feeStrategy: 'passive' }, 'Endpoint agreement, Solana.')
    const go = runCopiesLane(cfg, kp, newLaneState(cfg), { journal, network: 'local', state: armedState('sol', 10n ** 9n), poll: 1, alive: () => true, notify: async () => {}, clock: fakeClock() })
    if (sent) await assert.rejects(go, /without the executor's reconcile/)
    else assert.equal(await go, 'copies-done')
  }
})
const sigOf = (b64: unknown): string => base58.encode(VersionedTransaction.deserialize(base64.decode(String(b64))).signatures[0])

test('SOL: the send reaches BOTH verified endpoints (/relay/sol/ep/0 and /ep/1) with one ticket and identical bytes; the txId is the same', async () => {
  const s = solTwo()
  const { r, events } = await solRun(s, { solEndpoints: 2 })
  assert.equal(r, 'copies-done')
  const sends = s.relay.sends()
  assert.deepEqual(sends.map((c) => c.ep).sort(), ['0', '1'], 'each verified endpoint, by its own route')
  assert.equal(sends.filter((c) => c.ep === null).length, 0, 'not the preferred route as well')
  assert.equal(sends[0].params[0], sends[1].params[0], 'identical signed bytes')
  assert.ok(sends[0].ticket?.startsWith(TICKET_PREFIX)); assert.equal(sends[0].ticket, sends[1].ticket, 'the same ticket')
  const intent = events.find((e) => e.type === 'intent')!, sig = sigOf(sends[0].params[0])
  assert.equal(intent.txId, sig, 'the journaled txId is the signature of the bytes sent')
  assert.deepEqual(s.answered.map(([, x]) => x), [sig, sig], 'both endpoints answered that signature')
  assert.equal(events.find((e) => e.type === 'sent')!.outcome, 'accepted')
  assert.equal(events.filter((e) => e.type === 'sent').length, 1, 'one sent per attempt, not per endpoint')
  assert.equal(events.find((e) => e.type === 'included')!.txId, sig)
})

test('SOL: a rebroadcast under the same ticket goes through the preferred route with that ticket and the identical bytes (the endpoints had it once: Sfix1)', async () => {
  const s = solTwo({ hideStatuses: 2 })
  const { r, events } = await solRun(s, { solEndpoints: 2 })
  assert.equal(r, 'copies-done')
  const re = s.relay.sends().filter((c) => (c.params[1] as { skipPreflight?: boolean }).skipPreflight === true)
  assert.ok(re.length >= 1, `rebroadcasts (${re.length})`)
  assert.ok(re.every((c) => c.ep === null), 'the preferred route only')
  const first = s.relay.sends()[0]
  assert.ok(re.every((c) => c.ticket === first.ticket && c.params[0] === first.params[0]))
  assert.equal(events.filter((e) => e.type === 'intent').length, 1, 'never a new signature')
})

test('Sfix1: one ticket makes ONE per-endpoint round — the send to ep/0 + ep/1; every rebroadcast under that ticket goes to the preferred route only (zero ep requests); a fresh ticket gets a new round', { timeout: 30_000 }, async () => {
  const chain = fakeSolChain()
  const spent = new Set<string>()                                              // the relay's once-per-ticket-per-endpoint ledger (Sfix1)
  let hide = 60
  const relay = fakeRelay({ sol: (m, p, ep) => {
    if (m === 'sendTransaction' && ep !== null) {
      const k = `${relay.calls.at(-1)!.ticket}|${ep}`
      if (spent.has(k)) throw relayRefusal('relay.ticket-endpoint-reused')
      spent.add(k)
    }
    if (m === 'getSignatureStatuses' && hide > 0) { hide--; return { context: { slot: 600 }, value: (p[0] as string[]).map(() => null) } }
    return chain.handler(m, p)
  } })
  const rec = recordingJournal()
  let n = 0
  const journal = { ...rec.journal, ticket: async (txId: string) => ticketFor(`${txId}#${++n}`) }   // a fresh ticket of the same intent
  const cfg = cfgOf('sol', { mode: 'copies', copies: 1, distinct: true, feeStrategy: 'passive' }, 'Endpoint agreement, Solana.')
  const r = await runCopiesLane(cfg, solKey(), newLaneState(cfg), { journal, network: 'local', state: armedState('sol', 10n ** 9n), poll: 1, alive: () => true, notify: async () => {}, clock: fakeClock(), reconciled: true, solEndpoints: 2 })
  assert.equal(r, 'copies-done')
  const sends = relay.sends().map((c) => ({ ep: c.ep, ticket: c.ticket!, re: (c.params[1] as { skipPreflight?: boolean }).skipPreflight === true }))
  const tickets = [...new Set(sends.map((x) => x.ticket))]
  assert.ok(tickets.length >= 2, `a refresh happened (${tickets.length} tickets over ${sends.length} sends)`)
  for (const [k, t] of tickets.entries()) {
    const under = sends.filter((x) => x.ticket === t)
    const eps = under.filter((x) => x.ep !== null)
    assert.deepEqual(eps.map((x) => x.ep).sort(), ['0', '1'], `ticket ${k + 1}: one per-endpoint round, each endpoint once`)
    const firstPreferred = under.findIndex((x) => x.ep === null)
    assert.ok(firstPreferred === -1 || under.slice(firstPreferred).every((x) => x.ep === null), `ticket ${k + 1}: after its round, the preferred route only`)
    if (k === 0) assert.equal(under[0].re, false, 'the first round is the send itself')
  }
  const rebroadcastsT1 = sends.filter((x) => x.ticket === tickets[0] && x.re)
  assert.ok(rebroadcastsT1.length >= 10 && rebroadcastsT1.every((x) => x.ep === null), `rounds 2..n under the first ticket: preferred route only (${rebroadcastsT1.length})`)
  assert.equal(relay.calls.filter((c) => c.method === 'sendTransaction' && c.ep !== null).length, 2 * tickets.length, 'zero repeat ep requests: never refused relay.ticket-endpoint-reused')
  assert.equal(rec.events.filter((e) => e.type === 'intent').length, 1, 'one signature throughout')
})

test('SOL with one verified endpoint (or none passed): the preferred route alone', async () => {
  for (const extra of [{ solEndpoints: 1 }, {}]) {
    const s = solTwo()
    assert.equal((await solRun(s, extra)).r, 'copies-done')
    assert.deepEqual(s.relay.sends().map((c) => c.ep), [null])
  }
})

test('postSol: accepted if any endpoint accepted; unknown before rejected; a node-side hiccup is the rejection kept; another signature is no answer', async () => {
  const id = base58.encode(new Uint8Array(64).fill(9)), o = { solEndpoints: 2 }
  const rej = (msg: string): never => { throw new RpcError({ code: -32002, message: msg }) }
  assert.equal((await postSol(o, id, async (ep) => (ep === 0 ? rej('Transaction simulation failed: custom program error: 0x1') : id))).kind, 'accepted')
  assert.equal((await postSol(o, id, async (ep) => { if (ep === 0) throw new TransportError('timeout'); return rej('custom program error') })).kind, 'unknown')
  assert.equal((await postSol(o, id, async (ep) => { if (ep === 1) throw new RelayRefused('relay refused (403)'); throw new TransportError('timeout') })).kind, 'unknown')
  // planE5 m-3 (Efix3, single-endpoint trust): MIXED answers (one endpoint's definitive rejection, another's hiccup) are neither
  // accepted nor rejected: `unknown` — the attempt stays open and tracked, never failed / declared dead on one endpoint's word
  for (const swap of [false, true]) {
    const both = await postSol(o, id, async (ep) => rej((ep === 0) !== swap ? 'custom program error: 0x1' : 'Transaction simulation failed: Blockhash not found'))
    assert.equal(both.kind, 'unknown', `mixed answers are not a rejection (order ${swap})`); assert.match(both.msg, /endpoints disagree/)
    const funds = await postSol(o, id, async (ep) => rej((ep === 0) !== swap ? 'insufficient funds' : 'Blockhash not found'))
    assert.equal(funds.kind, 'unknown')
  }
  // every answering endpoint rejecting the same way IS a rejection
  assert.equal((await postSol(o, id, async () => rej('custom program error: 0x1'))).kind, 'rejected')
  const hiccups = await postSol(o, id, async (ep) => rej(ep === 0 ? 'Blockhash not found' : 'node is behind by 40 slots'))
  assert.equal(hiccups.kind, 'rejected'); assert.match(hiccups.msg, /Blockhash not found|behind/, 'hiccups only: still retried by solTx')
  // planE5 m-2 (Efix3): every route refused → the reason is the preferred route's own refusal (the fallback), not endpoint 0's
  const lock = await postSol(o, id, async (ep) => { throw new RelayRefused(ep === null ? 'relay refused (403): the mainnet job-send lock is on' : 'relay refused (403): sends go through /relay/<chain> only') })
  assert.equal(lock.kind, 'rejected'); assert.match(lock.msg, /job-send lock/)
  const dead = await postSol(o, id, async () => rej('custom program error: 0x1'))
  assert.equal(dead.kind, 'rejected'); assert.match(dead.msg, /custom program error/)
  assert.equal((await postSol(o, id, async () => base58.encode(new Uint8Array(64).fill(8)))).kind, 'unknown', 'an endpoint naming another signature')
  assert.equal((await postSol(o, id, async () => rej('Transaction simulation failed: This transaction has already been processed'))).kind, 'accepted')
  const asked: Array<number | null> = []
  await postSol({ solEndpoints: 3 }, id, async (ep) => { asked.push(ep); return id })
  assert.deepEqual(asked.sort(), [0, 1, 2])
  asked.length = 0
  await postSol({}, id, async (ep) => { asked.push(ep); return id })
  assert.deepEqual(asked, [null], 'one endpoint known: the preferred route')
  await assert.rejects(postSol(o, id, async () => { throw Object.assign(new Error('x'), { name: 'Refusal', guardId: 'engine.no-ticket' }) }), (e: unknown) => guardIdOf(e) === 'engine.no-ticket', 'a refusal is fatal, never an outcome')
})

// ---------------- the executor passes the relay's verified endpoint counts ----------------

test('executor: the relay verified 2 ETH endpoints → the lane reads both (/ep/0, /ep/1); while they disagree it pauses, then completes', { timeout: 60_000 }, async () => {
  let disagree = 4
  const eps = new Set<number>()
  const s = stack('eth', { copies: 1, startIn: 0, ethEndpoints: 2, eth: (m, p, base, ep) => {
    if (m === 'eth_getTransactionCount' && ep !== null) { eps.add(ep); if (ep === 1 && p[1] === 'latest' && disagree-- > 0) return hx(Number(BigInt(base(m, p) as string)) + 1) }
    return base(m, p)
  } })
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: exDeps(s) })
  assert.equal(await ex.start(), 'copies-done')
  assert.deepEqual([...eps].sort(), [0, 1])
  const mine = s.j.events.filter((e) => e.chain === 'eth' && e.by === 'cli')
  const p = mine.findIndex((e) => e.type === 'paused'), r = mine.findIndex((e) => e.type === 'resumed'), i = mine.findIndex((e) => e.type === 'intent')
  assert.ok(p >= 0 && p < r && r < i, 'paused, resumed, then the first intent')
  assert.match(String(mine[p].data.reason), /engine\.nonce-disagree/)
})

test('executor: the relay verified 2 SOL endpoints → the send goes to both with the one ticket of the journaled intent', { timeout: 60_000 }, async () => {
  const s = stack('sol', { copies: 1, startIn: 0, endpoints: 2 })
  const ex = createExecutor({ jobId: s.j.id, chain: 'sol', key: s.key, holder: 'cli', deps: exDeps(s) })
  assert.equal(await ex.start(), 'copies-done')
  const sends = s.relay.sends()
  assert.deepEqual(sends.map((c) => c.ep).sort(), [0, 1])
  assert.equal(sends[0].ticket, sends[1].ticket)
  const intent = s.j.events.find((e) => e.type === 'intent')!
  assert.equal(sigOf(sends[0].params[0]), intent.data.txId)
  assert.equal(sigOf(sends[1].params[0]), intent.data.txId)
})

// ---------------- security review finding: the rescue paths through the new code ----------------
// The relay of today refuses every send on /relay/<chain>/ep/<i> (403 before forwarding: nothing left the machine). A
// SOL send that went ONLY to the per-endpoint routes would then never leave on a relay with ≥ 2 SOL endpoints
// (mainnet) — the lane's parts, and the SOL claw-back, the rescue path. postSol now also uses the preferred route when the
// relay itself refused a per-endpoint send and no endpoint accepted.

const epRefusing = (base: (m: string, p: any[]) => unknown, o: { hide?: number } = {}) => {
  let hide = o.hide ?? 0
  return (m: string, p: any[], ep: string | null): unknown => {
    if (m === 'sendTransaction' && ep !== null) throw relayRefusal()
    if (m === 'getSignatureStatuses' && hide > 0) { hide--; return { context: { slot: 600 }, value: (p[0] as string[]).map(() => null) } }
    return base(m, p)
  }
}

test('rescue: a relay that refuses per-endpoint sends (today\'s relay, ≥ 2 SOL endpoints) — the lane\'s SOL part still leaves through the preferred route, once per send', async () => {
  const chain = fakeSolChain()
  const relay = fakeRelay({ sol: epRefusing(chain.handler) })
  const { journal, events } = recordingJournal()
  const cfg = cfgOf('sol', { mode: 'copies', copies: 1, distinct: true, feeStrategy: 'passive' }, 'Endpoint agreement, Solana.')
  const r = await runCopiesLane(cfg, solKey(), newLaneState(cfg), { journal, network: 'local', state: armedState('sol', 10n ** 9n), poll: 1, alive: () => true, notify: async () => {}, clock: fakeClock(), reconciled: true, solEndpoints: 2 })
  assert.equal(r, 'copies-done')
  const sends = relay.sends()
  assert.deepEqual(sends.map((c) => c.ep), ['0', '1', null], 'both endpoint routes refused by the relay, then the preferred route')
  assert.ok(sends.every((c) => c.ticket === sends[0].ticket && c.params[0] === sends[0].params[0]), 'one ticket, identical bytes')
  assert.equal(events.find((e) => e.type === 'sent')!.outcome, 'accepted')
  assert.equal(events.filter((e) => e.type === 'intent').length, 1)
})

// a SOL claw-back fake: the transfer's own record (pre/post balances), as clawback-journal.test.ts's solClaw
function solClawFake() {
  const base = fakeSolChain(), sent = new Map<string, Uint8Array>()
  const handler = (m: string, p: any[]): unknown => {
    if (m === 'sendTransaction') { const raw = base64.decode(String(p[0])), sig = sigOf(p[0]); sent.set(sig, raw); return sig }
    if (m === 'getSignatureStatuses') return { context: { slot: 600 }, value: (p[0] as string[]).map((x) => (sent.has(x) ? { slot: 501, confirmations: 1, err: null, confirmationStatus: 'confirmed' } : null)) }
    if (m === 'getTransaction') {
      const raw = sent.get(String(p[0])); if (!raw) return null
      const msg = VersionedTransaction.deserialize(raw).message, keys = msg.staticAccountKeys.map((k) => k.toBase58())
      const lamports = new DataView(msg.compiledInstructions[0].data.buffer, msg.compiledInstructions[0].data.byteOffset).getBigUint64(4, true)
      return { slot: 501, meta: { err: null, fee: 5000, preBalances: keys.map(() => 1_000), postBalances: keys.map((_k, i) => (i === 1 ? 1_000 + Number(lamports) : 1_000)) }, transaction: { message: { accountKeys: keys } } }
    }
    return base.handler(m, p)
  }
  return { handler, sent }
}

test('rescue: the SOL claw-back (and its wait\'s rebroadcasts) through a relay that refuses per-endpoint sends still claws back, with the executor\'s deps (no notify)', { timeout: 30_000 }, async () => {
  const c = solClawFake()
  const relay = fakeRelay({ sol: epRefusing(c.handler, { hide: 2 }) })
  const { journal, events } = recordingJournal()
  const kp = Keypair.generate(), dest = Keypair.generate().publicKey.toBase58()
  await clawbackSol({ chain: 'sol', kp }, dest, { journal, network: 'local', poll: 1, alive: () => true, clock: fakeClock(), solEndpoints: 2, state: armedState('sol', 10n ** 12n) })
  assert.deepEqual(events.map((e) => e.type), ['clawback-intent', 'clawback-sent', 'clawback-included', 'clawback-readback'])
  assert.equal(events[1].outcome, 'accepted')
  const preferred = relay.sends().filter((x) => x.ep === null)
  assert.ok(preferred.length >= 2, 'the send and at least one rebroadcast left through the preferred route')
  assert.equal(c.sent.size, 1, 'one signature: never a second claw-back')
  assert.equal(relay.calls.filter((x) => x.method === 'sendTransaction' && x.ep !== null).length, 2, 'one per-endpoint round for the ticket (Sfix1): the rebroadcasts never ask the endpoints again')
})

test('rescue: postSol — the preferred route joins only when the relay refused a per-endpoint send and none accepted; its answer counts like any other', async () => {
  const id = base58.encode(new Uint8Array(64).fill(9)), o = { solEndpoints: 2 }
  const asked: Array<number | null> = []
  const refused = (): never => { throw new RelayRefused('relay refused (403): sends go through /relay/<chain> only') }
  const rpcRej = (msg: string): never => { throw new RpcError({ code: -32002, message: msg }) }
  // both refused by the relay → the preferred route accepts → accepted
  assert.equal((await postSol(o, id, async (ep) => { asked.push(ep); return ep === null ? id : refused() })).kind, 'accepted')
  assert.deepEqual([...asked], [0, 1, null]); asked.length = 0
  // one refused by the relay, the other's upstream rejected (preflight) → the preferred route too; it is unreachable → unknown (never dead)
  assert.equal((await postSol(o, id, async (ep) => { asked.push(ep); if (ep === null) throw new TransportError('timeout'); return ep === 0 ? refused() : rpcRej('custom program error: 0x1') })).kind, 'unknown')
  assert.deepEqual([...asked], [0, 1, null]); asked.length = 0
  // every route refused by the relay (a relay-side refusal of the bytes themselves) → rejected, nothing forwarded
  const all = await postSol(o, id, async (ep) => { asked.push(ep); return refused() })
  assert.equal(all.kind, 'rejected'); assert.deepEqual([...asked], [0, 1, null]); asked.length = 0
  // one endpoint accepted → no extra route
  assert.equal((await postSol(o, id, async (ep) => { asked.push(ep); return ep === 1 ? id : refused() })).kind, 'accepted')
  assert.deepEqual([...asked], [0, 1]); asked.length = 0
  // upstream rejections only (no relay refusal) → no extra route
  await postSol(o, id, async (ep) => { asked.push(ep); return rpcRej('custom program error: 0x1') })
  assert.deepEqual([...asked], [0, 1])
})

test('rescue: the ETH claw-back refused on a disagreement (or an unreadable endpoint set) journals nothing and signs nothing; once they agree, the same claw-back runs', async () => {
  let state: 'disagree' | 'down' | 'ok' = 'disagree'
  const c = clawTwo({ latest: (ep) => { if (state === 'down') throw transportFailure(); return state === 'disagree' && ep === '1' ? 1 : 0 } })
  await assert.rejects(c.go(), (e: unknown) => guardIdOf(e) === 'engine.nonce-disagree')
  state = 'down'
  await assert.rejects(c.go(), TransportError)
  assert.equal(c.events.length, 0, 'nothing journaled by the refused claw-backs')
  assert.equal(c.sent.length, 0)
  state = 'ok'
  const res = await c.go()
  assert.equal(res.ok, true)
  assert.deepEqual(c.events.map((e) => e.type), ['clawback-intent', 'clawback-sent', 'clawback-included', 'clawback-readback'])
})

test('rescue (executor): a relay that refuses per-endpoint sends with 2 SOL endpoints — the run still completes through the preferred route', { timeout: 60_000 }, async () => {
  const s = stack('sol', { copies: 1, startIn: 0, endpoints: 2, sol: (m, p, ep, base) => { if (m === 'sendTransaction' && ep !== null) throw relayRefusal(); return base(m, p) } })
  const ex = createExecutor({ jobId: s.j.id, chain: 'sol', key: s.key, holder: 'cli', deps: exDeps(s) })
  assert.equal(await ex.start(), 'copies-done')
  assert.deepEqual(s.relay.sends().map((c) => c.ep), [0, 1, null])
})

// ---------------- fix round 1 (review I-1): engine.eip7702 ends the chain cleanly ----------------
// The lane starts no new send on a delegated key (or one an endpoint says is delegated); the run reconciles every open
// intent from the chain first (read-only), then journals `stopped` with the delegation reason, so the chain settles and
// the claw-back (C2) can rescue the remainder. A requested Stop is honoured before any rethrow.
const NULL_TO = '0x0000000000000000000000000000000000000000'
const CLAW_DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
type Hook = (m: string, p: any[], base: (m: string, p: any[]) => unknown, ep: number | null) => unknown
// A copies-2 job whose copy 1 landed under an earlier holder (gen 2: copy-built, intent, sent, included, readback), then
// that holder died (lease expired): the chain is RUNNING with nothing open. o.hook sees every ETH read (after `lane` is set).
async function landedPartStack(o: { hook?: Hook; ethEndpoints?: number } = {}) {
  let ready = false
  const s = stack('eth', { copies: 2, startIn: 0, ethBalance: 3n * 10n ** 17n, cap: '1000000000000000000', ...(o.ethEndpoints !== undefined ? { ethEndpoints: o.ethEndpoints } : {}),
    eth: (m, p, base, ep) => (ready && o.hook ? o.hook(m, p, base, ep) : base(m, p)) })
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  useRelayClient(s.relay.client)
  const cfg = laneConfigOf('eth', s.def.chains.eth!, s.text), payload = planLaneCopy(cfg, 1)[0].payload
  const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL_TO, data: toHex(payload), gas: 60_000n, maxFee: 3n * 10n ** 9n, tip: 10n ** 9n })
  const id = signed.id.toLowerCase()
  await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [signed.raw])
  const m = s.ethChain.mined.get(id)!
  s.j.asHolder(2, 'browser', 'eth', 'copy-built', { copy: 1, parts: 1, bytes: [payload.length], tight: false, level: 0 })
  s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: String(60_000n * 3n * 10n ** 9n), eth: { nonce: 0, tip: String(10n ** 9n), maxFee: String(3n * 10n ** 9n), gas: '60000', to: NULL_TO } })
  s.j.asHolder(2, 'browser', 'eth', 'sent', { txId: id, outcome: 'accepted', reason: null })
  s.j.asHolder(2, 'browser', 'eth', 'included', { txId: id, copy: 1, part: 1, attempt: 1, block: String(m.block), fee: String(m.gasUsed * m.price), ms: 1 })
  s.j.asHolder(2, 'browser', 'eth', 'readback', { txId: id, ok: true, detail: 'part bytes' })
  s.j.expire('eth')
  ready = true
  return { s, landedId: id }
}
const delegatedFor = (s: { key: { address: string } }, eps?: Array<number | null>): Hook => (m, p, base, ep) =>
  (m === 'eth_getCode' && String(p[0]).toLowerCase() === s.key.address.toLowerCase() && (eps === undefined || eps.includes(ep)) ? DELEGATED : base(m, p))
const run3 = (s: ReturnType<typeof stack>) => s.j.events.filter((e) => e.chain === 'eth' && e.by === 'cli' && (e.gen ?? 0) >= 3)
async function clawsBack(s: ReturnType<typeof stack>): Promise<ReturnType<typeof createExecutor>> {
  const claw = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: exDeps(s) })
  assert.equal(await claw.clawback(CLAW_DEST), 'clawed-back', claw.view().note)
  assert.equal(s.j.state().chains.eth!.phase, 'CLAWED_BACK')
  return claw
}

test('fix round 1 (a): a delegated key with a landed part — the rerun ends `stopped` (reason engine.eip7702), signs nothing, and the claw-back succeeds', { timeout: 60_000 }, async () => {
  let hook: Hook | undefined
  const { s } = await landedPartStack({ hook: (m, p, base, ep) => hook!(m, p, base, ep) })
  hook = delegatedFor(s)
  assert.equal(s.j.state().chains.eth!.phase, 'RUNNING', 'not settled: before the fix this chain could not be clawed back')
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: exDeps(s) })
  assert.equal(await ex.start(), 'stopped')
  assert.equal(ex.view().delegated, true, 'm-5: a chain that stopped for its delegation says delegated')
  const mine = run3(s)
  assert.deepEqual(mine.map((e) => e.type), ['stopped'])
  assert.match(String(mine[0].data.reason), /^engine\.eip7702: .*EIP-7702 delegation/)
  assert.equal(mine[0].data.delegated, true, 'Eminors: the stop carries the structured field')
  assert.equal(s.j.state().chains.eth!.phase, 'STOPPED')
  assert.equal(s.j.state().chains.eth!.delegated, true, 'Eminors: and the reducer surfaces it')
  assert.equal(s.relay.sends().length, 1, 'only the earlier holder\'s part: nothing new signed or sent')
  // R79b: the stop's code is eip7702 (final); a resume (the real API refuses it, resume.final-stop) never reopens it
  assert.deepEqual([mine[0].data.code, s.j.state().chains.eth!.stopClass], ['eip7702', 'final'])
  s.j.apiEvent('resume-requested', { chain: 'eth' }, null)
  const n = s.j.events.length
  const again = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: exDeps(s) })
  assert.equal(await again.start(), 'stopped')
  assert.deepEqual(s.j.events.slice(n).filter((e) => e.by === 'cli').map((e) => e.type), [], 'R79b: not reopened, nothing journaled')
  assert.match(again.view().note, /stopped for good: .*\(eip7702\)/)
  const claw = await clawsBack(s)
  // planE5 ruling C2 (core side): the executor's view carries the boolean and the warning for the CLI / page
  assert.equal(claw.view().delegated, true)
  assert.match(claw.view().note, /this key is delegated \(EIP-7702\); someone holding the authorization may move funds — claw back now/)
})

test('fix round 1 (b): the same, settled through the API\'s Stop (stop-requested, no injected `stopped`): the Stop is honoured before the refusal is rethrown, then the claw-back succeeds', { timeout: 60_000 }, async () => {
  let hook: Hook | undefined
  const { s } = await landedPartStack({ hook: (m, p, base, ep) => hook!(m, p, base, ep) })
  hook = delegatedFor(s)
  s.j.requestStop('eth')
  assert.equal(s.j.state().chains.eth!.phase, 'RUNNING', 'the API\'s Stop alone does not settle a chain with a tx')
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: exDeps(s) })
  assert.equal(await ex.start(), 'stopped')
  const mine = run3(s)
  assert.deepEqual(mine.map((e) => e.type), ['stopped'])
  assert.match(String(mine[0].data.reason), /^stopped during reconcile — engine\.eip7702: .*EIP-7702 delegation/, 'the operator\'s Stop took it, before any rethrow — and names the delegation (fix round 2)')
  assert.deepEqual([mine[0].data.code, s.j.state().chains.eth!.stopClass], ['eip7702', 'final'], 'R79b: the delegation it names makes the stop final')
  assert.equal(s.j.state().chains.eth!.phase, 'STOPPED')
  assert.equal(s.relay.sends().length, 1)
  await clawsBack(s)
})

const pausedOn = async (s: ReturnType<typeof stack>, gen: number): Promise<void> => {
  const paused = (): boolean => s.j.events.some((e) => e.type === 'paused' && e.gen === gen)
  for (let i = 0; i < 300 && !paused(); i++) await s.clock.sleep(1_000)   // bounded: a mutant that never pauses fails here, never hangs
  assert.ok(paused(), `paused (gen ${gen})`)
}

test('fix round 2 (c1): ONE of two endpoints lies with non-0x code, the other says 0x — PAUSED (engine.code-disagree), no part signed; then Stop + a rerun → `stopped` → the claw-back succeeds', { timeout: 60_000 }, async () => {
  let hook: Hook | undefined
  const { s } = await landedPartStack({ ethEndpoints: 2, hook: (m, p, base, ep) => hook!(m, p, base, ep) })
  hook = delegatedFor(s, [1])
  const run1 = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: exDeps(s) })
  const r1 = run1.start()
  await pausedOn(s, 3)
  assert.match(String(s.j.events.find((e) => e.type === 'paused' && e.gen === 3)!.data.reason), /^engine\.code-disagree: /)
  assert.equal(s.j.state().chains.eth!.phase, 'PAUSED')
  s.j.expire('eth')                                                            // the operator closes the paused run (its lease lapses)
  assert.equal(await r1, 'lease-lost')
  assert.ok(!s.j.events.some((e) => e.type === 'intent' && (e.gen ?? 0) >= 3), 'no part signed')
  s.j.requestStop('eth')
  const run2 = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: exDeps(s) })
  assert.equal(await run2.start(), 'stopped')
  const st = s.j.events.filter((e) => e.type === 'stopped' && e.by === 'cli')
  assert.equal(st.length, 1)
  assert.match(String(st[0].data.reason), /^stopped during reconcile — engine\.code-disagree: /)
  assert.equal(s.j.state().chains.eth!.phase, 'STOPPED')
  assert.equal(s.relay.sends().length, 1, 'only the earlier holder\'s part')
  await clawsBack(s)
})

test('fix round 2 (c2): EVERY endpoint reports the same 0xef0100… delegation — the chain ends `stopped` (engine.eip7702, reconcile first) → the claw-back succeeds', { timeout: 60_000 }, async () => {
  let hook: Hook | undefined
  const { s } = await landedPartStack({ ethEndpoints: 2, hook: (m, p, base, ep) => hook!(m, p, base, ep) })
  hook = delegatedFor(s)
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: exDeps(s) })
  assert.equal(await ex.start(), 'stopped')
  const mine = run3(s)
  assert.deepEqual(mine.map((e) => e.type), ['stopped'])
  assert.match(String(mine[0].data.reason), /^engine\.eip7702: /)
  assert.ok(s.relay.calls.some((c) => c.method === 'eth_getCode' && c.ep === 0) && s.relay.calls.some((c) => c.method === 'eth_getCode' && c.ep === 1), 'both endpoints were asked')
  assert.equal(s.relay.sends().length, 1)
  await clawsBack(s)
})

test('fix round 2 (c3): two endpoints report DIFFERENT non-0x codes — PAUSED (engine.code-disagree), nothing signed; the live run\'s Stop settles it; the claw-back succeeds', { timeout: 60_000 }, async () => {
  let hook: Hook | undefined
  const { s } = await landedPartStack({ ethEndpoints: 2, hook: (m, p, base, ep) => hook!(m, p, base, ep) })
  hook = (m, p, base, ep) => (m === 'eth_getCode' && String(p[0]).toLowerCase() === s.key.address.toLowerCase() ? (ep === 0 ? DELEGATED : DELEGATED2) : base(m, p))
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: exDeps(s) })
  const run = ex.start()
  await pausedOn(s, 3)
  assert.match(String(s.j.events.find((e) => e.type === 'paused' && e.gen === 3)!.data.reason), /different ones/)
  assert.equal(s.j.state().chains.eth!.phase, 'PAUSED')
  s.j.requestStop('eth')                                                       // the API's Stop: the running executor reads it on its lease tick
  assert.equal(await run, 'stopped')
  assert.ok(!s.j.events.some((e) => e.type === 'intent' && (e.gen ?? 0) >= 3), 'nothing signed')
  assert.match(String(s.j.events.filter((e) => e.type === 'stopped' && e.by === 'cli').at(-1)!.data.reason), /engine\.code-disagree/)
  await clawsBack(s)
})

test('fix round 1 (d): an intent still open when the delegation is found is reconciled from the chain (read-only) BEFORE `stopped`; nothing resent; then the claw-back succeeds', { timeout: 60_000 }, async () => {
  // the earlier holder's part landed, but the node lags (receipt and nonce hidden): the takeover reconcile adopts it; the
  // lag ends as the lane reads the account — the delegation is found then, with that intent still open
  let lag = true, id = ''
  const s = stack('eth', { copies: 1, startIn: 0, ethBalance: 3n * 10n ** 17n, cap: '1000000000000000000', eth: (m, p, base) => {
    if (m === 'eth_getCode' && String(p[0]).toLowerCase() === s.key.address.toLowerCase()) { lag = false; return DELEGATED }
    if (lag && (m === 'eth_getTransactionReceipt' || m === 'eth_getTransactionByHash') && p[0] === id) return null
    if (lag && m === 'eth_getTransactionCount' && String(p[0]).toLowerCase() === s.key.address.toLowerCase()) return '0x0'
    return base(m, p)
  } })
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  useRelayClient(s.relay.client)
  const cfg = laneConfigOf('eth', s.def.chains.eth!, s.text)
  const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL_TO, data: toHex(planLaneCopy(cfg, 1)[0].payload), gas: 60_000n, maxFee: 3n * 10n ** 9n, tip: 10n ** 9n })
  id = signed.id.toLowerCase()
  await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [signed.raw])
  s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: String(60_000n * 3n * 10n ** 9n), eth: { nonce: 0, tip: String(10n ** 9n), maxFee: String(3n * 10n ** 9n), gas: '60000', to: NULL_TO } })
  s.j.asHolder(2, 'browser', 'eth', 'sent', { txId: id, outcome: 'accepted', reason: null })
  s.j.expire('eth')
  const sends0 = s.relay.sends().length
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: exDeps(s) })
  assert.equal(await ex.start(), 'stopped')
  const mine = run3(s).map((e) => `${e.type}${e.type === 'reconcile' ? `:${String(e.data.outcome)}` : ''}`)
  const adopted = mine.indexOf('reconcile:adopted'), included = mine.indexOf('reconcile:included'), stopped = mine.indexOf('stopped')
  assert.ok(adopted >= 0 && adopted < included && included < stopped, `the open intent reconciled from the chain, then stopped (${mine.join(', ')})`)
  assert.ok(mine.indexOf('readback') > included && mine.indexOf('readback') < stopped)
  assert.equal(stopped, mine.length - 1, 'stopped last')
  assert.ok(!s.j.events.some((e) => e.type === 'intent' && (e.gen ?? 0) >= 3), 'nothing new signed')
  assert.equal(s.relay.sends().length, sends0, 'nothing resent')
  assert.deepEqual(s.j.state().chains.eth!.openIntents, [])
  await clawsBack(s)
})

test('fix round 1 (d2): the end-of-run reconcile cannot decide the open intent (its nonce is used, our receipt not visible): `stuck`, the run fails, NO `stopped` over it, nothing signed', { timeout: 60_000 }, async () => {
  let phase: 'adopt' | 'used' = 'adopt', id = ''
  const s = stack('eth', { copies: 1, startIn: 0, ethBalance: 3n * 10n ** 17n, cap: '1000000000000000000', eth: (m, p, base) => {
    const lane = String(p[0]).toLowerCase() === s.key.address.toLowerCase()
    if (m === 'eth_getCode' && lane) { phase = 'used'; return DELEGATED }
    if ((m === 'eth_getTransactionReceipt' || m === 'eth_getTransactionByHash') && p[0] === id) return null      // our receipt never shows
    if (m === 'eth_getBlockByNumber') { const b = base(m, p) as { transactions: unknown[] } | null; return b === null ? null : { ...b, transactions: [] } }
    if (phase === 'adopt' && m === 'eth_getTransactionCount' && lane) return '0x0'                                 // at the takeover: not used yet
    return base(m, p)
  } })
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  useRelayClient(s.relay.client)
  const cfg = laneConfigOf('eth', s.def.chains.eth!, s.text)
  const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL_TO, data: toHex(planLaneCopy(cfg, 1)[0].payload), gas: 60_000n, maxFee: 3n * 10n ** 9n, tip: 10n ** 9n })
  id = signed.id.toLowerCase()
  await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [signed.raw])
  s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: String(60_000n * 3n * 10n ** 9n), eth: { nonce: 0, tip: String(10n ** 9n), maxFee: String(3n * 10n ** 9n), gas: '60000', to: NULL_TO } })
  s.j.asHolder(2, 'browser', 'eth', 'sent', { txId: id, outcome: 'accepted', reason: null })
  s.j.expire('eth')
  const sends0 = s.relay.sends().length
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: { ...exDeps(s), rounds: 3 } })
  assert.equal(await ex.start(), 'failed')
  const mine = run3(s).map((e) => `${e.type}${e.type === 'reconcile' ? `:${String(e.data.outcome)}` : ''}`)
  assert.deepEqual(mine, ['reconcile:adopted', 'stuck'], 'reconciled from the chain: undecidable, so stuck — and no `stopped` over it')
  assert.ok(!mine.includes('reconcile:nonce-consumed'), 'never nonce-consumed from absence')
  assert.equal(s.j.state().chains.eth!.phase, 'STUCK')
  assert.equal(s.relay.sends().length, sends0, 'nothing signed or resent')
  // planE5 m-7 (Efix3): the failed outcome says why the chain is not settled and what to do
  assert.match(ex.view().note, /EIP-7702 delegation stands.*not settled until its open attempt resolves: run it again/)
})

test('fix round 1: the review\'s probe 1 — a journaled agreement pause (no endpoint readable), then the delegation: `stopped` (not stuck PAUSED); the claw-back succeeds', { timeout: 60_000 }, async () => {
  let codeReads = 0
  const s = stack('eth', { copies: 1, startIn: 0, ethBalance: 3n * 10n ** 17n, cap: '1000000000000000000', eth: (m, p, base) => {
    if (m === 'eth_getCode' && String(p[0]).toLowerCase() === s.key.address.toLowerCase()) { if (++codeReads === 1) throw transportFailure(); return DELEGATED }
    return base(m, p)
  } })
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: exDeps(s) })
  assert.equal(await ex.start(), 'stopped')
  const mine = s.j.events.filter((e) => e.chain === 'eth' && e.by === 'cli' && e.gen === 2).map((e) => e.type).filter((t) => t !== 'key-loaded' && t !== 'funds' && t !== 'note')
  assert.deepEqual(mine, ['paused', 'stopped'])
  assert.equal(s.j.state().chains.eth!.phase, 'STOPPED')
  assert.equal(s.relay.sends().length, 0)
  await clawsBack(s)
})

test('rescue (executor): paused on a nonce disagreement, a Stop ends the run `stopped` with nothing signed; the chain can then be clawed back once the endpoints agree', { timeout: 60_000 }, async () => {
  const DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
  let disagree = true
  const s = stack('eth', { copies: 1, startIn: 0, ethEndpoints: 2, ethBalance: 3n * 10n ** 17n, eth: (m, p, base, ep) => {
    if (m === 'eth_getTransactionCount' && ep === 1 && disagree) return hx(Number(BigInt(base(m, p) as string)) + 1)
    return base(m, p)
  } })
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: exDeps(s) })
  const run = ex.start()
  const paused = (): boolean => s.j.events.some((e) => e.type === 'paused')
  for (let i = 0; i < 300 && !paused(); i++) await s.clock.sleep(1_000)   // bounded: a mutant that never pauses fails here, never hangs
  assert.ok(paused(), 'paused on the disagreement')
  s.j.requestStop('eth'); ex.requestStop()                          // R79: the job Stop (journaled), not a detach
  assert.equal(await run, 'stopped')
  assert.equal(s.j.state().chains.eth!.phase, 'STOPPED')
  assert.ok(!s.j.events.some((e) => e.type === 'intent'), 'nothing signed')
  disagree = false
  const claw = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: { ...exDeps(s), clawbackConfirm: { amount: '300000000000000000' } } })
  assert.equal(await claw.clawback(DEST), 'clawed-back')
})

test('planE5 m-5: the pause / refusal text says how to recover (restart the stack or fix endpoints.json; Stop, then run again)', () => {
  for (const f of [() => assertNonceAgreement([0, 1], [0, 1], 2), () => assertCodeAgreement(['0x', DELEGATED], 2)]) {
    assert.throws(f, (e: unknown) => /restart the stack/.test((e as Error).message) && /endpoints\.json/.test((e as Error).message) && /Stop the chain, then run it again/.test((e as Error).message))
  }
})

test('m-5: a claw-back refused for pending transactions still carries the delegation warning (and calls d.delegated)', async () => {
  let seen = ''
  await assert.rejects(clawTwoPending().go((w) => { seen = w }), /still pending.*delegated \(EIP-7702\)/)
  assert.match(seen, /delegated \(EIP-7702\)/)
})

test('Eminors (Efix3 m-D): a claw-back refused for DISAGREEING nonces on a delegated key carries the warning too (same guard id), and a plain key does not', async () => {
  let seen = ''
  const c = clawTwo({ laneCode: DELEGATED, latest: (ep) => (ep === '1' ? 1 : 0) })
  await assert.rejects(c.go((w) => { seen = w }), (e: unknown) => guardIdOf(e) === 'engine.nonce-disagree' && /delegated \(EIP-7702\); someone holding the authorization/.test((e as Error).message))
  assert.match(seen, /delegated \(EIP-7702\)/, 'and the progress line is called')
  assert.equal(c.sent.length, 0, 'nothing signed or sent')
  const plain = clawTwo({ latest: (ep) => (ep === '1' ? 1 : 0) })
  await assert.rejects(plain.go(), (e: unknown) => guardIdOf(e) === 'engine.nonce-disagree' && !/EIP-7702/.test((e as Error).message))
})

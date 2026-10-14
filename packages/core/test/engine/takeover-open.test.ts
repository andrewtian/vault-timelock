// E2 review I-1: an attempt whose exact signed bytes may still land stays OPEN in the journal, so a takeover (a crash
// right after a hiccup) must reconcile it before any new intent, and the takeover's cap ledger holds its fee. Only
// provably dead bytes are journaled `rejected`. The journal written by the engine is reduced with E1's reduce, the way
// the API and the next holder see it. ALL DATA IS SYNTHETIC; the relay is a fake fetch.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Keypair } from '@solana/web3.js'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { ethTx, journalOutcome, solTx } from '../../src/engine/engine.js'
import { clawbackEth, ethAdapter, newLaneState, validateLaneConfig } from '../../src/engine/lane.js'
import { ETH } from '../../src/chains/constants.js'
import { utf8 } from '../../src/chains/plan.js'
import { CapLedger } from '../../src/gates/caps.ts'
import { reduce } from '../../src/job/index.ts'
import type { JobDef } from '../../src/contracts/index.ts'
import { guardOf, readJson } from '../job/helpers.ts'
import { armedEvent, armedLedger, armedState, asJournal, fakeEthChain, fakeRelay, fakeSolChain, recordingJournal, transportFailure } from './fakes.ts'

const GWEI = 10n ** 9n
const ETH_DEF = readJson<JobDef>('journals/01-created.def.json')            // eth only
const BOTH_DEF = readJson<JobDef>('journals/15a-skipped.def.json')         // eth + sol
const CAP = 10n ** 18n

test('journalOutcome: rejected only for bytes that can never land (consumed nonce, consensus-invalid); everything else unknown', () => {
  for (const msg of ['nonce too low: next nonce 5, tx nonce 4', 'intrinsic gas too low', 'floor data gas: gas 21000, minimum needed 21240']) assert.equal(journalOutcome('eth', { kind: 'rejected', msg }), 'rejected', msg)
  for (const msg of ['replacement transaction underpriced', 'transaction underpriced', 'insufficient funds for gas * price + value', 'oversized data', 'already in pool']) assert.equal(journalOutcome('eth', { kind: 'rejected', msg }), 'unknown', msg)
  for (const msg of ['Transaction simulation failed: Blockhash not found', 'node is behind', 'Attempt to debit an account but found no record of a prior credit.', 'custom program error: 0x1', 'nonce too low']) {
    assert.equal(journalOutcome('sol', { kind: 'rejected', msg }), 'unknown', `SOL ${msg}`)
  }
  assert.equal(journalOutcome('eth', { kind: 'unknown', msg: 'timeout' }), 'unknown'); assert.equal(journalOutcome('sol', { kind: 'accepted', msg: '' }), 'accepted')
})

test('SOL preflight hiccup ("blockhash not found"), then a same-bytes rebroadcast with no answer, then a crash: the attempt is open and held', { timeout: 30_000 }, async () => {
  const chain = fakeSolChain()
  let sends = 0, live = true
  const relay = fakeRelay({ sol: (m, p, ep) => {
    if (m === 'sendTransaction') {
      sends++
      if (sends === 1) throw new Error('Transaction simulation failed: Blockhash not found')   // a preflight hiccup: not forwarded … this time
      live = false; throw transportFailure()                                                   // the rebroadcast of the SAME bytes: no answer
    }
    return chain.handler(m, p)
  } })
  const { journal, events } = recordingJournal()
  const t: Record<string, any> = { copy: 1, part: 1, parts: 1, payload: utf8('hiccup memo') }
  const r = await solTx(t, { kp: Keypair.generate(), notify: async () => {}, alive: () => live, poll: 1, rent: 890_880n, used: new Map(), journal, ledger: armedLedger('sol', CAP),
    lane: { txs: [] }, payerFloor: 890_880n, cuPriceCap: 2_000_000, policy: { price: async () => ({ lamports: 0, rung: 0 }) } })
  assert.equal(r, 'aborted'); assert.equal(sends, 2)
  assert.deepEqual(relay.sends().map((c) => (c.params[1] as Record<string, unknown>).skipPreflight ?? false), [false, true], 'the second call re-sent the same signed bytes')
  assert.deepEqual(events.map((e) => [e.type, e.outcome ?? null]), [['intent', null], ['sent', 'unknown']], 'never `rejected`')
  const state = reduce(BOTH_DEF, asJournal([armedEvent(['sol'], CAP)], events))
  const cs = state.chains.sol!
  assert.deepEqual(cs.openIntents, [t.attempts[0].id], 'the next holder must reconcile it before any new intent')
  assert.equal(cs.txs[0].state, 'open')
  const takeover = CapLedger.fromArmed(state, 'sol', 'takeover-sol')
  assert.equal(takeover.held, 5000n, 'the takeover ledger holds its fee'); takeover.close()
})

test('ETH Passive: a non-dead rejection, then the same bytes rebroadcast with no answer, then a crash: open, held, never `rejected`', { timeout: 30_000 }, async () => {
  let sends = 0, live = true
  const chain = fakeEthChain({ mine: false })
  const relay = fakeRelay({ eth: (m, p) => {
    if (m === 'eth_sendRawTransaction') { sends++; if (sends === 1) throw new Error('transaction underpriced'); live = false; throw transportFailure() }
    if (m === 'eth_getTransactionByHash') return null                     // dropped from the pool: Passive rebroadcasts the same bytes
    return chain.handler(m, p)
  } })
  const { journal, events } = recordingJournal()
  const cfg = validateLaneConfig({ chain: 'eth', text: 'passive hiccup', mode: 'drain' }).cfg
  const lane = newLaneState(cfg), ledger = armedLedger('eth', CAP)
  const A = ethAdapter(cfg, { chain: 'eth', account: privateKeyToAccount(generatePrivateKey()) }, { journal, network: 'local', chainId: 31337, ledger, poll: 1, passiveWaitMs: 1, alive: () => live, notify: async () => {}, lane })
  await A.reconcile(lane, async () => {})
  const t: Record<string, any> = { copy: 1, part: 1, parts: 1, payload: A.planCopy(1)[0].payload }
  assert.equal(await A.sendTx(t, { tight: false }), 'aborted')
  assert.equal(sends, 2)
  assert.equal(relay.sends()[0].params[0], relay.sends()[1].params[0], 'the identical signed bytes went out twice')
  assert.deepEqual(events.filter((e) => e.type === 'sent').map((e) => e.outcome), ['unknown'])
  const state = reduce(ETH_DEF, asJournal([armedEvent(['eth'], CAP)], events))
  assert.deepEqual(state.chains.eth!.openIntents, [t.attempts[0].id])
  const intent = events.find((e) => e.type === 'intent')!.eth as Record<string, string>
  const takeover = CapLedger.fromArmed(state, 'eth', 'takeover-eth')
  assert.equal(takeover.held, BigInt(intent.gas) * BigInt(intent.maxFee), 'held at gas × maxFee'); takeover.close()
  assert.equal(ledger.held, BigInt(intent.gas) * BigInt(intent.maxFee), 'and the running lane still reserves it'); ledger.close()
})

test('the abandoning paths still journal `rejected`: an ETH consumed nonce and a consensus-invalid tx close the attempt', { timeout: 30_000 }, async () => {
  for (const msg of ['intrinsic gas too low', 'nonce too low']) {
    const chain = fakeEthChain({ mine: false })
    let sent = 0
    const relay = fakeRelay({ eth: (m, p) => {
      if (m === 'eth_sendRawTransaction') { sent++; throw new Error(msg) }
      if (m === 'eth_getTransactionCount' && msg === 'nonce too low') return sent ? '0x5' : '0x0'   // another tx took the nonce in the meantime
      return chain.handler(m, p)
    } })
    const { journal, events } = recordingJournal()
    const t: Record<string, any> = { copy: 1, part: 1, parts: 1, payload: utf8('data:,dead'), nonce: 0 }
    let live = true
    const r = await ethTx(t, { account: privateKeyToAccount(generatePrivateKey()), chainId: 31337, notify: async () => {}, alive: () => live, poll: 1, tipCap: 3n * GWEI,
      journal, ledger: armedLedger('eth', CAP), lane: { txs: [] }, gasRule: { amsterdam: false, toSelf: false }, to: ETH.NULL_ADDRESS })
    live = false
    assert.equal(r, msg === 'nonce too low' ? 'failed' : 'exhausted'); assert.equal(relay.sends().length, 1)
    assert.deepEqual(events.map((e) => [e.type, e.outcome ?? null]), [['intent', null], ['sent', 'rejected']])
    const state = reduce(ETH_DEF, asJournal([armedEvent(['eth'], CAP)], events))
    assert.deepEqual(state.chains.eth!.openIntents, [], 'dead bytes: closed')
  }
})

test('ETH: a rejection "nonce too low" after the send closes only that attempt; a nonce taken with no receipt of ours journals stuck, not closed', { timeout: 30_000 }, async () => {
  let sent = 0
  const chain = fakeEthChain({ mine: false })
  const relay = fakeRelay({ eth: (m, p) => {
    if (m === 'eth_sendRawTransaction') { sent++; return chain.handler(m, p) }
    if (m === 'eth_getTransactionCount') return sent ? '0x1' : '0x0'      // after the send the nonce is used … by a tx we cannot see
    return chain.handler(m, p)
  } })
  const { journal, events } = recordingJournal()
  const t: Record<string, any> = { copy: 1, part: 1, parts: 1, payload: utf8('data:,lagging receipt'), nonce: 0 }
  const r = await ethTx(t, { account: privateKeyToAccount(generatePrivateKey()), chainId: 31337, notify: async () => {}, alive: () => true, poll: 1, tipCap: 3n * GWEI,
    journal, ledger: armedLedger('eth', CAP), lane: { txs: [] }, gasRule: { amsterdam: false, toSelf: false }, to: ETH.NULL_ADDRESS })
  assert.equal(r, 'failed'); assert.equal(relay.sends().length, 1)
  assert.deepEqual(events.map((e) => e.type), ['intent', 'sent', 'stuck'], 'no reconcile nonce-consumed from a 6-poll heuristic')
  const state = reduce(ETH_DEF, asJournal([armedEvent(['eth'], CAP)], events))
  assert.equal(state.chains.eth!.phase, 'STUCK'); assert.deepEqual(state.chains.eth!.openIntents, [t.attempts[0].id])
  const takeover = CapLedger.fromArmed(state, 'eth', 'takeover-stuck')
  assert.ok(takeover.held > 0n, 'still held'); takeover.close()
})

test('ETH claw-back: a non-dead rejection leaves the claw-back intent open (no clawback-failed); the next ledger refuses until it is reconciled', { timeout: 30_000 }, async () => {
  const hx = (n: bigint): string => `0x${n.toString(16)}`
  const chain = fakeEthChain()
  fakeRelay({ eth: (m, p) => {
    if (m === 'eth_sendRawTransaction') throw new Error('insufficient funds for gas * price + value')
    if (m === 'eth_getCode') return '0x'
    if (m === 'eth_getBalance') return hx(10n ** 16n)
    return chain.handler(m, p)
  } })
  const { journal, events } = recordingJournal()
  const DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
  await assert.rejects(clawbackEth({ account: privateKeyToAccount(generatePrivateKey()) }, DEST, { journal, network: 'local', chainId: 31337, poll: 1, state: armedState('eth', CAP) }), /rejected/)
  assert.deepEqual(events.map((e) => [e.type, e.outcome ?? null]), [['clawback-intent', null], ['clawback-sent', 'unknown']])
  const state = reduce(ETH_DEF, asJournal([armedEvent(['eth'], CAP)], [{ type: 'stopped', chain: 'eth', reason: 'operator' }, ...events]))
  assert.equal(state.chains.eth!.phase, 'CLAWING_BACK'); assert.equal(state.chains.eth!.openIntents.length, 1)
  assert.equal(guardOf(() => CapLedger.fromArmed(state, 'eth', 'claw-open')), 'engine.cap-armed', 'reconcile the open claw-back first')
})

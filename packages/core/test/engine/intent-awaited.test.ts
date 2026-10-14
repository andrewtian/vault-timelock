// spec §7.2 "intent awaited": the engine journals the intent and awaits the API's ack (which carries the send ticket)
// BEFORE any send-type RPC. A rejected intent ends the attempt with nothing sent; a slow ack delays the send. Every
// journaled event has the contract's exact shape (validateEvent). ALL DATA IS SYNTHETIC; the relay is a fake fetch.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Keypair } from '@solana/web3.js'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { ethTx, JournalError, solTx } from '../../src/engine/engine.js'
import { ETH } from '../../src/chains/constants.js'
import { utf8 } from '../../src/chains/plan.js'
import { armedLedger, fakeEthChain, fakeRelay, fakeSolChain, recordingJournal, sleep, ticketFor } from './fakes.ts'
import type { Ev } from './fakes.ts'

const GWEI = 10n ** 9n
const RULE = { amsterdam: false, toSelf: false }
const ethOpts = (journal: unknown) => ({
  account: privateKeyToAccount(generatePrivateKey()), chainId: 31337, notify: async () => {}, alive: () => true, poll: 1,
  tipCap: 3n * GWEI, journal, ledger: armedLedger('eth', 10n ** 18n), lane: { txs: [] }, gasRule: RULE, to: ETH.NULL_ADDRESS,
})
const ethT = () => ({ copy: 1, part: 1, parts: 1, payload: utf8('data:,hello world'), nonce: 0 } as Record<string, any>)
const solOpts = (journal: unknown) => ({
  kp: Keypair.generate(), notify: async () => {}, alive: () => true, poll: 1, rent: 890_880n, used: new Map(), journal,
  ledger: armedLedger('sol', 10n ** 9n), lane: { txs: [] }, payerFloor: 890_880n, cuPriceCap: 2_000_000, policy: { price: async () => ({ lamports: 0, rung: 0 }) },
})
const solT = () => ({ copy: 1, part: 1, parts: 1, payload: utf8('hello memo'), state: 'planned' } as Record<string, any>)

test('ETH: a journal whose intent rejects → no eth_sendRawTransaction, no attempt recorded, the lane stops (JournalError)', async () => {
  const chain = fakeEthChain(), relay = fakeRelay({ eth: chain.handler })
  const { journal, events } = recordingJournal({ intent: async () => { throw new Error('api: lease.stale') } })
  const t = ethT()
  await assert.rejects(ethTx(t, ethOpts(journal)), JournalError)
  assert.equal(relay.sends().length, 0, 'nothing was sent')
  assert.equal(relay.calls.filter((c) => c.method === 'eth_estimateGas').length, 1, 'it did get as far as the quote')
  assert.deepEqual(t.attempts, [], 'an unacked attempt is not even recorded')
  assert.deepEqual(events.map((e) => e.type), [])
})

test('ETH: the send starts only after a slow intent ack resolves, and carries that exact ticket', async () => {
  const chain = fakeEthChain(), relay = fakeRelay({ eth: chain.handler })
  let ackedAt = 0
  const ticket = ticketFor('slow')
  const { journal, events } = recordingJournal({ intent: async () => { await sleep(60); ackedAt = performance.now(); return { ticket } } })
  const t = ethT()
  assert.equal(await ethTx(t, ethOpts(journal)), 'confirmed')
  const sends = relay.sends()
  assert.equal(sends.length, 1)
  assert.ok(ackedAt > 0 && sends[0].at >= ackedAt, 'the send began after the ack')
  assert.equal(sends[0].ticket, ticket, 'x-vt-send-ticket = the ticket of the acked intent')
  assert.deepEqual(events.map((e) => e.type), ['intent', 'sent', 'included', 'readback'])
  const intent = events[0]
  assert.equal(intent.txId, t.attempts[0].id); assert.match(String(intent.txId), /^0x[0-9a-f]{64}$/, 'ETH tx ids are lowercase')
  assert.equal(intent.replaces, null); assert.equal(intent.attempt, 1); assert.equal(intent.parts, 1)
  assert.deepEqual((intent.eth as Record<string, unknown>).to, ETH.NULL_ADDRESS)
  assert.equal((intent.eth as Record<string, unknown>).gas, String(21000 + 40 * t.payload.length), 'the exact pre-Amsterdam gas (anvil)')
  assert.equal(events.at(-1)!.ok, true, 'readback ok')
})

test('ETH: an intent ack without a ticket → engine.no-ticket, nothing sent', async () => {
  const chain = fakeEthChain(), relay = fakeRelay({ eth: chain.handler })
  const { journal } = recordingJournal({ intent: async () => ({ ticket: undefined as unknown as string }) })
  await assert.rejects(ethTx(ethT(), ethOpts(journal)), (e: Error & { guardId?: string }) => e.guardId === 'engine.no-ticket')
  assert.equal(relay.sends().length, 0)
})

test('ETH: no cap ledger → engine.cap-ledger before anything; a missing journal → nothing sent', async () => {
  const chain = fakeEthChain(), relay = fakeRelay({ eth: chain.handler })
  const { journal } = recordingJournal()
  for (const ledger of [undefined, { reserve() {}, settle() {} }]) {
    await assert.rejects(ethTx(ethT(), { ...ethOpts(journal), ledger, cap: 10n ** 18n }), (e: Error & { guardId?: string }) => e.guardId === 'engine.cap-ledger', 'a free cap or a look-alike ledger is not a cap')
  }
  await assert.rejects(ethTx(ethT(), { ...ethOpts(undefined) }), JournalError)
  assert.equal(relay.sends().length, 0)
})

test('ETH: a journal append that fails after the send stops the lane (fail closed), never retried as an RPC error', async () => {
  const chain = fakeEthChain(), relay = fakeRelay({ eth: chain.handler })
  const { journal } = recordingJournal()
  const broken = { intent: journal.intent, append: async (ev: Ev) => { if (ev.type === 'sent') throw new Error('api: journal.write'); return journal.append(ev) } }
  await assert.rejects(ethTx(ethT(), ethOpts(broken)), JournalError)
  assert.equal(relay.sends().length, 1, 'exactly the one acked send; no second attempt')
})

test('SOL: a journal whose intent rejects → no sendTransaction, no attempt recorded', async () => {
  const chain = fakeSolChain(), relay = fakeRelay({ sol: chain.handler })
  const { journal } = recordingJournal({ intent: async () => { throw new Error('api: lease.reconcile-first') } })
  const t = solT()
  await assert.rejects(solTx(t, solOpts(journal)), JournalError)
  assert.equal(relay.sends().length, 0)
  assert.deepEqual(t.attempts, [])
  assert.ok(relay.calls.some((c) => c.method === 'simulateTransaction'), 'it did get as far as the simulation')
})

test('SOL: the send starts only after a slow intent ack, carries its ticket; passive = no priority fee', { timeout: 20_000 }, async () => {
  const chain = fakeSolChain(), relay = fakeRelay({ sol: chain.handler })
  let ackedAt = 0
  const ticket = ticketFor('sol-slow')
  const { journal, events } = recordingJournal({ intent: async () => { await sleep(60); ackedAt = performance.now(); return { ticket } } })
  const t = solT()
  assert.equal(await solTx(t, solOpts(journal)), 'confirmed')
  const sends = relay.sends()
  assert.equal(sends.length, 1)
  assert.ok(sends[0].at >= ackedAt)
  assert.equal(sends[0].ticket, ticket)
  assert.deepEqual(events.map((e) => e.type), ['intent', 'sent', 'included', 'readback'])
  const sol = events[0].sol as Record<string, unknown>
  assert.equal(sol.cuPrice, 0); assert.equal(sol.cuLimit, 11_000); assert.equal(sol.fee, '5000'); assert.equal(sol.rung, 0)
  assert.equal(events[2].block, '501'); assert.equal(events[2].fee, '5000')
  assert.equal(events[3].ok, true)
  assert.deepEqual(t.chainBytes, t.payload, 'the memo bytes read back from the chain (R72 reassembly)')
})

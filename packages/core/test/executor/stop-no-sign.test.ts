// PF-E fix round 1 (5): a Stop means NO new signature. After requestStop(), no strategy (economy, prompt, passive) signs a
// replacement, a fee bump or a new attempt — not even for a part whose only adopted attempts were journaled rejected or marked
// failed. The attempt in flight keeps its already-signed bytes (they may be sent again, identical) until the end of its window:
// it lands, or the run ends `stopped` with it open (pending at the nodes), or STUCK (no endpoint knows it). SOL never re-signs
// after a Stop either, and the pause at a per-tx fee cap no longer waits for a Resume.
// ALL DATA IS SYNTHETIC: generated keys, the in-memory API and relay, fake chains; nothing listens on a port; virtual time.
import { afterEach, test } from 'node:test'
import assert from 'node:assert/strict'
import { Keypair } from '@solana/web3.js'
import { hexToBytes, keccak256, toHex } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { createExecutor, laneConfigOf } from '../../src/executor/executor.ts'
import { useRelayClient } from '../../src/engine/rpc.js'
import { ethTx, solTx } from '../../src/engine/engine.js'
import * as eth from '../../src/chains/eth.js'
import { CANON, ETH } from '../../src/chains/constants.js'
import { planLaneCopy } from '../../src/engine/lane.js'
import { utf8 } from '../../src/chains/plan.js'
import { sha256Hex } from '../../src/job/canonical.ts'
import { virtualClock } from '../fakes/fake-journal.ts'
import { armedLedger, fakeClock, fakeEthChain, fakeRelay, fakeSolChain, recordingJournal } from '../engine/fakes.ts'
import { T0, deps, sendViolations, stack } from './helpers.ts'

afterEach(() => { assert.deepEqual(sendViolations.splice(0), [], 'every ticketed send was exactly its journaled intent (id, bytes, declared nonce)') })

const NULL = '0x0000000000000000000000000000000000000000', GW = 10n ** 9n, BLOCK_MS = 12_000
const STRATEGIES = ['economy', 'prompt', 'passive'] as const
const windowMs = (strategy: string) => (strategy === 'passive' ? 25 : 3) * BLOCK_MS
// a run still going after 2 virtual hours (every case here ends within a few windows) is a wedge: the test fails
const MAX_MS = 2 * 3600_000
type S = ReturnType<typeof stack>
type Ex = ReturnType<typeof createExecutor>
const hx = (n: number): string => `0x${n.toString(16)}`

async function drive(s: S, ex: Ex, maxMs: number, at: Array<{ ms: number; go: () => void }> = []): Promise<{ outcome: string | null; ms: number }> {
  let outcome: string | null = null
  const run = ex.start().then((o: string) => { outcome = o }, (e: Error) => { outcome = `threw ${e.message}` })
  const t0 = s.clock.now(), todo = [...at]
  while (outcome === null && s.clock.now() - t0 < maxMs) {
    for (const x of todo.filter((y) => s.clock.now() - t0 >= y.ms)) { todo.splice(todo.indexOf(x), 1); x.go() }
    await new Promise((r) => setImmediate(r))
  }
  const ms = s.clock.now() - t0, done = outcome
  if (done === null) { s.j.expire('eth'); await run }
  return { outcome: done, ms }
}
const intents = (s: S, gen: number) => s.j.events.filter((e) => e.type === 'intent' && e.gen === gen)
// gen 2 (the page) journaled an attempt at nonce 0 and died; `after` the intent: the earlier holder's next line
async function earlier(s: S, after: ['sent', Record<string, unknown>]) {
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  useRelayClient(s.relay.client)
  const payload = planLaneCopy(laneConfigOf('eth', s.def.chains.eth!, s.text), 1)[0].payload
  const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL, data: toHex(payload), gas: 30_000n, maxFee: 3n * GW, tip: GW })
  const id = signed.id.toLowerCase()
  s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: sha256Hex(hexToBytes(signed.raw)), payloadSha256: sha256Hex(payload), reserved: '90000000000000', eth: { nonce: 0, tip: String(GW), maxFee: String(3n * GW), gas: '30000', to: NULL } })
  s.j.asHolder(2, 'browser', 'eth', after[0], { txId: id, ...after[1] })
  s.j.expire('eth')
  return { id, raw: signed.raw }
}

test('a Stop at a takeover with an adopted pending attempt — every strategy: no bump, no replacement; its identical bytes are sent again and land, then the run stops before the next copy', { timeout: 120_000 }, async () => {
  for (const strategy of STRATEGIES) {
    const s = stack('eth', { copies: 2, startIn: 0, feeStrategy: strategy })
    const { id, raw } = await earlier(s, ['sent', { outcome: 'unknown', reason: 'timeout' }])
    s.j.requestStop('eth')
    const r = await drive(s, createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) }), MAX_MS)
    assert.equal(r.outcome, 'stopped', strategy)
    assert.equal(intents(s, 3).length, 0, `${strategy}: nothing signed after the Stop (before: economy / prompt bumped it)`)
    assert.deepEqual(s.relay.sends().map((c) => c.params[0]), [raw], `${strategy}: only the identical bytes`)
    assert.equal(s.j.events.find((e) => e.type === 'included')!.data.txId, id)
    assert.equal(s.j.state().chains.eth!.phase, 'STOPPED')
  }
})

test('a Stop with only a claim adopted (journaled rejected, its nonce unused) — every strategy: nothing is signed for the part (before: economy / prompt signed a replacement after the Stop)', { timeout: 120_000 }, async () => {
  for (const strategy of STRATEGIES) {
    const s = stack('eth', { copies: 1, startIn: 0, feeStrategy: strategy })
    await earlier(s, ['sent', { outcome: 'rejected', reason: 'intrinsic gas too low' }])
    assert.deepEqual(s.j.state().chains.eth!.openIntents, [], 'only a claim')
    s.j.requestStop('eth')
    const r = await drive(s, createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) }), MAX_MS)
    assert.equal(r.outcome, 'stopped', strategy)
    assert.deepEqual([intents(s, 3).length, s.relay.sends().length, s.j.state().chains.eth!.phase], [0, 0, 'STOPPED'], strategy)
    assert.match(String(s.j.events.find((e) => e.type === 'stopped' && e.gen === 3)!.data.reason), /not sent/)
  }
})

test('a Stop while this run\'s own attempt is in flight and not mined — every strategy: no bump or replacement; within one window `stopped` with it open when it is pending, STUCK when no endpoint knows it', { timeout: 120_000 }, async () => {
  for (const strategy of STRATEGIES) {
    for (const pending of [true, false]) {
      let id = '', ex: Ex
      const clock = virtualClock(T0)
      const s = stack('eth', { copies: 1, startIn: 0, feeStrategy: strategy, clock, eth: (m, p, base) => {
        if (m === 'eth_sendRawTransaction') {
          if (id === '') { id = keccak256(p[0] as `0x${string}`).toLowerCase(); s.j.requestStop('eth'); ex.requestStop(); return id }   // taken, never mined; then the job Stop
          throw new Error('transaction underpriced: the pool is full (test)')
        }
        if (m === 'eth_getTransactionByHash' && pending && p[0] === id) return { hash: id, blockNumber: null, nonce: '0x0', to: NULL, value: '0x0', input: '0x' }
        if (m === 'eth_blockNumber') return hx(100 + Math.floor((clock.now() - T0) / BLOCK_MS))
        return base(m, p)
      } })
      ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
      const r = await drive(s, ex, MAX_MS)
      const name = `${strategy} pending ${pending}`
      assert.equal(r.outcome, pending ? 'stopped' : 'failed', name)
      assert.ok(r.ms <= windowMs(strategy) + 5 * BLOCK_MS, `${name}: within one window (${r.ms} ms)`)
      assert.deepEqual(intents(s, 2).map((e) => e.data.txId), [id], `${name}: the one attempt; no bump, no replacement`)
      const cs = s.j.state().chains.eth!
      if (pending) assert.deepEqual([cs.phase, cs.openIntents], ['STOPPED', [id]], name)
      else {
        assert.equal(cs.phase, 'STUCK', name)
        assert.match(String(s.j.events.find((e) => e.type === 'stuck')!.data.reason), /stopped by the operator while .* not known to every verified endpoint/, name)
      }
    }
  }
})

test('the pause at a per-tx fee cap no longer waits for a Resume after a Stop: the attempt in flight is watched to the end of one window (its same bytes, never a bump) and the run ends `stopped`', { timeout: 30_000 }, async () => {
  const chain = fakeEthChain({ mine: false })                       // taken into the pool, never mined; a block per eth_blockNumber
  const pool = new Set<string>()                                    // the pool shows what it took (pending)
  fakeRelay({ eth: (m, p) => {
    if (m === 'eth_sendRawTransaction') pool.add(keccak256(p[0] as `0x${string}`).toLowerCase())
    if (m === 'eth_getTransactionByHash') return pool.has(String(p[0])) ? { hash: p[0], blockNumber: null } : null
    return chain.handler(m, p)
  } })
  const rec = recordingJournal()
  let stop = false, calls = 0
  const journal = { ...rec.journal, append: async (ev: any) => { await rec.journal.append(ev); if (ev.type === 'paused') stop = true } }
  const t: Record<string, any> = { copy: 1, part: 1, parts: 1, payload: utf8('data:,cap'), nonce: 0 }
  const policy = { fees: async () => ({ nextBase: GW, tip0: GW, tip: GW, maxFee: 3n * GW }), initial: () => ({ tip: GW, maxFee: 3n * GW }), bump: () => ({ pause: 'the per-tx cap is reached (test)' }) }
  const r = await ethTx(t, { account: privateKeyToAccount(generatePrivateKey()), chainId: 31337, notify: async () => {}, alive: () => ++calls < 5_000, poll: 1, tipCap: 3n * GW,
    journal, ledger: armedLedger('eth', 10n ** 18n), lane: { txs: [] }, gasRule: { amsterdam: false, toSelf: false }, to: ETH.NULL_ADDRESS, policy, stopRequested: () => stop })
  assert.equal(r, 'stopped', 'before: it waited in the pause for a Resume (aborted only when the lease went)')
  assert.deepEqual(rec.events.map((e) => e.type).filter((x) => x === 'intent' || x === 'paused'), ['intent', 'paused'], 'one signature, no bump')
  assert.equal(t.pendingAtStop, true)
})

test('SOL: a Stop means no new signature too — a part whose Stop came before its first signature signs nothing', { timeout: 30_000 }, async () => {
  const chain = fakeSolChain()
  const relay = fakeRelay({ sol: (m, p) => chain.handler(m, p) })
  const { journal, events } = recordingJournal()
  const t: Record<string, any> = { copy: 1, part: 1, parts: 1, payload: utf8('stop before the first signature') }
  let calls = 0                                                   // bounded: a run that signs anyway ends 'aborted', never hangs
  const r = await solTx(t, { kp: Keypair.generate(), notify: async () => {}, alive: () => ++calls < 200, poll: 1, rent: 890_880n, used: new Map(), journal, ledger: armedLedger('sol', 10n ** 9n),
    lane: { txs: [] }, payerFloor: 890_880n, cuPriceCap: 2_000_000, clock: fakeClock(), policy: { price: async () => ({ lamports: 0, rung: 0 }) }, stopRequested: () => true })
  assert.equal(r, 'stopped')
  assert.deepEqual([events.length, relay.sends().length], [0, 0], 'nothing signed, nothing sent')
})

test('a Stop that arrives while the next tx is being prepared (after the check, before its signature) — every strategy, and SOL: nothing is signed', { timeout: 120_000 }, async () => {
  for (const strategy of STRATEGIES) {
    let ex: Ex
    // the lane's own quote (after copy-built; the executor's pre-start simulation quotes too, and a Stop there ends the run before the lane)
    const s = stack('eth', { copies: 1, startIn: 0, feeStrategy: strategy, eth: (m, p, base) => { if (m === 'eth_estimateGas' && s.j.events.some((e) => e.type === 'copy-built')) ex.requestStop(); return base(m, p) } })
    ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
    const r = await drive(s, ex, MAX_MS)
    assert.equal(r.outcome, 'stopped', strategy)
    assert.deepEqual([intents(s, 2).length, s.relay.sends().length], [0, 0], `${strategy}: nothing signed`)
    assert.ok(s.j.events.some((e) => e.type === 'copy-built'), `${strategy}: the Stop came inside the lane`)
  }
  let stop = false
  const chain = fakeSolChain()
  const relay = fakeRelay({ sol: (m, p) => { if (m === 'simulateTransaction') stop = true; return chain.handler(m, p) } })
  const { journal, events } = recordingJournal()
  const t: Record<string, any> = { copy: 1, part: 1, parts: 1, payload: utf8('stop while prepared') }
  let alive = 0                                                   // bounded: a run that loops or signs anyway ends 'aborted', never hangs
  const r = await solTx(t, { kp: Keypair.generate(), notify: async () => {}, alive: () => ++alive < 200, poll: 1, rent: 890_880n, used: new Map(), journal, ledger: armedLedger('sol', 10n ** 9n),
    lane: { txs: [] }, payerFloor: 890_880n, cuPriceCap: 2_000_000, clock: fakeClock(), policy: { price: async () => ({ lamports: 0, rung: 0 }) }, stopRequested: () => stop })
  assert.equal(r, 'stopped', 'SOL')
  assert.deepEqual([events.length, relay.sends().length], [0, 0], 'SOL: nothing signed')
})

test('economy / prompt after a Stop: a base fee above maxFee is no reason to replace (nothing new is signed) and the run still ends within one window; with every read failing too', { timeout: 120_000 }, async () => {
  for (const strategy of ['economy', 'prompt'] as const) {
    for (const how of ['base fee spike', 'reads fail'] as const) {
      let id = '', ex: Ex, stopped = false
      const clock = virtualClock(T0)
      const s = stack('eth', { copies: 1, startIn: 0, feeStrategy: strategy, clock, eth: (m, p, base) => {
        if (stopped && how === 'reads fail' && m !== 'eth_chainId') throw new Error('upstream unreachable (test)')
        if (m === 'eth_sendRawTransaction') { id = keccak256(p[0] as `0x${string}`).toLowerCase(); stopped = true; s.j.requestStop('eth'); ex.requestStop(); return id }   // taken, never mined; the job Stop
        if (m === 'eth_getTransactionByHash' && p[0] === id) return { hash: id, blockNumber: null, nonce: '0x0', to: NULL, value: '0x0', input: '0x' }
        if (m === 'eth_blockNumber') return hx(100 + Math.floor((clock.now() - T0) / BLOCK_MS))
        if (m === 'eth_feeHistory' && stopped) { const h = base(m, p) as { baseFeePerGas: string[] }; return { ...h, baseFeePerGas: [...h.baseFeePerGas.slice(0, -1), hx(1_000 * Number(GW))] } }
        return base(m, p)
      } })
      ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
      const r = await drive(s, ex, MAX_MS)
      const name = `${strategy} ${how}`
      assert.equal(r.outcome, 'stopped', name)
      assert.ok(r.ms <= windowMs(strategy) + 5 * BLOCK_MS, `${name}: within one window (${r.ms} ms)`)
      assert.deepEqual(intents(s, 2).map((e) => e.data.txId), [id], `${name}: no replacement`)
      assert.deepEqual([s.j.state().chains.eth!.phase, s.j.state().chains.eth!.openIntents], ['STOPPED', [id]], name)
    }
  }
})

test('M-4 SOL after a Stop is bounded even when one verified endpoint keeps failing its reads (the all-endpoint expiry proof never completes): STUCK with the reason within CANON.SOL_STOP_PROOF_MS, nothing re-signed', { timeout: 120_000 }, async () => {
  let ex: Ex, stopAt = -1
  const clock = virtualClock(T0)
  const s = stack('sol', { copies: 1, startIn: 0, endpoints: 2, clock, sol: (m, p, ep, base) => {
    if (m === 'sendTransaction') { if (stopAt < 0) { stopAt = clock.now(); s.j.requestStop('sol'); ex.requestStop() } return base(m, p) }
    if (m === 'getSignatureStatuses') return { context: { slot: 2_000 }, value: (p[0] as string[]).map(() => null) }   // never confirmed
    if (m === 'isBlockhashValid') { if (ep === 1) throw new Error('endpoint 1 unreachable (test)'); return { context: { slot: 2_000 }, value: false } }
    if (m === 'getLatestBlockhash' && p[0]?.commitment === 'finalized') { const r = base(m, p) as { context: unknown; value: { lastValidBlockHeight: number } }; return { ...r, context: { slot: 1_900 }, value: { ...r.value, lastValidBlockHeight: 2_100 } } }
    return base(m, p)
  } })
  ex = createExecutor({ jobId: s.j.id, chain: 'sol', key: s.key, holder: 'cli', deps: deps(s) })
  let outcome: string | null = null
  void ex.start().then((o) => { outcome = o }, (e: Error) => { outcome = `threw ${e.message}` })
  while (outcome === null && clock.now() - T0 < MAX_MS) await new Promise((r) => setImmediate(r))
  if (outcome === null) s.j.expire('sol')
  assert.equal(outcome, 'failed', 'before: no outcome while endpoint 1 fails')
  assert.ok(clock.now() - stopAt <= CANON.SOL_STOP_PROOF_MS + 30_000, `bounded after the Stop (${clock.now() - stopAt} ms)`)
  assert.equal(s.j.events.filter((e) => e.type === 'intent').length, 1, 'nothing re-signed')
  const st = s.j.events.filter((e) => e.type === 'stuck')
  assert.equal(st.length, 1)
  assert.match(String(st[0].data.reason), /neither confirmed nor proven expired on every verified endpoint 300 s after the Stop/)
  assert.equal(s.j.state().chains.sol!.phase, 'STUCK', 'vt job resolve is reachable')
})

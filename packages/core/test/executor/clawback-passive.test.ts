// PF-E fix round 1 (4): the ETH claw-back — the operator's way out on mainnet — never wedges and never loops for ever. Mirrors
// passive-adopt.test.ts for the claw-back family:
//   · its own passive attempt: the same signed bytes again while the pools drop it; unknown to every endpoint for
//     CANON.PASSIVE_ETH_UNSEEN_WINDOWS windows (no rebroadcast taken, the nonce unused) → stuck, vt job resolve reachable;
//   · a Stop: nothing new is signed (no first claw-back, no bump, whatever the strategy); with an attempt in flight the run ends
//     within one window — the claw-back open while it is pending, STUCK when no endpoint knows it;
//   · a claw-back member adopted at a takeover and dropped: its bytes are rebuilt from the journal and its ticket (identical, or
//     STUCK with the reason) and sent again;
//   · the Stop that settled the chain is not a Stop of the claw-back.
// ALL DATA IS SYNTHETIC: generated keys, the in-memory API and relay, fake chains; nothing listens on a port; virtual time.
import { afterEach, test } from 'node:test'
import assert from 'node:assert/strict'
import { hexToBytes, keccak256 } from 'viem'
import { createExecutor } from '../../src/executor/executor.ts'
import { useRelayClient } from '../../src/engine/rpc.js'
import * as eth from '../../src/chains/eth.js'
import { CANON } from '../../src/chains/constants.js'
import { sha256Hex } from '../../src/job/canonical.ts'
import { intentRefusal } from '../../src/job/index.ts'
import { virtualClock } from '../fakes/fake-journal.ts'
import { T0, deps, sendViolations, stack } from './helpers.ts'

afterEach(() => { assert.deepEqual(sendViolations.splice(0), [], 'every ticketed send was exactly its journaled intent (id, bytes, declared nonce)') })

const DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6', GW = 10n ** 9n
const REFUSED = 'transaction underpriced: the pool is full (test)'
const BLOCK_MS = 12_000, PASSIVE_WINDOW_MS = Number(CANON.PASSIVE_ETH_REBROADCAST_BLOCKS) * BLOCK_MS, ECON_WINDOW_MS = 3 * BLOCK_MS
// a run still going after 2 virtual hours (every case here ends within a few windows) is a wedge: the test fails
const MAX_MS = 2 * 3600_000
type S = ReturnType<typeof stack>
type Ex = ReturnType<typeof createExecutor>
const hx = (n: number): string => `0x${n.toString(16)}`
const pendingTx = (id: string) => ({ hash: id, blockNumber: null, nonce: '0x0', to: DEST, value: '0x1', input: '0x' })

// A settled chain (an earlier run journaled `stopped`, gen 2) on a chain that mints a block every 12 s of virtual time. hook: a per-test
// override of one method (undefined: the fake chain). operatorStop: the chain was stopped with `vt job stop` (stop-requested at the API).
function settled(feeStrategy: string, o: { hook?: (m: string, p: any[], ep: number | null, clock: { now(): number }, base: (m: string, p: any[]) => unknown) => unknown } = {}): S {
  const clock = virtualClock(T0)
  const s = stack('eth', { copies: 1, startIn: 0, feeStrategy, clock, ethBalance: 10n ** 17n, cap: '1000000000000000000', eth: (m, p, base, ep) => {
    const r = o.hook?.(m, p, ep, clock, base)
    if (r !== undefined) return r
    if (m === 'eth_blockNumber') return hx(100 + Math.floor((clock.now() - T0) / BLOCK_MS))
    return base(m, p)
  } })
  return s
}
async function settle(s: S, operatorStop = false): Promise<void> {
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  if (operatorStop) s.j.requestStop('eth')
  s.j.asHolder(2, 'browser', 'eth', 'stopped', { reason: 'operator' })
  s.j.expire('eth')
}
// Run the claw-back on virtual time for at most maxMs (at[i] once that much time passed); a run still going then loses its lease.
async function drive(s: S, ex: Ex, maxMs: number, at: Array<{ ms: number; go: () => void }> = []): Promise<{ outcome: string | null; ms: number }> {
  let outcome: string | null = null
  const run = ex.clawback(DEST).then((o: string) => { outcome = o }, (e: Error) => { outcome = `threw ${e.message}` })
  const t0 = s.clock.now(), todo = [...at]
  while (outcome === null && s.clock.now() - t0 < maxMs) {
    for (const x of todo.filter((y) => s.clock.now() - t0 >= y.ms)) { todo.splice(todo.indexOf(x), 1); x.go() }
    await new Promise((r) => setImmediate(r))
  }
  const ms = s.clock.now() - t0, done = outcome
  if (done === null) { s.j.expire('eth'); await run }
  return { outcome: done, ms }
}
const claws = (s: S) => s.j.events.filter((e) => e.type === 'clawback-intent')
const ex3 = (s: S) => createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
// the API's precondition for `vt job resolve` on a claw-back member (api arm.ts resolve), then mark-failed: the family fails by
// itself, the chain is settled again and a new claw-back is allowed
function resolveReachable(s: S, id: string): void {
  const cs = s.j.state().chains.eth!
  assert.deepEqual([cs.phase, cs.openIntents.includes(id)], ['STUCK', true], 'vt job resolve is reachable')
  s.j.apiEvent('resolved', { txId: id, action: 'mark-failed', typed: null }, 'eth', 'operator')
  const after = s.j.state()
  assert.deepEqual([after.chains.eth!.phase, after.chains.eth!.openIntents], ['STOPPED', []], 'the family failed by itself: settled again')
  assert.equal(intentRefusal(s.def, after, 'eth', s.j.serverNow(), 'clawback-intent'), null, 'a new claw-back is allowed')
}

test(`passive claw-back: dropped, its same-bytes rebroadcasts refused, unknown to every endpoint for ${CANON.PASSIVE_ETH_UNSEEN_WINDOWS} windows → stuck; vt job resolve is reachable (before: rebroadcast for ever)`, { timeout: 120_000 }, async () => {
  let first = true
  const s = settled('passive', { hook: (m, p) => { if (m === 'eth_sendRawTransaction') { if (first) { first = false; return keccak256(p[0] as `0x${string}`) } throw new Error(REFUSED) } } })
  await settle(s)
  const ex = ex3(s)
  const r = await drive(s, ex, MAX_MS)
  assert.equal(r.outcome, 'failed')
  const n = CANON.PASSIVE_ETH_UNSEEN_WINDOWS
  assert.ok(r.ms >= n * PASSIVE_WINDOW_MS - BLOCK_MS && r.ms <= (n + 1) * PASSIVE_WINDOW_MS, `at the end of window ${n} (${r.ms} ms)`)
  const c = claws(s)
  assert.equal(c.length, 1, 'one claw-back signed, never a second')
  const id = String(c[0].data.txId)
  assert.ok(s.relay.sends().length > n && s.relay.sends().every((x) => keccak256(x.params[0] as `0x${string}`).toLowerCase() === id), 'only its identical bytes')
  const st = s.j.events.filter((e) => e.type === 'stuck')
  assert.deepEqual(st.map((e) => e.data.txId), [id])
  assert.match(String(st[0].data.reason), new RegExp(`not known to every verified endpoint \\(the endpoint does not know it\\) after ${n} passive windows`))
  assert.match(ex.view().note, /vt job resolve/)
  resolveReachable(s, id)
})

test('M-6 passive claw-back: a node that TAKES its rebroadcast ("already known") but no endpoint shows by hash is not enough — STUCK after the unseen windows; known by hash: never stuck, and a Stop ends the run within one window, the claw-back open', { timeout: 120_000 }, async () => {
  for (const visible of [false, true]) {
    let first = true, id = ''
    const s = settled('passive', { hook: (m, p) => {
      if (m === 'eth_sendRawTransaction') { if (first) { first = false; id = keccak256(p[0] as `0x${string}`).toLowerCase(); return id } throw new Error('already known') }
      if (m === 'eth_getTransactionByHash' && visible && p[0] === id) return pendingTx(id)
      return undefined
    } })
    await settle(s)
    const ex = ex3(s)
    const stopAt = (CANON.PASSIVE_ETH_UNSEEN_WINDOWS + 2) * PASSIVE_WINDOW_MS + 100_000
    const r = await drive(s, ex, MAX_MS, [{ ms: stopAt, go: () => ex.requestStop() }])
    assert.equal(r.outcome, 'failed', 'the run ends (the claw-back did not land)')
    assert.equal(claws(s).length, 1, 'nothing new signed')
    const cs = s.j.state().chains.eth!
    if (!visible) {
      assert.ok(r.ms < stopAt, 'STUCK before the Stop')
      assert.match(String(s.j.events.find((e) => e.type === 'stuck')!.data.reason), /not known to every verified endpoint/)
      resolveReachable(s, id)
    } else {
      assert.ok(r.ms > stopAt && r.ms - stopAt <= PASSIVE_WINDOW_MS, `within one window of the Stop (${r.ms - stopAt} ms)`)
      assert.match(ex.view().note, /stopped by the operator: attempt 1 .* still pending at the nodes .* stays open/)
      assert.equal(s.j.events.filter((e) => e.type === 'stuck').length, 0)
      assert.deepEqual([cs.phase, cs.openIntents], ['CLAWING_BACK', [id]], 'open for the next run')
    }
  }
})

test('a Stop during a claw-back signs nothing new, whatever the strategy: pending → the run ends within one window, the claw-back open; unknown → STUCK; a Stop before the first signature signs nothing', { timeout: 120_000 }, async () => {
  for (const strategy of ['passive', 'economy', 'prompt']) {
    const win = strategy === 'passive' ? PASSIVE_WINDOW_MS : ECON_WINDOW_MS
    for (const pending of [true, false]) {
      let id = '', ex: Ex
      const s = settled(strategy, { hook: (m, p) => {
        if (m === 'eth_sendRawTransaction') {
          if (id === '') { id = keccak256(p[0] as `0x${string}`).toLowerCase(); ex.requestStop(); return id }   // taken, never mined; then the Stop
          throw new Error(REFUSED)
        }
        if (m === 'eth_getTransactionByHash' && pending && p[0] === id) return pendingTx(id)
        return undefined
      } })
      await settle(s)
      ex = ex3(s)
      const r = await drive(s, ex, MAX_MS)
      const name = `${strategy} pending ${pending}`
      assert.equal(r.outcome, 'failed', name)
      assert.ok(r.ms <= win + 10 * BLOCK_MS, `${name}: within one window of the Stop (${r.ms} ms)`)
      assert.equal(claws(s).length, 1, `${name}: no bump, no replacement after the Stop`)
      const cs = s.j.state().chains.eth!
      if (pending) {
        assert.match(ex.view().note, /stopped by the operator: attempt 1 .* still pending/, name)
        assert.deepEqual([cs.phase, cs.openIntents], ['CLAWING_BACK', [id]], name)
      } else {
        assert.match(String(s.j.events.find((e) => e.type === 'stuck')!.data.reason), /not known to every verified endpoint \(the endpoint does not know it\) at a Stop/, name)
        resolveReachable(s, id)
      }
    }
    // a Stop before anything is signed (economy / prompt sign at once; passive waits for a cheap block first): nothing signed
    const t = settled(strategy)
    await settle(t)
    const ex2 = ex3(t)
    ex2.requestStop()
    assert.equal((await drive(t, ex2, 3600_000)).outcome, 'failed', strategy)
    assert.match(ex2.view().note, /cancelled .*nothing was signed/, strategy)
    assert.deepEqual([claws(t).length, t.relay.sends().length], [0, 0], `${strategy}: nothing signed`)
  }
})

// gen 2 journaled a claw-back (signed with `signedValue`, journaled with `value`) and died before it landed; it was dropped
async function adoptedClaw(s: S, o: { honest?: boolean; signedValue?: bigint; ethTo?: string } = {}) {
  await settle(s)
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  useRelayClient(s.relay.client)
  const value = 10n ** 16n
  const x = await eth.signClawback(s.key.handle.account, { chainId: 31337, nonce: 0, to: DEST, value: o.signedValue ?? value, maxFee: 3n * GW, tip: GW, gas: 21_000n })
  const id = x.id.toLowerCase()
  s.j.asHolder(3, 'browser', 'eth', 'clawback-intent', { txId: id, to: DEST, value: String(value), rawSha256: o.honest === false ? 'ab'.repeat(32) : sha256Hex(hexToBytes(x.raw)), eth: { nonce: 0, tip: String(GW), maxFee: String(3n * GW), gas: '21000', to: o.ethTo ?? DEST } })
  s.j.asHolder(3, 'browser', 'eth', 'clawback-sent', { txId: id, outcome: 'unknown' })
  s.j.expire('eth')
  return { id, raw: x.raw }
}

test('a claw-back adopted at a takeover and dropped: its bytes are rebuilt (journal + ticket value, RFC 6979) and sent again — identical, so it lands; bytes that cannot be rebuilt are STUCK with the reason, nothing sent', { timeout: 120_000 }, async () => {
  const s = stack('eth', { copies: 1, startIn: 0, feeStrategy: 'passive', ethBalance: 10n ** 17n, cap: '1000000000000000000' })
  const { id, raw } = await adoptedClaw(s)
  const ex = ex3(s)
  assert.equal(await ex.clawback(DEST), 'clawed-back', 'before: watched without its bytes, then stuck')
  assert.deepEqual(s.relay.sends().map((c) => c.params[0]), [raw], 'exactly the earlier holder\'s bytes, once; nothing new signed')
  assert.equal(claws(s).length, 1)
  const mine = s.j.events.filter((e) => e.gen === 4 && e.by === 'cli')
  assert.deepEqual(mine.filter((e) => e.type !== 'clawback-readback').map((e) => [e.type, e.data.txId]), [['reconcile', id], ['clawback-included', id]])
  assert.deepEqual([s.j.state().chains.eth!.phase, s.j.state().chains.eth!.clawback!.landed], ['CLAWED_BACK', true])
  // the same takeover by a job run (`vt job run` on a chain whose claw-back is in flight): its reconcile sends the same bytes again too
  const j = stack('eth', { copies: 1, startIn: 0, feeStrategy: 'passive', ethBalance: 10n ** 17n, cap: '1000000000000000000' })
  const ja = await adoptedClaw(j)
  assert.equal(await ex3(j).start(), 'clawed-back')
  assert.deepEqual(j.relay.sends().map((c) => c.params[0]), [ja.raw], 'the job run re-sent the identical claw-back bytes')
  for (const c of [{ name: 'rawSha256', o: { honest: false }, why: /the sha256 of the rebuilt bytes is not the journaled rawSha256/ },
    { name: 'another value', o: { signedValue: 10n ** 16n + 1n }, why: /its keccak256 is not the journaled tx id/ },
    // M-7 (R11c): the ticket binds a destination that is not the member's journaled one — never signed, even in memory, never sent
    { name: 'another destination', o: { ethTo: '0x1111111111111111111111111111111111111111' }, why: /its destination is not the claw-back's/ }]) {
    const t = stack('eth', { copies: 1, startIn: 0, feeStrategy: 'passive', ethBalance: 10n ** 17n, cap: '1000000000000000000' })
    const a = await adoptedClaw(t, c.o)
    const ex2 = ex3(t)
    assert.equal(await ex2.clawback(DEST), 'failed', c.name)
    assert.equal(t.relay.sends().length, 0, `${c.name}: nothing sent`)
    const st = t.j.events.filter((e) => e.type === 'stuck')
    assert.deepEqual(st.map((e) => e.data.txId), [a.id], c.name)
    assert.match(String(st[0].data.reason), c.why, c.name)
    assert.match(String(st[0].data.reason), /nothing else is signed at that nonce/, c.name)
    resolveReachable(t, a.id)
  }
})

test('the Stop that settled the chain (`vt job stop`, still stop-requested at the API) is not a Stop of the claw-back: a passive claw-back that waits several lease ticks for a cheap block still signs and lands', { timeout: 120_000 }, async () => {
  let t0 = -1
  const s = settled('passive', { hook: (m, p, _ep, clock, base) => {
    if (m === 'eth_feeHistory' && p[1] === 'latest' && t0 >= 0 && clock.now() - t0 < 30_000) {   // the next base fee is far above the target for 30 s
      const h = base(m, p) as { baseFeePerGas: string[] }
      return { ...h, baseFeePerGas: [...h.baseFeePerGas.slice(0, -1), hx(10 * Number(GW))] }
    }
    return undefined
  } })
  await settle(s, true)
  assert.equal(s.j.state().chains.eth!.stopRequested, true)
  t0 = s.clock.now()
  const ex = ex3(s)
  const r = await drive(s, ex, 3600_000)
  assert.equal(r.outcome, 'clawed-back', `before: cancelled at the first lease tick (${ex.view().note})`)
  assert.ok(r.ms >= 30_000, 'it waited for the cheap block across several lease ticks')
  assert.equal(claws(s).length, 1)
})

test('SOL claw-back: a Stop means no new signature — before the first one nothing is signed', { timeout: 60_000 }, async () => {
  const { Keypair } = await import('@solana/web3.js')
  const s = stack('sol', { copies: 1, startIn: 0 })
  await s.j.client.lease(s.j.id, 'sol', 'acquire', 'browser')
  s.j.asHolder(2, 'browser', 'sol', 'stopped', { reason: 'operator' })
  s.j.expire('sol')
  const ex = createExecutor({ jobId: s.j.id, chain: 'sol', key: s.key, holder: 'cli', deps: deps(s) })
  ex.requestStop()
  assert.equal(await ex.clawback(Keypair.generate().publicKey.toBase58()), 'failed')
  assert.match(ex.view().note, /cancelled by a Stop .*nothing was signed/)
  assert.deepEqual([claws(s).length, s.relay.sends().length], [0, 0])
})

test('M-1 SOL claw-back: a Stop that arrives while the claw-back is being prepared (its fee read, after the loop-top check) cancels it — nothing signed, nothing sent', { timeout: 60_000 }, async () => {
  const { Keypair } = await import('@solana/web3.js')
  let ex: Ex, stopped = false
  const s = stack('sol', { copies: 1, startIn: 0, cap: '100000000000', sol: (m, p, _ep, base) => {
    if (m === 'getFeeForMessage' && !stopped) { stopped = true; ex.requestStop() }
    return base(m, p)
  } })
  await s.j.client.lease(s.j.id, 'sol', 'acquire', 'browser')
  s.j.asHolder(2, 'browser', 'sol', 'stopped', { reason: 'operator' })
  s.j.expire('sol')
  ex = createExecutor({ jobId: s.j.id, chain: 'sol', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await ex.clawback(Keypair.generate().publicKey.toBase58()), 'failed')
  assert.ok(stopped, 'the Stop came during the preparation')
  assert.match(ex.view().note, /cancelled by a Stop .*nothing was signed/)
  assert.deepEqual([claws(s).length, s.relay.sends().length], [0, 0], 'before: one claw-back journaled and sent')
})

test('M-4 SOL claw-back after a Stop with one verified endpoint failing its reads: STUCK with the reason in bounded time (CANON.SOL_STOP_PROOF_MS), nothing re-signed', { timeout: 120_000 }, async () => {
  const { Keypair } = await import('@solana/web3.js')
  let ex: Ex, stopAt = -1
  const clock = virtualClock(T0)
  const s = stack('sol', { copies: 1, startIn: 0, endpoints: 2, clock, cap: '100000000000', sol: (m, p, ep, base) => {
    if (m === 'sendTransaction') { if (stopAt < 0) { stopAt = clock.now(); ex.requestStop() } return base(m, p) }
    if (m === 'getSignatureStatuses') return { context: { slot: 2_000 }, value: (p[0] as string[]).map(() => null) }
    if (m === 'isBlockhashValid') { if (ep === 1) throw new Error('endpoint 1 unreachable (test)'); return { context: { slot: 2_000 }, value: false } }
    if (m === 'getLatestBlockhash' && p[0]?.commitment === 'finalized') { const r = base(m, p) as { context: unknown; value: { lastValidBlockHeight: number } }; return { ...r, context: { slot: 1_900 }, value: { ...r.value, lastValidBlockHeight: 2_100 } } }
    return base(m, p)
  } })
  await s.j.client.lease(s.j.id, 'sol', 'acquire', 'browser')
  s.j.asHolder(2, 'browser', 'sol', 'stopped', { reason: 'operator' })
  s.j.expire('sol')
  ex = createExecutor({ jobId: s.j.id, chain: 'sol', key: s.key, holder: 'cli', deps: deps(s) })
  let outcome: string | null = null
  void ex.clawback(Keypair.generate().publicKey.toBase58()).then((o) => { outcome = o })
  while (outcome === null && clock.now() - T0 < MAX_MS) await new Promise((r) => setImmediate(r))
  if (outcome === null) s.j.expire('sol')
  assert.equal(outcome, 'failed', 'before: no outcome while endpoint 1 fails')
  assert.ok(clock.now() - stopAt <= CANON.SOL_STOP_PROOF_MS + 30_000, `bounded (${clock.now() - stopAt} ms)`)
  assert.equal(claws(s).length, 1, 'nothing re-signed')
  assert.match(String(s.j.events.find((e) => e.type === 'stuck')!.data.reason), /neither confirmed nor proven expired on every verified endpoint/)
  assert.equal(s.j.state().chains.sol!.phase, 'STUCK')
})

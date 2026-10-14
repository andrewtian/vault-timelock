// PF-E fix round 2 (review I-1, M-3, M-5, M-7 R19): an ETH job attempt left open at an unused nonce is never a dead end.
//   · A chain already settled (STOPPED …) with that attempt open never enters the lane (its phase events would be refused): a rerun
//     runs WATCH-ONLY — its identical signed bytes are sent again in bounded windows, never a new signature — and ends with the landing
//     (settled), or STUCK with the exact reason (vt job resolve; after mark-failed: claw-back and close), or still pending (run again).
//   · The documented paths end to end: a Stop while pending, then the tx dropped, then a rerun → STUCK → resolve → claw back at that
//     nonce; a rerun after STUCK; pending then landed then a rerun.
//   · A bump that races `vt job stop` and is refused by the API (intent.after-stop) leaves a recoverable state; the API's stop state is
//     read before every new signature, so a Stop already at the API is never raced.
//   · An economy `wait` (a bump that would not fit the balance) keeps re-sending its identical bytes and is bounded like Passive.
// ALL DATA IS SYNTHETIC: generated keys, the in-memory API and relay, fake chains; nothing listens on a port; virtual time.
import { afterEach, test } from 'node:test'
import assert from 'node:assert/strict'
import { hexToBytes, keccak256, toHex } from 'viem'
import { createExecutor, laneConfigOf } from '../../src/executor/executor.ts'
import { useRelayClient } from '../../src/engine/rpc.js'
import * as eth from '../../src/chains/eth.js'
import { CANON } from '../../src/chains/constants.js'
import { planLaneCopy } from '../../src/engine/lane.js'
import { sha256Hex } from '../../src/job/canonical.ts'
import { intentRefusal } from '../../src/job/index.ts'
import { Refusal } from '../../src/contracts/index.ts'
import { virtualClock } from '../fakes/fake-journal.ts'
import { T0, deps, sendViolations, stack } from './helpers.ts'

afterEach(() => { assert.deepEqual(sendViolations.splice(0), [], 'every ticketed send was exactly its journaled intent (id, bytes, declared nonce)') })

const NULL = '0x0000000000000000000000000000000000000000', DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6', GW = 10n ** 9n
const REFUSED = 'transaction underpriced: the pool is full (test)'
const BLOCK_MS = 12_000, WINDOW_MS = Number(CANON.PASSIVE_ETH_REBROADCAST_BLOCKS) * BLOCK_MS, N = CANON.PASSIVE_ETH_UNSEEN_WINDOWS
const MAX_MS = 2 * 3600_000   // every case here ends within a few windows: a run still going after 2 virtual hours is a wedge (the test fails)
type S = ReturnType<typeof stack>
type Ex = ReturnType<typeof createExecutor>
const hx = (n: number): string => `0x${n.toString(16)}`
const pendingTx = (id: string) => ({ hash: id, blockNumber: null, nonce: '0x0', to: NULL, value: '0x0', input: '0x' })

// The chain: a block every 12 s of virtual time. Its pool, as the test sets it: `pool` (what is pending), `take` (whether a send of
// the attempt is taken into the pool), `mine` (whether a taken send is mined at once).
function chain(o: { feeStrategy: string; copies?: number; ethBalance?: bigint; cap?: string }) {
  const clock = virtualClock(T0)
  const net = { pool: new Set<string>(), take: false, mine: false, sends: 0 }
  const s = stack('eth', { copies: o.copies ?? 2, startIn: 0, feeStrategy: o.feeStrategy, clock, ethBalance: o.ethBalance ?? 10n ** 17n, cap: o.cap ?? '1000000000000000000', eth: (m, p, base) => {
    if (m === 'eth_blockNumber') return hx(100 + Math.floor((clock.now() - T0) / BLOCK_MS))
    if (m === 'eth_sendRawTransaction') {
      const id = keccak256(p[0] as `0x${string}`).toLowerCase()
      net.sends++
      if (net.mine) return base(m, p)
      if (!net.take) throw new Error(REFUSED)
      net.pool.add(id); return id
    }
    if (m === 'eth_getTransactionByHash' && net.pool.has(String(p[0]))) return pendingTx(String(p[0]))
    return base(m, p)
  } })
  return { s, net }
}
// gen 2 (the page) journaled an attempt at nonce 0 (honest digests, or `data` other than the planned part) and died
async function earlier(s: S, o: { data?: Uint8Array } = {}) {
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  useRelayClient(s.relay.client)
  const payload = planLaneCopy(laneConfigOf('eth', s.def.chains.eth!, s.text), 1)[0].payload
  const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL, data: toHex(o.data ?? payload), gas: 30_000n, maxFee: 3n * GW, tip: GW })
  const id = signed.id.toLowerCase()
  s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: sha256Hex(hexToBytes(signed.raw)), payloadSha256: sha256Hex(payload), reserved: '90000000000000', eth: { nonce: 0, tip: String(GW), maxFee: String(3n * GW), gas: '30000', to: NULL } })
  s.j.asHolder(2, 'browser', 'eth', 'sent', { txId: id, outcome: 'unknown', reason: 'timeout' })
  s.j.expire('eth')
  return { id, raw: signed.raw }
}
async function drive(s: S, run: () => Promise<string>, at: Array<{ ms: number; go: () => void }> = []): Promise<{ outcome: string | null; ms: number }> {
  let outcome: string | null = null
  const p = run().then((o) => { outcome = o }, (e: Error) => { outcome = `threw ${e.message}` })
  const t0 = s.clock.now(), todo = [...at]
  while (outcome === null && s.clock.now() - t0 < MAX_MS) {
    for (const x of todo.filter((y) => s.clock.now() - t0 >= y.ms)) { todo.splice(todo.indexOf(x), 1); x.go() }
    await new Promise((r) => setImmediate(r))
  }
  const ms = s.clock.now() - t0, done = outcome
  if (done === null) { s.j.expire('eth'); await p }
  return { outcome: done, ms }
}
const executor = (s: S) => createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
const cs = (s: S) => s.j.state().chains.eth!
const ofType = (s: S, type: string, fromSeq = 0) => s.j.events.filter((e) => e.type === type && e.seq >= fromSeq)
// vt job resolve's precondition (api arm.ts), mark-failed, then: settled with nothing open — the claw-back is allowed (core) and so is a
// close (its core-side precondition; the API's ledger side is the merge gate test/integration/merge-gate-clawback-after-mark-failed.test.ts)
function resolveFailed(s: S, id: string): void {
  assert.deepEqual([cs(s).phase, cs(s).openIntents.includes(id)], ['STUCK', true], 'vt job resolve is reachable')
  s.j.apiEvent('resolved', { txId: id, action: 'mark-failed', typed: null }, 'eth', 'operator')
  assert.deepEqual([cs(s).phase, cs(s).openIntents], ['STOPPED', []], 'settled, nothing open')
  assert.equal(intentRefusal(s.def, s.j.state(), 'eth', s.j.serverNow(), 'clawback-intent'), null, 'a claw-back is allowed')
}

test('I-1 (a) a Stop while the attempt is pending, then the pools drop it, then a rerun: watch-only, its same bytes re-sent, STUCK within the unseen windows; resolve mark-failed; the claw-back at that same nonce lands (passive and economy)', { timeout: 120_000 }, async () => {
  for (const feeStrategy of ['passive', 'economy']) {
    const { s, net } = chain({ feeStrategy })
    const { id, raw } = await earlier(s)
    net.pool.add(id)                                                   // pending at the nodes (the base fee is above its maxFee)
    const ex1 = executor(s)
    s.j.requestStop('eth'); ex1.requestStop()                          // the job Stop right away (economy would bump at once; passive just watches)
    const r1 = await drive(s, () => ex1.start())
    assert.deepEqual([r1.outcome, cs(s).phase, cs(s).openIntents], ['stopped', 'STOPPED', [id]], `${feeStrategy}: run 1 ends STOPPED, the attempt open`)
    net.pool.delete(id)                                                // the pools drop it; nonce 0 stays unused
    const seq = s.j.events.length, sends = net.sends
    const r2 = await drive(s, () => executor(s).start())
    assert.equal(r2.outcome, 'failed', `${feeStrategy}: before the fix the rerun died at copy-built (journal refused on a STOPPED chain)`)
    assert.ok(r2.ms <= (N + 1) * WINDOW_MS, `${feeStrategy}: within ${N} windows (${r2.ms} ms)`)
    assert.deepEqual(ofType(s, 'intent', seq).length + ofType(s, 'copy-built', seq).length + ofType(s, 'stopped', seq).length, 0, 'watch-only: no new intent, no phase event')
    assert.ok(net.sends > sends && s.relay.sends().slice(sends).every((c) => c.params[0] === raw), 'its identical bytes, again')
    assert.match(String(ofType(s, 'stuck', seq)[0].data.reason), /not known to every verified endpoint .* after 3 windows/)
    resolveFailed(s, id)
    net.mine = true                                                    // the claw-back at nonce 0 (the same, never-used nonce) lands
    const ex3 = executor(s)
    assert.equal(await ex3.clawback(DEST), 'clawed-back', `${feeStrategy}: ${ex3.view().note}`)
    const claw = ofType(s, 'clawback-intent')
    assert.deepEqual(claw.map((e) => (e.data.eth as { nonce: number }).nonce), [0], 'the claw-back signed at the nonce the dropped attempt held')
    assert.equal(cs(s).phase, 'CLAWED_BACK')
  }
})

test('I-1 (b) a rerun after a STUCK: watch-only again — STUCK again with the exact reason (resolve reachable), or, when the nodes take its bytes now, it lands and the chain is settled', { timeout: 120_000 }, async () => {
  for (const later of ['dropped', 'lands'] as const) {
    const { s, net } = chain({ feeStrategy: 'passive', copies: 1 })
    const { id } = await earlier(s)
    const r1 = await drive(s, () => executor(s).start())
    assert.deepEqual([r1.outcome, cs(s).phase], ['failed', 'STUCK'], 'run 1: STUCK after the unseen windows')
    if (later === 'lands') net.mine = true
    const seq = s.j.events.length
    const r2 = await drive(s, () => executor(s).start())
    assert.equal(ofType(s, 'intent', seq).length, 0, `${later}: nothing new signed`)
    if (later === 'dropped') {
      assert.equal(r2.outcome, 'failed')
      assert.deepEqual([cs(s).phase, cs(s).openIntents], ['STUCK', [id]], 'STUCK again (before the fix: STOPPED with it open, resolve unreachable)')
      resolveFailed(s, id)
    } else {
      assert.equal(r2.outcome, 'stopped')
      assert.deepEqual(ofType(s, 'included', seq).map((e) => e.data.txId), [id], 'its own bytes landed')
      assert.deepEqual([cs(s).phase, cs(s).openIntents, ofType(s, 'readback', seq)[0].data.ok], ['STOPPED', [], true], 'settled with nothing open')
    }
  }
})

test('I-1 (c) pending, then it lands while nobody runs, then a rerun: the reconcile records it; the chain is settled; nothing is sent', { timeout: 120_000 }, async () => {
  const { s, net } = chain({ feeStrategy: 'passive' })
  const { id, raw } = await earlier(s)
  net.pool.add(id)
  const ex1 = executor(s)
  await drive(s, () => ex1.start(), [{ ms: 100_000, go: () => { s.j.requestStop('eth'); ex1.requestStop() } }])
  assert.deepEqual([cs(s).phase, cs(s).openIntents], ['STOPPED', [id]])
  net.mine = true
  await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [raw])   // mined (no ticket: the test seeds the chain)
  const sends = s.relay.sends().length
  const r2 = await drive(s, () => executor(s).start())
  assert.equal(r2.outcome, 'stopped')
  assert.deepEqual([cs(s).phase, cs(s).openIntents, s.relay.sends().length - sends], ['STOPPED', [], 0])
  assert.ok(s.j.events.some((e) => e.type === 'reconcile' && e.data.txId === id && e.data.outcome === 'included'))
})

test('I-1 watch-only bounds: an attempt every endpoint still shows pending is watched for the unseen-window count and the run ends (nothing journaled, still open: run again later); one that cannot be rebuilt is STUCK at once', { timeout: 120_000 }, async () => {
  const { s, net } = chain({ feeStrategy: 'passive' })
  const { id } = await earlier(s)
  net.pool.add(id)
  const ex1 = executor(s)
  await drive(s, () => ex1.start(), [{ ms: 100_000, go: () => { s.j.requestStop('eth'); ex1.requestStop() } }])
  const seq = s.j.events.length
  const ex2 = executor(s)
  const r2 = await drive(s, () => ex2.start())
  assert.equal(r2.outcome, 'stopped')
  assert.ok(r2.ms >= N * WINDOW_MS - BLOCK_MS && r2.ms <= (N + 1) * WINDOW_MS, `${N} windows (${r2.ms} ms)`)
  assert.deepEqual([cs(s).phase, cs(s).openIntents], ['STOPPED', [id]])
  assert.deepEqual(s.j.events.slice(seq).filter((e) => e.by === 'cli').map((e) => e.type).filter((t) => !t.startsWith('lease')), ['reconcile'], 'only the reconcile is journaled')
  assert.match(ex2.view().note, /still pending at every verified endpoint after 3 windows/)
  // the same state with an attempt whose bytes are not the planned part: STUCK at once, nothing sent
  const t = chain({ feeStrategy: 'passive' })
  const bad = await earlier(t.s, { data: new TextEncoder().encode('data:,not the planned part') })
  t.net.pool.add(bad.id)
  const ex3 = executor(t.s)
  await drive(t.s, () => ex3.start(), [{ ms: 100_000, go: () => { t.s.j.requestStop('eth'); ex3.requestStop() } }])
  assert.equal(cs(t.s).phase, 'STUCK', 'already STUCK in run 1 (a Stop with an attempt it cannot re-send)')
  const r4 = await drive(t.s, () => executor(t.s).start())
  assert.equal(r4.outcome, 'failed')
  assert.ok(r4.ms < WINDOW_MS, 'at once')
  assert.match(String(ofType(t.s, 'stuck').at(-1)!.data.reason), /the chain is settled and .* cannot be sent again \(rebuilt from its journaled intent/)
  assert.equal(t.net.sends, 0)
})

test('M-7 (R19) a Stop at a takeover with an adopted attempt whose bytes cannot be rebuilt: STUCK at once with that reason, never a window later', { timeout: 60_000 }, async () => {
  for (const feeStrategy of ['economy', 'prompt', 'passive']) {
    const { s } = chain({ feeStrategy })
    await earlier(s, { data: new TextEncoder().encode('data:,not the planned part') })
    s.j.requestStop('eth')
    const r = await drive(s, () => executor(s).start())
    assert.equal(r.outcome, 'failed', feeStrategy)
    assert.ok(r.ms < 3 * BLOCK_MS, `${feeStrategy}: at once (${r.ms} ms)`)
    assert.match(String(ofType(s, 'stuck')[0].data.reason), /stopped by the operator: .* cannot be sent again \(.*keccak256 is not the journaled tx id/, feeStrategy)
  }
})

test('M-3 a bump that races `vt job stop` and is refused by the API (intent.after-stop) ends the run without `stopped` (the attempt is still open); the next run takes the Stop path: STUCK when it was dropped — then resolve, claw back', { timeout: 120_000 }, async () => {
  const { s, net } = chain({ feeStrategy: 'economy', copies: 1 })
  net.take = true                                                    // the first send is taken into the pools, never mined
  const append = s.j.client.append.bind(s.j.client)
  let raced = 0
  s.j.client.append = async (id, c, gen, type, data, x) => {
    if (type === 'intent' && (data as { attempt?: number }).attempt === 2) {   // the bump: the Stop reached the API just before it
      raced++; s.j.requestStop('eth'); throw new Refusal('intent.after-stop' as never, 'eth has a stop request: nothing new is signed after a Stop (test)')
    }
    return append(id, c, gen, type, data, x)
  }
  // the bump is signed when the API's stop state is read before the signature but the Stop arrives after that read: make the read stale
  const job = s.j.client.job.bind(s.j.client)
  s.j.client.job = async (id) => job(id)
  const r1 = await drive(s, () => executor(s).start())
  assert.equal(raced, 1, 'the bump reached the API')
  assert.equal(r1.outcome, 'stopped')
  const first = ofType(s, 'intent')[0].data.txId as string
  assert.deepEqual([cs(s).phase, cs(s).openIntents, ofType(s, 'stopped').length], ['RUNNING', [first], 0], 'no `stopped` while the attempt is open (before the fix: STOPPED with it open)')
  net.pool.clear(); net.take = false                                 // then the pools drop it
  s.j.client.append = append
  const r2 = await drive(s, () => executor(s).start())
  assert.equal(r2.outcome, 'failed')
  assert.ok(r2.ms <= 4 * 3 * BLOCK_MS, `one window of the Stop path (${r2.ms} ms)`)
  assert.equal(ofType(s, 'intent').length, 1, 'nothing new signed')
  resolveFailed(s, first)
})

test('M-3 a Stop already at the API is read before EVERY new signature (bumps too): an economy bump is never signed after it, even when no lease tick read it', { timeout: 120_000 }, async () => {
  const { s, net } = chain({ feeStrategy: 'economy', copies: 1 })
  net.take = true
  let bumpQuote = false
  const relayRpc = s.relay.client.rpc.bind(s.relay.client)
  ;(s.relay.client as { rpc: Function }).rpc = async (c: string, m: string, p: unknown[], x: unknown) => {
    // the bump's quote (after the first send): the Stop reaches the API now — after the lane's own Stop check of this round
    if (m === 'eth_estimateGas' && net.pool.size > 0 && !bumpQuote) { bumpQuote = true; s.j.requestStop('eth') }
    return relayRpc(c as never, m, p, x as never)
  }
  const r = await drive(s, () => executor(s).start())
  assert.ok(bumpQuote, 'the bump was being prepared when the Stop arrived')
  assert.equal(ofType(s, 'intent').length, 1, 'the bump was not signed (before: signed — the fake API admits a replacement after a Stop)')
  assert.equal(r.outcome, 'stopped')
  assert.deepEqual([cs(s).phase, cs(s).openIntents.length], ['STOPPED', 1], 'its one attempt open (pending at the nodes)')
})

test('M-5 an economy `wait` (a bump would not fit the balance) re-sends the identical bytes of a dropped attempt — never a new signature — and is bounded: STUCK after the unseen windows', { timeout: 120_000 }, async () => {
  // the attempt's exact worst case, from a run with ample funds; then a balance that fits it and no bump
  const probe = chain({ feeStrategy: 'economy', copies: 1 })
  probe.net.mine = true
  await drive(probe.s, () => executor(probe.s).start())
  const e0 = ofType(probe.s, 'intent')[0].data.eth as { gas: string; maxFee: string }
  const exact = BigInt(e0.gas) * BigInt(e0.maxFee)
  const { s, net } = chain({ feeStrategy: 'economy', copies: 1, ethBalance: exact * 108n / 100n })   // fits the attempt, not a ×1.125 bump
  let first = true
  const orig = s.relay.client.rpc.bind(s.relay.client)
  ;(s.relay.client as { rpc: Function }).rpc = async (c: never, m: string, p: unknown[], x: never) => {
    if (m === 'eth_sendRawTransaction' && first) { first = false; net.take = true; const r = await orig(c, m, p, x); net.pool.clear(); net.take = false; return r }   // taken, then dropped at once
    return orig(c, m, p, x)
  }
  const r = await drive(s, () => executor(s).start())
  assert.equal(r.outcome, 'failed', 'before: the `wait` never re-sent and never ended')
  const ids = ofType(s, 'intent').map((e) => e.data.txId as string)
  assert.equal(ids.length, 1, 'never a new signature')
  assert.ok(s.relay.sends().length > N && s.relay.sends().every((c) => keccak256(c.params[0] as `0x${string}`).toLowerCase() === ids[0]), 'its identical bytes, re-sent')
  assert.match(String(ofType(s, 'stuck')[0].data.reason), /not known to every verified endpoint .* after 3 windows/)
  assert.ok(r.ms <= (N + 1) * WINDOW_MS + 10 * BLOCK_MS, `bounded (${r.ms} ms)`)
})

test('I-1 watch-only: the Stop that settled the chain (`vt job stop`, still stop-requested at the API) is not a Stop of the watch — it runs its full windows; a later Ctrl-C ends it at the end of a window', { timeout: 120_000 }, async () => {
  for (const how of ['full', 'ctrl-c'] as const) {
    const { s, net } = chain({ feeStrategy: 'passive' })
    const { id } = await earlier(s)
    net.pool.add(id)
    s.j.requestStop('eth')                                             // `vt job stop`: the chain settles STOPPED with the attempt pending
    await drive(s, () => executor(s).start())
    assert.deepEqual([cs(s).phase, cs(s).openIntents, cs(s).stopRequested], ['STOPPED', [id], true])
    const ex = executor(s)
    const r = await drive(s, () => ex.start(), how === 'ctrl-c' ? [{ ms: 30_000, go: () => ex.requestStop() }] : [])
    assert.equal(r.outcome, 'stopped', how)
    if (how === 'full') assert.ok(r.ms >= N * WINDOW_MS - BLOCK_MS, `the full ${N} windows, not one (${r.ms} ms)`)
    else assert.ok(r.ms <= WINDOW_MS + BLOCK_MS, `Ctrl-C: at the end of the first window (${r.ms} ms)`)
  }
})

test('R79b M-1: Ctrl-C (a detach) during a watch-only rerun journals nothing — the attempt the pools dropped is not journaled `stuck` at the window\'s end; the chain stays STOPPED with it open, and a rerun without Ctrl-C still ends STUCK', { timeout: 120_000 }, async () => {
  const { s, net } = chain({ feeStrategy: 'passive' })
  const { id } = await earlier(s)
  net.pool.add(id)
  const ex1 = executor(s)
  s.j.requestStop('eth'); ex1.requestStop()                          // `vt job stop`: STOPPED with the attempt pending
  assert.equal((await drive(s, () => ex1.start())).outcome, 'stopped')
  assert.deepEqual([cs(s).phase, cs(s).openIntents], ['STOPPED', [id]])
  net.pool.delete(id)                                                // the pools drop it
  const seq = s.j.events.length
  const ex2 = executor(s)
  const r = await drive(s, () => ex2.start(), [{ ms: 30_000, go: () => ex2.requestStop() }])
  assert.equal(r.outcome, 'stopped', 'before R79b: `stuck` at the first window end (the detach was read as a Stop), outcome failed')
  assert.ok(r.ms <= WINDOW_MS + BLOCK_MS, `at the end of the first window (${r.ms} ms)`)
  assert.deepEqual(ofType(s, 'stuck', seq).length + ofType(s, 'stopped', seq).length, 0, 'a detach journals nothing')
  assert.deepEqual([cs(s).phase, cs(s).openIntents], ['STOPPED', [id]], 'still open for the next run')
  const r3 = await drive(s, () => executor(s).start())
  assert.equal(r3.outcome, 'failed')
  assert.match(String(ofType(s, 'stuck', seq)[0].data.reason), /not known to every verified endpoint .* after 3 windows/)
})

test('R79b M-1: Ctrl-C before a watch-only rerun whose open attempt cannot be rebuilt journals nothing (no `stuck`); without it the rerun is STUCK at once with that reason', { timeout: 60_000 }, async () => {
  for (const how of ['ctrl-c', 'plain'] as const) {
    const { s } = chain({ feeStrategy: 'passive' })
    const { id } = await earlier(s, { data: new TextEncoder().encode('data:,not the planned part') })   // its bytes cannot be rebuilt
    s.j.asHolder(2, 'browser', 'eth', 'stopped', { reason: 'stopped by the operator', code: 'operator-stop' })   // settled with it open
    assert.deepEqual([cs(s).phase, cs(s).openIntents], ['STOPPED', [id]])
    const seq = s.j.events.length
    const ex = executor(s)
    if (how === 'ctrl-c') ex.requestStop()
    const r = await drive(s, () => ex.start())
    if (how === 'ctrl-c') {
      assert.equal(r.outcome, 'stopped')
      assert.equal(ofType(s, 'stuck', seq).length, 0, 'a detach journals nothing (before R79b: stuck at once)')
      assert.deepEqual([cs(s).phase, cs(s).openIntents], ['STOPPED', [id]])
    } else {
      assert.equal(r.outcome, 'failed')
      assert.match(String(ofType(s, 'stuck', seq)[0].data.reason), /the chain is settled and .* cannot be sent again/)
    }
    assert.equal(s.relay.sends().length, 0)
  }
})

test('M5b (the PF-S fix round 5 latch, as the API reads it): a chain STUCK over a journaled stop, with no stop request held, refuses a job intent intent.after-stop at the fake API too; the executor reads that as a raced Stop', { timeout: 120_000 }, async () => {
  const { s, net } = chain({ feeStrategy: 'passive' })
  const { id } = await earlier(s)
  net.pool.add(id)
  // a journaled stop with no stop request held: one the run made itself (R79: a Ctrl-C alone journals nothing; a `vt job stop` holds
  // its request), journaled by the earlier holder with its attempt still open
  s.j.asHolder(2, 'browser', 'eth', 'stopped', { reason: 'a stop the run made itself (test)' })
  net.pool.delete(id)
  await drive(s, () => executor(s).start())                          // the watch-only rerun: STUCK over the latched STOPPED
  assert.deepEqual([cs(s).phase, cs(s).stuckBase, cs(s).stopLatched, cs(s).stopRequested], ['STUCK', 'STOPPED', true, false])
  const g = await s.j.client.lease(s.j.id, 'eth', 'acquire', 'cli')
  await s.j.client.append(s.j.id, 'eth', g.gen, 'reconcile', { txId: id, outcome: 'adopted' })   // this gen's reconcile (lease.reconcile-first)
  await s.j.client.append(s.j.id, 'eth', g.gen, 'stuck', { txId: id, reason: 'not known to every verified endpoint (test)' })
  assert.deepEqual([cs(s).phase, cs(s).stuckBase, cs(s).stopLatched], ['STUCK', 'STOPPED', true], 'STUCK again: the overlay hides STOPPED')
  const payload = planLaneCopy(laneConfigOf('eth', s.def.chains.eth!, s.text), 1)[0].payload
  const bump = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL, data: toHex(payload), gas: 30_000n, maxFee: 4n * GW, tip: 2n * GW })
  const seq = s.j.events.length
  await assert.rejects(s.j.client.append(s.j.id, 'eth', g.gen, 'intent', { txId: bump.id.toLowerCase(), copy: 1, part: 1, parts: 1, attempt: 2, replaces: id, rawSha256: sha256Hex(hexToBytes(bump.raw)), payloadSha256: sha256Hex(payload), reserved: '120000000000000', eth: { nonce: 0, tip: String(2n * GW), maxFee: String(4n * GW), gas: '30000', to: NULL } }),
    (e: unknown) => e instanceof Refusal && e.guardId === 'intent.after-stop', 'the latch, not the overlaid phase (a fake reading phase === STOPPED answers job.state, from core alone)')
  assert.equal(ofType(s, 'intent', seq).length, 0)
  assert.deepEqual([cs(s).phase, cs(s).stuckBase, cs(s).stopLatched], ['STUCK', 'STOPPED', true], 'nothing moved')
})

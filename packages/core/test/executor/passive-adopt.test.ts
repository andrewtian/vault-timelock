// PF-E — pre-flip review I-2: an ETH attempt journaled by an earlier holder and never mined (dropped from every pool) is adopted at a
// takeover. Before the fix a Passive lane (the drain default) held no bytes for it: it never rebroadcast it, never replaced it, and a
// Stop never applied — the chain stayed RUNNING with an open attempt for ever (probe /tmp/vt-review-probe/passive-adopt.test.ts,
// copied below as the first test). Now: the lane rebuilds the adopted attempt's bytes from its journaled intent and the planned
// payload (kept only when keccak256 is the journaled tx id and the send ticket binds the journaled rawSha256) and rebroadcasts them;
// bytes it cannot rebuild, an attempt unknown to every endpoint for CANON.PASSIVE_ETH_UNSEEN_WINDOWS windows, and a Stop with such an
// attempt are journaled `stuck` (vt job resolve is reachable); a Stop with the attempt still pending ends the run `stopped` at the end
// of the window. SOL needs no rebuild: the takeover reconcile watches an adopted signature until it lands or its expiry is proven on
// every endpoint (the last test). Same setup as executor.test.ts (the takeover with a pending ETH intent).
// ALL DATA IS SYNTHETIC: generated keys, the in-memory API and relay, fake chains; nothing listens on a port; virtual time.
import { afterEach, test } from 'node:test'
import assert from 'node:assert/strict'
import { base58, base64 } from '@scure/base'
import { VersionedTransaction } from '@solana/web3.js'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { hexToBytes, keccak256, toHex } from 'viem'
import { createExecutor, laneConfigOf } from '../../src/executor/executor.ts'
import { useRelayClient } from '../../src/engine/rpc.js'
import * as eth from '../../src/chains/eth.js'
import { CANON } from '../../src/chains/constants.js'
import { planLaneCopy } from '../../src/engine/lane.js'
import { sha256Hex } from '../../src/job/canonical.ts'
import { intentRefusal } from '../../src/job/index.ts'
import { virtualClock } from '../fakes/fake-journal.ts'
import { ethTx } from '../../src/engine/engine.js'
import { armedLedger, fakeEthChain, fakeRelay, recordingJournal } from '../engine/fakes.ts'
import { T0, deps, sendViolations, stack } from './helpers.ts'

afterEach(() => { assert.deepEqual(sendViolations.splice(0), [], 'every ticketed send was exactly its journaled intent (id, bytes, declared nonce)') })

const NULL = '0x0000000000000000000000000000000000000000', GW = 10n ** 9n
const REFUSED = 'transaction underpriced: the pool is full (test)'
const BLOCK_MS = 12_000, WINDOW_MS = Number(CANON.PASSIVE_ETH_REBROADCAST_BLOCKS) * BLOCK_MS
// a run still going after 2 virtual hours (every case here ends within a few windows) is a wedge: the test fails
const MAX_MS = 2 * 3600_000
type S = ReturnType<typeof stack>
type Ex = ReturnType<typeof createExecutor>
const hx = (n: number): string => `0x${n.toString(16)}`

// The earlier holder (gen 2, the page): an intent at nonce 0 signed with tip 1 gwei / maxFee 3 gwei, then `sent unknown` (a Tor timeout);
// never mined; then its lease lapses. honest: its real rawSha256 and payloadSha256 are journaled (false: the probe's 'ab'… / 'cd'…).
async function earlier(s: S, o: { honest?: boolean; data?: Uint8Array; to?: string; payloadSha256?: string; key?: S['key'] } = {}) {
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  useRelayClient(s.relay.client)
  const payload = planLaneCopy(laneConfigOf('eth', s.def.chains.eth!, s.text), 1)[0].payload
  const to = o.to ?? NULL, honest = o.honest !== false
  const signed = await eth.sign((o.key ?? s.key).handle.account, 31337, { nonce: 0, to, data: toHex(o.data ?? payload), gas: 30_000n, maxFee: 3n * GW, tip: GW })
  const id = signed.id.toLowerCase()
  s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: honest ? sha256Hex(hexToBytes(signed.raw)) : 'ab'.repeat(32),
    payloadSha256: o.payloadSha256 ?? (honest ? sha256Hex(payload) : 'cd'.repeat(32)), reserved: '90000000000000', eth: { nonce: 0, tip: String(GW), maxFee: String(3n * GW), gas: '30000', to } })
  s.j.asHolder(2, 'browser', 'eth', 'sent', { txId: id, outcome: 'unknown', reason: 'timeout' })
  return { id, raw: signed.raw }
}
// Run the executor on virtual time for at most maxMs; at[i] runs once when that much virtual time has passed. A run that has not ended
// by then loses its lease (so it stops and the test can fail cleanly instead of hanging).
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
const gen3 = (s: S, type: string) => s.j.events.filter((e) => e.type === type && e.gen === 3)
const oldSends = (s: S, id: string) => s.relay.sends().filter((c) => keccak256(c.params[0] as `0x${string}`).toLowerCase() === id)
// a chain that mints a block every 12 s of virtual time (blocks pass without any send); hook: a per-test override of one method
function chainByClock(o: { feeStrategy?: string; ethEndpoints?: number; hook?: (m: string, p: any[], ep: number | null) => unknown } = {}): S {
  const clock = virtualClock(T0)
  return stack('eth', { copies: 1, startIn: 0, feeStrategy: o.feeStrategy ?? 'passive', clock, ...(o.ethEndpoints !== undefined ? { ethEndpoints: o.ethEndpoints } : {}), eth: (m, p, base, ep) => {
    const r = o.hook?.(m, p, ep)
    if (r !== undefined) return r
    if (m === 'eth_blockNumber') return hx(100 + Math.floor((clock.now() - T0) / BLOCK_MS))
    return base(m, p)
  } })
}
// the API's precondition for `vt job resolve` (api arm.ts resolve): a STUCK chain, the tx open
function resolveReachable(s: S, id: string): void {
  const cs = s.j.state().chains.eth!
  assert.deepEqual([cs.phase, cs.openIntents.includes(id), cs.txs[0].attempts.find((a) => a.txId === id)!.state], ['STUCK', true, 'adopted'], 'vt job resolve is reachable')
  s.j.apiEvent('resolved', { txId: id, action: 'mark-failed', typed: null }, 'eth', 'operator')
  const after = s.j.state()
  assert.deepEqual([after.chains.eth!.phase, after.chains.eth!.openIntents], ['STOPPED', []], 'resolved: the chain is settled, nothing in flight')
  assert.equal(intentRefusal(s.def, after, 'eth', s.j.serverNow(), 'clawback-intent'), null, 'and the remainder can be clawed back')
}

// ---- the review probe (I-2), in the suite: economy vs passive (the probe's own journal: 'ab'… / 'cd'… digests; honest: the real ones) ----
async function probe(feeStrategy: string, honest = false) {
  const s = stack('eth', { copies: 1, startIn: 0, feeStrategy })
  const { id } = await earlier(s, { honest })
  s.j.expire('eth')
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  const r = await drive(s, ex, MAX_MS)
  return { s, id, ex, ...r }
}

test('the review probe, economy — unchanged: one same-nonce bump replacing the adopted attempt, copies-done; its bytes are never re-sent (whether or not they can be rebuilt)', { timeout: 120_000 }, async () => {
  for (const honest of [false, true]) {
    const econ = await probe('economy', honest)
    assert.equal(econ.outcome, 'copies-done', `honest ${honest}`)
    const bump = gen3(econ.s, 'intent')
    assert.deepEqual(bump.map((e) => [e.data.attempt, e.data.replaces, (e.data.eth as { nonce: number }).nonce]), [[2, econ.id, 0]], `honest ${honest}: one same-nonce bump`)
    assert.deepEqual([econ.s.relay.sends().length, oldSends(econ.s, econ.id).length], [1, 0], `honest ${honest}: the bump only`)
    assert.deepEqual(econ.s.j.state().chains.eth!.txs[0].attempts.map((a) => a.state), ['superseded', 'included'])
  }
})

test('the review probe, passive — digests that do not match the rebuilt bytes: STUCK at once with the exact reason (before the fix: no outcome after 6 virtual hours, nor after a Stop); no new intent, no tx at that nonce or any other', { timeout: 120_000 }, async () => {
  const pass = await probe('passive')
  assert.equal(pass.outcome, 'failed', 'an outcome')
  assert.ok(pass.ms < WINDOW_MS, 'at once, not after a window')
  assert.deepEqual([gen3(pass.s, 'intent').length, pass.s.relay.sends().length], [0, 0], 'nothing signed, nothing sent')
  const st = gen3(pass.s, 'stuck')
  assert.deepEqual(st.map((e) => e.data.txId), [pass.id])
  assert.match(String(st[0].data.reason), /cannot be rebroadcast: the sha256 of the rebuilt bytes is not the journaled rawSha256 .*vt job resolve/)
  assert.match(String(gen3(pass.s, 'stopped')[0].data.reason), /^stuck: /)
  resolveReachable(pass.s, pass.id)
})

test('passive + adopted + dropped: the rebuilt bytes match (keccak256 = txId, sha256 = rawSha256) → the SAME bytes are rebroadcast and land as attempt 1; no new intent, no other tx', { timeout: 60_000 }, async () => {
  const s = stack('eth', { copies: 1, startIn: 0, feeStrategy: 'passive' })
  const { id, raw } = await earlier(s)
  s.j.expire('eth')
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  const r = await drive(s, ex, MAX_MS)
  assert.equal(r.outcome, 'copies-done', 'before the fix: no outcome (no bytes to rebroadcast, passive never replaces)')
  assert.ok(r.ms < WINDOW_MS, 'within the first window')
  assert.deepEqual(s.relay.sends().map((c) => c.params[0]), [raw], 'exactly the earlier holder\'s signed bytes, once')
  assert.equal(gen3(s, 'intent').length, 0, 'nothing new signed')
  assert.deepEqual(gen3(s, 'reconcile').map((e) => [e.data.txId, e.data.outcome]), [[id, 'adopted']])
  const inc = gen3(s, 'included')
  assert.deepEqual(inc.map((e) => [e.data.txId, e.data.attempt]), [[id, 1]])
  assert.equal(gen3(s, 'readback')[0].data.ok, true)
  const cs = s.j.state().chains.eth!
  assert.deepEqual([cs.phase, cs.openIntents, cs.txs[0].attempts.map((a) => a.state)], ['COPIES_DONE', [], ['included']])
})

test('rebuild mismatch → stuck with the exact reason, nothing signed or sent at that nonce (or any other): other calldata, another recipient, a journaled payloadSha256 that is not the plan\'s', { timeout: 120_000 }, async () => {
  const cases: Array<{ name: string; o: Parameters<typeof earlier>[1]; why: RegExp }> = [
    { name: 'other calldata', o: { data: new TextEncoder().encode('data:,not the planned part') }, why: /its keccak256 is not the journaled tx id/ },
    { name: 'another recipient', o: { to: '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6' }, why: /its journaled recipient is not this lane's recipient/ },
    { name: 'payloadSha256', o: { payloadSha256: 'cd'.repeat(32) }, why: /the journaled payloadSha256 is not the planned payload's digest/ },
  ]
  for (const c of cases) {
    const s = stack('eth', { copies: 1, startIn: 0, feeStrategy: 'passive' })
    const { id } = await earlier(s, c.o)
    s.j.expire('eth')
    const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
    const r = await drive(s, ex, MAX_MS)
    assert.equal(r.outcome, 'failed', c.name)
    assert.deepEqual([gen3(s, 'intent').length, s.relay.sends().length], [0, 0], `${c.name}: nothing signed, nothing sent`)
    const st = gen3(s, 'stuck')
    assert.deepEqual(st.map((e) => e.data.txId), [id], c.name)
    assert.match(String(st[0].data.reason), c.why, c.name)
    assert.match(String(st[0].data.reason), /nothing else is signed at that nonce/, c.name)
    resolveReachable(s, id)
  }
})

test(`passive: an adopted attempt unknown to every endpoint, its nonce unused, for ${CANON.PASSIVE_ETH_UNSEEN_WINDOWS} windows of same-bytes rebroadcasts → stuck; vt job resolve is reachable`, { timeout: 120_000 }, async () => {
  // the pools dropped it and refuse it again (a full pool, a fee floor): no endpoint knows it, no rebroadcast is taken, the nonce stays unused
  const s = chainByClock({ hook: (m) => { if (m === 'eth_sendRawTransaction') throw new Error(REFUSED) } })
  const { id } = await earlier(s)
  s.j.expire('eth')
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  const r = await drive(s, ex, MAX_MS)
  assert.equal(r.outcome, 'failed', 'before the fix: no outcome after 24 virtual hours')
  const n = CANON.PASSIVE_ETH_UNSEEN_WINDOWS
  assert.ok(r.ms >= n * WINDOW_MS - BLOCK_MS && r.ms <= (n + 1) * WINDOW_MS, `at the end of window ${n} (${r.ms} ms)`)
  assert.ok(oldSends(s, id).length >= n && oldSends(s, id).length === s.relay.sends().length, 'only the identical bytes were rebroadcast, many times')
  assert.equal(gen3(s, 'intent').length, 0)
  const st = gen3(s, 'stuck')
  assert.deepEqual(st.map((e) => e.data.txId), [id])
  assert.match(String(st[0].data.reason), new RegExp(`not known to every verified endpoint \\(the endpoint does not know it\\) after ${n} windows of 25 blocks`))
  resolveReachable(s, id)
})

test('M-6: a node that TAKES the same-bytes rebroadcast ("already known", the preferred route\'s word) is not enough: an attempt no endpoint shows by hash goes STUCK after the unseen windows', { timeout: 120_000 }, async () => {
  const s = chainByClock({ hook: (m) => { if (m === 'eth_sendRawTransaction') throw new Error('already known') } })
  const { id, raw } = await earlier(s)
  s.j.expire('eth')
  const r = await drive(s, createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) }), MAX_MS)
  assert.equal(r.outcome, 'failed')
  const n = CANON.PASSIVE_ETH_UNSEEN_WINDOWS
  assert.ok(r.ms <= (n + 1) * WINDOW_MS, `within ${n} windows (${r.ms} ms)`)
  assert.ok(s.relay.sends().every((c) => c.params[0] === raw), 'only the identical bytes')
  assert.deepEqual(gen3(s, 'stuck').map((e) => e.data.txId), [id])
  resolveReachable(s, id)
})

test('M-6: the verified endpoints must AGREE that they know the attempt — one of two is not enough (STUCK after the unseen windows); both → never stuck, and a Stop ends the run `stopped` within one window, the attempt open', { timeout: 120_000 }, async () => {
  for (const both of [false, true]) {
    let id = ''
    // two verified ETH endpoints: endpoint 1 holds it in its pool (never mined); endpoint 0 too only when `both`
    const s = chainByClock({ ethEndpoints: 2, hook: (m, p, ep) => {
      if (m === 'eth_sendRawTransaction') throw new Error(REFUSED)        // no rebroadcast is taken
      if (m === 'eth_getTransactionByHash' && p[0] === id && (ep === 1 || (both && ep === 0))) return { hash: id, blockNumber: null, nonce: '0x0', to: NULL, value: '0x0', input: '0x' }
      return undefined
    } })
    id = (await earlier(s)).id
    s.j.expire('eth')
    const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
    const stopAt = (CANON.PASSIVE_ETH_UNSEEN_WINDOWS + 3) * WINDOW_MS + 100_000
    const r = await drive(s, ex, MAX_MS, [{ ms: stopAt, go: () => { s.j.requestStop('eth'); ex.requestStop() } }])
    const cs = s.j.state().chains.eth!
    assert.ok(s.relay.calls.some((c) => c.method === 'eth_getTransactionByHash' && c.ep === 1) && s.relay.calls.some((c) => c.method === 'eth_getTransactionByHash' && c.ep === 0), 'every endpoint was asked')
    if (!both) {
      assert.equal(r.outcome, 'failed', 'one endpoint\'s word: STUCK')
      assert.ok(r.ms < stopAt, 'before the Stop')
      assert.match(String(gen3(s, 'stuck')[0].data.reason), /not known to every verified endpoint \(endpoint 0 does not know it\)/)
      resolveReachable(s, id)
    } else {
      assert.equal(r.outcome, 'stopped')
      assert.ok(r.ms > stopAt && r.ms - stopAt <= WINDOW_MS, `the Stop applied within one window (${r.ms - stopAt} ms)`)
      assert.equal(gen3(s, 'stuck').length, 0, 'known to both endpoints: never stuck')
      assert.match(String(gen3(s, 'stopped')[0].data.reason), /still pending at the nodes and may land/)
      assert.deepEqual([cs.phase, cs.openIntents], ['STOPPED', [id]], 'stopped, the attempt still open for the next run')
    }
  }
})

test('Stop during loop B: an outcome within one window — `stopped` when the attempt is pending at the nodes, STUCK when no endpoint knows it', { timeout: 120_000 }, async () => {
  for (const pending of [true, false]) {
    let id = ''
    const s = chainByClock({ hook: (m, p) => {
      if (m === 'eth_sendRawTransaction') throw new Error(REFUSED)
      if (pending && m === 'eth_getTransactionByHash' && p[0] === id) return { hash: id, blockNumber: null, nonce: '0x0', to: NULL, value: '0x0', input: '0x' }
      return undefined
    } })
    id = (await earlier(s)).id
    s.j.expire('eth')
    const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
    const stopAt = 100_000                                              // in the first window, before any unseen window could end the run
    const r = await drive(s, ex, MAX_MS, [{ ms: stopAt, go: () => { s.j.requestStop('eth'); ex.requestStop() } }])
    assert.equal(r.outcome, pending ? 'stopped' : 'failed', `pending ${pending}: before the fix, no outcome after the Stop`)
    assert.ok(r.ms - stopAt <= WINDOW_MS, `pending ${pending}: within one window of the Stop (${r.ms - stopAt} ms)`)
    assert.equal(gen3(s, 'intent').length, 0, 'nothing new signed')
    const cs = s.j.state().chains.eth!
    if (pending) {
      assert.equal(s.relay.sends().length, 0, 'known: nothing to rebroadcast')
      assert.deepEqual([cs.phase, cs.openIntents, gen3(s, 'stuck').length], ['STOPPED', [id], 0])
    } else {
      const st = gen3(s, 'stuck')
      assert.deepEqual(st.map((e) => e.data.txId), [id])
      assert.match(String(st[0].data.reason), /stopped by the operator while .* is not known to every verified endpoint/)
      resolveReachable(s, id)
    }
  }
})

// the earlier run journaled stuck, the operator resolved mark-failed, and that run died before its `stopped`: RUNNING, a claim only
async function claimOnly(s: S, fields?: { gas: string; tip: string; maxFee: string }): Promise<string> {
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  useRelayClient(s.relay.client)
  const payload = planLaneCopy(laneConfigOf('eth', s.def.chains.eth!, s.text), 1)[0].payload
  const f = fields ?? { gas: '30000', tip: String(GW), maxFee: String(3n * GW) }
  const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL, data: toHex(payload), gas: BigInt(f.gas), maxFee: BigInt(f.maxFee), tip: BigInt(f.tip) })
  const id = signed.id.toLowerCase()
  s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: sha256Hex(hexToBytes(signed.raw)), payloadSha256: sha256Hex(payload), reserved: String(BigInt(f.gas) * BigInt(f.maxFee)), eth: { nonce: 0, ...f, to: NULL } })
  s.j.asHolder(2, 'browser', 'eth', 'stuck', { txId: id, reason: 'test' })
  s.j.apiEvent('resolved', { txId: id, action: 'mark-failed', typed: null }, 'eth', 'operator')
  s.j.expire('eth')
  assert.deepEqual([s.j.state().chains.eth!.phase, s.j.state().chains.eth!.openIntents], ['RUNNING', []])
  return id
}

test('passive: a part whose attempts were adopted only as claims (marked failed, nonce unused) is signed afresh in that nonce family (`replaces`), never stuck on a claim; byte-identical to the claim → the part ends, no duplicate intent', { timeout: 120_000 }, async () => {
  const s = stack('eth', { copies: 1, startIn: 0, feeStrategy: 'passive' })
  const id = await claimOnly(s)
  const r = await drive(s, createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) }), MAX_MS)
  assert.equal(r.outcome, 'copies-done')
  const mine = gen3(s, 'intent')
  assert.deepEqual(mine.map((e) => [e.data.attempt, e.data.replaces, (e.data.eth as { nonce: number }).nonce]), [[2, id, 0]], 'attempt 2 of the same nonce family')
  assert.deepEqual([gen3(s, 'stuck').length, oldSends(s, id).length], [0, 0], 'the claim is never flagged nor re-sent')
  assert.equal(gen3(s, 'included')[0].data.txId, mine[0].data.txId)
  // the same key and job on a fresh chain: the claim is exactly the tx passive would sign → no second intent for it (event.duplicate)
  const fields = mine[0].data.eth as { gas: string; tip: string; maxFee: string }
  const t = stack('eth', { copies: 1, startIn: 0, feeStrategy: 'passive', key: s.key })
  const same = await claimOnly(t, { gas: fields.gas, tip: fields.tip, maxFee: fields.maxFee })
  assert.equal(same, mine[0].data.txId, 'byte for byte the same tx')
  const r2 = await drive(t, createExecutor({ jobId: t.j.id, chain: 'eth', key: t.key, holder: 'cli', deps: deps(t) }), MAX_MS)
  assert.equal(r2.outcome, 'failed')
  assert.deepEqual([gen3(t, 'intent').length, t.relay.sends().length], [0, 0])
  assert.match(String(gen3(t, 'stopped')[0].data.reason), /byte for byte an attempt already journaled/)
  assert.equal(t.j.state().chains.eth!.phase, 'STOPPED')
  assert.equal(intentRefusal(t.def, t.j.state(), 'eth', t.j.serverNow(), 'clawback-intent'), null, 'the remainder can be clawed back')
  // a Stop already requested: nothing of the part is in flight, so nothing new is signed for it
  const u = stack('eth', { copies: 1, startIn: 0, feeStrategy: 'passive' })
  await claimOnly(u)
  u.j.requestStop('eth')
  const r3 = await drive(u, createExecutor({ jobId: u.j.id, chain: 'eth', key: u.key, holder: 'cli', deps: deps(u) }), MAX_MS)
  assert.equal(r3.outcome, 'stopped')
  assert.deepEqual([gen3(u, 'intent').length, u.relay.sends().length, u.j.state().chains.eth!.phase], [0, 0, 'STOPPED'], 'after a Stop: no new tx for a part with nothing in flight')
})

test('Stop while the status cannot be read (every chain read fails after it): the passive lane still ends `stopped` within one window, the attempt open', { timeout: 120_000 }, async () => {
  let id = '', stopped = false
  const s = chainByClock({ hook: (m, p) => {
    if (stopped && m !== 'eth_chainId') throw new Error('upstream unreachable (test)')
    if (m === 'eth_getTransactionByHash' && p[0] === id) return { hash: id, blockNumber: null, nonce: '0x0', to: NULL, value: '0x0', input: '0x' }   // pending
    return undefined
  } })
  id = (await earlier(s)).id
  s.j.expire('eth')
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  const stopAt = 100_000
  const r = await drive(s, ex, MAX_MS, [{ ms: stopAt, go: () => { stopped = true; s.j.requestStop('eth'); ex.requestStop() } }])
  assert.equal(r.outcome, 'stopped', 'before: no outcome while nothing can be read')
  assert.ok(r.ms - stopAt <= WINDOW_MS, `within one window of the Stop (${r.ms - stopAt} ms)`)
  assert.match(String(gen3(s, 'stopped')[0].data.reason), /its status cannot be read .* may still land/)
  assert.deepEqual([gen3(s, 'intent').length, gen3(s, 'stuck').length, s.j.state().chains.eth!.phase, s.j.state().chains.eth!.openIntents], [0, 0, 'STOPPED', [id]])
})

test('SOL (item 5): an adopted passive attempt that was dropped is never rebroadcast (its bytes are not held) and never re-signed early — the takeover reconcile proves its expiry on every endpoint, then ONE new signature lands; bounded by the blockhash lifetime', { timeout: 60_000 }, async () => {
  const clock = virtualClock(T0), LIFE = 90_000                    // the old blockhash leaves every endpoint's queue 90 s into the run
  const old = base58.encode(new Uint8Array(64).fill(42)), oldBh = base58.encode(new Uint8Array(32).fill(3))
  const expired = (): boolean => clock.now() - T0 > LIFE
  const s = stack('sol', { copies: 1, startIn: 0, endpoints: 2, clock, sol: (m, p, _ep, base) => {
    if (m === 'getLatestBlockhash' && p[0]?.commitment === 'finalized') return { context: { slot: 900 }, value: { blockhash: base58.encode(new Uint8Array(32).fill(9)), lastValidBlockHeight: (expired() ? 1_200 : 900) + 150 } }
    if (m === 'isBlockhashValid' && p[0] === oldBh) return { context: { slot: 900 }, value: !expired() }
    if (m === 'getSignatureStatuses') { const r = base(m, p) as { value: unknown[] }; return { context: { slot: 1_000 }, value: (p[0] as string[]).map((x, i) => (x === old ? null : r.value[i])) } }
    if (m === 'getLatestBlockhash') { const r = base(m, p) as { value: { lastValidBlockHeight: number } }; r.value.lastValidBlockHeight = 5_000; return r }
    return base(m, p)
  } })
  assert.equal(s.def.chains.sol!.feeStrategy, 'passive')
  await s.j.client.lease(s.j.id, 'sol', 'acquire', 'browser')
  s.j.asHolder(2, 'browser', 'sol', 'intent', { txId: old, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '5000', sol: { blockhash: oldBh, lastValidBlockHeight: 1_000, cuPrice: 0, cuLimit: 30_000, rung: 0, fee: '5000' } })
  s.j.asHolder(2, 'browser', 'sol', 'sent', { txId: old, outcome: 'unknown', reason: 'timeout' })
  s.j.expire('sol')
  const ex = createExecutor({ jobId: s.j.id, chain: 'sol', key: s.key, holder: 'cli', deps: deps(s) })
  let outcome: string | null = null
  void ex.start().then((o) => { outcome = o })
  const t0 = clock.now()
  while (outcome === null && clock.now() - t0 < 3600_000) await new Promise((r) => setImmediate(r))
  assert.equal(outcome, 'copies-done')
  assert.ok(clock.now() - t0 < LIFE + 60_000, 'bounded by the blockhash lifetime plus the two-round proof')
  const mine = s.j.events.filter((e) => e.gen === 3 && e.by === 'cli')
  const rc = mine.findIndex((e) => e.type === 'reconcile'), ni = mine.findIndex((e) => e.type === 'intent')
  assert.ok(rc >= 0 && rc < ni, 'reconcile expired BEFORE the new signature'); assert.deepEqual([mine[rc].data.txId, mine[rc].data.outcome], [old, 'expired'])
  const intents = mine.filter((e) => e.type === 'intent')
  assert.deepEqual(intents.map((e) => [e.data.copy, e.data.part]), [[1, 1]], 'one new signature for that part, after the proof')
  assert.notEqual(intents[0].data.txId, old)
  const sigs = s.relay.sends().map((c) => base58.encode(VersionedTransaction.deserialize(base64.decode(String(c.params[0]))).signatures[0]))
  assert.ok(sigs.length >= 1 && sigs.every((x) => x === intents[0].data.txId), 'only the new signature was ever sent: the dropped one was never re-sent')
  assert.deepEqual([s.j.state().chains.sol!.phase, s.j.state().chains.sol!.openIntents], ['COPIES_DONE', []])
})

test('an attempt adopted only as a claim (open: false) is never journaled stuck — the API takes `stuck` for open attempts only: a nonce taken with no receipt of ours flags the open attempt alone', { timeout: 30_000 }, async () => {
  const chain = fakeEthChain({ mine: false })
  fakeRelay({ eth: (m, p) => (m === 'eth_getTransactionCount' ? '0x1' : chain.handler(m, p)) })   // nonce 0 is used, by a tx we cannot see
  const { journal, events } = recordingJournal()
  const claim = `0x${'1'.repeat(64)}`, open = `0x${'2'.repeat(64)}`
  const att = (id: string, n: number, isOpen: boolean) => ({ id, n, gas: 30_000n, tip: GW, maxFee: 3n * GW, reserved: 90_000n * GW, at: 0, ticketAt: 0, adopted: true, open: isOpen })
  const t: Record<string, any> = { copy: 1, part: 1, parts: 1, payload: new TextEncoder().encode('data:,claims'), nonce: 0, state: 'sent', raws: {}, attempts: [att(claim, 1, false), att(open, 2, true)] }
  const r = await ethTx(t, { account: privateKeyToAccount(generatePrivateKey()), chainId: 31337, notify: async () => {}, alive: () => true, poll: 1, tipCap: 3n * GW,
    journal, ledger: armedLedger('eth', 10n ** 18n), lane: { txs: [] }, gasRule: { amsterdam: false, toSelf: false }, to: NULL })
  assert.equal(r, 'failed')
  assert.deepEqual(events.map((e) => [e.type, e.txId]), [['stuck', open]], 'the claim is not flagged (the API would refuse it and stop the lane)')
})

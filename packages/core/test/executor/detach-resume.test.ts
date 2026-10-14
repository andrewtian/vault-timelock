// PF-E fix round 3 — controller ruling R79: DETACH, STOP and RESUME are three different things.
//   (a) DETACH — requestStop() alone: Ctrl-C in `vt job run`, the page's "Stop running here", a closed tab. After the in-flight window
//       (nothing new signed, identical bytes only) the executor ends WITHOUT journaling `stopped` (no phase event; the lease is
//       released). The chain stays as it is; the next executor (a takeover) reconciles and continues it.
//   (b) STOP — the API's stop request (`vt job stop`, the page's job Stop) and the engine's own stops (a pre-start check, a cap, …):
//       journaled `stopped`, which latches the chain; no executor reopens it on its own.
//   (c) RESUME — the operator's resume route (resume-requested) clears the latch; the next executor reopens the chain (`resumed`,
//       which the gate takes only without the latch) and continues at the next part of the current copy (same header, same digest).
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
import { virtualClock } from '../fakes/fake-journal.ts'
import { T0, deps, sendViolations, stack, types } from './helpers.ts'

afterEach(() => { assert.deepEqual(sendViolations.splice(0), [], 'every ticketed send was exactly its journaled intent (id, bytes, declared nonce / blockhash)') })

const NULL = '0x0000000000000000000000000000000000000000', GW = 10n ** 9n
const FIVE = 'Stop between parts. '.repeat(230)   // five SOL parts
const BLOCK_MS = 12_000, MAX_MS = 2 * 3600_000
type S = ReturnType<typeof stack>
type Ex = ReturnType<typeof createExecutor>
const hx = (n: number): string => `0x${n.toString(16)}`
const intents = (s: S, chain: 'eth' | 'sol' = 'eth') => s.j.events.filter((e) => e.type === 'intent' && e.chain === chain)
const run = (s: S, chain: 'eth' | 'sol', holder: 'cli' | 'browser' = 'cli') => createExecutor({ jobId: s.j.id, chain, key: s.key, holder, deps: deps(s) })
async function drive(s: S, chain: 'eth' | 'sol', go: () => Promise<string>): Promise<string | null> {
  let outcome: string | null = null
  const p = go().then((o) => { outcome = o }, (e: Error) => { outcome = `threw ${e.message}` })
  const t0 = s.clock.now()
  while (outcome === null && s.clock.now() - t0 < MAX_MS) await new Promise((r) => setImmediate(r))
  if (outcome === null) { s.j.expire(chain); await p }
  return outcome
}
// an executor's own phase event (P1: the gate refuses it while the chain is latched)
async function executorAppend(s: S, chain: 'eth' | 'sol', type: string, data: Record<string, unknown>): Promise<string | null> {
  const g = await s.j.client.lease(s.j.id, chain, 'acquire', 'cli')
  try { await s.j.client.append(s.j.id, chain, g.gen, type, data); return null } catch (e) { return (e as { guardId?: string }).guardId ?? 'threw' } finally { await s.j.client.lease(s.j.id, chain, 'release', 'cli', g.gen) }
}

test('R79 (a) DETACH — Ctrl-C in `vt job run` and the page\'s "Stop running here": the run ends after its in-flight tx, nothing final journaled; a takeover by the other executor continues to copies-done', { timeout: 120_000 }, async () => {
  for (const [first, second] of [['cli', 'browser'], ['browser', 'cli']] as const) {
    let ex: Ex
    const s = stack('eth', { copies: 2, startIn: 0, eth: (m, p, base) => { if (m === 'eth_sendRawTransaction' && intents(s).length === 1) ex.requestStop(); return base(m, p) } })
    ex = run(s, 'eth', first)
    assert.equal(await ex.start(), 'stopped', first)
    assert.equal(ex.view().phase, 'detached', first)
    assert.deepEqual(intents(s).map((e) => e.data.copy), [1], `${first}: copy 2 never signed in this run`)
    assert.equal(s.j.events.filter((e) => e.type === 'stopped').length, 0, `${first}: no \`stopped\` journaled`)
    const st = s.j.state().chains.eth!
    assert.deepEqual([st.phase, st.stopLatched ?? false, st.copiesIncluded], ['RUNNING', false, 1], `${first}: the chain keeps running`)
    assert.equal(await run(s, 'eth', second).start(), 'copies-done', `${first} → ${second}: the takeover continues`)
    assert.deepEqual(intents(s).map((e) => e.data.copy), [1, 2], 'every copy exactly once')
    assert.deepEqual(s.j.state().chains.eth!.reassembled, [{ copy: 1, ok: true }, { copy: 2, ok: true }])
  }
})

test('R79 (a) DETACH with the in-flight tx still pending at the window end: nothing escalated (no `stopped`, no `stuck`), the attempt stays open; the takeover adopts its identical bytes, re-sends them, it lands and the job finishes', { timeout: 120_000 }, async () => {
  const clock = virtualClock(T0)
  let ex: Ex, id = '', mine = false
  const s = stack('eth', { copies: 2, startIn: 0, feeStrategy: 'passive', clock, eth: (m, p, base) => {
    if (m === 'eth_blockNumber') return hx(100 + Math.floor((clock.now() - T0) / BLOCK_MS))
    if (m === 'eth_sendRawTransaction' && !mine) { if (id === '') { id = keccak256(p[0] as `0x${string}`).toLowerCase(); ex.requestStop() } throw new Error('transaction underpriced (test)') }
    return base(m, p)
  } })
  ex = run(s, 'eth')
  assert.equal(await drive(s, 'eth', () => ex.start()), 'stopped')
  assert.equal(ex.view().phase, 'detached')
  assert.deepEqual(s.j.events.filter((e) => e.type === 'stopped' || e.type === 'stuck').length, 0, 'nothing escalated by a detach')
  const st = s.j.state().chains.eth!
  assert.deepEqual([st.phase, st.openIntents], ['RUNNING', [id]])
  mine = true                                                         // the nodes take it now
  const ex2 = run(s, 'eth')
  assert.equal(await drive(s, 'eth', () => ex2.start()), 'copies-done')
  assert.equal(s.j.events.find((e) => e.type === 'included')!.data.txId, id, 'the adopted attempt itself landed (its identical bytes)')
  assert.deepEqual(intents(s).map((e) => e.data.copy), [1, 2])
})

test('R79 (b)+(c) STOP then RESUME: `vt job stop` mid-copy → `stopped` journaled and latched; no executor can reopen it (a new run settles at once, an executor\'s `resumed` and intent are refused); `vt job resume` → the next run reopens it and continues at the next part of the same copy', { timeout: 120_000 }, async () => {
  const s = stack('sol', { copies: 1, startIn: 0, text: FIVE, sol: (m, p, _ep, base) => { if (m === 'sendTransaction' && intents(s, 'sol').length === 2 && !s.j.state().chains.sol!.stopRequested) s.j.requestStop('sol'); return base(m, p) } })
  assert.equal(await run(s, 'sol').start(), 'stopped')
  const st = s.j.state().chains.sol!
  assert.deepEqual([st.phase, st.stopLatched, intents(s, 'sol').map((e) => e.data.part)], ['STOPPED', true, [1, 2]], 'stopped after part 2, latched')
  // no executor reopens it on its own
  const seq = s.j.events.length
  assert.equal(await run(s, 'sol').start(), 'stopped', 'a new run settles at once')
  assert.equal(s.j.events.slice(seq).filter((e) => e.by === 'cli' && !e.type.startsWith('lease')).length, 0, 'it journals nothing')
  assert.equal(await executorAppend(s, 'sol', 'resumed', { reason: 'an executor trying to reopen it' }), 'job.state', 'P1: an executor\'s `resumed` is refused while latched')
  assert.match(String(intentRefusal(s.def, s.j.state(), 'sol', s.j.serverNow(), 'intent', { copy: 1, part: 3 })), /was stopped: no new intent until the operator resumes it/)
  // the operator's resume
  s.j.apiEvent('resume-requested', { chain: 'sol' }, null)
  const r = s.j.state().chains.sol!
  assert.deepEqual([r.phase, r.stopLatched ?? false, r.stopRequested], ['STOPPED', false, false], 'the latch is lifted; the chain is still STOPPED until an executor reopens it')
  assert.equal(await run(s, 'sol').start(), 'copies-done')
  const after = s.j.events.slice(seq).filter((e) => e.chain === 'sol' && e.by === 'cli').map((e) => e.type).filter((t) => !t.startsWith('lease') && t !== 'note')
  assert.equal(after[0], 'resumed', 'the executor reopens it first')
  assert.deepEqual(intents(s, 'sol').map((e) => e.data.part), [1, 2, 3, 4, 5], 'it continued at part 3; every part exactly once')
  assert.deepEqual(s.j.state().chains.sol!.reassembled, [{ copy: 1, ok: true }], 'the same copy: one header, one digest')
})

test('R79 (b)+(c) the engine\'s own stop (a pre-start check that fails at the start time) is journaled and latched; `vt job resume` reopens it and the job finishes', { timeout: 120_000 }, async () => {
  const s = stack('eth', { copies: 2, startIn: 10_000 })
  let bad = true
  const status = s.relay.client.status.bind(s.relay.client)
  let n = 0
  ;(s.relay.client as { status: () => Promise<unknown> }).status = async () => { const r = await status(); return bad && ++n > 1 ? { ...r, identity: { eth: { ok: false, message: 'chain id changed (test)' } } } : r }
  assert.equal(await run(s, 'eth').start(), 'failed')
  assert.deepEqual([s.j.state().chains.eth!.phase, s.j.state().chains.eth!.stopLatched, intents(s).length], ['STOPPED', true, 0], 'the engine\'s stop is journaled and latched')
  bad = false
  assert.equal(await run(s, 'eth').start(), 'stopped', 'latched: a run settles at once')
  s.j.apiEvent('resume-requested', { chain: 'eth' }, null)
  assert.equal(await run(s, 'eth').start(), 'copies-done', 'reopened by the operator\'s resume')
  assert.deepEqual(intents(s).map((e) => e.data.copy), [1, 2])
  assert.ok(types(s.j.events, 'eth').includes('resumed'))
})

test('R79 (c) a resume never reopens a DRAINED or COPIES_DONE chain (settled for good): the run ends at once, nothing journaled', { timeout: 60_000 }, async () => {
  const s = stack('eth', { copies: 1, startIn: 0 })
  assert.equal(await run(s, 'eth').start(), 'copies-done')
  s.j.apiEvent('resume-requested', { chain: 'eth' }, null)
  const seq = s.j.events.length
  assert.equal(await run(s, 'eth').start(), 'copies-done')
  assert.equal(s.j.events.slice(seq).filter((e) => e.by === 'cli').length, 0)
  assert.equal(await executorAppend(s, 'eth', 'resumed', { reason: 'try' }), 'job.state')
})

test('R79 (c) a resume after a STOP with the tx still pending: the reopened run adopts that attempt (its identical bytes) and continues; no watch-only, no new nonce', { timeout: 120_000 }, async () => {
  const clock = virtualClock(T0)
  let id = '', mine = false
  const s = stack('eth', { copies: 2, startIn: 0, feeStrategy: 'passive', clock, eth: (m, p, base) => {
    if (m === 'eth_blockNumber') return hx(100 + Math.floor((clock.now() - T0) / BLOCK_MS))
    if (m === 'eth_sendRawTransaction' && !mine) { if (id === '') { id = keccak256(p[0] as `0x${string}`).toLowerCase(); s.j.requestStop('eth') } return keccak256(p[0] as `0x${string}`) }   // taken, never mined
    if (m === 'eth_getTransactionByHash' && !mine && p[0] === id) return { hash: id, blockNumber: null, nonce: '0x0', to: NULL, value: '0x0', input: '0x' }
    return base(m, p)
  } })
  assert.equal(await drive(s, 'eth', () => run(s, 'eth').start()), 'stopped')
  assert.deepEqual([s.j.state().chains.eth!.phase, s.j.state().chains.eth!.stopLatched, s.j.state().chains.eth!.openIntents], ['STOPPED', true, [id]], 'stopped, latched, the attempt open')
  s.j.apiEvent('resume-requested', { chain: 'eth' }, null)
  mine = true
  assert.equal(await drive(s, 'eth', () => run(s, 'eth').start()), 'copies-done')
  assert.equal(s.j.events.find((e) => e.type === 'included')!.data.txId, id, 'the open attempt itself landed')
  assert.deepEqual(intents(s).map((e) => [e.data.copy, (e.data.eth as { nonce: number }).nonce]), [[1, 0], [2, 1]], 'no new nonce for copy 1')
})

test('R79 (a) DETACH of a SOL signature that can be neither confirmed nor proven expired (one endpoint failing): bounded, nothing escalated — no `stuck`, no `stopped`; the chain keeps running', { timeout: 120_000 }, async () => {
  const clock = virtualClock(T0)
  let ex: Ex, stopAt = -1
  const s = stack('sol', { copies: 1, startIn: 0, endpoints: 2, clock, sol: (m, p, ep, base) => {
    if (m === 'sendTransaction') { if (stopAt < 0) { stopAt = clock.now(); ex.requestStop() } return base(m, p) }
    if (m === 'getSignatureStatuses') return { context: { slot: 2_000 }, value: (p[0] as string[]).map(() => null) }
    if (m === 'isBlockhashValid') { if (ep === 1) throw new Error('endpoint 1 unreachable (test)'); return { context: { slot: 2_000 }, value: false } }
    if (m === 'getLatestBlockhash' && p[0]?.commitment === 'finalized') { const r = base(m, p) as { context: unknown; value: { lastValidBlockHeight: number } }; return { ...r, context: { slot: 1_900 }, value: { ...r.value, lastValidBlockHeight: 2_100 } } }
    return base(m, p)
  } })
  ex = run(s, 'sol')
  assert.equal(await drive(s, 'sol', () => ex.start()), 'stopped')
  assert.ok(clock.now() - stopAt <= CANON.SOL_STOP_PROOF_MS + 30_000, 'bounded')
  assert.equal(ex.view().phase, 'detached')
  assert.deepEqual(s.j.events.filter((e) => e.type === 'stuck' || e.type === 'stopped').length, 0, 'nothing escalated')
  assert.deepEqual([s.j.state().chains.sol!.phase, s.j.state().chains.sol!.openIntents.length], ['RUNNING', 1])
})


test('R79 (a) DETACH during the countdown: nothing journaled, the chain stays ARMED; the next run starts it at its time and finishes', { timeout: 60_000 }, async () => {
  const s = stack('eth', { copies: 1, startIn: 30_000 })
  const ex = run(s, 'eth')
  const p = ex.start()
  while (ex.view().phase !== 'countdown') await s.clock.sleep(500)
  ex.requestStop()
  assert.equal(await p, 'stopped')
  assert.equal(ex.view().phase, 'detached')
  assert.equal(s.j.events.filter((e) => e.type === 'stopped').length, 0, 'before R79: stopped "before the start", latching the chain')
  assert.equal(s.j.state().chains.eth!.phase, 'ARMED')
  assert.equal(await run(s, 'eth').start(), 'copies-done')
})

test('R79 (a) DETACH right at a takeover whose adopted attempt cannot be rebuilt: nothing escalated (no `stuck`) — the next run decides; a job Stop instead is STUCK at once', { timeout: 60_000 }, async () => {
  for (const how of ['detach', 'stop'] as const) {
    const s = stack('eth', { copies: 1, startIn: 0, feeStrategy: 'economy' })
    await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
    useRelayClient(s.relay.client)
    const payload = planLaneCopy(laneConfigOf('eth', s.def.chains.eth!, s.text), 1)[0].payload
    const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL, data: toHex(new TextEncoder().encode('data:,not the planned part')), gas: 30_000n, maxFee: 3n * GW, tip: GW })
    const id = signed.id.toLowerCase()
    s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: sha256Hex(hexToBytes(signed.raw)), payloadSha256: sha256Hex(payload), reserved: '90000000000000', eth: { nonce: 0, tip: String(GW), maxFee: String(3n * GW), gas: '30000', to: NULL } })
    s.j.asHolder(2, 'browser', 'eth', 'sent', { txId: id, outcome: 'unknown', reason: 'timeout' })
    s.j.expire('eth')
    if (how === 'stop') s.j.requestStop('eth')
    const ex = run(s, 'eth')
    ex.requestStop()
    const out = await ex.start()
    const stuck = s.j.events.filter((e) => e.type === 'stuck')
    if (how === 'detach') {
      assert.equal(out, 'stopped')
      assert.deepEqual([stuck.length, s.j.events.filter((e) => e.type === 'stopped').length, s.j.state().chains.eth!.phase], [0, 0, 'RUNNING'], 'nothing escalated by a detach')
    } else {
      assert.equal(out, 'failed')
      assert.match(String(stuck[0].data.reason), /stopped by the operator: .* cannot be sent again/)
    }
    assert.equal(s.relay.sends().length, 0)
  }
})

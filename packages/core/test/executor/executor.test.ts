// createExecutor (E3, spec §7.3) against the in-memory API (gens, TTL on a virtual clock, openIntents, reconcile-first,
// opaque tickets, the server's clock) and a fake relay. Review Focus 1–4: a takeover reconciles before its first intent
// and never re-sends a landed part; a lost lease stops before the next intent; the network must agree before any lease.
// ALL DATA IS SYNTHETIC; nothing listens on a port; virtual time.
import { afterEach, test } from 'node:test'
import assert from 'node:assert/strict'
import { base58 } from '@scure/base'
import { keccak256 } from 'viem'
import { createExecutor } from '../../src/executor/executor.ts'
import { useRelayClient } from '../../src/engine/rpc.js'
import * as eth from '../../src/chains/eth.js'
import { planLaneCopy } from '../../src/engine/lane.js'
import { laneConfigOf } from '../../src/executor/executor.ts'
import { JournalUnreachable } from '../../src/executor/journal-client.ts'
import { guardOf } from '../job/helpers.ts'
import { TICKET_PREFIX } from '../../src/contracts/index.ts'
import { checkSend, deps, newKey, recentBlockhashOf, sendStats, sendViolations, stack, types } from './helpers.ts'

async function guardAsync(p: Promise<unknown>): Promise<string | null> {
  try { await p } catch (e) { const g = (e as { guardId?: unknown }).guardId; if (typeof g === 'string') return g; throw e }
  return null
}
const intents = (s: ReturnType<typeof stack>) => s.j.events.filter((e) => e.type === 'intent')
const keccakOf = (raw: unknown): string => keccak256(raw as `0x${string}`)

// CC-3a: the relay refuses a signed tx whose nonce / blockhash is not the one its intent declared — every send here must pass
afterEach(() => { assert.deepEqual(sendViolations.splice(0), [], 'every ticketed send was exactly its journaled intent (id, bytes, declared nonce / blockhash)') })

test('a fresh armed job: lease, countdown by the server clock, every part sent once, copies-done; events reach the API under the live gen', { timeout: 60_000 }, async () => {
  const s = stack('eth', { copies: 2 })
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await ex.start(), 'copies-done')
  const mine = s.j.events.filter((e) => e.chain === 'eth' && e.by === 'cli')
  assert.ok(mine.every((e) => e.gen === 2), 'gen 2 (the earlier tab held gen 1)')
  assert.deepEqual(intents(s).map((e) => [e.data.copy, e.data.part]), [[1, 1], [2, 1]])
  assert.equal(s.relay.sends().length, 2)
  assert.ok(s.relay.sends().every((c) => typeof c.ticket === 'string' && c.ticket.startsWith(TICKET_PREFIX)))
  assert.deepEqual(types(s.j.events, 'eth').filter((t) => t !== 'note'), ['key-loaded', 'funds', 'copy-built', 'intent', 'sent', 'included', 'readback', 'reassembled', 'copy-built', 'intent', 'sent', 'included', 'readback', 'reassembled', 'copies-done'])
  assert.ok(s.j.events.at(-1)!.type === 'lease-released')
  const st = s.j.state().chains.eth!
  assert.deepEqual([st.phase, st.copiesIncluded, st.openIntents], ['COPIES_DONE', 2, []])
})

test('network: the job, the API and the relay must agree, before any lease (executor.network-mismatch); the key must be the job\'s (executor.key-mismatch)', { timeout: 30_000 }, async () => {
  for (const o of [{ apiNetwork: 'testnet' as const }, { relayNetwork: 'testnet' as const }]) {
    const s = stack('eth', o)
    const before = s.j.calls.filter((c) => c.startsWith('lease')).length
    const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
    assert.equal(await guardAsync(ex.start()), 'executor.network-mismatch', JSON.stringify(o))
    assert.equal(s.j.calls.filter((c) => c.startsWith('lease')).length, before, 'no lease was requested')
    assert.equal(s.relay.sends().length, 0)
  }
  const s = stack('eth', {})
  const other = newKey('eth')
  assert.equal(await guardAsync(createExecutor({ jobId: s.j.id, chain: 'eth', key: other, holder: 'cli', deps: deps(s) }).start()), 'executor.key-mismatch')
  const sol = newKey('sol')
  assert.equal(await guardAsync(createExecutor({ jobId: s.j.id, chain: 'eth', key: { ...s.key, handle: sol.handle }, holder: 'cli', deps: deps(s) }).start()), 'executor.key-mismatch', 'a handle of another key')
  const noId = stack('eth', {})
  ;(noId.relay.client as { status: () => Promise<unknown> }).status = async () => ({ network: 'local', build: 'x', confined: true, identity: { eth: { ok: false } }, endpoints: { eth: 0 } })
  assert.equal(await guardAsync(createExecutor({ jobId: noId.j.id, chain: 'eth', key: noId.key, holder: 'cli', deps: deps(noId) }).start()), 'executor.network-mismatch', 'the relay did not verify the chain')
})

test('PF-S M-2: a MAINNET eth / sol chain is not started with fewer than 2 verified relay endpoints (executor.endpoints-quorum, before any lease); 2 pass; local and testnet need 1', { timeout: 30_000 }, async () => {
  for (const [chain, o] of [['eth', { ethEndpoints: 1, endpoints: 2 }], ['sol', { ethEndpoints: 2, endpoints: 1 }], ['eth', { ethEndpoints: 0, endpoints: 2 }]] as const) {
    const s = stack(chain, { network: 'mainnet', arm: false, ...o })
    const before = s.j.calls.filter((c) => c.startsWith('lease')).length
    const ex = createExecutor({ jobId: s.j.id, chain, key: { ...s.key, network: 'mainnet' }, holder: 'cli', deps: deps(s) })
    ex.requestStop()                                                   // without the refusal the run would end at once ('stopped'), never hang
    assert.equal(await guardAsync(ex.start()), 'executor.endpoints-quorum', `${chain} ${JSON.stringify(o)}`)
    assert.equal(s.j.calls.filter((c) => c.startsWith('lease')).length, before, 'no lease was requested')
    assert.equal(s.relay.sends().length, 0)
  }
  // two verified endpoints (mainnet), or one on local / testnet: the run starts (a lease) and ends at the Stop before the arm
  for (const [chain, network, n] of [['eth', 'mainnet', 2], ['sol', 'mainnet', 3], ['eth', 'local', 1], ['sol', 'testnet', 1]] as const) {
    const s = stack(chain, { network, arm: false, ethEndpoints: n, endpoints: n })
    const before = s.j.calls.filter((c) => c.startsWith('lease')).length
    const ex = createExecutor({ jobId: s.j.id, chain, key: { ...s.key, network }, holder: 'cli', deps: deps(s) })
    ex.requestStop()
    assert.equal(await ex.start(), 'stopped', `${chain} ${network} ${n}`)
    assert.ok(s.j.calls.filter((c) => c.startsWith('lease')).length > before, `${chain} ${network}: a lease was taken`)
  }
})

test('start time by the SERVER clock: serverNowMs 10 s ahead of the local clock, the first intent comes exactly at startAt; a local clock jump never starts early', { timeout: 60_000 }, async () => {
  for (const offset of [10_000, -10_000]) {
    const s = stack('eth', { copies: 1, serverOffsetMs: offset, startIn: 20_000 })
    const startAt = s.j.state().armed!.releaseAt
    let skew = 0
    const clock = { now: () => s.clock.now() + skew, sleep: (ms: number) => s.clock.sleep(ms) }
    const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: { ...deps(s), clock } })
    const run = ex.start()
    skew = 3_600_000                                                          // the executor's own clock jumps an hour ahead
    assert.equal(await run, 'copies-done')
    const first = intents(s)[0]
    assert.ok(first.at >= startAt, `the first intent at server ${first.at} ≥ startAt ${startAt}`)
    assert.ok(first.at - startAt <= 2_000, 'and not long after it')
  }
})

test('takeover with an open ETH intent whose receipt appears: reconcile {included} BEFORE any new intent; copy 1 part 1 is never sent again', { timeout: 60_000 }, async () => {
  const s = stack('eth', { copies: 2, startIn: 0 })
  // the earlier executor (gen 2) signed and sent copy 1 part 1, journaled its intent, and died before `sent`
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  useRelayClient(s.relay.client)
  const cfg = laneConfigOf('eth', s.def.chains.eth!, s.text)
  const payload = planLaneCopy(cfg, 1)[0].payload
  const { toHex } = await import('viem')
  const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: '0x0000000000000000000000000000000000000000', data: toHex(payload), gas: 30_000n, maxFee: 3n * 10n ** 9n, tip: 10n ** 9n })
  await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [signed.raw])        // it reached the chain
  const id = signed.id.toLowerCase()
  s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '1', eth: { nonce: 0, tip: String(10n ** 9n), maxFee: String(3n * 10n ** 9n), gas: '30000', to: '0x0000000000000000000000000000000000000000' } })
  s.j.expire('eth')
  const sendsBefore = s.relay.sends().length
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await ex.start(), 'copies-done')
  const mine = s.j.events.filter((e) => e.gen === 3 && e.by === 'cli')
  const firstReconcile = mine.findIndex((e) => e.type === 'reconcile'), firstIntent = mine.findIndex((e) => e.type === 'intent')
  assert.ok(firstReconcile >= 0 && firstReconcile < firstIntent, 'reconcile before the first new intent')
  assert.deepEqual([mine[firstReconcile].data.txId, mine[firstReconcile].data.outcome], [id, 'included'])
  assert.deepEqual(intents(s).filter((e) => e.gen === 3).map((e) => [e.data.copy, e.data.part]), [[2, 1]], 'the run continued at copy 2')
  assert.equal(s.relay.sends().length - sendsBefore, 1, 'one send: copy 2 only')
  assert.equal(s.j.state().chains.eth!.copiesIncluded, 2)
  assert.deepEqual(s.j.state().chains.eth!.reassembled, [{ copy: 1, ok: true }, { copy: 2, ok: true }], 'copy 1 (completed by the reconcile) is reassembled from the chain before copy 2')
})

test('takeover: the nonce was consumed by a transaction this key\'s executor never signed → reconcile nonce-consumed, the lane stops failed', { timeout: 60_000 }, async () => {
  const s = stack('eth', { copies: 1, startIn: 0 })
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  useRelayClient(s.relay.client)
  const ours = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: '0x0000000000000000000000000000000000000000', data: '0x646174613a2c61', gas: 30_000n, maxFee: 3n * 10n ** 9n, tip: 10n ** 9n })
  const foreign = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: '0x0000000000000000000000000000000000000000', data: '0x646174613a2c62', gas: 30_000n, maxFee: 3n * 10n ** 9n, tip: 10n ** 9n })
  await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [foreign.raw])         // nonce 0 taken by another tx
  s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: ours.id.toLowerCase(), copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '1', eth: { nonce: 0, tip: String(10n ** 9n), maxFee: String(3n * 10n ** 9n), gas: '30000', to: '0x0000000000000000000000000000000000000000' } })
  s.j.expire('eth')
  const sends = s.relay.sends().length
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: { ...deps(s), rounds: 3 } })
  assert.equal(await ex.start(), 'failed')
  const rec = s.j.events.find((e) => e.type === 'reconcile' && e.gen === 3)!
  assert.deepEqual([rec.data.txId, rec.data.outcome], [ours.id.toLowerCase(), 'nonce-consumed'])
  assert.equal(intents(s).filter((e) => e.gen === 3).length, 0, 'no new intent')
  assert.equal(s.relay.sends().length, sends)
  assert.match(ex.view().note, /did not sign|another holder/)
  assert.equal(s.j.state().chains.eth!.txs[0].state, 'failed', 'the group failed')
})

test('takeover with an open SOL intent: no new intent until BOTH endpoints prove its expiry (ep routes); then reconcile expired and a re-sign', { timeout: 60_000 }, async () => {
  let expired = false
  const old = base58.encode(new Uint8Array(64).fill(42)), oldBh = base58.encode(new Uint8Array(32).fill(3))
  const s = stack('sol', { copies: 1, startIn: 0, endpoints: 2, sol: (m, p, ep, base) => {
    if (m === 'getLatestBlockhash' && p[0]?.commitment === 'finalized') return { context: { slot: 900 }, value: { blockhash: base58.encode(new Uint8Array(32).fill(9)), lastValidBlockHeight: (expired ? 1_200 : 900) + 150 } }
    if (m === 'isBlockhashValid' && p[0] === oldBh) return { context: { slot: 900 }, value: !expired }   // the blockhash leaves the queue
    if (m === 'getSignatureStatuses') { const r = base(m, p) as { value: unknown[] }; return { context: { slot: 1_000 }, value: (p[0] as string[]).map((x, i) => (x === old ? null : r.value[i])) } }
    if (m === 'getLatestBlockhash') { const r = base(m, p) as { value: { lastValidBlockHeight: number } }; r.value.lastValidBlockHeight = 5_000; return r }   // new signatures stay valid
    return base(m, p)
  } })
  await s.j.client.lease(s.j.id, 'sol', 'acquire', 'browser')
  s.j.asHolder(2, 'browser', 'sol', 'intent', { txId: old, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '5000', sol: { blockhash: base58.encode(new Uint8Array(32).fill(3)), lastValidBlockHeight: 1_000, cuPrice: 0, cuLimit: 30_000, rung: 0, fee: '5000' } })
  s.j.expire('sol')
  const ex = createExecutor({ jobId: s.j.id, chain: 'sol', key: s.key, holder: 'cli', deps: deps(s) })
  const run = ex.start()
  // while the old blockhash is valid nothing new is signed
  for (let i = 0; i < 20; i++) await s.clock.sleep(1_000)
  assert.equal(intents(s).filter((e) => e.gen === 3).length, 0, 'no intent while the old signature may still land')
  expired = true
  let statusesAfter = false
  ;(s.relay.client as { rpc: Function }).rpc = ((orig) => async (...a: unknown[]) => { const r = await (orig as Function)(...a); if (a[1] === 'getSignatureStatuses') statusesAfter = true; return r })(s.relay.client.rpc)
  assert.equal(await run, 'copies-done')
  void statusesAfter
  const mine = s.j.events.filter((e) => e.gen === 3 && e.by === 'cli')
  const r = mine.findIndex((e) => e.type === 'reconcile'), i = mine.findIndex((e) => e.type === 'intent')
  assert.ok(r >= 0 && r < i); assert.deepEqual([mine[r].data.txId, mine[r].data.outcome], [old, 'expired'])
  const eps = new Set(s.relay.calls.filter((c) => c.method === 'getSignatureStatuses' && c.ep !== null).map((c) => c.ep))
  assert.deepEqual([...eps].sort(), [0, 1], 'both endpoints were asked for the proof')
})

test('lease lost mid-run (a renew refused lease.lost): no further intent, the outcome is lease-lost', { timeout: 60_000 }, async () => {
  let sends = 0
  const s = stack('eth', { copies: 3, startIn: 0, eth: (m, p, base) => { if (m === 'eth_sendRawTransaction' && ++sends === 1) sj.expire('eth'); return base(m, p) } })
  const sj = s.j
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await ex.start(), 'lease-lost')
  assert.equal(intents(s).filter((e) => e.gen === 2).length, 1, 'only the intent before the loss')
  assert.equal(s.relay.sends().length, 1)
})

test('requestStop during an in-flight tx: `stopped` is journaled only after that tx\'s outcome (included + readback), and nothing more is sent', { timeout: 60_000 }, async () => {
  let ex: ReturnType<typeof createExecutor>
  const s = stack('eth', { copies: 3, startIn: 0, eth: (m, p, base) => { if (m === 'eth_sendRawTransaction') { s.j.requestStop('eth'); ex.requestStop() } return base(m, p) } })   // R79: the job Stop (the API's stop request), not a detach
  ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await ex.start(), 'stopped')
  const t = types(s.j.events, 'eth').filter((x) => x !== 'note')
  assert.deepEqual(t.slice(t.indexOf('intent')), ['intent', 'sent', 'included', 'readback', 'reassembled', 'stopped'])
  assert.equal(s.relay.sends().length, 1)
})

test('R72 + Review Focus 1: a run dies after copy 2 part 3; the next executor reconciles, builds copy 2 part 4 first, never re-sends parts 1–3, and copy 2 reassembles ✓', { timeout: 120_000 }, async () => {
  const text = 'R72 resume text. '.repeat(270)                                // > 4 KB: 5 SOL parts per copy
  let readbacks = 0
  const s = stack('sol', { copies: 2, startIn: 0, text })
  const sj = s.j
  const ex1 = createExecutor({ jobId: s.j.id, chain: 'sol', key: s.key, holder: 'browser', deps: { ...deps(s), onView: () => {} } })
  const orig = s.j.client.append
  s.j.client.append = async (...a: Parameters<typeof orig>) => {
    const r = await orig(...a)
    if (a[3] === 'readback' && ++readbacks === 8) sj.expire('sol')            // copy 2 part 3 read back: the tab crashes
    return r
  }
  assert.equal(await ex1.start(), 'lease-lost')
  s.j.client.append = orig
  const before = s.relay.sends().length
  assert.equal(before, 8, '5 parts of copy 1, 3 of copy 2')
  assert.deepEqual(s.j.state().chains.sol!.resume, { copy: 2, nextPart: 4 })
  const ex2 = createExecutor({ jobId: s.j.id, chain: 'sol', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await ex2.start(), 'copies-done')
  const next = intents(s).filter((e) => e.by === 'cli')
  assert.deepEqual(next.map((e) => [e.data.copy, e.data.part]), [[2, 4], [2, 5]], 'copy 2 part 4 first; parts 1–3 never again')
  assert.equal(s.relay.sends().length - before, 2)
  const ra = s.j.events.filter((e) => e.type === 'reassembled').map((e) => [e.data.copy, e.data.ok])
  assert.deepEqual(ra, [[1, true], [2, true]])
  assert.deepEqual(s.j.state().chains.sol!.reassembled, [{ copy: 1, ok: true }, { copy: 2, ok: true }])
})

test('E4 crash matrix: a run dies after the LAST copy reassembled, before copies-done; the next executor ends copies-done, signs nothing, never plans a copy past N', { timeout: 120_000 }, async () => {
  const s = stack('eth', { copies: 2, startIn: 0 })
  const sj = s.j
  const ex1 = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'browser', deps: { ...deps(s), onView: () => {} } })
  const orig = s.j.client.append
  let reassembled = 0
  s.j.client.append = async (...a: Parameters<typeof orig>) => {
    const r = await orig(...a)
    if (a[3] === 'reassembled' && ++reassembled === 2) sj.expire('eth')          // copy 2 reassembled: the tab crashes
    return r
  }
  assert.equal(await ex1.start(), 'lease-lost')
  s.j.client.append = orig
  const sends = s.relay.sends().length
  assert.equal(sends, 2)
  assert.equal(s.j.state().chains.eth!.phase, 'RUNNING', 'no copies-done yet')
  const ex2 = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await ex2.start(), 'copies-done')
  assert.equal(s.relay.sends().length, sends, 'nothing sent')
  assert.deepEqual(intents(s).filter((e) => e.by === 'cli'), [], 'nothing signed')
  assert.deepEqual([s.j.state().chains.eth!.phase, s.j.state().chains.eth!.copiesIncluded], ['COPIES_DONE', 2])
})

test('a lost intent reply is recovered with POST …/tickets (a fresh ticket for THAT intent), never a new intent', { timeout: 60_000 }, async () => {
  const s = stack('eth', { copies: 1, startIn: 0 })
  const orig = s.j.client.append
  let lost = false
  s.j.client.append = async (...a: Parameters<typeof orig>) => {
    if (a[3] === 'intent' && !lost) { lost = true; await orig(...a); throw new JournalUnreachable('the reply was lost (test)') }   // journaled, reply lost
    return orig(...a)
  }
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await ex.start(), 'copies-done')
  assert.ok(lost)
  assert.equal(intents(s).length, 1, 'one intent for that txId (event.duplicate never hit)')
  assert.ok(s.j.calls.includes('ticket'), 'the ticket route recovered the lost reply')
  assert.equal(s.relay.sends().length, 1)
  assert.equal(s.relay.sends()[0].params[0] !== undefined, true)
  // never journaled (the API refused it, nothing was sent): ticket.not-intent → the lane stops, nothing is sent
  const t = stack('eth', { copies: 1, startIn: 0 })
  const origT = t.j.client.append
  t.j.client.append = async (...a: Parameters<typeof orig>) => { if (a[3] === 'intent') throw new JournalUnreachable('no reply (test)'); return origT(...a) }
  const ext = createExecutor({ jobId: t.j.id, chain: 'eth', key: t.key, holder: 'cli', deps: deps(t) })
  assert.equal(await ext.start(), 'failed')
  assert.deepEqual([t.relay.sends().length, intents(t).length], [0, 0], 'never journaled: never sent')
  assert.ok(t.j.calls.includes('ticket'), 'it asked; ticket.not-intent answered')
})

test('Skip: refused client-side without IsTor (testnet) or without a fresh passing simulation (executor.skip); allowed → POST …/skip', { timeout: 60_000 }, async () => {
  const s = stack('eth', { copies: 1, startIn: 60_000 })
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await guardAsync(ex.skip()), 'executor.skip', 'no simulation yet')
  const run = ex.start()
  while (ex.view().phase !== 'countdown') await s.clock.sleep(500)
  await ex.skip()
  assert.ok(s.j.events.some((e) => e.type === 'skip'))
  assert.equal(await run, 'copies-done')
  const t = stack('eth', { copies: 1, startIn: 60_000, network: 'testnet', isTor: false })
  const ext = createExecutor({ jobId: t.j.id, chain: 'eth', key: { ...t.key, network: 'testnet' }, holder: 'cli', deps: deps(t) })
  const runT = ext.start()
  while (!['countdown', 'failed', 'stopped'].includes(ext.view().phase)) await t.clock.sleep(500)
  assert.equal(await guardAsync(ext.skip()), 'executor.skip', 'IsTor ✗ on testnet')
  assert.ok(!t.j.events.some((e) => e.type === 'skip'))
  ext.requestStop()
  assert.equal(await runT, 'stopped')
  void guardOf
})

test('claw-back: after a settled run, clawback(to) reconciles first, then claws back at the lane\'s fee strategy; over the armed cap it needs the typed exact amount (CC-2a)', { timeout: 60_000 }, async () => {
  const DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
  const settledStack = () => {
    const s = stack('eth', { copies: 1, startIn: 0, ethBalance: 3n * 10n ** 17n, cap: '100000000000000000' })
    return s
  }
  const s = settledStack()
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  s.j.asHolder(2, 'browser', 'eth', 'stopped', { reason: 'operator' })
  s.j.expire('eth')
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await ex.clawback(DEST), 'failed', 'value + fee (the whole 0.3 ETH) is over the 0.1 ETH armed cap')
  assert.match(ex.view().note, /type exactly 300000000000000000/)
  assert.equal(s.relay.sends().length, 0); assert.ok(!s.j.events.some((e) => e.type === 'clawback-intent'))
  const typed = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: { ...deps(s), clawbackConfirm: { amount: '300000000000000000' } } })
  assert.equal(await typed.clawback(DEST), 'clawed-back')
  const cs = s.j.state().chains.eth!
  assert.deepEqual([cs.phase, cs.clawback!.landed, cs.clawback!.to], ['CLAWED_BACK', true, DEST])
  const i = s.j.events.find((e) => e.type === 'clawback-intent')!
  assert.equal(BigInt(i.data.value as string) + 21_000n * BigInt((i.data.eth as { maxFee: string }).maxFee), 3n * 10n ** 17n, 'the typed amount = value + gas × maxFee')
  const wrong = settledStack()
  await wrong.j.client.lease(wrong.j.id, 'eth', 'acquire', 'browser')
  wrong.j.asHolder(2, 'browser', 'eth', 'stopped', { reason: 'operator' }); wrong.j.expire('eth')
  const w = createExecutor({ jobId: wrong.j.id, chain: 'eth', key: wrong.key, holder: 'cli', deps: { ...deps(wrong), clawbackConfirm: { amount: '299999999999999999' } } })
  assert.equal(await w.clawback(DEST), 'failed', 'a typed amount that is not exactly value + fee is refused')
  assert.equal(wrong.relay.sends().length, 0)
})

test('takeover with a pending ETH intent (its nonce unused): reconcile adopted, then a same-nonce bump that replaces it (attempt 2) — never a new nonce, never the old bytes again', { timeout: 60_000 }, async () => {
  const s = stack('eth', { copies: 1, startIn: 0 })
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  useRelayClient(s.relay.client)
  const cfg = laneConfigOf('eth', s.def.chains.eth!, s.text)
  const { toHex } = await import('viem')
  const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: '0x0000000000000000000000000000000000000000', data: toHex(planLaneCopy(cfg, 1)[0].payload), gas: 30_000n, maxFee: 3n * 10n ** 9n, tip: 10n ** 9n })
  const old = signed.id.toLowerCase()                                        // signed and journaled, never mined (dropped)
  s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: old, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '90000000000000', eth: { nonce: 0, tip: String(10n ** 9n), maxFee: String(3n * 10n ** 9n), gas: '30000', to: '0x0000000000000000000000000000000000000000' } })
  s.j.asHolder(2, 'browser', 'eth', 'sent', { txId: old, outcome: 'unknown', reason: 'timeout' })
  s.j.expire('eth')
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await ex.start(), 'copies-done')
  const mine = s.j.events.filter((e) => e.gen === 3 && e.by === 'cli')
  assert.deepEqual([mine[0].type, mine[0].data.txId, mine[0].data.outcome], ['reconcile', old, 'adopted'])
  const bump = intents(s).filter((e) => e.gen === 3)
  assert.equal(bump.length, 1)
  assert.deepEqual([bump[0].data.attempt, bump[0].data.replaces, (bump[0].data.eth as { nonce: number }).nonce], [2, old, 0], 'a replacement of the adopted attempt, same nonce')
  const inc = s.j.events.find((e) => e.type === 'included')!
  assert.deepEqual([inc.data.txId, inc.data.attempt], [bump[0].data.txId, 2])
  assert.deepEqual(s.j.state().chains.eth!.txs[0].attempts.map((a) => a.state), ['superseded', 'included'])
})

test('takeover after a crash between included and readback: the landed part is re-read from the chain (never re-sent) and the run goes on; bytes that do not match, or a status-0 receipt, stop it', { timeout: 60_000 }, async () => {
  const { toHex } = await import('viem')
  const NULL = '0x0000000000000000000000000000000000000000'
  for (const kind of ['match', 'other bytes', 'status 0'] as const) {
    const match = kind === 'match'
    let failedId = ''
    const s = stack('eth', { copies: 2, startIn: 0, eth: (m, p, base) => {
      const r = base(m, p) as Record<string, unknown> | null
      return m === 'eth_getTransactionReceipt' && r !== null && p[0] === failedId ? { ...r, status: '0x0' } : r
    } })
    await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
    useRelayClient(s.relay.client)
    const cfg = laneConfigOf('eth', s.def.chains.eth!, s.text)
    const payload = planLaneCopy(cfg, 1)[0].payload
    const data = kind !== 'other bytes' ? toHex(payload) : toHex(new TextEncoder().encode('data:,not the planned bytes'))
    const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL, data, gas: 60_000n, maxFee: 3n * 10n ** 9n, tip: 10n ** 9n })
    await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [signed.raw])        // it landed
    const id = signed.id.toLowerCase()
    if (kind === 'status 0') failedId = id
    s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '1', eth: { nonce: 0, tip: String(10n ** 9n), maxFee: String(3n * 10n ** 9n), gas: '60000', to: NULL } })
    s.j.asHolder(2, 'browser', 'eth', 'sent', { txId: id, outcome: 'accepted', reason: null })
    s.j.asHolder(2, 'browser', 'eth', 'included', { txId: id, copy: 1, part: 1, attempt: 1, block: '101', fee: '1', ms: 1 })   // then the tab died
    s.j.expire('eth')
    assert.deepEqual(s.j.state().chains.eth!.resume, { copy: 1, nextPart: 1 }, 'not complete without its readback')
    const sends = s.relay.sends().length
    const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
    const out = await ex.start()
    const rb = s.j.events.filter((e) => e.type === 'readback' && e.gen === 3)
    if (match) {
      assert.equal(out, 'copies-done')
      assert.deepEqual([rb[0].data.txId, rb[0].data.ok], [id, true], 'the re-read readback of the landed part')
      assert.deepEqual(intents(s).filter((e) => e.gen === 3).map((e) => [e.data.copy, e.data.part]), [[2, 1]], 'copy 1 part 1 never again')
      assert.equal(s.relay.sends().length - sends, 1)
      assert.deepEqual(s.j.state().chains.eth!.reassembled, [{ copy: 1, ok: true }, { copy: 2, ok: true }])
    } else {
      assert.equal(out, 'failed', kind)
      assert.match(ex.view().note, kind === 'status 0' ? /does not read back \(landed with status 0\)/ : /does not read back \(.*≠ payload bytes/)
      assert.deepEqual([rb.map((e) => [e.data.txId, e.data.ok]), intents(s).filter((e) => e.gen === 3).length, s.relay.sends().length - sends], [[[id, false]], 0, 0], 'the evidence journaled NOT ok (final round m-3: the journal fact), nothing sent')
    }
  }
})

test('the pre-start check runs at the start time: a relay identity that fails there stops the chain (stopped, outcome failed), nothing is signed', { timeout: 60_000 }, async () => {
  const s = stack('eth', { copies: 1, startIn: 10_000 })
  let n = 0
  const status = s.relay.client.status.bind(s.relay.client)
  ;(s.relay.client as { status: () => Promise<unknown> }).status = async () => { const r = await status(); return ++n === 1 ? r : { ...r, identity: { eth: { ok: false, message: 'chain id changed (test)' } } } }
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await ex.start(), 'failed')
  const st = s.j.events.find((e) => e.type === 'stopped')!
  assert.match(String(st.data.reason), /identity/)
  assert.deepEqual([intents(s).length, s.relay.sends().length], [0, 0])
})

test('an adopted ETH group keeps the JOURNALED attempt numbers: attempt 1 (open, the higher fee) lands after the takeover → included {attempt: 1}', { timeout: 60_000 }, async () => {
  const NULL = '0x0000000000000000000000000000000000000000', GW = 10n ** 9n
  let mineOld: string | null = null
  const s = stack('eth', { copies: 1, startIn: 0, eth: (m, p, base) => {
    // the old attempt reaches a block only after the takeover adopted it
    if (mineOld !== null && m === 'eth_getTransactionReceipt' && sj.events.some((e) => e.type === 'reconcile' && e.data.outcome === 'adopted')) { const r = mineOld; mineOld = null; base('eth_sendRawTransaction', [r]) }
    return base(m, p)
  } })
  const sj = s.j
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  useRelayClient(s.relay.client)
  const cfg = laneConfigOf('eth', s.def.chains.eth!, s.text)
  const { toHex } = await import('viem')
  const data = toHex(planLaneCopy(cfg, 1)[0].payload)
  const a1 = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL, data, gas: 60_000n, maxFee: 5n * GW, tip: GW })
  const a2 = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL, data, gas: 60_000n, maxFee: 4n * GW, tip: GW })
  const id1 = a1.id.toLowerCase(), id2 = a2.id.toLowerCase()
  const ethOf = (maxFee: bigint) => ({ nonce: 0, tip: String(GW), maxFee: String(maxFee), gas: '60000', to: NULL })
  s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id1, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '1', eth: ethOf(5n * GW) })
  s.j.asHolder(2, 'browser', 'eth', 'sent', { txId: id1, outcome: 'accepted', reason: null })
  s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id2, copy: 1, part: 1, parts: 1, attempt: 2, replaces: id1, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '1', eth: ethOf(4n * GW) })
  s.j.asHolder(2, 'browser', 'eth', 'sent', { txId: id2, outcome: 'rejected', reason: 'replacement transaction underpriced' })
  s.j.expire('eth')
  mineOld = a1.raw
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await ex.start(), 'copies-done')
  const mine = s.j.events.filter((e) => e.gen === 3 && e.by === 'cli')
  assert.deepEqual(mine.filter((e) => e.type === 'reconcile').map((e) => [e.data.txId, e.data.outcome]), [[id1, 'adopted']], 'the rejected attempt is never adopted')
  const inc = s.j.events.find((e) => e.type === 'included')!
  assert.deepEqual([inc.data.txId, inc.data.attempt], [id1, 1], 'the journaled attempt number, not its place in the adopted list')
  assert.equal(intents(s).filter((e) => e.gen === 3).length, 0, 'nothing new signed')
})

test('CC-3a: each intent declares the exact nonce (ETH) or recentBlockhash (SOL) it signs; a re-sign is a new intent (replaces); the relay-side check refuses anything else', { timeout: 60_000 }, async () => {
  const before = sendStats.checked
  for (const chain of ['eth', 'sol'] as const) {
    const s = stack(chain, { copies: 2, startIn: 0 })
    assert.equal(await createExecutor({ jobId: s.j.id, chain, key: s.key, holder: 'cli', deps: deps(s) }).start(), 'copies-done')
    for (const e of intents(s)) {
      const d = e.data as { eth?: { nonce: number }; sol?: { blockhash: string } }
      assert.ok(chain === 'eth' ? Number.isSafeInteger(d.eth?.nonce) : typeof d.sol?.blockhash === 'string', 'declared')
    }
  }
  assert.ok(sendStats.checked - before >= 4, 'the check ran on every send')
  // the check itself (negative controls): a tx signed at another nonce / blockhash than its intent declares is refused
  const s = stack('eth', { copies: 1 })
  const { toHex } = await import('viem')
  const { sha256Hex } = await import('../../src/job/canonical.ts')
  const tx = await eth.sign(s.key.handle.account, 31337, { nonce: 1, to: '0x0000000000000000000000000000000000000000', data: toHex(new TextEncoder().encode('data:,x')), gas: 30_000n, maxFee: 3n * 10n ** 9n, tip: 10n ** 9n })
  const { hexToBytes } = await import('viem')
  const r = sha256Hex(hexToBytes(tx.raw as `0x${string}`))
  const ev = (nonce: number) => [{ type: 'intent', data: { txId: tx.id.toLowerCase(), rawSha256: r, eth: { nonce } } }]
  const tk = (t: string, q: string) => `${TICKET_PREFIX}${Buffer.from(JSON.stringify({ t, r, q })).toString('base64url')}.x`
  const ticket = tk(tx.id.toLowerCase(), '1')
  assert.equal(checkSend(ev(1), 'eth', [tx.raw], ticket), null)
  assert.match(String(checkSend(ev(0), 'eth', [tx.raw], ticket)), /nonce 1 ≠ declared 0/)
  const sol = await import('../../src/chains/sol.js')
  const k = newKey('sol')
  const t2 = stack('sol', { copies: 1, key: k })
  useRelayClient(t2.relay.client)
  const p = await sol.prepare(k.handle.kp.publicKey, new TextEncoder().encode('memo'), { priorityLamports: 0, cuPriceCap: 2_000_000 })
  const sg = sol.sign(k.handle.kp, p)
  const { base64 } = await import('@scure/base')
  const rs = sha256Hex(base64.decode(sg.raw))
  const sev = (blockhash: string) => [{ type: 'intent', data: { txId: sg.id, rawSha256: rs, sol: { blockhash } } }]
  const stk = (q: string) => `${TICKET_PREFIX}${Buffer.from(JSON.stringify({ t: sg.id, r: rs, q })).toString('base64url')}.x`
  const st = stk(p.blockhash)
  assert.equal(checkSend(sev(p.blockhash), 'sol', [sg.raw], st), null)
  assert.match(String(checkSend(sev(base58.encode(new Uint8Array(32).fill(200))), 'sol', [sg.raw], st)), /blockhash .* ≠ declared/)
  assert.match(String(checkSend(sev(p.blockhash), 'sol', [sg.raw], stk(base58.encode(new Uint8Array(32).fill(200))))), /ticket q .* ≠ the signed blockhash/)
  assert.match(String(checkSend(ev(1), 'eth', [tx.raw], tk(tx.id.toLowerCase(), '2'))), /ticket q 2 ≠ the signed nonce 1/)
  assert.match(String(checkSend(ev(1), 'eth', [tx.raw], tk('other', '1'))), /no journaled intent/)
})

test('E3 review m-6: a key handle never serializes or shows its secret (JSON, spread, Object.keys, util.inspect); the engine still reads it by name', async () => {
  const { inspect } = await import('node:util')
  const { fromSecret } = await import('../../src/engine/keys.js')
  for (const chain of ['eth', 'sol'] as const) {
    const k = newKey(chain), h = k.handle as { secret: string; kp?: { secretKey: Uint8Array }; address: string }
    const secret = h.secret
    assert.equal(typeof secret, 'string'); assert.ok(secret.length > 40)
    const shown = [JSON.stringify(k), JSON.stringify(h), JSON.stringify({ ...h }), Object.keys(h).join(','), inspect(k, { depth: 6 }), inspect(h, { depth: 6 })]
    const needles = [secret, secret.replace(/^0x/, '')]
    if (chain === 'sol') needles.push(JSON.stringify(Array.from(h.kp!.secretKey.slice(0, 8))).slice(1, -1))
    for (const s of shown) for (const n of needles) assert.ok(!s.includes(n), `${chain}: the secret is not shown`)
    assert.equal(fromSecret(chain, secret).address, h.address, 'the secret is still readable by name (backups)')
    assert.throws(() => { (h as { secret: string }).secret = 'x' }, TypeError, 'and read-only')
  }
})

// E3 review I-1: Stop is honoured between parts (R64; the API rule; prototype add7b lane.js:135). A 5-part SOL copy.
const FIVE = 'Stop between parts. '.repeat(230)
test('R79 (a) DETACH: Ctrl-C (requestStop alone) during part 1 of 5 — the in-flight part resolves, NOTHING final is journaled (no `stopped`, the chain stays RUNNING, never latched); a takeover then continues at part 2 to copies-done', { timeout: 60_000 }, async () => {
  let ex: ReturnType<typeof createExecutor>
  const s = stack('sol', { copies: 1, startIn: 0, text: FIVE, sol: (m, p, _ep, base) => { if (m === 'sendTransaction' && ex !== undefined && intents(s).length === 1) ex.requestStop(); return base(m, p) } })
  ex = createExecutor({ jobId: s.j.id, chain: 'sol', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await ex.start(), 'stopped')
  assert.equal(ex.view().phase, 'detached')
  assert.match(ex.view().note, /detached: nothing final was journaled/)
  assert.deepEqual(intents(s).map((e) => [e.data.copy, e.data.part]), [[1, 1]], 'part 2 is never signed in this run')
  const t = types(s.j.events, 'sol').filter((x) => x !== 'note')
  assert.deepEqual(t.slice(t.indexOf('intent')), ['intent', 'sent', 'included', 'readback'], 'no `stopped` (before R79: stopped, latching the chain)')
  const st = s.j.state().chains.sol!
  assert.deepEqual([st.phase, st.stopLatched ?? false, st.stopRequested], ['RUNNING', false, false])
  assert.ok(s.j.events.at(-1)!.type === 'lease-released', 'the lease is released')
  // the next executor (a takeover: vt job run, Run here) reconciles and continues at part 2
  const ex2 = createExecutor({ jobId: s.j.id, chain: 'sol', key: s.key, holder: 'browser', deps: deps(s) })
  assert.equal(await ex2.start(), 'copies-done')
  assert.deepEqual(intents(s).map((e) => e.data.part), [1, 2, 3, 4, 5], 'every part exactly once')
  assert.equal(s.j.state().chains.sol!.phase, 'COPIES_DONE')
})

test('I-1: an API Stop mid-copy (the API refuses every new intent after it): the run ends `stopped` after the in-flight part, the chain is STOPPED, never stuck RUNNING; a run started after it signs nothing', { timeout: 60_000 }, async () => {
  let sj: ReturnType<typeof stack>['j']
  const s = stack('sol', { copies: 1, startIn: 0, text: FIVE, sol: (m, p, _ep, base) => { if (m === 'sendTransaction' && !sj.state().chains.sol!.stopRequested) sj.requestStop('sol'); return base(m, p) } })
  sj = s.j
  const ex = createExecutor({ jobId: s.j.id, chain: 'sol', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await ex.start(), 'stopped')
  assert.deepEqual(intents(s).map((e) => e.data.part), [1])
  assert.deepEqual([s.j.state().chains.sol!.phase, s.j.state().chains.sol!.openIntents], ['STOPPED', []])
  assert.ok(!s.j.calls.some((c, i) => c === 'append:intent' && i > s.j.calls.indexOf('append:readback')), 'no intent was even attempted after the Stop')
  // a fresh job whose Stop came before the run: nothing is signed, `stopped` is journaled, the chain is STOPPED
  const t = stack('sol', { copies: 1, startIn: 0, text: FIVE })
  t.j.requestStop('sol')
  const ex2 = createExecutor({ jobId: t.j.id, chain: 'sol', key: t.key, holder: 'cli', deps: deps(t) })
  assert.equal(await ex2.start(), 'stopped')
  assert.deepEqual([intents(t).length, t.relay.sends().length, t.j.state().chains.sol!.phase], [0, 0, 'STOPPED'])
  assert.ok(!t.j.calls.includes('append:intent'), 'the executor read the Stop at start: no intent was even attempted')
})

test('I-1 (SOL): a Stop while the in-flight signature is unconfirmed — once its expiry is proven nothing is re-signed; the run ends stopped', { timeout: 60_000 }, async () => {
  let expired = false, ex: ReturnType<typeof createExecutor>
  const s = stack('sol', { copies: 1, startIn: 0, text: FIVE, sol: (m, p, _ep, base) => {
    if (m === 'sendTransaction') { s.j.requestStop('sol'); ex.requestStop(); return base(m, p) }   // R79: the job Stop
    if (m === 'isBlockhashValid') return { context: { slot: 2_000 }, value: !expired }   // Efix3
    if (m === 'getSignatureStatuses') return { context: { slot: 2_000 }, value: (p[0] as string[]).map(() => null) }   // never confirmed
    if (m === 'getLatestBlockhash' && p[0]?.commitment === 'finalized') { const r = base(m, p) as { context: unknown; value: { lastValidBlockHeight: number } }; return { ...r, context: { slot: 1_000 }, value: { ...r.value, lastValidBlockHeight: expired ? 2_000 : 900 } } }
    return base(m, p)
  } })
  ex = createExecutor({ jobId: s.j.id, chain: 'sol', key: s.key, holder: 'cli', deps: deps(s) })
  const run = ex.start()
  for (let i = 0; i < 10; i++) await s.clock.sleep(1_000)
  expired = true
  assert.equal(await run, 'stopped')
  assert.deepEqual(intents(s).map((e) => e.data.part), [1], 'no re-sign after the Stop')
  assert.ok(s.j.events.some((e) => e.type === 'reconcile' && e.data.outcome === 'expired'), 'the expiry was proven and journaled first')
  assert.equal(s.j.state().chains.sol!.phase, 'STOPPED')
})

test('I-1: a Stop that races the next intent (it reaches the API after the executor read the stop state): the API refuses the intent, the run journals `stopped` and ends stopped', { timeout: 60_000 }, async () => {
  const s = stack('sol', { copies: 1, startIn: 0, text: FIVE })
  const orig = s.j.client.append
  s.j.client.append = async (...a: Parameters<typeof orig>) => {
    if (a[3] === 'intent' && (a[4] as { part: number }).part === 2 && !s.j.state().chains.sol!.stopRequested) s.j.requestStop('sol')   // after the refresh
    return orig(...a)
  }
  const ex = createExecutor({ jobId: s.j.id, chain: 'sol', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await ex.start(), 'stopped')
  assert.deepEqual([intents(s).map((e) => e.data.part), s.relay.sends().length], [[1], 1], 'part 2 was refused, nothing sent')
  assert.equal(s.j.state().chains.sol!.phase, 'STOPPED')
  assert.match(String(s.j.events.find((e) => e.type === 'stopped')!.data.reason), /refused the next intent/)
})

test('m-4: a LOCAL lease loss (the renew reply never comes back; the API still holds the lease) journals nothing final — the outcome is lease-lost and the chain stays resumable', { timeout: 60_000 }, async () => {
  const s = stack('eth', { copies: 1, startIn: 0, eth: (m, p, base) => (m === 'eth_sendRawTransaction' ? keccakOf(p[0]) : base(m, p)) })   // accepted, never mined
  const journal = { ...s.j.client, lease: async (...a: Parameters<typeof s.j.client.lease>) => { const g = await s.j.client.lease(...a); if (a[2] === 'renew' && intents(s).length > 0) await new Promise<never>(() => {}); return g } }
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: { ...deps(s), journal } })
  assert.equal(await ex.start(), 'lease-lost')
  assert.ok(!s.j.events.some((e) => e.type === 'stopped'), 'no `stopped` (it would end the chain for good)')
  assert.notEqual(s.j.state().chains.eth!.phase, 'STOPPED')
  assert.deepEqual(s.j.state().chains.eth!.openIntents.length, 1, 'the open attempt is left for the next holder\'s reconcile')
})

// E3 review I-2: ETH nonce-consumed only on positive evidence. A lagging index hides our landed tx (its receipt, the
// tx by hash and the block's body) while the account nonce already shows the nonce used.
function lagStack(o: { copies?: number; ethBalance?: bigint; cap?: string } = {}) {
  const hidden = new Set<string>()
  let lag = true
  const s = stack('eth', { copies: o.copies ?? 1, startIn: 0, ...(o.ethBalance !== undefined ? { ethBalance: o.ethBalance } : {}), ...(o.cap !== undefined ? { cap: o.cap } : {}), eth: (m, p, base) => {
    if (lag && (m === 'eth_getTransactionReceipt' || m === 'eth_getTransactionByHash') && hidden.has(String(p[0]))) return null
    if (lag && m === 'eth_getBlockByNumber') { const b = base(m, p) as { transactions: unknown[] } | null; return b === null ? null : { ...b, transactions: [] } }
    return base(m, p)
  } })
  return { s, hide: (id: string) => hidden.add(id), catchUp: () => { lag = false } }
}

test('I-2 (review probe C): our part landed but the index lags — the takeover journals `stuck`, never nonce-consumed; once the index catches up the next run records the landing and the part is NEVER published twice', { timeout: 60_000 }, async () => {
  const NULL = '0x0000000000000000000000000000000000000000'
  const { s, hide, catchUp } = lagStack()
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  useRelayClient(s.relay.client)
  const cfg = laneConfigOf('eth', s.def.chains.eth!, s.text)
  const { toHex } = await import('viem')
  const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL, data: toHex(planLaneCopy(cfg, 1)[0].payload), gas: 60_000n, maxFee: 3n * 10n ** 9n, tip: 10n ** 9n })
  const id = signed.id.toLowerCase()
  hide(id)
  await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [signed.raw])       // it landed (nonce 0 used)
  s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '1', eth: { nonce: 0, tip: String(10n ** 9n), maxFee: String(3n * 10n ** 9n), gas: '60000', to: NULL } })
  s.j.asHolder(2, 'browser', 'eth', 'sent', { txId: id, outcome: 'accepted', reason: null })
  s.j.expire('eth')
  const run1 = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: { ...deps(s), rounds: 3 } })
  assert.equal(await run1.start(), 'failed')
  assert.ok(!s.j.events.some((e) => e.type === 'reconcile' && e.data.outcome === 'nonce-consumed'), 'never nonce-consumed from absence')
  assert.equal(s.j.events.filter((e) => e.type === 'stuck').length, 1)
  assert.match(String(s.j.events.find((e) => e.type === 'stuck')!.data.reason), /run again later/)
  assert.deepEqual([intents(s).filter((e) => e.gen! >= 3).length, s.relay.sends().length], [0, 1], 'nothing signed')
  catchUp()
  const run2 = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await run2.start(), 'copies-done')
  const rec = s.j.events.find((e) => e.type === 'reconcile' && e.data.outcome === 'included')!
  assert.equal(rec.data.txId, id)
  assert.deepEqual([intents(s).length, s.relay.sends().length, s.ethChain.mined.size], [1, 1, 1], 'copy 1 part 1 is on chain once')
  assert.deepEqual(s.j.state().chains.eth!.reassembled, [{ copy: 1, ok: true }])
})

test('I-2 (review probe C2): a landed claw-back under the same lag is not journaled dead; the next run records it landed with the chain\'s value and fee', { timeout: 60_000 }, async () => {
  const DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6', GW = 10n ** 9n
  const { s, hide, catchUp } = lagStack({ ethBalance: 3n * 10n ** 17n })
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  useRelayClient(s.relay.client)
  s.j.asHolder(2, 'browser', 'eth', 'stopped', { reason: 'operator' })
  const value = 10n ** 17n
  const c = await eth.signClawback(s.key.handle.account, { chainId: 31337, nonce: 0, to: DEST, value, maxFee: 3n * GW, tip: GW, gas: 21_000n })
  const id = c.id.toLowerCase()
  hide(id)
  await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [c.raw])
  s.j.asHolder(2, 'browser', 'eth', 'clawback-intent', { txId: id, to: DEST, value: String(value), rawSha256: 'ab'.repeat(32), eth: { nonce: 0, tip: String(GW), maxFee: String(3n * GW), gas: '21000', to: DEST } })
  s.j.asHolder(2, 'browser', 'eth', 'clawback-sent', { txId: id, outcome: 'accepted' })
  s.j.expire('eth')
  const run1 = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: { ...deps(s), rounds: 3 } })
  assert.equal(await run1.clawback(DEST), 'failed')
  const cs1 = s.j.state().chains.eth!
  assert.ok(!s.j.events.some((e) => e.type === 'reconcile' && e.data.outcome === 'nonce-consumed'), 'the family is not journaled dead')
  assert.deepEqual([cs1.openIntents, cs1.clawback!.ok], [[id], null], 'still open')
  catchUp()
  const run2 = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await run2.clawback(DEST), 'clawed-back')
  const inc = s.j.events.find((e) => e.type === 'clawback-included')!
  const m = s.ethChain.mined.get(id)!
  assert.deepEqual([inc.data.txId, inc.data.value, inc.data.fee], [id, String(value), String(m.gasUsed * m.price)], 'the chain\'s value and fee')
  const cs2 = s.j.state().chains.eth!
  assert.deepEqual([cs2.phase, cs2.clawback!.landed, cs2.clawback!.value], ['CLAWED_BACK', true, String(value)])
  assert.equal(s.ethChain.mined.size, 1, 'no second claw-back')
})

test('I-2: before a part is signed again, every earlier attempt is re-checked — a dead-journaled attempt that landed after all is recorded (D-1), not re-published', { timeout: 60_000 }, async () => {
  const NULL = '0x0000000000000000000000000000000000000000'
  const s = stack('eth', { copies: 1, startIn: 0 })
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  useRelayClient(s.relay.client)
  const cfg = laneConfigOf('eth', s.def.chains.eth!, s.text)
  const { toHex } = await import('viem')
  const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL, data: toHex(planLaneCopy(cfg, 1)[0].payload), gas: 60_000n, maxFee: 3n * 10n ** 9n, tip: 10n ** 9n })
  const id = signed.id.toLowerCase()
  await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [signed.raw])
  s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '1', eth: { nonce: 0, tip: String(10n ** 9n), maxFee: String(3n * 10n ** 9n), gas: '60000', to: NULL } })
  s.j.asHolder(2, 'browser', 'eth', 'reconcile', { txId: id, outcome: 'nonce-consumed' })   // an earlier (buggy) holder's claim
  s.j.expire('eth')
  assert.equal(s.j.state().chains.eth!.txs[0].state, 'failed')
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await ex.start(), 'copies-done')
  assert.deepEqual([intents(s).length, s.relay.sends().length, s.ethChain.mined.size], [1, 1, 1], 'never re-published')
  assert.equal(s.j.events.find((e) => e.type === 'reconcile' && e.gen === 3)!.data.outcome, 'included')
})

test('m-3: a part whose only attempt was journaled `rejected` (its nonce still unused) is reconciled at takeover: the lane bumps THAT nonce with `replaces`, never a fresh family', { timeout: 60_000 }, async () => {
  const NULL = '0x0000000000000000000000000000000000000000'
  const s = stack('eth', { copies: 1, startIn: 0 })
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  useRelayClient(s.relay.client)
  const cfg = laneConfigOf('eth', s.def.chains.eth!, s.text)
  const { toHex } = await import('viem')
  const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL, data: toHex(planLaneCopy(cfg, 1)[0].payload), gas: 60_000n, maxFee: 3n * 10n ** 9n, tip: 10n ** 9n })
  const id = signed.id.toLowerCase()
  s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: 'cd'.repeat(32), reserved: '1', eth: { nonce: 0, tip: String(10n ** 9n), maxFee: String(3n * 10n ** 9n), gas: '60000', to: NULL } })
  s.j.asHolder(2, 'browser', 'eth', 'sent', { txId: id, outcome: 'rejected', reason: 'intrinsic gas too low' })
  s.j.expire('eth')
  assert.deepEqual(s.j.state().chains.eth!.openIntents, [], 'nothing open: only a claim')
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  assert.equal(await ex.start(), 'copies-done')
  const mine = intents(s).filter((e) => e.gen === 3)
  assert.deepEqual(mine.map((e) => [e.data.attempt, e.data.replaces, (e.data.eth as { nonce: number }).nonce]), [[2, id, 0]], 'a replacement in the same nonce family')
})

test('I-1 + PF-E fix 1: a Stop already requested at a takeover with an adopted pending ETH attempt — NOTHING new is signed (no bump, no replacement): its identical bytes are sent again and land, then the run stops before the next copy; bytes that cannot be re-sent are STUCK', { timeout: 60_000 }, async () => {
  const { hexToBytes, toHex } = await import('viem')
  const { sha256Hex } = await import('../../src/job/canonical.ts')
  for (const honest of [true, false]) {
    const s = stack('eth', { copies: 2, startIn: 0 })
    await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
    useRelayClient(s.relay.client)
    const cfg = laneConfigOf('eth', s.def.chains.eth!, s.text)
    const payload = planLaneCopy(cfg, 1)[0].payload
    const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: '0x0000000000000000000000000000000000000000', data: toHex(payload), gas: 30_000n, maxFee: 3n * 10n ** 9n, tip: 10n ** 9n })
    const old = signed.id.toLowerCase()                                        // journaled and pending (never mined)
    s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: old, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: honest ? sha256Hex(hexToBytes(signed.raw)) : 'ab'.repeat(32), payloadSha256: honest ? sha256Hex(payload) : 'cd'.repeat(32), reserved: '90000000000000', eth: { nonce: 0, tip: String(10n ** 9n), maxFee: String(3n * 10n ** 9n), gas: '30000', to: '0x0000000000000000000000000000000000000000' } })
    s.j.asHolder(2, 'browser', 'eth', 'sent', { txId: old, outcome: 'unknown', reason: 'timeout' })
    s.j.expire('eth')
    s.j.requestStop('eth')
    const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
    assert.equal(await ex.start(), honest ? 'stopped' : 'failed')
    assert.equal(intents(s).filter((e) => e.gen === 3).length, 0, `honest ${honest}: no new signature after the Stop`)
    const t = types(s.j.events, 'eth').filter((x) => x !== 'note')
    if (honest) {
      assert.deepEqual(t.slice(t.indexOf('reconcile')), ['reconcile', 'copy-built', 'included', 'readback', 'reassembled', 'stopped'], 'the in-flight part landed with its own bytes, then the Stop')
      assert.deepEqual(s.relay.sends().map((c) => keccakOf(c.params[0]).toLowerCase()), [old], 'only the identical bytes, once; copy 2 never signed')
      assert.equal(s.j.state().chains.eth!.phase, 'STOPPED')
    } else {
      assert.deepEqual([s.relay.sends().length, s.j.state().chains.eth!.phase], [0, 'STUCK'], 'nothing sent; STUCK for the operator')
      assert.match(String(s.j.events.find((e) => e.type === 'stuck')!.data.reason), /rawSha256/)
    }
  }
})

// PF-S fix round 3 (kept at the M5 merge beside PF-E's engine-side test above): the gate's intent.after-stop is a raced Stop.
test('PF-S fix round 3: an API Stop that races the next intent — the API refuses it intent.after-stop, nothing is signed, and the run ends `stopped` (not failed)', { timeout: 60_000 }, async () => {
  const s = stack('eth', { copies: 2, startIn: 0 })
  // the Stop lands at the API between the executor's last read and its copy-2 intent: the gate refuses that intent
  const refused: string[] = []
  const raced = { ...s.j.client, append: async (...a: Parameters<typeof s.j.client.append>) => {
    if (a[3] === 'intent' && (a[4] as { copy?: number }).copy === 2) s.j.requestStop('eth')
    try { return await s.j.client.append(...a) } catch (e) { refused.push(String((e as { guardId?: string }).guardId)); throw e }
  } }
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s, { journal: raced }) })
  assert.equal(await ex.start(), 'stopped')
  assert.deepEqual(intents(s).map((e) => e.data.copy), [1], 'copy 2 was never journaled')
  assert.equal(s.relay.sends().length, 1, 'only copy 1 was sent')
  assert.ok(s.j.calls.includes('append:intent'))
  const st = s.j.events.filter((e) => e.type === 'stopped').at(-1)!
  assert.match(String(st.data.reason), /refused the next intent after the Stop/)
  assert.equal(s.j.state().chains.eth!.phase, 'STOPPED')
  assert.deepEqual(refused, ['intent.after-stop'], 'the refusal the executor read is the gate\'s intent.after-stop')
})

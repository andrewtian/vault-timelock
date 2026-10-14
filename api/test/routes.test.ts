// The routes over HTTP: status; lease; events append (shape, executor types only, the chain's formats, live gen,
// reconcile-first, the legacy latch, the job-send lock, the job-domain send checks, fsync before the ack, a ticket bound
// to the intent); fresh tickets; job.missing. Jobs are real (job service, store, journal), armed over HTTP.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { fsyncSync, ftruncateSync, readFileSync, rmSync, writeSync } from 'node:fs'
import { join } from 'node:path'
import { LEASE_TTL_MS } from '@vault-timelock/core/contracts'
import type { JournalEvent, Network } from '@vault-timelock/core/contracts'
import { normalizeJob } from '@vault-timelock/core/job'
import { ethGasBudget, ethGasFormula } from '@vault-timelock/core/chains/plan.js'
import { networkName } from 'vt-broadcast/src/config.ts'
import { createStore } from 'vt-broadcast/src/lifecycle/store.ts'
import { openTrigger } from 'vt-broadcast/src/lifecycle/triggers.ts'
import { JOURNAL_FILE } from '../src/journal.ts'
import type { JournalFs } from '../src/journal.ts'
import { clawbackToAllowed, createRegistry } from '../src/jobs.ts'
import { verifyTicket } from '../src/tickets.ts'
import {
  CAPS, CLAWBACK_TO, JOB, JOB2, JOB2_INPUT, JOB_INPUT, KEYS, NULL_ADDRESS, START, TICKET_KEY, armBody, armed, call, ethClawback, ethIntent as intent, ethTx as tx,
  MAINNET_CLAWBACK_TO, guardOf, idOf, onNetwork, plannedGas, plannedParts, plannedPayloads, rawOf as raw, seedReady, solHash, solIntent, solSig, startApi, writeJob,
} from './helpers.ts'
import type { Reply, TestApi } from './helpers.ts'

process.env.NODE_ENV = 'test'

const lease = (a: TestApi, op: string, holder: string, gen?: number, chain = 'eth', network: Network = 'local', id = JOB) =>
  call(a.port, { path: `/jobs/${id}/chains/${chain}/lease`, body: gen === undefined ? { op, holder } : { op, holder, gen }, network })
const append = (a: TestApi, gen: number, type: string, data: unknown, chain = 'eth', network: Network = 'local', id = JOB) =>
  call(a.port, { path: `/jobs/${id}/chains/${chain}/events`, body: { gen, type, data }, network })
const ticket = (a: TestApi, gen: number, txId: string, network: Network = 'local', id = JOB) =>
  call(a.port, { path: `/jobs/${id}/chains/eth/tickets`, body: { gen, txId }, network })
const journalLines = (a: TestApi, id = JOB): Array<Record<string, unknown>> =>
  readFileSync(join(a.state, 'jobs', id, JOURNAL_FILE), 'utf8').split('\n').slice(0, -1).map((l) => JSON.parse(l))

async function api(t: { after(fn: () => Promise<void>): void }, o: Parameters<typeof startApi>[0] = {}): Promise<TestApi> {
  const a = await startApi(o)
  t.after(() => a.close())
  return a
}
// JOB armed (eth), released, and leased by `holder` (gen 1).
async function running(t: { after(fn: () => Promise<void>): void }, holder = 'browser', o: Parameters<typeof startApi>[0] = {}): Promise<TestApi> {
  const a = await api(t, o)
  await armed(a, a.ids[0], ['eth'])
  assert.equal((await lease(a, 'acquire', holder, undefined, 'eth', 'local', a.ids[0])).status, 200)
  return a
}
// A legacy T1 trigger opened (synthetic) in the API's $OUT, as broadcast's own CLI would.
async function openLegacyTrigger(a: TestApi): Promise<void> {
  await openTrigger({ out: a.out, store: createStore(a.out, { log: () => {} }) }, {
    id: 'f2-0123456789', profile: 'local', source: 'cli', ref: 'synthetic-legacy', payloadSha256: 'ab'.repeat(32),
    chains: [{ dest: 'eth', network: networkName('local', 'eth'), address: null, bytesSha256: 'cd'.repeat(32), explorer: null }],
  }, { now: () => 1791504000 })
}

// M2 FLIP (applied, operator R78): jobSends reads MAINNET_JOB_SENDS_ENABLED, now ENABLED on every network; mainnetSends stays LOCKED.
test('GET /status: the network names, mainnet sends LOCKED, mainnet job sends ENABLED (the M2 flip), the legacy latch clear (then open)', async (t) => {
  const a = await api(t)
  const r = await call(a.port, { path: '/status' })
  assert.equal(r.status, 200)
  assert.equal(r.headers['content-type'], 'application/json; charset=utf-8')
  assert.equal(r.headers['cache-control'], 'no-store')
  assert.deepEqual(r.json, { network: 'local', networks: { eth: 'anvil · 31337', sol: 'Solana local' }, mainnetSends: 'LOCKED', jobSends: 'ENABLED',
    build: 'test', confined: true, legacyLatch: 'clear', serverNowMs: 1791504000000 })
  await openLegacyTrigger(a)
  assert.equal(((await call(a.port, { path: '/status' })).json as { legacyLatch: string }).legacyLatch, 'open')
  const m = await api(t, { network: 'testnet' })
  assert.deepEqual((await call(m.port, { path: '/status', network: 'testnet' })).json, { network: 'testnet', networks: { eth: 'Sepolia · 11155111', sol: 'Solana devnet' },
    mainnetSends: 'LOCKED', jobSends: 'ENABLED', build: 'test', confined: true, legacyLatch: 'clear', serverNowMs: 1791504000000 })
  const mn = await api(t, { network: 'mainnet', jobs: [] })
  const ms = (await call(mn.port, { path: '/status', network: 'mainnet' })).json as { network: string; mainnetSends: string; jobSends: string }
  assert.deepEqual([ms.network, ms.mainnetSends, ms.jobSends], ['mainnet', 'LOCKED', 'ENABLED'])
})

test('lease route: acquire / renew / release, and their body shapes', async (t) => {
  const a = await api(t)
  const g = await lease(a, 'acquire', 'browser')
  assert.equal(g.status, 200)
  assert.deepEqual(g.json, { gen: 1, ttlMs: 15000, expiresAt: 1791504015000, holder: 'browser', openIntents: [] })
  assert.equal(guardOf(await lease(a, 'acquire', 'cli')), 'lease.held')
  assert.equal((await lease(a, 'acquire', 'cli')).status, 409)
  a.clock.advance(5000)
  const renewed = await lease(a, 'renew', 'browser', 1)
  assert.equal(renewed.status, 200)
  assert.equal((renewed.json as { expiresAt: number }).expiresAt, 1791504020000)
  assert.equal(guardOf(await lease(a, 'renew', 'browser', 2)), 'lease.lost')
  const rel = await lease(a, 'release', 'browser', 1)
  assert.deepEqual(rel.json, { gen: 1, ttlMs: 0, expiresAt: 1791504005000, holder: 'browser', openIntents: [] })
  for (const body of [{ op: 'acquire', holder: 'browser', gen: 1 }, { op: 'renew', holder: 'browser' }, { op: 'steal', holder: 'cli' }, { op: 'renew', holder: 'cli', gen: 0 },
    { op: 'renew', holder: 'cli', gen: '1' }, { op: 'acquire', holder: 'cli', extra: 1 }, [], 'acquire', null]) {
    const r = await call(a.port, { path: `/jobs/${JOB}/chains/eth/lease`, body })
    assert.equal(r.status, 400, JSON.stringify(body))
    assert.equal(guardOf(r), 'api.json', JSON.stringify(body))
  }
  const h = await lease(a, 'acquire', 'root')
  assert.equal(h.status, 409)
  assert.equal(guardOf(h), 'lease.holder')
})

test('events: no lease / a stale gen → 409 lease.stale; under the live gen → { seq }, by = the holder, nothing else', async (t) => {
  const a = await api(t)
  assert.equal(guardOf(await append(a, 1, 'note', { text: 'x' })), 'lease.stale')
  await lease(a, 'acquire', 'cli')
  const n = journalLines(a).length
  const r = await append(a, 1, 'key-loaded', { address: KEYS.eth })
  assert.equal(r.status, 200)
  assert.deepEqual(r.json, { seq: n })
  const line = journalLines(a)[n]
  assert.deepEqual([line.chain, line.by, line.gen, line.type], ['eth', 'cli', 1, 'key-loaded'])
  assert.equal(guardOf(await append(a, 2, 'note', { text: 'y' })), 'lease.stale')
  a.clock.advance(15_000)
  assert.equal(guardOf(await append(a, 1, 'note', { text: 'expired' })), 'lease.stale')
  assert.equal(journalLines(a).length, n + 1)
})

test('events: only the executor vocabulary (event.type); malformed bodies and data (event.shape); nothing journaled', async (t) => {
  const a = await api(t)
  await lease(a, 'acquire', 'browser')
  const n = journalLines(a).length
  for (const type of ['lease-acquired', 'lease-expired', 'lease-released', 'created', 'armed', 'skip', 'close', 'resolved', 'stop-requested', 'bogus', '', '__proto__']) {
    const r = await append(a, 1, type, { gen: 9 })
    assert.equal(r.status, 400, type)
    assert.equal(guardOf(r), 'event.type', type)
  }
  const shapes: unknown[] = [
    { gen: 1, type: 'note' }, { gen: 1, type: 'note', data: [] }, { gen: 1, type: 'note', data: null }, { gen: 0, type: 'note', data: { text: 'x' } },
    { gen: '1', type: 'note', data: { text: 'x' } }, { gen: 1.5, type: 'note', data: { text: 'x' } }, { gen: 1, type: 7, data: { text: 'x' } },
    { gen: 1, type: 'note', data: { text: 'x' }, by: 'api' }, { type: 'note', data: { text: 'x' } }, [1, 'note', {}],
  ]
  for (const body of shapes) {
    const r = await call(a.port, { path: `/jobs/${JOB}/chains/eth/events`, body })
    assert.equal(guardOf(r), 'event.shape', JSON.stringify(body))
  }
  // core validateEvent: exact members and formats
  // an id that is not id-shaped (upper-case hex) is no longer exempt from the body check
  assert.equal(guardOf(await append(a, 1, 'intent', { ...intent(1), txId: '0x' + 'AB'.repeat(32) })), 'api.key-like')
  for (const data of [{ ...intent(1), txId: 'nope' }, { ...intent(1), rawSha256: 'xyz' }, { ...intent(1), rawSha256: undefined },
    { ...intent(1), extra: 1 }, { text: 'ab '.repeat(70) }]) {
    assert.equal(guardOf(await append(a, 1, 'txId' in data ? 'intent' : 'note', data)), 'event.shape', JSON.stringify(data).slice(0, 80))
  }
  assert.equal(guardOf(await append(a, 1, 'clawback-intent', { txId: tx(3), to: '0x', value: '1' })), 'event.shape')
  // the route's chain: an eth route takes eth ids, eth intent members, eth addresses and the job's own key
  for (const [type, data] of [
    ['intent', solIntent(1)], ['intent', { ...intent(1), sol: solIntent(1).sol }], ['sent', { txId: solIntent(1).txId, outcome: 'accepted', reason: null }],
    ['replaced', { txId: tx(1), prevId: solIntent(2).txId, reason: 'r' }], ['intent', { ...intent(2), replaces: solIntent(2).txId }],
    ['clawback-intent', { txId: tx(4), to: KEYS.sol, value: '1', rawSha256: raw(4), eth: { nonce: 4, tip: '1', maxFee: '2', gas: '21000', to: CLAWBACK_TO } }],
    ['key-loaded', { address: CLAWBACK_TO }],
  ] as const) {
    assert.equal(guardOf(await append(a, 1, type, data)), 'event.shape', `${type} ${JSON.stringify(data).slice(0, 60)}`)
  }
  assert.equal(journalLines(a).length, n)
})

test('intent: acked only after the line is fsynced, with a ticket v2 bound to (job, network, chain, gen, txId, rawSha256) and the binding (CC-3/CC-3a)', async (t) => {
  const a = await running(t)
  a.clock.advance(1000)
  const n = journalLines(a).length
  const r = await append(a, 1, 'intent', intent(1))
  assert.equal(r.status, 200)
  const body = r.json as { seq: number; ticket: string }
  assert.deepEqual(Object.keys(body), ['seq', 'ticket'])
  assert.equal(body.seq, n)
  const p = verifyTicket(TICKET_KEY, body.ticket, a.clock.now())
  const eth = intent(1).eth as { gas: string; tip: string; maxFee: string }
  // a = the job DEFINITION's key (lower case), k job, p the payload, f = gas × maxFee (worstCaseFee: what the cap
  // reserved), q = the declared nonce, x = the declared fee members (PF-S fix round 2: gas:tip:maxFee)
  // PF-S I-1: p is the API's own plan of copy 1 part 1 from the stored message; to is the publish mode's recipient (eth.calldata.null)
  assert.deepEqual({ ...p, n: 'x' }, { j: JOB, w: 'local', c: 'eth', g: 1, t: tx(1), r: raw(1), a: KEYS.eth.toLowerCase(), k: 'job', p: plannedParts(JOB_INPUT, 'eth', 1)[0], to: NULL_ADDRESS, value: null,
    f: String(BigInt(eth.gas) * BigInt(eth.maxFee)), q: '1', x: `${eth.gas}:${eth.tip}:${eth.maxFee}`, e: a.clock.now() + 120_000, n: 'x' })
  assert.deepEqual(journalLines(a)[n].data, intent(1))
  // the fresh ticket for the same intent repeats the binding exactly
  const again = await ticket(a, 1, tx(1))
  assert.equal(again.status, 200)
  const q = verifyTicket(TICKET_KEY, (again.json as { ticket: string }).ticket, a.clock.now())
  assert.deepEqual([q.r, q.a, q.k, q.p, q.to, q.value, q.f, q.q, q.x], [p.r, p.a, p.k, p.p, p.to, p.value, p.f, p.q, p.x])
  const sent = await append(a, 1, 'sent', { txId: tx(1), outcome: 'accepted', reason: null })
  assert.deepEqual(sent.json, { seq: n + 1 })
})

test('CC-3 (I2): the claw-back ticket binds k clawback, to, value, f and q; a SOL ticket binds the blockhash and max(fee, the CU-implied fee)', async (t) => {
  const { a, id } = await drained(t)
  const claw = ethClawback(7, CLAWBACK_TO, '1000')
  const r = await append(a, 1, 'clawback-intent', claw, 'eth', 'local', id)
  assert.equal(r.status, 200, r.text)
  const p = verifyTicket(TICKET_KEY, (r.json as { ticket: string }).ticket, a.clock.now())
  const ce = claw.eth as { gas: string; tip: string; maxFee: string }
  assert.deepEqual([p.j, p.c, p.r, p.a, p.k, p.p, p.to, p.value, p.f, p.q, p.x], [id, 'eth', raw(7), KEYS.eth.toLowerCase(), 'clawback', null, CLAWBACK_TO.toLowerCase(), '1000',
    String(BigInt(ce.gas) * BigInt(ce.maxFee)), '7', `${ce.gas}:${ce.tip}:${ce.maxFee}`])
  // SOL (JOB2's sol lane)
  const b = await api(t, { jobs: [JOB2_INPUT] })
  await armed(b, JOB2, ['sol'])
  assert.equal((await lease(b, 'acquire', 'cli', undefined, 'sol', 'local', JOB2)).status, 200)
  const s1 = solIntent(1)
  const sr = await append(b, 1, 'intent', s1, 'sol', 'local', JOB2)
  assert.equal(sr.status, 200, sr.text)
  const sp = verifyTicket(TICKET_KEY, (sr.json as { ticket: string }).ticket, b.clock.now())
  const so = s1.sol as { blockhash: string; fee: string; cuLimit: number; cuPrice: number }
  assert.deepEqual([sp.c, sp.a, sp.k, sp.p, sp.to, sp.f, sp.q, sp.x], ['sol', KEYS.sol, 'job', plannedParts(JOB2_INPUT, 'sol', 1)[0], null, so.fee, so.blockhash, `${so.cuLimit}:${so.cuPrice}`])
})

test('intent when the fsync fails: 503 journal.write, no ticket, nothing on disk', async (t) => {
  let fail = false
  let fsyncs = 0
  const fs: JournalFs = {
    writeSync: (fd, b, o, l) => writeSync(fd, b, o, l),
    fsyncSync: (fd) => { if (fail) throw new Error('EIO'); fsyncs++; fsyncSync(fd) },
    ftruncateSync: (fd, n) => ftruncateSync(fd, n),
  }
  const a = await running(t, 'cli', { fs })
  const before = fsyncs
  const ok = await append(a, 1, 'intent', intent(1))
  assert.equal(ok.status, 200)
  assert.equal(fsyncs, before + 1)
  const n = journalLines(a).length
  fail = true
  const r = await append(a, 1, 'intent', intent(2, 2))
  assert.equal(r.status, 503)
  assert.equal(guardOf(r), 'journal.write')
  assert.ok(!r.text.includes('vt-ticket'))
  const lines = journalLines(a)
  assert.equal(lines.length, n)
  assert.ok(!lines.some((l) => JSON.stringify(l).includes(tx(2))))
})

test('intent before arm, before the release time, or for a landed part → 409 job.state; nothing journaled, no ticket', async (t) => {
  const a = await api(t)
  await lease(a, 'acquire', 'browser')
  const before = await append(a, 1, 'intent', intent(1))
  assert.equal(before.status, 409)
  assert.equal(guardOf(before), 'job.state')
  assert.ok(!before.text.includes('vt-ticket'))
  // armed, but the countdown is still running
  const b = await api(t)
  await seedReady(b, JOB, ['eth'])
  assert.equal((await call(b.port, { path: `/jobs/${JOB}/arm`, body: armBody(['eth'], { countdownSec: 30 }) })).status, 200)
  b.clock.advance(20_000)
  await lease(b, 'acquire', 'browser')
  b.clock.advance(9_999)
  assert.equal(guardOf(await append(b, 1, 'intent', intent(1))), 'job.state')
  b.clock.advance(1)
  assert.equal((await append(b, 1, 'intent', intent(1))).status, 200)
  await append(b, 1, 'included', { txId: tx(1), copy: 1, part: 1, attempt: 1, block: '5', fee: '1', ms: 1 })
  const again = await append(b, 1, 'intent', { ...intent(2), attempt: 2 }) // copy 1 part 1 landed already
  assert.equal(guardOf(again), 'job.state')
  assert.ok(!journalLines(b).some((l) => JSON.stringify(l).includes(tx(2))))
  assert.ok(!journalLines(a).some((l) => l.type === 'intent'))
})

test('a txId already journaled as an intent → 400 event.duplicate (ask /tickets instead)', async (t) => {
  const a = await running(t)
  assert.equal((await append(a, 1, 'intent', intent(1))).status, 200)
  const dup = await append(a, 1, 'intent', { ...intent(1), copy: 2 })
  assert.equal(dup.status, 400)
  assert.equal(guardOf(dup), 'event.duplicate')
  assert.equal((await ticket(a, 1, tx(1))).status, 200)
  assert.equal(journalLines(a).filter((l) => l.type === 'intent').length, 1)
})

test('the legacy latch opened mid-run → 423 trigger.uncleared for intents and fresh tickets; other events still journal', async (t) => {
  const a = await running(t)
  assert.equal((await append(a, 1, 'intent', intent(1))).status, 200)
  await openLegacyTrigger(a)
  const r = await append(a, 1, 'intent', intent(2, 2))
  assert.equal(r.status, 423)
  assert.equal(guardOf(r), 'trigger.uncleared')
  assert.ok(!r.text.includes('vt-ticket'))
  assert.equal(guardOf(await ticket(a, 1, tx(1))), 'trigger.uncleared')
  assert.equal((await append(a, 1, 'sent', { txId: tx(1), outcome: 'accepted', reason: null })).status, 200)
  assert.ok(!journalLines(a).some((l) => JSON.stringify(l).includes(tx(2))))
})

test('takeover over HTTP: intent before reconcile → 409 lease.reconcile-first; the old holder → lease.stale', async (t) => {
  const a = await running(t)
  await append(a, 1, 'intent', intent(1))
  a.clock.advance(15_000)
  const g = await lease(a, 'acquire', 'cli')
  assert.deepEqual((g.json as { openIntents: Array<{ txId: string }> }).openIntents.map((o) => o.txId), [tx(1)])
  const early = await append(a, 2, 'intent', intent(2, 2))
  assert.equal(early.status, 409)
  assert.equal(guardOf(early), 'lease.reconcile-first')
  assert.equal(guardOf(await ticket(a, 2, tx(1))), 'lease.reconcile-first')
  assert.equal(guardOf(await append(a, 1, 'sent', { txId: tx(1), outcome: 'accepted', reason: null })), 'lease.stale')
  assert.deepEqual((await append(a, 2, 'reconcile', { txId: tx(1), outcome: 'adopted' })).status, 200)
  assert.equal((await ticket(a, 2, tx(1))).status, 200) // adopted, reconciled by gen 2: a fresh ticket for the same bytes
  assert.equal((await append(a, 2, 'intent', intent(2, 2))).status, 200)
  assert.equal((await ticket(a, 2, tx(2))).status, 200) // its own intent: nothing to reconcile

  // Two open intents from gen 2; gen 3 adopts one: a fresh ticket for it is fine, the other still needs its reconcile.
  a.clock.advance(15_000)
  await lease(a, 'acquire', 'browser')
  await append(a, 3, 'reconcile', { txId: tx(1), outcome: 'adopted' })
  assert.equal((await ticket(a, 3, tx(1))).status, 200)
  assert.equal(guardOf(await ticket(a, 3, tx(2))), 'lease.reconcile-first')
  assert.equal(guardOf(await append(a, 3, 'intent', intent(3, 3))), 'lease.reconcile-first')
})

test('tickets: a fresh ticket for an open journaled intent (same rawSha256, live gen); else ticket.not-intent / ticket.terminal', async (t) => {
  const a = await running(t)
  await append(a, 1, 'intent', intent(1))
  for (let i = 0; i < 12; i++) { // a minute of heartbeats
    a.clock.advance(5_000)
    assert.equal((await lease(a, 'renew', 'browser', 1)).status, 200)
  }
  const r = await ticket(a, 1, tx(1))
  assert.equal(r.status, 200)
  const p = verifyTicket(TICKET_KEY, (r.json as { ticket: string }).ticket, a.clock.now())
  assert.deepEqual([p.t, p.r, p.g, p.e], [tx(1), raw(1), 1, a.clock.now() + 120_000])
  const none = await ticket(a, 1, tx(5))
  assert.equal(none.status, 409)
  assert.equal(guardOf(none), 'ticket.not-intent')
  await append(a, 1, 'included', { txId: tx(1), copy: 1, part: 1, attempt: 1, block: '5', fee: '1', ms: 1 })
  const done = await ticket(a, 1, tx(1))
  assert.equal(done.status, 409)
  assert.equal(guardOf(done), 'ticket.terminal')
  assert.equal(guardOf(await ticket(a, 2, tx(1))), 'lease.stale')
  for (const body of [{ gen: 1 }, { gen: 1, txId: 'x' }, { gen: 1, txId: tx(1), extra: 1 }]) {
    assert.equal(guardOf(await call(a.port, { path: `/jobs/${JOB}/chains/eth/tickets`, body })), 'api.json')
  }
})

// M2 FLIP (applied, operator R78): the job-send lock no longer refuses a mainnet intent or ticket; the job-domain checks (armed, released,
// R76's READY at arm), the legacy latch and the lease still do.
test('mainnet (M2 flip: the job-send lock lifted): an intent or claw-back of an unarmed job, or before its release, is refused (job.state) and the legacy latch still blocks sends, nothing journaled; once released the intent is journaled and ticketed; other events still journal', async (t) => {
  const input = onNetwork(JOB_INPUT, 'mainnet')
  const id = idOf(input, 'mainnet')
  const a = await api(t, { network: 'mainnet', jobs: [input] })
  await lease(a, 'acquire', 'cli', undefined, 'eth', 'mainnet', id)
  const sends = [['intent', intent(1, 1, 1, undefined, input)], ['clawback-intent', ethClawback(2, MAINNET_CLAWBACK_TO.eth, '5')], ['clawback-intent', ethClawback(2, CLAWBACK_TO, '5')]] as const
  for (const [type, data] of sends) {
    const r = await append(a, 1, type, data, 'eth', 'mainnet', id)
    assert.deepEqual([r.status, guardOf(r)], [409, 'job.state'], `${type}: the job is not armed`)
  }
  assert.ok(!journalLines(a, id).some((l) => l.type === 'intent' || l.type === 'clawback-intent'))
  assert.equal((await append(a, 1, 'note', { text: 'ok' }, 'eth', 'mainnet', id)).status, 200)
  // R76: an unfunded lane is not READY, so the job cannot be armed at all
  const unfunded = await call(a.port, { path: `/jobs/${id}/arm`, body: armBody(['eth'], { countdownSec: 60, typed: 'broadcast' }), network: 'mainnet' })
  assert.deepEqual([unfunded.status, guardOf(unfunded)], [409, 'job.state'])
  // armed (funds present): before the release still job.state; after it, an open legacy trigger blocks the send (trigger.uncleared)
  const b = await api(t, { network: 'mainnet', jobs: [input] })
  await seedReady(b, id, ['eth'])
  const ar = await call(b.port, { path: `/jobs/${id}/arm`, body: armBody(['eth'], { countdownSec: 60, typed: 'broadcast' }), network: 'mainnet' })
  assert.equal(ar.status, 200, ar.text)
  assert.equal((await lease(b, 'acquire', 'cli', undefined, 'eth', 'mainnet', id)).status, 200)   // gen 1
  const early = await append(b, 1, 'intent', intent(1, 1, 1, undefined, input), 'eth', 'mainnet', id)
  assert.deepEqual([early.status, guardOf(early)], [409, 'job.state'], 'before the release')
  b.clock.set((ar.json as { armed: { releaseAt: number } }).armed.releaseAt)
  assert.equal((await lease(b, 'acquire', 'cli', undefined, 'eth', 'mainnet', id)).status, 200)   // gen 2 (gen 1 lapsed)
  await openLegacyTrigger(b)
  const latched = await append(b, 2, 'intent', intent(1, 1, 1, undefined, input), 'eth', 'mainnet', id)
  assert.deepEqual([latched.status, guardOf(latched)], [423, 'trigger.uncleared'])
  assert.ok(!journalLines(b, id).some((l) => l.type === 'intent' || l.type === 'clawback-intent'))
  // a journaled mainnet intent (as from an older build) gets no fresh ticket while the latch is open either
  const old = { ...JOB_INPUT, name: 'older build' }
  const def = normalizeJob(onNetwork(old, 'mainnet'), { network: 'mainnet' }).def
  const oid = await writeJob(a.state, def, [{ chain: 'eth', by: 'api', gen: 1, type: 'lease-acquired', data: { gen: 1, holder: 'cli', ttlMs: 15000 } },
    { chain: 'eth', by: 'cli', gen: 1, type: 'intent', data: intent(3) }])
  await lease(a, 'acquire', 'cli', undefined, 'eth', 'mainnet', oid) // gen 2
  assert.equal((await append(a, 2, 'reconcile', { txId: tx(3), outcome: 'adopted' }, 'eth', 'mainnet', oid)).status, 200)
  await openLegacyTrigger(a)
  const latchedTicket = await ticket(a, 2, tx(3), 'mainnet', oid)
  assert.deepEqual([latchedTicket.status, guardOf(latchedTicket)], [423, 'trigger.uncleared'])
  // with no legacy trigger (a fresh API): the released intent is journaled and ticketed, for mainnet
  const c = await api(t, { network: 'mainnet', jobs: [input] })
  await seedReady(c, id, ['eth'])
  const ar2 = await call(c.port, { path: `/jobs/${id}/arm`, body: armBody(['eth'], { countdownSec: 60, typed: 'broadcast' }), network: 'mainnet' })
  assert.equal(ar2.status, 200, ar2.text)
  c.clock.set((ar2.json as { armed: { releaseAt: number } }).armed.releaseAt)
  assert.equal((await lease(c, 'acquire', 'cli', undefined, 'eth', 'mainnet', id)).status, 200)   // gen 1
  const ok = await append(c, 1, 'intent', intent(1, 1, 1, undefined, input), 'eth', 'mainnet', id)
  assert.equal(ok.status, 200, ok.text)
  assert.equal(journalLines(c, id).filter((l) => l.type === 'intent').length, 1)
  const tk = await ticket(c, 1, tx(1), 'mainnet', id)
  assert.equal(tk.status, 200, tk.text)
  const p = verifyTicket(TICKET_KEY, (tk.json as { ticket: string }).ticket, c.clock.now())
  assert.deepEqual([p.w, p.c, p.t, p.g], ['mainnet', 'eth', tx(1), 1])
})

// ---- PF-S I-1 (pre-flip review): an eth / sol job intent is bound to the part the API plans from the STORED message

// A copies job with distinct copies over a text the SOL lane splits into two parts (the copy marker differs per copy).
const LONG_TEXT = 'A synthetic vt fixture line for a long text, plain ASCII only.\n'.repeat(30)
const PLANNED_JOB = { format: 'vt-job/1', network: 'local', name: 'planned parts', message: LONG_TEXT, chains: {
  eth: { mode: { copies: 3 }, publishMode: 'eth.calldata.null', feeStrategy: 'economy', distinctCopies: true, keyAddress: KEYS.eth, budgetUsd: 10, clawbackTo: null },
  sol: { mode: { copies: 2 }, distinctCopies: true, keyAddress: KEYS.sol, budgetUsd: 5, clawbackTo: null } } }
// an eth intent of the long text: gas over its intrinsic gas (~51k), the worst case well inside CAPS.eth
const longEth = (n: number, copy: number, o: Record<string, unknown> = {}): Record<string, unknown> =>
  ({ ...intent(n, copy, 1, undefined, PLANNED_JOB), eth: { nonce: n, tip: '12000', maxFee: '2000012000', gas: plannedGas(PLANNED_JOB, copy), to: NULL_ADDRESS }, ...o })
const chainTicket = (a: TestApi, chain: 'eth' | 'sol', gen: number, txId: string, id: string) =>
  call(a.port, { path: `/jobs/${id}/chains/${chain}/tickets`, body: { gen, txId } })

test('PF-S I-1: a lane-planned eth intent (core planner) gets its ticket for copy 1 and copy N, each with its own marker; p is the plan, to the recipient', async (t) => {
  const a = await running(t, 'browser', { jobs: [PLANNED_JOB] })
  const id = a.ids[0]
  const c1 = plannedPayloads(PLANNED_JOB, 'eth', 1), c2 = plannedPayloads(PLANNED_JOB, 'eth', 2), c3 = plannedPayloads(PLANNED_JOB, 'eth', 3)
  assert.equal(c1.length, 1)
  assert.ok(new TextDecoder().decode(c3[0]).startsWith('data:,[copy 3/3]\n'), 'copy 3 carries its marker')
  for (const [n, copy, bytes] of [[1, 1, c1[0]], [2, 2, c2[0]], [3, 3, c3[0]]] as const) {   // copies in order (N-2)
    const r = await append(a, 1, 'intent', longEth(n, copy), 'eth', 'local', id)
    assert.equal(r.status, 200, r.text)
    const p = verifyTicket(TICKET_KEY, (r.json as { ticket: string }).ticket, a.clock.now())
    assert.deepEqual([p.k, p.p, p.to], ['job', createHash('sha256').update(bytes).digest('hex'), NULL_ADDRESS], `copy ${copy}`)
    // a fresh ticket for the same intent binds the same plan
    const again = verifyTicket(TICKET_KEY, ((await chainTicket(a, 'eth', 1, tx(n), id)).json as { ticket: string }).ticket, a.clock.now())
    assert.deepEqual([again.p, again.to], [p.p, p.to])
  }
})

test('PF-S I-1: arbitrary bytes, another copy\'s part, a wrong part count or a wrong recipient → refused (ticket.payload-plan / ticket.recipient), nothing journaled', async (t) => {
  const a = await running(t, 'browser', { jobs: [PLANNED_JOB] })
  const id = a.ids[0]
  assert.equal((await append(a, 1, 'intent', longEth(1, 1), 'eth', 'local', id)).status, 200)   // copy 1, as planned
  const n0 = journalLines(a, id).length
  const sha = (b: Uint8Array | string): string => createHash('sha256').update(b).digest('hex')
  const copy1 = sha(plannedPayloads(PLANNED_JOB, 'eth', 1)[0])
  for (const [why, data, guard] of [
    ['arbitrary bytes', longEth(2, 2, { payloadSha256: sha('anything at all, the lane key included') }), 'ticket.payload-plan'],
    ['the whole text without the data: prefix', longEth(2, 2, { payloadSha256: sha(LONG_TEXT) }), 'ticket.payload-plan'],
    ['another copy\'s part (copy 1 under copy 2)', longEth(2, 2, { payloadSha256: copy1 }), 'ticket.payload-plan'],
    ['a wrong part count', longEth(2, 2, { parts: 2 }), 'ticket.payload-plan'],
    ['a wrong recipient (the lane key under eth.calldata.null)', longEth(2, 2, { eth: { nonce: 2, tip: '12000', maxFee: '2000012000', gas: plannedGas(PLANNED_JOB, 2), to: KEYS.eth } }), 'ticket.recipient'],
  ] as const) {
    const r = await append(a, 1, 'intent', data, 'eth', 'local', id)
    assert.deepEqual([r.status, guardOf(r)], [409, guard], why)
    assert.ok(!r.text.includes('vt-ticket'), why)
  }
  assert.equal(journalLines(a, id).length, n0)
  assert.equal((await append(a, 1, 'intent', longEth(2, 2), 'eth', 'local', id)).status, 200)   // the planned copy 2 is accepted
})

test('PF-S I-1: SOL — every part of a multi-part copy is bound to its own planned digest; a part under another part\'s digest or another count is refused', async (t) => {
  const a = await api(t, { jobs: [PLANNED_JOB] })
  const id = a.ids[0]
  await armed(a, id, ['sol'])
  assert.equal((await lease(a, 'acquire', 'cli', undefined, 'sol', 'local', id)).status, 200)
  const parts = plannedParts(PLANNED_JOB, 'sol', 1)
  assert.equal(parts.length, 2)
  assert.notDeepEqual(parts, plannedParts(PLANNED_JOB, 'sol', 2))   // copy 2's marker differs
  const s = (n: number, part: number, o: Record<string, unknown> = {}): Record<string, unknown> => ({ ...solIntent(n, 1, part, undefined, PLANNED_JOB), ...o })
  assert.equal(guardOf(await append(a, 1, 'intent', s(1, 1, { payloadSha256: parts[1] }), 'sol', 'local', id)), 'ticket.payload-plan')
  assert.equal(guardOf(await append(a, 1, 'intent', s(1, 1, { parts: 1 }), 'sol', 'local', id)), 'ticket.payload-plan')
  assert.equal(guardOf(await append(a, 1, 'intent', s(1, 1, { parts: 3 }), 'sol', 'local', id)), 'ticket.payload-plan')
  for (const part of [1, 2]) {
    const r = await append(a, 1, 'intent', s(part, part), 'sol', 'local', id)
    assert.equal(r.status, 200, r.text)
    const p = verifyTicket(TICKET_KEY, (r.json as { ticket: string }).ticket, a.clock.now())
    assert.deepEqual([p.p, p.to], [parts[part - 1], null], `part ${part}`)
  }
})

test('PF-S fix round 1 (N-2): copies go in order — the top copy (a part up to one past its highest) or the next copy at part 1; no skipped, older or made-up copy (both modes)', async (t) => {
  // until drained (JOB: eth drain, distinct copies): a copy number is published in the marker, so none may be made up
  const a = await running(t)
  const order = async (n: number, copy: number, o: Record<string, unknown> = {}) => guardOf(await append(a, 1, 'intent', { ...intent(n, copy), ...o })) ?? 'ok'
  assert.equal(await order(1, 2), 'job.copy-order', 'the first intent is copy 1')
  assert.equal(await order(1, 2 ** 52), 'job.copy-order', 'an arbitrary copy number')
  assert.equal(await order(1, 1), 'ok')
  assert.equal(await order(2, 3), 'job.copy-order', 'copy 2 skipped')
  assert.equal(await order(2, 9_007_199_254_740_991), 'job.copy-order')
  assert.equal(await order(2, 2), 'ok')
  assert.equal(await order(3, 1), 'job.copy-order', 'an older copy')
  assert.equal(await order(3, 3), 'ok')
  const lines = journalLines(a).filter((l) => l.type === 'intent').map((l) => (l.data as { copy: number }).copy)
  assert.deepEqual(lines, [1, 2, 3])
  // copies mode, two parts a copy (SOL of the long text): the next part of the top copy, a re-sign of a part, then the next copy at part 1
  const b = await api(t, { jobs: [PLANNED_JOB] })
  const id = b.ids[0]
  await armed(b, id, ['sol'])
  assert.equal((await lease(b, 'acquire', 'cli', undefined, 'sol', 'local', id)).status, 200)
  const s = async (n: number, copy: number, part: number, o: Record<string, unknown> = {}) =>
    guardOf(await append(b, 1, 'intent', { ...solIntent(n, copy, part, undefined, PLANNED_JOB), ...o }, 'sol', 'local', id)) ?? 'ok'
  assert.equal(await s(1, 1, 2), 'job.copy-order', 'a new copy starts at part 1')
  assert.equal(await s(1, 1, 1), 'ok')
  assert.equal(await s(2, 2, 1), 'ok', 'the next copy may start while the top copy is in flight (the cap and families still bound it)')
  assert.equal(await s(3, 1, 2), 'job.copy-order', 'part 2 of an older copy')
  assert.equal(await s(3, 2, 3, { parts: 3 }), 'job.copy-order', 'part 3 of the top copy before its part 2')
  assert.equal(await s(3, 2, 2), 'ok', 'the next part of the top copy')
  assert.equal(await s(4, 2, 2, { attempt: 2, replaces: solIntent(3, 2, 2, undefined, PLANNED_JOB).txId }), 'ok', 'a re-sign of the top part')
  assert.equal(await s(5, 3, 1), 'job.state', 'copies mode: copy 3 of 2 stays job.state')
})

test('PF-S I-1: a journaled intent that is not the plan (an older build wrote it) never gets a fresh ticket (ticket.not-intent); a missing stored message refuses every intent', async (t) => {
  const a = await api(t)
  const def = normalizeJob({ ...JOB_INPUT, name: 'older build' }, { network: 'local' }).def
  const oid = await writeJob(a.state, def, [{ chain: 'eth', by: 'api', gen: 1, type: 'lease-acquired', data: { gen: 1, holder: 'cli', ttlMs: 15000 } },
    { chain: 'eth', by: 'cli', gen: 1, type: 'intent', data: { ...intent(3), payloadSha256: 'ab'.repeat(32) } }])
  await lease(a, 'acquire', 'cli', undefined, 'eth', 'local', oid) // gen 2
  assert.equal((await append(a, 2, 'reconcile', { txId: tx(3), outcome: 'adopted' }, 'eth', 'local', oid)).status, 200)
  assert.equal(guardOf(await ticket(a, 2, tx(3), 'local', oid)), 'ticket.not-intent')
  // the stored message is gone: the API cannot plan, so nothing is ticketed (fail closed)
  const b = await running(t)
  rmSync(join(b.state, 'messages'), { recursive: true, force: true })
  const r = await append(b, 1, 'intent', intent(1), 'eth', 'local', b.ids[0])
  assert.deepEqual([r.status, guardOf(r)], [409, 'ticket.payload-plan'])
})

// eth drained after one landed copy: a settled chain, so a claw-back may follow.
async function drained(t: { after(fn: () => Promise<void>): void }, input: Record<string, unknown> = JOB_INPUT): Promise<{ a: TestApi; id: string }> {
  const a = await api(t, { jobs: [input] })
  const id = a.ids[0]
  await armed(a, id, ['eth'])
  await lease(a, 'acquire', 'browser', undefined, 'eth', 'local', id)
  for (const [type, data] of [
    ['intent', intent(1)], ['sent', { txId: tx(1), outcome: 'accepted', reason: null }],
    ['included', { txId: tx(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '1000000000000000', ms: 1 }],
    ['readback', { txId: tx(1), ok: true, detail: 'byte-equal' }], ['drained', { balance: '10', nextCost: '20', copy: 2 }],
  ] as const) assert.equal((await append(a, 1, type, data, 'eth', 'local', id)).status, 200, type)
  return { a, id }
}

test('claw-back: only once settled; never to the null / burn address or the own key; to clawbackTo when set', async (t) => {
  const early = await running(t)
  assert.equal(guardOf(await append(early, 1, 'clawback-intent', ethClawback(7, CLAWBACK_TO, '1'))), 'job.state')

  const { a } = await drained(t)
  for (const to of [NULL_ADDRESS, '0x000000000000000000000000000000000000dEaD', KEYS.eth, KEYS.eth.toLowerCase()]) {
    const r = await append(a, 1, 'clawback-intent', ethClawback(7, to, '1'))
    assert.equal(r.status, 400, to)
    assert.equal(guardOf(r), 'job.clawback', to)
  }
  const ok = await append(a, 1, 'clawback-intent', ethClawback(7, '0x1111111111111111111111111111111111111111', '1'))
  assert.equal(ok.status, 200)
  assert.equal(verifyTicket(TICKET_KEY, (ok.json as { ticket: string }).ticket, a.clock.now()).r, raw(7))

  const set = await drained(t, { ...JOB_INPUT, chains: { eth: { ...(JOB_INPUT.chains as { eth: object }).eth, clawbackTo: CLAWBACK_TO } } })
  const other = await append(set.a, 1, 'clawback-intent', ethClawback(7, '0x1111111111111111111111111111111111111111', '1'), 'eth', 'local', set.id)
  assert.equal(guardOf(other), 'job.clawback')
  assert.equal((await append(set.a, 1, 'clawback-intent', ethClawback(7, CLAWBACK_TO.toLowerCase(), '1'), 'eth', 'local', set.id)).status, 200)
})

test('PF-S fix round 1 (N-6): a compromised executor\'s claw-back to another address is refused even with the exact typed amount; on mainnet only the stored clawbackTo', async (t) => {
  // the executor journals the whole remainder to its own address, with the typed amount (value + worst-case fee) it supplies itself
  const set = await drained(t, { ...JOB_INPUT, chains: { eth: { ...(JOB_INPUT.chains as { eth: object }).eth, clawbackTo: CLAWBACK_TO } } })
  const thief = '0x1111111111111111111111111111111111111111'
  const claw = ethClawback(7, thief, '3000000000000000')
  const typed = { amount: String(3_000_000_000_000_000n + 21_000n * 2_000_012_000n) }
  const r = await call(set.a.port, { path: `/jobs/${set.id}/chains/eth/events`, body: { gen: 1, type: 'clawback-intent', data: claw, clawbackConfirm: typed } })
  assert.deepEqual([r.status, guardOf(r)], [400, 'job.clawback'])
  assert.ok(!r.text.includes('vt-ticket'))
  // the destination rule itself: clawbackTo when set; on mainnet ONLY the stored clawbackTo (a stored mainnet job without one gets
  // no claw-back from vt); off mainnet with none set, any (the reserved addresses and the own key are refused beside it)
  for (const [network, chain, clawbackTo, to, ok] of [
    ['mainnet', 'eth', null, thief, false], ['mainnet', 'eth', CLAWBACK_TO, thief, false], ['mainnet', 'eth', CLAWBACK_TO, CLAWBACK_TO.toLowerCase(), true],
    ['mainnet', 'sol', null, KEYS.sol, false], ['mainnet', 'sol', 'G147qVmzynHL3EjQ8tvBGDms7u6FDCWbFfFmzNMZmg1x', 'G147qVmzynHL3EjQ8tvBGDms7u6FDCWbFfFmzNMZmg1x', true],
    ['testnet', 'eth', null, thief, true], ['local', 'eth', null, thief, true], ['testnet', 'eth', CLAWBACK_TO, thief, false],
  ] as const) assert.equal(clawbackToAllowed(network, chain, clawbackTo, to), ok, `${network} ${chain} ${String(clawbackTo)} → ${to}`)
})

test('PF-S fix round 2 (R1-2): with the job-send lock lifted (the M2 flip, through the test seam), the gate claws back on mainnet only to the stored clawbackTo; a stored mainnet job without one gets no claw-back', async (t) => {
  const thief = '0x1111111111111111111111111111111111111111'
  // one mainnet API per job (they share the lane key): the job armed, one copy landed and read back, the chain DRAINED — every
  // step through the gate, as on mainnet after the flip
  const onMainnet = async (setup: (a: TestApi) => Promise<string>) => {
    const a = await api(t, { network: 'mainnet', jobs: [], jobSendLock: () => {} })   // the lock as the flip leaves it for job sends
    const id = await setup(a)
    await a.api.registry.load(id)
    await seedReady(a, id, ['eth'])
    const r = await call(a.port, { path: `/jobs/${id}/arm`, body: armBody(['eth'], { countdownSec: 60, typed: 'broadcast' }), network: 'mainnet' })
    assert.equal(r.status, 200, r.text)
    a.clock.set((r.json as { armed: { releaseAt: number } }).armed.releaseAt)
    assert.equal((await lease(a, 'acquire', 'browser', undefined, 'eth', 'mainnet', id)).status, 200)
    for (const [type, data] of [
      ['intent', intent(1)], ['sent', { txId: tx(1), outcome: 'accepted', reason: null }],
      ['included', { txId: tx(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '1000000000000000', ms: 1 }],
      ['readback', { txId: tx(1), ok: true, detail: 'byte-equal' }], ['drained', { balance: '10', nextCost: '20', copy: 2 }],
    ] as const) assert.equal((await append(a, 1, type, data, 'eth', 'mainnet', id)).status, 200, type)
    const claw = (to: string, typed = false) => call(a.port, { path: `/jobs/${id}/chains/eth/events`, network: 'mainnet',
      body: { gen: 1, type: 'clawback-intent', data: ethClawback(7, to, '1000'), ...(typed ? { clawbackConfirm: { amount: String(1000n + 21_000n * 2_000_012_000n) } } : {}) } })
    return { a, claw }
  }
  // A: a STORED mainnet job without clawbackTo (created before it was required: written as an earlier API wrote it)
  const defA = normalizeJob({ ...JOB_INPUT, network: 'mainnet', name: 'stored without clawbackTo' }, { network: 'mainnet', existing: true }).def
  assert.equal(defA.chains.eth!.clawbackTo, null)
  const A = await onMainnet(async (a) => { a.api.registry.messages.storeText(JOB_INPUT.message as string, defA.messageSha256); return writeJob(a.state, defA, []) })
  for (const [to, typed] of [[thief, false], [thief, true], [CLAWBACK_TO, true], [MAINNET_CLAWBACK_TO.eth, false]] as const) {
    const r = await A.claw(to, typed)
    assert.deepEqual([r.status, guardOf(r)], [400, 'job.clawback'], `${to} typed ${typed}`)
    assert.ok(!r.text.includes('vt-ticket'))
  }
  // B: a new mainnet job naming its clawbackTo: another address is refused (a typed amount changes nothing); its own goes
  const B = await onMainnet(async (a) => (await a.api.registry.create(onNetwork(JOB_INPUT, 'mainnet'))).job.id)
  for (const typed of [false, true]) assert.equal(guardOf(await B.claw(thief, typed)), 'job.clawback', `typed ${typed}`)
  const ok = await B.claw(MAINNET_CLAWBACK_TO.eth.toLowerCase())
  assert.equal(ok.status, 200, ok.text)
  assert.equal(verifyTicket(TICKET_KEY, (ok.json as { ticket: string }).ticket, B.a.clock.now()).to, MAINNET_CLAWBACK_TO.eth.toLowerCase())
})

test('PF-S fix round 3 (R2-2): ticket.fee-plan per network — testnet (Amsterdam) takes the Amsterdam window of the publish mode (self or null) and the 204,600 claw-back; mainnet (pre-Amsterdam, lock lifted through the test seam) only the pre-Amsterdam window and 21,000', async (t) => {
  const n = plannedPayloads(JOB_INPUT, 'eth', 1)[0].length, big = plannedPayloads(PLANNED_JOB, 'eth', 1)[0].length
  const formula = (amsterdam: boolean, toSelf: boolean, size = n): string => String(ethGasFormula(size, { amsterdam, toSelf }))
  // the three formulas differ for this payload (else the cases below would not tell the branches apart)
  assert.equal(new Set([formula(false, false), formula(true, false), formula(true, true)]).size, 3)
  // mainnet's floor is the pre-Amsterdam intrinsic gas, so the Amsterdam window can only be told apart above it: a payload long enough
  // that 15,000 + 64n lies above the pre-Amsterdam window (PLANNED_JOB's eth part)
  assert.ok(ethGasFormula(big, { amsterdam: true, toSelf: false }) > ethGasBudget(big, { amsterdam: false, toSelf: false }), String(big))
  const self = { ...JOB_INPUT, name: 'publish to self', chains: { eth: { ...(JOB_INPUT.chains as { eth: Record<string, unknown> }).eth, publishMode: 'eth.calldata.self' } } }
  const onNet = async (network: Network, input: Record<string, unknown>) => {
    const a = await api(t, { network, jobs: [], ...(network === 'mainnet' ? { jobSendLock: () => {} } : {}) })   // mainnet: the lock as the flip leaves it
    const job = onNetwork(input, network)
    const id = (await a.api.registry.create(job)).job.id
    if (network === 'mainnet') {
      await seedReady(a, id, ['eth'])
      const r = await call(a.port, { path: `/jobs/${id}/arm`, body: armBody(['eth'], { countdownSec: 60, typed: 'broadcast' }), network })
      assert.equal(r.status, 200, r.text)
      a.clock.set((r.json as { armed: { releaseAt: number } }).armed.releaseAt)
    } else await armed(a, id, ['eth'], network)
    assert.equal((await lease(a, 'acquire', 'browser', undefined, 'eth', network, id)).status, 200)
    const ev = (type: string, data: unknown) => append(a, 1, type, data, 'eth', network, id)
    const at = (gas: string) => { const d = intent(1, 1, 1, undefined, job); return { ...d, eth: { ...(d.eth as object), gas, maxFee: '20000000', tip: '12000' } } }   // a low maxFee: the long part's gas fits the cap
    const drain = async (): Promise<void> => {
      for (const [type, data] of [['sent', { txId: tx(1), outcome: 'accepted', reason: null }], ['included', { txId: tx(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '1000', ms: 1 }],
        ['readback', { txId: tx(1), ok: true, detail: 'byte-equal' }], ['drained', { balance: '10', nextCost: '20', copy: 2 }]] as const) assert.equal((await ev(type, data)).status, 200, type)
    }
    return { a, ev, at, drain, job }
  }
  const planOk = async (r: Promise<Reply>, why: string) => { const x = await r; assert.equal(x.status, 200, `${why}: ${x.text}`) }
  const planNo = async (r: Promise<Reply>, why: string) => { const x = await r; assert.deepEqual([x.status, guardOf(x)], [409, 'ticket.fee-plan'], why) }
  // testnet, eth.calldata.null: the Amsterdam "to another address" window only; then a 204,600 claw-back (an empty destination)
  const tn = await onNet('testnet', JOB_INPUT)
  assert.equal((tn.at(formula(true, false)).eth as { gas: string }).gas, plannedGas(tn.job, 1), 'the planned gas is the Amsterdam null formula')
  await planNo(tn.ev('intent', tn.at(formula(false, false))), 'testnet null: the pre-Amsterdam formula')
  await planNo(tn.ev('intent', tn.at(String(ethGasBudget(n, { amsterdam: true, toSelf: false }) + 1n))), 'testnet null: above the Amsterdam window')   // (the to-self formula is below the intrinsic floor: event.shape)
  await planOk(tn.ev('intent', tn.at(formula(true, false))), 'testnet null: the Amsterdam null formula')
  await tn.drain()
  await planOk(tn.ev('clawback-intent', ethClawback(7, CLAWBACK_TO, '1000', { gas: '204600' })), 'testnet: a claw-back to an empty account')
  // testnet, eth.calldata.self: the Amsterdam to-self window only
  const ts = await onNet('testnet', self)
  await planNo(ts.ev('intent', ts.at(formula(true, false))), 'testnet self: the null formula')
  await planNo(ts.ev('intent', ts.at(formula(false, true))), 'testnet self: the pre-Amsterdam formula')
  await planOk(ts.ev('intent', ts.at(formula(true, true))), 'testnet self: the Amsterdam to-self formula')
  // mainnet (pre-Amsterdam): the Amsterdam window is refused, the pre-Amsterdam one taken; a claw-back's gas is 21,000 only
  const mn = await onNet('mainnet', PLANNED_JOB)
  await planNo(mn.ev('intent', mn.at(formula(true, false, big))), 'mainnet: the Amsterdam formula')
  await planOk(mn.ev('intent', mn.at(formula(false, false, big))), 'mainnet: the pre-Amsterdam formula')
  await mn.drain()
  await planNo(mn.ev('clawback-intent', ethClawback(7, MAINNET_CLAWBACK_TO.eth, '1000', { gas: '204600' })), 'mainnet: no Amsterdam empty-account claw-back gas')
  await planOk(mn.ev('clawback-intent', ethClawback(7, MAINNET_CLAWBACK_TO.eth, '1000')), 'mainnet: a 21,000 claw-back')
})

test('PF-S fix round 2 (R1-2): the job-send lock seam is a test seam — refused outside NODE_ENV=test (api.test-only)', () => {
  const saved = process.env.NODE_ENV
  delete process.env.NODE_ENV
  try {
    assert.throws(() => createRegistry({ stateDir: '/nonexistent', network: 'mainnet', clock: { now: () => 0, every: () => () => {} }, out: '/nonexistent', ticketKey: TICKET_KEY, jobSendLock: () => {} }),
      (e: unknown) => (e as { guardId?: string }).guardId === 'api.test-only')
  } finally { process.env.NODE_ENV = saved }
})

test('claw-back: an ETH precompile or reserved address (0x…0001 to 0x…ffff) is refused (job.clawback-precompile); 0x…010000 is not (as the CLI)', async (t) => {
  const { a } = await drained(t)
  const at = (n: bigint): string => `0x${n.toString(16).padStart(40, '0')}`
  for (const n of [1n, 2n, 9n, 0x11n, 0x100n, 0xfffen, 0xffffn]) {
    const r = await append(a, 1, 'clawback-intent', ethClawback(7, at(n), '1'))
    assert.equal(r.status, 400, n.toString(16))
    assert.equal(guardOf(r), 'job.clawback-precompile', n.toString(16))
  }
  assert.equal(guardOf(await append(a, 1, 'clawback-intent', ethClawback(7, NULL_ADDRESS, '1'))), 'job.clawback')   // 0x0 stays the burn rule
  assert.equal((await append(a, 1, 'clawback-intent', ethClawback(7, at(0x10000n), '1'))).status, 200)
})

test('claw-back: value + worst-case fee against what is left of the armed cap → over it, 400 arm.amount (no typed override yet)', async (t) => {
  // cap 4e15, spent 1e15: 3e15 left. Worst-case fee 21000 × 2000012000 = 42000252000000.
  const fee = 21000n * 2000012000n
  const left = 4_000_000_000_000_000n - 1_000_000_000_000_000n
  const { a } = await drained(t)
  const over = await append(a, 1, 'clawback-intent', ethClawback(7, CLAWBACK_TO, String(left - fee + 1n)))
  assert.equal(over.status, 400)
  assert.equal(guardOf(over), 'arm.amount')
  const bigFee = await append(a, 1, 'clawback-intent', ethClawback(8, CLAWBACK_TO, '1', { maxFee: String(left) }))
  assert.equal(guardOf(bigFee), 'arm.amount')
  assert.ok(!journalLines(a).some((l) => l.type === 'clawback-intent'))
  const exact = await append(a, 1, 'clawback-intent', ethClawback(9, CLAWBACK_TO, String(left - fee)))
  assert.equal(exact.status, 200)
})

test('job.missing: an unknown job, or a chain the job does not have → 404', async (t) => {
  const a = await api(t)
  const unknown = await call(a.port, { path: '/jobs/0123456789abcdef/chains/eth/lease', body: { op: 'acquire', holder: 'cli' } })
  assert.equal(unknown.status, 404)
  assert.equal(guardOf(unknown), 'job.missing')
  assert.equal(guardOf(await call(a.port, { path: `/jobs/${JOB}/chains/sol/lease`, body: { op: 'acquire', holder: 'cli' } })), 'job.missing')
  assert.equal(guardOf(await call(a.port, { path: `/jobs/${JOB}/chains/sol/events`, body: { gen: 1, type: 'note', data: { text: 'x' } } })), 'job.missing')
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/chains/btc/lease`, body: { op: 'acquire', holder: 'cli' } })).status, 404)
  // a sol route of a job with both chains takes sol data only
  const b = await api(t, { jobs: [JOB2_INPUT] })
  await lease(b, 'acquire', 'cli', undefined, 'sol', 'local', JOB2)
  assert.equal(guardOf(await append(b, 1, 'intent', intent(1), 'sol', 'local', JOB2)), 'event.shape')
  assert.equal(guardOf(await append(b, 1, 'key-loaded', { address: KEYS.eth }, 'sol', 'local', JOB2)), 'event.shape')
  assert.equal((await append(b, 1, 'key-loaded', { address: KEYS.sol }, 'sol', 'local', JOB2)).status, 200)
})

// ---- S2 review fix round 1 ----

const renew = (a: TestApi, gen: number, id = JOB, chain = 'eth', holder = 'browser') =>
  call(a.port, { path: `/jobs/${id}/chains/${chain}/lease`, body: { op: 'renew', holder, gen } })

test('I-1: a closed (DONE) chain is never revived: resumed / paused / drained / stopped → 409 job.state; intents too; no lease', async (t) => {
  const { a, id } = await drained(t)
  assert.equal((await call(a.port, { path: `/jobs/${id}/close`, body: { chain: 'eth' } })).status, 200)
  const n = journalLines(a, id).length
  for (const [type, data] of [['resumed', { reason: 'go' }], ['paused', { reason: 'p' }], ['drained', { balance: '1', nextCost: '2', copy: 3 }],
    ['copies-done', { copies: 1 }], ['stopped', { reason: 's' }]] as const) {
    const r = await append(a, 1, type, data, 'eth', 'local', id)
    assert.equal(r.status, 409, type)
    assert.equal(guardOf(r), 'job.state', type)
  }
  const i = await append(a, 1, 'intent', intent(5, 3), 'eth', 'local', id)
  assert.equal(guardOf(i), 'job.state')
  assert.ok(!i.text.includes('vt-ticket'))
  assert.equal((await append(a, 1, 'note', { text: 'evidence is still welcome' }, 'eth', 'local', id)).status, 200)
  assert.equal(journalLines(a, id).length, n + 1)
  // m8: no new lease on a chain that is over
  a.clock.advance(15_000)
  const l = await lease(a, 'acquire', 'cli', undefined, 'eth', 'local', id)
  assert.equal(l.status, 409)
  assert.equal(guardOf(l), 'job.state')
})

test('I-1: CLAWING_BACK and CLAWED_BACK chains are never revived (no intent while a claw-back is in flight)', async (t) => {
  const { a, id } = await drained(t)
  assert.equal((await append(a, 1, 'clawback-intent', ethClawback(7, CLAWBACK_TO, '1'), 'eth', 'local', id)).status, 200)
  for (const type of ['resumed', 'paused', 'stopped'] as const) assert.equal(guardOf(await append(a, 1, type, { reason: 'x' }, 'eth', 'local', id)), 'job.state', type)
  assert.equal(guardOf(await append(a, 1, 'intent', intent(8, 3), 'eth', 'local', id)), 'job.state')
  assert.equal((await append(a, 1, 'clawback-included', { txId: tx(7), value: '1', fee: '21000' }, 'eth', 'local', id)).status, 200)
  assert.equal(guardOf(await append(a, 1, 'resumed', { reason: 'x' }, 'eth', 'local', id)), 'job.state')
  assert.equal(guardOf(await append(a, 1, 'intent', intent(9, 3), 'eth', 'local', id)), 'job.state')
  a.clock.advance(15_000)
  assert.equal(guardOf(await lease(a, 'acquire', 'cli', undefined, 'eth', 'local', id)), 'job.state')
})

test('I-1: two jobs, one key — the closed job\'s executor keeps its lease, the next job arms the freed key: only the live job gets tickets', async (t) => {
  const a = await api(t, { jobs: [JOB_INPUT, JOB2_INPUT] })
  await armed(a, JOB, ['eth'])
  await lease(a, 'acquire', 'browser')
  await append(a, 1, 'intent', intent(1))
  await append(a, 1, 'included', { txId: tx(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '1000', ms: 1 })
  await append(a, 1, 'drained', { balance: '1', nextCost: '2', copy: 2 })
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/close`, body: { chain: 'eth' } })).status, 200)
  assert.equal((await renew(a, 1)).status, 200) // JOB's executor still holds its lease
  // JOB2 arms the same eth key, now free
  await seedReady(a, JOB2, ['eth'])
  assert.equal((await call(a.port, { path: `/jobs/${JOB2}/arm`, body: armBody(['eth'], { countdownSec: 5 }) })).status, 200)
  a.clock.advance(5_000)
  assert.equal((await renew(a, 1)).status, 200)
  await lease(a, 'acquire', 'cli', undefined, 'eth', 'local', JOB2)
  const live = await append(a, 1, 'intent', intent(2), 'eth', 'local', JOB2)
  assert.equal(live.status, 200)
  assert.ok((live.json as { ticket?: string }).ticket !== undefined)
  // the closed job's executor tries to come back
  assert.equal(guardOf(await append(a, 1, 'resumed', { reason: 'back' })), 'job.state')
  const second = await append(a, 1, 'intent', intent(3, 2))
  assert.equal(guardOf(second), 'job.state')
  assert.ok(!second.text.includes('vt-ticket'))
  assert.equal(guardOf(await ticket(a, 1, tx(1))), 'ticket.terminal')
})

test('m8: no lease on a SKIPPED chain', async (t) => {
  const a = await api(t, { jobs: [JOB2_INPUT] })
  await armed(a, JOB2, ['eth'])
  const r = await lease(a, 'acquire', 'cli', undefined, 'sol', 'local', JOB2)
  assert.equal(r.status, 409)
  assert.equal(guardOf(r), 'job.state')
})

// eth intents whose worst case (gas × maxFee) is 1e15 wei: four fill the 4e15 cap exactly.
// PF-S fix round 2 (R1-1): gas is the copy's planned gas (ticket.fee-plan); maxFee is scaled so the worst case stays the round number
// these probes count in: ⌊25,000 × maxFee / gas⌋ × gas, at most 25,000 × maxFee (1e15 at the default) and within one gas of it.
const big = (n: number, o: { copy?: number; attempt?: number; nonce?: number; maxFee?: string; replaces?: string } = {}) => {
  const d = intent(n, o.copy ?? n)
  const gas = BigInt((d.eth as { gas: string }).gas), maxFee = (25_000n * BigInt(o.maxFee ?? '40000000000')) / gas
  return { ...d, attempt: o.attempt ?? 1, replaces: o.replaces ?? null, eth: { ...(d.eth as object), nonce: o.nonce ?? n, gas: String(gas), maxFee: String(maxFee) } }
}
const worstOf = (d: { eth: unknown }): bigint => { const e = d.eth as { gas: string; maxFee: string }; return BigInt(e.gas) * BigInt(e.maxFee) }

test('I-2: the armed cap binds every ticket — spent + in flight (largest per eth nonce) + this worst case <= nativeCap', async (t) => {
  const a = await running(t)
  const huge = await append(a, 1, 'intent', { ...intent(99), eth: { ...(intent(99).eth as object), gas: '30000000', maxFee: '1000000000000' } })
  assert.equal(huge.status, 400) // 3e19 wei against a 4e15 cap
  assert.equal(guardOf(huge), 'arm.amount')
  assert.ok(!huge.text.includes('vt-ticket'))
  for (const n of [1, 2, 3]) assert.equal((await append(a, 1, 'intent', big(n))).status, 200, `intent ${n}`) // 3e15 in flight
  // a fee bump of an open attempt (of the top copy: N-2) adds only what it raises: 1.2e15 replaces 1e15 → 3.2e15
  const bump = await append(a, 1, 'intent', big(11, { copy: 3, attempt: 2, nonce: 3, maxFee: '48000000000', replaces: tx(3) }))
  assert.equal(bump.status, 200, bump.text)
  const over = await append(a, 1, 'intent', big(4)) // 3.2e15 + 1e15 > 4e15
  assert.equal(over.status, 400)
  assert.equal(guardOf(over), 'arm.amount')
  await append(a, 1, 'included', { txId: tx(2), copy: 2, part: 1, attempt: 1, block: '9', fee: '1000000000000000', ms: 1 }) // spent 1e15, 2.2e15 in flight
  assert.equal(guardOf(await append(a, 1, 'intent', big(5, { copy: 4 }))), 'arm.amount') // 1e15 + 2.2e15 + 1e15
  await append(a, 1, 'sent', { txId: tx(1), outcome: 'rejected', reason: 'dead' }) // a claim alone: still in flight (NEW-2)
  assert.equal(guardOf(await append(a, 1, 'intent', big(6, { copy: 4 }))), 'arm.amount')
  await append(a, 1, 'reconcile', { txId: tx(1), outcome: 'nonce-consumed' }) // evidence it can never land: released
  assert.equal((await append(a, 1, 'intent', big(6, { copy: 4 }))).status, 200) // 1e15 + 1.2e15 + 1e15
})

test('I-2: a sol re-sign while the earlier signature is open counts twice', async (t) => {
  const a = await api(t, { jobs: [JOB2_INPUT] })
  await armed(a, JOB2, ['sol'])
  await lease(a, 'acquire', 'cli', undefined, 'sol', 'local', JOB2)
  const sol = (n: number, attempt: number) => { const d = solIntent(n); return { ...d, attempt, sol: { ...(d.sol as object), fee: '20000000' } } } // 2e7 of a 5e7 cap
  assert.equal((await append(a, 1, 'intent', sol(1, 1), 'sol', 'local', JOB2)).status, 200)
  assert.equal((await append(a, 1, 'intent', sol(2, 2), 'sol', 'local', JOB2)).status, 200) // 4e7
  const third = await append(a, 1, 'intent', sol(3, 3), 'sol', 'local', JOB2) // 6e7 > 5e7
  assert.equal(third.status, 400)
  assert.equal(guardOf(third), 'arm.amount')
})

test('I-2 / N-3: one claw-back family at a time; a claw-back fee bump (same nonce, same destination) counts once', async (t) => {
  const { a, id } = await drained(t) // cap 4e15, spent 1e15: 3e15 left
  const first = await append(a, 1, 'clawback-intent', ethClawback(7, CLAWBACK_TO, '2000000000000000'), 'eth', 'local', id)
  assert.equal(first.status, 200)
  const second = await append(a, 1, 'clawback-intent', ethClawback(8, CLAWBACK_TO, '2000000000000000'), 'eth', 'local', id)
  assert.equal(second.status, 400)
  assert.equal(guardOf(second), 'event.family')
  const elsewhere = { ...ethClawback(18, '0x1111111111111111111111111111111111111111', '1'), eth: { nonce: 7, tip: '1', maxFee: '2', gas: '21000', to: '0x1111111111111111111111111111111111111111' } }
  assert.equal(guardOf(await append(a, 1, 'clawback-intent', elsewhere, 'eth', 'local', id)), 'event.family') // same nonce, another destination
  const fat = { ...ethClawback(19, CLAWBACK_TO, '2958000000000001'), eth: { nonce: 7, tip: '12000', maxFee: '2000000000', gas: '21000', to: CLAWBACK_TO } }
  assert.equal(guardOf(await append(a, 1, 'clawback-intent', fat, 'eth', 'local', id)), 'arm.amount') // 1e15 + 2.958e15 + 1 + 4.2e13 > 4e15
  const bump = { ...ethClawback(17, CLAWBACK_TO, '2000000000000000', { maxFee: '3000000000' }), eth: { nonce: 7, tip: '12000', maxFee: '3000000000', gas: '21000', to: CLAWBACK_TO } }
  assert.equal((await append(a, 1, 'clawback-intent', bump, 'eth', 'local', id)).status, 200)
})

test('m3 / m4: copies mode never goes past its copy count; eth `to` must be what the publish mode sends to (PF-S I-1: ticket.recipient)', async (t) => {
  const copies = { ...JOB_INPUT, name: 'one copy', chains: { eth: { ...(JOB_INPUT.chains as { eth: object }).eth, mode: { copies: 1 } } } }
  const a = await running(t, 'browser', { jobs: [copies] })
  const id = a.ids[0]
  const past = await append(a, 1, 'intent', intent(1, 2), 'eth', 'local', id)
  assert.equal(past.status, 409)
  assert.equal(guardOf(past), 'job.state')
  assert.equal(guardOf(await append(a, 1, 'intent', { ...intent(1, 1, 1, undefined, copies), eth: { ...(intent(1).eth as object), to: KEYS.eth } }, 'eth', 'local', id)), 'ticket.recipient') // calldata.null
  assert.equal((await append(a, 1, 'intent', intent(1, 1, 1, undefined, copies), 'eth', 'local', id)).status, 200)
  const self = { ...JOB_INPUT, name: 'to self', chains: { eth: { ...(JOB_INPUT.chains as { eth: object }).eth, publishMode: 'eth.calldata.self' } } }
  const b = await running(t, 'browser', { jobs: [self] })
  const sid = b.ids[0]
  assert.equal(guardOf(await append(b, 1, 'intent', intent(1), 'eth', 'local', sid)), 'ticket.recipient')
  assert.equal(guardOf(await append(b, 1, 'intent', { ...intent(1), eth: { ...(intent(1).eth as object), to: CLAWBACK_TO } }, 'eth', 'local', sid)), 'ticket.recipient')
  const ok = await append(b, 1, 'intent', { ...intent(1, 1, 1, undefined, self), eth: { ...(intent(1).eth as object), to: KEYS.eth.toLowerCase() } }, 'eth', 'local', sid)
  assert.equal(ok.status, 200)
  assert.equal(verifyTicket(TICKET_KEY, (ok.json as { ticket: string }).ticket, b.clock.now()).to, KEYS.eth.toLowerCase())   // the ticket binds the planned recipient
  const { a: c, id: cid } = await drained(t)
  const claw = ethClawback(7, CLAWBACK_TO, '1')
  assert.equal(guardOf(await append(c, 1, 'clawback-intent', { ...claw, eth: { ...(claw.eth as object), to: '0x1111111111111111111111111111111111111111' } }, 'eth', 'local', cid)), 'event.shape')
})

test('m1: claw-backs pass the legacy latch, reconcile-first and the duplicate check like intents', async (t) => {
  const latch = await drained(t)
  await openLegacyTrigger(latch.a)
  const r = await append(latch.a, 1, 'clawback-intent', ethClawback(7, CLAWBACK_TO, '1'), 'eth', 'local', latch.id)
  assert.equal(r.status, 423)
  assert.equal(guardOf(r), 'trigger.uncleared')

  const { a, id } = await drained(t)
  assert.equal(guardOf(await append(a, 1, 'clawback-intent', ethClawback(1, CLAWBACK_TO, '1'), 'eth', 'local', id)), 'event.duplicate') // tx(1) is a job intent
  assert.equal((await append(a, 1, 'clawback-intent', ethClawback(7, CLAWBACK_TO, '1'), 'eth', 'local', id)).status, 200)
  assert.equal(guardOf(await append(a, 1, 'clawback-intent', { ...ethClawback(7, CLAWBACK_TO, '2'), eth: { nonce: 8, tip: '1', maxFee: '2', gas: '21000', to: CLAWBACK_TO } }, 'eth', 'local', id)), 'event.duplicate')
  a.clock.advance(15_000)
  assert.equal((await lease(a, 'acquire', 'cli', undefined, 'eth', 'local', id)).status, 200) // gen 2; the gen-1 claw-back is open
  const early = await append(a, 2, 'clawback-intent', ethClawback(9, CLAWBACK_TO, '1'), 'eth', 'local', id)
  assert.equal(early.status, 409)
  assert.equal(guardOf(early), 'lease.reconcile-first')
})

test('m1: the lease checks and the append run in one queue turn (a takeover in between → lease.stale, nothing journaled)', async (t) => {
  const a = await running(t)
  let open!: () => void
  const gate = new Promise<void>((r) => { open = r })
  const held = a.api.leases.run(JOB, () => gate)
  const pending = append(a, 1, 'intent', intent(1)) // queued behind the gate, its gen live right now
  await new Promise((r) => setTimeout(r, 50))
  a.clock.advance(15_000) // the lease lapses while the intent waits
  const takeover = lease(a, 'acquire', 'cli') // queued after the intent
  open()
  await held
  const r = await pending
  assert.equal(r.status, 409)
  assert.equal(guardOf(r), 'lease.stale')
  assert.equal((await takeover).status, 200)
  assert.ok(!journalLines(a).some((l) => l.type === 'intent'))
})

// ---- S2 re-review fix round 2 ----

test('N-1: CLAWED_BACK → clawback-failed → resumed → intent: every step refused, no ticket', async (t) => {
  const { a, id } = await drained(t)
  assert.equal((await append(a, 1, 'clawback-intent', ethClawback(7, CLAWBACK_TO, '1'), 'eth', 'local', id)).status, 200)
  assert.equal((await append(a, 1, 'clawback-included', { txId: tx(7), value: '1', fee: '21000' }, 'eth', 'local', id)).status, 200)
  const failed = await append(a, 1, 'clawback-failed', { txId: tx(7), reason: 'after all' }, 'eth', 'local', id)
  assert.equal(failed.status, 409)
  assert.equal(guardOf(failed), 'job.state')
  assert.equal(guardOf(await append(a, 1, 'resumed', { reason: 'back' }, 'eth', 'local', id)), 'job.state')
  const i = await append(a, 1, 'intent', intent(8, 3), 'eth', 'local', id)
  assert.equal(guardOf(i), 'job.state')
  assert.ok(!i.text.includes('vt-ticket'))
  assert.equal((await append(a, 1, 'clawback-readback', { txId: tx(7), ok: true, destReceived: '1', laneBalance: '0' }, 'eth', 'local', id)).status, 200) // evidence
  const s = (await call(a.port, { path: `/jobs/${id}` })).json as { state: { chains: { eth: { phase: string } } } }
  assert.equal(s.state.chains.eth.phase, 'CLAWED_BACK')
})

test('N-1: a failed claw-back returns the chain to settled once; nothing reopens on a chain that is over or during a claw-back', async (t) => {
  const { a, id } = await drained(t)
  await append(a, 1, 'sent', { txId: tx(1), outcome: 'accepted', reason: null }, 'eth', 'local', id).then((r) => assert.equal(guardOf(r), 'event.attempt')) // landed: not open
  assert.equal((await append(a, 1, 'clawback-intent', ethClawback(7, CLAWBACK_TO, '1'), 'eth', 'local', id)).status, 200)
  assert.equal(guardOf(await append(a, 1, 'reconcile', { txId: tx(1), outcome: 'adopted' }, 'eth', 'local', id)), 'job.state') // a job attempt during a claw-back
  assert.equal((await append(a, 1, 'clawback-failed', { txId: tx(7), reason: 'rejected' }, 'eth', 'local', id)).status, 200)
  assert.equal(guardOf(await append(a, 1, 'clawback-failed', { txId: tx(7), reason: 'again' }, 'eth', 'local', id)), 'job.state')
  assert.equal(guardOf(await append(a, 1, 'clawback-included', { txId: tx(7), value: '1', fee: '1' }, 'eth', 'local', id)), 'job.state')
  assert.equal(guardOf(await call(a.port, { path: `/jobs/${id}/close`, body: { chain: 'eth' } })), 'job.state') // its value is still in flight (NEW-2)
  assert.equal((await append(a, 1, 'reconcile', { txId: tx(7), outcome: 'nonce-consumed' }, 'eth', 'local', id)).status, 200)
  assert.equal((await call(a.port, { path: `/jobs/${id}/close`, body: { chain: 'eth' } })).status, 200) // DRAINED again, nothing in flight
  for (const [type, data] of [['stuck', { txId: tx(1), reason: 'x' }], ['reconcile', { txId: tx(1), outcome: 'adopted' }]] as const) {
    assert.equal(guardOf(await append(a, 1, type, data, 'eth', 'local', id)), 'job.state', type)
  }
  assert.equal((await append(a, 1, 'readback', { txId: tx(1), ok: true, detail: 'again' }, 'eth', 'local', id)).status, 200) // evidence
})

test('N-1: evidence names a known attempt of its chain (event.attempt), with its own copy, part and attempt', async (t) => {
  const a = await running(t)
  assert.equal((await append(a, 1, 'intent', intent(1))).status, 200)
  for (const [type, data] of [
    ['sent', { txId: tx(9), outcome: 'accepted', reason: null }], ['readback', { txId: tx(9), ok: true, detail: '' }],
    ['included', { txId: tx(9), copy: 1, part: 1, attempt: 1, block: '1', fee: '1', ms: 1 }],
    ['included', { txId: tx(1), copy: 2, part: 1, attempt: 1, block: '1', fee: '1', ms: 1 }],
    ['included', { txId: tx(1), copy: 1, part: 1, attempt: 2, block: '1', fee: '1', ms: 1 }],
    ['reconcile', { txId: tx(9), outcome: 'expired' }], ['stuck', { txId: tx(9), reason: 'x' }],
    ['replaced', { txId: tx(1), prevId: tx(9), reason: 'bump' }], ['clawback-sent', { txId: tx(1), outcome: 'accepted' }],
    ['clawback-readback', { txId: tx(1), ok: true, destReceived: '1', laneBalance: '0' }], ['reassembled', { copy: 4, ok: true, sha256: 'ab'.repeat(32) }],
  ] as const) {
    const r = await append(a, 1, type, data)
    assert.equal(r.status, 400, `${type} ${JSON.stringify(data).slice(0, 60)}`)
    assert.equal(guardOf(r), 'event.attempt', type)
  }
  assert.equal((await append(a, 1, 'sent', { txId: tx(1), outcome: 'rejected', reason: 'dead' })).status, 200)
  assert.equal(guardOf(await append(a, 1, 'sent', { txId: tx(1), outcome: 'accepted', reason: null })), 'event.attempt') // a rejected attempt never reopens
  assert.equal(guardOf(await append(a, 1, 'reconcile', { txId: tx(1), outcome: 'adopted' })), 'event.attempt')
  assert.equal((await append(a, 1, 'reconcile', { txId: tx(1), outcome: 'included', block: '7', fee: '5' })).status, 200) // it landed after all: evidence
  assert.equal((await append(a, 1, 'reassembled', { copy: 1, ok: true, sha256: 'ab'.repeat(32) })).status, 200)
})

test('N-2: eth families are (copy, part, nonce) — the 12-intents-same-nonce probe gets one ticket', async (t) => {
  const a = await running(t)
  const statuses: string[] = []
  for (let c = 1; c <= 12; c++) {
    const r = await append(a, 1, 'intent', big(c, { copy: Math.min(c, 2), nonce: 5 }))   // N-2: copy 1, then the next copy (2) each time
    statuses.push(r.status === 200 ? 'ok' : String(guardOf(r)))
    if (c > 1) assert.ok(!r.text.includes('vt-ticket'))
  }
  assert.deepEqual(statuses, ['ok', ...Array(11).fill('event.family')])
  // the family of copy 1: a bump must name the open attempt it replaces
  assert.equal(guardOf(await append(a, 1, 'intent', big(20, { copy: 1, attempt: 2, nonce: 5 }))), 'event.family') // replaces: null
  assert.equal(guardOf(await append(a, 1, 'intent', big(21, { copy: 1, attempt: 2, nonce: 6 }))), 'event.family') // a 2nd family for copy 1
  assert.equal(guardOf(await append(a, 1, 'intent', big(22, { copy: 2, nonce: 6, replaces: tx(1) }))), 'event.family') // replaces another (copy, part)
  assert.equal((await append(a, 1, 'intent', big(23, { copy: 1, attempt: 2, nonce: 5, maxFee: '44000000000', replaces: tx(1) }))).status, 200)
  assert.equal((await append(a, 1, 'intent', big(24, { copy: 2, nonce: 6 }))).status, 200)
})

test('N-3: the 13-claw-backs probe: one family at a time; a sol claw-back waits until the open one is closed', async (t) => {
  const { a, id } = await drained(t) // cap 4e15, charged 1e15
  const out: string[] = []
  for (let n = 30; n < 43; n++) {
    const r = await append(a, 1, 'clawback-intent', ethClawback(n, CLAWBACK_TO, '1000000000000000'), 'eth', 'local', id)
    out.push(r.status === 200 ? 'ok' : String(guardOf(r)))
  }
  assert.deepEqual(out, ['ok', ...Array(12).fill('event.family')])
  assert.equal((await append(a, 1, 'reconcile', { txId: tx(30), outcome: 'expired' }, 'eth', 'local', id)).status, 200) // closed
  assert.equal((await append(a, 1, 'clawback-intent', ethClawback(50, CLAWBACK_TO, '1000000000000000'), 'eth', 'local', id)).status, 200) // a new family

  const b = await api(t, { jobs: [JOB2_INPUT] })
  await armed(b, JOB2, ['sol'])
  await lease(b, 'acquire', 'cli', undefined, 'sol', 'local', JOB2)
  const ev = (type: string, data: unknown) => append(b, 1, type, data, 'sol', 'local', JOB2)
  const s1 = solIntent(1)
  for (const [type, data] of [['intent', s1], ['included', { txId: s1.txId, copy: 1, part: 1, attempt: 1, block: '9', fee: '5000', ms: 1 }],
    ['drained', { balance: '1', nextCost: '2', copy: 2 }]] as const) assert.equal((await ev(type, data)).status, 200, type)
  // an unpriced transfer, as the engine journals it: no ComputeBudget instruction, the default limit 200,000 (PF-S fix round 3, R2-1)
  const solClaw = (n: number) => { const x = solIntent(n); return { txId: x.txId, to: 'G147qVmzynHL3EjQ8tvBGDms7u6FDCWbFfFmzNMZmg1x', value: '1000', rawSha256: raw(n), sol: { ...(x.sol as object), cuPrice: 0, cuLimit: 200_000 } } }
  assert.equal((await ev('clawback-intent', solClaw(2))).status, 200)
  assert.equal(guardOf(await ev('clawback-intent', solClaw(3))), 'event.family')
  assert.equal((await ev('reconcile', { txId: solClaw(2).txId, outcome: 'expired' })).status, 200)
  assert.equal((await ev('clawback-intent', solClaw(3))).status, 200)
})

test('N-4: a landing without a reported fee charges its worst case (the reviewer\'s probe); a fee reported later never makes room (I2: core spent)', async (t) => {
  const a = await running(t) // cap 4e15; each big() intent's worst case is 1e15
  const out: string[] = []
  for (let c = 1; c <= 12; c++) {
    const r = await append(a, 1, 'intent', big(c, { copy: Math.min(c, 5) }))   // N-2: a refused copy is tried again as the next copy
    out.push(r.status === 200 ? 'ok' : String(guardOf(r)))
    if (r.status === 200) assert.equal((await append(a, 1, 'reconcile', { txId: tx(c), outcome: 'included' })).status, 200)
  }
  assert.deepEqual(out, ['ok', 'ok', 'ok', 'ok', ...Array(8).fill('arm.amount')])
  // the fees arrive for copies 1 and 2 (0 and 1e9): the API ledger's charge drops to 2e15 + 1e9, but the cap takes
  // max(ledger charged, core's spent) (I2) and core's reducer paid each fee-less landing at its worst case: a later
  // `included` of an attempt that already landed changes nothing there (the first landing is the record). So the late
  // fees make no room — the conservative difference between the two ledgers, pinned here and in ledger-agreement.
  for (const [c, fee] of [[1, '0'], [2, '1000000000']] as const) {
    const r = await append(a, 1, 'included', { txId: tx(c), copy: c, part: 1, attempt: 1, block: '9', fee, ms: 1 })
    assert.equal(r.status, 200, r.text)
  }
  const w = [1, 2, 3, 4].map((c) => worstOf(big(c, { copy: c })))   // each ≈ 1e15 (big: within one gas below)
  assert.equal(a.api.registry.ledgerOf(await a.api.registry.load(JOB), 'eth').charged, w[2] + w[3] + 1_000_000_000n)
  assert.equal(a.api.registry.jobState(JOB).spent('eth'), w[0] + w[1] + w[2] + w[3])
  assert.equal(guardOf(await append(a, 1, 'intent', big(13, { copy: 5 }))), 'arm.amount')
  // resolve mark-done (no fee at all) charges the worst case too
  const b = await running(t)
  assert.equal((await append(b, 1, 'intent', big(1))).status, 200)
  await append(b, 1, 'stuck', { txId: tx(1), reason: 'unknowable' })
  assert.equal((await call(b.port, { path: `/jobs/${JOB}/chains/eth/resolve`, body: { txId: tx(1), action: 'mark-done' } })).status, 200)
  for (const n of [2, 3, 4]) assert.equal((await append(b, 1, 'intent', big(n))).status, 200)
  assert.equal(guardOf(await append(b, 1, 'intent', big(5))), 'arm.amount')
})

test('N-5: /tickets refuses a STUCK chain; after a Stop only an existing open intent is re-ticketed (identical bytes), never a new one', async (t) => {
  const a = await running(t)
  assert.equal((await append(a, 1, 'intent', intent(1))).status, 200)
  await append(a, 1, 'sent', { txId: tx(1), outcome: 'unknown', reason: 'timeout' })
  await append(a, 1, 'stuck', { txId: tx(1), reason: 'unknowable' })
  const stuck = await ticket(a, 1, tx(1))
  assert.equal(stuck.status, 409)
  assert.equal(guardOf(stuck), 'job.state')

  // operator stop: the open intent's identical bytes may be relayed again; a new intent may not, and (PF-S fix round 3) neither may a
  // bump of it: nothing new is signed after a Stop
  const b = await running(t)
  assert.equal((await append(b, 1, 'intent', big(1))).status, 200)
  assert.equal((await call(b.port, { path: `/jobs/${JOB}/stop`, body: { chain: 'eth' } })).status, 200)
  const again = await ticket(b, 1, tx(1))
  assert.equal(again.status, 200)
  assert.equal(verifyTicket(TICKET_KEY, (again.json as { ticket: string }).ticket, b.clock.now()).r, raw(1))
  const fresh = await append(b, 1, 'intent', big(2))
  assert.equal(fresh.status, 409)
  assert.equal(guardOf(fresh), 'intent.after-stop')
  const bump = await append(b, 1, 'intent', big(3, { copy: 1, attempt: 2, nonce: 1, maxFee: '44000000000', replaces: tx(1) }))
  assert.deepEqual([bump.status, guardOf(bump)], [409, 'intent.after-stop'])

  // executor stopped (STOPPED): the open intents are re-ticketed; nothing new
  const c = await running(t)
  assert.equal((await append(c, 1, 'intent', intent(1))).status, 200)
  assert.equal((await append(c, 1, 'stopped', { reason: 'operator' })).status, 200)
  assert.equal((await ticket(c, 1, tx(1))).status, 200)
  assert.equal(guardOf(await append(c, 1, 'intent', intent(2, 2))), 'intent.after-stop')
})

test('PF-S fix round 3: after a stop request (or a journaled stop) no new job intent — no bump, replacement, re-sign, next part or copy — until a resume; claw-backs stay allowed', async (t) => {
  const stop = (a: TestApi, chain: string, id = JOB) => call(a.port, { path: `/jobs/${id}/stop`, body: { chain } })
  const refusedAfterStop = async (r: Promise<Reply>, why: string): Promise<void> => {
    const x = await r
    assert.deepEqual([x.status, guardOf(x)], [409, 'intent.after-stop'], `${why}: ${x.text}`)
    assert.ok(!x.text.includes('vt-ticket'), why)
  }
  // ETH (JOB): copy 1 in flight, then the operator's Stop
  const a = await running(t)
  assert.equal((await append(a, 1, 'intent', intent(1))).status, 200)
  assert.equal((await stop(a, 'eth')).status, 200)
  const n0 = journalLines(a).length
  const bump = { ...intent(2), copy: 1, attempt: 2, replaces: tx(1), eth: { ...(intent(1).eth as object), maxFee: '2250013501', tip: '13501' } }
  await refusedAfterStop(append(a, 1, 'intent', bump), 'an eth fee bump of the attempt in flight (same nonce, replaces it)')
  await refusedAfterStop(append(a, 1, 'intent', { ...bump, replaces: null }), 'an eth replacement that names nothing')
  await refusedAfterStop(append(a, 1, 'intent', intent(3, 2)), 'the next copy')
  assert.equal(journalLines(a).length, n0, 'nothing journaled')
  assert.equal((await ticket(a, 1, tx(1))).status, 200, 'the in-flight bytes are still re-ticketed')
  // the control: without a Stop the same bump is accepted
  const ctl = await running(t)
  assert.equal((await append(ctl, 1, 'intent', intent(1))).status, 200)
  assert.equal((await append(ctl, 1, 'intent', bump)).status, 200, 'the bump without a Stop')
  // a resume lifts it: the next copy is accepted again
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/resume`, body: { chain: 'eth' } })).status, 200)
  assert.equal((await append(a, 1, 'intent', intent(3, 2))).status, 200)
  // an all-chain Stop (chain null) covers the chain too
  assert.equal((await stop(a, null as unknown as string)).status, 200)
  await refusedAfterStop(append(a, 1, 'intent', intent(4, 3)), 'the next copy after an all-chain Stop')

  // SOL (PLANNED_JOB: copy 1 has two parts): part 1 in flight, then the Stop — no re-sign of part 1, no part 2
  const s = await api(t, { jobs: [PLANNED_JOB] })
  const sid = s.ids[0]
  await armed(s, sid, ['sol'])
  assert.equal((await lease(s, 'acquire', 'cli', undefined, 'sol', 'local', sid)).status, 200)
  const sol = (n: number, part: number, o: Record<string, unknown> = {}): Record<string, unknown> => ({ ...solIntent(n, 1, part, undefined, PLANNED_JOB), ...o })
  assert.equal((await append(s, 1, 'intent', sol(1, 1), 'sol', 'local', sid)).status, 200)
  assert.equal((await stop(s, 'sol', sid)).status, 200)
  await refusedAfterStop(append(s, 1, 'intent', sol(2, 1, { attempt: 2, replaces: solSig(1) }), 'sol', 'local', sid), 'a sol re-sign of part 1')
  await refusedAfterStop(append(s, 1, 'intent', sol(3, 2), 'sol', 'local', sid), 'the next part')
  // the control: a resume lifts it (the next part, then a re-sign of it, are accepted)
  assert.equal((await call(s.port, { path: `/jobs/${sid}/resume`, body: { chain: 'sol' } })).status, 200)
  assert.equal((await append(s, 1, 'intent', sol(3, 2), 'sol', 'local', sid)).status, 200)
  assert.equal((await append(s, 1, 'intent', sol(4, 2, { attempt: 2, replaces: solSig(3) }), 'sol', 'local', sid)).status, 200)

  // a journaled stop (the executor's `stopped`: phase STOPPED): no bump, no next copy; a claw-back is allowed (the way out)
  const c = await running(t)
  for (const [type, data] of [['intent', intent(1)], ['sent', { txId: tx(1), outcome: 'accepted', reason: null }],
    ['included', { txId: tx(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '1000', ms: 1 }], ['stopped', { reason: 'operator' }]] as const) {
    assert.equal((await append(c, 1, type, data)).status, 200, type)
  }
  await refusedAfterStop(append(c, 1, 'intent', intent(2, 2)), 'the next copy on a STOPPED chain')
  await refusedAfterStop(append(c, 1, 'intent', { ...intent(1), txId: tx(5), attempt: 2, replaces: tx(1) }), 'a bump on a STOPPED chain')
  const cb = await append(c, 1, 'clawback-intent', ethClawback(7, CLAWBACK_TO, '1000'))
  assert.equal(cb.status, 200, cb.text)
  // a claw-back fee bump (same nonce and destination) stays allowed too: the claw-back family's own rules
  const cbBump = { ...ethClawback(8, CLAWBACK_TO, '1000', { maxFee: '3000000000' }), eth: { ...(ethClawback(8, CLAWBACK_TO, '1000', { maxFee: '3000000000' }).eth as object), nonce: 7 } }
  assert.equal((await append(c, 1, 'clawback-intent', cbBump)).status, 200)

  // a settled chain with a stop request (drained, then Stop): its claw-back is not refused by the Stop
  const d = await drained(t)
  assert.equal((await stop(d.a, 'eth', d.id)).status, 200)
  const dcb = await append(d.a, 1, 'clawback-intent', ethClawback(7, CLAWBACK_TO, '1000'), 'eth', 'local', d.id)
  assert.equal(dcb.status, 200, dcb.text)
})

test('N-1: after a claw-back reconcile the executor still journals its outcome (E1 ruling 5): included → CLAWED_BACK; expired → failed by itself (CC-2a)', async (t) => {
  const { a, id } = await drained(t)
  assert.equal((await append(a, 1, 'clawback-intent', ethClawback(7, CLAWBACK_TO, '1'), 'eth', 'local', id)).status, 200)
  assert.equal((await append(a, 1, 'reconcile', { txId: tx(7), outcome: 'included', block: '9', fee: '21000' }, 'eth', 'local', id)).status, 200)
  assert.equal(guardOf(await append(a, 1, 'clawback-failed', { txId: tx(7), reason: 'no' }, 'eth', 'local', id)), 'job.state') // it landed (NEW-1)
  const own = await append(a, 1, 'clawback-included', { txId: tx(7), value: '1', fee: '21000' }, 'eth', 'local', id)
  assert.equal(own.status, 200, own.text)
  const done = (await call(a.port, { path: `/jobs/${id}` })).json as { state: { chains: { eth: { phase: string } } } }
  assert.equal(done.state.chains.eth.phase, 'CLAWED_BACK')

  // I2 (core reducer, CC-2a D-2): every member dead → the claw-back failed BY ITSELF, back to DRAINED at the reconcile;
  // its outcome is no longer pending, so neither a late clawback-included nor a clawback-failed is accepted (E3 journals
  // clawback-failed only for a member that failed on chain, before its nonce-consumed)
  const b = await drained(t)
  assert.equal((await append(b.a, 1, 'clawback-intent', ethClawback(7, CLAWBACK_TO, '1'), 'eth', 'local', b.id)).status, 200)
  assert.equal((await append(b.a, 1, 'reconcile', { txId: tx(7), outcome: 'expired' }, 'eth', 'local', b.id)).status, 200)
  const back = (await call(b.a.port, { path: `/jobs/${b.id}` })).json as { state: { chains: { eth: { phase: string; clawback: { ok: boolean | null } } } } }
  assert.deepEqual([back.state.chains.eth.phase, back.state.chains.eth.clawback.ok], ['DRAINED', false])
  assert.equal(guardOf(await append(b.a, 1, 'clawback-included', { txId: tx(7), value: '1', fee: '1' }, 'eth', 'local', b.id)), 'job.state') // it expired
  assert.equal(guardOf(await append(b.a, 1, 'clawback-failed', { txId: tx(7), reason: 'expired' }, 'eth', 'local', b.id)), 'job.state')
})

// ---- security fix (verifier NEW-1..NEW-3) ----

test('NEW-1: a claw-back landed by reconcile settles the chain: no second claw-back, no clawback-failed/-sent, no phase event, no intent', async (t) => {
  const { a, id } = await drained(t)
  const ev = (type: string, data: unknown) => append(a, 1, type, data, 'eth', 'local', id)
  assert.equal((await ev('clawback-intent', ethClawback(7, CLAWBACK_TO, '1000000000000000'))).status, 200)
  assert.equal((await ev('reconcile', { txId: tx(7), outcome: 'included', block: '5', fee: '42000000000000' })).status, 200)
  for (const [type, data] of [
    ['clawback-intent', ethClawback(13, CLAWBACK_TO, '1', { gas: '21000', maxFee: '2000012000' })], ['clawback-intent', ethClawback(14, CLAWBACK_TO, '1')],
    ['clawback-failed', { txId: tx(7), reason: 'x' }], ['clawback-sent', { txId: tx(7), outcome: 'accepted' }],
    ['resumed', { reason: 'back' }], ['paused', { reason: 'p' }], ['stopped', { reason: 's' }], ['intent', intent(20, 2)],
  ] as const) {
    const r = await ev(type, data)
    assert.equal(r.status, 409, `${type}: ${r.text}`)
    assert.equal(guardOf(r), 'job.state', type)
    assert.ok(!r.text.includes('vt-ticket'))
  }
  const own = await ev('clawback-included', { txId: tx(7), value: '1000000000000000', fee: '42000000000000' }) // its own outcome
  assert.equal(own.status, 200, own.text)
  assert.equal(((await call(a.port, { path: `/jobs/${id}` })).json as { state: { chains: { eth: { phase: string } } } }).state.chains.eth.phase, 'CLAWED_BACK')
})

test('NEW-2: a rejected / failed claim never releases the cap — the 12-rounds and 8-late-landings probes stop at the cap', async (t) => {
  const a = await running(t) // cap 4e15, each big() intent 1e15
  const rounds: string[] = []
  for (let c = 1; c <= 12; c++) {
    const r = await append(a, 1, 'intent', big(c, { copy: Math.min(c, 5) }))   // N-2: a refused copy is tried again as the next copy
    rounds.push(r.status === 200 ? 'ok' : String(guardOf(r)))
    if (r.status !== 200) continue
    await append(a, 1, 'sent', { txId: tx(c), outcome: 'accepted', reason: null })
    await append(a, 1, 'sent', { txId: tx(c), outcome: 'rejected', reason: 'claimed' })
  }
  assert.deepEqual(rounds, ['ok', 'ok', 'ok', 'ok', ...Array(8).fill('arm.amount')])
  // the late landings: only the four that exist can land, so the reducer's spent stays within the cap
  for (let c = 1; c <= 4; c++) assert.equal((await append(a, 1, 'included', { txId: tx(c), copy: c, part: 1, attempt: 1, block: '9', fee: '1000000000000000', ms: 1 })).status, 200)
  const s = (await call(a.port, { path: `/jobs/${JOB}` })).json as { state: { chains: { eth: { spent: string } } } }
  assert.ok(BigInt(s.state.chains.eth.spent) <= 4_000_000_000_000_000n)
  assert.equal(guardOf(await append(a, 1, 'intent', big(5, { copy: 5 }))), 'arm.amount')
})

test('NEW-2: 16 claw-back rounds (intent, sent, failed): a new family waits; same-nonce retries keep fee charged and value in flight', async (t) => {
  const { a, id } = await drained(t) // cap 4e15, charged 1e15
  const ev = (type: string, data: unknown) => append(a, 1, type, data, 'eth', 'local', id)
  const out: string[] = []
  for (let n = 30; n < 46; n++) {
    const r = await ev('clawback-intent', ethClawback(n, CLAWBACK_TO, '1000000000000000'))
    out.push(r.status === 200 ? 'ok' : String(guardOf(r)))
    if (r.status !== 200) continue
    await ev('clawback-sent', { txId: tx(n), outcome: 'accepted' })
    assert.equal((await ev('clawback-failed', { txId: tx(n), reason: 'claimed' })).status, 200)
  }
  assert.deepEqual(out, ['ok', ...Array(15).fill('event.family')])
  const l = a.api.registry.ledgerOf(a.api.registry.get(id), 'eth')
  const fee = 21000n * 2000012000n
  assert.deepEqual([l.charged, l.inFlight], [1_000_000_000_000_000n + fee, 1_000_000_000_000_000n]) // the failed fee charged, the value in flight
  // a same-nonce retry is one family: counted once, and still capped
  const retry = (n: number, value: string) => ({ ...ethClawback(n, CLAWBACK_TO, value), eth: { nonce: 30, tip: '12000', maxFee: '2000012000', gas: '21000', to: CLAWBACK_TO } })
  assert.equal(guardOf(await ev('clawback-intent', retry(60, '2958000000000000'))), 'arm.amount') // 1e15 + fee + (2.958e15 + fee) > 4e15
  assert.equal((await ev('clawback-intent', retry(61, '2000000000000000'))).status, 200)
  assert.equal((await ev('reconcile', { txId: tx(61), outcome: 'nonce-consumed' })).status, 200)
  assert.equal((await ev('reconcile', { txId: tx(30), outcome: 'nonce-consumed' })).status, 200) // now evidence: nothing of nonce 30 can land
  assert.equal(l.inFlight, 0n)
})

test('NEW-3: declared fees are floored — eth gas >= intrinsic, maxFee >= 1 and >= tip; sol fee >= 5,000 + priority, cuPrice <= the cap', async (t) => {
  const a = await running(t)
  const eth = (o: Record<string, string>) => ({ ...intent(1), eth: { ...(intent(1).eth as object), ...o } })
  for (const o of [{ gas: '0', maxFee: '0' }, { gas: '1', maxFee: '1' }, { gas: '18583' }, { maxFee: '0' }, { maxFee: '11999' /* < tip 12000 */ }] as Array<Record<string, string>>) {
    const r = await append(a, 1, 'intent', eth(o))
    assert.equal(r.status, 400, JSON.stringify(o))
    assert.equal(guardOf(r), 'event.shape', JSON.stringify(o))
  }
  const sixty: number[] = []
  for (let c = 1; c <= 60; c++) sixty.push((await append(a, 1, 'intent', { ...intent(c, c), eth: { ...(intent(c, c).eth as object), gas: '0', maxFee: '0' } })).status)
  assert.ok(sixty.every((s) => s === 400)) // the 60-tickets probe
  assert.equal((await append(a, 1, 'intent', eth({ gas: '18584' }))).status, 200) // the local floor for 56 bytes to the null address
  const b = await api(t, { jobs: [JOB2_INPUT] })
  await armed(b, JOB2, ['sol'])
  await lease(b, 'acquire', 'cli', undefined, 'sol', 'local', JOB2)
  const sol = (n: number, o: Record<string, unknown>) => { const d = solIntent(n); return { ...d, sol: { ...(d.sol as object), ...o } } }
  for (const o of [{ fee: '0' }, { fee: '1', cuPrice: 1_000_000_000_000, cuLimit: 1_400_000 }, { fee: '5000', cuPrice: 1 }, { fee: '999999999', cuPrice: 8_000_001, cuLimit: 1 }]) {
    const r = await append(b, 1, 'intent', sol(1, o), 'sol', 'local', JOB2)
    assert.equal(guardOf(r), 'event.shape', JSON.stringify(o))
  }
  // within the network's cap (8,000,000) but above this lane's maxCuPrice (2,000,000): ticket.fee-plan (PF-S fix round 2); at the lane's cap it passes
  assert.equal(guardOf(await append(b, 1, 'intent', sol(1, { fee: '5008', cuPrice: 8_000_000, cuLimit: 1 }), 'sol', 'local', JOB2)), 'ticket.fee-plan')
  assert.equal((await append(b, 1, 'intent', sol(1, { fee: '5002', cuPrice: 2_000_000, cuLimit: 1 }), 'sol', 'local', JOB2)).status, 200) // 5,000 + ⌈1 × 2,000,000 / 10⁶⌉
})

// ---- PF-S fix round 2 (R1-1): the declared fee members are within vt's plan (the ticket binds them as x; decode.ts compares the bytes)

test('PF-S fix round 2 (R1-1): ticket.fee-plan — ETH gas in [formula, formula + ⌈15/985⌉] of the planned payload (local: either fork), a claw-back\'s the transfer gas; SOL CU limit up to the model, CU price up to the lane\'s cap', async (t) => {
  // JOB (eth.calldata.null, local), copy 1 part 1: 56 planned bytes → pre-Amsterdam [21000 + 40 × 56, + ⌈g × 15 / 985⌉] = [23240, 23594],
  // Amsterdam [15000 + 64 × 56, + ⌈g × 15 / 985⌉] = [18584, 18868] (chains/plan.js ethGasBudget: the estimate tolerance)
  assert.equal(plannedPayloads(JOB_INPUT, 'eth', 1)[0].length, 56)
  const a = await running(t)
  const eth = (gas: string): Record<string, unknown> => ({ ...intent(1), eth: { ...(intent(1).eth as object), gas } })
  const n0 = journalLines(a).length
  for (const gas of ['23239', '23595', '18869', '21000', '60000', '120000']) {
    const r = await append(a, 1, 'intent', eth(gas))
    assert.deepEqual([r.status, guardOf(r)], [409, 'ticket.fee-plan'], gas)
    assert.ok(!r.text.includes('vt-ticket'), gas)
  }
  assert.equal(journalLines(a).length, n0, 'nothing journaled')
  for (const gas of ['23240', '23594', '18584', '18868']) {
    const b = await running(t)
    const r = await append(b, 1, 'intent', eth(gas))
    assert.equal(r.status, 200, `${gas}: ${r.text}`)
    assert.equal(verifyTicket(TICKET_KEY, (r.json as { ticket: string }).ticket, b.clock.now()).x, `${gas}:12000:2000012000`)
  }
  // copy 2 is planned at 65 bytes (its marker): copy 1's gas is refused for it
  const c = await running(t)
  assert.equal((await append(c, 1, 'intent', intent(1))).status, 200)
  assert.equal(guardOf(await append(c, 1, 'intent', { ...intent(2, 2), eth: { ...(intent(2, 2).eth as object), gas: '23240' } })), 'ticket.fee-plan')
  assert.equal((await append(c, 1, 'intent', intent(2, 2))).status, 200)

  // SOL (JOB2: maxCuPrice 2,000,000; copy 1 part 1 is 50 bytes → the model's limit solCuLimit(solCuEstimate) = 49,500)
  const s = await api(t, { jobs: [JOB2_INPUT] })
  await armed(s, JOB2, ['sol'])
  await lease(s, 'acquire', 'cli', undefined, 'sol', 'local', JOB2)
  const sol = (n: number, o: Record<string, unknown>) => { const d = solIntent(n); return { ...d, sol: { ...(d.sol as object), fee: '200000', ...o } } }
  assert.equal((solIntent(1).sol as { cuLimit: number }).cuLimit, 49_500)
  for (const o of [{ cuLimit: 49_501 }, { cuLimit: 1_400_000 }, { cuPrice: 2_000_001 }, { cuPrice: 8_000_000, cuLimit: 1 }]) {
    assert.equal(guardOf(await append(s, 1, 'intent', sol(1, o), 'sol', 'local', JOB2)), 'ticket.fee-plan', JSON.stringify(o))
  }
  const ok = await append(s, 1, 'intent', sol(1, { cuPrice: 2_000_000 }), 'sol', 'local', JOB2)
  assert.equal(ok.status, 200, ok.text)
  assert.equal(verifyTicket(TICKET_KEY, (ok.json as { ticket: string }).ticket, s.clock.now()).x, '49500:2000000')
  // a lane without maxCuPrice: the engine's lane default, 2,000,000 (PF-S fix round 3, R2-1), not the network's 8,000,000
  const { maxCuPrice: _m, ...solNoCap } = (JOB2_INPUT as { chains: { sol: Record<string, unknown> } }).chains.sol
  const noCap = { ...JOB2_INPUT, name: 'no cu price cap', chains: { ...(JOB2_INPUT as { chains: Record<string, unknown> }).chains, sol: solNoCap } }
  const NOCAP = idOf(noCap)
  const nc = await api(t, { jobs: [noCap] })
  await armed(nc, NOCAP, ['sol'])
  await lease(nc, 'acquire', 'cli', undefined, 'sol', 'local', NOCAP)
  const ncsol = (n: number, cuPrice: number) => { const x = solIntent(n, 1, 1, undefined, noCap); return { ...x, sol: { ...(x.sol as object), fee: '200000', cuPrice } } }
  for (const price of [2_000_001, 3_000_000]) assert.equal(guardOf(await append(nc, 1, 'intent', ncsol(1, price), 'sol', 'local', NOCAP)), 'ticket.fee-plan', String(price))
  assert.equal((await append(nc, 1, 'intent', ncsol(1, 2_000_000), 'sol', 'local', NOCAP)).status, 200)
  // a lane with a lower maxCuPrice (1,000,000): an operator resume with a higher cuPriceCap raises its cap (the engine prices up to it)
  const j2 = JOB2_INPUT as { chains: { sol: Record<string, unknown> } & Record<string, unknown> }
  const low = { ...JOB2_INPUT, name: 'low cu price', chains: { ...j2.chains, sol: { ...j2.chains.sol, maxCuPrice: 1_000_000 } } }
  const LOW = idOf(low)
  const l = await api(t, { jobs: [low] })
  await armed(l, LOW, ['sol'])
  await lease(l, 'acquire', 'cli', undefined, 'sol', 'local', LOW)
  const lsol = (n: number, cuPrice: number) => { const x = solIntent(n, 1, 1, undefined, low); return { ...x, sol: { ...(x.sol as object), fee: '200000', cuPrice } } }
  assert.equal(guardOf(await append(l, 1, 'intent', lsol(1, 1_000_001), 'sol', 'local', LOW)), 'ticket.fee-plan')
  assert.equal((await call(l.port, { path: `/jobs/${LOW}/resume`, body: { chain: 'sol', cuPriceCap: 1_500_000 } })).status, 200)
  assert.equal(guardOf(await append(l, 1, 'intent', lsol(1, 1_500_001), 'sol', 'local', LOW)), 'ticket.fee-plan')
  assert.equal((await append(l, 1, 'intent', lsol(1, 1_500_000), 'sol', 'local', LOW)).status, 200)
  // an all-chain resume (chain null) raises it too; the API's bound is the highest cap ever journaled (a lower one never lowers it)
  assert.equal((await call(l.port, { path: `/jobs/${LOW}/resume`, body: { chain: null, cuPriceCap: 1_800_000 } })).status, 200)
  assert.equal((await call(l.port, { path: `/jobs/${LOW}/resume`, body: { chain: 'sol', cuPriceCap: 1_200_000 } })).status, 200)
  assert.equal(guardOf(await append(l, 1, 'intent', { ...lsol(2, 1_800_001), attempt: 2, replaces: solSig(1) }, 'sol', 'local', LOW)), 'ticket.fee-plan')
  const re = await append(l, 1, 'intent', { ...lsol(2, 1_800_000), attempt: 2, replaces: solSig(1) }, 'sol', 'local', LOW)
  assert.equal(re.status, 200, re.text)

  // a SOL claw-back: its CU price at most the claw-back ladder's cap (ECON.SOL_RUNG_CAP 2,000,000) or the lane's
  const d = await api(t, { jobs: [JOB2_INPUT] })
  await armed(d, JOB2, ['sol'])
  await lease(d, 'acquire', 'cli', undefined, 'sol', 'local', JOB2)
  const ev = (type: string, data: unknown) => append(d, 1, type, data, 'sol', 'local', JOB2)
  const s1 = solIntent(1)
  for (const [type, data] of [['intent', s1], ['included', { txId: s1.txId, copy: 1, part: 1, attempt: 1, block: '9', fee: '5000', ms: 1 }],
    ['drained', { balance: '1', nextCost: '2', copy: 2 }]] as const) assert.equal((await ev(type, data)).status, 200, type)
  const claw = (n: number, cuPrice: number, cuLimit = 450) => ({ txId: solSig(n), to: 'G147qVmzynHL3EjQ8tvBGDms7u6FDCWbFfFmzNMZmg1x', value: '1000', rawSha256: raw(n),
    sol: { blockhash: solHash(n), lastValidBlockHeight: 1000, cuPrice, cuLimit, rung: null, fee: '200000' } })
  assert.equal(guardOf(await ev('clawback-intent', claw(2, 2_000_001))), 'ticket.fee-plan')
  // PF-S fix round 3 (R2-1): sized as the engine sizes a transfer — priced: a limit up to solCuLimit(1,000) = 1,100; unpriced: the
  // journaled default 200,000 exactly (no ComputeBudget instruction is in the tx)
  for (const [price, limit] of [[1, 1_101], [1, 1_234_567], [0, 450], [0, 199_999], [0, 200_001]] as const) {
    assert.equal(guardOf(await ev('clawback-intent', claw(4, price, limit))), 'ticket.fee-plan', `price ${price} limit ${limit}`)
  }
  const cb = await ev('clawback-intent', claw(3, 2_000_000, 1_100))
  assert.equal(cb.status, 200, cb.text)
  assert.equal(verifyTicket(TICKET_KEY, (cb.json as { ticket: string }).ticket, d.clock.now()).x, '1100:2000000')

  // an ETH claw-back: the transfer gas of its destination class (21,000; 204,600 to an empty account under Amsterdam, which
  // local may run), nothing else
  const e = await drained(t)
  for (const gas of ['20999', '21001', '60000', '204599', '204601']) {
    assert.equal(guardOf(await append(e.a, 1, 'clawback-intent', ethClawback(7, CLAWBACK_TO, '1000', { gas }), 'eth', 'local', e.id)), 'ticket.fee-plan', gas)
  }
  const empty = await append(e.a, 1, 'clawback-intent', ethClawback(7, CLAWBACK_TO, '1000', { gas: '204600' }), 'eth', 'local', e.id)
  assert.equal(empty.status, 200, empty.text)
  assert.equal(verifyTicket(TICKET_KEY, (empty.json as { ticket: string }).ticket, e.a.clock.now()).x, '204600:12000:2000012000')
})

// ---- I2: CC-2a typed claw-back amount wired into the claw-back cap check

test('CC-2a (I2): a claw-back over the cap passes only with the operator\'s typed amount — exactly value + worst-case fee in base units, for that one intent', async (t) => {
  const { a, id } = await drained(t) // spent 1e15 of the 4e15 cap
  const ev = (type: string, data: unknown, extra: Record<string, unknown> = {}) =>
    call(a.port, { path: `/jobs/${id}/chains/eth/events`, body: { gen: 1, type, data, ...extra } })
  const value = 3_000_000_000_000_000n
  const claw = ethClawback(7, CLAWBACK_TO, String(value))
  const fee = 21_000n * 2_000_012_000n
  const need = value + fee // 3.042e15 > 4e15 − 1e15
  const n = journalLines(a, id).length
  assert.equal(guardOf(await ev('clawback-intent', claw)), 'arm.amount') // over the cap, nothing typed
  for (const confirm of [{ amount: String(need - 1n) }, { amount: String(need + 1n) }, { amount: String(value) }, { amount: Number(need) }, { amount: `0${need}` },
    { amount: String(need), note: 'x' }, { amount: '3.042000252' }, { amount: '' }, {}, 'x', null, [String(need)]]) {
    const r = await ev('clawback-intent', claw, { clawbackConfirm: confirm })
    assert.equal(guardOf(r), 'arm.amount', `${JSON.stringify(confirm)}: ${r.text}`)
    assert.ok(!r.text.includes('vt-ticket'))
  }
  // only beside a clawback-intent; never another member of the body
  assert.equal(guardOf(await ev('note', { text: 'x' }, { clawbackConfirm: { amount: '1' } })), 'arm.amount')
  assert.equal(guardOf(await ev('clawback-intent', claw, { confirm: { amount: String(need) } })), 'event.shape')
  assert.equal(journalLines(a, id).length, n) // nothing journaled
  const ok = await ev('clawback-intent', claw, { clawbackConfirm: { amount: String(need) } })
  assert.equal(ok.status, 200, ok.text)
  const p = verifyTicket(TICKET_KEY, (ok.json as { ticket: string }).ticket, a.clock.now())
  assert.deepEqual([p.k, p.to, p.value, p.f, p.q], ['clawback', CLAWBACK_TO.toLowerCase(), String(value), String(fee), '7'])
  const last = journalLines(a, id).at(-1)!
  assert.deepEqual([last.type, JSON.stringify(last).includes('clawbackConfirm')], ['clawback-intent', false]) // never journaled
  // a bump of the same family (same nonce and destination, a higher fee, the lane's balance again): the same typed amount
  // covers it exactly; a bump whose value + fee is not the typed amount is refused
  const bumpFee = 21_000n * 3_000_000_000n
  const bump = ethClawback(8, CLAWBACK_TO, String(need - bumpFee), { maxFee: '3000000000' })
  const bumped = { ...bump, eth: { ...(bump.eth as Record<string, unknown>), nonce: 7 } }
  assert.equal(guardOf(await ev('clawback-intent', { ...bumped, value: String(need - bumpFee - 1n) }, { clawbackConfirm: { amount: String(need) } })), 'arm.amount')
  const ok2 = await ev('clawback-intent', bumped, { clawbackConfirm: { amount: String(need) } })
  assert.equal(ok2.status, 200, ok2.text)
  // the typed amount raised the limit of those intents only: the chain's cap is the armed one still
  const s = (await call(a.port, { path: `/jobs/${id}` })).json as { state: { armed: { caps: { eth: { nativeCap: string } } } } }
  assert.equal(s.state.armed.caps.eth.nativeCap, '4000000000000000')
})

test('CC-2a (I2): a claw-back that fits needs no typed amount, and a typed amount that is not exactly value + fee is refused even then', async (t) => {
  const { a, id } = await drained(t)
  const ev = (data: unknown, extra: Record<string, unknown> = {}) =>
    call(a.port, { path: `/jobs/${id}/chains/eth/events`, body: { gen: 1, type: 'clawback-intent', data, ...extra } })
  const claw = ethClawback(7, CLAWBACK_TO, '1000')
  const need = 1000n + 21_000n * 2_000_012_000n
  assert.equal(guardOf(await ev(claw, { clawbackConfirm: { amount: String(need + 1n) } })), 'arm.amount')
  assert.equal((await ev(claw, { clawbackConfirm: { amount: String(need) } })).status, 200)
})

test('a journal whose write failed refuses fresh tickets for its open intents: 409 job.state, no ticket (S1 review m4)', async (t) => {
  let fail = false
  const fs: JournalFs = {
    writeSync: (fd, b, o, l) => writeSync(fd, b, o, l),
    fsyncSync: (fd) => { if (fail) throw new Error('EIO'); fsyncSync(fd) },
    ftruncateSync: (fd, n) => ftruncateSync(fd, n),
  }
  const a = await running(t, 'cli', { fs })
  assert.equal((await append(a, 1, 'intent', intent(1))).status, 200)
  assert.equal((await ticket(a, 1, tx(1))).status, 200, 'a healthy journal: a fresh ticket')
  fail = true
  assert.equal(guardOf(await append(a, 1, 'intent', intent(2, 2))), 'journal.write')   // the journal is poisoned from here on
  fail = false                                                                           // even though the disk works again
  const r = await ticket(a, 1, tx(1))
  assert.deepEqual([r.status, guardOf(r)], [409, 'job.state'])
  assert.ok(!r.text.includes('vt-ticket'))
})

test('fencing is atomic with the ticket mint (S1 review m1; the append is pinned by `m1` above, f0c4e29): a ticket request queued before the lease lapsed is judged at its turn — lease.stale after expiry, and no generation-1 line follows lease-acquired', async (t) => {
  const a = await running(t, 'cli')
  assert.equal((await append(a, 1, 'intent', intent(1))).status, 200)
  let open!: () => void
  const held = a.api.leases.run(JOB, () => new Promise<void>((r) => { open = r }))      // hold the job's queue
  const inflight = ticket(a, 1, tx(1))
  await new Promise((r) => setTimeout(r, 150))                                          // the request is queued behind the gate
  a.clock.advance(LEASE_TTL_MS + 1)                                                     // the lease lapses
  const takeover = lease(a, 'acquire', 'browser')                                       // queued after the request
  await new Promise((r) => setTimeout(r, 150))
  open(); await held
  const [old, next] = [await inflight, await takeover]
  assert.deepEqual([old.status, guardOf(old)], [409, 'lease.stale'])
  assert.equal(next.status, 200)
  const lines = journalLines(a)
  const acquired = lines.findLastIndex((l) => l.type === 'lease-acquired')
  assert.ok(acquired > 0 && lines[acquired].gen === 2)
  assert.ok(lines.slice(acquired + 1).every((l) => l.gen !== 1), 'nothing of generation 1 after the takeover')
})

// ---- PF-S fix round 4 (PF-E review I-2): the engine's documented recovery sequence for an ETH attempt dropped at an unused nonce

test('PF-S fix round 4 (PF-E I-2): stop (a raced bump refused) → stopped with the attempt open → rerun, reconcile adopted → its identical bytes re-ticketed → stuck → resolve mark-failed → a claw-back AT THAT NONCE is accepted (its family); the ledger holds both worst cases as core does until chain evidence frees the job attempt; nothing else reuses the nonce', async (t) => {
  const a = await running(t)                                                  // browser, gen 1
  const n = 1, d1 = intent(n)                                                 // copy 1 at nonce 1
  assert.equal((await append(a, 1, 'intent', d1)).status, 200)
  assert.equal((await append(a, 1, 'sent', { txId: tx(n), outcome: 'unknown', reason: 'timeout' })).status, 200)
  // the operator's Stop; the engine's bump raced it and is refused (nothing new signed after a Stop)
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/stop`, body: { chain: 'eth' } })).status, 200)
  const bump = { ...intent(2), copy: 1, attempt: 2, replaces: tx(n), eth: { ...(d1.eth as object), maxFee: '2250013501', tip: '13501' } }
  assert.equal(guardOf(await append(a, 1, 'intent', bump)), 'intent.after-stop')
  // the run ends `stopped` with the attempt open (STOPPED)
  assert.equal((await append(a, 1, 'stopped', { reason: 'stopped by the operator' })).status, 200)
  // the rerun: a new lease after the old one lapsed, the earlier generation's open intent reconciled (adopted), its identical bytes
  // re-ticketed for the rebroadcast, then `stuck` (unseen by every endpoint)
  a.clock.advance(LEASE_TTL_MS + 1)
  const g2 = await lease(a, 'acquire', 'cli', undefined, 'eth', 'local', JOB)
  assert.equal(g2.status, 200, g2.text)
  const gen = (g2.json as { gen: number }).gen
  assert.equal((await append(a, gen, 'reconcile', { txId: tx(n), outcome: 'adopted' })).status, 200)
  const again = await ticket(a, gen, tx(n))
  assert.equal(again.status, 200, again.text)
  assert.equal(verifyTicket(TICKET_KEY, (again.json as { ticket: string }).ticket, a.clock.now()).q, String(n))
  assert.equal((await append(a, gen, 'stuck', { txId: tx(n), reason: 'unseen by every endpoint for 3 windows' })).status, 200)
  // the operator looks it up: it never landed — mark-failed
  const res = await call(a.port, { path: `/jobs/${JOB}/chains/eth/resolve`, body: { txId: tx(n), action: 'mark-failed' } })
  assert.equal(res.status, 200, res.text)
  // nothing but a claw-back may use nonce n now: no job attempt (a new one, or a bump naming the marked-failed one)
  const job = await a.api.registry.load(JOB)
  const cl = () => a.api.registry.ledgerOf(job, 'eth')
  const jobWorst = BigInt((d1.eth as { gas: string }).gas) * BigInt((d1.eth as { maxFee: string }).maxFee)
  const before = cl().inFlight
  assert.equal(before, jobWorst, 'the marked-failed attempt still counts in flight (its bytes may have been accepted)')
  // the claw-back at n: accepted in the nonce's family; the ledger holds both worst cases (as core's CapLedger: the marked-failed
  // attempt stays held until chain evidence frees it), so the API is never below the engine
  const value = 1_000n
  const atN = (k: number, v: string, o: { maxFee?: string } = {}) => ({ ...ethClawback(k, CLAWBACK_TO, v, o), eth: { ...(ethClawback(k, CLAWBACK_TO, v, o).eth as object), nonce: n } })
  // the cap counts both kinds: a claw-back whose value + fee alone fits beside nothing, but not beside the held job attempt, is refused
  // without the operator's typed amount (4e15 cap: W1 + 3.95e15 + 4.2e13 > 4e15 >= 3.95e15 + 4.2e13)
  const tight = await append(a, gen, 'clawback-intent', atN(8, '3950000000000000'))
  assert.deepEqual([tight.status, guardOf(tight)], [400, 'arm.amount'], tight.text)
  const claw = atN(9, String(value))
  const cb = await append(a, gen, 'clawback-intent', claw)
  assert.equal(cb.status, 200, cb.text)
  assert.equal(verifyTicket(TICKET_KEY, (cb.json as { ticket: string }).ticket, a.clock.now()).q, String(n), 'the claw-back ticket binds nonce n')
  const clawWorst = 21_000n * 2_000_012_000n + value
  assert.equal(cl().inFlight, jobWorst + clawWorst, 'both kinds of the nonce count')
  // its replacement under the claw-back rules (same nonce, same destination, a higher fee) is accepted; another destination is not
  const bumpClaw = { ...ethClawback(10, CLAWBACK_TO, String(value), { maxFee: '3000000000' }), eth: { ...(ethClawback(10, CLAWBACK_TO, String(value), { maxFee: '3000000000' }).eth as object), nonce: n } }
  assert.equal((await append(a, gen, 'clawback-intent', bumpClaw)).status, 200)
  const other = { ...ethClawback(11, '0x1111111111111111111111111111111111111111', String(value)), eth: { ...(ethClawback(11, '0x1111111111111111111111111111111111111111', String(value)).eth as object), nonce: n } }
  assert.equal(guardOf(await append(a, gen, 'clawback-intent', other)), 'event.family')
  // the claw-back's own recovery (the engine's documented exit: its member dropped, stuck, resolved mark-failed, "claw back again
  // at the same nonce"): accepted under the claw-back rules (same nonce, same destination)
  assert.equal((await append(a, gen, 'clawback-sent', { txId: tx(10), outcome: 'unknown' })).status, 200)
  assert.equal((await append(a, gen, 'stuck', { txId: tx(10), reason: 'unseen by every endpoint' })).status, 200)
  const rc = await call(a.port, { path: `/jobs/${JOB}/chains/eth/resolve`, body: { txId: tx(10), action: 'mark-failed' } })
  assert.equal(rc.status, 200, rc.text)
  const again2 = { ...ethClawback(12, CLAWBACK_TO, String(value), { maxFee: '3000000000' }), eth: { ...(ethClawback(12, CLAWBACK_TO, String(value), { maxFee: '3000000000' }).eth as object), nonce: n } }
  const cb2 = await append(a, gen, 'clawback-intent', again2)
  assert.equal(cb2.status, 200, cb2.text)
  // the claw-back lands: CLAWED_BACK, the family settled (nothing in flight)
  assert.equal((await append(a, gen, 'clawback-included', { txId: tx(12), value: String(value), fee: '21000000000000' })).status, 200)
  assert.equal(((await call(a.port, { path: `/jobs/${JOB}` })).json as { state: { chains: { eth: { phase: string } } } }).state.chains.eth.phase, 'CLAWED_BACK')
  assert.equal(cl().inFlight, jobWorst, 'the marked-failed job attempt is held until chain evidence (as core)')
  // the evidence: its nonce was consumed (by the claw-back): released
  const nc = await append(a, gen, 'reconcile', { txId: tx(n), outcome: 'nonce-consumed' })
  assert.equal(nc.status, 200, nc.text)
  assert.equal(cl().inFlight, 0n)
})

test('PF-S fix round 4 (PF-E I-2): a marked-failed nonce is the claw-back\'s only — no job attempt joins it (a fresh one, or a bump naming it); an attempt still open (stuck, not resolved) keeps the claw-back out; a claimed-rejected one does not', async (t) => {
  // a RUNNING chain: stuck at nonce 1, resolved mark-failed (back to RUNNING): nothing of the job reuses nonce 1
  const a = await running(t)
  const d1 = intent(1)
  for (const [type, data] of [['intent', d1], ['sent', { txId: tx(1), outcome: 'unknown', reason: 'timeout' }], ['stuck', { txId: tx(1), reason: 'unseen' }]] as const) {
    assert.equal((await append(a, 1, type, data)).status, 200, type)
  }
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/chains/eth/resolve`, body: { txId: tx(1), action: 'mark-failed' } })).status, 200)
  const fresh = { ...intent(2), copy: 1, attempt: 2, eth: { ...(d1.eth as object) } }                       // copy 1 again at nonce 1, replaces nothing
  assert.equal(guardOf(await append(a, 1, 'intent', fresh)), 'event.family', 'a fresh job attempt at the marked-failed nonce')
  const bumpIt = { ...fresh, txId: tx(3), replaces: tx(1), eth: { ...(d1.eth as object), maxFee: '2250013501', tip: '13501' } }
  assert.equal(guardOf(await append(a, 1, 'intent', bumpIt)), 'event.family', 'a bump naming the marked-failed attempt')
  // the control: an attempt that is only stuck (not marked failed) keeps its nonce from a claw-back too (a drained chain's open attempt)
  const b = await running(t)
  for (const [type, data] of [['intent', intent(1)], ['sent', { txId: tx(1), outcome: 'accepted', reason: null }],
    ['included', { txId: tx(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '1000', ms: 1 }], ['readback', { txId: tx(1), ok: true, detail: 'x' }],
    ['intent', intent(2, 2)], ['sent', { txId: tx(2), outcome: 'unknown', reason: 'timeout' }], ['stopped', { reason: 'operator' }]] as const) {
    assert.equal((await append(b, 1, type, data)).status, 200, type)
  }
  b.clock.advance(LEASE_TTL_MS + 1)
  const g = (await lease(b, 'acquire', 'cli', undefined, 'eth', 'local', JOB)).json as { gen: number }
  assert.equal((await append(b, g.gen, 'reconcile', { txId: tx(2), outcome: 'adopted' })).status, 200)
  assert.equal((await append(b, g.gen, 'stuck', { txId: tx(2), reason: 'unseen' })).status, 200)
  const claw2 = { ...ethClawback(9, CLAWBACK_TO, '1000'), eth: { ...(ethClawback(9, CLAWBACK_TO, '1000').eth as object), nonce: 2 } }
  const r = await append(b, g.gen, 'clawback-intent', claw2)
  assert.deepEqual([r.status, guardOf(r)], [409, 'job.state'], 'stuck but not marked failed: still in flight, no claw-back (core first)')
  // ... and once it is marked failed, the claw-back at its nonce is taken
  assert.equal((await call(b.port, { path: `/jobs/${JOB}/chains/eth/resolve`, body: { txId: tx(2), action: 'mark-failed' } })).status, 200)
  assert.equal((await append(b, g.gen, 'clawback-intent', claw2)).status, 200)

  // an attempt the executor CLAIMED rejected is not open (nothing to resolve): it keeps counting, but it does not hold its nonce from
  // the claw-back once the chain is settled ("every open attempt at n resolved" holds); while RUNNING, its replacement stays allowed
  const c = await running(t)
  for (const [type, data] of [['intent', intent(1)], ['sent', { txId: tx(1), outcome: 'accepted', reason: null }],
    ['included', { txId: tx(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '1000', ms: 1 }], ['readback', { txId: tx(1), ok: true, detail: 'x' }],
    ['intent', intent(2, 2)], ['sent', { txId: tx(2), outcome: 'rejected', reason: 'replacement underpriced' }]] as const) {
    assert.equal((await append(c, 1, type, data)).status, 200, type)
  }
  const retry = { ...intent(3, 2), attempt: 2, replaces: tx(2), eth: { ...(intent(2, 2).eth as object), maxFee: '2250013501', tip: '13501' } }
  assert.equal((await append(c, 1, 'intent', retry)).status, 200, 'the replacement of a rejected (not marked failed) attempt')
  assert.equal((await append(c, 1, 'sent', { txId: tx(3), outcome: 'rejected', reason: 'still underpriced' })).status, 200)
  assert.equal((await append(c, 1, 'stopped', { reason: 'operator' })).status, 200)
  assert.ok(c.api.registry.ledgerOf(await c.api.registry.load(JOB), 'eth').inFlight > 0n, 'the rejected claims keep counting')
  const clawC = { ...ethClawback(9, CLAWBACK_TO, '1000'), eth: { ...(ethClawback(9, CLAWBACK_TO, '1000').eth as object), nonce: 2 } }
  const rC = await append(c, 1, 'clawback-intent', clawC)
  assert.equal(rC.status, 200, rC.text)
})

// ---- PF-S fix round 5 (R34-1): the stop latch, against the real gate (probes P1, P1b, P1d of re-review round 3+4)

// A chain STOPPED by the executor itself with its attempt open (Ctrl-C, the page's Stop: no stop request held), then a later executor
// that takes a lease after the old one lapsed.
async function stoppedOpen(t: { after(fn: () => Promise<void>): void }, o: { request?: boolean } = {}): Promise<{ a: TestApi; gen: number }> {
  const a = await running(t)
  assert.equal((await append(a, 1, 'intent', intent(1))).status, 200)
  assert.equal((await append(a, 1, 'sent', { txId: tx(1), outcome: 'unknown', reason: 'timeout' })).status, 200)
  // the operator's Stop (its request first), journaled by the executor (R79b: with its code; a Ctrl-C is a detach and journals nothing).
  // request: false — a stop journaled with no request held (P1's premise; final round: such an operator-stop is not taken on trust)
  if (o.request !== false) assert.equal((await call(a.port, { path: `/jobs/${JOB}/stop`, body: { chain: 'eth' } })).status, 200)
  assert.equal((await append(a, 1, 'stopped', { reason: 'stopped by the operator (copy 1 part 1 pending at its window end)', code: 'operator-stop' })).status, 200)
  a.clock.advance(LEASE_TTL_MS + 1)
  const g = await lease(a, 'acquire', 'browser', undefined, 'eth', 'local', JOB)
  assert.equal(g.status, 200, g.text)
  return { a, gen: (g.json as { gen: number }).gen }
}
const chainOf = async (a: TestApi): Promise<{ phase: string; stopLatched?: boolean; stopRequested: boolean }> =>
  ((await call(a.port, { path: `/jobs/${JOB}` })).json as { state: { chains: { eth: { phase: string; stopLatched?: boolean; stopRequested: boolean } } } }).state.chains.eth

test('PF-S fix round 5 (R34-1, P1 / P1d): a journaled stop is final for an executor — stuck, then resumed / paused are refused (job.state), adopted keeps it STOPPED, and the next copy and a bump are refused intent.after-stop', async (t) => {
  const { a, gen } = await stoppedOpen(t, { request: false })
  assert.deepEqual([(await chainOf(a)).phase, (await chainOf(a)).stopLatched, (await chainOf(a)).stopRequested], ['STOPPED', true, false])
  // evidence about the existing attempt is taken: stuck (STUCK over STOPPED)
  assert.equal((await append(a, gen, 'stuck', { txId: tx(1), reason: 'unseen' })).status, 200)
  assert.equal((await chainOf(a)).phase, 'STUCK')
  // the revival: refused while latched, whatever the overlay
  for (const type of ['resumed', 'paused', 'drained', 'copies-done', 'copy-built']) {
    const data = type === 'drained' ? { balance: '1', nextCost: '2', copy: 2 } : type === 'copies-done' ? { copies: 1 } : type === 'copy-built' ? { copy: 2, parts: 1, bytes: [10], tight: false, level: 0 } : { reason: 'executor' }
    const r = await append(a, gen, type, data)
    assert.deepEqual([r.status, guardOf(r)], [409, 'job.state'], `${type}: ${r.text}`)
  }
  assert.equal((await append(a, gen, 'reconcile', { txId: tx(1), outcome: 'adopted' })).status, 200)   // clears the stuck flag
  assert.deepEqual([(await chainOf(a)).phase, (await chainOf(a)).stopLatched], ['STOPPED', true], 'still STOPPED, still latched')
  // the identical bytes of the open attempt are still re-ticketed (the watch-only rebroadcast)
  assert.equal((await ticket(a, gen, tx(1))).status, 200)
  // under the STUCK overlay too, no job intent (the latch, not the overlaid phase, decides)
  const st2 = await append(a, gen, 'stuck', { txId: tx(1), reason: 'unseen again' })
  assert.equal(st2.status, 200, st2.text)
  assert.equal((await chainOf(a)).phase, 'STUCK')
  assert.equal(guardOf(await append(a, gen, 'intent', intent(3, 2))), 'intent.after-stop')
  // P1: the next copy; P1d: a fee bump of the attempt at its nonce — refused, no ticket
  const bump = { ...intent(2), copy: 1, attempt: 2, replaces: tx(1), eth: { ...(intent(1).eth as object), maxFee: '2250013501', tip: '13501' } }
  for (const [why, data] of [['the next copy', intent(3, 2)], ['a bump at its nonce', bump]] as const) {
    const r = await append(a, gen, 'intent', data)
    assert.deepEqual([r.status, guardOf(r)], [409, 'intent.after-stop'], `${why}: ${r.text}`)
    assert.ok(!r.text.includes('vt-ticket'), why)
  }
  // the executor cannot clear the latch itself: resume-requested is the operator's (an API event), refused on the events route
  const own = await append(a, gen, 'resume-requested', { chain: 'eth' })
  assert.equal(own.status >= 400, true, own.text)
  assert.equal((await chainOf(a)).stopLatched, true)
})

test('PF-S fix round 5 (R34-1, P1b): the OPERATOR\'s resume (POST /jobs/:id/resume) clears the latch — only then does the chain reopen; with a stop request held as well, both must be lifted by that one route', async (t) => {
  const { a, gen } = await stoppedOpen(t)
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/stop`, body: { chain: 'eth' } })).status, 200)   // a stop request on top
  // (R79b: no `stuck` here — a stuck attempt makes the stop FINAL, and the operator's resume would be refused: resume.final-stop)
  assert.equal(guardOf(await append(a, gen, 'resumed', { reason: 'executor' })), 'job.state')
  // the operator's resume: the request and the latch are both gone
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/resume`, body: { chain: 'eth' } })).status, 200)
  const c = await chainOf(a)
  assert.deepEqual([c.stopRequested, 'stopLatched' in c], [false, false])
  // now the executor may move it on again (intended: the operator chose to resume)
  assert.equal((await append(a, gen, 'resumed', { reason: 'executor' })).status, 200)
  assert.equal((await append(a, gen, 'reconcile', { txId: tx(1), outcome: 'adopted' })).status, 200)
  assert.equal((await chainOf(a)).phase, 'RUNNING')
  assert.equal((await append(a, gen, 'intent', intent(3, 2))).status, 200, 'the next copy after the operator\'s resume')
  // an all-chain resume (chain null) clears it too
  const b = await stoppedOpen(t)
  assert.equal((await call(b.a.port, { path: `/jobs/${JOB}/resume`, body: { chain: null } })).status, 200)
  assert.equal('stopLatched' in (await chainOf(b.a)), false)
})

test('PF-S fix round 5 (R34-1): watch-only recovery on a latched chain still works — stopped → rerun → reconcile adopted → stuck → resolve → claw-back, or close', async (t) => {
  // mark-failed → claw-back at the nonce (round 4)
  const { a, gen } = await stoppedOpen(t)
  assert.equal((await append(a, gen, 'reconcile', { txId: tx(1), outcome: 'adopted' })).status, 200)
  assert.equal((await ticket(a, gen, tx(1))).status, 200)
  assert.equal((await append(a, gen, 'stuck', { txId: tx(1), reason: 'unseen' })).status, 200)
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/chains/eth/resolve`, body: { txId: tx(1), action: 'mark-failed' } })).status, 200)
  const claw = { ...ethClawback(9, CLAWBACK_TO, '1000'), eth: { ...(ethClawback(9, CLAWBACK_TO, '1000').eth as object), nonce: 1 } }
  const cb = await append(a, gen, 'clawback-intent', claw)
  assert.equal(cb.status, 200, cb.text)
  // mark-failed → close (the operator ends the chain instead)
  const b = await stoppedOpen(t)
  assert.equal((await append(b.a, b.gen, 'reconcile', { txId: tx(1), outcome: 'adopted' })).status, 200)
  assert.equal((await append(b.a, b.gen, 'stuck', { txId: tx(1), reason: 'unseen' })).status, 200)
  assert.equal((await call(b.a.port, { path: `/jobs/${JOB}/chains/eth/resolve`, body: { txId: tx(1), action: 'mark-failed' } })).status, 200)
  const cl = await call(b.a.port, { path: `/jobs/${JOB}/close`, body: { chain: 'eth' } })
  assert.equal(cl.status, 200, cl.text)
  assert.equal((await chainOf(b.a)).phase, 'DONE')
  // it lands instead: included + readback on the latched chain; then close
  const c = await stoppedOpen(t)
  assert.equal((await append(c.a, c.gen, 'reconcile', { txId: tx(1), outcome: 'adopted' })).status, 200)
  assert.equal((await append(c.a, c.gen, 'included', { txId: tx(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '1000', ms: 1 })).status, 200)
  assert.equal((await append(c.a, c.gen, 'readback', { txId: tx(1), ok: true, detail: 'byte-equal' })).status, 200)
  assert.deepEqual([(await chainOf(c.a)).phase, (await chainOf(c.a)).stopLatched], ['STOPPED', true])
  assert.equal((await call(c.a.port, { path: `/jobs/${JOB}/close`, body: { chain: 'eth' } })).status, 200)
})

test('PF-S fix round 5 (R34-2): a marked-failed nonce stays blocked for job sends whatever events follow — an `adopted` of it is refused (event.attempt), and no later line clears the ledger flag', async (t) => {
  const a = await running(t)
  const d1 = intent(1)
  for (const [type, data] of [['intent', d1], ['sent', { txId: tx(1), outcome: 'unknown', reason: 'timeout' }], ['stuck', { txId: tx(1), reason: 'unseen' }]] as const) {
    assert.equal((await append(a, 1, type, data)).status, 200, type)
  }
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/chains/eth/resolve`, body: { txId: tx(1), action: 'mark-failed' } })).status, 200)
  const fresh = { ...intent(2), copy: 1, attempt: 2, eth: { ...(d1.eth as object) } }
  const bumpIt = { ...fresh, txId: tx(3), replaces: tx(1), eth: { ...(d1.eth as object), maxFee: '2250013501', tip: '13501' } }
  const blocked = async (when: string): Promise<void> => {
    for (const [why, data] of [['a fresh attempt at n', fresh], ['a bump naming it', bumpIt]] as const) {
      const r = await append(a, 1, 'intent', data)
      assert.deepEqual([r.status, guardOf(r)], [400, 'event.family'], `${when}: ${why}: ${r.text}`)
    }
  }
  await blocked('after mark-failed')
  // whatever the executor journals about it next: refused (it is not open), or taken without effect on the flag
  for (const [type, data] of [['reconcile', { txId: tx(1), outcome: 'adopted' }], ['sent', { txId: tx(1), outcome: 'accepted', reason: null }],
    ['stuck', { txId: tx(1), reason: 'again' }], ['reconcile', { txId: tx(1), outcome: 'unknown' }]] as const) {
    const r = await append(a, 1, type, data)
    if (type === 'reconcile' && (data as unknown as { outcome: string }).outcome === 'adopted') assert.deepEqual([r.status, guardOf(r)], [400, 'event.attempt'], r.text)
    await blocked(`after ${type} ${JSON.stringify(data).slice(0, 40)} (${r.status})`)
  }
  assert.equal(a.api.registry.ledgerOf(await a.api.registry.load(JOB), 'eth').byTx.get(tx(1))!.markedFailed, true)
})

// ---- PF-S fix round 6: no executor event moves a settled BASE again (DRAINED, COPIES_DONE, a latched STOPPED), STUCK overlay or not

const PHASE_MOVES: ReadonlyArray<[string, Record<string, unknown>]> = [
  ['resumed', { reason: 'executor' }], ['paused', { reason: 'executor' }], ['drained', { balance: '1', nextCost: '2', copy: 3 }],
  ['copies-done', { copies: 1 }], ['stopped', { reason: 'executor' }], ['copy-built', { copy: 3, parts: 1, bytes: [10], tight: false, level: 0 }],
]
const solChainOf = async (a: TestApi, id: string): Promise<{ phase: string; stuckBase?: string }> =>
  ((await call(a.port, { path: `/jobs/${id}` })).json as { state: { chains: { sol: { phase: string; stuckBase?: string } } } }).state.chains.sol

test('PF-S fix round 6: the P1 revive against a DRAINED base (its attempt still open) — stuck, then every phase event refused (job.state), adopted keeps DRAINED, the next copy and a bump refused', async (t) => {
  const a = await running(t)
  for (const [type, data] of [['intent', intent(1)], ['sent', { txId: tx(1), outcome: 'unknown', reason: 'timeout' }],
    ['drained', { balance: '1', nextCost: '2', copy: 2 }]] as const) assert.equal((await append(a, 1, type, data)).status, 200, type)
  a.clock.advance(LEASE_TTL_MS + 1)
  const g = await lease(a, 'acquire', 'browser', undefined, 'eth', 'local', JOB)
  assert.equal(g.status, 200, g.text)
  const gen = (g.json as { gen: number }).gen
  assert.equal((await append(a, gen, 'stuck', { txId: tx(1), reason: 'unseen' })).status, 200)
  const st = (await call(a.port, { path: `/jobs/${JOB}` })).json as { state: { chains: { eth: { phase: string; stuckBase?: string } } } }
  assert.deepEqual([st.state.chains.eth.phase, st.state.chains.eth.stuckBase], ['STUCK', 'DRAINED'], 'the base under the overlay is shown')
  for (const [type, data] of PHASE_MOVES) {
    const r = await append(a, gen, type, data)
    assert.deepEqual([r.status, guardOf(r)], [409, 'job.state'], `${type} on STUCK over DRAINED: ${r.text}`)
  }
  assert.equal((await append(a, gen, 'reconcile', { txId: tx(1), outcome: 'adopted' })).status, 200)
  assert.equal((await chainOf(a)).phase, 'DRAINED', 'adopted clears the overlay; the base is still DRAINED')
  for (const [type, data] of PHASE_MOVES) assert.equal(guardOf(await append(a, gen, type, data)), 'job.state', `${type} on DRAINED`)
  const bump = { ...intent(2), copy: 1, attempt: 2, replaces: tx(1), eth: { ...(intent(1).eth as object), maxFee: '2250013501', tip: '13501' } }
  for (const [why, data] of [['the next copy', intent(3, 2)], ['a bump at its nonce', bump]] as const) {
    const r = await append(a, gen, 'intent', data)
    assert.deepEqual([r.status, guardOf(r)], [409, 'job.state'], `${why}: ${r.text}`)
    assert.ok(!r.text.includes('vt-ticket'), why)
  }
  // watch-only recovery unchanged: the open bytes re-ticketed, stuck, mark-failed, then the claw-back at its nonce
  assert.equal((await ticket(a, gen, tx(1))).status, 200)
  assert.equal((await append(a, gen, 'stuck', { txId: tx(1), reason: 'unseen again' })).status, 200)
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/chains/eth/resolve`, body: { txId: tx(1), action: 'mark-failed' } })).status, 200)
  const claw = { ...ethClawback(9, CLAWBACK_TO, '1000'), eth: { ...(ethClawback(9, CLAWBACK_TO, '1000').eth as object), nonce: 1 } }
  const cb = await append(a, gen, 'clawback-intent', claw)
  assert.equal(cb.status, 200, cb.text)
})

test('PF-S fix round 6: the P1 revive against a COPIES_DONE base (sol, copies mode) — stuck, then every phase event and the next part refused; adopted keeps COPIES_DONE', async (t) => {
  const s = await api(t, { jobs: [JOB2_INPUT] })
  await armed(s, JOB2, ['sol'])
  assert.equal((await lease(s, 'acquire', 'cli', undefined, 'sol', 'local', JOB2)).status, 200)
  const ev = (type: string, data: unknown) => append(s, 1, type, data, 'sol', 'local', JOB2)
  for (const [type, data] of [['intent', solIntent(1)], ['sent', { txId: solIntent(1).txId, outcome: 'unknown', reason: 'timeout' }],
    ['copies-done', { copies: 3 }]] as const) assert.equal((await ev(type, data)).status, 200, type)
  assert.equal((await ev('stuck', { txId: solIntent(1).txId, reason: 'unseen' })).status, 200)
  assert.deepEqual([(await solChainOf(s, JOB2)).phase, (await solChainOf(s, JOB2)).stuckBase], ['STUCK', 'COPIES_DONE'])
  for (const [type, data] of PHASE_MOVES) {
    const r = await ev(type, data)
    assert.deepEqual([r.status, guardOf(r)], [409, 'job.state'], `${type} on STUCK over COPIES_DONE: ${r.text}`)
  }
  assert.equal((await ev('reconcile', { txId: solIntent(1).txId, outcome: 'adopted' })).status, 200)
  assert.equal((await solChainOf(s, JOB2)).phase, 'COPIES_DONE')
  const r = await ev('intent', solIntent(2, 2))
  assert.deepEqual([r.status, guardOf(r)], [409, 'job.state'], r.text)
  assert.equal(guardOf(await ev('resumed', { reason: 'executor' })), 'job.state')
})

test('PF-S fix round 6: a drained lane topped up later cannot be resumed by an executor — funds are recorded, but resumed / paused / copy-built and the next copy are refused; the claw-back is the way out', async (t) => {
  const { a, id } = await drained(t)
  assert.equal((await append(a, 1, 'funds', { balance: '90000000000000000000', affordable: true, nextCopyCost: '1' }, 'eth', 'local', id)).status, 200, 'the top-up is recorded')
  for (const [type, data] of PHASE_MOVES) assert.equal(guardOf(await append(a, 1, type, data, 'eth', 'local', id)), 'job.state', `${type} after a top-up`)
  const next = await append(a, 1, 'intent', intent(2, 2), 'eth', 'local', id)
  assert.deepEqual([next.status, guardOf(next)], [409, 'job.state'], next.text)
  assert.equal((await chainOf(a)).phase, 'DRAINED')
  assert.equal((await append(a, 1, 'clawback-intent', ethClawback(7, CLAWBACK_TO, '1000'), 'eth', 'local', id)).status, 200)
})

test('PF-S fix round 6: a running chain still moves — stuck over RUNNING takes paused / resumed (base RUNNING), and a STOPPED chain the operator resumed reopens', async (t) => {
  const a = await running(t)
  for (const [type, data] of [['intent', intent(1)], ['sent', { txId: tx(1), outcome: 'unknown', reason: 'timeout' }], ['stuck', { txId: tx(1), reason: 'unseen' }]] as const) {
    assert.equal((await append(a, 1, type, data)).status, 200, type)
  }
  for (const type of ['paused', 'resumed']) assert.equal((await append(a, 1, type, { reason: 'executor' })).status, 200, `${type} on STUCK over RUNNING`)
  assert.equal((await append(a, 1, 'reconcile', { txId: tx(1), outcome: 'adopted' })).status, 200)   // (R79b: a stuck attempt would make the stop FINAL)
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/stop`, body: { chain: 'eth' } })).status, 200)   // the operator's Stop: its request first
  assert.equal((await append(a, 1, 'stopped', { reason: 'stopped by the operator', code: 'operator-stop' })).status, 200, 'a stop of a running chain')
  assert.equal(guardOf(await append(a, 1, 'resumed', { reason: 'executor' })), 'job.state', 'latched')
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/resume`, body: { chain: 'eth' } })).status, 200)
  assert.equal((await append(a, 1, 'resumed', { reason: 'executor' })).status, 200, 'the operator resumed it: it reopens')
  assert.equal((await chainOf(a)).phase, 'RUNNING')
})

// ---- R79b (Lane S): the resume gate

test('R79b (M-4): an executor\'s `resumed` on a STOPPED chain the operator resumed is refused while a NEW stop request is pending; the next operator resume lets it through', async (t) => {
  const a = await running(t)                                                   // ARMED, released, leased (gen 1); no transaction yet
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/stop`, body: { chain: 'eth' } })).status, 200)   // the API journals `stopped` itself
  assert.deepEqual([(await chainOf(a)).phase, (await chainOf(a)).stopLatched], ['STOPPED', true])
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/resume`, body: { chain: 'eth' } })).status, 200)
  assert.equal('stopLatched' in (await chainOf(a)), false, 'the operator resumed it: unlatched, still STOPPED until the executor reopens it')
  // the operator stops it again before the executor reopened it: a stop request is pending
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/stop`, body: { chain: 'eth' } })).status, 200)
  assert.deepEqual([(await chainOf(a)).phase, (await chainOf(a)).stopRequested], ['STOPPED', true])
  for (const [type, data] of [['resumed', { reason: 'executor' }], ['paused', { reason: 'executor' }], ['copy-built', { copy: 1, parts: 1, bytes: [10], tight: false, level: 0 }]] as const) {
    const r = await append(a, 1, type, data)
    assert.deepEqual([r.status, guardOf(r)], [409, 'job.state'], `${type}: ${r.text}`)
    assert.match(r.text, /stop request is pending/, type)
  }
  assert.equal((await chainOf(a)).phase, 'STOPPED')
  // the operator's next resume lets the reopen through
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/resume`, body: { chain: 'eth' } })).status, 200)
  const r = await append(a, 1, 'resumed', { reason: 'executor' })
  assert.equal(r.status, 200, r.text)
  assert.equal((await chainOf(a)).phase, 'RUNNING')
})

test('R79b: the resume route answers { seq, resumed, refused }; a RESUMABLE stop (the API\'s operator-stop) is lifted; a FINAL one (a FINAL code, a missing code, or a FINAL fact) is refused resume.final-stop with the reason and the way out, and stays latched', async (t) => {
  type Answer = { seq: number; resumed: string[]; refused: Array<{ chain: string; guard: string; message: string }> }
  const resume = (a: TestApi, chain: string | null, id = JOB) => call(a.port, { path: `/jobs/${id}/resume`, body: { chain } })
  // nothing stopped: the request is cleared, the answer lists the chain
  const a = await running(t)
  const r0 = await resume(a, 'eth')
  assert.equal(r0.status, 200, r0.text)
  assert.deepEqual(Object.keys(r0.json as object), ['seq', 'resumed', 'refused'])
  assert.deepEqual([(r0.json as Answer).resumed, (r0.json as Answer).refused], [['eth'], []])
  // a RESUMABLE stop: the API's own stop of a chain that never started journals code operator-stop
  const b = await running(t)
  assert.equal((await call(b.port, { path: `/jobs/${JOB}/stop`, body: { chain: 'eth' } })).status, 200)
  const stopLine = journalLines(b).filter((l) => l.type === 'stopped').at(-1)!
  assert.deepEqual(stopLine.data, { reason: 'stopped before any transaction', code: 'operator-stop' })
  const cs = await chainOf(b) as { stopClass?: string; stopCode?: string; stopLatched?: boolean }
  assert.deepEqual([cs.stopClass, cs.stopCode, cs.stopLatched], ['resumable', 'operator-stop', true])
  const r1 = await resume(b, 'eth')
  assert.equal(r1.status, 200, r1.text)
  assert.deepEqual([(r1.json as Answer).resumed, (r1.json as Answer).refused], [['eth'], []])
  assert.equal('stopLatched' in (await chainOf(b)), false)
  // FINAL: a FINAL code (readback-mismatch), and a stop with no code (a journal from before R79b: fail closed)
  for (const [why, data, pattern] of [
    ['a FINAL code', { reason: 'readback mismatch on copy 1 part 1 — lane stopped (fail closed)', code: 'readback-mismatch' }, /does not read back.*\(readback-mismatch\)/],
    ['no code', { reason: 'stopped by the operator' }, /carries no reason code this build knows/],
  ] as const) {
    const c = await running(t)
    assert.equal((await append(c, 1, 'stopped', data)).status, 200, why)
    assert.equal(((await chainOf(c)) as { stopClass?: string }).stopClass, 'final', why)
    const n = journalLines(c).length
    const r = await resume(c, 'eth')
    assert.deepEqual([r.status, guardOf(r)], [409, 'resume.final-stop'], `${why}: ${r.text}`)
    const msg = (r.json as { error: { message: string } }).error.message
    assert.match(msg, pattern, why)
    assert.match(msg, /claw back what is left \(vt job clawback.*or close the chain \(vt job close\), then make a new job/, why)
    assert.equal(journalLines(c).length, n, `${why}: nothing journaled`)
    assert.equal(((await chainOf(c)) as { stopLatched?: boolean }).stopLatched, true, `${why}: still latched`)
    // an all-chain resume of a job whose only chain is FINAL: nothing resumed, 409 too
    assert.deepEqual([(await resume(c, null)).status, guardOf(await resume(c, null))], [409, 'resume.final-stop'])
    // the way out stays open: a claw-back (nothing in flight on a STOPPED chain)
    assert.equal((await append(c, 1, 'clawback-intent', ethClawback(7, CLAWBACK_TO, '1000'))).status, 200, `${why}: the claw-back`)
  }
})

test('R79b (M-9 b/c): FINAL facts override a resumable code — a resolved mark-failed attempt, or a copy that did not reassemble; a resume of every chain resumes the RESUMABLE ones and lists the FINAL ones', async (t) => {
  type Answer = { seq: number; resumed: string[]; refused: Array<{ chain: string; guard: string; message: string }> }
  // mark-failed (M-9 c): stuck → resolve mark-failed → the executor stops with operator-stop: FINAL all the same
  const a = await running(t)
  for (const [type, data] of [['intent', intent(1)], ['sent', { txId: tx(1), outcome: 'unknown', reason: 'timeout' }], ['stuck', { txId: tx(1), reason: 'unseen' }]] as const) {
    assert.equal((await append(a, 1, type, data)).status, 200, type)
  }
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/chains/eth/resolve`, body: { txId: tx(1), action: 'mark-failed' } })).status, 200)
  assert.equal((await append(a, 1, 'stopped', { reason: 'stopped by the operator', code: 'operator-stop' })).status, 200)
  const r = await call(a.port, { path: `/jobs/${JOB}/resume`, body: { chain: 'eth' } })
  assert.deepEqual([r.status, guardOf(r)], [409, 'resume.final-stop'], r.text)
  assert.match(r.text, /resolved mark-failed/)
  // reassembly (M-9 b): a copy that did not reassemble, then an operator-stop: FINAL
  const b = await running(t)
  for (const [type, data] of [['intent', intent(1)], ['sent', { txId: tx(1), outcome: 'accepted', reason: null }],
    ['included', { txId: tx(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '1000', ms: 1 }], ['readback', { txId: tx(1), ok: true, detail: 'x' }],
    ['reassembled', { copy: 1, ok: false, sha256: 'ab'.repeat(32) }], ['stopped', { reason: 'stopped by the operator', code: 'operator-stop' }]] as const) {
    assert.equal((await append(b, 1, type, data)).status, 200, type)
  }
  const rb = await call(b.port, { path: `/jobs/${JOB}/resume`, body: { chain: 'eth' } })
  assert.deepEqual([rb.status, guardOf(rb)], [409, 'resume.final-stop'], rb.text)
  assert.match(rb.text, /did not reassemble/)
  // a resume of every chain on a two-chain job: eth FINAL (spend-cap), sol RESUMABLE (the API's operator-stop)
  const c = await api(t, { jobs: [JOB2_INPUT] })
  await armed(c, JOB2, ['eth', 'sol'])
  assert.equal((await lease(c, 'acquire', 'cli', undefined, 'eth', 'local', JOB2)).status, 200)
  assert.equal((await append(c, 1, 'stopped', { reason: 'the armed cap cannot cover the next copy', code: 'spend-cap' }, 'eth', 'local', JOB2)).status, 200)
  assert.equal((await call(c.port, { path: `/jobs/${JOB2}/stop`, body: { chain: 'sol' } })).status, 200)
  const n = journalLines(c, JOB2).length
  const all = await call(c.port, { path: `/jobs/${JOB2}/resume`, body: { chain: null } })
  assert.equal(all.status, 200, all.text)
  const ans = all.json as Answer
  assert.deepEqual(ans.resumed, ['sol'])
  assert.deepEqual(ans.refused.map((x) => [x.chain, x.guard]), [['eth', 'resume.final-stop']])
  assert.match(ans.refused[0].message, /^eth is stopped for good: the armed spend cap cannot cover the next copy.*\(spend-cap\) — resume is refused; claw back/)
  const added = journalLines(c, JOB2).slice(n)
  assert.deepEqual(added.map((l) => [l.type, l.chain, (l.data as { chain: unknown }).chain]), [['resume-requested', 'sol', 'sol']], 'one resume-requested, for sol only')
  assert.equal(ans.seq, added[0].seq)
  const st = ((await call(c.port, { path: `/jobs/${JOB2}` })).json as { state: { chains: Record<string, { stopLatched?: boolean; stopClass?: string }> } }).state.chains
  assert.deepEqual([st.eth.stopLatched, st.eth.stopClass, 'stopLatched' in st.sol], [true, 'final', false])
})

// ---- Final round (R79b review m-4, m-5): the API does not take the executor's stop code on trust; FINAL is never reopened

test('Final round (m-4): an executor that journals operator-stop after a failed readback cannot get the chain resumed — even after it reports the readback ok again (the API\'s fact is sticky)', async (t) => {
  for (const overwrite of [false, true]) {
    const a = await running(t)
    for (const [type, data] of [['intent', intent(1)], ['sent', { txId: tx(1), outcome: 'accepted', reason: null }],
      ['included', { txId: tx(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '1000', ms: 1 }], ['readback', { txId: tx(1), ok: false, detail: 'other bytes' }]] as const) {
      assert.equal((await append(a, 1, type, data)).status, 200, type)
    }
    if (overwrite) {
      const r = await append(a, 1, 'readback', { txId: tx(1), ok: true, detail: 'byte-equal (a compromised executor)' })
      assert.equal(r.status, 200, `a second readback is taken: ${r.text}`)
      assert.equal(((await call(a.port, { path: `/jobs/${JOB}` })).json as { state: { chains: { eth: { txs: Array<{ readback: boolean | null }> } } } }).state.chains.eth.txs[0].readback, true, 'the reduced readback now says ok')
    }
    // the operator's Stop is requested (so the code looks trusted), and the executor journals operator-stop instead of readback-mismatch
    assert.equal((await call(a.port, { path: `/jobs/${JOB}/stop`, body: { chain: 'eth' } })).status, 200)
    assert.equal((await append(a, 1, 'stopped', { reason: 'stopped by the operator', code: 'operator-stop' })).status, 200)
    const r = await call(a.port, { path: `/jobs/${JOB}/resume`, body: { chain: 'eth' } })
    assert.deepEqual([r.status, guardOf(r)], [409, 'resume.final-stop'], `overwrite ${overwrite}: ${r.text}`)
    assert.match(r.text, /did not read back|does not read back/, `overwrite ${overwrite}`)
    assert.equal((await call(a.port, { path: `/jobs/${JOB}/resume`, body: { chain: null } })).status, 409)
  }
})

test('Final round (m-4): an executor\'s operator-stop with no stop request held is not taken on trust (FINAL); a reassembly that failed stays a fact after a later ok', async (t) => {
  // no stop request: the operator's Stop always journals stop-requested first
  const a = await running(t)
  assert.equal((await append(a, 1, 'stopped', { reason: 'stopped by the operator', code: 'operator-stop' })).status, 200)
  const r = await call(a.port, { path: `/jobs/${JOB}/resume`, body: { chain: 'eth' } })
  assert.deepEqual([r.status, guardOf(r)], [409, 'resume.final-stop'], r.text)
  assert.match(r.text, /no stop request was held/)
  // with the request held, the same stop is resumable (the control; a landed part, so the stop route only requests)
  const b = await running(t)
  for (const [type, data] of [['intent', intent(1)], ['sent', { txId: tx(1), outcome: 'accepted', reason: null }],
    ['included', { txId: tx(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '1000', ms: 1 }], ['readback', { txId: tx(1), ok: true, detail: 'x' }]] as const) {
    assert.equal((await append(b, 1, type, data)).status, 200, type)
  }
  assert.equal((await call(b.port, { path: `/jobs/${JOB}/stop`, body: { chain: 'eth' } })).status, 200)
  assert.equal((await append(b, 1, 'stopped', { reason: 'stopped by the operator', code: 'operator-stop' })).status, 200)
  const rb0 = await call(b.port, { path: `/jobs/${JOB}/resume`, body: { chain: 'eth' } })
  assert.equal(rb0.status, 200, rb0.text)
  // a reassembly that failed, then reported ok (the reducer keeps the later entry): still FINAL for the API
  const c = await running(t)
  for (const [type, data] of [['intent', intent(1)], ['sent', { txId: tx(1), outcome: 'accepted', reason: null }],
    ['included', { txId: tx(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '1000', ms: 1 }], ['readback', { txId: tx(1), ok: true, detail: 'x' }],
    ['reassembled', { copy: 1, ok: false, sha256: 'ab'.repeat(32) }], ['reassembled', { copy: 1, ok: true, sha256: 'cd'.repeat(32) }]] as const) {
    assert.equal((await append(c, 1, type, data)).status, 200, type)
  }
  assert.equal((await call(c.port, { path: `/jobs/${JOB}/stop`, body: { chain: 'eth' } })).status, 200)
  assert.equal((await append(c, 1, 'stopped', { reason: 'stopped by the operator', code: 'operator-stop' })).status, 200)
  const rc = await call(c.port, { path: `/jobs/${JOB}/resume`, body: { chain: 'eth' } })
  assert.deepEqual([rc.status, guardOf(rc)], [409, 'resume.final-stop'], rc.text)
  assert.match(rc.text, /did not reassemble/)
})

test('Final round (m-5): the gate refuses an executor\'s `resumed` (and every phase event but `stopped`) on an UNLATCHED FINAL stop — a pre-R79b journal with a resume in it, or a FINAL fact that appeared after the resume', async (t) => {
  // (a) a stop without a code, then a resume-requested an older API wrote (unlatched, FINAL: no code)
  const a = await running(t)
  assert.equal((await append(a, 1, 'stopped', { reason: 'stopped by the operator' })).status, 200)
  await a.api.registry.journalOf(JOB).append({ chain: 'eth', by: 'api', gen: null, type: 'resume-requested', data: { chain: 'eth' } })
  const st = (await chainOf(a)) as { phase: string; stopLatched?: boolean; stopClass?: string }
  assert.deepEqual([st.phase, 'stopLatched' in st, st.stopClass], ['STOPPED', false, 'final'])
  for (const [type, data] of [['resumed', { reason: 'an older executor' }], ['paused', { reason: 'x' }], ['copy-built', { copy: 1, parts: 1, bytes: [10], tight: false, level: 0 }]] as const) {
    const r = await append(a, 1, type, data)
    assert.deepEqual([r.status, guardOf(r)], [409, 'job.state'], `${type}: ${r.text}`)
    assert.match(r.text, /its stop is FINAL/, type)
  }
  assert.equal((await chainOf(a)).phase, 'STOPPED')
  // (b) a resumable stop resumed by the operator; then the takeover's reconcile journals `stuck`, the operator marks it failed: FINAL
  const { a: b, gen } = await stoppedOpen(t)
  assert.equal((await call(b.port, { path: `/jobs/${JOB}/resume`, body: { chain: 'eth' } })).status, 200)
  assert.equal((await append(b, gen, 'reconcile', { txId: tx(1), outcome: 'adopted' })).status, 200)
  assert.equal((await append(b, gen, 'stuck', { txId: tx(1), reason: 'unseen' })).status, 200)
  assert.equal((await call(b.port, { path: `/jobs/${JOB}/chains/eth/resolve`, body: { txId: tx(1), action: 'mark-failed' } })).status, 200)
  const rb = await append(b, gen, 'resumed', { reason: 'an older executor' })
  assert.deepEqual([rb.status, guardOf(rb)], [409, 'job.state'], rb.text)
  // the way out is open: the claw-back at the nonce (round 4)
  const claw = { ...ethClawback(9, CLAWBACK_TO, '1000'), eth: { ...(ethClawback(9, CLAWBACK_TO, '1000').eth as object), nonce: 1 } }
  assert.equal((await append(b, gen, 'clawback-intent', claw)).status, 200)
  // the control: an unlatched RESUMABLE stop does reopen
  const { a: c, gen: g2 } = await stoppedOpen(t)
  assert.equal((await call(c.port, { path: `/jobs/${JOB}/resume`, body: { chain: 'eth' } })).status, 200)
  assert.equal((await append(c, g2, 'resumed', { reason: 'the operator resumed it' })).status, 200)
})

test('Projection fix (M5d issue 1): GET /jobs/:id shows the API\'s stop verdict — stopClass equals what the resume route decides in each stricter case; stopCode stays as journaled', async (t) => {
  const land = [['intent', intent(1)], ['sent', { txId: tx(1), outcome: 'accepted', reason: null }],
    ['included', { txId: tx(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '1000', ms: 1 }]] as const
  const cases: Array<[string, boolean, ReadonlyArray<readonly [string, unknown]>, 'final' | 'resumable']> = [
    ['a failed readback reported ok again (sticky)', true, [...land, ['readback', { txId: tx(1), ok: false, detail: 'other bytes' }], ['readback', { txId: tx(1), ok: true, detail: 'ok (again)' }]], 'final'],
    ['a failed reassembly reported ok again (sticky)', true, [...land, ['readback', { txId: tx(1), ok: true, detail: 'x' }], ['reassembled', { copy: 1, ok: false, sha256: 'ab'.repeat(32) }],
      ['reassembled', { copy: 1, ok: true, sha256: 'cd'.repeat(32) }]], 'final'],
    ['an operator-stop with no stop request held (untrusted)', false, [...land, ['readback', { txId: tx(1), ok: true, detail: 'x' }]], 'final'],
    ['the control: an operator-stop after a stop request', true, [...land, ['readback', { txId: tx(1), ok: true, detail: 'x' }]], 'resumable'],
  ]
  for (const [why, request, lines, want] of cases) {
    const a = await running(t)
    for (const [type, data] of lines) assert.equal((await append(a, 1, type, data)).status, 200, `${why}: ${type}`)
    if (request) assert.equal((await call(a.port, { path: `/jobs/${JOB}/stop`, body: { chain: 'eth' } })).status, 200)
    assert.equal((await append(a, 1, 'stopped', { reason: 'stopped by the operator', code: 'operator-stop' })).status, 200, why)
    const cs = ((await call(a.port, { path: `/jobs/${JOB}` })).json as { state: { chains: { eth: { stopClass?: string; stopCode?: string } } } }).state.chains.eth
    assert.deepEqual([cs.stopClass, cs.stopCode], [want, 'operator-stop'], `${why}: the projected class, the journaled code`)
    // the resume route decides the same
    const r = await call(a.port, { path: `/jobs/${JOB}/resume`, body: { chain: 'eth' } })
    assert.equal(r.status, want === 'final' ? 409 : 200, `${why}: ${r.text}`)
    if (want === 'final') assert.equal(guardOf(r), 'resume.final-stop', why)
    // core's own class stays the looser one (the projection is the API's, not a change to core)
    const core = (await a.api.registry.load(JOB), (a.api.registry as unknown as { jobState(id: string): { state(): { chains: { eth: { stopClass?: string } } } } }).jobState(JOB).state().chains.eth.stopClass)
    if (want === 'final' && r.status === 409) assert.equal(core, 'resumable', `${why}: core alone says resumable`)
  }
})

test('m-a (M5d review): once FINAL, a STOPPED chain stays FINAL — a later `stopped` with a resumable code is refused (operator-stop with a request held, or start-check), and one journaled past the gate never lowers the verdict; resume and `resumed` stay refused', async (t) => {
  // S1: a code-less stop (a journal from before R79b), already resumed by an older API (unlatched, FINAL)
  const oldStopResumed = async () => {
    const a = await running(t)
    assert.equal((await append(a, 1, 'stopped', { reason: 'stopped by the operator' })).status, 200)
    await a.api.registry.journalOf(JOB).append({ chain: 'eth', by: 'api', gen: null, type: 'resume-requested', data: { chain: 'eth' } })
    const cs = (await chainOf(a)) as { phase: string; stopLatched?: boolean; stopClass?: string }
    assert.deepEqual([cs.phase, 'stopLatched' in cs, cs.stopClass], ['STOPPED', false, 'final'])
    return a
  }
  const stillFinal = async (a: TestApi, why: string, gen = 1): Promise<void> => {
    assert.equal(((await chainOf(a)) as { stopClass?: string }).stopClass, 'final', `${why}: the served class`)
    const r = await call(a.port, { path: `/jobs/${JOB}/resume`, body: { chain: 'eth' } })
    assert.deepEqual([r.status, guardOf(r)], [409, 'resume.final-stop'], `${why}: resume ${r.text}`)
    const rs = await append(a, gen, 'resumed', { reason: 'an executor' })
    assert.deepEqual([rs.status, guardOf(rs)], [409, 'job.state'], `${why}: resumed ${rs.text}`)
    assert.equal((await chainOf(a)).phase, 'STOPPED', why)
  }
  // variant 1: the operator's Stop (a request held, so the code would be trusted), then operator-stop
  const a = await oldStopResumed()
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/stop`, body: { chain: 'eth' } })).status, 200)
  const r1 = await append(a, 1, 'stopped', { reason: 'stopped by the operator', code: 'operator-stop' })
  assert.deepEqual([r1.status, guardOf(r1)], [409, 'job.state'], r1.text)
  assert.match(r1.text, /a later stop with a resumable code never lowers it/)
  await stillFinal(a, 'operator-stop with a request')
  // variant 2: start-check with no request at all
  const b = await oldStopResumed()
  const r2 = await append(b, 1, 'stopped', { reason: 'the check at the start failed', code: 'start-check' })
  assert.deepEqual([r2.status, guardOf(r2)], [409, 'job.state'], r2.text)
  await stillFinal(b, 'start-check')
  // a FINAL-coded stop is still taken (m-3's evidence and stop)
  assert.equal((await append(b, 1, 'stopped', { reason: 'readback mismatch', code: 'readback-mismatch' })).status, 200)
  // past the gate (a journal another process wrote, loaded as is): the resumable stop is in the journal and core follows its code;
  // the API's verdict, held from the FINAL stretch, does not
  const c = await api(t, { jobs: [] })
  const def = normalizeJob(JOB_INPUT, { network: 'local' }).def
  c.api.registry.messages.storeText(JOB_INPUT.message as string, def.messageSha256)
  const lines: Array<Pick<JournalEvent, 'chain' | 'by' | 'gen' | 'type' | 'data'>> = [
    { chain: 'eth', by: 'browser', gen: null, type: 'key-loaded', data: { address: KEYS.eth } },
    { chain: 'eth', by: 'browser', gen: null, type: 'funds', data: { balance: '50000000000000000', affordable: true, nextCopyCost: '25000300000000' } },
    { chain: null, by: 'api', gen: null, type: 'armed', data: { armedAt: START - 60_000, releaseAt: START - 55_000, countdownSec: 5, schedule: { order: ['eth'], offsetSec: { eth: 0 } }, caps: { eth: CAPS.eth }, sources: {} } },
    { chain: 'eth', by: 'api', gen: 1, type: 'lease-acquired', data: { gen: 1, holder: 'browser', ttlMs: 15_000 } },
    { chain: 'eth', by: 'browser', gen: 1, type: 'stopped', data: { reason: 'stopped by the operator' } },             // code-less (pre-R79b)
    { chain: 'eth', by: 'api', gen: null, type: 'resume-requested', data: { chain: 'eth' } },                          // an older API's resume
    { chain: 'eth', by: 'api', gen: null, type: 'stop-requested', data: { chain: 'eth' } },
    { chain: 'eth', by: 'browser', gen: 1, type: 'stopped', data: { reason: 'stopped by the operator', code: 'operator-stop' } },   // past the gate
    { chain: 'eth', by: 'api', gen: null, type: 'resume-requested', data: { chain: 'eth' } },
  ]
  const cid = await writeJob(c.state, def, lines)
  assert.equal(cid, JOB)
  await c.api.registry.load(JOB)
  const core = (c.api.registry as unknown as { jobState(id: string): { state(): { chains: { eth: { stopClass?: string; stopCode?: string } } } } }).jobState(JOB).state().chains.eth
  assert.deepEqual([core.stopClass, core.stopCode], ['resumable', 'operator-stop'], 'core alone follows the new code')
  c.clock.advance(LEASE_TTL_MS + 1)                                          // a later executor takes a lease
  const g = await lease(c, 'acquire', 'cli', undefined, 'eth', 'local', JOB)
  assert.equal(g.status, 200, g.text)
  await stillFinal(c, 'past the gate', (g.json as { gen: number }).gen)
  // the way out stays open: a claw-back on the STOPPED chain
  assert.equal((await append(c, (g.json as { gen: number }).gen, 'clawback-intent', ethClawback(7, CLAWBACK_TO, '1000'))).status, 200)
})

// Leases with fencing (spec §5.5): the leases.json vectors exactly, then the extras — renew at +16 s → lease.lost; after
// expiry acquire → gen + 1 with the open intents; reconcile-first; a stale gen; generations survive an API restart;
// concurrent acquires; release; the holder check.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import type { Chain, Holder, JournalEvent, OpenIntent } from '@vault-timelock/core/contracts'
import { createLeases, openIntentsFromEvents, reconciledFromEvents } from '../src/leases.ts'
import type { Leases } from '../src/leases.ts'
import { openJournal } from '../src/journal.ts'
import type { Journal } from '../src/journal.ts'
import { DEF_SHA, JOB, fakeClock, fixture, tempDir } from './helpers.ts'
import type { FakeClock } from './helpers.ts'

interface Step { at: number; op: 'acquire' | 'renew' | 'append'; holder?: Holder; gen?: number; type?: string; data?: Record<string, unknown>; expect: { grant?: unknown; guard?: string; ok?: boolean; ticket?: boolean } }
const V = fixture<{ jobId: string; chain: Chain; start: number; ttlMs: number; steps: Step[]; journalAfter: Array<[string, number | null]> }>('leases.json')

// The leases module over plain journals (the job service is not under test here): one journal per job id under
// <state>/jobs/<id>/, opened once, with its `created` line.
interface Journals { journalOf(id: string): Journal }
function journals(dir: string, clock: FakeClock): Journals {
  const open = new Map<string, Journal>()
  return {
    journalOf(id) {
      let j = open.get(id)
      if (j === undefined) { j = openJournal(join(dir, 'jobs', id), { clock }); open.set(id, j) }
      return j
    },
  }
}
interface World { clock: FakeClock; registry: Journals; leases: Leases; state: string }
async function world(t: { after(fn: () => void): void }, state?: string): Promise<World> {
  let dir = state
  if (dir === undefined) {
    const tmp = tempDir('vt-api-leases-')
    t.after(tmp.cleanup)
    dir = join(tmp.dir, 'local')
    mkdirSync(dir, { mode: 0o700 })
  }
  const clock = fakeClock(V.start)
  const registry = journals(dir, clock)
  const j = registry.journalOf(V.jobId)
  if (j.all().length === 0) await j.append({ chain: null, by: 'api', gen: null, type: 'created', data: { jobId: V.jobId, defSha256: DEF_SHA } })
  const leases = createLeases({
    clock, journalOf: registry.journalOf,
    openIntentsOf: (id, c) => openIntentsFromEvents(registry.journalOf(id).all(), c),
    reconciledOf: (id, c, gen) => reconciledFromEvents(registry.journalOf(id).all(), c, gen),
  })
  return { clock, registry, leases, state: dir }
}

// The events route's sequence, without HTTP: live gen → (send types) reconciled → append.
function append(w: World, chain: Chain, gen: number, type: string, data: Record<string, unknown>): Promise<JournalEvent> {
  return w.leases.run(V.jobId, async () => {
    const by = w.leases.assertLive(V.jobId, chain, gen)
    if (type === 'intent' || type === 'clawback-intent') w.leases.assertReconciled(V.jobId, chain, gen)
    return w.registry.journalOf(V.jobId).append({ chain, by, gen, type: type as JournalEvent['type'], data })
  })
}
async function guardOf(p: Promise<unknown>): Promise<string> {
  try { await p } catch (e) { return (e as { guardId: string }).guardId }
  assert.fail('expected a refusal')
}
const timeline = (w: World): Array<[string, number | null]> => w.registry.journalOf(V.jobId).all().map((e) => [e.type, e.gen])

test('leases.json: every step, then the journal timeline', async (t) => {
  const w = await world(t)
  for (const s of V.steps) {
    w.clock.set(V.start + s.at)
    const before = w.registry.journalOf(V.jobId).all().length
    const p = s.op === 'acquire' ? w.leases.acquire(V.jobId, V.chain, s.holder!)
      : s.op === 'renew' ? w.leases.renew(V.jobId, V.chain, s.gen!)
        : append(w, V.chain, s.gen!, s.type!, s.data!)
    const label = `${s.op} at +${s.at}`
    if (s.expect.guard !== undefined) {
      assert.equal(await guardOf(p), s.expect.guard, label)
      assert.equal(w.registry.journalOf(V.jobId).all().length, before, `${label}: a refused step journals nothing`)
    } else if (s.expect.grant !== undefined) assert.deepEqual(await p, s.expect.grant, label)
    else assert.equal(typeof (await p as JournalEvent).seq, 'number', label)
  }
  assert.deepEqual(timeline(w), V.journalAfter)
  const acquired = w.registry.journalOf(V.jobId).all().filter((e) => e.type === 'lease-acquired').map((e) => e.data)
  assert.deepEqual(acquired, [{ gen: 1, holder: 'browser', ttlMs: 15000 }, { gen: 2, holder: 'cli', ttlMs: 15000 }])
  const expired = w.registry.journalOf(V.jobId).all().find((e) => e.type === 'lease-expired')!
  assert.deepEqual([expired.by, expired.chain, expired.data], ['api', 'eth', { gen: 1 }])
})

test('acquire, acquire → lease.held (whoever asks); a renew at +16 s → lease.lost', async (t) => {
  const w = await world(t)
  assert.equal((await w.leases.acquire(JOB, 'eth', 'browser')).gen, 1)
  w.clock.advance(14_999)
  assert.equal(await guardOf(w.leases.acquire(JOB, 'eth', 'browser')), 'lease.held')
  assert.equal(await guardOf(w.leases.acquire(JOB, 'eth', 'cli')), 'lease.held')
  assert.equal((await w.leases.acquire(JOB, 'sol', 'cli')).gen, 1) // chains are independent
  w.clock.advance(1_001)
  assert.equal(await guardOf(w.leases.renew(JOB, 'eth', 1)), 'lease.lost')
})

test('renew keeps the lease alive; at exactly expiresAt it is lost; a wrong gen is lost', async (t) => {
  const w = await world(t)
  await w.leases.acquire(JOB, 'eth', 'browser')
  for (let i = 0; i < 5; i++) {
    w.clock.advance(5_000)
    assert.equal((await w.leases.renew(JOB, 'eth', 1)).expiresAt, w.clock.now() + 15_000)
  }
  assert.equal(await guardOf(w.leases.renew(JOB, 'eth', 2)), 'lease.lost')
  w.clock.advance(15_000)
  assert.equal(await guardOf(w.leases.renew(JOB, 'eth', 1)), 'lease.lost')
  assert.equal(await guardOf(w.leases.renew(JOB, 'sol', 1)), 'lease.lost') // never acquired
})

test('after expiry, acquire → gen + 1 with the open intents (the injected function), lease-expired journaled first', async (t) => {
  const w = await world(t)
  const injected: OpenIntent[] = [{ txId: '0x' + 'ab'.repeat(32), gen: 1, copy: 3, part: 2, attempt: 1 }]
  const calls: Chain[] = []
  const leases = createLeases({ clock: w.clock, journalOf: w.registry.journalOf, openIntentsOf: (_id, c) => { calls.push(c); return injected }, reconciledOf: () => new Set() })
  await leases.acquire(JOB, 'eth', 'browser')
  w.clock.advance(15_000)
  const g = await leases.acquire(JOB, 'eth', 'cli')
  assert.equal(g.gen, 2)
  assert.equal(g.holder, 'cli')
  assert.deepEqual(g.openIntents, injected)
  assert.ok(calls.every((c) => c === 'eth'))
  assert.deepEqual(timeline(w).slice(-3), [['lease-acquired', 1], ['lease-expired', 1], ['lease-acquired', 2]])
})

test('assertReconciled before a reconcile → lease.reconcile-first; a stale gen → lease.stale', async (t) => {
  const w = await world(t)
  const tx = (n: number): string => '0x' + n.toString(16).padStart(64, '0')
  await w.leases.acquire(JOB, 'sol', 'browser')
  await append(w, 'sol', 1, 'intent', { txId: tx(1), copy: 1, part: 1, parts: 2, attempt: 1, rawSha256: 'aa'.repeat(32) })
  await append(w, 'sol', 1, 'intent', { txId: tx(2), copy: 1, part: 2, parts: 2, attempt: 1, rawSha256: 'bb'.repeat(32) })
  w.clock.advance(15_000)
  const g = await w.leases.acquire(JOB, 'sol', 'cli')
  assert.deepEqual(g.openIntents.map((o) => o.txId), [tx(1), tx(2)])
  assert.throws(() => w.leases.assertReconciled(JOB, 'sol', 2), (e: { guardId?: string }) => e.guardId === 'lease.reconcile-first')
  assert.equal(await guardOf(append(w, 'sol', 1, 'note', { text: 'old holder' })), 'lease.stale')
  assert.equal(await guardOf(append(w, 'sol', 3, 'note', { text: 'future gen' })), 'lease.stale')
  await append(w, 'sol', 2, 'reconcile', { txId: tx(1), outcome: 'adopted' }) // still open, but reconciled by gen 2
  assert.throws(() => w.leases.assertReconciled(JOB, 'sol', 2), (e: { guardId?: string }) => e.guardId === 'lease.reconcile-first')
  await append(w, 'sol', 2, 'reconcile', { txId: tx(2), outcome: 'expired' })
  w.leases.assertReconciled(JOB, 'sol', 2)
  assert.equal(w.leases.assertLive(JOB, 'sol', 2), 'cli')
  // a reconcile journaled under the OLD generation does not count for the new one
  w.clock.advance(15_000)
  await w.leases.acquire(JOB, 'sol', 'browser')
  assert.throws(() => w.leases.assertReconciled(JOB, 'sol', 3), (e: { guardId?: string }) => e.guardId === 'lease.reconcile-first')
})

test('generations persist across an API restart (from the journal); the old lease is gone and journaled expired', async (t) => {
  const w = await world(t)
  await w.leases.acquire(JOB, 'eth', 'browser')
  w.clock.advance(15_000)
  await w.leases.acquire(JOB, 'eth', 'cli')
  await w.leases.acquire(JOB, 'sol', 'browser')
  w.registry.journalOf(JOB).close()
  const restarted = await world(t, w.state) // a new process: new registry, empty lease memory, same state dir
  restarted.clock.set(w.clock.now() + 1_000) // the gen-2 lease would still be live, but leases do not survive a restart
  assert.equal(await guardOf(restarted.leases.renew(JOB, 'eth', 2)), 'lease.lost')
  assert.deepEqual(restarted.leases.view(JOB), { eth: null, sol: null })
  const g = await restarted.leases.acquire(JOB, 'eth', 'browser')
  assert.equal(g.gen, 3)
  assert.equal((await restarted.leases.acquire(JOB, 'sol', 'cli')).gen, 2)
  const tl = restarted.registry.journalOf(JOB).all().filter((e) => e.chain === 'eth').map((e) => [e.type, e.gen])
  assert.deepEqual(tl, [['lease-acquired', 1], ['lease-expired', 1], ['lease-acquired', 2], ['lease-expired', 2], ['lease-acquired', 3]])
})

test('an executor cannot raise the generation: only lease-acquired lines written by the API count', async (t) => {
  const w = await world(t)
  await w.leases.acquire(JOB, 'eth', 'browser')
  await w.registry.journalOf(JOB).append({ chain: 'eth', by: 'browser', gen: 1, type: 'note', data: { text: 'x' } })
  await w.registry.journalOf(JOB).append({ chain: 'eth', by: 'browser', gen: 99, type: 'lease-acquired', data: { gen: 99 } })
  w.clock.advance(15_000)
  assert.equal((await w.leases.acquire(JOB, 'eth', 'cli')).gen, 2)
})

test('concurrent acquires: exactly one wins', async (t) => {
  const w = await world(t)
  const rs = await Promise.allSettled([w.leases.acquire(JOB, 'eth', 'browser'), w.leases.acquire(JOB, 'eth', 'cli'), w.leases.acquire(JOB, 'eth', 'browser')])
  assert.equal(rs.filter((r) => r.status === 'fulfilled').length, 1)
  for (const r of rs) if (r.status === 'rejected') assert.equal((r.reason as { guardId: string }).guardId, 'lease.held')
  assert.equal(timeline(w).filter(([type]) => type === 'lease-acquired').length, 1)
})

test('release: the live gen only (lease.lost otherwise); journals lease-released; the next acquire is gen + 1', async (t) => {
  const w = await world(t)
  await w.leases.acquire(JOB, 'eth', 'browser')
  assert.equal(await guardOf(w.leases.release(JOB, 'eth', 2)), 'lease.lost')
  await w.leases.release(JOB, 'eth', 1)
  assert.equal(await guardOf(w.leases.release(JOB, 'eth', 1)), 'lease.lost')
  assert.deepEqual(w.leases.view(JOB), { eth: null, sol: null })
  assert.equal((await w.leases.acquire(JOB, 'eth', 'cli')).gen, 2)
  assert.deepEqual(timeline(w).slice(1), [['lease-acquired', 1], ['lease-released', 1], ['lease-acquired', 2]])
})

test('holder must be browser or cli → lease.holder (nothing journaled)', async (t) => {
  const w = await world(t)
  for (const h of ['root', '', 'Browser', null]) {
    assert.equal(await guardOf(w.leases.acquire(JOB, 'eth', h as Holder)), 'lease.holder', String(h))
  }
  assert.equal(timeline(w).length, 1)
})

test('view: live leases only', async (t) => {
  const w = await world(t)
  await w.leases.acquire(JOB, 'eth', 'browser')
  assert.deepEqual(w.leases.view(JOB), { eth: { holder: 'browser', gen: 1, expiresAt: V.start + 15_000 }, sol: null })
  w.clock.advance(15_000)
  assert.deepEqual(w.leases.view(JOB), { eth: null, sol: null })
})

test('openIntentsFromEvents: the reducer\'s open/closed rules, (copy, part) order, the claw-back last as copy 0 part 0', () => {
  let seq = 0
  const ev = (type: string, gen: number | null, data: Record<string, unknown>, chain: Chain = 'eth'): JournalEvent =>
    ({ v: 1, seq: seq++, at: 0, prev: '', chain, by: gen === null ? 'api' : 'cli', gen, type: type as JournalEvent['type'], data })
  const t = (n: number): string => '0x' + n.toString(16).padStart(64, '0')
  const intent = (n: number, copy: number, part: number, attempt = 1, gen = 1): JournalEvent =>
    ev('intent', gen, { txId: t(n), copy, part, parts: 3, attempt, replaces: null, rawSha256: 'aa'.repeat(32), eth: { nonce: n } })
  const events = [
    intent(1, 2, 1), // copy 2 first in time, listed after copy 1
    intent(2, 1, 3),
    ev('sent', 1, { txId: t(2), outcome: 'accepted' }),
    intent(3, 1, 1),
    ev('sent', 1, { txId: t(3), outcome: 'rejected' }), // closed
    intent(4, 1, 2), intent(5, 1, 2, 2), ev('included', 1, { txId: t(5), copy: 1, part: 2 }), // both closed (sibling superseded)
    intent(6, 3, 1), ev('reconcile', 2, { txId: t(6), outcome: 'nonce-consumed' }),
    intent(7, 3, 2), ev('reconcile', 2, { txId: t(7), outcome: 'adopted' }), // open
    intent(8, 3, 3), ev('resolved', null, { txId: t(8), action: 'mark-failed' }),
    intent(9, 4, 1), ev('sent', 1, { txId: t(9), outcome: 'unknown' }), // open
    ev('intent', 1, { txId: t(10), copy: 1, part: 1, attempt: 1 }, 'sol'), // another chain
    ev('clawback-intent', 2, { txId: t(11), to: '0x' + '11'.repeat(20), value: '1', rawSha256: 'cc'.repeat(32), eth: { nonce: 11 } }),
  ]
  const open = openIntentsFromEvents(events, 'eth')
  assert.deepEqual(open.map((o) => o.txId), [t(2), t(1), t(7), t(9), t(11)])
  assert.deepEqual(open[0], { txId: t(2), gen: 1, copy: 1, part: 3, attempt: 1, eth: { nonce: 2 } })
  assert.deepEqual(open[4], { txId: t(11), gen: 2, copy: 0, part: 0, attempt: 1, eth: { nonce: 11 } })
  assert.deepEqual(openIntentsFromEvents([...events, ev('clawback-included', 2, { txId: t(11), value: '1', fee: '1' })], 'eth').map((o) => o.txId), [t(2), t(1), t(7), t(9)])
  assert.deepEqual(openIntentsFromEvents([...events, ev('reconcile', 3, { txId: t(11), outcome: 'expired' })], 'eth').length, 4)
  assert.deepEqual(openIntentsFromEvents([...events, ev('resolved', null, { txId: t(1), action: 'mark-done' })], 'eth').map((o) => o.txId), [t(2), t(7), t(9), t(11)])
  assert.deepEqual(openIntentsFromEvents(events, 'sol').map((o) => o.txId), [t(10)])
})

test('CC-12: a btc intent is carried in OpenIntent.btc (commit and reveal), and closes on included like the other chains', () => {
  let seq = 0
  const ev = (type: string, data: Record<string, unknown>): JournalEvent =>
    ({ v: 1, seq: seq++, at: 0, prev: '', chain: 'btc', by: 'cli', gen: 1, type: type as JournalEvent['type'], data })
  const commit = { kind: 'commit', pubkey: '02' + 'ab'.repeat(32), fee: '300', value: '1000', inputs: [`${'cd'.repeat(32)}:0`] }
  const reveal = { kind: 'reveal', pubkey: '02' + 'ab'.repeat(32), fee: '200', commitVout: 0 }
  const events = [
    ev('intent', { txId: '11'.repeat(32), copy: 1, part: 1, parts: 2, attempt: 1, replaces: null, rawSha256: 'aa'.repeat(32), btc: commit }),
    ev('intent', { txId: '22'.repeat(32), copy: 1, part: 2, parts: 2, attempt: 1, replaces: null, rawSha256: 'bb'.repeat(32), btc: reveal }),
  ]
  assert.deepEqual(openIntentsFromEvents(events, 'btc').map((o) => [o.txId, o.btc]), [['11'.repeat(32), commit], ['22'.repeat(32), reveal]])
  assert.deepEqual(openIntentsFromEvents([...events, ev('included', { txId: '11'.repeat(32), copy: 1, part: 1, block: '5', fee: '1300' })], 'btc').map((o) => o.txId), ['22'.repeat(32)])
})

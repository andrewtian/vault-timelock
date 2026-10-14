// The executor's lease (spec §5.5): acquire, a heartbeat every LEASE_RENEW_MS, release; LOST (fail closed) on a refused
// renew or when no renew was acknowledged before the local deadline. Virtual time; the in-memory API. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { LEASE_RENEW_MS, LEASE_TTL_MS, Refusal } from '../../src/contracts/index.ts'
import { createLease } from '../../src/executor/lease.ts'
import { JournalUnreachable } from '../../src/executor/journal-client.ts'
import { stack } from './helpers.ts'

test('acquire → gen 2 (an earlier tab held gen 1); the heartbeat renews every 5 s and keeps it alive for minutes; release journals lease-released', async () => {
  const s = stack('eth', {})
  let ticks = 0
  const l = createLease({ journal: s.j.client, jobId: s.j.id, chain: 'eth', holder: 'cli', clock: s.clock, onTick: () => { ticks++ } })
  const g = await l.acquire()
  assert.deepEqual([g.gen, l.gen, l.alive(), l.lost()], [2, 2, true, null])
  for (let i = 0; i < 60; i++) await s.clock.sleep(1_000)
  assert.equal(l.alive(), true)
  assert.ok(s.j.calls.filter((c) => c === 'lease:renew').length >= 10, 'renewed every LEASE_RENEW_MS')
  assert.ok(ticks >= 10)
  await l.release()
  assert.equal(s.j.events.at(-1)!.type, 'lease-released'); assert.equal(l.alive(), false)
  assert.equal(LEASE_RENEW_MS < LEASE_TTL_MS / 2, true)
})

test('a renew refused (lease.lost: a takeover) → lost at once, onLost told, no further renew', async () => {
  const s = stack('eth', {})
  let lostWhy = ''
  const l = createLease({ journal: s.j.client, jobId: s.j.id, chain: 'eth', holder: 'cli', clock: s.clock, onLost: (w) => { lostWhy = w } })
  await l.acquire()
  s.j.expire('eth')
  await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')            // someone else took over
  for (let i = 0; i < 10; i++) await s.clock.sleep(1_000)
  assert.equal(l.alive(), false); assert.match(l.lost()!, /lease\.lost/); assert.match(lostWhy, /taken over|expired/)
  const renews = s.j.calls.filter((c) => c === 'lease:renew').length
  for (let i = 0; i < 20; i++) await s.clock.sleep(1_000)
  assert.equal(s.j.calls.filter((c) => c === 'lease:renew').length, renews, 'the heartbeat stopped')
})

test('no renew acknowledged before the local deadline (the API unreachable) → lost (fail closed), even though no refusal came; the API coming back never revives it', async () => {
  const s = stack('eth', {})
  let down = true, lostWhy = ''
  const journal = { ...s.j.client, lease: async (...a: Parameters<typeof s.j.client.lease>) => { if (a[2] === 'renew' && down) throw new JournalUnreachable('down'); return s.j.client.lease(...a) } }
  const l = createLease({ journal, jobId: s.j.id, chain: 'eth', holder: 'cli', clock: s.clock, onLost: (w) => { lostWhy = w } })
  await l.acquire()
  for (let i = 0; i < 10; i++) await s.clock.sleep(1_000)
  assert.equal(l.alive(), true, 'still inside the TTL')
  for (let i = 0; i < 10; i++) await s.clock.sleep(1_000)
  assert.equal(l.alive(), false); assert.match(l.lost()!, /deadline/)
  assert.match(lostWhy, /no renewal was acknowledged/, 'the heartbeat itself declared the loss (onLost)')
  down = false
  const renews = s.j.calls.filter((c) => c === 'lease:renew').length
  for (let i = 0; i < 30; i++) await s.clock.sleep(1_000)
  assert.equal(s.j.calls.filter((c) => c === 'lease:renew').length, renews, 'no renew after the loss')
  assert.equal(l.alive(), false, 'never revived'); assert.match(l.lost()!, /no renewal was acknowledged/)
  await l.release()
})

test('a renew that never answers (a hung request): alive() turns false at the local deadline by itself, though the heartbeat is stuck', async () => {
  const s = stack('eth', {})
  const journal = { ...s.j.client, lease: async (...a: Parameters<typeof s.j.client.lease>) => (a[2] === 'renew' ? new Promise<never>(() => {}) : s.j.client.lease(...a)) }
  const l = createLease({ journal, jobId: s.j.id, chain: 'eth', holder: 'cli', clock: s.clock })
  await l.acquire()
  for (let i = 0; i < 14; i++) await s.clock.sleep(1_000)
  assert.equal(l.alive(), true, 'inside the TTL')
  for (let i = 0; i < 2; i++) await s.clock.sleep(1_000)
  assert.equal(l.alive(), false, 'the deadline passed: no new tx may start'); assert.match(l.lost()!, /deadline/)
  l.stop()
})

test('a renew answered with another generation is a loss, not a refresh', async () => {
  const s = stack('eth', {})
  const journal = { ...s.j.client, lease: async (...a: Parameters<typeof s.j.client.lease>) => { const g = await s.j.client.lease(...a); return a[2] === 'renew' ? { ...g, gen: g.gen + 1 } : g } }
  const l = createLease({ journal, jobId: s.j.id, chain: 'eth', holder: 'cli', clock: s.clock })
  await l.acquire()
  for (let i = 0; i < 6; i++) await s.clock.sleep(1_000)
  assert.equal(l.alive(), false); assert.match(l.lost()!, /another generation/)
  void Refusal
})

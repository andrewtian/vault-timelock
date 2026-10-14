// The page's handle on the worker (src/privacycash/client.js): calls, the idle and hard watchdogs, Stop, and what a stopped client says.
// A fake Worker and fake timers; no real worker, no network.
import { test, expect, vi, beforeEach, afterEach } from 'vitest'
import { DEFAULT_LIMITS, PcCallError, createPcClient } from '../src/privacycash/client.js'

class FakeWorker {
  constructor() { this.posted = []; this.terminated = 0 }
  postMessage(m) { this.posted.push(m) }
  terminate() { this.terminated++ }
  say(m) { this.onmessage?.({ data: m }) }
}
let w
const make = (limits, onStatus) => createPcClient({ makeWorker: () => (w = new FakeWorker()), limits, onStatus })
beforeEach(() => vi.useFakeTimers())
afterEach(() => vi.useRealTimers())

test('a call posts {id, cmd, args} and resolves with the worker\'s answer; errors carry the worker\'s code', async () => {
  const c = make()
  const p = c.call('balance', { x: 1 })
  expect(w.posted).toEqual([{ id: 1, cmd: 'balance', args: { x: 1 } }])
  w.say({ id: 1, ok: true, result: { lamports: 5 } })
  await expect(p).resolves.toEqual({ lamports: 5 })
  const q = c.call('quote', { net: 1 })
  w.say({ id: 2, ok: false, error: { code: 'pc.partial', message: 'too much' } })
  await expect(q).rejects.toMatchObject({ name: 'PcCallError', code: 'pc.partial', message: 'too much', sentAtStop: false })
  expect(c.alive).toBe(true)                                                                  // an ordinary refusal does not kill the worker
  w.say({ id: 99, ok: true, result: 1 }); w.say(null); w.say('x'); w.say({ type: 'nonsense' })    // strays are ignored
})

test('status events reach the page, trimmed, and keep a long call alive past the idle limit', async () => {
  const seen = []
  const c = make({ ...DEFAULT_LIMITS, balance: { idleMs: 1000, maxMs: 100_000 } }, (m) => seen.push(m))
  const p = c.call('balance')
  for (let i = 0; i < 5; i++) { vi.advanceTimersByTime(800); w.say({ type: 'status', msg: `(decrypting cached utxo: ${i}/9...)${'x'.repeat(300)}` }) }
  expect(c.alive).toBe(true)
  expect(seen).toHaveLength(5); expect(seen[0].length).toBe(120)
  w.say({ id: 1, ok: true, result: 1 })
  await expect(p).resolves.toBe(1)
})

test('WATCHDOG: no sign of life for idleMs terminates the worker, rejects every pending call pc.watchdog, and the client stays dead', async () => {
  const c = make({ ...DEFAULT_LIMITS, balance: { idleMs: 1000, maxMs: 100_000 }, quote: { idleMs: 1000, maxMs: 100_000 } })
  const a = c.call('balance'), b = c.call('quote')
  const ra = expect(a).rejects.toMatchObject({ code: 'pc.watchdog', stopped: true }), rb = expect(b).rejects.toMatchObject({ code: 'pc.watchdog' })
  vi.advanceTimersByTime(1001)
  await ra; await rb
  expect(w.terminated).toBe(1); expect(c.alive).toBe(false)
  await expect(c.call('balance')).rejects.toMatchObject({ code: 'pc.stopped', stopped: true })
  expect(w.posted).toHaveLength(2)                                                            // nothing was posted to the dead worker
  w.say({ id: 1, ok: true, result: 1 })                                                       // a late answer is ignored (handlers are cleared)
})

test('HARD CAP: a call that keeps reporting is still stopped at maxMs', async () => {
  const c = make({ ...DEFAULT_LIMITS, balance: { idleMs: 1000, maxMs: 5000 } })
  const p = c.call('balance')
  const r = expect(p).rejects.toMatchObject({ code: 'pc.watchdog', message: expect.stringMatching(/ran past/) })
  for (let i = 0; i < 7; i++) { vi.advanceTimersByTime(900); w.say({ type: 'status', msg: 'getting private balance' }) }
  await r
  expect(w.terminated).toBe(1)
})

test('STOP terminates the worker and rejects the pending call; once /withdraw has left, the rejection says so (funds may have moved)', async () => {
  const c = make()
  const p = c.call('withdraw', {})
  w.say({ type: 'sent' })
  const r = expect(p).rejects.toMatchObject({ code: 'pc.stopped', stopped: true, sentAtStop: true })
  c.stop()
  await r
  expect(w.terminated).toBe(1); expect(c.sentAtStop).toBe(true)
  c.stop(); expect(w.terminated).toBe(1)                                                      // idempotent
  const d = make(); const q = d.call('balance'); const r2 = expect(q).rejects.toMatchObject({ sentAtStop: false }); d.stop(); await r2
})

test('a crashed or unreadable worker is stopped, not retried', async () => {
  const c = make()
  const p = c.call('unlock', {})
  const r = expect(p).rejects.toMatchObject({ code: 'pc.worker-error' })
  w.onerror(new Event('error')); await r
  expect(w.terminated).toBe(1)
  const d = make(); const q = d.call('unlock', {}); const r2 = expect(q).rejects.toMatchObject({ code: 'pc.worker-error' }); w.onmessageerror(); await r2
})

test('the default limits cover every command the session has', () => {
  for (const k of ['unlock', 'balance', 'quote', 'withdraw', 'lock']) expect(DEFAULT_LIMITS[k].idleMs).toBeGreaterThan(0)
  expect(new PcCallError('c', 'm', { a: 1 }).a).toBe(1)
})

test('m-4: an error after /withdraw left STOPS the client (the key is forgotten, a fresh unlock comes first); sent is per call, never inherited', async () => {
  const c = make()
  const p = c.call('withdraw', {})
  w.say({ type: 'sent' })
  const r = expect(p).rejects.toMatchObject({ code: 'pc.sdk', sentAtStop: true, stopped: true })
  w.say({ id: 1, ok: false, error: { code: 'pc.sdk', message: 'relayer timed out' } })
  await r
  expect(c.alive).toBe(false); expect(w.terminated).toBe(1)
  await expect(c.call('balance')).rejects.toMatchObject({ code: 'pc.stopped', stopped: true })      // Withdraw is not available again on this client
  // an error that came before any /withdraw left changes nothing: the client lives, and says nothing about funds
  const d = make()
  const q = d.call('quote', {})
  w.say({ id: 1, ok: false, error: { code: 'pc.partial', message: 'x' } })
  await expect(q).rejects.toMatchObject({ sentAtStop: false }); expect(d.alive).toBe(true); expect(w.terminated).toBe(0)
  // a /withdraw call's `sent` does not leak into the next call's error
  const e = make()
  const a = e.call('withdraw', {}); w.say({ type: 'sent' }); w.say({ id: 1, ok: true, result: {} }); await a
  const b = e.call('balance', {})
  w.say({ id: 2, ok: false, error: { code: 'pc.sdk', message: 'unrelated' } })
  await expect(b).rejects.toMatchObject({ sentAtStop: false }); expect(e.alive).toBe(true)
})

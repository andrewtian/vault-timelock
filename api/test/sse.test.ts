// SSE (spec §5.2): from seq 3 → replays 3..n then live; Last-Event-ID honoured (and wins over ?from=, as in the
// contract replay server); a heartbeat comment every 15 s (fake clock); the subscriber is removed on close; the
// stream-05a fixture frames exactly.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createServer, request } from 'node:http'
import { EventEmitter } from 'node:events'
import type { ClientRequest } from 'node:http'
import { join } from 'node:path'
import { SSE_HEARTBEAT_MS, sseFrame, sseHeartbeat } from '@vault-timelock/core/contracts'
import { JOURNAL_FILE } from '../src/journal.ts'
import { SSE_MAX_BUFFER, createSse } from '../src/sse.ts'
import { FIXTURES, JOB, TOKEN, call, fixture, guardOf, installJournal, startApi } from './helpers.ts'
import type { TestApi } from './helpers.ts'

interface Stream { status: number; headers: Record<string, unknown>; text(): string; waitFor(pred: (s: string) => boolean): Promise<void>; close(): void }
function openStream(port: number, path: string, headers: Record<string, string> = {}): Promise<Stream> {
  return new Promise((resolve, reject) => {
    let buf = ''
    const waiters: Array<() => void> = []
    const req: ClientRequest = request({ host: '127.0.0.1', port, path, setHost: false,
      headers: { host: '127.0.0.1:5182', authorization: `Bearer ${TOKEN}`, ...headers } }, (res) => {
      res.setEncoding('utf8')
      res.on('data', (c: string) => { buf += c; for (const w of waiters.splice(0)) w() })
      res.on('error', () => {})
      resolve({
        status: res.statusCode ?? 0, headers: res.headers, text: () => buf,
        waitFor: (pred) => new Promise<void>((ok, fail) => {
          const timer = setTimeout(() => fail(new Error(`timed out; got ${JSON.stringify(buf.slice(-200))}`)), 5_000)
          const check = (): void => { if (pred(buf)) { clearTimeout(timer); ok() } else waiters.push(check) }
          check()
        }),
        close: () => { req.destroy() },
      })
    })
    req.on('error', (e) => { if ((e as NodeJS.ErrnoException).code !== 'ECONNRESET') reject(e) })
    req.end()
  })
}
const note = (text: string) => ({ chain: null, by: 'api' as const, gen: null, type: 'note' as const, data: { text } })
const linesOf = (a: TestApi, id = JOB): string[] => readFileSync(join(a.state, 'jobs', id, JOURNAL_FILE), 'utf8').split('\n').slice(0, -1)
const frames = (a: TestApi, from: number, id = JOB): string => linesOf(a, id).slice(from).map((l, i) => sseFrame(from + i, l)).join('')
const tick = (): Promise<void> => new Promise((r) => setTimeout(r, 30))

async function withJournal(t: { after(fn: () => Promise<void>): void }): Promise<TestApi> {
  const a = await startApi()
  t.after(() => a.close())
  for (let i = 1; i <= 5; i++) await a.api.registry.journalOf(JOB).append(note(`n${i}`)) // seq 0 (created) .. 5
  return a
}

test('?from=3 replays 3..5, then each new event live, framed id/data with the journal line', async (t) => {
  const a = await withJournal(t)
  const s = await openStream(a.port, `/jobs/${JOB}/events?from=3`)
  t.after(() => s.close())
  assert.equal(s.status, 200)
  assert.equal(s.headers['content-type'], 'text/event-stream; charset=utf-8')
  assert.equal(s.headers['cache-control'], 'no-store')
  await s.waitFor((b) => b === frames(a, 3))
  await a.api.registry.journalOf(JOB).append(note('live 6'))
  await a.api.registry.journalOf(JOB).append(note('live 7'))
  await s.waitFor((b) => b === frames(a, 3))
  assert.equal(linesOf(a).length, 8)
  assert.match(s.text(), /^id: 3\ndata: \{"v":1,"seq":3,/)
})

test('no from → everything from seq 0; from beyond the end → only what comes next', async (t) => {
  const a = await withJournal(t)
  const all = await openStream(a.port, `/jobs/${JOB}/events`)
  const later = await openStream(a.port, `/jobs/${JOB}/events?from=7`)
  t.after(() => { all.close(); later.close() })
  await all.waitFor((b) => b === frames(a, 0))
  await a.api.registry.journalOf(JOB).append(note('6'))
  await a.api.registry.journalOf(JOB).append(note('7'))
  await later.waitFor((b) => b === frames(a, 7))
})

test('Last-Event-ID is honoured, and wins over ?from= (agreeing or not); a malformed one is ignored', async (t) => {
  const a = await withJournal(t)
  const cases: Array<[string, Record<string, string>, number]> = [
    [`/jobs/${JOB}/events`, { 'last-event-id': '3' }, 4],
    [`/jobs/${JOB}/events?from=4`, { 'last-event-id': '3' }, 4], // the web client's reconnect: both, agreeing
    [`/jobs/${JOB}/events?from=1`, { 'last-event-id': '3' }, 4], // disagreeing: Last-Event-ID wins
    [`/jobs/${JOB}/events?from=2`, { 'last-event-id': 'x3' }, 2],
  ]
  for (const [path, headers, from] of cases) {
    const s = await openStream(a.port, path, headers)
    await s.waitFor((b) => b === frames(a, from))
    s.close()
  }
})

test('a heartbeat comment every 15 s (fake clock), and none in between', async (t) => {
  const a = await withJournal(t)
  const s = await openStream(a.port, `/jobs/${JOB}/events?from=6`)
  t.after(() => s.close())
  await tick()
  assert.equal(s.text(), '')
  a.clock.advance(SSE_HEARTBEAT_MS - 1)
  await tick()
  assert.equal(s.text(), '')
  a.clock.advance(1)
  const first = sseHeartbeat(a.clock.now())
  assert.equal(first, `: hb ${1791504000000 + SSE_HEARTBEAT_MS}\n\n`)
  await s.waitFor((b) => b === first)
  a.clock.advance(SSE_HEARTBEAT_MS)
  await s.waitFor((b) => b === first + sseHeartbeat(a.clock.now()))
})

test('the subscriber and its heartbeat timer are removed when the client goes away', async (t) => {
  const a = await withJournal(t)
  assert.equal(a.api.sse.count(), 0)
  // S1 review m2: count the journal's own listeners, so a missing unsubscribe() cannot hide behind the guarded write
  const journal = a.api.registry.journalOf(JOB)
  const realSubscribe = journal.subscribe.bind(journal)
  let listeners = 0
  journal.subscribe = (fn) => { listeners++; const off = realSubscribe(fn); return () => { listeners--; off() } }
  const s1 = await openStream(a.port, `/jobs/${JOB}/events`)
  const s2 = await openStream(a.port, `/jobs/${JOB}/events`)
  await s1.waitFor((b) => b.length > 0)
  assert.equal(a.api.sse.count(), 2)
  assert.equal(listeners, 2)
  assert.equal(a.clock.timers(), 2)
  s1.close()
  for (let i = 0; i < 100 && a.api.sse.count() !== 1; i++) await tick()
  assert.equal(a.api.sse.count(), 1)
  assert.equal(listeners, 1)
  assert.equal(a.clock.timers(), 1)
  s2.close()
  for (let i = 0; i < 100 && a.api.sse.count() !== 0; i++) await tick()
  assert.equal(a.api.sse.count(), 0)
  assert.equal(listeners, 0)
  assert.equal(a.clock.timers(), 0)
  await a.api.registry.journalOf(JOB).append(note('after close')) // no listener left to write to a closed stream
})

test('stream-05a: the contract journal streams line for line', async (t) => {
  const a = await startApi({ jobs: [] })
  t.after(() => a.close())
  const f = fixture<{ request: { path: string }; response: { status: number; headers: Record<string, string>; sse: { journal: string } } }>('http/stream-05a.json')
  const id = /^\/jobs\/([0-9a-f]{16})\/events$/.exec(f.request.path)![1]
  const vector = /^journals\/(.+)\.jsonl$/.exec(f.response.sse.journal)![1]
  const installed = await installJournal(a, vector) // its stored def and journal, as an API wrote them
  assert.equal(installed.id, id)
  const want = readFileSync(join(FIXTURES, f.response.sse.journal), 'utf8').split('\n').filter((l) => l !== '')
  const s = await openStream(a.port, f.request.path)
  t.after(() => s.close())
  assert.equal(s.status, f.response.status)
  assert.equal(s.headers['content-type'], f.response.headers['content-type'])
  await s.waitFor((b) => b === want.map((l, i) => sseFrame(i, l)).join(''))
  const resumed = await openStream(a.port, f.request.path, { 'last-event-id': '2' })
  t.after(() => resumed.close())
  await resumed.waitFor((b) => b === want.slice(3).map((l, i) => sseFrame(i + 3, l)).join(''))
})

test('a malformed ?from= → 400 api.args; an unknown job → 404 job.missing; the guards apply', async (t) => {
  const a = await withJournal(t)
  for (const q of ['from=-1', 'from=abc', 'from=1&from=2', 'from=', 'from=01']) {
    const s = await openStream(a.port, `/jobs/${JOB}/events?${q}`) // resolves on the headers: a stream would not end
    try {
      assert.equal(s.status, 400, q)
      await s.waitFor((b) => b.includes('"guard"'))
      assert.match(s.text(), /"guard":"api\.args"/, q)
    } finally {
      s.close()
    }
  }
  const missing = await call(a.port, { path: '/jobs/0000000000000000/events' })
  assert.equal(missing.status, 404)
  assert.equal(guardOf(missing), 'job.missing')
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/events`, headers: { authorization: null } })).status, 401)
  assert.equal(a.api.sse.count(), 0)
})

// a fake response: write() queues and says false past a 16 KiB mark; drain() is the client reading everything
class FakeRes extends EventEmitter {
  writableLength = 0; destroyed = false; writableEnded = false; frames = 0
  writeHead(): this { return this }
  flushHeaders(): void {}
  write(text: string): boolean { this.writableLength += Buffer.byteLength(text); this.frames++; return this.writableLength < 16_384 }
  drain(): void { this.writableLength = 0; this.emit('drain') }
  destroy(): this { this.destroyed = true; process.nextTick(() => this.emit('close')); return this }
}
const mkEvents = (n: number, size: number) => Array.from({ length: n }, (_, seq) => ({ seq, v: 1, at: 0, prev: '', chain: null, by: 'api', gen: null, type: 'note', data: { text: 'y'.repeat(size) } }))

test('the replay is written with backpressure: a stalled reader gets one frame past the mark and is NOT cut off; a reader that drains gets all of a journal far over SSE_MAX_BUFFER (lane-s re-review I-2)', async () => {
  const events = mkEvents(10, 400_000)                                        // 4 MB
  const journal = { all: () => events, subscribe: () => () => {} }
  const hub = createSse({ clock: { now: () => 0, every: () => () => {} } } as never)
  const stalled = new FakeRes()
  hub.stream(stalled as never, journal as never, 0)
  await tick()
  assert.deepEqual([stalled.destroyed, stalled.frames], [false, 1], 'one frame written, then it waits for drain')
  const reader = new FakeRes()
  hub.stream(reader as never, journal as never, 0)
  let total = 0
  for (let i = 0; i < 100 && reader.frames < 10; i++) { await tick(); total = Math.max(total, reader.writableLength); reader.drain() }
  assert.deepEqual([reader.destroyed, reader.frames], [false, 10], 'every frame of the 4 MB replay was delivered')
  assert.ok(total < SSE_MAX_BUFFER, 'never more than a frame or two queued')
})

test('after the replay, a reader that stops reading is cut off past SSE_MAX_BUFFER; live events during the replay are held, in order, and sent after it; a reader that keeps up is never cut (S1 m6)', async () => {
  const events = mkEvents(12, 400_000)
  let listeners: Array<(e: unknown) => void> = []
  const journal = { all: () => events.slice(0, 2), subscribe: (fn: (e: unknown) => void) => { listeners.push(fn); return () => { listeners = listeners.filter((x) => x !== fn) } } }
  const hub = createSse({ clock: { now: () => 0, every: () => () => {} } } as never)
  const r = new FakeRes()
  hub.stream(r as never, journal as never, 0)
  for (const fn of listeners) fn(events[2])                                   // arrives while the replay waits for drain
  assert.equal(r.frames, 1)
  for (let i = 0; i < 10 && r.frames < 3; i++) { r.drain(); await tick() }
  assert.deepEqual([r.frames, r.destroyed], [3, false], 'replay (2) then the held live event')
  // now live: a reader that keeps up
  for (let i = 3; i < 8; i++) { for (const fn of listeners) fn(events[i]); r.drain() }
  assert.deepEqual([r.frames, r.destroyed], [8, false])
  // and one that stops reading is cut off by the cap
  for (let i = 8; i < 12; i++) for (const fn of listeners) fn(events[i])
  assert.equal(r.destroyed, true)
  await tick()
  assert.deepEqual([hub.count(), listeners.length], [0, 0])
})

test('over a real socket: a 3+ MB journal replays fully to a normal reader (lane-s re-review I-2)', async (t) => {
  const events = mkEvents(16_000, 190)
  const journal = { all: () => events, subscribe: () => () => {} }
  const hub = createSse({ clock: { now: () => 0, every: () => () => {} } } as never)
  const server = createServer((_req, res) => { hub.stream(res, journal as never, 0) })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  t.after(() => { server.closeAllConnections(); server.close() })
  const port = (server.address() as { port: number }).port
  const s = await openStream(port, '/x')
  t.after(() => s.close())
  const want = events.map((e) => sseFrame(e.seq, JSON.stringify(e)).length).reduce((x, y) => x + y, 0)
  await s.waitFor((b) => b.length >= want)                                 // length only: a substring search per chunk would be quadratic
  assert.equal(s.text().length, want)
  assert.equal((s.text().match(/^id: /gm) ?? []).length, events.length)
  assert.ok(s.text().length > 3_000_000)
})

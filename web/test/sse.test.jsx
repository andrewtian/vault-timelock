import { test, expect, vi } from 'vitest'
import { subscribe, parseBlock } from '../src/lib/sse.js'

const enc = new TextEncoder()
const frame = (id, o) => `id: ${id}\ndata: ${JSON.stringify(o)}\n\n`
// A Response whose body yields the chunks, then ends (or stays open when `hang`).
function stream(chunks, { hang = false, signal } = {}) {
  return new Response(new ReadableStream({
    start(c) {
      for (const k of chunks) c.enqueue(enc.encode(k))
      if (!hang) c.close()
      else signal?.addEventListener('abort', () => c.error(new DOMException('aborted', 'AbortError')))
    },
  }), { status: 200, headers: { 'content-type': 'text/event-stream' } })
}
const until = async (f) => { for (let i = 0; i < 200 && !f(); i++) await new Promise((r) => setTimeout(r, 5)) }

test('parseBlock: id, multi-line data, comments ignored', () => {
  expect(parseBlock(': hb 1')).toBeNull()
  expect(parseBlock('id: 7\ndata: {"a":1}')).toEqual({ id: 7, line: '{"a":1}' })
})

test('delivers events, split across chunks, with heartbeats ignored', async () => {
  const got = []
  const f = vi.fn(async (_u, init) => stream([': hb 1\n\nid: 1\ndata: {"t":"a"}\n', '\nid: 2\ndata: {"t":"b"}\n\n'], { hang: true, signal: init.signal }))
  const close = subscribe('b858b37944ac7f70', 0, (m) => got.push([m.id, m.event.t]), { fetch: f, retryMs: 1 })
  await until(() => got.length === 2)
  close()
  expect(got).toEqual([[1, 'a'], [2, 'b']])
  expect(f.mock.calls[0][0]).toBe('/api/jobs/b858b37944ac7f70/events?from=0')
})

test('reconnect resumes from the last id (Last-Event-ID), never repeating a seq', async () => {
  const got = []
  const calls = []
  const f = vi.fn(async (url, init) => {
    calls.push([url, init.headers['last-event-id']])
    if (calls.length === 1) return stream([frame(1, { n: 1 }), frame(2, { n: 2 })])
    return stream([frame(2, { n: 2 }), frame(3, { n: 3 })], { hang: true, signal: init.signal })
  })
  const close = subscribe('b858b37944ac7f70', 0, (m) => got.push(m.id), { fetch: f, retryMs: 1 })
  await until(() => got.length === 3)
  close()
  expect(got).toEqual([1, 2, 3])
  expect(calls[0]).toEqual(['/api/jobs/b858b37944ac7f70/events?from=0', undefined])
  expect(calls[1]).toEqual(['/api/jobs/b858b37944ac7f70/events?from=3', '2'])
})

test('a server error is retried; a 401 stops with the guard', async () => {
  const errs = []
  let n = 0
  const f = vi.fn(async () => {
    n += 1
    if (n === 1) return new Response('x', { status: 503 })
    return new Response(JSON.stringify({ error: { guard: 'api.token', message: 'm' } }), { status: 401 })
  })
  subscribe('b858b37944ac7f70', 5, () => {}, { fetch: f, retryMs: 1, onError: (e) => errs.push(e) })
  await until(() => errs.length === 1)
  expect(errs).toEqual([{ guard: 'api.token', status: 401 }])
  await new Promise((r) => setTimeout(r, 30))
  expect(f).toHaveBeenCalledTimes(2)
})

test('close stops reconnecting', async () => {
  const f = vi.fn(async () => stream([]))
  const close = subscribe('b858b37944ac7f70', 0, () => {}, { fetch: f, retryMs: 1 })
  await until(() => f.mock.calls.length >= 2)
  close()
  const n = f.mock.calls.length
  await new Promise((r) => setTimeout(r, 40))
  expect(f.mock.calls.length).toBe(n)
})

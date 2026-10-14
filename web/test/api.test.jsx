import { test, expect, vi, beforeEach } from 'vitest'
import { api, apiText, putMessage, ApiError } from '../src/lib/api.js'

const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json; charset=utf-8' } })
beforeEach(() => { globalThis.fetch = vi.fn() })

test('api prefixes /api and returns JSON', async () => {
  globalThis.fetch.mockResolvedValue(json(200, { network: 'local' }))
  expect(await api('/status')).toEqual({ network: 'local' })
  expect(globalThis.fetch.mock.calls[0][0]).toBe('/api/status')
})

test('api maps { error: { guard } } to ApiError', async () => {
  globalThis.fetch.mockResolvedValue(json(404, { error: { guard: 'job.missing', message: 'no such job' } }))
  const e = await api('/jobs/0000000000000000').catch((x) => x)
  expect(e).toBeInstanceOf(ApiError)
  expect(e.guard).toBe('job.missing')
  expect(e.status).toBe(404)
})

test('a non-JSON failure is api.http; an unreachable API is api.unreachable', async () => {
  globalThis.fetch.mockResolvedValueOnce(new Response('<html>bad gateway</html>', { status: 502 }))
  const a = await api('/status').catch((x) => x)
  expect([a.guard, a.status]).toEqual(['api.http', 502])
  globalThis.fetch.mockRejectedValueOnce(new TypeError('fetch failed'))
  const b = await api('/status').catch((x) => x)
  expect([b.guard, b.status]).toEqual(['api.unreachable', 0])
})

test('apiText returns text and throws ApiError on failure', async () => {
  globalThis.fetch.mockResolvedValueOnce(new Response('hello', { status: 200 }))
  expect(await apiText('/messages/x')).toBe('hello')
  globalThis.fetch.mockResolvedValueOnce(json(400, { error: { guard: 'message.utf8', message: 'm' } }))
  expect((await apiText('/messages/x').catch((x) => x)).guard).toBe('message.utf8')
})

test('putMessage PUTs the exact text as UTF-8', async () => {
  const sha = 'a'.repeat(64)
  globalThis.fetch.mockResolvedValue(json(201, { sha256: sha, bytes: 5 }))
  expect(await putMessage(sha, 'héllo')).toEqual({ sha256: sha, bytes: 5 })
  const [url, init] = globalThis.fetch.mock.calls[0]
  expect(url).toBe(`/api/messages/${sha}`)
  expect(init.method).toBe('PUT')
  expect(init.headers['content-type']).toBe('text/plain; charset=utf-8')
  expect(init.body).toBe('héllo')
})

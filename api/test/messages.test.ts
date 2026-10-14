// PUT / GET /messages/:sha256 (messages.ts): stored once by digest; the digest, UTF-8 and message rules; the 16 MiB cap
// streamed (declared or counted, refused before the body ends); reads re-hashed. Synthetic texts only.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync, statSync, writeFileSync } from 'node:fs'
import { request } from 'node:http'
import { join } from 'node:path'
import { MESSAGE_MAX } from '@vault-timelock/core/contracts'
import { FIXTURES, TOKEN, call, fixture, guardOf, startApi } from './helpers.ts'
import type { Reply, TestApi } from './helpers.ts'

const sha = (b: Uint8Array | string): string => createHash('sha256').update(b).digest('hex')
const TEXT = { 'content-type': 'text/plain; charset=utf-8' }
const put = (a: TestApi, digest: string, raw: Buffer | string): Promise<Reply> => call(a.port, { method: 'PUT', path: `/messages/${digest}`, raw, headers: TEXT })
async function api(t: { after(fn: () => Promise<void>): void }): Promise<TestApi> {
  const a = await startApi({ jobs: [] })
  t.after(() => a.close())
  return a
}
const file = (name: string): Buffer => readFileSync(join(FIXTURES, 'messages', name))

test('PUT sealed-like.txt → 201 { sha256, bytes }, stored 0600 by digest, served back byte for byte; idempotent', async (t) => {
  const a = await api(t)
  const valid = fixture<Record<string, { bytes: number; sha256: string }>>('messages/valid.json')
  for (const [name, want] of Object.entries(valid)) {
    const bytes = file(name)
    const r = await put(a, want.sha256, bytes)
    assert.equal(r.status, 201, `${name}: ${r.text}`)
    assert.deepEqual(r.json, { sha256: want.sha256, bytes: want.bytes })
    assert.equal((await put(a, want.sha256, bytes)).status, 201)
    const stored = join(a.state, 'messages', `${want.sha256}.txt`)
    assert.deepEqual(readFileSync(stored), bytes)
    assert.equal(statSync(stored).mode & 0o777, 0o600)
    const back = await call(a.port, { path: `/messages/${want.sha256}` })
    assert.equal(back.status, 200)
    assert.equal(back.headers['content-type'], 'text/plain; charset=utf-8')
    assert.equal(back.headers['cache-control'], 'no-store')
    assert.deepEqual(Buffer.from(back.text, 'utf8'), bytes)
  }
})

test('the body sha256 ≠ the path → 400 message.digest; nothing stored', async (t) => {
  const a = await api(t)
  const bytes = file('sealed-like.txt')
  const r = await put(a, sha('something else'), bytes)
  assert.equal(r.status, 400)
  assert.equal(guardOf(r), 'message.digest')
  assert.equal(guardOf(await call(a.port, { path: `/messages/${sha(bytes)}` })), 'message.missing')
})

test('each bad message → its guard (refused, never rewritten): controls, NFC, secrets, IPs, empty, invalid UTF-8, a BOM', async (t) => {
  const a = await api(t)
  const bad = fixture<Record<string, string>>('messages/bad/expected.json')
  for (const [name, guard] of Object.entries(bad)) {
    const bytes = file(join('bad', name))
    const r = await put(a, sha(bytes), bytes)
    assert.equal(r.status, 400, name)
    assert.equal(guardOf(r), guard, name)
    assert.ok(!r.text.includes('203.0.113'), `${name}: the reply echoes the text`)
  }
})

test('16 MiB + 1 → 413 message.too-long: declared (no byte read) or chunked (refused before the body ends)', async (t) => {
  const a = await api(t)
  // declared: the server answers on the headers alone
  const declared = await new Promise<number>((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: a.port, method: 'PUT', path: `/messages/${'a'.repeat(64)}`, setHost: false,
      headers: { host: '127.0.0.1:5182', authorization: `Bearer ${TOKEN}`, ...TEXT, 'content-length': String(MESSAGE_MAX + 1) } }, (res) => {
      res.resume()
      resolve(res.statusCode ?? 0)
      req.destroy()
    })
    req.on('error', (e) => { if ((e as NodeJS.ErrnoException).code !== 'ECONNRESET' && (e as NodeJS.ErrnoException).code !== 'EPIPE') reject(e) })
    req.flushHeaders()
  })
  assert.equal(declared, 413)
  // chunked: cap + 1 bytes written, the request left open: the 413 comes without the end of the body
  const chunked = await new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: a.port, method: 'PUT', path: `/messages/${'a'.repeat(64)}`, setHost: false,
      headers: { host: '127.0.0.1:5182', authorization: `Bearer ${TOKEN}`, ...TEXT } }, (res) => {
      let body = ''
      res.setEncoding('utf8')
      res.on('data', (c: string) => { body += c })
      res.on('end', () => { resolve({ status: res.statusCode ?? 0, body }); req.destroy() })
    })
    req.on('error', (e) => { if ((e as NodeJS.ErrnoException).code !== 'ECONNRESET' && (e as NodeJS.ErrnoException).code !== 'EPIPE') reject(e) })
    const chunk = Buffer.alloc(1024 * 1024, 0x61)
    for (let i = 0; i < 16; i++) req.write(chunk)
    req.write('a') // one byte over; no req.end()
  })
  assert.equal(chunked.status, 413)
  assert.equal((JSON.parse(chunked.body) as { error: { guard: string } }).error.guard, 'message.too-long')
})

test('exactly 16 MiB is accepted (the cap is inclusive)', async (t) => {
  const a = await api(t)
  const line = 'lorem ipsum dolor sit amet\n'
  const text = line.repeat(Math.floor(MESSAGE_MAX / line.length)) + 'x'.repeat(MESSAGE_MAX % line.length)
  assert.equal(Buffer.byteLength(text), MESSAGE_MAX)
  const r = await put(a, sha(text), text)
  assert.equal(r.status, 201, r.text.slice(0, 200))
  assert.deepEqual(r.json, { sha256: sha(text), bytes: MESSAGE_MAX })
})

test('GET: missing, or a stored file that no longer hashes to its name → 400 message.missing (never another text)', async (t) => {
  const a = await api(t)
  assert.equal(guardOf(await call(a.port, { path: `/messages/${'b'.repeat(64)}` })), 'message.missing')
  const bytes = file('multibyte-5k.txt')
  const digest = sha(bytes)
  assert.equal((await put(a, digest, bytes)).status, 201)
  writeFileSync(join(a.state, 'messages', `${digest}.txt`), 'tampered', { mode: 0o600 })
  const r = await call(a.port, { path: `/messages/${digest}` })
  assert.equal(r.status, 400)
  assert.equal(guardOf(r), 'message.missing')
  assert.ok(!r.text.includes('tampered'))
  assert.equal((await call(a.port, { path: '/messages/ABC' })).status, 404)
})

test('a message upload must be text/plain; charset=utf-8 (api.content-type)', async (t) => {
  const a = await api(t)
  const r = await call(a.port, { method: 'PUT', path: `/messages/${sha('x')}`, raw: 'x', headers: { 'content-type': 'application/json' } })
  assert.equal(r.status, 415)
  assert.equal(guardOf(r), 'api.content-type')
})

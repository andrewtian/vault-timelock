// cli/test/source.test.ts — `vt source list|add` (F12-1; src/job/source.ts), in-process against a test-owned fake API on
// an ephemeral 127.0.0.1 port that mimics api/src/sources.ts (the label rule, 201/200, the source.label refusal).
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, writeFileSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import { join } from 'node:path'
import { sandboxFor } from '../src/args.ts'
import type { JobIo } from '../src/job/client.ts'
import { sourceCommand } from '../src/job/source.ts'
import { removeDir, tempDir, rejectsWith } from './lib.ts'

const TOKEN = 'cd'.repeat(32)
const LABEL = /^[a-z0-9][a-z0-9-]{0,23}$/
let T = '', server: Server, port = 0
let sources: Array<{ label: string; addedAt: number }> = []
const seen: Array<{ method: string; url: string; auth: string | undefined; body: string }> = []

before(async () => {
  T = tempDir('vt-src-')
  mkdirSync(join(T, 'local'), { recursive: true, mode: 0o700 })
  writeFileSync(join(T, 'local', 'api.token'), TOKEN, { mode: 0o600 })
  server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8')
      seen.push({ method: req.method ?? '', url: req.url ?? '', auth: req.headers.authorization, body })
      const send = (st: number, o: unknown): void => { res.writeHead(st, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)) }
      if (req.method === 'GET' && req.url === '/sources') return send(200, { sources })
      if (req.method === 'POST' && req.url === '/sources') {
        const label = (JSON.parse(body) as { label: unknown }).label
        const have = sources.find((s) => s.label === label)
        if (have) return send(200, have)
        if (typeof label !== 'string' || !LABEL.test(label)) return send(403, { error: { guard: 'source.label', message: 'a source label is 1 to 24 characters' } })
        const s = { label, addedAt: 1_791_504_000_000 }
        sources.push(s)
        return send(201, s)
      }
      send(404, { error: { guard: 'api.http', message: 'no' } })
    })
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()))
  port = (server.address() as { port: number }).port
})
after(async () => { server.closeAllConnections(); await new Promise<void>((r) => server.close(() => r())); removeDir(T) })

function io(): { io: JobIo; out: () => string } {
  let out = ''
  return { out: () => out, io: { network: 'local', env: { HOME: T, VT_HOME: T }, cwd: T, ports: { page: 1, relay: 1, api: port }, out: (t) => { out += t }, err: () => {}, ask: async () => undefined, now: () => 0 } }
}

test('vt source is a client command (the client sandbox)', () => {
  assert.equal(sandboxFor(['source', 'list']), 'client')
})

test('source list: empty, with the hint that arm needs --source once one exists; --json is the API body exactly', async () => {
  sources = []
  const a = io()
  assert.equal(await sourceCommand(['list'], a.io), 0)
  assert.match(a.out(), /^no funding sources on local .*every vt job arm needs --source <chain>=<label>\)\n$/)
  const b = io()
  assert.equal(await sourceCommand(['list', '--json'], b.io), 0)
  assert.equal(b.out(), '{"sources":[]}\n')
  assert.equal(seen.at(-1)?.auth, `Bearer ${TOKEN}`)
})

test('source add: 201 says added and never-deleted; list then shows it; --json is the API body exactly', async () => {
  sources = []
  const a = io()
  assert.equal(await sourceCommand(['add', 'pool-a'], a.io), 0)
  assert.match(a.out(), /^added funding source "pool-a" on local; sources are never deleted, and every vt job arm now needs --source <chain>=<label>\n$/)
  assert.deepEqual(JSON.parse(seen.at(-1)!.body), { label: 'pool-a' })
  const b = io()
  await sourceCommand(['add', 'pool-b', '--json'], b.io)
  assert.equal(b.out(), '{"label":"pool-b","addedAt":1791504000000}\n')
  const c = io()
  await sourceCommand(['list'], c.io)
  assert.match(c.out(), /^pool-a +added 2026-.*\npool-b +added 2026-/)
  const d = io()
  await sourceCommand(['list', '--json'], d.io)
  assert.deepEqual(JSON.parse(d.out()), { sources })
})

test('source add of an existing label: the API answers 200 and the CLI says nothing changed', async () => {
  sources = [{ label: 'pool-a', addedAt: 1_791_504_000_000 }]
  const a = io()
  assert.equal(await sourceCommand(['add', 'pool-a'], a.io), 0)
  assert.match(a.out(), /^funding source "pool-a" already exists on local \(added 2026-.*\); nothing changed\n$/)
  assert.equal(sources.length, 1)
})

test('source add of a bad label: the API\'s source.label refusal (exit 2 through the dispatcher); nothing is added', async () => {
  sources = []
  for (const bad of ['Pool', 'a_b', '-x', 'x'.repeat(25), '']) await rejectsWith(() => sourceCommand(['add', bad], io().io), 'source.label')
  assert.deepEqual(sources, [])
})

test('source: usage errors never reach the API', async () => {
  const n = seen.length
  for (const args of [[], ['bogus'], ['list', 'x'], ['add'], ['add', 'a', 'b'], ['list', '--bogus'], ['add', '--json']]) {
    await assert.rejects(() => sourceCommand(args, io().io), /usage: vt source/)
  }
  assert.equal(seen.length, n)
})

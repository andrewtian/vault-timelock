// The page server (api/serve/serve.mjs) and its gates (api/src/serve-gate.ts): an incoming Authorization (or Cookie) is
// never forwarded; the API token goes to the API only; the send ticket to the relay only; Host / Origin /
// Sec-Fetch-Site / repeats are refused with their guard; SSE replies stream unbuffered (the first event arrives before
// the upstream ends) and an abort on either side reaches the other. Fake API and relay servers, all on 127.0.0.1 port 0,
// in a temp VT_HOME with a synthetic token. One process smoke test (NODE_ENV=test for the test-only port flags).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs'
import { createServer, request } from 'node:http'
import type { IncomingHttpHeaders, IncomingMessage, Server, ServerResponse } from 'node:http'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Network } from '@vault-timelock/core/contracts'
import { checkPageRequest, proxyHeaders, responseHeaders } from '../src/serve-gate.ts'
import { SEC, SEC_WASM, WASM_PATH, buildOf, createServe, parseServeArgs } from '../serve/serve.mjs'
import { CANARY, JOB, TOKEN, makeHome, startApi, tempDir } from './helpers.ts'

const SERVE = fileURLToPath(new URL('../serve/serve.mjs', import.meta.url))
const ATTACKER = `Bearer ${'ee'.repeat(32)}`
const guardOf = (fn: () => unknown): string => { try { fn() } catch (e) { return (e as { guardId?: string }).guardId ?? String(e) } return 'passed' }

test('proxyHeaders: an allowlist per target; Authorization, Cookie and hop-by-hop never cross; the token only to the API, the ticket only to the relay', () => {
  const incoming: IncomingHttpHeaders = {
    host: '127.0.0.1:5180', authorization: ATTACKER, cookie: 'a=b', 'proxy-authorization': 'Basic eA==', connection: 'keep-alive, x-vt-send-ticket',
    'keep-alive': 'timeout=5', 'transfer-encoding': 'chunked', upgrade: 'websocket', te: 'trailers', 'x-forwarded-for': CANARY, forwarded: `for=${CANARY}`,
    accept: 'application/json', 'content-type': 'application/json', 'content-length': '12', origin: 'http://127.0.0.1:5180', 'sec-fetch-site': 'same-origin',
    'last-event-id': '4', 'x-vt-send-ticket': 'vt-ticket/1.x.y', referer: 'http://127.0.0.1:5180/', 'user-agent': 'x',
  }
  assert.deepEqual(proxyHeaders(incoming, 'api', TOKEN, 'local'), {
    accept: 'application/json', 'content-type': 'application/json', 'content-length': '12', origin: 'http://127.0.0.1:5180', 'sec-fetch-site': 'same-origin',
    'last-event-id': '4', host: '127.0.0.1:5182', authorization: `Bearer ${TOKEN}`,
  })
  assert.deepEqual(proxyHeaders(incoming, 'relay', TOKEN, 'local'), {
    accept: 'application/json', 'content-type': 'application/json', 'content-length': '12', origin: 'http://127.0.0.1:5180', 'sec-fetch-site': 'same-origin',
    'x-vt-send-ticket': 'vt-ticket/1.x.y', host: '127.0.0.1:5181',
  })
  assert.equal(proxyHeaders({}, 'api', TOKEN, 'testnet').host, '127.0.0.1:5192')
  assert.equal(proxyHeaders({}, 'relay', TOKEN, 'mainnet').host, '127.0.0.1:5201')
  assert.equal(proxyHeaders({}, 'relay', '', 'mainnet').authorization, undefined)
  for (const bad of ['', 'x', TOKEN.toUpperCase(), `${TOKEN}\n`]) assert.throws(() => proxyHeaders({}, 'api', bad, 'local'))
  assert.deepEqual(responseHeaders({ 'content-type': 'text/event-stream', 'set-cookie': ['a=b'], connection: 'close', 'cache-control': 'max-age=9', 'x-content-type-options': 'nosniff' }),
    { 'content-type': 'text/event-stream', 'x-content-type-options': 'nosniff', 'cache-control': 'no-store' })
})

const H = (...pairs: Array<[string, string]>): string[] => pairs.flat()
test('checkPageRequest: Host (serve.host); for /api and /relay Origin (serve.origin) and Sec-Fetch-Site (serve.fetch-site); repeats (serve.header-repeated)', () => {
  const host: [string, string] = ['Host', '127.0.0.1:5180']
  assert.equal(guardOf(() => checkPageRequest(H(host), { network: 'local', proxied: true, method: 'GET' })), 'passed')
  assert.equal(guardOf(() => checkPageRequest(H(['host', '127.0.0.1:5190']), { network: 'testnet', proxied: true, method: 'GET' })), 'passed')
  for (const h of ['localhost:5180', '127.0.0.1:5183', '127.0.0.1:5190', `${CANARY}:5180`, 'evil.example']) {
    assert.equal(guardOf(() => checkPageRequest(H(['host', h]), { network: 'local', proxied: false, method: 'GET' })), 'serve.host', h)
  }
  assert.equal(guardOf(() => checkPageRequest([], { network: 'local', proxied: false, method: 'GET' })), 'serve.host')
  assert.equal(guardOf(() => checkPageRequest(H(host, ['Origin', 'http://127.0.0.1:5180'], ['Sec-Fetch-Site', 'same-origin']), { network: 'local', proxied: true, method: 'GET' })), 'passed')
  for (const o of ['http://127.0.0.1:5183', 'http://127.0.0.1:5190', 'http://localhost:5180', 'null', 'http://evil.example']) {
    assert.equal(guardOf(() => checkPageRequest(H(host, ['origin', o]), { network: 'local', proxied: true, method: 'GET' })), 'serve.origin', o)
    assert.equal(guardOf(() => checkPageRequest(H(host, ['origin', o]), { network: 'local', proxied: false, method: 'GET' })), 'passed', o)   // static GETs
  }
  for (const site of ['cross-site', 'same-site']) {
    assert.equal(guardOf(() => checkPageRequest(H(host, ['sec-fetch-site', site]), { network: 'local', proxied: true, method: 'GET' })), 'serve.fetch-site', site)
    assert.equal(guardOf(() => checkPageRequest(H(host, ['sec-fetch-site', site]), { network: 'local', proxied: false, method: 'GET' })), 'passed', site)   // navigations
  }
  for (const twice of [H(host, host), H(host, ['origin', 'a'], ['Origin', 'a']), H(host, ['authorization', 'x'], ['Authorization', 'y'])]) {
    assert.equal(guardOf(() => checkPageRequest(twice, { network: 'local', proxied: false, method: 'GET' })), 'serve.header-repeated')
  }
})

test('PF-S M-3b: a proxied request other than GET needs exactly this page\'s Origin (absent is refused); GETs and static requests unchanged', () => {
  const host: [string, string] = ['Host', '127.0.0.1:5180']
  const page: [string, string] = ['Origin', 'http://127.0.0.1:5180']
  for (const method of ['POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'get', '', undefined]) {
    assert.equal(guardOf(() => checkPageRequest(H(host), { network: 'local', proxied: true, method })), 'serve.origin', `${String(method)} without Origin`)
    assert.equal(guardOf(() => checkPageRequest(H(host, ['sec-fetch-site', 'same-origin']), { network: 'local', proxied: true, method })), 'serve.origin', `${String(method)} same-origin, no Origin`)
    assert.equal(guardOf(() => checkPageRequest(H(host, page), { network: 'local', proxied: true, method })), 'passed', `${String(method)} with the page's Origin`)
    assert.equal(guardOf(() => checkPageRequest(H(host, ['origin', 'http://127.0.0.1:5190']), { network: 'local', proxied: true, method })), 'serve.origin', `${String(method)} another page`)
    assert.equal(guardOf(() => checkPageRequest(H(host), { network: 'local', proxied: false, method })), 'passed', `${String(method)} static (405 later)`)
  }
  assert.equal(guardOf(() => checkPageRequest(H(host), { network: 'local', proxied: true, method: 'GET' })), 'passed')
  assert.equal(guardOf(() => checkPageRequest(H(['Host', '127.0.0.1:5200']), { network: 'mainnet', proxied: true, method: 'POST' })), 'serve.origin')
  assert.equal(guardOf(() => checkPageRequest(H(['Host', '127.0.0.1:5200'], ['Origin', 'http://127.0.0.1:5200']), { network: 'mainnet', proxied: true, method: 'POST' })), 'passed')
})

// ---- the page server in process, with fake upstreams

interface Seen { method: string; path: string; headers: IncomingHttpHeaders; raw: string[]; body: string }
interface Fake { port: number; seen: Seen[]; server: Server; close(): Promise<void> }
async function fake(onRequest?: (req: IncomingMessage, res: ServerResponse, s: Seen) => boolean): Promise<Fake> {
  const seen: Seen[] = []
  const server = createServer((req, res) => {
    const c: Buffer[] = []
    req.on('data', (d: Buffer) => c.push(d))
    req.on('end', () => {
      const s: Seen = { method: req.method ?? '', path: req.url ?? '', headers: req.headers, raw: req.rawHeaders, body: Buffer.concat(c).toString('utf8') }
      seen.push(s)
      if (onRequest?.(req, res, s)) return
      const b = JSON.stringify({ ok: true, path: s.path })
      res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'tracker=1', 'content-length': String(Buffer.byteLength(b)) })
      res.end(b)
    })
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  return { port: (server.address() as { port: number }).port, seen, server, close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()) }) }
}

interface Page { port: number; home: string; logs: string[]; api: Fake; relay: Fake; close(): Promise<void> }
async function page(t: { after(fn: () => unknown): void }, o: { network?: Network; api?: Parameters<typeof fake>[0]; relay?: Parameters<typeof fake>[0]; token?: boolean } = {}): Promise<Page> {
  const network = o.network ?? 'local'
  const { dir, cleanup } = tempDir('vt-serve-')
  t.after(cleanup)
  const home = join(dir, 'home')
  if (o.token === false) mkdirSync(join(home, network), { recursive: true, mode: 0o700 })
  else makeHome(home, network)
  const root = join(dir, 'dist')
  mkdirSync(join(root, 'assets'), { recursive: true })
  writeFileSync(join(root, 'index.html'), '<!doctype html><title>vt</title>')
  writeFileSync(join(root, 'assets', 'app.js'), 'console.log(1)')
  writeFileSync(join(root, 'assets', 'privacycash-worker.js'), 'console.log(2)')
  writeFileSync(join(dir, 'outside.txt'), 'outside')
  const api = await fake(o.api), relay = await fake(o.relay)
  const logs: string[] = []
  const server = createServer(createServe({ network, home, root, build: 'b-test', upstreamPorts: { api: api.port, relay: relay.port }, log: (l: string) => { logs.push(l) } }))
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const port = (server.address() as { port: number }).port
  const p: Page = { port, home, logs, api, relay, close: async () => { server.closeAllConnections(); await new Promise<void>((r) => server.close(() => r())); await api.close(); await relay.close() } }
  t.after(() => p.close())
  return p
}

interface Reply { status: number; headers: IncomingHttpHeaders; text: string }
function get(p: Page, path: string, o: { method?: string; body?: string; headers?: Record<string, string | string[]>; network?: Network } = {}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const r = request({ host: '127.0.0.1', port: p.port, path, method: o.method ?? (o.body === undefined ? 'GET' : 'POST'),
      headers: { host: `127.0.0.1:${o.network === 'testnet' ? 5190 : 5180}`, ...(o.body === undefined ? {} : { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(o.body)) }), ...o.headers } }, (res) => {
      const c: Buffer[] = []
      res.on('data', (d: Buffer) => c.push(d))
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, text: Buffer.concat(c).toString('utf8') }))
    })
    r.on('error', reject)
    r.end(o.body)
  })
}
const guardIn = (r: Reply): string | undefined => { try { return (JSON.parse(r.text) as { error?: { guard?: string } }).error?.guard } catch { return undefined } }

test('an incoming Authorization is never forwarded: the API gets exactly the stack token; the relay gets none', { timeout: 30_000 }, async (t) => {
  const p = await page(t)
  const a = await get(p, '/api/status?x=1', { headers: { authorization: ATTACKER, cookie: 'session=1', origin: 'http://127.0.0.1:5180', 'sec-fetch-site': 'same-origin', 'x-vt-send-ticket': 'vt-ticket/1.a.b' } })
  assert.equal(a.status, 200)
  assert.equal(a.headers['set-cookie'], undefined)
  assert.equal(String(a.headers['content-security-policy']).startsWith("default-src 'self'"), true)
  const s = p.api.seen[0]
  assert.deepEqual([s.method, s.path], ['GET', '/status?x=1'])
  assert.deepEqual(s.raw.filter((_, i) => i % 2 === 0 && s.raw[i].toLowerCase() === 'authorization').length, 1)
  assert.equal(s.headers.authorization, `Bearer ${TOKEN}`)
  assert.equal(s.headers.host, '127.0.0.1:5182')
  assert.equal(s.headers.cookie, undefined)
  assert.equal(s.headers['x-vt-send-ticket'], undefined)                      // the ticket goes to the relay only
  assert.deepEqual([s.headers.origin, s.headers['sec-fetch-site']], ['http://127.0.0.1:5180', 'same-origin'])
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] })
  const r = await get(p, '/relay/eth', { body, headers: { authorization: ATTACKER, cookie: 'session=1', 'x-vt-send-ticket': 'vt-ticket/1.a.b', origin: 'http://127.0.0.1:5180' } })
  assert.equal(r.status, 200)
  const rs = p.relay.seen[0]
  assert.deepEqual([rs.method, rs.path, rs.body], ['POST', '/relay/eth', body])
  assert.equal(rs.headers.authorization, undefined)
  assert.equal(rs.headers.cookie, undefined)
  assert.equal(rs.headers.host, '127.0.0.1:5181')
  assert.equal(rs.headers['x-vt-send-ticket'], 'vt-ticket/1.a.b')
  const put = await get(p, '/api/messages/abc', { method: 'PUT', headers: { 'content-type': 'text/plain; charset=utf-8', 'content-length': '5', origin: 'http://127.0.0.1:5180' }, body: 'hello' })
  assert.equal(put.status, 200)
  assert.deepEqual([p.api.seen[1].method, p.api.seen[1].path, p.api.seen[1].body], ['PUT', '/messages/abc', 'hello'])
  assert.equal(p.api.seen[1].headers.authorization, `Bearer ${TOKEN}`)
  assert.equal((await get(p, '/api', {})).status, 200)
  assert.equal(p.api.seen[2].path, '/')
})

test('refusals before any upstream: foreign Origin, cross-site, foreign Host, repeated header, odd method, no token', { timeout: 30_000 }, async (t) => {
  const p = await page(t)
  const cases: Array<[string, Promise<Reply>, number, string | undefined]> = [
    ['origin', get(p, '/api/jobs', { headers: { origin: 'http://evil.example' } }), 403, 'serve.origin'],
    ['origin relay', get(p, '/relay/eth', { body: '{}', headers: { origin: 'http://127.0.0.1:5190' } }), 403, 'serve.origin'],
    ['site', get(p, '/api/jobs', { headers: { 'sec-fetch-site': 'cross-site' } }), 403, 'serve.fetch-site'],
    ['same-site', get(p, '/relay/tor', { headers: { 'sec-fetch-site': 'same-site' } }), 403, 'serve.fetch-site'],
    ['host', get(p, '/api/jobs', { headers: { host: 'localhost:5180' } }), 403, 'serve.host'],
    ['host static', get(p, '/', { headers: { host: `${CANARY}:5180` } }), 403, 'serve.host'],
    ['repeated', get(p, '/api/jobs', { headers: { authorization: [ATTACKER, ATTACKER] } }), 403, 'serve.header-repeated'],
    ['delete', get(p, '/api/jobs/x', { method: 'DELETE', headers: { origin: 'http://127.0.0.1:5180' } }), 405, undefined],
    ['put relay', get(p, '/relay/eth', { method: 'PUT', body: '{}', headers: { origin: 'http://127.0.0.1:5180' } }), 405, undefined],
    // PF-S M-3b: a POST / PUT without Origin (curl or a script that omits it) never borrows the token. A local process CAN set the
    // header (re-review N-4): this is a CSRF control, not a local-user boundary — docs/vt.md says to run vt on a single-user Mac
    ['arm without Origin', get(p, '/api/jobs/x/arm', { body: '{}' }), 403, 'serve.origin'],
    ['put without Origin', get(p, '/api/messages/abc', { method: 'PUT', body: 'hello', headers: { 'content-type': 'text/plain; charset=utf-8' } }), 403, 'serve.origin'],
    ['relay send without Origin', get(p, '/relay/eth', { body: '{}', headers: { 'sec-fetch-site': 'same-origin' } }), 403, 'serve.origin'],
    ['delete without Origin', get(p, '/api/jobs/x', { method: 'DELETE' }), 403, 'serve.origin'],
  ]
  for (const [name, pr, status, guard] of cases) {
    const r = await pr
    assert.equal(r.status, status, name)
    assert.equal(guardIn(r), guard, name)
    assert.ok(!r.text.includes(CANARY))
  }
  assert.equal(p.api.seen.length + p.relay.seen.length, 0)
  assert.ok(!p.logs.join('\n').includes(CANARY))
  for (const l of p.logs) assert.match(l, /^[A-Z]+ \d{3} \d+ms(?: [a-z0-9.-]+)?$/)
  const q = await page(t, { token: false })
  const r = await get(q, '/api/status')
  assert.deepEqual([r.status, guardIn(r)], [503, 'api.token-missing'])
  assert.equal(q.api.seen.length, 0)
  assert.equal((await get(q, '/relay/tor')).status, 200)                        // the relay needs no token
})

test('SSE streams without buffering: the first event arrives before the upstream ends; then the end passes through', { timeout: 30_000 }, async (t) => {
  let finish: (() => void) | null = null
  let upstreamEnded = false
  const p = await page(t, {
    api: (req, res) => {
      if (!req.url?.includes('/events')) return false
      res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-store' })
      res.write('id: 0\ndata: {"seq":0}\n\n')
      finish = () => { if (upstreamEnded) return; res.write('id: 1\ndata: {"seq":1}\n\n'); res.end(); upstreamEnded = true }
      setTimeout(() => finish?.(), 5000).unref()                  // a buffering proxy would wait for this, then fail below
      return true
    },
  })
  const got: string[] = []
  const ended = await new Promise<{ status: number; type: string | undefined; firstBeforeEnd: boolean }>((resolve, reject) => {
    let firstBeforeEnd = false
    const r = request({ host: '127.0.0.1', port: p.port, path: '/api/jobs/e3d45f73cf65abaa/events?from=0', headers: { host: '127.0.0.1:5180', accept: 'text/event-stream', 'last-event-id': '-' } }, (res) => {
      res.on('data', (d: Buffer) => {
        got.push(d.toString('utf8'))
        if (got.length === 1) { firstBeforeEnd = !upstreamEnded && got[0].includes('id: 0'); setTimeout(() => finish?.(), 50) }
      })
      res.on('end', () => resolve({ status: res.statusCode ?? 0, type: res.headers['content-type'], firstBeforeEnd }))
    })
    r.on('error', reject)
    r.end()
  })
  assert.equal(ended.status, 200)
  assert.equal(ended.type, 'text/event-stream; charset=utf-8')
  assert.equal(ended.firstBeforeEnd, true)
  assert.equal(got.join(''), 'id: 0\ndata: {"seq":0}\n\nid: 1\ndata: {"seq":1}\n\n')
  assert.equal(p.api.seen[0].headers['last-event-id'], '-')
})

test('aborts pass through: a client that leaves closes the upstream; an upstream that breaks off ends the client', { timeout: 30_000 }, async (t) => {
  let upstreamClosed: () => void = () => {}
  const closed = new Promise<void>((r) => { upstreamClosed = r })
  const p = await page(t, {
    api: (req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8' })
      res.write(': hb 1\n\n')
      if (req.url?.includes('break')) setTimeout(() => res.socket?.destroy(), 30)
      else res.on('close', () => upstreamClosed())
      return true
    },
  })
  await new Promise<void>((resolve, reject) => {                       // the client leaves after the first chunk
    const r = request({ host: '127.0.0.1', port: p.port, path: '/api/jobs/x/events', headers: { host: '127.0.0.1:5180' } }, (res) => {
      res.once('data', () => { r.destroy(); resolve() })
    })
    r.on('error', () => {})
    setTimeout(() => reject(new Error('no first chunk')), 5000).unref()
    r.end()
  })
  await closed
  const outcome = await new Promise<string>((resolve) => {             // the upstream breaks off mid-stream
    const r = request({ host: '127.0.0.1', port: p.port, path: '/api/jobs/break/events', headers: { host: '127.0.0.1:5180' } }, (res) => {
      res.on('data', () => {})
      res.on('end', () => resolve('ended cleanly'))
      res.on('error', () => resolve('aborted'))
      res.on('close', () => resolve(res.complete ? 'ended cleanly' : 'aborted'))
    })
    r.on('error', () => resolve('aborted'))
    r.end()
  })
  assert.equal(outcome, 'aborted')
})

test('static files, /__serve and /__stacks; no path escapes the root; malformed paths do not crash the server', { timeout: 30_000 }, async (t) => {
  const p = await page(t)
  writeFileSync(join(p.home, 'local', 'up.json'), JSON.stringify({ network: 'local', pagePort: 5180, build: 'b-test', startedAt: 1 }), { mode: 0o600 })
  const idx = await get(p, '/')
  assert.deepEqual([idx.status, idx.headers['content-type'], idx.text], [200, 'text/html; charset=utf-8', '<!doctype html><title>vt</title>'])
  for (const k of ['content-security-policy', 'x-dns-prefetch-control', 'referrer-policy', 'x-content-type-options', 'cache-control']) assert.ok(idx.headers[k], k)
  assert.equal((await get(p, '/assets/app.js')).headers['content-type'], 'text/javascript; charset=utf-8')
  assert.equal((await get(p, '/assets/app.js', { method: 'HEAD' })).text, '')
  for (const bad of ['/%2e%2e/outside.txt', '/..%2foutside.txt', '/assets/%2e%2e/%2e%2e/outside.txt']) {
    const r = await get(p, bad)
    assert.ok(r.status === 403 || r.status === 404, bad)
    assert.ok(!r.text.includes('outside'), bad)
  }
  assert.equal((await get(p, '/%E0%A4%A')).status, 404)
  assert.equal((await get(p, '/nope.js')).status, 404)
  assert.equal((await get(p, '/index.html', { method: 'POST', body: '{}' })).status, 405)
  assert.deepEqual(JSON.parse((await get(p, '/__serve')).text), { release: false, digest: null, build: 'b-test' })
  assert.deepEqual(JSON.parse((await get(p, '/__stacks')).text), [
    { network: 'local', up: true, pageUrl: 'http://127.0.0.1:5180/', build: 'b-test' },
    { network: 'testnet', up: false, pageUrl: 'http://127.0.0.1:5190/', build: null },
    { network: 'mainnet', up: false, pageUrl: 'http://127.0.0.1:5200/', build: null },
  ])
  assert.equal((await get(p, '/', { headers: { 'sec-fetch-site': 'same-site' } })).status, 200)   // a selector navigation
})

test('the command line, and the program: a ready line on an ephemeral port (test-only flags need NODE_ENV=test)', { timeout: 30_000 }, async (t) => {
  const { dir, cleanup } = tempDir('vt-serve-cli-')
  t.after(cleanup)
  const home = join(dir, 'home')
  makeHome(home, 'local')
  mkdirSync(join(dir, 'dist'))
  writeFileSync(join(dir, 'dist', 'index.html'), 'ok')
  const api = await fake(), relay = await fake()
  t.after(async () => { await api.close(); await relay.close() })
  const argv = ['--network', 'local', '--home', home, '--root', join(dir, 'dist'), '--build', 'cli1', '--port', '0', '--relay-port', String(relay.port), '--api-port', String(api.port)]
  const env = { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home }
  const refused = spawnSync(process.execPath, [SERVE, ...argv], { encoding: 'utf8', env, timeout: 30_000 })
  assert.equal(refused.status, 2)
  assert.match(refused.stderr, /^FATAL: refused api\.test-only: /)
  const bad = spawnSync(process.execPath, [SERVE, '--network', 'local', '--home', 'rel', '--root', join(dir, 'dist')], { encoding: 'utf8', env, timeout: 30_000 })
  assert.equal(bad.status, 2)
  assert.match(bad.stderr, /^FATAL: usage: /)
  const child = spawn(process.execPath, [SERVE, ...argv], { env: { ...env, NODE_ENV: 'test' }, stdio: ['ignore', 'pipe', 'pipe'] })
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL') })
  const port = await new Promise<number>((resolve, reject) => {
    let out = ''
    child.stdout.on('data', (d: Buffer) => { out += d.toString('utf8'); const m = /^vt-page ready network=local port=(\d+)$/m.exec(out); if (m) resolve(Number(m[1])) })
    child.once('exit', (c) => reject(new Error(`exited ${c}`)))
  })
  const p = { port } as Page
  assert.equal((await get(p, '/')).text, 'ok')
  assert.equal(JSON.parse((await get(p, '/api/status')).text).path, '/status')
  assert.equal(api.seen[0].headers.authorization, `Bearer ${TOKEN}`)
  const exited = new Promise<number | null>((r) => child.once('exit', (c) => r(c)))
  child.kill('SIGTERM')
  assert.equal(await exited, 0)
  assert.deepEqual(parseServeArgs(['--network', 'testnet', '--home', '/h', '--root', '/r']), { network: 'testnet', home: '/h', root: '/r', build: 'dev', port: 5190, upstreamPorts: { relay: 5191, api: 5192 } })
  assert.equal(buildOf('/Users/x/.local/state/vt/releases/0123456789ab/'), '0123456789ab')   // no --build from vt up: the release id
  for (const r of ['/repo/', '/vt/releases/', '/vt/releases/0123456789abc/', '/vt/other/0123456789ab/']) assert.equal(buildOf(r), 'dev', r)
})

test('against S1\'s real API handler: the forwarded Host, token, Origin and Sec-Fetch-Site pass its guards; SSE streams through', { timeout: 30_000 }, async (t) => {
  const api = await startApi()
  t.after(() => api.close())
  const relay = await fake()
  t.after(() => relay.close())
  const { dir, cleanup } = tempDir('vt-serve-x-')
  t.after(cleanup)
  const home = join(dir, 'home')
  makeHome(home, 'local')
  mkdirSync(join(dir, 'dist'))
  const server = createServer(createServe({ network: 'local', home, root: join(dir, 'dist'), build: 'x', upstreamPorts: { api: api.port, relay: relay.port }, log: () => {} }))
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  t.after(() => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()) }))
  const p = { port: (server.address() as { port: number }).port } as Page
  const same = { origin: 'http://127.0.0.1:5180', 'sec-fetch-site': 'same-origin' }
  const st = await get(p, '/api/status', { headers: { ...same, authorization: ATTACKER } })
  assert.equal(st.status, 200, st.text)
  assert.equal((JSON.parse(st.text) as { network: string }).network, 'local')
  const job = await get(p, `/api/jobs/${JOB}/chains/eth/lease`, { body: JSON.stringify({ op: 'nonsense' }), headers: same })
  assert.equal(job.status, 400)                                                      // reached the API's own body checks
  const chunk = await new Promise<string>((resolve, reject) => {
    const r = request({ host: '127.0.0.1', port: p.port, path: `/api/jobs/${JOB}/events?from=0`, headers: { host: '127.0.0.1:5180', ...same, accept: 'text/event-stream' } }, (res) => {
      res.once('data', (d: Buffer) => { resolve(`${res.statusCode} ${String(res.headers['content-type'])} ${d.toString('utf8')}`); r.destroy() })
    })
    r.on('error', (e) => { if (!/socket hang up|aborted/.test(String(e))) reject(e) })
    r.end()
  })
  assert.match(chunk, /^200 text\/event-stream; charset=utf-8 id: 0\ndata: \{/)
  assert.ok(api.logs.some((l) => /^api GET status 200 /.test(l)), api.logs.join(' | '))
  assert.ok(!api.logs.some((l) => / guard=api\.(?:host|origin|fetch-site|token)\b/.test(l)), api.logs.join(' | '))
  assert.ok(api.logs.some((l) => /^api POST lease 400 \d+ms guard=/.test(l)), api.logs.join(' | '))
})

test('symlinks never lead out of the root: a planted file or directory link answers 404 and leaks nothing (S3 review m1)', { timeout: 30_000 }, async (t) => {
  const p = await page(t)
  const root = join(p.home, '..', 'dist')
  writeFileSync(join(p.home, '..', 'secret.txt'), 'outside-secret')
  symlinkSync(join(p.home, '..', 'secret.txt'), join(root, 'leak.txt'))           // a file link out of the root
  symlinkSync(join(p.home, '..'), join(root, 'up'))                                // a directory link out of the root
  symlinkSync('/etc', join(root, 'assets', 'etc'))                                 // an absolute directory link
  symlinkSync(join(root, 'assets', 'app.js'), join(root, 'alias.js'))              // a link that stays inside the root
  for (const path of ['/leak.txt', '/up/secret.txt', '/up/outside.txt', '/assets/etc/hosts', '/up/home/local/api.token']) {
    const r = await get(p, path)
    assert.equal(r.status, 404, path)
    assert.ok(!r.text.includes('outside') && !r.text.includes('secret') && !/[0-9a-f]{64}/.test(r.text), path)
    assert.equal((await get(p, path, { method: 'HEAD' })).status, 404, `HEAD ${path}`)
  }
  const alias = await get(p, '/alias.js')
  assert.deepEqual([alias.status, alias.text], [200, 'console.log(1)'])
  assert.equal((await get(p, '/up/dist/index.html')).status, 200)                 // out and back in: its realpath is inside
  // the root itself may be a symlink (web/dist → a build dir): its realpath is the boundary
  const { dir, cleanup } = tempDir('vt-serve-rootlink-')
  t.after(cleanup)
  mkdirSync(join(dir, 'build'))
  writeFileSync(join(dir, 'build', 'index.html'), 'linked root')
  symlinkSync(join(dir, 'build'), join(dir, 'dist'))
  makeHome(join(dir, 'home'), 'local')
  const server = createServer(createServe({ network: 'local', home: join(dir, 'home'), root: join(dir, 'dist'), build: 'x', upstreamPorts: { api: 9, relay: 9 }, log: () => {} }))
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  t.after(() => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()) }))
  const q = { port: (server.address() as { port: number }).port } as Page
  assert.equal((await get(q, '/')).text, 'linked root')
})

// ---- Sfix-PC item 2: x-vt-pc-lane crosses to the relay on /relay/privacycash/* ONLY
test('proxyHeaders: x-vt-pc-lane is forwarded to the relay on /relay/privacycash/* only — never to the API, never on another relay path, never when the path is not given', () => {
  const incoming: IncomingHttpHeaders = { accept: 'application/json', 'x-vt-pc-lane': 'v2.lane.header', 'x-vt-send-ticket': 'vt-ticket/1.x.y', authorization: ATTACKER }
  const lane = { 'x-vt-pc-lane': 'v2.lane.header' }
  for (const path of ['/relay/privacycash/relayer/withdraw', '/relay/privacycash/rpc', '/relay/privacycash/relayer/config']) {
    assert.deepEqual(proxyHeaders(incoming, 'relay', TOKEN, 'local', path), { accept: 'application/json', 'x-vt-send-ticket': 'vt-ticket/1.x.y', ...lane, host: '127.0.0.1:5181' }, path)
  }
  for (const path of ['/relay/sol', '/relay/eth', '/relay/privacycash', '/relay/privacycashx/relayer/withdraw', '/relay/privacycash', '/relay//privacycash/relayer/withdraw', '/RELAY/PRIVACYCASH/relayer/withdraw', '/api/relay/privacycash/x', '']) {
    assert.equal(proxyHeaders(incoming, 'relay', TOKEN, 'local', path)['x-vt-pc-lane'], undefined, path)
  }
  assert.equal(proxyHeaders(incoming, 'relay', TOKEN, 'local')['x-vt-pc-lane'], undefined, 'no path given')
  assert.equal(proxyHeaders(incoming, 'api', TOKEN, 'local', '/relay/privacycash/relayer/withdraw')['x-vt-pc-lane'], undefined, 'never to the API')
  assert.equal(proxyHeaders({ 'x-vt-pc-lane': ['a', 'b'] }, 'relay', TOKEN, 'local', '/relay/privacycash/relayer/withdraw')['x-vt-pc-lane'], undefined, 'a list is not forwarded')
})

test('serve.mjs hands the request path to proxyHeaders: the lane header reaches the relay on /relay/privacycash/relayer/withdraw and not on /relay/sol; the API never gets it', { timeout: 30_000 }, async (t) => {
  const p = await page(t)
  const body = JSON.stringify({ x: 1 })
  const lane = 'v2.Vote111111111111111111111111111111111111111.e3d45f73cf65abaa.0.1.aa.bb.1.cc'
  const w = await get(p, '/relay/privacycash/relayer/withdraw', { body, headers: { 'x-vt-pc-lane': lane, authorization: ATTACKER, origin: 'http://127.0.0.1:5180' } })
  assert.equal(w.status, 200)
  const ws = p.relay.seen[0]
  assert.deepEqual([ws.path, ws.headers['x-vt-pc-lane'], ws.headers.authorization], ['/relay/privacycash/relayer/withdraw', lane, undefined])
  const s = await get(p, '/relay/sol', { body, headers: { 'x-vt-pc-lane': lane, origin: 'http://127.0.0.1:5180' } })
  assert.equal(s.status, 200)
  assert.equal(p.relay.seen[1].headers['x-vt-pc-lane'], undefined)
  const a = await get(p, '/api/jobs', { headers: { 'x-vt-pc-lane': lane } })
  assert.equal(a.status, 200)
  assert.equal(p.api.seen[0].headers['x-vt-pc-lane'], undefined)
})

const cspOf = (v: string) => Object.fromEntries(v.split('; ').map((d) => { const [k, ...r] = d.split(' '); return [k, r] }))
const BASE_CSP = {
  'default-src': ["'self'"], 'connect-src': ["'self'"], 'img-src': ["'self'", 'data:', 'blob:'], 'style-src': ["'self'", "'unsafe-inline'"],
  'script-src': ["'self'"], 'object-src': ["'none'"], 'frame-src': ["'none'"], 'frame-ancestors': ["'none'"],
  'form-action': ["'none'"], 'base-uri': ["'none'"],
}
test('the page CSP (W6, m-1): SEC has no WebAssembly compile right; SEC_WASM adds exactly \'wasm-unsafe-eval\' to script-src; no worker-src, no blob: script, no eval, nothing else widened', () => {
  assert.deepEqual(cspOf(SEC['content-security-policy']), BASE_CSP)
  assert.deepEqual(cspOf(SEC_WASM['content-security-policy']), { ...BASE_CSP, 'script-src': ["'self'", "'wasm-unsafe-eval'"] })
  for (const csp of [SEC['content-security-policy'], SEC_WASM['content-security-policy']]) {
    assert.equal(csp.includes("'unsafe-eval'"), false)
    assert.equal(csp.includes('worker-src'), false)      // a same-origin worker script falls back to script-src 'self'; blob: workers stay refused
    assert.equal(/script-src[^;]*(blob:|data:|https?:|\*)/.test(csp), false)
    assert.equal(/connect-src[^;]*(https?:|wss?:|\*)/.test(csp), false)
  }
  assert.deepEqual({ ...SEC_WASM, 'content-security-policy': '' }, { ...SEC, 'content-security-policy': '' })   // only the CSP differs
})

test('m-1: over HTTP only the Privacy Cash worker script carries wasm-unsafe-eval; the index, other assets, errors, the proxy and /__serve never do', { timeout: 30_000 }, async (t) => {
  const p = await page(t)
  const csp = (r: Reply) => String(r.headers['content-security-policy'])
  assert.equal(WASM_PATH, '/assets/privacycash-worker.js')
  const w = await get(p, WASM_PATH)
  assert.equal(w.status, 200); assert.equal(csp(w), SEC_WASM['content-security-policy']); assert.match(csp(w), /'wasm-unsafe-eval'/)
  for (const path of ['/', '/index.html', '/assets/app.js', '/assets/privacycash-worker.js.map', '/assets/Privacycash-worker.js', '/assets/x/../app.js', '/nope', '/__serve', '/__stacks', '/api/status', '/relay/release']) {
    const r = await get(p, path)
    assert.equal(csp(r), SEC['content-security-policy'], path)
    assert.equal(csp(r).includes('wasm-unsafe-eval'), false, path)
  }
})

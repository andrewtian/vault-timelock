// Spec §5.1 guards on every request, through the real handler on an ephemeral port: Host, Origin, Sec-Fetch-Site,
// token, content type, body cap, JSON. Error replies are JSON, carry the guard, and never echo input; the canary
// 203.0.113.77 never appears in a reply or a log line.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { connect } from 'node:net'
import { CANARY, TOKEN, call, guardOf, startApi } from './helpers.ts'
import type { TestApi } from './helpers.ts'

const JSON_CT = 'application/json; charset=utf-8'

function raw(port: number, text: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = connect({ host: '127.0.0.1', port })
    const chunks: Buffer[] = []
    s.on('data', (c: Buffer) => chunks.push(c))
    s.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    s.on('error', reject)
    s.end(text)
  })
}
const statusOf = (reply: string): number => Number(/^HTTP\/1\.1 (\d{3})/.exec(reply)?.[1] ?? 0)

async function withApi(t: { after(fn: () => Promise<void>): void }, network: 'local' | 'testnet' = 'local'): Promise<TestApi> {
  const a = await startApi({ network })
  t.after(() => a.close())
  return a
}

test('Host: exactly 127.0.0.1:<the API port>, else 403 api.host', async (t) => {
  const a = await withApi(t)
  assert.equal((await call(a.port, { path: '/status' })).status, 200)
  for (const [i, host] of ['localhost:5182', 'evil.test', '127.0.0.1', '127.0.0.1:5192', '127.0.0.1:5180', `${CANARY}:5182`, '127.0.0.1:5182.evil.test'].entries()) {
    const r = await call(a.port, { path: '/status', headers: { host } })
    assert.equal(r.status, 403, `host #${i}`)
    assert.equal(guardOf(r), 'api.host', `host #${i}`)
    assert.equal(r.headers['content-type'], JSON_CT)
  }
  const none = await raw(a.port, `GET /status HTTP/1.0\r\nAuthorization: Bearer ${TOKEN}\r\n\r\n`)
  assert.equal(statusOf(none), 403)
  assert.match(none, /"guard":"api\.host"/)
  const twice = await raw(a.port, `GET /status HTTP/1.1\r\nHost: 127.0.0.1:5182\r\nHost: evil.test\r\nAuthorization: Bearer ${TOKEN}\r\nConnection: close\r\n\r\n`)
  assert.equal(statusOf(twice), 403)
  assert.match(twice, /"guard":"api\.host"/)
})

test('Host on testnet: 127.0.0.1:5192 only', async (t) => {
  const a = await withApi(t, 'testnet')
  assert.equal((await call(a.port, { path: '/status', network: 'testnet' })).status, 200)
  assert.equal(guardOf(await call(a.port, { path: '/status', headers: { host: '127.0.0.1:5182' } })), 'api.host')
})

test('Origin: absent, or this network\'s page (and Vite dev on local only), else 403 api.origin', async (t) => {
  const a = await withApi(t)
  for (const origin of ['http://127.0.0.1:5180', 'http://127.0.0.1:5183']) assert.equal((await call(a.port, { path: '/status', headers: { origin } })).status, 200, origin)
  for (const [i, origin] of ['http://127.0.0.1:5190', 'http://127.0.0.1:5200', 'null', 'http://localhost:5180', 'https://127.0.0.1:5180',
    'http://127.0.0.1:5180/', 'http://evil.test', `http://${CANARY}:5180`, ''].entries()) {
    const r = await call(a.port, { path: '/status', headers: { origin } })
    assert.equal(r.status, 403, `origin #${i}`)
    assert.equal(guardOf(r), 'api.origin', `origin #${i}`)
  }
  const twice = await raw(a.port, `GET /status HTTP/1.1\r\nHost: 127.0.0.1:5182\r\nOrigin: http://127.0.0.1:5180\r\nOrigin: http://127.0.0.1:5180\r\nAuthorization: Bearer ${TOKEN}\r\nConnection: close\r\n\r\n`)
  assert.match(twice, /"guard":"api\.origin"/)
})

test('Origin on testnet: its own page 5190; Vite dev 5183 and the local page are refused', async (t) => {
  const a = await withApi(t, 'testnet')
  assert.equal((await call(a.port, { path: '/status', network: 'testnet', headers: { origin: 'http://127.0.0.1:5190' } })).status, 200)
  for (const origin of ['http://127.0.0.1:5183', 'http://127.0.0.1:5180']) {
    assert.equal(guardOf(await call(a.port, { path: '/status', network: 'testnet', headers: { origin } })), 'api.origin', origin)
  }
})

test('Sec-Fetch-Site: cross-site and same-site (and anything unknown) → 403 api.fetch-site', async (t) => {
  const a = await withApi(t)
  for (const site of ['same-origin', 'none']) assert.equal((await call(a.port, { path: '/status', headers: { 'sec-fetch-site': site } })).status, 200, site)
  for (const site of ['cross-site', 'same-site', 'Cross-Site', 'whatever', '']) {
    const r = await call(a.port, { path: '/status', headers: { 'sec-fetch-site': site } })
    assert.equal(r.status, 403, site)
    assert.equal(guardOf(r), 'api.fetch-site', site)
  }
})

test('token: missing or wrong → 401 api.token', async (t) => {
  const a = await withApi(t)
  for (const [i, authorization] of [null, 'Bearer wrong-token', `Bearer ${TOKEN}x`, TOKEN, `bearer ${TOKEN}`, `Bearer ${CANARY}`].entries()) {
    const r = await call(a.port, { path: '/status', headers: { authorization } })
    assert.equal(r.status, 401, `authorization #${i}`)
    assert.equal(guardOf(r), 'api.token')
    assert.equal(r.headers['content-type'], JSON_CT)
  }
  const twice = await raw(a.port, `GET /status HTTP/1.1\r\nHost: 127.0.0.1:5182\r\nAuthorization: Bearer ${TOKEN}\r\nAuthorization: Bearer ${TOKEN}\r\nConnection: close\r\n\r\n`)
  assert.equal(statusOf(twice), 401)
})

test('content type: a POST must be JSON → else 415 api.content-type; a GET carries no body', async (t) => {
  const a = await withApi(t)
  const path = `/jobs/e3d45f73cf65abaa/chains/eth/lease`
  const ok = await call(a.port, { path, body: { op: 'acquire', holder: 'browser' }, headers: { 'content-type': 'application/json; charset=utf-8' } })
  assert.equal(ok.status, 200)
  for (const ct of ['text/plain', 'text/plain; charset=utf-8', 'application/json; charset=latin1', 'application/jsonx', 'multipart/form-data', null]) {
    const r = await call(a.port, { path, raw: '{}', headers: { 'content-type': ct } })
    assert.equal(r.status, 415, String(ct))
    assert.equal(guardOf(r), 'api.content-type')
  }
  const getWithBody = await call(a.port, { method: 'GET', path: '/status', raw: '{}' })
  assert.equal(getWithBody.status, 415)
  assert.equal(guardOf(getWithBody), 'api.content-type')
})

test('body cap: 65,537 bytes → 413 api.body-cap; 65,536 bytes pass the cap', async (t) => {
  const a = await withApi(t)
  const big = await call(a.port, { path: '/jobs', raw: 'a'.repeat(65_537) })
  assert.equal(big.status, 413)
  assert.equal(guardOf(big), 'api.body-cap')
  // S1 review m3: unconditional. With the declared-length check gone the server would wait for a body that never comes, and this
  // call would time out (the baseline answers in milliseconds), so a timeout fails the test instead of skipping the assertion.
  const declared = await call(a.port, { path: '/jobs', raw: '{}', headers: { 'content-length': '70000' } })
  assert.equal(declared.status, 413)
  assert.equal(guardOf(declared), 'api.body-cap')
  const atCap = await call(a.port, { path: '/jobs', raw: `"${'a'.repeat(65_534)}"` })
  assert.equal(atCap.status, 400) // past the guards: a JSON string is not a vt-job/1 job
  assert.equal(guardOf(atCap), 'job.format')
  const chunked = await raw(a.port, `POST /jobs HTTP/1.1\r\nHost: 127.0.0.1:5182\r\nAuthorization: Bearer ${TOKEN}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n10001\r\n${'a'.repeat(0x10001)}\r\n0\r\n\r\n`)
  assert.equal(statusOf(chunked), 413)
})

test('JSON: not JSON, not UTF-8, a BOM, empty, or two values → 400 api.json', async (t) => {
  const a = await withApi(t)
  const path = `/jobs/e3d45f73cf65abaa/chains/eth/lease`
  for (const body of [Buffer.from('{'), Buffer.from([0x7b, 0xff, 0x7d]), Buffer.from('﻿{}'), Buffer.from(''), Buffer.from('{} {}'), Buffer.from(`{"op":"${CANARY}`)]) {
    const r = await call(a.port, { path, raw: body })
    assert.equal(r.status, 400)
    assert.equal(guardOf(r), 'api.json')
  }
})

test('error replies never echo input; the canary is in no reply and no log line', async (t) => {
  const a = await withApi(t)
  const probes: Array<Parameters<typeof call>[1]> = [
    { path: '/status', headers: { host: `${CANARY}:5182` } },
    { path: '/status', headers: { origin: `http://${CANARY}` } },
    { path: '/status', headers: { 'sec-fetch-site': CANARY } },
    { path: '/status', headers: { authorization: `Bearer ${CANARY}` } },
    { path: `/status?x=${CANARY}`, headers: { authorization: null } },
    { path: `/${CANARY}` },
    { path: `/jobs/e3d45f73cf65abaa/chains/eth/lease?${CANARY}`, body: { op: CANARY, holder: CANARY } },
    { path: `/jobs/e3d45f73cf65abaa/chains/eth/lease`, body: { op: 'acquire', holder: CANARY } },
    { path: `/jobs/e3d45f73cf65abaa/chains/eth/events`, body: { gen: 1, type: CANARY, data: { text: CANARY } } },
    { path: `/jobs/e3d45f73cf65abaa/chains/eth/events`, body: { gen: 1, type: 'note', data: { text: CANARY } } },
    { path: `/jobs/e3d45f73cf65abaa/chains/eth/tickets`, body: { gen: 1, txId: CANARY } },
    { path: `/jobs/e3d45f73cf65abaa/events?from=${CANARY}` },
    { path: '/jobs', raw: `${CANARY}`.repeat(6000) },
    { path: '/jobs', raw: `{"${CANARY}"` },
  ]
  for (const [i, p] of probes.entries()) {
    const r = await call(a.port, p)
    assert.ok(r.status >= 400, `probe #${i}`)
    assert.ok(!r.text.includes(CANARY), `probe #${i}: the reply echoes input`)
    assert.ok(!JSON.stringify(r.headers).includes(CANARY), `probe #${i}: a reply header echoes input`)
    assert.equal(r.headers['content-type'], JSON_CT)
    const e = (r.json as { error: { guard: string; message: string } }).error
    assert.deepEqual(Object.keys(e), ['guard', 'message'])
  }
  assert.ok(a.logs.length >= probes.length)
  for (const l of a.logs) {
    assert.ok(!l.includes(CANARY), 'a log line carries the canary')
    assert.match(l, /^api (?:GET|POST|PUT|OTHER) [a-z-]+ \d{3} \d+ms(?: guard=[a-z0-9.-]+)?$/)
  }
})

test('an unknown endpoint, or an absolute-form target, is 404 (after the guards)', async (t) => {
  const a = await withApi(t)
  assert.equal((await call(a.port, { path: '/nope' })).status, 404)
  assert.equal((await call(a.port, { method: 'DELETE', path: '/status' })).status, 404)
  const abs = await raw(a.port, `GET http://127.0.0.1:5182/status HTTP/1.1\r\nHost: 127.0.0.1:5182\r\nAuthorization: Bearer ${TOKEN}\r\nConnection: close\r\n\r\n`)
  assert.equal(statusOf(abs), 404)
  assert.equal((await call(a.port, { path: '/nope', headers: { authorization: null } })).status, 401) // guards first
})

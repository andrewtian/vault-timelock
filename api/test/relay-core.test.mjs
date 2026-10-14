// node --test test/relay-core.test.mjs — Tor circuit control + retry policy of the relay (fake transport, fake clock).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createTor, exchange, errLabel, classify } from '../relay/relay-core.mjs'

const clockAt = (t0 = 1_000_000) => { let t = t0; return { now: () => t, advance: (ms) => { t += ms } } }
const seq = (...outs) => { const calls = []; const fn = async (url, user) => { calls.push({ url, user }); const o = outs[Math.min(calls.length - 1, outs.length - 1)]; if (o instanceof Error) throw o; return o } ; fn.calls = calls; return fn }
const timeout = () => Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })
const socksErr = () => Object.assign(new Error('Socks5 proxy rejected connection - HostUnreachable'), { name: 'SocksClientError' })
const ok200 = { status: 200, body: Buffer.from('{"jsonrpc":"2.0","id":1,"result":"0x1"}') }

test('gen bump → a different SOCKS username; roles never share one; gens never reused', () => {
  let n = 0; const t = createTor({ profile: 'mainnet', rand: () => `s${n++}` })
  const u0 = t.username('eth')
  assert.equal(u0, 'eth.s0.0')
  assert.notEqual(t.username('eth'), t.username('sol'))
  assert.equal(new Set(['eth', 'sol', 'price', 'check'].map((r) => t.username(r))).size, 4)
  t.bump('eth'); assert.equal(t.username('eth'), 'eth.s0.1'); assert.notEqual(t.username('eth'), u0)
  t.bump('eth'); assert.equal(t.roles.eth.gen, 2)
  assert.equal(t.username('sol'), 'sol.s1.0')                            // other roles untouched
})
test('manual "New circuit": 1 per role per 10 s', () => {
  const c = clockAt(); const t = createTor({ profile: 'mainnet', now: c.now })
  assert.deepEqual(t.manual('sol'), { ok: true, gen: 1 })
  const r = t.manual('sol'); assert.equal(r.ok, false); assert.equal(r.retryInSec, 10); assert.equal(t.roles.sol.gen, 1)
  assert.equal(t.manual('eth').ok, true)                                 // per role
  c.advance(9999); assert.equal(t.manual('sol').ok, false)
  c.advance(1); assert.deepEqual(t.manual('sol'), { ok: true, gen: 2 })
})
test('auto-rotate: a 403 → new circuit, the SAME request retried once → success', async () => {
  const t = createTor({ profile: 'mainnet', rand: () => 'x' }); const logs = []
  const req = seq({ status: 403, body: Buffer.from('blocked') }, ok200)
  const r = await exchange(t, { role: 'eth', endpoints: ['https://a', 'https://b'], doRequest: req, log: (l) => logs.push(l) })
  assert.equal(r.res.status, 200)
  assert.deepEqual(req.calls, [{ url: 'https://a', user: 'eth.x.0' }, { url: 'https://a', user: 'eth.x.1' }])
  assert.match(logs[0], /^tor eth gen 0→1 403 \d+ms$/)
  assert.equal(t.roles.eth.failCount, 1); assert.equal(t.roles.eth.okCount, 1); assert.equal(t.roles.eth.lastError, 'HTTP 403')
})
test('auto-rotate: still refused after the retry → fail over to the next endpoint (with another fresh circuit)', async () => {
  const t = createTor({ profile: 'mainnet', rand: () => 'x' })
  const req = seq({ status: 429 }, { status: 429 }, ok200)
  const r = await exchange(t, { role: 'sol', endpoints: ['https://a', 'https://b'], doRequest: req })
  assert.equal(r.res.status, 200)
  assert.deepEqual(req.calls.map((c) => `${c.url} ${c.user}`), ['https://a sol.x.0', 'https://a sol.x.1', 'https://b sol.x.1'])
})
test('a timed-out SEND is never retried and never failed over (ambiguous → re-checked by receipt/status)', async () => {
  const t = createTor({ profile: 'mainnet', rand: () => 'x' })
  const req = seq(timeout(), ok200)
  const r = await exchange(t, { role: 'eth', endpoints: ['https://a', 'https://b'], send: true, doRequest: req })
  assert.equal(r.ambiguous, true); assert.equal(r.label, 'ETIMEDOUT')
  assert.equal(req.calls.length, 1); assert.equal(t.roles.eth.gen, 0)
  for (const out of [{ status: 503 }, { status: 502 }, Object.assign(new Error('reset'), { code: 'ECONNRESET' })]) {
    const q = seq(out, ok200); const x = await exchange(t, { role: 'sol', endpoints: ['https://a', 'https://b'], send: true, doRequest: q })
    assert.equal(x.ambiguous, true); assert.equal(q.calls.length, 1)
  }
})
test('a SEND refused before processing (429 / SOCKS failure) IS retried on a new circuit', async () => {
  const t = createTor({ profile: 'mainnet', rand: () => 'x' })
  const q1 = seq({ status: 429 }, ok200)
  assert.equal((await exchange(t, { role: 'sol', endpoints: ['https://a'], send: true, doRequest: q1 })).res.status, 200)
  assert.deepEqual(q1.calls.map((c) => c.user), ['sol.x.0', 'sol.x.1'])
  const q2 = seq(socksErr(), ok200)
  assert.equal((await exchange(t, { role: 'eth', endpoints: ['https://a'], send: true, doRequest: q2 })).res.status, 200)
  assert.deepEqual(q2.calls.map((c) => c.user), ['eth.x.0', 'eth.x.1'])
  const q3 = seq({ status: 403 })
  const r3 = await exchange(t, { role: 'eth', endpoints: ['https://a', 'https://b'], send: true, doRequest: q3 })
  assert.equal(r3.failed, true); assert.equal(r3.notAccepted, true)
  assert.deepEqual(q3.calls.map((c) => `${c.url} ${c.user.split('.').pop()}`), ['https://a 1', 'https://a 2', 'https://b 2', 'https://b 3'])   // one fresh-circuit retry per endpoint
})
test('a timed-out READ is retried once on a new circuit', async () => {
  const t = createTor({ profile: 'mainnet', rand: () => 'x' })
  const req = seq(timeout(), ok200)
  assert.equal((await exchange(t, { role: 'price', endpoints: ['https://jup'], doRequest: req })).res.status, 200)
  assert.deepEqual(req.calls.map((c) => c.user), ['price.x.0', 'price.x.1'])
})
test('auto-rotate OFF → no new circuit (plain failover); local profile → never a circuit', async () => {
  const t = createTor({ profile: 'mainnet', rand: () => 'x' }); t.state.auto = false
  const req = seq({ status: 403 }, ok200)
  assert.equal((await exchange(t, { role: 'eth', endpoints: ['https://a', 'https://b'], doRequest: req })).res.status, 200)
  assert.deepEqual(req.calls.map((c) => `${c.url} ${c.user}`), ['https://a eth.x.0', 'https://b eth.x.0'])
  const l = createTor({ profile: 'local', rand: () => 'x' })
  const q = seq({ status: 503 })
  const r = await exchange(l, { role: 'eth', endpoints: ['http://local'], doRequest: q })
  assert.equal(r.failed, true); assert.equal(q.calls.length, 1); assert.equal(l.roles.eth.gen, 0)
})
test('error labels and status never carry an IP', () => {
  assert.equal(errLabel(socksErr()), 'SOCKS HostUnreachable')
  assert.equal(errLabel(Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:9050'), { code: 'ECONNREFUSED' })), 'ECONNREFUSED')
  const l = errLabel(Object.assign(new Error('x'), { name: 'SocksClientError', message: 'Socks5 proxy rejected connection - 198.51.100.23' }))
  assert.ok(l.startsWith('SOCKS') && !/\d+\.\d+\.\d+\.\d+/.test(l))
  assert.equal(classify({ status: 451 }), 'refused'); assert.equal(classify({ status: 500 }), 'server'); assert.equal(classify({ status: 400 }), 'ok')
  const t = createTor({ profile: 'mainnet' }); t.record('check', 'refused', 'HTTP 403')
  assert.ok(!/\d+\.\d+\.\d+\.\d+/.test(JSON.stringify(t.status())))
  assert.deepEqual(Object.keys(t.status().roles), ['eth', 'sol', 'price', 'check'])
})

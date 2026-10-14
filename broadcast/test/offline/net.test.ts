// Net layer (spec B s2a, s6.1, s6.3): per-role Tor circuits over socks5h, the side guard, the
// lazy Tor gate, loopback-direct, body cap, timeouts, redirects, poisoned globals, JSON-RPC.
// Offline only: a fake SOCKS5 server (test/fakes/socks5.ts) routes every CONNECT to a local fixture
// server, loopback requests reach the fixture directly, and ReplayTransport answers from fixtures.
//
// The gate opens only through torGate (src/net/gate.ts). Tests that need an open gate run the real
// torGate: its RFC 1928 probe hits a fake SOCKS server, and its check request is answered by a test
// transport (withCheck) that hands every other request to the real exchange (`real`), so the SOCKS
// path is still the production one. The side guard is per tick across instances, so every test
// uses its own fresh tick: a canonical ISO minute (net.tick-format), one minute later each time, so
// the side guard's pruning (it remembers the newest tick and the 2 before it) only ever drops ticks
// of earlier tests.
import { test, before, after, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import http, { type ClientRequest } from 'node:http'
import https from 'node:https'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { inspect } from 'node:util'
import { Refusal } from '../../src/guard.ts'
import { assertRole, sideOf } from '../../src/net/roles.ts'
import { BODY_CAP, RpcError, TOR_CHECK_URL, createNet, sideTicks, timeoutFor } from '../../src/net/fetch.ts'
import { torGate } from '../../src/net/gate.ts'
import { poisonGlobals, restoreGlobals } from '../../src/net/poison.ts'
import type { Transport, TransportRequest, TransportResponse } from '../../src/net/transport.ts'
import { closedPort, startSocks5, type FakeSocks, type FakeSocksOptions } from '../fakes/socks5.ts'
import { CANARY, startFixtureHttp, type FixtureHttp } from '../fakes/http.ts'
import { ReplayTransport, loadFixture, type Fixture } from '../fakes/replay.ts'
import { assertSendAllowed, type SendPermit } from '../../src/config.ts'

let seq = 0
const BASE_MS = Date.UTC(2026, 9, 8, 3, 15)
const minute = (n: number): string => `${new Date(BASE_MS + n * 60_000).toISOString().slice(0, 16)}Z`
const fresh = (): string => minute(++seq)
const ONION = 'vtfake' + 'x'.repeat(50) // 56 base32 characters
const ONION_HOST = `${ONION}.onion`
const onionUrl = (path: string) => `http://${ONION_HOST}${path}`
const NET_TIMEOUT = { timeout: 30_000 }

// ---- globals: every createNet without a transport poisons them; restore after each test.
const G = globalThis as Record<string, unknown>
const ORIGINAL = { fetch: G.fetch, WebSocket: G.WebSocket, EventSource: G.EventSource, httpAgent: http.globalAgent, httpsAgent: https.globalAgent }
afterEach(restoreGlobals)

// ---- the gate's probe target (default mode: picks username/password, like Tor)
let probeSocks: FakeSocks
before(async () => { probeSocks = await startSocks5({ targetPort: await closedPort() }) })
after(async () => { await probeSocks.close() })

// ---- helpers
const isRefusal = (id: string) => (e: unknown) => e instanceof Refusal && e.guardId === id
const refused = (f: () => unknown, id: string) => assert.throws(f, isRefusal(id), `expected ${id}`)
const rejects = (p: Promise<unknown>, id: string) => assert.rejects(p, isRefusal(id), `expected ${id}`)

async function caught(p: Promise<unknown>): Promise<unknown> {
  try { await p } catch (e) { return e }
  return assert.fail('expected a rejection')
}
// Never print the error itself: if it leaked the canary, printing it would leak it again.
function leaksCanary(e: unknown): boolean {
  const parts = [String(e), inspect(e, { depth: 8, showHidden: true })]
  if (e instanceof Error) parts.push(e.message, String(e.stack))
  return parts.join('\n').includes(CANARY)
}

const enc = (s: string) => new TextEncoder().encode(s)
const okResponse = (body = '{"ok":true}', status = 200): TransportResponse =>
  ({ status, headers: { 'content-type': 'application/json' }, body: enc(body) })
function recorder(answer: (req: TransportRequest) => Promise<TransportResponse> = async () => okResponse()) {
  const calls: TransportRequest[] = []
  const t: Transport = async (req) => { calls.push(req); return answer(req) }
  return Object.assign(t, { calls })
}

async function withFakes(o: Partial<FakeSocksOptions>, run: (f: { http: FixtureHttp; socksPort: number; socks: FakeSocks }) => Promise<void>) {
  const http = await startFixtureHttp()
  const socks = await startSocks5({ targetPort: http.port, ...o })
  try { await run({ http, socksPort: socks.port, socks }) } finally { await socks.close(); await http.close() }
}
// Answers the gate's check request (IsTor true); everything else goes to `inner`, else to the real
// exchange (SOCKS or loopback), exactly as without a transport.
const withCheck = (inner?: Transport): Transport => async (req, real) =>
  req.method === 'GET' && req.url === TOR_CHECK_URL ? okResponse('{"IsTor":true}')
    : inner !== undefined ? inner(req, real) : real()
interface Extra { tick?: string; maxTimeoutMs?: number; permit?: SendPermit }
// A net whose gate was opened by the real torGate; requests go over the real SOCKS path to `socksPort`.
async function gated(socksPort: number, extra: Extra = {}) {
  const n = createNet({ tick: extra.tick ?? fresh(), socksPort, maxTimeoutMs: extra.maxTimeoutMs, transport: withCheck() })
  await torGate(n, {})
  return n
}
// A net whose gate was opened by the real torGate; requests go to the test transport `inner`.
async function gatedT(inner: Transport, extra: Extra = {}) {
  const n = createNet({ tick: extra.tick ?? fresh(), socksPort: probeSocks.port, maxTimeoutMs: extra.maxTimeoutMs, transport: withCheck(inner), permit: extra.permit })
  await torGate(n, {})
  return n
}
const notCheck = (e: { role: string }) => e.role !== 'check'

// ---- roles

const GOOD_ROLES = [
  'd-railgun-eth', 'pool-railgun-eth', 'pub-j1-eth', 'pub-j1-arb', 'pub-j1-base', 'pub-job-2-sol', 'pub-j1-btc',
  'l1hop-j1', 'l2-j1-arb', 'l2-j1-base', 'btcw-j1', 'btck-j1', 'swap-j1', 'arweave-j1', 'waku-j1',
  'drand', 'check', 'artifacts',
]
const BAD_ROLES: unknown[] = [
  '', 'D-railgun-eth', 'd-railgun-arb', 'pool-railgun-arb', 'pub-j1-doge', 'pub--eth', 'pub-j1-eth.x', 'pub-J1-eth',
  'l2-j1-eth', 'l2-j1-sol', 'l1hop-', 'waku-', 'drand ', ' check', 'check\n', 'checks', 'artifact', 'x',
  'pub-j1_x-eth', 'pub-j1-eth\u0000', `pub-${'a'.repeat(200)}-eth`, 42, null, undefined, ['drand'],
]

test('net.role: the role grammar, good and bad; fetchFor/jsonRpc/sideOf refuse a bad role', () => {
  for (const r of GOOD_ROLES) assert.doesNotThrow(() => assertRole(r), r)
  for (const r of BAD_ROLES) refused(() => assertRole(r as string), 'net.role')
  refused(() => sideOf('bogus'), 'net.role')
  const net = createNet({ tick: fresh(), transport: recorder() })
  refused(() => net.fetchFor('bogus'), 'net.role')
  refused(() => net.jsonRpc('D-railgun-eth', 'https://rpc.eth.example/'), 'net.role')
})

test('sideOf: deposit / publication / neutral table', () => {
  const want: Record<string, string> = {
    'd-railgun-eth': 'deposit',
    'pub-j1-eth': 'publication', 'pub-j1-sol': 'publication', 'l1hop-j1': 'publication', 'l2-j1-arb': 'publication',
    'l2-j1-base': 'publication', 'btcw-j1': 'publication', 'btck-j1': 'publication', 'swap-j1': 'publication',
    'arweave-j1': 'publication', 'waku-j1': 'publication',
    'pool-railgun-eth': 'neutral', drand: 'neutral', check: 'neutral', artifacts: 'neutral',
  }
  for (const r of GOOD_ROLES) assert.ok(Object.hasOwn(want, r) || r.startsWith('pub-'), `table covers ${r}`)
  for (const [r, s] of Object.entries(want)) assert.equal(sideOf(r), s, r)
})

// ---- construction

test('net.ctx: socksPort and maxTimeoutMs are validated', () => {
  for (const socksPort of [0, -1, 65536, 1.5, Number.NaN, '9050' as unknown as number]) {
    refused(() => createNet({ tick: fresh(), socksPort, transport: recorder() }), 'net.ctx')
  }
  for (const maxTimeoutMs of [0, -5, 1.5, Number.POSITIVE_INFINITY]) {
    refused(() => createNet({ tick: fresh(), maxTimeoutMs, transport: recorder() }), 'net.ctx')
  }
  const n = createNet({ tick: fresh(), socksPort: 9150, transport: recorder() })
  assert.equal(n.socksPort, 9150)
  assert.equal(createNet({ tick: fresh(), transport: recorder() }).socksPort, 9050)
})

test('net.tick-format: the tick must be the canonical ISO minute YYYY-MM-DDTHH:MMZ', () => {
  const bad: unknown[] = [
    '', ' ', 'tick-7', '1234', 'a.b', '2026-10-08T03:15Z.1', '2026-10-08T03:15', '2026-10-08T03:15:00Z',
    '2026-10-08T03:15:00.000Z', '2026-10-08 03:15Z', '2026-10-8T03:15Z', '2026-10-08T3:15Z', '2026-10-08t03:15z',
    ' 2026-10-08T03:15Z', '2026-10-08T03:15Z\n', '+02026-10-08T03:15Z', '2026-10-08T03:15+00:00',
    // shapes that Date.parse would roll over into another minute: not canonical
    '2026-02-30T00:00Z', '2026-02-29T12:00Z', '2026-04-31T00:00Z', '2026-10-08T24:00Z', '2026-10-08T03:60Z', '2026-13-01T00:00Z', '2026-00-10T00:00Z',
    '\uff12026-10-08T03:15Z', 7, null, undefined, new Date(BASE_MS), ['2026-10-08T03:15Z'],
  ]
  for (const tick of bad) refused(() => createNet({ tick: tick as string, transport: recorder() }), 'net.tick-format')
  refused(() => createNet(null as unknown as { tick: string }), 'net.tick-format')
  for (const tick of ['2026-10-08T03:15Z', '2028-02-29T23:59Z', '2026-12-31T00:00Z', '2026-01-01T00:00Z']) {
    assert.equal(createNet({ tick, transport: recorder() }).tick, tick)
  }
  // What the CLI builds (src/cli.ts tor-check) is canonical.
  const now = `${new Date().toISOString().slice(0, 16)}Z`
  assert.equal(createNet({ tick: now, transport: recorder() }).tick, now)
})

// ---- SOCKS: remote DNS, circuits, keep-alive off, events

test('socks5h: ATYP is always domain; username <role>.<tick>; a fresh password per agent; keep-alive off', NET_TIMEOUT, async () => {
  await withFakes({}, async ({ http, socksPort, socks }) => {
    const TICK = fresh()
    const TICK2 = fresh()
    const a = await gated(socksPort, { tick: TICK })
    const b = await gated(socksPort, { tick: TICK2 })
    const c = await gated(socksPort, { tick: TICK })
    const probes = socks.connections()
    assert.equal(probes, 3, 'one gate probe per net')
    assert.equal(socks.records.length, 0, 'probes never CONNECT')
    const r = await a.fetchFor('pub-j1-eth')(onionUrl('/ok'))
    assert.equal(r.status, 200)
    assert.deepEqual(await r.json(), { ok: true })
    await a.fetchFor('pub-j1-eth')(onionUrl('/ok')) // same role, same agent, NEW socket
    await a.fetchFor('drand')(onionUrl('/ok')) // another role
    await b.fetchFor('pub-j1-eth')(onionUrl('/ok')) // another tick
    await c.fetchFor('pub-j1-eth')(onionUrl('/ok')) // same role and tick, another net => another agent

    const rec = socks.records
    assert.equal(rec.length, 5)
    for (const x of rec) {
      assert.equal(x.atyp, 'domain')
      assert.equal(x.host, ONION_HOST)
      assert.equal(x.port, 80)
      assert.match(x.password ?? '', /^[0-9a-f]{16}$/)
    }
    assert.deepEqual(rec.map((x) => x.user),
      [`pub-j1-eth.${TICK}`, `pub-j1-eth.${TICK}`, `drand.${TICK}`, `pub-j1-eth.${TICK2}`, `pub-j1-eth.${TICK}`])
    assert.equal(rec[0].password, rec[1].password, 'one agent per (role, tick)')
    assert.notEqual(rec[0].password, rec[2].password, 'distinct roles, distinct agents')
    assert.notEqual(rec[0].password, rec[3].password, 'distinct ticks, distinct agents')
    assert.notEqual(rec[0].password, rec[4].password, 'a new net instance makes a new agent')
    // keep-alive off: every request opened its own SOCKS connection and asked the server to close.
    assert.equal(socks.connections() - probes, 5)
    assert.equal(http.hits.length, 5)
    for (const h of http.hits) assert.equal(h.headers.connection, 'close')

    const all = a.events()
    assert.deepEqual(all[0], { role: 'check', socksUser: `check.${TICK}`, host: 'check.torproject.org', atyp: 'domain' })
    const ev = all.filter(notCheck)
    assert.deepEqual(ev, [
      { role: 'pub-j1-eth', socksUser: `pub-j1-eth.${TICK}`, host: ONION_HOST, atyp: 'domain' },
      { role: 'pub-j1-eth', socksUser: `pub-j1-eth.${TICK}`, host: ONION_HOST, atyp: 'domain' },
      { role: 'drand', socksUser: `drand.${TICK}`, host: ONION_HOST, atyp: 'domain' },
    ])
    for (const x of rec) assert.ok(!JSON.stringify(ev).includes(x.password ?? '-'), 'events never carry the password')
    // read-only log
    assert.throws(() => { (all as unknown as unknown[]).push(all[0]) })
    assert.throws(() => { (all[1] as { role: string }).role = 'x' })
    assert.equal(a.events().length, 4)
  })
})

test('socks5h: https goes through SOCKS by name (port 443, ATYP domain); a TLS failure is net.failed', NET_TIMEOUT, async () => {
  await withFakes({}, async ({ socksPort, socks }) => {
    const net = await gated(socksPort)
    await rejects(net.fetchFor('pub-j1-eth')('https://rpc.eth.example/'), 'net.failed')
    assert.deepEqual(socks.records.map((x) => [x.atyp, x.host, x.port, x.user]), [['domain', 'rpc.eth.example', 443, `pub-j1-eth.${net.tick}`]])
  })
})

// ---- refusals on the SOCKS path

test('net.redirect: every 3xx is refused, and the error carries only status and host', NET_TIMEOUT, async () => {
  await withFakes({}, async ({ socksPort }) => {
    const f = (await gated(socksPort)).fetchFor('drand')
    for (const code of [300, 301, 302, 303, 304, 307, 308]) {
      const e = await caught(f(onionUrl(`/redirect/${code}`)))
      assert.ok(isRefusal('net.redirect')(e), `${code}`)
      assert.ok((e as Error).message.includes(String(code)) && (e as Error).message.includes(ONION_HOST))
      assert.ok(!leaksCanary(e), `canary leaked from a ${code}`)
      assert.ok(!(e as Error).message.includes('elsewhere'), 'no Location header in the message')
    }
  })
})

const BAD_URLS: unknown[] = [
  'ftp://files.example/x', 'http://clearnet.example/', 'http://localhost:8545', 'http://localhost:8545/',
  'https://localhost/', 'https://LOCALHOST/', 'https://foo.localhost/', 'http://localhost.:8545', 'https://localhost.:443/',
  'https://127.0.0.1/', 'https://127.0.0.1:8545/', 'https://[::1]:8545/', 'https://192.0.2.1/', 'https://[2001:db8::1]/',
  'https://0x7f.1/', 'http://127.0.0.1/', 'http://127.1:8545', 'http://0x7f000001:8545',
  'http://[::1]/', 'http://0.0.0.0:8545', 'http://127.0.0.2:8545', 'HTTP://127.0.0.1:8545', 'http://127.0.0.1:8545@evil.example/',
  'https://user:pw@rpc.eth.example/', 'https://user@rpc.eth.example/', 'http://127.0.0.1:8545\\evil', 'https://rpc.eth.example/ x',
  ' https://rpc.eth.example/', 'https://rpc.eth.example/\t', `http://${'v'.repeat(55)}.onion/`, `http://${'v'.repeat(57)}.onion/`,
  `http://${'1'.repeat(56)}.onion/`, `http://${ONION}.onion:8080/`, `ws://${ONION}.onion/`, 'wss://rpc.eth.example/',
  'not a url', '', 'https://', 'file:///etc/hosts', 'data:text/plain,x', 'javascript:alert(1)', 42, null,
]

test('net.scheme: only https, http://<56 base32>.onion, or literal loopback; localhost is refused', NET_TIMEOUT, async () => {
  const t = recorder()
  const net = await gatedT(t)
  const f = net.fetchFor('drand')
  for (const u of BAD_URLS) await rejects(f(u as string), 'net.scheme')
  assert.equal(t.calls.length, 0, 'nothing reached the transport')
  refused(() => net.jsonRpc('drand', 'http://localhost:8545'), 'net.scheme')
  // positives
  for (const u of ['https://rpc.eth.example/', 'https://rpc.eth.example:8443/a?b=c', onionUrl('/api/tx?x=1'),
    `https://${ONION}.onion/`, 'http://127.0.0.1:8545', 'http://127.0.0.1:8545/x?y=1', 'http://[::1]:8545/']) {
    const r = await f(u)
    assert.equal(r.status, 200, u)
  }
  // also on the real path: nothing reaches the SOCKS server
  await withFakes({}, async ({ socksPort, socks }) => {
    const g = (await gated(socksPort)).fetchFor('drand')
    const probes = socks.connections()
    await rejects(g('http://clearnet.example/ok'), 'net.scheme')
    await rejects(g('http://localhost:1/ok'), 'net.scheme')
    assert.equal(socks.connections(), probes)
  })
})

test('tor.unreachable: closed SOCKS port, SOCKS CONNECT failure, SOCKS auth refused', NET_TIMEOUT, async () => {
  // The check request is the one SOCKS request allowed before the gate: it exercises the real
  // no-transport path.
  const port = await closedPort()
  await rejects(createNet({ tick: fresh(), socksPort: port }).fetchFor('check')(TOR_CHECK_URL), 'tor.unreachable')
  await withFakes({ reply: 4 }, async ({ socksPort, socks }) => {
    await rejects(createNet({ tick: fresh(), socksPort }).fetchFor('check')(TOR_CHECK_URL), 'tor.unreachable')
    assert.equal(socks.records.length, 1)
    // ... and after the gate, for any role.
    await rejects((await gated(socksPort)).fetchFor('drand')(onionUrl('/ok')), 'tor.unreachable')
    assert.equal(socks.records.length, 2)
  })
  await withFakes({ refuseAuth: true }, async ({ socksPort }) => {
    await rejects(createNet({ tick: fresh(), socksPort }).fetchFor('check')(TOR_CHECK_URL), 'tor.unreachable')
  })
})

test('net.failed: a reset after the tunnel is up, a dead loopback port, a malformed transport answer', NET_TIMEOUT, async () => {
  await withFakes({}, async ({ socksPort }) => {
    await rejects((await gated(socksPort)).fetchFor('drand')(onionUrl('/reset')), 'net.failed')
  })
  const port = await closedPort()
  await rejects(createNet({ tick: fresh() }).fetchFor('drand')(`http://127.0.0.1:${port}/`), 'net.failed')
  for (const bad of [{ status: 99, headers: {}, body: enc('') }, { status: 200, headers: {}, body: 'x' }, null]) {
    const net = await gatedT(async () => bad as unknown as TransportResponse)
    await rejects(net.fetchFor('drand')('https://rpc.eth.example/'), 'net.failed')
  }
})

test('a transport that throws: tor.unreachable on the SOCKS side, net.failed for loopback; Refusals pass through', async () => {
  const net = await gatedT(async () => { throw new Error(`boom ${CANARY}`) })
  const e = await caught(net.fetchFor('drand')('https://rpc.eth.example/'))
  assert.ok(isRefusal('tor.unreachable')(e))
  assert.ok(!leaksCanary(e), 'transport error text never surfaces')
  await rejects(net.fetchFor('drand')('http://127.0.0.1:8545/'), 'net.failed')
  const n2 = await gatedT(ReplayTransport([]))
  await rejects(n2.fetchFor('drand')('https://rpc.eth.example/'), 'replay.unmatched')
})

// ---- side guard

test('net.tick-mixes-sides: deposit and publication never share a tick; neutral roles mix with either', () => {
  const mk = () => createNet({ tick: fresh(), transport: recorder() })
  let n = mk()
  n.fetchFor('d-railgun-eth')
  refused(() => n.fetchFor('pub-j1-eth'), 'net.tick-mixes-sides')
  refused(() => n.jsonRpc('l1hop-j1', 'https://rpc.eth.example/'), 'net.tick-mixes-sides')
  n.fetchFor('d-railgun-eth') // the first side stays usable
  n.fetchFor('pool-railgun-eth')

  n = mk()
  n.jsonRpc('pub-j1-eth', 'https://rpc.eth.example/')
  refused(() => n.fetchFor('d-railgun-eth'), 'net.tick-mixes-sides')
  for (const r of ['pool-railgun-eth', 'drand', 'check', 'artifacts', 'swap-j1', 'arweave-j1', 'waku-j1']) n.fetchFor(r)

  n = mk()
  for (const r of ['pool-railgun-eth', 'drand', 'check', 'artifacts', 'd-railgun-eth', 'pool-railgun-eth']) n.fetchFor(r)
  for (const r of ['btcw-j1', 'btck-j1', 'l2-j1-base', 'waku-j1']) refused(() => n.fetchFor(r), 'net.tick-mixes-sides')

  // A new tick is a clean slate.
  createNet({ tick: fresh(), transport: recorder() }).fetchFor('pub-j1-eth')
})

test('net.tick-mixes-sides across instances: nets that share a tick share its side', () => {
  const tick = fresh()
  const a = createNet({ tick, transport: recorder() })
  const b = createNet({ tick, transport: recorder() })
  a.fetchFor('d-railgun-eth')
  refused(() => b.fetchFor('pub-j1-eth'), 'net.tick-mixes-sides')
  refused(() => createNet({ tick }).jsonRpc('l1hop-j1', 'https://rpc.eth.example/'), 'net.tick-mixes-sides')
  b.fetchFor('d-railgun-eth')
  b.fetchFor('drand')
  const t2 = fresh()
  createNet({ tick: t2, transport: recorder() }).jsonRpc('l2-j1-base', 'https://rpc.base.example/')
  refused(() => createNet({ tick: t2, transport: recorder() }).fetchFor('d-railgun-eth'), 'net.tick-mixes-sides')
  // Another tick is unaffected.
  createNet({ tick: fresh(), transport: recorder() }).fetchFor('d-railgun-eth')
})

test('the side guard remembers only the newest tick and the 2 before it (pruned); an older tick is refused (net.tick-stale)', () => {
  const [t1, t2, gap, t3, t4] = [fresh(), fresh(), fresh(), fresh(), fresh()]
  createNet({ tick: t1, transport: recorder() }).fetchFor('d-railgun-eth')
  const n2 = createNet({ tick: t2, transport: recorder() })
  n2.fetchFor('pub-j1-eth')
  createNet({ tick: t3, transport: recorder() }).fetchFor('d-railgun-eth')
  // Every tick of the earlier tests is older than t1: pruned already.
  assert.deepEqual(sideTicks(), [t1, t2, t3])
  // Neutral roles claim no side, so they neither add nor prune.
  createNet({ tick: t4, transport: recorder() }).fetchFor('drand')
  assert.deepEqual(sideTicks(), [t1, t2, t3])
  const n4 = createNet({ tick: t4, transport: recorder() })
  n4.fetchFor('pub-j1-eth')
  assert.deepEqual(sideTicks(), [t2, t3, t4], 't1 is now older than 2 ticks: pruned')
  // A pruned tick can't be checked any more: refused, whichever side asks.
  refused(() => createNet({ tick: t1, transport: recorder() }).fetchFor('pub-j1-eth'), 'net.tick-stale')
  refused(() => createNet({ tick: t1, transport: recorder() }).fetchFor('d-railgun-eth'), 'net.tick-stale')
  // So is a tick never seen that is older than everything remembered; neutral roles stay usable.
  refused(() => createNet({ tick: '2026-01-01T00:00Z', transport: recorder() }).fetchFor('swap-j1'), 'net.tick-stale')
  createNet({ tick: t1, transport: recorder() }).fetchFor('drand')
  // The remembered ticks still guard their side.
  refused(() => createNet({ tick: t2, transport: recorder() }).fetchFor('d-railgun-eth'), 'net.tick-mixes-sides')
  n2.fetchFor('pub-j1-arb')
  refused(() => n4.fetchFor('d-railgun-eth'), 'net.tick-mixes-sides')
  // A tick never seen with exactly 2 newer ones is still within the window: accepted, and the
  // oldest remembered tick (t2) is pruned, so the net that used t2 is refused from now on.
  createNet({ tick: gap, transport: recorder() }).fetchFor('d-railgun-eth')
  assert.deepEqual(sideTicks(), [gap, t3, t4])
  refused(() => n2.fetchFor('l1hop-j1'), 'net.tick-stale')
  // Bounded: many ticks later there are still 3.
  for (let i = 0; i < 20; i++) createNet({ tick: fresh(), transport: recorder() }).fetchFor(i % 2 === 0 ? 'd-railgun-eth' : 'pub-j1-eth')
  assert.equal(sideTicks().length, 3)
  assert.ok(Object.isFrozen(sideTicks()))
})

test('the side guard also holds for loopback requests', async () => {
  const n = createNet({ tick: fresh(), transport: recorder() })
  await n.fetchFor('d-railgun-eth')('http://127.0.0.1:8545/')
  refused(() => n.fetchFor('pub-j1-eth'), 'net.tick-mixes-sides')
})

// ---- body cap

test('net.body-too-large: over 8 MiB is refused (declared length, chunked stream, transport); exactly 8 MiB is fine', NET_TIMEOUT, async () => {
  assert.equal(BODY_CAP, 8 * 1024 * 1024)
  await withFakes({}, async ({ socksPort }) => {
    const f = (await gated(socksPort)).fetchFor('artifacts')
    await rejects(f(onionUrl(`/size/${BODY_CAP + 1}`)), 'net.body-too-large')
    await rejects(f(onionUrl(`/chunked/${BODY_CAP + 1}`)), 'net.body-too-large')
    assert.equal((await (await f(onionUrl(`/size/${BODY_CAP}`))).bytes()).length, BODY_CAP)
    assert.equal((await (await f(onionUrl(`/chunked/${BODY_CAP}`))).bytes()).length, BODY_CAP)
  })
  const big = await gatedT(async () => ({ status: 200, headers: {}, body: new Uint8Array(BODY_CAP + 1) }))
  await rejects(big.fetchFor('drand')('https://rpc.eth.example/'), 'net.body-too-large')
  const srv = await startFixtureHttp()
  try {
    await rejects(createNet({ tick: fresh() }).fetchFor('artifacts')(`http://127.0.0.1:${srv.port}/chunked/${BODY_CAP + 1}`), 'net.body-too-large')
  } finally { await srv.close() }
})

test('HEAD: a declared content-length is not a body, so the cap does not apply to it', NET_TIMEOUT, async () => {
  const srv = await startFixtureHttp()
  try {
    const f = createNet({ tick: fresh() }).fetchFor('artifacts')
    const url = `http://127.0.0.1:${srv.port}/size/${BODY_CAP + 1}`
    const r = await f(url, { method: 'HEAD' })
    assert.equal(r.status, 200)
    assert.equal(r.headers['content-length'], String(BODY_CAP + 1))
    assert.equal((await r.bytes()).length, 0)
    await rejects(f(url), 'net.body-too-large') // GET still refuses
  } finally { await srv.close() }
})

// ---- status, body, canary

test('a 500 is returned as a status; json() of a non-JSON body is net.json and never echoes the body', NET_TIMEOUT, async () => {
  await withFakes({}, async ({ socksPort }) => {
    const f = (await gated(socksPort)).fetchFor('drand')
    const r = await f(onionUrl('/status/500'))
    assert.equal(r.status, 500)
    assert.ok((await r.text()).includes(CANARY), 'the caller gets the body itself')
    const e = await caught(r.json())
    assert.ok(isRefusal('net.json')(e))
    assert.ok(!leaksCanary(e), 'canary leaked from json()')
    const nj = await f(onionUrl('/not-json'))
    const e2 = await caught(nj.json())
    assert.ok(isRefusal('net.json')(e2))
    assert.ok(!leaksCanary(e2), 'canary leaked from json() of html')
    const nf = await f(onionUrl('/status/404'))
    assert.equal(nf.status, 404)
    assert.deepEqual(await nf.json(), { error: 'not found' })
  })
})

test('net.rpc-status: jsonRpc on a 500 refuses with status and host only', NET_TIMEOUT, async () => {
  await withFakes({}, async ({ socksPort }) => {
    const rpc = (await gated(socksPort)).jsonRpc('pub-j1-eth', onionUrl('/status/500'))
    const e = await caught(rpc.request({ method: 'eth_chainId' }))
    assert.ok(isRefusal('net.rpc-status')(e))
    const m = (e as Error).message
    assert.ok(m.includes('500') && m.includes(ONION_HOST))
    assert.ok(!m.includes('internal error') && !leaksCanary(e), 'no body in the error')
  })
  const net = await gatedT(ReplayTransport([loadFixture('http', 'server-error')]))
  const e = await caught(net.jsonRpc('pub-j1-eth', 'https://rpc.eth.example/').request({ method: 'eth_chainId', params: [] }))
  assert.ok(isRefusal('net.rpc-status')(e))
  assert.ok(!leaksCanary(e) && !(e as Error).message.includes('upstream'))
})

test('canary: the canary IP in a fixture body never appears in any thrown error', NET_TIMEOUT, async () => {
  const errors: unknown[] = []
  await withFakes({}, async ({ socksPort }) => {
    const n = await gated(socksPort)
    const f = n.fetchFor('pub-j1-eth')
    errors.push(await caught(f(onionUrl('/redirect/302'))))
    errors.push(await caught((await f(onionUrl('/not-json'))).json()))
    errors.push(await caught((await f(onionUrl('/status/500'))).json()))
    errors.push(await caught(n.jsonRpc('pub-j1-eth', onionUrl('/status/500')).request({ method: 'eth_chainId' })))
    errors.push(await caught(n.jsonRpc('pub-j1-eth', onionUrl('/not-json')).request({ method: 'eth_chainId' })))
    errors.push(await caught(n.jsonRpc('pub-j1-eth', onionUrl('/rpc')).request({ method: 'eth_gasPrice' })))
  })
  const replay = ReplayTransport([loadFixture('http', 'not-json'), loadFixture('rpc', 'rate-limited'), loadFixture('http', 'server-error')])
  const n = await gatedT(replay)
  errors.push(await caught((await n.fetchFor('drand')('https://api.service.example/v1/status')).json()))
  errors.push(await caught(n.jsonRpc('pub-j1-eth', 'https://rpc.eth.example/').request({ method: 'eth_gasPrice', params: [] })))
  errors.push(await caught(n.jsonRpc('pub-j1-eth', 'https://rpc.eth.example/').request({ method: 'eth_chainId', params: [] })))
  const thrower = await gatedT(async () => { throw new Error(CANARY) })
  errors.push(await caught(thrower.fetchFor('drand')('https://rpc.eth.example/')))
  assert.equal(errors.length, 10)
  errors.forEach((e, i) => assert.ok(!leaksCanary(e), `canary leaked from error #${i}`))
  assert.equal(replay.remaining(), 0)
})

// ---- poisoned globals

// A request that was NOT refused synchronously must not leave an unhandled 'error' behind.
function refusedRequest(f: () => ClientRequest, id: string): void {
  let req: ClientRequest | undefined
  let err: unknown = null
  try { req = f() } catch (e) { err = e }
  if (req !== undefined) { req.on('error', () => { /* the assertion below reports it */ }); req.destroy() }
  assert.ok(isRefusal(id)(err), `expected ${id}`)
}

test('net.poisoned: createNet without a transport poisons fetch, WebSocket and the http/https global agents', NET_TIMEOUT, async () => {
  createNet({ tick: fresh(), transport: recorder() })
  assert.equal(G.fetch, ORIGINAL.fetch)
  assert.equal(http.globalAgent, ORIGINAL.httpAgent)
  assert.equal(https.globalAgent, ORIGINAL.httpsAgent)
  const net = createNet({ tick: fresh() })
  const fetchFn = G.fetch as (...a: unknown[]) => unknown
  const Ws = G.WebSocket as new (...a: unknown[]) => unknown
  assert.notEqual(fetchFn, ORIGINAL.fetch)
  refused(() => fetchFn('https://example.com/'), 'net.poisoned')
  refused(() => fetchFn(), 'net.poisoned')
  refused(() => new Ws('wss://example.com/'), 'net.poisoned')
  // node:http / node:https with the default agent, and with agent:false (which Node builds from the
  // global agent's class): refused before any socket. Loopback URLs only, in case the poison fails.
  refusedRequest(() => http.get('http://127.0.0.1:1/'), 'net.poisoned')
  refusedRequest(() => http.request('http://127.0.0.1:1/', { agent: false }), 'net.poisoned')
  refusedRequest(() => https.get('https://127.0.0.1:1/'), 'net.poisoned')
  refusedRequest(() => https.request('https://127.0.0.1:1/', { agent: false }), 'net.poisoned')
  // The net layer's own loopback requests never use a global agent, so they still work.
  const srv = await startFixtureHttp()
  try {
    assert.equal((await net.fetchFor('drand')(`http://127.0.0.1:${srv.port}/ok`)).status, 200)
  } finally { await srv.close() }
  restoreGlobals()
  assert.equal(G.fetch, ORIGINAL.fetch)
  assert.equal(G.WebSocket, ORIGINAL.WebSocket)
  assert.equal(http.globalAgent, ORIGINAL.httpAgent)
  assert.equal(https.globalAgent, ORIGINAL.httpsAgent)
  poisonGlobals()
  poisonGlobals() // idempotent: the second call must not save the poisoned values as "originals"
  refused(() => (G.fetch as () => unknown)(), 'net.poisoned')
  refusedRequest(() => http.get('http://127.0.0.1:1/'), 'net.poisoned')
  restoreGlobals()
  assert.equal(G.fetch, ORIGINAL.fetch)
  assert.equal(http.globalAgent, ORIGINAL.httpAgent)
  assert.equal(https.globalAgent, ORIGINAL.httpsAgent)
  restoreGlobals() // idempotent too
  assert.equal(http.globalAgent, ORIGINAL.httpAgent)
})

// ---- JSON-RPC

test('jsonRpc: round-trips via ReplayTransport, ids increase, an unmatched request fails', async () => {
  const replay = ReplayTransport([
    loadFixture('rpc', 'eth-chainid'), loadFixture('rpc', 'eth-blocknumber'), loadFixture('rpc', 'eth-getbalance'),
  ])
  const net = await gatedT(replay)
  const rpc = net.jsonRpc('pub-j1-eth', 'https://rpc.eth.example/')
  assert.equal(await rpc.request({ method: 'eth_chainId' }), '0xaa36a7')
  assert.equal(await rpc.request({ method: 'eth_blockNumber', params: [] }), '0x10')
  assert.equal(await rpc.request({ method: 'eth_getBalance', params: ['0x000000000000000000000000000000000000dEaD', 'latest'] }), '0x0')
  const sent = replay.requests.map((r) => JSON.parse(new TextDecoder().decode(r.body ?? new Uint8Array())))
  assert.deepEqual(sent.map((b) => [b.jsonrpc, b.id, b.method]), [['2.0', 1, 'eth_chainId'], ['2.0', 2, 'eth_blockNumber'], ['2.0', 3, 'eth_getBalance']])
  for (const r of replay.requests) {
    assert.equal(r.method, 'POST')
    assert.equal(r.headers['content-type'], 'application/json')
    assert.equal(r.socksUser, `pub-j1-eth.${net.tick}`)
  }
  assert.deepEqual(net.events().filter(notCheck).map((e) => e.atyp), ['domain', 'domain', 'domain'])
  // used up: the same call again is unmatched and fails
  await rejects(rpc.request({ method: 'eth_chainId' }), 'replay.unmatched')
  await rejects(rpc.request({ method: 'eth_getBalance', params: ['0x000000000000000000000000000000000000dEaD', 'pending'] }), 'replay.unmatched')
  assert.equal(replay.unmatched.length, 2)
})

test('jsonRpc: an RPC error becomes RpcError(code, message) with no data and no IPs', async () => {
  const net = await gatedT(ReplayTransport([loadFixture('rpc', 'rate-limited')]))
  const e = await caught(net.jsonRpc('pub-j1-eth', 'https://rpc.eth.example/').request({ method: 'eth_gasPrice' }))
  assert.ok(e instanceof RpcError)
  assert.equal(e.code, -32005)
  assert.ok(e.message.startsWith('rate limit exceeded for '))
  assert.ok(!leaksCanary(e))
  assert.ok(!e.message.includes('2001:db8') && !e.message.includes('::ffff'), 'IPv6 forms are redacted too')
  assert.deepEqual(Object.keys(e).sort(), ['code', 'name'])
})

test('net.rpc-malformed: wrong id, wrong version, both/neither result and error, batch, bad error object', async () => {
  const bodies = [
    '{"jsonrpc":"2.0","id":99,"result":"0x1"}',
    '{"jsonrpc":"1.0","id":1,"result":"0x1"}',
    '{"id":1,"result":"0x1"}',
    '{"jsonrpc":"2.0","id":1,"result":"0x1","error":{"code":1,"message":"m"}}',
    '{"jsonrpc":"2.0","id":1}',
    '[{"jsonrpc":"2.0","id":1,"result":"0x1"}]',
    '{"jsonrpc":"2.0","id":1,"error":{"code":"x","message":"m"}}',
    '{"jsonrpc":"2.0","id":1,"error":{"code":1.5,"message":"m"}}',
    '{"jsonrpc":"2.0","id":1,"error":{"code":1}}',
    '{"jsonrpc":"2.0","id":1,"error":"boom"}',
    'null',
  ]
  for (const b of bodies) {
    const net = await gatedT(async () => okResponse(b))
    await rejects(net.jsonRpc('drand', 'https://rpc.eth.example/').request({ method: 'm' }), 'net.rpc-malformed')
  }
})

// ---- request shape

test('net.request: GET|HEAD|POST, body only with POST, plain string headers, no framing headers', async () => {
  const t = recorder()
  // Arbitrary POST bodies are send-type since C2 review I-2 (net.send-permit): this shape test holds an 'all' permit.
  const net = await gatedT(t, { permit: assertSendAllowed('testnet') })
  const f = net.fetchFor('drand')
  const u = 'https://rpc.eth.example/'
  const bad: unknown[] = [
    { method: 'PUT' }, { method: 'get' }, { method: 'CONNECT' }, { method: 'GET', body: 'x' }, { method: 'POST', body: { a: 1 } },
    { headers: { connection: 'keep-alive' } }, { headers: { Host: 'other.example' } }, { headers: { 'Content-Length': '5' } },
    { headers: { 'transfer-encoding': 'chunked' } }, { headers: { 'proxy-authorization': 'x' } }, { headers: { a: 1 } },
    { headers: { 'x-a': 'v\r\nx: y' } }, { headers: { 'bad name': 'v' } }, { headers: [['a', 'b']] }, 'nope',
  ]
  for (const init of bad) await rejects(f(u, init as never), 'net.request')
  assert.equal(t.calls.length, 0)
  await f(u)
  await f(u, { method: 'HEAD' })
  await f(u, { method: 'POST', body: 'x', headers: { 'content-type': 'text/plain' } })
  await f(u, { method: 'POST', body: new Uint8Array([1, 2]) })
  assert.deepEqual(t.calls.map((c) => [c.method, c.body === null ? null : [...c.body]]),
    [['GET', null], ['HEAD', null], ['POST', [...enc('x')]], ['POST', [1, 2]]])
  assert.equal(t.calls[2].headers['content-type'], 'text/plain')
})

test('responses: lowercased headers, text/json/bytes, read more than once', async () => {
  const net = await gatedT(ReplayTransport([loadFixture('http', 'ok')]))
  const r = await net.fetchFor('drand')('https://api.service.example/v1/status')
  assert.equal(r.status, 200)
  assert.equal(r.headers['content-type'], 'application/json')
  assert.equal(r.headers['x-multi'], 'a')
  assert.equal(await r.text(), '{"status":"ok"}')
  assert.deepEqual(await r.json(), { status: 'ok' })
  const b = await r.bytes()
  b[0] = 0
  assert.equal(await r.text(), '{"status":"ok"}', 'bytes() returns a copy')
})

// ---- loopback direct (R17)

test('loopback: reached directly with no SOCKS and no gate; event atyp loopback; guards still apply', NET_TIMEOUT, async () => {
  await withFakes({}, async ({ http, socksPort, socks }) => {
    // gate NOT passed; a permit, since a non-JSON-RPC POST is send-type (C2 review I-2)
    const net = createNet({ tick: fresh(), socksPort, maxTimeoutMs: 500, permit: assertSendAllowed('local') })
    const f = net.fetchFor('pub-j1-eth')
    const base = `http://127.0.0.1:${http.port}`
    const r = await f(`${base}/echo`, { method: 'POST', body: '{"a":1}', headers: { 'content-type': 'application/json' } })
    assert.equal(r.status, 200)
    const echo = await r.json() as { method: string; body: string; headers: Record<string, string> }
    assert.equal(echo.method, 'POST')
    assert.equal(echo.body, '{"a":1}')
    assert.equal(echo.headers.connection, 'close')
    assert.equal(echo.headers['proxy-authorization'], undefined)
    assert.equal(socks.connections(), 0, 'the fake SOCKS server saw no connection')
    assert.deepEqual(net.events(), [{ role: 'pub-j1-eth', socksUser: null, host: '127.0.0.1', atyp: 'loopback' }])
    await rejects(f(`${base}/redirect/302`), 'net.redirect')
    await rejects(f(`${base}/size/${BODY_CAP + 1}`), 'net.body-too-large')
    await rejects(f(`${base}/hang`), 'net.timeout')
    const rpc = net.jsonRpc('pub-j1-eth', `${base}/rpc`)
    assert.equal(await rpc.request({ method: 'eth_chainId' }), '0x7a69')
    assert.equal(socks.connections(), 0)
    assert.equal(net.gatePassed(), false)
  })
})

test('loopback: [::1] literal works too', NET_TIMEOUT, async () => {
  const http = await startFixtureHttp('::1')
  try {
    const net = createNet({ tick: fresh() })
    const r = await net.fetchFor('drand')(`http://[::1]:${http.port}/ok`)
    assert.deepEqual(await r.json(), { ok: true })
    assert.deepEqual(net.events(), [{ role: 'drand', socksUser: null, host: '[::1]', atyp: 'loopback' }])
  } finally { await http.close() }
})

test('loopback via a transport: socksUser null, no gate needed', async () => {
  const t = recorder()
  const net = createNet({ tick: fresh(), transport: t })
  await net.fetchFor('drand')('http://127.0.0.1:8545/')
  assert.equal(t.calls[0].socksUser, null)
  assert.deepEqual(net.events(), [{ role: 'drand', socksUser: null, host: '127.0.0.1', atyp: 'loopback' }])
})

// ---- lazy Tor gate (R17)

test('net.gate-required: no SOCKS request before torGate passes; allowed after', NET_TIMEOUT, async () => {
  await withFakes({}, async ({ socksPort, socks }) => {
    const net = createNet({ tick: fresh(), socksPort, transport: withCheck() })
    assert.equal(net.gatePassed(), false)
    await rejects(net.fetchFor('drand')(onionUrl('/ok')), 'net.gate-required')
    await rejects(net.jsonRpc('pub-j1-eth', onionUrl('/rpc')).request({ method: 'eth_chainId' }), 'net.gate-required')
    // only the check role, only to the check URL, only GET
    await rejects(net.fetchFor('drand')(TOR_CHECK_URL), 'net.gate-required')
    await rejects(net.fetchFor('check')('https://check.torproject.org/'), 'net.gate-required')
    await rejects(net.fetchFor('check')(onionUrl('/ok')), 'net.gate-required')
    await rejects(net.fetchFor('check')(TOR_CHECK_URL, { method: 'POST', body: '{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}' }), 'net.gate-required')
    assert.equal(socks.connections(), 0)
    assert.deepEqual(net.events(), [])

    assert.deepEqual(await torGate(net, {}), { isTor: true })
    assert.equal(net.gatePassed(), true)
    assert.equal(socks.connections(), 1, 'the gate probe')
    assert.equal((await net.fetchFor('drand')(onionUrl('/ok'))).status, 200)
    assert.equal(socks.records.length, 1)
  })
})

test('the check request to check.torproject.org is allowed before the gate (and goes through SOCKS by name)', NET_TIMEOUT, async () => {
  assert.equal(TOR_CHECK_URL, 'https://check.torproject.org/api/ip')
  await withFakes({}, async ({ socksPort, socks }) => {
    const net = createNet({ tick: fresh(), socksPort })
    // The fixture server isn't TLS, so the handshake fails: not net.gate-required.
    await rejects(net.fetchFor('check')(TOR_CHECK_URL), 'net.failed')
    assert.deepEqual(socks.records.map((x) => [x.atyp, x.host, x.port, x.user]), [['domain', 'check.torproject.org', 443, `check.${net.tick}`]])
  })
  const replayed = ReplayTransport([{
    request: { method: 'GET', url: TOR_CHECK_URL },
    response: { status: 200, headers: { 'content-type': 'application/json' }, body: `{"IsTor":true,"IP":"${CANARY}"}` },
  } satisfies Fixture])
  const net = createNet({ tick: fresh(), transport: replayed })
  const r = await net.fetchFor('check')(TOR_CHECK_URL)
  assert.equal(((await r.json()) as { IsTor: boolean }).IsTor, true)
  assert.equal(replayed.requests[0].socksUser, `check.${net.tick}`)
  assert.equal(net.gatePassed(), false, 'the check request does not pass the gate by itself')
})

// ---- timeouts

test('timeoutFor: 60 s for .onion, 30 s otherwise; a cap only ever shortens', () => {
  assert.equal(timeoutFor(onionUrl('/x')), 60_000)
  assert.equal(timeoutFor(`https://${ONION}.onion/`), 60_000)
  assert.equal(timeoutFor('https://rpc.eth.example/'), 30_000)
  assert.equal(timeoutFor('http://127.0.0.1:8545'), 30_000)
  assert.equal(timeoutFor(onionUrl('/x'), 500), 500)
  assert.equal(timeoutFor('https://rpc.eth.example/', 120_000), 30_000)
})

test('net.timeout: a hung server, a hung SOCKS CONNECT, a hung transport', NET_TIMEOUT, async () => {
  await withFakes({}, async ({ socksPort }) => {
    const f = (await gated(socksPort, { maxTimeoutMs: 400 })).fetchFor('drand')
    await rejects(f(onionUrl('/hang')), 'net.timeout')
    await rejects(f(onionUrl('/hang-body')), 'net.timeout')
  })
  await withFakes({ hangOnConnect: true }, async ({ socksPort }) => {
    await rejects((await gated(socksPort, { maxTimeoutMs: 400 })).fetchFor('drand')(onionUrl('/ok')), 'net.timeout')
  })
  const hung = await gatedT(() => new Promise<TransportResponse>(() => { /* never */ }), { maxTimeoutMs: 300 })
  await rejects(hung.fetchFor('drand')('https://rpc.eth.example/'), 'net.timeout')
})

// ---- jitter

test('jitter: uniform in [0, maxMs] from the injected random; net.jitter on bad input', async () => {
  const draws = [0, 0.5, 0.999999]
  let i = 0
  const net = createNet({ tick: fresh(), transport: recorder(), random: () => draws[i++] })
  assert.equal(await net.jitter(40), 0)
  const t0 = Date.now()
  assert.equal(await net.jitter(40), 20)
  assert.ok(Date.now() - t0 >= 15)
  assert.equal(await net.jitter(10), 10)
  assert.equal(await createNet({ tick: fresh(), transport: recorder() }).jitter(0), 0)
  const def = await createNet({ tick: fresh(), transport: recorder() }).jitter(5)
  assert.ok(Number.isInteger(def) && def >= 0 && def <= 5)
  for (const m of [-1, 1.5, Number.NaN, 3_600_001, '5' as unknown as number]) {
    await rejects(createNet({ tick: fresh(), transport: recorder() }).jitter(m), 'net.jitter')
  }
  for (const r of [1, -0.1, Number.NaN, 2]) {
    await rejects(createNet({ tick: fresh(), transport: recorder(), random: () => r }).jitter(10), 'net.jitter')
  }
})

// ---- the transport seam is for tests only

test('net.transport-test-only: createNet({ transport }) refuses outside a test runner', () => {
  const fetchTs = fileURLToPath(new URL('../../src/net/fetch.ts', import.meta.url))
  const script = `import { createNet } from ${JSON.stringify(fetchTs)}
try { createNet({ tick: '2026-10-08T03:15Z', transport: async () => ({ status: 200, headers: {}, body: new Uint8Array() }) }); console.log('created') }
catch (e) { console.log('refused ' + e.guardId) }
createNet({ tick: '2026-10-08T03:16Z' }); console.log('plain ok')`
  const run = (extra: Record<string, string>) => spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    encoding: 'utf8', timeout: 30_000, env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', ...extra },
  }).stdout
  assert.equal(run({}), 'refused net.transport-test-only\nplain ok\n')
  assert.equal(run({ NODE_TEST_CONTEXT: '', VITEST: '' }), 'refused net.transport-test-only\nplain ok\n')
  assert.equal(run({ NODE_TEST_CONTEXT: 'child-v8' }), 'created\nplain ok\n')
  assert.equal(run({ VITEST: 'true' }), 'created\nplain ok\n')
})

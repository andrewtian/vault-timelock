// cli/test/status.test.ts — `vt status` (src/ops/status.ts; plan Task C3), in-process, against test-owned fake page,
// relay and API servers on ephemeral 127.0.0.1 ports (deps.ports). The fixed stack ports are never bound. The real
// client sandbox around `vt status` is test/wrapper.test.ts (phase B).
import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { chmodSync, mkdirSync, symlinkSync, writeFileSync } from 'node:fs'
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http'
import { join } from 'node:path'
import type { Network } from '@vault-timelock/core/contracts'
import { NETWORKS } from '@vault-timelock/core/contracts'
import { upJsonText } from '../src/ops/stack.ts'
import { parseStatusArgs, renderStatus, status } from '../src/ops/status.ts'
import type { StatusEntry } from '../src/ops/status.ts'
import { CANARY, removeDir, tempDir } from './lib.ts'

interface Seen { role: string; method: string; url: string; headers: IncomingHttpHeaders }
interface Answer { status: number; body: string }
let T = ''
const VTH = () => join(T, 'vt-home')
const TOKEN = 'ab'.repeat(32)
const seen: Seen[] = []
const answers: Record<string, Answer> = {}
const servers: Server[] = []
let PORTS_ = { page: 0, relay: 0, api: 0 }
let CLOSED = 0 // a port nothing listens on

const json = (v: unknown, status = 200): Answer => ({ status, body: JSON.stringify(v) })
const GOOD = (n: Network): Record<string, Answer> => ({
  '/__serve': json({ release: false, digest: null, build: '0123456789ab' }),
  '/relay/status': json({ network: n, build: 'dev', confined: true, identity: { eth: { ok: true }, sol: { ok: true } }, endpoints: { eth: 1, sol: 2 } }),
  '/relay/tor': json({ profile: n, isTor: n === 'local' ? null : true, auto: true }),
  '/status': json({ network: n, networks: { eth: 'x', sol: 'y' }, mainnetSends: 'LOCKED', jobSends: 'LOCKED', build: 'dev', confined: true, legacyLatch: 'clear', serverNowMs: 1 }),
})

async function serve(role: string): Promise<number> {
  const s = createServer((req, res) => {
    seen.push({ role, method: req.method ?? '', url: req.url ?? '', headers: req.headers })
    const a = answers[`${role}${req.url}`] ?? { status: 404, body: '{"error":{"message":"no such route"}}' }
    res.writeHead(a.status, { 'content-type': 'application/json' })
    res.end(a.body)
  })
  servers.push(s)
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', () => r()))
  const addr = s.address()
  if (addr === null || typeof addr === 'string') throw new Error('no port')
  return addr.port
}

function answer(n: Network, over: Record<string, Answer> = {}): void {
  for (const k of Object.keys(answers)) delete answers[k]
  const g = { ...GOOD(n), ...over }
  answers['page/__serve'] = g['/__serve']
  answers['relay/relay/status'] = g['/relay/status']
  answers['relay/relay/tor'] = g['/relay/tor']
  answers['api/status'] = g['/status']
}
function markUp(n: Network, o: { token?: string | null; tokenMode?: number } = {}): void {
  const dir = join(VTH(), n)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  writeFileSync(join(dir, 'up.json'), upJsonText({ network: n, pagePort: { local: 5180, testnet: 5190, mainnet: 5200 }[n], build: 'dev', startedAt: 1_791_000_000_000 }), { mode: 0o600 })
  if (o.token !== null) {
    writeFileSync(join(dir, 'api.token'), o.token ?? TOKEN, { mode: 0o600 })
    chmodSync(join(dir, 'api.token'), o.tokenMode ?? 0o600)
  }
}

async function vtStatus(networks: readonly Network[], explicit: boolean, json: boolean, ports = () => PORTS_): Promise<{ code: number; text: string }> {
  let text = ''
  const code = await status({ networks, explicit, json, env: { HOME: join(T, 'home'), VT_HOME: VTH() } }, { ports, out: (t) => { text += t } })
  return { code, text }
}

before(async () => {
  T = tempDir('vt-status-')
  PORTS_ = { page: await serve('page'), relay: await serve('relay'), api: await serve('api') }
  CLOSED = await serve('closed')
  await new Promise<void>((r) => servers.pop()!.close(() => r()))
})
after(async () => {
  for (const s of servers) { s.closeAllConnections(); await new Promise<void>((r) => s.close(() => r())) }
  removeDir(T)
})
beforeEach(() => {
  seen.length = 0
  removeDir(VTH())
})

const DOWN = (n: Network): StatusEntry => ({
  network: n, up: false, pageUrl: `http://127.0.0.1:${{ local: 5180, testnet: 5190, mainnet: 5200 }[n]}/`, build: null, startedAt: null,
  page: null, relay: null, tor: null, api: null, healthy: false,
})

test('nothing up: every network down, no request made; exit 0 for "every stack", 1 for one named network', async () => {
  let r = await vtStatus(NETWORKS, false, true)
  assert.equal(r.code, 0)
  assert.deepEqual(JSON.parse(r.text), NETWORKS.map(DOWN))
  r = await vtStatus(NETWORKS, false, false)
  assert.equal(r.text, 'local    down\ntestnet  down\nmainnet  down\n')
  r = await vtStatus(['testnet'], true, true)
  assert.equal(r.code, 1)
  assert.deepEqual(JSON.parse(r.text), [DOWN('testnet')])
  assert.deepEqual(seen, [])
})

test('a healthy local stack: the JSON shape, field by field; exit 0', async () => {
  markUp('local')
  answer('local')
  const r = await vtStatus(['local'], true, true)
  assert.equal(r.code, 0, r.text)
  assert.deepEqual(JSON.parse(r.text), [{
    network: 'local', up: true, pageUrl: 'http://127.0.0.1:5180/', build: 'dev', startedAt: 1_791_000_000_000,
    page: { ok: true, error: null, release: false, build: '0123456789ab', digest: null },
    relay: { ok: true, error: null, network: 'local', build: 'dev', confined: true, identity: { eth: true, sol: true }, endpoints: { eth: 1, sol: 2 } },
    tor: { ok: true, error: null, isTor: null, drandViaTor: null },
    api: { ok: true, error: null, network: 'local', build: 'dev', confined: true, mainnetSends: 'LOCKED', jobSends: 'LOCKED', legacyLatch: 'clear' },
    healthy: true,
  }])
  // The human form.
  const h = await vtStatus(['local'], true, false)
  assert.equal(h.text, [
    'local    up      http://127.0.0.1:5180/  build dev  healthy',
    '  page   ok   release no  build 0123456789ab  digest -',
    '  relay  ok   network local  build dev  confined yes  identity eth ok sol ok  endpoints eth 1 sol 2',
    '  tor    ok   isTor n/a (local: direct loopback)',
    '  api    ok   network local  build dev  confined yes  mainnet sends: locked  mainnet job sends: locked  legacy latch clear',
    '',
  ].join('\n'))
})

test('S6 fix round 1 (review I-1): a local relay serving drand says "drand via Tor" with its IsTor state — never just "direct loopback"; Tor down → unavailable', async () => {
  markUp('local')
  const line = async (tor: unknown): Promise<{ text: string; entry: StatusEntry; code: number }> => {
    answer('local', { '/relay/tor': json(tor) })
    const h = await vtStatus(['local'], true, false)
    const j = await vtStatus(['local'], true, true)
    return { text: h.text.split('\n').find((l) => l.startsWith('  tor '))!, entry: (JSON.parse(j.text) as StatusEntry[])[0], code: h.code }
  }
  const roles = ['check', 'drand']
  const unchecked = await line({ profile: 'local', tor: false, isTor: null, checkedAt: null, torRoles: roles })
  assert.equal(unchecked.text, '  tor    ok   drand via Tor (IsTor not checked yet: on first use); chains direct loopback')
  assert.deepEqual(unchecked.entry.tor, { ok: true, error: null, isTor: null, drandViaTor: true })
  const ok = await line({ profile: 'local', tor: false, isTor: true, checkedAt: 1, torRoles: roles })
  assert.equal(ok.text, '  tor    ok   drand via Tor (IsTor yes); chains direct loopback')
  const down = await line({ profile: 'local', tor: false, isTor: false, checkedAt: 1, torRoles: roles })
  assert.equal(down.text, '  tor    ok   drand via Tor: unavailable (IsTor no); chains direct loopback')
  for (const x of [unchecked, ok, down]) {
    assert.equal(x.code, 0)                                                     // the local chains do not need Tor
    assert.ok(!x.text.includes('n/a (local: direct loopback)'))
  }
  // a local relay that serves no drand (torRoles []) is direct loopback only; an older relay without torRoles is unchanged
  assert.equal((await line({ profile: 'local', tor: false, isTor: null, torRoles: [] })).text, '  tor    ok   isTor n/a (local: direct loopback)')
  assert.equal((await line({ profile: 'local', isTor: null })).entry.tor?.drandViaTor, null)
  // a hostile torRoles is reduced to a boolean
  const evil = await line({ profile: 'local', isTor: null, torRoles: [CANARY, { drand: CANARY }] })
  assert.ok(!evil.text.includes(CANARY) && evil.entry.tor?.drandViaTor === false)
})

test('I3 minor #2: the API\'s two locks are mainnet\'s, and labelled so on every network ("mainnet job sends: locked"), lower case; enabled reads enabled', async () => {
  for (const n of ['local', 'testnet'] as const) {
    markUp(n)
    answer(n)
    const h = await vtStatus([n], true, false)
    assert.match(h.text, /  mainnet sends: locked  mainnet job sends: locked  /)
    assert.ok(!/ job sends LOCKED/.test(h.text) && !/(?<!mainnet )job sends/.test(h.text), h.text)
  }
  markUp('local')
  answer('local', { '/status': json({ network: 'local', networks: {}, mainnetSends: 'LOCKED', jobSends: 'ENABLED', build: 'dev', confined: true, legacyLatch: 'clear', serverNowMs: 1 }) })
  assert.match((await vtStatus(['local'], true, false)).text, /mainnet sends: locked  mainnet job sends: enabled/)
})

test('the requests: GET only, Host 127.0.0.1:<port>, no Origin / Sec-Fetch-Site / Cookie; the token goes to the API only', async () => {
  markUp('local')
  answer('local')
  await vtStatus(['local'], true, true)
  assert.deepEqual(seen.map((s) => `${s.role} ${s.method} ${s.url}`), ['page GET /__serve', 'relay GET /relay/status', 'relay GET /relay/tor', 'api GET /status'])
  for (const s of seen) {
    const port = PORTS_[s.role as 'page' | 'relay' | 'api']
    assert.equal(s.headers.host, `127.0.0.1:${port}`)
    for (const h of ['origin', 'sec-fetch-site', 'cookie', 'referer']) assert.equal(s.headers[h], undefined, `${s.role}: ${h}`)
    assert.equal(s.headers.authorization, s.role === 'api' ? `Bearer ${TOKEN}` : undefined)
  }
})

test('canary: whatever the servers answer (addresses, messages, extra fields), the output holds only checked fields', async () => {
  markUp('testnet')
  const ip = CANARY
  const evil = { ip, address: ip, message: `upstream ${ip}`, error: { message: ip }, note: `http://${ip}:8545/` }
  answer('testnet', {
    '/__serve': json({ ...evil, release: ip, digest: `${ip}`, build: ip }),
    '/relay/status': json({ ...evil, network: ip, build: ip, confined: ip, identity: { eth: { ok: true, message: `eth via ${ip}` }, sol: ip }, endpoints: { eth: ip, sol: 1e9 } }),
    '/relay/tor': json({ ...evil, isTor: ip, exitIp: ip, roles: { check: { lastError: ip } } }),
    '/status': json({ ...evil, network: ip, build: ip, confined: ip, mainnetSends: ip, jobSends: ip, legacyLatch: ip, networks: { eth: ip } }),
  })
  for (const asJson of [true, false]) {
    const r = await vtStatus(['testnet'], true, asJson)
    assert.equal(r.code, 1)
    assert.ok(!r.text.includes(ip), r.text)
    assert.ok(!r.text.includes('203.0.113'), r.text)
    for (const m of r.text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? []) assert.equal(m, '127.0.0.1', 'only the loopback page URL')
  }
  const [e] = JSON.parse((await vtStatus(['testnet'], true, true)).text) as StatusEntry[]
  assert.deepEqual(e.relay?.identity, { eth: true, sol: null })
  assert.equal(e.healthy, false)
  // An answer over 64 KiB is not read at all.
  answer('testnet', { '/status': { status: 200, body: JSON.stringify({ pad: 'x'.repeat(70_000), network: 'testnet' }) } })
  const big = JSON.parse((await vtStatus(['testnet'], true, true)).text) as StatusEntry[]
  assert.deepEqual([big[0].api?.ok, big[0].api?.error], [false, 'unreachable'])
})

test('failures are fixed words: unreachable, http <code>, not json; a failing part makes the stack not healthy', async () => {
  markUp('local')
  answer('local', { '/__serve': { status: 200, body: 'not json at all' }, '/status': json({ error: { guard: 'api.token', message: 'missing or wrong API token' } }, 401) })
  const r = await vtStatus(['local'], true, true, () => ({ ...PORTS_, relay: CLOSED }))
  assert.equal(r.code, 1)
  const [e] = JSON.parse(r.text) as StatusEntry[]
  assert.deepEqual([e.page?.ok, e.page?.error], [false, 'not json'])
  assert.deepEqual([e.relay?.ok, e.relay?.error, e.tor?.error], [false, 'unreachable', 'unreachable'])
  assert.deepEqual([e.api?.ok, e.api?.error], [false, 'http 401'])
  assert.equal(e.healthy, false)
  const h = (await vtStatus(['local'], true, false, () => ({ ...PORTS_, relay: CLOSED }))).text
  assert.match(h, /^local {4}up .* NOT HEALTHY$/m)
  assert.match(h, /^ {2}relay {2}unreachable$/m)
  assert.match(h, /^ {2}api {4}http 401$/m)
  assert.ok(!h.includes('missing or wrong'), 'a server message is never printed')
})

test('api.token: a loose mode, a symlink or a malformed token is "token unreadable", and the API is not asked', async () => {
  const cases: Array<[string, () => void]> = [
    ['0644', () => markUp('local', { tokenMode: 0o644 })],
    ['missing', () => markUp('local', { token: null })],
    ['short', () => markUp('local', { token: 'ab'.repeat(31) })],
    ['upper', () => markUp('local', { token: 'AB'.repeat(32) })],
    ['symlink', () => {
      markUp('local', { token: null })
      writeFileSync(join(T, 'elsewhere.token'), TOKEN, { mode: 0o600 })
      symlinkSync(join(T, 'elsewhere.token'), join(VTH(), 'local', 'api.token'))
    }],
  ]
  answer('local')
  for (const [name, setup] of cases) {
    removeDir(VTH())
    seen.length = 0
    setup()
    const [e] = JSON.parse((await vtStatus(['local'], true, true)).text) as StatusEntry[]
    assert.deepEqual([e.api?.ok, e.api?.error], [false, 'token unreadable'], name)
    assert.ok(!seen.some((s) => s.role === 'api'), `${name}: the API was not asked`)
  }
  // A trailing newline is fine (the API accepts it too).
  removeDir(VTH())
  markUp('local', { token: `${TOKEN}\n` })
  assert.equal((await vtStatus(['local'], true, true)).code, 0)
})

test('up.json: missing, malformed, another network or port, an extra key or a link -> down, and nothing is asked', async () => {
  answer('local')
  const bad = [
    'garbage', '[]', '{}',
    '{"network":"testnet","pagePort":5180,"build":"dev","startedAt":1}',
    '{"network":"local","pagePort":5190,"build":"dev","startedAt":1}',
    '{"network":"local","pagePort":5180,"build":"dev","startedAt":1,"extra":1}',
    `{"network":"local","pagePort":5180,"build":"${CANARY}","startedAt":1}`,
    '{"network":"local","pagePort":5180,"build":"dev","startedAt":-1}',
  ]
  for (const text of bad) {
    removeDir(VTH())
    mkdirSync(join(VTH(), 'local'), { recursive: true, mode: 0o700 })
    writeFileSync(join(VTH(), 'local', 'up.json'), text)
    const r = await vtStatus(['local'], true, true)
    assert.deepEqual(JSON.parse(r.text), [DOWN('local')], text)
    assert.ok(!r.text.includes(CANARY))
  }
  removeDir(VTH())
  mkdirSync(join(VTH(), 'local'), { recursive: true, mode: 0o700 })
  writeFileSync(join(T, 'up-elsewhere.json'), upJsonText({ network: 'local', pagePort: 5180, build: 'dev', startedAt: 1 }))
  symlinkSync(join(T, 'up-elsewhere.json'), join(VTH(), 'local', 'up.json'))
  assert.deepEqual(JSON.parse((await vtStatus(['local'], true, true)).text), [DOWN('local')])
  assert.deepEqual(seen, [])
})

test('healthy needs this network from the relay and the API, both confined, and on testnet/mainnet isTor', async () => {
  markUp('testnet')
  const cases: Array<[Record<string, Answer>, boolean]> = [
    [{}, true],
    [{ '/relay/tor': json({ isTor: false }) }, false],
    [{ '/relay/tor': json({ isTor: null }) }, false],
    [{ '/relay/status': json({ ...JSON.parse(GOOD('testnet')['/relay/status'].body), network: 'local' }) }, false],
    [{ '/status': json({ ...JSON.parse(GOOD('testnet')['/status'].body), network: 'mainnet' }) }, false],
    [{ '/status': json({ ...JSON.parse(GOOD('testnet')['/status'].body), confined: false }) }, false],
    [{ '/relay/status': json({ ...JSON.parse(GOOD('testnet')['/relay/status'].body), confined: 'true' }) }, false],
  ]
  for (const [over, healthy] of cases) {
    answer('testnet', over)
    const r = await vtStatus(['testnet'], true, true)
    assert.equal((JSON.parse(r.text) as StatusEntry[])[0].healthy, healthy, JSON.stringify(over))
    assert.equal(r.code, healthy ? 0 : 1)
  }
  // Without --network: a down network does not fail the command, an unhealthy up one does.
  answer('testnet')
  assert.equal((await vtStatus(NETWORKS, false, true)).code, 0)
  answer('testnet', { '/relay/tor': json({ isTor: false }) })
  assert.equal((await vtStatus(NETWORKS, false, true)).code, 1)
})

test('renderStatus: a down network is one line; arguments: only --json', () => {
  assert.equal(renderStatus([DOWN('mainnet')]), 'mainnet  down\n')
  assert.deepEqual(parseStatusArgs([]), { json: false })
  assert.deepEqual(parseStatusArgs(['--json']), { json: true })
  for (const args of [['--json', '--json'], ['-j'], ['local']]) assert.throws(() => parseStatusArgs(args), /usage: vt status/)
})

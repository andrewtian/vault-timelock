// cli/test/preflight.test.ts — `vt preflight` (src/preflight.ts; plan Task C7), in-process: a fake `get` (no socket is
// opened) for the page, relay and API reads and a fake RelayClient for core's preflight(). The real client sandbox
// around the command is test/wrapper.test.ts (phase B). ALL DATA IS SYNTHETIC; nothing listens, nothing is sent.
import { test, beforeEach, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Network, RelayClient } from '@vault-timelock/core/contracts'
import { pageRows } from '@vault-timelock/core/executor'
import { upJsonText } from '../src/ops/stack.ts'
import { RELEASE_TIMEOUT_MS, SERVICES_TIMEOUT_MS, parsePreflightArgs, preflightCommand, renderPreflight, runPreflight } from '../src/preflight.ts'
import { httpGet } from '../src/ops/status.ts'
import { createServer } from 'node:http'
import type { PreflightDeps, PreflightOutput } from '../src/preflight.ts'
import { CANARY, IPV4, removeDir, tempDir } from './lib.ts'

let T = ''
const VTH = () => join(T, 'vt-home')
const TOKEN = 'ab'.repeat(32)
const PORTS_ = { page: 11, relay: 12, api: 13 }
const B = 'b1c2d3e4f5a6'
const DIGEST = 'd'.repeat(64)

interface World {
  net: Network; build: string; relayBuild: string; serve: Record<string, unknown> | null; release: Record<string, unknown> | null
  ethMessage?: string; ethOk: boolean; isTor: boolean | null; down: boolean; jobSends: string; estimate?: (n: number) => number
  // Cfix3: the relay's btc identity/endpoints (as /relay/status carries them) and its /relay/services answer
  btc?: { identity: unknown; endpoints: unknown }; services?: unknown
  jobs?: unknown                       // M4b: GET /jobs (token-authenticated)
}
let W: World
const calls: Array<{ chain: string; method: string }> = []
const seenGet: Array<{ port: number; path: string; auth: string | undefined }> = []

const world = (net: Network, over: Partial<World> = {}): World => ({
  net, build: 'dev', relayBuild: 'dev', serve: { release: false, digest: null, build: 'dev' }, release: { release: false },
  ethOk: true, isTor: net === 'local' ? null : true, down: false, jobSends: 'LOCKED', ...over,
})
const forkN = (net: Network, n: number) => (net === 'testnet' ? 15000 + 64 * n : 21000 + 40 * n)

const relayClient = (): RelayClient => ({
  async status() {
    if (W.down) throw new Error(`connect ECONNREFUSED ${CANARY}:5181`)
    // 2 verified endpoints per chain: mainnet needs 2 (core preflight, PF-S M-2), local and testnet 1
    return { network: W.net, build: W.relayBuild, confined: true, identity: { eth: { ok: W.ethOk, ...(W.ethMessage ? { message: W.ethMessage } : {}) }, sol: { ok: true } }, endpoints: { eth: 2, sol: 2 } } as never
  },
  async rpc(chain, method, params) {
    calls.push({ chain, method })
    switch (method) {
      case 'eth_feeHistory': return { baseFeePerGas: ['0x3b9aca00', '0x3b9aca00'], reward: [['0x3b9aca00']] }
      case 'eth_estimateGas': return '0x' + (W.estimate ? W.estimate(0) : forkN(W.net, 100)).toString(16)
      case 'getAccountInfo': return { value: { executable: true } }
      case 'getLatestBlockhash': return { value: { blockhash: '11111111111111111111111111111111' } }
      case 'getFeeForMessage': return { value: 5000 }
      default: throw new Error(`unexpected ${method} ${JSON.stringify(params)}`)
    }
  },
  async tor() { return { isTor: W.isTor } },
  async price() { throw new Error('not read') },
})

const reply = (v: unknown, status = 200) => ({ status, body: JSON.stringify(v) })
const deps = (out: { text: string }): PreflightDeps => ({
  ports: () => PORTS_,
  async get(port, path, headers) {
    seenGet.push({ port, path, auth: headers.authorization })
    if (path === '/__serve') return port === PORTS_.page && W.serve ? reply(W.serve) : null
    if (path === '/relay/status') return W.down ? null : reply({ network: W.net, build: W.relayBuild, identity: { eth: { ok: W.ethOk, ...(W.ethMessage ? { message: W.ethMessage } : {}) }, sol: { ok: true }, ...(W.btc ? { btc: W.btc.identity } : {}) }, ...(W.btc ? { endpoints: { eth: 1, sol: 1, btc: W.btc.endpoints } } : {}) })
    if (path === '/relay/services') return W.services === undefined ? null : reply(W.services)
    if (path === '/relay/release') return W.release ? reply(W.release) : null
    if (path === '/status') return headers.authorization === `Bearer ${TOKEN}` ? reply({ network: W.net, build: W.build, mainnetSends: 'LOCKED', jobSends: W.jobSends, confined: true }) : reply({ error: 'no' }, 401)
    if (path === '/jobs') return headers.authorization === `Bearer ${TOKEN}` && W.jobs !== undefined ? reply(W.jobs) : null
    return null
  },
  out: (t) => { out.text += t },
  relay: () => relayClient(),
  now: () => 1_791_000_000_000,
  err: () => {},
})

function markUp(n: Network): void {
  const dir = join(VTH(), n)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  writeFileSync(join(dir, 'up.json'), upJsonText({ network: n, pagePort: { local: 5180, testnet: 5190, mainnet: 5200 }[n], build: 'dev', startedAt: 1_791_000_000_000 }), { mode: 0o600 })
  writeFileSync(join(dir, 'api.token'), TOKEN, { mode: 0o600 })
  chmodSync(join(dir, 'api.token'), 0o600)
}
const env = () => ({ HOME: join(T, 'home'), VT_HOME: VTH() })
async function run(n: Network, json: boolean): Promise<{ code: number; text: string }> {
  const out = { text: '' }
  const code = await preflightCommand({ network: n, env: env(), json }, deps(out))
  return { code, text: out.text }
}
const row = (o: PreflightOutput, id: string) => o.rows.find((r) => r.id === id)!

before(() => { T = tempDir('vt-preflight-') })
after(() => removeDir(T))
beforeEach(() => { removeDir(VTH()); calls.length = 0; seenGet.length = 0; W = world('local') })

test('parsePreflightArgs: nothing or --json; anything else is a usage error', () => {
  assert.deepEqual(parsePreflightArgs([]), { json: false })
  assert.deepEqual(parsePreflightArgs(['--json']), { json: true })
  for (const bad of [['--network'], ['--json', '--json'], ['x'], ['--JSON']]) assert.throws(() => parsePreflightArgs(bad), /usage: vt preflight/)
})

test('a healthy dev-tree stack: the F9-5 case — page build differs from "dev" everywhere else, the build row is — and the exit is 0', async () => {
  markUp('local')
  W = world('local', { serve: { release: false, digest: null, build: 'dev' } })
  const r = await run('local', false)
  assert.equal(r.code, 0, r.text)
  const lines = r.text.split('\n')
  assert.match(r.text, /^vt preflight — network local\n/)
  assert.ok(lines.includes('  —  Build id equal across page, API and relay — dev tree (needed only on mainnet/verified release)'), r.text)
  assert.ok(lines.includes('  ✓  API answers — build dev'))
  assert.ok(lines.some((l) => /^ {2}✓ {2}ETH chain identity/.test(l)))
  assert.ok(lines.some((l) => /^ {2}✓ {2}ETH fork gas probe/.test(l)))
  assert.ok(lines.includes('  —  Release verified — dev tree (needed only on mainnet)'))
  assert.ok(!lines.some((l) => l.startsWith('  ✗')), 'no failing row')
  assert.ok(lines.some((l) => /^regime: LOCAL/.test(l)))
  assert.ok(lines.includes('mainnet sends: locked  ·  mainnet job sends: locked'))
  assert.ok(lines.includes('page and relay digests: n/a (a development tree has no release digest)'))
  assert.equal(lines.at(-2), 'every check passed · exit 0')
  assert.ok(!IPV4.test(r.text))
})

test('the page and `vt preflight` agree: the same rows with the same verdicts, from the same function (core pageRows)', async () => {
  markUp('testnet')
  W = world('testnet', { build: B, relayBuild: B, serve: { release: true, digest: DIGEST, build: B }, release: { release: true, files: 10, ok: 10, mismatch: 0, missing: 0, digest: DIGEST, hashedAt: 1_791_000_000_001 } })
  const out = { text: '' }
  const o = await runPreflight('testnet', env(), deps(out))
  const page = pageRows({
    network: 'testnet', status: { network: 'testnet', build: B },
    relay: { network: 'testnet', build: B, identity: { eth: { ok: true }, sol: { ok: true } } },
    extras: { serve: { release: true, digest: DIGEST, build: B }, release: { release: true, files: 10, ok: 10, mismatch: 0, missing: 0, digest: DIGEST, hashedAt: 1_791_000_000_001 } }, pageNetwork: 'testnet',
  })
  assert.deepEqual(o.rows.slice(0, page.length).map((r) => ({ id: r.id, ok: r.ok, label: r.label, detail: r.detail })), page)
  assert.equal(o.rows.length > page.length, true, 'core preflight() rows follow')
  assert.equal(o.exit, 0)
  assert.deepEqual(o.digests, { page: DIGEST, relay: DIGEST, equal: true, kind: 'equal' })
})

test('a release: build ids that differ are a hard check (exit 1 although preflight() itself passed); different digests fail the mainnet release row', async () => {
  markUp('mainnet')
  W = world('mainnet', { build: B, relayBuild: 'f'.repeat(12), serve: { release: true, digest: DIGEST, build: B }, release: { release: true, files: 10, ok: 10, mismatch: 0, missing: 0, digest: DIGEST, hashedAt: 1_791_000_000_001 } })
  let r = await run('mainnet', true)
  let o = JSON.parse(r.text) as PreflightOutput
  assert.equal(r.code, 1)
  assert.equal(o.idOk && o.deployOk, true, 'preflight() passed')
  assert.equal(row(o, 'build').ok, false)
  assert.match(row(o, 'build').detail, /server b1c2d3e4f5a6 · api b1c2d3e4f5a6 · relay ffffffffffff/)
  assert.equal(o.failing, 1)
  W = world('mainnet', { build: B, relayBuild: B, serve: { release: true, digest: DIGEST, build: B }, release: { release: true, files: 10, ok: 10, mismatch: 0, missing: 0, digest: 'e'.repeat(64), hashedAt: 1_791_000_000_001 } })
  r = await run('mainnet', true)
  o = JSON.parse(r.text) as PreflightOutput
  assert.equal(r.code, 1)
  assert.deepEqual([row(o, 'release').ok, o.digests.equal], [false, false])
  assert.match(row(o, 'release').detail, /different releases/)
  assert.match((await run('mainnet', false)).text, /page and relay digests: DIFFER/)
  W = world('mainnet', { build: B, relayBuild: B, serve: { release: true, digest: DIGEST, build: B }, release: { release: true, files: 10, ok: 10, mismatch: 0, missing: 0, digest: DIGEST, hashedAt: 1_791_000_000_001 } })
  r = await run('mainnet', false)
  assert.equal(r.code, 0, r.text)
  assert.match(r.text, /page and relay digests: equal \(dddddddddddd…\)/)
  assert.match(r.text, /✓ {2}Release verified \(files re-hashed; page and relay digests equal\) — re-hashed just now \(10 files\) · digest dddddddddddd…/)
})

test('exit 1 when identity or a deployment fails (core): a relay that does not verify the chain, no Tor off local, fork drift, relay down', async () => {
  markUp('testnet')
  W = world('testnet', { ethOk: false, ethMessage: 'Amsterdam appears inactive on testnet — update required' })
  let o = JSON.parse((await run('testnet', true)).text) as PreflightOutput
  assert.deepEqual([o.idOk, o.exit], [false, 1])
  assert.deepEqual([row(o, 'fork').ok, row(o, 'fork').detail], [false, 'Amsterdam appears inactive on testnet — update required'])
  W = world('testnet', { isTor: false })
  const r = await run('testnet', false)
  assert.equal(r.code, 1)
  assert.match(r.text, /✗ {2}Tor — IsTor ✗ — the relay is not on Tor/)
  W = world('testnet', { estimate: () => 21000 + 40 * 100 })               // testnet must price Amsterdam gas
  o = JSON.parse((await run('testnet', true)).text) as PreflightOutput
  assert.deepEqual([row(o, 'eth.fork').ok, o.exit], [false, 1])
  W = world('local', { down: true }); markUp('local')
  const d = await run('local', true)
  o = JSON.parse(d.text) as PreflightOutput
  assert.equal(d.code, 1)
  assert.equal(row(o, 'relay').ok, false)
  assert.equal((row(o, 'relay') as { guard?: string }).guard, 'relay-unreachable')
  assert.ok(!d.text.includes(CANARY), 'no address from an error text')
})

test('no stack up (no valid up.json): one failing row naming the start command; nothing is read', async () => {
  const r = await run('mainnet', false)
  assert.equal(r.code, 1)
  assert.equal(r.text, 'vt preflight — network mainnet\n  ✗  The mainnet stack is up — no mainnet stack is up; start it with: vt up --network mainnet\n'
    + 'regime: MAINNET: ' + r.text.split('regime: MAINNET: ')[1])
  assert.match(r.text, /1 check failing · exit 1\n$/)
  assert.deepEqual(seenGet, [])
  assert.deepEqual(calls, [])
  const j = JSON.parse((await run('mainnet', true)).text) as PreflightOutput
  assert.deepEqual([j.up, j.exit], [false, 1])
})

test('read-only: only reads reach the relay (fee history, an estimate, account and fee reads); the API read carries the token as a header only', async () => {
  markUp('local')
  const r = await run('local', true)
  assert.equal(r.code, 0)
  const methods = new Set(calls.map((c) => c.method))
  for (const m of methods) assert.ok(['eth_feeHistory', 'eth_estimateGas', 'getAccountInfo', 'getLatestBlockhash', 'getFeeForMessage'].includes(m), m)
  assert.ok(!r.text.includes(TOKEN), 'the token is never printed')
  assert.deepEqual(seenGet.filter((g) => g.path === '/status').map((g) => [g.port, g.auth]), [[PORTS_.api, `Bearer ${TOKEN}`]])
  assert.deepEqual(seenGet.filter((g) => g.path === '/jobs').map((g) => [g.port, g.auth]), [[PORTS_.api, `Bearer ${TOKEN}`]])
  assert.deepEqual(seenGet.filter((g) => g.path !== '/status' && g.path !== '/jobs').map((g) => g.auth), [undefined, undefined, undefined, undefined])
  assert.deepEqual(seenGet.filter((g) => g.path !== '/status' && g.path !== '/jobs').map((g) => g.path).sort(), ['/__serve', '/relay/release', '/relay/services', '/relay/status'])
  const o = JSON.parse(r.text) as PreflightOutput
  assert.equal(o.format, 'vt-preflight/1')
  assert.deepEqual(o.regime, { label: 'LOCAL', sub: (o.regime as { sub: string }).sub })
  assert.deepEqual([o.mainnetSends, o.jobSends, o.up], ['LOCKED', 'LOCKED', true])
})

test('nothing a server says reaches the output unfiltered: a canary address in the fork message and a hostile build id', async () => {
  markUp('mainnet')
  W = world('mainnet', { ethOk: false, ethMessage: `fork mismatch at ${CANARY}:8545 \u001b[31m`, build: `${CANARY}`, relayBuild: 'zz', serve: { release: true, digest: DIGEST, build: B }, release: { release: true, files: 10, ok: 10, mismatch: 0, missing: 0, digest: DIGEST, hashedAt: 1_791_000_000_001 }, jobSends: 'maybe' })
  for (const json of [false, true]) {
    const r = await run('mainnet', json)
    assert.ok(!r.text.includes(CANARY), `json=${json}`)
    assert.ok(!r.text.includes('\u001b'), `json=${json}`)
    assert.ok(!IPV4.test(r.text), `json=${json}`)
  }
  assert.match((await run('mainnet', false)).text, /mainnet job sends: \?/)
})

test('renderPreflight: ✓ ✗ — marks, the failing count and the exit line', () => {
  const o = { network: 'local', regime: { label: 'LOCAL', sub: 'x' }, mainnetSends: null, jobSends: null, digests: { page: null, relay: null, equal: null, kind: 'dev' }, exit: 1, failing: 2,
    rows: [{ id: 'a', chain: null, ok: true, label: 'A', detail: 'a' }, { id: 'b', chain: null, ok: false, label: 'B', detail: 'b' }, { id: 'c', chain: null, ok: null, label: 'C', detail: 'c' }] } as unknown as PreflightOutput
  const t = renderPreflight(o)
  assert.match(t, /^vt preflight — network local\n {2}✓ {2}A — a\n {2}✗ {2}B — b\n {2}— {2}C — c\n/)
  assert.match(t, /mainnet sends: \?  ·  mainnet job sends: \?\n/)
  assert.match(t, /2 checks failing · exit 1\n$/)
  assert.match(renderPreflight({ ...o, failing: 0, exit: 0 }), /every check passed · exit 0\n$/)
  assert.match(renderPreflight({ ...o, failing: 0, exit: 1 }), /0 checks failing · exit 1\n$/)
})

// ---- Cfix2: the relay's first /relay/release can wait on its re-hash; unreadable is never "development tree"
const REL = { release: true, files: 27389, ok: 27389, mismatch: 0, missing: 0, digest: DIGEST, hashedAt: 1_791_000_000_001 }
const releaseWorld = () => world('mainnet', { build: B, relayBuild: B, serve: { release: true, digest: DIGEST, build: B }, release: REL })

test('Cfix2: /relay/release has its own long timeout and one progress line; the other reads keep the short one', async () => {
  markUp('mainnet')
  W = releaseWorld()
  const timeouts: Array<[string, number | undefined]> = []
  const errs: string[] = []
  const out = { text: '' }
  const d = deps(out)
  const get = d.get
  const o = await runPreflight('mainnet', env(), { ...d, err: (t) => errs.push(t), async get(port, path, headers, timeoutMs) { timeouts.push([path, timeoutMs]); return get(port, path, headers, timeoutMs) } })
  assert.deepEqual(timeouts.filter(([p]) => p === '/relay/release'), [['/relay/release', 180_000]])
  assert.equal(RELEASE_TIMEOUT_MS, 180_000)
  assert.deepEqual(timeouts.filter(([p]) => p === '/relay/services'), [['/relay/services', 60_000]])
  assert.equal(SERVICES_TIMEOUT_MS, 60_000)
  assert.ok(timeouts.filter(([p]) => p !== '/relay/release' && p !== '/relay/services').every(([, t]) => t === undefined), 'the other reads use the default timeout')
  assert.deepEqual(errs, ["waiting for the relay's release re-hash…\n"])
  assert.equal(o.exit, 0)
})

test('Cfix2: a relay whose FIRST /relay/release outlasts the old 3 s timeout: preflight waits and passes (real sockets)', { timeout: 30_000 }, async () => {
  markUp('mainnet')
  W = { ...releaseWorld(), services: { network: 'mainnet', services: {} } }  // answered (no rows): this test is about the release read
  let hits = 0
  const srv = createServer((_q, res) => { hits++; setTimeout(() => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(REL)) }, 3_400) })
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()))
  const port = (srv.address() as { port: number }).port
  try {
    const out = { text: '' }
    const d = deps(out)
    const code = await preflightCommand({ network: 'mainnet', env: env(), json: false }, { ...d, async get(p, path, headers, ms) { return path === '/relay/release' ? httpGet(port, path, headers, ms) : d.get(p, path, headers, ms) } })
    assert.equal(hits, 1)
    assert.equal(code, 0, out.text)
    assert.match(out.text, /✓ {2}Release verified .* — re-hashed just now \(27389 files\) · digest dddddddddddd…/)
    assert.match(out.text, /page and relay digests: equal/)
    assert.ok(!/could not be read/.test(out.text))
  } finally { srv.closeAllConnections(); await new Promise<void>((r) => srv.close(() => r())) }
})

test('Cfix2: unreadable release facts say "could not be read" with the reason, never "development tree"', async () => {
  markUp('mainnet')
  for (const [name, release, want] of [
    ['no answer', null, 'unreachable'], ['503', 'status:503', 'http 503'], ['not json', 'text', 'not json'],
  ] as const) {
    W = releaseWorld()
    W.release = null
    const out = { text: '' }
    const d = deps(out)
    const code = await preflightCommand({ network: 'mainnet', env: env(), json: false }, { ...d, async get(p, path, h) {
      if (path !== '/relay/release') return d.get(p, path, h)
      return release === null ? null : release === 'text' ? { status: 200, body: '<html>' } : { status: 503, body: '{}' }
    } })
    assert.equal(code, 1, name)
    assert.match(out.text, new RegExp(`page and relay digests: could not be read \\(${want}\\)\n`), name)
    assert.match(out.text, new RegExp(`✗ {2}Release verified .* — could not be read \\(${want}\\)\n`), name)
    assert.ok(!/development tree/.test(out.text), name)
  }
})

test('Cfix2: a timeout is named as one; and a page server that is down is "could not be read", not a development tree', async () => {
  markUp('mainnet')
  W = releaseWorld()
  let t = 0
  const out = { text: '' }
  const d = deps(out)
  const o = await runPreflight('mainnet', env(), { ...d, now: () => t, async get(p, path, h) { if (path === '/relay/release') { t += 180_000; return null } return d.get(p, path, h) } })
  assert.equal(o.digests.kind, 'unreadable')
  assert.equal(o.digests.why, 'no answer within 180 s')
  assert.equal(row(o, 'release').detail, 'could not be read (no answer within 180 s)')
  // page server down on a local stack whose relay says nothing either: unreadable
  markUp('local')
  W = world('local', { serve: null, release: null })
  const o2 = await runPreflight('local', env(), deps({ text: '' }))
  assert.equal(o2.digests.kind, 'unreadable')
  assert.match(renderPreflight(o2), /page and relay digests: could not be read \(/)
})

test('Cfix2: "development tree" only when the facts positively say release:false (either server)', async () => {
  markUp('local')
  for (const w of [world('local'), world('local', { serve: { release: true, digest: DIGEST, build: B }, release: { release: false } }), world('local', { serve: { release: false, digest: null, build: 'dev' }, release: null })]) {
    W = w
    const o = await runPreflight('local', env(), deps({ text: '' }))
    assert.equal(o.digests.kind, 'dev')
    assert.match(renderPreflight(o), /page and relay digests: n\/a \(a development tree has no release digest\)\n/)
  }
})

test('Cfix2 fix round 1: an answer without hashedAt, or one hashed BEFORE the request, is not a fresh re-hash: mainnet release row fails', async () => {
  markUp('mainnet')
  for (const [name, hashedAt] of [['missing', undefined], ['older than the request', 1_790_999_999_999], ['not a number', 'now']] as const) {
    W = releaseWorld()
    W.release = { ...REL, hashedAt }
    const o = await runPreflight('mainnet', env(), deps({ text: '' }))
    assert.equal(row(o, 'release').ok, false, name)
    assert.equal(row(o, 'release').detail, 'could not be read', name)
    assert.equal(o.exit, 1, name)
  }
  W = releaseWorld()
  W.release = { ...REL, hashedAt: 1_791_000_000_000 }   // started exactly at the request
  assert.equal(row(await runPreflight('mainnet', env(), deps({ text: '' })), 'release').ok, true)
})

// ---- Cfix3: BTC and the relay's services. The shapes are the real relay's (api/test/readiness-breadth.test.ts runs the real
// relay through the same command); here the facts are whitelisted and the rows are core's.
const SERVICES = {
  network: 'testnet',
  services: {
    'blockscout.eth': { ok: true, viaTor: true, endpoints: 1 },
    'blockscout.base': { ok: false, viaTor: true, endpoints: 0, message: 'an endpoint answered another identity: disabled until the relay restarts' },
    drand: { ok: false, viaTor: true, endpoints: 0, message: `Tor is not available (IsTor ✗): ${CANARY}` },
  },
}
const breadthRows = (o: PreflightOutput) => o.rows.filter((r) => r.id === 'btc-identity' || r.id === 'btc-endpoints' || r.id.startsWith('service-')).map((r) => [r.id, r.ok, r.detail])

test('Cfix3: BTC and service rows come from the relay facts and match the page rows; they never fail the exit', async () => {
  markUp('testnet')
  W = world('testnet', { estimate: () => forkN('testnet', 100), btc: { identity: { ok: true }, endpoints: 2 }, services: SERVICES })
  const out = { text: '' }
  const o = await runPreflight('testnet', env(), deps(out))
  assert.deepEqual(breadthRows(o), [
    ['btc-identity', true, 'block 0 is the testnet genesis (identity verified)'],
    ['btc-endpoints', true, '2 verified endpoints'],
    ['service-blockscout.base', null, 'identity disabled (relay.service-identity) · via Tor · reachable ✓'],
    ['service-blockscout.eth', true, 'identity ok · via Tor · reachable ✓'],
    ['service-drand', null, 'identity not checked · via Tor · reachable ✗ (unavailable: Tor is down)'],
  ])
  const page = pageRows({ network: 'testnet', status: { network: 'testnet', build: 'dev' }, relay: { network: 'testnet', build: 'dev', identity: { eth: { ok: true }, btc: { ok: true } }, endpoints: { btc: 2 } }, extras: { services: SERVICES }, pageNetwork: 'testnet' })
  assert.deepEqual(o.rows.filter((r) => r.id.startsWith('service-') || r.id.startsWith('btc')).map(({ id, ok, label, detail }) => ({ id, ok, label, detail })), page.filter((r) => r.id.startsWith('service-') || r.id.startsWith('btc')))
  assert.equal(o.exit, 0)
  const text = renderPreflight(o)
  assert.match(text, /  ✓  BTC chain identity — block 0 is the testnet genesis/)
  assert.match(text, /  —  Service drand — identity not checked · via Tor · reachable ✗ \(unavailable: Tor is down\)/)
  assert.ok(!(text + JSON.stringify(o)).includes(CANARY), 'the relay\'s free text is classified, never printed')
})

test('Cfix3 (+Cfix4): no btc in /relay/status -> no BTC rows; no /relay/services answer -> the service rows read "not checked", not absent; a hostile services answer is whitelisted', async () => {
  markUp('testnet')
  W = world('testnet', { estimate: () => forkN('testnet', 100) })
  const NAMES = ['blockscout.eth', 'blockscout.arb', 'blockscout.base', 'arweave', 'drand']
  assert.deepEqual(breadthRows(await runPreflight('testnet', env(), deps({ text: '' }))), NAMES.map((n) => [`service-${n}`, null, 'not checked (could not be read)']))
  W = world('testnet', { estimate: () => forkN('testnet', 100), btc: { identity: { ok: 'yes', message: CANARY }, endpoints: 'many' }, services: { services: { drand: { ok: 'maybe', viaTor: 1, message: 5 }, 'Bad Name': { ok: true }, x: 7 }, network: 'moon' } })
  const o = await runPreflight('testnet', env(), deps({ text: '' }))
  assert.deepEqual(breadthRows(o), [
    ['btc-identity', null, 'identity not checked'], ['btc-endpoints', null, 'could not be read'],
    ['service-drand', null, 'identity not checked · route unknown · reachable: not checked'], ['service-x', null, 'identity not checked · route unknown · reachable: not checked'],
  ])
  assert.equal(o.exit, 0)
  assert.ok(!JSON.stringify(o).includes(CANARY))
  W = world('testnet', { estimate: () => forkN('testnet', 100), services: { services: 'x' } })
  assert.deepEqual(breadthRows(await runPreflight('testnet', env(), deps({ text: '' }))), [])
})

test('Cfix4 (parked from Cfix3): after the 60 s /relay/services timeout the service rows read "not checked (timed out)" (every network\'s set), informational, exit unchanged', async () => {
  for (const [n, names] of [['testnet', ['blockscout.eth', 'blockscout.arb', 'blockscout.base', 'arweave', 'drand']], ['local', ['btc.ord', 'drand']]] as const) {
    removeDir(VTH())
    markUp(n)
    W = world(n, { estimate: () => forkN(n, 100) })
    let clock = 1_791_000_000_000
    const out = { text: '' }
    const d = deps(out)
    const get = d.get
    const o = await runPreflight(n, env(), { ...d, now: () => clock, async get(port, path, headers, t) { if (path === '/relay/services') { clock += SERVICES_TIMEOUT_MS; return null } return get(port, path, headers, t) } })
    assert.deepEqual(breadthRows(o), names.map((x) => [`service-${x}`, null, 'not checked (timed out)']), n)
    assert.equal(o.exit, 0, 'informational: a timed-out services read never fails the exit')
    const text = renderPreflight(o)
    assert.match(text, /Service drand .*not checked \(timed out\)/)
  }
  // a quick refusal (not a timeout) is "could not be read"
  removeDir(VTH())
  markUp('testnet')
  W = world('testnet', { estimate: () => forkN('testnet', 100) })
  assert.ok(breadthRows(await runPreflight('testnet', env(), deps({ text: '' }))).every((r) => r[2] === 'not checked (could not be read)'))
})

test('M4b glue: a lane key whose chain the journal stopped with engine.eip7702 reads as a failing "Lane key delegated" row; settled, absent or garbled job lists add none', async () => {
  markUp('local')
  const jobs = (chains: unknown) => ({ jobs: [{ id: 'a'.repeat(16), name: 'x', createdAt: 1, phase: 'RUNNING', chains }] })
  const rows = async (j: unknown) => { W = world('local', { estimate: () => forkN('local', 100), jobs: j }); return (await runPreflight('local', env(), deps({ text: '' }))).rows.filter((r) => r.id.startsWith('delegated-')) }
  const hit = await rows(jobs({ eth: { phase: 'STOPPED', reason: 'engine.eip7702: the key is delegated — the chain stops' }, sol: { phase: 'STOPPED', reason: 'stopped by the operator' } }))
  assert.deepEqual(hit.map((r) => [r.id, r.ok]), [['delegated-eth', false]])
  assert.deepEqual(await rows(jobs({ eth: { phase: 'CLAWED_BACK', reason: 'engine.eip7702: x' } })), [])
  for (const bad of [undefined, { jobs: 'x' }, { jobs: [null, 7, { chains: 'x' }] }, jobs({ eth: null })]) assert.deepEqual(await rows(bad), [])
  W = world('local', { estimate: () => forkN('local', 100), jobs: jobs({ eth: { phase: 'STOPPED', reason: 'engine.eip7702: x' } }) })
  assert.equal((await runPreflight('local', env(), deps({ text: '' }))).exit, 1, 'a delegated key fails the verdict')
})

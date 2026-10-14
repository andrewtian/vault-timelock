// Cfix1: the SHAPE CONTRACT between the servers and the readiness rows. The readiness rows (core executor/readiness.ts, shared
// by the page's Status table and `vt preflight`) once assumed `/relay/release`.ok was a boolean while the relay returns a
// COUNT, and compared the page bundle id with the release build id (different hash domains); both passed every test because
// the tests fed hand-written objects. Here the inputs come from the REAL producers, in process, over synthetic data:
//   · rehashRelease (api/relay/relay.mjs: what GET /relay/release returns) over a temp release tree with a SHA256SUMS;
//   · the page server's /__serve (createServe, with the temp SHA256SUMS), the relay's /relay/status (createRelay with a
//     fake transport, no socket off loopback) and the API's /status (createApi);
// and the assertions are on the rows pageRows() and `vt preflight` (cli runPreflight) print. Nothing listens off 127.0.0.1
// port 0; no key, no network, no 1Password data.
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { chmodSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, request } from 'node:http'
import type { Server } from 'node:http'
import { join } from 'node:path'
import { PORTS } from '@vault-timelock/core/contracts'
import type { Network, RelayClient } from '@vault-timelock/core/contracts'
import { pageRows } from '@vault-timelock/core/executor'
import { GENESIS } from 'vt-broadcast/src/config.ts'
import { runPreflight } from '../../cli/src/preflight.ts'
import { upJsonText } from '../../cli/src/ops/stack.ts'
import { createRelay, rehashRelease, relayUpstreams } from '../relay/relay.mjs'
import { createServe, serveInfo } from '../serve/serve.mjs'
import { TICKET_KEY, TOKEN, startApi, tempDir } from './helpers.ts'

const NET: Network = 'mainnet'
const REL_ID = 'c570388ab174'            // the release build id (12 hex)
const BUNDLE = '0f172b942a29'            // the page bundle id: another hash domain, never equal
const sha = (b: string | Buffer): string => createHash('sha256').update(b).digest('hex')
const get = (rows: ReturnType<typeof pageRows>, id: string) => rows.find((r) => r.id === id)!
const wire = <T>(v: T): unknown => JSON.parse(JSON.stringify(v))   // what crosses the socket

const cleanups: Array<() => unknown> = []
after(async () => { for (const c of cleanups.reverse()) await c() })

// ---- a synthetic release tree: <tmp>/releases/<REL_ID>/{a.txt,b/c.txt,d.txt} + SHA256SUMS
interface Tree { root: string; sums: string }
function tree(name: string, o: { corrupt?: boolean; remove?: boolean; garbage?: boolean; noSums?: boolean } = {}): Tree {
  const t = tempDir('vt-readiness-')
  cleanups.push(t.cleanup)
  const root = join(t.dir, name, 'releases', REL_ID)
  mkdirSync(join(root, 'b'), { recursive: true })
  const files: Record<string, string> = { 'a.txt': 'alpha\n', 'b/c.txt': 'bravo\n', 'd.txt': 'delta\n' }
  const sums = Object.entries(files).map(([f, c]) => `${sha(c)}  ${f}`)
  for (const [f, c] of Object.entries(files)) writeFileSync(join(root, f), c)
  if (o.garbage) sums.push('not a sums line')
  if (!o.noSums) writeFileSync(join(root, 'SHA256SUMS'), sums.join('\n') + '\n')
  if (o.corrupt) writeFileSync(join(root, 'a.txt'), 'ALPHA\n')
  if (o.remove) rmSync(join(root, 'd.txt'))
  return { root, sums: join(root, 'SHA256SUMS') }
}

// ---- the real page server, in process on port 0 (Host is the network's page host, as the browser sends it)
async function pageServer(t: Tree, build = REL_ID): Promise<number> {
  const dir = tempDir('vt-readiness-page-')
  cleanups.push(dir.cleanup)
  const root = join(dir.dir, 'dist')
  mkdirSync(root, { recursive: true })
  writeFileSync(join(root, 'index.html'), '<!doctype html>')
  const server = createServer(createServe({ network: NET, home: join(dir.dir, 'home'), root, build, sums: t.sums, upstreamPorts: { api: 9, relay: 9 }, log: () => {} }))
  return listen(server)
}
async function listen(server: Server): Promise<number> {
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  cleanups.push(() => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()) }))
  return (server.address() as { port: number }).port
}
function fetchJson(port: number, host: string, path: string, headers: Record<string, string> = {}): Promise<{ status: number; json: unknown } | null> {
  return new Promise((resolve) => {
    const req = request({ host: '127.0.0.1', port, path, method: 'GET', agent: false, setHost: false, headers: { host, ...headers } }, (res) => {
      const c: Buffer[] = []
      res.on('data', (d: Buffer) => c.push(d))
      res.on('end', () => { let json: unknown = null; try { json = JSON.parse(Buffer.concat(c).toString('utf8')) } catch { /* */ } resolve({ status: res.statusCode ?? 0, json }) })
    })
    req.on('error', () => resolve(null))
    req.end()
  })
}

// ---- the real relay (fake transport: no socket), and the real API
const TOR_CHECK = 'https://check.torproject.org/api/ip'
async function relayServer(build = REL_ID): Promise<number> {
  const rpc = (b: Buffer | undefined) => (b ? JSON.parse(b.toString('utf8')) as { id: unknown; method: string } : null)
  const relay = createRelay({
    network: NET, build, upstream: relayUpstreams(NET, {}),
    transport: async (url: string, r: { body?: Buffer }) => {
      const q = rpc(r.body)
      const out = (v: unknown) => ({ status: 200, body: Buffer.from(JSON.stringify(v)) })
      if (url === TOR_CHECK) return out({ IsTor: true })
      if (q === null) return { status: 404, body: Buffer.from('{}') }
      const result = q.method === 'eth_chainId' ? '0x1' : q.method === 'getGenesisHash' ? GENESIS.sol.mainnet : q.method === 'eth_estimateGas' ? '0x61a8' : 'x'
      return out({ jsonrpc: '2.0', id: q.id, result })
    },
    priceFixture: null, ticketKey: () => TICKET_KEY, confinement: { ok: true, probes: 5, result: 'EPERM ×5' },
    now: () => 1_791_504_000_000, log: () => {}, rand: () => 'sess',
  })
  await relay.startup()
  return listen(createServer(relay.handle))
}

interface Stack { page: number; relay: number; api: number; tree: Tree; home: string }
async function stack(t: Tree, o: { pageBuild?: string; relayBuild?: string; apiBuild?: string } = {}): Promise<Stack> {
  const a = await startApi({ network: NET, extra: { build: o.apiBuild ?? REL_ID } })
  cleanups.push(() => a.close())
  const home = tempDir('vt-readiness-home-')
  cleanups.push(home.cleanup)
  const dir = join(home.dir, NET)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  writeFileSync(join(dir, 'up.json'), upJsonText({ network: NET, pagePort: PORTS[NET].page, build: REL_ID, startedAt: 1_791_504_000_000 }), { mode: 0o600 })
  writeFileSync(join(dir, 'api.token'), TOKEN, { mode: 0o600 })
  chmodSync(join(dir, 'api.token'), 0o600)
  return { page: await pageServer(t, o.pageBuild), relay: await relayServer(o.relayBuild), api: a.port, tree: t, home: home.dir }
}

const HOSTS = { page: `127.0.0.1:${PORTS[NET].page}`, relay: `127.0.0.1:${PORTS[NET].relay}`, api: `127.0.0.1:${PORTS[NET].api}` }

// Fake RelayClient for core's preflight() (mainnet: Tor on, Prague-fork estimates). The page rows do not use it.
const relayClient = (st: () => Promise<unknown>): RelayClient => ({
  status: st as never,
  async rpc(_chain, method) {
    switch (method) {
      case 'eth_feeHistory': return { baseFeePerGas: ['0x3b9aca00', '0x3b9aca00'], reward: [['0x3b9aca00']] }
      case 'eth_estimateGas': return '0x61a8'
      case 'getAccountInfo': return { value: { executable: true } }
      case 'getLatestBlockhash': return { value: { blockhash: '11111111111111111111111111111111' } }
      case 'getFeeForMessage': return { value: 5000 }
      default: throw new Error(`unexpected ${method}`)
    }
  },
  async tor() { return { isTor: true } },
  async price() { throw new Error('not read') },
})

// What the page reads (same-origin /__serve and /relay/release) and what the pageRows take, from the real servers.
async function pageInputs(s: Stack, bundle = BUNDLE) {
  const serve = (await fetchJson(s.page, HOSTS.page, '/__serve'))?.json
  const release = wire({ ...(await rehashRelease(s.tree.root)), hashedAt: 1_791_000_000_000 })               // the relay's /relay/release handler returns exactly this
  const relayStatus = (await fetchJson(s.relay, HOSTS.relay, '/relay/status'))?.json
  const apiStatus = (await fetchJson(s.api, HOSTS.api, '/status', { authorization: `Bearer ${TOKEN}` }))?.json
  return { serve, release, relayStatus, apiStatus, extras: { pageBuild: bundle, serve, release } as never }
}

test('rehashRelease: the shape of /relay/release over a synthetic tree — counts, not booleans', async () => {
  const good = await rehashRelease(tree('good').root)
  assert.deepEqual(Object.keys(good).sort(), ['digest', 'files', 'mismatch', 'missing', 'ok', 'release'])
  assert.deepEqual({ ...good, digest: undefined }, { release: true, files: 3, ok: 3, mismatch: 0, missing: 0, digest: undefined })
  assert.match(String((good as { digest: string }).digest), /^[0-9a-f]{64}$/)
  assert.equal(typeof (good as { ok: unknown }).ok, 'number', 'ok is a COUNT of files that re-hashed ok')
  const t = tree('trailing')
  assert.deepEqual(await rehashRelease(t.root + '/'), await rehashRelease(t.root), 'a trailing separator makes no difference')
  assert.deepEqual(await rehashRelease(tree('corrupt', { corrupt: true }).root), { ...good, ok: 2, mismatch: 1 })
  assert.deepEqual(await rehashRelease(tree('remove', { remove: true }).root), { ...good, ok: 2, missing: 1 })
  const garbage = await rehashRelease(tree('garbage', { garbage: true }).root)
  assert.deepEqual({ ...garbage, digest: '' }, { ...good, files: 4, mismatch: 1, digest: '' })
  assert.notEqual((garbage as { digest: string }).digest, (good as { digest: string }).digest)
  assert.deepEqual(await rehashRelease(tree('none', { noSums: true }).root), { release: false })
})

test('the page rows on a REAL release: verified ✓ and the build row ✓ when server = api = relay and the bundle differs', async () => {
  const s = await stack(tree('ok'))
  const p = await pageInputs(s)
  assert.deepEqual(p.serve, serveInfo(REL_ID, s.tree.sums), '/__serve is serveInfo')
  assert.deepEqual(p.apiStatus && (p.apiStatus as { build: string }).build, REL_ID)
  assert.notEqual(BUNDLE, REL_ID)
  const rows = pageRows({ network: NET, status: p.apiStatus as never, relay: p.relayStatus as never, extras: p.extras, pageNetwork: NET })
  assert.deepEqual(rows.filter((r) => r.ok === false), [], JSON.stringify(rows))
  assert.equal(get(rows, 'release').ok, true)
  assert.match(get(rows, 'release').detail, /^re-hashed just now \(3 files\) · digest [0-9a-f]{12}…$/)
  assert.equal(get(rows, 'build').ok, true)
  assert.equal(get(rows, 'build').detail, `server ${REL_ID} · api ${REL_ID} · relay ${REL_ID} · page bundle ${BUNDLE} (information only)`)
})

test('the page rows on a REAL release that is damaged: mismatch ✗ with counts, missing ✗, digest unequal ✗, unreadable ✗', async () => {
  const release = (name: string, o: Parameters<typeof tree>[1]) => stack(tree(name, o)).then((s) => pageInputs(s).then((p) => ({ s, p })))
  const rel = (p: Awaited<ReturnType<typeof pageInputs>>, override: Partial<{ serve: unknown; release: unknown }> = {}) =>
    get(pageRows({ network: NET, status: p.apiStatus as never, relay: p.relayStatus as never, extras: { pageBuild: BUNDLE, serve: p.serve, release: p.release, ...override } as never, pageNetwork: NET }), 'release')
  const bad = await release('bad', { corrupt: true })
  assert.deepEqual([rel(bad.p).ok, rel(bad.p).detail], [false, 'files differ (1 changed, 0 missing)'])
  const gone = await release('gone', { remove: true })
  assert.deepEqual([rel(gone.p).ok, rel(gone.p).detail], [false, 'files differ (0 changed, 1 missing)'])
  const good = await release('fine', {})
  // the page server is from another release (its SHA256SUMS digest differs)
  const other = (await fetchJson(await pageServer(tree('other', { garbage: true })), HOSTS.page, '/__serve'))?.json
  assert.deepEqual([rel(good.p, { serve: other }).ok, rel(good.p, { serve: other }).detail], [false, 'the page and the relay come from different releases'])
  // unreadable: the relay did not answer, or answered something else
  for (const unreadable of [null, undefined, {}, [], 'oops']) {
    assert.deepEqual([rel(good.p, { release: unreadable }).ok, rel(good.p, { release: unreadable }).detail], [false, 'could not be read'])
  }
  // a client that says why it could not read (the CLI: unreachable / http 503 / a timeout) is shown with that plain reason
  assert.deepEqual([rel(good.p, { release: { error: 'x' } }).ok, rel(good.p, { release: { error: 'x' } }).detail], [false, 'could not be read (x)'])
})

test('a REAL stack whose servers disagree on the build id fails the build row, naming which', async () => {
  const s = await stack(tree('disagree'), { relayBuild: 'a'.repeat(12) })
  const p = await pageInputs(s)
  const b = get(pageRows({ network: NET, status: p.apiStatus as never, relay: p.relayStatus as never, extras: p.extras, pageNetwork: NET }), 'build')
  assert.equal(b.ok, false)
  assert.match(b.detail, /server c570388ab174 · api c570388ab174 · relay aaaaaaaaaaaa/)
})

test('`vt preflight --network mainnet` against the REAL producers: exit 0 when everything passes; exit 1 for a damaged release', async () => {
  const run = async (s: Stack) => {
    const out = { text: '' }
    const o = await runPreflight(NET, { HOME: join(s.home, 'h'), VT_HOME: s.home }, {
      ports: () => ({ page: s.page, relay: s.relay, api: s.api }),
      // the real page server, relay and API over loopback; Host is the network's own, as the CLI sends it
      async get(port, path, headers) {
        // The relay's /relay/release handler re-hashes ITS OWN module's tree; the same function over the temp tree answers.
        if (path === '/relay/release') return { status: 200, body: JSON.stringify({ ...(await rehashRelease(s.tree.root)), hashedAt: 1_791_504_000_001 }) }
        const host = port === s.page ? HOSTS.page : port === s.relay ? HOSTS.relay : HOSTS.api
        const r = await fetchJson(port, host, path, headers)
        return r === null ? null : { status: r.status, body: JSON.stringify(r.json) }
      },
      out: (t) => { out.text += t },
      relay: () => relayClient(async () => (await fetchJson(s.relay, HOSTS.relay, '/relay/status'))?.json),
      now: () => 1_791_504_000_000, err: () => {},
    })
    return o
  }
  const o = await run(await stack(tree('pf-ok')))
  assert.deepEqual(o.rows.filter((r) => r.ok === false), [], JSON.stringify(o.rows))
  assert.equal(o.exit, 0)
  assert.equal(o.rows.find((r) => r.id === 'release')?.ok, true)
  assert.equal(o.rows.find((r) => r.id === 'build')?.ok, true)
  assert.equal(o.digests.equal, true)
  for (const [name, opt, detail] of [['pf-bad', { corrupt: true }, 'files differ (1 changed, 0 missing)'], ['pf-gone', { remove: true }, 'files differ (0 changed, 1 missing)']] as const) {
    const d = await run(await stack(tree(name, opt)))
    assert.equal(d.exit, 1, name)
    assert.deepEqual([d.rows.find((r) => r.id === 'release')?.ok, d.rows.find((r) => r.id === 'release')?.detail], [false, detail])
  }
})

test('Cfix2 fix round 1: /__serve reads SHA256SUMS per request (a change after startup shows at once; nothing is cached)', async () => {
  const t = tree('serve-fresh')
  const port = await pageServer(t)
  const d1 = (await fetchJson(port, HOSTS.page, '/__serve'))?.json as { digest: string }
  writeFileSync(t.sums, 'tampered\n')
  const d2 = (await fetchJson(port, HOSTS.page, '/__serve'))?.json as { digest: string }
  assert.match(d1.digest, /^[0-9a-f]{64}$/)
  assert.equal(d2.digest, sha('tampered\n'))
  assert.notEqual(d1.digest, d2.digest)
  rmSync(t.sums)
  assert.deepEqual((await fetchJson(port, HOSTS.page, '/__serve'))?.json, { release: false, digest: null, build: REL_ID })
})

// Cfix3: the readiness rows for the S6 relay breadth (BTC and the relay's services), fed by the REAL producers. The inputs are
// what the real relay (createRelay, in process, an injected transport that plays every upstream; nothing leaves the machine)
// answers on GET /relay/status and GET /relay/services, read over its own socket on 127.0.0.1:0, and the real API's /status.
// The assertions are on the rows core's pageRows() makes (the page's Status table) and on `vt preflight` (cli runPreflight),
// which must print the SAME rows with the SAME verdicts. Synthetic data only; no key, no network, no 1Password data.
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs'
import { createServer, request } from 'node:http'
import type { Server } from 'node:http'
import { join } from 'node:path'
import { PORTS } from '@vault-timelock/core/contracts'
import type { Network, RelayClient } from '@vault-timelock/core/contracts'
import { REQUIRED_BREADTH, pageRows } from '@vault-timelock/core/executor'
import { GENESIS, NETWORK_IDS } from 'vt-broadcast/src/config.ts'
import { runPreflight } from '../../cli/src/preflight.ts'
import { upJsonText } from '../../cli/src/ops/stack.ts'
import { createRelay, relayBreadth, relayUpstreams } from '../relay/relay.mjs'
import { QUICKNET_INFO_BYTES } from '../src/relay-routes.ts'
import { TICKET_KEY, TOKEN, startApi, tempDir } from './helpers.ts'

const NOW = 1_791_504_000_000
const TOR_CHECK = 'https://check.torproject.org/api/ip'
const AUTH_LINE = 'vtsynth:Synthetic-Pass-7f3a9c1e'                         // synthetic; never a real credential
const AUTH_B64 = Buffer.from(AUTH_LINE).toString('base64')
const ARWEAVE_NET = 'arweave.N.1'
const cleanups: Array<() => unknown> = []
after(async () => { for (const c of cleanups.reverse()) await c() })

interface Up { status: number; body: Buffer }
const json = (v: unknown): Up => ({ status: 200, body: Buffer.from(JSON.stringify(v)) })
const raw = (s: string): Up => ({ status: 200, body: Buffer.from(s) })
const wire = <T>(v: T): unknown => JSON.parse(JSON.stringify(v))

const IDS: Record<Network, { eth: string; sol: string; btc: string }> = {
  local: { eth: '0x7a69', sol: '8pUq7jxkLxNpHg6M9KxzRtNEC4pNEHsr4kDTLSE5uVRW', btc: GENESIS.btc.regtest },
  testnet: { eth: '0xaa36a7', sol: GENESIS.sol.devnet, btc: GENESIS.btc.testnet4 },
  mainnet: { eth: '0x1', sol: GENESIS.sol.mainnet, btc: GENESIS.btc.mainnet },
}
// Every upstream the relay may reach, faked by URL. `wrong`: hosts answering ANOTHER identity; `isTor`: the IsTor check.
function world(network: Network, o: { isTor?: boolean; wrong?: RegExp; unreachable?: RegExp } = {}) {
  const calls: string[] = []
  const transport = async (url: string, r: { body?: Buffer; headers?: Record<string, string> }): Promise<Up> => {
    calls.push(url)
    if (o.unreachable?.test(url)) throw new Error('refused')
    if (url === TOR_CHECK) return json({ IsTor: o.isTor ?? true })
    const u = new URL(url)
    const wrong = o.wrong?.test(url) ?? false
    const rpc = r.body ? JSON.parse(r.body.toString('utf8')) as { id: unknown; method: string } : null
    if (u.pathname === '/api/eth-rpc') { const chain = /arbitrum/.test(u.host) ? 'arb' : /base/.test(u.host) ? 'base' : 'eth'; return json({ jsonrpc: '2.0', id: 1, result: wrong ? '0x539' : `0x${(NETWORK_IDS as Record<string, Record<string, number>>)[network === 'local' ? 'testnet' : network][chain].toString(16)}` }) }
    if (u.port === '18443') return r.headers?.authorization === `Basic ${AUTH_B64}` ? json({ jsonrpc: '2.0', id: rpc?.id ?? null, result: wrong ? 'ab'.repeat(32) : IDS.local.btc }) : { status: 401, body: Buffer.alloc(0) }
    if (u.port === '8090') return u.pathname === '/r/blockhash/0' ? json(IDS.local.btc) : json({ path: u.pathname })
    if (rpc && (u.port === '8545' || u.port === '8999' || /publicnode|solana|drpc|1rpc|sepolia/.test(u.host))) {
      return json({ jsonrpc: '2.0', id: rpc.id, result: rpc.method === 'eth_chainId' ? IDS[network].eth : rpc.method === 'getGenesisHash' ? IDS[network].sol : rpc.method === 'eth_estimateGas' ? `0x${(network === 'testnet' ? 21_400 : 25_000).toString(16)}` : 'x' })
    }
    if (u.pathname.endsWith('/block-height/0')) return raw(wrong ? 'ab'.repeat(32) : IDS[network].btc)
    if (u.pathname === '/info') return json({ network: wrong ? 'arweave.N.2' : ARWEAVE_NET, height: 1_500_000 })
    if (/^\/[0-9a-f]{64}\/info$/.test(u.pathname)) return { status: 200, body: QUICKNET_INFO_BYTES }
    return { status: 404, body: Buffer.from('{}') }
  }
  return { calls, transport }
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
      res.on('end', () => { let j: unknown = null; try { j = JSON.parse(Buffer.concat(c).toString('utf8')) } catch { /* */ } resolve({ status: res.statusCode ?? 0, json: j }) })
    })
    req.on('error', () => resolve(null))
    req.end()
  })
}

async function relayOn(network: Network, o: Parameters<typeof world>[1] & { noBtc?: boolean } = {}) {
  const w = world(network, o)
  const breadth = relayBreadth(network, {})
  const relay = createRelay({
    network, build: 'dev', upstream: relayUpstreams(network, {}), breadth: o.noBtc ? { ...breadth, btc: [], ord: [] } : breadth, bitcoindAuth: AUTH_LINE,
    transport: w.transport, priceFixture: network === 'local' ? { SOL: 150, ETH: 3000 } : null, ticketKey: () => TICKET_KEY,
    confinement: { ok: true, probes: 5, result: 'EPERM ×5' }, now: () => NOW, log: () => {}, rand: () => 'sess',
  })
  await relay.startup()
  return { port: await listen(createServer(relay.handle)), calls: w.calls }
}
// Host is the network's own port for that server, as the browser and the CLI send it (the servers check it)
const hostOf = (n: Network, port: number, who: 'relay' | 'api' = 'relay'): string => `127.0.0.1:${PORTS[n][who]}`
const get = (rows: ReturnType<typeof pageRows>, id: string) => rows.find((r) => r.id === id)!

// What the page reads: the relay's real /relay/status and /relay/services, the real API's /status.
async function inputs(network: Network, o: Parameters<typeof relayOn>[1] = {}) {
  const r = await relayOn(network, o)
  const a = await startApi({ network, extra: { build: 'dev' } })
  cleanups.push(() => a.close())
  const relayStatus = (await fetchJson(r.port, hostOf(network, r.port), '/relay/status'))?.json
  const services = (await fetchJson(r.port, hostOf(network, r.port), '/relay/services'))?.json
  const apiStatus = (await fetchJson(a.port, hostOf(network, a.port, 'api'), '/status', { authorization: `Bearer ${TOKEN}` }))?.json
  return { r, a, relayStatus, services, apiStatus }
}
const rowsOf = (network: Network, p: Awaited<ReturnType<typeof inputs>>, extra: Record<string, unknown> = {}) =>
  pageRows({ network, status: p.apiStatus as never, relay: p.relayStatus as never, extras: { services: p.services, serve: { release: false, digest: null, build: 'dev' }, release: { release: false }, ...extra } as never, pageNetwork: network })

test('REQUIRED_BREADTH is empty: for now no BTC or service row can fail an exit (BTC and timelocked publishing are not enabled)', () => {
  assert.deepEqual([...REQUIRED_BREADTH], [])
})

test('testnet, everything healthy: BTC identity and endpoints, and one row per real /relay/services entry, all ✓ and via Tor', async () => {
  const p = await inputs('testnet')
  const rows = rowsOf('testnet', p)
  assert.equal(get(rows, 'btc-identity').label, 'BTC chain identity')
  assert.deepEqual([get(rows, 'btc-identity').ok, get(rows, 'btc-identity').detail], [true, 'block 0 is the testnet genesis (identity verified)'])
  assert.equal(get(rows, 'btc-endpoints').label, 'BTC endpoints')
  assert.equal(get(rows, 'btc-endpoints').ok, true)
  assert.match(get(rows, 'btc-endpoints').detail, /^\d+ verified endpoints?$/)
  const names = Object.keys((p.services as { services: object }).services).sort()
  assert.deepEqual(names, ['arweave', 'blockscout.arb', 'blockscout.base', 'blockscout.eth', 'drand'])
  for (const n of names) assert.deepEqual([get(rows, `service-${n}`).ok, get(rows, `service-${n}`).label, get(rows, `service-${n}`).detail], [true, `Service ${n}`, 'identity ok · via Tor · reachable ✓'])
  assert.deepEqual(rows.filter((r) => r.ok === false), [])
})

test('a service disabled for a WRONG identity: shown as disabled (relay.service-identity), informational — it cannot fail the exit', async () => {
  const p = await inputs('testnet', { wrong: /base-sepolia\.blockscout|arweave|ar-io/ })
  const sv = (p.services as { services: Record<string, { ok: boolean; message: string }> }).services
  assert.equal(sv['blockscout.base'].ok, false)
  assert.match(sv['blockscout.base'].message, /another identity/)
  const rows = rowsOf('testnet', p)
  for (const n of ['blockscout.base', 'arweave']) {
    assert.deepEqual([get(rows, `service-${n}`).ok, get(rows, `service-${n}`).detail], [null, 'identity disabled (relay.service-identity) · via Tor · reachable ✓'])
  }
  assert.equal(get(rows, 'service-blockscout.eth').ok, true, 'the others are unaffected')
  assert.deepEqual(rows.filter((r) => r.ok === false), [])
})

test('a service whose endpoints do not answer: identity not checked, reachable ✗, informational', async () => {
  const p = await inputs('testnet', { unreachable: /arweave|ar-io|g8way|arweave\.net/ })
  const rows = rowsOf('testnet', p)
  assert.deepEqual([get(rows, 'service-arweave').ok, get(rows, 'service-arweave').detail], [null, 'identity not checked · via Tor · reachable ✗'])
  assert.deepEqual(rows.filter((r) => r.ok === false), [])
})

test('a BTC upstream with the WRONG genesis is fatal for the real relay at startup (no row to show); no BTC served -> no BTC rows', async () => {
  await assert.rejects(relayOn('testnet', { wrong: /block-height\/0/ }), /btc identity MISMATCH/)
  const p = await inputs('testnet', { noBtc: true })
  const ids = rowsOf('testnet', p).map((r) => r.id)
  assert.ok(!ids.includes('btc-identity') && !ids.includes('btc-endpoints'))
  assert.ok(ids.includes('service-drand'))
})

test('local: Tor down -> drand unavailable (IsTor ✗), via Tor, informational; ord on loopback; not failing', async () => {
  const p = await inputs('local', { isTor: false })
  const rows = rowsOf('local', p)
  assert.deepEqual([get(rows, 'service-drand').ok, get(rows, 'service-drand').detail], [null, 'identity not checked · via Tor · reachable ✗ (unavailable: Tor is down)'])
  assert.deepEqual([get(rows, 'service-btc.ord').ok, get(rows, 'service-btc.ord').detail], [true, 'identity ok · loopback · reachable ✓'])
  assert.equal(get(rows, 'btc-identity').detail, 'block 0 is the local genesis (identity verified)')
  assert.deepEqual(rows.filter((r) => r.ok === false), [])
  assert.ok(!p.r.calls.some((u) => /\/info$/.test(u) && /[0-9a-f]{64}/.test(u)), 'no drand request was made')
})

test('local: Tor up -> drand ok via Tor; no Blockscout or Arweave rows on local', async () => {
  const p = await inputs('local')
  const rows = rowsOf('local', p)
  assert.deepEqual([get(rows, 'service-drand').ok, get(rows, 'service-drand').detail], [true, 'identity ok · via Tor · reachable ✓'])
  assert.deepEqual(rows.filter((r) => r.id.startsWith('service-')).map((r) => r.id).sort(), ['service-btc.ord', 'service-drand'])
})

test('a job that NEEDS a service or BTC makes it ✗ when it is not good (extras.required); good stays ✓', async () => {
  const p = await inputs('local', { isTor: false })
  const rows = rowsOf('local', p, { required: ['drand', 'btc'] })
  assert.equal(get(rows, 'service-drand').ok, false)
  assert.equal(get(rows, 'service-btc.ord').ok, true)
  assert.equal(get(rows, 'btc-identity').ok, true)
  assert.equal(get(rows, 'btc-endpoints').ok, true)
})

test('hostile shapes are only classified, never echoed: a free-text message, odd names and values print nothing of their own', () => {
  const canary = 'CANARY-203.0.113.9'
  const rows = pageRows({
    network: 'testnet', status: { network: 'testnet', build: 'x' }, relay: { network: 'testnet', identity: { eth: { ok: true }, btc: { ok: false, message: `no ${canary}` } }, endpoints: { btc: 'two' } },
    extras: { services: { network: 'testnet', services: { drand: { ok: false, viaTor: 'yes', message: canary }, 'Bad Name': { ok: true }, weird: 5, arweave: { ok: 'maybe' } } } },
  })
  assert.ok(!JSON.stringify(rows).includes('203.0.113.9'))
  assert.deepEqual(rows.filter((r) => r.id.startsWith('service-')).map((r) => [r.id, r.ok, r.detail]), [
    ['service-arweave', null, 'could not be read'], ['service-drand', null, 'identity not checked · route unknown · reachable ✗'], ['service-weird', null, 'could not be read'],
  ])
  assert.equal(get(rows, 'btc-endpoints').detail, 'could not be read')
  assert.deepEqual(rows.filter((r) => r.ok === false).map((r) => r.id), ['build'], 'only the build row (no release facts here) fails; no BTC or service row does')
})

// ---- `vt preflight` prints the same rows with the same verdicts, from the same real servers
async function preflightOf(network: Network, o: Parameters<typeof relayOn>[1] = {}) {
  const p = await inputs(network, o)
  const home = tempDir('vt-breadth-home-')
  cleanups.push(home.cleanup)
  const dir = join(home.dir, network)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  writeFileSync(join(dir, 'up.json'), upJsonText({ network, pagePort: PORTS[network].page, build: 'dev', startedAt: NOW }), { mode: 0o600 })
  writeFileSync(join(dir, 'api.token'), TOKEN, { mode: 0o600 })
  chmodSync(join(dir, 'api.token'), 0o600)
  const client: RelayClient = {
    status: (async () => (await fetchJson(p.r.port, hostOf(network, p.r.port), '/relay/status'))?.json) as never,
    async rpc(_c, method) {
      switch (method) {
        case 'eth_feeHistory': return { baseFeePerGas: ['0x3b9aca00', '0x3b9aca00'], reward: [['0x3b9aca00']] }
        case 'eth_estimateGas': return network === 'testnet' ? '0x5398' : '0x61a8'
        case 'getAccountInfo': return { value: { executable: true } }
        case 'getLatestBlockhash': return { value: { blockhash: '11111111111111111111111111111111' } }
        case 'getFeeForMessage': return { value: 5000 }
        default: throw new Error(`unexpected ${method}`)
      }
    },
    async tor() { return { isTor: true } },
    async price() { return { source: 'fixture', fixture: true, fetchedAt: NOW, prices: { SOL: { usd: 150, mint: 'x' }, ETH: { usd: 3000, mint: 'y' } } } as never },
  }
  const out = await runPreflight(network, { HOME: join(home.dir, 'h'), VT_HOME: home.dir }, {
    ports: () => ({ page: 1, relay: p.r.port, api: p.a.port }),
    async get(port, path, headers) {
      if (path === '/__serve') return { status: 200, body: JSON.stringify({ release: false, digest: null, build: 'dev' }) }
      if (path === '/relay/release') return { status: 200, body: JSON.stringify({ release: false }) }
      const r = await fetchJson(port, hostOf(network, port, port === p.a.port ? 'api' : 'relay'), path, headers)
      return r === null ? null : { status: r.status, body: JSON.stringify(r.json) }
    },
    out: () => {}, relay: () => client, now: () => NOW, err: () => {},
  })
  return { p, out }
}

test('`vt preflight` prints the SAME BTC and service rows as the page, and a wrong-identity service or Tor down on local does not fail the exit', async () => {
  for (const [network, o] of [['testnet', { wrong: /base-sepolia\.blockscout|arweave|ar-io/ }], ['local', { isTor: false }], ['testnet', {}]] as const) {
    const { p, out } = await preflightOf(network, o)
    const ids = (r: { id: string }) => r.id === 'btc-identity' || r.id === 'btc-endpoints' || r.id.startsWith('service-')
    const page = rowsOf(network, p).filter(ids).map(({ id, ok, label, detail }) => ({ id, ok, label, detail }))
    const cli = out.rows.filter(ids).map((r) => ({ id: r.id, ok: r.ok, label: r.label, detail: r.detail }))
    assert.ok(page.length >= 4)
    assert.deepEqual(cli, wire(page))
    assert.equal(out.rows.filter((r) => ids(r) && r.ok === false).length, 0)
    assert.deepEqual(out.rows.filter((r) => r.ok === false).map((r) => r.id), [], JSON.stringify(out.rows.filter((r) => r.ok === false)))
    assert.equal(out.exit, 0, `${network} ${JSON.stringify(o)}`)
  }
})

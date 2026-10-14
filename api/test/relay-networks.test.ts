// The ported relay per network (R71), in process: createRelay with an injected transport that plays every upstream
// (Tor check, RPC endpoints, Jupiter), so nothing leaves the machine and no chain or Tor is needed. The relay is served on
// 127.0.0.1 port 0. Covers: upstream lists from endpoints.json (one source; 1rpc.io demoted), the identity checks
// (a mismatch is fatal: exit code 2), requestAirdrop per network, the testnet price label, the send gate end to end
// (S4: genuine signed bytes pass; bytes that are not what the ticket binds → relay.decode-mismatch, never forwarded),
// /relay/status and /relay/tor shapes, and a log scan with the canary. Synthetic data only.
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer, request } from 'node:http'
import { fileURLToPath } from 'node:url'
import { PORTS } from '@vault-timelock/core/contracts'
import type { Network, RelayStatus, TicketPayload } from '@vault-timelock/core/contracts'
import { GENESIS } from 'vt-broadcast/src/config.ts'
import { refuse } from 'vt-broadcast/src/guard.ts'
import {
  RELAY_PROBES, TESTNET_PRICE_LABEL, createRelay, demote, parseRelayArgs, relayUpstreams, socksTransport, torAgent,
} from '../relay/relay.mjs'
import { encodeTicket } from '../src/tickets.ts'
import type { TicketBinding } from '../src/tickets.ts'
import { ANY_BINDING, ETH_TEST_KEY, genuineEth, genuineEthClawback, genuineSol, genuineSolClawback, txIdOf } from './genuine.ts'
import type { Genuine } from './genuine.ts'
import { CANARY, JOB_INPUT, START, TICKET_KEY, armBody, call, plannedGas, plannedPayloads, startApi } from './helpers.ts'

const ENDPOINTS = JSON.parse(readFileSync(fileURLToPath(import.meta.resolve('vt-broadcast/endpoints.json')), 'utf8')) as Record<Network, Record<string, string[]>>
const TOR_CHECK = 'https://check.torproject.org/api/ip'
const NOW = 1_791_504_000_000
const LOCAL_GENESIS = '8pUq7jxkLxNpHg6M9KxzRtNEC4pNEHsr4kDTLSE5uVRW'
const IDS: Record<Network, { eth: string; sol: string }> = {
  local: { eth: '0x7a69', sol: LOCAL_GENESIS }, testnet: { eth: '0xaa36a7', sol: GENESIS.sol.devnet }, mainnet: { eth: '0x1', sol: GENESIS.sol.mainnet },
}
const SOL_MINT = 'So11111111111111111111111111111111111111112'
const ETH_MINT = '7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs'

interface Rpc { jsonrpc: string; id: unknown; method: string; params?: unknown[] }
interface Call { url: string; method: string; role: string; user: string; rpc: Rpc | null }
interface UpRes { status: number; body: Buffer }
const json = (status: number, v: unknown): UpRes => ({ status, body: Buffer.from(JSON.stringify(v)) })

// Every upstream the relay may reach, faked. `override` answers first (a reply, an Error to throw, or undefined).
function fakeUpstream(network: Network, o: { override?: (url: string, rpc: Rpc | null) => UpRes | Error | undefined; isTor?: boolean; estimate?: number } = {}) {
  const calls: Call[] = []
  const transport = async (url: string, r: { method: string; body?: Buffer; role: string; user: string }): Promise<UpRes> => {
    const rpc = r.body ? JSON.parse(r.body.toString('utf8')) as Rpc : null
    calls.push({ url, method: r.method, role: r.role, user: r.user, rpc })
    const x = o.override?.(url, rpc)
    if (x instanceof Error) throw x
    if (x) return x
    if (url === TOR_CHECK) return json(200, { IsTor: o.isTor ?? true, IP: CANARY })
    if (url.startsWith('https://api.jup.ag/') || url.startsWith('https://lite-api.jup.ag/')) {
      return json(200, { [SOL_MINT]: { usdPrice: 151.5, blockId: 1, decimals: 9, liquidity: 5e8 }, [ETH_MINT]: { usdPrice: 3010.25, blockId: 1, decimals: 8, liquidity: 3e7 } })
    }
    if (rpc === null) return json(404, {})
    // FORK_PROBE_BYTES = 100. Sepolia (Amsterdam): 15000 + 64·n to another address, 12000 + 64·n to itself (no `from` =
    // the zero address, so a probe to 0x0 without a sender is a self-transfer); Prague: 21000 + 40·n either way.
    const tx = (rpc.params?.[0] ?? {}) as { from?: string; to?: string }
    const self = typeof tx.from !== 'string' || tx.from.toLowerCase() === String(tx.to).toLowerCase()
    const estimate = o.estimate ?? (network === 'testnet' ? (self ? 18_400 : 21_400) : 25_000)
    const result = rpc.method === 'eth_chainId' ? IDS[network].eth : rpc.method === 'getGenesisHash' ? IDS[network].sol
      : rpc.method === 'eth_estimateGas' ? `0x${estimate.toString(16)}` : `${rpc.method}-result`
    return json(200, { jsonrpc: '2.0', id: rpc.id, result })
  }
  return { calls, transport }
}

interface Started { port: number; logs: string[]; calls: Call[]; status(): RelayStatus; close(): Promise<void> }
async function start(network: Network, o: Parameters<typeof fakeUpstream>[1] & { ticketKey?: () => Uint8Array; priceFixture?: { SOL: number; ETH: number } | null } = {}): Promise<Started> {
  const up = fakeUpstream(network, o)
  const logs: string[] = []
  const relay = createRelay({
    network, build: 'test', upstream: relayUpstreams(network, {}), transport: up.transport,
    priceFixture: o.priceFixture === undefined ? (network === 'local' ? { SOL: 150, ETH: 3000 } : null) : o.priceFixture,
    ticketKey: o.ticketKey ?? (() => TICKET_KEY), confinement: { ok: true, probes: 5, result: 'EPERM ×5' },
    now: () => NOW, log: (l: string) => { logs.push(l) }, rand: () => 'sess',
  })
  await relay.startup()
  const server = createServer(relay.handle)
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const port = (server.address() as { port: number }).port
  const s: Started = { port, logs, calls: up.calls, status: relay.status, close: () => { OPEN.delete(s); return new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()) }) } }
  OPEN.add(s)
  return s
}
// Whatever a failing assertion left open is closed at the end, so the file always exits (never a hang).
const OPEN = new Set<Started>()
after(() => Promise.all([...OPEN].map((s) => s.close())))

interface Reply { status: number; text: string; json: any }
function rq(s: Started, network: Network, path: string, o: { method?: string; body?: unknown; headers?: Record<string, string | string[]> } = {}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const b = o.body === undefined ? null : Buffer.from(typeof o.body === 'string' ? o.body : JSON.stringify(o.body))
    const r = request({ host: '127.0.0.1', port: s.port, path, method: o.method ?? (b ? 'POST' : 'GET'),
      headers: { host: `127.0.0.1:${PORTS[network].relay}`, ...(b ? { 'content-type': 'application/json', 'content-length': String(b.length) } : {}), ...o.headers } }, (res) => {
      const c: Buffer[] = []
      res.on('data', (d: Buffer) => c.push(d))
      res.on('end', () => { const text = Buffer.concat(c).toString('utf8'); let j: unknown; try { j = JSON.parse(text) } catch { j = undefined } resolve({ status: res.statusCode ?? 0, text, json: j }) })
    })
    r.on('error', reject)
    r.end(b ?? undefined)
  })
}
const rpc = (method: string, params: unknown[] = []): Rpc => ({ jsonrpc: '2.0', id: 7, method, params })
const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex')
// A ticket for bytes the gate refuses before decoding (t and the binding are fillers).
function ticket(network: Network, chain: 'eth' | 'sol', raw: Uint8Array): string {
  const t = chain === 'eth' ? `0x${'cd'.repeat(32)}` : '4nFJ19CY7VzhcJt9CEThokVbZVgtBDVgzJFz65YQQwTKYYYXLEu3e6yRMFGT8WG3FuUG8i7VjS7He77vbinmLEpC'
  const p: TicketPayload = { j: 'e3d45f73cf65abaa', w: network, c: chain, g: 1, t, r: sha(raw), ...ANY_BINDING[chain], e: NOW + 120_000, n: 'fedcba9876543210' }
  return encodeTicket(TICKET_KEY, p)
}
// The ticket the API gives a genuine tx (S4: t = its id; the binding as given, the genuine one by default).
function genuineTicket(network: Network, chain: 'eth' | 'sol', g: Genuine, binding: TicketBinding = g.binding): string {
  return encodeTicket(TICKET_KEY, { j: 'e3d45f73cf65abaa', w: network, c: chain, g: 1, t: txIdOf(chain, g.raw), r: sha(g.raw), ...binding, e: NOW + 120_000, n: 'fedcba9876543210' })
}
const sends = (calls: Call[], method: string): Call[] => calls.filter((c) => c.rpc?.method === method)
const guardOf = (r: Reply): string | undefined => r.json?.error?.data?.guard
async function fatalOf(p: Promise<unknown>): Promise<{ exitCode: number; message: string }> {
  let v: unknown
  try { v = await p } catch (e) { return { exitCode: (e as { exitCode?: number }).exitCode ?? -1, message: (e as Error).message } }
  if (typeof (v as Started | null)?.close === 'function') await (v as Started).close()
  assert.fail('expected a fatal startup')
}

test('testnet upstream lists equal endpoints.json testnet eth.rpc / sol.rpc; mainnet eth demotes 1rpc.io; local is loopback', { timeout: 30_000 }, () => {
  assert.deepEqual(relayUpstreams('testnet', {}), { eth: ENDPOINTS.testnet['eth.rpc'], sol: ENDPOINTS.testnet['sol.rpc'] })
  assert.deepEqual(relayUpstreams('testnet', {}).eth, ['https://ethereum-sepolia-rpc.publicnode.com'])   // S3 review m4 + ruling: publicnode only
  assert.deepEqual(relayUpstreams('testnet', {}).sol, ['https://api.devnet.solana.com'])
  const m = relayUpstreams('mainnet', {})
  assert.deepEqual(m.eth, ['https://ethereum-rpc.publicnode.com', 'https://eth.drpc.org', 'https://1rpc.io/eth'])
  assert.deepEqual([...m.eth].sort(), [...ENDPOINTS.mainnet['eth.rpc']].sort())
  assert.deepEqual(m.sol, ENDPOINTS.mainnet['sol.rpc'])
  assert.deepEqual(relayUpstreams('local', {}), { eth: ENDPOINTS.local['eth.rpc'], sol: ENDPOINTS.local['sol.rpc'] })
  assert.deepEqual(demote(['https://1rpc.io/x', 'https://a.example', 'https://1rpc.io/y', 'https://b.example']), ['https://a.example', 'https://b.example', 'https://1rpc.io/x', 'https://1rpc.io/y'])
})

test('test overrides (VT_TEST_*_RPC): local and loopback only; refused on testnet and mainnet (exit 2)', { timeout: 30_000 }, async () => {
  assert.deepEqual(relayUpstreams('local', { VT_TEST_ETH_RPC: 'http://127.0.0.1:18545', VT_TEST_SOL_RPC: 'http://127.0.0.1:18999' }),
    { eth: ['http://127.0.0.1:18545'], sol: ['http://127.0.0.1:18999'] })
  for (const n of ['testnet', 'mainnet'] as const) {
    for (const k of ['VT_TEST_ETH_RPC', 'VT_TEST_SOL_RPC']) {
      const f = await fatalOf(Promise.resolve().then(() => relayUpstreams(n, { [k]: 'http://127.0.0.1:18545' })))
      assert.equal(f.exitCode, 2)
      assert.match(f.message, new RegExp(`^${k} is a local test override — refused with --network ${n}$`))
    }
  }
  const off = await fatalOf(Promise.resolve().then(() => relayUpstreams('local', { VT_TEST_SOL_RPC: `http://${CANARY}:8899` })))
  assert.equal(off.exitCode, 2)
  assert.ok(!off.message.includes(CANARY))
})

test('the relay uses exactly those lists: every testnet identity check goes to endpoints.json testnet, over the Tor roles', { timeout: 30_000 }, async () => {
  const seen = new Set<string>()
  const s = await start('testnet', { override: (url, r) => (url.includes('publicnode') && r?.method === 'eth_chainId' && !seen.has(url) ? (seen.add(url), json(429, { error: 'busy' })) : undefined) })   // one refusal: a fresh circuit, then OK
  try {
    const ids = s.calls.filter((c) => c.rpc?.method === 'eth_chainId' || c.rpc?.method === 'getGenesisHash')
    assert.deepEqual([...new Set(ids.filter((c) => c.role === 'eth').map((c) => c.url))].sort(), [...ENDPOINTS.testnet['eth.rpc']].sort())
    assert.deepEqual(ids.filter((c) => c.role === 'sol').map((c) => c.url), ENDPOINTS.testnet['sol.rpc'])
    assert.ok(s.calls.every((c) => /^(?:eth|sol|price|check)\.sess\.\d+$/.test(c.user)))
    assert.equal(s.calls[0].url, TOR_CHECK)                                               // Tor first
    assert.deepEqual(s.status(), { network: 'testnet', build: 'test', confined: true, identity: { eth: { ok: true }, sol: { ok: true } }, endpoints: { eth: 1, sol: 1 } })
    assert.ok(s.logs.some((l) => /^tor eth gen \d+→\d+ 429 \d+ms$/.test(l)))                       // a fresh circuit, then the retry
    assert.ok(s.logs.some((l) => /^identity eth ethereum-sepolia-rpc\.publicnode\.com: eth_chainId 0xaa36a7 OK/.test(l)))
    assert.ok(s.logs.some((l) => l.startsWith(`identity sol api.devnet.solana.com: genesis ${GENESIS.sol.devnet} (devnet) OK`)))
    assert.ok(s.logs.includes('fork probe eth: amsterdam OK'))
  } finally { await s.close() }
})

test('identity mismatch (a fake upstream answering chainId 0x1 on testnet) → startup fails with exit code 2, naming the host only', { timeout: 30_000 }, async () => {
  const eth = await fatalOf(start('testnet', { override: (url, r) => (url.includes('publicnode') && r?.method === 'eth_chainId' ? json(200, { jsonrpc: '2.0', id: 1, result: '0x1' }) : undefined) }))
  assert.equal(eth.exitCode, 2)
  assert.equal(eth.message, "eth identity MISMATCH at ethereum-sepolia-rpc.publicnode.com: the chain id is not testnet's (11155111)")
  const sol = await fatalOf(start('testnet', { override: (_u, r) => (r?.method === 'getGenesisHash' ? json(200, { jsonrpc: '2.0', id: 1, result: GENESIS.sol.mainnet }) : undefined) }))
  assert.equal(sol.exitCode, 2)
  assert.equal(sol.message, 'sol identity MISMATCH at api.devnet.solana.com: not the pinned testnet genesis')
  const mainnetAtLocal = await fatalOf(start('local', { override: (_u, r) => (r?.method === 'eth_chainId' ? json(200, { jsonrpc: '2.0', id: 1, result: '0x1' }) : undefined) }))
  assert.equal(mainnetAtLocal.exitCode, 2)
  assert.match(mainnetAtLocal.message, /^eth identity MISMATCH at loopback:8545: /)
  const publicGenesisAtLocal = await fatalOf(start('local', { override: (_u, r) => (r?.method === 'getGenesisHash' ? json(200, { jsonrpc: '2.0', id: 1, result: GENESIS.sol.devnet }) : undefined) }))
  assert.equal(publicGenesisAtLocal.message, 'sol identity MISMATCH at loopback:8999: the genesis is public or malformed')
  const odd = await fatalOf(start('mainnet', { override: (_u, r) => (r?.method === 'eth_chainId' ? json(200, { jsonrpc: '2.0', id: 1, result: `${CANARY}` }) : undefined) }))
  assert.equal(odd.exitCode, 2)
  assert.ok(!odd.message.includes(CANARY))
  const noTor = await fatalOf(start('testnet', { isTor: false }))
  assert.deepEqual(noTor, { exitCode: 2, message: 'Tor check failed' })
  const none = await fatalOf(start('testnet', { override: (url) => (url === TOR_CHECK ? undefined : Object.assign(new Error('x'), { code: 'ETIMEDOUT' })) }))
  assert.deepEqual(none, { exitCode: 2, message: 'no chain passed identity' })
})

test('requestAirdrop on mainnet → relay.airdrop-network (never forwarded); on testnet (and local) → forwarded unchanged', { timeout: 30_000 }, async () => {
  const addr = '9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin'
  const m = await start('mainnet')
  try {
    const r = await rq(m, 'mainnet', '/relay/sol', { body: rpc('requestAirdrop', [addr, 1_000_000_000]) })
    assert.equal(r.status, 403)
    assert.equal(guardOf(r), 'relay.airdrop-network')
    assert.equal(r.json.id, 7)
    assert.equal(sends(m.calls, 'requestAirdrop').length, 0)
  } finally { await m.close() }
  for (const n of ['testnet', 'local'] as const) {
    const s = await start(n)
    try {
      const r = await rq(s, n, '/relay/sol', { body: rpc('requestAirdrop', [addr, 1_000_000_000]) })
      assert.equal(r.status, 200, n)
      assert.deepEqual(r.json, { jsonrpc: '2.0', id: 7, result: 'requestAirdrop-result' })
      assert.deepEqual(sends(s.calls, 'requestAirdrop').map((c) => c.rpc?.params), [[addr, 1_000_000_000]])
      for (const bad of [[addr, 1_000_000_001], [addr, 0], ['not-an-address', 1], [addr, '1']]) {
        assert.equal((await rq(s, n, '/relay/sol', { body: rpc('requestAirdrop', bad) })).status, 403, JSON.stringify(bad))
      }
      assert.equal((await rq(s, n, '/relay/sol/ep/0', { body: rpc('requestAirdrop', [addr, 1]) })).status, 403)
      const onEth = await rq(s, n, '/relay/eth', { body: rpc('requestAirdrop', [addr, 1]) })
      assert.equal(guardOf(onEth), 'relay.airdrop-network')
      assert.equal(sends(s.calls, 'requestAirdrop').length, 1)
    } finally { await s.close() }
  }
})

test('the testnet /relay/price says TEST FUNDS — NO VALUE (a nominal fixture, never fetched); local: its fixture; mainnet: Jupiter via Tor', { timeout: 30_000 }, async () => {
  const t = await start('testnet')
  try {
    const r = await rq(t, 'testnet', '/relay/price')
    assert.equal(r.status, 200)
    assert.equal(r.json.source, 'TEST FUNDS — NO VALUE')
    assert.equal(TESTNET_PRICE_LABEL, 'TEST FUNDS — NO VALUE')
    assert.equal(r.json.fixture, true)
    assert.equal(r.json.fetchedAt, NOW)
    assert.ok(r.json.prices.SOL.usd > 0 && r.json.prices.ETH.usd > 0)
    assert.deepEqual([r.json.prices.SOL.mint, r.json.prices.ETH.mint], [SOL_MINT, ETH_MINT])
    assert.deepEqual(Object.keys(r.json).sort(), ['fetchedAt', 'fixture', 'prices', 'source'])   // W2's shape
    assert.equal(t.calls.filter((c) => c.role === 'price').length, 0)
  } finally { await t.close() }
  const l = await start('local')
  try {
    const r = await rq(l, 'local', '/relay/price')
    assert.deepEqual([r.status, r.json.source, r.json.fixture, r.json.prices.SOL.usd, r.json.prices.ETH.usd], [200, 'LOCAL FIXTURE PRICE (--price-fixture)', true, 150, 3000])
  } finally { await l.close() }
  const l0 = await start('local', { priceFixture: null })
  try { assert.equal((await rq(l0, 'local', '/relay/price')).status, 503) } finally { await l0.close() }
  const m = await start('mainnet')
  try {
    const r = await rq(m, 'mainnet', '/relay/price')
    assert.equal(r.status, 200)
    assert.deepEqual([r.json.source, r.json.fixture, r.json.prices.SOL.usd, r.json.prices.ETH.usd], ['https://api.jup.ag/price/v3', false, 151.5, 3010.25])
    assert.deepEqual(m.calls.filter((c) => c.role === 'price').map((c) => c.method), ['GET'])
  } finally { await m.close() }
})

test('sends end to end: a valid ticket forwards the identical bytes; no ticket, wrong bytes, another network → refused, nothing forwarded', { timeout: 30_000 }, async () => {
  const s = await start('testnet')
  try {
    const gs = genuineSol(), raw = gs.raw, b64 = gs.b64
    const params = [b64, { encoding: 'base64', skipPreflight: true, maxRetries: 0 }]
    const tk = genuineTicket('testnet', 'sol', gs)
    for (let i = 0; i < 2; i++) {                                                         // a rebroadcast of the same bytes
      const ok = await rq(s, 'testnet', '/relay/sol', { body: rpc('sendTransaction', params), headers: { 'x-vt-send-ticket': tk } })
      assert.equal(ok.status, 200)
      assert.deepEqual(ok.json, { jsonrpc: '2.0', id: 7, result: 'sendTransaction-result' })
    }
    assert.deepEqual(sends(s.calls, 'sendTransaction').map((c) => c.rpc), [rpc('sendTransaction', params), rpc('sendTransaction', params)])
    const refusals: Array<[string, Promise<Reply>]> = [
      ['relay.send-ticket', rq(s, 'testnet', '/relay/sol', { body: rpc('sendTransaction', params) })],
      ['relay.ticket-raw', rq(s, 'testnet', '/relay/sol', { body: rpc('sendTransaction', [randomBytes(200).toString('base64'), params[1]]), headers: { 'x-vt-send-ticket': tk } })],
      ['relay.ticket-network', rq(s, 'testnet', '/relay/sol', { body: rpc('sendTransaction', params), headers: { 'x-vt-send-ticket': ticket('local', 'sol', raw) } })],
      ['relay.ticket-chain', rq(s, 'testnet', '/relay/eth', { body: rpc('eth_sendRawTransaction', [`0x${raw.toString('hex')}`]), headers: { 'x-vt-send-ticket': tk } })],
      ['relay.header-repeated', rq(s, 'testnet', '/relay/sol', { body: `{"jsonrpc":"2.0","id":7,"method":"sendTransaction","params":${JSON.stringify(params)}}`, headers: { 'x-vt-send-ticket': [tk, tk] } })],
    ]
    for (const [guard, p] of refusals) {
      const r = await p
      assert.equal(r.status, 403, guard)
      assert.equal(guardOf(r), guard)
      assert.equal(r.json.error.code, guard === 'relay.header-repeated' ? -32601 : -32003)
    }
    // Sfix1: the endpoint route takes the same ticketed bytes once (the same gate), then refuses that ticket there
    const ep = await rq(s, 'testnet', '/relay/sol/ep/0', { body: rpc('sendTransaction', params), headers: { 'x-vt-send-ticket': tk } })
    assert.deepEqual([ep.status, ep.json], [200, { jsonrpc: '2.0', id: 7, result: 'sendTransaction-result' }])
    const epAgain = await rq(s, 'testnet', '/relay/sol/ep/0', { body: rpc('sendTransaction', params), headers: { 'x-vt-send-ticket': tk } })
    assert.deepEqual([epAgain.status, guardOf(epAgain), epAgain.json.error.code], [403, 'relay.ticket-endpoint-reused', -32003])
    assert.equal(sends(s.calls, 'sendTransaction').length, 3)
    assert.equal(sends(s.calls, 'eth_sendRawTransaction').length, 0)
    const ge = await genuineEth('testnet')
    const e = await rq(s, 'testnet', '/relay/eth', { body: rpc('eth_sendRawTransaction', [ge.hex]), headers: { 'x-vt-send-ticket': genuineTicket('testnet', 'eth', ge) } })
    assert.deepEqual([e.status, e.json.result], [200, 'eth_sendRawTransaction-result'])
    assert.deepEqual(sends(s.calls, 'eth_sendRawTransaction').map((c) => c.rpc?.params), [[ge.hex]])
  } finally { await s.close() }
  const noKey = await start('testnet', { ticketKey: () => refuse('api.token-missing', 'missing') })
  try {
    const raw = randomBytes(64)
    const r = await rq(noKey, 'testnet', '/relay/sol', { body: rpc('sendTransaction', [raw.toString('base64'), { encoding: 'base64' }]), headers: { 'x-vt-send-ticket': ticket('testnet', 'sol', raw) } })
    assert.deepEqual([r.status, guardOf(r)], [403, 'api.token-missing'])
    assert.equal(sends(noKey.calls, 'sendTransaction').length, 0)
  } finally { await noKey.close() }
})

test('S4 over HTTP: signed bytes that are not what the ticket binds → 403 relay.decode-mismatch (-32003), never forwarded; genuine claw-backs pass', { timeout: 30_000 }, async () => {
  const s = await start('testnet')
  try {
    const ge = await genuineEth('testnet'), gs = genuineSol()
    const other = `0x${'22'.repeat(20)}`
    const refusals: Array<[string, string, unknown[], string]> = [
      ['eth payload', '/relay/eth', [ge.hex], genuineTicket('testnet', 'eth', ge, { ...ge.binding, p: 'ab'.repeat(32) })],
      ['eth sender', '/relay/eth', [ge.hex], genuineTicket('testnet', 'eth', ge, { ...ge.binding, a: other })],
      ['eth fee', '/relay/eth', [ge.hex], genuineTicket('testnet', 'eth', ge, { ...ge.binding, f: String(ge.gas * ge.maxFee - 1n) })],
      ['eth kind', '/relay/eth', [ge.hex], genuineTicket('testnet', 'eth', ge, { ...ge.binding, k: 'clawback', p: null, to: other, value: '1' })],
      ['sol payload', '/relay/sol', [gs.b64, { encoding: 'base64' }], genuineTicket('testnet', 'sol', gs, { ...gs.binding, p: 'ab'.repeat(32) })],
      ['sol fee', '/relay/sol', [gs.b64, { encoding: 'base64' }], genuineTicket('testnet', 'sol', gs, { ...gs.binding, f: '4999' })],
      ['eth nonce (CC-3a)', '/relay/eth', [ge.hex], genuineTicket('testnet', 'eth', ge, { ...ge.binding, q: String(ge.nonce + 1) })],
      ['sol blockhash (CC-3a)', '/relay/sol', [gs.b64, { encoding: 'base64' }], genuineTicket('testnet', 'sol', gs, { ...gs.binding, q: '11111111111111111111111111111111' })],
    ]
    const local = await genuineEth('local')                                            // a local chain id at the testnet relay
    refusals.push(['eth chain id', '/relay/eth', [local.hex], genuineTicket('testnet', 'eth', local)])
    const junk = randomBytes(140)                                                      // undecodable bytes with a ticket for exactly them
    refusals.push(['junk', '/relay/eth', [`0x${junk.toString('hex')}`], ticket('testnet', 'eth', junk)])
    for (const [name, path, params, tk] of refusals) {
      const r = await rq(s, 'testnet', path, { body: rpc(path === '/relay/eth' ? 'eth_sendRawTransaction' : 'sendTransaction', params), headers: { 'x-vt-send-ticket': tk } })
      assert.deepEqual([r.status, guardOf(r), r.json.error.code], [403, 'relay.decode-mismatch', -32003], name)
      assert.match(r.json.error.message, /^the signed transaction is not what the API ticketed \((?:eth|sol)\.[a-z-]+\): nothing was forwarded$/, name)
    }
    assert.equal(sends(s.calls, 'eth_sendRawTransaction').length + sends(s.calls, 'sendTransaction').length, 0)
    const ec = await genuineEthClawback('testnet', { to: `0x${'33'.repeat(20)}`, value: 123_456_789n })
    const sc = genuineSolClawback({ to: '8pUq7jxkLxNpHg6M9KxzRtNEC4pNEHsr4kDTLSE5uVRW', lamports: 4_242n })
    const okE = await rq(s, 'testnet', '/relay/eth', { body: rpc('eth_sendRawTransaction', [ec.hex]), headers: { 'x-vt-send-ticket': genuineTicket('testnet', 'eth', ec) } })
    const okS = await rq(s, 'testnet', '/relay/sol', { body: rpc('sendTransaction', [sc.b64, { encoding: 'base64' }]), headers: { 'x-vt-send-ticket': genuineTicket('testnet', 'sol', sc) } })
    assert.deepEqual([okE.status, okS.status], [200, 200])
    assert.deepEqual(sends(s.calls, 'eth_sendRawTransaction').map((c) => c.rpc?.params), [[ec.hex]])
    assert.deepEqual(sends(s.calls, 'sendTransaction').map((c) => c.rpc?.params), [[sc.b64, { encoding: 'base64' }]])
    const lines = s.logs.filter((l) => / 403 \d+ms relay\.decode-mismatch$/.test(l))
    assert.equal(lines.length, refusals.length)
    for (const l of s.logs) for (const leak of [ge.hex.slice(2, 40), ETH_TEST_KEY.address.slice(2).toLowerCase(), gs.b64.slice(0, 30), other.slice(2)]) assert.ok(!l.toLowerCase().includes(leak), l)
  } finally { await s.close() }
})

// M2 FLIP (applied, operator R78): the job-send lock no longer refuses a mainnet job send; every other check of the gate still does.
test('mainnet send (M2 flip: the job-send lock lifted): a genuine mainnet tx with its valid ticket is forwarded once on each chain; other bytes, no ticket, another network\'s ticket → 403, never forwarded', { timeout: 30_000 }, async () => {
  const m = await start('mainnet')
  try {
    const raw = randomBytes(150)
    const e = await rq(m, 'mainnet', '/relay/eth', { body: rpc('eth_sendRawTransaction', [`0x${raw.toString('hex')}`]), headers: { 'x-vt-send-ticket': ticket('mainnet', 'eth', raw) } })
    const s = await rq(m, 'mainnet', '/relay/sol', { body: rpc('sendTransaction', [raw.toString('base64'), { encoding: 'base64' }]), headers: { 'x-vt-send-ticket': ticket('mainnet', 'sol', raw) } })
    for (const r of [e, s]) assert.deepEqual([r.status, guardOf(r)], [403, 'relay.decode-mismatch'])   // not genuine: the decode verification refuses
    const ge = await genuineEth('mainnet'), gs = genuineSol()
    const refusals: Array<[string, Reply]> = [
      ['relay.send-ticket', await rq(m, 'mainnet', '/relay/eth', { body: rpc('eth_sendRawTransaction', [ge.hex]) })],
      ['relay.send-ticket', await rq(m, 'mainnet', '/relay/sol', { body: rpc('sendTransaction', [gs.b64, { encoding: 'base64' }]) })],
      ['relay.ticket-network', await rq(m, 'mainnet', '/relay/eth', { body: rpc('eth_sendRawTransaction', [ge.hex]), headers: { 'x-vt-send-ticket': genuineTicket('testnet', 'eth', ge) } })],
      ['relay.ticket-network', await rq(m, 'mainnet', '/relay/sol', { body: rpc('sendTransaction', [gs.b64, { encoding: 'base64' }]), headers: { 'x-vt-send-ticket': genuineTicket('testnet', 'sol', gs) } })],
      ['relay.decode-mismatch', await rq(m, 'mainnet', '/relay/eth', { body: rpc('eth_sendRawTransaction', [ge.hex]), headers: { 'x-vt-send-ticket': genuineTicket('mainnet', 'eth', ge, { ...ge.binding, p: 'ab'.repeat(32) }) } })],
    ]
    for (const [want, r] of refusals) assert.deepEqual([r.status, guardOf(r)], [403, want], want)
    assert.equal(sends(m.calls, 'eth_sendRawTransaction').length + sends(m.calls, 'sendTransaction').length, 0, 'nothing refused was forwarded')
    // a testnet-signed ETH tx (chain id 11155111) under a mainnet ticket: the decode verification refuses it (eth.chain-id)
    const tge = await genuineEth('testnet')
    const wrong = await rq(m, 'mainnet', '/relay/eth', { body: rpc('eth_sendRawTransaction', [tge.hex]), headers: { 'x-vt-send-ticket': genuineTicket('mainnet', 'eth', tge) } })
    assert.deepEqual([wrong.status, guardOf(wrong)], [403, 'relay.decode-mismatch'])
    // genuine mainnet bytes with their own ticket: forwarded, byte for byte, once each
    const ge2 = await rq(m, 'mainnet', '/relay/eth', { body: rpc('eth_sendRawTransaction', [ge.hex]), headers: { 'x-vt-send-ticket': genuineTicket('mainnet', 'eth', ge) } })
    const gs2 = await rq(m, 'mainnet', '/relay/sol', { body: rpc('sendTransaction', [gs.b64, { encoding: 'base64' }]), headers: { 'x-vt-send-ticket': genuineTicket('mainnet', 'sol', gs) } })
    assert.deepEqual([ge2.status, ge2.json.result], [200, 'eth_sendRawTransaction-result'])
    assert.deepEqual([gs2.status, gs2.json.result], [200, 'sendTransaction-result'])
    assert.deepEqual(sends(m.calls, 'eth_sendRawTransaction').map((c) => c.rpc?.params), [[ge.hex]])
    assert.deepEqual(sends(m.calls, 'sendTransaction').map((c) => c.rpc?.params), [[gs.b64, { encoding: 'base64' }]])
    const read = await rq(m, 'mainnet', '/relay/eth', { body: rpc('eth_blockNumber') })   // reads still work
    assert.deepEqual([read.status, read.json.result], [200, 'eth_blockNumber-result'])
  } finally { await m.close() }
})

test('/relay/status and /relay/tor shapes; a fork drift is reported with its specific message', { timeout: 30_000 }, async () => {
  const l = await start('local')
  try {
    assert.deepEqual((await rq(l, 'local', '/relay/status')).json, { network: 'local', build: 'test', confined: true, identity: { eth: { ok: true }, sol: { ok: true } }, endpoints: { eth: 1, sol: 1 } })
    const tor = (await rq(l, 'local', '/relay/tor')).json
    assert.deepEqual(Object.keys(tor), ['profile', 'tor', 'isTor', 'checkedAt', 'auto', 'roles', 'torRoles', 'endpoints', 'confinement'])
    assert.deepEqual([tor.profile, tor.tor, tor.isTor, Object.keys(tor.roles).join(), tor.torRoles], ['local', false, null, 'eth,sol,price,check', []])   // S6 fix 1: no drand here, nothing via Tor
    const nw = await rq(l, 'local', '/relay/tor/new', { body: { role: 'eth' } })
    assert.equal(nw.status, 403)
    assert.equal((await rq(l, 'local', '/relay/release')).json.release, false)       // a dev tree has no SHA256SUMS
  } finally { await l.close() }
  const m = await start('mainnet', { estimate: 21_400 })                             // Amsterdam-shaped gas on mainnet
  try {
    const st = (await rq(m, 'mainnet', '/relay/status')).json as RelayStatus
    assert.deepEqual(st.identity, { eth: { ok: false, message: 'Amsterdam appears active on mainnet — update required' }, sol: { ok: true } })
    assert.deepEqual(st.endpoints, { eth: 3, sol: 2 })
    const tor = (await rq(m, 'mainnet', '/relay/tor')).json
    assert.deepEqual([tor.profile, tor.tor, tor.isTor, tor.auto], ['mainnet', true, true, true])
    const nw = await rq(m, 'mainnet', '/relay/tor/new', { body: { role: 'all' } })
    assert.equal(nw.status, 200)
    assert.deepEqual(Object.keys(nw.json), ['results', 'status'])
    const auto = await rq(m, 'mainnet', '/relay/tor/auto', { body: { on: false } })
    assert.deepEqual([auto.status, auto.json.auto], [200, false])
  } finally { await m.close() }
  const t = await start('testnet', { estimate: 25_000 })
  try {
    assert.equal((await rq(t, 'testnet', '/relay/status')).json.identity.eth.message, 'Amsterdam appears inactive on testnet — update required')
  } finally { await t.close() }
})

test('the request gate over HTTP: foreign Origin, Host, Sec-Fetch-Site → 403 with the guard; policy routes as MQ', { timeout: 30_000 }, async () => {
  const s = await start('local')
  try {
    const cases: Array<[string, Promise<Reply>, number, string | undefined]> = [
      ['origin', rq(s, 'local', '/relay/eth', { body: rpc('eth_chainId'), headers: { origin: 'http://evil.example' } }), 403, 'relay.origin'],
      ['host', rq(s, 'local', '/relay/eth', { body: rpc('eth_chainId'), headers: { host: 'localhost:5181' } }), 403, 'relay.host'],
      ['site', rq(s, 'local', '/relay/eth', { body: rpc('eth_chainId'), headers: { 'sec-fetch-site': 'cross-site' } }), 403, 'relay.fetch-site'],
      ['dev page', rq(s, 'local', '/relay/eth', { body: rpc('eth_chainId'), headers: { origin: 'http://127.0.0.1:5183', 'sec-fetch-site': 'same-origin' } }), 200, undefined],
      ['page host', rq(s, 'local', '/relay/eth', { body: rpc('eth_chainId'), headers: { host: '127.0.0.1:5180', origin: 'http://127.0.0.1:5180' } }), 200, undefined],
      ['not allowlisted', rq(s, 'local', '/relay/eth', { body: rpc('eth_accounts') }), 403, 'relay.method'],
      ['feeHistory 1024 base-fee', rq(s, 'local', '/relay/eth', { body: rpc('eth_feeHistory', ['0x400', 'latest', []]) }), 200, undefined],
      ['feeHistory 1024 rewards', rq(s, 'local', '/relay/eth', { body: rpc('eth_feeHistory', ['0x400', 'latest', [10]]) }), 403, undefined],
      ['batch', rq(s, 'local', '/relay/eth', { body: [rpc('eth_chainId')] }), 403, undefined],
    ]
    for (const [name, p, status, guard] of cases) {
      const r = await p
      assert.equal(r.status, status, name)
      assert.equal(guardOf(r), guard, name)
    }
  } finally { await s.close() }
  const t = await start('testnet')
  try {
    const dev = await rq(t, 'testnet', '/relay/eth', { body: rpc('eth_chainId'), headers: { origin: 'http://127.0.0.1:5183' } })
    assert.deepEqual([dev.status, guardOf(dev)], [403, 'relay.origin'])                // the dev server is local only
  } finally { await t.close() }
})

test('logs never carry params, tickets or an IP (canary): request lines are "<tag> <method> <status> <ms>ms[ <guard>]"', { timeout: 30_000 }, async () => {
  const hexCanary = Buffer.from(CANARY).toString('hex')
  const s = await start('testnet', { override: (url, r) => (url.includes('publicnode') && r?.method === 'eth_call' ? Object.assign(new Error(`connect ECONNREFUSED ${CANARY}:443`), { code: 'ECONNREFUSED' }) : undefined) })
  try {
    await rq(s, 'testnet', '/relay/eth', { body: rpc('eth_call', [{ to: `0x${'11'.repeat(20)}`, data: `0x${hexCanary}` }, 'latest']) })
    await rq(s, 'testnet', '/relay/eth', { body: { ...rpc('eth_getBalance', [CANARY, 'latest']), id: CANARY } })
    await rq(s, 'testnet', '/relay/eth', { body: rpc('eth_sendRawTransaction', [`0x${hexCanary}`]), headers: { 'x-vt-send-ticket': `vt-ticket/1.${CANARY}` } })
    await rq(s, 'testnet', '/relay/eth', { body: rpc('eth_chainId'), headers: { host: `${CANARY}:5191` } })
    await rq(s, 'testnet', '/relay/eth', { body: rpc('eth_chainId'), headers: { origin: `http://${CANARY}` } })
    await rq(s, 'testnet', '/relay/tor')
    await rq(s, 'testnet', `/relay/${CANARY}`, { body: rpc('eth_chainId') })
    const all = s.logs.join('\n')
    assert.ok(!all.includes(CANARY) && !all.includes(hexCanary), 'the canary reached the log')
    assert.ok(!/\b\d{1,3}(?:\.\d{1,3}){3}\b/.test(all), 'an IPv4 literal reached the log')
    const circuit = s.logs.filter((l) => /^tor [a-z]+ gen /.test(l))
    assert.ok(circuit.length >= 1)
    for (const l of circuit) assert.match(l, /^tor (?:eth|sol|price|check) gen \d+→\d+ [A-Za-z0-9 ]+ \d+ms$/)
    const reqLines = s.logs.filter((l) => /^(?:eth|sol|price|tor|release|status|-) /.test(l) && !circuit.includes(l))
    assert.ok(reqLines.length >= 7)
    for (const l of reqLines) assert.match(l, /^(?:eth|sol|price|tor|release|status|-) (?:[A-Za-z_]+|-) \d{3} \d+ms(?: [a-z0-9]+(?:[.-][a-z0-9]+)*)?$/)
    assert.ok(reqLines.some((l) => / 403 \d+ms relay\.send-ticket$/.test(l)))
  } finally { await s.close() }
})

test('the confinement probes: loopback 9 and the DNS socket first, then TEST-NET-1 :9/:443/:80 — never Tor or the relay port', { timeout: 30_000 }, () => {
  assert.deepEqual(RELAY_PROBES.map((p) => p.label), ['loopback port 9', 'the DNS socket', 'TEST-NET-1 port 9', 'TEST-NET-1 port 443', 'TEST-NET-1 port 80'])
  assert.ok(RELAY_PROBES.every((p) => p.kind !== 'tcp' || p.port !== 9050))
})

test('the command line: --network (or --profile), --home absolute; --price-fixture local only; --port 0 tests only', { timeout: 30_000 }, () => {
  const home = '/nonexistent-vt-home'
  assert.deepEqual(parseRelayArgs(['--network', 'testnet', '--home', home]), { network: 'testnet', home, build: 'dev', priceFixture: null, port: null })
  assert.deepEqual(parseRelayArgs(['--profile', 'local', '--home', home, '--price-fixture', 'SOL=150,ETH=3000', '--build', 'b1']),
    { network: 'local', home, build: 'b1', priceFixture: { SOL: 150, ETH: 3000 }, port: null })
  const fails = (argv: string[]): string => { try { parseRelayArgs(argv); return 'passed' } catch (e) { return (e as Error).message } }
  assert.equal(fails(['--network', 'mainnet', '--home', home, '--price-fixture', 'SOL=1,ETH=1']), '--price-fixture is only allowed with --network local')
  assert.equal(fails(['--network', 'testnet', '--home', home, '--price-fixture', 'SOL=1,ETH=1']), '--price-fixture is only allowed with --network local')
  for (const argv of [[], ['--network', 'devnet', '--home', home], ['--network', 'local'], ['--network', 'local', '--home', 'rel'], ['--network', 'local', '--profile', 'local', '--home', home],
    ['--network', 'local', '--home', home, '--port', '5181'], ['--network', 'local', '--home', home, '--extra', 'x'], ['--network', 'local', '--home', home, '--build', 'a b']]) {
    assert.match(fails(argv), /^usage: /, argv.join(' '))
  }
  const saved = process.env.NODE_ENV
  try {
    delete process.env.NODE_ENV
    assert.throws(() => parseRelayArgs(['--network', 'local', '--home', home, '--port', '0']), (e: { guardId?: string }) => e.guardId === 'api.test-only')
    process.env.NODE_ENV = 'test'
    assert.equal(parseRelayArgs(['--network', 'local', '--home', home, '--port', '0']).port, 0)
  } finally {
    if (saved === undefined) delete process.env.NODE_ENV
    else process.env.NODE_ENV = saved
  }
})

test('a ticket S2\'s API issues for a journaled intent passes this relay\'s gate: those bytes go upstream, no others', { timeout: 30_000 }, async () => {
  assert.equal(START, NOW)                                                            // the API's fake clock and the relay's clock agree
  // I2: S2's real job service (a testnet job of this file's genuine key, armed over HTTP); the ticket's `a` is the job
  // DEFINITION's key, `f` the worst case its cap reserved, `q` the declared nonce
  const input = { ...JOB_INPUT, network: 'testnet', chains: { eth: { ...(JOB_INPUT.chains as { eth: Record<string, unknown> }).eth, keyAddress: ETH_TEST_KEY.address } } }
  const a = await startApi({ network: 'testnet', jobs: [input] })
  const s = await start('testnet')
  try {
    const id = a.ids[0]
    const j = a.api.registry.journalOf(id)
    await j.append({ chain: 'eth', by: 'cli', gen: null, type: 'key-loaded', data: { address: ETH_TEST_KEY.address } })
    await j.append({ chain: 'eth', by: 'cli', gen: null, type: 'funds', data: { balance: '50000000000000000', affordable: true, nextCopyCost: '25000300000000' } })
    const armedR = await call(a.port, { path: `/jobs/${id}/arm`, body: armBody(['eth'], { countdownSec: 5 }), network: 'testnet' })
    assert.equal(armedR.status, 200, armedR.text)
    a.clock.set((armedR.json as { armed: { releaseAt: number } }).armed.releaseAt)
    const g = await call(a.port, { path: `/jobs/${id}/chains/eth/lease`, body: { op: 'acquire', holder: 'cli' }, network: 'testnet' })
    assert.equal(g.status, 200, g.text)
    const gen = (g.json as { gen: number }).gen
    // PF-S I-1: the executor signs the part the API plans from the stored message (copy c of this job)
    const plan = (copy: number): Uint8Array => plannedPayloads(input, 'eth', copy)[0]
    const gasOf = (copy: number): bigint => BigInt(plannedGas(input, copy))   // PF-S fix round 2: the planned gas (ticket.fee-plan)
    const ge = await genuineEth('testnet', { nonce: 0, payload: plan(1), gas: gasOf(1) })
    const raw = ge.raw, hex = ge.hex
    const intentOf = (x: typeof ge, over: Record<string, unknown> = {}): Record<string, unknown> => ({ txId: x.txId, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: sha(x.raw),
      payloadSha256: sha(x.payload), reserved: String(x.gas * x.maxFee), eth: { nonce: x.nonce, tip: '1000000', maxFee: String(x.maxFee), gas: String(x.gas), to: '0x0000000000000000000000000000000000000000' }, ...over })
    const data = intentOf(ge)
    const ack = await call(a.port, { path: `/jobs/${id}/chains/eth/events`, body: { gen, type: 'intent', data }, network: 'testnet' })
    assert.equal(ack.status, 200, ack.text)
    const tk = (ack.json as { ticket: string }).ticket
    const ok = await rq(s, 'testnet', '/relay/eth', { body: rpc('eth_sendRawTransaction', [hex]), headers: { 'x-vt-send-ticket': tk } })
    assert.deepEqual([ok.status, ok.json.result], [200, 'eth_sendRawTransaction-result'])
    assert.deepEqual(sends(s.calls, 'eth_sendRawTransaction').map((c) => c.rpc?.params), [[hex]])
    const other = Buffer.from(raw); other[0] ^= 0xff
    const bad = await rq(s, 'testnet', '/relay/eth', { body: rpc('eth_sendRawTransaction', [`0x${other.toString('hex')}`]), headers: { 'x-vt-send-ticket': tk } })
    assert.deepEqual([bad.status, guardOf(bad)], [403, 'relay.ticket-raw'])
    const sol = await rq(s, 'testnet', '/relay/sol', { body: rpc('sendTransaction', [raw.toString('base64'), { encoding: 'base64' }]), headers: { 'x-vt-send-ticket': tk } })
    assert.deepEqual([sol.status, guardOf(sol)], [403, 'relay.ticket-chain'])
    // PF-S I-1: an intent that declares any payload but the planned part gets no ticket at all (nothing is journaled)
    const arbitrary = await genuineEth('testnet', { nonce: 1, gas: gasOf(2) })
    const refused = await call(a.port, { path: `/jobs/${id}/chains/eth/events`, body: { gen, type: 'intent', data: intentOf(arbitrary, { copy: 2 }) }, network: 'testnet' })
    assert.deepEqual([refused.status, (refused.json as { error: { guard: string } }).error.guard], [409, 'ticket.payload-plan'])
    // S4: an executor that declares fields its signed bytes do not have gets a ticket for them, and the relay refuses the
    // bytes: the planned payloadSha256 over other calldata (the ticket binds the PLAN, so other bytes never pass), a gas ×
    // maxFee below the signed one (the cap reserved too little: the planned gas declared, one more signed). Each on its own
    // (copy, part): S2 allows one nonce family per (copy, part) in flight.
    const lies: Array<[string, Awaited<ReturnType<typeof genuineEth>>, Record<string, unknown>]> = [
      ['payload', arbitrary, { copy: 2, payloadSha256: sha(plan(2)) }],
      ['fee', await genuineEth('testnet', { nonce: 2, gas: gasOf(3) + 1n, payload: plan(3) }), { copy: 3, eth: { nonce: 2, tip: '1000000', maxFee: '3000000000', gas: String(gasOf(3)), to: '0x0000000000000000000000000000000000000000' } }],
    ]
    for (const [name, x, over] of lies) {
      const lie = await call(a.port, { path: `/jobs/${id}/chains/eth/events`, body: { gen, type: 'intent', data: intentOf(x, over) }, network: 'testnet' })
      assert.equal(lie.status, 200, lie.text)
      const r = await rq(s, 'testnet', '/relay/eth', { body: rpc('eth_sendRawTransaction', [x.hex]), headers: { 'x-vt-send-ticket': (lie.json as { ticket: string }).ticket } })
      assert.deepEqual([r.status, guardOf(r)], [403, 'relay.decode-mismatch'], name)
    }
    // CC-3a, the review's probe (I-1): attempt 1 declares and signs nonce 7 and is forwarded; attempt 2 is declared a bump
    // of the same nonce-7 family (replaces attempt 1) but is signed at nonce 8. Its ticket binds q = 7: refused, never
    // forwarded, so a family counted once can never land twice.
    const a7 = await genuineEth('testnet', { nonce: 7, payload: plan(4), gas: gasOf(4) })
    const t7 = await call(a.port, { path: `/jobs/${id}/chains/eth/events`, body: { gen, type: 'intent', data: intentOf(a7, { copy: 4 }) }, network: 'testnet' })
    assert.equal(t7.status, 200, t7.text)
    const ok7 = await rq(s, 'testnet', '/relay/eth', { body: rpc('eth_sendRawTransaction', [a7.hex]), headers: { 'x-vt-send-ticket': (t7.json as { ticket: string }).ticket } })
    assert.equal(ok7.status, 200)
    const b8 = await genuineEth('testnet', { nonce: 8, payload: a7.payload, maxFee: 3_375_000_000n, gas: gasOf(4) })
    const bump = intentOf(b8, { copy: 4, attempt: 2, replaces: a7.txId, eth: { nonce: 7, tip: '1000000', maxFee: '3375000000', gas: String(b8.gas), to: '0x0000000000000000000000000000000000000000' } })
    const t8 = await call(a.port, { path: `/jobs/${id}/chains/eth/events`, body: { gen, type: 'intent', data: bump }, network: 'testnet' })
    assert.equal(t8.status, 200, t8.text)
    const r8 = await rq(s, 'testnet', '/relay/eth', { body: rpc('eth_sendRawTransaction', [b8.hex]), headers: { 'x-vt-send-ticket': (t8.json as { ticket: string }).ticket } })
    assert.deepEqual([r8.status, guardOf(r8), r8.json.error.message], [403, 'relay.decode-mismatch', 'the signed transaction is not what the API ticketed (eth.nonce): nothing was forwarded'])
    assert.deepEqual(sends(s.calls, 'eth_sendRawTransaction').map((c) => c.rpc?.params), [[hex], [a7.hex]])
    assert.equal(sends(s.calls, 'eth_sendRawTransaction').length + sends(s.calls, 'sendTransaction').length, 2)
  } finally { await s.close(); await a.close() }
})

test('default deny over HTTP: a send by another name (eth_sendRawTransactionSync, …) is refused relay.method and never forwarded', { timeout: 30_000 }, async () => {
  const raw = randomBytes(90), hex = `0x${raw.toString('hex')}`
  for (const n of ['mainnet', 'testnet'] as const) {
    const s = await start(n)
    try {
      const probes: Array<['eth' | 'sol', string, unknown[]]> = [
        ['eth', 'eth_sendRawTransactionSync', [hex]], ['eth', 'eth_sendRawTransactionConditional', [hex, {}]], ['eth', 'eth_sendTransaction', [{}]],
        ['eth', 'eth_sendBundle', [{ txs: [hex] }]], ['eth', 'sendTransaction', [raw.toString('base64'), { encoding: 'base64' }]],
        ['sol', 'sendBundle', [[raw.toString('base64')]]], ['sol', 'eth_sendRawTransaction', [hex]], ['sol', 'sendRawTransaction', [raw.toString('base64')]],
        ['eth', 'ETH_SENDRAWTRANSACTION', [hex]], ['eth', '__proto__', []], ['eth', 'anvil_setBalance', ['0x00', '0x1']],
      ]
      for (const [chain, method, params] of probes) {
        const variants: Array<Record<string, string>> = [{}, { 'x-vt-send-ticket': ticket(n, chain, raw) }]
        for (const headers of variants) {
          const r = await rq(s, n, `/relay/${chain}`, { body: { jsonrpc: '2.0', id: 3, method, params }, headers })
          assert.deepEqual([r.status, guardOf(r)], [403, 'relay.method'], `${n} ${chain} ${method}`)
        }
      }
      const forwarded = s.calls.filter((c) => c.rpc !== null && !['eth_chainId', 'getGenesisHash', 'eth_estimateGas'].includes(c.rpc.method))
      assert.deepEqual(forwarded.map((c) => c.rpc?.method), [], `${n}: something reached the upstream`)
      assert.ok(s.logs.filter((l) => / 403 \d+ms relay\.method$/.test(l)).every((l) => l.startsWith('eth disallowed ') || l.startsWith('sol disallowed ')))
    } finally { await s.close() }
  }
})

test('socks5h is pinned: every Tor agent resolves names at the exit (no local DNS); one agent per role and circuit; none locally', () => {
  for (const n of ['testnet', 'mainnet'] as const) {
    const t = socksTransport(n)
    const a = t.agentFor('eth', 'eth.sess.0')
    assert.ok(a !== undefined)
    assert.deepEqual([a.proxy.type, a.proxy.host, a.proxy.port, a.proxy.userId, a.shouldLookup], [5, '127.0.0.1', 9050, 'eth.sess.0', false])
    assert.equal(t.agentFor('eth', 'eth.sess.0'), a)                                           // the same circuit, the same agent
    const b = t.agentFor('eth', 'eth.sess.1')
    assert.ok(b !== undefined && b !== a && b.shouldLookup === false && b.proxy.userId === 'eth.sess.1')   // a new circuit
    const p = t.agentFor('price', 'price.sess.0')
    assert.ok(p !== undefined && p !== b && p.shouldLookup === false)
  }
  assert.equal(socksTransport('local').agentFor('eth', 'eth.sess.0'), undefined)               // local: direct loopback, no Tor
  assert.equal(torAgent('check.x.0').shouldLookup, false)
})

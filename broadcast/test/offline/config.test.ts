import { test } from 'node:test'
import assert from 'node:assert/strict'
import { chmodSync, cpSync, mkdirSync, symlinkSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  GENESIS, NETWORK_IDS, anchor, chainId, endpoint, endpointInfo, isFaucetNetwork, isLocalBitcoinGenesis, isLocalNetwork,
  isLocalSolanaGenesis, isOnion, loadBitcoindAuth, loadConfig, loopbackPorts, networkName, parseOverrides, parseProfile, parseTimingOverrides,
} from '../../src/config.ts'
import { Refusal } from '../../src/guard.ts'

const ROOT = new URL('../../', import.meta.url).pathname
const refused = (f: () => unknown, id: string) =>
  assert.throws(f, (e: unknown) => e instanceof Refusal && e.guardId === id, `expected ${id}`)

const K20 = 'a1B2c3D4e5F6g7H8i9J0' // 20 alphanumerics
const ONION = 'mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad'

// A temp copy of the two json files, mutated by `edit`.
function withJson(edit: (e: any, a: any) => void, run: (dir: string) => void) {
  const d = mkdtempSync(join(tmpdir(), 'vt-cfg-'))
  try {
    cpSync(join(ROOT, 'endpoints.json'), join(d, 'endpoints.json'))
    cpSync(join(ROOT, 'anchors.json'), join(d, 'anchors.json'))
    const e = JSON.parse(readFileSync(join(d, 'endpoints.json'), 'utf8'))
    const a = JSON.parse(readFileSync(join(d, 'anchors.json'), 'utf8'))
    edit(e, a)
    writeFileSync(join(d, 'endpoints.json'), JSON.stringify(e))
    writeFileSync(join(d, 'anchors.json'), JSON.stringify(a))
    run(d)
  } finally {
    rmSync(d, { recursive: true, force: true })
  }
}
const loadWith = (edit: (e: any, a: any) => void, profile: 'mainnet' | 'testnet' | 'local' = 'mainnet') =>
  withJson(edit, (d) => loadConfig(profile, {}, {}, d))

test('the real json files load cleanly with an empty env, in every profile', () => {
  for (const p of ['mainnet', 'testnet', 'local'] as const) {
    const c = loadConfig(p, {})
    assert.equal(c.profile, p)
  }
  const m = loadConfig('mainnet', {})
  assert.ok(endpoint(m, 'eth.rpc').length >= 2)
  assert.deepEqual(endpoint(loadConfig('local', {}), 'eth.rpc'), ['http://127.0.0.1:8545'])
})

test('the local profile loads eth.rpc, sol.rpc, btc.bitcoind and btc.ord (R35), all direct loopback', () => {
  const l = loadConfig('local', {})
  assert.deepEqual(endpoint(l, 'eth.rpc'), ['http://127.0.0.1:8545'])
  assert.deepEqual(endpoint(l, 'sol.rpc'), ['http://127.0.0.1:8999'])
  assert.deepEqual(endpoint(l, 'btc.bitcoind'), ['http://127.0.0.1:18443'])
  assert.deepEqual(endpoint(l, 'btc.ord'), ['http://127.0.0.1:8090'])
  assert.ok(['eth.rpc', 'sol.rpc', 'btc.bitcoind', 'btc.ord'].every((k) => endpointInfo(l, k).every((e) => e.direct)))
  assert.deepEqual(loopbackPorts(l), [8090, 8545, 8999, 18443])
})

test('btc.ord is a known key: no default in testnet, an override follows the normal rules', () => {
  const t = loadConfig('testnet', {})
  refused(() => endpoint(t, 'btc.ord'), 'config.endpoint-missing')
  const o = loadConfig('testnet', {}, parseOverrides(['--endpoint', 'btc.ord=https://ord.example.org'], {}))
  assert.deepEqual(endpoint(o, 'btc.ord'), ['https://ord.example.org'])
  assert.deepEqual(endpoint(loadConfig('testnet', {}, { 'btc.ord': 'http://127.0.0.1:8090' }), 'btc.ord'), ['http://127.0.0.1:8090'])
  refused(() => loadConfig('testnet', {}, { 'btc.ord': 'http://ord.example.org' }), 'config.scheme')
  refused(() => loadConfig('testnet', {}, { 'btc.ord': 'https://ord.example.org/?apikey=x' }), 'config.url-key')
  assert.deepEqual(parseOverrides([], { VT_ENDPOINT_BTC_ORD: 'http://127.0.0.1:8090' }), { 'btc.ord': 'http://127.0.0.1:8090' })
  assert.deepEqual(parseOverrides([], { VT_ENDPOINT_BTC_BITCOIND: 'http://127.0.0.1:18443' }), { 'btc.bitcoind': 'http://127.0.0.1:18443' })
})

test('btc.bitcoind: userinfo in the URL is refused (the credential lives in the auth file only)', () => {
  // H0 (K27): the key check runs before the scheme check, so userinfo is config.url-key even on loopback.
  refused(() => loadConfig('local', {}, { 'btc.bitcoind': 'http://vt:secret@127.0.0.1:18443' }), 'config.url-key')
  refused(() => loadConfig('local', {}, { 'btc.bitcoind': 'https://vt:secret@node.example.org' }), 'config.url-key')
})

test('endpoints.json: onion candidates come before clearnet and are marked not direct', () => {
  const m = loadConfig('mainnet', {})
  const btc = endpointInfo(m, 'btc.esplora')
  assert.ok(btc[0].url.endsWith('.onion/api'))
  assert.ok(btc.every((e) => !e.direct))
  assert.equal(endpoint(loadConfig('testnet', {}), 'btc.esplora')[1], 'https://mempool.space/testnet4/api')
})

test('config.endpoint-missing: thorchain has no testnet endpoint; unknown key', () => {
  refused(() => endpoint(loadConfig('testnet', {}), 'thorchain'), 'config.endpoint-missing')
  assert.equal(endpoint(loadConfig('mainnet', {}), 'thorchain').length, 1)
  refused(() => endpoint(loadConfig('mainnet', {}), 'nope.rpc'), 'config.endpoint-missing')
})

// ---- config.env-key
test('config.env-key: names the variable, never the value', () => {
  const secret = 'sentinel-secret-value-123'
  for (const name of ['ALCHEMY_API_KEY', 'infura_project', 'HELIUS_X', 'QUICKNODE_URL', 'ANKR_KEY', 'MORALIS', 'FOO_API_KEY', 'FOO_APIKEY']) {
    assert.throws(() => loadConfig('mainnet', { [name]: secret }), (e: unknown) =>
      e instanceof Refusal && e.guardId === 'config.env-key' && e.message.includes(name) && !e.message.includes(secret), name)
  }
  assert.throws(() => loadConfig('mainnet', { ALCHEMY_API_KEY: 'x' }), (e: unknown) =>
    e instanceof Refusal && e.guardId === 'config.env-key' && !e.message.includes('x'))
})
test('config.env-key: negatives (empty value, unrelated names)', () => {
  loadConfig('mainnet', { ALCHEMY_API_KEY: '' })
  loadConfig('mainnet', { PATH: '/usr/bin', HOME: '/h', API_KEYS_NOT: 'v', MYANKR: 'v', FOO_API_KEY_X: 'v' })
})

// ---- config.url-key / scheme / onion-order via endpoints.json
test('config.url-key: key-like path segment or query parameter (json)', () => {
  for (const u of [`https://x.example/v2/${K20}`, `https://x.example/v3/${K20}/extra`, 'https://x.example/rpc?api-key=a',
    'https://x.example/rpc?apikey=a', 'https://x.example/rpc?API_KEY=a', 'https://x.example/rpc?a=1&key=a',
    'https://x.example/rpc?token=a', 'https://user:pw@x.example/rpc']) {
    refused(() => loadWith((e) => { e.mainnet['eth.rpc'] = [u] }), 'config.url-key')
  }
})
test('config.url-key: negatives', () => {
  for (const u of ['https://x.example/v2/short', `https://x.example/v1/${K20}`, 'https://x.example/api/v2', 'https://x.example/rpc?monkey=a&chain=1']) {
    loadWith((e) => { e.mainnet['eth.rpc'] = [u] })
  }
})
test('config.scheme: only https, onion http, or exact loopback http', () => {
  for (const u of ['http://x.example/rpc', 'ftp://x.example', 'ws://x.example', 'x.example', 'HTTPS://x.example', `http://${ONION.slice(1)}.onion/api`,
    `http://${ONION.toUpperCase()}.onion`, `http://${ONION}.onion.evil.example/api`, 'https://', 'https://x example/']) {
    refused(() => loadWith((e) => { e.mainnet['eth.rpc'] = [u] }), 'config.scheme')
  }
  loadWith((e) => { e.mainnet['btc.esplora'] = [`http://${ONION}.onion/api`, 'https://mempool.space/api'] })
})
test('config.scheme: loopback edge cases (https loopback, no port, localhost, bad port, query)', () => {
  for (const u of ['https://127.0.0.1:8545', 'https://[::1]:8545', 'https://localhost:8545', 'http://127.0.0.1', 'http://[::1]', 'http://127.0.0.1/',
    'http://localhost:8545', 'http://127.0.0.1:0', 'http://127.0.0.1:65536', 'http://127.0.0.1:08545', 'http://127.0.0.2:8545',
    'http://127.0.0.1:8545?x=1', 'https://127.0.0.1', 'http://0.0.0.0:8545']) {
    refused(() => loadWith((e) => { e.mainnet['eth.rpc'] = [u] }), 'config.scheme')
  }
  // userinfo is a key in any URL, endpoints.json included, and the key check runs first (H0, K27)
  refused(() => loadWith((e) => { e.mainnet['eth.rpc'] = ['http://user@127.0.0.1:8545'] }), 'config.url-key')
  for (const u of ['http://127.0.0.1:8545', 'http://[::1]:8545', 'http://127.0.0.1:1', 'http://127.0.0.1:65535', 'http://127.0.0.1:8545/rpc']) {
    loadWith((e) => { e.mainnet['eth.rpc'] = [u] })
  }
})
test('config.onion-order: a clearnet URL before an onion URL is refused', () => {
  refused(() => loadWith((e) => { e.mainnet['btc.esplora'] = ['https://mempool.space/api', `http://${ONION}.onion/api`] }), 'config.onion-order')
  loadWith((e) => { e.mainnet['btc.esplora'] = [`http://${ONION}.onion/api`, 'https://mempool.space/api'] })
  loadWith((e) => { e.mainnet['btc.esplora'] = ['https://mempool.space/api', 'https://blockstream.info/api'] })
})
test('config.endpoints-list: a section entry must be a known key with a non-empty list of strings', () => {
  refused(() => loadWith((e) => { e.mainnet['eth.rpc'] = [] }), 'config.endpoints-list')
  refused(() => loadWith((e) => { e.mainnet['eth.rpc'] = 'https://x.example' }), 'config.endpoints-list')
  refused(() => loadWith((e) => { e.mainnet['eth.rpc'] = [5] }), 'config.endpoints-list')
  refused(() => loadWith((e) => { e.testnet['mystery.rpc'] = ['https://x.example'] }), 'config.endpoints-list')
})
test('config.endpoints-shape: endpoints.json must have exactly mainnet, testnet and local sections', () => {
  refused(() => loadWith((e) => { delete e.local }), 'config.endpoints-shape')
  refused(() => loadWith((e) => { e.extra = {} }), 'config.endpoints-shape')
  refused(() => loadWith((e) => { e.testnet = [] }), 'config.endpoints-shape')
  withJson(() => {}, (d) => {
    writeFileSync(join(d, 'endpoints.json'), '[]')
    refused(() => loadConfig('mainnet', {}, {}, d), 'config.endpoints-shape')
  })
})

// ---- anchors
test('anchors: every entry has an official source; present ones load and resolve', () => {
  const a = JSON.parse(readFileSync(join(ROOT, 'anchors.json'), 'utf8'))
  for (const [name, v] of Object.entries<any>(a)) {
    assert.match(v.source, /^https:\/\//, name)
    assert.ok(['mainnet', 'testnet', 'any'].includes(v.network), name)
  }
  const m = loadConfig('mainnet', {})
  assert.equal(anchor(m, 'railgun.proxy.eth'), '0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9')
  assert.equal(anchor(m, 'solana.memo'), 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr')
  assert.equal(anchor(m, 'drand.quicknet'), '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971')
  const t = loadConfig('testnet', {})
  assert.equal(anchor(t, 'railgun.proxy.sepolia'), '0xeCFCf3b4eC647c4Ca6D49108b311b7a7C9543fea')
})
test('config.anchor-missing: null, absent, unknown', () => {
  withJson((_e, a) => { a['railgun.proxy.eth'].address = null }, (d) => {
    const c = loadConfig('mainnet', {}, {}, d) // loading is fine; using it is not
    refused(() => anchor(c, 'railgun.proxy.eth'), 'config.anchor-missing')
    assert.equal(anchor(c, 'solana.memo'), 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr')
  })
  withJson((_e, a) => { delete a['solana.memo'] }, (d) => refused(() => anchor(loadConfig('mainnet', {}, {}, d), 'solana.memo'), 'config.anchor-missing'))
  refused(() => anchor(loadConfig('mainnet', {}), 'no.such.anchor'), 'config.anchor-missing')
})
test('config.anchor-format: EVM, base58-32, hex64', () => {
  const bad = (name: string, v: string) => refused(() => loadWith((_e, a) => { a[name].address = v }), 'config.anchor-format')
  for (const v of ['0x' + 'a'.repeat(39), '0x' + 'a'.repeat(41), 'a'.repeat(42), '0x' + 'g'.repeat(40), '', ' 0x' + 'a'.repeat(40)]) bad('railgun.proxy.eth', v)
  for (const v of ['abc', 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcH', 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr1', '0'.repeat(32), 'l'.repeat(44), '1'.repeat(33)]) bad('solana.memo', v)
  for (const v of ['ab', 'z'.repeat(64), '5'.repeat(63), '5'.repeat(65)]) bad('drand.quicknet', v)
  loadWith((_e, a) => { a['railgun.proxy.eth'].address = '0x' + 'aB'.repeat(20) })
  loadWith((_e, a) => { a['solana.memo'].address = '1'.repeat(32) }) // 32 zero bytes
  loadWith((_e, a) => { a['solana.memo'].address = '11111111111111111111111111111111' })
})
test('config.anchors-entry: malformed anchor entries', () => {
  refused(() => loadWith((_e, a) => { a['solana.memo'].source = 'http://insecure.example' }), 'config.anchors-entry')
  refused(() => loadWith((_e, a) => { a['solana.memo'].network = 'devnet' }), 'config.anchors-entry')
  refused(() => loadWith((_e, a) => { a['mystery'] = { address: null, source: 'https://x.example', network: 'any' } }), 'config.anchors-entry')
  refused(() => loadWith((_e, a) => { a['solana.memo'] = 5 }), 'config.anchors-entry')
  refused(() => loadWith((_e, a) => { a['solana.memo'].address = 5 }), 'config.anchors-entry')
})
test('config.anchors-shape: anchors.json must be an object', () => {
  withJson(() => {}, (d) => {
    writeFileSync(join(d, 'anchors.json'), '[]')
    refused(() => loadConfig('mainnet', {}, {}, d), 'config.anchors-shape')
  })
})
test('config.anchor-network: an anchor from another network is refused', () => {
  refused(() => anchor(loadConfig('mainnet', {}), 'railgun.proxy.sepolia'), 'config.anchor-network')
  refused(() => anchor(loadConfig('testnet', {}), 'railgun.proxy.eth'), 'config.anchor-network')
  refused(() => anchor(loadConfig('local', {}), 'railgun.proxy.eth'), 'config.anchor-network')
  assert.equal(anchor(loadConfig('testnet', {}), 'solana.memo'), 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr')
})

// ---- identities
test('network identities are code constants', () => {
  assert.deepEqual(NETWORK_IDS.mainnet, { eth: 1, arb: 42161, base: 8453 })
  assert.deepEqual(NETWORK_IDS.testnet, { eth: 11155111, arb: 421614, base: 84532 })
  assert.deepEqual(NETWORK_IDS.local, { eth: 31337 })
  assert.equal(GENESIS.btc.regtest, '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206')
  assert.equal(GENESIS.sol.mainnet, '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d')
  assert.equal(GENESIS.sol.devnet, 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG')
  assert.equal(GENESIS.sol.testnet, '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY')
  assert.equal(GENESIS.btc.mainnet, '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')
  assert.equal(GENESIS.btc.testnet4, '00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043')
})
test('isFaucetNetwork: testnet values only', () => {
  for (const id of [11155111, 421614, 84532, GENESIS.sol.devnet, GENESIS.btc.testnet4]) assert.equal(isFaucetNetwork(id), true, String(id))
  for (const id of [1, 42161, 8453, 31337, 0, -1, 1.5, NaN, GENESIS.sol.mainnet, GENESIS.sol.testnet, GENESIS.btc.mainnet, '', 'devnet', '11155111', '1']) {
    assert.equal(isFaucetNetwork(id), false, String(id))
  }
})
test('isLocalNetwork: 31337 in the local profile only', () => {
  assert.equal(isLocalNetwork(31337, 'local'), true)
  assert.equal(isLocalNetwork(1, 'local'), false) // an anvil fork must use --chain-id 31337
  assert.equal(isLocalNetwork(31337, 'mainnet'), false)
  assert.equal(isLocalNetwork(31337, 'testnet'), false)
  assert.equal(isLocalNetwork(11155111, 'local'), false)
})
test('chainId per profile; config.local-scope for arb and base (and anything but eth, sol, btc) in local', () => {
  assert.equal(chainId('mainnet', 'arb'), 42161)
  assert.equal(chainId('testnet', 'base'), 84532)
  assert.equal(chainId('local', 'eth'), 31337)
  for (const c of ['arb', 'base'] as const) refused(() => chainId('local', c), 'config.local-scope')
  const l = loadConfig('local', {})
  for (const k of ['arb.rpc', 'base.rpc', 'arb.blockscout', 'base.blockscout']) refused(() => endpoint(l, k), 'config.local-scope')
  for (const n of ['arbitrum.inbox.mainnet', 'base.l1StandardBridge.mainnet']) refused(() => anchor(l, n), 'config.local-scope')
  for (const k of ['eth.rpc', 'sol.rpc', 'btc.bitcoind', 'btc.ord']) assert.equal(endpoint(l, k).length, 1, k)
  refused(() => endpoint(l, 'drand'), 'config.local-scope') // nothing but eth, sol and btc is local
  refused(() => endpoint(l, 'btc.esplora'), 'config.endpoint-missing') // btc is local, but esplora has no local default
  refused(() => endpoint(l, 'nope.rpc'), 'config.local-scope')
})

// ---- overrides
// Task T1: one source for the per-chain network names (triggers, M1's preflight, Part D's banner).
test('networkName: the 16 names by profile and chain; local Arbitrum/Base refuse config.local-scope; an unknown chain config.network-name', () => {
  const want = {
    mainnet: { eth: 'Ethereum mainnet · 1', arb: 'Arbitrum One · 42161', base: 'Base · 8453', sol: 'Solana mainnet-beta', btc: 'Bitcoin mainnet', arweave: 'Arweave mainnet' },
    testnet: { eth: 'Sepolia · 11155111', arb: 'Arbitrum Sepolia · 421614', base: 'Base Sepolia · 84532', sol: 'Solana devnet', btc: 'Bitcoin testnet4', arweave: 'Arweave dev sandbox (ar-io.dev)' },
    local: { eth: 'anvil · 31337', sol: 'Solana local', btc: 'Bitcoin regtest', arweave: 'Arweave (local: skipped)' },
  } as const
  let n = 0
  for (const [profile, names] of Object.entries(want)) {
    for (const [chain, name] of Object.entries(names)) { assert.equal(networkName(profile as 'mainnet', chain as 'eth'), name); n++ }
  }
  assert.equal(n, 16)
  refused(() => networkName('local', 'arb'), 'config.local-scope')
  refused(() => networkName('local', 'base'), 'config.local-scope')
  for (const p of ['mainnet', 'testnet'] as const) refused(() => networkName(p, 'doge' as 'eth'), 'config.network-name')
  refused(() => networkName('testnet', '__proto__' as 'eth'), 'config.network-name')
  refused(() => networkName('prod' as 'mainnet', 'eth'), 'config.profile-invalid')
})

test('parseOverrides: --rpc and --endpoint, env forms', () => {
  assert.deepEqual(parseOverrides(['--rpc', 'eth=http://127.0.0.1:8545'], {}), { 'eth.rpc': 'http://127.0.0.1:8545' })
  assert.deepEqual(parseOverrides(['--rpc', 'sol=https://s.example', '--rpc', 'arb=https://a.example', '--endpoint', 'btc.esplora=https://b.example/api'], {}),
    { 'sol.rpc': 'https://s.example', 'arb.rpc': 'https://a.example', 'btc.esplora': 'https://b.example/api' })
  assert.deepEqual(parseOverrides([], { VT_RPC_ETH: 'http://127.0.0.1:8545', VT_ENDPOINT_BTC_ESPLORA: 'https://b.example/api', VT_ENDPOINT_TURBO_UPLOAD: 'https://t.example', PATH: '/x' }),
    { 'eth.rpc': 'http://127.0.0.1:8545', 'btc.esplora': 'https://b.example/api', 'turbo.upload': 'https://t.example' })
  // flag wins over env for the same key
  assert.deepEqual(parseOverrides(['--rpc', 'eth=https://f.example'], { VT_RPC_ETH: 'https://e.example' }), { 'eth.rpc': 'https://f.example' })
})
test('config.override-key: unknown chain or service; chains are --rpc only, services --endpoint only', () => {
  for (const argv of [['--rpc', 'btc=https://x.example'], ['--rpc', 'eth.rpc=https://x.example'], ['--rpc', 'nope=https://x.example'],
    ['--endpoint', 'eth.rpc=https://x.example'], ['--endpoint', 'eth=https://x.example'], ['--endpoint', 'nope=https://x.example']]) {
    refused(() => parseOverrides(argv, {}), 'config.override-key')
  }
  for (const env of [{ VT_RPC_BTC: 'https://x.example' }, { VT_RPC_NOPE: 'https://x.example' }, { VT_ENDPOINT_NOPE: 'https://x.example' },
    { VT_ENDPOINT_ETH_RPC: 'https://x.example' }, { VT_ENDPOINT_BTC: 'https://x.example' }]) {
    refused(() => parseOverrides([], env), 'config.override-key')
  }
})
test('config.override-format: no "=", empty side', () => {
  for (const argv of [['--rpc', 'eth'], ['--rpc', 'eth='], ['--rpc', '=https://x.example'], ['--endpoint', 'drand']]) {
    refused(() => parseOverrides(argv, {}), 'config.override-format')
  }
})
test('config.override-duplicate: the same key twice on the command line', () => {
  refused(() => parseOverrides(['--rpc', 'eth=https://a.example', '--rpc', 'eth=https://b.example'], {}), 'config.override-duplicate')
  refused(() => parseOverrides(['--endpoint', 'drand=https://a.example', '--endpoint', 'drand=https://b.example'], {}), 'config.override-duplicate')
})
test('config.flag-format: missing value or --flag=value form is refused, never ignored', () => {
  for (const argv of [['--rpc'], ['--rpc', '--endpoint'], ['--rpc=eth=https://x.example'], ['--endpoint=btc.esplora=https://x.example'], ['--endpoint']]) {
    refused(() => parseOverrides(argv, {}), 'config.flag-format')
  }
  refused(() => parseProfile(['--profile'], {}), 'config.flag-format')
  refused(() => parseProfile(['--profile=local'], {}), 'config.flag-format')
  refused(() => parseTimingOverrides(['--confirmations'], 'testnet'), 'config.flag-format')
})
test('config.flag-duplicate: single-valued flags given twice', () => {
  refused(() => parseProfile(['--profile', 'local', '--profile', 'local'], {}), 'config.flag-duplicate')
  refused(() => parseTimingOverrides(['--tick-seconds', '1', '--tick-seconds', '2'], 'testnet'), 'config.flag-duplicate')
  refused(() => parseTimingOverrides(['--cooling-seconds', '1-2', '--cooling-seconds', '1-2'], 'local'), 'config.flag-duplicate')
  refused(() => parseTimingOverrides(['--confirmations', '1', '--confirmations', '1'], 'local'), 'config.flag-duplicate')
})
test('overrides replace the whole list with the single URL', () => {
  const c = loadConfig('mainnet', {}, { 'eth.rpc': 'https://my.node.example/rpc', 'btc.esplora': 'https://my.esplora.example/api' })
  assert.deepEqual(endpoint(c, 'eth.rpc'), ['https://my.node.example/rpc'])
  assert.deepEqual(endpointInfo(c, 'eth.rpc'), [{ url: 'https://my.node.example/rpc', direct: false }])
  assert.deepEqual(endpoint(c, 'btc.esplora'), ['https://my.esplora.example/api'])
  assert.ok(endpoint(c, 'arb.rpc').length >= 2) // untouched
})
test('override validation: unknown key, url-key, scheme (loadConfig)', () => {
  refused(() => loadConfig('mainnet', {}, { 'nope.rpc': 'https://x.example' }), 'config.override-key')
  refused(() => loadConfig('mainnet', {}, { 'eth.rpc': `https://x/v2/${K20}` }), 'config.url-key')
  refused(() => loadConfig('mainnet', {}, { 'eth.rpc': 'https://x.example/?token=abc' }), 'config.url-key')
  refused(() => loadConfig('mainnet', {}, { 'eth.rpc': 'http://x.example/rpc' }), 'config.scheme')
  refused(() => loadConfig('mainnet', {}, { 'eth.rpc': 'http://localhost:8545' }), 'config.scheme')
  refused(() => loadConfig('mainnet', {}, { 'eth.rpc': 'http://127.0.0.1' }), 'config.scheme')
  refused(() => loadConfig('mainnet', {}, { 'eth.rpc': 'https://127.0.0.1:8545' }), 'config.scheme')
})
test('a loopback override in the mainnet profile is accepted and direct', () => {
  const c = loadConfig('mainnet', {}, { 'eth.rpc': 'http://127.0.0.1:18545', 'sol.rpc': 'http://[::1]:8899' })
  assert.deepEqual(endpointInfo(c, 'eth.rpc'), [{ url: 'http://127.0.0.1:18545', direct: true }])
  assert.deepEqual(endpointInfo(c, 'sol.rpc'), [{ url: 'http://[::1]:8899', direct: true }])
  assert.equal(endpointInfo(c, 'arb.rpc')[0].direct, false)
})
test('config.local-loopback: the local profile accepts loopback only', () => {
  refused(() => loadConfig('local', {}, { 'eth.rpc': 'https://rpc.example.org' }), 'config.local-loopback')
  refused(() => loadConfig('local', {}, { 'eth.blockscout': 'https://b.example.org/api/v2' }), 'config.local-loopback')
  refused(() => loadConfig('local', {}, { 'eth.rpc': `http://${ONION}.onion` }), 'config.local-loopback')
  const c = loadConfig('local', {}, { 'eth.rpc': 'http://127.0.0.1:9999', 'eth.blockscout': 'http://[::1]:5100/api/v2' })
  assert.deepEqual(endpointInfo(c, 'eth.rpc'), [{ url: 'http://127.0.0.1:9999', direct: true }])
  // a non-loopback default in the local section is refused too
  refused(() => loadWith((e) => { e.local['eth.rpc'] = ['https://rpc.example.org'] }, 'local'), 'config.local-loopback')
})
test('local profile: overriding arb or base (or a service of another chain) is config.local-scope', () => {
  for (const key of ['arb.rpc', 'base.rpc', 'arb.blockscout', 'drand']) {
    refused(() => loadConfig('local', {}, { [key]: 'http://127.0.0.1:1234' }), 'config.local-scope')
  }
  for (const key of ['sol.rpc', 'btc.esplora', 'btc.bitcoind', 'btc.ord']) loadConfig('local', {}, { [key]: 'http://127.0.0.1:1234' })
})
test('config.local-scope: a sol or btc endpoint that is not loopback is refused in local', () => {
  for (const key of ['sol.rpc', 'btc.bitcoind', 'btc.ord', 'btc.esplora']) {
    refused(() => loadConfig('local', {}, { [key]: 'https://node.example.org' }), 'config.local-scope')
    refused(() => loadConfig('local', {}, { [key]: `http://${ONION}.onion` }), 'config.local-scope')
  }
  refused(() => loadWith((e) => { e.local['sol.rpc'] = ['https://api.devnet.solana.com'] }, 'local'), 'config.local-scope')
  refused(() => loadWith((e) => { e.local['btc.bitcoind'] = ['https://node.example.org'] }, 'local'), 'config.local-scope')
})

const REGTEST = '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'
test('isLocalSolanaGenesis: false for each public genesis, true for any other hash', () => {
  for (const h of [GENESIS.sol.mainnet, GENESIS.sol.devnet, GENESIS.sol.testnet]) assert.equal(isLocalSolanaGenesis(h), false, h)
  assert.equal(isLocalSolanaGenesis('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'), true) // any well-formed 32-byte hash
  assert.equal(isLocalSolanaGenesis('11111111111111111111111111111111'), true)
  for (const bad of ['', GENESIS.sol.mainnet + 'x', 'abc', '0'.repeat(44)]) assert.equal(isLocalSolanaGenesis(bad), false, bad) // not a hash: never "local"
  assert.equal(isLocalSolanaGenesis(5 as unknown as string), false)
})
test('isLocalBitcoinGenesis: regtest only', () => {
  assert.equal(GENESIS.btc.regtest, REGTEST)
  assert.equal(isLocalBitcoinGenesis(REGTEST), true)
  for (const h of [GENESIS.btc.mainnet, GENESIS.btc.testnet4, '', REGTEST.toUpperCase(), REGTEST + '0', REGTEST.slice(1),
    '00000000' + REGTEST.slice(8), 5 as unknown as string]) assert.equal(isLocalBitcoinGenesis(h), false, String(h))
})

// ---- bitcoind credential file (R36)
const CANARY = 'vt:canary0123456789abcdef0123456789ab'
function withOut(run: (out: string) => void) {
  const out = mkdtempSync(join(tmpdir(), 'vt-out-'))
  try { run(out) } finally { rmSync(out, { recursive: true, force: true }) }
}
function writeAuth(out: string, text: string, mode = 0o600) {
  mkdirSync(join(out, 'local'), { recursive: true })
  const f = join(out, 'local', 'btc-rpc.auth')
  writeFileSync(f, text)
  chmodSync(f, mode)
}
test('loadBitcoindAuth: reads $OUT/local/btc-rpc.auth (one line, 0600) and returns user:pass', () => {
  withOut((out) => {
    writeAuth(out, CANARY + '\n')
    assert.equal(loadBitcoindAuth(out), CANARY)
    writeAuth(out, 'vt:' + 'ab'.repeat(16)) // no trailing newline is fine
    assert.equal(loadBitcoindAuth(out), 'vt:' + 'ab'.repeat(16))
    writeAuth(out, 'a_b.c-1:p@ss/w+rd=\n', 0o400)
    assert.equal(loadBitcoindAuth(out), 'a_b.c-1:p@ss/w+rd=')
  })
})
test('config.bitcoind-auth: missing file, loose mode, malformed line, directory', () => {
  withOut((out) => {
    refused(() => loadBitcoindAuth(out), 'config.bitcoind-auth') // missing
    refused(() => loadBitcoindAuth(join(out, 'nope')), 'config.bitcoind-auth')
    for (const mode of [0o644, 0o640, 0o604, 0o660, 0o666, 0o700, 0o601]) {
      writeAuth(out, CANARY + '\n', mode)
      refused(() => loadBitcoindAuth(out), 'config.bitcoind-auth')
    }
    const bad = ['', '\n', 'vt', 'vt:', ':pw', 'vt:a:b', 'v t:pw', 'vt:p w', 'vt:pw\nsecond:line\n', 'vt:pw\r\n', ' vt:pw', 'vt:pw ', 'v/t:pw', 'vt:pw\n\n', 'vt:p\tw', 'vt:pw\0']
    for (const text of bad) {
      writeAuth(out, text)
      refused(() => loadBitcoindAuth(out), 'config.bitcoind-auth')
    }
    rmSync(join(out, 'local', 'btc-rpc.auth'))
    mkdirSync(join(out, 'local', 'btc-rpc.auth'), { mode: 0o700 })
    refused(() => loadBitcoindAuth(out), 'config.bitcoind-auth') // a directory is no credential file
  })
})
test('config.bitcoind-auth: a symlink to a valid 0600 file is refused (O_NOFOLLOW)', () => {
  withOut((out) => {
    writeAuth(out, CANARY + '\n')
    const real = join(out, 'local', 'real.auth')
    const link = join(out, 'local', 'btc-rpc.auth')
    cpSync(link, real)
    rmSync(link)
    chmodSync(real, 0o600)
    symlinkSync(real, link)
    refused(() => loadBitcoindAuth(out), 'config.bitcoind-auth')
    rmSync(link)
    cpSync(real, link) // the same bytes as a regular file are accepted
    assert.equal(loadBitcoindAuth(out), CANARY)
  })
})
test('config.bitcoind-auth: a file owned by another uid is refused (injected getuid)', () => {
  withOut((out) => {
    writeAuth(out, CANARY + '\n')
    const me = process.getuid!()
    assert.equal(loadBitcoindAuth(out, () => me), CANARY)
    refused(() => loadBitcoindAuth(out, () => me + 1), 'config.bitcoind-auth')
  })
})
test('the bitcoind credential never leaks: not into a refusal message, nor stdout/stderr', () => {
  withOut((out) => {
    const seen: string[] = []
    const grab = (f: () => unknown) => { try { f() } catch (e) { seen.push(String((e as Error).message), String((e as Error).stack ?? ''), JSON.stringify(e, Object.getOwnPropertyNames(e as object))) } }
    writeAuth(out, CANARY + '\n', 0o644); grab(() => loadBitcoindAuth(out))
    writeAuth(out, CANARY + ':extra\n'); grab(() => loadBitcoindAuth(out))
    writeAuth(out, CANARY + ' \n' + CANARY + '\n'); grab(() => loadBitcoindAuth(out))
    assert.equal(seen.length, 9)
    assert.ok(seen.every((m) => !m.includes('canary0123') && !m.includes(CANARY)))
    // loading, and building the local config next to it, writes nothing to stdout/stderr
    writeAuth(out, CANARY + '\n')
    const wo = process.stdout.write, we = process.stderr.write
    const out_: string[] = []
    process.stdout.write = ((c: unknown) => { out_.push(String(c)); return true }) as typeof process.stdout.write
    process.stderr.write = ((c: unknown) => { out_.push(String(c)); return true }) as typeof process.stderr.write
    try { assert.equal(loadBitcoindAuth(out), CANARY); loadConfig('local', {}) } finally { process.stdout.write = wo; process.stderr.write = we }
    assert.deepEqual(out_, [])
    // the config never carries it either
    assert.ok(!JSON.stringify(loadConfig('local', {})).includes('canary'))
  })
})
test('anchor(local, solana.memo) is the Memo v2 program; the Arbitrum and Base anchors stay refused', () => {
  const l = loadConfig('local', {})
  assert.equal(anchor(l, 'solana.memo'), 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr')
  for (const n of ['arbitrum.inbox.mainnet', 'arbitrum.inbox.sepolia', 'base.l1StandardBridge.mainnet', 'base.l1StandardBridge.sepolia']) refused(() => anchor(l, n), 'config.local-scope')
})
test('loopbackPorts: distinct ports from defaults plus overrides, sorted', () => {
  assert.deepEqual(loopbackPorts(loadConfig('local', {})), [8090, 8545, 8999, 18443])
  assert.deepEqual(loopbackPorts(loadConfig('mainnet', {})), [])
  assert.deepEqual(loopbackPorts(loadConfig('local', {}, { 'eth.blockscout': 'http://127.0.0.1:5100', 'eth.rpc': 'http://[::1]:8545' })), [5100, 8090, 8545, 8999, 18443])
  assert.deepEqual(loopbackPorts(loadConfig('mainnet', {}, { 'eth.rpc': 'http://127.0.0.1:9000', 'sol.rpc': 'http://[::1]:9000', 'arb.rpc': 'http://127.0.0.1:80' })), [80, 9000])
  assert.deepEqual(loopbackPorts(loadConfig('local', {}, { 'eth.rpc': 'http://127.0.0.1:9999' })), [8090, 8999, 9999, 18443]) // default replaced
})

// ---- profile selection
test('parseProfile: default mainnet, flag, env, agree', () => {
  assert.equal(parseProfile([], {}), 'mainnet')
  assert.equal(parseProfile(['--profile', 'testnet'], {}), 'testnet')
  assert.equal(parseProfile([], { VT_PROFILE: 'local' }), 'local')
  assert.equal(parseProfile(['--profile', 'local'], { VT_PROFILE: 'local' }), 'local')
  assert.equal(parseProfile([], { VT_PROFILE: '' }), 'mainnet')
})
test('config.profile-conflict: flag disagrees with VT_PROFILE', () => {
  refused(() => parseProfile(['--profile', 'testnet'], { VT_PROFILE: 'mainnet' }), 'config.profile-conflict')
  refused(() => parseProfile(['--profile', 'mainnet'], { VT_PROFILE: 'local' }), 'config.profile-conflict')
})
test('config.profile-invalid: unknown profile name', () => {
  refused(() => parseProfile(['--profile', 'prod'], {}), 'config.profile-invalid')
  refused(() => parseProfile([], { VT_PROFILE: 'Mainnet' }), 'config.profile-invalid')
  refused(() => parseProfile(['--profile', 'prod'], { VT_PROFILE: 'prod' }), 'config.profile-invalid')
})

// ---- timing overrides
test('network.override-mainnet: timing overrides refused in mainnet, accepted in testnet/local', () => {
  for (const argv of [['--tick-seconds', '5'], ['--cooling-seconds', '1-2'], ['--confirmations', '1']]) {
    refused(() => parseTimingOverrides(argv, 'mainnet'), 'network.override-mainnet')
    for (const p of ['testnet', 'local'] as const) parseTimingOverrides(argv, p)
  }
  refused(() => parseTimingOverrides(['--tick-seconds', 'garbage'], 'mainnet'), 'network.override-mainnet') // presence is enough
  assert.deepEqual(parseTimingOverrides([], 'mainnet'), {})
  assert.deepEqual(parseTimingOverrides(['--tick-seconds', '5', '--cooling-seconds', '10-20', '--confirmations', '2'], 'testnet'),
    { tickSeconds: 5, coolingSeconds: [10, 20], confirmations: 2 })
})
test('config.timing-format: malformed timing values', () => {
  for (const argv of [['--tick-seconds', '0'], ['--tick-seconds', '-1'], ['--tick-seconds', '1.5'], ['--tick-seconds', 'x'], ['--tick-seconds', '1e3'],
    ['--cooling-seconds', '5'], ['--cooling-seconds', '20-10'], ['--cooling-seconds', '1-2-3'], ['--cooling-seconds', '-5'], ['--cooling-seconds', 'a-b'],
    ['--confirmations', '0'], ['--confirmations', ' 2'], ['--confirmations', '99999999999999999999']]) {
    refused(() => parseTimingOverrides(argv, 'testnet'), 'config.timing-format')
  }
  assert.deepEqual(parseTimingOverrides(['--cooling-seconds', '7-7'], 'local'), { coolingSeconds: [7, 7] })
})

test('config.override-key: prototype names are not endpoints or anchors', () => {
  const m = loadConfig('mainnet', {})
  for (const k of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) {
    refused(() => endpoint(m, k), 'config.endpoint-missing')
    refused(() => anchor(m, k), 'config.anchor-missing')
  }
  refused(() => loadConfig('mainnet', {}, { constructor: 'https://x.example' }), 'config.override-key')
})
test('config.load: missing or invalid json files refuse with a guard', () => {
  for (const name of ['endpoints.json', 'anchors.json']) {
    withJson(() => {}, (d) => { rmSync(join(d, name)); refused(() => loadConfig('mainnet', {}, {}, d), 'config.load') })
    withJson(() => {}, (d) => { writeFileSync(join(d, name), '{not json'); refused(() => loadConfig('mainnet', {}, {}, d), 'config.load') })
  }
  refused(() => loadConfig('mainnet', {}, {}, join(tmpdir(), 'vt-no-such-dir-xyz')), 'config.load')
})
test('config.override-empty: an empty VT_RPC_* / VT_ENDPOINT_* is refused, not ignored', () => {
  refused(() => parseOverrides([], { VT_RPC_ETH: '' }), 'config.override-empty')
  refused(() => parseOverrides([], { VT_ENDPOINT_DRAND: '' }), 'config.override-empty')
  refused(() => parseOverrides([], { VT_RPC_NOPE: '' }), 'config.override-empty')
  assert.deepEqual(parseOverrides([], { VT_RPC: '', VT_RPCX: '' }), {})
})

// ---- Task H0 items 1-2: no input echo (K27), key-like inversion (K28)
//
// The canary IP (global constraints) and synthetic keys below must never reach any output: these
// tests never hand a refusal's text to assert (assert.throws would print it on a mismatch); they
// compare guard ids and print fixed text only.
const CANARY_IP = '203.0.113.77'
const SYNTH_KEY = 'synthKEY0a1b2c3d4e5f6a7b8c9d0e1f2' // synthetic, 33 chars, letters and digits
const SECRETS = [CANARY_IP, '203.0.113', SYNTH_KEY, SYNTH_KEY.slice(0, 12)]

function refusalOf(f: () => unknown): { id: string | null; text: string } {
  try { f() } catch (e) {
    const err = e as Error
    return { id: e instanceof Refusal ? e.guardId : 'not-a-refusal', text: `${String(err?.message)}\n${String(err?.stack)}` }
  }
  return { id: null, text: '' }
}
// Refused with `id`, and no canary or synthetic key in the refusal's message or stack.
function refusedQuietly(f: () => unknown, id: string, what: string): string {
  const r = refusalOf(f)
  assert.equal(r.id, id, what)
  assert.ok(SECRETS.every((x) => !r.text.includes(x)), `${what}: a canary or synthetic key reached the refusal text`)
  return r.text
}
const overrideAs = (key: string, url: string, profile: 'mainnet' | 'testnet' | 'local' = 'mainnet') => () => loadConfig(profile, {}, { [key]: url })

test('H0-1 (K27): config.scheme names only the key and the scheme class, never the URL', () => {
  const cases: Array<[string, string, string]> = [
    [`http://${CANARY_IP}:8545`, 'http', 'http IP literal'],
    [`http://${CANARY_IP}:8545/rpc`, 'http', 'http IP literal with a path'],
    [`ftp://${CANARY_IP}/x`, 'other', 'ftp'],
    [`ws://${CANARY_IP}:8546`, 'other', 'ws'],
    [`https://${CANARY_IP}/rpc`, 'https', 'https IP literal'],
    [`http://eth-mainnet.example/x/${SYNTH_KEY.slice(0, 12)}`, 'http', 'plain http host'],
    [CANARY_IP, 'other', 'no scheme'],
  ]
  for (const [url, cls, what] of cases) {
    const text = refusedQuietly(overrideAs('eth.rpc', url), 'config.scheme', what)
    assert.ok(text.startsWith('eth.rpc: '), `${what}: the message names the override key`)
    assert.ok(text.includes(`(scheme class: ${cls})`), `${what}: the message names the scheme class ${cls}`)
  }
  // the same through endpoints.json: the label is the section and key
  withJson((e) => { e.mainnet['eth.rpc'] = [`http://${CANARY_IP}:8545`] }, (d) => {
    const text = refusedQuietly(() => loadConfig('mainnet', {}, {}, d), 'config.scheme', 'json http IP literal')
    assert.ok(text.startsWith('endpoints.json mainnet.eth.rpc: '), 'json: the message names the section and key')
  })
})

test('H0-1 (K27): the key check runs first; config.url-key is fixed text (CD-I3 vectors)', () => {
  for (const [url, what] of [
    [`http://eth-mainnet.example/v2/${SYNTH_KEY}`, 'http + /v2/<key>'],
    [`http://127.0.0.1:8545/?apikey=${SYNTH_KEY}`, 'loopback + apikey'],
    [`ws://eth-mainnet.example/v3/${SYNTH_KEY}`, 'ws + /v3/<key>'],
    [`https://user:${SYNTH_KEY}@${CANARY_IP}/`, 'userinfo on an IP literal'],
    [`http://${CANARY_IP}:8545/${SYNTH_KEY}`, 'IP literal + key-like segment'],
  ] as const) {
    const text = refusedQuietly(overrideAs('eth.rpc', url), 'config.url-key', what)
    assert.ok(text.startsWith('eth.rpc: '), `${what}: the message names the override key`)
  }
})

test('H0-1 (K27): profile values are never echoed (config.profile-invalid, config.profile-conflict, config.override-key)', () => {
  refusedQuietly(() => parseProfile(['--profile', `http://${CANARY_IP}/`], {}), 'config.profile-invalid', 'flag')
  refusedQuietly(() => parseProfile([], { VT_PROFILE: `${SYNTH_KEY}` }), 'config.profile-invalid', 'env')
  const conflict = refusalOf(() => parseProfile(['--profile', 'testnet'], { VT_PROFILE: 'local' }))
  assert.equal(conflict.id, 'config.profile-conflict')
  assert.ok(!/\btestnet\b|\blocal\b/.test(conflict.text.split('\n')[0]), 'the conflict message names neither value')
  refusedQuietly(() => parseOverrides(['--rpc', `http://${CANARY_IP}/${SYNTH_KEY}=https://a.example`], {}), 'config.override-key', 'argv key')
})

const HEX40 = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678'
const HEX64 = '0123456789abcdef'.repeat(4)
const HEX32 = '0123456789abcdef'.repeat(2)
const UUID = '123e4567-e89b-12d3-a456-426614174000'
test('H0-2 (K28): key-like overrides are refused (CD-I4 and SA-I7 vectors)', () => {
  const vectors: Array<[string, string]> = [
    // CD-I4
    [`https://example.quiknode.pro/${HEX40}/`, 'QuickNode /<40 hex>/'],
    [`https://rpc.ankr.com/eth/${HEX64}`, 'Ankr /eth/<64 hex>'],
    ['https://lb.drpc.org/ogrpc?network=ethereum&dkey=synthetic', 'dRPC ?dkey='],
    // SA-I7
    ['https://eth-mainnet.g.alchemy.com/v2/ab-cd_efGH-ijkl_mnop-qrstuv', 'Alchemy key with - and _ in the first 20 chars'],
    ['https://eth-mainnet.g.alchemy.com/v2/abcdefghijklmnopQRSTUV', 'Alchemy-style letters-only /v2/ token'],
    [`https://nd-123-456-789.p2pify.com/${HEX32}`, 'Chainstack /<32 hex>'],
    [`https://eth-mainnet.blastapi.io/${UUID}`, 'Blast /<uuid>'],
    ['https://rpc.example.org/?access_token=synthetic', 'access_token'],
    ['https://rpc.example.org/?x-api-key=synthetic', 'x-api-key'],
    [`https://${HEX32}.rpc.example.org/`, 'subdomain token (hex)'],
    ['https://a1b2c3d4e5f6g7h8.rpc.example.org/', 'subdomain token (mixed)'],
    // the inversion: any query string, fragment or userinfo; any long hex / UUID / mixed segment
    ['https://rpc.example.org/?network=ethereum', 'any query string'],
    ['https://rpc.example.org/rpc?', 'an empty query string'],
    ['https://rpc.example.org/rpc#k', 'a fragment'],
    ['https://user@rpc.example.org/', 'userinfo without a password'],
    ['https://rpc.example.org/eth/0123456789ABCDEF', 'upper-case hex, exactly 16'],
    ['https://rpc.example.org/eth/abc123def456ghi7', 'mixed letters and digits, exactly 16'],
    ['https://rpc.example.org/%61%62%63%31%32%33%64%65%66%34%35%36%67%68%69%37', 'a percent-encoded mixed segment'],
    [`https://rpc.example.org/${HEX32}/..`, 'a key segment the URL parser would resolve away'],
    [`https://rpc.example.org/${SYNTH_KEY}`, 'a synthetic key segment'],
  ]
  for (const [url, what] of vectors) refusedQuietly(overrideAs('eth.rpc', url), 'config.url-key', what)
  // ... in VT_* form too, and for a service key
  refusedQuietly(() => loadConfig('mainnet', {}, parseOverrides([], { VT_ENDPOINT_DRAND: `https://drand.example/${HEX32}` })), 'config.url-key', 'VT_ENDPOINT_DRAND')
})

test('H0-2 (K28): ordinary segments pass (short, letters only, digits under 16, words with dashes)', () => {
  for (const url of [
    'https://rpc.example.org/eth', 'https://rpc.example.org/v2/short', 'https://rpc.example.org/api/v2',
    'https://arbitrum-sepolia-rpc.example.org/rpc', 'https://rpc.example.org/chain/thorchain_api',
    'https://rpc.example.org/0123456789abcde', 'https://rpc.example.org/abc123def456ghi', 'https://rpc.example.org/an-ordinary-long-path-name',
    'https://rpc.example.org:8443/rpc', 'https://rpc.example.org/testnet4/api',
  ]) {
    assert.deepEqual(endpoint(loadConfig('mainnet', {}, { 'eth.rpc': url }), 'eth.rpc'), [url], url)
  }
})

test('H0-2 (K28): every endpoints.json URL passes as an override, verbatim and normalized', () => {
  const json = JSON.parse(readFileSync(join(ROOT, 'endpoints.json'), 'utf8')) as Record<string, Record<string, string[]>>
  let n = 0
  for (const [profile, section] of Object.entries(json)) {
    for (const [key, urls] of Object.entries(section)) {
      for (const url of urls) {
        assert.deepEqual(endpoint(loadConfig(profile as 'mainnet', {}, { [key]: url }), key), [url], `${profile} ${key} ${url}`)
        n++
      }
    }
  }
  assert.ok(n >= 40, `endpoints.json URLs checked: ${n}`)
})

test('H0-2 (K28): the endpoints.json exemption (ruling 1: scheme and host lower-cased, one trailing "/" ignored)', () => {
  const keyLike = `https://rpc.public.example/${HEX32}`
  const queried = 'https://rpc.public.example/rpc?chain=1'
  withJson((e) => { e.mainnet['eth.rpc'] = [keyLike]; e.mainnet['drand'] = [queried] }, (d) => {
    // the json itself loads: its own URLs are exempt from the shape rule
    assert.deepEqual(endpoint(loadConfig('mainnet', {}, {}, d), 'eth.rpc'), [keyLike])
    // exact
    for (const [key, url] of [['eth.rpc', keyLike], ['eth.rpc', queried], ['drand', keyLike]]) {
      assert.deepEqual(endpoint(loadConfig('mainnet', {}, { [key]: url }, d), key), [url], `exact ${url}`)
    }
    // normalized-equal: host case, a trailing slash (also on the json side)
    for (const url of [`https://RPC.Public.Example/${HEX32}`, `${keyLike}/`, `https://rpc.PUBLIC.example/${HEX32}/`]) {
      assert.deepEqual(endpoint(loadConfig('mainnet', {}, { 'eth.rpc': url }, d), 'eth.rpc'), [url], `normalized ${url}`)
    }
    // not equal: the path is case-sensitive, another query, a second slash, an added segment
    for (const url of [`https://rpc.public.example/${HEX32.toUpperCase()}`, 'https://rpc.public.example/rpc?chain=2',
      `${keyLike}//`, `${keyLike}/x`, `https://rpc.public.example/${HEX32}?`, `https://other.example/${HEX32}`]) {
      refusedQuietly(() => loadConfig('mainnet', {}, { 'eth.rpc': url }, d), 'config.url-key', url)
    }
    // the scheme still has to be https: an upper-case scheme matches the json entry but is config.scheme
    refusedQuietly(() => loadConfig('mainnet', {}, { 'eth.rpc': `HTTPS://rpc.public.example/${HEX32}` }, d), 'config.scheme', 'HTTPS://')
  })
  // certain keys are refused even inside endpoints.json (never weaker than before H0)
  for (const url of ['https://rpc.public.example/rpc?apikey=synthetic', 'https://u:p@rpc.public.example/', `https://rpc.public.example/v2/${SYNTH_KEY}`]) {
    refusedQuietly(() => loadWith((e) => { e.mainnet['eth.rpc'] = [url] }), 'config.url-key', `json ${url}`)
  }
})

test('H0-2: isPublicHttps refuses IP-literal hosts in every spelling', () => {
  for (const [url, what] of [
    [`https://${CANARY_IP}/rpc`, 'dotted'], ['https://3405803853/rpc', 'decimal'], ['https://0xcb.0.0x71.0x4d/', 'hex parts'],
    ['https://[2001:db8::1]/', 'IPv6'], ['https://[::ffff:203.0.113.77]/', 'IPv4-mapped IPv6'], ['https://198.51.100.9:8443/', 'with a port'],
    ['https://127.0.0.1.example.org/', 'a 127. name'], ['https://rpc.example.org./', 'a trailing-dot name'], ['https://a.localhost/', '.localhost'],
  ] as const) {
    refusedQuietly(overrideAs('eth.rpc', url), 'config.scheme', what)
  }
})

test('H0-2: https://<56>.onion counts as an onion (config.onion-order), and isOnion says so', () => {
  assert.equal(isOnion(`https://${ONION}.onion`), true)
  assert.equal(isOnion(`https://${ONION}.onion/api`), true)
  assert.equal(isOnion(`http://${ONION}.onion/api`), true)
  for (const u of [`https://${ONION.slice(1)}.onion`, `https://x.${ONION}.onion`, 'https://mempool.space/api', `https://${ONION}.onion?x=1`]) {
    assert.equal(isOnion(u), false, u)
  }
  refused(() => loadWith((e) => { e.mainnet['btc.esplora'] = ['https://mempool.space/api', `https://${ONION}.onion/api`] }), 'config.onion-order')
  loadWith((e) => { e.mainnet['btc.esplora'] = [`https://${ONION}.onion/api`, `http://${ONION}.onion/api`, 'https://mempool.space/api'] })
  assert.deepEqual(endpoint(loadConfig('mainnet', {}, { 'btc.esplora': `https://${ONION}.onion/api` }), 'btc.esplora'), [`https://${ONION}.onion/api`])
  // a .onion host that is not a v3 onion address is no https host either
  refused(() => loadConfig('mainnet', {}, { 'btc.esplora': 'https://short.onion/api' }), 'config.scheme')
})

test('H0-2: the env-name rule adds _TOKEN$, _SECRET$, RPC_URL$, PRIVATE_KEY and MNEMONIC', () => {
  for (const name of ['GITHUB_TOKEN', 'npm_token', 'AWS_SECRET', 'ETH_RPC_URL', 'MAINNET_RPC_URL', 'PRIVATE_KEY', 'DEPLOYER_PRIVATE_KEY_HEX',
    'MNEMONIC', 'WALLET_MNEMONIC_PHRASE']) {
    refused(() => loadConfig('mainnet', { [name]: 'synthetic' }), 'config.env-key')
  }
  loadConfig('mainnet', {
    PATH: '/usr/bin', HOME: '/h', LANG: 'C', TERM: 'dumb', TOKENIZER: 'v', MY_TOKENS: 'v', SECRETS_DIR: 'v', RPC_URLS: 'v',
    VT_RPC_ETH_X: 'v', VT_SUITE_SENTINEL_FILE: 'v', NODE_TEST_CONTEXT: 'v', GITHUB_TOKEN: '',
  })
})

test('Cfix4 (C2 review m1): the identity constants are deep-frozen; a write is refused and the locks still read the real ids', async () => {
  const { PROFILES, isMainnetIdentity } = await import('../../src/config.ts') as any
  for (const o of [NETWORK_IDS, NETWORK_IDS.mainnet, NETWORK_IDS.testnet, NETWORK_IDS.local, GENESIS, GENESIS.sol, GENESIS.btc, PROFILES]) {
    assert.equal(Object.isFrozen(o), true)
  }
  const attempts: Array<() => void> = [
    () => { (GENESIS.sol as any).mainnet = 'x' },
    () => { (GENESIS.btc as any).mainnet = 'x' },
    () => { (GENESIS as any).evil = {} },
    () => { delete (GENESIS.sol as any).devnet },
    () => { (NETWORK_IDS.mainnet as any).eth = 5 },
    () => { (NETWORK_IDS.local as any).eth = 1 },
    () => { (PROFILES as any).push('x') },
    () => { (PROFILES as any)[0] = 'local' },
  ]
  for (const f of attempts) assert.throws(f, TypeError)
  assert.equal(GENESIS.sol.mainnet, '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d')
  assert.equal(NETWORK_IDS.mainnet.eth, 1)
  assert.deepEqual([...PROFILES], ['mainnet', 'testnet', 'local'])
  assert.equal(isMainnetIdentity('sol', GENESIS.sol.mainnet), true)
})

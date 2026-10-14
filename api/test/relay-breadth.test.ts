// S6 (M4) relay breadth routes: BTC (the local regtest bitcoind and ord; testnet4 / mainnet Esplora), Blockscout
// provenance reads, the Arweave tags of an ar id, drand quicknet. Phase A: the gates in api/src/relay-routes.ts and
// relay-gate.ts (allowlists: relay.method, relay.path; answers: relay.upstream-shape, relay.upstream-secret; params:
// relay.btc-params; identities: relay.service-identity), then the real createRelay in process with an injected
// transport that plays every upstream (nothing leaves the machine; the URLs are only strings), then the real local
// transport against loopback servers. The bitcoind credential is synthetic, in a temp $OUT. Synthetic data only.
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { chmodSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs'
import { createServer, request } from 'node:http'
import type { IncomingHttpHeaders, Server } from 'node:http'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { PORTS } from '@vault-timelock/core/contracts'
import type { Network } from '@vault-timelock/core/contracts'
import { GENESIS, NETWORK_IDS } from 'vt-broadcast/src/config.ts'
import { Refusal } from 'vt-broadcast/src/guard.ts'
import { SERVICE_RETRY_MS, createRelay, readBitcoindCredential, relayBreadth, relayUpstreams, socksTransport, torBanner } from '../relay/relay.mjs'
import { classifyMethod } from '../src/relay-gate.ts'
import {
  AR_TAGS_QUERY, ARWEAVE_NETWORK, JSON_TYPE, QUICKNET_INFO, QUICKNET_INFO_BYTES, SERVICES, TEXT_TYPE, assertNoSecret, bitcoindAuthHeader,
  MIN_CREDENTIAL_PASS, bitcoindSecrets, checkAnswer, checkBtcParams, credentialLongEnough, identityProbe, refuseRoute, resolveRest, rpcShape, sameJson, serviceIdentity, upstreamRequest,
} from '../src/relay-routes.ts'
import type { RestRoute } from '../src/relay-routes.ts'
import { CANARY, TICKET_KEY, tempDir } from './helpers.ts'

const ENDPOINTS = JSON.parse(readFileSync(fileURLToPath(import.meta.resolve('vt-broadcast/endpoints.json')), 'utf8')) as Record<Network, Record<string, string[]>>
const TOR_CHECK = 'https://check.torproject.org/api/ip'
const NOW = 1_791_504_000_000
const NETS = ['local', 'testnet', 'mainnet'] as const

// ---- synthetic values
const TXID = 'ab'.repeat(32)
const BLOCK = 'cd'.repeat(32)
const ADDR = { mainnet: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', testnet: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', regtest: 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080' }
const LEGACY = { mainnet: '1BoatSLRHtKNngkdXEeobR76b53LETtpyT', testnet: 'mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn' }
const P2SH = { mainnet: '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy', testnet: '2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc' }
const EVM = `0x${'11'.repeat(20)}`
const EVM_TX = `0x${'cd'.repeat(32)}`
const AR_ID = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123-_x'
const QN = '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971'
// The sealer's INFO_PINNED (1password-timelock.sh), written out here independently of the implementation's constant.
const SEALER_INFO = '{"genesis_time":1692803367,"groupHash":"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e","hash":"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971","metadata":{"beaconID":"quicknet"},"period":3,"public_key":"83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a","schemeID":"bls-unchained-g1-rfc9380"}'
const INFO_AS_DRAND_SENDS = { public_key: QUICKNET_INFO.public_key, period: 3, genesis_time: 1692803367, hash: QN, groupHash: QUICKNET_INFO.groupHash, schemeID: 'bls-unchained-g1-rfc9380', metadata: { beaconID: 'quicknet' } }
const SIG = (round: number): string => createHash('sha512').update(`sig ${round}`).digest('hex').slice(0, 96)
const beaconOf = (round: number): { round: number; randomness: string; signature: string } => ({ round, randomness: createHash('sha256').update(Buffer.from(SIG(round), 'hex')).digest('hex'), signature: SIG(round) })
const AUTH_LINE = 'vtsynth:Synthetic-Pass-7f3a9c1e'                        // synthetic; never a real credential
const AUTH_B64 = Buffer.from(AUTH_LINE).toString('base64')
const SECRET_NEEDLES = ['Synthetic-Pass-7f3a9c1e', AUTH_B64]

const guardOf = (f: () => unknown): string | null => {
  try { f() } catch (e) { return e instanceof Refusal ? e.guardId : `not a refusal: ${String(e)}` }
  return null
}
const route = (n: Network, path: string, method = 'GET'): RestRoute => resolveRest(n, method, path)

// =====================================================================================================================
// 1. the gates (pure)
// =====================================================================================================================

test('the services per network: local ord + drand; testnet and mainnet Esplora, Blockscout, Arweave, drand', () => {
  assert.deepEqual(SERVICES, { local: ['ord', 'drand'], testnet: ['esplora', 'blockscout', 'arweave', 'drand'], mainnet: ['esplora', 'blockscout', 'arweave', 'drand'] })
  assert.ok(Object.isFrozen(SERVICES) && Object.isFrozen(SERVICES.local) && Object.isFrozen(SERVICES.mainnet))
})

test('allowlists: every route of each network resolves to its pattern, kind and exact upstream path', () => {
  const want = (n: Network, path: string, name: string, kind: string, up: string): void => {
    const r = route(n, path)
    assert.deepEqual([r.name, r.kind, r.path], [name, kind, up], `${n} ${path}`)
  }
  for (const n of ['testnet', 'mainnet'] as const) {
    const a = ADDR[n], l = LEGACY[n], p = '/relay/btc/esplora/'
    want(n, `${p}blocks/tip/height`, 'esplora:blocks/tip/height', 'height', 'blocks/tip/height')
    want(n, `${p}blocks/tip/hash`, 'esplora:blocks/tip/hash', 'hash', 'blocks/tip/hash')
    want(n, `${p}block-height/0`, 'esplora:block-height/:n', 'hash', 'block-height/0')
    want(n, `${p}block-height/123456789`, 'esplora:block-height/:n', 'hash', 'block-height/123456789')
    want(n, `${p}block/${BLOCK}`, 'esplora:block/:hash', 'json', `block/${BLOCK}`)
    want(n, `${p}block/${BLOCK}/status`, 'esplora:block/:hash/status', 'json', `block/${BLOCK}/status`)
    for (const x of [a, l, P2SH[n]]) {
      want(n, `${p}address/${x}`, 'esplora:address/:addr', 'json', `address/${x}`)
      want(n, `${p}address/${x}/utxo`, 'esplora:address/:addr/utxo', 'json', `address/${x}/utxo`)
      want(n, `${p}address/${x}/txs`, 'esplora:address/:addr/txs', 'json', `address/${x}/txs`)
      want(n, `${p}address/${x}/txs/mempool`, 'esplora:address/:addr/txs/mempool', 'json', `address/${x}/txs/mempool`)
      want(n, `${p}address/${x}/txs/chain/${TXID}`, 'esplora:address/:addr/txs/chain/:txid', 'json', `address/${x}/txs/chain/${TXID}`)
    }
    want(n, `${p}tx/${TXID}`, 'esplora:tx/:txid', 'json', `tx/${TXID}`)
    want(n, `${p}tx/${TXID}/status`, 'esplora:tx/:txid/status', 'json', `tx/${TXID}/status`)
    want(n, `${p}tx/${TXID}/hex`, 'esplora:tx/:txid/hex', 'hex', `tx/${TXID}/hex`)
    want(n, `${p}tx/${TXID}/outspend/1`, 'esplora:tx/:txid/outspend/:n', 'json', `tx/${TXID}/outspend/1`)
    want(n, `${p}fee-estimates`, 'esplora:fee-estimates', 'json', 'fee-estimates')
    want(n, `${p}v1/fees/recommended`, 'esplora:v1/fees/recommended', 'json', 'v1/fees/recommended')
    for (const c of ['eth', 'arb', 'base'] as const) {
      want(n, `/relay/blockscout/${c}/addresses/${EVM}/transactions?filter=to`, `blockscout.${c}:addresses/:evm/transactions?filter=to`, 'json', `addresses/${EVM}/transactions?filter=to`)
      want(n, `/relay/blockscout/${c}/addresses/${EVM}/internal-transactions?filter=to`, `blockscout.${c}:addresses/:evm/internal-transactions?filter=to`, 'json', `addresses/${EVM}/internal-transactions?filter=to`)
      want(n, `/relay/blockscout/${c}/transactions/${EVM_TX}`, `blockscout.${c}:transactions/:evmtx`, 'json', `transactions/${EVM_TX}`)
      assert.equal(route(n, `/relay/blockscout/${c}/transactions/${EVM_TX}`).sub, c)
    }
    const ar = route(n, `/relay/arweave/tags/${AR_ID}`)
    assert.deepEqual([ar.name, ar.kind, ar.path, ar.arId], ['arweave:tags/:arid', 'ar-tags', 'graphql', AR_ID])
  }
  const o = '/relay/btc/ord/'
  want('local', `${o}status`, 'ord:status', 'json', 'status')
  want('local', `${o}r/blockheight`, 'ord:r/blockheight', 'height', 'r/blockheight')
  want('local', `${o}r/blockhash/0`, 'ord:r/blockhash/:n', 'json', 'r/blockhash/0')
  want('local', `${o}tx/${TXID}`, 'ord:tx/:txid', 'json', `tx/${TXID}`)
  want('local', `${o}output/${TXID}:0`, 'ord:output/:txid::n', 'json', `output/${TXID}:0`)
  want('local', `${o}inscription/${TXID}i0`, 'ord:inscription/:txidi:n', 'json', `inscription/${TXID}i0`)
  for (const n of NETS) {
    const info = route(n, `/relay/drand/${QN}/info`)
    assert.deepEqual([info.name, info.kind, info.path, info.round], ['drand:info', 'drand-info', `${QN}/info`, null])
    const latest = route(n, `/relay/drand/${QN}/public/latest`)
    assert.deepEqual([latest.name, latest.kind, latest.path, latest.round], ['drand:public/latest', 'drand-beacon', `${QN}/public/latest`, null])
    const r = route(n, `/relay/drand/${QN}/public/23456789`)
    assert.deepEqual([r.name, r.kind, r.path, r.round], ['drand:public/:round', 'drand-beacon', `${QN}/public/23456789`, 23456789])
  }
})

test('relay.method: the breadth routes take GET only (POST, PUT, HEAD, DELETE, lower case, empty)', () => {
  const paths: Array<[Network, string]> = [['testnet', `/relay/btc/esplora/tx/${TXID}`], ['mainnet', '/relay/btc/esplora/tx'], ['local', `/relay/btc/ord/tx/${TXID}`],
    ['mainnet', `/relay/blockscout/eth/transactions/${EVM_TX}`], ['testnet', `/relay/arweave/tags/${AR_ID}`], ['local', `/relay/drand/${QN}/info`], ['mainnet', '/relay/btc/nothing']]
  for (const [n, p] of paths) for (const m of ['POST', 'PUT', 'HEAD', 'DELETE', 'get', '']) assert.equal(guardOf(() => resolveRest(n, m, p)), 'relay.method', `${n} ${m} ${p}`)
  assert.equal(guardOf(() => refuseRoute(true)), 'relay.method')
  assert.equal(guardOf(() => refuseRoute(false)), 'relay.path')
})

test('relay.path: anything off the exact patterns — encodings, dot segments, queries, other networks\' addresses and services, sends', () => {
  const t = ADDR.testnet, m = ADDR.mainnet
  const refused: Array<[Network, string]> = [
    // Esplora: sends and pushes, encodings, case, dot segments, extra segments, queries, fragments
    ['mainnet', '/relay/btc/esplora/tx'], ['mainnet', '/relay/btc/esplora/txs/package'], ['mainnet', `/relay/btc/esplora/tx/${TXID}/push`],
    ['mainnet', '/relay/btc/esplora/broadcast'], ['mainnet', '/relay/btc/esplora/'], ['mainnet', '/relay/btc/esplora'],
    ['mainnet', `/relay/btc/esplora/tx/${TXID.toUpperCase()}`], ['mainnet', `/relay/btc/esplora/tx/${TXID.slice(1)}`], ['mainnet', `/relay/btc/esplora/tx/${TXID}0`],
    ['mainnet', `/relay/btc/esplora/tx/${TXID}/`], ['mainnet', `/relay/btc/esplora/tx//${TXID}`], ['mainnet', `/relay/btc/esplora/./tx/${TXID}`],
    ['mainnet', `/relay/btc/esplora/tx/../tx/${TXID}`], ['mainnet', `/relay/btc/esplora/tx/%61${TXID.slice(1)}`], ['mainnet', `/relay/btc/esplora/tx/${TXID}?x=1`],
    ['mainnet', `/relay/btc/esplora/tx/${TXID}#x`], ['mainnet', `/relay/btc/esplora/tx/${TXID}/hex\n`], ['mainnet', '/relay/btc/esplora/blocks/tip/height/'],
    ['mainnet', '/relay/btc/esplora/block-height/01'], ['mainnet', '/relay/btc/esplora/block-height/-1'], ['mainnet', '/relay/btc/esplora/block-height/1234567890'],
    ['mainnet', `/relay/btc/esplora/tx/${TXID}/outspend/01`], ['mainnet', '/relay/btc/esplora/mempool'], ['mainnet', '/relay/btc/esplora/mempool/txids'],
    ['mainnet', `/relay/btc/esplora/address/${m}/utxo?limit=1`], ['mainnet', `/relay/btc/esplora/address/${m.toUpperCase()}`],
    ['mainnet', `/relay/btc/ESPLORA/tx/${TXID}`], ['mainnet', `/relay/BTC/esplora/tx/${TXID}`],
    // another network's address: never through this network's circuits
    ['mainnet', `/relay/btc/esplora/address/${t}`], ['mainnet', `/relay/btc/esplora/address/${LEGACY.testnet}/utxo`], ['mainnet', `/relay/btc/esplora/address/${ADDR.regtest}`],
    ['testnet', `/relay/btc/esplora/address/${m}`], ['testnet', `/relay/btc/esplora/address/${LEGACY.mainnet}/txs`],
    // fix round 1 (review m3, M3): P2SH on the other network (testnet 2…, mainnet 3…)
    ['mainnet', `/relay/btc/esplora/address/${P2SH.testnet}`], ['mainnet', `/relay/btc/esplora/address/${P2SH.testnet}/utxo`],
    ['testnet', `/relay/btc/esplora/address/${P2SH.mainnet}`], ['testnet', `/relay/btc/esplora/address/${P2SH.mainnet}/txs`],
    // a service another network serves
    ['local', `/relay/btc/esplora/tx/${TXID}`], ['testnet', `/relay/btc/ord/tx/${TXID}`], ['mainnet', '/relay/btc/ord/status'],
    ['local', `/relay/blockscout/eth/transactions/${EVM_TX}`], ['local', `/relay/arweave/tags/${AR_ID}`],
    // ord: content (any bytes, any type) and everything else
    ['local', `/relay/btc/ord/content/${TXID}i0`], ['local', `/relay/btc/ord/r/content/${TXID}i0`], ['local', `/relay/btc/ord/preview/${TXID}i0`],
    ['local', '/relay/btc/ord/inscriptions'], ['local', `/relay/btc/ord/inscription/${TXID}`], ['local', `/relay/btc/ord/output/${TXID}`], ['local', '/relay/btc/ord/r/blockhash/x'],
    // bitcoind is POST /relay/btc only: no REST, no wallet path, no ep route
    ['local', '/relay/btc/rpc'], ['local', '/relay/btc/wallet/vt'], ['local', '/relay/btc/ep/0'],
    // Blockscout: only the three patterns, exactly; filter=to exactly
    ['mainnet', `/relay/blockscout/eth/addresses/${EVM}/transactions`], ['mainnet', `/relay/blockscout/eth/addresses/${EVM}/transactions?filter=from`],
    ['mainnet', `/relay/blockscout/eth/addresses/${EVM}/transactions?filter=to&page=2`], ['mainnet', `/relay/blockscout/eth/addresses/${EVM}/transactions?filter=to#x`],
    ['mainnet', `/relay/blockscout/eth/addresses/${EVM}/token-transfers?filter=to`], ['mainnet', `/relay/blockscout/eth/addresses/${EVM}`],
    ['mainnet', `/relay/blockscout/eth/transactions/${EVM_TX.toUpperCase().replace('0X', '0x')}`], ['mainnet', `/relay/blockscout/op/transactions/${EVM_TX}`],
    ['mainnet', '/relay/blockscout/eth/eth-rpc'], ['mainnet', `/relay/blockscout/eth/addresses/0x${'11'.repeat(19)}/transactions?filter=to`],
    // Arweave: the tags of one 43-character id only
    ['mainnet', `/relay/arweave/tags/${AR_ID.slice(1)}`], ['mainnet', `/relay/arweave/tags/${AR_ID}x`], ['mainnet', `/relay/arweave/tags/${AR_ID.slice(1)}=`],
    ['mainnet', '/relay/arweave/graphql'], ['mainnet', `/relay/arweave/tx/${AR_ID}`], ['mainnet', `/relay/arweave/${AR_ID}`],
    // drand: the pinned quicknet chain only; info, latest or a round
    ['mainnet', `/relay/drand/${'ff'.repeat(32)}/info`], ['mainnet', `/relay/drand/${QN.toUpperCase()}/info`], ['mainnet', '/relay/drand/info'],
    ['mainnet', `/relay/drand/${QN}/public/0`], ['mainnet', `/relay/drand/${QN}/public/01`], ['mainnet', `/relay/drand/${QN}/public/9007199254740993`],
    ['mainnet', `/relay/drand/${QN}/public/latest?x`], ['mainnet', `/relay/drand/${QN}/public`], ['mainnet', `/relay/drand/${QN}/public/../info`],
    ['mainnet', `/relay/drand/${QN}/health`], ['mainnet', '/relay/drand/chains'], ['mainnet', `/relay/drand/${QN}/info/`],
  ]
  for (const [n, p] of refused) assert.equal(guardOf(() => resolveRest(n, 'GET', p)), 'relay.path', `${n} ${JSON.stringify(p)}`)
  assert.equal(guardOf(() => resolveRest('mainnet', 'GET', `/relay/btc/esplora/address/${m}/${'x'.repeat(600)}`)), 'relay.path')
})

test('bitcoind (POST /relay/btc): local reads only; sends, wallet, mining and node control → relay.method on every network', () => {
  for (const m of ['getblockchaininfo', 'getblockcount', 'getrawtransaction', 'testmempoolaccept', 'scantxoutset', 'estimatesmartfee']) assert.equal(classifyMethod('local', 'btc', m), 'read')
  const refused = ['sendrawtransaction', 'sendtoaddress', 'sendmany', 'submitpackage', 'submitblock', 'generatetoaddress', 'generateblock', 'getnewaddress',
    'dumpprivkey', 'dumpwallet', 'importprivkey', 'listunspent', 'walletpassphrase', 'createwallet', 'loadwallet', 'stop', 'setban', 'addnode',
    'invalidateblock', 'prioritisetransaction', 'getrawtransaction ', 'GetBlockCount', 'eth_chainId', 'getGenesisHash', '__proto__', '']
  for (const n of NETS) {
    for (const m of refused) assert.equal(guardOf(() => classifyMethod(n, 'btc', m)), 'relay.method', `${n} ${m}`)
    if (n !== 'local') assert.equal(guardOf(() => classifyMethod(n, 'btc', 'getblockcount')), 'relay.method', `${n}: no bitcoind`)
  }
})

test('relay.btc-params: scantxoutset takes [\'start\', [addr(<regtest address>) …]] only', () => {
  const ok: unknown[] = [['start', [`addr(${ADDR.regtest})`]], ['start', [{ desc: `addr(${ADDR.regtest})` }, `addr(${LEGACY.testnet})`]], ['start', Array(16).fill(`addr(${ADDR.regtest})`)]]
  for (const p of ok) assert.equal(guardOf(() => checkBtcParams('scantxoutset', p)), null, JSON.stringify(p))
  const bad: unknown[] = [undefined, [], ['start'], ['abort', [`addr(${ADDR.regtest})`]], ['status', []], ['start', []], ['start', Array(17).fill(`addr(${ADDR.regtest})`)],
    ['start', [`addr(${ADDR.mainnet})`]], ['start', [`addr(${ADDR.testnet})`]], ['start', [`pkh(${'02'.padEnd(66, '1')})`]], ['start', ['combo(tpubXXX/0/*)']],
    ['start', [{ desc: `addr(${ADDR.regtest})`, range: 1000 }]], ['start', [`addr(${ADDR.regtest})#checksum`]], ['start', [`raw(00)`]], ['start', `addr(${ADDR.regtest})`],
    ['start', [`addr(${ADDR.regtest})`], 'extra'], { 0: 'start' },
    // fix round 1 (review m3, M4): EVERY descriptor must be addr(<regtest>): one good one does not let a ranged or key one through
    ['start', [`addr(${ADDR.regtest})`, 'combo(tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp/*)']],
    ['start', [{ desc: `addr(${ADDR.regtest})` }, { desc: `addr(${ADDR.regtest})`, range: [0, 1000] }]], ['start', [`addr(${ADDR.regtest})`, `addr(${ADDR.mainnet})`]]]
  for (const p of bad) assert.equal(guardOf(() => checkBtcParams('scantxoutset', p)), 'relay.btc-params', JSON.stringify(p))
  assert.equal(guardOf(() => checkBtcParams('getblockcount', 'anything')), null)       // bitcoind checks the other params itself
})

test('answers: JSON only as JSON; text only as exactly a height, a hash, a tx hex; the relay\'s own content types', () => {
  const tx = route('mainnet', `/relay/btc/esplora/tx/${TXID}`)
  const ok = checkAnswer(tx, 200, Buffer.from('{"txid":"x","vout":[]}'))
  assert.deepEqual([ok.status, ok.contentType, ok.body.toString()], [200, JSON_TYPE, '{"txid":"x","vout":[]}'])       // the upstream bytes as received
  for (const b of ['<html><script>alert(1)</script></html>', '', '{"a":', '﻿{}']) assert.equal(guardOf(() => checkAnswer(tx, 200, Buffer.from(b))), 'relay.upstream-shape', b)
  assert.equal(guardOf(() => checkAnswer(tx, 200, Buffer.from([0x7b, 0xff, 0x7d]))), 'relay.upstream-shape')
  const h = route('mainnet', '/relay/btc/esplora/blocks/tip/height')
  for (const [b, v] of [['912345', '912345'], ['912345\n', '912345'], ['0', '0']]) {
    const a = checkAnswer(h, 200, Buffer.from(b))
    assert.deepEqual([a.status, a.contentType, a.body.toString()], [200, TEXT_TYPE, v])
  }
  for (const b of ['912345\n\n', ' 912345', '0912345', '9.1', '<b>1</b>', '12345678901', '-1']) assert.equal(guardOf(() => checkAnswer(h, 200, Buffer.from(b))), 'relay.upstream-shape', b)
  const hash = route('testnet', '/relay/btc/esplora/block-height/0')
  assert.equal(checkAnswer(hash, 200, Buffer.from(GENESIS.btc.testnet4)).body.toString(), GENESIS.btc.testnet4)
  for (const b of [GENESIS.btc.testnet4.toUpperCase(), GENESIS.btc.testnet4.slice(2), `${GENESIS.btc.testnet4}x`, `"${GENESIS.btc.testnet4}"`]) assert.equal(guardOf(() => checkAnswer(hash, 200, Buffer.from(b))), 'relay.upstream-shape', b)
  const hex = route('testnet', `/relay/btc/esplora/tx/${TXID}/hex`)
  assert.equal(checkAnswer(hex, 200, Buffer.from('0200aabb\n')).body.toString(), '0200aabb')
  for (const b of ['0200aab', '0200AABB', '0x0200', '']) assert.equal(guardOf(() => checkAnswer(hex, 200, Buffer.from(b))), 'relay.upstream-shape', b)
  // statuses: 404 is the relay's own 404 (never the upstream's text); anything else non-200 a 502
  const nf = checkAnswer(tx, 404, Buffer.from(`Transaction not found <script>${CANARY}</script>`))
  assert.deepEqual([nf.status, nf.contentType, JSON.parse(nf.body.toString())], [404, JSON_TYPE, { error: { message: 'not found upstream (HTTP 404)' } }])
  for (const st of [400, 401, 410, 500, 302]) {
    const a = checkAnswer(tx, st, Buffer.from(`${CANARY} detail`))
    assert.deepEqual([a.status, JSON.parse(a.body.toString())], [502, { error: { message: `upstream HTTP ${st}` } }])
  }
  const ord = route('local', '/relay/btc/ord/r/blockheight')
  assert.equal(checkAnswer(ord, 200, Buffer.from('101')).contentType, TEXT_TYPE)
  assert.equal(checkAnswer(route('local', `/relay/btc/ord/inscription/${TXID}i0`), 404, Buffer.from('null')).status, 404)
})

test('drand: info only when the upstream\'s equals the pinned quicknet info exactly, and then the PINNED bytes; beacons re-serialized after their checks', () => {
  assert.equal(QUICKNET_INFO_BYTES.toString(), SEALER_INFO)
  const info = route('testnet', `/relay/drand/${QN}/info`)
  const a = checkAnswer(info, 200, Buffer.from(JSON.stringify(INFO_AS_DRAND_SENDS)))          // drand's own key order
  assert.deepEqual([a.status, a.contentType, a.body.toString()], [200, JSON_TYPE, SEALER_INFO])
  const variants: unknown[] = [
    { ...INFO_AS_DRAND_SENDS, public_key: `${INFO_AS_DRAND_SENDS.public_key.slice(0, -2)}00` }, { ...INFO_AS_DRAND_SENDS, period: 30 },
    { ...INFO_AS_DRAND_SENDS, genesis_time: 1692803368 }, { ...INFO_AS_DRAND_SENDS, schemeID: 'pedersen-bls-chained' }, { ...INFO_AS_DRAND_SENDS, hash: 'ff'.repeat(32) },
    { ...INFO_AS_DRAND_SENDS, groupHash: '00'.repeat(32) }, { ...INFO_AS_DRAND_SENDS, metadata: { beaconID: 'default' } }, { ...INFO_AS_DRAND_SENDS, extra: 1 },
    { ...INFO_AS_DRAND_SENDS, schemeid: 'x' }, { ...INFO_AS_DRAND_SENDS, period: '3' }, Object.fromEntries(Object.entries(INFO_AS_DRAND_SENDS).filter(([k]) => k !== 'groupHash')),
    // fix round 1 (review m3, M1): missing the LAST key in sorted order (schemeID), or the first (genesis_time)
    Object.fromEntries(Object.entries(INFO_AS_DRAND_SENDS).filter(([k]) => k !== 'schemeID')), Object.fromEntries(Object.entries(INFO_AS_DRAND_SENDS).filter(([k]) => k !== 'genesis_time')),
    [INFO_AS_DRAND_SENDS], null,
  ]
  for (const v of variants) assert.equal(guardOf(() => checkAnswer(info, 200, Buffer.from(JSON.stringify(v)))), 'relay.upstream-shape', JSON.stringify(v).slice(0, 80))
  assert.equal(checkAnswer(info, 404, Buffer.alloc(0)).status, 502)                       // no info is an error, not "not yet"
  const latest = route('testnet', `/relay/drand/${QN}/public/latest`)
  const b = checkAnswer(latest, 200, Buffer.from(JSON.stringify({ signature: SIG(100), round: 100, randomness: beaconOf(100).randomness })))
  assert.deepEqual([b.status, b.contentType, b.body.toString()], [200, JSON_TYPE, JSON.stringify(beaconOf(100))])
  const r7 = route('mainnet', `/relay/drand/${QN}/public/7`)
  assert.equal(checkAnswer(r7, 200, Buffer.from(JSON.stringify(beaconOf(7)))).body.toString(), JSON.stringify(beaconOf(7)))
  const bad: unknown[] = [beaconOf(8), { ...beaconOf(7), randomness: '00'.repeat(32) }, { ...beaconOf(7), signature: SIG(8) }, { ...beaconOf(7), previous_signature: SIG(6) },
    { ...beaconOf(7), round: '7' }, { round: 7, signature: SIG(7) }, { ...beaconOf(7), signature: SIG(7).toUpperCase() }, { ...beaconOf(7), signature: `${SIG(7)}00` }]
  for (const v of bad) assert.equal(guardOf(() => checkAnswer(r7, 200, Buffer.from(JSON.stringify(v)))), 'relay.upstream-shape', JSON.stringify(v).slice(0, 60))
  assert.equal(guardOf(() => checkAnswer(latest, 200, Buffer.from(JSON.stringify({ ...beaconOf(0), round: 0 })))), 'relay.upstream-shape')
  for (const st of [404, 425]) {
    const n = checkAnswer(r7, st, Buffer.from('too early'))
    assert.deepEqual([n.status, JSON.parse(n.body.toString())], [404, { error: { message: 'this drand round is not published yet' } }])
  }
  assert.equal(checkAnswer(r7, 500, Buffer.alloc(0)).status, 502)
})

test('arweave: a fixed GraphQL query with the id as a variable; the answer re-serialized as { id, found, tags }', () => {
  const r = route('mainnet', `/relay/arweave/tags/${AR_ID}`)
  const up = upstreamRequest(r, 'https://arweave.net/')
  assert.deepEqual([up.url, up.method], ['https://arweave.net/graphql', 'POST'])
  assert.deepEqual(JSON.parse(String(up.body)), { query: AR_TAGS_QUERY, variables: { ids: [AR_ID] } })
  assert.ok(!AR_TAGS_QUERY.includes(AR_ID) && !/mutation/i.test(AR_TAGS_QUERY))
  const tags = [{ name: 'Content-Type', value: 'text/plain' }, { name: 'Unlock-After', value: '2027-01-01T00:00:00Z' }]
  const found = checkAnswer(r, 200, Buffer.from(JSON.stringify({ data: { transactions: { edges: [{ node: { id: AR_ID, tags: tags.map((t) => ({ value: t.value, name: t.name })) } }] } } })))
  assert.deepEqual([found.status, found.contentType, found.body.toString()], [200, JSON_TYPE, JSON.stringify({ id: AR_ID, found: true, tags })])
  assert.equal(checkAnswer(r, 200, Buffer.from('{"data":{"transactions":{"edges":[]}}}')).body.toString(), JSON.stringify({ id: AR_ID, found: false, tags: [] }))
  const node = (n: unknown): string => JSON.stringify({ data: { transactions: { edges: [{ node: n }] } } })
  const bad = ['{"errors":[{"message":"x"}],"data":null}', '{"data":{"transactions":{"edges":[]}},"errors":[]}', '{"data":{"transactions":{}}}', '[]',
    JSON.stringify({ data: { transactions: { edges: [{ node: { id: AR_ID, tags: [] } }, { node: { id: AR_ID, tags: [] } }] } } }),
    node({ id: `${AR_ID.slice(1)}y`, tags: [] }), node({ id: AR_ID, tags: [{ name: 'a', value: 1 }] }), node({ id: AR_ID, tags: [{ name: 'a' }] }),
    node({ id: AR_ID, tags: 'x' }), node({ id: AR_ID, tags: Array(129).fill({ name: 'a', value: 'b' }) }), node({ id: AR_ID, tags: [{ name: 'a', value: 'v'.repeat(3073) }] })]
  for (const b of bad) assert.equal(guardOf(() => checkAnswer(r, 200, Buffer.from(b))), 'relay.upstream-shape', b.slice(0, 70))
  assert.equal(checkAnswer(r, 500, Buffer.alloc(0)).status, 502)
})

test('relay.upstream-secret: an answer carrying the bitcoind credential (raw, base64 header, the password alone) is withheld', () => {
  const s = bitcoindSecrets(AUTH_LINE)
  assert.deepEqual(s.slice(0, 3), [AUTH_LINE, AUTH_B64, 'Synthetic-Pass-7f3a9c1e'])
  assert.equal(bitcoindAuthHeader(AUTH_LINE), `Basic ${AUTH_B64}`)
  for (const leak of [AUTH_LINE, `Basic ${AUTH_B64}`, 'Synthetic-Pass-7f3a9c1e']) {
    assert.equal(guardOf(() => assertNoSecret(Buffer.from(`{"jsonrpc":"2.0","result":"${leak}"}`), s)), 'relay.upstream-secret', leak)
  }
  const q = bitcoindSecrets('u:pa"ss\\word1')
  assert.equal(guardOf(() => assertNoSecret(Buffer.from(JSON.stringify({ result: 'pa"ss\\word1' })), q)), 'relay.upstream-secret')   // as JSON escapes it
  assert.equal(guardOf(() => assertNoSecret(Buffer.from('{"result":101}'), s)), null)
  // S6 review m2: the bare password is ALWAYS a needle (the relay accepts no short password, so a short one cannot slip through)
  assert.ok(bitcoindSecrets('u:short').includes('short'))
  assert.equal(guardOf(() => assertNoSecret(Buffer.from('{"result":"x short y"}'), bitcoindSecrets('u:short'))), 'relay.upstream-secret')
})

test('relay.upstream-secret (S6 review m1): the \\u-escaped, hex and base64 forms of the password, a key holding it, and a nested value are withheld too', () => {
  const pass = 'Synthetic-Pass-7f3a9c1e', s = bitcoindSecrets(AUTH_LINE)
  const uEsc = [...pass].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('')
  const leaks = [
    `{"result":"${uEsc}"}`,                                                           // every character \u-escaped: the raw text never holds it
    `{"result":"${Buffer.from(pass).toString('hex')}"}`,
    `{"result":"${Buffer.from(pass).toString('base64').replace(/=+$/, '')}"}`,
    `{"result":"${Buffer.from(pass).toString('base64')}"}`,
    `{"${uEsc}":1}`,                                                                  // as an object key
    `{"a":[{"b":["x ${uEsc} y"]}]}`,                                                  // nested, inside a longer string
  ]
  for (const l of leaks) assert.equal(guardOf(() => assertNoSecret(Buffer.from(l), s)), 'relay.upstream-secret', l.slice(0, 60))
  assert.equal(guardOf(() => assertNoSecret(Buffer.from('{"result":"S\\u0079nthetic-Pass-other"}'), s)), null)   // another password: fine
  assert.equal(guardOf(() => assertNoSecret(Buffer.from('not json at all'), s)), null)
  assert.equal(guardOf(() => assertNoSecret(Buffer.from('not json ' + pass), s)), 'relay.upstream-secret')           // a non-JSON answer is scanned raw
})

test('the minimum bitcoind password (S6 review m2): under MIN_CREDENTIAL_PASS characters the credential is refused and the local BTC lane stays off', async () => {
  assert.equal(MIN_CREDENTIAL_PASS, 16)
  assert.deepEqual(['u:' + 'x'.repeat(15), 'u:' + 'x'.repeat(16), 'u:x', AUTH_LINE].map(credentialLongEnough), [false, true, false, true])
  const { dir, cleanup } = tempDir('vt-s6-short-')
  try {
    const logs: string[] = []
    mkdirSync(join(dir, 'local'), { mode: 0o700 })
    const f = join(dir, 'local', 'btc-rpc.auth')
    writeFileSync(f, `vtsynth:${'p'.repeat(15)}\n`, { mode: 0o600 })
    assert.equal(readBitcoindCredential(dir, (l) => { logs.push(l) }), null)
    assert.ok(logs.some((l) => l.includes('shorter than 16 characters') && l.includes('the local BTC lane is off')))
    assert.ok(!logs.join('\n').includes('ppppp'))
    writeFileSync(f, `vtsynth:${'p'.repeat(16)}\n`, { mode: 0o600 })
    assert.equal(readBitcoindCredential(dir, () => {}), `vtsynth:${'p'.repeat(16)}`)
  } finally { cleanup() }
  const s = await start('local', { auth: 'vtsynth:short' })                           // handed straight to the relay: the lane is off as well
  try {
    assert.equal(s.calls.filter((c) => c.url.startsWith('http://127.0.0.1:18443') || c.url.startsWith('http://127.0.0.1:8090')).length, 0)
    assert.equal((await rq(s, '/relay/btc', { body: rpc('getblockcount') })).status, 503)
  } finally { await s.close() }
})

test('service identities: ord block 0; Blockscout eth_chainId at /api/eth-rpc; Arweave network; drand info — a definitive other identity → relay.service-identity', () => {
  assert.deepEqual(identityProbe('ord', 'http://127.0.0.1:8090'), { url: 'http://127.0.0.1:8090/r/blockhash/0', method: 'GET', body: null })
  const bs = identityProbe('blockscout', 'https://eth-sepolia.blockscout.com/api/v2')
  assert.deepEqual([bs?.url, bs?.method, JSON.parse(String(bs?.body)).method], ['https://eth-sepolia.blockscout.com/api/eth-rpc', 'POST', 'eth_chainId'])
  assert.equal(identityProbe('blockscout', 'https://eth.blockscout.com/api'), null)
  assert.equal(identityProbe('arweave', 'https://arweave.net')?.url, 'https://arweave.net/info')
  assert.equal(identityProbe('drand', 'https://api.drand.sh/')?.url, `https://api.drand.sh/${QN}/info`)
  const j = (v: unknown): Buffer => Buffer.from(JSON.stringify(v))
  const idOf = (n: Network, s: Parameters<typeof serviceIdentity>[1], sub: 'eth' | 'arb' | 'base' | null, st: number, b: Buffer): string | boolean => {
    try { return serviceIdentity(n, s, sub, st, b) } catch (e) { return e instanceof Refusal ? e.guardId : String(e) }
  }
  assert.equal(idOf('local', 'ord', null, 200, j(GENESIS.btc.regtest)), true)
  for (const g of [GENESIS.btc.mainnet, GENESIS.btc.testnet4, GENESIS.btc.regtest.toUpperCase()]) assert.equal(idOf('local', 'ord', null, 200, j(g)), 'relay.service-identity')
  assert.equal(idOf('testnet', 'ord', null, 200, j(GENESIS.btc.regtest)), 'relay.service-identity')
  for (const [st, b] of [[200, Buffer.from('<html>')], [200, j(null)], [503, j(GENESIS.btc.regtest)], [200, j({ hash: GENESIS.btc.regtest })]] as const) assert.equal(idOf('local', 'ord', null, st, b), false)
  const hex = (n: number): string => `0x${n.toString(16)}`
  for (const n of ['testnet', 'mainnet'] as const) {
    for (const c of ['eth', 'arb', 'base'] as const) {
      assert.equal(idOf(n, 'blockscout', c, 200, j({ jsonrpc: '2.0', id: 1, result: hex(NETWORK_IDS[n][c]) })), true, `${n} ${c}`)
      const other = n === 'testnet' ? NETWORK_IDS.mainnet[c] : NETWORK_IDS.testnet[c]
      assert.equal(idOf(n, 'blockscout', c, 200, j({ jsonrpc: '2.0', id: 1, result: hex(other) })), 'relay.service-identity', `${n} ${c} other`)
    }
    assert.equal(idOf(n, 'blockscout', 'arb', 200, j({ result: hex(NETWORK_IDS[n].eth) })), 'relay.service-identity')
    assert.equal(idOf(n, 'blockscout', 'eth', 200, j({ jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'no' } })), false)
    assert.equal(idOf(n, 'arweave', null, 200, j({ network: ARWEAVE_NETWORK, height: 1 })), true)
    assert.equal(idOf(n, 'arweave', null, 200, j({ network: 'arweave.localtest', height: 1 })), 'relay.service-identity')
    assert.equal(idOf(n, 'arweave', null, 200, j({ height: 1 })), false)
  }
  assert.equal(idOf('mainnet', 'drand', null, 200, j(INFO_AS_DRAND_SENDS)), true)
  assert.equal(idOf('local', 'drand', null, 200, j({ ...INFO_AS_DRAND_SENDS, public_key: '00' })), 'relay.service-identity')
  // fix round 1 (review m3, M1): an info missing schemeID (the last sorted key) is another chain's, not quicknet's
  assert.equal(idOf('local', 'drand', null, 200, j(Object.fromEntries(Object.entries(INFO_AS_DRAND_SENDS).filter(([k]) => k !== 'schemeID')))), 'relay.service-identity')
  for (const [a, b] of [[{ a: 1 }, { a: 1, b: 2 }], [{ a: 1, b: 2 }, { a: 1 }], [[1], [1, 2]], [{ a: { b: 1 } }, { a: { b: 1, c: 2 } }]] as const) {
    assert.equal(sameJson(a, b), false, JSON.stringify([a, b]))
  }
  assert.equal(sameJson({ b: [1, { c: 'x' }], a: 1 }, { a: 1, b: [1, { c: 'x' }] }), true)
  assert.equal(idOf('local', 'drand', null, 200, Buffer.from('not json')), false)
  assert.equal(idOf('local', 'drand', null, 404, j(INFO_AS_DRAND_SENDS)), false)
})

test('refusal and answer messages never echo the path, an address, a txid or an upstream value', () => {
  const msgs: string[] = []
  const grab = (f: () => unknown): void => { try { f() } catch (e) { msgs.push((e as Error).message) } }
  grab(() => resolveRest('mainnet', 'GET', `/relay/btc/esplora/address/${ADDR.testnet}`))
  grab(() => resolveRest('mainnet', 'POST', `/relay/btc/esplora/tx/${TXID}`))
  grab(() => checkAnswer(route('mainnet', `/relay/btc/esplora/tx/${TXID}`), 200, Buffer.from(`<p>${CANARY}</p>`)))
  grab(() => checkBtcParams('scantxoutset', ['start', [`addr(${ADDR.mainnet})`]]))
  grab(() => assertNoSecret(Buffer.from(AUTH_LINE), bitcoindSecrets(AUTH_LINE)))
  grab(() => serviceIdentity('mainnet', 'arweave', null, 200, Buffer.from(JSON.stringify({ network: CANARY }))))
  assert.equal(msgs.length, 6)
  for (const m of msgs) for (const v of [ADDR.testnet, ADDR.mainnet, TXID, CANARY, AUTH_LINE, 'Synthetic-Pass']) assert.ok(!m.includes(v), m)
})

// =====================================================================================================================
// 2. the relay in process: an injected transport plays every upstream
// =====================================================================================================================

interface Call { url: string; method: string; role: string; user: string; headers: Record<string, string>; body: string | null }
interface UpRes { status: number; body: Buffer }
const json = (status: number, v: unknown): UpRes => ({ status, body: Buffer.from(JSON.stringify(v)) })
const raw = (status: number, s: string): UpRes => ({ status, body: Buffer.from(s) })
const LOCAL_SOL = '8pUq7jxkLxNpHg6M9KxzRtNEC4pNEHsr4kDTLSE5uVRW'
const IDS: Record<Network, { eth: string; sol: string; btc: string }> = {
  local: { eth: '0x7a69', sol: LOCAL_SOL, btc: GENESIS.btc.regtest }, testnet: { eth: '0xaa36a7', sol: GENESIS.sol.devnet, btc: GENESIS.btc.testnet4 },
  mainnet: { eth: '0x1', sol: GENESIS.sol.mainnet, btc: GENESIS.btc.mainnet },
}
const evmIdOf = (url: string, n: Network): string => {
  const c = /\/\/(?:eth|arbitrum|base)/.exec(url)?.[0].slice(2)
  const chain = c === 'arbitrum' ? 'arb' : c === 'base' ? 'base' : 'eth'
  return `0x${((NETWORK_IDS as Record<string, Record<string, number>>)[n === 'local' ? 'testnet' : n][chain]).toString(16)}`
}

type Override = (url: string, c: Call) => UpRes | Error | undefined
// Every upstream a breadth relay may reach, faked by URL.
function fakeWorld(network: Network, o: { override?: Override; isTor?: boolean } = {}) {
  const calls: Call[] = []
  const transport = async (url: string, r: { method: string; body?: Buffer; role: string; user: string; headers?: Record<string, string> }): Promise<UpRes> => {
    const c: Call = { url, method: r.method, role: r.role, user: r.user, headers: { ...(r.headers ?? {}) }, body: r.body ? r.body.toString('utf8') : null }
    calls.push(c)
    const x = o.override?.(url, c)
    if (x instanceof Error) throw x
    if (x) return x
    if (url === TOR_CHECK) return json(200, { IsTor: o.isTor ?? true, IP: CANARY })
    const rpcReq = c.body !== null && c.body.startsWith('{"jsonrpc"') ? JSON.parse(c.body) as { id: unknown; method: string; params?: unknown[] } : null
    const u = new URL(url)
    // the eth/sol chains
    if (rpcReq && (u.port === '8545' || u.port === '8999' || /publicnode|solana|drpc|1rpc|sepolia/.test(u.host)) && !u.pathname.endsWith('eth-rpc')) {
      const result = rpcReq.method === 'eth_chainId' ? IDS[network].eth : rpcReq.method === 'getGenesisHash' ? IDS[network].sol : rpcReq.method === 'eth_estimateGas' ? `0x${(network === 'testnet' ? 21_400 : 25_000).toString(16)}` : `${rpcReq.method}-result`
      return json(200, { jsonrpc: '2.0', id: rpcReq.id, result })
    }
    // the local regtest bitcoind (needs the credential) and ord
    if (u.port === '18443') {
      if (c.headers.authorization !== `Basic ${AUTH_B64}`) return raw(401, '')
      const result = rpcReq?.method === 'getblockhash' ? IDS.local.btc : rpcReq?.method === 'getblockcount' ? 101 : `${rpcReq?.method}-result`
      return json(200, { jsonrpc: '2.0', id: rpcReq?.id ?? null, result })
    }
    if (u.port === '8090') {
      if (u.pathname === '/r/blockhash/0') return json(200, IDS.local.btc)
      if (u.pathname === '/r/blockheight') return raw(200, '101')
      return json(200, { path: u.pathname })
    }
    // Esplora
    if (u.pathname.endsWith('/block-height/0')) return raw(200, IDS[network].btc)
    if (u.pathname.endsWith('/blocks/tip/height')) return raw(200, '912345')
    if (u.pathname.endsWith('/hex')) return raw(200, '0200aabb\n')
    if (/\/(?:testnet4\/)?api\//.test(u.pathname) && /mempool|blockstream|onion/.test(u.host)) return json(200, { esplora: u.pathname })
    // Blockscout
    if (u.pathname === '/api/eth-rpc') return json(200, { jsonrpc: '2.0', id: 1, result: evmIdOf(url, network) })
    if (u.pathname.startsWith('/api/v2/')) return json(200, { items: [], next_page_params: null, at: u.pathname + u.search })
    // Arweave
    if (u.pathname === '/info') return json(200, { network: ARWEAVE_NETWORK, height: 1_500_000 })
    if (u.pathname === '/graphql') return json(200, { data: { transactions: { edges: [{ node: { id: AR_ID, tags: [{ name: 'Unlock-After', value: '2027-01-01T00:00:00Z' }] } }] } } })
    // drand
    if (u.pathname === `/${QN}/info`) return json(200, INFO_AS_DRAND_SENDS)
    if (u.pathname === `/${QN}/public/latest`) return json(200, beaconOf(100))
    const round = /^\/[0-9a-f]{64}\/public\/(\d+)$/.exec(u.pathname)
    if (round) return Number(round[1]) > 1000 ? raw(425, 'too early') : json(200, beaconOf(Number(round[1])))
    return json(404, {})
  }
  return { calls, transport }
}

interface Started { port: number; network: Network; logs: string[]; calls: Call[]; clock: { t: number }; status(): unknown; close(): Promise<void> }
const OPEN = new Set<{ close(): Promise<void> }>()
after(() => Promise.all([...OPEN].map((s) => s.close())))
function closeServer(s: { close(): Promise<void> }, server: Server): Promise<void> {
  OPEN.delete(s)
  return new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()) })
}
async function start(network: Network, o: { override?: Override; isTor?: boolean; auth?: string | null; breadth?: ReturnType<typeof relayBreadth> } = {}): Promise<Started> {
  const w = fakeWorld(network, o)
  const logs: string[] = []
  const clock = { t: NOW }
  const relay = createRelay({
    network, build: 'test', upstream: relayUpstreams(network, {}), breadth: o.breadth ?? relayBreadth(network, {}), bitcoindAuth: o.auth === undefined ? AUTH_LINE : o.auth,
    transport: w.transport, priceFixture: network === 'local' ? { SOL: 150, ETH: 3000 } : null, ticketKey: () => TICKET_KEY,
    confinement: { ok: true, probes: 5, result: 'EPERM ×5' }, now: () => clock.t, log: (l: string) => { logs.push(l) }, rand: () => 'sess',
  })
  await relay.startup()
  const server = createServer(relay.handle)
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const s: Started = { port: (server.address() as { port: number }).port, network, logs, calls: w.calls, clock, status: relay.status, close: () => closeServer(s, server) }
  OPEN.add(s)
  return s
}
interface Reply { status: number; type: string | undefined; nosniff: string | undefined; text: string; json: any }
function rq(s: Started, path: string, o: { method?: string; body?: unknown; headers?: Record<string, string> } = {}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const b = o.body === undefined ? null : Buffer.from(typeof o.body === 'string' ? o.body : JSON.stringify(o.body))
    const r = request({ host: '127.0.0.1', port: s.port, path, method: o.method ?? (b ? 'POST' : 'GET'),
      headers: { host: `127.0.0.1:${PORTS[s.network].relay}`, ...(b ? { 'content-type': 'application/json', 'content-length': String(b.length) } : {}), ...o.headers } }, (res) => {
      const c: Buffer[] = []
      res.on('data', (d: Buffer) => c.push(d))
      res.on('end', () => {
        const text = Buffer.concat(c).toString('utf8')
        let j: unknown
        try { j = JSON.parse(text) } catch { j = undefined }
        resolve({ status: res.statusCode ?? 0, type: res.headers['content-type'], nosniff: res.headers['x-content-type-options'] as string | undefined, text, json: j })
      })
    })
    r.on('error', reject)
    r.end(b ?? undefined)
  })
}
const rpc = (method: string, params: unknown[] = []): Record<string, unknown> => ({ jsonrpc: '2.0', id: 9, method, params })
const g = (r: Reply): string | undefined => r.json?.error?.data?.guard
const BTCD = 'http://127.0.0.1:18443', ORD = 'http://127.0.0.1:8090'
const hasSecret = (s: string): boolean => SECRET_NEEDLES.some((x) => s.includes(x))
const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 20))

test('local BTC lane: block 0 checked with the credential; POST /relay/btc reads reach the bitcoind with it, and only the bitcoind', { timeout: 30_000 }, async () => {
  const s = await start('local')
  try {
    const st = s.status() as { identity: Record<string, unknown>; endpoints: Record<string, number> }
    assert.deepEqual([st.identity.btc, st.endpoints.btc], [{ ok: true }, 1])
    assert.ok(s.logs.some((l) => /^identity btc loopback:18443: block 0 = the regtest genesis OK/.test(l)))
    const r = await rq(s, '/relay/btc', { body: rpc('getblockcount') })
    assert.deepEqual([r.status, r.json], [200, { jsonrpc: '2.0', id: 9, result: 101 }])
    const toBtcd = s.calls.filter((c) => c.url.startsWith(BTCD))
    assert.ok(toBtcd.length >= 2 && toBtcd.every((c) => c.headers.authorization === `Basic ${AUTH_B64}` && c.role === 'btc'))
    assert.deepEqual(JSON.parse(toBtcd.at(-1)!.body!), { jsonrpc: '2.0', id: 9, method: 'getblockcount', params: [] })   // the canonical envelope
    // ord (the same lane, no credential)
    const ord = await rq(s, `/relay/btc/ord/tx/${TXID}`)
    assert.deepEqual([ord.status, ord.json, ord.type, ord.nosniff], [200, { path: `/tx/${TXID}` }, JSON_TYPE, 'nosniff'])
    const height = await rq(s, '/relay/btc/ord/r/blockheight')
    assert.deepEqual([height.status, height.text, height.type], [200, '101', TEXT_TYPE])
    const notBtcd = s.calls.filter((c) => !c.url.startsWith(BTCD))
    assert.ok(notBtcd.length > 0 && notBtcd.every((c) => c.headers.authorization === undefined && !hasSecret(JSON.stringify(c))), 'the credential went elsewhere')
    assert.ok(s.calls.filter((c) => c.url.startsWith(ORD)).every((c) => c.role === 'btc' && c.user === `btc.sess.${0}`))
    // scantxoutset with its guard; a refused one never reaches the node
    const before = s.calls.length
    const scan = await rq(s, '/relay/btc', { body: rpc('scantxoutset', ['abort', []]) })
    assert.deepEqual([scan.status, g(scan)], [403, 'relay.btc-params'])
    for (const m of ['sendrawtransaction', 'sendtoaddress', 'generatetoaddress', 'dumpprivkey', 'stop', 'listunspent']) {
      const x = await rq(s, '/relay/btc', { body: rpc(m, ['00']) })
      assert.deepEqual([x.status, g(x)], [403, 'relay.method'], m)
    }
    assert.equal(s.calls.length, before, 'a refused bitcoind request was forwarded')
    const ok = await rq(s, '/relay/btc', { body: rpc('scantxoutset', ['start', [{ desc: `addr(${ADDR.regtest})` }]]) })
    assert.equal(ok.status, 200)
    // never in a response, a log line or a refusal
    const all = [r, ord, height, scan, ok].map((x) => x.text).join('\n') + s.logs.join('\n')
    assert.ok(!hasSecret(all) && !all.includes(CANARY))
    assert.ok(s.logs.some((l) => l === `btc getblockcount 200 0ms`))
    assert.ok(s.logs.some((l) => /^btc ord:tx\/:txid 200 \d+ms$/.test(l)) && !s.logs.some((l) => l.includes(TXID)))
  } finally { await s.close() }
})

test('a bitcoind answer that echoes the credential is withheld: 502 relay.upstream-secret, nothing of it passed on', { timeout: 30_000 }, async () => {
  const echo: Override = (url, c) => (url.startsWith(BTCD) && c.body?.includes('getbestblockhash') ? json(200, { jsonrpc: '2.0', id: 9, result: c.headers.authorization }) : undefined)
  const s = await start('local', { override: echo })
  try {
    const r = await rq(s, '/relay/btc', { body: rpc('getbestblockhash') })
    assert.deepEqual([r.status, g(r)], [502, 'relay.upstream-secret'])
    assert.ok(!hasSecret(r.text) && !hasSecret(s.logs.join('\n')))
    // fix round 1 (review m3, M2): not only 200 answers — a 4xx JSON echo of the header or the password is withheld too
    for (const st of [400, 404, 500]) {
      const four: Override = (url, c) => (url.startsWith(BTCD) && c.body?.includes('getblockheader') ? json(st, { jsonrpc: '2.0', id: 9, error: { code: -8, message: `bad ${st === 400 ? c.headers.authorization : 'Synthetic-Pass-7f3a9c1e'}` } }) : undefined)
      const f = await start('local', { override: four })
      try {
        const x = await rq(f, '/relay/btc', { body: rpc('getblockheader', ['00']) })
        // 4xx: the answer reaches the relay and is withheld; 5xx: relay-core never passes a 5xx body on (upstream unavailable)
        assert.deepEqual([x.status, g(x)], [502, st < 500 ? 'relay.upstream-secret' : undefined], `HTTP ${st}`)
        assert.ok(!hasSecret(x.text) && !hasSecret(f.logs.join('\n')))
      } finally { await f.close() }
    }
    const plain: Override = (url, c) => (url.startsWith(BTCD) && c.body?.includes('getbestblockhash') ? json(200, { jsonrpc: '2.0', id: 9, result: 'Synthetic-Pass-7f3a9c1e' }) : undefined)
    const t = await start('local', { override: plain })
    try {
      const x = await rq(t, '/relay/btc', { body: rpc('getbestblockhash') })
      assert.deepEqual([x.status, g(x)], [502, 'relay.upstream-secret'])
    } finally { await t.close() }
  } finally { await s.close() }
})

test('an ord answer that carries the bitcoind credential is withheld (S6 review m5): 502 relay.upstream-secret, nothing of it passed on', { timeout: 30_000 }, async () => {
  for (const leak of ['Synthetic-Pass-7f3a9c1e', AUTH_LINE, `Basic ${AUTH_B64}`]) {
    const echo: Override = (url) => (url.startsWith(ORD) && url.endsWith('/status') ? json(200, { chain: 'regtest', note: leak }) : undefined)
    const s = await start('local', { override: echo })
    try {
      const r = await rq(s, '/relay/btc/ord/status')
      assert.deepEqual([r.status, g(r)], [502, 'relay.upstream-secret'])
      assert.ok(!hasSecret(r.text) && !hasSecret(s.logs.join('\n')))
      assert.equal((await rq(s, '/relay/btc/ord/r/blockheight')).status, 200)             // other ord answers still go through
    } finally { await s.close() }
  }
})

test('a /relay/btc answer is strict UTF-8 JSON or relay.upstream-shape (S6 review m6); a good one carries nosniff', { timeout: 30_000 }, async () => {
  assert.equal(guardOf(() => rpcShape(Buffer.from('{"result":1}'))), null)
  for (const bad of [Buffer.from('<html>'), Buffer.from('\ufeff{"result":1}'), Buffer.from([0x7b, 0xff, 0x7d]), Buffer.alloc(0)]) assert.equal(guardOf(() => rpcShape(bad)), 'relay.upstream-shape')
  const html: Override = (url, c) => (url.startsWith(BTCD) && c.body?.includes('getbestblockhash') ? raw(200, '<html><script>1</script></html>') : undefined)
  const bom: Override = (url, c) => (url.startsWith(BTCD) && c.body?.includes('getbestblockhash') ? raw(200, '\ufeff{"jsonrpc":"2.0","id":9,"result":"x"}') : undefined)
  for (const override of [html, bom]) {
    const s = await start('local', { override })
    try {
      const r = await rq(s, '/relay/btc', { body: rpc('getbestblockhash') })
      assert.deepEqual([r.status, g(r)], [502, 'relay.upstream-shape'])
      assert.ok(!r.text.includes('<html') && !r.text.includes('{"jsonrpc":"2.0","id":9,"result":"x"}'))
    } finally { await s.close() }
  }
  const ok = await start('local')
  try {
    const r = await rq(ok, '/relay/btc', { body: rpc('getblockcount') })
    assert.deepEqual([r.status, r.type, r.nosniff], [200, 'application/json', 'nosniff'])
  } finally { await ok.close() }
})

test('no bitcoind credential: the local BTC lane is off — not one request to the bitcoind or ord, 503s, btc ✗ in /relay/status', { timeout: 30_000 }, async () => {
  for (const auth of [null, '']) {
    const s = await start('local', { auth })
    try {
      assert.equal(s.calls.filter((c) => c.url.startsWith(BTCD) || c.url.startsWith(ORD)).length, 0)
      const st = (await rq(s, '/relay/status')).json
      assert.deepEqual([st.identity.btc, st.endpoints.btc], [{ ok: false, message: 'the bitcoind credential is unavailable ($OUT/local/btc-rpc.auth)' }, 0])
      assert.deepEqual([st.identity.eth, st.identity.sol], [{ ok: true }, { ok: true }])
      const r = await rq(s, '/relay/btc', { body: rpc('getblockcount') })
      assert.deepEqual([r.status, r.json.error.message], [503, 'btc disabled (identity not verified at startup)'])
      const o = await rq(s, '/relay/btc/ord/status')
      assert.equal(o.status, 503)
      assert.ok(s.logs.includes('identity btc: DISABLED — the bitcoind credential is unavailable ($OUT/local/btc-rpc.auth); /relay/btc answers 503, ord is not served'))
      assert.equal(s.calls.filter((c) => c.url.startsWith(BTCD) || c.url.startsWith(ORD)).length, 0)
    } finally { await s.close() }
  }
  // a relay without breadth upstreams keeps the eth/sol status shape exactly
  const plain = createRelay({ network: 'local', build: 'test', upstream: relayUpstreams('local', {}), transport: fakeWorld('local').transport, priceFixture: null,
    ticketKey: () => TICKET_KEY, confinement: { ok: true, probes: 5, result: 'EPERM ×5' }, log: () => {} })
  await plain.startup()
  assert.deepEqual(plain.status(), { network: 'local', build: 'test', confined: true, identity: { eth: { ok: true }, sol: { ok: true } }, endpoints: { eth: 1, sol: 1 } })
})

test('BTC identity mismatch at startup is fatal (exit 2), naming the host only: a non-regtest bitcoind; a wrong Esplora genesis', { timeout: 30_000 }, async () => {
  const fatal = async (p: Promise<Started>): Promise<{ exitCode: number; message: string }> => {
    try { const s = await p; await s.close() } catch (e) { return { exitCode: (e as { exitCode?: number }).exitCode ?? -1, message: (e as Error).message } }
    assert.fail('expected a fatal startup')
  }
  const main = await fatal(start('local', { override: (url) => (url.startsWith(BTCD) ? json(200, { jsonrpc: '2.0', id: 1, result: GENESIS.btc.mainnet }) : undefined) }))
  assert.deepEqual(main, { exitCode: 2, message: 'btc identity MISMATCH at loopback:18443: block 0 is not the regtest genesis' })
  const t4 = await fatal(start('testnet', { override: (url) => (url.endsWith('/block-height/0') ? raw(200, GENESIS.btc.mainnet) : undefined) }))
  assert.equal(t4.exitCode, 2)
  assert.match(t4.message, /^btc identity MISMATCH at [a-z0-9.]+: block 0 is not the testnet4 genesis$/)
  const mn = await fatal(start('mainnet', { override: (url) => (url.endsWith('/block-height/0') ? raw(200, GENESIS.btc.testnet4) : undefined) }))
  assert.match(mn.message, /block 0 is not the mainnet genesis$/)
  // not a hash (a block page, a JSON answer): not verified, never fatal; the endpoint is skipped
  const s = await start('testnet', { override: (url) => (url.endsWith('/block-height/0') && url.includes('.onion') ? raw(200, '<html>blocked</html>') : undefined) })
  try {
    const st = s.status() as { endpoints: Record<string, number> }
    assert.equal(st.endpoints.btc, ENDPOINTS.testnet['btc.esplora'].length - 1)
    assert.ok(s.logs.some((l) => /^identity btc [a-z2-7]{56}\.onion: refused\/blocked \(HTTP 200\)/.test(l)))
  } finally { await s.close() }
  // a bitcoind that refuses the credential: not verified (401), the lane is off
  const d = await start('local', { override: (url) => (url.startsWith(BTCD) ? raw(401, '') : undefined) })
  try { assert.deepEqual((d.status() as { identity: Record<string, unknown> }).identity.btc, { ok: false, message: 'no endpoint passed the identity check yet (a dropped endpoint is checked again every 30 s)' }) } finally { await d.close() }
})

test('testnet/mainnet Esplora: block 0 at startup over the btc role; reads forwarded to <base>/<the matched path> with failover; text and JSON answers', { timeout: 30_000 }, async () => {
  for (const n of ['testnet', 'mainnet'] as const) {
    const down = new Set<string>()
    const s = await start(n, { override: (url) => ([...down].some((d) => url.startsWith(d)) ? Object.assign(new Error('x'), { code: 'ECONNREFUSED' }) : undefined) })
    try {
      const bases = ENDPOINTS[n]['btc.esplora']
      const st = s.status() as { identity: Record<string, unknown>; endpoints: Record<string, number> }
      assert.deepEqual([st.identity.btc, st.endpoints.btc], [{ ok: true }, bases.length])
      assert.deepEqual(s.calls.filter((c) => c.url.endsWith('/block-height/0')).map((c) => c.url).sort(), bases.map((b) => `${b}/block-height/0`).sort())
      assert.ok(s.calls.filter((c) => c.role === 'btc').every((c) => /^btc\.sess\.\d+$/.test(c.user) && c.headers.authorization === undefined))
      const h = await rq(s, '/relay/btc/esplora/blocks/tip/height')
      assert.deepEqual([h.status, h.text, h.type, h.nosniff], [200, '912345', TEXT_TYPE, 'nosniff'])
      const hex = await rq(s, `/relay/btc/esplora/tx/${TXID}/hex`)
      assert.deepEqual([hex.status, hex.text], [200, '0200aabb'])
      const utxo = await rq(s, `/relay/btc/esplora/address/${ADDR[n]}/utxo`)
      assert.deepEqual([utxo.status, utxo.type], [200, JSON_TYPE])
      assert.equal(s.calls.at(-1)!.url, `${bases[0]}/address/${ADDR[n]}/utxo`)
      down.add(bases[0])                                          // the first base refuses before processing: the next one answers
      const fo = await rq(s, `/relay/btc/esplora/tx/${TXID}/status`)
      assert.equal(fo.status, 200)
      assert.equal(s.calls.at(-1)!.url, `${bases[1]}/tx/${TXID}/status`)
      assert.ok(s.logs.some((l) => /^btc esplora:tx\/:txid\/status 200 \d+ms$/.test(l)))
      assert.ok(!s.logs.join('\n').includes(TXID) && !s.logs.join('\n').includes(ADDR[n]) && !s.logs.join('\n').includes(CANARY))
      // refusals over HTTP: nothing forwarded
      const count = s.calls.length
      const cases: Array<[string, string, number, string]> = [
        ['POST', '/relay/btc/esplora/tx', 403, 'relay.method'], ['GET', `/relay/btc/esplora/address/${n === 'testnet' ? ADDR.mainnet : ADDR.testnet}`, 403, 'relay.path'],
        ['GET', '/relay/btc/esplora/mempool/recent', 403, 'relay.path'], ['GET', `/relay/btc/ord/tx/${TXID}`, 403, 'relay.path'],
        ['GET', `/relay/btc/esplora/tx/${TXID}?callback=x`, 403, 'relay.path'],
      ]
      for (const [m, p, code, guard] of cases) {
        const r = m === 'POST' ? await rq(s, p, { body: '0200' }) : await rq(s, p)
        assert.deepEqual([r.status, g(r)], [code, guard], `${m} ${p}`)
      }
      const b = await rq(s, '/relay/btc', { body: rpc('getblockcount') })
      assert.deepEqual([b.status, g(b)], [403, 'relay.method'])              // no bitcoind off local
      assert.equal(s.calls.length, count)
    } finally { await s.close() }
  }
})

test('an upstream answering another shape is withheld: 502 relay.upstream-shape, nothing of it passed on (HTML, a wrong hex)', { timeout: 30_000 }, async () => {
  const s = await start('mainnet', { override: (url) => (url.endsWith('/hex') ? raw(200, `<html><script>fetch('//${CANARY}')</script></html>`) : url.endsWith('/status') ? raw(200, 'not json') : undefined) })
  try {
    for (const p of [`/relay/btc/esplora/tx/${TXID}/hex`, `/relay/btc/esplora/tx/${TXID}/status`]) {
      const r = await rq(s, p)
      assert.deepEqual([r.status, g(r)], [502, 'relay.upstream-shape'], p)
      assert.ok(!r.text.includes(CANARY) && !r.text.includes('<html>'))
    }
  } finally { await s.close() }
})

test('Blockscout (D2a): eth/arb/base each checked by eth_chainId at /api/eth-rpc; provenance reads forwarded; a mismatch disables only that chain', { timeout: 30_000 }, async () => {
  const s = await start('testnet', { override: (url) => (url.startsWith('https://base-sepolia.blockscout.com/api/eth-rpc') ? json(200, { jsonrpc: '2.0', id: 1, result: '0x1' }) : undefined) })
  try {
    const sv = (await rq(s, '/relay/services')).json
    assert.equal(sv.network, 'testnet')
    assert.deepEqual(sv.services['blockscout.eth'], { ok: true, viaTor: true, endpoints: 1 })
    assert.deepEqual(sv.services['blockscout.arb'], { ok: true, viaTor: true, endpoints: 1 })
    assert.deepEqual(sv.services['blockscout.base'], { ok: false, viaTor: true, endpoints: 0, message: 'an endpoint answered another identity: disabled until the relay restarts' })
    assert.ok(s.logs.includes('identity blockscout.base: DISABLED — an endpoint answered another identity (relay.service-identity); until restart'))
    const idCalls = s.calls.filter((c) => c.url.endsWith('/api/eth-rpc'))
    assert.deepEqual(idCalls.map((c) => c.url).sort(), ['https://arbitrum-sepolia.blockscout.com/api/eth-rpc', 'https://base-sepolia.blockscout.com/api/eth-rpc', 'https://eth-sepolia.blockscout.com/api/eth-rpc'])
    assert.ok(idCalls.every((c) => c.role === 'blockscout' && c.method === 'POST' && JSON.parse(c.body!).method === 'eth_chainId'))
    for (const p of [`addresses/${EVM}/transactions?filter=to`, `addresses/${EVM}/internal-transactions?filter=to`, `transactions/${EVM_TX}`]) {
      const r = await rq(s, `/relay/blockscout/eth/${p}`)
      assert.deepEqual([r.status, r.json.at], [200, `/api/v2/${p}`])
      assert.equal(s.calls.at(-1)!.url, `https://eth-sepolia.blockscout.com/api/v2/${p}`)
      assert.equal(s.calls.at(-1)!.role, 'blockscout')
    }
    const arb = await rq(s, `/relay/blockscout/arb/transactions/${EVM_TX}`)
    assert.equal(arb.status, 200)
    const count = s.calls.length
    const base = await rq(s, `/relay/blockscout/base/transactions/${EVM_TX}`)
    assert.deepEqual([base.status, base.json.error.message], [503, 'blockscout.base disabled (an endpoint answered another identity: disabled until the relay restarts)'])
    s.clock.t += SERVICE_RETRY_MS * 10                                           // a mismatch is not retried
    assert.equal((await rq(s, `/relay/blockscout/base/transactions/${EVM_TX}`)).status, 503)
    assert.equal(s.calls.length, count)
    assert.ok(!s.logs.join('\n').includes(EVM.slice(2)))
  } finally { await s.close() }
})

test('Arweave (D3 ar-id): the gateway\'s network checked; GET /relay/arweave/tags/<id> → one fixed GraphQL POST, answered { id, found, tags }', { timeout: 30_000 }, async () => {
  const s = await start('mainnet')
  try {
    const r = await rq(s, `/relay/arweave/tags/${AR_ID}`)
    assert.deepEqual([r.status, r.type, r.json], [200, JSON_TYPE, { id: AR_ID, found: true, tags: [{ name: 'Unlock-After', value: '2027-01-01T00:00:00Z' }] }])
    const q = s.calls.filter((c) => c.url.endsWith('/graphql'))
    assert.equal(q.length, 1)
    assert.deepEqual([q[0].url, q[0].method, q[0].role], [`${ENDPOINTS.mainnet['arweave.gateway'][0]}/graphql`, 'POST', 'arweave'])
    assert.deepEqual(JSON.parse(q[0].body!), { query: AR_TAGS_QUERY, variables: { ids: [AR_ID] } })
    assert.ok(s.calls.some((c) => c.url === `${ENDPOINTS.mainnet['arweave.gateway'][0]}/info` && c.role === 'arweave'))
    assert.ok(s.logs.some((l) => /^arweave arweave:tags\/:arid 200 \d+ms$/.test(l)) && !s.logs.join('\n').includes(AR_ID))
  } finally { await s.close() }
  const t = await start('testnet', { override: (url) => (url.endsWith('/info') && url.includes('ar-io.dev') ? json(200, { network: 'arweave.N.2' }) : undefined) })
  try {
    const sv = (await rq(t, '/relay/services')).json.services
    assert.deepEqual(sv.arweave, { ok: false, viaTor: true, endpoints: 0, message: 'an endpoint answered another identity: disabled until the relay restarts' })
    assert.equal((await rq(t, `/relay/arweave/tags/${AR_ID}`)).status, 503)
    assert.equal(t.calls.filter((c) => c.url.endsWith('/graphql')).length, 0)
    assert.deepEqual(sv.drand, { ok: true, viaTor: true, endpoints: ENDPOINTS.testnet.drand.length })     // other services unaffected
  } finally { await t.close() }
})

test('drand (D6): pinned info bytes, latest, a round, "not yet" 404; foreign chain → relay.path; a mismatching info disables drand only', { timeout: 30_000 }, async () => {
  const s = await start('testnet')
  try {
    const info = await rq(s, `/relay/drand/${QN}/info`)
    assert.deepEqual([info.status, info.type, info.text], [200, JSON_TYPE, SEALER_INFO])
    const latest = await rq(s, `/relay/drand/${QN}/public/latest`)
    assert.deepEqual([latest.status, latest.text], [200, JSON.stringify(beaconOf(100))])
    const r7 = await rq(s, `/relay/drand/${QN}/public/7`)
    assert.deepEqual([r7.status, r7.json], [200, beaconOf(7)])
    const future = await rq(s, `/relay/drand/${QN}/public/999999999`)
    assert.deepEqual([future.status, future.json], [404, { error: { message: 'this drand round is not published yet' } }])
    assert.ok(s.calls.filter((c) => c.url.includes(QN)).every((c) => c.role === 'drand' && /^drand\.sess\.\d+$/.test(c.user)))
    assert.equal(s.calls.find((c) => c.url.endsWith('/public/7'))!.url, `${ENDPOINTS.testnet.drand[0]}/${QN}/public/7`)
    const foreign = await rq(s, `/relay/drand/${'ff'.repeat(32)}/public/latest`)
    assert.deepEqual([foreign.status, g(foreign)], [403, 'relay.path'])
    assert.ok(s.logs.some((l) => l.startsWith('drand drand:public/:round 200 ')) && !s.logs.some((l) => l.includes('/public/7')))
  } finally { await s.close() }
  const bad = await start('mainnet', { override: (url) => (url.endsWith(`/${QN}/info`) && url.includes('api2.') ? json(200, { ...INFO_AS_DRAND_SENDS, period: 30 }) : undefined) })
  try {
    const r = await rq(bad, `/relay/drand/${QN}/public/latest`)
    assert.equal(r.status, 503)
    assert.equal(bad.calls.filter((c) => c.url.includes('/public/')).length, 0)
    assert.deepEqual((await rq(bad, '/relay/services')).json.services['blockscout.eth'], { ok: true, viaTor: true, endpoints: 1 })
  } finally { await bad.close() }
})

test('local drand (D-R15): the testnet section\'s endpoints, through Tor — an IsTor check first; IsTor ✗ → 503 and no drand request', { timeout: 30_000 }, async () => {
  const off = await start('local', { isTor: false })
  try {
    assert.equal(off.calls.filter((c) => c.url === TOR_CHECK).length, 0, 'the local relay checks Tor only when drand is asked for')
    const r = await rq(off, `/relay/drand/${QN}/public/latest`)
    assert.deepEqual([r.status, r.json.error.message], [503, 'Tor is not available (IsTor ✗): the local relay reaches this service through Tor only'])
    assert.equal(off.calls.filter((c) => c.url.includes(QN)).length, 0)
    assert.equal(off.calls.filter((c) => c.url === TOR_CHECK).length, 1)
  } finally { await off.close() }
  const on = await start('local')
  try {
    const r = await rq(on, `/relay/drand/${QN}/public/7`)
    assert.deepEqual([r.status, r.json], [200, beaconOf(7)])
    const drand = on.calls.filter((c) => c.url.includes(QN))
    assert.ok(drand.length >= 2 && drand.every((c) => ENDPOINTS.testnet.drand.some((b) => c.url.startsWith(`${b}/`)) && c.role === 'drand'))
    const checks = on.calls.filter((c) => c.url === TOR_CHECK)
    assert.ok(checks.length >= 1 && checks.every((c) => c.role === 'check'))
    assert.ok(on.calls.indexOf(checks[0]) < on.calls.indexOf(drand[0]), 'Tor is checked before the first drand request')
    const st = (await rq(on, '/relay/services')).json
    assert.deepEqual(Object.keys(st.services).sort(), ['btc.ord', 'drand'])
  } finally { await on.close() }
})

test('fix round 1 (review I-1): the local relay says drand goes via Tor — /relay/tor torRoles and IsTor, /relay/services viaTor, the banner; Tor down → drand unavailable, never "direct"', { timeout: 30_000 }, async () => {
  const down = await start('local', { isTor: false })
  try {
    const before = (await rq(down, '/relay/tor')).json
    assert.deepEqual([before.profile, before.tor, before.isTor, before.checkedAt, before.torRoles], ['local', false, null, null, ['check', 'drand']])
    assert.deepEqual(Object.keys(before), ['profile', 'tor', 'isTor', 'checkedAt', 'auto', 'roles', 'torRoles', 'endpoints', 'confinement'])
    assert.equal(down.calls.filter((c) => c.url === TOR_CHECK).length, 0, '/relay/tor never starts a Tor check on local')
    // /relay/services checks drand now: Tor down → drand unavailable, and not one drand request (review m3, T4)
    const sv = (await rq(down, '/relay/services')).json.services
    assert.deepEqual(sv.drand, { ok: false, viaTor: true, endpoints: 0, message: 'Tor is not available (IsTor ✗): the local relay reaches this service through Tor only' })
    assert.deepEqual(sv['btc.ord'], { ok: true, viaTor: false, endpoints: 1 })
    assert.equal(down.calls.filter((c) => c.url.includes(QN)).length, 0)
    assert.equal(down.calls.filter((c) => c.url === TOR_CHECK).length, 1)
    const after = (await rq(down, '/relay/tor')).json
    assert.deepEqual([after.tor, after.isTor, after.checkedAt, after.torRoles], [false, false, NOW, ['check', 'drand']])
    assert.ok(down.logs.includes('identity drand: not checked — Tor is not available'))
  } finally { await down.close() }
  const up = await start('local')
  try {
    assert.equal((await rq(up, `/relay/drand/${QN}/public/latest`)).status, 200)
    const t = (await rq(up, '/relay/tor')).json
    assert.deepEqual([t.tor, t.isTor, t.checkedAt, t.torRoles], [false, true, NOW, ['check', 'drand']])
    assert.deepEqual((await rq(up, '/relay/services')).json.services.drand, { ok: true, viaTor: true, endpoints: ENDPOINTS.testnet.drand.length })
  } finally { await up.close() }
  // a local relay that serves no drand goes to Tor for nothing, and says so
  const none = await start('local', { breadth: { ...relayBreadth('local', {}), drand: [] } })
  try {
    const t = (await rq(none, '/relay/tor')).json
    assert.deepEqual([t.tor, t.isTor, t.torRoles], [false, null, []])
    assert.deepEqual(Object.keys((await rq(none, '/relay/services')).json.services), ['btc.ord'])
  } finally { await none.close() }
  // testnet and mainnet: every role through Tor; every service viaTor
  const m = await start('mainnet')
  try {
    const t = (await rq(m, '/relay/tor')).json
    assert.deepEqual([t.tor, t.isTor, t.torRoles], [true, true, ['eth', 'sol', 'price', 'check', 'btc', 'blockscout', 'arweave', 'drand']])
    for (const v of Object.values((await rq(m, '/relay/services')).json.services) as Array<{ viaTor: boolean }>) assert.equal(v.viaTor, true)
  } finally { await m.close() }
  // the ready banner's Tor part (relay-policy pins the real line)
  assert.equal(torBanner('local', ['check', 'drand']), 'drand only, via Tor (socks5h; IsTor checked on first use); chains direct loopback')
  assert.equal(torBanner('local', []), 'none (direct loopback)')
  for (const n of ['testnet', 'mainnet'] as const) assert.equal(torBanner(n, ['eth']), 'circuits per role, auto-rotate on')
})

test('a service none of whose endpoints answered is 503 now and checked again after SERVICE_RETRY_MS', { timeout: 30_000 }, async () => {
  let up = false
  const s = await start('mainnet', { override: (url) => (!up && url.includes('arweave.net') || !up && url.includes('turbo-gateway.com') ? Object.assign(new Error('t'), { code: 'ETIMEDOUT' }) : undefined) })
  try {
    await settle()
    const first = await rq(s, `/relay/arweave/tags/${AR_ID}`)
    assert.equal(first.status, 503)
    assert.match(first.json.error.message, /^arweave disabled \(no endpoint answered the identity check/)
    up = true
    assert.equal((await rq(s, `/relay/arweave/tags/${AR_ID}`)).status, 503)          // within the retry window: not asked again
    s.clock.t += SERVICE_RETRY_MS
    const later = await rq(s, `/relay/arweave/tags/${AR_ID}`)
    assert.equal(later.status, 200)
  } finally { await s.close() }
})

test('every other request under /relay: a known path with the wrong HTTP method → relay.method; an unknown path → relay.path', { timeout: 30_000 }, async () => {
  const s = await start('local')
  try {
    const cases: Array<[string, string, string]> = [
      ['GET', '/relay/eth', 'relay.method'], ['GET', '/relay/btc', 'relay.method'], ['POST', '/relay/status', 'relay.method'], ['POST', '/relay/services', 'relay.method'],
      ['PUT', '/relay/sol', 'relay.method'], ['GET', '/relay/tor/new', 'relay.method'],
      ['POST', '/relay/other', 'relay.path'], ['GET', '/relay/nothing', 'relay.path'], ['POST', '/relay/eth/ep/a', 'relay.path'], ['POST', '/relay/btc/ep/0', 'relay.method'],
      ['GET', '/relay/btc/ep/0', 'relay.path'], ['POST', '/relay/ETH', 'relay.path'], ['GET', '/relay', 'relay.path'], ['GET', '/relay/status/', 'relay.path'],
    ]
    for (const [m, p, guard] of cases) {
      const r = m === 'GET' ? await rq(s, p) : await rq(s, p, { method: m, body: rpc('eth_chainId') })
      assert.deepEqual([r.status, g(r)], [403, guard], `${m} ${p}`)
    }
    const tor = (await rq(s, '/relay/tor')).json
    assert.equal(Object.keys(tor.roles).join(), 'eth,sol,price,check,btc,drand')
  } finally { await s.close() }
  const m = await start('mainnet')
  try {
    const tor = (await rq(m, '/relay/tor')).json
    assert.equal(Object.keys(tor.roles).join(), 'eth,sol,price,check,btc,blockscout,arweave,drand')
    const nw = await rq(m, '/relay/tor/new', { body: { role: 'drand' } })
    assert.deepEqual([nw.status, nw.json.results.drand.ok], [200, true])
    assert.ok(m.calls.every((c) => /^(?:eth|sol|price|check|btc|blockscout|arweave|drand)\.sess\.\d+$/.test(c.user)))
    const st = (await rq(m, '/relay/status')).json
    assert.deepEqual(st, { network: 'mainnet', build: 'test', confined: true, identity: { eth: { ok: true }, sol: { ok: true }, btc: { ok: true } }, endpoints: { eth: 3, sol: 2, btc: 4 } })
    const sv = (await rq(m, '/relay/services')).json
    assert.deepEqual(Object.keys(sv.services), ['blockscout.eth', 'blockscout.arb', 'blockscout.base', 'arweave', 'drand'])
    for (const v of Object.values(sv.services) as Array<{ ok: boolean }>) assert.equal(v.ok, true)
    assert.ok(!JSON.stringify(sv).includes('blockscout.com') && !JSON.stringify(sv).includes(CANARY))
  } finally { await m.close() }
})

// =====================================================================================================================
// 3. the real local transport, the breadth lists, the credential file
// =====================================================================================================================

interface Seen { headers: IncomingHttpHeaders[]; url: string; close(): Promise<void> }
async function loopbackServer(answer: (path: string) => string): Promise<Seen> {
  const headers: IncomingHttpHeaders[] = []
  const server = createServer((req, res) => {
    req.resume()
    req.on('end', () => { headers.push(req.headers); const b = Buffer.from(answer(req.url ?? '')); res.writeHead(200, { 'content-type': 'application/json', 'content-length': b.length }); res.end(b) })
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const s: Seen = { headers, url: `http://127.0.0.1:${(server.address() as { port: number }).port}`, close: () => closeServer(s, server) }
  OPEN.add(s)
  return s
}

test('the real local transport: the credential reaches the loopback bitcoind only; ord never sees it; off loopback it is refused before a socket', { timeout: 30_000 }, async () => {
  const btcd = await loopbackServer(() => JSON.stringify({ jsonrpc: '2.0', id: 1, result: GENESIS.btc.regtest }))
  const ord = await loopbackServer((p) => (p === '/r/blockhash/0' ? JSON.stringify(GENESIS.btc.regtest) : '{"chain":"regtest"}'))
  const logs: string[] = []
  const relay = createRelay({ network: 'local', build: 'test', upstream: { eth: [], sol: [] }, breadth: { btc: [btcd.url], ord: [ord.url], blockscout: {}, arweave: [], drand: [] },
    bitcoindAuth: AUTH_LINE, transport: socksTransport('local'), priceFixture: null, ticketKey: () => TICKET_KEY, confinement: { ok: true, probes: 5, result: 'EPERM ×5' },
    log: (l: string) => { logs.push(l) } })
  await assert.rejects(relay.startup(), /no chain passed identity/)                    // eth and sol are what a relay needs; btc alone is not enough
  assert.equal(btcd.headers.length, 1)
  assert.equal(btcd.headers[0].authorization, `Basic ${AUTH_B64}`)
  assert.ok(logs.some((l) => /^identity btc loopback:\d+: block 0 = the regtest genesis OK/.test(l)) && !hasSecret(logs.join('\n')))
  const t = socksTransport('local')
  const got = await t(`${ord.url}/status`, { method: 'GET', role: 'btc', user: 'btc.s.0' })
  assert.equal(got.status, 200)
  assert.equal(ord.headers.at(-1)!.authorization, undefined)
  await assert.rejects(t('https://api.drand.sh/x', { method: 'GET', role: 'btc', user: 'btc.s.0', headers: { authorization: 'Basic eA==' } }), (e: NodeJS.ErrnoException) => e.code === 'ECREDENTIAL')
  await assert.rejects(t('http://203.0.113.77:18443/', { method: 'POST', role: 'btc', user: 'btc.s.0', headers: { Authorization: 'Basic eA==' } }), (e: NodeJS.ErrnoException) => e.code === 'ECREDENTIAL')
  // local: loopback direct; anything else through Tor (socks5h), never direct
  assert.equal(t.agentFor('btc', 'btc.s.0', btcd.url), undefined)
  const a = t.agentFor('drand', 'drand.s.0', 'https://api.drand.sh/x')
  assert.ok(a !== undefined)
  assert.deepEqual([a.proxy.type, a.proxy.host, a.proxy.port, a.proxy.userId, a.shouldLookup], [5, '127.0.0.1', 9050, 'drand.s.0', false])   // socks5h
  assert.equal(t.agentFor('check', 'check.s.0', TOR_CHECK)?.proxy.userId, 'check.s.0')
  assert.equal(t.agentFor('btc', 'btc.s.0', 'http://[::1]:18443'), undefined)
  assert.equal(socksTransport('mainnet').agentFor('btc', 'btc.s.0', 'http://127.0.0.1:1') !== undefined, true)   // testnet/mainnet: everything through Tor
  await btcd.close(); await ord.close()
})

test('relayBreadth: the lists are endpoints.json\'s; local drand is the testnet section\'s; VT_TEST_BTC_RPC / VT_TEST_ORD_RPC local and loopback only', { timeout: 30_000 }, async () => {
  assert.deepEqual(relayBreadth('local', {}), { btc: ENDPOINTS.local['btc.bitcoind'], ord: ENDPOINTS.local['btc.ord'], blockscout: {}, arweave: [], drand: ENDPOINTS.testnet.drand })
  for (const n of ['testnet', 'mainnet'] as const) {
    assert.deepEqual(relayBreadth(n, {}), {
      btc: ENDPOINTS[n]['btc.esplora'], ord: [], arweave: ENDPOINTS[n]['arweave.gateway'], drand: ENDPOINTS[n].drand,
      blockscout: { eth: ENDPOINTS[n]['eth.blockscout'], arb: ENDPOINTS[n]['arb.blockscout'], base: ENDPOINTS[n]['base.blockscout'] },
    })
  }
  assert.deepEqual(relayBreadth('local', { VT_TEST_BTC_RPC: 'http://127.0.0.1:28443', VT_TEST_ORD_RPC: 'http://127.0.0.1:28090' }).btc, ['http://127.0.0.1:28443'])
  assert.deepEqual(relayBreadth('local', { VT_TEST_ORD_RPC: 'http://127.0.0.1:28090' }).ord, ['http://127.0.0.1:28090'])
  const fatalOf = (f: () => unknown): { exitCode: number; message: string } => {
    try { f() } catch (e) { return { exitCode: (e as { exitCode?: number }).exitCode ?? -1, message: (e as Error).message } }
    return assert.fail('expected a refusal')
  }
  for (const n of ['testnet', 'mainnet'] as const) {
    for (const k of ['VT_TEST_BTC_RPC', 'VT_TEST_ORD_RPC']) assert.deepEqual(fatalOf(() => relayBreadth(n, { [k]: 'http://127.0.0.1:28443' })), { exitCode: 2, message: `${k} is a local test override — refused with --network ${n}` })
  }
  const off = fatalOf(() => relayBreadth('local', { VT_TEST_BTC_RPC: `http://${CANARY}:18443` }))
  assert.deepEqual(off, { exitCode: 2, message: 'VT_TEST_BTC_RPC must be http://127.0.0.1:<port>' })
})

test('readBitcoindCredential: only $OUT/local/btc-rpc.auth of an explicit absolute VAULT_TIMELOCK_DIR; never a default; the log never holds it', () => {
  const { dir, cleanup } = tempDir('vt-s6-out-')
  try {
    const logs: string[] = []
    const log = (l: string): void => { logs.push(l) }
    assert.equal(readBitcoindCredential(undefined, log), null)
    assert.equal(readBitcoindCredential('relative/out', log), null)
    assert.equal(readBitcoindCredential('', log), null)
    assert.equal(logs.filter((l) => l.includes('VAULT_TIMELOCK_DIR is not an absolute path (it is never defaulted)')).length, 3)
    assert.equal(readBitcoindCredential(dir, log), null)                                  // no file
    mkdirSync(join(dir, 'local'), { mode: 0o700 })
    const f = join(dir, 'local', 'btc-rpc.auth')
    writeFileSync(f, `${AUTH_LINE}\n`, { mode: 0o600 })
    assert.equal(readBitcoindCredential(dir, log), AUTH_LINE)
    chmodSync(f, 0o644)
    assert.equal(readBitcoindCredential(dir, log), null)                                  // readable by others: refused
    chmodSync(f, 0o600)
    writeFileSync(f, 'two words:x\n', { mode: 0o600 })
    assert.equal(readBitcoindCredential(dir, log), null)
    const { dir: other, cleanup: c2 } = tempDir('vt-s6-link-')
    try {
      writeFileSync(join(other, 'real.auth'), `${AUTH_LINE}\n`, { mode: 0o600 })
      mkdirSync(join(other, 'local'))
      symlinkSync(join(other, 'real.auth'), join(other, 'local', 'btc-rpc.auth'))
      assert.equal(readBitcoindCredential(other, log), null)                              // a symlink: refused
    } finally { c2() }
    assert.ok(logs.filter((l) => l.includes('refused config.bitcoind-auth')).length >= 3)
    assert.ok(!hasSecret(logs.join('\n')) && !logs.join('\n').includes(dir))
  } finally { cleanup() }
})

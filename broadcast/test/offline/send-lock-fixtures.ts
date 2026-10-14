// Shared fixtures for net-send-permit.test.ts and send-lock-flip.test.ts (not a test file itself): the send-type
// requests with the class the net layer must give each (C2 review I-1/I-2), the reads that need no permit, and a
// recording test transport. URLs are loopback literals at unused ports: they are strings handed to the test transport,
// never connected to. No key, no signature: RAW_TX is filler bytes.
import type { Transport, TransportRequest, TransportResponse } from '../../src/net/transport.ts'

export const ETH = 'http://127.0.0.1:65001/'
export const SOL = 'http://127.0.0.1:65002/'
const BTCD = 'http://127.0.0.1:65003/wallet/vt'
const ESPLORA = 'http://127.0.0.1:65004/api'
const TURBO = 'http://127.0.0.1:65005'
const GATEWAY = 'http://127.0.0.1:65006'
const ETHERSCAN = 'http://127.0.0.1:65007/v2/api'
const GETH = 'http://127.0.0.1:65008'
const BLOCKBOOK = 'http://127.0.0.1:65009'
export const RAW_TX = '0x02f8' + 'ab'.repeat(40)

const enc = (s: string) => new TextEncoder().encode(s)
const dec = (b: Uint8Array | null) => (b === null ? '' : new TextDecoder().decode(b))
const utf16le = (s: string) => new Uint8Array(Buffer.from(s, 'utf16le'))
const utf16be = (s: string) => { const b = utf16le(s); for (let i = 0; i + 1 < b.length; i += 2) [b[i], b[i + 1]] = [b[i + 1], b[i]]; return b }
const concat = (a: number[], b: Uint8Array) => new Uint8Array([...a, ...b])

export type Init = { method: 'GET' | 'HEAD' | 'POST'; headers?: Record<string, string>; body?: string | Uint8Array }
export type Send = { why: string; url: string; init: Init; cls: 'job' | 'all' }

export const json = (body: unknown): Init => ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
export const rpc = (method: string, params: unknown[] = []) => ({ jsonrpc: '2.0', id: 1, method, params })
const btc = (method: string, params: unknown[] = []) => json({ jsonrpc: '1.0', id: 'vt', method, params })
const post = (body?: string | Uint8Array, contentType?: string): Init =>
  ({ method: 'POST', ...(contentType === undefined ? {} : { headers: { 'content-type': contentType } }), ...(body === undefined ? {} : { body }) })
const SEND_RAW = JSON.stringify(rpc('eth_sendRawTransaction', [RAW_TX]))
const ETHERSCAN_QUERY = `module=proxy&action=eth_sendRawTransaction&hex=${RAW_TX}`

// Every send-type request the brief names (spec B §6.5), the reviewer's probes (C2 review I-2, m4), and the shapes a
// lenient server would still take as a send. `cls` is what the net layer must class it as.
export const SENDS: readonly Send[] = [
  // the job sends (I-1): exactly eth_sendRawTransaction / Solana sendTransaction as JSON-RPC
  { cls: 'job', why: 'eth_sendRawTransaction', url: ETH, init: json(rpc('eth_sendRawTransaction', [RAW_TX])) },
  { cls: 'job', why: 'sendTransaction (Solana)', url: SOL, init: json(rpc('sendTransaction', ['AQID', { encoding: 'base64' }])) },
  { cls: 'job', why: 'batch with one job send among reads', url: ETH, init: json([rpc('eth_chainId'), rpc('eth_sendRawTransaction', [RAW_TX]), rpc('eth_blockNumber')]) },
  { cls: 'job', why: 'batch of two job sends', url: ETH, init: json([rpc('eth_sendRawTransaction', [RAW_TX]), rpc('eth_sendRawTransaction', [RAW_TX])]) },
  { cls: 'job', why: 'method with spacing', url: SOL, init: post('{ "id" : 1 , "method" :\n "sendTransaction" }') },
  { cls: 'job', why: 'byte body', url: SOL, init: post(enc(JSON.stringify(rpc('sendTransaction', ['AQID'])))) },
  // every other send class needs an 'all' permit
  { cls: 'all', why: 'eth_sendTransaction', url: ETH, init: json(rpc('eth_sendTransaction', [{ to: '0x' + '00'.repeat(20) }])) },
  { cls: 'all', why: 'eth_sendRawTransactionSync', url: ETH, init: json(rpc('eth_sendRawTransactionSync', [RAW_TX])) },
  { cls: 'all', why: 'requestAirdrop (Solana)', url: SOL, init: json(rpc('requestAirdrop', ['11111111111111111111111111111111', 1_000_000_000])) },
  { cls: 'all', why: 'requestAirdrop, byte body', url: SOL, init: post(enc(JSON.stringify(rpc('requestAirdrop', ['x', 1])))) },
  { cls: 'all', why: 'sendrawtransaction (bitcoind)', url: BTCD, init: btc('sendrawtransaction', ['00']) },
  { cls: 'all', why: 'sendtoaddress (bitcoind wallet)', url: BTCD, init: btc('sendtoaddress', ['bcrt1q', 1]) },
  { cls: 'all', why: 'sendmany (bitcoind wallet)', url: BTCD, init: btc('sendmany', ['', {}]) },
  { cls: 'all', why: 'submitpackage (bitcoind)', url: BTCD, init: btc('submitpackage', [['00']]) },
  { cls: 'all', why: 'bumpfee (bitcoind wallet)', url: BTCD, init: btc('bumpfee', ['ab']) },
  { cls: 'all', why: 'Esplora POST /tx', url: `${ESPLORA}/tx`, init: post('0200000001', 'text/plain') },
  { cls: 'all', why: 'Esplora POST /txs/package', url: `${ESPLORA}/txs/package`, init: post('["00"]') },
  { cls: 'all', why: 'Esplora POST /tx, percent-encoded', url: `${ESPLORA}/%74x`, init: post('0200000001') },
  { cls: 'all', why: 'Esplora POST /TX', url: `${ESPLORA}/TX`, init: post('0200000001') },
  { cls: 'all', why: 'Esplora POST /tx;v=1 (I-2 probe)', url: `${ESPLORA}/tx;v=1`, init: post('0200000001') },
  { cls: 'all', why: 'Esplora POST /tx with a JSON-RPC job body', url: `${ESPLORA}/tx`, init: post(SEND_RAW) },
  { cls: 'all', why: 'POST /api/v2/transactions (I-2 probe)', url: `${ESPLORA}/v2/transactions`, init: json({ tx: RAW_TX }) },
  { cls: 'all', why: 'Turbo POST /v1/tx', url: `${TURBO}/v1/tx`, init: post(new Uint8Array([1, 2, 3]), 'application/octet-stream') },
  { cls: 'all', why: 'Turbo POST /v1/tx/<token>', url: `${TURBO}/v1/tx/solana`, init: post(new Uint8Array([1])) },
  { cls: 'all', why: 'Arweave POST /tx', url: `${GATEWAY}/tx`, init: json({ format: 2, data_root: '' }) },
  { cls: 'all', why: 'Arweave POST /chunk', url: `${GATEWAY}/chunk`, init: json({ chunk: '' }) },
  { cls: 'all', why: 'POST /pushtx', url: `${ESPLORA}/pushtx`, init: post('tx=00') },
  { cls: 'all', why: 'POST /v1/transactions/submit', url: `${TURBO}/v1/transactions/submit`, init: post('{}') },
  // I-2: the query string, for every method
  { cls: 'all', why: 'Etherscan-style GET ?module=proxy&action=eth_sendRawTransaction', url: `${ETHERSCAN}?chainid=1&${ETHERSCAN_QUERY}`, init: { method: 'GET' } },
  { cls: 'all', why: 'the same as HEAD', url: `${ETHERSCAN}?${ETHERSCAN_QUERY}`, init: { method: 'HEAD' } },
  { cls: 'all', why: 'the same, percent-encoded', url: `${ETHERSCAN}?module=proxy&action=eth_s%65ndRawTransaction&hex=0x02`, init: { method: 'GET' } },
  { cls: 'all', why: 'the same, in a parameter name', url: `${ETHERSCAN}?sendRawTransaction=0x02`, init: { method: 'GET' } },
  { cls: 'all', why: 'the same as a POST query, with a JSON-RPC read body', url: `${ETHERSCAN}?${ETHERSCAN_QUERY}`, init: json(rpc('eth_chainId')) },
  { cls: 'all', why: 'a JSON-RPC job send with a query', url: `${ETH}?x=1`, init: post(SEND_RAW) },
  { cls: 'all', why: 'a GraphQL mutation as a GET query', url: `${GETH}/graphql?query=mutation%7Bx%7D`, init: { method: 'GET' } },
  // I-2: bodies that are not plain JSON-RPC
  { cls: 'all', why: 'form-encoded POST body', url: ETHERSCAN, init: post(ETHERSCAN_QUERY, 'application/x-www-form-urlencoded') },
  { cls: 'all', why: 'GraphQL mutation sendRawTransaction (geth)', url: `${GETH}/graphql`, init: json({ query: `mutation { sendRawTransaction(data: "${RAW_TX}") }` }) },
  { cls: 'all', why: 'GraphQL mutation, other name', url: `${GETH}/graphql`, init: json({ query: 'mutation M { x }' }) },
  { cls: 'all', why: 'GraphQL query naming a send', url: `${GETH}/graphql`, init: json({ query: '{ sendRawTransaction }' }) },
  { cls: 'all', why: 'UTF-16LE JSON-RPC body', url: ETH, init: post(utf16le(SEND_RAW)) },
  { cls: 'all', why: 'UTF-16LE JSON-RPC body with a BOM', url: ETH, init: post(concat([0xff, 0xfe], utf16le(SEND_RAW))) },
  { cls: 'all', why: 'UTF-16BE JSON-RPC body', url: ETH, init: post(utf16be(SEND_RAW)) },
  { cls: 'all', why: 'UTF-16LE JSON-RPC READ body (undecodable as UTF-8 JSON)', url: ETH, init: post(utf16le(JSON.stringify(rpc('eth_chainId')))) },
  { cls: 'all', why: 'UTF-8 BOM before a JSON-RPC body', url: ETH, init: post(`\ufeff${SEND_RAW}`) },
  { cls: 'all', why: 'invalid UTF-8', url: ETH, init: post(new Uint8Array([0x7b, 0xc3, 0x28, 0x7d])) },
  { cls: 'all', why: 'not JSON (trailing garbage)', url: ETH, init: post(`${SEND_RAW} x`) },
  { cls: 'all', why: 'not JSON (raw hex)', url: ETH, init: post(RAW_TX) },
  { cls: 'all', why: 'unknown POST shape (JSON, not JSON-RPC)', url: `${TURBO}/v1/upload`, init: json({ a: 1 }) },
  { cls: 'all', why: 'POST without a body', url: `${TURBO}/v1/anything`, init: post() },
  { cls: 'all', why: 'an empty batch', url: ETH, init: json([]) },
  { cls: 'all', why: 'nested batch', url: ETH, init: json([[rpc('eth_chainId')], [rpc('eth_sendRawTransaction', [RAW_TX])]]) },
  // m4: key spelling, duplicates, nesting
  { cls: 'all', why: 'upper-case key (Go matches keys case-insensitively)', url: ETH, init: json({ jsonrpc: '2.0', id: 1, METHOD: 'eth_sendRawTransaction', params: [RAW_TX] }) },
  { cls: 'all', why: 'escaped upper-case key', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"M\\u0045THOD":"eth_sendRawTransaction","params":[]}') },
  { cls: 'all', why: 'escaped key', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"m\\u0065thod":"eth_sendRawTransaction","params":[]}') },
  { cls: 'all', why: 'escaped key with trailing garbage', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"m\\u0065thod":"eth_sendRawTransaction","params":[]} x') },
  { cls: 'all', why: 'duplicate method keys (last one a read)', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","method":"eth_chainId","params":[]}') },
  { cls: 'all', why: 'duplicate method keys (both job sends)', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","method":"eth_sendRawTransaction","params":[]}') },
  { cls: 'all', why: 'a send hidden in params', url: ETH, init: json(rpc('eth_call', [{ method: 'eth_sendRawTransaction' }])) },
  { cls: 'all', why: 'an escaped send nested in params', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"m\\u0065thod":"eth_s\\u0065ndRawTransaction"}]}') },
  { cls: 'all', why: 'a job send with a nested job method', url: ETH, init: json(rpc('eth_sendRawTransaction', [{ method: 'eth_sendRawTransaction' }])) },
  { cls: 'all', why: 'a job send next to a non-job send in one batch', url: ETH, init: json([rpc('eth_sendRawTransaction', [RAW_TX]), rpc('sendtoaddress', [])]) },
  // N-1 (re-review): keys are compared DECODED; a duplicate key anywhere, or an escaped method key or value, is 'all'
  { cls: 'all', why: 'N-1: escaped send key first, plain read key last', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"m\\u0065thod":"eth_sendRawTransaction","method":"eth_chainId"}') },
  { cls: 'all', why: 'N-1: plain read key first, escaped send key last', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"method":"eth_chainId","m\\u0065thod":"eth_sendRawTransaction"}') },
  { cls: 'all', why: 'N-1: both method keys escaped', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"m\\u0065thod":"eth_sendRawTransaction","m\\u0065thod":"eth_chainId"}') },
  { cls: 'all', why: 'N-1 (job permit): escaped eth_sendTransaction key, plain job key', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"m\\u0065thod":"eth_sendTransaction","method":"eth_sendRawTransaction"}') },
  { cls: 'all', why: 'N-1: an escaped job method value', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"method":"eth_s\\u0065ndRawTransaction","params":[]}') },
  { cls: 'all', why: 'N-1: an escaped read method value', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"method":"eth_ch\\u0061inId"}') },
  { cls: 'all', why: 'N-1: a duplicate non-method key', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"id":2,"method":"eth_chainId"}') },
  { cls: 'all', why: 'N-1: a duplicate key in a nested object', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x00","t\\u006f":"0x01"}]}') },
  { cls: 'all', why: 'N-1: a duplicate key in one batch element', url: ETH, init: post('[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},{"jsonrpc":"2.0","id":2,"method":"eth_chainId","method":"eth_sendRawTransaction"}]') },
  { cls: 'all', why: 'N-1: a read with a nested method key', url: ETH, init: json(rpc('eth_call', [{ method: 'eth_chainId' }])) },
  { cls: 'all', why: 'N-1: a method name outside [A-Za-z0-9_]', url: ETH, init: json(rpc('eth_chainId ')) },
  { cls: 'all', why: 'GraphQL mutation written with an escape', url: `${GETH}/graphql`, init: post('{"query":"m\\u0075tation { x }"}') },
  { cls: 'all', why: 'GraphQL with a duplicate query key', url: `${GETH}/graphql`, init: post('{"query":"{ a }","qu\\u0065ry":"mutation { x }"}') },
  { cls: 'all', why: 'GraphQL send named in operationName', url: `${GETH}/graphql`, init: json({ query: '{ a }', operationName: 'sendIt' }) },
  // C2 m4 (Cfix5): gaps the overlapping detection layers used to hide. Each case below has a plain read `method` that
  // alone would make the request a read: only the case-insensitive key match, the walk into nested objects and arrays,
  // or the JSON-validity check turns it into 'all'. (Blanking any one of them must fail this file.)
  { cls: 'all', why: 'm4: plain read key, then an upper-case METHOD send key', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"method":"eth_chainId","METHOD":"eth_sendRawTransaction","params":[]}') },
  { cls: 'all', why: 'm4: an upper-case METHOD send key, then the plain read key', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"METHOD":"eth_sendRawTransaction","method":"eth_chainId","params":[]}') },
  { cls: 'all', why: 'm4: mixed-case Method send key next to a plain job key', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","Method":"eth_sendTransaction","params":[]}') },
  { cls: 'all', why: 'm4: second batch element carries a METHOD key next to its plain method', url: ETH, init: post('[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},{"jsonrpc":"2.0","id":2,"method":"eth_chainId","METHOD":"eth_sendRawTransaction"}]') },
  { cls: 'all', why: 'm4: escaped upper-case key (M\\u0045THOD) nested in params', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"M\\u0045THOD":"eth_sendRawTransaction"}]}') },
  { cls: 'all', why: 'm4: plain nested method key two arrays and two objects deep', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[[{"a":{"method":"eth_sendRawTransaction"}}]]}') },
  { cls: 'all', why: 'm4: a nested method key inside the second batch element only', url: ETH, init: post('[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},{"jsonrpc":"2.0","id":2,"method":"eth_call","params":[{"method":"eth_sendRawTransaction"}]}]') },
  { cls: 'all', why: 'm4: a plain job send, then trailing garbage (not valid JSON)', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[]} x') },
  { cls: 'all', why: 'm4: a plain read, then a second JSON value (not valid JSON)', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}{"jsonrpc":"2.0","id":2,"method":"eth_sendRawTransaction"}') },
  { cls: 'all', why: 'm4: an upper-case key send followed by trailing garbage', url: ETH, init: post('{"jsonrpc":"2.0","id":1,"METHOD":"eth_sendRawTransaction"} x') },
  // N-2 (re-review): a send in the PATH counts for every method, GET and HEAD included
  { cls: 'all', why: 'N-2: Blockbook GET /api/v2/sendtx/<hex>', url: `${BLOCKBOOK}/api/v2/sendtx/${'ab'.repeat(40)}`, init: { method: 'GET' } },
  { cls: 'all', why: 'N-2: GET /broadcast/<hex>', url: `${BLOCKBOOK}/broadcast/${'ab'.repeat(40)}`, init: { method: 'GET' } },
  { cls: 'all', why: 'N-2: GET /pushtx', url: `${BLOCKBOOK}/pushtx`, init: { method: 'GET' } },
  { cls: 'all', why: 'N-2: GET /api/tx/push', url: `${BLOCKBOOK}/api/tx/push`, init: { method: 'GET' } },
  { cls: 'all', why: 'N-2: GET /push/transaction/<hex>', url: `${BLOCKBOOK}/push/transaction/${'ab'.repeat(40)}`, init: { method: 'GET' } },
  { cls: 'all', why: 'N-2: HEAD /api/v2/sendtx/<hex>', url: `${BLOCKBOOK}/api/v2/sendtx/${'ab'.repeat(40)}`, init: { method: 'HEAD' } },
  { cls: 'all', why: 'N-2: GET, percent-encoded /%73endtx', url: `${BLOCKBOOK}/api/v2/%73endtx/00`, init: { method: 'GET' } },
  { cls: 'all', why: 'N-2: GET, upper case /API/V2/SENDTX', url: `${BLOCKBOOK}/API/V2/SENDTX/00`, init: { method: 'GET' } },
  { cls: 'all', why: 'N-2: GET /sendrawtransaction/<hex>', url: `${BLOCKBOOK}/sendrawtransaction/00`, init: { method: 'GET' } },
  { cls: 'all', why: 'N-2: GET /submit/<hex>', url: `${BLOCKBOOK}/submit/00`, init: { method: 'GET' } },
  { cls: 'all', why: 'N-2: GET /push;v=1/<hex>', url: `${BLOCKBOOK}/push;v=1/00`, init: { method: 'GET' } },
  { cls: 'all', why: 'N-2: GET /pushTransaction', url: `${BLOCKBOOK}/pushTransaction?tx=00`, init: { method: 'GET' } },
]
export const NON_JOB_SENDS: readonly Send[] = SENDS.filter((s) => s.cls === 'all')

// Reads: no permit needed, and a job permit does not change them.
export const READS: ReadonlyArray<{ why: string; url: string; init?: Init }> = [
  { why: 'JSON-RPC read batch', url: ETH, init: json([rpc('eth_chainId'), rpc('eth_getBalance', ['0x' + '00'.repeat(20), 'latest'])]) },
  { why: 'bitcoind read', url: BTCD, init: btc('getblockhash', [0]) },
  { why: 'GET Esplora tx', url: `${ESPLORA}/tx/${'ab'.repeat(32)}/hex` },
  { why: 'GET Esplora block 0', url: `${ESPLORA}/block-height/0` },
  { why: 'HEAD', url: `${GATEWAY}/info`, init: { method: 'HEAD' } },
  { why: 'GET with a harmless query', url: `${ESPLORA}/address/x/txs/chain?after_txid=${'ab'.repeat(32)}` },
  { why: 'GraphQL query', url: `${GATEWAY}/graphql`, init: json({ query: '{ transactions(first: 1) { edges { node { id } } } }' }) },
]

// Answers a single JSON-RPC request with its own id (so jsonRpc accepts it), anything else with {}.
export function answer(req: TransportRequest): TransportResponse {
  let id: unknown = null
  try { id = (JSON.parse(dec(req.body)) as { id?: unknown }).id ?? null } catch { /* not JSON-RPC */ }
  const body = id === null ? '{}' : JSON.stringify({ jsonrpc: '2.0', id, result: '0x1' })
  return { status: 200, headers: { 'content-type': 'application/json' }, body: enc(body) }
}
export function recorder() {
  const calls: TransportRequest[] = []
  const t: Transport = async (req) => { calls.push(req); return answer(req) }
  return Object.assign(t, { calls })
}

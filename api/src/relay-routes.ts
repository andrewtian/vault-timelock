// api/src/relay-routes.ts — the relay's breadth routes (S6, M4; canonical spec §6.1 change 8): read-only routes for BTC
// (the local bitcoind and ord; testnet4 / mainnet Esplora), the Blockscout provenance reads (D2a), the Arweave tags of an
// ar id (D3's ar-id check) and drand quicknet (D6 Open). In TypeScript so the mutation runner covers every guard; the
// ported relay (api/relay/relay.mjs) calls them on every breadth request and answer.
//
//   resolveRest(network, httpMethod, rawPath)  every request under /relay/{btc,blockscout,arweave,drand}/: GET only
//       (relay.method), and the RAW request path (relay.path) is exactly one route of this network's table, matched whole
//       by an anchored pattern over a restricted alphabet: no percent-encoding, no dot segment, no empty segment, no
//       query (Blockscout's exact `?filter=to` aside), no fragment, no other network's address. The upstream path is
//       that matched text itself, below the endpoint's base, and nothing else.
//   checkAnswer(route, status, body)  every upstream answer, before a byte goes back (relay.upstream-shape): a JSON route
//       returns the upstream bytes only when they parse as JSON; a text route (a height, a block hash, a tx's hex)
//       returns only exactly that text; drand info returns the PINNED quicknet chain info, and only when the upstream's
//       equals it exactly (the sealer's rule: 1password-timelock.sh chain_info); a drand beacon and the ar-id tags are
//       re-serialized from their checked fields, so the client never parses a byte nobody checked. Content types are
//       the relay's own (application/json or text/plain), never the upstream's: an upstream cannot make the page's
//       origin serve HTML. 404 (and drand's 425 "too early") pass as the relay's own 404; any other status is a 502.
//   checkBtcParams(method, params)  the local bitcoind's scantxoutset: 'start' with addr() descriptors only
//       (relay.btc-params).
//   assertNoSecret(body, secrets)  every bitcoind and local ord answer: an answer that ECHOES the credential the relay added
//       (raw, base64 of the header or of the password, hex of the password, JSON-escaped or \u-escaped) is withheld
//       (relay.upstream-secret). That covers what bitcoind itself can emit; an adversarial upstream can encode it in other
//       ways, which no filter stops, so the credential is also long (MIN_CREDENTIAL_PASS) and local only.
//   rpcShape(body)  a /relay/btc JSON-RPC answer: strict UTF-8 JSON, else relay.upstream-shape (S6 review m6).
//   serviceIdentity(...)  the identity of a breadth service's endpoint (relay.service-identity): ord's block 0 is the
//       regtest genesis; Blockscout's eth_chainId (its /api/eth-rpc, the sibling of the /api/v2 base) is the network's
//       chain id for eth / arb / base (config.ts identityMatches, one source); an Arweave gateway's /info network is
//       arweave.N.1; drand's /<quicknet>/info is the pinned chain info exactly. BTC (bitcoind / Esplora) is a chain:
//       relay.mjs checks block 0 with identityMatches at startup, as eth and sol (a mismatch is fatal there).
// Messages never echo a path, a param, an address or an upstream value.
import { createHash } from 'node:crypto'
import type { Network } from '@vault-timelock/core/contracts'
import { identityMatches } from 'vt-broadcast/src/config.ts'
import { QUICKNET } from 'vt-broadcast/src/drand.ts'
import { refuse } from 'vt-broadcast/src/guard.ts'
import { methodOk } from './relay-gate.ts'

export type Service = 'esplora' | 'ord' | 'blockscout' | 'arweave' | 'drand'
export type EvmChain = 'eth' | 'arb' | 'base'
export const EVM_CHAINS: readonly EvmChain[] = Object.freeze(['eth', 'arb', 'base'])
export type AnswerKind = 'json' | 'height' | 'hash' | 'hex' | 'drand-info' | 'drand-beacon' | 'ar-tags'

export interface RestRoute {
  readonly service: Service
  readonly sub: EvmChain | null            // Blockscout's chain
  readonly name: string                    // `<service>:<pattern>` for the log line: never a value from the request
  readonly path: string                    // the upstream path below the endpoint's base: the matched request text
  readonly kind: AnswerKind
  readonly round: number | null            // drand public/<round>
  readonly arId: string | null             // arweave tags/<ar id>
}
export interface Answer { readonly status: number; readonly contentType: string; readonly body: Buffer }

// The services each network serves (anything else is relay.path). Local: the regtest ord beside the local bitcoind, and
// drand (D-R15: the testnet section's endpoints, through Tor). Testnet4 / mainnet: Esplora, Blockscout, Arweave, drand.
export const SERVICES: Readonly<Record<Network, readonly Service[]>> = Object.freeze({
  local: Object.freeze(['ord', 'drand'] as const),
  testnet: Object.freeze(['esplora', 'blockscout', 'arweave', 'drand'] as const),
  mainnet: Object.freeze(['esplora', 'blockscout', 'arweave', 'drand'] as const),
})

export const JSON_TYPE = 'application/json'
export const TEXT_TYPE = 'text/plain; charset=utf-8'
export const ARWEAVE_NETWORK = 'arweave.N.1'

// drand quicknet's chain info, pinned exactly as the sealer pins it (1password-timelock.sh INFO_PINNED: the same seven
// keys, nothing else); its canonical bytes (keys sorted, as jq -cS) are what /relay/drand/<hash>/info serves.
export const QUICKNET_INFO = Object.freeze({
  genesis_time: QUICKNET.genesis,
  groupHash: 'f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e',
  hash: QUICKNET.hash,
  metadata: Object.freeze({ beaconID: 'quicknet' }),
  period: QUICKNET.period,
  public_key: '83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a',
  schemeID: QUICKNET.schemeID,
})
export const QUICKNET_INFO_BYTES: Buffer = Buffer.from(JSON.stringify(QUICKNET_INFO))

// The ar-id lookup: a fixed GraphQL query, the id passed as a variable (never spliced into the query text).
export const AR_TAGS_QUERY = 'query($ids:[ID!]){transactions(ids:$ids){edges{node{id tags{name value}}}}}'
const AR_ID = /^[A-Za-z0-9_-]{43}$/
const MAX_TAGS = 128
const MAX_TAG_TEXT = 3072

// ---- the route tables

type Rule = readonly [pattern: string, kind: AnswerKind]
const ESPLORA: readonly Rule[] = [
  ['blocks/tip/height', 'height'], ['blocks/tip/hash', 'hash'], ['block-height/:n', 'hash'], ['block/:hash', 'json'], ['block/:hash/status', 'json'],
  ['address/:addr', 'json'], ['address/:addr/utxo', 'json'], ['address/:addr/txs', 'json'], ['address/:addr/txs/mempool', 'json'],
  ['address/:addr/txs/chain/:txid', 'json'],
  ['tx/:txid', 'json'], ['tx/:txid/status', 'json'], ['tx/:txid/hex', 'hex'], ['tx/:txid/outspend/:n', 'json'],
  ['fee-estimates', 'json'], ['v1/fees/recommended', 'json'],
]
// ord (local, its JSON API; the transport asks for application/json). Never /content/<id>: an inscription's body is any
// bytes under any content type. The engine reads an inscription back from the reveal's witness (bitcoind
// getrawtransaction), not from ord.
const ORD: readonly Rule[] = [
  ['status', 'json'], ['r/blockheight', 'height'], ['r/blockhash/:n', 'json'],
  ['tx/:txid', 'json'], ['output/:txid::n', 'json'], ['inscription/:txidi:n', 'json'],
]
// Blockscout v2 (D2a, B §6.2 eth row): the inbound transfers to an address (one page: more is refused by the checker,
// never partially checked) and the parent tx of an internal transfer.
const BLOCKSCOUT: readonly Rule[] = [
  ['addresses/:evm/transactions?filter=to', 'json'], ['addresses/:evm/internal-transactions?filter=to', 'json'], ['transactions/:evmtx', 'json'],
]

// A network's own address forms only (lower-case bech32/bech32m, or base58 P2PKH/P2SH): another network's address is
// not on the list, so it never leaves the machine through this network's circuits.
const BTC_ADDRESS: Readonly<Record<'testnet' | 'mainnet', string>> = {
  mainnet: '(?:bc1[02-9ac-hj-np-z]{8,87}|[13][1-9A-HJ-NP-Za-km-z]{25,34})',
  testnet: '(?:tb1[02-9ac-hj-np-z]{8,87}|[mn2][1-9A-HJ-NP-Za-km-z]{25,34})',
}
const TOKENS: Readonly<Record<string, string>> = {
  ':txid': '[0-9a-f]{64}', ':hash': '[0-9a-f]{64}', ':n': '(?:0|[1-9][0-9]{0,8})', ':evmtx': '0x[0-9a-f]{64}', ':evm': '0x[0-9a-fA-F]{40}',
}
const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')
interface Compiled { readonly re: RegExp; readonly name: string; readonly kind: AnswerKind }
function compile(prefix: string, rules: readonly Rule[], addr: string): readonly Compiled[] {
  return Object.freeze(rules.map(([p, kind]) => {
    const src = p.split(/(:addr|:txid|:hash|:evmtx|:evm|:n)/).map((x, i) => (i % 2 === 1 ? (x === ':addr' ? addr : TOKENS[x]) : esc(x))).join('')
    return Object.freeze({ re: new RegExp(`^${src}$`), name: `${prefix}:${p}`, kind })
  }))
}
const ESPLORA_TABLE: Readonly<Record<'testnet' | 'mainnet', readonly Compiled[]>> = {
  testnet: compile('esplora', ESPLORA, BTC_ADDRESS.testnet), mainnet: compile('esplora', ESPLORA, BTC_ADDRESS.mainnet),
}
const ORD_TABLE = compile('ord', ORD, '')
const BLOCKSCOUT_TABLE = compile('blockscout', BLOCKSCOUT, '')

const BREADTH = /^\/relay\/(btc|blockscout|arweave|drand)\//
export const isBreadthPath = (path: string): boolean => BREADTH.test(path)
// The log tag of a breadth path ('btc' for Esplora and ord), or null.
export const breadthTag = (path: string): string | null => BREADTH.exec(path)?.[1] ?? null

function pick(service: Service, sub: EvmChain | null, table: readonly Compiled[], rest: string): RestRoute | null {
  const rule = table.find((c) => c.re.test(rest))
  if (rule === undefined) return null
  return { service, sub, name: sub === null ? rule.name : rule.name.replace('blockscout:', `blockscout.${sub}:`), path: rest, kind: rule.kind, round: null, arId: null }
}

function matchRest(network: Network, raw: string): RestRoute | null {
  if (raw.length > 512) return null
  const on = (s: Service): boolean => SERVICES[network].includes(s)
  let m = /^\/relay\/btc\/(esplora|ord)\/(.+)$/s.exec(raw)
  if (m !== null) {
    if (m[1] === 'esplora') return on('esplora') && network !== 'local' ? pick('esplora', null, ESPLORA_TABLE[network], m[2]) : null
    return on('ord') ? pick('ord', null, ORD_TABLE, m[2]) : null
  }
  m = /^\/relay\/blockscout\/(eth|arb|base)\/(.+)$/s.exec(raw)
  if (m !== null) return on('blockscout') ? pick('blockscout', m[1] as EvmChain, BLOCKSCOUT_TABLE, m[2]) : null
  m = /^\/relay\/arweave\/tags\/([A-Za-z0-9_-]{43})$/.exec(raw)
  if (m !== null) return on('arweave') ? { service: 'arweave', sub: null, name: 'arweave:tags/:arid', path: 'graphql', kind: 'ar-tags', round: null, arId: m[1] } : null
  m = /^\/relay\/drand\/([0-9a-f]{64})\/(info|public\/latest|public\/([1-9][0-9]{0,15}))$/.exec(raw)
  if (m !== null) {
    const round = m[3] === undefined ? null : Number(m[3])
    const ok = on('drand') && m[1] === QUICKNET.hash && (round === null || Number.isSafeInteger(round))
    return ok ? { service: 'drand', sub: null, name: `drand:${round === null ? m[2] : 'public/:round'}`, path: `${m[1]}/${m[2]}`, kind: m[2] === 'info' ? 'drand-info' : 'drand-beacon', round, arId: null } : null
  }
  return null
}

// THE relay.path line (one marker): a path under /relay that is not on this network's list.
export function pathOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.path', "this path is not on the relay's list for this network (the breadth routes take exact patterns: no query, no encoding, no other network's address or drand chain)") // @guard:relay.path
}

// A breadth request: GET only (relay.method), then exactly one route of this network's table (relay.path).
export function resolveRest(network: Network, httpMethod: string, raw: string): RestRoute {
  methodOk(httpMethod === 'GET')
  const r = matchRest(network, raw)
  pathOk(r !== null)
  return r
}

// A request matching no route of the relay at all: a known path asked with the wrong HTTP method is relay.method,
// anything else relay.path. `known` = the path is one of the relay's routes.
export function refuseRoute(known: boolean): void {
  methodOk(!known)
  pathOk(false)
}

// The upstream request of a route at one endpoint base (endpoints.json, no trailing slash).
export function upstreamRequest(r: RestRoute, base: string): { url: string; method: 'GET' | 'POST'; body: Buffer | null } {
  const b = base.replace(/\/+$/, '')
  if (r.service === 'arweave') return { url: `${b}/graphql`, method: 'POST', body: arTagsBody(r.arId ?? '') }
  return { url: `${b}/${r.path}`, method: 'GET', body: null }
}
export function arTagsBody(arId: string): Buffer {
  pathOk(AR_ID.test(arId))
  return Buffer.from(JSON.stringify({ query: AR_TAGS_QUERY, variables: { ids: [arId] } }))
}

// ---- answers

const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })   // a BOM stays, so it is not JSON
function text(body: Buffer): string | null {
  try { return UTF8.decode(body) } catch { return null }
}
function parse(body: Buffer): unknown {
  const t = text(body)
  if (t === null) return undefined
  try { return JSON.parse(t) as unknown } catch { return undefined }
}
const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype

// JSON values equal exactly: the same keys (no more, no fewer), the same primitives.
export function sameJson(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) || Array.isArray(b)) return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => sameJson(x, b[i]))
  if (isPlainObject(a) || isPlainObject(b)) {
    if (!isPlainObject(a) || !isPlainObject(b)) return false
    const ka = Object.keys(a).sort(), kb = Object.keys(b).sort()
    return ka.length === kb.length && ka.every((k, i) => k === kb[i] && sameJson(a[k], b[k]))
  }
  return a === b
}

const TEXT_KINDS: Readonly<Partial<Record<AnswerKind, RegExp>>> = {
  height: /^(?:0|[1-9][0-9]{0,9})$/, hash: /^[0-9a-f]{64}$/, hex: /^(?:[0-9a-f]{2})+$/,
}
const json = (v: unknown): Buffer => Buffer.from(JSON.stringify(v))
const errorBody = (message: string): Buffer => json({ error: { message } })

// A text answer as Esplora and ord send it: the value, optionally one trailing newline.
export function textValue(body: Buffer, kind: 'height' | 'hash' | 'hex'): string | null {
  const t = text(body)
  const v = t === null ? null : t.endsWith('\n') ? t.slice(0, -1) : t
  return v !== null && TEXT_KINDS[kind]!.test(v) ? v : null
}

function beacon(v: unknown, want: number | null): Buffer | null {
  if (!isPlainObject(v) || !sameJson(Object.keys(v).sort(), ['randomness', 'round', 'signature'])) return null
  const { round, randomness, signature } = v
  const ok = typeof round === 'number' && Number.isSafeInteger(round) && round >= 1 && (want === null || round === want)
    && typeof signature === 'string' && /^[0-9a-f]{96}$/.test(signature)
    && typeof randomness === 'string' && randomness === createHash('sha256').update(Buffer.from(signature, 'hex')).digest('hex')
  return ok ? json({ round, randomness, signature }) : null
}

function arTags(v: unknown, arId: string): Buffer | null {
  if (!isPlainObject(v) || v.errors !== undefined || !isPlainObject(v.data) || !isPlainObject(v.data.transactions)) return null
  const edges = v.data.transactions.edges
  if (!Array.isArray(edges) || edges.length > 1) return null
  if (edges.length === 0) return json({ id: arId, found: false, tags: [] })
  const node: unknown = isPlainObject(edges[0]) ? edges[0].node : undefined
  if (!isPlainObject(node) || node.id !== arId || !Array.isArray(node.tags) || node.tags.length > MAX_TAGS) return null
  const tags: Array<{ name: string; value: string }> = []
  for (const t of node.tags as unknown[]) {
    const ok = isPlainObject(t) && typeof t.name === 'string' && typeof t.value === 'string' && t.name.length <= MAX_TAG_TEXT && t.value.length <= MAX_TAG_TEXT
    if (!ok) return null
    tags.push({ name: t.name as string, value: t.value as string })
  }
  return json({ id: arId, found: true, tags })
}

function shape(r: RestRoute, body: Buffer): Answer | null {
  const ok = (b: Buffer | null, contentType = JSON_TYPE): Answer | null => (b === null ? null : { status: 200, contentType, body: b })
  switch (r.kind) {
    case 'json': return parse(body) === undefined ? null : ok(body)
    case 'height': case 'hash': case 'hex': { const v = textValue(body, r.kind); return v === null ? null : ok(Buffer.from(v), TEXT_TYPE) }
    case 'drand-info': return sameJson(parse(body), QUICKNET_INFO) ? ok(QUICKNET_INFO_BYTES) : null
    case 'drand-beacon': return ok(beacon(parse(body), r.round))
    case 'ar-tags': return ok(arTags(parse(body), r.arId ?? ''))
  }
}

// THE relay.upstream-shape line (one marker).
function shapeOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.upstream-shape', 'the upstream answer is not what this route returns (JSON; a height, block hash or tx hex; the pinned drand chain info; a drand beacon of this round; an ar id\'s tags): nothing of it was passed on') // @guard:relay.upstream-shape
}

// What goes back for an upstream answer: 200 only in the route's own shape; 404 (drand: also 425, "too early") as the
// relay's own 404; anything else a 502. Never the upstream's text or content type.
export function checkAnswer(r: RestRoute, status: number, body: Buffer): Answer {
  const notYet = r.kind === 'drand-beacon' && (status === 404 || status === 425)
  if (notYet) return { status: 404, contentType: JSON_TYPE, body: errorBody('this drand round is not published yet') }
  if (status === 404 && r.kind !== 'drand-info') return { status: 404, contentType: JSON_TYPE, body: errorBody('not found upstream (HTTP 404)') }
  if (status !== 200) return { status: 502, contentType: JSON_TYPE, body: errorBody(`upstream HTTP ${Number.isSafeInteger(status) ? status : 0}`) }
  const a = shape(r, body)
  shapeOk(a !== null)
  return a
}

// ---- the local bitcoind

const REGTEST_ADDRESS = /^addr\((?:bcrt1[02-9ac-hj-np-z]{8,87}|[mn2][1-9A-HJ-NP-Za-km-z]{25,34})\)$/
const descOk = (d: unknown): boolean =>
  typeof d === 'string' ? REGTEST_ADDRESS.test(d) : isPlainObject(d) && Object.keys(d).length === 1 && typeof d.desc === 'string' && REGTEST_ADDRESS.test(d.desc)
function scanOk(params: unknown): boolean {
  if (!Array.isArray(params) || params.length !== 2 || params[0] !== 'start' || !Array.isArray(params[1])) return false
  const d = params[1] as unknown[]
  return d.length >= 1 && d.length <= 16 && d.every(descOk)
}
export function checkBtcParams(method: string, params: unknown): void {
  const ok = method !== 'scantxoutset' || scanOk(params)
  if (!ok) refuse('relay.btc-params', "scantxoutset takes exactly ['start', [addr(<regtest address>), …]] (1–16 descriptors; no other action, no key or ranged descriptor)") // @guard:relay.btc-params
}

// The answer of a BTC send's upstream (S6b): the txid and nothing else. bitcoind answers { result: <txid> }, Esplora the txid as
// text; either must be exactly the txid the relay computed from the ticketed bytes (checkSend's decode: t), so no upstream
// text, error or other id is ever passed on (relay.upstream-shape). A JSON-RPC 2.0 success from bitcoind has no `error` member
// (Bitcoin Core 28+ for a "jsonrpc":"2.0" request), a 1.0 one has `error: null`; any other error value is no success.
export function btcSendTxid(source: 'bitcoind' | 'esplora', body: Buffer, txid: string): string {
  const p = source === 'bitcoind' ? parse(body) : undefined
  const got = source === 'bitcoind' ? (isPlainObject(p) && (p.error === null || p.error === undefined) ? p.result : undefined) : textValue(body, 'hash')
  shapeOk(typeof got === 'string' && got === txid)
  return got
}

// The prevout of an Esplora `GET /tx/<txid>/hex` answer (S6b review m-2), committed by the txid itself: the raw transaction is
// parsed here, its NON-witness serialization is hashed twice with SHA-256 and byte-reversed, and that must equal the txid the
// relay asked for. Only then is output `vout` read from those verified bytes, so a lying Esplora cannot make the relay see
// another value or script for an input. Anything malformed, trailing, or of another txid is null (relay.btc-prevout fails closed).
// Spentness is the node's job, as before.
const TX_MAX_BYTES = 4_000_000
const MAX_SATS = 21_000_000n * 100_000_000n
const sha256d = (b: Uint8Array): Buffer => createHash('sha256').update(createHash('sha256').update(b).digest()).digest()
export function esploraPrevout(hex: string, txid: string, vout: number): { value: bigint; script: Uint8Array } | null {
  if (!/^(?:[0-9a-f]{2})+$/.test(hex) || hex.length > 2 * TX_MAX_BYTES || !/^[0-9a-f]{64}$/.test(txid) || !Number.isSafeInteger(vout) || vout < 0) return null
  const raw = Buffer.from(hex, 'hex')
  let at = 0
  const take = (n: number): number => { if (n < 0 || at + n > raw.length) throw new RangeError('short'); at += n; return at - n }
  const varint = (): number => {
    const b = raw[take(1)]
    if (b < 0xfd) return b
    const w = b === 0xfd ? 2 : b === 0xfe ? 4 : 8
    const o = take(w)
    const v = w === 2 ? raw.readUInt16LE(o) : w === 4 ? raw.readUInt32LE(o) : Number(raw.readBigUInt64LE(o))
    if (!Number.isSafeInteger(v) || v > TX_MAX_BYTES || v < (w === 2 ? 0xfd : w === 4 ? 0x10000 : 0x100000000)) throw new RangeError('varint')   // too large or not minimal
    return v
  }
  try {
    take(4)                                                  // version
    const segwit = raw[at] === 0                             // the marker (no real transaction has zero inputs)
    if (segwit) { if (raw[take(2) + 1] !== 1) return null }  // marker 00, flag 01 only
    const bodyStart = at
    const nIn = varint()
    if (nIn < 1) return null
    for (let i = 0; i < nIn; i++) { take(36); take(varint()); take(4) }
    const nOut = varint()
    if (nOut < 1 || vout >= nOut) return null
    let found: { value: bigint; script: Uint8Array } | null = null
    for (let i = 0; i < nOut; i++) {
      const value = raw.readBigUInt64LE(take(8))
      const len = varint()
      const o = take(len)
      if (value > MAX_SATS) return null
      if (i === vout) found = { value, script: Uint8Array.from(raw.subarray(o, o + len)) }
    }
    const bodyEnd = at
    if (segwit) for (let i = 0; i < nIn; i++) { const items = varint(); for (let k = 0; k < items; k++) take(varint()) }
    const lockTime = take(4)
    if (at !== raw.length) return null                       // trailing bytes
    const stripped = Buffer.concat([raw.subarray(0, 4), raw.subarray(bodyStart, bodyEnd), raw.subarray(lockTime, lockTime + 4)])
    return Buffer.from(sha256d(stripped)).reverse().toString('hex') === txid ? found : null
  } catch { return null }
}

// The Authorization header for the local bitcoind, from the <user>:<pass> line (loadBitcoindAuth).
export const bitcoindAuthHeader = (line: string): string => `Basic ${Buffer.from(line, 'utf8').toString('base64')}`
// The shortest bitcoind password the relay accepts (S6 review m2): a short one could not be scanned for, and bitcoind echoes
// bad input in its errors, so the 502 would tell a page whether a guess equals it. readBitcoindCredential refuses less.
export const MIN_CREDENTIAL_PASS = 16
export const credentialPass = (line: string): string => line.slice(line.indexOf(':') + 1)
export const credentialLongEnough = (line: string): boolean => credentialPass(line).length >= MIN_CREDENTIAL_PASS

// What must never come back from bitcoind (or ord): the line, its base64 (the header), and the password alone as raw text, as
// a JSON string, as hex and as base64 (S6 review m1). The bare password is always a needle: the relay accepts no short one.
export function bitcoindSecrets(line: string): string[] {
  const pass = credentialPass(line)
  const b = Buffer.from(pass, 'utf8')
  const out = [line, Buffer.from(line, 'utf8').toString('base64')]
  if (pass.length > 0) out.push(pass, JSON.stringify(pass).slice(1, -1), b.toString('hex'), b.toString('base64').replace(/=+$/, ''))
  return out
}
// The strings a JSON answer holds once decoded (every key and string value): a `\uXXXX`-escaped credential is plain here.
function decodedStrings(v: unknown, out: string[], depth = 0): string[] {
  if (typeof v === 'string') out.push(v)
  else if (depth < 64 && Array.isArray(v)) for (const x of v) decodedStrings(x, out, depth + 1)
  else if (depth < 64 && typeof v === 'object' && v !== null) for (const [k, x] of Object.entries(v)) { out.push(k); decodedStrings(x, out, depth + 1) }
  return out
}
export function assertNoSecret(body: Buffer, secrets: readonly string[]): void {
  const t = body.toString('utf8')
  let hay = [t]
  try { hay = [t, ...decodedStrings(JSON.parse(t) as unknown, [])] } catch { /* not JSON: the raw text is scanned */ }
  const clean = secrets.every((s) => s.length === 0 || hay.every((h) => !h.includes(s)))
  if (!clean) refuse('relay.upstream-secret', 'the upstream answer carries the credential the relay sent it: nothing of it was passed on') // @guard:relay.upstream-secret
}

// The answer of the /relay/btc JSON-RPC route (S6 review m6): bytes that are not strict UTF-8 JSON are no answer
// (relay.upstream-shape); a JSON answer is passed on as received, with the relay's own content type.
export function rpcShape(body: Buffer): void {
  shapeOk(parse(body) !== undefined)
}

// ---- the identity of a breadth service's endpoint

export type ProbeService = 'ord' | 'blockscout' | 'arweave' | 'drand'
export interface Probe { readonly url: string; readonly method: 'GET' | 'POST'; readonly body: Buffer | null }

// The identity request of one endpoint base, or null when the base has no identity endpoint (Blockscout: the base must be
// the instance's /api/v2; its /api/eth-rpc answers eth_chainId).
export function identityProbe(service: ProbeService, base: string): Probe | null {
  const b = base.replace(/\/+$/, '')
  switch (service) {
    case 'ord': return { url: `${b}/r/blockhash/0`, method: 'GET', body: null }
    case 'blockscout': return b.endsWith('/api/v2') ? { url: `${b.slice(0, -'v2'.length)}eth-rpc`, method: 'POST', body: json({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }) } : null
    case 'arweave': return { url: `${b}/info`, method: 'GET', body: null }
    case 'drand': return { url: `${b}/${QUICKNET.hash}/info`, method: 'GET', body: null }
  }
}

// THE relay.service-identity line (one marker): an endpoint that answers, definitively, another identity.
function identityOk(ok: boolean): void {
  if (!ok) refuse('relay.service-identity', "the endpoint answered another network's identity (ord: block 0; Blockscout: eth_chainId; Arweave: the network; drand: the chain info): the service is disabled") // @guard:relay.service-identity
}

// true: this endpoint is the network's (verified); false: no definitive answer (unreachable, refused, an error, not
// JSON: it is not used, and may be checked again later); a definitive wrong answer refuses relay.service-identity.
export function serviceIdentity(network: Network, service: ProbeService, sub: EvmChain | null, status: number, body: Buffer): boolean {
  if (status !== 200) return false
  const v = parse(body)
  switch (service) {
    case 'ord': {
      if (typeof v !== 'string') return false
      identityOk(network === 'local' && identityMatches('local', 'btc', v))
      return true
    }
    case 'blockscout': {
      const id = isPlainObject(v) && typeof v.result === 'string' ? v.result : null
      if (id === null || sub === null) return false
      identityOk(identityMatches(network, sub, id))
      return true
    }
    case 'arweave': {
      const n = isPlainObject(v) && typeof v.network === 'string' ? v.network : null
      if (n === null) return false
      identityOk(n === ARWEAVE_NETWORK)
      return true
    }
    case 'drand': {
      if (!isPlainObject(v)) return false
      identityOk(sameJson(v, QUICKNET_INFO))
      return true
    }
  }
}

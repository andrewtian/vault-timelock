// api/src/privacycash.ts — the relay's Privacy Cash proxy gates (S7, M4; plan Task S7), in TypeScript so the mutation runner
// covers every guard. The glue is api/relay/privacycash.mjs; relay.mjs only hands it the requests under /relay/privacycash.
//
// What is forwarded (research-privacycash.md D3/D4): the 6 relayer routes of the SDK's SOL path and ONE Solana JSON-RPC
// method, nothing else. Everything below is exact: the raw request path (and query) is matched whole by an anchored
// pattern over a restricted alphabet: no percent-encoding, no dot segment, no extra query key, no fragment.
//   GET  relayer/config                         no query                                       resp ≤ 64 KB
//   GET  relayer/utxos/range?start=S&end=E      end − start = 20000                            resp ≤ 12 MB
//   POST relayer/utxos/indices                  {encrypted_outputs: 1–750 × hex}      req ≤ 256 KB resp ≤ 64 KB
//   GET  relayer/merkle/proofv2/?commitments=a,b  two decimal field elements                    resp ≤ 64 KB
//   POST relayer/withdraw                       the 15 keys of the SDK, no referralId  req ≤ 8 KB resp ≤ 4 KB   ★ A SEND
//   GET  relayer/utxos/check/<hex>              no query                                       resp ≤ 4 KB
//   POST rpc                                    one JSON-RPC 2.0 getMultipleAccounts (≤ 100 keys)  req ≤ 64 KB resp ≤ 2 MB
//   GET  artifacts/transaction2.{wasm,zkey}     served LOCALLY from the vendored files, sha256-pinned (never upstream)
// Anything else (/deposit*, /withdraw/spl, /merkle/root, ?token=, other RPC methods, batches) is relay.path or relay.method.
//
// The withdrawal is FUNDING, a MAINNET send whatever stack carries it (Privacy Cash has no devnet; the relayer host is
// fixed). It goes through C2's FUNDING / Flow-1 lock (assertSendAllowed('mainnet', …) → release.mainnet-locked while
// MAINNET_SEND_ENABLED is false), NOT the job-send lock: the operator's M2 flip of MAINNET_JOB_SENDS_ENABLED must not open
// withdrawals. Checked before the body is read or anything is forwarded (fix round 1, ruling A).
// Beyond the shape, a withdrawal is checked SEMANTICALLY before it is forwarded (checkWithdrawSemantics, ruling B): the
// recipient is the requesting lane's (a MAC'd lane binding minted by the API under relay-ticket.key), the fixed pool
// accounts, an amount cap, the fee clamp, the proof structure and the extDataHash binding.
//
// Messages never echo a path, a query, a body, an address or an upstream value (they hold commitments, ciphertexts and
// the recipient). Callers log the route NAME only.
import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import { lstatSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { PublicKey } from '@solana/web3.js'
import type { Network } from '@vault-timelock/core/contracts'
import { GENESIS, assertSendAllowed } from 'vt-broadcast/src/config.ts'
import { refuse } from 'vt-broadcast/src/guard.ts'
import { methodOk } from './relay-gate.ts'
import { pathOk } from './relay-routes.ts'
import { ENC_HEX_RE, ENC_MAX_BYTES, ENC_MIN_BYTES } from './pc-record.ts'

export const PC_PREFIX = '/relay/privacycash/'
export const isPrivacyCashPath = (path: string): boolean => path === '/relay/privacycash' || path.startsWith(PC_PREFIX)

// The fixed relayer (the SDK's hard-coded default). The only host a withdrawal can go to.
export const PC_RELAYER = 'https://api3.privacycash.org'
export const RANGE_SPAN = 20000

export type PcKind = 'config' | 'range' | 'indices' | 'proof' | 'withdraw' | 'check' | 'rpc' | 'artifact'
export interface PcRoute {
  readonly kind: PcKind
  readonly name: string                  // the pattern, for the log line: never a value from the request
  readonly method: 'GET' | 'POST'
  readonly upstream: string              // relayer: path + query below the relayer base; rpc / artifact: ''
  readonly reqCap: number                // request body cap (bytes)
  readonly respCap: number               // upstream answer cap (bytes)
  readonly timeoutMs: number             // per-route upstream timeout (research D4)
  readonly artifact: 'transaction2.wasm' | 'transaction2.zkey' | null
}
const KB = 1024
const TIMEOUTS: Readonly<Record<PcKind, number>> = Object.freeze({ config: 30000, range: 120000, indices: 60000, proof: 30000, withdraw: 90000, check: 30000, rpc: 60000, artifact: 0 })
const route = (kind: PcKind, name: string, method: 'GET' | 'POST', upstream: string, reqCap: number, respCap: number, artifact: PcRoute['artifact'] = null): PcRoute =>
  Object.freeze({ kind, name, method, upstream, reqCap, respCap, timeoutMs: TIMEOUTS[kind], artifact })

const HEX_OUT = ENC_HEX_RE                 // one definition (pc-record.ts): 36..200 bytes, the ledger's too
const R = '/relay/privacycash/relayer/'

// THE relay.pc-query line (one marker): a query or path parameter off the route's exact form.
function queryOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.pc-query', 'a Privacy Cash route takes exactly its own query form (range: start & end, 20000 apart; proofv2: commitments=<n>,<n>; check: a hex path; the others: none)') // @guard:relay.pc-query
}

// Resolves the raw request URL to exactly one route, or refuses: relay.path (no such route), relay.method (the route
// takes another HTTP method), relay.pc-query (the route, a malformed query or parameter).
export function resolvePc(httpMethod: string, raw: string): PcRoute {
  const q = raw.indexOf('?')
  const path = q < 0 ? raw : raw.slice(0, q), query = q < 0 ? null : raw.slice(q + 1)
  pathOk(raw.length <= 1024 && !raw.includes('#'))
  let r: PcRoute | null = null
  let queryGood = query === null
  if (path === `${R}config`) r = route('config', 'config', 'GET', '/config', 0, 64 * KB)
  else if (path === `${R}utxos/range`) {
    r = route('range', 'utxos/range', 'GET', '', 0, 12 * KB * KB)
    const m = query === null ? null : /^start=(\d{1,9})&end=(\d{1,9})$/.exec(query)
    queryGood = m !== null && Number(m[2]) - Number(m[1]) === RANGE_SPAN
    if (queryGood && query !== null) r = route('range', 'utxos/range', 'GET', `/utxos/range?${query}`, 0, 12 * KB * KB)
  } else if (path === `${R}utxos/indices`) r = route('indices', 'utxos/indices', 'POST', '/utxos/indices', 256 * KB, 64 * KB)
  else if (path === `${R}merkle/proofv2/`) {
    r = route('proof', 'merkle/proofv2', 'GET', '', 0, 64 * KB)
    queryGood = query !== null && /^commitments=\d{1,78},\d{1,78}$/.test(query)
    if (queryGood && query !== null) r = route('proof', 'merkle/proofv2', 'GET', `/merkle/proofv2/?${query}`, 0, 64 * KB)
  } else if (path === `${R}withdraw`) r = route('withdraw', 'withdraw', 'POST', '/withdraw', 8 * KB, 4 * KB)
  else if (path.startsWith(`${R}utxos/check/`)) {
    const hex = path.slice(`${R}utxos/check/`.length)
    if (HEX_OUT.test(hex)) { r = route('check', 'utxos/check', 'GET', '', 0, 4 * KB); queryGood = query === null; if (queryGood) r = route('check', 'utxos/check', 'GET', `/utxos/check/${hex}`, 0, 4 * KB) }
  } else if (path === '/relay/privacycash/rpc') r = route('rpc', 'rpc', 'POST', '', 64 * KB, 2 * KB * KB)
  else {
    const a = /^\/relay\/privacycash\/artifacts\/(transaction2\.(?:wasm|zkey))$/.exec(path)
    if (a !== null) r = route('artifact', `artifacts/${a[1]}`, 'GET', '', 0, 0, a[1] as PcRoute['artifact'])
  }
  pathOk(r !== null)
  methodOk(httpMethod === r.method)
  queryOk(queryGood)
  return r
}

// THE relay.pc-tor line (one marker): off local every Privacy Cash request goes through Tor on its own circuit, so it needs
// the relay's IsTor check to hold right now; otherwise nothing is forwarded (the caller answers 503).
export function torRequired(ok: boolean): asserts ok {
  if (!ok) refuse('relay.pc-tor', 'Tor is not available (IsTor check failed): Privacy Cash is reached through Tor only, nothing was forwarded') // @guard:relay.pc-tor
}

// ---- the send lock

// THE withdraw lock (one marker). Privacy Cash is a mainnet service and a withdrawal is FUNDING: C2's funding / Flow-1 lock
// (MAINNET_SEND_ENABLED, which stays locked after the M2 job-send flip) with the mainnet profile and the mainnet Solana
// identity refuses release.mainnet-locked. `lock` is a test seam; the relay always uses the default.
export type FundingLock = (profile: 'mainnet', observed: { chain: 'sol'; id: string }) => unknown
export function assertWithdrawAllowed(lock: FundingLock = assertSendAllowed): void {
  lock('mainnet', { chain: 'sol', id: GENESIS.sol.mainnet }) // @guard:relay.pc-send-lock
}

// ---- request bodies

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype
const parse = (buf: Buffer): unknown => { try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buf)) as unknown } catch { return undefined } }
const sameKeys = (o: Record<string, unknown>, keys: readonly string[]): boolean => {
  const k = Object.keys(o).sort(), w = [...keys].sort()
  return k.length === w.length && k.every((x, i) => x === w[i])
}
const B58_KEY = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/

// The 15 keys of the SDK's withdraw body (SOL path, research D4 item 2). referralId is absent: it would be a partner id.
export const WITHDRAW_KEYS: readonly string[] = Object.freeze(['serializedProof', 'treeAccount', 'nullifier0PDA', 'nullifier1PDA', 'nullifier2PDA',
  'nullifier3PDA', 'treeTokenAccount', 'globalConfigAccount', 'recipient', 'feeRecipientAccount', 'extAmount', 'encryptedOutput1', 'encryptedOutput2',
  'fee', 'lookupTableAddress'])
const ACCOUNT_KEYS = ['treeAccount', 'nullifier0PDA', 'nullifier1PDA', 'nullifier2PDA', 'nullifier3PDA', 'treeTokenAccount', 'globalConfigAccount', 'recipient', 'feeRecipientAccount', 'lookupTableAddress']
const intLike = (v: unknown, negative: boolean): boolean => {
  if (typeof v === 'number') return Number.isSafeInteger(v) && (negative ? v < 0 : v >= 0)
  return typeof v === 'string' && (negative ? /^-[1-9]\d{0,17}$/ : /^(?:0|[1-9]\d{0,17})$/).test(v)
}
const RPC_KEYS_MAX = 100
const RPC_CONFIG_KEYS = new Set(['encoding', 'commitment', 'dataSlice', 'minContextSlot'])

function bodyShapeOk(r: PcRoute, buf: Buffer): boolean {
  if (r.reqCap === 0) return buf.length === 0
  const j = parse(buf)
  switch (r.kind) {
    case 'indices': {
      if (!isPlainObject(j) || !sameKeys(j, ['encrypted_outputs'])) return false
      const e = j.encrypted_outputs
      return Array.isArray(e) && e.length >= 1 && e.length <= 750 && e.every((x) => typeof x === 'string' && HEX_OUT.test(x))
    }
    case 'withdraw': {
      if (!isPlainObject(j) || !sameKeys(j, WITHDRAW_KEYS)) return false
      const proofOk = typeof j.serializedProof === 'string' && j.serializedProof.length >= 684 && j.serializedProof.length <= 6000 && /^[A-Za-z0-9+/=]+$/.test(j.serializedProof)
      const outOk = (v: unknown): boolean => typeof v === 'string' && v.length >= 1 && v.length <= 1000
      return proofOk && ACCOUNT_KEYS.every((k) => typeof j[k] === 'string' && B58_KEY.test(j[k])) && intLike(j.extAmount, true) && intLike(j.fee, false)
        && outOk(j.encryptedOutput1) && outOk(j.encryptedOutput2)
    }
    case 'rpc': {
      if (!isPlainObject(j) || j.jsonrpc !== '2.0' || j.method !== 'getMultipleAccounts') return false
      const idOk = j.id === undefined || j.id === null || typeof j.id === 'number' || typeof j.id === 'string'
      const p = j.params
      if (!idOk || !Array.isArray(p) || p.length < 1 || p.length > 2 || !Array.isArray(p[0])) return false
      const keys = p[0] as unknown[]
      const cfgOk = p.length === 1 || (isPlainObject(p[1]) && Object.keys(p[1]).every((k) => RPC_CONFIG_KEYS.has(k)))
      return keys.length >= 1 && keys.length <= RPC_KEYS_MAX && keys.every((k) => typeof k === 'string' && B58_KEY.test(k)) && cfgOk
    }
    default: return false
  }
}

// THE relay.pc-body-cap line (one marker): the request body over this route's cap (the caller counts bytes while
// reading and aborts; this is the check on what it got).
export function bodyCapOk(r: PcRoute, size: number): void {
  if (!(size <= r.reqCap)) refuse('relay.pc-body-cap', 'the request body is larger than this Privacy Cash route takes') // @guard:relay.pc-body-cap
}

// THE relay.pc-body line (one marker): a body that is not exactly this route's form (no body on a GET).
export function checkPcBody(r: PcRoute, buf: Buffer): void {
  bodyCapOk(r, buf.length)
  if (!bodyShapeOk(r, buf)) refuse('relay.pc-body', 'the request body is not exactly this Privacy Cash route\'s form (indices: 1–750 hex notes; withdraw: the SDK\'s 15 keys; rpc: one getMultipleAccounts of ≤ 100 keys)') // @guard:relay.pc-body
}

// The upstream request of a route. The JSON bodies are re-serialized from the parsed, checked values (canonical: no
// duplicate key can smuggle a second field); the bytes of a withdrawal's proof are untouched strings.
export function forwardBody(r: PcRoute, buf: Buffer): Buffer | null {
  if (r.method === 'GET') return null
  return Buffer.from(JSON.stringify(parse(buf)))
}

// ---- answers

export interface PcAnswer { readonly status: number; readonly contentType: string; readonly body: Buffer }
const JSON_TYPE = 'application/json'
const errorBody = (message: string): Buffer => Buffer.from(JSON.stringify({ error: { message } }))

// THE relay.pc-upstream-shape line (one marker): an upstream answer over the route's cap or not its JSON form.
function shapeOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.pc-upstream-shape', 'the upstream answer is over this route\'s size cap or not the JSON form it returns: nothing of it was passed on') // @guard:relay.pc-upstream-shape
}
function answerOk(r: PcRoute, body: Buffer): boolean {
  if (body.length > r.respCap) return false
  const j = parse(body)
  switch (r.kind) {
    case 'rpc': return isPlainObject(j) && j.jsonrpc === '2.0' && (Object.hasOwn(j, 'result') || isPlainObject(j.error))
    case 'withdraw': return isPlainObject(j) && (j.signature === undefined || (typeof j.signature === 'string' && /^[1-9A-HJ-NP-Za-km-z]{64,100}$/.test(j.signature)))
    case 'indices': case 'proof': case 'check': case 'config': case 'range': return isPlainObject(j) || Array.isArray(j)
    default: return false
  }
}

// What goes back: 200 only in the route's own form (JSON within its cap), the upstream bytes as received; 404 as the relay's
// own 404; any other status a 502 with no upstream text. Never the upstream's headers or content type.
export function checkPcAnswer(r: PcRoute, status: number, body: Buffer): PcAnswer {
  if (status === 404) return { status: 404, contentType: JSON_TYPE, body: errorBody('not found upstream (HTTP 404)') }
  if (status !== 200) return { status: 502, contentType: JSON_TYPE, body: errorBody(`upstream HTTP ${Number.isSafeInteger(status) ? status : 0}`) }
  shapeOk(answerOk(r, body))
  return { status: 200, contentType: JSON_TYPE, body }
}

// ---- the circuit files, served locally

export interface Pin { readonly size: number; readonly sha256: string }
export type ArtifactName = 'transaction2.wasm' | 'transaction2.zkey'
// privacycash@1.2.3 circuit2/ (research-privacycash.md Q4; git blob ids match the program repo's artifacts/circuits/).
export const PC_PINS: Readonly<Record<ArtifactName, Pin>> = Object.freeze({
  'transaction2.wasm': Object.freeze({ size: 3208099, sha256: 'a277631b7616c2c0bfd78a1648b069972ac6020e5509ae8f9bfc8772bdc70ec1' }),
  'transaction2.zkey': Object.freeze({ size: 16461496, sha256: '4aa7aa5c1c28ed1f00fee84f49c1686f53210fd999ef7c8db6cfcd298af4e693' }),
})
export const ARTIFACT_TYPES: Readonly<Record<ArtifactName, string>> = Object.freeze({ 'transaction2.wasm': 'application/wasm', 'transaction2.zkey': 'application/octet-stream' })

// THE relay.pc-artifact line (one marker): a circuit file that is not the pinned one (missing, not a regular file, a
// symlink, another size or sha256). The caller serves nothing for it (503) and logs the guard id.
function artifactOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.pc-artifact', 'a Privacy Cash circuit file is missing or is not the pinned file (regular file, exact size and sha256): it is not served') // @guard:relay.pc-artifact
}
// Reads one file of `dir`, once, and returns its bytes only when they are exactly the pin. The bytes are then held in
// memory, so a later change on disk is never served.
export function loadArtifact(dir: string, name: ArtifactName, pins: Readonly<Record<ArtifactName, Pin>> = PC_PINS): Buffer {
  const pin = pins[name]
  const file = join(dir, name)
  let buf: Buffer | null = null
  try {
    const st = lstatSync(file)
    if (st.isFile() && !st.isSymbolicLink() && st.size === pin.size) buf = readFileSync(file)
  } catch { buf = null }
  artifactOk(buf !== null && buf.length === pin.size && createHash('sha256').update(buf).digest('hex') === pin.sha256)
  return buf as Buffer
}

// ---- the Privacy Cash RPC's identity (ruling C)

// THE relay.pc-rpc-identity line (one marker): an RPC endpoint that answers, definitively, another genesis than mainnet's.
function rpcIdentityOk(ok: boolean): void {
  if (!ok) refuse('relay.pc-rpc-identity', "the Privacy Cash RPC endpoint answered a genesis hash other than Solana mainnet's: the route is disabled until the relay restarts") // @guard:relay.pc-rpc-identity
}
// true: this endpoint is mainnet's; false: no definitive answer (unreachable, refused, not JSON-RPC: it is not used and is
// checked again later); a definitive wrong answer refuses relay.pc-rpc-identity.
export function pcRpcIdentity(status: number, body: Buffer): boolean {
  if (status !== 200) return false
  const j = parse(body)
  const id = isPlainObject(j) && typeof j.result === 'string' ? j.result : null
  if (id === null) return false
  rpcIdentityOk(id === GENESIS.sol.mainnet)
  return true
}
export const GENESIS_BODY: Buffer = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getGenesisHash', params: [] }))

// ---- the withdrawal, semantically (ruling B)

// The program id's neighbours, pinned (research Q5, derived offline): the pool accounts, the fee recipient and the ALT.
export const PC_FIXED: Readonly<Record<'treeAccount' | 'treeTokenAccount' | 'globalConfigAccount' | 'feeRecipientAccount' | 'lookupTableAddress', string>> = Object.freeze({
  treeAccount: '6VVKJ44WTJGCksTGJHjf1kJWZaMf9Nswgj6w7Dtrw55D', treeTokenAccount: '4AV2Qzp3N4c9RfzyEbNZs2wqWfW4EwKnnxFAZCndvfGh',
  globalConfigAccount: '2vV7xhCMWRrcLiwGoTaTRgvx98ku98TRJKPXhsS8jvBV', feeRecipientAccount: '97rSMQUukMDjA7PYErccyx7ZxbHvSDaeXp2ig5BwSrTf',
  lookupTableAddress: 'HEN49U2ySJ85Vc78qprSW9y6mFDhs1NczRxyppNHjofe',
})
export const TRANSACT_DISCRIMINATOR: Buffer = Buffer.from([217, 149, 130, 143, 221, 52, 252, 119])
// Fee clamp (research D4 step 5; Sfix-PC item 3). The published schedule is fee = 0.006 SOL + 0.35 % of the GROSS, where
// gross = |extAmount| + fee (the program takes the fee out of the gross; W6 concern 1: at a net of 0.01 SOL the schedule is
// 6,056,196 lamports, which a clamp on the NET refused). With gross = net + fee the schedule solves to
//     fee = (BASE × 10⁴ + RATE × net) / (10⁴ − RATE)          (RATE = 35, in ten-thousandths)
// and the ceiling uses RATE + MARGIN (MARGIN = 5, so 0.40 % of the gross) plus one lamport for rounding: a fee above that is
// not the published schedule.
export const FEE_BASE_LAMPORTS = 6_000_000n
export const FEE_RATE_PER_10K = 35n
export const FEE_MARGIN_PER_10K = 5n
export const feeCeiling = (net: bigint): bigint => {
  const rate = FEE_RATE_PER_10K + FEE_MARGIN_PER_10K
  return (FEE_BASE_LAMPORTS * 10_000n + rate * net) / (10_000n - rate) + 1n
}
// BN254: the scalar field r (public inputs) and the base field q (curve coordinates).
export const FIELD_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n
export const FIELD_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n
export const MIN_PROOF_BYTES = 512
export const LANE_HEADER = 'x-vt-pc-lane'
// The authorization window: exp must be within this many ms of now (the API mints with a shorter life).
export const WITHDRAW_AUTH_WINDOW_MS = 120_000
const MINT_PLACEHOLDER = '11111111111111111111111111111112'

// The withdrawal authorization (x-vt-pc-lane), SINGLE-USE and bound to the exact withdrawal:
//   v2.<recipient>.<job>.<try>.<allowance>.<nonce>.<bodySha256>.<exp>.<mac>
//   recipient  the lane's address (base58); job  the 16-hex job id; try  the try index; allowance  the lane's cumulative
//   allowance in lamports (|extAmount| + fee, all withdrawals); nonce  32 hex, fresh per authorization; bodySha256  sha256
//   hex of the EXACT request body bytes of the withdrawal; exp  ms epoch. Integers are canonical (0 or no leading zero).
//   mac = HMAC-SHA256(relay-ticket.key, "vt-pc-wd/2|<network>|<recipient>|<job>|<try>|<allowance>|<nonce>|<bodySha256>|<exp>").
export interface WithdrawAuth { network: Network; recipient: string; job: string; tryIndex: number; allowance: bigint; nonce: string; bodySha256: string; exp: number }
const authMac = (key: Uint8Array, a: WithdrawAuth): Buffer =>
  createHmac('sha256', key).update(`vt-pc-wd/2|${a.network}|${a.recipient}|${a.job}|${a.tryIndex}|${a.allowance}|${a.nonce}|${a.bodySha256}|${a.exp}`).digest()
export function mintWithdrawAuth(key: Uint8Array, a: WithdrawAuth): string {
  return `v2.${a.recipient}.${a.job}.${a.tryIndex}.${a.allowance}.${a.nonce}.${a.bodySha256}.${a.exp}.${authMac(key, a).toString('hex')}`
}
const CANON = '(?:0|[1-9][0-9]{0,17})'
const AUTH_RE = new RegExp(`^v2\\.([1-9A-HJ-NP-Za-km-z]{32,44})\\.([0-9a-f]{16})\\.(${CANON})\\.(${CANON})\\.([0-9a-f]{32})\\.([0-9a-f]{64})\\.(${CANON})\\.([0-9a-f]{64})$`)
export function verifyWithdrawAuth(header: string | undefined, key: Uint8Array, network: Network, now: number, bodySha256: string): WithdrawAuth | null {
  const m = typeof header === 'string' ? AUTH_RE.exec(header) : null
  if (m === null || key.length < 16) return null
  const a: WithdrawAuth = { network, recipient: m[1], job: m[2], tryIndex: Number(m[3]), allowance: BigInt(m[4]), nonce: m[5], bodySha256: m[6], exp: Number(m[7]) }
  if (!Number.isSafeInteger(a.tryIndex) || !Number.isSafeInteger(a.exp)) return null
  const ok = timingSafeEqual(authMac(key, a), Buffer.from(m[8], 'hex')) && a.bodySha256 === bodySha256 && a.exp > now && a.exp <= now + WITHDRAW_AUTH_WINDOW_MS
  return ok ? a : null
}
// THE relay.pc-lane line (one marker): the withdrawal is not authorized for the requesting lane (no valid, unexpired,
// canonical authorization under this relay's key and network for these exact body bytes, or the body's recipient is not its).
function laneOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.pc-lane', "a withdrawal needs the requesting lane's binding (valid, unexpired, this network) and may pay only that lane's address") // @guard:relay.pc-lane
}
// THE relay.pc-network line (one marker): Privacy Cash is a MAINNET pool (no devnet): its pool accounts are mainnet's. A stack
// that is not mainnet's refuses a withdrawal carrying them (S7 review M-1: a testnet stack must not forward real funds),
// and a mainnet stack refuses one that carries none of them (another network's parameters; a partly wrong set is
// relay.pc-accounts). Local reaches no real
// upstream (no upstream is configured unless a test injects a loopback fake), so it is not constrained.
function networkOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.pc-network', "a withdrawal carries the mainnet pool's parameters only on a mainnet stack, and a mainnet stack only those") // @guard:relay.pc-network
}
// THE relay.pc-check line (one marker): /utxos/check/<hex> is answered only for the first encrypted output of a withdrawal
// this relay forwarded (recorded in the ledger); the SDK checks only after its own withdraw.
export function checkRecordedOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.pc-check', 'a UTXO check is forwarded only for the output of a withdrawal this relay forwarded and recorded') // @guard:relay.pc-check
}
// THE relay.pc-accounts line (one marker): the pool accounts, the fee recipient or the ALT are not the pinned ones.
function accountsOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.pc-accounts', "the withdrawal's tree, vault, config, fee-recipient or lookup-table account is not the pinned Privacy Cash one") // @guard:relay.pc-accounts
}
// THE relay.pc-amount line (one marker): |extAmount| + fee above the authorization's allowance.
function amountOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.pc-amount', "the withdrawal's amount is above the lane's cap") // @guard:relay.pc-amount
}
// THE relay.pc-fee line (one marker): the relayer fee above the published schedule's ceiling (0.006 SOL + 0.35 % of the gross, plus a margin).
function feeOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.pc-fee', 'the relayer fee is above the published schedule (0.006 SOL + 0.35 % of the gross, with a small margin)') // @guard:relay.pc-fee
}
// THE relay.pc-proof line (one marker): serializedProof is not the transact instruction data of this withdrawal.
function proofOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.pc-proof', "serializedProof is not a well-formed transact instruction (discriminator, field ranges, lengths) carrying this withdrawal's amount, fee and encrypted outputs") // @guard:relay.pc-proof
}
// THE relay.pc-ext-hash line (one marker): the proof's extDataHash does not bind this recipient, amount, outputs and fee.
function extHashOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.pc-ext-hash', "the proof's extDataHash does not match the withdrawal's recipient, amount, encrypted outputs, fee and fee recipient") // @guard:relay.pc-ext-hash
}

const beInt = (b: Uint8Array): bigint => BigInt(`0x${Buffer.from(b).toString('hex') || '0'}`)
const leInt = (b: Uint8Array): bigint => beInt(Buffer.from(b).reverse())
const i64 = (v: bigint): Buffer => { const b = Buffer.alloc(8); b.writeBigInt64LE(v); return b }
const u64 = (v: bigint): Buffer => { const b = Buffer.alloc(8); b.writeBigUInt64LE(v); return b }
const u32 = (v: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32LE(v); return b }
const keyBytes = (s: string): Buffer => Buffer.from(new PublicKey(s).toBytes())

interface Decoded { extAmount: bigint; fee: bigint; enc1: Buffer; enc2: Buffer; extDataHash: Buffer }
// The transact instruction data (research Q5): disc(8) | proofA(64) | proofB(128) | proofC(64) | root | publicAmount |
// extDataHash | nf0 | nf1 | c0 | c1 (32 each, @264…) | extAmount i64 LE @488 | fee u64 LE @496 | u32 len + encOut1 | u32 len + encOut2,
// and nothing after. Curve coordinates < q, public inputs < r.
export function decodeProof(b64: string): Decoded | null {
  const b = Buffer.from(b64, 'base64')
  if (b.toString('base64') !== b64 || b.length < MIN_PROOF_BYTES || !b.subarray(0, 8).equals(TRANSACT_DISCRIMINATOR)) return null
  for (let o = 8; o < 264; o += 32) if (beInt(b.subarray(o, o + 32)) >= FIELD_Q) return null
  for (let o = 264; o < 488; o += 32) if (beInt(b.subarray(o, o + 32)) >= FIELD_R) return null
  const l1 = b.readUInt32LE(504)
  if (l1 < ENC_MIN_BYTES || l1 > ENC_MAX_BYTES || 508 + l1 + 4 > b.length) return null
  const l2 = b.readUInt32LE(508 + l1)
  if (l2 < ENC_MIN_BYTES || l2 > ENC_MAX_BYTES || 512 + l1 + l2 !== b.length) return null
  return { extAmount: b.readBigInt64LE(488), fee: b.readBigUInt64LE(496), enc1: b.subarray(508, 508 + l1), enc2: b.subarray(512 + l1, 512 + l1 + l2), extDataHash: b.subarray(328, 360) }
}
// The extDataHash the program recomputes: sha256(borsh{recipient, extAmount, encOut1, encOut2, fee, feeRecipient, mint}),
// compared as LE-mod-r with the proof's big-endian value mod r (lib.rs:228-242).
export function extDataHashMatches(recipient: string, d: Decoded, feeRecipient: string): boolean {
  const borsh = Buffer.concat([keyBytes(recipient), i64(d.extAmount), u32(d.enc1.length), d.enc1, u32(d.enc2.length), d.enc2, u64(d.fee), keyBytes(feeRecipient), keyBytes(MINT_PLACEHOLDER)])
  const digest = createHash('sha256').update(borsh).digest()
  return leInt(digest) % FIELD_R === beInt(d.extDataHash) % FIELD_R
}
const sameBytes = (s: unknown, b: Buffer): boolean => typeof s === 'string' && (s === b.toString('hex') || s === b.toString('base64'))

export interface WithdrawChecked { auth: WithdrawAuth; amount: bigint; enc1: string }
// The semantic check of a withdrawal body (already shape-checked by checkPcBody), before anything is forwarded. `header` is
// the x-vt-pc-lane value, `key` relay-ticket.key. Returns the verified authorization and the lamports to reserve
// (|extAmount| + fee); the caller burns the nonce and reserves the amount (privacycash-ledger.ts) before forwarding.
export function checkWithdrawSemantics(body: Buffer, o: { header: string | undefined; key: Uint8Array; network: Network; now: number }): WithdrawChecked {
  const j = parse(body) as Record<string, unknown>
  const carriesMainnet = (Object.keys(PC_FIXED) as Array<keyof typeof PC_FIXED>).some((k) => j[k] === PC_FIXED[k])
  networkOk(o.network === 'mainnet' ? carriesMainnet : o.network === 'testnet' ? !carriesMainnet : true)   // local: no real upstream exists unless a test injects a fake
  const auth = verifyWithdrawAuth(o.header, o.key, o.network, o.now, createHash('sha256').update(body).digest('hex'))
  laneOk(auth !== null && j.recipient === auth.recipient)
  const a = auth as WithdrawAuth
  accountsOk((Object.keys(PC_FIXED) as Array<keyof typeof PC_FIXED>).every((k) => j[k] === PC_FIXED[k]))
  const ext = BigInt(String(j.extAmount)), fee = BigInt(String(j.fee))
  amountOk(-ext + fee <= a.allowance)
  feeOk(fee <= feeCeiling(-ext))
  const d = decodeProof(String(j.serializedProof))
  proofOk(d !== null && d.extAmount === ext && d.fee === fee && sameBytes(j.encryptedOutput1, d.enc1) && sameBytes(j.encryptedOutput2, d.enc2))
  extHashOk(extDataHashMatches(String(j.recipient), d as Decoded, String(j.feeRecipientAccount)))
  return { auth: a, amount: -ext + fee, enc1: (d as Decoded).enc1.toString('hex') }
}

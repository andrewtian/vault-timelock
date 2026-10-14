// api/src/tickets.ts — send tickets (spec §5.6; CC-3 ticket v2; contract/fixtures/tickets.json).
//
//   ticket = 'vt-ticket/2.' + b64url(payload JSON) + '.' + b64url(HMAC-SHA256(key, 'vt-ticket/2.' + b64url(payload)))
//   payload = {"j","w","c","g","t","r","a","k","p","to","value","f","q","x","e","n"} in that order, no whitespace (fields:
//   @vault-timelock/core/contracts http.ts); b64url = RFC 4648 §5 without padding.
//   e = issue time + TICKET_TTL_MS; n = 16 lowercase hex from the CSPRNG. Valid while now < e.
//
// CC-8: c may be 'btc' (k 'commit' | 'reveal'; contracts http.ts has the btc binding). ticketBinding('btc', …) mints from the
// stored body and the journaled commit only (btcBinding below); worstCaseFee and declaredIdentity stay null for btc: its fee bound
// is the intent's own `fee` (ledger.ts worstFee reserves fee + value for a commit).
//
// verifyTicket checks format and MAC (relay.send-ticket), then expiry (relay.ticket-expired). The relay gate adds the
// network, chain and raw-bytes bindings, the job-send lock, then the decode verification (decode.ts) of a, k, p, to,
// value, f and q (CC-3a: the declared ETH nonce / SOL recentBlockhash). Both base64url parts must be in canonical form: the MAC is compared as its canonical encoding (constant
// time), so a MAC that differs only in the unused bits of its last character is refused, and the payload must
// re-encode to exactly the text that was signed. A v1 ticket ('vt-ticket/1.', or a v1 payload under the v2 prefix) is
// refused: no downgrade.
//
// ticketBinding / worstCaseFee: what the API puts in a, k, p, to, value, f and q for a journaled intent. f MUST be the
// worst case the API's cap check reserved for that attempt (one formula: worstCaseFee), because the relay forwards only
// bytes whose fee is at most f.
//
// PF-S I-1 (pre-flip review): an eth / sol JOB intent is bound to the STORED message, never to the executor's word. The API plans
// the copy itself with the lane's own planner (jobs.ts planOf: planLaneCopy(laneConfigOf(chain, def.chains[chain], text), copy)) and
// hands ticketBinding that plan (JobPlan): p is the planned part's sha256 (the intent's payloadSha256 must equal it, its parts must
// be the planned count and its part within it), and an ETH job ticket's `to` is the job tx's recipient from the publish mode
// (eth.calldata.null: 0x000…000; eth.calldata.self: the lane key's address), which the intent's eth.to must equal; the relay
// (decode.ts) compares the signed tx's `to` with exactly that address. A SOL job ticket's `to` stays null (a memo tx has no
// recipient). Without a plan an eth / sol job intent has no binding (null: refused). Claw-back bindings are unchanged.
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { TICKET_PREFIX, TICKET_TTL_MS } from '@vault-timelock/core/contracts'
import type { Chain, Network, TicketPayload } from '@vault-timelock/core/contracts'
import { BTC_MAX_INPUTS, BTC_POSTAGE, commitAddress, laneAddresses, maxCommitFee, maxCommitValue, maxRevealFee, revealDestination } from '@vault-timelock/core/chains/btc-ord.ts'
import { refuse } from 'vt-broadcast/src/guard.ts'

const B64URL = /^[A-Za-z0-9_-]+$/
const HEX16 = /^[0-9a-f]{16}$/
const HEX64 = /^[0-9a-f]{64}$/
const ETH_TX = /^0x[0-9a-f]{64}$/
const SOL_TX = /^[1-9A-HJ-NP-Za-km-z]{64,88}$/
const ETH_ADDRESS = /^0x[0-9a-f]{40}$/
const ANY_CASE_ETH_ADDRESS = /^0x[0-9a-fA-F]{40}$/
const DEC = /^(?:0|[1-9][0-9]{0,77})$/                 // base units: wei, lamports, gas
const POSITIVE = /^[1-9][0-9]{0,77}$/
const ETH_NONCE = /^(?:0|[1-9][0-9]{0,19})$/            // q on ETH: the declared nonce (uint64 fits in 20 digits)
// CC-8 (btc): addresses are lower-case bech32 / bech32m of the ticket's network (hrp bcrt | tb | bc); q is 1..8 outpoints in
// ascending order (a reveal: exactly one). The checksum and the script type are the decode verification's (decode.ts).
const BTC_ADDRESS = { local: /^bcrt1[02-9ac-hj-np-z]{11,87}$/, testnet: /^tb1[02-9ac-hj-np-z]{11,87}$/, mainnet: /^bc1[02-9ac-hj-np-z]{11,87}$/ } as const
const BTC_OUTPOINT = /^[0-9a-f]{64}:(?:0|[1-9][0-9]{0,9})$/
const MAX_TICKET = 2048
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
const ORDER = 'j,w,c,g,t,r,a,k,p,to,value,f,q,x,e,n'
// PF-S fix round 2 (R1-1): x, the declared fee members the signed bytes must carry exactly — ETH "<gas>:<tip>:<maxFee>", SOL
// "<cuLimit>:<cuPrice>", btc null. The values are the intent's own (validateEvent bounds them; the gate bounds them by the plan).
const ETH_X = /^[1-9][0-9]{0,77}:(?:0|[1-9][0-9]{0,77}):[1-9][0-9]{0,77}$/
const SOL_X = /^([1-9][0-9]{0,6}):(0|[1-9][0-9]{0,19})$/
const U64_MAX = 18_446_744_073_709_551_615n
const isFeeMembers = (c: unknown, x: unknown): boolean => {
  if (c === 'btc') return x === null
  if (typeof x !== 'string') return false
  if (c === 'eth') return ETH_X.test(x)
  const m = c === 'sol' ? SOL_X.exec(x) : null
  return m !== null && Number(m[1]) <= 1_400_000 && BigInt(m[2]) <= U64_MAX
}

// ---- base58 (Bitcoin alphabet), bounded: tickets carry at most 88 characters of it

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
export function base58Encode(b: Uint8Array): string {
  let n = 0n
  for (const x of b) n = n * 256n + BigInt(x)
  let s = ''
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n }
  for (const x of b) { if (x !== 0) break; s = `1${s}` }
  return s
}
export function base58Decode(s: string): Uint8Array | null {
  if (typeof s !== 'string' || s.length === 0 || s.length > 90) return null
  let n = 0n
  for (const ch of s) { const i = B58.indexOf(ch); if (i < 0) return null; n = n * 58n + BigInt(i) }
  const out: number[] = []
  while (n > 0n) { out.unshift(Number(n % 256n)); n /= 256n }
  for (const ch of s) { if (ch !== '1') break; out.unshift(0) }
  return Uint8Array.from(out)
}
// A canonical base58 Solana address (32 bytes).
export const isSolAddress = (v: unknown): v is string => typeof v === 'string' && base58Decode(v)?.length === 32 && base58Encode(base58Decode(v)!) === v
// The ticket's address form for a chain: ETH lower case, SOL canonical base58.
const isAddressOf = (c: unknown, v: unknown): boolean => (c === 'eth' ? typeof v === 'string' && ETH_ADDRESS.test(v) : c === 'sol' && isSolAddress(v))

const isBtcAddress = (w: unknown, v: unknown): boolean => (w === 'local' || w === 'testnet' || w === 'mainnet') && typeof v === 'string' && v.length <= 90 && BTC_ADDRESS[w].test(v)
// q of a btc ticket: "<txid>:<vout>" outpoints, 1..max, comma-joined, strictly ascending in plain string order.
function isBtcOutpoints(v: unknown, max: number): boolean {
  if (typeof v !== 'string') return false
  const list = v.split(',')
  return list.length >= 1 && list.length <= max && list.every((x, i) => BTC_OUTPOINT.test(x) && (i === 0 || list[i - 1] < x))
}

function checkKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error('the ticket key must be 32 bytes')
}

const isPosInt = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 1

export function isTicketPayload(v: unknown): v is TicketPayload {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false
  const p = v as Record<string, unknown>
  const btcKind = (p.k === 'commit' || p.k === 'reveal') && typeof p.p === 'string' && HEX64.test(p.p) && isBtcAddress(p.w, p.to)
    && typeof p.value === 'string' && POSITIVE.test(p.value)
  const kindOk = p.c === 'btc' ? btcKind
    : p.k === 'job'
      ? typeof p.p === 'string' && HEX64.test(p.p) && (p.c === 'eth' ? isAddressOf('eth', p.to) : p.to === null) && p.value === null
      : p.k === 'clawback' && p.p === null && isAddressOf(p.c, p.to) && typeof p.value === 'string' && POSITIVE.test(p.value)
  const txOk = typeof p.t === 'string' && (p.c === 'eth' ? ETH_TX : p.c === 'btc' ? HEX64 : SOL_TX).test(p.t)
  const senderOk = p.c === 'btc' ? isBtcAddress(p.w, p.a) : isAddressOf(p.c, p.a)
  const idOk = p.c === 'eth' ? typeof p.q === 'string' && ETH_NONCE.test(p.q)
    : p.c === 'btc' ? isBtcOutpoints(p.q, p.k === 'reveal' ? 1 : BTC_MAX_INPUTS) : isSolAddress(p.q)
  return Object.keys(p).join(',') === ORDER
    && typeof p.j === 'string' && HEX16.test(p.j)
    && (p.w === 'local' || p.w === 'testnet' || p.w === 'mainnet')
    && (p.c === 'eth' || p.c === 'sol' || p.c === 'btc')
    && isPosInt(p.g)
    && txOk
    && typeof p.r === 'string' && HEX64.test(p.r)
    && senderOk
    && kindOk
    && typeof p.f === 'string' && POSITIVE.test(p.f)
    && idOk
    && isFeeMembers(p.c, p.x)
    && isPosInt(p.e)
    && typeof p.n === 'string' && HEX16.test(p.n)
}

const payloadJson = (p: TicketPayload): string =>
  JSON.stringify({ j: p.j, w: p.w, c: p.c, g: p.g, t: p.t, r: p.r, a: p.a, k: p.k, p: p.p, to: p.to, value: p.value, f: p.f, q: p.q, x: p.x, e: p.e, n: p.n })
const mac = (key: Uint8Array, p64: string): string => createHmac('sha256', key).update(TICKET_PREFIX + p64).digest('base64url')

// The ticket for exactly this payload (deterministic; issueTicket draws e and n).
export function encodeTicket(key: Uint8Array, p: TicketPayload): string {
  checkKey(key)
  if (!isTicketPayload(p)) throw new Error('refusing to sign a malformed ticket payload')
  const p64 = Buffer.from(payloadJson(p), 'utf8').toString('base64url')
  return `${TICKET_PREFIX}${p64}.${mac(key, p64)}`
}

export function issueTicket(key: Uint8Array, p: Omit<TicketPayload, 'e' | 'n'>, now: number): string {
  return encodeTicket(key, { j: p.j, w: p.w, c: p.c, g: p.g, t: p.t, r: p.r, a: p.a, k: p.k, p: p.p, to: p.to, value: p.value, f: p.f, q: p.q, x: p.x,
    e: now + TICKET_TTL_MS, n: randomBytes(8).toString('hex') })
}

// ---- the v2 binding of a journaled BTC intent (CC-8, S6b fix round 1: server-computed)
//
// The API mints a btc ticket ONLY from values it computes itself; the executor's intent contributes nothing but choices the
// chain cannot be hurt by (which lane UTXOs, a fee and a value under the caps):
//   a      the job definition's key address, which must be the p2wpkh address of the intent's lane pubkey (never its p2tr: the
//          reveal pays the postage to that p2tr, and a commit must not be able to spend it back);
//   p      sha256 of the body the API slices from the STORED message (BtcMint.body); the intent's payloadSha256 must equal it;
//   commit to = p2tr(NUMS, the inscription leaf of that lane key and body) (btc-ord.ts); value <= postage + the reveal's fee
//          cap; q = the declared lane outpoints; f <= the fee cap of the commit;
//   reveal to = p2tr(lane x-only key) (where the inscribed sat lands), value = the postage, q = the journaled commit's
//          txid : the declared vout; f <= the fee cap of the reveal.
// intent data: data.btc = { kind: 'commit', pubkey, fee, value, inputs } | { kind: 'reveal', pubkey, fee, commitVout }.
// Anything else returns null: the API then refuses the intent BEFORE journaling it.
export interface BtcMint {
  network: Network
  body: Uint8Array | null                  // the part's bytes, sliced by the API from the stored message
  commitTxId: string | null                // a reveal: the txid of the journaled commit intent of the same (copy, part)
}
// The member SET, in any order (JSON key order carries no meaning).
const sameKeys = (o: Record<string, unknown>, keys: readonly string[]): boolean => Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k))
const HEX66 = /^0[23][0-9a-f]{64}$/
const sha256Hex = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex')
function btcBinding(type: string, data: Record<string, unknown>, keyAddress: string | null, m: BtcMint | undefined): TicketBinding | null {
  const bt = data.btc
  if (m === undefined || m.body === null || m.body.length === 0 || type !== 'intent' || keyAddress === null || !isObj(bt) || data.eth !== undefined || data.sol !== undefined) return null
  const pk = typeof bt.pubkey === 'string' && HEX66.test(bt.pubkey) ? Uint8Array.from(Buffer.from(bt.pubkey, 'hex')) : null
  const lane = pk === null ? null : laneAddresses(m.network, pk)
  if (lane === null || keyAddress !== lane.p2wpkh) return null   // the p2wpkh lane ONLY (fix round 2 review m-1): a p2tr `a` would let a later commit spend the 546-sat postage of an earlier reveal, which lands on the lane's own p2tr
  const p = sha256Hex(m.body)
  if (data.payloadSha256 !== p) return null
  const fee = typeof bt.fee === 'string' && POSITIVE.test(bt.fee) ? BigInt(bt.fee) : null
  if (fee === null) return null
  if (bt.kind === 'commit') {
    const inputs = bt.inputs
    if (!sameKeys(bt, ['kind', 'pubkey', 'fee', 'value', 'inputs']) || !Array.isArray(inputs) || inputs.length < 1) return null
    const q = inputs.join(',')
    if (!isBtcOutpoints(q, BTC_MAX_INPUTS) || q.split(',').length !== inputs.length) return null
    const value = typeof bt.value === 'string' && POSITIVE.test(bt.value) ? BigInt(bt.value) : null
    if (value === null || value < BTC_POSTAGE || value > maxCommitValue(m.body.length) || fee > maxCommitFee(inputs.length)) return null
    return { a: keyAddress, k: 'commit', p, to: commitAddress(m.network, lane.xonly, m.body), value: String(value), f: String(fee), q, x: null }
  }
  if (bt.kind === 'reveal') {
    if (!sameKeys(bt, ['kind', 'pubkey', 'fee', 'commitVout']) || typeof m.commitTxId !== 'string' || !/^[0-9a-f]{64}$/.test(m.commitTxId)) return null
    const vout = bt.commitVout
    if (!Number.isSafeInteger(vout) || (vout as number) < 0 || (vout as number) > 999_999_999 || fee > maxRevealFee(m.body.length)) return null
    return { a: keyAddress, k: 'reveal', p, to: revealDestination(m.network, lane.xonly), value: String(BTC_POSTAGE), f: String(fee), q: `${m.commitTxId}:${vout as number}`, x: null }
  }
  return null
}

// ---- the v2 binding of a journaled intent (CC-3)

export type TicketBinding = Pick<TicketPayload, 'a' | 'k' | 'p' | 'to' | 'value' | 'f' | 'q' | 'x'>
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)
const SOL_BASE_FEE = 5_000n // lamports per signature; every vt tx has exactly one (decode.ts refuses others)

// The worst-case fee of an intent's declared fields, in base units, or null when they are missing or malformed:
//   ETH: gas × maxFee (what the tx can be charged at most);
//   SOL: max(the declared fee, 5,000 + ⌈cuLimit × cuPrice / 10⁶⌉) — never below the fee its compute budget implies.
export function worstCaseFee(chain: Chain, data: Record<string, unknown>): bigint | null {
  if (chain === 'btc') return null // btc has no gas-style worst case here: ledger.ts worstFee (fee + value for a commit) and btcBinding's f
  if (chain === 'eth') {
    const e = data.eth
    if (!isObj(e) || data.sol !== undefined || typeof e.gas !== 'string' || !DEC.test(e.gas) || typeof e.maxFee !== 'string' || !DEC.test(e.maxFee)) return null
    const f = BigInt(e.gas) * BigInt(e.maxFee)
    return f > 0n ? f : null
  }
  const s = data.sol
  if (!isObj(s) || data.eth !== undefined || typeof s.fee !== 'string' || !DEC.test(s.fee)) return null
  const lim = s.cuLimit, price = s.cuPrice
  if (!Number.isSafeInteger(lim) || (lim as number) < 0 || !Number.isSafeInteger(price) || (price as number) < 0) return null
  const implied = SOL_BASE_FEE + (BigInt(lim as number) * BigInt(price as number) + 999_999n) / 1_000_000n
  const declared = BigInt(s.fee)
  return declared > implied ? declared : implied
}

// PF-S fix round 2 (R1-1): the attempt's declared fee members x: ETH "<gas>:<tip>:<maxFee>", SOL "<cuLimit>:<cuPrice>"; null when
// missing or malformed.
export function declaredFeeMembers(chain: Chain, data: Record<string, unknown>): string | null {
  if (chain === 'btc') return null
  if (chain === 'eth') {
    const e = data.eth
    const x = isObj(e) && typeof e.gas === 'string' && typeof e.tip === 'string' && typeof e.maxFee === 'string' ? `${e.gas}:${e.tip}:${e.maxFee}` : null
    return x !== null && isFeeMembers('eth', x) ? x : null
  }
  const s = data.sol
  const x = isObj(s) && Number.isSafeInteger(s.cuLimit) && Number.isSafeInteger(s.cuPrice) ? `${s.cuLimit as number}:${s.cuPrice as number}` : null
  return x !== null && isFeeMembers('sol', x) ? x : null
}

// CC-3a: the attempt's declared identity q: the ETH eth.nonce (decimal) or the SOL sol.blockhash; null when missing.
export function declaredIdentity(chain: Chain, data: Record<string, unknown>): string | null {
  if (chain === 'btc') return null // btc has no declared nonce / blockhash: its q is the lane outpoints (btcBinding)
  if (chain === 'eth') {
    const e = data.eth
    return isObj(e) && Number.isSafeInteger(e.nonce) && (e.nonce as number) >= 0 ? String(e.nonce) : null
  }
  const s = data.sol
  return isObj(s) && isSolAddress(s.blockhash) ? s.blockhash : null
}

// PF-S I-1: the API's own plan of one copy of an eth / sol job chain: the sha256 of each planned part's payload, in part order
// (planLaneCopy over the STORED message), and the job tx's recipient (ETH: from the publish mode, any case; SOL: null).
export interface JobPlan {
  readonly digests: readonly string[]
  readonly to: string | null
}
const isJobPlan = (v: unknown): v is JobPlan => isObj(v) && Array.isArray(v.digests) && v.digests.length >= 1 && v.digests.every((x) => typeof x === 'string' && HEX64.test(x))
  && (v.to === null || typeof v.to === 'string')

// a, k, p, to, value, f and q for a send intent of `chain`: type 'intent' (k job) or 'clawback-intent' (k clawback),
// its journaled data, and the job key's address on that chain; for an eth / sol job intent also the API's plan of its copy
// (JobPlan), for btc the API's BtcMint. null when anything the binding needs is missing or malformed, or the intent is not the
// planned part (payloadSha256, parts, part, eth.to): the API then refuses the intent BEFORE journaling it (no journaled intent
// without a ticket), and never mints a ticket for one.
export function ticketBinding(chain: Chain, type: string, data: Record<string, unknown>, keyAddress: string | null, ctx?: BtcMint | JobPlan): TicketBinding | null {
  if (chain === 'btc') return btcBinding(type, data, keyAddress, ctx !== undefined && 'network' in ctx ? ctx : undefined)
  const norm = (v: unknown): string | null => {
    if (chain === 'eth') return typeof v === 'string' && ANY_CASE_ETH_ADDRESS.test(v) ? v.toLowerCase() : null
    return isSolAddress(v) ? v : null
  }
  const a = norm(keyAddress)
  const f = worstCaseFee(chain, data)
  const q = declaredIdentity(chain, data)
  const x = declaredFeeMembers(chain, data)
  if (a === null || f === null || q === null || x === null) return null
  if (type === 'intent') {
    const plan = isJobPlan(ctx) ? ctx : null
    const part = data.part, parts = data.parts
    const inPlan = plan !== null && parts === plan.digests.length && Number.isSafeInteger(part) && (part as number) >= 1 && (part as number) <= plan.digests.length
    const p = inPlan ? plan.digests[(part as number) - 1] : null
    // ETH: the recipient the publish mode sends to (lower case), and the intent's own eth.to must be it; SOL: no recipient
    const own = isObj(data.eth) ? norm(data.eth.to) : null
    const to = plan === null ? null : chain === 'eth' ? norm(plan.to) : null
    const toOk = chain === 'eth' ? to !== null && own === to : plan?.to === null
    return p !== null && data.payloadSha256 === p && toOk ? { a, k: 'job', p, to, value: null, f: String(f), q, x } : null
  }
  if (type === 'clawback-intent') {
    const to = norm(data.to), value = data.value
    return to !== null && typeof value === 'string' && POSITIVE.test(value) ? { a, k: 'clawback', p: null, to, value, f: String(f), q, x } : null
  }
  return null
}

// The payload of a well-formed ticket with a valid MAC, or null.
function decodeTicket(key: Uint8Array, ticket: unknown): TicketPayload | null {
  if (typeof ticket !== 'string' || ticket.length > MAX_TICKET || !ticket.startsWith(TICKET_PREFIX)) return null
  const parts = ticket.slice(TICKET_PREFIX.length).split('.')
  if (parts.length !== 2) return null
  const [p64, m64] = parts
  if (!B64URL.test(p64) || !B64URL.test(m64)) return null
  const want = Buffer.from(mac(key, p64), 'utf8')
  const got = Buffer.from(m64, 'utf8')
  if (got.length !== want.length || !timingSafeEqual(got, want)) return null
  const bytes = Buffer.from(p64, 'base64url')
  if (bytes.toString('base64url') !== p64) return null
  let json: string
  let value: unknown
  try {
    json = UTF8.decode(bytes)
    value = JSON.parse(json)
  } catch {
    return null
  }
  if (!isTicketPayload(value) || payloadJson(value) !== json) return null
  return value
}

export function verifyTicket(key: Uint8Array, ticket: string, now: number): TicketPayload {
  checkKey(key)
  const p = decodeTicket(key, ticket)
  if (p === null) refuse('relay.send-ticket', 'missing or invalid send ticket') // @guard:relay.send-ticket
  const fresh = now < p.e
  if (!fresh) refuse('relay.ticket-expired', 'the send ticket has expired: ask the API for a fresh one') // @guard:relay.ticket-expired
  return p
}

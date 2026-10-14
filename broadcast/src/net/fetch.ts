// The net layer: the ONLY place in broadcast/ that constructs network clients (spec B s2a, s6.1,
// s6.3; enforced by test/offline/static-net.test.ts). Fail closed everywhere: an IP leak here
// would tie the operator to every address the tool touches.
//
// - Every non-loopback request goes over Tor SOCKS as socks5h (names resolve inside Tor; ATYP is
//   always "domain", IP-literal hosts are refused). The SOCKS username is `<role>.<tick>` with a
//   random 16-hex password per agent, one agent per (role, tick), keep-alive off: IsolateSOCKSAuth
//   gives every role its own circuit, and no socket is ever shared between roles.
// - Loopback URLs (literal http://127.0.0.1|[::1]:<port>, the same classification as config.ts)
//   connect directly with no SOCKS, through a one-off http.Agent of their own (never the global
//   agent, which poisonGlobals replaces). Every other guard still applies to them.
// - Lazy Tor gate (R17): no SOCKS request before torGate (gate.ts) has passed for THIS instance,
//   except the gate's own check request (role `check`, GET TOR_CHECK_URL). Only gate.ts can open it.
// - Ticks: a tick is the canonical ISO minute `YYYY-MM-DDTHH:MMZ` (e.g. 2026-10-08T03:15Z, what
//   the runner and `tor-check` build from the clock), so ticks sort by time as strings and one
//   moment has exactly one spelling. Anything else is refused (net.tick-format): a second spelling
//   of the same minute would be a second tick to the side guard.
// - Side guard: a tick never serves both deposit and publication roles, across ALL net instances
//   with that tick (module-level map). The map remembers the newest tick and the 2 before it (older
//   entries are pruned, so a long-running runner does not grow it forever); a side claim for a tick
//   older than that window is refused (net.tick-stale), because its record may be gone.
// - The transport seam is for tests only (net.transport-test-only).
// - Send permit (M1a, spec B §6.5; C2 review I-1/I-2): every request is classed read / job / all (sendClass). A
//   'job' request needs a permit from assertSendAllowed or assertJobSendAllowed (src/config.ts); an 'all' request
//   needs one from assertSendAllowed (scope 'all', i.e. MAINNET_SEND_ENABLED on mainnet). Given as
//   createNet({ tick, permit }). Otherwise, or with anything else in its place, the request is refused
//   (net.send-permit) before the gate, the event log and the wire.
// - Errors carry the status and host only, never a response body, never the transport's text.
import { Agent as HttpAgent, request as httpRequest, type ClientRequest, type IncomingHttpHeaders, type IncomingMessage } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { isIP, type LookupFunction } from 'node:net'
import { randomBytes } from 'node:crypto'
import { SocksProxyAgent } from 'socks-proxy-agent'
import { Refusal, refuse } from '../guard.ts'
import { isLoopback, isOnion, isSendPermit, type Profile, type SendPermit } from '../config.ts'
import { assertRole, sideOf, type Role, type Side } from './roles.ts'
import { poisonGlobals } from './poison.ts'
import { TOR_CHECK_URL, checkTorReached, gatePassedFor } from './gate.ts'
import { SOCKS_HOST } from './socks-probe.ts'
import type { Transport } from './transport.ts'

export { TOR_CHECK_URL }
export const BODY_CAP = 8 * 1024 * 1024
export const TIMEOUT_ONION_MS = 60_000
export const TIMEOUT_CLEAR_MS = 30_000
export const DEFAULT_SOCKS_PORT = 9050
const JITTER_MAX_MS = 3_600_000
// The canonical ISO minute. The shape alone is not enough: Date.parse rolls 02-30 or 24:00 over
// into another day, so the tick must also survive a round trip through Date unchanged.
const TICK_SHAPE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}Z$/
// The side guard keeps the newest tick and this many before it.
const OLDER_TICKS_KEPT = 2
const METHODS: readonly string[] = ['GET', 'HEAD', 'POST']
const HEADER_NAME = /^[A-Za-z0-9-]{1,64}$/
// Framing, routing and keep-alive are the net layer's business, not the caller's.
const RESERVED_HEADERS: readonly string[] = [
  'host', 'connection', 'keep-alive', 'content-length', 'transfer-encoding', 'te', 'trailer', 'upgrade',
  'expect', 'proxy-authorization', 'proxy-connection',
]
const RPC_METHOD = /^[A-Za-z0-9_]{1,64}$/

// ---- public types

export type Atyp = 'domain' | 'loopback'
export interface NetEvent {
  readonly role: Role
  // `<role>.<tick>` (the SOCKS username, never the password); null for a loopback request.
  readonly socksUser: string | null
  readonly host: string
  readonly atyp: Atyp
}
export interface NetInit {
  readonly method?: 'GET' | 'HEAD' | 'POST'
  readonly headers?: Readonly<Record<string, string>>
  readonly body?: string | Uint8Array
}
export interface NetResponse {
  readonly status: number
  readonly headers: Readonly<Record<string, string>>
  text(): Promise<string>
  json(): Promise<unknown>
  bytes(): Promise<Uint8Array>
}
export type NetFetch = (url: string, init?: NetInit) => Promise<NetResponse>
export interface RequestArguments { readonly method: string; readonly params?: unknown }
export interface Eip1193 { request(args: RequestArguments): Promise<unknown> }
export interface TorNet {
  readonly tick: string
  // Tor's SOCKS port on 127.0.0.1 (the gate probes it).
  readonly socksPort: number
  fetchFor(role: Role): NetFetch
  jsonRpc(role: Role, url: string): Eip1193
  jitter(maxMs: number): Promise<number>
  events(): readonly NetEvent[]
  // Read-only. Only torGate (gate.ts) opens the gate.
  gatePassed(): boolean
}
export interface NetContext {
  // The canonical ISO minute YYYY-MM-DDTHH:MMZ (net.tick-format), e.g. 2026-10-08T03:15Z.
  readonly tick: string
  readonly socksPort?: number
  readonly transport?: Transport
  readonly random?: () => number
  // Tests only: caps the per-request timeout (it can only shorten it, never lengthen it).
  readonly maxTimeoutMs?: number
  // From assertSendAllowed / assertJobSendAllowed only: lets this net make send-type requests (net.send-permit).
  readonly permit?: SendPermit
}

// A JSON-RPC error answer. Only `code` and a scrubbed `message` survive: no `data`, no IPs.
export class RpcError extends Error {
  readonly code: number

  constructor(code: number, message: string) {
    super(scrub(message))
    this.name = 'RpcError'
    this.code = code
  }
}

// ---- helpers

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v) && !(v instanceof Uint8Array)
}

// No local DNS, ever. Every socket here connects to an IP literal (the SOCKS port or a loopback
// literal), so this only fires if that invariant is broken.
const noLookup: LookupFunction = (_host, _opts, cb) => {
  const e: NodeJS.ErrnoException = new Error('local DNS is disabled in the net layer')
  e.code = 'ENOTFOUND'
  cb(e, '', 0)
}

const cryptoRandom = (): number => randomBytes(6).readUIntBE(0, 6) / 2 ** 48

// Server-supplied text that may reach an error message (only RpcError.message): no control
// characters, no IPv4/IPv6-looking runs, bounded length.
const IPV6ISH = /[0-9A-Fa-f.]*:[0-9A-Fa-f.]*:[0-9A-Fa-f.:]*/g
const IPV4 = /\d{1,3}(?:\.\d{1,3}){3}/g
function scrub(m: string): string {
  return String(m)
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ')
    .replace(IPV6ISH, (s) => (/[0-9A-Fa-f]/.test(s) ? '[ip]' : s))
    .replace(IPV4, '[ip]')
    .slice(0, 300)
}

function isCanonicalTick(t: unknown): t is string {
  if (typeof t !== 'string' || !TICK_SHAPE.test(t)) return false
  const ms = Date.parse(`${t.slice(0, 16)}:00.000Z`)
  return Number.isFinite(ms) && `${new Date(ms).toISOString().slice(0, 16)}Z` === t
}

// ---- URL classification

type Kind = 'loopback' | 'onion' | 'https'
interface Target { readonly url: URL; readonly kind: Kind; readonly host: string }

const RAW_BAD = /[\s\u0000-\u001f\u007f\\]/
const RAW_ORIGIN = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*/
const ONION_HOST = /^[a-z2-7]{56}\.onion$/

function parseTarget(raw: unknown): Target | null {
  if (typeof raw !== 'string' || raw.length > 8192 || RAW_BAD.test(raw)) return null
  let url: URL
  try { url = new URL(raw) } catch { return null }
  if (url.username !== '' || url.password !== '') return null
  const host = url.hostname
  if (host === '' || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.')) return null
  // The origin as WRITTEN (the URL parser would normalize 127.1 or 0x7f000001 to 127.0.0.1).
  const origin = RAW_ORIGIN.exec(raw)?.[0] ?? ''
  if (url.protocol === 'http:' && isLoopback(origin) && (host === '127.0.0.1' || host === '[::1]')) return { url, kind: 'loopback', host }
  if (url.protocol === 'http:' && isOnion(origin) && ONION_HOST.test(host)) return { url, kind: 'onion', host }
  const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host
  if (url.protocol === 'https:' && isIP(bare) === 0) return { url, kind: 'https', host }
  return null
}

function classify(raw: unknown): Target {
  const t = parseTarget(raw)
  if (t === null) refuse('net.scheme', 'URL must be https://<name>, http://<56 base32>.onion, or http://127.0.0.1|[::1]:<port> (no localhost, no IP literal over Tor, no userinfo)') // @guard:net.scheme
  return t
}

// 60 s for an onion service, 30 s otherwise; `cap` can only shorten it.
export function timeoutFor(url: string, cap?: number): number {
  let onion = false
  try { onion = new URL(url).hostname.endsWith('.onion') } catch { /* not an onion */ }
  const base = onion ? TIMEOUT_ONION_MS : TIMEOUT_CLEAR_MS
  return cap === undefined ? base : Math.min(base, cap)
}

// ---- request shape

interface Prepared { readonly method: string; readonly headers: Readonly<Record<string, string>>; readonly body: Uint8Array | null }

function shape(ok: boolean): void {
  if (!ok) refuse('net.request', 'bad request: method GET|HEAD|POST, a string or byte body only with POST, string headers without host/connection/framing/proxy headers; JSON-RPC method [A-Za-z0-9_]{1,64}') // @guard:net.request
}

function prepare(init: unknown): Prepared | null {
  const i = init === undefined ? {} : init
  if (!isRecord(i)) return null
  const method = i.method ?? 'GET'
  if (typeof method !== 'string' || !METHODS.includes(method)) return null
  const b = i.body
  const body = b === undefined ? null
    : typeof b === 'string' ? new Uint8Array(Buffer.from(b, 'utf8'))
      : b instanceof Uint8Array ? new Uint8Array(b) : undefined
  if (body === undefined || (body !== null && method !== 'POST')) return null
  const h = i.headers ?? {}
  if (!isRecord(h)) return null
  const headers: Array<[string, string]> = []
  for (const [k, v] of Object.entries(h)) {
    const ok = HEADER_NAME.test(k) && typeof v === 'string' && !/[\r\n\u0000]/.test(v) && !RESERVED_HEADERS.includes(k.toLowerCase())
    if (!ok) return null
    headers.push([k.toLowerCase(), v as string])
  }
  headers.push(['connection', 'close'])
  if (body !== null) headers.push(['content-length', String(body.length)])
  return { method, headers: Object.fromEntries(headers), body }
}

function prepared(init: unknown): Prepared {
  const p = prepare(init)
  shape(p !== null)
  return p as Prepared
}

// ---- response guards (each id has exactly one marker line)

function checkRedirect(status: number, host: string): void {
  const redirect = status >= 300 && status <= 399
  if (redirect) refuse('net.redirect', `HTTP ${status} from ${host}: redirects are refused`) // @guard:net.redirect
}

function checkSize(n: number, host: string): void {
  if (n > BODY_CAP) refuse('net.body-too-large', `the response from ${host} is over 8 MiB`) // @guard:net.body-too-large
}

// Why a request produced no response. The thrown error text never surfaces.
// The last line is unconditional on purpose: this function is only called once the request has
// already failed, and its contract is "never returns". If that line were blanked, finish() in
// exchangeNode still rejects ('net: no outcome'), and the net.failed tests fail.
function requestFailed(host: string, timedOut: boolean, socksStage: boolean): never {
  if (timedOut) refuse('net.timeout', `no complete response from ${host} in time`) // @guard:net.timeout
  checkTorReached(!socksStage, `the request to ${host}`)
  refuse('net.failed', `the request to ${host} failed`) // @guard:net.failed
}

function parseJson(body: Uint8Array, status: number, host: string): unknown {
  let v: unknown
  let ok = true
  // JSON.parse's own message quotes the input: swallow it.
  try { v = JSON.parse(new TextDecoder().decode(body)) } catch { ok = false }
  if (!ok) refuse('net.json', `the HTTP ${status} response from ${host} is not valid JSON`) // @guard:net.json
  return v
}

function checkRpcStatus(status: number, host: string): void {
  const ok = status >= 200 && status <= 299
  if (!ok) refuse('net.rpc-status', `JSON-RPC answered HTTP ${status} from ${host}`) // @guard:net.rpc-status
}

function rpcKind(body: unknown, id: number): 'result' | 'error' | null {
  if (!isRecord(body) || body.jsonrpc !== '2.0' || body.id !== id) return null
  const hasResult = Object.hasOwn(body, 'result')
  if (hasResult === Object.hasOwn(body, 'error')) return null
  if (hasResult) return 'result'
  const e = body.error
  return isRecord(e) && Number.isSafeInteger(e.code) && typeof e.message === 'string' ? 'error' : null
}

function rpcResult(body: unknown, id: number, host: string): unknown {
  const kind = rpcKind(body, id)
  if (kind === null) refuse('net.rpc-malformed', `malformed JSON-RPC response from ${host}`) // @guard:net.rpc-malformed
  const b = body as Record<string, unknown>
  if (kind === 'error') {
    const e = b.error as { code: number; message: string }
    throw new RpcError(e.code, e.message)
  }
  return b.result
}

// ---- send-type requests (M1a, spec B §6.5; C2 review I-1, I-2; re-review N-1, N-2)
//
// Every request is classed. Fail closed: a request is a READ only when it is positively recognised as one, and a
// JOB send only when it is positively recognised as one; everything else is an 'all' send.
//   - Any method (GET and HEAD too):
//     - a URL query whose raw text, decoded text, or any decoded parameter name or value names a send (QUERY_SEND:
//       send, submit, airdrop, broadcast, bumpfee, e.g. the Etherscan-family ?module=proxy&action=eth_sendRawTransaction)
//       or a GraphQL mutation is 'all';
//     - a path segment (raw or percent-decoded, any case) that names a send (SEND_NAME) or starts with "push" is 'all'
//       (N-2): Blockbook GET /api/v2/sendtx/<hex>, /broadcast/<hex>, /pushtx, /api/tx/push, /push/transaction/<hex>.
//     Otherwise GET and HEAD are reads (they carry no body here, net.request).
//   - POST is also 'all' when: a path segment is tx, txs, chunk or chunks (POST only, so GET /tx/<id> stays a read:
//     Esplora/mempool POST /api/tx, Turbo POST /v1/tx[/<token>], Arweave POST /tx and /chunk); it has no body; the
//     body is not strict UTF-8, holds a NUL (UTF-16/32) or a BOM, or is not JSON (form bodies, raw hex, trailing
//     garbage); ANY object in it has a duplicate key after unescaping (N-1: first-wins and last-wins servers would
//     disagree); it is neither a JSON-RPC request nor a GraphQL query to .../graphql.
//   - JSON-RPC (an object, or a flat non-empty batch of objects): every "method" key, found by a key scanner that
//     decodes each key (N-1) and matched case-insensitively (Go's encoding/json, i.e. geth, does), must be spelled
//     exactly "method" with no escape, be one per element at its top level (none nested), and hold a plain method
//     name [A-Za-z0-9_]{1,64} with no escape. Otherwise 'all'. Then:
//     - no method names a send (SEND_NAME): a read;
//     - every send is exactly eth_sendRawTransaction or Solana sendTransaction and the URL has no query: a JOB send
//       (I-1), the ETH and SOL job sends to their JSON-RPC endpoints (which never carry a query: config refuses one);
//     - else 'all': Turbo, Arweave, Esplora POST /tx, bitcoind sendrawtransaction / sendtoaddress / sendmany,
//       requestAirdrop, eth_sendTransaction, ... Lifting MAINNET_JOB_SENDS_ENABLED never opens them.
//   - GraphQL (a JSON object with a string "query", POSTed to .../graphql): a read unless any key or string in it,
//     decoded, mentions a mutation or names a send.
const SEND_NAME = /send|submit|airdrop|broadcast|bumpfee/i
const POST_SEND_SEGMENT = /^(?:txs?|chunks?)$/i
const PUSH_SEGMENT = /^push/i
const QUERY_SEND = /send|submit|airdrop|broadcast|bumpfee|mutation/i
const PLAIN_METHOD = /^[A-Za-z0-9_]{1,64}$/
const JOB_SEND_METHODS: readonly string[] = ['eth_sendRawTransaction', 'sendTransaction']
const UTF8_STRICT = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

type SendClass = 'read' | 'job' | 'all'

function decodedText(s: string): string {
  try { return decodeURIComponent(s) } catch { return s }
}

function queryNamesSend(url: URL): boolean {
  if (url.search === '') return false
  if (QUERY_SEND.test(url.search) || QUERY_SEND.test(decodedText(url.search))) return true
  for (const [k, v] of url.searchParams) if (QUERY_SEND.test(k) || QUERY_SEND.test(v)) return true
  return false
}

// N-1: every object key of a JSON text that JSON.parse has accepted, as written (`raw`, between the quotes) and
// decoded (`key`), with the raw text of its value when that value is a string (else null), and whether any object
// repeats a key after decoding. A small tokenizer: the text is known-valid JSON, so strings are the only tokens that
// can hold structural characters. Iterative (no recursion).
interface JsonKey { readonly raw: string; readonly key: string; readonly rawValue: string | null }
function jsonKeys(text: string): { keys: JsonKey[]; duplicate: boolean } {
  const keys: JsonKey[] = []
  let duplicate = false
  const stack: Array<{ seen: Set<string> | null; expectKey: boolean }> = []
  const stringEnd = (from: number): number => { // index of the closing quote of the string opened at `from`
    let j = from + 1
    while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1
    return j
  }
  const skipSpace = (from: number): number => { let k = from; while (/\s/.test(text[k] ?? '')) k++; return k }
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]
    const top = stack[stack.length - 1]
    if (ch === '{') stack.push({ seen: new Set<string>(), expectKey: true })
    else if (ch === '[') stack.push({ seen: null, expectKey: false })
    else if (ch === '}' || ch === ']') stack.pop()
    else if (ch === ',' && top !== undefined && top.seen !== null) top.expectKey = true
    else if (ch === '"') {
      const end = stringEnd(i)
      if (top !== undefined && top.seen !== null && top.expectKey) {
        const raw = text.slice(i + 1, end)
        const key = String(JSON.parse(`"${raw}"`))
        if (top.seen.has(key)) duplicate = true
        top.seen.add(key)
        top.expectKey = false
        const v = skipSpace(skipSpace(end + 1) + 1) // past the ':'
        keys.push({ raw, key, rawValue: text[v] === '"' ? text.slice(v + 1, stringEnd(v)) : null })
      }
      i = end
    }
  }
  return { keys, duplicate }
}

// Every string in a parsed JSON value, keys included (iterative).
function jsonStrings(v: unknown): string[] {
  const out: string[] = []
  const stack: unknown[] = [v]
  while (stack.length > 0) {
    const x = stack.pop()
    if (typeof x === 'string') out.push(x)
    else if (Array.isArray(x)) for (const e of x) stack.push(e)
    else if (isRecord(x)) for (const [k, val] of Object.entries(x)) { out.push(k); stack.push(val) }
  }
  return out
}

function sendClass(t: Target, p: Prepared): SendClass {
  if (queryNamesSend(t.url)) return 'all'
  const segments = t.url.pathname.split('/').flatMap((s) => [s, decodedText(s)])
  if (segments.some((s) => SEND_NAME.test(s) || PUSH_SEGMENT.test(s))) return 'all'
  if (p.method !== 'POST') return 'read'
  if (segments.some((s) => POST_SEND_SEGMENT.test(s))) return 'all'
  if (p.body === null) return 'all'
  let text: string
  try { text = UTF8_STRICT.decode(p.body) } catch { return 'all' }
  if (text.includes('\u0000') || text.includes('\ufeff')) return 'all'
  let v: unknown
  try { v = JSON.parse(text) } catch { return 'all' }
  const scan = jsonKeys(text)
  if (scan.duplicate) return 'all'
  const last = decodedText(t.url.pathname.split('/').pop() ?? '')
  if (last.toLowerCase() === 'graphql' && isRecord(v) && typeof v.query === 'string') {
    return jsonStrings(v).some((x) => /mutation/i.test(x) || SEND_NAME.test(x)) || /mutation/i.test(text) ? 'all' : 'read'
  }
  const elements = Array.isArray(v) ? v : [v]
  if (elements.length === 0 || !elements.every((e) => isRecord(e) && typeof e.method === 'string')) return 'all'
  const methods = scan.keys.filter((k) => k.key.toLowerCase() === 'method')
  const plain = methods.length === elements.length
    && methods.every((k) => k.raw === 'method' && k.rawValue !== null && PLAIN_METHOD.test(k.rawValue))
  if (!plain) return 'all'
  const sends = methods.map((k) => k.rawValue as string).filter((n) => SEND_NAME.test(n))
  if (sends.length === 0) return 'read'
  return t.url.search === '' && sends.every((n) => JOB_SEND_METHODS.includes(n)) ? 'job' : 'all'
}

// The one net.send-permit line: a forged permit at createNet, and a request whose class the permit does not cover.
function requirePermit(ok: boolean): void {
  if (!ok) refuse('net.send-permit', 'a send-type request needs a send permit: job sends (eth_sendRawTransaction, Solana sendTransaction) one from assertJobSendAllowed or assertSendAllowed, every other send class (Turbo/Arweave/Esplora POST, bitcoind, requestAirdrop, query-string or non-JSON sends, ...) one from assertSendAllowed (src/config.ts); none was given, it does not cover this class, it is a local permit and the target is not loopback, or the object given is not one') // @guard:net.send-permit
}

// ---- exchanges

interface Raw { readonly status: number; readonly headers: Readonly<Record<string, string>>; readonly body: Uint8Array }

function flatten(h: IncomingHttpHeaders | Readonly<Record<string, unknown>>): Record<string, string> {
  const out: Array<[string, string]> = []
  for (const [k, v] of Object.entries(h)) {
    if (typeof v === 'string') out.push([k.toLowerCase(), v])
    else if (Array.isArray(v)) out.push([k.toLowerCase(), v.join(', ')])
  }
  return Object.fromEntries(out)
}

// One request over node:http(s). `agent` is the role's SOCKS agent, or null for a loopback request
// (then a one-off plain http.Agent: no pooling, no SOCKS). Not `agent: false`: Node builds that from
// the GLOBAL agent's class, which poisonGlobals replaces.
function exchangeNode(t: Target, p: Prepared, agent: SocksProxyAgent | null, ms: number): Promise<Raw> {
  return new Promise<Raw>((resolve, reject) => {
    let settled = false
    let socksStage = agent !== null // until the tunnel is up (the agent emits 'proxy' on the request)
    let timedOut = false
    let req: ClientRequest | null = null
    let res: IncomingMessage | null = null
    const finish = (produce: () => Raw): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      let out: Raw | undefined
      let err: unknown = null
      try { out = produce() } catch (e) { err = e }
      if (err !== null || out === undefined) { req?.destroy(); res?.destroy() }
      if (err !== null) reject(err)
      else if (out === undefined) reject(new Error('net: no outcome')) // only if a guard line were removed
      else resolve(out)
    }
    const fail = (): void => finish(() => requestFailed(t.host, timedOut, socksStage))
    const refuseWith = (e: unknown): void => finish(() => { throw e })
    const timer = setTimeout(() => { timedOut = true; fail() }, ms)

    const opts = { method: p.method, headers: p.headers, agent: agent ?? new HttpAgent({ keepAlive: false }), lookup: noLookup }
    try {
      req = (t.url.protocol === 'https:' ? httpsRequest : httpRequest)(t.url, opts, (r) => {
        res = r
        try {
          checkRedirect(r.statusCode ?? 0, t.host)
          // A HEAD answer declares the size of a body it does not send: not a body to cap.
          const declared = r.headers['content-length']
          if (declared !== undefined && p.method !== 'HEAD') checkSize(Number(declared), t.host)
        } catch (e) { refuseWith(e); return }
        const chunks: Buffer[] = []
        let size = 0
        r.on('data', (c: Buffer) => {
          if (settled) return
          size += c.length
          try { checkSize(size, t.host) } catch (e) { refuseWith(e); return }
          chunks.push(c)
        })
        r.on('end', () => finish(() => ({ status: r.statusCode ?? 0, headers: flatten(r.headers), body: new Uint8Array(Buffer.concat(chunks)) })))
        r.on('error', fail)
        r.on('close', () => { if (!r.complete) fail() })
      })
    } catch { fail(); return }
    req.on('proxy', () => { socksStage = false })
    req.on('error', fail)
    req.on('close', () => { if (res === null) fail() })
    req.end(p.body ?? undefined)
  })
}

const TIMEOUT = Symbol('timeout')

function isTransportResponse(v: unknown): v is Raw {
  return isRecord(v) && Number.isInteger(v.status) && (v.status as number) >= 100 && (v.status as number) <= 599
    && isRecord(v.headers) && Object.values(v.headers).every((x) => typeof x === 'string')
    && v.body instanceof Uint8Array
}

async function exchangeTransport(transport: Transport, t: Target, p: Prepared, socksUser: string | null, ms: number, real: () => Promise<Raw>): Promise<Raw> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const deadline = new Promise<typeof TIMEOUT>((res) => { timer = setTimeout(() => res(TIMEOUT), ms) })
  let out: unknown
  let thrown = false
  let error: unknown
  try {
    out = await Promise.race([
      transport({ method: p.method, url: t.url.href, headers: { ...p.headers }, body: p.body === null ? null : new Uint8Array(p.body), socksUser }, real),
      deadline,
    ])
  } catch (e) { thrown = true; error = e } finally { clearTimeout(timer) }
  if (thrown && error instanceof Refusal) throw error
  if (thrown) requestFailed(t.host, false, socksUser !== null)
  if (out === TIMEOUT) requestFailed(t.host, true, false)
  if (!isTransportResponse(out)) requestFailed(t.host, false, false)
  const r = out as Raw
  checkRedirect(r.status, t.host)
  checkSize(r.body.length, t.host)
  return { status: r.status, headers: flatten(r.headers), body: new Uint8Array(r.body) }
}

function response(raw: Raw, host: string): NetResponse {
  const { status, body } = raw
  return Object.freeze({
    status,
    headers: Object.freeze({ ...raw.headers }),
    text: async () => new TextDecoder().decode(body),
    json: async () => parseJson(body, status, host),
    bytes: async () => new Uint8Array(body),
  })
}

// ---- the factory

// tick -> the non-neutral side it has served, across every net instance (spec B s6.1 "Temporal
// separation"): a second instance with the same tick cannot serve the other side. Holds the newest
// tick and the OLDER_TICKS_KEPT before it (canonical ticks sort by time as strings).
const SIDES_BY_TICK = new Map<string, Set<Side>>()

// Drops every entry older than the newest tick and the OLDER_TICKS_KEPT before it.
function pruneSideTicks(): void {
  const ticks = [...SIDES_BY_TICK.keys()].sort()
  for (const t of ticks.slice(0, Math.max(0, ticks.length - (OLDER_TICKS_KEPT + 1)))) SIDES_BY_TICK.delete(t)
}

// Read-only (tests, diagnostics): the ticks the side guard remembers, oldest first.
export function sideTicks(): readonly string[] {
  return Object.freeze([...SIDES_BY_TICK.keys()].sort())
}

// The Transport seam exists for node --test (which sets NODE_TEST_CONTEXT in its test processes)
// or vitest. bin/vt-broadcast runs Node under env -i, so neither is ever set in production.
function testContext(): boolean {
  const set = (v: string | undefined) => v !== undefined && v !== ''
  return set(process.env.NODE_TEST_CONTEXT) || set(process.env.VITEST)
}

export function createNet(ctx: NetContext): TorNet {
  const c: Partial<NetContext> = isRecord(ctx) ? ctx : {}
  const socksPort = c.socksPort ?? DEFAULT_SOCKS_PORT
  const tickOk = isCanonicalTick(c.tick)
  if (!tickOk) refuse('net.tick-format', 'createNet: the tick must be the canonical ISO minute YYYY-MM-DDTHH:MMZ (e.g. 2026-10-08T03:15Z)') // @guard:net.tick-format
  const ctxOk = Number.isInteger(socksPort) && socksPort >= 1 && socksPort <= 65535
    && (c.maxTimeoutMs === undefined || (Number.isInteger(c.maxTimeoutMs) && c.maxTimeoutMs > 0))
    && (c.transport === undefined || typeof c.transport === 'function')
    && (c.random === undefined || typeof c.random === 'function')
  if (!ctxOk) refuse('net.ctx', 'createNet: socksPort 1-65535, maxTimeoutMs a positive integer, transport and random functions') // @guard:net.ctx
  const seamOk = c.transport === undefined || testContext()
  if (!seamOk) refuse('net.transport-test-only', 'createNet: the transport option is a test seam; it is refused outside a test runner') // @guard:net.transport-test-only
  const permit: unknown = c.permit
  requirePermit(permit === undefined || isSendPermit(permit))
  // The scope the permit covers, read once: 'all' admits every class, 'job' only job sends (I-1).
  const scope: 'all' | 'job' | null = permit !== undefined && isSendPermit(permit) ? permit.scope : null
  // C2 m2: a LOCAL permit is bound to the local destination class: send-type requests go to loopback targets only.
  const permitProfile: Profile | null = permit !== undefined && isSendPermit(permit) ? permit.profile : null
  const tick = c.tick as string
  const transport = c.transport
  const random = c.random ?? cryptoRandom
  const maxTimeoutMs = c.maxTimeoutMs
  if (transport === undefined) poisonGlobals()

  const log: NetEvent[] = []
  const agents = new Map<Role, SocksProxyAgent>()

  function claimSide(role: Role): void {
    const side = sideOf(role)
    if (side === 'neutral') return
    const other: Side = side === 'deposit' ? 'publication' : 'deposit'
    let sides = SIDES_BY_TICK.get(tick)
    if (sides === undefined) {
      const newer = [...SIDES_BY_TICK.keys()].filter((t) => t > tick).length
      const current = newer <= OLDER_TICKS_KEPT
      if (!current) refuse('net.tick-stale', `tick ${tick} is older than the side guard's window (the newest tick and the ${OLDER_TICKS_KEPT} before it); its sides can no longer be checked: use the current tick`) // @guard:net.tick-stale
      sides = new Set<Side>()
      SIDES_BY_TICK.set(tick, sides)
      pruneSideTicks()
    }
    const ok = !sides.has(other)
    if (!ok) refuse('net.tick-mixes-sides', `tick ${tick} already served ${other}-side roles; ${side}-side requests must wait for another tick`) // @guard:net.tick-mixes-sides
    sides.add(side)
  }

  function requireGate(role: Role, t: Target, p: Prepared): void {
    const exempt = role === 'check' && t.url.href === TOR_CHECK_URL && p.method === 'GET'
    const ok = gatePassedFor(self) || exempt
    if (!ok) refuse('net.gate-required', 'the Tor gate has not passed in this run: no request goes over SOCKS before it (loopback endpoints need no Tor)') // @guard:net.gate-required
  }

  // One agent per (role, tick) with a fresh random password; keep-alive off.
  function agentFor(role: Role, user: string): SocksProxyAgent {
    let a = agents.get(role)
    if (a === undefined) {
      const password = randomBytes(8).toString('hex')
      a = new SocksProxyAgent(`socks5h://${encodeURIComponent(user)}:${password}@${SOCKS_HOST}:${socksPort}`, {
        keepAlive: false,
        timeout: TIMEOUT_ONION_MS,
        socketOptions: { lookup: noLookup },
      })
      agents.set(role, a)
    }
    return a
  }

  function fetchFor(role: Role): NetFetch {
    assertRole(role)
    claimSide(role)
    const socksUser = `${role}.${tick}`
    return async (url: string, init?: NetInit): Promise<NetResponse> => {
      const t = classify(url)
      const p = prepared(init)
      const cls = sendClass(t, p)
      requirePermit(cls === 'read' || ((scope === 'all' || (cls === 'job' && scope === 'job')) && (permitProfile !== 'local' || t.kind === 'loopback')))
      const direct = t.kind === 'loopback'
      if (!direct) requireGate(role, t, p)
      const user = direct ? null : socksUser
      log.push(Object.freeze({ role, socksUser: user, host: t.host, atyp: direct ? 'loopback' : 'domain' }))
      const ms = timeoutFor(t.url.href, maxTimeoutMs)
      const real = (): Promise<Raw> => exchangeNode(t, p, direct ? null : agentFor(role, socksUser), ms)
      const raw = transport !== undefined ? await exchangeTransport(transport, t, p, user, ms, real) : await real()
      return response(raw, t.host)
    }
  }

  function jsonRpc(role: Role, url: string): Eip1193 {
    const f = fetchFor(role)
    const { host } = classify(url)
    let nextId = 0
    return Object.freeze({
      async request(args: RequestArguments): Promise<unknown> {
        const a: Partial<RequestArguments> = isRecord(args) ? args : {}
        const params = a.params ?? []
        let body: string | null = null
        try { body = JSON.stringify({ jsonrpc: '2.0', id: nextId + 1, method: a.method, params }) } catch { body = null }
        shape(typeof a.method === 'string' && RPC_METHOD.test(a.method) && typeof params === 'object' && params !== null && body !== null)
        const id = ++nextId
        const res = await f(url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: body as string })
        checkRpcStatus(res.status, host)
        return rpcResult(await res.json(), id, host)
      },
    })
  }

  async function jitter(maxMs: number): Promise<number> {
    const r = random()
    const ok = Number.isInteger(maxMs) && maxMs >= 0 && maxMs <= JITTER_MAX_MS && typeof r === 'number' && r >= 0 && r < 1
    if (!ok) refuse('net.jitter', 'jitter: maxMs must be an integer in [0, 3600000] and random() must return a number in [0, 1)') // @guard:net.jitter
    const ms = Math.floor(r * (maxMs + 1))
    await new Promise<void>((res) => setTimeout(res, ms))
    return ms
  }

  const self: TorNet = Object.freeze({
    tick,
    socksPort,
    fetchFor,
    jsonRpc,
    jitter,
    events: (): readonly NetEvent[] => Object.freeze(log.slice()),
    gatePassed: (): boolean => gatePassedFor(self),
  })
  return self
}

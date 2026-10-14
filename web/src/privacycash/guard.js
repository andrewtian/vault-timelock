// The worker's ONLY way to the network (plan W6, research D6). Every SDK request goes through createGuardedFetch:
//   · an absolute https://api3.privacycash.org URL (the SDK's hard-coded default) is REWRITTEN to /relay/privacycash/relayer/…;
//   · anything not on the route table (limits.js ROUTES) with its own method and query form is refused before a byte leaves
//     the worker (the relay and the CSP check the same thing again);
//   · only Content-Type (and, on /withdraw, the lane authorization) is sent: no cookies, no referrer, no cache, no redirects;
//   · the lane authorization (v2, single-use, bound to the sha256 of the exact withdrawal body) is minted at the moment the SDK posts the
//     body: the guard hashes the body it is about to send, asks the API (POST /api/jobs/<job>/privacycash/lane, the one request that is not
//     a relay route), checks the answer names this job, try, recipient and body hash, and only then sends. A refusal of the API (for example
//     api.pc-lock on mainnet: the funding lock) is kept like a relay refusal and nothing leaves;
//   · every request has a timeout (the relay's per-route timeout + 5 s) joined with the caller's own abort signal;
//   · /withdraw is recorded: `sent` BEFORE the request leaves (a stop after that point may have moved funds), the signature
//     from the answer after it, and a relay refusal ({error:{guard,message}}) is kept so the page can name it (the SDK would
//     throw "[object Object]").
// Error messages never contain the URL, a query, a body or an address: those hold commitments, ciphertexts and the recipient.
import { LANE_HEADER, ROUTES, SDK_RELAYER_URL, UPSTREAM_ORIGIN } from './limits.js'

const QUERY = {
  range: /^\?start=\d{1,9}&end=\d{1,9}$/,
  proof: /^\?commitments=\d{1,78},\d{1,78}$/,
}
const blocked = (why) => new TypeError(`privacycash: blocked request (${why})`)
const SIG = /^[1-9A-HJ-NP-Za-km-z]{64,100}$/
const CANON = '(?:0|[1-9][0-9]{0,17})'
const AUTH_RE = new RegExp(`^v2\\.([1-9A-HJ-NP-Za-km-z]{32,44})\\.([0-9a-f]{16})\\.(${CANON})\\.(${CANON})\\.([0-9a-f]{32})\\.([0-9a-f]{64})\\.(${CANON})\\.([0-9a-f]{64})$`)
const MINT_TIMEOUT_MS = 30_000
async function sha256Hex(text) {
  const d = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))
  return Array.from(d, (b) => b.toString(16).padStart(2, '0')).join('')
}
// -> a validated lane request or null: { job: 16 hex, tryIndex: 0..1000000, allowance: lamports (a safe integer >= 1), recipient: base58 }
function laneOf(r) {
  if (!r || typeof r !== 'object') return null
  const { job, tryIndex, allowance, recipient } = r
  if (typeof job !== 'string' || !/^[0-9a-f]{16}$/.test(job)) return null
  if (!Number.isSafeInteger(tryIndex) || tryIndex < 0 || tryIndex > 1_000_000) return null
  if (!Number.isSafeInteger(allowance) || allowance < 1) return null
  if (typeof recipient !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(recipient)) return null
  return { job, tryIndex, allowance, recipient }
}

export function createGuardedFetch({ origin, native, timeout = (ms) => AbortSignal.timeout(ms) }) {
  const events = {}                      // events.sent(): called once per /withdraw request, just before it leaves
  const state = { lane: null, withdrawSent: false, signature: null, refusal: null, requests: 0 }
  // The lane authorization for THIS body: one POST to the API's mint, then every field of the answer is checked against what was asked.
  const mintAuthorization = async (lane, bodySha256) => {
    let res
    try {
      res = await native(`${origin}/api/jobs/${lane.job}/privacycash/lane`, {
        method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ bodySha256, allowanceLamports: String(lane.allowance), tryIndex: lane.tryIndex }),
        credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', mode: 'same-origin', signal: timeout(MINT_TIMEOUT_MS),
      })
    } catch { throw blocked('withdraw: the API could not be reached for the lane authorization') }
    let j = null
    try { j = await res.json() } catch { /* not JSON */ }
    if (!res.ok) {
      const e = j && typeof j === 'object' ? j.error : null
      state.refusal = { status: res.status, guard: e && typeof e.guard === 'string' ? e.guard.slice(0, 64) : 'api.http', message: e && typeof e.message === 'string' ? e.message.slice(0, 300) : `HTTP ${res.status}` }
      throw blocked('withdraw: the API refused the lane authorization')
    }
    const a = j && typeof j.authorization === 'string' ? j.authorization : null
    const m = a === null ? null : AUTH_RE.exec(a)
    if (m === null || m[1] !== lane.recipient || m[2] !== lane.job || Number(m[3]) !== lane.tryIndex || BigInt(m[4]) < BigInt(lane.allowance) || m[6] !== bodySha256) throw blocked('withdraw: the API answered another authorization than asked for')
    return a
  }
  const guarded = async (input, init = {}) => {
    const rawUrl = typeof input === 'string' ? input : input instanceof URL ? input.href : input && typeof input.url === 'string' ? input.url : null
    if (rawUrl === null) throw blocked('not a URL')
    let u
    try { u = new URL(rawUrl, origin) } catch { throw blocked('not a URL') }
    if (u.origin === UPSTREAM_ORIGIN) u = new URL(origin + SDK_RELAYER_URL + u.pathname + u.search)   // belt and braces: the SDK's default host
    if (u.origin !== origin || u.hash !== '' || u.username !== '' || u.password !== '') throw blocked('not this page')
    const route = ROUTES.find((r) => r.re.test(u.pathname))
    if (!route) throw blocked('no such route')
    const method = String(init.method ?? (typeof input === 'object' && input && 'method' in input ? input.method : 'GET')).toUpperCase()
    if (method !== route.method) throw blocked(`${route.kind}: method`)
    const wantQuery = QUERY[route.kind]
    if (wantQuery ? !wantQuery.test(u.search) : u.search !== '') throw blocked(`${route.kind}: query`)
    const body = init.body
    if (route.method === 'GET' ? body != null : typeof body !== 'string') throw blocked(`${route.kind}: body`)
    const headers = new Headers()
    if (route.method === 'POST') headers.set('content-type', 'application/json')
    if (route.kind === 'withdraw') {
      if (state.lane === null) throw blocked('withdraw: no lane authorization')
      headers.set(LANE_HEADER, await mintAuthorization(state.lane, await sha256Hex(body)))
      state.withdrawSent = true
      try { events.sent?.() } catch { /* a listener must not stop the request */ }
    }
    const signals = [timeout(route.timeoutMs)]
    if (init.signal) signals.push(init.signal)
    state.requests += 1
    const res = await native(u.href, {
      method, headers, body: body ?? undefined, credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', mode: 'same-origin',
      signal: signals.length === 1 ? signals[0] : AbortSignal.any(signals),
    })
    if (route.kind === 'withdraw') {
      let j = null
      try { j = await res.clone().json() } catch { /* not JSON */ }
      if (res.ok && j && typeof j.signature === 'string' && SIG.test(j.signature)) state.signature = j.signature
      if (!res.ok) {
        const e = j && typeof j === 'object' ? j.error : null
        state.refusal = { status: res.status, guard: e && typeof e.guard === 'string' ? e.guard.slice(0, 64) : 'relay.http', message: e && typeof e.message === 'string' ? e.message.slice(0, 300) : `HTTP ${res.status}` }
      }
    }
    return res
  }
  return {
    fetch: guarded,
    state,
    events,
    setLane(request) { state.lane = laneOf(request) },
    reset() { state.withdrawSent = false; state.signature = null; state.refusal = null },
  }
}

// @ts-check
// PORTED (R69) from the prototype, tag add7b-e540f8ae4d6b, relay-core.mjs (sha256 7fa70ca86b733c9aa299bf62a59359106604c00a1b32cfe0a5d5b5e28ec27e05).
// Changes: `// @ts-check` and JSDoc types only (the logic is byte-for-byte the prototype's; test/relay-core.test.mjs is
// the prototype's test with only its import path changed). S6: createTor takes an optional `roles` list (default ROLES,
// so the prototype's behaviour and test are unchanged): the relay adds a role per breadth service it serves (btc,
// blockscout, arweave, drand), each its own circuit like eth and sol.
//
// Task MQ relay core — Tor circuit control + the forward/retry policy, transport injected (unit-tested by
// test/relay-core.test.mjs). relay.mjs wires it to the real SOCKS transport and the HTTP server.
//
// Circuits: every role (eth, sol, price, check) has its own random session and a generation counter; its SOCKS username
// is `<role>.<session>.<gen>` and Tor (IsolateSOCKSAuth) gives each distinct username its own circuit. Roles never share
// a username; a new circuit = gen + 1 (never reused).
// Auto-rotate (default on): on upstream 403/429/451/5xx, a SOCKS failure or a timeout, bump the role's gen and retry the
// SAME request once, then fail over to the next endpoint. A SEND (eth_sendRawTransaction / sendTransaction) is retried or
// failed over ONLY when the failure proves the tx was not accepted (403/429/451 or a SOCKS failure, i.e. refused before
// processing / never delivered); a timeout, 5xx or reset on a send is returned as ambiguous and never re-sent here.
import { randomBytes } from 'node:crypto'
/** @typedef {'eth' | 'sol' | 'price' | 'check' | 'btc' | 'blockscout' | 'arweave' | 'drand' | 'privacycash' | 'privacycash-rpc'} Role */
/** @typedef {{ status: number, body?: Buffer }} UpstreamRes */
/** @typedef {Error & { code?: string, socks?: boolean }} UpstreamErr */
/** @typedef {{ session: string, gen: number, since: number, lastManual: number, lastStatus: string | null, lastError: string | null, okCount: number, failCount: number }} RoleState */
/** @typedef {{ auto: boolean, isTor: boolean | null, checkedAt: number | null }} TorState */
/**
 * @typedef {object} Tor
 * @property {string | undefined} profile
 * @property {Record<Role, RoleState>} roles
 * @property {TorState} state
 * @property {boolean} tor
 * @property {(r: Role) => string} username
 * @property {(r: Role) => number} bump
 * @property {(r: Role) => ({ ok: true, gen: number } | { ok: false, retryInSec: number, gen: number })} manual
 * @property {(r: Role, kind: string, label: string) => void} record
 * @property {() => { profile: string | undefined, tor: boolean, isTor: boolean | null, checkedAt: number | null, auto: boolean, roles: Record<string, { gen: number, ageSec: number, lastStatus: string | null, lastError: string | null, okCount: number, failCount: number }> }} status
 */
/** @type {Role[]} */
export const ROLES = ['eth', 'sol', 'price', 'check']
export const SEND_METHODS = new Set(['eth_sendRawTransaction', 'sendTransaction'])
export const REFUSED = new Set([403, 429, 451])
export const MANUAL_ROTATE_MS = 10000
export const TIMEOUT_MS = 20000

const ipFree = (/** @type {unknown} */ s) => String(s).replace(/\b\d{1,3}(\.\d{1,3}){3}\b|\[?[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}\]?/gi, '[addr]')
/** @param {UpstreamErr | null | undefined} err */
export function errLabel(err) {
  if (!err) return 'error'
  if (err.name === 'SocksClientError') return ipFree(`SOCKS ${(/- ?(\w[\w ]*)$/.exec(err.message) || [])[1] || 'failure'}`)
  return ipFree(err.code || err.name || 'error')
}
// ok | refused (403/429/451) | server (5xx) | socks (handshake failed: never delivered) | timeout | transport (other)
/** @param {UpstreamRes | undefined} res @param {UpstreamErr} [err] */
export function classify(res, err) {
  if (err) {
    if (err.code === 'ETIMEDOUT') return 'timeout'
    if (err.name === 'SocksClientError' || (err.code === 'ECONNREFUSED' && err.socks !== false)) return 'socks'
    return 'transport'
  }
  if (REFUSED.has(/** @type {UpstreamRes} */ (res).status)) return 'refused'
  if (/** @type {UpstreamRes} */ (res).status >= 500) return 'server'
  return 'ok'
}

/**
 * @param {{ profile?: string, tor?: boolean, now?: () => number, rand?: () => string, roles?: readonly Role[] }} [o]
 * @returns {Tor}
 */
export function createTor({ profile, tor = profile !== 'local', now = () => Date.now(), rand = () => randomBytes(6).toString('hex'), roles: names = ROLES } = {}) {
  const roles = /** @type {Record<Role, RoleState>} */ (Object.fromEntries(names.map((r) => [r, { session: rand(), gen: 0, since: now(), lastManual: -Infinity, lastStatus: null, lastError: null, okCount: 0, failCount: 0 }])))
  /** @type {TorState} */
  const state = { auto: true, isTor: null, checkedAt: null }
  /** @type {Tor} */
  const t = {
    profile, roles, state, tor,
    username: (r) => `${r}.${roles[r].session}.${roles[r].gen}`,
    bump(r) { const s = roles[r]; s.gen += 1; s.since = now(); return s.gen },
    manual(r) {   // operator "New circuit": at most 1 per role per 10 s
      const s = roles[r], wait = s.lastManual + MANUAL_ROTATE_MS - now()
      if (wait > 0) return { ok: false, retryInSec: Math.ceil(wait / 1000), gen: s.gen }
      s.lastManual = now(); return { ok: true, gen: t.bump(r) }
    },
    record(r, kind, label) { const s = roles[r]; if (kind === 'ok') { s.okCount++; s.lastStatus = label } else { s.failCount++; s.lastStatus = label; s.lastError = label } },
    status() {
      return { profile, tor: t.tor, isTor: state.isTor, checkedAt: state.checkedAt, auto: state.auto,
        roles: Object.fromEntries(names.map((r) => { const s = roles[r]; return [r, { gen: s.gen, ageSec: Math.max(0, Math.round((now() - s.since) / 1000)), lastStatus: s.lastStatus, lastError: s.lastError, okCount: s.okCount, failCount: s.failCount }] })) }
    },
  }
  return t
}

// One upstream exchange with the retry policy above. doRequest(url, username) → { status, body } or throws.
// Returns { res } | { ambiguous, label } (send: outcome unknown) | { failed, notAccepted, label }.
/**
 * @param {Tor} t
 * @param {{ role: Role, endpoints: string[], send?: boolean, doRequest: (url: string, user: string) => Promise<UpstreamRes>, log?: (l: string) => void, clock?: () => number }} o
 * @returns {Promise<{ res: UpstreamRes, ambiguous?: undefined, failed?: undefined, notAccepted?: undefined, label?: undefined } | { ambiguous: true, label: string, res?: undefined, failed?: undefined, notAccepted?: undefined } | { failed: true, notAccepted: boolean, label: string, res?: undefined, ambiguous?: undefined }>}
 */
export async function exchange(t, { role, endpoints, send = false, doRequest, log = () => {}, clock = () => Date.now() }) {
  let last = { kind: 'transport', label: 'no endpoint' }, allNotAccepted = true
  for (const url of endpoints) {
    for (let attempt = 0; attempt < 2; attempt++) {
      const gen = t.roles[role].gen, t0 = clock()
      /** @type {UpstreamRes | undefined} */ let res
      /** @type {UpstreamErr | undefined} */ let err
      try { res = await doRequest(url, t.username(role)) } catch (e) { err = /** @type {UpstreamErr} */ (e) }
      const kind = classify(res, err), label = res ? `HTTP ${res.status}` : errLabel(err)
      t.record(role, kind, label)
      if (kind === 'ok') return { res: /** @type {UpstreamRes} */ (res) }
      last = { kind, label }
      const notAccepted = kind === 'refused' || kind === 'socks'
      if (!notAccepted) allNotAccepted = false
      if (send && !notAccepted) return { ambiguous: true, label }        // never retried, never failed over
      if (t.tor && t.state.auto && attempt === 0) { const g = t.bump(role); log(`tor ${role} gen ${gen}→${g} ${res ? res.status : label} ${clock() - t0}ms`); continue }
      break
    }
  }
  return { failed: true, notAccepted: allNotAccepted, label: last.label }
}

// @ts-check
// PORTED (R69) from the prototype, tag add7-00927d6ade7f, src/mainnet/rpc.js (sha256 38cfedb35a03b68eb70558bbc124904173465e92a477c03d457ea1478a807191).
// Same-origin JSON-RPC client for the Tor-confined relay (Vite proxies /relay/* → 127.0.0.1:5175).
// Failure kinds matter for "never double-send":
//   RpcError       — upstream answered with a JSON-RPC error: definitive (e.g. a send was rejected).
//   RelayRefused   — the relay refused BEFORE forwarding (403/413/503): definitive, nothing left the machine.
//   TransportError — no definitive answer (relay/Vite down, timeout, all endpoints failed): a send's outcome is UNKNOWN.
// Canonical (E2, spec §7.2): rpc() takes { ticket, ep }. The ticket (the relay send ticket of an acked intent) travels in
// header x-vt-send-ticket; ep picks one verified endpoint (/relay/<chain>/ep/<i>: reads — the I3 expiry proof, the E5 nonce
// quorum — and, on sol only, ticketed sends, once per ticket per endpoint (Sfix1); ETH per-endpoint routes stay read-only).
// The send gate itself is gates/send.ts, called by the chain modules' send functions.
import { TICKET_HEADER } from '../contracts/index.ts'
/** @typedef {import('../chains/types.ts').Json} Json */
/** @typedef {(url: string, init: RequestInit) => Promise<Response>} RelayFetch */
export class RpcError extends Error {
  /** @param {{ code: number, message: string }} e */
  constructor(e) { super(`${e.code}: ${e.message}`); this.rpc = e }
}
export class RelayRefused extends Error {}
export class TransportError extends Error {}
let seq = 1
// The relay client is injectable (R64 heads-up: a Node CLI drives the same lane runner): the browser uses the same-origin
// path; Node sets { base: 'http://127.0.0.1:5175', fetch }. No DOM APIs here.
/** @type {{ base: string, fetch: RelayFetch }} */
const relay = { base: '', fetch: (url, init) => globalThis.fetch(url, init) }
// E3: the executor hands its RelayClient to the engine (useRelayClient); its rpc keeps these error classes. A
// configureRelay call (tests, the ported entry points) goes back to plain HTTP at that base.
/** @typedef {{ rpc(chain: 'eth' | 'sol' | 'btc', method: string, params: unknown[], o?: { ticket?: string, ep?: number }): Promise<unknown> }} RpcClient */
/** @type {RpcClient | null} */
let client = null
/** @param {{ base?: string, fetch?: RelayFetch }} [_o] */
export function configureRelay({ base, fetch } = {}) { if (base != null) relay.base = base; if (fetch) relay.fetch = fetch; client = null }
/** @param {RpcClient | null} c */
export function useRelayClient(c) { client = c }
/** @param {string} chain @param {unknown} ep */
function checkRoute(chain, ep) {
  if (chain !== 'eth' && chain !== 'sol' && chain !== 'btc') throw new TypeError('rpc: chain must be eth, sol or btc')
  if (ep != null && !(Number.isSafeInteger(ep) && /** @type {number} */ (ep) >= 0 && /** @type {number} */ (ep) < 16)) throw new TypeError('rpc: ep must be an endpoint index')
  if (chain === 'btc' && ep != null) throw new TypeError('rpc: btc has no per-endpoint route')
}
// One JSON-RPC request to the relay at cfg.base (the one HTTP implementation: rpc() and the executor's httpRelayClient).
/** @param {{ base: string, fetch: RelayFetch }} cfg @param {string} chain @param {string} method @param {unknown[]} [params] @param {{ ticket?: string, ep?: number | null }} [o] @returns {Promise<Json>} */
export async function relayRpc(cfg, chain, method, params = [], { ticket, ep } = {}) {
  checkRoute(chain, ep)
  /** @type {Record<string, string>} */
  const headers = { 'content-type': 'application/json' }
  if (ticket !== undefined) headers[TICKET_HEADER] = ticket
  // E7: the ticketed BTC send is not JSON-RPC: POST /relay/btc/send { hex } answers { txid } (spec 6.1 change 9). Every failure
  // is TransportError or RelayRefused, never RpcError: bitcoind answers HTTP 200 for JSON-RPC errors and the relay turns them into
  // 502, a rejection after an accepted send is a refusal (relay.btc-prevout), so no answer here proves "not sent" (reconcile by txid).
  if (chain === 'btc' && method === 'btc_send') {
    let sr
    try {
      sr = await cfg.fetch(`${cfg.base}/relay/btc/send`, { method: 'POST', cache: 'no-store', headers, body: JSON.stringify({ hex: params[0] }) })
    } catch (e) { throw new TransportError(`relay unreachable (${/** @type {Error} */ (e).message})`) }
    let sj; try { sj = await sr.json() } catch { throw new TransportError(`relay HTTP ${sr.status} (no JSON)`) }
    if ([403, 413, 503].includes(sr.status)) throw new RelayRefused(`relay refused (${sr.status}): ${sj?.error?.message || ''}`)
    if (sr.status !== 200 || typeof sj?.txid !== 'string') throw new TransportError(`relay HTTP ${sr.status}: ${String(sj?.error?.message ?? 'no txid').slice(0, 120)}`)
    return sj.txid
  }
  let r
  try {
    r = await cfg.fetch(`${cfg.base}/relay/${chain}${ep != null ? `/ep/${ep}` : ''}`, { method: 'POST', cache: 'no-store', headers,
      body: JSON.stringify({ jsonrpc: '2.0', id: seq++, method, params }) })
  } catch (e) { throw new TransportError(`relay unreachable (${/** @type {Error} */ (e).message})`) }
  let j; try { j = await r.json() } catch { throw new TransportError(`relay HTTP ${r.status} (no JSON)`) }
  if ([403, 413, 503].includes(r.status)) throw new RelayRefused(`relay refused (${r.status}): ${j?.error?.message || ''}`)
  if (r.status === 502 && [-32098, -32099].includes(j?.error?.code)) throw new TransportError(`relay: ${j.error.message}`)
  if (j?.error) throw new RpcError(j.error)
  if (!j || !('result' in j)) throw new TransportError(`relay HTTP ${r.status} (no result)`)
  return j.result
}
/** @param {string} chain @param {string} method @param {unknown[]} [params] @param {{ ticket?: string, ep?: number | null }} [o] @returns {Promise<Json>} */
export async function rpc(chain, method, params = [], o = {}) {
  checkRoute(chain, o.ep)
  if (client !== null) return client.rpc(/** @type {'eth' | 'sol' | 'btc'} */ (chain), method, params, { ...(o.ticket !== undefined ? { ticket: o.ticket } : {}), ...(o.ep != null ? { ep: o.ep } : {}) })
  return relayRpc(relay, chain, method, params, o)
}
export const ethRpc = (/** @type {string} */ m, /** @type {unknown[]} */ p) => rpc('eth', m, p)
export const solRpc = (/** @type {string} */ m, /** @type {unknown[]} */ p) => rpc('sol', m, p)
export const btcRpc = (/** @type {string} */ m, /** @type {unknown[]} */ p) => rpc('btc', m, p)

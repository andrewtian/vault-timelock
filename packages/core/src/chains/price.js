// @ts-check
// PORTED (R69) from the prototype, tag add7-00927d6ade7f, src/mainnet/price.js (sha256 3381dd691d5df689934d36085ee15f6759cc8c2669ef4a9d70b9ea14913e261d);
// P2 delta (E3, tag add7b-e540f8ae4d6b): testnet has no price ("test funds — no value").
// Latest Jupiter price, fetched ONLY by the relay through Tor (GET /relay/price). The browser never contacts jup.ag.
// Fail closed: missing or older than PRICE.MAX_AGE_MS → USD entry is disabled (native entry still works).
// Canonical change (E3): no browser-relative URL — the caller injects { base, fetch } (the page: base '' through its own
// origin; the CLI: http://127.0.0.1:<relay port>), or uses the executor's RelayClient.price(). A testnet answer — the
// relay's nominal fixture labelled TEST FUNDS — NO VALUE, or the prototype's { none: true } — is never a price: the caps
// use the R60 native fallback.
import { PRICE, TEST_FUNDS_LABEL } from './constants.js'
/** @typedef {import('./types.ts').PriceData} PriceData */
/** @param {{ base: string, fetch: (url: string, init?: RequestInit) => Promise<Response> }} o @returns {Promise<PriceData>} */
export async function fetchPrice(o) {
  if (!o || typeof o.fetch !== 'function' || typeof o.base !== 'string') throw new TypeError('fetchPrice: inject { base, fetch } (no browser-relative URL)')
  let r; try { r = await o.fetch(`${o.base}/relay/price`, { cache: 'no-store' }) } catch (e) { throw new Error(`relay unreachable (${/** @type {Error} */ (e).message})`) }
  const j = await r.json().catch(() => null)
  if (r.ok && j?.none) return j                                   // the prototype's testnet answer: { none: true, source }
  if (!r.ok || !j?.prices) throw new Error(j?.error?.message || `relay HTTP ${r.status}`)
  return j
}
// Test funds: the testnet relay's nominal fixture, or the prototype's { none: true }.
/** @param {any} p */
export const isTestFunds = (p) => !!p && (p.none === true || (p.fixture === true && typeof p.source === 'string' && p.source.toUpperCase().includes('TEST FUNDS')))
/** @param {PriceData | null | undefined} p @param {number} [now] @returns {{ ok: true, age: number, why?: undefined, none?: undefined } | { ok: false, why: string, age?: undefined, none?: boolean }} */
export function priceStatus(p, now = Date.now()) {
  if (!p) return { ok: false, why: 'no price yet' }
  if (isTestFunds(p)) return { ok: false, none: true, why: `${TEST_FUNDS_LABEL} (no price on testnet)` }
  const age = now - p.fetchedAt
  if (!(age >= -5000)) return { ok: false, why: 'price timestamp is in the future' }
  if (age > PRICE.MAX_AGE_MS) return { ok: false, why: `price is ${Math.round(age / 1000)} s old (limit ${PRICE.MAX_AGE_MS / 1000} s)` }
  const ok = (/** @type {any} */ x) => Number.isFinite(x?.usd) && x.usd > 0
  if (!ok(p.prices?.SOL) || !ok(p.prices?.ETH)) return { ok: false, why: 'price missing for SOL or ETH' }
  const thin = [p.prices.SOL, p.prices.ETH].find((x) => x.liquidity != null && !(x.liquidity >= PRICE.MIN_LIQUIDITY_USD))
  if (thin) return { ok: false, why: `liquidity below $1M for ${thin.mint.slice(0, 6)}…` }
  return { ok: true, age: Math.max(0, Math.round(age / 1000)) }
}

// @ts-check
// PORTED (R69) from the prototype, tag add7-00927d6ade7f, src/mainnet/plan.js (sha256 9a2937f9afdde64a9f914c3182919549f4ce207657dcecf7ee91772f480d0bf3).
// Pure functions (no I/O): part splitting, copies ↔ amount, USD ↔ native, blockspace, fee math.
// Unit-tested by test/plan.test.mjs (node --test). All money is integer base units (wei / lamports / US cents).
// Canonical changes (E2; the ported tests' adjustments are marked `R72` / `fork` in test/ported/plan.test.mjs):
//   · R72 parts: the header is the contract's vt-parts/1 (contracts/parts.ts partPrefix), not the prototype's `[i/n] `;
//     the copy marker goes into the header line (copy, copies), so every copy carries the same text and digest;
//     the WRITER RULE (Task 0 ruling, CC-1a): a one-part text whose own first line parses as a header gets the explicit
//     [1/1 <h8> sha256=<64hex>] header (partPrefix force) — only when no other header line (a copy marker) precedes it.
//   · reassembleCopy: the reader rules of contracts/parts.ts over chain bytes.
//   · gas: an optional `rule` { amsterdam, toSelf } selects the exact fork- and recipient-aware formula
//     (contracts/gas.ts; publication-modes-elite.md §6); without it MQ's max(21000+40n, 12000+64n). The engine always
//     passes a rule.
import { DECIMALS, ETH, PLAN, SOL } from './constants.js'
import { ESTIMATE_TOL, ethDataGas, parsePart, partPrefix } from '../contracts/index.ts'
import { sha256Hex } from '../job/canonical.ts'

/** @typedef {import('./types.ts').Part} Part @typedef {import('./types.ts').PlanTx} PlanTx */
/** @typedef {(width: number) => number} CostFn */
/** @typedef {{ amsterdam: boolean, toSelf: boolean }} GasRule */
/** @typedef {{ copy?: number | null, copies?: number | null, sha256?: string | null }} PartOpts */
const enc = new TextEncoder()
export const utf8 = (/** @type {string} */ s) => enc.encode(s)
/** @param {...Uint8Array} parts */
export function concat(...parts) { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length } return out }
const max = (/** @type {bigint[]} */ ...xs) => xs.reduce((a, b) => (b > a ? b : a))

// ---------- splitting ----------
// Largest end ≤ start + room that does not cut a UTF-8 sequence (never stop before a continuation byte 10xxxxxx).
/** @param {Uint8Array} bytes @param {number} start @param {number} room */
export function cutAt(bytes, start, room) {
  let end = Math.min(bytes.length, start + room)
  if (end < bytes.length) while (end > start && (bytes[end] & 0xc0) === 0x80) end--
  return end
}
export const utf8Width = (/** @type {number} */ b) => (b < 0x80 ? 1 : b >= 0xf0 ? 4 : b >= 0xe0 ? 3 : 2)
// Like cutAt, and additionally stop before the summed per-character cost would exceed `budget` (Solana Memo v2 CU).
/** @param {Uint8Array} bytes @param {number} start @param {number} room @param {CostFn | undefined} cost @param {number} budget */
export function cutPart(bytes, start, room, cost, budget) {
  if (!cost) return cutAt(bytes, start, room)
  let end = start, w = 0
  while (end < bytes.length) {
    const width = utf8Width(bytes[end])
    if (end + width - start > room || w + cost(width) > budget) break
    w += cost(width); end += width
  }
  return end
}
export const weigh = (/** @type {Uint8Array} */ bytes, /** @type {CostFn} */ cost) => { let w = 0; for (let i = 0; i < bytes.length; i += utf8Width(bytes[i])) w += cost(utf8Width(bytes[i])); return w }
// Split text bytes into as FEW parts as possible, each as LARGE as possible:
// payload_i = lead + header(i, n) + chunk_i, |payload_i| ≤ cap, and (optional) weigh(payload_i) ≤ budget.
// header = contracts/parts.ts partPrefix (vt-parts/1, R72): none for n = 1 (unless a copy marker or the writer rule),
// [1/N <h8> sha256=…]\n on part 1 and [k/N <h8>]\n on part k, with the copy marker inside the line for copies ≥ 2.
// While a pass has more parts than n, a part's header is sized as if n were i (never narrower than the final one).
/** @param {Uint8Array} textBytes @param {{ lead?: Uint8Array, cap: number, cost?: CostFn, budget?: number } & PartOpts} _o @returns {Part[]} */
export function splitText(textBytes, { lead = new Uint8Array(0), cap, cost, budget = Infinity, copy = null, copies = null, sha256 = null }) {
  const sha = sha256 ?? sha256Hex(textBytes)
  /** @type {boolean | null} */
  let force = null   // the writer rule, decided once (only a one-part plan can need it)
  const header = (/** @type {number} */ i, /** @type {number} */ n) => {
    const h = { part: i, parts: Math.max(n, i), sha256: sha, copy, copies }
    if (h.parts > 1 || partPrefix(h) !== '') return partPrefix(h)
    force ??= parsePart(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(textBytes)).headerLength > 0
    return partPrefix(h, { force })
  }
  let n = 1
  for (let guard = 0; guard < 64; guard++) {
    /** @type {Uint8Array[]} */
    const chunks = []; let off = 0
    do {
      const pfx = utf8(header(chunks.length + 1, n))
      const room = cap - lead.length - pfx.length
      if (room < 4) throw new Error(`part capacity ${room} B is too small`)
      const end = cutPart(textBytes, off, room, cost, cost ? budget - weigh(concat(lead, pfx), cost) : Infinity)
      if (end === off && off < textBytes.length) throw new Error('cannot split')
      chunks.push(textBytes.subarray(off, end)); off = end
    } while (off < textBytes.length)
    if (chunks.length === n) return chunks.map((c, k) => ({ i: k + 1, n, chunk: c, payload: concat(lead, utf8(header(k + 1, n)), c) }))
    n = chunks.length   // widening the header can only add parts, so this converges upward
  }
  throw new Error('part split did not converge')
}
export const ethParts = (/** @type {Uint8Array} */ textBytes, /** @type {PartOpts} */ o = {}) => splitText(textBytes, { lead: utf8(ETH.PREFIX), cap: ETH.TX_DATA_CAP, ...o })
export const solCharCu = (/** @type {number} */ width) => SOL.CU_PER_CHAR[width]
export const solParts = (/** @type {Uint8Array} */ textBytes, /** @type {number} */ maxMemo, /** @type {PartOpts} */ o = {}) => splitText(textBytes, { cap: Math.min(SOL.MEMO_MAX, maxMemo), cost: solCharCu, budget: SOL.CU_PLAN_BUDGET - SOL.CU_BASE, ...o })
// R72 reassembly of ONE copy from chain bytes (raw calldata or memo bytes, in part order 1..N), by the reader rules of
// contracts/parts.ts: each payload starts with `lead` (ETH 'data:,'), decodes as UTF-8, carries the header of part k
// of N with the copy's h8 (part 1 the full digest), one copy index throughout; the bodies concatenate to the text whose
// sha256 is `sha256`. → { ok, sha256 (of what was reassembled, or null), why }
/** @param {Uint8Array[]} payloads @param {{ lead?: Uint8Array, sha256: string }} o @returns {{ ok: boolean, sha256: string | null, why: string }} */
export function reassembleCopy(payloads, { lead = new Uint8Array(0), sha256 }) {
  const dec = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }), n = payloads.length
  if (n < 1) return { ok: false, sha256: null, why: 'no parts' }
  /** @type {string[]} */
  const bodies = []; let copy = null
  for (let k = 1; k <= n; k++) {
    const b = payloads[k - 1]
    if (b.length < lead.length || lead.some((x, j) => b[j] !== x)) return { ok: false, sha256: null, why: `part ${k}: the payload does not start with the expected prefix` }
    let str; try { str = dec.decode(b.subarray(lead.length)) } catch { return { ok: false, sha256: null, why: `part ${k}: not valid UTF-8` } }
    const p = parsePart(str)
    const headerOk = n === 1 ? p.parts === 1 : p.parts === n && p.part === k && p.h8 === sha256.slice(0, 8) && (k > 1 || p.sha256 === sha256)
    if (!headerOk) return { ok: false, sha256: null, why: `part ${k} of ${n}: the header does not match` }
    if (copy !== null && p.copy !== copy) return { ok: false, sha256: null, why: `part ${k}: another copy's part` }
    copy = p.copy; bodies.push(p.body)
  }
  const got = sha256Hex(bodies.join(''))
  return { ok: got === sha256, sha256: got, why: got === sha256 ? '' : 'the reassembled text has another sha256' }
}
// N copies × parts, copy-major. `partsFor(i)` = the parts of copy i (they differ only when ETH copies are made distinct).
/** @param {Part[] | ((copy: number) => Part[])} partsOrFn @param {number} copies @returns {PlanTx[]} */
export function buildPlan(partsOrFn, copies) {
  const partsFor = typeof partsOrFn === 'function' ? partsOrFn : () => partsOrFn
  /** @type {PlanTx[]} */
  const txs = []
  for (let c = 1; c <= copies; c++) for (const p of partsFor(c)) txs.push({ k: txs.length, copy: c, part: p.i, parts: p.n, payload: p.payload, textBytes: p.chunk.length })
  return txs
}
// ETH option "make copies distinct (index every copy)": copies 2..N end with `\n[copy i/N]` (Ethscriptions index only the
// FIRST identical content; ESIP-6 cannot be combined with `data:,`). Default off = identical duplicates.
export const ethCopyText = (/** @type {string} */ text, /** @type {number} */ i, /** @type {number} */ n, /** @type {boolean} */ distinct) => (distinct && i > 1 ? text + PLAN.copySuffix(i, n) : text)

// ---------- decimals ----------
/** @param {unknown} s @param {number} decimals @returns {bigint} */
export function parseDecimal(s, decimals) {
  const m = /^(\d+)(?:\.(\d*))?$/.exec(String(s).trim())
  if (!m) throw new Error('not a decimal number')
  const frac = m[2] || ''
  if (frac.length > decimals) throw new Error(`more than ${decimals} decimals`)
  return BigInt(m[1]) * 10n ** BigInt(decimals) + BigInt((frac + '0'.repeat(decimals)).slice(0, decimals) || '0')
}
/** @param {bigint} v @param {number} decimals */
export function formatUnits(v, decimals) {
  const neg = v < 0n; let a = neg ? -v : v
  const s = a.toString().padStart(decimals + 1, '0')
  const int = s.slice(0, s.length - decimals), frac = s.slice(s.length - decimals).replace(/0+$/, '')
  return `${neg ? '-' : ''}${int}${frac ? '.' + frac : ''}`
}
// human value to 6 significant digits (display only; exact base units are shown next to it)
/** @param {bigint} v @param {number} decimals */
export function sig6(v, decimals) {
  if (v === 0n) return '0'
  const x = Number(formatUnits(v, decimals))
  return Number(x.toPrecision(6)).toLocaleString('en-US', { maximumSignificantDigits: 6, useGrouping: false })
}
// unit: 'eth' | 'sol' | 'usd' → { ok, value (base units / cents), error }
/** @param {unknown} s @param {'eth' | 'sol' | 'btc' | 'usd'} unit @returns {{ ok: true, value: bigint, error?: undefined } | { ok: false, error: string, value?: undefined }} */
export function validateAmount(s, unit) {
  if (s === '' || s == null) return { ok: false, error: 'empty' }
  /** @type {bigint} */
  let v
  try { v = parseDecimal(s, DECIMALS[unit]) } catch (e) { return { ok: false, error: `${/** @type {Error} */ (e).message}${unit === 'usd' ? '' : ` (max ${DECIMALS[unit]} for ${unit.toUpperCase()})`}` } }
  if (v <= 0n) return { ok: false, error: 'must be > 0' }
  return { ok: true, value: v }
}
/** @param {unknown} s @returns {{ ok: true, value: number, error?: undefined } | { ok: false, error: string, value?: undefined }} */
export function validateCopies(s) {
  if (!/^\d+$/.test(String(s).trim())) return { ok: false, error: 'whole number ≥ 1' }
  const n = Number(s); if (n < 1) return { ok: false, error: 'whole number ≥ 1' }
  return { ok: true, value: n }
}

// ---------- USD ↔ native (price = USD per 1 whole coin, a float from Jupiter) ----------
const P = 12   // price precision (decimals)
/** @param {unknown} price */
export function priceScaled(price) {
  if (typeof price !== 'number' || !Number.isFinite(price) || price <= 0) throw new Error('no price')
  return parseDecimal(price.toFixed(P), P)
}
// native base units for `cents` US cents, rounded UP to the next wei/lamport
/** @param {bigint} cents @param {number} price @param {number} decimals */
export function usdToBase(cents, price, decimals) {
  const num = cents * 10n ** BigInt(decimals) * 10n ** BigInt(P), den = priceScaled(price) * 100n
  return (num + den - 1n) / den
}
// US cents for `base` units, rounded UP to the next cent (an amount *needed*)
/** @param {bigint} base @param {number} price @param {number} decimals */
export function baseToCents(base, price, decimals) {
  const num = base * priceScaled(price) * 100n, den = 10n ** BigInt(decimals) * 10n ** BigInt(P)
  return (num + den - 1n) / den
}
export const centsToString = (/** @type {bigint} */ c) => `${c / 100n}.${String(c % 100n).padStart(2, '0')}`

// ---------- copies ↔ amount ----------
// reserve = what must stay untouched (SOL: rent-exempt minimum of the fee-payer account; ETH: 0)
/** @param {bigint} amount @param {bigint} perCopy @param {bigint} [reserve] */
export function copiesFromAmount(amount, perCopy, reserve = 0n) { return perCopy > 0n && amount > reserve ? (amount - reserve) / perCopy : 0n }
export const amountForCopies = (/** @type {number} */ n, /** @type {bigint} */ perCopy, reserve = 0n) => reserve + BigInt(n) * perCopy
export const leftover = (/** @type {bigint} */ amount, /** @type {number} */ n, /** @type {bigint} */ perCopy, reserve = 0n) => amount - reserve - BigInt(n) * perCopy

// ---------- ETH fees ----------
const ceilDiv = (/** @type {bigint} */ a, /** @type {bigint} */ b) => (a + b - 1n) / b
// gas for n calldata bytes = max over the fork formulas (21000+40n now; 12000+64n after Amsterdam). No ×1.2.
// With a rule (canonical): the exact formula of that fork and recipient (contracts/gas.ts ethDataGas).
export const ethGasFormula = (/** @type {number} */ n, /** @type {GasRule | undefined} */ rule = undefined) => (rule ? BigInt(ethDataGas(n, rule)) : max(...ETH.GAS_FORMULAS.map((f) => f.base + f.perByte * BigInt(n))))
// the tx's gasLimit: the formula, or the node's estimate if that is higher (geth estimates up to +1.5 %)
export const ethGasLimit = (/** @type {number} */ n, estimate = 0n, /** @type {GasRule | undefined} */ rule = undefined) => max(ethGasFormula(n, rule), estimate)
// upper bound used for funding / plan math (formula + the estimate tolerance)
export const ethGasBudget = (/** @type {number} */ n, /** @type {GasRule | undefined} */ rule = undefined) => { const g = ethGasFormula(n, rule); return g + ceilDiv(g * ETH.ESTIMATE_TOL_NUM, ETH.ESTIMATE_TOL_DEN) }
/** @param {GasRule} rule */
export const ethGasRuleName = (rule) => (!rule.amsterdam ? '21000+40n (pre-Amsterdam)' : rule.toSelf ? '12000+64n (Amsterdam, to self)' : '15000+64n (Amsterdam, to another address)')
// eth_estimateGas must lie in [formula, formula + 1.5 %] for one of the formulas, otherwise fail closed.
// With a rule: for exactly that formula; an estimate matching the other fork's formula names the drift.
/** @param {bigint} estimate @param {number} n @param {GasRule} [rule] @returns {{ ok: true, rule: string, why?: undefined } | { ok: false, why: string, rule?: undefined }} */
export function ethCheckEstimate(estimate, n, rule) {
  if (rule) {
    const tol = (/** @type {bigint} */ g) => g + ceilDiv(g * BigInt(ESTIMATE_TOL.num), BigInt(ESTIMATE_TOL.den))
    const g = ethGasFormula(n, rule)
    if (estimate >= g && estimate <= tol(g)) return { ok: true, rule: `${ethGasRuleName(rule)}${estimate > g ? ` +${estimate - g}` : ''}` }
    const other = { ...rule, amsterdam: !rule.amsterdam }, go = ethGasFormula(n, other)
    const drift = estimate >= go && estimate <= tol(go) ? ` — it matches ${ethGasRuleName(other)}: Amsterdam appears ${other.amsterdam ? 'active' : 'inactive'} on this network, update required` : ''
    return { ok: false, why: `eth_estimateGas ${estimate} is not within [formula, +1.5 %] of ${ethGasRuleName(rule)} = ${g}${drift} — fail closed` }
  }
  const hit = ETH.GAS_FORMULAS.find((f) => { const g = f.base + f.perByte * BigInt(n); return estimate >= g && estimate <= g + ceilDiv(g * ETH.ESTIMATE_TOL_NUM, ETH.ESTIMATE_TOL_DEN) })
  if (hit) { const g = hit.base + hit.perByte * BigInt(n); return { ok: true, rule: `${hit.name}${estimate > g ? ` +${estimate - g}` : ''}` } }
  return { ok: false, why: `eth_estimateGas ${estimate} is not within [formula, +1.5 %] of ${ETH.GAS_FORMULAS.map((f) => `${f.name} = ${f.base + f.perByte * BigInt(n)}`).join(' or ')} — fail closed` }
}
export const ethMaxFee = (/** @type {bigint} */ nextBase, /** @type {bigint} */ tip) => ETH.MAXFEE_BASE_MULT * nextBase + tip
// tip = median of the per-block p50 rewards, clamped to [0.1 gwei, operator cap]
export const tipCapOk = (/** @type {bigint | null | undefined} */ cap) => cap != null && cap >= ETH.TIP_MIN   // M10: a cap below the 0.1 gwei floor is refused
/** @param {Array<string | string[]>} rewards @param {bigint} cap @returns {bigint} */
export function ethTipFromRewards(rewards, cap) {
  const v = rewards.map((r) => BigInt(Array.isArray(r) ? r[0] : r)).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
  const med = v.length ? (v.length % 2 ? v[(v.length - 1) / 2] : (v[v.length / 2 - 1] + v[v.length / 2]) / 2n) : 0n
  return med < ETH.TIP_MIN ? ETH.TIP_MIN : med > cap ? cap : med
}
const bumpOne = (/** @type {bigint} */ x) => ceilDiv(x * ETH.BUMP_NUM, ETH.BUMP_DEN) + 1n
// same-nonce replacement: tip′ = max(⌈1.125·tip⌉+1, fresh tip); maxFee′ = max(⌈1.125·maxFee⌉+1, 2·fresh next base + tip′)
/** @param {{ tip: bigint, maxFee: bigint }} prev @param {{ tip: bigint, nextBase: bigint }} fresh */
export function replacementFees(prev, fresh) {
  const tip = max(bumpOne(prev.tip), fresh.tip)
  const maxFee = max(bumpOne(prev.maxFee), ethMaxFee(fresh.nextBase, tip))
  return { tip, maxFee }
}
// plain-text bytes ONE tx can carry when `amountWei` must cover ethGasBudget(n) × maxFee (binary search, exact)
/** @param {bigint} amountWei @param {bigint} maxFeeWei @param {GasRule} [rule] */
export function ethTextBytesAffordable(amountWei, maxFeeWei, rule) {
  const pre = utf8(ETH.PREFIX).length
  if (maxFeeWei <= 0n || ethGasBudget(pre, rule) * maxFeeWei > amountWei) return 0n
  let lo = pre, hi = ETH.TX_DATA_CAP
  while (lo < hi) { const mid = Math.ceil((lo + hi) / 2); if (ethGasBudget(mid, rule) * maxFeeWei <= amountWei) lo = mid; else hi = mid - 1 }
  return BigInt(lo - pre)
}

// ---------- SOL fees ----------
export const solCuLimit = (/** @type {number} */ units) => Math.min(SOL.CU_MAX, Math.ceil((units * SOL.CU_MARGIN_NUM) / SOL.CU_MARGIN_DEN))
export const solCuEstimate = (/** @type {Uint8Array} */ memo) => SOL.CU_BASE + weigh(memo, solCharCu)   // conservative model (bytes of one memo)
export const solPriorityFee = (/** @type {number} */ cuLimit, /** @type {number} */ microLamportsPerCu) => (BigInt(cuLimit) * BigInt(microLamportsPerCu) + 999999n) / 1000000n
export const solFee = (/** @type {number} */ signatures, /** @type {number} */ cuLimit, /** @type {number} */ microLamportsPerCu) => BigInt(signatures) * SOL.LAMPORTS_PER_SIGNATURE + solPriorityFee(cuLimit, microLamportsPerCu)
// CU price = clamp(p90 of the NON-ZERO recent prioritization fees, 100,000, 2,000,000) µlamports/CU
/** @param {any[]} fees */
export function solCuPriceFromRecent(fees) {
  const v = fees.map((f) => Number(f.prioritizationFee ?? f)).filter((x) => x > 0).sort((a, b) => a - b)
  const p = v.length ? v[Math.min(v.length - 1, Math.ceil((SOL.CU_PRICE_PERCENTILE / 100) * v.length) - 1)] : 0
  return Math.min(SOL.CU_PRICE_MAX, Math.max(SOL.CU_PRICE_MIN, p))
}
export const solResignPrice = (/** @type {number} */ prev) => Math.min(SOL.CU_PRICE_CAP, prev * SOL.CU_PRICE_RESIGN_MULT)
// memo transactions an amount covers: the fee-payer account must keep the rent-exempt minimum
export const solTxsAffordable = (/** @type {bigint} */ amount, /** @type {bigint} */ feePerTx, /** @type {bigint} */ rent) => (feePerTx > 0n && amount > rent ? (amount - rent) / feePerTx : 0n)

// ---------- R60: spend cap + stagger ----------
// lane spend cap in native base units: $10 via the price, else the native fallback (fail closed to the smaller-known cap)
/** @param {'eth' | 'sol' | 'btc'} chain @param {number | null | undefined} price @param {number} decimals @returns {{ base: bigint, via: 'usd' | 'native' }} */
export function spendCapBase(chain, price, decimals) {
  if (typeof price === 'number' && Number.isFinite(price) && price > 0) return { base: usdToBase(PLAN.SPEND_CAP_USD_CENTS, price, decimals) - 1n, via: 'usd' }
  return { base: PLAN.SPEND_CAP_NATIVE[chain], via: 'native' }
}
// CSPRNG integer in [a, b]
/** @param {number} a @param {number} b @param {(n: number) => Uint32Array} [rand] */
export function randInt(a, b, rand = (n) => crypto.getRandomValues(new Uint32Array(n))) {
  const span = b - a + 1; if (span <= 1) return a
  const lim = Math.floor(0x100000000 / span) * span
  for (;;) { const x = rand(1)[0]; if (x < lim) return a + (x % span) }
}
// random order of the chains + per-chain start offsets: first at 0, second after U[min, max] s
/** @param {string[]} ids @param {[number, number]} range @param {(n: number) => Uint32Array} [rand] */
export function staggerPlan(ids, [min, max], rand) {
  const order = [...ids]
  if (order.length > 1 && randInt(0, 1, rand) === 1) order.reverse()
  return order.map((c, i) => ({ chain: c, offsetS: i === 0 ? 0 : randInt(min, max, rand) }))
}

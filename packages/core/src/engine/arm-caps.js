// @ts-check
// packages/core/src/engine/arm-caps.js — the per-chain arm caps (R60), for the Arm dialog (W), `vt job arm` (C) and
// the API's re-check inputs. laneCalc is MOVED VERBATIM (R69) from the prototype, tag add7-00927d6ade7f,
// src/mainnet/MainnetView.jsx (sha256 fc5ef4ee5b023b955e9588b19e68d3a7d3b21380723efa6d7bbe10d307cc5215) — only JSDoc
// added and the UNIT/DEC maps it read inlined. computeArmCaps (new) feeds it from a job definition:
//   · one copy = all R72 parts of the text (plan.js), costed at the lane strategy's starting fees: ETH Σ gasLimit (exact
//     fork- and recipient-aware formula + the estimate tolerance) × maxFee; SOL Σ (5,000 + priority) per part with the
//     conservative Memo v2 CU model. With distinct copies the costliest copy variant (a copy-marked copy) counts.
//   · laneCalc then gives MQ's planned spend (copies: N × per-copy; drain: the lane's balance) and the R60 cap ($10 via
//     the Jupiter price, else the native fallback); over that cap the Arm needs the planned amount typed (overCap).
//   · the job's budgetUsd bounds the planned spend (its native value; without a price the R60 native fallback applies).
//   · ArmCap (contracts/types.ts): nativeCap = overCap ? planned spend : min(R60 cap, budget) (MQ: the typed approval
//     raises the cap to the planned spend); planned = the planned spend in native units, rendered EXACTLY (formatUnits,
//     no rounding: what the operator types; checkArmConfirm compares it to the typed amount, and the API compares it to
//     nativeCap exactly in base units — I2, was sig6); usd = the USD value of nativeCap (0 without a price); priceAt =
//     the price's fetchedAt.
//   · fullCopyCost (base units of one full copy), parts (of copy 1), affordable = the balance covers the reserve plus one
//     full copy AND one full copy fits under nativeCap ("Arm refuses unless one full copy is affordable within the cap").
//   · PF-S M-4 (pre-flip review): off local an UNTYPED cap is also at most untypedCapCeiling — the R60 native fallback
//     (PLAN.SPEND_CAP_NATIVE), price-free, so the API (which has no price) re-applies the very bound planned here
//     (armCapExcess): above it the planned spend is typed (overCap). On testnet it changes nothing (no price there: the cap is
//     that fallback already); on mainnet a $10 cap worth more than the fallback (ETH under $2,500, SOL under ~$143) is
//     typed.
import { ECON, PLAN } from '../chains/constants.js'
import { amountForCopies, baseToCents, copiesFromAmount, ethGasBudget, ethParts, ethTextBytesAffordable, formatUnits, solCuEstimate, solCuLimit, solFee, solParts, solTxsAffordable, spendCapBase, usdToBase, utf8, validateAmount, validateCopies } from '../chains/plan.js'
import { priceStatus } from '../chains/price.js'
import { copyCost, feeCeilingOf, planBtcCopy } from '../chains/btc.js'
import { layoutMaxMemo, solPriceForLamports } from '../chains/sol.js'
import { ethAmsterdam } from '../contracts/index.ts'
import { sha256Hex } from '../job/canonical.ts'

const UNIT = { eth: 'ETH', sol: 'SOL', btc: 'BTC' }, DEC = { eth: 18, sol: 9, btc: 8 }

// ---- MQ laneCalc, verbatim ----
// The lane's two always-visible fields (Copies N, Amount USD) + optional native override. `src` = the field edited last.
/** @param {'eth' | 'sol' | 'btc'} c @param {any} lane @param {any} a @param {any} priceData @param {any} ps @param {number} nParts @param {bigint | undefined} balance @returns {any} */
export function laneCalc(c, lane, a, priceData, ps, nParts, balance) {
  // SOL drain lanes keep rent + one claw-back fee (fee-payer rule), so the remainder can always be clawed back to 0
  /** @type {any} */
  const out = { N: null, amount: null, cents: null, err: '', perCopy: a?.perCopy ?? null, reserve: (a?.reserve ?? 0n) + (c === 'sol' && lane.mode === 'drain' && a ? ECON.SOL_CLAW_RESERVE : 0n) }
  if (!a) { out.err = 'waiting for a fee quote (valid text + relay)'; return out }
  const px = priceData?.prices?.[UNIT[c]]?.usd
  const toCents = (/** @type {bigint} */ b) => (ps.ok ? baseToCents(b, px, DEC[c]) : null)
  if (lane.src === 'n') {
    const v = validateCopies(lane.n); if (!v.ok) { out.err = `Copies: ${v.error}`; return out }
    out.N = v.value; out.amount = amountForCopies(v.value, a.perCopy, out.reserve); out.cents = toCents(out.amount)
  } else {
    if (lane.src === 'usd') {
      if (!ps.ok) { out.err = `USD entry disabled: ${ps.why}`; return out }
      const v = validateAmount(lane.usd, 'usd'); if (!v.ok) { out.err = `Amount (USD): ${v.error}`; return out }
      out.amount = usdToBase(v.value, px, DEC[c]); out.cents = v.value
    } else {
      const v = validateAmount(lane.native, c); if (!v.ok) { out.err = `Amount (${UNIT[c]}): ${v.error}`; return out }
      out.amount = v.value; out.cents = toCents(v.value)
    }
    out.N = Number(copiesFromAmount(out.amount, a.perCopy, out.reserve))
  }
  out.one = out.reserve + a.perCopy                                   // requirement for ONE copy of the current text
  out.leftover = /** @type {bigint} */ (out.amount) - /** @type {bigint} */ (out.reserve) - BigInt(out.N) * a.perCopy
  out.covers = out.amount >= out.one
  out.warn = out.amount > PLAN.WARN_FACTOR * out.one
  out.txs = out.N * nParts
  out.space = c === 'eth' ? ethTextBytesAffordable(out.amount, a.fees.maxFee) : solTxsAffordable(out.amount, a.fee, out.reserve)
  out.perCopyCents = toCents(a.perCopy); out.oneCents = toCents(out.one)
  // R60 hard spend cap (fees): $10 via the price, else the native fallback
  const cap = spendCapBase(c, ps.ok ? px : null, DEC[c])
  out.cap = cap.base; out.capVia = cap.via; out.spend = BigInt(out.N) * a.perCopy; out.overCap = out.spend > cap.base
  if (lane.mode === 'drain') {                                        // R64: planned spend = the lane's balance at Arm
    out.drain = true; out.balance = balance ?? 0n
    out.estCopies = Number(copiesFromAmount(out.balance, a.perCopy, out.reserve)); out.spend = out.balance; out.overCap = out.spend > cap.base
    out.spendCents = toCents(out.spend)
  }
  return out
}

const big = (/** @type {unknown} */ v) => (typeof v === 'bigint' ? v : BigInt(/** @type {any} */ (v)))
// One copy's per-part reserved costs (a = the laneCalc quote): ETH at maxFee, SOL at the priority lamports.
/** @param {'eth' | 'sol' | 'btc'} c @param {any} ch the JobChainDef @param {string} text @param {any} fees @param {{ network: string, amsterdamOverride?: boolean }} net */
export function copyQuote(c, ch, text, fees, net) {
  const bytes = utf8(text), sha = sha256Hex(bytes), copies = typeof ch.mode === 'object' && ch.mode ? ch.mode.copies : null
  const widest = ch.distinctCopies ? (copies !== null ? (copies >= 2 ? { copy: copies, copies } : null) : { copy: 9999, copies: null }) : null
  if (c === 'eth') {
    const rule = { amsterdam: ethAmsterdam(/** @type {any} */ (net.network), net.amsterdamOverride === undefined ? {} : { localOverride: net.amsterdamOverride }), toSelf: ch.publishMode === 'eth.calldata.self' }
    const maxFee = big(fees.maxFee)
    const cost = (/** @type {any[]} */ ps) => ps.reduce((a, p) => a + ethGasBudget(p.payload.length, rule) * maxFee, 0n)
    const parts = ethParts(bytes, { sha256: sha }), alt = widest ? ethParts(bytes, { sha256: sha, ...widest }) : null
    const perCopy = alt && cost(alt) > cost(parts) ? cost(alt) : cost(parts)
    return { parts: parts.length, a: { perCopy, reserve: 0n, fees: { maxFee } } }
  }
  if (c === 'btc') {                                                  // E7b: one copy = a commit + a reveal; the worst case from the vsize bounds at the lane's fee rate
    const rate = feeCeilingOf(ch)                                       // E7b m-1: the CEILING (the job's maxFeeRateSatVb, else the tickets' 500 sat/vB), never today's estimate
    const cost = (/** @type {any[]} */ ps) => copyCost(ps[0].payload.length, rate).perCopy
    const parts = planBtcCopy(bytes, { sha256: sha, copy: null, copies: null }), alt = widest ? planBtcCopy(bytes, { sha256: sha, copy: widest.copy, copies: widest.copies }) : null
    const perCopy = alt && cost(alt) > cost(parts) ? cost(alt) : cost(parts)
    return { parts: 2, a: { perCopy, reserve: 0n, fee: perCopy } }
  }
  const lamports = fees.priorityLamports ?? 0, cap = ch.maxCuPrice ?? ECON.SOL_RUNG_CAP, maxMemo = layoutMaxMemo()
  const feeOf = (/** @type {any} */ p) => { const cuLimit = solCuLimit(solCuEstimate(p.payload)); return solFee(1, cuLimit, solPriceForLamports(lamports, cuLimit, cap)) }
  const cost = (/** @type {any[]} */ ps) => ps.reduce((a, p) => a + feeOf(p), 0n)
  const parts = solParts(bytes, maxMemo, { sha256: sha }), alt = widest ? solParts(bytes, maxMemo, { sha256: sha, ...widest }) : null
  const use = alt && cost(alt) > cost(parts) ? alt : parts
  return { parts: parts.length, a: { perCopy: cost(use), reserve: big(fees.rent), fee: use.reduce((m, p) => { const f = feeOf(p); return f > m ? f : m }, 0n) } }
}

// PF-S M-4 (pre-flip review): the largest nativeCap an arm may carry WITHOUT the typed amount, price-free: the R60 native fallback
// (PLAN.SPEND_CAP_NATIVE) for eth and sol off local; null (no such bound) on local and for btc (local only).
/** @param {string} network @param {string} c @returns {bigint | null} */
export function untypedCapCeiling(network, c) {
  return network !== 'local' && (c === 'eth' || c === 'sol') ? PLAN.SPEND_CAP_NATIVE[c] : null
}
// The job.budget rule (job/validate.ts): budgetUsd is > 0 and at most this.
const BUDGET_MAX_USD = 1000
// PF-S M-4: the API's re-check of one armed chain's ArmCap against the job definition's chain (null = within what computeArmCaps
// plans; else the reason). Off local, for eth and sol:
//   · the job's budgetUsd is a number in (0, BUDGET_MAX_USD] (the job.budget rule, applied again at the arm);
//   · an untyped cap (overCap false) is at most untypedCapCeiling — above it the arm needs the typed amount;
//   · a typed cap (overCap true) has a price (priceAt): the USD value is what the budget bounds;
//   · a priced cap is worth at most the job's budgetUsd (cap.usd ≤ budgetUsd); an unpriced one says usd 0.
// The typed amount itself (confirm.amounts[c] === planned, planned = nativeCap exactly) is checkArmConfirm's and the API's arm.amount.
/** @param {string} network @param {string} c @param {any} ch the JobChainDef @param {{ nativeCap: string, usd: number, priceAt: number | null, overCap: boolean }} cap @returns {string | null} */
export function armCapExcess(network, c, ch, cap) {
  const ceiling = untypedCapCeiling(network, c)
  if (ceiling === null) return null
  const budget = ch?.budgetUsd
  if (!(typeof budget === 'number' && Number.isFinite(budget) && budget > 0 && budget <= BUDGET_MAX_USD)) return `the job's budgetUsd is not a number in (0, ${BUDGET_MAX_USD}]`
  let n
  try { n = BigInt(cap.nativeCap) } catch { return 'the cap is not a decimal amount in base units' }
  const priced = cap.priceAt !== null
  if (!cap.overCap && n > ceiling) return `an untyped cap of ${n} base units is above ${ceiling}, the most an arm carries without the typed amount (the R60 native ceiling): arm it over the cap, with the planned amount typed`
  if (cap.overCap && !priced) return 'a typed (over-cap) arm needs a price: its USD value is what the job\'s budget bounds'
  if (priced ? !(cap.usd <= budget) : cap.usd !== 0) return priced ? `the cap is worth $${cap.usd}, more than the job's budget ($${budget})` : 'an unpriced cap is worth $0 (usd 0)'
  return null
}

// computeArmCaps(def, text, net) → per armed-able chain of the def: ArmCap & { fullCopyCost, parts, affordable }.
//   net.prices: the relay's /relay/price answer ({ prices: { ETH: {usd}, SOL: {usd} }, fetchedAt }) or null (testnet:
//   no price); net.fees.eth = { maxFee } (+ nextBase, tip) at the lane strategy's start; net.fees.sol = { rent,
//   priorityLamports? }; net.balances[c] base units; net.network; net.now (ms, for the price's age).
/** @param {import('../contracts/index.ts').JobDef} def @param {string} text @param {{ prices: any, fees: any, balances: any, network: string, now?: number, amsterdamOverride?: boolean }} net */
export function computeArmCaps(def, text, net) {
  /** @type {Record<string, any>} */
  const out = {}
  const ps = priceStatus(net.prices, net.now ?? Date.now())
  for (const c of /** @type {Array<'eth' | 'sol' | 'btc'>} */ (['eth', 'sol', 'btc'])) {
    const ch = /** @type {any} */ (def.chains)[c]
    if (!ch) continue
    const q = copyQuote(c, ch, text, net.fees?.[c] ?? {}, net)
    const copies = typeof ch.mode === 'object' && ch.mode ? ch.mode.copies : null
    const lane = copies !== null ? { mode: 'copies', src: 'n', n: String(copies) } : { mode: 'drain', src: 'n', n: '1' }
    const balance = big(net.balances?.[c] ?? 0n)
    const psc = c === 'btc' ? { ok: false, none: true, why: 'no BTC price (the local lane has no value)' } : ps   // btc is capped in sats
    const calc = laneCalc(c, lane, q.a, net.prices, psc, q.parts, balance)
    if (calc.err) throw new Error(`computeArmCaps ${c}: ${calc.err}`)
    const px = psc.ok ? net.prices.prices[UNIT[c]].usd : null
    const budgetCap = px !== null ? usdToBase(BigInt(Math.round(ch.budgetUsd * 100)), px, DEC[c]) - 1n : PLAN.SPEND_CAP_NATIVE[c]
    // btc (Eminors fix 1, I-1): there is no USD budget to clip to (budgetCap IS the native fallback cap), so the planned spend is N x the worst-case copy
    // and over-cap is reachable, exactly as on the other chains (typed confirmation) - never a plan silently clipped below N x the worst case
    const spend = c === 'btc' ? /** @type {bigint} */ (calc.spend) : /** @type {bigint} */ (calc.spend) < budgetCap ? calc.spend : budgetCap
    // PF-S M-4: off local the untyped cap never exceeds the price-free ceiling the API re-applies (armCapExcess)
    const ceiling = untypedCapCeiling(net.network, c)
    const r60 = ceiling !== null && ceiling < calc.cap ? ceiling : calc.cap
    const overCap = spend > r60
    const nativeCap = overCap ? spend : (r60 < budgetCap ? r60 : budgetCap)
    out[c] = {
      nativeCap: String(nativeCap), usd: px !== null ? Number(baseToCents(nativeCap, px, DEC[c])) / 100 : 0, priceAt: psc.ok ? net.prices.fetchedAt : null,
      overCap, planned: formatUnits(spend, DEC[c]),
      fullCopyCost: String(q.a.perCopy), parts: q.parts, affordable: balance >= calc.one && q.a.perCopy <= nativeCap,
      // why not affordable (balance, else cap), and where the cap came from; btc rows also name the fee-rate ceiling the worst case is priced at
      ...(balance < calc.one ? { notAffordableBecause: 'balance' } : q.a.perCopy > nativeCap ? { notAffordableBecause: 'cap' } : {}),
      capVia: c === 'btc' ? (overCap ? 'typed' : 'fallback') : px !== null ? 'budget' : 'fallback',
      ...(c === 'btc' ? { ceilingSatVb: Number(feeCeilingOf(ch)), ceilingFromJob: ch.maxFeeRateSatVb != null } : {}),
    }
  }
  return out
}
// The contract's ArmCap (what the ArmRequest carries; validateEvent/checkArmConfirm refuse extra members).
/** @param {{ nativeCap: string, usd: number, priceAt: number | null, overCap: boolean, planned: string }} c */
export const toArmCap = ({ nativeCap, usd, priceAt, overCap, planned }) => ({ nativeCap, usd, priceAt, overCap, planned })

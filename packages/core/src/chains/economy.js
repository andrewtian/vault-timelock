// @ts-check
// PORTED (R69) from the prototype, tag add7-00927d6ade7f, src/mainnet/economy.js (sha256 c5ebd91a595eb191343288cf0ff972dd6ddc19de01c9efc285a5aa54c5187c0c).
// R64 economy fee ladder + drain math + claw-back amounts (PURE; unit-tested by test/economy.test.mjs).
// All amounts are integer base units (wei / lamports); prices are wei/gas and µlamports/CU.
import { getAddress } from 'viem'
import { PublicKey } from '@solana/web3.js'
import { CANON, ECON, ETH, LANE } from './constants.js'
import { ethGasBudget } from './plan.js'
// Canonical changes (E2): every ETH cost function takes the optional gas `rule` (plan.js; exact fork- and
// recipient-aware formula); ethClawback takes the claw-back gas (sized by destination class, ethClawGas); the Passive
// strategy (R73, PM §6) and the lamport-denominated SOL rungs (PM finding 4) are added below the ported code.
/** @typedef {import('./plan.js').GasRule} GasRule */
/** @typedef {{ tip: bigint, maxFee: bigint }} EthFee */
const ceilDiv = (/** @type {bigint} */ a, /** @type {bigint} */ b) => (a + b - 1n) / b
const max = (/** @type {bigint[]} */ ...xs) => xs.reduce((a, b) => (b > a ? b : a))
const median = (/** @type {bigint[]} */ v) => { const s = [...v].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)); return s.length ? s[Math.floor((s.length - 1) / 2)] : 0n }

// ---------- copy text in drain mode ----------
export const drainCopyText = (/** @type {string} */ text, /** @type {number} */ i, /** @type {boolean} */ distinct) => (distinct && i > 1 ? text + LANE.drainSuffix(i) : text)

// ---------- ETH ladder ----------
// tip₀ = max(floor, median of the per-block p10 rewards) — `rewards` = feeHistory reward rows [[p10, p50], …]
export const ethTip0 = (/** @type {Array<string | string[]> | null | undefined} */ rewards, floor = ECON.ETH_TIP_FLOOR) => max(floor, median((rewards || []).map((r) => BigInt(Array.isArray(r) ? r[0] : r))))
// learning: the next copy starts at max(fresh tip₀, last included tip ÷ 1.125)
export const ethStartTip = (/** @type {bigint} */ tip0, /** @type {bigint | null | undefined} */ lastIncludedTip) => (lastIncludedTip == null ? tip0 : max(tip0, (lastIncludedTip * ECON.LEARN_NUM) / ECON.LEARN_DEN))
export const ethTightMaxFee = (/** @type {bigint} */ nextBase, /** @type {bigint} */ tip) => ceilDiv(nextBase * ECON.ETH_TIGHT_NUM, ECON.ETH_TIGHT_DEN) + tip
export const ethFullMaxFee = (/** @type {bigint} */ nextBase, /** @type {bigint} */ tip) => ETH.MAXFEE_BASE_MULT * nextBase + tip
// first attempt of a tx: maxFee = 2·base + tip (or the tight ⌈1.25·base⌉ + tip for an unaffordable final copy); pause above the cap
/** @param {{ nextBase: bigint, startTip: bigint, tight?: boolean, cap?: bigint | null }} _o @returns {{ tip: bigint, maxFee: bigint, pause?: undefined } | { pause: string, tip?: undefined, maxFee?: undefined }} */
export function ethEconomyInitial({ nextBase, startTip, tight = false, cap }) {
  if (cap != null && startTip > cap) return { pause: `start tip ${startTip} wei is above the per-tx tip cap ${cap} wei` }
  return { tip: startTip, maxFee: tight ? ethTightMaxFee(nextBase, startTip) : ethFullMaxFee(nextBase, startTip) }
}
// stall (3 blocks) → same-nonce replacement: BOTH fields ×1.125 (ceil, +1 wei), maxFee re-read from the next base fee
/** @param {EthFee} prev @param {{ nextBase: bigint, tip0?: bigint, tight?: boolean, cap?: bigint | null, balance?: bigint | null, gas?: bigint | null }} _o @returns {{ tip: bigint, maxFee: bigint, pause?: undefined, wait?: undefined } | { pause: string, tip?: undefined, maxFee?: undefined, wait?: undefined } | { wait: string, tip?: undefined, maxFee?: undefined, pause?: undefined }} */
export function ethEconomyBump(prev, { nextBase, tip0 = 0n, tight = false, cap, balance, gas }) {
  const tip = max(ceilDiv(prev.tip * ETH.BUMP_NUM, ETH.BUMP_DEN) + 1n, tip0)
  if (cap != null && tip > cap) return { pause: `the next bump (tip ${tip} wei) would exceed the per-tx tip cap ${cap} wei` }
  const maxFee = max(ceilDiv(prev.maxFee * ETH.BUMP_NUM, ETH.BUMP_DEN) + 1n, (tight ? ethTightMaxFee(nextBase, tip) : ethFullMaxFee(nextBase, tip)))
  if (balance != null && gas != null && gas * maxFee > balance) return { wait: `a replacement would reserve ${gas * maxFee} wei > balance ${balance} wei — waiting for inclusion / the base fee to fall` }
  return { tip, maxFee }
}
// worst case of the next FULL copy (all parts) at the start tip: Σ gasLimit × (2·base + tip); tight variant for the final copy
export const ethCopyCost = (/** @type {number[]} */ payloadLens, /** @type {bigint} */ nextBase, /** @type {bigint} */ tip, tight = false, /** @type {GasRule | undefined} */ rule = undefined) => payloadLens.reduce((a, n) => a + ethGasBudget(n, rule) * (tight ? ethTightMaxFee(nextBase, tip) : ethFullMaxFee(nextBase, tip)), 0n)
// drained = balance < worst case at the start fee AND the tight final-copy variant is unaffordable too
/** @param {bigint} balance @param {number[]} payloadLens @param {bigint} nextBase @param {bigint} startTip @param {GasRule} [rule] @returns {{ send: boolean, tight?: boolean, drained?: boolean, cost: bigint }} */
export function ethDrainDecision(balance, payloadLens, nextBase, startTip, rule) {
  const full = ethCopyCost(payloadLens, nextBase, startTip, false, rule)
  if (balance >= full) return { send: true, tight: false, cost: full }
  const tight = ethCopyCost(payloadLens, nextBase, startTip, true, rule)
  if (balance >= tight) return { send: true, tight: true, cost: tight }
  return { send: false, drained: true, cost: full }
}

// ---------- SOL ladder ----------
const pctl = (/** @type {number[]} */ v, /** @type {number} */ p) => { const s = [...v].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.max(0, Math.ceil((p / 100) * s.length) - 1))] }
// rungs: P₀ = 0, then p25/p50/p75/p90 of the NON-ZERO recent fees (capped, deduplicated, strictly increasing)
/** @param {Array<{ prioritizationFee?: number } | number> | null | undefined} fees @param {{ pcts?: number[], cap?: number, fallback?: number[] }} [_o] @returns {number[]} */
export function solRungs(fees, { pcts = ECON.SOL_RUNG_PCTS, cap = ECON.SOL_RUNG_CAP, fallback = ECON.SOL_FALLBACK_RUNGS } = {}) {
  const nz = (fees || []).map((/** @type {any} */ f) => Number(f?.prioritizationFee ?? f)).filter((x) => Number.isFinite(x) && x > 0)
  const top = nz.length ? pcts.map((p) => pctl(nz, p)) : fallback
  /** @type {number[]} */
  const out = [0]
  for (const x of top.map((v) => Math.min(cap, Math.ceil(v)))) if (x > /** @type {number} */ (out.at(-1))) out.push(x)
  return out
}
// learning: the next copy starts one rung below the rung that landed
export const solStartRung = (/** @type {number | null | undefined} */ landedRung) => (landedRung == null ? 0 : Math.max(0, landedRung - 1))
// next rung after a PROVEN expiry; past the top → pause
/** @type {(rung: number, rungs: number[]) => ({ rung: number, pause?: undefined } | { pause: string, rung?: undefined })} */
export const solNextRung = (rung, rungs) => (rung + 1 < rungs.length ? { rung: rung + 1 } : { pause: `top rung ${rungs.at(-1)} µL/CU reached and its attempt expired` })
// drained = balance − Σ fees(next full copy) would leave the payer between 0 and the rent-exempt minimum (or below 0)
// drained = after this copy the payer would end below rent + the claw-back fee reserve (and not exactly 0)
/** @param {bigint} balance @param {bigint[]} copyFees @param {bigint} rent @param {bigint} [reserve] @returns {{ send: boolean, drained?: boolean, cost: bigint, fees: bigint }} */
export function solDrainDecision(balance, copyFees, rent, reserve = ECON.SOL_CLAW_RESERVE) {
  const fees = copyFees.reduce((a, f) => a + f, 0n), after = balance - fees, floor = rent + reserve
  return after === 0n || after >= floor ? { send: true, cost: fees + (after === 0n ? 0n : floor), fees } : { send: false, drained: true, cost: fees + floor, fees }
}

// ---------- claw back ----------
// ETH: value = balance − 21000 × maxFee (prompt-inclusion fees); the unused part of the reserve is refunded = dust
/** @param {bigint} balance @param {bigint} nextBase @param {bigint} tip @param {bigint} [gas] the claw-back gas (ethClawGas) */
export function ethClawback(balance, nextBase, tip, gas = ECON.ETH_CLAW_GAS) {
  const maxFee = ethFullMaxFee(nextBase, tip), reserve = gas * maxFee, value = balance - reserve
  if (value <= 0n) return { ok: false, why: `balance ${balance} wei ≤ ${gas} × maxFee ${maxFee} wei` }
  return { ok: true, value, maxFee, tip, reserve, expectedDust: gas * (maxFee - nextBase - tip) }
}
// SOL: amount = balance − exact fee → the lane ends at 0 lamports (measured: accepted). A NEW destination needs ≥ rent.
/** @param {bigint} balance @param {bigint} fee @param {bigint} destBalance @param {bigint} rent @returns {{ ok: true, amount: bigint, why?: undefined } | { ok: false, why: string, amount?: undefined }} */
export function solClawback(balance, fee, destBalance, rent) {
  const amount = balance - fee
  if (amount <= 0n) return { ok: false, why: `balance ${balance} ≤ fee ${fee} lamports` }
  // fee-payer validation runs BEFORE the transfer: balance − fee must be ≥ rent (or 0) — measured, InsufficientFundsForRent
  if (amount < rent) return { ok: false, why: `the remainder ${balance} lamports cannot pay the ${fee}-lamport fee and keep the rent-exempt minimum ${rent} until the transfer runs (fee-payer rule) — it cannot be moved` }
  if (destBalance === 0n && amount < rent) return { ok: false, why: `the destination does not exist yet and ${amount} lamports < the rent-exempt minimum ${rent} — use an existing (funded) address` }
  return { ok: true, amount }
}
/** @param {unknown} dest @param {string} [lane] @returns {{ ok: true, address: string, why?: undefined } | { ok: false, why: string, address?: undefined }} */
export function validateEthDest(dest, lane) {
  const d = String(dest || '').trim()
  /** @type {string} */
  let cs; try { cs = getAddress(d) } catch { return { ok: false, why: 'not an Ethereum address' } }
  if (d !== cs) return { ok: false, why: `not EIP-55 checksummed (expected ${cs})` }
  if (cs === ETH.NULL_ADDRESS) return { ok: false, why: 'the null address burns funds' }
  if (lane && cs.toLowerCase() === String(lane).toLowerCase()) return { ok: false, why: 'that is the lane address itself' }
  return { ok: true, address: cs }
}
// Reserved (nobody-controls) addresses: one source, chains/reserved.js (E6); re-exported here for the existing importers.
export { isEthReserved, isSolReserved, ethReservedKind, solReservedKind } from './reserved.js'
/** @param {unknown} dest @param {string} [lane] @returns {{ ok: true, address: string, why?: undefined } | { ok: false, why: string, address?: undefined }} */
export function validateSolDest(dest, lane) {
  const d = String(dest || '').trim()
  /** @type {PublicKey} */
  let pk; try { pk = new PublicKey(d) } catch { return { ok: false, why: 'not a base58 Solana address' } }
  if (pk.toBase58() !== d || pk.toBytes().length !== 32) return { ok: false, why: 'not a canonical 32-byte base58 address' }
  if (d === ECON.SOL_INCINERATOR) return { ok: false, why: 'the incinerator burns funds' }
  if (d === lane) return { ok: false, why: 'that is the lane address itself' }
  return { ok: true, address: d }
}

// ---------- canonical additions (E2) ----------
// ETH claw-back gas by destination class (PM finding 1): pre-Amsterdam 21,000; Amsterdam 21,000 to an existing account,
// 204,600 to an empty one. A destination with code is refused by the caller.
/** @param {{ amsterdam: boolean, empty: boolean }} o */
export const ethClawGas = ({ amsterdam, empty }) => (amsterdam && empty ? CANON.ETH_CLAW_GAS_EMPTY_AMSTERDAM : CANON.ETH_CLAW_GAS_EXISTING)
// Passive (R73, PM §6). Target T = the pct-th percentile (nearest rank) of the window's base fees.
/** @param {bigint[]} bases @param {number} [pct] */
export function ethPassiveTarget(bases, pct = CANON.PASSIVE_ETH_TARGET_PCT) {
  if (!bases.length) throw new Error('no base fees for the passive target — fail closed')
  const s = [...bases].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
  return s[Math.min(s.length - 1, Math.max(0, Math.ceil((pct / 100) * s.length) - 1))]
}
// first attempt: sign only when the next base fee ≤ T (else wait, nothing signed); maxFee = T + tip, tip at the floor
/** @param {{ nextBase: bigint, target: bigint, tip?: bigint }} o @returns {{ tip: bigint, maxFee: bigint, wait?: undefined } | { wait: string, tip?: undefined, maxFee?: undefined }} */
export function ethPassiveInitial({ nextBase, target, tip = CANON.PASSIVE_ETH_TIP }) {
  if (nextBase > target) return { wait: `waiting for a cheap block: next base fee ${nextBase} wei > target ${target} wei` }
  return { tip, maxFee: target + tip }
}
// a stall never escalates: the same signed bytes stay in the pool and are rebroadcast
export const ethPassiveBump = () => ({ wait: 'passive: no escalation — the same signed bytes are rebroadcast' })
// drained ⇔ the balance cannot cover the next full copy at maxFee = T + tip (gasLimit at the exact formula + tolerance)
/** @param {bigint} balance @param {number[]} payloadLens @param {bigint} target @param {bigint} tip @param {GasRule} [rule] */
export function ethPassiveDecision(balance, payloadLens, target, tip, rule) {
  const cost = payloadLens.reduce((a, n) => a + ethGasBudget(n, rule) * (target + tip), 0n)
  return balance >= cost ? { send: true, tight: false, cost } : { send: false, drained: true, cost }
}

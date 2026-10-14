// @ts-check
// PORTED (R69) from the prototype, tag add7-00927d6ade7f, src/mainnet/MainnetView.jsx (sha256
// fc5ef4ee5b023b955e9588b19e68d3a7d3b21380723efa6d7bbe10d307cc5215): quoteEth, quoteSol, simEth, simSol, the
// assessChain loop body, isFresh and the startChain pre-start checks — moved out of the view (spec §7.2) so the page
// and `vt job run` use the same pre-start check.
// Text privacy (MQ I7): before Arm, fees are computed LOCALLY (formula gas, fee history, the conservative CU model — no
// calldata or memo leaves); `kind: 'precheck'`. After Arm (cfg.real), simulations run with the REAL bytes; `kind: 'sim'`.
// Canonical changes: one copy's planned payloads come in (payloadParts, plus cfg.altParts = the costliest copy variant,
// e.g. a copy-marked copy); fees follow the lane's fee strategy (passive / economy / prompt) and the exact gas rule;
// SOL is priced in lamports per tx; `at` is a millisecond timestamp; the Tor gate takes the injected network.
import { formatEther, formatGwei } from 'viem'
import { CANON, networkOf } from '../chains/constants.js'
import { ethGasBudget, ethGasFormula, formatUnits, solCuEstimate, solCuLimit, solFee } from '../chains/plan.js'
import { ethPassiveTarget } from '../chains/economy.js'
import * as eth from '../chains/eth.js'
import * as sol from '../chains/sol.js'
import * as btcc from '../chains/btc.js'
import { short } from './engine.js'
import { btcRpc } from './rpc.js'
import { maxTipWei } from '../gates/fee-window.ts'

export const FRESH_MS = 15000   // a real simulation counts at a chain's start for 15 s (MQ isFresh)

/** @typedef {{ payload: Uint8Array, i?: number }} PayloadPart */
/** @typedef {{ real: boolean, network: string, address: string, kp?: import('@solana/web3.js').Keypair, recipient?: 'null' | 'self', gasRule?: import('../chains/plan.js').GasRule, strategy?: 'passive' | 'economy' | 'prompt', tipCap?: bigint, maxTipGwei?: number | string, ethFees?: StartingEthFees, priorityLamports?: number, cuPriceCap?: number, reserve?: bigint, altParts?: PayloadPart[], msSha: string, cfgKey: string, now?: () => number }} AssessCfg */
/** @typedef {{ ok: boolean, reason: string, at: number, kind: 'sim' | 'precheck', cost: string, msSha: string, cfg: string, [k: string]: unknown }} Assessment */

// ---- the arm-time starting fees (one source for assess.js, `vt job arm` and the page) ----
/** @typedef {{ tipCap?: bigint, maxTipGwei?: number | string, gasRule?: import('../chains/plan.js').GasRule, parts?: PayloadPart[], altParts?: PayloadPart[], priorityLamports?: number, cuPriceCap?: number }} StartingFeeInputs */
/** @typedef {'passive' | 'economy' | 'prompt'} FeeStrategy */
/** @typedef {{ nextBase: bigint, tip: bigint, maxFee: bigint, target?: bigint, windowBlocks?: number, truncated?: boolean }} StartingEthFees */

// Per-part worst-case cost of one ETH copy at these fees: reserved = exact gas budget × maxFee; likely = formula gas × (next base + tip).
// altParts (the costliest copy variant) replaces parts when its total reserve is higher.
/** @param {PayloadPart[]} parts @param {PayloadPart[] | undefined} altParts @param {import('../chains/plan.js').GasRule | undefined} rule @param {StartingEthFees} f */
function ethPerPart(parts, altParts, rule, f) {
  const cost = (/** @type {PayloadPart[]} */ ps) => ps.map((p) => { const gasLimit = ethGasBudget(p.payload.length, rule); return { gasLimit, reserved: gasLimit * f.maxFee, likely: ethGasFormula(p.payload.length, rule) * (f.nextBase + f.tip) } })
  let perPart = cost(parts)
  if (altParts) { const alt = cost(altParts); if (alt.reduce((a, p) => a + p.reserved, 0n) > perPart.reduce((a, p) => a + p.reserved, 0n)) perPart = alt }
  return perPart
}
// Same for SOL: per-tx fee = 5000 + the priority for the conservative CU limit (lamports); altParts as above.
/** @param {PayloadPart[]} parts @param {PayloadPart[] | undefined} altParts @param {number} priorityLamports @param {number} cuPriceCap */
function solPerPart(parts, altParts, priorityLamports, cuPriceCap) {
  const costOf = (/** @type {PayloadPart[]} */ ps) => ps.map((p) => { const cuLimit = solCuLimit(solCuEstimate(p.payload)), price = sol.solPriceForLamports(priorityLamports, cuLimit, cuPriceCap); return { cuLimit, price, reserved: solFee(1, cuLimit, price) } })
  let perPart = costOf(parts)
  if (altParts) { const a = costOf(altParts); if (a.reduce((x, p) => x + p.reserved, 0n) > perPart.reduce((x, p) => x + p.reserved, 0n)) perPart = a }
  return perPart
}
/**
 * The fees a lane STARTS with, as the arm-time caps and the pre-Arm quote price them (spec §7.2); read-only (fee-history /
 * rent reads through the relay, nothing text-bearing, no send).
 *  - eth passive: next base + tip PASSIVE_ETH_TIP, maxFee = the 24 h base-fee target (ethPassiveTarget) + that tip;
 *    economy: eth.economyFees(the network's tip floor); anything else (prompt): eth.fees(tipCap ?? 3 gwei).
 *  - sol: { rent: rentMin, priorityLamports } where priorityLamports = feeInputs.priorityLamports, else SOL_PROMPT_LAMPORTS
 *    for prompt and 0 for passive / economy.
 *  - perCopy: the worst-case total for ONE copy (sum over its parts, the costlier of parts / altParts): eth wei
 *    (needs feeInputs.parts and feeInputs.gasRule), sol lamports (needs feeInputs.parts; cuPriceCap default 2,000,000); null without parts.
 * @overload
 * @param {string} network @param {'eth'} chain @param {FeeStrategy | undefined} feeStrategy @param {StartingFeeInputs} [feeInputs]
 * @returns {Promise<{ chain: 'eth', fees: StartingEthFees, perCopy: bigint | null }>}
 */
/**
 * @overload
 * @param {string} network @param {'sol'} chain @param {FeeStrategy | undefined} feeStrategy @param {StartingFeeInputs} [feeInputs]
 * @returns {Promise<{ chain: 'sol', fees: { rent: bigint, priorityLamports: number }, perCopy: bigint | null }>}
 */
/**
 * @overload
 * @param {string} network @param {'btc'} chain @param {FeeStrategy | undefined} feeStrategy @param {StartingFeeInputs & { maxFeeRateSatVb?: number }} [feeInputs]
 * @returns {Promise<{ chain: 'btc', fees: { rate: bigint, commitFee: bigint, revealFee: bigint, postage: bigint }, perCopy: bigint | null }>}
 */
/**
 * @param {string} network @param {'eth' | 'sol' | 'btc'} chain @param {FeeStrategy | undefined} feeStrategy @param {StartingFeeInputs & { maxFeeRateSatVb?: number }} [feeInputs]
 * @returns {Promise<any>}
 */
export async function startingFees(network, chain, feeStrategy, feeInputs = {}) {
  if (chain === 'btc') {                                              // E7b: the node's fee rate (clamped to the job's cap) and the worst case of one copy (sats)
    const rate = await btcc.cappedFeeRate(feeInputs.maxFeeRateSatVb)
    const ceiling = btcc.feeCeilingOf(feeInputs)   // E7b m-1: quotes are at the CEILING the engine can pay, `rate` is only today's (capped) estimate
    const worst = (/** @type {PayloadPart[]} */ ps) => btcc.copyCost(ps[0].payload.length, ceiling)
    const c0 = feeInputs.parts ? worst(feeInputs.parts) : btcc.copyCost(0, ceiling)
    const alt = feeInputs.altParts ? worst(feeInputs.altParts) : null
    const c = alt && alt.perCopy > c0.perCopy ? alt : c0
    return { chain, fees: { rate, commitFee: c.commitFee, revealFee: c.revealFee, postage: c.postage }, perCopy: feeInputs.parts ? c.perCopy : null }
  }
  if (chain === 'sol') {
    const priorityLamports = feeInputs.priorityLamports ?? (feeStrategy === 'prompt' ? CANON.SOL_PROMPT_LAMPORTS : 0)
    const fees = { rent: await sol.rentMin(), priorityLamports }
    const perCopy = feeInputs.parts ? solPerPart(feeInputs.parts, feeInputs.altParts, priorityLamports, feeInputs.cuPriceCap ?? 2000000).reduce((a, p) => a + p.reserved, 0n) : null
    return { chain, fees, perCopy }
  }
  /** @type {StartingEthFees} */
  let fees
  if (feeStrategy === 'passive') {
    const w = await eth.baseFeeWindow(), target = ethPassiveTarget(w.bases), tip = CANON.PASSIVE_ETH_TIP
    fees = { nextBase: w.nextBase, tip, maxFee: target + tip, target, windowBlocks: w.windowBlocks, truncated: w.truncated }
  } else if (feeStrategy === 'economy') fees = await eth.economyFees(networkOf(network).eth.tipFloor)
  else fees = await eth.fees(feeInputs.maxTipGwei !== undefined ? maxTipWei(feeInputs.maxTipGwei) : feeInputs.tipCap ?? 3n * 10n ** 9n)
  const perCopy = feeInputs.parts && feeInputs.gasRule ? ethPerPart(feeInputs.parts, feeInputs.altParts, feeInputs.gasRule, fees).reduce((a, p) => a + p.reserved, 0n) : null
  return { chain, fees, perCopy }
}
// ETH fees of the lane's strategy (or the injected ones): { nextBase, tip, maxFee }
/** @param {AssessCfg} cfg */
async function ethFeesFor(cfg) {
  if (cfg.ethFees) return cfg.ethFees
  const r = await startingFees(cfg.network, 'eth', cfg.strategy, { tipCap: cfg.tipCap, maxTipGwei: cfg.maxTipGwei })
  return /** @type {StartingEthFees} */ (r.fees)
}
// ---- before Arm: LOCAL fee math, nothing text-bearing leaves the page (I7) ----
/** @param {AssessCfg} cfg @param {PayloadPart[]} parts */
async function quoteEth(cfg, parts) {
  const rule = cfg.gasRule
  const [f, bal] = await Promise.all([ethFeesFor(cfg), eth.balance(cfg.address)])
  const perPart = ethPerPart(parts, cfg.altParts, rule, f)
  const perCopy = perPart.reduce((a, p) => a + p.reserved, 0n), likely = perPart.reduce((a, p) => a + p.likely, 0n)
  const ok = bal >= perPart[0].reserved
  return { kind: /** @type {const} */ ('precheck'), ok, reason: ok ? '' : `balance ${formatEther(bal)} ETH < reserved ${formatEther(perPart[0].reserved)} ETH for tx #1`, balance: bal, fees: f, perPart, perCopy, likely, reserve: 0n,
    cost: `tx #1 gas ≤ ${perPart[0].gasLimit} (${rule ? 'exact formula' : 'max of the fork formulas'} + estimate tolerance) × ≤${formatGwei(f.maxFee)} gwei (next base ${formatGwei(f.nextBase)} + tip ${formatGwei(f.tip)}) = ≤${formatEther(perPart[0].reserved)} ETH${f.truncated ? ` · passive window ${f.windowBlocks} blocks (RPC limit)` : ''}` }
}
/** @param {AssessCfg} cfg */
const solPricing = (cfg) => ({ priorityLamports: cfg.priorityLamports ?? 0, cuPriceCap: cfg.cuPriceCap ?? 2000000 })
/** @param {AssessCfg} cfg @param {PayloadPart[]} parts */
async function quoteSol(cfg, parts) {
  const [bal, rent] = await Promise.all([sol.solBalance(cfg.address), sol.rentMin()])
  const { priorityLamports, cuPriceCap } = solPricing(cfg)
  const perPart = solPerPart(parts, cfg.altParts, priorityLamports, cuPriceCap)
  const fee = perPart.reduce((m, x) => (x.reserved > m ? x.reserved : m), 0n)
  const perCopy = perPart.reduce((a, p) => a + p.reserved, 0n)
  const reserve = rent + (cfg.reserve ?? 0n)
  const ok = bal >= fee + reserve
  return { kind: /** @type {const} */ ('precheck'), ok, reason: ok ? '' : `balance ${formatUnits(bal, 9)} SOL < fee + rent-exempt minimum ${formatUnits(rent, 9)} SOL`, balance: bal, perPart, perCopy, likely: perCopy, reserve, fee,
    cost: `≤ ${fee} lamports/tx = 5000 + ⌈CU limit ${perPart[0].cuLimit} (conservative Memo v2 model) × ${perPart[0].price} µL/CU / 10⁶⌉ (${priorityLamports} lamports priority)` }
}
// ---- after Arm: simulations with the REAL bytes (RPC providers see the text from here on) ----
/** @param {AssessCfg} cfg @param {PayloadPart[]} parts */
async function simEth(cfg, parts) {
  const q0 = await quoteEth(cfg, parts)
  const to = eth.recipientAddress(cfg.recipient ?? 'null', cfg.address)
  const q1 = await eth.quote(cfg.address, parts[0].payload, q0.fees, to, cfg.gasRule)
  await eth.call(cfg.address, q1.data, to)                                         // explicit eth_call simulation (to the chosen recipient)
  const ok = q1.check.ok && q0.balance >= q1.reserved
  return { ...q0, kind: /** @type {const} */ ('sim'), ok, reason: !q1.check.ok ? q1.check.why : ok ? '' : `balance ${formatEther(q0.balance)} ETH < reserved ${formatEther(q1.reserved)} ETH for tx #1`,
    cost: `tx #1 gasLimit ${q1.gasLimit} (estimate ${q1.estimate} [${q1.check.ok ? q1.check.rule : '✗'}]) × ≤${formatGwei(q0.fees.maxFee)} gwei = ≤${formatEther(q1.reserved)} ETH` }
}
/** @param {AssessCfg} cfg @param {PayloadPart[]} parts */
async function simSol(cfg, parts) {
  if (!cfg.kp) throw new Error('no key')
  const kp = cfg.kp
  const heavy = parts.reduce((h, p) => (solCuEstimate(p.payload) > solCuEstimate(h.payload) ? p : h), parts[0])
  const probes = heavy === parts[0] ? [parts[0]] : [parts[0], heavy]
  const [q0, pr] = await Promise.all([quoteSol(cfg, parts), Promise.all(probes.map((x) => sol.prepare(kp.publicKey, x.payload, solPricing(cfg))))])
  const err = pr.map((x) => x.err).find(Boolean)
  const fee = pr.reduce((m, x) => (x.fee > m ? x.fee : m), 0n)
  const ok = !err && q0.balance >= fee + q0.reserve
  const p = pr.reduce((a, b) => (b.fee > a.fee || b.err ? b : a))
  return { ...q0, kind: /** @type {const} */ ('sim'), ok, reason: err ? `simulation: ${err}` : ok ? '' : q0.reason || 'balance below fee + rent',
    cost: `${fee} lamports/tx (getFeeForMessage, incl. priority ${p.cuPrice} µL/CU) · CU limit ${p.cuLimit} ${p.estimated ? '(model: account not simulable yet)' : `(measured ${p.units} CU${probes.length > 1 ? ' on the heaviest part' : ''})`} · signed tx ${pr[0].size} B` }
}

// BTC (E7b): the commit's plan at the node's fee rate. Both before and after Arm only the lane's own coins are read and the fee plan
// is made locally; after Arm (real) the REAL commit is also checked by the node's testmempoolaccept (it validates and never relays).
// perCopy = the whole copy's outlay (the commit's fee + the value it locks for the reveal's fee and the postage).
/** @param {AssessCfg} cfg @param {PayloadPart[]} parts */
async function assessBtc(cfg, parts) {
  const key = /** @type {any} */ (cfg).btcKey
  if (!key) throw new Error('no key')
  if (/** @type {any} */ (cfg).btcCommitExists === true) {            // the copy's commit is already journaled (landed or open): the reveal needs no funding
    return { kind: /** @type {'sim' | 'precheck'} */ (cfg.real ? 'sim' : 'precheck'), ok: true, reason: '', balance: 0n, perCopy: 0n, likely: 0n, reserve: 0n, perPart: [{ reserved: 0n }, { reserved: 0n }], cost: 'the commit is already journaled: only the reveal is left (it moves what the commit locked)' }
  }
  const [utxos, rate] = await Promise.all([btcc.utxosOf(key.address), btcc.cappedFeeRate(/** @type {any} */ (cfg).maxFeeRateSatVb)])
  const bal = utxos.reduce((a, u) => a + u.amount, 0n)
  const p = btcc.planCommit(key, parts[0].payload, utxos, rate)
  const perCopy = p.fee + p.value
  if (p.inputs === null) return { kind: /** @type {'sim' | 'precheck'} */ (cfg.real ? 'sim' : 'precheck'), ok: false, reason: `balance ${bal} sat < ${p.value} sat for the inscription + the commit fee`, balance: bal, perCopy, likely: perCopy, reserve: 0n, perPart: [{ reserved: perCopy }, { reserved: 0n }], cost: `${p.value} sat locked for the reveal + the commit fee @ ${rate} sat/vB` }
  let reason = ''
  if (cfg.real) {
    const c = btcc.buildCommit({ key, body: parts[0].payload, inputs: p.inputs, value: p.value, fee: p.fee })
    const res = /** @type {any[]} */ (await btcRpc('testmempoolaccept', [[c.hex]]))
    if (!res?.[0]?.allowed) reason = `the node would not accept the commit: ${String(res?.[0]?.['reject-reason'] ?? 'unknown')}`
  }
  return { kind: /** @type {'sim' | 'precheck'} */ (cfg.real ? 'sim' : 'precheck'), ok: reason === '', reason, balance: bal, perCopy, likely: perCopy, reserve: 0n, perPart: [{ reserved: perCopy }, { reserved: 0n }],
    cost: `commit ${p.fee} sat + ${p.value} sat locked for the reveal (fee ${p.revealFee} + 546 postage, which stays with the inscription) @ ${rate} sat/vB` }
}

// One assessment of one chain: a local pre-check before Arm, a real-byte simulation after. Never throws: a failure is
// { ok: false, reason }. The result is stamped with the message digest and the config key it was made for.
/** @param {'eth' | 'sol' | 'btc'} chain @param {PayloadPart[]} payloadParts @param {AssessCfg} cfg @param {unknown} [_relay] reserved (the RPC goes through rpc.js configureRelay) @returns {Promise<Assessment>} */
export async function assessChain(chain, payloadParts, cfg, _relay) {
  const now = cfg.now ?? Date.now
  /** @type {any} */
  let s
  try {
    if (!payloadParts?.length) throw new Error('no parts planned')
    if (!cfg.address) throw new Error('no key')
    if (chain === 'eth' && !cfg.gasRule) throw new Error('no gas rule (network fork + recipient) — fail closed')
    s = chain === 'btc' ? await assessBtc(cfg, payloadParts) : chain === 'eth' ? await (cfg.real ? simEth : quoteEth)(cfg, payloadParts) : await (cfg.real ? simSol : quoteSol)(cfg, payloadParts)
  } catch (e) { s = { kind: cfg.real ? 'sim' : 'precheck', ok: false, reason: short(e), cost: '—' } }
  return { ...s, msSha: cfg.msSha, cfg: cfg.cfgKey, at: now() }
}
// A real simulation, for this message and this config, made within FRESH_MS (MQ isFresh: whether it passed is
// checked separately).
/** @param {Assessment | null | undefined} s @param {string} msSha @param {string} cfg @param {number} now */
export function isFresh(s, msSha, cfg, now) {
  return !!s && s.kind === 'sim' && s.msSha === msSha && s.cfg === cfg && now - s.at >= 0 && now - s.at < FRESH_MS
}
// MQ torGate: sends need IsTor ✓ except on the local network (loopback chains, no Tor).
/** @param {{ isTor?: boolean | null } | null | undefined} st @param {string} network */
export const torGate = (st, network) => (network === 'local' ? { ok: true, why: '' } : st?.isTor === true ? { ok: true, why: '' }
  : { ok: false, why: st?.isTor === false ? 'IsTor ✗ — the relay is not reaching the network through Tor' : 'IsTor unknown — Tor not confirmed yet' })
// MQ startChain's checks at a chain's own start time (zero or Skip, plus its stagger): Tor, relay identity, and a FRESH
// PASSING real-byte simulation. Any failure skips the chain (fail closed). relay: { tor(), status() } (RelayClient).
/** @param {'eth' | 'sol' | 'btc'} chain @param {Assessment | null | undefined} s @param {{ msSha: string, cfgKey: string, network: string, relay: { tor(): Promise<{ isTor: boolean | null }>, status(): Promise<{ identity: Partial<Record<string, { ok: boolean, message?: string }>> }> }, now: number }} o */
export async function startCheck(chain, s, o) {
  const [ts, st] = await Promise.all([o.relay.tor().catch(() => null), o.relay.status().catch(() => null)])
  const tg = torGate(ts, o.network)
  if (!tg.ok) return { ok: false, why: `sends disabled at its start: ${tg.why} (fail closed)` }
  const id = st?.identity?.[chain]
  if (!id?.ok) return { ok: false, why: `relay identity not OK at its start${id?.message ? ` (${id.message})` : ''}` }
  if (!isFresh(s, o.msSha, o.cfgKey, o.now) || !s?.ok) return { ok: false, why: `not broadcast: last simulation ${!s ? 'missing' : !isFresh(s, o.msSha, o.cfgKey, o.now) ? 'stale' : `failed (${s.reason})`}` }
  return { ok: true, why: '' }
}

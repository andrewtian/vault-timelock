// @ts-check
// PORTED (R69) from the prototype, tag add7-00927d6ade7f, src/mainnet/sol.js (sha256 d251f772bbdc750b5c2354d9c5bc218ea2c0058b7d6c2949771a926e59a3fc79).
// Solana: legacy message, account keys [payer, ComputeBudget, Memo v2]; ALWAYS setComputeUnitLimit + setComputeUnitPrice;
// one Memo v2 (immutable MemoSq4…, R31) instruction with ZERO accounts (research §6). The CU limit is sized from an
// unsigned simulation of the exact tx (⌈1.1 × unitsConsumed⌉); the fee is getFeeForMessage of the FINAL message (it
// already includes the priority fee) and is cross-checked against 5,000 + ⌈limit × price / 10⁶⌉ (fail closed).
// Every RPC goes through the relay; simulations are UNSIGNED (all-zero signatures, sigVerify:false).
import { ComputeBudgetProgram, PublicKey, SystemProgram, TransactionInstruction, TransactionMessage, VersionedTransaction } from '@solana/web3.js'
import { base58, base64 } from '@scure/base'
import { ECON, SOL } from './constants.js'
import { solCuEstimate, solCuLimit, solCuPriceFromRecent, solFee } from './plan.js'
import { rpc, solRpc } from '../engine/rpc.js'
import { assertTicketedSend } from '../gates/send.ts'
import { assertFinalizedAnswer, assertStatusAnswer, assertValidityAnswer } from '../gates/sol-expiry.ts'
// Canonical changes (E2, spec §7.2 + PM): send/rebroadcast pass the gates/send.ts check and carry the relay send ticket;
// the per-endpoint route is rpc(…, { ep }); prepare() also prices by priority LAMPORTS per tx (PM finding 4), converted
// with the part's CU limit; readback also returns the memo bytes (R72 reassembly). E5: send/rebroadcast take the endpoint.
// one specific verified SOL endpoint (relay route /relay/sol/ep/<i>): reads here — the two-endpoint expiry proof (I3); the
// same route also takes ticketed sends (Sfix1: once per ticket per endpoint), through send/rebroadcast's `ep` below
/** @typedef {import('./types.ts').Json} Json */
/** @type {(i: number | null) => (m: string, p: unknown[]) => Promise<Json>} */
const solEp = (i) => (m, p) => (i == null ? solRpc(m, p) : rpc('sol', m, p, { ep: i }))
export const MEMO_V2 = new PublicKey(SOL.MEMO_PROGRAM)

/** @param {PublicKey} payer @param {Uint8Array} bytes @param {string} blockhash @param {{ cuLimit: number, cuPrice: number }} _o */
export function buildTx(payer, bytes, blockhash, { cuLimit, cuPrice }) {
  // R64: price 0 = rung P₀ → omit SetComputeUnitPrice (the CU LIMIT is always set; a price without a limit is the failing case)
  const ixs = [ComputeBudgetProgram.setComputeUnitLimit({ units: cuLimit }), ...(cuPrice > 0 ? [ComputeBudgetProgram.setComputeUnitPrice({ microLamports: cuPrice })] : []),
    new TransactionInstruction({ programId: MEMO_V2, keys: [], data: Buffer.from(bytes) })]
  return new VersionedTransaction(new TransactionMessage({ payerKey: payer, recentBlockhash: blockhash, instructions: ixs }).compileToLegacyMessage())
}
// Largest memo whose SIGNED tx (this exact layout) is ≤ 1232 B — derived from the serialized tx, not guessed.
export function layoutMaxMemo() {
  const L = 300   // any length with a 2-byte shortvec data length (128…16383)
  const size = buildTx(PublicKey.default, new Uint8Array(L), PublicKey.default.toBase58(), { cuLimit: SOL.CU_PROBE_LIMIT, cuPrice: SOL.CU_PRICE_CAP }).serialize().length
  return Math.min(SOL.MEMO_MAX, SOL.TX_CAP - (size - L))
}
export const txSize = (/** @type {VersionedTransaction} */ tx) => { try { return tx.serialize().length } catch { return Infinity } }

/** @type {unknown} */
let rentCache = null
export const rentMin = async () => BigInt(/** @type {any} */ (rentCache ??= await solRpc('getMinimumBalanceForRentExemption', [0])))
export const solBalance = async (/** @type {string} */ addr) => BigInt((await solRpc('getBalance', [addr, { commitment: 'confirmed' }])).value)
/** @param {string} [commitment] @returns {Promise<{ blockhash: string, lastValidBlockHeight: number, slot: number | undefined }>} */
export async function latestBlockhash(commitment = 'confirmed') { const r = await solRpc('getLatestBlockhash', [{ commitment }]); return { ...r.value, slot: r.context?.slot } }
// finalized block height, derived without getBlockHeight: the latest finalized blockhash is valid for 150 more blocks
export const finalizedHeight = async () => (await latestBlockhash('finalized')).lastValidBlockHeight - SOL.MAX_PROCESSING_AGE
// I3: { height, slot } of the finalized bank on endpoint i (height = latest finalized blockhash's lastValidBlockHeight − 150)
/** @param {number | null} i @returns {Promise<{ height: number, slot: number }>} */
export async function finalizedAt(i) { const r = assertFinalizedAnswer(await solEp(i)('getLatestBlockhash', [{ commitment: 'finalized' }])); return { height: r.lastValidBlockHeight - SOL.MAX_PROCESSING_AGE, slot: r.slot } }
// Efix3 (E4 parked / E3 ruling 3): expiry evidence tied to the BLOCKHASH itself, asked of the node that decides it:
// isBlockhashValid says whether a transaction carrying this blockhash can still be processed (older than its validity
// window, or never known: it cannot). `minSlot` (the slot the blockhash was fetched at, when this engine signed it) is sent
// as minContextSlot, so a node whose bank is older than that errors instead of calling a brand-new blockhash unknown. Only a
// well-formed boolean answer counts; anything else (an error, a missing field, a non-boolean, no slot) THROWS — an
// unreadable or ambiguous answer is never proof of expiry (fail closed). Commitment `confirmed`: once invalid there, a
// blockhash stays invalid.
/** @param {number | null} i @param {string} blockhash @param {number} [minSlot] @returns {Promise<{ valid: boolean, slot: number }>} */
export async function blockhashValidAt(i, blockhash, minSlot) {
  if (typeof blockhash !== 'string' || blockhash === '') throw new Error('isBlockhashValid: no blockhash to ask about — fail closed')
  const cfg = { commitment: 'confirmed', ...(Number.isSafeInteger(minSlot) && /** @type {number} */ (minSlot) > 0 ? { minContextSlot: minSlot } : {}) }
  return assertValidityAnswer(await solEp(i)('isBlockhashValid', [blockhash, cfg]), minSlot)   // gates/sol-expiry.ts: only a well-formed boolean from a bank at or past the fetch slot
}
/** @param {number | null} i @param {string[]} ids @param {boolean} history @returns {Promise<{ slot: number, value: Json[] }>} */
export async function statusesAt(i, ids, history) { return assertStatusAnswer(await solEp(i)('getSignatureStatuses', [ids, { searchTransactionHistory: history }]), ids) }   // I-1: only a well-formed answer can say "absent"
// I2: how many transactions this address SENT (fee payer) — memo-bearing signatures, each checked by its fee payer
/** @param {string} address @returns {Promise<number>} */
export async function sentCount(address) {
  const sigs = (await solRpc('getSignaturesForAddress', [address, { limit: 50, commitment: 'confirmed' }])) || []
  let n = 0
  for (const s of sigs.filter((/** @type {Json} */ x) => x.memo != null).slice(0, 10)) {
    const t = await solRpc('getTransaction', [s.signature, { encoding: 'json', commitment: 'confirmed', maxSupportedTransactionVersion: 0 }])
    if (t?.transaction?.message?.accountKeys?.[0] === address) n++
  }
  return n
}
export const autoCuPrice = async () => solCuPriceFromRecent((await solRpc('getRecentPrioritizationFees', [])) || [])

// Exact tx for these bytes: measure CU on an unsigned probe, size the limit, then the fee of the FINAL message.
// o.cuPrice (µL/CU), or o.priorityLamports (per tx, PM): price = ⌈L·10⁶ / CU limit⌉ capped at o.cuPriceCap.
/** @param {PublicKey} payer @param {Uint8Array} bytes @param {{ cuPrice?: number, priorityLamports?: number, cuPriceCap?: number }} o */
export async function prepare(payer, bytes, o) {
  const lamportsMode = o.priorityLamports != null
  let cuPrice = lamportsMode ? (/** @type {number} */ (o.priorityLamports) > 0 ? 1 : 0) : /** @type {number} */ (o.cuPrice)
  if (!Number.isSafeInteger(cuPrice) || cuPrice < 0) throw new Error('prepare: a CU price or priority lamports is required — fail closed')
  const bh = await latestBlockhash()
  // the CU probe runs at the provisional 1.4M CU limit; at the REAL price that would charge up to 1.4M × price in the
  // simulation (e.g. 140,000 lamports at 100,000 µL/CU) and fail a tight payer with InsufficientFundsForRent (R64, found
  // under pressure). So it carries the SAME instruction layout at 1 µL/CU (≤ 2 lamports): identical CU, no fee distortion.
  const probe = buildTx(payer, bytes, bh.blockhash, { cuLimit: SOL.CU_PROBE_LIMIT, cuPrice: cuPrice > 0 ? 1 : 0 })
  const simulate = (/** @type {VersionedTransaction} */ t) => solRpc('simulateTransaction', [base64.encode(t.serialize()), { encoding: 'base64', sigVerify: false, replaceRecentBlockhash: true, commitment: 'confirmed' }])
  const sim = await simulate(probe)
  let err = sim?.value?.err ? JSON.stringify(sim.value.err) : ''
  const units = sim?.value?.unitsConsumed ?? 0
  const estimated = !!err || !units          // e.g. AccountNotFound before funding: fall back to the conservative CU model
  if (!estimated && units > SOL.CU_SPLIT) err = `part needs ${units} CU > ${SOL.CU_SPLIT} — refused (split smaller)`
  const cuLimit = solCuLimit(estimated ? solCuEstimate(bytes) : units)
  if (lamportsMode) cuPrice = solPriceForLamports(/** @type {number} */ (o.priorityLamports), cuLimit, o.cuPriceCap ?? SOL.CU_PRICE_CAP)
  const tx = buildTx(payer, bytes, bh.blockhash, { cuLimit, cuPrice })
  if (/InsufficientFunds/.test(err)) { const s2 = await simulate(tx); err = s2?.value?.err ? JSON.stringify(s2.value.err) : '' }   // funds: judge the REAL tx (real limit + price)
  const fee = await solRpc('getFeeForMessage', [base64.encode(tx.message.serialize()), { commitment: 'confirmed' }])
  if (fee?.value == null) throw new Error('getFeeForMessage returned null (blockhash unknown to the node)')
  const expect = solFee(1, cuLimit, cuPrice)
  if (BigInt(fee.value) !== expect) throw new Error(`fee cross-check failed: getFeeForMessage ${fee.value} ≠ 5000 + ⌈${cuLimit}×${cuPrice}/10⁶⌉ = ${expect} — fail closed`)
  return { tx, err, units, estimated, cuLimit, cuPrice, fee: BigInt(fee.value), size: txSize(tx), blockhash: bh.blockhash, lastValidBlockHeight: bh.lastValidBlockHeight, slot: bh.slot }
}
/** @param {import('@solana/web3.js').Keypair} kp @param {{ tx: VersionedTransaction }} prepared */
export function sign(kp, prepared) {
  const { tx } = prepared
  tx.sign([kp])
  const raw = tx.serialize()
  if (raw.length > SOL.TX_CAP) throw new Error(`signed tx ${raw.length} B > ${SOL.TX_CAP} B`)
  return { raw: base64.encode(raw), id: base58.encode(tx.signatures[0]), size: raw.length }
}
// The ONLY send-type calls on Solana: each needs the relay send ticket of the acked intent (gates/send.ts).
// E5: ep names one verified endpoint (/relay/sol/ep/<i>); the engine sends the same bytes with the same ticket to every
// verified endpoint (engine.js postSol). null: the preferred route.
export const send = (/** @type {string} */ rawB64, /** @type {number | undefined} */ slot, /** @type {string | undefined} */ ticket, /** @type {number | null} */ ep = null) => { assertTicketedSend(ticket); return rpc('sol', 'sendTransaction', [rawB64, { encoding: 'base64', preflightCommitment: 'confirmed', ...(slot ? { minContextSlot: slot } : {}) }], { ticket, ep }) }
export const rebroadcast = (/** @type {string} */ rawB64, /** @type {string | undefined} */ ticket, /** @type {number | null} */ ep = null) => { assertTicketedSend(ticket); return rpc('sol', 'sendTransaction', [rawB64, { encoding: 'base64', skipPreflight: true, maxRetries: 0 }], { ticket, ep }) }
/** @param {string[]} ids @param {boolean} [history] @returns {Promise<Json[]>} */
export async function statuses(ids, history = false) { return assertStatusAnswer(await solRpc('getSignatureStatuses', [ids, { searchTransactionHistory: history }]), ids).value }
/** @param {string} id @param {Uint8Array} bytes @returns {Promise<{ ok: boolean, fee: bigint, cu?: number, slot?: number, detail: string, bytes?: Uint8Array } | null>} */
export async function readback(id, bytes) {
  const t = await solRpc('getTransaction', [id, { encoding: 'json', commitment: 'confirmed', maxSupportedTransactionVersion: 0 }])
  if (!t) return null
  const m = t.transaction.message, keys = m.accountKeys
  const ix = m.instructions.find((/** @type {Json} */ i) => keys[i.programIdIndex] === SOL.MEMO_PROGRAM)
  if (!ix) return { ok: false, detail: 'no Memo v2 instruction', fee: BigInt(t.meta?.fee ?? 0) }
  const data = base58.decode(ix.data)
  const ok = !t.meta?.err && data.length === bytes.length && data.every((b, i) => b === bytes[i])
  return { ok, bytes: data, fee: BigInt(t.meta?.fee ?? 0), cu: t.meta?.computeUnitsConsumed, slot: t.slot,
    detail: `slot ${t.slot} · memo ${data.length} B ${ok ? '= part bytes' : '≠ part bytes'} · fee ${t.meta?.fee} · ${t.meta?.computeUnitsConsumed} CU${t.meta?.err ? ' · err ' + JSON.stringify(t.meta.err) : ''}` }
}

// The chain's record of a landed transfer (claw-back journal integrity): the fee charged, the error if it failed, and
// what `dest` actually received in this tx (post − pre balance of that account in the tx's own metadata).
/** @param {string} id @param {string} dest @returns {Promise<{ fee: bigint, err: unknown, received: bigint | null } | null>} */
export async function transferResult(id, dest) {
  const t = await solRpc('getTransaction', [id, { encoding: 'json', commitment: 'confirmed', maxSupportedTransactionVersion: 0 }])
  if (!t || !t.meta) return null
  const keys = t.transaction?.message?.accountKeys ?? [], i = keys.indexOf(dest)
  const pre = t.meta.preBalances?.[i], post = t.meta.postBalances?.[i]
  const received = i >= 0 && Number.isSafeInteger(pre) && Number.isSafeInteger(post) ? BigInt(post) - BigInt(pre) : null
  return { fee: BigInt(t.meta.fee ?? 0), err: t.meta.err ?? null, received }
}
// R64 claw back: one SystemProgram transfer of (balance − exact fee) so the lane ends at 0 lamports (measured: accepted)
// P2 delta (E3, G1: the claw-back at the lane's fee strategy): Passive / Economy = a plain transfer (5,000 lamports);
// Prompt adds SetComputeUnitLimit + SetComputeUnitPrice for a priority of L lamports per tx (prototype add7b sol.js).
/** @param {PublicKey} from @param {string} to @param {bigint} lamports @param {string} blockhash @param {{ cuLimit?: number, cuPrice?: number }} [o] */
export function buildTransfer(from, to, lamports, blockhash, { cuLimit = 0, cuPrice = 0 } = {}) {
  const cb = cuPrice > 0 ? [ComputeBudgetProgram.setComputeUnitLimit({ units: cuLimit }), ComputeBudgetProgram.setComputeUnitPrice({ microLamports: cuPrice })] : []
  return new VersionedTransaction(new TransactionMessage({ payerKey: from, recentBlockhash: blockhash, instructions: [...cb, SystemProgram.transfer({ fromPubkey: from, toPubkey: new PublicKey(to), lamports })] }).compileToLegacyMessage())
}
/** @param {PublicKey} from @param {string} to @param {{ priorityLamports?: number }} [o] */
export async function transferFee(from, to, { priorityLamports = 0 } = {}) {
  const bh = await latestBlockhash()
  let cuLimit = 0, cuPrice = 0
  if (priorityLamports > 0) {                                     // size the CU limit from an unsigned probe at 1 µL/CU (the same layout)
    const probe = buildTransfer(from, to, 1n, bh.blockhash, { cuLimit: SOL.CU_PROBE_LIMIT, cuPrice: 1 })
    const sim = await solRpc('simulateTransaction', [base64.encode(probe.serialize()), { encoding: 'base64', sigVerify: false, replaceRecentBlockhash: true, commitment: 'confirmed' }])
    cuLimit = solCuLimit(sim?.value?.unitsConsumed || 1000)
    cuPrice = solPriceForLamports(priorityLamports, cuLimit, ECON.SOL_RUNG_CAP)
  }
  const fee = await solRpc('getFeeForMessage', [base64.encode(buildTransfer(from, to, 1n, bh.blockhash, { cuLimit, cuPrice }).message.serialize()), { commitment: 'confirmed' }])
  if (fee?.value == null) throw new Error('getFeeForMessage returned null')
  return { fee: BigInt(fee.value), cuLimit, cuPrice, ...bh }
}
/** @param {VersionedTransaction} tx @returns {Promise<string>} */
export async function simulateUnsigned(tx) {
  const r = await solRpc('simulateTransaction', [base64.encode(tx.serialize()), { encoding: 'base64', sigVerify: false, replaceRecentBlockhash: true, commitment: 'confirmed' }])
  return r?.value?.err ? JSON.stringify(r.value.err) : ''
}
export const recentFeesFor = (/** @type {string[]} */ accounts) => solRpc('getRecentPrioritizationFees', [accounts])
// PM finding 4: a priority of L lamports per tx as a CU price for a part with this CU limit (0 → no SetComputeUnitPrice).
/** @param {number} lamports @param {number} cuLimit @param {number} cap */
export function solPriceForLamports(lamports, cuLimit, cap) {
  if (!(Number.isSafeInteger(lamports) && lamports >= 0 && Number.isSafeInteger(cuLimit) && cuLimit > 0)) throw new Error('priority lamports and the CU limit must be integers — fail closed')
  return lamports === 0 ? 0 : Math.min(cap, Math.ceil((lamports * 1e6) / cuLimit))
}

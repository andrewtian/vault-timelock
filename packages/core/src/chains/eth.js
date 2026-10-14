// @ts-check
// PORTED (R69) from the prototype, tag add7-00927d6ade7f, src/mainnet/eth.js (sha256 2b096152eb0af85b2b028676a221e5bb9beb58d7c3d38a6424443acdf83553d0).
// Ethereum: EIP-1559 (type 2) tx to the NULL ADDRESS (default) or a self-send, value always 0, carrying `data:,` [+ `[i/n] `] + text chunk as calldata. Signed in the page;
// every RPC via the relay. Per tx (research §1, §3):
//   gasLimit = max(21000 + 40·n, 12000 + 64·n, estimate)  (eth_estimateGas must lie within +1.5 % of one formula, else fail closed)
//   tip      = median p50 reward of eth_feeHistory(20), clamped to [0.1 gwei, operator cap]
//   maxFee   = 2 × next block's base fee + tip;  reserved = gasLimit × maxFee;  actual = gasUsed × effectiveGasPrice
// Canonical changes (E2, spec §7.2 + PM): send(raw, ticket) passes the gates/send.ts check and carries the ticket;
// quote(…, rule) checks eth_estimateGas against the exact fork- and recipient-aware formula; the claw-back tx takes
// its gas (sized by destination class, lane.js); baseFeeWindow feeds the Passive target; readback also returns the
// chain's input bytes (R72 reassembly). Tx ids are lowercase (keccak256; receipts lower-cased by the engine).
// E5: accountsAt reads the account (nonces, code) from every verified endpoint for the agreement gate (gates/agree.ts).
import { hexToBytes, keccak256, toHex } from 'viem'
import { CANON, ETH } from './constants.js'
import { ethCheckEstimate, ethGasLimit, ethMaxFee, ethTipFromRewards } from './plan.js'
import { ethTip0 } from './economy.js'
import { ECON } from './constants.js'
import { ethRpc, rpc } from '../engine/rpc.js'
import { assertTicketedSend } from '../gates/send.ts'
import { feeWindowChunkFailed } from '../gates/fee-window.ts'
/** @typedef {import('./types.ts').Json} Json @typedef {`0x${string}`} Hex */
/** @typedef {{ nextBase: bigint, tip: bigint, maxFee: bigint }} EthFees */
/** @param {bigint} tipCap */
export async function fees(tipCap) {
  const h = await ethRpc('eth_feeHistory', ['0x' + ETH.FEE_HISTORY_BLOCKS.toString(16), 'latest', [ETH.TIP_PERCENTILE]])
  const bases = h.baseFeePerGas
  const nextBase = BigInt(bases[bases.length - 1])                 // "includes the next block after the newest"
  const tip = ethTipFromRewards(h.reward || [], tipCap)
  return { nextBase, tip, maxFee: ethMaxFee(nextBase, tip), tipCap }
}
// R64 economy fees: next base + tip₀ = max(floor, median per-block p10 reward) over the last 20 blocks
// P2 delta (E3): the tip floor is the network's (constants.js NETWORK: Sepolia 0.001 gwei, mainnet and local 12,000 wei)
export async function economyFees(floor = ECON.ETH_TIP_FLOOR) {
  const h = await ethRpc('eth_feeHistory', ['0x' + ETH.FEE_HISTORY_BLOCKS.toString(16), 'latest', ECON.ETH_FEE_HISTORY_PCTS])
  const nextBase = BigInt(h.baseFeePerGas[h.baseFeePerGas.length - 1]), tip0 = ethTip0(h.reward || [], floor)
  return { nextBase, tip0, tip: tip0, maxFee: ethMaxFee(nextBase, tip0) }
}
export const balance = async (/** @type {string} */ a) => BigInt(await ethRpc('eth_getBalance', [a, 'latest']))
export const blockNumber = async () => BigInt(await ethRpc('eth_blockNumber', []))
export const nonceAt = async (/** @type {string} */ a, /** @type {'latest' | 'pending'} */ tag) => Number(BigInt(await ethRpc('eth_getTransactionCount', [a, tag])))
// E5 (gates/agree.ts): this address's account on EVERY verified endpoint (n ≥ 2: /relay/eth/ep/<i>, reads only; one:
// the preferred route) — its 'latest' and 'pending' nonces and its code, one answer per endpoint that answered (a failed
// read is left out; when none answered, the first error is thrown, as a single read's would be).
/** @param {string} a @param {number | undefined} n @returns {Promise<Array<{ latest: number, pending: number, code: string }>>} */
export async function accountsAt(a, n) {
  const eps = Number.isSafeInteger(n) && /** @type {number} */ (n) > 1 ? /** @type {number} */ (n) : 1
  const at = async (/** @type {number | null} */ i) => {
    const q = (/** @type {string} */ m, /** @type {unknown[]} */ p) => (i === null ? ethRpc(m, p) : rpc('eth', m, p, { ep: i }))
    const [l, p, code] = await Promise.all([q('eth_getTransactionCount', [a, 'latest']), q('eth_getTransactionCount', [a, 'pending']), q('eth_getCode', [a, 'latest'])])
    return { latest: Number(BigInt(l)), pending: Number(BigInt(p)), code: String(code) }
  }
  const rs = await Promise.allSettled(Array.from({ length: eps }, (_, i) => at(eps > 1 ? i : null)))
  const ok = rs.flatMap((r) => (r.status === 'fulfilled' ? [r.value] : []))
  if (ok.length === 0) throw /** @type {PromiseRejectedResult} */ (rs[0]).reason
  return ok
}
// fee quote for these exact calldata bytes; `check` = estimateGas cross-check against the formulas
// recipient: 'null' → the null address, 'self' → the signer's own address
export const recipientAddress = (/** @type {string} */ choice, /** @type {string} */ from) => (choice === 'self' ? from : ETH.NULL_ADDRESS)
/** @template {EthFees} F @param {string} address @param {Uint8Array} bytes @param {F} f @param {string} [to] @param {import('./plan.js').GasRule} [rule] */
export async function quote(address, bytes, f, to = address, rule = undefined) {
  const data = toHex(bytes)
  const est = BigInt(await ethRpc('eth_estimateGas', [{ from: address, to, value: '0x0', data }]))
  const check = ethCheckEstimate(est, bytes.length, rule)
  const gasLimit = ethGasLimit(bytes.length, est, rule)
  return { data, estimate: est, check, gasLimit, ...f, reserved: gasLimit * f.maxFee, likely: est * (f.nextBase + f.tip) }
}
export const call = (/** @type {string} */ address, /** @type {string} */ data, to = address) => ethRpc('eth_call', [{ from: address, to, value: '0x0', data }, 'latest'])
// the ONLY place a tx object is built: value is always 0 — anything else is refused (ETH sent to 0x0 is burned forever)
/** @param {{ chainId: number, nonce: number, to: string, data: Hex, gas: bigint, maxFee: bigint, tip: bigint, value?: bigint }} _o */
export function buildEthTx({ chainId, nonce, to, data, gas, maxFee, tip, value = 0n }) {
  if (value !== 0n) throw new Error('refusing a non-zero value: this page never transfers ETH (sent to the null address it would be burned forever)')
  if (typeof to !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(to)) throw new Error('bad recipient address')
  return { type: /** @type {const} */ ('eip1559'), chainId, nonce, to: /** @type {Hex} */ (to), value: 0n, data, gas, maxFeePerGas: maxFee, maxPriorityFeePerGas: tip }
}
/** @param {import('viem/accounts').PrivateKeyAccount} account @param {number} chainId @param {{ nonce: number, data: Hex, gas: bigint, maxFee: bigint, tip: bigint, to?: string, value?: bigint }} _o */
export async function sign(account, chainId, { nonce, data, gas, maxFee, tip, to = account.address, value = 0n }) {
  const raw = await account.signTransaction(buildEthTx({ chainId, nonce, to, data, gas, maxFee, tip, value }))
  if ((raw.length - 2) / 2 > ETH.SIGNED_TX_MAX) throw new Error(`signed tx ${(raw.length - 2) / 2} B > ${ETH.SIGNED_TX_MAX} B`)
  return { raw, id: keccak256(raw) }
}
// R64 claw back: the ONLY value-bearing tx — plain transfer, value > 0, 21000 gas, no data, never to 0x0 or to itself
/** @param {{ chainId: number, nonce: number, from: string, to: string, value: bigint, maxFee: bigint, tip: bigint, gas?: bigint }} _o */
export function buildClawbackTx({ chainId, nonce, from, to, value, maxFee, tip, gas = ECON.ETH_CLAW_GAS }) {
  if (typeof value !== 'bigint' || value <= 0n) throw new Error('claw back needs a positive value')
  if (!/^0x[0-9a-fA-F]{40}$/.test(to) || to.toLowerCase() === ETH.NULL_ADDRESS || to.toLowerCase() === String(from).toLowerCase()) throw new Error('bad claw-back destination')
  if (typeof gas !== 'bigint' || gas < ECON.ETH_CLAW_GAS || gas > CANON.ETH_CLAW_GAS_EMPTY_AMSTERDAM) throw new Error('bad claw-back gas')
  return { type: /** @type {const} */ ('eip1559'), chainId, nonce, to: /** @type {Hex} */ (to), value, data: /** @type {Hex} */ ('0x'), gas, maxFeePerGas: maxFee, maxPriorityFeePerGas: tip }
}
/** @param {import('viem/accounts').PrivateKeyAccount} account @param {{ chainId: number, nonce: number, to: string, value: bigint, maxFee: bigint, tip: bigint, gas?: bigint }} fields */
export async function signClawback(account, fields) {
  const raw = await account.signTransaction(buildClawbackTx({ ...fields, from: account.address }))
  return { raw, id: keccak256(raw) }
}
// The ONLY send-type call on Ethereum: it needs the relay send ticket of the acked intent (gates/send.ts).
export const send = (/** @type {string} */ raw, /** @type {string | undefined} */ ticket) => { assertTicketedSend(ticket); return rpc('eth', 'eth_sendRawTransaction', [raw], { ticket }) }
export const known = async (/** @type {string} */ id) => !!(await ethRpc('eth_getTransactionByHash', [id]))
// PF-E (pre-flip review I-2; fix round 2 M-6): the tx as EVERY verified endpoint sees it (eth_getTransactionByHash: in its pool or on
// chain). n ≥ 2: every /relay/eth/ep/<i> (reads); one: the preferred route. known only when every endpoint answered and knows it — one
// endpoint's word is never enough (on mainnet ≥ 2 agree); why names the first endpoint that did not (unreadable, or does not know it).
// When none answered, the first error is thrown (no evidence either way). Used at the end of a window: it is what bounds a wait (engine.js).
/** @param {string} id @param {number | undefined} n @returns {Promise<{ known: boolean, why: string }>} */
export async function knownByEvery(id, n) {
  const eps = Number.isSafeInteger(n) && /** @type {number} */ (n) > 1 ? /** @type {number} */ (n) : 1
  const rs = await Promise.allSettled(Array.from({ length: eps }, (_, i) => (eps > 1 ? rpc('eth', 'eth_getTransactionByHash', [id], { ep: i }) : ethRpc('eth_getTransactionByHash', [id]))))
  if (rs.every((r) => r.status === 'rejected')) throw /** @type {PromiseRejectedResult} */ (rs[0]).reason
  const bad = rs.findIndex((r) => r.status === 'rejected' || !r.value)
  const who = eps > 1 ? `endpoint ${bad}` : 'the endpoint'
  return bad < 0 ? { known: true, why: '' } : { known: false, why: `${who} ${rs[bad].status === 'rejected' ? 'cannot be read' : 'does not know it'}` }
}
/** @type {(id: string) => Promise<Json>} */
export const receipt = (id) => ethRpc('eth_getTransactionReceipt', [id])
// readback: the input bytes AND the recipient AND value 0
/** @param {string} id @param {Uint8Array} bytes @param {string} [to] @returns {Promise<{ ok: boolean, detail: string, bytes: Uint8Array } | null>} */
export async function readback(id, bytes, to) {
  const tx = await ethRpc('eth_getTransactionByHash', [id])
  if (!tx || !tx.blockNumber) return null
  const want = (to ?? tx.from).toLowerCase(), toOk = tx.to?.toLowerCase() === want, inOk = tx.input.toLowerCase() === toHex(bytes).toLowerCase(), valOk = BigInt(tx.value ?? 0) === 0n
  const ok = inOk && toOk && valOk
  return { ok, bytes: hexToBytes(tx.input), detail: `block ${BigInt(tx.blockNumber)} · nonce ${BigInt(tx.nonce)} · to ${want === ETH.NULL_ADDRESS ? '0x0 (Null Address)' : 'self'} ${toOk ? '✓' : '✗'} · input ${(tx.input.length - 2) / 2} B ${inOk ? '= payload bytes' : '≠ payload bytes'}${valOk ? '' : ' · NON-ZERO VALUE'}` }
}
// Passive target data (PM §6): the base fees of the trailing `blocks` blocks (oldest first) and the next block's base fee,
// from base-fee-only eth_feeHistory calls of ≤ 1,024 blocks each (8 calls for the 7,200-block window).
// E5: only the FIRST (newest) chunk must succeed (engine.fee-window-first). An RPC that limits fee history (anvil, public
// providers: about the newest 1,024 blocks) fails a LATER chunk; the walk then stops, never retries, and returns what it
// has: windowBlocks = bases.length, truncated = true (callers show "passive window N blocks (RPC limit)").
/** @param {number} [blocks] @returns {Promise<{ bases: bigint[], nextBase: bigint, latest: number, windowBlocks: number, truncated: boolean }>} */
export async function baseFeeWindow(blocks = CANON.PASSIVE_ETH_WINDOW_BLOCKS) {
  /** @type {bigint[]} */
  let bases = []
  let newest = /** @type {string} */ ('latest'), nextBase = 0n, latest = -1, truncated = false
  for (let left = blocks; left > 0;) {
    const first = latest < 0, count = Math.min(left, CANON.FEE_HISTORY_MAX_BLOCKS)
    /** @type {any} */ let h = null, why = ''
    try { h = await ethRpc('eth_feeHistory', ['0x' + count.toString(16), newest, []]) } catch (e) { why = String(/** @type {Error} */ (e)?.message ?? e).slice(0, 120) }
    const b = (h?.baseFeePerGas || []).map((/** @type {string} */ x) => BigInt(x)), oldest = Number(BigInt(h?.oldestBlock ?? '0x0'))
    if (b.length < 2) { feeWindowChunkFailed(first, why || 'no base fees'); truncated = true; break }
    if (first) { nextBase = b[b.length - 1]; latest = oldest + b.length - 2 }
    bases = [...b.slice(0, -1), ...bases]
    left -= b.length - 1
    if (oldest === 0) break
    newest = '0x' + (oldest - 1).toString(16)
  }
  return { bases, nextBase, latest, windowBlocks: bases.length, truncated }
}
// Claw-back destination class (PM finding 1): empty = nonce 0, balance 0 and no code.
/** @param {string} a @returns {Promise<{ empty: boolean, code: boolean }>} */
export async function accountClass(a) {
  const [n, b, c] = await Promise.all([ethRpc('eth_getTransactionCount', [a, 'latest']), ethRpc('eth_getBalance', [a, 'latest']), ethRpc('eth_getCode', [a, 'latest'])])
  const code = typeof c === 'string' && c !== '0x' && !/^0x0*$/.test(c)
  return { code, empty: BigInt(n) === 0n && BigInt(b) === 0n && !code }
}

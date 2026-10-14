// @ts-check
// PORTED (E7) from the prototype, src/release/chains/btc.js (MQ; the byte vectors in test/engine/btc.test.ts are its output):
// a text INSCRIPTION is two transactions, a COMMIT and a REVEAL. The derivation of everything an inscription is (the leaf
// script, the commit address, the reveal script and destination, the postage, the fee caps) is chains/btc-ord.ts — the one file
// the builder here, the API's ticket minting and the relay's reveal check share (S6b fix round 1, I-2); this module never
// computes those itself.
//
//   · The lane key is ONE secp256k1 key: p2wpkh funds the commit (the lane address `a`), its x-only half signs the reveal
//     by the script path, and the inscribed sat lands at p2tr(x-only).
//   · Signing is DETERMINISTIC (RFC 6979 ECDSA; the Schnorr signature with a zero aux), so a takeover rebuilds the very bytes
//     (the same txid) from the journaled intent and only ever sends the same transaction again.
//   · A copy is two lane txs, part 1 = the commit and part 2 = the reveal, each with its own intent and ticket; the body of both
//     is the copy's one inscription (the part planner's single part, so the copy marker header is in it).
//   · Cost accounting (the cap ledger): the sats that leave the lane's spendable UTXOs. The COMMIT's reserved/spent = its fee + the
//     value it locks into the commit output (the reveal's fee + the 546 sat postage, which stays with the inscription); the REVEAL
//     reserves and spends 0 (it moves only what the commit locked). So the cap is checked once, before the commit, for the whole copy.
//   · Reads go through the relay's POST /relay/btc (the bitcoind JSON-RPC read list, local only in M4). A tx that is not there is
//     "absent" ONLY for bitcoind's txindex-on answer (-5 "No such mempool or blockchain transaction"); every other failure is
//     unknown — never "not sent".
import * as btc from '@scure/btc-signer'
import { pubECDSA } from '@scure/btc-signer/utils.js'
import { OutOrdinalReveal } from 'micro-ordinals'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { BTC_MAX_FEE_RATE, BTC_MAX_INPUTS, BTC_POSTAGE, btcNetwork, commitAddress, commitOutput, commitVsizeBound, laneAddresses, maxCommitFee, maxRevealFee, readReveal, revealDestination, revealVsizeBound } from './btc-ord.ts'
import { splitText } from './plan.js'
import { RpcError, btcRpc, rpc } from '../engine/rpc.js'
import { assertTicketedSend } from '../gates/send.ts'
import { assertBtcRate } from '../gates/btc.ts'

/** @typedef {import('../contracts/index.ts').Network} Network */
/** @typedef {{ txid: string, index: number, amount: bigint }} Utxo */
export const BTC_BODY_MAX = 100_000        // bytes of one inscription body (a standard reveal tx stays far below 400k weight)
export const BTC_DUST = 546n                // the smallest change output kept (below it the leftover goes to the fee)
export const BTC_RATE_FALLBACK = 2n         // sat/vB when the node has no estimate (a fresh regtest chain)
export const BTC_CONFIRMATIONS = 1

// ---------- the key ----------
// A BTC lane key: 0x-less 64 hex secp256k1 secret → { chain, network, address (p2wpkh), pubkey (33-byte hex), xonly } with the
// secret non-enumerable (JSON.stringify / spread / inspect never show it; code that needs it names it: key.secret).
/** @param {unknown} input @param {Network} network */
export function btcFromSecret(input, network) {
  const hex = String(input).trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error('BTC key must be exactly 64 hex characters')
  const secret = hexToBytes(hex)
  /** @type {Uint8Array} */ let pub
  try { pub = pubECDSA(secret) } catch { throw new Error('not a valid secp256k1 private key (need 0 < k < n)') }
  const lane = laneAddresses(network, pub)
  if (lane === null) throw new Error('not a valid secp256k1 private key')
  const key = { chain: /** @type {const} */ ('btc'), network, address: /** @type {string} */ (lane.p2wpkh), pubkey: bytesToHex(pub), xonly: bytesToHex(lane.xonly), p2tr: /** @type {string} */ (lane.p2tr) }
  Object.defineProperty(key, 'secret', { value: hex, enumerable: false, writable: false, configurable: false })
  return /** @type {typeof key & { readonly secret: string }} */ (key)
}
/** @typedef {ReturnType<typeof btcFromSecret>} BtcKey */
/** @param {BtcKey} key */
const priv = (key) => hexToBytes(key.secret)

// ---------- the body of a copy ----------
// Copy i's single inscription body (the planner's one part, so the copy marker header is in it) as the two lane txs.
// More than one part (the text does not fit BTC_BODY_MAX) is refused: one copy is one inscription.
/** @param {Uint8Array} textBytes @param {{ sha256: string, copy: number | null, copies: number | null }} o */
export function planBtcCopy(textBytes, o) {
  const parts = splitText(textBytes, { cap: BTC_BODY_MAX, ...o })
  if (parts.length !== 1) throw new Error(`a BTC copy is one inscription of at most ${BTC_BODY_MAX} bytes; this text needs ${parts.length}`)
  const { chunk, payload } = parts[0]
  return [1, 2].map((i) => ({ i, n: 2, chunk, payload }))
}

// ---------- the transactions (deterministic) ----------
/** @param {Utxo[]} ins */
const sortIns = (ins) => [...ins].sort((a, b) => { const x = `${a.txid}:${a.index}`, y = `${b.txid}:${b.index}`; return x < y ? -1 : x > y ? 1 : 0 })
export const outpointsOf = (/** @type {Utxo[]} */ ins) => sortIns(ins).map((u) => `${u.txid}:${u.index}`)
/** @param {import('@scure/btc-signer').Transaction} t */
const bundle = (t) => { const bytes = t.extract(); return { bytes, hex: bytesToHex(bytes), txid: t.id, vsize: t.vsize, rawSha256: bytesToHex(sha256(bytes)) } }
/** The commit: inputs (all lane p2wpkh UTXOs), output 0 = value to the commit address, output 1 = change when ≥ BTC_DUST.
 * @param {{ key: BtcKey, body: Uint8Array, inputs: Utxo[], value: bigint, fee: bigint }} o */
export function buildCommit({ key, body, inputs, value, fee }) {
  const net = btcNetwork(key.network), pub = hexToBytes(key.pubkey), xonly = hexToBytes(key.xonly)
  const W = btc.p2wpkh(pub, net)
  const ins = sortIns(inputs)
  if (ins.length < 1 || ins.length > BTC_MAX_INPUTS) throw new Error(`a commit spends 1..${BTC_MAX_INPUTS} lane outputs`)
  const total = ins.reduce((a, u) => a + u.amount, 0n)
  if (value < BTC_POSTAGE || fee < 1n || total < value + fee) throw new Error('the commit does not fit its inputs')
  const t = new btc.Transaction()
  for (const u of ins) t.addInput({ txid: u.txid, index: u.index, witnessUtxo: { script: W.script, amount: u.amount } })
  t.addOutputAddress(commitAddress(key.network, xonly, body), value, net)
  const change = total - value - fee
  if (change >= BTC_DUST) t.addOutputAddress(/** @type {string} */ (W.address), change, net)
  t.sign(priv(key)); t.finalize()
  const b = bundle(t)
  return { ...b, fee: change >= BTC_DUST ? fee : total - value, change: change >= BTC_DUST ? change : 0n, value, commitVout: 0 }
}
/** The reveal: spends the commit output (txid:vout, `amount` sats) by the script path to the 546 sat postage at p2tr(x-only);
 * its fee is the rest: amount − 546.
 * @param {{ key: BtcKey, body: Uint8Array, commitTxid: string, commitVout: number, amount: bigint }} o */
export function buildReveal({ key, body, commitTxid, commitVout, amount }) {
  const net = btcNetwork(key.network), xonly = hexToBytes(key.xonly)
  if (amount <= BTC_POSTAGE) throw new Error('the commit output cannot pay the reveal fee')
  const out = commitOutput(key.network, xonly, body)
  const t = new btc.Transaction({ customScripts: [OutOrdinalReveal] })
  t.addInput({ ...out, txid: commitTxid, index: commitVout, witnessUtxo: { script: out.script, amount } })
  t.addOutputAddress(revealDestination(key.network, xonly), BTC_POSTAGE, net)
  t.sign(priv(key), undefined, new Uint8Array(32)); t.finalize()
  return { ...bundle(t), fee: amount - BTC_POSTAGE }
}

// ---------- fees ----------
// sat/vB from the node (estimatesmartfee 2 blocks), the fallback on a chain with no estimate; never above BTC_MAX_FEE_RATE.
export async function feeRate() {
  let r = BTC_RATE_FALLBACK
  try {
    const e = await btcRpc('estimatesmartfee', [2])
    if (typeof e?.feerate === 'number' && e.feerate > 0) r = BigInt(Math.ceil((e.feerate * 1e8) / 1000))
  } catch { /* no estimate: the fallback */ }
  return r < 1n ? 1n : r
}
/** The plan of a commit over the UTXOs: the inputs, value (postage + the reveal's fee at `rate`) and the commit fee.
 * @param {BtcKey} key @param {Uint8Array} body @param {Utxo[]} utxos @param {bigint} rate */
export function planCommit(key, body, utxos, rate) {
  assertBtcRate(rate <= BTC_MAX_FEE_RATE, `the fee rate ${rate} sat/vB is above the ${BTC_MAX_FEE_RATE} sat/vB the tickets allow — nothing is signed`)
  const probe = buildReveal({ key, body, commitTxid: '00'.repeat(32), commitVout: 0, amount: 10_000_000n })
  const value = BTC_POSTAGE + BigInt(probe.vsize) * rate
  // a coin at the postage size or below may be a foreign inscription sent to the lane address (a commit spending it would move it and
  // turn our reveal into a reinscription), and is useless as funding anyway: never selected
  utxos = utxos.filter((u) => u.amount > BTC_POSTAGE)
  const sorted = [...utxos].sort((a, b) => (a.amount > b.amount ? -1 : a.amount < b.amount ? 1 : 0))
  for (let n = 1; n <= Math.min(BTC_MAX_INPUTS, sorted.length); n++) {
    const inputs = sorted.slice(0, n), total = inputs.reduce((a, u) => a + u.amount, 0n)
    if (total <= value) continue
    const dry = buildCommit({ key, body, inputs, value, fee: 1n })   // vsize probe (the fee is not part of the size)
    const fee = BigInt(dry.vsize) * rate
    if (total >= value + fee) {
      if (fee > maxCommitFee(n)) throw new Error('the commit fee would exceed the ticket cap')
      if (value - BTC_POSTAGE > maxRevealFee(body.length)) throw new Error('the reveal fee would exceed the ticket cap')
      // a leftover below the dust limit has no change output: it goes to the fee (the intent journals the fee the tx pays)
      const paid = total - value - fee >= BTC_DUST ? fee : total - value
      if (paid > maxCommitFee(n)) throw new Error('the commit fee would exceed the ticket cap')
      return { inputs, value, fee: paid, revealFee: value - BTC_POSTAGE, total }
    }
  }
  const have = sorted.slice(0, BTC_MAX_INPUTS).reduce((a, u) => a + u.amount, 0n)
  return { inputs: null, value, fee: 0n, revealFee: value - BTC_POSTAGE, total: have }
}

// ---------- reads (the relay's /relay/btc: bitcoind JSON-RPC, local) ----------
const sats = (/** @type {number} */ btcAmount) => BigInt(Math.round(btcAmount * 1e8))
/** The lane address's confirmed UTXOs. @param {string} address @returns {Promise<Utxo[]>} */
export async function utxosOf(address) {
  for (let i = 0; ; i++) {
    try {
      const r = await btcRpc('scantxoutset', ['start', [{ desc: `addr(${address})` }]])
      if (!r?.success || !Array.isArray(r.unspents)) throw new Error('scantxoutset did not succeed')
      return r.unspents.map((/** @type {any} */ u) => ({ txid: String(u.txid), index: Number(u.vout), amount: sats(u.amount) }))
    } catch (e) {
      if (i < 5 && /already in progress/i.test(String(/** @type {Error} */ (e)?.message))) { await new Promise((r) => setTimeout(r, 300)); continue }
      throw e
    }
  }
}
export const balanceOf = async (/** @type {string} */ address) => (await utxosOf(address)).reduce((a, u) => a + u.amount, 0n)
/** A tx by id: null when the node (with a txindex) says there is no such mempool or blockchain tx; throws on anything else.
 * @param {string} txid @returns {Promise<any | null>} */
export async function getTx(txid) {
  try { return await btcRpc('getrawtransaction', [txid, true]) } catch (e) {
    if (e instanceof RpcError && /** @type {any} */ (e).rpc?.code === -5 && /No such mempool or blockchain transaction/.test(/** @type {any} */ (e).rpc?.message ?? '')) return null
    throw e
  }
}
/** The unspent output (mempool included unless `mempool` is false), or null when it is spent / does not exist. @param {string} txid @param {number} vout @param {boolean} [mempool] */
export async function txOut(txid, vout, mempool = true) { return btcRpc('gettxout', [txid, vout, mempool]) }
/** The height of a block by hash. @param {string} blockhash */
export async function heightOf(blockhash) { return Number((await btcRpc('getblockheader', [blockhash, true])).height) }

// ---------- the send ----------
// The ONLY send-type call on Bitcoin: it needs the relay send ticket of the acked intent (gates/send.ts) and goes to POST
// /relay/btc/send. Resolves the txid the relay answered; every failure throws and means NOTHING about whether the tx was sent.
/** @param {string} hex @param {string | undefined} ticket */
export const send = (hex, ticket) => { assertTicketedSend(ticket); return rpc('btc', 'btc_send', [hex], { ticket }) }

// ---------- readback ----------
/** The commit as the chain shows it: output 0 pays the commit address exactly `value`.
 * @param {BtcKey} key @param {Uint8Array} body @param {any} tx @param {bigint} value */
export function readbackCommit(key, body, tx, value) {
  const o = tx?.vout?.[0]
  const addrOk = o?.scriptPubKey?.address === commitAddress(key.network, hexToBytes(key.xonly), body)
  const valOk = typeof o?.value === 'number' && sats(o.value) === value
  return { ok: addrOk && valOk, bytes: body, detail: `commit output 0 → the commit address ${addrOk ? '✓' : '✗'} · ${valOk ? `${value} sat ✓` : 'value differs ✗'}` }
}
/** The reveal as the chain shows it: its witness is exactly the builder's one inscription (btc-ord readReveal), the body is the part's
 * bytes, and the postage went to p2tr(x-only).
 * @param {BtcKey} key @param {Uint8Array} body @param {any} tx */
export function readbackReveal(key, body, tx) {
  const w = tx?.vin?.[0]?.txinwitness
  if (!Array.isArray(w)) return { ok: false, bytes: /** @type {Uint8Array | null} */ (null), detail: 'no witness' }
  const r = readReveal(w.map((/** @type {string} */ h) => hexToBytes(h)))
  if (!r.ok) return { ok: false, bytes: null, detail: `the witness is not the one inscription (${r.reason})` }
  const bodyOk = r.body.length === body.length && r.body.every((b, i) => b === body[i])
  const keyOk = bytesToHex(r.xonly) === key.xonly
  const o = tx.vout?.[0]
  const destOk = tx.vout?.length === 1 && o?.scriptPubKey?.address === revealDestination(key.network, hexToBytes(key.xonly)) && typeof o?.value === 'number' && sats(o.value) === BTC_POSTAGE
  return { ok: bodyOk && keyOk && destOk, bytes: r.body, detail: `inscription ${r.body.length} B ${bodyOk ? '= part bytes ✓' : '≠ part bytes ✗'} · text/plain · ${destOk ? `${BTC_POSTAGE} sat to the lane's taproot address ✓` : 'destination differs ✗'}` }
}

/** The fee-rate ceiling a job prices and caps at: its maxFeeRateSatVb, else the tickets' 500 sat/vB (a job created before the field was required).
 * @param {{ maxFeeRateSatVb?: number | null } | null | undefined} ch @returns {bigint} */
export const feeCeilingOf = (ch) => BigInt(ch?.maxFeeRateSatVb ?? BTC_MAX_FEE_RATE)
// ---------- pricing (E7b m-1): the key-free TRUE worst case of ONE copy, for the arm caps and `startingFees` ----------
// `maxRate` is the CEILING the engine can pay at (the job's maxFeeRateSatVb, or the tickets' 500 sat/vB when unset), never today's estimate.
// A copy's outlay = the commit's fee (paid) + the value the commit locks (postage + the reveal's fee). Upper bounds, each reachable by planCommit:
//   · commitFee: the commit vsize bound for the most inputs a commit may spend (BTC_MAX_INPUTS = 8; signatures, one change output included) at the
//     ceiling, PLUS the largest leftover that has no change output (BTC_DUST - 1 = 545 sat), which planCommit adds to the fee it pays;
//   · revealFee: the reveal vsize bound for this exact body length at the ceiling; postage: BTC_POSTAGE.
// perCopy = their sum: the engine never spends more than this for a copy (test/engine/btc-keys-fees.test.ts: property over bodies, rates, input counts).
/** @param {number} bodyLen @param {bigint} maxRate */
export function copyCost(bodyLen, maxRate) {
  const commitFee = commitVsizeBound(BTC_MAX_INPUTS) * maxRate + (BTC_DUST - 1n), revealFee = revealVsizeBound(bodyLen) * maxRate
  return { rate: maxRate, commitFee, revealFee, postage: BTC_POSTAGE, perCopy: commitFee + revealFee + BTC_POSTAGE }
}
// The fee rate the lane uses: the node's estimate, clamped to the job's maxFeeRateSatVb (and to the tickets' 500 sat/vB).
/** @param {number | null | undefined} cap */
export async function cappedFeeRate(cap) {
  const est = await feeRate(), top = cap == null ? BTC_MAX_FEE_RATE : BigInt(cap)
  return est > top ? top : est
}

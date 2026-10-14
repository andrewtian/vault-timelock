// packages/core/src/chains/btc-ord.ts — the ONE derivation of a BTC text inscription (plan S6b fix round 1, CC-8; the
// builder of plan E7, the API's ticket minting and the relay's reveal check all import this file, so they cannot disagree).
//
// An inscription is a commit tx and a reveal tx:
//   · the lane key (secp256k1, 33-byte compressed pubkey; x-only = bytes 1..33) signs for everything;
//   · the leaf script is exactly p2tr_ord_reveal(xonly, [{ tags: { contentType }, body }]).script: <xonly> CHECKSIG
//     OP_0 OP_IF "ord" 1 <content type> OP_0 <body in <= 520-byte pushes> OP_ENDIF;
//   · the commit pays p2tr(NUMS internal key, that one leaf) = the "commit address" (scure's TAPROOT_UNSPENDABLE_KEY, so
//     only the script path can spend it, and only by the lane key);
//   · the reveal spends that output by the script path (witness: <64-byte schnorr signature> <leaf> <control block>, the
//     control block 33 bytes: 0xc0 or 0xc1, then NUMS) and pays POSTAGE sats to p2tr(xonly), the "reveal destination".
// The content type is always BTC_CONTENT_TYPE. A body is the exact UTF-8 bytes of the message part.
import * as btc from '@scure/btc-signer'
import { PubT, hash160, validatePubkey } from '@scure/btc-signer/utils.js'
import { OutOrdinalReveal, p2tr_ord_reveal, parseWitness } from 'micro-ordinals'
import type { Network } from '../contracts/index.ts'

export const BTC_CONTENT_TYPE = 'text/plain;charset=utf-8'
export const BTC_POSTAGE = 546n                      // sats on the inscription output
export const BTC_BODY_MAX = 100_000                   // bytes of one inscription body (one copy = one inscription; the part planner's cap)
export const BTC_MAX_INPUTS = 8                       // lane UTXOs one commit may spend (ticket q)
export const BTC_MAX_FEE_RATE = 500n                  // sat/vB: the highest rate a ticket's value / fee cap assumes
export const BTC_NUMS = btc.TAPROOT_UNSPENDABLE_KEY as Uint8Array

const NETWORKS: Readonly<Record<Network, typeof btc.NETWORK>> = Object.freeze({
  local: Object.freeze({ bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef }),
  testnet: btc.TEST_NETWORK,                          // testnet4 shares testnet3's address versions
  mainnet: btc.NETWORK,
})
export const btcNetwork = (network: Network): typeof btc.NETWORK => NETWORKS[network]

const eq = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i])
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex')

// The 32-byte x-only key of a 33-byte compressed pubkey, or null when it is not a valid curve point.
export function xonlyOf(pubkey: Uint8Array): Uint8Array | null {
  try {
    if (pubkey.length !== 33 || (pubkey[0] !== 2 && pubkey[0] !== 3)) return null
    validatePubkey(pubkey, PubT.ecdsa)   // throws on a point that is not on the curve
    return Uint8Array.from(pubkey.subarray(1))
  } catch { return null }
}

// The lane's addresses on a network: the p2wpkh address (the funding address a of a commit) and the p2tr address of the
// x-only key (the reveal destination, also a valid lane address a).
export function laneAddresses(network: Network, pubkey: Uint8Array): { p2wpkh: string; p2tr: string; xonly: Uint8Array } | null {
  const xonly = xonlyOf(pubkey)
  if (xonly === null) return null
  const net = NETWORKS[network]
  return { p2wpkh: btc.p2wpkh(pubkey, net).address!, p2tr: btc.p2tr(xonly, undefined, net).address!, xonly }
}
// True when the pubkey's p2wpkh hash160 (or its p2tr key) is exactly address `a` on this network.
export function laneOwns(network: Network, pubkey: Uint8Array, a: string): boolean {
  const l = laneAddresses(network, pubkey)
  return l !== null && (a === l.p2wpkh || a === l.p2tr)
}

// The inscription leaf script, exactly as the builder makes it.
export function inscriptionLeaf(xonly: Uint8Array, body: Uint8Array): Uint8Array {
  return p2tr_ord_reveal(xonly, [{ tags: { contentType: BTC_CONTENT_TYPE }, body }]).script
}
// The commit output: the p2tr_ord_reveal payment object (the builder signs the reveal with it: { ...reveal, txid, index,
// witnessUtxo }), its script (scriptPubKey) and its address on `network`.
export function commitOutput(network: Network, xonly: Uint8Array, body: Uint8Array) {
  const reveal = btc.p2tr(undefined, p2tr_ord_reveal(xonly, [{ tags: { contentType: BTC_CONTENT_TYPE }, body }]), NETWORKS[network], false, [OutOrdinalReveal])
  return reveal
}
export const commitAddress = (network: Network, xonly: Uint8Array, body: Uint8Array): string => commitOutput(network, xonly, body).address!
// The reveal's destination: p2tr(xonly) on the network, where the inscribed sat lands.
export const revealDestination = (network: Network, xonly: Uint8Array): string => btc.p2tr(xonly, undefined, NETWORKS[network]).address!

// ---- the signatures of a commit's inputs (I-3): every one must commit to ALL outputs, or anyone may re-spend the public
// signature (SIGHASH_NONE / SINGLE / ANYONECANPAY). `script` is the scriptPubKey the relay read for the input, `witness` and
// `scriptSig` the input as signed. Returns null, or the reason.
export function inputSighashMismatch(script: Uint8Array, witness: Uint8Array[] | undefined, scriptSig: Uint8Array | undefined): string | null {
  if (scriptSig !== undefined && scriptSig.length !== 0) return 'btc.sighash'
  const w = witness ?? []
  if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) {          // p2wpkh: [DER signature ‖ 0x01 (SIGHASH_ALL), pubkey]
    if (w.length !== 2) return 'btc.sighash'
    const [sig, pk] = w
    if (sig.length < 9 || sig.length > 73 || sig[sig.length - 1] !== 0x01 || sig[0] !== 0x30) return 'btc.sighash'
    if (pk.length !== 33 || !eq(hash160(pk), script.subarray(2))) return 'btc.sighash'
    return null
  }
  if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) return w.length === 1 && w[0].length === 64 ? null : 'btc.sighash'   // p2tr key path: SIGHASH_DEFAULT
  return 'btc.sighash'                                                              // no other input type is a lane input
}

// ---- fee / value caps a ticket may bind (the API mints f and the commit value only up to these)
const ceilDiv = (a: bigint, b: bigint): bigint => (a + b - 1n) / b
// A bound on the reveal's vsize for a body of `bodyLen` bytes (one input by the script path, one output).
export const revealVsizeBound = (bodyLen: number): bigint => 300n + ceilDiv(BigInt(bodyLen) + 3n * ceilDiv(BigInt(bodyLen), 520n) + 200n, 4n)
// A bound on a commit's vsize spending `nInputs` p2wpkh / p2tr inputs with two outputs.
export const commitVsizeBound = (nInputs: number): bigint => 100n + 70n * BigInt(nInputs)
// The most sats the commit may put on the reveal output, and the most either tx may pay in fee.
export const maxCommitValue = (bodyLen: number): bigint => BTC_POSTAGE + revealVsizeBound(bodyLen) * BTC_MAX_FEE_RATE
export const maxRevealFee = (bodyLen: number): bigint => revealVsizeBound(bodyLen) * BTC_MAX_FEE_RATE
export const maxCommitFee = (nInputs: number): bigint => commitVsizeBound(nInputs) * BTC_MAX_FEE_RATE

// ---- the reveal witness (the relay's check; ord's parser and micro-ordinals' parser differ on odd scripts, so the leaf is
// pinned byte for byte instead of being "parsed")
export type RevealRead = { ok: true; body: Uint8Array; xonly: Uint8Array } | { ok: false; reason: string }
export function readReveal(witness: Uint8Array[] | undefined): RevealRead {
  const bad = (reason: string): RevealRead => ({ ok: false, reason })
  if (witness === undefined || witness.length !== 3) return bad('btc.witness')          // no annex, no extra items
  const [sig, leaf, control] = witness
  if (sig.length !== 64) return bad('btc.witness')                                       // a schnorr signature, default sighash
  if (control.length !== 33 || (control[0] !== 0xc0 && control[0] !== 0xc1)) return bad('btc.control')   // one leaf, tapscript version
  if (!eq(control.subarray(1), BTC_NUMS)) return bad('btc.control')                      // the commit's internal key
  let key: unknown
  try { [key] = btc.Script.decode(leaf) as unknown[] } catch { return bad('btc.envelope') }
  if (!(key instanceof Uint8Array)) return bad('btc.envelope')            // the rebuild below fixes its length and the rest of the script
  let found: ReturnType<typeof parseWitness>
  try { found = parseWitness(witness) } catch { return bad('btc.envelope') }
  if (found === undefined || found[0] === undefined) return bad('btc.inscription')
  const { body } = found[0]                                                       // two inscriptions: the rebuild (one) differs
  if (!eq(inscriptionLeaf(key, body), leaf)) return bad('btc.envelope')                  // ord sees exactly this one inscription
  return { ok: true, body, xonly: Uint8Array.from(key) }
}
export const hexOf = hex

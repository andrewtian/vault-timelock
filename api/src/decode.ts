// api/src/decode.ts — the relay's decode verification (S4; CC-3 ticket v2; required before the M2 mainnet flip).
//
// The relay forwards a send only if the signed bytes are exactly what the API ticketed. checkSend (relay-gate.ts) has
// already verified the ticket (MAC, expiry), w, c, r = sha256(raw) and the job-send lock; this decodes the raw bytes
// and checks them against t, a, k, p, to, value, f and q (field formats: @vault-timelock/core/contracts http.ts). Any
// difference, any decoding error and any shape outside the list below refuses relay.decode-mismatch (fail closed: an
// exception is a mismatch, never a pass). The refusal names a fixed reason token, never a value from the request.
//
// ETH (viem parseTransaction):
//   · 1 … 131,072 bytes; type 2 (EIP-1559) only — legacy, EIP-2930, blob (type 3) and EIP-7702 (type 4) are refused;
//   · canonical: serializeTransaction(parse(raw)) re-encodes to exactly raw (no leading zeros, no trailing bytes);
//   · chainId = the network's (vt-broadcast chainId); nonce = q (CC-3a: the declared nonce, which the API's nonce
//     families and the takeover reconcile rely on); gas > 0 and maxFeePerGas > 0 present;
//     maxPriorityFeePerGas ≤ maxFeePerGas; empty access list;
//   · signature: yParity 0/1, 0 < r < n, 0 < s ≤ n/2 (low s, EIP-2); recovered from = a; keccak256(raw) = t;
//   · fee binding: gas × maxFeePerGas ≤ f; and (PF-S fix round 2, R1-1) gas, maxPriorityFeePerGas and maxFeePerGas are exactly the
//     ticket's x (the intent's declared members): no executor-chosen value rides in them ('eth.fee-members');
//   · job: value 0, to = the ticket's to (PF-S I-1: the recipient the job's publish mode sends to, 0x000…0 or a — exactly that one,
//     never "either"), sha256(data) = p. clawback: to = ticket to, value = ticket value, data empty.
// SOL (@solana/web3.js VersionedTransaction.deserialize):
//   · 1 … 1,232 bytes; canonical (re-serializes to exactly raw); a legacy message or v0 WITHOUT address lookup tables;
//   · header: exactly one required signature (the fee payer, writable), readonly counts within the key list; one
//     signature; no duplicate account keys; fee payer = a; the ed25519 signature verifies over the message bytes;
//     base58(signature) = t; recentBlockhash = q (CC-3a: the declared blockhash, which expiry is judged by);
//   · instructions only from: ComputeBudget SetComputeUnitLimit (u32) / SetComputeUnitPrice (u64), at most one each,
//     no accounts; Memo v2 (MemoSq4…), no accounts; System transfer (instruction 2: from, to; u64 lamports);
//   · fee binding: 5,000 × 1 + ⌈limit × price / 10⁶⌉ ≤ f, a missing limit counted at 1,400,000 CU (the runtime's
//     maximum, so never under the real charge) and a missing price at 0;
//   · job: exactly one memo, sha256(memo data) = p, no transfer, and the fee payer is the only writable account;
//     clawback: exactly one transfer, from the fee payer to ticket `to` of exactly `value` lamports, no memo, and the
//     writable accounts are exactly the fee payer and `to`;
//   · PF-S fix round 2 (R1-1): the message is EXACTLY the one vt's own builder makes from the ticket (core chains/sol.js buildTx for a
//     job: payer a, the memo, blockhash q, x's cuLimit and cuPrice; buildTransfer for a claw-back: a → to of value, q, x), byte for
//     byte ('sol.layout'): a legacy message, its keys and instructions in the builder's order, SetComputeUnitLimit = cuLimit (a job
//     always carries it; a claw-back only with a price), SetComputeUnitPrice = cuPrice and present only when cuPrice > 0. So a CU
//     limit of 0, a CU price as free bits, another order or a v0 message never pass;
//   · PF-S fix round 1 (re-review N-1): the account keys are EXACTLY the ones the instructions use — the fee payer, the
//     programs of the instructions present (Memo v2 / System, ComputeBudget only with a CU instruction) and, for a
//     claw-back, `to`. An extra key, read-only or not, is refused ('sol.extra-account'): 32 executor-chosen bytes each,
//     published with the tx.
import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto'
import * as btc from '@scure/btc-signer'
import { VersionedTransaction } from '@solana/web3.js'
import { OutOrdinalReveal, parseWitness } from 'micro-ordinals'
import { BTC_CONTENT_TYPE, btcNetwork, inputSighashMismatch, readReveal, revealDestination as btcRevealTo } from '@vault-timelock/core/chains/btc-ord.ts'
import { keccak256, parseTransaction, recoverTransactionAddress, serializeTransaction, toHex } from 'viem'
import type { TransactionSerializedEIP1559 } from 'viem'
import type { Network, TicketPayload } from '@vault-timelock/core/contracts'
import { buildTransfer as solBuildTransfer, buildTx as solBuildTx } from '@vault-timelock/core/chains/sol.js'
import { PublicKey } from '@solana/web3.js'
import { chainId } from 'vt-broadcast/src/config.ts'
import { refuse } from 'vt-broadcast/src/guard.ts'
import { base58Encode } from './tickets.ts'

export const ETH_RAW_MAX = 131_072                  // 128 KiB: the largest tx a node's pool accepts
export const SOL_RAW_MAX = 1_232                    // the Solana packet limit for a signed tx
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const SECP256K1_HALF_N = SECP256K1_N >> 1n
const COMPUTE_BUDGET = 'ComputeBudget111111111111111111111111111111'
const MEMO_V2 = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'
const SYSTEM = '11111111111111111111111111111111'
const SOL_SIGNATURE_FEE = 5_000n
const SOL_MAX_CU_LIMIT = 1_400_000n

const sha256Hex = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex')
const ceilDiv = (a: bigint, b: bigint): bigint => (a + b - 1n) / b

// ---- ETH

async function ethMismatch(t: TicketPayload, raw: Uint8Array, network: Network): Promise<string | null> {
  if (raw.length < 1 || raw.length > ETH_RAW_MAX) return 'eth.size'
  if (raw[0] !== 0x02) return 'eth.type'
  const hex = toHex(raw) as TransactionSerializedEIP1559
  const tx = parseTransaction(hex)
  if (tx.type !== 'eip1559') return 'eth.type'
  if (serializeTransaction(tx) !== hex) return 'eth.canonical'
  if (tx.chainId !== chainId(network, 'eth')) return 'eth.chain-id'
  if (!Number.isSafeInteger(tx.nonce) || String(tx.nonce) !== t.q) return 'eth.nonce'
  const gas = tx.gas, maxFee = tx.maxFeePerGas, tip = tx.maxPriorityFeePerGas ?? 0n
  if (typeof gas !== 'bigint' || gas <= 0n) return 'eth.gas'
  if (typeof maxFee !== 'bigint' || maxFee <= 0n) return 'eth.max-fee'
  if (tip > maxFee) return 'eth.tip'
  if (tx.accessList !== undefined && tx.accessList.length !== 0) return 'eth.access-list'
  const r = BigInt(tx.r ?? '0x0'), s = BigInt(tx.s ?? '0x0')
  const sigOk = (tx.yParity === 0 || tx.yParity === 1) && r > 0n && r < SECP256K1_N && s > 0n && s <= SECP256K1_HALF_N
  if (!sigOk) return 'eth.signature'
  const from = (await recoverTransactionAddress({ serializedTransaction: hex })).toLowerCase()
  if (from !== t.a) return 'eth.from'
  if (keccak256(raw) !== t.t) return 'eth.tx-id'
  if (gas * maxFee > BigInt(t.f)) return 'eth.fee'
  // R1-1: the fee members are exactly the declared ones
  const members = (t.x ?? '').split(':')
  if (members.length !== 3 || members.some((v) => !/^(?:0|[1-9][0-9]*)$/.test(v))) return 'eth.fee-members'
  if (gas !== BigInt(members[0]) || tip !== BigInt(members[1]) || maxFee !== BigInt(members[2])) return 'eth.fee-members'
  const to = tx.to?.toLowerCase() ?? null, value = tx.value ?? 0n, data = tx.data ?? '0x'
  if (t.k === 'job') {
    if (value !== 0n) return 'eth.value'
    if (to === null || to !== t.to) return 'eth.to'
    if (sha256Hex(Buffer.from(data.slice(2), 'hex')) !== t.p) return 'eth.payload'
    return null
  }
  if (t.k === 'clawback') {
    if (to === null || to !== t.to) return 'eth.to'
    if (t.value === null || value !== BigInt(t.value)) return 'eth.value'
    if (data !== '0x') return 'eth.data'
    return null
  }
  return 'kind'
}

// ---- BTC

export const BTC_RAW_MAX = 131_072                  // 128 KiB, like ETH: well under the relay's 256 KiB body cap (hex doubles it)
// What the relay read for one input outpoint: its value in sats and its scriptPubKey. null: not found / not readable.
export interface BtcPrevout { readonly value: bigint; readonly script: Uint8Array }
export type BtcPrevouts = (txid: string, vout: number) => Promise<BtcPrevout | null>
export interface DecodeContext { readonly btcPrevouts?: BtcPrevouts }

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex')
// The scriptPubKey of an address spelled canonically for this network, or null.
function scriptOfAddress(network: Network, address: string): Uint8Array | null {
  try {
    const net = btcNetwork(network)
    const decoded = btc.Address(net).decode(address)
    return btc.Address(net).encode(decoded) === address ? btc.OutScript.encode(decoded) : null
  } catch { return null }
}

async function btcMismatch(t: TicketPayload, raw: Uint8Array, network: Network, ctx: DecodeContext): Promise<string | null> {
  if (raw.length < 1 || raw.length > BTC_RAW_MAX) return 'btc.size'
  if (t.k !== 'commit' && t.k !== 'reveal') return 'kind'
  const tx = btc.Transaction.fromRaw(raw, { customScripts: [OutOrdinalReveal] })
  if (!Buffer.from(tx.toBytes(true, true)).equals(raw)) return 'btc.canonical'
  if (tx.id !== t.t) return 'btc.tx-id'
  if (tx.lockTime !== 0) return 'btc.locktime'
  const n = tx.inputsLength
  const points: Array<{ txid: string; vout: number }> = []
  for (let i = 0; i < n; i++) {
    const inp = tx.getInput(i)
    if (inp.txid === undefined || inp.index === undefined) return 'btc.inputs'
    points.push({ txid: hex(inp.txid), vout: inp.index })
    const signed = (inp.finalScriptSig?.length ?? 0) > 0 || (inp.finalScriptWitness?.length ?? 0) > 0
    if (!signed) return 'btc.unsigned'
  }
  const names = points.map((x) => `${x.txid}:${x.vout}`)
  if ([...names].sort().join(',') !== t.q) return 'btc.inputs'
  // outputs
  const toScript = scriptOfAddress(network, t.to ?? ''), laneScript = scriptOfAddress(network, t.a)
  if (toScript === null || laneScript === null || t.value === null) return 'btc.address'
  const [toHex, laneHex] = [hex(toScript), hex(laneScript)]
  const outs: Array<{ script: string; amount: bigint }> = []
  for (let i = 0; i < tx.outputsLength; i++) {
    const o = tx.getOutput(i)
    if (o.script === undefined || o.amount === undefined) return 'btc.outputs'
    outs.push({ script: hex(o.script), amount: o.amount })
  }
  const paid = outs.filter((o) => o.script === toHex), other = outs.filter((o) => o.script !== toHex)
  if (t.k === 'commit' && (toHex === laneHex || btc.OutScript.decode(toScript).type !== 'tr')) return 'btc.to'
  if (paid.length !== 1 || paid[0].amount !== BigInt(t.value)) return 'btc.to'
  if (t.k === 'commit' ? other.length > 1 || other.some((o) => o.script !== laneHex) : other.length !== 0) return 'btc.outputs'
  // reveal: the witness is exactly the inscription envelope
  if (t.k === 'reveal') {
    const witness = tx.getInput(0).finalScriptWitness as Uint8Array[]
    const found = parseWitness(witness)   // no witness, or not three items: it throws, a mismatch
    if (found === undefined || found.length !== 1) return 'btc.inscription'
    const { tags, body, cursed } = found[0]
    if (cursed === true || Object.keys(tags).join(',') !== 'contentType') return 'btc.tags'
    if (tags.contentType !== BTC_CONTENT_TYPE) return 'btc.content-type'
    if (sha256Hex(body) !== t.p) return 'btc.payload'
    // ord's parser and micro-ordinals' differ on odd scripts (an OP_0 inside the body, an envelope opened by OP_PUSHDATA1 0x00,
    // a content type split over two pushes), so the parse above is not trusted: the leaf must be byte for byte the canonical
    // one-inscription script of this body, in a 3-item witness with a single-leaf control block over the NUMS key (btc-ord.ts)
    const pinned = readReveal(witness)
    if (!pinned.ok) return pinned.reason
    if (btcRevealTo(network, pinned.xonly) !== t.to) return 'btc.destination'   // the lane's own p2tr, as the builder pays it
  }
  // fee, from the chain's own input values
  const read = ctx.btcPrevouts as BtcPrevouts   // absent: the call below throws, which is a read that found nothing
  let sumIn = 0n
  for (const x of points) {
    let pv: BtcPrevout | null = null
    try { pv = await read(x.txid, x.vout) } catch { pv = null }   // a failed read is a read that found nothing
    if (pv === null) return 'btc.prevout'
    if (t.k === 'commit' && hex(pv.script) !== laneHex) return 'btc.input-owner'
    if (t.k === 'commit') {
      const inp = tx.getInput(points.indexOf(x))
      const bad = inputSighashMismatch(pv.script, inp.finalScriptWitness, inp.finalScriptSig)
      if (bad !== null) return bad
    }
    sumIn += pv.value
  }
  const fee = sumIn - outs.reduce((a, o) => a + o.amount, 0n)
  if (fee < 0n || fee > BigInt(t.f)) return 'btc.fee'
  return null
}

// ---- SOL

function solMismatch(t: TicketPayload, raw: Uint8Array): string | null {
  if (raw.length < 1 || raw.length > SOL_RAW_MAX) return 'sol.size'
  const tx = VersionedTransaction.deserialize(raw)
  if (!Buffer.from(tx.serialize()).equals(Buffer.from(raw))) return 'sol.canonical'
  const m = tx.message
  if (m.version !== 'legacy' && m.version !== 0) return 'sol.version'
  if (m.addressTableLookups.length !== 0) return 'sol.lookup-table'
  const h = m.header
  const keys = m.staticAccountKeys.map((k) => k.toBase58())
  const n = keys.length
  const headerOk = h.numRequiredSignatures === 1 && h.numReadonlySignedAccounts === 0 && tx.signatures.length === 1
    && h.numReadonlyUnsignedAccounts >= 0 && h.numRequiredSignatures + h.numReadonlyUnsignedAccounts <= n
  if (!headerOk) return 'sol.signers'
  if (new Set(keys).size !== n) return 'sol.accounts'
  if (keys[0] !== t.a) return 'sol.fee-payer'
  // The message is everything after the signature section: compact-u16(1) = one byte, then 64 signature bytes.
  const signature = tx.signatures[0]
  const payer = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(m.staticAccountKeys[0].toBytes()).toString('base64url') }, format: 'jwk' })
  if (raw[0] !== 1 || !verifySignature(null, raw.subarray(65), payer, signature)) return 'sol.signature'
  if (base58Encode(signature) !== t.t) return 'sol.tx-id'
  if (m.recentBlockhash !== t.q) return 'sol.blockhash'
  let limit: bigint | null = null, price: bigint | null = null
  const memos: Uint8Array[] = []
  const transfers: Array<{ from: number; to: number; lamports: bigint }> = []
  for (const ix of m.compiledInstructions) {
    const program = keys[ix.programIdIndex]
    const d = Buffer.from(ix.data)
    if (program === COMPUTE_BUDGET) {
      if (ix.accountKeyIndexes.length !== 0) return 'sol.compute-budget'
      if (d.length === 5 && d[0] === 2 && limit === null) limit = BigInt(d.readUInt32LE(1))
      else if (d.length === 9 && d[0] === 3 && price === null) price = d.readBigUInt64LE(1)
      else return 'sol.compute-budget'
    } else if (program === MEMO_V2) {
      if (ix.accountKeyIndexes.length !== 0) return 'sol.memo'
      memos.push(d)
    } else if (program === SYSTEM) {
      if (d.length !== 12 || d.readUInt32LE(0) !== 2 || ix.accountKeyIndexes.length !== 2) return 'sol.transfer'
      transfers.push({ from: ix.accountKeyIndexes[0], to: ix.accountKeyIndexes[1], lamports: d.readBigUInt64LE(4) })
    } else return 'sol.program'
  }
  const fee = SOL_SIGNATURE_FEE * BigInt(h.numRequiredSignatures) + ceilDiv((limit ?? SOL_MAX_CU_LIMIT) * (price ?? 0n), 1_000_000n)
  if (fee > BigInt(t.f)) return 'sol.fee'
  // Writable by the header: signed [0, required - readonlySigned), unsigned [required, n - readonlyUnsigned).
  const writable = keys.map((_, i) => (i < h.numRequiredSignatures ? i < h.numRequiredSignatures - h.numReadonlySignedAccounts : i < n - h.numReadonlyUnsignedAccounts))
  const writableSet = (allowed: readonly number[]): boolean => writable.every((w, i) => w === allowed.includes(i))
  // R1-1: the message bytes are exactly the builder's for the ticket's fee members x ("<cuLimit>:<cuPrice>")
  const builderMade = (build: (cu: { cuLimit: number; cuPrice: number }) => VersionedTransaction): boolean => {
    const mx = /^([1-9][0-9]{0,6}):(0|[1-9][0-9]{0,15})$/.exec(t.x ?? '')
    if (mx === null || !Number.isSafeInteger(Number(mx[2]))) return false
    const rebuilt = build({ cuLimit: Number(mx[1]), cuPrice: Number(mx[2]) })
    return Buffer.from(rebuilt.message.serialize()).equals(Buffer.from(m.serialize()))
  }
  // N-1: every account key is one the tx uses: the fee payer, an instruction's program, or one of `accounts` (the claw-back's `to`)
  const onlyUsedKeys = (accounts: readonly number[]): boolean => {
    const used = new Set<number>([0, ...accounts])
    for (const ix of m.compiledInstructions) used.add(ix.programIdIndex)
    return used.size === n && [...used].every((i) => Number.isSafeInteger(i) && i >= 0 && i < n)
  }
  if (t.k === 'job') {
    if (transfers.length !== 0) return 'sol.transfer'
    if (memos.length !== 1) return 'sol.memo'
    if (sha256Hex(memos[0]) !== t.p) return 'sol.payload'
    if (!writableSet([0])) return 'sol.writable'
    if (!onlyUsedKeys([])) return 'sol.extra-account'
    if (!builderMade((cu) => solBuildTx(new PublicKey(t.a), memos[0], t.q, cu))) return 'sol.layout'
    return null
  }
  if (t.k === 'clawback') {
    if (memos.length !== 0) return 'sol.memo'
    if (transfers.length !== 1 || transfers[0].from !== 0) return 'sol.transfer'
    const x = transfers[0]
    if (keys[x.to] !== t.to) return 'sol.to'
    if (t.value === null || x.lamports !== BigInt(t.value)) return 'sol.value'
    if (!writableSet([0, x.to])) return 'sol.writable'
    if (!onlyUsedKeys([x.to])) return 'sol.extra-account'
    if (!builderMade((cu) => solBuildTransfer(new PublicKey(t.a), t.to as string, BigInt(t.value as string), t.q, cu))) return 'sol.layout'
    return null
  }
  return 'kind'
}

// BTC (CC-8; @scure/btc-signer Transaction.fromRaw, micro-ordinals parseWitness; no hand-rolled parser):
//   · 1 … 131,072 bytes; canonical (re-serializes to exactly raw); txid = t; locktime 0; the
//     outpoints exactly the ticket's q (strictly ascending, so 1 … 8 and none twice), each carrying a signature (a scriptSig or a witness);
//   · outputs: the output scripts of `to` and `a` come from the ticket's addresses of THIS network (a foreign network's
//     address, a bad checksum, a non-canonical spelling is a mismatch); exactly one output pays `to`, exactly `value`;
//     commit: `to` is a taproot output and not `a`, at most one other output, to `a` (the change), every input's
//     prevout pays `a`; reveal: one input, no other output;
//   · fee = sum(input values) - sum(output values), 0 <= fee <= f. The input values are the relay's own read of the chain
//     (BtcPrevouts: bitcoind gettxout / Esplora tx), never the caller's. A read that finds nothing is the token
//     'btc.prevout', which refuses relay.btc-prevout instead of relay.decode-mismatch (fail closed either way);
//   · reveal: the input's witness is exactly the ordinals reveal envelope: one inscription, not cursed, no tag but the
//     content type, which is exactly text/plain;charset=utf-8, with sha256(body) = p.
// The commit's inscription is hidden in its taproot commitment: p is checked on the reveal only.
// The first mismatch between the signed bytes and the ticket (a fixed token such as 'eth.fee'), or null when the bytes
// are exactly what the ticket binds. Never throws: a decoding error is the mismatch '<chain>.decode'.
export async function decodeMismatch(t: TicketPayload, raw: Uint8Array, network: Network, ctx: DecodeContext = {}): Promise<string | null> {
  try {
    if (t.c === 'eth') return await ethMismatch(t, raw, network)
    if (t.c === 'sol') return solMismatch(t, raw)
    if (t.c === 'btc') return await btcMismatch(t, raw, network, ctx)
    return 'chain'
  } catch {
    return `${t.c}.decode`
  }
}

// THE relay.btc-prevout line (one marker): the chain read for the input values found nothing (fail closed, CC-8).
function prevoutOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.btc-prevout', 'the relay could not read the value of an input of the ticketed transaction from the chain (or no such unspent output): nothing was forwarded') // @guard:relay.btc-prevout
}

export async function assertDecodedMatches(t: TicketPayload, raw: Uint8Array, network: Network, ctx: DecodeContext = {}): Promise<void> {
  const why = await decodeMismatch(t, raw, network, ctx)
  prevoutOk(why !== 'btc.prevout')
  const ok = why === null
  if (!ok) refuse('relay.decode-mismatch', `the signed transaction is not what the API ticketed (${why}): nothing was forwarded`) // @guard:relay.decode-mismatch
}

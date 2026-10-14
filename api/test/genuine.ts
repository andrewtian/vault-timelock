// Genuine signed transactions for the relay tests (not a test file). S4: a send passes the relay only when its bytes
// decode to what the ticket binds (decode.ts), so every case that must PASS carries one of these, with the ticket
// binding (CC-3: a, k, p, to, value, f; CC-3a: q) the API would give it. Keys are derived from fixed labels: synthetic, never
// funded anywhere.
import { createHash, randomBytes } from 'node:crypto'
import { ComputeBudgetProgram, Keypair, PublicKey, SystemProgram, TransactionInstruction, TransactionMessage, VersionedTransaction } from '@solana/web3.js'
import { keccak256, toHex } from 'viem'
import type { Hex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import type { Network } from '@vault-timelock/core/contracts'
import { chainId } from 'vt-broadcast/src/config.ts'
import { base58Encode } from '../src/tickets.ts'
import type { TicketBinding } from '../src/tickets.ts'

const seed = (label: string): Buffer => createHash('sha256').update(`vt-api-test:${label}`).digest()
export const ETH_TEST_KEY = privateKeyToAccount(toHex(seed('eth key')))
export const SOL_TEST_KEY = Keypair.fromSeed(seed('sol key'))
export const NULL_ADDRESS = '0x0000000000000000000000000000000000000000'
const MEMO_V2 = new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr')
const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex')
export const txIdOf = (chain: 'eth' | 'sol', raw: Uint8Array): string => (chain === 'eth' ? keccak256(raw) : base58Encode(raw.subarray(1, 65)))

export interface Genuine { raw: Buffer; binding: TicketBinding; txId: string }
export interface GenuineEth extends Genuine { hex: Hex; gas: bigint; maxFee: bigint; nonce: number; payload: Uint8Array }

// An EIP-1559 job tx (to the null address unless `to`), signed by viem as the engine signs it.
export async function genuineEth(network: Network, o: { payload?: Uint8Array; to?: string; nonce?: number; gas?: bigint; maxFee?: bigint; key?: typeof ETH_TEST_KEY } = {}): Promise<GenuineEth> {
  const key = o.key ?? ETH_TEST_KEY
  const payload = o.payload ?? randomBytes(40), gas = o.gas ?? 60_000n, maxFee = o.maxFee ?? 3_000_000_000n, nonce = o.nonce ?? 1
  const hex = await key.signTransaction({ type: 'eip1559', chainId: chainId(network, 'eth'), nonce, to: (o.to ?? NULL_ADDRESS) as Hex, value: 0n,
    data: toHex(payload), gas, maxFeePerGas: maxFee, maxPriorityFeePerGas: 1_000_000n })
  const raw = Buffer.from(hex.slice(2), 'hex')
  return { raw, hex, gas, maxFee, nonce, payload, txId: keccak256(hex),
    binding: { a: key.address.toLowerCase(), k: 'job', p: sha(payload), to: (o.to ?? NULL_ADDRESS).toLowerCase(), value: null, f: String(gas * maxFee), q: String(nonce), x: `${gas}:1000000:${maxFee}` } }   // PF-S I-1: to = the recipient; fix round 2: x = the fee members
}

// An EIP-1559 claw-back: value to `to`, no data, 21,000 gas.
export async function genuineEthClawback(network: Network, o: { to: string; value: bigint; nonce?: number; maxFee?: bigint }): Promise<Genuine & { hex: Hex }> {
  const gas = 21_000n, maxFee = o.maxFee ?? 2_000_000_000n, nonce = o.nonce ?? 2
  const hex = await ETH_TEST_KEY.signTransaction({ type: 'eip1559', chainId: chainId(network, 'eth'), nonce, to: o.to as Hex, value: o.value,
    gas, maxFeePerGas: maxFee, maxPriorityFeePerGas: 1_000_000n })
  return { raw: Buffer.from(hex.slice(2), 'hex'), hex, txId: keccak256(hex),
    binding: { a: ETH_TEST_KEY.address.toLowerCase(), k: 'clawback', p: null, to: o.to.toLowerCase(), value: String(o.value), f: String(gas * maxFee), q: String(nonce), x: `${gas}:1000000:${maxFee}` } }
}

// A legacy-message memo job as vt's builder lays it out (SetComputeUnitLimit 30,000, no price, the memo; fee 5000). `mod3`: the
// serialized length ≡ mod3 (mod 3), for base64 padding cases.
export function genuineSol(o: { payload?: Uint8Array; mod3?: number; blockhash?: string; payer?: Keypair } = {}): Genuine & { b64: string; payload: Uint8Array } {
  const payer = o.payer ?? SOL_TEST_KEY
  for (let n = 30; ; n++) {
    const payload = o.payload ?? randomBytes(n), blockhash = o.blockhash ?? new PublicKey(randomBytes(32)).toBase58()
    const tx = new VersionedTransaction(new TransactionMessage({ payerKey: payer.publicKey, recentBlockhash: blockhash,
      instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 30_000 }), new TransactionInstruction({ programId: MEMO_V2, keys: [], data: Buffer.from(payload) })] }).compileToLegacyMessage())
    tx.sign([payer])
    const raw = Buffer.from(tx.serialize())
    if (o.mod3 !== undefined && o.payload === undefined && raw.length % 3 !== o.mod3) continue
    return { raw, b64: raw.toString('base64'), payload, txId: txIdOf('sol', raw),
      binding: { a: payer.publicKey.toBase58(), k: 'job', p: sha(payload), to: null, value: null, f: '5000', q: blockhash, x: '30000:0' } }
  }
}

// A System transfer claw-back (fee 5000; no priority, so no ComputeBudget instruction: x carries the default limit, unused).
export function genuineSolClawback(o: { to: string; lamports: bigint; blockhash?: string; payer?: Keypair }): Genuine & { b64: string } {
  const payer = o.payer ?? SOL_TEST_KEY, blockhash = o.blockhash ?? new PublicKey(randomBytes(32)).toBase58()
  const tx = new VersionedTransaction(new TransactionMessage({ payerKey: payer.publicKey, recentBlockhash: blockhash,
    instructions: [SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: new PublicKey(o.to), lamports: o.lamports })] }).compileToLegacyMessage())
  tx.sign([payer])
  const raw = Buffer.from(tx.serialize())
  return { raw, b64: raw.toString('base64'), txId: txIdOf('sol', raw),
    binding: { a: payer.publicKey.toBase58(), k: 'clawback', p: null, to: o.to, value: String(o.lamports), f: '5000', q: blockhash, x: '200000:0' } }
}

// Fillers for a ticket whose bytes are refused BEFORE decoding (format, network, chain, raw, lock cases).
export const ANY_BINDING: Readonly<Record<'eth' | 'sol', TicketBinding>> = {
  eth: { a: `0x${'11'.repeat(20)}`, k: 'job', p: '00'.repeat(32), to: `0x${'00'.repeat(20)}`, value: null, f: '1', q: '0', x: '1:0:1' },
  sol: { a: '11111111111111111111111111111111', k: 'job', p: '00'.repeat(32), to: null, value: null, f: '5000', q: '11111111111111111111111111111111', x: '1:0' },
}

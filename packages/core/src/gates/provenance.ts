// packages/core/src/gates/provenance.ts — funding provenance (plan Task W6, spec D-R21; the broadcast design's §6.2 `eth` row,
// `flow2-mainnet` row and the typed attestation). Pure functions over data the page (or the CLI) read through the relay:
// no network, no clock, no randomness. FAIL CLOSED: anything that is not exactly the expected shape, or is cut short, is
// refused, never read "as far as it goes".
//
//   evaluateEthRow(i)         The §6.2 `eth` row for an address that was funded from Railgun: EVERY inbound native
//                             transfer arrived in a tx whose `to` is the Railgun proxy or a contract whose `railgun()` is
//                             the proxy (RelayAdapt); the address has never sent (nonce 0); the inbound total equals the
//                             balance (no unaccounted funds). Returns a verdict listing every failed check.
// R76: provenance is INFORMATIONAL. Nothing gates Arm on it (mainnet relies on funds being present in
// each lane wallet); the badge and the verdict are shown when the operator asks. The typed attestation and the Arm gate were removed.
//
// Failure ids (contracts/guards.ts, family `provenance`; verdict entries, not refusals): incomplete (malformed reading), paged
// (another page of transfers), no-inbound, not-railgun, nonce, unaccounted.
import type { GuardId } from '../contracts/index.ts'

// The Railgun proxy (Ethereum mainnet / Sepolia), pinned here so the page needs no config file. web/test pins them to
// broadcast/anchors.json.
export const RAILGUN_PROXY: Readonly<Record<'mainnet' | 'testnet', string>> = Object.freeze({
  mainnet: '0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9',
  testnet: '0xeCFCf3b4eC647c4Ca6D49108b311b7a7C9543fea',
})
// The RelayAdapt (the contract that unshields ETH to an address), PINNED per network (shared-models NETWORK_CONFIG relayAdaptContract; also
// broadcast/anchors.json railgun.relayadapt.*, which a web test compares). A RelayAdapt is NEVER discovered: any contract can answer
// railgun() with the proxy, so discovery was spoofable (review W6 I-2). `railgun()` is only a consistency check of these pins.
export const RAILGUN_RELAYADAPT: Readonly<Record<'mainnet' | 'testnet', string>> = Object.freeze({
  mainnet: '0xAc9f360Ae85469B27aEDdEaFC579Ef2d052aD405',
  testnet: '0x7e3d929EbD5bDC84d02Bd3205c777578f33A214D',
})
// RelayAdapt.relay((…)[], (bytes31,bool,uint256,(address,bytes,uint256)[])) — the only entry that runs a Railgun transaction's actions.
// multicall / transfer are callable by anyone outside relay(), so a transfer made by them proves nothing.
export const RELAY_SELECTOR = '0x28223a77'
// keccak256('railgun()')[0..4]: the RelayAdapt's getter for the proxy it serves (an eth_call to the contract).
export const RAILGUN_GETTER = '0x4013074d'

export type ProvenanceStatus = 'railgun' | 'elsewhere' | 'attested' | 'stand-in' | 'unchecked'
// txHash: the parent tx; viaTo: the parent tx's `to`; from: who sent the value transfer to the address (the internal transfer's sender; for a
// plain transfer the tx's sender); relayCall: the parent tx called relay() (RELAY_SELECTOR) with value 0.
export interface InboundTransfer { readonly txHash: string; readonly viaTo: string; readonly from: string; readonly relayCall: boolean; readonly value: bigint; readonly success: boolean }
export interface EthRowInput {
  readonly address: string
  readonly balance: bigint
  readonly nonce: number
  readonly inbound: readonly InboundTransfer[]
  readonly proxy: string
  readonly relayAdapts: ReadonlySet<string>      // the PINNED RelayAdapt(s), LOWER-CASE (never discovered)
  readonly truncated: boolean                    // the indexer said there is another page
}
export interface Failure { readonly guard: GuardId; readonly message: string }
export interface EthRowVerdict { readonly ok: boolean; readonly failures: readonly Failure[]; readonly railgunTxs: readonly string[] }

const ADDR = /^0x[0-9a-fA-F]{40}$/
const TXH = /^0x[0-9a-fA-F]{64}$/
const lc = (s: string): string => s.toLowerCase()
const short = (s: string): string => `${s.slice(0, 12)}…`

function wellFormed(i: EthRowInput): boolean {
  const adapts = i.relayAdapts instanceof Set && [...i.relayAdapts].every((a) => typeof a === 'string' && ADDR.test(a) && a === lc(a))
  const inbound = Array.isArray(i.inbound) && i.inbound.every((t) => t !== null && typeof t === 'object' && typeof t.txHash === 'string' && TXH.test(t.txHash)
    && typeof t.viaTo === 'string' && ADDR.test(t.viaTo) && typeof t.from === 'string' && ADDR.test(t.from) && typeof t.relayCall === 'boolean' && typeof t.value === 'bigint' && t.value >= 0n && typeof t.success === 'boolean')
  return adapts && inbound && typeof i.address === 'string' && ADDR.test(i.address) && typeof i.proxy === 'string' && ADDR.test(i.proxy)
    && typeof i.balance === 'bigint' && i.balance >= 0n && Number.isSafeInteger(i.nonce) && i.nonce >= 0 && typeof i.truncated === 'boolean'
}

export function evaluateEthRow(i: EthRowInput): EthRowVerdict {
  const failures: Failure[] = []
  const fail = (guard: GuardId, message: string): void => { failures.push({ guard, message }) }
  const ok = wellFormed(i)
  if (!ok) fail('provenance.incomplete', 'the reading is malformed (an address, hash, amount or nonce is not what the check needs): refused, not guessed') // @guard:provenance.incomplete
  if (!ok) return { ok: false, failures, railgunTxs: [] }
  if (i.truncated) fail('provenance.paged', 'more than one page of inbound transfers: refused rather than partially checked') // @guard:provenance.paged
  const pinned = (a: string): boolean => lc(a) === lc(i.proxy) || i.relayAdapts.has(lc(a))
  // Railgun's own: the parent tx went to the pinned proxy or RelayAdapt, the value was sent by one of them, and a RelayAdapt tx ran relay() with value 0
  const via = (t: InboundTransfer): boolean => pinned(t.viaTo) && pinned(t.from) && (lc(t.viaTo) === lc(i.proxy) || t.relayCall)
  const funds = i.inbound.filter((t) => t.success && t.value > 0n)
  if (funds.length === 0) fail('provenance.no-inbound', 'no inbound native transfer yet') // @guard:provenance.no-inbound
  const why = (t: InboundTransfer): string => (!pinned(t.viaTo) ? `inbound ${short(t.txHash)} came through ${short(t.viaTo)}, not the Railgun proxy or its pinned RelayAdapt`
    : !pinned(t.from) ? `inbound ${short(t.txHash)} was sent by ${short(t.from)}, not the Railgun proxy or its pinned RelayAdapt`
      : `inbound ${short(t.txHash)} did not run relay() with value 0 on the RelayAdapt`)
  for (const t of funds) if (!via(t)) fail('provenance.not-railgun', why(t)) // @guard:provenance.not-railgun
  if (i.nonce !== 0) fail('provenance.nonce', `the address has already sent ${i.nonce} transaction(s); its nonce must be 0`) // @guard:provenance.nonce
  const total = funds.reduce((a, t) => a + t.value, 0n)
  if (total !== i.balance) fail('provenance.unaccounted', `the inbound total ${total} wei is not the balance ${i.balance} wei (unaccounted funds)`) // @guard:provenance.unaccounted
  return { ok: failures.length === 0, failures, railgunTxs: funds.filter(via).map((t) => t.txHash) }
}

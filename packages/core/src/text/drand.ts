// drand quicknet (the chain every vault-timelock seal uses), pinned. Round math is SEALED.txt's:
//   round time = genesis + (round - 1) * period.
// sealed-from.ts checks chain-info.json against this; checkChainInfo() is the same check for a chain info
// fetched at run time (Open). broadcast/src/drand.ts keeps its own four-field constant (its test pins it
// equal to anchors.json); packages/core/test/text/drand.test.ts pins the two equal.
import { refuse } from './guard.ts'

export const QUICKNET = Object.freeze({
  public_key: '83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a',
  period: 3,
  genesis_time: 1692803367,
  hash: '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971',
  groupHash: 'f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e',
  schemeID: 'bls-unchained-g1-rfc9380',
  metadata: Object.freeze({ beaconID: 'quicknet' }),
} as const)

/** Unix seconds at which `round` is published. */
export const roundTime = (round: number): number => QUICKNET.genesis_time + (round - 1) * QUICKNET.period
/** The round current at `unixSec` (the last one published at or before it); 0 before genesis (drand's CurrentRound stays at 0/1 there). */
export const roundAt = (unixSec: number): number => Math.max(0, Math.floor((unixSec - QUICKNET.genesis_time) / QUICKNET.period) + 1)
/** The first round published at or after `unixSec`. */
export const roundForUnlock = (unixSec: number): number => Math.max(1, Math.ceil((unixSec - QUICKNET.genesis_time) / QUICKNET.period) + 1)
/** `YYYY-MM-DDTHH:MM:SSZ` of a round's publication, the form SEALED.txt and the envelope header carry. */
export const unlockIso = (round: number): string => new Date(roundTime(round) * 1000).toISOString().replace('.000Z', 'Z')

export function checkChainInfo(v: unknown): void {
  const o = (typeof v === 'object' && v !== null ? v : {}) as Record<string, unknown>
  const ok = o.hash === QUICKNET.hash && o.public_key === QUICKNET.public_key && o.period === QUICKNET.period &&
    o.genesis_time === QUICKNET.genesis_time && o.schemeID === QUICKNET.schemeID
  if (!ok) refuse('drand.chain-info', 'the drand chain info does not match the pinned quicknet chain') // @guard:drand.chain-info
}

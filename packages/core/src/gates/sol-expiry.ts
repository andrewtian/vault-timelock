// packages/core/src/gates/sol-expiry.ts — the SOL expiry oracle's answer (Efix3; E4 parked / E3 ruling 3).
// A Solana attempt may be re-signed only after PROOF that its signed bytes can never land. The proof asks every verified
// endpoint isBlockhashValid(<the attempt's blockhash>) (engine.js solWait), not a block-height comparison. This gate decides
// whether ONE answer is usable at all; anything else is no proof, and the engine keeps waiting (fail closed):
//   engine.sol-expiry-unreadable  the answer is not `{ context: { slot: <integer> }, value: <boolean> }` (an error is thrown
//                                 by the transport before it gets here; a null, a missing field, a string "false", a number)
//   engine.sol-expiry-stale       the answer came from a bank OLDER than the slot the blockhash was fetched at (a node
//                                 behind the cluster calls a brand-new blockhash unknown, i.e. "invalid")
// solWait catches exactly these two ids as "no proof this round" (it never re-signs on them and never stops the lane for them).
import { refuse } from '../contracts/index.ts'

/** The usable answer { valid, slot } of one isBlockhashValid call, or refuse. minSlot: the slot the blockhash was fetched at, when known. */
export function assertValidityAnswer(r: unknown, minSlot?: number): { valid: boolean; slot: number } {
  const o = r as { context?: { slot?: unknown }; value?: unknown } | null
  const slot = o?.context?.slot
  const ok = o !== null && typeof o === 'object' && typeof o.value === 'boolean' && typeof slot === 'number' && Number.isSafeInteger(slot)
  if (!ok) refuse('engine.sol-expiry-unreadable', 'isBlockhashValid answered without a boolean value and a slot — not a proof of expiry (fail closed)') // @guard:engine.sol-expiry-unreadable
  const stale = typeof minSlot === 'number' && Number.isSafeInteger(minSlot) && (slot as number) < minSlot
  if (stale) refuse('engine.sol-expiry-stale', 'isBlockhashValid answered from a bank older than the slot the blockhash was fetched at — not a proof of expiry (fail closed)') // @guard:engine.sol-expiry-stale
  return { valid: (o as { value: boolean }).value, slot: slot as number }
}

const isInt = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n)
/** I-1 (Efix3 fix round 1): a getSignatureStatuses answer is usable only as `{ context: { slot: int }, value: [one entry per id asked] }`,
 * each entry null (absent) or an object. A null/missing value, a short or long list, a missing context or slot is NOT "absent". */
export function assertStatusAnswer(r: unknown, ids: readonly string[]): { slot: number; value: Array<Record<string, unknown> | null> } {
  const o = r as { context?: { slot?: unknown }; value?: unknown } | null
  const ok = o !== null && typeof o === 'object' && isInt(o.context?.slot) && Array.isArray(o.value) && o.value.length === ids.length
    && o.value.every((x) => x === null || (typeof x === 'object' && !Array.isArray(x)))
  if (!ok) refuse('engine.sol-expiry-status', 'getSignatureStatuses answered without a context slot and one entry per signature asked — not "absent", not a proof (fail closed)') // @guard:engine.sol-expiry-status
  return { slot: (o as { context: { slot: number } }).context.slot, value: (o as { value: Array<Record<string, unknown> | null> }).value }
}
/** The finalized bank an endpoint reported: `{ context: { slot: int }, value: { lastValidBlockHeight: int } }`, else refuse (never slot 0). */
export function assertFinalizedAnswer(r: unknown): { lastValidBlockHeight: number; slot: number } {
  const o = r as { context?: { slot?: unknown }; value?: { lastValidBlockHeight?: unknown } } | null
  const ok = o !== null && typeof o === 'object' && isInt(o.context?.slot) && isInt(o.value?.lastValidBlockHeight)
  if (!ok) refuse('engine.sol-expiry-finalized', 'getLatestBlockhash(finalized) answered without a context slot and a lastValidBlockHeight — not a proof (fail closed)') // @guard:engine.sol-expiry-finalized
  return { lastValidBlockHeight: (o as { value: { lastValidBlockHeight: number } }).value.lastValidBlockHeight, slot: (o as { context: { slot: number } }).context.slot }
}

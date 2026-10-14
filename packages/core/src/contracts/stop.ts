// packages/core/src/contracts/stop.ts — R79b: the stop-reason classes. ONE table; every lane (core, api, cli, web) uses it.
//
// Every journaled `stopped` carries a machine reason code: its data is `{ reason, code?, delegated? }` (job/events.ts). `code` is
// optional in the event shape ONLY so that journals written before R79b replay; every writer of this build sets it (the executor and
// the engine's lane for their own stops, the API's stop route for a chain that never started). The code's class says what the
// operator's resume may do:
//   RESUMABLE  the cause is one the operator can fix and then continue: `vt job resume` / the page's Resume clears the stop latch, and
//              the next executor (vt job run) reopens the chain at the next part of the current copy — after every pre-start check
//              passed (the reread of a landed part, the reconcile, the check at the start); a check that fails journals nothing.
//   FINAL      resume is refused: guard resume.final-stop (409), with a message that names the reason and the way out. Nothing more
//              is sent for this job on this key; the way out is claw-back / close (and a new job). An executor never reopens a FINAL
//              stop either (executor.ts, its own @guard:resume.final-stop), even if the latch was cleared.
// The reducer projects both on a chain whose base is STOPPED (GET /jobs lists them): ChainState.stopCode (the journaled code, when this
// build knows it) and ChainState.stopClass ('resumable' | 'final' = stopClassOf(the chain).cls). The page and the API read stopClass.
// Fail closed (stopClassOf): a missing or unknown code is FINAL, and so is a stopped chain whose journal shows a FINAL fact whatever
// its code — a landed part whose readback is not ok (a mismatch, ETH status 0, a SOL transaction that landed with an error), a copy
// that did not reassemble, an EIP-7702-delegated key, a stuck attempt, an attempt the operator resolved mark-failed (its nonce is
// unusable for job sends). When in doubt a new code is FINAL.
import type { ChainState } from './types.ts'

export type StopClass = 'resumable' | 'final'   // ChainState.stopClass (the page and the API read it)
export interface StopCodeRow { readonly cls: StopClass; readonly what: string }

// The codes, from the code (R79b). Who journals each:
//   operator-stop        the API's stop route (a chain that never started); the executor: a Stop in the countdown, the API refusing
//                        the next intent after a Stop; the lane (engine/lane.js opStop): a Stop between parts or copies, while paused
//                        (Tor, an RPC error, the fee-cap pause), during the reconcile. A DETACH journals nothing at all.
//   start-check          the executor: the check at the chain's start failed (Tor, the relay identity, a fresh passing simulation).
//   rpc-unavailable      the lane: the RPC stayed unavailable while it planned the next copy, or the verified ETH endpoints could not
//                        be read during the reconcile (nothing of that copy was signed).
//   readback-mismatch    the lane: a landed part does not read back as planned; the executor: the takeover's reread of a landed part.
//   reverted             a landed part failed on the chain (ETH status 0; a SOL transaction that landed with an error).
//   reassembly-mismatch  the lane: a copy did not reassemble from the chain.
//   eip7702              the executor (engine.eip7702) or the reconcile: the lane key's account is EIP-7702-delegated.
//   spend-cap            the lane (engine.cap-copy): the armed spend cap cannot cover the next copy — resuming cannot add cap.
//   stuck                the lane: a transaction was journaled stuck (vt job resolve, then claw back or close).
//   tx-failed            the lane: a part's transaction failed otherwise (its nonce consumed by a transaction this lane did not
//                        sign, a SOL preflight program error, the very bytes of an attempt already journaled, a btc commit that cannot
//                        pay its reveal).
//   exhausted            the lane: a part's fee, balance or per-transaction cap limit was exhausted (its signed attempts may still land).
//   integrity            the lane: any other integrity failure (a part confirmed without a journaled inclusion; an unknown outcome).
export const STOP_CODES = {
  'operator-stop': { cls: 'resumable', what: 'the operator stopped it (vt job stop, the page\'s job Stop)' },
  'start-check': { cls: 'resumable', what: 'the check at its start failed (Tor, the relay identity or the simulation)' },
  'rpc-unavailable': { cls: 'resumable', what: 'the RPC endpoints could not be read while the next copy was planned (nothing of it was signed)' },
  'readback-mismatch': { cls: 'final', what: 'a landed part does not read back from the chain as planned' },
  reverted: { cls: 'final', what: 'a landed part failed on the chain (ETH status 0, or a SOL transaction that landed with an error)' },
  'reassembly-mismatch': { cls: 'final', what: 'a copy did not reassemble from the chain' },
  eip7702: { cls: 'final', what: 'the lane key\'s account has an EIP-7702 delegation' },
  'spend-cap': { cls: 'final', what: 'the armed spend cap cannot cover the next copy (a resume cannot add cap)' },
  stuck: { cls: 'final', what: 'a transaction is stuck (vt job resolve records what the chain shows)' },
  'tx-failed': { cls: 'final', what: 'a part\'s transaction failed (its nonce cannot be used for the job again)' },
  exhausted: { cls: 'final', what: 'a part ran out of fee bumps, balance or cap while its transactions may still land' },
  integrity: { cls: 'final', what: 'an integrity check failed (fail closed)' },
} as const satisfies Readonly<Record<string, StopCodeRow>>
export type StopCode = keyof typeof STOP_CODES
export const STOP_CODE_LIST: readonly StopCode[] = Object.keys(STOP_CODES) as StopCode[]
export function isStopCode(x: unknown): x is StopCode {
  return typeof x === 'string' && Object.hasOwn(STOP_CODES, x)
}
// The class of a journaled code alone: unknown or missing = FINAL (fail closed).
export function stopCodeClass(code: unknown): StopClass {
  return isStopCode(code) ? STOP_CODES[code].cls : 'final'
}

// Final round (R79b review m-4): which codes a journal FACT backs — stopClassOf makes such a stop final from the fact, whatever code was
// journaled with it. The others (null) rest on the code alone: the lane's mapping is pinned by test/engine/stop-codes.test.ts and the API
// cross-checks a resumable code (lane S). ETH status 0 and a SOL transaction that landed with an error are journaled `readback` not ok
// (engine.js ethFinish / solLandedFailed), the executor's reread journals the same, so `reverted` is backed like `readback-mismatch`.
export const STOP_CODE_FACT: Readonly<Record<StopCode, string | null>> = {
  'operator-stop': null, 'start-check': null, 'rpc-unavailable': null,
  'readback-mismatch': 'a landed part whose readback is not ok',
  reverted: 'a landed part whose readback is not ok (status 0 / landed with an error is journaled so)',
  'reassembly-mismatch': 'a copy whose reassembly is not ok',
  eip7702: 'the stop\'s delegated: true',
  stuck: 'a stuck attempt (until it is resolved; mark-failed is a fact of its own)',
  'spend-cap': null, 'tx-failed': null, exhausted: null, integrity: null,
}

// The way out of a FINAL stop (every refusal and every page / CLI text says it).
export const FINAL_STOP_WAY_OUT = 'claw back what is left (vt job clawback, the page\'s claw-back) or close the chain (vt job close), then make a new job'

// The facts stopClassOf reads (ChainState as reduced; GET /jobs lists the same fields).
export type StopFacts = Pick<ChainState, 'txs' | 'reassembled'> & { stopCode?: unknown; delegated?: unknown }
export interface StopVerdict {
  cls: StopClass
  code: StopCode | null   // the journaled code (null: none, or one this build does not know)
  why: string             // names the reason: the code's text, or the FINAL fact found
}
// The class of a stopped chain's stop: a FINAL code, then the FINAL facts of its journal, then a RESUMABLE code; anything else FINAL.
// (For a chain that is not STOPPED the caller decides what a resume means: this answers for the facts it is given.)
export function stopClassOf(cs: StopFacts): StopVerdict {
  const code = isStopCode(cs.stopCode) ? cs.stopCode : null
  if (code !== null && STOP_CODES[code].cls === 'final') return { cls: 'final', code, why: STOP_CODES[code].what }
  const fact = finalFactOf(cs)
  if (fact !== null) return { cls: 'final', code, why: fact }
  if (code !== null) return { cls: 'resumable', code, why: STOP_CODES[code].what }
  return { cls: 'final', code: null, why: 'its stop carries no reason code this build knows (a journal from before R79b): treated as final (fail closed)' }
}
function finalFactOf(cs: StopFacts): string | null {
  if (cs.delegated === true) return STOP_CODES.eip7702.what
  if (cs.txs.some((t) => t.readback === false)) return 'a landed part does not read back from the chain (other bytes, or it failed on the chain: ETH status 0, a SOL transaction that landed with an error)'
  if (cs.reassembled.some((r) => r.ok !== true)) return STOP_CODES['reassembly-mismatch'].what
  if (cs.txs.some((t) => t.attempts.some((a) => a.state === 'resolved-failed'))) return 'an attempt was resolved mark-failed: its nonce cannot be used for the job again'
  if (cs.txs.some((t) => t.state === 'stuck')) return STOP_CODES.stuck.what
  return null
}
// The text of the resume.final-stop refusal (the API's 409 message; the CLI and the page show the same words).
export function finalStopText(chain: string, v: StopVerdict): string {
  return `${chain} is stopped for good: ${v.why}${v.code !== null ? ` (${v.code})` : ''} — resume is refused; ${FINAL_STOP_WAY_OUT}`
}

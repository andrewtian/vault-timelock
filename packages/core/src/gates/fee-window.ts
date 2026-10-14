// packages/core/src/gates/fee-window.ts — the passive ETH base-fee window (E5). chains/eth.js baseFeeWindow walks back
// 7,200 blocks in eth_feeHistory chunks of ≤ 1,024; some RPCs (anvil, public providers) serve fee history only for about
// the newest 1,024 blocks, so an OLDER chunk may fail. Only the FIRST chunk (the newest) is load-bearing:
//   engine.fee-window-first  the first chunk errored or returned < 2 base fees → no target at all, so the assess/arm/run
//                            fails closed (a passive lane never prices from nothing). A LATER chunk failing is not a
//                            refusal: the walk stops and the shorter window is used and shown (windowBlocks/truncated).
//   engine.fee-tip-input     feeInputs.maxTipGwei (a job's tip cap) must be a decimal gwei amount of 0.1..100 (the job
//                            validator's own bounds, job.tip-cap); anything else is refused, never priced at a default.
import { refuse } from '../contracts/index.ts'

/** Called when a chunk errored or came back short. The first chunk refuses; a later one just ends the walk. */
export function feeWindowChunkFailed(first: boolean, why: string): void {
  if (first) refuse('engine.fee-window-first', `the newest eth_feeHistory chunk failed (${why}): no passive fee window`) // @guard:engine.fee-window-first
}

/** feeInputs.maxTipGwei → wei (gwei with up to 9 decimals), or refuse. */
export function maxTipWei(gwei: number | string): bigint {
  const s = String(gwei)
  const ok = /^\d{1,3}(\.\d{1,9})?$/.test(s) && Number(s) >= 0.1 && Number(s) <= 100
  if (!ok) refuse('engine.fee-tip-input', `maxTipGwei must be 0.1..100 gwei, got ${s.slice(0, 40)}`) // @guard:engine.fee-tip-input
  const [i, f = ''] = s.split('.')
  return BigInt(i) * 10n ** 9n + BigInt(f.padEnd(9, '0'))
}

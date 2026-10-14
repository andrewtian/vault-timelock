// packages/core/src/gates/btc.ts — the two refusals of the BTC lane (E7), one marker each so the mutation runner covers them.
//   engine.btc-order    a reveal asked before its commit landed in a block (seen by txid): nothing is built or sent
//   engine.btc-open     a BTC attempt that may still land is left open (the node or relay could not answer, a send never got through): the run ends
//                       `failed` WITHOUT journaling `stopped` (a stopped chain can never run again), so a rerun or a takeover reconciles it by
//                       txid and sends what is missing once. No btc tx is ever declared dead by a failed read or send.
//   engine.btc-fee-rate the fee rate to pay is above what the tickets allow (500 sat/vB): nothing is signed
//   engine.btc-rebuild  a journaled BTC attempt that is not on the chain and cannot be rebuilt byte for byte (or whose inputs are
//                       spent): the run stops with the attempt left open, nothing is built beside it
import { refuse } from '../contracts/index.ts'

export function assertBtcOrder(commitLanded: boolean, why: string): void {
  if (!commitLanded) refuse('engine.btc-order', why) // @guard:engine.btc-order
}
export function assertBtcRebuild(rebuilt: boolean, why: string): void {
  if (!rebuilt) refuse('engine.btc-rebuild', why) // @guard:engine.btc-rebuild
}
export function refuseBtcOpen(why: string): never {
  return refuse('engine.btc-open', why) // @guard:engine.btc-open
}
export function assertBtcRate(ok: boolean, why: string): void {
  if (!ok) refuse('engine.btc-fee-rate', why) // @guard:engine.btc-fee-rate
}

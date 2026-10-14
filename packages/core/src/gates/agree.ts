// packages/core/src/gates/agree.ts — endpoint agreement (E5; MQ's parked M11). The relay verifies several upstream
// endpoints per chain and serves each one alone at /relay/<chain>/ep/<i> (spec §6.1, I3). One endpoint's word is not
// enough for what decides an ETH signature, so the account a lane starts from is read from EVERY verified endpoint:
//   engine.nonce-disagree  the account nonce ('latest' and 'pending' eth_getTransactionCount) must be the same on every
//                          endpoint that answered, and at least 2 must answer when the relay verified ≥ 2. A lagging or
//                          lying endpoint would otherwise have the lane sign at a nonce already used, queue behind a
//                          pending tx it does not show, or open a gap that lands later. The lane pauses (journaled
//                          `paused`) and reads again until they agree; a claw-back is refused. Nothing is signed.
//   engine.code-disagree   (fix round 2) eth_getCode of the lane key's address must tell ONE clear state on every
//                          endpoint that answered (at least 2 when the relay verified ≥ 2): all exactly '0x' (no code),
//                          or all the same EIP-7702 delegation designator. Endpoints that disagree (some '0x', some not;
//                          two different codes), too few answers, or an agreed answer that is neither (contract code, a
//                          malformed value) are one endpoint's word or a broken set: the lane PAUSES like
//                          engine.nonce-disagree, nothing is signed, and Stop settles it.
//   engine.eip7702         the agreed code must be exactly '0x'. An EIP-7702 delegation (code 0xef0100 ‖ delegate) runs the
//                          delegate's code for every call TO the account — a self-send's calldata, anyone else's call —
//                          which can move the account's funds and bump its nonce without a signature of ours. The lane
//                          starts no new send; the run reconciles every open intent and ends the chain `stopped`
//                          (executor.ts), so the remainder can be clawed back (only the key holder can remove it).
// SOL has no account nonce: its sends go to every verified endpoint instead (engine.js postSol), and its expiry proof
// already asks every endpoint (engine.js solWait, I3).
import { refuse } from '../contracts/index.ts'

// PF-S M-2 (pre-flip review): on MAINNET a job chain (eth, sol) needs at least this many relay-verified endpoints, or the two-endpoint
// guarantees above (the ETH nonce / code agreement, every SOL send and the expiry proof on every endpoint) silently rest on one
// provider's word. `vt preflight` shows fewer as a failing row (exit 1) and the executor refuses to start such a chain
// (executor.endpoints-quorum); local and testnet keep one. The relay re-checks a dropped endpoint in the background.
export const MAINNET_MIN_ENDPOINTS = 2
/** How many verified relay endpoints a chain of this network needs: 2 for a mainnet eth / sol chain, else 1. */
export const endpointsNeeded = (network: string, chain: string): number => (network === 'mainnet' && (chain === 'eth' || chain === 'sol') ? MAINNET_MIN_ENDPOINTS : 1)

const nonceOk = (n: unknown): boolean => Number.isSafeInteger(n) && (n as number) >= 0
// planE5 m-5: how to recover. The relay's endpoint count is fixed for a running lane (an endpoint dropped at startup is re-checked
// in the background and joins later lanes, PF-S M-2), so one endpoint that dies or lies afterwards keeps an ETH lane paused (and an ETH claw-back refused) until the stack is restarted — its startup check drops a
// dead endpoint — or the endpoint list (endpoints.json) is fixed; Stop, then run again, settles a paused chain.
const RECOVER = ' — to recover: restart the stack (its startup check drops a dead endpoint) or fix endpoints.json; Stop the chain, then run it again'
const list = (a: readonly number[]): string => a.slice(0, 8).map((n) => String(n).slice(0, 20)).join(', ')

/** The one ('latest', 'pending') nonce pair the verified ETH endpoints agree on (answers in endpoint order; a failed
 * read is left out), or refuse. relayEndpoints: how many endpoints the relay verified (default: as many as answered). */
export function assertNonceAgreement(latest: number[], pending: number[], relayEndpoints: number = latest.length): { latest: number; pending: number } {
  const quorum = relayEndpoints >= 2 ? 2 : 1
  const ok = latest.length >= quorum && pending.length === latest.length && latest.every((n) => nonceOk(n) && n === latest[0])
    && pending.every((n) => nonceOk(n) && n === pending[0]) && pending[0] >= latest[0]
  const why = `the verified ETH endpoints do not agree on this key's nonce (${latest.length} of ${relayEndpoints} answered, ${quorum} needed; latest ${list(latest)}; pending ${list(pending)}) — nothing is signed until they agree${RECOVER}`
  if (!ok) refuse('engine.nonce-disagree', why) // @guard:engine.nonce-disagree
  return { latest: latest[0], pending: pending[0] }
}

const DELEGATION = /^0xef0100[0-9a-f]{40}$/
/** The one eth_getCode answer every verified ETH endpoint gave for the lane key's address (answers in endpoint order; a
 * failed read is left out): all '0x', or all the same delegation designator (any case) — else refuse. */
export function assertCodeAgreement(codes: string[], relayEndpoints: number = codes.length): string {
  const quorum = relayEndpoints >= 2 ? 2 : 1
  const lc = codes.map((c) => (typeof c === 'string' ? c.toLowerCase() : ''))
  const ok = lc.length >= quorum && lc.every((c) => c === lc[0]) && (lc[0] === '0x' || DELEGATION.test(lc[0]))
  const plain = lc.filter((c) => c === '0x').length, deleg = lc.filter((c) => DELEGATION.test(c)).length
  const why = `the verified ETH endpoints do not agree on this key's account code (${codes.length} of ${relayEndpoints} answered, ${quorum} needed: ${plain} no code, ${deleg} an EIP-7702 delegation${new Set(lc.filter((c) => DELEGATION.test(c))).size > 1 ? ' — different ones' : ''}, ${codes.length - plain - deleg} other) — nothing is signed until they agree${RECOVER}`
  if (!ok) refuse('engine.code-disagree', why) // @guard:engine.code-disagree
  return lc[0]
}

/** eth_getCode of the lane key's address, as the endpoints agreed on it: exactly '0x' (no code), or refuse. */
export function assertNoDelegation(code: string): void {
  const ok = code === '0x'
  const delegated = typeof code === 'string' && /^0xef0100[0-9a-f]{40}$/i.test(code)
  const why = delegated ? "this key's account has an EIP-7702 delegation (code 0xef0100…): the delegate's code runs for every call to it — refusing to sign (only the key holder can remove the delegation)"
    : "this key's account has code (eth_getCode is not 0x): refusing to sign from it"
  if (!ok) refuse('engine.eip7702', why) // @guard:engine.eip7702
}

/** The warning a claw-back from an EIP-7702-delegated key carries (planE5 ruling C2): a transfer FROM the account runs none of
 * the delegate's code, so the remainder can still leave — but whoever holds the authorization (or the delegate) may move
 * the funds first, so the claw-back should not wait. One text for the journal note, the result and the progress line. */
export const DELEGATED_CLAWBACK_WARNING = 'this key is delegated (EIP-7702); someone holding the authorization may move funds — claw back now'
/** Whether eth_getCode says an EIP-7702 delegation designator (any case). */
export const isDelegationCode = (code: unknown): boolean => typeof code === 'string' && DELEGATION.test(code.toLowerCase())

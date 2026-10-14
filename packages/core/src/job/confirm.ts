// packages/core/src/job/confirm.ts — checkArmConfirm(network, req): the API re-checks what the page and the CLI
// collected before arming (spec §5.4 checks 6-7, plus the request's own rules). The API runs its state checks first
// (job.network, release.mainnet-locked, trigger.uncleared, job.armed, job.state, job.key-busy), then this.
//   arm.chains     a non-empty list of distinct chains (eth, sol)
//   arm.typed      mainnet: confirm.typed === 'broadcast' exactly
//   arm.amount     every armed chain has a well-formed cap (the engine enforces it at every signature, and a takeover
//                  reads it from the arm record); an overCap chain has confirm.amounts[c] === caps[c].planned exactly
//   arm.countdown  mainnet: absent or exactly MAINNET_COUNTDOWN_S (60); local and testnet: absent or an integer in
//                  COUNTDOWN_RANGE_S (5..300)
//   arm.stagger    local only: [min, max] integers with 0 <= min <= max <= STAGGER_S[1] (300)
//
// checkClawbackConfirm(state, chain, data, confirm?) (CC-2a, the typed claw-back amount; S2 calls it on every
// clawback-intent after assertIntentAllowed, with the request's clawbackConfirm; the engine's cap ledger applies the
// same rule before signing, gates/caps.ts reserveClawback):
//   arm.amount     need = value + worst-case fee of the intent (eth value + gas × maxFee; sol value + sol.fee); room =
//                  nativeCap − spent (+ a landed claw-back's value). Refused when the cap, the spend or the intent's
//                  amounts are malformed; when need > room and no clawbackConfirm; and when a clawbackConfirm is given
//                  that is not exactly { amount: String(need) } (decimal base units, no other member).
import { COUNTDOWN_RANGE_S, MAINNET_COUNTDOWN_S, STAGGER_S, assertNetwork, refuse } from '../contracts/index.ts'
import type { ArmRequest, Chain, JobState, Network } from '../contracts/index.ts'
import { isArmCap } from './events.ts'
import { worstFeeOf } from './reduce.ts'

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v)
const own = (o: unknown, k: string): unknown => (isObj(o) && Object.hasOwn(o, k) ? o[k] : undefined)
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v)

export function checkArmConfirm(network: Network, req: ArmRequest): void {
  assertNetwork(network)
  const chains: unknown = own(req, 'chains')
  const chainsOk = Array.isArray(chains) && chains.length > 0 && chains.every((c) => c === 'eth' || c === 'sol' || (c === 'btc' && network === 'local')) && new Set(chains).size === chains.length
  if (!chainsOk) refuse('arm.chains', 'chains must be a non-empty list of distinct chains (eth, sol, and btc on a local network)') // @guard:arm.chains
  const confirm = own(req, 'confirm')
  const typedOk = network !== 'mainnet' || own(confirm, 'typed') === 'broadcast'
  if (!typedOk) refuse('arm.typed', 'a mainnet arm needs the typed confirmation "broadcast"') // @guard:arm.typed
  const caps = own(req, 'caps'), amounts = own(confirm, 'amounts')
  const amountOk = chains.every((c: string) => {
    const cap = own(caps, c)
    return isArmCap(cap) && (own(cap, 'overCap') !== true || (typeof own(amounts, c) === 'string' && own(amounts, c) === own(cap, 'planned')))
  })
  assertAmount(amountOk, 'every armed chain needs its cap, and an over-cap chain its planned amount typed exactly')
  const cd = own(req, 'countdownSec')
  const countdownOk = network === 'mainnet' ? cd === undefined || cd === MAINNET_COUNTDOWN_S
    : cd === undefined || (isInt(cd) && cd >= COUNTDOWN_RANGE_S[0] && cd <= COUNTDOWN_RANGE_S[1])
  if (!countdownOk) refuse('arm.countdown', `countdownSec: ${MAINNET_COUNTDOWN_S} on mainnet; an integer ${COUNTDOWN_RANGE_S[0]}..${COUNTDOWN_RANGE_S[1]} on local and testnet`) // @guard:arm.countdown
  const st = own(req, 'stagger')
  const staggerOk = st === undefined || (network === 'local' && Array.isArray(st) && st.length === 2 && isInt(st[0]) && isInt(st[1])
    && st[0] >= 0 && st[0] <= st[1] && st[1] <= STAGGER_S[1])
  if (!staggerOk) refuse('arm.stagger', `stagger is for local only: [min, max] integers with 0 <= min <= max <= ${STAGGER_S[1]}`) // @guard:arm.stagger
}

// One marker for arm.amount (the mutation runner allows one per id): the arm's over-cap amount and the claw-back's.
function assertAmount(ok: boolean, why: string): void {
  if (!ok) refuse('arm.amount', why) // @guard:arm.amount
}

const DEC = /^(?:0|[1-9][0-9]{0,77})$/
const big = (v: unknown): bigint | null => (typeof v === 'string' && DEC.test(v) ? BigInt(v) : null)

// The claw-back's value + worst-case fee must fit what is left of the armed cap, or the operator typed exactly that
// amount (types.ts claw-back note, CC-2a). Returns need (base units) when allowed.
export function checkClawbackConfirm(state: JobState, chain: Chain, data: Record<string, unknown>, confirm?: unknown): bigint {
  const cs = state?.chains?.[chain]
  const cap = big(state?.armed?.caps?.[chain]?.nativeCap), spent = big(cs?.spent)
  const value = big(data?.value), fee = worstFeeOf(isObj(data) ? data : {})
  const landed = cs?.clawback?.landed === true ? big(cs.clawback.value) : 0n
  const typed = cap !== null && spent !== null && value !== null && fee !== null && landed !== null
  const need = typed ? value + fee : -1n
  const room = typed ? cap - spent - landed : -1n
  const given = confirm === undefined ? null : isObj(confirm) && Object.keys(confirm).length === 1 && typeof confirm.amount === 'string' ? confirm.amount : false
  const ok = typed && (given === null ? need <= room : given === String(need))
  assertAmount(ok, typed
    ? given === null
      ? `the claw-back's value + worst-case fee (${need} base units) is over what is left of the armed cap (${room}): the operator types that exact amount to confirm`
      : 'the typed claw-back amount is not exactly value + worst-case fee of this claw-back (base units)'
    : 'the claw-back needs a well-formed armed cap, spend, value and fee')
  return need
}

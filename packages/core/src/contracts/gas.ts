// packages/core/src/contracts/gas.ts — fork- and recipient-aware intrinsic gas of a data tx, and the fork-drift check
// (ruling 6; research-long-messages.md §8). n = calldata bytes (`data:,` + part header + chunk). The bytes are never
// zero (U+0000 is refused in messages), so one per-byte price applies.
//   pre-Amsterdam (Prague/Osaka, EIP-7623 floor):  21000 + 40·n
//   Amsterdam, to self:                            12000 + 64·n
//   Amsterdam, to any other address (0x0 included): 15000 + 64·n   (TX_BASE_COST 12000 + COLD_ACCOUNT_ACCESS 3000)
// eth_estimateGas matches a formula when estimate ∈ [g, g + ⌈g·15/985⌉] (geth's estimator overshoot; MQ I6).
// Anything else fails closed in the engine. checkForkDrift turns a mismatch into a specific message for
// `vt preflight` (C7) and the relay identity check (S3) instead of a generic refusal.
import type { Network } from './types.ts'
import { ethAmsterdam } from './network.ts'

export type EthFork = 'pre-amsterdam' | 'amsterdam'
export const ETH_GAS = {
  preAmsterdam: { base: 21_000, perByte: 40 },
  amsterdamSelf: { base: 12_000, perByte: 64 },
  amsterdamOther: { base: 15_000, perByte: 64 },
} as const
export const ESTIMATE_TOL = { num: 15, den: 985 } as const
// The probe payload size for fork detection: every formula's window is disjoint from the others at this size.
export const FORK_PROBE_BYTES = 100

function checkBytes(n: number): void {
  if (!Number.isInteger(n) || n < 0) throw new RangeError('calldata bytes must be a non-negative integer')
}

export function ethDataGas(n: number, o: { amsterdam: boolean; toSelf: boolean }): number {
  checkBytes(n)
  const f = !o.amsterdam ? ETH_GAS.preAmsterdam : o.toSelf ? ETH_GAS.amsterdamSelf : ETH_GAS.amsterdamOther
  return f.base + f.perByte * n
}

export function estimateMatches(estimate: number | bigint, gas: number): boolean {
  const e = Number(estimate)
  return Number.isSafeInteger(e) && e >= gas && e <= gas + Math.ceil((gas * ESTIMATE_TOL.num) / ESTIMATE_TOL.den)
}

export function detectEthFork(estimate: number | bigint, n: number, toSelf: boolean): EthFork | 'ambiguous' | 'unknown' {
  const pre = estimateMatches(estimate, ethDataGas(n, { amsterdam: false, toSelf }))
  const ams = estimateMatches(estimate, ethDataGas(n, { amsterdam: true, toSelf }))
  return pre && ams ? 'ambiguous' : pre ? 'pre-amsterdam' : ams ? 'amsterdam' : 'unknown'
}

export interface ForkDrift {
  network: Network; expected: EthFork; observed: EthFork | 'ambiguous' | 'unknown'; ok: boolean; message: string | null
}
export function checkForkDrift(
  network: Network, probe: { estimate: number | bigint; n: number; toSelf: boolean }, o: { localOverride?: boolean } = {},
): ForkDrift {
  const expected: EthFork = ethAmsterdam(network, o) ? 'amsterdam' : 'pre-amsterdam'
  const observed = detectEthFork(probe.estimate, probe.n, probe.toSelf)
  const ok = observed === expected
  const message = ok ? null
    : observed === 'amsterdam' ? `Amsterdam appears active on ${network} — update required`
    : observed === 'pre-amsterdam' ? `Amsterdam appears inactive on ${network} — update required`
    : observed === 'ambiguous' ? `the fork probe is ambiguous at ${probe.n} bytes — probe with ${FORK_PROBE_BYTES} bytes`
    : `eth_estimateGas matches neither the pre-Amsterdam nor the Amsterdam formula on ${network} — update required`
  return { network, expected, observed, ok, message }
}

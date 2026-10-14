// Cooling and amount policy (spec C 4.1-4.2). Pure functions over injected time and randomness;
// all money arithmetic is bigint wei.
import { refuse } from '../guard.ts'
import type { Profile, Timing } from '../config.ts'
import type { Random } from './clock.ts'

export const DAY = 86400
export const HISTORY_DAYS = 90
export const MAX_ATTEMPTS = 32

// R37: mainnet 24-72 h; every local/testnet timer defaults to 5 minutes. --cooling-seconds (already
// parsed and guarded in config.ts: testnet/local only) replaces the range.
export function coolingRange(profile: Profile, timing?: Timing): [number, number] {
  if (timing?.coolingSeconds !== undefined) return [timing.coolingSeconds[0], timing.coolingSeconds[1]]
  return profile === 'mainnet' ? [DAY, 3 * DAY] : [300, 300]
}

export interface CoolingJob { createdAt: number; coolingDrawSec?: number }
export interface FundingTimes { tShield?: number; tReceived?: number }

function checkDraw(d: unknown): number {
  const ok = typeof d === 'number' && Number.isInteger(d) && d >= 0
  if (!ok) refuse('policy.cooling-draw', 'persisted coolingDrawSec must be a non-negative integer') // @guard:policy.cooling-draw
  return d as number
}

// The ONLY place that draws: the job's persisted draw if present (never redrawn), else a fresh integer draw
// in [lo, hi]. The caller persists it on the job before COOLING starts.
export function coolingDraw(job: CoolingJob, rnd: Random, range: readonly [number, number]): number {
  if (job.coolingDrawSec !== undefined) return checkDraw(job.coolingDrawSec)
  return Math.min(range[1], Math.floor(rnd.uniform(range[0], range[1] + 1)))
}

// max(job created, latest funding time) + the job's persisted draw. A newer funding event moves the end later.
export function coolingEnd(job: CoolingJob, reserve: FundingTimes): number {
  const has = job.coolingDrawSec !== undefined
  if (!has) refuse('policy.draw-missing', 'job has no persisted coolingDrawSec: draw it with coolingDraw and persist it first') // @guard:policy.draw-missing
  const funded = Math.max(reserve.tShield ?? -Infinity, reserve.tReceived ?? -Infinity)
  return Math.max(job.createdAt, funded) + checkDraw(job.coolingDrawSec)
}

const pow10 = (k: number): bigint => 10n ** BigInt(k)

export interface Spent { amountWei: bigint; at: number }

// needed x U(1.2, 1.6) (rational, 1e6 precision), rounded to 6 significant digits whose last digit is
// then replaced by a random 1-9; redrawn if within 1% of any amount from the last 90 days, or outside
// [1.2, 1.6] x needed (the digit swap can push it out by up to ~1e-4 relative). 32 attempts, then refuse.
export function withdrawAmount(neededWei: bigint, history: readonly Spent[], now: number, rnd: Random): bigint {
  const okNeeded = neededWei > 0n
  if (!okNeeded) refuse('policy.amount-needed', 'needed amount must be positive') // @guard:policy.amount-needed
  const digits = neededWei.toString().length
  const okSize = digits >= 6
  if (!okSize) refuse('policy.amount-tiny', 'needed amount has fewer than 6 digits in wei; cannot form a 6-significant-digit amount') // @guard:policy.amount-tiny
  const recent = history.filter((h) => now - h.at <= HISTORY_DAYS * DAY)
  const lo = neededWei * 1_200_000n / 1_000_000n
  const hi = neededWei * 1_600_000n / 1_000_000n
  let found: bigint | undefined
  for (let attempt = 0; attempt < MAX_ATTEMPTS && found === undefined; attempt++) {
    const mult = 1_200_000n + BigInt(rnd.int(400_001))
    const lastDigit = BigInt(rnd.int(9) + 1)
    let amount = neededWei * mult / 1_000_000n
    let drop = amount.toString().length - 6
    let six = (amount + pow10(drop) / 2n) / pow10(drop) // nearest, 6 digits (or 1000000 after a carry)
    if (six >= 1_000_000n) { six /= 10n; drop += 1 }
    amount = (six - (six % 10n) + lastDigit) * pow10(drop)
    const inRange = amount >= lo && amount <= hi && amount >= neededWei
    const collides = recent.some((h) => {
      const diff = amount > h.amountWei ? amount - h.amountWei : h.amountWei - amount
      return diff * 100n <= h.amountWei
    })
    if (inRange && !collides) found = amount
  }
  const ok = found !== undefined
  if (!ok) refuse('policy.amount-exhausted', `no amount clear of the last ${HISTORY_DAYS} days' history in ${MAX_ATTEMPTS} attempts`) // @guard:policy.amount-exhausted
  return found as bigint
}

// perPublication x n, rounded UP to 2 significant digits.
export function suggestedDeposit(perPublicationWei: bigint, n = 5): bigint {
  const ok = perPublicationWei > 0n && Number.isSafeInteger(n) && n > 0
  if (!ok) refuse('policy.deposit-input', 'perPublicationWei and n must be positive') // @guard:policy.deposit-input
  const v = perPublicationWei * BigInt(n)
  const drop = v.toString().length - 2
  if (drop <= 0) return v
  const unit = pow10(drop)
  return (v + unit - 1n) / unit * unit
}

// LOW flag: spendable < 2 x one publication.
export function isLow(spendableWei: bigint, perPublicationWei: bigint): boolean {
  return spendableWei < 2n * perPublicationWei
}

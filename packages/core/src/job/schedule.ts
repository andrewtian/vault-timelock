// packages/core/src/job/schedule.ts — the arm schedule (spec §5.4). The API draws it once at arm, with node:crypto
// randomInt as randInt, and journals it in the ArmRecord; every executor (a takeover included) reads the same one.
//   order      a Fisher–Yates permutation of the armed chains (j = randInt(i + 1), i from the last position down);
//   offsetSec  order[0] → 0; each next chain → the previous offset + range[0] + randInt(range[1] - range[0] + 1),
//              so with two chains the second starts range[0]..range[1] seconds (inclusive) after release;
//   startAt    releaseAt + offsetSec[chain] * 1000.
// Bad inputs (a range that is not 0 <= min <= max integers, an empty or repeated chain list, a randInt result outside
// [0, max)) throw RangeError: the API validated them already (arm.chains, arm.stagger), so this is a programming
// error and never a silent default.
import type { ArmRecord, Chain } from '../contracts/index.ts'

const CHAINS: readonly Chain[] = ['eth', 'sol', 'btc']

export function drawSchedule(chains: readonly Chain[], range: readonly [number, number], randInt: (maxExclusive: number) => number): ArmRecord['schedule'] {
  const [min, max] = range
  if (!Number.isSafeInteger(min) || !Number.isSafeInteger(max) || min < 0 || min > max) throw new RangeError('drawSchedule: the range must be integers 0 <= min <= max')
  const order = [...chains]
  if (order.length === 0 || new Set(order).size !== order.length || !order.every((c) => CHAINS.includes(c))) throw new RangeError('drawSchedule: chains must be a non-empty list of distinct chains')
  const draw = (m: number): number => {
    const r = randInt(m)
    if (!Number.isSafeInteger(r) || r < 0 || r >= m) throw new RangeError('drawSchedule: randInt returned a value outside [0, max)')
    return r
  }
  for (let i = order.length - 1; i > 0; i--) {
    const j = draw(i + 1)
    const t = order[i]; order[i] = order[j]; order[j] = t
  }
  const offsetSec: Partial<Record<Chain, number>> = {}
  let at = 0
  order.forEach((c, i) => {
    if (i > 0) at += min + draw(max - min + 1)
    offsetSec[c] = at
  })
  return { order, offsetSec }
}

export function startAt(armed: ArmRecord, chain: Chain): number {
  const off = armed.schedule.offsetSec[chain]
  if (!armed.schedule.order.includes(chain) || off === undefined || !Number.isSafeInteger(off)) throw new RangeError(`startAt: ${chain} is not in the arm schedule`)
  return armed.releaseAt + off * 1000
}

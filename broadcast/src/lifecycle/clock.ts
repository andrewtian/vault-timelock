// Time and randomness behind two small interfaces, so lifecycle logic is deterministic under test.
// Production uses the system clock and the OS CSPRNG (crypto.randomInt, crypto.getRandomValues).
// Seeded/fake versions live in test/offline/lifecycle/helpers.ts: a test PRNG must never ship in src/.
import { getRandomValues, randomInt } from 'node:crypto'

export interface Clock { now(): number /* unix seconds */ }
export interface Random {
  uniform(lo: number, hi: number): number // real in [lo, hi)
  int(n: number): number // integer in [0, n)
}

export const systemClock: Clock = { now: () => Math.floor(Date.now() / 1000) }

export const systemRandom: Random = {
  uniform(lo, hi) {
    const w = getRandomValues(new Uint32Array(2))
    const u = (w[0] * 2 ** 21 + (w[1] >>> 11)) / 2 ** 53 // 53 random bits -> [0, 1)
    return lo + u * (hi - lo)
  },
  int: (n) => randomInt(n),
}

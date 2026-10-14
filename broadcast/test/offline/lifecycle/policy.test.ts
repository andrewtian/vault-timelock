import { test } from 'node:test'
import assert from 'node:assert/strict'
import { coolingRange, coolingDraw, coolingEnd, withdrawAmount, suggestedDeposit, isLow } from '../../../src/lifecycle/policy.ts'
import { refused, seededRandom } from './helpers.ts'

const H = 3600, D = 86400
const NEEDED = 12_345_678_901_234_567n // wei, 17 digits
const mulFrac = (x: bigint, num: bigint) => x * num / 1_000_000n

test('coolingRange: mainnet 24-72 h; testnet and local 5 min; timing override wins', () => {
  assert.deepEqual(coolingRange('mainnet'), [86400, 259200])
  assert.deepEqual(coolingRange('testnet'), [300, 300])
  assert.deepEqual(coolingRange('local'), [300, 300])
  assert.deepEqual(coolingRange('mainnet', {}), [86400, 259200])
  assert.deepEqual(coolingRange('testnet', { tickSeconds: 5 }), [300, 300])
  for (const p of ['mainnet', 'testnet', 'local'] as const) assert.deepEqual(coolingRange(p, { coolingSeconds: [10, 20] }), [10, 20])
})

test('coolingDraw: persisted draw is reused and the rng untouched; otherwise uniform in range', () => {
  const rnd = { uniform: () => { throw new Error('must not draw') }, int: () => { throw new Error('must not draw') } }
  assert.equal(coolingDraw({ createdAt: 1, coolingDrawSec: 4242 }, rnd, [86400, 259200]), 4242)
  const r = seededRandom(1)
  const d = coolingDraw({ createdAt: 1 }, r, [86400, 259200])
  assert.ok(Number.isInteger(d) && d >= 86400 && d <= 259200)
  assert.equal(coolingDraw({ createdAt: 1 }, seededRandom(1), [300, 300]), 300)
})

test('coolingDraw refuses a malformed persisted draw (policy.cooling-draw)', () => {
  const r = seededRandom(1)
  for (const bad of [-1, NaN, Infinity, 1.5, '5' as unknown as number]) {
    refused(() => coolingDraw({ createdAt: 1, coolingDrawSec: bad }, r, [1, 2]), 'policy.cooling-draw')
  }
  assert.equal(coolingDraw({ createdAt: 1, coolingDrawSec: 0 }, r, [1, 2]), 0)
})

test('10k seeded cooling draws (coolingDraw) stay within [24 h, 72 h]; end = max(created, lastFunded) + draw', () => {
  const rnd = seededRandom(42)
  const range = coolingRange('mainnet')
  let lo = Infinity, hi = -Infinity
  for (let i = 0; i < 10_000; i++) {
    const created = 1_000_000 + i
    const funded = i % 3 === 0 ? created - 500 : created + 700
    const draw = coolingDraw({ createdAt: created }, rnd, range)
    assert.ok(draw >= 24 * H && draw <= 72 * H, String(draw))
    assert.equal(coolingEnd({ createdAt: created, coolingDrawSec: draw }, { tShield: funded }), Math.max(created, funded) + draw)
    lo = Math.min(lo, draw); hi = Math.max(hi, draw)
  }
  assert.ok(lo < 24 * H + H && hi > 72 * H - H, 'the draws cover the range')
})

test('coolingEnd: lastFundedAt is the latest of t_shield and t_received; none -> createdAt', () => {
  const job = { createdAt: 1000, coolingDrawSec: 50 }
  assert.equal(coolingEnd(job, {}), 1050)
  assert.equal(coolingEnd(job, { tShield: 900 }), 1050)
  assert.equal(coolingEnd(job, { tShield: 1200 }), 1250)
  assert.equal(coolingEnd(job, { tReceived: 1300 }), 1350)
  assert.equal(coolingEnd(job, { tShield: 1200, tReceived: 1300 }), 1350)
  assert.equal(coolingEnd(job, { tShield: 1500, tReceived: 1300 }), 1550)
})

test('policy.draw-missing: coolingEnd never draws; it requires the persisted draw', () => {
  refused(() => coolingEnd({ createdAt: 1 }, {}), 'policy.draw-missing')
  refused(() => coolingEnd({ createdAt: 1, coolingDrawSec: -1 }, {}), 'policy.cooling-draw')
})

test('a persisted draw is never redrawn; a later funding event moves coolingEnd later with the same draw', () => {
  const job = { createdAt: 10_000, coolingDrawSec: 100_000 }
  const e1 = coolingEnd(job, { tShield: 9000 })
  assert.equal(e1, 110_000)
  const e2 = coolingEnd(job, { tShield: 9000, tReceived: 50_000 })
  assert.equal(e2, 150_000)
  assert.ok(e2 > e1)
})

test('coolingDraw with a timing override range uses that range', () => {
  const rnd = seededRandom(5)
  const range = coolingRange('local', { coolingSeconds: [60, 90] })
  for (let i = 0; i < 500; i++) {
    const d = coolingDraw({ createdAt: 0 }, rnd, range)
    assert.ok(d >= 60 && d <= 90)
  }
  assert.equal(coolingDraw({ createdAt: 7 }, rnd, coolingRange('testnet')), 300)
})

function sig6(a: bigint): { ok: boolean; last: number } {
  const s = a.toString()
  return { ok: s.length >= 6 && /^0*$/.test(s.slice(6)) && s[5] !== '0', last: Number(s[5]) }
}

test('10k seeded amounts: within [1.2, 1.6] x needed, exactly 6 significant digits, last digit 1-9', () => {
  const rnd = seededRandom(99)
  const lasts = new Set<number>()
  for (let i = 0; i < 10_000; i++) {
    const needed = NEEDED + BigInt(i) * 1_000_003n
    const a = withdrawAmount(needed, [], 1_000_000, rnd)
    assert.ok(a >= mulFrac(needed, 1_200_000n) && a <= mulFrac(needed, 1_600_000n) + 1n, `${a} vs ${needed}`)
    assert.ok(a >= needed)
    const s = sig6(a)
    assert.ok(s.ok, String(a))
    assert.ok(s.last >= 1 && s.last <= 9)
    lasts.add(s.last)
  }
  assert.equal(lasts.size, 9)
})

test('withdrawAmount: digits count in wei; 6-digit and 7-digit needed work; example shape', () => {
  const rnd = seededRandom(3)
  for (const needed of [100_000n, 999_999n, 1_000_000n, 123_456n, 10n ** 30n + 7n]) {
    for (let i = 0; i < 200; i++) {
      const a = withdrawAmount(needed, [], 0, rnd)
      assert.ok(sig6(a).ok, `${needed} -> ${a}`)
      assert.ok(a >= needed)
    }
  }
  const a = withdrawAmount(10n ** 18n, [], 0, seededRandom(11))
  assert.match(a.toString(), /^1[2-6][0-9]{4}0{13}$/)
})

test('policy.amount-tiny: needed with fewer than 6 digits; policy.amount-needed: non-positive', () => {
  const rnd = seededRandom(1)
  for (const n of [1n, 99_999n, 12_345n]) refused(() => withdrawAmount(n, [], 0, rnd), 'policy.amount-tiny')
  for (const n of [0n, -5n]) refused(() => withdrawAmount(n, [], 0, rnd), 'policy.amount-needed')
})

test('history within 1% is avoided; history older than 90 days is ignored', () => {
  const now = 100 * D
  const needed = 10n ** 18n
  const rnd = seededRandom(2)
  // recent history in the middle of the range: no result is within 1% of it
  const h = 14n * 10n ** 17n
  const hist = [{ amountWei: h, at: now - D }]
  for (let i = 0; i < 3000; i++) {
    const a = withdrawAmount(needed, hist, now, rnd)
    const diff = a > h ? a - h : h - a
    assert.ok(diff * 100n > h, `${a} too close to ${h}`)
  }
  // the same history, 91 days old, is ignored: some result lands within 1% of it
  const old = [{ amountWei: h, at: now - 91 * D }]
  const r2 = seededRandom(2)
  let close = 0
  for (let i = 0; i < 3000; i++) {
    const a = withdrawAmount(needed, old, now, r2)
    const diff = a > h ? a - h : h - a
    if (diff * 100n <= h) close++
  }
  assert.ok(close > 0)
})

test('90-day boundary: exactly 90 days counts, 90 days + 1 s does not', () => {
  const now = 200 * D
  const needed = 10n ** 18n
  // a single-value history that blocks every draw (spans the whole range) tests the window edge
  const dense = (at: number) => denseHistory(needed, at)
  refused(() => withdrawAmount(needed, dense(now - 90 * D), now, seededRandom(4)), 'policy.amount-exhausted')
  assert.ok(withdrawAmount(needed, dense(now - 90 * D - 1), now, seededRandom(4)) >= needed)
})

function denseHistory(needed: bigint, at: number): { amountWei: bigint; at: number }[] {
  const out: { amountWei: bigint; at: number }[] = []
  // 1.5% steps from 1.19 x to 1.61 x: every point in [1.2, 1.6] is within 1% of one entry
  for (let m = 1_190_000n; m <= 1_650_000n; m = m * 1015n / 1000n) out.push({ amountWei: needed * m / 1_000_000n, at })
  return out
}

test('policy.amount-exhausted: dense history makes every draw collide; and it takes at most 32 attempts', () => {
  const needed = 10n ** 18n
  const now = 5 * D
  let calls = 0
  const base = seededRandom(8)
  const counting = { uniform: base.uniform, int: (n: number) => { calls++; return base.int(n) } }
  refused(() => withdrawAmount(needed, denseHistory(needed, now - D), now, counting), 'policy.amount-exhausted')
  assert.equal(calls, 32 * 2) // two int() draws per attempt (multiplier, last digit), exactly 32 attempts
})

test('suggestedDeposit: per x n rounded UP to 2 significant digits', () => {
  assert.equal(suggestedDeposit(10n ** 16n), 5n * 10n ** 16n) // 0.01 ETH x 5 = 0.05 ETH exactly
  assert.equal(suggestedDeposit(12_345n * 10n ** 12n), 62n * 10n ** 15n) // 61.725e15 -> 62e15
  assert.equal(suggestedDeposit(20n * 10n ** 15n, 5), 10n ** 17n)
  assert.equal(suggestedDeposit(2_000_000_000_000_001n), 11n * 10n ** 15n) // 10.000000000000005e15 -> 11e15
  assert.equal(suggestedDeposit(1_000_000_000_000_000n, 10), 10n ** 16n)
  assert.equal(suggestedDeposit(3n), 15n)
  assert.equal(suggestedDeposit(1n, 99), 99n)
  assert.equal(suggestedDeposit(199n, 5), 1000n) // 995 -> 1000
  assert.equal(suggestedDeposit(10n ** 18n, 3), 3n * 10n ** 18n)
  assert.equal(suggestedDeposit(333n * 10n ** 15n), 17n * 10n ** 17n) // 1665e15 -> 17e17
})

test('policy.deposit-input: non-positive wei or bad n', () => {
  for (const [p, n] of [[0n, 5], [-1n, 5], [1n, 0], [1n, -1], [1n, 1.5], [1n, NaN]] as const) refused(() => suggestedDeposit(p, n), 'policy.deposit-input')
})

test('isLow: spendable < 2 x perPublication (boundary)', () => {
  assert.equal(isLow(199n, 100n), true)
  assert.equal(isLow(200n, 100n), false)
  assert.equal(isLow(201n, 100n), false)
  assert.equal(isLow(0n, 100n), true)
  assert.equal(isLow(0n, 0n), false)
})

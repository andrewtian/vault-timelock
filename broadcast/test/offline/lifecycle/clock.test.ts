import { test } from 'node:test'
import assert from 'node:assert/strict'
import { systemClock, systemRandom } from '../../../src/lifecycle/clock.ts'
import { seededRandom } from './helpers.ts'

test('systemClock is unix seconds (integer)', () => {
  const t = systemClock.now()
  assert.ok(Number.isInteger(t))
  assert.ok(Math.abs(t - Date.now() / 1000) < 2)
})

test('systemRandom: uniform stays in [lo, hi), int in [0, n); not constant', () => {
  const seen = new Set<number>()
  for (let i = 0; i < 2000; i++) {
    const u = systemRandom.uniform(10, 20)
    assert.ok(u >= 10 && u < 20)
    const k = systemRandom.int(9)
    assert.ok(Number.isInteger(k) && k >= 0 && k < 9)
    seen.add(k)
  }
  assert.equal(seen.size, 9)
  assert.notEqual(systemRandom.uniform(0, 1), systemRandom.uniform(0, 1))
})

test('seededRandom is deterministic per seed', () => {
  const a = seededRandom(7), b = seededRandom(7), c = seededRandom(8)
  const xs = [a.uniform(0, 1), a.int(100), a.uniform(5, 6)]
  assert.deepEqual([b.uniform(0, 1), b.int(100), b.uniform(5, 6)], xs)
  assert.notDeepEqual([c.uniform(0, 1), c.int(100), c.uniform(5, 6)], xs)
})

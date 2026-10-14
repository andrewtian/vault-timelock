// drawSchedule / startAt (spec §5.4): order is a permutation drawn with the caller's CSPRNG (randInt), the first chain
// starts at release, the second after a stagger drawn from the range, inclusive. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { drawSchedule, startAt } from '../../src/job/index.ts'
import type { ArmRecord, Chain } from '../../src/contracts/index.ts'
import { readJson, seeded } from './helpers.ts'

const v = readJson<{
  draws: Array<{ chains: Chain[]; range: [number, number]; rand: 'zero' | 'max'; secondOffset: number | null }>
  startAt: Array<{ armed: ArmRecord; chain: Chain; at: number }>
}>('arm/schedule.json')

test('seeded draws: the order is a permutation, the first offset is 0, the second is within the range inclusive', () => {
  const rand = seeded(20261009)
  for (let i = 0; i < 200; i++) {
    const s = drawSchedule(['eth', 'sol'], [30, 300], rand)
    assert.deepEqual([...s.order].sort(), ['eth', 'sol'])
    assert.equal(s.offsetSec[s.order[0]], 0)
    const second = s.offsetSec[s.order[1]]!
    assert.ok(Number.isInteger(second) && second >= 30 && second <= 300, String(second))
    assert.deepEqual(Object.keys(s.offsetSec).sort(), ['eth', 'sol'])
  }
})

test('1,000 seeded draws cover both orders and both ends of a small range', () => {
  const rand = seeded(7)
  const orders = new Set<string>()
  const seconds = new Set<number>()
  for (let i = 0; i < 1_000; i++) {
    const s = drawSchedule(['eth', 'sol'], [5, 7], rand)
    orders.add(s.order.join(','))
    seconds.add(s.offsetSec[s.order[1]]!)
  }
  assert.deepEqual([...orders].sort(), ['eth,sol', 'sol,eth'])
  assert.deepEqual([...seconds].sort(), [5, 6, 7])
})

test('a single chain gets offset 0 and draws no stagger', () => {
  let calls = 0
  const s = drawSchedule(['sol'], [30, 300], (m) => { calls++; return m - 1 })
  assert.deepEqual(s, { order: ['sol'], offsetSec: { sol: 0 } })
  assert.equal(calls, 0)
})

test('the contract vectors (randInt always 0, or always max - 1)', () => {
  for (const d of v.draws) {
    const s = drawSchedule(d.chains, d.range, (max) => (d.rand === 'zero' ? 0 : max - 1))
    assert.deepEqual([...s.order].sort(), [...d.chains].sort())
    assert.equal(s.offsetSec[s.order[0]], 0)
    if (d.secondOffset !== null) assert.equal(s.offsetSec[s.order[1]], d.secondOffset)
  }
})

test('fails closed on a bad randInt, range or chain list (never a silent default)', () => {
  for (const bad of [(m: number) => m, () => -1, () => 0.5, () => Number.NaN]) assert.throws(() => drawSchedule(['eth', 'sol'], [30, 300], bad), RangeError)
  for (const r of [[10, 5], [-1, 5], [1.5, 3], [0, Number.POSITIVE_INFINITY]] as Array<[number, number]>) assert.throws(() => drawSchedule(['eth', 'sol'], r, () => 0), RangeError)
  for (const c of [[], ['eth', 'eth'], ['doge']] as unknown as Chain[][]) assert.throws(() => drawSchedule(c, [30, 300], () => 0), RangeError)
})

test('startAt = releaseAt + offsetSec[chain] * 1000; an un-armed chain has no start', () => {
  for (const c of v.startAt) assert.equal(startAt(c.armed, c.chain), c.at)
  const armed = v.startAt[0].armed
  assert.throws(() => startAt({ ...armed, schedule: { order: ['sol'], offsetSec: { sol: 0 } } }, 'eth'), RangeError)
})

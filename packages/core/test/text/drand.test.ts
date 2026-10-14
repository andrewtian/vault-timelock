import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Refusal } from '../../src/text/guard.ts'
import { checkChainInfo, QUICKNET, roundAt, roundForUnlock, roundTime, unlockIso } from '../../src/text/drand.ts'
import { CHAIN_INFO, GENESIS, PERIOD, ROUND, UNLOCK } from './fixtures.ts'

test('round math matches SEALED.txt (genesis + (round - 1) x period)', () => {
  assert.equal(roundTime(1), GENESIS)
  assert.equal(roundTime(ROUND), GENESIS + (ROUND - 1) * PERIOD)
  assert.equal(unlockIso(ROUND), UNLOCK)
  assert.equal(roundAt(roundTime(ROUND)), ROUND)
  assert.equal(roundAt(roundTime(ROUND) - 1), ROUND - 1)
  assert.equal(roundAt(roundTime(ROUND) + PERIOD - 1), ROUND)
  assert.equal(roundForUnlock(roundTime(ROUND)), ROUND)
  assert.equal(roundForUnlock(roundTime(ROUND) - 1), ROUND)
  assert.equal(roundForUnlock(roundTime(ROUND) + 1), ROUND + 1)
  assert.equal(roundForUnlock(0), 1)
})

test('the pinned quicknet equals the fixture chain info', () => {
  assert.deepEqual(JSON.parse(JSON.stringify(QUICKNET)), CHAIN_INFO)
})

test('planE6 M-7: roundAt is 0 before genesis, never negative; the pinned quicknet is frozen', () => {
  for (const d of [1, 3, 4, 10, 1e6]) assert.equal(roundAt(QUICKNET.genesis_time - d), 0)
  assert.equal(roundAt(QUICKNET.genesis_time), 1)
  assert.equal(Object.isFrozen(QUICKNET), true)
  assert.equal(Object.isFrozen(QUICKNET.metadata), true)
})

test('drand.chain-info: the chain info must equal the pinned quicknet chain', () => {
  checkChainInfo(CHAIN_INFO)
  const bad = (v: unknown) => assert.throws(() => checkChainInfo(v), (e: unknown) => e instanceof Refusal && e.guardId === 'drand.chain-info')
  bad(null)
  bad('quicknet')
  bad({})
  for (const k of ['hash', 'public_key', 'period', 'genesis_time', 'schemeID'] as const) bad({ ...CHAIN_INFO, [k]: k === 'period' || k === 'genesis_time' ? 1 : '00' })
})

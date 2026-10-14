// Fork- and recipient-aware gas (contracts/gas.ts) and the fork-drift messages for vt preflight / the relay.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkForkDrift, detectEthFork, estimateMatches, ethDataGas, FORK_PROBE_BYTES } from '../../src/contracts/index.ts'

test('the three formulas', () => {
  assert.equal(ethDataGas(100, { amsterdam: false, toSelf: false }), 25_000)
  assert.equal(ethDataGas(100, { amsterdam: false, toSelf: true }), 25_000)
  assert.equal(ethDataGas(100, { amsterdam: true, toSelf: true }), 18_400)
  assert.equal(ethDataGas(100, { amsterdam: true, toSelf: false }), 21_400)
  assert.equal(ethDataGas(98_304, { amsterdam: true, toSelf: false }), 6_306_456) // under the 2^24 per-tx cap
  assert.throws(() => ethDataGas(-1, { amsterdam: false, toSelf: false }), RangeError)
})

test('an estimate matches within [g, g + ceil(g * 15 / 985)]', () => {
  assert.equal(estimateMatches(25_000, 25_000), true)
  assert.equal(estimateMatches(25_000 + 381, 25_000), true)
  assert.equal(estimateMatches(25_000 + 382, 25_000), false)
  assert.equal(estimateMatches(24_999, 25_000), false)
  assert.equal(estimateMatches(25_100n, 25_000), true)
})

test('fork detection at the probe size is unambiguous for both recipients', () => {
  for (const toSelf of [false, true]) {
    assert.equal(detectEthFork(ethDataGas(FORK_PROBE_BYTES, { amsterdam: false, toSelf }), FORK_PROBE_BYTES, toSelf), 'pre-amsterdam')
    assert.equal(detectEthFork(ethDataGas(FORK_PROBE_BYTES, { amsterdam: true, toSelf }), FORK_PROBE_BYTES, toSelf), 'amsterdam')
  }
  assert.equal(detectEthFork(20_000, FORK_PROBE_BYTES, false), 'unknown')
  assert.equal(detectEthFork(31_000, 250, false), 'ambiguous') // 21000+40·250 = 15000+64·250
})

test('drift messages name the cause', () => {
  const ams = ethDataGas(FORK_PROBE_BYTES, { amsterdam: true, toSelf: false })
  const pre = ethDataGas(FORK_PROBE_BYTES, { amsterdam: false, toSelf: false })
  assert.deepEqual(checkForkDrift('mainnet', { estimate: pre, n: FORK_PROBE_BYTES, toSelf: false }),
    { network: 'mainnet', expected: 'pre-amsterdam', observed: 'pre-amsterdam', ok: true, message: null })
  assert.equal(checkForkDrift('mainnet', { estimate: ams, n: FORK_PROBE_BYTES, toSelf: false }).message, 'Amsterdam appears active on mainnet — update required')
  assert.equal(checkForkDrift('testnet', { estimate: pre, n: FORK_PROBE_BYTES, toSelf: false }).message, 'Amsterdam appears inactive on testnet — update required')
  assert.equal(checkForkDrift('testnet', { estimate: ams, n: FORK_PROBE_BYTES, toSelf: false }).ok, true)
  assert.equal(checkForkDrift('local', { estimate: ams, n: FORK_PROBE_BYTES, toSelf: false }, { localOverride: true }).ok, true)
  assert.match(checkForkDrift('mainnet', { estimate: 1, n: FORK_PROBE_BYTES, toSelf: false }).message!, /matches neither/)
  assert.match(checkForkDrift('mainnet', { estimate: 31_000, n: 250, toSelf: false }).message!, /ambiguous/)
})

// Mapped by test/mutation/guards.json: contract.network, contract.fork-override.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { assertNetwork, ethAmsterdam, ETH_FORKS, isNetwork, isRefusal, NETWORKS } from '../src/contracts/index.ts'

const guardOf = (fn: () => unknown): string | null => {
  try { fn() } catch (e) { if (isRefusal(e)) return e.guardId; throw e }
  return null
}

test('assertNetwork accepts the three networks', () => {
  for (const n of ['local', 'testnet', 'mainnet']) assert.equal(guardOf(() => assertNetwork(n)), null)
  assert.deepEqual([...NETWORKS], ['local', 'testnet', 'mainnet'])
})

test('assertNetwork refuses anything else with contract.network', () => {
  for (const v of ['devnet', '', 1, null, undefined, 'Local', 'mainnet ', {}]) assert.equal(guardOf(() => assertNetwork(v)), 'contract.network', String(v))
  assert.equal(isNetwork('devnet'), false)
})

test('the network table: Amsterdam is on for testnet only by default', () => {
  assert.deepEqual(Object.fromEntries(NETWORKS.map((n) => [n, ethAmsterdam(n)])), { local: false, testnet: true, mainnet: false })
  assert.deepEqual(Object.fromEntries(NETWORKS.map((n) => [n, ETH_FORKS[n].overridable])), { local: true, testnet: false, mainnet: false })
})

test('the Amsterdam override applies to local only; anywhere else contract.fork-override', () => {
  assert.equal(ethAmsterdam('local', { localOverride: true }), true)
  assert.equal(ethAmsterdam('local', { localOverride: false }), false)
  assert.equal(guardOf(() => ethAmsterdam('mainnet', { localOverride: true })), 'contract.fork-override')
  assert.equal(guardOf(() => ethAmsterdam('testnet', { localOverride: false })), 'contract.fork-override')
  assert.equal(guardOf(() => ethAmsterdam('mainnet', { localOverride: false })), 'contract.fork-override')
  assert.equal(guardOf(() => ethAmsterdam('devnet' as never)), 'contract.network')
})

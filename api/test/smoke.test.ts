// Task 0 smoke: the workspace resolves the contracts (workspace link) and vt-broadcast (file: link).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { PORTS } from '@vault-timelock/core/contracts'
import { NETWORK_IDS } from 'vt-broadcast/src/config.ts'

test('contracts and vt-broadcast resolve', () => {
  assert.equal(PORTS.testnet.relay, 5191)
  assert.equal(NETWORK_IDS.testnet.eth, 11155111)
})

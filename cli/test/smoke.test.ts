// Task 0 smoke: the workspace resolves vt-broadcast (file: link) and the contracts (workspace link).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readPassphrase } from 'vt-broadcast/src/lifecycle/passphrase.ts'
import { PORTS } from '@vault-timelock/core/contracts'

test('vt-broadcast and contracts resolve', () => {
  assert.equal(typeof readPassphrase, 'function')
  assert.equal(PORTS.local.api, 5182)
})

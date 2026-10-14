// E6: broadcast and the moved core modules agree (the core tests cannot import broadcast: a release would treat a core
// devDependency on vt-broadcast as dev-only).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { QUICKNET } from '../../src/drand.ts'
import { QUICKNET as CORE } from '@vault-timelock/core/text/drand.ts'
import { Refusal as CoreRefusal } from '@vault-timelock/core/text/guard.ts'
import { Refusal } from '../../src/guard.ts'

test('core\'s pinned quicknet (what sealed-from.ts checks) is broadcast\'s drand.ts constant, field for field, and anchors.json\'s', () => {
  assert.equal(CORE.hash, QUICKNET.hash)
  assert.equal(CORE.genesis_time, QUICKNET.genesis)
  assert.equal(CORE.period, QUICKNET.period)
  assert.equal(CORE.schemeID, QUICKNET.schemeID)
  const anchors = JSON.parse(readFileSync(new URL('../../anchors.json', import.meta.url), 'utf8')) as Record<string, { address: string }>
  assert.equal(anchors['drand.quicknet'].address, CORE.hash)
})

test('broadcast\'s Refusal is core\'s', () => {
  assert.equal(Refusal, CoreRefusal)
})

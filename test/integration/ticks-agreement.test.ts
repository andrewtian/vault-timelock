// PF-C M-5: `vt job arm` shows the five mainnet ticks in the page's words (web/src/status/readiness.js MAINNET_TICKS). Repository-level
// because the cli workspace (and its mutation copy) cannot see web/.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { MAINNET_TICKS } from '../../cli/src/job/arm.ts'

test('the CLI\'s five ticks are the page\'s, word for word and in order', () => {
  const web = readFileSync(new URL('../../web/src/status/readiness.js', import.meta.url), 'utf8')
  const page = [...web.matchAll(/\{ id: '(\w+)', label: '([^']+)' \}/g)].map((m) => [m[1], m[2]])
  assert.equal(page.length, 5)
  assert.deepEqual(MAINNET_TICKS.map((t) => [t.id, t.label]), page)
})

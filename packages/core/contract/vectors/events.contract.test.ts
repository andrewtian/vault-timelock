// Event vectors: every journal line in the fixtures validates; each invalid case is refused with its guard.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { fixture, guardOf, loadJobModule, readJson } from './job-module.ts'
import type { JournalEvent } from '../../src/contracts/index.ts'

const journals = readdirSync(fixture('journals')).filter((f) => f.endsWith('.jsonl')).sort()
const invalid = readJson<{ cases: Array<{ name: string; type: string; data: unknown; by: string; guard: string }> }>('events/invalid.json')

for (const f of journals) {
  test(`every line of ${f} validates`, async () => {
    const m = await loadJobModule()
    for (const line of readFileSync(fixture(`journals/${f}`), 'utf8').split('\n').filter((l) => l !== '')) {
      const e = JSON.parse(line) as JournalEvent
      assert.equal(guardOf(() => m.validateEvent(e.type, e.data, e.by)), null, `seq ${e.seq} ${e.type}`)
    }
  })
}

for (const c of invalid.cases) {
  test(`invalid event: ${c.name} → ${c.guard}`, async () => {
    const m = await loadJobModule()
    assert.equal(guardOf(() => m.validateEvent(c.type, c.data, c.by)), c.guard)
  })
}

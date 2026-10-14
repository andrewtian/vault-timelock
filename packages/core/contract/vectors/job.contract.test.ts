// vt-job/1 vectors: every valid job normalizes to the pinned canonical def and id; every invalid job is refused with
// its guard. Fixtures: contract/fixtures/jobs/.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync } from 'node:fs'
import { fixture, guardOf, loadJobModule, readJson } from './job-module.ts'
import type { JobDef, Network } from '../../src/contracts/index.ts'

const valid = readJson<Record<string, { id: string; def: JobDef }>>('jobs/valid/expected.json')
const invalid = readJson<Record<string, string>>('jobs/invalid/expected.json')
const reversed = (v: unknown): unknown => Array.isArray(v) ? v.map(reversed)
  : v !== null && typeof v === 'object' ? Object.fromEntries(Object.entries(v as object).reverse().map(([k, x]) => [k, reversed(x)])) : v

test('every fixture file is listed in its expected.json', () => {
  assert.deepEqual(readdirSync(fixture('jobs/valid')).filter((f) => f !== 'expected.json').sort(), Object.keys(valid).sort())
  assert.deepEqual(readdirSync(fixture('jobs/invalid')).filter((f) => f !== 'expected.json').sort(), Object.keys(invalid).sort())
})

for (const [file, want] of Object.entries(valid)) {
  test(`valid ${file} → canonical def ${want.id}`, async () => {
    const m = await loadJobModule()
    const input = readJson<Record<string, unknown>>(`jobs/valid/${file}`)
    // btc-defaults.json is the OLD shape (no maxFeeRateSatVb): an existing record loads (500 sat/vB fallback); a NEW job must name the ceiling (Eminors fix 1)
    const existing = file === 'btc-defaults.json'
    if (existing) assert.throws(() => m.normalizeJob(input, { network: input.network as Network }), (e: unknown) => (e as { guardId?: string }).guardId === 'job.btc-fee-ceiling')
    const { def, text } = m.normalizeJob(input, { network: input.network as Network, existing })
    assert.deepEqual(def, want.def)
    assert.equal(m.jobId(def), want.id)
    assert.equal(text, typeof input.message === 'string' ? input.message : null)
    assert.equal(m.canonicalJson(reversed(def)), m.canonicalJson(def), 'canonical JSON is stable under key reordering')
    assert.deepEqual(m.normalizeJob(reversed(input), { network: input.network as Network, existing }).def, want.def)
  })
}

for (const [file, guard] of Object.entries(invalid)) {
  test(`invalid ${file} → ${guard}`, async () => {
    const m = await loadJobModule()
    const input = readJson<Record<string, unknown>>(`jobs/invalid/${file}`)
    const network = (typeof input.network === 'string' && ['local', 'testnet', 'mainnet'].includes(input.network) ? input.network : 'local') as Network
    assert.equal(guardOf(() => m.normalizeJob(input, { network })), guard)
  })
}

test('the same definition on another network is refused job.network', async () => {
  const m = await loadJobModule()
  const input = readJson<Record<string, unknown>>('jobs/valid/both-testnet.json')
  assert.equal(guardOf(() => m.normalizeJob(input, { network: 'local' })), 'job.network')
})

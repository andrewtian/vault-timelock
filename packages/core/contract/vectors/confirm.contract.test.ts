// Arm-confirmation vectors: checkArmConfirm(network, request) refuses with the pinned guard, or passes.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { guardOf, loadJobModule, readJson } from './job-module.ts'
import type { ArmRequest, Chain, JobState, Network } from '../../src/contracts/index.ts'

const v = readJson<{ cases: Array<{ name: string; network: Network; request: ArmRequest; guard: string | null }> }>('arm/confirm.json')

for (const c of v.cases) {
  test(`checkArmConfirm ${c.network}: ${c.name} → ${c.guard ?? 'ok'}`, async () => {
    const m = await loadJobModule()
    assert.equal(guardOf(() => m.checkArmConfirm(c.network, c.request)), c.guard)
  })
}

// CC-2a: the typed claw-back amount (checkClawbackConfirm) refuses with the pinned guard, or passes.
const cc = readJson<{ cases: Array<{ name: string; chain: Chain; state: JobState; data: Record<string, unknown>; confirm?: unknown; guard: string | null }> }>('arm/clawback-confirm.json')
for (const c of cc.cases) {
  test(`checkClawbackConfirm ${c.chain}: ${c.name} → ${c.guard ?? 'ok'}`, async () => {
    const m = await loadJobModule()
    assert.equal(guardOf(() => m.checkClawbackConfirm(c.state, c.chain, c.data, ...(Object.hasOwn(c, 'confirm') ? [c.confirm] : []))), c.guard)
  })
}

// Schedule vectors: drawSchedule maps randInt onto the stagger range; startAt follows the arm record.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { loadJobModule, readJson } from './job-module.ts'
import type { ArmRecord, Chain } from '../../src/contracts/index.ts'

const v = readJson<{
  draws: Array<{ chains: Chain[]; range: [number, number]; rand: 'zero' | 'max'; secondOffset: number | null }>
  startAt: Array<{ armed: ArmRecord; chain: Chain; at: number }>
}>('arm/schedule.json')

for (const d of v.draws) {
  test(`drawSchedule ${d.chains.join('+')} [${d.range.join(', ')}] rand=${d.rand}`, async () => {
    const m = await loadJobModule()
    const s = m.drawSchedule(d.chains, d.range, (max) => (d.rand === 'zero' ? 0 : max - 1))
    assert.deepEqual([...s.order].sort(), [...d.chains].sort(), 'order is a permutation')
    assert.equal(s.offsetSec[s.order[0]], 0)
    if (d.secondOffset !== null) assert.equal(s.offsetSec[s.order[1]], d.secondOffset)
    assert.deepEqual(Object.keys(s.offsetSec).sort(), [...d.chains].sort())
  })
}

for (const c of v.startAt) {
  test(`startAt ${c.chain}`, async () => {
    const m = await loadJobModule()
    assert.equal(m.startAt(c.armed, c.chain), c.at)
  })
}

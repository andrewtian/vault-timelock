// Reducer vectors: reduce(def, events) deep-equals the pinned JobState; the semantics are in src/contracts/types.ts.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fixture, loadJobModule, readJson } from './job-module.ts'
import type { JobDef, JobState, JournalEvent } from '../../src/contracts/index.ts'

const index = readJson<{ vectors: Array<{ name: string }> }>('journals/index.json')
const events = (name: string): JournalEvent[] => readFileSync(fixture(`journals/${name}.jsonl`), 'utf8').split('\n').filter((l) => l !== '').map((l) => JSON.parse(l) as JournalEvent)

for (const { name } of index.vectors) {
  test(`reduce ${name}`, async () => {
    const m = await loadJobModule()
    const def = readJson<JobDef>(`journals/${name}.def.json`)
    const evs = events(name)
    assert.equal(m.jobId(def), (evs[0].data as { jobId: string }).jobId, 'created.jobId = jobId(def)')
    const state = m.reduce(def, evs)
    assert.deepEqual(state, readJson<JobState>(`journals/${name}.state.json`))
    for (const cs of Object.values(state.chains)) {
      const terminal = (cs!.phase === 'DONE' || cs!.phase === 'CLAWED_BACK' || cs!.phase === 'SKIPPED') && cs!.openIntents.length === 0
      assert.equal(m.isChainTerminal(cs!), terminal, `isChainTerminal(${cs!.phase})`)
    }
  })
}

// E6 (M1.1a issue 3 / E5 concern 5): a RUNNING passive ETH lane shows "(window N blocks, RPC limit)" in the progress text
// (the ChainRunView note the page and `vt job run` print), not only in the adapter label. Progress text only: no new journal
// event type. ALL DATA IS SYNTHETIC; the fake RPC serves fee history for the newest 1,024 blocks only.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createExecutor } from '../../src/executor/executor.ts'
import { windowNoteOf } from '../../src/engine/lane.js'
import type { ChainRunView } from '../../src/contracts/index.ts'
import { deps, stack, types } from './helpers.ts'

const GWEI = 10n ** 9n
const hx = (n: bigint | number): string => `0x${BigInt(n).toString(16)}`
// every block has base fee 1 gwei; fee history is served only when it ends at "latest" (an older chunk errors), count capped at 1,024
function limitedHistory(limit: number | null) {
  return (m: string, p: any[], base: (m: string, q: any[]) => unknown): unknown => {
    if (m !== 'eth_feeHistory') return base(m, p)
    if (limit !== null && p[1] !== 'latest') throw new Error('-32602: requested block range is out of bounds')
    const n = Math.min(Number(BigInt(p[0])), limit ?? 7200)
    return { oldestBlock: hx(10_000 - n), baseFeePerGas: Array.from({ length: n + 1 }, () => hx(GWEI)), reward: Array.from({ length: n }, () => (p[2] as unknown[]).map(() => hx(GWEI))) }
  }
}
async function runPassive(limit: number | null): Promise<{ views: ChainRunView[]; types: string[] }> {
  const s = stack('eth', { copies: 1, feeStrategy: 'passive', eth: limitedHistory(limit) })
  const views: ChainRunView[] = []
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: { ...deps(s), onView: (v: ChainRunView) => { views.push(v) } } })
  assert.equal(await ex.start(), 'copies-done')
  return { views, types: types(s.j.events, 'eth') }
}

test('the note text is one function: "(window N blocks, RPC limit)"', () => {
  assert.equal(windowNoteOf(1024), '(window 1024 blocks, RPC limit)')
})

test('a running passive ETH lane on an RPC that limits fee history shows the truncated window in its progress note', { timeout: 60_000 }, async () => {
  const r = await runPassive(1024)
  const running = r.views.filter((v) => v.phase === 'running' && v.note.includes('window'))
  assert.ok(running.length > 0, 'a running view carries the window note')
  assert.ok(running.every((v) => v.note.includes('(window 1024 blocks, RPC limit)')), running.map((v) => v.note).join(' | '))
  assert.ok(!r.types.includes('window') && r.types.every((t) => !/window/.test(t)), 'no new journal event type')
})

test('a full window (no RPC limit) never shows the note', { timeout: 60_000 }, async () => {
  const r = await runPassive(null)
  assert.ok(r.views.every((v) => !v.note.includes('RPC limit')), r.views.map((v) => v.note).join(' | '))
})

// Efix3 (Efix1 residual): the claw-back's OWN passive fee path shows the truncated window too (progress line, journal note, result)
test('a PASSIVE ETH claw-back on an RPC that limits fee history shows the truncated window in its progress note', { timeout: 60_000 }, async () => {
  for (const [limit, shows] of [[1024, true], [null, false]] as const) {
    const s = stack('eth', { copies: 1, feeStrategy: 'passive', cap: '100000000000000000000', eth: limitedHistory(limit) })
    const views: ChainRunView[] = []
    const d = { ...deps(s), onView: (v: ChainRunView) => { views.push(v) } }
    assert.equal(await createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: d }).start(), 'copies-done')
    views.length = 0
    const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: d })
    assert.equal(await ex.clawback('0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'), 'clawed-back', ex.view().note)
    const hit = views.filter((v) => v.note.includes('(window 1024 blocks, RPC limit)'))
    assert.equal(hit.length > 0, shows, views.map((v) => v.note).join(' | '))
  }
})

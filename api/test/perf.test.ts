// Per-append cost stays flat with the journal's length (S2 review I-3): a synthetic job with 80,005 journal lines (16,000
// one-part copies, five lines each), loaded once, then intent / sent / included / readback appended over HTTP — the full
// send path (lease, reconcile-first, latch, lock, assertIntentAllowed, the cap, the fsync, the ticket). Its median and
// p90 per append are compared with the same appends on a fresh job in the same process. Both use the journal's test fs
// seam with a no-op fsync, so the numbers are the API's own work, not the disk's. Before the fix an append at 80k lines
// cost ~200 ms (a full reduce + render + trace rewrite each); a flat path costs the same as on a fresh job.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { ftruncateSync, mkdirSync, writeFileSync, writeSync } from 'node:fs'
import { join } from 'node:path'
import type { JobDef } from '@vault-timelock/core/contracts'
import { canonicalJson } from '@vault-timelock/core/job'
import { createStore } from 'vt-broadcast/src/lifecycle/store.ts'
import { JOURNAL_FILE } from '../src/journal.ts'
import type { JournalFs } from '../src/journal.ts'
import { CAPS, JOB, JOB_INPUT, KEYS, START, armed, call, ethIntent, ethTx, fakeClock, fixture, startApi } from './helpers.ts'
import type { TestApi } from './helpers.ts'

process.env.NODE_ENV = 'test'

const COPIES = 16_000
const fs: JournalFs = { writeSync: (fd, b, o, l) => writeSync(fd, b, o, l), fsyncSync: () => {}, ftruncateSync: (fd, n) => ftruncateSync(fd, n) }
const sha = (s: string): string => createHash('sha256').update(s).digest('hex')

// The journal of JOB as an API would have written it: created, READY, armed and released, a lease, then COPIES copies.
function synthesize(state: string, def: JobDef): number {
  const lines: string[] = []
  let prev = ''
  let at = START
  const put = (chain: string | null, by: string, gen: number | null, type: string, data: unknown): void => {
    const line = JSON.stringify({ v: 1, seq: lines.length, at: at++, prev, chain, by, gen, type, data })
    lines.push(line)
    prev = sha(line)
  }
  put(null, 'api', null, 'created', { jobId: JOB, defSha256: sha(canonicalJson(def)) })
  put('eth', 'browser', null, 'key-loaded', { address: KEYS.eth })
  put('eth', 'browser', null, 'funds', { balance: '50000000000000000', affordable: true, nextCopyCost: '25000300000000' })
  put(null, 'api', null, 'armed', { armedAt: START - 60_000, releaseAt: START - 55_000, countdownSec: 5, schedule: { order: ['eth'], offsetSec: { eth: 0 } }, caps: { eth: CAPS.eth }, sources: {} })
  put('eth', 'api', 1, 'lease-acquired', { gen: 1, holder: 'browser', ttlMs: 15000 })
  for (let k = 1; k <= COPIES; k++) {
    const txId = ethTx(k)
    const d = ethIntent(k, k)   // gas: the copy's planned gas (PF-S fix round 2: ticket.fee-plan)
    put('eth', 'browser', 1, 'intent', { ...d, eth: { ...(d.eth as object), tip: '1', maxFee: '1000' } })
    put('eth', 'browser', 1, 'sent', { txId, outcome: 'accepted', reason: null })
    put('eth', 'browser', 1, 'included', { txId, copy: k, part: 1, attempt: 1, block: String(100 + k), fee: '1000', ms: 1 })
    put('eth', 'browser', 1, 'readback', { txId, ok: true, detail: 'byte-equal' })
    put('eth', 'browser', 1, 'reassembled', { copy: k, ok: true, sha256: 'ab'.repeat(32) })
  }
  const dir = join(state, 'jobs', JOB)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  writeFileSync(join(dir, JOURNAL_FILE), lines.join('\n') + '\n', { mode: 0o600 })
  return lines.length
}

// `rounds` copies appended as intent / sent / included / readback from copy `from`: each append's wall time in ms.
async function rounds(a: TestApi, gen: number, from: number, n: number): Promise<number[]> {
  const ms: number[] = []
  const timed = async (type: string, data: unknown): Promise<void> => {
    const t0 = performance.now()
    const r = await call(a.port, { path: `/jobs/${JOB}/chains/eth/events`, body: { gen, type, data } })
    ms.push(performance.now() - t0)
    assert.equal(r.status, 200, `${type}: ${r.text}`)
  }
  for (let k = from; k < from + n; k++) {
    const txId = ethTx(k)
    const d = ethIntent(k, k)   // gas: the copy's planned gas (PF-S fix round 2: ticket.fee-plan)
    await timed('intent', { ...d, eth: { ...(d.eth as object), tip: '1', maxFee: '1000' } })
    await timed('sent', { txId, outcome: 'accepted', reason: null })
    await timed('included', { txId, copy: k, part: 1, attempt: 1, block: String(100 + k), fee: '1000', ms: 1 })
    await timed('readback', { txId, ok: true, detail: 'byte-equal' })
  }
  return ms
}
const quantile = (xs: number[], q: number): number => { const s = [...xs].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.floor(q * s.length))] }

test('at 80,005 journal lines an append costs what it costs on a fresh job (median and p90 within 3× + 5 ms)', async (t) => {
  // the fresh job: JOB created, READY, armed, released and leased
  const small = await startApi({ fs })
  t.after(() => small.close())
  await armed(small, JOB, ['eth'])
  assert.equal((await call(small.port, { path: `/jobs/${JOB}/chains/eth/lease`, body: { op: 'acquire', holder: 'cli' } })).status, 200)
  await rounds(small, 1, 1, 5) // warm-up
  const base = await rounds(small, 1, 6, 30)

  // the long job: the same JOB with 80,005 lines, loaded on its first request
  const big = await startApi({ jobs: [], clock: fakeClock(START), fs })
  t.after(() => big.close())
  const def = fixture<{ 'eth-drain-null.json': { def: JobDef } }>('jobs/valid/expected.json')['eth-drain-null.json'].def
  await createStore(big.state, { log: () => {} }).update('job', JOB, () => ({ def, createdAt: START }))
  big.api.registry.messages.storeText(JOB_INPUT.message as string, def.messageSha256)   // as POST /jobs stores it (PF-S I-1: the API plans from it)
  const lines = synthesize(big.state, def)
  assert.equal(lines, 80_005)
  const t0 = performance.now()
  assert.equal((await call(big.port, { path: `/jobs/${JOB}/chains/eth/lease`, body: { op: 'acquire', holder: 'cli' } })).status, 200) // load + gen 2
  const loadMs = performance.now() - t0
  await rounds(big, 2, COPIES + 1, 5) // warm-up
  const long = await rounds(big, 2, COPIES + 6, 30)
  const [m0, m1, p0, p1] = [quantile(base, 0.5), quantile(long, 0.5), quantile(base, 0.9), quantile(long, 0.9)]
  t.diagnostic(`fresh job: median ${m0.toFixed(2)} ms, p90 ${p0.toFixed(2)} ms; 80k lines: median ${m1.toFixed(2)} ms, p90 ${p1.toFixed(2)} ms; load ${loadMs.toFixed(0)} ms`)
  assert.ok(m1 <= 3 * m0 + 5, `median per append at 80k lines ${m1.toFixed(2)} ms vs ${m0.toFixed(2)} ms on a fresh job`)
  assert.ok(p1 <= 3 * p0 + 5, `p90 per append at 80k lines ${p1.toFixed(2)} ms vs ${p0.toFixed(2)} ms on a fresh job`)
  // the state is right at the end: every copy landed and read back
  const s = big.api.registry.jobState(JOB)
  assert.equal(s.count, 80_005 + 2 + 35 * 4)
  assert.equal(s.spent('eth'), BigInt((COPIES + 35) * 1000))
  assert.deepEqual(s.openIntentIds('eth'), [])
})

// jobs/<id>/trace.txt (trace-text.ts): the ASCII twin of the journal. Written when a journal is opened, then at most once
// per traceDelayMs while appends come in, at once on the operator's close / stop and on shutdown (registry.close());
// 0600; free text escaped (no forged lines, no non-ASCII); never the message text.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import type { JobDef, JournalEvent } from '@vault-timelock/core/contracts'
import { reduce } from '@vault-timelock/core/job'
import { TRACE_FILE, esc, renderTrace } from '../src/trace-text.ts'
import { JOB, JOB_INPUT, armed, call, ethIntent, ethTx, fixture, installJournal, startApi } from './helpers.ts'
import type { TestApi } from './helpers.ts'

process.env.NODE_ENV = 'test'

const traceOf = (a: TestApi, id = JOB): string => readFileSync(join(a.state, 'jobs', id, TRACE_FILE), 'latin1')
// The twin as of now (a pending throttled write is done first).
const flushed = (a: TestApi, id = JOB): string => { a.api.registry.flushTraces(); return traceOf(a, id) }
const ASCII = /^[\x20-\x7e\n]*$/

test('written at create, then from the latest state (API and executor lines), 0600, ASCII, never the message text', async (t) => {
  const a = await startApi()
  t.after(() => a.close())
  const first = traceOf(a)
  assert.equal(statSync(join(a.state, 'jobs', JOB, TRACE_FILE)).mode & 0o777, 0o600)
  assert.match(first, new RegExp(`^job ${JOB}\nname: eth drain to the null address\nnetwork: local\n`))
  assert.match(first, /\nphase: DEFINED\n/)
  assert.match(first, /\njournal seq: 0\n/)
  assert.match(first, /\nchain eth: anvil \| 31337\n  phase: AWAITING_KEY\n/)
  await armed(a, JOB, ['eth'])
  await call(a.port, { path: `/jobs/${JOB}/chains/eth/lease`, body: { op: 'acquire', holder: 'cli' } })
  assert.match(flushed(a), /\njournal seq: 4\n/)
  for (const [type, data] of [
    ['intent', ethIntent(1)], ['sent', { txId: ethTx(1), outcome: 'accepted', reason: null }],
    ['included', { txId: ethTx(1), copy: 1, part: 1, attempt: 1, block: '101', fee: '25000300000000', ms: 9 }],
  ] as const) {
    const r = await call(a.port, { path: `/jobs/${JOB}/chains/eth/events`, body: { gen: 1, type, data } })
    assert.match(flushed(a), new RegExp(`\njournal seq: ${(r.json as { seq: number }).seq}\n`))
  }
  const text = flushed(a)
  assert.match(text, /\nphase: RUNNING\n/)
  assert.match(text, new RegExp(`    copy 1 part 1/1: included; landed ${ethTx(1)}; block 101; fee 25000300000000; readback -\n      attempt ${ethTx(1)} gen 1 included \\(eth nonce 1 tip 12000 maxFee 2000012000 gas ${(ethIntent(1).eth as { gas: string }).gas} to 0x0{40}\\)\n`))
  assert.match(text, /\n  cap: 4000000000000000 base units \(planned 0\.004, usd 10, over cap no\)\n/)
  assert.ok(ASCII.test(text))
  for (const line of (JOB_INPUT.message as string).split('\n').filter((l) => l !== '')) assert.ok(!text.includes(line))
})

test('free text is escaped: a reason can neither forge a line nor bring non-ASCII into the twin', async (t) => {
  const a = await startApi()
  t.after(() => a.close())
  await armed(a, JOB, ['eth'])
  await call(a.port, { path: `/jobs/${JOB}/chains/eth/lease`, body: { op: 'acquire', holder: 'cli' } })
  await call(a.port, { path: `/jobs/${JOB}/chains/eth/events`, body: { gen: 1, type: 'intent', data: ethIntent(1) } })
  const r = await call(a.port, { path: `/jobs/${JOB}/chains/eth/events`, body: { gen: 1, type: 'paused', data: { reason: 'tip cap\nphase: DONE · é\t\\' } } })
  assert.equal(r.status, 200)
  const text = flushed(a)
  assert.ok(ASCII.test(text))
  assert.ok(text.includes('  phase: PAUSED (tip cap\\nphase: DONE \\u00b7 \\u00e9\\t\\\\)\n'))
  assert.ok(!/\nphase: DONE/.test(text))
  assert.equal(esc('a‮b\r'), 'a\\u202eb\\r')
})

test('an opened journal gets its twin; renderTrace is pure and deterministic (claw-back, attempts, schedule)', async (t) => {
  const a = await startApi({ jobs: [] })
  t.after(() => a.close())
  const { id, def, lines } = await installJournal(a, '12-clawback')
  await call(a.port, { path: `/jobs/${id}` })
  const events = lines.map((l) => JSON.parse(l) as JournalEvent)
  const want = renderTrace({ id, def, state: reduce(def, events), network: 'local' })
  assert.equal(traceOf(a, id), want)
  assert.equal(renderTrace({ id, def: fixture<JobDef>('journals/12-clawback.def.json'), state: reduce(def, events), network: 'local' }), want)
  assert.match(want, /\n  claw-back: 0x3d981fa6ba2b4c4c4fcda58588440d060bcba13d8a4de6091b66c9838c5ef1f0 to 0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6 value 1179000000000 ok\n/)
  assert.match(want, /\narmed: 2026-[0-9-]+T[0-9:.]+Z; countdown 15 s; release 2026-[0-9-]+T[0-9:.]+Z; order eth\n/)
  assert.ok(ASCII.test(want))
})

test('throttled: appends inside the window do not rewrite the twin; the timer, close / stop and shutdown do', async (t) => {
  const a = await startApi({ traceDelayMs: 2000 })
  t.after(() => a.close())
  const first = traceOf(a)
  assert.match(first, /\njournal seq: 0\n/)
  await armed(a, JOB, ['eth'])
  assert.equal(traceOf(a), first, 'no write on the appends themselves')
  await new Promise((r) => setTimeout(r, 2500))
  assert.match(traceOf(a), /\njournal seq: 3\n/) // the throttled write happened
  await call(a.port, { path: `/jobs/${JOB}/chains/eth/lease`, body: { op: 'acquire', holder: 'cli' } })
  await call(a.port, { path: `/jobs/${JOB}/chains/eth/events`, body: { gen: 1, type: 'stopped', data: { reason: 'operator' } } })
  await call(a.port, { path: `/jobs/${JOB}/close`, body: { chain: 'eth' } })
  assert.match(traceOf(a), /\njournal seq: 6\n.*\n  phase: DONE\n/s) // at once on close

  const b = await startApi({ traceDelayMs: 60_000 })
  t.after(() => b.close())
  await armed(b, JOB, ['eth'])
  assert.match(traceOf(b), /\njournal seq: 0\n/)
  b.api.registry.close() // shutdown (main.ts stop): the final flush
  assert.match(traceOf(b), /\njournal seq: 3\n/)
})

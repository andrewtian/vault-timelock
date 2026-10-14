// Funding sources and the per-text try ledger (R47; sources.ts, arm.ts, routes.ts): GET/POST /sources, the arm's
// `sources` (required once one is declared), source.unknown / exhausted / reused, tries/<messageSha256>.json written
// before the `armed` ack, and everything surviving a restart. Synthetic labels, texts and keys only.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync, writeFileSync, chmodSync, mkdirSync } from 'node:fs'
import { writeSync } from 'node:fs'
import { join } from 'node:path'
import type { ArmRecord } from '@vault-timelock/core/contracts'
import type { JournalFs } from '../src/journal.ts'
import { JOB, JOB_INPUT, armBody, call, guardOf, jobFixture, seedReady, startApi } from './helpers.ts'
import type { Reply, TestApi } from './helpers.ts'

process.env.NODE_ENV = 'test'

async function api(t: { after(fn: () => Promise<void>): void }, o: Parameters<typeof startApi>[0] = {}): Promise<TestApi> {
  const a = await startApi(o)
  t.after(() => a.close())
  return a
}
const declare = (a: TestApi, label: unknown): Promise<Reply> => call(a.port, { path: '/sources', body: { label } })
const listed = async (a: TestApi): Promise<string[]> => ((await call(a.port, { path: '/sources' })).json as { sources: Array<{ label: string }> }).sources.map((s) => s.label)
const TEXT_SHA = (a: TestApi): string => a.api.registry.get(JOB).def.messageSha256

// One more try of the same text: a new job (same message, another name), READY, armed with `sources`; a successful arm
// is then stopped and closed so the one eth key is free for the next try.
async function tryOnce(a: TestApi, n: number, sources: unknown): Promise<Reply> {
  const made = await call(a.port, { path: '/jobs', body: { ...JOB_INPUT, name: `try ${n}` } })
  assert.ok(made.status === 200 || made.status === 201, made.text)
  const id = (made.json as { id: string }).id
  await seedReady(a, id, ['eth'])
  const r = await call(a.port, { path: `/jobs/${id}/arm`, body: { ...armBody(['eth'], { countdownSec: 5 }), ...(sources === undefined ? {} : { sources }) } })
  if (r.status === 200) {
    assert.equal((await call(a.port, { path: `/jobs/${id}/stop`, body: { chain: null } })).status, 200)
    assert.equal((await call(a.port, { path: `/jobs/${id}/close`, body: { chain: 'eth' } })).status, 200)
  }
  return r
}
const triesFile = (a: TestApi): string => join(a.state, 'tries', `${TEXT_SHA(a)}.json`)

test('POST /sources: a good label → 201 (200 again, idempotent); a bad one or a bad body → 400 source.label / api.json; GET lists them; nothing deletes', async (t) => {
  const a = await api(t, { jobs: [] })
  assert.deepEqual((await call(a.port, { path: '/sources' })).json, { sources: [] })
  const first = await declare(a, 'railgun-eth')
  assert.equal(first.status, 201)
  assert.deepEqual(first.json, { label: 'railgun-eth', addedAt: a.clock.now() })
  a.clock.advance(1000)
  const again = await declare(a, 'railgun-eth')
  assert.equal(again.status, 200)
  assert.deepEqual(again.json, first.json) // the first addedAt stays
  for (const label of ['a', '0', 'a-b-c', 'x'.repeat(24)]) assert.equal((await declare(a, label)).status, 201, label)
  const bad = ['', 'A', 'Railgun', '-a', 'a_b', 'a b', 'x'.repeat(25), 'é', 'a\n', 'a.b', 5, null, ['a']]
  for (const label of bad) {
    const r = await declare(a, label)
    assert.equal(r.status, 400, JSON.stringify(label))
    assert.equal(guardOf(r), 'source.label', JSON.stringify(label))
  }
  for (const body of [{}, { label: 'ok', extra: 1 }, [], 'ok']) assert.equal(guardOf(await call(a.port, { path: '/sources', body })), 'api.json', JSON.stringify(body))
  assert.deepEqual(await listed(a), ['railgun-eth', 'a', '0', 'a-b-c', 'x'.repeat(24)])
  const file = join(a.state, 'sources.json')
  assert.equal(statSync(file).mode & 0o777, 0o600)
  for (const method of ['DELETE', 'PATCH']) assert.equal((await call(a.port, { method, path: '/sources' })).status, 404, method)
  assert.equal((await call(a.port, { method: 'DELETE', path: '/sources/railgun-eth' })).status, 404)
  assert.deepEqual(await listed(a), ['railgun-eth', 'a', '0', 'a-b-c', 'x'.repeat(24)])
})

test('at most 64 sources (they are never deleted): the 65th → source.label, a declared one still answers 200', async (t) => {
  const a = await api(t, { jobs: [] })
  for (let i = 0; i < 64; i++) assert.equal((await declare(a, `s${i}`)).status, 201)
  assert.equal(guardOf(await declare(a, 's64')), 'source.label')
  assert.equal((await declare(a, 's0')).status, 200)
  assert.equal((await listed(a)).length, 64)
})

test('the sources routes need the token and refuse a stranger like every other route', async (t) => {
  const a = await api(t, { jobs: [] })
  assert.equal(guardOf(await call(a.port, { path: '/sources', headers: { authorization: null } })), 'api.token')
  assert.equal(guardOf(await call(a.port, { path: '/sources', body: { label: 'a' }, headers: { authorization: 'Bearer 00' } })), 'api.token')
  assert.deepEqual(await listed(a), [])
})

test('no source declared: an arm without sources works (armed.sources is {}); naming one → 400 source.unknown, nothing journaled or recorded', async (t) => {
  const a = await api(t)
  await seedReady(a, JOB, ['eth'])
  const named = await call(a.port, { path: `/jobs/${JOB}/arm`, body: { ...armBody(['eth']), sources: { eth: 'ghost' } } })
  assert.equal(named.status, 400)
  assert.equal(guardOf(named), 'source.unknown')
  assert.deepEqual(a.api.registry.journalOf(JOB).all().filter((e) => e.type === 'armed'), [])
  const ok = await call(a.port, { path: `/jobs/${JOB}/arm`, body: armBody(['eth']) })
  assert.equal(ok.status, 200)
  assert.deepEqual((ok.json as { armed: ArmRecord }).armed.sources, {})
  assert.deepEqual(readdirSync(a.state).filter((f) => f === 'tries' || f === 'sources.json'), []) // no source, no ledger
})

test('once one source exists the arm needs a declared label per armed chain: missing, {}, an undeclared one → source.unknown (400); a declared one → armed.sources', async (t) => {
  const a = await api(t)
  await declare(a, 'pool-a')
  await seedReady(a, JOB, ['eth'])
  for (const sources of [undefined, {}, { eth: 'pool-b' }, { eth: 'POOL-A' }]) {
    const r = await call(a.port, { path: `/jobs/${JOB}/arm`, body: { ...armBody(['eth']), ...(sources === undefined ? {} : { sources }) } })
    assert.equal(r.status, 400, JSON.stringify(sources))
    assert.equal(guardOf(r), 'source.unknown', JSON.stringify(sources))
  }
  assert.deepEqual(a.api.registry.journalOf(JOB).all().filter((e) => e.type === 'armed'), [])
  assert.throws(() => readFileSync(triesFile(a)), { code: 'ENOENT' }) // a refused arm leaves no try
  const ok = await call(a.port, { path: `/jobs/${JOB}/arm`, body: { ...armBody(['eth']), sources: { eth: 'pool-a' } } })
  assert.equal(ok.status, 200)
  assert.deepEqual((ok.json as { armed: ArmRecord }).armed.sources, { eth: 'pool-a' })
  const journaled = a.api.registry.journalOf(JOB).all().find((e) => e.type === 'armed')!
  assert.deepEqual((journaled.data as unknown as ArmRecord).sources, { eth: 'pool-a' })
})

test('three labels, three tries of one text, the fourth → 409 source.exhausted; a label reused → 409 source.reused; each try is on record', async (t) => {
  const a = await api(t)
  for (const l of ['pool-a', 'pool-b', 'pool-c']) await declare(a, l)
  assert.equal((await tryOnce(a, 1, { eth: 'pool-a' })).status, 200)
  const reused = await tryOnce(a, 2, { eth: 'pool-a' })
  assert.equal(reused.status, 409)
  assert.equal(guardOf(reused), 'source.reused')
  assert.equal((await tryOnce(a, 3, { eth: 'pool-b' })).status, 200)
  assert.equal(guardOf(await tryOnce(a, 4, { eth: 'pool-b' })), 'source.reused')
  assert.equal((await tryOnce(a, 5, { eth: 'pool-c' })).status, 200)
  for (const label of ['pool-a', 'pool-b', 'pool-c']) {
    const r = await tryOnce(a, 6, { eth: label })
    assert.equal(r.status, 409, label)
    assert.equal(guardOf(r), 'source.exhausted', label) // nothing unused is left, whatever label is named
  }
  const ledger = JSON.parse(readFileSync(triesFile(a), 'utf8')) as { format: string; messageSha256: string; tries: Array<{ jobId: string; sources: Record<string, string> }> }
  assert.equal(ledger.format, 'vt-tries/1')
  assert.equal(ledger.messageSha256, TEXT_SHA(a))
  assert.deepEqual(ledger.tries.map((x) => x.sources), [{ eth: 'pool-a' }, { eth: 'pool-b' }, { eth: 'pool-c' }])
  assert.equal(new Set(ledger.tries.map((x) => x.jobId)).size, 3)
  assert.equal(statSync(triesFile(a)).mode & 0o777, 0o600)
  assert.equal(statSync(join(a.state, 'tries')).mode & 0o777, 0o700)
  // a newly declared source makes room again, for this text
  await declare(a, 'pool-d')
  assert.equal((await tryOnce(a, 7, { eth: 'pool-d' })).status, 200)
})

test('another text has its own ledger: the same labels fund it again', async (t) => {
  const a = await api(t, { jobs: [] })
  await declare(a, 'pool-a')
  assert.equal((await tryOnce(a, 1, { eth: 'pool-a' })).status, 200)
  assert.equal(guardOf(await tryOnce(a, 2, { eth: 'pool-a' })), 'source.exhausted')
  const other = await call(a.port, { path: '/jobs', body: { ...JOB_INPUT, name: 'other text', message: 'A different synthetic message.\n' } })
  const id = (other.json as { id: string }).id
  await seedReady(a, id, ['eth'])
  assert.equal((await call(a.port, { path: `/jobs/${id}/arm`, body: { ...armBody(['eth']), sources: { eth: 'pool-a' } } })).status, 200)
  assert.equal(readdirSync(join(a.state, 'tries')).length, 2)
})

test('two chains of one try may share a label; the ledger lists both', async (t) => {
  const a = await api(t, { jobs: [] })
  await declare(a, 'pool-a')
  const made = await call(a.port, { path: '/jobs', body: jobFixture('defaults') })
  const id = (made.json as { id: string }).id
  await seedReady(a, id, ['eth', 'sol'])
  const body = armBody(['eth', 'sol'], { countdownSec: 5, stagger: [5, 10] })
  assert.equal(guardOf(await call(a.port, { path: `/jobs/${id}/arm`, body: { ...body, sources: { eth: 'pool-a' } } })), 'source.unknown') // sol has none
  const ok = await call(a.port, { path: `/jobs/${id}/arm`, body: { ...body, sources: { eth: 'pool-a', sol: 'pool-a' } } })
  assert.equal(ok.status, 200, ok.text)
  assert.deepEqual((ok.json as { armed: ArmRecord }).armed.sources, { eth: 'pool-a', sol: 'pool-a' })
})

test('the try is on disk BEFORE the `armed` ack: an arm whose journal write fails still spent its source', async (t) => {
  let fail = false
  const fs: JournalFs = {
    writeSync: (fd, buf, off, len) => { if (fail) throw new Error('disk full (synthetic)'); return writeSync(fd, buf, off, len) },
    fsyncSync: (fd) => { if (fail) throw new Error('disk full (synthetic)') },
    ftruncateSync: () => {},
  }
  const a = await api(t, { fs: { ...fs, fsyncSync: (fd) => (fail ? fs.fsyncSync(fd) : void 0) } })
  await declare(a, 'pool-a')
  await declare(a, 'pool-b')
  await seedReady(a, JOB, ['eth'])
  fail = true
  const r = await call(a.port, { path: `/jobs/${JOB}/arm`, body: { ...armBody(['eth']), sources: { eth: 'pool-a' } } })
  fail = false
  assert.ok(r.status >= 500, r.text) // nothing acked
  assert.deepEqual(a.api.registry.journalOf(JOB).all().filter((e) => e.type === 'armed'), [])
  const ledger = JSON.parse(readFileSync(triesFile(a), 'utf8')) as { tries: Array<{ jobId: string; sources: unknown }> }
  assert.deepEqual(ledger.tries, [{ jobId: JOB, at: a.clock.now(), sources: { eth: 'pool-a' } }])
})

test('sources and tries persist across a restart: the same labels, a spent label still reused, the exhausted state still exhausted', async (t) => {
  const a = await startApi({})
  await declare(a, 'pool-a')
  await declare(a, 'pool-b')
  assert.equal((await tryOnce(a, 1, { eth: 'pool-a' })).status, 200)
  await a.close(true)
  const b = await startApi({ reuse: a, jobs: [] })
  t.after(() => b.close())
  assert.deepEqual(await listed(b), ['pool-a', 'pool-b'])
  assert.equal(guardOf(await tryOnce(b, 2, { eth: 'pool-a' })), 'source.reused')
  assert.equal((await tryOnce(b, 3, { eth: 'pool-b' })).status, 200)
  await b.close(true)
  const c = await startApi({ reuse: b, jobs: [] })
  t.after(() => c.close())
  assert.equal(guardOf(await tryOnce(c, 4, { eth: 'pool-a' })), 'source.exhausted')
  assert.equal((await declare(c, 'pool-b')).status, 200) // still declared, never deleted
})

test('a job that armed before the crash of its own journal write may arm again: its own entry is replaced, never counted as an earlier try', async (t) => {
  const a = await api(t)
  await declare(a, 'pool-a')
  await declare(a, 'pool-b')
  await seedReady(a, JOB, ['eth'])
  // the ledger as a crash after the try was written and before `armed` was journaled would leave it
  mkdirSync(join(a.state, 'tries'), { mode: 0o700, recursive: true })
  const file = triesFile(a)
  writeFileSync(file, JSON.stringify({ format: 'vt-tries/1', messageSha256: TEXT_SHA(a), tries: [{ jobId: JOB, at: 1, sources: { eth: 'pool-a' } }] }) + '\n', { mode: 0o600 })
  const r = await call(a.port, { path: `/jobs/${JOB}/arm`, body: { ...armBody(['eth']), sources: { eth: 'pool-b' } } })
  assert.equal(r.status, 200, r.text)
  const ledger = JSON.parse(readFileSync(file, 'utf8')) as { tries: Array<{ jobId: string; sources: unknown }> }
  assert.deepEqual(ledger.tries.map((x) => [x.jobId, x.sources]), [[JOB, { eth: 'pool-b' }]])
})

test('a damaged state file is never used: sources.json or a ledger that is malformed, group-readable or not a regular file → 500 api.internal, nothing armed', async (t) => {
  const a = await api(t)
  await declare(a, 'pool-a')
  await seedReady(a, JOB, ['eth'])
  const arm = (): Promise<Reply> => call(a.port, { path: `/jobs/${JOB}/arm`, body: { ...armBody(['eth']), sources: { eth: 'pool-a' } } })
  const tries = join(a.state, 'tries')
  mkdirSync(tries, { mode: 0o700, recursive: true })
  const ledger = triesFile(a)
  for (const bad of ['{', JSON.stringify({ format: 'vt-tries/1', messageSha256: '0'.repeat(64), tries: [] }), JSON.stringify({ format: 'vt-tries/1', messageSha256: TEXT_SHA(a), tries: [{ jobId: 'x', at: 1, sources: {} }] })]) {
    writeFileSync(ledger, bad, { mode: 0o600 })
    const r = await arm()
    assert.equal(r.status, 500, bad)
    assert.equal(guardOf(r), 'api.internal')
  }
  writeFileSync(ledger, JSON.stringify({ format: 'vt-tries/1', messageSha256: TEXT_SHA(a), tries: [] }), { mode: 0o600 })
  chmodSync(ledger, 0o640)
  assert.equal(guardOf(await arm()), 'api.internal')
  chmodSync(ledger, 0o600)
  const file = join(a.state, 'sources.json')
  for (const bad of ['{', '[]', JSON.stringify({ format: 'vt-sources/1', sources: [{ label: 'Bad', addedAt: 1 }] }), JSON.stringify({ format: 'vt-sources/1', sources: [{ label: 'a', addedAt: 1 }, { label: 'a', addedAt: 2 }] })]) {
    writeFileSync(file, bad, { mode: 0o600 })
    assert.equal(guardOf(await call(a.port, { path: '/sources' })), 'api.internal', bad)
    assert.equal(guardOf(await arm()), 'api.internal', bad)
  }
  chmodSync(file, 0o644)
  assert.equal(guardOf(await call(a.port, { path: '/sources' })), 'api.internal')
  assert.deepEqual(a.api.registry.journalOf(JOB).all().filter((e) => e.type === 'armed'), [])
})

test('GET /sources/tries/<messageSha256> → { labelsUsed }: the labels that paid an earlier try of that text, sorted, once each; labels only; durable across a restart (S5 / Wfix3)', async (t) => {
  const a = await startApi({})
  let aOpen = true
  t.after(async () => { if (aOpen) await a.close() })                                    // a failing assertion must not leave the server listening
  const sha = TEXT_SHA(a)
  const tries = (x: TestApi, d: string = sha): Promise<Reply> => call(x.port, { path: `/sources/tries/${d}` })
  assert.deepEqual([(await tries(a)).status, (await tries(a)).json], [200, { labelsUsed: [] }], 'a text never armed')
  for (const l of ['pool-c', 'pool-a', 'pool-b']) await declare(a, l)
  assert.deepEqual((await tries(a)).json, { labelsUsed: [] }, 'declared is not used')
  assert.equal((await tryOnce(a, 1, { eth: 'pool-c' })).status, 200)
  assert.equal(guardOf(await tryOnce(a, 2, { eth: 'pool-c' })), 'source.reused')
  assert.equal((await tryOnce(a, 3, { eth: 'pool-a' })).status, 200)
  const r = await tries(a)
  assert.deepEqual([r.status, r.json], [200, { labelsUsed: ['pool-a', 'pool-c'] }])
  // labels only: nothing of the jobs, their time or their chains
  assert.deepEqual(Object.keys(r.json as object), ['labelsUsed'])
  const ledger = JSON.parse(readFileSync(triesFile(a), 'utf8')) as { tries: Array<{ jobId: string }> }
  for (const j of ledger.tries) assert.ok(!r.text.includes(j.jobId))
  // another text has its own ledger
  assert.deepEqual((await tries(a, 'ab'.repeat(32))).json, { labelsUsed: [] })
  // a failed arm that still spent its source (the try is on record) shows too
  assert.equal((await tryOnce(a, 4, { eth: 'pool-b' })).status, 200)
  assert.deepEqual((await tries(a)).json, { labelsUsed: ['pool-a', 'pool-b', 'pool-c'] })
  // bad digests are no route; the token is needed; GET only
  for (const bad of ['', 'AB'.repeat(32), 'ab'.repeat(31), 'ab'.repeat(33), '..%2f', `${sha}/x`]) assert.equal(guardOf(await tries(a, bad)), 'api.route', bad)
  assert.equal(guardOf(await call(a.port, { path: `/sources/tries/${sha}`, headers: { authorization: null } })), 'api.token')
  assert.equal(guardOf(await call(a.port, { path: `/sources/tries/${sha}`, body: {} })), 'api.route')
  // durable: a restart reads the same
  aOpen = false
  await a.close(true)
  const b = await startApi({ reuse: a, jobs: [] })
  t.after(() => b.close())
  assert.deepEqual((await tries(b)).json, { labelsUsed: ['pool-a', 'pool-b', 'pool-c'] })
  // a damaged ledger is never read as "nothing used": 500 api.internal
  const file = join(b.state, 'tries', `${sha}.json`)
  writeFileSync(file, '{', { mode: 0o600 })
  assert.deepEqual([(await tries(b)).status, guardOf(await tries(b))], [500, 'api.internal'])
  writeFileSync(file, JSON.stringify({ format: 'vt-tries/1', messageSha256: sha, tries: [] }), { mode: 0o600 })
  chmodSync(file, 0o644)
  assert.equal(guardOf(await tries(b)), 'api.internal')
})

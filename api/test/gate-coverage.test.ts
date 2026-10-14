// Gate coverage (security review): every route and handler that appends to a journal or mints a send ticket passes ONE
// shared function, jobs.ts gate(), before the fsync / before minting.
//   · static: in api/src the raw journal is appended in exactly one place, right after `await gate(`; a ticket is minted
//     in exactly one place, right after `await gate(`; only jobs.ts opens journals or mints tickets (index.ts only
//     re-exports); routes.ts, arm.ts and leases.ts hold neither a raw journal nor the ticket key;
//   · dynamic: the route table is walked; every route runs once with a request that succeeds; a route whose request
//     appended a journal line or returned a ticket must have run the gate, and must be marked mutating — and every route
//     marked mutating must have done so. A route missing from the recipes fails the test.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { request } from 'node:http'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { JOB, JOB_INPUT, KEYS, idOf, jobFixture, TOKEN, armBody, call, ethIntent, ethTx, seedReady, startApi } from './helpers.ts'
import type { Reply, TestApi } from './helpers.ts'

process.env.NODE_ENV = 'test'

const SRC = fileURLToPath(new URL('../src/', import.meta.url))
const sources = (): Map<string, string> => new Map(readdirSync(SRC).filter((f) => f.endsWith('.ts')).map((f) => [f, readFileSync(join(SRC, f), 'utf8')]))
const count = (s: string, needle: string): number => s.split(needle).length - 1

test('static: one raw append and one ticket mint in api/src, each right behind `await gate(`; nobody else opens journals or mints', () => {
  const src = sources()
  const total = (needle: string): number => [...src.values()].reduce((n, s) => n + count(s, needle), 0)
  assert.equal(total('raw.append('), 1)
  assert.equal(total('issueTicket('), 2) // its definition (tickets.ts) and the one call (jobs.ts)
  assert.equal(count(src.get('tickets.ts')!, 'export function issueTicket('), 1)
  const jobs = src.get('jobs.ts')!
  const append = jobs.slice(jobs.indexOf('async append(e, o?: AppendOptions) {'), jobs.indexOf('raw.append('))
  assert.match(append, /^async append\(e, o\?: AppendOptions\) \{\s*await gate\(l, \{ append: e, confirm: o\?\.clawbackConfirm \}\)\s*const ev = await $/)
  const mint = jobs.slice(jobs.indexOf('async ticket(job, chain, gen, txId) {'), jobs.indexOf('issueTicket(o.ticketKey'))
  assert.match(mint, /^async ticket\(job, chain, gen, txId\) \{\s*const intent = await gate\(loadedOf\(job\), \{ ticket: \{ chain, txId \} \}\)\s*return $/)
  for (const [file, s] of src) {
    if (file === 'jobs.ts' || file === 'journal.ts') continue
    assert.ok(!/openJournal\(/.test(s), `${file} opens a journal`)
    if (file !== 'tickets.ts' && file !== 'index.ts') assert.ok(!/issueTicket/.test(s), `${file} reaches the ticket minter`)
  }
  for (const file of ['routes.ts', 'arm.ts', 'leases.ts', 'main.ts']) {
    assert.ok(!/ticketKey\s*[,)]|\.ticketKey/.test(src.get(file)!.replace(/createRegistry\(\{[^}]*\}\)/g, '')), `${file} handles the ticket key`)
  }
})

// A stream request: resolves with the status as soon as the headers arrive, then closes the stream.
function opened(port: number, path: string): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, setHost: false, headers: { host: '127.0.0.1:5182', authorization: `Bearer ${TOKEN}` } }, (res) => {
      resolve({ status: res.statusCode ?? 0, headers: res.headers, text: '', json: null })
      req.destroy()
    })
    req.on('error', (e) => { if ((e as NodeJS.ErrnoException).code !== 'ECONNRESET') reject(e) })
    req.end()
  })
}

test('dynamic: every route of the table, once — a journal line or a ticket only ever comes through the gate', async (t) => {
  const a: TestApi = await startApi({ jobs: [JOB_INPUT], privacyCash: { capLamports: 10n ** 10n } })
  t.after(() => a.close())
  const p = (path: string, body: unknown) => call(a.port, { path, body })
  const text = 'A second synthetic message.\n'
  const sha = createHash('sha256').update(text).digest('hex')
  const ev = (type: string, data: unknown) => p(`/jobs/${JOB}/chains/eth/events`, { gen: 1, type, data })
  // Each recipe: optional unmeasured preparation, then the one measured request.
  const recipes: Record<string, { prepare?: () => Promise<unknown>; run: () => Promise<Reply> }> = {
    status: { run: () => call(a.port, { path: '/status' }) },
    'jobs-list': { run: () => call(a.port, { path: '/jobs' }) },
    job: { run: () => call(a.port, { path: `/jobs/${JOB}` }) },
    receipt: { run: () => call(a.port, { path: `/jobs/${JOB}/receipt` }) },
    stream: { run: () => opened(a.port, `/jobs/${JOB}/events`) },
    // Sfix-PC: the mint reserves in its own ledger and signs; it neither appends a journal line nor mints a send ticket
    'privacycash-lane': { prepare: () => p('/jobs', jobFixture('sol-copies')), run: () => p(`/jobs/${idOf(jobFixture('sol-copies'))}/privacycash/lane`, { bodySha256: 'ab'.repeat(32), allowanceLamports: '1000000', tryIndex: 0 }) },
    'message-put': { run: () => call(a.port, { method: 'PUT', path: `/messages/${sha}`, raw: text, headers: { 'content-type': 'text/plain; charset=utf-8' } }) },
    'message-get': { run: () => call(a.port, { path: `/messages/${sha}` }) },
    'sources-list': { run: () => call(a.port, { path: '/sources' }) },
    'sources-tries': { run: () => call(a.port, { path: `/sources/tries/${sha}` }) },
    'sources-add': { run: () => p('/sources', { label: 'coverage' }) },
    'jobs-create': { run: () => p('/jobs', { ...JOB_INPUT, name: 'coverage' }) },
    lease: { run: () => p(`/jobs/${JOB}/chains/eth/lease`, { op: 'acquire', holder: 'cli' }) },
    'events-append': { run: () => ev('key-loaded', { address: KEYS.eth }) },
    arm: { prepare: () => seedReady(a, JOB, ['eth']), run: () => p(`/jobs/${JOB}/arm`, armBody(['eth'], { countdownSec: 30 })) },
    skip: { run: () => p(`/jobs/${JOB}/skip`, {}) },
    tickets: { prepare: () => ev('intent', ethIntent(1)), run: () => p(`/jobs/${JOB}/chains/eth/tickets`, { gen: 1, txId: ethTx(1) }) },
    stop: { run: () => p(`/jobs/${JOB}/stop`, { chain: 'eth' }) },
    resume: { run: () => p(`/jobs/${JOB}/resume`, { chain: 'eth' }) },
    resolve: { prepare: () => ev('stuck', { txId: ethTx(1), reason: 'x' }), run: () => p(`/jobs/${JOB}/chains/eth/resolve`, { txId: ethTx(1), action: 'mark-done' }) },
    close: { prepare: () => ev('drained', { balance: '1', nextCost: '2', copy: 2 }), run: () => p(`/jobs/${JOB}/close`, { chain: 'eth' }) },
  }
  const order = ['status', 'jobs-list', 'job', 'receipt', 'privacycash-lane', 'stream', 'message-put', 'message-get', 'jobs-create', 'lease', 'events-append', 'arm', 'skip', 'tickets', 'stop', 'resume', 'resolve', 'close', 'sources-list', 'sources-tries', 'sources-add'] // the sources last: once one is declared, an arm needs it
  assert.deepEqual([...order].sort(), a.api.routes.map((r) => r.name).sort(), 'a recipe for every route of the table')
  assert.deepEqual(Object.keys(recipes).sort(), [...order].sort())
  const lines = async (): Promise<number> => (await a.api.registry.list()).reduce((n, j) => n + j.journal.all().length, 0)
  for (const name of order) {
    const route = a.api.routes.find((r) => r.name === name)!
    const recipe = recipes[name]
    if (recipe.prepare !== undefined) await recipe.prepare()
    const [l0, g0] = [await lines(), a.api.registry.gates()]
    const r = await recipe.run()
    assert.ok(r.status >= 200 && r.status < 300, `${name}: ${r.status} ${r.text}`)
    const [l1, g1] = [await lines(), a.api.registry.gates()]
    const minted = typeof (r.json as { ticket?: unknown } | null)?.ticket === 'string'
    const mutated = l1 > l0 || minted
    if (mutated) assert.ok(g1 > g0, `${name} appended or minted without the gate`)
    assert.equal(mutated, route.mutating, `${name}: mutating is ${route.mutating}, the request ${mutated ? 'mutated' : 'did not mutate'}`)
  }
})

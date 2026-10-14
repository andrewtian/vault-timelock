// The contract HTTP vectors (every contract/fixtures/http/*.json) against the real handler: auth, host, origin, fetch
// site, body cap, content type, status, jobs (create 201 → 200, 400, get 200 / 404), messages, arm, lease, events
// append, the SSE stream, and leases.json end to end over HTTP. Each fixture's request is sent as written ({{token}},
// {{host}} = 127.0.0.1:<the API port>, {{port}}); status, content type and body must match, except the fixture's
// `volatile` fields. A fixture's `after` names the vector that must be served first.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { request } from 'node:http'
import { join } from 'node:path'
import { sseFrame } from '@vault-timelock/core/contracts'
import type { ArmRecord, Chain, Holder } from '@vault-timelock/core/contracts'
import { JOURNAL_FILE } from '../src/journal.ts'
import { verifyTicket } from '../src/tickets.ts'
import { FIXTURES, JOB, START, TICKET_KEY, TOKEN, armBody, armed, call, fakeClock, fixture, installJournal, seedReady, startApi } from './helpers.ts'
import type { Reply, TestApi } from './helpers.ts'

// CC-3: tickets bind the job key (`a`): the stored definition's keyAddress (jobs/valid/eth-drain-null.json, the job of the
// http and leases fixtures).
const JOB_KEY = (fixture<{ chains: { eth: { keyAddress: string } } }>('jobs/valid/eth-drain-null.json')).chains.eth.keyAddress

interface HttpFixture {
  name: string; after: string | null; volatile: string[]
  request: { method: string; path: string; headers: Record<string, string | null>; body?: unknown; bodyText?: string; bodyFill?: { char: string; length: number } }
  response: { status: number; headers: Record<string, string>; body?: unknown; sse?: { journal: string } }
}
const ALL = new Map(readdirSync(join(FIXTURES, 'http')).filter((f) => f.endsWith('.json'))
  .map((f) => JSON.parse(readFileSync(join(FIXTURES, 'http', f), 'utf8')) as HttpFixture).map((f) => [f.name, f]))
const COVERED = new Set<string>()
const F = (name: string): HttpFixture => {
  const f = ALL.get(name)
  assert.ok(f !== undefined, name)
  COVERED.add(name)
  return f
}
const sub = (v: string): string => v.replaceAll('{{token}}', TOKEN).replaceAll('{{host}}', '127.0.0.1:5182').replaceAll('{{port}}', '5182')

function send(port: number, f: HttpFixture): Promise<Reply> {
  const headers: Record<string, string | null> = { authorization: null, host: null }
  for (const [k, v] of Object.entries(f.request.headers)) headers[k] = v === null ? null : sub(v)
  const r = f.request
  const raw = r.body !== undefined ? JSON.stringify(r.body) : r.bodyText !== undefined ? r.bodyText : r.bodyFill !== undefined ? r.bodyFill.char.repeat(r.bodyFill.length) : undefined
  if (raw !== undefined) headers['content-length'] = String(Buffer.byteLength(raw))
  return call(port, { method: r.method, path: r.path, headers, ...(raw !== undefined ? { raw } : {}) })
}
function without(v: unknown, paths: readonly string[]): unknown {
  const copy = JSON.parse(JSON.stringify(v)) as Record<string, unknown>
  for (const p of paths) {
    const keys = p.split('.')
    let o: Record<string, unknown> | undefined = copy
    for (const k of keys.slice(0, -1)) o = o?.[k] as Record<string, unknown> | undefined
    if (o !== undefined) delete o[keys.at(-1)!]
  }
  return copy
}
function matches(f: HttpFixture, r: Reply): void {
  assert.equal(r.status, f.response.status, `${f.name}: ${r.text.slice(0, 200)}`)
  for (const [k, v] of Object.entries(f.response.headers)) assert.equal(r.headers[k], v, `${f.name}: ${k}`)
  assert.deepEqual(without(r.json, f.volatile), without(f.response.body, f.volatile), f.name)
  assert.deepEqual(Object.keys(r.json as object).sort(), Object.keys(f.response.body as object).sort(), `${f.name}: the same fields`)
}
async function api(t: { after(fn: () => Promise<void>): void }, o: Parameters<typeof startApi>[0] = {}): Promise<TestApi> {
  const a = await startApi(o)
  t.after(() => a.close())
  return a
}

test('auth, host, origin, fetch site, body cap, content type', async (t) => {
  const a = await api(t)
  for (const n of ['status-401-token-missing', 'status-401-token-wrong', 'status-403-host', 'status-403-origin', 'status-403-fetch-site', 'jobs-create-413', 'jobs-create-415']) {
    const f = F(n)
    assert.equal(f.after, null)
    matches(f, await send(a.port, f))
  }
})

// M2 FLIP (applied, operator R78): this build answers jobSends 'ENABLED' (MAINNET_JOB_SENDS_ENABLED lifted); the vector's LOCKED stays a valid
// example of the shape (the contract allows both), so only that member of the expected body differs. mainnetSends stays LOCKED.
test('status-200: the network names, mainnet sends LOCKED, mainnet job sends ENABLED (the M2 flip), the legacy latch clear', async (t) => {
  const a = await api(t)
  const f = F('status-200')
  assert.equal((f.response.body as { jobSends: string }).jobSends, 'LOCKED')
  const flipped: HttpFixture = { ...f, response: { ...f.response, body: { ...(f.response.body as object), jobSends: 'ENABLED' } } }
  const r = await send(a.port, f)
  matches(flipped, r)
  assert.equal((r.json as { mainnetSends: string }).mainnetSends, 'LOCKED')
})

test('jobs-create-201, then jobs-create-200 (the identical definition: the existing job); jobs-create-400', async (t) => {
  const a = await api(t, { jobs: [] })
  const first = F('jobs-create-201'), again = F('jobs-create-200'), bad = F('jobs-create-400')
  assert.equal(again.after, first.name)
  matches(bad, await send(a.port, bad))
  matches(first, await send(a.port, first))
  matches(again, await send(a.port, again))
  matches(again, await send(a.port, again))
})

test('jobs-get-200 and jobs-get-404', async (t) => {
  const a = await api(t)
  matches(F('jobs-get-200'), await send(a.port, F('jobs-get-200')))
  matches(F('jobs-get-404'), await send(a.port, F('jobs-get-404')))
})

test('messages-put-201: the message stored by digest, then served back byte for byte', async (t) => {
  const a = await api(t, { jobs: [] })
  const f = F('messages-put-201')
  matches(f, await send(a.port, f))
  matches(f, await send(a.port, f)) // idempotent
  const back = await call(a.port, { path: f.request.path })
  assert.equal(back.status, 200)
  assert.equal(back.headers['content-type'], 'text/plain; charset=utf-8')
  assert.equal(back.text, f.request.bodyText)
})

test('arm-200-local: { armed: ArmRecord } with releaseAt = armedAt + countdown, the job READY beforehand', async (t) => {
  const a = await api(t)
  await seedReady(a, JOB, ['eth'])
  const f = F('arm-200-local')
  const r = await send(a.port, f)
  matches(f, r)
  const rec = (r.json as { armed: ArmRecord }).armed
  assert.equal(rec.armedAt, a.clock.now())
  assert.equal(rec.releaseAt, rec.armedAt + 15_000)
})

test('lease-acquire-200, then lease-acquire-409-held', async (t) => {
  const a = await api(t)
  const first = F('lease-acquire-200'), second = F('lease-acquire-409-held')
  assert.equal(second.after, first.name)
  matches(first, await send(a.port, first))
  matches(second, await send(a.port, second))
})

test('events-append-intent-200: { seq, ticket } under the live gen of an armed job; the ticket binds the intent', async (t) => {
  const a = await api(t)
  await armed(a, JOB, ['eth'])
  const f = F('events-append-intent-200')
  await call(a.port, { path: `/jobs/${JOB}/chains/eth/lease`, body: { op: 'acquire', holder: 'browser' } })
  const r = await send(a.port, f)
  matches(f, r)
  // The fixture's example ticket (volatile) binds the same j, w, c, g, t and r (CC-1); a real one also has e and n.
  const want = verifyTicket(TICKET_KEY, (f.response.body as { ticket: string }).ticket, 0)
  const got = verifyTicket(TICKET_KEY, (r.json as { ticket: string }).ticket, a.clock.now())
  const rawSha256 = (f.request.body as { data: { rawSha256: string } }).data.rawSha256
  assert.deepEqual({ ...got, e: 0, n: '' }, { ...want, r: rawSha256, e: 0, n: '' })
  assert.equal(got.e, a.clock.now() + 120_000)
})

test('stream-05a: the contract journal streams line for line', async (t) => {
  const a = await api(t, { jobs: [] })
  const f = F('stream-05a')
  const { lines } = await installJournal(a, /^journals\/(.+)\.jsonl$/.exec(f.response.sse!.journal)![1])
  const text = await new Promise<{ status: number; type: string | undefined; body: string }>((resolve, reject) => {
    let body = ''
    const req = request({ host: '127.0.0.1', port: a.port, path: f.request.path, setHost: false,
      headers: { host: '127.0.0.1:5182', authorization: `Bearer ${TOKEN}` } }, (res) => {
      res.setEncoding('utf8')
      res.on('data', (c: string) => {
        body += c
        if (body.length >= lines.map((l, i) => sseFrame(i, l)).join('').length) { req.destroy(); resolve({ status: res.statusCode ?? 0, type: res.headers['content-type'], body }) }
      })
      res.on('error', () => {})
    })
    req.on('error', (e) => { if ((e as NodeJS.ErrnoException).code !== 'ECONNRESET') reject(e) })
    req.end()
  })
  assert.equal(text.status, f.response.status)
  assert.equal(text.type, f.response.headers['content-type'])
  assert.equal(text.body, lines.map((l, i) => sseFrame(i, l)).join(''))
})

interface Step { at: number; op: 'acquire' | 'renew' | 'append'; holder?: Holder; gen?: number; type?: string; data?: Record<string, unknown>; expect: { grant?: unknown; guard?: string; ok?: boolean; ticket?: boolean } }
const V = fixture<{ jobId: string; chain: Chain; start: number; steps: Step[]; journalAfter: Array<[string, number | null]> }>('leases.json')

test('leases.json over HTTP: every step, the 409 events vectors at their steps, and the journal timeline', async (t) => {
  assert.equal(V.start, START)
  // "the job exists (created at seq 0) and is ARMED with eth READY": created, READY and armed a minute before the start,
  // with no lease generation used.
  const clock = fakeClock(V.start - 60_000)
  const a = await api(t, { clock })
  assert.equal(a.ids[0], V.jobId)
  await seedReady(a, V.jobId, [V.chain as 'eth'])
  assert.equal((await call(a.port, { path: `/jobs/${V.jobId}/arm`, body: armBody(['eth'], { countdownSec: 5 }) })).status, 200)
  const stale = F('events-append-409-stale'), early = F('events-append-409-reconcile-first')
  let matchedVectors = 0
  for (const s of V.steps) {
    clock.set(V.start + s.at)
    const label = `${s.op} at +${s.at}`
    const r = s.op === 'append'
      ? await call(a.port, { path: `/jobs/${V.jobId}/chains/${V.chain}/events`, body: { gen: s.gen, type: s.type, data: s.data } })
      : await call(a.port, { path: `/jobs/${V.jobId}/chains/${V.chain}/lease`, body: s.op === 'acquire' ? { op: 'acquire', holder: s.holder } : { op: 'renew', holder: 'cli', gen: s.gen } })
    if (s.expect.guard !== undefined) {
      assert.equal((r.json as { error: { guard: string } }).error.guard, s.expect.guard, label)
      assert.equal(r.status, 409, label)
      for (const f of [stale, early]) {
        if (JSON.stringify(f.request.body) === JSON.stringify({ gen: s.gen, type: s.type, data: s.data })) {
          matches(f, r)
          matchedVectors++
        }
      }
    } else if (s.expect.grant !== undefined) {
      assert.equal(r.status, 200, label)
      assert.deepEqual(r.json, s.expect.grant, label)
    } else {
      assert.equal(r.status, 200, `${label}: ${r.text}`)
      const body = r.json as { seq: number; ticket?: string }
      assert.equal(typeof body.seq, 'number', label)
      assert.equal('ticket' in body, s.expect.ticket === true, label)
      if (body.ticket !== undefined) {
        const p = verifyTicket(TICKET_KEY, body.ticket, clock.now())
        assert.deepEqual([p.j, p.w, p.c, p.g, p.t, p.r, p.e], [V.jobId, 'local', V.chain, s.gen, s.data!.txId, s.data!.rawSha256, clock.now() + 120_000], label)
        // ticket v2 (CC-3/CC-3a): the job definition's key, the payload, f = gas × maxFee (the cap's reservation), q = nonce
        const eth = s.data!.eth as { gas: string; maxFee: string; nonce: number }
        assert.deepEqual([p.a, p.k, p.p, p.to, p.value, p.f, p.q], [JOB_KEY.toLowerCase(), 'job', s.data!.payloadSha256, '0x0000000000000000000000000000000000000000' /* PF-S I-1: eth.calldata.null */, null, String(BigInt(eth.gas) * BigInt(eth.maxFee)), String(eth.nonce)], label)
      }
    }
  }
  assert.equal(matchedVectors, 2)
  const lines = readFileSync(join(a.state, 'jobs', V.jobId, JOURNAL_FILE), 'utf8').split('\n').slice(0, -1).map((l) => JSON.parse(l) as { type: string; gen: number | null })
  assert.deepEqual(lines.slice(1, 4).map((e) => e.type), ['key-loaded', 'funds', 'armed']) // the setup
  assert.deepEqual([lines[0], ...lines.slice(4)].map((e) => [e.type, e.gen]), V.journalAfter)
})

test('every http/*.json vector is covered by this file', () => {
  assert.deepEqual([...COVERED].sort(), [...ALL.keys()].sort())
})

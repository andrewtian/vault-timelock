// The job service (jobs.ts) over HTTP and directly: create (every valid fixture 201 then 200, every invalid fixture its
// guard, job.network, message.missing), GET /jobs and /jobs/:id (state = reduce over the journal; job.missing), the
// stored record re-checked on load, lazy journal opening (nothing before the first request), validated appends, and
// one active job per (chain, key).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { chmodSync, existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { JobState, JournalEvent } from '@vault-timelock/core/contracts'
import { reduce } from '@vault-timelock/core/job'
import { createStore } from 'vt-broadcast/src/lifecycle/store.ts'
import { createRegistry } from '../src/jobs.ts'
import { JOURNAL_FILE } from '../src/journal.ts'
import {
  FIXTURES, JOB, JOB2, JOB2_INPUT, JOB_INPUT, KEYS, TICKET_KEY, armBody, armed, call, ethIntent, fakeClock, fixture, guardOf, idOf, installJournal, onNetwork, seedReady, startApi,
} from './helpers.ts'
import type { TestApi } from './helpers.ts'

process.env.NODE_ENV = 'test'

async function api(t: { after(fn: () => Promise<void>): void }, o: Parameters<typeof startApi>[0] = {}): Promise<TestApi> {
  const a = await startApi(o)
  t.after(() => a.close())
  return a
}
const post = (a: TestApi, body: unknown, network: 'local' | 'testnet' | 'mainnet' = 'local') => call(a.port, { path: '/jobs', body, network })
const VALID = fixture<Record<string, { id: string; def: unknown }>>('jobs/valid/expected.json')
const INVALID = fixture<Record<string, string>>('jobs/invalid/expected.json')
const SEALED = readFileSync(join(FIXTURES, 'messages', 'sealed-like.txt'))

test('every valid fixture → 201 { id, def (canonical), state }, then 200 with the same job on repeat', async (t) => {
  for (const [file, want] of Object.entries(VALID)) {
    const input = fixture<Record<string, unknown>>(`jobs/valid/${file}`)
    const network = input.network as 'local' | 'testnet'
    const a = await api(t, { network, jobs: [] })
    if (input.messageSha256 !== undefined) {
      assert.equal(guardOf(await post(a, input, network)), 'message.missing', `${file}: not uploaded yet`)
      const up = await call(a.port, { method: 'PUT', path: `/messages/${input.messageSha256 as string}`, raw: SEALED, headers: { 'content-type': 'text/plain; charset=utf-8' }, network })
      assert.equal(up.status, 201, file)
    }
    if (file === 'btc-defaults.json') {                                  // Eminors fix 1 (I-1): an OLD-shape btc job (no maxFeeRateSatVb) is not creatable any more
      const r = await post(a, input, network)
      assert.equal(r.status, 400, file); assert.equal(guardOf(r), 'job.btc-fee-ceiling', file)
      continue
    }
    const first = await post(a, input, network)
    assert.equal(first.status, 201, `${file}: ${first.text}`)
    const body = first.json as { id: string; def: unknown; state: JobState }
    assert.deepEqual([body.id, body.def], [want.id, want.def], file)
    assert.equal(body.state.phase, 'DEFINED')
    const again = await post(a, input, network)
    assert.equal(again.status, 200, file)
    assert.deepEqual(again.json, first.json, file)
    const lines = readFileSync(join(a.state, 'jobs', want.id, JOURNAL_FILE), 'utf8').split('\n').filter((l) => l !== '')
    assert.equal(lines.length, 1, `${file}: one created line`)
    const created = JSON.parse(lines[0]) as JournalEvent
    assert.deepEqual([created.type, created.by, created.data.jobId], ['created', 'api', want.id])
  }
})

const OFF_LOCAL = new Set(['chain-btc-unsupported.json', 'chain-btc-mainnet.json', 'clawback-required-mainnet-eth.json', 'clawback-required-mainnet-sol.json'])
test('E7b: btc off the local network → 400 job.chain-unsupported on the API of that network', async (t) => {
  for (const [file, network] of [['chain-btc-unsupported.json', 'testnet'], ['chain-btc-mainnet.json', 'mainnet']] as const) {
    const a = await api(t, { network, jobs: [] })
    const r = await post(a, fixture(`jobs/invalid/${file}`), network)
    assert.equal(r.status, 400, file)
    assert.equal(guardOf(r), 'job.chain-unsupported', file)
  }
})

test('PF-S fix round 1 (N-6): a new mainnet job without clawbackTo on an eth or sol chain → 400 job.clawback-required on the mainnet API; nothing stored', async (t) => {
  const a = await api(t, { network: 'mainnet', jobs: [] })
  for (const file of ['clawback-required-mainnet-eth.json', 'clawback-required-mainnet-sol.json']) {
    const r = await post(a, fixture(`jobs/invalid/${file}`), 'mainnet')
    assert.deepEqual([r.status, guardOf(r)], [400, 'job.clawback-required'], file)
    assert.match((r.json as { error: { message: string } }).error.message, /^chains\.(eth|sol)\.clawbackTo is required on mainnet/)
  }
  assert.equal(existsSync(join(a.state, 'jobs')), false)
})

test('every invalid fixture → 400 and its guard; nothing stored', async (t) => {
  const a = await api(t, { jobs: [] })
  for (const [file, guard] of Object.entries(INVALID)) {
    if (OFF_LOCAL.has(file)) continue                                    // E7b: btc off the local network — posted to the API of ITS network below
    const r = await post(a, fixture(`jobs/invalid/${file}`))
    assert.equal(r.status, 400, file)
    assert.equal(guardOf(r), guard, file)
  }
  assert.equal(existsSync(join(a.state, 'jobs')), false)
  assert.deepEqual((await call(a.port, { path: '/jobs' })).json, { jobs: [], serverNowMs: a.clock.now() })
})

test('a testnet job on the local API (and the reverse) → 400 job.network', async (t) => {
  const a = await api(t, { jobs: [] })
  const r = await post(a, fixture('jobs/valid/both-testnet.json'))
  assert.equal(r.status, 400)
  assert.equal(guardOf(r), 'job.network')
  const b = await api(t, { network: 'testnet', jobs: [] })
  assert.equal(guardOf(await post(b, JOB_INPUT, 'testnet')), 'job.network')
  assert.equal((await post(b, onNetwork(JOB_INPUT, 'testnet'), 'testnet')).status, 201)
})

test('by digest: the message must be stored with exactly messageBytes bytes (message.missing otherwise)', async (t) => {
  const a = await api(t, { jobs: [] })
  const input = fixture<Record<string, unknown>>('jobs/valid/message-ref.json')
  await call(a.port, { method: 'PUT', path: `/messages/${input.messageSha256 as string}`, raw: SEALED, headers: { 'content-type': 'text/plain; charset=utf-8' } })
  assert.equal(guardOf(await post(a, { ...input, messageBytes: 513 })), 'message.missing')
  assert.equal(guardOf(await post(a, { ...input, messageSha256: 'a'.repeat(64) })), 'message.missing')
  assert.equal((await post(a, input)).status, 201)
})

test('an inline message is stored by digest (0600 in a 0700 dir); arweaveCopy false is the same job, true is reserved', async (t) => {
  const a = await api(t, { jobs: [] })
  assert.equal((await post(a, { ...JOB_INPUT, arweaveCopy: true })).status, 400)
  assert.equal(guardOf(await post(a, { ...JOB_INPUT, arweaveCopy: true })), 'job.publish-mode-unavailable')
  assert.equal(guardOf(await post(a, { ...JOB_INPUT, arweaveCopy: 'yes' })), 'job.arweave-copy')
  const r = await post(a, JOB_INPUT)
  assert.equal((r.json as { id: string }).id, JOB)
  assert.equal((await post(a, { ...JOB_INPUT, arweaveCopy: false })).status, 200)
  const sha = VALID['eth-drain-null.json'].def as { messageSha256: string }
  const file = join(a.state, 'messages', `${sha.messageSha256}.txt`)
  assert.equal(readFileSync(file, 'utf8'), JOB_INPUT.message)
  assert.equal(statSync(file).mode & 0o777, 0o600)
  assert.equal(statSync(join(a.state, 'messages')).mode & 0o777, 0o700)
  assert.equal(statSync(join(a.state, 'lifecycle', 'job', `${JOB}.json`)).mode & 0o777, 0o600)
})

test('two identical creates at once: one 201, one 200, one created line', async (t) => {
  const a = await api(t, { jobs: [] })
  const [x, y] = await Promise.all([post(a, JOB_INPUT), post(a, JOB_INPUT)])
  assert.deepEqual([x.status, y.status].sort(), [200, 201])
  assert.equal(readFileSync(join(a.state, 'jobs', JOB, JOURNAL_FILE), 'utf8').split('\n').filter((l) => l !== '').length, 1)
})

test('GET /jobs/:id: the state equals reduce(def, journal) for every contract journal; unknown → 404 job.missing', async (t) => {
  const index = fixture<{ vectors: Array<{ name: string }> }>('journals/index.json')
  for (const { name } of index.vectors) {
    const a = await api(t, { jobs: [] }) // vectors share definitions (and so ids): one API each
    const { id, def, lines } = await installJournal(a, name)
    const r = await call(a.port, { path: `/jobs/${id}` })
    assert.equal(r.status, 200, name)
    const body = r.json as { id: string; def: unknown; state: JobState; leases: unknown; seq: number; serverNowMs: number }
    const events = lines.map((l) => JSON.parse(l) as JournalEvent)
    assert.deepEqual(body.state, reduce(def, events), name)
    assert.deepEqual(body.state, fixture(`journals/${name}.state.json`), name)
    assert.deepEqual([body.id, body.def, body.seq], [id, def, events.at(-1)!.seq], name)
    assert.deepEqual(Object.keys(body.leases as object), Object.keys(def.chains), name)
  }
  const a = await api(t)
  const missing = await call(a.port, { path: '/jobs/0123456789abcdef' })
  assert.equal(missing.status, 404)
  assert.equal(guardOf(missing), 'job.missing')
  assert.equal(guardOf(await call(a.port, { path: '/jobs/0123456789abcdef/receipt' })), 'job.missing')
  await installJournal(a, '05a-copies-done')
  const list = (await call(a.port, { path: '/jobs' })).json as { jobs: Array<{ id: string; name: string; phase: string; chains: Record<string, { phase: string }> }> }
  const id05a = idOf(fixture('journals/05a-copies-done.def.json'))
  assert.deepEqual(list.jobs.map((j) => j.id).sort(), [JOB, id05a].sort())
  const one = list.jobs.find((j) => j.id === id05a)!
  assert.deepEqual(Object.keys(one).sort(), ['chains', 'createdAt', 'id', 'name', 'phase'])
  assert.deepEqual([one.phase, one.chains.eth.phase], ['ARMED', 'COPIES_DONE'])
})

test('a corrupt journal: phase CORRUPT with its reason; every append refused journal.corrupt', async (t) => {
  const a = await api(t, { jobs: [] })
  const { id } = await installJournal(a, '04-intent')
  const file = join(a.state, 'jobs', id, JOURNAL_FILE)
  const lines = readFileSync(file, 'utf8').split('\n')
  lines[2] = lines[2].replace('"browser"', '"cli"')
  writeFileSync(file, lines.join('\n'))
  const s = (await call(a.port, { path: `/jobs/${id}` })).json as { state: JobState }
  assert.equal(s.state.phase, 'CORRUPT')
  assert.match(s.state.corrupt ?? '', /^line 4: /)
  const r = await call(a.port, { path: `/jobs/${id}/chains/eth/lease`, body: { op: 'acquire', holder: 'cli' } })
  assert.equal(r.status, 503)
  assert.equal(guardOf(r), 'journal.corrupt')
})

test('the stored record is re-checked on load: another network → job.network; not the canonical def of its id → 500', async (t) => {
  const a = await api(t, { jobs: [] })
  const testnet = VALID['both-testnet.json']
  await createStore(a.state, { log: () => {} }).update('job', testnet.id, () => ({ def: testnet.def, createdAt: 1 }))
  const r = await call(a.port, { path: `/jobs/${testnet.id}` })
  assert.equal(r.status, 400)
  assert.equal(guardOf(r), 'job.network')
  const local = VALID['sol-copies.json']
  await createStore(a.state, { log: () => {} }).update('job', '0123456789abcdef', () => ({ def: local.def, createdAt: 1 }))
  const wrong = await call(a.port, { path: '/jobs/0123456789abcdef' })
  assert.equal(wrong.status, 500)
  assert.equal(guardOf(wrong), 'api.internal')
  assert.equal(existsSync(join(a.state, 'jobs', '0123456789abcdef')), false)
})

test('lazy open: a registry touches nothing until a job is named; then a torn tail is cut and noted', async (t) => {
  const a = await api(t, { jobs: [] })
  const { id } = await installJournal(a, '03-armed')
  const file = join(a.state, 'jobs', id, JOURNAL_FILE)
  writeFileSync(file, readFileSync(file, 'utf8') + '{"v":1,"seq":5,"torn')
  chmodSync(file, 0o600)
  const before = readFileSync(file)
  const registry = createRegistry({ stateDir: a.state, network: 'local', clock: fakeClock(), out: a.out, ticketKey: TICKET_KEY })
  assert.deepEqual(readFileSync(file), before)
  assert.deepEqual(readdirSync(join(a.state, 'jobs', id)), [JOURNAL_FILE])
  const job = await registry.load(id)
  const tail = job.journal.all().at(-1)!
  assert.deepEqual([tail.type, tail.data], ['note', { text: 'recovered tail' }])
  assert.ok(!readFileSync(file, 'utf8').includes('torn'))
})

test('every append is validated (event.*) before it is written: nothing malformed reaches the journal', async (t) => {
  const a = await api(t)
  const j = a.api.registry.journalOf(JOB)
  const n = j.all().length
  const refused = async (p: Promise<unknown>): Promise<string> => { try { await p } catch (e) { return (e as { guardId: string }).guardId } return 'none' }
  assert.equal(await refused(j.append({ chain: 'eth', by: 'browser', gen: 1, type: 'note', data: { text: 'x', extra: 1 } })), 'event.shape')
  assert.equal(await refused(j.append({ chain: 'eth', by: 'browser', gen: 1, type: 'armed', data: {} })), 'event.by')
  assert.equal(await refused(j.append({ chain: 'eth', by: 'api', gen: 1, type: 'intent', data: ethIntent(1) })), 'event.by')
  assert.equal(j.all().length, n)
})

test('one active job per (chain, key): an armed job blocks lease acquire on another job with the same key (job.key-busy)', async (t) => {
  const a = await api(t, { jobs: [JOB_INPUT, JOB2_INPUT] })
  // Neither is armed: both may hold leases (no funds touched).
  assert.equal((await call(a.port, { path: `/jobs/${JOB2}/chains/eth/lease`, body: { op: 'acquire', holder: 'cli' } })).status, 200)
  assert.equal((await call(a.port, { path: `/jobs/${JOB2}/chains/eth/lease`, body: { op: 'release', holder: 'cli', gen: 1 } })).status, 200)
  await armed(a, JOB, ['eth'])
  const r = await call(a.port, { path: `/jobs/${JOB2}/chains/eth/lease`, body: { op: 'acquire', holder: 'cli' } })
  assert.equal(r.status, 409)
  assert.equal(guardOf(r), 'job.key-busy')
  // the sol key is another key; the armed job itself is free to lease
  assert.equal((await call(a.port, { path: `/jobs/${JOB2}/chains/sol/lease`, body: { op: 'acquire', holder: 'cli' } })).status, 200)
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/chains/eth/lease`, body: { op: 'acquire', holder: 'browser' } })).status, 200)
  // a key-loaded for another key is refused on the route (event.shape); the job's own key is accepted
  assert.equal(guardOf(await call(a.port, { path: `/jobs/${JOB}/chains/eth/events`, body: { gen: 1, type: 'key-loaded', data: { address: '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6' } } })), 'event.shape')
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/chains/eth/events`, body: { gen: 1, type: 'key-loaded', data: { address: KEYS.eth } } })).status, 200)
})

test('m1: a CORRUPT job on the same key blocks arming another job (its state is unknown: job.key-busy)', async (t) => {
  const a = await api(t)
  const { id } = await installJournal(a, '02-ready') // a READY job on the eth key JOB uses
  const file = join(a.state, 'jobs', id, JOURNAL_FILE)
  const lines = readFileSync(file, 'utf8').split('\n')
  lines[1] = lines[1].replace('"browser"', '"cli"')
  writeFileSync(file, lines.join('\n'))
  await seedReady(a, JOB, ['eth'])
  const r = await call(a.port, { path: `/jobs/${JOB}/arm`, body: armBody(['eth']) })
  assert.equal(r.status, 409, r.text)
  assert.equal(guardOf(r), 'job.key-busy')
  assert.equal(((await call(a.port, { path: `/jobs/${id}` })).json as { state: JobState }).state.phase, 'CORRUPT')
})

// M1.2 (c): a job whose clawbackTo nobody controls is refused at creation (core E6): precompile → job.clawback-precompile, null / burn → job.clawback.
test('POST /jobs: a clawbackTo that is a precompile is refused (job.clawback-precompile); null and burn stay job.clawback; an ordinary address is created', async (t) => {
  const a = await api(t, { jobs: [] })
  const withTo = (to: string) => ({ ...JOB_INPUT, chains: { eth: { ...(JOB_INPUT.chains as { eth: object }).eth, clawbackTo: to } } })
  const at = (n: bigint): string => `0x${n.toString(16).padStart(40, '0')}`
  for (const n of [1n, 9n, 0x11n, 0x100n]) {          // digit-only hex: the lowercase form is also the EIP-55 form
    const r = await post(a, withTo(at(n)))
    assert.equal(r.status, 400, n.toString(16))
    assert.equal(guardOf(r), 'job.clawback-precompile', n.toString(16))
  }
  for (const to of [at(0n), '0x000000000000000000000000000000000000dEaD']) assert.equal(guardOf(await post(a, withTo(to))), 'job.clawback', to)
  assert.equal((await post(a, withTo('0x1111111111111111111111111111111111111111'))).status, 201)
})

// M4f glue (a): GET /jobs projects ChainState.delegated (the structured EIP-7702 stop) from a real journal (contract vector 14-stopped, its last
// event rewritten as the executor writes it); a plain stop and a text-only reason project no field (the page and CLI keep their text fallback).
test('GET /jobs projects ChainState.delegated from the journaled stop; a plain stop projects none', async (t) => {
  type Row = { id: string; chains: Record<string, { phase: string; reason: string | null; delegated?: true }> }
  const a = await api(t, { jobs: [] })
  const { id } = await installJournal(a, '14-stopped')
  const plain = ((await call(a.port, { path: '/jobs' })).json as { jobs: Row[] }).jobs.find((j) => j.id === id)!
  assert.equal(plain.chains.eth.phase, 'STOPPED')
  assert.equal('delegated' in plain.chains.eth, false, 'absent, not false')
  const file = join(a.state, 'jobs', id, JOURNAL_FILE)
  const lines = readFileSync(file, 'utf8').split('\n').filter((l) => l !== '')
  const last = JSON.parse(lines.at(-1)!) as { data: Record<string, unknown> }
  last.data = { reason: 'engine.eip7702: the key is delegated; the chain stops', delegated: true }
  lines[lines.length - 1] = JSON.stringify(last)
  const b = await api(t, { jobs: [] })
  const { id: id2 } = await installJournal(b, '14-stopped')
  writeFileSync(join(b.state, 'jobs', id2, JOURNAL_FILE), lines.join('\n') + '\n')
  const row = ((await call(b.port, { path: '/jobs' })).json as { jobs: Row[] }).jobs.find((j) => j.id === id2)!
  assert.deepEqual(row.chains.eth, { phase: 'STOPPED', reason: 'engine.eip7702: the key is delegated; the chain stops', delegated: true })
  assert.deepEqual(((await call(b.port, { path: `/jobs/${id2}` })).json as { state: JobState }).state.chains.eth?.delegated, true)
})

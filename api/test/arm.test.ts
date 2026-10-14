// POST /jobs/:id/arm (spec §5.4) and the other operator commands (arm.ts): the checks in order (the mainnet lock first,
// the legacy latch, the request's members, already armed, READY, the key, the confirmations), the drawn schedule and the
// journaled ArmRecord; skip, stop, resume, close and resolve.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { ArmRecord, JobState, JournalEvent } from '@vault-timelock/core/contracts'
import { normalizeJob } from '@vault-timelock/core/job'
import { MAINNET_JOB_SENDS_ENABLED, networkName } from 'vt-broadcast/src/config.ts'
import { createStore } from 'vt-broadcast/src/lifecycle/store.ts'
import { openTrigger } from 'vt-broadcast/src/lifecycle/triggers.ts'
import {
  CAPS, JOB, JOB2, JOB2_INPUT, JOB_INPUT, KEYS, armBody, armed, call, ethIntent, ethTx, guardOf, idOf, onNetwork, seedReady, startApi, writeJob,
} from './helpers.ts'
import type { TestApi } from './helpers.ts'

process.env.NODE_ENV = 'test'

async function api(t: { after(fn: () => Promise<void>): void }, o: Parameters<typeof startApi>[0] = {}): Promise<TestApi> {
  const a = await startApi(o)
  t.after(() => a.close())
  return a
}
const arm = (a: TestApi, id: string, body: unknown, network: 'local' | 'testnet' | 'mainnet' = 'local') => call(a.port, { path: `/jobs/${id}/arm`, body, network })
const lines = (a: TestApi, id: string): readonly JournalEvent[] => a.api.registry.journalOf(id).all()
const stateOf = async (a: TestApi, id: string, network: 'local' | 'testnet' | 'mainnet' = 'local'): Promise<JobState> =>
  ((await call(a.port, { path: `/jobs/${id}`, network })).json as { state: JobState }).state
async function openLegacyTrigger(a: TestApi, ref = 'synthetic-legacy'): Promise<void> {
  await openTrigger({ out: a.out, store: createStore(a.out, { log: () => {} }) }, {
    id: 'f2-0123456789', profile: 'local', source: 'cli', ref, payloadSha256: 'ab'.repeat(32),
    chains: [{ dest: 'eth', network: networkName('local', 'eth'), address: null, bytesSha256: 'cd'.repeat(32), explorer: null }],
  }, { now: () => 1791504000 })
}

// M2 FLIP (applied, operator R78): MAINNET_JOB_SENDS_ENABLED = true, so the lock no longer refuses a mainnet arm; every later check still
// does, in order: the legacy latch, the request, R76 (each armed lane READY: funds present), the typed word, the countdown, the cap ceiling.
test('mainnet with MAINNET_JOB_SENDS_ENABLED = true (the M2 flip): the lock no longer refuses; the legacy latch, R76 (an unfunded lane is not READY), the typed word, the countdown and the cap ceiling still refuse, nothing journaled; then it arms', async (t) => {
  assert.equal(MAINNET_JOB_SENDS_ENABLED, true)
  const input = onNetwork(JOB_INPUT, 'mainnet')
  const id = idOf(input, 'mainnet')
  const a = await api(t, { network: 'mainnet', jobs: [input] })
  await openLegacyTrigger(a) // the latch open: the first refusal now, whatever the job's state or the request
  for (const body of [armBody(['eth'], { countdownSec: 60, typed: 'broadcast' }), armBody(['eth']), { bogus: true }]) {
    const r = await arm(a, id, body, 'mainnet')
    assert.deepEqual([r.status, guardOf(r)], [423, 'trigger.uncleared'], JSON.stringify(body))
  }
  assert.ok(!lines(a, id).some((e) => e.type === 'armed'))
  const b = await api(t, { network: 'mainnet', jobs: [input] })
  const good = armBody(['eth'], { countdownSec: 60, typed: 'broadcast' })
  assert.equal(guardOf(await arm(b, id, { bogus: true }, 'mainnet')), 'api.json')
  // R76: no key and no funds, then the key but no funds present (balance 0, not affordable): not READY → 409 job.state
  const unready = await arm(b, id, good, 'mainnet')
  assert.deepEqual([unready.status, guardOf(unready)], [409, 'job.state'])
  const j = b.api.registry.journalOf(id)
  await j.append({ chain: 'eth', by: 'browser', gen: null, type: 'key-loaded', data: { address: KEYS.eth } })
  await j.append({ chain: 'eth', by: 'browser', gen: null, type: 'funds', data: { balance: '0', affordable: false, nextCopyCost: '25000300000000' } })
  const unfunded = await arm(b, id, good, 'mainnet')
  assert.deepEqual([unfunded.status, guardOf(unfunded)], [409, 'job.state'])
  await j.append({ chain: 'eth', by: 'browser', gen: null, type: 'funds', data: { balance: '50000000000000000', affordable: true, nextCopyCost: '25000300000000' } })
  for (const [why, body, guard] of [
    ['no typed word', armBody(['eth'], { countdownSec: 60 }), 'arm.typed'],
    ['a wrong typed word', armBody(['eth'], { countdownSec: 60, typed: 'Broadcast' }), 'arm.typed'],
    ['a countdown other than 60 s', armBody(['eth'], { countdownSec: 5, typed: 'broadcast' }), 'arm.countdown'],
    ['a stagger (local only)', { ...good, stagger: [0, 0] }, 'arm.stagger'],
    ['an untyped cap above the R60 ceiling', { ...good, caps: { eth: { ...CAPS.eth, nativeCap: '4000000000000001' } } }, 'arm.cap-ceiling'],
  ] as const) assert.equal(guardOf(await arm(b, id, body, 'mainnet')), guard, why)
  assert.ok(!lines(b, id).some((e) => e.type === 'armed'), 'nothing armed by a refused request')
  const ok = await arm(b, id, good, 'mainnet')
  assert.equal(ok.status, 200, ok.text)
  const rec = (ok.json as { armed: ArmRecord }).armed
  assert.deepEqual([rec.countdownSec, rec.releaseAt - rec.armedAt], [60, 60_000])
  assert.equal(lines(b, id).filter((e) => e.type === 'armed').length, 1)
})

test('a legacy trigger open in $OUT (synthetic, opened with broadcast\'s openTrigger) → 423 trigger.uncleared, even one naming this job', async (t) => {
  const a = await api(t)
  await seedReady(a, JOB, ['eth'])
  await openLegacyTrigger(a, JOB)
  const r = await arm(a, JOB, armBody(['eth']))
  assert.equal(r.status, 423)
  assert.equal(guardOf(r), 'trigger.uncleared')
  assert.equal((await stateOf(a, JOB)).armed, null)
})

test('not READY → 409 job.state; chains not of the job or empty → job.state; a second arm → 409 job.armed', async (t) => {
  const a = await api(t)
  const notReady = await arm(a, JOB, armBody(['eth']))
  assert.equal(notReady.status, 409)
  assert.equal(guardOf(notReady), 'job.state')
  await seedReady(a, JOB, ['eth'])
  assert.equal(guardOf(await arm(a, JOB, armBody(['eth', 'sol']))), 'job.state') // sol is not a chain of this job
  for (const chains of [[], ['sol'], ['btc']]) assert.equal(guardOf(await arm(a, JOB, { chains, confirm: { typed: null, amounts: {} }, caps: {} })), 'job.state', JSON.stringify(chains))
  assert.equal((await arm(a, JOB, armBody(['eth']))).status, 200)
  const again = await arm(a, JOB, armBody(['eth']))
  assert.equal(again.status, 409)
  assert.equal(guardOf(again), 'job.armed')
  assert.equal(lines(a, JOB).filter((e) => e.type === 'armed').length, 1)
})

test('another active job on the same key → 409 job.key-busy; once it is closed, the key is free', async (t) => {
  const a = await api(t, { jobs: [JOB_INPUT, JOB2_INPUT] })
  await seedReady(a, JOB2, ['eth', 'sol'])
  await armed(a, JOB, ['eth'])
  const busy = await arm(a, JOB2, armBody(['eth', 'sol']))
  assert.equal(busy.status, 409)
  assert.equal(guardOf(busy), 'job.key-busy')
  // stop JOB (no transaction yet → STOPPED), close it → DONE: the eth key is free again
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/stop`, body: { chain: null } })).status, 200)
  assert.equal((await stateOf(a, JOB)).chains.eth!.phase, 'STOPPED')
  assert.equal(guardOf(await arm(a, JOB2, armBody(['eth', 'sol']))), 'job.key-busy') // STOPPED keeps the key (ruling 5)
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/close`, body: { chain: 'eth' } })).status, 200)
  assert.equal((await stateOf(a, JOB)).phase, 'DONE')
  assert.equal((await arm(a, JOB2, armBody(['eth', 'sol'], { countdownSec: 5, stagger: [5, 10] }))).status, 200)
})

test('two arms at once: of one job → one 200, one job.armed; of two jobs on one key → one 200, one job.key-busy', async (t) => {
  const a = await api(t, { jobs: [JOB_INPUT, JOB2_INPUT] })
  await seedReady(a, JOB, ['eth'])
  await seedReady(a, JOB2, ['eth'])
  const same = await Promise.all([arm(a, JOB, armBody(['eth'])), arm(a, JOB, armBody(['eth']))])
  assert.deepEqual(same.map((r) => r.status).sort(), [200, 409])
  assert.ok(same.some((r) => guardOf(r) === 'job.armed'))
  const b = await api(t, { jobs: [JOB_INPUT, JOB2_INPUT] })
  await seedReady(b, JOB, ['eth'])
  await seedReady(b, JOB2, ['eth'])
  const two = await Promise.all([arm(b, JOB, armBody(['eth'])), arm(b, JOB2, armBody(['eth']))])
  assert.deepEqual(two.map((r) => r.status).sort(), [200, 409])
  assert.ok(two.some((r) => guardOf(r) === 'job.key-busy'))
})

test('local arm → armed journaled: releaseAt = armedAt + countdown·1000, a CSPRNG order and the second start within the stagger', async (t) => {
  const orders = new Set<string>()
  for (let i = 0; i < 12; i++) {
    const a = await startApi({ jobs: [JOB2_INPUT] })
    try {
      await seedReady(a, JOB2, ['eth', 'sol'])
      a.clock.advance(1234)
      const r = await arm(a, JOB2, armBody(['eth', 'sol'], { countdownSec: 15, stagger: [5, 10] }))
      assert.equal(r.status, 200, r.text)
      const rec = (r.json as { armed: ArmRecord }).armed
      assert.equal(rec.armedAt, a.clock.now())
      assert.equal(rec.releaseAt, rec.armedAt + 15_000)
      assert.equal(rec.countdownSec, 15)
      assert.deepEqual([...rec.schedule.order].sort(), ['eth', 'sol'])
      const [first, second] = rec.schedule.order
      assert.equal(rec.schedule.offsetSec[first], 0)
      const off = rec.schedule.offsetSec[second]!
      assert.ok(Number.isInteger(off) && off >= 5 && off <= 10, String(off))
      assert.deepEqual(rec.caps, { eth: CAPS.eth, sol: CAPS.sol })
      assert.deepEqual(rec.sources, {})
      const line = lines(a, JOB2).at(-1)!
      assert.deepEqual([line.type, line.by, line.chain, line.gen], ['armed', 'api', null, null])
      assert.deepEqual(line.data, rec)
      orders.add(rec.schedule.order.join(','))
    } finally {
      await a.close()
    }
  }
  assert.equal(orders.size, 2, 'both orders appear in 12 draws (fails with probability 2^-11)')
})

test('defaults: countdown 60 s; testnet staggers the second chain 30..300 s; a cap only for the armed chains', async (t) => {
  const a = await api(t)
  await seedReady(a, JOB, ['eth'])
  const rec = ((await arm(a, JOB, armBody(['eth']))).json as { armed: ArmRecord }).armed
  assert.deepEqual([rec.countdownSec, rec.releaseAt - rec.armedAt], [60, 60_000])
  const input = onNetwork(JOB2_INPUT, 'testnet')
  const id = idOf(input, 'testnet')
  const b = await api(t, { network: 'testnet', jobs: [input] })
  await seedReady(b, id, ['eth', 'sol'])
  assert.equal(guardOf(await arm(b, id, armBody(['eth', 'sol'], { stagger: [5, 10] }), 'testnet')), 'arm.stagger')
  const r = await arm(b, id, armBody(['eth', 'sol'], { countdownSec: 300 }), 'testnet')
  const t2 = (r.json as { armed: ArmRecord }).armed
  const off = t2.schedule.offsetSec[t2.schedule.order[1]]!
  assert.ok(off >= 30 && off <= 300, String(off))
})

test('the request: unknown members, a cap for a chain not armed, malformed sources → api.json; the confirmations → arm.*', async (t) => {
  const a = await api(t, { jobs: [JOB2_INPUT] })
  await seedReady(a, JOB2, ['eth', 'sol'])
  const base = armBody(['eth'])
  for (const body of [
    { ...base, force: true }, { ...base, confirm: { typed: null, amounts: {}, skip: true } }, { ...base, caps: { eth: CAPS.eth, sol: CAPS.sol } },
    { ...base, sources: { sol: 'label' } }, { ...base, sources: { eth: 5 } }, { ...base, sources: [] }, { ...base, chains: 'eth' }, { ...base, confirm: null }, [],
  ]) {
    const r = await arm(a, JOB2, body)
    assert.equal(r.status, 400, JSON.stringify(body))
    assert.equal(guardOf(r), 'api.json', JSON.stringify(body))
  }
  const over = { ...CAPS.eth, overCap: true }
  for (const [body, guard] of [
    [{ ...base, chains: ['eth', 'eth'] }, 'arm.chains'],
    [{ ...base, caps: { eth: over } }, 'arm.amount'],
    [{ ...base, caps: { eth: { ...CAPS.eth, extra: 1 } } }, 'arm.amount'],
    [{ ...base, caps: {} }, 'arm.amount'],
    [{ ...base, countdownSec: 4 }, 'arm.countdown'],
    [{ ...base, stagger: [10, 5] }, 'arm.stagger'],
  ] as const) {
    const r = await arm(a, JOB2, body)
    assert.equal(guardOf(r), guard, JSON.stringify(body))
  }
  assert.equal((await arm(a, JOB2, { ...base, caps: { eth: over }, confirm: { typed: null, amounts: { eth: over.planned } } })).status, 200)
})

test('skip: only before the release of an armed job → { releaseAt: now }, journaled; after it → job.state', async (t) => {
  const a = await api(t)
  assert.equal(guardOf(await call(a.port, { path: `/jobs/${JOB}/skip`, body: {} })), 'job.state')
  await seedReady(a, JOB, ['eth'])
  await arm(a, JOB, armBody(['eth'], { countdownSec: 30 }))
  assert.equal(guardOf(await call(a.port, { path: `/jobs/${JOB}/skip`, body: { now: 1 } })), 'api.json')
  a.clock.advance(10_000)
  const r = await call(a.port, { path: `/jobs/${JOB}/skip`, body: {} })
  assert.deepEqual(r.json, { releaseAt: a.clock.now() })
  const s = await stateOf(a, JOB)
  assert.deepEqual([s.releaseAt, s.armed!.releaseAt], [a.clock.now(), a.clock.now()])
  assert.equal(guardOf(await call(a.port, { path: `/jobs/${JOB}/skip`, body: {} })), 'job.state')
})

test('stop: stop-requested; a chain without a transaction goes straight to STOPPED; a running chain only gets the request', async (t) => {
  const a = await api(t, { jobs: [JOB2_INPUT] })
  await armed(a, JOB2, ['eth', 'sol'])
  await call(a.port, { path: `/jobs/${JOB2}/chains/eth/lease`, body: { op: 'acquire', holder: 'cli' } })
  assert.equal((await call(a.port, { path: `/jobs/${JOB2}/chains/eth/events`, body: { gen: 1, type: 'intent', data: ethIntent(1) } })).status, 200)
  for (const body of [{}, { chain: 'btc' }, { chain: 'eth', extra: 1 }]) assert.equal(guardOf(await call(a.port, { path: `/jobs/${JOB2}/stop`, body })), 'api.json')
  const r = await call(a.port, { path: `/jobs/${JOB2}/stop`, body: { chain: null } })
  const n = lines(a, JOB2).length
  assert.deepEqual(r.json, { seq: n - 2 })
  assert.deepEqual(lines(a, JOB2).slice(-2).map((e) => [e.type, e.chain, e.by]), [['stop-requested', null, 'api'], ['stopped', 'sol', 'api']])
  const s = await stateOf(a, JOB2)
  assert.deepEqual([s.chains.eth!.phase, s.chains.eth!.stopRequested, s.chains.sol!.phase], ['RUNNING', true, 'STOPPED'])
  const resume = await call(a.port, { path: `/jobs/${JOB2}/resume`, body: { chain: 'eth', tipCapGwei: '2.5' } })
  assert.equal(resume.status, 200)
  assert.equal((await stateOf(a, JOB2)).chains.eth!.stopRequested, false)
  assert.equal(guardOf(await call(a.port, { path: `/jobs/${JOB2}/resume`, body: { chain: 'eth', tipCapGwei: 'lots' } })), 'event.shape')
  assert.equal(guardOf(await call(a.port, { path: `/jobs/${JOB2}/resume`, body: { tipCapGwei: '1' } })), 'api.json')
})

test('close: only a settled chain with nothing in flight (job.state) → close → DONE', async (t) => {
  const a = await api(t)
  await armed(a, JOB, ['eth'])
  await call(a.port, { path: `/jobs/${JOB}/chains/eth/lease`, body: { op: 'acquire', holder: 'cli' } })
  const ev = (type: string, data: unknown) => call(a.port, { path: `/jobs/${JOB}/chains/eth/events`, body: { gen: 1, type, data } })
  assert.equal(guardOf(await call(a.port, { path: `/jobs/${JOB}/close`, body: { chain: 'eth' } })), 'job.state') // ARMED
  await ev('intent', ethIntent(1))
  await ev('stopped', { reason: 'operator' })
  assert.equal(guardOf(await call(a.port, { path: `/jobs/${JOB}/close`, body: { chain: 'eth' } })), 'job.state') // an open intent
  await ev('reconcile', { txId: ethTx(1), outcome: 'expired' })
  assert.equal(guardOf(await call(a.port, { path: `/jobs/${JOB}/close`, body: { chain: null } })), 'api.json')
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/close`, body: { chain: 'eth' } })).status, 200)
  assert.deepEqual([(await stateOf(a, JOB)).phase, (await stateOf(a, JOB)).chains.eth!.phase], ['DONE', 'DONE'])
})

test('resolve: an open tx of a STUCK chain, by the operator; else job.state; mainnet needs typed "resolve" (job.resolve-typed)', async (t) => {
  const a = await api(t)
  await armed(a, JOB, ['eth'])
  await call(a.port, { path: `/jobs/${JOB}/chains/eth/lease`, body: { op: 'acquire', holder: 'cli' } })
  await call(a.port, { path: `/jobs/${JOB}/chains/eth/events`, body: { gen: 1, type: 'intent', data: ethIntent(1) } })
  const resolve = (body: unknown, network: 'local' | 'mainnet' = 'local', id = JOB) => call(a.port, { path: `/jobs/${id}/chains/eth/resolve`, body, network })
  assert.equal(guardOf(await resolve({ txId: ethTx(1), action: 'mark-done' })), 'job.state') // not stuck
  await call(a.port, { path: `/jobs/${JOB}/chains/eth/events`, body: { gen: 1, type: 'stuck', data: { txId: ethTx(1), reason: 'no receipt, nonce not moved' } } })
  assert.equal(guardOf(await resolve({ txId: ethTx(2), action: 'mark-done' })), 'job.state') // not an open tx
  assert.equal(guardOf(await resolve({ txId: ethTx(1), action: 'retry' })), 'api.json')
  const r = await resolve({ txId: ethTx(1), action: 'mark-done' })
  assert.equal(r.status, 200, r.text)
  const line = lines(a, JOB).at(-1)!
  assert.deepEqual([line.type, line.by, line.chain, line.data], ['resolved', 'operator', 'eth', { txId: ethTx(1), action: 'mark-done', typed: null }])
  assert.equal((await stateOf(a, JOB)).chains.eth!.txs[0].state, 'included')

  // a mainnet job with a stuck intent, as an earlier (unlocked) build would have journaled it
  const m = await api(t, { network: 'mainnet', jobs: [] })
  const armedAt = m.clock.now()
  const id = await writeJob(m.state, normalizeJob(onNetwork(JOB_INPUT, 'mainnet'), { network: 'mainnet' }).def, [
    { chain: 'eth', by: 'browser', gen: null, type: 'key-loaded', data: { address: '0x8739Eb87B3d11f221Df63454F8D229a1A4F4049C' } },
    { chain: 'eth', by: 'browser', gen: null, type: 'funds', data: { balance: '50000000000000000', affordable: true, nextCopyCost: '1' } },
    { chain: null, by: 'api', gen: null, type: 'armed', data: { armedAt, releaseAt: armedAt + 60_000, countdownSec: 60, schedule: { order: ['eth'], offsetSec: { eth: 0 } }, caps: { eth: CAPS.eth }, sources: {} } },
    { chain: 'eth', by: 'cli', gen: 1, type: 'intent', data: ethIntent(1) },
    { chain: 'eth', by: 'cli', gen: 1, type: 'stuck', data: { txId: ethTx(1), reason: 'unknowable' } },
  ])
  const mr = (body: unknown) => call(m.port, { path: `/jobs/${id}/chains/eth/resolve`, body, network: 'mainnet' })
  for (const typed of [undefined, null, 'Resolve', 'resolve ']) {
    const r2 = await mr({ txId: ethTx(1), action: 'mark-failed', ...(typed === undefined ? {} : { typed }) })
    assert.equal(r2.status, 400, String(typed))
    assert.equal(guardOf(r2), 'job.resolve-typed', String(typed))
  }
  assert.equal((await mr({ txId: ethTx(1), action: 'mark-failed', typed: 'resolve' })).status, 200)
})

test('m5 (I2: exact base units): an over-cap arm types the armed cap itself, exactly — never rounded → else arm.amount', async (t) => {
  const a = await api(t)
  await seedReady(a, JOB, ['eth'])
  const cap = { nativeCap: '4123456789012345', usd: 10.31, priceAt: 1791504009000, overCap: true, planned: '0.004' }
  const body = (planned: string) => ({ chains: ['eth'], confirm: { typed: null, amounts: { eth: planned } }, caps: { eth: { ...cap, planned } }, countdownSec: 5 })
  // typed what it planned, but not what the cap enforces: 6 significant digits (the old rule), one wei off either way,
  // more decimals than ETH has, not a plain decimal
  for (const planned of ['0.004', '0.00412346', '0.004123456789012344', '0.004123456789012346', '0.0041234567890123450', '4123456789012345', '0.004123456789012345e0', '.004123456789012345']) {
    const r = await arm(a, JOB, body(planned))
    assert.equal(r.status, 400, planned)
    assert.equal(guardOf(r), 'arm.amount', planned)
  }
  assert.equal((await arm(a, JOB, body('0.004123456789012345'))).status, 200) // exactly nativeCap wei
})

test('PF-S M-4: off local the API bounds the arm cap (arm.cap-ceiling): an untyped cap above the R60 native ceiling, a typed cap without a price, a cap worth more than the job\'s budget → refused, nothing journaled; typed above the ceiling arms', async (t) => {
  const input = onNetwork(JOB2_INPUT, 'testnet')   // eth budget $10, sol budget $5 (testnet: mainnet's rule; mainnet arms are locked until the flip)
  const id = idOf(input, 'testnet')
  const a = await api(t, { network: 'testnet', jobs: [input] })
  await seedReady(a, id, ['eth', 'sol'])
  const n0 = lines(a, id).length
  const PRICE_AT = 1791504009000
  const body = (caps: Record<string, unknown>, amounts: Record<string, string> = {}) => ({ chains: Object.keys(caps), confirm: { typed: null, amounts }, caps, countdownSec: 5 })
  const eth = (o: Record<string, unknown>) => ({ ...CAPS.eth, ...o }), sol = (o: Record<string, unknown>) => ({ ...CAPS.sol, ...o })
  for (const [why, b] of [
    ['eth untyped, one wei above 0.004 ETH', body({ eth: eth({ nativeCap: '4000000000000001' }) })],
    ['sol untyped, one lamport above 0.07 SOL', body({ sol: sol({ nativeCap: '70000001', usd: 5 }) })],
    ['eth untyped and unpriced above the ceiling', body({ eth: eth({ nativeCap: '9000000000000000', usd: 0, priceAt: null }) })],
    ['eth typed without a price (the budget cannot bound it)', body({ eth: eth({ nativeCap: '5000000000000000', usd: 0, priceAt: null, overCap: true, planned: '0.005' }) }, { eth: '0.005' })],
    ['eth worth more than its $10 budget', body({ eth: eth({ usd: 10.01 }) })],
    ['sol worth more than its $5 budget', body({ sol: sol({ usd: 5.01 }) })],
    ['eth typed, worth more than its budget', body({ eth: eth({ nativeCap: '5000000000000000', usd: 12.5, priceAt: PRICE_AT, overCap: true, planned: '0.005' }) }, { eth: '0.005' })],
  ] as const) {
    const r = await arm(a, id, b, 'testnet')
    assert.deepEqual([r.status, guardOf(r)], [400, 'arm.cap-ceiling'], why)
  }
  assert.equal(lines(a, id).length, n0, 'nothing journaled')
  // typed above the ceiling, priced, within the budget: arms (the typed amount is the cap: arm.amount)
  const typed = eth({ nativeCap: '5000000000000000', usd: 9.5, priceAt: PRICE_AT, overCap: true, planned: '0.005' })
  const ok = await arm(a, id, body({ eth: typed, sol: sol({ usd: 5, nativeCap: '70000000' }) }, { eth: '0.005' }), 'testnet')
  assert.equal(ok.status, 200, ok.text)
  assert.deepEqual((ok.json as { armed: ArmRecord }).armed.caps.eth, typed)
  // local keeps its own rules (no ceiling: a local price fixture, no value)
  const l = await api(t)
  await seedReady(l, JOB, ['eth'])
  assert.equal((await arm(l, JOB, body({ eth: eth({ nativeCap: '9000000000000000', usd: 30 }) }))).status, 200)
  // mainnet: while job sends are locked the lock refuses first; once lifted (the M2 flip) the same check runs there — this line
  // needs no edit at the flip (PF-S fix round 1, N-3)
  const m = onNetwork(JOB_INPUT, 'mainnet')
  const b = await api(t, { network: 'mainnet', jobs: [m] })
  const mid = idOf(m, 'mainnet')
  await seedReady(b, mid, ['eth'])
  const mr = await arm(b, mid, { ...body({ eth: eth({ nativeCap: '9000000000000000' }) }), countdownSec: 60, confirm: { typed: 'broadcast', amounts: {} } }, 'mainnet')
  assert.equal(guardOf(mr), MAINNET_JOB_SENDS_ENABLED ? 'arm.cap-ceiling' : 'release.mainnet-locked')
})

test('close after an eth fee bump LANDED: 200 (the replaced attempt is not in flight); with no attempt landed the family still blocks close (lane-s re-review I-1)', async (t) => {
  const a = await api(t)
  await armed(a, JOB, ['eth'])
  await call(a.port, { path: `/jobs/${JOB}/chains/eth/lease`, body: { op: 'acquire', holder: 'cli' } })
  const ev = (type: string, data: unknown) => call(a.port, { path: `/jobs/${JOB}/chains/eth/events`, body: { gen: 1, type, data } })
  const first = ethIntent(1), bump = { ...ethIntent(2), attempt: 2, replaces: ethTx(1), eth: { ...(ethIntent(1).eth as object), maxFee: '3000000000' } }
  assert.equal((await ev('intent', first)).status, 200)
  assert.equal((await ev('intent', bump)).status, 200, 'the bump')
  await ev('stopped', { reason: 'operator' })
  assert.equal(guardOf(await call(a.port, { path: `/jobs/${JOB}/close`, body: { chain: 'eth' } })), 'job.state', 'nothing landed: blocked')
  assert.equal((await ev('included', { txId: ethTx(2), copy: 1, part: 1, attempt: 2, block: '5', fee: '1', ms: 1 })).status, 200)
  const closed = await call(a.port, { path: `/jobs/${JOB}/close`, body: { chain: 'eth' } })
  assert.equal(closed.status, 200, closed.text)
})

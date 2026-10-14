// S6b fix round 2 (C-1): a btc commit and reveal ticket are minted by the REAL job service from a real journaled job — the body is
// sliced from the STORED message by the lane's own part planner, the commit txid for the reveal comes from the JOURNAL (the commit
// that landed), the cap reserves the commit's fee + the value it locks (the reveal reserves 0), and everything the executor
// declares beyond what the API computes is refused before it is journaled. The job is a real canonical btc job (normalizeJob, as POST /jobs
// stores it; the lane runs on local since E7b), written as files with its history, then driven over HTTP: lease, events, tickets.
// Synthetic keys and data only.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { pubECDSA } from '@scure/btc-signer/utils.js'
import { BTC_BODY_MAX, BTC_POSTAGE, commitAddress, laneAddresses, maxCommitFee, maxCommitValue, revealDestination } from '@vault-timelock/core/chains/btc-ord.ts'
import { splitText } from '@vault-timelock/core/chains/plan.js'
import type { ArmRecord, JobDef } from '@vault-timelock/core/contracts'
import { jobId, normalizeJob } from '@vault-timelock/core/job'
import { verifyTicket } from '../src/tickets.ts'
import { START, TICKET_KEY, call, startApi, writeJob } from './helpers.ts'
import type { TestApi } from './helpers.ts'

process.env.NODE_ENV = 'test'
const sha = (b: Uint8Array | string): string => createHash('sha256').update(b).digest('hex')
const PUB = Buffer.from(pubECDSA(createHash('sha256').update('vt-fixture:ticket btc lane').digest()))
const LANE = laneAddresses('local', PUB)!
const TEXT = 'A synthetic vt fixture message for the btc lane.\nIt has two lines.\n'
const TEXT_SHA = sha(TEXT)
const O1 = `${'11'.repeat(32)}:0`, O2 = `${'22'.repeat(32)}:1`
const rnd = (l: string): string => sha(`btc-mint ${l}`)
const CAP = 1_000_000n

function btcDef(text = TEXT): JobDef {
  return normalizeJob({ format: 'vt-job/1', network: 'local', name: 'btc mint', messageSha256: sha(text), messageBytes: Buffer.byteLength(text),
    chains: { btc: { mode: { copies: 2 }, distinctCopies: true, keyAddress: LANE.p2wpkh, budgetUsd: 10, clawbackTo: null, maxFeeRateSatVb: 25 } } }, { network: 'local' }).def
}
const ARMED: ArmRecord = { armedAt: START, releaseAt: START + 5_000, countdownSec: 5, schedule: { order: ['btc'], offsetSec: { btc: 0 } },
  caps: { btc: { nativeCap: String(CAP), usd: 10, priceAt: START, overCap: false, planned: '0.01' } }, sources: {} }

async function setup(t: { after(fn: () => Promise<void>): void }, o: { cap?: bigint; text?: string } = {}): Promise<{ a: TestApi; id: string }> {
  const a = await startApi({ jobs: [] })
  t.after(() => a.close())
  const text = o.text ?? TEXT
  const def = btcDef(text)
  a.api.registry.messages.storeText(text, sha(text))
  const armed = o.cap === undefined ? ARMED : { ...ARMED, caps: { btc: { ...ARMED.caps.btc!, nativeCap: String(o.cap) } } }
  const id = await writeJob(a.state, def, [
    { chain: 'btc', by: 'browser', gen: null, type: 'key-loaded', data: { address: LANE.p2wpkh } },
    { chain: 'btc', by: 'browser', gen: null, type: 'funds', data: { balance: '5000000000', affordable: true, nextCopyCost: '1000' } },
    { chain: null, by: 'api', gen: null, type: 'armed', data: armed as unknown as Record<string, unknown> },
  ])
  assert.equal(id, jobId(def))
  a.clock.set(START + 6_000)
  return { a, id }
}
const lease = (a: TestApi, id: string): Promise<{ status: number; json: any }> => call(a.port, { path: `/jobs/${id}/chains/btc/lease`, body: { op: 'acquire', holder: 'cli' } }) as never
const append = (a: TestApi, id: string, type: string, data: unknown): Promise<{ status: number; json: any }> => call(a.port, { path: `/jobs/${id}/chains/btc/events`, body: { gen: 1, type, data } }) as never
const mintTicket = (a: TestApi, id: string, txId: string): Promise<{ status: number; json: any }> => call(a.port, { path: `/jobs/${id}/chains/btc/tickets`, body: { gen: 1, txId } }) as never
const bodyOf = (copy: number): Uint8Array => splitText(new TextEncoder().encode(TEXT), { cap: BTC_BODY_MAX, sha256: TEXT_SHA, copy, copies: 2 })[0].payload
const commitIntent = (copy: number, txId: string, btc: Record<string, unknown> = {}, o: Record<string, unknown> = {}): Record<string, unknown> =>
  ({ txId, copy, part: 1, parts: 2, attempt: 1, replaces: null, rawSha256: rnd(`raw ${txId}`), payloadSha256: sha(bodyOf(copy)), reserved: '0',
    btc: { kind: 'commit', pubkey: PUB.toString('hex'), fee: '306', value: '846', inputs: [O1], ...btc }, ...o })
const revealIntent = (copy: number, txId: string, btc: Record<string, unknown> = {}, o: Record<string, unknown> = {}): Record<string, unknown> =>
  ({ txId, copy, part: 2, parts: 2, attempt: 1, replaces: null, rawSha256: rnd(`raw ${txId}`), payloadSha256: sha(bodyOf(copy)), reserved: '0',
    btc: { kind: 'reveal', pubkey: PUB.toString('hex'), fee: '300', commitVout: 0, ...btc }, ...o })
const guard = (r: { json: any }): string | undefined => r.json?.error?.guard
const payloadOf = (ticket: string) => verifyTicket(TICKET_KEY, ticket, START + 6_000)

test('a commit and a reveal ticket mint from a real journaled job: every field is the API\'s, the reveal\'s q is the LANDED commit from the journal', async (t) => {
  const { a, id } = await setup(t)
  const l0 = await lease(a, id)
  assert.equal(l0.status, 200, JSON.stringify(l0.json) + String(a.api.registry.journalOf(id).corrupt()))
  const body = bodyOf(1)
  assert.ok(Buffer.from(body).toString().includes(TEXT), 'the planned body carries the stored text')
  const C = rnd('commit 1')
  const ci = await append(a, id, 'intent', commitIntent(1, C, { inputs: [O1, O2] }))
  assert.equal(ci.status, 200, JSON.stringify(ci.json))
  const ct = await mintTicket(a, id, C)
  assert.equal(ct.status, 200, JSON.stringify(ct.json))
  const cp = payloadOf(ct.json.ticket)
  assert.deepEqual({ w: cp.w, c: cp.c, k: cp.k, t: cp.t, r: cp.r, a: cp.a, p: cp.p, to: cp.to, value: cp.value, f: cp.f, q: cp.q },
    { w: 'local', c: 'btc', k: 'commit', t: C, r: rnd(`raw ${C}`), a: LANE.p2wpkh, p: sha(body), to: commitAddress('local', LANE.xonly, body), value: '846', f: '306', q: `${O1},${O2}` })
  // a reveal before its commit landed has no txid to bind: refused before it is journaled
  const R = rnd('reveal 1')
  assert.equal(guard(await append(a, id, 'intent', revealIntent(1, R))), 'event.shape')
  // the executor journals the commit sent and included
  assert.equal((await append(a, id, 'sent', { txId: C, outcome: 'accepted', reason: null })).status, 200)
  assert.equal((await append(a, id, 'included', { txId: C, copy: 1, part: 1, attempt: 1, block: '102', fee: '1152', ms: 10 })).status, 200)
  const ri = await append(a, id, 'intent', revealIntent(1, R, { commitVout: 1 }))
  assert.equal(ri.status, 200, JSON.stringify(ri.json))
  const rt = await mintTicket(a, id, R)
  assert.equal(rt.status, 200, JSON.stringify(rt.json))
  const rp = payloadOf(rt.json.ticket)
  assert.deepEqual({ k: rp.k, a: rp.a, p: rp.p, to: rp.to, value: rp.value, f: rp.f, q: rp.q },
    { k: 'reveal', a: LANE.p2wpkh, p: sha(body), to: revealDestination('local', LANE.xonly), value: String(BTC_POSTAGE), f: '300', q: `${C}:1` })
})

test('the executor\'s other choices are refused before they are journaled: a foreign key, a body that is not the stored message\'s, a value over the cap, another copy\'s commit', async (t) => {
  const { a, id } = await setup(t)
  await lease(a, id)
  const foreign = Buffer.from(pubECDSA(createHash('sha256').update('another key').digest())).toString('hex')
  const bad = async (name: string, data: Record<string, unknown>): Promise<void> => {
    const r = await append(a, id, 'intent', data)
    assert.deepEqual([r.status, guard(r)], [400, 'event.shape'], name)
  }
  await bad('foreign pubkey (hash160 differs from the job key)', commitIntent(1, rnd('c a'), { pubkey: foreign }))
  await bad('payloadSha256 of another text', commitIntent(1, rnd('c b'), {}, { payloadSha256: sha('other text') }))
  await bad('the copy 2 body under copy 1', commitIntent(1, rnd('c c'), {}, { payloadSha256: sha(bodyOf(2)) }))
  await bad('a value over postage + the reveal fee cap', commitIntent(1, rnd('c d'), { value: String(maxCommitValue(bodyOf(1).length) + 1n) }))
  await bad('a fee over the cap', commitIntent(1, rnd('c e'), { fee: String(maxCommitFee(1) + 1n) }))
  await bad('a destination of its own', commitIntent(1, rnd('c f'), { to: LANE.p2tr }))
  await bad('part 2 with the commit kind', commitIntent(1, rnd('c g'), {}, { part: 2 }))
  await bad('a replacement', commitIntent(1, rnd('c rep'), {}, { replaces: rnd('c a') }))
  await bad('one part', commitIntent(1, rnd('c h'), {}, { parts: 1 }))
  await bad('both eth and btc', commitIntent(1, rnd('c i'), {}, { eth: { nonce: 0, tip: '1', maxFee: '2', gas: '3', to: `0x${'00'.repeat(20)}` } }))
  await bad('a key that is no curve point', commitIntent(1, rnd('c j'), { pubkey: `02${'00'.repeat(31)}05` }))
  assert.equal(a.api.registry.gates() >= 10, true)
  // the journal holds none of them
  const ok = await append(a, id, 'intent', commitIntent(1, rnd('c ok')))
  assert.equal(ok.status, 200, JSON.stringify(ok.json))
  // a reveal binds the commit that landed for ITS copy, not another copy's
  const C2 = rnd('c copy2')
  assert.equal((await append(a, id, 'intent', commitIntent(2, C2))).status, 200)
  assert.equal((await append(a, id, 'sent', { txId: C2, outcome: 'accepted', reason: null })).status, 200)
  assert.equal((await append(a, id, 'included', { txId: C2, copy: 2, part: 1, attempt: 1, block: '103', fee: '1152', ms: 1 })).status, 200)
  assert.equal(guard(await append(a, id, 'intent', revealIntent(1, rnd('r copy1')))), 'event.shape', 'copy 1 has no landed commit; copy 2\'s is not its')
  const r2 = rnd('r copy2')
  assert.equal((await append(a, id, 'intent', revealIntent(2, r2))).status, 200)
  assert.equal(payloadOf((await mintTicket(a, id, r2)).json.ticket).q, `${C2}:0`)
})

test('the spend cap reserves a commit\'s fee + value (the reveal 0); exhaustion refuses; a refused intent reserves nothing', async (t) => {
  // cap = exactly one commit (306 + 846 = 1152): a second commit does not fit while the first is in flight
  const { a, id } = await setup(t, { cap: 1152n })
  await lease(a, id)
  const C = rnd('cap c1')
  assert.equal((await append(a, id, 'intent', commitIntent(1, C))).status, 200)
  const second = await append(a, id, 'intent', commitIntent(2, rnd('cap c2')))
  assert.equal(second.status >= 400, true, JSON.stringify(second.json))
  assert.equal(guard(second), 'arm.amount')
  // a commit that alone exceeds the cap is refused the same way
  const { a: b, id: idb } = await setup(t, { cap: 1151n })
  await lease(b, idb)
  const big = await append(b, idb, 'intent', commitIntent(1, rnd('cap big')))
  assert.equal(guard(big), 'arm.amount')
  // the reveal reserves 0: with the commit landed, the reveal fits a cap the commit already filled
  assert.equal((await append(a, id, 'sent', { txId: C, outcome: 'accepted', reason: null })).status, 200)
  assert.equal((await append(a, id, 'included', { txId: C, copy: 1, part: 1, attempt: 1, block: '102', fee: '1152', ms: 1 })).status, 200)
  const R = rnd('cap r1')
  const rv = await append(a, id, 'intent', revealIntent(1, R))
  assert.equal(rv.status, 200, JSON.stringify(rv.json))
  assert.equal((await mintTicket(a, id, R)).status, 200)
})

test('Stop between commit and reveal: exactly one reveal intent (and its ticket) is admitted for the copy; a second reveal, a replacement and any new commit are refused', async (t) => {
  const { a, id } = await setup(t)
  await lease(a, id)
  const C = rnd('stop c1')
  assert.equal((await append(a, id, 'intent', commitIntent(1, C))).status, 200)
  assert.equal((await append(a, id, 'sent', { txId: C, outcome: 'accepted', reason: null })).status, 200)
  // the operator's Stop (an API event), while the commit awaits its block
  await a.api.registry.journalOf(id).append({ chain: 'btc', by: 'api', gen: null, type: 'stop-requested', data: { chain: 'btc' } })
  // a new commit (another copy) and a commit replacement are refused: nothing new is signed after a Stop (PF-S fix round 3)
  const c2 = await append(a, id, 'intent', commitIntent(2, rnd('stop c2')))
  assert.deepEqual([c2.status, guard(c2)], [409, 'intent.after-stop'])
  const rNo = await append(a, id, 'intent', revealIntent(2, rnd('stop r-nocommit')))
  assert.deepEqual([rNo.status, guard(rNo)], [400, 'event.shape'], 'no commit of copy 2: its binding cannot form (refused before the Stop rule)')
  // the reveal of copy 1 (commit open, or landed) is admitted once, with the server-computed binding q = the journaled commit
  const R = rnd('stop r1')
  const ri = await append(a, id, 'intent', revealIntent(1, R))
  assert.equal(ri.status, 200, JSON.stringify(ri.json))
  const rt = await mintTicket(a, id, R)
  assert.equal(rt.status, 200, JSON.stringify(rt.json))
  assert.equal(payloadOf(rt.json.ticket).q, `${C}:0`)
  assert.equal(payloadOf(rt.json.ticket).k, 'reveal')
  // a second reveal for the copy, a reveal replacing the first, and a commit for the copy again are refused
  // (btc has no replacement at all: a reveal naming `replaces` is malformed before the Stop rule is reached)
  for (const [why, data, want] of [['a second reveal', revealIntent(1, rnd('stop r1b')), [409, 'intent.after-stop']],
    ['a reveal replacing the first', revealIntent(1, rnd('stop r1c'), {}, { replaces: R, attempt: 2 }), [400, 'event.shape']],
    ['a commit for the copy again', commitIntent(1, rnd('stop c1b')), [409, 'intent.after-stop']]] as const) {
    const r = await append(a, id, 'intent', data)
    assert.deepEqual([r.status, guard(r)], want, why)
  }
})

test('PF-S fix round 3: a Stop after the commit LANDED still admits that copy\'s one reveal; a new commit is refused intent.after-stop', async (t) => {
  const { a, id } = await setup(t)
  await lease(a, id)
  const C = rnd('stop-landed c1')
  assert.equal((await append(a, id, 'intent', commitIntent(1, C))).status, 200)
  assert.equal((await append(a, id, 'sent', { txId: C, outcome: 'accepted', reason: null })).status, 200)
  assert.equal((await append(a, id, 'included', { txId: C, copy: 1, part: 1, attempt: 1, block: '102', fee: '1152', ms: 1 })).status, 200)
  await a.api.registry.journalOf(id).append({ chain: 'btc', by: 'api', gen: null, type: 'stop-requested', data: { chain: 'btc' } })
  const c2 = await append(a, id, 'intent', commitIntent(2, rnd('stop-landed c2')))
  assert.deepEqual([c2.status, guard(c2)], [409, 'intent.after-stop'])
  const R = rnd('stop-landed r1')
  const ri = await append(a, id, 'intent', revealIntent(1, R))
  assert.equal(ri.status, 200, JSON.stringify(ri.json))
  assert.equal(payloadOf((await mintTicket(a, id, R)).json.ticket).q, `${C}:0`)
})

test('one open btc attempt per (copy, part): a second commit beside an open one is refused (event.family), so a Stop cannot bind a reveal to a sibling that never lands (review m-1, HM12)', async (t) => {
  const { a, id } = await setup(t)
  await lease(a, id)
  const C1 = rnd('m1 c1'), C2 = rnd('m1 c2')
  assert.equal((await append(a, id, 'intent', commitIntent(1, C1))).status, 200)
  const second = await append(a, id, 'intent', commitIntent(1, C2, { fee: '307' }))
  assert.deepEqual([second.status, guard(second)], [400, 'event.family'])
  // a Stop with the one commit open: the reveal binds THAT commit
  await a.api.registry.journalOf(id).append({ chain: 'btc', by: 'api', gen: null, type: 'stop-requested', data: { chain: 'btc' } })
  const sibling = await append(a, id, 'intent', commitIntent(1, rnd('m1 c3'), { fee: '308' }))
  assert.equal(sibling.status >= 400, true, 'no new commit after a Stop')
  const R = rnd('m1 r')
  assert.equal((await append(a, id, 'intent', revealIntent(1, R))).status, 200)
  assert.equal(payloadOf((await mintTicket(a, id, R)).json.ticket).q, `${C1}:0`)
  // a commit that is DEAD (expired) is not open: the executor may rebuild one, and the reveal binds the one that landed
  const { a: b, id: idb } = await setup(t)
  await lease(b, idb)
  const D1 = rnd('m1 d1'), D2 = rnd('m1 d2')
  assert.equal((await append(b, idb, 'intent', commitIntent(1, D1))).status, 200)
  // Eminors fix 1 (E7b m-7): a btc attempt is never "expired" / "nonce-consumed" - the gate refuses those outcomes; the dead way is stuck + mark-failed
  const expired = await append(b, idb, 'reconcile', { txId: D1, outcome: 'expired' })
  assert.ok(expired.status >= 400 && guard(expired) === 'job.state', JSON.stringify(expired.json))
  assert.equal((await append(b, idb, 'stuck', { txId: D1, reason: 'input spent elsewhere' })).status, 200)
  assert.equal((await call(b.port, { path: `/jobs/${idb}/chains/btc/resolve`, body: { txId: D1, action: 'mark-failed' } }) as { status: number }).status, 200)
  assert.equal((await append(b, idb, 'intent', commitIntent(1, D2, { fee: '307' }))).status, 200)
  assert.equal((await append(b, idb, 'sent', { txId: D2, outcome: 'accepted', reason: null })).status, 200)
  assert.equal((await append(b, idb, 'included', { txId: D2, copy: 1, part: 1, attempt: 1, block: '102', fee: '1153', ms: 1 })).status, 200)
  const R2 = rnd('m1 r2')
  assert.equal((await append(b, idb, 'intent', revealIntent(1, R2))).status, 200)
  assert.equal(payloadOf((await mintTicket(b, idb, R2)).json.ticket).q, `${D2}:0`)
})

test('a landed commit charges at least its fee + the value it locked, whatever fee the executor reports (review m-2)', async (t) => {
  // cap 1500: one commit (306 + 846 = 1152) leaves 348, so a second commit (1152) never fits once the first landed
  for (const reported of ['300', '1152']) {
    const { a, id } = await setup(t, { cap: 1500n })
    await lease(a, id)
    const C = rnd(`m2 c1 ${reported}`)
    assert.equal((await append(a, id, 'intent', commitIntent(1, C))).status, 200)
    assert.equal((await append(a, id, 'sent', { txId: C, outcome: 'accepted', reason: null })).status, 200)
    assert.equal((await append(a, id, 'included', { txId: C, copy: 1, part: 1, attempt: 1, block: '102', fee: reported, ms: 1 })).status, 200)
    const two = await append(a, id, 'intent', commitIntent(2, rnd(`m2 c2 ${reported}`)))
    assert.deepEqual([two.status >= 400, guard(two)], [true, 'arm.amount'], `reported fee ${reported}`)
    // the reveal still reserves nothing new and its landing report is only the reveal's own fee
    assert.equal((await append(a, id, 'intent', revealIntent(1, rnd(`m2 r1 ${reported}`)))).status, 200)
  }
})

test('a text over BTC_BODY_MAX gets no binding: its commit is refused before it is journaled (HM8)', async (t) => {
  const long = `${'a long synthetic line of text. '.repeat(Math.ceil((BTC_BODY_MAX + 500) / 31))}\n`
  assert.ok(Buffer.byteLength(long) > BTC_BODY_MAX)
  const { a, id } = await setup(t, { text: long })
  await lease(a, id)
  const r = await append(a, id, 'intent', commitIntent(1, rnd('hm8'), {}, { payloadSha256: sha(long) }))
  assert.deepEqual([r.status, guard(r)], [400, 'event.shape'])
})

test('btc recovery (E7 I-1): stuck + the operator\'s mark-failed admit exactly ONE new commit for the copy; a concurrent second one stays refused', async (t) => {
  const { a, id } = await setup(t)
  await lease(a, id)
  const resolve = (txId: string, action: string): Promise<{ status: number; json: any }> => call(a.port, { path: `/jobs/${id}/chains/btc/resolve`, body: { txId, action } }) as never
  const C1 = rnd('rec c1')
  assert.equal((await append(a, id, 'intent', commitIntent(1, C1))).status, 200)
  assert.equal((await append(a, id, 'sent', { txId: C1, outcome: 'accepted', reason: null })).status, 200)
  // its input was spent elsewhere: the engine journals stuck (positive evidence), the chain is STUCK, the commit still counts as open
  assert.equal((await append(a, id, 'stuck', { txId: C1, reason: 'input spent elsewhere' })).status, 200)
  const early = await append(a, id, 'intent', commitIntent(1, rnd('rec c2')))
  assert.ok(early.status >= 400, 'before the resolve nothing new is admitted')
  const done = await resolve(C1, 'mark-failed')
  assert.equal(done.status, 200, JSON.stringify(done.json))
  // the operator resumes; the lease holder journals the new attempt
  const C2 = rnd('rec c2b')
  const ni = await append(a, id, 'intent', commitIntent(1, C2, { fee: '307' }, { attempt: 2 }))
  assert.equal(ni.status, 200, JSON.stringify(ni.json))
  assert.equal((await mintTicket(a, id, C2)).status, 200)
  // exactly one: a second concurrent attempt for the copy is refused, and the failed one gets no ticket
  const third = await append(a, id, 'intent', commitIntent(1, rnd('rec c3'), { fee: '308' }, { attempt: 3 }))
  assert.deepEqual([third.status, guard(third)], [400, 'event.family'])
  assert.equal((await mintTicket(a, id, C1)).status >= 400, true)
})

test('security review: a btc attempt that is stuck + mark-failed (or reconciled expired) stops being OPEN but KEEPS its cap reservation; every new attempt reserves fresh', async (t) => {
  // one commit reserves 306 + 846 = 1152. Cap 2304 = exactly two commits.
  const { a, id } = await setup(t, { cap: 2304n })
  await lease(a, id)
  const resolve = (txId: string): Promise<{ status: number; json: any }> => call(a.port, { path: `/jobs/${id}/chains/btc/resolve`, body: { txId, action: 'mark-failed' } }) as never
  const C1 = rnd('sec c1'), C2 = rnd('sec c2'), C3 = rnd('sec c3')
  assert.equal((await append(a, id, 'intent', commitIntent(1, C1))).status, 200)
  assert.equal((await append(a, id, 'sent', { txId: C1, outcome: 'accepted', reason: null })).status, 200)
  assert.equal((await append(a, id, 'stuck', { txId: C1, reason: 'input spent elsewhere' })).status, 200)
  assert.equal((await resolve(C1)).status, 200)
  // the failed attempt still counts: the ledger holds 1152 for it, and the new attempt adds its own 1152 (fits exactly)
  assert.equal((await append(a, id, 'intent', commitIntent(1, C2, { fee: '306' }, { attempt: 2 }))).status, 200)
  assert.equal((await append(a, id, 'sent', { txId: C2, outcome: 'accepted', reason: null })).status, 200)
  assert.equal((await append(a, id, 'stuck', { txId: C2, reason: 'input spent elsewhere' })).status, 200)
  assert.equal((await resolve(C2)).status, 200)
  // the "input spent elsewhere" story repeated cannot re-spend the cap: C3 would be the third 1152 on a 2304 cap
  const third = await append(a, id, 'intent', commitIntent(1, C3, {}, { attempt: 3 }))
  assert.deepEqual([third.status >= 400, guard(third)], [true, 'arm.amount'])
  // a reconcile `expired` report on a btc attempt is refused outright now (E7b m-7), so it can never release anything
  const { a: b, id: idb } = await setup(t, { cap: 1500n })
  await lease(b, idb)
  const D1 = rnd('sec d1')
  assert.equal((await append(b, idb, 'intent', commitIntent(1, D1))).status, 200)
  const exp = await append(b, idb, 'reconcile', { txId: D1, outcome: 'expired' })
  assert.ok(exp.status >= 400 && guard(exp) === 'job.state', JSON.stringify(exp.json))
  assert.equal((await append(b, idb, 'stuck', { txId: D1, reason: 'input spent elsewhere' })).status, 200)
  assert.equal((await call(b.port, { path: `/jobs/${idb}/chains/btc/resolve`, body: { txId: D1, action: 'mark-failed' } }) as { status: number }).status, 200)
  const d2 = await append(b, idb, 'intent', commitIntent(1, rnd('sec d2'), {}, { attempt: 2 }))
  assert.deepEqual([d2.status >= 400, guard(d2)], [true, 'arm.amount'])
})

test('security review: after stuck + mark-failed a new attempt that FITS the cap is admitted once; one that does not is refused (the operator raises the cap with the typed arm.amount path)', async (t) => {
  const { a, id } = await setup(t, { cap: 2304n })
  await lease(a, id)
  const C1 = rnd('fit c1')
  assert.equal((await append(a, id, 'intent', commitIntent(1, C1))).status, 200)
  assert.equal((await append(a, id, 'sent', { txId: C1, outcome: 'accepted', reason: null })).status, 200)
  assert.equal((await append(a, id, 'stuck', { txId: C1, reason: 'x' })).status, 200)
  assert.equal((await call(a.port, { path: `/jobs/${id}/chains/btc/resolve`, body: { txId: C1, action: 'mark-failed' } })).status, 200)
  const big = await append(a, id, 'intent', commitIntent(1, rnd('fit big'), { value: '1000' }, { attempt: 2 }))   // 306 + 1000 + 1152 > 2304
  assert.deepEqual([big.status >= 400, guard(big)], [true, 'arm.amount'])
  const fits = await append(a, id, 'intent', commitIntent(1, rnd('fit ok'), {}, { attempt: 2 }))                 // 1152 + 1152 = 2304
  assert.equal(fits.status, 200, JSON.stringify(fits.json))
})

test('E7 fix-3 I-1: a btc attempt cannot be resolved mark-done (only mark-failed); the chain is not wedged', async (t) => {
  const { a, id } = await setup(t)
  await lease(a, id)
  const C = rnd('md c1')
  assert.equal((await append(a, id, 'intent', commitIntent(1, C))).status, 200)
  assert.equal((await append(a, id, 'sent', { txId: C, outcome: 'accepted', reason: null })).status, 200)
  assert.equal((await append(a, id, 'stuck', { txId: C, reason: 'x' })).status, 200)
  const done = await call(a.port, { path: `/jobs/${id}/chains/btc/resolve`, body: { txId: C, action: 'mark-done' } }) as { status: number; json: any }
  assert.deepEqual([done.status, guard(done)], [409, 'job.state'])
  assert.equal(((await call(a.port, { path: `/jobs/${id}/chains/btc/resolve`, body: { txId: C, action: 'mark-failed' } })) as { status: number }).status, 200)
})

test('E7 fix-3 I-2: repeated stuck + mark-failed cycles never exceed the cap (the reviewer\'s 3-commit probe); a chain with only abandoned attempts can still close', async (t) => {
  const { a, id } = await setup(t, { cap: 1713n })            // one commit reserves 1152: a second cannot fit while the first is counted
  await lease(a, id)
  const C1 = rnd('p c1')
  assert.equal((await append(a, id, 'intent', commitIntent(1, C1))).status, 200)
  assert.equal((await append(a, id, 'sent', { txId: C1, outcome: 'accepted', reason: null })).status, 200)
  assert.equal((await append(a, id, 'stuck', { txId: C1, reason: 'x' })).status, 200)
  assert.equal(((await call(a.port, { path: `/jobs/${id}/chains/btc/resolve`, body: { txId: C1, action: 'mark-failed' } })) as { status: number }).status, 200)
  for (let n = 2; n <= 4; n++) {
    const r = await append(a, id, 'intent', commitIntent(1, rnd(`p c${n}`), {}, { attempt: n }))
    assert.deepEqual([r.status >= 400, guard(r)], [true, 'arm.amount'], `attempt ${n}`)
  }
  // close: the abandoned attempt is neither open nor in flight for the close check
  await a.api.registry.journalOf(id).append({ chain: 'btc', by: 'api', gen: null, type: 'stop-requested', data: { chain: 'btc' } })
  assert.equal((await append(a, id, 'stopped', { reason: 'operator' })).status, 200)
  const closed = await call(a.port, { path: `/jobs/${id}/close`, body: { chain: 'btc' } }) as { status: number; json: any }
  assert.equal(closed.status, 200, JSON.stringify(closed.json))
})

// Eminors fix 2 (re-review 2): a stored btc job from before maxFeeRateSatVb was required still LOADS (readRecord re-normalizes it with
// existing: true) and quotes at the 500 sat/vB fallback. Dropping `existing: true` at jobs.ts readRecord makes this fail.
test('a stored btc job WITHOUT maxFeeRateSatVb loads over HTTP (existing: true) and quotes at 500; creating it anew is job.btc-fee-ceiling', async (t) => {
  const text = TEXT
  const old = normalizeJob({ format: 'vt-job/1', network: 'local', name: 'btc old', messageSha256: sha(text), messageBytes: Buffer.byteLength(text),
    chains: { btc: { mode: { copies: 1 }, distinctCopies: true, keyAddress: LANE.p2wpkh, budgetUsd: 10, clawbackTo: null } } }, { network: 'local', existing: true }).def
  assert.equal('maxFeeRateSatVb' in old.chains.btc!, false)
  const a = await startApi({ jobs: [] })
  t.after(() => a.close())
  const id = await writeJob(a.state, old, [])
  const got = await call(a.port, { method: 'GET', path: `/jobs/${id}` }) as { status: number; json: { id: string; def: JobDef } }
  assert.equal(got.status, 200, JSON.stringify(got.json))
  assert.equal(got.json.id, id)
  assert.equal('maxFeeRateSatVb' in got.json.def.chains.btc!, false)
  const { feeCeilingOf, copyCost } = await import('@vault-timelock/core/chains/btc.js')
  assert.equal(feeCeilingOf(got.json.def.chains.btc), 500n)
  const { computeArmCaps } = await import('@vault-timelock/core/engine/arm-caps.js')
  const cap = computeArmCaps(got.json.def, text, { prices: null, fees: { btc: { rate: 2n } }, balances: { btc: 50_000_000n }, network: 'local', now: 1 }).btc
  assert.equal(cap.ceilingSatVb, 500)
  assert.ok(BigInt(cap.fullCopyCost) >= copyCost(0, 500n).perCopy)
  const list = await call(a.port, { method: 'GET', path: '/jobs' }) as { status: number; json: { jobs: Array<{ id: string }> } }
  assert.ok(list.status === 200 && list.json.jobs.some((j) => j.id === id), 'and it is listed')
})

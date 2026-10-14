// E7 (M4): the BTC inscription lane — commit/reveal text inscriptions as a copies lane. ALL DATA IS SYNTHETIC: a fixed
// test key, a fake bitcoind behind an injected fetch (test/engine/btc-fakes.ts), the in-memory jobs API (test/fakes/fake-journal.ts).
// What is pinned: the MQ byte vectors; an intent before each broadcast; the reveal never sent before its commit landed (seen by txid
// in a block); every ambiguous send answer reconciled BY TXID (never "not sent", never a second tx); a crash between commit and
// reveal (and after the reveal's intent) reconciled by a takeover that sends the reveal exactly once; the cap checked once per copy.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { hexToBytes } from '@noble/hashes/utils.js'
import * as btc from '@scure/btc-signer'
import { OutOrdinalReveal } from 'micro-ordinals'
import { TICKET_HEADER } from '../../src/contracts/index.ts'
import type { JobDef, JobState } from '../../src/contracts/index.ts'
import { assertEventAllowed, createReducer, reduce, validateEvent } from '../../src/job/index.ts'
import { reconcileChain } from '../../src/executor/reconcile.ts'
import { sha256Hex } from '../../src/job/canonical.ts'
import { BTC_CONTENT_TYPE, BTC_POSTAGE, commitAddress } from '../../src/chains/btc-ord.ts'
import * as btcc from '../../src/chains/btc.js'
import { btcAdapter, newLaneState, planLaneCopy, runCopiesLane, validateLaneConfig } from '../../src/engine/lane.js'
import { btcTx } from '../../src/engine/btc-tx.js'
import { configureRelay, rpc } from '../../src/engine/rpc.js'
import { CapLedger } from '../../src/gates/caps.ts'
import { resumeOf } from '../../src/executor/executor.ts'
import { fakeJournal, virtualClock } from '../fakes/fake-journal.ts'
import { isRefusal } from '../../src/contracts/index.ts'
import { guardOf } from '../job/helpers.ts'
import { jobFor, newKey, T0 } from '../executor/helpers.ts'
import { fakeBtcChain } from './btc-fakes.ts'

const V = JSON.parse(readFileSync(new URL('./btc-vectors.json', import.meta.url), 'utf8')) as {
  key: string; address: string
  out: Array<{ name: string; text: string; rate: string; ins: Array<{ txid: string; index: number; amount: string }>; commitHex: string; commitTxid: string; revealHex: string; revealTxid: string; commitFee: string; revealFee: string; revealAmount: string; commitAddress: string }>
}
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s)
const guardOfAsync = async (fn: () => Promise<unknown>): Promise<string | null> => { try { await fn() } catch (e) { if (isRefusal(e)) return e.guardId; throw e } return null }

// ---------------------------------------------------------------------------------------------------------------- bytes
test('the commit and the reveal are byte for byte the MQ prototype\'s (vectors made by its buildPair)', () => {
  const key = btcc.btcFromSecret(V.key, 'local')
  assert.equal(key.address, V.address)
  for (const c of V.out) {
    const body = utf8(c.text)
    const ins = c.ins.map((u) => ({ txid: u.txid, index: u.index, amount: BigInt(u.amount) }))
    const commit = btcc.buildCommit({ key, body, inputs: ins, value: BigInt(c.revealAmount), fee: BigInt(c.commitFee) })
    assert.equal(commit.hex, c.commitHex, `${c.name}: commit`)
    assert.equal(commit.txid, c.commitTxid, `${c.name}: commit txid`)
    assert.equal(commitAddress('local', hexToBytes(key.xonly), body), c.commitAddress)
    const reveal = btcc.buildReveal({ key, body, commitTxid: commit.txid, commitVout: 0, amount: BigInt(c.revealAmount) })
    assert.equal(reveal.hex, c.revealHex, `${c.name}: reveal`)
    assert.equal(reveal.txid, c.revealTxid, `${c.name}: reveal txid`)
    assert.equal(reveal.fee, BigInt(c.revealFee), `${c.name}: reveal fee`)
    // deterministic: the very bytes again (a takeover rebuilds them)
    assert.equal(btcc.buildCommit({ key, body, inputs: ins, value: BigInt(c.revealAmount), fee: BigInt(c.commitFee) }).hex, c.commitHex)
    assert.equal(btcc.buildReveal({ key, body, commitTxid: commit.txid, commitVout: 0, amount: BigInt(c.revealAmount) }).hex, c.revealHex)
  }
})
test('planCommit chooses the MQ amounts: value = postage + the reveal fee at the rate, fee = vsize × rate (single input)', () => {
  const key = btcc.btcFromSecret(V.key, 'local')
  for (const c of V.out.filter((x) => x.ins.length === 1)) {
    const p = btcc.planCommit(key, utf8(c.text), c.ins.map((u) => ({ txid: u.txid, index: u.index, amount: BigInt(u.amount) })), BigInt(c.rate))
    assert.ok(p.inputs !== null)
    assert.equal(p.value, BigInt(c.revealAmount), c.name)
    assert.equal(p.fee, BigInt(c.commitFee), c.name)
    assert.equal(p.revealFee, BigInt(c.revealFee), c.name)
  }
  const poor = btcc.planCommit(key, utf8('x'), [{ txid: 'aa'.repeat(32), index: 0, amount: 600n }], 2n)
  assert.equal(poor.inputs, null)                                        // not enough: nothing is planned
  assert.equal(guardOf(() => btcc.planCommit(key, utf8('x'), [{ txid: 'aa'.repeat(32), index: 0, amount: 10_000_000n }], 501n)), 'engine.btc-fee-rate')
})
test('the readback of a reveal accepts only the one inscription of the part\'s bytes, to the lane\'s taproot address, at the postage', () => {
  const key = btcc.btcFromSecret(V.key, 'local')
  const body = utf8(V.out[0].text)
  const rev = btcc.buildReveal({ key, body, commitTxid: V.out[0].commitTxid, commitVout: 0, amount: BigInt(V.out[0].revealAmount) })
  const view = (hex: string, over: { value?: number; address?: string } = {}) => {
    const t = btc.Transaction.fromRaw(hexToBytes(hex), { customScripts: [OutOrdinalReveal] })
    return { vin: [{ txinwitness: t.getInput(0).finalScriptWitness!.map((w) => Buffer.from(w).toString('hex')) }],
      vout: [{ value: over.value ?? 0.00000546, scriptPubKey: { address: over.address ?? key.p2tr } }] }
  }
  assert.equal(btcc.readbackReveal(key, body, view(rev.hex)).ok, true)
  assert.equal(btcc.readbackReveal(key, utf8('another text'), view(rev.hex)).ok, false)          // not the part's bytes
  assert.equal(btcc.readbackReveal(key, body, view(rev.hex, { value: 0.00001 })).ok, false)       // not the postage
  assert.equal(btcc.readbackReveal(key, body, view(rev.hex, { address: key.address })).ok, false)  // not the taproot address
  assert.equal(btcc.readbackReveal(key, body, { vin: [{ txinwitness: [] }], vout: [] }).ok, false)
  assert.equal(btcc.readbackReveal(key, body, {}).ok, false)
  const w = view(rev.hex).vin[0].txinwitness
  assert.equal(btcc.readbackReveal(key, body, { ...view(rev.hex), vin: [{ txinwitness: [w[0], w[1]] }] }).ok, false)   // a missing control block
  assert.equal(btcc.readbackReveal(btcc.btcFromSecret('33'.repeat(32), 'local'), body, view(rev.hex)).ok, false)        // another key's inscription
  // the commit's readback: output 0 pays the commit address exactly the value
  const c = V.out[0], commit = btc.Transaction.fromRaw(hexToBytes(c.commitHex))
  const cv = { vout: [{ value: Number(commit.getOutput(0).amount) / 1e8, scriptPubKey: { address: c.commitAddress } }] }
  assert.equal(btcc.readbackCommit(key, body, cv, BigInt(c.revealAmount)).ok, true)
  assert.equal(btcc.readbackCommit(key, body, cv, BigInt(c.revealAmount) + 1n).ok, false)
  assert.equal(btcc.readbackCommit(key, utf8('another text'), cv, BigInt(c.revealAmount)).ok, false)
  assert.equal(BTC_CONTENT_TYPE, 'text/plain;charset=utf-8')
  assert.equal(BTC_POSTAGE, 546n)
})
test('the body of a copy: one inscription with the copy marker; the two lane txs share it; a text over the cap is refused', () => {
  const text = 'a message', sha = sha256Hex(utf8(text))
  const one = btcc.planBtcCopy(utf8(text), { sha256: sha, copy: 1, copies: 3 })
  assert.deepEqual(one.map((p) => [p.i, p.n]), [[1, 2], [2, 2]])
  assert.equal(new TextDecoder().decode(one[0].payload), text)           // copy 1 has no marker
  const two = btcc.planBtcCopy(utf8(text), { sha256: sha, copy: 2, copies: 3 })
  assert.equal(new TextDecoder().decode(two[1].payload), `[copy 2/3]\n${text}`)
  assert.throws(() => btcc.planBtcCopy(utf8('x'.repeat(btcc.BTC_BODY_MAX + 1)), { sha256: sha, copy: null, copies: null }), /one inscription/)
})
test('lane config: btc is copies only; clawbackTo is refused; the executor\'s planner gives the two txs', () => {
  assert.equal(validateLaneConfig({ chain: 'btc', mode: 'drain', text: 'x' }).ok, false)
  assert.match(validateLaneConfig({ chain: 'btc', mode: 'drain', text: 'x' }).errors.join(), /copies mode only/)
  assert.equal(validateLaneConfig({ chain: 'btc', mode: 'copies', copies: 2, text: 'x', clawbackTo: 'bcrt1qzzz' }).ok, false)
  const v = validateLaneConfig({ chain: 'btc', mode: 'copies', copies: 2, text: 'x' })
  assert.equal(v.ok, true)
  assert.equal(planLaneCopy(v.cfg, 2).length, 2)
})

// ---------------------------------------------------------------------------------------------------------------- the rig
const FUND = 5_000_000n
function rig(o: { text?: string; copies?: number; cap?: string; blockAfterLookups?: number; fund?: bigint | null; keyHex?: string } = {}) {
  const clock = virtualClock(T0)
  const chain = fakeBtcChain(o.blockAfterLookups === undefined ? {} : { blockAfterLookups: o.blockAfterLookups })
  const key = btcc.btcFromSecret(o.keyHex ?? '22'.repeat(32), 'local')
  const text = o.text ?? 'BTC lane test message.\n'
  const base = jobFor('eth', newKey('eth'), { copies: o.copies ?? 1, text })
  const def: JobDef = { ...base.def, chains: { btc: { ...(base.def.chains.eth as object), keyAddress: key.address, publishMode: 'sol.memo', feeStrategy: 'economy' } } as unknown as JobDef['chains'] }
  const j = fakeJournal({ def, text, clock })
  // the earlier tab: key-loaded + funds, released; armed (the countdown already over)
  void j.client.lease(j.id, 'btc', 'acquire', 'browser')
  j.asHolder(1, 'browser', 'btc', 'key-loaded', { address: key.address })
  j.asHolder(1, 'browser', 'btc', 'funds', { balance: String(FUND), affordable: true, nextCopyCost: '1' })
  void j.client.lease(j.id, 'btc', 'release', 'browser', 1)
  j.arm(['btc'], { caps: { btc: o.cap ?? '1000000' }, releaseAt: j.serverNow() - 1 })
  if (o.fund !== null) chain.fund(key.address, o.fund ?? FUND)
  const cfg = validateLaneConfig({ chain: 'btc', mode: 'copies', copies: o.copies ?? 1, text, distinct: true, feeStrategy: 'economy' }).cfg
  /** One holder's run: lease, a journal seam under that gen, the lane. `until` makes the holder "die" (alive() false) when it returns true. */
  async function run(r: { until?: (ev: { type: string; [k: string]: unknown }) => boolean; holder?: 'cli' | 'browser'; extra?: Record<string, unknown> } = {}) {
    const holder = r.holder ?? 'cli'
    const grant = await j.client.lease(j.id, 'btc', 'acquire', holder)
    let dead = false
    const seen = (ev: { type: string; [k: string]: unknown }): void => { if (r.until?.(ev)) dead = true }
    const ej = {
      async append(ev: { type: string; chain: string; [k: string]: unknown }) { const { type, chain: c, ...data } = ev; await j.client.append(j.id, c as 'btc', grant.gen, type, data); seen(ev) },
      async intent(ev: { type: string; chain: string; [k: string]: unknown }) { const { type, chain: c, ...data } = ev; const x = await j.client.append(j.id, c as 'btc', grant.gen, type, data); seen(ev); return { ticket: x.ticket! } },
      ticket: (txId: string) => j.client.ticket(j.id, 'btc', grant.gen, txId),
    }
    // the takeover reconcile of the executor, BTC: the lane reconciles each journaled attempt by txid at its own part
    const state: JobState = j.state()
    const resume = resumeOf(state.chains.btc!)
    const lane = newLaneState(cfg)
    const d = { journal: ej, network: 'local', state, poll: 1_000, clock, alive: () => !dead, notify: () => {}, ...(resume !== null ? { resume } : {}), ...(r.extra ?? {}) }
    const out = await runCopiesLane(cfg, key, lane, d)
    return { out, lane, gen: grant.gen, state: j.state() }
  }
  const seed = j.events.length
  const evs = () => j.events.slice(seed).filter((e) => e.chain === 'btc' && e.by !== 'api')
  const kinds = () => evs().map((e) => e.type)
  return { clock, chain, key, text, def, j, cfg, run, evs, kinds }
}

// ---------------------------------------------------------------------------------------------------------------- the happy path
test('a copies lane: copy = commit + reveal, an intent before each broadcast, the reveal after the commit landed, the readback = the part bytes', async () => {
  const r = rig({ copies: 2, text: 'héllo ₿ 漢字\nline two\n' })
  const { out, lane } = await r.run()
  assert.equal(out, 'copies-done')
  assert.equal(lane.state, 'copies-done')
  // the journal: per copy copy-built, then [intent, sent, included, readback] for the commit and for the reveal, then reassembled
  const seq = r.evs().map((e) => `${e.type}${e.type === 'intent' ? `:${(e.data.btc as { kind: string }).kind}` : ''}`)
  const one = ['copy-built', 'intent:commit', 'sent', 'included', 'readback', 'intent:reveal', 'sent', 'included', 'readback', 'reassembled']
  assert.deepEqual(seq, [...one, ...one, 'copies-done'])
  // every send carried its ticket and was journaled BEFORE it left (the intent's seq precedes the send in the call log)
  const sends = r.chain.sends()
  assert.equal(sends.length, 4)
  for (const s of sends) assert.match(s.ticket!, /^vt-ticket\/2\./, TICKET_HEADER)
  const intents = r.evs().filter((e) => e.type === 'intent')
  assert.deepEqual(sends.map((s) => s.txid), intents.map((e) => e.data.txId))   // one send per intent, in the intent order: the journal is ahead of the chain
  // the reveal of a copy was sent only after that copy's commit was in a block
  for (let c = 0; c < 2; c++) {
    const commitId = intents[c * 2].data.txId as string, revealId = intents[c * 2 + 1].data.txId as string
    assert.ok(r.chain.onChain(commitId) && r.chain.onChain(revealId))
    const commitIncluded = r.j.events.findIndex((e) => e.type === 'included' && e.data.txId === commitId), revealIntent = r.j.events.findIndex((e) => e.type === 'intent' && e.data.txId === revealId)
    assert.ok(commitIncluded > 0 && commitIncluded < revealIntent, 'the commit\'s inclusion is journaled before the reveal exists')
    // the reveal spends exactly the commit's output 0
    assert.equal(r.chain.txs.get(revealId)!.ins[0], `${commitId}:0`)
  }
  // readback: the reveal's witness holds the part bytes, and the journal says so
  const text = r.text
  for (const e of r.evs().filter((x) => x.type === 'readback')) assert.equal(e.data.ok, true, String(e.data.detail))
  const rev1 = r.chain.txs.get(intents[1].data.txId as string)!
  const wit = rev1.tx.getInput(0).finalScriptWitness!
  assert.equal(btcc.readbackReveal(r.key, utf8(text), { vin: [{ txinwitness: wit.map((w) => Buffer.from(w).toString('hex')) }], vout: [{ value: 0.00000546, scriptPubKey: { address: btcc.btcFromSecret('22'.repeat(32), 'local').p2tr } }] }).ok, true)
  // reassembled: the digest of the text, ok
  assert.deepEqual(r.evs().filter((e) => e.type === 'reassembled').map((e) => [e.data.copy, e.data.ok, e.data.sha256]), [[1, true, sha256Hex(utf8(text))], [2, true, sha256Hex(utf8(text))]])
  // the cap: the commit holds fee + value, the reveal 0; spent = Σ commit costs
  const cs = r.j.state().chains.btc!
  const cost = intents.filter((e) => (e.data.btc as { kind: string }).kind === 'commit').reduce((a, e) => a + BigInt(e.data.reserved as string), 0n)
  assert.equal(BigInt(cs.spent), cost)
  assert.equal(cs.copiesIncluded, 2)
  assert.equal(cs.phase, 'COPIES_DONE')
  // the lane's coins: change returned, the postage at the taproot address
  const left = await btcc.balanceOf(r.key.address)
  assert.equal(left, FUND - cost)
})

test('every btc event the lane journals is a valid event (validateEvent) and the intent shapes are exact', async () => {
  const r = rig()
  await r.run()
  for (const e of r.evs()) validateEvent(e.type, e.data, 'cli')
  const c = r.evs().find((e) => e.type === 'intent')!, rv = r.evs().filter((e) => e.type === 'intent')[1]
  assert.deepEqual(Object.keys(c.data.btc as object), ['kind', 'pubkey', 'fee', 'value', 'inputs'])
  assert.deepEqual(Object.keys(rv.data.btc as object), ['kind', 'pubkey', 'fee', 'commitVout'])
  assert.equal(c.data.payloadSha256, sha256Hex(utf8(r.text)))
  assert.equal(rv.data.payloadSha256, c.data.payloadSha256)
  assert.equal(rv.data.reserved, '0')
  const bad = (btc: unknown): void => assert.equal(guardOf(() => validateEvent('intent', { ...c.data, btc }, 'cli')), 'event.shape')
  bad({ ...(c.data.btc as object), kind: 'other' })
  bad({ ...(c.data.btc as object), extra: 1 })
  bad({ ...(c.data.btc as object), inputs: [] })
  bad({ ...(c.data.btc as object), inputs: ['b'.repeat(64) + ':1', 'a'.repeat(64) + ':1'] })   // not ascending
  bad({ ...(rv.data.btc as object), commitVout: -1 })
  assert.equal(guardOf(() => validateEvent('intent', { ...c.data, eth: { nonce: 1, tip: '1', maxFee: '1', gas: '1', to: '0x' + '1'.repeat(40) } }, 'cli')), 'event.shape')   // exactly one chain member
})

// ---------------------------------------------------------------------------------------------------------------- ambiguous answers
test('accepted, then a 502: the answer is not "not sent" — the lookup by txid sees it, nothing is sent twice', async () => {
  const r = rig()
  r.chain.setSendMode('accept-then-502')
  const { out } = await r.run()
  assert.equal(out, 'copies-done')
  const intents = r.evs().filter((e) => e.type === 'intent')
  for (const i of intents) assert.equal(r.chain.sendsOf(i.data.txId as string).length, 1, 'one send per tx')
  assert.equal(intents.length, 2)
  // the 502 is journaled unknown (never rejected); the lookup that sees the txid then makes it accepted
  const outcomes = r.evs().filter((e) => e.type === 'sent')
  assert.ok(outcomes.every((e) => e.data.outcome === 'unknown' || e.data.outcome === 'accepted'))
  for (const i of intents) assert.equal(outcomes.filter((e) => e.data.txId === i.data.txId).at(-1)!.data.outcome, 'accepted')
})
test('accepted, then a refusal (relay.btc-prevout is what a re-send of an accepted tx gets): no duplicate, the tx is found by txid', async () => {
  const r = rig()
  r.chain.setSendMode('accept-then-403')
  assert.equal((await r.run()).out, 'copies-done')
  for (const i of r.evs().filter((e) => e.type === 'intent')) assert.equal(r.chain.sendsOf(i.data.txId as string).length, 1)
})
test('a 502 that did NOT reach the node: the same bytes are sent again (one tx, one intent per part), never a new tx', async () => {
  const r = rig()
  r.chain.nextSend('drop-then-502')
  const { out } = await r.run()
  assert.equal(out, 'copies-done')
  const intents = r.evs().filter((e) => e.type === 'intent')
  assert.equal(intents.length, 2, 'no second intent: it is the same transaction')
  const commit = intents[0].data.txId as string
  assert.equal(r.chain.sendsOf(commit).length, 2)
  assert.equal(new Set(r.chain.sendsOf(commit).map((s) => (s.params[0] as string))).size, 1, 'the identical bytes')
  assert.deepEqual(r.evs().filter((e) => e.type === 'sent' && e.data.txId === commit).map((e) => e.data.outcome), ['unknown', 'accepted'])
  assert.equal(r.chain.txs.size, 2)
})
test('a transport failure on the send and an unreadable lookup: read again, send the same bytes again, still one tx', async () => {
  const r = rig()
  r.chain.nextSend('transport-fail')
  r.chain.unreadable(2)
  assert.equal((await r.run()).out, 'copies-done')
  assert.equal(r.chain.txs.size, 2)
  assert.equal(r.evs().filter((e) => e.type === 'intent').length, 2)
})
test('I-1: a send that never gets through ends the run `failed` with engine.btc-open — NO `stopped` is journaled, the attempt stays open, and a rerun sends the same bytes once', async () => {
  const r = rig()
  r.chain.setSendMode('drop-then-502')
  await assert.rejects(r.run({ extra: { retryMax: 3 } }), (e: unknown) => (e as { guardId?: string }).guardId === 'engine.btc-open')
  assert.equal(r.evs().filter((e) => e.type === 'intent').length, 1)
  assert.ok(!r.kinds().includes('stopped'), 'no stopped over an open attempt')
  const st = r.j.state().chains.btc!
  assert.notEqual(st.phase, 'STOPPED')
  assert.equal(st.openIntents.length, 1)
  assert.ok(r.evs().every((e) => e.type !== 'sent' || e.data.outcome === 'unknown'))
  assert.equal(r.chain.txs.size, 0)
  // the rerun (the node answers again): the same txid is sent and lands, then the reveal
  r.chain.setSendMode('ok')
  r.j.expire('btc')
  assert.equal((await r.run()).out, 'copies-done')
  const intents = r.evs().filter((e) => e.type === 'intent')
  assert.equal(intents.length, 2, 'no second commit')
  for (const i of intents) assert.equal(r.chain.sendsOf(i.data.txId as string).length >= 1, true)
  assert.equal(r.chain.sendsOf(intents[1].data.txId as string).length, 1, 'the reveal was sent once')
  assert.equal(r.j.state().chains.btc!.copiesIncluded, 1)
})
test('I-1: an outage while the commit waits for its block (accepted, then the node cannot be read past retryMax): the run fails open; once the node is back the rerun reconciles by txid and the reveal is sent once', async () => {
  const r = rig()
  // the commit is accepted; the lookups then fail for longer than retryMax rounds
  let sends = 0
  const first = r.run({ extra: { retryMax: 3 }, until: (e) => { if (e.type === 'sent' && ++sends === 1) { r.chain.unreadable(50) } return false } })
  await assert.rejects(first, (e: unknown) => (e as { guardId?: string }).guardId === 'engine.btc-open')
  const cid = r.evs().find((e) => e.type === 'intent')!.data.txId as string
  assert.ok(!r.kinds().includes('stopped'))
  assert.equal(r.j.state().chains.btc!.openIntents.length, 1)
  r.chain.unreadable(0)                                                   // the node is back; the commit confirms while the rerun waits
  r.j.expire('btc')
  const second = await r.run()
  assert.equal(second.out, 'copies-done')
  assert.equal(r.chain.sendsOf(cid).length, 1, 'the commit was sent once')
  const intents = r.evs().filter((e) => e.type === 'intent')
  assert.equal(intents.length, 2)
  assert.equal(r.chain.sendsOf(intents[1].data.txId as string).length, 1, 'the reveal was sent once')
  assert.ok(r.evs().some((e) => e.type === 'reconcile' && e.data.txId === cid && e.data.outcome === 'adopted'), 'found by txid in the mempool and adopted')
  assert.ok(r.evs().some((e) => e.type === 'included' && e.data.txId === cid))
})
test('I-1: btcAdapter.reconcile finds a landed commit by txid before the copy loop (reconcile included + readback) and adopts a mempool one', async () => {
  const r = rig()
  const first = await r.run({ until: (e) => e.type === 'sent' })
  assert.equal(first.out, 'aborted')
  const cid = r.evs().find((e) => e.type === 'intent')!.data.txId as string
  r.chain.mine()
  r.j.expire('btc')
  const second = await r.run()
  assert.equal(second.out, 'copies-done')
  const seq = r.evs().map((e) => `${e.type}:${String(e.data.txId ?? '').slice(0, 4)}`)
  const iR = seq.findIndex((x) => x === `reconcile:${cid.slice(0, 4)}`), iB = seq.findIndex((x, i) => i > 0 && x.startsWith('copy-built') && i > iR)
  assert.ok(iR >= 0 && iB > iR, 'reconciled before the next copy-built')
})
test('I-2: Stop while the commit waits for its block: the reveal is still sent, then the chain stops — before the NEXT copy, never between commit and reveal', async () => {
  let stop = false
  const r = rig({ copies: 2 })
  const { out, lane } = await r.run({ extra: { stopRequested: () => stop }, until: (e) => { if (e.type === 'sent') stop = true; return false } })
  assert.equal(out, 'stopped')
  assert.match(lane.reason, /stopped by the operator/)
  const st = r.j.state().chains.btc!
  assert.equal(st.copiesIncluded, 1, 'copy 1 is complete')
  assert.deepEqual(st.openIntents, [])
  assert.equal(r.chain.sends().length, 2)
  assert.deepEqual(r.evs().filter((e) => e.type === 'intent').map((e) => (e.data.btc as { kind: string }).kind), ['commit', 'reveal'])
  // a Stop that is already pending when a resumed copy (commit landed, reveal missing) starts does not stop it either
  const r2 = rig({ copies: 2 })
  const f = await r2.run({ until: (e) => e.type === 'readback' })
  assert.equal(f.out, 'aborted')
  r2.j.expire('btc')
  const g = await r2.run({ extra: { stopRequested: () => true } })
  assert.equal(g.out, 'stopped')
  assert.equal(r2.j.state().chains.btc!.copiesIncluded, 1, 'the resumed copy got its reveal before the Stop applied')
  assert.equal(r2.chain.sends().length, 2)
})
test('m-2: a rebuilt tx whose BYTES differ from the journaled intent (another input amount, the same txid) is refused engine.btc-rebuild', async () => {
  const r = rig()
  const first = await r.run({ until: (e) => e.type === 'intent' })
  assert.equal(first.out, 'aborted')
  const orig = r.chain.fetch
  void orig
  // gettxout answers a wrong amount for the commit's input: the BIP143 sighash differs, the txid does not
  const { configureRelay } = await import('../../src/engine/rpc.js')
  configureRelay({ base: 'http://relay.test', fetch: async (url, init) => {
    const body = typeof init.body === 'string' ? JSON.parse(init.body) : null
    if (body?.method === 'gettxout') { const res = await orig(url, init); const j = await res.json() as { result: { value: number } | null }; if (j.result) j.result.value += 0.00000001; return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, ...j }), { status: 200 }) }
    return orig(url, init)
  } })
  r.j.expire('btc')
  await assert.rejects(r.run(), (e: unknown) => (e as { guardId?: string }).guardId === 'engine.btc-rebuild')
  assert.equal(r.chain.sends().length, 0)
})
test('m-1: coin selection scans the lane\'s p2wpkh address only (never the postage address), and skips coins at the postage size or below', async () => {
  const r = rig({ copies: 2, fund: null })
  r.chain.fund(r.key.address, 546n)                                       // a foreign inscribed dust coin at the lane address
  r.chain.fund(r.key.address, 3_000n)
  const { out } = await r.run()
  assert.equal(out, 'copies-done')
  const dust = [...r.chain.outs].find(([, v]) => v.amount === 546n && v.address === r.key.address)!
  assert.equal(dust[1].spentBy, null, 'the dust coin was never spent')
  const scans = r.chain.calls.filter((c) => c.method === 'scantxoutset').map((c) => JSON.stringify(c.params))
  assert.ok(scans.length > 0 && scans.every((x) => x.includes(`addr(${r.key.address})`)), 'only the lane p2wpkh address is scanned')
})
test('m-3: the cap arithmetic — a landed/open commit holds fee + value, the reveal 0; the per-signature reserve is fee + value', async () => {
  const r = rig()
  const first = await r.run({ until: (e) => e.type === 'intent' })
  assert.equal(first.out, 'aborted')
  const it = r.evs().find((e) => e.type === 'intent')!, b = it.data.btc as { fee: string; value: string }
  assert.equal(it.data.reserved, String(BigInt(b.fee) + BigInt(b.value)))
  assert.equal(CapLedger.view(r.j.state(), 'btc', r.key.address).held, BigInt(b.fee) + BigInt(b.value), 'the ledger holds the whole outlay of the open commit')
  // the per-signature reserve alone refuses a cap between fee and fee + value (the per-copy check is not involved)
  const r2 = rig({ cap: '1' })
  const ledger = CapLedger.fromArmed({ ...r2.j.state(), armed: { ...r2.j.state().armed!, caps: { btc: { nativeCap: '700', usd: 0, priceAt: null, overCap: false, planned: '0' } } } }, 'btc', r2.key.address)
  const t = { k: 0, copy: 1, part: 1, parts: 2, payload: utf8(r2.text), textBytes: 1, state: 'planned' }
  const d = { journal: { append: async () => {}, intent: async () => { throw new Error('no intent may be journaled') } }, network: 'local', state: r2.j.state(), poll: 1000, clock: r2.clock, alive: () => true, notify: () => {}, key: r2.key, rate: 2n, ledger }
  assert.equal(await btcTx(t, d), 'exhausted')                           // a commit costs ~1100 sat in all, the fee alone is ~300: only fee + value exceeds 700
  assert.equal(r2.chain.sends().length, 0)
  ledger.close()
})
test('m-6: a fee rate above the tickets\' 500 sat/vB is a refusal (engine.btc-fee-rate), nothing is signed', () => {
  const key = btcc.btcFromSecret(V.key, 'local')
  assert.equal(guardOf(() => btcc.planCommit(key, utf8('x'), [{ txid: 'aa'.repeat(32), index: 0, amount: 10_000_000n }], 501n)), 'engine.btc-fee-rate')
})

// ---------------------------------------------------------------------------------------------------------------- ordering
test('a reveal is never built before its commit landed: refused engine.btc-order, no intent, no send', async () => {
  const r = rig()
  const grant = await r.j.client.lease(r.j.id, 'btc', 'acquire', 'cli')
  const ej = { append: async () => {}, intent: async () => { throw new Error('no intent must be journaled') }, ticket: async () => 'x' }
  const ledger = CapLedger.fromArmed(r.j.state(), 'btc', r.key.address)
  const t = { k: 1, copy: 1, part: 2, parts: 2, payload: utf8(r.text), textBytes: 1, state: 'planned' }
  const d = { journal: ej, network: 'local', state: r.j.state(), poll: 1000, clock: r.clock, alive: () => true, notify: () => {}, key: r.key, rate: 2n, ledger }
  assert.equal(await guardOfAsync(async () => { await btcTx(t, d) }), 'engine.btc-order')
  assert.equal(r.chain.sends().length, 0)
  assert.equal(grant.gen, 2)
  ledger.close()
  // also with a commit that is only in the mempool (not in a block)
  const r2 = rig({ blockAfterLookups: 0 })
  r2.chain.fund(r2.key.address, 1n)
  const commit = r2.chain.accept(btcc.buildCommit({ key: r2.key, body: utf8(r2.text), inputs: [{ ...[...r2.chain.outs].map(([k, v]) => ({ txid: k.split(':')[0], index: Number(k.split(':')[1]), amount: v.amount }))[0] }], value: 1000n, fee: 300n }).hex)
  assert.ok(commit.ok)
  const ledger2 = CapLedger.fromArmed(r2.j.state(), 'btc', r2.key.address)
  const d2 = { ...d, ledger: ledger2, state: r2.j.state(), resume: { copy: 1, nextPart: 2, landed: { 1: (commit as { id: string }).id } } }
  assert.equal(await guardOfAsync(async () => { await btcTx({ ...t }, d2) }), 'engine.btc-order')
  ledger2.close()
})
test('the commit is not seen as landed from a txid that is not the commit address\'s output', async () => {
  const r = rig({ blockAfterLookups: 0 })
  const some = [...r.chain.outs][0]
  r.chain.mine()
  const ledger = CapLedger.fromArmed(r.j.state(), 'btc', r.key.address)
  const t = { k: 1, copy: 1, part: 2, parts: 2, payload: utf8(r.text), textBytes: 1, state: 'planned' }
  const d = { journal: { append: async () => {}, intent: async () => { throw new Error('no') } }, network: 'local', state: r.j.state(), poll: 1000, clock: r.clock, alive: () => true, notify: () => {}, key: r.key, rate: 2n, ledger,
    resume: { copy: 1, nextPart: 2, landed: { 1: some[0].split(':')[0] } } }
  // a funding coin with no tx in the node's index is not a commit
  assert.equal(await guardOfAsync(async () => { await btcTx(t, d) }), 'engine.btc-order')
  ledger.close()
})

// ---------------------------------------------------------------------------------------------------------------- takeover
test('crash between the commit and the reveal: the takeover sends the reveal once (the commit is not sent again)', async () => {
  const r = rig()
  const first = await r.run({ until: (e) => e.type === 'readback' })     // dies right after the commit's readback
  assert.equal(first.out, 'aborted')
  assert.equal(r.chain.sends().length, 1)
  const commitId = r.evs().find((e) => e.type === 'intent')!.data.txId as string
  assert.ok(r.chain.onChain(commitId))
  r.j.expire('btc')
  const second = await r.run()
  assert.equal(second.out, 'copies-done')
  const intents = r.evs().filter((e) => e.type === 'intent')
  assert.equal(intents.length, 2)
  assert.equal(r.chain.sendsOf(commitId).length, 1, 'the commit was sent exactly once')
  assert.equal(r.chain.sendsOf(intents[1].data.txId as string).length, 1, 'the reveal was sent exactly once')
  assert.equal(r.chain.sends().length, 2)
  assert.equal(second.state.chains.btc!.copiesIncluded, 1)
})
test('crash after the reveal\'s intent, before its send: the takeover rebuilds the same bytes, reconciles (adopted) and sends it once', async () => {
  const r = rig()
  const first = await r.run({ until: (e) => e.type === 'intent' && (e.btc as { kind: string }).kind === 'reveal' })
  assert.equal(first.out, 'aborted')
  assert.equal(r.chain.sends().length, 1, 'only the commit left')
  const revealIntent = r.evs().filter((e) => e.type === 'intent')[1]
  assert.equal(r.j.state().chains.btc!.openIntents.length, 1)
  r.j.expire('btc')
  const second = await r.run()
  assert.equal(second.out, 'copies-done')
  assert.equal(r.evs().filter((e) => e.type === 'intent').length, 2, 'no new intent: the open one was taken over')
  const rid = revealIntent.data.txId as string
  assert.equal(r.chain.sendsOf(rid).length, 1)
  assert.equal(sha256Hex(hexToBytes(r.chain.txs.get(rid)!.hex)), revealIntent.data.rawSha256, 'the very bytes the intent journaled')
  assert.ok(r.evs().some((e) => e.type === 'reconcile' && e.data.txId === rid && e.data.outcome === 'adopted'))
})
test('crash after the reveal was SENT (in the mempool, no block yet): the takeover finds it by txid, sends nothing, waits for the block', async () => {
  const r = rig()
  let sents = 0
  const first = await r.run({ until: (e) => e.type === 'sent' && ++sents === 2 })     // dies right after the reveal's `sent`
  assert.equal(first.out, 'aborted')
  const rid = r.evs().filter((e) => e.type === 'intent')[1].data.txId as string
  assert.equal(r.chain.sends().length, 2)
  assert.ok(r.chain.inMempool(rid) || r.chain.onChain(rid))
  r.j.expire('btc')
  const second = await r.run()
  assert.equal(second.out, 'copies-done')
  assert.equal(r.chain.sendsOf(rid).length, 1, 'found by txid: not sent again')
  assert.equal(r.chain.sends().length, 2)
  assert.equal(r.evs().filter((e) => e.type === 'intent').length, 2)
})
test('crash after the commit\'s intent, before its send: rebuilt from the journaled intent, sent once, then the reveal', async () => {
  const r = rig()
  const first = await r.run({ until: (e) => e.type === 'intent' })
  assert.equal(first.out, 'aborted')
  assert.equal(r.chain.sends().length, 0)
  const commit = r.evs().find((e) => e.type === 'intent')!
  r.j.expire('btc')
  const second = await r.run()
  assert.equal(second.out, 'copies-done')
  assert.equal(r.evs().filter((e) => e.type === 'intent').length, 2)
  assert.equal(r.chain.sendsOf(commit.data.txId as string).length, 1)
  assert.equal(sha256Hex(hexToBytes(r.chain.txs.get(commit.data.txId as string)!.hex)), commit.data.rawSha256)
})
test('crash after the commit was sent and mined but before its inclusion was journaled: reconcile included, then the reveal; one send each', async () => {
  const r = rig()
  const first = await r.run({ until: (e) => e.type === 'sent' })
  assert.equal(first.out, 'aborted')
  const cid = r.evs().find((e) => e.type === 'intent')!.data.txId as string
  r.chain.mine()                                                         // the commit confirmed while nobody was running
  r.j.expire('btc')
  const second = await r.run()
  assert.equal(second.out, 'copies-done')
  assert.equal(r.chain.sendsOf(cid).length, 1)
  assert.ok(r.evs().some((e) => e.type === 'reconcile' && e.data.txId === cid && e.data.outcome === 'included'))
  assert.equal(r.evs().filter((e) => e.type === 'intent').length, 2)
})
test('a landed commit whose readback was never journaled is read back from the chain at the takeover, never sent again', async () => {
  const r = rig()
  const first = await r.run({ until: (e) => e.type === 'included' })
  assert.equal(first.out, 'aborted')
  const cid = r.evs().find((e) => e.type === 'intent')!.data.txId as string
  r.j.expire('btc')
  const second = await r.run()
  assert.equal(second.out, 'copies-done')
  assert.equal(r.chain.sendsOf(cid).length, 1)
  assert.equal(r.evs().filter((e) => e.type === 'readback' && e.data.txId === cid).length, 1)
})
test('an open attempt that is not on the chain and whose inputs were spent elsewhere: refused engine.btc-rebuild, nothing built beside it', async () => {
  const r = rig()
  const first = await r.run({ until: (e) => e.type === 'intent' })
  assert.equal(first.out, 'aborted')
  const commit = r.evs().find((e) => e.type === 'intent')!
  // another holder of this key spent the commit's input (a different tx)
  const input = (commit.data.btc as { inputs: string[] }).inputs[0].split(':')
  const other = btcc.buildCommit({ key: r.key, body: utf8('another text'), inputs: [{ txid: input[0], index: Number(input[1]), amount: FUND }], value: 5000n, fee: 400n })
  assert.ok(r.chain.accept(other.hex).ok)
  r.j.expire('btc')
  const grant = await r.j.client.lease(r.j.id, 'btc', 'acquire', 'cli')
  void grant
  r.j.expire('btc')
  await assert.rejects(r.run(), (e: unknown) => (e as { guardId?: string }).guardId === 'engine.btc-rebuild')
  assert.equal(r.evs().filter((e) => e.type === 'intent').length, 1, 'no second intent')
  assert.equal(r.chain.sendsOf(commit.data.txId as string).length, 0)
  assert.equal(r.j.state().chains.btc!.openIntents.length, 1, 'the attempt stays open')
})

// ---------------------------------------------------------------------------------------------------------------- cap, funds, network
test('the cap is checked once, before the commit, for the whole copy: a cap under the outlay stops the lane before any intent', async () => {
  const r = rig({ cap: '1000' })
  const { out, lane } = await r.run()
  assert.equal(out, 'stopped')
  assert.match(lane.reason, /spend cap/)
  assert.equal(r.evs().filter((e) => e.type === 'intent').length, 0)
  assert.equal(r.chain.sends().length, 0)
})
test('not enough funds for a copy: the lane drains (nothing signed)', async () => {
  const r = rig({ fund: 700n })
  const { out } = await r.run()
  assert.equal(out, 'drained')
  assert.equal(r.evs().filter((e) => e.type === 'intent').length, 0)
  assert.ok(r.kinds().includes('drained'))
})
test('a commit spends several lane outputs when one is not enough, and the cap holds fee + value', async () => {
  const r = rig({ fund: null })
  for (let i = 0; i < 3; i++) r.chain.fund(r.key.address, 700n)
  const { out } = await r.run()
  assert.equal(out, 'copies-done')
  const commit = r.evs().find((e) => e.type === 'intent')!
  const b = commit.data.btc as { inputs: string[]; fee: string; value: string }
  assert.ok(b.inputs.length >= 2 && b.inputs.length <= 8)
  assert.deepEqual(b.inputs, [...b.inputs].sort())
  assert.equal(commit.data.reserved, String(BigInt(b.fee) + BigInt(b.value)))
})
test('the lane runs on a local network only (M4), with a key of its network', async () => {
  const r = rig()
  const grant = await r.j.client.lease(r.j.id, 'btc', 'acquire', 'cli')
  void grant
  const mk = (network: string, key = r.key) => runCopiesLane(r.cfg, key, newLaneState(r.cfg), { journal: {}, network, state: r.j.state(), clock: r.clock, alive: () => true, notify: () => {}, poll: 1 })
  await assert.rejects(mk('testnet'), /local network only/)
  await assert.rejects(mk('local', btcc.btcFromSecret('22'.repeat(32), 'testnet')), /another btc key/)
})

// ---------------------------------------------------------------------------------------------------------------- the relay client
test('btc_send goes to POST /relay/btc/send as { hex } with the ticket header; a send without a well-formed ticket never leaves', async () => {
  const seen: Array<{ url: string; body: string; ticket: string | null }> = []
  configureRelay({ base: 'http://relay.test', fetch: async (url, init) => { seen.push({ url, body: String(init.body), ticket: ((init.headers ?? {}) as Record<string, string>)[TICKET_HEADER] ?? null }); return new Response(JSON.stringify({ txid: 'ab'.repeat(32) }), { status: 200 }) } })
  const ticket = `vt-ticket/2.${'a'.repeat(10)}.${'A'.repeat(43)}`
  assert.equal(await btcc.send('00ff', ticket), 'ab'.repeat(32))
  assert.deepEqual(seen as unknown, [{ url: 'http://relay.test/relay/btc/send', body: '{"hex":"00ff"}', ticket }])
  assert.equal(guardOf(() => btcc.send('00ff', undefined)), 'engine.no-ticket')
  assert.equal(seen.length, 1)
  // reads are plain JSON-RPC on /relay/btc, with no ticket and no per-endpoint route
  seen.length = 0
  configureRelay({ base: 'http://relay.test', fetch: async (url, init) => { seen.push({ url, body: String(init.body), ticket: null }); return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: 7 }), { status: 200 }) } })
  assert.equal(await rpc('btc', 'getblockcount', []), 7)
  assert.equal(seen[0].url, 'http://relay.test/relay/btc')
  await assert.rejects(rpc('btc', 'getblockcount', [], { ep: 0 }), /per-endpoint/)
})
test('every failure of btc_send is a transport or refusal error, never a definitive "rejected": nothing it answers means "not sent"', async () => {
  const answer = (status: number, body: unknown) => configureRelay({ base: 'http://relay.test', fetch: async () => new Response(JSON.stringify(body), { status }) })
  const ticket = `vt-ticket/2.${'a'.repeat(10)}.${'A'.repeat(43)}`
  for (const [status, body, cls] of [[403, { error: { message: 'relay.btc-prevout' } }, 'RelayRefused'], [502, { error: { message: 'relay.upstream-shape' } }, 'TransportError'], [500, { error: { message: 'send outcome unknown' } }, 'TransportError'],
    [200, { txid: 7 }, 'TransportError'], [200, { error: { code: -26, message: 'x' } }, 'TransportError']] as const) {
    answer(status, body)
    await assert.rejects(btcc.send('00', ticket), (e: Error) => e.constructor.name === cls, `${status} ${JSON.stringify(body)}`)
  }
  configureRelay({ base: 'http://relay.test', fetch: async () => { throw new TypeError('fetch failed') } })
  await assert.rejects(btcc.send('00', ticket), (e: Error) => e.constructor.name === 'TransportError')
})
test('getTx: absent only for the txindex-on "No such mempool or blockchain transaction"; every other failure throws (unknown, not absent)', async () => {
  const reply = (r: Response) => configureRelay({ base: 'http://relay.test', fetch: async () => r.clone() })
  reply(new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -5, message: 'No such mempool or blockchain transaction. Use gettransaction for wallet transactions.' } }), { status: 200 }))
  assert.equal(await btcc.getTx('a'.repeat(64)), null)
  reply(new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -5, message: 'No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries.' } }), { status: 200 }))
  await assert.rejects(btcc.getTx('a'.repeat(64)))
  reply(new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -5, message: 'something else' } }), { status: 200 }))
  await assert.rejects(btcc.getTx('a'.repeat(64)))
  reply(new Response(JSON.stringify({ error: { message: 'relay.upstream-shape', code: -32000 } }), { status: 502 }))
  await assert.rejects(btcc.getTx('a'.repeat(64)))
  reply(new Response('not json', { status: 502 }))
  await assert.rejects(btcc.getTx('a'.repeat(64)))
})

// ---------------------------------------------------------------------------------------------------------------- coin selection and sighash
test('a later copy\'s commit never spends an earlier copy\'s postage (the inscription outputs are not lane coins), and every input is signed SIGHASH_ALL / DEFAULT', async () => {
  const r = rig({ copies: 3 })
  const { out } = await r.run()
  assert.equal(out, 'copies-done')
  const intents = r.evs().filter((e) => e.type === 'intent')
  const reveals = intents.filter((e) => (e.data.btc as { kind: string }).kind === 'reveal').map((e) => e.data.txId as string)
  const postage = new Set(reveals.map((id) => `${id}:0`))
  for (const c of intents.filter((e) => (e.data.btc as { kind: string }).kind === 'commit')) {
    for (const op of (c.data.btc as { inputs: string[] }).inputs) assert.ok(!postage.has(op), `commit spends the postage ${op}`)
    const tx = r.chain.txs.get(c.data.txId as string)!
    for (let i = 0; i < tx.tx.inputsLength; i++) {
      const sig = tx.tx.getInput(i).finalScriptWitness![0]
      assert.equal(sig[sig.length - 1], 0x01, 'ECDSA input signed SIGHASH_ALL')
    }
  }
  for (const id of reveals) assert.equal(r.chain.txs.get(id)!.tx.getInput(0).finalScriptWitness![0].length, 64, 'schnorr SIGHASH_DEFAULT (64 bytes)')
  // the postage outputs are still unspent at the end
  for (const op of postage) assert.equal(r.chain.outs.get(op)!.spentBy, null)
  // and the lane\'s spendable set (utxosOf) never lists them
  assert.ok((await btcc.utxosOf(r.key.address)).every((u) => !postage.has(`${u.txid}:${u.index}`)))
})

// ---------------------------------------------------------------------------------------------------------------- fix round 2
test('R2 I-1: planning-retry exhaustion over a LANDED commit never journals stopped: the reveal-only copy plans nothing and finishes', async () => {
  const r = rig()
  assert.equal((await r.run({ until: (e) => e.type === 'readback' })).out, 'aborted')
  r.chain.failScans(1000)                                                // the node answers getrawtransaction but not scantxoutset
  r.j.expire('btc')
  assert.equal((await r.run({ extra: { retryMax: 3 } })).out, 'copies-done')
  assert.ok(!r.kinds().includes('stopped'))
  assert.equal(r.j.state().chains.btc!.copiesIncluded, 1)
})
test('R2 I-1: ... and over an OPEN commit (accepted, not yet mined)', async () => {
  const r = rig()
  assert.equal((await r.run({ until: (e) => e.type === 'sent' })).out, 'aborted')
  r.chain.failScans(1000)
  r.j.expire('btc')
  assert.equal((await r.run({ extra: { retryMax: 3 } })).out, 'copies-done')
  assert.ok(!r.kinds().includes('stopped'))
  assert.equal(r.chain.sends().length, 2)
})
test('R2 I-1: with no commit journaled, planning exhaustion may still stop the chain (nothing is stranded)', async () => {
  const r = rig()
  r.chain.failScans(1000)
  const { out } = await r.run({ extra: { retryMax: 2, retryMs: 1 } })
  assert.equal(out, 'failed')
  assert.ok(r.kinds().includes('stopped'))
})
test('R2 I-2: a Stop pending at a takeover with an UNCONFIRMED commit waits for the commit, sends the reveal, THEN stops', async () => {
  const r = rig({ copies: 2 })
  assert.equal((await r.run({ until: (e) => e.type === 'sent' })).out, 'aborted')
  assert.ok(r.chain.inMempool(r.evs().find((e) => e.type === 'intent')!.data.txId as string))
  r.j.expire('btc')
  const { out } = await r.run({ extra: { stopRequested: () => true } })
  assert.equal(out, 'stopped')
  const st = r.j.state().chains.btc!
  assert.equal(st.copiesIncluded, 1)
  assert.deepEqual(st.openIntents, [])
  assert.equal(r.chain.sends().length, 2, 'the commit once, the reveal once, nothing of copy 2')
})
test('Eminors (E7b m-5): a JOURNALED Stop (stop-requested, as the API writes it) after the commit landed: the one reveal is admitted, then the chain stops; no new commit', async () => {
  for (const stopAt of ['readback', 'sent'] as const) {            // the commit landed / the commit only in the mempool
    const r = rig({ copies: 2 })
    assert.equal((await r.run({ until: (e) => e.type === stopAt })).out, 'aborted', stopAt)
    r.j.requestStop('btc')
    r.j.expire('btc')
    const { out } = await r.run({ extra: { stopRequested: () => true } })
    assert.equal(out, 'stopped', stopAt)
    const st = r.j.state().chains.btc!
    assert.equal(st.copiesIncluded, 1, `${stopAt}: copy 1 got its reveal`)
    assert.deepEqual(st.openIntents, [])
    assert.deepEqual(r.evs().filter((e) => e.type === 'intent').map((e) => (e.data.btc as { kind: string }).kind), ['commit', 'reveal'], `${stopAt}: nothing of copy 2`)
  }
})
test('R2 gate: the shared append gate refuses stopped / drained / copies-done on a btc chain while a commit lacks its reveal (engine.btc-open), and allows them after', async () => {
  const r = rig()
  assert.equal((await r.run({ until: (e) => e.type === 'sent' })).out, 'aborted')          // an open commit
  r.j.expire('btc')
  const grant = await r.j.client.lease(r.j.id, 'btc', 'acquire', 'cli')
  for (const [type, data] of [['stopped', { reason: 'x' }], ['drained', { balance: '0', nextCost: '1', copy: 1 }], ['copies-done', { copies: 1 }]] as const) {
    await assert.rejects(r.j.client.append(r.j.id, 'btc', grant.gen, type, data), (e: unknown) => (e as { guardId?: string }).guardId === 'engine.btc-open', type)
  }
  r.chain.mine()
  r.j.expire('btc')
  assert.equal((await r.run()).out, 'copies-done')                          // finishing is allowed once the reveal landed
  assert.ok(r.j.state().chains.btc!.phase === 'COPIES_DONE')
})
test('R3 I-1: an input spent elsewhere IN A BLOCK is positive evidence: `stuck` is journaled, the operator\'s mark-failed is accepted and a rerun lands attempt 2 with replaces null', async () => {
  const r = rig()
  assert.equal((await r.run({ until: (e) => e.type === 'intent' })).out, 'aborted')
  const commit = r.evs().find((e) => e.type === 'intent')!
  const input = (commit.data.btc as { inputs: string[] }).inputs[0].split(':')
  const other = btcc.buildCommit({ key: r.key, body: utf8('another text'), inputs: [{ txid: input[0], index: Number(input[1]), amount: FUND }], value: 5000n, fee: 400n })
  assert.ok(r.chain.accept(other.hex).ok)
  // 1. spent only in the MEMPOOL: no evidence — engine.btc-rebuild, nothing stuck, the attempt keeps waiting
  r.j.expire('btc')
  await assert.rejects(r.run(), (e: unknown) => (e as { guardId?: string }).guardId === 'engine.btc-rebuild')
  assert.ok(!r.kinds().includes('stuck'))
  assert.equal(r.j.state().chains.btc!.phase === 'STUCK', false)
  // 2. spent in a BLOCK by another tx: stuck with the evidence
  r.chain.mine()
  r.j.expire('btc')
  await assert.rejects(r.run(), (e: unknown) => (e as { guardId?: string }).guardId === 'engine.btc-rebuild')
  const stuck = r.evs().filter((e) => e.type === 'stuck')
  assert.equal(stuck.length, 1)
  assert.equal(stuck[0].data.txId, commit.data.txId)
  assert.match(String(stuck[0].data.reason), /in a block by another transaction.*mark-failed/)
  assert.equal(r.j.state().chains.btc!.phase, 'STUCK')
  assert.equal(r.chain.sends().length, 0)
  // 3. the operator marks it failed; the gate admits the next attempt and the chain's end
  r.j.apiEvent('resolved', { txId: commit.data.txId, action: 'mark-failed', typed: null }, 'btc', 'operator')
  r.j.expire('btc')
  assert.equal((await r.run()).out, 'copies-done')
  const intents = r.evs().filter((e) => e.type === 'intent')
  assert.ok(intents.length >= 3 && intents.every((e) => e.data.replaces === null))
  assert.deepEqual(intents.map((e) => e.data.attempt).slice(0, 2), [1, 2])
  assert.equal(r.j.state().chains.btc!.copiesIncluded, 1)
})
test('R3 I-1: a mempool drop (the commit accepted, then gone, its input unspent again) is never stuck: the same bytes go again', async () => {
  const r = rig()
  assert.equal((await r.run({ until: (e) => e.type === 'intent' })).out, 'aborted')
  r.j.expire('btc')
  assert.equal((await r.run()).out, 'copies-done')
  assert.ok(!r.kinds().includes('stuck'))
  // an unreadable funding lookup is not evidence either
  const r2 = rig()
  assert.equal((await r2.run({ until: (e) => e.type === 'intent' })).out, 'aborted')
  const c2 = r2.evs().find((e) => e.type === 'intent')!
  const inp = (c2.data.btc as { inputs: string[] }).inputs[0].split(':')
  r2.chain.accept(btcc.buildCommit({ key: r2.key, body: utf8('x'), inputs: [{ txid: inp[0], index: Number(inp[1]), amount: FUND }], value: 5000n, fee: 400n }).hex)
  r2.chain.mine()
  r2.chain.unreadable(1)                                                 // the funding tx cannot be read: no proof either way
  r2.j.expire('btc')
  await assert.rejects(r2.run(), (e: unknown) => ['engine.btc-rebuild', 'engine.btc-open'].includes((e as { guardId?: string }).guardId ?? ''))
  assert.ok(!r2.kinds().includes('stuck'))
})
test('E7-fix3 m-1: a commit that lands between the "absent" lookup and the input check is NOT journaled stuck (re-read by txid: seen -> not dead); the rerun lands it', async () => {
  const r = rig()
  assert.equal((await r.run({ until: (e) => e.type === 'intent' })).out, 'aborted')
  const commit = r.evs().find((e) => e.type === 'intent')!
  const bt = commit.data.btc as { inputs: string[]; value: string; fee: string }
  const [txid, index] = bt.inputs[0].split(':')
  const same = btcc.buildCommit({ key: r.key, body: planLaneCopy(r.cfg, 1)[0].payload, inputs: [{ txid, index: Number(index), amount: FUND }], value: BigInt(bt.value), fee: BigInt(bt.fee) })
  assert.equal(same.txid, commit.data.txId, 'the very commit the holder journaled')
  // the first include-mempool gettxout (the rebuild's input read) finds the input spent: the commit itself was accepted and mined in between
  let fired = false
  configureRelay({ base: 'http://relay.test', fetch: (async (input: unknown, init?: { body?: unknown }) => {
    const b = JSON.parse(String(init?.body ?? '{}')) as { method?: string; params?: unknown[] }
    if (!fired && b.method === 'gettxout' && b.params?.[2] !== false) { fired = true; assert.ok(r.chain.accept(same.hex).ok); r.chain.mine() }
    return r.chain.fetch(input as never, init as never)
  }) as never })
  r.j.expire('btc')
  await assert.rejects(r.run(), (e: unknown) => (e as { guardId?: string }).guardId === 'engine.btc-rebuild')
  assert.ok(fired)
  assert.ok(!r.kinds().includes('stuck'), 'no stuck: the commit is on the chain')
  assert.equal(r.j.state().chains.btc!.phase === 'STUCK', false)
  configureRelay({ base: 'http://relay.test', fetch: r.chain.fetch })
  r.j.expire('btc')
  assert.equal((await r.run()).out, 'copies-done')
})
test('E7b m-6: a raw read error (a node blip) at the reveal\'s commit lookup or at a landed tx is engine.btc-open, never a bare error; nothing is sent', async () => {
  for (const [stopAt, what] of [['readback', 'the commit lookup of a new reveal'], ['included', 'the lookup of a landed tx']] as const) {
    const r = rig()
    assert.equal((await r.run({ until: (e) => e.type === stopAt })).out, 'aborted', what)
    const sent = r.chain.sends().length
    r.j.expire('btc')
    r.chain.unreadable(1)
    await assert.rejects(r.run(), (e: unknown) => (e as { guardId?: string }).guardId === 'engine.btc-open', what)
    assert.equal(r.chain.sends().length, sent, `${what}: nothing was sent`)
    assert.ok(!r.kinds().includes('stopped'), `${what}: never stopped`)
    r.j.expire('btc')
    assert.equal((await r.run()).out, 'copies-done', `${what}: the rerun finishes`)
  }
})
// ---------------------------------------------------------------------------------------------------------------- Eminors fix round 1
test('Eminors m-4: a commit that lands between the lookups is refused with its OWN reason (it is on the chain now), and a real stuck names the re-read and the real ids', async () => {
  // (a) the race: the reason says the commit is on the chain, not "its input is spent in the mempool"
  const r = rig()
  assert.equal((await r.run({ until: (e) => e.type === 'intent' })).out, 'aborted')
  const commit = r.evs().find((e) => e.type === 'intent')!
  const bt = commit.data.btc as { inputs: string[]; value: string; fee: string }
  const [txid, index] = bt.inputs[0].split(':')
  const same = btcc.buildCommit({ key: r.key, body: planLaneCopy(r.cfg, 1)[0].payload, inputs: [{ txid, index: Number(index), amount: FUND }], value: BigInt(bt.value), fee: BigInt(bt.fee) })
  let fired = false
  configureRelay({ base: 'http://relay.test', fetch: (async (input: unknown, init?: { body?: unknown }) => {
    const b = JSON.parse(String(init?.body ?? '{}')) as { method?: string; params?: unknown[] }
    if (!fired && b.method === 'gettxout' && b.params?.[2] !== false) { fired = true; r.chain.accept(same.hex); r.chain.mine() }
    return r.chain.fetch(input as never, init as never)
  }) as never })
  r.j.expire('btc')
  await assert.rejects(r.run(), (e: unknown) => (e as { guardId?: string }).guardId === 'engine.btc-rebuild' && /on the chain now/.test((e as Error).message) && !/in the mempool, by this tx or another/.test((e as Error).message))
  configureRelay({ base: 'http://relay.test', fetch: r.chain.fetch })
  // (b) a true stuck: no placeholders, the real job id and txId, and the evidence (absent by txid, again after the in-block spend)
  const r2 = rig()
  assert.equal((await r2.run({ until: (e) => e.type === 'intent' })).out, 'aborted')
  const c2 = r2.evs().find((e) => e.type === 'intent')!, i2 = (c2.data.btc as { inputs: string[] }).inputs[0].split(':')
  assert.ok(r2.chain.accept(btcc.buildCommit({ key: r2.key, body: utf8('another text'), inputs: [{ txid: i2[0], index: Number(i2[1]), amount: FUND }], value: 5000n, fee: 400n }).hex).ok)
  r2.chain.mine()
  r2.j.expire('btc')
  await assert.rejects(r2.run({ extra: { jobId: r2.j.id } }), (e: unknown) => (e as { guardId?: string }).guardId === 'engine.btc-rebuild')
  const reason = String(r2.evs().find((e) => e.type === 'stuck')!.data.reason)
  assert.ok(!/<job>|<txId>/.test(reason), reason)
  assert.ok(reason.includes(r2.j.id) && reason.includes(String(c2.data.txId).slice(0, 12)), 'the real job id and the txid prefix')
  assert.match(reason, /absent by txid.*again after that in-block spend/)
})

test('Eminors E7b m-2 (HM8): a commit with NO change output (the leftover goes to the fee) rebuilt with another input amount has the SAME txid and other bytes: refused engine.btc-rebuild', async () => {
  const probe = rig()
  const body = planLaneCopy(probe.cfg, 1)[0].payload
  const p = btcc.planCommit(probe.key, body, [{ txid: '11'.repeat(32), index: 0, amount: 10_000_000n }], 2n)
  const fund = p.value + p.fee + 100n                                       // the 100 sat leftover is below the dust limit: no change output
  const r = rig({ fund })
  assert.equal((await r.run({ until: (e) => e.type === 'intent' })).out, 'aborted')
  const bt = r.evs().find((e) => e.type === 'intent')!.data.btc as { fee: string }
  assert.equal(BigInt(bt.fee), p.fee + 100n, 'no change output: the leftover is in the fee')
  const orig = r.chain.fetch
  configureRelay({ base: 'http://relay.test', fetch: async (url: string, init: RequestInit) => {
    const body = typeof init.body === 'string' ? JSON.parse(init.body) : null
    if (body?.method === 'gettxout') { const res = await orig(url as never, init as never); const j = await res.json() as { result: { value: number } | null }; if (j.result) j.result.value += 0.00000001; return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, ...j }), { status: 200 }) }
    return orig(url as never, init as never)
  } })
  r.j.expire('btc')
  await assert.rejects(r.run(), (e: unknown) => (e as { guardId?: string }).guardId === 'engine.btc-rebuild' && /bytes differ/.test((e as Error).message))
  assert.equal(r.chain.sends().length, 0)
  configureRelay({ base: 'http://relay.test', fetch: orig })
})

test('Eminors E7b m-2 (HM9): a coin at the postage size is NEVER selected, even when the lane would otherwise be one input short', async () => {
  const probe = rig()
  const body = planLaneCopy(probe.cfg, 1)[0].payload
  const p = btcc.planCommit(probe.key, body, [{ txid: '11'.repeat(32), index: 0, amount: 10_000_000n }], 2n)
  const r = rig({ fund: null })
  r.chain.fund(r.key.address, p.value + p.fee - 100n)                         // not enough alone
  const dust = r.chain.fund(r.key.address, 546n)                              // enough together, if the dust coin were used
  const { out } = await r.run()
  assert.notEqual(out, 'copies-done')
  assert.equal(r.chain.sends().length, 0, 'nothing was signed')
  assert.equal(r.chain.outs.get(`${dust.txid}:${dust.vout}`)!.spentBy, null)
})

test('Eminors E7b m-2 (HM7): the takeover shortcut in decide() needs an OPEN commit attempt; a group whose only attempt is dead (marked failed) goes through the funding decision', async () => {
  const r = rig()
  assert.equal((await r.run({ until: (e) => e.type === 'intent' })).out, 'aborted')
  const commit = r.evs().find((e) => e.type === 'intent')!, inp = (commit.data.btc as { inputs: string[] }).inputs[0].split(':')
  assert.ok(r.chain.accept(btcc.buildCommit({ key: r.key, body: utf8('another text'), inputs: [{ txid: inp[0], index: Number(inp[1]), amount: FUND }], value: FUND - 400n, fee: 400n }).hex).ok)   // spends the whole coin: the lane is left with nothing
  r.chain.mine()
  r.j.expire('btc')
  await assert.rejects(r.run(), (e: unknown) => (e as { guardId?: string }).guardId === 'engine.btc-rebuild')
  r.j.apiEvent('resolved', { txId: commit.data.txId, action: 'mark-failed', typed: null }, 'btc', 'operator')
  r.j.expire('btc')
  const x = await r.run()
  assert.equal(x.out, 'drained', 'a dead attempt is not "a commit an earlier holder journaled": the funding decision is made, and the lane has nothing left')
  assert.equal(r.evs().filter((e) => e.type === 'intent').length, 1, 'no second commit')
  assert.deepEqual(r.kinds().slice(r.kinds().indexOf('resolved') + 1), ['drained'], 'decided by the funding decision, not by a takeover shortcut')
})

test('Eminors m-3: a node blip on getblockheader while a commit lands is engine.btc-open (the landed tx stays open), then the rerun finishes', async () => {
  const r = rig()
  r.chain.failHeaders(1)
  await assert.rejects(r.run(), (e: unknown) => (e as { guardId?: string }).guardId === 'engine.btc-open')
  assert.ok(!r.kinds().includes('stopped'))
  r.j.expire('btc')
  assert.equal((await r.run()).out, 'copies-done')
})

test('Eminors m-2: every caller of the one "commit without reveal" predicate counts a REJECTED commit attempt (state view, reducer view, lane copyInFlight)', async () => {
  const r = rig()
  assert.equal((await r.run({ until: (e) => e.type === 'intent' })).out, 'aborted')
  const commit = r.evs().find((e) => e.type === 'intent')!
  r.j.expire('btc')
  const grant = await r.j.client.lease(r.j.id, 'btc', 'acquire', 'cli')
  await r.j.client.append(r.j.id, 'btc', grant.gen, 'sent', { txId: commit.data.txId, outcome: 'rejected', reason: 'x' })
  const st = r.j.state()
  assert.equal(st.chains.btc!.txs[0].state, 'failed', 'the group view is "failed": the old inline predicate would let the chain end')
  const ev = { chain: 'btc', type: 'stopped', data: { reason: 'x' } }
  assert.equal(guardOf(() => assertEventAllowed(r.def, st, ev)), 'engine.btc-open', 'JobState view')
  const reducer = createReducer(r.def); for (const e of r.j.events) reducer.apply(e)
  assert.equal(guardOf(() => assertEventAllowed(r.def, { reducer, corrupt: null }, ev)), 'engine.btc-open', 'reducer view')
  const A = btcAdapter(r.cfg, r.key, { state: st, network: 'local' })
  assert.equal(A.copyInFlight(1), true, 'the lane')
  assert.equal(A.copyInFlight(2), false)
})

test('Eminors m-7: `reconcile expired / nonce-consumed` on a btc attempt is refused by the append gate, and a journal that holds one anyway makes the reconcile fail closed (nothing is read as "absent")', async () => {
  const r = rig()
  assert.equal((await r.run({ until: (e) => e.type === 'intent' })).out, 'aborted')
  const commit = r.evs().find((e) => e.type === 'intent')!
  r.j.expire('btc')
  const grant = await r.j.client.lease(r.j.id, 'btc', 'acquire', 'cli')
  for (const outcome of ['expired', 'nonce-consumed']) {
    await assert.rejects(r.j.client.append(r.j.id, 'btc', grant.gen, 'reconcile', { txId: commit.data.txId, outcome }), (e: unknown) => (e as { guardId?: string }).guardId === 'job.state', outcome)
  }
  assert.equal(guardOf(() => assertEventAllowed(r.def, r.j.state(), { chain: 'btc', type: 'reconcile', data: { txId: commit.data.txId, outcome: 'adopted' } })), null, 'adopted is still fine')
  // a foreign writer's journal: the dead outcome is in the journal already
  const evs = r.j.events.map((e) => e)
  evs.push({ ...evs[evs.length - 1], seq: evs.length, type: 'reconcile', chain: 'btc', by: 'cli', data: { txId: commit.data.txId, outcome: 'expired' } } as never)
  const dead = reduce(r.def, evs)
  const out = await reconcileChain({ chain: 'btc', state: dead, grant, journal: { append: async () => { throw new Error('nothing may be journaled') } } as never, clock: r.clock, poll: 1, alive: () => true, address: r.key.address, network: 'local', solEndpoints: 1, payloadOf: () => null, btcKey: r.key as never })
  assert.equal(out.ok, false)
  assert.match((out as { why: string }).why, /journaled dead.*not looked up by txid/)
})
test('Eminors E7-fix3 m-3: never stuck when the FUNDING read faults (the 2nd getrawtransaction fails), when the funding tx is unconfirmed, or when only the mempool spends the input; `stopped` is admitted after mark-failed', async () => {
  const spend = (r: ReturnType<typeof rig>) => {
    const c = r.evs().find((e) => e.type === 'intent')!, i = (c.data.btc as { inputs: string[] }).inputs[0].split(':')
    return { c, i, other: btcc.buildCommit({ key: r.key, body: utf8('another text'), inputs: [{ txid: i[0], index: Number(i[1]), amount: FUND }], value: 5000n, fee: 400n }).hex }
  }
  // (a) the funding read faults: spent in a block by another tx, but the lane cannot prove it
  const a = rig()
  assert.equal((await a.run({ until: (e) => e.type === 'intent' })).out, 'aborted')
  const sa = spend(a); a.chain.accept(sa.other); a.chain.mine()
  let reads = 0
  configureRelay({ base: 'http://relay.test', fetch: (async (input: unknown, init?: { body?: unknown }) => {
    const b = JSON.parse(String(init?.body ?? '{}')) as { method?: string }
    if (b.method === 'getrawtransaction' && ++reads === 2) return new Response(JSON.stringify({ error: { message: 'upstream timeout', code: -32099 } }), { status: 502 })
    return a.chain.fetch(input as never, init as never)
  }) as never })
  a.j.expire('btc')
  await assert.rejects(a.run(), (e: unknown) => ['engine.btc-open', 'engine.btc-rebuild'].includes((e as { guardId?: string }).guardId ?? ''))
  assert.ok(!a.kinds().includes('stuck'), 'a faulted funding read is no evidence')
  configureRelay({ base: 'http://relay.test', fetch: a.chain.fetch })
  // (b) only the mempool spends the input (nothing mined): never stuck
  const b = rig()
  assert.equal((await b.run({ until: (e) => e.type === 'intent' })).out, 'aborted')
  b.chain.accept(spend(b).other)
  b.j.expire('btc')
  await assert.rejects(b.run(), (e: unknown) => (e as { guardId?: string }).guardId === 'engine.btc-rebuild')
  assert.ok(!b.kinds().includes('stuck'))
  // (c) after a true stuck + mark-failed the chain may END: `stopped` is admitted (nothing is stranded)
  const c = rig()
  assert.equal((await c.run({ until: (e) => e.type === 'intent' })).out, 'aborted')
  const sc = spend(c); c.chain.accept(sc.other); c.chain.mine()
  c.j.expire('btc')
  await assert.rejects(c.run(), (e: unknown) => (e as { guardId?: string }).guardId === 'engine.btc-rebuild')
  assert.equal(guardOf(() => assertEventAllowed(c.def, c.j.state(), { chain: 'btc', type: 'stopped', data: { reason: 'x' } })), 'engine.btc-open', 'stuck: still stranded')
  c.j.apiEvent('resolved', { txId: sc.c.data.txId, action: 'mark-failed', typed: null }, 'btc', 'operator')
  assert.equal(guardOf(() => assertEventAllowed(c.def, c.j.state(), { chain: 'btc', type: 'stopped', data: { reason: 'x' } })), null, 'after mark-failed the chain may end')
})
test('R3 m-1: the gate also refuses an ending over a LANDED commit without its reveal (both state views, all three events); the reveal then lets the chain end', async () => {
  const r = rig()
  assert.equal((await r.run({ until: (e) => e.type === 'readback' })).out, 'aborted')           // the commit landed and read back; no reveal
  r.j.expire('btc')
  const grant = await r.j.client.lease(r.j.id, 'btc', 'acquire', 'cli')
  const events = [['stopped', { reason: 'x' }], ['drained', { balance: '0', nextCost: '1', copy: 1 }], ['copies-done', { copies: 1 }]] as const
  for (const [type, data] of events) {
    await assert.rejects(r.j.client.append(r.j.id, 'btc', grant.gen, type, data), (e: unknown) => (e as { guardId?: string }).guardId === 'engine.btc-open', type)
    for (const view of [r.j.state(), { reducer: createReducer(r.def), corrupt: null }] as const) {
      if ('reducer' in view) for (const ev of r.j.events) view.reducer.apply(ev)
      assert.equal(guardOf(() => assertEventAllowed(r.def, view, { chain: 'btc', type, data })), 'engine.btc-open', `${type} ${'reducer' in view ? 'reducer' : 'state'} view`)
    }
  }
  assert.equal(r.j.state().chains.btc!.openIntents.length, 0, 'the commit landed: nothing is open, yet the chain may not end')
  r.j.expire('btc')
  assert.equal((await r.run()).out, 'copies-done')
})

// R79b (PF-E fix round 4, lane E) — the stop-reason classes in the executor and the engine (contracts/stop.ts):
//   · every `stopped` the executor or the lane journals carries its code; a FINAL stop (a readback mismatch, a status-0 receipt, …) is
//     never reopened, whatever cleared its latch (the API refuses its resume: resume.final-stop; an executor has its own guard);
//   · I-1: every pre-start check runs BEFORE `resumed`: a check that fails journals nothing and the chain stays STOPPED — never
//     RUNNING with no run behind it; a takeover whose reread of a landed part fails on a RUNNING chain stops it with a FINAL code;
//   · M-8: a Stop in the countdown that the API already journaled ends `stopped`, not `failed`;
//   · M-3: a local detach is sticky in its process — an API resume after it never lets that process sign again;
//   · M-2: a detach at an adopted attempt whose rebuilt bytes its ticket does not bind journals nothing (no `stuck`).
// Mapped by test/mutation/guards.json: resume.final-stop (the executor's own guard: executor.ts finalStop).
// ALL DATA IS SYNTHETIC: generated keys, the in-memory API and relay, fake chains; nothing listens on a port; virtual time.
import { afterEach, test } from 'node:test'
import assert from 'node:assert/strict'
import { hexToBytes, keccak256, toHex } from 'viem'
import { createExecutor, laneConfigOf } from '../../src/executor/executor.ts'
import { useRelayClient } from '../../src/engine/rpc.js'
import * as eth from '../../src/chains/eth.js'
import { planLaneCopy } from '../../src/engine/lane.js'
import { sha256Hex } from '../../src/job/canonical.ts'
import { intentRefusal, reduce } from '../../src/job/index.ts'
import { STOP_CODES } from '../../src/contracts/index.ts'
import { virtualClock } from '../fakes/fake-journal.ts'
import { T0, deps, sendViolations, stack } from './helpers.ts'

afterEach(() => { assert.deepEqual(sendViolations.splice(0), [], 'every ticketed send was exactly its journaled intent (id, bytes, declared nonce / blockhash)') })

const NULL = '0x0000000000000000000000000000000000000000', GW = 10n ** 9n
const BLOCK_MS = 12_000, MAX_MS = 2 * 3600_000
type S = ReturnType<typeof stack>
type Ex = ReturnType<typeof createExecutor>
const hx = (n: number): string => `0x${n.toString(16)}`
const run = (s: S, holder: 'cli' | 'browser' = 'cli'): Ex => createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder, deps: deps(s) })
const cs = (s: S) => s.j.state().chains.eth!
const intents = (s: S) => s.j.events.filter((e) => e.type === 'intent' && e.chain === 'eth')
const stops = (s: S) => s.j.events.filter((e) => e.type === 'stopped')
// what executors journaled from seq on (lease lines are the API's)
const byExecutors = (s: S, seq: number) => s.j.events.slice(seq).filter((e) => e.by === 'cli' || e.by === 'browser').map((e) => e.type)
// the class the journal's FACTS give: every journaled stop's code swapped for `code` (final round m-4: a FINAL cause with a journal fact stays
// final even if a regression journaled a resumable code; one without a fact rests on its code alone — pinned by the lane code tests)
const classWithCode = (s: S, code: string): string | undefined =>
  reduce(s.def, s.j.events.map((e) => (e.type === 'stopped' ? { ...e, data: { ...e.data, code } } : e))).chains.eth!.stopClass
const clawbackAllowed = (s: S): boolean => intentRefusal(s.def, s.j.state(), 'eth', s.j.serverNow(), 'clawback-intent') === null
// a run on virtual time, bounded: still going after MAX_MS is a wedge (its lease lapses, the test fails on the outcome)
async function drive(s: S, go: () => Promise<string>, at: Array<{ ms: number; go: () => void }> = []): Promise<string | null> {
  let outcome: string | null = null
  const p = go().then((o) => { outcome = o }, (e: Error) => { outcome = `threw ${e.message}` })
  const t0 = s.clock.now(), todo = [...at]
  while (outcome === null && s.clock.now() - t0 < MAX_MS) {
    for (const x of todo.filter((y) => s.clock.now() - t0 >= y.ms)) { todo.splice(todo.indexOf(x), 1); x.go() }
    await new Promise((r) => setImmediate(r))
  }
  const done = outcome
  if (done === null) { s.j.expire('eth'); await p }
  return done
}

test('R79b I-1: the lane\'s FINAL stops — a readback mismatch, a status-0 receipt — are journaled with their code, latched and final; after the operator\'s resume the next run reopens nothing (journals nothing, ends stopped) and the claw-back stays allowed', { timeout: 120_000 }, async () => {
  for (const kind of ['readback', 'status 0'] as const) {
    let first = ''
    const s = stack('eth', { copies: 2, startIn: 0, eth: (m, p, base) => {
      if (m === 'eth_sendRawTransaction' && first === '') first = keccak256(p[0] as `0x${string}`).toLowerCase()
      const r = base(m, p) as Record<string, unknown> | null
      if (kind === 'status 0' && m === 'eth_getTransactionReceipt' && r !== null && p[0] === first) return { ...r, status: '0x0' }
      if (kind === 'readback' && m === 'eth_getTransactionByHash' && r !== null && p[0] === first) return { ...r, input: '0x00' }
      return r
    } })
    const out1 = await drive(s, () => run(s).start())
    assert.equal(out1, kind === 'readback' ? 'stopped' : 'failed', kind)
    const code = kind === 'readback' ? 'readback-mismatch' : 'reverted'
    assert.deepEqual(stops(s).map((e) => e.data.code), [code], `${kind}: the lane's stop carries its code`)
    assert.deepEqual([cs(s).phase, cs(s).stopLatched, cs(s).stopCode, cs(s).stopClass], ['STOPPED', true, code, 'final'], kind)
    // final round m-4: the journal FACT (readback not ok — for status 0 too, whatever the calldata) makes it final, not only the code
    assert.deepEqual(s.j.events.filter((e) => e.type === 'readback').map((e) => e.data.ok), [false], kind)
    assert.equal(classWithCode(s, 'operator-stop'), 'final', `${kind}: final from the fact, whatever code a regression journaled`)
    assert.deepEqual(intents(s).map((e) => e.data.copy), [1], `${kind}: copy 2 never signed`)
    s.j.apiEvent('resume-requested', { chain: 'eth' }, null)          // the real API refuses it (resume.final-stop); an older one cleared the latch
    const seq = s.j.events.length
    const ex = run(s, 'browser')
    assert.equal(await drive(s, () => ex.start()), 'stopped', `${kind}: settled — before R79b \`resumed\` then the reread failed: RUNNING and dead`)
    assert.deepEqual(byExecutors(s, seq), [], `${kind}: nothing journaled (no resumed, no readback, no intent)`)
    assert.match(ex.view().note, new RegExp(`stopped for good: .*\\(${code}\\) — resume is refused; claw back`), kind)
    assert.deepEqual([cs(s).phase, cs(s).stopClass, intents(s).length], ['STOPPED', 'final', 1], kind)
    assert.ok(clawbackAllowed(s), `${kind}: the claw-back is allowed`)
  }
})

test('R79b I-1 (the crash variant): a takeover whose reread of a landed part fails on a RUNNING chain journals `stopped` with a FINAL code — STOPPED, latched, final, the claw-back allowed; never RUNNING with no run behind it', { timeout: 60_000 }, async () => {
  for (const kind of ['other bytes', 'status 0'] as const) {
    let failedId = ''
    const s = stack('eth', { copies: 2, startIn: 0, eth: (m, p, base) => {
      const r = base(m, p) as Record<string, unknown> | null
      return m === 'eth_getTransactionReceipt' && r !== null && p[0] === failedId ? { ...r, status: '0x0' } : r
    } })
    await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
    useRelayClient(s.relay.client)
    const payload = planLaneCopy(laneConfigOf('eth', s.def.chains.eth!, s.text), 1)[0].payload
    const data = kind === 'status 0' ? toHex(payload) : toHex(new TextEncoder().encode('data:,not the planned bytes'))
    const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL, data, gas: 60_000n, maxFee: 3n * GW, tip: GW })
    await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [signed.raw])    // it landed
    const id = signed.id.toLowerCase()
    if (kind === 'status 0') failedId = id
    s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: sha256Hex(hexToBytes(signed.raw)), payloadSha256: sha256Hex(payload), reserved: '1', eth: { nonce: 0, tip: String(GW), maxFee: String(3n * GW), gas: '60000', to: NULL } })
    s.j.asHolder(2, 'browser', 'eth', 'sent', { txId: id, outcome: 'accepted', reason: null })
    s.j.asHolder(2, 'browser', 'eth', 'included', { txId: id, copy: 1, part: 1, attempt: 1, block: '101', fee: '1', ms: 1 })   // then the tab died
    s.j.expire('eth')
    assert.equal(cs(s).phase, 'RUNNING')
    const ex = run(s)
    assert.equal(await ex.start(), 'failed', kind)
    const code = kind === 'status 0' ? 'reverted' : 'readback-mismatch'
    assert.deepEqual(stops(s).map((e) => [e.by, e.data.code]), [['cli', code]], `${kind}: the engine stops it (before R79b: nothing journaled, RUNNING)`)
    assert.match(String(stops(s)[0].data.reason), /does not read back/)
    assert.deepEqual([cs(s).phase, cs(s).stopLatched, cs(s).stopClass, intents(s).length, s.relay.sends().length], ['STOPPED', true, 'final', 1, 1], `${kind}: nothing signed or sent`)
    assert.deepEqual(s.j.events.filter((e) => e.type === 'readback').map((e) => e.data.ok), [false], `${kind}: the evidence (final round m-3/m-4)`)
    assert.equal(classWithCode(s, 'operator-stop'), 'final', kind)
    assert.ok(clawbackAllowed(s), `${kind}: the claw-back is allowed`)
  }
})

test('R79b I-1 (the crash variant, the chain unreadable now): no verdict — nothing journaled, a later run reads it again; with the operator\'s Stop pending that Stop is journaled (operator-stop, resumable) and the resume re-reads the part, then continues', { timeout: 60_000 }, async () => {
  for (const how of ['no stop', 'stop'] as const) {
    let hidden = true, id = ''
    const s = stack('eth', { copies: 2, startIn: 0, eth: (m, p, base) => {
      if (hidden && id !== '' && p[0] === id && (m === 'eth_getTransactionReceipt' || m === 'eth_getTransactionByHash')) return null   // not readable now
      return base(m, p)
    } })
    await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
    useRelayClient(s.relay.client)
    const payload = planLaneCopy(laneConfigOf('eth', s.def.chains.eth!, s.text), 1)[0].payload
    const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL, data: toHex(payload), gas: 60_000n, maxFee: 3n * GW, tip: GW })
    await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [signed.raw])    // it landed (the planned bytes)
    id = signed.id.toLowerCase()
    s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: sha256Hex(hexToBytes(signed.raw)), payloadSha256: sha256Hex(payload), reserved: '1', eth: { nonce: 0, tip: String(GW), maxFee: String(3n * GW), gas: '60000', to: NULL } })
    s.j.asHolder(2, 'browser', 'eth', 'sent', { txId: id, outcome: 'accepted', reason: null })
    s.j.asHolder(2, 'browser', 'eth', 'included', { txId: id, copy: 1, part: 1, attempt: 1, block: '101', fee: '1', ms: 1 })
    s.j.expire('eth')
    if (how === 'stop') s.j.requestStop('eth')
    const seq = s.j.events.length
    const ex = run(s)
    const out = await drive(s, () => ex.start())
    if (how === 'no stop') {
      assert.equal(out, 'failed')
      assert.deepEqual(byExecutors(s, seq), [], 'no verdict from an unreadable chain: nothing journaled (a FINAL stop here would end the job over an RPC flake)')
      assert.equal(cs(s).phase, 'RUNNING')
      assert.match(ex.view().note, /cannot be read back now .* run the job again/)
      hidden = false
      assert.equal(await drive(s, () => run(s, 'browser').start()), 'copies-done', 'a later run reads it again and continues')
    } else {
      assert.equal(out, 'stopped')
      assert.deepEqual(stops(s).map((e) => e.data.code), ['operator-stop'])
      assert.deepEqual([cs(s).phase, cs(s).stopLatched, cs(s).stopClass], ['STOPPED', true, 'resumable'])
      s.j.apiEvent('resume-requested', { chain: 'eth' }, null)
      // M5c (text): a resumed run whose reread gives no verdict journals nothing and says the chain stays STOPPED with the resume standing
      const seq1 = s.j.events.length
      const ex1 = run(s, 'browser')
      assert.equal(await drive(s, () => ex1.start()), 'failed')
      assert.deepEqual(byExecutors(s, seq1), [], 'still unreadable at the resume: nothing journaled')
      assert.deepEqual([cs(s).phase, cs(s).stopLatched ?? false, cs(s).stopClass], ['STOPPED', false, 'resumable'])
      assert.match(ex1.view().note, /cannot be read back now .* nothing journaled; resumed, but the chain stays stopped and the resume still stands; run the job again/)
      assert.ok(!/claw back/.test(ex1.view().note), 'no verdict: not the claw-back advice')
      s.j.expire('eth')
      hidden = false
      const seq2 = s.j.events.length
      assert.equal(await drive(s, () => run(s, 'browser').start()), 'copies-done')
      assert.deepEqual(byExecutors(s, seq2).slice(0, 2), ['readback', 'resumed'], 'the resume re-read the part first, then reopened')
    }
    assert.deepEqual(intents(s).map((e) => e.data.copy), [1, 2], 'copy 1 part 1 never sent again')
  }
})

test('R79b I-1: a RESUMABLE stop whose pre-start check fails at the resume — (a) the check at the start journals nothing: the chain stays STOPPED (no `resumed`, no `stopped`), and once the check passes the resume reopens it; (b) a reread that the chain ANSWERS with other bytes (final round m-3) journals the evidence (readback not ok) and a FINAL stop: never resumable for good', { timeout: 120_000 }, async () => {
  // (a) the check at the start (the relay identity) fails on the run after the resume
  {
    let bad = false, n = 0
    const s = stack('eth', { copies: 2, startIn: 0, eth: (m, p, base) => { if (m === 'eth_sendRawTransaction' && intents(s).length === 1 && stops(s).length === 0) s.j.requestStop('eth'); return base(m, p) } })
    const status = s.relay.client.status.bind(s.relay.client)
    ;(s.relay.client as { status: () => Promise<unknown> }).status = async () => { const r = await status(); return bad && ++n > 1 ? { ...r, identity: { eth: { ok: false, message: 'chain id changed (test)' } } } : r }
    assert.equal(await drive(s, () => run(s).start()), 'stopped')
    assert.deepEqual([cs(s).phase, cs(s).stopLatched, cs(s).stopCode, cs(s).stopClass], ['STOPPED', true, 'operator-stop', 'resumable'])
    s.j.apiEvent('resume-requested', { chain: 'eth' }, null)
    bad = true
    const seq = s.j.events.length
    const ex = run(s)
    assert.equal(await drive(s, () => ex.start()), 'failed')
    assert.deepEqual(byExecutors(s, seq), [], 'nothing journaled: before R79b `resumed`, then `stopped` (start-check)')
    assert.deepEqual([cs(s).phase, cs(s).stopLatched ?? false, cs(s).stopRequested, cs(s).stopClass], ['STOPPED', false, false, 'resumable'], 'STOPPED, the resume still in effect')
    assert.match(ex.view().note, /^resumed, but the check at its start failed: .*identity .* the chain stays stopped \(nothing journaled\) and the resume still stands; run it again/)   // M5c: the run says it was resumed and is still STOPPED
    bad = false
    assert.equal(await drive(s, () => run(s).start()), 'copies-done', 'the check passes: the resume reopens it')
    assert.equal(byExecutors(s, seq).filter((t) => t === 'resumed').length, 1)
    assert.deepEqual(intents(s).map((e) => e.data.copy), [1, 2])
  }
  // (b) a landed part without its readback (its holder died before it) does not read back at the resume
  {
    const s = stack('eth', { copies: 2, startIn: 0 })
    await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
    useRelayClient(s.relay.client)
    const payload = planLaneCopy(laneConfigOf('eth', s.def.chains.eth!, s.text), 1)[0].payload
    const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL, data: toHex(new TextEncoder().encode('data:,not the planned bytes')), gas: 60_000n, maxFee: 3n * GW, tip: GW })
    await s.relay.client.rpc('eth', 'eth_sendRawTransaction', [signed.raw])
    const id = signed.id.toLowerCase()
    s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: sha256Hex(hexToBytes(signed.raw)), payloadSha256: sha256Hex(payload), reserved: '1', eth: { nonce: 0, tip: String(GW), maxFee: String(3n * GW), gas: '60000', to: NULL } })
    s.j.asHolder(2, 'browser', 'eth', 'sent', { txId: id, outcome: 'accepted', reason: null })
    s.j.asHolder(2, 'browser', 'eth', 'included', { txId: id, copy: 1, part: 1, attempt: 1, block: '101', fee: '1', ms: 1 })
    s.j.asHolder(2, 'browser', 'eth', 'stopped', { reason: 'stopped by the operator', code: 'operator-stop' })
    s.j.expire('eth')
    s.j.apiEvent('resume-requested', { chain: 'eth' }, null)
    assert.deepEqual([cs(s).phase, cs(s).stopClass], ['STOPPED', 'resumable'])
    const seq = s.j.events.length
    const ex = run(s)
    assert.equal(await ex.start(), 'failed')
    assert.deepEqual(byExecutors(s, seq), ['readback', 'stopped'], 'no `resumed` (before R79b: RUNNING with no run behind it); the evidence and a FINAL stop (before the final round: nothing, resumable for good)')
    assert.deepEqual(s.j.events.slice(seq).filter((e) => e.type === 'readback').map((e) => [e.data.txId, e.data.ok]), [[id, false]])
    assert.deepEqual([cs(s).phase, cs(s).stopLatched, cs(s).stopCode, cs(s).stopClass], ['STOPPED', true, 'readback-mismatch', 'final'])
    assert.match(ex.view().note, /does not read back/)
    assert.equal(s.relay.sends().length, 1, 'nothing sent')
    // the fact alone makes it final: with the code swapped for a resumable one, the class is still final
    assert.equal(classWithCode(s, 'operator-stop'), 'final')
    const seq2 = s.j.events.length
    assert.equal(await run(s).start(), 'stopped', 'a later run: settled, final')
    assert.deepEqual(byExecutors(s, seq2), [])
  }
})

test('final round m-2: Ctrl-C (a detach) during the check at the start of a resumed chain journals nothing — not `resumed`: the chain stays STOPPED with the resume standing, and the next run reopens it', { timeout: 120_000 }, async () => {
  let ex: Ex | null = null, armed = false
  const s = stack('eth', { copies: 2, startIn: 0, eth: (m, p, base) => { if (m === 'eth_sendRawTransaction' && intents(s).length === 1 && stops(s).length === 0) s.j.requestStop('eth'); return base(m, p) } })
  assert.equal(await drive(s, () => run(s).start()), 'stopped')
  assert.deepEqual([cs(s).stopCode, cs(s).stopClass], ['operator-stop', 'resumable'])
  s.j.apiEvent('resume-requested', { chain: 'eth' }, null)
  const status = s.relay.client.status.bind(s.relay.client)
  let calls = 0   // the run's 1st relay status is its open(); the 2nd is the check at the start
  ;(s.relay.client as { status: () => Promise<unknown> }).status = async () => { if (armed && ++calls === 2) ex!.requestStop(); return status() }   // Ctrl-C at the start check
  const seq = s.j.events.length
  ex = run(s)
  armed = true
  assert.equal(await drive(s, () => ex!.start()), 'stopped')
  armed = false
  assert.equal(ex.view().phase, 'detached')
  assert.deepEqual(byExecutors(s, seq), [], 'nothing journaled (before: `resumed`, then a detach left it RUNNING with no executor)')
  assert.deepEqual([cs(s).phase, cs(s).stopLatched ?? false, cs(s).stopRequested, cs(s).stopClass], ['STOPPED', false, false, 'resumable'], 'the resume still stands')
  assert.equal(await drive(s, () => run(s, 'browser').start()), 'copies-done')
  assert.deepEqual(intents(s).map((e) => e.data.copy), [1, 2])
})

test('final round m-6: the executor\'s own pending-stop checks — (i) a stop requested after the resume and before the run: settled at once, nothing journaled; (ii) a stop requested during the run\'s pre-start checks: no `resumed`, the operator\'s Stop journaled (operator-stop, latched again)', { timeout: 120_000 }, async () => {
  for (const when of ['before the run', 'at the start check'] as const) {
    let armed = false
    const s = stack('eth', { copies: 2, startIn: 0, eth: (m, p, base) => { if (m === 'eth_sendRawTransaction' && intents(s).length === 1 && stops(s).length === 0) s.j.requestStop('eth'); return base(m, p) } })
    assert.equal(await drive(s, () => run(s).start()), 'stopped')
    s.j.apiEvent('resume-requested', { chain: 'eth' }, null)
    assert.deepEqual([cs(s).phase, cs(s).stopLatched ?? false, cs(s).stopRequested], ['STOPPED', false, false])
    if (when === 'before the run') s.j.requestStop('eth')
    else {
      const status = s.relay.client.status.bind(s.relay.client)
      let calls = 0   // the run's 1st relay status is its open(); the 2nd is the check at the start
      ;(s.relay.client as { status: () => Promise<unknown> }).status = async () => { if (armed && ++calls === 2) s.j.requestStop('eth'); return status() }
    }
    const seq = s.j.events.length
    armed = true
    const out = await drive(s, () => run(s).start())
    armed = false
    assert.equal(out, 'stopped', when)
    if (when === 'before the run') assert.deepEqual(byExecutors(s, seq), [], `${when}: settled at once — never reopened (reopens() requires no pending stop request)`)
    else {
      assert.deepEqual(byExecutors(s, seq), ['stopped'], `${when}: no \`resumed\` (the look before it re-reads the API)`)
      assert.deepEqual([stops(s).at(-1)!.data.code, cs(s).stopLatched, cs(s).stopClass], ['operator-stop', true, 'resumable'])
    }
    assert.equal(cs(s).phase, 'STOPPED', when)
    assert.deepEqual(intents(s).map((e) => e.data.copy), [1], `${when}: nothing new signed`)
  }
})

test('R79b resume.final-stop (the executor\'s guard): a FINAL stop is never reopened, whatever cleared its latch — no code (a journal from before R79b), spend-cap, an EIP-7702 stop; an operator-stop is', { timeout: 120_000 }, async () => {
  const cases: Array<[string, Record<string, unknown>, string]> = [
    ['no code', {}, 'final'], ['spend-cap', { code: 'spend-cap' }, 'final'], ['eip7702', { code: 'eip7702', delegated: true }, 'final'], ['operator-stop', { code: 'operator-stop' }, 'resumable'],
  ]
  for (const [name, extra, cls] of cases) {
    const s = stack('eth', { copies: 1, startIn: 0 })
    s.j.apiEvent('stopped', { reason: `stopped (${name})`, ...extra }, 'eth')   // a chain that never started: STOPPED, latched
    s.j.apiEvent('resume-requested', { chain: 'eth' }, null)
    assert.deepEqual([cs(s).phase, cs(s).stopLatched ?? false, cs(s).stopClass], ['STOPPED', false, cls], name)
    const seq = s.j.events.length
    const ex = run(s)
    const out = await drive(s, () => ex.start())
    if (cls === 'final') {
      assert.equal(out, 'stopped', name)
      assert.deepEqual(byExecutors(s, seq), [], `${name}: nothing journaled, never reopened`)
      assert.match(ex.view().note, /stopped for good: .* resume is refused; claw back/, name)
      assert.equal(intents(s).length, 0, name)
      assert.ok(clawbackAllowed(s), name)
    } else {
      assert.equal(out, 'copies-done', name)
      assert.equal(byExecutors(s, seq)[0], 'resumed', `${name}: reopened`)
    }
  }
  assert.equal(STOP_CODES['spend-cap'].cls, 'final')
})

test('R79b M-8: a Stop in the countdown that the API already journaled (its stop route, a chain that never started) ends the run `stopped`, never `failed`; one `stopped` in the journal', { timeout: 60_000 }, async () => {
  const s = stack('eth', { copies: 1, startIn: 60_000 })
  const ex = run(s)
  const p = ex.start()
  while (ex.view().phase !== 'countdown') await s.clock.sleep(500)
  s.j.requestStop('eth')
  s.j.apiEvent('stopped', { reason: 'stopped before any transaction', code: 'operator-stop' }, 'eth')
  assert.equal(await p, 'stopped', 'before R79b: its own `stopped` was refused (job.state) and the run ended failed')
  assert.equal(ex.view().phase, 'stopped')
  assert.deepEqual(stops(s).map((e) => [e.by, e.data.code]), [['api', 'operator-stop']])
  assert.deepEqual([cs(s).phase, cs(s).stopLatched, intents(s).length], ['STOPPED', true, 0])
})

test('R79b M-3: a local detach is sticky in its process — `vt job stop` and Ctrl-C together, then the operator\'s resume at the API: that process signs nothing new (it ends detached); a new run continues', { timeout: 120_000 }, async () => {
  const clock = virtualClock(T0)
  let ex: Ex, id = '', mine = false
  const s = stack('eth', { copies: 2, startIn: 0, feeStrategy: 'passive', clock, eth: (m, p, base) => {
    if (m === 'eth_blockNumber') return hx(100 + Math.floor((clock.now() - T0) / BLOCK_MS))
    if (m === 'eth_sendRawTransaction' && !mine) { if (id === '') { id = keccak256(p[0] as `0x${string}`).toLowerCase(); s.j.requestStop('eth'); ex.requestStop() } return keccak256(p[0] as `0x${string}`) }   // taken, not mined yet
    if (m === 'eth_getTransactionByHash' && !mine && p[0] === id) return { hash: id, blockNumber: null, nonce: '0x0', to: NULL, value: '0x0', input: '0x' }
    return base(m, p)
  } })
  ex = run(s)
  const out = await drive(s, () => ex.start(), [
    { ms: 60_000, go: () => s.j.apiEvent('resume-requested', { chain: 'eth' }, null) },   // a lease tick saw the stop request by then
    { ms: 120_000, go: () => { mine = true } },                                            // copy 1 lands inside its window
  ])
  assert.equal(out, 'stopped')
  assert.equal(ex.view().phase, 'detached', 'before R79b the API resume cleared the local stop too and copy 2 was signed')
  assert.deepEqual(intents(s).map((e) => e.data.copy), [1], 'nothing new signed by that process')
  assert.equal(stops(s).length, 0, 'a detach journals nothing')
  assert.deepEqual([cs(s).phase, cs(s).copiesIncluded], ['RUNNING', 1])
  assert.equal(await drive(s, () => run(s, 'browser').start()), 'copies-done', 'the next run continues')
  assert.deepEqual(intents(s).map((e) => e.data.copy), [1, 2])
})

test('R79b M-2: a detach at an adopted attempt whose rebuilt bytes its send ticket does not bind (the journaled rawSha256 differs) journals nothing — no `stuck`, no `stopped`; a job Stop instead is STUCK at once', { timeout: 60_000 }, async () => {
  for (const how of ['detach', 'stop'] as const) {
    const clock = virtualClock(T0)
    const s = stack('eth', { copies: 1, startIn: 0, feeStrategy: 'passive', clock, eth: (m, p, base) => (m === 'eth_blockNumber' ? hx(100 + Math.floor((clock.now() - T0) / BLOCK_MS)) : base(m, p)) })
    await s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
    useRelayClient(s.relay.client)
    const payload = planLaneCopy(laneConfigOf('eth', s.def.chains.eth!, s.text), 1)[0].payload
    // the planned part at nonce 0 (so its bytes are rebuilt: keccak256 = the txId), journaled with a rawSha256 that is not theirs; never sent
    const signed = await eth.sign(s.key.handle.account, 31337, { nonce: 0, to: NULL, data: toHex(payload), gas: 30_000n, maxFee: 3n * GW, tip: GW })
    const id = signed.id.toLowerCase()
    s.j.asHolder(2, 'browser', 'eth', 'intent', { txId: id, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: 'ab'.repeat(32), payloadSha256: sha256Hex(payload), reserved: '90000000000000', eth: { nonce: 0, tip: String(GW), maxFee: String(3n * GW), gas: '30000', to: NULL } })
    s.j.asHolder(2, 'browser', 'eth', 'sent', { txId: id, outcome: 'unknown', reason: 'timeout' })
    s.j.expire('eth')
    if (how === 'stop') s.j.requestStop('eth')
    const ex = run(s)
    ex.requestStop()
    const out = await drive(s, () => ex.start())
    const stuck = s.j.events.filter((e) => e.type === 'stuck')
    if (how === 'detach') {
      assert.equal(out, 'stopped')
      assert.deepEqual([stuck.length, stops(s).length, cs(s).phase, cs(s).openIntents], [0, 0, 'RUNNING', [id]], 'nothing escalated by a detach (before R79b: `stuck` at the first rebroadcast)')
      assert.equal(ex.view().phase, 'detached')
    } else {
      assert.equal(out, 'failed')
      assert.match(String(stuck[0].data.reason), /cannot be rebroadcast: the sha256 of the rebuilt bytes is not the journaled rawSha256/)
      assert.deepEqual(stops(s).map((e) => e.data.code), ['stuck'], 'the lane\'s stop: code stuck (final)')
    }
    assert.equal(s.relay.sends().length, 0, 'its bytes never left')
  }
})

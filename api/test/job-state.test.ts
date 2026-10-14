// The API's job state (job-state.ts) is core's incremental reducer (I2: createReducer, lane E) plus the API's small
// indexes. After every line of every contract journal, and of seeded random journals: state() deep-equals core's
// reduce(def, prefix); every accessor (open intents and attempts in order, spent, landed, terminal, stop requested, the
// claw-back family) agrees with that state; core's intent check gives the same answer on { reducer } as on the full
// state. A reload (a new registry over the same files) rebuilds the same state as the live one.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Chain, JobDef, JobState, JournalEvent } from '@vault-timelock/core/contracts'
import { intentRefusal, isChainTerminal, reduce } from '@vault-timelock/core/job'
import type { IntentKind } from '@vault-timelock/core/job'
import { createJobState } from '../src/job-state.ts'
import type { JobStateAdapter } from '../src/job-state.ts'
import { createRegistry } from '../src/jobs.ts'
import { FIXTURES, TICKET_KEY, fakeClock, fixture, installJournal, startApi } from './helpers.ts'

process.env.NODE_ENV = 'test'

const CHAINS: readonly Chain[] = ['eth', 'sol']
const BOTH = fixture<Record<string, { def: JobDef }>>('jobs/valid/expected.json')['defaults.json'].def // eth + sol, local

// Every accessor against the full state; core's intent check on the reducer against the full state.
function agree(js: JobStateAdapter, def: JobDef, want: JobState, label: string, probes: Array<{ kind: IntentKind; target?: { copy: number; part: number } }>, nows: number[]): void {
  assert.deepEqual(js.armed(), want.armed, `${label}: armed`)
  for (const c of CHAINS) {
    const cs = want.chains[c]
    if (cs === undefined) { assert.equal(js.phase(c), undefined); continue }
    assert.equal(js.phase(c), cs.phase, `${label}: ${c} phase`)
    assert.deepEqual(js.openIntentIds(c), cs.openIntents, `${label}: ${c} open`)
    assert.deepEqual(js.openAttempts(c).map((x) => x.txId), cs.openIntents, `${label}: ${c} open attempts`)
    for (const id of cs.openIntents) assert.ok(js.isOpen(c, id), `${label}: ${c} isOpen ${id}`)
    assert.equal(js.spent(c), BigInt(cs.spent), `${label}: ${c} spent`)
    assert.equal(js.terminal(c), isChainTerminal(cs), `${label}: ${c} terminal`)
    assert.equal(js.stopRequested(c), cs.stopRequested, `${label}: ${c} stop requested`)
    assert.equal(js.reducer.openIntents(c), cs.openIntents.length, `${label}: ${c} open count`)
    for (const t of cs.txs) assert.equal(js.landed(c, t.copy, t.part), t.state === 'included', `${label}: ${c} landed ${t.copy}:${t.part}`)
    const claw = js.claw(c)
    assert.equal(claw === null, cs.clawback === null, `${label}: ${c} claw-back family`)
    if (claw !== null && cs.clawback !== null) {
      assert.ok(claw.members.includes(cs.clawback.txId), `${label}: ${c} the shown member is a member`)
      assert.equal(claw.landed, cs.clawback.landed, `${label}: ${c} claw-back landed`)
      assert.equal(claw.open, claw.members.some((m) => cs.openIntents.includes(m)), `${label}: ${c} claw-back open`)
    }
    for (const p of probes) {
      for (const now of nows) {
        assert.equal(intentRefusal(def, { reducer: js.reducer, corrupt: null }, c, now, p.kind, p.target), intentRefusal(def, want, c, now, p.kind, p.target), `${label}: ${c} ${p.kind} ${JSON.stringify(p.target)} @${now}`)
      }
    }
  }
}
const probesOf = (s: JobState): Array<{ kind: IntentKind; target?: { copy: number; part: number } }> => {
  const out: Array<{ kind: IntentKind; target?: { copy: number; part: number } }> = [{ kind: 'clawback-intent' }, { kind: 'intent', target: { copy: 99, part: 1 } }]
  for (const c of CHAINS) for (const t of s.chains[c]?.txs ?? []) out.push({ kind: 'intent', target: { copy: t.copy, part: t.part } })
  return out.slice(0, 12)
}
const nowsOf = (s: JobState): number[] => (s.releaseAt === null ? [0] : [s.releaseAt - 1, s.releaseAt + 400_000])

test('every contract journal, after every line: state() = reduce(def, prefix), and every accessor agrees', () => {
  const index = fixture<{ vectors: Array<{ name: string }> }>('journals/index.json')
  for (const { name } of index.vectors) {
    const def = fixture<JobDef>(`journals/${name}.def.json`)
    const events = readFileSync(join(FIXTURES, 'journals', `${name}.jsonl`), 'utf8').split('\n').filter((l) => l !== '').map((l) => JSON.parse(l) as JournalEvent)
    const js = createJobState(def)
    assert.deepEqual(js.state(), reduce(def, []), `${name}: empty`)
    events.forEach((e, i) => {
      js.apply(e)
      const want = reduce(def, events.slice(0, i + 1))
      assert.deepEqual(js.state(), want, `${name} after line ${i}`)
      agree(js, def, want, `${name} after line ${i}`, probesOf(want), nowsOf(want))
    })
    assert.equal(js.count, events.length)
  }
})

// A seeded random journal over a two-chain job: every event type, ids reused, malformed members, claw-back families,
// replacements, takeovers, stuck / resolve, skips and closes.
function randomJournal(seed: number, n: number): JournalEvent[] {
  let x = seed >>> 0 || 1
  const r = (): number => { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; return x / 4294967296 }
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)]
  const ri = (lo: number, hi: number): number => lo + Math.floor(r() * (hi - lo + 1))
  const pool: Record<Chain, string[]> = { eth: [], sol: [], btc: [] }
  const claws: Record<Chain, string[]> = { eth: [], sol: [], btc: [] }
  let id = 0
  const out: JournalEvent[] = []
  const types: Array<[string, number]> = [
    ['intent', 18], ['sent', 10], ['reconcile', 8], ['included', 9], ['readback', 7], ['resolved', 3], ['stuck', 4], ['paused', 2], ['resumed', 2],
    ['drained', 1], ['copies-done', 1], ['stopped', 1], ['clawback-intent', 2], ['clawback-included', 1], ['clawback-readback', 1], ['clawback-failed', 1],
    ['reassembled', 3], ['armed', 1], ['skip', 1], ['stop-requested', 1], ['resume-requested', 1], ['close', 1], ['key-loaded', 1], ['funds', 2],
    ['note', 1], ['lease-acquired', 1], ['replaced', 1],
  ]
  const total = types.reduce((s, [, w]) => s + w, 0)
  const anyTx = (c: Chain): string => (r() < 0.08 ? `x${ri(0, 9999)}` : r() < 0.15 && claws[c].length > 0 ? pick(claws[c]) : pool[c].length > 0 ? pick(pool[c]) : 'none')
  for (let seq = 0; seq < n; seq++) {
    let w = r() * total
    let type = 'note'
    for (const [t, tw] of types) { if ((w -= tw) < 0) { type = t; break } }
    const c: Chain = r() < 0.55 ? 'eth' : 'sol'
    const gen = ri(1, 4)
    let chain: Chain | null = c
    let data: Record<string, unknown> = {}
    const fee = String(ri(0, 5_000_000))
    const ethI = () => ({ nonce: ri(0, 6), tip: '1', maxFee: String(ri(1, 9) * 1000), gas: '21000', to: '0x0000000000000000000000000000000000000000' })
    const solI = () => ({ blockhash: `b${ri(0, 9)}`, lastValidBlockHeight: ri(0, 99), cuPrice: 1, cuLimit: 1000, rung: null, fee: String(ri(5000, 9000)) })
    switch (type) {
      case 'intent': {
        const txId = r() < 0.05 && pool[c].length > 0 ? pick(pool[c]) : `${c}${++id}`
        pool[c].push(txId)
        data = { txId, copy: ri(1, 4), part: ri(1, 3), parts: 3, attempt: ri(1, 3), replaces: null, rawSha256: 'a', payloadSha256: 'b', reserved: '1', ...(c === 'eth' ? { eth: ethI() } : { sol: solI() }) }
        if (r() < 0.03) delete data.copy
        break
      }
      case 'sent': data = { txId: anyTx(c), outcome: pick(['accepted', 'unknown', 'rejected', 'odd']), reason: null }; break
      case 'reconcile': data = { txId: anyTx(c), outcome: pick(['included', 'expired', 'nonce-consumed', 'adopted', 'odd']), ...(r() < 0.5 ? { block: String(ri(1, 99)), fee } : {}) }; break
      case 'included': data = { txId: anyTx(c), copy: 1, part: 1, attempt: 1, block: String(ri(1, 99)), fee: r() < 0.05 ? 'x' : fee, ms: 1 }; break
      case 'readback': data = { txId: anyTx(c), ok: r() < 0.8, detail: '' }; break
      case 'resolved': data = { txId: anyTx(c), action: pick(['mark-done', 'mark-failed', 'retry']), typed: null }; break
      case 'stuck': data = { txId: anyTx(c), reason: `stuck ${ri(0, 9)}` }; break
      case 'paused': case 'stopped': data = { reason: `r${ri(0, 9)}` }; break
      case 'resumed': data = { reason: 'go' }; break
      case 'drained': data = { balance: '1', nextCost: '2', copy: 1 }; break
      case 'copies-done': data = { copies: 1 }; break
      case 'clawback-intent': {
        const txId = `${c}c${++id}`
        claws[c].push(txId)
        data = { txId, to: 'dest', value: String(ri(0, 1000)), rawSha256: 'a', ...(c === 'eth' ? { eth: ethI() } : { sol: solI() }) }
        break
      }
      case 'clawback-included': data = { txId: claws[c].length > 0 && r() < 0.8 ? pick(claws[c]) : anyTx(c), value: '1', fee }; break
      case 'clawback-readback': data = { txId: claws[c].length > 0 ? pick(claws[c]) : 'none', ok: r() < 0.7, destReceived: '1', laneBalance: '0' }; break
      case 'clawback-failed': data = { txId: claws[c].length > 0 ? pick(claws[c]) : 'none', reason: 'f' }; break
      case 'reassembled': data = { copy: ri(1, 4), ok: r() < 0.8, sha256: 'a' }; break
      case 'armed': {
        chain = null
        const order = r() < 0.5 ? ['eth', 'sol'] : [pick(['eth', 'sol'])]
        data = r() < 0.1 ? { armedAt: 1 } : { armedAt: 1000 * seq, releaseAt: 1000 * seq + 5000, countdownSec: 5, schedule: { order, offsetSec: Object.fromEntries(order.map((o, i) => [o, i * 7])) }, caps: Object.fromEntries(order.map((o) => [o, { nativeCap: '1', usd: 1, priceAt: null, overCap: false, planned: '1' }])), sources: {} }
        break
      }
      case 'skip': chain = null; data = { releaseAt: 1000 * seq }; break
      case 'stop-requested': case 'resume-requested': chain = r() < 0.5 ? null : c; data = r() < 0.3 ? {} : { chain: r() < 0.5 ? null : pick(['eth', 'sol']) }; break
      case 'close': chain = r() < 0.5 ? null : c; data = { chain: r() < 0.7 ? pick(['eth', 'sol']) : null }; break
      case 'key-loaded': data = { address: `addr${ri(0, 3)}` }; break
      case 'funds': data = { balance: '1', affordable: r() < 0.7, nextCopyCost: '1' }; break
      case 'replaced': data = { txId: anyTx(c), prevId: anyTx(c), reason: 'bump' }; break
      default: chain = r() < 0.5 ? null : c; data = { text: 't' }
    }
    out.push({ v: 1, seq, at: seq, prev: '', chain, by: chain === null ? 'api' : 'browser', gen: chain === null ? null : gen, type: type as JournalEvent['type'], data })
  }
  return out
}

test('seeded random journals (2,000 lines × 4 seeds): state() = reduce(def, prefix) after every line; the accessors agree', () => {
  const both = BOTH
  for (const seed of [1, 7, 42, 20261009]) {
    const events = randomJournal(seed, 2000)
    const js = createJobState(both)
    events.forEach((e, i) => {
      js.apply(e)
      const want = reduce(both, events.slice(0, i + 1))
      assert.deepEqual(js.state(), want, `seed ${seed} after line ${i}`)
      if (i % 5 === 0) agree(js, both, want, `seed ${seed} after line ${i}`, probesOf(want), nowsOf(want))
    })
  }
})

test('a 12,000-line random journal: the accessors agree after every line, the full state every 250 lines and at the end', () => {
  const both = BOTH
  const events = randomJournal(99, 12_000)
  const js = createJobState(both)
  events.forEach((e, i) => {
    js.apply(e)
    if (i % 250 === 249 || i === events.length - 1) {
      const want = reduce(both, events.slice(0, i + 1))
      assert.deepEqual(js.state(), want, `after line ${i}`)
      agree(js, both, want, `after line ${i}`, probesOf(want), nowsOf(want))
    }
  })
})

test('a reload rebuilds the same state as the live one (registry over the same files)', async (t) => {
  const a = await startApi({ jobs: [] })
  t.after(() => a.close())
  const { id } = await installJournal(a, '12-clawback')
  const live = a.api.registry.state(await a.api.registry.load(id))
  const again = createRegistry({ stateDir: a.state, network: 'local', clock: fakeClock(), out: a.out, ticketKey: TICKET_KEY })
  const reloaded = await again.load(id)
  assert.deepEqual(again.state(reloaded), live)
  assert.deepEqual(live, reduce(reloaded.def, reloaded.journal.all()))
  again.close()
})

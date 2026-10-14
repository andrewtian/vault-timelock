// Final round (R79b review m-4): every stop the lane journals carries the code its cause has in the stop table (contracts/stop.ts), pinned
// one by one here (generic drain controller, fake adapter) — a regression that journals a FINAL cause as a resumable code fails this
// file, also for the FINAL codes no journal fact backs (spend-cap, tx-failed, exhausted, integrity: their class rests on the code; the
// API cross-checks are lane S's). A detach journals no stop at all. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { failCodeOf, newLaneState, runDrain } from '../../src/engine/lane.js'
import { STOP_CODES } from '../../src/contracts/index.ts'
import { armedLedger, journalLanding, recordingJournal } from './fakes.ts'
import type { CapLedger } from '../../src/gates/caps.ts'

type Part = { i: number; n: number; chunk: Uint8Array; payload: Uint8Array }
let LEDGER: CapLedger | null = null
// A fake adapter: 2 parts per copy, each confirms with readback ok (journaled, so the cap ledger counts it) unless `send` says otherwise
function adapter(o: { send?: (t: any) => string; reassemble?: () => unknown; startLevel?: () => Promise<unknown>; reconcile?: () => Promise<unknown>; spend?: bigint } = {}) {
  const A: Record<string, any> = {
    unit: 'test', sha256: 'f'.repeat(64),
    planCopy: (i: number): Part[] => Array.from({ length: 2 }, (_, k) => ({ i: k + 1, n: 2, chunk: new Uint8Array(1), payload: Uint8Array.from([i, k + 1]) })),
    startLevel: o.startLevel ?? (async () => ({ label: 'L0', level: 0 })),
    balance: async () => 100n,
    decide: async (parts: Part[]) => ({ send: true, cost: BigInt(parts.length), spend: o.spend ?? BigInt(parts.length) }),
    sendTx: async (t: any) => {
      if (o.send) return o.send(t)
      t.actual = 1n; t.readback = { ok: true }; journalLanding(LEDGER!, t, 1n); return 'confirmed'
    },
    learn: () => {},
  }
  if (o.reassemble) A.reassemble = o.reassemble
  if (o.reconcile) A.reconcile = o.reconcile
  return A
}
const deps = (journal: unknown, extra: Record<string, unknown> = {}, cap = 10n ** 30n) => ({ journal, sleep: async () => {}, retryMax: 2, retryMs: 1, ledger: (LEDGER = armedLedger('eth', cap)), ...extra })
async function stopOf(A: Record<string, any>, extra: Record<string, unknown> = {}, cap?: bigint): Promise<{ r: string; stops: any[] }> {
  const { journal, events } = recordingJournal()
  const r = await runDrain(newLaneState({ chain: 'eth', mode: 'drain', startCopy: 1 }), A, deps(journal, extra, cap))
  return { r, stops: events.filter((e) => e.type === 'stopped') }
}

test('final round m-4: each lane stop journals its own code (a FINAL cause is never journaled resumable)', async () => {
  const cases: Array<[string, () => Promise<{ r: string; stops: any[] }>, string]> = [
    ['readback mismatch', () => stopOf(adapter({ send: (t) => { t.actual = 1n; t.readback = { ok: false }; journalLanding(LEDGER!, t, 1n); return 'confirmed' } })), 'readback-mismatch'],
    ['confirmed without a journaled inclusion', () => stopOf(adapter({ send: (t) => { t.actual = 1n; t.readback = { ok: true }; return 'confirmed' } })), 'integrity'],
    ['a landed tx that failed (status 0)', () => stopOf(adapter({ send: (t) => { t.landedId = `0x${'1'.repeat(64)}`; t.reason = 'status 0'; return 'failed' } })), 'reverted'],
    ['a tx that failed, not landed', () => stopOf(adapter({ send: (t) => { t.reason = 'nonce used by another tx'; return 'failed' } })), 'tx-failed'],
    ['a stuck attempt', () => stopOf(adapter({ send: () => 'stuck' })), 'stuck'],
    ['fees / balance / cap exhausted', () => stopOf(adapter({ send: () => 'exhausted' })), 'exhausted'],
    ['an outcome the lane does not know', () => stopOf(adapter({ send: () => 'something else' })), 'integrity'],
    ['a copy that did not reassemble', () => stopOf(adapter({ reassemble: async () => ({ ok: false, sha256: 'b'.repeat(64), why: 'another digest' }) })), 'reassembly-mismatch'],
    ['the RPC unavailable while planning', () => stopOf(adapter({ startLevel: async () => { throw new Error('connection refused (test)') } })), 'rpc-unavailable'],
    ['the spend cap cannot cover the next copy', () => stopOf(adapter({ spend: 10n }), {}, 1n), 'spend-cap'],
    ['the reconcile: endpoints unreadable', () => stopOf(adapter({ reconcile: async () => ({ stopped: 'the verified ETH endpoints could not be read', code: 'rpc-unavailable' }) })), 'rpc-unavailable'],
    ['the reconcile: an EIP-7702 delegation under a Stop', () => stopOf(adapter({ reconcile: async () => ({ stopped: 'stopped during reconcile — engine.eip7702: delegated', code: 'eip7702' }) })), 'eip7702'],
    ['the reconcile: a Stop', () => stopOf(adapter({ reconcile: async () => 'stopped' })), 'operator-stop'],
    ['the operator\'s Stop between copies', () => stopOf(adapter(), { stopRequested: () => true, refreshStop: async () => {} }), 'operator-stop'],
  ]
  for (const [name, go, code] of cases) {
    const { stops } = await go()
    assert.deepEqual(stops.map((e) => e.code), [code], name)
    assert.equal(STOP_CODES[code as keyof typeof STOP_CODES].cls, code === 'operator-stop' || code === 'rpc-unavailable' ? 'resumable' : 'final', name)
  }
  // the EIP-7702 stop carries its journal fact too (delegated: true), so the class is final from the journal, not from the code alone
  const d = await stopOf(adapter({ reconcile: async () => ({ stopped: 'stopped during reconcile — engine.eip7702: delegated', code: 'eip7702' }) }))
  assert.equal(d.stops[0].delegated, true)
  // a detach journals no stop, whatever the cause it ends at
  const det = await stopOf(adapter(), { stopRequested: () => true, refreshStop: async () => {}, detachOnly: () => true })
  assert.deepEqual([det.r, det.stops.length], ['detached', 0])
})

test('final round m-4: failCodeOf — every outcome of a part that did not end confirmed / unaffordable / stopped / aborted maps to a FINAL code', () => {
  assert.equal(failCodeOf('failed', { landedId: `0x${'1'.repeat(64)}` }), 'reverted')
  assert.equal(failCodeOf('failed', { landedId: null }), 'tx-failed')
  assert.equal(failCodeOf('failed', {}), 'tx-failed')
  assert.equal(failCodeOf('stuck', {}), 'stuck')
  assert.equal(failCodeOf('exhausted', {}), 'exhausted')
  for (const r of ['', 'confirmed?', 'aborted?', 'paused', 'resume']) assert.equal(failCodeOf(r, {}), 'integrity', r)
  for (const r of ['failed', 'stuck', 'exhausted', 'other']) assert.equal(STOP_CODES[failCodeOf(r, {}) as keyof typeof STOP_CODES].cls, 'final', r)
})

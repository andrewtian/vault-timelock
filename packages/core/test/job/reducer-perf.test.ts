// S2 review I-3 benchmark: an 80,000-event job (16,000 SOL parts × intent, sent, included, readback, + copy-built and
// reassembled per copy) folds one event at a time in about a second here; apply is O(1) amortised, so the per-event
// cost does not grow with the journal (the second half costs about what the first half does). Not mapped to a guard
// (timing). ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { base58 } from '@scure/base'
import { createReducer } from '../../src/job/index.ts'
import type { JobDef, JournalEvent } from '../../src/contracts/index.ts'
import { readJson } from './helpers.ts'

test('80k events apply in under ~2 s; the last 40k cost no more than ~3× the first 40k; state() is one O(n) pass', () => {
  const def = readJson<JobDef>('journals/07-sol-expired.def.json')
  const evs: JournalEvent[] = []
  const add = (type: string, data: Record<string, unknown>, chain: 'sol' | null = 'sol', by: JournalEvent['by'] = 'cli'): void => {
    evs.push({ v: 1, seq: evs.length, at: evs.length, prev: '', chain, by, gen: chain === null ? null : 1, type: type as JournalEvent['type'], data })
  }
  add('armed', { armedAt: 0, releaseAt: 1, countdownSec: 5, schedule: { order: ['sol'], offsetSec: { sol: 0 } }, caps: { sol: { nativeCap: '1000000000000', usd: 0, priceAt: null, overCap: false, planned: '0' } }, sources: {} }, null, 'api')
  const sig = (n: number): string => { const b = new Uint8Array(64); new DataView(b.buffer).setUint32(0, n + 1); return base58.encode(b) }
  const BH = base58.encode(new Uint8Array(32).fill(5)), H = 'ab'.repeat(32), PARTS = 20
  let n = 0
  for (let copy = 1; evs.length < 80_000; copy++) {
    add('copy-built', { copy, parts: PARTS, bytes: Array(PARTS).fill(1000), tight: false, level: 0 })
    for (let part = 1; part <= PARTS; part++) {
      const txId = sig(n++)
      add('intent', { txId, copy, part, parts: PARTS, attempt: 1, replaces: null, rawSha256: H, payloadSha256: H, reserved: '5000', sol: { blockhash: BH, lastValidBlockHeight: 1, cuPrice: 0, cuLimit: 30000, rung: null, fee: '5000' } })
      add('sent', { txId, outcome: 'accepted', reason: null })
      add('included', { txId, copy, part, attempt: 1, block: '9', fee: '5000', ms: 1 })
      add('readback', { txId, ok: true, detail: 'payload bytes match' })
    }
    add('reassembled', { copy, ok: true, sha256: H })
  }
  const r = createReducer(def), half = Math.floor(evs.length / 2)
  const t0 = performance.now()
  for (let i = 0; i < half; i++) r.apply(evs[i])
  const t1 = performance.now()
  for (let i = half; i < evs.length; i++) r.apply(evs[i])
  const t2 = performance.now()
  const st = r.state()
  const t3 = performance.now()
  assert.equal(st.chains.sol!.txs.length, n); assert.equal(st.chains.sol!.spent, String(5000n * BigInt(n)))
  assert.ok(t2 - t0 < 2_000, `apply ${Math.round(t2 - t0)} ms for ${evs.length} events`)
  assert.ok(t2 - t1 < 3 * (t1 - t0) + 50, `the second half ${Math.round(t2 - t1)} ms vs the first ${Math.round(t1 - t0)} ms: no growth with n`)
  assert.ok(t3 - t2 < 2_000, `state() ${Math.round(t3 - t2)} ms`)
  console.log(`# reducer benchmark: ${evs.length} events, apply ${Math.round(t2 - t0)} ms (halves ${Math.round(t1 - t0)} / ${Math.round(t2 - t1)} ms), state() ${Math.round(t3 - t2)} ms`)
})

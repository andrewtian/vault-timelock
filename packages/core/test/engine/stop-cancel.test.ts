// m-b (M5d review): the lane acts on the stop flag as last synced, up to one lease tick old. When opStop's re-read of the API shows that
// the operator's stop request was LIFTED meanwhile (vt job resume, the page's "Cancel the stop"), it is no stop: nothing is journaled (an
// operator-stop without a held request is FINAL at the API) and the lane goes on — at every place it calls opStop: the reconcile, a copy's
// start, between parts, the Tor pause, the planning retry, a part that came back `stopped`. A request still held at the re-read is journaled
// operator-stop as before; a detach stays a detach; the engine's own codes are journaled whatever the request. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { newLaneState, runDrain } from '../../src/engine/lane.js'
import { armedLedger, journalLanding, recordingJournal } from './fakes.ts'
import type { CapLedger } from '../../src/gates/caps.ts'

type Part = { i: number; n: number; chunk: Uint8Array; payload: Uint8Array }
let LEDGER: CapLedger | null = null
const confirm = (t: any): string => { t.actual = 1n; t.readback = { ok: true }; journalLanding(LEDGER!, t, 1n); return 'confirmed' }
function adapter(o: { send?: (t: any, n: number) => string; torOk?: () => boolean; startLevel?: (n: number) => Promise<unknown>; reconcile?: (n: number) => Promise<unknown> } = {}) {
  let sends = 0, levels = 0, reconciles = 0
  const sent: string[] = []
  const A: Record<string, any> = {
    unit: 'test', sha256: 'f'.repeat(64),
    planCopy: (i: number): Part[] => Array.from({ length: 2 }, (_, k) => ({ i: k + 1, n: 2, chunk: new Uint8Array(1), payload: Uint8Array.from([i, k + 1]) })),
    startLevel: async () => { if (++levels > 20) throw new Error('invariant violated: the planning looped (test bound)'); return o.startLevel ? o.startLevel(levels) : { label: 'L0', level: 0 } },
    balance: async () => 100n,
    decide: async (parts: Part[]) => ({ send: true, cost: BigInt(parts.length), spend: BigInt(parts.length) }),
    sendTx: async (t: any) => { if (++sends > 20) throw new Error('invariant violated: the sends looped (test bound)'); sent.push(`${t.copy}.${t.part}`); return o.send ? o.send(t, sends) : confirm(t) },
    learn: () => {},
  }
  if (o.reconcile) A.reconcile = async () => { if (++reconciles > 5) throw new Error('invariant violated: the reconcile looped (test bound)'); return o.reconcile!(reconciles) }   // a mutant that loops fails, never hangs
  return { A, sent }
}
// the executor's stop state as the lane sees it: `flag` (stopFlag, as last synced) and the API's request; refreshStop re-reads the API.
// liftAt: the refresh number at which the operator's resume has lifted the request (the flag still stale until then)
function stopState(o: { liftAt: number; detach?: boolean }) {
  let flag = false, held = false, refreshes = 0
  return {
    raise() { flag = true; held = true },                                // `vt job stop`, seen at a lease tick
    deps: {
      stopRequested: () => flag,
      refreshStop: async () => { refreshes++; if (held && refreshes >= o.liftAt) held = false; flag = held },
      ...(o.detach === true ? { detachOnly: () => true } : {}),
    },
    refreshes: () => refreshes,
  }
}
async function run(A: Record<string, any>, extra: Record<string, unknown>, copiesLimit = 2) {
  const { journal, events } = recordingJournal()
  const lane = newLaneState({ chain: 'eth', mode: 'copies', startCopy: 1 })
  const r = await runDrain(lane, A, { journal, sleep: async () => {}, retryMax: 5, retryMs: 1, copiesLimit, ledger: (LEDGER = armedLedger('eth', 10n ** 30n)), ...extra })
  return { r, stops: events.filter((e) => e.type === 'stopped').map((e) => e.code) }
}

test('m-b: a stop request lifted before opStop journals it is no stop — at each place the lane stops, nothing is journaled and the lane goes on to copies-done', async () => {
  // a copy's start: stopNow's own refresh still sees the request, opStop's re-read finds it lifted
  { const st = stopState({ liftAt: 2 }); st.raise(); const f = adapter()
    const out = await run(f.A, st.deps)
    assert.deepEqual([out.r, out.stops, f.sent], ['copies-done', [], ['1.1', '1.2', '2.1', '2.2']], 'a copy\'s start') }
  // between parts: raised while part 1 was in flight
  { const st = stopState({ liftAt: 3 }); const f = adapter({ send: (t, n) => { if (n === 1) st.raise(); return confirm(t) } })
    const out = await run(f.A, st.deps)
    assert.deepEqual([out.r, out.stops, f.sent], ['copies-done', [], ['1.1', '1.2', '2.1', '2.2']], 'between parts') }
  // a part that came back `stopped` (the engine read the stale flag at a window's end): the same part goes on, never a second part in flight
  { const st = stopState({ liftAt: 2 }); const f = adapter({ send: (t, n) => { if (n === 1) { st.raise(); t.pendingAtStop = true; t.reason = 'pending at the window end'; return 'stopped' } return confirm(t) } })
    const out = await run(f.A, st.deps)
    assert.deepEqual([out.r, out.stops, f.sent], ['copies-done', [], ['1.1', '1.1', '1.2', '2.1', '2.2']], 'a part back `stopped`: sent on (its open attempt)') }
  // the Tor pause: the stale flag read in the pause loop
  { const st = stopState({ liftAt: 2 }); let tor = 0; const f = adapter()
    const out = await run(f.A, { ...st.deps, torOk: async () => { if (++tor === 1) { st.raise(); return false } return true } })
    assert.deepEqual([out.r, out.stops], ['copies-done', []], 'the Tor pause') }
  // the planning retry: the stale flag read between retries
  { const st = stopState({ liftAt: 2 }); const f = adapter({ startLevel: async (n) => { if (n === 1) { st.raise(); throw new Error('RPC error (test)') } return { label: 'L0', level: 0 } } })
    const out = await run(f.A, st.deps)
    assert.deepEqual([out.r, out.stops], ['copies-done', []], 'the planning retry') }
  // the reconcile: it came back `stopped` on the stale flag; it is run again (read-only) and the lane goes on
  { const st = stopState({ liftAt: 1 }); st.raise(); let again = 0; const f = adapter({ reconcile: async (n) => { again = n; return n === 1 ? 'stopped' : 'ok' } })
    const out = await run(f.A, st.deps)
    assert.deepEqual([out.r, out.stops, again], ['copies-done', [], 2], 'the reconcile, run again') }
})

test('m-b: a request still held at the re-read is journaled operator-stop as before; a detach stays a detach; the engine\'s own codes are journaled whatever the request', async () => {
  { const st = stopState({ liftAt: Number.MAX_SAFE_INTEGER }); st.raise(); const f = adapter()
    const out = await run(f.A, st.deps)
    assert.deepEqual([out.r, out.stops, f.sent], ['stopped', ['operator-stop'], []], 'held: journaled') }
  { const st = stopState({ liftAt: 2, detach: true }); st.raise(); const f = adapter()
    const out = await run(f.A, st.deps)
    assert.deepEqual([out.r, out.stops], ['detached', []], 'a detach journals nothing and does not go on') }
  { const st = stopState({ liftAt: 1 }); st.raise(); const f = adapter({ reconcile: async () => ({ stopped: 'the verified ETH endpoints could not be read', code: 'rpc-unavailable' }) })
    const out = await run(f.A, st.deps)
    assert.deepEqual([out.r, out.stops], ['stopped', ['rpc-unavailable']], 'an engine code is journaled even with the request lifted') }
  { const st = stopState({ liftAt: 1 }); st.raise(); const f = adapter({ reconcile: async () => ({ stopped: 'stopped during reconcile — engine.eip7702: delegated', code: 'eip7702' }) })
    const out = await run(f.A, st.deps)
    assert.deepEqual([out.r, out.stops], ['stopped', ['eip7702']]) }
})

// R72 resume-at-part and copy markers in the lane runner (runDrain): a resumed run starts at {copy, nextPart} and never
// builds or sends an earlier part of that copy; copies 2..N carry the copy marker on every part; copies mode ends
// copies-done; each finished copy is reassembled (reassembled event; a failure stops the lane). ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Keypair } from '@solana/web3.js'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { ethAdapter, newLaneState, runCopiesLane, runDrain, runDrainLane, solAdapter, validateLaneConfig } from '../../src/engine/lane.js'
import { ETH } from '../../src/chains/constants.js'
import { reassembleCopy, utf8 } from '../../src/chains/plan.js'
import { parsePart } from '../../src/contracts/index.ts'
import { sha256Hex } from '../../src/job/canonical.ts'
import { armedLedger, armedState, fakeEthChain, fakeRelay, journalLanding, recordingJournal } from './fakes.ts'
import type { CapLedger } from '../../src/gates/caps.ts'

type Part = { i: number; n: number; chunk: Uint8Array; payload: Uint8Array }
const dec = new TextDecoder('utf-8', { fatal: true })

// A fake adapter: N parts per copy, each tx costs 1 and confirms with readback ok. Records what was planned and sent.
function fakeAdapter(o: { parts?: number; balance?: bigint; reassemble?: (i: number, txs: any[], landed: Record<number, string> | null) => any } = {}) {
  const n = o.parts ?? 5
  let bal = o.balance ?? 100n
  const sent: string[] = [], decided: number[][] = []
  const A: Record<string, any> = {
    unit: 'test', sha256: 'f'.repeat(64),
    planCopy: (i: number): Part[] => Array.from({ length: n }, (_, k) => ({ i: k + 1, n, chunk: new Uint8Array(1), payload: Uint8Array.from([i, k + 1]) })),
    startLevel: async () => ({ label: 'L0', level: 0 }),
    balance: async () => bal,
    decide: async (parts: Part[], _l: unknown, b: bigint) => { decided.push(parts.map((p) => p.i)); const cost = BigInt(parts.length); return b >= cost ? { send: true, cost, spend: cost } : { send: false, cost } },
    sendTx: async (t: any) => { sent.push(`${t.copy}.${t.part}`); bal -= 1n; t.actual = 1n; t.readback = { ok: true }; journalLanding(LEDGER!, t, 1n); return 'confirmed' },
    learn: () => {},
  }
  if (o.reassemble) A.reassemble = o.reassemble
  return { A, sent, decided }
}
let LEDGER: CapLedger | null = null                                   // the ledger of the latest deps (the fake adapter journals into it)
const deps = (journal: unknown, extra: Record<string, unknown> = {}) => ({ journal, sleep: async () => {}, ledger: (LEDGER = armedLedger('eth', 10n ** 30n)), ...extra })

test('resume {copy 2, nextPart 4}: the first tx built is copy 2 part 4; parts 1–3 of copy 2 are never built or sent', async () => {
  const f = fakeAdapter({ balance: 12n }), { journal, events } = recordingJournal()
  const lane = newLaneState({ chain: 'sol', mode: 'drain', startCopy: 1 })
  const r = await runDrain(lane, f.A, deps(journal, { resume: { copy: 2, nextPart: 4 } }))
  assert.equal(r, 'drained')
  assert.deepEqual(f.sent.slice(0, 2), ['2.4', '2.5'], 'copy 2 part 4 first')
  assert.ok(!f.sent.some((s) => ['1.1', '2.1', '2.2', '2.3'].includes(s)), 'nothing of copy 1, no part 1–3 of copy 2')
  assert.ok(!lane.txs.some((t: any) => t.copy === 2 && t.part < 4), 'no tx object for copy 2 parts 1–3')
  assert.deepEqual(lane.txs[0] && [lane.txs[0].copy, lane.txs[0].part], [2, 4])
  assert.deepEqual(f.decided[0], [4, 5], 'the resumed copy is costed by its remaining parts')
  assert.deepEqual(f.decided[1], [1, 2, 3, 4, 5], 'the next copy is a full copy')
  assert.deepEqual(f.sent.slice(2), ['3.1', '3.2', '3.3', '3.4', '3.5', '4.1', '4.2', '4.3', '4.4', '4.5'])
  const built = events.filter((e) => e.type === 'copy-built')
  assert.deepEqual(built.map((e) => [e.copy, e.parts]), [[2, 5], [3, 5], [4, 5]], 'copy-built describes the whole copy')
  assert.deepEqual(events.at(-1), { type: 'drained', chain: 'sol', balance: '0', nextCost: '5', copy: 5 })
})

test('resume past the last part: that copy is complete, the run starts with the next copy', async () => {
  const f = fakeAdapter({ balance: 5n }), { journal } = recordingJournal()
  const lane = newLaneState({ chain: 'eth', mode: 'drain', startCopy: 1 })
  assert.equal(await runDrain(lane, f.A, deps(journal, { resume: { copy: 2, nextPart: 6 } })), 'drained')
  assert.deepEqual(f.sent, ['3.1', '3.2', '3.3', '3.4', '3.5'])
})

test('a malformed resume point is a programming error (invariant), never a silent restart at copy 1', async () => {
  const f = fakeAdapter(), { journal } = recordingJournal()
  for (const resume of [{ copy: 0, nextPart: 1 }, { copy: 2, nextPart: 0 }, { copy: 1.5, nextPart: 1 }, { copy: 2 }]) {
    await assert.rejects(runDrain(newLaneState({ chain: 'eth', mode: 'drain', startCopy: 1 }), f.A, deps(journal, { resume })), /invariant/)
  }
  assert.deepEqual(f.sent, [])
})

test('copies mode: copies-done after copy N (and a resumed copies run counts from the resume copy)', async () => {
  const f = fakeAdapter({ parts: 2 }), { journal, events } = recordingJournal()
  assert.equal(await runDrain(newLaneState({ chain: 'eth', mode: 'copies', startCopy: 1 }), f.A, deps(journal, { copiesLimit: 3 })), 'copies-done')
  assert.deepEqual(f.sent, ['1.1', '1.2', '2.1', '2.2', '3.1', '3.2'])
  assert.deepEqual(events.at(-1), { type: 'copies-done', chain: 'eth', copies: 3 })
  const g = fakeAdapter({ parts: 2 }), j2 = recordingJournal()
  assert.equal(await runDrain(newLaneState({ chain: 'eth', mode: 'copies', startCopy: 1 }), g.A, deps(j2.journal, { copiesLimit: 3, resume: { copy: 3, nextPart: 2 } })), 'copies-done')
  assert.deepEqual(g.sent, ['3.2'])
})

test('reassembly after each copy: reassembled {copy, ok, sha256}; a resumed copy gets the landed tx ids; a failure stops the lane', async () => {
  const seen: Array<[number, string[], Record<number, string> | null]> = []
  const f = fakeAdapter({ parts: 3, balance: 6n, reassemble: async (i, txs, landed) => { seen.push([i, txs.map((t: any) => `${t.copy}.${t.part}`), landed]); return { ok: true, sha256: 'a'.repeat(64), why: '' } } })
  const { journal, events } = recordingJournal()
  const landed = { 1: `0x${'1'.repeat(64)}`, 2: `0x${'2'.repeat(64)}` }
  assert.equal(await runDrain(newLaneState({ chain: 'eth', mode: 'drain', startCopy: 1 }), f.A, deps(journal, { resume: { copy: 4, nextPart: 3, landed } })), 'drained')
  assert.deepEqual(seen, [[4, ['4.3'], landed], [5, ['5.1', '5.2', '5.3'], null]])
  assert.deepEqual(events.filter((e) => e.type === 'reassembled'), [{ type: 'reassembled', chain: 'eth', copy: 4, ok: true, sha256: 'a'.repeat(64) }, { type: 'reassembled', chain: 'eth', copy: 5, ok: true, sha256: 'a'.repeat(64) }])
  const bad = fakeAdapter({ parts: 2, reassemble: async () => ({ ok: false, sha256: 'b'.repeat(64), why: 'the reassembled text has another sha256' }) })
  const j2 = recordingJournal()
  const lane = newLaneState({ chain: 'sol', mode: 'drain', startCopy: 1 })
  assert.equal(await runDrain(lane, bad.A, deps(j2.journal)), 'stopped')
  assert.match(lane.reason, /did not reassemble/)
  assert.deepEqual(bad.sent, ['1.1', '1.2'], 'no next copy after a failed reassembly')
  const none = fakeAdapter({ parts: 2, balance: 2n, reassemble: async () => null }), j3 = recordingJournal()
  await runDrain(newLaneState({ chain: 'sol', mode: 'drain', startCopy: 1 }), none.A, deps(j3.journal, { resume: { copy: 1, nextPart: 2 } }))
  assert.ok(j3.events.some((e) => e.type === 'note' && /not reassembled/.test(String(e.text))), 'unknown earlier tx ids: a note, no false claim')
})

// ---- the real adapters' planners: R72 headers and copy markers (planCopy is pure) ----
const text = Array.from({ length: 60 }, (_, k) => `line ${k} — é 😀 漢`).join('\n')   // a few SOL parts
const ethKey = { chain: 'eth', account: privateKeyToAccount(generatePrivateKey()) }
const solKey = { chain: 'sol', kp: Keypair.generate() }
const cfgOf = (chain: 'eth' | 'sol', extra: Record<string, unknown>, t = text) => { const v = validateLaneConfig({ chain, text: t, ...extra }); assert.equal(v.ok, true, v.errors.join()); return v.cfg }
const D = { network: 'local', journal: recordingJournal().journal }

test('copies 2..N carry the copy marker on every part (copies mode: [copy c/N]); copy 1 none; every copy reassembles to one digest', () => {
  const cfg = cfgOf('sol', { mode: 'copies', copies: 3, distinct: true })
  const A = solAdapter(cfg, solKey, D), sha = sha256Hex(utf8(text))
  for (const c of [1, 2, 3]) {
    const parts: Part[] = A.planCopy(c)
    assert.ok(parts.length >= 3, 'a multi-part text')
    for (const p of parts) {
      const h = parsePart(dec.decode(p.payload))
      assert.equal(h.part, p.i); assert.equal(h.parts, p.n); assert.equal(h.h8, sha.slice(0, 8))
      assert.equal(h.copy, c); assert.equal(h.copies, c === 1 ? null : 3)
      assert.equal(dec.decode(p.payload).split('\n')[0].includes(`[copy ${c}/3]`), c > 1)
    }
    assert.deepEqual(reassembleCopy(parts.map((p) => p.payload), { sha256: sha }), { ok: true, sha256: sha, why: '' })
  }
})

test('drain mode markers are [copy c] (N unknown); distinct off: no marker, byte-identical copies', () => {
  const drain = ethAdapter(cfgOf('eth', { mode: 'drain', distinct: true }, 'x'.repeat(200_000)), ethKey, D)
  for (const p of drain.planCopy(7)) assert.match(dec.decode(p.payload).split('\n')[0], new RegExp(`^data:,\\[${p.i}/${p.n} [0-9a-f]{8}.*\\] \\[copy 7\\]$`))
  const same = ethAdapter(cfgOf('eth', { mode: 'copies', copies: 2, distinct: false }, 'x'.repeat(200_000)), ethKey, D)
  assert.deepEqual(same.planCopy(2).map((p: Part) => p.payload), same.planCopy(1).map((p: Part) => p.payload))
  const one = ethAdapter(cfgOf('eth', { mode: 'copies', copies: 2, distinct: true }, 'hello'), ethKey, D)
  assert.deepEqual(one.planCopy(1).map((p: Part) => dec.decode(p.payload)), ['data:,hello'])
  assert.deepEqual(one.planCopy(2).map((p: Part) => dec.decode(p.payload)), ['data:,[copy 2/2]\nhello'], 'a one-part copy 2: the marker line alone')
  assert.equal(ETH.PREFIX, 'data:,')
})

test('runCopiesLane end to end (fake chain): every event has the contract shape; each copy reassembles from chain bytes; copies-done', async () => {
  const chain = fakeEthChain(), relay = fakeRelay({ eth: chain.handler })
  const { journal, events } = recordingJournal()
  const cfg = cfgOf('eth', { mode: 'copies', copies: 2, distinct: true, feeStrategy: 'economy' }, 'x'.repeat(100_000))
  const lane = newLaneState(cfg)
  const d = { journal, network: 'local', chainId: 31337, state: armedState('eth', 10n ** 17n), poll: 1, alive: () => true, notify: async () => {}, sleep: async () => {} }
  assert.equal(await runCopiesLane(cfg, ethKey, lane, d), 'copies-done')
  const kinds = events.map((e) => e.type)
  assert.deepEqual(kinds.filter((k) => k === 'intent').length, 4, '2 copies × 2 parts')
  assert.deepEqual(events.filter((e) => e.type === 'reassembled').map((e) => [e.copy, e.ok, e.sha256]), [[1, true, sha256Hex(utf8(cfg.text))], [2, true, sha256Hex(utf8(cfg.text))]])
  assert.deepEqual(events.at(-1), { type: 'copies-done', chain: 'eth', copies: 2 })
  const second = relay.sends()[2]
  assert.ok(second, 'copy 2 part 1 was sent')
  assert.match(dec.decode(lane.txs[2].chainBytes).split('\n')[0], /\] \[copy 2\/2\]$/, 'copy 2 carries [copy 2/2] on chain')
  await assert.rejects(runDrainLane(cfg, ethKey, newLaneState(cfg), d), /invariant/, 'a copies config on the drain runner')
  await assert.rejects(runCopiesLane(cfg, ethKey, newLaneState(cfg), { ...d, state: undefined, cap: 10n ** 18n }), (e: Error & { guardId?: string }) => e.guardId === 'engine.cap-armed', 'no armed state, no lane — a free deps.cap is ignored (a rejection, not a sync throw)')
  await assert.rejects(runCopiesLane(cfg, ethKey, newLaneState(cfg), { ...d, network: 'nowhere' }), (e: Error & { guardId?: string }) => e.guardId === 'contract.network', 'the network is injected and checked')
})

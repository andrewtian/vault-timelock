// node --test test/economy.test.mjs — R64: economy ladder math, drained threshold, final-copy tight maxFee, claw-back amounts,
// copy suffixes, SOL rungs, the lane config object, and the drain controller's invariants (never two in flight, Stop semantics).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ECON } from '../../src/chains/constants.js'
import { drainCopyText, ethClawback, ethCopyCost, ethDrainDecision, ethEconomyBump, ethEconomyInitial, ethStartTip, ethTightMaxFee, ethTip0, solClawback, solDrainDecision, solNextRung, solRungs, solStartRung, isEthReserved, isSolReserved, ethReservedKind, solReservedKind, validateEthDest, validateSolDest } from '../../src/chains/economy.js'
import { newLaneState, runDrain, validateLaneConfig } from '../../src/engine/lane.js'
import { ethGasBudget } from '../../src/chains/plan.js'
import { armedLedger } from '../engine/fakes.ts'

const G = 10n ** 9n
test('ETH tip₀ = max(measured floor 12,000 wei, median per-block p10); learning probes down by ÷1.125', () => {
  assert.equal(ECON.ETH_TIP_FLOOR, 12000n)
  assert.equal(ethTip0([['0x2ee0', '0x10'], ['0x186a0', '0x10'], ['0x0', '0x10']]), 12000n)          // median(12000, 100000, 0) = 12000
  assert.equal(ethTip0([['0x186a0'], ['0x30d40'], ['0x186a0']]), 100000n)                             // median 100,000 > floor
  assert.equal(ethTip0([['0x1'], ['0x2'], ['0x3']]), 12000n)                                          // below the floor → floor
  assert.equal(ethStartTip(12000n, null), 12000n)
  assert.equal(ethStartTip(12000n, 30800n), 27377n)                                                   // 30800 ÷ 1.125 (floored)
  assert.equal(ethStartTip(50000n, 30800n), 50000n)                                                   // never below fresh tip₀
})
test('ETH first attempt: maxFee = 2·base + tip (tight final copy ⌈1.25·base⌉ + tip); pause above the per-tx cap', () => {
  assert.deepEqual(ethEconomyInitial({ nextBase: 300n, startTip: 12000n, cap: 3n * G }), { tip: 12000n, maxFee: 12600n })
  assert.deepEqual(ethEconomyInitial({ nextBase: 301n, startTip: 12000n, tight: true, cap: 3n * G }), { tip: 12000n, maxFee: 12377n })   // ⌈376.25⌉ + 12000
  assert.match(ethEconomyInitial({ nextBase: 1n, startTip: 4n * G, cap: 3n * G }).pause, /above the per-tx tip cap/)
  assert.equal(ethTightMaxFee(1000n, 5n), 1255n)
})
test('ETH stall bump: BOTH fields ×1.125 (ceil, +1 wei), maxFee re-read from base; pause at the cap; wait when unaffordable', () => {
  const b = ethEconomyBump({ tip: 12000n, maxFee: 12600n }, { nextBase: 300n, cap: 3n * G })
  assert.deepEqual(b, { tip: 13501n, maxFee: 14176n })                                                 // ⌈13500⌉+1, max(⌈14175⌉+1, 600+13501)
  const hb = ethEconomyBump({ tip: 12000n, maxFee: 12600n }, { nextBase: 100000n, cap: 3n * G })        // base jumped → maxFee re-read
  assert.equal(hb.maxFee, 2n * 100000n + 13501n)
  assert.match(ethEconomyBump({ tip: 3n * G - 1n, maxFee: 7n * G }, { nextBase: 1n, cap: 3n * G }).pause, /would exceed the per-tx tip cap/)
  assert.match(ethEconomyBump({ tip: 12000n, maxFee: 12600n }, { nextBase: 300n, cap: 3n * G, balance: 1000n, gas: 25000n }).wait, /waiting/)
  let p = { tip: 12000n, maxFee: 12600n }, n = 0                                                       // from the floor to 30,000 wei takes 8 bumps
  while (p.tip < 30000n) { p = ethEconomyBump(p, { nextBase: 7n, cap: 3n * G }); n++ }
  assert.equal(n, 8); assert.equal(p.tip, 30807n)
})
test('ETH drained threshold: full copy at 2·base + tip, else the tight final copy, else drained', () => {
  const lens = [106], gas = ethGasBudget(106), base = 300n, tip = 12000n
  assert.equal(ethCopyCost(lens, base, tip), gas * 12600n)
  assert.deepEqual(ethDrainDecision(gas * 12600n, lens, base, tip), { send: true, tight: false, cost: gas * 12600n })
  const tightCost = gas * (375n + 12000n)
  assert.deepEqual(ethDrainDecision(tightCost, lens, base, tip), { send: true, tight: true, cost: tightCost })
  assert.deepEqual(ethDrainDecision(tightCost - 1n, lens, base, tip), { send: false, drained: true, cost: gas * 12600n })
})
test('SOL rungs: P₀ = 0, then p25/p50/p75/p90 of the non-zero fees (capped, deduped); fallback; learning; pause past the top', () => {
  const mainnet = [151992, 170300, 187500, 202657, 0, 0].map((x) => ({ prioritizationFee: x }))
  assert.deepEqual(solRungs(mainnet), [0, 151992, 170300, 187500, 202657])
  assert.deepEqual(solRungs([{ prioritizationFee: 5e6 }]), [0, 2000000])                              // capped + deduped
  assert.deepEqual(solRungs([]), [0, 100000, 500000, 1000000, 2000000])                                // quiet RPC → fallback
  assert.deepEqual(solRungs(mainnet, { cap: 160000 }), [0, 151992, 160000])
  assert.equal(solStartRung(null), 0); assert.equal(solStartRung(3), 2); assert.equal(solStartRung(0), 0)
  assert.deepEqual(solNextRung(1, [0, 10, 20]), { rung: 2 })
  assert.match(solNextRung(2, [0, 10, 20]).pause, /top rung 20/)
})
test('SOL drained threshold: the payer must end at ≥ rent + claw-back fee reserve, or exactly 0 (measured)', () => {
  const rent = 890880n
  assert.equal(solDrainDecision(rent + 10000n, [5000n], rent).send, true)                              // ends at rent + 5000
  assert.equal(solDrainDecision(rent + 9999n, [5000n], rent).drained, true)                            // would strand the remainder
  assert.equal(solDrainDecision(rent + 9999n, [5000n], rent).cost, 5000n + rent + 5000n)
  assert.equal(solDrainDecision(rent + 15000n, [5000n, 5000n], rent).send, true)                       // 2-part copy
  assert.equal(solDrainDecision(10000n, [5000n, 5000n], rent).send, true)                              // ends exactly at 0
})
test('claw back amounts: ETH value = balance − 21000 × (2·base + tip), dust shown; SOL amount = balance − fee, new destination ≥ rent', () => {
  const c = ethClawback(10n ** 15n, 300n, 12000n)
  assert.equal(c.value, 10n ** 15n - 21000n * 12600n); assert.equal(c.expectedDust, 21000n * 300n)
  assert.equal(ethClawback(21000n * 12600n, 300n, 12000n).ok, false)
  assert.deepEqual(solClawback(900000n, 5000n, 1n, 890880n), { ok: true, amount: 895000n })
  assert.match(solClawback(893000n, 5000n, 0n, 890880n).why, /fee-payer rule/)                       // 888,000 < rent after the fee
  assert.match(solClawback(893000n, 5000n, 1n, 890880n).why, /fee-payer rule/)                         // … even to an existing account
  assert.equal(solClawback(890880n + 5000n, 5000n, 1n, 890880n).amount, 890880n)                      // a drained lane (rent + reserve) → 0
  assert.equal(solClawback(900000n, 5000n, 0n, 890880n).ok, true)                                      // 895,000 ≥ rent → fine
})
test('isEthReserved: 0x…0001 to 0x…ffff are reserved (precompiles and the range kept for more); 0x…010000 is not', () => {
  const at = (n) => `0x${n.toString(16).padStart(40, '0')}`
  for (const n of [0n, 1n, 9n, 0x11n, 0x100n, 0xffffn]) assert.equal(isEthReserved(at(n)), true, n.toString(16))
  for (const n of [0x10000n, 0x10001n]) assert.equal(isEthReserved(at(n)), false, n.toString(16))
  assert.equal(isEthReserved('0x70997970C51812dc3A010C7d01b50e0d17dc79C8'), false)
})
test('claw-back destinations: EIP-55 only, never 0x0 / the lane / the incinerator', () => {
  const A = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'
  assert.equal(validateEthDest(A).ok, true)
  assert.match(validateEthDest(A.toLowerCase()).why, /EIP-55/)
  assert.match(validateEthDest('0x0000000000000000000000000000000000000000').why, /null address/)
  assert.match(validateEthDest(A, A.toLowerCase()).why, /lane address/)
  assert.equal(validateSolDest('8jy3aPvZbRwJW9qY5S4JXtqMZBSzAFvBPa2jhQ2SXbhq').ok, true)
  assert.match(validateSolDest('1nc1nerator11111111111111111111111111111111').why, /incinerator/)
  assert.match(validateSolDest('not-base58!').why, /base58/)
})
test('drain copy text: copy 1 = the text; copy i ≥ 2 = text + "\\n[copy i]" (distinct ON); unchanged when OFF', () => {
  assert.equal(drainCopyText('hi', 1, true), 'hi'); assert.equal(drainCopyText('hi', 7, true), 'hi\n[copy 7]'); assert.equal(drainCopyText('hi', 7, false), 'hi')
})
test('lane config: one plain serializable object; defaults drain + null + distinct; key material refused', () => {
  const v = validateLaneConfig({ chain: 'eth', text: 'hello' })
  assert.equal(v.ok, true); assert.equal(v.cfg.mode, 'drain'); assert.equal(v.cfg.recipient, 'null'); assert.equal(v.cfg.distinct, true)
  assert.deepEqual(JSON.parse(JSON.stringify(v.cfg)), v.cfg)
  assert.match(validateLaneConfig({ chain: 'eth', text: 'x', secret: '0x1' }).errors.join(), /key material/)
  assert.match(validateLaneConfig({ chain: 'sol', text: '' }).errors.join(), /text/)
  assert.match(validateLaneConfig({ chain: 'eth', text: 'x', mode: 'copies', copies: 0 }).errors.join(), /copies/)
  assert.match(validateLaneConfig({ chain: 'eth', text: 'x', tipCapGwei: '0.01' }).errors.join(), /tipCapGwei/)
  assert.match(validateLaneConfig({ chain: 'eth', text: 'x', clawbackTo: '0x0000000000000000000000000000000000000000' }).errors.join(), /null address/)
})

// ---------- the drain controller with a fake adapter ----------
function fakeChain({ balance, cost = 10n, fee = 10n, mismatchAt = null, txMs = 30, stopAfterCopy = null, state }) {
  let bal = balance, inflight = 0, maxInflight = 0
  return {
    stats: () => ({ maxInflight, bal }),
    A: {
      planCopy: (i) => [{ i: 1, n: 1, chunk: new Uint8Array(1), payload: Uint8Array.from([i]) }],
      startLevel: async () => ({ label: 'L0' }),
      balance: async () => bal,
      decide: async (_p, _l, b) => (b >= cost ? { send: true, cost, spend: fee } : { send: false, cost }),
      sendTx: async (t) => {
        inflight++; maxInflight = Math.max(maxInflight, inflight)
        if (stopAfterCopy === t.copy) state.stop = true                // Stop pressed WHILE this tx is in flight
        await new Promise((r) => setTimeout(r, txMs))
        inflight--; bal -= fee; t.actual = fee; t.readback = { ok: mismatchAt !== t.copy }
        // the engine journals the intent and the inclusion; the cap ledger follows the journal (security review: drift)
        const id = `0x${(t.copy * 1000 + t.part).toString(16).padStart(64, '0')}`
        state.ledger.observe({ type: 'intent', chain: 'eth', txId: id, copy: t.copy, part: t.part, parts: t.parts, eth: { nonce: t.copy, tip: '1', maxFee: String(fee), gas: '1', to: '0x0000000000000000000000000000000000000000' } })
        state.ledger.observe({ type: 'included', chain: 'eth', txId: id, copy: t.copy, part: t.part, attempt: 1, block: '1', fee: String(fee), ms: 1 })
        return 'confirmed'
      },
      learn: () => {},
    },
  }
}
// §7.2: the journal replaces onEvent (append is awaited; these fakes never send, so intent is never called).
// E2 security fix: the spend cap is a ledger from the armed job state, mandatory (a wide one unless a test sets it).
const deps = (state, events, cap = 10n ** 30n) => ({ journal: { append: async (e) => { events.push(e) }, intent: async () => { throw new Error('no sends here') } }, ledger: (state.ledger = armedLedger('eth', cap)), stopRequested: () => !!state.stop, sleep: (ms) => new Promise((r) => setTimeout(r, Math.min(ms, 5))) })
test('drain: sends copies one after another until drained (balance < next full copy) — never two in flight', async () => {
  const state = {}, ev = [], f = fakeChain({ balance: 55n, state }), lane = newLaneState({ chain: 'eth', mode: 'drain', startCopy: 1 })
  const r = await runDrain(lane, f.A, deps(state, ev))
  assert.equal(r, 'drained'); assert.equal(lane.copies.length, 5); assert.equal(f.stats().maxInflight, 1); assert.equal(lane.spent, 50n)
  assert.deepEqual(ev.filter((e) => e.type === 'copy-built').map((e) => e.copy), [1, 2, 3, 4, 5])
  assert.equal(ev.at(-1).type, 'drained'); assert.equal(ev.at(-1).balance, '5')
})
test('drain: Stop during an in-flight tx → that tx resolves, NO further tx starts', async () => {
  const state = {}, ev = [], f = fakeChain({ balance: 1000n, stopAfterCopy: 3, state }), lane = newLaneState({ chain: 'sol', mode: 'drain', startCopy: 1 })
  const r = await runDrain(lane, f.A, deps(state, ev))
  assert.equal(r, 'stopped'); assert.equal(lane.copies.length, 3); assert.ok(lane.copies.every((c) => c.txs.every((t) => t.readback?.ok)))
  assert.equal(ev.at(-1).type, 'stopped')
})
test('drain: a readback mismatch stops the lane (fail closed)', async () => {
  const state = {}, ev = [], f = fakeChain({ balance: 1000n, mismatchAt: 2, state }), lane = newLaneState({ chain: 'eth', mode: 'drain', startCopy: 1 })
  assert.equal(await runDrain(lane, f.A, deps(state, ev)), 'stopped'); assert.match(lane.reason, /readback mismatch on copy 2/); assert.equal(lane.copies.length, 2)
})
test('drain: relay not on Tor → paused (no tx), resumes when Tor is back; spend cap stops the lane', async () => {
  const state = {}, ev = [], f = fakeChain({ balance: 30n, state }), lane = newLaneState({ chain: 'eth', mode: 'drain', startCopy: 1 })
  let checks = 0
  const r = await runDrain(lane, f.A, { ...deps(state, ev), torOk: async () => ++checks > 2 })
  assert.equal(r, 'drained'); assert.deepEqual(ev.slice(0, 2).map((e) => e.type), ['paused', 'resumed']); assert.match(ev[0].reason, /not on Tor/)
  const st2 = {}, ev2 = [], f2 = fakeChain({ balance: 1000n, state: st2 }), l2 = newLaneState({ chain: 'eth', mode: 'drain', startCopy: 1 })
  assert.equal(await runDrain(l2, f2.A, deps(st2, ev2, 25n)), 'stopped'); assert.match(l2.reason, /spend cap/); assert.equal(l2.copies.length, 2)
})
test('drain: a transient RPC error while planning a copy pauses + retries (nothing signed); persistent errors end the lane', async () => {
  const state = {}, ev = [], f = fakeChain({ balance: 30n, state }), lane = newLaneState({ chain: 'sol', mode: 'drain', startCopy: 1 })
  let fails = 3; const bal0 = f.A.balance
  f.A.balance = async () => { if (fails-- > 0) throw new Error('relay 502: upstream unreachable'); return bal0() }
  assert.equal(await runDrain(lane, f.A, { ...deps(state, ev), retryMs: 1 }), 'drained')
  assert.deepEqual(ev.slice(0, 2).map((e) => e.type), ['paused', 'resumed']); assert.match(ev[0].reason, /RPC error while planning copy 1/)
  assert.equal(lane.copies.length, 3)
  const st2 = {}, ev2 = [], f2 = fakeChain({ balance: 30n, state: st2 }), l2 = newLaneState({ chain: 'sol', mode: 'drain', startCopy: 1 })
  f2.A.startLevel = async () => { throw new Error('down') }
  assert.equal(await runDrain(l2, f2.A, { ...deps(st2, ev2), retryMs: 1, retryMax: 4 }), 'failed'); assert.match(l2.reason, /4 consecutive errors/); assert.equal(l2.copies.length, 0)
})
test('reserved addresses (E6): one source per chain — isEthReserved / isSolReserved and their kinds', () => {
  const at = (n) => `0x${n.toString(16).padStart(40, '0')}`
  assert.equal(ethReservedKind(at(0n)), 'null')
  assert.equal(ethReservedKind(at(1n)), 'precompile')
  assert.equal(ethReservedKind(at(0xffffn)), 'precompile')
  assert.equal(ethReservedKind(at(0x10000n)), null)
  assert.equal(ethReservedKind('0x000000000000000000000000000000000000dEaD'), 'burn')
  assert.equal(isEthReserved('0x000000000000000000000000000000000000dEaD'), true)
  assert.equal(isEthReserved('0x000000000000000000000000000000000001dEaD'), false)
  assert.equal(solReservedKind('11111111111111111111111111111111'), 'system')
  assert.equal(solReservedKind('1nc1nerator11111111111111111111111111111111'), 'incinerator')
  assert.equal(isSolReserved('11111111111111111111111111111111'), true)
  assert.equal(isSolReserved('1nc1nerator11111111111111111111111111111111'), true)
  assert.equal(isSolReserved('9xx7qC7uwTAeaSo7T5Gk9canYBosFh1pMQaDmQEa83Tb'), false)
})

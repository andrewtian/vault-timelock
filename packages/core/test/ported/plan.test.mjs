// node --test test/plan.test.mjs — pure-function tests: part sizing, N from amount, USD↔native, blockspace, fee math.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ETH, GWEI, SOL } from '../../src/chains/constants.js'
import {
  amountForCopies, baseToCents, buildPlan, centsToString, copiesFromAmount, cutAt, ethGasLimit, ethGasBudget, ethGasFormula, ethCheckEstimate, ethCopyText, ethMaxFee, ethParts, ethTipFromRewards, solCuPriceFromRecent, solResignPrice,
  ethTextBytesAffordable, formatUnits, leftover, parseDecimal, replacementFees, sig6, solCuLimit, solFee, solParts, solPriorityFee,
  solTxsAffordable, splitText, usdToBase, utf8, validateAmount, validateCopies, weigh, solCharCu, solCuEstimate, ethTextBytesAffordable as _etba,
} from '../../src/chains/plan.js'

const dec = new TextDecoder('utf-8', { fatal: true })
const joinChunks = (parts) => Buffer.concat(parts.map((p) => Buffer.from(p.chunk))).toString('utf8')

test('cutAt never splits a multibyte character', () => {
  const b = utf8('aé€😀')            // 1 + 2 + 3 + 4 bytes
  assert.equal(cutAt(b, 0, 2), 1)      // would cut inside é → back off to 1
  assert.equal(cutAt(b, 0, 3), 3)
  assert.equal(cutAt(b, 3, 2), 3)      // € needs 3 → nothing fits in 2 → stays at start
  assert.equal(cutAt(b, 3, 5), 6)
  assert.equal(cutAt(b, 6, 3), 6)      // 😀 needs 4
  assert.equal(cutAt(b, 6, 4), 10)
})

test('SOL parts: 1,010 B (legacy, both ComputeBudget ixs, memo without accounts) fits without a prefix', () => {
  const t = utf8('x'.repeat(1010))
  const p = solParts(t, 1062)                                                   // policy cap SOL.MEMO_MAX = 1010 applies
  assert.equal(SOL.MEMO_MAX, 1010)
  assert.equal(p.length, 1); assert.equal(p[0].payload.length, 1010); assert.equal(dec.decode(p[0].payload), 'x'.repeat(1010))
})
test('SOL parts: 1,011 B splits into 2 parts with [i/n] prefix, max-size first part, lossless', () => {
  const text = 'y'.repeat(1011)
  const p = solParts(utf8(text), 1010)
  assert.equal(p.length, 2)
  assert.equal(p[0].payload.length, 1010)                                      // as large as possible
  // R72 (vt-parts/1 header, contracts/parts.ts) replaces the prototype's '[1/2] ' / '[2/2] ' prefix:
  assert.match(dec.decode(p[0].payload), /^\[1\/2 [0-9a-f]{8} sha256=[0-9a-f]{64}\]\n/); assert.match(dec.decode(p[1].payload), /^\[2\/2 [0-9a-f]{8}\]\n/)
  assert.equal(joinChunks(p), text)
})
test('byte-limited split: multibyte boundary — every part is valid UTF-8 and ≤ cap', () => {
  const text = '€'.repeat(700) + 'é'.repeat(300) + '😀'.repeat(50)            // 2100 + 600 + 200 = 2900 B
  const cap = 1009
  const p = splitText(utf8(text), { cap })                                       // bytes only (the SOL CU budget is tested below)
  for (const x of p) { assert.ok(x.payload.length <= cap); dec.decode(x.payload) }   // fatal decoder throws on a split char
  assert.equal(joinChunks(p), text)
  assert.equal(p.length, 3)
  assert.ok(p[0].payload.length >= cap - 2, 'first part within one char of the cap')
})
test('ETH parts: data:, + text ≤ 98,304 is one tx; larger splits with prefix after data:,', () => {
  const one = ethParts(utf8('a'.repeat(98298)))
  assert.equal(one.length, 1); assert.equal(one[0].payload.length, 98304)
  const two = ethParts(utf8('a'.repeat(98299)))
  assert.equal(two.length, 2)
  // R72 (vt-parts/1 header after data:,) replaces the prototype's 'data:,[1/2] ' / 'data:,[2/2] ':
  assert.match(dec.decode(two[0].payload), /^data:,\[1\/2 [0-9a-f]{8} sha256=[0-9a-f]{64}\]\n/); assert.equal(two[0].payload.length, 98304)
  assert.match(dec.decode(two[1].payload), /^data:,\[2\/2 [0-9a-f]{8}\]\n/)
  assert.equal(joinChunks(two), 'a'.repeat(98299))
})
test('splitText: prefix width growth converges (10+ parts)', () => {
  const p = splitText(utf8('z'.repeat(5000)), { cap: 500 })
  assert.equal(p.length, 11)                    // [i/11] prefix eats 7–8 B per part
  for (const x of p) assert.ok(x.payload.length <= 500)
  assert.equal(joinChunks(p), 'z'.repeat(5000))
})
test('buildPlan: N copies × parts, copy-major order', () => {
  const parts = solParts(utf8('q'.repeat(1500)), 1010)
  const txs = buildPlan(parts, 3)
  assert.equal(txs.length, 6)
  assert.deepEqual(txs.map((t) => `${t.copy}.${t.part}`), ['1.1', '1.2', '2.1', '2.2', '3.1', '3.2'])
})
test('ETH "make copies distinct": copies 2..N end with \\n[copy i/N]; default off = byte-identical copies', () => {
  const text = 'hello'
  const same = buildPlan(ethParts(utf8(text)), 3)
  assert.ok(same.every((t) => dec.decode(t.payload) === 'data:,hello'))
  const dist = buildPlan((i) => ethParts(utf8(ethCopyText(text, i, 3, true))), 3)
  assert.deepEqual(dist.map((t) => dec.decode(t.payload)), ['data:,hello', 'data:,hello\n[copy 2/3]', 'data:,hello\n[copy 3/3]'])
  assert.equal(ethCopyText(text, 2, 3, false), text)
})

test('decimals: parse/format/validate', () => {
  assert.equal(parseDecimal('1.5', 18), 1500000000000000000n)
  assert.equal(parseDecimal('0.000000001', 9), 1n)
  assert.throws(() => parseDecimal('0.0000000001', 9))
  assert.equal(formatUnits(1500000000000000000n, 18), '1.5')
  assert.equal(formatUnits(5000n, 9), '0.000005')
  assert.equal(sig6(1234567890123456789n, 18), '1.23457')
  assert.equal(sig6(5000n, 9), '0.000005')
  assert.equal(validateAmount('0', 'eth').ok, false)
  assert.equal(validateAmount('1.0000000000000000001', 'eth').ok, false)  // 19 decimals
  assert.equal(validateAmount('0.000000000000000001', 'eth').value, 1n)
  assert.equal(validateAmount('0.0000000001', 'sol').ok, false)           // 10 decimals
  assert.equal(validateAmount('12.34', 'usd').value, 1234n)
  assert.equal(validateAmount('1.234', 'usd').ok, false)
  assert.equal(validateCopies('3').value, 3); assert.equal(validateCopies('0').ok, false); assert.equal(validateCopies('1.5').ok, false)
})
test('USD ↔ native: native = USD / price, rounded up to the base unit', () => {
  // $25.00 at $3,000/ETH = 0.008333… ETH → 8333333333333334 wei (ceil)
  assert.equal(usdToBase(2500n, 3000, 18), 8333333333333334n)
  // $10.00 at $150/SOL = 0.0666… SOL → 66666667 lamports
  assert.equal(usdToBase(1000n, 150, 9), 66666667n)
  // the other way, rounded up to the cent
  assert.equal(baseToCents(8333333333333334n, 3000, 18), 2501n)          // 25.000000000000002 → 25.01 (ceil)
  assert.equal(baseToCents(10n ** 18n, 2492.8498171598235, 18), 249285n)
  assert.equal(centsToString(249285n), '2492.85')
  assert.throws(() => usdToBase(100n, 0, 18)); assert.throws(() => usdToBase(100n, NaN, 18))
})
test('N from amount, amount for N, leftover (SOL keeps the rent-exempt minimum)', () => {
  const rent = 890880n, fee = 5000n, perCopy = 2n * fee            // 2 parts per copy
  assert.equal(copiesFromAmount(rent + 3n * perCopy + 9999n, perCopy, rent), 3n)
  assert.equal(copiesFromAmount(rent + perCopy - 1n, perCopy, rent), 0n)  // "amount covers 0 copies"
  assert.equal(copiesFromAmount(100n, perCopy, rent), 0n)
  assert.equal(amountForCopies(3, perCopy, rent), rent + 30000n)
  assert.equal(leftover(rent + 3n * perCopy + 9999n, 3, perCopy, rent), 9999n)
  assert.equal(copiesFromAmount(10n ** 16n, 3n * 10n ** 15n), 3n)     // ETH: no reserve
})

test('ETH gas: max(21000+40n, 12000+64n), no ×1.2; estimate must lie within ⌈g·15/985⌉ of one formula', () => {
  assert.equal(ethGasFormula(6), 21240n)                   // pre-fork formula wins below n = 375
  assert.equal(ethGasFormula(375), 36000n); assert.equal(21000n + 40n * 375n, 12000n + 64n * 375n)
  assert.equal(ethGasFormula(1548), 12000n + 64n * 1548n)  // post-fork formula wins above
  assert.equal(ethGasFormula(98304), 6303456n)             // research: 6,303,456 at the per-tx cap (pre-fork 3,953,160)
  // measured on anvil (Bpo1): eth_estimateGas = 21000 + 40·n exactly → accepted, gasLimit = formula
  for (const n of [6, 106, 1006, 10006, 98304]) assert.equal(ethCheckEstimate(21000n + 40n * BigInt(n), n).ok, true)
  // measured on mainnet via Tor (publicnode = drpc): +0.78 … +1.35 % (geth estimate error ratio 0.015) → accepted
  for (const [n, e] of [[6, 21406n], [106, 25581n], [1006, 62066n], [10006, 425750n]]) { const c = ethCheckEstimate(e, n); assert.equal(c.ok, true, `${n}`); assert.match(c.rule, /21000\+40n .*\+\d+/) }
  assert.equal(ethGasLimit(106, 25581n), 25581n)           // gasLimit = max(formulas, estimate)
  assert.equal(ethGasLimit(106, 0n), 25240n)
  assert.equal(ethCheckEstimate(12000n + 64n * 1006n, 1006).ok, true)
  assert.equal(ethCheckEstimate(25239n, 106).ok, false)    // below the formula → fail closed
  assert.equal(ethCheckEstimate(25240n + 385n, 106).ok, true); assert.equal(ethCheckEstimate(25240n + 386n, 106).ok, false)   // ⌈g·15/985⌉ = 385
  assert.equal(ethGasBudget(106), 25240n + 385n)
  assert.equal(ethMaxFee(10n ** 9n, 2n * 10n ** 9n), 4n * 10n ** 9n)
})
test('ETH tip: median p50 of feeHistory rewards, clamped to [0.1 gwei, cap]', () => {
  const r = [['0x3b9aca00'], ['0x77359400'], ['0x1dcd6500']]                 // 1, 2, 0.5 gwei
  assert.equal(ethTipFromRewards(r, 3n * GWEI), GWEI)
  assert.equal(ethTipFromRewards([['0x1'], ['0x2']], 3n * GWEI), GWEI / 10n)   // clamp low
  assert.equal(ethTipFromRewards([['0x2540be400']], 3n * GWEI), 3n * GWEI)     // 10 gwei → cap
  assert.equal(ethTipFromRewards([], 3n * GWEI), GWEI / 10n)
})
test('ETH replacement: ⌈1.125·x⌉+1 on tip and maxFee, maxFee ≥ 2·fresh next base + tip′', () => {
  const r = replacementFees({ tip: 1000n, maxFee: 10000n }, { tip: 1n, nextBase: 1n })
  assert.equal(r.tip, 1126n); assert.equal(r.maxFee, 11251n)
  const z = replacementFees({ tip: 0n, maxFee: 7n }, { tip: 0n, nextBase: 0n })
  assert.equal(z.tip, 1n); assert.equal(z.maxFee, 9n)
  const m = replacementFees({ tip: 1000n, maxFee: 10000n }, { tip: 5000n, nextBase: 40000n })
  assert.equal(m.tip, 5000n); assert.equal(m.maxFee, 85000n)
  assert.ok(m.tip * 1000n >= 1000n * 1125n && m.maxFee * 1000n >= 10000n * 1125n)
  assert.equal(ETH.MAX_BUMPS, 6)
})
test('ETH blockspace: bytes of text one tx can carry (budget = formula + 1.5 %)', () => {
  const maxFee = 10n ** 9n                                           // 1 gwei
  const need = ethGasBudget(106) * maxFee                            // exactly 100 text bytes (+ 6 B prefix)
  assert.equal(ethTextBytesAffordable(need, maxFee), 100n)
  assert.equal(ethTextBytesAffordable(need - 1n, maxFee), 99n)
  assert.equal(ethTextBytesAffordable(ethGasBudget(1006) * maxFee, maxFee), 1000n)   // post-fork formula binds here
  assert.equal(ethTextBytesAffordable(0n, maxFee), 0n)
  assert.equal(ethTextBytesAffordable(10n ** 30n, maxFee), BigInt(ETH.TX_DATA_CAP - 6))   // capped at one tx
})
test('SOL fee math: CU limit ⌈1.1 × units⌉, priority fee, CU price p90 clamp, ×2 per re-sign, txs covered', () => {
  assert.equal(solCuLimit(373296), 410626)
  assert.equal(solCuLimit(10 ** 7), SOL.CU_MAX)
  assert.equal(solPriorityFee(420000, 1000), 420n)                    // measured: getFeeForMessage 5420 = 5000 + 420
  assert.equal(solFee(1, 420000, 1000), 5420n)
  assert.equal(solFee(1, 410626, 100000), 5000n + 41063n)
  assert.equal(solCuPriceFromRecent([]), 100000)                       // all-zero (local validator) → floor
  assert.equal(solCuPriceFromRecent([{ prioritizationFee: 0 }, { prioritizationFee: 5 }]), 100000)
  const many = Array.from({ length: 100 }, (_, i) => ({ prioritizationFee: (i + 1) * 10000 }))   // 10k … 1M
  assert.equal(solCuPriceFromRecent(many), 900000)                     // p90 of the non-zero values
  assert.equal(solCuPriceFromRecent([{ prioritizationFee: 9e6 }]), 2000000)                  // clamp high
  assert.equal(solResignPrice(100000), 200000); assert.equal(solResignPrice(5e6), 8000000)
  assert.equal(solTxsAffordable(890880n + 50000n, 5000n, 890880n), 10n)
  assert.equal(solTxsAffordable(890880n, 5000n, 890880n), 0n)
})
test('SOL parts: Memo v2 CU budget limits parts of 3/4-byte text (measured: 1,020 B of 漢/😀 exceeds 1.4M CU)', () => {
  const cjk = '漢'.repeat(300), emoji = '😀'.repeat(200)
  const pc = solParts(utf8(cjk), 1010), pe = solParts(utf8(emoji), 1010)
  for (const p of [...pc, ...pe]) { assert.ok(solCuEstimate(p.payload) <= SOL.CU_PLAN_BUDGET); assert.ok(p.payload.length <= 1010); dec.decode(p.payload) }
  assert.equal(joinChunks(pc), cjk); assert.equal(joinChunks(pe), emoji)
  assert.equal(pc.length, 4)                                   // (1.2M − 25k − 6 × 400) / 14k = 83 chars per part
  assert.equal(pc[0].chunk.length, 81 * 3)                     // R72: part 1's 87-B vt-parts/1 header costs 34,800 CU (prototype: 83 × 3 after '[1/4] ')
  assert.equal(pe.length, 4)                                   // (1.2M − 25k − 2.4k) / 22k = 53 emoji per part
  // ASCII / Latin text stays byte-limited (1,021 B), not CU-limited
  assert.equal(solParts(utf8('a'.repeat(1010)), 1010).length, 1)
  assert.equal(solParts(utf8('é'.repeat(505)), 1010).length, 1)
  assert.equal(weigh(utf8('a€😀'), solCharCu), 400 + 14000 + 22000)
})

// I6 (security review): model of geth eth/gasestimator — optimistic (used+2300)·64/63, bisection until (hi−lo)/hi < 0.015,
// return hi. A tx below `used` (the intrinsic/floor gas) fails, at/above it succeeds.
function gethEstimate(used, cap = 30_000_000) {
  let lo = used - 1, hi = cap
  const optimistic = Math.floor(((used + 2300) * 64) / 63)
  if (optimistic < hi) { if (optimistic >= used) hi = optimistic; else lo = optimistic }
  while (lo + 1 < hi) {
    if ((hi - lo) / hi < 0.015) break
    let mid = Math.floor((hi + lo) / 2); if (mid > lo * 2) mid = lo * 2
    if (mid >= used) hi = mid; else lo = mid
  }
  return hi
}
test('I6: the geth estimator model reproduces mainnet and the tolerance refuses NO payload length (pre- and post-Amsterdam)', () => {
  assert.equal(gethEstimate(25240), 25581)                       // mainnet sample: n = 106 → 25,581 (publicnode = drpc)
  for (const [n, e] of [[6, 21406], [1006, 62066], [10006, 425750]]) assert.equal(gethEstimate(21000 + 40 * n), e)   // all measured on mainnet
  let refused = 0, oldRefused = 0
  for (let n = 6; n <= ETH.TX_DATA_CAP; n++) {
    for (const f of ETH.GAS_FORMULAS) {
      const used = Number(f.base) + Number(f.perByte) * n, est = BigInt(gethEstimate(used))
      if (!ethCheckEstimate(est, n).ok) refused++
      if (f.base === 21000n && est > BigInt(used) + (BigInt(used) * 15n + 999n) / 1000n) oldRefused++
    }
  }
  assert.equal(refused, 0)
  assert.equal(oldRefused, 151)                                  // the review's count for the old ⌈g·1.5 %⌉ tolerance
  // the review's probe sizes (payload bytes incl. data:,) that the old tolerance refused
  for (const n of [25, 28, 31, 772, 780, 793, 3481, 3550, 3603]) assert.equal(ethCheckEstimate(BigInt(gethEstimate(21000 + 40 * n)), n).ok, true, `n=${n}`)
})

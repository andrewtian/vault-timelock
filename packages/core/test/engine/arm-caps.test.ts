// computeArmCaps (engine/arm-caps.js) against MQ's laneCalc (moved verbatim) with fixed fees and the local relay's price
// fixture (SOL=150, ETH=3000): the planned native strings are laneCalc's; the job budget bounds them; affordable is false
// when one full copy exceeds the balance; the caps pass E1's checkArmConfirm. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { armCapExcess, computeArmCaps, laneCalc, toArmCap, untypedCapCeiling } from '../../src/engine/arm-caps.js'
import { ECON, PLAN } from '../../src/chains/constants.js'
import { ethGasBudget, ethParts, formatUnits, parseDecimal, solCuEstimate, solCuLimit, solFee, solParts, usdToBase, utf8 } from '../../src/chains/plan.js'
import { priceStatus } from '../../src/chains/price.js'
import { layoutMaxMemo } from '../../src/chains/sol.js'
import { checkArmConfirm } from '../../src/job/index.ts'
import { sha256Hex } from '../../src/job/canonical.ts'
import type { JobDef } from '../../src/contracts/index.ts'
import { guardOf } from '../job/helpers.ts'

const NOW = 1_791_504_000_000
const PRICES = { prices: { SOL: { usd: 150, mint: 'So11' }, ETH: { usd: 3000, mint: '7vfC' } }, fetchedAt: NOW - 1_000, source: 'fixture', fixture: true }
const GWEI = 10n ** 9n
const FEES = { eth: { nextBase: GWEI, tip: GWEI / 10n, maxFee: 2n * GWEI + GWEI / 10n }, sol: { rent: 890_880n, priorityLamports: 0 } }
const text = 'A synthetic vt fixture message.\nIt has two lines.\n'
const def = (chains: Record<string, unknown>, network: JobDef['network'] = 'local'): JobDef => ({ format: 'vt-job/1', network, name: 'caps', messageSha256: sha256Hex(utf8(text)), messageBytes: utf8(text).length, chains } as unknown as JobDef)
const ethChain = (mode: unknown, extra: Record<string, unknown> = {}) => ({ mode, publishMode: 'eth.calldata.null', feeStrategy: 'economy', distinctCopies: true, keyAddress: '0x8739Eb87B3d11f221Df63454F8D229a1A4F4049C', budgetUsd: 10, maxTipGwei: 3, clawbackTo: null, ...extra })
const solChain = (mode: unknown, extra: Record<string, unknown> = {}) => ({ mode, publishMode: 'sol.memo', feeStrategy: 'passive', distinctCopies: true, keyAddress: '9xx7qC7uwTAeaSo7T5Gk9canYBosFh1pMQaDmQEa83Tb', budgetUsd: 10, maxCuPrice: 2_000_000, clawbackTo: null, ...extra })
const ps = priceStatus(PRICES, NOW)
const RULE = { amsterdam: false, toSelf: false }

// MQ's quote for one copy (quoteEth / quoteSol, local math), the costliest copy variant when distinct
function mqEthQuote(copies: number) {
  const cost = (ps: Array<{ payload: Uint8Array }>) => ps.reduce((a, p) => a + ethGasBudget(p.payload.length, RULE) * FEES.eth.maxFee, 0n)
  const sha = sha256Hex(utf8(text))
  const a = cost(ethParts(utf8(text), { sha256: sha })), b = cost(ethParts(utf8(text), { sha256: sha, copy: copies, copies }))
  return { perCopy: a > b ? a : b, reserve: 0n, fees: { maxFee: FEES.eth.maxFee } }
}

test('ETH copies: planned = MQ laneCalc spend (N × one copy), rendered exactly (I2); the R60 cap via the price; under it, not overCap', () => {
  const caps = computeArmCaps(def({ eth: ethChain({ copies: 3 }) }), text, { prices: PRICES, fees: FEES, balances: { eth: 10n ** 17n }, network: 'local', now: NOW })
  const a = mqEthQuote(3), mq = laneCalc('eth', { mode: 'copies', src: 'n', n: '3' }, a, PRICES, ps, 1, 10n ** 17n)
  assert.equal(caps.eth.planned, formatUnits(mq.spend, 18))
  assert.equal(parseDecimal(caps.eth.planned, 18), mq.spend, 'exact in base units, never rounded')
  assert.equal(mq.spend, 3n * a.perCopy)
  assert.equal(caps.eth.overCap, false)
  assert.equal(caps.eth.nativeCap, String(usdToBase(1000n, 3000, 18) - 1n), 'the $10 R60 cap (budget $10)')
  assert.equal(caps.eth.fullCopyCost, String(a.perCopy)); assert.equal(caps.eth.parts, 1)
  assert.equal(caps.eth.affordable, true); assert.equal(caps.eth.priceAt, PRICES.fetchedAt)
  assert.ok(Math.abs(caps.eth.usd - 10) < 0.011, 'usd = the cap in dollars')
})

test('drain: planned = the lane balance (MQ); above the $10 R60 cap → overCap and nativeCap = the planned spend', () => {
  const balance = 10n ** 16n                                        // 0.01 ETH = $30 at the fixture price
  const caps = computeArmCaps(def({ eth: ethChain('drain', { budgetUsd: 1000 }) }), text, { prices: PRICES, fees: FEES, balances: { eth: balance }, network: 'local', now: NOW })
  const mq = laneCalc('eth', { mode: 'drain', src: 'n', n: '1' }, mqEthQuote(9999), PRICES, ps, 1, balance)
  assert.equal(caps.eth.planned, formatUnits(mq.spend, 18)); assert.equal(mq.spend, balance)
  assert.equal(caps.eth.planned, '0.01')
  assert.equal(caps.eth.overCap, true); assert.equal(mq.overCap, true)
  assert.equal(caps.eth.nativeCap, String(balance))
  const armCaps = { eth: toArmCap(caps.eth) }
  assert.equal(guardOf(() => checkArmConfirm('mainnet', { chains: ['eth'], confirm: { typed: 'broadcast', amounts: {} }, caps: armCaps })), 'arm.amount', 'over the cap: the amount must be typed')
  assert.equal(guardOf(() => checkArmConfirm('mainnet', { chains: ['eth'], confirm: { typed: 'broadcast', amounts: { eth: caps.eth.planned } }, caps: armCaps })), null)
  assert.equal(guardOf(() => checkArmConfirm('mainnet', { chains: ['eth'], confirm: { typed: 'broadcast', amounts: { eth: caps.eth.planned } }, caps: { eth: caps.eth } })), 'arm.amount', 'the extras must be stripped (toArmCap)')
})

test('the job budget bounds the planned spend (budget $5 < balance $30): planned and nativeCap = the budget', () => {
  const caps = computeArmCaps(def({ eth: ethChain('drain', { budgetUsd: 5 }) }), text, { prices: PRICES, fees: FEES, balances: { eth: 10n ** 16n }, network: 'local', now: NOW })
  const budget = usdToBase(500n, 3000, 18) - 1n
  assert.equal(caps.eth.planned, formatUnits(budget, 18)); assert.equal(parseDecimal(caps.eth.planned, 18), budget); assert.equal(caps.eth.overCap, false); assert.equal(caps.eth.nativeCap, String(budget))
})

test('affordable is false when one full copy exceeds the balance (or the cap)', () => {
  const a = mqEthQuote(2)
  const caps = computeArmCaps(def({ eth: ethChain({ copies: 2 }) }), text, { prices: PRICES, fees: FEES, balances: { eth: a.perCopy - 1n }, network: 'local', now: NOW })
  assert.equal(caps.eth.affordable, false)
  const ok = computeArmCaps(def({ eth: ethChain({ copies: 2 }) }), text, { prices: PRICES, fees: FEES, balances: { eth: a.perCopy }, network: 'local', now: NOW })
  assert.equal(ok.eth.affordable, true)
  const tiny = computeArmCaps(def({ eth: ethChain({ copies: 2 }, { budgetUsd: 0.01 }) }), text, { prices: PRICES, fees: FEES, balances: { eth: 10n ** 18n }, network: 'local', now: NOW })
  assert.equal(tiny.eth.affordable, a.perCopy <= BigInt(tiny.eth.nativeCap), 'one copy must also fit under the cap')
})

test('SOL drain: the reserve is rent + one claw-back fee (MQ laneCalc); passive copies cost 5,000 per part', () => {
  const balance = 10n ** 8n
  const caps = computeArmCaps(def({ sol: solChain('drain', { budgetUsd: 1000 }) }), text, { prices: PRICES, fees: FEES, balances: { sol: balance }, network: 'local', now: NOW })
  const parts = solParts(utf8(text), layoutMaxMemo())
  const perCopy = parts.reduce((x, p) => x + solFee(1, solCuLimit(solCuEstimate(p.payload)), 0), 0n)
  assert.equal(caps.sol.fullCopyCost, String(perCopy)); assert.equal(perCopy, 5000n * BigInt(parts.length))
  const mq = laneCalc('sol', { mode: 'drain', src: 'n', n: '1' }, { perCopy, reserve: 890_880n, fee: 5000n }, PRICES, ps, parts.length, balance)
  assert.equal(mq.reserve, 890_880n + ECON.SOL_CLAW_RESERVE)
  assert.equal(caps.sol.planned, formatUnits(mq.spend, 9)); assert.equal(caps.sol.planned, '0.1'); assert.equal(caps.sol.overCap, true, '$15 > the $10 R60 cap')
  assert.equal(caps.sol.affordable, true)
  const poor = computeArmCaps(def({ sol: solChain('drain', { budgetUsd: 1000 }) }), text, { prices: PRICES, fees: FEES, balances: { sol: 890_880n + ECON.SOL_CLAW_RESERVE + perCopy - 1n }, network: 'local', now: NOW })
  assert.equal(poor.sol.affordable, false)
})

test('no price (testnet: no Jupiter; or stale): the R60 native fallback, usd 0, priceAt null', () => {
  for (const prices of [null, { ...PRICES, fetchedAt: NOW - 10 * 60_000 }]) {
    const caps = computeArmCaps(def({ eth: ethChain({ copies: 1 }), sol: solChain({ copies: 1 }) }, 'testnet'), text, { prices, fees: FEES, balances: { eth: 10n ** 18n, sol: 10n ** 9n }, network: 'testnet', now: NOW })
    assert.equal(caps.eth.nativeCap, String(PLAN.SPEND_CAP_NATIVE.eth)); assert.equal(caps.sol.nativeCap, String(PLAN.SPEND_CAP_NATIVE.sol))
    assert.equal(caps.eth.usd, 0); assert.equal(caps.eth.priceAt, null)
  }
})

test('testnet ETH is Amsterdam: the exact 15000 + 64·n gas to the null address prices the copy', () => {
  const caps = computeArmCaps(def({ eth: ethChain({ copies: 1 }) }, 'testnet'), text, { prices: PRICES, fees: FEES, balances: { eth: 10n ** 18n }, network: 'testnet', now: NOW })
  const n = ethParts(utf8(text))[0].payload.length
  assert.equal(caps.eth.fullCopyCost, String(ethGasBudget(n, { amsterdam: true, toSelf: false }) * FEES.eth.maxFee))
  const self = computeArmCaps(def({ eth: ethChain({ copies: 1 }, { publishMode: 'eth.calldata.self' }) }, 'testnet'), text, { prices: PRICES, fees: FEES, balances: { eth: 10n ** 18n }, network: 'testnet', now: NOW })
  assert.equal(self.eth.fullCopyCost, String(ethGasBudget(n, { amsterdam: true, toSelf: true }) * FEES.eth.maxFee))
})

test('every cap has the ArmCap shape E1 checks (checkArmConfirm passes on local)', () => {
  const caps = computeArmCaps(def({ eth: ethChain({ copies: 2 }), sol: solChain('drain') }), text, { prices: PRICES, fees: FEES, balances: { eth: 10n ** 17n, sol: 10n ** 8n }, network: 'local', now: NOW })
  const armCaps = Object.fromEntries(Object.entries(caps).map(([c, v]) => [c, toArmCap(v)]))
  assert.equal(guardOf(() => checkArmConfirm('local', { chains: ['eth', 'sol'], confirm: { typed: null, amounts: {} }, caps: armCaps })), null)
})

// ---- PF-S M-4 (pre-flip review): the price-free ceiling the API re-applies, and the plan never exceeds it

const priced = (eth: number, sol: number) => ({ ...PRICES, prices: { SOL: { usd: sol, mint: 'So11' }, ETH: { usd: eth, mint: '7vfC' } } })

test('M-4: untypedCapCeiling is the R60 native fallback for eth and sol off local; none on local or for btc', () => {
  for (const n of ['mainnet', 'testnet']) {
    assert.equal(untypedCapCeiling(n, 'eth'), PLAN.SPEND_CAP_NATIVE.eth, n); assert.equal(untypedCapCeiling(n, 'sol'), PLAN.SPEND_CAP_NATIVE.sol, n)
    assert.equal(untypedCapCeiling(n, 'btc'), null, n)
  }
  for (const c of ['eth', 'sol', 'btc']) assert.equal(untypedCapCeiling('local', c), null, c)
})

test('M-4: on mainnet a $10 cap worth more than the native fallback (ETH at $2,000) is typed above it; at $3,000 nothing changes; local keeps the $10 cap', () => {
  const low = priced(2000, 100)                                        // $10 = 0.005 ETH > 0.004; 0.1 SOL > 0.07
  const a = mqEthQuote(1)
  // a plan under the ceiling: untyped, capped AT the ceiling (not at $10)
  const under = computeArmCaps(def({ eth: ethChain({ copies: 1 }) }, 'mainnet'), text, { prices: low, fees: FEES, balances: { eth: 10n ** 17n }, network: 'mainnet', now: NOW })
  assert.ok(a.perCopy <= PLAN.SPEND_CAP_NATIVE.eth)
  assert.deepEqual([under.eth.overCap, under.eth.nativeCap], [false, String(PLAN.SPEND_CAP_NATIVE.eth)])
  // a drain plan between the ceiling and $10: typed, nativeCap = the planned spend
  const balance = 45n * 10n ** 14n                                      // 0.0045 ETH = $9 at $2,000
  const mid = computeArmCaps(def({ eth: ethChain('drain') }, 'mainnet'), text, { prices: low, fees: FEES, balances: { eth: balance }, network: 'mainnet', now: NOW })
  assert.deepEqual([mid.eth.overCap, mid.eth.nativeCap, mid.eth.planned], [true, String(balance), '0.0045'])
  const local = computeArmCaps(def({ eth: ethChain('drain') }), text, { prices: low, fees: FEES, balances: { eth: balance }, network: 'local', now: NOW })
  assert.deepEqual([local.eth.overCap, local.eth.nativeCap], [false, String(usdToBase(1000n, 2000, 18) - 1n)], 'local: the $10 cap, untyped')
  // SOL at $100 likewise
  const sol = computeArmCaps(def({ sol: solChain('drain', { budgetUsd: 1000 }) }, 'mainnet'), text, { prices: low, fees: FEES, balances: { sol: 95_000_000n }, network: 'mainnet', now: NOW })
  assert.deepEqual([sol.sol.overCap, sol.sol.planned], [true, '0.095'])
  // at the fixture price ($10 = 0.00333 ETH < 0.004) mainnet plans what local plans
  for (const mode of [{ copies: 2 }, 'drain'] as const) {
    const m = computeArmCaps(def({ eth: ethChain(mode) }, 'mainnet'), text, { prices: PRICES, fees: FEES, balances: { eth: 10n ** 16n }, network: 'mainnet', now: NOW })
    const l = computeArmCaps(def({ eth: ethChain(mode) }), text, { prices: PRICES, fees: FEES, balances: { eth: 10n ** 16n }, network: 'local', now: NOW })
    assert.deepEqual(toArmCap(m.eth), toArmCap(l.eth), JSON.stringify(mode))
  }
})

test('M-4: whatever computeArmCaps plans off local (prices, budgets, balances, modes, both chains, no price), armCapExcess accepts it', () => {
  let x = 20261011
  const r = (): number => { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; return x / 4294967296 }
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)]
  let typed = 0, untyped = 0
  for (let i = 0; i < 400; i++) {
    const network = pick(['mainnet', 'testnet'] as const)
    const prices = r() < 0.2 ? null : priced(50 + Math.floor(r() * 9950), 5 + Math.floor(r() * 995))
    const budgetUsd = pick([0.01, 1, 5, 9.99, 10, 10.01, 50, 250, 999.99, 1000])
    const mode = r() < 0.5 ? 'drain' : { copies: 1 + Math.floor(r() * 5) }
    const chains = { eth: ethChain(mode, { budgetUsd }), sol: solChain(mode, { budgetUsd }) }
    const balances = { eth: BigInt(Math.floor(r() * 1e6)) * 10n ** 11n, sol: BigInt(Math.floor(r() * 1e6)) * 10n ** 3n + 900_000n }
    const caps = computeArmCaps(def(chains, network), text, { prices, fees: FEES, balances, network, now: NOW })
    for (const c of ['eth', 'sol'] as const) {
      const cap = toArmCap(caps[c])
      assert.equal(armCapExcess(network, c, chains[c], cap), null, `${network} ${c} ${JSON.stringify({ prices: prices?.prices, budgetUsd, mode, cap })}`)
      if (cap.overCap) typed++; else untyped++
      if (!cap.overCap) assert.ok(BigInt(cap.nativeCap) <= PLAN.SPEND_CAP_NATIVE[c])
    }
  }
  assert.ok(typed >= 20 && untyped >= 20, `${typed} typed, ${untyped} untyped`)
})

test('M-4: armCapExcess refuses an untyped cap above the ceiling, a typed cap without a price, a cap worth more than the budget, a budget outside (0, 1000]; local and btc: never', () => {
  const eth = ethChain('drain', { budgetUsd: 10 }), sol = solChain('drain', { budgetUsd: 5 })
  const cap = (o: Record<string, unknown>) => ({ nativeCap: '4000000000000000', usd: 10, priceAt: NOW, overCap: false, planned: '0.004', ...o })
  const ok = (n: string, c: 'eth' | 'sol', ch: unknown, k: Record<string, unknown>) => assert.equal(armCapExcess(n, c, ch, cap(k)), null, `${n} ${c} ${JSON.stringify(k)}`)
  const no = (n: string, c: 'eth' | 'sol', ch: unknown, k: Record<string, unknown>, why: RegExp) => assert.match(armCapExcess(n, c, ch, cap(k)) ?? 'null', why, `${n} ${c} ${JSON.stringify(k)}`)
  for (const n of ['mainnet', 'testnet']) {
    ok(n, 'eth', eth, {})                                                                       // exactly at the ceiling, $10 of a $10 budget
    no(n, 'eth', eth, { nativeCap: '4000000000000001' }, /untyped cap .* above 4000000000000000/)
    ok(n, 'sol', sol, { nativeCap: '70000000', usd: 5 })
    no(n, 'sol', sol, { nativeCap: '70000001', usd: 5 }, /untyped cap .* above 70000000/)
    ok(n, 'eth', eth, { nativeCap: '9000000000000000', usd: 9, overCap: true, planned: '0.009' }) // typed above the ceiling, within the budget
    no(n, 'eth', eth, { nativeCap: '9000000000000000', usd: 0, priceAt: null, overCap: true, planned: '0.009' }, /typed .* needs a price/)
    no(n, 'eth', eth, { usd: 10.01 }, /worth \$10\.01, more than the job's budget \(\$10\)/)
    no(n, 'eth', eth, { nativeCap: '9000000000000000', usd: 18, overCap: true, planned: '0.009' }, /more than the job's budget/)
    ok(n, 'eth', eth, { usd: 0, priceAt: null })
    no(n, 'eth', eth, { usd: 3, priceAt: null }, /unpriced cap is worth \$0/)
    for (const budgetUsd of [0, -1, 1000.01, Number.NaN, Number.POSITIVE_INFINITY, '10', null]) no(n, 'eth', { ...eth, budgetUsd }, {}, /budgetUsd is not a number in \(0, 1000\]/)
    ok(n, 'eth', { ...eth, budgetUsd: 1000 }, {})
    no(n, 'eth', eth, { nativeCap: 'x' }, /not a decimal amount/)
  }
  for (const c of ['eth', 'sol'] as const) assert.equal(armCapExcess('local', c, { budgetUsd: 1 }, cap({ nativeCap: String(10n ** 20n), usd: 1e6, overCap: false })), null)
  assert.equal(armCapExcess('mainnet', 'btc', { budgetUsd: 1 }, cap({ nativeCap: String(10n ** 20n) })), null)
})

// Privacy Cash funding: the numbers and pure rules (src/privacycash/limits.js). Synthetic values only.
import { test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import {
  CONFIG_MAX, FEE_BASE_LAMPORTS, FEE_MARGIN_PER_10K, FEE_RATE_PER_10K, LANE_HEADER, LINKAGE_WARNING, MIN_NET_LAMPORTS, ROUTES, checkConfig, checkCovered, feeCeiling, parseSol, sdkFee, sol, solveGross,
} from '../src/privacycash/limits.js'

const CFG = { rate: 0.0035, rent: 0.006, minimum: 0.01 }       // the published schedule: 0.35 % + 0.006 SOL
const cfg = checkConfig(CFG)

test('the fee clamp is the relay\'s (api/src/privacycash.ts), constant for constant', () => {
  const src = readFileSync(resolve(process.cwd(), '../api/src/privacycash.ts'), 'utf8')
  expect(/FEE_BASE_LAMPORTS = (\d[\d_]*)n/.exec(src)[1].replaceAll('_', '')).toBe(String(FEE_BASE_LAMPORTS))
  expect(/FEE_RATE_PER_10K = (\d+)n/.exec(src)[1]).toBe(String(FEE_RATE_PER_10K))
  expect(/FEE_MARGIN_PER_10K = (\d+)n/.exec(src)[1]).toBe(String(FEE_MARGIN_PER_10K))
  expect(/LANE_HEADER = '([^']+)'/.exec(src)[1]).toBe(LANE_HEADER)
  expect(feeCeiling(1_000_000_000)).toBe(Number((6_000_000n * 10_000n + 40n * 1_000_000_000n) / 9_960n + 1n))
  expect(feeCeiling(10_000_000)).toBeGreaterThanOrEqual(6_056_196)                              // the published schedule at the 0.01 SOL minimum (W6 concern 1)
})

test('the route table is the relay\'s (S7): every kind the relay serves, nothing else', () => {
  const src = readFileSync(resolve(process.cwd(), '../api/src/privacycash.ts'), 'utf8')
  const kinds = /export type PcKind = ([^\n]+)/.exec(src)[1].match(/'([a-z]+)'/g).map((s) => s.slice(1, -1)).sort()
  expect(ROUTES.map((r) => r.kind).sort()).toEqual(kinds)
  const ok = (m, p) => ROUTES.some((r) => r.method === m && r.re.test(p))
  expect(ok('GET', '/relay/privacycash/relayer/config')).toBe(true)
  expect(ok('POST', '/relay/privacycash/relayer/withdraw')).toBe(true)
  expect(ok('POST', '/relay/privacycash/rpc')).toBe(true)
  expect(ok('GET', '/relay/privacycash/artifacts/transaction2.zkey')).toBe(true)
  for (const p of ['/relay/privacycash/relayer/deposit', '/relay/privacycash/relayer/withdraw/spl', '/relay/privacycash/relayer/merkle/root', '/relay/privacycash/relayer/config/',
    '/relay/privacycash/relayer/../config', '/relay/privacycash/relayer/utxos/check/zz', '/relay/privacycash/artifacts/other.wasm', '/relay/eth']) expect(ROUTES.some((r) => r.re.test(p))).toBe(false)
  expect(ok('GET', '/relay/privacycash/relayer/withdraw')).toBe(false)
})

test('checkConfig: the relayer\'s /config is bounded, and any other shape is refused', () => {
  expect(cfg).toEqual({ rate: 0.0035, rent: 0.006, minimumLamports: 10_000_000 })
  expect(() => checkConfig({ ...CFG, rate: CONFIG_MAX.rate + 0.0001 })).toThrow(/withdraw_fee_rate/)
  expect(() => checkConfig({ ...CFG, rent: 0.011 })).toThrow(/withdraw_rent_fee/)
  expect(() => checkConfig({ ...CFG, minimum: 0.06 })).toThrow(/minimum withdrawal/)
  for (const bad of [undefined, null, '0.0035', NaN, Infinity, -1]) {
    expect(() => checkConfig({ ...CFG, rate: bad })).toThrow(/pc\.config/)
    expect(() => checkConfig({ ...CFG, minimum: bad })).toThrow(/pc\.config/)
  }
})

test('solveGross: the smallest gross whose NET (gross - the SDK\'s own fee) covers the wanted amount', () => {
  for (const net of [20_000_000, 20_000_001, 33_333_333, 99_999_999, 1_000_000_000, 5_000_000_000]) {
    const q = solveGross(net, cfg)
    expect(q.net).toBeGreaterThanOrEqual(net)
    expect(q.net).toBe(q.gross - sdkFee(q.gross, cfg.rate, cfg.rent))
    expect(q.net - net).toBeLessThanOrEqual(1)                                    // minimal: at most one lamport of slack
    expect(q.gross - 1 - sdkFee(q.gross - 1, cfg.rate, cfg.rent)).toBeLessThan(net)   // one lamport less would not cover it
    expect(q.fee).toBeLessThanOrEqual(feeCeiling(q.net))
  }
})

test('solveGross: amounts and fees outside the rules are refused', () => {
  for (const bad of [0, -5, 1.5, NaN, '10000000', 9_999_999, 1e21]) expect(() => solveGross(bad, cfg)).toThrow(/pc\.amount/)
  expect(() => solveGross(MIN_NET_LAMPORTS, checkConfig({ rate: 0.005, rent: 0.01, minimum: 0.05 }))).toThrow(/minimum/)    // the relayer's own (higher) minimum
  // The S7 clamp on the GROSS (Sfix-PC item 3) passes the published schedule from the 0.01 SOL minimum up (the W6 concern: a clamp on the net refused it).
  for (const net of [10_000_000, 13_000_000, 14_500_000]) expect(solveGross(net, cfg).net).toBeGreaterThanOrEqual(net)
  // a fee above the clamp can also come from a cap-edge config: rent 0.01 SOL (cap) is above 0.006 SOL + 0.5 %, at a small amount
  expect(() => solveGross(20_000_000, checkConfig({ rate: 0.005, rent: 0.01, minimum: 0.01 }))).toThrow(/pc\.fee/)
})

test('checkCovered refuses the silent partial withdrawal (only the two largest notes are spent)', () => {
  expect(checkCovered(100, [60, 50, 5])).toBe(110)
  expect(checkCovered(110, [60, 50, 5])).toBe(110)
  expect(() => checkCovered(111, [60, 50, 5])).toThrow(/pc\.partial/)
  expect(() => checkCovered(1, [])).toThrow(/pc\.partial/)
  expect(() => checkCovered(100, [40, 40, 40, 40])).toThrow(/pc\.partial/)       // many small notes do not add up: the SDK uses two
})

test('parseSol and sol: whole lamports only', () => {
  expect(parseSol('0.01')).toBe(10_000_000)
  expect(parseSol(' 1 ')).toBe(1_000_000_000)
  expect(parseSol('1.123456789')).toBe(1_123_456_789)
  for (const bad of ['', '0', '0.0', '1.1234567891', '-1', '1e3', '0x10', '1,5', 'abc', '1.', '.5', '9999999999']) expect(parseSol(bad)).toBeNull()
  expect(sol(10_000_000)).toBe('0.01 SOL')
  expect(sol(1_000_000_000)).toBe('1.0 SOL')
})

test('the linkage warning names what is sent and says Tor does not hide it', () => {
  expect(LINKAGE_WARNING).toMatch(/\/utxos\/indices/)
  expect(LINKAGE_WARNING).toMatch(/\/merkle\/proofv2/)
  expect(LINKAGE_WARNING).toMatch(/\/withdraw/)
  expect(LINKAGE_WARNING).toMatch(/Tor hides your IP, not this link/)
})

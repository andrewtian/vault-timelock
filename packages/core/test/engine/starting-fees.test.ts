// engine/assess.js startingFees — the arm-time starting fees and the per-copy worst case (lane E follow-up; one source
// for assess.js, `vt job arm` and the page). Pinned per chain and strategy, pre- and post-Amsterdam. ALL DATA IS
// SYNTHETIC: a hand-made fee history (base 1 gwei, the next block 1.25 gwei, every reward `reward`) behind the fake relay.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { assessChain, startingFees } from '../../src/engine/assess.js'
import { ethParts, solParts, utf8 } from '../../src/chains/plan.js'
import { CANON } from '../../src/chains/constants.js'
import { fakeRelay } from './fakes.ts'

const GWEI = 10n ** 9n
const hx = (n: bigint | number): string => `0x${BigInt(n).toString(16)}`
const relayWith = (reward: bigint) => fakeRelay({
  eth: (m, p) => {
    if (m === 'eth_getBalance') return hx(10n ** 18n)
    if (m !== 'eth_feeHistory') return undefined
    const n = Math.min(Number(BigInt(p[0])), 101)
    return { oldestBlock: hx(101 - n), baseFeePerGas: Array.from({ length: n + 1 }, (_, k) => hx(k === n ? 5n * GWEI / 4n : GWEI)), reward: Array.from({ length: n }, () => (p[2] as unknown[]).map(() => hx(reward))) }
  },
  sol: (m) => (m === 'getMinimumBalanceForRentExemption' ? 890_880 : m === 'getBalance' ? { value: 10 ** 9 } : undefined),
})

const hello = ethParts(utf8('hello'))
const pre = { amsterdam: false, toSelf: false }
const toOther = { amsterdam: true, toSelf: false }
const toSelf = { amsterdam: true, toSelf: true }
const NEXT = 5n * GWEI / 4n

test('startingFees eth passive: next base, tip PASSIVE_ETH_TIP, maxFee = the 24 h base-fee target + that tip', async () => {
  relayWith(2n * GWEI)
  const r = await startingFees('mainnet', 'eth', 'passive')
  assert.deepEqual(r, { chain: 'eth', fees: { nextBase: NEXT, tip: 1_000_000n, maxFee: 1_001_000_000n, target: GWEI, windowBlocks: 101, truncated: false }, perCopy: null })
  assert.equal(r.fees.tip, CANON.PASSIVE_ETH_TIP)
})

test('startingFees eth economy: next base + the network tip floor or the median p10 reward', async () => {
  relayWith(100n)   // below both floors
  const main = await startingFees('mainnet', 'eth', 'economy')
  assert.deepEqual([main.fees.nextBase, main.fees.tip, main.fees.maxFee], [NEXT, 12_000n, 2n * NEXT + 12_000n])
  const local = await startingFees('local', 'eth', 'economy')
  assert.equal(local.fees.tip, 12_000n)
  const sepolia = await startingFees('testnet', 'eth', 'economy')
  assert.equal(sepolia.fees.tip, 1_000_000n, 'Sepolia floor 0.001 gwei')
  relayWith(2n * GWEI)
  const busy = await startingFees('mainnet', 'eth', 'economy')
  assert.deepEqual([busy.fees.tip, busy.fees.maxFee], [2n * GWEI, 2n * NEXT + 2n * GWEI])
})

test('startingFees eth prompt: the p50 tip at the 3 gwei default cap (or the given cap); no strategy falls through to prompt', async () => {
  relayWith(2n * GWEI)
  const r = await startingFees('mainnet', 'eth', 'prompt')
  assert.deepEqual(r.fees, { nextBase: NEXT, tip: 2n * GWEI, maxFee: 4_500_000_000n, tipCap: 3n * GWEI })
  assert.deepEqual((await startingFees('mainnet', 'eth', undefined)).fees, r.fees)
  const capped = await startingFees('mainnet', 'eth', 'prompt', { tipCap: GWEI })
  assert.deepEqual([capped.fees.tip, capped.fees.maxFee], [GWEI, 2n * NEXT + GWEI])
})

test('startingFees eth perCopy: gas budget × maxFee per part, summed; pre- and post-Amsterdam; null without parts or a gas rule', async () => {
  relayWith(2n * GWEI)
  const gas = { pre: 21_767n, toOther: 15_944n, toSelf: 12_898n }   // budget (formula + estimate tolerance) of the one 5-byte part
  for (const [name, rule] of [['pre', pre], ['toOther', toOther], ['toSelf', toSelf]] as const) {
    const r = await startingFees('mainnet', 'eth', 'prompt', { parts: hello, gasRule: rule })
    assert.equal(r.perCopy, gas[name] * 4_500_000_000n, name)
    const p = await startingFees('mainnet', 'eth', 'passive', { parts: hello, gasRule: rule })
    assert.equal(p.perCopy, gas[name] * 1_001_000_000n, `${name} passive`)
  }
  assert.equal((await startingFees('mainnet', 'eth', 'prompt', { parts: hello })).perCopy, null, 'no gas rule: fail closed to null')
  assert.equal((await startingFees('mainnet', 'eth', 'prompt', { gasRule: pre })).perCopy, null)
  // several parts add up; the costlier of parts / altParts wins
  const long = ethParts(utf8('x'.repeat(200_000)))
  assert.ok(long.length > 1)
  const one = await startingFees('mainnet', 'eth', 'prompt', { parts: hello, gasRule: pre })
  const both = await startingFees('mainnet', 'eth', 'prompt', { parts: hello, altParts: long, gasRule: pre })
  const longOnly = await startingFees('mainnet', 'eth', 'prompt', { parts: long, gasRule: pre })
  assert.equal(both.perCopy, longOnly.perCopy)
  assert.ok(longOnly.perCopy! > one.perCopy!)
  assert.equal((await startingFees('mainnet', 'eth', 'prompt', { parts: long, altParts: hello, gasRule: pre })).perCopy, longOnly.perCopy, 'a cheaper alt does not replace')
})

test('startingFees sol: rent + priority (prompt SOL_PROMPT_LAMPORTS, else 0, or the given); perCopy = 5000 + priority per tx', async () => {
  relayWith(2n * GWEI)
  const one = solParts(utf8('hello'), 566), six = solParts(utf8('x'.repeat(3000)), 566)
  assert.equal(one.length, 1); assert.equal(six.length, 6)
  for (const s of ['passive', 'economy'] as const) {
    assert.deepEqual(await startingFees('mainnet', 'sol', s, { parts: one }), { chain: 'sol', fees: { rent: 890_880n, priorityLamports: 0 }, perCopy: 5_000n })
    assert.equal((await startingFees('mainnet', 'sol', s, { parts: six })).perCopy, 30_000n)
  }
  assert.equal(CANON.SOL_PROMPT_LAMPORTS, 12_500)
  assert.deepEqual(await startingFees('mainnet', 'sol', 'prompt', { parts: one }), { chain: 'sol', fees: { rent: 890_880n, priorityLamports: 12_500 }, perCopy: 17_501n })
  assert.equal((await startingFees('mainnet', 'sol', 'prompt', { parts: six })).perCopy, 105_006n)
  assert.deepEqual(await startingFees('mainnet', 'sol', 'prompt', { priorityLamports: 777, cuPriceCap: 5, parts: one }), { chain: 'sol', fees: { rent: 890_880n, priorityLamports: 777 }, perCopy: 5_001n })
  assert.equal((await startingFees('mainnet', 'sol', 'prompt')).perCopy, null)
})

test('assess.js quotes with the same fees and per-copy figure (no behaviour change)', async () => {
  relayWith(2n * GWEI)
  const address = '0x00000000000000000000000000000000000000aa'
  for (const [strategy, rule] of [['passive', pre], ['economy', toOther], ['prompt', toSelf]] as const) {
    const sf = await startingFees('mainnet', 'eth', strategy, { parts: hello, gasRule: rule })
    const q = await assessChain('eth', hello, { real: false, network: 'mainnet', address, gasRule: rule, strategy, msSha: 'a', cfgKey: 'k' })
    assert.equal(q.ok, true, String(q.reason))
    assert.equal((q as unknown as { perCopy: bigint }).perCopy, sf.perCopy, strategy)
    assert.deepEqual((q as unknown as { fees: unknown }).fees, sf.fees, strategy)
  }
  const one = solParts(utf8('hello'), 566)
  const q = await assessChain('sol', one, { real: false, network: 'mainnet', address: '11111111111111111111111111111111', priorityLamports: 12_500, strategy: 'prompt', msSha: 'a', cfgKey: 'k' })
  assert.equal((q as unknown as { perCopy: bigint }).perCopy, (await startingFees('mainnet', 'sol', 'prompt', { parts: one })).perCopy)
})

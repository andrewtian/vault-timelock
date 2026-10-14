// The publication-modes rehearsal carry-forwards in the engine (publication-modes-elite.md, "PM"): fork- and
// recipient-aware gas (exact formulas, estimate check, drift named), the Passive ETH strategy (target, tip, wait, no
// escalation), destination-aware claw-back gas checked against eth_estimateGas (fail closed), SOL priority in lamports
// per tx. ALL DATA IS SYNTHETIC; the relay is a fake fetch.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { CANON, ECON } from '../../src/chains/constants.js'
import { ethCheckEstimate, ethGasBudget, ethGasFormula } from '../../src/chains/plan.js'
import { ethClawback, ethClawGas, ethPassiveBump, ethPassiveDecision, ethPassiveInitial, ethPassiveTarget } from '../../src/chains/economy.js'
import { solPriceForLamports } from '../../src/chains/sol.js'
import { _gasRuleOf, clawbackEth, ethAdapter, newLaneState, validateLaneConfig } from '../../src/engine/lane.js'
import { armedLedger, armedState, fakeEthChain, fakeRelay, recordingJournal } from './fakes.ts'

const PRE = { amsterdam: false, toSelf: false }, NULL_AMS = { amsterdam: true, toSelf: false }, SELF_AMS = { amsterdam: true, toSelf: true }

test('PM constants: Passive tip 0.001 gwei, 24 h window (7,200 blocks, refresh 300), empty-destination claw-back 204,600 gas', () => {
  assert.equal(CANON.PASSIVE_ETH_TIP, 1_000_000n)
  assert.equal(CANON.PASSIVE_ETH_WINDOW_BLOCKS, 7200); assert.equal(CANON.PASSIVE_ETH_REFRESH_BLOCKS, 300); assert.equal(CANON.PASSIVE_ETH_TARGET_PCT, 10)
  assert.equal(CANON.ETH_CLAW_GAS_EMPTY_AMSTERDAM, 204_600n); assert.equal(CANON.ETH_CLAW_GAS_EXISTING, 21_000n)
  assert.deepEqual(CANON.SOL_RUNG_LAMPORTS, [0, 160, 1400, 12500])
})

test('gas is fork- and recipient-aware and exact (PM §3.1 table: n = 6, 249, 250, 251, 2,889, 2,890, 98,304)', () => {
  const table: Array<[number, number, number, number]> = [[6, 15384, 12384, 21240], [249, 30936, 27936, 30960], [250, 31000, 28000, 31000], [251, 31064, 28064, 31040],
    [1006, 79384, 76384, 61240], [2889, 199896, 196896, 136560], [2890, 199960, 196960, 136600], [98304, 6306456, 6303456, 3953160]]
  for (const [n, toNull, toSelf, pre] of table) {
    assert.equal(ethGasFormula(n, NULL_AMS), BigInt(toNull), `null ${n}`)
    assert.equal(ethGasFormula(n, SELF_AMS), BigInt(toSelf), `self ${n}`)
    assert.equal(ethGasFormula(n, PRE), BigInt(pre), `pre ${n}`)
    assert.equal(ethGasFormula(n, { amsterdam: false, toSelf: true }), BigInt(pre), 'pre-Amsterdam: the recipient does not matter')
  }
})

test('the estimate check uses the exact formula: Sepolia to 0x0 passes; the prototype max() check refused it (fail closed)', () => {
  const n = 1030, est = 15000n + 64n * BigInt(n)                      // Sepolia, to the null address
  assert.equal(ethCheckEstimate(est, n, NULL_AMS).ok, true)
  assert.equal(ethCheckEstimate(est, n).ok, false, 'the MQ max(21000+40n, 12000+64n) window misses 15000+64n at this size')
  const drift = ethCheckEstimate(21000n + 40n * BigInt(n), n, NULL_AMS)
  assert.equal(drift.ok, false); assert.match(String(drift.why), /Amsterdam appears inactive.*update required.*fail closed/)
  const drift2 = ethCheckEstimate(15000n + 64n * BigInt(n), n, PRE)
  assert.match(String(drift2.why), /Amsterdam appears active/)
  assert.equal(ethCheckEstimate(est - 1n, n, NULL_AMS).ok, false, 'below the formula')
  const g = 15000n + 64n * BigInt(n), tol = (g * 15n + 984n) / 985n
  assert.equal(ethCheckEstimate(g + tol, n, NULL_AMS).ok, true); assert.equal(ethCheckEstimate(g + tol + 1n, n, NULL_AMS).ok, false)
  assert.equal(ethGasBudget(n, NULL_AMS), g + tol)
})

test('the adapters take the fork from the injected network (no location, no URL): local pre, testnet Amsterdam, mainnet pre', () => {
  assert.deepEqual(_gasRuleOf({ recipient: 'null' }, { network: 'local' }), PRE)
  assert.deepEqual(_gasRuleOf({ recipient: 'self' }, { network: 'testnet' }), SELF_AMS)
  assert.deepEqual(_gasRuleOf({ recipient: 'null' }, { network: 'mainnet' }), PRE)
  assert.deepEqual(_gasRuleOf({ recipient: 'null' }, { network: 'local', amsterdamOverride: true }), NULL_AMS)
  assert.throws(() => _gasRuleOf({ recipient: 'null' }, { network: 'mainnet', amsterdamOverride: true }), /local network only/)
  assert.throws(() => _gasRuleOf({ recipient: 'null' }, {}), /network/)
})

test('Passive ETH: T = p10 of the window; sign only at next base ≤ T with maxFee = T + tip; a stall never escalates', () => {
  const bases = Array.from({ length: 100 }, (_, i) => BigInt(i + 1) * 1_000_000n)
  assert.equal(ethPassiveTarget(bases), 10_000_000n)
  assert.throws(() => ethPassiveTarget([]), /fail closed/)
  assert.match(String(ethPassiveInitial({ nextBase: 10_000_001n, target: 10_000_000n }).wait), /waiting for a cheap block/)
  assert.deepEqual(ethPassiveInitial({ nextBase: 10_000_000n, target: 10_000_000n }), { tip: 1_000_000n, maxFee: 11_000_000n })
  assert.match(ethPassiveBump().wait, /no escalation/)
  const cost = ethGasBudget(106, PRE) * 11_000_000n
  assert.deepEqual(ethPassiveDecision(cost, [106], 10_000_000n, 1_000_000n, PRE), { send: true, tight: false, cost })
  assert.equal(ethPassiveDecision(cost - 1n, [106], 10_000_000n, 1_000_000n, PRE).send, false)
})

test('claw-back gas by destination class; the value keeps exactly gas × maxFee back', () => {
  assert.equal(ethClawGas({ amsterdam: false, empty: true }), 21_000n)
  assert.equal(ethClawGas({ amsterdam: true, empty: false }), 21_000n)
  assert.equal(ethClawGas({ amsterdam: true, empty: true }), 204_600n)
  const c = ethClawback(10n ** 15n, 300n, 12_000n, 204_600n)
  assert.equal(c.value, 10n ** 15n - 204_600n * 12_600n)
  assert.equal(ethClawback(10n ** 15n, 300n, 12_000n).value, 10n ** 15n - ECON.ETH_CLAW_GAS * 12_600n, 'the MQ default stays 21,000')
})

test('SOL priority in lamports per tx: price = ⌈L·10⁶ / CU limit⌉, capped; 0 means no SetComputeUnitPrice', () => {
  assert.equal(solPriceForLamports(0, 393_000, 2_000_000), 0)
  assert.equal(solPriceForLamports(160, 393_000, 2_000_000), 408)          // ⌈160e6 / 393000⌉
  assert.equal(solPriceForLamports(12_500, 393_000, 2_000_000), 31_807)
  assert.equal(solPriceForLamports(12_500, 1_000, 2_000_000), 2_000_000, 'capped by maxCuPrice')
  assert.throws(() => solPriceForLamports(1.5, 1000, 1), /fail closed/)
})

// A claw-back on Sepolia (Amsterdam) to an EMPTY destination: 204,600 gas, cross-checked with eth_estimateGas.
function clawChain(o: { destEmpty: boolean; estimate: bigint; code?: string }) {
  const hx = (n: bigint | number): string => `0x${BigInt(n).toString(16)}`
  const sent: string[] = []
  return {
    sent,
    handler: (m: string, p: any[]): unknown => {
      const who = String(p[0]?.to ?? p[0] ?? '').toLowerCase()
      switch (m) {
        case 'eth_getTransactionCount': return who === DEST.toLowerCase() && o.destEmpty ? '0x0' : hx(sent.length)
        case 'eth_getBalance': return who === DEST.toLowerCase() ? (o.destEmpty ? '0x0' : hx(5n)) : hx(10n ** 16n)
        case 'eth_getCode': return o.code ?? '0x'
        case 'eth_feeHistory': return { oldestBlock: '0x1', baseFeePerGas: Array.from({ length: Number(BigInt(p[0])) + 1 }, () => hx(10n ** 9n)), reward: Array.from({ length: Number(BigInt(p[0])) }, () => [hx(10n ** 9n)]) }
        case 'eth_estimateGas': return hx(o.estimate)
        case 'eth_sendRawTransaction': sent.push(String(p[0])); return '0x' + '1'.repeat(64)
        case 'eth_blockNumber': return '0x10'
        case 'eth_getTransactionReceipt': return null
        default: return undefined
      }
    },
  }
}
const DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'

test('ETH claw-back to an empty account on Amsterdam signs 204,600 gas, journaled before the send', async () => {
  const chain = clawChain({ destEmpty: true, estimate: 204_600n }), relay = fakeRelay({ eth: chain.handler })
  const intents: Array<Record<string, any>> = []
  const { journal } = recordingJournal({ intent: async (ev) => { intents.push(ev); throw new Error('stop after the intent') } })
  await assert.rejects(clawbackEth({ account: privateKeyToAccount(generatePrivateKey()) }, DEST, { journal, network: 'testnet', chainId: 11155111, poll: 1, state: armedState('eth', 10n ** 18n) }), /not acked/)
  assert.equal(intents.length, 1); assert.equal(intents[0].type, 'clawback-intent')
  assert.equal(intents[0].eth.gas, '204600'); assert.equal(intents[0].value, String(10n ** 16n - 204_600n * (2n * 10n ** 9n + 10n ** 9n)))
  assert.equal(relay.sends().length, 0, 'the unacked claw-back was not sent')
})

test('ETH claw-back fails closed when eth_estimateGas does not match the class, and refuses a contract destination', async () => {
  const wrong = clawChain({ destEmpty: true, estimate: 21_000n }), r1 = fakeRelay({ eth: wrong.handler })
  const { journal } = recordingJournal()
  await assert.rejects(clawbackEth({ account: privateKeyToAccount(generatePrivateKey()) }, DEST, { journal, network: 'testnet', chainId: 11155111, poll: 1, state: armedState('eth', 10n ** 18n) }), /does not match .*204600 gas.*fail closed/)
  assert.equal(r1.sends().length, 0)
  const pre = clawChain({ destEmpty: true, estimate: 204_600n }), r2 = fakeRelay({ eth: pre.handler })
  await assert.rejects(clawbackEth({ account: privateKeyToAccount(generatePrivateKey()) }, DEST, { journal, network: 'local', chainId: 31337, poll: 1, state: armedState('eth', 10n ** 18n) }), /21000 gas/, 'pre-Amsterdam: 21,000 even to an empty account')
  assert.equal(r2.sends().length, 0)
  const contract = clawChain({ destEmpty: false, estimate: 21_000n, code: '0x6000' }), r3 = fakeRelay({ eth: contract.handler })
  await assert.rejects(clawbackEth({ account: privateKeyToAccount(generatePrivateKey()) }, DEST, { journal, network: 'local', chainId: 31337, poll: 1, state: armedState('eth', 10n ** 18n) }), /is a contract/)
  assert.equal(r3.sends().length, 0)
})

test('Passive ETH through the adapter: while the next base fee is above T it waits (paused; nothing estimated or signed), then signs at maxFee T + 0.001 gwei', async () => {
  const GWEI = 10n ** 9n
  let polls = 0
  const chain = fakeEthChain({ baseFee: GWEI, next: () => (++polls <= 3 ? 3n * GWEI : GWEI) }), relay = fakeRelay({ eth: chain.handler })
  const { journal, events } = recordingJournal()
  const v = validateLaneConfig({ chain: 'eth', text: 'passive hello', mode: 'drain' })
  assert.equal(v.cfg.feeStrategy, 'passive', 'drain defaults to passive (contracts defaultFeeStrategy)')
  const lane = newLaneState(v.cfg)
  const d = { journal, network: 'local', chainId: 31337, ledger: armedLedger('eth', 10n ** 17n), poll: 1, passiveWaitMs: 1, alive: () => true, notify: async () => {}, lane }
  const A = ethAdapter(v.cfg, { chain: 'eth', account: privateKeyToAccount(generatePrivateKey()) }, d)
  await A.reconcile(lane, async () => {})
  const t: Record<string, any> = { copy: 1, part: 1, parts: 1, payload: A.planCopy(1)[0].payload }
  assert.equal(await A.sendTx(t, { tight: false }), 'confirmed')
  assert.deepEqual(events.map((e) => e.type), ['paused', 'intent', 'resumed', 'sent', 'included', 'readback'])
  assert.match(String(events[0].reason), /waiting for a cheap block/)
  assert.equal(relay.calls.filter((c) => c.method === 'eth_estimateGas').length, 1, 'no estimate (no calldata out) while waiting')
  const eth = events[1].eth as Record<string, string>
  assert.equal(eth.tip, '1000000'); assert.equal(eth.maxFee, String(GWEI + 1_000_000n), 'maxFee = T + tip, T = p10 of the window = 1 gwei')
  assert.equal(relay.sends().length, 1)
})

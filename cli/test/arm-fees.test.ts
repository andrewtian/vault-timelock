// cli/test/arm-fees.test.ts — `vt job arm`'s caps come from core's one source of starting fees (assess.js
// startingFees; M1 glue), and they are IDENTICAL to the caps of the fee logic arm.ts carried before (a copy of
// assess.js's, frozen below as the reference). In process, over a test-owned RelayClient whose fee history varies per
// block and per percentile (so passive, economy and prompt each read a different answer), on every network and for
// every strategy on both chains. Nothing is sent; no port is bound.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { Chain, JobChainDef, JobDef, Network, RelayClient } from '@vault-timelock/core/contracts'
import { normalizeJob } from '@vault-timelock/core/job'
import { computeArmCaps } from '@vault-timelock/core/engine/arm-caps.js'
import { startingFees } from '@vault-timelock/core/engine/assess.js'
import { useRelayClient } from '@vault-timelock/core/engine/rpc.js'
import * as eth from '@vault-timelock/core/chains/eth.js'
import * as sol from '@vault-timelock/core/chains/sol.js'
import { ethPassiveTarget } from '@vault-timelock/core/chains/economy.js'
import { CANON, GWEI, networkOf } from '@vault-timelock/core/chains/constants.js'
import { planCaps } from '../src/job/arm.ts'
import type { JobView } from '../src/job/status.ts'

const NOW = 1_791_504_000_000
const ETH_KEY = '0x8739Eb87B3d11f221Df63454F8D229a1A4F4049C'
const SOL_KEY = '9xx7qC7uwTAeaSo7T5Gk9canYBosFh1pMQaDmQEa83Tb'
const TEXT = 'A synthetic vt fixture message for the arm-fee parity test.\nIt has two lines.\n'
const PRICE = { fixture: true, source: 'fixture', prices: { SOL: { usd: 150 }, ETH: { usd: 3000 } } }
const HEAD = 3000 // the fake chain's newest block; the passive window (7,200 blocks) reaches block 0 and stops there

// A deterministic fee history: base fees and rewards differ per block, and each percentile has its own reward.
const baseAt = (b: number): bigint => GWEI + BigInt((b * 7919) % 997) * 1_000_000n
const rewardAt = (b: number, pct: number): bigint => 10_000n + BigInt((b * 104_729 + pct * 3_571) % 50_000) * 100n
const hex = (x: bigint | number): string => `0x${x.toString(16)}`

function feeHistory(params: unknown[]): unknown {
  const count = Number(BigInt(params[0] as string))
  const newest = params[1] === 'latest' ? HEAD : Number(BigInt(params[1] as string))
  const pcts = (params[2] ?? []) as number[]
  const oldest = Math.max(0, newest - count + 1)
  const blocks: number[] = []
  for (let b = oldest; b <= newest; b++) blocks.push(b)
  return {
    oldestBlock: hex(oldest),
    baseFeePerGas: [...blocks, newest + 1].map((b) => hex(baseAt(b))),
    gasUsedRatio: blocks.map(() => 0.5),
    ...(pcts.length > 0 ? { reward: blocks.map((b) => pcts.map((p) => hex(rewardAt(b, p)))) } : {}),
  }
}

function relayClient(balances: { eth: bigint; sol: bigint }): RelayClient & { calls: string[] } {
  const calls: string[] = []
  return {
    calls,
    async status() { throw new Error('not used') },
    async tor() { return { isTor: null } },
    async price() { return PRICE },
    async rpc(chain, method, params) {
      calls.push(`${chain} ${method}`)
      if (chain === 'eth' && method === 'eth_feeHistory') return feeHistory(params)
      if (chain === 'eth' && method === 'eth_getBalance') return hex(balances.eth)
      if (chain === 'sol' && method === 'getMinimumBalanceForRentExemption') return 890_880
      if (chain === 'sol' && method === 'getBalance') return { context: { slot: 1 }, value: Number(balances.sol) }
      throw new Error(`unexpected ${chain} ${method}`)
    },
  }
}

// ---- the reference: arm.ts's own fee logic as it was before the M1 glue (a copy of assess.js's), frozen here ----
async function legacyEthFees(ch: JobChainDef, n: Network): Promise<{ nextBase: bigint; tip: bigint; maxFee: bigint }> {
  if (ch.feeStrategy === 'passive') {
    const w = await eth.baseFeeWindow()
    const tip = CANON.PASSIVE_ETH_TIP
    return { nextBase: w.nextBase, tip, maxFee: ethPassiveTarget(w.bases) + tip }
  }
  if (ch.feeStrategy === 'economy') return await eth.economyFees(networkOf(n).eth.tipFloor)
  return await eth.fees(3n * GWEI)
}
async function legacyCaps(def: JobDef, chains: readonly Chain[], relay: RelayClient, n: Network) {
  useRelayClient(relay)
  const d = { ...def, chains: Object.fromEntries(chains.map((c) => [c, def.chains[c]])) }
  const prices = await relay.price()
  const fees: Record<string, unknown> = {}
  const balances: Record<string, bigint> = {}
  for (const c of chains) {
    const ch = def.chains[c]!
    if (c === 'eth') {
      fees.eth = await legacyEthFees(ch, n)
      balances.eth = await eth.balance(ch.keyAddress)
    } else {
      fees.sol = { rent: await sol.rentMin(), priorityLamports: ch.feeStrategy === 'prompt' ? CANON.SOL_PROMPT_LAMPORTS : 0 }
      balances.sol = await sol.solBalance(ch.keyAddress)
    }
  }
  return { caps: computeArmCaps(d as JobDef, TEXT, { prices, fees, balances, network: n, now: NOW }), fees }
}

const STRATEGIES = ['passive', 'economy', 'prompt'] as const
function defFor(n: Network, ethStrategy: string, solStrategy: string, budgetUsd: number): JobDef {
  const input = {
    format: 'vt-job/1', network: n, name: 'arm fee parity', message: TEXT,
    chains: {
      // a new mainnet job names its claw-back addresses (PF-S fix round 1, N-6); they do not change the caps
      eth: { mode: 'drain', publishMode: 'eth.calldata.null', feeStrategy: ethStrategy, distinctCopies: true, keyAddress: ETH_KEY, budgetUsd, maxTipGwei: 3, clawbackTo: n === 'mainnet' ? '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6' : null },
      sol: { mode: { copies: 2 }, feeStrategy: solStrategy, distinctCopies: true, keyAddress: SOL_KEY, budgetUsd, maxCuPrice: 2_000_000, clawbackTo: n === 'mainnet' ? 'G147qVmzynHL3EjQ8tvBGDms7u6FDCWbFfFmzNMZmg1x' : null },
    },
  }
  return normalizeJob(input, { network: n }).def
}

test('arm caps: core startingFees gives caps identical to arm.ts\'s former copied fee logic (every network, strategy and chain)', async () => {
  let cases = 0
  const seenEthMaxFee = new Set<bigint>()
  for (const n of ['local', 'testnet', 'mainnet'] as const) {
    for (const es of STRATEGIES) {
      for (const ss of STRATEGIES) {
        for (const [budgetUsd, bal] of [[10, { eth: 10n ** 15n, sol: 10n ** 8n }], [1000, { eth: 10n ** 17n + 1n, sol: 5n * 10n ** 9n + 7n }]] as const) {
          const def = defFor(n, es, ss, budgetUsd)
          const view = { def } as unknown as JobView
          for (const chains of [['eth', 'sol'], ['eth'], ['sol']] as Chain[][]) {
            const ref = await legacyCaps(def, chains, relayClient(bal), n)
            const live = relayClient(bal)
            const got = await planCaps(view, chains, TEXT, live, n, NOW)
            assert.deepEqual(got.caps, ref.caps, `${n} eth=${es} sol=${ss} $${budgetUsd} ${chains.join('+')}`)
            // Only fee, rent (sol.rentMin caches it) and balance reads; each armed key's balance read once, in chain order.
            assert.ok(live.calls.every((c) => ['eth eth_feeHistory', 'eth eth_getBalance', 'sol getMinimumBalanceForRentExemption', 'sol getBalance'].includes(c)), live.calls.join(','))
            assert.deepEqual(live.calls.filter((c) => c.endsWith('etBalance')), chains.map((c) => c === 'eth' ? 'eth eth_getBalance' : 'sol getBalance'))
            cases++
          }
          // The starting fees themselves agree on what the caps read (ETH maxFee; SOL rent + priority lamports).
          useRelayClient(relayClient(bal))
          const e = (await startingFees(n, 'eth', es)).fees
          const s = (await startingFees(n, 'sol', ss)).fees
          const r = (await legacyCaps(def, ['eth', 'sol'], relayClient(bal), n)).fees as { eth: { maxFee: bigint; nextBase: bigint; tip: bigint }; sol: unknown }
          assert.deepEqual({ maxFee: e.maxFee, nextBase: e.nextBase, tip: e.tip }, { maxFee: r.eth.maxFee, nextBase: r.eth.nextBase, tip: r.eth.tip })
          assert.deepEqual(s, r.sol)
          seenEthMaxFee.add(e.maxFee)
        }
      }
    }
  }
  assert.equal(cases, 3 * 3 * 3 * 2 * 3)
  // The fake history really separates the strategies (and economy's per-network tip floor), so the parity is not vacuous.
  assert.ok(seenEthMaxFee.size >= 3, `distinct ETH starting maxFees: ${seenEthMaxFee.size}`)
})

test('arm caps: the caps move with the starting fees (the fake history is read, not ignored)', async () => {
  const def = defFor('local', 'prompt', 'prompt', 1000)
  const view = { def } as unknown as JobView
  const bal = { eth: 10n ** 17n, sol: 5n * 10n ** 9n }
  const prompt = await planCaps(view, ['eth', 'sol'], TEXT, relayClient(bal), 'local', NOW)
  const passive = await planCaps({ def: defFor('local', 'passive', 'passive', 1000) } as unknown as JobView, ['eth', 'sol'], TEXT, relayClient(bal), 'local', NOW)
  assert.notEqual(prompt.caps.eth!.fullCopyCost, passive.caps.eth!.fullCopyCost, 'ETH prompt and passive price one copy differently')
  assert.notEqual(prompt.caps.sol!.fullCopyCost, passive.caps.sol!.fullCopyCost, 'SOL prompt pays priority lamports, passive does not')
})

// E5 / M1.1a: the prompt strategy prices the starting tip under the JOB's maxTipGwei (not a fixed 3 gwei), the same cap the
// executor uses at run time. The fake chain pays an 8 gwei tip, so the cap is what sets the quote.
test('arm caps: prompt pricing honours the job\'s maxTipGwei (5 gwei cap), as core startingFees does', async () => {
  const relay8 = (bal: { eth: bigint; sol: bigint }): RelayClient => {
    const r = relayClient(bal)
    return { ...r, async rpc(chain, method, params) {
      if (chain === 'eth' && method === 'eth_feeHistory') {
        const h = feeHistory(params) as { reward: string[][] }
        return { ...h, reward: h.reward.map((row) => row.map(() => hex(8n * GWEI))) }
      }
      return r.rpc(chain, method, params)
    } }
  }
  const bal = { eth: 10n ** 17n, sol: 5n * 10n ** 9n }
  const withCap = (gwei: number): JobDef => {
    const d = defFor('local', 'prompt', 'prompt', 1000)
    return { ...d, chains: { ...d.chains, eth: { ...d.chains.eth!, maxTipGwei: gwei } } }
  }
  useRelayClient(relay8(bal))
  const tip = async (g: number | undefined): Promise<bigint> => (await startingFees('local', 'eth', 'prompt', g === undefined ? {} : { maxTipGwei: g })).fees.tip
  assert.equal(await tip(undefined), 3n * GWEI, 'the default cap is 3 gwei')
  assert.equal(await tip(5), 5n * GWEI, 'a 5 gwei cap prices a 5 gwei tip (the chain pays 8)')
  const caps = async (g: number) => (await planCaps({ def: withCap(g) } as unknown as JobView, ['eth'], TEXT, relay8(bal), 'local', NOW)).caps.eth!
  const c3 = await caps(3), c5 = await caps(5)
  assert.notEqual(c5.fullCopyCost, c3.fullCopyCost, 'arm prices one copy with the job\'s 5 gwei cap, not the 3 gwei default')
  // the reference: computeArmCaps over core's startingFees at maxTipGwei 5
  useRelayClient(relay8(bal))
  const fees = { eth: (await startingFees('local', 'eth', 'prompt', { maxTipGwei: 5 })).fees }
  const ref = computeArmCaps({ ...withCap(5), chains: { eth: withCap(5).chains.eth } } as JobDef, TEXT, { prices: PRICE, fees, balances: { eth: bal.eth }, network: 'local', now: NOW })
  assert.deepEqual(c5, ref.eth)
})

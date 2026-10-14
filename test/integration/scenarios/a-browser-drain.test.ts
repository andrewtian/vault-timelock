// E4 scenario A (M1): "Until drained" on BOTH chains with BOTH quiet fee strategies, run by the PAGE's executor (the
// browser adapter in its own process: jsdom origin, S3's REAL page server proxying S2's REAL API and S4's REAL relay; its
// sandbox allows the page port only):
//   job A1: ETH Passive + SOL Economy;  job A2: ETH Economy + SOL Passive.
// Each lane is funded for 3½ full copies at the run's (deterministic) fees: base fee pinned at the 7-wei floor; SOL at
// 5,000 lamports a signature (rung 0 = no priority). Asserts per lane: DRAINED after exactly 3 copies; every included part
// read back ✓ and its bytes on chain = the plan (read directly from the chain); the key published nothing else; the
// `drained` line's balance is the chain's; the dust left is UNDER ONE MINIMAL TX (ETH: the next copy is one tx, its worst
// case) and, on SOL, the rent rule holds: the payer keeps rent-exempt minimum + the claw-back fee reserve, and less than
// that plus the next copy's fees. The two ETH strategies run on separate anvils (the economy tip reads the recent
// rewards; a passive tip in the same blocks would move it). OWN SANDBOX. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { Chain, JobDef } from '../../../packages/core/src/contracts/index.ts'
import { laneConfigOf } from '../../../packages/core/src/executor/executor.ts'
import { planLaneCopy } from '../../../packages/core/src/engine/lane.js'
import { ethGasBudget } from '../../../packages/core/src/chains/plan.js'
import { CANON, ECON } from '../../../packages/core/src/chains/constants.js'
import { startAnvil, startValidator, fundEth, fundSol, ethBalance, solBalance, solRent, ethTxsFrom, solTxsOf } from '../harness/chains.ts'
import { armOk, capOf, createJob, evidence, jobOf, journalOf, outcomesOf, spawnExecutor, startStack, waitReady } from '../harness/stack.ts'
import type { Stack } from '../harness/stack.ts'
import { assertPublished, keyOf, lifecycle, ms, scratch, syntheticText } from '../harness/kit.ts'

const T = lifecycle()
const RULE = { amsterdam: false, toSelf: false }
const BASE = 7n                                                       // the EIP-1559 floor: an empty or light block keeps it

test('A: drain on both chains, Passive and Economy, by the browser adapter — drained with dust under one minimal tx; the SOL rent rule', { timeout: 900_000 }, async () => {
  const t0 = Date.now()
  const home = scratch(T)
  const [anvilP, anvilE, sol] = await Promise.all([startAnvil(T, { home, blockTime: 1, baseFee: BASE }), startAnvil(T, { home, blockTime: 1, baseFee: BASE }), startValidator(T, { home, dir: home })])
  const [sP, sE] = await Promise.all([startStack(T, { network: 'local', ethRpc: anvilP.url, solRpc: sol.url }), startStack(T, { network: 'local', ethRpc: anvilE.url, solRpc: sol.url })])
  const tUp = ms(t0)
  const rent = await solRent(sol.port)
  // one text for both lanes: ETH carries it in ONE part (one tx a copy, so the next copy is one minimal tx), SOL in 3
  const text = syntheticText(2_300, 'E4 scenario A: one ETH tx a copy, several SOL parts a copy')

  async function runJob(s: Stack, anvil: number, name: string, eth: 'passive' | 'economy', solStrategy: 'passive' | 'economy') {
    const ek = keyOf('eth'), sk = keyOf('sol')
    const { id, def } = await createJob(s, {
      format: 'vt-job/1', network: 'local', name, message: text,
      chains: {
        eth: { mode: 'drain', publishMode: 'eth.calldata.null', feeStrategy: eth, distinctCopies: true, keyAddress: ek.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: null },
        sol: { mode: 'drain', feeStrategy: solStrategy, distinctCopies: true, keyAddress: sk.address, budgetUsd: 5, maxCuPrice: 2_000_000, clawbackTo: null },
      },
    })
    // the exact worst case of copies 1..4 at this run's fees (ETH: Σ gas budget × maxFee; SOL: Σ exact fees)
    const maxFee = eth === 'passive' ? BASE + CANON.PASSIVE_ETH_TIP : 2n * BASE + ECON.ETH_TIP_FLOOR
    const ethCfg = laneConfigOf('eth', def.chains.eth!, text), solCfg = laneConfigOf('sol', def.chains.sol!, text)
    const ethCost = (i: number): bigint => planLaneCopy(ethCfg, i).reduce((a: bigint, p: { payload: Uint8Array }) => a + BigInt(ethGasBudget(p.payload.length, RULE)) * maxFee, 0n)
    const solFees = (i: number): bigint => BigInt(planLaneCopy(solCfg, i).length) * 5_000n
    assert.equal(planLaneCopy(ethCfg, 1).length, 1, 'ETH: one tx a copy')
    assert.ok(planLaneCopy(solCfg, 1).length >= 3, 'SOL: several parts a copy')
    const floor = rent + ECON.SOL_CLAW_RESERVE
    const ethFund = ethCost(1) + ethCost(2) + ethCost(3) + ethCost(4) / 2n
    const solFund = floor + solFees(1) + solFees(2) + solFees(3) + solFees(4) / 2n
    await fundEth(anvil, ek.address, ethFund)
    await fundSol(sol.port, sk.address, solFund)
    assert.equal(await solBalance(sol.port, sk.address), solFund)
    const t1 = Date.now()
    const proc = spawnExecutor(s, { adapter: 'browser', jobId: id, keys: [ek, sk] })
    T.after(() => proc.stop('SIGKILL'))
    await waitReady(s, id, ['eth', 'sol'])
    await armOk(s, id, { eth: capOf('eth', ethFund), sol: capOf('sol', solFund) })
    const out = await outcomesOf(proc, ['eth', 'sol'], 600_000)
    return { id, def, text, ek, sk, out, ethFund, solFund, ethCost, solFees, floor, runMs: ms(t1), s, anvil, eth, solStrategy, maxFee }
  }

  const jobs = await Promise.all([runJob(sP, anvilP.port, 'E4 A1 eth-passive sol-economy', 'passive', 'economy'), runJob(sE, anvilE.port, 'E4 A2 eth-economy sol-passive', 'economy', 'passive')])
  for (const j of jobs) {
    assert.deepEqual(j.out, { eth: 'drained', sol: 'drained' }, `${j.def.name}: ${JSON.stringify(j.out)}`)
    const st = (await jobOf(j.s, j.id)).state
    const lines = journalOf(j.s, j.id)
    for (const c of ['eth', 'sol'] as Chain[]) {
      const cs = st.chains[c]!
      assert.equal(cs.phase, 'DRAINED', `${j.def.name} ${c}`)
      assert.equal(cs.copiesIncluded, 3, `${j.def.name} ${c}: 3 copies`)
      assert.ok(cs.txs.every((t) => t.state === 'included' && t.readback === true), `${c}: every included part read back ✓`)
      await assertPublished('A', { anvil: j.anvil, sol: sol.port }, j.def as JobDef, j.text, st, c, { copies: 3 })
      const drained = lines.filter((e) => e.chain === c && e.type === 'drained')
      assert.equal(drained.length, 1)
      const d = drained[0].data as { balance: string; nextCost: string; copy: number }
      assert.equal(d.copy, 4)
      const bal = c === 'eth' ? await ethBalance(j.anvil, j.ek.address) : await solBalance(sol.port, j.sk.address)
      assert.equal(BigInt(d.balance), bal, `${c}: the drained line names the chain's balance`)
      // what the chain charged, read from the chain, is exactly what left the lane
      const onChainFees = c === 'eth' ? (await ethTxsFrom(j.anvil, j.ek.address)).reduce((a, x) => a + x.fee, 0n) : (await solTxsOf(sol.port, j.sk.address)).reduce((a, x) => a + x.fee, 0n)
      assert.equal((c === 'eth' ? j.ethFund : j.solFund) - onChainFees, bal, `${c}: funded − on-chain fees = the balance left`)
      assert.equal(BigInt(cs.spent), onChainFees, `${c}: the journal's spent = the chain's fees`)
      if (c === 'eth') {
        assert.equal(BigInt(d.nextCost), j.ethCost(4), 'ETH: the next copy\'s worst case, as computed independently')
        assert.ok(bal < j.ethCost(4), `ETH dust ${bal} wei < one minimal tx's worst case ${j.ethCost(4)} wei (the next copy is one tx)`)
      } else {
        assert.equal(BigInt(d.nextCost), j.solFees(4) + j.floor, 'SOL: the next copy\'s fees + the rent floor')
        assert.ok(bal >= j.floor, `SOL rent rule: ${bal} ≥ rent-exempt minimum + claw-back reserve ${j.floor}`)
        assert.ok(bal < j.floor + j.solFees(4), `SOL: ${bal} < ${j.floor} + the next copy's fees ${j.solFees(4)}`)
        assert.ok(bal - j.floor < 5_000n * BigInt(planLaneCopy(laneConfigOf('sol', j.def.chains.sol!, j.text), 4).length), 'SOL dust above the floor < the next copy')
      }
      evidence('A', `${c} drained`, { job: j.def.name, strategy: c === 'eth' ? j.eth : j.solStrategy, copies: cs.copiesIncluded, parts: cs.txs.length, funded: c === 'eth' ? j.ethFund : j.solFund,
        spent: cs.spent, left: bal, nextCost: d.nextCost, ...(c === 'sol' ? { rentFloor: j.floor } : { maxFee: j.maxFee }) })
    }
    evidence('A', 'timing', { job: j.def.name, runMs: j.runMs })
  }
  evidence('A', 'timing', { stacksUpMs: tUp, totalMs: ms(t0) })
})

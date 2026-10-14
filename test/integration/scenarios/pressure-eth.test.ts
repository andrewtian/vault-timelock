// E4 scenario pressure-eth (M1; R64): the economy ladder under inclusion pressure, with the prototype's ETH pressure
// miner (harness/eth-pressure-miner.mjs, ported) mining the harness's own --no-mining anvil every 1.5 s, base fee pinned at
// 1 gwei, and dropping every pending tx whose tip is below T. Through S2's REAL API and S4's REAL relay; the CLI's adapter.
//   copy 1 under T = 20,000 wei: the first attempt starts at the local tip floor (12,000 wei) and is dropped; each stall
//          of 3 blocks brings a same-nonce replacement (tip and maxFee ×1.125 + 1) until the tip clears T; it lands.
//   T released the moment copy 1's inclusion is journaled; copies 2 and 3 PROBE BACK DOWN: each starts at the last landed
//          tip ÷ 1.125 (never below the floor) and lands at its first attempt.
// Asserts the ladder from the journal (tips, `replaced`, one nonce per copy), that the dropped attempts never reached a
// block, and the published bytes on chain. OWN SANDBOX. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ECON } from '../../../packages/core/src/chains/constants.js'
import { startAnvil, fundEth, ethNonce, rpcResult, startEthPressure, waitFor } from '../harness/chains.ts'
import { armOk, capOf, createJob, evidence, executor, jobOf, journalOf, startStack, waitReady } from '../harness/stack.ts'
import { assertPublished, keyOf, lifecycle, ms, scratch, syntheticText } from '../harness/kit.ts'

const T = lifecycle()
const GWEI = 1_000_000_000n, PRESSURE = 20_000n

test('pressure-eth: the economy ladder bumps through the pressure miner\'s threshold, then probes back down', { timeout: 900_000 }, async () => {
  const t0 = Date.now()
  const home = scratch(T)
  const anvil = await startAnvil(T, { home, blockTime: null, baseFee: GWEI })
  const miner = await startEthPressure(T, { home, anvil: anvil.port, every: 1_500, baseFee: GWEI })
  const s = await startStack(T, { network: 'local', ethRpc: anvil.url, solRpc: null, page: false })
  const key = keyOf('eth')
  await fundEth(anvil.port, key.address, 10n ** 18n)
  const text = syntheticText(500, 'E4 pressure: the ETH ladder')
  const { id, def } = await createJob(s, { format: 'vt-job/1', network: 'local', name: 'E4 pressure eth', message: text,
    chains: { eth: { mode: { copies: 3 }, publishMode: 'eth.calldata.null', feeStrategy: 'economy', distinctCopies: true, keyAddress: key.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: null } } })
  // the pressure: T = 20,000 wei from now; released (back to the schedule's 0) as soon as copy 1's inclusion is journaled,
  // before the executor hears the answer — so copy 2's first attempt meets no pressure
  assert.equal((await miner.set({ T: PRESSURE })).T, String(PRESSURE))
  let released = false
  // Delivery timing (a network delay, never the bytes): each send reaches the pool right after a block was mined, ~1.5 s
  // before the miner's next drop-then-mine, so a tip below T can never slip in between its pool read and its evm_mine.
  s.hooks.before = async (r) => {
    if (r.target !== 'relay' || r.path !== '/relay/eth' || r.body?.method !== 'eth_sendRawTransaction') return
    const b0 = await rpcResult(anvil.port, 'eth_blockNumber')
    await waitFor(async () => ((await rpcResult(anvil.port, 'eth_blockNumber')) !== b0 ? true : null), 30_000, 'the next block', 10)
  }
  s.hooks.after = async (r) => {
    if (!released && r.method === 'POST' && r.path === `/jobs/${id}/chains/eth/events` && r.body?.type === 'included' && r.body.data.copy === 1) { released = true; await miner.set({ T: null }) }
    return 'deliver' as const
  }
  const ex = executor(s, { jobId: id, chain: 'eth', key })
  const run = ex.start()
  await waitReady(s, id, ['eth'])
  await armOk(s, id, { eth: capOf('eth', 10n ** 17n) })
  assert.equal(await run, 'copies-done', ex.view().note)
  assert.ok(released)
  const lines = journalOf(s, id)
  const intents = lines.filter((e) => e.type === 'intent').map((e) => ({ copy: Number(e.data.copy), txId: String(e.data.txId), tip: BigInt((e.data.eth as { tip: string }).tip), nonce: (e.data.eth as { nonce: number }).nonce }))
  const byCopy = (c: number) => intents.filter((x) => x.copy === c)
  // copy 1: the ladder — strictly rising tips, each a ×1.125 + 1 bump, one nonce; every attempt below T dropped
  const c1 = byCopy(1)
  assert.ok(c1.length >= 2, `copy 1 needed bumps (${c1.length} attempts)`)
  assert.equal(c1[0].tip, ECON.ETH_TIP_FLOOR, 'the first attempt starts at the local tip floor')
  for (let i = 1; i < c1.length; i++) {
    assert.equal(c1[i].tip, (c1[i - 1].tip * 1125n + 999n) / 1000n + 1n, `attempt ${i + 1}: ⌈tip × 1.125⌉ + 1`)
    assert.equal(c1[i].nonce, c1[0].nonce, 'a same-nonce replacement')
  }
  assert.ok(c1.slice(0, -1).every((x) => x.tip < PRESSURE) && c1.at(-1)!.tip >= PRESSURE, 'bumped exactly until the tip cleared T')
  assert.equal(lines.filter((e) => e.type === 'replaced').length, c1.length - 1)
  const st = (await jobOf(s, id)).state
  const landed1 = st.chains.eth!.txs.find((t) => t.copy === 1)!.landedId
  assert.equal(landed1, c1.at(-1)!.txId, 'the attempt that cleared T landed')
  for (const x of c1.slice(0, -1)) assert.equal(await rpcResult(anvil.port, 'eth_getTransactionByHash', [x.txId]), null, `${x.txId}: dropped, never mined`)
  assert.ok(miner.child.lines.some((l) => / dropped 0x/.test(l) && /\(T=20000\)/.test(l)), 'the miner dropped the low-tip attempts')
  // copies 2 and 3: probing back down — each starts at the last landed tip ÷ 1.125 (≥ the floor) and lands at once
  const c2 = byCopy(2), c3 = byCopy(3)
  assert.equal(c2.length, 1); assert.equal(c3.length, 1)
  const down = (tip: bigint): bigint => { const t = (tip * 1000n) / 1125n; return t > ECON.ETH_TIP_FLOOR ? t : ECON.ETH_TIP_FLOOR }
  assert.equal(c2[0].tip, down(c1.at(-1)!.tip), 'copy 2 starts one step below copy 1\'s landed tip')
  assert.equal(c3[0].tip, down(c2[0].tip), 'copy 3 one step lower again')
  assert.ok(c3[0].tip < c2[0].tip && c2[0].tip < c1.at(-1)!.tip, 'probes back down')
  assert.equal(await ethNonce(anvil.port, key.address), 3)
  await assertPublished('pressure-eth', { anvil: anvil.port }, def, text, st, 'eth', { copies: 3 })
  evidence('pressure-eth', 'ladder', { T: PRESSURE, copy1Tips: c1.map((x) => x.tip), copy1Dropped: c1.slice(0, -1).map((x) => x.txId), copy1Landed: landed1,
    copy2Tip: c2[0].tip, copy3Tip: c3[0].tip, minerDrops: miner.child.lines.filter((l) => / dropped /.test(l)).length, totalMs: ms(t0) })
})

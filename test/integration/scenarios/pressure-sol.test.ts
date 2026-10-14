// E4 scenario pressure-sol (M1; R64): the SOL economy rungs under a leader that drops low-priority txs — the prototype's
// SOL pressure filter (harness/sol-pressure-filter.mjs, ported) in front of the harness's own solana-test-validator; the
// REAL relay reaches the chain through it (VT_TEST_SOL_RPC, local only). It answers a sendTransaction whose CU price is
// below T as accepted and never forwards it. Through S2's REAL API; the CLI's adapter.
//   copy 1 under T = 1 µL/CU: rung 0 (no priority) is withheld; it is rebroadcast (the same bytes) until its blockhash is
//          PROVEN expired on the endpoint (Efix3: isBlockhashValid says the blockhash is dead, the signature is absent from
//          history, twice ≥ 4 s apart), journaled `reconcile expired`; only THEN one rung up (rung 1, a priority price), which lands.
//   T released the moment copy 1's inclusion is journaled; copy 2 starts one rung below the landed one (rung 0): it
//          probes back down and lands at once.
// Asserts the order from the journal, that the rung-0 signature never reached the chain, and — from the chain's own
// heights — that the rung-1 signature was made over a blockhash fetched after rung 0's validity window had ended.
// OWN SANDBOX. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startValidator, startSolPressure, fundSol, solTxOnChain, rpcResult } from '../harness/chains.ts'
import { armOk, capOf, createJob, evidence, executor, jobOf, journalOf, startStack, waitReady } from '../harness/stack.ts'
import { assertPublished, keyOf, lifecycle, ms, scratch, syntheticText } from '../harness/kit.ts'

const T = lifecycle()

test('pressure-sol: rung up only after a proven expiry, then probes back down', { timeout: 900_000 }, async () => {
  const t0 = Date.now()
  const home = scratch(T)
  const validator = await startValidator(T, { home, dir: home })
  const filter = await startSolPressure(T, { home, validator: validator.port })
  const s = await startStack(T, { network: 'local', ethRpc: null, solRpc: filter.url, page: false })
  const key = keyOf('sol')
  await fundSol(validator.port, key.address, 100_000_000)
  const text = syntheticText(400, 'E4 pressure: the SOL rungs')
  const { id, def } = await createJob(s, { format: 'vt-job/1', network: 'local', name: 'E4 pressure sol', message: text,
    chains: { sol: { mode: { copies: 2 }, feeStrategy: 'economy', distinctCopies: true, keyAddress: key.address, budgetUsd: 5, maxCuPrice: 2_000_000, clawbackTo: null } } })
  assert.equal((await filter.set(1)).T, 1)
  let released = false
  s.hooks.after = async (r) => {
    if (!released && r.method === 'POST' && r.path === `/jobs/${id}/chains/sol/events` && r.body?.type === 'included' && r.body.data.copy === 1) { released = true; await filter.set(null) }
    return 'deliver' as const
  }
  const ex = executor(s, { jobId: id, chain: 'sol', key })
  const run = ex.start()
  await waitReady(s, id, ['sol'])
  await armOk(s, id, { sol: capOf('sol', 10n ** 9n) })
  assert.equal(await run, 'copies-done', ex.view().note)
  assert.ok(released)
  const lines = journalOf(s, id)
  const intents = lines.filter((e) => e.type === 'intent').map((e) => ({ i: lines.indexOf(e), copy: Number(e.data.copy), txId: String(e.data.txId), sol: e.data.sol as { rung: number; cuPrice: number; lastValidBlockHeight: number; fee: string } }))
  const c1 = intents.filter((x) => x.copy === 1), c2 = intents.filter((x) => x.copy === 2)
  assert.equal(c1.length, 2, 'copy 1: rung 0, then rung 1')
  assert.deepEqual([c1[0].sol.rung, c1[0].sol.cuPrice], [0, 0], 'rung 0: no priority')
  assert.equal(c1[1].sol.rung, 1)
  assert.ok(c1[1].sol.cuPrice > 0 && BigInt(c1[1].sol.fee) > 5_000n, 'rung 1: a priority price')
  const expired = lines.findIndex((e) => e.type === 'reconcile' && e.data.txId === c1[0].txId && e.data.outcome === 'expired')
  assert.ok(expired >= 0 && expired < c1[1].i, 'the rung-0 signature was journaled PROVEN expired before rung 1 was signed')
  assert.ok(lines.some((e) => e.type === 'replaced' && e.data.txId === c1[1].txId && e.data.prevId === c1[0].txId))
  // from the chain's heights: rung 1's blockhash was fetched at height lvb₂ − 150 > lvb₁ (rung 0's window had ended)
  assert.ok(c1[1].sol.lastValidBlockHeight - 150 > c1[0].sol.lastValidBlockHeight, `rung 1 signed after rung 0's window: ${c1[1].sol.lastValidBlockHeight - 150} > ${c1[0].sol.lastValidBlockHeight}`)
  assert.equal(await solTxOnChain(validator.port, c1[0].txId), null, 'the withheld rung-0 signature never reached the chain')
  // Efix3: the proof was the validator's own isBlockhashValid — it still says rung 0's blockhash is dead, and rung 1's was live when signed
  const bh0 = (c1[0].sol as unknown as { blockhash: string }).blockhash
  assert.equal((await rpcResult(validator.port, 'isBlockhashValid', [bh0, { commitment: 'confirmed' }])).value, false, 'the validator itself calls rung 0\'s blockhash expired')
  const ctl = await filter.set(null)
  assert.ok(ctl.withheld >= 1 && ctl.forwarded >= 2, `the filter withheld ${ctl.withheld} and forwarded ${ctl.forwarded}`)
  // copy 2: one rung below the landed one — rung 0 again, lands at once
  assert.equal(c2.length, 1)
  assert.deepEqual([c2[0].sol.rung, c2[0].sol.cuPrice], [0, 0], 'copy 2 probes back down to rung 0')
  const st = (await jobOf(s, id)).state
  const p = await assertPublished('pressure-sol', { sol: validator.port }, def, text, st, 'sol', { copies: 2 })
  assert.deepEqual(p.parts.map((x) => x.fee), [c1[1].sol.fee, '5000'], 'copy 1 paid its priority, copy 2 the base fee')
  const expiredAt = lines[expired].at, signed0 = lines[c1[0].i].at
  evidence('pressure-sol', 'rungs', { T: 1, rung0: c1[0].txId, rung0LastValid: c1[0].sol.lastValidBlockHeight, rung0Withheld: ctl.withheld, provenExpiredAfterMs: expiredAt - signed0,
    rung1: c1[1].txId, rung1CuPrice: c1[1].sol.cuPrice, rung1Fee: c1[1].sol.fee, rung1BlockhashHeight: c1[1].sol.lastValidBlockHeight - 150, copy2Rung: c2[0].sol.rung, copy2: c2[0].txId, totalMs: ms(t0) })
})

// E4 scenario parity-real (M1; spec §7.3): the page's executor (browser adapter: jsdom origin, S3's REAL page server;
// its process confined to the page port) and the CLI's (node adapter: nodeClients + the API token file; confined to the
// API's front and the relay) run the SAME job definition (another key each) on the harness's own chains at the same
// time, through S2's REAL API and S4's REAL relay. Their journals are equal event for event: the same [type, copy, part]
// sequence on each chain. Both end COPIES_DONE with every part on chain once. OWN SANDBOX. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { Chain } from '../../../packages/core/src/contracts/index.ts'
import { startAnvil, startValidator, fundEth, fundSol } from '../harness/chains.ts'
import { armOk, capOf, createJob, evidence, jobOf, journalOf, outcomesOf, spawnExecutor, startStack, waitReady } from '../harness/stack.ts'
import { assertPublished, keyOf, lifecycle, ms, scratch, syntheticText } from '../harness/kit.ts'

const T = lifecycle()

test('parity-real: the browser adapter and the node adapter, the same job on the harness chains — equal event sequences', { timeout: 900_000 }, async () => {
  const t0 = Date.now()
  const home = scratch(T)
  const [anvil, sol] = await Promise.all([startAnvil(T, { home, blockTime: 1, baseFee: 7n }), startValidator(T, { home, dir: home })])
  const s = await startStack(T, { network: 'local', ethRpc: anvil.url, solRpc: sol.url })
  const text = syntheticText(1_600, 'E4 parity: one job, two adapters')   // ETH 1 part, SOL 2 parts a copy

  const runs = await Promise.all((['node', 'browser'] as const).map(async (adapter) => {
    const ek = keyOf('eth'), sk = keyOf('sol')
    await fundEth(anvil.port, ek.address, 10n ** 18n)
    await fundSol(sol.port, sk.address, 100_000_000)
    const { id, def } = await createJob(s, { format: 'vt-job/1', network: 'local', name: `E4 parity ${adapter}`, message: text, chains: {
      eth: { mode: { copies: 2 }, publishMode: 'eth.calldata.null', feeStrategy: 'economy', distinctCopies: true, keyAddress: ek.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: null },
      sol: { mode: { copies: 2 }, feeStrategy: 'economy', distinctCopies: true, keyAddress: sk.address, budgetUsd: 5, maxCuPrice: 2_000_000, clawbackTo: null },
    } })
    const t1 = Date.now()
    const p = spawnExecutor(s, { adapter, jobId: id, keys: [ek, sk] })
    T.after(() => p.stop('SIGKILL'))
    await waitReady(s, id, ['eth', 'sol'])
    await armOk(s, id, { eth: capOf('eth', 10n ** 17n), sol: capOf('sol', 10n ** 9n) })
    const out = await outcomesOf(p, ['eth', 'sol'], 600_000)
    return { adapter, id, def, out, ms: ms(t1) }
  }))
  const seq = (id: string, c: Chain, holder: string) => journalOf(s, id).filter((e) => e.chain === c && e.by === holder).map((e) => [e.type, e.data.copy ?? null, e.data.part ?? null])
  const [n, b] = runs
  for (const c of ['eth', 'sol'] as Chain[]) {
    assert.equal(n.out[c], 'copies-done'); assert.equal(b.out[c], 'copies-done')
    const sn = seq(n.id, c, 'cli'), sb = seq(b.id, c, 'browser')
    assert.ok(sn.length > 10, `${c}: a real sequence`)
    assert.deepEqual(sb, sn, `${c}: the browser adapter's journal equals the node adapter's, event for event`)
    for (const r of runs) {
      const st = (await jobOf(s, r.id)).state
      assert.equal(st.chains[c]!.phase, 'COPIES_DONE')
      await assertPublished('parity-real', { anvil: anvil.port, sol: sol.port }, r.def, text, st, c, { copies: 2 })
    }
    evidence('parity-real', `${c} sequence`, { events: sn.length, sequence: sn.map((x) => x.filter((y) => y !== null).join(':')).join(' ') })
  }
  evidence('parity-real', 'timing', { nodeMs: n.ms, browserMs: b.ms, totalMs: ms(t0) })
})

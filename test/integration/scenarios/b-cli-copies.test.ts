// E4 scenario B (M1): ETH copies ×3 by the REAL `vt job run` on a pseudo-terminal — the passphrase typed at its /dev/tty prompt
// (never echoed), the key from its encrypted backup, the API token from $VT_HOME — through S2's REAL API and S4's REAL
// relay, on the harness's own anvil. Asserts: COPIES_DONE; exactly 3 distinct copies on chain by the copy marker of each
// payload's own header (copy 1 none, [copy 2/3], [copy 3/3]); the chain's bytes = the planned bytes; nothing else from
// the key. OWN SANDBOX (test/integration/own-sandbox.list). ALL DATA IS SYNTHETIC; no testnet or mainnet traffic.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parsePart } from '../../../packages/core/src/contracts/index.ts'
import { startAnvil, fundEth, ethTxsFrom } from '../harness/chains.ts'
import { armOk, capOf, createJob, evidence, jobOf, runCli, startStack, waitReady } from '../harness/stack.ts'
import { assertPublished, backupOf, keyOf, lifecycle, ms, passphrase, scratch, syntheticText } from '../harness/kit.ts'

const T = lifecycle()

test('B: ETH copies ×3 via the real `vt job run` in a pty — exactly 3 distinct copies on chain', { timeout: 900_000 }, async () => {
  const t0 = Date.now()
  const anvil = await startAnvil(T, { home: scratch(T), blockTime: 1, baseFee: 7n })
  const s = await startStack(T, { network: 'local', ethRpc: anvil.url, solRpc: null })
  const tUp = ms(t0)
  const key = keyOf('eth'), pass = passphrase(), backup = await backupOf(key, pass)
  await fundEth(anvil.port, key.address, 10n ** 17n)
  const text = syntheticText(1_200, 'E4 scenario B: three copies by the CLI')
  const { id, def } = await createJob(s, {
    format: 'vt-job/1', network: 'local', name: 'E4 B cli copies', message: text,
    chains: { eth: { mode: { copies: 3 }, publishMode: 'eth.calldata.null', feeStrategy: 'economy', distinctCopies: true, keyAddress: key.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: null } },
  })
  const t1 = Date.now()
  const run = runCli(s, { jobId: id, chain: 'eth', address: key.address, backup, passphrase: pass })
  await waitReady(s, id, ['eth'])
  await armOk(s, id, { eth: capOf('eth', 10n ** 16n) })
  const r = await run
  assert.equal(r.outcome, 'copies-done', r.out.slice(-600))
  assert.ok(!r.out.includes(pass), 'the passphrase is never echoed')
  const st = (await jobOf(s, id)).state
  assert.equal(st.chains.eth!.phase, 'COPIES_DONE')
  assert.equal(st.chains.eth!.copiesIncluded, 3)
  const p = await assertPublished('B', { anvil: anvil.port }, def, text, st, 'eth', { copies: 3 })
  assert.equal(p.parts.length, 3)
  // the copy markers, read from the chain's own bytes (data:, + header + text)
  const onChain = (await ethTxsFrom(anvil.port, key.address)).map((x) => parsePart(x.input.subarray(6).toString('utf8')))
  assert.deepEqual(onChain.map((x) => [x.copy, x.copies]).sort(), [[1, null], [2, 3], [3, 3]])
  assert.ok(onChain.every((x) => x.body === text), 'every copy carries the whole text')
  evidence('B', 'timing', { stackUpMs: tUp, runMs: ms(t1), cliMs: r.ms, totalMs: ms(t0) })
})

// E5 scenario passive-fee-limit (found in the Chrome loop, pass 9): a passive ETH lane on a chain of thousands of blocks
// whose RPC serves eth_feeHistory only for about the newest 1,024 blocks (this anvil's own limit, probed below). Before E5
// the second chunk of the 7,200-block walk failed with "-32602: requested block range is out of bounds" and the whole
// assess threw, so Arm never became ready. Now the lane assesses on the shorter window, arms and publishes.
// `vt job run` by the REAL CLI on a pty, through S2's REAL API and S4's REAL relay, on the harness's own anvil.
// OWN SANDBOX (test/integration/own-sandbox.list). ALL DATA IS SYNTHETIC; no testnet or mainnet traffic.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startAnvil, fundEth, rpc, rpcResult } from '../harness/chains.ts'
import { armOk, capOf, createJob, evidence, jobOf, runCli, startStack, waitReady } from '../harness/stack.ts'
import { assertPublished, backupOf, keyOf, lifecycle, ms, passphrase, scratch, syntheticText } from '../harness/kit.ts'

const T = lifecycle()

test('passive-fee-limit: 5,000 blocks on an anvil that limits fee history — the passive ETH lane assesses, arms and publishes', { timeout: 900_000 }, async () => {
  const t0 = Date.now()
  const anvil = await startAnvil(T, { home: scratch(T), blockTime: 1, baseFee: 7n })
  await rpcResult(anvil.port, 'anvil_mine', ['0x1388'])
  const latest = Number(BigInt(await rpcResult(anvil.port, 'eth_blockNumber')))
  assert.ok(latest >= 5000)
  // this anvil's actual limit: the newest 1,024-block range is served, a range ending 2,100 blocks back is refused
  const hist = (newest: number) => rpc(anvil.port, 'eth_feeHistory', ['0x400', '0x' + newest.toString(16), []])
  assert.ok((await hist(latest)).result, 'the newest range is served')
  const old = await hist(latest - 2100)
  assert.equal(old.error?.code, -32602, 'an older range is refused (the limit this test relies on)')
  assert.match(String(old.error?.message), /out of bounds/)

  const s = await startStack(T, { network: 'local', ethRpc: anvil.url, solRpc: null })
  const key = keyOf('eth'), pass = passphrase(), backup = await backupOf(key, pass)
  await fundEth(anvil.port, key.address, 10n ** 17n)
  const text = syntheticText(600, 'E5 passive fee window under an RPC limit')
  const { id, def } = await createJob(s, {
    format: 'vt-job/1', network: 'local', name: 'E5 passive fee limit', message: text,
    chains: { eth: { mode: { copies: 1 }, publishMode: 'eth.calldata.null', feeStrategy: 'passive', distinctCopies: true, keyAddress: key.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: null } },
  })
  const run = runCli(s, { jobId: id, chain: 'eth', address: key.address, backup, passphrase: pass })
  await waitReady(s, id, ['eth'])                                   // the assess passed on the shorter window
  await armOk(s, id, { eth: capOf('eth', 10n ** 16n) })
  const r = await run
  assert.equal(r.outcome, 'copies-done', r.out.slice(-600))
  const st = (await jobOf(s, id)).state
  assert.equal(st.chains.eth!.phase, 'COPIES_DONE')
  await assertPublished('passive-fee-limit', { anvil: anvil.port }, def, text, st, 'eth', { copies: 1 })
  evidence('passive-fee-limit', 'timing', { blocks: latest, totalMs: ms(t0) })
})

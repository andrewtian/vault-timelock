// E4 scenario C (M1): two jobs on ONE ETH key (spec §4.2, ruling 5). Both executors take their leases and reach READY
// before either is armed; job A is armed; then, until A's chain is DONE (copies done AND closed — a settled chain keeps
// its key until a claw-back or close):
//   · arming job C is refused job.key-busy (nothing journaled),
//   · a third job's executor cannot even take a lease (job.key-busy) — it signs nothing;
// once A is closed, C arms and runs. On chain: A's copies, then C's, one tx each, nothing else from the key; C's first
// intent is journaled after A's close. Through S2's REAL API and S4's REAL relay on the harness's own anvil.
// OWN SANDBOX (test/integration/own-sandbox.list). ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startAnvil, fundEth, ethNonce } from '../harness/chains.ts'
import { apiCall, arm, armOk, capOf, createJob, evidence, executor, jobOf, journalOf, startStack, waitReady } from '../harness/stack.ts'
import { assertPublished, keyOf, lifecycle, ms, scratch, syntheticText } from '../harness/kit.ts'

const T = lifecycle()

test('C: a second job on the same key — arm refused job.key-busy until the first job\'s chain is DONE, then it runs', { timeout: 900_000 }, async () => {
  const t0 = Date.now()
  const anvil = await startAnvil(T, { home: scratch(T), blockTime: 1, baseFee: 7n })
  const s = await startStack(T, { network: 'local', ethRpc: anvil.url, solRpc: null })
  const key = keyOf('eth')
  await fundEth(anvil.port, key.address, 10n ** 17n)
  const eth = (copies: number) => ({ mode: { copies }, publishMode: 'eth.calldata.null', feeStrategy: 'economy', distinctCopies: true, keyAddress: key.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: null })
  const textA = syntheticText(700, 'E4 scenario C: job A'), textC = syntheticText(700, 'E4 scenario C: job C'), textD = syntheticText(500, 'E4 scenario C: job D')
  const A = await createJob(s, { format: 'vt-job/1', network: 'local', name: 'E4 C job A', message: textA, chains: { eth: eth(2) } })
  const C = await createJob(s, { format: 'vt-job/1', network: 'local', name: 'E4 C job C', message: textC, chains: { eth: eth(1) } })
  const D = await createJob(s, { format: 'vt-job/1', network: 'local', name: 'E4 C job D', message: textD, chains: { eth: eth(1) } })
  // both executors before either arm: no job is armed on the key yet, so both take a lease and become READY
  const exA = executor(s, { jobId: A.id, chain: 'eth', key }), exC = executor(s, { jobId: C.id, chain: 'eth', key })
  const runA = exA.start(), runC = exC.start()
  await waitReady(s, A.id, ['eth']); await waitReady(s, C.id, ['eth'])
  await armOk(s, A.id, { eth: capOf('eth', 10n ** 16n) })
  const tArmA = Date.now()
  // while A is active: C's arm is refused job.key-busy; nothing is journaled for it
  const before = journalOf(s, C.id).length
  const r1 = await arm(s, C.id, { eth: capOf('eth', 10n ** 16n) })
  assert.equal(r1.status, 409, JSON.stringify(r1.json))
  assert.equal(r1.json.error.guard, 'job.key-busy')
  assert.equal(journalOf(s, C.id).length, before, 'a refused arm journals nothing')
  // a third job on the key cannot take a lease at all: its executor is refused before it signs anything
  const refusedD = await executor(s, { jobId: D.id, chain: 'eth', key }).start().then((x) => `started:${x}`, (e: { guardId?: string }) => e.guardId ?? String(e))
  assert.equal(refusedD, 'job.key-busy')
  assert.equal((await jobOf(s, D.id)).state.chains.eth!.phase, 'AWAITING_KEY', 'job D never got further')
  // A finishes its copies; COPIES_DONE still holds the key (ruling 5)
  assert.equal(await runA, 'copies-done', exA.view().note)
  const r2 = await arm(s, C.id, { eth: capOf('eth', 10n ** 16n) })
  assert.equal(r2.json?.error?.guard, 'job.key-busy', 'a settled chain keeps its key until close or claw-back')
  // closing A's chain makes it DONE: the key is free, C arms and runs
  const cl = await apiCall(s, 'POST', `/jobs/${A.id}/close`, { chain: 'eth' })
  assert.equal(cl.status, 200, cl.text)
  assert.equal((await jobOf(s, A.id)).state.chains.eth!.phase, 'DONE')
  const tFree = Date.now()
  await armOk(s, C.id, { eth: capOf('eth', 10n ** 16n) })
  assert.equal(await runC, 'copies-done', exC.view().note)
  // the journals: C's first intent after A's close; on chain: 2 + 1 txs from the key, nothing else
  const closeAt = journalOf(s, A.id).find((e) => e.type === 'close')!.at
  const firstC = journalOf(s, C.id).find((e) => e.type === 'intent')!
  assert.ok(firstC.at >= closeAt, 'job C signed nothing before job A was DONE')
  const stA = (await jobOf(s, A.id)).state, stC = (await jobOf(s, C.id)).state
  await assertPublished('C', { anvil: anvil.port }, A.def, textA, stA, 'eth', { copies: 2, scope: 'job' })
  await assertPublished('C', { anvil: anvil.port }, C.def, textC, stC, 'eth', { copies: 1, scope: 'job' })
  assert.equal(await ethNonce(anvil.port, key.address), 3, 'the key sent exactly A\'s 2 and C\'s 1 txs')
  evidence('C', 'key-busy', { armC_whileA_active: `${r1.status} ${r1.json.error.guard}`, leaseD: refusedD, armC_afterCopiesDone: r2.json?.error?.guard, armC_afterClose: 200,
    keyBusyMs: tFree - tArmA, totalMs: ms(t0) })
})

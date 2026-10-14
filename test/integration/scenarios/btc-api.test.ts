// E7 fix round 3: the btc executor through S2's REAL jobs API process (its gate(), ledger, arm, resolve and ticket minting — d8c6756) with
// the executor's chain behind the fake bitcoind of core's test fakes (no relay process: the relay has its own regtest scenarios). The
// real regtest + relay + ord path is btc-executor.test.ts.
//   · a btc job is created, its executor takes the lease, journals key-loaded + funds, the btc chain is ARMED through the API (checkArmConfirm, btc);
//   · the first holder dies after the commit's intent; the commit's input is then spent IN A BLOCK by another tx: the next run journals `stuck`
//     (positive evidence), the API's gate refuses to end the chain (engine.btc-open), the operator's resolve mark-failed is accepted by the API,
//     and the rerun lands attempt 2 (replaces null) and reveals; the API's journal ends COPIES_DONE.
// OWN SANDBOX (test/integration/own-sandbox.list). ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createExecutor } from '../../../packages/core/src/executor/executor.ts'
import { nodeAdapter, nodeClients } from '../../../packages/core/src/executor/adapters/node.ts'
import { btcFromSecret, buildCommit } from '../../../packages/core/src/chains/btc.js'
import { relayRpc } from '../../../packages/core/src/engine/rpc.js'
import type { RelayClient } from '../../../packages/core/src/contracts/index.ts'
import { fakeBtcChain } from '../../../packages/core/test/engine/btc-fakes.ts'
import { apiCall, capOf, armOk, createJob, jobOf, journalOf, startStack, TOKEN, waitReady } from '../harness/stack.ts'
import { lifecycle } from '../harness/kit.ts'

const T = lifecycle()

test('btc through the real API: arm, a spent-elsewhere commit becomes stuck, resolve mark-failed, attempt 2 lands; the gate refuses to end a chain with a commit and no reveal (E7 round 3)', { timeout: 300_000 }, async () => {
  const s = await startStack(T, { ethRpc: null, solRpc: null, relay: false, page: false })
  const chain = fakeBtcChain()
  const key = btcFromSecret('77'.repeat(32), 'local')
  chain.fund(key.address, 5_000_000n); chain.mine()
  const text = 'btc through the real API\nsynthetic text.\n'
  const job = await createJob(s, { format: 'vt-job/1', network: 'local', name: 'E7 r3 btc api', message: text,
    chains: { btc: { mode: { copies: 1 }, publishMode: 'btc.inscription', feeStrategy: 'economy', distinctCopies: true, keyAddress: key.address, budgetUsd: 5, maxFeeRateSatVb: 25, clawbackTo: null } } })
  const cfg = { base: 'http://relay.test', fetch: chain.fetch as never }
  const relay: RelayClient = {
    async status() { return { network: 'local', build: 'fake', confined: true, identity: { btc: { ok: true } }, endpoints: { btc: 1 } } },
    rpc: (c, m, p, x) => relayRpc(cfg, c, m, p, x ?? {}),
    async tor() { return { isTor: null } },
    async price() { return { fixture: true, source: 'x', prices: { SOL: { usd: 1 }, ETH: { usd: 1 } } } },
  }
  const { journal } = nodeClients({ network: 'local', token: TOKEN, fetch: s.fetch })
  const { clock, random } = nodeAdapter()
  let die = false, dieOn = (_type: string): boolean => false
  const j2 = { ...journal, async append(id: string, c: never, gen: number, type: string, data: Record<string, unknown>, x?: never) {
    const r = await journal.append(id, c, gen, type, data, x)
    if (dieOn(type) && !die) { die = true; throw new Error('the connection died (test)') }
    return r
  } } as typeof journal
  const make = () => createExecutor({ jobId: job.id, chain: 'btc', key: { chain: 'btc', address: key.address, network: 'local', handle: key }, holder: 'cli', deps: { journal: j2, relay, clock, random, poll: 300 } })

  // run 1: READY, armed through the API, then dies right after the commit's intent
  dieOn = (type) => type === 'intent'
  const run1 = make().start()
  await waitReady(s, job.id, ['btc'])
  await armOk(s, job.id, { btc: capOf('btc', 1_000_000n) }, { countdownSec: 5 })
  assert.equal(await run1, 'failed')
  let st = (await jobOf(s, job.id)).state.chains.btc!
  assert.equal(st.openIntents.length, 1)
  const commit = journalOf(s, job.id).find((e) => e.type === 'intent')!
  assert.equal((commit.data as { replaces: unknown }).replaces, null)

  // the gate (the API's): a chain with an open commit is never ended
  const lease = await journal.lease(job.id, 'btc', 'acquire', 'cli')
  for (const [type, data] of [['stopped', { reason: 'x' }], ['drained', { balance: '0', nextCost: '1', copy: 1 }], ['copies-done', { copies: 1 }]] as const) {
    await assert.rejects(journal.append(job.id, 'btc', lease.gen, type, data), (e: { guardId?: string }) => e.guardId === 'engine.btc-open', type)
  }
  await journal.lease(job.id, 'btc', 'release', 'cli', lease.gen)

  // the commit's input is spent in a block by another transaction
  const input = (commit.data as { btc: { inputs: string[] } }).btc.inputs[0].split(':')
  assert.ok(chain.accept(buildCommit({ key, body: new TextEncoder().encode('another'), inputs: [{ txid: input[0], index: Number(input[1]), amount: 5_000_000n }], value: 5000n, fee: 400n }).hex).ok)
  chain.mine()
  dieOn = () => false
  const run2 = make()
  assert.equal(await run2.start(), 'failed')
  st = (await jobOf(s, job.id)).state.chains.btc!
  assert.equal(st.phase, 'STUCK')
  assert.ok(journalOf(s, job.id).some((e) => e.type === 'stuck' && (e.data as { txId: string }).txId === (commit.data as { txId: string }).txId))
  assert.equal(chain.sends().length, 0)

  // the operator's exit: resolve mark-failed (accepted: the chain is STUCK), then the rerun builds attempt 2
  const rs = await apiCall(s, 'POST', `/jobs/${job.id}/chains/btc/resolve`, { txId: (commit.data as { txId: string }).txId, action: 'mark-failed' })
  assert.equal(rs.status, 200, rs.text)
  const run3 = make()
  assert.equal(await run3.start(), 'copies-done', JSON.stringify(run3.view()))
  const intents = journalOf(s, job.id).filter((e) => e.type === 'intent')
  assert.ok(intents.length >= 3 && intents.every((e) => (e.data as { replaces: unknown }).replaces === null))
  assert.deepEqual(intents.map((e) => (e.data as { attempt: number }).attempt).slice(0, 2), [1, 2])
  st = (await jobOf(s, job.id)).state.chains.btc!
  assert.deepEqual([st.phase, st.copiesIncluded], ['COPIES_DONE', 1])
  // every send carried the API's ticket (minted from the stored body and the journaled commit)
  assert.ok(chain.sends().length === 2 && chain.sends().every((c) => /^vt-ticket\/2\./.test(c.ticket ?? '')))
})

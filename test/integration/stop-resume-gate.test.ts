// PF-E fix round 3 (controller ruling R79 (c)) against the REAL API gate: a journaled stop latches the chain; no executor reopens it on
// its own (its `resumed` is refused job.state, a new job intent intent.after-stop); the operator's resume route lifts the latch; then
// the executor's `resumed` is accepted (STOPPED → RUNNING) and the next part of the job is admitted (the copy order, the planned payload
// and fee bindings unchanged). A detach (R79 (a)) journals nothing, so a chain the executor left by Ctrl-C keeps admitting the next part.
// R79b (M-10): the detach case runs a REAL executor (core createExecutor over httpJournalClient) against this real API — Ctrl-C while
// copy 1 is in flight: the run ends detached with nothing journaled after it (no `stopped`), the chain RUNNING and unlatched, and a
// second executor takes over through the same gate and finishes copy 2. The executor's chain is core's fake ETH chain behind core's
// fake relay (nothing listens but the API); the API's clock is the executor's virtual clock. The stops journaled here carry their code
// (R79b, contracts/stop.ts: operator-stop is resumable).
// ALL DATA IS SYNTHETIC. The in-process API listens on 127.0.0.1 port 0 only (helpers.startApi), as ledger-equivalence does.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { JournalEvent } from '../../packages/core/src/contracts/index.ts'
import { laneConfigOf } from '../../packages/core/src/executor/executor.ts'
import { planLaneCopy } from '../../packages/core/src/engine/lane.js'
import { ethGasLimit } from '../../packages/core/src/chains/plan.js'
import { sha256Hex } from '../../packages/core/src/job/canonical.ts'
import { createExecutor } from '../../packages/core/src/executor/executor.ts'
import { httpJournalClient } from '../../packages/core/src/executor/journal-client.ts'
import { PORTS } from '../../packages/core/src/contracts/index.ts'
import { fakeRelayClient } from '../../packages/core/test/fakes/fake-relay.ts'
import { virtualClock } from '../../packages/core/test/fakes/fake-journal.ts'
import { fakeEthChain } from '../../packages/core/test/engine/fakes.ts'
import { newKey } from '../../packages/core/test/executor/helpers.ts'
import { JOB2, JOB2_INPUT, TOKEN, armBody, armed, call, ethTx, rawOf, startApi } from '../../api/test/helpers.ts'
import type { FakeClock } from '../../api/test/helpers.ts'
import { stackFetch } from './stack.ts'

process.env.NODE_ENV = 'test'
const NULL = '0x0000000000000000000000000000000000000000'

async function setup(t: { after(fn: () => Promise<void> | void): void }) {
  const a = await startApi({ jobs: [JOB2_INPUT] })
  t.after(() => a.close())
  await armed(a, JOB2, ['eth', 'sol'])
  const job = await a.api.registry.load(JOB2)
  const text = (JOB2_INPUT as { message: string }).message
  const cfg = laneConfigOf('eth', job.def.chains.eth!, text)
  const append = async (type: string, data: Record<string, unknown>): Promise<string | null> => {
    try { await job.journal.append({ chain: 'eth', by: 'cli', gen: 1, type: type as JournalEvent['type'], data }) } catch (e) {
      const g = (e as { guardId?: string }).guardId
      if (g === undefined) throw e
      return g
    }
    return null
  }
  // copy c, part 1 at nonce c - 1: the part the API plans (payload digest, the formula gas), as the engine signs it
  const intentOf = (c: number) => {
    const part = planLaneCopy(cfg, c)[0].payload
    return { txId: ethTx(c), copy: c, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: rawOf(c), payloadSha256: sha256Hex(part), reserved: '1',
      eth: { nonce: c - 1, tip: '1', maxFee: '1000000000', gas: String(ethGasLimit(part.length, 0n, { amsterdam: false, toSelf: false })), to: NULL } }
  }
  const landed = async (c: number) => {
    assert.equal(await append('intent', intentOf(c)), null, `copy ${c}: intent accepted`)
    assert.equal(await append('sent', { txId: ethTx(c), outcome: 'accepted', reason: null }), null)
    assert.equal(await append('included', { txId: ethTx(c), copy: c, part: 1, attempt: 1, block: String(100 + c), fee: '21000000000000', ms: 1 }), null)
    assert.equal(await append('readback', { txId: ethTx(c), ok: true, detail: 'synthetic' }), null)
  }
  const phase = () => a.api.registry.state(job).chains.eth!
  return { a, append, intentOf, landed, phase }
}

test('R79 (c) real gate: `stopped` latches; the executor cannot reopen it; the operator\'s resume lifts the latch, then `resumed` reopens it and the next part is admitted', async (t) => {
  const { a, append, intentOf, landed, phase } = await setup(t)
  await landed(1)
  assert.equal((await call(a.port, { path: `/jobs/${JOB2}/stop`, body: { chain: 'eth' } })).status, 200)   // the operator's Stop: its request first
  assert.equal(await append('stopped', { reason: 'stopped by the operator', code: 'operator-stop' }), null)   // R79b: an operator stop carries its code (resumable)
  assert.equal(phase().stopClass, 'resumable')
  assert.deepEqual([phase().phase, phase().stopLatched], ['STOPPED', true])
  assert.equal(await append('resumed', { reason: 'an executor reopening it on its own' }), 'job.state', 'P1: no executor reopens a latched chain')
  assert.equal(await append('intent', intentOf(2)), 'intent.after-stop', 'nothing new while latched')
  const r = await call(a.port, { path: `/jobs/${JOB2}/resume`, body: { chain: 'eth' } })
  assert.equal(r.status, 200, r.text)
  assert.deepEqual([phase().phase, phase().stopLatched ?? false, phase().stopRequested], ['STOPPED', false, false], 'lifted; still STOPPED until an executor reopens it')
  assert.equal(await append('intent', intentOf(2)), 'job.state', 'the reopening comes first')
  assert.equal(await append('resumed', { reason: 'the operator resumed the job (vt job resume)' }), null, 'the executor reopens it')
  assert.equal(phase().phase, 'RUNNING')
  await landed(2)                                                    // the next part, copy order and bindings as before
  assert.equal(await append('stopped', { reason: 'stopped again', code: 'operator-stop' }), null, 'and a later stop latches again')
  assert.deepEqual([phase().phase, phase().stopLatched], ['STOPPED', true])
})

test('R79 (a) + R79b M-10 real gate: a REAL executor detached by Ctrl-C while copy 1 is in flight journals nothing after it (no `stopped`, RUNNING, unlatched); a second executor takes over through the same gate and finishes', { timeout: 120_000 }, async (t) => {
  const clock = virtualClock()
  const apiClock = { now: () => clock.now(), every: () => () => {}, set: () => {}, advance: () => {}, timers: () => 0 } as FakeClock
  const key = newKey('eth')
  const input = { format: 'vt-job/1', network: 'local', name: 'detach gate', message: 'R79b detach through the real gate.\n',
    chains: { eth: { mode: { copies: 2 }, keyAddress: key.address, budgetUsd: 5, clawbackTo: null, distinctCopies: true, feeStrategy: 'prompt' } } }
  const a = await startApi({ jobs: [input], clock: apiClock })
  t.after(() => a.close())
  const id = a.ids[0]!
  const j = a.api.registry.journalOf(id)
  await j.append({ chain: 'eth', by: 'browser', gen: null, type: 'key-loaded', data: { address: key.address } })
  await j.append({ chain: 'eth', by: 'browser', gen: null, type: 'funds', data: { balance: '50000000000000000', affordable: true, nextCopyCost: '25000300000000' } })
  const r = await call(a.port, { path: `/jobs/${id}/arm`, body: armBody(['eth'], { countdownSec: 5, stagger: [0, 0] }) })
  assert.equal(r.status, 200, r.text)
  clock.jump((r.json as { armed: { releaseAt: number } }).armed.releaseAt - clock.now() + 1)
  const chain = fakeEthChain({ balance: 10n ** 18n, from: key.address })
  let onSend = (): void => {}
  const relay = fakeRelayClient({ network: 'local', endpoints: { eth: 1, sol: 1 }, eth: (m, p) => {
    if (m === 'eth_sendRawTransaction') onSend()
    return m === 'eth_chainId' ? '0x7a69' : m === 'eth_getCode' ? '0x' : chain.handler(m, p)
  } })
  const journal = httpJournalClient({ base: `http://127.0.0.1:${PORTS.local.api}`, fetch: stackFetch({ api: a.port, relay: 0 }), token: TOKEN })
  const executor = (holder: 'cli' | 'browser') => createExecutor({ jobId: id, chain: 'eth', key, holder, deps: { journal, relay: relay.client, clock, random: { int: () => 0 }, poll: 1_000 } })
  const events = () => a.api.registry.journalOf(id).all()
  const state = async () => a.api.registry.state(await a.api.registry.load(id)).chains.eth!
  const ex1 = executor('cli')
  onSend = () => { onSend = () => {}; ex1.requestStop() }            // Ctrl-C while copy 1 is in flight
  assert.equal(await ex1.start(), 'stopped')
  assert.equal(ex1.view().phase, 'detached', ex1.view().note)
  const after1 = events()
  const intents1 = after1.filter((e) => e.type === 'intent').map((e) => e.data.copy)
  assert.deepEqual(intents1, [1], 'copy 2 never signed by the detached run')
  assert.equal(after1.filter((e) => e.type === 'stopped').length, 0, 'a detach journals nothing final')
  const st1 = await state()
  assert.deepEqual([st1.phase, st1.stopLatched ?? false, st1.stopRequested], ['RUNNING', false, false], 'the chain keeps running')
  const ex2 = executor('browser')
  assert.equal(await ex2.start(), 'copies-done', ex2.view().note)
  const all = events()
  assert.deepEqual(all.filter((e) => e.type === 'intent').map((e) => e.data.copy), [1, 2], 'every copy once, through the real gate')
  assert.deepEqual((await state()).reassembled, [{ copy: 1, ok: true }, { copy: 2, ok: true }])
  assert.equal(all.filter((e) => e.type === 'stopped').length, 0)
})

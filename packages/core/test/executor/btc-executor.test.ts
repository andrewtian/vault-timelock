// E7b: createExecutor runs a btc chain (local network): lease, reconcile-first, the copies loop through the BTC lane, the cap,
// the view. ALL DATA IS SYNTHETIC: a fixed test key, the fake bitcoind behind the relay's two BTC routes (test/engine/btc-fakes.ts),
// the in-memory jobs API (test/fakes/fake-journal.ts); virtual time. The same executor on testnet4 / mainnet is refused.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createExecutor } from '../../src/executor/executor.ts'
import type { ExecutorKey } from '../../src/executor/executor.ts'
import type { JournalClient, Network, RelayClient } from '../../src/contracts/index.ts'
import * as btcSigner from '@scure/btc-signer'
import { hexToBytes } from '@noble/hashes/utils.js'
import { btcFromSecret, buildCommit } from '../../src/chains/btc.js'
import { relayRpc } from '../../src/engine/rpc.js'
import { fakeJournal, virtualClock } from '../fakes/fake-journal.ts'
import { jobFor, newKey, T0 } from './helpers.ts'
import { fakeBtcChain } from '../engine/btc-fakes.ts'

async function guardAsync(p: Promise<unknown>): Promise<string | null> {
  try { await p } catch (e) { const g = (e as { guardId?: unknown }).guardId; if (typeof g === 'string') return g; throw e }
  return null
}
function rig(o: { feerate?: number; maxFeeRateSatVb?: number; statusFailFrom?: number[]; copies?: number; network?: Network; cap?: string; text?: string; hook?: (type: string, data: Record<string, unknown>) => void } = {}) {
  const network = o.network ?? 'local'
  const clock = virtualClock(T0)
  const chain = fakeBtcChain(o.feerate === undefined ? {} : { feerate: o.feerate })
  const k = btcFromSecret('44'.repeat(32), 'local')
  const text = o.text ?? 'BTC executor test.\n'
  const base = jobFor('eth', newKey('eth'), { copies: o.copies ?? 1, text, network })
  const def = { ...base.def, chains: { btc: { ...(base.def.chains.eth as object), keyAddress: k.address, publishMode: 'sol.memo', feeStrategy: 'economy', ...(o.maxFeeRateSatVb !== undefined ? { maxFeeRateSatVb: o.maxFeeRateSatVb } : {}) } } } as unknown as typeof base.def
  const j = fakeJournal({ def, text, clock, network })
  void j.client.lease(j.id, 'btc', 'acquire', 'browser')
  j.asHolder(1, 'browser', 'btc', 'key-loaded', { address: k.address })
  j.asHolder(1, 'browser', 'btc', 'funds', { balance: '1', affordable: true, nextCopyCost: '1' })
  void j.client.lease(j.id, 'btc', 'release', 'browser', 1)
  j.arm(['btc'], { caps: { btc: o.cap ?? '1000000' }, releaseAt: j.serverNow() + 3_000 })
  chain.fund(k.address, 5_000_000n)
  chain.mine()
  const cfg = { base: 'http://relay.test', fetch: chain.fetch as never }
  let statusCalls = 0
  const relay: RelayClient = {
    async status() { statusCalls++; if (o.statusFailFrom?.includes(statusCalls)) throw new Error('relay status unreachable (test)'); return { network, build: 'fake', confined: true, identity: { btc: { ok: true } }, endpoints: { btc: 1 } } },
    rpc: (c, m, p, x) => relayRpc(cfg, c, m, p, x ?? {}),
    async tor() { return { isTor: null } },
    async price() { return { fixture: true, source: 'x', prices: { SOL: { usd: 1 }, ETH: { usd: 1 } } } },
  }
  // a journal that lets a test act (or fail) right after an event was journaled
  const journal: JournalClient = { ...j.client, async append(id, c, gen, type, data, x) {
    const r = await j.client.append(id, c, gen, type, data, x)
    o.hook?.(type, data)
    return r
  } }
  const key: ExecutorKey = { chain: 'btc', address: k.address, network: 'local', handle: k }
  const deps = { journal, relay, clock, random: { int: () => 0 }, poll: 1_000 }
  const make = () => createExecutor({ jobId: j.id, chain: 'btc', key, holder: 'cli', deps })
  const evs = () => j.events.filter((e) => e.chain === 'btc' && e.by === 'cli' && (e.gen ?? 0) > 1)
  return { clock, chain, key: k, j, make, evs, deps, text }
}

test('Eminors fix 2 (m-2, executor pre-start check): a failed pre-start check over a REJECTED commit attempt ends `failed` (never `stopped`) - the call site uses the one stranded predicate', { timeout: 60_000 }, async () => {
  // run 1 = status #1 (open) + #2 (pre-start); run 2 = #3 + #4 -> fail #4
  let boom = false
  const t = rig({ statusFailFrom: [4], hook: (type) => { if (type === 'intent' && !boom) { boom = true; throw new Error('the connection died (test)') } } })
  assert.equal(await t.make().start(), 'failed')                           // died right after the commit's intent was journaled
  const commit = t.j.events.find((e) => e.type === 'intent')!
  t.j.expire('btc')
  const grant = await t.j.client.lease(t.j.id, 'btc', 'acquire', 'cli')
  await t.j.client.append(t.j.id, 'btc', grant.gen, 'sent', { txId: commit.data.txId, outcome: 'rejected', reason: 'x' })
  const g = t.j.state().chains.btc!.txs[0]
  assert.deepEqual([g.state, g.attempts[0].state], ['failed', 'rejected'], 'the group view says "failed": the old inline predicate (state !== failed) would not see a stranded commit')
  const before = t.j.events.length
  t.j.expire('btc')
  const ex = t.make()
  assert.equal(await ex.start(), 'failed', JSON.stringify(ex.view()))
  assert.match(ex.view().note, /a commit is journaled without its reveal: the chain stays open/)
  assert.ok(!t.j.events.slice(before).some((e) => e.type === 'stopped'), 'no stopped is journaled')
})

test('a btc chain runs: lease, countdown, copy = commit + reveal, copies-done; tickets on every send, an intent before each', { timeout: 60_000 }, async () => {
  const s = rig({ copies: 2 })
  const ex = s.make()
  const out0 = await ex.start()
  assert.equal(out0, 'copies-done', JSON.stringify(ex.view()))
  const types = s.evs().map((e) => e.type).filter((t) => t !== 'note')
  const one = ['copy-built', 'intent', 'sent', 'included', 'readback', 'intent', 'sent', 'included', 'readback', 'reassembled']
  assert.deepEqual(types, [...one, ...one, 'copies-done'])
  const st = s.j.state().chains.btc!
  assert.deepEqual([st.phase, st.copiesIncluded, st.openIntents], ['COPIES_DONE', 2, []])
  const sends = s.chain.sends()
  assert.equal(sends.length, 4)
  assert.ok(sends.every((c) => /^vt-ticket\/2\./.test(c.ticket ?? '')))
  assert.deepEqual(sends.map((c) => c.txid), s.j.events.filter((e) => e.type === 'intent').map((e) => e.data.txId))
  assert.equal(s.j.events.at(-1)!.type, 'lease-released')
  assert.equal(ex.view().phase, 'copies-done')
})

test('testnet4 / mainnet: the btc chain is refused executor.chain-unsupported with a clear message, before any lease', async () => {
  for (const network of ['testnet', 'mainnet'] as const) {
    const s = rig({ network })
    const leases = s.j.calls.filter((c) => c.startsWith('lease')).length
    const ex = s.make()
    const g = await guardAsync(ex.start())
    assert.equal(g, 'executor.chain-unsupported')
    assert.equal(s.j.calls.filter((c) => c.startsWith('lease')).length, leases)
    assert.equal(s.chain.sends().length, 0)
    await assert.rejects(s.make().start(), /local network only/)
  }
})

test('E7b m-3: the job\'s maxFeeRateSatVb reaches the engine: the commit is priced at 1 sat/vB when the node estimates 50 (and at the estimate without the cap)', { timeout: 60_000 }, async () => {
  const fees: Record<string, bigint> = {}
  for (const [name, cap] of [['capped', 1], ['uncapped', undefined]] as const) {
    const s = rig({ feerate: 0.0005, ...(cap !== undefined ? { maxFeeRateSatVb: cap } : {}) })      // 0.0005 BTC/kvB = 50 sat/vB
    assert.equal(await s.make().start(), 'copies-done', name)
    const commit = s.j.events.find((e) => e.type === 'intent')!.data.btc as { fee: string }
    fees[name] = BigInt(commit.fee)
  }
  assert.ok(fees.capped < 400n, `1 sat/vB: the fee is the commit's vsize (${fees.capped} sat)`)
  assert.ok(fees.uncapped > 5_000n, `50 sat/vB: ${fees.uncapped} sat`)
})

test('E7b m-7: a btc claw-back is refused clearly, before any lease or reconcile; nothing is signed', async () => {
  const s = rig()
  const leases = s.j.calls.filter((c) => c.startsWith('lease')).length
  const ex = s.make()
  assert.equal(await guardAsync(ex.clawback('bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080')), 'engine.btc-clawback')
  assert.match(ex.view().note, /no claw-back for a bitcoin lane/)
  assert.equal(ex.view().phase, 'failed')
  assert.equal(s.j.calls.filter((c) => c.startsWith('lease')).length, leases)
  assert.equal(s.chain.sends().length, 0)
})

test('the cap: a cap under the copy\'s outlay stops the chain before any intent', async () => {
  const s = rig({ cap: '500' })
  const out = await s.make().start()
  assert.ok(out === 'stopped' || out === 'failed', out)
  assert.equal(s.j.events.filter((e) => e.type === 'intent').length, 0)
  assert.equal(s.chain.sends().length, 0)
})

for (const [name, after] of [['the reveal\'s intent was acked (before its send)', 'reveal-intent'], ['the commit\'s readback', 'commit-readback']] as const) {
  test(`takeover: the first executor dies after ${name}; the next reconciles and sends the reveal exactly once`, { timeout: 60_000 }, async () => {
    let die = false, intents = 0, boom = false
    const s = rig({ hook: (type) => {
      if (boom) return
      if (type === 'intent') { intents++; if (after === 'reveal-intent' && intents === 2) boom = die = true }
      if (type === 'readback' && after === 'commit-readback') boom = die = true
      if (die) { die = false; throw new Error('the connection died (test)') }
    } })
    assert.equal(await s.make().start(), 'failed')
    assert.equal(s.chain.sends().length, after === 'reveal-intent' ? 1 : 1, 'only the commit left')
    const open = s.j.state().chains.btc!.openIntents.length
    assert.equal(open, after === 'reveal-intent' ? 1 : 0)
    s.j.expire('btc')
    const ex2 = s.make()
    assert.equal(await ex2.start(), 'copies-done')
    const ids = s.j.events.filter((e) => e.type === 'intent').map((e) => e.data.txId as string)
    assert.equal(ids.length, 2, 'no third intent')
    for (const id of ids) assert.equal(s.chain.sendsOf(id).length, 1, 'each tx sent exactly once')
    const st = s.j.state().chains.btc!
    assert.deepEqual([st.phase, st.copiesIncluded, st.openIntents], ['COPIES_DONE', 1, []])
    if (after === 'reveal-intent') assert.ok(s.j.events.some((e) => e.type === 'reconcile' && e.data.txId === ids[1] && e.data.outcome === 'adopted'))
  })
}

test('E7b m-4: the takeover re-reads a LANDED commit from the chain (the holder died between included and readback): a matching read journals readback ok and the reveal goes; a MISMATCHING one ends the run failed, nothing sent', { timeout: 60_000 }, async () => {
  for (const mismatch of [false, true]) {
    let boom = false
    const s = rig({ hook: (type, data) => { if (!boom && type === 'included' && data.part === 1) { boom = true; throw new Error('the connection died (test)') } } })
    assert.equal(await s.make().start(), 'failed')
    const commitId = s.j.events.find((e) => e.type === 'intent')!.data.txId as string
    assert.ok(s.j.events.some((e) => e.type === 'included' && e.data.txId === commitId) && !s.j.events.some((e) => e.type === 'readback'), 'died between included and readback')
    const sent = s.chain.sends().length
    if (mismatch) {                                                    // the chain now shows another tx under that id: the readback cannot match
      const bt = s.j.events.find((e) => e.type === 'intent')!.data.btc as { inputs: string[]; value: string; fee: string }
      const [txid, index] = bt.inputs[0].split(':')
      const other = buildCommit({ key: s.key, body: new TextEncoder().encode('another body'), inputs: [{ txid, index: Number(index), amount: 5_000_000n }], value: BigInt(bt.value), fee: BigInt(bt.fee) })
      s.chain.txs.get(commitId)!.tx = btcSigner.Transaction.fromRaw(hexToBytes(other.hex), { allowUnknownOutputs: true })
    }
    s.j.expire('btc')
    const ex = s.make()
    const out = await ex.start()
    if (!mismatch) {
      assert.equal(out, 'copies-done')
      assert.ok(s.j.events.some((e) => e.type === 'readback' && e.data.txId === commitId && e.data.ok === true && /re-read at the takeover/.test(String(e.data.detail))), 'the executor journaled the re-read')
      assert.equal(s.chain.sendsOf(commitId).length, 1, 'the commit was not sent again')
    } else {
      assert.equal(out, 'failed')
      assert.equal(s.chain.sends().length, sent, 'nothing was sent')
      assert.ok(!s.j.events.some((e) => e.type === 'intent' && (e.data.btc as { kind: string }).kind === 'reveal'), 'no reveal was built')
    }
  }
})

test('a crash after the reveal was SENT, before the block: the takeover finds it by txid and sends nothing', { timeout: 60_000 }, async () => {
  let sents = 0
  const s = rig({ hook: (type) => { if (type === 'sent' && ++sents === 2) throw new Error('the connection died (test)') } })
  assert.equal(await s.make().start(), 'failed')
  assert.equal(s.chain.sends().length, 2)
  s.j.expire('btc')
  assert.equal(await s.make().start(), 'copies-done')
  assert.equal(s.chain.sends().length, 2, 'nothing was sent again')
  assert.equal(s.j.state().chains.btc!.openIntents.length, 0)
})

test('Stop while the commit waits (I-2): the reveal still goes (a commit alone locks funds), the chain stops after the copy; nothing is left open', { timeout: 60_000 }, async () => {
  let ex: ReturnType<typeof createExecutor> | null = null
  let sent = false
  const s = rig({ copies: 2, hook: (type) => { if (type === 'sent' && !sent) { sent = true; ex!.requestStop() } } })
  ex = s.make()
  assert.equal(await ex.start(), 'stopped')
  const st = s.j.state().chains.btc!
  assert.equal(st.copiesIncluded, 1, 'copy 1 complete: commit and reveal')
  assert.deepEqual(st.openIntents, [])
  assert.equal(s.j.events.filter((e) => e.type === 'intent').length, 2)
  assert.equal(s.chain.sends().length, 2)
  assert.ok(st.txs.every((t) => t.state === 'included' && t.readback === true))
})

test('I-1 (executor): a node outage while the commit waits for its block ends the run `failed` — never `stopped`; the rerun finds the commit by txid and sends the reveal once', { timeout: 60_000 }, async () => {
  let sents = 0
  let s: ReturnType<typeof rig>
  s = rig({ hook: (type) => { if (type === 'sent' && ++sents === 1) s.chain.unreadable(1_000) } })
  const ex = s.make()
  assert.equal(await ex.start(), 'failed')
  assert.match(ex.view().note, /cannot be read|stays open/)
  assert.ok(!s.j.events.some((e) => e.type === 'stopped'), 'no stopped')
  const cid = s.j.events.find((e) => e.type === 'intent')!.data.txId as string
  assert.equal(s.j.state().chains.btc!.openIntents.length, 1)
  s.chain.unreadable(0)
  s.j.expire('btc')
  assert.equal(await s.make().start(), 'copies-done')
  const ids = s.j.events.filter((e) => e.type === 'intent').map((e) => e.data.txId as string)
  assert.equal(ids.length, 2)
  assert.equal(s.chain.sendsOf(cid).length, 1)
  assert.equal(s.chain.sendsOf(ids[1]).length, 1)
})

test('R2 I-1 (executor): a failed pre-start check (relay status error) with a commit journaled ends `failed`, never `stopped`; the rerun finishes with one reveal', { timeout: 60_000 }, async () => {
  // status() calls: run 1 = #1 (open) + #2 (pre-start check); run 2 = #3 + #4 -> fail #4
  let die2 = false
  const t = rig({ statusFailFrom: [4], hook: (type) => { if (type === 'readback' && !die2) { die2 = true; throw new Error('the connection died (test)') } } })
  assert.equal(await t.make().start(), 'failed')                          // the first holder dies after the commit's readback
  const before = t.j.events.length
  t.j.expire('btc')
  const ex = t.make()
  assert.equal(await ex.start(), 'failed', JSON.stringify(ex.view()))
  assert.ok(!t.j.events.slice(before).some((e) => e.type === 'stopped'), 'no stopped')
  assert.match(ex.view().note, /commit is journaled without its reveal|unreachable/)
  assert.equal(t.j.state().chains.btc!.phase === 'STOPPED', false)
  t.j.expire('btc')
  assert.equal(await t.make().start(), 'copies-done')
  const ids = t.j.events.filter((e) => e.type === 'intent').map((e) => e.data.txId as string)
  assert.equal(ids.length, 2)
  assert.equal(t.chain.sendsOf(ids[1]).length, 1)
})

test('PF-E fix round 2 (M-2): a Stop that arrives while a copy is planned (after the copy-start check) signs no commit — the run ends stopped, nothing built', { timeout: 60_000 }, async () => {
  let ex: ReturnType<ReturnType<typeof rig>['make']> | null = null
  const r = rig({ hook: (type) => { if (type === 'copy-built') { r.j.requestStop('btc'); ex!.requestStop() } } })   // R79: the job Stop
  ex = r.make()
  assert.equal(await ex.start(), 'stopped')
  assert.deepEqual(r.evs().filter((e) => e.type === 'intent').length, 0, 'no commit signed (before: the commit was built, journaled and sent)')
  assert.ok(r.evs().some((e) => e.type === 'stopped'))
  assert.equal(r.j.state().chains.btc!.phase, 'STOPPED')
})

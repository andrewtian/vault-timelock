// Task T1: the trigger latch core (spec B §6.6, R39/R43): persistent per-chain traces that gate further use until
// cleared. Synthetic data only (made-up addresses, tx ids and hashes); every test runs on its own temp $OUT.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { networkName } from '../../../src/config.ts'
import { Refusal } from '../../../src/guard.ts'
import { keystoreDir, lifecycleDir } from '../../../src/lifecycle/paths.ts'
import { createStore } from '../../../src/lifecycle/store.ts'
import type { Kind, Store } from '../../../src/lifecycle/store.ts'
import {
  advanceTrace, assertNoUncleared, clearTrigger, listTriggers, observe, openTrigger, readTrigger, renderTraceText, resetLatch, resolveTrigger,
  verifyTraceSha,
} from '../../../src/lifecycle/triggers.ts'
import type { ChainTrace, Dest, Evidence, TraceState, Trigger, TriggerCtx } from '../../../src/lifecycle/triggers.ts'
import { assertNoSecretsInStore, fakeClock, refusedAsync } from './helpers.ts'

const CHILD = new URL('./triggers-child.ts', import.meta.url).pathname
const T0 = 1_760_000_000
const DESTS: readonly Dest[] = ['eth', 'arb', 'base', 'btc', 'sol', 'arweave']
const STATES: readonly TraceState[] = ['planned', 'signed', 'submitted', 'confirmed', 'failed', 'not-broadcast', 'unknown']
const LEGAL: Record<TraceState, readonly TraceState[]> = {
  planned: ['signed', 'not-broadcast'], signed: ['submitted', 'unknown', 'failed'], submitted: ['confirmed', 'failed', 'unknown'],
  confirmed: [], failed: [], 'not-broadcast': [], unknown: [],
}
const sha = (s: string) => createHash('sha256').update(s).digest('hex')
const ADDRESS: Record<Dest, string> = {
  eth: '0x' + '1'.repeat(40), arb: '0x' + '2'.repeat(40), base: '0x' + '3'.repeat(40),
  btc: 'tb1q-synthetic-btc-address', sol: 'SyntheticSolanaAddress1111111111', arweave: 'synthetic-arweave-owner',
}
type Profile = 'mainnet' | 'testnet' | 'local'
type Source = 'flow2' | 'flow1' | 'cli'

const chainsFor = (profile: Profile, dests: readonly Dest[]) =>
  dests.map((dest) => ({ dest, network: networkName(profile, dest), address: ADDRESS[dest] as string | null, bytesSha256: sha(`bytes ${dest}`), explorer: null as string | null }))

// Task P1: no test here tests the store's fairness (store.test.ts does), so the store skips its 60 ms self-gap
// (the test-only fairGapMs, store.fair-gap outside NODE_ENV=test).
process.env.NODE_ENV = 'test'
interface Ctx { t: TriggerCtx; out: string; clock: ReturnType<typeof fakeClock> }
async function withT(f: (c: Ctx) => Promise<void>, outName = 'out'): Promise<void> {
  const d = mkdtempSync(join(tmpdir(), 'vt-t1-'))
  try {
    const out = join(d, outName)
    await f({ t: { out, store: createStore(out, { fairGapMs: 0 }) }, out, clock: fakeClock(T0) })
  } finally { rmSync(d, { recursive: true, force: true }) }
}
function open(c: Ctx, id: string, o: { profile?: Profile; dests?: readonly Dest[]; source?: Source } = {}): Promise<Trigger> {
  const profile = o.profile ?? 'testnet'
  return openTrigger(c.t, { id, profile, source: o.source ?? 'flow2', ref: id, payloadSha256: sha('payload'), chains: chainsFor(profile, o.dests ?? ['eth', 'btc']) }, c.clock)
}
// Bitcoin records [commit, reveal] and txId = the reveal; every other chain one id.
const signedOf = (d: Dest) => (d === 'btc' ? { txId: 'btc-reveal-0001', txIds: ['btc-commit-0001', 'btc-reveal-0001'] } : { txId: `${d}-tx-0001`, txIds: [`${d}-tx-0001`] })
function fieldsFor(d: Dest, to: TraceState): Partial<ChainTrace> & { state: TraceState } {
  if (to === 'signed') return { state: to, ...signedOf(d) }
  if (to === 'confirmed') return { state: to, block: '1234', confirmations: 3, readback: true }
  if (to === 'failed' || to === 'unknown' || to === 'not-broadcast') return { state: to, reason: `synthetic ${to}` }
  return { state: to }
}
// A legal path from planned (through advanceTrace only: confirmed via submitted).
const PATH: Record<TraceState, readonly TraceState[]> = {
  planned: [], signed: ['signed'], submitted: ['signed', 'submitted'], confirmed: ['signed', 'submitted', 'confirmed'],
  failed: ['signed', 'failed'], unknown: ['signed', 'unknown'], 'not-broadcast': ['not-broadcast'],
}
async function drive(c: Ctx, id: string, d: Dest, to: TraceState): Promise<Trigger> {
  let tr = await readTrigger(c.t, id)
  for (const s of PATH[to]) tr = await advanceTrace(c.t, id, d, fieldsFor(d, s), c.clock)
  return tr
}
async function endPlanned(c: Ctx, id: string): Promise<void> {
  for (const ch of (await readTrigger(c.t, id)).chains) {
    if (ch.state === 'planned') await advanceTrace(c.t, id, ch.dest, { state: 'not-broadcast', reason: 'synthetic end' }, c.clock)
  }
}
const chainOf = (tr: Trigger, d: Dest): ChainTrace => tr.chains.find((x) => x.dest === d)!
const latchPath = (out: string) => join(lifecycleDir(out), 'latch', 'trigger.json')
const latchOf = (out: string): { open: string | null } | undefined =>
  existsSync(latchPath(out)) ? (JSON.parse(readFileSync(latchPath(out), 'utf8')) as { value: { open: string | null } }).value : undefined
const setLatch = (c: Ctx, open: string | null) => c.t.store.update('latch', 'trigger', () => ({ open }))
const recordPath = (out: string, id: string) => join(lifecycleDir(out), 'trigger', `${id}.json`)
const twinPath = (out: string, id: string) => join(out, 'triggers', `${id}.txt`)
const mode = (p: string) => statSync(p).mode & 0o777

// An independent canonical JSON (sorted keys, no whitespace) for the traceSha256 check.
function canon(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`
  if (v !== null && typeof v === 'object') {
    const o = v as Record<string, unknown>
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canon(o[k])}`).join(',')}}`
  }
  return JSON.stringify(v)
}
function expectedSha(tr: Trigger): string {
  const { traceSha256: _drop, ...rest } = tr
  return sha(canon(rest))
}
// A valid (hash-sealed) uncleared record written straight to the store, eth + btc, each chain `planned` unless `states`
// says otherwise: what a racing or crashed opener leaves behind (the gate would refuse a normal open next to another).
async function plant(c: Ctx, id: string, states: Partial<Record<Dest, TraceState>> = {}): Promise<void> {
  const chains = (['eth', 'btc'] as const).map((dest) => {
    const state = states[dest] ?? 'planned'
    const ids = state === 'planned' ? { txId: null, txIds: null } : signedOf(dest)
    return {
      dest, network: networkName('testnet', dest), state, address: ADDRESS[dest], ...ids, block: null, confirmations: null, readback: null,
      feePaid: null, explorer: null, bytesSha256: sha(`bytes ${dest}`), reason: null, updatedAt: T0,
    }
  })
  const rec: Trigger = {
    id, createdAt: T0, profile: 'testnet', source: 'flow2', ref: id, payloadSha256: sha('payload'), chains, clearedAt: null, clearedBy: null, traceSha256: '',
  }
  rec.traceSha256 = expectedSha(rec)
  await c.t.store.update('trigger', id, () => rec)
  assert.deepEqual(await readTrigger(c.t, id), rec)
}
async function refusalOf(f: () => Promise<unknown>): Promise<Refusal> {
  try { await f() } catch (e) {
    if (e instanceof Refusal) return e
    throw e
  }
  assert.fail('expected a refusal')
}

// ---- open

test('openTrigger: the record first (every chain planned, canonical order), then the latch; 0600 files, 0700 dirs; the text twin', async () => {
  await withT(async (c) => {
    const id = 'f2-0123456789'
    const tr = await openTrigger(c.t, {
      id, profile: 'testnet', source: 'flow2', ref: id, payloadSha256: sha('payload'),
      chains: chainsFor('testnet', ['arweave', 'sol', 'eth', 'btc', 'base', 'arb']),
    }, c.clock)
    assert.deepEqual(tr.chains.map((x) => x.dest), DESTS)
    for (const ch of tr.chains) {
      assert.deepEqual(ch, {
        dest: ch.dest, network: networkName('testnet', ch.dest), state: 'planned', address: ADDRESS[ch.dest], txId: null, txIds: null,
        block: null, confirmations: null, readback: null, feePaid: null, explorer: null, bytesSha256: sha(`bytes ${ch.dest}`), reason: null, updatedAt: T0,
      })
    }
    assert.deepEqual({ ...tr, chains: [], traceSha256: '' }, {
      id, createdAt: T0, profile: 'testnet', source: 'flow2', ref: id, payloadSha256: sha('payload'), chains: [], clearedAt: null, clearedBy: null, traceSha256: '',
    })
    assert.equal(tr.traceSha256, expectedSha(tr))
    assert.equal(verifyTraceSha(tr), true)
    assert.deepEqual(await readTrigger(c.t, id), tr)
    assert.deepEqual(latchOf(c.out), { open: id })
    assert.equal(mode(recordPath(c.out, id)), 0o600)
    assert.equal(mode(join(lifecycleDir(c.out), 'trigger')), 0o700)
    assert.equal(mode(join(c.out, 'triggers')), 0o700)
    assert.equal(mode(twinPath(c.out, id)), 0o600)
    assert.equal(readFileSync(twinPath(c.out, id), 'utf8'), renderTraceText(tr))
  })
})

test('openTrigger refuses malformed input (trigger.input) and writes nothing; local Arbitrum/Base refuse config.local-scope', async () => {
  await withT(async (c) => {
    const good = { id: 'job-1', profile: 'testnet' as Profile, source: 'flow1' as Source, ref: 'job-1', payloadSha256: sha('p'), chains: chainsFor('testnet', ['eth']) }
    const eth = good.chains[0]
    const bad: unknown[] = [
      { ...good, chains: [] },
      { ...good, chains: 'eth' },
      { ...good, chains: [{ ...eth, dest: 'doge' }] },
      { ...good, chains: [eth, eth] },
      { ...good, chains: [{ ...eth, bytesSha256: 'xyz' }] },
      { ...good, chains: [{ ...eth, bytesSha256: sha('a').toUpperCase() }] },
      { ...good, chains: [{ ...eth, network: networkName('mainnet', 'eth') }] },
      { ...good, chains: [{ ...eth, address: 5 }] },
      { ...good, chains: [{ ...eth, explorer: 5 }] },
      { ...good, payloadSha256: 'not-a-hash' },
      { ...good, profile: 'prod' },
      { ...good, source: 'web' },
      { ...good, ref: '' },
      { ...good, ref: 7 },
    ]
    for (const p of bad) await refusedAsync(() => openTrigger(c.t, p as Parameters<typeof openTrigger>[1], c.clock), 'trigger.input')
    await refusedAsync(() => openTrigger(c.t, { ...good, profile: 'local', chains: [{ ...eth, dest: 'arb', network: 'anvil · 31337' }] }, c.clock), 'config.local-scope')
    assert.equal(existsSync(join(lifecycleDir(c.out), 'trigger')), false)
    assert.equal(latchOf(c.out), undefined)
    // the good one passes
    await openTrigger(c.t, good, c.clock)
    assert.deepEqual(latchOf(c.out), { open: 'job-1' })
  })
})

test('one latch at a time: a second openTrigger while one is uncleared refuses trigger.uncleared and writes no record', async () => {
  await withT(async (c) => {
    await open(c, 'f2-aaaaaaaaaa')
    const r = await refusalOf(() => open(c, 'f2-bbbbbbbbbb'))
    assert.equal(r.guardId, 'trigger.uncleared')
    assert.match(r.message, /f2-aaaaaaaaaa/)
    assert.match(r.message, /2 of 2 chains not terminal/)
    assert.equal(existsSync(recordPath(c.out, 'f2-bbbbbbbbbb')), false)
    assert.deepEqual(latchOf(c.out), { open: 'f2-aaaaaaaaaa' })
  })
})

test('trigger.exists: a record is never rewritten, cleared or not (a retry is a new trigger id)', async () => {
  await withT(async (c) => {
    await open(c, 'job-7', { source: 'flow1' })
    await endPlanned(c, 'job-7')
    await clearTrigger(c.t, 'job-7', { by: 'cli' }, c.clock)
    const before = readFileSync(recordPath(c.out, 'job-7'), 'utf8')
    await refusedAsync(() => open(c, 'job-7', { source: 'flow1' }), 'trigger.exists')
    assert.equal(readFileSync(recordPath(c.out, 'job-7'), 'utf8'), before)
    assert.deepEqual(latchOf(c.out), { open: null })
  })
})

// ---- per-chain traces

test('full happy path per chain (Bitcoin txIds [commit, reveal], txId = reveal), then clear; the cleared record keeps every trace', async () => {
  await withT(async (c) => {
    const id = 'f2-1111111111'
    await open(c, id, { dests: DESTS })
    for (const d of DESTS) {
      let tr = await advanceTrace(c.t, id, d, { state: 'signed', ...signedOf(d), feePaid: '21000' }, c.clock)
      assert.equal(chainOf(tr, d).state, 'signed')
      tr = await advanceTrace(c.t, id, d, { state: 'submitted', explorer: `https://explorer.invalid/tx/${signedOf(d).txId}` }, c.clock)
      assert.equal(chainOf(tr, d).state, 'submitted')
      c.clock.set(T0 + 60)
      tr = await advanceTrace(c.t, id, d, { state: 'confirmed', block: '777', confirmations: 2, readback: true }, c.clock)
      const ch = chainOf(tr, d)
      assert.deepEqual({ ...ch }, {
        dest: d, network: networkName('testnet', d), state: 'confirmed', address: ADDRESS[d], ...signedOf(d), block: '777', confirmations: 2,
        readback: true, feePaid: '21000', explorer: `https://explorer.invalid/tx/${signedOf(d).txId}`, bytesSha256: sha(`bytes ${d}`), reason: null, updatedAt: T0 + 60,
      })
      c.clock.set(T0)
    }
    const btc = chainOf(await readTrigger(c.t, id), 'btc')
    assert.deepEqual(btc.txIds, ['btc-commit-0001', 'btc-reveal-0001'])
    assert.equal(btc.txId, 'btc-reveal-0001')
    const confirmed = await readTrigger(c.t, id)
    c.clock.set(T0 + 3600)
    const cleared = await clearTrigger(c.t, id, { by: 'web' }, c.clock)
    assert.equal(cleared.clearedAt, T0 + 3600)
    assert.equal(cleared.clearedBy, 'web')
    assert.deepEqual(cleared.chains, confirmed.chains)
    assert.deepEqual(latchOf(c.out), { open: null })
    await assertNoUncleared(c.t)
  })
})

test('every illegal transition refuses trigger.transition (by id); every legal one passes', async () => {
  for (const from of STATES) {
    await withT(async (c) => {
      const id = `m-${from}`
      await open(c, id, { dests: DESTS })
      // chain eth sits in `from`: every illegal target is refused and leaves it unchanged
      await drive(c, id, 'eth', from)
      for (const to of STATES) {
        if (LEGAL[from].includes(to)) continue
        await refusedAsync(() => advanceTrace(c.t, id, 'eth', fieldsFor('eth', to), c.clock), 'trigger.transition')
        assert.equal(chainOf(await readTrigger(c.t, id), 'eth').state, from)
      }
      // each legal target on its own chain
      const others: Dest[] = ['arb', 'base', 'btc', 'sol', 'arweave']
      for (const to of LEGAL[from]) {
        const d = others.shift()!
        await drive(c, id, d, from)
        const tr = await advanceTrace(c.t, id, d, fieldsFor(d, to), c.clock)
        assert.equal(chainOf(tr, d).state, to)
      }
    })
  }
})

test('signed needs txId and txIds (Bitcoin exactly [commit, reveal], txId = reveal); both are immutable afterwards', async () => {
  await withT(async (c) => {
    const id = 'f2-2222222222'
    await open(c, id, { dests: ['eth', 'btc', 'sol'] })
    const T = 'trigger.transition'
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { state: 'signed' }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { state: 'signed', txId: 'eth-tx-0001' }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { state: 'signed', txIds: ['eth-tx-0001'] }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { state: 'signed', txId: '', txIds: [''] }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { state: 'signed', txId: 'eth-tx-0001', txIds: [] }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { state: 'signed', txId: 'eth-tx-0001', txIds: ['eth-tx-0002'] }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { state: 'signed', txId: 'eth-tx-0001', txIds: ['eth-tx-0001', 5 as unknown as string] }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'btc', { state: 'signed', txId: 'btc-reveal-0001', txIds: ['btc-reveal-0001'] }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'btc', { state: 'signed', txId: 'btc-commit-0001', txIds: ['btc-commit-0001', 'btc-reveal-0001'] }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'btc', { state: 'signed', txId: 'btc-reveal-0001', txIds: ['btc-commit-0001', 'btc-reveal-0001', 'x'] }, c.clock), T)
    for (const d of ['eth', 'btc', 'sol'] as const) await advanceTrace(c.t, id, d, { state: 'signed', ...signedOf(d) }, c.clock)
    // immutable: a different txId / txIds on any later move is refused; the same ones are accepted
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { state: 'submitted', txId: 'eth-tx-9999' }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { state: 'submitted', txIds: ['eth-tx-9999'] }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { state: 'submitted', txId: null }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'btc', { state: 'submitted', txIds: ['btc-reveal-0001', 'btc-commit-0001'] }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'sol', { state: 'unknown', reason: 'r', txId: 'sol-tx-0002' }, c.clock), T)
    const tr = await advanceTrace(c.t, id, 'btc', { state: 'submitted', ...signedOf('btc') }, c.clock)
    assert.deepEqual(chainOf(tr, 'btc').txIds, ['btc-commit-0001', 'btc-reveal-0001'])
    assert.equal(chainOf(tr, 'btc').txId, 'btc-reveal-0001')
    await refusedAsync(() => advanceTrace(c.t, id, 'btc', { state: 'confirmed', block: '1', confirmations: 1, readback: true, txId: 'btc-commit-0001' }, c.clock), T)
    assert.equal(chainOf(await readTrigger(c.t, id), 'eth').txId, 'eth-tx-0001')
  })
})

test('confirmed needs block, confirmations >= 1 and readback; they are set at confirmed only; failed/unknown/not-broadcast need a reason', async () => {
  await withT(async (c) => {
    const id = 'f2-3333333333'
    await open(c, id, { dests: ['eth', 'sol', 'btc', 'arb'] })
    await drive(c, id, 'eth', 'submitted')
    const T = 'trigger.transition'
    const ok = { state: 'confirmed' as const, block: '10', confirmations: 1, readback: false }
    for (const bad of [
      { ...ok, block: undefined }, { ...ok, block: '' }, { ...ok, block: null }, { ...ok, confirmations: 0 }, { ...ok, confirmations: 1.5 },
      { ...ok, confirmations: null }, { ...ok, confirmations: undefined }, { ...ok, readback: undefined }, { ...ok, readback: null },
      { ...ok, readback: 'yes' as unknown as boolean },
    ]) await refusedAsync(() => advanceTrace(c.t, id, 'eth', bad, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'sol', { state: 'signed', ...signedOf('sol'), block: '1' }, c.clock), T)
    await drive(c, id, 'sol', 'signed')
    await refusedAsync(() => advanceTrace(c.t, id, 'sol', { state: 'submitted', confirmations: 1 }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'sol', { state: 'submitted', readback: true }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'sol', { state: 'submitted', reason: 'not now' }, c.clock), T)
    for (const s of ['failed', 'unknown'] as const) {
      await refusedAsync(() => advanceTrace(c.t, id, 'sol', { state: s }, c.clock), T)
      await refusedAsync(() => advanceTrace(c.t, id, 'sol', { state: s, reason: '' }, c.clock), T)
    }
    await refusedAsync(() => advanceTrace(c.t, id, 'btc', { state: 'not-broadcast' }, c.clock), T)
    const tr = await advanceTrace(c.t, id, 'eth', ok, c.clock)
    assert.deepEqual([chainOf(tr, 'eth').state, chainOf(tr, 'eth').readback], ['confirmed', false])
    // null for an optional field changes nothing (keeps what is recorded)
    await drive(c, id, 'arb', 'signed')
    await advanceTrace(c.t, id, 'arb', { state: 'submitted', feePaid: '5', explorer: 'https://explorer.invalid/a' }, c.clock)
    const a = chainOf(await advanceTrace(c.t, id, 'arb', { ...ok, feePaid: null, explorer: null, reason: null }, c.clock), 'arb')
    assert.deepEqual([a.feePaid, a.explorer, a.reason], ['5', 'https://explorer.invalid/a', null])
  })
})

test('advanceTrace: malformed input refuses trigger.input; dest, network, bytesSha256 and a set address never change', async () => {
  await withT(async (c) => {
    const id = 'f2-4444444444'
    await openTrigger(c.t, {
      id, profile: 'testnet', source: 'flow2', ref: id, payloadSha256: sha('payload'),
      chains: [...chainsFor('testnet', ['eth']), { dest: 'sol', network: networkName('testnet', 'sol'), address: null, bytesSha256: sha('s'), explorer: null }],
    }, c.clock)
    const I = 'trigger.input'
    await refusedAsync(() => advanceTrace(c.t, id, 'btc', fieldsFor('btc', 'signed'), c.clock), I) // not a chain of this trigger
    await refusedAsync(() => advanceTrace(c.t, id, 'doge' as Dest, fieldsFor('eth', 'signed'), c.clock), I)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { ...fieldsFor('eth', 'signed'), extra: 1 } as unknown as ChainTrace, c.clock), I)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { ...fieldsFor('eth', 'signed'), feePaid: '1.5' }, c.clock), I)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { ...fieldsFor('eth', 'signed'), feePaid: 21000 as unknown as string }, c.clock), I)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { ...fieldsFor('eth', 'signed'), explorer: 5 as unknown as string }, c.clock), I)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { ...fieldsFor('eth', 'signed'), updatedAt: 1 }, c.clock), I)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { state: 'done' as TraceState }, c.clock), I)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', null as unknown as ChainTrace, c.clock), I)
    const T = 'trigger.transition'
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { ...fieldsFor('eth', 'signed'), dest: 'sol' }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { ...fieldsFor('eth', 'signed'), network: networkName('mainnet', 'eth') }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { ...fieldsFor('eth', 'signed'), bytesSha256: sha('other') }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', { ...fieldsFor('eth', 'signed'), address: '0x' + '9'.repeat(40) }, c.clock), T)
    // the same values are fine; a null address may be filled once
    await advanceTrace(c.t, id, 'eth', { ...fieldsFor('eth', 'signed'), dest: 'eth', network: networkName('testnet', 'eth'), bytesSha256: sha('bytes eth'), address: ADDRESS.eth }, c.clock)
    const tr = await advanceTrace(c.t, id, 'sol', { ...fieldsFor('sol', 'signed'), address: 'SyntheticSolanaFilled11111111111' }, c.clock)
    assert.equal(chainOf(tr, 'sol').address, 'SyntheticSolanaFilled11111111111')
    await refusedAsync(() => advanceTrace(c.t, id, 'sol', { state: 'submitted', address: 'SyntheticSolanaOther111111111111' }, c.clock), T)
    await refusedAsync(() => advanceTrace(c.t, 'f2-ffffffffff', 'eth', fieldsFor('eth', 'signed'), c.clock), 'trigger.store-missing')
  })
})

// ---- evidence (R43)

test('observe: evidence is the only way from signed to confirmed, and (besides resolve) the only way out of unknown', async () => {
  await withT(async (c) => {
    const id = 'f2-5555555555'
    await open(c, id, { dests: DESTS })
    for (const d of DESTS) await drive(c, id, d, d === 'sol' || d === 'arweave' ? 'unknown' : 'signed')
    const T = 'trigger.transition'
    // advanceTrace never moves signed to confirmed, nor anything out of unknown
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', fieldsFor('eth', 'confirmed'), c.clock), T)
    for (const to of STATES) await refusedAsync(() => advanceTrace(c.t, id, 'sol', fieldsFor('sol', to), c.clock), T)
    // found -> confirmed (needs readback; confirmations >= 1; a block)
    const found = { kind: 'found' as const, block: '4242', confirmations: 2, readback: true }
    await refusedAsync(() => observe(c.t, id, 'eth', { kind: 'found', block: '4242', confirmations: 2 }, c.clock), T)
    await refusedAsync(() => observe(c.t, id, 'eth', { ...found, readback: null as unknown as boolean }, c.clock), T)
    await refusedAsync(() => observe(c.t, id, 'eth', { ...found, confirmations: 0 }, c.clock), T)
    await refusedAsync(() => observe(c.t, id, 'eth', { ...found, block: '' }, c.clock), T)
    c.clock.set(T0 + 5)
    let tr = await observe(c.t, id, 'eth', found, c.clock)
    assert.deepEqual([chainOf(tr, 'eth').state, chainOf(tr, 'eth').block, chainOf(tr, 'eth').confirmations, chainOf(tr, 'eth').readback, chainOf(tr, 'eth').reason, chainOf(tr, 'eth').updatedAt],
      ['confirmed', '4242', 2, true, null, T0 + 5])
    tr = await observe(c.t, id, 'arweave', { ...found, readback: false }, c.clock) // from unknown; a mined mismatch is still confirmed (readback false)
    assert.deepEqual([chainOf(tr, 'arweave').state, chainOf(tr, 'arweave').readback, chainOf(tr, 'arweave').reason], ['confirmed', false, null])
    // failure evidence fits its chain only: EVM nonce, Solana blockhash, Bitcoin input
    await refusedAsync(() => observe(c.t, id, 'btc', { kind: 'nonce-consumed', detail: 'x' }, c.clock), T)
    await refusedAsync(() => observe(c.t, id, 'arb', { kind: 'input-spent', detail: 'x' }, c.clock), T)
    await refusedAsync(() => observe(c.t, id, 'arb', { kind: 'blockhash-expired', detail: 'x' }, c.clock), T)
    await refusedAsync(() => observe(c.t, id, 'sol', { kind: 'nonce-consumed', detail: 'x' }, c.clock), T)
    await refusedAsync(() => observe(c.t, id, 'arb', { kind: 'nonce-consumed', detail: '' }, c.clock), T)
    await refusedAsync(() => observe(c.t, id, 'arb', { kind: 'rumour', detail: 'x' } as unknown as Evidence, c.clock), 'trigger.input')
    tr = await observe(c.t, id, 'arb', { kind: 'nonce-consumed', detail: 'nonce 7 used by 0xabc' }, c.clock)
    assert.deepEqual([chainOf(tr, 'arb').state, chainOf(tr, 'arb').reason], ['failed', 'nonce-consumed: nonce 7 used by 0xabc'])
    tr = await observe(c.t, id, 'base', { kind: 'nonce-consumed', detail: 'nonce 3 used' }, c.clock)
    assert.equal(chainOf(tr, 'base').state, 'failed')
    tr = await observe(c.t, id, 'sol', { kind: 'blockhash-expired', detail: 'no status; blockhash expired at slot 99' }, c.clock)
    assert.deepEqual([chainOf(tr, 'sol').state, chainOf(tr, 'sol').reason], ['failed', 'blockhash-expired: no status; blockhash expired at slot 99'])
    tr = await observe(c.t, id, 'btc', { kind: 'input-spent', detail: 'input 0 spent by other' }, c.clock)
    assert.deepEqual([chainOf(tr, 'btc').state, chainOf(tr, 'btc').reason], ['failed', 'input-spent: input 0 spent by other'])
    // nothing else is observable: terminal chains refuse
    for (const d of DESTS) await refusedAsync(() => observe(c.t, id, d, found, c.clock), T)
  })
  await withT(async (c) => { // observe never moves planned or submitted
    const id = 'f2-5555555556'
    await open(c, id, { dests: ['eth', 'sol'] })
    await drive(c, id, 'sol', 'submitted')
    const found = { kind: 'found' as const, block: '1', confirmations: 1, readback: true }
    await refusedAsync(() => observe(c.t, id, 'eth', found, c.clock), 'trigger.transition')
    await refusedAsync(() => observe(c.t, id, 'sol', found, c.clock), 'trigger.transition')
    await refusedAsync(() => observe(c.t, id, 'sol', { kind: 'blockhash-expired', detail: 'x' }, c.clock), 'trigger.transition')
  })
})

test('resolve: mark-done / mark-failed from signed, submitted or unknown; mark-not-broadcast only from planned', async () => {
  await withT(async (c) => {
    const id = 'f2-6666666666'
    await open(c, id, { dests: DESTS })
    await drive(c, id, 'eth', 'signed')
    await drive(c, id, 'arb', 'submitted')
    await drive(c, id, 'btc', 'unknown')
    await drive(c, id, 'sol', 'submitted')
    const by = { by: 'cli' as const }
    const T = 'trigger.transition'
    const done = (tx: string) => ({ action: 'mark-done' as const, tx, block: null, confirmations: null, readback: null })
    // planned: only mark-not-broadcast
    await refusedAsync(() => resolveTrigger(c.t, id, 'base', done('base-tx-0001'), by, c.clock), T)
    await refusedAsync(() => resolveTrigger(c.t, id, 'base', { action: 'mark-failed' }, by, c.clock), T)
    // a tx that is not one of the recorded ids
    await refusedAsync(() => resolveTrigger(c.t, id, 'eth', done('eth-tx-9999'), by, c.clock), T)
    await refusedAsync(() => resolveTrigger(c.t, id, 'eth', { action: 'mark-not-broadcast' }, by, c.clock), T)
    // mark-done with null fields: confirmed, reason `operator: mark-done <tx>` (m1: which tx), readback not checked
    let tr = await resolveTrigger(c.t, id, 'eth', done('eth-tx-0001'), by, c.clock)
    assert.deepEqual({ ...chainOf(tr, 'eth') }, { ...chainOf(tr, 'eth'), state: 'confirmed', block: null, confirmations: null, readback: null, reason: 'operator: mark-done eth-tx-0001', txId: 'eth-tx-0001' })
    assert.match(readFileSync(twinPath(c.out, id), 'utf8'), /^ {2}readback: not checked \(operator\)$/m)
    // mark-done with observed fields, from submitted
    tr = await resolveTrigger(c.t, id, 'arb', { action: 'mark-done', tx: 'arb-tx-0001', block: '88', confirmations: 4, readback: true }, { by: 'web' }, c.clock)
    assert.deepEqual([chainOf(tr, 'arb').state, chainOf(tr, 'arb').block, chainOf(tr, 'arb').confirmations, chainOf(tr, 'arb').readback], ['confirmed', '88', 4, true])
    // Bitcoin: the commit id is one of the recorded ids too; from unknown. The reason records WHICH one was named (m1)
    tr = await resolveTrigger(c.t, id, 'btc', done('btc-commit-0001'), by, c.clock)
    assert.deepEqual([chainOf(tr, 'btc').state, chainOf(tr, 'btc').txId, chainOf(tr, 'btc').reason], ['confirmed', 'btc-reveal-0001', 'operator: mark-done btc-commit-0001'])
    assert.match(readFileSync(twinPath(c.out, id), 'utf8'), /^ {2}reason: operator: mark-done btc-commit-0001$/m)
    tr = await resolveTrigger(c.t, id, 'sol', { action: 'mark-failed' }, by, c.clock)
    assert.deepEqual([chainOf(tr, 'sol').state, chainOf(tr, 'sol').reason], ['failed', 'operator: mark-failed'])
    tr = await resolveTrigger(c.t, id, 'base', { action: 'mark-not-broadcast' }, by, c.clock)
    assert.deepEqual([chainOf(tr, 'base').state, chainOf(tr, 'base').reason], ['not-broadcast', 'operator: mark-not-broadcast'])
    // terminal chains refuse every action
    for (const d of ['eth', 'sol', 'base'] as const) {
      await refusedAsync(() => resolveTrigger(c.t, id, d, done(signedOf(d).txId), by, c.clock), T)
      await refusedAsync(() => resolveTrigger(c.t, id, d, { action: 'mark-failed' }, by, c.clock), T)
      await refusedAsync(() => resolveTrigger(c.t, id, d, { action: 'mark-not-broadcast' }, by, c.clock), T)
    }
    // malformed actions and callers
    const I = 'trigger.input'
    await drive(c, id, 'arweave', 'signed')
    for (const bad of [
      { action: 'retry' }, { ...done('arweave-tx-0001'), confirmations: 0 }, { ...done('arweave-tx-0001'), block: '' },
      { ...done('arweave-tx-0001'), readback: 'yes' }, { ...done('arweave-tx-0001'), block: 5 },
    ]) await refusedAsync(() => resolveTrigger(c.t, id, 'arweave', bad as Parameters<typeof resolveTrigger>[3], by, c.clock), I)
    await refusedAsync(() => resolveTrigger(c.t, id, 'arweave', { action: 'mark-failed' }, { by: 'nobody' as 'cli' }, c.clock), I)
    await refusedAsync(() => resolveTrigger(c.t, id, 'arweave', done(5 as unknown as string), by, c.clock), T)
  })
})

test('mainnet record: resolve needs typed "resolve" and clear needs typed "clear" (the record decides); testnet/local need nothing', async () => {
  await withT(async (c) => {
    const id = 'f2-7777777777'
    await open(c, id, { profile: 'mainnet', dests: ['eth', 'sol'] })
    const CT = 'trigger.clear-typed'
    for (const typed of [undefined, 'clear', 'RESOLVE', ' resolve', '']) {
      await refusedAsync(() => resolveTrigger(c.t, id, 'eth', { action: 'mark-not-broadcast' }, { by: 'cli', ...(typed === undefined ? {} : { typed }) }, c.clock), CT)
    }
    assert.equal(chainOf(await readTrigger(c.t, id), 'eth').state, 'planned')
    await resolveTrigger(c.t, id, 'eth', { action: 'mark-not-broadcast' }, { by: 'web', typed: 'resolve' }, c.clock)
    await resolveTrigger(c.t, id, 'sol', { action: 'mark-not-broadcast' }, { by: 'cli', typed: 'resolve' }, c.clock)
    for (const typed of [undefined, 'resolve', 'CLEAR', 'clear\n']) {
      await refusedAsync(() => clearTrigger(c.t, id, { by: 'cli', ...(typed === undefined ? {} : { typed }) }, c.clock), CT)
    }
    assert.equal((await readTrigger(c.t, id)).clearedAt, null)
    assert.deepEqual(latchOf(c.out), { open: id })
    await clearTrigger(c.t, id, { by: 'cli', typed: 'clear' }, c.clock)
    assert.deepEqual(latchOf(c.out), { open: null })
  })
  for (const profile of ['testnet', 'local'] as const) {
    await withT(async (c) => {
      await open(c, 'job-1', { profile, source: 'cli', dests: ['eth'] })
      await resolveTrigger(c.t, 'job-1', 'eth', { action: 'mark-not-broadcast' }, { by: 'cli' }, c.clock)
      await clearTrigger(c.t, 'job-1', { by: 'cli' }, c.clock)
    })
  }
})

test('planned exit: mark-not-broadcast from planned, then clear succeeds; from any other state trigger.transition', async () => {
  await withT(async (c) => {
    const id = 'f2-8888888888'
    await open(c, id, { dests: ['eth', 'btc'] })
    await refusedAsync(() => clearTrigger(c.t, id, { by: 'web' }, c.clock), 'trigger.not-terminal')
    await resolveTrigger(c.t, id, 'eth', { action: 'mark-not-broadcast' }, { by: 'web' }, c.clock)
    await drive(c, id, 'btc', 'signed')
    await refusedAsync(() => resolveTrigger(c.t, id, 'btc', { action: 'mark-not-broadcast' }, { by: 'web' }, c.clock), 'trigger.transition')
    await resolveTrigger(c.t, id, 'btc', { action: 'mark-failed' }, { by: 'web' }, c.clock)
    const tr = await clearTrigger(c.t, id, { by: 'web' }, c.clock)
    assert.deepEqual(tr.chains.map((x) => [x.dest, x.state]), [['eth', 'not-broadcast'], ['btc', 'failed']])
  })
})

// ---- the gate

test('gate: uncleared refuses (names the id and the non-terminal count); continuing passes only for its own live id; all terminal + clear passes', async () => {
  await withT(async (c) => {
    await assertNoUncleared(c.t) // nothing at all: no keystore, no store
    const id = 'f2-9999999999'
    await open(c, id, { dests: ['eth', 'btc', 'sol'] })
    await drive(c, id, 'eth', 'confirmed')
    const r = await refusalOf(() => assertNoUncleared(c.t))
    assert.equal(r.guardId, 'trigger.uncleared')
    assert.match(r.message, /f2-9999999999/)
    assert.match(r.message, /2 of 3 chains not terminal/)
    await assertNoUncleared(c.t, { continuing: id })
    await refusedAsync(() => assertNoUncleared(c.t, { continuing: 'f2-0000000000' }), 'trigger.continuing') // m3: no such record
    await refusedAsync(() => assertNoUncleared(c.t, {}), 'trigger.uncleared')
    // persistence: a fresh store instance over the same $OUT still refuses
    await refusedAsync(() => assertNoUncleared({ out: c.out, store: createStore(c.out) }), 'trigger.uncleared')
    // an uncleared record the latch does not name (the latch reset by hand) still refuses: the files are scanned
    await setLatch(c, null)
    await refusedAsync(() => assertNoUncleared(c.t), 'trigger.uncleared')
    await assertNoUncleared(c.t, { continuing: id })
    await setLatch(c, id)
    await endPlanned(c, id)
    await clearTrigger(c.t, id, { by: 'cli' }, c.clock)
    await assertNoUncleared(c.t)
    await assertNoUncleared({ out: c.out, store: createStore(c.out) })
    // a later trigger can open
    await open(c, 'f2-9999999998')
    await refusedAsync(() => assertNoUncleared(c.t, { continuing: id }), 'trigger.continuing') // m3: cleared
  })
})

test('gate fails closed: a corrupt trigger file (store.corrupt) or a tampered one (trigger.hash-mismatch) refuses, even as continuing; a malformed latch counts as uncleared', async () => {
  await withT(async (c) => {
    await open(c, 'job-1', { source: 'flow1', dests: ['eth'] })
    await endPlanned(c, 'job-1')
    await clearTrigger(c.t, 'job-1', { by: 'cli' }, c.clock)
    await assertNoUncleared(c.t)
    const file = recordPath(c.out, 'job-1')
    const good = readFileSync(file, 'utf8')
    for (const text of ['', '{', 'null', '{"rev":1,"updatedAt":1}']) {
      writeFileSync(file, text)
      await refusedAsync(() => assertNoUncleared(c.t), 'store.corrupt')
      await refusedAsync(() => assertNoUncleared(c.t, { continuing: 'job-1' }), 'store.corrupt')
    }
    for (const value of [null, 5, 'x', [], {}, { id: 'job-1' }]) {
      writeFileSync(file, JSON.stringify({ rev: 9, value, updatedAt: 1 }))
      await refusedAsync(() => assertNoUncleared(c.t), 'trigger.hash-mismatch')
    }
    writeFileSync(file, good)
    await assertNoUncleared(c.t)
    for (const value of [{}, { open: 5 }, { open: ['job-1'] }, null, 'job-1']) {
      writeFileSync(latchPath(c.out), JSON.stringify({ rev: 9, value, updatedAt: 1 }))
      await refusedAsync(() => assertNoUncleared(c.t), 'trigger.uncleared')
    }
    writeFileSync(latchPath(c.out), '{')
    await refusedAsync(() => assertNoUncleared(c.t), 'store.corrupt')
  })
})

test('gate: lifecycle/trigger/ missing while keystore/master.pub exists refuses trigger.store-missing; without a keystore it passes', async () => {
  await withT(async (c) => {
    await assertNoUncleared(c.t)
    mkdirSync(keystoreDir(c.out), { recursive: true, mode: 0o700 })
    writeFileSync(join(keystoreDir(c.out), 'master.pub'), 'age1synthetic\n', { mode: 0o600 })
    await refusedAsync(() => assertNoUncleared(c.t), 'trigger.store-missing')
    await refusedAsync(() => assertNoUncleared(c.t, { continuing: 'job-1' }), 'trigger.store-missing')
    await refusedAsync(() => open(c, 'job-1'), 'trigger.store-missing')
    assert.equal(existsSync(join(lifecycleDir(c.out), 'trigger')), false) // never created behind the gate's back
    await refusedAsync(() => advanceTrace(c.t, 'job-1', 'eth', fieldsFor('eth', 'signed'), c.clock), 'trigger.store-missing')
    await refusedAsync(() => clearTrigger(c.t, 'job-1', { by: 'cli' }, c.clock), 'trigger.store-missing')
    assert.equal(existsSync(join(lifecycleDir(c.out), 'trigger')), false)
    mkdirSync(join(lifecycleDir(c.out), 'trigger'), { recursive: true, mode: 0o700 })
    await assertNoUncleared(c.t)
  })
})

// ---- crash-order protocol (I5)

test('crash between openTrigger steps 1 and 2 (record written, latch never CASed): the gate refuses; mark-not-broadcast + clear end it; a retry answers trigger.cleared', async () => {
  await withT(async (c) => {
    const id = 'f2-c1c1c1c1c1'
    await open(c, id, { dests: ['eth', 'sol'] })
    await setLatch(c, null) // the state a crash between the two steps leaves
    await refusedAsync(() => assertNoUncleared(c.t), 'trigger.uncleared')
    await refusedAsync(() => open(c, 'f2-c2c2c2c2c2'), 'trigger.uncleared')
    for (const d of ['eth', 'sol'] as const) await resolveTrigger(c.t, id, d, { action: 'mark-not-broadcast' }, { by: 'cli' }, c.clock)
    const tr = await clearTrigger(c.t, id, { by: 'cli' }, c.clock) // the null latch makes the latch step a no-op: no error
    assert.equal(tr.clearedBy, 'cli')
    assert.deepEqual(latchOf(c.out), { open: null })
    await refusedAsync(() => clearTrigger(c.t, id, { by: 'cli' }, c.clock), 'trigger.cleared')
    await assertNoUncleared(c.t)
  })
  await withT(async (c) => { // no latch record at all (never created)
    await open(c, 'job-2', { dests: ['eth'] })
    rmSync(latchPath(c.out))
    await refusedAsync(() => assertNoUncleared(c.t), 'trigger.uncleared')
    await resolveTrigger(c.t, 'job-2', 'eth', { action: 'mark-not-broadcast' }, { by: 'cli' }, c.clock)
    await clearTrigger(c.t, 'job-2', { by: 'cli' }, c.clock)
    assert.equal(latchOf(c.out), undefined)
    await assertNoUncleared(c.t)
  })
})

test('crash in clearTrigger between the stamp and the latch CAS: a latch naming a cleared record is reset by assertNoUncleared', async () => {
  await withT(async (c) => {
    const id = 'f2-d1d1d1d1d1'
    await open(c, id, { dests: ['eth'] })
    await endPlanned(c, id)
    await clearTrigger(c.t, id, { by: 'web' }, c.clock)
    await setLatch(c, id) // the state the crash leaves: record cleared, latch still naming it
    await assertNoUncleared(c.t)
    assert.deepEqual(latchOf(c.out), { open: null })
    await setLatch(c, id)
    await refusedAsync(() => assertNoUncleared(c.t, { continuing: id }), 'trigger.continuing') // m3: nothing continues a cleared trigger
    assert.deepEqual(latchOf(c.out), { open: id }) // left to the plain gate
    await open(c, 'f2-d2d2d2d2d2') // openTrigger's own gate resets it, then takes the latch
    assert.deepEqual(latchOf(c.out), { open: 'f2-d2d2d2d2d2' })
  })
})

test('a latch naming a missing record refuses trigger.store-missing (continuing that id: trigger.continuing, m3)', async () => {
  await withT(async (c) => {
    await setLatch(c, 'f2-ghostghost')
    await refusedAsync(() => assertNoUncleared(c.t), 'trigger.store-missing')
    await refusedAsync(() => assertNoUncleared(c.t, { continuing: 'f2-ghostghost' }), 'trigger.continuing')
    await refusedAsync(() => open(c, 'f2-e1e1e1e1e1'), 'trigger.store-missing')
  })
})

test('m3: continuing needs an existing, uncleared record; anything else refuses trigger.continuing (a START point uses the plain gate)', async () => {
  await withT(async (c) => {
    const C = 'trigger.continuing'
    await refusedAsync(() => assertNoUncleared(c.t, { continuing: 'job-1' }), C) // no store at all: nothing to continue
    await assertNoUncleared(c.t) // ... while the plain gate passes
    await open(c, 'job-1', { dests: ['eth'] })
    await assertNoUncleared(c.t, { continuing: 'job-1' })
    const m = await refusalOf(() => assertNoUncleared(c.t, { continuing: 'job-none' }))
    assert.deepEqual([m.guardId, m.message.includes('continuing job-none: there is no such trigger record (lifecycle/trigger/job-none.json)')], [C, true], m.message)
    await endPlanned(c, 'job-1')
    await assertNoUncleared(c.t, { continuing: 'job-1' }) // terminal but not cleared yet: still its own
    await clearTrigger(c.t, 'job-1', { by: 'cli' }, c.clock)
    const k = await refusalOf(() => assertNoUncleared(c.t, { continuing: 'job-1' }))
    assert.deepEqual([k.guardId, k.message.includes('continuing job-1: that trigger is cleared')], [C, true], k.message)
    await assertNoUncleared(c.t)
    await refusedAsync(() => assertNoUncleared(c.t, { continuing: 'Bad/Id' }), 'store.id') // fail closed on a malformed id
  })
})

test('m2: the twin is written after the commit (and after the latch CAS); a twin failure is a warning, never a refusal', async () => {
  await withT(async (c0) => {
    const warnings: string[] = []
    const c: Ctx = { ...c0, t: { ...c0.t, warn: (l) => { warnings.push(l) } } }
    const id = 'f2-7a7a7a7a7a'
    mkdirSync(join(c.out, 'triggers'), { recursive: true, mode: 0o700 })
    chmodSync(join(c.out, 'triggers'), 0o500) // private, but nothing can be created in it: every twin write fails (EACCES)
    const tr = await open(c, id, { dests: ['eth', 'sol'] }) // resolves: the record and the latch are committed
    assert.deepEqual(latchOf(c.out), { open: id })
    assert.deepEqual(await readTrigger(c.t, id), tr)
    assert.equal(existsSync(twinPath(c.out, id)), false)
    const line = `warn trigger.twin-stale: triggers/${id}.txt was not rewritten (EACCES); the write to lifecycle/trigger/${id}.json is committed and authoritative (vt-broadcast triggers show ${id} prints it; the next write regenerates the twin)`
    assert.deepEqual(warnings, [line])
    let after = await advanceTrace(c.t, id, 'eth', fieldsFor('eth', 'signed'), c.clock)
    assert.equal(chainOf(await readTrigger(c.t, id), 'eth').state, 'signed')
    assert.equal(warnings.length, 2)
    chmodSync(join(c.out, 'triggers'), 0o700)
    after = await advanceTrace(c.t, id, 'eth', fieldsFor('eth', 'submitted'), c.clock) // the next write regenerates it
    assert.equal(readFileSync(twinPath(c.out, id), 'utf8'), renderTraceText(after))
    assert.equal(warnings.length, 2)
    // clear: record stamped, latch CASed, then the twin (which fails): the clear stands
    await advanceTrace(c.t, id, 'eth', fieldsFor('eth', 'confirmed'), c.clock)
    await resolveTrigger(c.t, id, 'sol', { action: 'mark-not-broadcast' }, { by: 'cli' }, c.clock)
    chmodSync(join(c.out, 'triggers'), 0o500)
    const cleared = await clearTrigger(c.t, id, { by: 'cli' }, c.clock)
    assert.notEqual(cleared.clearedAt, null)
    assert.deepEqual(await readTrigger(c.t, id), cleared)
    assert.deepEqual(latchOf(c.out), { open: null })
    assert.deepEqual(warnings, [line, line, line])
    await assertNoUncleared(c.t)
    chmodSync(join(c.out, 'triggers'), 0o700)
    // a loose triggers/ (store.perms): the same warning, naming the guard and only relative paths (m8)
    chmodSync(join(c.out, 'triggers'), 0o755)
    await open(c, 'f2-7b7b7b7b7b', { dests: ['eth'] })
    assert.equal(warnings.length, 4)
    assert.match(warnings[3], /^warn trigger\.twin-stale: triggers\/f2-7b7b7b7b7b\.txt was not rewritten \(store\.perms\); /)
    for (const w of warnings) assert.ok(!w.includes(c.out) && !w.includes(realpathSync(c.out)) && !w.includes(tmpdir()), w)
  })
})

test('m2: openTrigger and clearTrigger write the twin only after the latch CAS', async () => {
  await withT(async (c) => {
    const id = 'f2-7c7c7c7c7c'
    const atCas: string[] = []
    const inner: Store = c.t.store
    const watching: Store = {
      read: <T>(kind: Kind, k: string) => inner.read<T>(kind, k),
      list: (kind: Kind) => inner.list(kind),
      update: async <T>(kind: Kind, k: string, fn: (cur?: T) => T) => {
        if (kind === 'latch') atCas.push(existsSync(twinPath(c.out, id)) ? readFileSync(twinPath(c.out, id), 'utf8') : 'no twin')
        return inner.update<T>(kind, k, fn)
      },
    }
    const t: TriggerCtx = { out: c.out, store: watching }
    const tr = await openTrigger(t, { id, profile: 'testnet', source: 'flow2', ref: id, payloadSha256: sha('p'), chains: chainsFor('testnet', ['eth']) }, c.clock)
    assert.deepEqual(atCas, ['no twin'])
    assert.equal(readFileSync(twinPath(c.out, id), 'utf8'), renderTraceText(tr))
    await endPlanned(c, id)
    const openText = readFileSync(twinPath(c.out, id), 'utf8')
    const cleared = await clearTrigger(t, id, { by: 'cli' }, c.clock)
    assert.deepEqual(atCas, ['no twin', openText]) // the latch moved while the twin still showed the open record
    assert.equal(readFileSync(twinPath(c.out, id), 'utf8'), renderTraceText(cleared))
  })
})

test('m8: refusals and warnings name paths relative to $OUT, never $OUT\'s basename (the user name when VAULT_TIMELOCK_DIR=$HOME)', async () => {
  await withT(async (c0) => {
    const warnings: string[] = []
    const c: Ctx = { ...c0, t: { ...c0.t, warn: (l) => { warnings.push(l) } } }
    const USER = 'synthetic-user-name'
    await open(c, 'job-1', { dests: ['eth'] })
    const msg = async (f: () => Promise<unknown>, id: string): Promise<string> => {
      const r = await refusalOf(f)
      assert.equal(r.guardId, id)
      assert.ok(!r.message.includes(USER) && !r.message.includes(c.out), r.message)
      return r.message
    }
    for (const name of ['lifecycle', 'lifecycle/trigger', 'lifecycle/latch']) {
      const dir = join(c.out, name)
      chmodSync(dir, 0o750)
      assert.ok((await msg(() => assertNoUncleared(c.t), 'store.perms')).startsWith(`${name} must be a real directory`), name)
      if (name !== 'lifecycle/latch') assert.ok((await msg(() => advanceTrace(c.t, 'job-1', 'eth', fieldsFor('eth', 'signed'), c.clock), 'store.perms')).startsWith(`${name} must be`), name)
      chmodSync(dir, 0o700)
    }
    chmodSync(join(c.out, 'triggers'), 0o750)
    await resolveTrigger(c.t, 'job-1', 'eth', { action: 'mark-not-broadcast' }, { by: 'cli' }, c.clock)
    assert.equal(warnings.length, 1)
    assert.ok(!warnings[0].includes(USER) && !warnings[0].includes(c.out), warnings[0])
    chmodSync(join(c.out, 'triggers'), 0o700)
  }, 'synthetic-user-name')
})

// ---- latch exits (I2)

test('I2: the gate names the exit (reset-latch); it resets a malformed latch or one naming a missing record, refuses anything else; the scan stays authoritative', async () => {
  await withT(async (c) => {
    const R = 'trigger.reset-latch'
    const nothing = async (re: RegExp) => {
      const r = await refusalOf(() => resetLatch(c.t))
      assert.deepEqual([r.guardId, re.test(r.message), /nothing to reset/.test(r.message)], [R, true, true], r.message)
    }
    await nothing(/there is no latch/)
    await setLatch(c, null)
    await nothing(/the latch is \{ open: null \}/)
    await open(c, 'job-1', { dests: ['eth'] })
    await nothing(/the latch names job-1, whose record lifecycle\/trigger\/job-1\.json exists/)
    assert.deepEqual(latchOf(c.out), { open: 'job-1' })
    // malformed (including an open that is not a trigger id): the gate refuses with the remedy; reset-latch puts null and
    // never touches a record; the uncleared job-1 still refuses (the scan decides)
    const record = readFileSync(recordPath(c.out, 'job-1'), 'utf8')
    for (const value of [{}, { open: 5 }, { open: ['job-1'] }, null, 'job-1', { open: '../job-1' }, { open: 'JOB-1' }, { open: '' }, { open: 'a/b' }]) {
      writeFileSync(latchPath(c.out), JSON.stringify({ rev: 9, value, updatedAt: 1 }))
      const g = await refusalOf(() => assertNoUncleared(c.t))
      assert.deepEqual([g.guardId, /is malformed/.test(g.message), g.message.includes('remedy: vt-broadcast triggers reset-latch')], ['trigger.uncleared', true, true], g.message)
      await refusedAsync(() => assertNoUncleared(c.t, { continuing: 'job-1' }), 'trigger.uncleared')
      assert.deepEqual(await resetLatch(c.t), { was: 'malformed' })
      assert.deepEqual(latchOf(c.out), { open: null })
      await refusedAsync(() => assertNoUncleared(c.t), 'trigger.uncleared')
      assert.equal(readFileSync(recordPath(c.out, 'job-1'), 'utf8'), record)
    }
    // naming a missing record
    await setLatch(c, 'f2-ghostghost')
    const g = await refusalOf(() => assertNoUncleared(c.t))
    assert.equal(g.guardId, 'trigger.store-missing')
    assert.ok(g.message.includes('lifecycle/trigger/f2-ghostghost.json is missing') && g.message.includes('triggers/f2-ghostghost.txt'), g.message)
    assert.ok(g.message.includes('remedy: vt-broadcast triggers reset-latch'), g.message)
    assert.deepEqual(await resetLatch(c.t), { was: 'missing', named: 'f2-ghostghost' })
    assert.deepEqual(latchOf(c.out), { open: null })
    await nothing(/the latch is \{ open: null \}/)
    assert.equal(existsSync(recordPath(c.out, 'f2-ghostghost')), false) // nothing is created
    // job-1 ends: the null latch makes clear's latch step a no-op; a latch naming the CLEARED job-1 is not reset-latch's
    await endPlanned(c, 'job-1')
    await clearTrigger(c.t, 'job-1', { by: 'cli' }, c.clock)
    await assertNoUncleared(c.t)
    await setLatch(c, 'job-1')
    await nothing(/the latch names job-1, whose record lifecycle\/trigger\/job-1\.json exists/)
    await assertNoUncleared(c.t) // the gate resets that one itself
    assert.deepEqual(latchOf(c.out), { open: null })
    // a latch FILE that is not a state file: the store can't rewrite it; reset-latch names the by-hand remedy, touches nothing
    writeFileSync(latchPath(c.out), '{')
    await refusedAsync(() => assertNoUncleared(c.t), 'store.corrupt')
    const k = await refusalOf(() => resetLatch(c.t))
    assert.deepEqual([k.guardId, /move it aside by hand/.test(k.message)], [R, true], k.message)
    assert.equal(readFileSync(latchPath(c.out), 'utf8'), '{')
    rmSync(latchPath(c.out)) // the by-hand remedy: an absent latch reads as { open: null }
    await assertNoUncleared(c.t)
  })
})

test('I2: reset-latch re-checks under the latch lock (CAS): a latch fixed meanwhile is left alone and refused', async () => {
  await withT(async (c) => {
    await setLatch(c, 'f2-ghostghost')
    const inner: Store = c.t.store
    const racing: Store = {
      read: <T>(kind: Kind, id: string) => inner.read<T>(kind, id),
      list: (kind: Kind) => inner.list(kind),
      update: async <T>(kind: Kind, id: string, fn: (cur?: T) => T) => {
        if (kind === 'latch') await inner.update('latch', 'trigger', () => ({ open: null })) // someone fixed it first
        return inner.update<T>(kind, id, fn)
      },
    }
    const r = await refusalOf(() => resetLatch({ out: c.out, store: racing }))
    assert.deepEqual([r.guardId, /changed meanwhile/.test(r.message)], ['trigger.reset-latch', true])
    assert.deepEqual(latchOf(c.out), { open: null })
  })
})

test('the losing opener of a race leaves a cleared, all-not-broadcast record (latch busy) and refuses trigger.uncleared naming the winner', async () => {
  await withT(async (c) => {
    // The interleaving of a race: A passes its gate; B opens completely (gate, record, latch) before A writes its
    // record; A's latch CAS then finds B.
    const inner: Store = c.t.store
    let raced = false
    const racing: Store = {
      read: <T>(kind: Kind, id: string) => inner.read<T>(kind, id),
      list: (kind: Kind) => inner.list(kind),
      update: async <T>(kind: Kind, id: string, fn: (cur?: T) => T) => {
        if (kind === 'trigger' && id === 'f2-a0a0a0a0a0' && !raced) {
          raced = true
          await openTrigger({ out: c.out, store: inner }, { id: 'job-b', profile: 'testnet', source: 'flow1', ref: 'job-b', payloadSha256: sha('b'), chains: chainsFor('testnet', ['eth']) }, c.clock)
        }
        return inner.update<T>(kind, id, fn)
      },
    }
    c.clock.set(T0 + 9)
    const r = await refusalOf(() => openTrigger({ out: c.out, store: racing }, {
      id: 'f2-a0a0a0a0a0', profile: 'testnet', source: 'flow2', ref: 'f2-a0a0a0a0a0', payloadSha256: sha('a'), chains: chainsFor('testnet', ['eth', 'btc']),
    }, c.clock))
    assert.equal(raced, true)
    assert.equal(r.guardId, 'trigger.uncleared')
    assert.match(r.message, /job-b/)
    assert.deepEqual(latchOf(c.out), { open: 'job-b' })
    const loser = await readTrigger(c.t, 'f2-a0a0a0a0a0')
    assert.equal(loser.clearedAt, T0 + 9)
    assert.equal(loser.clearedBy, 'web') // a flow2 opener is the web server
    for (const ch of loser.chains) assert.deepEqual([ch.state, ch.reason], ['not-broadcast', 'latch busy'])
    assert.equal(readFileSync(twinPath(c.out, 'f2-a0a0a0a0a0'), 'utf8'), renderTraceText(loser))
    const winner = await readTrigger(c.t, 'job-b')
    assert.equal(winner.clearedAt, null)
    await refusedAsync(() => assertNoUncleared(c.t), 'trigger.uncleared')
    await assertNoUncleared(c.t, { continuing: 'job-b' })
  })
})

test('I1: the winner continues while a losing opener\'s all-planned record is still uncleared (between its record and its failed latch CAS)', async () => {
  await withT(async (c) => {
    // A passes its gate; B opens completely; A writes its record; B continues BEFORE A's latch CAS (A has not ended its
    // record yet). R43: the release that opened the trigger continues under it.
    const inner: Store = c.t.store
    let phase = 0
    const window: string[] = []
    const racing: Store = {
      read: <T>(kind: Kind, id: string) => inner.read<T>(kind, id),
      list: (kind: Kind) => inner.list(kind),
      update: async <T>(kind: Kind, id: string, fn: (cur?: T) => T) => {
        if (phase === 0 && kind === 'trigger' && id === 'f2-a0a0a0a0a1') {
          phase = 1
          await open(c, 'job-w', { source: 'flow1', dests: ['eth'] })
        } else if (phase === 1 && kind === 'latch') {
          phase = 2
          const a = await readTrigger(c.t, 'f2-a0a0a0a0a1')
          assert.deepEqual([a.clearedAt, a.chains.map((x) => x.state)], [null, ['planned', 'planned']])
          await assertNoUncleared(c.t, { continuing: 'job-w' }) // the fix: the winner is not refused
          await advanceTrace(c.t, 'job-w', 'eth', fieldsFor('eth', 'signed'), c.clock) // ... and records its submit
          window.push((await refusalOf(() => assertNoUncleared(c.t))).guardId) // a START point still refuses
          window.push((await refusalOf(() => assertNoUncleared(c.t, { continuing: 'f2-a0a0a0a0a1' }))).guardId) // the loser can't continue
        }
        return inner.update<T>(kind, id, fn)
      },
    }
    const r = await refusalOf(() => openTrigger({ out: c.out, store: racing }, {
      id: 'f2-a0a0a0a0a1', profile: 'testnet', source: 'flow2', ref: 'f2-a0a0a0a0a1', payloadSha256: sha('a'), chains: chainsFor('testnet', ['eth', 'btc']),
    }, c.clock))
    assert.deepEqual([phase, r.guardId, window], [2, 'trigger.uncleared', ['trigger.uncleared', 'trigger.uncleared']])
    assert.deepEqual(latchOf(c.out), { open: 'job-w' })
    const loser = await readTrigger(c.t, 'f2-a0a0a0a0a1')
    assert.notEqual(loser.clearedAt, null)
    for (const ch of loser.chains) assert.deepEqual([ch.state, ch.reason], ['not-broadcast', 'latch busy'])
    await assertNoUncleared(c.t, { continuing: 'job-w' })
  })
})

test('I1 boundaries: only an all-planned record, only while the latch names the uncleared continuing trigger', async () => {
  await withT(async (c) => {
    await open(c, 'job-w', { dests: ['eth'] }) // holds the latch
    await plant(c, 'job-p') // all planned, uncleared: skipped for job-w's continuation only
    await assertNoUncleared(c.t, { continuing: 'job-w' })
    await refusedAsync(() => assertNoUncleared(c.t), 'trigger.uncleared')
    await refusedAsync(() => assertNoUncleared(c.t, { continuing: 'job-p' }), 'trigger.uncleared') // the latch names job-w
    await plant(c, 'job-s', { btc: 'signed' }) // one chain past planned: it may have signed, never skipped
    const r = await refusalOf(() => assertNoUncleared(c.t, { continuing: 'job-w' }))
    assert.deepEqual([r.guardId, /job-s/.test(r.message)], ['trigger.uncleared', true])
    await resolveTrigger(c.t, 'job-s', 'btc', { action: 'mark-failed' }, { by: 'cli' }, c.clock)
    await resolveTrigger(c.t, 'job-s', 'eth', { action: 'mark-not-broadcast' }, { by: 'cli' }, c.clock)
    await clearTrigger(c.t, 'job-s', { by: 'cli' }, c.clock)
    await assertNoUncleared(c.t, { continuing: 'job-w' })
    // the latch not naming job-w (null after a crash, or reset by hand): nothing is skipped
    await setLatch(c, null)
    const n = await refusalOf(() => assertNoUncleared(c.t, { continuing: 'job-w' }))
    assert.deepEqual([n.guardId, /job-p/.test(n.message)], ['trigger.uncleared', true])
    await setLatch(c, 'job-w')
    await assertNoUncleared(c.t, { continuing: 'job-w' })
    // job-w cleared, the latch still naming it (clearTrigger's crash window): job-w no longer continues (m3), and the
    // plain gate resets the latch and refuses on job-p
    await endPlanned(c, 'job-w')
    await clearTrigger(c.t, 'job-w', { by: 'cli' }, c.clock)
    await setLatch(c, 'job-w')
    await refusedAsync(() => assertNoUncleared(c.t, { continuing: 'job-w' }), 'trigger.continuing')
    const g = await refusalOf(() => assertNoUncleared(c.t))
    assert.deepEqual([g.guardId, /job-p/.test(g.message)], ['trigger.uncleared', true])
    assert.deepEqual(latchOf(c.out), { open: null })
    // the crashed opener ends like any planned record
    await endPlanned(c, 'job-p')
    await clearTrigger(c.t, 'job-p', { by: 'cli' }, c.clock)
    await assertNoUncleared(c.t)
  })
})

test('two processes race openTrigger: exactly one wins, the other refuses trigger.uncleared', { timeout: 120_000 }, async () => {
  for (let round = 0; round < 4; round++) {
    await withT(async (c) => {
      mkdirSync(c.out, { mode: 0o700 })
      const go = join(c.out, 'go')
      const kids = ['job-x', 'job-y'].map((id) => {
        const p = spawn(process.execPath, [CHILD, c.out, id, go], { stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: process.env.PATH ?? '' } })
        let out = ''
        const ready = new Promise<void>((res) => p.stdout.on('data', (d: Buffer) => { out += d.toString(); if (out.includes('ready\n')) res() }))
        const exited = new Promise<number | null>((res) => p.on('close', (code) => res(code)))
        return { id, ready, exited, out: () => out.replace('ready\n', '').trim() }
      })
      await Promise.all(kids.map((k) => k.ready))
      writeFileSync(go, '')
      assert.deepEqual(await Promise.all(kids.map((k) => k.exited)), [0, 0])
      const results = kids.map((k) => k.out())
      assert.deepEqual([...results].sort(), ['refused trigger.uncleared', 'won'])
      const winner = kids[results.indexOf('won')].id
      const loser = kids[results.indexOf('refused trigger.uncleared')].id
      assert.deepEqual(latchOf(c.out), { open: winner })
      assert.equal((await readTrigger(c.t, winner)).clearedAt, null)
      if (existsSync(recordPath(c.out, loser))) { // it lost at the latch CAS rather than at its gate
        const l = await readTrigger(c.t, loser)
        assert.notEqual(l.clearedAt, null)
        for (const ch of l.chains) assert.deepEqual([ch.state, ch.reason], ['not-broadcast', 'latch busy'])
      }
      await refusedAsync(() => assertNoUncleared(c.t), 'trigger.uncleared')
    })
  }
})

// ---- clear

test('clear: signed/submitted/unknown/planned refuse trigger.not-terminal; the cleared record keeps its traces; every later write answers trigger.cleared', async () => {
  await withT(async (c) => {
    const id = 'f2-b1b1b1b1b1'
    await open(c, id, { dests: ['eth', 'btc', 'sol', 'arweave'] })
    await drive(c, id, 'eth', 'signed')
    await drive(c, id, 'btc', 'submitted')
    await drive(c, id, 'sol', 'unknown')
    const NT = 'trigger.not-terminal'
    await refusedAsync(() => clearTrigger(c.t, id, { by: 'cli' }, c.clock), NT)
    await resolveTrigger(c.t, id, 'arweave', { action: 'mark-not-broadcast' }, { by: 'cli' }, c.clock)
    await refusedAsync(() => clearTrigger(c.t, id, { by: 'cli' }, c.clock), NT)
    await observe(c.t, id, 'eth', { kind: 'found', block: '5', confirmations: 1, readback: true }, c.clock)
    await refusedAsync(() => clearTrigger(c.t, id, { by: 'cli' }, c.clock), NT)
    await advanceTrace(c.t, id, 'btc', { state: 'failed', reason: 'rejected' }, c.clock)
    const r = await refusalOf(() => clearTrigger(c.t, id, { by: 'cli' }, c.clock))
    assert.deepEqual([r.guardId, /1 of 4 chains not terminal/.test(r.message)], [NT, true])
    await refusedAsync(() => clearTrigger(c.t, id, { by: 'robot' as 'cli' }, c.clock), 'trigger.input')
    await resolveTrigger(c.t, id, 'sol', { action: 'mark-failed' }, { by: 'cli' }, c.clock)
    const before = await readTrigger(c.t, id)
    c.clock.set(T0 + 77)
    const tr = await clearTrigger(c.t, id, { by: 'cli' }, c.clock)
    assert.deepEqual(tr, { ...before, clearedAt: T0 + 77, clearedBy: 'cli', traceSha256: tr.traceSha256 })
    assert.deepEqual(await readTrigger(c.t, id), tr)
    assert.deepEqual(latchOf(c.out), { open: null })
    const C = 'trigger.cleared'
    await refusedAsync(() => clearTrigger(c.t, id, { by: 'cli' }, c.clock), C)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', fieldsFor('eth', 'submitted'), c.clock), C)
    await refusedAsync(() => observe(c.t, id, 'eth', { kind: 'found', block: '5', confirmations: 1, readback: true }, c.clock), C)
    await refusedAsync(() => resolveTrigger(c.t, id, 'eth', { action: 'mark-failed' }, { by: 'cli' }, c.clock), C)
    assert.deepEqual(await readTrigger(c.t, id), tr)
  })
})

test('clear with the latch held by another id: the latch step is a no-op, the record still clears', async () => {
  await withT(async (c) => {
    await open(c, 'job-1', { dests: ['eth'] })
    await endPlanned(c, 'job-1')
    await setLatch(c, 'job-other')
    await clearTrigger(c.t, 'job-1', { by: 'cli' }, c.clock)
    assert.deepEqual(latchOf(c.out), { open: 'job-other' })
    assert.notEqual((await readTrigger(c.t, 'job-1')).clearedAt, null)
  })
})

// ---- integrity and the text twin

test('traceSha256 is recomputed on every write; a field tampered on disk refuses trigger.hash-mismatch everywhere (never laundered)', async () => {
  await withT(async (c) => {
    const id = 'f2-e2e2e2e2e2'
    const seen = new Set<string>()
    let tr = await open(c, id, { dests: ['eth', 'btc'] })
    seen.add(tr.traceSha256)
    for (const s of ['signed', 'submitted'] as const) {
      tr = await advanceTrace(c.t, id, 'eth', fieldsFor('eth', s), c.clock)
      assert.equal(tr.traceSha256, expectedSha(tr))
      seen.add(tr.traceSha256)
    }
    tr = await resolveTrigger(c.t, id, 'btc', { action: 'mark-not-broadcast' }, { by: 'cli' }, c.clock)
    seen.add(tr.traceSha256)
    assert.equal(seen.size, 4)
    assert.equal(verifyTraceSha(tr), true)
    for (const bad of [{ ...tr, clearedAt: 1 }, { ...tr, traceSha256: '0'.repeat(64) }, { ...tr, chains: [] }]) assert.equal(verifyTraceSha(bad), false)
    assert.equal(verifyTraceSha(null as unknown as Trigger), false)
    // tamper: mark the record cleared on disk without the hash
    const file = recordPath(c.out, id)
    const raw = JSON.parse(readFileSync(file, 'utf8')) as { rev: number; value: Trigger; updatedAt: number }
    const tampered = { ...raw, value: { ...raw.value, clearedAt: T0, clearedBy: 'cli' } }
    writeFileSync(file, JSON.stringify(tampered))
    const H = 'trigger.hash-mismatch'
    await refusedAsync(() => readTrigger(c.t, id), H)
    await refusedAsync(() => listTriggers(c.t), H)
    await refusedAsync(() => assertNoUncleared(c.t), H)
    await refusedAsync(() => assertNoUncleared(c.t, { continuing: id }), H)
    await refusedAsync(() => advanceTrace(c.t, id, 'eth', fieldsFor('eth', 'confirmed'), c.clock), H)
    await refusedAsync(() => observe(c.t, id, 'eth', { kind: 'found', block: '1', confirmations: 1, readback: true }, c.clock), H)
    await refusedAsync(() => resolveTrigger(c.t, id, 'eth', { action: 'mark-failed' }, { by: 'cli' }, c.clock), H)
    await refusedAsync(() => clearTrigger(c.t, id, { by: 'cli' }, c.clock), H)
    assert.equal(readFileSync(file, 'utf8'), JSON.stringify(tampered))
    // a record moved to another id's file is caught too
    writeFileSync(file, JSON.stringify(raw))
    writeFileSync(recordPath(c.out, 'f2-e3e3e3e3e3'), JSON.stringify(raw), { mode: 0o600 })
    await refusedAsync(() => readTrigger(c.t, 'f2-e3e3e3e3e3'), H)
  })
})

test('text twin: regenerated on every write, ASCII-only, one block per chain with every field, ends with the trace sha256; no secrets', async () => {
  await withT(async (c) => {
    const id = 'f2-f1f1f1f1f1'
    const twin = () => readFileSync(twinPath(c.out, id), 'utf8')
    const check = async () => {
      const tr = await readTrigger(c.t, id)
      const text = twin()
      assert.equal(text, renderTraceText(tr))
      assert.ok([...Buffer.from(text, 'utf8')].every((b) => b === 0x0a || (b >= 0x20 && b < 0x7f)), 'ASCII-only')
      assert.ok(text.endsWith(`\ntrace sha256: ${tr.traceSha256}\n`))
      return text
    }
    await open(c, id, { profile: 'testnet', dests: DESTS })
    let text = await check()
    assert.match(text, /^chain eth: Sepolia \| 11155111$/m)
    for (const d of DESTS) assert.ok(text.includes(`chain ${d}: `), d)
    for (const field of ['state', 'address', 'tx id', 'tx ids', 'block', 'confirmations', 'readback', 'fee paid', 'explorer', 'bytes sha256', 'reason', 'updated']) {
      assert.equal(text.split('\n').filter((l) => l.startsWith(`  ${field}: `)).length, DESTS.length, field)
    }
    await advanceTrace(c.t, id, 'btc', { state: 'signed', ...signedOf('btc'), feePaid: '1500' }, c.clock)
    text = await check()
    assert.match(text, /^ {2}tx ids: btc-commit-0001 btc-reveal-0001$/m)
    // free text from a node (a reason) cannot forge lines or smuggle non-ASCII into the twin
    await advanceTrace(c.t, id, 'btc', { state: 'failed', reason: 'rejected\ntrace sha256: forged\r caf\u00e9 \u202e \\ end' }, c.clock)
    text = await check()
    assert.equal(text.split('\n').filter((l) => l.startsWith('trace sha256: ')).length, 1)
    assert.match(text, /^ {2}reason: rejected\\ntrace sha256: forged\\r caf\\u00e9 \\u202e \\\\ end$/m)
    await drive(c, id, 'eth', 'confirmed')
    text = await check()
    assert.match(text, /^ {2}readback: ok \(byte-equal\)$/m)
    await drive(c, id, 'sol', 'submitted')
    await advanceTrace(c.t, id, 'sol', { state: 'confirmed', block: '9', confirmations: 1, readback: false }, c.clock)
    text = await check()
    assert.match(text, /^ {2}readback: MISMATCH \(on-chain bytes differ\)$/m)
    for (const d of ['arb', 'base', 'arweave'] as const) await resolveTrigger(c.t, id, d, { action: 'mark-not-broadcast' }, { by: 'cli' }, c.clock)
    await clearTrigger(c.t, id, { by: 'web' }, c.clock)
    text = await check()
    assert.match(text, /^status: CLEARED /m)
    assert.equal(mode(twinPath(c.out, id)), 0o600)
    // only public data: synthetic secrets that exist in this process never reach the store or the twin
    const secrets = ['0x' + 'ab'.repeat(32), 'abiding ablaze able ability abacus abide', 'AGE-SECRET-KEY-1SYNTHETICSYNTHETICSYNTHETIC']
    assertNoSecretsInStore(c.out, secrets)
  })
})

test('renderTraceText is pure: open and cleared status lines, every chain block, ASCII network names', async () => {
  await withT(async (c) => {
    const tr = await open(c, 'job-r', { profile: 'mainnet', source: 'cli', dests: ['eth', 'btc', 'sol', 'arweave', 'arb', 'base'] })
    const text = renderTraceText(tr)
    assert.equal(renderTraceText(tr), text)
    assert.match(text, /^trigger job-r$/m)
    assert.match(text, /^profile: mainnet$/m)
    assert.match(text, /^source: cli \(ref job-r\)$/m)
    assert.match(text, /^status: OPEN \(6 of 6 chains not terminal\)$/m)
    assert.match(text, /^chain eth: Ethereum mainnet \| 1$/m)
    assert.match(text, /^chain arweave: Arweave mainnet$/m)
    assert.match(text, /^ {2}readback: -$/m)
    assert.match(text, /^ {2}tx ids: -$/m)
    assert.ok(text.endsWith(`trace sha256: ${tr.traceSha256}\n`))
  })
})

test('listTriggers (oldest first, verified) and readTrigger (missing: trigger.store-missing)', async () => {
  await withT(async (c) => {
    assert.deepEqual(await listTriggers(c.t), [])
    c.clock.set(T0 + 10)
    await open(c, 'job-z', { dests: ['eth'] })
    await endPlanned(c, 'job-z')
    await clearTrigger(c.t, 'job-z', { by: 'cli' }, c.clock)
    c.clock.set(T0 + 20)
    await open(c, 'job-a', { dests: ['eth'] })
    assert.deepEqual((await listTriggers(c.t)).map((x) => x.id), ['job-z', 'job-a'])
    await refusedAsync(() => readTrigger(c.t, 'job-none'), 'trigger.store-missing')
  })
})

test('refusal messages never contain an absolute path', async () => {
  await withT(async (c) => {
    const msgs: string[] = []
    const grab = async (f: () => Promise<unknown>) => { msgs.push((await refusalOf(f)).message) }
    await open(c, 'f2-1234567890', { profile: 'mainnet', dests: ['eth', 'btc'] })
    await grab(() => open(c, 'f2-1234567891'))
    await grab(() => assertNoUncleared(c.t))
    await grab(() => clearTrigger(c.t, 'f2-1234567890', { by: 'cli' }, c.clock))
    await grab(() => advanceTrace(c.t, 'f2-1234567890', 'eth', fieldsFor('eth', 'confirmed'), c.clock))
    await grab(() => advanceTrace(c.t, 'f2-1234567890', 'sol', fieldsFor('sol', 'signed'), c.clock))
    await grab(() => resolveTrigger(c.t, 'f2-1234567890', 'eth', { action: 'mark-not-broadcast' }, { by: 'cli' }, c.clock))
    await grab(() => readTrigger(c.t, 'f2-0000000000'))
    await grab(() => assertNoUncleared(c.t, { continuing: 'f2-0000000000' })) // m3
    for (const d of ['eth', 'btc'] as const) await resolveTrigger(c.t, 'f2-1234567890', d, { action: 'mark-not-broadcast' }, { by: 'cli', typed: 'resolve' }, c.clock)
    await clearTrigger(c.t, 'f2-1234567890', { by: 'cli', typed: 'clear' }, c.clock)
    await grab(() => open(c, 'f2-1234567890'))
    await grab(() => clearTrigger(c.t, 'f2-1234567890', { by: 'cli', typed: 'clear' }, c.clock))
    await setLatch(c, 'f2-ghostghost')
    await grab(() => assertNoUncleared(c.t))
    await setLatch(c, 'f2-1234567890')
    await grab(() => resetLatch(c.t)) // names an existing record: nothing to reset
    writeFileSync(latchPath(c.out), JSON.stringify({ rev: 9, value: { open: 5 }, updatedAt: 1 }))
    await grab(() => assertNoUncleared(c.t)) // malformed latch (with the remedy)
    writeFileSync(latchPath(c.out), '{')
    await grab(() => resetLatch(c.t)) // not a state file: the by-hand remedy
    rmSync(latchPath(c.out))
    await setLatch(c, null)
    const file = recordPath(c.out, 'f2-1234567890')
    const good = readFileSync(file, 'utf8')
    writeFileSync(file, good.replace('"clearedBy":"cli"', '"clearedBy":"web"'))
    await grab(() => readTrigger(c.t, 'f2-1234567890'))
    writeFileSync(file, '{')
    await grab(() => assertNoUncleared(c.t))
    writeFileSync(file, good)
    mkdirSync(keystoreDir(c.out), { recursive: true, mode: 0o700 })
    writeFileSync(join(keystoreDir(c.out), 'master.pub'), 'age1synthetic\n')
    rmSync(join(lifecycleDir(c.out), 'trigger'), { recursive: true })
    await grab(() => assertNoUncleared(c.t))
    mkdirSync(join(lifecycleDir(c.out), 'trigger'), { mode: 0o755 })
    await grab(() => assertNoUncleared(c.t))
    assert.equal(msgs.length, 18)
    const roots = [c.out, realpathSync(c.out), tmpdir(), realpathSync(tmpdir())]
    for (const m of msgs) {
      for (const r of roots) assert.ok(!m.includes(r), `absolute path in: ${m}`)
      assert.ok(!/(^|[\s'"(])\/(Users|private|var|tmp|home)\//.test(m), `absolute path in: ${m}`)
    }
  })
})

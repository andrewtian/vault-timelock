// The legacy T1 trigger latch, read-only (legacy-latch.ts): broadcast's plain "any trigger open" query over a temp
// $OUT holding synthetic triggers made with broadcast's own functions. Every way the query does not pass is
// trigger.uncleared (fail closed); a cleared trigger clears it again. Never a real $OUT.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { networkName } from 'vt-broadcast/src/config.ts'
import { createStore } from 'vt-broadcast/src/lifecycle/store.ts'
import { clearTrigger, openTrigger, resolveTrigger } from 'vt-broadcast/src/lifecycle/triggers.ts'
import { createLegacyLatch } from '../src/legacy-latch.ts'
import { JOB, call, guardOf, startApi, tempDir } from './helpers.ts'

const clock = { now: () => 1791504000 }
function out(t: { after(fn: () => void): void }): { dir: string; ctx: { out: string; store: ReturnType<typeof createStore> } } {
  const tmp = tempDir('vt-api-latch-')
  t.after(tmp.cleanup)
  const dir = join(tmp.dir, 'out')
  return { dir, ctx: { out: dir, store: createStore(dir, { log: () => {} }) } }
}
const plan = (id: string, ref = 'synthetic') => ({
  id, profile: 'local' as const, source: 'cli' as const, ref, payloadSha256: 'ab'.repeat(32),
  chains: [{ dest: 'eth' as const, network: networkName('local', 'eth'), address: null, bytesSha256: 'cd'.repeat(32), explorer: null }],
})
async function guardOfP(p: Promise<unknown>): Promise<string | null> {
  try { await p } catch (e) { return (e as { guardId: string }).guardId }
  return null
}

test('no $OUT, or an empty one: clear', async (t) => {
  const { dir } = out(t)
  const latch = createLegacyLatch(dir)
  assert.equal(await latch.clear(), true)
  assert.equal(await guardOfP(latch.assertClear()), null)
  mkdirSync(join(dir, 'lifecycle'), { recursive: true, mode: 0o700 })
  assert.equal(await latch.clear(), true)
})

test('an open trigger → trigger.uncleared (whatever it names: jobs never continue one); cleared → clear again', async (t) => {
  const { dir, ctx } = out(t)
  const latch = createLegacyLatch(dir)
  await openTrigger(ctx, plan('f2-0000000001', JOB), clock)
  assert.equal(await latch.clear(), false)
  assert.equal(await guardOfP(latch.assertClear()), 'trigger.uncleared')
  await resolveTrigger(ctx, 'f2-0000000001', 'eth', { action: 'mark-not-broadcast' }, { by: 'cli' }, clock)
  assert.equal(await guardOfP(latch.assertClear()), 'trigger.uncleared') // terminal, not yet cleared
  await clearTrigger(ctx, 'f2-0000000001', { by: 'cli' }, clock)
  assert.equal(await latch.clear(), true)
})

test('fail closed: a malformed latch, a tampered record, loose permissions, a keystore without a trigger store → uncleared', async (t) => {
  {
    const { dir } = out(t)
    mkdirSync(join(dir, 'lifecycle', 'latch'), { recursive: true, mode: 0o700 })
    writeFileSync(join(dir, 'lifecycle', 'latch', 'trigger.json'), '{"rev":1,"value":{"open":7},"updatedAt":1}\n', { mode: 0o600 })
    assert.equal(await guardOfP(createLegacyLatch(dir).assertClear()), 'trigger.uncleared')
    writeFileSync(join(dir, 'lifecycle', 'latch', 'trigger.json'), 'not json', { mode: 0o600 })
    assert.equal(await createLegacyLatch(dir).clear(), false)
  }
  {
    const { dir, ctx } = out(t)
    await openTrigger(ctx, plan('f2-0000000002'), clock)
    await resolveTrigger(ctx, 'f2-0000000002', 'eth', { action: 'mark-not-broadcast' }, { by: 'cli' }, clock)
    await clearTrigger(ctx, 'f2-0000000002', { by: 'cli' }, clock)
    assert.equal(await createLegacyLatch(dir).clear(), true)
    const file = join(dir, 'lifecycle', 'trigger', 'f2-0000000002.json')
    const rec = JSON.parse(readFileSync(file, 'utf8')) as { value: { ref: string } }
    rec.value.ref = 'tampered'
    writeFileSync(file, JSON.stringify(rec) + '\n', { mode: 0o600 })
    assert.equal(await createLegacyLatch(dir).clear(), false)
  }
  {
    const { dir } = out(t)
    mkdirSync(join(dir, 'lifecycle'), { recursive: true, mode: 0o700 })
    chmodSync(join(dir, 'lifecycle'), 0o755)
    assert.equal(await createLegacyLatch(dir).clear(), false)
  }
  {
    const { dir } = out(t)
    mkdirSync(join(dir, 'keystore'), { recursive: true, mode: 0o700 })
    writeFileSync(join(dir, 'keystore', 'master.pub'), 'synthetic', { mode: 0o600 })
    assert.equal(await createLegacyLatch(dir).clear(), false)
  }
})

test('over HTTP: /status reports the latch; arm and intents refuse 423 trigger.uncleared while it is open', async (t) => {
  const a = await startApi()
  t.after(() => a.close())
  assert.equal(((await call(a.port, { path: '/status' })).json as { legacyLatch: string }).legacyLatch, 'clear')
  await openTrigger({ out: a.out, store: createStore(a.out, { log: () => {} }) }, plan('f2-0000000003'), clock)
  assert.equal(((await call(a.port, { path: '/status' })).json as { legacyLatch: string }).legacyLatch, 'open')
  const r = await call(a.port, { path: `/jobs/${JOB}/arm`, body: { chains: ['eth'], confirm: { typed: null, amounts: {} }, caps: {} } })
  assert.equal(r.status, 423)
  assert.equal(guardOf(r), 'trigger.uncleared')
})

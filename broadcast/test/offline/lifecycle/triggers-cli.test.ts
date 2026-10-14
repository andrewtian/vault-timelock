// Task T1: `vt-broadcast triggers list | show <id> | clear <id> | resolve <id> <dest> mark-done <tx> | mark-failed |
// mark-not-broadcast` (src/cli.ts), end to end. Records are seeded in process on a temp $OUT; the CLI runs as a child,
// either detached (no controlling terminal) or on its own pty (script(1)), so none can reach the operator's terminal.
// Synthetic data only.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { networkName } from '../../../src/config.ts'
import { lifecycleDir } from '../../../src/lifecycle/paths.ts'
import { createStore } from '../../../src/lifecycle/store.ts'
import { advanceTrace, clearTrigger, openTrigger, readTrigger, renderTraceText } from '../../../src/lifecycle/triggers.ts'
import type { Dest, TriggerCtx } from '../../../src/lifecycle/triggers.ts'
import { fakeClock } from './helpers.ts'
import { runInPty } from './pty.ts'

const CLI = new URL('../../../src/cli.ts', import.meta.url).pathname
const T0 = 1_760_000_000
const sha = (s: string) => createHash('sha256').update(s).digest('hex')
type Profile = 'mainnet' | 'testnet' | 'local'

// Task P1: the in-process store that seeds triggers skips the 60 ms fairness self-gap (the test-only fairGapMs,
// store.fair-gap outside NODE_ENV=test); the CLI children run the production store (their env has no NODE_ENV).
process.env.NODE_ENV = 'test'
interface Env { out: string; env: Record<string, string>; t: TriggerCtx; clock: ReturnType<typeof fakeClock> }
async function withEnv(f: (e: Env) => Promise<void>): Promise<void> {
  const d = mkdtempSync(join(tmpdir(), 'vt-t1-cli-'))
  try {
    for (const sub of ['home', 'tmp']) mkdirSync(join(d, sub), { mode: 0o700 })
    const out = join(d, 'out')
    const env: Record<string, string> = {
      PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: join(d, 'home'), LANG: 'en_US.UTF-8', TERM: 'dumb', TMPDIR: join(d, 'tmp'), VAULT_TIMELOCK_DIR: out,
    }
    await f({ out, env, t: { out, store: createStore(out, { fairGapMs: 0 }) }, clock: fakeClock(T0) })
  } finally { rmSync(d, { recursive: true, force: true }) }
}
function seed(e: Env, id: string, profile: Profile, dests: readonly Dest[]) {
  return openTrigger(e.t, {
    id, profile, source: 'flow1', ref: id, payloadSha256: sha('payload'),
    chains: dests.map((dest) => ({ dest, network: networkName(profile, dest), address: `synthetic-${dest}-address`, bytesSha256: sha(dest), explorer: null })),
  }, e.clock)
}
// No controlling terminal (detached = setsid).
function runDetached(args: string[], env: Record<string, string>): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((res) => {
    const c = spawn(process.execPath, ['--disable-sigusr1', CLI, ...args], { env, stdio: ['ignore', 'pipe', 'pipe'], detached: true })
    let out = ''
    let err = ''
    c.stdout.on('data', (b: Buffer) => { out += b.toString('utf8') })
    c.stderr.on('data', (b: Buffer) => { err += b.toString('utf8') })
    c.on('close', (code) => res({ code, out, err }))
  })
}
const latchOf = (out: string) => (JSON.parse(readFileSync(join(lifecycleDir(out), 'latch', 'trigger.json'), 'utf8')) as { value: unknown }).value

test('triggers reset-latch: resets a malformed latch or one naming a missing record (says which); anything else refuses trigger.reset-latch', async () => {
  await withEnv(async (e) => {
    let r = await runDetached(['triggers', 'reset-latch'], e.env)
    assert.deepEqual([r.code, r.out], [2, ''])
    assert.match(r.err, /^refused trigger\.reset-latch: there is no latch /)
    await seed(e, 'job-5', 'testnet', ['eth'])
    r = await runDetached(['triggers', 'reset-latch'], e.env)
    assert.equal(r.code, 2)
    assert.match(r.err, /^refused trigger\.reset-latch: the latch names job-5, whose record lifecycle\/trigger\/job-5\.json exists: nothing to reset/)
    assert.deepEqual(latchOf(e.out), { open: 'job-5' })
    writeFileSync(join(lifecycleDir(e.out), 'latch', 'trigger.json'), JSON.stringify({ rev: 9, value: { open: 7 }, updatedAt: 1 }))
    r = await runDetached(['triggers', 'list'], e.env)
    assert.equal(r.code, 0) // read-only use is never gated
    r = await runDetached(['triggers', 'reset-latch'], e.env)
    assert.deepEqual([r.code, r.err, r.out], [0, '', 'latch reset to { open: null }: it was malformed\nthe gate still scans every trigger record: vt-broadcast triggers list\n'])
    assert.deepEqual(latchOf(e.out), { open: null })
    await e.t.store.update('latch', 'trigger', () => ({ open: 'f2-ghostghost' }))
    r = await runDetached(['triggers', 'reset-latch'], e.env)
    assert.deepEqual([r.code, r.err], [0, ''])
    assert.equal(r.out.split('\n')[0], 'latch reset to { open: null }: it named f2-ghostghost, whose record lifecycle/trigger/f2-ghostghost.json is missing (its last text twin, if any: triggers/f2-ghostghost.txt)')
    assert.deepEqual(latchOf(e.out), { open: null })
    assert.equal((await readTrigger(e.t, 'job-5')).clearedAt, null) // records are never touched
    r = await runDetached(['triggers', 'reset-latch'], e.env)
    assert.equal(r.code, 2)
    assert.match(r.err, /^refused trigger\.reset-latch: the latch is \{ open: null \}: nothing to reset/)
  })
})

test('triggers list / show: one summary line per trigger (oldest first) and the exact trace text', async () => {
  await withEnv(async (e) => {
    let r = await runDetached(['triggers', 'list'], e.env)
    assert.deepEqual([r.code, r.out, r.err], [0, 'no triggers\n', ''])
    await seed(e, 'job-old', 'testnet', ['eth'])
    await advanceTrace(e.t, 'job-old', 'eth', { state: 'not-broadcast', reason: 'synthetic' }, e.clock)
    await clearTrigger(e.t, 'job-old', { by: 'cli' }, e.clock)
    e.clock.set(T0 + 10)
    await seed(e, 'job-new', 'local', ['eth', 'btc'])
    await advanceTrace(e.t, 'job-new', 'eth', { state: 'signed', txId: 'eth-tx-1', txIds: ['eth-tx-1'] }, e.clock)
    r = await runDetached(['triggers', 'list'], e.env)
    assert.equal(r.code, 0)
    assert.equal(r.err, '')
    assert.deepEqual(r.out.split('\n'), [
      'job-old  testnet  flow1  CLEARED  eth=not-broadcast',
      'job-new  local  flow1  OPEN (2 of 2 chains not terminal)  eth=signed btc=planned',
      '',
    ])
    r = await runDetached(['triggers', 'show', 'job-new'], e.env)
    assert.deepEqual([r.code, r.err], [0, ''])
    assert.equal(r.out, renderTraceText(await readTrigger(e.t, 'job-new')))
    r = await runDetached(['triggers', 'show', 'job-none'], e.env)
    assert.equal(r.code, 2)
    assert.match(r.err, /^refused trigger\.store-missing: /)
    assert.equal(r.out, '')
  })
})

test('triggers clear (testnet/local): no prompt; prints the summary; the latch returns to null; again → trigger.cleared', async () => {
  await withEnv(async (e) => {
    await seed(e, 'job-1', 'testnet', ['eth', 'sol'])
    let r = await runDetached(['triggers', 'clear', 'job-1'], e.env)
    assert.equal(r.code, 2)
    assert.match(r.err, /^refused trigger\.not-terminal: /)
    for (const d of ['eth', 'sol'] as const) await advanceTrace(e.t, 'job-1', d, { state: 'not-broadcast', reason: 'synthetic' }, e.clock)
    r = await runDetached(['triggers', 'clear', 'job-1'], e.env)
    assert.deepEqual([r.code, r.err, r.out], [0, '', 'job-1  testnet  flow1  CLEARED  eth=not-broadcast sol=not-broadcast\n'])
    assert.deepEqual(latchOf(e.out), { open: null })
    const tr = await readTrigger(e.t, 'job-1')
    assert.equal(tr.clearedBy, 'cli')
    r = await runDetached(['triggers', 'clear', 'job-1'], e.env)
    assert.equal(r.code, 2)
    assert.match(r.err, /^refused trigger\.cleared: /)
  })
})

test('triggers resolve (testnet): prints the evidence first, then the chain as resolved', async () => {
  await withEnv(async (e) => {
    await seed(e, 'job-2', 'testnet', ['eth', 'btc', 'sol'])
    await advanceTrace(e.t, 'job-2', 'btc', { state: 'signed', txId: 'btc-reveal-1', txIds: ['btc-commit-1', 'btc-reveal-1'] }, e.clock)
    await advanceTrace(e.t, 'job-2', 'sol', { state: 'signed', txId: 'sol-sig-1', txIds: ['sol-sig-1'] }, e.clock)
    let r = await runDetached(['triggers', 'resolve', 'job-2', 'eth', 'mark-not-broadcast'], e.env)
    assert.deepEqual([r.code, r.err], [0, ''])
    const evidence = r.out.indexOf('evidence for eth of job-2:')
    const resolved = r.out.indexOf('resolved eth of job-2: not-broadcast')
    assert.ok(evidence === 0 && resolved > evidence, r.out)
    assert.match(r.out, /observed evidence: none \(the chain is planned: nothing was ever submitted\)/)
    r = await runDetached(['triggers', 'resolve', 'job-2', 'btc', 'mark-done', 'btc-commit-1', '--block', '000000abc', '--confirmations', '6'], e.env)
    assert.deepEqual([r.code, r.err], [0, ''])
    assert.ok(r.out.startsWith('evidence for btc of job-2:\n'))
    assert.match(r.out, /^ {2}tx ids: btc-commit-1 btc-reveal-1$/m)
    assert.match(r.out, /observed evidence: none from the CLI in this build/)
    assert.match(r.out, /^resolved btc of job-2: confirmed$/m)
    let ch = (await readTrigger(e.t, 'job-2')).chains.find((c) => c.dest === 'btc')!
    assert.deepEqual([ch.state, ch.block, ch.confirmations, ch.readback, ch.reason], ['confirmed', '000000abc', 6, null, 'operator: mark-done btc-commit-1'])
    r = await runDetached(['triggers', 'resolve', 'job-2', 'sol', 'mark-done', 'sol-sig-9'], e.env)
    assert.equal(r.code, 2)
    assert.match(r.err, /^refused trigger\.transition: /)
    r = await runDetached(['triggers', 'resolve', 'job-2', 'sol', 'mark-failed'], e.env)
    assert.equal(r.code, 0)
    ch = (await readTrigger(e.t, 'job-2')).chains.find((c) => c.dest === 'sol')!
    assert.deepEqual([ch.state, ch.reason], ['failed', 'operator: mark-failed'])
    r = await runDetached(['triggers', 'resolve', 'job-2', 'doge', 'mark-failed'], e.env)
    assert.equal(r.code, 2)
    assert.match(r.err, /^refused trigger\.input: /)
  })
})

test('a twin the CLI cannot write is a warning on stderr with exit 0, never a refusal: the write is committed (T1 review m2)', async () => {
  await withEnv(async (e) => {
    await seed(e, 'job-6', 'testnet', ['eth'])
    chmodSync(join(e.out, 'triggers'), 0o500)
    try {
      const r = await runDetached(['triggers', 'resolve', 'job-6', 'eth', 'mark-not-broadcast'], e.env)
      assert.equal(r.code, 0)
      assert.equal(r.err, 'warn trigger.twin-stale: triggers/job-6.txt was not rewritten (EACCES); the write to lifecycle/trigger/job-6.json is committed and authoritative (vt-broadcast triggers show job-6 prints it; the next write regenerates the twin)\n')
      assert.match(r.out, /^resolved eth of job-6: not-broadcast$/m)
      assert.equal((await readTrigger(e.t, 'job-6')).chains[0].state, 'not-broadcast')
    } finally { chmodSync(join(e.out, 'triggers'), 0o700) }
  })
})

test('mainnet clear/resolve with no tty refuse trigger.clear-typed, whatever the caller profile (VT_PROFILE=local)', async () => {
  await withEnv(async (e) => {
    await seed(e, 'job-3', 'mainnet', ['eth', 'sol'])
    const env = { ...e.env, VT_PROFILE: 'local' }
    let r = await runDetached(['triggers', 'resolve', 'job-3', 'eth', 'mark-not-broadcast'], env)
    assert.equal(r.code, 2)
    assert.match(r.err, /^refused trigger\.clear-typed: /)
    assert.equal((await readTrigger(e.t, 'job-3')).chains[0].state, 'planned')
    for (const d of ['eth', 'sol'] as const) await advanceTrace(e.t, 'job-3', d, { state: 'not-broadcast', reason: 'synthetic' }, e.clock)
    r = await runDetached(['triggers', 'clear', 'job-3'], env)
    assert.equal(r.code, 2)
    assert.match(r.err, /^refused trigger\.clear-typed: /)
    assert.equal((await readTrigger(e.t, 'job-3')).clearedAt, null)
  })
})

test('mainnet clear/resolve on a pty: the typed word decides', { timeout: 120_000 }, async () => {
  await withEnv(async (e) => {
    await seed(e, 'job-4', 'mainnet', ['eth'])
    const run = (args: string[], word: string) => runInPty([process.execPath, '--disable-sigusr1', CLI, ...args], { env: e.env, steps: [{ waitFor: 'to confirm: ', send: word + '\r' }], timeoutMs: 60_000 })
    let r = await run(['triggers', 'resolve', 'job-4', 'eth', 'mark-not-broadcast'], 'clear')
    assert.equal(r.code, 2)
    assert.match(r.out, /refused trigger\.clear-typed: /)
    r = await run(['triggers', 'resolve', 'job-4', 'eth', 'mark-not-broadcast'], 'resolve')
    assert.equal(r.code, 0, r.out)
    assert.ok(r.out.indexOf('evidence for eth of job-4:') < r.out.indexOf('Type "resolve"'), 'evidence before the prompt')
    assert.match(r.out, /resolved eth of job-4: not-broadcast/)
    r = await run(['triggers', 'clear', 'job-4'], 'nope')
    assert.equal(r.code, 2)
    assert.match(r.out, /refused trigger\.clear-typed: /)
    r = await run(['triggers', 'clear', 'job-4'], 'clear')
    assert.equal(r.code, 0, r.out)
    assert.match(r.out, /job-4 {2}mainnet {2}flow1 {2}CLEARED {2}eth=not-broadcast/)
    assert.deepEqual(latchOf(e.out), { open: null })
  })
})

test('triggers: malformed commands print usage and exit 64, touching nothing', async () => {
  await withEnv(async (e) => {
    for (const args of [
      ['triggers'], ['triggers', 'bogus'], ['triggers', 'list', 'x'], ['triggers', 'show'], ['triggers', 'clear', 'a', 'b'],
      ['triggers', 'resolve', 'a', 'eth'], ['triggers', 'resolve', 'a', 'eth', 'mark-done'], ['triggers', 'resolve', 'a', 'eth', 'retry'],
      ['triggers', 'resolve', 'a', 'eth', 'mark-failed', 'x'], ['triggers', 'resolve', 'a', 'eth', 'mark-done', 'tx', '--confirmations', '0'],
      ['triggers', 'resolve', 'a', 'eth', 'mark-done', 'tx', '--block'], ['triggers', 'resolve', 'a', 'eth', 'mark-done', 'tx', '--block', 'b', '--block', 'c'],
      ['triggers', 'resolve', 'a', 'eth', 'mark-done', 'tx', '--readback', 'true'],
      ['triggers', 'reset-latch', 'x'],
    ]) {
      const r = await runDetached(args, e.env)
      assert.equal(r.code, 64, args.join(' '))
      assert.match(r.err, /usage/)
    }
    assert.equal(existsSync(e.out), false)
  })
})

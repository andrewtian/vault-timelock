// cli/test/run.test.ts — `vt job run` (src/job/run.ts; plan Task C6), in process: the command with E3's in-memory API and
// relay (packages/core/test/fakes: the contract's lease / reconcile-first / ticket semantics, on a virtual clock), a
// fake terminal (passphrases, typed words and keys from queues; the real /dev/tty readers are pinned by the pty tests in
// tty.test.ts) and synthetic keys saved as real age backups (core encryptKey). Nothing listens on a port.
// ALL DATA IS SYNTHETIC: keys made here, a made-up passphrase, fake chains.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Chain, JournalEvent, Network } from '@vault-timelock/core/contracts'
import { Refusal } from '@vault-timelock/core/contracts'
import { normalizeJob } from '@vault-timelock/core/job'
import { encryptKey, fromSecret, newKey } from '@vault-timelock/core/engine/keys.js'
import type { JobIo } from '../src/job/client.ts'
import { jobCommand } from '../src/job/index.ts'
import type { FaultEvent, Faults, Held, ProcFacts, RunDeps } from '../src/job/run.ts'
import { afterSending, lastResort, loopbackFetch, mmss, printer, processFacts, viewLine } from '../src/job/run.ts'
import type { Key, Signals, TtyIo } from '../src/job/tty.ts'
import { keyOf } from '../src/job/tty.ts'
import type * as HelpersModule from '../../packages/core/test/executor/helpers.ts'
import type * as JournalModule from '../../packages/core/test/fakes/fake-journal.ts'
import type * as RelayModule from '../../packages/core/test/fakes/fake-relay.ts'
import type * as ChainsModule from '../../packages/core/test/engine/fakes.ts'
import { FAULT_CANARY_IP, FAULT_CANARY_KEY, FAULT_MARKER, faultError } from './fixtures/fault-hook.ts'
import { CANARY, IPV4, removeDir, tempDir } from './lib.ts'

const PASS = 'c6-synthetic-passphrase-never-a-secret'
const TOKEN = 'ab'.repeat(32)
// E3's fakes, found through the core package (a mutation-runner copy of this workspace links node_modules only).
const CORE_TEST = new URL('../../test/', import.meta.resolve('@vault-timelock/core/contracts'))
let stack: typeof HelpersModule.stack, fakeJournal: typeof JournalModule.fakeJournal, virtualClock: typeof JournalModule.virtualClock
let fakeRelayClient: typeof RelayModule.fakeRelayClient, fakeEthChain: typeof ChainsModule.fakeEthChain, fakeSolChain: typeof ChainsModule.fakeSolChain
let T = ''
before(async () => {
  T = tempDir('vt-c6-run-')
  ;({ stack } = await import(new URL('executor/helpers.ts', CORE_TEST).href) as typeof HelpersModule)
  ;({ fakeJournal, virtualClock } = await import(new URL('fakes/fake-journal.ts', CORE_TEST).href) as typeof JournalModule)
  ;({ fakeRelayClient } = await import(new URL('fakes/fake-relay.ts', CORE_TEST).href) as typeof RelayModule)
  ;({ fakeEthChain, fakeSolChain } = await import(new URL('engine/fakes.ts', CORE_TEST).href) as typeof ChainsModule)
})
after(() => removeDir(T))

// ---- the outside world

type Handle = { chain: Chain; address: string; secret: string; kp?: { _keypair: { secretKey: Uint8Array } } }
type ExKey = { chain: Chain; address: string; network: Network | null; handle: Handle }
const keyOfChain = (chain: Chain): ExKey => {
  const h = newKey(chain) as unknown as Handle
  return { chain, address: h.address, network: 'local', handle: h }
}
let n = 0
async function backup(k: ExKey, o: { network?: Network | null; pass?: string } = {}): Promise<string> {
  const { ct } = await encryptKey(k.handle as never, o.pass ?? PASS, o.network === undefined ? 'local' : o.network)
  const f = join(T, `b${++n}`, `vt-${k.chain}-key.age`)
  mkdirSync(join(T, `b${n}`), { recursive: true })
  writeFileSync(f, ct)
  return f
}

interface Term { tty: TtyIo; asked: { passphrase: number; words: string[] }; press(k: Key): void; readerStops: () => number }
function term(o: { available?: boolean; passphrases?: string[]; words?: Array<string | undefined> } = {}): Term {
  const passphrases = [...(o.passphrases ?? [PASS])], words = [...(o.words ?? [])]
  const asked = { passphrase: 0, words: [] as string[] }
  let on: ((k: Key) => void) | null = null, stops = 0
  return {
    tty: {
      available: () => o.available ?? true,
      passphrase: async () => { asked.passphrase++; const p = passphrases.shift(); if (p === undefined) throw new Refusal('passphrase.aborted', 'no passphrase left (test)'); return p },
      word: async (prompt) => { asked.words.push(prompt); return words.shift() },
      keys: (f) => { on = f; return () => { stops++; on = null } },
    },
    asked, press: (k) => { on?.(k) }, readerStops: () => stops,
  }
}
function signals(): Signals & { live: () => number } {
  const m = new Map<string, Set<() => void>>()
  return {
    on: (s, f) => { if (!m.has(s)) m.set(s, new Set()); m.get(s)!.add(f) },
    off: (s, f) => { m.get(s)?.delete(f) },
    live: () => [...m.values()].reduce((a, x) => a + x.size, 0),
  }
}
interface Cap { io: JobIo; out: () => string; all: () => string; lines: string[] }
function mkIo(network: Network = 'local', onLine?: (l: string) => void): Cap {
  let out = '', err = ''
  const lines: string[] = []
  const take = (t: string): void => { for (const l of t.split('\n')) if (l !== '') { lines.push(l); onLine?.(l) } }
  const io: JobIo = {
    network, env: { HOME: T, VT_HOME: join(T, 'vt-home') }, cwd: T, ports: { page: 1, relay: 1, api: 1 },
    out: (t) => { out += t; take(t) }, err: (t) => { err += t; take(t) },
    ask: async () => undefined, now: () => Date.now(),
  }
  return { io, out: () => out, all: () => out + err, lines }
}
type S = ReturnType<typeof HelpersModule.stack>
// The process as bin/vt starts it (vt.inspector), and the last resort's process hooks, faked (faults()).
const AS_BIN_VT: ProcFacts = { execArgv: ['--disable-sigusr1', '--no-addons'], nodeOptions: undefined, inspector: undefined }
function faults(): Faults & { live: () => number; emit: (ev: FaultEvent, e: unknown) => void; exits: number[] } {
  const m = new Map<FaultEvent, Set<(e: unknown) => void>>()
  const exits: number[] = []
  return {
    on: (ev, f) => { if (!m.has(ev)) m.set(ev, new Set()); m.get(ev)!.add(f) },
    off: (ev, f) => { m.get(ev)?.delete(f) },
    exit: (code) => { exits.push(code) },
    live: () => [...m.values()].reduce((a, x) => a + x.size, 0),
    emit: (ev, e) => { for (const f of [...(m.get(ev) ?? [])]) f(e) },
    exits,
  }
}
function depsFor(s: { j: { client: unknown }; relay: { client: unknown }; clock: unknown }, t: Term, sig = signals(), extra: Partial<RunDeps> = {}): RunDeps {
  return {
    tty: t.tty, signals: sig, token: TOKEN, proc: AS_BIN_VT, faults: faults(),
    clients: () => ({ journal: s.j.client as never, relay: s.relay.client as never }),
    adapter: { clock: s.clock as never, random: { int: () => 0 } }, poll: 1_000, passiveWaitMs: 1_000, ...extra,
  }
}
const refusedWith = async (p: Promise<unknown>, id: string, why?: RegExp): Promise<void> => {
  await assert.rejects(p, (e: Error & { guardId?: string }) => { assert.equal(e.guardId, id, e.message); if (why) assert.match(e.message, why); return true })
}
// No secret text, no passphrase, no IP anywhere in what was printed.
function clean(text: string, keys: ExKey[], extra: string[] = []): void {
  const low = text.toLowerCase()
  for (const k of keys) {
    const s = k.handle.secret.toLowerCase()
    assert.ok(!low.includes(s) && !low.includes(s.replace(/^0x/, '')), `${k.chain} secret printed`)
  }
  for (const x of [PASS, ...extra]) assert.ok(!text.includes(x), 'the passphrase was printed')
  assert.ok(!text.includes(CANARY) && !IPV4.test(text), 'an IP was printed')
}
const evTypes = (evs: JournalEvent[], c: Chain) => evs.filter((e) => e.chain === c).map((e) => e.type)
const tick = () => new Promise<void>((r) => setImmediate(r))

// =====================================================================================================================

test('the terminal is required: no TTY → vt.tty-required before anything is read or asked (no API call, no passphrase)', async () => {
  const k = keyOfChain('eth')
  const s = stack('eth', { key: k as never })
  const t = term({ available: false })
  const setup = s.j.calls.length
  await refusedWith(jobCommand(['run', s.j.id, '--backup-eth', await backup(k)], mkIo().io, { run: depsFor(s, t) }), 'vt.tty-required', /terminal only/)
  assert.deepEqual(s.j.calls.slice(setup), [])
  assert.equal(t.asked.passphrase, 0)
})

// M2 FLIP (applied, operator R78): the real C2 lock no longer refuses `vt job run` on mainnet; the terminal check before it and the
// one-network checks after it still refuse, before any passphrase is asked.
test('mainnet: the job-send lock is lifted (the M2 flip); no terminal, a jobs API that does not serve mainnet, or a job of another network is still refused before any passphrase', async () => {
  const k = keyOfChain('eth')
  const real = (s: S, t: Term): RunDeps => { const d = depsFor(s, t); delete d.assertSendAllowed; return d }   // the real C2 lock
  const s = stack('eth', { key: k as never })
  const setup = s.j.calls.length
  let t = term({ available: false })
  await refusedWith(jobCommand(['run', s.j.id, '--backup-eth', await backup(k)], mkIo('mainnet').io, { run: real(s, t) }), 'vt.tty-required')
  assert.deepEqual(s.j.calls.slice(setup), [])
  t = term()
  await refusedWith(jobCommand(['run', s.j.id, '--backup-eth', await backup(k)], mkIo('mainnet').io, { run: real(s, t) }), 'executor.network-mismatch', /the jobs API on the mainnet port serves local/)
  assert.deepEqual(s.j.calls.slice(setup), ['status'], 'past the lock: only the network was read')
  assert.equal(t.asked.passphrase, 0)
  // an API that answers mainnet, holding a local job
  const m = stack('eth', { key: k as never, apiNetwork: 'mainnet' })
  t = term()
  await refusedWith(jobCommand(['run', m.j.id, '--backup-eth', await backup(k)], mkIo('mainnet').io, { run: real(m, t) }), 'executor.network-mismatch', /is a local job; this is the mainnet stack/)
  assert.equal(t.asked.passphrase, 0)
  assert.equal(m.relay.sends().length + s.relay.sends().length, 0, 'nothing sent')
})

test('the backup file is checked before any passphrase is asked (vt.backup-format); wrong passphrase → backup.decrypt; another key → backup.address-mismatch; nothing leased or signed', async () => {
  const k = keyOfChain('eth')
  const s = stack('eth', { key: k as never })
  const setup = s.j.calls.length
  const notAge = join(T, 'not-age.txt')
  writeFileSync(notAge, 'synthetic text, not an age file\n')
  let t = term()
  await refusedWith(jobCommand(['run', s.j.id, '--backup-eth', notAge], mkIo().io, { run: depsFor(s, t) }), 'vt.backup-format')
  assert.equal(t.asked.passphrase, 0)
  t = term({ passphrases: ['c6-a-wrong-synthetic-passphrase'] })
  const c = mkIo()
  await refusedWith(jobCommand(['run', s.j.id, '--backup-eth', await backup(k)], c.io, { run: depsFor(s, t) }), 'backup.decrypt')
  assert.equal(t.asked.passphrase, 1)
  assert.ok(!c.all().includes('c6-a-wrong-synthetic-passphrase'))
  const other = keyOfChain('eth')
  t = term()
  await refusedWith(jobCommand(['run', s.j.id, '--backup-eth', await backup(other)], mkIo().io, { run: depsFor(s, t) }), 'backup.address-mismatch')
  // a backup of the right key for the other chain
  t = term()
  const sk = keyOfChain('sol')
  await refusedWith(jobCommand(['run', s.j.id, '--backup-eth', await backup(sk)], mkIo().io, { run: depsFor(s, t) }), 'backup.chain')
  assert.ok(!s.j.calls.slice(setup).some((x) => x.startsWith('lease') || x.startsWith('append')), 'nothing leased or journaled')
  assert.equal(s.relay.sends().length, 0)
})

test('the backup\'s network (R71): another network is refused (backup.network); a backup without one needs `again` typed', async () => {
  const k = keyOfChain('eth')
  const s = stack('eth', { key: k as never, copies: 1, startIn: 0 })
  const setup = s.j.calls.length // the earlier tab's lease (stack())
  let t = term()
  await refusedWith(jobCommand(['run', s.j.id, '--backup-eth', await backup(k, { network: 'testnet' })], mkIo().io, { run: depsFor(s, t) }), 'backup.network', /made on testnet.*never used on another network/)
  const none = await backup(k, { network: null })
  for (const w of [undefined, 'Again', 'yes']) {
    t = term({ words: [w] })
    await refusedWith(jobCommand(['run', s.j.id, '--backup-eth', none], mkIo().io, { run: depsFor(s, t) }), 'backup.network', /not confirmed/)
    assert.match(t.asked.words[0], /records no network.*Type again to use it on local: $/)
  }
  assert.ok(!s.j.calls.slice(setup).some((x) => x.startsWith('lease')), 'no lease before the network is settled')
  t = term({ words: ['again'] })
  const c = mkIo()
  assert.equal(await jobCommand(['run', s.j.id, '--backup-eth', none], c.io, { run: depsFor(s, t) }), 0, c.all())
  assert.match(c.out(), /^eth: copies-done/m)
})

test('a whole run: lease, journal, copies done; the output never holds the key, the passphrase or an IP; the key is dropped and the terminal restored', async () => {
  const k = keyOfChain('sol')
  const s = stack('sol', { key: k as never, copies: 2, startIn: 3_000 })
  const t = term(), sig = signals(), f = faults()
  const c = mkIo()
  const loaded: Handle[] = []
  assert.equal(await jobCommand(['run', s.j.id, '--backup-sol', await backup(k)], c.io, { run: depsFor(s, t, sig, { faults: f, onKey: (x) => { loaded.push(x.handle as Handle) } }) }), 0, c.all())
  assert.match(c.out(), /^vt job run [0-9a-f]{16} "executor sol" on .*chains sol$/m)
  assert.match(c.all(), /^sol: the passphrase of the key backup vt-sol-key\.age \(asked next, at the terminal\)$/m)
  assert.match(c.out(), /^sol {2}countdown 0:0[0-9]/m)
  assert.match(c.out(), /^sol: copies-done/m)
  const types = evTypes(s.j.events, 'sol')
  assert.ok(types.indexOf('lease-acquired') < types.indexOf('intent'))
  assert.equal(types.filter((x) => x === 'reassembled').length, 2)
  clean(c.all(), [k])
  assert.equal(loaded.length, 1)
  assert.equal(loaded[0].address, k.address)
  assert.ok(loaded[0].kp!._keypair.secretKey.length === 64 && loaded[0].kp!._keypair.secretKey.every((b) => b === 0), 'the SOL secret bytes are zeroed on exit')
  assert.equal(t.readerStops(), 1, 'the key reader stopped (raw mode restored)')
  assert.equal(sig.live(), 0, 'the signal handlers are removed')
  assert.equal(f.live(), 0, 'the last resort is removed')
  assert.deepEqual(f.exits, [])
})

test('R79 (c): after `vt job stop` (journaled, latched) `vt job run` has nothing to run; after `vt job resume` it reopens the chain and finishes at the next copy', async () => {
  const k = keyOfChain('eth')
  let asked = false
  const s: S = stack('eth', { key: k as never, copies: 2, startIn: 0, eth: (m, p, base) => {
    if (m === 'eth_sendRawTransaction' && !asked) { asked = true; s.j.requestStop('eth') }   // `vt job stop` while copy 1 is in flight
    return base(m, p)
  } })
  const c1 = mkIo()
  assert.equal(await jobCommand(['run', s.j.id, '--backup-eth', await backup(k)], c1.io, { run: depsFor(s, term()) }), 0, c1.all())
  assert.deepEqual([s.j.state().chains.eth!.phase, s.j.state().chains.eth!.stopLatched], ['STOPPED', true])
  const c2 = mkIo()
  assert.equal(await jobCommand(['run', s.j.id, '--backup-eth', await backup(k)], c2.io, { run: depsFor(s, term()) }), 0, c2.all())
  assert.match(c2.out(), /^eth: STOPPED — nothing to run/m, 'latched: nothing to run')
  s.j.apiEvent('resume-requested', { chain: 'eth' }, null)          // `vt job resume`
  const c3 = mkIo()
  assert.equal(await jobCommand(['run', s.j.id, '--backup-eth', await backup(k)], c3.io, { run: depsFor(s, term()) }), 0, c3.all())
  assert.match(c3.out(), /^eth: copies-done/m)
  assert.deepEqual(s.j.events.filter((e) => e.type === 'intent').map((e) => e.data.copy), [1, 2], 'continued at copy 2; copy 1 once')
  assert.ok(s.j.events.some((e) => e.type === 'resumed'))
})

test('M5c: a FINAL stop whose latch was cleared (a journal from before R79b: a stop without a code) is settled for `vt job run` — nothing to run, no key loaded, nothing journaled (the executor\'s own reopen rule)', async () => {
  const k = keyOfChain('eth')
  const s: S = stack('eth', { key: k as never, copies: 2, startIn: 0 })
  s.j.apiEvent('stopped', { reason: 'stopped before any transaction' }, 'eth')   // no code: FINAL (fail closed)
  s.j.apiEvent('resume-requested', { chain: 'eth' }, null)
  const cs = s.j.state().chains.eth!
  assert.deepEqual([cs.phase, cs.stopLatched ?? false, cs.stopRequested, cs.stopClass], ['STOPPED', false, false, 'final'])
  const n = s.j.events.length
  const tm = term()
  const c = mkIo()
  assert.equal(await jobCommand(['run', s.j.id, '--backup-eth', await backup(k)], c.io, { run: depsFor(s, tm) }), 0, c.all())
  assert.match(c.out(), /^eth: STOPPED — nothing to run/m)
  assert.equal(tm.asked.passphrase, 0, 'no key is loaded for a chain that does not run')
  assert.deepEqual(s.j.events.slice(n).map((e) => e.type), [], 'nothing journaled (no lease, no resumed)')
})

test('Ctrl-C mid-transaction (R79: a DETACH): the in-flight tx resolves first; vt waits for it (a second Ctrl-C only warns); nothing final is journaled (no `stopped`, the chain keeps running); nothing new is signed', async () => {
  const k = keyOfChain('eth')
  let held = true, sent = 0, heldPolls = 0, preNonce = '0x0'
  let tm: Term | null = null
  let settledEarly = false, stoppedEarly = false
  let run: Promise<number> | null = null
  const s: S = stack('eth', { key: k as never, copies: 2, startIn: 2_000, eth: (m, p, base) => {
    if (m === 'eth_sendRawTransaction') {
      sent++
      if (sent === 1) { preNonce = base('eth_getTransactionCount', []) as string; queueMicrotask(() => tm!.press('interrupt')) }
      return base(m, p)
    }
    if (held && sent === 1) {
      if (m === 'eth_getTransactionReceipt') {
        heldPolls++
        if (heldPolls === 3) tm!.press('interrupt')        // the second Ctrl-C, while the tx is still in flight
        if (heldPolls >= 6) {                               // the tx resolves now; until here vt kept waiting
          stoppedEarly = s.j.events.some((e) => e.type === 'stopped')
          held = false
        }
        return null
      }
      if (m === 'eth_getTransactionCount') return preNonce
    }
    return base(m, p)
  } })
  tm = term()
  const c = mkIo()
  run = jobCommand(['run', s.j.id, '--backup-eth', await backup(k)], c.io, { run: depsFor(s, tm) })
  void run.then(() => { if (held) settledEarly = true })
  assert.equal(await run, 0, c.all())
  assert.equal(settledEarly, false, 'vt never exited while the tx was in flight')
  assert.equal(stoppedEarly, false, 'nothing was journaled stopped while the tx was in flight')
  assert.ok(heldPolls >= 6)
  const evs = s.j.events.filter((e) => e.chain === 'eth')
  const included = evs.findIndex((e) => e.type === 'included')
  assert.ok(included >= 0, evTypes(s.j.events, 'eth').join(' '))
  assert.equal(evs.filter((e) => e.type === 'stopped').length, 0, `a Ctrl-C journals no stop (R79): ${evTypes(s.j.events, 'eth').join(' ')}`)
  assert.equal(evs.filter((e) => e.type === 'intent').length, 1, 'no new intent after the Ctrl-C')
  assert.equal(s.relay.sends().length, 1)
  assert.deepEqual([s.j.state().chains.eth!.phase, s.j.state().chains.eth!.stopLatched ?? false], ['RUNNING', false], 'the job keeps running: the next vt job run continues it')
  const out = c.all()
  assert.equal(out.split('stopping after the in-flight transaction').length - 1, 1)
  assert.match(out, /still waiting: a transaction that may land is never abandoned/)
  const seq = c.lines.join('\n') // in the order printed (stdout and stderr together)
  assert.ok(seq.indexOf('stopping after the in-flight transaction') < seq.indexOf('eth: stopped'), seq)
  assert.ok(seq.indexOf('stopping after the in-flight transaction') < seq.indexOf('still waiting'), seq)
  assert.match(c.out(), /^eth: stopped/m)
  clean(out, [k])
})

test('`s` during the countdown: Skip once (POST …/skip), however often it is pressed; outside the countdown it does nothing', async () => {
  const k = keyOfChain('eth')
  const s = stack('eth', { key: k as never, copies: 1, startIn: 60_000 })
  const t = term()
  let pressed = false
  const c = mkIo('local', (l) => {
    if (!pressed && /^eth {2}countdown /.test(l)) { pressed = true; t.press('skip'); t.press('skip'); t.press('skip') }
  })
  t.press('skip') // before the run: nobody listens yet
  assert.equal(await jobCommand(['run', s.j.id, '--backup-eth', await backup(k)], c.io, { run: depsFor(s, t) }), 0, c.all())
  assert.ok(pressed)
  assert.equal(s.j.calls.filter((x) => x === 'skip').length, 1, 'skip called once')
  assert.equal(s.j.events.filter((e) => e.type === 'skip').length, 1)
  assert.match(c.all(), /Skip: the countdown ends now/)
  assert.match(c.out(), /^eth: copies-done/m)
})

test('a chain held by another executor (the page): lease.held, nothing signed; the key is dropped', async () => {
  const k = keyOfChain('sol')
  const s = stack('sol', { key: k as never, copies: 1, startIn: 0 })
  await s.j.client.lease(s.j.id, 'sol', 'acquire', 'browser') // the page's tab holds it
  const c = mkIo()
  const loaded: Handle[] = []
  await refusedWith(jobCommand(['run', s.j.id, '--backup-sol', await backup(k)], c.io, { run: depsFor(s, term(), signals(), { onKey: (x) => { loaded.push(x.handle as Handle) } }) }), 'lease.held')
  assert.match(c.out(), /^sol: did not run — refused lease\.held$/m)
  assert.equal(s.relay.sends().length, 0)
  assert.ok(loaded.length === 1 && loaded[0].kp!._keypair.secretKey.every((b) => b === 0), 'dropped')
})

test('two chains, one passphrase: asked once and tried on the second backup first; another passphrase is asked only when it does not open it', async () => {
  const ek = keyOfChain('eth'), sk = keyOfChain('sol')
  const clock = virtualClock(1_791_504_000_000)
  const { def, text } = (() => {
    const msg = 'Two chains, one synthetic message.\n'
    return { def: normalizeJob({ format: 'vt-job/1', network: 'local', name: 'two', message: msg, chains: {
      eth: { mode: { copies: 1 }, keyAddress: ek.address, budgetUsd: 5, clawbackTo: null, distinctCopies: true, feeStrategy: 'prompt' },
      sol: { mode: { copies: 1 }, keyAddress: sk.address, budgetUsd: 5, clawbackTo: null, distinctCopies: true, feeStrategy: 'passive' } } }, { network: 'local' }).def, text: msg }
  })()
  const mk = () => {
    const j = fakeJournal({ def, text, clock })
    const ec = fakeEthChain(), sc = fakeSolChain({ balance: 10n ** 10n })
    const relay = fakeRelayClient({ network: 'local', endpoints: { eth: 1, sol: 1 }, eth: (m, p) => (m === 'eth_chainId' ? '0x7a69' : m === 'eth_getCode' ? '0x' : ec.handler(m, p)), sol: (m, p) => sc.handler(m, p) })
    j.arm(['eth', 'sol'], { caps: { eth: '100000000000000000', sol: '100000000' }, releaseAt: j.serverNow() + 2_000 })
    return { j, relay, clock }
  }
  // one passphrase for both
  let x = mk(), t = term({ passphrases: [PASS] })
  const c = mkIo()
  assert.equal(await jobCommand(['run', x.j.id, '--backup-eth', await backup(ek), '--backup-sol', await backup(sk)], c.io, { run: depsFor(x, t) }), 0, c.all())
  assert.equal(t.asked.passphrase, 1)
  assert.match(c.out(), /^eth: copies-done/m)
  assert.match(c.out(), /^sol: copies-done/m)
  clean(c.all(), [ek, sk])
  // two passphrases: the first does not open the sol backup, so a second is asked; a wrong second → backup.decrypt
  const ek2 = { ...ek, handle: fromSecret('eth', ek.handle.secret) as Handle }
  const sk2 = { ...sk, handle: fromSecret('sol', sk.handle.secret) as Handle }
  x = mk()
  t = term({ passphrases: ['c6-second-synthetic-passphrase'] })
  const c2 = mkIo()
  assert.equal(await jobCommand(['run', x.j.id, '--chain', 'sol', '--backup-sol', await backup(sk2, { pass: 'c6-second-synthetic-passphrase' }), '--backup-eth', await backup(ek2)], c2.io, { run: depsFor(x, t) }), 0, c2.all())
  assert.equal(t.asked.passphrase, 1, '--chain sol: only the sol backup is opened')
  x = mk()
  t = term({ passphrases: [PASS, 'c6-second-synthetic-passphrase'] })
  await refusedWith(jobCommand(['run', x.j.id, '--backup-eth', await backup(ek2), '--backup-sol', await backup(sk2, { pass: 'c6-third-synthetic-passphrase' })], mkIo().io, { run: depsFor(x, t) }), 'backup.decrypt')
  assert.equal(t.asked.passphrase, 2)
})

test('a chain that cannot start (lease.held) stops the other chain too (after its in-flight tx); a key that fails its checks is dropped with the ones before it', async () => {
  const ek = keyOfChain('eth'), sk = keyOfChain('sol')
  const clock = virtualClock(1_791_504_000_000)
  const msg = 'Two chains, one refused.\n'
  const def = normalizeJob({ format: 'vt-job/1', network: 'local', name: 'two', message: msg, chains: {
    eth: { mode: { copies: 1 }, keyAddress: ek.address, budgetUsd: 5, clawbackTo: null, distinctCopies: true, feeStrategy: 'prompt' },
    sol: { mode: { copies: 1 }, keyAddress: sk.address, budgetUsd: 5, clawbackTo: null, distinctCopies: true, feeStrategy: 'passive' } } }, { network: 'local' }).def
  const j = fakeJournal({ def, text: msg, clock })
  const ec = fakeEthChain(), sc = fakeSolChain({ balance: 10n ** 10n })
  const relay = fakeRelayClient({ network: 'local', endpoints: { eth: 1, sol: 1 }, eth: (m, p) => (m === 'eth_chainId' ? '0x7a69' : m === 'eth_getCode' ? '0x' : ec.handler(m, p)), sol: (m, p) => sc.handler(m, p) })
  j.arm(['eth', 'sol'], { caps: { eth: '100000000000000000', sol: '100000000' }, releaseAt: j.serverNow() + 30_000 })
  await j.client.lease(j.id, 'sol', 'acquire', 'browser') // the page holds sol
  const c = mkIo()
  await refusedWith(jobCommand(['run', j.id, '--backup-eth', await backup(ek), '--backup-sol', await backup(sk)], c.io, { run: depsFor({ j, relay, clock }, term()) }), 'lease.held')
  assert.match(c.out(), /^sol: did not run — refused lease\.held$/m)
  assert.match(c.out(), /^eth: stopped/m)
  assert.ok(!j.events.some((e) => e.chain === 'eth' && e.type === 'stopped'), 'eth detached (R79): nothing journaled, it can still run')
  assert.equal(relay.sends().length, 0)
  // the sol key decrypts, then fails the network check: it is dropped (zeroed) with every key loaded before it
  const loaded: Handle[] = []
  const s2 = stack('sol', { key: sk as never, copies: 1, startIn: 0 })
  await refusedWith(jobCommand(['run', s2.j.id, '--backup-sol', await backup(sk, { network: 'mainnet' })], mkIo().io, { run: depsFor(s2, term(), signals(), { onKey: (x) => { loaded.push(x.handle as Handle) } }) }), 'backup.network')
  assert.ok(loaded.length === 1 && loaded[0].kp!._keypair.secretKey.every((b) => b === 0), 'dropped on the refusal')
})

test('usage: a backup for each chain that runs; --chain names a chain of the job; a settled chain needs nothing (no passphrase)', async () => {
  const k = keyOfChain('eth')
  const s = stack('eth', { key: k as never, copies: 1, startIn: 0 })
  const t = term()
  const usage = (args: string[]) => assert.rejects(jobCommand(['run', ...args], mkIo().io, { run: depsFor(s, t) }), (e: Error) => e.name === 'UsageError')
  await usage([s.j.id])
  await usage([s.j.id, '--chain', 'sol', '--backup-sol', 'x.age'])
  await usage([s.j.id, '--backup-eth', 'a.age', '--backup-sol', 'b.age'])
  await usage(['not-an-id', '--backup-eth', 'a.age'])
  await usage([s.j.id, '--backup-eth'])
  assert.equal(t.asked.passphrase, 0)
  // run it to the end, then again: nothing to run
  assert.equal(await jobCommand(['run', s.j.id, '--backup-eth', await backup(k)], mkIo().io, { run: depsFor(s, term()) }), 0)
  const t2 = term(), c = mkIo()
  assert.equal(await jobCommand(['run', s.j.id, '--backup-eth', 'never-read.age'], c.io, { run: depsFor(s, t2) }), 0)
  assert.match(c.out(), /^eth: COPIES_DONE — nothing to run/m)
  assert.equal(t2.asked.passphrase, 0)
})

test('the printer withholds a line that would hold a key\'s secret text; the progress lines; M:SS; the key map', () => {
  const k = keyOfChain('eth')
  const c = mkIo()
  const out = printer(c.io)
  out.forbid(k as never)
  out.line(`a line with ${k.handle.secret.slice(2).toUpperCase()} in it`)
  out.line(`fine ${CANARY}`)
  assert.ok(!c.all().toLowerCase().includes(k.handle.secret.slice(2)))
  assert.match(c.all(), /^\(a line was withheld: it held key material\)$/m)
  assert.ok(!c.all().includes(CANARY), 'C4\'s printer redacts IPs')
  out.clear()
  assert.deepEqual([mmss(60_000), mmss(59_001), mmss(0), mmss(-5), mmss(61_000), mmss(600_000)], ['1:00', '1:00', '0:00', '0:00', '1:01', '10:00'])
  assert.equal(viewLine('eth', { phase: 'countdown', copy: null, part: null, parts: null, note: 'simulation ✓', startsInMs: 42_000 }), 'eth  countdown 0:42  simulation ✓  (s = skip the countdown, Ctrl-C = detach: nothing is stopped; vt job stop <id> stops)')
  assert.equal(viewLine('sol', { phase: 'running', copy: 2, part: 3, parts: 7, note: '', startsInMs: 0 }), 'sol  running  copy 2 part 3/7')
  assert.deepEqual([0x73, 0x53, 0x03, 0x1c, 0x71, 0x0d, 0x1b].map(keyOf), ['skip', 'skip', 'interrupt', 'interrupt', null, null, null])
})

test('loopbackFetch reaches only this network\'s relay and API (Host = the fixed port); anything else is refused without a transport text', async () => {
  const f = loopbackFetch('local', { api: 1, relay: 2 })
  for (const u of ['http://127.0.0.1:5180/', 'http://127.0.0.1:5192/status', 'http://localhost:5182/status', 'https://127.0.0.1:5182/status', `http://${CANARY}:5182/`, 'http://u:p@127.0.0.1:5182/']) {
    await assert.rejects(f(u), (e: Error) => e instanceof TypeError && e.message === 'fetch failed: only this network\'s relay and API are reachable')
  }
  await assert.rejects(f('nonsense'), (e: Error) => e instanceof TypeError && e.message === 'fetch failed: not a URL')
  // a closed port: the error text never names the address
  await assert.rejects(f('http://127.0.0.1:5182/status'), (e: Error) => e.message === 'fetch failed')
})

// ---- fix round 1 (task-C6-review.md m-1, m-2, m-4)

test('review m-4: an executor not started as bin/vt starts it (node --disable-sigusr1 and nothing else, no NODE_OPTIONS, no inspector open) → vt.inspector, before anything is read or asked', async () => {
  const k = keyOfChain('eth')
  const s = stack('eth', { key: k as never })
  const setup = s.j.calls.length
  const f = await backup(k)
  const bad: ProcFacts[] = [
    { ...AS_BIN_VT, execArgv: [] },                                         // SIGUSR1 would open an inspector
    { ...AS_BIN_VT, execArgv: ['--disable-sigusr1', '--no-addons', '--inspect'] },
    { ...AS_BIN_VT, execArgv: ['--inspect-brk=0', '--disable-sigusr1', '--no-addons'] },
    { ...AS_BIN_VT, execArgv: ['--disable-sigusr1', '--no-addons', '--inspect_wait'] },
    { ...AS_BIN_VT, execArgv: ['--disable-sigusr1', '--no-addons', '--inspect-port=0'] },
    { ...AS_BIN_VT, execArgv: ['--disable-sigusr1', '--debug-port=9230'] },
    { ...AS_BIN_VT, execArgv: ['--disable-sigusr1', '--no-addons', '--import', 'preload.mjs'] },
    { ...AS_BIN_VT, execArgv: ['--disable_sigusr1'] },
    { ...AS_BIN_VT, nodeOptions: '--inspect' },
    { ...AS_BIN_VT, nodeOptions: '--debug-port=9230' },
    { ...AS_BIN_VT, nodeOptions: '' },                                       // env -i clears it: it is never there at all
    { ...AS_BIN_VT, inspector: 'ws://localhost:9229/synthetic' },
  ]
  for (const proc of bad) {
    const t = term()
    await refusedWith(jobCommand(['run', s.j.id, '--backup-eth', f], mkIo().io, { run: depsFor(s, t, signals(), { proc }) }), 'vt.inspector', /no debugger can attach/)
    assert.equal(t.asked.passphrase, 0, JSON.stringify(proc))
  }
  await refusedWith(jobCommand(['clawback', s.j.id, '--chain', 'eth', '--to', '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6', '--backup-eth', f], mkIo().io, { run: depsFor(s, term(), signals(), { proc: bad[0] }) }), 'vt.inspector')
  assert.deepEqual(s.j.calls.slice(setup), [], 'no API call')
  // the default facts are this process's own; started as bin/vt starts it, the command goes on (here: to the terminal)
  assert.deepEqual(processFacts(), { execArgv: process.execArgv, nodeOptions: process.env.NODE_OPTIONS, inspector: undefined })
  await refusedWith(jobCommand(['run', s.j.id, '--backup-eth', f], mkIo().io, { run: depsFor(s, term({ available: false })) }), 'vt.tty-required')
})

test('review m-1: the test-only fault hook is refused unless NODE_ENV=test (vt.test-fault), before anything is read; under it, the hook runs once the keys are loaded and after each intent, with the last resort armed', async () => {
  const k = keyOfChain('eth')
  const s = stack('eth', { key: k as never, copies: 1, startIn: 0 })
  const setup = s.j.calls.length
  const f = await backup(k)
  for (const env of [{}, { NODE_ENV: 'production' }, { NODE_ENV: 'TEST' }]) {
    const c = mkIo()
    const t = term()
    await refusedWith(jobCommand(['run', s.j.id, '--backup-eth', f], { ...c.io, env: { ...c.io.env, ...env } }, { run: depsFor(s, t, signals(), { fault: () => {} }) }), 'vt.test-fault', /tests only/)
    assert.equal(t.asked.passphrase, 0)
  }
  assert.deepEqual(s.j.calls.slice(setup), [], 'no API call')
  const fl = faults(), at: string[] = []
  let armedAtPassphrase = -1
  const t = term()
  const tty: TtyIo = { ...t.tty, passphrase: async () => { armedAtPassphrase = fl.live(); return PASS } }
  const c = mkIo()
  assert.equal(await jobCommand(['run', s.j.id, '--backup-eth', f], { ...c.io, env: { ...c.io.env, NODE_ENV: 'test' } }, { run: depsFor(s, t, signals(), { tty, faults: fl, fault: (x) => { at.push(`${x} ${fl.live()}`) } }) }), 0, c.all())
  assert.equal(armedAtPassphrase, 2, 'the last resort (both handlers) is armed before the passphrase is asked')
  assert.deepEqual(at, ['keys 2', 'intent 2'])
  assert.equal(fl.live(), 0)
})

test('review m-1, the last resort: an unhandled rejection or uncaught exception drops the keys (SOL bytes zeroed) and passphrases, prints ONE fixed line (never the error: no canary IP or key, no stack) and what it means per chain, then exits 1', () => {
  const sk = keyOfChain('sol'), ek = keyOfChain('eth')
  const c = mkIo()
  const out = printer(c.io)
  out.forbid(sk as never)
  out.forbid(ek as never)
  const f = faults()
  const held: Held = { keys: new Map([['sol', sk as never], ['eth', ek as never]]), passphrases: [PASS], chains: ['eth', 'sol'], sent: new Set(['eth']) }
  const disarm = lastResort({ out, held, what: 'run', faults: f })
  assert.equal(f.live(), 2)
  const e = faultError()
  assert.ok(e.message.includes(FAULT_CANARY_IP) && e.message.includes(FAULT_CANARY_KEY) && (e.stack ?? '').includes(FAULT_CANARY_IP))
  f.emit('unhandledRejection', e)
  assert.deepEqual(f.exits, [1])
  assert.ok(sk.handle.kp!._keypair.secretKey.length === 64 && sk.handle.kp!._keypair.secretKey.every((b) => b === 0), 'the SOL secret bytes are zeroed')
  assert.equal(held.keys.size, 0)
  assert.deepEqual(held.passphrases, [])
  assert.deepEqual(c.lines, [
    'vt job run: an unexpected internal error (Error), an unhandled rejection, ended this process; its text is withheld (it could hold an address or key material); the keys were dropped',
    'eth: stopped unexpectedly after sending — run `vt job run` again to reconcile (nothing will be sent twice)',
    'sol: did not run — nothing was sent',
  ])
  assert.equal(c.lines[1], `eth: ${afterSending('run')}`)
  for (const x of [FAULT_CANARY_IP, FAULT_CANARY_KEY, FAULT_MARKER, 'Error:', ' at ']) assert.ok(!c.all().includes(x), x)
  assert.ok(!IPV4.test(c.all()))
  // a second fault while the first one ends the process: exit again, nothing more printed
  f.emit('uncaughtException', new TypeError(`again ${FAULT_CANARY_IP}`))
  assert.deepEqual(f.exits, [1, 1])
  assert.equal(c.lines.length, 3)
  disarm()
  assert.equal(f.live(), 0)
  // an uncaught exception before any chain is known (a claw-back, nothing journaled); an error name that is not a plain word is not shown
  const c2 = mkIo()
  const f2 = faults()
  lastResort({ out: printer(c2.io), held: { keys: new Map(), passphrases: [], chains: [], sent: new Set() }, what: 'clawback', faults: f2 })
  const odd = new Error(`synthetic ${FAULT_CANARY_IP}`)
  odd.name = `Odd ${FAULT_CANARY_IP}`
  f2.emit('uncaughtException', odd)
  assert.deepEqual(c2.lines, [
    'vt job clawback: an unexpected internal error, an uncaught exception, ended this process; its text is withheld (it could hold an address or key material); the keys were dropped',
    'did not run — nothing was sent',
  ])
  assert.deepEqual(f2.exits, [1])
})

test('review m-2: a chain that ends in an error AFTER this run journaled an intent says "stopped unexpectedly after sending — run `vt job run` again …"; "did not run" only when it provably journaled none', async () => {
  // after: the relay answers a malformed receipt once the part is sent (core throws: not a refusal)
  const k = keyOfChain('eth')
  let sent = 0
  const s = stack('eth', { key: k as never, copies: 1, startIn: 0, eth: (m, p, base) => {
    if (m === 'eth_sendRawTransaction') { sent++; return base(m, p) }
    if (sent > 0 && m === 'eth_getTransactionReceipt') return { status: '0x1', blockNumber: 'zz', gasUsed: 'zz', effectiveGasPrice: 'zz', transactionHash: p[0], logs: [] }
    return base(m, p)
  } })
  const c = mkIo()
  assert.equal(await jobCommand(['run', s.j.id, '--backup-eth', await backup(k)], c.io, { run: depsFor(s, term()) }), 1, c.all())
  assert.ok(s.j.events.some((e) => e.chain === 'eth' && e.type === 'intent'), 'an intent was journaled')
  assert.match(c.out(), /^eth: stopped unexpectedly after sending — run `vt job run` again to reconcile \(nothing will be sent twice\); the error: Cannot convert zz to a BigInt$/m)
  assert.ok(!c.all().includes('did not run'))
  clean(c.all(), [k])
  // before: the API fails the lease (not a refusal); nothing was journaled
  const k2 = keyOfChain('eth')
  const s2 = stack('eth', { key: k2 as never, copies: 1, startIn: 0 })
  const journal = { ...s2.j.client, lease: (...a: Parameters<typeof s2.j.client.lease>) => (a[2] === 'acquire' ? Promise.reject(new Error('synthetic: the API did not answer')) : s2.j.client.lease(...a)) }
  const c2 = mkIo()
  assert.equal(await jobCommand(['run', s2.j.id, '--backup-eth', await backup(k2)], c2.io, { run: depsFor(s2, term(), signals(), { clients: () => ({ journal: journal as never, relay: s2.relay.client as never }) }) }), 1, c2.all())
  assert.match(c2.out(), /^eth: did not run — synthetic: the API did not answer$/m)
  assert.ok(!c2.all().includes('stopped unexpectedly'))
})

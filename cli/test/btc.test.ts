// cli/test/btc.test.ts — the BTC lane in the `vt job …` commands (Task Cbtc; E7 lane, E7b executor, E7 re-review I-2), in process:
//   · `vt job run` over E3's in-memory API and a fake bitcoind behind the relay's two BTC routes (packages/core/test: fake-journal.ts,
//     engine/btc-fakes.ts), a fake terminal and synthetic keys saved as real age backups. Nothing listens on a port. The REAL
//     bitcoind / ord / relay run is test/run-btc-real.test.ts (phase B).
//   · `vt job arm`, `status`, `receipt`, `clawback` and the argument parsing, over a recording fake API and relay.
// The run tests hand the executor an in-memory journal through the `clients` seam; the arm test runs core's real checkArmConfirm
// (M4d: the ArmDeps.checkConfirm stub is gone, core accepts btc).
// ALL DATA IS SYNTHETIC: keys made here, a made-up passphrase, a fake chain.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, writeFileSync } from 'node:fs'
import { createServer, type Server, type ServerResponse } from 'node:http'
import { join } from 'node:path'
import type { ArmRequest, Chain, JournalEvent, Network, RelayClient } from '@vault-timelock/core/contracts'
import { Refusal } from '@vault-timelock/core/contracts'
import { jobId, normalizeJob, reduce, sha256Hex } from '@vault-timelock/core/job'
import { encryptKey, newKey } from '@vault-timelock/core/engine/keys.js'
import { relayRpc } from '@vault-timelock/core/engine/rpc.js'
import type { JobIo } from '../src/job/client.ts'
import { jobCommand } from '../src/job/index.ts'
import type { ProcFacts, RunDeps } from '../src/job/run.ts'
import { controls } from '../src/job/run.ts'
import type { Key, Signals, TtyIo } from '../src/job/tty.ts'
import { describeCap, notAffordableMessage, planCaps } from '../src/job/arm.ts'
import { renderEvent, renderStatus } from '../src/job/status.ts'
import type { JobView } from '../src/job/status.ts'
import { renderReceipt } from '../src/job/receipt.ts'
import { describeDef } from '../src/job/validate.ts'
import { CANARY, IPV4, removeDir, tempDir } from './lib.ts'
import type * as HelpersModule from '../../packages/core/test/executor/helpers.ts'
import type * as JournalModule from '../../packages/core/test/fakes/fake-journal.ts'
import type * as RelayModule from '../../packages/core/test/fakes/fake-relay.ts'
import type * as ChainsModule from '../../packages/core/test/engine/fakes.ts'
import type * as BtcFakes from '../../packages/core/test/engine/btc-fakes.ts'

const PASS = 'cbtc-synthetic-passphrase-never-a-secret'
const TOKEN = 'ab'.repeat(32)
const NOW = 1_791_504_000_000
const CORE_TEST = new URL('../../test/', import.meta.resolve('@vault-timelock/core/contracts'))
let fakeJournal: typeof JournalModule.fakeJournal, virtualClock: typeof JournalModule.virtualClock
let fakeRelayClient: typeof RelayModule.fakeRelayClient, fakeEthChain: typeof ChainsModule.fakeEthChain
let fakeBtcChain: typeof BtcFakes.fakeBtcChain
let newEth: typeof HelpersModule.newKey
let T = ''
const servers: Server[] = []
before(async () => {
  T = tempDir('vt-cbtc-')
  ;({ fakeJournal, virtualClock } = await import(new URL('fakes/fake-journal.ts', CORE_TEST).href) as typeof JournalModule)
  ;({ fakeRelayClient } = await import(new URL('fakes/fake-relay.ts', CORE_TEST).href) as typeof RelayModule)
  ;({ fakeEthChain } = await import(new URL('engine/fakes.ts', CORE_TEST).href) as typeof ChainsModule)
  ;({ fakeBtcChain } = await import(new URL('engine/btc-fakes.ts', CORE_TEST).href) as typeof BtcFakes)
  ;({ newKey: newEth } = await import(new URL('executor/helpers.ts', CORE_TEST).href) as typeof HelpersModule)
})
after(async () => {
  for (const s of servers) { s.closeAllConnections(); await new Promise<void>((r) => s.close(() => r())) }
  removeDir(T)
})

// ---- the outside world

type Handle = { chain: Chain; address: string; secret: string; network?: Network }
type ExKey = { chain: Chain; address: string; network: Network | null; handle: Handle }
const btcKey = (network: Network = 'local'): ExKey => {
  const h = newKey('btc', network) as unknown as Handle
  return { chain: 'btc', address: h.address, network, handle: h }
}
const ethKey = (): ExKey => {
  const k = newEth('eth')
  return { chain: 'eth', address: k.address, network: 'local', handle: k.handle as Handle }
}
let nb = 0
async function backup(k: ExKey, o: { pass?: string; network?: Network | null } = {}): Promise<string> {
  const { ct } = await encryptKey(k.handle as never, o.pass ?? PASS, o.network === undefined ? (k.chain === 'btc' ? k.network : 'local') : o.network)
  const f = join(T, `b${++nb}`, `vt-${k.chain}-key.age`)
  mkdirSync(join(T, `b${nb}`), { recursive: true })
  writeFileSync(f, ct)
  return f
}
interface Term { tty: TtyIo; asked: { passphrase: number; words: string[] }; press(k: Key): void }
function term(o: { passphrases?: string[]; words?: Array<string | undefined> } = {}): Term {
  const passphrases = [...(o.passphrases ?? [PASS])], words = [...(o.words ?? [])]
  const asked = { passphrase: 0, words: [] as string[] }
  let on: ((k: Key) => void) | null = null
  return {
    tty: {
      available: () => true,
      passphrase: async () => { asked.passphrase++; const p = passphrases.shift(); if (p === undefined) throw new Refusal('passphrase.aborted', 'no passphrase left (test)'); return p },
      word: async (prompt) => { asked.words.push(prompt); return words.shift() },
      keys: (f) => { on = f; return () => { on = null } },
    },
    asked, press: (k) => { on?.(k) },
  }
}
const signals = (): Signals => ({ on: () => {}, off: () => {} })
function mkIo(network: Network = 'local'): { io: JobIo; out: () => string; all: () => string } {
  let out = '', err = ''
  const io: JobIo = { network, env: { HOME: T, VT_HOME: join(T, 'vt-home') }, cwd: T, ports: { page: 1, relay: 1, api: 1 }, out: (t) => { out += t }, err: (t) => { err += t }, ask: async () => undefined, now: () => NOW }
  return { io, out: () => out, all: () => out + err }
}
const AS_BIN_VT: ProcFacts = { execArgv: ['--disable-sigusr1', '--no-addons'], nodeOptions: undefined, inspector: undefined }
const refusedWith = async (p: Promise<unknown>, id: string, why?: RegExp): Promise<void> => {
  await assert.rejects(p, (e: Error & { guardId?: string }) => { assert.equal(e.guardId, id, e.message); if (why) assert.match(e.message, why); return true })
}
function clean(text: string, keys: ExKey[]): void {
  const low = text.toLowerCase()
  for (const k of keys) assert.ok(!low.includes(k.handle.secret.toLowerCase().replace(/^0x/, '')), `${k.chain} secret printed`)
  assert.ok(!text.includes(PASS), 'the passphrase was printed')
  assert.ok(!text.includes(CANARY) && !IPV4.test(text), 'an IP was printed')
}

// ---- a btc (and eth) job over E3's in-memory API and the fake bitcoind

const TEXT = 'A synthetic BTC vt message.\nTwo lines.\n'
function jobDef(o: { btc: ExKey; eth?: ExKey; copies?: number; network?: Network; text?: string; maxFeeRateSatVb?: number }) {
  const text = o.text ?? TEXT
  const chains: Record<string, unknown> = {
    btc: { mode: { copies: o.copies ?? 1 }, publishMode: 'btc.inscription', feeStrategy: 'economy', distinctCopies: true, keyAddress: o.btc.address, budgetUsd: 5, clawbackTo: null, maxFeeRateSatVb: o.maxFeeRateSatVb ?? 25 },
    ...(o.eth ? { eth: { mode: { copies: 1 }, keyAddress: o.eth.address, budgetUsd: 5, clawbackTo: null, distinctCopies: true, feeStrategy: 'prompt' } } : {}),
  }
  const def = normalizeJob({ format: 'vt-job/1', network: 'local', name: 'btc job', message: text, chains }, { network: 'local' }).def
  return { def: o.network !== undefined && o.network !== 'local' ? { ...def, network: o.network } : def, text }
}
function rig(o: { copies?: number; eth?: ExKey; btc?: ExKey; network?: Network; hook?: (type: string) => void; arm?: boolean } = {}) {
  const k = o.btc ?? btcKey()
  const network = o.network ?? 'local'
  const { def, text } = jobDef({ btc: k, ...(o.eth ? { eth: o.eth } : {}), ...(o.copies !== undefined ? { copies: o.copies } : {}), network })
  const clock = virtualClock(NOW)
  const j = fakeJournal({ def, text, clock, network })
  const chain = fakeBtcChain()
  chain.fund(k.address, 5_000_000n)
  chain.mine()
  const ec = o.eth ? fakeEthChain({ from: o.eth.address }) : null
  const eth = ec ? fakeRelayClient({ network, endpoints: { eth: 1 }, identity: { eth: { ok: true } }, eth: (m, p) => (m === 'eth_chainId' ? '0x7a69' : m === 'eth_getCode' ? '0x' : ec.handler(m, p)) }) : null
  const cfg = { base: 'http://relay.test', fetch: chain.fetch as never }
  const relay: RelayClient = {
    async status() { return { network, build: 'fake', confined: true, identity: { btc: { ok: true }, ...(eth ? { eth: { ok: true } } : {}) }, endpoints: { btc: 1, ...(eth ? { eth: 1 } : {}) } } },
    rpc: (c, m, p, x) => (c === 'btc' ? relayRpc(cfg, c, m, p, x ?? {}) : eth!.client.rpc(c, m, p, x)),
    async tor() { return { isTor: null } },
    async price() { return { fixture: true, source: 'x', prices: { SOL: { usd: 1 }, ETH: { usd: 1 } } } },
  }
  for (const [c, addr, bal] of [['btc', k.address, '1'], ...(o.eth ? [['eth', o.eth.address, '1000000000000000000']] : [])] as Array<[Chain, string, string]>) {
    void j.client.lease(j.id, c, 'acquire', 'browser')
    j.asHolder(1, 'browser', c, 'key-loaded', { address: addr })
    j.asHolder(1, 'browser', c, 'funds', { balance: bal, affordable: true, nextCopyCost: '1' })
    void j.client.lease(j.id, c, 'release', 'browser', 1)
  }
  if (o.arm !== false) j.arm(['btc', ...(o.eth ? ['eth' as const] : [])], { caps: { btc: '1000000', ...(o.eth ? { eth: '100000000000000000' } : {}) }, releaseAt: j.serverNow() + 2_000 })
  const journal = { ...j.client, async append(id: string, c: Chain, gen: number, type: string, data: Record<string, unknown>, x?: unknown) {
    const r = await (j.client.append as Function)(id, c, gen, type, data, x)
    if (c === 'btc') o.hook?.(type)
    return r
  } }
  const deps = (t: Term, extra: Partial<RunDeps> = {}): RunDeps => ({
    tty: t.tty, signals: signals(), token: TOKEN, proc: AS_BIN_VT, faults: { on: () => {}, off: () => {}, exit: () => {} },
    clients: () => ({ journal: journal as never, relay }),
    adapter: { clock: clock as never, random: { int: () => 0 } }, poll: 1_000, passiveWaitMs: 1_000, ...extra,
  })
  return { k, j, chain, relay, deps, clock, text, def }
}

// =====================================================================================================================
// vt job run
// =====================================================================================================================

test('run: a btc copies job through the CLI executor: one passphrase, key and network checks, commit then reveal, copies-done; nothing secret printed; the key dropped', async () => {
  const s = rig({ copies: 2 })
  const t = term()
  const loaded: unknown[] = []
  const c = mkIo()
  assert.equal(await jobCommand(['run', s.j.id, '--backup-btc', await backup(s.k)], c.io, { run: s.deps(t, { onKey: (x) => { loaded.push(x.handle) } }) }), 0, c.all())
  assert.equal(t.asked.passphrase, 1)
  assert.match(c.out(), /^btc: copies-done/m)
  assert.match(c.all(), /chains btc/)
  assert.equal(s.chain.sends().length, 4, 'two copies = two commits + two reveals')
  assert.ok(s.chain.sends().every((x) => /^vt-ticket\/2\./.test(x.ticket ?? '')), 'every send carries a ticket')
  const st = s.j.state().chains.btc!
  assert.deepEqual([st.phase, st.copiesIncluded, st.openIntents], ['COPIES_DONE', 2, []])
  assert.deepEqual(s.j.events.filter((e) => e.type === 'intent' && e.chain === 'btc').map((e) => (e.data as { btc: { kind: string } }).btc.kind), ['commit', 'reveal', 'commit', 'reveal'])
  assert.equal(loaded.length, 1)
  clean(c.all(), [s.k])
})

test('run: btc is in the default set (every unsettled chain): eth + btc in one `vt job run`, one passphrase for both, both backups needed', async () => {
  const ek = ethKey()
  const s = rig({ eth: ek })
  // the btc backup is missing: a usage error that names it (btc runs without --chain)
  await assert.rejects(jobCommand(['run', s.j.id, '--backup-eth', await backup(ek)], mkIo().io, { run: s.deps(term()) }), /--backup-btc <file> names its key backup/)
  const t = term()
  const c = mkIo()
  assert.equal(await jobCommand(['run', s.j.id, '--backup-eth', await backup(ek), '--backup-btc', await backup(s.k)], c.io, { run: s.deps(t) }), 0, c.all())
  assert.equal(t.asked.passphrase, 1)
  assert.match(c.out(), /^eth: copies-done/m)
  assert.match(c.out(), /^btc: copies-done/m)
  clean(c.all(), [ek, s.k])
  // --chain btc: only the btc backup is read and opened
  const s2 = rig({ eth: ek })
  const t2 = term()
  assert.equal(await jobCommand(['run', s2.j.id, '--chain', 'btc', '--backup-btc', await backup(s2.k)], mkIo().io, { run: s2.deps(t2) }), 0)
  assert.equal(s2.j.state().chains.eth!.phase, 'ARMED', 'eth was not touched')
})

test('run: a settled btc chain has nothing to run (and no claw-back hint: there is none yet)', async () => {
  const s = rig()
  const t = term()
  assert.equal(await jobCommand(['run', s.j.id, '--backup-btc', await backup(s.k)], mkIo().io, { run: s.deps(t) }), 0)
  const c = mkIo()
  assert.equal(await jobCommand(['run', s.j.id], c.io, { run: s.deps(term()) }), 0, c.all())
  assert.match(c.out(), /^btc: COPIES_DONE — nothing to run$/m)
  assert.ok(!/clawback/.test(c.out()))
})

test('run: the btc lane is local only — a btc chain on testnet or mainnet is refused (executor.chain-unsupported) before any backup is read or passphrase asked', async () => {
  for (const network of ['testnet', 'mainnet'] as const) {
    const s = rig({ network })
    const t = term()
    const c = mkIo(network)
    await refusedWith(jobCommand(['run', s.j.id, '--backup-btc', join(T, 'does-not-exist.age')], c.io, { run: s.deps(t, { assertSendAllowed: () => {} }) }), 'executor.chain-unsupported', /local network only/)
    assert.equal(t.asked.passphrase, 0)
    assert.equal(s.chain.sends().length, 0)
    assert.equal(s.j.events.filter((e) => e.type === 'intent').length, 0)
  }
})

test('run: the key checks — a wrong passphrase, another chain\'s backup, another network\'s key (its address is not the job\'s), a tampered pair', async () => {
  const s = rig()
  const t = term({ passphrases: ['wrong-passphrase-0000'] })
  await refusedWith(jobCommand(['run', s.j.id, '--backup-btc', await backup(s.k)], mkIo().io, { run: s.deps(t) }), 'backup.decrypt')
  // an eth backup given as the btc one
  await refusedWith(jobCommand(['run', s.j.id, '--backup-btc', await backup(ethKey())], mkIo().io, { run: s.deps(term()) }), 'backup.chain')
  // a btc key made for testnet: its address is a testnet address, not the job's regtest one
  await refusedWith(jobCommand(['run', s.j.id, '--backup-btc', await backup(btcKey('testnet'))], mkIo().io, { run: s.deps(term()) }), 'backup.address-mismatch')
  // the same secret under another address of the same network (a different key)
  await refusedWith(jobCommand(['run', s.j.id, '--backup-btc', await backup(btcKey('local'))], mkIo().io, { run: s.deps(term()) }), 'backup.address-mismatch')
  assert.equal(s.chain.sends().length, 0)
  assert.equal(s.j.events.filter((e) => e.type === 'intent').length, 0)
})

test('run: Ctrl-C with a commit out waits for the reveal (a btc copy is one unit): both txs sent, then vt detaches (R79: nothing journaled); nothing of the next copy; the note says so', async () => {
  let pressNow: (() => void) | null = null, done = false
  const s = rig({ copies: 2, hook: (type) => { if (type === 'sent' && !done) { done = true; pressNow?.() } } })
  const t = term()
  pressNow = () => t.press('interrupt')
  const c = mkIo()
  assert.equal(await jobCommand(['run', s.j.id, '--backup-btc', await backup(s.k)], c.io, { run: s.deps(t, { signals: signals() }) }), 0, c.all())
  assert.match(c.out(), /^btc: stopped/m)
  assert.match(c.all(), /a btc copy is a commit and its reveal: vt waits for the reveal/)
  assert.equal(s.chain.sends().length, 2, 'the commit and its reveal; nothing of copy 2')
  const st = s.j.state().chains.btc!
  assert.deepEqual([st.phase, st.copiesIncluded, st.openIntents], ['RUNNING', 1, []], 'the copy is complete; the job keeps running')
  assert.equal(s.j.events.filter((e) => e.type === 'stopped').length, 0, 'R79: a Ctrl-C journals no stop')
  clean(c.all(), [s.k])
})

test('the Ctrl-C note names the btc commit+reveal rule only when a btc chain runs', () => {
  for (const btc of [true, false]) {
    const notes: string[] = []
    const keys = { f: null as ((k: Key) => void) | null }
    const release = controls({ out: { line: () => {}, note: (x) => { notes.push(x) }, forbid: () => {}, clear: () => {}, scrub: (x) => x }, tty: { available: () => true, passphrase: async () => '', word: async () => '', keys: (f) => { keys.f = f; return () => {} } }, signals: signals(), stop: () => {}, btc })
    keys.f!('interrupt')
    release()
    assert.equal(/commit and its reveal/.test(notes[0]), btc)
  }
})

// =====================================================================================================================
// argument parsing and refusals
// =====================================================================================================================

test('run: argument parsing — --backup-btc takes one value, once; --chain btc is a chain; a chain the job lacks is a usage error', async () => {
  const s = rig()
  const f = await backup(s.k)
  await assert.rejects(jobCommand(['run', s.j.id, '--backup-btc'], mkIo().io, { run: s.deps(term()) }), /usage: vt job run .* --backup-btc <file>/)
  await assert.rejects(jobCommand(['run', s.j.id, '--backup-btc', f, '--backup-btc', f], mkIo().io, { run: s.deps(term()) }), /usage: vt job run/)
  await assert.rejects(jobCommand(['run', s.j.id, '--chain', 'doge', '--backup-btc', f], mkIo().io, { run: s.deps(term()) }), /a chain is eth, sol or btc/)
  await assert.rejects(jobCommand(['run', s.j.id, '--chain', 'eth', '--backup-eth', f], mkIo().io, { run: s.deps(term()) }), /job .* has no eth chain/)
  await assert.rejects(jobCommand(['run', s.j.id, '--backup-sol', f], mkIo().io, { run: s.deps(term()) }), /has no sol chain \(--backup-sol\)/)
  assert.equal(s.chain.sends().length, 0)
})

test('clawback: `--chain btc` is refused with a clear "not available yet", before anything is read; the other flags and chains are as before', async () => {
  const s = rig()
  const t = term()
  const c = mkIo()
  const before = s.j.calls.length
  await assert.rejects(jobCommand(['clawback', s.j.id, '--chain', 'btc', '--to', s.k.address, '--backup-btc', await backup(s.k)], c.io, { run: s.deps(t) }), /vt job clawback --chain btc is not available yet/)
  assert.equal(t.asked.passphrase, 0)
  assert.equal(s.j.calls.length, before, 'no request at all: not even the job was read')
  await assert.rejects(jobCommand(['clawback', s.j.id, '--chain', 'eth', '--to', '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6', '--backup-btc', 'x'], mkIo().io, { run: s.deps(term()) }), /usage: vt job clawback/)
})

// =====================================================================================================================
// the control commands take btc; status / watch / receipt show the attempts
// =====================================================================================================================

test('stop / resume / close / resolve accept --chain btc (the API validates it); a doubtful chain is still a usage error', async () => {
  const bodies: Array<{ path: string; body: unknown }> = []
  const api = await fake((m, p, b, res) => { bodies.push({ path: p, body: b }); json(res, 200, {}) })
  const home = join(T, 'vt-home-ctl')
  mkdirSync(join(home, 'local'), { recursive: true, mode: 0o700 })
  writeFileSync(join(home, 'local', 'api.token'), TOKEN, { mode: 0o600 })
  const ctl = (): ReturnType<typeof mkIo> => { const c = mkIo(); c.io.env = { HOME: T, VT_HOME: home }; c.io.ports = { page: 1, relay: 1, api }; return c }
  for (const argv of [['stop'], ['resume'], ['close']]) await jobCommand([...argv, '0123456789abcdef', '--chain', 'btc'], ctl().io).catch(() => 0)
  assert.deepEqual(bodies.map((b) => (b.body as { chain: string }).chain), ['btc', 'btc', 'btc'])
  const c = ctl()
  await assert.rejects(jobCommand(['stop', '0123456789abcdef', '--chain', 'ltc'], c.io), /a chain is eth, sol or btc/)
})

function btcView(): JobView {
  const k = btcKey()
  const { def } = jobDef({ btc: k, copies: 2, maxFeeRateSatVb: 25 })
  const id = jobId(def)
  const ev: JournalEvent[] = []
  const add = (chain: Chain | null, type: string, data: Record<string, unknown>, by: JournalEvent['by'] = 'cli'): void => { ev.push({ v: 1, seq: ev.length, at: NOW, prev: '', chain, by, gen: chain === null ? null : 1, type: type as JournalEvent['type'], data }) }
  add(null, 'created', { jobId: id, defSha256: sha256Hex(JSON.stringify(def)) }, 'api')
  add('btc', 'key-loaded', { address: k.address })
  add('btc', 'funds', { balance: '1', affordable: true, nextCopyCost: '1' })
  const state = reduce(def, ev)
  return { id, def, state, leases: { btc: null }, seq: state.seq, serverNowMs: NOW }
}

test('status: a btc chain shows its job line and (with attempts) the commit and reveal txids, state, block, fee in sats and the readback — no key, no IP', () => {
  const v = btcView()
  const c = 'c'.repeat(64), r = 'd'.repeat(64)
  const cs = v.state.chains.btc!
  const txs = [
    { copy: 1, part: 1, parts: 2, attempts: [{ txId: c, gen: 2, state: 'included' }], state: 'included', landedId: c, block: '103', fee: '282', readback: true },
    { copy: 1, part: 2, parts: 2, attempts: [{ txId: 'e'.repeat(64), gen: 2, state: 'open' }, { txId: r, gen: 3, state: 'open' }], state: 'open', landedId: null, block: null, fee: null, readback: null },
  ]
  const text = renderStatus({ ...v, state: { ...v.state, chains: { btc: { ...cs, txs } as never } } })
  assert.match(text, /^ {2}btc {2}/m)
  assert.match(text, new RegExp(`copy 1 commit {2}${c} {2}included {2}block 103 {2}fee 282 sat {2}readback ok`))
  assert.match(text, new RegExp(`copy 1 reveal {2}${r} {2}open {2}readback pending {2}attempts 2`))
  assert.ok(!IPV4.test(text) && !text.includes(CANARY))
  assert.match(describeDef(v.id, v.def), /btc {2}2 copies {2}btc\.inscription {2}economy {2}key bcrt1\w+ {2}budget \$5 {2}max fee rate 25 sat\/vB/)
})

test('watch: a btc intent event shows commit or reveal, never the pubkey, inputs or value', () => {
  const data = { copy: 1, part: 1, parts: 2, attempt: 1, txId: 'a'.repeat(64), replaces: null, rawSha256: 'b'.repeat(64), btc: { kind: 'commit', pubkey: '02' + 'f'.repeat(64), fee: '282', value: '20000', inputs: [`${'1'.repeat(64)}:0`] } }
  const line = renderEvent({ seq: 5, at: NOW, chain: 'btc', by: 'cli', gen: 2, type: 'intent', data })
  assert.match(line, /btc intent \[cli gen 2\] copy 1 part 1\/2 attempt 1 commit a{64}$/)
  assert.ok(!line.includes('f'.repeat(64)) && !line.includes('20000'))
  assert.match(renderEvent({ seq: 6, at: NOW, chain: 'btc', by: 'cli', gen: 2, type: 'intent', data: { ...data, part: 2, btc: { kind: 'reveal', pubkey: '02' + 'f'.repeat(64), fee: '200', commitVout: 0 } } }), /attempt 1 reveal a{64}$/)
  assert.doesNotMatch(renderEvent({ seq: 7, at: NOW, chain: 'eth', by: 'cli', gen: 2, type: 'intent', data: { copy: 1, part: 1, parts: 1, attempt: 1, txId: '0x' + 'a'.repeat(64), replaces: null } }), / (commit|reveal) /)
})

test('receipt: a btc chain row lists its commit and reveal with the readback', () => {
  const txid = (x: string): string => x.repeat(64)
  const text = renderReceipt({ format: 'vt-receipt/1', jobId: '0123456789abcdef', name: 'btc job', network: 'local', messageSha256: 'f'.repeat(64), build: 'dev', chains: { btc: {
    address: 'bcrt1qsynthetic', network: 'local', mode: { copies: 1 }, phase: 'COPIES_DONE', copiesIncluded: 1, reassembled: [{ copy: 1, ok: true }], spent: '482', clawback: null,
    txs: [{ copy: 1, part: 1, txId: txid('a'), attempts: 1, block: '103', fee: '282', readback: true, links: [] }, { copy: 1, part: 2, txId: txid('b'), attempts: 1, block: '104', fee: '200', readback: true, links: [{ label: 'ord', href: 'http://127.0.0.1:8090/inscription/x', copyOnly: false }] }],
  } } })
  assert.match(text, /^ {2}btc {2}local {2}bcrt1qsynthetic {2}1 copies {2}COPIES_DONE {2}copies included 1 {2}spent 482 sat \(0\.00000482 BTC\)/m)
  assert.match(text, new RegExp(`copy 1 part 1 {2}${txid('a')} {2}block 103 {2}fee 282 {2}attempts 1 {2}readback ok`))
  assert.match(text, new RegExp(`copy 1 part 2 {2}${txid('b')} {2}block 104`))
})

// =====================================================================================================================
// vt job arm
// =====================================================================================================================

interface Fake { port: number }
function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify(body))
}
async function fake(h: (method: string, path: string, body: unknown, res: ServerResponse) => void): Promise<number> {
  const s = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (x: Buffer) => chunks.push(x))
    req.on('end', () => { let b: unknown; try { b = JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch { b = null } h(req.method ?? '', (req.url ?? '').split('?')[0], b, res) })
  })
  servers.push(s)
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', () => r()))
  return (s.address() as { port: number }).port
}
void (null as unknown as Fake)

test('arm: btc is priced from core startingFees (fee rate, worst-case commit + reveal, postage per copy) through the relay, with a native cap in sats; --source btc=<label> is sent; the request is exact', async () => {
  const k = btcKey()
  const { def, text } = jobDef({ btc: k, copies: 2, maxFeeRateSatVb: 10 })
  const id = jobId(def)
  const chain = fakeBtcChain()
  chain.fund(k.address, 3_000_000n)
  chain.mine()
  const cfg = { base: 'http://relay.test', fetch: chain.fetch as never }
  const relay: RelayClient = {
    async status() { return { network: 'local', build: 'fake', confined: true, identity: { btc: { ok: true } }, endpoints: { btc: 1 } } },
    rpc: (c, m, p, x) => relayRpc(cfg, c, m, p, x ?? {}),
    async tor() { return { isTor: null } },
    async price() { return { fixture: true, source: 'x', prices: { SOL: { usd: 1 }, ETH: { usd: 1 } } } },
  }
  const ev: JournalEvent[] = []
  const add = (chainId: Chain | null, type: string, data: Record<string, unknown>): void => { ev.push({ v: 1, seq: ev.length, at: NOW, prev: '', chain: chainId, by: 'cli', gen: chainId === null ? null : 1, type: type as JournalEvent['type'], data }) }
  add(null, 'created', { jobId: id, defSha256: sha256Hex(JSON.stringify(def)) })
  add('btc', 'key-loaded', { address: k.address })
  add('btc', 'funds', { balance: '3000000', affordable: true, nextCopyCost: '1' })
  const state = reduce(def, ev)
  const posts: ArmRequest[] = []
  const port = await fake((m, p, b, res) => {
    if (m === 'GET' && p === '/status') return json(res, 200, { network: 'local', networks: {}, mainnetSends: 'LOCKED', jobSends: 'LOCKED', build: 'dev', confined: true, legacyLatch: 'clear', serverNowMs: NOW })
    if (m === 'GET' && p === `/jobs/${id}`) return json(res, 200, { id, def, state, leases: { btc: null }, seq: state.seq, serverNowMs: NOW })
    if (m === 'GET' && p === `/messages/${def.messageSha256}`) { res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' }); return void res.end(Buffer.from(text, 'utf8')) }
    if (m === 'POST' && p === `/jobs/${id}/arm`) { posts.push(b as ArmRequest); return json(res, 200, { armed: { armedAt: NOW, releaseAt: NOW + 15_000, countdownSec: 15, schedule: { order: ['btc'], offsetSec: { btc: 0 } }, caps: (b as ArmRequest).caps, sources: {} } }) }
    json(res, 404, { error: { guard: 'api.route', message: 'no such endpoint' } })
  })
  const env = { HOME: T, VT_HOME: join(T, 'vt-home-arm') }
  mkdirSync(join(env.VT_HOME, 'local'), { recursive: true, mode: 0o700 })
  writeFileSync(join(env.VT_HOME, 'local', 'api.token'), TOKEN, { mode: 0o600 })
  let out = ''
  const io: JobIo = { network: 'local', env, cwd: T, ports: { page: 1, relay: 1, api: port }, out: (x) => { out += x }, err: (x) => { out += x }, ask: async () => undefined, now: () => NOW }
  const deps = { relay }
  assert.equal(await jobCommand(['arm', id, '--chains', 'btc', '--source', 'btc=main.1', '--countdown', '15'], io, { arm: deps }), 0, out)
  assert.equal(posts.length, 1)
  const req = posts[0]
  assert.deepEqual(req.chains, ['btc'])
  assert.deepEqual((req as ArmRequest & { sources: unknown }).sources, { btc: 'main.1' })
  assert.equal(req.countdownSec, 15)
  const cap = req.caps.btc!
  assert.match(cap.nativeCap, /^[1-9][0-9]*$/)
  assert.equal(cap.priceAt, null, 'no BTC price: the cap is in sats')
  assert.match(out, /btc worst case per copy at 10 sat\/vB \(the job's maxFeeRateSatVb\): commit \d+ \+ reveal \d+ sat, postage \d+ sat .*today's node estimate is \d+ sat\/vB/)
  assert.match(out, /the cap is the 0\.01 BTC native fallback/)
  assert.match(out, /btc {2}2 copies {2}planned [0-9.]+ BTC {2}cap \d+ sat \(no price: the R60 native fallback\)/)
  assert.match(out, /one copy: 2 parts, at most \d+ sat/)
  // the numbers are core's: the same startingFees / copyCost the executor uses
  const plan = await planCaps({ id, def, state, leases: {}, seq: state.seq, serverNowMs: NOW } as JobView, ['btc'], text, relay, 'local', NOW)
  assert.ok(plan.btc !== undefined && plan.btc.rate <= 10n && plan.btc.rate >= 1n)
  assert.equal(plan.btc!.commitFee + plan.btc!.revealFee + plan.btc!.postage, BigInt(plan.caps.btc.fullCopyCost), 'fullCopyCost = commit + reveal + postage')
  assert.ok(!IPV4.test(out) && !out.includes(CANARY))
  // a source that is not an armed chain, or a malformed label
  const io2 = { ...io }
  await assert.rejects(jobCommand(['arm', id, '--chains', 'btc', '--source', 'btc=a b'], io2, { arm: deps }), /--source: chain=label/)
  await assert.rejects(jobCommand(['arm', id, '--chains', 'btc', '--source', 'ltc=a'], io2, { arm: deps }), /--source: chain=label/)
  await assert.rejects(jobCommand(['arm', id, '--chains', 'doge'], io2, { arm: deps }), /--chains: a list of eth, sol, btc/)
})

// Eminors fix 2 (re-review 3): the Arm wording is pinned - the ceiling is named, and a refusal says cap or balance.
test('arm wording: the row names the ceiling (the job\'s or the 500 default) and the fallback cap; the refusal says balance or cap and the rate', () => {
  const base = { nativeCap: '1000000', usd: 0, priceAt: null, overCap: false, planned: '0.0002', fullCopyCost: '5000', parts: 2, affordable: true, capVia: 'fallback' }
  const fees = { rate: 2n, commitFee: 100n, revealFee: 200n, postage: 546n }
  const ch = { mode: { copies: 2 } } as never
  const job = describeCap('btc', { ...base, ceilingSatVb: 25, ceilingFromJob: true } as never, ch, fees).join('\n')
  assert.match(job, /worst case per copy at 25 sat\/vB \(the job's maxFeeRateSatVb\)/)
  assert.match(job, /today's node estimate is 2 sat\/vB/)
  assert.match(job, /the cap is the 0\.01 BTC native fallback/)
  const dflt = describeCap('btc', { ...base, ceilingSatVb: 500, ceilingFromJob: false } as never, ch, fees).join('\n')
  assert.match(dflt, /at 500 sat\/vB \(the 500 sat\/vB default ceiling: this job names none\)/)
  assert.doesNotMatch(describeCap('btc', { ...base, capVia: 'typed', ceilingSatVb: 25, ceilingFromJob: true } as never, ch, fees).join('\n'), /the cap is the 0\.01 BTC native fallback/)
  const bal = notAffordableMessage('btc', { ...base, affordable: false, notAffordableBecause: 'balance', ceilingSatVb: 25, ceilingFromJob: true } as never, 'abc')
  assert.match(bal, /the lane balance is below one worst-case copy \(priced at 25 sat\/vB, the job's maxFeeRateSatVb\); nothing was armed/)
  const cap = notAffordableMessage('btc', { ...base, affordable: false, notAffordableBecause: 'cap', ceilingSatVb: 500, ceilingFromJob: false } as never, 'abc')
  assert.match(cap, /one worst-case copy is above the cap \(priced at 500 sat\/vB, the 500 sat\/vB default: set maxFeeRateSatVb in a new job\)/)
  assert.doesNotMatch(notAffordableMessage('eth', { ...base, affordable: false, notAffordableBecause: 'balance' } as never, 'abc'), /sat\/vB/)
})

// =====================================================================================================================
// E7-fix3 m-2: stuck / resolve / stop wording for btc
// =====================================================================================================================

const COMMIT = 'c'.repeat(64)
function stuckView(): JobView {
  const v = btcView()
  const cs = v.state.chains.btc!
  const reason = 'the commit can never land: resolve it (vt job resolve <job> --chain btc --tx <txId> mark-failed), then run again'
  return { ...v, state: { ...v.state, chains: { btc: { ...cs, phase: 'STUCK', reason, openIntents: [COMMIT], txs: [{ copy: 1, part: 1, parts: 2, attempts: [{ txId: COMMIT, gen: 2, state: 'stuck' }], state: 'stuck', landedId: null, block: null, fee: null, readback: null }] } as never } } as never }
}

test('status: a STUCK btc chain fills <job> and <txId> and prints the exact next command (--mark-failed)', () => {
  const v = stuckView()
  const text = renderStatus(v)
  assert.ok(!text.includes('<job>') && !text.includes('<txId>'), text)
  assert.match(text, new RegExp(`resolve it \\(vt job resolve ${v.id} --chain btc --mark-failed\\)`))
  assert.match(text, new RegExp(`^ {13}vt job resolve ${v.id} --chain btc --mark-failed `, 'm'))
  assert.ok(!/btc --tx .* mark-done/.test(text))
  // the watch line for the stuck event is filled too
  const line = renderEvent({ seq: 9, at: NOW, chain: 'btc', by: 'cli', gen: 2, type: 'stuck', data: { txId: COMMIT, reason: 'x (vt job resolve <job> --chain btc --tx <txId> mark-failed)' } }, v.id)
  assert.match(line, new RegExp(`vt job resolve ${v.id} --chain btc --mark-failed`))
  assert.ok(!line.includes('<job>'))
})

test('resolve --chain btc: only --mark-failed; mark-done (flag or positional) is refused with the reason, before any request', async () => {
  const v = stuckView()
  const posts: unknown[] = []
  const seen: string[] = []
  const api = await fake((m, p, b, res) => {
    seen.push(`${m} ${p}`)
    if (m === 'GET' && p === `/jobs/${v.id}`) return json(res, 200, v)
    if (m === 'POST' && p === `/jobs/${v.id}/chains/btc/resolve`) { posts.push(b); return json(res, 200, { seq: 12 }) }
    json(res, 404, { error: { guard: 'api.route', message: 'no' } })
  })
  const home = join(T, 'vt-home-res')
  mkdirSync(join(home, 'local'), { recursive: true, mode: 0o700 })
  writeFileSync(join(home, 'local', 'api.token'), TOKEN, { mode: 0o600 })
  const mk = (): ReturnType<typeof mkIo> => { const c = mkIo(); c.io.env = { HOME: T, VT_HOME: home }; c.io.ports = { page: 1, relay: 1, api }; return c }
  for (const args of [['resolve', v.id, '--chain', 'btc', '--mark-done'], ['resolve', v.id, '--chain', 'btc', '--tx', COMMIT, 'mark-done']]) {
    await assert.rejects(jobCommand(args, mk().io), /accepts only --mark-failed: mark-done is refused for btc.*a commit that never landed must not be marked done/)
  }
  assert.deepEqual(seen, [], 'refused before any request')
  const c = mk()
  assert.equal(await jobCommand(['resolve', v.id, '--chain', 'btc', '--mark-failed'], c.io), 0, c.all())
  assert.deepEqual(posts, [{ txId: COMMIT, action: 'mark-failed' }], 'the stuck commit is found from the chain state')
  assert.match(c.out(), /recorded mark-failed for c{64} \(seq 12\)/)
  // both flags, or the flag form on an eth chain, are usage errors
  await assert.rejects(jobCommand(['resolve', v.id, '--chain', 'btc', '--mark-failed', '--mark-done'], mk().io), /usage: vt job resolve/)
  await assert.rejects(jobCommand(['resolve', v.id, '--chain', 'eth', '--mark-failed'], mk().io), /are for btc/)
})

test('stop --chain btc (and every chain) explains that Stop takes effect after the in-flight commit\'s reveal; eth does not', async () => {
  const api = await fake((m, p, b, res) => json(res, 200, { seq: 3 }))
  const home = join(T, 'vt-home-stop')
  mkdirSync(join(home, 'local'), { recursive: true, mode: 0o700 })
  writeFileSync(join(home, 'local', 'api.token'), TOKEN, { mode: 0o600 })
  const run = async (extra: string[]): Promise<string> => { const c = mkIo(); c.io.env = { HOME: T, VT_HOME: home }; c.io.ports = { page: 1, relay: 1, api }; assert.equal(await jobCommand(['stop', '0123456789abcdef', ...extra], c.io), 0); return c.out() }
  assert.match(await run(['--chain', 'btc']), /Stop takes effect after the in-flight commit's reveal/)
  assert.match(await run([]), /for a btc chain: a btc copy is a commit and its reveal, so Stop takes effect after the in-flight commit's reveal/)
  assert.doesNotMatch(await run(['--chain', 'eth']), /reveal/)
})

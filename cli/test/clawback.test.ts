// cli/test/clawback.test.ts — `vt job clawback` (src/job/clawback.ts; plan Task C6), in process: E3's in-memory API and
// relay (packages/core/test/fakes, a virtual clock), a fake terminal, synthetic keys in real age backups. The chain is
// settled the way E3's own claw-back test settles it (an earlier holder journaled `stopped`). Nothing listens on a port.
// ALL DATA IS SYNTHETIC.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Chain, Network } from '@vault-timelock/core/contracts'
import { Refusal } from '@vault-timelock/core/contracts'
import { encryptKey, newKey } from '@vault-timelock/core/engine/keys.js'
import { validateEthDest } from '@vault-timelock/core/chains/economy.js'
import { formatUnits } from '@vault-timelock/core/chains/plan.js'
import type { JobIo } from '../src/job/client.ts'
import { jobCommand } from '../src/job/index.ts'
import { checkDestination } from '../src/job/clawback.ts'
import type { RunDeps } from '../src/job/run.ts'
import type { Key, TtyIo } from '../src/job/tty.ts'
import type * as HelpersModule from '../../packages/core/test/executor/helpers.ts'
import { CANARY, IPV4, removeDir, tempDir } from './lib.ts'

const PASS = 'c6-synthetic-claw-passphrase-never-a-secret'
const DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
// E3's fakes, found through the core package (a mutation-runner copy of this workspace links node_modules only).
const CORE_TEST = new URL('../../test/', import.meta.resolve('@vault-timelock/core/contracts'))
let stack: typeof HelpersModule.stack
let T = ''
before(async () => {
  T = tempDir('vt-c6-claw-')
  ;({ stack } = await import(new URL('executor/helpers.ts', CORE_TEST).href) as typeof HelpersModule)
})
after(() => removeDir(T))

type Handle = { chain: Chain; address: string; secret: string }
let n = 0
async function backup(h: Handle, network: Network = 'local'): Promise<string> {
  const { ct } = await encryptKey(h as never, PASS, network)
  mkdirSync(join(T, `b${++n}`))
  const f = join(T, `b${n}`, `vt-${h.chain}-key.age`)
  writeFileSync(f, ct)
  return f
}
function term(words: Array<string | undefined> = []): { tty: TtyIo; asked: { passphrase: number; words: string[] }; press(k: Key): void } {
  const q = [...words]
  const asked = { passphrase: 0, words: [] as string[] }
  let on: ((k: Key) => void) | null = null
  return {
    tty: {
      available: () => true,
      passphrase: async () => { asked.passphrase++; return PASS },
      word: async (p) => { asked.words.push(p); return q.shift() },
      keys: (f) => { on = f; return () => { on = null } },
    },
    asked, press: (k) => { on?.(k) },
  }
}
function mkIo(network: Network = 'local'): { io: JobIo; all: () => string; lines: string[] } {
  let all = ''
  const lines: string[] = []
  const take = (t: string): void => { all += t; for (const l of t.split('\n')) if (l !== '') lines.push(l) }
  return { io: { network, env: { HOME: T, VT_HOME: join(T, 'vt-home') }, cwd: T, ports: { page: 1, relay: 1, api: 1 }, out: take, err: take, ask: async () => undefined, now: () => Date.now() }, all: () => all, lines }
}
// A settled ETH chain (stopped by an earlier holder, its lease expired); the lane holds `balance`, the armed cap is `cap`.
function settled(o: { balance?: bigint; cap?: string; network?: Network; clawbackTo?: string; code?: boolean } = {}) {
  const s = stack('eth', { copies: 1, startIn: 0, ethBalance: o.balance ?? 3n * 10n ** 17n, cap: o.cap ?? '100000000000000000', ...(o.network ? { network: o.network } : {}),
    ...(o.code ? { eth: (m: string, p: unknown[], base: (m: string, p: unknown[]) => unknown) => (m === 'eth_getCode' ? '0x6080604052' : base(m, p as never[])) } : {}) })
  void s.j.client.lease(s.j.id, 'eth', 'acquire', 'browser')
  s.j.asHolder(2, 'browser', 'eth', 'stopped', { reason: 'operator' })
  s.j.expire('eth')
  return s
}
type S = ReturnType<typeof settled>
const depsFor = (s: S, t: { tty: TtyIo }, extra: Partial<RunDeps> = {}): RunDeps => ({
  tty: t.tty, token: 'cd'.repeat(32), signals: { on: () => {}, off: () => {} },
  proc: { execArgv: ['--disable-sigusr1', '--no-addons'], nodeOptions: undefined, inspector: undefined }, faults: { on: () => {}, off: () => {}, exit: () => {} },
  clients: () => ({ journal: s.j.client, relay: s.relay.client }), adapter: { clock: s.clock, random: { int: () => 0 } }, poll: 1_000, passiveWaitMs: 1_000, ...extra,
})
const refusedWith = async (p: Promise<unknown>, id: string, why?: RegExp): Promise<void> => {
  await assert.rejects(p, (e: Error & { guardId?: string }) => { assert.equal(e.guardId, id, e.message); if (why) assert.match(e.message, why); return true })
}
const nothingSigned = (s: S): void => {
  assert.equal(s.relay.sends().length, 0, 'nothing sent')
  assert.ok(!s.j.events.some((e) => e.type === 'clawback-intent'), 'no claw-back intent')
}
function clean(text: string, h: Handle): void {
  const low = text.toLowerCase(), sec = h.secret.toLowerCase()
  assert.ok(!low.includes(sec) && !low.includes(sec.replace(/^0x/, '')), 'the secret was printed')
  assert.ok(!text.includes(PASS), 'the passphrase was printed')
  assert.ok(!text.includes(CANARY) && !IPV4.test(text), 'an IP was printed')
}

// =====================================================================================================================

test('the destination (job.clawback): EIP-55 / canonical base58; never the lane itself, 0x0, 0x…dEaD, the System Program or the incinerator; exactly clawbackTo when set', () => {
  const lane = newKey('eth') as unknown as Handle, sl = newKey('sol') as unknown as Handle, other = newKey('sol') as unknown as Handle
  const refused = (c: Chain, to: string, lanes: string, cb: string | null = null) =>
    assert.throws(() => checkDestination(c, to, lanes, cb), (e: Error & { guardId?: string }) => e.guardId === 'job.clawback')
  refused('eth', DEST.toLowerCase(), lane.address)                    // not checksummed
  refused('eth', DEST.replace('fe0FE', 'fe0fe'), lane.address)         // a wrong checksum
  refused('eth', '0x0000000000000000000000000000000000000000', lane.address)
  refused('eth', '0x000000000000000000000000000000000000dEaD', lane.address)
  refused('eth', lane.address, lane.address)
  refused('eth', 'not an address', lane.address)
  refused('eth', DEST, lane.address, '0x8739Eb87B3d11f221Df63454F8D229a1A4F4049C') // not the job's clawbackTo
  assert.equal(checkDestination('eth', DEST, lane.address, null), DEST)
  assert.equal(checkDestination('eth', DEST, lane.address, DEST.toLowerCase()), DEST, 'clawbackTo compares by address')
  refused('sol', '11111111111111111111111111111111', sl.address)
  refused('sol', '1nc1nerator11111111111111111111111111111111', sl.address)
  refused('sol', sl.address, sl.address)
  refused('sol', `${other.address}x`, sl.address)
  refused('sol', other.address, sl.address, newKey('sol').address)
  assert.equal(checkDestination('sol', other.address, sl.address, other.address), other.address)
})

test('only a settled chain (job.state); a CLAWED_BACK chain says so; the destination is checked before any key is touched', async () => {
  const s = stack('eth', { copies: 1, startIn: 60_000 })
  let t = term()
  await refusedWith(jobCommand(['clawback', s.j.id, '--chain', 'eth', '--to', DEST, '--backup-eth', await backup(s.key.handle)], mkIo().io, { run: depsFor(s as S, t) }), 'job.state', /settled chain.*ARMED/)
  assert.equal(t.asked.passphrase, 0)
  const z = settled()
  t = term()
  await refusedWith(jobCommand(['clawback', z.j.id, '--chain', 'eth', '--to', '0x000000000000000000000000000000000000dEaD', '--backup-eth', 'never-read.age'], mkIo().io, { run: depsFor(z, t) }), 'job.clawback', /nobody controls/)
  assert.equal(t.asked.passphrase, 0)
  nothingSigned(z)
  for (const bad of [['--chain', 'sol'], ['--chain', 'eth', '--to', DEST], ['--chain', 'eth', '--to', DEST, '--backup-sol', 'x.age']]) {
    await assert.rejects(jobCommand(['clawback', z.j.id, ...bad], mkIo().io, { run: depsFor(z, term()) }), (e: Error) => e.name === 'UsageError')
  }
})

test('over the armed cap: the exact remainder typed (arm.amount otherwise, nothing signed); then it rides as clawbackConfirm and the claw-back lands', async () => {
  const s = settled()
  const f = await backup(s.key.handle)
  for (const w of [undefined, '0.3000000000000000001', '0.29', '300000000000000000', 'all']) {
    const t = term([w])
    await refusedWith(jobCommand(['clawback', s.j.id, '--chain', 'eth', '--to', DEST, '--backup-eth', f], mkIo().io, { run: depsFor(s, t) }), 'arm.amount', /typed amount is not exactly 0\.3 ETH \(= 300000000000000000 wei\)/)
    assert.match(t.asked.words[0], /^eth: the remainder is over what is left of the cap confirmed at Arm\. Type 0\.3 to approve clawing back exactly this amount \(300000000000000000 wei\): $/)
    nothingSigned(s)
  }
  const t = term(['0.30'])
  const c = mkIo()
  assert.equal(await jobCommand(['clawback', s.j.id, '--chain', 'eth', '--to', DEST, '--backup-eth', f], c.io, { run: depsFor(s, t) }), 0, c.all())
  const cs = s.j.state().chains.eth!
  assert.deepEqual([cs.phase, cs.clawback!.landed, cs.clawback!.to], ['CLAWED_BACK', true, DEST])
  const i = s.j.events.find((e) => e.type === 'clawback-intent')!
  assert.equal(BigInt(i.data.value as string) + 21_000n * BigInt((i.data.eth as { maxFee: string }).maxFee), 3n * 10n ** 17n, 'value + worst-case fee = the typed amount')
  assert.match(c.all(), /remainder \(value \+ fee\) 0\.3 ETH \(= 300000000000000000 wei\); left of the armed cap 0\.1 ETH/)
  assert.match(c.all(), /gas 21000: the destination is an existing account/)
  assert.match(c.all(), /warning: this claw-back links the lane key .* on-chain, publicly and for good \(R47\/R57\)/)
  assert.match(c.all(), /^eth: clawed-back/m)
  clean(c.all(), s.key.handle)
  // and again: already clawed back, nothing asked
  const t2 = term()
  const c2 = mkIo()
  assert.equal(await jobCommand(['clawback', s.j.id, '--chain', 'eth', '--to', DEST, '--backup-eth', f], c2.io, { run: depsFor(s, t2) }), 0)
  assert.match(c2.all(), /^eth: already clawed back/m)
  assert.equal(t2.asked.passphrase, 0)
})

test('under the armed cap: no amount is asked; no clawbackConfirm rides (a confirm on a fitting claw-back would be refused)', async () => {
  const s = settled({ balance: 3n * 10n ** 17n, cap: '1000000000000000000' })
  const t = term()
  const c = mkIo()
  assert.equal(await jobCommand(['clawback', s.j.id, '--chain', 'eth', '--to', DEST, '--backup-eth', await backup(s.key.handle)], c.io, { run: depsFor(s, t) }), 0, c.all())
  assert.deepEqual(t.asked.words, [])
  assert.equal(s.j.state().chains.eth!.phase, 'CLAWED_BACK')
})

test('a contract destination is refused (job.clawback) after the relay classifies it; nothing signed', async () => {
  const s = settled({ code: true })
  await refusedWith(jobCommand(['clawback', s.j.id, '--chain', 'eth', '--to', DEST, '--backup-eth', await backup(s.key.handle)], mkIo().io, { run: depsFor(s, term()) }), 'job.clawback', /is a contract/)
  nothingSigned(s)
})

// M2 FLIP (applied, operator R78): the real job-send lock no longer refuses a mainnet claw-back; the typed words still do.
test('mainnet: the linkage warning, then `claw back` typed (job.clawback-typed otherwise, nothing signed); the real job-send lock is lifted (the M2 flip) and refuses nothing', async () => {
  const s = settled({ network: 'mainnet', cap: '1000000000000000000' })
  const f = await backup(s.key.handle, 'mainnet')
  // the real lock first: lifted, so the claw-back goes on to the typed word, which refuses (no word typed); nothing signed
  const lifted = term()
  await refusedWith(jobCommand(['clawback', s.j.id, '--chain', 'eth', '--to', DEST, '--backup-eth', f], mkIo('mainnet').io, { run: depsFor(s, lifted) }), 'job.clawback-typed')
  assert.match(lifted.asked.words.at(-1)!, /^MAINNET: real funds\. Type claw back to send/)
  nothingSigned(s)
  for (const w of [undefined, 'clawback', 'Claw back', 'claw  back']) {
    const t = term([w])
    const c = mkIo('mainnet')
    await refusedWith(jobCommand(['clawback', s.j.id, '--chain', 'eth', '--to', DEST, '--backup-eth', f], c.io, { run: depsFor(s, t, { assertSendAllowed: () => {} }) }), 'job.clawback-typed')
    assert.match(t.asked.words.at(-1)!, /^MAINNET: real funds\. Type claw back to send 0\.3 ETH \(value \+ fee\) to 0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6: $/)
    assert.match(c.all(), /links the lane key .* on-chain/)
    nothingSigned(s)
  }
  const t = term(['claw back'])
  const c = mkIo('mainnet')
  assert.equal(await jobCommand(['clawback', s.j.id, '--chain', 'eth', '--to', DEST, '--backup-eth', f], c.io, { run: depsFor(s, t) }), 0, c.all())   // the real lock: lifted
  assert.equal(s.j.state().chains.eth!.phase, 'CLAWED_BACK')
})

test('SOL: the plain-transfer note, under the cap no amount asked, then the executor\'s claw-back (its outcome on real chains: run-real.test.ts)', async () => {
  const dest = (newKey('sol') as unknown as Handle).address
  const s = stack('sol', { copies: 1, startIn: 0, cap: '100000000000' })
  void s.j.client.lease(s.j.id, 'sol', 'acquire', 'browser')
  s.j.asHolder(2, 'browser', 'sol', 'stopped', { reason: 'operator' })
  s.j.expire('sol')
  const t = term()
  const c = mkIo()
  const loaded: Array<{ kp?: { _keypair: { secretKey: Uint8Array } } }> = []
  // the in-memory SOL chain cannot measure the transfer, so the engine leaves the claw-back open (failed, exit 1)
  assert.equal(await jobCommand(['clawback', s.j.id, '--chain', 'sol', '--to', dest, '--backup-sol', await backup(s.key.handle)], c.io, { run: depsFor(s as S, t, { onKey: (k) => { loaded.push(k.handle as never) } }) }), 1, c.all())
  assert.ok(loaded.length === 1 && loaded[0].kp!._keypair.secretKey.every((b) => b === 0), 'the key is dropped (zeroed) on exit')
  assert.match(c.all(), /a plain transfer of balance − fee: the lane ends at 0 lamports/)
  assert.deepEqual(t.asked.words, [], 'under the cap: nothing typed')
  const i = s.j.events.find((e) => e.type === 'clawback-intent')
  assert.ok(i !== undefined && i.data.to === dest, 'the executor signed the claw-back to the destination')
  assert.match(c.all(), /^sol: failed — claw back: landed, but the transfer to the destination cannot be measured/m)
  // review m-2: it ended otherwise than clawed-back after this run journaled the claw-back intent
  assert.match(c.all(), /^sol: stopped unexpectedly after sending — run `vt job clawback` again to reconcile \(nothing will be sent twice\)$/m)
  clean(c.all(), s.key.handle)
})

// ---- fix round 1 (task-C6-review.md m-3, m-5)

test('review m-3: what is left of the cap counts what the chain already spent — cap − spent < remainder ≤ cap: the amount is typed and rides as clawbackConfirm (the API refuses the claw-back otherwise)', async () => {
  const k = newKey('eth') as unknown as Handle
  const bal0 = 3n * 10n ** 17n
  // one copy lands first (its fee is spent), under an armed cap 1 wei below the lane's first balance
  const s = stack('eth', { key: k as never, copies: 1, startIn: 0, ethBalance: bal0, cap: String(bal0 - 1n) })
  const f = await backup(k)
  const c0 = mkIo()
  assert.equal(await jobCommand(['run', s.j.id, '--backup-eth', f], c0.io, { run: depsFor(s as S, term()) }), 0, c0.all())
  const cs = s.j.state().chains.eth!
  const spent = BigInt(cs.spent), cap = bal0 - 1n, remainder = bal0 - spent
  assert.equal(cs.phase, 'COPIES_DONE')
  assert.ok(spent > 0n && cap - spent < remainder && remainder <= cap, 'the remainder fits the cap, not what is left of it')
  const shown = formatUnits(remainder, 18)
  const t = term([shown])
  const c = mkIo()
  assert.equal(await jobCommand(['clawback', s.j.id, '--chain', 'eth', '--to', DEST, '--backup-eth', f], c.io, { run: depsFor(s as S, t) }), 0, c.all())
  assert.equal(t.asked.words.length, 1, 'the amount was asked')
  assert.equal(t.asked.words[0], `eth: the remainder is over what is left of the cap confirmed at Arm. Type ${shown} to approve clawing back exactly this amount (${remainder} wei): `)
  assert.ok(c.all().includes(`; left of the armed cap ${formatUnits(cap - spent, 18)} ETH`), c.all())
  assert.equal(s.j.state().chains.eth!.phase, 'CLAWED_BACK')
  clean(c.all(), k)
})

test('review m-5: an ETH precompile or reserved system address (0x…0001 to 0x…ffff) is refused (job.clawback-precompile) before any key is touched; 0x…010000 is not', async () => {
  const lane = newKey('eth') as unknown as Handle
  // the EIP-55 form of a low address (core's validator names it when given the lowercase one)
  const at = (n: bigint): string => {
    const low = `0x${n.toString(16).padStart(40, '0')}`
    const v = validateEthDest(low, '')
    return v.ok ? v.address : /expected (0x[0-9a-fA-F]{40})/.exec(v.why)![1]
  }
  for (const n of [1n, 2n, 9n, 0x0an, 0x11n, 0x100n, 0x1234n, 0xfffen, 0xffffn]) {
    assert.throws(() => checkDestination('eth', at(n), lane.address, null), (e: Error & { guardId?: string }) => e.guardId === 'job.clawback-precompile', n.toString(16))
  }
  for (const n of [0x10000n, 0x10001n]) assert.equal(checkDestination('eth', at(n), lane.address, null), at(n))
  assert.throws(() => checkDestination('eth', '0x0000000000000000000000000000000000000000', lane.address, null), (e: Error & { guardId?: string }) => e.guardId === 'job.clawback')
  const z = settled()
  const t = term()
  await refusedWith(jobCommand(['clawback', z.j.id, '--chain', 'eth', '--to', at(0x11n), '--backup-eth', 'never-read.age'], mkIo().io, { run: depsFor(z, t) }), 'job.clawback-precompile', /precompile/)
  assert.equal(t.asked.passphrase, 0)
  nothingSigned(z)
})

void Refusal

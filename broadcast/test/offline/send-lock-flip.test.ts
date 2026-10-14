// C2 review I-1: lifting one mainnet lock never lifts the other, at the lock AND at the net layer.
// Each test copies src/ into a temp dir, sets the two lock lines there — the named one `= true`, the other `= false` — and
// imports the copy's config.ts and net/fetch.ts (a separate module instance, so its permits are its own). The real tree is
// never edited. The copy's state never depends on the real tree's (PF-S fix round 1, N-3): after the operator-approved M2
// flip (MAINNET_JOB_SENDS_ENABLED = true in src/) both tests pass unedited, and the flip commit does not touch this file. With MAINNET_JOB_SENDS_ENABLED lifted (the planned M2 flip), a mainnet job permit exists, and
// createNet must still refuse every non-job send class (Turbo, Arweave, Esplora POST /tx, bitcoind, requestAirdrop,
// query-string and non-JSON sends, ...): those stay behind MAINNET_SEND_ENABLED (Flow 1 / funding).
// Offline: a recording test transport, loopback URL strings, no socket, no key.
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { cpSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import type * as Config from '../../src/config.ts'
import type * as Fetch from '../../src/net/fetch.ts'
import { assertSendAllowed as realAssertSendAllowed, GENESIS } from '../../src/config.ts'
import { NON_JOB_SENDS, READS, SENDS, recorder } from './send-lock-fixtures.ts'

const ROOT = new URL('../../', import.meta.url).pathname
const made: string[] = []
after(() => { for (const d of made) rmSync(d, { recursive: true, force: true }) })

// The copy's Refusal is another class: match by name and guard id.
const isRefusal = (id: string) => (e: unknown) => e instanceof Error && e.name === 'Refusal' && (e as { guardId?: unknown }).guardId === id
const refused = (f: () => unknown, id: string, why = '') => assert.throws(f, isRefusal(id), `expected ${id} ${why}`)
const rejects = (p: Promise<unknown>, id: string, why = '') => assert.rejects(p, isRefusal(id), `expected ${id} ${why}`)

let seq = 0
const fresh = (): string => `${new Date(Date.UTC(2026, 9, 9, 9, 0) + ++seq * 60_000).toISOString().slice(0, 16)}Z`

async function flipped(name: 'MAINNET_SEND_ENABLED' | 'MAINNET_JOB_SENDS_ENABLED'): Promise<{ c: typeof Config; f: typeof Fetch }> {
  const d = mkdtempSync(join(tmpdir(), 'vt-flip-'))
  made.push(d)
  cpSync(join(ROOT, 'src'), join(d, 'src'), { recursive: true })
  writeFileSync(join(d, 'package.json'), '{ "type": "module" }\n')
  symlinkSync(realpathSync(join(ROOT, 'node_modules')), join(d, 'node_modules'))
  const file = join(d, 'src/config.ts')
  const lines = readFileSync(file, 'utf8').split('\n')
  for (const flag of ['MAINNET_SEND_ENABLED', 'MAINNET_JOB_SENDS_ENABLED'] as const) {
    const at = lines.flatMap((l, i) => (l === `export const ${flag} = false` || l === `export const ${flag} = true` ? [i] : []))
    assert.equal(at.length, 1, `exactly one ${flag} line in src/config.ts`)
    lines[at[0]] = `export const ${flag} = ${flag === name}`
  }
  writeFileSync(file, lines.join('\n'))
  const url = (p: string): string => pathToFileURL(join(d, p)).href
  const c = await import(url('src/config.ts')) as typeof Config
  const f = await import(url('src/net/fetch.ts')) as typeof Fetch
  return { c, f }
}

test('job lock lifted (copy): a mainnet job permit covers only the ETH/SOL job sends; every other class stays closed', async () => {
  const { c, f } = await flipped('MAINNET_JOB_SENDS_ENABLED')
  assert.equal(c.MAINNET_JOB_SENDS_ENABLED, true)
  assert.equal(c.MAINNET_SEND_ENABLED, false)
  // The all-scope lock does not move.
  refused(() => c.assertSendAllowed('mainnet'), 'release.mainnet-locked')
  refused(() => c.assertSendAllowed('mainnet', { chain: 'eth', id: '0x1' }), 'release.mainnet-locked')
  refused(() => c.assertSendAllowed('testnet', { chain: 'eth', id: '1' }), 'release.mainnet-locked')
  // The job lock is lifted for the mainnet profile and mainnet identities only.
  const permits = [
    c.assertJobSendAllowed('mainnet'), c.assertJobSendAllowed('mainnet', { chain: 'eth', id: '0x1' }),
    c.assertJobSendAllowed('mainnet', { chain: 'sol', id: GENESIS.sol.mainnet }),
  ]
  for (const p of permits) assert.deepEqual([p.profile, p.scope, c.isSendPermit(p)], ['mainnet', 'job', true])
  refused(() => c.assertJobSendAllowed('mainnet', { chain: 'eth', id: '11155111' }), 'config.identity-mismatch')
  refused(() => c.assertJobSendAllowed('testnet', { chain: 'eth', id: '1' }), 'release.mainnet-locked')
  // PF-S M-1 (pre-flip review): mainnet BTC stays locked after the flip — a btc send off local takes the all-scope lock
  // (MAINNET_SEND_ENABLED, still false), so the relay's Esplora POST /tx on mainnet is refused; testnet4 and local BTC are unchanged
  for (const id of [c.GENESIS.btc.mainnet, c.GENESIS.btc.mainnet.toUpperCase()]) {
    assert.throws(() => c.assertJobSendAllowed('mainnet', { chain: 'btc', id }), (e: unknown) => isRefusal('release.mainnet-locked')(e) && /MAINNET_SEND_ENABLED\)/.test((e as Error).message), id)
  }
  refused(() => c.assertJobSendAllowed('testnet', { chain: 'btc', id: c.GENESIS.btc.mainnet }), 'release.mainnet-locked')
  assert.equal(c.assertJobSendAllowed('testnet', { chain: 'btc', id: c.GENESIS.btc.testnet4 }).scope, 'job')
  assert.equal(c.assertJobSendAllowed('local', { chain: 'btc', id: c.GENESIS.btc.regtest }).scope, 'job')
  // The net layer: non-job classes refused with the mainnet job permit, job sends and reads pass.
  for (const permit of permits) {
    const t = recorder()
    const net = f.createNet({ tick: fresh(), transport: t, permit })
    for (const s of NON_JOB_SENDS) await rejects(net.fetchFor('pub-j1-eth')(s.url, s.init), 'net.send-permit', s.why)
    assert.equal(t.calls.length, 0, 'no non-job send reached the transport')
    const jobs = SENDS.filter((s) => s.cls === 'job')
    for (const s of jobs) assert.equal((await net.fetchFor('pub-j1-eth')(s.url, s.init)).status, 200, s.why)
    for (const r of READS) assert.equal((await net.fetchFor('pub-j1-eth')(r.url, r.init)).status, 200, r.why)
    assert.equal(t.calls.length, jobs.length + READS.length)
  }
  // A permit from the real tree is not one of the copy's.
  refused(() => f.createNet({ tick: fresh(), transport: recorder(), permit: realAssertSendAllowed('testnet') }), 'net.send-permit')
})

test('all lock lifted (copy): the job lock stays shut; a mainnet all permit covers every send class', async () => {
  const { c, f } = await flipped('MAINNET_SEND_ENABLED')
  assert.equal(c.MAINNET_SEND_ENABLED, true)
  assert.equal(c.MAINNET_JOB_SENDS_ENABLED, false)
  refused(() => c.assertJobSendAllowed('mainnet'), 'release.mainnet-locked')
  refused(() => c.assertJobSendAllowed('mainnet', { chain: 'eth', id: '1' }), 'release.mainnet-locked')
  // M-1: a mainnet btc job send passes the all-scope lock here and is still refused by the job lock (both must be lifted)
  refused(() => c.assertJobSendAllowed('mainnet', { chain: 'btc', id: c.GENESIS.btc.mainnet }), 'release.mainnet-locked')
  const p = c.assertSendAllowed('mainnet', { chain: 'eth', id: '1' })
  assert.deepEqual([p.profile, p.scope], ['mainnet', 'all'])
  const t = recorder()
  const net = f.createNet({ tick: fresh(), transport: t, permit: p })
  for (const s of SENDS) assert.equal((await net.fetchFor('pub-j1-eth')(s.url, s.init)).status, 200, s.why)
  assert.equal(t.calls.length, SENDS.length)
})

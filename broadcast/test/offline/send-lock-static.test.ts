// M1a (spec B §6.5) + the job scope (canonical spec §12): the two mainnet locks are code constants. This test reads
// src/config.ts as text and requires the exact lines
//   export const MAINNET_SEND_ENABLED = false
//   export const MAINNET_JOB_SENDS_ENABLED = true
// so changing either lock is an explicit commit that also changes this file (MAINNET_JOB_SENDS_ENABLED was lifted by the
// operator-approved canonical plan Task M2 Step 6 commit, R78; MAINNET_SEND_ENABLED stays false). It also pins that each
// lock reads its own constant, that nothing else in src/ defines or assigns them, and that permits are issued in one
// place only.
// C2 review I-3: the decision itself is pinned too. lock() must hold its two decision lines exactly, its text must
// hash to LOCK_SHA256 (any edit to it, an env/global/file override included, must also edit this file), and neither
// it, the two entry points, nor the helpers it calls may touch the environment, globals, files or dynamic loading.
// R71: the Amsterdam facts in src/config.ts must agree with packages/core's network table (contracts/network.ts). That
// check imports a file outside broadcast/, so this file is mapped to no mutation guard (the runner copies broadcast/
// alone).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { ETH_AMSTERDAM_TIME, PROFILES } from '../../src/config.ts'

const ROOT = new URL('../../', import.meta.url).pathname
const CONFIG = join(ROOT, 'src/config.ts')
const text = readFileSync(CONFIG, 'utf8')
const lines = text.split('\n')

const LOCKS = ['export const MAINNET_SEND_ENABLED = false', 'export const MAINNET_JOB_SENDS_ENABLED = true']

function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir).sort()) {
    const p = join(dir, n)
    if (statSync(p).isDirectory()) walk(p, out)
    else out.push(p)
  }
  return out
}

// The text of `[export ]function <name>(` up to its closing line `}`.
function body(name: string): string {
  const m = new RegExp(`^(?:export )?function ${name}\\([^]*?\\n\\}$`, 'm').exec(text)
  assert.ok(m !== null, `${name} not found in src/config.ts`)
  return m[0]
}

test('src/config.ts holds both lock lines exactly, once each', () => {
  for (const l of LOCKS) assert.equal(lines.filter((x) => x === l).length, 1, `exactly one line: ${l}`)
})

test('nothing in src/ or bin/ declares or assigns the lock names except those two lines', () => {
  const hits: string[] = []
  for (const f of [...walk(join(ROOT, 'src')), ...walk(join(ROOT, 'bin'))]) {
    readFileSync(f, 'utf8').split('\n').forEach((l, i) => {
      const t = l.trim()
      if (t.startsWith('//')) return
      if (/\bMAINNET_(?:JOB_)?SENDS?_ENABLED\b\s*(?:=(?!=)|:)/.test(l) && !LOCKS.includes(l)) hits.push(`${relative(ROOT, f)}:${i + 1}`)
      if (/\b(?:let|var)\s+MAINNET_|MAINNET_(?:JOB_)?SENDS?_ENABLED\s+as\b/.test(l)) hits.push(`${relative(ROOT, f)}:${i + 1}`)
    })
  }
  assert.deepEqual(hits, [])
})

test('each lock reads its own constant; the one lock() is called only by them; permits are issued in one place', () => {
  const all = body('assertSendAllowed')
  const job = body('assertJobSendAllowed')
  assert.match(all, /\breturn lock\(MAINNET_SEND_ENABLED, 'all', ID_CHAINS, profile, observed\)/)
  assert.doesNotMatch(all, /MAINNET_JOB_SENDS_ENABLED|\btrue\b/)
  assert.match(job, /\breturn lock\(MAINNET_JOB_SENDS_ENABLED, 'job', JOB_CHAINS, profile, observed\)/)
  assert.doesNotMatch(job, /MAINNET_SEND_ENABLED|\btrue\b/)
  const calls = lines.filter((l) => /\block\(/.test(l) && !l.trim().startsWith('//'))
  assert.equal(calls.length, 3, `the definition and two calls: ${calls.join(' | ')}`)
  assert.equal(lines.filter((l) => /^function lock\(/.test(l)).length, 1, 'lock is not exported')
  assert.equal(lines.filter((l) => l.includes('ISSUED.add(')).length, 1)
  assert.equal(lines.filter((l) => /^const ISSUED = new WeakSet<object>\(\)$/.test(l)).length, 1, 'ISSUED is module-private')
  assert.doesNotMatch(text, /export\s*\{[^}]*\b(?:ISSUED|lock)\b/)
})

test('R71: the Amsterdam facts agree with packages/core\'s network table (ETH_FORKS)', async () => {
  const net = new URL('../../../packages/core/src/contracts/network.ts', import.meta.url)
  assert.ok(existsSync(net), 'packages/core/src/contracts/network.ts exists next to broadcast/')
  const { ETH_FORKS } = await import(net.href) as { ETH_FORKS: Record<string, { amsterdam: boolean }> }
  assert.deepEqual(Object.keys(ETH_FORKS).sort(), [...PROFILES].sort())
  for (const n of PROFILES) assert.equal(ETH_FORKS[n].amsterdam, ETH_AMSTERDAM_TIME[n] !== null, `${n}: amsterdam flag vs amsterdamTime`)
  assert.equal(ETH_FORKS.testnet.amsterdam, true)
  assert.equal(ETH_FORKS.mainnet.amsterdam, false, 'mainnet has no Amsterdam time yet')
  assert.ok((ETH_AMSTERDAM_TIME.testnet as number) * 1000 <= Date.now(), 'Sepolia Amsterdam (2026-10-06 13:53 UTC) is in the past')
})

// ---- C2 review I-3: the lock decision

// sha256 of lock()'s text, from `function lock(` to its closing `}`. Changing lock() in any way means changing this
// constant in the same commit, so an override cannot ride in unnoticed.
const LOCK_SHA256 = '8429a33238b882e559b33913171c962b786d163a2ea3459dafc834960a4ddf44'
const DECISION = [
  '  const mainnetOk = profile === \'mainnet\' && enabled',
  '  const ok = (profile === \'testnet\' || profile === \'local\' || mainnetOk) && (!mainnetSeen || mainnetOk)',
]
// What the lock functions and the helpers they call must never mention: the environment, globals, argv, files,
// dynamic loading, eval.
const OVERRIDE = /\b(?:process|env|globalThis|global|window|self|argv|require|eval|Function|Reflect|Deno|Bun|fs|readFileSync|readFile|openSync|existsSync|statSync|loadConfig)\b|import\s*\(|import\.meta/
const LOCK_PATH = [
  'lock', 'assertSendAllowed', 'assertJobSendAllowed', 'assertProfile', 'isMainnetIdentity', 'identityMatches', 'evmId',
  'isLocalSolanaGenesis', 'base58Length', 'isRecord', 'isSendPermit',
]

test('I-3: lock() holds its two decision lines exactly, and its text is pinned by sha256', () => {
  const lock = body('lock')
  for (const l of DECISION) {
    assert.equal(lines.filter((x) => x === l).length, 1, `exactly one line in config.ts: ${l}`)
    assert.ok(lock.split('\n').includes(l), `inside lock(): ${l}`)
  }
  const ok = lock.split('\n').findIndex((l) => l === DECISION[1])
  assert.match(lock.split('\n')[ok + 1], /^ {2}if \(!ok\) refuse\('release\.mainnet-locked', /, 'the refusal follows the decision directly')
  assert.equal(createHash('sha256').update(lock).digest('hex'), LOCK_SHA256, 'lock() changed: review it for overrides, then update LOCK_SHA256')
})

test('I-3: the lock functions and their helpers touch no environment, global, file or loader', () => {
  for (const name of LOCK_PATH) {
    const hit = body(name).split('\n').filter((l) => OVERRIDE.test(l))
    assert.deepEqual(hit, [], `${name} mentions an override source`)
  }
  // The scanner bites (synthetic lines).
  for (const l of ['enabled || process.env.VT_MAINNET_SENDS === \'1\'', 'enabled || globalThis.__vtMainnet === true', 'readFileSync(\'x\')', 'await import(x)', 'import.meta.url', 'Reflect.get(o, k)']) {
    assert.ok(OVERRIDE.test(l), l)
  }
})

// packages/core/contract/static.contract.test.ts — repository-wide static rules every lane runs (`npm run contract`).
// Each scan passes vacuously on directories that do not exist yet. Scope: the canonical workspaces (packages/**, api/**,
// cli/**, web/src/**) and scripts/**; broadcast/ has its own static tests. Exempt everywhere: node_modules, dist and
// packages/core/contract/** (this file, the fixtures and the vector tests name the forbidden strings on purpose).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { basename, join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('../../../', import.meta.url))
const SKIP_DIRS = new Set(['node_modules', 'dist', '.git', '.tmp', '.vite'])
const CODE = /\.(?:ts|tsx|js|jsx|mjs|cjs|sh)$/
const TEXT = /\.(?:ts|tsx|js|jsx|mjs|cjs|sh|json|html|css)$/

function walk(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) return out
  for (const name of readdirSync(dir).sort()) {
    if (SKIP_DIRS.has(name)) continue
    const p = join(dir, name)
    if (statSync(p).isDirectory()) walk(p, out)
    else out.push(p)
  }
  return out
}
const rel = (p: string): string => relative(ROOT, p).split(sep).join('/')
const inBin = (r: string): boolean => /(^|\/)bin\/[^/]+$/.test(r)
function files(roots: string[], accept: RegExp): string[] {
  return roots.flatMap((r) => walk(join(ROOT, r))).map(rel)
    .filter((r) => !r.startsWith('packages/core/contract/') && r !== 'package-lock.json' && (accept.test(r) || inBin(r)))
}
const read = (r: string): string => readFileSync(join(ROOT, r), 'utf8')
const isTest = (r: string): boolean => r.split('/').includes('test')
const WORKSPACES = ['packages', 'api', 'cli', 'web/src']

function offenders(list: string[], re: RegExp, allowed: (r: string) => boolean = () => false): string[] {
  return list.filter((r) => !allowed(r) && re.test(read(r)))
}

test('1. send-type RPC names only in the chain modules, the relay and tests', () => {
  const allowed = (r: string): boolean => isTest(r) || r === 'packages/core/src/chains/eth.js' || r === 'packages/core/src/chains/sol.js'
    || r.startsWith('api/relay/') || r === 'api/src/relay-gate.ts'
  assert.deepEqual(offenders(files(WORKSPACES, CODE), /eth_sendRawTransaction|['"`]sendTransaction['"`]/, allowed), [])
})

test('2. no browser storage APIs in web/src or packages/core/src', () => {
  assert.deepEqual(offenders(files(['web/src', 'packages/core/src'], CODE), /\b(?:localStorage|sessionStorage|indexedDB)\b|document\.cookie/), [])
})

test('3. no window.confirm / alert / prompt in web/src', () => {
  assert.deepEqual(offenders(files(['web/src'], CODE), /\bwindow\.(?:confirm|alert|prompt)\b/), [])
})

test('4. no node: imports in packages/core/src except the node adapter', () => {
  const re = /\bfrom\s+['"]node:|\bimport\s*\(\s*['"]node:|\brequire\s*\(\s*['"]node:/
  assert.deepEqual(offenders(files(['packages/core/src'], CODE), re, (r) => r === 'packages/core/src/executor/adapters/node.ts'), [])
})

// Strict dotted quads (each part 0-255, no leading zeros beyond "0").
const QUAD = /(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?!\d|\.\d)/g
const TEST_NET = /^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d+$/

test('5. IPv4 literals: only loopback and 0.0.0.0 in sources; TEST-NET-1 192.0.2.1 only in confinement probes; documentation ranges (incl. the canary) only in tests', () => {
  const bad: string[] = []
  for (const r of files(WORKSPACES, TEXT)) {
    const confine = basename(r).includes('confine') || r === 'packages/core/src/executor/adapters/node.ts'
    for (const ip of read(r).match(QUAD) ?? []) {
      if (ip === '127.0.0.1' || ip === '0.0.0.0') continue
      if (ip === '192.0.2.1' && (confine || isTest(r))) continue
      if (TEST_NET.test(ip) && isTest(r)) continue
      bad.push(`${r}: ${ip.startsWith('203.0.113.') ? 'the canary' : 'an IPv4 literal'}`) // never print the address itself
    }
  }
  assert.deepEqual(bad, [])
})

test('5b. nothing listens on 0.0.0.0', () => {
  assert.deepEqual(offenders(files(WORKSPACES, CODE), /\blisten\s*\([^)]*0\.0\.0\.0/), [])
})

test('6. no pkill or killall in cli or scripts', () => {
  assert.deepEqual(offenders(files(['cli', 'scripts'], TEXT), /\b(?:pkill|killall)\b/), [])
})

test('7. the Alchemy key name appears only in tests (which assert its absence)', () => {
  assert.deepEqual(offenders(files([...WORKSPACES, 'scripts'], TEXT), /ALCHEMY/, isTest), [])
})

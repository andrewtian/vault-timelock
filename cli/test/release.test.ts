// cli/test/release.test.ts — `vt release build | verify | list`, and mainnet only from a verified release
// (src/ops/release.ts, up.ts, cli/scripts/release.sh; plan Task C4), in the suite sandbox (phase A).
// Every release here is built from a SYNTHETIC git repository made in a temp dir:
//   · this workspace's cli/ (bin, src, package.json, test/fixtures): a mutated guard reaches the release it builds;
//   · the real packages/core and broadcast sources, found through this workspace's node_modules links;
//   · synthetic api servers and SYNTHETIC sealer stubs (never the real 1password-timelock.sh / timelock-key.sh);
//   · a synthetic node_modules: an npm linked store plus broadcast's own hoisted install, with two versions of one
//     package, a peer dependency, a missing optional one, package-root test/ dirs, *.test.* files and dev-only
//     packages (typescript, @types/node);
//   · tracked files that must stay out (tests, fixtures, harness names, docs) and untracked ones (state, notes).
// The page is a fake (the real, sandboxed vite build is test/release-real.test.ts, phase B). Tor is never reached:
// inside the suite sandbox 127.0.0.1:9050 is denied, and the in-process runs give a fake probe.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  appendFileSync, chmodSync, cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, readlinkSync, realpathSync, renameSync,
  rmSync, symlinkSync, unlinkSync, writeFileSync,
} from 'node:fs'
import { dirname, join, relative } from 'node:path'
import {
  BUILD_ID, COPY, assertNoHiddenIndexFlags, assertNoLockDrift, assertVerified, build, computeBuildId, hiddenIndexEntries, installDrift, isReleaseSource, list,
  TEST_OVERRIDE_ALLOWED, lookupChain, outsideSources, readCommitTree, removeTree, verify,
} from '../src/ops/release.ts'
import type { BuildResult } from '../src/ops/release.ts'
import { systemTmux } from '../src/ops/tmux.ts'
import { assertMainnetAllowed, up } from '../src/ops/up.ts'
import { FAULT_CANARY_KEY, FAULT_MARKER } from './fixtures/fault-hook.ts'
import { CANARY, CLI, NODE, PATH0, assertTorDenied, fakeTmux, refused, rejectsWith, run, tempDir, throwsWith, writeExe } from './lib.ts'
import type { FakeTmux, Run } from './lib.ts'

const REAL_CORE = realpathSync(join(CLI, 'node_modules', '@vault-timelock', 'core'))
const REAL_BCAST = realpathSync(join(CLI, 'node_modules', 'vt-broadcast'))
// core's contracts hash with @noble/hashes at runtime: the real package (no dependencies of its own) is copied in.
const REAL_NOBLE = realpathSync(join(REAL_CORE, 'node_modules', '@noble', 'hashes'))
const NOBLE_VERSION = (JSON.parse(readFileSync(join(REAL_NOBLE, 'package.json'), 'utf8')) as { version: string }).version
const SEALER = (name: string): string => `#!/bin/sh\n# ${name}: a SYNTHETIC stub for the release tests, not the real sealer\necho 'synthetic sealer stub' >&2\nexit 3\n`
const PAGE = '<!doctype html><title>synthetic release page</title>\n'
const fakeWeb = (_repo: string, out: string): void => { writeFileSync(join(out, 'index.html'), PAGE) }

let T = ''
let HOME0 = ''
let REPO = ''
let F: FakeTmux
let FIRST: BuildResult
const envOf = (home: string): Record<string, string> => ({ PATH: PATH0, HOME: HOME0, LANG: 'C', TERM: 'dumb', VT_HOME: home, VAULT_TIMELOCK_DIR: join(T, 'out') })
let homes = 0
const newHome = (): string => {
  const h = join(T, `vt-home-${++homes}`)
  mkdirSync(h, { mode: 0o700 })
  return h
}
const buildIn = (home: string, repo = REPO): BuildResult => build({ repo, env: envOf(home), buildWeb: fakeWeb })
const fresh = (): BuildResult => buildIn(newHome())

function git(repo: string, ...args: string[]): string {
  const r = spawnSync('git', ['-C', repo, '-c', 'user.name=synthetic', '-c', 'user.email=synthetic@example.invalid', '-c', 'commit.gpgsign=false',
    '-c', 'init.defaultBranch=main', ...args], { env: { PATH: PATH0, HOME: HOME0, LANG: 'C' }, encoding: 'utf8' })
  assert.equal(r.status, 0, r.stderr)
  return r.stdout
}

const sha256hex = (b: Buffer): string => createHash('sha256').update(b).digest('hex')
const headOf = (repo: string): string => git(repo, 'rev-parse', 'HEAD').trim()
const headId = (repo: string): string => computeBuildId(readCommitTree(repo, headOf(repo), envOf(join(T, 'unused'))))
// A file as the commit has it (never the working tree).
function blob(repo: string, rev: string, path: string): Buffer {
  const r = spawnSync('git', ['-C', repo, 'cat-file', 'blob', `${rev}:${path}`], { env: { PATH: PATH0, HOME: HOME0 } })
  assert.equal(r.status, 0, String(r.stderr))
  return r.stdout
}

// ---- the synthetic repository

// A package whose index.js reports the tree of packages it resolved: { "<name>@<version>": { <dep>: <its tree> } }.
function fakePackage(dir: string, name: string, version: string, o: { deps?: Record<string, string>; peer?: Record<string, string>; opt?: Record<string, string>; imports?: string[] } = {}): void {
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'package.json'), `${JSON.stringify({ name, version, type: 'module', exports: { '.': './index.js' }, dependencies: o.deps, peerDependencies: o.peer, optionalDependencies: o.opt })}\n`)
  const imports = o.imports ?? []
  writeFileSync(join(dir, 'index.js'), `${imports.map((d, i) => `import { tree as t${i} } from '${d}'\n`).join('')}export const tree = { '${name}@${version}': { ${imports.map((d, i) => `'${d}': t${i}`).join(', ')} } }\n`)
}
const store = (repo: string, name: string, version: string): string => join(repo, 'node_modules', '.store', `${name}@${version}-synthetic`, 'node_modules', name)
function link(target: string, at: string): void {
  mkdirSync(dirname(at), { recursive: true })
  symlinkSync(relative(dirname(at), target), at)
}

function makeRepo(root: string): string {
  const r = join(root, 'repo')
  // cli/: this workspace's (the mutation runner's copy, under mutation)
  for (const d of ['bin', 'src', 'package.json', join('test', 'fixtures')]) cpSync(join(CLI, d), join(r, 'cli', d), { recursive: true, verbatimSymlinks: true })
  writeFileSync(join(r, 'cli', 'test', 'synthetic.test.ts'), '// a tracked test: never in a release\n')
  mkdirSync(join(r, 'cli', 'scripts'), { recursive: true })
  writeFileSync(join(r, 'cli', 'scripts', 'notes.sh'), '# cli/scripts stays out of a release\n')
  // packages/core: the real sources and exports, synthetic dependencies
  const coreJson = JSON.parse(readFileSync(join(REAL_CORE, 'package.json'), 'utf8')) as Record<string, unknown>
  cpSync(join(REAL_CORE, 'src'), join(r, 'packages', 'core', 'src'), { recursive: true })
  writeFileSync(join(r, 'packages', 'core', 'package.json'), `${JSON.stringify({ name: coreJson.name, version: coreJson.version, private: true, type: 'module', exports: coreJson.exports,
    dependencies: { '@noble/hashes': NOBLE_VERSION, shared: '1.0.0', 'dep-a': '1.0.0', 'peer-user': '1.0.0', 'opt-user': '1.0.0' }, devDependencies: { typescript: '5.9.3' } }, null, 2)}\n`)
  // broadcast: the real sources, bin, vendor and endpoint files; synthetic dependencies
  for (const d of ['src', 'bin', 'vendor', 'endpoints.json', 'anchors.json']) cpSync(join(REAL_BCAST, d), join(r, 'broadcast', d), { recursive: true })
  writeFileSync(join(r, 'broadcast', 'package.json'), `${JSON.stringify({ name: 'vt-broadcast', private: true, type: 'module',
    dependencies: { shared: '2.0.0', 'dep-b': '1.0.0', '@vault-timelock/core': 'file:../packages/core' },
    devDependencies: { typescript: '5.9.3', '@types/node': '24.19.1' } }, null, 2)}\n`)
  mkdirSync(join(r, 'broadcast', 'test'), { recursive: true })
  writeFileSync(join(r, 'broadcast', 'test', 'x.test.ts'), '// tracked, never in a release\n')
  // api: synthetic servers. The relay holds the local-only test override (its allowed place).
  mkdirSync(join(r, 'api', 'src'), { recursive: true })
  mkdirSync(join(r, 'api', 'relay'), { recursive: true })
  mkdirSync(join(r, 'api', 'serve'), { recursive: true })
  mkdirSync(join(r, 'api', 'test'), { recursive: true })
  writeFileSync(join(r, 'api', 'package.json'), `${JSON.stringify({ name: '@vault-timelock/api', version: '0.0.0', private: true, type: 'module',
    dependencies: { '@vault-timelock/core': '0.0.0', 'dep-a': '1.0.0', 'vt-broadcast': 'file:../broadcast' } }, null, 2)}\n`)
  writeFileSync(join(r, 'api', 'src', 'main.ts'), '// synthetic API\nconsole.log(\'synthetic api\')\n')
  writeFileSync(join(r, 'api', 'relay', 'relay.mjs'), '// synthetic relay\nif (process.env.VT_TEST_ETH_RPC && process.argv.includes(\'mainnet\')) process.exit(2) // local-only override\n')
  writeFileSync(join(r, 'api', 'serve', 'serve.mjs'), '// synthetic page server\n')
  writeFileSync(join(r, 'api', 'test', 'sol-pressure-filter.mjs'), '// a tracked harness outside every release root\n')
  mkdirSync(join(r, 'test', 'integration', 'harness'), { recursive: true })
  writeFileSync(join(r, 'test', 'integration', 'harness', 'eth-pressure-miner.mjs'), '// tracked, never in a release\n')
  // the root: synthetic sealers, docs, the web sources, .gitignore
  writeExe(join(r, '1password-timelock.sh'), SEALER('1password-timelock.sh'))
  writeExe(join(r, 'timelock-key.sh'), SEALER('timelock-key.sh'))
  writeFileSync(join(r, 'package.json'), '{ "name": "synthetic-vault-timelock", "private": true, "type": "module" }\n')
  mkdirSync(join(r, 'docs'), { recursive: true })
  writeFileSync(join(r, 'docs', 'notes.md'), '# docs stay out\n')
  mkdirSync(join(r, 'web', 'src'), { recursive: true })
  writeFileSync(join(r, 'web', 'index.html'), '<!doctype html>\n')
  writeFileSync(join(r, '.gitignore'), 'node_modules/\n')
  // node_modules: a linked store (packages/core, api, cli) and broadcast's hoisted install
  fakePackage(store(r, 'shared', '1.0.0'), 'shared', '1.0.0')
  fakePackage(store(r, 'shared', '2.0.0'), 'shared', '2.0.0')
  const depA = store(r, 'dep-a', '1.0.0')
  fakePackage(depA, 'dep-a', '1.0.0', { deps: { shared: '2.0.0', '@types/dep-a': '1.0.0' }, imports: ['shared'] })
  mkdirSync(join(depA, 'test'), { recursive: true })
  writeFileSync(join(depA, 'test', 'helper.js'), '// a package-root test dir: not copied\n')
  mkdirSync(join(depA, 'lib'), { recursive: true })
  writeFileSync(join(depA, 'lib', 'util.js'), 'export const util = 1\n')
  writeFileSync(join(depA, 'lib', 'util.test.js'), '// a test file: not copied\n')
  link(store(r, 'shared', '2.0.0'), join(dirname(depA), 'shared'))
  const peer = store(r, 'peer-user', '1.0.0')
  fakePackage(peer, 'peer-user', '1.0.0', { peer: { shared: '*' }, imports: ['shared'] })
  link(store(r, 'shared', '2.0.0'), join(dirname(peer), 'shared')) // the store gave the peer another version (as isows -> ws)
  fakePackage(store(r, 'opt-user', '1.0.0'), 'opt-user', '1.0.0', { opt: { 'not-installed': '1.0.0' } })
  fakePackage(store(r, 'typescript', '5.9.3'), 'typescript', '5.9.3')
  cpSync(REAL_NOBLE, store(r, '@noble/hashes', NOBLE_VERSION), { recursive: true })
  link(store(r, '@noble/hashes', NOBLE_VERSION), join(r, 'packages', 'core', 'node_modules', '@noble', 'hashes'))
  const coreNm = join(r, 'packages', 'core', 'node_modules')
  for (const [n, v] of [['shared', '1.0.0'], ['dep-a', '1.0.0'], ['peer-user', '1.0.0'], ['opt-user', '1.0.0'], ['typescript', '5.9.3']]) link(store(r, n, v), join(coreNm, n))
  for (const ws of ['cli', 'api']) {
    link(join(r, 'packages', 'core'), join(r, ws, 'node_modules', '@vault-timelock', 'core'))
    link(join(r, 'broadcast'), join(r, ws, 'node_modules', 'vt-broadcast'))
  }
  link(depA, join(r, 'api', 'node_modules', 'dep-a'))
  const bNm = join(r, 'broadcast', 'node_modules')
  fakePackage(join(bNm, 'shared'), 'shared', '2.0.0')
  fakePackage(join(bNm, 'dep-b'), 'dep-b', '1.0.0', { deps: { shared: '2.0.0' }, imports: ['shared'] })
  fakePackage(join(bNm, 'typescript'), 'typescript', '5.9.3')
  fakePackage(join(bNm, '@types', 'node'), '@types/node', '24.19.1')
  link(join(r, 'packages', 'core'), join(bNm, '@vault-timelock', 'core')) // E6: broadcast's one first-party link
  writeLockfiles(r)
  git(root, 'init', '-q', r)
  git(r, 'add', '-A')
  git(r, 'commit', '-qm', 'synthetic release source')
  // untracked, after the commit: never copied (tracked files only), and the tree stays clean (tracked files only)
  mkdirSync(join(r, '.superpowers'), { recursive: true })
  writeFileSync(join(r, '.superpowers', 'notes.md'), 'untracked notes\n')
  writeFileSync(join(r, 'cli', 'src', 'untracked-debug.ts'), '// untracked, inside a release root\n')
  writeFileSync(join(r, 'api', 'src', 'api.token'), 'synthetic-untracked-token\n')
  return r
}

// The lockfiles of the synthetic installs, as npm writes them: the committed package-lock.json (hoisted form) and
// npm's record of the install, node_modules/.package-lock.json (linked form at the root: .store entries without
// integrity, link entries; hoisted, key for key, in broadcast). not-installed is an optional package for another
// platform: in the lockfile, rightly not installed.
const url = (n: string, v: string): string => `https://registry.example.invalid/${n}/-/${n.split('/').pop()}-${v}.tgz`
const integrity = (n: string, v: string): string => `sha512-${createHash('sha512').update(`${n}@${v}`).digest('base64')}`
const reg = (n: string, v: string, extra: Record<string, unknown> = {}): Record<string, unknown> => ({ version: v, resolved: url(n, v), integrity: integrity(n, v), ...extra })
const S = (n: string, v: string): string => `node_modules/.store/${n}@${v}-synthetic/node_modules/${n}`
const lockJson = (name: string, packages: Record<string, unknown>): string => `${JSON.stringify({ name, lockfileVersion: 3, requires: true, packages }, null, 2)}\n`
function writeLockfiles(r: string): void {
  const pj = (ws: string): Record<string, unknown> => {
    const j = JSON.parse(readFileSync(join(r, ws, 'package.json'), 'utf8')) as Record<string, unknown>
    return Object.fromEntries(['name', 'version', 'dependencies', 'devDependencies'].filter((k) => j[k] !== undefined).map((k) => [k, j[k]]))
  }
  const wsEntries = { api: pj('api'), cli: pj('cli'), 'packages/core': pj('packages/core') }
  const store = (n: string, v: string, extra: Record<string, unknown> = {}): Record<string, unknown> =>
    ({ [S(n, v).slice(0, -(`/node_modules/${n}`).length)]: {}, [S(n, v)]: { version: v, resolved: url(n, v), ...extra } })
  const lk = (target: string): Record<string, unknown> => ({ resolved: target, link: true })
  writeFileSync(join(r, 'package-lock.json'), lockJson('synthetic-vault-timelock', {
    '': { name: 'synthetic-vault-timelock', workspaces: ['packages/core', 'api', 'cli'] },
    ...wsEntries,
    'node_modules/@vault-timelock/api': lk('api'), 'node_modules/@vault-timelock/cli': lk('cli'), 'node_modules/@vault-timelock/core': lk('packages/core'),
    'node_modules/vt-broadcast': lk('broadcast'),
    'node_modules/@noble/hashes': reg('@noble/hashes', NOBLE_VERSION),
    'node_modules/dep-a': reg('dep-a', '1.0.0', { dependencies: { shared: '2.0.0' } }),
    'node_modules/dep-a/node_modules/shared': reg('shared', '2.0.0'),
    'node_modules/not-installed': reg('not-installed', '1.0.0', { optional: true, os: ['win32'] }),
    'node_modules/opt-user': reg('opt-user', '1.0.0', { optionalDependencies: { 'not-installed': '1.0.0' } }),
    'node_modules/peer-user': reg('peer-user', '1.0.0', { peerDependencies: { shared: '*' } }),
    'node_modules/peer-user/node_modules/shared': reg('shared', '2.0.0'),
    'node_modules/shared': reg('shared', '1.0.0'),
    'node_modules/typescript': reg('typescript', '5.9.3', { dev: true }),
  }))
  writeFileSync(join(r, 'node_modules', '.package-lock.json'), lockJson('synthetic-vault-timelock', {
    ...wsEntries,
    'api/node_modules/@vault-timelock/core': lk('packages/core'), 'api/node_modules/vt-broadcast': lk('broadcast'), 'api/node_modules/dep-a': lk(S('dep-a', '1.0.0')),
    'cli/node_modules/@vault-timelock/core': lk('packages/core'), 'cli/node_modules/vt-broadcast': lk('broadcast'),
    'packages/core/node_modules/@noble/hashes': lk(S('@noble/hashes', NOBLE_VERSION)), 'packages/core/node_modules/dep-a': lk(S('dep-a', '1.0.0')),
    'packages/core/node_modules/opt-user': lk(S('opt-user', '1.0.0')), 'packages/core/node_modules/peer-user': lk(S('peer-user', '1.0.0')),
    'packages/core/node_modules/shared': lk(S('shared', '1.0.0')), 'packages/core/node_modules/typescript': lk(S('typescript', '5.9.3')),
    ...store('@noble/hashes', NOBLE_VERSION), ...store('dep-a', '1.0.0', { dependencies: { shared: '2.0.0' } }), ...store('opt-user', '1.0.0', { optionalDependencies: { 'not-installed': '1.0.0' } }),
    ...store('peer-user', '1.0.0', { peerDependencies: { shared: '*' } }), ...store('shared', '1.0.0'), ...store('shared', '2.0.0'), ...store('typescript', '5.9.3'),
    [`${S('dep-a', '1.0.0').slice(0, -'dep-a'.length)}shared`]: lk(S('shared', '2.0.0')),
    [`${S('peer-user', '1.0.0').slice(0, -'peer-user'.length)}shared`]: lk(S('shared', '2.0.0')),
  }))
  const bPackages = {
    'node_modules/@types/node': reg('@types/node', '24.19.1', { dev: true }),
    'node_modules/dep-b': reg('dep-b', '1.0.0', { dependencies: { shared: '2.0.0' } }),
    'node_modules/shared': reg('shared', '2.0.0'),
    'node_modules/typescript': reg('typescript', '5.9.3', { dev: true }),
    'node_modules/@vault-timelock/core': { resolved: '../packages/core', link: true },
  }
  writeFileSync(join(r, 'broadcast', 'package-lock.json'), lockJson('vt-broadcast', { '': { name: 'vt-broadcast', ...pj('broadcast') }, ...bPackages }))
  writeFileSync(join(r, 'broadcast', 'node_modules', '.package-lock.json'), lockJson('vt-broadcast', bPackages))
}

// Every entry of a tree, relative ("dir/", "file", "link -> target").
function entries(dir: string): string[] {
  const out: string[] = []
  const walk = (rel: string): void => {
    for (const e of readdirSync(join(dir, rel)).sort()) {
      const p = rel === '' ? e : `${rel}/${e}`
      const st = lstatSync(join(dir, p))
      if (st.isSymbolicLink()) out.push(`${p} -> ${readlinkSync(join(dir, p))}`)
      else if (st.isDirectory()) { out.push(`${p}/`); walk(p) } else out.push(p)
    }
  }
  walk('')
  return out
}
const opened = (p: string, fn: () => void): void => {
  const mode = lstatSync(p).mode & 0o7777
  chmodSync(p, mode | 0o200)
  try { fn() } finally { chmodSync(p, mode) }
}
const releaseVt = (rel: string, args: string[], home: string): Run => run(args, { file: join(rel, 'cli', 'bin', 'vt'), env: { PATH: PATH0, HOME: HOME0, VT_HOME: home } })
const devVt = (args: string[], home: string): Run => run(args, { env: envOf(home) })
const nodeAt = (cwd: string, code: string): string => {
  const r = spawnSync(NODE, ['--input-type=module', '-e', code], { cwd, env: { PATH: PATH0, HOME: HOME0 }, encoding: 'utf8' })
  assert.equal(r.status, 0, r.stderr)
  return r.stdout.trim()
}

before(() => {
  T = tempDir('vt-release-')
  HOME0 = join(T, 'home')
  mkdirSync(HOME0, { mode: 0o700 })
  F = fakeTmux(T)
  REPO = makeRepo(T)
  FIRST = fresh()
})
after(() => removeTree(T))

// ---- build

test('build: $VT_HOME/releases/<buildId>, read-only, verified, holding exactly the tracked release sources, the closure and the page', () => {
  const r = FIRST
  assert.ok(r.created)
  assert.match(r.buildId, BUILD_ID)
  assert.equal(r.dir, join(realpathSync(dirname(dirname(r.dir))), 'releases', r.buildId))
  assert.equal(r.commit, git(REPO, 'rev-parse', 'HEAD').trim())
  const v = verify(r.dir)
  assert.deepEqual({ ...v, problems: [], digest: '' }, { ...v, ok: v.files, mismatch: 0, missing: 0, extra: 0, links: 0, writable: 0, outside: 0, manifest: true, testOnly: [], problems: [], digest: '' })
  assertVerified(v)
  // What it contains, entry by entry.
  const all = entries(r.dir)
  const tracked = git(REPO, 'ls-files', '-z').split('\0').filter((p) => p !== '')
  const firstParty = all.filter((e) => !e.endsWith('/') && !e.includes(' -> ') && !e.includes('node_modules/') && !e.startsWith('web/') && e !== 'SHA256SUMS' && e !== 'RELEASE.json')
  assert.deepEqual(firstParty, tracked.filter(isReleaseSource).sort(), 'first-party files = the tracked files of the release roots, no more')
  for (const p of firstParty) assert.deepEqual(readFileSync(join(r.dir, p)), blob(REPO, r.commit, p), `${p}: the commit's blob`)
  assert.deepEqual(all.filter((e) => e.includes(' -> ')), [
    'api/node_modules/@vault-timelock/core -> ../../../packages/core', 'api/node_modules/vt-broadcast -> ../../broadcast',
    'broadcast/node_modules/@vault-timelock/core -> ../../../packages/core',
    'cli/node_modules/@vault-timelock/core -> ../../../packages/core', 'cli/node_modules/vt-broadcast -> ../../broadcast',
  ], 'the only links: the first-party workspace links (C1 ruling 5: vt-broadcast through cli/node_modules)')
  const packages = all.filter((e) => /node_modules\/(?:@[^/]+\/)?[^/@]+\/$/.test(e) && !e.includes(' -> ')).filter((e) => existsSync(join(r.dir, e, 'package.json')))
  assert.deepEqual(packages.sort(), ['broadcast/node_modules/shared/', 'node_modules/@noble/hashes/', 'node_modules/dep-a/', 'node_modules/dep-a/node_modules/shared/', 'node_modules/dep-b/',
    'node_modules/dep-b/node_modules/shared/', 'node_modules/opt-user/', 'node_modules/peer-user/', 'node_modules/peer-user/node_modules/shared/', 'node_modules/shared/'],
  'the production closure, dereferenced: no typescript, no @types, nothing optional that is not installed')
  assert.ok(existsSync(join(r.dir, 'node_modules', 'dep-a', 'lib', 'util.js')))
  for (const gone of ['node_modules/dep-a/test/', 'node_modules/dep-a/lib/util.test.js']) assert.ok(!all.includes(gone), gone)
  assert.deepEqual(all.filter((e) => e.startsWith('web/')), ['web/', 'web/dist/', 'web/dist/index.html'])
  assert.equal(readFileSync(join(r.dir, 'web', 'dist', 'index.html'), 'utf8'), PAGE)
  // Carry-forward 1: the sealers are in (and in SHA256SUMS); cli/test/fixtures and every test, harness and doc are out.
  const sums = readFileSync(join(r.dir, 'SHA256SUMS'), 'utf8')
  for (const s of ['1password-timelock.sh', 'timelock-key.sh']) {
    assert.equal(readFileSync(join(r.dir, s), 'utf8'), SEALER(s), 'the synthetic stub, byte for byte')
    assert.equal(lstatSync(join(r.dir, s)).mode & 0o777, 0o555)
    assert.match(sums, new RegExp(`^[0-9a-f]{64} {2}\\./${s.replace('.', '\\.')}$`, 'm'))
  }
  // Carry-forward 4: no secrets, tokens, state dirs, .superpowers, tests, fixtures, docs, untracked files.
  for (const e of all) assert.ok(!/(?:^|\/)(?:test|tests|fixtures|scripts|docs|\.superpowers|\.git)\/|pressure|harness|\.test\.|untracked|api\.token|typescript|@types/.test(e), e)
  // RELEASE.json, SHA256SUMS, read-only, nothing staged left.
  assert.deepEqual(JSON.parse(readFileSync(join(r.dir, 'RELEASE.json'), 'utf8')), {
    format: 'vt-release/1', buildId: r.buildId, commit: r.commit,
    links: { 'api/node_modules/@vault-timelock/core': '../../../packages/core', 'api/node_modules/vt-broadcast': '../../broadcast',
      'broadcast/node_modules/@vault-timelock/core': '../../../packages/core',
      'cli/node_modules/@vault-timelock/core': '../../../packages/core', 'cli/node_modules/vt-broadcast': '../../broadcast' },
    lockfiles: { 'package-lock.json': sha256hex(blob(REPO, r.commit, 'package-lock.json')), 'broadcast/package-lock.json': sha256hex(blob(REPO, r.commit, 'broadcast/package-lock.json')) },
  })
  const listed = sums.trimEnd().split('\n').map((l) => l.slice(68))
  assert.deepEqual(listed, all.filter((e) => !e.endsWith('/') && !e.includes(' -> ') && e !== 'SHA256SUMS').sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))))
  for (const e of all) if (!e.includes(' -> ')) assert.equal(lstatSync(join(r.dir, e)).mode & 0o222, 0, e)
  assert.equal(lstatSync(r.dir).mode & 0o777, 0o555)
  assert.deepEqual(readdirSync(dirname(r.dir)), [r.buildId])
})

test('review m-1: the test-only fault hook (test/fixtures/fault-hook.ts, used by the job stub) is tracked in the repository and absent from the release: neither file, nor its marker, env name or canary key in any file', () => {
  const tracked = git(REPO, 'ls-files', '-z').split('\0')
  for (const p of ['cli/test/fixtures/fault-hook.ts', 'cli/test/fixtures/job-stub.ts']) {
    assert.ok(tracked.includes(p), `${p} is tracked`)
    assert.equal(isReleaseSource(p), false, p)
    assert.ok(!existsSync(join(FIRST.dir, p)), p)
  }
  const markers = [FAULT_MARKER, 'VT_JOB_STUB_FAULT', 'faultHook', FAULT_CANARY_KEY]
  let files = 0
  for (const e of entries(FIRST.dir)) {
    if (e.endsWith('/') || e.includes(' -> ')) continue
    const b = readFileSync(join(FIRST.dir, e))
    files++
    for (const m of markers) assert.ok(b.indexOf(m) < 0, `${e} holds ${m}`)
  }
  assert.ok(files > 100, `the release was walked (${files} files)`)
  // the one thing src keeps is the seam (RunDeps.fault), which it refuses unless NODE_ENV=test: vt.test-fault (run.test.ts)
  assert.match(readFileSync(join(FIRST.dir, 'cli', 'src', 'job', 'run.ts'), 'utf8'), /refuse\('vt\.test-fault'/)
})

test('the closure resolves in the release exactly as in the development tree; vt-broadcast and core resolve through cli/node_modules', () => {
  const tree = (cwd: string, names: string[]): string => nodeAt(cwd, `const out = {}; for (const n of ${JSON.stringify(names)}) out[n] = (await import(n)).tree; console.log(JSON.stringify(out))`)
  for (const [ws, names] of [['packages/core', ['shared', 'dep-a', 'peer-user', 'opt-user']], ['broadcast', ['shared', 'dep-b']], ['api', ['dep-a']]] as const) {
    assert.equal(tree(join(FIRST.dir, ws), [...names]), tree(join(REPO, ws), [...names]), ws)
  }
  assert.equal(tree(join(FIRST.dir, 'packages', 'core'), ['dep-a']), '{"dep-a":{"dep-a@1.0.0":{"shared":{"shared@2.0.0":{}}}}}')
  assert.equal(tree(join(FIRST.dir, 'packages', 'core'), ['peer-user']), '{"peer-user":{"peer-user@1.0.0":{"shared":{"shared@2.0.0":{}}}}}', 'a peer resolves as installed')
  assert.equal(tree(join(FIRST.dir, 'packages', 'core'), ['shared']), '{"shared":{"shared@1.0.0":{}}}')
  const rel = realpathSync(FIRST.dir)
  const cli = join(rel, 'cli')
  assert.equal(nodeAt(cli, 'console.log(import.meta.resolve(\'vt-broadcast/package.json\'))'), `file://${join(rel, 'broadcast', 'package.json')}`)
  assert.equal(nodeAt(cli, 'console.log(typeof (await import(\'vt-broadcast/src/config.ts\')).loadConfig)'), 'function')
  assert.equal(nodeAt(cli, 'console.log(typeof (await import(\'@vault-timelock/core/contracts\')).refuse)'), 'function', 'core\'s TypeScript loads (outside node_modules)')
  assert.deepEqual(lookupChain('node_modules/@a/b'), ['node_modules/@a/b/node_modules', 'node_modules/@a/node_modules', 'node_modules'])
  assert.deepEqual(lookupChain('packages/core'), ['packages/core/node_modules', 'packages/node_modules', 'node_modules'])
})

test('buildId: the same tree gives the same id and byte-identical SHA256SUMS; an existing verified release is reused; any tracked change, a new id', () => {
  const again = fresh()
  assert.equal(again.buildId, FIRST.buildId)
  assert.deepEqual(readFileSync(join(again.dir, 'SHA256SUMS')), readFileSync(join(FIRST.dir, 'SHA256SUMS')))
  const reuse = buildIn(dirname(dirname(FIRST.dir)))
  assert.deepEqual([reuse.created, reuse.dir], [false, FIRST.dir])
  // An existing release is reused only when it verifies.
  const f = join(again.dir, 'cli', 'src', 'main.ts')
  opened(f, () => appendFileSync(f, '// edited in place\n'))
  throwsWith(() => buildIn(dirname(dirname(again.dir))), 'release.mismatch')
  // The id covers every file of the commit (path, type, bytes), not only the release roots.
  assert.equal(headId(REPO), FIRST.buildId)
  const copy = join(T, 'repo-change')
  cpSync(REPO, copy, { recursive: true, verbatimSymlinks: true })
  appendFileSync(join(copy, 'docs', 'notes.md'), 'a change outside the release roots\n')
  git(copy, 'commit', '-qam', 'docs')
  const changed = headId(copy)
  assert.notEqual(changed, FIRST.buildId)
  chmodSync(join(copy, 'docs', 'notes.md'), 0o755)
  git(copy, 'commit', '-qam', 'mode')
  assert.notEqual(headId(copy), changed, 'the executable bit counts')
  chmodSync(join(copy, 'docs', 'notes.md'), 0o644)
  git(copy, 'commit', '-qam', 'mode back')
  assert.equal(headId(copy), changed)
  git(copy, 'mv', 'docs/notes.md', 'docs/notes2.md')
  git(copy, 'commit', '-qm', 'rename')
  assert.notEqual(headId(copy), changed, 'a path counts, not only the bytes')
  const r = buildIn(newHome(), copy)
  assert.equal(r.buildId, headId(copy))
  removeTree(copy)
})

test('build refuses: uncommitted tracked changes, a missing required file, test-only code in a copied root; nothing is left behind', async () => {
  const copy = join(T, 'repo-refuse')
  cpSync(REPO, copy, { recursive: true, verbatimSymlinks: true })
  try {
    const home = newHome()
    appendFileSync(join(copy, 'cli', 'src', 'help.ts'), '// uncommitted\n')
    assert.throws(() => buildIn(home, copy), /uncommitted changes to tracked files/)
    git(copy, 'checkout', '--', 'cli/src/help.ts')
    git(copy, 'rm', '-q', 'api/serve/serve.mjs')
    git(copy, 'commit', '-qm', 'no page server')
    assert.throws(() => buildIn(home, copy), /api\/serve\/serve\.mjs is not in this tree/)
    git(copy, 'revert', '--no-edit', 'HEAD')
    // A test-only module in a copied root: refused, and neither the release nor a staging dir is kept.
    for (const [file, text] of [['api/relay/sol-pressure-filter.mjs', '// the SOL withholding filter\n'], ['api/src/extra.ts', `export const u = process.env.VT_TEST_SOL_RPC // ${CANARY.length}\n`],
      ['cli/src/ops/extra.ts', '// mentions anvil_dropTransaction\n'], ['api/src/fixtures/a.json', '{}\n'], ['api/src/a.test.ts', '// test\n']] as const) {
      mkdirSync(dirname(join(copy, file)), { recursive: true })
      writeFileSync(join(copy, file), text)
      git(copy, 'add', file)
      git(copy, 'commit', '-qm', `add ${file}`)
      throwsWith(() => buildIn(home, copy), 'release.test-only-present')
      assert.deepEqual(readdirSync(join(home, 'releases')), [], `${file}: nothing kept`)
      git(copy, 'rm', '-rq', file)
      git(copy, 'commit', '-qm', `drop ${file}`)
    }
    assert.equal(buildIn(home, copy).created, true, 'the same tree without them builds')
    // Not a git work tree at all.
    assert.throws(() => build({ repo: join(T, 'home'), env: envOf(home), buildWeb: fakeWeb }), /git work tree/)
  } finally {
    removeTree(copy)
  }
})

test('C4 review I-2: a skip-worktree or assume-unchanged edit is refused (release.index-flags, naming the paths); nothing is built', () => {
  const copy = join(T, 'repo-flags')
  cpSync(REPO, copy, { recursive: true, verbatimSymlinks: true })
  try {
    const home = newHome()
    // The reviewer's probe: a hidden edit to the file that holds the mainnet send locks.
    appendFileSync(join(copy, 'broadcast', 'src', 'config.ts'), '\n// a hidden edit\n')
    git(copy, 'update-index', '--skip-worktree', 'broadcast/src/config.ts')
    assert.equal(git(copy, 'status', '--porcelain', '--untracked-files=no'), '', 'git status cannot see it')
    assert.throws(() => buildIn(home, copy), (x: unknown) => (x as { guardId?: string }).guardId === 'release.index-flags' && /broadcast\/src\/config\.ts/.test((x as Error).message))
    git(copy, 'update-index', '--no-skip-worktree', 'broadcast/src/config.ts')
    assert.throws(() => buildIn(home, copy), /uncommitted changes/, 'visible again: the dirty-tree refusal')
    git(copy, 'checkout', '--', 'broadcast/src/config.ts')
    appendFileSync(join(copy, 'cli', 'src', 'help.ts'), '// hidden too\n')
    git(copy, 'update-index', '--assume-unchanged', 'cli/src/help.ts')
    assert.throws(() => buildIn(home, copy), (x: unknown) => (x as { guardId?: string }).guardId === 'release.index-flags' && /cli\/src\/help\.ts/.test((x as Error).message))
    assert.ok(!existsSync(join(home, 'releases')) || readdirSync(join(home, 'releases')).length === 0, 'no release, no staging or export dir')
    // The listing rule: S and every lowercase tag; H (and the others) pass.
    assert.deepEqual(hiddenIndexEntries(Buffer.from('H a\0S b\0h c\0s d\0M e\0C f\0')), ['b', 'c', 'd'])
    assertNoHiddenIndexFlags(Buffer.from('H a\0H b\0'))
    throwsWith(() => assertNoHiddenIndexFlags(Buffer.from('H a\0S b\0')), 'release.index-flags')
  } finally {
    removeTree(copy)
  }
})

test('C4 review I-2: the release is the commit: an edit or a commit made during the build never reaches it; the page builds in the export', () => {
  const copy = join(T, 'repo-during')
  cpSync(REPO, copy, { recursive: true, verbatimSymlinks: true })
  try {
    const before = headOf(copy)
    writeFileSync(join(copy, 'web', 'src', 'untracked.js'), '// an untracked page source: never in the export\n')
    let exportSeen = ''
    const r = build({ repo: copy, env: envOf(newHome()), buildWeb: (exported, out) => {
      exportSeen = exported
      assert.notEqual(realpathSync(exported), realpathSync(copy))
      assert.ok(existsSync(join(exported, 'web', 'index.html')) && !existsSync(join(exported, 'web', 'src', 'untracked.js')), 'the commit\'s web/ only')
      // First-party links in the export resolve to the export (the commit), installed packages to the install.
      for (const ws of ['cli', 'api']) {
        assert.equal(realpathSync(join(exported, ws, 'node_modules', 'vt-broadcast')), realpathSync(join(exported, 'broadcast')))
        assert.equal(realpathSync(join(exported, ws, 'node_modules', '@vault-timelock', 'core')), realpathSync(join(exported, 'packages', 'core')))
      }
      assert.ok(realpathSync(join(exported, 'packages', 'core', 'node_modules', 'shared')).startsWith(realpathSync(join(copy, 'node_modules', '.store'))))
      // Mid-build: an editor saves a tracked file, and someone commits another.
      appendFileSync(join(copy, 'cli', 'src', 'help.ts'), '// saved during the build\n')
      appendFileSync(join(copy, 'api', 'src', 'main.ts'), '// committed during the build\n')
      git(copy, 'commit', '-qm', 'during the build', '--', 'api/src/main.ts')
      // ... and a manifest edit (a dependency that is not even installed): the closure reads the commit's manifests.
      const pj = join(copy, 'broadcast', 'package.json')
      writeFileSync(pj, readFileSync(pj, 'utf8').replace('"dep-b": "1.0.0"', '"dep-b": "1.0.0", "dep-a": "1.0.0"'))
      fakeWeb(exported, out)
    } })
    assert.equal(r.commit, before)
    assert.notEqual(headOf(copy), before)
    for (const p of ['cli/src/help.ts', 'api/src/main.ts', 'broadcast/src/config.ts', 'broadcast/package.json']) assert.deepEqual(readFileSync(join(r.dir, p)), blob(copy, before, p), p)
    assert.ok(!existsSync(join(r.dir, 'broadcast', 'node_modules', 'dep-a')))
    assert.equal(r.buildId, computeBuildId(readCommitTree(copy, before, envOf(join(T, 'unused')))))
    assert.ok(!existsSync(exportSeen), 'the export is removed')
    assert.deepEqual(readdirSync(dirname(r.dir)), [r.buildId])
  } finally {
    removeTree(copy)
  }
})

test('review fix round 2: node_modules that drift from the commit\'s lockfiles -> release.lock-drift (names only); a clean install builds', () => {
  const edit = (p: string, fn: (j: { packages: Record<string, Record<string, unknown>> }) => void): void => {
    const j = JSON.parse(readFileSync(p, 'utf8')) as { packages: Record<string, Record<string, unknown>> }
    fn(j)
    writeFileSync(p, `${JSON.stringify(j, null, 2)}\n`)
  }
  const setVersion = (dir: string, v: string): void => {
    const p = join(dir, 'package.json')
    writeFileSync(p, readFileSync(p, 'utf8').replace(/"version":"[^"]*"/, `"version":"${v}"`))
  }
  const hiddenB = (c: string): string => join(c, 'broadcast', 'node_modules', '.package-lock.json')
  const hiddenR = (c: string): string => join(c, 'node_modules', '.package-lock.json')
  const cases: Array<[string, (c: string) => void, RegExp]> = [
    // A stale install: what an older or newer lockfile installed (npm's record and the disk agree with each other).
    ['broadcast: a version bump', (c) => { setVersion(join(c, 'broadcast', 'node_modules', 'dep-b'), '1.0.1'); edit(hiddenB(c), (j) => { j.packages['node_modules/dep-b'].version = '1.0.1' }) },
      /broadcast install: dep-b 1\.0\.0 is in the lockfile, not installed/],
    ['root .store: a version bump', (c) => { setVersion(join(c, S('shared', '1.0.0')), '1.0.1'); edit(hiddenR(c), (j) => { j.packages[S('shared', '1.0.0')].version = '1.0.1' }) },
      /root install: shared 1\.0\.1 is installed, not in the lockfile/],
    // An extra package: on disk only; on disk and in npm's record but not in the lockfile.
    ['broadcast: an extra directory', (c) => fakePackage(join(c, 'broadcast', 'node_modules', 'extra-pkg'), 'extra-pkg', '1.0.0'),
      /broadcast\/node_modules\/extra-pkg: on disk, not in npm's record/],
    ['broadcast: an extra recorded package', (c) => { fakePackage(join(c, 'broadcast', 'node_modules', 'extra-pkg'), 'extra-pkg', '1.0.0'); edit(hiddenB(c), (j) => { j.packages['node_modules/extra-pkg'] = reg('extra-pkg', '1.0.0') }) },
      /broadcast install: extra-pkg 1\.0\.0 is installed, not in the lockfile/],
    ['root: an extra workspace link', (c) => link(join(c, S('shared', '2.0.0')), join(c, 'cli', 'node_modules', 'shared')), /cli\/node_modules\/shared: on disk, not in npm's record/],
    // E6: broadcast's one first-party link (core) is checked like any other link; no other link may sit beside it.
    ['broadcast: the core link retargeted', (c) => { unlinkSync(join(c, 'broadcast', 'node_modules', '@vault-timelock', 'core')); link(join(c, 'api'), join(c, 'broadcast', 'node_modules', '@vault-timelock', 'core')) },
      /broadcast\/node_modules\/@vault-timelock\/core: the link is not where npm put it/],
    ['broadcast: the core link missing', (c) => unlinkSync(join(c, 'broadcast', 'node_modules', '@vault-timelock', 'core')), /broadcast\/node_modules\/@vault-timelock\/core: missing on disk/],
    ['broadcast: an extra link (vt-broadcast itself)', (c) => link(join(c, 'broadcast'), join(c, 'broadcast', 'node_modules', 'vt-broadcast')),
      /broadcast\/node_modules\/vt-broadcast: on disk, not in npm's record/],
    // A modified integrity (broadcast's hoisted record keeps it).
    ['broadcast: a modified integrity', (c) => edit(hiddenB(c), (j) => { j.packages['node_modules/shared'].integrity = integrity('shared', '9.9.9') }), /broadcast\/node_modules\/shared: integrity differs/],
    // A missing directory: npm recorded it, the disk lacks it.
    ['broadcast: a missing directory', (c) => rmSync(join(c, 'broadcast', 'node_modules', 'dep-b'), { recursive: true }), /broadcast\/node_modules\/dep-b: missing on disk/],
    ['root .store: a missing directory', (c) => rmSync(join(c, S('opt-user', '1.0.0')), { recursive: true }), /node_modules\/opt-user: missing on disk/],
    // A workspace link moved to another installed version; a package directory swapped for another package.
    ['root: a retargeted link', (c) => { unlinkSync(join(c, 'packages', 'core', 'node_modules', 'shared')); link(join(c, S('shared', '2.0.0')), join(c, 'packages', 'core', 'node_modules', 'shared')) },
      /packages\/core\/node_modules\/shared: the link is not where npm put it/],
    ['broadcast: a swapped package', (c) => { rmSync(join(c, 'broadcast', 'node_modules', 'shared'), { recursive: true }); fakePackage(join(c, 'broadcast', 'node_modules', 'shared'), 'shared', '2.0.1') },
      /broadcast\/node_modules\/shared: not the package npm installed there/],
    // A dependency edge npm's record says differently (peer-user's peer resolved to 1.0.0 in the record only).
    ['root: a different edge', (c) => edit(hiddenR(c), (j) => { j.packages[`${S('peer-user', '1.0.0').slice(0, -'peer-user'.length)}shared`].resolved = S('shared', '1.0.0') }),
      /root install: a dependency differs: peer-user 1\.0\.0 -> shared -> shared 1\.0\.0 \(installed\)/],
    // An edge the lockfile has and the install lacks (the peer link gone from disk and from npm's record alike).
    ['root: a missing edge', (c) => {
      const sib = `${S('peer-user', '1.0.0').slice(0, -'peer-user'.length)}shared`
      unlinkSync(join(c, sib))
      edit(hiddenR(c), (j) => { delete j.packages[sib] })
    }, /root install: a dependency differs: peer-user 1\.0\.0 -> shared -> shared 2\.0\.0 \(the lockfile\)/],
    // No record at all; no lockfile in the commit; an optional package for THIS platform that is not installed.
    ['broadcast: no npm record', (c) => unlinkSync(hiddenB(c)), /broadcast\/node_modules\/\.package-lock\.json: missing or unreadable/],
    ['root: no lockfile in the commit', (c) => { git(c, 'rm', '-q', 'package-lock.json'); git(c, 'commit', '-qm', 'no lockfile') }, /\(package-lock\.json: not in the commit/],
    ['root: an optional for this platform, not installed', (c) => { edit(join(c, 'package-lock.json'), (j) => { j.packages['node_modules/not-installed'].os = [process.platform] }); git(c, 'commit', '-qam', 'this platform') },
      /root install: not-installed 1\.0\.0 is in the lockfile, not installed/],
  ]
  for (const [label, fn, want] of cases) {
    const copy = join(T, 'repo-drift')
    cpSync(REPO, copy, { recursive: true, verbatimSymlinks: true })
    try {
      fn(copy)
      const home = newHome()
      assert.throws(() => buildIn(home, copy), (e: unknown) => {
        assert.equal((e as { guardId?: string }).guardId, 'release.lock-drift', `${label}: ${String(e)}`)
        assert.match((e as Error).message, want, label)
        return true
      })
      assert.ok(!existsSync(join(home, 'releases')) || readdirSync(join(home, 'releases')).length === 0, `${label}: nothing kept`)
    } finally {
      removeTree(copy)
    }
  }
  // The clean install (what npm ci left) builds; the other-platform optional is excused.
  assert.deepEqual(installDrift(REPO, '', blob(REPO, 'HEAD', 'package-lock.json')), [])
  assert.deepEqual(installDrift(REPO, 'broadcast', blob(REPO, 'HEAD', 'broadcast/package-lock.json')), [])
  assertNoLockDrift([])
  throwsWith(() => assertNoLockDrift(['x: missing on disk']), 'release.lock-drift')
})

// ---- verify (each on a fresh release, so one tamper at a time)

function tampered(fn: (dir: string) => void): ReturnType<typeof verify> {
  const r = fresh()
  fn(r.dir)
  return verify(r.dir)
}

test('verify: one flipped byte -> mismatch 1 -> release.mismatch (also through vt release verify, exit 2)', () => {
  const home = newHome()
  const r = buildIn(home)
  const f = join(r.dir, 'packages', 'core', 'src', 'contracts', 'ports.ts')
  opened(f, () => {
    const b = readFileSync(f)
    b[10] ^= 0x01
    writeFileSync(f, b)
  })
  const v = verify(r.dir)
  assert.deepEqual([v.mismatch, v.missing, v.extra, v.writable, v.ok], [1, 0, 0, 0, v.files - 1])
  assert.deepEqual(v.problems, ['packages/core/src/contracts/ports.ts: changed'])
  throwsWith(() => assertVerified(v), 'release.mismatch')
  const cli = devVt(['release', 'verify', r.buildId], home)
  refused({ ...cli, out: '' }, 'release.mismatch')
  assert.match(cli.out, /mismatch 1, missing 0, extra 0/)
  assert.match(cli.out, /^ {2}packages\/core\/src\/contracts\/ports\.ts: changed$/m)
})

test('verify: a deleted file -> missing 1 -> release.mismatch', () => {
  const v = tampered((d) => opened(join(d, 'cli', 'src'), () => unlinkSync(join(d, 'cli', 'src', 'help.ts'))))
  assert.deepEqual([v.missing, v.mismatch, v.extra], [1, 0, 0])
  throwsWith(() => assertVerified(v), 'release.mismatch')
})

test('verify: an extra file, a writable entry, a changed or extra link, a renamed release, a bad manifest, a missing SHA256SUMS -> release.mismatch', () => {
  const cases: Array<[string, (d: string) => void, (v: ReturnType<typeof verify>) => void]> = [
    ['an extra file', (d) => opened(join(d, 'cli', 'src'), () => { writeFileSync(join(d, 'cli', 'src', 'extra.ts'), 'export {}\n'); chmodSync(join(d, 'cli', 'src', 'extra.ts'), 0o444) }),
      (v) => assert.deepEqual([v.extra, v.writable, v.ok === v.files], [1, 0, true])],
    ['a writable file', (d) => chmodSync(join(d, 'cli', 'src', 'main.ts'), 0o644), (v) => assert.equal(v.writable, 1)],
    ['a writable directory', (d) => chmodSync(join(d, 'api'), 0o755), (v) => assert.equal(v.writable, 1)],
    ['a retargeted link', (d) => opened(join(d, 'cli', 'node_modules'), () => { unlinkSync(join(d, 'cli', 'node_modules', 'vt-broadcast')); symlinkSync('../../packages/core', join(d, 'cli', 'node_modules', 'vt-broadcast')) }), (v) => assert.equal(v.links, 1)],
    ['an extra link', (d) => opened(join(d, 'api', 'src'), () => symlinkSync('/tmp', join(d, 'api', 'src', 'elsewhere'))), (v) => assert.equal(v.links, 1)],
    ['broadcast: a removed core link', (d) => opened(join(d, 'broadcast', 'node_modules', '@vault-timelock'), () => unlinkSync(join(d, 'broadcast', 'node_modules', '@vault-timelock', 'core'))), (v) => assert.equal(v.links, 1)],
    ['broadcast: the core link retargeted', (d) => opened(join(d, 'broadcast', 'node_modules', '@vault-timelock'), () => { unlinkSync(join(d, 'broadcast', 'node_modules', '@vault-timelock', 'core')); symlinkSync('../../../api', join(d, 'broadcast', 'node_modules', '@vault-timelock', 'core')) }), (v) => assert.equal(v.links, 1)],
    ['broadcast: an extra link beside it', (d) => opened(join(d, 'broadcast', 'node_modules'), () => symlinkSync('../../cli', join(d, 'broadcast', 'node_modules', 'cli'))), (v) => assert.equal(v.links, 1)],
    ['a removed link', (d) => opened(join(d, 'cli', 'node_modules'), () => unlinkSync(join(d, 'cli', 'node_modules', 'vt-broadcast'))), (v) => assert.equal(v.links, 1)],
    ['a FIFO', (d) => opened(join(d, 'api', 'src'), () => assert.equal(spawnSync('/usr/bin/mkfifo', [join(d, 'api', 'src', 'pipe')]).status, 0)), (v) => assert.equal(v.extra, 1)],
    ['SHA256SUMS missing', (d) => opened(d, () => unlinkSync(join(d, 'SHA256SUMS'))), (v) => assert.deepEqual([v.files, v.digest, v.extra > 0], [0, null, true])],
    ['a malformed SHA256SUMS line', (d) => opened(d, () => opened(join(d, 'SHA256SUMS'), () => appendFileSync(join(d, 'SHA256SUMS'), 'not a line\n'))), (v) => assert.ok(v.mismatch >= 1)],
    ['SHA256SUMS reordered', (d) => opened(d, () => opened(join(d, 'SHA256SUMS'), () => {
      const lines = readFileSync(join(d, 'SHA256SUMS'), 'utf8').trimEnd().split('\n')
      writeFileSync(join(d, 'SHA256SUMS'), `${[lines[1], lines[0], ...lines.slice(2)].join('\n')}\n`)
    })), (v) => assert.ok(v.mismatch >= 1)],
  ]
  for (const [label, fn, check] of cases) {
    const v = tampered(fn)
    check(v)
    throwsWith(() => assertVerified(v), 'release.mismatch')
    assert.equal(v.testOnly.length, 0, label)
  }
  // Renamed (or copied) under another id: RELEASE.json names another build.
  const r = fresh()
  const other = join(dirname(r.dir), '0123456789ab')
  chmodSync(r.dir, 0o755)
  renameSync(r.dir, other)
  chmodSync(other, 0o555)
  const v = verify(other)
  assert.deepEqual([v.manifest, v.links, v.mismatch, v.extra, v.ok === v.files], [false, 0, 0, 0, true], 'only the build id is wrong')
  throwsWith(() => assertVerified(v), 'release.mismatch')
  // RELEASE.json rewritten (and SHA256SUMS with it): a wrong format, an extra key, a link it does not list.
  for (const edit of [(m: Record<string, unknown>) => { m.format = 'vt-release/0' }, (m: Record<string, unknown>) => { m.extra = 1 }, (m: Record<string, unknown>) => { m.links = {} }]) {
    const t = tampered((d) => opened(d, () => {
      const p = join(d, 'RELEASE.json')
      const m = JSON.parse(readFileSync(p, 'utf8')) as Record<string, unknown>
      edit(m)
      opened(p, () => writeFileSync(p, `${JSON.stringify(m, null, 2)}\n`))
      resum(d)
    }))
    throwsWith(() => assertVerified(t), 'release.mismatch')
  }
  // A retargeted link with RELEASE.json and SHA256SUMS rewritten to match: the link rule alone catches it.
  const relinked = tampered((d) => opened(d, () => {
    opened(join(d, 'cli', 'node_modules'), () => { unlinkSync(join(d, 'cli', 'node_modules', 'vt-broadcast')); symlinkSync('../../api', join(d, 'cli', 'node_modules', 'vt-broadcast')) })
    const p = join(d, 'RELEASE.json')
    const m = JSON.parse(readFileSync(p, 'utf8')) as { links: Record<string, string> }
    m.links['cli/node_modules/vt-broadcast'] = '../../api'
    opened(p, () => writeFileSync(p, `${JSON.stringify(m, null, 2)}\n`))
    resum(d)
  }))
  assert.deepEqual([relinked.links, relinked.manifest, relinked.mismatch, relinked.extra], [1, true, 0, 0])
  throwsWith(() => assertVerified(relinked), 'release.mismatch')
  // E6: a first-party link under broadcast/node_modules other than core, with RELEASE.json and SHA256SUMS rewritten to list it: refused.
  const extra = tampered((d) => opened(d, () => {
    opened(join(d, 'broadcast', 'node_modules'), () => symlinkSync('../../broadcast', join(d, 'broadcast', 'node_modules', 'vt-broadcast')))
    const p = join(d, 'RELEASE.json')
    const m = JSON.parse(readFileSync(p, 'utf8')) as { links: Record<string, string> }
    m.links['broadcast/node_modules/vt-broadcast'] = '../../broadcast'
    opened(p, () => writeFileSync(p, `${JSON.stringify(m, null, 2)}\n`))
    resum(d)
  }))
  assert.deepEqual([extra.links, extra.manifest, extra.mismatch, extra.extra], [1, true, 0, 0])
  throwsWith(() => assertVerified(extra), 'release.mismatch')
  // A release that does not exist.
  const none = verify(join(dirname(r.dir), 'ffffffffffff'))
  assert.deepEqual([none.files, none.problems], [0, ['.: no such release']])
  throwsWith(() => assertVerified(none), 'release.mismatch')
})

// Rewrites SHA256SUMS for the tree as it is now (an attacker or an accident that "fixes" the sums too).
function resum(d: string): void {
  const p = join(d, 'SHA256SUMS')
  const r = spawnSync('/bin/sh', ['-c', 'find . -type f ! -path ./SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256'], { cwd: d, encoding: 'utf8' })
  assert.equal(r.status, 0, r.stderr)
  opened(p, () => writeFileSync(p, r.stdout))
}

test('drop the test-only module into the tree -> release.test-only-present, even with SHA256SUMS rewritten to match', () => {
  const drops: Array<[string, string, string]> = [
    ['api/relay', 'sol-pressure-filter.mjs', '// the SOL withholding filter (R64 harness)\n'],
    ['api/relay', 'helper.mjs', '// eth-pressure-miner, imported for a test\n'],
    ['api/src', 'override.ts', 'export const rpc = process.env.VT_TEST_ETH_RPC\n'],
    ['cli/src', 'testing.ts', '// WITHHELD marker\n'],
    ['packages/core/src', 'x.spec.ts', '// a spec file\n'],
    ['cli/src', 'api.token', 'synthetic-token\n'],
    ['api/src', 'privacycash-withdrawals.jsonl', '{}\n'],
    ['api/src', 'privacycash-withdrawals.lock', '1\n'],
    ['api/src', 'privacycash-lane-mints.jsonl', '{}\n'],
  ]
  for (const [dir, name, text] of drops) {
    for (const reseal of [false, true]) {
      const v = tampered((d) => opened(join(d, dir), () => {
        writeFileSync(join(d, dir, name), text)
        chmodSync(join(d, dir, name), 0o444)
        if (reseal) opened(d, () => resum(d))
      }))
      assert.ok(v.testOnly.some((t) => t.startsWith(`${dir}/${name}: `)), `${dir}/${name}: ${v.testOnly.join('; ')}`)
      if (reseal) assert.deepEqual([v.mismatch, v.missing, v.extra, v.writable], [0, 0, 0, 0], 'integrity alone would pass')
      throwsWith(() => assertVerified(v), 'release.test-only-present')
    }
  }
  // Directories: a test or fixtures dir, a harness dir, a dev-only package, .superpowers.
  for (const dir of ['cli/src/test', 'api/src/fixtures', 'api/relay/harness', 'node_modules/typescript', 'node_modules/@types/node', '.superpowers']) {
    const v = tampered((d) => {
      let parent = dirname(dir)
      while (!existsSync(join(d, parent))) parent = dirname(parent)
      opened(join(d, parent), () => mkdirSync(join(d, dir), { recursive: true }))
    })
    assert.ok(v.testOnly.some((t) => t.startsWith(`${dir}: `)), `${dir}: ${v.testOnly.join('; ')}`)
    throwsWith(() => assertVerified(v), 'release.test-only-present')
  }
  // The relay's own local-only override is its allowed place.
  assert.equal(verify(FIRST.dir).testOnly.length, 0)
  assert.match(readFileSync(join(FIRST.dir, 'api', 'relay', 'relay.mjs'), 'utf8'), /VT_TEST_ETH_RPC/)
})

test('Cfix4 (C4 review m6): verify counts every directory that no listed file or link implies as extra', () => {
  for (const dirs of [['cli/nothing-here'], ['cli/a/b'], ['node_modules/.empty']]) {
    const v = tampered((d) => {
      let parent = dirname(dirs[0])
      while (!existsSync(join(d, parent))) parent = dirname(parent)
      opened(join(d, parent), () => mkdirSync(join(d, dirs[0]), { recursive: true }))
    })
    assert.ok(v.extra >= 1, dirs[0])
    assert.match(v.problems.join('\n'), /an empty directory/)
    throwsWith(() => assertVerified(v), 'release.mismatch')
  }
  // The clean release has no such finding (links imply their directories).
  assert.equal(verify(FIRST.dir).extra, 0)
})

test('Cfix4 (C4 review m7): the VT_TEST_ allowance is a pinned count in the relay; a further hook is refused, a file elsewhere stays refused', () => {
  const allowed = TEST_OVERRIDE_ALLOWED.get('api/relay/relay.mjs') as number
  assert.equal(allowed, 6)
  const realPath = join(CLI, '..', 'api', 'relay', 'relay.mjs') // absent in the mutation copy (no sibling workspaces)
  if (existsSync(realPath)) assert.ok((readFileSync(realPath, 'utf8').match(/VT_TEST_/g) ?? []).length <= allowed, 'the real relay is within the reviewed count')
  const relay = (extra: string) => tampered((d) => opened(join(d, 'api', 'relay'), () => {
    const f = join(d, 'api', 'relay', 'relay.mjs')
    opened(f, () => appendFileSync(f, extra))
    opened(d, () => resum(d))
  }))
  const base = (readFileSync(join(FIRST.dir, 'api', 'relay', 'relay.mjs'), 'utf8').match(/VT_TEST_/g) ?? []).length
  const fill = (n: number) => 'VT_TEST_X '.repeat(n)
  assert.equal(relay(fill(allowed - base)).testOnly.length, 0, 'exactly at the reviewed count')
  const over = relay(fill(allowed - base + 1))
  assert.match(over.testOnly.join('\n'), /api\/relay\/relay\.mjs: test override code beyond its reviewed hooks/)
  throwsWith(() => assertVerified(over), 'release.test-only-present')
})

test('Cfix4 (C4 review m8): outsideSources counts Node\'s CJS global folder $PREFIX/lib/node', () => {
  const prefix = join(T, 'node-prefix')
  mkdirSync(join(prefix, 'bin'), { recursive: true })
  const fakeNode = join(prefix, 'bin', 'node')
  assert.equal(outsideSources(FIRST.dir, fakeNode), 0)
  mkdirSync(join(prefix, 'lib', 'node'), { recursive: true })
  assert.equal(outsideSources(FIRST.dir, fakeNode), 1)
  rmSync(join(prefix, 'lib'), { recursive: true })
  assert.equal(outsideSources(FIRST.dir, fakeNode), 0)
})

test('verify: a node_modules directory above the release (Node would load a missing module from it) -> release.mismatch', () => {
  const home = newHome()
  const r = buildIn(home)
  mkdirSync(join(home, 'node_modules'))
  const v = verify(r.dir)
  assert.equal(v.outside, 1)
  assert.deepEqual([v.mismatch, v.missing, v.extra, v.links, v.writable], [0, 0, 0, 0, 0])
  throwsWith(() => assertVerified(v), 'release.mismatch')
  assert.match(v.problems.join('\n'), /a node_modules directory above the release/)
})

test('build: a dependency installed only outside the repository is not taken from there (the build refuses)', () => {
  const outer = join(T, 'outer')
  mkdirSync(outer)
  const copy = join(outer, 'repo')
  cpSync(REPO, copy, { recursive: true, verbatimSymlinks: true })
  try {
    fakePackage(join(outer, 'node_modules', 'escaped'), 'escaped', '1.0.0')
    const pj = join(copy, 'api', 'package.json')
    const j = JSON.parse(readFileSync(pj, 'utf8')) as { dependencies: Record<string, string> }
    j.dependencies.escaped = '1.0.0'
    writeFileSync(pj, `${JSON.stringify(j, null, 2)}\n`)
    git(copy, 'commit', '-qam', 'a dependency installed above the repository only')
    assert.throws(() => buildIn(newHome(), copy), /api needs escaped, which is not installed/)
  } finally {
    removeTree(outer)
  }
})

test('C4 review m3: an ACL on any entry -> release.mismatch (the mode bits alone do not show it); release.sh agrees', () => {
  const me = spawnSync('/usr/bin/id', ['-un'], { encoding: 'utf8' }).stdout.trim()
  const r = fresh()
  const f = join(r.dir, 'cli', 'src', 'main.ts')
  assert.equal(spawnSync('/bin/chmod', ['+a', `user:${me} allow write`, f]).status, 0)
  assert.equal(lstatSync(f).mode & 0o222, 0, 'the mode bits still say read-only')
  const v = verify(r.dir)
  assert.deepEqual([v.writable, v.mismatch, v.extra], [1, 0, 0])
  assert.match(v.problems.join('\n'), /1 ACL entry/)
  throwsWith(() => assertVerified(v), 'release.mismatch')
  const sh = spawnSync('/bin/sh', [join(CLI, 'scripts', 'release.sh'), 'check', r.dir], { env: { PATH: PATH0, HOME: HOME0, LANG: 'C' }, encoding: 'utf8' })
  assert.equal(sh.status, 1)
  assert.match(sh.stderr, /an ACL/)
})

test('C4 review m4: names from a release tree are printed without control sequences or addresses', () => {
  const home = newHome()
  const r = buildIn(home)
  const name = `x\u001b[2Jy${CANARY}.test.ts`
  opened(join(r.dir, 'cli', 'src'), () => { writeFileSync(join(r.dir, 'cli', 'src', name), '//\n'); chmodSync(join(r.dir, 'cli', 'src', name), 0o444) })
  const out = devVt(['release', 'verify', r.buildId], home)
  assert.equal(out.code, 2)
  for (const t of [out.out, out.err]) {
    assert.ok(!t.includes('\u001b') && !t.includes(CANARY), t)
  }
  assert.match(out.err, /^refused release\.test-only-present: /m)
})

// ---- mainnet only from a verified release

test('vt up --network mainnet from the release: a mismatch or a test-only module -> refused; a clean verify -> on to the Tor check', async () => {
  await assertTorDenied() // never a real testnet/mainnet `vt up` that could reach the system Tor
  const home = newHome()
  const r = buildIn(home)
  // Clean, through the release's own bin/vt: verify passes, then the Tor check refuses (127.0.0.1:9050 is denied in this
  // sandbox). Nothing is written, no tmux is called.
  let out = releaseVt(r.dir, ['--network', 'mainnet', 'up'], home)
  refused(out, 'vt.tor-required')
  assert.ok(!existsSync(join(home, 'mainnet')))
  // In process with a fake probe: it is reached exactly once, after verify.
  let probed = 0
  const upMainnet = (): Promise<number> => up({ network: 'mainnet', open: false, dev: false, env: { PATH: `${F.bin}:${PATH0}`, HOME: HOME0, VT_HOME: home }, repo: r.dir, release: r.buildId },
    { tmux: systemTmux({ env: { PATH: `${F.bin}:${PATH0}` } }), torProbe: async () => { probed++; return false } })
  await rejectsWith(upMainnet, 'vt.tor-required')
  assert.equal(probed, 1)
  // One flipped byte: refused before Tor, every time.
  const f = join(r.dir, 'api', 'src', 'main.ts')
  opened(f, () => appendFileSync(f, '// hot-reloaded\n'))
  out = releaseVt(r.dir, ['--network', 'mainnet', 'up'], home)
  refused(out, 'release.mismatch')
  assert.match(out.err, /mismatch 1/)
  await rejectsWith(upMainnet, 'release.mismatch')
  assert.equal(probed, 1, 'Tor was not reached')
  assert.deepEqual(F.calls(), [], 'no tmux call before the release verifies and Tor answers')
  // A test-only module, with SHA256SUMS rewritten to match: refused (release.test-only-present).
  const r2 = buildIn(newHome())
  opened(join(r2.dir, 'api', 'relay'), () => writeFileSync(join(r2.dir, 'api', 'relay', 'sol-pressure-filter.mjs'), '// R64 harness\n'))
  opened(r2.dir, () => resum(r2.dir))
  refused(releaseVt(r2.dir, ['--network', 'mainnet', 'up'], dirname(dirname(r2.dir))), 'release.test-only-present')
  // testnet and local from a release do not need a verify (testnet still needs Tor).
  refused(releaseVt(r.dir, ['--network', 'testnet', 'up'], home), 'vt.tor-required')
  // From the development tree: never (vt.mainnet-dev-tree), whatever the releases say.
  refused(devVt(['--network', 'mainnet', 'up'], home), 'vt.mainnet-dev-tree')
})

test('assertMainnetAllowed: a development tree never; a release only through verifyRelease, which is called for mainnet only', () => {
  const calls: string[] = []
  const ok = (id: string): void => { calls.push(id) }
  throwsWith(() => assertMainnetAllowed('mainnet', null, ok), 'vt.mainnet-dev-tree')
  assert.deepEqual(calls, [])
  assertMainnetAllowed('mainnet', '0123456789ab', ok)
  assert.deepEqual(calls, ['0123456789ab'])
  throwsWith(() => assertMainnetAllowed('mainnet', '0123456789ab', () => { throw Object.assign(new Error('x'), { guardId: 'release.mismatch' }) }), 'release.mismatch')
  for (const n of ['local', 'testnet'] as const) {
    assertMainnetAllowed(n, null, ok)
    assertMainnetAllowed(n, '0123456789ab', ok)
  }
  assert.deepEqual(calls, ['0123456789ab'])
})

// ---- the CLI: verify, list, usage

test('vt release verify | list | build through bin/vt: ids, usage errors, a release verifying itself', () => {
  const home = dirname(dirname(FIRST.dir))
  let r = devVt(['release', 'verify', FIRST.buildId], home)
  assert.equal(r.code, 0, r.err)
  assert.match(r.out, new RegExp(`^vt release verify ${FIRST.buildId}: files \\d+, ok \\d+, mismatch 0, missing 0, extra 0, links 0, writable 0, outside 0, manifest ok, test-only 0; SHA256SUMS sha256 [0-9a-f]{64}\\nvt release verify ${FIRST.buildId}: ok\\n$`))
  // From inside the release, without an id: that release.
  r = releaseVt(FIRST.dir, ['release', 'verify'], home)
  assert.equal(r.code, 0, r.err)
  assert.match(r.out, /: ok\n$/)
  r = devVt(['release', 'list'], home)
  assert.equal(r.code, 0, r.err)
  assert.match(r.out, new RegExp(`^${FIRST.buildId} {2}commit ${FIRST.commit} {2}built \\d{4}-\\d\\d-\\d\\dT`, 'm'))
  assert.deepEqual(list(home).map((x) => x.id), [FIRST.buildId])
  assert.match(releaseVt(FIRST.dir, ['release', 'list'], home).out, /\(this one\)/)
  assert.match(devVt(['release', 'list'], newHome()).out, /no release in/)
  // An unknown id: no such release (release.mismatch). Usage errors: exit 1, never echoing the value.
  r = devVt(['release', 'verify', 'ffffffffffff'], home)
  refused({ ...r, out: '' }, 'release.mismatch')
  assert.match(r.out, /^ {2}\.: no such release$/m)
  for (const args of [['release'], ['release', 'verify'], ['release', 'verify', `../${CANARY}`], ['release', 'verify', 'ABCDEF012345'], ['release', 'list', 'x'],
    ['release', 'build', 'now'], ['release', 'publish']]) {
    r = devVt(args, home)
    assert.equal(r.code, 1, args.join(' '))
    assert.ok(!r.err.includes(CANARY))
    assert.match(r.err, /^vt: /)
  }
  r = releaseVt(FIRST.dir, ['release', 'build'], home)
  assert.equal(r.code, 1)
  assert.equal(r.err, 'vt: vt release build runs from the development tree, not from a release\n')
})

// ---- the independent shell check (cli/scripts/release.sh, ported from MQ)

test('cli/scripts/release.sh check agrees: a clean release passes; each tamper fails', () => {
  const check = (dir: string): Run => {
    const r = spawnSync('/bin/sh', [join(CLI, 'scripts', 'release.sh'), 'check', dir], { env: { PATH: PATH0, HOME: HOME0, LANG: 'C' }, encoding: 'utf8' })
    return { code: r.status, out: r.stdout, err: r.stderr }
  }
  let r = check(FIRST.dir)
  assert.equal(r.code, 0, r.err)
  assert.match(r.out, new RegExp(`^release check: ${FIRST.buildId} ok \\(\\d+ files, SHA256SUMS sha256 [0-9a-f]{16}…; read-only; no test harness\\)\\n$`))
  const fails: Array<[string, (d: string) => void, RegExp]> = [
    ['a flipped byte', (d) => opened(join(d, 'cli', 'src', 'main.ts'), () => appendFileSync(join(d, 'cli', 'src', 'main.ts'), ' ')), /SHA256SUMS: 1 mismatched/],
    ['an extra file', (d) => opened(join(d, 'cli'), () => writeFileSync(join(d, 'cli', 'extra.ts'), '\n')), /does not list exactly/],
    ['writable', (d) => chmodSync(join(d, 'web'), 0o755), /writable/],
    ['a harness, resealed', (d) => opened(join(d, 'api', 'relay'), () => { writeFileSync(join(d, 'api', 'relay', 'eth-pressure-miner.mjs'), '//\n'); chmodSync(join(d, 'api', 'relay', 'eth-pressure-miner.mjs'), 0o444); opened(d, () => resum(d)) }), /test harness/],
    ['VT_TEST_ elsewhere, resealed', (d) => opened(join(d, 'api', 'src'), () => { writeFileSync(join(d, 'api', 'src', 'o.ts'), 'process.env.VT_TEST_X\n'); chmodSync(join(d, 'api', 'src', 'o.ts'), 0o444); opened(d, () => resum(d)) }), /outside api\/relay\/relay\.mjs/],
    ['a retargeted link', (d) => opened(join(d, 'cli', 'node_modules'), () => { unlinkSync(join(d, 'cli', 'node_modules', 'vt-broadcast')); symlinkSync('../../api', join(d, 'cli', 'node_modules', 'vt-broadcast')) }), /unexpected link/],
    ['a broadcast link other than core, listed in RELEASE.json and resealed', (d) => opened(d, () => {
      opened(join(d, 'broadcast', 'node_modules'), () => symlinkSync('../../broadcast', join(d, 'broadcast', 'node_modules', 'vt-broadcast')))
      const p = join(d, 'RELEASE.json')
      const m = JSON.parse(readFileSync(p, 'utf8')) as { links: Record<string, string> }
      m.links['broadcast/node_modules/vt-broadcast'] = '../../broadcast'
      opened(p, () => writeFileSync(p, `${JSON.stringify(m, null, 2)}\n`))
      resum(d)
    }), /unexpected link: broadcast\/node_modules\/vt-broadcast/],
    ['a dev-only package', (d) => opened(join(d, 'node_modules'), () => mkdirSync(join(d, 'node_modules', 'typescript'), { mode: 0o555 })), /dev-only packages/],
    ['a marker in an innocent file, resealed', (d) => opened(join(d, 'api', 'src'), () => { writeFileSync(join(d, 'api', 'src', 'util.ts'), '// anvil_dropTransaction\n'); chmodSync(join(d, 'api', 'src', 'util.ts'), 0o444); opened(d, () => resum(d)) }), /pressure-harness markers/],
    ['a state file, resealed', (d) => opened(join(d, 'cli'), () => { writeFileSync(join(d, 'cli', 'api.token'), 'synthetic\n'); chmodSync(join(d, 'cli', 'api.token'), 0o444); opened(d, () => resum(d)) }), /state or secret files/],
    ['a node_modules above it', (d) => mkdirSync(join(dirname(dirname(d)), 'node_modules')), /node_modules directory above the release/],
    ['Cfix4 m6: an extra empty directory', (d) => opened(join(d, 'cli'), () => mkdirSync(join(d, 'cli', 'nothing-here'), { mode: 0o555 })), /empty directory/],
    ['Cfix4 m6: a directory holding only an empty directory', (d) => opened(join(d, 'cli'), () => mkdirSync(join(d, 'cli', 'a', 'b'), { recursive: true })), /empty directory/],
    ['Cfix4 m7: a second VT_TEST_ hook in the relay, resealed', (d) => opened(join(d, 'api', 'relay'), () => {
      const f = join(d, 'api', 'relay', 'relay.mjs')
      opened(f, () => appendFileSync(f, 'VT_TEST_A VT_TEST_B VT_TEST_C VT_TEST_D VT_TEST_E VT_TEST_F VT_TEST_G\n'))
      opened(d, () => resum(d))
    }), /more VT_TEST_ hooks than were reviewed/],
  ]
  for (const [label, fn, want] of fails) {
    const rel = fresh()
    fn(rel.dir)
    r = check(rel.dir)
    assert.equal(r.code, 1, `${label}: ${r.out}`)
    assert.match(r.err, want, label)
  }
  // Cfix4 m8: Node's CJS global folder next to the node that runs the check ($PREFIX/lib/node) -> refused; absent -> fine.
  {
    const prefix = join(T, 'fake-prefix')
    mkdirSync(join(prefix, 'bin'), { recursive: true })
    writeExe(join(prefix, 'bin', 'node'), '#!/bin/sh\nexit 0\n')
    const withNode = (dir: string): Run => {
      const x = spawnSync('/bin/sh', [join(CLI, 'scripts', 'release.sh'), 'check', dir], { env: { PATH: `${join(prefix, 'bin')}:${PATH0}`, HOME: HOME0, LANG: 'C' }, encoding: 'utf8' })
      return { code: x.status, out: x.stdout, err: x.stderr }
    }
    assert.equal(withNode(FIRST.dir).code, 0)
    mkdirSync(join(prefix, 'lib', 'node'), { recursive: true })
    const x = withNode(FIRST.dir)
    assert.equal(x.code, 1, x.out)
    assert.match(x.err, /Node's global module folder/)
    rmSync(join(prefix, 'lib'), { recursive: true })
  }
  // Renamed under another id.
  const rel = fresh()
  const other = join(dirname(rel.dir), '0123456789ab')
  chmodSync(rel.dir, 0o755)
  renameSync(rel.dir, other)
  chmodSync(other, 0o555)
  r = check(other)
  assert.equal(r.code, 1)
  assert.match(r.err, /RELEASE\.json does not name build id 0123456789ab/)
  assert.ok(COPY.includes('cli/src/') && !COPY.some((c) => c.startsWith('cli/test') || c.startsWith('cli/scripts')))
})

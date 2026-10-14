// cli/test/release-real.test.ts — the real `vt release build` of this repository (plan Task C4), phase B: the build
// applies sandbox-exec to the web build itself, and macOS refuses a sandbox inside the suite's.
// The tree built is this repository's tracked files (the index, with their working-tree bytes) copied into a temp git
// repository, with the node_modules directories APFS-cloned (`cp -Rc`; the linked store's relative links resolve inside
// the copy). Where api/relay or api/serve are not in this tree yet (before S3 merges), synthetic stubs stand in. The
// copy's own bin/vt builds it twice, into two temp VT_HOMEs, with the real sandboxed vite build:
//   · the same build id and byte-identical SHA256SUMS: the page build is reproducible (carry-forward 2, W1);
//   · what the release holds (carry-forwards 1 and 4): the sealers (copied and hashed, never run), the workspace links,
//     the production closure without dev-only packages, no cli/test (fixtures), no tests, docs or state;
//   · the closure loads from inside the release; the release's own bin/vt verifies it; cli/scripts/release.sh agrees.
// Nothing here starts a server, reaches Tor or the network, or runs a sealer.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { BUILD_ID, removeTree, verify } from '../src/ops/release.ts'
import { CLI, NODE, PATH0, tempDir } from './lib.ts'

const REPO = dirname(CLI)
let T = ''
let COPY = ''
let HOME0 = ''
const sha = (p: string): string => createHash('sha256').update(readFileSync(p)).digest('hex')
const sh = (cmd: string, cwd: string): string => {
  const r = spawnSync('/bin/sh', ['-c', cmd], { cwd, env: { PATH: PATH0, HOME: HOME0, LANG: 'C' }, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
  assert.equal(r.status, 0, `${cmd}: ${r.stderr}`)
  return r.stdout
}
function vtBuild(home: string): { code: number | null; out: string; err: string } {
  const r = spawnSync(join(COPY, 'bin', 'vt'), ['release', 'build'], { env: { PATH: PATH0, HOME: HOME0, LANG: 'C', VT_HOME: home, VAULT_TIMELOCK_DIR: join(T, 'out') }, encoding: 'utf8', timeout: 600_000 })
  return { code: r.status, out: r.stdout, err: r.stderr }
}
const idOf = (out: string): string => {
  const m = /^vt release build: built ([0-9a-f]{12}) from commit [0-9a-f]{40}$/m.exec(out)
  assert.ok(m !== null, out)
  return m[1]
}

before(() => {
  T = tempDir('vt-release-real-')
  HOME0 = join(T, 'home')
  mkdirSync(HOME0, { mode: 0o700 })
  COPY = join(T, 'repo')
  mkdirSync(COPY)
  sh(`git -C '${REPO}' ls-files -z | tar --null -T - -cf - | tar -xf - -C '${COPY}'`, REPO)
  for (const d of ['node_modules', 'broadcast/node_modules', 'packages/core/node_modules', 'cli/node_modules', 'api/node_modules', 'web/node_modules']) {
    if (existsSync(join(REPO, d))) sh(`cp -Rc '${join(REPO, d)}' '${join(COPY, d)}'`, REPO)
  }
  for (const [d, f] of [['api/relay', 'relay.mjs'], ['api/serve', 'serve.mjs']]) {
    if (!existsSync(join(COPY, d, f))) {
      mkdirSync(join(COPY, d), { recursive: true })
      writeFileSync(join(COPY, d, f), `// synthetic stand-in until S3 merges (release-real.test.ts)\n`)
    }
  }
  sh('git init -q . && git add -A && git -c user.name=synthetic -c user.email=synthetic@example.invalid -c commit.gpgsign=false commit -qm release-real', COPY)
})
after(() => removeTree(T))

test('vt release build of this repository, twice: one build id, byte-identical SHA256SUMS (reproducible page), verified, read-only', () => {
  const homes = [join(T, 'vt-home-a'), join(T, 'vt-home-b')]
  const ids: string[] = []
  for (const h of homes) {
    mkdirSync(h, { mode: 0o700 })
    const r = vtBuild(h)
    assert.equal(r.code, 0, r.err)
    ids.push(idOf(r.out))
    assert.match(r.out, /^ {2}verify {2}files \d+, ok \d+, mismatch 0, missing 0, extra 0, links 0, writable 0, outside 0, manifest ok, test-only 0; SHA256SUMS sha256 [0-9a-f]{64}$/m)
  }
  assert.equal(ids[0], ids[1])
  assert.match(ids[0], BUILD_ID)
  const [a, b] = homes.map((h) => join(h, 'releases', ids[0]))
  assert.deepEqual(readFileSync(join(a, 'SHA256SUMS')), readFileSync(join(b, 'SHA256SUMS')), 'two builds of one tree are byte-identical, the page included')
  const v = verify(a)
  assert.deepEqual([v.mismatch, v.missing, v.extra, v.links, v.writable, v.outside, v.manifest, v.testOnly], [0, 0, 0, 0, 0, 0, true, []])
  assert.ok(v.files > 1000 && v.ok === v.files, `files ${v.files}`)
  // Building again into a home that has it: reused, not rebuilt.
  const again = vtBuild(homes[0])
  assert.equal(again.code, 0, again.err)
  assert.match(again.out, new RegExp(`^vt release build: already built \\(verified\\) ${ids[0]} from commit`))
})

test('M-1: sandboxed client commands run from a BUILT release (the release tree is allowed as built; no development-tree subset)', () => {
  const home = join(T, 'vt-home-a')
  const rel = realpathSync(join(home, 'releases', readdirSync(join(home, 'releases'))[0]))
  const run = (args: string[]) => spawnSync(join(rel, 'cli', 'bin', 'vt'), args, { env: { PATH: PATH0, HOME: HOME0, LANG: 'C', VT_HOME: home, VAULT_TIMELOCK_DIR: join(T, 'out') }, encoding: 'utf8', timeout: 120_000, cwd: T })
  // The profile of a release names the release root as ONE subpath (and nothing of the dev subset)
  const prof = spawnSync(NODE, [join(rel, 'cli', 'src', 'ops', 'profile.ts'), 'status'], { env: { PATH: PATH0, HOME: HOME0, VT_HOME: home, VAULT_TIMELOCK_DIR: join(T, 'out'), VT_NETWORK: 'local' }, encoding: 'utf8' }).stdout
  assert.ok(prof.includes(`(subpath "${rel}")`) && !prof.includes(`${rel}/cli/src`), 'release root as built')
  // No stack runs on this temp VT_HOME: the commands must still RUN inside the sandbox (no abort, no sandbox refusal) and say so
  const st = run(['status', '--network', 'local'])
  assert.equal(st.status, 1, st.stderr)
  assert.match(st.stdout, /^local {4}down$/m, JSON.stringify([st.status, st.stdout, st.stderr]))
  const pf = run(['preflight', '--network', 'local'])
  assert.equal(pf.status, 1, pf.stderr)
  assert.match(pf.stdout, /no local stack is up/)
  const jl = run(['job', 'list', '--network', 'local'])
  assert.equal(jl.status, 1)
  assert.match(jl.stdout + jl.stderr, /no readable API token for local|vt: error/, JSON.stringify([jl.status, jl.stdout, jl.stderr, jl.signal]))
  for (const r of [st, pf, jl]) assert.ok(!/Native stack trace|refused vt\./.test(r.stdout + r.stderr))
})

test('what the release holds: the sealers, the workspace links, the production closure; no tests, fixtures, docs, state or dev-only packages', () => {
  const home = join(T, 'vt-home-a')
  const id = readdirSync(join(home, 'releases'))[0]
  const rel = realpathSync(join(home, 'releases', id))
  // Carry-forward 1: both sealers, byte for byte, in SHA256SUMS (hashed, never run); vt-broadcast through cli/node_modules.
  const sums = readFileSync(join(rel, 'SHA256SUMS'), 'utf8')
  for (const s of ['1password-timelock.sh', 'timelock-key.sh']) {
    assert.equal(sha(join(rel, s)), sha(join(COPY, s)))
    assert.ok(sums.includes(`${sha(join(rel, s))}  ./${s}\n`))
  }
  const files = sh('find . -type f -print', rel).split('\n').filter((l) => l !== '')
  const links = sh('find . -type l -print | LC_ALL=C sort', rel)
  assert.equal(links, './api/node_modules/@vault-timelock/core\n./api/node_modules/vt-broadcast\n./broadcast/node_modules/@vault-timelock/core\n./cli/node_modules/@vault-timelock/core\n./cli/node_modules/vt-broadcast\n')
  // Carry-forward 4, and cli/test/fixtures out (VT_SEALER is always refused in a release).
  for (const f of files) {
    assert.ok(!/^\.\/(?:cli\/(?:test|scripts)|docs|test|web\/src|\.superpowers|\.git)\//.test(f), f)
    assert.ok(!/\/node_modules\/(?:typescript|@types|vite|vitest|jsdom|@testing-library)\//.test(f), f)
    assert.ok(!/(?:^|\/)(?:api\.token|relay-ticket\.key|up\.json|journal\.jsonl|identity\.key)$|\.age$/.test(f), f)
  }
  assert.ok(!existsSync(join(rel, 'cli', 'test')))
  for (const top of ['1password-timelock.sh', 'timelock-key.sh', 'RELEASE.json', 'SHA256SUMS', 'api', 'broadcast', 'cli', 'node_modules', 'packages', 'web']) assert.ok(existsSync(join(rel, top)), top)
  assert.deepEqual(readdirSync(rel).sort(), ['1password-timelock.sh', 'RELEASE.json', 'SHA256SUMS', 'api', 'broadcast', 'cli', 'node_modules', 'packages', 'timelock-key.sh', 'web'])
  assert.ok(existsSync(join(rel, 'web', 'dist', 'index.html')))
  // The closure loads from inside the release, outside the development tree.
  const load = (cwd: string, names: string[]): string => {
    const r = spawnSync(NODE, ['--input-type=module', '-e', `for (const n of ${JSON.stringify(names)}) { await import(n); console.log(import.meta.resolve(n)) }`],
      { cwd, env: { PATH: PATH0, HOME: HOME0 }, encoding: 'utf8' })
    assert.equal(r.status, 0, r.stderr)
    return r.stdout
  }
  for (const line of load(join(rel, 'packages', 'core'), ['viem', 'viem/accounts', '@solana/web3.js', 'age-encryption', '@noble/hashes/sha2.js', '@scure/base']).trim().split('\n')) {
    assert.ok(line.startsWith(`file://${rel}/`), line)
  }
  // E6: the release's broadcast imports core (its one link), from inside the release.
  assert.equal(load(join(rel, 'broadcast'), ['@vault-timelock/core/text/envelope.ts']), `file://${rel}/packages/core/src/text/envelope.ts\n`)
  for (const line of load(join(rel, 'broadcast'), ['viem/accounts', 'socks-proxy-agent', 'age-encryption']).trim().split('\n')) assert.ok(line.startsWith(`file://${rel}/`), line)
  assert.equal(load(join(rel, 'cli'), ['vt-broadcast/src/config.ts', '@vault-timelock/core/contracts']), `file://${rel}/broadcast/src/config.ts\nfile://${rel}/packages/core/src/contracts/index.ts\n`)
  // The release's own bin/vt verifies it; the independent shell check agrees.
  const self = spawnSync(join(rel, 'cli', 'bin', 'vt'), ['release', 'verify'], { env: { PATH: PATH0, HOME: HOME0, VT_HOME: home }, encoding: 'utf8' })
  assert.equal(self.status, 0, self.stderr)
  assert.match(self.stdout, new RegExp(`^vt release verify ${id}: ok$`, 'm'))
  const check = spawnSync('/bin/sh', [join(CLI, 'scripts', 'release.sh'), 'check', rel], { env: { PATH: PATH0, HOME: HOME0, LANG: 'C' }, encoding: 'utf8' })
  assert.equal(check.status, 0, check.stderr)
  assert.match(check.stdout, new RegExp(`^release check: ${id} ok `))
})

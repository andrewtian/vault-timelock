import { test } from 'node:test'
import assert from 'node:assert/strict'
import { copyFileSync, mkdtempSync, mkdirSync, readdirSync, readFileSync, realpathSync, writeFileSync, rmSync, unlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { spawnSync } from 'node:child_process'

const runner = new URL('./run.ts', import.meta.url).pathname
const ROOT = new URL('../../', import.meta.url).pathname

const SRC = `export function check(ok: boolean): void {
  if (!ok) throw new Error('g1:fail') // @guard:g1
}
`
const GOOD_TEST = `import { test } from 'node:test'
import assert from 'node:assert/strict'
import { check } from '../../src/g.ts'
test('g1 refuses', () => { assert.throws(() => check(false), /g1:fail/) })
`
const WEAK_TEST = `import { test } from 'node:test'
import assert from 'node:assert/strict'
import { check } from '../../src/g.ts'
test('only the happy path', () => { check(true); assert.ok(true) })
`

function project(opts: { test: string; guards: Record<string, string[]>; src?: string; testFile?: string }): string {
  const d = mkdtempSync(join(tmpdir(), 'vt-runner-test-'))
  mkdirSync(join(d, 'src')); mkdirSync(join(d, 'test/offline'), { recursive: true })
  mkdirSync(join(d, 'test/mutation'), { recursive: true })
  writeFileSync(join(d, 'src/g.ts'), opts.src ?? SRC)
  writeFileSync(join(d, opts.testFile ?? 'test/offline/g.test.ts'), opts.test)
  writeFileSync(join(d, 'test/mutation/guards.json'), JSON.stringify(opts.guards))
  return d
}

function run(root: string, extra: string[] = [], o: { env?: Record<string, string>; runner?: string } = {}) {
  const r = spawnSync(process.execPath, [o.runner ?? runner, '--root', root, ...extra], { encoding: 'utf8', env: o.env ?? process.env })
  return { code: r.status, out: (r.stdout ?? '') + (r.stderr ?? '') }
}

test('(a) KILLED when the mapped test catches the blanked line', () => {
  const d = project({ test: GOOD_TEST, guards: { g1: ['test/offline/g.test.ts'] } })
  try {
    const r = run(d)
    assert.equal(r.code, 0, r.out)
    assert.match(r.out, /KILLED g1/)
    assert.match(r.out, /KILLED 1\/1/)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('(b) SURVIVED with non-zero exit when the test does not exercise the guard', () => {
  const d = project({ test: WEAK_TEST, guards: { g1: ['test/offline/g.test.ts'] } })
  try {
    const r = run(d)
    assert.notEqual(r.code, 0, r.out)
    assert.match(r.out, /SURVIVED g1/)
    assert.doesNotMatch(r.out, /KILLED 1\/1/)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('(c1) fails when a marker is missing from guards.json', () => {
  const d = project({ test: GOOD_TEST, guards: {} })
  try {
    const r = run(d)
    assert.notEqual(r.code, 0, r.out)
    assert.match(r.out, /marker without guards\.json entry: g1/)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('(c2) fails when a guards.json entry has no marker', () => {
  const d = project({ test: GOOD_TEST, guards: { g1: ['test/offline/g.test.ts'], ghost: ['test/offline/g.test.ts'] } })
  try {
    const r = run(d)
    assert.notEqual(r.code, 0, r.out)
    assert.match(r.out, /guards\.json entry without marker: ghost/)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('(c3) fails when an id has more than one marker line', () => {
  const src = SRC + `export function other(ok: boolean): void {
  if (!ok) throw new Error('g1:fail') // @guard:g1
}
`
  const d = project({ test: GOOD_TEST, guards: { g1: ['test/offline/g.test.ts'] }, src })
  try {
    const r = run(d)
    assert.notEqual(r.code, 0, r.out)
    assert.match(r.out, /more than one marker: g1/)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('--only restricts the run to one guard', () => {
  const d = project({ test: GOOD_TEST, guards: { g1: ['test/offline/g.test.ts'] } })
  try {
    const r = run(d, ['--only', 'g1'])
    assert.equal(r.code, 0, r.out)
    assert.match(r.out, /KILLED 1\/1/)
    const bad = run(d, ['--only', 'nope'])
    assert.notEqual(bad.code, 0, bad.out)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('constructor marker is not satisfied by Object.prototype', () => {
  const src = `export function f(ok: boolean): void {
  if (!ok) throw new Error('x') // @guard:constructor
}
`
  const d = project({ test: GOOD_TEST, guards: {}, src })
  try {
    const r = run(d)
    assert.notEqual(r.code, 0, r.out)
    assert.match(r.out, /marker without guards\.json entry: constructor/)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('infinite loop under mutation is TIMEOUT, a hard failure, never KILLED', () => {
  const src = `export function spin(): void {
  let done = false
  done = true // @guard:g1
  while (!done) { /* spin */ }
}
`
  const t = `import { test } from 'node:test'
import { spin } from '../../src/g.ts'
test('spin returns', () => { spin() })
`
  const d = project({ test: t, guards: { g1: ['test/offline/g.test.ts'] }, src })
  try {
    const r = run(d, ['--timeout-ms', '4000'])
    assert.notEqual(r.code, 0, r.out)
    assert.match(r.out, /^TIMEOUT g1$/m, 'the MUTATED run timed out (not the baseline)')
    assert.doesNotMatch(r.out, /KILLED g1|baseline/)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

// Task H0 item 3 (the Task 3 deferred item): --timeout-ms used to bound the unmutated baseline too, so a
// slow baseline under load read as a TIMEOUT of the guard. The baseline now has its own bound.
test('--timeout-ms bounds only the mutated run; --baseline-timeout-ms bounds the baseline', () => {
  const src = `export function spin(): void {
  let done = false
  done = true // @guard:g1
  while (!done) { /* spin */ }
}
`
  const t = `import { test } from 'node:test'
import { spin } from '../../src/g.ts'
test('slow, then spin', async () => { await new Promise((r) => setTimeout(r, 3000)); spin() })
`
  const d = project({ test: t, guards: { g1: ['test/offline/g.test.ts'] }, src })
  try {
    const r = run(d, ['--timeout-ms', '2000'])
    assert.notEqual(r.code, 0, r.out)
    assert.match(r.out, /^TIMEOUT g1$/m, 'a 3 s baseline passes despite --timeout-ms 2000; the mutated run then times out')
    assert.doesNotMatch(r.out, /baseline|KILLED g1/)
    const b = run(d, ['--timeout-ms', '2000', '--baseline-timeout-ms', '1000'])
    assert.notEqual(b.code, 0, b.out)
    assert.match(b.out, /^TIMEOUT g1 \(baseline\)$/m)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('zero guards fails unless --allow-empty', () => {
  const d = project({ test: GOOD_TEST, guards: {}, src: 'export const x = 1\n' })
  try {
    const r = run(d)
    assert.notEqual(r.code, 0, r.out)
    assert.match(r.out, /no guards found/)
    const ok = run(d, ['--allow-empty'])
    assert.equal(ok.code, 0, ok.out)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('relative --root is resolved', () => {
  const d = project({ test: GOOD_TEST, guards: { g1: ['test/offline/g.test.ts'] } })
  try {
    const r = spawnSync(process.execPath, [runner, '--root', '.'], { cwd: d, encoding: 'utf8' })
    assert.equal(r.status, 0, r.stdout + r.stderr)
    assert.match(r.stdout, /KILLED 1\/1/)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('BASELINE-FAILED: a test already failing unmutated is never KILLED', () => {
  const bad = GOOD_TEST + `test('always fails', () => { assert.fail('baseline') })\n`
  const d = project({ test: bad, guards: { g1: ['test/offline/g.test.ts'] } })
  try {
    const r = run(d)
    assert.notEqual(r.code, 0, r.out)
    assert.match(r.out, /BASELINE-FAILED g1/)
    assert.doesNotMatch(r.out, /KILLED g1/)
    assert.doesNotMatch(r.out, /KILLED 1\/1/)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

// P1 review I1: a child that crashes (killed by a signal, spawn failure) is no evidence that a test caught
// the mutation. `node --test` exits 1 for a failing test, so the fixture kills the runner's child itself
// (its parent, the `node --test` process) with SIGKILL: exit code null, signal SIGKILL.
const KILL_PARENT = `process.kill(process.ppid, 'SIGKILL')`
test('P1 review I1: a mutant run whose child is SIGKILLed is ERROR (exit 1), never KILLED', () => {
  const t = `import { test } from 'node:test'
import assert from 'node:assert/strict'
import { check } from '../../src/g.ts'
test('refuses, or the child dies', () => {
  let threw = false
  try { check(false) } catch { threw = true }
  if (!threw) ${KILL_PARENT}
})
`
  const d = project({ test: t, guards: { g1: ['test/offline/g.test.ts'] } })
  try {
    for (const jobs of ['1', '2']) {
      const r = run(d, ['--jobs', jobs])
      assert.equal(r.code, 1, r.out)
      assert.match(r.out, /^ERROR g1 \(child crashed\)$/m)
      assert.doesNotMatch(r.out, /KILLED g1|SURVIVED g1/)
      assert.doesNotMatch(r.out, /KILLED 1\/1/)
      assert.match(r.out, /^ERRORED 1: g1 \(/m)
    }
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('P1 review I1: a baseline (unmutated) run whose child is SIGKILLed is ERROR, the guard is not mutated', () => {
  const t = `import { test } from 'node:test'
test('dies', () => { ${KILL_PARENT} })
`
  const d = project({ test: t, guards: { g1: ['test/offline/g.test.ts'] } })
  try {
    const r = run(d)
    assert.equal(r.code, 1, r.out)
    assert.match(r.out, /^ERROR g1 \(baseline child crashed\)$/m)
    assert.doesNotMatch(r.out, /KILLED g1|SURVIVED g1|BASELINE-FAILED/)
    assert.match(r.out, /^ERRORED 1: g1 \(/m)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

// ---- Task H0 item 3 (K29): the confined runner
//
// The runner's children get env -i (exactly PATH HOME LANG TERM, HOME a fresh temp dir) and the suite
// sandbox profile of scripts/test-offline.sh; that script's OWN_SANDBOX files run unsandboxed under the
// same env. To prove the scrub, the PARENT gets synthetic hostile values (never the operator's key).
const HOSTILE = { ALCHEMY_API_KEY: 'synthetic-canary', NODE_OPTIONS: '--no-deprecation', HTTPS_PROXY: 'http://proxy.invalid:1', VT_RUNNER_CANARY: 'synthetic' }
const hostileEnv = () => ({ ...process.env, ...HOSTILE } as Record<string, string>)
const NOT_THE_SANDBOX = '(version 1)(allow default)(deny network-outbound)' // differs from the suite profile

// The mapped test asserts its own confinement; the env checks come first, so an unconfined child fails
// before it opens any socket (and TEST-NET-1 / [::1]:9050 reach nothing even then).
const confinedTest = (sandboxed: boolean) => `import { test } from 'node:test'
import assert from 'node:assert/strict'
import { connect } from 'node:net'
import { statSync } from 'node:fs'
import { userInfo } from 'node:os'
import { spawnSync } from 'node:child_process'
import { check } from '../../src/g.ts'
const attempt = (host: string, port: number) => new Promise<string>((done) => {
  const s = connect({ host, port })
  const t = setTimeout(() => { s.destroy(); done('timeout') }, 2000)
  s.on('connect', () => { clearTimeout(t); s.destroy(); done('connected') })
  s.on('error', (e: NodeJS.ErrnoException) => { clearTimeout(t); done(e.code ?? 'error') })
})
test('the runner child is confined', async () => {
  for (const n of ['ALCHEMY_API_KEY', 'NODE_OPTIONS', 'HTTPS_PROXY', 'VT_RUNNER_CANARY']) assert.equal(process.env[n], undefined, n)
  assert.deepEqual(Object.keys(process.env).filter((n) => !['PATH', 'HOME', 'LANG', 'TERM', 'NODE_TEST_CONTEXT', '__CF_USER_TEXT_ENCODING'].includes(n)), [])
  assert.notEqual(process.env.HOME, userInfo().homedir, 'HOME is synthetic')
  assert.ok(statSync(process.env.HOME!).isDirectory())
  // macOS refuses to apply a different profile inside a sandbox (exit 71): a network-free proof of where we are
  const nested = spawnSync('/usr/bin/sandbox-exec', ['-p', ${JSON.stringify(NOT_THE_SANDBOX)}, '/usr/bin/true']).status
  assert.equal(nested, ${sandboxed ? 71 : 0}, ${sandboxed ? "'inside the suite sandbox'" : "'outside any sandbox'"})
  ${sandboxed ? "assert.equal(await attempt('192.0.2.1', 9), 'EPERM')\n  assert.equal(await attempt('::1', 9050), 'EPERM')" : ''}
  assert.throws(() => check(false), /g1:fail/)
})
`

test('K29: a mapped test runs under env -i and the suite sandbox; the parent\'s (synthetic) key, NODE_OPTIONS and proxy never reach it', () => {
  const d = project({ test: confinedTest(true), guards: { g1: ['test/offline/g.test.ts'] } })
  try {
    const r = run(d, [], { env: hostileEnv() })
    assert.equal(r.code, 0, r.out)
    assert.match(r.out, /^SENTINEL ok /m)
    assert.match(r.out, /^KILLED g1$/m)
    assert.match(r.out, /KILLED 1\/1/)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('K29: an OWN_SANDBOX file (confine.test.ts) runs unsandboxed, but still under env -i with a synthetic HOME', () => {
  const d = project({ test: confinedTest(false), guards: { g1: ['test/offline/confine.test.ts'] }, testFile: 'test/offline/confine.test.ts' })
  try {
    const r = run(d, [], { env: hostileEnv() })
    assert.equal(r.code, 0, r.out)
    assert.match(r.out, /^KILLED 1\/1$/m)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('K29: one guard may map to both kinds of file; each runs in its own group', () => {
  const d = project({ test: confinedTest(true), guards: { g1: ['test/offline/g.test.ts', 'test/offline/wrapper.test.ts'] } })
  writeFileSync(join(d, 'test/offline/wrapper.test.ts'), confinedTest(false))
  try {
    const r = run(d, [], { env: hostileEnv() })
    assert.equal(r.code, 0, r.out)
    assert.match(r.out, /^KILLED 1\/1$/m)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('K29: the profile and the OWN_SANDBOX list come from scripts/test-offline.sh (one source)', () => {
  const sh = readFileSync(join(ROOT, 'scripts/test-offline.sh'), 'utf8')
  const profile = /^SUITE_PROFILE='([^'\n]+)'$/m.exec(sh)?.[1] ?? ''
  assert.match(profile, /\(deny network-outbound\)\(allow network-outbound \(remote ip "localhost:\*"\)\)\(deny network-outbound \(remote ip "\*:9050"\)/)
  assert.match(/^OWN_SANDBOX='([^'\n]+)'$/m.exec(sh)?.[1] ?? '', /test\/offline\/confine\.test\.ts.*test\/offline\/wrapper\.test\.ts/)
})

// A copy of the runner in a scratch tree with its own scripts/test-offline.sh and sentinel (the runner
// finds both next to itself), to watch it refuse when the sentinel does not pass.
function scratchRunner(sentinel: string | null, script?: string): { dir: string; runner: string } {
  const dir = mkdtempSync(join(tmpdir(), 'vt-runner-copy-'))
  const r = join(dir, 'test/mutation/run.ts')
  mkdirSync(dirname(r), { recursive: true }); mkdirSync(join(dir, 'test/offline')); mkdirSync(join(dir, 'scripts'))
  copyFileSync(runner, r)
  writeFileSync(join(dir, 'scripts/test-offline.sh'), script ?? readFileSync(join(ROOT, 'scripts/test-offline.sh'), 'utf8'))
  if (sentinel !== null) writeFileSync(join(dir, 'test/offline/suite-sandbox.test.ts'), sentinel)
  return { dir, runner: r }
}

test('K29: the sentinel runs first; if it fails, or passes without writing its marker, no guard runs', () => {
  const failing = `import { test } from 'node:test'\ntest('sentinel', () => { throw new Error('not confined') })\n`
  const silent = `import { test } from 'node:test'\ntest('sentinel', () => {})\n`
  const d = project({ test: GOOD_TEST, guards: { g1: ['test/offline/g.test.ts'] } })
  try {
    for (const sentinel of [failing, silent, null]) {
      const c = scratchRunner(sentinel)
      try {
        const r = run(d, [], { runner: c.runner })
        assert.notEqual(r.code, 0, r.out)
        assert.match(r.out, /^SENTINEL-FAILED /m)
        assert.doesNotMatch(r.out, /KILLED|SURVIVED|BASELINE/)
      } finally { rmSync(c.dir, { recursive: true, force: true }) }
    }
    // the real sentinel, copied, passes in the scratch tree too (positive control)
    const ok = scratchRunner(readFileSync(join(ROOT, 'test/offline/suite-sandbox.test.ts'), 'utf8'))
    try { assert.match(run(d, [], { runner: ok.runner }).out, /^KILLED 1\/1$/m) } finally { rmSync(ok.dir, { recursive: true, force: true }) }
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('K29: no SUITE_PROFILE or OWN_SANDBOX line in scripts/test-offline.sh -> ERROR, nothing runs (fail closed)', () => {
  const d = project({ test: GOOD_TEST, guards: { g1: ['test/offline/g.test.ts'] } })
  const sentinel = readFileSync(join(ROOT, 'test/offline/suite-sandbox.test.ts'), 'utf8')
  try {
    for (const script of ['#!/bin/sh\nOWN_SANDBOX=\'a.test.ts\'\n', "#!/bin/sh\nSUITE_PROFILE='(version 1)(deny default)'\n"]) {
      const c = scratchRunner(sentinel, script)
      try {
        const r = run(d, [], { runner: c.runner })
        assert.notEqual(r.code, 0, r.out)
        assert.match(r.out, /^ERROR .*scripts\/test-offline\.sh/m)
        assert.doesNotMatch(r.out, /KILLED|SENTINEL/)
      } finally { rmSync(c.dir, { recursive: true, force: true }) }
    }
  } finally { rmSync(d, { recursive: true, force: true }) }
})

// ---- Task P1: parallel workers, one baseline per test set, sorted output, targeted (--changed) runs

// A project from a { path: text } map (guards.json among them).
function tree(files: Record<string, string>, dir = mkdtempSync(join(tmpdir(), 'vt-runner-test-'))): string {
  for (const [p, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, p)), { recursive: true })
    writeFileSync(join(dir, p), text)
  }
  return dir
}
// One guard per line; `<id>:fail` is each one's refusal.
const guardsSrc = (ids: string[], fn = 'check') =>
  `export function ${fn}(id: string, ok: boolean): void {\n${ids.map((g) => `  if (!ok && id === '${g}') throw new Error('${g}:fail') // @guard:${g}\n`).join('')}}\n`
const assertsTest = (ids: string[], from = 'g', fn = 'check') => `import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ${fn} } from '../../src/${from}.ts'
test('refusals', () => {
${ids.map((g) => `  assert.throws(() => ${fn}('${g}', false), /${g}:fail/)\n`).join('')}})
`
const verdicts = (out: string) => out.split('\n').filter((l) => /^(KILLED|SURVIVED|TIMEOUT|BASELINE-FAILED) [a-z0-9.-]+( \(baseline\))?$/.test(l))

test('P1: bad --jobs / --only / --changed arguments are an ERROR before anything runs', () => {
  const d = project({ test: GOOD_TEST, guards: { g1: ['test/offline/g.test.ts'] } })
  try {
    for (const extra of [['--jobs', '0'], ['--jobs', 'x'], ['--jobs', '1.5'], ['--jobs', '1000'], ['--only', 'g1,'], ['--changed', '-x'], ['--only', 'g1', '--changed', 'HEAD']]) {
      const r = run(d, extra)
      assert.notEqual(r.code, 0, r.out)
      assert.match(r.out, /^ERROR /m, extra.join(' '))
      assert.doesNotMatch(r.out, /SENTINEL|KILLED/)
    }
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('P1: in parallel a seeded surviving mutant is still SURVIVED; verdicts sorted by id and identical to --jobs 1; one unmutated run per distinct test set; --only takes a list', () => {
  const ids = ['a1', 'a2', 'a3', 'a4', 'a5', 'w1']
  const log = mkdtempSync(join(tmpdir(), 'vt-runner-log-'))
  // a.test.ts (the set of a1..a5) leaves one file per run, named after whether its src/g.ts was mutated
  const counted = assertsTest(['a1', 'a2', 'a3', 'a4', 'a5']).replace("test('refusals', () => {\n", `import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
const src = readFileSync(fileURLToPath(new URL('../../src/g.ts', import.meta.url)), 'utf8')
writeFileSync(join(${JSON.stringify(log)}, (src.split('// @guard:').length === 7 ? 'unmutated-' : 'mutated-') + process.pid + '-' + Date.now()), '') // all 6 markers: unmutated
test('refusals', () => {
`)
  const runsOfA = () => {
    const names = readdirSync(log)
    for (const n of names) unlinkSync(join(log, n))
    return { unmutated: names.filter((n) => n.startsWith('unmutated-')).length, mutated: names.filter((n) => n.startsWith('mutated-')).length }
  }
  const d = tree({
    'src/g.ts': guardsSrc(ids),
    'test/offline/a.test.ts': counted,
    // the seeded survivor: w1's only test never makes the guard refuse
    'test/offline/w.test.ts': `import { test } from 'node:test'\nimport { check } from '../../src/g.ts'\ntest('happy path only', () => { check('w1', true) })\n`,
    'test/mutation/guards.json': JSON.stringify({ ...Object.fromEntries(ids.slice(0, 5).map((g) => [g, ['test/offline/a.test.ts']])), w1: ['test/offline/w.test.ts'] }),
  })
  try {
    const want = ['KILLED a1', 'KILLED a2', 'KILLED a3', 'KILLED a4', 'KILLED a5', 'SURVIVED w1']
    const par = run(d, ['--jobs', '4'])
    assert.notEqual(par.code, 0, par.out)
    assert.deepEqual(verdicts(par.out), want, par.out)
    assert.match(par.out, /^KILLED 5\/6$/m)
    assert.match(par.out, /^wall [0-9.]+ s; --jobs 4: 4 worker\(s\), 2 distinct test set\(s\) run unmutated, 6 mutant\(s\)$/m)
    assert.deepEqual(runsOfA(), { unmutated: 1, mutated: 5 }, 'the shared set ran unmutated ONCE for its five guards')
    const seq = run(d, ['--jobs', '1'])
    assert.notEqual(seq.code, 0, seq.out)
    assert.deepEqual(verdicts(seq.out), want, seq.out)
    assert.match(seq.out, /--jobs 1: 1 worker\(s\)/)
    assert.deepEqual(runsOfA(), { unmutated: 1, mutated: 5 })
    const only = run(d, ['--only', 'w1,a2', '--jobs', '2'])
    assert.notEqual(only.code, 0, only.out)
    assert.deepEqual(verdicts(only.out), ['KILLED a2', 'SURVIVED w1'], only.out)
    assert.match(only.out, /^KILLED 1\/2$/m)
    const unknown = run(d, ['--only', 'a1,nope'])
    assert.notEqual(unknown.code, 0, unknown.out)
    assert.match(unknown.out, /^ERROR --only: unknown guard nope$/m)
  } finally {
    rmSync(d, { recursive: true, force: true })
    rmSync(log, { recursive: true, force: true })
  }
})

test('P1: two workers never share a temp copy; every run sees the project plus at most its own blanked line; a copy a test changed is re-made', () => {
  const ids = ['c1', 'c2', 'c3', 'c4', 'c5', 'c6']
  const log = mkdtempSync(join(tmpdir(), 'vt-runner-log-'))
  // Each mapped test (its own set, so the unmutated runs are parallel too) records where it ran, when, which marker
  // lines it found blank and whether c1's stray file is there; c1's test then leaves that file in its copy.
  const recording = (id: string) => `import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { check } from '../../src/g.ts'
const root = realpathSync(fileURLToPath(new URL('../../', import.meta.url)))
test('${id}', async () => {
  const start = Date.now()
  const src = readFileSync(join(root, 'src/g.ts'), 'utf8')
  const blank = ${JSON.stringify(ids)}.filter((g) => !src.includes('// @guard:' + g))
  const stray = existsSync(join(root, 'stray.txt'))
  await new Promise((r) => setTimeout(r, 300))
  ${id === 'c1' ? "writeFileSync(join(root, 'stray.txt'), 'a test changed its copy')" : ''}
  writeFileSync(join(${JSON.stringify(log)}, process.pid + '-' + start + '-${id}.json'), JSON.stringify({ id: '${id}', root, start, end: Date.now(), blank, stray }))
  assert.throws(() => check('${id}', false), /${id}:fail/)
})
`
  const d = tree({
    'src/g.ts': guardsSrc(ids),
    ...Object.fromEntries(ids.map((g) => [`test/offline/${g}.test.ts`, recording(g)])),
    'test/mutation/guards.json': JSON.stringify(Object.fromEntries(ids.map((g) => [g, [`test/offline/${g}.test.ts`]]))),
  })
  try {
    const r = run(d, ['--jobs', '3'])
    assert.equal(r.code, 0, r.out)
    assert.deepEqual(verdicts(r.out), ids.map((g) => `KILLED ${g}`))
    assert.match(r.out, /--jobs 3: 3 worker\(s\), 6 distinct test set\(s\) run unmutated, 6 mutant\(s\), 2 copy\(ies\) re-made after a test changed them$/m)
    type Rec = { id: string; root: string; start: number; end: number; blank: string[]; stray: boolean }
    const recs = readdirSync(log).map((f) => JSON.parse(readFileSync(join(log, f), 'utf8')) as Rec)
    assert.equal(recs.length, 12, 'six unmutated runs and six mutants')
    const project = realpathSync(d), tmp = realpathSync(tmpdir())
    for (const x of recs) {
      assert.ok(x.root !== project && x.root.startsWith(tmp + '/vt-mutation-'), `ran in ${x.root}`)
      assert.equal(x.stray, false, `${x.id} saw the file another run left in its copy`)
    }
    // unmutated: nothing blank; mutated: exactly its own line blank (earlier mutants of that copy were restored)
    assert.deepEqual(recs.filter((x) => x.blank.length === 0).map((x) => x.id).sort(), ids)
    assert.deepEqual(recs.filter((x) => x.blank.length > 0).map((x) => [x.id, x.blank]).sort(), ids.map((g) => [g, [g]]))
    let concurrent = 0
    for (const a of recs) {
      for (const b of recs) {
        if (a === b || a.end <= b.start || b.end <= a.start) continue // not at the same time
        assert.notEqual(a.root, b.root, `${a.id} and ${b.id} ran in one copy at the same time`)
        concurrent++
      }
    }
    assert.ok(concurrent > 0, 'no two runs overlapped: the workers did not run in parallel')
    assert.ok(new Set(recs.map((x) => x.root)).size <= 3 + 2, 'three copies, plus the two re-made ones')
  } finally {
    rmSync(d, { recursive: true, force: true })
    rmSync(log, { recursive: true, force: true })
  }
})

test('P1: --changed selects by marker line, source file, mapped test and guards.json entry (staged, unstaged, untracked); none selected exits 0; git errors are ERRORs', () => {
  const repo = mkdtempSync(join(tmpdir(), 'vt-runner-git-'))
  const git = (...args: string[]) => {
    const r = spawnSync('git', ['-c', 'user.name=synthetic', '-c', 'user.email=synthetic@example.invalid', '-c', 'commit.gpgsign=false', ...args], { cwd: repo, encoding: 'utf8' })
    assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`)
  }
  const p = (f: string) => join(repo, 'proj', f)
  try {
    // The project is a subdirectory of the repository, as broadcast/ is.
    tree({
      'notes.txt': 'outside the project\n',
      'proj/old.txt': 'deleted later\n',
      'proj/src/a.ts': guardsSrc(['a1', 'a2'], 'a'),
      'proj/src/b.ts': guardsSrc(['b1'], 'b'),
      'proj/src/c.ts': guardsSrc(['c1', 'c2'], 'c'),
      'proj/src/e.ts': guardsSrc(['e1'], 'e'),
      'proj/test/offline/a.test.ts': assertsTest(['a1', 'a2'], 'a', 'a'),
      'proj/test/offline/b.test.ts': assertsTest(['b1'], 'b', 'b'),
      'proj/test/offline/c.test.ts': assertsTest(['c1', 'c2'], 'c', 'c'),
      'proj/test/offline/e.test.ts': assertsTest(['e1'], 'e', 'e'),
      'proj/test/mutation/guards.json': JSON.stringify({
        a1: ['test/offline/a.test.ts'], a2: ['test/offline/a.test.ts'], b1: ['test/offline/b.test.ts'],
        c1: ['test/offline/c.test.ts'], c2: ['test/offline/c.test.ts'], e1: ['test/offline/e.test.ts', 'test/offline/b.test.ts'],
      }, null, 2) + '\n',
    }, repo)
    git('init', '-q')
    git('add', '-A')
    git('commit', '-q', '-m', 'base')
    // a1's marker line (unstaged); c's test (staged); a deleted file and a change outside the project (no effect);
    // a new untracked guard d1 with its new test; e1's guards.json entry loses b.test.ts (b1 itself is unchanged).
    writeFileSync(p('src/a.ts'), readFileSync(p('src/a.ts'), 'utf8').replace("id === 'a1'", "'a1' === id"))
    writeFileSync(p('test/offline/c.test.ts'), readFileSync(p('test/offline/c.test.ts'), 'utf8') + '// changed\n')
    git('add', 'proj/test/offline/c.test.ts')
    unlinkSync(p('old.txt'))
    writeFileSync(join(repo, 'notes.txt'), 'changed outside the project\n')
    tree({ 'src/d.ts': guardsSrc(['d1'], 'd'), 'test/offline/d.test.ts': assertsTest(['d1'], 'd', 'd') }, join(repo, 'proj'))
    const gj = JSON.parse(readFileSync(p('test/mutation/guards.json'), 'utf8')) as Record<string, string[]>
    writeFileSync(p('test/mutation/guards.json'), JSON.stringify({ ...gj, d1: ['test/offline/d.test.ts'], e1: ['test/offline/e.test.ts'] }, null, 2) + '\n')

    const r = run(p(''), ['--changed', 'HEAD', '--jobs', '3'])
    assert.equal(r.code, 0, r.out)
    assert.match(r.out, /^CHANGED since HEAD \([0-9a-f]{12}\): 6 of 7 guards selected$/m)
    assert.deepEqual(r.out.split('\n').filter((l) => l.startsWith('SELECTED ')), [
      'SELECTED a1: marker line changed (src/a.ts:2); source changed (src/a.ts)',
      'SELECTED a2: source changed (src/a.ts)',
      'SELECTED c1: test changed (test/offline/c.test.ts)',
      'SELECTED c2: test changed (test/offline/c.test.ts)',
      'SELECTED d1: marker line changed (src/d.ts:2); source changed (src/d.ts); test changed (test/offline/d.test.ts); test/mutation/guards.json entry changed',
      'SELECTED e1: test/mutation/guards.json entry changed',
    ])
    assert.deepEqual(verdicts(r.out), ['KILLED a1', 'KILLED a2', 'KILLED c1', 'KILLED c2', 'KILLED d1', 'KILLED e1'])
    assert.match(r.out, /^KILLED 6\/6$/m)

    // everything committed: nothing selected, nothing run, exit 0
    git('add', '-A')
    git('commit', '-q', '-m', 'next')
    const none = run(p(''), ['--changed', 'HEAD'])
    assert.equal(none.code, 0, none.out)
    assert.match(none.out, /^CHANGED since HEAD \([0-9a-f]{12}\): 0 of 7 guards selected$/m)
    assert.match(none.out, /^nothing to run: no guard is affected by the change$/m)
    assert.doesNotMatch(none.out, /SENTINEL|KILLED|SELECTED/)
    // and the previous commit, as a base, selects exactly the same six again
    assert.match(run(p(''), ['--changed', 'HEAD~1', '--jobs', '3']).out, /^CHANGED since HEAD~1 \([0-9a-f]{12}\): 6 of 7 guards selected$/m)

    // fail closed: an unknown base, or a project outside any repository, is an ERROR, never "nothing changed"
    const bad = run(p(''), ['--changed', 'no-such-ref'])
    assert.notEqual(bad.code, 0, bad.out)
    assert.match(bad.out, /^ERROR --changed: no-such-ref is not a commit of this repository$/m)
    assert.doesNotMatch(bad.out, /CHANGED since|SENTINEL/)
    const loose = project({ test: GOOD_TEST, guards: { g1: ['test/offline/g.test.ts'] } })
    try {
      const nr = run(loose, ['--changed', 'HEAD'])
      assert.notEqual(nr.code, 0, nr.out)
      assert.match(nr.out, /^ERROR --changed: git rev-parse failed: /m)
    } finally { rmSync(loose, { recursive: true, force: true }) }
  } finally { rmSync(repo, { recursive: true, force: true }) }
})

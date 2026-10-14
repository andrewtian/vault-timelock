// Mutation runner: for each `// @guard:<id>` marker, blank that one line in a
// throwaway copy of the project and require the mapped tests to fail.
//   node test/mutation/run.ts [--jobs <n>] [--only <id,...> | --changed <git-base>] [--root <dir>]
//                             [--timeout-ms <n>] [--baseline-timeout-ms <n>] [--allow-empty]
//
// ★★ CONFINED (Task H0 item 3, audit K29). The mapped tests run exactly when a guard has been removed,
//   so they get the suite's walls and never the caller's environment:
//   · env -i: each child's environment is exactly PATH HOME LANG TERM (a fresh env object, nothing
//     inherited), with HOME a fresh empty temp dir (K31), never the account's home. The operator's
//     ALCHEMY_API_KEY, NODE_OPTIONS, DEBUG and proxies reach no test;
//   · every mapped test file runs under the suite sandbox profile, SUITE_PROFILE, read from
//     scripts/test-offline.sh (one source), through /usr/bin/sandbox-exec: loopback only, the relay
//     ports (Tor 9050/9150, 9222, 8931, 11434) and the internet denied;
//   · except that script's OWN_SANDBOX files (confine/wrapper/runner tests apply sandboxes themselves,
//     and macOS refuses to apply a different profile inside a sandbox): those run unsandboxed, under
//     the same env. A guard mapped to both kinds runs each group separately.
//   · A sentinel runs before any guard, through the same spawn path: test/offline/suite-sandbox.test.ts
//     with VT_SUITE_SANDBOX=1 (sandboxed) and =env (unsandboxed). It proves the child sees no
//     ALCHEMY_API_KEY, NODE_OPTIONS or HTTPS_PROXY, a synthetic HOME, and (sandboxed) EPERM on 9050 and
//     the other relay ports. Unless both runs pass AND write their exact markers: SENTINEL-FAILED, exit 1.
//   The runner finds scripts/test-offline.sh and the sentinel next to ITSELF (not under --root): a
//   scratch project given with --root is confined the same way.
//
// ★★ PARALLEL (Task P1). --jobs N workers (default min(8, availableParallelism() - 1), at least 1; --jobs 1 is
//   sequential) run mutants concurrently, each under exactly the confinement above:
//   · each worker owns ONE temp copy of the project (made once with mkdtemp, node_modules symlinked and never
//     written), which no other worker ever touches. It blanks one marker line, runs that guard's mapped tests,
//     and writes the line back;
//   · after EVERY run the copy is compared with the project's manifest (every directory; every file's path,
//     mode and sha256; node_modules and .git aside). A copy a test changed is thrown away and re-made (and
//     checked) before its worker runs anything else, so a mutant always runs on the project plus its one
//     blanked line, as when each guard got a fresh copy;
//   · baselines: each DISTINCT mapped test set runs ONCE unmutated (on a checked copy), before any mutant. A
//     guard whose set fails it is BASELINE-FAILED (TIMEOUT ... (baseline) if it timed out) and is not mutated;
//   · output: one line per guard (KILLED / SURVIVED / TIMEOUT / BASELINE-FAILED), sorted by guard id whatever
//     the finishing order (diffable between runs and between --jobs values), then `KILLED k/n` and the wall
//     time. Progress lines go to stderr only when it is a terminal.
//
// ★ TARGETED (--changed <git-base>, Task P1). Selects the guards whose marker line changed, whose source file
//   changed, one of whose mapped test files changed, or whose guards.json entry changed, between <git-base> and
//   the working tree (`git diff <base>`, staged and unstaged, plus untracked files under the project: an
//   untracked file counts as changed on every line). It prints each selected guard with its reasons, then
//   runs only those (sentinel first, as always). Zero selected: it says so and exits 0. Any git error, or a
//   diff it cannot read: ERROR, exit 1, never "nothing changed". Imports are NOT followed (a change to a helper
//   module selects nothing by itself): a task's closing commit runs the full run.
//   --only <id,...> runs just those guards (unknown id: ERROR). --only and --changed exclude each other.
//
// ★ CRASH (P1 review I1). A child that does not exit 0 or 1 (spawn error, killed by a signal, other exit code)
//   is `crash`, never a kill: that guard reports `ERROR <id> (child crashed)` (`(baseline child crashed)` for
//   the unmutated run), the run exits 1, and an `ERRORED n: <ids>` line follows the KILLED k/n line.
//
// --timeout-ms bounds each MUTATED run (default 600000). The unmutated baseline and the sentinel have
// their own bound, --baseline-timeout-ms (default 600000): under load a slow baseline is not a TIMEOUT of
// the guard (the Task 3 deferred item). Cfix4: raised from 120000 each. With the default --jobs the cli's big files (release,
// clawback, run, args: dozens of real child processes) take longer than 120 s on a loaded machine, and 18 of 42 baselines
// timed out; the bound only stops a hung child, so a generous one costs nothing when the tests are healthy.
import {
  cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, rmSync, statSync,
  symlinkSync, writeFileSync,
} from 'node:fs'
import { createHash } from 'node:crypto'
import { availableParallelism, tmpdir } from 'node:os'
import { join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawn, spawnSync } from 'node:child_process'

const SCRIPT = fileURLToPath(new URL('../../scripts/test-offline.sh', import.meta.url))
const SENTINEL = fileURLToPath(new URL('../offline/suite-sandbox.test.ts', import.meta.url))
// test/offline/suite-sandbox.test.ts writes exactly these after passing (repeated there and in the script).
const SANDBOXED_MARKER = 'sentinel: env clean, HOME synthetic, EPERM on 192.0.2.1:9 and loopback 9050 9150 9222 8931 11434'
const ENV_MARKER = 'sentinel: env clean, HOME synthetic'
const GUARDS_JSON = 'test/mutation/guards.json'

// SUITE_PROFILE and OWN_SANDBOX from scripts/test-offline.sh; anything missing or odd is an error.
function readSuite(): { profile: string; own: ReadonlySet<string> } {
  let text = ''
  try { text = readFileSync(SCRIPT, 'utf8') } catch { /* refused below */ }
  const profile = /^SUITE_PROFILE='([^'\n]+)'$/m.exec(text)?.[1]
  const own = /^OWN_SANDBOX='([^'\n]+)'$/m.exec(text)?.[1]
  const ok = profile !== undefined && profile.includes('(deny network-outbound)') && own !== undefined && /^[A-Za-z0-9/._ -]+$/.test(own)
  if (!ok) throw new Error(`cannot read a SUITE_PROFILE with (deny network-outbound) and an OWN_SANDBOX list from ${SCRIPT.split(sep).slice(-2).join('/')}`)
  return { profile: profile!, own: new Set(own!.split(' ').filter((f) => f !== '')) }
}

const MARKER = /\/\/ @guard:(\S+)\s*$/
const ID = /^[a-z0-9]+(?:[.-][a-z0-9]+)*$/

type Marker = { file: string; line: number }

interface Args {
  only?: string[]; changed?: string; jobs: number; root: string; timeoutMs: number; baselineTimeoutMs: number; allowEmpty: boolean
}
const defaultJobs = () => Math.max(1, Math.min(8, availableParallelism() - 1))
function parseArgs(argv: string[]): Args {
  let only: string[] | undefined
  let changed: string | undefined
  let jobs = String(defaultJobs())
  let root = fileURLToPath(new URL('../../', import.meta.url))
  let timeoutMs = 600000
  let baselineTimeoutMs = 600000
  let allowEmpty = false
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--only' && i + 1 < argv.length) only = [...(only ?? []), ...argv[++i].split(',')]
    else if (a === '--changed' && i + 1 < argv.length) changed = argv[++i]
    else if (a === '--jobs' && i + 1 < argv.length) jobs = argv[++i]
    else if (a === '--root' && i + 1 < argv.length) root = argv[++i]
    else if (a === '--timeout-ms' && i + 1 < argv.length) timeoutMs = Number(argv[++i])
    else if (a === '--baseline-timeout-ms' && i + 1 < argv.length) baselineTimeoutMs = Number(argv[++i])
    else if (a === '--allow-empty') allowEmpty = true
    else throw new Error(`bad argument: ${a}`)
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) throw new Error('bad --timeout-ms')
  if (!Number.isInteger(baselineTimeoutMs) || baselineTimeoutMs <= 0) throw new Error('bad --baseline-timeout-ms')
  if (!/^[1-9][0-9]{0,2}$/.test(jobs)) throw new Error('bad --jobs (an integer from 1 to 999)')
  if (only !== undefined && only.some((id) => id === '')) throw new Error('bad --only (a comma-separated list of guard ids)')
  if (changed !== undefined && (changed === '' || changed.startsWith('-'))) throw new Error('bad --changed (a git revision)')
  if (only !== undefined && changed !== undefined) throw new Error('--only and --changed exclude each other')
  return { only, changed, jobs: Number(jobs), root: resolve(root), timeoutMs, baselineTimeoutMs, allowEmpty }
}

function walk(dir: string, accept: (p: string) => boolean, out: string[] = []): string[] {
  if (!existsSync(dir)) return out
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) walk(p, accept, out)
    else if (accept(p)) out.push(p)
  }
  return out
}

// The web workspace (Vite + vitest, .js/.jsx sources) is recognised by its vitest config; every other project is node --test over .ts.
const isWeb = (dir: string): boolean => existsSync(join(dir, 'vitest.config.js'))

function scan(root: string): Map<string, Marker[]> {
  const files = [
    ...walk(join(root, 'src'), (p) => (isWeb(root) ? /\.jsx?$/ : /\.ts$/).test(p)),
    ...walk(join(root, 'bin'), () => true),
  ]
  const markers = new Map<string, Marker[]>()
  for (const f of files) {
    const lines = readFileSync(f, 'utf8').split('\n')
    lines.forEach((l, i) => {
      const m = MARKER.exec(l)
      if (!m) return
      const list = markers.get(m[1]) ?? []
      list.push({ file: relative(root, f), line: i })
      markers.set(m[1], list)
    })
  }
  return markers
}

// pass: exit 0. fail: exit 1 (what `node --test` returns when a test fails: the only evidence of a kill).
// crash: anything else (spawn error, killed by a signal, any other exit code): no evidence either way (P1 review I1).
type Outcome = 'pass' | 'fail' | 'timeout' | 'crash'

// Process groups and temp dirs that are live right now: an interrupted run kills and removes them.
const live = { groups: new Set<number>(), dirs: new Set<string>() }
function tempDir(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix))
  live.dirs.add(d)
  return d
}
function removeDir(d: string): void {
  rmSync(d, { recursive: true, force: true })
  live.dirs.delete(d)
}
for (const [sig, code] of [['SIGINT', 130], ['SIGTERM', 143]] as const) {
  process.once(sig, () => {
    for (const g of live.groups) { try { process.kill(-g, 'SIGKILL') } catch { /* already gone */ } }
    for (const d of live.dirs) { try { rmSync(d, { recursive: true, force: true }) } catch { /* best effort */ } }
    console.error(`interrupted (${sig}): the run is void`)
    process.exit(code)
  })
}

// env -i: exactly PATH HOME LANG TERM (plus `extra`, the sentinel's two variables); nothing inherited.
// (NODE_TEST_CONTEXT is never passed either, so a runner started under `node --test` gives its children
// a real top-level run whose exit status is meaningful.)
function cleanEnv(home: string, extra: Record<string, string> = {}): Record<string, string> {
  return {
    PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home, LANG: process.env.LANG || 'en_US.UTF-8', TERM: process.env.TERM || 'dumb',
    ...extra,
  }
}

// One `node --test` child, sandboxed with `profile` unless it is null. Async + detached so a timeout can
// SIGKILL the whole process group (node --test spawns a grandchild per file, which would otherwise keep
// spinning; sandbox-exec execs node in place, so the group is the same).
function runGroup(cwd: string, files: string[], env: Record<string, string>, profile: string | null, timeoutMs: number): Promise<Outcome> {
  const node = isWeb(cwd) ? [process.execPath, 'node_modules/vitest/vitest.mjs', 'run', ...files] : [process.execPath, '--test', ...files]
  const [cmd, ...args] = profile === null ? node : ['/usr/bin/sandbox-exec', '-p', profile, ...node]
  return new Promise((res) => {
    const child = spawn(cmd, args, { cwd, env, stdio: 'ignore', detached: true })
    const pid = child.pid
    if (pid !== undefined) live.groups.add(pid)
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      try { process.kill(-child.pid!, 'SIGKILL') } catch { /* already gone */ }
    }, timeoutMs)
    child.on('error', () => { clearTimeout(timer); if (pid !== undefined) live.groups.delete(pid); res('crash') })
    child.on('close', (code, signal) => {
      clearTimeout(timer)
      if (pid !== undefined) live.groups.delete(pid)
      res(timedOut ? 'timeout' : signal !== null || code === null ? 'crash' : code === 0 ? 'pass' : code === 1 ? 'fail' : 'crash')
    })
  })
}

// The mapped files in two groups (suite sandbox / OWN_SANDBOX unsandboxed), each with a fresh empty
// HOME. `all`: run every group (the baseline must pass in all of them); otherwise stop at the first
// group that fails (one failing mapped test kills the mutant).
async function runTests(cwd: string, files: string[], timeoutMs: number, suite: ReturnType<typeof readSuite>, all: boolean): Promise<Outcome> {
  const groups: Array<[string[], string | null]> = [
    [files.filter((f) => !suite.own.has(f)), suite.profile],
    [files.filter((f) => suite.own.has(f)), null],
  ]
  let outcome: Outcome = 'pass'
  for (const [group, profile] of groups) {
    if (group.length === 0) continue
    const home = tempDir('vt-mutation-home-')
    let o: Outcome
    try { o = await runGroup(cwd, group, cleanEnv(home), profile, timeoutMs) } finally { removeDir(home) }
    if (o === 'timeout' || o === 'crash') return o
    if (o === 'fail') { outcome = 'fail'; if (!all) return outcome }
  }
  return outcome
}

// The sentinel, through the same path as the mapped tests: [] when both modes passed with their markers.
async function sentinelFailures(suite: ReturnType<typeof readSuite>, timeoutMs: number): Promise<string[]> {
  const failures: string[] = []
  const modes: Array<[string, string | null, string]> = [['1', suite.profile, SANDBOXED_MARKER], ['env', null, ENV_MARKER]]
  for (const [mode, profile, marker] of modes) {
    const d = tempDir('vt-mutation-sentinel-')
    try {
      const home = join(d, 'home')
      mkdirSync(home, { mode: 0o700 })
      const file = join(d, 'marker')
      const env = cleanEnv(home, { VT_SUITE_SANDBOX: mode, VT_SUITE_SENTINEL_FILE: file })
      const o = await runGroup(d, [SENTINEL], env, profile, timeoutMs)
      let got = ''
      try { got = readFileSync(file, 'utf8') } catch { /* no marker */ }
      if (o !== 'pass' || got !== marker) failures.push(`${profile === null ? 'unsandboxed' : 'sandboxed'} (${o}${got === marker ? '' : ', no marker'})`)
    } finally {
      removeDir(d)
    }
  }
  return failures
}

// ---- worker copies (Task P1)

const skipped = (rel: string) => rel.split(sep).some((s) => s === 'node_modules' || s === '.git')

// Every directory, file (mode + sha256) and symlink (target) under `dir`, node_modules and .git aside: the
// copy check compares a worker's copy with the project through this one string.
function manifest(dir: string): string {
  const rows: string[] = []
  const visit = (d: string): void => {
    for (const name of readdirSync(d).sort()) {
      const p = join(d, name)
      const rel = relative(dir, p)
      if (skipped(rel)) continue
      const st = lstatSync(p)
      if (st.isDirectory()) { rows.push(`d ${JSON.stringify(rel)}`); visit(p) }
      else if (st.isSymbolicLink()) rows.push(`l ${JSON.stringify(rel)} ${JSON.stringify(readlinkSync(p))}`)
      else if (st.isFile()) rows.push(`f ${JSON.stringify(rel)} ${(st.mode & 0o7777).toString(8)} ${createHash('sha256').update(readFileSync(p)).digest('hex')}`)
      else rows.push(`? ${JSON.stringify(rel)}`)
    }
  }
  visit(dir)
  return rows.join('\n')
}

interface Worker { readonly n: number; dir: string; remade: number }

// A fresh copy of `root` in its own mkdtemp dir, checked against `want`; anything else is an error.
// The web workspace reads its sibling ../packages/core (contract fixtures), so its copy sits in <dir>/web with <dir>/packages linked to the real
// siblings (read-only use); copyOf(dir) is where the project copy is.
const copyOf = (dir: string, web: boolean): string => (web ? join(dir, 'web') : dir)
function makeCopy(root: string, want: string): string {
  const dir = tempDir('vt-mutation-')
  const web = isWeb(root), at = copyOf(dir, web)
  cpSync(root, at, { recursive: true, verbatimSymlinks: true, filter: (src) => !skipped(relative(root, src)) })
  if (existsSync(join(root, 'node_modules'))) symlinkSync(join(root, 'node_modules'), join(at, 'node_modules'))
  if (web && existsSync(join(root, '..', 'packages'))) symlinkSync(resolve(root, '..', 'packages'), join(dir, 'packages'))
  if (manifest(at) !== want) throw new Error('a fresh copy of the project differs from the project (was it edited during the run?)')
  return dir
}

// After every run: a copy that is no longer the project is replaced before its worker runs anything else.
function checkCopy(w: Worker, root: string, want: string): void {
  if (manifest(copyOf(w.dir, isWeb(root))) === want) return
  removeDir(w.dir)
  w.dir = makeCopy(root, want)
  w.remade++
}

// Runs `fn` over `items` on the workers, each worker one item at a time. After a failure no new item starts;
// the first error is rethrown once every worker has stopped.
async function pool<T>(items: readonly T[], workers: Worker[], fn: (w: Worker, item: T) => Promise<void>): Promise<void> {
  let next = 0
  let failed = false
  const results = await Promise.allSettled(workers.map(async (w) => {
    while (!failed && next < items.length) {
      const item = items[next++]
      try { await fn(w, item) } catch (e) { failed = true; throw e }
    }
  }))
  const bad = results.find((r) => r.status === 'rejected')
  if (bad !== undefined) throw (bad as PromiseRejectedResult).reason
}

// ---- targeted selection (Task P1)

function git(root: string, args: string[]): string {
  const r = spawnSync('git', ['-C', root, '-c', 'core.quotePath=false', ...args], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 })
  if (r.error !== undefined || r.status !== 0) {
    const why = r.error?.message ?? (r.stderr ?? '').split('\n').find((l) => l.trim() !== '') ?? `exit ${r.status}`
    throw new Error(`--changed: git ${args[0]} failed: ${why}`)
  }
  return r.stdout
}
const nulList = (s: string) => s.split('\0').filter((p) => p !== '')

// guard id -> the reasons it is selected (only selected guards are in the map).
function selectChanged(root: string, base: string, ids: readonly string[], map: Record<string, string[]>, markers: Map<string, Marker[]>): { sha: string; why: Map<string, string[]> } {
  git(root, ['rev-parse', '--show-toplevel']) // not a repository: git's own message
  let sha = ''
  try { sha = git(root, ['rev-parse', '--verify', '--quiet', `${base}^{commit}`]).trim() } catch { /* refused below */ }
  if (!/^[0-9a-f]{40,64}$/.test(sha)) throw new Error(`--changed: ${base} is not a commit of this repository`)
  // Paths relative to the project (--relative under -C root); renames as delete + add, so a moved file is new.
  const diffArgs = ['--relative', '--no-renames', '--no-ext-diff', '--no-textconv', '--no-color']
  const changed = new Set(nulList(git(root, ['diff', '--name-only', '-z', ...diffArgs, sha, '--'])))
  const untracked = new Set(nulList(git(root, ['ls-files', '-z', '--others', '--exclude-standard', '--'])))
  for (const f of untracked) changed.add(f)
  // New-side line numbers of every changed line, from the zero-context patch. A file's header runs from its
  // `diff --git` line to its first hunk; only there is `+++ b/<path>` a header (in a hunk it is an added line).
  const added = new Map<string, Set<number>>()
  let file: string | null = null // null: no new side seen yet; '' : the file was deleted (its hunks add nothing)
  let header = false
  for (const l of git(root, ['diff', '-U0', '--src-prefix=a/', '--dst-prefix=b/', ...diffArgs, sha, '--']).split('\n')) {
    if (l.startsWith('diff --git ')) { file = null; header = true; continue }
    if (header && l.startsWith('+++ ')) {
      const p = l.slice(4)
      if (p === '/dev/null') { file = ''; continue }
      if (!p.startsWith('b/') || p.length < 3) throw new Error(`--changed: cannot read the diff header ${JSON.stringify(l)}`)
      file = p.slice(2)
      continue
    }
    if (!l.startsWith('@@')) continue
    header = false
    const h = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(l)
    if (h === null) throw new Error(`--changed: cannot read the hunk header ${JSON.stringify(l)}`)
    if (file === null) throw new Error(`--changed: a hunk without a file in the diff: ${JSON.stringify(l)}`)
    if (file === '') continue
    const start = Number(h[1]), count = h[2] === undefined ? 1 : Number(h[2])
    const set = added.get(file) ?? new Set<number>()
    for (let n = start; n < start + count; n++) set.add(n)
    added.set(file, set)
  }
  // guards.json entries as of the base (only read when the file changed): a changed or new entry selects its guard.
  let baseMap: Record<string, unknown> | undefined
  if (changed.has(GUARDS_JSON)) {
    const there = git(root, ['ls-tree', '-z', '--name-only', sha, '--', GUARDS_JSON]) !== ''
    if (there) { try { baseMap = JSON.parse(git(root, ['show', `${sha}:./${GUARDS_JSON}`])) as Record<string, unknown> } catch (e) { if (e instanceof SyntaxError) baseMap = {}; else throw e } }
    else baseMap = {}
  }
  const why = new Map<string, string[]>()
  for (const id of ids) {
    const reasons: string[] = []
    const m = markers.get(id)![0]
    if (untracked.has(m.file) || added.get(m.file)?.has(m.line + 1)) reasons.push(`marker line changed (${m.file}:${m.line + 1})`)
    if (changed.has(m.file)) reasons.push(`source changed (${m.file})`)
    for (const t of map[id]) if (changed.has(t)) reasons.push(`test changed (${t})`)
    if (baseMap !== undefined && JSON.stringify(Object.hasOwn(baseMap, id) ? baseMap[id] : null) !== JSON.stringify(map[id])) reasons.push(`${GUARDS_JSON} entry changed`)
    if (reasons.length > 0) why.set(id, reasons)
  }
  return { sha, why }
}

async function main(): Promise<number> {
  const t0 = performance.now()
  const { only, changed, jobs, root, timeoutMs, baselineTimeoutMs, allowEmpty } = parseArgs(process.argv.slice(2))
  const suite = readSuite()
  const gj = join(root, GUARDS_JSON)
  const map = JSON.parse(readFileSync(gj, 'utf8')) as Record<string, string[]>
  const markers = scan(root)
  const errors: string[] = []

  for (const [id, list] of markers) {
    if (!ID.test(id)) errors.push(`bad guard id in marker: ${id}`)
    if (list.length > 1) errors.push(`more than one marker: ${id} (${list.map((m) => `${m.file}:${m.line + 1}`).join(', ')})`)
    if (!Object.hasOwn(map, id)) errors.push(`marker without guards.json entry: ${id}`)
  }
  for (const [id, tests] of Object.entries(map)) {
    if (!markers.has(id)) errors.push(`guards.json entry without marker: ${id}`)
    if (!Array.isArray(tests) || tests.length === 0) errors.push(`guards.json entry has no tests: ${id}`)
    else for (const t of tests) if (!existsSync(join(root, t))) errors.push(`guards.json test missing: ${id} -> ${t}`)
  }
  for (const id of only ?? []) if (!Object.hasOwn(map, id)) errors.push(`--only: unknown guard ${id}`)
  if (markers.size === 0 && Object.keys(map).length === 0 && !allowEmpty) errors.push('no guards found')
  if (errors.length > 0) {
    for (const e of errors) console.error(`ERROR ${e}`)
    return 1
  }

  let ids = Object.keys(map).filter((id) => only === undefined || only.includes(id)).sort()
  if (changed !== undefined) {
    const { sha, why } = selectChanged(root, changed, ids, map, markers)
    console.log(`CHANGED since ${changed} (${sha.slice(0, 12)}): ${why.size} of ${ids.length} guards selected`)
    for (const [id, reasons] of why) console.log(`SELECTED ${id}: ${reasons.join('; ')}`)
    ids = ids.filter((id) => why.has(id))
    if (ids.length === 0) {
      console.log('nothing to run: no guard is affected by the change')
      return 0
    }
  }
  if (ids.length > 0) {
    const failed = await sentinelFailures(suite, baselineTimeoutMs)
    if (failed.length > 0) {
      for (const f of failed) console.log(`SENTINEL-FAILED ${f}`)
      console.log('no guard was run: the children would not be confined')
      return 1
    }
    console.log(`SENTINEL ok (env -i, synthetic HOME; sandboxed: ${SANDBOXED_MARKER.replace('sentinel: env clean, HOME synthetic, ', '')})`)
  }

  const want = manifest(root)
  const workers: Worker[] = []
  const verdicts = new Map<string, string>()
  const mutate: string[] = [] // the guards whose test set passed unmutated
  const setKey = (id: string) => JSON.stringify([...map[id]].sort())
  const sets = new Map<string, string[]>() // distinct mapped test sets -> the files, in the first guard's order
  for (const id of ids) if (!sets.has(setKey(id))) sets.set(setKey(id), map[id])
  const progress = (w: Worker, line: string) => { if (process.stderr.isTTY) process.stderr.write(`.. ${verdicts.size}/${ids.length} ${line} (worker ${w.n})\n`) }
  try {
    for (let n = 0; n < Math.min(jobs, ids.length); n++) workers.push({ n, dir: makeCopy(root, want), remade: 0 })

    // The unmutated copy must pass, otherwise a failing run proves nothing: once per distinct test set.
    const baseline = new Map<string, Outcome>()
    await pool([...sets], workers, async (w, [key, files]) => {
      const o = await runTests(copyOf(w.dir, isWeb(root)), files, baselineTimeoutMs, suite, true)
      checkCopy(w, root, want)
      baseline.set(key, o)
    })
    for (const id of ids) {
      const b = baseline.get(setKey(id))
      if (b === 'pass') mutate.push(id)
      else verdicts.set(id, b === 'timeout' ? `TIMEOUT ${id} (baseline)` : b === 'crash' ? `ERROR ${id} (baseline child crashed)` : `BASELINE-FAILED ${id}`)
    }

    await pool(mutate, workers, async (w, id) => {
      const m = markers.get(id)![0]
      const target = join(copyOf(w.dir, isWeb(root)), m.file)
      const original = readFileSync(target, 'utf8')
      const lines = original.split('\n')
      if (MARKER.exec(lines[m.line])?.[1] !== id) throw new Error(`${m.file}:${m.line + 1} is not the marker of ${id} in the copy`)
      lines[m.line] = ''
      writeFileSync(target, lines.join('\n'))
      let out: Outcome
      try { out = await runTests(copyOf(w.dir, isWeb(root)), map[id], timeoutMs, suite, false) } finally {
        writeFileSync(target, original)
        checkCopy(w, root, want)
      }
      const line = out === 'timeout' ? `TIMEOUT ${id}` : out === 'crash' ? `ERROR ${id} (child crashed)` : out === 'pass' ? `SURVIVED ${id}` : `KILLED ${id}`
      verdicts.set(id, line)
      progress(w, line)
    })
  } finally {
    for (const w of workers) removeDir(w.dir)
  }

  let killed = 0
  let hard = false
  const errored: string[] = []
  for (const id of ids) {
    const line = verdicts.get(id)
    if (line === undefined) throw new Error(`no verdict for ${id}`)
    if (line.startsWith('KILLED ')) killed++
    if (line.startsWith('TIMEOUT ')) hard = true
    if (line.startsWith('ERROR ')) { hard = true; errored.push(id) }
    console.log(line)
  }
  const remade = workers.reduce((s, w) => s + w.remade, 0)
  console.log(`KILLED ${killed}/${ids.length}`)
  if (errored.length > 0) console.log(`ERRORED ${errored.length}: ${errored.join(', ')} (a crashed child is no evidence a test caught the mutation)`)
  // (no verdict word on this line: tests match the verdict lines alone)
  console.log(`wall ${((performance.now() - t0) / 1000).toFixed(1)} s; --jobs ${jobs}: ${workers.length} worker(s), ${sets.size} distinct test set(s) run unmutated, ${mutate.length} mutant(s)${remade > 0 ? `, ${remade} copy(ies) re-made after a test changed them` : ''}`)
  return !hard && killed === ids.length ? 0 : 1
}

try {
  process.exitCode = await main()
} catch (e) {
  console.error(`ERROR ${e instanceof Error ? e.message : String(e)}`)
  process.exitCode = 1
}

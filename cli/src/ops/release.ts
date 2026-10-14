// cli/src/ops/release.ts — `vt release build | verify [<id>] | list`, and the check behind "mainnet runs only from a
// verified release" (canonical vt spec §8, §9; plan Task C4). Orchestration: unsandboxed (it applies a sandbox to the
// web build itself). The prototype's release.sh (MQ I5) is ported as cli/scripts/release.sh, an independent second
// check with system tools only.
//
// ★★★ RELEASE INTEGRITY KEEPS MAINNET OFF HOT-RELOADING DEV CODE. `vt up --network mainnet` (up.ts) runs only from
//   bin/vt inside $VT_HOME/releases/<buildId>/ (vt.mainnet-dev-tree otherwise), and runs verify() + assertVerified()
//   on that tree EVERY time, before Tor, tmux or any file: release.test-only-present, then release.mismatch.
//
// ★★ build (from a development tree only). A RELEASE IS A COMMIT, read from git's objects, never from the working tree
//   (security review C4 I-2: hidden index flags, or an edit saved during the build, put uncommitted bytes in a
//   release that named the commit):
//   1. refused unless the tree is a git work tree with no index entry marked skip-worktree or assume-unchanged
//      (release.index-flags: `git ls-files -v` tag S or lowercase; the paths are named) and no uncommitted change to a
//      tracked file. HEAD is resolved ONCE to a commit id; nothing after that reads the working tree's sources;
//   2. that commit's tree (`git ls-tree -r -z --full-tree`, blobs through `git cat-file --batch`) is exported into a
//      temp dir under $VT_HOME/releases/, with the installed node_modules mirrored beside it (links to the installed
//      packages; first-party workspace links point into the export). buildId = the first 12 hex of sha256 over those
//      blobs, sorted by path bytes, each framed as path NUL type NUL size NUL bytes (type from the tree entry: f,
//      x = 100755, l = 120000, whose bytes are its target). The same commit always gives the same id; an existing
//      verified release of that id is reused, not rebuilt;
//      Before anything is copied, every install the release draws from (the repository root's, broadcast's) must be
//      exactly what the commit's package-lock.json describes (release.lock-drift, review fix round 2; offline, names
//      only, never contents):
//      · npm's own record of the install, <install>/node_modules/.package-lock.json, against the commit's lockfile:
//        the same packages (name, version, resolved; an optional one is excused only when its os/cpu exclude this
//        machine) and the same dependency edges, each resolved by Node's lookup over that file's keys. A hoisted
//        install (broadcast) must match key for key, version, resolved and integrity too. (npm's linked install, the
//        root's, records no integrity: there the integrity npm checked at install time is trusted.)
//      · the disk against that record: every package directory and link under the install's node_modules and its
//        workspaces' (the linked .store included) is in it, nothing is missing, each link points where it says, each
//        package.json has its name and version. Files inside a package are not compared with the registry tarball
//        (offline that is not possible): a file added to an installed package is not detected here;
//   3. into a staging dir under $VT_HOME/releases/ it copies ONLY the commit's files of COPY (so untracked files,
//      state dirs, tokens, .superpowers/, tests and fixtures outside these roots can never enter):
//        1password-timelock.sh timelock-key.sh (C1 ruling 5: vt seal|open find them beside cli/, in SHA256SUMS)
//        cli/{package.json,bin,src}   api/{package.json,src,relay,serve}   packages/core/{package.json,src}
//        broadcast/{package.json,bin,src,vendor,endpoints.json,anchors.json}
//      cli/test (fixtures included: VT_SEALER is then always refused in a release), cli/scripts, docs and every test
//      stay out. The web page is built inside the export (vite build, sandboxed: no network, writes only to the
//      release) straight into web/dist: the commit's web/ sources only (untracked web/src files never reach the page
//      or its build id); Tailwind's sources are pinned to web/src (W1), so the build is byte-reproducible;
//   4. the production node_modules closure, dereferenced: every dependency, optional and peer dependency of the four
//      workspaces, followed from where it is installed (npm's linked store, broadcast's own install), never
//      devDependencies, typescript or @types/*. A package instance is identified by its name, version and the
//      instances its dependencies resolve to (two installs that resolve one package differently stay two copies,
//      exactly as in the development tree). Each instance is placed at the root node_modules/ when that name is
//      free there, else in its dependent's own node_modules/; every resolution is then re-checked against the
//      development tree's. Third-party test/, tests/, __tests__/, fixtures/, __fixtures__/, __mocks__/ directories
//      at a package root and *.test.* / *.spec.* files are not copied;
//   5. the four first-party workspace links stay symlinks, because Node never strips types under node_modules/:
//      <ws>/node_modules/<first-party name> -> the relative path of that workspace in the release (so vt-broadcast
//      resolves through cli/node_modules, C1 ruling 5). They are the only symlinks a release may hold;
//   6. RELEASE.json {format, buildId, commit, links, lockfiles: {<path>: sha256}} (deterministic: no time), SHA256SUMS (every regular file but itself, `<sha256>  ./<path>`,
//      sorted, as shasum -a 256 writes it; the relay's /relay/release and the page's /__serve read it), chmod a-w on
//      every file and directory, rename to releases/<buildId>, then verify (a release that does not verify, test-only
//      content included, is removed again: nothing is kept).
//
// ★★ verify(dir) walks the whole tree (lstat, never following a link) and reports { files, ok, mismatch, missing,
//   extra, links, writable, outside, manifest, testOnly, digest }. assertVerified refuses
//   · release.test-only-present: a path segment test/tests/__tests__/fixtures/__fixtures__/__mocks__ (except viem's
//     own runtime actions/test/), a name with "pressure" or "harness", a *.test.* / *.spec.* file, a pressure-harness
//     marker string in any file, the test override prefix (VT_ TEST_) in any file but api/relay/relay.mjs (S3's
//     local-only, loopback-only override block), a dev-only package (typescript, vite, vitest, jsdom, @types/*, …,
//     and every first-party devDependency) under a node_modules/, or a state/secret name (api.token,
//     relay-ticket.key, api.lock, up.json, journal.jsonl, privacycash-withdrawals.jsonl/.lock, privacycash-lane-mints.jsonl, identity.key, *.age, .env, .npmrc, .git/, .superpowers/,
//     .vt-dev/, restored/);
//   · release.mismatch: unless every SHA256SUMS line is well formed, sorted and unique, every listed file exists as
//     a regular file with that hash (mismatch, missing), no regular file or other entry is unlisted (extra), every
//     symlink is exactly a first-party workspace link listed in RELEASE.json (links), nothing is writable and no
//     entry carries an ACL (writable; review m3: a macOS ACL can grant writes the mode bits do not show), RELEASE.json says this directory's id (manifest), and no node_modules/ above the release (or
//     ~/.node_modules, ~/.node_libraries) could supply a module the release lacks (outside).
//   This guards against drift, accidents and a stray dev file, not against someone who can write to $VT_HOME (who
//   could rewrite SHA256SUMS too); the read-only tree and the clean-commit rule make every change deliberate.
import { refuse } from '@vault-timelock/core/contracts'
import { ensureDir } from 'vt-broadcast/src/lifecycle/paths.ts'
import { spawnSync } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import {
  chmodSync, constants, copyFileSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, readlinkSync, realpathSync,
  renameSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { basename, dirname, join, relative, sep } from 'node:path'
import { UsageError } from '../args.ts'
import { renderLogLine } from './logs.ts'
import type { Env } from './paths.ts'
import { vtHome } from './paths.ts'
import { assertProfilePath } from './sandbox.ts'

export const RELEASE_FORMAT = 'vt-release/1'
export const SUMS = 'SHA256SUMS'
export const MANIFEST = 'RELEASE.json'
export const BUILD_ID = /^[0-9a-f]{12}$/
export const releasesDir = (home: string): string => join(home, 'releases')

// The first-party workspaces: the same relative path in the development tree and in a release.
export const WORKSPACES = ['cli', 'api', 'packages/core', 'broadcast'] as const
// What a release copies of the tracked files: a file, or (trailing /) a directory.
export const COPY: readonly string[] = [
  '1password-timelock.sh', 'timelock-key.sh',
  'cli/package.json', 'cli/bin/', 'cli/src/',
  'api/package.json', 'api/src/', 'api/relay/', 'api/serve/',
  'packages/core/package.json', 'packages/core/src/',
  'broadcast/package.json', 'broadcast/bin/', 'broadcast/src/', 'broadcast/vendor/', 'broadcast/endpoints.json', 'broadcast/anchors.json',
]
// What a release cannot run without.
export const REQUIRED: readonly string[] = [
  '1password-timelock.sh', 'timelock-key.sh', 'cli/package.json', 'cli/bin/vt', 'cli/src/main.ts', 'api/package.json', 'api/src/main.ts',
  'api/relay/relay.mjs', 'api/serve/serve.mjs', 'packages/core/package.json', 'broadcast/package.json', 'broadcast/bin/vt-broadcast',
  'broadcast/src/config.ts', 'broadcast/endpoints.json',
]
export const isReleaseSource = (p: string): boolean => COPY.some((r) => (r.endsWith('/') ? p.startsWith(r) : p === r))

const byBytes = (a: string, b: string): number => Buffer.compare(Buffer.from(a), Buffer.from(b))
const sha256 = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex')
const relPosix = (from: string, to: string): string => relative(from, to).split(sep).join('/')
// A path or finding as it may be printed: no control sequence, no address (review m4: names come from the tree).
const shown = (s: string): string => renderLogLine(Buffer.from(s, 'utf8'))

// ---- the test-only rules (verify and build). The marker strings are assembled from parts, so that this file, which
// ships in every release, does not hold them.
const part = (...p: string[]): Buffer => Buffer.from(p.join(''))
const HARNESS_MARKERS: readonly Buffer[] = [part('sol-pres', 'sure-filter'), part('eth-pres', 'sure-miner'), part('anvil_drop', 'Transaction'), part('WITH', 'HELD')]
const TEST_OVERRIDE = part('VT_', 'TEST_')
// Cfix4 (C4 review m7): the allowance is per OCCURRENCE, not per file. The reviewed relay mentions the marker this many
// times (its comment and the four local-only RPC hooks); a further hook added to relay.mjs
// raises the count and the release refuses until this number is reviewed and changed (cli/scripts/release.sh mirrors it).
export const TEST_OVERRIDE_ALLOWED: ReadonlyMap<string, number> = new Map([['api/relay/relay.mjs', 6]])
const occurrences = (bytes: Buffer, needle: Buffer): number => {
  let n = 0
  for (let i = bytes.indexOf(needle); i >= 0; i = bytes.indexOf(needle, i + needle.length)) n++
  return n
}
const TEST_DIRS = new Set(['test', 'tests', '__tests__', 'fixtures', '__fixtures__', '__mocks__'])
// Third-party directories named like tests that are runtime code: viem's test-client actions (anvil_*/hardhat_* RPC
// wrappers), imported by viem's own index. Matched on the path after the last node_modules/.
const RUNTIME_TEST_DIRS = new Set(['viem/actions/test', 'viem/_cjs/actions/test', 'viem/_esm/actions/test', 'viem/_types/actions/test'])
const TEST_FILE = /\.(?:test|spec)\.[^/]*$/
const HARNESS_NAME = /pressure|harness/i
const STATE_DIRS = new Set(['.git', '.superpowers', '.vt-dev', 'restored'])
const STATE_FILES = new Set(['api.token', 'relay-ticket.key', 'api.lock', 'up.json', 'journal.jsonl', 'identity.key', '.env', '.npmrc',
  'privacycash-withdrawals.jsonl', 'privacycash-withdrawals.lock', 'privacycash-lane-mints.jsonl'])
const STATE_FILE = /\.age$|^\.env\./
const DEV_PACKAGES = new Set(['typescript', 'vite', 'vitest', 'jsdom', 'tsx', 'ts-node', 'esbuild', 'rolldown'])
const DEV_SCOPES = ['@types/', '@testing-library/', '@vitest/', '@vitejs/']
const isDevName = (name: string, extra: ReadonlySet<string>): boolean => DEV_PACKAGES.has(name) || extra.has(name) || DEV_SCOPES.some((s) => name.startsWith(s))

// The package name a release-relative path denotes when it is a package directory inside a node_modules/ (the last
// one): `x/node_modules/@scope/name` -> @scope/name, `x/node_modules/name` -> name, else null.
function packageAt(rel: string): string | null {
  const segs = rel.split('/')
  const i = segs.lastIndexOf('node_modules')
  if (i < 0) return null
  const rest = segs.slice(i + 1)
  if (rest.length === 1 && !rest[0].startsWith('@') && !rest[0].startsWith('.')) return rest[0]
  if (rest.length === 2 && rest[0].startsWith('@')) return `${rest[0]}/${rest[1]}`
  return null
}

// Why a release-relative path (dir true for a directory) is test-only, harness, state or secret; null when it is not.
function namedTestOnly(rel: string, dir: boolean): string | null {
  const segs = rel.split('/')
  const name = segs[segs.length - 1]
  if (HARNESS_NAME.test(name)) return 'a harness/pressure name'
  if (dir && TEST_DIRS.has(name)) {
    const i = segs.lastIndexOf('node_modules')
    const inPackage = i >= 0 ? segs.slice(i + 1).join('/') : null
    const thirdParty = inPackage !== null && !inPackage.startsWith('@vault-timelock/') && !inPackage.startsWith('vt-broadcast/')
    if (!(thirdParty && RUNTIME_TEST_DIRS.has(inPackage))) return 'a test/fixtures directory'
  }
  if (!dir && TEST_FILE.test(name)) return 'a test file'
  if (dir && STATE_DIRS.has(name)) return 'a state or repository directory'
  if (!dir && (STATE_FILES.has(name) || STATE_FILE.test(name))) return 'a state or secret file'
  return null
}

// Why a file's bytes are test-only; null when they are not.
function contentTestOnly(rel: string, bytes: Buffer): string | null {
  for (const m of HARNESS_MARKERS) if (bytes.indexOf(m) >= 0) return 'a pressure-harness marker'
  const found = occurrences(bytes, TEST_OVERRIDE)
  if (found > (TEST_OVERRIDE_ALLOWED.get(rel) ?? 0)) return TEST_OVERRIDE_ALLOWED.has(rel) ? 'test override code beyond its reviewed hooks' : 'test override code outside its guard'
  return null
}

// ---- verify

export interface VerifyReport {
  dir: string
  files: number      // SHA256SUMS lines
  ok: number
  mismatch: number   // a malformed, unsorted or repeated line, a different hash, or a listed path that is not a regular file
  missing: number
  extra: number      // a regular file (or a FIFO, socket, device) SHA256SUMS does not list
  links: number      // a symlink that is not a listed first-party workspace link with its exact target
  writable: number   // a file or directory with a write bit
  outside: number    // node_modules/ above the release, ~/.node_modules, ~/.node_libraries
  manifest: boolean  // RELEASE.json well formed and naming this directory's id
  testOnly: string[] // "<path>: <why>"
  problems: string[] // the first integrity findings, "<path>: <why>" (paths inside the release only)
  digest: string | null // sha256 of SHA256SUMS
}

interface Found { files: Map<string, string>; links: Map<string, string> }

const LINE = /^([0-9a-f]{64}) {2}\.\/(.+)$/

// The name of the first-party package of each workspace of the release (from its own, hashed, package.json).
function firstPartyNames(dir: string): Map<string, string> {
  const names = new Map<string, string>()
  for (const ws of WORKSPACES) {
    try {
      const pj = JSON.parse(readFileSync(join(dir, ws, 'package.json'), 'utf8')) as { name?: unknown }
      if (typeof pj.name === 'string') names.set(pj.name, ws)
    } catch { /* a missing workspace is reported as missing files */ }
  }
  return names
}
export const BROADCAST_CORE_LINK = '@vault-timelock/core'
// The target a first-party workspace link at `rel` must have, or null when `rel` is not such a link's path.
export function expectedLinkTarget(rel: string, names: ReadonlyMap<string, string>): string | null {
  for (const ws of WORKSPACES) {
    const prefix = `${ws}/node_modules/`
    if (!rel.startsWith(prefix)) continue
    const name = rel.slice(prefix.length)
    // broadcast's only first-party link is its dependency on core (E6 fix round 1; M4a: a dependency, not an optional one): any other link
    // under broadcast/node_modules is refused, however RELEASE.json lists it.
    if (ws === 'broadcast' && name !== BROADCAST_CORE_LINK) return null
    const target = names.get(name)
    return target === undefined ? null : relPosix(dirname(rel), target)
  }
  return null
}

function devExtra(dir: string): Set<string> {
  const extra = new Set<string>()
  for (const ws of WORKSPACES) {
    try {
      const pj = JSON.parse(readFileSync(join(dir, ws, 'package.json'), 'utf8')) as { devDependencies?: Record<string, unknown> }
      for (const n of Object.keys(pj.devDependencies ?? {})) extra.add(n)
    } catch { /* see firstPartyNames */ }
  }
  return extra
}

// Exported for the tests; `execPath` is the node binary whose prefix names Node's CJS global folder (m8).
export function outsideSources(dir: string, execPath: string = process.execPath): number {
  let n = 0
  let real: string
  try { real = realpathSync(dir) } catch { return 0 }
  for (let d = dirname(real); ; d = dirname(d)) {
    if (basename(d) !== 'node_modules' && existsSync(join(d, 'node_modules'))) n++
    if (dirname(d) === d) break
  }
  for (const g of ['.node_modules', '.node_libraries']) if (existsSync(join(homedir(), g))) n++
  // Cfix4 (C4 review m8): Node's CJS global folder, $PREFIX/lib/node (NODE_PATH is stripped, this one is not).
  if (existsSync(join(dirname(dirname(execPath)), 'lib', 'node'))) n++
  return n
}

// `id`: the build id the tree must declare (default: its directory name; build passes it while the tree is staged).
// The number of ACL entries anywhere in the tree (`ls -leRA` prints each as " <n>: …"); -1 when they cannot be read.
function aclEntries(dir: string): number {
  const r = spawnSync('/bin/ls', ['-leRA', dir], { encoding: 'buffer', maxBuffer: 512 * 1024 * 1024, timeout: 120_000 })
  if (r.error !== undefined || r.status !== 0) return -1
  return (r.stdout.toString('utf8').match(/^ \d+: /gm) ?? []).length
}

export function verify(dir: string, id: string = basename(dir)): VerifyReport {
  const r: VerifyReport = { dir, files: 0, ok: 0, mismatch: 0, missing: 0, extra: 0, links: 0, writable: 0, outside: 0, manifest: false, testOnly: [], problems: [], digest: null }
  const problem = (rel: string, why: string): void => { if (r.problems.length < 20) r.problems.push(`${rel}: ${why}`) }
  let top: ReturnType<typeof lstatSync>
  try { top = lstatSync(dir) } catch { problem('.', 'no such release'); return r }
  if (!top.isDirectory()) { problem('.', 'not a directory'); return r }
  const names = firstPartyNames(dir)
  const dev = devExtra(dir)
  const found: Found = { files: new Map(), links: new Map() }
  const stack: string[] = ['']
  const dirs = new Set<string>()
  while (stack.length > 0) {
    const rel = stack.pop() as string
    const abs = rel === '' ? dir : join(dir, rel)
    const st = lstatSync(abs)
    if ((st.mode & 0o222) !== 0 && !st.isSymbolicLink()) { r.writable++; problem(rel || '.', 'writable') }
    if (st.isDirectory()) {
      if (rel !== '') {
        const why = namedTestOnly(rel, true)
        if (why !== null) r.testOnly.push(`${rel}: ${why}`)
        const pkg = packageAt(rel)
        if (pkg !== null && isDevName(pkg, dev)) r.testOnly.push(`${rel}: a dev-only package`)
      }
      if (rel !== '') dirs.add(rel)
      for (const e of readdirSync(abs).sort(byBytes).reverse()) stack.push(rel === '' ? e : `${rel}/${e}`)
    } else if (st.isSymbolicLink()) {
      found.links.set(rel, readlinkSync(abs))
      const pkg = packageAt(rel)
      if (pkg !== null && isDevName(pkg, dev)) r.testOnly.push(`${rel}: a dev-only package`)
    } else if (st.isFile()) {
      const bytes = readFileSync(abs)
      found.files.set(rel, sha256(bytes))
      const why = namedTestOnly(rel, false) ?? contentTestOnly(rel, bytes)
      if (why !== null) r.testOnly.push(`${rel}: ${why}`)
    } else {
      r.extra++
      problem(rel, 'not a regular file, directory or link')
    }
  }
  // Cfix4 (C4 review m6): a directory that no file or link beneath it implies is an extra (an empty directory can only
  // shadow a package into a load error, but a release holds nothing it did not list).
  const implied = new Set<string>()
  for (const p of [...found.files.keys(), ...found.links.keys()]) for (let d = dirname(p); d !== '.' && d !== '/'; d = dirname(d)) implied.add(d)
  for (const d of dirs) if (!implied.has(d)) { r.extra++; problem(d, 'an empty directory (nothing in it is listed)') }
  // SHA256SUMS
  const sumsHash = found.files.get(SUMS)
  found.files.delete(SUMS)
  const listed = new Map<string, string>()
  if (sumsHash === undefined) {
    problem(SUMS, 'missing')
  } else {
    const text = readFileSync(join(dir, SUMS))
    r.digest = sha256(text)
    const lines = text.toString('utf8').split('\n')
    if (lines.pop() !== '') { r.mismatch++; problem(SUMS, 'does not end in a newline') }
    let prev: string | null = null
    for (const line of lines) {
      r.files++
      const m = LINE.exec(line)
      if (m === null) { r.mismatch++; problem(SUMS, 'a malformed line'); continue }
      const [, hash, path] = m
      if (prev !== null && byBytes(prev, path) >= 0) { r.mismatch++; problem(path, 'out of order or repeated in SHA256SUMS'); continue }
      prev = path
      listed.set(path, hash)
      const got = found.files.get(path)
      if (got === undefined) {
        if (found.links.has(path)) { r.mismatch++; problem(path, 'listed, but a link') } else { r.missing++; problem(path, 'missing') }
      } else if (got !== hash) {
        r.mismatch++
        problem(path, 'changed')
      } else {
        r.ok++
      }
    }
  }
  for (const path of found.files.keys()) if (!listed.has(path)) { r.extra++; problem(path, 'not in SHA256SUMS') }
  // RELEASE.json and the links
  // The links RELEASE.json lists are compared whatever else it says; its other fields decide `manifest`.
  let manifestLinks: Record<string, unknown> | null = null
  try {
    const m = JSON.parse(readFileSync(join(dir, MANIFEST), 'utf8')) as Record<string, unknown>
    if (typeof m.links === 'object' && m.links !== null && !Array.isArray(m.links)) manifestLinks = m.links as Record<string, unknown>
    const keysOk = JSON.stringify(Object.keys(m).sort()) === JSON.stringify(['buildId', 'commit', 'format', 'links', 'lockfiles'])
    const locks = m.lockfiles as Record<string, unknown> | null
    const locksOk = typeof locks === 'object' && locks !== null && !Array.isArray(locks) && Object.values(locks).every((v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v))
    r.manifest = keysOk && locksOk && manifestLinks !== null && m.format === RELEASE_FORMAT && typeof m.buildId === 'string' && BUILD_ID.test(m.buildId) && m.buildId === id
      && typeof m.commit === 'string' && /^[0-9a-f]{40}$/.test(m.commit)
  } catch { /* manifest stays false */ }
  if (!r.manifest) problem(MANIFEST, 'missing, malformed, or naming another build id')
  for (const [rel, target] of found.links) {
    const want = expectedLinkTarget(rel, names)
    if (want === null || target !== want || manifestLinks === null || manifestLinks[rel] !== target) { r.links++; problem(rel, 'an unexpected link') }
  }
  if (manifestLinks !== null) for (const rel of Object.keys(manifestLinks)) if (!found.links.has(rel)) { r.links++; problem(rel, 'a listed link is missing') }
  const acl = aclEntries(dir)
  if (acl !== 0) { r.writable += acl < 0 ? 1 : acl; problem('.', acl < 0 ? 'its ACLs could not be read' : `${acl} ACL entr${acl === 1 ? 'y' : 'ies'} (a release carries none)`) }
  r.outside = outsideSources(dir)
  if (r.outside > 0) problem('..', 'a node_modules directory above the release (or ~/.node_modules, ~/.node_libraries) could supply code')
  return r
}

const summary = (r: VerifyReport): string =>
  `files ${r.files}, ok ${r.ok}, mismatch ${r.mismatch}, missing ${r.missing}, extra ${r.extra}, links ${r.links}, writable ${r.writable}, outside ${r.outside}, manifest ${r.manifest ? 'ok' : 'bad'}, test-only ${r.testOnly.length}`

export function assertVerified(r: VerifyReport): void {
  const clean = r.testOnly.length === 0
  const testOnly = `release ${basename(r.dir)} holds test-only, harness, dev-only or state files (${r.testOnly.slice(0, 3).map(shown).join('; ')}${r.testOnly.length > 3 ? '; …' : ''}); it never runs`
  if (!clean) refuse('release.test-only-present', testOnly) // @guard:release.test-only-present
  const ok = r.files > 0 && r.ok === r.files && r.mismatch === 0 && r.missing === 0 && r.extra === 0 && r.links === 0 && r.writable === 0 && r.outside === 0 && r.manifest
  if (!ok) refuse('release.mismatch', `release ${basename(r.dir)} does not verify (${summary(r)}); it never runs: build a new one (vt release build)`) // @guard:release.mismatch
}

// ---- build

function git(repo: string, args: readonly string[], env: Env, input?: string): Buffer {
  const r = spawnSync('git', ['-C', repo, ...args], {
    env: { PATH: env.PATH ?? '/usr/bin:/bin', HOME: env.HOME ?? '', LANG: 'C', GIT_OPTIONAL_LOCKS: '0' }, maxBuffer: 1024 * 1024 * 1024, timeout: 300_000, input,
  })
  if (r.error !== undefined || r.status !== 0) throw new UsageError(`vt release build needs a git work tree: git ${args[0]} failed (${r.stderr?.toString('utf8').split('\n')[0] ?? ''})`)
  return r.stdout
}

// One file of a commit, from git's objects: its path, type (f, x = executable, l = symlink) and bytes.
export interface TreeEntry { path: string; type: 'f' | 'x' | 'l'; bytes: Buffer }
const MODES: Readonly<Record<string, TreeEntry['type']>> = { 100644: 'f', 100755: 'x', 120000: 'l' }

// The files of `commit` (a full commit id), read from the object store: `git ls-tree -r -z --full-tree`, then every
// blob through one `git cat-file --batch`. A submodule or an unknown mode refuses the build.
export function readCommitTree(repo: string, commit: string, env: Env): TreeEntry[] {
  const listed: Array<{ path: string; type: TreeEntry['type']; oid: string }> = []
  for (const rec of git(repo, ['ls-tree', '-r', '-z', '--full-tree', commit], env).toString('utf8').split('\0')) {
    if (rec === '') continue
    const m = /^(\d{6}) (\w+) ([0-9a-f]{40,64})\t(.+)$/s.exec(rec)
    if (m === null || m[2] !== 'blob' || !Object.hasOwn(MODES, m[1])) throw new UsageError(`vt release build: the commit holds an entry vt cannot release (a submodule or mode ${m?.[1] ?? '?'}): ${shown(m?.[4] ?? rec)}`)
    listed.push({ path: m[4], type: MODES[m[1]], oid: m[3] })
  }
  const out = git(repo, ['cat-file', '--batch'], env, listed.map((e) => `${e.oid}\n`).join(''))
  const entries: TreeEntry[] = []
  let at = 0
  for (const e of listed) {
    const nl = out.indexOf(0x0a, at)
    const head = out.toString('utf8', at, nl).split(' ')
    if (head[0] !== e.oid || head[1] !== 'blob') throw new Error(`vt release build: git cat-file did not return blob ${e.oid}`)
    const size = Number(head[2])
    entries.push({ path: e.path, type: e.type, bytes: Buffer.from(out.subarray(nl + 1, nl + 1 + size)) })
    at = nl + 1 + size + 1
  }
  return entries.sort((a, b) => byBytes(a.path, b.path))
}

// ---- the installed tree against the commit's lockfiles (see the header, build step 2; review fix round 2)

// The installs a release draws its node_modules from: the repository root (npm's linked install: the workspaces and
// the .store) and broadcast's own (hoisted) install.
export const INSTALLS = ['', 'broadcast'] as const
interface LockEntry {
  version?: unknown; resolved?: unknown; integrity?: unknown; link?: unknown; optional?: unknown; os?: unknown; cpu?: unknown
  dependencies?: unknown; optionalDependencies?: unknown; peerDependencies?: unknown; devDependencies?: unknown; workspaces?: unknown
}
type Packages = Readonly<Record<string, LockEntry>>
const lockName = (k: string): string => k.slice(k.lastIndexOf('node_modules/') + 'node_modules/'.length)
const isWorkspaceKey = (k: string): boolean => !k.includes('node_modules/')
const isPackageKey = (P: Packages, k: string): boolean => !isWorkspaceKey(k) && P[k].link !== true && typeof P[k].version === 'string'
const nodeId = (P: Packages, k: string): string => `${lockName(k)}@${String(P[k].version)}|${String(P[k].resolved)}`
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [])
// npm's platform rule for an optional package: a `!x` excludes x, a positive list must name the current value.
function platformAllows(e: LockEntry): boolean {
  const allows = (list: string[], value: string): boolean => {
    if (list.length === 0) return true
    if (list.includes(`!${value}`)) return false
    const positive = list.filter((x) => !x.startsWith('!'))
    return positive.length === 0 || positive.includes(value)
  }
  return allows(strings(e.os), process.platform) && allows(strings(e.cpu), process.arch)
}
// What a dependency name resolves to from a key, by Node's lookup over the file's keys (links followed).
function lockResolve(P: Packages, from: string, dep: string): string | null {
  for (const d of lookupChain(from)) {
    let k = `${d}/${dep}`
    if (P[k] === undefined) continue
    for (let n = 0; P[k] !== undefined && P[k].link === true && n < 16; n++) k = String(P[k].resolved)
    if (isWorkspaceKey(k)) return `workspace ${k}`
    return P[k] === undefined || typeof P[k].version !== 'string' ? `unresolved ${k}` : nodeId(P, k)
  }
  return null
}
// The packages and dependency edges a lockfile (or npm's record of an install) describes. The root project ('') is
// left out: npm's record never holds it.
function lockGraph(P: Packages): { nodes: Map<string, LockEntry>; edges: Set<string> } {
  const nodes = new Map<string, LockEntry>()
  const edges = new Set<string>()
  for (const k of Object.keys(P).sort(byBytes)) {
    if (k === '' || P[k].link === true) continue
    const ws = isWorkspaceKey(k)
    if (!ws && typeof P[k].version !== 'string') continue // a .store container
    const from = ws ? `workspace ${k}` : nodeId(P, k)
    if (!ws) nodes.set(from, P[k])
    const e = P[k]
    for (const dep of new Set([...keysOf(e.dependencies), ...keysOf(e.optionalDependencies), ...keysOf(e.peerDependencies), ...(ws ? keysOf(e.devDependencies) : [])])) {
      const to = lockResolve(P, k, dep)
      if (to !== null) edges.add(`${from} -> ${dep} -> ${to}`)
    }
  }
  return { nodes, edges }
}

// Every package position under the given node_modules directories (relative to `root`): package directories, links,
// .store containers (npm's linked install), nested node_modules of hoisted packages. Dot entries (.bin, caches, npm's
// .package-lock.json) are not positions.
function installedPositions(root: string, nmDirs: readonly string[]): Map<string, 'dir' | 'link' | 'container' | 'other'> {
  const out = new Map<string, 'dir' | 'link' | 'container' | 'other'>()
  const position = (at: string): void => {
    const st = lstatSync(join(root, at))
    if (st.isSymbolicLink()) { out.set(at, 'link'); return }
    out.set(at, st.isDirectory() ? 'dir' : 'other')
    if (st.isDirectory()) walk(`${at}/node_modules`)
  }
  const store = (): void => {
    const s = 'node_modules/.store'
    for (const e of readdirSync(join(root, s)).sort(byBytes)) {
      const ids = e.startsWith('@') ? readdirSync(join(root, s, e)).sort(byBytes).map((x) => `${e}/${x}`) : [e]
      for (const id of ids) { out.set(`${s}/${id}`, 'container'); walk(`${s}/${id}/node_modules`) }
    }
  }
  const walk = (nm: string): void => {
    let names: string[]
    try { names = readdirSync(join(root, nm)).sort(byBytes) } catch { return }
    for (const e of names) {
      if (e.startsWith('.')) { if (e === '.store' && nm === 'node_modules') store(); continue }
      const at = `${nm}/${e}`
      const st = lstatSync(join(root, at))
      if (e.startsWith('@') && st.isDirectory()) { for (const sub of readdirSync(join(root, at)).sort(byBytes)) if (!sub.startsWith('.')) position(`${at}/${sub}`) } else position(at)
    }
  }
  for (const nm of nmDirs) walk(nm)
  return out
}

// What differs between one install and the commit's lockfile for it (keys and names only; empty: none).
export function installDrift(repo: string, install: string, lockBytes: Buffer | undefined): string[] {
  const where = install === '' ? '' : `${install}/`
  const label = install === '' ? 'root install' : `${install} install`
  const found: string[] = []
  const add = (s: string): void => { if (found.length < 50) found.push(s) }
  // A package as printed: "name version" (name@version would read as a user@host to the log redaction).
  const disp = (id: string): string => (id.startsWith('workspace ') ? id : id.split('|')[0].replace(/@(?=[^@]*$)/, ' '))
  const dispEdge = (edge: string): string => edge.split(' -> ').map((x, i) => (i === 1 ? x : disp(x))).join(' -> ')
  if (lockBytes === undefined) return [`${where}package-lock.json: not in the commit`]
  let L: Packages
  let H: Packages
  try { L = (JSON.parse(lockBytes.toString('utf8')) as { packages: Packages }).packages } catch { return [`${where}package-lock.json: not a lockfile`] }
  const root = join(repo, install)
  try { H = (JSON.parse(readFileSync(join(root, 'node_modules', '.package-lock.json'), 'utf8')) as { packages: Packages }).packages } catch { return [`${where}node_modules/.package-lock.json: missing or unreadable (not installed with npm ci?)`] }
  if (typeof L !== 'object' || L === null || typeof H !== 'object' || H === null) return [`${where}package-lock.json: no packages`]
  // The record against the lockfile: packages and edges.
  const gl = lockGraph(L)
  const gh = lockGraph(H)
  const excused = new Set<string>()
  for (const [id, e] of gl.nodes) {
    if (gh.nodes.has(id)) continue
    if (e.optional === true && !platformAllows(e)) excused.add(id)
    else add(`${label}: ${disp(id)} is in the lockfile, not installed`)
  }
  for (const id of gh.nodes.keys()) if (!gl.nodes.has(id)) add(`${label}: ${disp(id)} is installed, not in the lockfile`)
  const touches = (edge: string): boolean => [...excused].some((id) => edge.startsWith(`${id} `) || edge.endsWith(` ${id}`))
  for (const edge of gl.edges) if (!gh.edges.has(edge) && !touches(edge)) add(`${label}: a dependency differs: ${dispEdge(edge)} (the lockfile)`)
  for (const edge of gh.edges) if (!gl.edges.has(edge)) add(`${label}: a dependency differs: ${dispEdge(edge)} (installed)`)
  const linked = Object.keys(H).some((k) => k.startsWith('node_modules/.store/'))
  if (!linked) {
    // A hoisted install: key for key, with integrity.
    for (const k of Object.keys(L)) {
      if (k === '' || (isPackageKey(L, k) && excused.has(nodeId(L, k)))) continue
      if (H[k] === undefined) { add(`${where}${k}: in the lockfile, not installed`); continue }
      for (const f of ['version', 'resolved', 'integrity', 'link'] as const) if (JSON.stringify(L[k][f]) !== JSON.stringify(H[k][f])) add(`${where}${k}: ${f} differs`)
    }
    for (const k of Object.keys(H)) if (L[k] === undefined) add(`${where}${k}: installed, not in the lockfile`)
  }
  // The disk against npm's record.
  const workspaces = strings(L['']?.workspaces)
  const nmDirs = ['node_modules', ...workspaces.map((w) => `${w}/node_modules`)]
  const inScope = (k: string): boolean => nmDirs.some((d) => k.startsWith(`${d}/`))
  const disk = installedPositions(root, nmDirs)
  for (const [k, e] of Object.entries(H)) {
    if (!inScope(k)) continue
    const d = disk.get(k)
    if (d === undefined) { add(`${where}${k}: missing on disk`); continue }
    if (e.link === true) {
      let same = false
      try { same = d === 'link' && realpathSync(join(root, k)) === realpathSync(join(root, String(e.resolved))) } catch { /* a dangling link */ }
      if (!same) add(`${where}${k}: the link is not where npm put it`)
    } else if (typeof e.version === 'string') {
      let pj: Record<string, unknown> = {}
      try { pj = d === 'dir' ? readPkg(join(root, k)) : {} } catch { /* below */ }
      if (pj.name !== lockName(k) || pj.version !== e.version) add(`${where}${k}: not the package npm installed there`)
    } else if (d !== 'container') {
      add(`${where}${k}: not what npm installed`)
    }
  }
  for (const k of disk.keys()) if (H[k] === undefined) add(`${where}${k}: on disk, not in npm's record of the install`)
  return found
}

export function assertNoLockDrift(found: readonly string[]): void {
  const ok = found.length === 0
  if (!ok) refuse('release.lock-drift', `the installed node_modules are not what the commit's lockfiles describe (${found.slice(0, 5).map(shown).join('; ')}${found.length > 5 ? '; …' : ''}); reinstall: npx --yes npm@11.21.0 ci --ignore-scripts at the root, then cd broadcast && npm ci --ignore-scripts`) // @guard:release.lock-drift
}

// The build id of a commit's files (see the header, build step 2).
export function computeBuildId(entries: readonly TreeEntry[]): string {
  const h = createHash('sha256').update('vt-build/1\0')
  for (const e of [...entries].sort((a, b) => byBytes(a.path, b.path))) {
    h.update(e.path).update('\0').update(e.type).update('\0').update(String(e.bytes.length)).update('\0').update(e.bytes)
  }
  return h.digest('hex').slice(0, 12)
}

// Writes a commit's files under `root` (regular files 0644/0755, links as links).
function exportTree(entries: readonly TreeEntry[], root: string): void {
  for (const e of entries) {
    const dst = join(root, e.path)
    mkdirSync(dirname(dst), { recursive: true, mode: 0o755 })
    if (e.type === 'l') symlinkSync(e.bytes.toString('utf8'), dst)
    else writeFileSync(dst, e.bytes, { mode: e.type === 'x' ? 0o755 : 0o644 })
  }
}

// The installed node_modules beside an export: for the repository root and every workspace (and web), a node_modules
// whose entries link to the installed packages' real paths, except a first-party workspace, which links to the
// export's copy (so the closure and the page build resolve the commit's first-party code, and installed third-party
// packages). Entries starting with a dot (.bin, .store, caches) are not mirrored.
const MIRRORED = ['', ...WORKSPACES, 'web'] as const
function mirrorNodeModules(repo: string, root: string): void {
  const workspaces = new Map<string, string>()
  for (const ws of [...WORKSPACES, 'web']) {
    try { workspaces.set(realpathSync(join(repo, ws)), ws) } catch { /* not in this tree */ }
  }
  for (const ws of MIRRORED) {
    const src = join(repo, ws, 'node_modules')
    if (!existsSync(src)) continue
    const dst = join(root, ws, 'node_modules')
    const one = (name: string): void => {
      const real = realpathSync(join(src, name))
      const at = join(dst, name)
      mkdirSync(dirname(at), { recursive: true, mode: 0o755 })
      const own = workspaces.get(real)
      symlinkSync(own === undefined ? real : relative(dirname(at), join(root, own)), at)
    }
    for (const e of readdirSync(src).sort(byBytes)) {
      if (e.startsWith('.')) continue
      const st = lstatSync(join(src, e))
      if (e.startsWith('@') && st.isDirectory()) for (const sub of readdirSync(join(src, e)).sort(byBytes)) one(`${e}/${sub}`)
      else one(e)
    }
  }
}

// Index entries git status cannot see change: skip-worktree (tag S) or assume-unchanged (a lowercase tag).
export function hiddenIndexEntries(listing: Buffer): string[] {
  return listing.toString('utf8').split('\0').filter((r) => /^(?:S|[a-z]) /.test(r)).map((r) => r.slice(2))
}
export function assertNoHiddenIndexFlags(listing: Buffer): void {
  const hidden = hiddenIndexEntries(listing)
  const ok = hidden.length === 0
  if (!ok) refuse('release.index-flags', `index entries marked skip-worktree or assume-unchanged hide their edits from git status: ${hidden.slice(0, 5).map(shown).join(', ')}${hidden.length > 5 ? ', …' : ''} (clear them: git update-index --no-skip-worktree --no-assume-unchanged <path>)`) // @guard:release.index-flags
}

// -- the production closure

interface Pkg { real: string; name: string; version: string; deps: Map<string, string> /* name -> real */ }
export interface Instance { key: string; name: string; version: string; src: string; deps: Map<string, string> /* name -> key */ }
export interface Closure { instances: Map<string, Instance>; consumers: Map<string, Map<string, string>> /* ws -> name -> key */; links: Map<string, string> }

const readPkg = (dir: string): Record<string, unknown> => JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as Record<string, unknown>
const keysOf = (v: unknown): string[] => (typeof v === 'object' && v !== null ? Object.keys(v) : [])
const isDevEdge = (name: string): boolean => name === 'typescript' || name.startsWith('@types/')

// Node's lookup of a bare package name from `from` (a real directory), bounded to `bounds` (the export and the
// repository): a package installed above them is never taken.
function resolveDev(from: string, name: string, bounds: readonly string[]): string | null {
  const inside = (d: string): boolean => bounds.some((b) => d === b || d.startsWith(`${b}${sep}`))
  for (let d = from; inside(d); d = dirname(d)) {
    if (basename(d) !== 'node_modules') {
      const p = join(d, 'node_modules', name)
      if (existsSync(join(p, 'package.json'))) return realpathSync(p)
    }
    if (bounds.includes(d)) break
  }
  return null
}

// The closure of the workspaces under `treePath` (the export), resolving installed packages within `boundPaths`.
export function productionClosure(treePath: string, boundPaths: readonly string[] = [treePath]): Closure {
  const repo = realpathSync(treePath)
  const bounds = boundPaths.map((b) => realpathSync(b))
  const firstParty = new Map<string, string>() // package name -> workspace
  for (const ws of WORKSPACES) {
    const name = readPkg(join(repo, ws)).name
    if (typeof name === 'string') firstParty.set(name, ws)
  }
  const pkgs = new Map<string, Pkg>()
  const edgesOf = (dir: string, label: string): Map<string, string> => {
    const pj = readPkg(dir)
    const optional = new Set(keysOf(pj.optionalDependencies))
    const required = new Set(keysOf(pj.dependencies).filter((n) => !optional.has(n)))
    const deps = new Map<string, string>()
    for (const name of [...new Set([...keysOf(pj.dependencies), ...optional, ...keysOf(pj.peerDependencies)])].sort(byBytes)) {
      if (isDevEdge(name) || firstParty.has(name)) continue
      const real = resolveDev(dir, name, bounds)
      if (real === null) {
        if (required.has(name)) throw new UsageError(`vt release build: ${label} needs ${name}, which is not installed (npx --yes npm@11.21.0 ci --ignore-scripts; cd broadcast && npm ci --ignore-scripts)`)
        continue
      }
      deps.set(name, real)
      visit(real)
    }
    return deps
  }
  const visit = (real: string): void => {
    if (pkgs.has(real)) return
    const pj = readPkg(real)
    if (typeof pj.name !== 'string' || typeof pj.version !== 'string') throw new Error(`a package without a name or version under node_modules (${relPosix(repo, real)})`)
    const p: Pkg = { real, name: pj.name, version: pj.version, deps: new Map() }
    pkgs.set(real, p)
    p.deps = edgesOf(real, `${pj.name}@${pj.version}`)
  }
  const consumerReals = new Map<string, Map<string, string>>()
  const links = new Map<string, string>()
  for (const ws of WORKSPACES) {
    consumerReals.set(ws, edgesOf(join(repo, ws), ws))
    const pj = readPkg(join(repo, ws))
    for (const name of [...new Set([...keysOf(pj.dependencies), ...(ws === 'broadcast' ? keysOf(pj.optionalDependencies) : [])])].sort(byBytes)) {
      const target = firstParty.get(name)
      if (ws === 'broadcast' && name !== BROADCAST_CORE_LINK) continue
      if (target !== undefined) links.set(`${ws}/node_modules/${name}`, relPosix(join(ws, 'node_modules', dirname(name)), target))
    }
  }
  // Canonical keys: name@version plus the keys its dependencies resolve to (a cycle keeps its real path).
  const keys = new Map<string, string>()
  const onPath = new Set<string>()
  const keyOf = (real: string): string => {
    const done = keys.get(real)
    if (done !== undefined) return done
    const p = pkgs.get(real) as Pkg
    if (onPath.has(real)) return `cycle:${p.name}@${p.version}:${real}`
    onPath.add(real)
    const parts = [...p.deps].map(([n, r]) => `${n}=${keyOf(r)}`).join(',')
    onPath.delete(real)
    const key = `${p.name}@${p.version}#${sha256(parts).slice(0, 16)}`
    keys.set(real, key)
    return key
  }
  const instances = new Map<string, Instance>()
  for (const real of [...pkgs.keys()].sort(byBytes)) {
    const p = pkgs.get(real) as Pkg
    const key = keyOf(real)
    if (!instances.has(key)) instances.set(key, { key, name: p.name, version: p.version, src: real, deps: new Map([...p.deps].map(([n, r]) => [n, keyOf(r)])) })
  }
  const consumers = new Map<string, Map<string, string>>()
  for (const [ws, deps] of consumerReals) consumers.set(ws, new Map([...deps].map(([n, r]) => [n, keyOf(r)])))
  return { instances, consumers, links }
}

// The node_modules/ directories Node consults from a release-relative directory, nearest first (Node's
// _nodeModulePaths, stopping at the release root).
export function lookupChain(loc: string): string[] {
  const out: string[] = []
  const segs = loc === '' ? [] : loc.split('/')
  for (let i = segs.length; i >= 0; i--) {
    if (i > 0 && segs[i - 1] === 'node_modules') continue
    out.push([...segs.slice(0, i), 'node_modules'].join('/'))
  }
  return out
}

// Where each instance goes (release-relative package directory -> instance key); see the header, build step 4.
export function placeClosure(c: Closure): Map<string, string> {
  const at = new Map<string, string>()
  const visible = (loc: string, name: string): string | undefined => {
    for (const d of lookupChain(loc)) {
      const k = at.get(`${d}/${name}`)
      if (k !== undefined) return k
    }
    return undefined
  }
  const queue: Array<[string, Map<string, string>]> = [...c.consumers].map(([ws, deps]) => [ws, deps])
  while (queue.length > 0) {
    const [loc, deps] = queue.shift() as [string, Map<string, string>]
    const placed: Array<[string, string]> = []
    for (const [name, key] of [...deps].sort((a, b) => byBytes(a[0], b[0]))) {
      const seen = visible(loc, name)
      if (seen === key) continue
      const target = seen === undefined ? `node_modules/${name}` : `${loc}/node_modules/${name}`
      at.set(target, key)
      placed.push([target, key])
    }
    for (const [target, key] of placed) queue.push([target, (c.instances.get(key) as Instance).deps])
  }
  // Every resolution as in the development tree.
  const check = (loc: string, deps: Map<string, string>): void => {
    for (const [name, key] of deps) if (visible(loc, name) !== key) throw new Error(`release closure: ${name} would not resolve as in the development tree from ${loc}`)
  }
  for (const [ws, deps] of c.consumers) check(ws, deps)
  for (const [loc, key] of at) check(loc, (c.instances.get(key) as Instance).deps)
  return at
}

const PACKAGE_ROOT_SKIP = TEST_DIRS
// A third-party package directory, dereferenced: no nested node_modules/ (placed separately), no test directories at
// its root, no *.test.* / *.spec.* files. A symlink or special file inside a package refuses the build.
function copyPackage(src: string, dst: string, rootDir = src): void {
  mkdirSync(dst, { recursive: true, mode: 0o755 })
  for (const e of readdirSync(src).sort(byBytes)) {
    const s = join(src, e)
    const d = join(dst, e)
    const st = lstatSync(s)
    if (st.isDirectory()) {
      if (e === 'node_modules' || (src === rootDir && PACKAGE_ROOT_SKIP.has(e))) continue
      copyPackage(s, d, rootDir)
    } else if (st.isFile()) {
      if (TEST_FILE.test(e)) continue
      copyFileSync(s, d, constants.COPYFILE_FICLONE)
      chmodSync(d, (st.mode & 0o111) !== 0 ? 0o755 : 0o644)
    } else {
      throw new Error(`release closure: ${relPosix(rootDir, s)} in a dependency is a link or special file`)
    }
  }
}

// -- writing the tree

function walkFiles(dir: string): string[] {
  const out: string[] = []
  const stack = ['']
  while (stack.length > 0) {
    const rel = stack.pop() as string
    const abs = rel === '' ? dir : join(dir, rel)
    const st = lstatSync(abs)
    if (st.isDirectory()) for (const e of readdirSync(abs)) stack.push(rel === '' ? e : `${rel}/${e}`)
    else if (st.isFile()) out.push(rel)
  }
  return out.sort(byBytes)
}

const SAFE_PATH = /^[^\u0000-\u001f\u007f\\]+$/
function writeSums(dir: string): void {
  const files = walkFiles(dir).filter((f) => f !== SUMS)
  for (const f of files) if (!SAFE_PATH.test(f)) throw new Error('a release path holds a control character or a backslash')
  writeFileSync(join(dir, SUMS), files.map((f) => `${sha256(readFileSync(join(dir, f)))}  ./${f}\n`).join(''), { mode: 0o644 })
}

// chmod a-w on every file and directory, deepest first (symlinks keep theirs: they live in read-only directories).
function readOnly(dir: string): void {
  const st = lstatSync(dir)
  if (st.isSymbolicLink()) return
  if (st.isDirectory()) for (const e of readdirSync(dir)) readOnly(join(dir, e))
  chmodSync(dir, st.mode & 0o7555)
}
// Removes a (possibly read-only) tree.
export function removeTree(dir: string): void {
  const make = (p: string): void => {
    let st: ReturnType<typeof lstatSync>
    try { st = lstatSync(p) } catch { return }
    if (!st.isDirectory()) return
    chmodSync(p, 0o700)
    for (const e of readdirSync(p)) make(join(p, e))
  }
  make(dir)
  rmSync(dir, { recursive: true, force: true })
}

// The default web build: vite build of <repo>/web straight into outDir, under sandbox-exec with no network at all and
// file writes only below outDir, under env -i.
export function viteBuild(repo: string, outDir: string, env: Env): void {
  const vite = join(repo, 'web', 'node_modules', 'vite', 'bin', 'vite.js')
  if (!existsSync(vite)) throw new UsageError('vt release build needs the web workspace installed (at the repository root: npx --yes npm@11.21.0 ci --ignore-scripts)')
  mkdirSync(outDir, { recursive: true, mode: 0o755 })
  const out = realpathSync(outDir)
  assertProfilePath(out)
  const profile = `(version 1)(allow default)(deny network-outbound)(deny file-write*)(allow file-write* (subpath "${out}") (literal "/dev/null"))`
  const r = spawnSync('/usr/bin/sandbox-exec', ['-p', profile, '/usr/bin/env', '-i', `PATH=${env.PATH ?? '/usr/bin:/bin'}`, `HOME=${env.HOME ?? ''}`,
    `LANG=${env.LANG ?? 'en_US.UTF-8'}`, 'TERM=dumb', process.execPath, vite, 'build', join(repo, 'web'), '--configLoader', 'native', '--outDir', out,
    '--emptyOutDir', '--logLevel', 'error'], { stdio: ['ignore', 'ignore', 'inherit'], timeout: 600_000 })
  if (r.status !== 0) throw new Error('the web build failed (vite build, sandboxed: no network, writes only into the release)')
  if (!existsSync(join(out, 'index.html'))) throw new Error('the web build wrote no index.html')
}

export interface BuildOptions {
  repo: string
  env: Env
  buildWeb?: (exported: string, outDir: string) => void // tests: a fake page; default viteBuild (both get the export)
}
export interface BuildResult { buildId: string; dir: string; created: boolean; commit: string; report: VerifyReport }

export function build(o: BuildOptions): BuildResult {
  const repo = realpathSync(o.repo)
  const top = git(repo, ['rev-parse', '--show-toplevel'], o.env).toString('utf8').trim()
  if (realpathSync(top) !== repo) throw new UsageError('vt release build runs at the root of the development tree (a git work tree)')
  // 1.
  assertNoHiddenIndexFlags(git(repo, ['ls-files', '-v', '-z'], o.env))
  const dirty = git(repo, ['status', '--porcelain=v1', '-z', '--untracked-files=no'], o.env)
  if (dirty.length > 0) throw new UsageError('vt release build: the development tree has uncommitted changes to tracked files; commit them first (a release is built from a commit)')
  const commit = git(repo, ['rev-parse', '--verify', 'HEAD^{commit}'], o.env).toString('utf8').trim()
  // 2. the commit, from git's objects
  const entries = readCommitTree(repo, commit, o.env)
  const paths = new Set(entries.map((e) => e.path))
  for (const p of REQUIRED) if (!paths.has(p)) throw new UsageError(`vt release build: ${p} is not in this tree (a release needs it)`)
  const buildId = computeBuildId(entries)
  const home = vtHome(o.env)
  ensureDir(home)
  const releases = releasesDir(home)
  ensureDir(releases)
  const dest = join(releases, buildId)
  if (existsSync(dest)) {
    const report = verify(dest)
    assertVerified(report)
    return { buildId, dir: dest, created: false, commit, report }
  }
  const byPath = new Map(entries.map((e) => [e.path, e.bytes]))
  const lockfiles: Record<string, string> = {}
  for (const ins of INSTALLS) {
    const path = ins === '' ? 'package-lock.json' : `${ins}/package-lock.json`
    const bytes = byPath.get(path)
    if (bytes !== undefined) lockfiles[path] = sha256(bytes)
  }
  assertNoLockDrift(INSTALLS.flatMap((ins) => installDrift(repo, ins, byPath.get(ins === '' ? 'package-lock.json' : `${ins}/package-lock.json`))))
  const tag = randomBytes(6).toString('hex')
  const exported = join(releases, `.export-${buildId}-${tag}`)
  const stage = join(releases, `.stage-${buildId}-${tag}`)
  mkdirSync(exported, { mode: 0o700 })
  mkdirSync(stage, { mode: 0o755 })
  try {
    exportTree(entries, exported)
    mirrorNodeModules(repo, exported)
    // the page, built inside the export (first: whatever the working tree does meanwhile, nothing below reads it)
    const web = join(stage, 'web', 'dist')
    if (o.buildWeb !== undefined) {
      mkdirSync(web, { recursive: true, mode: 0o755 })
      o.buildWeb(exported, web)
    } else {
      viteBuild(exported, web, o.env)
    }
    // 3. first-party files: the commit's, of COPY
    for (const e of entries) {
      if (!isReleaseSource(e.path)) continue
      if (e.type === 'l') throw new UsageError(`vt release build: ${shown(e.path)} is a link; a release copies regular files only`)
      mkdirSync(dirname(join(stage, e.path)), { recursive: true, mode: 0o755 })
      writeFileSync(join(stage, e.path), e.bytes, { mode: e.type === 'x' ? 0o755 : 0o644 })
    }
    // 4. the production closure: the commit's manifests, the installed packages
    const closure = productionClosure(exported, [exported, repo])
    for (const [loc, key] of placeClosure(closure)) copyPackage((closure.instances.get(key) as Instance).src, join(stage, loc))
    // 5. the workspace links
    for (const [rel, target] of closure.links) {
      mkdirSync(dirname(join(stage, rel)), { recursive: true, mode: 0o755 })
      symlinkSync(target, join(stage, rel))
    }
    // 6.
    writeFileSync(join(stage, MANIFEST), `${JSON.stringify({ format: RELEASE_FORMAT, buildId, commit, links: Object.fromEntries([...closure.links].sort((a, b) => byBytes(a[0], b[0]))), lockfiles }, null, 2)}\n`, { mode: 0o644 })
    writeSums(stage)
    spawnSync('/bin/chmod', ['-RN', stage], { stdio: 'ignore' }) // no ACL (one inherited from a parent directory, say); verify checks
    readOnly(stage)
    chmodSync(stage, 0o755) // macOS renames a directory only while it is writable; read-only right after the rename
    renameSync(stage, dest)
  } catch (e) {
    removeTree(stage)
    throw e
  } finally {
    removeTree(exported)
  }
  chmodSync(dest, 0o555)
  const report = verify(dest)
  try {
    assertVerified(report)
  } catch (e) {
    removeTree(dest) // it did not exist before this build: nothing that does not verify is left behind
    throw e
  }
  return { buildId, dir: dest, created: true, commit, report }
}

// ---- list

export interface ListedRelease { id: string; commit: string | null; builtAt: number }
export function list(home: string): ListedRelease[] {
  const dir = releasesDir(home)
  let entries: string[]
  try { entries = readdirSync(dir) } catch { return [] }
  const out: ListedRelease[] = []
  for (const id of entries) {
    if (!BUILD_ID.test(id)) continue
    let st: ReturnType<typeof lstatSync>
    try { st = lstatSync(join(dir, id)) } catch { continue }
    if (!st.isDirectory()) continue
    let commit: string | null = null
    try {
      const m = JSON.parse(readFileSync(join(dir, id, MANIFEST), 'utf8')) as { commit?: unknown }
      if (typeof m.commit === 'string' && /^[0-9a-f]{40}$/.test(m.commit)) commit = m.commit
    } catch { /* shown without a commit */ }
    out.push({ id, commit, builtAt: st.mtimeMs })
  }
  return out.sort((a, b) => b.builtAt - a.builtAt || byBytes(a.id, b.id))
}

// ---- `vt release …`

const USAGE = 'usage: vt release build | verify [<id>] | list'
export interface ReleaseCommand { args: readonly string[]; env: Env; repo: string; release: string | null; out?: (l: string) => void; buildWeb?: BuildOptions['buildWeb'] }
export function releaseCommand(o: ReleaseCommand): number {
  const out = o.out ?? ((l: string) => { process.stdout.write(`${l}\n`) })
  const [sub, ...rest] = o.args
  const home = vtHome(o.env)
  if (sub === 'build' && rest.length === 0) {
    if (o.release !== null) throw new UsageError('vt release build runs from the development tree, not from a release')
    const r = build({ repo: o.repo, env: o.env, buildWeb: o.buildWeb })
    out(`vt release build: ${r.created ? 'built' : 'already built (verified)'} ${r.buildId} from commit ${r.commit}`)
    out(`  dir     ${r.dir}`)
    out(`  verify  ${summary(r.report)}; SHA256SUMS sha256 ${r.report.digest ?? ''}`)
    out(`  run it  ${join(r.dir, 'cli', 'bin', 'vt')} --network mainnet up   (mainnet runs only from a verified release)`)
    return 0
  }
  if (sub === 'verify' && rest.length <= 1) {
    const id = rest[0] ?? o.release
    if (id === null || id === undefined) throw new UsageError('vt release verify <id> (from the development tree the id is required; vt release list shows them)')
    if (!BUILD_ID.test(id)) throw new UsageError('a release id is 12 lowercase hex characters (the value is not echoed)')
    const r = verify(join(releasesDir(home), id))
    out(`vt release verify ${id}: ${summary(r)}; SHA256SUMS sha256 ${r.digest ?? 'none'}`)
    for (const p of [...r.testOnly.slice(0, 10), ...r.problems]) out(`  ${shown(p)}`)
    assertVerified(r)
    out(`vt release verify ${id}: ok`)
    return 0
  }
  if (sub === 'list' && rest.length === 0) {
    const all = list(home)
    if (all.length === 0) out(`vt release list: no release in ${releasesDir(home)} (vt release build)`)
    for (const r of all) out(`${r.id}  commit ${r.commit ?? 'unknown'}  built ${new Date(r.builtAt).toISOString()}${r.id === o.release ? '  (this one)' : ''}`)
    if (all.length > 0) out('vt release verify <id> checks one (vt up --network mainnet verifies it every time)')
    return 0
  }
  throw new UsageError(USAGE)
}

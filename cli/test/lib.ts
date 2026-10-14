// cli/test/lib.ts — shared helpers for the cli tests (not a test file itself).
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { connect } from 'node:net'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

export const CLI = realpathSync(fileURLToPath(new URL('../', import.meta.url)))
export const WRAPPER = join(CLI, 'bin', 'vt')
export const MAIN = join(CLI, 'src', 'main.ts')
export const STUB = join(CLI, 'test', 'fixtures', 'sealer-stub.sh')
export const PATH0 = process.env.PATH ?? '/usr/bin:/bin'
export const NODE = process.execPath
// The canary (Global Constraints): it must never appear in any output.
export const CANARY = '203.0.113.77'
export const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/
// Names macOS CoreFoundation synthesises in a child's environment (not passed by the wrapper).
export const SYNTHESISED = ['__CF_USER_TEXT_ENCODING']

export function tempDir(prefix: string): string {
  const d = realpathSync(mkdtempSync(join(tmpdir(), prefix)))
  assert.ok(!/['\s]/.test(d + NODE), 'temp and node paths are safe to single-quote')
  return d
}
export function removeDir(d: string): void {
  if (d !== '') rmSync(d, { recursive: true, force: true })
}
export function writeExe(path: string, text: string): void {
  writeFileSync(path, text)
  chmodSync(path, 0o755)
}

export interface Run { code: number | null; out: string; err: string }
export interface RunOpts { env?: Record<string, string | undefined>; input?: string; cwd?: string; file?: string }

// Runs `file` (default: cli/bin/vt) with EXACTLY the given environment (nothing inherited).
export function run(args: readonly string[], o: RunOpts = {}): Run {
  const env: Record<string, string> = {}
  for (const [k, v] of Object.entries(o.env ?? {})) if (v !== undefined) env[k] = v
  const r = spawnSync(o.file ?? WRAPPER, [...args], { env, input: o.input ?? '', encoding: 'utf8', timeout: 60_000, cwd: o.cwd })
  if (r.error !== undefined) throw r.error
  return { code: r.status, out: r.stdout, err: r.stderr }
}

// node src/main.ts directly (no wrapper; o.file: another main.ts, e.g. a sealer-free copy's), with exactly `env`.
export function runMain(args: readonly string[], o: RunOpts = {}): Run {
  const env: Record<string, string> = {}
  for (const [k, v] of Object.entries(o.env ?? {})) if (v !== undefined) env[k] = v
  const r = spawnSync(NODE, [o.file ?? MAIN, ...args], { env, input: o.input ?? '', encoding: 'utf8', timeout: 60_000, cwd: o.cwd })
  if (r.error !== undefined) throw r.error
  return { code: r.status, out: r.stdout, err: r.stderr }
}

// A refusal: exit 2, `refused <id>: ` on stderr, nothing on stdout.
export function refused(r: Run, id: string): void {
  assert.equal(r.code, 2, `exit code for ${id}: ${r.err}`)
  assert.match(r.err, new RegExp(`^refused ${id.replaceAll('.', '\\.')}: `, 'm'), r.err)
  assert.equal(r.out, '', 'nothing ran after a refusal')
}

// ★ A precondition of every test that lets a real `vt up --network testnet|mainnet` run (C6 incident: release.test.ts
//   run outside the suite sandbox reached the system Tor and started a session on vt's tmux server): 127.0.0.1:9050
//   must be DENIED here (EPERM: the suite sandbox, or the mutation runner's). Anything else fails the test BEFORE that
//   `vt up` runs. The probe is one TCP connect to loopback, closed at once (no byte is sent).
export function assertTorDenied(): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const s = connect({ host: '127.0.0.1', port: 9050 })
    const done = (code: string | undefined): void => {
      s.destroy()
      if (code === 'EPERM') resolve()
      else reject(new assert.AssertionError({ message: 'run this file only through scripts/test-root.sh (or the mutation runner): 127.0.0.1:9050 is not denied here, so its real testnet/mainnet `vt up` would reach the system Tor; it was not run' }))
    }
    s.once('connect', () => done('connected'))
    s.once('error', (e: NodeJS.ErrnoException) => done(e.code))
  })
}

// The refusal thrown by fn (sync or async) carries this guard id.
export async function rejectsWith(fn: () => unknown, id: string): Promise<void> {
  await assert.rejects(async () => { await fn() }, (e: unknown) => {
    assert.equal((e as { guardId?: unknown }).guardId, id, String(e))
    return true
  })
}
export function throwsWith(fn: () => unknown, id: string): void {
  assert.throws(fn, (e: unknown) => {
    assert.equal((e as { guardId?: unknown }).guardId, id, String(e))
    return true
  })
}

// ★★ A copy of this cli workspace at <tmp>/repo/cli, for every test that drives `vt seal|open` through bin/vt or
//   src/main.ts (C1 review I1). main.ts takes the repository root from its own location, so in the copy REPO is
//   <tmp>/repo, which holds no 1password-timelock.sh and no timelock-key.sh: whatever regresses (an empty VT_SEALER
//   dropped, VT_SEALER lost on the way), the real sealers are unreachable from a test by construction. The stub is
//   the copy's own test/fixtures/sealer-stub.sh. node_modules is a link to this workspace's (as the mutation runner
//   does), never written.
export interface SealerFreeCopy { root: string; repo: string; cli: string; wrapper: string; main: string; stub: string }
export function sealerFreeCopy(): SealerFreeCopy {
  const root = tempDir('vt-sealer-free-')
  const repo = join(root, 'repo')
  const cli = join(repo, 'cli')
  mkdirSync(join(cli, 'test'), { recursive: true })
  for (const d of ['bin', 'src', join('test', 'fixtures'), 'package.json']) cpSync(join(CLI, d), join(cli, d), { recursive: true, verbatimSymlinks: true })
  symlinkSync(join(CLI, 'node_modules'), join(cli, 'node_modules'))
  for (const s of ['1password-timelock.sh', 'timelock-key.sh']) assert.ok(!existsSync(join(repo, s)), `the copy's repository root holds no ${s}`)
  const c = { root, repo, cli, wrapper: join(cli, 'bin', 'vt'), main: join(cli, 'src', 'main.ts'), stub: join(cli, 'test', 'fixtures', 'sealer-stub.sh') }
  for (const f of [c.wrapper, c.stub]) assert.ok(existsSync(f), f)
  return c
}

// What the stub reported on stderr: its arguments, its environment names (minus the ones its own sh adds) and the
// TMPDIR / TOR_SOCKS values. null when the stub did not run.
export const SH_ADDED = ['PWD', 'SHLVL', 'OLDPWD', '_', ...SYNTHESISED]
export interface StubReport { args: string[]; names: string[]; tmpdir: string; torSocks: string }
export function stubReport(stderr: string): StubReport | null {
  const lines = stderr.split('\n')
  const at = lines.findIndex((l) => l.startsWith('sealer-stub: argc='))
  if (at < 0) return null
  const argc = Number(lines[at].slice('sealer-stub: argc='.length))
  const args = lines.slice(at + 1, at + 1 + argc).map((l) => {
    assert.ok(l.startsWith('sealer-stub: arg=[') && l.endsWith(']'), l)
    return l.slice('sealer-stub: arg=['.length, -1)
  })
  const envLine = lines[at + 1 + argc]
  assert.ok(envLine.startsWith('sealer-stub: env='), envLine)
  const names = envLine.slice('sealer-stub: env='.length).split(' ').filter((n) => n !== '' && !SH_ADDED.includes(n)).sort()
  const m = /^sealer-stub: TMPDIR=\[(.*)\] TOR_SOCKS=\[(.*)\]$/.exec(lines[at + 2 + argc])
  assert.ok(m !== null, lines[at + 2 + argc])
  return { args, names, tmpdir: m[1], torSocks: m[2] }
}

// ---- C3: the fake tmux (test/fakes/tmux.sh) and a fake `open` (Chrome), first on PATH

export const FAKES = join(CLI, 'test', 'fakes')

// NUL-separated records: an argument count, then that many arguments (the fakes' call logs).
export function nulRecords(path: string): string[][] {
  if (!existsSync(path)) return []
  const toks = readFileSync(path, 'utf8').split('\0')
  toks.pop()
  const out: string[][] = []
  for (let i = 0; i < toks.length;) {
    const n = Number(toks[i])
    assert.ok(Number.isInteger(n) && n >= 0, 'a well-formed call record')
    out.push(toks.slice(i + 1, i + 1 + n))
    i += 1 + n
  }
  return out
}

export interface FakeTmux {
  bin: string            // put first on PATH: holds `tmux` and `open`
  state: string
  calls(): string[][]    // every tmux invocation
  opens(): string[][]    // every `open` invocation
  mode(window: string, m: 'ready' | 'mq' | 'other' | 'silent' | 'exit'): void
  fail(cmd: string): void
  reset(): void
}
export function fakeTmux(root: string): FakeTmux {
  const bin = join(root, 'fakebin')
  const state = join(root, 'tmux-state')
  const opens = join(root, 'open-calls')
  mkdirSync(bin, { recursive: true })
  writeExe(join(bin, 'tmux'), `#!/bin/sh\nFAKE_TMUX_STATE='${state}'; export FAKE_TMUX_STATE\nexec /bin/sh '${join(FAKES, 'tmux.sh')}' "$@"\n`)
  writeExe(join(bin, 'open'), `#!/bin/sh\nprintf '%s\\0' "$#" "$@" >> '${opens}'\nexit 0\n`)
  const reset = (): void => {
    rmSync(state, { recursive: true, force: true })
    rmSync(opens, { force: true })
    mkdirSync(state, { recursive: true })
  }
  reset()
  return {
    bin, state, reset,
    calls: () => nulRecords(join(state, 'calls')),
    opens: () => nulRecords(opens),
    mode: (w, m) => writeFileSync(join(state, `mode-${w}`), m),
    fail: (cmd) => writeFileSync(join(state, `fail-${cmd}`), ''),
  }
}

// The window script of src/ops/stack.ts, restated (a change there must be deliberate).
export const WINDOW_SCRIPT = 'log=$1; shift; { "$@" 2>&1; echo "vt: exited with status $?"; } | /usr/bin/tee -a "$log"; exec /bin/sleep 2147483647'

// The node a PATH resolves to (bin/vt runs `node` from PATH; vt up puts that binary's path into every window).
export function nodeOn(path: string): string {
  const r = spawnSync('node', ['-p', 'process.execPath'], { env: { PATH: path }, encoding: 'utf8' })
  assert.equal(r.status, 0, r.stderr)
  return r.stdout.trim()
}

// A synthetic age file: the header line, then made-up bytes (never a real backup).
export function synthAge(extra = 'synthetic-not-a-real-backup'): Buffer {
  return Buffer.concat([Buffer.from('age-encryption.org/v1\n-> scrypt c3RhbmRpbg 18\nc3ludGhldGlj\n--- c3ludGg\n'), Buffer.from(extra), Buffer.from([0, 1, 2, 255])])
}

// vt-broadcast's runInPty (test/offline/lifecycle/pty.ts: `cat | script -q /dev/null <argv>`, its own process group),
// with the output seen AS IT ARRIVES: after each chunk, on(out, type) gets the whole output so far, and type() writes to
// the terminal. For a test that must act on a running command from outside (a signal to its recorded pid).
export function ptyLive(argv: readonly string[], o: { env: Record<string, string>; timeoutMs?: number; on: (out: string, type: (s: string) => void) => void }): Promise<{ out: string; code: number | null }> {
  const SH = 'cat | { script -q /dev/null "$@"; echo "@@pty-exit $?"; }'
  const EXIT = /@@pty-exit (\d+)\r?\n/
  return new Promise((resolve, reject) => {
    const c = spawn('/bin/sh', ['-c', SH, 'sh', ...argv], { env: o.env, stdio: ['pipe', 'pipe', 'pipe'], detached: true })
    let out = '', code: number | null = null, timedOut = false, failed: unknown = null
    const timer = setTimeout(() => { timedOut = true; try { process.kill(-c.pid!, 'SIGKILL') } catch { /* gone */ } }, o.timeoutMs ?? 60_000)
    const type = (t: string): void => { if (code === null) c.stdin.write(t) }
    const seen = (): void => {
      const m = code === null ? EXIT.exec(out) : null
      if (m !== null) { code = Number(m[1]); c.stdin.end(); return }
      if (code === null && failed === null) { try { o.on(out, type) } catch (e) { failed = e } }
    }
    c.stdin.on('error', () => { /* the command ended first */ })
    c.stdout.on('data', (d: Buffer) => { out += d.toString('latin1'); seen() })
    c.stderr.on('data', (d: Buffer) => { out += d.toString('latin1') })
    c.on('error', (e) => { clearTimeout(timer); reject(e) })
    c.on('close', () => {
      clearTimeout(timer)
      if (failed !== null) reject(failed)
      else if (timedOut) reject(new Error('pty run timed out'))
      else resolve({ out: out.replace(EXIT, ''), code })
    })
  })
}

// One TCP connect to 127.0.0.1:<port>, closed at once (no byte sent): 'connected' or the errno code.
export function connectOutcome(port: number): Promise<string> {
  return new Promise((resolve) => {
    const s = connect({ host: '127.0.0.1', port })
    s.once('connect', () => { s.destroy(); resolve('connected') })
    s.once('error', (e: NodeJS.ErrnoException) => { s.destroy(); resolve(e.code ?? 'error') })
  })
}

// A launcher whose ONLY difference from cli/bin/vt is that sandbox-exec is looked up on PATH (the real one is /usr/bin/sandbox-exec by absolute path, M-1), for the
// tests that put a FAKE sandbox-exec first on PATH (a recorder, a tripwire, one that drops the profile). It lives in <dir>/cli/bin/vt next to symlinks to the real
// src, package.json and node_modules, so main.ts, profile.ts and broker.ts are the real ones.
export function fakeableWrapper(dir: string): string {
  const bin = join(dir, 'cli', 'bin')
  mkdirSync(bin, { recursive: true })
  for (const n of ['src', 'package.json', 'node_modules']) if (!existsSync(join(dir, 'cli', n))) symlinkSync(join(CLI, n), join(dir, 'cli', n))
  const text = readFileSync(WRAPPER, 'utf8').replace('[ -x /usr/bin/sandbox-exec ]', 'command -v sandbox-exec >/dev/null 2>&1').replaceAll('/usr/bin/sandbox-exec', 'sandbox-exec')
  assert.ok(text.includes('sandbox-exec'), 'the launcher names sandbox-exec')
  writeFileSync(join(bin, 'vt'), text)
  chmodSync(join(bin, 'vt'), 0o755)
  return join(bin, 'vt')
}

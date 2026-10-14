// cli/test/up-real.test.ts — `vt up` / `vt down` for real (plan Task C3): the real tmux, the real sandbox-exec and the
// real window script, plus S1's real API under the profile vt builds.
// This file applies sandboxes (sandbox-exec) and talks to a tmux server over a unix socket, so it runs OUTSIDE the
// suite sandbox (test/own-sandbox.list; scripts/test-root.sh phase B).
// ★ Never the operator's tmux: a private server (`tmux -L vt-c3-<pid>-<rand>`) whose socket lives in a private
//   TMUX_TMPDIR under /tmp, killed and removed afterwards. Never a fixed stack port: the servers here are fakes that
//   print readiness lines without listening, and S1's API listens on an ephemeral port (`--port 0`, NODE_ENV=test).
// ★ No packet leaves the machine: every probe is a loopback connect inside a profile that denies it (EPERM), and S1's
//   own confinement proof only meets denying profiles (EPERM before any packet).
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { down } from '../src/ops/down.ts'
import { apiProfile } from '../src/ops/sandbox.ts'
import { stackWindows, writeSecretFile } from '../src/ops/stack.ts'
import { hasSession, systemTmux } from '../src/ops/tmux.ts'
import { up } from '../src/ops/up.ts'
import { CLI, NODE, PATH0, removeDir, tempDir } from './lib.ts'

const REPO = dirname(CLI)
let T = ''
let TM = ''   // TMUX_TMPDIR of the private tmux server
let SOCK = ''
let HOME0 = ''
const OUT = () => join(T, 'out')
const REAL = () => join(T, 'real-home')
const LINK = () => join(T, 'link-home')
const FAKE_REPO = () => join(T, 'repo')
const tmuxEnv = () => ({ PATH: PATH0, HOME: HOME0, TERM: 'xterm', LANG: 'C', TMUX_TMPDIR: TM })
const tmux = () => systemTmux({ socket: SOCK, env: tmuxEnv() })
const vtEnv = () => ({ PATH: PATH0, HOME: HOME0, LANG: 'C', TERM: 'xterm', VT_HOME: LINK(), VAULT_TIMELOCK_DIR: OUT() })

// A fake server: probes its own sandbox, prints the results and its readiness line, then stays up (or, with the
// mode file saying `exit`, refuses and exits 2 before any readiness line).
function fakeServer(role: 'relay' | 'api' | 'page'): string {
  const ready = {
    relay: '`vt-relay ready network=${n} port=5181`',
    api: '`vt-api ready network=${n} port=5182 build=${get(\'--build\')}`',
    page: '`vt-page ready network=${n} port=5180`',
  }[role]
  return `import { connect } from 'node:net'
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
const args = process.argv.slice(2)
const get = (k) => { const i = args.indexOf(k); return i < 0 ? null : args[i + 1] }
const n = get('--network'), home = get('--home')
const tcp = (port) => new Promise((res) => {
  const s = connect({ host: '127.0.0.1', port })
  const t = setTimeout(() => { s.destroy(); res('timeout') }, 3000)
  s.on('connect', () => { clearTimeout(t); s.destroy(); res('connected') })
  s.on('error', (e) => { clearTimeout(t); res(e.code || 'error') })
})
const write = (p) => { try { writeFileSync(p, 'x'); rmSync(p, { force: true }); return 'ok' } catch (e) { return e.code || 'error' } }
const modeFile = ${JSON.stringify(join(T, `fake-mode-${role}`))}
if (existsSync(modeFile) && readFileSync(modeFile, 'utf8') === 'exit') { console.log('refused api.not-confined: a synthetic failure'); process.exit(2) }
const loop9 = await tcp(9)
const env = Object.keys(process.env).filter((k) => k !== '__CF_USER_TEXT_ENCODING').sort().join(',')
const out = process.env.VAULT_TIMELOCK_DIR
let outRead = 'error'
try { outRead = readFileSync(join(out, 'lifecycle', 'latch'), 'utf8') === 'synthetic' ? 'ok' : 'wrong' } catch (e) { outRead = e.code || 'error' }
console.log('probe ${role} pid=' + process.pid + ' loop9=' + loop9 + ' inState=' + write(join(home, n, 'probe-${role}')) + ' outside=' + write(join(home, 'probe-${role}'))
  + ' outRead=' + outRead + ' outWrite=' + write(join(out, 'probe-${role}')) + ' out=' + (out === ${JSON.stringify(join(T, 'out'))} ? 'resolved' : 'other') + ' env=' + env)
console.log(${ready})
setInterval(() => {}, 1 << 30)
`
}

before(() => {
  T = tempDir('vt-up-real-')
  TM = realpathSync(mkdtempSync('/tmp/vt-c3-tm-'))
  SOCK = `vt-c3-${process.pid}-${randomBytes(4).toString('hex')}`
  HOME0 = join(T, 'home')
  mkdirSync(HOME0, { mode: 0o700 })
  mkdirSync(REAL(), { mode: 0o700 })
  symlinkSync(REAL(), LINK())
  mkdirSync(join(FAKE_REPO(), 'api', 'relay'), { recursive: true })
  mkdirSync(join(FAKE_REPO(), 'api', 'src'), { recursive: true })
  mkdirSync(join(FAKE_REPO(), 'api', 'serve'), { recursive: true })
  writeFileSync(join(FAKE_REPO(), 'package.json'), '{ "type": "module" }\n')
  writeFileSync(join(FAKE_REPO(), 'api', 'relay', 'relay.mjs'), fakeServer('relay'))
  writeFileSync(join(FAKE_REPO(), 'api', 'src', 'main.ts'), fakeServer('api'))
  writeFileSync(join(FAKE_REPO(), 'api', 'serve', 'serve.mjs'), fakeServer('page'))
  mkdirSync(join(OUT(), 'lifecycle'), { recursive: true, mode: 0o700 })
  writeFileSync(join(OUT(), 'lifecycle', 'latch'), 'synthetic') // a made-up latch file, only ever read
})
after(() => {
  spawnSync('tmux', ['-L', SOCK, 'kill-server'], { env: tmuxEnv(), stdio: 'ignore', timeout: 15_000 })
  removeDir(TM)
  removeDir(T)
})

const isAlive = (pid: number): boolean => { try { process.kill(pid, 0); return true } catch { return false } }
async function gone(pids: number[]): Promise<boolean> {
  for (let i = 0; i < 100; i++) {
    if (!pids.some(isAlive)) return true
    await new Promise((r) => setTimeout(r, 50))
  }
  return false
}

test('real tmux + real sandbox-exec: vt up starts relay, api and page confined, logs through tee, writes up.json; vt down stops them all', async () => {
  const lines: string[] = []
  const code = await up({ network: 'local', open: false, dev: false, env: vtEnv(), repo: FAKE_REPO(), release: null, node: NODE },
    { tmux: tmux(), out: (l) => lines.push(l), err: (l) => lines.push(l), readyTimeoutMs: 30_000, pollMs: 50 })
  assert.equal(code, 0, lines.join('\n'))
  assert.ok(hasSession(tmux(), 'vt-local'))
  const state = join(REAL(), 'local')
  assert.deepEqual(Object.keys(JSON.parse(readFileSync(join(state, 'up.json'), 'utf8'))), ['network', 'pagePort', 'build', 'startedAt'])

  const probes: Record<string, Record<string, string>> = {}
  for (const role of ['relay', 'api', 'page']) {
    const log = readFileSync(join(state, 'logs', `${role}.log`), 'utf8')
    const m = new RegExp(`^probe ${role} (.*)$`, 'm').exec(log)
    assert.ok(m !== null, `${role}.log: ${log}`)
    probes[role] = Object.fromEntries(m[1].split(' ').map((kv) => kv.split('=') as [string, string]))
  }
  // Every server: env -i (exactly these names), loopback 9 denied.
  for (const role of ['relay', 'api', 'page']) {
    assert.equal(probes[role].env, 'HOME,LANG,PATH,TERM,VAULT_TIMELOCK_DIR,VT_HOME', role)
    assert.equal(probes[role].loop9, 'EPERM', role)
  }
  // The API writes below its state dir only (through the REAL path, C1 review M2), the page writes nothing, the relay's
  // profile restricts only the network (spec §3.1).
  assert.deepEqual([probes.api.inState, probes.api.outside], ['ok', 'EPERM'])
  assert.deepEqual([probes.page.inState, probes.page.outside], ['EPERM', 'EPERM'])
  assert.deepEqual([probes.relay.inState, probes.relay.outside], ['ok', 'ok'])
  // $OUT (VAULT_TIMELOCK_DIR, the resolved real path): the API reads it and cannot write it (the controller's S2 note).
  for (const role of ['relay', 'api', 'page']) assert.deepEqual([probes[role].out, probes[role].outRead], ['resolved', 'ok'], role)
  assert.deepEqual([probes.api.outWrite, probes.page.outWrite], ['EPERM', 'EPERM'])

  const pids = Object.values(probes).map((p) => Number(p.pid))
  assert.ok(pids.every(isAlive), 'the servers run after vt up returned')
  const out: string[] = []
  assert.equal(down({ network: 'local', env: vtEnv() }, { tmux: tmux(), out: (l) => out.push(l), err: (l) => out.push(l) }), 0)
  assert.deepEqual(out, ['vt down: stopped vt-local'])
  assert.ok(!hasSession(tmux(), 'vt-local'))
  assert.ok(!existsSync(join(state, 'up.json')))
  assert.ok(await gone(pids), 'every server process ended with its session')
})

// A tmux query on a private server (no -f: the server is running already, so no config is read by this call).
function tmuxQuery(sock: string, home: string, args: readonly string[]): string[] {
  const r = spawnSync('tmux', ['-L', sock, ...args], { env: { ...tmuxEnv(), HOME: home }, encoding: 'utf8', timeout: 15_000 })
  assert.equal(r.status, 0, `tmux ${args.join(' ')}: ${r.stderr}`)
  return r.stdout.split('\n').filter((l) => l !== '')
}

test('I3: vt\'s tmux server never loads a tmux config (-f /dev/null): under a HOME whose config adds a session-created hook, an autosave window and resurrect/continuum options, a fresh vt server has none of them', async () => {
  const hostile = join(T, 'hostile-home')
  mkdirSync(join(hostile, '.config', 'tmux'), { recursive: true, mode: 0o700 })
  // Synthetic, harmless: the hook only opens a window running sleep; the options name a directory that never exists.
  const conf = [
    `set-hook -g session-created 'new-window -d -n autosave "sleep 600"'`,
    `set -g @resurrect-dir '${join(T, 'resurrect-never')}'`,
    `set -g @continuum-save-interval '15'`,
    `set -g @continuum-restore 'on'`,
    '',
  ].join('\n')
  writeFileSync(join(hostile, '.tmux.conf'), conf)
  writeFileSync(join(hostile, '.config', 'tmux', 'tmux.conf'), conf)
  const env = { ...tmuxEnv(), HOME: hostile }
  // Negative control: a server started WITHOUT -f loads it (so the checks below can see it).
  const ctl = `${SOCK}-ctl`
  try {
    const r = spawnSync('tmux', ['-L', ctl, 'new-session', '-d', '-s', 'probe', '--', 'sleep', '600'], { env, encoding: 'utf8', timeout: 15_000 })
    assert.equal(r.status, 0, r.stderr)
    for (let i = 0; i < 100 && !tmuxQuery(ctl, hostile, ['list-windows', '-a', '-F', '#{window_name}']).includes('autosave'); i++) await new Promise((x) => setTimeout(x, 20))
    assert.ok(tmuxQuery(ctl, hostile, ['list-windows', '-a', '-F', '#{window_name}']).includes('autosave'), 'the control ran the hook: an autosave window')
    assert.ok(tmuxQuery(ctl, hostile, ['show-hooks', '-g']).some((l) => /^session-created\[\d+\] /.test(l)), 'the control loaded the hook')
    assert.ok(tmuxQuery(ctl, hostile, ['show-options', '-g']).some((l) => l.startsWith('@resurrect-dir ')), 'the control loaded the options')
  } finally {
    spawnSync('tmux', ['-L', ctl, 'kill-server'], { env, stdio: 'ignore', timeout: 15_000 })
  }
  // vt: a fresh server on another private socket, started by vt up through systemTmux, with the same HOME.
  const sock = `${SOCK}-cfg`
  const t = systemTmux({ socket: sock, env })
  try {
    const lines: string[] = []
    const code = await up({ network: 'local', open: false, dev: false, env: vtEnv(), repo: FAKE_REPO(), release: null, node: NODE },
      { tmux: t, out: (l) => lines.push(l), err: (l) => lines.push(l), readyTimeoutMs: 30_000, pollMs: 50 })
    assert.equal(code, 0, lines.join('\n'))
    await new Promise((x) => setTimeout(x, 300)) // a session-created hook would have run by now (the control's did)
    const hooks = tmuxQuery(sock, hostile, ['show-hooks', '-g'])
    assert.ok(hooks.length > 0 && hooks.every((l) => /^[a-z-]+$/.test(l)), `no hook has a command: ${hooks.filter((l) => !/^[a-z-]+$/.test(l)).join(' | ')}`)
    assert.deepEqual(tmuxQuery(sock, hostile, ['list-windows', '-a', '-F', '#{session_name}:#{window_name}']), ['vt-local:relay', 'vt-local:api', 'vt-local:page'])
    assert.deepEqual(tmuxQuery(sock, hostile, ['show-options', '-g']).filter((l) => l.startsWith('@')), [], 'no @resurrect / @continuum (no user option at all)')
    assert.deepEqual(tmuxQuery(sock, hostile, ['list-sessions', '-F', '#{session_name}']), ['vt-local'])
    assert.equal(down({ network: 'local', env: vtEnv() }, { tmux: t, out: () => {}, err: () => {} }), 0)
  } finally {
    spawnSync('tmux', ['-L', sock, 'kill-server'], { env, stdio: 'ignore', timeout: 15_000 })
  }
})

test('real tmux: a server that exits before its readiness line -> exit 1 naming the window; the session is gone', async () => {
  writeFileSync(join(T, 'fake-mode-api'), 'exit')
  try {
    const lines: string[] = []
    const code = await up({ network: 'local', open: false, dev: false, env: vtEnv(), repo: FAKE_REPO(), release: null, node: NODE },
      { tmux: tmux(), out: (l) => lines.push(l), err: (l) => lines.push(l), readyTimeoutMs: 30_000, pollMs: 50 })
    assert.equal(code, 1)
    assert.deepEqual(lines, ['vt up: the api window exited (status 2) before its readiness line; vt-local was stopped. Its log: vt logs api --network local'])
    assert.ok(!hasSession(tmux(), 'vt-local'))
    const log = readFileSync(join(REAL(), 'local', 'logs', 'api.log'), 'utf8')
    assert.match(log, /^refused api\.not-confined: a synthetic failure$/m)
    assert.match(log, /^vt: exited with status 2$/m, 'the window script appended the exit marker')
  } finally {
    removeDir(join(T, 'fake-mode-api'))
  }
})

// Runs argv until `ready` matches its stdout, it exits, or 30 s pass. Then SIGTERM.
function runUntil(argv: readonly string[], ready: RegExp): Promise<{ line: string | null; code: number | null; err: string }> {
  return new Promise((resolve) => {
    const p = spawn(argv[0], argv.slice(1), { env: {}, stdio: ['ignore', 'pipe', 'pipe'] })
    let out = ''
    let err = ''
    let line: string | null = null
    const timer = setTimeout(() => p.kill('SIGTERM'), 30_000)
    p.stdout.on('data', (d: Buffer) => {
      out += d.toString('utf8')
      const m = ready.exec(out)
      if (m !== null && line === null) { line = m[0]; p.kill('SIGTERM') }
    })
    p.stderr.on('data', (d: Buffer) => { err += d.toString('utf8') })
    p.on('close', (code) => { clearTimeout(timer); resolve({ line, code, err }) })
  })
}

test('C1 review M2 + the token files: S1\'s REAL API starts under vt\'s API window command (real-path profile) with the files vt wrote; a profile from the link path denies its writes', async () => {
  const home = join(T, 'm2-real')
  const link = join(T, 'm2-link')
  mkdirSync(join(home, 'local'), { recursive: true, mode: 0o700 })
  symlinkSync(home, link)
  writeSecretFile(join(home, 'local'), 'api.token')
  writeSecretFile(join(home, 'local'), 'relay-ticket.key')
  const [, api] = stackWindows({ network: 'local', homeReal: realpathSync(link), outReal: OUT(), repo: REPO, node: NODE, build: 'dev', chainPorts: [], viteCache: null,
    env: { PATH: PATH0, HOME: HOME0, VAULT_TIMELOCK_DIR: OUT() } })
  assert.equal(api.name, 'api')
  // Tests only: NODE_ENV=test and --port 0 (S1 accepts --port 0 only then), so the fixed API port is never bound.
  const argv = [...api.argv]
  argv.splice(argv.indexOf('-i') + 1, 0, 'NODE_ENV=test')
  argv.push('--port', '0')
  assert.equal(argv[2], apiProfile(join(home, 'local'), OUT()))
  const good = await runUntil(argv, /^vt-api ready network=local port=(\d+) build=dev$/m)
  assert.notEqual(good.line, null, `the API did not start: ${good.err}`)
  assert.equal(good.code, 0, 'SIGTERM: a clean exit')
  // Before the fix: the same command with the profile (and --home) through the link. Every write is denied, so the
  // API cannot even take its lock.
  const bad = argv.map((a) => (a === argv[2] ? apiProfile(join(link, 'local'), OUT()) : a === home ? link : a))
  assert.ok(bad.includes(link) && bad[2].includes(join(link, 'local')))
  const r = await runUntil(bad, /^vt-api ready/m)
  assert.equal(r.line, null)
  assert.notEqual(r.code, 0)
  assert.match(r.err, /EPERM/, 'denied by the sandbox')
})

test('apiProfile: $OUT stays read only for the API even when it lies inside the state dir (the deny comes last)', () => {
  const state = join(T, 'ro-home', 'local')
  const out = join(state, 'out')
  mkdirSync(join(out, 'lifecycle'), { recursive: true, mode: 0o700 })
  writeFileSync(join(out, 'lifecycle', 'latch'), 'synthetic')
  const probe = `const fs = require('node:fs'), path = require('node:path'), r = {}
for (const [k, p] of [['state', ${JSON.stringify(join(state, 'x'))}], ['out', ${JSON.stringify(join(out, 'y'))}], ['outNested', ${JSON.stringify(join(out, 'lifecycle', 'z'))}]]) {
  try { fs.writeFileSync(p, 'x'); r[k] = 'ok' } catch (e) { r[k] = e.code }
}
try { r.read = fs.readFileSync(${JSON.stringify(join(out, 'lifecycle', 'latch'))}, 'utf8') } catch (e) { r.read = e.code }
process.stdout.write(JSON.stringify(r))`
  const r = spawnSync('/usr/bin/sandbox-exec', ['-p', apiProfile(state, out), NODE, '-e', probe], { env: {}, encoding: 'utf8', timeout: 30_000 })
  assert.equal(r.status, 0, r.stderr)
  assert.deepEqual(JSON.parse(r.stdout), { state: 'ok', out: 'EPERM', outNested: 'EPERM', read: 'synthetic' })
})

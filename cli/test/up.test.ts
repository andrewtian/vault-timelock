// cli/test/up.test.ts — `vt up` (src/ops/up.ts, stack.ts, tmux.ts; plan Task C3), in the suite sandbox (phase A).
// Never a real tmux server and never a real stack: tmux is test/fakes/tmux.sh first on PATH (through bin/vt), whose
// "servers" are test/fakes/node-ready.sh; Chrome is a fake `open`. Tor is never reached: inside the suite sandbox
// 127.0.0.1:9050 is denied (EPERM), and in-process tests give their own SOCKS listener on an ephemeral port.
// The real chain (real tmux on a private socket, real sandbox-exec, real S1 API) is test/up-real.test.ts (phase B).
import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { createServer, type Server, type Socket } from 'node:net'
import { dirname, join } from 'node:path'
import { PORTS } from '@vault-timelock/core/contracts'
import { loadConfig, loopbackPorts } from 'vt-broadcast/src/config.ts'
import { apiProfile, loopbackProfile, relayProfile, viteProfile } from '../src/ops/sandbox.ts'
import { readyPatterns, relayArgs, scanLog, stackWindows } from '../src/ops/stack.ts'
import { systemTmux } from '../src/ops/tmux.ts'
import { assertTor, chromeArgs, parseUpArgs, readyTimeoutFor, socksAnswers, up } from '../src/ops/up.ts'
import type { UpDeps } from '../src/ops/up.ts'
import { CANARY, CLI, IPV4, PATH0, WINDOW_SCRIPT, assertTorDenied, fakeTmux, nodeOn, refused, rejectsWith, removeDir, run, tempDir, throwsWith } from './lib.ts'
import type { FakeTmux, Run } from './lib.ts'

const REPO = dirname(CLI)
let T = ''
let HOME0 = ''
let F: FakeTmux
let NODE_BIN = ''
let CHAIN_PORTS: number[] = []
const servers: Server[] = []
const sockets = new Set<Socket>()
const VTH = () => join(T, 'vt-home')
const OUT = () => join(T, 'out')
const envOf = (extra: Record<string, string> = {}): Record<string, string> =>
  ({ PATH: `${F.bin}:${PATH0}`, HOME: HOME0, LANG: 'C', TERM: 'xterm', VT_HOME: VTH(), VAULT_TIMELOCK_DIR: OUT(), ...extra })
const vt = (args: string[], extra: Record<string, string> = {}): Run => run(args, { env: envOf(extra) })
const mode = (p: string) => statSync(p).mode & 0o777

before(() => {
  T = tempDir('vt-up-')
  HOME0 = join(T, 'home')
  mkdirSync(HOME0, { mode: 0o700 })
  F = fakeTmux(T)
  NODE_BIN = nodeOn(`${F.bin}:${PATH0}`)
  CHAIN_PORTS = loopbackPorts(loadConfig('local', {}))
})
after(async () => {
  for (const c of sockets) c.destroy()
  for (const s of servers) await new Promise<void>((res) => s.close(() => res()))
  removeDir(T)
})
beforeEach(() => {
  F.reset()
  removeDir(VTH())
})

// The window command vt up must give tmux, built here from the profiles' own functions and literal paths.
function windowArgv(home: string, n: string, name: string, profile: string, script: string, args: string[], extraEnv: string[] = []): string[] {
  return ['/bin/sh', '-c', WINDOW_SCRIPT, `vt-${name}`, join(home, n, 'logs', `${name}.log`),
    '/usr/bin/sandbox-exec', '-p', profile, '/usr/bin/env', '-i',
    `PATH=${F.bin}:${PATH0}`, `HOME=${HOME0}`, 'LANG=C', 'TERM=xterm', `VT_HOME=${home}`, `VAULT_TIMELOCK_DIR=${OUT()}`, ...extraEnv,
    NODE_BIN, script, ...args]
}
function expectedCalls(home: string, n: 'local' | 'testnet'): string[][] {
  const P = PORTS[n]
  const common = ['--network', n, '--home', home]
  return [
    ['has-session', '-t', `=vt-${n}`],
    ['new-session', '-d', '-s', `vt-${n}`, '-n', 'relay', '--', ...windowArgv(home, n, 'relay', relayProfile(n, n === 'local' ? CHAIN_PORTS : []), join(REPO, 'api', 'relay', 'relay.mjs'),
      n === 'local' ? [...common, '--price-fixture', 'SOL=150,ETH=3000'] : common)],
    ['new-window', '-d', '-t', `=vt-${n}:`, '-n', 'api', '--', ...windowArgv(home, n, 'api', apiProfile(join(home, n), OUT()), join(REPO, 'api', 'src', 'main.ts'), [...common, '--build', 'dev'])],
    ['new-window', '-d', '-t', `=vt-${n}:`, '-n', 'page', '--', ...windowArgv(home, n, 'page', loopbackProfile([P.relay, P.api]), join(REPO, 'api', 'serve', 'serve.mjs'), [...common, '--root', join(REPO, 'web', 'dist')])],
  ]
}
const secrets = (home: string, n = 'local') => ['api.token', 'relay-ticket.key'].map((f) => readFileSync(join(home, n, f), 'utf8'))

// ---- the whole start, through bin/vt

test('vt up (local): has-session, then relay, api, page, each with its exact sandbox-wrapped command; up.json; URL and build', () => {
  const r = vt(['up'])
  assert.equal(r.code, 0, r.err)
  assert.equal(r.err, '')
  assert.deepEqual(F.calls(), expectedCalls(VTH(), 'local'))
  // The chain ports really are the shared chains' (endpoints.json `local`), allowed for the local relay only.
  assert.ok(CHAIN_PORTS.includes(8545) && CHAIN_PORTS.includes(8999))
  // up.json: exactly { network, pagePort, build, startedAt }, 0600.
  const upJson = join(VTH(), 'local', 'up.json')
  assert.equal(mode(upJson), 0o600)
  const u = JSON.parse(readFileSync(upJson, 'utf8')) as Record<string, unknown>
  assert.deepEqual(Object.keys(u), ['network', 'pagePort', 'build', 'startedAt'])
  assert.equal(u.network, 'local')
  assert.equal(u.pagePort, 5180)
  assert.equal(u.build, 'dev')
  assert.ok(Number.isSafeInteger(u.startedAt) && Math.abs((u.startedAt as number) - Date.now()) < 120_000)
  // The output: the URL and the build id, and the local notes; nothing else of note.
  assert.match(r.out, /^vt up: the local stack is running in tmux session vt-local \(windows relay, api, page\)\n/)
  assert.match(r.out, /^ {2}page {3}http:\/\/127\.0\.0\.1:5180\/$/m)
  assert.match(r.out, /^ {2}build {2}dev$/m)
  assert.match(r.out, /^ {2}tmux {3}tmux -L vt attach -t vt-local$/m, 'vt\'s own tmux server (the fake refuses any call without -L vt)')
  assert.match(r.out, /--limit-ledger-size 50000000/)
  assert.match(r.out, /"Apps on device"/)
  // Directories 0700, logs 0600 (one per window, holding what the fake servers printed).
  for (const d of [VTH(), join(VTH(), 'local'), join(VTH(), 'local', 'logs')]) assert.equal(mode(d), 0o700, d)
  for (const w of ['relay', 'api', 'page']) {
    const log = join(VTH(), 'local', 'logs', `${w}.log`)
    assert.equal(mode(log), 0o600)
    assert.match(readFileSync(log, 'utf8'), new RegExp(`^vt-${w} ready network=local port=${PORTS.local[w as 'relay' | 'api' | 'page']}`, 'm'))
  }
  assert.deepEqual(F.opens(), [], 'no Chrome without --open')
})

test('api.token and relay-ticket.key: 64 hex each, 0600, written by vt up before the windows start, fresh per up, never printed', () => {
  let r = vt(['up'])
  assert.equal(r.code, 0, r.err)
  const first = secrets(VTH())
  for (const [i, f] of ['api.token', 'relay-ticket.key'].entries()) {
    assert.match(first[i], /^[0-9a-f]{64}$/, `${f}: exactly 64 lowercase hex, no newline`)
    const st = lstatSync(join(VTH(), 'local', f))
    assert.ok(st.isFile() && (st.mode & 0o777) === 0o600, f)
    assert.ok(!r.out.includes(first[i]) && !r.err.includes(first[i]), `${f} is never printed`)
  }
  assert.notEqual(first[0], first[1])
  // No temp file is left behind.
  assert.deepEqual(readdirSync(join(VTH(), 'local')).filter((f) => f.startsWith('.')), [])
  // down, up again: both are new.
  assert.equal(vt(['down']).code, 0)
  r = vt(['up'])
  assert.equal(r.code, 0, r.err)
  const second = secrets(VTH())
  assert.notEqual(second[0], first[0])
  assert.notEqual(second[1], first[1])
})

test('C1 review M2: through a symlinked VT_HOME, the API profile and every --home use the REAL path of the state dir', () => {
  const real = join(T, 'real-home')
  const link = join(T, 'link-home')
  mkdirSync(real, { mode: 0o700 })
  symlinkSync(real, link)
  try {
    const r = vt(['up'], { VT_HOME: link })
    assert.equal(r.code, 0, r.err)
    assert.deepEqual(F.calls(), expectedCalls(real, 'local'))
    const api = F.calls()[2]
    assert.ok(api.includes(`(version 1)(allow default)(deny network-outbound)(deny file-write*)(allow file-write* (subpath "${real}/local") (literal "/dev/null"))(allow file-read* (subpath "${OUT()}"))(deny file-write* (subpath "${OUT()}"))`))
    assert.ok(!api.some((a) => a.includes(link)), 'the link path appears nowhere in the API window')
    assert.ok(existsSync(join(real, 'local', 'up.json')))
  } finally {
    removeDir(real)
    removeDir(link)
  }
})

test('a second vt up while vt-<network> runs: exit 1, and nothing is touched (the running API keeps its token)', () => {
  assert.equal(vt(['up']).code, 0)
  const before = secrets(VTH())
  F.reset()
  writeFileSync(join(F.state, 'mode-relay'), 'ready')
  mkdirSync(join(F.state, 'sessions'), { recursive: true })
  writeFileSync(join(F.state, 'sessions', 'vt-local'), 'relay\napi\npage\n')
  const r = vt(['up'])
  assert.equal(r.code, 1)
  assert.match(r.err, /vt-local is already running/)
  assert.deepEqual(F.calls(), [['has-session', '-t', '=vt-local']])
  assert.deepEqual(secrets(VTH()), before)
})

test('testnet: the same three windows with the testnet ports, a Tor-only relay and no chain ports (Tor probe given)', async () => {
  const outs: string[] = []
  const code = await up({ network: 'testnet', open: false, dev: false, env: envOf(), repo: REPO, release: null, node: NODE_BIN },
    { tmux: systemTmux({ env: envOf() }), torProbe: async () => true, out: (l) => outs.push(l), err: (l) => outs.push(l), readyTimeoutMs: 5_000, pollMs: 10 })
  assert.equal(code, 0, outs.join('\n'))
  assert.deepEqual(F.calls(), expectedCalls(VTH(), 'testnet'))
  assert.equal(F.calls()[1][F.calls()[1].indexOf('-p') + 1], '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:9050"))')
  assert.ok(outs.includes('  page   http://127.0.0.1:5190/'))
  assert.ok(!outs.some((l) => l.includes('limit-ledger-size')), 'the local notes are for local only')
})

test('$OUT: always passed as VAULT_TIMELOCK_DIR (absolute, real path) and read only in the API profile; resolved like broadcast resolveOut', async () => {
  const outOf = async (env: Record<string, string | undefined>): Promise<{ word: string; profile: string }> => {
    F.reset()
    removeDir(VTH())
    const e: Record<string, string> = {}
    for (const [k, v] of Object.entries(env)) if (v !== undefined) e[k] = v
    const lines: string[] = []
    const code = await up({ network: 'local', open: false, dev: false, env: e, repo: REPO, release: null, node: NODE_BIN },
      { tmux: systemTmux({ env: envOf() }), out: (l) => lines.push(l), err: (l) => lines.push(l), readyTimeoutMs: 5_000, pollMs: 10 })
    assert.equal(code, 0, lines.join('\n'))
    const api = F.calls()[2]
    const words = api.filter((a) => a.startsWith('VAULT_TIMELOCK_DIR='))
    assert.equal(words.length, 1)
    return { word: words[0], profile: api[api.indexOf('-p') + 1] }
  }
  // VAULT_TIMELOCK_DIR unset (a release tree may do that; bin/vt refuses it in a dev tree): $XDG_DATA_HOME/vault-timelock,
  // else $HOME/.local/share/vault-timelock. HOME0 is this test's synthetic home, never the operator's.
  let r = await outOf({ ...envOf(), VAULT_TIMELOCK_DIR: undefined })
  assert.equal(r.word, `VAULT_TIMELOCK_DIR=${join(HOME0, '.local', 'share', 'vault-timelock')}`)
  assert.ok(r.profile.endsWith(`(allow file-read* (subpath "${join(HOME0, '.local', 'share', 'vault-timelock')}"))(deny file-write* (subpath "${join(HOME0, '.local', 'share', 'vault-timelock')}"))`))
  r = await outOf({ ...envOf(), VAULT_TIMELOCK_DIR: undefined, XDG_DATA_HOME: join(T, 'xdg') })
  assert.equal(r.word, `VAULT_TIMELOCK_DIR=${join(T, 'xdg', 'vault-timelock')}`)
  // Through a symlink: the real path, in the environment and in the profile.
  mkdirSync(join(T, 'out-real'), { recursive: true })
  symlinkSync(join(T, 'out-real'), join(T, 'out-link'))
  r = await outOf(envOf({ VAULT_TIMELOCK_DIR: join(T, 'out-link') }))
  assert.equal(r.word, `VAULT_TIMELOCK_DIR=${join(T, 'out-real')}`)
  assert.ok(r.profile.endsWith(`(allow file-read* (subpath "${join(T, 'out-real')}"))(deny file-write* (subpath "${join(T, 'out-real')}"))`))
  // A relative or unsafe $OUT is refused (vt.path) before anything starts.
  for (const bad of ['out', join(T, 'a"b')]) {
    F.reset()
    await rejectsWith(() => up({ network: 'local', open: false, dev: false, env: envOf({ VAULT_TIMELOCK_DIR: bad }), repo: REPO, release: null, node: NODE_BIN },
      { tmux: systemTmux({ env: envOf() }) }), 'vt.path')
    assert.deepEqual(F.calls().filter((c) => c[0] !== 'has-session'), [])
  }
})

test('--price-fixture SOL=150,ETH=3000 goes to the LOCAL relay only; never to testnet or mainnet, and never to another window', () => {
  assert.deepEqual(relayArgs('local'), ['--price-fixture', 'SOL=150,ETH=3000'])
  assert.deepEqual(relayArgs('testnet'), [])
  assert.deepEqual(relayArgs('mainnet'), [])
  assert.throws(() => relayArgs('devnet' as 'local'))
  for (const n of ['local', 'testnet', 'mainnet'] as const) {
    const windows = stackWindows({ network: n, homeReal: VTH(), outReal: OUT(), repo: REPO, node: NODE_BIN, build: 'dev', chainPorts: n === 'local' ? CHAIN_PORTS : [],
      viteCache: null, env: envOf() })
    for (const w of windows) {
      const at = w.argv.indexOf('--price-fixture')
      if (n === 'local' && w.name === 'relay') {
        assert.deepEqual(w.argv.slice(at), ['--price-fixture', 'SOL=150,ETH=3000'], 'the last two words of the local relay command')
        assert.equal(w.argv.filter((a) => a === '--price-fixture').length, 1)
      } else {
        assert.equal(at, -1, `${n} ${w.name}: no --price-fixture`)
        assert.ok(!w.argv.some((a) => a.includes('SOL=') || a.includes('ETH=')), `${n} ${w.name}`)
      }
    }
  }
})

// ---- refusals

test('vt.mainnet-dev-tree: vt up --network mainnet from this dev tree is refused before anything (no tmux, no files)', () => {
  for (const args of [['up', '--network', 'mainnet'], ['--network', 'mainnet', 'up', '--open']]) {
    const r = vt(args)
    refused(r, 'vt.mainnet-dev-tree')
    assert.deepEqual(F.calls(), [])
    assert.ok(!existsSync(VTH()), 'nothing was created')
  }
})

test('vt.tor-required: testnet without Tor (in this sandbox 127.0.0.1:9050 is denied) is refused before any file or window', async () => {
  await assertTorDenied()
  const r = vt(['up', '--network', 'testnet'])
  refused(r, 'vt.tor-required')
  assert.deepEqual(F.calls(), [])
  assert.ok(!existsSync(join(VTH(), 'testnet')), 'no state dir, no token')
})

async function listen(onConn: (c: Socket) => void): Promise<number> {
  const s = createServer((c) => { sockets.add(c); c.on('close', () => sockets.delete(c)); onConn(c) })
  servers.push(s)
  await new Promise<void>((res) => s.listen(0, '127.0.0.1', () => res()))
  const a = s.address()
  if (a === null || typeof a === 'string') throw new Error('no port')
  return a.port
}

test('socksAnswers: true only for a SOCKS5 "no authentication" answer to the greeting; nothing but the greeting is sent', async () => {
  const seen: Buffer[] = []
  const socks = await listen((c) => c.once('data', (d: Buffer) => { seen.push(d); c.end(Buffer.from([0x05, 0x00])) }))
  const authOnly = await listen((c) => c.once('data', () => c.end(Buffer.from([0x05, 0xff]))))
  const http = await listen((c) => c.once('data', () => c.end('HTTP/1.1 400 Bad Request\r\n\r\n')))
  const silent = await listen(() => { /* never answers */ })
  const closed = await listen((c) => c.destroy())
  assert.equal(await socksAnswers({ host: '127.0.0.1', port: socks }), true)
  assert.deepEqual(seen, [Buffer.from([0x05, 0x01, 0x00])])
  for (const port of [authOnly, http, closed]) assert.equal(await socksAnswers({ host: '127.0.0.1', port }), false, String(port))
  assert.equal(await socksAnswers({ host: '127.0.0.1', port: silent, timeoutMs: 200 }), false)
})

test('assertTor: local needs no Tor; testnet and mainnet need the probe to answer', async () => {
  let probed = 0
  await assertTor('local', async () => { probed++; return false })
  assert.equal(probed, 0, 'local does not probe')
  for (const n of ['testnet', 'mainnet'] as const) {
    await rejectsWith(() => assertTor(n, async () => false), 'vt.tor-required')
    await rejectsWith(() => assertTor(n, async () => 'yes' as unknown as boolean), 'vt.tor-required')
    await assertTor(n, async () => true)
  }
  // Through up(): no window, no file.
  await rejectsWith(() => up({ network: 'testnet', open: false, dev: false, env: envOf(), repo: REPO, release: null },
    { tmux: systemTmux({ env: envOf() }), torProbe: async () => false }), 'vt.tor-required')
  assert.deepEqual(F.calls(), [])
  assert.ok(!existsSync(VTH()))
})

// ---- readiness

test('a window that exits before its readiness line: exit 1 naming the window; the session is killed; no up.json (a stale one is gone too)', () => {
  mkdirSync(join(VTH(), 'local'), { recursive: true, mode: 0o700 })
  writeFileSync(join(VTH(), 'local', 'up.json'), '{"network":"local","pagePort":5180,"build":"dev","startedAt":1}\n')
  F.mode('api', 'exit')
  const r = vt(['up'])
  assert.equal(r.code, 1)
  assert.match(r.err, /^vt up: the api window exited \(status 2\) before its readiness line; vt-local was stopped\. Its log: vt logs api --network local$/m)
  assert.deepEqual(F.calls().at(-1), ['kill-session', '-t', '=vt-local'])
  assert.ok(!existsSync(join(VTH(), 'local', 'up.json')))
  assert.match(readFileSync(join(VTH(), 'local', 'logs', 'api.log'), 'utf8'), /^vt: exited with status 2$/m)
})

async function upLocal(timeoutMs: number, extra: Partial<UpDeps> = {}): Promise<{ code: number; lines: string[] }> {
  const lines: string[] = []
  const code = await up({ network: 'local', open: false, dev: false, env: envOf(), repo: REPO, release: null, node: NODE_BIN },
    { tmux: systemTmux({ env: envOf() }), out: (l) => lines.push(l), err: (l) => lines.push(l), readyTimeoutMs: timeoutMs, pollMs: 10, ...extra })
  return { code, lines }
}

test('no readiness line within the time limit (here shortened): exit 1 naming the first window still waiting', async () => {
  F.mode('page', 'silent')
  const r = await upLocal(300)
  assert.equal(r.code, 1)
  assert.deepEqual(r.lines, ['vt up: the page window printed no readiness line within 0.3 s; vt-local was stopped. Its log: vt logs page --network local'])
  assert.deepEqual(F.calls().at(-1), ['kill-session', '-t', '=vt-local'])
  assert.ok(!existsSync(join(VTH(), 'local', 'up.json')))
})

test('the readiness wait is per network: local 60 s; testnet and mainnet at least 90 s (Tor identity checks; here 120 s)', async () => {
  assert.equal(readyTimeoutFor('local'), 60_000)
  for (const n of ['testnet', 'mainnet'] as const) assert.ok(readyTimeoutFor(n) >= 90_000 && readyTimeoutFor(n) === 120_000, n)
  assert.throws(() => readyTimeoutFor('devnet' as 'local'))
  // Through up() with no override, on a fake clock (no real Tor: the probe answers; no real wait: sleep advances time):
  // a relay that never prints its line is given up after exactly its network's limit.
  for (const n of ['local', 'testnet'] as const) {
    F.reset()
    removeDir(VTH())
    F.mode('relay', 'silent')
    let t = 0
    let waited = 0
    const lines: string[] = []
    const code = await up({ network: n, open: false, dev: false, env: envOf(), repo: REPO, release: null, node: NODE_BIN }, {
      tmux: systemTmux({ env: envOf() }), torProbe: async () => true, out: (l) => lines.push(l), err: (l) => lines.push(l),
      now: () => t, sleep: async (ms) => { t += ms; waited += ms }, pollMs: 5_000,
    })
    assert.equal(code, 1)
    assert.deepEqual(lines, [`vt up: the relay window printed no readiness line within ${readyTimeoutFor(n) / 1000} s; vt-${n} was stopped. Its log: vt logs relay --network ${n}`])
    assert.equal(waited, readyTimeoutFor(n), `${n}: waited the whole limit, and no longer`)
  }
})

test('a readiness line naming another port does not count', async () => {
  F.mode('relay', 'other')
  const r = await upLocal(300)
  assert.equal(r.code, 1)
  assert.match(r.lines[0], /^vt up: the relay window printed no readiness line/)
})

test('the MQ servers\' lines (S3 keeps them) count as readiness for the relay and the page', async () => {
  F.mode('relay', 'mq')
  F.mode('page', 'mq')
  const r = await upLocal(5_000)
  assert.equal(r.code, 0, r.lines.join('\n'))
})

test('readyPatterns and scanLog: exact network and port, complete lines only, ANSI removed, the exit marker wins', () => {
  const api = readyPatterns('api', 'local', 'dev')
  assert.deepEqual(scanLog('vt-api ready network=local port=5182 build=dev\n', api), { ready: true, exited: null })
  for (const bad of ['vt-api ready network=local port=5182 build=dev', 'vt-api ready network=testnet port=5182 build=dev\n',
    'vt-api ready network=local port=5192 build=dev\n', 'vt-api ready network=local port=5182 build=devX\n', 'x vt-api ready network=local port=5182 build=dev\n']) {
    assert.equal(scanLog(bad, api).ready, false, bad)
  }
  assert.deepEqual(scanLog('vt-api ready network=local port=5182 build=dev\nvt: exited with status 1\n', api), { ready: true, exited: 1 })
  const relay = readyPatterns('relay', 'testnet', 'dev')
  assert.equal(scanLog('vt-relay ready network=testnet port=5191\n', relay).ready, true)
  assert.equal(scanLog('listening on loopback :5191 (eth on, sol on)\n', relay).ready, true)
  assert.equal(scanLog('listening on loopback :51910 (eth on)\n', relay).ready, false)
  const page = readyPatterns('page', 'mainnet', '0123456789ab')
  assert.equal(scanLog('vt-page ready network=mainnet port=5200 build=0123456789ab\r\n', page).ready, true)
  assert.equal(scanLog('release build on http://127.0.0.1:5200/?view=mainnet (relay proxy → :5201)\n', page).ready, true)
  assert.equal(scanLog('\u001b[32m  ➜  Local:   http://127.0.0.1:5183/\u001b[39m\n', readyPatterns('vite', 'local', 'dev')).ready, true)
  assert.throws(() => readyPatterns('relay', 'devnet' as 'local', 'dev'))
})

// ---- tmux failures, --open, --dev, arguments

test('tmux cannot start a later window: the session is killed, exit 1, no up.json', () => {
  F.fail('new-window')
  const r = vt(['up'])
  assert.equal(r.code, 1)
  assert.match(r.err, /^vt up: tmux could not start the api window of vt-local; nothing is running$/m)
  assert.deepEqual(F.calls().map((c) => c[0]), ['has-session', 'new-session', 'new-window', 'kill-session'])
  assert.ok(!existsSync(join(VTH(), 'local', 'up.json')))
})

test('--open: Chrome (LaunchServices, a new instance) with its own profile under $VT_HOME/chrome (0700), no first run, no extensions', () => {
  const r = vt(['up', '--open'])
  assert.equal(r.code, 0, r.err)
  const profile = join(VTH(), 'chrome')
  assert.deepEqual(F.opens(), [['-na', 'Google Chrome', '--args', `--user-data-dir=${profile}`, '--no-first-run', '--disable-extensions', 'http://127.0.0.1:5180/']])
  assert.deepEqual(chromeArgs(profile, 'http://127.0.0.1:5180/'), F.opens()[0])
  assert.equal(mode(profile), 0o700)
})

test('--dev (local only): a fourth window, Vite on 5183 under viteProfile (writes only its cache), VT_HOME passed', async () => {
  const repo = join(T, 'fake-repo')
  mkdirSync(join(repo, 'web', 'node_modules'), { recursive: true })
  try {
    const lines: string[] = []
    const code = await up({ network: 'local', open: false, dev: true, env: envOf(), repo, release: null, node: NODE_BIN },
      { tmux: systemTmux({ env: envOf() }), out: (l) => lines.push(l), err: (l) => lines.push(l), readyTimeoutMs: 5_000, pollMs: 10 })
    assert.equal(code, 0, lines.join('\n'))
    const calls = F.calls()
    assert.deepEqual(calls.slice(1).map((c) => c[c.indexOf('-n') + 1]), ['relay', 'api', 'page', 'vite'])
    assert.deepEqual(calls.at(-1), ['new-window', '-d', '-t', '=vt-local:', '-n', 'vite', '--', ...windowArgv(VTH(), 'local', 'vite',
      viteProfile([5181, 5182], join(repo, 'web', 'node_modules', '.vite')), join(repo, 'web', 'node_modules', 'vite', 'bin', 'vite.js'),
      [join(repo, 'web'), '--configLoader', 'native', '--host', '127.0.0.1', '--port', '5183', '--strictPort'])])
    assert.ok(lines.includes('  vite   http://127.0.0.1:5183/ (dev server, hot reload)'))
  } finally {
    removeDir(repo)
  }
  // Without an installed web workspace: a usage error, nothing started.
  F.reset()
  await assert.rejects(up({ network: 'local', open: false, dev: true, env: envOf(), repo: join(T, 'no-repo'), release: null, node: NODE_BIN },
    { tmux: systemTmux({ env: envOf() }) }), /--dev needs the web workspace installed/)
  assert.deepEqual(F.calls().filter((c) => c[0] !== 'has-session'), [])
  // Not on testnet or mainnet: a usage error, nothing started.
  F.reset()
  const r = vt(['up', '--dev', '--network', 'testnet'])
  assert.equal(r.code, 1)
  assert.equal(r.err, 'vt: --dev (the Vite dev server on 127.0.0.1:5183) is for the local network only\n')
  assert.deepEqual(F.calls(), [])
})

test('arguments: only --open and --dev, each once; anything else is a usage error (exit 1) and starts nothing', () => {
  assert.deepEqual(parseUpArgs([]), { open: false, dev: false })
  assert.deepEqual(parseUpArgs(['--dev', '--open']), { open: true, dev: true })
  for (const args of [['--open', '--open'], ['--opne'], ['local'], ['--json'], [`--rpc=http://${CANARY}`]]) {
    const r = vt(['up', ...args])
    assert.equal(r.code, 1, args.join(' '))
    assert.equal(r.err, 'vt: usage: vt up [--network local|testnet|mainnet] [--open] [--dev]\n')
    assert.ok(!IPV4.test(r.err + r.out))
  }
  assert.deepEqual(F.calls(), [])
})

test('a state dir that is not private (0755) is refused (vt-broadcast store.perms) before any secret is written', () => {
  mkdirSync(join(VTH(), 'local'), { recursive: true, mode: 0o755 })
  const r = vt(['up'])
  refused(r, 'store.perms')
  assert.ok(!existsSync(join(VTH(), 'local', 'api.token')))
  assert.deepEqual(F.calls(), [['has-session', '-t', '=vt-local']])
})

// ---- Cfix2: on mainnet the stack is ready only after the relay's release re-hash has finished
const RID = '0123456789ab'
async function upMainnet(relayRelease: UpDeps['relayRelease'], extra: Partial<UpDeps> = {}): Promise<{ code: number; lines: string[]; errs: string[] }> {
  const lines: string[] = [], errs: string[] = []
  const code = await up({ network: 'mainnet', open: false, dev: false, env: envOf(), repo: REPO, release: RID, node: NODE_BIN },
    { tmux: systemTmux({ env: envOf() }), torProbe: async () => true, verifyRelease: () => {}, relayRelease,
      out: (l) => lines.push(l), err: (l) => errs.push(l), readyTimeoutMs: 5_000, pollMs: 10, ...extra })
  return { code, lines, errs }
}
const reply = (o: unknown, status = 200) => async () => ({ status, body: typeof o === 'string' ? o : JSON.stringify(o) })
const CLEAN = { release: true, files: 27389, ok: 27389, mismatch: 0, missing: 0, digest: 'a'.repeat(64) }

test('Cfix2: mainnet up waits for the relay\'s release re-hash: no up.json and no "running" line until it answers; then it says so', async () => {
  let release!: (r: { status: number; body: string }) => void
  const calls: Array<[number, number]> = []
  const gate = new Promise<{ status: number; body: string }>((r) => { release = r })
  let finished = false
  const p = upMainnet((port, ms) => { calls.push([port, ms]); return gate }).then((r) => { finished = true; return r })
  await new Promise((r) => setTimeout(r, 400))
  assert.deepEqual(calls, [[PORTS.mainnet.relay, 300_000]], 'asked the relay once, with a long timeout')
  assert.equal(finished, false, 'still waiting for the re-hash')
  assert.ok(!existsSync(join(VTH(), 'mainnet', 'up.json')), 'not up yet')
  release({ status: 200, body: JSON.stringify(CLEAN) })
  const r = await p
  assert.equal(r.code, 0, r.errs.join('\n'))
  const i = r.lines.indexOf('vt up: relay: release re-hashed (27389 files, 0 mismatches)')
  assert.ok(i > 0, r.lines.join('\n'))
  assert.equal(r.lines[i - 1], "vt up: waiting for the relay's release re-hash…")
  assert.match(r.lines[i + 1], /^vt up: the mainnet stack is running in tmux session vt-mainnet/)
  assert.ok(existsSync(join(VTH(), 'mainnet', 'up.json')))
})

test('Cfix2: a failed, damaged, unreadable or timed-out re-hash stops the mainnet stack (exit 1, session killed, no up.json)', async () => {
  const cases: Array<[string, UpDeps['relayRelease'], RegExp]> = [
    ['no answer', async () => null, /did not finish within 7 s \(or the relay did not answer\)/],
    ['503', reply({ error: { message: 'x' } }, 503), /re-hash failed \(HTTP 503\)/],
    ['not json', reply('<html>'), /not JSON/],
    ['not a release', reply({ release: false }), /not a release tree/],
    ['unreadable', reply({ release: true, files: 'many', ok: 1, mismatch: 0, missing: 0 }), /unreadable result/],
    ['zero files', reply({ release: true, files: 0, ok: 0, mismatch: 0, missing: 0 }), /unreadable result/],
    ['mismatch', reply({ ...CLEAN, ok: 27388, mismatch: 1 }), /does not re-hash clean \(1 changed, 0 missing, 27388 of 27389 ok\)/],
    ['missing', reply({ ...CLEAN, ok: 27388, missing: 1 }), /does not re-hash clean \(0 changed, 1 missing/],
    ['ok short', reply({ ...CLEAN, ok: 5 }), /does not re-hash clean \(0 changed, 0 missing, 5 of 27389 ok\)/],
  ]
  for (const [name, fn, re] of cases) {
    F.reset(); removeDir(VTH())
    const r = await upMainnet(fn, { rehashTimeoutMs: 7_000 })
    assert.equal(r.code, 1, name)
    assert.match(r.errs.join('\n'), re, name)
    assert.match(r.errs.join('\n'), /vt-mainnet was stopped\. Its log: vt logs relay --network mainnet/, name)
    assert.deepEqual(F.calls().at(-1), ['kill-session', '-t', '=vt-mainnet'], name)
    assert.ok(!existsSync(join(VTH(), 'mainnet', 'up.json')), name)
    assert.ok(!r.lines.some((l) => /re-hashed \(/.test(l) || /is running/.test(l)), name)
  }
})

test('Cfix2: testnet and local never ask for the release re-hash', async () => {
  let asked = 0
  const spy: UpDeps['relayRelease'] = async () => { asked++; return null }
  assert.equal((await upLocal(5_000, { relayRelease: spy })).code, 0)
  F.reset(); removeDir(VTH())
  const lines: string[] = []
  const code = await up({ network: 'testnet', open: false, dev: false, env: envOf(), repo: REPO, release: null, node: NODE_BIN },
    { tmux: systemTmux({ env: envOf() }), torProbe: async () => true, relayRelease: spy, out: (l) => lines.push(l), err: (l) => lines.push(l), readyTimeoutMs: 5_000, pollMs: 10 })
  assert.equal(code, 0)
  assert.equal(asked, 0)
  assert.ok(!lines.some((l) => /re-hash/.test(l)))
})

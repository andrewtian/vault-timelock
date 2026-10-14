// bin/vt-broadcast (spec B s6.1, s6.3; Task 7 + addenda): the env -i scrub, the sandbox-exec
// re-exec (never nested), --profile/--rpc/--endpoint -> env, and sandbox widening for loopback ports.
// This file applies sandboxes itself, so it runs OUTSIDE the suite sandbox (scripts/test-offline.sh,
// unsandboxed phase; feasibility/F5.txt explains why). Every wrapper invocation below is confined by
// the wrapper's own profile unless a fake sandbox-exec says otherwise.
//
// Fakes on PATH (the shell-convention self-test style):
//   fake `node`         -> a probe that prints its argv, its env NAMES, selected VT_* values, and the
//                          errno of TCP connects it is asked to make (from INSIDE the real sandbox);
//   fake `sandbox-exec` -> a recorder (exact args + env names at the exec boundary), a nesting
//                          tripwire (marker file + exit 99), or a no-op that drops the profile.
// Tripwire: wherever tor-check runs outside the production profile, it runs under TOR_DENY (a
// sandbox that denies only Tor's SOCKS ports): to assertConfined that is "not sandboxed" (TEST-NET-1
// is not denied), and even a mutated assertConfined() can't reach Tor (the gate's probe gets EPERM).
// (An ALCHEMY_API_KEY=x tripwire no longer works: since Task 7b the inner branch scrubs it too.)
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { createServer, type Server } from 'node:net'
import { tmpdir, userInfo } from 'node:os'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { connect } from 'node:net'
import { runInPty } from './lifecycle/pty.ts'

const ROOT = fileURLToPath(new URL('../../', import.meta.url))
const WRAPPER = join(ROOT, 'bin', 'vt-broadcast')
const PROD = '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:9050"))'
const allow = (p: number) => `(allow network-outbound (remote ip "localhost:${p}"))`
// Denies Tor's SOCKS ports and nothing else (feasibility/F5.txt: only "*:<port>" denies take effect,
// written as one rule). Checked by the first test below, since it is the tripwire.
const TOR_DENY = '(version 1)(allow default)(deny network-outbound (remote ip "*:9050") (remote ip "*:9150"))'
const PATH0 = process.env.PATH ?? '/usr/bin:/bin'
// K31 (Task H0 item 6): every wrapper run below gets a synthetic HOME, $T/home, never the account's
// home: nothing the wrapper or the CLI starts can write the real ~/.local/share/vault-timelock.
let HOME0 = ''
// Names macOS CoreFoundation synthesises inside a child (not passed by the wrapper; F5.txt).
const SYNTHESISED = ['__CF_USER_TEXT_ENCODING']

let T = ''
let A = 0 // 127.0.0.1 listener: the "fixture" a loopback override points at
let B = 0 // 127.0.0.1 listener nobody configured: must stay blocked
let C = 0 // [::1] listener
const servers: Server[] = []
const dir = (name: string) => join(T, name)

function writeExe(path: string, text: string): void {
  writeFileSync(path, text)
  chmodSync(path, 0o755)
}
async function listen(host: string): Promise<number> {
  const s = createServer((c) => c.end())
  servers.push(s)
  await new Promise<void>((res) => s.listen(0, host, () => res()))
  const a = s.address()
  if (a === null || typeof a === 'string') throw new Error('no port')
  return a.port
}

before(async () => {
  T = realpathSync(mkdtempSync(join(tmpdir(), 'vt-wrapper-')))
  assert.ok(!/['\s]/.test(T + process.execPath), 'temp and node paths are safe to single-quote')
  HOME0 = join(T, 'home')
  mkdirSync(HOME0, { mode: 0o700 })
  A = await listen('127.0.0.1')
  B = await listen('127.0.0.1')
  C = await listen('::1')

  // fake node: probe + env report
  mkdirSync(dir('node'))
  writeFileSync(dir('fake-node.mjs'), `
import { connect } from 'node:net'
const [...rest] = process.argv.slice(2)
const flags = []
while (rest.length > 0 && rest[0].startsWith('--')) flags.push(rest.shift())
const [cli, ...args] = rest
const env = {}
for (const k of Object.keys(process.env).sort()) if (/^(VT_|LANG$|TERM$|VAULT_TIMELOCK_DIR$|XDG_DATA_HOME$)/.test(k)) env[k] = process.env[k]
const outcomes = {}
if (args[0] === 'probe') {
  for (const t of args.slice(1)) {
    const m = /^\\[?([^\\]]+)\\]?:(\\d+)$/.exec(t)
    outcomes[t] = await new Promise((res) => {
      const s = connect({ host: m[1], port: Number(m[2]) })
      const timer = setTimeout(() => { s.destroy(); res('timeout') }, 3000)
      s.on('connect', () => { clearTimeout(timer); s.destroy(); res('connected') })
      s.on('error', (e) => { clearTimeout(timer); res(e.code ?? 'error') })
    })
  }
}
process.stdout.write(JSON.stringify({ flags, cli, args, names: Object.keys(process.env).sort(), env, home: process.env.HOME, outcomes }) + '\\n')
`)
  writeExe(join(dir('node'), 'node'), `#!/bin/sh\nexec '${process.execPath}' '${dir('fake-node.mjs')}' "$@"\n`)

  // fake sandbox-exec #1: records its argv and the env NAMES it was given, runs nothing. A Node
  // script, not sh: sh adds PWD/SHLVL/_ to its own environment, which would blur the measurement.
  mkdirSync(dir('rec'))
  writeExe(join(dir('rec'), 'sandbox-exec'), `#!${process.execPath}
const fs = require('node:fs')
fs.writeFileSync(${JSON.stringify(dir('rec.args'))}, process.argv.slice(2).join('\\n') + '\\n')
const names = Object.keys(process.env).filter((n) => !${JSON.stringify(SYNTHESISED)}.includes(n)).sort()
fs.writeFileSync(${JSON.stringify(dir('rec.env'))}, names.join('\\n') + '\\n')
`)
  // fake sandbox-exec #2: a nesting tripwire
  mkdirSync(dir('nest'))
  writeExe(join(dir('nest'), 'sandbox-exec'), `#!/bin/sh\n: > '${dir('nested.marker')}'\nexit 99\n`)
  // fake sandbox-exec #3: drops the production profile and runs the command under TOR_DENY instead
  // (not confined as far as assertConfined can tell, but Tor stays out of reach: the tripwire)
  mkdirSync(dir('noop'))
  writeExe(join(dir('noop'), 'sandbox-exec'), `#!/bin/sh\n[ "$1" = -p ] || exit 98\nshift 2\nexec /usr/bin/sandbox-exec -p '${TOR_DENY}' "$@"\n`)
})

after(async () => {
  for (const s of servers) await new Promise<void>((res) => s.close(() => res()))
  if (T !== '') rmSync(T, { recursive: true, force: true })
})

interface Run { code: number | null; out: string; err: string }
interface Opts { env?: Record<string, string | undefined>; input?: string; path?: string; wrapper?: string }
function wrap(args: string[], o: Opts = {}): Run {
  const env: Record<string, string> = { PATH: o.path ?? PATH0, HOME: HOME0 }
  for (const [k, v] of Object.entries(o.env ?? {})) {
    if (v === undefined) delete env[k]
    else env[k] = v
  }
  const r = spawnSync(o.wrapper ?? WRAPPER, args, { env, input: o.input ?? '', encoding: 'utf8', timeout: 60_000 })
  return { code: r.status, out: r.stdout, err: r.stderr }
}
interface Probe { flags: string[]; cli: string; args: string[]; names: string[]; env: Record<string, string>; home: string; outcomes: Record<string, string> }
// The wrapper with the fake node first on PATH: a real sandbox, a fake program inside it.
function probe(args: string[], o: Opts = {}): Probe {
  const r = wrap(args, { ...o, path: `${dir('node')}:${PATH0}` })
  assert.equal(r.code, 0, `wrapper failed: ${r.err}`)
  return JSON.parse(r.out) as Probe
}
function refused(r: Run, id: string): void {
  assert.equal(r.code, 2, `exit code for ${id}: ${r.err}`)
  assert.match(r.err, new RegExp(`^refused ${id.replace('.', '\\.')}: `, 'm'))
  assert.equal(r.out, '', 'nothing ran after a wrapper refusal')
}
function recorded(args: string[], o: Opts = {}): { argv: string[]; env: string[] } {
  rmSync(dir('rec.args'), { force: true })
  const r = wrap(args, { ...o, path: `${dir('rec')}:${PATH0}` })
  assert.equal(r.code, 0, r.err)
  return {
    argv: readFileSync(dir('rec.args'), 'utf8').replace(/\n$/, '').split('\n'),
    env: readFileSync(dir('rec.env'), 'utf8').trim().split('\n'),
  }
}
const lo = (p: number) => `127.0.0.1:${p}`

// ---- the tripwire profile itself

test('TOR_DENY (the tripwire for tor-check outside the production profile) denies Tor\'s ports and only them', () => {
  const r = spawnSync('/usr/bin/sandbox-exec', ['-p', TOR_DENY, process.execPath, dir('fake-node.mjs'), 'cli', 'probe',
    lo(9050), lo(9150), '[::1]:9050', '[::1]:9150', lo(A)], { env: { PATH: PATH0, HOME: HOME0 }, encoding: 'utf8', timeout: 60_000 })
  assert.equal(r.status, 0, r.stderr)
  assert.deepEqual((JSON.parse(r.stdout) as Probe).outcomes, {
    [lo(9050)]: 'EPERM', [lo(9150)]: 'EPERM', '[::1]:9050': 'EPERM', '[::1]:9150': 'EPERM', [lo(A)]: 'connected',
  })
})

// ---- the file itself

test('bin/vt-broadcast is an executable POSIX sh script that parses', () => {
  assert.ok((statSync(WRAPPER).mode & 0o111) !== 0, 'executable')
  assert.equal(readFileSync(WRAPPER, 'utf8').split('\n')[0], '#!/bin/sh')
  const r = spawnSync('/bin/sh', ['-n', WRAPPER], { encoding: 'utf8' })
  assert.equal(r.status, 0, r.stderr)
})

// ---- env -i scrub

const HOSTILE_ENV = {
  ALCHEMY_API_KEY: 'x', FOO: '1', DEBUG: 'socks-proxy-agent', DEBUG_COLORS: '1', NODE_OPTIONS: '--require /nonexistent.cjs',
  NODE_EXTRA_CA_CERTS: '/nonexistent.pem', HTTPS_PROXY: 'http://proxy.invalid:1', ALL_PROXY: 'socks5h://proxy.invalid:1',
  NODE_TEST_CONTEXT: 'child-v8', VITEST: '1', VT_DEBUG: '1', LANG: 'C', TERM: 'xterm',
}

test('env -i: exactly PATH HOME LANG TERM VT_CONFINED reach sandbox-exec, plus pass-throughs only when set', () => {
  const plain = recorded(['env-names'], { env: HOSTILE_ENV })
  assert.deepEqual(plain.env, ['HOME', 'LANG', 'PATH', 'TERM', 'VT_CONFINED'])
  const full = recorded(['env-names'], {
    env: { ...HOSTILE_ENV, VAULT_TIMELOCK_DIR: '/tmp/vt-x', XDG_DATA_HOME: '/tmp/xdg-x', VT_PROFILE: 'testnet', VT_RPC_ETH: 'https://rpc.eth.example/', VT_ENDPOINT_BTC_ESPLORA: 'https://esplora.example/api' },
  })
  assert.deepEqual(full.env, ['HOME', 'LANG', 'PATH', 'TERM', 'VAULT_TIMELOCK_DIR', 'VT_CONFINED', 'VT_ENDPOINT_BTC_ESPLORA', 'VT_PROFILE', 'VT_RPC_ETH', 'XDG_DATA_HOME'])
})

test('env-names through the real sandbox: ALCHEMY_API_KEY, FOO, DEBUG*, NODE_*, proxies never reach the CLI', () => {
  const r = wrap(['env-names'], { env: HOSTILE_ENV })
  assert.equal(r.code, 0, r.err)
  const names = r.out.trim().split('\n')
  assert.deepEqual(names, [...names].sort(), 'sorted')
  assert.deepEqual(names.filter((n) => !SYNTHESISED.includes(n)), ['HOME', 'LANG', 'PATH', 'TERM', 'VT_CONFINED'])
  for (const n of Object.keys(HOSTILE_ENV)) if (!['LANG', 'TERM'].includes(n)) assert.ok(!names.includes(n), n)
  assert.ok(!r.out.includes('='), 'names only, never values')
})

test('DEBUG=socks-proxy-agent in the parent does not reach the child (env-names)', () => {
  const r = wrap(['env-names'], { env: { DEBUG: 'socks-proxy-agent', DEBUG_DEPTH: '9' } })
  assert.equal(r.code, 0, r.err)
  assert.ok(!r.out.split('\n').some((n) => n.startsWith('DEBUG')))
})

test('LANG and TERM get defaults when unset; VAULT_TIMELOCK_DIR/XDG_DATA_HOME pass only when set', () => {
  const p = probe(['report'], { env: { LANG: undefined, TERM: undefined } })
  assert.equal(p.env.LANG, 'en_US.UTF-8')
  assert.equal(p.env.TERM, 'dumb')
  assert.ok(!('VAULT_TIMELOCK_DIR' in p.env) && !('XDG_DATA_HOME' in p.env))
  const q = probe(['report'], { env: { LANG: 'C', TERM: 'xterm', VAULT_TIMELOCK_DIR: '/tmp/vt-x', XDG_DATA_HOME: '' } })
  assert.equal(q.env.LANG, 'C')
  assert.equal(q.env.TERM, 'xterm')
  assert.equal(q.env.VAULT_TIMELOCK_DIR, '/tmp/vt-x')
  assert.equal(q.env.XDG_DATA_HOME, '')
  assert.equal(q.env.VT_CONFINED, '1')
})

// ---- the real CLI through the wrapper

test('validate-note through the wrapper: stdin hello -> ok 5', () => {
  const r = wrap(['validate-note'], { input: 'hello' })
  assert.equal(r.err, '')
  assert.equal(r.out, 'ok 5\n')
  assert.equal(r.code, 0)
})

// ---- sandbox-exec and nesting

test('the sandbox profile is exactly the production one, and the wrapper re-execs itself', () => {
  const r = recorded(['validate-note', '--max-bytes', '5'])
  assert.deepEqual(r.argv, ['-p', PROD, realpathSync(WRAPPER), 'validate-note', '--max-bytes', '5'])
})

// The wrapper started by hand with VT_CONFINED=1 under TOR_DENY instead of the production profile.
function handConfined(args: string[], env: Record<string, string> = {}): Run {
  const r = spawnSync('/usr/bin/sandbox-exec', ['-p', TOR_DENY, WRAPPER, ...args], {
    env: { PATH: PATH0, HOME: HOME0, VT_CONFINED: '1', ...env }, input: '', encoding: 'utf8', timeout: 60_000,
  })
  return { code: r.status, out: r.stdout, err: r.stderr }
}

test('VT_CONFINED=1 set by hand outside the production sandbox: tor-check refuses confine.not-sandboxed (fail closed)', () => {
  refused(handConfined(['tor-check']), 'confine.not-sandboxed')
})

test('a sandbox-exec that drops the production profile: tor-check still refuses confine.not-sandboxed', () => {
  const r = wrap(['tor-check'], { path: `${dir('noop')}:${PATH0}` })
  refused(r, 'confine.not-sandboxed')
})

test('never nests: under VT_CONFINED=1 inside the sandbox, sandbox-exec is not called again', () => {
  const marker = dir('nested.marker')
  const path = `${dir('nest')}:${PATH0}`
  // Positive control: outside, the wrapper does call the (tripwire) sandbox-exec on PATH.
  rmSync(marker, { force: true })
  const outer = wrap(['env-names'], { path })
  assert.equal(outer.code, 99)
  assert.ok(existsSync(marker), 'the tripwire sandbox-exec was called')
  // Inside a real sandbox with VT_CONFINED=1: straight to node, no second sandbox-exec.
  rmSync(marker, { force: true })
  const r = spawnSync('/usr/bin/sandbox-exec', ['-p', PROD, WRAPPER, 'env-names'], {
    env: { PATH: path, HOME: HOME0, VT_CONFINED: '1' }, encoding: 'utf8', timeout: 60_000,
  })
  assert.equal(r.status, 0, r.stderr)
  assert.ok(r.stdout.split('\n').includes('VT_CONFINED'))
  assert.ok(!existsSync(marker), 'sandbox-exec was called again (nested)')
})

test('wrapper.no-sandbox: sandbox-exec missing from PATH -> refused, nothing runs', () => {
  const bin = dir('nosb')
  mkdirSync(bin, { recursive: true })
  for (const tool of ['dirname', 'env', 'sed', 'sort', 'tr']) {
    if (!existsSync(join(bin, tool))) symlinkSync(`/usr/bin/${tool}`, join(bin, tool))
  }
  if (!existsSync(join(bin, 'node'))) symlinkSync(join(dir('node'), 'node'), join(bin, 'node'))
  refused(wrap(['env-names'], { path: bin }), 'wrapper.no-sandbox')
})

test('wrapper.env: HOME or PATH unset -> refused', () => {
  refused(wrap(['env-names'], { env: { HOME: undefined } }), 'wrapper.env')
  const r = spawnSync('/bin/sh', [WRAPPER, 'env-names'], { env: { HOME: HOME0 }, encoding: 'utf8' })
  assert.equal(r.status, 2)
  assert.match(r.stderr, /^refused wrapper\.env: /m)
})

// ---- ADDENDUM: sandbox widening for loopback ports (R17/R23)

test('VT_RPC_ETH=http://127.0.0.1:<A>: a sandboxed child reaches A; another local port stays blocked', () => {
  const p = probe(['probe', lo(A), lo(B)], { env: { VT_RPC_ETH: `http://127.0.0.1:${A}` } })
  assert.deepEqual(p.outcomes, { [lo(A)]: 'connected', [lo(B)]: 'EPERM' })
  assert.equal(p.env.VT_RPC_ETH, `http://127.0.0.1:${A}`)
  // Negative control: without the override, A is blocked too.
  assert.deepEqual(probe(['probe', lo(A)]).outcomes, { [lo(A)]: 'EPERM' })
})

test('--rpc/--endpoint/--profile args become env, are removed from argv, and widen the sandbox', () => {
  const p = probe(['--rpc', `eth=http://127.0.0.1:${A}`, 'probe', lo(A), lo(B), `[::1]:${C}`,
    '--endpoint', `btc.esplora=http://[::1]:${C}/api`, '--profile', 'testnet'])
  assert.deepEqual(p.args, ['probe', lo(A), lo(B), `[::1]:${C}`])
  assert.deepEqual(p.outcomes, { [lo(A)]: 'connected', [lo(B)]: 'EPERM', [`[::1]:${C}`]: 'connected' })
  assert.equal(p.env.VT_RPC_ETH, `http://127.0.0.1:${A}`)
  assert.equal(p.env.VT_ENDPOINT_BTC_ESPLORA, `http://[::1]:${C}/api`)
  assert.equal(p.env.VT_PROFILE, 'testnet')
  // The rebuilt "$@" keeps spaces, empty strings and '=' intact.
  const q = probe(['report', 'a b', '', 'x=y', '--rpc', 'sol=https://sol.example/', '-z'])
  assert.deepEqual(q.args, ['report', 'a b', '', 'x=y', '-z'])
  assert.equal(q.env.VT_RPC_SOL, 'https://sol.example/')
})

test('a flag wins over the env; an empty env value replaced by a flag is fine', () => {
  const p = probe(['report', '--rpc', 'eth=https://flag.example/'], { env: { VT_RPC_ETH: 'https://env.example/' } })
  assert.equal(p.env.VT_RPC_ETH, 'https://flag.example/')
  const q = probe(['report', '--rpc', 'eth=https://flag.example/'], { env: { VT_RPC_ETH: '' } })
  assert.equal(q.env.VT_RPC_ETH, 'https://flag.example/')
})

test('the widened profile: sorted, de-duplicated loopback ports; non-loopback values add nothing', () => {
  const [lo2, hi] = A < C ? [A, C] : [C, A]
  const r = recorded(['env-names'], {
    env: {
      VT_RPC_ETH: `http://127.0.0.1:${A}`, VT_ENDPOINT_DRAND: `http://127.0.0.1:${A}/x`, VT_ENDPOINT_BTC_ESPLORA: `http://[::1]:${C}`,
      VT_RPC_ARB: 'https://arb.example/', VT_RPC_BASE: `http://localhost:${B}`, VT_RPC_SOL: `HTTP://127.0.0.1:${B}`,
    },
  })
  assert.equal(r.argv[1], PROD + allow(lo2) + allow(hi))
  // localhost / upper-case scheme / https are not loopback: no widening, and the CLI refuses them later.
  const p = probe(['probe', lo(B)], { env: { VT_RPC_BASE: `http://localhost:${B}`, VT_RPC_SOL: `HTTP://127.0.0.1:${B}` } })
  assert.deepEqual(p.outcomes, { [lo(B)]: 'EPERM' })
})

// R35: anvil, solana-test-validator, bitcoind regtest, ord (8090 sorts first numerically)
const LOCAL_PORTS = [8545, 8999, 18443, 8090]
// Task H0: the operator's own local chains may be listening on exactly these ports, so this test never
// connects to them (an earlier version probed them live). The widened profile is checked as recorded;
// that the kernel enforces a widened port, and only that port, is shown with test-owned listeners (the
// VT_RPC_ETH test above and the scratch endpoints.json test below).
test('VT_PROFILE=local (or --profile local) widens to exactly the endpoints.json local ports (recorded, never probed live)', () => {
  const local = JSON.parse(readFileSync(join(ROOT, 'endpoints.json'), 'utf8')).local
  assert.deepEqual(local, {
    'eth.rpc': ['http://127.0.0.1:8545'], 'sol.rpc': ['http://127.0.0.1:8999'],
    'btc.bitcoind': ['http://127.0.0.1:18443'], 'btc.ord': ['http://127.0.0.1:8090'],
  })
  const widened = PROD + [...LOCAL_PORTS].sort((a, b) => a - b).map(allow).join('')
  const ways: Array<{ args: string[]; env: Record<string, string> }> = [
    { args: [], env: { VT_PROFILE: 'local' } },
    { args: ['--profile', 'local'], env: {} },
  ]
  for (const o of ways) {
    // exactly these ports (plus Tor's 9050), sorted numerically
    assert.equal(recorded([...o.args, 'env-names'], { env: o.env }).argv[1], widened)
    // in the real sandbox, a different (test-owned) loopback port stays blocked
    assert.equal(probe(['probe', lo(B), ...o.args], { env: o.env }).outcomes[lo(B)], 'EPERM', 'a different loopback port stays blocked')
  }
  for (const profile of ['mainnet', 'testnet']) {
    assert.equal(recorded(['env-names'], { env: { VT_PROFILE: profile } }).argv[1], PROD, `${profile}: no local port is widened`)
  }
})

// A copy of the wrapper in a scratch tree, to feed it other endpoints.json files.
function scratchWrapper(name: string, endpoints: string): string {
  const root = dir(name)
  mkdirSync(join(root, 'bin'), { recursive: true })
  writeExe(join(root, 'bin', 'vt-broadcast'), readFileSync(WRAPPER, 'utf8'))
  writeFileSync(join(root, 'endpoints.json'), endpoints)
  return join(root, 'bin', 'vt-broadcast')
}

test('the local ports come from the json: a scratch endpoints.json widens exactly its port', () => {
  const w = scratchWrapper('local-ok', JSON.stringify({ local: { 'eth.rpc': [`http://127.0.0.1:${A}`] } }))
  const p = probe(['probe', lo(A), lo(B)], { wrapper: w, env: { VT_PROFILE: 'local' } })
  assert.deepEqual(p.outcomes, { [lo(A)]: 'connected', [lo(B)]: 'EPERM' })
})

test('wrapper.local-endpoints: unreadable or malformed endpoints.json in the local profile -> refused', () => {
  for (const [name, text] of [['local-bad-json', '{'], ['local-missing', '{"mainnet":{}}'], ['local-not-list', '{"local":{"eth.rpc":"http://127.0.0.1:8545"}}']]) {
    const w = scratchWrapper(name, text)
    refused(wrap(['report'], { wrapper: w, path: `${dir('node')}:${PATH0}`, env: { VT_PROFILE: 'local' } }), 'wrapper.local-endpoints')
  }
})

test('wrapper.port: a loopback URL with a bad port dies (env, flag, or json)', () => {
  const bad = ['0', '65536', '99999', '08545', 'abc', '', '8545@evil.example', '-1', '1e3', '123456']
  for (const port of bad) {
    for (const url of [`http://127.0.0.1:${port}`, `http://[::1]:${port}/x`]) {
      refused(wrap(['report'], { path: `${dir('node')}:${PATH0}`, env: { VT_RPC_ETH: url } }), 'wrapper.port')
    }
  }
  for (const url of ['http://127.0.0.1', 'http://127.0.0.1/', 'http://[::1]', 'http://127.0.0.1.evil.example:80/', 'http://[::1]x:80']) {
    refused(wrap(['report'], { path: `${dir('node')}:${PATH0}`, env: { VT_ENDPOINT_DRAND: url } }), 'wrapper.port')
  }
  refused(wrap(['report', '--rpc', 'eth=http://127.0.0.1:70000'], { path: `${dir('node')}:${PATH0}` }), 'wrapper.port')
  const w = scratchWrapper('local-bad-port', JSON.stringify({ local: { 'eth.rpc': ['http://127.0.0.1:0'] } }))
  refused(wrap(['report'], { wrapper: w, path: `${dir('node')}:${PATH0}`, env: { VT_PROFILE: 'local' } }), 'wrapper.port')
  // Boundaries that are fine.
  assert.equal(recorded(['x'], { env: { VT_RPC_ETH: 'http://127.0.0.1:1', VT_RPC_ARB: 'http://[::1]:65535/rpc' } }).argv[1], PROD + allow(1) + allow(65535))
})

test('wrapper.flag: malformed --rpc/--endpoint/--profile -> refused', () => {
  const path = `${dir('node')}:${PATH0}`
  for (const args of [
    ['x', '--rpc'], ['x', '--profile'], ['x', '--endpoint'], ['--rpc=eth=https://a.example/', 'x'], ['--profile=local', 'x'],
    ['--endpoint=drand=https://a.example/', 'x'], ['--rpc', 'eth'], ['--rpc', '=https://a.example/'], ['--rpc', 'eth='],
    ['--rpc', 'ETH=https://a.example/'], ['--rpc', 'e-th=https://a.example/'], ['--endpoint', 'btc..esplora=https://a.example/'],
    ['--endpoint', '.drand=https://a.example/'], ['--endpoint', 'drand.=https://a.example/'], ['--profile', ''],
  ]) {
    refused(wrap(args, { path }), 'wrapper.flag')
  }
})

test('wrapper.flag-duplicate: the same override or --profile twice -> refused', () => {
  const path = `${dir('node')}:${PATH0}`
  refused(wrap(['x', '--rpc', 'eth=https://a.example/', '--rpc', 'eth=https://b.example/'], { path }), 'wrapper.flag-duplicate')
  refused(wrap(['x', '--endpoint', 'drand=https://a.example/', '--endpoint', 'drand=https://a.example/'], { path }), 'wrapper.flag-duplicate')
  refused(wrap(['x', '--profile', 'testnet', '--profile', 'testnet'], { path }), 'wrapper.flag-duplicate')
})

test('wrapper.profile-conflict and wrapper.profile-invalid', () => {
  const path = `${dir('node')}:${PATH0}`
  refused(wrap(['x', '--profile', 'local'], { path, env: { VT_PROFILE: 'testnet' } }), 'wrapper.profile-conflict')
  assert.equal(probe(['x', '--profile', 'testnet'], { env: { VT_PROFILE: 'testnet' } }).env.VT_PROFILE, 'testnet')
  refused(wrap(['x', '--profile', 'prod'], { path }), 'wrapper.profile-invalid')
  refused(wrap(['x'], { path, env: { VT_PROFILE: 'Local' } }), 'wrapper.profile-invalid')
  // An empty VT_PROFILE is unset (config's rule): not passed on.
  assert.ok(!('VT_PROFILE' in probe(['x'], { env: { VT_PROFILE: '' } }).env))
})

test('wrapper.override-empty: an empty VT_RPC_*/VT_ENDPOINT_* is refused, never passed on', () => {
  const path = `${dir('node')}:${PATH0}`
  refused(wrap(['x'], { path, env: { VT_RPC_ETH: '' } }), 'wrapper.override-empty')
  refused(wrap(['x'], { path, env: { VT_ENDPOINT_BTC_ESPLORA: '' } }), 'wrapper.override-empty')
})

test('wrapper.override-name: a VT_RPC_/VT_ENDPOINT_ name outside [A-Z0-9_] is refused, never dropped silently', () => {
  const path = `${dir('node')}:${PATH0}`
  refused(wrap(['x'], { path, env: { VT_RPC_eth: 'https://a.example/' } }), 'wrapper.override-name')
  refused(wrap(['x'], { path, env: { 'VT_ENDPOINT_BTC.ESPLORA': 'https://a.example/' } }), 'wrapper.override-name')
  // Unknown but well-formed names pass through, so the CLI refuses them (config.override-key).
  assert.equal(probe(['x'], { env: { VT_RPC_DOGE: 'https://doge.example/' } }).env.VT_RPC_DOGE, 'https://doge.example/')
})

// ---- Task 7b: the inner branch scrubs too; NUL-safe env enumeration; symlinked wrapper

test('VT_CONFINED=1 by hand: the inner branch rebuilds the env with env -i (NODE_OPTIONS, DEBUG, keys never reach node)', () => {
  const hostile = { ...HOSTILE_ENV, VT_CONFINED: '1', NODE_OPTIONS: '--require=/nonexistent', DEBUG: 'x', ALCHEMY_API_KEY: 'x' }
  const r = wrap(['env-names'], { env: hostile })
  assert.equal(r.err, '', 'node did not crash on the bogus --require (NODE_OPTIONS never reached it)')
  assert.equal(r.code, 0)
  const names = r.out.trim().split('\n').filter((n) => !SYNTHESISED.includes(n))
  assert.deepEqual(names, ['HOME', 'LANG', 'PATH', 'TERM', 'VT_CONFINED'])
  for (const n of ['NODE_OPTIONS', 'DEBUG', 'DEBUG_COLORS', 'ALCHEMY_API_KEY', 'NODE_TEST_CONTEXT', 'HTTPS_PROXY', 'PWD', 'SHLVL', '_']) {
    assert.ok(!names.includes(n), n)
  }
  // The same allowlist as the outer branch: pass-throughs survive, values intact, defaults applied.
  const passing = {
    ...hostile, LANG: undefined, TERM: undefined, VAULT_TIMELOCK_DIR: '/tmp/vt-x', XDG_DATA_HOME: '/tmp/xdg-x',
    VT_PROFILE: 'testnet', VT_RPC_ETH: 'https://rpc.eth.example/', VT_ENDPOINT_BTC_ESPLORA: 'https://esplora.example/api',
  }
  const all = wrap(['env-names'], { env: passing })
  assert.equal(all.code, 0, all.err)
  assert.deepEqual(all.out.trim().split('\n').filter((n) => !SYNTHESISED.includes(n)),
    ['HOME', 'LANG', 'PATH', 'TERM', 'VAULT_TIMELOCK_DIR', 'VT_CONFINED', 'VT_ENDPOINT_BTC_ESPLORA', 'VT_PROFILE', 'VT_RPC_ETH', 'XDG_DATA_HOME'])
  // (The fake node is a sh script, which adds PWD/SHLVL to its own env: only its VT_*/LANG/TERM view.)
  const p = probe(['report'], { env: passing })
  assert.deepEqual(Object.keys(p.env), ['LANG', 'TERM', 'VAULT_TIMELOCK_DIR', 'VT_CONFINED', 'VT_ENDPOINT_BTC_ESPLORA', 'VT_PROFILE', 'VT_RPC_ETH', 'XDG_DATA_HOME'])
  assert.equal(p.env.LANG, 'en_US.UTF-8')
  assert.equal(p.env.TERM, 'dumb')
  assert.equal(p.env.VT_RPC_ETH, 'https://rpc.eth.example/')
  assert.equal(p.env.VT_CONFINED, '1')
})

test('VT_CONFINED=1 by hand: the inner branch applies the same override-name / override-empty refusals', () => {
  const path = `${dir('node')}:${PATH0}`
  refused(wrap(['x'], { path, env: { VT_CONFINED: '1', VT_RPC_eth: 'https://a.example/' } }), 'wrapper.override-name')
  refused(wrap(['x'], { path, env: { VT_CONFINED: '1', VT_ENDPOINT_DRAND: '' } }), 'wrapper.override-empty')
})

// A value that LOOKS like more variables when the environment is read line by line.
const SNEAKY = {
  FOO: `x\nVT_RPC_EVIL=http://127.0.0.1:1`,
  BAR: 'y\nVT_RPC_evil=https://a.example/',
  BAZ: 'z\nVT_ENDPOINT_EMPTY=\nVT_RPC_ALSO_EVIL=http://[::1]:2',
}

test('NUL-safe env enumeration: "\\nVT_RPC_EVIL=..." inside a value is no variable (no refusal, no widening, not passed)', () => {
  const r = recorded(['env-names'], { env: SNEAKY })
  assert.deepEqual(r.env, ['HOME', 'LANG', 'PATH', 'TERM', 'VT_CONFINED'])
  assert.equal(r.argv[1], PROD, 'no port widened by a value')
  const w = wrap(['env-names'], { env: SNEAKY })
  assert.equal(w.code, 0, w.err)
  assert.deepEqual(w.out.trim().split('\n').filter((n) => !SYNTHESISED.includes(n)), ['HOME', 'LANG', 'PATH', 'TERM', 'VT_CONFINED'])
  // A real override whose value hides another name: only the real one passes, value intact.
  const hidden = `https://a.example/\nVT_RPC_EVIL=http://127.0.0.1:${B}`
  const p = probe(['probe', lo(B)], { env: { ...SNEAKY, VT_RPC_ETH: hidden } })
  assert.equal(p.env.VT_RPC_ETH, hidden)
  assert.ok(!('VT_RPC_EVIL' in p.env) && !('VT_RPC_ALSO_EVIL' in p.env))
  assert.deepEqual(p.outcomes, { [lo(B)]: 'EPERM' })
  // And in the inner branch.
  const q = wrap(['env-names'], { env: { ...SNEAKY, VT_CONFINED: '1' } })
  assert.equal(q.code, 0, q.err)
  assert.deepEqual(q.out.trim().split('\n').filter((n) => !SYNTHESISED.includes(n)), ['HOME', 'LANG', 'PATH', 'TERM', 'VT_CONFINED'])
})

test('wrapper.env-read: an environment that cannot be read (a broken env on PATH) is refused, not skipped', () => {
  const bin = dir('badenv')
  mkdirSync(bin, { recursive: true })
  writeExe(join(bin, 'env'), '#!/bin/sh\nexit 0\n') // prints nothing, succeeds
  refused(wrap(['env-names'], { path: `${bin}:${PATH0}`, env: { VT_RPC_ETH: 'https://a.example/' } }), 'wrapper.env-read')
  refused(wrap(['env-names'], { path: `${bin}:${PATH0}`, env: { VT_CONFINED: '1' } }), 'wrapper.env-read')
})

test('a symlinked wrapper finds its real ROOT (absolute, relative and chained links)', () => {
  const links = dir('links')
  mkdirSync(join(links, 'sub'), { recursive: true })
  const abs = join(links, 'vt-abs')
  const rel = join(links, 'vt-rel')
  const chained = join(links, 'sub', 'vt-chained')
  if (!existsSync(abs)) symlinkSync(WRAPPER, abs)
  if (!existsSync(rel)) symlinkSync(relative(links, WRAPPER), rel)
  if (!existsSync(chained)) symlinkSync('../vt-rel', chained)
  for (const w of [abs, rel, chained]) {
    const r = wrap(['validate-note'], { input: 'hello', wrapper: w })
    assert.equal(r.err, '', w)
    assert.equal(r.out, 'ok 5\n', w)
    assert.equal(r.code, 0, w)
    // The sandbox re-runs the REAL script, not the link.
    assert.equal(recorded(['x'], { wrapper: w }).argv[2], realpathSync(WRAPPER), w)
  }
})

// ---- Task H0 item 1 (K27): --profile / VT_PROFILE are validated before anything is printed, never echoed;
// item 6 (K31): synthetic HOME. The canary IP and the synthetic key must never reach any output, so these
// tests never hand stderr to assert: they compare the guard id and print fixed text only.
const CANARY_IP = '203.0.113.77'
const SYNTH_KEY = 'synthKEY0a1b2c3d4e5f6a7b8c9d0e1f2'
function refusedQuietly(r: Run, id: string, what: string): void {
  const got = /^refused ([a-z0-9.-]+): /m.exec(r.err)?.[1] ?? null
  assert.equal(got, id, what)
  assert.equal(r.code, 2, what)
  const leaked = [CANARY_IP, '203.0.113', SYNTH_KEY, SYNTH_KEY.slice(0, 12)].some((x) => r.err.includes(x) || r.out.includes(x))
  assert.ok(!leaked, `${what}: a canary or synthetic key reached the output`)
}

test('H0-1: a --profile value carrying a URL, an IP or a key is wrapper.profile-invalid, never echoed (with or without VT_PROFILE)', () => {
  const path = `${dir('node')}:${PATH0}`
  for (const bad of [`http://${CANARY_IP}/`, `https://eth.example/v2/${SYNTH_KEY}`, SYNTH_KEY, `${CANARY_IP}`]) {
    refusedQuietly(wrap(['x', '--profile', bad], { path }), 'wrapper.profile-invalid', 'flag alone')
    refusedQuietly(wrap(['x', '--profile', bad], { path, env: { VT_PROFILE: 'testnet' } }), 'wrapper.profile-invalid', 'flag vs VT_PROFILE')
    refusedQuietly(wrap(['x'], { path, env: { VT_PROFILE: bad } }), 'wrapper.profile-invalid', 'VT_PROFILE alone')
    refusedQuietly(wrap(['x', '--profile', 'testnet'], { path, env: { VT_PROFILE: bad } }), 'wrapper.profile-invalid', 'VT_PROFILE vs flag')
    refusedQuietly(wrap(['x', '--rpc', 'eth', '--profile', 'testnet'], { path, env: { VT_PROFILE: bad } }), 'wrapper.profile-invalid', 'VT_PROFILE before a malformed flag')
    // the inner branch (VT_CONFINED=1 by hand) validates too, before node
    refusedQuietly(wrap(['x'], { path, env: { VT_CONFINED: '1', VT_PROFILE: bad } }), 'wrapper.profile-invalid', 'inner branch')
  }
})

test('H0-1: wrapper.profile-conflict names neither value', () => {
  const r = wrap(['x', '--profile', 'local'], { path: `${dir('node')}:${PATH0}`, env: { VT_PROFILE: 'testnet' } })
  refused(r, 'wrapper.profile-conflict')
  assert.ok(!/\b(local|testnet)\b/.test(r.err), 'the conflict message names neither value')
})

test('H0-6 (K31): the wrapper tests run with a synthetic HOME, never the account home', () => {
  assert.notEqual(HOME0, userInfo().homedir)
  assert.ok(HOME0.startsWith(T + '/'), 'HOME is inside this file\'s temp dir')
  assert.ok(statSync(HOME0).isDirectory())
  assert.equal(probe(['report']).home, HOME0, 'the CLI sees the synthetic HOME')
})

// ── Task B-SIGUSR1: node never opens an inspector on SIGUSR1 ───────────────────────────────────
// A default node starts its inspector (127.0.0.1:9229) when it gets SIGUSR1, and a local process could then attach to a
// process that holds a passphrase. The wrapper starts every node with --disable-sigusr1.
test('B-SIGUSR1: the node the wrapper starts gets --disable-sigusr1 first, in the outer and the inner (VT_CONFINED=1) branch', () => {
  for (const env of [undefined, { VT_CONFINED: '1' }]) {
    const p = probe(['report'], env === undefined ? {} : { env })
    assert.deepEqual(p.flags, ['--disable-sigusr1'], `node flags${env === undefined ? '' : ' (inner)'}`)
    assert.ok(p.cli.endsWith('/src/cli.ts'))
    assert.ok(!p.names.includes('NODE_OPTIONS'))
  }
})

const tcp = (port: number, host: string): Promise<string> => new Promise((res) => {
  const s = connect({ host, port })
  const t = setTimeout(() => { s.destroy(); res('timeout') }, 1000)
  s.on('connect', () => { clearTimeout(t); s.destroy(); res('connected') })
  s.on('error', (e: NodeJS.ErrnoException) => { clearTimeout(t); res(e.code ?? 'error') })
})
const sleep = (ms: number) => new Promise<void>((res) => setTimeout(res, ms))

test('B-SIGUSR1: SIGUSR1 to the real wrapper path (keystore init, waiting at its passphrase prompt) opens no inspector on 9229', { timeout: 120_000 }, async () => {
  const out = join(T, 'sigusr1-out')
  const env = { PATH: PATH0, HOME: HOME0, LANG: 'en_US.UTF-8', TERM: 'dumb', VAULT_TIMELOCK_DIR: out }
  for (const host of ['127.0.0.1', '::1']) assert.equal(await tcp(9229, host), 'ECONNREFUSED', `nothing may listen on ${host}:9229 before the test (free the port)`)
  mkdirSync(join(T, 'sigusr1-link'))
  const link = join(T, 'sigusr1-link', 'vt-broadcast')
  symlinkSync(WRAPPER, link)
  const seen: string[] = []
  let signalled = false
  const r = await runInPty([link, 'keystore', 'init', '--profile', 'testnet'], {
    env,
    timeoutMs: 100_000,
    steps: [{
      waitFor: 'Passphrase: ',
      send: '',
      then: async () => {
        // The node process: the child of the script(1) whose command line holds this test's unique symlink to the wrapper.
        const rows = spawnSync('/bin/ps', ['-axwwo', 'pid=,ppid=,command='], { encoding: 'utf8' }).stdout.split('\n').map((l) => {
          const m = /^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(l)
          return m === null ? null : { pid: Number(m[1]), ppid: Number(m[2]), cmd: m[3] }
        }).filter((x) => x !== null)
        const scripts = rows.filter((x) => x.cmd.startsWith('script ') && x.cmd.includes(link))
        assert.equal(scripts.length, 1, 'one script(1) runs this test\'s wrapper link')
        const nodes = rows.filter((x) => x.ppid === scripts[0].pid && x.cmd.includes('src/cli.ts keystore init'))
        assert.equal(nodes.length, 1, 'exactly one node process is waiting at the prompt')
        const pid = nodes[0].pid
        assert.ok(nodes[0].cmd.includes('--disable-sigusr1'), `its command line carries --disable-sigusr1: ${nodes[0].cmd}`)
        process.kill(pid, 'SIGUSR1')
        signalled = true
        for (let i = 0; i < 20; i++) {
          await sleep(150)
          seen.push(await tcp(9229, '127.0.0.1'), await tcp(9229, '::1'))
        }
        try { process.kill(pid, 'SIGKILL') } catch { /* it already ended from the signal */ }
      },
    }],
  })
  assert.ok(signalled, 'the signal was sent')
  assert.ok(seen.length > 0 && seen.every((x) => x === 'ECONNREFUSED'), `an inspector listener appeared on 9229 after SIGUSR1: ${[...new Set(seen)].join(',')}`)
  assert.ok(!r.out.includes('Debugger listening'), 'node announced an inspector')
})

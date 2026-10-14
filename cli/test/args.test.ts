// cli/test/args.test.ts — cli/bin/vt, driven through fakes on PATH (plan Task C1). No real sandbox is applied here
// (this file runs inside the suite sandbox, where macOS refuses another profile); test/wrapper.test.ts does that.
//
// Fakes:
//   fake `node`          -> for src/ops/profile.ts the real node (the profile is real); for anything else a reporter
//                           that prints its argv, its env NAMES and selected values as JSON;
//   fake `sandbox-exec`  -> a recorder: appends its argv and env names to a log, then runs the command WITHOUT a
//                           sandbox (so the inner VT_CONFINED=1 branch runs too, and must not call it again).
// The sh refusals (vt.env, vt.flag, vt.network-invalid, vt.no-sandbox) are asserted by id; the mutation runner blanks
// each one and these tests must fail.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync } from 'node:fs'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { COMMANDS, clientTty, sandboxFor } from '../src/args.ts'
import { commandProfile, denyProtectedFiles, handedIndices, denyTerminals, hardening, loopbackProfile, readAllowList } from '../src/ops/sandbox.ts'
import { scopeFor } from '../src/ops/scope.ts'
import { realPathOf } from '../src/ops/stack.ts'
import { resolve } from 'node:path'
import { CANARY, MAIN, fakeableWrapper, NODE, PATH0, SYNTHESISED, WRAPPER, refused, removeDir, run, tempDir, writeExe } from './lib.ts'
import type { Run } from './lib.ts'

const SYNTH = 'SYNTH-NOT-A-VAULT'
let T = ''
let HOME0 = ''
let FW = ''   // the launcher with sandbox-exec looked up on PATH (fakeableWrapper)
let SELF = ''
const runW = (args: readonly string[], o: Parameters<typeof run>[1] = {}): Run => run(args, { ...o, file: FW })
const dir = (name: string) => join(T, name)
const LOG = () => dir('sandbox-exec.log')

before(() => {
  T = tempDir('vt-args-')
  FW = fakeableWrapper(join(T, 'fw'))
  SELF = realpathSync(FW)
  HOME0 = dir('home')
  mkdirSync(HOME0, { mode: 0o700 })
  // The fake node: a node script (a sh one would add PWD/SHLVL/_ to the names it reports).
  const node = (onProfile: string) => `#!${NODE}
const { spawnSync } = require('node:child_process')
const argv = process.argv.slice(2)
const flags = []
while (argv.length > 0 && argv[0].startsWith('--')) flags.push(argv.shift())
const [cli, ...args] = argv
if (typeof cli === 'string' && cli.endsWith('/src/ops/broker.ts')) {
  const r = spawnSync(${JSON.stringify(NODE)}, [...flags, cli, ...args], { stdio: 'inherit', env: process.env }); process.exit(r.status ?? 1)
} else if (typeof cli === 'string' && cli.endsWith('/src/ops/profile.ts')) {
  ${onProfile}
} else {
  const env = {}
  for (const k of Object.keys(process.env).sort()) if (/^(VT_|LANG$|TERM$|VAULT_TIMELOCK_DIR$|XDG_DATA_HOME$|HOME$|TMPDIR$|TOR_SOCKS$|OP_)/.test(k)) env[k] = process.env[k]
  const names = Object.keys(process.env).filter((n) => !${JSON.stringify(SYNTHESISED)}.includes(n)).sort()
  process.stdout.write(JSON.stringify({ flags, cli, argv: args, names, env }) + '\\n')
}
`
  for (const [d, onProfile] of [
    ['fake', `const r = spawnSync(${JSON.stringify(NODE)}, [cli, ...args], { stdio: 'inherit', env: process.env }); process.exit(r.status ?? 1)`],
    ['fake-fail', 'process.exit(1)'],
    ['fake-open', `process.stdout.write('(version 1)(allow default)')`],
    ['fake-nowrite', `process.stdout.write('(version 1)(allow default)(deny network-outbound)')`],
  ] as const) {
    mkdirSync(dir(d))
    writeExe(join(dir(d), 'node'), node(onProfile))
  }
  // The recorder: a node script (sh would add PWD/SHLVL/_ to the names it sees).
  mkdirSync(dir('rec'))
  writeExe(join(dir('rec'), 'sandbox-exec'), `#!${NODE}
const fs = require('node:fs')
const { spawnSync } = require('node:child_process')
const names = Object.keys(process.env).filter((n) => !${JSON.stringify(SYNTHESISED)}.includes(n)).sort()
fs.appendFileSync(${JSON.stringify(LOG())}, JSON.stringify({ argv: process.argv.slice(2), names }) + '\\n')
const [p, profile, cmd, ...args] = process.argv.slice(2)
if (p !== '-p' || typeof profile !== 'string') process.exit(98)
const r = spawnSync(cmd, args, { stdio: 'inherit', env: process.env })
process.exit(r.status ?? 97)
`)
  // PATH without sandbox-exec: only what the wrapper needs before it refuses, plus the fake node.
  mkdirSync(dir('nosb'))
  for (const tool of ['dirname', 'readlink', 'env', 'tr', 'sed', 'sort']) symlinkSync(`/usr/bin/${tool}`, join(dir('nosb'), tool))
  symlinkSync(join(dir('fake'), 'node'), join(dir('nosb'), 'node'))
  // A `tr` that fails: bin/vt cannot read the environment for OP_SESSION_* (vt.op-session).
  mkdirSync(dir('badtr'))
  writeExe(join(dir('badtr'), 'tr'), '#!/bin/sh\nexit 1\n')
})
after(() => removeDir(T))

const FAKE_PATH = () => `${dir('fake')}:${dir('rec')}:${PATH0}`
interface Report { flags: string[]; cli: string; argv: string[]; names: string[]; env: Record<string, string> }
interface Traced { r: Run; report: Report | null; calls: Array<{ argv: string[]; names: string[] }> }

// The wrapper with the fakes first on PATH and exactly `env` (PATH and HOME default to the fakes and HOME0).
function traced(args: string[], env: Record<string, string | undefined> = {}, fakeDir = 'fake'): Traced {
  rmSync(LOG(), { force: true })
  const r = runW(args, { env: { PATH: `${dir(fakeDir)}:${dir('rec')}:${PATH0}`, HOME: HOME0, ...env } })
  const calls = existsSync(LOG()) ? readFileSync(LOG(), 'utf8').trim().split('\n').map((l) => JSON.parse(l) as { argv: string[]; names: string[] }) : []
  const report = r.code === 0 && r.out !== '' ? JSON.parse(r.out) as Report : null
  if (report !== null) {
    assert.equal(report.cli, join(dir('fw'), 'cli', 'src', 'main.ts'), 'node runs src/main.ts')
    assert.deepEqual(report.flags, report.env.VT_CONFINED === '1' ? ['--disable-sigusr1', '--no-addons'] : ['--disable-sigusr1'], 'node starts as node --disable-sigusr1 (review m-4), and inside the sandbox also --no-addons')
  }
  return { r, report, calls }
}
// PF-C M-3a: every sandboxed command's profile ends with the ticket-key denies of the default $VT_HOME (HOME0/.local/state/vt here)
const OUT0 = (): string => join(HOME0, '.local', 'share', 'vault-timelock')
// bin/vt rewrites the files a sandboxed command is handed to absolute real paths (profile.ts --args); the expected argv of such a command
const REWRITTEN = (args: string[]): string[] => { const idx = new Set(handedIndices(args)); return args.map((a, i) => (idx.has(i) ? realPathOf(resolve(process.cwd(), a)) : a)) }
const VTH = (): string => join(HOME0, '.local', 'state', 'vt')
const DENY = (nets: string[], args: string[] = []): string => {
  const scope = scopeFor(args, { HOME: HOME0, PATH: `${dir('fake')}:${dir('rec')}:${PATH0}` })   // the same function bin/vt's profile.ts uses; the test's cwd is the traced command's cwd
  // TTY-less round: no sandboxed command has a terminal; denyTerminals closes /dev/tty and the pty devices
  return readAllowList(VTH(), nets, scope, OUT0(), false) + denyProtectedFiles(VTH(), OUT0(), nets, scope.userHomes ?? scope.userHome) + hardening(scope, false) + denyTerminals()
}
const NETS_OF = (ports: number[]): string[] => ['local', 'testnet', 'mainnet'].filter((n, i) => ports.some((p) => Math.floor((p - 5180) / 10) === i))
const PLAIN = ['HOME', 'LANG', 'PATH', 'TERM']
const CONFINED = ['HOME', 'LANG', 'PATH', 'TERM', 'VT_CONFINED']
// what the broker passes to sandbox-exec and the sandboxed launcher: + VT_BROKER and VT_TTY (whether the broker has a terminal)
const BROKERED = [...CONFINED, 'VT_BROKER', 'VT_TTY'].sort()

// ---- the file

test('cli/bin/vt is an executable POSIX sh script that parses', () => {
  assert.ok((statSync(WRAPPER).mode & 0o111) !== 0, 'executable')
  assert.equal(readFileSync(WRAPPER, 'utf8').split('\n')[0], '#!/bin/sh')
  const r = spawnSync('/bin/sh', ['-n', WRAPPER], { encoding: 'utf8' })
  assert.equal(r.status, 0, r.stderr)
})

// ---- dispatch: which commands get which sandbox (and the drift check against src/args.ts)

const UNSANDBOXED = [[], ['help'], ['up', '--dev'], ['down'], ['logs', 'relay', '-f'], ['release', 'list'], ['backup', 'import', 'f'],
  ['seal', 'vault', SYNTH, '30d'], ['open', 'file', 'p'], ['note', 'validate'], ['seal-text', 'p'], ['tor-check'], ['keystore', 'init'],
  ['triggers', 'list'], ['bogus'], ['--json', 'status'], ['STATUS']]
const CLIENT = [['status'], ['preflight', '--json'], ['source', 'list'], ['source', 'add', 'x'], ['job'], ['job', 'list'], ['job', 'validate', 'f'],
  ['job', 'status', 'x', '--watch'], ['job', 'watch', 'x'], ['job', 'skip', 'x'], ['job', 'stop', 'x'], ['job', 'resume', 'x'],
  ['job', 'close', 'x', '--chain', 'eth'], ['job', 'receipt', 'x'], ['job', 'bogus']]
// Client commands that read a typed word (C5): the client profile; the broker asks on the terminal (TTY-less round).
const CLIENT_TTY_ARGS = [['job', 'create', 'f', '--message-file', 'm'], ['job', 'arm', 'x'], ['job', 'resolve', 'x', '--chain', 'eth', '--tx', 't', 'mark-done']]
const EXECUTOR = [['job', 'run', 'x'], ['job', 'clawback', 'x', '--chain', 'eth', '--to', 'addr']]

test('orchestration, pass-throughs and unknown words: node runs unsandboxed, with exactly PATH HOME LANG TERM', () => {
  for (const args of UNSANDBOXED) {
    const t = traced(args)
    assert.equal(t.r.code, 0, `${args.join(' ')}: ${t.r.err}`)
    assert.deepEqual(t.calls, [], `${args.join(' ')}: sandbox-exec was not called`)
    assert.deepEqual(t.report?.argv, args)
    assert.deepEqual(t.report?.names, PLAIN)
  }
})

test('client commands: sandbox-exec once with loopbackProfile([page, relay, api]) of the network, then node inside with VT_CONFINED=1 (never nested)', () => {
  const local = '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:5180"))(allow network-outbound (remote ip "localhost:5181"))(allow network-outbound (remote ip "localhost:5182"))(deny file-write*)(allow file-write* (literal "/dev/null"))(deny network-bind)(deny network-inbound)'
  for (const args of CLIENT) {
    const t = traced(args, { VT_NETWORK: 'local' })
    assert.equal(t.r.code, 0, `${args.join(' ')}: ${t.r.err}`)
    assert.deepEqual(t.calls, [{ argv: ['-p', local + DENY(['local'], args), SELF, ...REWRITTEN(args)], names: [...BROKERED, 'VT_NETWORK'].sort() }], args.join(' '))
    assert.deepEqual(t.report?.argv, REWRITTEN(args))
    assert.equal(t.report?.env.VT_CONFINED, '1')
  }
})

test('job create | arm | resolve: the client profile (page, relay, API), no terminal (the broker asks), still no file writes', () => {
  const local = '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:5180"))(allow network-outbound (remote ip "localhost:5181"))(allow network-outbound (remote ip "localhost:5182"))(deny file-write*)(allow file-write* (literal "/dev/null"))(deny network-bind)(deny network-inbound)'
  for (const args of CLIENT_TTY_ARGS) {
    const t = traced(args, { VT_NETWORK: 'local' })
    assert.equal(t.r.code, 0, `${args.join(' ')}: ${t.r.err}`)
    assert.deepEqual(t.calls, [{ argv: ['-p', local + DENY(['local'], args), SELF, ...REWRITTEN(args)], names: [...BROKERED, 'VT_NETWORK'].sort() }], args.join(' '))
    assert.deepEqual(t.report?.argv, REWRITTEN(args))
  }
})

test('job run | job clawback: the executor profile (relay, API, no terminal, no listening)', () => {
  for (const n of ['local', 'testnet', 'mainnet'] as const) {
    for (const args of EXECUTOR) {
      const t = traced(['--network', n, ...args])
      assert.equal(t.r.code, 0, t.r.err)
      assert.equal(t.calls.length, 1)
      assert.equal(t.calls[0].argv[1], commandProfile(args, n, VTH(), OUT0(), scopeFor(args, { HOME: HOME0, PATH: `${dir('fake')}:${dir('rec')}:${PATH0}` })))
      assert.ok(t.calls[0].argv[1].endsWith('(allow file-write* (literal "/dev/null"))(deny network-bind)(deny network-inbound)' + DENY([n], args)), 'C7: the executor never listens; M-3a: it cannot read the ticket keys')
      assert.deepEqual(t.report?.argv, args)
    }
  }
})

test('the sh dispatch agrees with src/args.ts for every command (a drift would fail closed in main.ts, but must not exist)', () => {
  const lines = [...Object.keys(COMMANDS).map((c) => [c]), ...CLIENT, ...CLIENT_TTY_ARGS, ...EXECUTOR, ...UNSANDBOXED]
  for (const args of lines) {
    const t = traced(args)
    assert.equal(t.r.code, 0, `${args.join(' ')}: ${t.r.err}`)
    const want = sandboxFor(args) === 'none' ? [] : [commandProfile(args, undefined, VTH(), OUT0(), scopeFor(args, { HOME: HOME0, PATH: `${dir('fake')}:${dir('rec')}:${PATH0}` }))]
    assert.deepEqual(t.calls.map((c) => c.argv[1]), want, args.join(' '))
  }
})

// ---- --network

test('--network: anywhere, once; becomes VT_NETWORK and the profile\'s ports; removed from the arguments', () => {
  const ports = (...p: number[]) => loopbackProfile(p, { noListen: true }) + DENY(NETS_OF(p)) // Cfix4: client commands never listen
  let t = traced(['--network', 'testnet', 'status', '--json'])
  assert.equal(t.calls[0].argv[1], ports(5190, 5191, 5192))
  assert.deepEqual(t.report?.argv, ['status', '--json'])
  assert.equal(t.report?.env.VT_NETWORK, 'testnet')
  t = traced(['job', 'list', '--network', 'mainnet'])
  assert.equal(t.calls[0].argv[1], ports(5200, 5201, 5202))
  assert.deepEqual(t.report?.argv, ['job', 'list'])
  // From the environment.
  t = traced(['job', 'list'], { VT_NETWORK: 'testnet' })
  assert.equal(t.calls[0].argv[1], ports(5190, 5191, 5192))
  // The same value twice (flag + env) is fine.
  t = traced(['--network', 'testnet', 'job', 'list'], { VT_NETWORK: 'testnet' })
  assert.equal(t.calls[0].argv[1], ports(5190, 5191, 5192))
  // No network: client commands use local, status reaches every stack.
  t = traced(['job', 'list'])
  assert.equal(t.calls[0].argv[1], ports(5180, 5181, 5182))
  assert.ok(!('VT_NETWORK' in (t.report?.env ?? {})))
  t = traced(['status'])
  assert.equal(t.calls[0].argv[1], loopbackProfile([5180, 5181, 5182, 5190, 5191, 5192, 5200, 5201, 5202], { noListen: true }) + DENY(['local', 'testnet', 'mainnet']))
  // An empty VT_NETWORK is unset (not passed on).
  t = traced(['help'], { VT_NETWORK: '' })
  assert.deepEqual(t.report?.names, PLAIN)
  // Orchestration commands get it too.
  t = traced(['up', '--network', 'local'])
  assert.deepEqual(t.report?.argv, ['up'])
  assert.equal(t.report?.env.VT_NETWORK, 'local')
})

const NETWORK_INVALID = 'refused vt.network-invalid: the network must be local, testnet or mainnet (the value is not echoed)\n'
const FLAG = 'refused vt.flag: malformed, repeated or conflicting --network: give it once, as a separate argument (--network local|testnet|mainnet), agreeing with VT_NETWORK when that is set (the values are not echoed)\n'
const BAD_NETWORKS = ['devnet', 'Local', 'mainnet ', ' local', 'local\n', 'loc', 'https://rpc.example/?key=synthetic-secret', CANARY, 'local;x', '*']

test('vt.network-invalid: --network devnet (or any other value) is refused, and the value is never echoed', () => {
  for (const v of BAD_NETWORKS) {
    for (const args of [['--network', v, 'status'], ['help', '--network', v], ['--network', v, 'job', 'run', 'x']]) {
      const t = traced(args)
      refused(t.r, 'vt.network-invalid')
      assert.deepEqual(t.calls, [], 'no sandbox-exec')
      assert.equal(t.r.err, NETWORK_INVALID, 'exactly the fixed line: the value is never echoed')
    }
  }
})

test('vt.network-invalid: VT_NETWORK from the environment is checked too (outside and inside the sandbox branch)', () => {
  for (const v of BAD_NETWORKS) {
    for (const env of [{ VT_NETWORK: v }, { VT_NETWORK: v, VT_CONFINED: '1' }]) {
      const t = traced(['status'], env)
      refused(t.r, 'vt.network-invalid')
      assert.deepEqual(t.calls, [])
      assert.equal(t.r.err, NETWORK_INVALID)
    }
  }
})

test('vt.flag: --network twice, without a value, as --network=x, followed by a flag, or disagreeing with VT_NETWORK', () => {
  const cases: Array<[string[], Record<string, string>]> = [
    [['--network', 'local', '--network', 'local', 'status'], {}],
    [['--network', 'local', 'status', '--network', 'testnet'], {}],
    [['status', '--network'], {}],
    [['--network'], {}],
    [['--network=local', 'status'], {}],
    [['--network=', 'status'], {}],
    [['--network', '--json', 'status'], {}],
    [['--network', '-x', 'status'], {}],
    [['--network', '', 'status'], {}],
    [['--network', 'local', 'status'], { VT_NETWORK: 'testnet' }],
    [['--network', 'mainnet', 'help'], { VT_NETWORK: 'local' }],
  ]
  for (const [args, env] of cases) {
    const t = traced(args, env)
    refused(t.r, 'vt.flag')
    assert.equal(t.r.err, FLAG)
    assert.deepEqual(t.calls, [], args.join(' '))
  }
})

// ---- vt.no-sandbox

test('vt.no-sandbox: no sandbox-exec on PATH -> refused, for every kind of command, and nothing runs', () => {
  for (const args of [['help'], ['status'], ['job', 'run', 'x'], ['seal', 'vault', SYNTH, '30d']]) {
    const r = runW(args, { env: { PATH: dir('nosb'), HOME: HOME0 } })
    refused(r, 'vt.no-sandbox')
  }
})

test('vt.no-sandbox: a profile that cannot be built, or one without the deny-all prefix or the write deny, is never applied', () => {
  for (const fake of ['fake-fail', 'fake-open', 'fake-nowrite']) {
    for (const args of [['status'], ['job', 'run', 'x']]) {
      const t = traced(args, {}, fake)
      refused(t.r, 'vt.no-sandbox')
      assert.deepEqual(t.calls, [], `${fake}: sandbox-exec not called`)
    }
  }
})

// ---- vt.env

test('vt.env: HOME unset or relative, or a PATH with an empty or relative entry -> refused', () => {
  refused(runW(['help'], { env: { PATH: FAKE_PATH() } }), 'vt.env')
  refused(runW(['help'], { env: { PATH: FAKE_PATH(), HOME: 'home' } }), 'vt.env')
  refused(runW(['help'], { env: { PATH: FAKE_PATH(), HOME: '' } }), 'vt.env')
  for (const p of [`${FAKE_PATH()}:`, `:${FAKE_PATH()}`, `${dir('fake')}::${PATH0}`, `bin:${FAKE_PATH()}`, `${FAKE_PATH()}:.`]) {
    refused(runW(['help'], { env: { PATH: p, HOME: HOME0 } }), 'vt.env')
  }
  // PATH unset: sh's own default PATH is not used for anything.
  const r = spawnSync('/bin/sh', [FW, 'help'], { env: { HOME: HOME0 }, encoding: 'utf8' })
  assert.equal(r.status, 2)
  assert.match(r.stderr, /^refused vt\.env: /m)
})

// ---- env -i

const HOSTILE = {
  ALCHEMY_API_KEY: 'synthetic', FOO: '1', DEBUG: 'socks-proxy-agent', NODE_OPTIONS: '--require /nonexistent.cjs',
  NODE_EXTRA_CA_CERTS: '/nonexistent.pem', HTTPS_PROXY: 'http://proxy.invalid:1', ALL_PROXY: 'socks5h://proxy.invalid:1',
  NODE_TEST_CONTEXT: 'child-v8', VT_PROFILE: 'mainnet', VT_RPC_ETH: 'https://rpc.example/', VT_DEBUG: '1', TMPDIR: '/tmp/x',
  NODE_ENV: 'test', VT_TEST_PORTS: 'api=3,relay=2', // main()'s test-only ports seam (M1): bin/vt never passes either
}

test('env -i: none of ALCHEMY_API_KEY, NODE_OPTIONS, HTTPS_PROXY, … reaches sandbox-exec or node; the allowlist passes when set', () => {
  for (const args of [['help'], ['status'], ['job', 'run', 'x']]) {
    const t = traced(args, HOSTILE)
    assert.equal(t.r.code, 0, t.r.err)
    const sandboxed = sandboxFor(args) !== 'none'
    assert.deepEqual(t.report?.names, sandboxed ? BROKERED : PLAIN, args.join(' '))
    if (sandboxed) assert.deepEqual(t.calls[0].names, BROKERED)
  }
  const passed = { VT_HOME: '/tmp/vt-h', VAULT_TIMELOCK_DIR: '/tmp/vt-o', XDG_DATA_HOME: '', VT_NETWORK: 'testnet', VT_SEALER: '', LANG: 'C', TERM: 'xterm' }
  const all = [...BROKERED, 'VAULT_TIMELOCK_DIR', 'VT_HOME', 'VT_NETWORK', 'VT_SEALER', 'XDG_DATA_HOME'].sort()
  const t = traced(['status'], { ...HOSTILE, ...passed })
  assert.deepEqual(t.calls[0].names, all)
  assert.deepEqual(t.report?.names, all)
  assert.deepEqual(t.report?.env, { HOME: HOME0, LANG: 'C', TERM: 'xterm', VAULT_TIMELOCK_DIR: '/tmp/vt-o', VT_BROKER: '1', VT_CONFINED: '1', VT_HOME: '/tmp/vt-h', VT_NETWORK: 'testnet', VT_SEALER: '', VT_TTY: '0', XDG_DATA_HOME: '' })
})

test('env -i: LANG and TERM get defaults when unset; a value holding "\\nNAME=…" stays a value', () => {
  let t = traced(['help'])
  assert.equal(t.report?.env.LANG, 'en_US.UTF-8')
  assert.equal(t.report?.env.TERM, 'dumb')
  const v = '/tmp/vt-h\nNODE_OPTIONS=--require /nonexistent.cjs\nVT_CONFINED=1'
  t = traced(['help'], { VT_HOME: v, VAULT_TIMELOCK_DIR: '/tmp/o\nALL_PROXY=socks5h://proxy.invalid:1' })
  assert.equal(t.r.code, 0, t.r.err)
  assert.deepEqual(t.report?.names, [...PLAIN, 'VAULT_TIMELOCK_DIR', 'VT_HOME'].sort())
  assert.equal(t.report?.env.VT_HOME, v)
})

test('VT_CONFINED=1 from the caller: straight to node (no sandbox-exec), with the environment rebuilt', () => {
  const t = traced(['status', '--network', 'local'], { ...HOSTILE, VT_CONFINED: '1' })
  assert.equal(t.r.code, 0, t.r.err)
  assert.deepEqual(t.calls, [])
  assert.deepEqual(t.report?.names, CONFINED)
  // Inside, --network is not a flag any more (main.ts sees it as an argument and fails closed).
  assert.deepEqual(t.report?.argv, ['status', '--network', 'local'])
})

// ---- arguments

test('the rebuilt arguments keep spaces, empty strings, "=", tabs and newlines intact', () => {
  const args = ['job', 'create', 'a b', '', 'x=y', '-z', 'tab\there', 'new\nline', "q'uote", '$HOME', '*']
  const t = traced([...args.slice(0, 3), '--network', 'local', ...args.slice(3)])
  assert.equal(t.r.code, 0, t.r.err)
  assert.deepEqual(t.report?.argv, REWRITTEN(args))
  assert.deepEqual(t.calls[0].argv.slice(3), REWRITTEN(args))
})

// ---- the real main.ts behind a sandbox-exec that drops the profile

test('a sandbox-exec that drops the profile: the real main.ts refuses vt.not-confined', () => {
  rmSync(LOG(), { force: true })
  const r = runW(['status'], { env: { PATH: `${dir('rec')}:${PATH0}`, HOME: HOME0, VT_HOME: dir('vt-home'), VAULT_TIMELOCK_DIR: dir('out') } })
  refused(r, 'vt.not-confined')
  assert.equal(readFileSync(LOG(), 'utf8').trim().split('\n').length, 1, 'the recorder ran once')
})

// ---- vt seal|open: the sealer's settings (controller ruling (1), C1 fix round 1). The fake node stands in for
// src/main.ts, so nothing is sealed or started here; test/passthrough.test.ts checks what the stub sealer receives.

const SETTINGS = { TMPDIR: '/tmp/vt-operator-tmp', TOR_SOCKS: '127.0.0.1:9150', OP_ACCOUNT: 'synthetic.example', OP_SESSION_synth: 'synthetic-a', OP_SESSION_TEAM_2: 'synthetic-b' }
const STRIPPED = { OP_SERVICE_ACCOUNT_TOKEN: 'synthetic-sa-token', OP_CONNECT_HOST: 'http://connect.invalid', OP_CONNECT_TOKEN: 'synthetic-connect-token' }
const SETTING_NAMES = ['OP_ACCOUNT', 'OP_SESSION_TEAM_2', 'OP_SESSION_synth', 'TMPDIR', 'TOR_SOCKS']
const NOTE = 'vt: note: OP_SERVICE_ACCOUNT_TOKEN / OP_CONNECT_* are set in your environment and were NOT passed to the sealer (service-account and Connect credentials never reach it)\n'
const TOR_SOCKS_REFUSAL = 'refused vt.tor-socks: TOR_SOCKS must be a loopback SOCKS address, 127.0.0.1:<port> or [::1]:<port> (the value is not echoed)\n'
const OP_SESSION_REFUSAL = 'refused vt.op-session: could not read the environment, or an OP_SESSION_* variable has a name outside A-Z a-z 0-9 _ (names and values are not echoed)\n'

test('vt seal|open: TMPDIR, TOR_SOCKS, OP_ACCOUNT and OP_SESSION_* reach node, values intact; nothing else does', () => {
  for (const args of [['seal', 'vault', SYNTH, '30d'], ['open', 'file', 'p'], ['--network', 'local', 'seal', 'file', '-']]) {
    const t = traced(args, { ...HOSTILE, ...SETTINGS })
    assert.equal(t.r.code, 0, t.r.err)
    assert.equal(t.r.err, '', 'no note, nothing printed by bin/vt')
    assert.deepEqual(t.calls, [])
    const net = args[0] === '--network' ? ['VT_NETWORK'] : []
    assert.deepEqual(t.report?.names, [...PLAIN, ...SETTING_NAMES, ...net].sort())
    for (const [k, v] of Object.entries(SETTINGS)) assert.equal(t.report?.env[k], v, k)
  }
  // One at a time; an empty TMPDIR or OP_ACCOUNT is passed as set; [::1] is loopback too; the port bounds hold.
  for (const [k, v] of [['TMPDIR', ''], ['OP_ACCOUNT', ''], ['TOR_SOCKS', '[::1]:9050'], ['TOR_SOCKS', '127.0.0.1:1'], ['TOR_SOCKS', '[::1]:65535'], ['OP_SESSION_a', '']]) {
    const t = traced(['seal', 'vault', SYNTH], { [k]: v })
    assert.equal(t.r.code, 0, t.r.err)
    assert.deepEqual(t.report?.names, [...PLAIN, k].sort())
    assert.equal(t.report?.env[k], v)
  }
  // A value holding "\nNAME=…" stays a value.
  const v = 'synthetic\nOP_SERVICE_ACCOUNT_TOKEN=x\nNODE_OPTIONS=--require /nonexistent.cjs'
  const t = traced(['seal', 'vault', SYNTH], { OP_SESSION_synth: v })
  assert.equal(t.r.err, '', 'no note: the token name was inside a value')
  assert.deepEqual(t.report?.names, [...PLAIN, 'OP_SESSION_synth'].sort())
  assert.equal(t.report?.env.OP_SESSION_synth, v)
})

test('every other command gets none of the sealer\'s settings, and no note (a bad TOR_SOCKS is simply not passed)', () => {
  for (const args of [['help'], ['status'], ['job', 'run', 'x'], ['note', 'validate'], ['triggers', 'list'], ['up'], ['seal-text', 'p'], ['keystore', 'init']]) {
    const t = traced(args, { ...SETTINGS, ...STRIPPED, TOR_SOCKS: 'not-loopback', 'OP_SESSION_a-b': 'x' })
    assert.equal(t.r.code, 0, t.r.err)
    assert.equal(t.r.err, '', args.join(' '))
    assert.deepEqual(t.report?.names, sandboxFor(args) === 'none' ? PLAIN : BROKERED, args.join(' '))
  }
})

test('OP_SERVICE_ACCOUNT_TOKEN and OP_CONNECT_*: stripped for seal|open, with one fixed note naming no value', () => {
  for (const env of [STRIPPED, { OP_SERVICE_ACCOUNT_TOKEN: 'synthetic-sa-token' }, { OP_CONNECT_HOST: 'http://connect.invalid' }, { OP_CONNECT_X: '' }]) {
    for (const args of [['seal', 'vault', SYNTH, '30d'], ['open', 'vault', 'p']]) {
      const t = traced(args, { ...env, OP_SESSION_synth: 'synthetic-a' })
      assert.equal(t.r.code, 0, t.r.err)
      assert.equal(t.r.err, NOTE)
      assert.deepEqual(t.report?.names, [...PLAIN, 'OP_SESSION_synth'].sort())
    }
  }
})

test('vt.tor-socks: a TOR_SOCKS that is not a literal loopback host:port is refused for seal|open, never echoed', () => {
  for (const v of ['', 'localhost:9050', `${CANARY}:9050`, '198.51.100.7:9050', '127.0.0.1', '127.0.0.1:', '127.0.0.1:0', '127.0.0.1:65536', '127.0.0.1:09050',
    '127.0.0.1:123456', '127.0.0.1:9050 ', ' 127.0.0.1:9050', '127.0.0.1:9050\n', '127.0.0.1.evil.example:9050', 'socks5h://127.0.0.1:9050', '[::1]', '[::1]:x', '::1:9050', '0.0.0.0:9050']) {
    for (const args of [['seal', 'vault', SYNTH, '30d'], ['open', 'file', 'p']]) {
      const t = traced(args, { TOR_SOCKS: v })
      refused(t.r, 'vt.tor-socks')
      assert.equal(t.r.err, TOR_SOCKS_REFUSAL)
    }
  }
})

test('vt.op-session: an OP_SESSION_* name outside A-Z a-z 0-9 _, or an environment bin/vt cannot read, is refused', () => {
  for (const name of ['OP_SESSION_', 'OP_SESSION_a-b', 'OP_SESSION_a.b', 'OP_SESSION_a b', 'OP_SESSION_\u00e9']) {
    const t = traced(['seal', 'vault', SYNTH, '30d'], { [name]: 'synthetic' })
    refused(t.r, 'vt.op-session')
    assert.equal(t.r.err, OP_SESSION_REFUSAL)
  }
  const r = runW(['open', 'vault', 'p'], { env: { PATH: `${dir('badtr')}:${FAKE_PATH()}`, HOME: HOME0, OP_SESSION_synth: 'synthetic' } })
  refused(r, 'vt.op-session')
  // Positive control: the same PATH (the failing tr) is fine for a command that never reads the environment.
  assert.equal(runW(['help'], { env: { PATH: `${dir('badtr')}:${FAKE_PATH()}`, HOME: HOME0 } }).code, 0)
})

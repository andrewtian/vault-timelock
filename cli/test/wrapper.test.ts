// cli/test/wrapper.test.ts — cli/bin/vt with the REAL sandbox-exec (plan Task C1): env -i, the per-command profile,
// never nesting, the symlinks, and the vt-broadcast pass-throughs end to end.
// This file applies sandboxes itself, so it runs OUTSIDE the suite sandbox (test/own-sandbox.list; scripts/test-root.sh
// phase B): macOS refuses to apply a profile inside a sandbox.
// ★ No packet leaves the machine: TEST-NET-1 is probed only from inside the wrapper's sandbox (EPERM at connect), and
//   every unsandboxed confinement proof stops at loopback port 9. Tor is never probed and tor-check is never run.
//   The sealer is never run here (test/passthrough.test.ts runs the stub).
// Fakes on PATH (node scripts: a sh fake would add PWD/SHLVL/_ to what it reports):
//   fake `node` "env"    -> prints `env -0` of what it was given (NUL-safe), for src/main.ts; the real node for
//                           src/ops/profile.ts (the profile is real);
//   fake `node` "probe"  -> from inside the real sandbox: TCP connects, file writes, /dev/tty;
//   fake `sandbox-exec`  -> a nesting tripwire (marker + exit 99), or one that drops the profile.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, lstatSync, mkdirSync, openSync, readFileSync, readlinkSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { createServer, type Server } from 'node:net'
import { dirname, join } from 'node:path'
import { helpText } from '../src/help.ts'
import { fakeableWrapper, CLI, MAIN, NODE, PATH0, SYNTHESISED, WRAPPER, refused, removeDir, run, tempDir, writeExe } from './lib.ts'
import type { Run } from './lib.ts'

let T = ''
let HOME0 = ''
let L = 0 // a test-owned 127.0.0.1 listener no vt profile allows
const servers: Server[] = []
const dir = (name: string) => join(T, name)
const TEST_NET = '192.0.2.1:9'

before(async () => {
  T = tempDir('vt-wrapper-')
  HOME0 = dir('home')
  mkdirSync(HOME0, { mode: 0o700 })
  const s = createServer((c) => c.end())
  servers.push(s)
  await new Promise<void>((res) => s.listen(0, '127.0.0.1', () => res()))
  const a = s.address()
  if (a === null || typeof a === 'string') throw new Error('no port')
  L = a.port

  const fakeNode = (body: string) => `#!${NODE}
const { spawnSync } = require('node:child_process')
const argv = process.argv.slice(2)
const flags = []
while (argv.length > 0 && argv[0].startsWith('--')) flags.push(argv.shift())
const [cli, ...args] = argv
if (typeof cli === 'string' && cli.endsWith('/src/ops/profile.ts')) {
  const r = spawnSync(${JSON.stringify(NODE)}, [cli, ...args], { stdio: 'inherit', env: process.env })
  process.exit(r.status ?? 1)
}
if (typeof cli === 'string' && cli.endsWith('/src/ops/broker.ts')) {
  const r = spawnSync(${JSON.stringify(NODE)}, [...flags, cli, ...args], { stdio: 'inherit', env: process.env })
  process.exit(r.status ?? 1)
}
${body}
`
  mkdirSync(dir('env'))
  writeExe(join(dir('env'), 'node'), fakeNode(`
// NUL bytes would be stripped by the broker's output filter (terminal control characters): the separator is a printable ASCII marker
const SEP = '@@SEP@@'
// (the sandboxed process may not fork, so the environment is read in-process)
process.stdout.write(JSON.stringify(flags) + SEP + cli + SEP + Object.entries(process.env).map(([k, v]) => k + '=' + v).join(SEP))
process.exit(0)
`))
  mkdirSync(dir('probe'))
  writeExe(join(dir('probe'), 'node'), fakeNode(`
const net = require('node:net')
const fs = require('node:fs')
;(async () => {
  const out = {}
  for (const spec of args) {
    const [kind, target] = spec.split('=')
    if (kind === 'tcp') {
      const i = target.lastIndexOf(':')
      out[spec] = await new Promise((res) => {
        const s = net.connect({ host: target.slice(0, i), port: Number(target.slice(i + 1)) })
        const timer = setTimeout(() => { s.destroy(); res('timeout') }, 3000)
        s.on('connect', () => { clearTimeout(timer); s.destroy(); res('connected') })
        s.on('error', (e) => { clearTimeout(timer); res(e.code || 'error') })
      })
    } else if (kind === 'listen') {
      out[spec] = await new Promise((res) => {
        const srv = net.createServer()
        srv.on('error', (e) => res(e.code || 'error'))
        srv.listen(0, '127.0.0.1', () => { srv.close(); res('listening') })
      })
    } else if (kind === 'write') {
      try { fs.writeFileSync(target, 'x'); out[spec] = 'ok' } catch (e) { out[spec] = e.code }
    } else if (kind === 'open-rw') {
      try { fs.closeSync(fs.openSync(target, fs.constants.O_RDWR | fs.constants.O_NOCTTY)); out[spec] = 'ok' } catch (e) { out[spec] = e.code }
    }
  }
  process.stdout.write(JSON.stringify({ cli, confined: process.env.VT_CONFINED || null, out }) + '\\n')
})()
`))
  mkdirSync(dir('nest'))
  writeExe(join(dir('nest'), 'sandbox-exec'), `#!/bin/sh\n: > '${dir('nested.marker')}'\nexit 99\n`)
  mkdirSync(dir('noop'))
  writeExe(join(dir('noop'), 'sandbox-exec'), `#!/bin/sh\n[ "$1" = -p ] || exit 98\nshift 2\nexec "$@"\n`)
})
after(async () => {
  for (const s of servers) await new Promise<void>((res) => s.close(() => res()))
  removeDir(T)
})

const BASE_ENV = () => ({ PATH: PATH0, HOME: HOME0, VT_HOME: dir('vt-home'), VAULT_TIMELOCK_DIR: dir('out') })

// `env -0` as the fake node saw it: the script it was asked to run, and the names, NUL-separated (a value with a
// newline cannot fake a name).
function envNames(args: string[], env: Record<string, string>): { flags: string[]; cli: string; names: string[]; values: Record<string, string> } {
  const r = run(args, { env: { ...env, PATH: `${dir('env')}:${PATH0}` } })
  assert.equal(r.code, 0, r.err)
  const [flags, cli, ...records] = r.out.split('@@SEP@@').filter((x) => x !== '')
  const values: Record<string, string> = {}
  for (const rec of records) {
    const i = rec.indexOf('=')
    values[rec.slice(0, i)] = rec.slice(i + 1)
  }
  return { flags: JSON.parse(flags) as string[], cli, names: Object.keys(values).filter((n) => !SYNTHESISED.includes(n)).sort(), values }
}

// ---- symlinks

test('bin/vt at the repository root is a symlink to cli/bin/vt, and runs the real tree', () => {
  const root = join(dirname(CLI), 'bin', 'vt')
  assert.ok(lstatSync(root).isSymbolicLink())
  assert.equal(readlinkSync(root), '../cli/bin/vt')
  assert.equal(realpathSync(root), realpathSync(WRAPPER))
  const r = run(['help'], { file: root, env: { PATH: PATH0, HOME: HOME0 } })
  assert.equal(r.code, 0, r.err)
  assert.equal(r.out, helpText())
})

test('a chain of links (absolute and relative) on PATH runs the real tree; sandbox-exec re-runs the real script', () => {
  mkdirSync(dir('links'))
  symlinkSync(join(dirname(CLI), 'bin', 'vt'), dir('links/vt-abs'))
  symlinkSync('vt-abs', dir('links/vt'))
  const r = spawnSync('vt', ['help'], { env: { PATH: `${dir('links')}:${PATH0}`, HOME: HOME0 }, encoding: 'utf8' })
  assert.equal(r.status, 0, r.stderr)
  assert.equal(r.stdout, helpText())
  // A client command through the link: the real sandbox, then the real main.ts (vt status: no stack is up here).
  const s = spawnSync('vt', ['status'], { env: { ...BASE_ENV(), PATH: `${dir('links')}:${PATH0}` }, encoding: 'utf8' })
  assert.equal(s.stderr, '')
  assert.equal(s.stdout, 'local    down\ntestnet  down\nmainnet  down\n')
  assert.equal(s.status, 0)
})

// ---- env -i, through the real sandbox

const HOSTILE = {
  ALCHEMY_API_KEY: 'synthetic', NODE_OPTIONS: '--require /nonexistent.cjs', HTTPS_PROXY: 'http://proxy.invalid:1',
  ALL_PROXY: 'socks5h://proxy.invalid:1', DEBUG: 'socks-proxy-agent', NODE_EXTRA_CA_CERTS: '/nonexistent.pem', NODE_TEST_CONTEXT: 'child-v8',
  VT_PROFILE: 'mainnet', VT_RPC_ETH: 'https://rpc.example/', FOO: '1', LANG: 'C', TERM: 'xterm',
}

test('ALCHEMY_API_KEY, NODE_OPTIONS and HTTPS_PROXY never reach node (a stub prints env -0 names), sandboxed or not', () => {
  const env = { PATH: PATH0, HOME: HOME0, ...HOSTILE }
  for (const [args, names] of [
    [['help'], ['HOME', 'LANG', 'PATH', 'TERM']],
    [['up', '--network', 'local'], ['HOME', 'LANG', 'PATH', 'TERM', 'VT_NETWORK']],
    [['status'], ['HOME', 'LANG', 'PATH', 'TERM', 'VT_BROKER', 'VT_CONFINED', 'VT_TTY']],
    [['job', 'run', 'x'], ['HOME', 'LANG', 'PATH', 'TERM', 'VT_BROKER', 'VT_CONFINED', 'VT_TTY']],
  ] as const) {
    const e = envNames([...args], env)
    assert.equal(e.cli, realpathSync(MAIN))
    assert.deepEqual(e.flags, (names as readonly string[]).includes('VT_CONFINED') ? ['--disable-sigusr1', '--no-addons'] : ['--disable-sigusr1'], `${args.join(' ')}: node --disable-sigusr1 (review m-4); sandboxed also --no-addons`)
    assert.deepEqual(e.names, names, args.join(' '))
    assert.equal(e.values.LANG, 'C')
  }
})

test('the allowlist passes when set, values intact; a value holding "\\nNAME=…" stays a value', () => {
  const v = `${dir('vt-home')}\nNODE_OPTIONS=--require /nonexistent.cjs\nALCHEMY_API_KEY=synthetic`
  // `help` runs unsandboxed: a sandboxed command with such a VT_HOME is refused (vt.path: the profile now names $VT_HOME, PF-C M-3a)
  const e = envNames(['help'], { PATH: PATH0, HOME: HOME0, ...HOSTILE, VT_HOME: v, VAULT_TIMELOCK_DIR: dir('out'), XDG_DATA_HOME: '', VT_NETWORK: 'testnet', VT_SEALER: '' })
  assert.deepEqual(e.names, ['HOME', 'LANG', 'PATH', 'TERM', 'VAULT_TIMELOCK_DIR', 'VT_HOME', 'VT_NETWORK', 'VT_SEALER', 'XDG_DATA_HOME'])
  assert.equal(e.values.VT_HOME, v)
  assert.equal(e.values.VT_CONFINED, undefined)
})

test('M-5: hostile environment values are driven through a SANDBOXED command too: only the allowlist reaches node, values intact', () => {
  const e = envNames(['status'], { PATH: PATH0, HOME: HOME0, ...HOSTILE, VT_HOME: dir('vt-home'), VAULT_TIMELOCK_DIR: dir('out'), XDG_DATA_HOME: '', VT_NETWORK: 'testnet', VT_SEALER: '' })
  assert.deepEqual(e.names, ['HOME', 'LANG', 'PATH', 'TERM', 'VAULT_TIMELOCK_DIR', 'VT_BROKER', 'VT_CONFINED', 'VT_HOME', 'VT_NETWORK', 'VT_SEALER', 'VT_TTY', 'XDG_DATA_HOME'])
  assert.equal(e.values.VT_HOME, dir('vt-home'))
  assert.equal(e.values.VT_CONFINED, '1')
  for (const k of Object.keys(HOSTILE)) if (!['LANG', 'TERM'].includes(k)) assert.equal(e.values[k], undefined, k)
})

// I-1: a redirected stdout/stderr (`vt job receipt <id> --json > receipt.json`) must not abort the sandboxed node (it fstat()s fds 0-2 at start)
test('I-1: stdout and stderr redirected to REGULAR FILES (and /dev/null, a pipe) work for client commands; stdin from a file too', () => {
  const d = dir('redir')
  mkdirSync(d, { recursive: true })
  const outF = join(d, 'status out (1).json'), errF = join(d, 'err.txt'), inF = join(d, 'in.txt')
  writeFileSync(inF, '')
  const open = (f: string, flag: string): number => openSync(f, flag, 0o600)
  const go = (args: string[], stdio: Array<number | 'ignore' | 'pipe'>) => spawnSync(WRAPPER, args, { env: { ...BASE_ENV(), PATH: PATH0 }, stdio, encoding: 'utf8', timeout: 60_000 })
  for (const args of [['--network', 'local', 'status', '--json'], ['--network', 'local', 'preflight', '--json'], ['--network', 'local', 'job', 'list']]) {
    const a = go(args, ['ignore', open(outF, 'w'), open(errF, 'w')])
    assert.notEqual(a.signal, 'SIGABRT', args.join(' '))
    assert.ok(a.status === 0 || a.status === 1, `${args.join(' ')}: exit ${String(a.status)}`)
    assert.ok(readFileSync(outF, 'utf8') + readFileSync(errF, 'utf8') !== '', `${args.join(' ')}: something was written to the files`)
    assert.ok(!/Native stack trace/.test(readFileSync(outF, 'utf8') + readFileSync(errF, 'utf8')))
    const b = go(args, [open(inF, 'r'), 'ignore', 'ignore'])   // stdin from a file, output discarded
    assert.ok(b.status === 0 || b.status === 1, `stdin file: ${String(b.status)}`)
    const c = go(args, ['pipe', 'pipe', 'pipe'])
    assert.ok(c.status === 0 || c.status === 1)
    assert.equal(c.stdout + c.stderr === '', false)
  }
  // the file really received the command's own output (the receipt use case)
  const r = go(['--network', 'local', 'status', '--json'], ['ignore', open(outF, 'w'), 'ignore'])
  assert.ok(r.status === 0 || r.status === 1)
  assert.match(readFileSync(outF, 'utf8'), /"network": "local"/)
})

// ---- the sandbox each command gets

interface ProbeOut { cli: string; confined: string | null; out: Record<string, string> }
function probe(args: string[], specs: string[], env: Record<string, string> = {}): ProbeOut {
  const r = run([...args, ...specs], { env: { PATH: `${dir('probe')}:${PATH0}`, HOME: HOME0, ...env } })
  assert.equal(r.code, 0, r.err)
  return JSON.parse(r.out) as ProbeOut
}

test('a client command: the real sandbox denies 192.0.2.1:9, loopback 9, any other loopback port, file writes and /dev/tty', () => {
  const file = dir('client-write')
  for (const args of [['status'], ['--network', 'testnet', 'job', 'list'], ['preflight', '--network', 'mainnet']]) {
    const p = probe(args, [`tcp=${TEST_NET}`, 'tcp=127.0.0.1:9', `tcp=127.0.0.1:${L}`, `write=${file}`, 'write=/dev/null', 'open-rw=/dev/tty'])
    assert.equal(p.confined, '1')
    assert.deepEqual(p.out, {
      [`tcp=${TEST_NET}`]: 'EPERM', 'tcp=127.0.0.1:9': 'EPERM', [`tcp=127.0.0.1:${L}`]: 'EPERM',
      [`write=${file}`]: 'EPERM', 'write=/dev/null': 'ok', 'open-rw=/dev/tty': 'EPERM',
    }, args.join(' '))
  }
  assert.ok(!existsSync(file))
})

test('job run | clawback: the same walls, and NO terminal either (TTY-less round: /dev/tty is EPERM)', () => {
  const file = dir('executor-write')
  for (const args of [['job', 'run', 'x'], ['job', 'clawback', 'x']]) {
    const p = probe(args, [`tcp=${TEST_NET}`, `tcp=127.0.0.1:${L}`, `write=${file}`, 'open-rw=/dev/tty'])
    assert.equal(p.confined, '1')
    assert.equal(p.out[`tcp=${TEST_NET}`], 'EPERM')
    assert.equal(p.out[`tcp=127.0.0.1:${L}`], 'EPERM')
    assert.equal(p.out[`write=${file}`], 'EPERM')
    assert.equal(p.out['open-rw=/dev/tty'], 'EPERM', 'the broker owns the terminal, the sandboxed process has none')
  }
})

test('C7 (parked from C6 fix 1): the executor sandbox also denies listening (network-bind); the unsandboxed control still listens', () => {
  for (const args of [['job', 'run', 'x'], ['job', 'clawback', 'x']]) {
    const p = probe(args, ['listen=127.0.0.1', `tcp=${TEST_NET}`])
    assert.equal(p.confined, '1')
    assert.equal(p.out['listen=127.0.0.1'], 'EPERM', `${args.join(' ')}: an executor attempting to listen is refused`)
    assert.equal(p.out[`tcp=${TEST_NET}`], 'EPERM')
  }
  // Controls: the same attempt succeeds unsandboxed and in a client sandbox, so the refusal above is the profile's.
  assert.equal(probe(['help'], ['listen=127.0.0.1']).out['listen=127.0.0.1'], 'listening')
})

test('Cfix4 (C1 review M3): the client sandbox (status, preflight, job list | arm | create) also refuses to listen', () => {
  for (const args of [['status'], ['preflight'], ['job', 'list'], ['job', 'arm', 'x'], ['job', 'create', 'f']]) {
    const p = probe(args, ['listen=127.0.0.1', `tcp=${TEST_NET}`])
    assert.equal(p.confined, '1', args.join(' '))
    assert.equal(p.out['listen=127.0.0.1'], 'EPERM', `${args.join(' ')}: a client attempting to listen is refused`)
    assert.equal(p.out[`tcp=${TEST_NET}`], 'EPERM')
  }
})

test('job create | arm | resolve (C5): the client walls, and no terminal (the broker asks the typed word)', () => {
  const file = dir('arm-write')
  for (const args of [['job', 'create', 'f'], ['job', 'arm', 'x'], ['--network', 'mainnet', 'job', 'resolve', 'x']]) {
    const p = probe(args, [`tcp=${TEST_NET}`, `tcp=127.0.0.1:${L}`, `write=${file}`, 'write=/dev/null', 'open-rw=/dev/tty'])
    assert.equal(p.confined, '1')
    assert.equal(p.out[`tcp=${TEST_NET}`], 'EPERM')
    assert.equal(p.out[`tcp=127.0.0.1:${L}`], 'EPERM')
    assert.equal(p.out[`write=${file}`], 'EPERM')
    assert.equal(p.out['write=/dev/null'], 'ok')
    assert.equal(p.out['open-rw=/dev/tty'], 'EPERM', 'the broker owns the terminal, the sandboxed process has none')
  }
  // The page port stays reachable for them (a client profile), another network's stays denied.
  const arm = probe(['--network', 'local', 'job', 'arm', 'x'], ['tcp=127.0.0.1:5180', 'tcp=127.0.0.1:5190'])
  assert.notEqual(arm.out['tcp=127.0.0.1:5180'], 'EPERM')
  assert.equal(arm.out['tcp=127.0.0.1:5190'], 'EPERM')
})

test('positive control: an orchestration command runs unsandboxed (the listener is reachable, a file can be written)', () => {
  const file = dir('orchestration-write')
  const p = probe(['help'], [`tcp=127.0.0.1:${L}`, `write=${file}`])
  assert.equal(p.confined, null)
  assert.deepEqual(p.out, { [`tcp=127.0.0.1:${L}`]: 'connected', [`write=${file}`]: 'ok' })
  rmSync(file, { force: true })
})

test('the real main.ts inside the real sandbox proves its confinement and goes on (vt preflight with no stack up: C7)', () => {
  const r0 = run(['preflight'], { env: BASE_ENV() })
  assert.equal(r0.err, '')
  assert.equal(r0.code, 1)
  assert.match(r0.out, /^vt preflight — network local\n {2}✗ {2}The local stack is up — no local stack is up; start it with: vt up --network local\n/)
  assert.match(r0.out, /1 check failing · exit 1\n$/)
  const r1 = run(['preflight', '--network', 'mainnet', '--json'], { env: BASE_ENV() })
  assert.equal(r1.code, 1)
  assert.deepEqual([JSON.parse(r1.out).network, JSON.parse(r1.out).up, JSON.parse(r1.out).exit], ['mainnet', false, 1])
  // C6: vt job run / clawback inside the REAL executor sandbox: past the confinement proof (EPERM on 192.0.2.1:9 and on
  // a loopback port it may not reach), then refused at once without a terminal (stdin is a pipe here): nothing read.
  for (const args of [['job', 'run', '0123456789abcdef', '--backup-eth', 'never-read.age'], ['job', 'clawback', '0123456789abcdef', '--chain', 'eth', '--to', '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6', '--backup-eth', 'never-read.age']]) {
    const r = run(args, { env: BASE_ENV(), input: 'c6-not-a-passphrase\n' })
    refused(r, 'vt.tty-required')
    assert.ok(!r.err.includes('c6-not-a-passphrase'))
  }
  // vt job list with no mainnet stack: no API token to read, so nothing is contacted (exit 1, a plain error).
  const l = run(['--network', 'mainnet', 'job', 'list'], { env: BASE_ENV() })
  assert.equal(l.err, 'vt: error: no readable API token for mainnet: is the mainnet stack up? (vt up --network mainnet)\n')
  assert.equal(l.code, 1)
  const r = run(['status', '--json'], { env: BASE_ENV() })
  assert.equal(r.code, 0, r.err)
  assert.deepEqual((JSON.parse(r.out) as Array<{ network: string; up: boolean }>).map((e) => [e.network, e.up]), [['local', false], ['testnet', false], ['mainnet', false]])
  assert.equal(run(['--network', 'testnet', 'status'], { env: BASE_ENV() }).code, 1, 'a named network that is not up: exit 1')
})

test('ruling (2): a client command reaches its network\'s PAGE port too (connect not denied); the executor does not', () => {
  // Nothing needs to listen: a denied connect is EPERM at once; an allowed one to a closed port is ECONNREFUSED.
  const client = probe(['--network', 'local', 'status'], ['tcp=127.0.0.1:5180', 'tcp=127.0.0.1:5190'])
  assert.notEqual(client.out['tcp=127.0.0.1:5180'], 'EPERM')
  assert.equal(client.out['tcp=127.0.0.1:5190'], 'EPERM', 'another network\'s page stays denied')
  const executor = probe(['--network', 'local', 'job', 'run', 'x'], ['tcp=127.0.0.1:5180'])
  assert.equal(executor.out['tcp=127.0.0.1:5180'], 'EPERM')
})

test('vt job validate inside the real client sandbox (C5): reads the job file and --message-file, decodes strictly, prints the id; writes nothing', () => {
  const jd = dir('job-files')
  mkdirSync(join(jd, 'texts'), { recursive: true })
  writeFileSync(join(jd, 'texts', 'm.txt'), 'A synthetic vt fixture message.\nIt has two lines.\n')
  const job = { format: 'vt-job/1', network: 'local', name: 'eth drain to the null address',
    chains: { eth: { mode: 'drain', publishMode: 'eth.calldata.null', feeStrategy: 'passive', distinctCopies: true, keyAddress: '0x8739Eb87B3d11f221Df63454F8D229a1A4F4049C', budgetUsd: 10, maxTipGwei: 3, clawbackTo: null } } }
  writeFileSync(join(jd, 'job.json'), JSON.stringify(job))
  // The contract fixture's id (jobs-create-201): the same canonical definition, by digest.
  const r = run(['job', 'validate', join(jd, 'job.json'), '--message-file', join(jd, 'texts', 'm.txt'), '--json'], { env: BASE_ENV() })
  assert.equal(r.code, 0, r.err)
  assert.equal((JSON.parse(r.out) as { id: string }).id, 'e3d45f73cf65abaa')
  writeFileSync(join(jd, 'texts', 'bad.txt'), Buffer.from([0x61, 0xc3, 0x28, 0x0a]))
  refused(run(['job', 'validate', join(jd, 'job.json'), '--message-file', join(jd, 'texts', 'bad.txt')], { env: BASE_ENV() }), 'message.utf8')
  // A job JSON naming a file is refused (the path comes from argv only), and a key directory stays out of reach.
  writeFileSync(join(jd, 'named.json'), JSON.stringify({ ...job, messageFile: 'texts/m.txt' }))
  refused(run(['job', 'validate', join(jd, 'named.json')], { env: BASE_ENV() }), 'vt.message-path')
  mkdirSync(join(HOME0, '.ssh'), { recursive: true })
  writeFileSync(join(HOME0, '.ssh', 'id_synthetic'), 'synthetic\n')
  refused(run(['job', 'validate', join(jd, 'job.json'), '--message-file', join(HOME0, '.ssh', 'id_synthetic')], { env: BASE_ENV() }), 'vt.message-path')
})

test('vt status inside the real client sandbox reads up.json and api.token (reads are allowed; writes are not)', () => {
  const home = dir('status-home')
  mkdirSync(join(home, 'local'), { recursive: true, mode: 0o700 })
  writeFileSync(join(home, 'local', 'up.json'), '{"network":"local","pagePort":5180,"build":"dev","startedAt":1}\n', { mode: 0o600 })
  writeFileSync(join(home, 'local', 'api.token'), 'cd'.repeat(32), { mode: 0o600 })
  const r = run(['--network', 'local', 'status', '--json'], { env: { ...BASE_ENV(), VT_HOME: home } })
  const [e] = JSON.parse(r.out) as Array<{ up: boolean; build: string; api: { error: string | null } }>
  assert.equal(e.up, true)
  assert.equal(e.build, 'dev')
  assert.notEqual(e.api.error, 'token unreadable')
  assert.ok(!r.out.includes('cd'.repeat(32)) && !r.err.includes('cd'.repeat(32)), 'the token is never printed')
})

// ---- never nests, and a hint is not a proof

test('VT_CONFINED=1 set by hand outside any sandbox -> vt.not-confined (no TEST-NET-1 packet: the loopback probe stops it)', () => {
  for (const args of [['status'], ['help'], ['job', 'run', 'x']]) {
    const r = run(args, { env: { ...BASE_ENV(), VT_CONFINED: '1' } })
    refused(r, 'vt.not-confined')
    assert.match(r.err, /TEST-NET-1: not tried/)
  }
})

test('a sandbox-exec on PATH that drops the profile -> vt.not-confined', () => {
  const r = run(['status'], { file: fakeableWrapper(dir('fw-noop')), env: { ...BASE_ENV(), PATH: `${dir('noop')}:${PATH0}` } })
  refused(r, 'vt.not-confined')
})

test('never nests: inside the real sandbox with VT_CONFINED=1, sandbox-exec is not called again', () => {
  const marker = dir('nested.marker')
  const path = `${dir('nest')}:${PATH0}`
  // Positive control: outside, the wrapper calls the (tripwire) sandbox-exec on PATH.
  rmSync(marker, { force: true })
  const outer: Run = run(['status'], { file: fakeableWrapper(dir('fw-nest')), env: { ...BASE_ENV(), PATH: path } })
  assert.equal(outer.code, 99)
  assert.ok(existsSync(marker), 'the tripwire sandbox-exec was called')
  // Inside a real sandbox (the client profile) with VT_CONFINED=1: straight to node.
  rmSync(marker, { force: true })
  const profile = spawnSync(NODE, [join(CLI, 'src', 'ops', 'profile.ts'), 'status'], { encoding: 'utf8', env: { PATH: PATH0, HOME: HOME0, VT_NETWORK: 'local' } }).stdout
  const r = spawnSync('/usr/bin/sandbox-exec', ['-p', profile, WRAPPER, 'status'], {
    env: { ...BASE_ENV(), PATH: path, VT_CONFINED: '1', VT_NETWORK: 'local' }, encoding: 'utf8', timeout: 60_000, cwd: '/',   // bin/vt starts a sandboxed command in `/` (follow-up 3)
  })
  assert.equal(r.stderr, '')
  assert.equal(r.stdout, 'local    down\n')
  assert.ok(!existsSync(marker), 'sandbox-exec was called again (nested)')
})

// ---- vt-broadcast pass-throughs, for real (bin/vt-broadcast applies its own sandbox; never tor-check)

test('vt note validate -> vt-broadcast validate-note: stdin, stdout and the exit status pass through; nothing is echoed', () => {
  let r = run(['note', 'validate'], { env: BASE_ENV(), input: 'hello' })
  assert.equal(r.code, 0, r.err)
  assert.equal(r.out, 'ok 5\n')
  assert.equal(r.err, '')
  r = run(['--network', 'testnet', 'note', 'validate', '--max-bytes', '5'], { env: BASE_ENV(), input: 'hello' })
  assert.equal(r.code, 0, r.err)
  assert.equal(r.out, 'ok 5\n')
  r = run(['note', 'validate', '--max-bytes', '4'], { env: BASE_ENV(), input: 'hello' })
  assert.notEqual(r.code, 0, 'a refusal of vt-broadcast is vt\'s exit status')
})

test('vt triggers list -> vt-broadcast triggers list (a fresh VAULT_TIMELOCK_DIR)', () => {
  const r = run(['triggers', 'list'], { env: BASE_ENV() })
  assert.equal(r.code, 0, r.err)
  assert.equal(r.err, '')
  assert.equal(r.out, 'no triggers\n')
})

test('a pass-through never echoes its arguments (an --rpc URL can hold a key): vt-broadcast\'s own refusal is all there is', () => {
  const key = 'synthetic-key-0123456789'
  const r = run(['note', 'validate', '--rpc', `eth=https://rpc.example/v2/${key}`], { env: BASE_ENV(), input: 'hello' })
  assert.ok(!r.err.includes(key) && !r.out.includes(key), r.err)
  assert.ok(!r.err.includes('vt: running'))
})

// M-4(b): the REAL bin/vt names /usr/bin/sandbox-exec by absolute path: a tripwire sandbox-exec first on PATH is never called, and the command still runs confined
test('M-4: a sandbox-exec earlier on PATH is ignored by the real bin/vt (absolute /usr/bin/sandbox-exec): the tripwire is not called and `vt status` runs in the real sandbox', () => {
  const marker = dir('abs.marker')
  rmSync(marker, { force: true })
  const trip = dir('abs-trip')
  mkdirSync(trip, { recursive: true })
  writeExe(join(trip, 'sandbox-exec'), `#!/bin/sh\n: > '${marker}'\nexit 99\n`)
  const r = run(['status', '--network', 'local'], { env: { ...BASE_ENV(), PATH: `${trip}:${PATH0}` } })
  assert.equal(r.code, 1, r.err)
  assert.match(r.out, /^local {4}down$/m)
  assert.ok(!existsSync(marker), 'the PATH sandbox-exec was called')
})

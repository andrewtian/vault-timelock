// cli/test/passthrough.test.ts — `vt seal|open` and the vt-broadcast pass-throughs (src/passthrough.ts, plan C1;
// C1 fix round 1: review I1 and controller ruling (1)).
//
// ★★ The real sealers are NEVER run here, and cannot be:
//   · every `vt seal|open` below runs bin/vt of a SEALER-FREE COPY of this workspace (lib.ts sealerFreeCopy): its
//     repository root holds no 1password-timelock.sh or timelock-key.sh, so even a regression that loses VT_SEALER
//     ends in ENOENT, never in a real sealer (a test below proves exactly that);
//   · VT_SEALER names the copy's test/fixtures/sealer-stub.sh, which reports its arguments and its environment NAMES;
//   · tripwires behind that: an `op` on PATH that only leaves a marker and exits 99, and this file's own walls
//     (scripts/test-root.sh phase A: the suite sandbox, which denies Tor and the internet). The marker is checked.
//   · The positive case seals the plain vault name `Example`; the other cases use a synthetic vault name (SYNTH).
// The vt-broadcast pass-throughs are checked as command lines here (bin/vt-broadcast applies its own sandbox, which
// cannot nest inside the suite's); test/wrapper.test.ts runs them for real.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, realpathSync, statSync, symlinkSync } from 'node:fs'
import { basename, dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { broadcastCommand, broadcastTarget, childEnv, isLoopbackSocks, sealTarget, showCommand } from '../src/passthrough.ts'
import type { BroadcastSub } from '../src/passthrough.ts'
import { CANARY, CLI, IPV4, PATH0, STUB, removeDir, refused, run, runMain, sealerFreeCopy, stubReport, tempDir, throwsWith, writeExe } from './lib.ts'
import type { Run, SealerFreeCopy } from './lib.ts'

const SYNTH = 'SYNTH-NOT-A-VAULT'
let T = ''
let C: SealerFreeCopy
let ENV: Record<string, string> = {}
const OP_MARKER = () => join(T, 'op-was-called')
before(() => {
  T = tempDir('vt-passthrough-')
  C = sealerFreeCopy()
  mkdirSync(join(T, 'tripwire'))
  writeExe(join(T, 'tripwire', 'op'), `#!/bin/sh\n: > '${OP_MARKER()}'\nexit 99\n`)
  mkdirSync(join(T, 'home'))
  ENV = { PATH: `${join(T, 'tripwire')}:${PATH0}`, HOME: join(T, 'home'), VT_HOME: join(T, 'vt-home'), VAULT_TIMELOCK_DIR: join(T, 'out'), VT_SEALER: C.stub }
})
after(() => {
  assert.ok(!existsSync(OP_MARKER()), 'the op tripwire fired')
  removeDir(T)
  removeDir(C.root)
})
const STUB_REAL = realpathSync(STUB)
// The copy's bin/vt, with exactly ENV plus `env` (undefined deletes).
function seal(args: string[], env: Record<string, string | undefined> = {}, o: { input?: string; cwd?: string } = {}): Run {
  return run(args, { file: C.wrapper, env: { ...ENV, ...env }, ...o })
}
// The sealer's environment when the caller sets nothing special: the allowlist only.
const BASE = ['HOME', 'LANG', 'PATH', 'TERM', 'VAULT_TIMELOCK_DIR']
// The first stderr line is vt's, then the stub's report: arguments exactly, environment names exactly.
function ranStub(r: Run, args: string[], names: string[] = BASE): void {
  assert.equal(r.code, 0, r.err)
  assert.equal(r.out, '')
  assert.equal(r.err.split('\n')[0], `vt: running ${basename(C.stub)} ${args.join(' ')}`)
  const rep = stubReport(r.err)
  assert.ok(rep !== null, 'the stub ran')
  assert.deepEqual(rep.args, args)
  assert.deepEqual(rep.names, [...names].sort())
}

// ---- sealTarget (pure: nothing is run)

test('sealTarget: the real sealer beside the repository root when VT_SEALER is unset (never run here)', () => {
  assert.equal(sealTarget('vault', {}, '/repo'), '/repo/1password-timelock.sh')
  assert.equal(sealTarget('file', {}, '/repo'), '/repo/timelock-key.sh')
  assert.throws(() => sealTarget('dir' as 'vault', {}, '/repo'), { name: 'UsageError' })
})

test('sealTarget: VT_SEALER naming the stub (absolute, relative to the cwd, or through a link) -> the stub\'s real path', () => {
  assert.equal(sealTarget('vault', { VT_SEALER: STUB }, '/repo'), STUB_REAL)
  assert.equal(sealTarget('file', { VT_SEALER: relative(process.cwd(), STUB) }, '/repo'), STUB_REAL)
  symlinkSync(STUB, join(T, 'link-to-stub'))
  assert.equal(sealTarget('vault', { VT_SEALER: join(T, 'link-to-stub') }, '/repo'), STUB_REAL)
})

test('vt.sealer-stub-only: VT_SEALER=/bin/echo, empty, a missing file, the fixtures dir, an escape, or a link out -> refused', () => {
  writeExe(join(T, 'sealer-stub.sh'), '#!/bin/sh\nexit 0\n') // same name, wrong place
  symlinkSync('/bin/echo', join(T, 'link-to-echo'))
  const fixtures = dirname(STUB)
  for (const v of ['/bin/echo', '', join(fixtures, 'no-such-stub.sh'), fixtures, `${fixtures}/../../src/main.ts`,
    join(T, 'sealer-stub.sh'), join(T, 'link-to-echo'), join(CLI, 'bin', 'vt'), 'sealer-stub.sh']) {
    for (const kind of ['vault', 'file'] as const) throwsWith(() => sealTarget(kind, { VT_SEALER: v }, '/repo'), 'vt.sealer-stub-only')
  }
})

test('an empty or unset VT_SEALER never resolves to a real sealer (regression, review I1)', () => {
  // Pure: empty is refused; unset is the real path, which only a run could reach.
  for (const kind of ['vault', 'file'] as const) throwsWith(() => sealTarget(kind, { VT_SEALER: '' }, C.repo), 'vt.sealer-stub-only')
  // Through bin/vt: an empty VT_SEALER reaches node as empty (bin/vt passes it when set) and is refused.
  const empty = seal(['seal', 'vault', SYNTH, '30d'], { VT_SEALER: '' })
  refused(empty, 'vt.sealer-stub-only')
  assert.ok(!empty.err.includes('vt: running') && stubReport(empty.err) === null, 'nothing was started')
  // Unset: the target is the copy's repository root, where no sealer exists: ENOENT, exit 1, nothing ran.
  for (const [kind, script] of [['vault', '1password-timelock.sh'], ['file', 'timelock-key.sh']] as const) {
    const r = seal(['seal', kind, SYNTH, '30d'], { VT_SEALER: undefined })
    const target = join(realpathSync(C.repo), script)
    assert.ok(!existsSync(target))
    assert.equal(r.code, 1, r.err)
    assert.equal(r.err.split('\n')[0], `vt: running ${script} seal ${SYNTH} 30d`)
    assert.ok(!r.err.split('\n')[0].includes('/'), 'Cfix4 (C1 M5): the running line names the program by base name, never an absolute path')
    assert.match(r.err, /ENOENT/)
    assert.ok(!r.err.includes(join(dirname(CLI), script)), 'the real sealer\'s path never appears')
  }
})

// ---- through the copy's wrapper (orchestration: no sandbox; the stub reports what it received)

test('vt seal vault Example 30d with VT_SEALER=<stub>: the command is printed, then the stub receives exactly `seal Example 30d`', () => {
  const r = seal(['seal', 'vault', 'Example', '30d'])
  ranStub(r, ['seal', 'Example', '30d'])
})

test('VT_SEALER as the brief writes it, cli/test/fixtures/sealer-stub.sh, relative to the repository root', () => {
  const r = seal(['seal', 'vault', SYNTH, '30d'], { VT_SEALER: 'cli/test/fixtures/sealer-stub.sh' }, { cwd: C.repo })
  ranStub(r, ['seal', SYNTH, '30d'])
})

test('vt open|seal vault|file: the same arguments, unchanged (spaces, empty strings, flags); stdin is attached', () => {
  const r = seal(['open', 'file', 'pkg dir', '', '--clearnet'])
  assert.equal(r.err.split('\n')[0], `vt: running ${basename(C.stub)} open 'pkg dir' '' --clearnet`)
  assert.deepEqual(stubReport(r.err)?.args, ['open', 'pkg dir', '', '--clearnet'])
  ranStub(seal(['seal', 'file', '-', '30d', '--armor'], {}, { input: 'synthetic\n' }), ['seal', '-', '30d', '--armor'])
  ranStub(seal(['open', 'vault', 'pkg']), ['open', 'pkg'])
})

test('the sealer\'s exit status is vt\'s exit status', () => {
  const r = seal(['seal', 'vault', 'exit-7'])
  assert.equal(r.code, 7)
  assert.deepEqual(stubReport(r.err)?.args, ['seal', 'exit-7'])
})

test('VT_SEALER=/bin/echo (or empty) through the wrapper -> vt.sealer-stub-only, and nothing ran', () => {
  for (const v of ['/bin/echo', '']) {
    const r = seal(['seal', 'vault', SYNTH, '30d'], { VT_SEALER: v })
    refused(r, 'vt.sealer-stub-only')
    assert.ok(!r.err.includes('vt: running'), 'nothing was started')
  }
})

test('vt seal without vault|file -> usage, exit 1, nothing ran', () => {
  for (const args of [['seal'], ['seal', 'dir', SYNTH], ['open'], ['open', 'Vault', SYNTH]]) {
    const r = seal(args)
    assert.equal(r.code, 1, r.err)
    assert.match(r.err, /^vt: usage: vt (seal|open) vault/)
    assert.ok(stubReport(r.err) === null)
  }
})

// ---- the sealer's environment (exact names; review I1, controller ruling (1))

test('the sealer gets exactly PATH HOME LANG TERM VAULT_TIMELOCK_DIR (+ XDG_DATA_HOME when set): no VT_*, keys, proxies or OP', () => {
  const hostile = {
    ALCHEMY_API_KEY: 'synthetic', GITHUB_TOKEN: 'synthetic', NODE_OPTIONS: '--require /nonexistent.cjs', HTTPS_PROXY: 'http://proxy.invalid:1',
    OP: '/bin/echo', VT_PROFILE: 'mainnet', VT_RPC_ETH: 'https://rpc.example/', VT_DEBUG: '1', FOO: '1',
  }
  ranStub(seal(['seal', 'vault', SYNTH, '30d'], hostile), ['seal', SYNTH, '30d'])
  ranStub(seal(['--network', 'testnet', 'open', 'file', 'pkg'], { ...hostile, XDG_DATA_HOME: join(T, 'xdg') }), ['open', 'pkg'], [...BASE, 'XDG_DATA_HOME'])
})

const SEALER_SETTINGS = { TOR_SOCKS: '127.0.0.1:9150', OP_ACCOUNT: 'synthetic.example', OP_SESSION_synth: 'synthetic-session-a', OP_SESSION_TEAM_2: 'synthetic-session-b' }
const STRIPPED = { OP_SERVICE_ACCOUNT_TOKEN: 'synthetic-sa-token', OP_CONNECT_HOST: 'http://connect.invalid', OP_CONNECT_TOKEN: 'synthetic-connect-token' }
const NOTE = 'vt: note: OP_SERVICE_ACCOUNT_TOKEN / OP_CONNECT_* are set in your environment and were NOT passed to the sealer (service-account and Connect credentials never reach it)'

test('ruling (1): TMPDIR, TOR_SOCKS (loopback), OP_ACCOUNT and OP_SESSION_* reach the sealer, values intact', () => {
  const settings = { ...SEALER_SETTINGS, TMPDIR: join(T, 'operator-tmp') }
  for (const args of [['seal', 'vault', SYNTH, '30d'], ['open', 'file', 'pkg']]) {
    const r = seal(args, settings)
    ranStub(r, args.filter((a) => a !== 'vault' && a !== 'file'), [...BASE, 'OP_ACCOUNT', 'OP_SESSION_TEAM_2', 'OP_SESSION_synth', 'TMPDIR', 'TOR_SOCKS'])
    const rep = stubReport(r.err)
    assert.equal(rep?.tmpdir, settings.TMPDIR)
    assert.equal(rep?.torSocks, '127.0.0.1:9150')
    for (const v of ['synthetic-session-a', 'synthetic-session-b', 'synthetic.example']) assert.ok(!r.err.includes(v), 'no value is printed')
  }
  const v6 = seal(['seal', 'vault', SYNTH], { TOR_SOCKS: '[::1]:9050' })
  ranStub(v6, ['seal', SYNTH], [...BASE, 'TOR_SOCKS'])
  assert.equal(stubReport(v6.err)?.torSocks, '[::1]:9050')
})

test('ruling (1): OP_SERVICE_ACCOUNT_TOKEN and OP_CONNECT_* never reach the sealer; one fixed note says so, no value shown', () => {
  const r = seal(['seal', 'vault', SYNTH, '30d'], { ...STRIPPED, OP_SESSION_synth: 'synthetic-session-a' })
  assert.equal(r.code, 0, r.err)
  const lines = r.err.split('\n')
  assert.equal(lines[0], NOTE)
  assert.equal(lines.filter((l) => l.startsWith('vt: note:')).length, 1, 'exactly one note')
  // The rest is as without them, plus the session.
  assert.equal(lines[1], `vt: running ${basename(C.stub)} seal ${SYNTH} 30d`)
  assert.deepEqual(stubReport(r.err)?.names, [...BASE, 'OP_SESSION_synth'].sort())
  for (const v of Object.values(STRIPPED)) assert.ok(!r.err.includes(v), 'no value is printed')
  // Only one of them is enough for the note; none, no note.
  assert.equal(seal(['open', 'vault', 'pkg'], { OP_CONNECT_HOST: 'http://connect.invalid' }).err.split('\n')[0], NOTE)
  assert.ok(!seal(['open', 'vault', 'pkg']).err.includes('vt: note:'))
})

test('ruling (1): a TOR_SOCKS that is not a literal loopback address refuses vt.tor-socks before anything runs', () => {
  for (const v of ['', 'localhost:9050', `${CANARY}:9050`, '127.0.0.1', '127.0.0.1:0', '127.0.0.1:65536', '127.0.0.1:09050', 'socks5h://127.0.0.1:9050', '[::1]']) {
    const r = seal(['seal', 'vault', SYNTH, '30d'], { TOR_SOCKS: v })
    refused(r, 'vt.tor-socks')
    assert.equal(r.err, 'refused vt.tor-socks: TOR_SOCKS must be a loopback SOCKS address, 127.0.0.1:<port> or [::1]:<port> (the value is not echoed)\n')
  }
})

test('main.ts started without bin/vt: the sealer still gets only the allowlist (a non-loopback TOR_SOCKS is dropped)', () => {
  const r = runMain(['seal', 'vault', SYNTH, '30d'], {
    file: C.main,
    env: { ...ENV, LANG: 'C', TERM: 'dumb', ...STRIPPED, VT_NETWORK: 'local', VT_CONFINED: undefined, TOR_SOCKS: `${CANARY}:9050`, OP_SESSION_synth: 'x', OP_SESSION_bad_name_ok: 'y' },
  })
  // OP_SERVICE_ACCOUNT_TOKEN / OP_CONNECT_TOKEN end in _TOKEN: vt-broadcast's assertNoKeyEnv refuses before anything.
  refused(r, 'config.env-key')
  const q = runMain(['seal', 'vault', SYNTH, '30d'], {
    file: C.main,
    env: { ...ENV, LANG: 'C', TERM: 'dumb', OP_CONNECT_HOST: 'http://connect.invalid', VT_NETWORK: 'local', TOR_SOCKS: `${CANARY}:9050`, OP_SESSION_synth: 'x' },
  })
  ranStub(q, ['seal', SYNTH, '30d'], [...BASE, 'OP_SESSION_synth'])
})

// ---- vt-broadcast pass-throughs (command lines)

const BROADCAST_BIN = join(realpathSync(fileURLToPath(new URL('../node_modules/vt-broadcast', import.meta.url))), 'bin', 'vt-broadcast')

test('broadcastTarget: broadcast/bin/vt-broadcast (through the workspace link) and the words of spec §11', () => {
  assert.ok((statSync(BROADCAST_BIN).mode & 0o111) !== 0, 'vt-broadcast is executable')
  const expected: Record<BroadcastSub, string[]> = {
    note: ['validate-note'], 'seal-text': ['seal-text'], 'tor-check': ['tor-check'], keystore: ['keystore'], triggers: ['triggers'],
  }
  for (const [sub, mapped] of Object.entries(expected)) {
    assert.deepEqual(broadcastTarget(sub as BroadcastSub), { argv0: BROADCAST_BIN, mapped })
  }
  assert.throws(() => broadcastTarget('env-names' as BroadcastSub), { name: 'UsageError' })
})

test('vt note validate -> vt-broadcast validate-note; vt triggers list -> vt-broadcast triggers list; the rest unchanged', () => {
  assert.deepEqual(broadcastCommand('note', ['validate']), { file: BROADCAST_BIN, args: ['validate-note'] })
  assert.deepEqual(broadcastCommand('note', ['validate', '--max-bytes', '5']), { file: BROADCAST_BIN, args: ['validate-note', '--max-bytes', '5'] })
  assert.deepEqual(broadcastCommand('triggers', ['list']), { file: BROADCAST_BIN, args: ['triggers', 'list'] })
  assert.deepEqual(broadcastCommand('triggers', ['resolve', 'id', 'dest', 'mark-done', '0xabc']), { file: BROADCAST_BIN, args: ['triggers', 'resolve', 'id', 'dest', 'mark-done', '0xabc'] })
  assert.deepEqual(broadcastCommand('keystore', ['init', '--profile', 'testnet']), { file: BROADCAST_BIN, args: ['keystore', 'init', '--profile', 'testnet'] })
  assert.deepEqual(broadcastCommand('seal-text', ['pkg dir', '--write']), { file: BROADCAST_BIN, args: ['seal-text', 'pkg dir', '--write'] })
  assert.deepEqual(broadcastCommand('tor-check', []), { file: BROADCAST_BIN, args: ['tor-check'] })
  for (const rest of [[], ['check'], ['--max-bytes', '5']]) assert.throws(() => broadcastCommand('note', rest), { name: 'UsageError' })
})

test('vt note without validate through the wrapper -> usage, exit 1, vt-broadcast not started', () => {
  const r = seal(['note', 'check'])
  assert.equal(r.code, 1, r.err)
  assert.match(r.err, /^vt: usage: vt note validate/)
  assert.ok(!r.err.includes('vt: running'))
})

// ---- the child's environment and the printed command

test('childEnv: the allowlist; the sealer\'s settings only for a sealer; VT_PROFILE=<network> only for vt-broadcast', () => {
  const env = {
    PATH: '/usr/bin', HOME: '/h', LANG: 'C', TERM: 'xterm', VAULT_TIMELOCK_DIR: '/o', XDG_DATA_HOME: '', VT_HOME: '/v', VT_NETWORK: 'testnet',
    VT_SEALER: STUB, VT_CONFINED: '1', NODE_OPTIONS: '--require x', HTTPS_PROXY: 'http://proxy.invalid:1', VT_PROFILE: 'mainnet', VT_RPC_ETH: 'https://x.example/',
    TMPDIR: '/t', TOR_SOCKS: '127.0.0.1:9050', OP_ACCOUNT: 'a', OP_SESSION_x: 's', OP_SESSION_: 'e', 'OP_SESSION_a-b': 'h', OP: '/bin/echo', ...STRIPPED,
  }
  const base = { PATH: '/usr/bin', HOME: '/h', LANG: 'C', TERM: 'xterm', VAULT_TIMELOCK_DIR: '/o', XDG_DATA_HOME: '' }
  assert.deepEqual(childEnv(env, { for: 'sealer' }), { ...base, TMPDIR: '/t', OP_ACCOUNT: 'a', OP_SESSION_x: 's', TOR_SOCKS: '127.0.0.1:9050' })
  assert.deepEqual(childEnv(env, { for: 'broadcast' }), { ...base, VT_PROFILE: 'testnet' })
  assert.deepEqual(childEnv({ PATH: '/usr/bin', HOME: '/h', VT_NETWORK: '' }, { for: 'broadcast' }), { PATH: '/usr/bin', HOME: '/h' })
  assert.deepEqual(childEnv({ PATH: '/usr/bin', TOR_SOCKS: `${CANARY}:9050` }, { for: 'sealer' }), { PATH: '/usr/bin' })
})

test('isLoopbackSocks: 127.0.0.1:<port> or [::1]:<port>, port 1-65535 without leading zeros', () => {
  for (const v of ['127.0.0.1:9050', '127.0.0.1:1', '127.0.0.1:65535', '[::1]:9150']) assert.equal(isLoopbackSocks(v), true, v)
  for (const v of ['', '127.0.0.1', '127.0.0.1:', '127.0.0.1:0', '127.0.0.1:65536', '127.0.0.1:09050', '127.0.0.1:123456', 'localhost:9050', '[::1]', '::1:9050',
    `${CANARY}:9050`, ' 127.0.0.1:9050', '127.0.0.1:9050\n', '127.0.0.1.evil.example:9050', 'socks5h://127.0.0.1:9050']) assert.equal(isLoopbackSocks(v), false, JSON.stringify(v))
})

test('showCommand: plain words as they are, the rest quoted so the printed line is unambiguous', () => {
  assert.equal(showCommand(['/a/b.sh', 'seal', 'Example', '30d', '--x=1']), '/a/b.sh seal Example 30d --x=1')
  assert.equal(showCommand(['a b', '', "it's", 'x$y']), `'a b' '' 'it'\\''s' 'x$y'`)
  assert.equal(showCommand(['new\nline']), '"new\\nline"')
})

test('showCommand never prints an address or a URL: such an argument is <redacted>', () => {
  const line = showCommand(['/a/b.sh', 'seal', CANARY, `x${CANARY}y`, 'fe80::1', '2001:db8::7', 'https://rpc.example/v2/synthetic-key', 'tor://h', '30d'])
  assert.equal(line, '/a/b.sh seal <redacted> <redacted> <redacted> <redacted> <redacted> <redacted> 30d')
  assert.ok(!line.includes(CANARY) && !IPV4.test(line))
})

test('through the wrapper: the printed line redacts an address, while the sealer still receives it unchanged', () => {
  const r = seal(['seal', 'vault', '198.51.100.7', '30d'])
  assert.equal(r.err.split('\n')[0], `vt: running ${basename(C.stub)} seal <redacted> 30d`)
  assert.deepEqual(stubReport(r.err)?.args, ['seal', '198.51.100.7', '30d'])
})

test('a seal run never leaks the environment into the printed line', () => {
  const r = seal(['seal', 'vault', SYNTH, '30d'], { HTTPS_PROXY: 'http://proxy.invalid:1', NODE_OPTIONS: '--require /nonexistent.cjs' })
  assert.equal(r.code, 0, r.err)
  assert.ok(!r.err.includes('proxy.invalid') && !r.err.includes('nonexistent'))
})

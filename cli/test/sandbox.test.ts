// cli/test/sandbox.test.ts — the sandbox profile strings (src/ops/sandbox.ts, plan Task C1): exact strings for each
// profile and network, and the vt.port / vt.path / vt.relay-ports refusals. Pure: no sandbox is applied here
// (test/confine.test.ts runs them in the real sandbox).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { Network } from '@vault-timelock/core/contracts'
import { PORTS } from '@vault-timelock/core/contracts'
import { DENY_NETWORK, apiProfile, assertProfilePath, commandProfile as commandProfileFull, denyProtectedFiles, denyTerminals, readAllowList, loopbackProfile, relayProfile, sandboxPorts, viteProfile } from '../src/ops/sandbox.ts'
import { throwsWith } from './lib.ts'

const BASE = '(version 1)(allow default)(deny network-outbound)'
const TOR = '(allow network-outbound (remote ip "localhost:9050"))'
const allow = (p: number) => `(allow network-outbound (remote ip "localhost:${p}"))`
const NO_WRITES = '(deny file-write*)(allow file-write* (literal "/dev/null"))'
const NO_LISTEN = '(deny network-bind)(deny network-inbound)'
const TTY_WRITES = '(deny file-write*)(allow file-write* (literal "/dev/null") (literal "/dev/tty"))'

test('the brief\'s literal strings', () => {
  assert.equal(DENY_NETWORK, BASE)
  assert.equal(relayProfile('testnet', []),
    '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:9050"))')
  assert.equal(apiProfile('/tmp/vt-home/local'),
    '(version 1)(allow default)(deny network-outbound)(deny file-write*)(allow file-write* (subpath "/tmp/vt-home/local") (literal "/dev/null"))')
  assert.equal(loopbackProfile([5181, 5182]),
    '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:5181"))(allow network-outbound (remote ip "localhost:5182"))(deny file-write*)(allow file-write* (literal "/dev/null"))')
  assert.equal(loopbackProfile([5181, 5182], { tty: true }),
    '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:5181"))(allow network-outbound (remote ip "localhost:5182"))(deny file-write*)(allow file-write* (literal "/dev/null") (literal "/dev/tty"))')
})

test('relayProfile: Tor only on every network; the local relay adds its chain ports, sorted and de-duplicated', () => {
  for (const n of ['local', 'testnet', 'mainnet'] as const) assert.equal(relayProfile(n, []), BASE + TOR)
  assert.equal(relayProfile('local', [8999, 8545, 18443, 8090, 8545]), BASE + TOR + allow(8090) + allow(8545) + allow(8999) + allow(18443))
})

test('vt.relay-ports: chain ports on a testnet or mainnet relay are refused', () => {
  throwsWith(() => relayProfile('testnet', [8545]), 'vt.relay-ports')
  throwsWith(() => relayProfile('mainnet', [8545, 8999]), 'vt.relay-ports')
  throwsWith(() => relayProfile('devnet' as Network, []), 'contract.network')
})

test('apiProfile: no outbound rule at all; writes only below the state dir and /dev/null', () => {
  for (const n of ['local', 'testnet', 'mainnet'] as const) {
    const dir = `/Users/op/.local/state/vt/${n}`
    const p = apiProfile(dir)
    assert.equal(p, `${BASE}(deny file-write*)(allow file-write* (subpath "${dir}") (literal "/dev/null"))`)
    assert.ok(!p.includes('allow network-outbound'))
  }
})

test('apiProfile with $OUT: read only there (an allow-read and a final deny-write), vt.path on the dir', () => {
  assert.equal(apiProfile('/s/local', '/o'),
    `${BASE}(deny file-write*)(allow file-write* (subpath "/s/local") (literal "/dev/null"))(allow file-read* (subpath "/o"))(deny file-write* (subpath "/o"))`)
  assert.ok(!apiProfile('/s/local', '/o').includes('allow network-outbound'))
  for (const p of ['out', '/o/', '/o"', '/o)(allow network-outbound', '', '/']) throwsWith(() => apiProfile('/s/local', p), 'vt.path')
})

test('loopbackProfile: exactly the given loopback ports, sorted and de-duplicated; /dev/tty only with tty', () => {
  assert.equal(loopbackProfile([]), BASE + NO_WRITES)
  assert.equal(loopbackProfile([5182, 5181, 5182]), BASE + allow(5181) + allow(5182) + NO_WRITES)
  assert.equal(loopbackProfile([5181, 5182], { tty: false }), BASE + allow(5181) + allow(5182) + NO_WRITES)
  assert.equal(loopbackProfile([5181, 5182], { tty: true }), BASE + allow(5181) + allow(5182) + TTY_WRITES)
  // Only a literal true widens to /dev/tty.
  assert.equal(loopbackProfile([5181], { tty: 'yes' as unknown as boolean }), BASE + allow(5181) + NO_WRITES)
})

// The profile without its trailing file-read denies (their own tests are below and in ticket-key-real.test.ts).
const H = '/h/vt', O = '/o/out'
const SCOPE = { tree: ['/r/repo/cli/src'], treeFiles: ['/r/repo/package.json'], node: ['/n/bin/node'], launcher: '/r/repo/cli/bin/vt', stdio: [] as string[], userHome: '/u/me', handed: [] as string[] }
const commandProfile = (argv: readonly string[], n: string | undefined): string | null => {
  const p = commandProfileFull(argv, n, H, O, SCOPE)
  return p === null ? null : p.split('(deny file-read*')[0]
}

test('commandProfile: fail closed — a missing or unsafe $VT_HOME / $VAULT_TIMELOCK_DIR refuses (vt.path); the denies cover the key, the credential and the other networks\' tokens', () => {
  for (const [h, o] of [[undefined, O], [H, undefined], ['', O], [H, ''], ['relative', O], [H, 'rel/out'], ['/h/"x', O]] as const) {
    throwsWith(() => commandProfileFull(['job', 'run', 'x'], 'local', h as unknown as string, o as unknown as string, SCOPE), 'vt.path')
    throwsWith(() => commandProfileFull(['status'], 'local', h as unknown as string, o as unknown as string, SCOPE), 'vt.path')
  }
  assert.equal(commandProfileFull(['help'], 'local', undefined as unknown as string, undefined as unknown as string, undefined as unknown as typeof SCOPE), null, 'an unsandboxed command has no profile to fail')
  const run = commandProfileFull(['job', 'run', 'x'], 'mainnet', H, O, SCOPE) as string
  for (const n of ['local', 'testnet', 'mainnet']) assert.ok(run.includes(`(deny file-read* (literal "${H}/${n}/relay-ticket.key"))`), n)
  assert.ok(run.includes(`(deny file-read* (literal "${O}/local/btc-rpc.auth"))`))
  assert.ok(run.includes(`(deny file-read* (literal "${H}/local/api.token"))`) && run.includes(`(deny file-read* (literal "${H}/testnet/api.token"))`), 'another network\'s token')
  assert.ok(!run.includes(`(deny file-read* (literal "${H}/mainnet/api.token"))`) && run.includes(`(allow file-read* `) && run.includes(`(literal "${H}/mainnet/api.token")`), 'its own network\'s token is allowed, not denied')
  const status = commandProfileFull(['status'], undefined, H, O, SCOPE) as string
  assert.ok(!/deny file-read\* \(literal "[^"]*api\.token/.test(status), 'vt status reads every network\'s token')
  assert.ok(commandProfileFull(['job', 'list'], 'local', H, O, SCOPE)!.includes(denyProtectedFiles(H, O, ['local'], SCOPE.userHome)))
})

test('commandProfile: client commands reach the page, relay and API ports of each network (ruling (2)); the executor relay and API only', () => {
  const client = (n: Network) => [PORTS[n].page, PORTS[n].relay, PORTS[n].api]
  const executor = (n: Network) => [PORTS[n].relay, PORTS[n].api]
  for (const n of ['local', 'testnet', 'mainnet'] as const) {
    assert.equal(commandProfile(['status'], n), loopbackProfile(client(n), { noListen: true }))
    assert.equal(commandProfile(['preflight', '--json'], n), loopbackProfile(client(n), { noListen: true }))
    assert.equal(commandProfile(['job', 'list'], n), loopbackProfile(client(n), { noListen: true }))
    assert.equal(commandProfile(['job', 'run', 'x'], n), loopbackProfile(executor(n), { noListen: true }))
    assert.equal(commandProfile(['job', 'clawback', 'x'], n), loopbackProfile(executor(n), { noListen: true }))
  }
  // The literal ports (contracts/ports.ts): local 5180/5181/5182, testnet 5190/5191/5192, mainnet 5200/5201/5202.
  assert.equal(commandProfile(['job', 'list'], 'testnet'), BASE + allow(5190) + allow(5191) + allow(5192) + NO_WRITES + NO_LISTEN)
  // job create, job arm and job resolve read a typed word: since the TTY-less round the broker asks on the terminal, so no sandboxed command has /dev/tty.
  assert.equal(commandProfile(['job', 'arm', 'x'], 'testnet'), BASE + allow(5190) + allow(5191) + allow(5192) + NO_WRITES + NO_LISTEN)
  assert.equal(commandProfile(['job', 'resolve', 'x'], 'mainnet'), BASE + allow(5200) + allow(5201) + allow(5202) + NO_WRITES + NO_LISTEN)
  assert.equal(commandProfile(['job', 'create', 'f'], 'local'), BASE + allow(5180) + allow(5181) + allow(5182) + NO_WRITES + NO_LISTEN)
  for (const sub of ['validate', 'list', 'status', 'watch', 'skip', 'stop', 'resume', 'close', 'receipt']) {
    assert.equal(commandProfile(['job', sub, 'x'], 'local'), BASE + allow(5180) + allow(5181) + allow(5182) + NO_WRITES + NO_LISTEN, sub)
  }
  assert.equal(commandProfile(['job', 'run', 'x'], 'mainnet'), BASE + allow(5201) + allow(5202) + NO_WRITES + NO_LISTEN)
  // No network: status reaches every stack; everything else is local.
  assert.equal(commandProfile(['status'], undefined), BASE + [5180, 5181, 5182, 5190, 5191, 5192, 5200, 5201, 5202].map(allow).join('') + NO_WRITES + NO_LISTEN)
  assert.equal(commandProfile(['status'], ''), commandProfile(['status'], undefined))
  assert.equal(commandProfile(['job', 'list'], undefined), BASE + allow(5180) + allow(5181) + allow(5182) + NO_WRITES + NO_LISTEN)
  assert.equal(commandProfile(['preflight'], undefined), BASE + allow(5180) + allow(5181) + allow(5182) + NO_WRITES + NO_LISTEN)
  assert.equal(commandProfile(['job', 'run', 'x'], undefined), BASE + allow(5181) + allow(5182) + NO_WRITES + NO_LISTEN)
  // Unsandboxed commands have no profile.
  for (const argv of [['help'], ['up'], ['seal', 'vault', 'X'], ['note', 'validate'], ['bogus'], []]) assert.equal(commandProfile(argv, 'local'), null)
  throwsWith(() => commandProfile(['status'], 'devnet'), 'contract.network')
})

test('viteProfile (vt up --dev): the given ports; writes only /dev/null and the Vite cache dir (vt.path on the dir)', () => {
  assert.equal(viteProfile([5182, 5181], '/repo/web/node_modules/.vite'),
    BASE + allow(5181) + allow(5182) + '(deny file-write*)(allow file-write* (literal "/dev/null") (subpath "/repo/web/node_modules/.vite"))')
  for (const p of ['relative/.vite', '/repo/web/node_modules/.vite/', '/a"b/.vite', '/']) throwsWith(() => viteProfile([5181], p), 'vt.path')
  throwsWith(() => viteProfile([0], '/repo/.vite'), 'vt.port')
})

test('vt.port: 0, 70000, "1)" and every other non-port are refused, by each profile', () => {
  const bad: unknown[] = [0, 70000, '1)', 65536, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '5181', null, 9e99]
  for (const p of bad) {
    const ports = [5181, p as number]
    throwsWith(() => sandboxPorts(ports), 'vt.port')
    throwsWith(() => loopbackProfile(ports), 'vt.port')
    throwsWith(() => loopbackProfile(ports, { tty: true }), 'vt.port')
    throwsWith(() => relayProfile('local', ports), 'vt.port')
  }
  // The boundaries are fine.
  assert.equal(loopbackProfile([65535, 1]), BASE + allow(1) + allow(65535) + NO_WRITES)
})

test('vt.path: a stateDir with `"` (or anything that could end or escape an SBPL string) is refused', () => {
  const bad = [
    '/tmp/a"b', '/tmp/a)b', '/tmp/a(b', '/tmp/a\\b', '/tmp/a;b', '/tmp/a\nb', '/tmp/a\u0000b', '/tmp/a\u007fb', '/tmp/a\tb',
    'relative/dir', './x', '', '/', '/tmp/x/', '/tmp/../etc', '/tmp/./x', '/tmp//x',
    '/tmp/x") (allow network-outbound (remote ip "localhost:*',
  ]
  for (const p of bad) {
    throwsWith(() => apiProfile(p), 'vt.path')
    throwsWith(() => assertProfilePath(p), 'vt.path')
  }
  throwsWith(() => apiProfile(undefined as unknown as string), 'vt.path')
  // Ordinary absolute paths, spaces and non-ASCII included, are fine.
  for (const p of ['/tmp/vt home/local', '/Users/öp/.local/state/vt/mainnet', '/a']) assert.ok(apiProfile(p).includes(`(subpath "${p}")`))
})

test('C7 (parked from C6 fix 1): the executor and (Cfix4) every client profile deny network-bind and network-inbound; the page server, relay and API keep listening', () => {
  assert.equal(loopbackProfile([5181], { tty: true, noListen: true }), BASE + allow(5181) + TTY_WRITES + NO_LISTEN)
  assert.equal(loopbackProfile([5181], { noListen: true }), BASE + allow(5181) + NO_WRITES + NO_LISTEN)
  assert.equal(loopbackProfile([5181], { noListen: false }), BASE + allow(5181) + NO_WRITES)
  assert.equal(loopbackProfile([5181], { noListen: 'yes' as unknown as boolean }), BASE + allow(5181) + NO_WRITES, 'only a literal true')
  for (const argv of [['job', 'run', 'x'], ['job', 'clawback', 'x']]) for (const n of ['local', 'testnet', 'mainnet'] as const) assert.ok(commandProfile(argv, n)!.endsWith(NO_LISTEN), argv.join(' '))
  // Cfix4 (C1 review M3): every CLIENT profile denies them too (status, preflight, the job client commands, with and without /dev/tty).
  for (const argv of [['status'], ['preflight'], ['job', 'list'], ['job', 'status', 'x'], ['job', 'watch', 'x'], ['job', 'arm', 'x'], ['job', 'create', 'f'], ['job', 'resolve', 'x']]) {
    for (const n of ['local', 'testnet', 'mainnet'] as const) assert.ok(commandProfile(argv, n)!.endsWith(NO_LISTEN), `Cfix4 ${argv.join(' ')} ${n}: a client never listens`)
  }
  assert.ok(!relayProfile('local', [8545]).includes('network-bind') && !apiProfile('/tmp/vt-home/local').includes('network-bind'), 'the relay and the API listen')
})

test('readAllowList fails closed: a subpath that is, or contains, $HOME, ~/.local, the default state/OUT, ~/p, or the current $VT_HOME / $OUT refuses (vt.read-allow); exact literals are fine', () => {
  const base = { tree: ['/r/repo/cli/src'], treeFiles: [] as string[], node: ['/n/bin/node'], launcher: '/r/repo/cli/bin/vt', stdio: [] as string[], userHome: '/u/me', handed: [] as string[] }
  const ok = (tree: string[]): void => { readAllowList('/h/vt', ['local'], { ...base, tree }, '/o/out') }
  ok(['/r/repo/cli/src'])
  for (const bad of ['/u/me', '/u', '/', '/u/me/.local', '/u/me/.local/share', '/u/me/.local/share/vault-timelock', '/u/me/.local/state', '/u/me/.local/state/vt', '/u/me/p', '/h/vt', '/h', '/o/out', '/o']) {
    throwsWith(() => ok([bad]), 'vt.read-allow')
  }
  ok(['/u/me/p/repo/cli/src', '/u/me/.local/share/fnm/x'])          // below a protected root is not covering it
  readAllowList('/h/vt', ['local'], { ...base, handed: ['/u/me/.local/share/vault-timelock/x'] }, '/o/out')   // handed files are literals, named one by one
})

test('every path that reaches the SBPL text is checked (vt.path); handed and stdio FILES may hold spaces, parentheses and `;` (Chrome\'s "key (1).age"), nothing else changes', () => {
  const base = { tree: ['/r/repo/cli/src'], treeFiles: ['/r/repo/package.json'], node: ['/n/bin/node'], launcher: '/r/repo/cli/bin/vt', stdio: [] as string[], userHome: '/u/me', handed: ['/b/backup.age'] }
  const hostile = ['/x/a"b', '/x/a\\b', '/x/a\nb', '/x/a\u0000b', '/x/a\u007fb', 'rel/x', '/x/../y', '/x/./y', '/x/y/', '/x//y']
  const punct = ['/x/a(b', '/x/a)b', '/x/a;b', '/x/a b', '/x/vt-eth-key-20261010T101500Z (1).age']
  for (const bad of [...hostile, ...punct.filter((x) => /[();]/.test(x))]) {   // directories and scope literals other than handed/stdio keep the strict rule
    for (const field of ['tree', 'treeFiles', 'node'] as const) throwsWith(() => readAllowList('/h/vt', ['local'], { ...base, [field]: [bad] }, '/o/out'), 'vt.path')
    throwsWith(() => commandProfileFull(['job', 'run', 'x'], 'local', bad, '/o/out', base), 'vt.path')
    throwsWith(() => commandProfileFull(['job', 'run', 'x'], 'local', '/h/vt', bad, base), 'vt.path')
    throwsWith(() => commandProfileFull(['job', 'run', 'x'], 'local', '/h/vt', '/o/out', { ...base, userHome: bad }), 'vt.path')
  }
  for (const bad of hostile) for (const field of ['handed', 'stdio'] as const) throwsWith(() => commandProfileFull(['job', 'run', 'x'], 'local', '/h/vt', '/o/out', { ...base, [field]: [bad] }), 'vt.path')
  for (const ok of punct) for (const field of ['handed', 'stdio'] as const) {
    const p = commandProfileFull(['job', 'run', 'x'], 'local', '/h/vt', '/o/out', { ...base, [field]: [ok] }) as string
    assert.ok(p.includes(`(literal "${ok}")`), `${field}: ${ok}`)
  }
  assert.ok(commandProfileFull(['job', 'run', 'x'], 'local', '/h/vt', '/o/out', base))
})

test('hardening (I-2): exec only the launcher chain, no mach lookup / Apple Events / raw IPC / AF_SYSTEM, ioctl only on /dev/null; no terminal for anyone (the broker prompts); no /usr/local', () => {
  const scope = { tree: ['/r/repo/cli/src'], treeFiles: [] as string[], node: ['/n/bin/node'], launcher: '/r/repo/cli/bin/vt', stdio: [] as string[], userHome: '/u/me', handed: [] as string[] }
  const run = commandProfileFull(['job', 'run', 'x'], 'local', H, O, scope) as string
  const list = commandProfileFull(['job', 'list'], 'local', H, O, scope) as string
  for (const p of [run, list]) {
    for (const need of ['(deny process-exec*)', '(allow process-exec* (literal "/bin/sh") (literal "/bin/bash") (literal "/usr/bin/env") (literal "/r/repo/cli/bin/vt") (literal "/n/bin/node"))', '(deny file-map-executable)', '(deny signal)(allow signal (target self))', '(deny mach-lookup)', '(deny appleevent-send)', '(deny ipc-posix*)', '(deny ipc-sysv*)', '(deny system-socket)', '(deny file-ioctl)']) assert.ok(p.includes(need), need)
    assert.ok(!/\(subpath "\/usr"\)|\(subpath "\/bin"\)|usr\/local/.test(p.replace(/\(deny[^)]*\)/g, '')), 'no /usr, /bin or /usr/local subpath allowed')
  }
  // TTY-less round: NO sandboxed command has a terminal, whatever it prompts for (the unsandboxed broker asks)
  for (const argv of [['job', 'run', 'x'], ['job', 'clawback', 'x'], ['job', 'arm', 'x'], ['job', 'create', 'f'], ['job', 'resolve', 'x'], ['job', 'list'], ['status']]) {
    const p = commandProfileFull(argv, 'local', H, O, scope) as string
    const allows = p.slice(0, p.indexOf(denyTerminals()))
    assert.ok(!allows.includes('/dev/tty'), `${argv.join(' ')}: /dev/tty is in no allow`)
    assert.ok(p.includes('(allow file-ioctl (literal "/dev/null"))'), 'ioctl only on /dev/null')
    assert.ok(p.endsWith(denyTerminals()), 'the terminal denies are the last rule')
  }
  assert.equal(denyTerminals(), '(deny file-read* file-write* file-ioctl (literal "/dev/tty") (regex #"^/dev/(tty[a-z0-9]*|pty[a-z0-9]*|ptmx|console)$"))')
})

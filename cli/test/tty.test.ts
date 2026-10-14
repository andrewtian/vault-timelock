// cli/test/tty.test.ts — `vt job run` at a REAL terminal (plan Task C6): the command runs in a fresh pseudo-terminal
// (vt-broadcast's runInPty: `script -q /dev/null …`), started through the job stub (test/fixtures/job-stub.ts: src/job's
// jobCommand + processIo, as src/main.ts runs it, against a test's ports), so the real /dev/tty readers are used: the
// passphrase (raw mode, no echo), the keys during the run (raw mode: `s`, Ctrl-C as a byte) and the typed words.
// Behind the ports: E3's in-memory API and relay (packages/core/test/fakes) on a real clock, served over HTTP on
// ephemeral 127.0.0.1 ports by this test; they record the Host header vt sends. ALL DATA IS SYNTHETIC.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import { join } from 'node:path'
import type { Chain } from '@vault-timelock/core/contracts'
import { PORTS } from '@vault-timelock/core/contracts'
import { encryptKey, newKey } from '@vault-timelock/core/engine/keys.js'
import { runInPty } from 'vt-broadcast/test/offline/lifecycle/pty.ts'
import type * as HelpersModule from '../../packages/core/test/executor/helpers.ts'
import type * as RelayModule from '../../packages/core/test/fakes/fake-relay.ts'
import { FAULT_CANARY_IP, FAULT_CANARY_KEY, FAULT_MARKER } from './fixtures/fault-hook.ts'
import { CANARY, CLI, IPV4, NODE, PATH0, connectOutcome, ptyLive, removeDir, tempDir } from './lib.ts'

const STUB = join(CLI, 'test', 'fixtures', 'job-stub.ts')
const PASS = 'c6-pty-synthetic-passphrase-never-a-secret'
const TOKEN = 'ef'.repeat(32)
let T = '', VTH = ''
const servers: Server[] = []
// E3's fakes, found through the core package (a mutation-runner copy of this workspace links node_modules only).
const CORE_TEST = new URL('../../test/', import.meta.resolve('@vault-timelock/core/contracts'))
let stack: typeof HelpersModule.stack, stackFetch: typeof RelayModule.stackFetch
before(async () => {
  ;({ stack } = await import(new URL('executor/helpers.ts', CORE_TEST).href) as typeof HelpersModule)
  ;({ stackFetch } = await import(new URL('fakes/fake-relay.ts', CORE_TEST).href) as typeof RelayModule)
  T = tempDir('vt-c6-pty-')
  VTH = join(T, 'vt-home')
  mkdirSync(join(VTH, 'local'), { recursive: true, mode: 0o700 })
  writeFileSync(join(VTH, 'local', 'api.token'), TOKEN, { mode: 0o600 })
})
after(async () => {
  for (const s of servers) { s.closeAllConnections(); await new Promise<void>((r) => s.close(() => r())) }
  removeDir(T)
})

const realClock = { now: () => Date.now(), sleep: (ms: number) => new Promise<void>((r) => setTimeout(r, Math.max(0, ms))), jump: () => {} }
type Handle = { chain: Chain; address: string; secret: string }

// E3's fake stack behind two HTTP servers (the API's and the relay's), reached by vt on ephemeral ports.
async function served(s: ReturnType<typeof HelpersModule.stack>): Promise<{ api: number; relay: number; hosts: Set<string> }> {
  const f = stackFetch({ network: 'local', journal: s.j.client, relay: s.relay.client, token: TOKEN })
  const hosts = new Set<string>()
  const listen = async (origin: string): Promise<number> => {
    const srv = createServer((req, res) => {
      const chunks: Buffer[] = []
      req.on('data', (c: Buffer) => chunks.push(c))
      req.on('end', () => {
        hosts.add(String(req.headers.host))
        const headers: Record<string, string> = {}
        for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') headers[k] = v
        const body = Buffer.concat(chunks)
        f.fetch(`${origin}${req.url ?? '/'}`, { method: req.method, headers, ...(body.length > 0 ? { body: body.toString('utf8') } : {}) })
          .then(async (r) => { res.writeHead(r.status, { 'content-type': r.headers.get('content-type') ?? 'application/json' }); res.end(Buffer.from(await r.arrayBuffer())) }, () => res.destroy())
      })
    })
    servers.push(srv)
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()))
    return (srv.address() as { port: number }).port
  }
  return { api: await listen(`http://127.0.0.1:${PORTS.local.api}`), relay: await listen(`http://127.0.0.1:${PORTS.local.relay}`), hosts }
}
let n = 0
async function backupOf(h: Handle, pass = PASS): Promise<string> {
  const { ct } = await encryptKey(h as never, pass, 'local')
  const f = join(T, `k${++n}.age`)
  writeFileSync(f, ct)
  return f
}
const env = (): Record<string, string> => ({ PATH: PATH0, HOME: T, LANG: 'en_US.UTF-8', TERM: 'xterm', VT_HOME: VTH, VT_JOB_STUB_POLL: '300' })
// node as bin/vt starts it: `node --disable-sigusr1 …` (the executor refuses anything else: vt.inspector)
const argvOf = (ports: { api: number; relay: number }, args: string[]) => [NODE, '--disable-sigusr1', '--no-addons', STUB, String(ports.api), String(ports.relay), 'local', ...args]
function clean(out: string, secrets: string[]): void {
  const low = out.toLowerCase()
  for (const s of secrets) assert.ok(!low.includes(s.toLowerCase()) && !low.includes(s.toLowerCase().replace(/^0x/, '')), 'secret text in the output')
  assert.ok(!out.includes(CANARY) && !IPV4.test(out), 'an IP in the output')
}

test('at a real terminal: the passphrase is not echoed; the run completes; vt addressed the fixed ports (Host); no key, passphrase or IP in the output', { timeout: 120_000 }, async () => {
  const s = stack('eth', { clock: realClock, copies: 1, startIn: 2_000 })
  const ports = await served(s)
  const r = await runInPty(argvOf(ports, ['run', s.j.id, '--backup-eth', await backupOf(s.key.handle as Handle)]), { env: env(), steps: [{ waitFor: 'Passphrase: ', send: `${PASS}\r` }] })
  assert.equal(r.code, 0, r.out)
  assert.ok(!r.out.includes(PASS), 'the passphrase was echoed')
  assert.match(r.out, /eth: copies-done/)
  assert.deepEqual([...ports.hosts].sort(), [`127.0.0.1:${PORTS.local.api}`, `127.0.0.1:${PORTS.local.relay}`].sort())
  clean(r.out, [PASS, (s.key.handle as Handle).secret])
})

test('at a real terminal: a wrong passphrase → refused backup.decrypt; another key → refused backup.address-mismatch (exit 2, nothing echoed)', { timeout: 120_000 }, async () => {
  const s = stack('eth', { clock: realClock, copies: 1, startIn: 60_000 })
  const ports = await served(s)
  const f = await backupOf(s.key.handle as Handle)
  const wrong = 'c6-pty-a-wrong-synthetic-passphrase'
  let r = await runInPty(argvOf(ports, ['run', s.j.id, '--backup-eth', f]), { env: env(), steps: [{ waitFor: 'Passphrase: ', send: `${wrong}\r` }] })
  assert.equal(r.code, 2, r.out)
  assert.match(r.out, /refused backup\.decrypt: /)
  assert.ok(!r.out.includes(wrong))
  const other = newKey('eth') as unknown as Handle
  r = await runInPty(argvOf(ports, ['run', s.j.id, '--backup-eth', await backupOf(other)]), { env: env(), steps: [{ waitFor: 'Passphrase: ', send: `${PASS}\r` }] })
  assert.equal(r.code, 2, r.out)
  assert.match(r.out, /refused backup\.address-mismatch: /)
  clean(r.out, [PASS, other.secret])
  // Ctrl-C at the passphrase prompt aborts (raw mode: a byte, not a signal), nothing decrypted
  r = await runInPty(argvOf(ports, ['run', s.j.id, '--backup-eth', f]), { env: env(), steps: [{ waitFor: 'Passphrase: ', send: 'abc\x03' }] })
  assert.equal(r.code, 2, r.out)
  assert.match(r.out, /refused passphrase\.aborted: /)
  assert.equal(s.j.events.filter((e) => e.type === 'lease-acquired').length, 1, 'no lease but the earlier tab\'s (stack())')
})

test('stdin a pipe while /dev/tty IS a terminal: still refused vt.tty-required (both are needed), nothing read', { timeout: 60_000 }, async () => {
  const argv = argvOf({ api: 1, relay: 1 }, ['run', '0123456789abcdef', '--backup-eth', 'never-read.age'])
  const r = await runInPty(['/bin/sh', '-c', 'printf "%s\\n" not-a-passphrase | "$0" "$@"', ...argv], { env: env() })
  assert.equal(r.code, 2, r.out)
  assert.match(r.out, /refused vt\.tty-required: /)
  assert.ok(!r.out.includes('Passphrase: '))
})

test('no terminal (stdin a pipe): refused vt.tty-required, nothing read', () => {
  const r = spawnSync(NODE, argvOf({ api: 1, relay: 1 }, ['run', '0123456789abcdef', '--backup-eth', 'never-read.age']).slice(1), { env: env(), input: `${PASS}\n`, encoding: 'utf8', timeout: 60_000 })
  assert.equal(r.status, 2, r.stderr)
  assert.match(r.stderr, /^refused vt\.tty-required: /m)
  assert.ok(!r.stdout.includes(PASS) && !r.stderr.includes(PASS))
})

test('at a real terminal: Ctrl-C (a byte in raw mode) mid-transaction → stop after it resolves; a second Ctrl-C warns; vt exits only after the in-flight tx resolved; stopped after included', { timeout: 120_000 }, async () => {
  const HOLD_MS = 3_000
  let firstSend = 0, servedAt = 0, preNonce = '0x0'
  const s = stack('eth', { clock: realClock, copies: 2, startIn: 2_000, eth: (m, p, base) => {
    if (m === 'eth_sendRawTransaction' && firstSend === 0) { preNonce = base('eth_getTransactionCount', []) as string; firstSend = Date.now() }
    const holding = firstSend > 0 && Date.now() < firstSend + HOLD_MS
    if (holding && m === 'eth_getTransactionReceipt') return null
    if (holding && m === 'eth_getTransactionCount') return preNonce
    if (m === 'eth_getTransactionReceipt' && servedAt === 0 && firstSend > 0) servedAt = Date.now()
    return base(m, p)
  } })
  const ports = await served(s)
  const r = await runInPty(argvOf(ports, ['run', s.j.id, '--backup-eth', await backupOf(s.key.handle as Handle)]), { env: env(), steps: [
    { waitFor: 'Passphrase: ', send: `${PASS}\r` },
    { waitFor: 'copy 1 part 1/1', send: '\x03' },
    { waitFor: 'stopping after the in-flight transaction', send: '\x03' },
  ] })
  const exitedAt = Date.now()
  assert.equal(r.code, 0, r.out)
  assert.ok(servedAt > 0 && exitedAt >= servedAt, 'vt exited after the in-flight tx resolved')
  assert.match(r.out, /still waiting: a transaction that may land is never abandoned/)
  assert.ok(r.out.indexOf('stopping after the in-flight transaction') < r.out.indexOf('eth: stopped'), r.out)
  const evs = s.j.events.filter((e) => e.chain === 'eth')
  const inc = evs.findIndex((e) => e.type === 'included'), st = evs.findIndex((e) => e.type === 'stopped')
  assert.ok(inc >= 0 && st < 0, `R79: a Ctrl-C detaches — nothing journaled stopped: ${evs.map((e) => e.type).join(' ')}`)
  assert.equal(evs.filter((e) => e.type === 'intent').length, 1, 'copy 2 never signed')
  clean(r.out, [PASS, (s.key.handle as Handle).secret])
})

test('at a real terminal: `s` during the countdown skips it, once (a second `s` says so)', { timeout: 120_000 }, async () => {
  const s = stack('eth', { clock: realClock, copies: 1, startIn: 30_000 })
  const ports = await served(s)
  const t0 = Date.now()
  const r = await runInPty(argvOf(ports, ['run', s.j.id, '--backup-eth', await backupOf(s.key.handle as Handle)]), { env: env(), steps: [
    { waitFor: 'Passphrase: ', send: `${PASS}\r` },
    { waitFor: "(s = skip the countdown, Ctrl-C = detach", send: 's' },
    { waitFor: 'Skip: the countdown ends now', send: 'S' },
  ] })
  assert.equal(r.code, 0, r.out)
  assert.equal(s.j.calls.filter((x) => x === 'skip').length, 1)
  assert.match(r.out, /Skip: already done/)
  assert.match(r.out, /eth: copies-done/)
  assert.ok(Date.now() - t0 < 28_000, 'the 30 s countdown was skipped')
})

// ---- fix round 1 (task-C6-review.md m-1, m-4)

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))
async function until(ok: () => boolean, ms: number, what: string): Promise<void> {
  const end = Date.now() + ms
  while (!ok()) { if (Date.now() > end) assert.fail(`timed out: ${what}`); await sleep(50) }
}
const alive = (pid: number): boolean => { try { process.kill(pid, 0); return true } catch { return false } }
const INSPECTOR_PORT = 9229 // Node's default, where SIGUSR1 would open it (no --inspect-port is ever allowed)
// The TCP ports a process listens on (lsof, the pid's own sockets). Compared before and after a signal, so the test holds
// on a machine where something already listens on 9229 (C7, parked from the C6 re-review: no hard-coded precondition).
const LSOF = '/usr/sbin/lsof'
function listeningPorts(pid: number): string[] {
  const r = spawnSync(LSOF, ['-nP', '-a', '-p', String(pid), '-iTCP', '-sTCP:LISTEN', '-Fn'], { encoding: 'utf8', timeout: 20_000 })
  assert.ok(r.status === 0 || r.status === 1, `lsof failed: ${r.stderr}`)                 // 1: no such socket
  return r.stdout.split('\n').filter((l) => l.startsWith('n')).sort()
}

test('review m-4: the executor process refuses vt.inspector unless started as bin/vt starts it — no --disable-sigusr1, an inspector option, NODE_OPTIONS — before anything is read', () => {
  const args = [STUB, '1', '1', 'local', 'run', '0123456789abcdef', '--backup-eth', 'never-read.age']
  const cases: Array<[string[], Record<string, string>]> = [
    [[], {}],
    [['--disable-sigusr1', '--no-addons', '--inspect-port=0'], {}],
    [['--inspect-port=0', '--disable-sigusr1', '--no-addons'], {}],
    [['--disable-sigusr1', '--no-addons'], { NODE_OPTIONS: '--max-old-space-size=256' }],
  ]
  for (const [flags, extra] of cases) {
    const r = spawnSync(NODE, [...flags, ...args], { env: { ...env(), ...extra }, input: '', encoding: 'utf8', timeout: 60_000 })
    assert.equal(r.status, 2, `${flags.join(' ')} ${JSON.stringify(extra)}: ${r.stderr}`)
    assert.match(r.stderr, /^refused vt\.inspector: /m)
    assert.ok(!r.stderr.includes('Passphrase'))
  }
})

test('review m-4: SIGUSR1 to a running executor opens no inspector (no NEW listener appears: not on 9229, none on the process, no "Debugger listening"); the run goes on to its normal end', { timeout: 120_000 }, async () => {
  // Control: here, SIGUSR1 makes a plain node (started without --disable-sigusr1) open its inspector, so the check below
  // is not vacuous. Its own random port (--inspect-port=0); it is killed by its handle.
  const ctl = spawn(NODE, ['--inspect-port=0', '-e', 'process.stdout.write("ready\\n"); setTimeout(() => {}, 30000)'], { stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: PATH0 } })
  let ctlOut = '', ctlErr = ''
  try {
    ctl.stdout.on('data', (d: Buffer) => { ctlOut += d.toString() })
    ctl.stderr.on('data', (d: Buffer) => { ctlErr += d.toString() })
    await until(() => ctlOut.includes('ready'), 20_000, 'the control node started')
    process.kill(ctl.pid!, 'SIGUSR1')
    await until(() => ctlErr.includes('Debugger listening'), 20_000, 'control: SIGUSR1 opens the inspector of a node started without --disable-sigusr1')
  } finally {
    ctl.kill('SIGKILL')
  }
  assert.ok(existsSync(LSOF), 'lsof is needed to list the executor\'s listeners')
  const portBefore = await connectOutcome(INSPECTOR_PORT)       // whatever this machine has on 9229 now (usually nothing)
  const s = stack('eth', { clock: realClock, copies: 1, startIn: 25_000 })   // long enough that the signal (sent on the first countdown line, after the executor printed its own pid) is never late
  const ports = await served(s)
  const h = s.key.handle as Handle
  const f = await backupOf(h)
  let pid = 0, typed = false, signalled = false
  let listenersBefore: string[] = []
  let probe: Promise<{ port: string; alive: boolean; listeners: string[] }> | null = null
  const r = await ptyLive(argvOf(ports, ['run', s.j.id, '--backup-eth', f]), { env: env(), timeoutMs: 120_000, on: (out, type) => {
    if (pid === 0) { const m = /vt-job-stub argv (\{[^\r\n]*\})/.exec(out); if (m !== null) pid = (JSON.parse(m[1]) as { pid: number }).pid }
    if (!typed && out.includes('Passphrase: ')) { typed = true; type(`${PASS}\r`) }
    if (!signalled && pid > 0 && /eth {2}countdown /.test(out)) {
      signalled = true
      listenersBefore = listeningPorts(pid)
      process.kill(pid, 'SIGUSR1') // the executor's own recorded pid
      probe = sleep(2_000).then(async () => ({ port: await connectOutcome(INSPECTOR_PORT), alive: alive(pid), listeners: alive(pid) ? listeningPorts(pid) : [] }))
    }
  } })
  assert.ok(signalled, 'SIGUSR1 was sent during the countdown')
  const p = await probe!
  assert.equal(p.alive, true, 'the executor was still running 2 s after SIGUSR1')
  assert.equal(p.port, portBefore, 'no new listener on the default inspector port')
  assert.deepEqual(p.listeners, listenersBefore, 'the executor opened no listener')
  assert.deepEqual(listenersBefore, [], 'the executor listens on nothing')
  assert.equal(r.code, 0, r.out)
  assert.match(r.out, /eth: copies-done/)
  assert.ok(!/Debugger listening|ws:\/\/|inspector/i.test(r.out), 'no inspector line')
  clean(r.out, [PASS, h.secret])
})

test('review m-1: an unhandled rejection or uncaught exception in a running executor (the test-only fault hook: its message holds a canary IP and a canary 64-hex key) → neither is printed, the keys are zeroed, ONE fixed line and what it means, exit 1', { timeout: 120_000 }, async () => {
  for (const [spec, sent] of [['intent:rejection', true], ['keys:exception', false]] as const) {
    const s = stack('sol', { clock: realClock, copies: 1, startIn: 1_000 })
    const ports = await served(s)
    const h = s.key.handle as Handle
    const p = await runInPty(argvOf(ports, ['run', s.j.id, '--backup-sol', await backupOf(h)]), { env: { ...env(), NODE_ENV: 'test', VT_JOB_STUB_FAULT: spec }, steps: [{ waitFor: 'Passphrase: ', send: `${PASS}\r` }] })
    const r = { code: p.code, out: Buffer.from(p.out, 'latin1').toString('utf8') } // runInPty reads latin1; vt prints UTF-8
    for (const x of [FAULT_CANARY_IP, FAULT_CANARY_KEY, FAULT_MARKER]) assert.ok(!r.out.includes(x), `${spec}: the fault's text reached the terminal`)
    assert.ok(!/^\s+at /m.test(r.out), `${spec}: a stack trace was printed`)
    assert.equal(r.code, 1, `${spec}: exit code ${String(r.code)}`)
    const kind = spec.endsWith('rejection') ? 'an unhandled rejection' : 'an uncaught exception'
    assert.equal(r.out.split('an unexpected internal error').length - 1, 1, `${spec}: one line`)
    assert.match(r.out, new RegExp(`vt job run: an unexpected internal error \\(Error\\), ${kind}, ended this process; its text is withheld \\(it could hold an address or key material\\); the keys were dropped`))
    assert.match(r.out, sent ? /sol: stopped unexpectedly after sending — run `vt job run` again to reconcile \(nothing will be sent twice\)/ : /sol: did not run — nothing was sent/)
    assert.match(r.out, /vt-job-stub keys-zeroed true/, `${spec}: the SOL secret bytes were zeroed`)
    assert.equal(s.j.events.some((e) => e.chain === 'sol' && e.type === 'intent'), sent)
    clean(r.out, [PASS, h.secret])
  }
  // without NODE_ENV=test the hook is refused, before anything is read
  const r = spawnSync(NODE, argvOf({ api: 1, relay: 1 }, ['run', '0123456789abcdef', '--backup-sol', 'never-read.age']).slice(1), { env: { ...env(), VT_JOB_STUB_FAULT: 'keys:rejection' }, input: '', encoding: 'utf8', timeout: 60_000 })
  assert.equal(r.status, 2, r.stderr)
  assert.match(r.stderr, /^refused vt\.test-fault: /m)
})

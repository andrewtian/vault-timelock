// cli/test/confine.test.ts — the profiles of src/ops/sandbox.ts in the REAL sandbox, and assertConfined
// (src/ops/confine.ts) under each of them (plan Task C1).
// This file applies sandboxes itself, so it runs OUTSIDE the suite sandbox (test/own-sandbox.list; scripts/test-root.sh
// phase B): macOS refuses to apply a profile inside a sandbox.
// ★ No packet leaves the machine: TEST-NET-1 is only ever probed inside a profile that denies it (EPERM at connect),
//   and assertConfined stops at the loopback probe whenever that is not denied. Tor's port is never probed. Every
//   listener is a test-owned ephemeral port on 127.0.0.1.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, readdirSync, writeFileSync } from 'node:fs'
import { createServer, type Server } from 'node:net'
import { join } from 'node:path'
import { scopeFor } from '../src/ops/scope.ts'
import { apiProfile, commandProfile, loopbackProfile, relayProfile } from '../src/ops/sandbox.ts'
import { CLI, IPV4, NODE, removeDir, tempDir } from './lib.ts'

let T = ''
let L = 0 // a listener the profile under test allows
let M = 0 // a listener nobody allowed: must stay blocked
const servers: Server[] = []
const CONFINE = join(CLI, 'src', 'ops', 'confine.ts')
const TEST_NET = '192.0.2.1:9'
const LOOPBACK_9 = '127.0.0.1:9'

async function listen(): Promise<number> {
  const s = createServer((c) => c.end())
  servers.push(s)
  await new Promise<void>((res) => s.listen(0, '127.0.0.1', () => res()))
  const a = s.address()
  if (a === null || typeof a === 'string') throw new Error('no port')
  return a.port
}

before(async () => {
  T = tempDir('vt-confine-')
  L = await listen()
  M = await listen()
  // The probe: connects, file writes and assertConfined, reported as JSON. Run as `node probe.mjs <spec...>`.
  writeFileSync(join(T, 'probe.mjs'), `
import { connect } from 'node:net'
import { openSync, closeSync, writeFileSync, constants } from 'node:fs'
const out = {}
for (const spec of process.argv.slice(2)) {
  const [kind, target] = spec.split('=')
  if (kind === 'tcp') {
    const i = target.lastIndexOf(':')
    out[spec] = await new Promise((res) => {
      const s = connect({ host: target.slice(0, i), port: Number(target.slice(i + 1)) })
      const timer = setTimeout(() => { s.destroy(); res('timeout') }, 3000)
      s.on('connect', () => { clearTimeout(timer); s.destroy(); res('connected') })
      s.on('error', (e) => { clearTimeout(timer); res(e.code ?? 'error') })
    })
  } else if (kind === 'listen') {
    // listen=<host>: a test-owned ephemeral listener on loopback (port 0), then it is closed again
    const { createServer } = await import('node:net')
    out[spec] = await new Promise((res) => {
      const srv = createServer((c) => c.end())
      srv.on('error', (e) => res(e.code ?? 'error'))
      srv.listen(0, target, () => srv.close(() => res('listening')))
    })
  } else if (kind === 'write') {
    try { writeFileSync(target, 'x'); out[spec] = 'ok' } catch (e) { out[spec] = e.code }
  } else if (kind === 'open-rw') {
    try { closeSync(openSync(target, constants.O_RDWR | constants.O_NOCTTY)); out[spec] = 'ok' } catch (e) { out[spec] = e.code }
  } else if (kind === 'confined-with') {
    // confined-with=<internet host:port>|<write dir>: assertConfinedWith with the real loopback probe, the given "internet"
    // and the given write dir (the proof's seam: a listener stands in for the internet, so no packet leaves the machine).
    const [net, dir] = target.split('|')
    const i = net.lastIndexOf(':')
    const { assertConfinedWith } = await import(${JSON.stringify(CONFINE)})
    try {
      await assertConfinedWith({ loopback: { host: '127.0.0.1', port: 9 }, internet: { host: net.slice(0, i), port: Number(net.slice(i + 1)) }, writeDirs: [dir] }, 2000)
      out[spec] = 'confined'
    } catch (e) { out[spec] = 'refused ' + e.guardId; out.message = e.message }
  } else if (kind === 'confined-net') {
    // The network arms alone (writeDirs empty): the relay's own profile may write (it keeps its journal), and it is not a
    // client or executor, so main.ts never asks it for the write proof.
    const { assertConfinedWith } = await import(${JSON.stringify(CONFINE)})
    try {
      await assertConfinedWith({ loopback: { host: '127.0.0.1', port: 9 }, internet: { host: '192.0.2.1', port: 9 }, writeDirs: [] }, 2000)
      out[spec] = 'confined'
    } catch (e) { out[spec] = 'refused ' + e.guardId; out.message = e.message }
  } else if (kind === 'confined-dir') {
    const { assertConfined } = await import(${JSON.stringify(CONFINE)})
    try { await assertConfined({ writeDirs: [target] }); out[spec] = 'confined' } catch (e) { out[spec] = 'refused ' + e.guardId; out.message = e.message }
  } else if (kind === 'confined') {
    const { assertConfined } = await import(${JSON.stringify(CONFINE)})
    try { await assertConfined(); out[spec] = 'confined' } catch (e) { out[spec] = 'refused ' + e.guardId; out.message = e.message }
  }
}
process.stdout.write(JSON.stringify(out) + '\\n')
`)
})
after(async () => {
  for (const s of servers) await new Promise<void>((res) => s.close(() => res()))
  removeDir(T)
})

function probe(profile: string | null, specs: string[]): Record<string, string> {
  const argv = [NODE, join(T, 'probe.mjs'), ...specs]
  const env = { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: join(T) }
  const r = profile === null
    ? spawnSync(argv[0], argv.slice(1), { encoding: 'utf8', env, timeout: 60_000 })
    : spawnSync('/usr/bin/sandbox-exec', ['-p', profile, ...argv], { encoding: 'utf8', env, timeout: 60_000 })
  assert.equal(r.status, 0, r.stderr)
  return JSON.parse(r.stdout) as Record<string, string>
}
const lo = (p: number) => `tcp=127.0.0.1:${p}`

test('unsandboxed: assertConfined refuses vt.not-confined at the loopback probe (TEST-NET-1 not tried); a listener is reachable', () => {
  const out = probe(null, ['confined', lo(L)])
  assert.equal(out.confined, 'refused vt.not-confined')
  assert.match(out.message, /TEST-NET-1: not tried/)
  assert.ok(!IPV4.test(out.message), 'the refusal names no address')
  assert.equal(out[lo(L)], 'connected', 'positive control: the probe can connect when nothing denies it')
})

test('loopbackProfile (client): only its ports; TEST-NET-1 and loopback 9 EPERM; no file writes but /dev/null; assertConfined passes', () => {
  const file = join(T, 'client-write')
  const out = probe(loopbackProfile([L]), ['confined', lo(L), lo(M), `tcp=${LOOPBACK_9}`, `tcp=${TEST_NET}`, `write=${file}`, 'write=/dev/null', 'open-rw=/dev/tty'])
  assert.deepEqual(out, {
    confined: 'confined', [lo(L)]: 'connected', [lo(M)]: 'EPERM', [`tcp=${LOOPBACK_9}`]: 'EPERM', [`tcp=${TEST_NET}`]: 'EPERM',
    [`write=${file}`]: 'EPERM', 'write=/dev/null': 'ok', 'open-rw=/dev/tty': 'EPERM',
  })
})

test('M4c (Cfix4 e0ebca5 verified): the profile bin/vt really applies to a client command (commandProfile) denies network-bind, and the page-server profile keeps listening', () => {
  for (const argv of [['status'], ['preflight'], ['job', 'list'], ['job', 'create', 'x.json'], ['job', 'run', 'x'], ['job', 'clawback', 'x']]) {
    const out = probe(commandProfile(argv, 'local', '/tmp/vt-confine-h', '/tmp/vt-confine-o', { ...scopeFor(argv, { HOME: process.env.HOME }), handed: [join(T, 'probe.mjs')] }), ['listen=127.0.0.1'])
    assert.equal(out['listen=127.0.0.1'], 'EPERM', `${argv.join(' ')}: a vt command never listens`)
  }
  assert.equal(probe(null, ['listen=127.0.0.1'])['listen=127.0.0.1'], 'listening', 'positive control: unsandboxed the probe can listen')
  assert.equal(probe(loopbackProfile([L]), ['listen=127.0.0.1'])['listen=127.0.0.1'], 'listening', 'the page server profile (no noListen) listens')
})

test('loopbackProfile with tty (executor): /dev/tty is no longer denied by the sandbox (ENXIO here: no terminal), the rest unchanged', () => {
  const file = join(T, 'executor-write')
  const out = probe(loopbackProfile([L], { tty: true }), ['confined', lo(L), lo(M), `tcp=${TEST_NET}`, `write=${file}`, 'open-rw=/dev/tty'])
  assert.equal(out.confined, 'confined')
  assert.equal(out[lo(L)], 'connected')
  assert.equal(out[lo(M)], 'EPERM')
  assert.equal(out[`tcp=${TEST_NET}`], 'EPERM')
  assert.equal(out[`write=${file}`], 'EPERM')
  assert.notEqual(out['open-rw=/dev/tty'], 'EPERM')
})

test('assertConfined refuses a looser sandbox: every loopback port open (the suite\'s kind), or port 9 widened', () => {
  const suiteLike = '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))'
  for (const profile of [suiteLike, loopbackProfile([9, L])]) {
    const out = probe(profile, ['confined'])
    assert.equal(out.confined, 'refused vt.not-confined')
    assert.ok(!IPV4.test(out.message))
  }
})

test('relayProfile: local reaches exactly its chain ports (plus Tor, never probed); testnet/mainnet only Tor', () => {
  let out = probe(relayProfile('local', [L]), ['confined-net', lo(L), lo(M), `tcp=${TEST_NET}`])
  assert.deepEqual(out, { 'confined-net': 'confined', [lo(L)]: 'connected', [lo(M)]: 'EPERM', [`tcp=${TEST_NET}`]: 'EPERM' })
  for (const n of ['testnet', 'mainnet'] as const) {
    out = probe(relayProfile(n, []), ['confined-net', lo(L), `tcp=${TEST_NET}`])
    assert.deepEqual(out, { 'confined-net': 'confined', [lo(L)]: 'EPERM', [`tcp=${TEST_NET}`]: 'EPERM' })
  }
})

test('apiProfile: no outbound connection at all; writes only below its state dir (and /dev/null)', () => {
  const state = join(T, 'vt-home', 'local')
  mkdirSync(state, { recursive: true })
  const inside = join(state, 'jobs.jsonl')
  const outside = join(T, 'vt-home', 'escaped')
  const out = probe(apiProfile(state), ['confined', lo(L), `tcp=${TEST_NET}`, `write=${inside}`, `write=${outside}`, 'write=/dev/null'])
  assert.deepEqual(out, {
    confined: 'confined', [lo(L)]: 'EPERM', [`tcp=${TEST_NET}`]: 'EPERM', [`write=${inside}`]: 'ok', [`write=${outside}`]: 'EPERM', 'write=/dev/null': 'ok',
  })
})

// ---- Cfix5 M1: the "internet not denied" arm --------------------------------------------------------------------
test('assertConfined refuses when loopback port 9 is denied but the "internet" probe connects (the TEST-NET-1 arm); a denied one passes', () => {
  const dir = join(T, 'probe-dir-m1')
  mkdirSync(dir, { recursive: true })
  const spec = `confined-with=127.0.0.1:${L}|${dir}`
  // loopback 9 EPERM, the stand-in "internet" (a test listener) allowed -> the TEST-NET-1 arm sees 'connected'.
  let out = probe(loopbackProfile([L]), [spec])
  assert.equal(out[spec], 'refused vt.not-confined')
  assert.match(out.message, /loopback port 9: EPERM; TEST-NET-1: connected; file writes: not tried/)
  // The same probe with the "internet" denied too (an unlisted listener) passes the network arms; the write arm is then
  // the only one left, and the client profile denies it.
  const denied = `confined-with=127.0.0.1:${M}|${dir}`
  out = probe(loopbackProfile([L]), [denied])
  assert.equal(out[denied], 'confined')
  assert.deepEqual(readdirSync(dir), [], 'a denied write probe leaves nothing behind')
})

// ---- Cfix5 M4: the proof covers file writes too ------------------------------------------------------------------
test('assertConfined refuses a sandbox that denies the network but allows file writes; the probe file is deleted again, the message names no path', () => {
  const dir = join(T, 'probe-dir-m4')
  mkdirSync(dir, { recursive: true })
  const netOnly = '(version 1)(allow default)(deny network-outbound)'
  const spec = `confined-dir=${dir}`
  const out = probe(netOnly, [spec])
  assert.equal(out[spec], 'refused vt.not-confined')
  assert.match(out.message, /loopback port 9: EPERM; TEST-NET-1: EPERM; file writes: created/)
  assert.ok(!out.message.includes(dir) && !out.message.includes(T), 'no path in the refusal')
  assert.deepEqual(readdirSync(dir), [], 'the probe file was deleted again')
  // The same sandbox with writes denied everywhere (the client profile) passes with the same dir.
  const out2 = probe(loopbackProfile([L]), [spec])
  assert.equal(out2[spec], 'confined')
  assert.deepEqual(readdirSync(dir), [])
})

test('the write arm: a directory the profile allows writes to refuses, even when the temp dir is denied; a missing directory is skipped', () => {
  const allowed = join(T, 'probe-dir-allowed')
  mkdirSync(allowed, { recursive: true })
  const profile = `${loopbackProfile([L])}(allow file-write* (subpath ${JSON.stringify(allowed)}))`
  const spec = `confined-dir=${allowed}`
  const out = probe(profile, [spec])
  assert.equal(out[spec], 'refused vt.not-confined')
  assert.match(out.message, /file writes: (created|EPERM,created|created,EPERM)/)
  assert.deepEqual(readdirSync(allowed), [])
  const missing = `confined-dir=${join(T, 'does-not-exist')}`
  assert.equal(probe(loopbackProfile([L]), [missing])[missing], 'confined')
})

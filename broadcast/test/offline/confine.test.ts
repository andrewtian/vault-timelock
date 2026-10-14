// Confinement self-check (spec B s6.1, C s6.1, Task 7 + 7b). assertConfined() makes two direct
// connection attempts and accepts ONLY EPERM for both (feasibility/F5.txt):
//   1. 192.0.2.1:9 (TEST-NET-1, never routed): proves a sandbox denies the internet
//      (else confine.not-sandboxed);
//   2. loopback port 9, which no run configures: proves it is the broadcaster's narrow profile, not a
//      looser one such as the test suite's "every loopback port" (else confine.loopback-open).
// Every arm runs in a child process, so this file must itself run OUTSIDE any sandbox
// (scripts/test-offline.sh runs it in its unsandboxed phase): macOS refuses to apply a different
// profile inside a sandbox, and inside one the "unsandboxed" arm would be confined too.
// The child only runs assertConfined (never the Tor gate), so no arm can reach Tor.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const PRODUCTION_PROFILE =
  '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:9050"))'
// The test suite's kind of profile: the internet is denied, but every loopback port is open.
const LOOPBACK_OPEN_PROFILE =
  '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))'
// Loopback denied, the internet not: the TEST-NET-1 attempt is the only one that notices.
const LOOPBACK_ONLY_DENIED_PROFILE = '(version 1)(allow default)(deny network-outbound (remote ip "localhost:*"))'
// A run that configured loopback port 9 itself (e.g. --rpc eth=http://127.0.0.1:9): fails closed.
const PORT_9_WIDENED_PROFILE = PRODUCTION_PROFILE + '(allow network-outbound (remote ip "localhost:9"))'

const CONFINE = fileURLToPath(new URL('../../src/net/confine.ts', import.meta.url))
const SCRIPT = `import { assertConfined } from ${JSON.stringify(CONFINE)}
try { await assertConfined(); console.log('confined') }
catch (e) { console.log('refused ' + e.guardId); console.error(String(e.message)); process.exitCode = 2 }`

function run(profile: string | null) {
  const argv = [process.execPath, '--input-type=module', '-e', SCRIPT]
  const env = { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '' }
  const r = profile !== null
    ? spawnSync('/usr/bin/sandbox-exec', ['-p', profile, ...argv], { encoding: 'utf8', env, timeout: 30_000 })
    : spawnSync(argv[0], argv.slice(1), { encoding: 'utf8', env, timeout: 30_000 })
  return { code: r.status, out: r.stdout, err: r.stderr }
}
const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/

test('unsandboxed: assertConfined refuses with confine.not-sandboxed (no EPERM, so no proof)', () => {
  const r = run(null)
  assert.equal(r.out, 'refused confine.not-sandboxed\n')
  assert.equal(r.code, 2)
  assert.ok(!IPV4.test(r.err), 'the refusal names no IP')
})

test('under the production profile: assertConfined passes (EPERM on TEST-NET-1 and on loopback port 9)', () => {
  const r = run(PRODUCTION_PROFILE)
  assert.equal(r.err, '')
  assert.equal(r.out, 'confined\n')
  assert.equal(r.code, 0)
})

test('confine.loopback-open: a sandbox that denies the internet but opens every loopback port is refused', () => {
  const r = run(LOOPBACK_OPEN_PROFILE)
  assert.equal(r.out, 'refused confine.loopback-open\n')
  assert.equal(r.code, 2)
  assert.ok(!IPV4.test(r.err), 'the refusal names no IP')
})

test('confine.loopback-open: a run that widened loopback port 9 itself fails closed', () => {
  const r = run(PORT_9_WIDENED_PROFILE)
  assert.equal(r.out, 'refused confine.loopback-open\n')
  assert.equal(r.code, 2)
})

test('both measurements are needed: loopback denied but the internet not -> confine.not-sandboxed', () => {
  const r = run(LOOPBACK_ONLY_DENIED_PROFILE)
  assert.equal(r.out, 'refused confine.not-sandboxed\n')
  assert.equal(r.code, 2)
})

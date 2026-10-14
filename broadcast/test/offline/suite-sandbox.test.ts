// The sentinel (Task 7b; Task H0 items 3, 6, 7). Its harnesses run it INSIDE the real runs, so a run
// that silently lost a wall (a changed script, a different runner) fails instead of running tests with
// the internet, the operator's environment or the real HOME:
//   · scripts/test-offline.sh phase A sets VT_SUITE_SANDBOX=1 (under the suite sandbox);
//   · test/mutation/run.ts runs it first, through the same spawn path as the mapped tests: =1 under the
//     suite sandbox, and =env unsandboxed (the path of the OWN_SANDBOX files). It stops unless both pass.
// What it checks:
//   both modes: the environment is clean (only PATH HOME LANG TERM, the two sentinel variables, and what
//     node --test and macOS add: NODE_TEST_CONTEXT, __CF_USER_TEXT_ENCODING), so no ALCHEMY_API_KEY,
//     NODE_OPTIONS or HTTPS_PROXY; and HOME is synthetic: a directory that is not the account's home (K31);
//   =1 also: TEST-NET-1 and the loopback relay ports give EPERM: Tor's SOCKS ports 9050/9150 and, since
//     H0 (SA-N1), Chrome DevTools 9222, the E2EE sidecar 8931 and Ollama 11434, loopback listeners that
//     turn a loopback connect into internet traffic.
// Probe order, so a broken sandbox never reaches a live listener: TEST-NET-1 first (nothing listens
// there), then for each relay port [::1] before 127.0.0.1 (those listeners are on 127.0.0.1; the deny
// rule is "*:<port>", so both addresses are denied or neither), stopping at the first answer that is
// not EPERM. Nothing is ever sent on a socket.
//
// Without VT_SUITE_SANDBOX (a plain `node --test`) it is skipped with a reason: the only allowed skip.
// Any value other than 1 or env fails. A skip still lets node --test exit 0, so after passing it writes
// its marker to VT_SUITE_SENTINEL_FILE (when given), and each harness fails unless it reads exactly that
// marker (SANDBOXED_MARKER / ENV_MARKER, repeated in scripts/test-offline.sh and test/mutation/run.ts).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { statSync, writeFileSync } from 'node:fs'
import { connect } from 'node:net'
import { userInfo } from 'node:os'

const RELAY_PORTS = [9050, 9150, 9222, 8931, 11434] as const
const SANDBOXED_MARKER = 'sentinel: env clean, HOME synthetic, EPERM on 192.0.2.1:9 and loopback 9050 9150 9222 8931 11434'
const ENV_MARKER = 'sentinel: env clean, HOME synthetic'

const FLAG = process.env.VT_SUITE_SANDBOX
const SKIP = FLAG === undefined || FLAG === ''
  ? 'VT_SUITE_SANDBOX is not set: this sentinel only runs inside phase A of scripts/test-offline.sh and in test/mutation/run.ts'
  : false
const ALLOWED_ENV = ['PATH', 'HOME', 'LANG', 'TERM', 'VT_SUITE_SANDBOX', 'VT_SUITE_SENTINEL_FILE', 'NODE_TEST_CONTEXT', '__CF_USER_TEXT_ENCODING']

function attempt(host: string, port: number): Promise<string> {
  return new Promise((done) => {
    const s = connect({ host, port })
    const t = setTimeout(() => { s.destroy(); done('timeout') }, 2_000)
    s.on('connect', () => { clearTimeout(t); s.destroy(); done('connected') })
    s.on('error', (e: NodeJS.ErrnoException) => { clearTimeout(t); done(typeof e.code === 'string' ? e.code : 'error') })
  })
}

test('sentinel: clean env and synthetic HOME; under the suite sandbox, TEST-NET-1 and the loopback relay ports give EPERM', { skip: SKIP }, async () => {
  assert.ok(FLAG === '1' || FLAG === 'env', 'VT_SUITE_SANDBOX must be 1, env or unset')
  for (const n of ['ALCHEMY_API_KEY', 'NODE_OPTIONS', 'HTTPS_PROXY']) assert.equal(process.env[n], undefined, `${n} reached the test process`)
  assert.deepEqual(Object.keys(process.env).filter((n) => !ALLOWED_ENV.includes(n)).sort(), [], 'only the allowlisted variables are set')
  const home = process.env.HOME ?? ''
  assert.ok(home !== '' && home !== userInfo().homedir, 'HOME is synthetic, not the account home')
  assert.ok(statSync(home).isDirectory(), 'HOME is a directory')
  if (FLAG === '1') {
    assert.equal(await attempt('192.0.2.1', 9), 'EPERM', 'TEST-NET-1 (nothing on loopback is probed unless this is denied)')
    for (const port of RELAY_PORTS) {
      assert.equal(await attempt('::1', port), 'EPERM', `[::1]:${port}`)
      assert.equal(await attempt('127.0.0.1', port), 'EPERM', `127.0.0.1:${port}`)
    }
  }
  const marker = process.env.VT_SUITE_SENTINEL_FILE
  if (marker !== undefined && marker !== '') writeFileSync(marker, FLAG === '1' ? SANDBOXED_MARKER : ENV_MARKER)
})

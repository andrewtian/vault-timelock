// OWN SANDBOX (listed in test/own-sandbox.list; test-root.sh runs it unsandboxed in phase B, because macOS refuses to
// apply a profile inside a sandbox). The API process proves its own confinement before it listens:
//   · unsandboxed, main.ts exits 2 with api.not-confined (stopped by the local write probe: no packet leaves);
//   · under the API profile (mirroring C1's apiProfile(stateDir) string) it prints the ready line and serves;
//   · under a looser profile (loopback open, or writes allowed) it exits 2 with api.not-confined.
// Children get env -i style environments (PATH, HOME, NODE_ENV=test for --port 0) and are stopped by their recorded pid.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { CANARY, TOKEN, call, makeHome, tempDir } from './helpers.ts'

const MAIN = fileURLToPath(new URL('../src/main.ts', import.meta.url))
const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/
// C1's cli/src/ops/sandbox.ts apiProfile(stateDir), verbatim from the plan.
const apiProfile = (stateDir: string): string =>
  `(version 1)(allow default)(deny network-outbound)(deny file-write*)(allow file-write* (subpath "${stateDir}") (literal "/dev/null"))`
// Looser profiles a careless wrapper might use.
const loopbackOpen = (stateDir: string): string =>
  `(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))(deny file-write*)(allow file-write* (subpath "${stateDir}") (literal "/dev/null"))`
const writesOpen = '(version 1)(allow default)(deny network-outbound)'

function setup(t: { after(fn: () => void): void }): { home: string; state: string } {
  const { dir, cleanup } = tempDir('vt-api-confine-')
  t.after(cleanup)
  const home = join(dir, 'home')
  return { home, state: makeHome(home, 'local') }
}
const argv = (home: string): string[] => [MAIN, '--network', 'local', '--home', home, '--build', 'confinetest', '--port', '0']
const env = (home: string): Record<string, string> => ({ PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home, NODE_ENV: 'test' })

function runToExit(cmd: string, args: string[], e: Record<string, string>): { code: number | null; out: string; err: string } {
  const r = spawnSync(cmd, args, { encoding: 'utf8', env: e, timeout: 60_000 })
  return { code: r.status, out: r.stdout, err: r.stderr }
}

test('unsandboxed: main.ts exits 2 with api.not-confined, prints no ready line and no address, and frees its lock', (t) => {
  const { home, state } = setup(t)
  const r = runToExit(process.execPath, argv(home), env(home))
  assert.equal(r.code, 2)
  assert.equal(r.out, '')
  assert.match(r.err, /^refused api\.not-confined: the API is not confined \(write outside the state dir: written\)/)
  assert.ok(!IPV4.test(r.err))
  assert.equal(existsSync(join(state, 'api.lock')), false)
})

test('looser profiles: loopback open, or writes outside the state dir allowed → exit 2 api.not-confined', (t) => {
  const { home, state } = setup(t)
  const lo = runToExit('/usr/bin/sandbox-exec', ['-p', loopbackOpen(state), process.execPath, ...argv(home)], env(home))
  assert.equal(lo.code, 2)
  assert.match(lo.err, /^refused api\.not-confined: .*loopback port 9: ECONNREFUSED/)
  const wr = runToExit('/usr/bin/sandbox-exec', ['-p', writesOpen, process.execPath, ...argv(home)], env(home))
  assert.equal(wr.code, 2)
  assert.match(wr.err, /^refused api\.not-confined: .*write outside the state dir: written/)
  for (const r of [lo, wr]) {
    assert.equal(r.out, '')
    assert.ok(!IPV4.test(r.err))
  }
})

test('a profile that allows $VT_HOME instead of $VT_HOME/<network> is caught by the write probe beside the state dir (S1 review m5)', (t) => {
  const { home, state } = setup(t)
  const wrong = `(version 1)(allow default)(deny network-outbound)(deny file-write*)(allow file-write* (subpath "${home}") (literal "/dev/null"))`
  const r = runToExit('/usr/bin/sandbox-exec', ['-p', wrong, process.execPath, ...argv(home)], env(home))
  assert.equal(r.code, 2)
  assert.match(r.err, /^refused api\.not-confined: .*write beside the state dir: written/)
  assert.equal(r.out, '')
  assert.ok(!IPV4.test(r.err))
  assert.equal(existsSync(join(state, 'api.lock')), false)
})

test('under the API profile: the ready line, a guarded /status, and SIGTERM frees the lock', async (t) => {
  const { home, state } = setup(t)
  const child = spawn('/usr/bin/sandbox-exec', ['-p', apiProfile(state), process.execPath, ...argv(home)], { env: env(home), stdio: ['ignore', 'pipe', 'pipe'] })
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL') }) // by recorded pid
  let out = ''
  let err = ''
  child.stderr.setEncoding('utf8').on('data', (c: string) => { err += c })
  const ready = await new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`no ready line; stderr: ${err.slice(0, 300)}`)), 30_000)
    child.stdout.setEncoding('utf8').on('data', (c: string) => {
      out += c
      const m = /^vt-api ready network=local port=(\d+) build=confinetest\n/.exec(out)
      if (m !== null) { clearTimeout(timer); resolve(m[1]) }
    })
    child.on('exit', (code) => { clearTimeout(timer); reject(new Error(`exited ${code}; stderr: ${err.slice(0, 300)}`)) })
  })
  const port = Number(ready)
  assert.ok(port > 0 && (port < 5174 || port > 5202))
  assert.equal(existsSync(join(state, 'api.lock')), true)
  const ok = await call(port, { path: '/status' })
  assert.equal(ok.status, 200)
  assert.deepEqual([(ok.json as { confined: boolean }).confined, (ok.json as { build: string }).build], [true, 'confinetest'])
  assert.equal((await call(port, { path: '/status', headers: { authorization: `Bearer ${TOKEN.replace('0', '1')}` } })).status, 401)
  assert.equal((await call(port, { path: `/status?${CANARY}`, headers: { host: `${CANARY}:5182` } })).status, 403)
  const exited = new Promise<number | null>((resolve) => child.on('exit', (code) => resolve(code)))
  child.kill('SIGTERM')
  assert.equal(await exited, 0)
  assert.equal(existsSync(join(state, 'api.lock')), false)
  assert.equal(err, '')
  assert.ok(!out.includes(CANARY) && !IPV4.test(out), 'the API printed an address')
  assert.match(out, /^vt-api ready network=local port=\d+ build=confinetest\napi GET status 200 \d+ms\napi GET unmatched 401 \d+ms guard=api\.token\napi GET unmatched 403 \d+ms guard=api\.host\n$/)
})

test('under the API profile, a missing token file still refuses first (api.token-missing, exit 2)', (t) => {
  const { dir, cleanup } = tempDir('vt-api-confine-')
  t.after(cleanup)
  const home = join(dir, 'home')
  const state = makeHome(home, 'local', { token: 'not-hex' })
  const r = runToExit('/usr/bin/sandbox-exec', ['-p', apiProfile(state), process.execPath, ...argv(home)], env(home))
  assert.equal(r.code, 2)
  assert.match(r.err, /^refused api\.token-missing: /)
  assert.ok(!r.err.includes(home))
})

// cli/test/down.test.ts — `vt down` (src/ops/down.ts; plan Task C3), through bin/vt with the fake tmux
// (test/fakes/tmux.sh) first on PATH: never a real tmux server.
import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { PATH0, fakeTmux, removeDir, run, tempDir } from './lib.ts'
import type { FakeTmux, Run } from './lib.ts'

let T = ''
let HOME0 = ''
let F: FakeTmux
const VTH = () => join(T, 'vt-home')
const vt = (args: string[]): Run => run(args, { env: { PATH: `${F.bin}:${PATH0}`, HOME: HOME0, VT_HOME: VTH(), VAULT_TIMELOCK_DIR: join(T, 'out') } })
const upJson = (n = 'local') => join(VTH(), n, 'up.json')

before(() => {
  T = tempDir('vt-down-')
  HOME0 = join(T, 'home')
  mkdirSync(HOME0, { mode: 0o700 })
  F = fakeTmux(T)
})
after(() => removeDir(T))
beforeEach(() => {
  F.reset()
  removeDir(VTH())
})

test('vt up, then vt down: kill-session of exactly =vt-local, up.json removed; the tokens and the logs stay', () => {
  assert.equal(vt(['up']).code, 0)
  assert.ok(existsSync(upJson()))
  const token = readFileSync(join(VTH(), 'local', 'api.token'), 'utf8')
  F.reset()
  writeFileSync(join(F.state, 'mode-relay'), 'ready')
  mkdirSync(join(F.state, 'sessions'))
  writeFileSync(join(F.state, 'sessions', 'vt-local'), '')
  const r = vt(['down'])
  assert.equal(r.code, 0, r.err)
  assert.equal(r.out, 'vt down: stopped vt-local\n')
  assert.equal(r.err, '')
  assert.deepEqual(F.calls(), [['has-session', '-t', '=vt-local'], ['kill-session', '-t', '=vt-local']])
  assert.ok(!existsSync(upJson()))
  assert.equal(readFileSync(join(VTH(), 'local', 'api.token'), 'utf8'), token)
  assert.ok(existsSync(join(VTH(), 'local', 'logs', 'api.log')))
})

test('--network selects the session; only that one is killed, and only its up.json goes', () => {
  for (const n of ['local', 'testnet', 'mainnet']) {
    mkdirSync(join(VTH(), n), { recursive: true, mode: 0o700 })
    writeFileSync(upJson(n), '{}')
  }
  mkdirSync(join(F.state, 'sessions'))
  for (const n of ['local', 'testnet']) writeFileSync(join(F.state, 'sessions', `vt-${n}`), '')
  const r = vt(['down', '--network', 'testnet'])
  assert.equal(r.code, 0, r.err)
  assert.deepEqual(F.calls(), [['has-session', '-t', '=vt-testnet'], ['kill-session', '-t', '=vt-testnet']])
  assert.ok(!existsSync(upJson('testnet')))
  assert.ok(existsSync(upJson('local')) && existsSync(upJson('mainnet')))
  assert.ok(existsSync(join(F.state, 'sessions', 'vt-local')), 'vt-local still runs')
})

test('a stack that is not running: nothing is killed, a stale up.json is removed, exit 0', () => {
  mkdirSync(join(VTH(), 'local'), { recursive: true, mode: 0o700 })
  writeFileSync(upJson(), '{"network":"local","pagePort":5180,"build":"dev","startedAt":1}\n')
  const r = vt(['down'])
  assert.equal(r.code, 0, r.err)
  assert.equal(r.out, 'vt down: vt-local was not running\n')
  assert.deepEqual(F.calls(), [['has-session', '-t', '=vt-local']])
  assert.ok(!existsSync(upJson()))
  // And with no state at all.
  removeDir(VTH())
  assert.equal(vt(['down']).code, 0)
})

test('tmux cannot kill the session: exit 1, and up.json is kept (the stack may still run)', () => {
  mkdirSync(join(VTH(), 'local'), { recursive: true, mode: 0o700 })
  writeFileSync(upJson(), '{}')
  mkdirSync(join(F.state, 'sessions'))
  writeFileSync(join(F.state, 'sessions', 'vt-local'), '')
  F.fail('kill-session')
  const r = vt(['down'])
  assert.equal(r.code, 1)
  assert.equal(r.err, 'vt down: tmux could not stop vt-local; up.json was kept\n')
  assert.ok(existsSync(upJson()))
})

test('arguments: none (the network comes from --network); anything else is a usage error and kills nothing', () => {
  for (const args of [['now'], ['--all'], ['-f']]) {
    const r = vt(['down', ...args])
    assert.equal(r.code, 1)
    assert.equal(r.err, 'vt: usage: vt down [--network local|testnet|mainnet]\n')
  }
  assert.deepEqual(F.calls(), [])
})

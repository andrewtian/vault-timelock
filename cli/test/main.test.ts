// cli/test/main.test.ts — the dispatcher's own walls (src/main.ts, src/ops/confine.ts; plan Task C1), run as
// `node src/main.ts …` WITHOUT bin/vt and without a vt sandbox:
//   · every command args.ts sandboxes, and any command under a VT_CONFINED=1 hint, must PROVE confinement first
//     (vt.not-confined). Here it cannot: unsandboxed, or inside the suite sandbox (scripts/test-root.sh phase A, the
//     mutation runner), loopback port 9 is not denied, so the proof stops there and no TEST-NET-1 packet is sent;
//   · every command but help needs explicit dirs in a dev tree (vt.dev-dirs-required);
//   · an API-key-like variable is refused before anything (config.env-key, vt-broadcast's assertNoKeyEnv).
// The real sandbox side (the proof passes under the profiles) is test/confine.test.ts and test/wrapper.test.ts.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { assertConfined } from '../src/ops/confine.ts'
import { helpText } from '../src/help.ts'
import { IPV4, PATH0, refused, rejectsWith, removeDir, runMain, sealerFreeCopy, tempDir, writeExe } from './lib.ts'
import type { Run, SealerFreeCopy } from './lib.ts'

const SYNTH = 'SYNTH-NOT-A-VAULT'
let T = ''
let C: SealerFreeCopy
let ENV: Record<string, string> = {}
// main.ts of a sealer-free copy (lib.ts sealerFreeCopy): no real sealer is reachable from this file, whatever regresses.
const main = (args: string[], env: Record<string, string>): Run => runMain(args, { file: C.main, env })
const OP_MARKER = () => join(T, 'op-was-called')
before(() => {
  T = tempDir('vt-main-')
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

test('assertConfined outside the vt sandbox -> vt.not-confined (loopback port 9 is not denied here); the message names no address', async () => {
  await rejectsWith(() => assertConfined(), 'vt.not-confined')
  await assert.rejects(assertConfined({ timeoutMs: 500 }), (e: Error) => {
    assert.ok(!IPV4.test(e.message), 'no address in the refusal')
    assert.match(e.message, /TEST-NET-1: not tried/, 'stopped at the loopback probe: nothing left the machine')
    return true
  })
})

test('a client or executor command started without the vt sandbox -> vt.not-confined, before anything else', () => {
  for (const args of [['status'], ['preflight'], ['job'], ['job', 'list'], ['job', 'create', 'f.json'], ['job', 'run', 'x'], ['job', 'clawback', 'x']]) {
    const r = main(args, ENV)
    refused(r, 'vt.not-confined')
    assert.ok(!r.err.includes('not available'), 'the command did not run')
  }
})

test('VT_CONFINED=1 set by hand (no sandbox) -> vt.not-confined for every command, help and seal included', () => {
  for (const args of [['help'], ['seal', 'vault', SYNTH, '30d'], ['note', 'validate'], ['status']]) {
    const r = main(args, { ...ENV, VT_CONFINED: '1' })
    refused(r, 'vt.not-confined')
    assert.ok(!r.err.includes('sealer-stub'), 'the stub did not run')
  }
})

test('help needs no directories and no sandbox', () => {
  for (const args of [[], ['help'], ['--help'], ['-h']]) {
    const r = main(args, { PATH: PATH0, HOME: join(T, 'home') })
    assert.equal(r.code, 0, r.err)
    assert.equal(r.out, helpText())
    assert.equal(r.err, '')
  }
})

test('vt.dev-dirs-required: from this dev tree, every other command needs VT_HOME and VAULT_TIMELOCK_DIR', () => {
  const { VT_HOME: _h, VAULT_TIMELOCK_DIR: _o, ...bare } = ENV
  for (const env of [bare, { ...bare, VT_HOME: ENV.VT_HOME }, { ...bare, VAULT_TIMELOCK_DIR: ENV.VAULT_TIMELOCK_DIR }, { ...ENV, VT_HOME: '' }]) {
    for (const args of [['seal', 'vault', SYNTH, '30d'], ['open', 'file', 'pkg'], ['note', 'validate'], ['triggers', 'list'], ['up']]) {
      const r = main(args, env)
      refused(r, 'vt.dev-dirs-required')
      assert.ok(!r.err.includes('sealer-stub') && !r.err.includes('vt: running'), 'nothing was started')
    }
  }
})

test('an API-key-like variable is refused before anything runs (config.env-key)', () => {
  for (const name of ['ALCHEMY_API_KEY', 'INFURA_PROJECT', 'MY_SECRET', 'ETH_RPC_URL']) {
    const r = main(['seal', 'vault', SYNTH, '30d'], { ...ENV, [name]: 'synthetic-value' })
    refused(r, 'config.env-key')
    assert.ok(!r.err.includes('synthetic-value'), 'the value is not echoed')
  }
})

test('an unknown command -> exit 1 with a hint; the word is not echoed', () => {
  const r = main(['https://rpc.example/?key=synthetic-secret'], ENV)
  assert.equal(r.code, 1)
  assert.equal(r.err, 'vt: unknown command (run vt help for the list)\n')
})

test('vt release (C4) is dispatched: without a subcommand, a usage error (exit 1)', () => {
  const r = main(['release'], ENV)
  assert.equal(r.code, 1)
  assert.equal(r.err, 'vt: usage: vt release build | verify [<id>] | list\n')
})

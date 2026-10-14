// cli/test/ports-seam.test.ts — main()'s test-only ports seam (M1 glue: the E4 integration harness runs the real
// `vt job run` / `vt job clawback` against a local stack on ephemeral ports through test/fixtures/vt-entry.ts).
//   · refused (vt.test-only) unless NODE_ENV=test, a development tree and the local network — by main() itself, before
//     anything else runs (no confinement proof, no request), and by the fixture first;
//   · with the seam allowed, main()'s own walls still run (here, outside the vt sandbox: vt.not-confined);
//   · never in a release: the fixture is outside what a release copies, and src/main.ts holds no test override string;
//   · bin/vt never passes NODE_ENV or VT_TEST_PORTS (test/args.test.ts, env -i).
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { assertTestSeam, main } from '../src/main.ts'
import { COPY, isReleaseSource } from '../src/ops/release.ts'
import { CLI, PATH0, refused, rejectsWith, removeDir, runMain as runNode, tempDir, throwsWith } from './lib.ts'

const ENTRY = join(CLI, 'test', 'fixtures', 'vt-entry.ts')
const PORTS = { page: 1, relay: 2, api: 3 }
let T = ''
let ENV: Record<string, string> = {}
before(() => {
  T = tempDir('vt-seam-')
  mkdirSync(join(T, 'home'))
  ENV = { PATH: PATH0, HOME: join(T, 'home'), VT_HOME: join(T, 'vt-home'), VAULT_TIMELOCK_DIR: join(T, 'out') }
})
after(() => removeDir(T))

test('assertTestSeam: only NODE_ENV=test, a development tree and the local network', () => {
  for (const nodeEnv of [undefined, '', 'production', 'TEST', 'test ']) throwsWith(() => assertTestSeam({ nodeEnv, release: null, network: 'local' }), 'vt.test-only')
  throwsWith(() => assertTestSeam({ nodeEnv: 'test', release: '0123456789ab', network: 'local' }), 'vt.test-only')
  for (const network of ['testnet', 'mainnet', 'devnet']) throwsWith(() => assertTestSeam({ nodeEnv: 'test', release: null, network }), 'vt.test-only')
  for (const network of [undefined, '', 'local']) assertTestSeam({ nodeEnv: 'test', release: null, network })
})

test('main() with the seam outside NODE_ENV=test: vt.test-only before anything (no confinement proof, nothing run)', async () => {
  const saved = process.env.NODE_ENV
  try {
    delete process.env.NODE_ENV
    for (const argv of [['job', 'run', 'x'], ['job', 'list'], ['help'], ['status']]) await rejectsWith(() => main(argv, ENV, { ports: PORTS }), 'vt.test-only')
    process.env.NODE_ENV = 'production'
    await rejectsWith(() => main(['job', 'list'], ENV, { ports: PORTS }), 'vt.test-only')
    // NODE_ENV=test, but on testnet or mainnet: refused too
    process.env.NODE_ENV = 'test'
    for (const n of ['testnet', 'mainnet']) await rejectsWith(() => main(['job', 'list'], { ...ENV, VT_NETWORK: n }, { ports: PORTS }), 'vt.test-only')
    // allowed: main()'s own walls still run first (outside the vt sandbox, the confinement proof refuses)
    await rejectsWith(() => main(['job', 'list'], ENV, { ports: PORTS }), 'vt.not-confined')
  } finally {
    if (saved === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = saved
  }
})

test('the fixture: refused without NODE_ENV=test (exit 2, nothing run); with it, main() decides (network, confinement)', () => {
  refused(runNode(['job', 'list'], { file: ENTRY, env: { ...ENV, VT_TEST_PORTS: 'api=3,relay=2' } }), 'vt.test-only')
  refused(runNode(['job', 'list'], { file: ENTRY, env: { ...ENV, NODE_ENV: 'production', VT_TEST_PORTS: 'api=3,relay=2' } }), 'vt.test-only')
  refused(runNode(['job', 'list'], { file: ENTRY, env: { ...ENV, NODE_ENV: 'test', VT_NETWORK: 'mainnet', VT_TEST_PORTS: 'api=3,relay=2' } }), 'vt.test-only')
  refused(runNode(['job', 'list'], { file: ENTRY, env: { ...ENV, NODE_ENV: 'test', VT_TEST_PORTS: 'api=3,relay=2' } }), 'vt.not-confined')
  for (const bad of ['', 'api=3', 'relay=2,api=3', 'api=0,relay=2', 'api=65536,relay=2', 'api=3,relay=2,page=x']) {
    const r = runNode(['job', 'list'], { file: ENTRY, env: { ...ENV, NODE_ENV: 'test', VT_TEST_PORTS: bad } })
    assert.equal(r.code, 1, `${bad}: ${r.err}`)
    assert.match(r.err, /VT_TEST_PORTS must be/)
  }
})

test('never in a release: the fixture is outside what a release copies; src/main.ts holds no test override string', () => {
  assert.equal(isReleaseSource('cli/test/fixtures/vt-entry.ts'), false)
  assert.ok(COPY.includes('cli/src/') && !COPY.some((p) => p.startsWith('cli/test')))
  // release.ts refuses a shipped file holding the test override prefix (outside the relay's block): main.ts has none
  assert.ok(!readFileSync(join(CLI, 'src', 'main.ts'), 'utf8').includes(['VT_', 'TEST_'].join('')))
})

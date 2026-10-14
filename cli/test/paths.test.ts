// cli/test/paths.test.ts — VT_HOME, state dirs, release-tree detection and the dev-tree rule (src/ops/paths.ts,
// plan Task C1). Every directory is a fresh temp dir; nothing reads or writes the operator's real state.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Network } from '@vault-timelock/core/contracts'
import { assertDevDirs, isReleaseTree, releaseId, stateDir, vtHome } from '../src/ops/paths.ts'
import { removeDir, tempDir, throwsWith } from './lib.ts'

let T = ''
before(() => { T = tempDir('vt-paths-') })
after(() => removeDir(T))

test('vtHome: VT_HOME when set, else ~/.local/state/vt; an empty VT_HOME counts as unset', () => {
  assert.equal(vtHome({ VT_HOME: '/tmp/vt-a', HOME: '/Users/x' }), '/tmp/vt-a')
  assert.equal(vtHome({ HOME: '/Users/x' }), '/Users/x/.local/state/vt')
  assert.equal(vtHome({ VT_HOME: '', HOME: '/Users/x' }), '/Users/x/.local/state/vt')
  assert.equal(vtHome({ HOME: '/Users/x/' }), '/Users/x/.local/state/vt')
})

test('vtHome: a relative, odd or missing home is refused (vt.path): it ends up in sandbox profiles', () => {
  for (const env of [{ VT_HOME: 'rel/home', HOME: '/Users/x' }, { VT_HOME: '/tmp/a"b' }, { VT_HOME: '/tmp/x/' }, { VT_HOME: '/tmp/../x' }, {}, { HOME: 'rel' }, { HOME: '/Users/a)b' }]) {
    throwsWith(() => vtHome(env), 'vt.path')
  }
})

test('stateDir: $VT_HOME/<network>, for the three networks only', () => {
  for (const n of ['local', 'testnet', 'mainnet'] as const) assert.equal(stateDir('/tmp/vt-a', n), `/tmp/vt-a/${n}`)
  throwsWith(() => stateDir('/tmp/vt-a', 'devnet' as Network), 'contract.network')
  throwsWith(() => stateDir('/tmp/a"b', 'local'), 'vt.path')
})

test('isReleaseTree: only a file below $home/releases/<12 hex>/ (compared as real paths)', () => {
  const home = join(T, 'home')
  mkdirSync(join(home, 'releases', '0123456789ab', 'cli', 'src'), { recursive: true })
  const main = join(home, 'releases', '0123456789ab', 'cli', 'src', 'main.ts')
  writeFileSync(main, '')
  assert.equal(isReleaseTree(main, home), true)
  // Through a symlinked home, the real script path still matches.
  symlinkSync(home, join(T, 'home-link'))
  assert.equal(isReleaseTree(main, join(T, 'home-link')), true)
  for (const p of [
    join(home, 'releases', '0123456789ab'), // the release dir itself is not a file of the tree
    join(home, 'releases', '0123456789AB', 'cli', 'src', 'main.ts'),
    join(home, 'releases', '0123456789abc', 'cli', 'src', 'main.ts'),
    join(home, 'releases', 'not-a-build', 'cli', 'src', 'main.ts'),
    join(home, 'local', 'cli', 'src', 'main.ts'),
    join(T, 'elsewhere', 'releases', '0123456789ab', 'cli', 'src', 'main.ts'),
    '/Users/x/src/vault-timelock/cli/src/main.ts',
  ]) assert.equal(isReleaseTree(p, home), false, p)
  assert.equal(isReleaseTree(main, join(T, 'no-such-home')), false)
  // releaseId (C3: the build id vt up passes the API and writes into up.json): the <12 hex> directory, else null.
  assert.equal(releaseId(main, home), '0123456789ab')
  assert.equal(releaseId(main, join(T, 'home-link')), '0123456789ab')
  assert.equal(releaseId(join(home, 'releases', 'not-a-build', 'cli', 'src', 'main.ts'), home), null)
  assert.equal(releaseId('/Users/x/src/vault-timelock/cli/src/main.ts', home), null)
})

test('vt.dev-dirs-required: a dev tree without VT_HOME or VAULT_TIMELOCK_DIR (both explicit and absolute) is refused', () => {
  const both = { VT_HOME: '/tmp/vt-h', VAULT_TIMELOCK_DIR: '/tmp/vt-o', HOME: '/Users/x' }
  assertDevDirs(both, false)
  for (const env of [
    {}, { HOME: '/Users/x' },
    { VT_HOME: '/tmp/vt-h' }, { VAULT_TIMELOCK_DIR: '/tmp/vt-o' },
    { VT_HOME: '', VAULT_TIMELOCK_DIR: '/tmp/vt-o' }, { VT_HOME: '/tmp/vt-h', VAULT_TIMELOCK_DIR: '' },
    { VT_HOME: 'vt-h', VAULT_TIMELOCK_DIR: '/tmp/vt-o' }, { VT_HOME: '/tmp/vt-h', VAULT_TIMELOCK_DIR: 'out' },
  ]) throwsWith(() => assertDevDirs(env, false), 'vt.dev-dirs-required')
  // Only a literal true is a release tree.
  throwsWith(() => assertDevDirs({}, 1 as unknown as boolean), 'vt.dev-dirs-required')
})

test('a release tree with neither VT_HOME nor VAULT_TIMELOCK_DIR: the defaults', () => {
  const home = join(T, 'op')
  const vth = join(home, '.local', 'state', 'vt')
  mkdirSync(join(vth, 'releases', 'abcdef012345', 'cli', 'src'), { recursive: true })
  const env = { HOME: home }
  assert.equal(vtHome(env), vth)
  const inRelease = isReleaseTree(join(vth, 'releases', 'abcdef012345', 'cli', 'src', 'main.ts'), vtHome(env))
  assert.equal(inRelease, true)
  assertDevDirs(env, inRelease)
  // The same env from a dev tree is refused.
  throwsWith(() => assertDevDirs(env, isReleaseTree(join(T, 'dev', 'cli', 'src', 'main.ts'), vtHome(env))), 'vt.dev-dirs-required')
})

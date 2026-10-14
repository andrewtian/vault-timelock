import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, rmSync, statSync, chmodSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { Refusal } from '../../../src/guard.ts'
import { resolveOut, lifecycleDir, keystoreDir, broadcastDir, checkPrivateDir, ensureDir } from '../../../src/lifecycle/paths.ts'
import { refused } from './helpers.ts'

test('resolveOut: VAULT_TIMELOCK_DIR, then XDG_DATA_HOME, then ~/.local/share (empty counts as unset)', () => {
  assert.equal(resolveOut({ VAULT_TIMELOCK_DIR: '/a/b', XDG_DATA_HOME: '/x', HOME: '/h' }), '/a/b')
  assert.equal(resolveOut({ XDG_DATA_HOME: '/x', HOME: '/h' }), '/x/vault-timelock')
  assert.equal(resolveOut({ VAULT_TIMELOCK_DIR: '', XDG_DATA_HOME: '/x', HOME: '/h' }), '/x/vault-timelock')
  assert.equal(resolveOut({ HOME: '/h' }), '/h/.local/share/vault-timelock')
  assert.equal(resolveOut({ XDG_DATA_HOME: '', HOME: '/h' }), '/h/.local/share/vault-timelock')
})

test('lifecycleDir, keystoreDir, broadcastDir', () => {
  assert.equal(lifecycleDir('/o'), '/o/lifecycle')
  assert.equal(keystoreDir('/o'), '/o/keystore')
  const ar = 'A'.repeat(43)
  assert.equal(broadcastDir('/o', ar), `/o/broadcast/${ar}`)
  for (const bad of ['', 'A'.repeat(42), 'A'.repeat(44), '../' + 'A'.repeat(40), 'A'.repeat(42) + '/', 'A'.repeat(42) + '+']) {
    refused(() => broadcastDir('/o', bad), 'paths.ar-id')
  }
})

test('ensureDir: creates 0700 (parents too); an existing looser directory is refused, never chmodded', () => {
  const root = mkdtempSync(join(tmpdir(), 'vt-paths-'))
  try {
    const d = join(root, 'a', 'b')
    ensureDir(d)
    assert.equal(statSync(d).mode & 0o777, 0o700)
    assert.equal(statSync(join(root, 'a')).mode & 0o777, 0o700)
    ensureDir(d) // idempotent
    for (const mode of [0o755, 0o750, 0o701, 0o770]) {
      chmodSync(d, mode)
      refused(() => ensureDir(d), 'store.perms')
      assert.equal(statSync(d).mode & 0o777, mode, 'mode untouched')
    }
    const link = join(root, 'link')
    symlinkSync(d, link)
    chmodSync(d, 0o700)
    refused(() => ensureDir(link), 'store.perms') // a symlink is not a private directory
    mkdirSync(join(root, 'file-parent'))
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('store.perms names the directory relative to $OUT, never $OUT\'s basename (the user name when VAULT_TIMELOCK_DIR=$HOME; T1 review m8)', () => {
  const root = mkdtempSync(join(tmpdir(), 'vt-paths-'))
  try {
    const USER = 'synthetic-user-name'
    const out = join(root, USER)
    const msgs: string[] = []
    const msgOf = (f: () => unknown): string => {
      try { f() } catch (e) {
        if (!(e instanceof Refusal && e.guardId === 'store.perms')) throw e
        msgs.push(e.message)
        return e.message
      }
      return assert.fail('expected store.perms')
    }
    mkdirSync(out, { mode: 0o700 })
    chmodSync(out, 0o755)
    assert.ok(msgOf(() => checkPrivateDir(out, out)).startsWith('$OUT must be a real directory with mode 0700'))
    chmodSync(out, 0o700)
    for (const sub of ['lifecycle', 'lifecycle/trigger', 'keystore', 'triggers']) {
      const d = join(out, sub)
      ensureDir(d, out)
      chmodSync(d, 0o750)
      assert.ok(msgOf(() => ensureDir(d, out)).startsWith(`${sub} must be`), sub)
      assert.ok(msgOf(() => checkPrivateDir(d, out)).startsWith(`${sub} must be`), sub)
      assert.ok(msgOf(() => ensureDir(d)).startsWith(`${basename(sub)} must be`), sub) // no out: the last component only
      chmodSync(d, 0o700)
    }
    for (const m of msgs) assert.ok(!m.includes(USER) && !m.includes(root), m)
  } finally { rmSync(root, { recursive: true, force: true }) }
})

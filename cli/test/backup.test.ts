// cli/test/backup.test.ts — `vt backup import` (src/ops/backup.ts; plan Task C3; E2E loop finding L2-3), through bin/vt
// (an unsandboxed command) and in-process. Synthetic age-shaped files only (lib.ts synthAge): never a real backup,
// never decrypted.
import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { AGE_HEADER, BACKUP_CAP, backupName, importBackup, parseBackupArgs } from '../src/ops/backup.ts'
import { CANARY, PATH0, refused, removeDir, run, synthAge, tempDir, throwsWith } from './lib.ts'
import type { Run } from './lib.ts'

let T = ''
const VTH = () => join(T, 'vt-home')
const DL = () => join(T, 'Downloads')
const mode = (p: string) => statSync(p).mode & 0o777
const vt = (args: string[], cwd = DL()): Run => run(args, { cwd, env: { PATH: PATH0, HOME: join(T, 'home'), VT_HOME: VTH(), VAULT_TIMELOCK_DIR: join(T, 'out') } })

before(() => { T = tempDir('vt-backup-') })
after(() => removeDir(T))
beforeEach(() => {
  removeDir(VTH())
  removeDir(DL())
  mkdirSync(DL(), { recursive: true })
})

test('an age file: moved into $VT_HOME/backups/ (dir 0700, file 0600), bytes unchanged, the download removed, contents never shown', () => {
  const bytes = synthAge(`marker-${CANARY}`)
  writeFileSync(join(DL(), 'vt-eth-key-0x1234.age'), bytes, { mode: 0o644 })
  const r = vt(['backup', 'import', 'vt-eth-key-0x1234.age'])
  assert.equal(r.code, 0, r.err)
  assert.equal(r.out, 'vt backup import: saved $VT_HOME/backups/vt-eth-key-0x1234.age (mode 0600; not decrypted). The downloaded file was removed.\n')
  assert.equal(r.err, '')
  assert.ok(!r.out.includes('age-encryption') && !r.out.includes(CANARY) && !r.out.includes('marker'), 'no contents printed')
  const dest = join(VTH(), 'backups', 'vt-eth-key-0x1234.age')
  assert.deepEqual(readFileSync(dest), bytes)
  assert.equal(mode(dest), 0o600)
  assert.equal(mode(join(VTH(), 'backups')), 0o700)
  assert.ok(!existsSync(join(DL(), 'vt-eth-key-0x1234.age')), 'moved, not copied')
  assert.deepEqual(readdirSync(join(VTH(), 'backups')), ['vt-eth-key-0x1234.age'], 'no temp file left')
})

test('--chain eth|sol|btc: into backups/<chain>/ (0700); an absolute path works from anywhere', () => {
  writeFileSync(join(DL(), 'k.age'), synthAge())
  const r = vt(['backup', 'import', join(DL(), 'k.age'), '--chain', 'sol'], T)
  assert.equal(r.code, 0, r.err)
  assert.equal(mode(join(VTH(), 'backups', 'sol')), 0o700)
  assert.equal(mode(join(VTH(), 'backups', 'sol', 'k.age')), 0o600)
  writeFileSync(join(DL(), 'b.age'), synthAge())
  const b = vt(['backup', 'import', join(DL(), 'b.age'), '--chain', 'btc'], T)
  assert.equal(b.code, 0, b.err)
  assert.equal(mode(join(VTH(), 'backups', 'btc')), 0o700)
  assert.equal(mode(join(VTH(), 'backups', 'btc', 'b.age')), 0o600)
})

test('vt.backup-format: not an age file, an empty one, a symlink to one, a directory, a FIFO or more than 1 MiB is refused; nothing moves', () => {
  writeFileSync(join(DL(), 'plain.txt'), `just text ${CANARY}\n`)
  writeFileSync(join(DL(), 'empty.age'), '')
  writeFileSync(join(DL(), 'header-only.age'), AGE_HEADER)
  writeFileSync(join(DL(), 'armored.age'), '-----BEGIN AGE ENCRYPTED FILE-----\nYWdl\n-----END AGE ENCRYPTED FILE-----\n')
  writeFileSync(join(DL(), 'almost.age'), Buffer.concat([Buffer.from('age-encryption.org/v2\n'), Buffer.from('x')]))
  writeFileSync(join(T, 'real.age'), synthAge())
  symlinkSync(join(T, 'real.age'), join(DL(), 'link.age'))
  mkdirSync(join(DL(), 'dir.age'))
  assert.equal(spawnSync('/usr/bin/mkfifo', [join(DL(), 'fifo.age')]).status, 0)
  writeFileSync(join(DL(), 'huge.age'), Buffer.concat([synthAge(), Buffer.alloc(BACKUP_CAP)]))
  for (const f of ['plain.txt', 'empty.age', 'header-only.age', 'armored.age', 'almost.age', 'link.age', 'dir.age', 'fifo.age', 'huge.age']) {
    const r = vt(['backup', 'import', f])
    refused(r, 'vt.backup-format')
    assert.ok(!r.err.includes(CANARY) && !r.err.includes('just text'), 'contents not shown')
    assert.ok(existsSync(join(DL(), f)), `${f} stays where it was`)
  }
  assert.ok(existsSync(join(T, 'real.age')), 'the link target is untouched')
  assert.ok(!existsSync(join(VTH(), 'backups')), 'nothing was written')
})

test('in-process: the same refusal by id (the mapped guard)', () => {
  writeFileSync(join(DL(), 'plain.txt'), 'not age\n')
  throwsWith(() => importBackup({ file: 'plain.txt', chain: null, env: { VT_HOME: VTH() }, cwd: DL() }), 'vt.backup-format')
  writeFileSync(join(T, 'real2.age'), synthAge())
  symlinkSync(join(T, 'real2.age'), join(DL(), 'link2.age'))
  throwsWith(() => importBackup({ file: 'link2.age', chain: null, env: { VT_HOME: VTH() }, cwd: DL() }), 'vt.backup-format')
  const lines: string[] = []
  writeFileSync(join(DL(), 'ok.age'), synthAge())
  assert.equal(importBackup({ file: 'ok.age', chain: 'eth', env: { VT_HOME: VTH() }, cwd: DL() }, { out: (l) => lines.push(l) }), 0)
  assert.equal(lines.length, 1)
})

test('an existing backup of that name is never overwritten: exit 1, nothing changed', () => {
  writeFileSync(join(DL(), 'k.age'), synthAge('first'))
  assert.equal(vt(['backup', 'import', 'k.age']).code, 0)
  writeFileSync(join(DL(), 'k.age'), synthAge('second'))
  const r = vt(['backup', 'import', 'k.age'])
  assert.equal(r.code, 1)
  assert.equal(r.err, 'vt: backup import: $VT_HOME/backups/k.age already exists; nothing was changed (rename the file to import it)\n')
  assert.deepEqual(readFileSync(join(VTH(), 'backups', 'k.age')), synthAge('first'))
  assert.ok(existsSync(join(DL(), 'k.age')))
})

test('names: reduced to [A-Za-z0-9._-], no leading dot or dash, ending .age; a missing file and bad arguments are usage errors', () => {
  assert.equal(backupName('/x/vt-eth-key (1).age'), 'vt-eth-key--1-.age')
  assert.equal(backupName('.hidden'), 'hidden.age')
  assert.equal(backupName('-x.age'), 'x.age')
  assert.equal(backupName('ключ'), 'backup.age')
  assert.equal(backupName('...'), 'backup.age')
  assert.equal(backupName(`a${'b'.repeat(200)}.age`).length, 124)
  assert.deepEqual(parseBackupArgs(['import', 'f.age']), { file: 'f.age', chain: null })
  assert.deepEqual(parseBackupArgs(['import', 'f.age', '--chain', 'eth']), { file: 'f.age', chain: 'eth' })
  assert.deepEqual(parseBackupArgs(['import', 'f.age', '--chain', 'btc']), { file: 'f.age', chain: 'btc' })
  for (const args of [[], ['export', 'f'], ['import'], ['import', '--chain', 'eth'], ['import', 'f', '--chain'], ['import', 'f', '--chain', 'doge'], ['import', 'f', 'g']]) {
    const r = vt(['backup', ...args])
    assert.equal(r.code, 1, args.join(' '))
    assert.equal(r.err, 'vt: usage: vt backup import <file> [--chain eth|sol|btc]\n')
  }
  const r = vt(['backup', 'import', 'no-such.age'])
  assert.equal(r.code, 1)
  assert.equal(r.err, 'vt: backup import: no such file\n')
})

// cli/src/ops/backup.ts — `vt backup import <file> [--chain eth|sol|btc]` (canonical vt spec §8; plan Task C3; E2E loop
// finding L2-3). Orchestration (unsandboxed). Moves a key backup the page downloaded (e.g. into ~/Downloads) into
// $VT_HOME/backups/ (or backups/<chain>/ with --chain), directory 0700, file 0600.
// ★ It never decrypts and never prints the contents. It accepts only a regular file (never a symlink, a FIFO or a
//   device: lstat, then open with O_NOFOLLOW|O_NONBLOCK and the same inode on fstat), at most 1 MiB, that starts with
//   the age header `age-encryption.org/v1` (vt.backup-format).
// ★ The bytes it checked are the bytes it writes: the new file is created with O_CREAT|O_EXCL|O_NOFOLLOW at 0600,
//   fsynced (and its directory), never overwriting an existing backup. Only then is the original removed, and only if
//   the path still names the same file (dev + inode); otherwise it is left in place, and the message says so.
import type { Chain } from '@vault-timelock/core/contracts'
import { refuse } from '@vault-timelock/core/contracts'
import { ensureDir } from 'vt-broadcast/src/lifecycle/paths.ts'
import { closeSync, constants, fchmodSync, fstatSync, fsyncSync, lstatSync, openSync, readSync, unlinkSync, writeSync } from 'node:fs'
import { basename, join, resolve } from 'node:path'
import { UsageError } from '../args.ts'
import type { Env } from './paths.ts'
import { vtHome } from './paths.ts'

export const AGE_HEADER = Buffer.from('age-encryption.org/v1\n', 'utf8')
export const BACKUP_CAP = 1024 * 1024
const USAGE = 'usage: vt backup import <file> [--chain eth|sol|btc]'

export function parseBackupArgs(args: readonly string[]): { file: string; chain: Chain | null } {
  const [sub, file, ...rest] = args
  if (sub !== 'import' || file === undefined || file === '' || file.startsWith('-')) throw new UsageError(USAGE)
  if (rest.length === 0) return { file, chain: null }
  const [flag, chain] = rest
  if (rest.length !== 2 || flag !== '--chain' || (chain !== 'eth' && chain !== 'sol' && chain !== 'btc')) throw new UsageError(USAGE)
  return { file, chain }
}

// The name the backup gets: the downloaded file's base name, reduced to [A-Za-z0-9._-] (other characters become -),
// without leading dots or dashes, at most 120 characters, ending in .age.
export function backupName(file: string): string {
  let n = basename(file).replace(/[^A-Za-z0-9._-]/g, '-').replace(/^[.-]+/, '').slice(0, 120)
  if (n === '') n = 'backup'
  return n.endsWith('.age') ? n : `${n}.age`
}

interface Read { bytes: Buffer; dev: number; ino: number }
// The file's bytes, read once, when it is a regular file (not a link) of at most BACKUP_CAP bytes; else null.
function readRegular(path: string): Read | null {
  let fd: number
  try {
    const l = lstatSync(path)
    if (!l.isFile()) return null
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  } catch {
    return null
  }
  try {
    const st = fstatSync(fd)
    if (!st.isFile() || st.size > BACKUP_CAP) return null
    const bytes = Buffer.alloc(st.size)
    let off = 0
    while (off < st.size) {
      const r = readSync(fd, bytes, off, st.size - off, off)
      if (r === 0) break
      off += r
    }
    return { bytes: bytes.subarray(0, off), dev: st.dev, ino: st.ino }
  } catch {
    return null
  } finally {
    closeSync(fd)
  }
}

// The one vt.backup-format marker: a regular file (never a link, FIFO or device), at most BACKUP_CAP bytes, starting
// with the age header. `vt backup import` moves it; `vt job run` / `vt job clawback` (C6) decrypt it in memory.
function checkedBackup(path: string, what: string): Read {
  const got = readRegular(path)
  const ok = got !== null && got.bytes.length > AGE_HEADER.length && got.bytes.subarray(0, AGE_HEADER.length).equals(AGE_HEADER)
  if (!ok) refuse('vt.backup-format', `${what}: a backup must be a regular file (not a symlink, FIFO or device) of at most 1 MiB that starts with the age header age-encryption.org/v1; its contents are not shown`) // @guard:vt.backup-format
  return got!
}

// A key backup's bytes for the executor (C6): read once, checked as above. The caller zeroes them when done.
export function readKeyBackup(path: string): Uint8Array {
  return new Uint8Array(checkedBackup(path, 'not read').bytes)
}

function fsyncDir(dir: string): void {
  const fd = openSync(dir, constants.O_RDONLY)
  try { fsyncSync(fd) } finally { closeSync(fd) }
}

export function importBackup(o: { file: string; chain: Chain | null; env: Env; cwd: string }, deps: { out?: (line: string) => void } = {}): number {
  const out = deps.out ?? ((l: string) => { process.stdout.write(`${l}\n`) })
  const src = resolve(o.cwd, o.file)
  let exists = true
  try { lstatSync(src) } catch { exists = false }
  if (!exists) throw new UsageError('backup import: no such file')

  const got = checkedBackup(src, 'not imported')

  const rel = o.chain === null ? 'backups' : join('backups', o.chain)
  const dir = join(vtHome(o.env), rel)
  ensureDir(dir)
  const name = backupName(src)
  let fd: number
  try {
    fd = openSync(join(dir, name), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'EEXIST') throw new UsageError(`backup import: $VT_HOME/${rel}/${name} already exists; nothing was changed (rename the file to import it)`)
    throw e
  }
  try {
    fchmodSync(fd, 0o600)
    let off = 0
    while (off < got!.bytes.length) off += writeSync(fd, got!.bytes, off, got!.bytes.length - off)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
  fsyncDir(dir)

  let removed = false
  try {
    const l = lstatSync(src)
    if (l.isFile() && l.dev === got!.dev && l.ino === got!.ino) {
      unlinkSync(src)
      removed = true
    }
  } catch { /* gone or unreadable: left as it is */ }
  out(`vt backup import: saved $VT_HOME/${rel}/${name} (mode 0600; not decrypted). ${removed ? 'The downloaded file was removed.' : 'The original was left in place: it changed while it was imported.'}`)
  return 0
}

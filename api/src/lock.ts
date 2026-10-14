// api/src/lock.ts — the single-instance pid lock <VT_HOME>/<network>/api.lock (0600).
//
// Taking it: the pid is written to a private temp file in the same directory, which is then hard-linked to api.lock.
// link() fails if api.lock exists, so the lock appears atomically and always complete (never empty or half-written).
// If api.lock exists:
//   · it names a live process (this one included) → api.already-running;
//   · it names a dead process, or is not a pid at all (a crash left it) → it is stale: it is removed if it still holds
//     what was read, and the link is tried once more.
// Two stale takeovers racing within microseconds could both win; the fixed API port (EADDRINUSE on listen) is the
// second single-instance guarantee behind this lock. A reused pid makes a stale lock look live: refused (fail closed;
// `vt down` or the operator removes the file).
import { closeSync, constants, fstatSync, linkSync, openSync, readFileSync, unlinkSync, writeSync, fsyncSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { refuse } from 'vt-broadcast/src/guard.ts'

export interface ApiLock { readonly file: string; release(): void }

function readLock(file: string): string | null {
  let fd = -1
  try {
    fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW)
    const st = fstatSync(fd)
    if (!st.isFile() || st.size > 64) return null
    return readFileSync(fd, 'utf8')
  } catch {
    return null
  } finally {
    if (fd >= 0) closeSync(fd)
  }
}

function pidOf(text: string | null): number | null {
  return text !== null && /^[1-9][0-9]{0,9}\n$/.test(text) ? Number(text.slice(0, -1)) : null
}

// True when a process with this pid exists (EPERM: it exists but belongs to someone else).
export function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    return (e as NodeJS.ErrnoException).code !== 'ESRCH'
  }
}

function tryLink(tmp: string, file: string): boolean {
  try {
    linkSync(tmp, file)
    return true
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'EEXIST') return false
    throw e
  }
}

export function takeLock(file: string): ApiLock {
  const mine = `${process.pid}\n`
  const tmp = `${file}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  try {
    writeSync(fd, mine)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
  try {
    let held = tryLink(tmp, file)
    if (!held) {
      const text = readLock(file)
      const pid = pidOf(text)
      const stale = pid === null || !pidAlive(pid)
      if (stale) {
        if (readLock(file) === text) unlinkSync(file)
        held = tryLink(tmp, file)
      }
    }
    if (!held) refuse('api.already-running', 'another API instance holds the lock for this network (vt down stops it)') // @guard:api.already-running
  } finally {
    unlinkSync(tmp)
  }
  return {
    file,
    release(): void {
      if (readLock(file) === mine) {
        try { unlinkSync(file) } catch { /* already gone */ }
      }
    },
  }
}

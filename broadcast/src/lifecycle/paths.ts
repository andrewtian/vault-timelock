// $OUT resolution and private directories (spec C 6.2). Same rule as 1password-timelock.sh:
//   OUT=${VAULT_TIMELOCK_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/vault-timelock}
// (an empty variable counts as unset, as with `:-`). Directories we create are 0700; an existing
// directory that is looser, or not a real directory, is refused and never silently chmodded.
import { lstatSync, mkdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { basename, isAbsolute, join, relative } from 'node:path'
import { refuse } from '../guard.ts'
import { AR_ID } from '../envelope.ts'

export function resolveOut(env: Readonly<Record<string, string | undefined>>): string {
  const set = (v: string | undefined): v is string => v !== undefined && v !== ''
  if (set(env.VAULT_TIMELOCK_DIR)) return env.VAULT_TIMELOCK_DIR
  if (set(env.XDG_DATA_HOME)) return join(env.XDG_DATA_HOME, 'vault-timelock')
  return join(set(env.HOME) ? env.HOME : homedir(), '.local', 'share', 'vault-timelock')
}

export const lifecycleDir = (out: string): string => join(out, 'lifecycle')
export const keystoreDir = (out: string): string => join(out, 'keystore')

export function broadcastDir(out: string, arId: string): string {
  const ok = typeof arId === 'string' && AR_ID.test(arId)
  if (!ok) refuse('paths.ar-id', 'ar id must match [A-Za-z0-9_-]{43}') // @guard:paths.ar-id
  return join(out, 'broadcast', arId)
}

function lstatOrUndefined(dir: string) {
  try { return lstatSync(dir) } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw e
  }
}

// The name a refusal prints for `dir` (Task T1, T1 review m8): relative to $OUT when `out` is given (lifecycle/trigger,
// or `$OUT` for $OUT itself); never the absolute path, which holds the macOS user name, and never $OUT's own basename,
// which IS the user name when VAULT_TIMELOCK_DIR=$HOME. Without `out` only the last component is named: every caller
// that omits it checks a fixed name directly under $OUT (keystore, lifecycle, ...), never $OUT itself.
function nameOf(dir: string, out: string | undefined): string {
  const r = out === undefined ? undefined : relative(out, dir)
  if (r === '') return '$OUT'
  if (r !== undefined && r !== '..' && !r.startsWith('../') && !isAbsolute(r)) return r
  return basename(dir)
}

// Refuses unless `dir` is a real directory with no group/other access. Returns false if it does not exist.
export function checkPrivateDir(dir: string, out?: string): boolean {
  const st = lstatOrUndefined(dir)
  if (st === undefined) return false
  const ok = st.isDirectory() && (st.mode & 0o077) === 0
  if (!ok) refuse('store.perms', `${nameOf(dir, out)} must be a real directory with mode 0700 (it is looser, or not a directory)`) // @guard:store.perms
  return true
}

// Creates `dir` (missing parents too, all 0700) or verifies an existing one. Existing ancestors are not inspected.
// `out`: $OUT, so a refusal names `dir` relative to it (see nameOf).
export function ensureDir(dir: string, out?: string): void {
  if (checkPrivateDir(dir, out)) return
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  checkPrivateDir(dir, out) // verify what is there (a concurrent creator, a umask surprise)
}

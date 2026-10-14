// cli/src/job/message-file.ts — which file `vt job create|validate --message-file <path>` may read (security review of
// C5). Whatever file the message comes from is PUBLISHED, permanently and publicly, on chain. So:
//
// ★★ The path comes ONLY from the command line (argv), typed by the operator. A job file never names a file: a job JSON
//    with `messageFile` is refused (vt.message-path), and no other path field exists (normalizeJob refuses unknown
//    members). A job file someone else wrote can therefore never make vt read, let alone publish, a file.
// ★★ The path is resolved and checked before a byte is read, and the bytes are READ ONCE, from one verified descriptor
//    (security review of ce5129d, message-file TOCTOU). Invariant: the bytes that are checked, shown, confirmed
//    (sha256: `publish` / --yes-publish-file) and uploaded are exactly the bytes of the file that passed the denylist,
//    and no path swap between the check and the read can change which file is read. The path is never re-opened.
//    1. the named file itself must not be a symbolic link (lstat; name the file itself) (vt.message-path);
//    2. its real path is resolved ONCE (realpath: every directory link resolved); the denylist below is applied to it,
//       to the path as given, and to each of them with an ALIAS of a denied root rewritten to the root (an ancestor
//       directory with the same dev+ino as a root: e.g. /System/Volumes/Data/Users/<me>/.ssh is ~/.ssh, a firmlink
//       that realpath does not fold) (vt.message-path);
//    3. the real path must be a regular file (no FIFO, device or directory): its lstat (dev, ino) is the checked file;
//    4. THAT real path is opened O_RDONLY | O_NOFOLLOW | O_NONBLOCK (a planted FIFO cannot block); the descriptor must
//       be a regular file with the checked (dev, ino); after the open, the argument's realpath is resolved again and
//       must be the same path, and lstat of that path must still be the descriptor's file. A swap of the file, or of
//       any parent directory for a link, at any moment between the check and the open is refused
//       (vt.message-changed);
//    5. the descriptor's file must have exactly one link (nlink 1): a second hard link could name the same bytes inside
//       a denied directory, and no path check can see it. This is stricter than comparing dev with the denied roots:
//       any second link refuses, on every file system (vt.message-hardlink; cp the file and name the copy);
//    6. at most MESSAGE_MAX bytes by fstat (message.too-long, nothing read), then ONE bounded read loop from the
//       descriptor: it reads until end of file but never more than MESSAGE_MAX + 1 bytes (message.too-long if the file
//       grew past the cap during the read); the count must equal the size at open, and size, mtime and ctime (ns) must
//       be unchanged after the read (vt.message-changed);
//    7. sha256 is computed from THOSE bytes (MessageFile.sha256); validate.ts decodes, checks and hashes the same
//       buffer, and create.ts confirms and uploads it.
// ★★ The denylist (checked on the real path; a refusal never shows contents):
//    · keys and credentials: ~/.ssh, ~/.gnupg, ~/Library/Keychains, ~/.aws, ~/.config/op, ~/.op;
//    · vt's state: VT_HOME (and the default ~/.local/state/vt): tokens, ticket keys, journals, backups;
//    · /tmp/vt-asdf.* (a throwaway seal-demo output directory: never read);
//    · names that only a sealer writes and that are never published, anywhere: identity.key, *.age (unlock-*.age,
//      vault.tar.gz.age), SEALED-plaintext.txt, STRUCTURE.txt, MANIFEST.csv, BLANK-AT-SEAL.txt, and vt's api.token
//      and relay-ticket.key;
//    · PACKAGE TERRITORY (controller ruling, C6: package directories allow only SEALED.txt, WHEREVER they live) —
//      inside $OUT (VAULT_TIMELOCK_DIR, its defaults), inside any ~/p/1password-* directory (the conventional place for
//      packages and exports), or inside a package directory anywhere (named `1password-*-timelock-*`,
//      `*-timelock-<stamp>`, `timelock-<stamp>`, or holding a sealer's file: vault.tar.gz.age, unlock-TIME.age,
//      unlock-KEY.age, identity.key, STRUCTURE.txt, MANIFEST.csv, SEALED-plaintext.txt): EVERYTHING is refused except
//      a file named exactly `SEALED.txt` that sits directly in a package directory and below no items/, files/ or
//      restored/ directory. SEALED.txt is the one file a seal writes to be published; README.txt, BLANK-AT-SEAL.txt,
//      STRUCTURE.txt, MANIFEST.csv, an export's items and attachments, the restored vault and the rest never are.
//    The denylist is applied to the real path AND to the path as given (made absolute, `..` folded): a ~/p/1password-*
//    directory that is itself a link to another disk is still package territory.
// ★★ A SEALER'S WORK DIRECTORY (review m-6): 1password-timelock.sh exports the vault's plaintext into
//    ${TMPDIR:-/tmp}/1password-timelock.XXXXXXXX/{items,files} BEFORE any marker file exists there. A directory named
//    1password-timelock.<anything> (case-insensitive) is refused by its NAME alone, wherever it is: vt job commands never
//    see the sealer's TMPDIR (/var/folders/…/T, its real path /private/var/folders/…/T, /tmp, or another), so the name
//    is matched in every directory of the path as given and of the real path. Nothing in one is ever published, not
//    even a SEALED.txt (vt.message-workdir).
// The checks only look at names, links and file types (lstat, realpath); nothing else of any directory is read (no
// directory is ever listed).
import { MESSAGE_MAX, refuse } from '@vault-timelock/core/contracts'
import { sha256Hex } from '@vault-timelock/core/job'
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync, statSync } from 'node:fs'
import { userInfo } from 'node:os'
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { resolveOut } from 'vt-broadcast/src/lifecycle/paths.ts'
import type { Env } from '../ops/paths.ts'

// The one vt.message-path marker of this workspace.
export function assertMessagePath(ok: boolean, why: string): void {
  if (!ok) refuse('vt.message-path', why) // @guard:vt.message-path
}
function assertFits(ok: boolean): void {
  if (!ok) refuse('message.too-long', `the message file is over ${MESSAGE_MAX} bytes; it is not read`) // @guard:message.too-long
}
function assertUnchanged(ok: boolean, why: string): void {
  if (!ok) refuse('vt.message-changed', why) // @guard:vt.message-changed
}
function assertNotWorkDir(ok: boolean): void {
  if (!ok) refuse('vt.message-workdir', 'the message file is inside a sealer\'s work directory (1password-timelock.*), where a vault export\'s plaintext lives during a seal: nothing there is ever published; nothing was read') // @guard:vt.message-workdir
}
function assertOneLink(ok: boolean): void {
  if (!ok) refuse('vt.message-hardlink', 'the message file has another hard link, which could name it inside a denied directory; nothing was read (copy it and name the copy)') // @guard:vt.message-hardlink
}

const HOME_DENY = ['.ssh', '.gnupg', join('Library', 'Keychains'), '.aws', join('.config', 'op'), '.op']
// Names a sealer (or vt) writes that are never published, refused wherever they are (compared case-insensitively:
// macOS file systems usually are).
const NAME_DENY = new Set(['identity.key', 'sealed-plaintext.txt', 'structure.txt', 'manifest.csv', 'blank-at-seal.txt', 'api.token', 'relay-ticket.key'])
const PACKAGE_MARKERS = ['vault.tar.gz.age', 'unlock-TIME.age', 'unlock-KEY.age', 'identity.key', 'STRUCTURE.txt', 'MANIFEST.csv', 'SEALED-plaintext.txt']
const PACKAGE_NAME = /^(?:1password-.+-timelock-.+|.+-timelock-\d{8}T\d{6}Z|timelock-\d{8}T\d{6}Z)$/i
const NEVER_BELOW = new Set(['items', 'files', 'restored'])
const SEALER_WORK_DIR = /^1password-timelock\..+$/i
// Some directory on the path is named like a sealer's work directory.
export const inSealerWorkDir = (p: string): boolean => dirname(p).split(sep).some((c) => SEALER_WORK_DIR.test(c))

const real = (p: string): string | null => { try { return realpathSync.native(p) } catch { return null } }
const exists = (p: string): boolean => { try { lstatSync(p); return true } catch { return false } }
// child is root or lies below it (both real paths).
function within(child: string, root: string): boolean {
  const rel = relative(root, child)
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))
}
const isPackageDir = (dir: string): boolean => PACKAGE_NAME.test(basename(dir)) || PACKAGE_MARKERS.some((m) => exists(join(dir, m)))

// The homes whose credential directories are denied: $HOME and the account's home from the user database (a changed
// HOME does not hide the real one).
function homes(env: Env): string[] {
  const hs = new Set<string>()
  if (env.HOME !== undefined && isAbsolute(env.HOME)) hs.add(env.HOME)
  try { const h = userInfo().homedir; if (isAbsolute(h)) hs.add(h) } catch { /* no user database entry */ }
  return [...hs]
}

// Why a real path may not be published, or null. Exported for the tests' table.
export function deniedBecause(file: string, env: Env): string | null {
  const name = basename(file)
  const lower = name.toLowerCase()
  if (NAME_DENY.has(lower) || lower.endsWith('.age')) return 'a file the sealer or vt writes and that is never published (keys, state, the vault\'s shape or plaintext)'
  const onePassword = new Set<string>()
  for (const h of homes(env)) {
    for (const d of HOME_DENY) {
      const r = real(join(h, d))
      if (r !== null && within(file, r)) return 'a key or credential directory'
    }
    // ~/p/1password-*: package territory (below), as the path names it and as the real path does.
    for (const p of new Set([join(h, 'p'), real(join(h, 'p'))])) {
      if (p === null || !within(file, p) || file === p) continue
      const top = relative(p, file).split(sep)[0]
      if (top.toLowerCase().startsWith('1password-')) onePassword.add(join(p, top))
    }
    const st = real(join(h, '.local', 'state', 'vt'))
    if (st !== null && within(file, st)) return 'vt\'s state (VT_HOME)'
  }
  const vh = env.VT_HOME !== undefined && env.VT_HOME !== '' ? real(env.VT_HOME) : null
  if (vh !== null && within(file, vh)) return 'vt\'s state (VT_HOME)'
  const tmp = real('/tmp')
  for (const t of new Set(['/tmp', ...(tmp === null ? [] : [tmp])])) {
    if (file.startsWith(`${t}/vt-asdf.`)) return 'a /tmp/vt-asdf.* directory'
  }
  // Package territory: $OUT (each way it can be set) and every package directory.
  const outs = new Set<string>()
  for (const o of [resolveOut(env), ...(env.XDG_DATA_HOME ? [join(env.XDG_DATA_HOME, 'vault-timelock')] : []), ...homes(env).map((h) => join(h, '.local', 'share', 'vault-timelock'))]) {
    const r = isAbsolute(o) ? real(o) : null
    if (r !== null) outs.add(r)
  }
  // The territory's root is the OUTERMOST of them, so every directory between it and the file is checked.
  let root: string | null = null
  for (const o of [...outs, ...onePassword]) if (within(file, o) && (root === null || within(root, o))) root = o
  for (let d = dirname(file); ; d = dirname(d)) {
    if (isPackageDir(d) && (root === null || within(root, d))) root = d
    if (dirname(d) === d) break
  }
  if (root === null) return null
  const below = relative(root, dirname(file)).split(sep).filter((c) => c !== '')
  const published = name === 'SEALED.txt' && file !== root && isPackageDir(dirname(file)) && !below.some((c) => c === '..' || NEVER_BELOW.has(c.toLowerCase()))
  if (published) return null
  return onePassword.size > 0
    ? 'a 1Password package or export (~/p/1password-*): from there only a package\'s own SEALED.txt is ever published'
    : 'inside a vault-timelock package or $OUT, only a package\'s own SEALED.txt is ever published'
}

// Every directory the denylist names, as a path (each of its forms) with its identity (dev, ino), for alias folding.
function deniedRoots(env: Env): Array<{ path: string; dev: number; ino: number }> {
  const paths = new Set<string>(['/tmp'])
  for (const h of homes(env)) {
    paths.add(h)
    for (const d of HOME_DENY) paths.add(join(h, d))
    paths.add(join(h, 'p'))
    paths.add(join(h, '.local', 'state', 'vt'))
    paths.add(join(h, '.local', 'share', 'vault-timelock'))
  }
  if (env.VT_HOME !== undefined && isAbsolute(env.VT_HOME)) paths.add(env.VT_HOME)
  const out = resolveOut(env)
  if (isAbsolute(out)) paths.add(out)
  if (env.XDG_DATA_HOME !== undefined && isAbsolute(env.XDG_DATA_HOME)) paths.add(join(env.XDG_DATA_HOME, 'vault-timelock'))
  const roots: Array<{ path: string; dev: number; ino: number }> = []
  for (const p of paths) {
    const r = real(p)
    if (r === null) continue
    try { const st = statSync(r); roots.push({ path: r, dev: st.dev, ino: st.ino }) } catch { /* gone: nothing to fold */ }
  }
  return roots
}

// `path` with its deepest ancestor directory that is an ALIAS of a denied root (same dev+ino, another path: a
// firmlink such as /System/Volumes/Data/…, or any other second name of the directory) rewritten to the root's own
// path; `path` itself when there is none.
function foldAlias(path: string, roots: ReadonlyArray<{ path: string; dev: number; ino: number }>): string {
  for (let d = dirname(path); ; d = dirname(d)) {
    let st: ReturnType<typeof statSync> | null
    try { st = statSync(d) } catch { st = null }
    const r = st === null ? undefined : roots.find((x) => x.dev === st!.dev && x.ino === st!.ino)
    if (r !== undefined) return r.path === d ? path : join(r.path, relative(d, path))
    if (dirname(d) === d) return path
  }
}

// The denylist on every form of the path: the real path (every link resolved), the path as given (absolute, `..`
// folded lexically: a linked ~/p/1password-* directory), and each with an alias of a denied root folded to the root.
// The first refusal, or null.
export function deniedEither(given: string, file: string, env: Env): string | null {
  const roots = deniedRoots(env)
  for (const p of new Set([file, given, foldAlias(file, roots), foldAlias(given, roots)])) {
    const why = deniedBecause(p, env)
    if (why !== null) return why
  }
  return null
}

// path: the real path read; bytes: the file's bytes, read once from the verified descriptor; sha256: their digest.
export interface MessageFile { path: string; bytes: Uint8Array; sha256: string }

// TEST SEAM ONLY (never set by vt): called at each point between the check and the end of the read, so a test can swap
// the file or a parent directory, or grow the file, exactly there. `chunk` passes the bytes read so far.
export const messageFileSeams: { at?: (point: 'checked' | 'statted' | 'opened' | 'chunk', read?: number) => void } = {}

const CHUNK = 1 << 20
type Id = { dev: number; ino: number }
const same = (a: Id, b: Id): boolean => a.dev === b.dev && a.ino === b.ino

// The bytes of the message file named on the command line, after every check above. `cwd` resolves a relative path.
export function readMessageFile(arg: string, o: { env: Env; cwd: string }): MessageFile {
  const given = resolve(o.cwd, arg)
  let ls: ReturnType<typeof lstatSync> | null
  try { ls = lstatSync(given) } catch { ls = null }
  assertMessagePath(ls !== null, 'the message file does not exist or cannot be read (the path is not echoed)')
  assertMessagePath(!ls!.isSymbolicLink(), 'the message file is a symbolic link: name the file itself')
  const file = real(given) // resolved ONCE: every later step uses this path or the descriptor
  assertMessagePath(file !== null, 'the message file\'s real path cannot be resolved')
  assertNotWorkDir(!inSealerWorkDir(given) && !inSealerWorkDir(file!))
  const why = deniedEither(given, file!, o.env)
  assertMessagePath(why === null, `the message file may not be published: ${why}; nothing was read`)
  messageFileSeams.at?.('checked')
  let st: ReturnType<typeof lstatSync> | null
  try { st = lstatSync(file!) } catch { st = null }
  assertMessagePath(st !== null && st.isFile(), 'the message file is not a regular file (a directory, FIFO, socket or device is never read)')
  messageFileSeams.at?.('statted')
  let fd = -1
  try { fd = openSync(file!, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK) } catch { fd = -1 }
  assertMessagePath(fd >= 0, 'the message file cannot be opened')
  try {
    const fs = fstatSync(fd, { bigint: true })
    const fid = { dev: Number(fs.dev), ino: Number(fs.ino) }
    assertUnchanged(fs.isFile() && same(fid, st!), 'the message file changed between its check and its open; nothing was read')
    messageFileSeams.at?.('opened')
    // After the open: the argument still resolves to the same real path, and that path (and the argument, which is no
    // link) still names the descriptor's file. A parent directory swapped for a link, and swapped back, is caught.
    assertUnchanged(real(given) === file, 'the message file\'s path resolves elsewhere since its check (a directory on the way changed); nothing was read')
    let now: Array<{ dev: number; ino: number; link: boolean }> | null
    try { now = [lstatSync(file!), lstatSync(given)].map((x) => ({ dev: x.dev, ino: x.ino, link: x.isSymbolicLink() })) } catch { now = null }
    assertUnchanged(now !== null && now.every((x) => !x.link && same(x, fid)), 'the message file\'s path names another file since its open; nothing was read')
    assertOneLink(fs.nlink === 1n)
    assertFits(fs.size <= BigInt(MESSAGE_MAX))
    // One bounded read loop from the descriptor: to end of file, never more than MESSAGE_MAX + 1 bytes.
    const chunks: Buffer[] = []
    let total = 0
    for (;;) {
      const want = Math.min(CHUNK, MESSAGE_MAX + 1 - total)
      if (want <= 0) break
      const b = Buffer.alloc(want)
      const r = readSync(fd, b, 0, want, total)
      if (r === 0) break
      chunks.push(r === want ? b : b.subarray(0, r))
      total += r
      messageFileSeams.at?.('chunk', total)
    }
    assertFits(total <= MESSAGE_MAX)
    const after = fstatSync(fd, { bigint: true })
    assertUnchanged(BigInt(total) === fs.size && after.size === fs.size && after.mtimeNs === fs.mtimeNs && after.ctimeNs === fs.ctimeNs,
      'the message file changed while it was read; nothing is uploaded')
    const bytes = new Uint8Array(Buffer.concat(chunks, total))
    return { path: file!, bytes, sha256: sha256Hex(bytes) }
  } finally {
    closeSync(fd)
  }
}

// The first line of a text for the operator's eyes: control, format and separator characters escaped (\u{…}), at most
// 80 characters. (The caller prints it through the printer, which also redacts any address.)
export function firstLine(text: string): string {
  const line = text.split('\n', 1)[0]
  const chars = [...line]
  const shown = chars.slice(0, 80).map((c) => (/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\p{Cn}]/u.test(c) ? `\\u{${c.codePointAt(0)!.toString(16)}}` : c)).join('')
  return chars.length > 80 ? `${shown}…` : shown
}

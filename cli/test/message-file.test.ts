// cli/test/message-file.test.ts — the message file is read ONCE, from a verified descriptor (security review of ce5129d:
// message-file TOCTOU). Through the test seam (messageFileSeams.at, never set by vt) the file, or a parent directory,
// is swapped exactly between the check and the open, or after the open, and the file grows, shrinks or is rewritten
// during the read: each is refused, and nothing of a denied file is ever returned. Every HOME, key and file here is
// synthetic, under this test's temp dir (never the real ~/.ssh, ~/p or a real package).
import { test, before, after, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { appendFileSync, existsSync, linkSync, mkdirSync, mkdtempSync, openSync, closeSync, realpathSync, renameSync, rmSync, symlinkSync, truncateSync, writeFileSync, writeSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { MESSAGE_MAX } from '@vault-timelock/core/contracts'
import { sha256Hex } from '@vault-timelock/core/job'
import { messageFileSeams, readMessageFile } from '../src/job/message-file.ts'
import { removeDir, tempDir } from './lib.ts'

let T = ''
before(() => { T = tempDir('vt-c6-mf-') })
after(() => removeDir(T))
afterEach(() => { delete messageFileSeams.at })

const SECRET = 'synthetic-denied-bytes: never returned\n'
const PLAIN = 'a synthetic message to publish\n'
const put = (p: string, text: string | Buffer = PLAIN): string => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); return p }
function home(name: string): { home: string; env: Record<string, string>; key: string } {
  const h = join(T, `home-${name}`)
  const key = put(join(h, '.ssh', 'message.txt'), SECRET) // a "key" in a denied directory, under the SAME name
  return { home: h, env: { HOME: h, VT_HOME: join(T, `vth-${name}`), VAULT_TIMELOCK_DIR: join(T, `out-${name}`) }, key }
}
function refusedWith(f: () => unknown, id: string, why?: RegExp): void {
  assert.throws(f, (e: Error & { guardId?: string }) => {
    assert.equal(e.guardId, id, e.message)
    if (why !== undefined) assert.match(e.message, why)
    assert.ok(!e.message.includes('synthetic-denied-bytes') && !e.message.includes(PLAIN.trim()), 'a refusal never shows contents')
    return true
  })
}
const read = (file: string, env: Record<string, string>) => readMessageFile(file, { env, cwd: T })

test('the bytes returned are the file\'s, with their sha256; the seam points are reached in order', () => {
  const { env } = home('ok')
  const f = put(join(T, 'ok', 'message.txt'))
  const seen: string[] = []
  messageFileSeams.at = (p) => { seen.push(p) }
  const m = read(f, env)
  assert.equal(Buffer.from(m.bytes).toString('utf8'), PLAIN)
  assert.equal(m.sha256, sha256Hex(PLAIN))
  assert.deepEqual(seen, ['checked', 'statted', 'opened', 'chunk'])
})

test('the file swapped for another between the check and the open: refused (vt.message-changed)', () => {
  const { env } = home('swap-file')
  const f = put(join(T, 'swap-file', 'message.txt'))
  const other = put(join(T, 'swap-file', 'other.txt'), 'another synthetic file\n')
  messageFileSeams.at = (p) => { if (p === 'statted') renameSync(other, f) }
  refusedWith(() => read(f, env), 'vt.message-changed', /between its check and its open/)
  // Swapped for a link (to the denied key) after the check: O_NOFOLLOW / lstat refuse it; nothing is read.
  const g = put(join(T, 'swap-file', 'message2.txt'))
  const { key } = home('swap-file-2')
  messageFileSeams.at = (p) => { if (p === 'checked') { renameSync(g, `${g}.orig`); symlinkSync(key, g) } }
  refusedWith(() => read(g, env), 'vt.message-path', /not a regular file/)
  const h = put(join(T, 'swap-file', 'message3.txt'))
  messageFileSeams.at = (p) => { if (p === 'statted') { renameSync(h, `${h}.orig`); symlinkSync(key, h) } }
  refusedWith(() => read(h, env), 'vt.message-path', /cannot be opened/)
})

test('a parent directory swapped for a link into a denied directory, at any point, is refused (vt.message-changed); swapped back too', () => {
  const { env, key } = home('swap-dir')
  const denied = dirname(key)
  for (const point of ['checked', 'statted'] as const) {
    const d = join(T, `swap-dir-${point}`)
    const f = put(join(d, 'message.txt'))
    messageFileSeams.at = (p) => { if (p === point) { renameSync(d, `${d}.orig`); symlinkSync(denied, d) } }
    refusedWith(() => read(f, env), 'vt.message-changed')
  }
  // Swapped before the lstat (so the open and the lstat agree on the denied file) and swapped BACK right after the open:
  // the realpath agrees again, but lstat of the path no longer names the descriptor's file.
  const d = join(T, 'swap-dir-back')
  const f = put(join(d, 'message.txt'))
  messageFileSeams.at = (p) => {
    if (p === 'checked') { renameSync(d, `${d}.orig`); symlinkSync(denied, d) }
    if (p === 'opened') { renameSync(d, `${d}.link`); renameSync(`${d}.orig`, d) }
  }
  refusedWith(() => read(f, env), 'vt.message-changed', /names another file since its open/)
  // Not swapped back: the argument resolves elsewhere after the open.
  const e = join(T, 'swap-dir-stay')
  const g = put(join(e, 'message.txt'))
  messageFileSeams.at = (p) => { if (p === 'checked') { renameSync(e, `${e}.orig`); symlinkSync(denied, e) } }
  refusedWith(() => read(g, env), 'vt.message-changed', /resolves elsewhere/)
})

test('the file grows, shrinks or is rewritten during the read: refused; grown past the cap: message.too-long', () => {
  const { env } = home('grow')
  const big = Buffer.alloc(2 * (1 << 20) + 123, 0x61)
  const grow = put(join(T, 'grow', 'grow.txt'), big)
  messageFileSeams.at = (p, n) => { if (p === 'chunk' && n === 1 << 20) appendFileSync(grow, 'more') }
  refusedWith(() => read(grow, env), 'vt.message-changed', /changed while it was read/)
  const shrink = put(join(T, 'grow', 'shrink.txt'), big)
  messageFileSeams.at = (p, n) => { if (p === 'chunk' && n === 1 << 20) truncateSync(shrink, 1 << 20) }
  refusedWith(() => read(shrink, env), 'vt.message-changed', /changed while it was read/)
  const rewrite = put(join(T, 'grow', 'rewrite.txt'), big)
  messageFileSeams.at = (p, n) => {
    if (p === 'chunk' && n === 1 << 20) { const fd = openSync(rewrite, 'r+'); try { writeSync(fd, 'X', 0) } finally { closeSync(fd) } }
  }
  refusedWith(() => read(rewrite, env), 'vt.message-changed', /changed while it was read/)
  // At the cap at open, then grown past it during the read: never more than MESSAGE_MAX + 1 bytes are read.
  const cap = put(join(T, 'grow', 'cap.txt'), '')
  truncateSync(cap, MESSAGE_MAX - 5)
  let most = 0
  messageFileSeams.at = (p, n) => { if (p === 'chunk') { most = Math.max(most, n ?? 0); if (n === 1 << 20) appendFileSync(cap, Buffer.alloc(100, 0x62)) } }
  refusedWith(() => read(cap, env), 'message.too-long')
  assert.equal(most, MESSAGE_MAX + 1, 'the read stopped one byte past the cap')
  // Exactly the cap, unchanged: read whole.
  const exact = put(join(T, 'grow', 'exact.txt'), '')
  truncateSync(exact, MESSAGE_MAX)
  delete messageFileSeams.at
  assert.equal(read(exact, env).bytes.length, MESSAGE_MAX)
})

test('a hard link (into a synthetic denied directory, or any second link) is refused (vt.message-hardlink); nothing is read', () => {
  const { env, key } = home('hl')
  const f = join(T, 'hl', 'message.txt')
  mkdirSync(dirname(f), { recursive: true })
  linkSync(key, f) // the same bytes as ~/.ssh/message.txt under an innocent path
  let reads = 0
  messageFileSeams.at = (p) => { if (p === 'chunk') reads++ }
  refusedWith(() => read(f, env), 'vt.message-hardlink', /another hard link/)
  const plain = put(join(T, 'hl', 'plain.txt'))
  linkSync(plain, join(T, 'hl', 'plain-2.txt'))
  refusedWith(() => read(plain, env), 'vt.message-hardlink')
  assert.equal(reads, 0)
})

test('an alias of a denied directory that realpath does not fold (the /System/Volumes/Data firmlink) is still denied', () => {
  const { env, key, home: h } = home('alias')
  const firm = '/System/Volumes/Data'
  assert.ok(existsSync(join(firm, key)), 'macOS: the Data volume firmlink names the same file')
  refusedWith(() => read(join(firm, key), env), 'vt.message-path', /a key or credential directory/)
  put(join(h, 'p', '1password-Test-export', 'notes.txt'))
  refusedWith(() => read(join(firm, h, 'p', '1password-Test-export', 'notes.txt'), env), 'vt.message-path', /~\/p\/1password-\*/)
  const vth = put(join(env.VT_HOME, 'local', 'notes.txt'))
  refusedWith(() => read(join(firm, vth), env), 'vt.message-path', /VT_HOME/)
  // An allowed file through the alias is still read.
  const ok = put(join(T, 'alias-ok', 'message.txt'))
  assert.equal(Buffer.from(read(join(firm, ok), env).bytes).toString('utf8'), PLAIN)
})

// ---- fix round 1 (task-C6-review.md m-6)

test('review m-6: a sealer\'s work directory (1password-timelock.*) is refused by its NAME, before any marker file exists, wherever it is (vt.message-workdir)', () => {
  const { env } = home('workdir')
  const read6 = (f: string, e: Record<string, string> = env): void => refusedWith(() => read(f, e), 'vt.message-workdir', /sealer's work directory/)
  // as the sealer leaves it mid-seal: items and files exported, no STRUCTURE.txt, MANIFEST.csv or identity.key yet
  const tmp = join(T, 'tmpdir')
  const w = join(tmp, '1password-timelock.Ab3dE9xQ')
  const files = [put(join(w, 'items', 'synthetic-item.json'), SECRET), put(join(w, 'files', 'synthetic-attachment.txt'), SECRET), put(join(w, 'notes.txt'), SECRET), put(join(w, 'SEALED.txt'), SECRET)]
  for (const f of files) {
    read6(f, { ...env, TMPDIR: tmp })
    read6(f) // vt job commands never get the sealer's TMPDIR: the name alone decides
  }
  // named through a link (the path as given is clean, the real path is not), a link named like one (the reverse), any case
  symlinkSync(w, join(T, 'innocent-link'))
  read6(join(T, 'innocent-link', 'items', 'synthetic-item.json'))
  put(join(T, 'plain', 'm.txt'))
  symlinkSync(join(T, 'plain'), join(T, '1password-timelock.link'))
  read6(join(T, '1password-timelock.link', 'm.txt'))
  read6(put(join(T, 'case', '1PASSWORD-TIMELOCK.Zz', 'x.txt'), SECRET))
  // the per-user temp dir a sealer uses on macOS: /var/folders/…/T as given, /private/var/folders/…/T as its real path
  const userTmp = spawnSync('/usr/bin/getconf', ['DARWIN_USER_TEMP_DIR'], { encoding: 'utf8' }).stdout.trim()
  assert.match(userTmp, /^\/var\/folders\//)
  const uw = mkdtempSync(join(userTmp, '1password-timelock.'))  // this test's own, synthetic, removed below
  try {
    const f = put(join(uw, 'items', 'synthetic-item.json'), SECRET)
    assert.ok(realpathSync(f).startsWith('/private/var/folders/'))
    read6(f)
    read6(realpathSync(f))
  } finally {
    rmSync(uw, { recursive: true, force: true })
  }
  // not one: a name that only contains the words, the bare name without a suffix, and a package keeps its SEALED.txt rule
  for (const f of [put(join(T, 'x-1password-timelock.notes', 'm.txt')), put(join(T, '1password-timelock', 'm.txt')), put(join(T, 'pkgs', '1password-Synthetic-timelock-20261009T120000Z', 'SEALED.txt'))]) {
    assert.equal(Buffer.from(read(f, env).bytes).toString('utf8'), PLAIN)
  }
})

// cli/test/decrypt-broker.test.ts — the UNSANDBOXED side of `vt decrypt` (src/ops/decrypt-broker.ts, the decrypt parts of src/ops/broker.ts),
// in-process, inside the suite sandbox: where the plaintext may go (vt.decrypt-output, vt.out-exists), the paste / pipe rules (decrypt.format,
// decrypt.size: decided before any prompt), the broker's own reading of the input's kind (a passphrase prompt only for age scrypt), the
// prompt policy (exactly one age passphrase), and the writer (O_EXCL, 0600 / 0700, never overwriting or merging: `A` / `a` and NFC / NFD \u00e9
// are refused, M-5). The mutation runner blanks each of those guard lines and these tests must fail (test/mutation/guards.json).
// SYNTHETIC data only: made-up passphrases, fresh identities, archives built here.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { PassThrough } from 'node:stream'
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, statSync, symlinkSync, truncateSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type * as Fixtures from '../../packages/core/test/decrypt/fixtures.ts'
import { OutputViolation, OutputWriter, checkOutPath, isScrypt, outputFor, peekFile, prepareDecrypt, readInput, safeSegments, shapeOfBytes, stanzaTypes, PasteScanner } from '../src/ops/decrypt-broker.ts'
import { BROKER_TAG, Violation, answerRequest, decryptPolicy, policyFor } from '../src/ops/broker.ts'
import type { BrokerTty } from '../src/ops/broker.ts'
import { ARMOR_END, FILE_MAX, PASTE_MAX, decryptPositions, parseDecryptArgs } from '../src/decrypt-args.ts'
import { rejectsWith, removeDir, tempDir, throwsWith } from './lib.ts'

const PASS = 'decrypt-broker-synthetic-passphrase'
let T = ''
let SCRYPT_ARMOR = ''
let SCRYPT_BIN: Uint8Array = new Uint8Array()
let X_ARMOR = ''
let X_BIN: Uint8Array = new Uint8Array()
const SEALED_HEAD = '== vault-timelock sealed package: self-contained, age + drand timelock ==\nformat: vault-timelock-sealed/1\nsynthetic preamble line\n'
// core's synthetic fixtures (age-encryption is core's dependency, not the cli's), found through the linked package like btc.test.ts does
const CORE_TEST = new URL('../../test/', import.meta.resolve('@vault-timelock/core/contracts'))
before(async () => {
  T = tempDir('vt-decrypt-broker-')
  const f = await import(new URL('decrypt/fixtures.ts', CORE_TEST).href) as typeof Fixtures
  SCRYPT_BIN = await f.passphraseBin('synthetic plaintext\n', PASS)
  SCRYPT_ARMOR = f.armor(SCRYPT_BIN)
  X_BIN = await f.identityBin('synthetic plaintext\n', (await f.newIdentity()).recipient)
  X_ARMOR = f.armor(X_BIN)
})
after(() => removeDir(T))
const dir = (n: string): string => join(T, n)
const args = (...a: string[]) => parseDecryptArgs(a)

// ---- where the plaintext goes

test('vt.decrypt-output: neither --out nor --stdout is refused before anything is read, on a terminal and off it; --stdout and --list are allowed on a terminal', { timeout: 30_000 }, () => {
  throwsWith(() => outputFor(args('f.age'), { stdoutIsTty: true, sealed: false }), 'vt.decrypt-output')
  throwsWith(() => outputFor(args('f.age'), { stdoutIsTty: false, sealed: false }), 'vt.decrypt-output')
  throwsWith(() => outputFor(args('S.txt', '--only', 'items/a.json'), { stdoutIsTty: true, sealed: true }), 'vt.decrypt-output')
  assert.throws(() => outputFor(args('f.age'), { stdoutIsTty: true, sealed: false }), /never shows a decrypted file by accident/)
  assert.deepEqual(outputFor(args('f.age', '--stdout'), { stdoutIsTty: true, sealed: false }), { kind: 'stdout' })
  assert.deepEqual(outputFor(args('S.txt', '--list'), { stdoutIsTty: true, sealed: true }), { kind: 'none' })
  assert.deepEqual(outputFor(args('f.age', '--out', dir('new.txt')), { stdoutIsTty: true, sealed: false }), { kind: 'file', path: dir('new.txt') })
  assert.deepEqual(outputFor(args('S.txt', '--out', dir('newdir')), { stdoutIsTty: true, sealed: true }), { kind: 'dir', path: dir('newdir') })
  assert.deepEqual(outputFor(args('S.txt', '--only', 'a', '--out', dir('one')), { stdoutIsTty: true, sealed: true }), { kind: 'file', path: dir('one') })
})

test('vt.out-exists: --out that exists (a file, a directory, a dangling link) or whose directory does not exist is refused before anything is read', { timeout: 30_000 }, () => {
  writeFileSync(dir('exists.txt'), 'synthetic')
  mkdirSync(dir('exists-dir'))
  symlinkSync(dir('nowhere'), dir('dangling'))
  for (const p of [dir('exists.txt'), dir('exists-dir'), dir('dangling')]) throwsWith(() => checkOutPath(p), 'vt.out-exists')
  throwsWith(() => checkOutPath(join(T, 'no-such-dir', 'x.txt')), 'vt.out-exists')
  throwsWith(() => outputFor(args('f.age', '--out', dir('exists.txt')), { stdoutIsTty: false, sealed: false }), 'vt.out-exists')
  checkOutPath(dir('fresh.txt'))
  assert.equal(readFileSync(dir('exists.txt'), 'utf8'), 'synthetic', 'untouched')
})

test('usage: the argv rules both sides share (repeats, values, combinations)', { timeout: 30_000 }, () => {
  assert.deepEqual(args(), { input: null, identity: null, out: null, stdout: false, list: false, only: null, fromLauncher: false })
  assert.deepEqual(args('-', '--stdout'), { input: null, identity: null, out: null, stdout: true, list: false, only: null, fromLauncher: false })
  assert.deepEqual(args('--identity', 'k', 'S.txt', '--only', 'a/b', '--out', 'x'), { input: 'S.txt', identity: 'k', out: 'x', stdout: false, list: false, only: 'a/b', fromLauncher: false })
  for (const bad of [['a', 'b'], ['--out'], ['--out', 'x', '--out', 'y'], ['--stdout', '--out', 'x'], ['--list', '--out', 'x'], ['--list', '--only', 'a'], ['--list', '--stdout'], ['--bogus'], ['--identity', '-'], ['--out', '--stdout']]) {
    assert.throws(() => args(...bad), /usage: vt decrypt/, bad.join(' '))
  }
})

// ---- the paste and the pipe

const feed = async (chunks: Array<string | Buffer>, o: { tty: boolean; end?: boolean; limit?: number }): Promise<Buffer> => {
  const s = new PassThrough()
  const p = readInput(s, { tty: o.tty, quietMs: 20, limit: o.limit })
  for (const c of chunks) s.write(c)
  if (o.end !== false) s.end()
  return p
}
const lines = (t: string): string[] => t.split(/(?<=\n)/)

test('paste: it ends AT the end line (armor, SEALED.txt); what follows is never taken; a leading blank line and a BOM are fine', { timeout: 30_000 }, async () => {
  const got = await feed(['\n', `\ufeff${SCRYPT_ARMOR.split('\n')[0]}\n`, ...lines(SCRYPT_ARMOR.split('\n').slice(1).join('\n')), 'echo this-must-never-run\n'], { tty: true, end: false })
  assert.ok(got.toString().trimEnd().endsWith(ARMOR_END))
  assert.ok(!got.toString().includes('this-must-never-run'))
  const sealed = `${SEALED_HEAD}[file x bytes=1 sha256=00]\n${X_ARMOR}== end ==\n`
  const s2 = await feed([...lines(sealed), 'trailing\n'], { tty: true, end: false })
  assert.ok(s2.toString().endsWith('== end ==\n'))
  assert.ok(s2.toString().includes(ARMOR_END), 'a SEALED.txt is not cut at its first armor block')
})

test('paste: Ctrl-D ends it — after the end line typed without its newline it completes; before the end line, or on nothing, it is refused (decrypt.format)', { timeout: 30_000 }, async () => {
  const body = SCRYPT_ARMOR.trimEnd()
  const ls = lines(body)
  const got = await feed(ls, { tty: true, end: false })     // the last piece has no newline: what Ctrl-D after it hands over
  assert.ok(got.toString().endsWith(ARMOR_END))
  await rejectsWith(() => feed(lines(body).slice(0, 2), { tty: true }), 'decrypt.format')
  await rejectsWith(() => feed([], { tty: true }), 'decrypt.format')
  await assert.rejects(feed(lines(body).slice(0, 2), { tty: true }), /ended before -----END AGE ENCRYPTED FILE-----/)
})

test('decrypt.format before any prompt: a paste whose first line is not armor / SEALED.txt is refused AT ONCE (no Ctrl-D needed); a non-base64 armor line; not UTF-8', { timeout: 30_000 }, async () => {
  await rejectsWith(() => feed(['hello, this is not armor\n'], { tty: true, end: false }), 'decrypt.format')
  await rejectsWith(() => feed(['-----BEGIN AGE ENCRYPTED FILE-----\n', 'not base64 at all!\n'], { tty: true, end: false }), 'decrypt.format')
  await rejectsWith(() => feed([Buffer.from([0xff, 0xfe, 0x0a])], { tty: true, end: false }), 'decrypt.format')
  await rejectsWith(() => feed(['plain text on a pipe\n'], { tty: false }), 'decrypt.format')
  await rejectsWith(() => feed([`${SEALED_HEAD}no end line\n`], { tty: false }), 'decrypt.format')
  await rejectsWith(() => feed([SCRYPT_ARMOR, 'junk after the end\n'], { tty: false }), 'decrypt.format')
  await rejectsWith(() => feed([Buffer.from('age-encryption.org/v1\n-> scrypt')], { tty: false }), 'decrypt.format')
})

test('decrypt.size: over 1 MiB is refused as soon as it is over (a paste and a pipe), at exactly the cap it is not', { timeout: 30_000 }, async () => {
  assert.equal(PASTE_MAX, 1024 * 1024)
  const big = `${'A'.repeat(63)}\n`
  const head = `${SEALED_HEAD}`
  const n = Math.ceil(PASTE_MAX / big.length) + 2
  await rejectsWith(() => feed([head, ...Array.from({ length: n }, () => big)], { tty: true, end: false }), 'decrypt.size')
  await rejectsWith(() => feed([head, ...Array.from({ length: n }, () => big)], { tty: false }), 'decrypt.size')
  const sc = new PasteScanner(false, 100)
  assert.equal(sc.push(Buffer.alloc(100, 0x41)), false)
  throwsWith(() => sc.push(Buffer.alloc(1, 0x41)), 'decrypt.size')
})

test('a pipe: read to EOF; armor, a SEALED.txt and BINARY age are accepted, blank lines after the end line too', { timeout: 30_000 }, async () => {
  assert.equal((await feed([SCRYPT_ARMOR, '\n\n'], { tty: false })).toString().trim(), SCRYPT_ARMOR.trim())
  assert.deepEqual([...await feed([Buffer.from(X_BIN)], { tty: false })], [...X_BIN])
  const sealed = `${SEALED_HEAD}[file x bytes=1 sha256=00]\n${X_ARMOR}== end ==\n`
  assert.equal((await feed([sealed], { tty: false })).toString(), sealed)
})

// ---- the broker's own reading of the input (the passphrase prompt is allowed only for age scrypt)

test('kind: only an age file whose ONLY stanza is scrypt asks a passphrase (armored and binary); X25519, a SEALED.txt and garbage never do', { timeout: 30_000 }, () => {
  assert.equal(isScrypt(SCRYPT_BIN), true)
  assert.equal(isScrypt(Buffer.from(SCRYPT_ARMOR)), true)
  assert.equal(isScrypt(X_BIN), false)
  assert.equal(isScrypt(Buffer.from(X_ARMOR)), false)
  assert.equal(isScrypt(Buffer.from(`${SEALED_HEAD}== end ==\n`)), false)
  assert.equal(isScrypt(Buffer.from('age-encryption.org/v1\n-> scrypt c2FsdA 10\n-> X25519 a\nYQ\n--- bWFj\n')), false, 'scrypt beside another stanza')
  assert.deepEqual(stanzaTypes(Buffer.from('age-encryption.org/v1\n-> tlock 1 ab\nYQ\n--- bWFj\n')), ['tlock'])
  assert.equal(stanzaTypes(Buffer.from('age-encryption.org/v1\n-> scrypt c2FsdA 10\n')), null, 'no MAC line: no header')
  assert.equal(shapeOfBytes(Buffer.from(`\n${SEALED_HEAD}`)), 'sealed')
  assert.equal(shapeOfBytes(Buffer.from('vault-timelock/1 unlock=2100-01-01T00:00:00Z\n')), 'sealed')
  assert.equal(shapeOfBytes(X_BIN), 'binary')
  assert.equal(shapeOfBytes(Buffer.from('hello')), null)
  writeFileSync(dir('p.age'), SCRYPT_ARMOR)
  assert.equal(isScrypt(peekFile(dir('p.age'))), true)
  assert.equal(peekFile(dir('missing.age')).length, 0)
})

test('prepareDecrypt: a handed file is peeked (passphrase label = its name, only for scrypt); a SEALED.txt goes to a NEW directory; a paste is validated and handed on', { timeout: 30_000 }, async () => {
  writeFileSync(dir('pf.age'), SCRYPT_ARMOR)
  writeFileSync(dir('xf.age'), X_BIN)
  writeFileSync(dir('S.txt'), `${SEALED_HEAD}== end ==\n`)
  const tty = { stdin: new PassThrough(), stdinIsTty: false, stdoutIsTty: true, note: () => {}, flush: () => {} }
  const p = await prepareDecrypt(['decrypt', dir('pf.age'), '--out', dir('o1')], tty)
  assert.equal(p.passLabel, 'pf.age'); assert.equal(p.stdin, null); assert.deepEqual(p.output, { kind: 'file', path: dir('o1') })
  assert.equal((await prepareDecrypt(['decrypt', dir('xf.age'), '--stdout'], tty)).passLabel, null)
  assert.deepEqual((await prepareDecrypt(['decrypt', dir('S.txt'), '--out', dir('o2')], tty)).output, { kind: 'dir', path: dir('o2') })
  // a paste on a terminal: the note is shown, the input is flushed afterwards, the label names the paste
  const notes: string[] = []
  let flushed = 0
  const stdin = new PassThrough()
  const pp = prepareDecrypt(['decrypt', '--out', dir('o3')], { stdin, stdinIsTty: true, stdoutIsTty: true, note: (t) => notes.push(t), flush: () => { flushed++ }, quietMs: 20 })
  for (const l of lines(SCRYPT_ARMOR)) stdin.write(l)
  const plan = await pp
  assert.equal(plan.passLabel, 'the pasted age file'); assert.equal(plan.fromTty, true); assert.equal(flushed, 1)
  assert.match(notes.join(''), /paste the age armor or the SEALED\.txt now/)
  assert.equal(plan.stdin?.toString().trim(), SCRYPT_ARMOR.trim())
  // refused BEFORE reading: no destination
  const untouched = new PassThrough()
  await rejectsWith(() => prepareDecrypt(['decrypt'], { stdin: untouched, stdinIsTty: true, stdoutIsTty: true, note: () => { throw new Error('nothing is asked') }, flush: () => {} }), 'vt.decrypt-output')
})

// ---- the prompt policy: one age passphrase, only when the input is scrypt

const fakeTty = (answers: string[] = [PASS]): BrokerTty & { notes: string[] } => {
  const notes: string[] = []
  return { notes, available: () => true, passphrase: async () => answers.shift() ?? '', word: async () => undefined, keys: () => () => {}, note: (t) => { notes.push(t) } }
}
const noKeys = { start: () => {}, stop: () => {} }

test('decrypt policy: exactly ONE echo-off age passphrase, named by the broker; a second, one for a non-scrypt input, a chain passphrase, a typed word or the key reader are violations', { timeout: 30_000 }, async () => {
  const pol = decryptPolicy('pf.age')
  assert.equal(pol.prompts, true)
  const tty = fakeTty()
  const state = { asked: new Set<'eth' | 'sol' | 'btc'>(), left: new Map(pol.words) }
  const a = await answerRequest(JSON.stringify({ id: 1, kind: 'age-passphrase' }), tty, pol, state, noKeys)
  assert.deepEqual(JSON.parse(a as string), { id: 1, answer: PASS })
  assert.match(tty.notes.join(''), new RegExp(`${BROKER_TAG.replace(/[[\]]/g, '\\$&')}passphrase of pf\\.age \\(age scrypt\\); typed here, not echoed`))
  await assert.rejects(answerRequest(JSON.stringify({ id: 2, kind: 'age-passphrase' }), fakeTty(), pol, state, noKeys), (e: unknown) => e instanceof Violation && /a second time/.test(e.message))
  const none = decryptPolicy(null)
  assert.equal(none.prompts, false)
  await assert.rejects(answerRequest(JSON.stringify({ id: 1, kind: 'age-passphrase' }), fakeTty(), none, { asked: new Set(), left: new Map() }, noKeys), Violation)
  for (const req of [{ id: 3, kind: 'passphrase', chain: 'eth' }, { id: 4, kind: 'word', word: 'again' }, { kind: 'keys', on: true }]) {
    await assert.rejects(answerRequest(JSON.stringify(req), fakeTty(), decryptPolicy('pf.age'), { asked: new Set(), left: new Map() }, noKeys), Violation, JSON.stringify(req))
  }
  // a job command's policy never allows the age passphrase
  await assert.rejects(answerRequest(JSON.stringify({ id: 1, kind: 'age-passphrase' }), fakeTty(), policyFor(['job', 'run', 'x', '--backup-eth', 'f']), { asked: new Set(), left: new Map() }, noKeys), Violation)
  // a name from argv cannot forge the broker's tag or move the cursor
  const t2 = fakeTty()
  await answerRequest(JSON.stringify({ id: 1, kind: 'age-passphrase' }), t2, decryptPolicy('x\u001b[2J[vt broker] y\n.age'), { asked: new Set(), left: new Map() }, noKeys)
  assert.ok(!t2.notes.join('').includes('\u001b[2J') && !/\[vt broker\] y/.test(t2.notes.join('')))
})

// ---- the writer

const frame = (path: string, body: string | Buffer): Buffer => Buffer.concat([Buffer.from(`${JSON.stringify({ path, size: Buffer.byteLength(body) })}\n`), Buffer.from(body)])
const END = Buffer.from('{"end":true}\n')
const mode = (p: string): number => lstatSync(p).mode & 0o777

test('writer, --out <file>: O_EXCL, 0600, any split of the stream; a second file, a header without its bytes or no end is refused / removed', { timeout: 30_000 }, () => {
  const w = new OutputWriter({ kind: 'file', path: dir('w1.txt') })
  const all = Buffer.concat([frame('plaintext', 'synthetic bytes\n'), END])
  for (let i = 0; i < all.length; i += 3) w.push(all.subarray(i, i + 3))
  const r = w.finish(true)
  assert.equal(r?.files, 1); assert.equal(r?.bytes, 16)
  assert.equal(readFileSync(dir('w1.txt'), 'utf8'), 'synthetic bytes\n')
  assert.equal(mode(dir('w1.txt')), 0o600)
  const w2 = new OutputWriter({ kind: 'file', path: dir('w2.txt') })
  w2.push(frame('a', 'one'))
  assert.throws(() => w2.push(frame('b', 'two')), OutputViolation)
  assert.equal(w2.finish(false), null)
  assert.equal(existsSync(dir('w2.txt')), false, 'removed')
  const w3 = new OutputWriter({ kind: 'file', path: dir('w3.txt') })
  w3.push(frame('a', 'complete bytes'))
  assert.equal(w3.finish(true), null, 'no end frame: not complete')
  assert.equal(existsSync(dir('w3.txt')), false)
  // the file appeared between the check and the write: never overwritten (fix round 1: refused when the complete file is linked into place)
  writeFileSync(dir('w4.txt'), 'theirs')
  const w4 = new OutputWriter({ kind: 'file', path: dir('w4.txt') })
  w4.push(Buffer.concat([frame('a', 'ours'), END]))
  throwsWith(() => w4.finish(true), 'vt.out-exists')
  assert.equal(readFileSync(dir('w4.txt'), 'utf8'), 'theirs')
  for (const bad of ['not json\n', '{"path":"a"}\n', '{"path":"a","size":-1}\n', '{"path":"a","size":1,"x":1}\n', `${'x'.repeat(9000)}`]) {
    assert.throws(() => new OutputWriter({ kind: 'file', path: dir('w5.txt') }).push(Buffer.from(bad)), OutputViolation, bad.slice(0, 30))
  }
})

test('writer, --out <dir>: a NEW directory 0700, nested directories 0700, files 0600; unsafe paths are refused and nothing is kept', { timeout: 30_000 }, () => {
  const root = dir('d1')
  const w = new OutputWriter({ kind: 'dir', path: root })
  w.push(Buffer.concat([frame('items/a.json', '{"a":1}'), frame('files/a/f1', 'att'), frame('MANIFEST.csv', 'm'), END]))
  assert.equal(w.finish(true)?.files, 3)
  assert.equal(mode(root), 0o700); assert.equal(mode(join(root, 'items')), 0o700); assert.equal(mode(join(root, 'files', 'a')), 0o700)
  assert.equal(mode(join(root, 'items', 'a.json')), 0o600)
  assert.deepEqual(readdirSync(root).sort(), ['MANIFEST.csv', 'files', 'items'])
  for (const p of ['/abs', '../up', 'a/../b', 'a//b', './a', 'a\\b', 'a\u0001b', '', 'a/']) assert.throws(() => safeSegments(p), OutputViolation, JSON.stringify(p))
  const bad = new OutputWriter({ kind: 'dir', path: dir('d2') })
  bad.push(frame('ok.txt', 'fine'))
  assert.throws(() => bad.push(frame('../escape.txt', 'no')), OutputViolation)
  assert.equal(bad.finish(false), null)
  assert.equal(existsSync(dir('d2')), false, 'the whole directory is removed')
  assert.equal(existsSync(join(T, 'escape.txt')), false)
  // an empty archive still makes its (empty) directory
  const e = new OutputWriter({ kind: 'dir', path: dir('d3') })
  e.push(END)
  assert.equal(e.finish(true)?.files, 0)
  assert.ok(statSync(dir('d3')).isDirectory())
})

test('M-5: two entries APFS stores as ONE file — `A` / `a`, `\u00e9` NFC / `\u00e9` NFD, and a directory case pair — the second is refused (vt.out-exists), never merged; nothing is kept', { timeout: 30_000 }, () => {
  const nfc = 'caf\u00e9.txt', nfd = 'cafe\u0301.txt'
  assert.notEqual(nfc, nfd)
  const cases: Array<[string, string, string]> = [['case', 'A', 'a'], ['nfc-nfd', nfc, nfd], ['dir-case', 'Items/x.json', 'items/y.json'], ['file-dir', 'a', 'A/b'], ['dir-file', 'a/b', 'A'], ['exact', 'same', 'same']]
  for (const [name, first, second] of cases) {
    const root = dir(`m5-${name}`)
    const w = new OutputWriter({ kind: 'dir', path: root })
    w.push(frame(first, 'first'))
    throwsWith(() => w.push(frame(second, 'second')), 'vt.out-exists')
    assert.equal(w.finish(false), null, name)
    assert.equal(existsSync(root), false, `${name}: nothing kept`)
  }
  // the O_EXCL backstop under the fold check: a file that appears inside the (partial) output directory is never overwritten
  const w = new OutputWriter({ kind: 'dir', path: dir('m5-planted') })
  w.push(frame('first.txt', 'first'))
  const partial = join(T, readdirSync(T).find((n) => n.startsWith('.m5-planted.vt-partial-')) as string)
  writeFileSync(join(partial, 'second.txt'), 'planted')
  throwsWith(() => w.push(frame('second.txt', 'ours')), 'vt.out-exists')
  assert.equal(readFileSync(join(partial, 'second.txt'), 'utf8'), 'planted', 'not overwritten')
  w.finish(false)
  assert.equal(existsSync(partial), false)
  // on this disk (APFS, case- and normalization-insensitive by default) O_EXCL alone already sees each pair as one name
  const probe = dir('m5-probe')
  mkdirSync(probe)
  const insensitive = (a: string, b: string): boolean => {
    writeFileSync(join(probe, a), 'x', { flag: 'wx' })
    try { writeFileSync(join(probe, b), 'y', { flag: 'wx' }); return false } catch (e) { return (e as NodeJS.ErrnoException).code === 'EEXIST' } finally { removeDir(probe); mkdirSync(probe) }
  }
  if (insensitive('A', 'a')) assert.ok(insensitive('caf\u00e9', 'cafe\u0301'), 'APFS: NFC / NFD are one name too')
})

test('writer, --stdout: the bytes go to the sink raw (no filter), with backpressure; a second file is refused; --list expects no output at all', { timeout: 30_000 }, () => {
  const got: Buffer[] = []
  let ok = false
  const w = new OutputWriter({ kind: 'stdout' }, (b) => { got.push(b); return ok })
  const raw = Buffer.from([0x1b, 0x5d, 0x35, 0x32, 0x00, 0xff, 0x0a])
  assert.equal(w.push(Buffer.concat([frame('p', raw)])), false, 'the sink asked to wait')
  ok = true
  w.push(END)
  assert.deepEqual([...Buffer.concat(got)], [...raw])
  assert.equal(w.finish(true)?.bytes, raw.length)
  assert.throws(() => new OutputWriter({ kind: 'none' }).push(frame('p', 'x')), OutputViolation)
})

// =============================== fix round 1 ===============================

test('fix1 I-2: an input under a protected location ($VAULT_TIMELOCK_DIR, the default package dir) is opened by the LAUNCHER and handed on stdin; the child gets `-`', { timeout: 30_000 }, async () => {
  const out = dir('fx-out')
  mkdirSync(join(out, 'pkg'), { recursive: true })
  writeFileSync(join(out, 'pkg', 'p.age.txt'), SCRYPT_ARMOR)
  const d = { stdin: new PassThrough(), stdinIsTty: false, stdoutIsTty: false, note: () => {}, flush: () => {}, protectedRoots: [out] }
  const argv = ['decrypt', join(out, 'pkg', 'p.age.txt'), '--out', dir('fx-o1')]
  const plan = await prepareDecrypt(argv, d)
  assert.equal(plan.stdin?.toString(), SCRYPT_ARMOR)
  assert.deepEqual(plan.childArgs, ['decrypt', '-', '--out', dir('fx-o1'), '--from-launcher'])
  assert.equal(plan.passLabel, 'p.age.txt')
  // outside a protected location: handed as before
  writeFileSync(dir('fx-plain.age'), SCRYPT_ARMOR)
  const p2 = await prepareDecrypt(['decrypt', dir('fx-plain.age'), '--stdout'], d)
  assert.equal(p2.stdin, null); assert.deepEqual(p2.childArgs, ['decrypt', dir('fx-plain.age'), '--stdout'])
})

test('fix1 I-2: vt.decrypt-input — the launcher refuses, naming the reason: under restored/, a link, not a regular file, a vt credential, --identity in a protected place; over 1 MiB is decrypt.size', { timeout: 30_000 }, async () => {
  const out = dir('fx2-out')
  mkdirSync(join(out, 'pkg', 'restored'), { recursive: true })
  mkdirSync(join(out, 'local'), { recursive: true })
  writeFileSync(join(out, 'pkg', 'restored', 'x.age'), SCRYPT_ARMOR)
  writeFileSync(join(out, 'pkg', 'real.age'), SCRYPT_ARMOR)
  symlinkSync(join(out, 'pkg', 'real.age'), join(out, 'pkg', 'link.age'))
  writeFileSync(join(out, 'local', 'btc-rpc.auth'), 'synthetic:not-a-credential')
  writeFileSync(join(out, 'pkg', 'big.age'), `${SCRYPT_ARMOR}${'\n'.repeat(PASTE_MAX)}`)
  writeFileSync(dir('fx2-id.txt'), '# synthetic\n')
  writeFileSync(join(out, 'pkg', 'id.txt'), '# synthetic\n')
  const d = { stdin: new PassThrough(), stdinIsTty: false, stdoutIsTty: false, note: () => {}, flush: () => {}, protectedRoots: [out] }
  const cases: Array<[string[], RegExp]> = [
    [['decrypt', join(out, 'pkg', 'restored', 'x.age'), '--stdout'], /restored\//],
    [['decrypt', join(out, 'pkg', 'link.age'), '--stdout'], /link/],
    [['decrypt', join(out, 'pkg'), '--stdout'], /not a regular file/],
    [['decrypt', join(out, 'local', 'btc-rpc.auth'), '--stdout'], /credential/],
    [['decrypt', dir('fx-plain.age'), '--identity', join(out, 'pkg', 'id.txt'), '--stdout'], /--identity/],
    [['decrypt', join(dir('nowhere'), 'restored', 'y.age'), '--stdout'], /restored\//],
  ]
  for (const [argv, re] of cases) {
    await assert.rejects(prepareDecrypt(argv, d), (e: unknown) => {
      assert.equal((e as { guardId?: string }).guardId, 'vt.decrypt-input', `${argv[1]}: ${String(e)}`)
      assert.match((e as Error).message, re)
      assert.ok(!/^EPERM|: EPERM/.test((e as Error).message))
      return true
    })
  }
  // fix round 2: one cap for every FILE input (128 MiB), wherever it lies; a sparse file over it is refused before it is read
  const huge = join(out, 'pkg', 'huge.age')
  writeFileSync(huge, SCRYPT_ARMOR); truncateSync(huge, FILE_MAX + 1)
  await rejectsWith(() => prepareDecrypt(['decrypt', huge, '--stdout'], d), 'decrypt.size')
})

test('fix1 M-2: --out - / --out --stdout / --identity - are refused as ambiguous, and bin/vt never rewrites them into paths', { timeout: 30_000 }, () => {
  assert.throws(() => args('f.age', '--out', '-'), /ambiguous/)
  assert.throws(() => args('f.age', '--out', '--stdout'), /ambiguous/)
  assert.throws(() => args('f.age', '--identity', '-', '--stdout'), /ambiguous|path/)
  assert.deepEqual(decryptPositions(['decrypt', 'f.age', '--out', '-']), { handed: [1], out: null, input: 1, identity: null })
  assert.deepEqual(decryptPositions(['decrypt', 'f.age', '--out', '--stdout']), { handed: [1], out: null, input: 1, identity: null })
  assert.deepEqual(decryptPositions(['decrypt', 'f.age', '--identity', '-', '--stdout']), { handed: [1], out: null, input: 1, identity: null })
})

test('fix1 M-6: --out is written to an O_EXCL temporary beside it and LINKED into place: the final name never holds a partial file; a failure leaves nothing', { timeout: 30_000 }, () => {
  const w = new OutputWriter({ kind: 'file', path: dir('fx6.txt') })
  w.push(Buffer.from(`${JSON.stringify({ path: 'p', size: 10 })}\nhalf-`))
  assert.equal(existsSync(dir('fx6.txt')), false, 'nothing at the final name mid-write')
  const partials = (): string[] => readdirSync(T).filter((n) => n.startsWith('.fx6') && n.includes('.vt-partial-'))
  const temps = readdirSync(T).filter((n) => n.startsWith('.fx6.txt.vt-partial-'))
  assert.equal(temps.length, 1, 'a clearly named partial file beside it')
  assert.equal(mode(join(T, temps[0])), 0o600)
  w.push(Buffer.concat([Buffer.from('bytes'), END]))
  assert.equal(w.finish(true)?.files, 1)
  assert.equal(readFileSync(dir('fx6.txt'), 'utf8'), 'half-bytes')
  assert.deepEqual(partials(), [], 'the temporary is gone')
  // the final name appears meanwhile: link() refuses, nothing is overwritten, the temporary is removed
  const w2 = new OutputWriter({ kind: 'file', path: dir('fx6b.txt') })
  w2.push(frame('p', 'ours'))
  writeFileSync(dir('fx6b.txt'), 'theirs')
  w2.push(END)
  throwsWith(() => w2.finish(true), 'vt.out-exists')
  assert.equal(readFileSync(dir('fx6b.txt'), 'utf8'), 'theirs')
  assert.deepEqual(partials(), [])
  // a directory: built beside, renamed into place at the end
  const wd = new OutputWriter({ kind: 'dir', path: dir('fx6d') })
  wd.push(frame('items/a.json', '{}'))
  assert.equal(existsSync(dir('fx6d')), false, 'the directory appears only when complete')
  wd.push(END)
  assert.equal(wd.finish(true)?.files, 1)
  assert.equal(readFileSync(join(dir('fx6d'), 'items', 'a.json'), 'utf8'), '{}')
  assert.equal(mode(dir('fx6d')), 0o700)
  const wf = new OutputWriter({ kind: 'dir', path: dir('fx6e') })
  wf.push(frame('a', 'x'))
  assert.equal(wf.finish(false), null)
  assert.deepEqual(partials(), [])
})

test('fix1 M-4: the age passphrase prompt switches echo off and discards type-ahead BEFORE it prints anything', { timeout: 30_000 }, async () => {
  const events: string[] = []
  const tty: BrokerTty = { available: () => true, passphrase: async () => { events.push('read'); return PASS }, word: async () => undefined, keys: () => () => {},
    note: () => { events.push('note') }, quiet: () => { events.push('quiet') }, flush: () => { events.push('flush') }, loud: () => { events.push('loud') } }
  await answerRequest(JSON.stringify({ id: 1, kind: 'age-passphrase' }), tty, decryptPolicy('p.age'), { asked: new Set(), left: new Map() }, noKeys)
  assert.deepEqual(events.slice(0, 3), ['quiet', 'flush', 'note'], events.join(','))
  assert.equal(events.at(-1), 'loud')
})

// =============================== fix round 2 ===============================

const fx2 = (): { out: string; d: Parameters<typeof prepareDecrypt>[1] } => {
  const out = dir(`f2-out-${Math.random().toString(16).slice(2)}`)
  mkdirSync(join(out, 'pkg'), { recursive: true })
  return { out, d: { stdin: new PassThrough(), stdinIsTty: false, stdoutIsTty: false, note: () => {}, flush: () => {}, protectedRoots: [out] } }
}

test('fix2 N-1: the launcher VALIDATES a package-directory file like a pipe before handing it on: a plaintext stand-in is refused (vt.decrypt-input) by the broker', { timeout: 30_000 }, async () => {
  const { out, d } = fx2()
  writeFileSync(join(out, 'pkg', 'notes.txt'), 'synthetic stand-in for a plaintext view: item one, item two\n')
  writeFileSync(join(out, 'pkg', 'half.age'), SCRYPT_ARMOR.split('\n').slice(0, 3).join('\n') + '\n')
  writeFileSync(join(out, 'pkg', 'bin.age'), Buffer.from('age-encryption.org/v1\n-> scrypt c2FsdA 10\n'))
  for (const n of ['notes.txt', 'half.age', 'bin.age']) {
    await assert.rejects(prepareDecrypt(['decrypt', join(out, 'pkg', n), '--stdout'], d), (e: unknown) => {
      assert.equal((e as { guardId?: string }).guardId, 'vt.decrypt-input', `${n}: ${String(e)}`)
      assert.match((e as Error).message, /not age armor, a binary age file or a SEALED\.txt/)
      return true
    })
  }
  // valid inputs still pass: armor (with blank lines after its end), binary age, a SEALED.txt
  writeFileSync(join(out, 'pkg', 'ok.age'), `${SCRYPT_ARMOR}\n\n`)
  writeFileSync(join(out, 'pkg', 'ok-bin.age'), X_BIN)
  for (const n of ['ok.age', 'ok-bin.age']) assert.ok((await prepareDecrypt(['decrypt', join(out, 'pkg', n), '--stdout'], d)).stdin !== null, n)
})

test('fix2 N-1: the package\'s plaintext / key files are refused BY NAME (case-insensitively) even when they would validate; --identity identity.key elsewhere stays allowed', { timeout: 30_000 }, async () => {
  const { out, d } = fx2()
  const names = ['SEALED-plaintext.txt', 'sealed-PLAINTEXT.TXT', '.SEALED-plaintext.txt.ab12', 'identity.key', 'IDENTITY.KEY', 'MANIFEST.local.csv', 'STRUCTURE.txt', 'vault.tar', 'vault.TAR.GZ', 'secret.tgz']
  mkdirSync(dir('f2-elsewhere'), { recursive: true })
  for (const n of names) {
    writeFileSync(join(out, 'pkg', n), SCRYPT_ARMOR)
    writeFileSync(join(dir('f2-elsewhere'), n), SCRYPT_ARMOR)
    for (const p of [join(out, 'pkg', n), join(dir('f2-elsewhere'), n)]) {
      await assert.rejects(prepareDecrypt(['decrypt', p, '--stdout'], d), (e: unknown) => {
        assert.equal((e as { guardId?: string }).guardId, 'vt.decrypt-input', `${p}: ${String(e)}`)
        return true
      })
    }
  }
  writeFileSync(dir('f2-x.age'), X_BIN)
  writeFileSync(dir('identity.key'), '# synthetic\n')
  assert.equal((await prepareDecrypt(['decrypt', dir('f2-x.age'), '--identity', dir('identity.key'), '--stdout'], d)).passLabel, null)
})

test('fix2 N-2: restored/ is refused case-insensitively (RESTORED/, Restored/), for the input and for --identity', { timeout: 30_000 }, async () => {
  const { d } = fx2()
  for (const seg of ['RESTORED', 'Restored', 'restoreD']) {
    await rejectsWith(() => prepareDecrypt(['decrypt', join(dir('f2-any'), seg, 'x.age'), '--stdout'], d), 'vt.decrypt-input')
    writeFileSync(dir('f2-in.age'), X_BIN)
    await rejectsWith(() => prepareDecrypt(['decrypt', dir('f2-in.age'), '--identity', join(dir('f2-any'), seg, 'k.txt'), '--stdout'], d), 'vt.decrypt-input')
  }
})

test('fix2 cap: a package-directory file over 1 MiB (under 128 MiB) is handed in place, marked for the child as a FILE (its cap, not the paste cap)', { timeout: 30_000 }, async () => {
  const { out, d } = fx2()
  const big = `${SCRYPT_ARMOR}${'\n'.repeat(PASTE_MAX + 10)}`
  writeFileSync(join(out, 'pkg', 'big.age'), big)
  const p = await prepareDecrypt(['decrypt', join(out, 'pkg', 'big.age'), '--out', dir('f2-big-out')], d)
  assert.equal(p.stdin?.length, Buffer.byteLength(big))
  assert.deepEqual(p.childArgs, ['decrypt', '-', '--out', dir('f2-big-out'), '--from-launcher'])
  assert.equal(FILE_MAX, 128 * 1024 * 1024)
  // the flag is the broker's own: a user cannot give it
  assert.throws(() => args('-', '--stdout', '--from-launcher'), /unknown option/)
  assert.equal(parseDecryptArgs(['-', '--stdout', '--from-launcher'], { child: true }).fromLauncher, true)
})

test('fix2 N-5: a leftover partial output of an earlier, killed run beside --out is REPORTED (by its name pattern) and left alone', { timeout: 30_000 }, async () => {
  const { d } = fx2()
  const left = dir('.f2-report.txt.vt-partial-0123456789ab')
  writeFileSync(left, 'synthetic partial')
  writeFileSync(dir('.f2-report.txt.vt-partial-not-ours'), 'x')
  writeFileSync(dir('f2-r.age'), X_BIN)
  const p = await prepareDecrypt(['decrypt', dir('f2-r.age'), '--out', dir('f2-report.txt')], d)
  assert.equal(p.notes.length, 1)
  assert.match(p.notes[0], /\.f2-report\.txt\.vt-partial-0123456789ab/)
  assert.match(p.notes[0], /interrupted/)
  assert.equal(readFileSync(left, 'utf8'), 'synthetic partial', 'never deleted')
  assert.deepEqual((await prepareDecrypt(['decrypt', dir('f2-r.age'), '--out', dir('f2-clean.txt')], d)).notes, [])
})

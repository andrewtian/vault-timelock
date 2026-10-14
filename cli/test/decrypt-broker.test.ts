// cli/test/decrypt-broker.test.ts — the UNSANDBOXED side of `vt decrypt` (src/ops/decrypt-broker.ts, the decrypt parts of src/ops/broker.ts),
// in-process, inside the suite sandbox: where the plaintext may go (vt.decrypt-output, vt.out-exists), the paste / pipe rules (decrypt.format,
// decrypt.size: decided before any prompt), the broker's own reading of the input's kind (a passphrase prompt only for age scrypt), the
// prompt policy (exactly one age passphrase), and the writer (O_EXCL, 0600 / 0700, never overwriting or merging: `A` / `a` and NFC / NFD \u00e9
// are refused, M-5). The mutation runner blanks each of those guard lines and these tests must fail (test/mutation/guards.json).
// SYNTHETIC data only: made-up passphrases, fresh identities, archives built here.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { PassThrough } from 'node:stream'
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type * as Fixtures from '../../packages/core/test/decrypt/fixtures.ts'
import { OutputViolation, OutputWriter, checkOutPath, isScrypt, outputFor, peekFile, prepareDecrypt, readInput, safeSegments, shapeOfBytes, stanzaTypes, PasteScanner } from '../src/ops/decrypt-broker.ts'
import { BROKER_TAG, Violation, answerRequest, decryptPolicy, policyFor } from '../src/ops/broker.ts'
import type { BrokerTty } from '../src/ops/broker.ts'
import { ARMOR_END, PASTE_MAX, parseDecryptArgs } from '../src/decrypt-args.ts'
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
  assert.deepEqual(args(), { input: null, identity: null, out: null, stdout: false, list: false, only: null })
  assert.deepEqual(args('-', '--stdout'), { input: null, identity: null, out: null, stdout: true, list: false, only: null })
  assert.deepEqual(args('--identity', 'k', 'S.txt', '--only', 'a/b', '--out', 'x'), { input: 'S.txt', identity: 'k', out: 'x', stdout: false, list: false, only: 'a/b' })
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
  // the file appeared between the check and the write: never overwritten
  writeFileSync(dir('w4.txt'), 'theirs')
  throwsWith(() => new OutputWriter({ kind: 'file', path: dir('w4.txt') }).push(frame('a', 'ours')), 'vt.out-exists')
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
  // the O_EXCL backstop under the fold check: a file that appears inside the output directory is never overwritten
  const root = dir('m5-planted')
  const w = new OutputWriter({ kind: 'dir', path: root })
  w.push(frame('first.txt', 'first'))
  writeFileSync(join(root, 'second.txt'), 'planted')
  throwsWith(() => w.push(frame('second.txt', 'ours')), 'vt.out-exists')
  assert.equal(readFileSync(join(root, 'second.txt'), 'utf8'), 'planted', 'not overwritten')
  w.finish(false)
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

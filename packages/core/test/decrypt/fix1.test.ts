// vt decrypt core, lane E fix round 1 (review I-1, M-1, M-4, M-5, M-6): SYNTHETIC archives only.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { gzipSync } from 'node:zlib'
import * as api from '../../src/decrypt/index.ts'
import { extractAll, extractOne, listArchive, showPath } from '../../src/decrypt/index.ts'
import type { ArchiveSource } from '../../src/decrypt/index.ts'
import { TarError, scanTar } from '../../src/decrypt/tar.ts'
import { isRefusal } from '../../src/text/guard.ts'
import { paxRecords, tar, targz } from './fixtures.ts'

async function refused(p: Promise<unknown>, guard: string, re?: RegExp): Promise<void> {
  try { await p } catch (e) {
    assert.ok(isRefusal(e), `expected a Refusal ${guard}, got ${String(e)}`)
    assert.equal(e.guardId, guard, e.message)
    if (re) assert.match(e.message, re)
    return
  }
  assert.fail(`expected a refusal ${guard}`)
}
const paxPath = (path: string, content = 'x'): Array<[string, string | Uint8Array, string?]> => [['PaxHeader', paxRecords({ path }), 'x'], ['short', content]]

test('I-1: a path nested deeper than the depth cap is refused decrypt.size, before any per-prefix work', async () => {
  const deep = Array.from({ length: 2000 }, () => 'a').join('/') + '/f'            // 4003 bytes, 2001 segments: inside nameBytes
  const t = tar(paxPath(deep))
  assert.throws(() => scanTar(t), (e) => e instanceof TarError && e.kind === 'size' && /deep/.test(e.message))
  await refused(listArchive(new Uint8Array(gzipSync(t))), 'decrypt.size', /nested more than 32 levels/)
  assert.equal(api.ARCHIVE_DEPTH, 32)
  const ok = Array.from({ length: 32 }, () => 'd').join('/')                         // exactly the cap
  assert.equal(scanTar(tar(paxPath(ok))).length, 1)
  assert.throws(() => scanTar(tar(paxPath(ok + '/d'))), /deep/)
  assert.equal(scanTar(tar(paxPath('a/b/c/d')), { depth: 4 }).length, 1)
  assert.throws(() => scanTar(tar(paxPath('a/b/c/d')), { depth: 3 }), /deep/)
})

test('I-1: 10,000 entries on paths at the depth cap are scanned in linear time (a generous wall-clock bound)', () => {
  const seg = 'x'.repeat(31)
  const base = Array.from({ length: 31 }, () => seg).join('/')                      // 31 segments, ~1 KiB
  const files: Array<[string, string | Uint8Array, string?]> = []
  for (let i = 0; i < 10_000; i++) files.push(['PaxHeader', paxRecords({ path: `${base}/f${i}` }), 'x'], ['short', ''])
  const t = tar(files)
  const t0 = performance.now()
  const slots = scanTar(t)
  const ms = performance.now() - t0
  assert.equal(slots.length, 10_000)
  assert.ok(ms < 8000, `scan took ${ms} ms`)
})

test('I-1: the incremental scan still finds duplicates, file/dir conflicts and implied directories', () => {
  assert.throws(() => scanTar(tar([['a/b', 'x'], ['a/b', 'y']])), /more than once/)
  assert.throws(() => scanTar(tar([['a', 'x'], ['a/b', 'y']])), /"a" appears more than once|both a file and a directory/)
  assert.throws(() => scanTar(tar([['a/b', 'x'], ['a', 'y']])), /both a file and a directory/)
  assert.throws(() => scanTar(tar([['a/b/c', 'x'], ['a/b', 'y']])), /both a file and a directory/)
  assert.throws(() => scanTar(tar([['a/b', 'x'], ['a/b/', '', '5']])), /both a file and a directory/)
  assert.equal(scanTar(tar([['a/b', 'x'], ['a/c', 'y'], ['a/', '', '5'], ['c/b', 'z']])).length, 3)
})

test('M-1: an undefined / NaN / negative / fractional / non-number archive limit never means "no cap"', async () => {
  const many = targz(Array.from({ length: 50 }, (_, i) => [`f${i}`, 'x'] as [string, string]))
  assert.equal((await listArchive(many, { entries: 60 })).length, 50)
  await refused(listArchive(many, { entries: 10 }), 'decrypt.size')
  assert.equal((await listArchive(many, { entries: undefined })).length, 50, 'undefined = absent = the default cap')
  assert.equal((await listArchive(many, { entries: undefined, bytes: 1 << 20 })).length, 50)
  for (const bad of [NaN, -1, 1.5, Infinity, '10', null]) {
    for (const k of ['entries', 'bytes', 'meta', 'nameBytes', 'depth']) {
      await refused(listArchive(many, { [k]: bad } as never), 'decrypt.size', /limit/)
      await refused(extractOne(many, 'f1', { [k]: bad } as never), 'decrypt.size', /limit/)
    }
  }
  assert.throws(() => scanTar(tar({ a: 'x' }), { entries: NaN }), /limit "entries"/)
  assert.throws(() => scanTar(tar({ a: 'x' }), { bytes: NaN }), /limit "bytes"/)
})

test('M-4: listArchive returns exactly { path, size }, also for a foreign ArchiveSource', async () => {
  const rich = [{ path: 'a.txt', size: 3, bytes: new Uint8Array([1, 2, 3]), handle: { secret: 'synthetic' } }]
  const src: ArchiveSource = { name: 'v2', list: async () => rich, extract: async () => new Uint8Array(), all: async () => [] }
  const l = await listArchive(src)
  assert.deepEqual(l, [{ path: 'a.txt', size: 3 }])
  assert.deepEqual(Object.keys(l[0]).sort(), ['path', 'size'])
  const bad = (x: unknown): ArchiveSource => ({ name: 'v2', list: async () => x as never, extract: async () => new Uint8Array(), all: async () => [] })
  for (const x of [[{ path: 1, size: 1 }], [{ path: 'a', size: -1 }], [{ path: 'a', size: 1.5 }], [null], 'nope', [{ path: 'a' }]]) await refused(listArchive(bad(x)), 'decrypt.format')
})

test('M-5: core exports a display escaper for archive paths', () => {
  assert.equal(typeof showPath, 'function')
  assert.equal(showPath('a‮b\u0007c​'), 'a[U+202E]b[U+0007]c[U+200B]')
  assert.equal(showPath('x'.repeat(300)).length, 201)
})

test('M-6: strict mode refuses pax records that would change what system tar extracts; path and benign keys still work', async () => {
  const withRec = (rec: Record<string, string>): Uint8Array => targz([['PaxHeader', paxRecords(rec), 'x'], ['name.txt', 'data']])
  for (const rec of ([{ size: '2' }, { linkpath: 'x' }, { 'GNU.sparse.size': '5' }, { 'SCHILY.xattr.a': 'b' }, { path: 'p/q', size: '1' }, { type: 'x' }] as Array<Record<string, string>>)) {
    await refused(listArchive(withRec(rec)), 'decrypt.format', /would change what `tar` extracts/)
    await refused(extractAll(withRec(rec)), 'decrypt.format', /would change what/)
  }
  assert.deepEqual(await listArchive(withRec({ path: 'p/q.txt', mtime: '1.5', uid: '0', uname: 'u', comment: 'c', charset: 'ISO-IR 10646 2000 UTF-8' })), [{ path: 'p/q.txt', size: 4 }])
  // a global header is checked too, and a global `path` (which would rename every later entry) is refused
  const g = (rec: Record<string, string>): Uint8Array => targz([['GlobalHead', paxRecords(rec), 'g'], ['name.txt', 'data']])
  await refused(listArchive(g({ size: '9' })), 'decrypt.format', /would change/)
  await refused(listArchive(g({ path: 'zzz' })), 'decrypt.format', /would change/)
  assert.deepEqual(await listArchive(g({ mtime: '1' })), [{ path: 'name.txt', size: 4 }])
  // the page's lenient reader is unchanged: it ignores these records
  const { readTar } = await import('../../src/decrypt/tar.ts')
  assert.deepEqual(readTar(tar([['PaxHeader', paxRecords({ size: '2' }), 'x'], ['name.txt', 'data']])).files.map((f) => f.name), ['name.txt'])
})

// ── fix round 2 (re-review N-1..N-4): strict mode refuses whatever bsdtar / GNU tar could read differently ─────────────────────
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { readTar } from '../../src/decrypt/tar.ts'

const fix = (t: Buffer, edit: (b: Buffer) => void, at = 0): Buffer => {
  const b = Buffer.from(t); edit(b.subarray(at, at + 512))
  const h = b.subarray(at, at + 512)
  let sum = 0; for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : h[i]
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148)
  return b
}
const bad = (t: Buffer, re: RegExp): void => assert.throws(() => scanTar(t), (e) => e instanceof TarError && e.kind === 'format' && re.test(e.message))

test('N-1: a GNU-magic header with data where ustar keeps its prefix is refused; a clean GNU header and a real ustar prefix pass', () => {
  const gnu = fix(tar({ f: 'x' }), (h) => { h.write('ustar \0', 257); h.write(' \0', 263); h.write('evil', 345) })
  bad(gnu, /GNU-format header/)
  const clean = fix(tar({ f: 'x' }), (h) => { h.write('ustar \0', 257); h.write(' \0', 263) })
  assert.deepEqual(scanTar(clean).map((s) => s.path), ['f'])
  const v7 = fix(tar({ f: 'x' }), (h) => { h.fill(0, 257, 265); h.write('evil', 345) })
  bad(v7, /without ustar magic/)
  const pre = fix(tar({ f: 'x' }), (h) => { h.write('dir', 345) })
  assert.deepEqual(scanTar(pre).map((s) => s.path), ['dir/f'])
})

test('N-2: a directory or link with a nonzero size, and a regular file named with a trailing "/", are refused', () => {
  bad(tar([['d', 'x'.repeat(512), '5'], ['hidden', 'h']]), /nonzero size/)
  bad(tar([['d', 'x', '2'], ['hidden', 'h']]), /nonzero size/)
  bad(tar([['d/', 'hello']]), /ends in "\/"/)
  bad(tar([['PaxHeader', paxRecords({ path: 'e/' }), 'x'], ['s', 'hello']]), /ends in "\/"/)
  assert.deepEqual(scanTar(tar([['d/', '', '5'], ['d/f', 'x']])).map((s) => s.path), ['d/f'])
})

test('N-3: a GNU long name together with a pax path names one entry twice: refused (K and pax linkpath are refused already)', () => {
  bad(tar([['LongLink', 'one', 'L'], ['PaxHeader', paxRecords({ path: 'real' }), 'x'], ['f', 'data']]), /named twice/)
  bad(tar([['PaxHeader', paxRecords({ path: 'real' }), 'x'], ['LongLink', 'one', 'L'], ['f', 'data']]), /named twice/)
  assert.deepEqual(scanTar(tar([['LongLink', 'one', 'L'], ['f', 'data']])).map((s) => s.path), ['one'])
  bad(tar([['LongLink', 'one', 'K'], ['f', 'data']]), /type K/)
})

test('N-4: size and checksum fields must be octal digits then NUL / space only (NBSP, newline, leading blanks refused)', () => {
  for (const pad of ['0000005\n', ' 0000005', ' 0000005\0', '00000 5\0']) {
    const t = fix(tar({ f: 'hello' }), (h) => { h.fill(0, 124, 136); h.write(pad, 124) })
    bad(t, /padding that tar does not write/)
  }
  const sp = fix(tar({ f: 'hello' }), (h) => { h.fill(0, 124, 136); h.write('00000000005 ', 124) })
  assert.equal(scanTar(sp)[0].size, 5)
  const cks = fix(tar({ f: 'hello' }), () => {}); cks.write(' ', 148); // leading blank in the checksum field
  bad(cks, /padding|checksum/)
  assert.equal(readTar(fix(tar({ f: 'hello' }), (h) => { h.fill(0, 124, 136); h.write('0000005\n', 124) })).files.length, 1, 'the page\'s lenient reader is unchanged')
})

test('sealer-shaped archives (bsdtar --format ustar, the sealer\'s scrub flags, and a default bsdtar archive) still scan strictly', () => {
  const d = mkdtempSync(join(tmpdir(), 'vt-e2-')); const src = join(d, 'src')
  try {
    mkdirSync(join(src, 'items'), { recursive: true }); mkdirSync(join(src, 'files/ab12'), { recursive: true })
    writeFileSync(join(src, 'items/aaaa.json'), '{"synthetic":1}\n'); writeFileSync(join(src, 'files/ab12/f1'), 'synthetic\n'); writeFileSync(join(src, 'MANIFEST.csv'), 'id\n')
    writeFileSync(join(src, 'long-' + 'n'.repeat(120) + '.txt'), 'l')
    const list = ['items/aaaa.json', 'files/ab12/f1', 'MANIFEST.csv', 'long-' + 'n'.repeat(120) + '.txt']
    const scrub = '--format ustar --no-mac-metadata --no-xattrs --no-acls --no-fflags --uid 0 --gid 0 --uname nobody --gname nobody'.split(' ')
    for (const [name, flags] of [['u.tar', scrub], ['d.tar', []]] as Array<[string, string[]]>) {
      try { execFileSync('/usr/bin/bsdtar', ['-cf', join(d, name), ...flags, '-C', src, ...list], { stdio: 'ignore' }) } catch { execFileSync('/usr/bin/bsdtar', ['-cf', join(d, name), ...flags.filter((f) => !f.startsWith('--no-mac'))  , '-C', src, ...list], { stdio: 'ignore' }) }
      const t = readFileSync(join(d, name))
      try { const paths = scanTar(t).map((s) => s.path.replace(/^\.\//, '')).sort(); assert.ok(paths.includes('items/aaaa.json') && paths.includes('files/ab12/f1'), name) }
      catch (e) { if (name === 'd.tar' && e instanceof TarError && /pax record/.test(e.message)) continue; throw e }   // default format may carry pax creationtime: refused by M-6 by design
    }
  } finally { rmSync(d, { recursive: true, force: true }) }
})

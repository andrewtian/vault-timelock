// vt decrypt core (lane E): per-file access to a decrypted archive — listArchive / extractOne / extractAll over a tar.gz, STRICT:
// traversal, absolute, symlink, hard-link, device, duplicate and file/directory-conflict entries refuse the whole archive; caps refuse
// too. The list never carries file bytes. SYNTHETIC archives, made here.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { gzipSync } from 'node:zlib'
import { ARCHIVE_LIMITS, extractAll, extractOne, listArchive, tarGzSource } from '../../src/decrypt/index.ts'
import type { ArchiveSource } from '../../src/decrypt/index.ts'
import { isRefusal } from '../../src/text/guard.ts'
import { pax, tar, targz, text } from './fixtures.ts'

async function refused(p: Promise<unknown>, guard: string, re?: RegExp): Promise<string> {
  try { await p } catch (e) {
    assert.ok(isRefusal(e), `expected a Refusal ${guard}, got ${String(e)}`)
    assert.equal(e.guardId, guard, e.message)
    if (re) assert.match(e.message, re)
    return e.message
  }
  assert.fail(`expected a refusal ${guard}, nothing was refused`)
}
const gz = (b: Buffer): Uint8Array => new Uint8Array(gzipSync(b))

const FILES: Array<[string, string, string?]> = [['items/', '', '5'], ['items/aaaa.json', '{"synthetic":1}\n'], ['files/x1/', '', '5'], ['files/x1/note.txt', 'synthetic note\n'], ['MANIFEST.csv', 'id,sha\n']]

test('list: path + size of every regular file, in archive order, directories left out; never any bytes', async () => {
  const a = targz(FILES)
  const list = await listArchive(a)
  assert.deepEqual(list, [{ path: 'items/aaaa.json', size: 16 }, { path: 'files/x1/note.txt', size: 15 }, { path: 'MANIFEST.csv', size: 7 }])
  for (const e of list) assert.deepEqual(Object.keys(e).sort(), ['path', 'size'], 'only the path and the size')
  assert.ok(!JSON.stringify(list).includes('synthetic'), 'no file content in the list')
  const src = tarGzSource('vault.tar.gz', a)
  assert.equal(src.name, 'vault.tar.gz')
  assert.deepEqual(await src.list(), list)
})

test('extractOne: exactly that file\'s bytes; extractAll: every file once; a path not in the archive is decrypt.format', async () => {
  const a = targz(FILES)
  assert.equal(text(await extractOne(a, 'files/x1/note.txt')), 'synthetic note\n')
  assert.equal(text(await extractOne(a, 'MANIFEST.csv')), 'id,sha\n')
  assert.deepEqual((await extractAll(a)).map((f) => [f.path, f.size, text(f.bytes)]), [
    ['items/aaaa.json', 16, '{"synthetic":1}\n'], ['files/x1/note.txt', 15, 'synthetic note\n'], ['MANIFEST.csv', 7, 'id,sha\n']])
  for (const p of ['nope', 'items', 'items/', './MANIFEST.csv', 'items/aaaa.json/']) await refused(extractOne(a, p), 'decrypt.format', /holds no file/)
  await refused(extractOne(a, 42 as unknown as string), 'decrypt.format', /holds no file/)
  // a copy each time: changing a returned buffer changes nothing
  const one = await extractOne(a, 'MANIFEST.csv'); one.fill(0)
  assert.equal(text(await extractOne(a, 'MANIFEST.csv')), 'id,sha\n')
})

test('hostile entries refuse the WHOLE archive (decrypt.format): traversal, absolute, ".", empty segments, backslash, controls', async () => {
  for (const name of ['../evil', 'ok/../../evil', '/abs', '/etc/x', 'a/./b', './a', 'a//b', 'back\\slash', 'ctl\u0001x', 'esc\u001b[31mred', 'del\u007f', 'c1\u0085x', '.', '..']) {
    const a = targz([['ok.txt', 'fine'], [name, 'x']])
    for (const op of [() => listArchive(a), () => extractOne(a, 'ok.txt'), () => extractAll(a)]) await refused(op(), 'decrypt.format', /unsafe entry path/)
  }
  // a pax path record that traverses, under a harmless header name
  await refused(listArchive(gz(tar([['PaxHeader', pax('../../evil'), 'x'], ['harmless', 'x']]))), 'decrypt.format', /unsafe entry path/)
  // a GNU long name that is absolute
  await refused(listArchive(gz(tar([['././@LongLink', '/abs/long\0', 'L'], ['harmless', 'x']]))), 'decrypt.format', /unsafe entry path/)
  // a name that is not UTF-8
  const raw = Buffer.from(tar({ abcd: 'x' })); raw[1] = 0xff
  let sum = 0; for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : raw[i]
  raw.write(sum.toString(8).padStart(6, '0') + '\0 ', 148)
  await refused(listArchive(gz(raw)), 'decrypt.format', /not valid UTF-8/)
  // the refusal shows a control character written out, never raw
  const m = await refused(listArchive(targz([['esc\u001b]0;title\u0007', 'x']])), 'decrypt.format')
  assert.ok(!/[\u0000-\u001f\u007f]/.test(m) && m.includes('[U+001B]'), m)
})

test('symlinks, hard links, devices, FIFOs and other types refuse the whole archive (decrypt.format)', async () => {
  const want: Record<string, RegExp> = { 2: /symbolic link/, 1: /hard link/, 3: /type 3/, 4: /type 4/, 6: /type 6/, 7: /./, S: /type S/ }
  for (const [type, re] of Object.entries(want)) {
    const a = targz([['ok.txt', 'fine'], ['link', '', type]])
    if (type === '7') { assert.deepEqual((await listArchive(a)).map((e) => e.path), ['ok.txt', 'link'], 'type 7 (contiguous) is a regular file'); continue }
    await refused(listArchive(a), 'decrypt.format', re)
    await refused(extractOne(a, 'ok.txt'), 'decrypt.format', re)
  }
})

test('duplicates and file/directory conflicts refuse the whole archive (decrypt.format)', async () => {
  const cases: Array<Array<[string, string, string?]>> = [
    [['a', '1'], ['a', '2']],                       // the same file twice
    [['d/a', '1'], ['d/a', '2']],
    [['a', '1'], ['a/b', '2']],                     // a file, then a file under it
    [['a/b', '1'], ['a', '2']],                     // a file under a, then a as a file
    [['a', '1'], ['a/', '', '5']],                  // a file, then a directory of the same path
    [['a/', '', '5'], ['a', '2']],                  // a directory, then a file of the same path
    // (a regular file named 'a/' is refused by its own rule, see fix1.test.ts N-2)
  ]
  for (const c of cases) {
    const a = targz(c)
    await refused(listArchive(a), 'decrypt.format', /more than once, or is both a file and a directory/)
    await refused(extractAll(a), 'decrypt.format', /more than once/)
  }
  // a directory named twice, or after its files, is no conflict
  assert.deepEqual((await listArchive(targz([['d/', '', '5'], ['d/x', '1'], ['d/', '', '5']]))).map((e) => e.path), ['d/x'])
})

test('caps are decrypt.size: expanded bytes, entry count, path length', async () => {
  await refused(listArchive(gz(Buffer.from(tar({ big: 'x'.repeat(5000) }))), { bytes: 4096 }), 'decrypt.size', /expands to more than 4096 bytes/)
  assert.equal((await listArchive(gz(Buffer.from(tar({ big: 'x'.repeat(5000) }))), { bytes: 8192 })).length, 1, 'within the bound it lists')
  await refused(listArchive(targz({ a: '1', b: '2', c: '3' }), { entries: 2 }), 'decrypt.size', /more than 2 files/)
  await refused(listArchive(gz(tar([['PaxHeader', pax('d/' + 'n'.repeat(5000)), 'x'], ['a', 'd']]))), 'decrypt.size', /longer than 4096 bytes/)
  await refused(tarGzSource('v.tar.gz', targz({ a: '1', b: '2' }), { entries: 1 }).all(), 'decrypt.size', /v\.tar\.gz/)
  assert.equal(ARCHIVE_LIMITS.bytes, 64 * 1024 * 1024)
  assert.equal((await listArchive(targz({ a: '1', b: '2' }), { entries: 2 })).length, 2)
})

test('not a tar.gz is decrypt.format: plain bytes, a gzip of no tar, a damaged checksum, a cut-off member, trailing junk', async () => {
  await refused(listArchive(new TextEncoder().encode('synthetic plain text')), 'decrypt.format', /not a gzip archive/)
  await refused(listArchive(gz(Buffer.from('synthetic: gzip of no tar'))), 'decrypt.format', /too short|checksum|two empty blocks/)
  const t = Buffer.from(tar({ f: 'x' })); t[0] ^= 1
  await refused(listArchive(gz(t)), 'decrypt.format', /checksum/)
  const g = gz(Buffer.from(tar({ f: 'x' })))
  await refused(listArchive(g.subarray(0, g.length - 20)), 'decrypt.format', /exactly one complete gzip member/)
  const junk = new Uint8Array([...g, 1, 2, 3])
  await refused(listArchive(junk), 'decrypt.format', /exactly one complete gzip member/)
  await refused(listArchive(null as unknown as Uint8Array), 'decrypt.format', /not an archive/)
})

test('any ArchiveSource is accepted (the seam a SEALED v2 index + blocks source implements)', async () => {
  const src: ArchiveSource = {
    name: 'synthetic-v2',
    list: async () => [{ path: 'b0001', size: 3 }],
    extract: async (p) => { assert.equal(p, 'b0001'); return new Uint8Array([1, 2, 3]) },
    all: async () => [{ path: 'b0001', size: 3, bytes: new Uint8Array([1, 2, 3]) }],
  }
  assert.deepEqual(await listArchive(src), [{ path: 'b0001', size: 3 }])
  assert.deepEqual([...await extractOne(src, 'b0001')], [1, 2, 3])
  assert.equal((await extractAll(src)).length, 1)
})

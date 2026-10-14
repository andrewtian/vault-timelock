// The tar.gz reader MOVED from web/src/lib/tar.js (vt decrypt addendum): its page tests (web/test/tar.test.js, W7 / M-5 / F13-1), ported
// to node:test against the core module. web/test/tar.test.js still runs them through the page's import. SYNTHETIC archives only.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'
import { TAR_LIMITS, TarError, crc32, gunzip, isGzip, readTar, readTarGz } from '../../src/decrypt/tar.ts'
import { pax, tar, targz } from './fixtures.ts'

const files = { 'a/b.txt': 'one', 'c.bin': new Uint8Array([0, 1, 2, 255]) }

test('a tar.gz is read back, byte for byte', async () => {
  const r = await readTarGz(targz(files))
  assert.deepEqual(r.files.map((f) => f.name), ['a/b.txt', 'c.bin'])
  assert.equal(Buffer.from(r.files[0].bytes).toString(), 'one')
  assert.deepEqual([...r.files[1].bytes], [0, 1, 2, 255])
  assert.equal(isGzip(targz(files)), true)
})

test('unsafe names are skipped and said so, never rewritten (the page\'s lenient reader)', () => {
  const r = readTar(tar({ '../evil': 'x', '/abs': 'y', 'ok/..': 'z', 'ok/file': 'f', 'back\\slash': 'q' }))
  assert.deepEqual(r.files.map((f) => f.name), ['ok/file'])
  assert.deepEqual(r.skipped.map((s) => s.name).sort(), ['../evil', '/abs', 'back\\slash', 'ok/..'].sort())
})

test('a link or device entry is skipped; a wrong checksum or a short archive is refused', () => {
  const t = Buffer.from(tar({ f: 'x' }))
  const link = Buffer.from(t); link.write('2', 156)
  let sum = 0; for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : link[i]
  link.write(sum.toString(8).padStart(6, '0') + '\0 ', 148)
  assert.equal(readTar(link).skipped.length, 1)
  const bad = Buffer.from(t); bad[0] ^= 1
  assert.throws(() => readTar(bad), /checksum/)
  assert.throws(() => readTar(t.subarray(0, 100)), /too short/)
  assert.throws(() => readTar(t.subarray(0, 512 + 512)), /two empty blocks|past the end/)
})

test('caps: an archive that expands too far, or holds too many entries, is refused (TarError size)', async () => {
  await assert.rejects(gunzip(gzipSync(Buffer.alloc(100_000)), 1000), (e) => e instanceof TarError && e.kind === 'size' && /more than 1000/.test(e.message))
  assert.throws(() => readTar(tar({ a: 'x', b: 'y' }), { ...TAR_LIMITS, entries: 1 }), /more than the page will restore/)
  assert.throws(() => readTar(tar({ a: 'xxxx' }), { ...TAR_LIMITS, bytes: 3 }), /more than the page will restore/)
})

test('M-5: a pax path with non-ASCII characters is read by bytes, not UTF-16 units', () => {
  const name = 'dir/日本語-é-😀.txt'
  const r = readTar(tar([['PaxHeader', pax(name), 'x'], ['short', 'data']]))
  assert.deepEqual(r.files.map((f) => f.name), [name])
})

test('M-5: a malformed or oversized pax record, an oversized name block and a very long name are refused or skipped, clearly', () => {
  const bad = Buffer.from('99999 path=x\n')
  assert.throws(() => readTar(tar([['PaxHeader', bad, 'x'], ['a', 'd']])), /pax record is malformed or too long/)
  assert.throws(() => readTar(tar([['PaxHeader', pax('x'.repeat(200)), 'x'], ['a', 'd']]), { ...TAR_LIMITS, meta: 100 }), /longer than 100 bytes; refused/)
  assert.throws(() => readTar(tar([['LongLink', Buffer.alloc(200, 97), 'L'], ['a', 'd']]), { ...TAR_LIMITS, meta: 100 }), /longer than 100 bytes; refused/)
  const r = readTar(tar([['PaxHeader', pax('d/' + 'n'.repeat(5000)), 'x'], ['a', 'd']]))
  assert.deepEqual(r.files, [])
  assert.match(r.skipped[0].why, /name longer than 4096 bytes/)
})

test('M-5: the default ceiling is 64 MiB, and the refusal says so in plain words', async () => {
  assert.equal(TAR_LIMITS.bytes, 64 * 1024 * 1024)
  await assert.rejects(gunzip(gzipSync(Buffer.alloc(3 * 1048576)), 2 * 1048576), /more than 2 MiB, more than this page will hold in memory/)
})

// F13-1: the sealer's `tar -czf` output is padded with zero bytes to the 10240-byte tar record. The archive here is made exactly
// like the sealer's (tar -czf, default blocking, from a temp dir of synthetic files) and padded the same way.
function sealerLike(): { raw: Buffer; padded: Buffer } {
  const d = mkdtempSync(join(tmpdir(), 'vt-decrypt-tar-'))
  try {
    mkdirSync(join(d, 'src'))
    writeFileSync(join(d, 'src', 'note.txt'), 'synthetic note\n')
    writeFileSync(join(d, 'src', 'data.bin'), Buffer.from([0, 1, 2, 0, 0, 255]))
    execFileSync('tar', ['-czf', join(d, 'secret.tar.gz'), '-C', join(d, 'src'), 'note.txt', 'data.bin'], { env: { ...process.env, COPYFILE_DISABLE: '1' } })
    const raw = readFileSync(join(d, 'secret.tar.gz'))
    const padded = Buffer.concat([raw, Buffer.alloc((10240 - (raw.length % 10240)) % 10240 || 10240)])
    return { raw, padded }
  } finally { rmSync(d, { recursive: true, force: true }) }
}

test('F13-1: a tar.gz padded with zeros to the tar record unpacks and lists its files', async () => {
  const { raw, padded } = sealerLike()
  assert.equal(padded.length % 10240, 0); assert.ok(padded.length > raw.length)
  for (const bytes of [raw, padded]) {
    const r = await readTarGz(new Uint8Array(bytes))
    assert.deepEqual(r.files.map((f) => f.name), ['note.txt', 'data.bin'])
    assert.equal(Buffer.from(r.files[0].bytes).toString(), 'synthetic note\n')
    assert.deepEqual([...r.files[1].bytes], [0, 1, 2, 0, 0, 255])
  }
})

test('F13-1: the member\'s own trailer may end in zero bytes and is not cut', async () => {
  // ISIZE is little-endian: a content of 256 bytes has ISIZE 00 01 00 00, so the trailer ends in two zeros
  const g = gzipSync(Buffer.alloc(256, 7))
  assert.deepEqual([...g.subarray(-2)], [0, 0])
  const out = await gunzip(new Uint8Array(Buffer.concat([g, Buffer.alloc(5000)])))
  assert.equal(out.length, 256)
  assert.equal(crc32(new Uint8Array([1, 2, 3])), 0x55bc801d)
})

test('F13-1: non-zero trailing data, a second member, a bad checksum or a cut-off member are refused', async () => {
  const { padded } = sealerLike()
  const junk = Buffer.from(padded); junk[junk.length - 3] = 1
  await assert.rejects(readTarGz(new Uint8Array(junk)), /exactly one/)
  const junk2 = Buffer.concat([padded.subarray(0, 200), Buffer.from('JUNK'), Buffer.alloc(100)])
  await assert.rejects(readTarGz(new Uint8Array(junk2)), /exactly one/)
  const second = Buffer.concat([gzipSync(Buffer.from(tar({ a: 'x' }))), gzipSync(Buffer.from(tar({ b: 'y' })))])
  await assert.rejects(readTarGz(new Uint8Array(second)), /exactly one/)
  const g = Buffer.from(gzipSync(Buffer.from(tar({ a: 'x' }))))
  const badCrc = Buffer.from(g); badCrc[badCrc.length - 8] ^= 1
  await assert.rejects(readTarGz(new Uint8Array(badCrc)), /exactly one/)
  const badSize = Buffer.from(g); badSize[badSize.length - 4] ^= 1
  await assert.rejects(readTarGz(new Uint8Array(badSize)), /exactly one/)
  await assert.rejects(readTarGz(new Uint8Array(g.subarray(0, g.length - 20))), /exactly one/)
  await assert.rejects(readTarGz(new Uint8Array(Buffer.concat([g.subarray(0, g.length - 20), Buffer.alloc(9000)]))), /exactly one/)
})

test('the strict and the lenient reader read the same sealer-made archive the same way', async () => {
  const { padded } = sealerLike()
  const { listArchive, extractAll } = await import('../../src/decrypt/index.ts')
  const lenient = await readTarGz(new Uint8Array(padded))
  assert.deepEqual(await listArchive(new Uint8Array(padded)), lenient.files.map((f) => ({ path: f.name, size: f.bytes.length })))
  assert.deepEqual((await extractAll(new Uint8Array(padded))).map((f) => [...f.bytes]), lenient.files.map((f) => [...f.bytes]))
})

import { test, expect } from 'vitest'
import { gzipSync } from 'node:zlib'
import { TAR_LIMITS, gunzip, isGzip, readTar, readTarGz } from '../src/lib/tar.js'
import { tar, targz } from './open-fixtures.js'

const files = { 'a/b.txt': 'one', 'c.bin': new Uint8Array([0, 1, 2, 255]) }

test('a tar.gz is read back, byte for byte', async () => {
  const r = await readTarGz(targz(files))
  expect(r.files.map((f) => f.name)).toEqual(['a/b.txt', 'c.bin'])
  expect(Buffer.from(r.files[0].bytes).toString()).toBe('one')
  expect([...r.files[1].bytes]).toEqual([0, 1, 2, 255])
  expect(isGzip(targz(files))).toBe(true)
})

test('unsafe names are skipped and said so, never rewritten', () => {
  const r = readTar(tar({ '../evil': 'x', '/abs': 'y', 'ok/..': 'z', 'ok/file': 'f', 'back\\slash': 'q' }))
  expect(r.files.map((f) => f.name)).toEqual(['ok/file'])
  expect(r.skipped.map((s) => s.name).sort()).toEqual(['../evil', '/abs', 'back\\slash', 'ok/..'].sort())
})

test('a link or device entry is skipped; a wrong checksum or a short archive is refused', () => {
  const t = Buffer.from(tar({ f: 'x' }))
  const link = Buffer.from(t); link.write('2', 156)
  let sum = 0; for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : link[i]
  link.write(sum.toString(8).padStart(6, '0') + '\0 ', 148)
  expect(readTar(link).skipped).toHaveLength(1)
  const bad = Buffer.from(t); bad[0] ^= 1
  expect(() => readTar(bad)).toThrow(/checksum/)
  expect(() => readTar(t.subarray(0, 100))).toThrow(/too short/)
  expect(() => readTar(t.subarray(0, 512 + 512))).toThrow(/two empty blocks|past the end/)
})

test('caps: an archive that expands too far, or holds too many entries, is refused', async () => {
  await expect(gunzip(gzipSync(Buffer.alloc(100_000)), 1000)).rejects.toThrow(/more than 1000/)
  expect(() => readTar(tar({ a: 'x', b: 'y' }), { ...TAR_LIMITS, entries: 1 })).toThrow(/more than the page will restore/)
  expect(() => readTar(tar({ a: 'xxxx' }), { ...TAR_LIMITS, bytes: 3 })).toThrow(/more than the page will restore/)
})

// pax extended header: one `path` record whose length counts BYTES
const pax = (path) => {
  const body = Buffer.from(` path=${path}\n`)
  let len = body.length + 1
  while (String(len).length + body.length !== len) len = String(len).length + body.length
  return Buffer.concat([Buffer.from(String(len)), body])
}

test('M-5: a pax path with non-ASCII characters is read by bytes, not UTF-16 units', () => {
  const name = 'dir/日本語-é-😀.txt'
  const r = readTar(tar([['PaxHeader', pax(name), 'x'], ['short', 'data']]))
  expect(r.files.map((f) => f.name)).toEqual([name])
})

test('M-5: a malformed or oversized pax record, an oversized name block and a very long name are refused or skipped, clearly', () => {
  const bad = Buffer.from('99999 path=x\n')
  expect(() => readTar(tar([['PaxHeader', bad, 'x'], ['a', 'd']]))).toThrow(/pax record is malformed or too long/)
  expect(() => readTar(tar([['PaxHeader', pax('x'.repeat(200)), 'x'], ['a', 'd']]), { ...TAR_LIMITS, meta: 100 })).toThrow(/longer than 100 bytes; refused/)
  expect(() => readTar(tar([['LongLink', Buffer.alloc(200, 97), 'L'], ['a', 'd']]), { ...TAR_LIMITS, meta: 100 })).toThrow(/longer than 100 bytes; refused/)
  const r = readTar(tar([['PaxHeader', pax('d/' + 'n'.repeat(5000)), 'x'], ['a', 'd']]))
  expect(r.files).toEqual([])
  expect(r.skipped[0].why).toMatch(/name longer than 4096 bytes/)
})

test('M-5: the default ceiling is 64 MiB, and the refusal says so in plain words', async () => {
  expect(TAR_LIMITS.bytes).toBe(64 * 1024 * 1024)
  await expect(gunzip(gzipSync(Buffer.alloc(3 * 1048576)), 2 * 1048576)).rejects.toThrow(/more than 2 MiB, more than this page will hold in memory/)
})

// F13-1: the sealer's `tar -czf` output is padded with zero bytes to the 10240-byte tar record. The archive here is made exactly
// like the sealer's (tar -czf, default blocking, from a temp dir of synthetic files) and padded the same way.
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { crc32 } from '../src/lib/tar.js'

function sealerLike() {
  const d = mkdtempSync(join(tmpdir(), 'w7b-tar-'))
  try {
    mkdirSync(join(d, 'src'))
    writeFileSync(join(d, 'src', 'note.txt'), 'synthetic note\n')
    writeFileSync(join(d, 'src', 'data.bin'), Buffer.from([0, 1, 2, 0, 0, 255]))
    execFileSync('tar', ['-czf', join(d, 'secret.tar.gz'), '-C', join(d, 'src'), 'note.txt', 'data.bin'])
    const raw = readFileSync(join(d, 'secret.tar.gz'))
    const padded = Buffer.concat([raw, Buffer.alloc((10240 - (raw.length % 10240)) % 10240 || 10240)])
    return { raw, padded }
  } finally { rmSync(d, { recursive: true, force: true }) }
}

test('F13-1: a tar.gz padded with zeros to the tar record unpacks and lists its files', async () => {
  const { raw, padded } = sealerLike()
  expect(padded.length % 10240).toBe(0); expect(padded.length).toBeGreaterThan(raw.length)
  for (const bytes of [raw, padded]) {
    const r = await readTarGz(new Uint8Array(bytes))
    expect(r.files.map((f) => f.name)).toEqual(['note.txt', 'data.bin'])
    expect(Buffer.from(r.files[0].bytes).toString()).toBe('synthetic note\n')
    expect([...r.files[1].bytes]).toEqual([0, 1, 2, 0, 0, 255])
  }
})

test('F13-1: the member\'s own trailer may end in zero bytes and is not cut', async () => {
  // ISIZE is little-endian: a content of 256 bytes has ISIZE 00 01 00 00, so the trailer ends in two zeros
  const g = gzipSync(Buffer.alloc(256, 7))
  expect([...g.subarray(-2)]).toEqual([0, 0])
  const out = await gunzip(new Uint8Array(Buffer.concat([g, Buffer.alloc(5000)])))
  expect(out.length).toBe(256)
  expect(crc32(new Uint8Array([1, 2, 3]))).toBe(0x55bc801d)
})

test('F13-1: non-zero trailing data, a second member, a bad checksum or a cut-off member are refused', async () => {
  const { padded } = sealerLike()
  const junk = Buffer.from(padded); junk[junk.length - 3] = 1
  await expect(readTarGz(new Uint8Array(junk))).rejects.toThrow(/exactly one/)
  const junk2 = Buffer.concat([padded.subarray(0, 200), Buffer.from('JUNK'), Buffer.alloc(100)])
  await expect(readTarGz(new Uint8Array(junk2))).rejects.toThrow(/exactly one/)
  const second = Buffer.concat([gzipSync(Buffer.from(tar({ a: 'x' }))), gzipSync(Buffer.from(tar({ b: 'y' })))])
  await expect(readTarGz(new Uint8Array(second))).rejects.toThrow(/exactly one/)
  const g = Buffer.from(gzipSync(Buffer.from(tar({ a: 'x' }))))
  const badCrc = Buffer.from(g); badCrc[badCrc.length - 8] ^= 1
  await expect(readTarGz(new Uint8Array(badCrc))).rejects.toThrow(/exactly one/)
  const badSize = Buffer.from(g); badSize[badSize.length - 4] ^= 1
  await expect(readTarGz(new Uint8Array(badSize))).rejects.toThrow(/exactly one/)
  await expect(readTarGz(new Uint8Array(g.subarray(0, g.length - 20)))).rejects.toThrow(/exactly one/)
  await expect(readTarGz(new Uint8Array(Buffer.concat([g.subarray(0, g.length - 20), Buffer.alloc(9000)])))).rejects.toThrow(/exactly one/)
})

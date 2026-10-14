// A minimal tar.gz reader for Open (W7). What a restored vault or secret is: `tar -czf` output (ustar, GNU long names and
// pax `path` records). Nothing is written anywhere: the entries come back as bytes in memory.
//   · regular files only; directories are skipped; links, devices and every other type are listed in `skipped`;
//   · a name that is absolute, holds a `..` segment, a backslash or a NUL is refused (`skipped`), never rewritten;
//   · caps: total output bytes and entry count, so a hostile archive cannot fill the tab's memory;
//   · the header checksum of every block is verified.
// Memory: the gzip input + the joined tar + a copy of every file ≈ 3x `bytes` at the peak, so the cap is 64 MiB of expanded data
// (≈ 200 MiB in the tab); a bigger archive is refused with a clear message and offered as the archive itself.
// A name, a pax record or a GNU long-name block is at most `meta` bytes, a name at most `nameBytes`.
export const TAR_LIMITS = { bytes: 64 * 1024 * 1024, entries: 10_000, meta: 64 * 1024, nameBytes: 4096 }

const dec = new TextDecoder('utf-8', { fatal: true })
const text = (b, a, n) => { let e = a; while (e < a + n && b[e] !== 0) e++; return dec.decode(b.subarray(a, e)) }
const octal = (b, a, n) => {
  const s = text(b, a, n).trim()
  if (s === '') return 0
  if (!/^[0-7]+$/.test(s)) throw new Error('tar: a size or checksum field is not octal')
  return parseInt(s, 8)
}

export function isGzip(bytes) { return bytes.length > 2 && bytes[0] === 0x1f && bytes[1] === 0x8b }

// F13-1: the sealer's `tar -czf` pads its output with zero bytes to the 10240-byte tar record. gzip and tar ignore that padding;
// DecompressionStream rejects it ("junk after the end"). So: exactly ONE gzip member is decompressed, and the bytes after it are
// accepted only when they are all 0x00. The member's end is found without parsing deflate: the trailing zero run Z may hold up to
// 8 bytes of the member's own trailer (CRC32 + ISIZE can end in zeros), so the end is one of the 9 positions len-Z .. len-Z+8;
// DecompressionStream accepts only the exact one (it refuses junk after the end and a cut-off member). The trailer is then
// checked here as well (CRC32 and ISIZE of the output), which also refuses a second member (its trailer would not match the
// joined output). Anything else is an error, and Open falls back to offering the archive itself.
const CRC_TABLE = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0 } return t })()
export function crc32(b) { let c = 0xffffffff; for (let i = 0; i < b.length; i++) c = CRC_TABLE[(c ^ b[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0 }
const BAD_MEMBER = 'gzip: not exactly one complete gzip member (a cut-off member, a second member, a wrong checksum, or trailing bytes that are not zero padding)'

async function inflateMember(bytes, cap) {
  const ds = new DecompressionStream('gzip')
  const w = ds.writable.getWriter()
  w.write(bytes).catch(() => {}); w.close().catch(() => {})
  const r = ds.readable.getReader()
  const parts = []
  let n = 0
  try {
    for (;;) {
      const { done, value } = await r.read()
      if (done) break
      n += value.length
      if (n > cap) { await r.cancel().catch(() => {}); const e = new Error(`tar: the archive expands to more than ${cap >= 1048576 ? `${Math.floor(cap / 1048576)} MiB` : `${cap} bytes`}, more than this page will hold in memory`); e.cap = true; throw e }
      parts.push(value)
    }
  } catch (e) { if (e.cap) throw e; return null }
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) { out.set(p, o); o += p.length }
  return out
}

export async function gunzip(bytes, cap = TAR_LIMITS.bytes) {
  let z = 0
  while (z < bytes.length && bytes[bytes.length - 1 - z] === 0) z++
  const base = bytes.length - z
  for (let e = base; e <= Math.min(bytes.length, base + 8); e++) {
    if (e < 18) continue                                           // a member is at least a 10-byte header and an 8-byte trailer
    const out = await inflateMember(bytes.subarray(0, e), cap)
    if (out === null) continue
    const dv = new DataView(bytes.buffer, bytes.byteOffset + e - 8, 8)
    if (dv.getUint32(0, true) === crc32(out) && dv.getUint32(4, true) === (out.length >>> 0)) return out
    out.fill(0)
  }
  throw new Error(BAD_MEMBER)
}

const safeName = (n) => n !== '' && !n.startsWith('/') && !/[\\\0]/.test(n) && !n.split('/').includes('..')

// -> { files: [{ name, bytes }], skipped: [{ name, why }] }; throws Error when the bytes are not a tar archive.
export function readTar(tar, limits = TAR_LIMITS) {
  const meta = limits.meta ?? TAR_LIMITS.meta, nameBytes = limits.nameBytes ?? TAR_LIMITS.nameBytes
  const files = [], skipped = []
  let pos = 0, longName = null, pax = null, total = 0
  const zero = (a) => { for (let i = 0; i < 512; i++) if (tar[a + i] !== 0) return false; return true }
  if (tar.length < 512) throw new Error('tar: too short to be a tar archive')
  for (;;) {
    if (pos + 512 > tar.length) throw new Error('tar: the archive ends without its two empty blocks')
    if (zero(pos)) break
    let sum = 0
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : tar[pos + i]
    if (sum !== octal(tar, pos + 148, 8)) throw new Error('tar: a header checksum is wrong (not a tar archive, or damaged)')
    const type = String.fromCharCode(tar[pos + 156] || 48)
    const size = octal(tar, pos + 124, 12)
    const magic = text(tar, pos + 257, 5)
    let name = text(tar, pos, 100)
    if (magic === 'ustar') { const pre = text(tar, pos + 345, 155); if (pre) name = `${pre}/${name}` }
    const start = pos + 512, end = start + size
    if (end > tar.length) throw new Error('tar: an entry runs past the end of the archive')
    pos = start + Math.ceil(size / 512) * 512
    const body = tar.subarray(start, end)
    if ((type === 'L' || type === 'x' || type === 'g') && size > meta) throw new Error(`tar: a name or extended header is longer than ${meta} bytes; refused`)
    if (type === 'L') { longName = dec.decode(body).replace(/\0+$/, ''); continue }
    if (type === 'x') {
      pax = {}
      // records are `<len> <key>=<value>\n`, <len> in BYTES (the whole record, digits and newline included): parse bytes, not UTF-16 units
      for (let i = 0; i < body.length;) {
        let sp = i
        while (sp < body.length && body[sp] !== 0x20 && sp - i < 8) sp++
        const len = sp < body.length && body[sp] === 0x20 && /^[0-9]+$/.test(new TextDecoder().decode(body.subarray(i, sp))) ? Number(new TextDecoder().decode(body.subarray(i, sp))) : NaN
        if (!Number.isInteger(len) || len < sp - i + 3 || i + len > body.length || len > meta || body[i + len - 1] !== 0x0a) throw new Error('tar: a pax record is malformed or too long')
        const rec = dec.decode(body.subarray(sp + 1, i + len - 1)), eq = rec.indexOf('=')
        if (eq > 0) pax[rec.slice(0, eq)] = rec.slice(eq + 1)
        i += len
      }
      continue
    }
    if (type === 'g') continue
    if (longName !== null) name = longName
    if (pax?.path) name = pax.path
    longName = null; pax = null
    name = name.replace(/\/+$/, '')
    if (type === '5') continue
    if (new TextEncoder().encode(name).length > nameBytes) { skipped.push({ name: `${name.slice(0, 80)}…`, why: `name longer than ${nameBytes} bytes` }); continue }
    if (type !== '0' && type !== '7') { skipped.push({ name, why: `type ${type} is not a regular file` }); continue }
    if (!safeName(name)) { skipped.push({ name, why: 'unsafe path (absolute, "..", backslash or NUL)' }); continue }
    total += size
    if (total > limits.bytes || files.length >= limits.entries) throw new Error('tar: the archive holds more than the page will restore')
    files.push({ name, bytes: tar.slice(start, end) })
  }
  return { files, skipped }
}

export async function readTarGz(bytes, limits = TAR_LIMITS) {
  const tar = await gunzip(bytes, limits.bytes)
  try { return readTar(tar, limits) } finally { tar.fill(0) }       // the joined tar copy is the page's own; the files are copies
}

// A minimal tar.gz reader, MOVED from web/src/lib/tar.js (vt decrypt addendum: the CLI and the page share it; web/src/lib/tar.js
// re-exports this file). Browser-safe: DecompressionStream, no node:*. What a restored vault or secret is: `tar -czf` output
// (ustar, GNU long names and pax `path` records). Nothing is written anywhere: the entries come back as bytes in memory.
//
// Two readers over ONE header walker (entries()):
//   · readTar / readTarGz (the page's Open, unchanged behaviour): regular files only; directories are skipped; links, devices and
//     every other type are listed in `skipped`; a name that is absolute, holds a `..` segment, a backslash or a NUL is listed in
//     `skipped`, never rewritten; caps: total output bytes and entry count, so a hostile archive cannot fill the tab's memory;
//   · scanTar (vt decrypt's listArchive / extractOne, archive.ts): STRICT — any entry that is not a regular file or a directory,
//     any unsafe path (absolute, empty, `.` / `..` / empty segment, backslash, a control character), a duplicate path or a file
//     that is also a directory refuses the WHOLE archive (TarError 'format'); the caps refuse it too (TarError 'size').
//   The header checksum of every block is verified.
// Memory: the gzip input + the joined tar + a copy of every file ≈ 3x `bytes` at the peak, so the cap is 64 MiB of expanded data
// (≈ 200 MiB in the tab); a bigger archive is refused with a clear message.
// A name, a pax record or a GNU long-name block is at most `meta` bytes, a name at most `nameBytes`.
import type { ArchiveLimits } from './api.ts'
import { ARCHIVE_DEPTH, ARCHIVE_LIMITS } from './api.ts'

export const TAR_LIMITS: Required<ArchiveLimits> = Object.freeze({ ...ARCHIVE_LIMITS, depth: ARCHIVE_DEPTH })

/** Every limit must be a non-negative safe integer; an absent (undefined) one is the default. Anything else (NaN, negative,
 *  fractional, Infinity, a non-number) refuses TarError 'size': a limit that is not a number is never "no cap" (fail closed). */
export function checkedLimits(l: Partial<ArchiveLimits> | undefined): Required<ArchiveLimits> {
  const out: Record<string, number> = { ...TAR_LIMITS } as Record<string, number>
  for (const k of Object.keys(out)) {
    const v = (l as Record<string, unknown> | undefined)?.[k]
    if (v === undefined) continue
    if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) throw new TarError('size', `tar: the archive limit "${k}" is not a non-negative whole number`)
    out[k] = v
  }
  return out as unknown as Required<ArchiveLimits>
}

/** A reader failure: `size` = a cap was hit, `format` = not a (safe) tar.gz. Messages never carry file contents. */
export class TarError extends Error {
  readonly kind: 'size' | 'format'
  constructor(kind: 'size' | 'format', message: string) {
    super(message)
    this.name = 'TarError'
    this.kind = kind
  }
}

const fatal = new TextDecoder('utf-8', { fatal: true })
const dec = { decode: (b: Uint8Array): string => { try { return fatal.decode(b) } catch { throw new TarError('format', 'tar: a name or header field is not valid UTF-8') } } }
const enc = new TextEncoder()
const text = (b: Uint8Array, a: number, n: number): string => { let e = a; while (e < a + n && b[e] !== 0) e++; return dec.decode(b.subarray(a, e)) }
const octal = (b: Uint8Array, a: number, n: number): number => {
  const s = text(b, a, n).trim()
  if (s === '') return 0
  if (!/^[0-7]+$/.test(s)) throw new TarError('format', 'tar: a size or checksum field is not octal')
  return parseInt(s, 8)
}

export function isGzip(bytes: Uint8Array): boolean { return bytes.length > 2 && bytes[0] === 0x1f && bytes[1] === 0x8b }

// F13-1: the sealer's `tar -czf` pads its output with zero bytes to the 10240-byte tar record. gzip and tar ignore that padding;
// DecompressionStream rejects it ("junk after the end"). So: exactly ONE gzip member is decompressed, and the bytes after it are
// accepted only when they are all 0x00. The member's end is found without parsing deflate: the trailing zero run Z may hold up to
// 8 bytes of the member's own trailer (CRC32 + ISIZE can end in zeros), so the end is one of the 9 positions len-Z .. len-Z+8;
// DecompressionStream accepts only the exact one (it refuses junk after the end and a cut-off member). The trailer is then
// checked here as well (CRC32 and ISIZE of the output), which also refuses a second member (its trailer would not match the
// joined output). Anything else is an error.
const CRC_TABLE = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0 } return t })()
export function crc32(b: Uint8Array): number { let c = 0xffffffff; for (let i = 0; i < b.length; i++) c = CRC_TABLE[(c ^ b[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0 }
const BAD_MEMBER = 'gzip: not exactly one complete gzip member (a cut-off member, a second member, a wrong checksum, or trailing bytes that are not zero padding)'

async function inflateMember(bytes: Uint8Array, cap: number): Promise<Uint8Array | null> {
  const ds = new DecompressionStream('gzip')
  const w = ds.writable.getWriter()
  w.write(bytes as Uint8Array<ArrayBuffer>).catch(() => {}); w.close().catch(() => {})
  const r = ds.readable.getReader()
  const parts: Uint8Array[] = []
  let n = 0
  try {
    for (;;) {
      const { done, value } = await r.read()
      if (done) break
      n += value.length
      if (n > cap) {
        await r.cancel().catch(() => {})
        for (const p of parts) p.fill(0)
        throw new TarError('size', `tar: the archive expands to more than ${cap >= 1048576 ? `${Math.floor(cap / 1048576)} MiB` : `${cap} bytes`}, more than this page will hold in memory`)
      }
      parts.push(value)
    }
  } catch (e) { if (e instanceof TarError) throw e; for (const p of parts) p.fill(0); return null }
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) { out.set(p, o); o += p.length; p.fill(0) }
  return out
}

export async function gunzip(bytes: Uint8Array, cap: number = TAR_LIMITS.bytes): Promise<Uint8Array> {
  cap = checkedLimits({ bytes: cap }).bytes
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
  throw new TarError('format', BAD_MEMBER)
}

const safeName = (n: string): boolean => n !== '' && !n.startsWith('/') && !/[\\\0]/.test(n) && !n.split('/').includes('..')

// One non-meta entry as the walker resolved it: the name (long name / pax path applied, trailing slashes cut), its type
// character and where its body is in the tar.
interface RawEntry { name: string; type: string; size: number; start: number; end: number }

// pax records are `<len> <key>=<value>\n`, <len> in BYTES (the whole record, digits and newline included): parse bytes, not UTF-16 units
function parsePax(body: Uint8Array, meta: number): Record<string, string> {
  const rec: Record<string, string> = {}
  for (let i = 0; i < body.length;) {
    let sp = i
    while (sp < body.length && body[sp] !== 0x20 && sp - i < 8) sp++
    const digits = new TextDecoder().decode(body.subarray(i, sp))
    const len = sp < body.length && body[sp] === 0x20 && /^[0-9]+$/.test(digits) ? Number(digits) : NaN
    if (!Number.isInteger(len) || len < sp - i + 3 || i + len > body.length || len > meta || body[i + len - 1] !== 0x0a) throw new TarError('format', 'tar: a pax record is malformed or too long')
    const r = dec.decode(body.subarray(sp + 1, i + len - 1)), eq = r.indexOf('=')
    if (eq > 0) rec[r.slice(0, eq)] = r.slice(eq + 1)
    i += len
  }
  return rec
}

// M-6 (strict only): system `tar` honours pax `size` / `linkpath` (and vendor keys) that this reader ignores, so an archive could list
// as benign here and unpack differently there. Only keys that cannot change what is extracted are allowed; `path` is honoured (a
// global `path` would rename every later entry, so it is refused there).
const PAX_OK = new Set(['path', 'mtime', 'atime', 'ctime', 'comment', 'charset', 'uname', 'gname', 'uid', 'gid'])
function strictPax(rec: Record<string, string>, global: boolean): void {
  for (const k of Object.keys(rec)) {
    if (!PAX_OK.has(k) || (global && k === 'path')) throw new TarError('format', `tar: a pax record "${showPath(k)}" would change what \`tar\` extracts; refused`)
  }
}

function* entries(tar: Uint8Array, limits: ArchiveLimits, strict = false): Generator<RawEntry> {
  const meta = limits.meta ?? TAR_LIMITS.meta
  let pos = 0, longName: string | null = null, pax: Record<string, string> | null = null
  const zero = (a: number): boolean => { for (let i = 0; i < 512; i++) if (tar[a + i] !== 0) return false; return true }
  if (tar.length < 512) throw new TarError('format', 'tar: too short to be a tar archive')
  for (;;) {
    if (pos + 512 > tar.length) throw new TarError('format', 'tar: the archive ends without its two empty blocks')
    if (zero(pos)) break
    let sum = 0
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : tar[pos + i]
    if (sum !== octal(tar, pos + 148, 8)) throw new TarError('format', 'tar: a header checksum is wrong (not a tar archive, or damaged)')
    const type = String.fromCharCode(tar[pos + 156] || 48)
    const size = octal(tar, pos + 124, 12)
    const magic = text(tar, pos + 257, 5)
    let name = text(tar, pos, 100)
    if (magic === 'ustar') { const pre = text(tar, pos + 345, 155); if (pre) name = `${pre}/${name}` }
    const start = pos + 512, end = start + size
    if (end > tar.length) throw new TarError('format', 'tar: an entry runs past the end of the archive')
    pos = start + Math.ceil(size / 512) * 512
    const body = tar.subarray(start, end)
    if ((type === 'L' || type === 'x' || type === 'g') && size > meta) throw new TarError('format', `tar: a name or extended header is longer than ${meta} bytes; refused`)
    if (type === 'L') { longName = dec.decode(body).replace(/\0+$/, ''); continue }
    if (type === 'x' || (type === 'g' && strict)) {
      const rec = parsePax(body, meta)
      if (strict) strictPax(rec, type === 'g')
      if (type === 'x') pax = rec
      continue
    }
    if (type === 'g') continue
    if (longName !== null) name = longName
    if (pax?.path) name = pax.path
    longName = null; pax = null
    name = name.replace(/\/+$/, '')
    yield { name, type, size, start, end }
  }
}

export interface TarFile { name: string; bytes: Uint8Array }
export interface TarSkip { name: string; why: string }

// The page's Open reader. -> { files: [{ name, bytes }], skipped: [{ name, why }] }; throws TarError when the bytes are not a tar archive.
export function readTar(tar: Uint8Array, lim: Partial<ArchiveLimits> = TAR_LIMITS): { files: TarFile[]; skipped: TarSkip[] } {
  const limits = checkedLimits(lim)
  const nameBytes = limits.nameBytes ?? TAR_LIMITS.nameBytes
  const files: TarFile[] = [], skipped: TarSkip[] = []
  let total = 0
  for (const { name, type, size, start, end } of entries(tar, limits)) {
    if (type === '5') continue
    if (enc.encode(name).length > nameBytes) { skipped.push({ name: `${name.slice(0, 80)}…`, why: `name longer than ${nameBytes} bytes` }); continue }
    if (type !== '0' && type !== '7') { skipped.push({ name, why: `type ${type} is not a regular file` }); continue }
    if (!safeName(name)) { skipped.push({ name, why: 'unsafe path (absolute, "..", backslash or NUL)' }); continue }
    total += size
    if (total > limits.bytes || files.length >= limits.entries) throw new TarError('size', 'tar: the archive holds more than the page will restore')
    files.push({ name, bytes: tar.slice(start, end) })
  }
  return { files, skipped }
}

export async function readTarGz(bytes: Uint8Array, lim: Partial<ArchiveLimits> = TAR_LIMITS): Promise<{ files: TarFile[]; skipped: TarSkip[] }> {
  const limits = checkedLimits(lim)
  const tar = await gunzip(bytes, limits.bytes)
  try { return readTar(tar, limits) } finally { tar.fill(0) }       // the joined tar copy is the reader's own; the files are copies
}

// ── strict (vt decrypt) ─────────────────────────────────────────────────────────────────────────────────────────────────────────
// A path is shown in a refusal only after every control character is written out as [U+XXXX] (a terminal never sees it raw).
export const showPath = (p: string): string => (p.length > 200 ? `${p.slice(0, 200)}…` : p).replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, (c) => `[U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}]`)
// Strict path rule: relative, non-empty segments, none `.` or `..`, no backslash, no control character (C0, DEL, C1).
const strictPath = (p: string): boolean => p !== '' && !p.startsWith('/') && !/[\\\p{Cc}]/u.test(p) && p.split('/').every((s) => s !== '' && s !== '.' && s !== '..')

/** A regular file of a strictly scanned archive: its path as stored, its size and where its bytes are in the tar. */
export interface TarSlot { path: string; size: number; start: number; end: number }

/** STRICT scan of an uncompressed tar: every regular file, in archive order; throws TarError ('format' | 'size') for anything unsafe. */
export function scanTar(tar: Uint8Array, lim: Partial<ArchiveLimits> = TAR_LIMITS): TarSlot[] {
  const limits = checkedLimits(lim)
  const { nameBytes, depth } = limits
  const out: TarSlot[] = []
  // every path seen is ONE thing: a file, or a directory (named by an entry, or implied by a file under it). The key is
  // `<parent node id>:<segment>`, so each entry costs O(its path bytes) (I-1: no per-prefix string rebuilding).
  const seen = new Map<string, { id: number; kind: 'file' | 'dir' }>()
  let nextId = 1
  const twice = (p: string): TarError => new TarError('format', `tar: the path "${showPath(p)}" appears more than once, or is both a file and a directory`)
  let total = 0
  for (const { name, type, size, start, end } of entries(tar, limits, true)) {
    if (enc.encode(name).length > nameBytes) throw new TarError('size', `tar: an entry path is longer than ${nameBytes} bytes`)
    if (!strictPath(name)) throw new TarError('format', `tar: unsafe entry path "${showPath(name)}" (absolute, empty, ".", "..", a backslash or a control character)`)
    const isDir = type === '5'
    if (!isDir && type !== '0' && type !== '7') throw new TarError('format', `tar: entry "${showPath(name)}" is ${type === '2' ? 'a symbolic link' : type === '1' ? 'a hard link' : `of type ${showPath(type)}`}, not a regular file or a directory`)
    const segs = name.split('/')
    if (segs.length > depth) throw new TarError('size', `tar: an entry path is nested more than ${depth} levels deep`)
    let parent = 0
    for (let i = 0; i < segs.length; i++) {
      const last = i === segs.length - 1
      const key = `${parent}:${segs[i]}`
      const node = seen.get(key)
      if (!last) {
        if (node === undefined) { seen.set(key, { id: nextId, kind: 'dir' }); parent = nextId++ }
        else { if (node.kind === 'file') throw twice(segs.slice(0, i + 1).join('/')); parent = node.id }
        continue
      }
      if (isDir) {
        if (node === undefined) seen.set(key, { id: nextId++, kind: 'dir' })
        else if (node.kind === 'file') throw twice(name)
      } else {
        if (node !== undefined) throw twice(name)
        seen.set(key, { id: nextId++, kind: 'file' })
      }
    }
    if (isDir) continue
    total += size
    if (!(total <= limits.bytes)) throw new TarError('size', `tar: the files add up to more than ${limits.bytes} bytes`)
    if (!(out.length < limits.entries)) throw new TarError('size', `tar: the archive holds more than ${limits.entries} files`)
    out.push({ path: name, size, start, end })
  }
  return out
}

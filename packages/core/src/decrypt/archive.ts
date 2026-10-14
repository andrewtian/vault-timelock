// Per-file access to a decrypted archive (vt decrypt addendum): listArchive → [{path, size}] (paths as stored, never contents),
// extractOne → the bytes of one file, extractAll → every file. v1 is a tar.gz, read by the moved page reader in STRICT mode
// (tar.ts scanTar): a traversal, absolute, empty or control-character path, a symlink / hard link / device, a duplicate path or a
// path that is both a file and a directory refuses the whole archive (decrypt.format); the caps refuse it too (decrypt.size).
// Stateless: every call reads the archive anew and zeroes its own expanded copy; the returned bytes are copies.
// A future SEALED v2 ("index + blocks") implements ArchiveSource itself; listArchive / extractOne / extractAll accept any source.
import type { ArchiveEntry, ArchiveFile, ArchiveLimits, ArchiveSource } from './api.ts'
import { ARCHIVE_LIMITS } from './api.ts'
import { refuseFormat, refuseSize } from './refuse.ts'
import { TarError, gunzip, isGzip, scanTar, showPath } from './tar.ts'
import type { TarSlot } from './tar.ts'

const limitsOf = (l: Partial<ArchiveLimits> | undefined): ArchiveLimits => ({ ...ARCHIVE_LIMITS, ...(l ?? {}) })

function failed(name: string, e: unknown): never {
  if (e instanceof TarError) {
    if (e.kind === 'size') refuseSize(`${name}: ${e.message}`)
    refuseFormat(`${name}: ${e.message}`)
  }
  throw e
}

async function open(name: string, bytes: Uint8Array, limits: ArchiveLimits): Promise<{ tar: Uint8Array; slots: TarSlot[] }> {
  if (!(bytes instanceof Uint8Array) || !isGzip(bytes)) refuseFormat(`${name} is not a gzip archive (.tar.gz)`)
  let tar: Uint8Array
  try { tar = await gunzip(bytes, limits.bytes) } catch (e) { failed(name, e) }
  try { return { tar, slots: scanTar(tar, limits) } } catch (e) { tar.fill(0); failed(name, e) }
}

export function tarGzSource(name: string, bytes: Uint8Array, limits?: Partial<ArchiveLimits>): ArchiveSource {
  const L = limitsOf(limits)
  return {
    name,
    async list(): Promise<readonly ArchiveEntry[]> {
      const { tar, slots } = await open(name, bytes, L)
      tar.fill(0)
      return slots.map(({ path, size }) => ({ path, size }))
    },
    async extract(path: string): Promise<Uint8Array> {
      const { tar, slots } = await open(name, bytes, L)
      try {
        const s = typeof path === 'string' ? slots.find((x) => x.path === path) : undefined
        if (s === undefined) refuseFormat(`${name} holds no file "${showPath(String(path))}"`)
        return tar.slice(s.start, s.end)
      } finally { tar.fill(0) }
    },
    async all(): Promise<readonly ArchiveFile[]> {
      const { tar, slots } = await open(name, bytes, L)
      try { return slots.map(({ path, size, start, end }) => ({ path, size, bytes: tar.slice(start, end) })) } finally { tar.fill(0) }
    },
  }
}

export function sourceOf(archive: Uint8Array | ArchiveSource, limits?: Partial<ArchiveLimits>): ArchiveSource {
  if (archive instanceof Uint8Array) return tarGzSource('the archive', archive, limits)
  const ok = typeof archive === 'object' && archive !== null && typeof archive.list === 'function' && typeof archive.extract === 'function' && typeof archive.all === 'function'
  if (!ok) refuseFormat('not an archive (a .tar.gz or an ArchiveSource)')
  return archive
}

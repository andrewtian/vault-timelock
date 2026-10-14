// @vault-timelock/core/decrypt — vt decrypt's shared core (design 2026-10-14-vt-decrypt, lane E). See api.ts for the contract.
// Browser-safe. The CLI and the page import ONLY from here.
import type {
  ArchiveEntry, ArchiveFile, ArchiveLimits, ArchiveSource, DecryptHow, DecryptLimits, DecryptResult, Detected,
} from './api.ts'
import { unlockIso } from '../text/drand.ts'
import { ageInfo, classify, limitsOf, openAge } from './age.ts'
import { sourceOf, tarGzSource as tarGz } from './archive.ts'
import { decrypted, openSealed, readSealed } from './sealed.ts'
import { isGzip } from './tar.ts'
import { refuseFormat } from './refuse.ts'

export type * from './api.ts'
/** Writes every control / format / line-separator character out as [U+XXXX] and cuts at 200 chars: use for ANY archive path shown to a user. */
export { showPath } from './tar.ts'
export { ARCHIVE_DEPTH, ARCHIVE_LIMITS, DECRYPT_LIMITS, PASTE_LIMIT, SEALED_FORMATS, SEALED_FORMAT_V1 } from './api.ts'

/**
 * Read what the input is, without any secret and without decrypting: the kind (passphrase / identity / timelocked / sealed),
 * the form, and for a time lock the round and its UTC time; for a SEALED.txt its format, layout and blocks (each checked against
 * its [file] line). The CLI broker calls it on a paste BEFORE any prompt; the page shows its kind.
 * Refuses decrypt.size (over limits.input), decrypt.format (not age / SEALED.txt, an unknown SEALED format, a block mismatch) and
 * decrypt.kind (recipients this build cannot open).
 */
export function detectInput(input: string | Uint8Array, limits?: Partial<DecryptLimits>): Detected {
  const L = limitsOf(limits)
  const c = classify(input, L)
  if ('bin' in c) {
    const a = ageInfo(c.bin, L)
    return {
      kind: a.kind, form: c.form, round: a.round, chainHash: a.chainHash, opensAt: a.round === null ? null : unlockIso(a.round),
      format: null, layout: null, contents: null, arId: null, blocks: [], identityPath: a.kind === 'identity',
    }
  }
  const s = readSealed(c.text, c.form)
  return {
    kind: 'sealed', form: c.form, round: s.round, chainHash: s.chainHash, opensAt: unlockIso(s.round), format: s.format,
    layout: s.layout, contents: s.contents, arId: s.arId, blocks: s.blocks, identityPath: s.layout === 'two-layer' && s.contents === 'full',
  }
}

/**
 * Decrypt one age file (armored or binary) or a whole SEALED.txt chain. Output: bytes only. See api.ts for every refusal.
 * A time lock is never asked of the fetcher before its round (by how.now): decrypt.too-early "opens at <UTC>".
 * A SEALED.txt given an identity opens by the identity path (no time lock, any time); otherwise by its time lock.
 */
export async function decryptAge(input: string | Uint8Array, how: DecryptHow): Promise<DecryptResult> {
  const h: DecryptHow = how ?? {}
  const L = limitsOf(h.limits)
  const c = classify(input, L)
  if ('text' in c) return openSealed(readSealed(c.text, c.form), h, L, h.archiveLimits ?? {})
  const a = ageInfo(c.bin, L)
  const plain = await openAge(c.bin, a, h, L)
  return {
    kind: a.kind, via: a.kind === 'timelocked' ? 'timelock' : a.kind, files: [decrypted('plaintext', plain)], blocks: [],
    archive: isGzip(plain) ? tarGz('plaintext', plain, h.archiveLimits) : null, notes: [],
  }
}

/** An ArchiveSource over a decrypted .tar.gz (the moved, hardened page reader; strict: unsafe entries are refused). */
export function tarGzSource(name: string, bytes: Uint8Array, limits?: Partial<ArchiveLimits>): ArchiveSource {
  return tarGz(name, bytes, limits)
}

/** [{path, size}] of every regular file (paths as stored; never contents). bytes = a .tar.gz, or any ArchiveSource. */
export async function listArchive(archive: Uint8Array | ArchiveSource, limits?: Partial<ArchiveLimits>): Promise<ArchiveEntry[]> {
  const raw: unknown = await sourceOf(archive, limits).list()
  if (!Array.isArray(raw)) refuseFormat('the archive source did not list its files as an array')
  // exactly { path, size } per entry, whatever else a foreign source put on its objects (a listing never carries contents)
  return raw.map((e: unknown): ArchiveEntry => {
    const { path, size } = (typeof e === 'object' && e !== null ? e : {}) as { path?: unknown; size?: unknown }
    if (typeof path !== 'string' || typeof size !== 'number' || !Number.isSafeInteger(size) || size < 0) refuseFormat('the archive source listed an entry that is not { path, size }')
    return { path, size }
  })
}

/** The bytes of exactly the file at `path` (as listed). */
export async function extractOne(archive: Uint8Array | ArchiveSource, path: string, limits?: Partial<ArchiveLimits>): Promise<Uint8Array> {
  return sourceOf(archive, limits).extract(path)
}

/** Every regular file with its bytes, in archive order (one pass; the CLI's `--out <dir>`, the page's "Download all"). */
export async function extractAll(archive: Uint8Array | ArchiveSource, limits?: Partial<ArchiveLimits>): Promise<ArchiveFile[]> {
  return [...await sourceOf(archive, limits).all()]
}

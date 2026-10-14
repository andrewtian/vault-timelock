// @vault-timelock/core/decrypt — vt decrypt's shared core (design 2026-10-14-vt-decrypt, lane E). See api.ts for the contract.
// Browser-safe. The CLI and the page import ONLY from here.
import type {
  ArchiveEntry, ArchiveFile, ArchiveLimits, ArchiveSource, DecryptHow, DecryptLimits, DecryptResult, Detected,
} from './api.ts'

export type * from './api.ts'
export { ARCHIVE_LIMITS, DECRYPT_LIMITS, PASTE_LIMIT, SEALED_FORMATS, SEALED_FORMAT_V1 } from './api.ts'

const PENDING = 'vt decrypt core: the API commit has no implementation yet'

/**
 * Read what the input is, without any secret and without decrypting: the kind (passphrase / identity / timelocked / sealed),
 * the form, and for a time lock the round and its UTC time; for a SEALED.txt its format, layout and blocks (each checked against
 * its [file] line). The CLI broker calls it on a paste BEFORE any prompt; the page shows its kind.
 * Refuses decrypt.size (over limits.input), decrypt.format (not age / SEALED.txt, an unknown SEALED format, a block mismatch) and
 * decrypt.kind (recipients this build cannot open).
 */
export function detectInput(input: string | Uint8Array, limits?: Partial<DecryptLimits>): Detected {
  void input; void limits
  throw new Error(PENDING)
}

/**
 * Decrypt one age file (armored or binary) or a whole SEALED.txt chain. Output: bytes only. See api.ts for every refusal.
 * A time lock is never asked of the fetcher before its round (by how.now): decrypt.too-early "opens at <UTC>".
 */
export async function decryptAge(input: string | Uint8Array, how: DecryptHow): Promise<DecryptResult> {
  void input; void how
  throw new Error(PENDING)
}

/** An ArchiveSource over a decrypted .tar.gz (the moved, hardened page reader; strict: unsafe entries are refused). */
export function tarGzSource(name: string, bytes: Uint8Array, limits?: Partial<ArchiveLimits>): ArchiveSource {
  void name; void bytes; void limits
  throw new Error(PENDING)
}

/** [{path, size}] of every regular file (paths as stored; never contents). bytes = a .tar.gz, or any ArchiveSource. */
export async function listArchive(archive: Uint8Array | ArchiveSource, limits?: Partial<ArchiveLimits>): Promise<ArchiveEntry[]> {
  void archive; void limits
  throw new Error(PENDING)
}

/** The bytes of exactly the file at `path` (as listed). */
export async function extractOne(archive: Uint8Array | ArchiveSource, path: string, limits?: Partial<ArchiveLimits>): Promise<Uint8Array> {
  void archive; void path; void limits
  throw new Error(PENDING)
}

/** Every regular file with its bytes, in archive order (one pass; the CLI's `--out <dir>`, the page's "Download all"). */
export async function extractAll(archive: Uint8Array | ArchiveSource, limits?: Partial<ArchiveLimits>): Promise<ArchiveFile[]> {
  void archive; void limits
  throw new Error(PENDING)
}

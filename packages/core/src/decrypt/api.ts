// vt decrypt — the shared core's API (design 2026-10-14-vt-decrypt, lane E). Types and limits only; the functions are in index.ts.
// Browser-safe: no node:*, no fetch, no storage, no logging. The CLI (`vt decrypt`, lane C) and the page's Decrypt tab (lane W) both
// call exactly these.
//
// Inputs: armored age text, binary .age bytes, or a whole SEALED.txt (bare, or inside a published text). The kind is read from the
// age header stanza(s): `scrypt` → a passphrase; `X25519` (or the age post-quantum hybrid `mlkem768x25519`) → an identity
// (`AGE-SECRET-KEY-1…` text); `tlock <round> <chainhash>` (drand quicknet only) → the round's drand signature, from a CALLER-SUPPLIED
// fetcher (the relay; core never fetches). A SEALED.txt is dispatched on its `format:` line (v1 = vault-timelock-sealed/1: the
// two-layer chain unlock-TIME.age → identity → vault.tar.gz.age, or a one-layer package); an unknown format is refused decrypt.format.
//
// Every refusal is a Refusal (contracts/guard.ts) with one of the decrypt.* guard ids:
//   decrypt.kind       the input is a kind this call cannot open: the secret it needs was not given (a passphrase, an identity, a
//                      signature fetcher), or its recipients are none of scrypt / X25519 / tlock (or a tlock stanza of another chain);
//   decrypt.passphrase the passphrase does not open it;
//   decrypt.identity   the identity text is not age identities, or none of them opens it;
//   decrypt.too-early  the drand round is not reached yet (by this device's clock, or the fetcher says drand has not published it):
//                      the message says "opens at <UTC>";
//   decrypt.format     not age armor / binary age / a SEALED.txt; an unknown SEALED format; a SEALED block that differs from its
//                      [file] line; damaged ciphertext; a signature that does not open the time lock; an archive that is not a safe
//                      tar.gz (a traversal / absolute / symlink / hard-link / device / duplicate entry), or a path not in it;
//   decrypt.size       over a bound: the input, a passphrase / identity text, the scrypt work factor, an archive's expanded size or
//                      entry count.
// Nothing here logs; messages never carry plaintext, a passphrase or an identity.

/** The kind of one age file, from its header stanza(s). */
export type AgeKind = 'passphrase' | 'identity' | 'timelocked'
/** What decryptAge was given: one age file, or a SEALED.txt (its whole open chain). */
export type InputKind = AgeKind | 'sealed'
/** How the input was given. `published`: a SEALED.txt inside a published text (`vault-timelock/1 unlock=…` header). */
export type InputForm = 'armored' | 'binary' | 'sealed' | 'published'
/** The package a v1 SEALED.txt describes (sealed-from.ts's shapes; `payload` = payload.age, raw or tar+gzip). */
export type SealedLayout = 'two-layer' | 'vault' | 'secret' | 'payload'
/** How the result was opened. */
export type OpenedVia = 'passphrase' | 'identity' | 'timelock'

/** The SEALED.txt format this build opens. Dispatch is on the `format:` line; any other value is refused decrypt.format. */
export const SEALED_FORMAT_V1 = 'vault-timelock-sealed/1'
export const SEALED_FORMATS: readonly string[] = Object.freeze([SEALED_FORMAT_V1])

export interface DecryptLimits {
  /** Bytes of the input: armored text, binary .age, or a SEALED.txt / published text. */
  readonly input: number
  /** Bytes (UTF-8) of a passphrase or of an identity text. */
  readonly secret: number
  /** The highest scrypt work factor (log2 N) attempted (age-encryption's own ceiling is 20). */
  readonly scryptLogN: number
}
export const DECRYPT_LIMITS: DecryptLimits = Object.freeze({ input: 128 * 1024 * 1024, secret: 64 * 1024, scryptLogN: 20 })
/** The cap for PASTED input (the CLI broker's paste and pipe, the page's paste box): ~1 MiB. Pass it as limits.input there. */
export const PASTE_LIMIT = 1024 * 1024

/** The tar.gz reader's bounds (moved from web/src/lib/tar.js; ARCHIVE_LIMITS are the page's numbers). */
export interface ArchiveLimits {
  /** Bytes of expanded data: the gunzipped tar, and the sum of the regular files' sizes. */
  readonly bytes: number
  /** Regular-file entries. */
  readonly entries: number
  /** Bytes of one pax record, pax header or GNU long-name block. */
  readonly meta: number
  /** Bytes (UTF-8) of one entry path. */
  readonly nameBytes: number
}
export const ARCHIVE_LIMITS: ArchiveLimits = Object.freeze({ bytes: 64 * 1024 * 1024, entries: 10_000, meta: 64 * 1024, nameBytes: 4096 })

/**
 * The relay's drand route, supplied by the caller (CLI: through `vt up`'s relay; page: /relay/drand/…). Core never fetches.
 * Resolves to the round's BLS signature as lowercase hex (quicknet: a 48-byte G1 point, 96 hex), or null when drand has not
 * published the round yet (→ decrypt.too-early). A rejection (relay down, …) is passed through to the caller unchanged.
 * The signature needs no verification here: the tlock IBE check fails closed on any other signature (decrypt.format).
 */
export type FetchRoundSignature = (chainHash: string, round: number) => Promise<string | null>

export interface DecryptHow {
  /** For a `scrypt` input. Never logged, never in a message. */
  readonly passphrase?: string
  /** For an X25519 input, or a SEALED.txt's recovery path: identity text, one `AGE-SECRET-KEY-1…` (or `AGE-SECRET-KEY-PQ-1…`) per
   *  line; blank lines and `#` comment lines allowed (age-keygen's file). Never logged, never in a message. */
  readonly identity?: string
  /** For a `tlock` input or a SEALED.txt opened by its time lock. */
  readonly fetchRoundSignature?: FetchRoundSignature
  /** Unix ms (default Date.now): the before-round refusal is judged by it, before the fetcher is called. */
  readonly now?: () => number
  readonly limits?: Partial<DecryptLimits>
  readonly archiveLimits?: Partial<ArchiveLimits>
}

/** A ciphertext block of a SEALED.txt: its [file] name, decoded size and sha256 — checked equal to its [file] line. */
export interface BlockInfo { readonly name: string; readonly size: number; readonly sha256: string }

/** What detectInput reads, without any secret and without decrypting. */
export interface Detected {
  readonly kind: InputKind
  readonly form: InputForm
  /** timelocked / sealed: the drand round (quicknet) the time lock opens at; null otherwise. */
  readonly round: number | null
  /** timelocked / sealed: the drand chain hash named by the tlock stanza (always quicknet's: another chain is refused). */
  readonly chainHash: string | null
  /** timelocked / sealed: `YYYY-MM-DDTHH:MM:SSZ` of that round. */
  readonly opensAt: string | null
  /** sealed: the `format:` value (SEALED_FORMAT_V1). */
  readonly format: string | null
  /** sealed: the package shape. */
  readonly layout: SealedLayout | null
  /** sealed: `full`, or `key-only` (the archive is at ar://arId, not in the text). */
  readonly contents: 'full' | 'key-only' | null
  readonly arId: string | null
  /** sealed: every block, each checked against its [file] line; [] otherwise. */
  readonly blocks: readonly BlockInfo[]
  /** sealed: whether an identity (the one-time key, e.g. recovered with the recovery key) can open it without the time lock. */
  readonly identityPath: boolean
}

/** One decrypted file. Bytes only: the caller decides where they go (CLI: --out by the launcher; page: a Download). */
export interface DecryptedFile {
  /** single age file: `plaintext`; SEALED.txt: identity.key, vault.tar.gz, secret.tar.gz, content.tar.gz or content. */
  readonly name: string
  readonly bytes: Uint8Array
  readonly size: number
  readonly sha256: string
}

/** One entry of an archive: its path AS STORED (pseudonymous ids for a vault) and its size. Never its contents. */
export interface ArchiveEntry { readonly path: string; readonly size: number }
export interface ArchiveFile extends ArchiveEntry { readonly bytes: Uint8Array }

/**
 * Per-file access to a decrypted archive. v1: a tar.gz (tarGzSource). A future SEALED v2 ("index + blocks": an encrypted index of
 * path ↔ block, one age block per file) implements the same interface: list() from the index, extract() decrypts one block only.
 * Every method refuses (decrypt.format / decrypt.size) an archive with an unsafe, duplicate or oversized entry: nothing is skipped
 * silently.
 */
export interface ArchiveSource {
  /** The archive's file name (e.g. vault.tar.gz). */
  readonly name: string
  list(): Promise<readonly ArchiveEntry[]>
  /** The bytes of exactly one regular file; a path not in list() is refused decrypt.format. */
  extract(path: string): Promise<Uint8Array>
  /** Every regular file, in archive order (one pass). */
  all(): Promise<readonly ArchiveFile[]>
}

export interface DecryptResult {
  readonly kind: InputKind
  readonly via: OpenedVia
  /** single age file: [plaintext]; SEALED.txt: what the chain yields, e.g. [identity.key, vault.tar.gz]. */
  readonly files: readonly DecryptedFile[]
  /** sealed: every ciphertext block, checked against its [file] line; [] otherwise. */
  readonly blocks: readonly BlockInfo[]
  /** The archive among files (vault.tar.gz / secret.tar.gz / content.tar.gz) as an ArchiveSource, or null (no archive, or a
   *  key-only text whose archive is not in the text). */
  readonly archive: ArchiveSource | null
  /** Plain-language notes (e.g. where a key-only text's archive is). Never secret. */
  readonly notes: readonly string[]
}

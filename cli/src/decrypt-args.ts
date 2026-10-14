// cli/src/decrypt-args.ts — what BOTH sides of `vt decrypt` share (design 2026-10-14-vt-decrypt, lane C): the unsandboxed broker
// (src/ops/broker.ts with src/ops/decrypt-broker.ts: the paste, the passphrase prompt, the --out writes) and the sandboxed command
// (src/decrypt.ts: core's decryptAge). Each side parses the argv ITSELF with parseDecryptArgs: the broker never takes the child's word
// for where the plaintext goes or whether a passphrase may be asked.
//
//   vt decrypt [<file> | -] [--identity F] [--out <path|dir>] [--stdout] [--list] [--only <path>]
//
// Node builtins and core's tiny guard module only: the broker imports this file, and the broker is the process that types the passphrase.
// The refusals here are shared by both sides, one marker per guard id (the mutation runner's rule):
//   decrypt.format   the pasted / piped text is not age armor or a SEALED.txt (the broker, before any prompt); the child's own input
//                    checks before core;
//   decrypt.size     the paste / pipe is over PASTE_LIMIT (1 MiB), or a file over core's input bound;
//   vt.out-exists    --out names something that exists, its directory does not, or a file of the output would overwrite (or, on a
//                    case- / normalization-insensitive disk such as APFS, merge with) one already written: never overwritten;
//   vt.decrypt-input the input or --identity file cannot be used, and why (fix round 1, I-2): under a restored/ directory, a link, not a
//                    regular file, a vt credential, an --identity in a protected place, or a file the sandbox may not read (never a bare
//                    EPERM).
import { refuse } from '@vault-timelock/core/text/guard.ts'

export interface DecryptArgs {
  readonly input: string | null      // a file, or null: stdin (`-`, or nothing: a paste on a terminal, else the pipe to EOF)
  readonly identity: string | null   // --identity F: an age identity file (AGE-SECRET-KEY-1…), handed read-only to the sandbox
  readonly out: string | null        // --out: a file (one age file, or --only), or a NEW directory (a SEALED.txt: every file of its archive)
  readonly stdout: boolean           // --stdout: the plaintext to stdout, only when asked (also on a terminal: asked is not by accident)
  readonly list: boolean             // --list: path + size of every file of the archive (no contents; allowed on a terminal)
  readonly only: string | null       // --only <path>: one file of the archive, as --list shows it
}

export const DECRYPT_USAGE = 'usage: vt decrypt [<file>|-] [--identity F] [--out <path|dir>] [--stdout] [--list] [--only <path>]'
export class DecryptUsage extends Error {
  constructor(message: string) { super(`${message}; ${DECRYPT_USAGE}`); this.name = 'DecryptUsage' }
}

const VALUED = new Set(['--identity', '--out', '--only'])
const FLAGS = new Set(['--stdout', '--list'])

// The words after `decrypt` → DecryptArgs. A repeated flag, a missing value, an unknown flag or a second file is a usage error (exit 1);
// values are never echoed (a path can name anything).
export function parseDecryptArgs(args: readonly string[]): DecryptArgs {
  const seen = new Set<string>()
  const v: Record<string, string> = {}
  let input: string | null = null
  let gotInput = false
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (VALUED.has(a) || FLAGS.has(a)) {
      if (seen.has(a)) throw new DecryptUsage(`${a} is given twice`)
      seen.add(a)
      if (FLAGS.has(a)) continue
      const val = args[i + 1]
      if (val === undefined || val === '') throw new DecryptUsage(`${a} needs a value`)
      // fix round 1 (M-2): `--out -`, `--out --stdout`, `--identity -`: never guessed, never written as a file named so
      if (a !== '--only' && val.startsWith('-')) throw new DecryptUsage(`${a} followed by - or another option is ambiguous: ${a === '--out' ? '--stdout prints the plaintext, --out takes a new file\'s path (./- for a file named -)' : '--identity takes the identity file\'s path (stdin is the input)'}`)
      v[a] = val
      i++
    } else if (a === '-' || !a.startsWith('-')) {
      if (gotInput) throw new DecryptUsage('one input only (a file, or - for stdin)')
      if (a === '') throw new DecryptUsage('an empty file name')
      gotInput = true
      input = a === '-' ? null : a
    } else {
      throw new DecryptUsage('an unknown option (the value is not echoed)')
    }
  }
  const out = v['--out'] ?? null, only = v['--only'] ?? null
  const stdout = seen.has('--stdout'), list = seen.has('--list')
  if (list && (out !== null || stdout || only !== null)) throw new DecryptUsage('--list prints the archive\'s paths and sizes only: not with --out, --stdout or --only')
  if (out !== null && stdout) throw new DecryptUsage('--out or --stdout, not both')
  return { input, identity: v['--identity'] ?? null, out, stdout, list, only }
}

// The positions (in the FULL argv, argv[0] === 'decrypt') of the input file and the --identity file (handed to the sandbox, read-only)
// and of the --out path (rewritten to an absolute path by bin/vt, like the handed files: the broker runs in `/`; never handed).
// Only a value the parser accepts is reported (M-2): `--out -` and `--out --stdout` are left as they are, so the parser refuses them.
export function decryptPositions(argv: readonly string[]): { handed: number[]; out: number | null; input: number | null; identity: number | null } {
  const handed: number[] = []
  let out: number | null = null, input: number | null = null, identity: number | null = null
  if (argv[0] !== 'decrypt') return { handed, out, input, identity }
  let gotInput = false
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]
    if (VALUED.has(a)) {
      const v = argv[i + 1]
      if (v === undefined) break
      if (v === '' || v.startsWith('-')) continue      // not a value the parser takes: the parser refuses the line
      if (a === '--identity' && identity === null) { identity = i + 1; handed.push(i + 1) }
      else if (a === '--out' && out === null) out = i + 1
      i++
    } else if (!FLAGS.has(a) && !gotInput && a !== '-' && a !== '' && !a.startsWith('-')) {
      handed.push(i)
      input = i
      gotInput = true
    } else if (a === '-') gotInput = true
  }
  return { handed, out, input, identity }
}

// ---- the shared refusals (one marker each in this workspace)

export function refuseInputFormat(message: string): never {
  refuse('decrypt.format', message) // @guard:decrypt.format
}
export function refuseInputSize(message: string): never {
  refuse('decrypt.size', message) // @guard:decrypt.size
}
export function refuseOutExists(message: string): never {
  refuse('vt.out-exists', message) // @guard:vt.out-exists
}
export function refuseInputPath(message: string): never {
  refuse('vt.decrypt-input', message) // @guard:vt.decrypt-input
}
// Anything under a restored/ directory holds decrypted package contents: vt decrypt never takes it as an input or identity (fix round 1).
export function checkInputPath(path: string, what: string): void {
  if (path.split('/').includes('restored')) refuseInputPath(`${what} lies under a restored/ directory, which holds decrypted contents: vt decrypt never reads there`)
}

// ---- the texts a paste may be (core's own markers: age.ts / sealed-from.ts)

export const ARMOR_BEGIN = '-----BEGIN AGE ENCRYPTED FILE-----'
export const ARMOR_END = '-----END AGE ENCRYPTED FILE-----'
export const SEALED_TITLE = '== vault-timelock sealed package: self-contained, age + drand timelock =='
export const PUBLISHED_HEAD = 'vault-timelock/1 unlock='
export const SEALED_END = '== end =='
export const AGE_MAGIC = 'age-encryption.org/v1\n'
// core's PASTE_LIMIT (packages/core/src/decrypt/api.ts), restated so the broker needs no core import; test/decrypt.test.ts pins equality.
export const PASTE_MAX = 1024 * 1024

// ---- the data channel (child → broker, fd 5): a JSON header line {"path","size"}, then exactly `size` bytes; last {"end":true}

export const DATA_FD = 5
export const FRAME_HEADER_MAX = 8192
export const OUT_FILE_MAX = 128 * 1024 * 1024        // one file (core's DECRYPT_LIMITS.input: no plaintext is larger)
export const OUT_TOTAL_MAX = 256 * 1024 * 1024       // every file together
export const OUT_FILES_MAX = 10_002                  // core's ARCHIVE_LIMITS.entries + identity.key + the archive itself

// ---- display (M-5, fix round 1 M-1): an archive path as --list prints it

// Printable ASCII is shown as itself; EVERY other code point (controls, bidi and format characters, zero-width and invisible fillers, every
// non-ASCII letter, combining marks), and the three characters `\` `[` `]`, are written as \u{hex}. The result is printable ASCII with no
// bracket at all, so the broker's output filter (which drops invisible characters, turns a non-ASCII or tag-like bracketed run into
// parentheses, and writes non-ASCII as \u{..} in a non-UTF-8 locale) passes it through unchanged; and since `\` is always escaped, the
// notation is unambiguous: listName / unlistName are inverse, and `--only` takes a path exactly as --list printed it. An NFC and an NFD
// name print differently. (A strict superset of core's showPath escapes; test/decrypt.test.ts pins that over all of Unicode.)
export function listName(path: string): string {
  let out = ''
  for (const ch of path) {
    const c = ch.codePointAt(0) as number
    out += c >= 0x20 && c <= 0x7e && ch !== '\\' && ch !== '[' && ch !== ']' ? ch : `\\u{${c.toString(16)}}`
  }
  return out
}
export function unlistName(shown: string): string {
  return shown.replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (m, h: string) => {
    const n = parseInt(h, 16)
    return n <= 0x10ffff && !(n >= 0xd800 && n <= 0xdfff) ? String.fromCodePoint(n) : m
  })
}

// The key two paths share when a case-insensitive, normalization-insensitive file system (APFS, HFS+) stores them as ONE file:
// decomposed, case folded (lower(upper(lower)) approximates full folding: \u00df → SS → ss), recomposed. Over-folding refuses a rare
// distinct pair; it never merges two files.
export function foldKey(path: string): string {
  return path.normalize('NFD').toLowerCase().toUpperCase().toLowerCase().normalize('NFC')
}

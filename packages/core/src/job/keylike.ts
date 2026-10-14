// packages/core/src/job/keylike.ts — secret-shaped and IP-shaped content (spec §4.1, controller ruling 3).
//
// Two strictness levels share these scanners:
//   · STRUCTURAL fields (job name, addresses, labels; the API's JSON body strings via S2's bodycheck):
//     assertNoSecretOrIp refuses, fail closed —
//       job.ip-like:  any IPv4 or IPv6 literal, loopback included, bare or as a URL host;
//       job.key-like: a run of >= 64 hex digits (with or without 0x); a base58 run of >= 87 characters (64-byte
//                     secrets); a JSON array of >= 32 byte values; "AGE-SECRET-KEY-" (any case); >= 12 consecutive
//                     BIP-39 English words (any case, any separators); any URL (scheme://); a .onion host.
//   · MESSAGE text (publication text, message.ts): only the unambiguous patterns (an age secret key with key data
//     after it, base58 runs of exactly 87 or 88, a JSON array of exactly 64 byte values, >= 12 BIP-39 words) and IP
//     literals other than loopback. Hashes and URLs pass; a bare 64-hex token is a warning.
// Tokens are scanned with ASCII class tables in single passes (no backtracking regexes), so a 16 MiB text costs a few
// linear scans. Nothing here echoes the value it looked at.
import { english } from 'viem/accounts'
import { refuse } from '../contracts/index.ts'

// ---- ASCII character classes ------------------------------------------------------------------------------------
const HEX = 1, B58 = 2, ALPHA = 4, V4 = 8, V6 = 16, WORD = 32
const CLS = new Uint8Array(128)
for (let c = 0; c < 128; c++) {
  const ch = String.fromCharCode(c)
  if (/[0-9a-fA-F]/.test(ch)) CLS[c] |= HEX | V6
  if (/[1-9A-HJ-NP-Za-km-z]/.test(ch)) CLS[c] |= B58
  if (/[A-Za-z]/.test(ch)) CLS[c] |= ALPHA
  if (/[0-9.]/.test(ch)) CLS[c] |= V4
  if (ch === ':' || ch === '.') CLS[c] |= V6
  if (/[A-Za-z0-9_]/.test(ch)) CLS[c] |= WORD
}
const is = (code: number, mask: number): boolean => code < 128 && (CLS[code] & mask) !== 0

// Calls hit(start, end) for every maximal run of characters in `mask`; true as soon as one hit returns true.
function someRun(s: string, mask: number, hit: (start: number, end: number) => boolean): boolean {
  const n = s.length
  let i = 0
  while (i < n) {
    if (!is(s.charCodeAt(i), mask)) { i++; continue }
    const start = i
    while (i < n && is(s.charCodeAt(i), mask)) i++
    if (hit(start, i)) return true
  }
  return false
}

// ---- secret shapes ----------------------------------------------------------------------------------------------
const BIP39: ReadonlySet<string> = new Set(english)
const BIP_MIN = Math.min(...english.map((w) => w.length))
const BIP_MAX = Math.max(...english.map((w) => w.length))

// >= 12 consecutive BIP-39 words: words are maximal runs of ASCII letters, compared lower-cased; whatever lies between
// two words (spaces, newlines, digits, punctuation) does not break the run, any other word does.
export function hasBip39Run(s: string): boolean {
  let run = 0
  return someRun(s, ALPHA, (a, b) => {
    const len = b - a
    run = len >= BIP_MIN && len <= BIP_MAX && BIP39.has(s.slice(a, b).toLowerCase()) ? run + 1 : 0
    return run >= 12
  })
}

export const hasHexRun = (s: string, ok: (len: number) => boolean): boolean => someRun(s, HEX, (a, b) => ok(b - a))
export const hasBase58Run = (s: string, ok: (len: number) => boolean): boolean => someRun(s, B58, (a, b) => ok(b - a))

// The element count of a JSON array of byte values (integers 0..255, 1-3 digits) starting at s[i] === '[', else -1.
function byteArrayAt(s: string, i: number): number {
  const ws = (j: number): number => { while (j < s.length && ' \t\n\r'.includes(s[j])) j++; return j }
  let j = ws(i + 1)
  let count = 0
  for (;;) {
    let digits = 0, value = 0
    while (j < s.length && digits <= 3) {
      const d = s.charCodeAt(j) - 48
      if (d < 0 || d > 9) break
      value = value * 10 + d; digits++; j++
    }
    if (digits === 0 || digits > 3 || value > 255) return -1
    count++
    j = ws(j)
    if (s[j] === ',') { j = ws(j + 1); continue }
    return s[j] === ']' ? count : -1
  }
}
// True when some JSON array of byte values has an element count that `ok` accepts. Linear: an array of digits holds
// no '[', so no character is scanned from more than one opening bracket.
export function hasByteArray(s: string, ok: (count: number) => boolean): boolean {
  for (let i = s.indexOf('['); i !== -1; i = s.indexOf('[', i + 1)) {
    const n = byteArrayAt(s, i)
    if (n > 0 && ok(n)) return true
  }
  return false
}

// age X25519 (and post-quantum) identities: AGE-SECRET-KEY-[PQ-]1 followed by bech32 data. The message rule needs key
// data after the "1" (SEALED.txt legitimately says "one AGE-SECRET-KEY-1... line"); structural fields refuse the prefix.
export const AGE_KEY = /AGE-SECRET-KEY-(?:PQ-)?1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]/i
const AGE_PREFIX = /AGE-SECRET-KEY-/i
const ONION = /\.onion(?![A-Za-z0-9])/i

// ---- IP shapes --------------------------------------------------------------------------------------------------
const QUAD = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/
const isQuad = (t: string): boolean => QUAD.test(t) && t.split('.').every((p) => Number(p) <= 255)
// The WHATWG-normalized bracketed host of an IPv6 literal, or null. Only [0-9A-Fa-f:.] reaches the parser.
function v6Host(t: string): string | null {
  if (t.length === 0 || t.length > 64 || !t.includes(':') || !/^[0-9A-Fa-f:.]+$/.test(t)) return null
  try { return new URL(`http://[${t}]/`).hostname } catch { return null }
}
const isLoopback = (host: string): boolean => host.startsWith('127.') || host === '[::1]'

// One token: a strict IPv4 dotted quad (each part 0-255, 1-3 digits), or anything a bracketed URL parse accepts as
// IPv6 (brackets and a %zone allowed). '12:30:45' is not an IP; '::1' is.
export function looksLikeIp(token: string): boolean {
  if (typeof token !== 'string') return false
  if (isQuad(token)) return true
  let t = token.length >= 2 && token.startsWith('[') && token.endsWith(']') ? token.slice(1, -1) : token
  const zone = t.indexOf('%')
  if (zone > 0) t = t.slice(0, zone)
  return v6Host(t) !== null
}

const URL_AUTHORITY_END = ' \t\n\r/?#\\"\'<>`(){}|^,;'

// Any IP literal in free text: dotted quads; IPv6 candidates (runs of hex digits, ':' and '.', with >= 2 colons and
// a hex digit, not glued to a word on an alphanumeric edge, so std::vector is not one); URL hosts after WHATWG
// normalization (a decimal, hex or short IPv4 host becomes a dotted quad). allowLoopback exempts the 127/8 block and ::1 (message text only).
export function hasIp(s: string, allowLoopback: boolean): boolean {
  const quad = someRun(s, V4, (a, b) => {
    let x = a, y = b
    while (x < y && s[x] === '.') x++
    while (y > x && s[y - 1] === '.') y--
    if (y - x < 7 || y - x > 15) return false
    const t = s.slice(x, y)
    return isQuad(t) && !(allowLoopback && isLoopback(t))
  })
  if (quad) return true
  const v6 = someRun(s, V6, (a, b) => {
    if (b - a > 80) return false
    if (is(s.charCodeAt(a), HEX) && a > 0 && is(s.charCodeAt(a - 1), WORD)) return false
    if (is(s.charCodeAt(b - 1), HEX) && b < s.length && is(s.charCodeAt(b), WORD)) return false
    let x = a, y = b
    while (y > x && s[y - 1] === '.') y--
    if (y - x >= 2 && s[y - 1] === ':' && s[y - 2] !== ':') y--
    while (x < y && s[x] === '.') x++
    if (y - x >= 2 && s[x] === ':' && s[x + 1] !== ':') x++
    let colons = 0, hex = false
    for (let i = x; i < y; i++) { const c = s.charCodeAt(i); if (c === 58) colons++; else if (c !== 46) hex = true }
    if (colons < 2 || !hex) return false
    const host = v6Host(s.slice(x, y))
    return host !== null && !(allowLoopback && isLoopback(host))
  })
  if (v6) return true
  for (let k = s.indexOf('://'); k !== -1; k = s.indexOf('://', k + 3)) {
    let e = k + 3
    while (e < s.length && e - k < 300 && !URL_AUTHORITY_END.includes(s[e])) e++
    let auth = s.slice(k + 3, e)
    const at = auth.lastIndexOf('@')
    if (at >= 0) auth = auth.slice(at + 1)
    if (auth === '') continue
    let host: string
    try { host = new URL(`http://${auth}/`).hostname } catch { continue }
    if ((isQuad(host) || host.startsWith('[')) && !(allowLoopback && isLoopback(host))) return true
  }
  return false
}

// ---- the structural check ---------------------------------------------------------------------------------------
function structuralKeyLike(s: string): boolean {
  return hasHexRun(s, (n) => n >= 64) || hasBase58Run(s, (n) => n >= 87) || hasByteArray(s, (n) => n >= 32)
    || AGE_PREFIX.test(s) || hasBip39Run(s) || s.includes('://') || ONION.test(s)
}

// A field label is echoed only when it is a plain dotted path of short words (a key name from a request body could
// itself be a secret).
const LABEL = /^[A-Za-z][A-Za-z0-9]{0,23}(?:\.[A-Za-z][A-Za-z0-9]{0,23}){0,4}$/
const labelOf = (field: string): string => (typeof field === 'string' && LABEL.test(field) ? field : 'a field')

export function assertNoSecretOrIp(s: string, field: string): void {
  const text = typeof s === 'string' ? s : String(s)
  const noIp = !hasIp(text, false)
  if (!noIp) refuse('job.ip-like', `${labelOf(field)} holds an IP address literal (the value is not echoed)`) // @guard:job.ip-like
  const noKey = !structuralKeyLike(text)
  if (!noKey) refuse('job.key-like', `${labelOf(field)} looks like a key or secret (64 hex, a 64-byte base58 or byte array, an age key, a BIP-39 phrase), a URL or an onion host (the value is not echoed)`) // @guard:job.key-like
}

// cli/src/ops/logs.ts — `vt logs relay|api|page|vite [--network N] [-n N] [-f]` (canonical vt spec §8; plan Task C3).
// Orchestration (unsandboxed). Prints the last N lines (default 50) of $VT_HOME/<network>/logs/<name>.log, the log
// `vt up` tees each window to; -f then follows it (polling; a log `vt up` rotated is reopened from its start) until
// Ctrl-C. The file is opened without following a symlink and must be a regular file.
//
// ★★ NEVER PRINT AN IP ADDRESS (Global Constraints). The servers never log one (spec §3.2); this command does not
//   trust that, and its redaction FAILS CLOSED (security review of C3/C4: a regex of one address shape was a parser
//   differential). Every line goes through renderLogLine, on its raw bytes, in this order:
//   1. decodeLine: valid UTF-8 decodes as is. A byte that is not part of a valid sequence becomes a lone surrogate
//      U+DC80+byte ("surrogateescape"; a valid decode never yields one) and is printed as the text \xNN at the end:
//      an undecodable line is printed escaped, never raw;
//   2. stripTerminal: every escape sequence (ESC [ … CSI, ESC ] … OSC, DCS/SOS/PM/APC strings, two-byte ESC forms,
//      the C1 equivalents) and every other control, format, line- or paragraph-separator, default-ignorable or
//      unassigned character (\p{Cc} \p{Cf} \p{Zl} \p{Zp} \p{Default_Ignorable_Code_Point} \p{Cn}; a tab stays) is
//      REMOVED before anything is matched. A line can then neither hide, move or
//      rewrite text on the terminal (colour codes, cursor moves, \r, backspace, bidi overrides, zero-width
//      characters), nor split an address so that the matching misses it while the screen still shows it;
//   3. redactIps, with a real parser deciding (node:net isIP, and WHATWG URL, the parser fetch uses):
//      · host contexts first: the host after `://`, `@`, `Host:` / `host=` (also quoted, any case) is printed as
//        [ip] whenever it is numeric in ANY form a resolver accepts: dotted quad, 0x7f.1, 0177.0.0.1, 127.1, a
//        32-bit decimal (2130706433), a trailing dot, percent-encoded or full-width digits, [IPv6] including the
//        IPv4-mapped/compatible forms ([::ffff:7f00:1]), an unbracketed IPv6 (host=2001:db8::1);
//      · then every candidate token: a run of hex digits (and 0x prefixes), Unicode numbers, ASCII/full-width/ideographic dots and
//        colons, brackets, combining marks, undecodable bytes and %-segments (zone ids, percent-encoding). It is
//        normalised (undecodable bytes and marks dropped, NFKC, ideographic dots and other Unicode digits mapped to
//        ASCII, brackets dropped; checked both as written and with ASCII %XX decoded, % being a separator) and the
//        WHOLE run is printed as [ip] when any part of it is an address: a dotted quad anywhere in it (also glued
//        to other digits, inside a longer dotted run, before a trailing dot or a port), a dotted form with a 0x part
//        or 4 parts that WHATWG reads as IPv4 (0x7f.0.0.1, 0177.0.0.01), or any 2+-colon stretch of at most 45
//        characters node:net reads as IPv6 (so before a :port, inside brackets, after a zone id, IPv4-mapped).
//        Outside host contexts a plain number (an amount, 2130706433, 127.1), a port, a timestamp, a 0x+64-hex or
//        bare-hex txid, a txid:vout outpoint, a digest, a base58 signature or a MAC-like string stays as it is.
//      Loopback is an address too: 127.0.0.1 and ::1 are redacted like any other (one rule, no exception to get
//      wrong; vt's own messages, not logs, name the loopback ports);
//      Redaction runs twice over: first on the decoded text, where an undecodable byte is transparent (an address
//      split by one is found), then on the EXACT text that will be printed, where each undecodable byte is its four
//      characters \xNN (security review C4 I-1: the two hex digits of a rendered byte can complete an address with
//      their neighbours, 0x80-0x99 even as decimal digits), again and again until nothing changes;
//   4. a second, independent check on that same printed text (other tokenisation, same parsers): assertNoControl
//      (vt.log-control) and assertNoAddress (vt.log-ip). If either finds anything, the line is held back (a fixed
//      notice is printed instead), never printed. The text checked is the text returned.
//   A line longer than 64 KiB is withheld whole (a fixed notice with its length).
import type { Network } from '@vault-timelock/core/contracts'
import { assertNetwork, isRefusal, refuse } from '@vault-timelock/core/contracts'
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs'
import { isIP } from 'node:net'
import { join } from 'node:path'
import { UsageError } from '../args.ts'
import type { Env } from './paths.ts'
import { stateDir, vtHome } from './paths.ts'
import { isLogName } from './stack.ts'
import type { WindowName } from './stack.ts'

export const DEFAULT_LINES = 50
const TAIL_CAP = 4 * 1024 * 1024
const USAGE = 'usage: vt logs relay|api|page|vite [--network local|testnet|mainnet] [-n N] [-f]'

export function parseLogsArgs(args: readonly string[]): { name: WindowName; lines: number; follow: boolean } {
  const [name, ...rest] = args
  if (!isLogName(name)) throw new UsageError(USAGE)
  let lines: number | null = null
  let follow = false
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]
    if (a === '-f' && !follow) follow = true
    else if (a === '-n' && lines === null && /^[1-9][0-9]{0,4}$/.test(rest[i + 1] ?? '')) lines = Number(rest[++i])
    else throw new UsageError(USAGE)
  }
  return { name, lines: lines ?? DEFAULT_LINES, follow }
}

// ---- 1. bytes -> text (surrogateescape)

// The length of the valid UTF-8 sequence at b[i], or 0 (overlong forms, surrogates and code points above U+10FFFF are
// invalid, as for a fatal TextDecoder).
function utf8SeqLen(b: Uint8Array, i: number): number {
  const c = b[i]
  if (c < 0x80) return 1
  const n = c >= 0xc2 && c <= 0xdf ? 2 : c >= 0xe0 && c <= 0xef ? 3 : c >= 0xf0 && c <= 0xf4 ? 4 : 0
  if (n === 0 || i + n > b.length) return 0
  for (let k = 1; k < n; k++) if ((b[i + k] & 0xc0) !== 0x80) return 0
  if ((c === 0xe0 && b[i + 1] < 0xa0) || (c === 0xed && b[i + 1] >= 0xa0) || (c === 0xf0 && b[i + 1] < 0x90) || (c === 0xf4 && b[i + 1] >= 0x90)) return 0
  return n
}
const STRICT = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
export function decodeLine(b: Uint8Array): string {
  try { return STRICT.decode(b) } catch { /* not valid UTF-8: byte by byte below */ }
  let s = ''
  for (let i = 0; i < b.length;) {
    const n = utf8SeqLen(b, i)
    if (n > 0) {
      s += Buffer.from(b.subarray(i, i + n)).toString('utf8')
      i += n
    } else {
      s += String.fromCharCode(0xdc00 + b[i]) // b[i] >= 0x80 here: an ASCII byte is always valid
      i++
    }
  }
  return s
}
const UNDECODABLE = /[\uDC80-\uDCFF]/gu
const renderUndecodable = (s: string): string => s.replace(UNDECODABLE, (c) => `\\x${(c.charCodeAt(0) - 0xdc00).toString(16).padStart(2, '0')}`)

// ---- 2. terminal control sequences and characters

// ESC [ … (CSI), ESC ] … BEL|ST (OSC), ESC P|X|^|_ … ST (DCS, SOS, PM, APC), ESC + intermediates + final; the C1 forms
// (CSI U+009B, DCS/SOS/OSC/PM/APC U+0090 U+0098 U+009D U+009E U+009F). An unterminated one is removed to the end of
// what it could span; whatever is left of it is a control character removed below.
const ESCAPES = /\u001b(?:\[[0-?]*[ -/]*[@-~]?|\][^\u0007\u001b\u009c]*(?:\u0007|\u001b\\|\u009c)?|[PX^_][^\u001b\u009c]*(?:\u001b\\|\u009c)?|[ -/]*[0-~]?)|\u009b[0-?]*[ -/]*[@-~]?|[\u0090\u0098\u009d\u009e\u009f][^\u001b\u009c]*(?:\u001b\\|\u009c)?/gu
const CONTROLS = /(?!\t)[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\p{Cn}]/gu
export const stripTerminal = (s: string): string => s.replace(ESCAPES, '').replace(CONTROLS, '')

// ---- 3. redaction

// Unicode dots and colons resolvers (UTS 46 / NFKC) read as `.` and `:`.
const DOTS = '．。｡․﹒'
const COLONS = '：﹕︓'
// A non-ASCII decimal digit's value: its distance from the start of its run of ten (digit blocks are contiguous).
function digitValue(c: string): string {
  let cp = c.codePointAt(0) ?? 0
  let v = 0
  while (v < 9 && /\p{Nd}/u.test(String.fromCodePoint(cp - 1))) { cp--; v++ }
  return String(v)
}
// The spellings a candidate has for a resolver: undecodable bytes and combining marks dropped, NFKC, Unicode dots,
// colons and decimal digits mapped to ASCII, brackets dropped; then two views, as written and with ASCII %XX decoded,
// each with every remaining % (a zone id's, or a stray one) turned into a separator. Both views are checked, so an
// address hidden by an encoding and one that a %XX would swallow (`50%2` glued to a quad starting `03.`) are both found.
export function candidateViews(s: string): string[] {
  let t = s.replace(UNDECODABLE, '').normalize('NFKC').replace(/\p{M}/gu, '')
  t = t.replace(new RegExp(`[${DOTS}]`, 'gu'), '.').replace(new RegExp(`[${COLONS}]`, 'gu'), ':')
  t = t.replace(/(?![0-9])\p{Nd}/gu, digitValue).replace(/[[\]]/g, '')
  const decoded = t.replace(/%([0-7][0-9A-Fa-f])/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)))
  return [t, decoded].map((v) => v.replace(/%/g, ' '))
}

// True when WHATWG URL reads h as a numeric host: an IPv4 address (in any of its forms) or an [IPv6] one.
export function numericHost(h: string): boolean {
  if (h === '' || /[/?#@\\\s]/u.test(h)) return false
  let host: string
  try { host = new URL(`http://${h}/`).hostname } catch { return false }
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.startsWith('[')
}

const MAX_SEGMENTS = 64
const MAX_V6 = 45 // the longest IPv6 text form (an IPv4-mapped one in full); a longer colon stretch is not one
// A dotted quad anywhere in s, also glued to other digits (`20` + a quad still shows the quad): from any start, three
// groups of 1-3 digits worth at most 255 (leading zeros allowed), each followed by a dot, then a digit.
const QUAD_FROM = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d/y
function dottedQuadInside(s: string): boolean {
  for (let k = 0; k < s.length; k++) {
    QUAD_FROM.lastIndex = k
    const m = QUAD_FROM.exec(s)
    if (m !== null && Number(m[1]) <= 255 && Number(m[2]) <= 255 && Number(m[3]) <= 255) return true
  }
  return false
}
// True when a chunk (ASCII letters, digits, dots and colons only) holds an address anywhere (header, step 3).
function chunkHoldsIp(n: string): boolean {
  if (!/[.:]/.test(n)) return false
  const segs = n.split(':')
  if (segs.length > MAX_SEGMENTS) return true // fails closed
  for (let i = 0; i < segs.length; i++) {
    let len = segs[i].length
    for (let j = i + 1; j < segs.length && len <= MAX_V6; j++) {
      len += 1 + segs[j].length
      if (j - i >= 2 && len <= MAX_V6 + 1 && isIP(segs.slice(i, j + 1).join(':').replace(/\.$/, '')) === 6) return true
    }
  }
  for (const seg of segs) {
    if (!seg.includes('.')) continue
    if (dottedQuadInside(seg)) return true
    const p = seg.replace(/\.$/, '').split('.')
    if ((p.length === 4 || p.some((x) => /^0x/i.test(x))) && numericHost(seg)) return true
  }
  return false
}
// True when any view of s, in any of its chunks, holds an address.
export function holdsIp(s: string): boolean {
  return candidateViews(s).some((v) => v.split(/[^0-9A-Za-z.:]+/).some(chunkHoldsIp))
}

const RUN = new RegExp(`(?:0[xX]|[\\p{Hex_Digit}\\p{N}\\p{M}.:[\\]${DOTS}${COLONS}\\uDC80-\\uDCFF]|%[0-9A-Za-z._~-]*)+`, 'gu')
const SEPARATOR = new RegExp(`[.:%${DOTS}${COLONS}]`, 'u')
function redactRuns(s: string): string {
  return s.replace(RUN, (m) => (SEPARATOR.test(m) && holdsIp(m) ? '[ip]' : m))
}

// Host contexts: the marker, then the host token (bracketed, an unbracketed IPv6 run, or up to a port/terminator).
// Cfix4 (C4 review m1): also the special-scheme spellings without `://` (`http:\\h`, `http:/h`, `https:h`: WHATWG URL reads them
// all as a host), a scheme-relative `//h`, and the key names `hostname`, `addr`/`address`, `ip`, `peer`, `remote(Address)`.
const HOST_MARK = /\b(?:https?|wss?|ftp|file):[\\/]*|:\/\/|\/\/|@|(?<![A-Za-z0-9])(?:host(?:name)?|addr(?:ess)?|ip|peer|remote[_-]?(?:addr(?:ess)?)?)["']?\s*[:=]\s*["']?/giu
const HOST_END = new RegExp(`[\\s/?#@,;"'<>(){}[\\]\\\\|^\`]`, 'u')
const COLON = new RegExp(`[:${COLONS}]`, 'u')
const MAX_HOST = 512 // longer than any host name; the run scan below still sees whatever follows
function hostToken(s: string, at: number): string {
  if (s[at] === '[') {
    const close = s.indexOf(']', at)
    if (close > at) return s.slice(at, close + 1)
  }
  let end = at
  const stop = Math.min(s.length, at + MAX_HOST)
  while (end < stop && !HOST_END.test(s[end])) end++
  const full = s.slice(at, end)
  const colon = full.search(COLON)
  if (colon < 0) return full
  // An unbracketed IPv6 (host=2001:db8::1) keeps its colons; anything else ends at the port.
  return holdsIp(full) && (full.match(/[:：﹕︓]/gu) ?? []).length >= 2 ? full : full.slice(0, colon)
}
// Whether a host token is an address, remembered per token text for the duration of one scan: a line of many marks
// repeats the same tokens (bounded work, Cfix4: the check now runs twice, once to redact and once to verify).
function hostChecker(): (token: string) => boolean {
  const memo = new Map<string, boolean>()
  return (token) => {
    if (token === '') return false
    let v = memo.get(token)
    if (v === undefined) { v = numericHost(token) || holdsIp(token); memo.set(token, v) }
    return v
  }
}
function redactHosts(s: string): string {
  let out = ''
  let from = 0
  const isAddress = hostChecker()
  for (const m of s.matchAll(HOST_MARK)) {
    const at = (m.index ?? 0) + m[0].length
    if (at < from) continue
    const token = hostToken(s, at)
    if (isAddress(token)) {
      out += `${s.slice(from, at)}[ip]`
      from = at + token.length
    }
  }
  return out + s.slice(from)
}

// Redaction of a line already decoded and stripped of terminal controls (renderLogLine runs the whole pipeline).
export const redactIps = (line: string): string => redactRuns(redactHosts(line))

// ---- 4. the independent check on what is about to be printed

export function assertNoControl(s: string): void {
  const ok = !/(?!\t)[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\p{Cn}\p{Cs}]/u.test(s)
  if (!ok) refuse('vt.log-control', 'a log line still held a control or format character after it was cleaned; it was not printed') // @guard:vt.log-control
}
function tokenLeaks(tok: string): boolean {
  for (const m of tok.matchAll(/(?::\/\/|@)([^/?#@]*)/gu)) {
    const host = m[1].startsWith('[') ? m[1].slice(0, m[1].indexOf(']') + 1) : m[1].split(COLON)[0]
    if (numericHost(host)) return true
  }
  return holdsIp(tok)
}
// A host context (redactHosts' marks) whose host token is an address, in what is about to be printed.
function hostContextLeaks(s: string): boolean {
  const isAddress = hostChecker()
  for (const m of s.matchAll(HOST_MARK)) if (isAddress(hostToken(s, (m.index ?? 0) + m[0].length))) return true
  return false
}
export function assertNoAddress(s: string): void {
  const ok = !hostContextLeaks(s) && !s.split(/[\s,;"'<>(){}=|`^]+/u).some((tok) => tok !== '' && tokenLeaks(tok))
  if (!ok) refuse('vt.log-ip', 'a log line still looked like it held an address after redaction; it was not printed') // @guard:vt.log-ip
}

export const LINE_HELD_BACK = '[vt logs: line withheld: it failed the check after redaction]'
// A longer line is not printed at all (it bounds the cost of the checks; the servers' lines are short).
export const MAX_LINE = 64 * 1024
const MAX_REDACTIONS = 8
// One raw log line (no newline) -> the text printed for it. `redact` is replaceable for tests only (to prove step 4).
export function renderLogLine(raw: Uint8Array, redact: (s: string) => string = redactIps): string {
  if (raw.length > MAX_LINE) return `[vt logs: line withheld: ${raw.length} bytes, longer than ${MAX_LINE}]`
  // Step 3 on the decoded text, then the printed form (undecodable bytes as \xNN), redacted until it is stable.
  let printed = renderUndecodable(redact(stripTerminal(decodeLine(raw))))
  for (let i = 0; i < MAX_REDACTIONS; i++) {
    const next = redact(printed)
    if (next === printed) break
    printed = next
  }
  // Step 4 on exactly what is returned.
  try {
    assertNoControl(printed)
    assertNoAddress(printed)
  } catch (e) {
    if (isRefusal(e)) return LINE_HELD_BACK
    throw e
  }
  return printed
}

// ---- reading

interface Chunk { ino: number; size: number; bytes: Buffer }
// Bytes [from, min(size, from + cap)) of a regular file, never through a symlink. null: missing or not a regular file.
function readFrom(path: string, from: number, cap: number): Chunk | null {
  let fd: number
  try { fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK) } catch { return null }
  try {
    const st = fstatSync(fd)
    if (!st.isFile()) return null
    const start = Math.min(from, st.size)
    const len = Math.min(st.size - start, cap)
    const buf = Buffer.alloc(len)
    let off = 0
    while (off < len) {
      const r = readSync(fd, buf, off, len - off, start + off)
      if (r === 0) break
      off += r
    }
    return { ino: st.ino, size: start + off, bytes: buf.subarray(0, off) }
  } catch {
    return null
  } finally {
    closeSync(fd)
  }
}

// Complete lines of `bytes` (split on LF, which no multi-byte UTF-8 sequence contains) and the unterminated rest.
function splitLines(bytes: Buffer): { lines: Buffer[]; rest: Buffer } {
  const lines: Buffer[] = []
  let start = 0
  for (let i = bytes.indexOf(0x0a); i >= 0; i = bytes.indexOf(0x0a, start)) {
    lines.push(bytes.subarray(start, i))
    start = i + 1
  }
  return { lines, rest: bytes.subarray(start) }
}

export interface LogsDeps {
  out: (text: string) => void
  err: (line: string) => void
  sleep: (ms: number) => Promise<void>
  pollMs: number
  stop: () => boolean   // -f ends when this returns true (tests); by default only Ctrl-C ends it
}

export async function logs(o: { network: Network; env: Env; name: WindowName; lines: number; follow: boolean }, deps: Partial<LogsDeps> = {}): Promise<number> {
  const d: LogsDeps = {
    out: (t) => { process.stdout.write(t) },
    err: (l) => { process.stderr.write(`${l}\n`) },
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    pollMs: 250,
    stop: () => false,
    ...deps,
  }
  assertNetwork(o.network)
  const show = (lines: readonly Buffer[]): void => {
    if (lines.length > 0) d.out(lines.map((l) => `${renderLogLine(l)}\n`).join(''))
  }
  const path = join(stateDir(vtHome(o.env), o.network), 'logs', `${o.name}.log`)
  const head = readFrom(path, 0, 0)
  if (head === null) {
    d.err(`vt logs: no ${o.name} log for ${o.network} yet (vt up --network ${o.network})`)
    return 1
  }
  const from = Math.max(0, head.size - TAIL_CAP)
  const first = readFrom(path, from, TAIL_CAP) ?? { ino: head.ino, size: head.size, bytes: Buffer.alloc(0) }
  let ino = first.ino
  let offset = first.size
  const split = splitLines(first.bytes)
  let rest = split.rest
  if (from > 0) split.lines.shift() // a cut first line
  show(split.lines.slice(-o.lines))
  if (!o.follow) {
    if (rest.length > 0) show([rest])
    return 0
  }
  while (!d.stop()) {
    await d.sleep(d.pollMs)
    let c = readFrom(path, offset, TAIL_CAP)
    if (c === null) continue
    if (c.ino !== ino || c.size < offset) {
      ino = c.ino
      offset = 0
      rest = Buffer.alloc(0)
      d.out(`--- ${o.name} log restarted ---\n`)
      c = readFrom(path, 0, TAIL_CAP)
      if (c === null) continue
    }
    offset = c.size
    const s = splitLines(Buffer.concat([rest, c.bytes]))
    rest = s.rest
    show(s.lines)
  }
  return 0
}

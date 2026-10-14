// The keystore passphrase (spec C 5): read from the terminal only, and judged by one rule.
//
// ★★ /dev/tty ONLY. readPassphrase opens /dev/tty itself; it never reads stdin, argv or the environment, so a
//   passphrase can't arrive through a pipe, a shell history, `ps` or a crash dump of the env. No controlling terminal
//   (a cron job, a detached process, a CI runner) refuses passphrase.no-tty: there is no fallback.
// ★ Echo off: the terminal goes into raw mode (tty.ReadStream.setRawMode on the opened fd) BEFORE the prompt is
//   printed, so nothing typed after the prompt is ever echoed; the mode is restored in a `finally`, refusal or not.
//   Raw mode also turns off the terminal's own line editing and Ctrl-C, so this reader does them: Enter (CR or LF)
//   ends the line, Backspace (DEL or BS) removes one character (UTF-8 aware), Ctrl-U clears the line, and Ctrl-C,
//   Ctrl-D, end of input or any other control character (an arrow key's ESC sequence, Ctrl-V, ...) aborts
//   (passphrase.aborted). So a passphrase is always printable text, typed the same way here and at `age -d`.
//   With `confirm` it is asked twice; two different entries refuse passphrase.mismatch.
// ★ Never logged, echoed or put in a refusal message. JavaScript strings can't be wiped; the byte buffers are.
//
// checkStrength (spec C 5: at least 6 EFF words or an estimated 80 bits; refuse anything weaker). Task 12b review
// rulings (fix rounds 1 and 2): the estimate is the price of the CHEAPEST way to build the passphrase, so a guesser's
// shortcuts count. The passphrase is trimmed and matched in lowercase, and cut into pieces:
//   · an EFF word: log2(7776) = 12.9 bits (t-shirt also matches as tshirt); a word already seen earlier ~1 bit;
//   · a run of non-alphanumeric characters BETWEEN TWO WORDS (spaces, hyphens, dots, ...): free;
//   · any 3+ characters already seen earlier (abc!abc!, aaaa.aaaa): ~1 bit, however long;
//   · one character: ~1 bit if it is a symbol already seen earlier, or a letter/digit equal to the previous letter/digit,
//     next to it in a run (abc, 321) or on a keyboard row (qwerty, asdf, zxcv, 1234); otherwise log2(charset), the
//     charset being the classes present: lowercase 26, uppercase 26, digits 10, symbols 33 (anything else, space and
//     non-ASCII included, counts as a symbol).
// Accept if the fewest list words that make up all the letters and digits are at least 6 DISTINCT words (the explicit
// 6-word rule, 77.5 bits by the list; separators of any kind or none), or if the cheapest price is >= 80 bits.
// So 5 words with any separators, repeats, runs and keyboard rows are weak, while the symbols of a random password
// count as characters: a random 20-character password over all 95 printable characters keeps ~131 bits.
import { closeSync, constants, openSync, writeSync } from 'node:fs'
import { isatty, ReadStream } from 'node:tty'
import { refuse } from '../guard.ts'
import { effWords } from './wordlist.ts'

export interface ReadPassphraseOptions { confirm: boolean; ttyPath?: string }

const PROMPT = 'Passphrase: '
const REPEAT = 'Repeat passphrase: '

// Reads lines from the raw-mode terminal. read(): null = aborted (see the header). wipe(): stop listening and zero the
// bytes typed after the last line (type-ahead), called when reading is over.
function lineReader(rs: ReadStream): { read: () => Promise<string | null>; wipe: () => void } {
  const pending: number[] = []
  let closed = false
  let wake: (() => void) | undefined
  const onData = (chunk: Buffer) => {
    for (const b of chunk) pending.push(b)
    chunk.fill(0)
    wake?.()
  }
  rs.on('data', onData)
  const end = () => { closed = true; wake?.() }
  rs.on('end', end)
  rs.on('close', end)
  rs.on('error', end)
  const wipe = () => {
    rs.off('data', onData)
    pending.fill(0)
    pending.length = 0
  }
  const read = async (): Promise<string | null> => {
    const line: number[] = []
    try {
      for (;;) {
        while (pending.length > 0) {
          const b = pending.shift()!
          if (b === 0x0d || b === 0x0a) {
            const bytes = Uint8Array.from(line)
            try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes) } catch { return null } finally { bytes.fill(0) }
          }
          if (b === 0x7f || b === 0x08) { // erase one character: its continuation bytes, then its lead byte
            while (line.length > 0 && (line[line.length - 1] & 0xc0) === 0x80) line.pop()
            line.pop()
          } else if (b === 0x15) {
            line.fill(0)
            line.length = 0
          } else if (b < 0x20) {
            return null // Ctrl-C, Ctrl-D, ESC, ...
          } else {
            line.push(b)
          }
        }
        if (closed) return null
        await new Promise<void>((res) => { wake = res })
        wake = undefined
      }
    } finally {
      line.fill(0)
    }
  }
  return { read, wipe }
}

export async function readPassphrase(opts: ReadPassphraseOptions): Promise<string> {
  const path = opts.ttyPath ?? '/dev/tty'
  let fd: number | undefined
  try { fd = openSync(path, constants.O_RDWR | constants.O_NOCTTY) } catch { fd = undefined } // ENXIO: no controlling terminal
  if (fd !== undefined && !isatty(fd)) { closeSync(fd); fd = undefined }
  if (fd === undefined) refuse('passphrase.no-tty', 'no controlling terminal: the passphrase is read from /dev/tty only (never stdin, argv or the environment)') // @guard:passphrase.no-tty
  // Prompts go through a second, blocking descriptor (the stream makes its own non-blocking).
  let wfd: number
  try { wfd = openSync(path, constants.O_WRONLY | constants.O_NOCTTY) } catch (e) { closeSync(fd); throw e }
  let rs: ReadStream
  try { rs = new ReadStream(fd) } catch (e) { closeSync(fd); closeSync(wfd); throw e }
  let raw = false
  const reader = lineReader(rs)
  try {
    rs.setRawMode(true)
    raw = true
    const ask = async (prompt: string): Promise<string | null> => {
      writeSync(wfd, prompt)
      const line = await reader.read()
      writeSync(wfd, '\r\n') // raw mode: the Enter was not echoed either
      return line
    }
    const first = await ask(PROMPT)
    const second = opts.confirm && first !== null ? await ask(REPEAT) : first
    if (first === null || second === null) refuse('passphrase.aborted', 'passphrase entry aborted (Ctrl-C, Ctrl-D, end of input, or a control character)') // @guard:passphrase.aborted
    if (first !== second) refuse('passphrase.mismatch', 'the two passphrase entries differ') // @guard:passphrase.mismatch
    return first
  } finally {
    reader.wipe()
    try { if (raw) rs.setRawMode(false) } finally {
      rs.destroy() // closes fd
      closeSync(wfd)
    }
  }
}

// ---- strength

const WORD_BITS = Math.log2(7776)
const CHEAP_BITS = 1 // a repeat, a run, a keyboard neighbour, a symbol or word or piece seen before
const MIN_WORDS = 6
const MIN_BITS = 80
const ALNUM = /[\p{L}\p{N}]/u
const ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890']

function charsetSize(p: string): number {
  let n = 0
  if (/[a-z]/.test(p)) n += 26
  if (/[A-Z]/.test(p)) n += 26
  if (/[0-9]/.test(p)) n += 10
  if (/[^a-zA-Z0-9]/.test(p)) n += 33
  return n
}

// The list as matched: `any` = every word, hyphenated ones also without the hyphen (t-shirt, tshirt), for pricing the
// whole passphrase; `bare` = hyphens removed, for the 6-word rule over the letters and digits alone.
let dictCache: { any: ReadonlySet<string>; bare: ReadonlySet<string>; min: number; max: number } | undefined
function dict(): NonNullable<typeof dictCache> {
  if (dictCache === undefined) {
    const bare = new Set([...effWords()].map((w) => w.replaceAll('-', '')))
    const any = new Set([...effWords(), ...bare])
    const lens = [...any].map((w) => w.length)
    dictCache = { any, bare, min: Math.min(...lens), max: Math.max(...lens) }
  }
  return dictCache
}

// b costs ~1 bit after the letter/digit a: the same character, the next or previous one (abc, 321), or a keyboard-row
// neighbour.
function cheapAfter(a: string, b: string): boolean {
  if (a === b || Math.abs(a.codePointAt(0)! - b.codePointAt(0)!) === 1) return true
  return ROWS.some((r) => { const k = r.indexOf(a); return k >= 0 && (r[k + 1] === b || r[k - 1] === b) })
}

export interface Strength {
  distinctWords: number // distinct list words in the fewest-words reading of all letters and digits; 0 if not all words
  bits: number // the price of the cheapest segmentation
}

// The estimate behind checkStrength (see the header). Exported for tests; it never logs anything.
export function strengthOf(p: string): Strength {
  const { any, bare, min, max } = dict()
  const t = p.trim()
  const perChar = Math.log2(charsetSize(t) || 1)
  const s = [...t].map((c) => (c >= 'A' && c <= 'Z' ? c.toLowerCase() : c))
  const n = s.length
  const alnum = s.map((c) => ALNUM.test(c))
  const piece = (i: number, j: number): string => s.slice(i, j).join('')

  // The 6-word rule: the fewest list words that cover all the letters and digits, and how many are distinct.
  const a = s.filter((_, i) => alnum[i])
  const fewest: number[] = [0]
  const from: number[] = [0]
  for (let j = 1; j <= a.length; j++) {
    fewest[j] = Infinity
    for (let len = min; len <= max && len <= j; len++) {
      const i = j - len
      if (fewest[i] + 1 < fewest[j] && bare.has(a.slice(i, j).join(''))) { fewest[j] = fewest[i] + 1; from[j] = i }
    }
  }
  let distinctWords = 0
  if (a.length > 0 && Number.isFinite(fewest[a.length])) {
    const seen = new Set<string>()
    for (let j = a.length; j > 0; j = from[j]) seen.add(a.slice(from[j], j).join(''))
    distinctWords = seen.size
  }

  // The price: the cheapest segmentation. State 0: after a character or a repeat; 1: right after a word; 2: after a
  // free separator run (only a word may follow it, so the run sits between two words).
  const cost: number[][] = [0, 1, 2].map(() => new Array<number>(n + 1).fill(Infinity))
  cost[0][0] = 0
  const relax = (state: number, j: number, c: number) => { if (c < cost[state][j]) cost[state][j] = c }
  let prevAlnum = -1
  for (let i = 0; i < n; i++) {
    const open = Math.min(cost[0][i], cost[1][i]) // anything may follow
    const prefix = piece(0, i)
    const cheap = alnum[i] ? prevAlnum >= 0 && cheapAfter(s[prevAlnum], s[i]) : prefix.includes(s[i])
    relax(0, i + 1, open + (cheap ? CHEAP_BITS : perChar))
    const beforeWord = Math.min(open, cost[2][i])
    for (let len = min; len <= max && i + len <= n; len++) {
      const w = piece(i, i + len)
      if (any.has(w)) relax(1, i + len, beforeWord + (prefix.includes(w) ? CHEAP_BITS : WORD_BITS))
    }
    for (let j = i; j < n && !alnum[j]; j++) relax(2, j + 1, cost[1][i]) // a separator run after a word
    let rep = piece(i, i + 2)
    for (let j = i + 3; j <= n; j++) { // any 3+ characters seen before: ~1 bit, however long
      rep += s[j - 1]
      if (!prefix.includes(rep)) break
      relax(0, j, open + CHEAP_BITS)
    }
    if (alnum[i]) prevAlnum = i
  }
  return { distinctWords, bits: Math.min(cost[0][n], cost[1][n]) }
}

export function checkStrength(p: string): void {
  const { distinctWords, bits } = strengthOf(p)
  const ok = distinctWords >= MIN_WORDS || bits >= MIN_BITS
  if (!ok) refuse('passphrase.weak', 'the passphrase is too weak: use at least 6 different words of the EFF large wordlist, or about 80 bits of random characters (repeats, runs and keyboard rows count for almost nothing)') // @guard:passphrase.weak
}

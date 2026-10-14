// cli/src/ops/sanitize.ts — what the sandboxed child's output may carry to the operator's real terminal (TTY-less round, ruling (c)).
// The child writes through pipes; the broker (unsandboxed) passes the text through this filter before it reaches the real stdout/stderr, which may be
// a terminal: terminal control sequences are an input channel INTO the terminal (OSC 52 sets the clipboard, DCS/APC carry data, CSI can report and
// move the cursor, title and window ops, and answerback reports can type into the shell). Kept: printable text, newline and tab. Dropped:
//   · ESC sequences of every kind: CSI (ESC [ ... final), OSC / DCS / SOS / PM / APC strings (to BEL or ST, also an unterminated one: everything after
//     it is dropped until a terminator or the end of the stream), two-character ESC sequences; SGR colours are dropped too (nothing in vt prints any);
//   · C0 controls except \n and \t (so \r, BEL, BS, ... are gone; CRLF becomes LF), DEL;
//   · C1 controls (U+0080..U+009F), whose 8-bit forms are CSI (U+009B), OSC (U+009D), DCS (U+0090), SOS, PM, APC.
// The filter is a state machine over decoded text, so a sequence split across chunks is still recognised.
import { StringDecoder } from 'node:string_decoder'

type State = 'text' | 'esc' | 'csi' | 'str' | 'str-esc' | 'esc-inter'

// M-3: Unicode FORMAT characters (category Cf: the bidi controls U+202A-202E, U+2066-2069, U+200E/F, U+061C; zero-width U+200B-200D, U+2060-2064, U+FEFF; soft hyphen;
// the tag characters), the line / paragraph separators, U+3164 (Hangul filler) and the variation selectors would let text be reordered or hidden on a terminal.
const INVISIBLE = /[\p{Cf}\u2028\u2029\u3164\ufe00-\ufe0f\u{e0100}-\u{e01ef}\p{Cn}\p{Co}\p{Cs}\u2800\u115f\u1160\uffa0\u034f\u17b4\u17b5\u180b-\u180f]/u
const WIDE_SPACE = /[\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]/u   // shown as an ordinary space

// N-3: the broker's own lines start with the tag "[vt broker]". Child output (and a detail line) can never carry it: any bracketed text that reads as "vt broker" after
// NFKC folding, removal of spaces / separators and a small confusables fold (Cyrillic / Greek look-alikes) has its brackets turned into parentheses.
const CONFUSABLES: Readonly<Record<string, string>> = { '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u03bf': 'o', '\u0432': 'b', '\u043a': 'k', '\u0442': 't', '\u0433': 'r', '\u03c5': 'u', '\u03c4': 't', '\u03ba': 'k', '\u03c1': 'p', '\u03bd': 'v' }
const fold = (t: string): string => [...t.normalize('NFKC').toLowerCase()].map((c) => CONFUSABLES[c] ?? c).join('').replace(/[^a-z0-9]/g, '')
const OPENERS = '[\\p{Ps}]', CLOSERS = '[\\p{Pe}]'
const BRACKETED = /(?![({])[\[\p{Ps}]((?:[^\n\[\]\p{Ps}\p{Pe}]|[(){}])*)(?![)}])[\]\p{Pe}]/gu   // ASCII ( ) { } are ordinary text; every other open / close bracket counts
void OPENERS; void CLOSERS
// R2-2: ANY bracketed run (ASCII brackets, fullwidth ones, every Unicode open/close punctuation) whose content is not plain ASCII or folds to
// "vt broker" (NFKC, combining marks and separators removed, confusables mapped) has its brackets turned into parentheses. A broker line therefore cannot be imitated.
export function neutralizeTag(text: string): string {
  return text.replace(BRACKETED, (m, inner: string) => {
    const suspicious = /[^\x20-\x7e]/.test(inner) || fold(inner.replace(/\p{M}/gu, '')).startsWith('vtbroker')
    return suspicious ? `(${inner})` : m
  })
}
const HOLD = /(?![({])[\[\p{Ps}](?:[^\n\[\]\p{Ps}\p{Pe}]|[(){}]){0,200}$/u

// True when the environment's locale is a UTF-8 one (LC_ALL, LC_CTYPE, LANG, in that order of precedence). Otherwise the terminal may read bytes >= 0x80 as C1
// controls (a Latin-1 `ě` = C4 9B carries 9B, which is CSI there), so only ASCII is emitted and other characters are shown as \u{hex}.
export function localeIsUtf8(env: Readonly<Record<string, string | undefined>> = process.env): boolean {
  const v = [env.LC_ALL, env.LC_CTYPE, env.LANG].find((x) => x !== undefined && x !== '')
  return v !== undefined && /utf-?8/i.test(v)
}

export class Sanitizer {
  private readonly ascii: boolean
  constructor(ascii: boolean = false) { this.ascii = ascii }
  private state: State = 'text'
  private carry = ''
  private readonly dec = new StringDecoder('utf8')

  push(chunk: Buffer | string): string {
    const text = typeof chunk === 'string' ? chunk : this.dec.write(chunk)
    let out = ''
    for (const ch of text) {
      const c = ch.codePointAt(0) as number
      switch (this.state) {
        case 'text':
          if (c === 0x1b) this.state = 'esc'
          else if (c === 0x9b) this.state = 'csi'
          else if (c === 0x9d || c === 0x90 || c === 0x98 || c === 0x9e || c === 0x9f) this.state = 'str'
          else if (c === 0x0a || c === 0x09 || (c >= 0x20 && c < 0x7f)) out += ch
          else if (WIDE_SPACE.test(ch)) out += ' '
          else if (c >= 0xa0 && !INVISIBLE.test(ch)) out += this.ascii ? `\\u{${c.toString(16)}}` : ch
          break
        case 'esc':
          if (c === 0x5b) this.state = 'csi'                                          // ESC [
          else if (c === 0x5d || c === 0x50 || c === 0x58 || c === 0x5e || c === 0x5f) this.state = 'str'   // ESC ] P X ^ _
          else if (c >= 0x20 && c <= 0x2f) this.state = 'esc-inter'                  // ESC + intermediates, e.g. ESC ( B
          else this.state = 'text'                                                    // a two-character sequence (ESC c, ESC 7, ...)
          break
        case 'esc-inter':
          if (c < 0x20 || c > 0x2f) this.state = 'text'
          break
        case 'csi':
          if (c >= 0x40 && c <= 0x7e) this.state = 'text'                             // the final byte
          else if (c === 0x1b) this.state = 'esc'                                     // a new sequence aborts this one
          break
        case 'str':
          if (c === 0x07 || c === 0x9c) this.state = 'text'                           // BEL or 8-bit ST
          else if (c === 0x1b) this.state = 'str-esc'
          break
        case 'str-esc':
          this.state = c === 0x5c ? 'text' : c === 0x1b ? 'str-esc' : 'str'          // ESC \ = ST; anything else stays inside the string
          break
      }
    }
    return this.tagSafe(out)
  }

  // Output that may be the start of a "[vt broker]" lookalike is held back until the bracket closes, a newline arrives or the stream ends.
  private tagSafe(out: string): string {
    const all = neutralizeTag(this.carry + out)
    const m = HOLD.exec(all)
    if (m === null) { this.carry = ''; return all }
    if ([...m[0]].length > 200) { this.carry = ''; return all.slice(0, m.index) + '(' + all.slice(m.index + 1) }
    this.carry = m[0]
    return all.slice(0, m.index)
  }

  // End of stream: whatever an unterminated sequence held is dropped; a partial UTF-8 character becomes U+FFFD (printable, harmless).
  end(): string {
    const rest = this.dec.end()
    const last = rest === '' ? '' : this.push(rest)
    const held = neutralizeTag(this.carry)
    this.carry = ''
    return last + held
  }
}

// One-shot, for labels and tests.
export function sanitize(text: string, ascii = false): string {
  const s = new Sanitizer(ascii)
  return s.push(text) + s.end()
}

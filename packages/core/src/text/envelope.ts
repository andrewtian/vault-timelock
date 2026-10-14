// Envelope + note validation (moved from broadcast/src/envelope.ts, E6; browser-safe). Single validator for the plain-text note that is
// published on Arweave and on every chain. Nothing is truncated or normalized;
// invalid input is refused.
//   vault-timelock/1 unlock=<YYYY-MM-DDTHH:MM:SSZ>\nar://<arId>\n<note>   (R34: two-line header, 94 B)
import { refuse } from './guard.ts'
import { sha256Hex, utf8 } from './bytes.ts'

export const ENVELOPE_MAX = 4096
export const HEADER_BYTES = 94
export const NOTE_MAX = 4002

export const AR_ID = /^[A-Za-z0-9_-]{43}$/
const UNLOCK = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/
// TextDecoder strips a leading BOM unless ignoreBOM is set; we must see it.
// C0 except \n, DEL, C1, BOM, and U+2028/U+2029 (Task H0: LF is the only line break, spec B s5.0).
const CONTROL = /[\u0000-\u0009\u000B-\u001F\u007F-\u009F\ufeff\u2028\u2029]/u
// All of Unicode's Bidi_Control (Task H0): U+061C, U+200E, U+200F, U+202A-E, U+2066-9.
const BIDI = /\p{Bidi_Control}/u
// Invisible characters a NEW text may not carry (Eminors fix round 1, I-2/I-3): every Default_Ignorable_Code_Point (soft hyphen, U+034F, the Hangul
// fillers U+115F/U+1160/U+3164/U+FFA0, Khmer U+17B4/5, Mongolian selectors, ZWSP/ZWNJ/ZWJ, U+2060-U+206F, variation selectors, the tag characters
// U+E0000-U+E0FFF) PLUS the interlinear annotation characters U+FFF9-U+FFFB (which Unicode leaves out of that property), EXCEPT U+FE0E/U+FE0F: the
// text/emoji presentation selectors hide nothing ("love ❤️" is fine). Bidi controls and the BOM are in the set too; they have their own ids.
// checkPayload (exact mode) and validateNote use this one set, so buildEnvelope never builds a text checkPayload refuses.
export const INVISIBLE_NEW = /(?![\uFE0E\uFE0F])[\p{Default_Ignorable_Code_Point}\u{FFF9}-\u{FFFB}]/u
const EDGE_WS = /^\s|\s$/u

export const isAscii = (s: string): boolean => /^[\u0000-\u007f]*$/.test(s)

export function validateNote(raw: Uint8Array): string {
  if (raw.length === 0) refuse('note.empty', 'note is empty') // @guard:note.empty
  let s = ''
  try { s = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw) } catch { refuse('note.utf8', 'note is not valid UTF-8') } // @guard:note.utf8
  if (s.includes('\ufffd')) refuse('note.replacement', 'note contains U+FFFD') // @guard:note.replacement
  if (CONTROL.test(s)) refuse('note.control', 'note contains a control character, DEL, C1, BOM or a U+2028/U+2029 separator') // @guard:note.control
  if (BIDI.test(s)) refuse('note.bidi', 'note contains a bidirectional control character') // @guard:note.bidi
  if (EDGE_WS.test(s)) refuse('note.whitespace', 'note has leading or trailing whitespace') // @guard:note.whitespace
  if (s.normalize('NFC') !== s) refuse('note.nfc', 'note is not NFC-normalized') // @guard:note.nfc
  if (raw.length > NOTE_MAX) refuse('note.too-long', `note exceeds ${NOTE_MAX} bytes`) // @guard:note.too-long
  return s
}

function unlockOk(u: string): boolean {
  if (!UNLOCK.test(u)) return false
  const d = new Date(u)
  if (Number.isNaN(d.getTime())) return false
  return d.toISOString().replace('.000Z', 'Z') === u
}

export function buildEnvelope(
  a: { arId: string; unlock: string; note: string },
  maxBytes = ENVELOPE_MAX,
  invisible = true,                       // false only when READING an older text (Open, payload.ts): the rule is for NEW texts
): { arId: string; unlock: string; note: string; bytes: Uint8Array; sha256: string } {
  if (!AR_ID.test(a.arId)) refuse('envelope.ar-id', 'ar id must match [A-Za-z0-9_-]{43}') // @guard:envelope.ar-id
  if (!unlockOk(a.unlock)) refuse('envelope.unlock', 'unlock must be a valid YYYY-MM-DDTHH:MM:SSZ instant') // @guard:envelope.unlock
  validateNote(utf8(a.note))
  if (invisible && INVISIBLE_NEW.test(a.note)) refuse('note.invisible', 'note contains a zero-width or invisible format character (U+FE0E / U+FE0F excepted)') // @guard:note.invisible
  const bytes = utf8(`vault-timelock/1 unlock=${a.unlock}\nar://${a.arId}\n${a.note}`)
  if (bytes.length > maxBytes) refuse('envelope.too-long', `envelope exceeds ${maxBytes} bytes`) // @guard:envelope.too-long
  return { arId: a.arId, unlock: a.unlock, note: a.note, bytes, sha256: sha256Hex(bytes) }
}

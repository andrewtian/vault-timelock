// packages/core/src/job/message.ts — the message rules (spec §4.1, R50 + R72, controller ruling 3). The text is
// refused, never rewritten: no normalization, no line-ending conversion, no trimming.
//
// Checks, in order (each a one-line guard):
//   message.empty     ''
//   message.utf8      not a string, a lone surrogate, or U+FFFD (the mark a lossy decoder leaves: bytes must be
//                     decoded with TextDecoder('utf-8', { fatal: true, ignoreBOM: true }), Task 0 ruling 7)
//   message.too-long  more than MESSAGE_MAX (16 MiB) UTF-8 bytes
//   message.control   any C0/C1 control except LF (so CR and TAB too), DEL, bidi controls (ALM, LRM, RLM, LRE..RLO,
//                     LRI..PDI), U+2028/U+2029 (line breaks other than LF) and U+FEFF (BOM) anywhere
//   message.nfc       not in Unicode NFC
//   message.secret    the unambiguous secret shapes (keylike.ts): age secret key data, a base58 run of exactly 87 or
//                     88 characters, a JSON array of exactly 64 byte values, >= 12 consecutive BIP-39 words
//   message.ip-like   an IPv4 or IPv6 literal, bare or as a URL host. Loopback (the 127/8 block, ::1) is exempt: it
//                     identifies no one, and broadcast's SEALED.txt open steps name Tor's SOCKS port on it.
// Accepted text returns its UTF-8 size, its sha256 and warnings: 'hex64' when a bare 64-hex token appears (it may be a
// private key; the UI says "if this is a private key, do not publish"). Hashes and URLs are publication text.
import { MESSAGE_MAX, refuse } from '../contracts/index.ts'
import { sha256Hex } from './canonical.ts'
import { AGE_KEY, hasBase58Run, hasBip39Run, hasByteArray, hasHexRun, hasIp } from './keylike.ts'

export interface MessageInfo { bytes: number; sha256: string; warnings: Array<'hex64'> }

const CONTROL = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029\ufeff]/

// UTF-8 length, or -1 when the string holds a lone surrogate (it has no UTF-8 form).
function utf8Length(s: string): number {
  let n = 0
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 0x80) n += 1
    else if (c < 0x800) n += 2
    else if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1)
      if (!(d >= 0xdc00 && d <= 0xdfff)) return -1
      n += 4; i++
    } else if (c >= 0xdc00 && c <= 0xdfff) return -1
    else n += 3
  }
  return n
}

function hasSecret(s: string): boolean {
  return AGE_KEY.test(s) || hasBase58Run(s, (n) => n === 87 || n === 88) || hasByteArray(s, (n) => n === 64) || hasBip39Run(s)
}

export function validateMessage(text: string): MessageInfo {
  const nonEmpty = text !== ''
  if (!nonEmpty) refuse('message.empty', 'the message is empty') // @guard:message.empty
  const isText = typeof text === 'string'
  const long = isText && text.length > MESSAGE_MAX // >= 1 byte per UTF-16 unit: certainly too long, not scanned
  const bytes = isText && !long ? utf8Length(text) : -1
  const wellFormed = isText && (long || (bytes >= 0 && !text.includes('�')))
  if (!wellFormed) refuse('message.utf8', 'the message is not valid UTF-8 text (a lone surrogate, or U+FFFD from a lossy decode: decode with TextDecoder fatal: true, ignoreBOM: true)') // @guard:message.utf8
  const fits = !long && bytes <= MESSAGE_MAX
  if (!fits) refuse('message.too-long', `the message is over ${MESSAGE_MAX} UTF-8 bytes`) // @guard:message.too-long
  const plain = !CONTROL.test(text)
  if (!plain) refuse('message.control', 'the message holds a control character (only LF line breaks; no CR, TAB, bidi controls, line/paragraph separators or BOM)') // @guard:message.control
  const nfc = text.normalize('NFC') === text
  if (!nfc) refuse('message.nfc', 'the message is not in Unicode NFC; it is refused, never rewritten') // @guard:message.nfc
  const noSecret = !hasSecret(text)
  if (!noSecret) refuse('message.secret', 'the message holds a secret (an age secret key, a 64-byte base58 token or byte array, or a BIP-39 phrase); the text is not echoed') // @guard:message.secret
  const noIp = !hasIp(text, true)
  if (!noIp) refuse('message.ip-like', 'the message holds an IP address literal; the text is not echoed') // @guard:message.ip-like
  return { bytes, sha256: sha256Hex(text), warnings: hasHexRun(text, (n) => n === 64) ? ['hex64'] : [] }
}

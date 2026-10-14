// age ASCII armor, byte-compatible with `age -a`:
//   header line, standard base64 (padded) in 64-column lines, footer line, all "\n".
// dearmor is strict and canonical: armor(dearmor(t)) === t, otherwise refused.
// Moved from broadcast/src/armor.ts (E6); Buffer replaced by bytes.ts.
import { refuse } from './guard.ts'
import { b64decode, b64encode } from './bytes.ts'

const HEADER = '-----BEGIN AGE ENCRYPTED FILE-----\n'
const FOOTER = '-----END AGE ENCRYPTED FILE-----\n'

export function armor(bin: Uint8Array): string {
  const b64 = b64encode(bin)
  let body = ''
  for (let i = 0; i < b64.length; i += 64) body += b64.slice(i, i + 64) + '\n'
  return HEADER + body + FOOTER
}

export function dearmor(text: string): Uint8Array {
  // Decode leniently (newlines dropped), then demand the exact canonical re-encoding. Any CRLF,
  // wrong line width, bad alphabet/padding, missing header/footer or trailing bits changes the
  // re-encoding, so one equality check is the whole parser.
  let bin: Uint8Array = new Uint8Array(0)
  if (text.startsWith(HEADER) && text.endsWith(FOOTER) && text.length >= HEADER.length + FOOTER.length) {
    bin = b64decode(text.slice(HEADER.length, text.length - FOOTER.length).replace(/\n/g, '')) ?? new Uint8Array(0)
  }
  if (bin.length === 0 || armor(bin) !== text) refuse('armor.malformed', 'not canonical age ASCII armor') // @guard:armor.malformed
  return bin
}

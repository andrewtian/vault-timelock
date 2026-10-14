// A SEALED.txt (bare, or inside a published text): dispatched on its `format:` line, then opened along its chain.
//   vault-timelock-sealed/1: the ONE parser (payload.ts sealedFiles: every block de-armored and checked against its [file] line —
//   bytes and sha256 — and the whole structure checked as Open checks it), then
//     two-layer   unlock-TIME.age (tlock → the one-time identity) → vault.tar.gz.age (X25519) → identity.key + vault.tar.gz;
//                 or, given an identity (the one-time key, e.g. recovered with the recovery key from unlock-KEY.age), straight
//                 vault.tar.gz.age → vault.tar.gz, at any time;
//     vault / secret / payload   the one tlock layer → vault.tar.gz / secret.tar.gz / content(.tar.gz).
//   Any other format value is refused decrypt.format (a v2 "index + blocks" text gets its own reader beside v1, behind the same
//   DecryptResult and ArchiveSource).
import { sha256Hex, utf8 } from '../text/bytes.ts'
import { unlockIso } from '../text/drand.ts'
import { isRefusal } from '../text/guard.ts'
import { sealedFiles } from '../text/payload.ts'
import { parseTlockStanza } from '../text/sealed-from.ts'
import type { ArchiveLimits, ArchiveSource, BlockInfo, DecryptHow, DecryptLimits, DecryptResult, DecryptedFile, OpenedVia, SealedLayout } from './api.ts'
import { SEALED_FORMATS } from './api.ts'
import { SEALED_TITLE, ageInfo, openAge, parseIdentities } from './age.ts'
import { tarGzSource } from './archive.ts'
import { refuseFormat, refuseKind } from './refuse.ts'
import { isGzip } from './tar.ts'

const FORMAT_LINE = /^format: ([!-~]{1,64})$/
const ROUND_LINE = /^unlock-after: [^\n]*\(drand round ([1-9]\d{0,15})\)$/m
const KEY_ONLY_LINE = /^contents: key-only \(payload: ar:\/\/([A-Za-z0-9_-]{43})\)$/m
const AGE_KEY = /^AGE-SECRET-KEY-1[0-9A-Z]+$/

export interface SealedText {
  readonly format: string
  readonly layout: SealedLayout
  readonly contents: 'full' | 'key-only'
  readonly arId: string | null
  readonly round: number
  readonly chainHash: string
  readonly files: ReadonlyMap<string, Uint8Array>
  readonly blocks: readonly BlockInfo[]
  readonly tlockName: string
}

/** The `format:` value right after the SEALED.txt title line; one this build opens, or decrypt.format. */
export function sealedFormat(text: string): string {
  const lines = text.split('\n')
  const t = lines.indexOf(SEALED_TITLE)
  if (t < 0) refuseFormat('no SEALED.txt title line')
  const m = FORMAT_LINE.exec(lines[t + 1] ?? '')
  if (m === null) refuseFormat('the SEALED.txt title line is not followed by its format: line')
  if (!SEALED_FORMATS.includes(m[1])) refuseFormat(`SEALED.txt format "${m[1]}" is not one this build opens (it opens ${SEALED_FORMATS.join(', ')}): update vault-timelock`)
  return m[1]
}

// A bare SEALED.txt has no `vault-timelock/1 unlock=…` and `ar://…` header lines: wrap it in the two lines the parser wants,
// built from the text's own round and key-only id (the page's Open does the same, web/src/lib/open.js asPublished). The parser then
// checks everything, including that the header agrees with the section. A text without a round line is returned unchanged, so the
// parser refuses it.
export function asPublished(text: string): string {
  const round = ROUND_LINE.exec(text)
  if (round === null) return text
  let iso: string
  try { iso = unlockIso(Number(round[1])) } catch { return text }
  const ar = KEY_ONLY_LINE.exec(text)
  return `vault-timelock/1 unlock=${iso}\nar://${ar ? ar[1] : 'A'.repeat(43)}\nopened from a SEALED.txt\n\n${text}`
}

export function readSealed(text: string, form: 'sealed' | 'published'): SealedText {
  const format = sealedFormat(text)
  const published = form === 'sealed' ? asPublished(text) : text
  let files: Map<string, Uint8Array> | null = null
  try { files = sealedFiles(published) } catch (e) {
    if (!isRefusal(e)) throw e
    const ids = e.message.replace(/^not a valid published text: /, '')
    refuseFormat(`not a valid SEALED.txt (${ids.slice(0, 300)}): e.g. a block that differs from its [file] line (bytes or sha256), or an edited text`)
  }
  const names = [...files.keys()]
  const layout: SealedLayout = names.includes('unlock-TIME.age') ? 'two-layer' : names[0] === 'vault.tar.gz.age' ? 'vault' : names[0] === 'secret.tar.gz.age' ? 'secret' : 'payload'
  const tlockName = layout === 'two-layer' ? 'unlock-TIME.age' : names[0]
  const st = parseTlockStanza(files.get(tlockName) ?? new Uint8Array(0))
  if (st === null) refuseFormat(`${tlockName}: no tlock stanza`)
  const ko = KEY_ONLY_LINE.exec(published)
  const blocks = names.map((name) => { const b = files.get(name)!; return { name, size: b.length, sha256: sha256Hex(b) } })
  return { format, layout, contents: ko ? 'key-only' : 'full', arId: ko ? ko[1] : null, round: Number(st.round), chainHash: st.hash, files, blocks, tlockName }
}

export const decrypted = (name: string, bytes: Uint8Array): DecryptedFile => ({ name, bytes, size: bytes.length, sha256: sha256Hex(bytes) })

export async function openSealed(s: SealedText, how: DecryptHow, limits: DecryptLimits, archiveLimits: Partial<ArchiveLimits>): Promise<DecryptResult> {
  const notes: string[] = []
  const files: DecryptedFile[] = []
  let via: OpenedVia = 'timelock'
  const ids = typeof how.identity === 'string' ? parseIdentities(how.identity, limits) : null
  const tlockBin = s.files.get(s.tlockName)!
  if (s.layout === 'two-layer') {
    const vault = s.files.get('vault.tar.gz.age')
    const vaultInfo = () => {
      const vi = ageInfo(vault!, limits, 'vault.tar.gz.age')
      if (vi.kind !== 'identity') refuseFormat('vault.tar.gz.age is not encrypted to an age identity')
      return vi
    }
    if (ids !== null) {
      // the identity path: the one-time key (e.g. recovered from unlock-KEY.age with the recovery key) opens the archive directly
      if (vault === undefined) refuseKind(`a key-only SEALED.txt: vault.tar.gz.age is not in the text (it is at ar://${s.arId}), so an identity opens nothing here`)
      files.push(decrypted('vault.tar.gz', await openAge(vault, vaultInfo(), how, limits, 'vault.tar.gz.age', ids)))
      via = 'identity'
    } else {
      const plain = await openAge(tlockBin, ageInfo(tlockBin, limits, s.tlockName), how, limits, s.tlockName)
      let key = ''
      try { key = new TextDecoder('utf-8', { fatal: true }).decode(plain).trim() } catch { key = '' }
      plain.fill(0)
      if (!AGE_KEY.test(key)) refuseFormat('the time-locked layer (unlock-TIME.age) does not hold an age identity')
      files.push(decrypted('identity.key', utf8(`${key}\n`)))
      if (vault !== undefined) {
        const tgz = await openAge(vault, vaultInfo(), how, limits, 'vault.tar.gz.age', [key],
          () => refuseFormat('the time-locked identity does not open vault.tar.gz.age: the package is inconsistent'))
        files.push(decrypted('vault.tar.gz', tgz))
      } else notes.push(`key-only text: the archive is at ar://${s.arId}. Fetch it (any Arweave gateway) and open it with identity.key: age -d -i identity.key -o vault.tar.gz vault.tar.gz.age`)
    }
  } else {
    if (ids !== null && typeof how.fetchRoundSignature !== 'function') refuseKind('this SEALED.txt has one layer, a time lock: an identity cannot open it; it needs the round\'s drand signature (the relay)')
    const plain = await openAge(tlockBin, ageInfo(tlockBin, limits, s.tlockName), how, limits, s.tlockName)
    const name = s.layout === 'vault' ? 'vault.tar.gz' : s.layout === 'secret' ? 'secret.tar.gz' : isGzip(plain) ? 'content.tar.gz' : 'content'
    files.push(decrypted(name, plain))
  }
  let archive: ArchiveSource | null = null
  for (const f of files) {
    if (!f.name.endsWith('.tar.gz')) continue
    if (isGzip(f.bytes)) archive = tarGzSource(f.name, f.bytes, archiveLimits)
    else notes.push(`${f.name} is not a gzip archive; it is given as it is`)
  }
  return { kind: 'sealed', via, files, blocks: s.blocks, archive, notes }
}

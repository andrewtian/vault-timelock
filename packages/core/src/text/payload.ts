// Timelocked-text input check (R26, R32-R34; D0b): the payload is the published text (two-line header + note +
// SEALED.txt with armored age). Collects every issue instead of stopping at the first, so a UI can list them.
// Nothing is rewritten: NFC, CR, BOM, bidi, zero-width problems are refused, never normalized. Browser-safe.
//
// ★ One parser. parseText() is the only place a published text is split into header, note, SEALED.txt preamble and
//   blocks. checkPayload() judges its result, variants() cuts at its section start, and sealedFiles() (what Open
//   decrypts) returns its blocks: a text that checkPayload accepts is read the same way by every consumer in this file,
//   and the armor goes through dearmor() and the age header through parseAgeHeader()/parseTlockStanza() (sealed-from.ts),
//   the functions buildSealedFrom() uses. Where the text is read by something else (the printed shell steps cut blocks
//   with awk over the WHOLE text, the part reassembler reads the first line), the check is strictly narrower:
//   anything those readers could see differently is refused (markers in the note, a second title/unlock/contents line,
//   trailing blanks, extra or duplicate blocks, text between blocks, a first line that could be a part header).
import { dearmor } from './armor.ts'
import { sha256Hex, utf8 } from './bytes.ts'
import { QUICKNET, unlockIso } from './drand.ts'
import { INVISIBLE_NEW, buildEnvelope, isAscii } from './envelope.ts'
import { isRefusal, refuse } from './guard.ts'
import { ETH_PREFIX, PUBLISH_CAP, SOL_MEMO_MAX } from './published.ts'
import { buildSealedFrom, mapReader, parseAgeHeader, parseTlockStanza } from './sealed-from.ts'

export type ChainId = 'eth' | 'btc' | 'sol'
export interface Variants { readonly eth: Uint8Array; readonly btc: Uint8Array; readonly sol: Uint8Array }
export interface Issue { readonly id: string; readonly message: string }
export interface ArmorBlock { readonly name: string; readonly bytes: number; readonly sha256: string }
export interface PayloadCheck {
  readonly ok: boolean
  readonly issues: readonly Issue[]
  readonly warnings: readonly Issue[]
  readonly firstLine: string
  readonly arId: string | null
  readonly unlock: string | null
  readonly contents: 'full' | 'key-only' | null
  readonly blocks: readonly ArmorBlock[]
  readonly textSha256: string
  readonly variants: Variants
  readonly fits: Readonly<Record<ChainId, boolean>>
}

const LINE1 = /^vault-timelock\/1 unlock=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)$/
const LINE2 = /^ar:\/\/([A-Za-z0-9_-]{43})$/
// The first line of a SEALED.txt (sealed-from.ts); the section starts after a blank line.
const SEALED_TITLE = '== vault-timelock sealed package: self-contained, age + drand timelock =='
const SEALED_START = `\n\n${SEALED_TITLE}\n`
const END_MARK = '== end =='
const UNLOCK_AFTER = /^unlock-after: (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) {2}\(drand round ([1-9]\d{0,15})\)$/
const FILE_LINE = /^\[file ([A-Za-z0-9][A-Za-z0-9._-]*) bytes=([1-9]\d{0,9}) sha256=([0-9a-f]{64})\]$/
const BEGIN = '-----BEGIN AGE ENCRYPTED FILE-----'
const END = '-----END AGE ENCRYPTED FILE-----'
// The note rules (envelope.ts) widened to the whole text: C0 except \n (so CR and TAB too), DEL, C1, BOM, U+2028/U+2029, U+FFFD; all Bidi_Control.
const CONTROL = /[\u0000-\u0009\u000B-\u001F\u007F-\u009F\uFEFF\uFFFD\u2028\u2029]/u
const BIDI = /\p{Bidi_Control}/u
// Invisible characters. EXACT mode (checkPayload, publishing) uses the widened set of envelope.ts (INVISIBLE_NEW: every Default_Ignorable_Code_Point
// plus U+FFF9-U+FFFB, minus the emoji presentation selectors U+FE0E/U+FE0F). Open (sealedFiles, not exact) keeps the PRE-Eminors set, so a text an
// older tool published and checkPayload accepted still opens: soft hyphen, Mongolian vowel separator, ZWSP/ZWNJ/ZWJ, U+2060-U+2064, U+206A-U+206F,
// interlinear annotation U+FFF9-U+FFFB.
const INVISIBLE_OLD = /[\u00AD\u180E\u200B-\u200D\u2060-\u2064\u206A-\u206F\uFFF9-\uFFFB]/u
// A preamble line the printed `awk` step would cut a block out of: `[file `, an armor marker (the awk regexes are anchored at the line start).
const PREAMBLE_AWK = /^(?:\[file |-----BEGIN |-----END )/
// In the note (the text between the two header lines and the sealed section) nothing may look like SEALED.txt structure:
// the printed `awk` step cuts blocks out of the WHOLE text, so a block-looking note would be cut too.
// Also the language of the printed steps (1password-timelock.sh literal_steps: `^  [0-9]+b?\. ` step lines and `^     \$ ` command
// lines) and anything a reader could take for a step or a command: after any indentation (spaces, tabs, NBSP and other
// Unicode spaces) a line may not start with `$`, a number (any Unicode digit, optional letter) followed by `.` or `)`, or `Step`.
const NOTE_STEP = /^[\p{White_Space}\u180E\u200B\uFEFF]*(?:\$|\p{Nd}+\p{L}?[.)\uFF0E\uFF09]|step\b)/imu
const NOTE_STRUCTURE = /^(?:\[file |-----BEGIN |-----END |== |unlock-after: |contents: |drand: |drand-signature: |format: |tools: )/m
const BLANK_END = /[ \t]$/m
// The block sets a sealed package can have (sealed-from.ts detect()); `full` carries all of them, `key-only` only the tlock file.
const LAYOUTS: ReadonlyArray<{ full: readonly string[]; tlock: readonly string[] }> = [
  { full: ['payload.age'], tlock: ['payload.age'] },
  { full: ['unlock-TIME.age', 'vault.tar.gz.age'], tlock: ['unlock-TIME.age'] },
  { full: ['vault.tar.gz.age'], tlock: ['vault.tar.gz.age'] },
  { full: ['secret.tar.gz.age'], tlock: ['secret.tar.gz.age'] },
]

interface Block { name: string; bytes: number; sha256: string; bin: Uint8Array }
interface Parsed {
  issues: Issue[]
  warnings: Issue[]
  line1: string
  unlock: string | null
  arId: string | null
  contents: 'full' | 'key-only' | null
  section: number         // index in the text of the sealed section's title line, or -1
  blocks: Block[]
}

// unlockIso, but null for a round whose time is no date (a refusal for the caller, never a throw)
function safeIso(round: number): string | null { try { return unlockIso(round) } catch { return null } }

// Where the sealed section starts (the index of the blank line's second LF + 1 is the title line), or -1.
// Refusing a second title is the parseText's job; this finds the first, the one a reader scanning from the top finds.
const sectionAt = (text: string): number => text.indexOf(SEALED_START)

// Per chain (R14, R32-R34, R41): Ethereum = `data:,` + text; Bitcoin = text; Solana = header + note +
// "\nsha256:<hex of the text as given>", which is the Bitcoin body (a verifiable pointer to what the other
// chains carry, never the armor). The cut is the sealed section's start (a text with a second one is refused).
export function variants(text: string): Variants {
  const cut = sectionAt(text)
  const headerNote = cut >= 0 ? text.slice(0, cut) : text
  return { eth: utf8(ETH_PREFIX + text), btc: utf8(text), sol: utf8(`${headerNote}\nsha256:${sha256Hex(utf8(text))}`) }
}

// A stand-in for the vault layer a key-only text leaves out (an age file with an X25519 stanza and no tlock stanza), so the
// builder can regenerate a key-only SEALED.txt, whose text only names it.
const VAULT_STAND_IN = utf8(`age-encryption.org/v1\n-> X25519 ${'A'.repeat(43)}\n${'A'.repeat(43)}\n--- ${'A'.repeat(43)}\nstand-in`)

// Whether `sealed` is the SEALED.txt the producer (buildSealedFrom) makes for exactly these blocks, round and contents.
function isProducerText(sealed: string, blocks: readonly Block[], round: number, contents: 'full' | 'key-only', arId: string | null): boolean {
  const files = new Map<string, Uint8Array>(blocks.map((b) => [b.name, b.bin]))
  if (contents === 'key-only' && files.has('unlock-TIME.age')) files.set('vault.tar.gz.age', VAULT_STAND_IN)
  files.set('chain-info.json', utf8(JSON.stringify({ hash: QUICKNET.hash, genesis_time: QUICKNET.genesis_time, period: QUICKNET.period, schemeID: QUICKNET.schemeID })))
  files.set('round', utf8(`${round}\n`))
  const encodings = files.has('payload.age') ? ['raw', 'tar+gzip'] : [null]
  for (const encoding of encodings) {
    if (encoding !== null) files.set('encoding', utf8(encoding))
    // `now` = genesis: any round is still ahead, so an already-open text (Open) is read the same way
    try { if (buildSealedFrom(mapReader(files), { contents, arId: arId ?? undefined, now: QUICKNET.genesis_time }) === sealed) return true } catch { /* a refusal, or a round with no date: not the producer's text */ }
  }
  return false
}

function parseText(text: string, exact: boolean): Parsed {
  const issues: Issue[] = []
  const warnings: Issue[] = []
  const add = (id: string, message: string): void => { issues.push({ id, message }) }
  if (text.length === 0) add('payload.empty', 'payload is empty') // @guard:payload.empty
  if (CONTROL.test(text)) add('payload.control', 'control characters other than \\n (CR and TAB too), a BOM, U+FFFD or a U+2028/U+2029 separator are not allowed') // @guard:payload.control
  if (BIDI.test(text)) add('payload.bidi', 'bidirectional control characters are not allowed') // @guard:payload.bidi
  if ((exact ? INVISIBLE_NEW : INVISIBLE_OLD).test(text)) add('payload.invisible', 'zero-width and invisible format characters are not allowed') // @guard:payload.invisible
  if (text.normalize('NFC') !== text) add('payload.nfc', 'the text is not NFC-normalized (it is refused, never rewritten)') // @guard:payload.nfc

  const [line1 = '', line2 = ''] = text.split('\n', 2)
  const h1 = LINE1.exec(line1)
  const h2 = LINE2.exec(line2)
  if (h1 === null || h2 === null) add('payload.header', 'the header must be two lines: `vault-timelock/1 unlock=<YYYY-MM-DDTHH:MM:SSZ>` then `ar://<43-char id>`') // @guard:payload.header
  const s = sectionAt(text)
  if (s < 0) add('payload.sealed-missing', 'no SEALED.txt section (a blank line, then its title line)') // @guard:payload.sealed-missing
  const titles = text.split('\n').filter((l) => l === SEALED_TITLE).length
  if (titles > 1) add('payload.sealed-duplicate', 'the SEALED.txt title line appears more than once') // @guard:payload.sealed-duplicate
  const noteStart = line1.length + line2.length + 2
  // a note is required: a section that starts right after the second header line leaves an empty note (note.empty)
  if (h1 !== null && h2 !== null && s >= 0) {
    const note = s >= noteStart ? text.slice(noteStart, s) : ''
    try { buildEnvelope({ arId: h2[1], unlock: h1[1], note }, undefined, exact) } catch (e) { if (!isRefusal(e)) throw e; add(e.guardId, e.message) }
    if (NOTE_STRUCTURE.test(note) || NOTE_STEP.test(note)) add('payload.note-structure', 'the note holds a line that looks like SEALED.txt structure (a [file] line, an armor marker, a `== ` line, a key: line, a `$ ` command or a numbered step); use \'- \' bullets for lists in a note') // @guard:payload.note-structure
    if (!isAscii(note)) warnings.push({ id: 'note.non-ascii', message: 'the note has non-ASCII characters: each costs ~3,000 Solana compute units, and some explorers render them poorly' })
  }

  let contents: 'full' | 'key-only' | null = null
  const blocks: Block[] = []
  if (s >= 0) {
    const sealed = text.slice(s + 2)
    const sl = sealed.split('\n')
    // the section ends with "== end ==\n" exactly once, and nothing follows
    const ends = sl.filter((l) => l === END_MARK).length
    const endOk = sl.length >= 2 && sl[sl.length - 1] === '' && sl[sl.length - 2] === END_MARK && ends === 1
    if (!endOk) add('payload.sealed-end', 'the SEALED.txt section must end with one `== end ==` line and a newline, nothing after it') // @guard:payload.sealed-end
    if (!isAscii(sealed)) add('payload.sealed-non-ascii', 'the SEALED.txt section must be pure ASCII (R32)') // @guard:payload.sealed-non-ascii
    if (BLANK_END.test(sealed)) add('payload.trailing-blank', 'a SEALED.txt line ends with a space or tab') // @guard:payload.trailing-blank
    // the preamble runs to the first [file] line; each key line appears exactly once
    let f = sl.findIndex((l) => FILE_LINE.test(l))
    if (f < 0) f = Math.max(0, sl.length - 2)
    const pre = sl.slice(0, f)
    // planE6 M-8 (Eminors): no preamble line may look like a block to the awk cut (Open's non-exact read would otherwise accept a text
    // whose printed steps write a file Open never reads)
    const preFake = pre.some((l) => PREAMBLE_AWK.test(l))
    const one = (re: RegExp): RegExpExecArray | null => {
      const hits = pre.filter((l) => re.test(l))
      return hits.length === 1 ? re.exec(hits[0]) : null
    }
    const ul = one(/^unlock-after: /) === null ? null : UNLOCK_AFTER.exec(pre.find((l) => l.startsWith('unlock-after: ')) as string)
    const round = ul === null ? null : Number(ul[2])
    if (ul === null || round === null || !Number.isSafeInteger(round)) add('payload.unlock-line', 'the sealed section needs exactly one `unlock-after: <time>  (drand round <n>)` line') // @guard:payload.unlock-line
    if (h1 !== null && ul !== null && ul[1] !== h1[1]) add('payload.unlock-mismatch', 'the header unlock= differs from the sealed unlock-after line') // @guard:payload.unlock-mismatch
    if (ul !== null && round !== null && Number.isSafeInteger(round) && safeIso(round) !== ul[1]) add('payload.round-mismatch', 'the unlock-after time is not the time of its drand round') // @guard:payload.round-mismatch
    const keyLines: Array<[string, string]> = [
      ['format: vault-timelock-sealed/1', 'format:'],
      [`drand: quicknet ${QUICKNET.hash}  scheme ${QUICKNET.schemeID}`, 'drand:'],
      [`drand-signature: https://api.drand.sh/${QUICKNET.hash}/public/${round ?? 0}`, 'drand-signature:'],
    ]
    for (const [want, prefix] of keyLines) {
      const hits = pre.filter((l) => l.startsWith(`${prefix} `))
      if (hits.length !== 1 || hits[0] !== want) add('payload.sealed-line', `the sealed section needs exactly one \`${prefix}\` line, and it must be the pinned quicknet one`) // @guard:payload.sealed-line
    }
    const cl = pre.filter((l) => l.startsWith('contents: '))
    if (cl.length === 1 && cl[0] === 'contents: full') contents = 'full'
    if (cl.length === 1 && h2 !== null && cl[0] === `contents: key-only (payload: ar://${h2[1]})`) contents = 'key-only'
    if (contents === null) add('payload.contents', 'the sealed section needs exactly one contents line: `contents: full` or `contents: key-only (payload: ar://<the header id>)`') // @guard:payload.contents
    // the blocks: [file] line, armor, [file] line, armor, ..., then the end line; nothing in between
    let i = f
    let stray = false
    while (i < sl.length - 2) {
      const m = FILE_LINE.exec(sl[i])
      const end = m === null || sl[i + 1] !== BEGIN ? -1 : sl.indexOf(END, i + 2)
      if (m === null || end < 0) { stray = true; break }
      let bin: Uint8Array | null = null
      try { bin = dearmor(sl.slice(i + 1, end + 1).join('\n') + '\n') } catch (e) { if (!isRefusal(e)) throw e; add('payload.armor', `the armor block of ${m[1]} is not canonical age armor`) } // @guard:payload.armor
      if (bin !== null) {
        const sha = sha256Hex(bin)
        if (bin.length !== Number(m[2]) || sha !== m[3]) add('payload.block-mismatch', `block ${m[1]}: its bytes or sha256 differ from its [file] line`) // @guard:payload.block-mismatch
        blocks.push({ name: m[1], bytes: bin.length, sha256: sha, bin })
      }
      i = end + 1
    }
    if (stray && !endOk) stray = false
    if (stray || preFake) add('payload.sealed-structure', stray ? 'after the first [file] line the section must be armor blocks, each right after its [file] line, then `== end ==`: nothing else' : 'the SEALED.txt preamble holds a line that looks like a [file] line or an armor marker') // @guard:payload.sealed-structure
    if (blocks.length === 0 && !issues.some((x) => x.id === 'payload.armor' || x.id === 'payload.sealed-structure')) add('payload.no-blocks', 'no armored age block found') // @guard:payload.no-blocks
    // the block set must be one a package can have, in order, for the contents line
    const names = blocks.map((b) => b.name)
    const layout = LAYOUTS.find((l) => JSON.stringify(contents === 'key-only' ? l.tlock : l.full) === JSON.stringify(names))
    if (blocks.length > 0 && contents !== null && layout === undefined) add('payload.layout', `the blocks (${names.join(', ')}) are not the files of any package for contents: ${contents}`) // @guard:payload.layout
    // every block is an age file; a tlock file names this round and quicknet, and the two-layer vault carries no tlock stanza
    for (const b of blocks) {
      const tlockFile = layout?.tlock.includes(b.name) === true
      if (parseAgeHeader(b.bin) === null) add('payload.not-age', `block ${b.name} is not an age file (version line, stanza, MAC line)`) // @guard:payload.not-age
      const st = parseTlockStanza(b.bin)
      const stanzaOk = !tlockFile || (st !== null && round !== null && st.round === String(round) && st.hash === QUICKNET.hash)
      if (layout !== undefined && parseAgeHeader(b.bin) !== null && !stanzaOk) add('payload.stanza', `block ${b.name}: its tlock stanza does not name this round and drand quicknet`) // @guard:payload.stanza
      const plain = layout !== undefined && !tlockFile && parseAgeHeader(b.bin)?.stanzas.some((x) => x.type === 'tlock') === true
      if (plain) add('payload.stanza', `block ${b.name}: carries a tlock stanza, which only the time-locked file may`)
    }
    // Exact mode (publishing): the whole section is byte for byte what the producer makes for these blocks, so the printed
    // commands, the notes and every key line are the producer's own and no reader (awk, sed, a person) sees anything else.
    if (exact && issues.length === 0 && layout !== undefined && contents !== null && round !== null) {
      if (!isProducerText(sealed, blocks, round, contents, h2?.[1] ?? null)) add('payload.sealed-text', 'the SEALED.txt section is not the text the sealer makes for these blocks (an edited or foreign section)') // @guard:payload.sealed-text
    }
  }
  return { issues, warnings, line1, unlock: h1?.[1] ?? null, arId: h2?.[1] ?? null, contents, section: s, blocks }
}

export function checkPayload(text: string): PayloadCheck {
  const p = parseText(text, true)
  const v = variants(text)
  const issues = [...p.issues]
  if (v.eth.length > PUBLISH_CAP) issues.push({ id: 'payload.too-long', message: `too long: ${v.eth.length} B > ${PUBLISH_CAP} B (including the 6-byte Ethereum data:, prefix)` }) // @guard:payload.too-long
  const fits = { eth: v.eth.length <= PUBLISH_CAP, btc: v.btc.length <= PUBLISH_CAP, sol: v.sol.length <= SOL_MEMO_MAX }
  return {
    ok: issues.length === 0, issues, warnings: p.warnings, firstLine: p.line1, arId: p.arId, unlock: p.unlock,
    contents: p.contents, blocks: p.blocks.map(({ name, bytes, sha256 }) => ({ name, bytes, sha256 })),
    textSha256: sha256Hex(v.btc), variants: v, fits,
  }
}

// The binary files of a published text's armored blocks, by their [file] names (for Open, D6): the blocks parseText
// found, and only for a text whose structure checkPayload would accept (ignoring its size caps, and not requiring the
// section to be byte for byte the current producer's: an older tool's text still opens).
export function sealedFiles(text: string): Map<string, Uint8Array> {
  const p = parseText(text, false)
  if (p.issues.length > 0) refuse('payload.invalid', `not a valid published text: ${p.issues.map((i) => i.id).join(', ')}`) // @guard:payload.invalid
  return new Map(p.blocks.map((b) => [b.name, b.bin]))
}

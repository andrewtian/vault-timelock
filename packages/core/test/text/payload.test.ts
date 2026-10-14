import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { armor } from '../../src/text/armor.ts'
import { Refusal } from '../../src/text/guard.ts'
import { checkPayload, sealedFiles, variants } from '../../src/text/payload.ts'
import { buildPublished, ETH_PREFIX, PUBLISH_CAP, SOL_MEMO_MAX } from '../../src/text/published.ts'
import { buildSealed } from './build-sealed.ts'
import { AR, NOW, UNLOCK, makePkg } from './fixtures.ts'
import type { Kind } from './fixtures.ts'

const NOTE = 'e2e note: synthetic payload'
const dec = (b: Uint8Array) => new TextDecoder().decode(b)
const sha = (b: Uint8Array | string) => createHash('sha256').update(b).digest('hex')
const ids = (t: string) => checkPayload(t).issues.map((i) => i.id)
const ethLen = (t: string) => new TextEncoder().encode(ETH_PREFIX + t).length

function texts(kind: Kind = 'raw', note = NOTE): { text: string; full: string; key: string; files: Record<string, Buffer> } {
  const p = makePkg(kind)
  const full = buildSealed(p.dir, { contents: 'full', now: NOW })
  const key = buildSealed(p.dir, { contents: 'key-only', arId: AR, now: NOW })
  return { text: dec(buildPublished({ arId: AR, unlock: UNLOCK, note }, full, key, 'btc').bytes), full, key, files: p.files }
}
const validText = (): string => texts().text

test('a core-built published text is valid; the per-chain variants are exact (R32-R34, R41)', () => {
  const { text: t, full, key } = texts()
  const c = checkPayload(t)
  assert.equal(c.ok, true, JSON.stringify(c.issues))
  assert.deepEqual(c.warnings, [])
  assert.equal(c.firstLine, `vault-timelock/1 unlock=${UNLOCK}`)
  assert.equal(c.arId, AR)
  assert.equal(c.unlock, UNLOCK)
  assert.equal(c.contents, 'full')
  assert.deepEqual(c.blocks.map((b) => b.name), ['payload.age'])
  assert.deepEqual(c.fits, { eth: true, btc: true, sol: true })
  assert.equal(c.textSha256, sha(t))
  const v = variants(t)
  assert.equal(dec(v.eth), 'data:,' + t)
  assert.equal(dec(v.btc), t)
  assert.equal(dec(v.sol), `vault-timelock/1 unlock=${UNLOCK}\nar://${AR}\n${NOTE}\nsha256:${sha(t)}`)
  assert.ok(!dec(v.sol).includes('-----BEGIN AGE'))
  // R41: the Solana memo equals what the CLI-side builder makes for the same publication
  assert.deepEqual(v.sol, buildPublished({ arId: AR, unlock: UNLOCK, note: NOTE }, full, key, 'sol').bytes)
  assert.deepEqual(c.variants, v)
})

test('every kind of package builds a payload that checks clean', () => {
  for (const kind of ['two-layer', 'one-layer', 'secret', 'raw', 'tar+gzip'] as const) {
    const c = checkPayload(texts(kind).text)
    assert.equal(c.ok, true, `${kind}: ${JSON.stringify(c.issues)}`)
  }
  const two = checkPayload(texts('two-layer').text)
  assert.deepEqual(two.blocks.map((b) => b.name), ['unlock-TIME.age', 'vault.tar.gz.age'])
})

test('a key-only text is recognised as such', () => {
  const { full, key } = texts()
  const t = dec(buildPublished({ arId: AR, unlock: UNLOCK, note: NOTE }, full, key, 'btc').bytes).replace('contents: full', `contents: key-only (payload: ar://${AR})`)
  assert.equal(checkPayload(t).contents, 'key-only')
  assert.deepEqual(ids(t.replace(`payload: ar://${AR}`, `payload: ar://${'B'.repeat(43)}`)), ['payload.contents'])
})

test('payload.empty / payload.header / payload.sealed-missing: an empty text, in that order', () => {
  assert.deepEqual(ids(''), ['payload.empty', 'payload.header', 'payload.sealed-missing'])
})

test('pasted-text hazards are refused with reasons, never rewritten', () => {
  const t = validText()
  assert.ok(ids(t.replace(/\n/g, '\r\n')).includes('payload.control'))
  assert.ok(ids('\uFEFF' + t).includes('payload.control'))
  assert.ok(ids(t.replace(NOTE, 'a\u2028b')).includes('payload.control'))
  assert.ok(ids(t.replace(NOTE, 'a\uFFFDb')).includes('payload.control'))
  const nfd = ids(t.replace(NOTE, 'cafe\u0301'))
  assert.ok(nfd.includes('payload.nfc') && nfd.includes('note.nfc'))
  assert.ok(ids(t.replace(NOTE, 'e2e \u202Enote')).includes('payload.bidi'))
  assert.ok(ids(t.replace(NOTE, 'e2e \u200Enote')).includes('payload.bidi'))
  assert.ok(ids(t.replace(NOTE, NOTE + ' ')).includes('note.whitespace'))
})

test('header, sealed section and contents line', () => {
  const t = validText()
  assert.ok(ids(t.replace('vault-timelock/1', 'vault-timelock/2')).includes('payload.header'))
  assert.ok(ids(t.replace('\nar://', '\nar:/')).includes('payload.header'))
  assert.ok(ids(t.replace('\n\n== vault-timelock sealed', '\n== vault-timelock sealed')).includes('payload.sealed-missing'))
  assert.ok(ids(t.replace('== end ==\n', '== end ==')).includes('payload.sealed-end'))
  assert.ok(ids(t.replace('contents: full', 'contents: most')).includes('payload.contents'))
  assert.ok(ids(t.replace(`unlock-after: ${UNLOCK}`, 'unlock-after: 2099-01-01T00:00:00Z')).includes('payload.unlock-mismatch'))
  assert.ok(ids(t.replace(/unlock-after: [^\n]*\n/, '')).includes('payload.unlock-line'))
  assert.deepEqual(ids(t.replace('tools: tle ', 'tools: tle '+String.fromCharCode(0xb7)+' ')), ['payload.sealed-non-ascii'])
})

test('a Unicode (NFC) note is accepted with a warning; a long note no longer fits the Solana memo', () => {
  const { text: t } = texts()
  const u = checkPayload(t.replace(NOTE, 'café note'))
  assert.equal(u.ok, true)
  assert.deepEqual(u.warnings.map((w) => w.id), ['note.non-ascii'])
  const long = checkPayload(t.replace(NOTE, 'n'.repeat(900)))
  assert.equal(long.ok, true)
  assert.deepEqual(long.fits, { eth: true, btc: true, sol: false })
  assert.ok(variants(t.replace(NOTE, 'n'.repeat(900))).sol.length > SOL_MEMO_MAX)
})

test('a note with an inner blank line is carried whole on Solana (cut = the LAST sealed-section start)', () => {
  const t = validText().replace(NOTE, 'line one\n\nline three')
  assert.equal(checkPayload(t).ok, true, JSON.stringify(checkPayload(t).issues))
  assert.equal(dec(variants(t).sol), `vault-timelock/1 unlock=${UNLOCK}\nar://${AR}\nline one\n\nline three\nsha256:${sha(t)}`)
})

test('variants of a text with no sealed section carry the whole text on Solana', () => {
  assert.equal(dec(variants('abc').sol), `abc\nsha256:${sha('abc')}`)
})

test('R41: for an oversize (key-only) package the Solana memo equals the CLI memo', () => {
  const p = makePkg('two-layer')
  const big = Buffer.concat([p.files['vault.tar.gz.age'], Buffer.alloc(80_000, 7)])
  const dir = p.dir
  // a bigger vault layer: rewrite vault.tar.gz.age with 80 KB extra
  writeFileSync(`${dir}/vault.tar.gz.age`, big)
  const full = buildSealed(dir, { contents: 'full', now: NOW })
  const key = buildSealed(dir, { contents: 'key-only', arId: AR, now: NOW })
  const a = { arId: AR, unlock: UNLOCK, note: NOTE }
  const base = buildPublished(a, full, key, 'base')
  assert.equal(base.contents, 'key-only')
  assert.deepEqual(variants(dec(base.bytes)).sol, buildPublished(a, full, key, 'sol').bytes)
  const c = checkPayload(dec(base.bytes))
  assert.equal(c.ok, true, JSON.stringify(c.issues))
  assert.equal(c.contents, 'key-only')
})

test('armor blocks parse strictly and must be age files matching their [file] line', () => {
  const t = validText()
  const lines = t.split('\n')
  const i = lines.indexOf('-----BEGIN AGE ENCRYPTED FILE-----') + 1
  const wide = [...lines]
  wide[i] = lines[i] + lines[i + 1].slice(0, 1)
  wide[i + 1] = lines[i + 1].slice(1)
  assert.ok(ids(wide.join('\n')).includes('payload.armor'))
  assert.ok(ids(t.replace('-----END AGE ENCRYPTED FILE-----\n', '')).includes('payload.sealed-structure'))
  const hello = new TextEncoder().encode('hello, not an age file')
  const notAge = t.replace(/\[file payload\.age[^\n]*\]\n-----BEGIN[\s\S]*?-----END AGE ENCRYPTED FILE-----\n/,
    `[file payload.age bytes=${hello.length} sha256=${sha(hello)}]\n${armor(hello)}`)
  assert.deepEqual(ids(notAge), ['payload.not-age'])
  assert.deepEqual(ids(t.replace(/bytes=\d+/, 'bytes=1')), ['payload.block-mismatch'])
  assert.deepEqual(ids(t.replace(/sha256=[0-9a-f]{64}\]/, `sha256=${'0'.repeat(64)}]`)), ['payload.block-mismatch'])
})

test('payload.no-blocks: a sealed section with no [file] block', () => {
  const t = validText().replace(/\[file payload\.age[^\n]*\]\n-----BEGIN[\s\S]*?-----END AGE ENCRYPTED FILE-----\n/, '')
  assert.deepEqual(ids(t), ['payload.no-blocks'])
})

test('cap: the Ethereum variant (6-byte data:, prefix + text) must be <= 98304 B', () => {
  // a package with a big payload, the text assembled by hand (buildPublished would fall back to key-only); the note length tunes the size
  const p = makePkg('raw')
  writeFileSync(`${p.dir}/payload.age`, Buffer.concat([p.files['payload.age'], Buffer.alloc(67_000, 9)]))
  const full = buildSealed(p.dir, { contents: 'full', now: NOW })
  const at = (k: number): string => `vault-timelock/1 unlock=${UNLOCK}\nar://${AR}\n${'n'.repeat(k)}\n\n${full}`
  let k = 1
  while (ethLen(at(k)) < PUBLISH_CAP && k < 4000) k++
  assert.equal(ethLen(at(k)), PUBLISH_CAP, 'the note length that lands exactly on the cap')
  assert.equal(checkPayload(at(k)).ok, true, JSON.stringify(checkPayload(at(k)).issues))
  assert.equal(checkPayload(at(k)).fits.eth, true)
  assert.deepEqual(ids(at(k + 1)), ['payload.too-long'])
  assert.equal(checkPayload(at(k + 1)).fits.eth, false)
})

test('sealedFiles returns the exact binary files of the armored blocks', () => {
  const { text, files } = texts()
  assert.deepEqual([...sealedFiles(text).entries()], [['payload.age', new Uint8Array(files['payload.age'])]])
  const two = texts('two-layer')
  assert.deepEqual([...sealedFiles(two.text).keys()], ['unlock-TIME.age', 'vault.tar.gz.age'])
  assert.throws(() => sealedFiles('no blocks here'), (e: unknown) => e instanceof Refusal && e.guardId === 'payload.invalid')
  assert.throws(() => sealedFiles(text.replace('contents: full', 'contents: most')), (e: unknown) => e instanceof Refusal && e.guardId === 'payload.invalid')
})

test('Eminors I-2: a note with an emoji presentation selector publishes AND opens; an OLDER text with a newly refused invisible character still opens (liberal read)', () => {
  const love = texts('raw', 'love \u2764\ufe0f').text
  assert.equal(checkPayload(love).ok, true, JSON.stringify(checkPayload(love).issues))
  assert.deepEqual([...sealedFiles(love).keys()], ['payload.age'])
  const t = validText()
  for (const c of ['\u034f', '\u3164', '\u{e0041}', '\ufe00']) {
    const old = t.replace(NOTE, `a${c}b`)
    assert.ok(ids(old).includes('payload.invisible'), `exact mode refuses U+${c.codePointAt(0)!.toString(16)}`)
    assert.deepEqual([...sealedFiles(old).keys()], ['payload.age'], 'Open still opens it')
  }
  for (const c of ['\u200b', '\u00ad', '\ufff9']) {
    const bad = t.replace(NOTE, `a${c}b`)
    assert.throws(() => sealedFiles(bad), (e: unknown) => e instanceof Refusal && e.guardId === 'payload.invalid', 'the pre-Eminors set stays refused on read')
  }
  assert.throws(() => texts('raw', 'a\u034fb'), (e: unknown) => e instanceof Refusal && e.guardId === 'note.invisible', 'buildEnvelope never builds what checkPayload refuses')
})

test('planE6 M-8: a preamble line the awk cut would take for a block is refused, in checkPayload and in Open (sealedFiles)', () => {
  const t = validText()
  for (const line of [`[file evil.age bytes=0 sha256=00]`, '-----BEGIN AGE ENCRYPTED FILE-----', '-----END AGE ENCRYPTED FILE-----']) {
    const bad = t.replace('contents: full\n', `contents: full\n${line}\n`)
    assert.notEqual(bad, t)
    assert.ok(ids(bad).includes('payload.sealed-structure'), line)
    assert.throws(() => sealedFiles(bad), (e: unknown) => e instanceof Refusal && e.guardId === 'payload.invalid', line)
  }
  sealedFiles(t)
})

test('security review finding (parser differential): each structural refusal carries its own id', () => {
  const t = validText()
  const two = texts('two-layer').text
  const blockOf = (x: string, name: string): string => (new RegExp(`\\[file ${name.replace('.', '\\.')} [^\\n]*\\]\\n-----BEGIN[\\s\\S]*?-----END AGE ENCRYPTED FILE-----\\n`).exec(x) as RegExpExecArray)[0]
  const cases: Array<[string, string, string]> = [
    ['payload.invisible', t.replace(NOTE, 'a\u200Bb'), 'payload.invisible'],
    ['soft hyphen', t.replace(NOTE, 'a\u00ADb'), 'payload.invisible'],
    ['U+034F (combining grapheme joiner)', t.replace(NOTE, 'a\u034Fb'), 'payload.invisible'],
    ['Hangul filler U+3164', t.replace(NOTE, 'a\u3164b'), 'payload.invisible'],
    ['tag character U+E0041', t.replace(NOTE, 'a\u{E0041}b'), 'payload.invisible'],
    ['variation selector U+FE00', t.replace(NOTE, 'a\uFE00b'), 'payload.invisible'],
    ['interlinear annotation U+FFF9', t.replace(NOTE, 'a\uFFF9b'), 'payload.invisible'],
    ['interlinear annotation U+FFFA', t.replace(NOTE, 'a\uFFFAb'), 'payload.invisible'],
    ['interlinear annotation U+FFFB', t.replace(NOTE, 'a\uFFFBb'), 'payload.invisible'],
    ['payload.sealed-duplicate', t + t.slice(t.indexOf('\n\n== vault')), 'payload.sealed-duplicate'],
    ['payload.note-structure ([file])', t.replace(NOTE, `[file x bytes=1 sha256=${'0'.repeat(64)}]`), 'payload.note-structure'],
    ['payload.note-structure (armor marker)', t.replace(NOTE, '-----END AGE ENCRYPTED FILE-----'), 'payload.note-structure'],
    ['payload.note-structure (key line)', t.replace(NOTE, 'unlock-after: 2099'), 'payload.note-structure'],
    ['payload.trailing-blank', t.replace('contents: full', 'contents: full '), 'payload.trailing-blank'],
    ['payload.unlock-line (twice)', t.replace(/(unlock-after: [^\n]*\n)/, '$1$1'), 'payload.unlock-line'],
    ['payload.unlock-line (garbled)', t.replace(/unlock-after: [^\n]*\n/, 'unlock-after: soon\n'), 'payload.unlock-line'],
    ['payload.round-mismatch', t.replace(/\(drand round \d+\)/, '(drand round 500000001)'), 'payload.round-mismatch'],
    ['payload.sealed-line (format)', t.replace('format: vault-timelock-sealed/1', 'format: vault-timelock-sealed/2'), 'payload.sealed-line'],
    ['payload.sealed-line (drand twice)', t.replace(/(drand: quicknet [^\n]*\n)/, '$1$1'), 'payload.sealed-line'],
    ['payload.sealed-line (signature round)', t.replace(/(public\/)\d+/, '$1500000001'), 'payload.sealed-line'],
    ['payload.sealed-structure (junk between blocks)', two.replace(blockOf(two, 'unlock-TIME.age'), blockOf(two, 'unlock-TIME.age') + 'junk\n'), 'payload.sealed-structure'],
    ['payload.sealed-structure (missing END)', t.replace('-----END AGE ENCRYPTED FILE-----\n', ''), 'payload.sealed-structure'],
    ['payload.layout (extra block)', t.replace('== end ==\n', `${blockOf(two, 'vault.tar.gz.age')}== end ==\n`), 'payload.layout'],
    ['payload.layout (missing block)', two.replace(blockOf(two, 'vault.tar.gz.age'), ''), 'payload.layout'],
    ['payload.layout (swapped)', two.replace(blockOf(two, 'unlock-TIME.age') + blockOf(two, 'vault.tar.gz.age'), blockOf(two, 'vault.tar.gz.age') + blockOf(two, 'unlock-TIME.age')), 'payload.layout'],
    ['payload.sealed-text (edited step)', t.replace('tle --decrypt', 'tle --decrypt --evil'), 'payload.sealed-text'],
    ['payload.sealed-text (edited note line)', t.replace('nothing here is signed', 'everything here is signed'), 'payload.sealed-text'],
  ]
  for (const [label, text, id] of cases) {
    assert.notEqual(text, t, `${label}: the mutation changed the text`)
    assert.ok(ids(text).includes(id), `${label}: ${JSON.stringify(ids(text))}`)
  }
  assert.ok(ids(t.replace(NOTE, '')).includes('note.empty'), 'an empty note, section right after the header')
  assert.ok(ids(t.replace(`\n${NOTE}\n\n`, '\n\n')).includes('note.empty'))
})

test('payload.stanza: a tlock stanza for another round / a tlock stanza on the vault layer', () => {
  const p = makePkg('two-layer', { stanzaRound: 500000001, round: 500000001 })
  const full = buildSealed(p.dir, { contents: 'full', now: NOW })
  const good = `vault-timelock/1 unlock=${UNLOCK.replace(/.*/, '2027-01-01T00:00:00Z')}\nar://${AR}\n${NOTE}\n\n${full}`
  assert.ok(ids(good).includes('payload.unlock-mismatch'), 'the header names another time than this round')
  const t = texts('two-layer').text
  // claim round +1 everywhere but keep the stanza inside the block
  const lie = t.replace(/\(drand round \d+\)/, '(drand round 500000001)').replace(/public\/\d+/, 'public/500000001')
  assert.ok(ids(lie).includes('payload.stanza') || ids(lie).includes('payload.round-mismatch'))
  const x = texts('two-layer', 'full').text
  const tl = (/\[file unlock-TIME\.age [^\n]*\]\n-----BEGIN[\s\S]*?-----END AGE ENCRYPTED FILE-----\n/.exec(x) as RegExpExecArray)[0]
  const vt = (/\[file vault\.tar\.gz\.age [^\n]*\]\n-----BEGIN[\s\S]*?-----END AGE ENCRYPTED FILE-----\n/.exec(x) as RegExpExecArray)[0]
  assert.ok(ids(x.replace(vt, tl.replace('unlock-TIME.age', 'vault.tar.gz.age'))).includes('payload.stanza'))
})

test('payload.invalid: sealedFiles refuses a text with any structural issue', () => {
  const t = validText()
  for (const bad of [t.replace('contents: full', 'contents: most'), t + 'x', t.replace(NOTE, 'a\u200Bb')]) {
    assert.throws(() => sealedFiles(bad), (e: unknown) => e instanceof Refusal && e.guardId === 'payload.invalid')
  }
})

// M4a glue: the refusal tells the writer what to do instead.
test('payload.note-structure: the message ends with the bullet hint', () => {
  const issue = checkPayload(validText().replace(NOTE, '1. first thing')).issues.find((i) => i.id === 'payload.note-structure')
  assert.ok(issue)
  assert.ok(issue.message.endsWith("use '- ' bullets for lists in a note"), issue.message)
})

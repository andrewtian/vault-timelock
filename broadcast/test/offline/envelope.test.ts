import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import {
  ENVELOPE_MAX, HEADER_BYTES, NOTE_MAX, buildEnvelope, isAscii, validateNote,
} from '../../src/envelope.ts'
import { Refusal } from '../../src/guard.ts'

const enc = (s: string) => new TextEncoder().encode(s)
const AR = 'A'.repeat(43)
const UNLOCK = '2031-01-02T03:04:05Z'

function refusedWith(fn: () => unknown, id: string) {
  assert.throws(fn, (e: unknown) => e instanceof Refusal && e.guardId === id, `expected refusal ${id}`)
}
const note = (s: string, id: string) => refusedWith(() => validateNote(enc(s)), id)

test('constants', () => {
  assert.equal(ENVELOPE_MAX, 4096)
  assert.equal(HEADER_BYTES, 94)
  assert.equal(NOTE_MAX, 4002)
})

test('accepts 1-byte, multiline, non-ASCII NFC notes unchanged', () => {
  assert.equal(validateNote(enc('x')), 'x')
  assert.equal(validateNote(enc('a\nb\n\nc')), 'a\nb\n\nc')
  assert.equal(validateNote(enc('café')), 'café')
})

test('note.empty', () => refusedWith(() => validateNote(new Uint8Array(0)), 'note.empty'))

test('note limit', () => {
  assert.equal(validateNote(enc('a'.repeat(NOTE_MAX))).length, NOTE_MAX)
  note('a'.repeat(NOTE_MAX + 1), 'note.too-long')
  // limit is in bytes, not characters: 2001 x U+00E9 = 4002 bytes ok, +1 char = 4004 refused
  assert.equal(validateNote(enc('é'.repeat(2001))).length, 2001)
  note('é'.repeat(2002), 'note.too-long')
})

test('note.utf8', () => {
  refusedWith(() => validateNote(Uint8Array.from([0xc3, 0x28])), 'note.utf8')
  refusedWith(() => validateNote(Uint8Array.from([0xed, 0xa0, 0x80])), 'note.utf8')
})

test('note.replacement', () => note('a\ufffdb', 'note.replacement'))

test('note.control', () => {
  for (const c of ['\r', '\t', '\u0000', '\u0008', '\u000b', '\u001f', '\u007f', '\u0085', '\u009f', '\ufeff'])
    note(`a${c}b`, 'note.control')
  note('\ufeffabc', 'note.control')
})

test('note.bidi', () => {
  for (const c of ['\u202a', '\u202e', '\u2066', '\u2067', '\u2069']) note(`a${c}b`, 'note.bidi')
})

test('H0-9: note.bidi is all of Unicode Bidi_Control (ALM, LRM, RLM too)', () => {
  const all = ['\u061c', '\u200e', '\u200f', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068', '\u2069']
  for (const c of all) note(`a${c}b`, 'note.bidi')
  // neighbours that are not Bidi_Control stay accepted (ZWNJ/ZWJ are needed by some scripts)
  for (const c of ['\u200c', '\u200d', '\u2065', '\u206a', '\u061b']) assert.equal(validateNote(enc(`a${c}b`)), `a${c}b`)
})

test('H0-9: U+2028 / U+2029 (line and paragraph separators) are refused: LF is the only line break', () => {
  for (const c of ['\u2028', '\u2029']) {
    note(`a${c}b`, 'note.control')
    note(`a\n${c}\nb`, 'note.control')
  }
})

test('note.whitespace', () => {
  note(' a', 'note.whitespace')
  note('a ', 'note.whitespace')
  note('a\u00a0', 'note.whitespace')
  note('\na', 'note.whitespace')
  note('a\n', 'note.whitespace')
})

test('note.nfc refuses and does not normalize', () => {
  const nfd = 'e\u0301'
  const bytes = enc(`a${nfd}`)
  const before = Uint8Array.from(bytes)
  refusedWith(() => validateNote(bytes), 'note.nfc')
  assert.deepEqual(bytes, before)
})

test('envelope.ar-id', () => {
  for (const arId of ['A'.repeat(42), 'A'.repeat(44), 'A'.repeat(42) + '+', 'A'.repeat(42) + '/', 'A'.repeat(42) + '\n'])
    refusedWith(() => buildEnvelope({ arId, unlock: UNLOCK, note: 'hi' }), 'envelope.ar-id')
})

test('envelope.unlock', () => {
  for (const unlock of ['2031-02-30T00:00:00Z', '2031-01-02T03:04:05', '2031-01-02T03:04:05.000Z', '2031-13-01T00:00:00Z', '2031-01-02T25:00:00Z', ''])
    refusedWith(() => buildEnvelope({ arId: AR, unlock, note: 'hi' }), 'envelope.unlock')
})

test('buildEnvelope validates the note too', () => {
  refusedWith(() => buildEnvelope({ arId: AR, unlock: UNLOCK, note: 'a\r' }), 'note.control')
  refusedWith(() => buildEnvelope({ arId: AR, unlock: UNLOCK, note: '' }), 'note.empty')
})

test('envelope bytes, format, sha256', () => {
  const e = buildEnvelope({ arId: AR, unlock: UNLOCK, note: 'héllo\nworld' })
  const text = `vault-timelock/1 unlock=${UNLOCK}\nar://${AR}\nhéllo\nworld`
  assert.equal(new TextDecoder().decode(e.bytes), text)
  assert.equal(e.sha256, createHash('sha256').update(e.bytes).digest('hex'))
  assert.match(e.sha256, /^[0-9a-f]{64}$/)
  assert.equal(e.arId, AR)
  assert.equal(e.unlock, UNLOCK)
  assert.equal(e.note, 'héllo\nworld')
  assert.equal(enc(`vault-timelock/1 unlock=${UNLOCK}\nar://${AR}\n`).length, HEADER_BYTES)
})

test('max-size envelope is exactly 4096 bytes and accepted', () => {
  const e = buildEnvelope({ arId: AR, unlock: UNLOCK, note: 'a'.repeat(NOTE_MAX) })
  assert.equal(e.bytes.length, ENVELOPE_MAX)
})

test('envelope.too-long with smaller maxBytes', () => {
  refusedWith(() => buildEnvelope({ arId: AR, unlock: UNLOCK, note: 'hello' }, HEADER_BYTES + 4), 'envelope.too-long')
  assert.equal(buildEnvelope({ arId: AR, unlock: UNLOCK, note: 'hello' }, HEADER_BYTES + 5).bytes.length, HEADER_BYTES + 5)
})

test('R34: two-line header, line 1 is exactly 44 chars, 94 bytes total', () => {
  const e = buildEnvelope({ arId: AR, unlock: UNLOCK, note: 'hi' })
  const text = new TextDecoder().decode(e.bytes)
  const [l1, l2, ...rest] = text.split('\n')
  assert.equal(l1, `vault-timelock/1 unlock=${UNLOCK}`)
  assert.equal(l1.length, 44)
  assert.equal(l2, `ar://${AR}`)
  assert.equal(rest.join('\n'), 'hi')
  assert.equal(e.bytes.length - 2, HEADER_BYTES)
  assert.equal(HEADER_BYTES + NOTE_MAX, ENVELOPE_MAX)
})

test('isAscii', () => {
  assert.equal(isAscii('plain\nascii ~'), true)
  assert.equal(isAscii(''), true)
  assert.equal(isAscii('caf\u00e9'), false)
  assert.equal(isAscii('\u007f'), true)
  assert.equal(isAscii('\u0080'), false)
})

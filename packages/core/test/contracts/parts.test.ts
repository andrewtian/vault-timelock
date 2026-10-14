// The R72 part header (contracts/parts.ts) against its pinned vectors, plus round trips at every size class.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { h8, PART_FORMAT, parsePart, partPrefix } from '../../src/contracts/index.ts'
import type { PartHeaderInput, ParsedPart } from '../../src/contracts/index.ts'

const v = JSON.parse(readFileSync(new URL('../../contract/fixtures/parts/headers.json', import.meta.url), 'utf8')) as {
  format: string; sha256: string; headers: Array<{ name: string; input: PartHeaderInput; force?: boolean; prefix: string }>; parse: Array<{ name: string; payload: string; parsed: ParsedPart }>
}
const sha = (s: string): string => createHash('sha256').update(s).digest('hex')

test('the fixture is for this format version', () => assert.equal(v.format, PART_FORMAT))
for (const c of v.headers) test(`partPrefix: ${c.name}`, () => assert.equal(partPrefix(c.input, { force: c.force === true }), c.prefix))
for (const c of v.parse) test(`parsePart: ${c.name}`, () => assert.deepEqual(parsePart(c.payload), c.parsed))

test('literal bytes of the final format', () => {
  const s = sha('x')
  assert.equal(partPrefix({ part: 1, parts: 2, sha256: s, copy: null, copies: null }), `[1/2 ${s.slice(0, 8)} sha256=${s}]\n`)
  assert.equal(partPrefix({ part: 2, parts: 2, sha256: s, copy: null, copies: null }), `[2/2 ${s.slice(0, 8)}]\n`)
  assert.equal(partPrefix({ part: 2, parts: 2, sha256: s, copy: 3, copies: 4 }), `[2/2 ${s.slice(0, 8)}] [copy 3/4]\n`)
  assert.equal(partPrefix({ part: 1, parts: 1, sha256: s, copy: 3, copies: 4 }), '[copy 3/4]\n')
  assert.equal(partPrefix({ part: 1, parts: 1, sha256: s, copy: 3, copies: null }), '[copy 3]\n')
  // CC-1a: the writer-forced one-part header
  assert.equal(partPrefix({ part: 1, parts: 1, sha256: s, copy: null, copies: null }, { force: true }), `[1/1 ${s.slice(0, 8)} sha256=${s}]\n`)
  assert.equal(partPrefix({ part: 1, parts: 1, sha256: s, copy: 3, copies: 4 }, { force: true }), `[1/1 ${s.slice(0, 8)} sha256=${s}] [copy 3/4]\n`)
  assert.equal(partPrefix({ part: 1, parts: 1, sha256: s, copy: null, copies: null }, { force: false }), '')
  for (const p of v.headers.map((c) => c.prefix)) {
    assert.ok(!p.includes('#') && !p.includes(','), 'no # and no comma in a header')
    assert.ok(p === '' || p.endsWith('\n'), 'a header ends with LF')
    assert.equal(p.indexOf('\n'), p === '' ? -1 : p.length - 1, 'exactly one line')
  }
})

test('round trip: parsePart(partPrefix(h) + chunk) gives h back and the exact chunk', () => {
  const text = 'é😀漢a'.repeat(50)
  const s = sha(text)
  const chunk = 'chunk [1/2 deadbeef]\n with a header-looking second line'
  for (const parts of [1, 2, 3, 104]) {
    for (const part of [1, parts]) {
      for (const [copy, copies] of [[null, null], [1, 5], [2, 5], [5, 5], [9, null]] as Array<[number | null, number | null]>) {
        const h: PartHeaderInput = { part, parts, sha256: s, copy, copies }
        const p = parsePart(partPrefix(h) + chunk)
        assert.equal(p.body, chunk)
        assert.equal(p.part, part); assert.equal(p.parts, parts)
        assert.equal(p.copy, copy === null || copy < 2 ? 1 : copy)
        assert.equal(p.copies, copy === null || copy < 2 ? null : copies)
        assert.equal(p.h8, parts === 1 ? null : h8(s))
        assert.equal(p.sha256, parts > 1 && part === 1 ? s : null)
      }
    }
  }
})

test('CC-1a: a forced one-part header round-trips only over the text it hashes', () => {
  for (const text of ['x', 'é😀漢a\n'.repeat(40), '[2/3 deadbeef]\nlooks like a header', `[1/1 deadbeef sha256=${'d'.repeat(64)}]\nanother`]) {
    const s = sha(text)
    for (const [copy, copies] of [[null, null], [1, 5], [2, 5], [9, null]] as Array<[number | null, number | null]>) {
      const prefix = partPrefix({ part: 1, parts: 1, sha256: s, copy, copies }, { force: true })
      const p = parsePart(prefix + text)
      assert.equal(p.body, text); assert.equal(p.headerLength, prefix.length)
      assert.equal(p.part, 1); assert.equal(p.parts, 1); assert.equal(p.h8, h8(s)); assert.equal(p.sha256, s)
      assert.equal(p.copy, copy === null || copy < 2 ? 1 : copy)
      // the same header over different bytes does not verify: the whole payload is plain text
      const q = parsePart(prefix + text + '!')
      assert.equal(q.headerLength, 0); assert.equal(q.body, prefix + text + '!'); assert.equal(q.h8, null)
    }
  }
})

test('partPrefix refuses malformed input (programming errors)', () => {
  const s = sha('x')
  const bad: PartHeaderInput[] = [
    { part: 0, parts: 2, sha256: s, copy: null, copies: null }, { part: 3, parts: 2, sha256: s, copy: null, copies: null },
    { part: 1, parts: 2, sha256: s.toUpperCase(), copy: null, copies: null }, { part: 1, parts: 2, sha256: 'ab', copy: null, copies: null },
    { part: 1, parts: 2, sha256: s, copy: 0, copies: null }, { part: 1, parts: 2, sha256: s, copy: 3, copies: 2 },
    { part: 1.5, parts: 2, sha256: s, copy: null, copies: null },
  ]
  for (const h of bad) assert.throws(() => partPrefix(h), RangeError, JSON.stringify(h))
})

// The R72 writer (chains/plan.js over contracts/parts.ts): the writer rule (Task 0 ruling, CC-1a) — a one-part text whose
// own first line parses as a header gets the explicit [1/1 <h8> sha256=<64hex>] header — UTF-8 safety at every split
// boundary, and reassembleCopy (the reader rules over chain bytes). ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ETH, SOL } from '../../src/chains/constants.js'
import { ethParts, reassembleCopy, solParts, splitText, utf8 } from '../../src/chains/plan.js'
import { previewParts } from '../../src/chains/text.js'
import { parsePart } from '../../src/contracts/index.ts'
import { sha256Hex } from '../../src/job/canonical.ts'

const dec = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
const LEAD = utf8(ETH.PREFIX)
const body = (payload: Uint8Array, lead = 0): string => dec.decode(payload.subarray(lead))
const LOOKALIKES = ['[2/3 deadbeef]\nhello', '[copy 2/5]\nthe whole text', '[copy 9]\nx', `[3/3 0123abcd] [copy 2/2]\nend`]

test('writer rule: a one-part text whose first line parses as a header gets [1/1 <h8> sha256=…] (ETH and SOL)', () => {
  for (const text of LOOKALIKES) {
    assert.ok(parsePart(text).headerLength > 0, 'the text alone would be misread as a part')
    const sha = sha256Hex(utf8(text))
    for (const [parts, lead] of [[ethParts(utf8(text)), LEAD.length], [solParts(utf8(text), 1010), 0]] as const) {
      assert.equal(parts.length, 1)
      const s = body(parts[0].payload, lead)
      assert.equal(s, `[1/1 ${sha.slice(0, 8)} sha256=${sha}]\n${text}`)
      const p = parsePart(s)
      assert.deepEqual([p.part, p.parts, p.sha256, p.body], [1, 1, sha, text], 'a reader gets the exact text back')
    }
  }
})

test('writer rule: plain texts keep no header; a header-looking line that is not the first does not force one', () => {
  for (const text of ['hello', '[not a header]\nx', 'x\n[2/3 deadbeef]\ny', `[1/1 deadbeef sha256=${'d'.repeat(64)}]\nsha does not verify`]) {
    assert.equal(parsePart(text).headerLength, 0)
    assert.equal(body(ethParts(utf8(text))[0].payload, LEAD.length), text)
  }
})

test('writer rule: a copy marker already separates the text, so copies ≥ 2 get the marker line only', () => {
  const text = LOOKALIKES[0], sha = sha256Hex(utf8(text))
  const p2 = ethParts(utf8(text), { sha256: sha, copy: 2, copies: 3 })
  assert.equal(body(p2[0].payload, LEAD.length), `[copy 2/3]\n${text}`)
  assert.equal(parsePart(body(p2[0].payload, LEAD.length)).body, text)
  const p1 = ethParts(utf8(text), { sha256: sha, copy: 1, copies: 3 })
  assert.match(body(p1[0].payload, LEAD.length), /^\[1\/1 [0-9a-f]{8} sha256=/, 'copy 1 has no marker, so it is forced')
})

test('writer rule: when the forced header does not fit one tx, the text takes two parts with ordinary headers', () => {
  const head = '[2/3 deadbeef]\n'
  const fitsBare = ETH.TX_DATA_CAP - LEAD.length                       // one part without a header
  const text = head + 'a'.repeat(fitsBare - head.length)
  const parts = ethParts(utf8(text))
  assert.equal(parts.length, 2)
  assert.match(body(parts[0].payload, LEAD.length), /^\[1\/2 [0-9a-f]{8} sha256=[0-9a-f]{64}\]\n\[2\/3 deadbeef\]\n/)
  assert.deepEqual(reassembleCopy(parts.map((p) => p.payload), { lead: LEAD, sha256: sha256Hex(utf8(text)) }).ok, true)
})

test('UTF-8 safety: an emoji, a CJK, a 2-byte char at every split boundary — every part decodes, the copy reassembles', () => {
  const unit = 'é漢😀a'                                                // 2 + 3 + 4 + 1 bytes
  for (let shift = 0; shift < 10; shift++) {
    const text = 'b'.repeat(shift) + unit.repeat(40), bytes = utf8(text), sha = sha256Hex(bytes)
    for (const cap of [120, 121, 122, 123, 157]) {
      const parts = splitText(bytes, { cap, sha256: sha })
      assert.ok(parts.length > 1)
      for (const p of parts) { assert.ok(p.payload.length <= cap); dec.decode(p.payload); dec.decode(p.chunk) }
      assert.equal(reassembleCopy(parts.map((p) => p.payload), { sha256: sha }).ok, true, `shift ${shift} cap ${cap}`)
    }
  }
})

test('SOL: the CU budget includes the header; 3/4-byte text splits by compute and still reassembles', () => {
  const text = '😀'.repeat(120) + '漢'.repeat(200), bytes = utf8(text), sha = sha256Hex(bytes)
  const parts = solParts(bytes, 1010)
  for (const p of parts) assert.ok(p.payload.length <= SOL.MEMO_MAX)
  assert.equal(reassembleCopy(parts.map((p) => p.payload), { sha256: sha }).ok, true)
})

test('reassembleCopy refuses: a missing or swapped part, another text\'s part, a mixed copy, a wrong lead, bad UTF-8', () => {
  const text = 'z'.repeat(2500), bytes = utf8(text), sha = sha256Hex(bytes)
  const parts = solParts(bytes, 1010).map((p) => p.payload)
  assert.equal(parts.length, 3)
  assert.equal(reassembleCopy(parts, { sha256: sha }).ok, true)
  assert.match(reassembleCopy([parts[0], parts[2]], { sha256: sha }).why, /header does not match/)
  assert.match(reassembleCopy([parts[1], parts[0], parts[2]], { sha256: sha }).why, /header does not match/)
  const other = solParts(utf8('y'.repeat(2500)), 1010).map((p) => p.payload)
  assert.equal(reassembleCopy([parts[0], other[1], parts[2]], { sha256: sha }).ok, false)
  const c2 = solParts(bytes, 1010, { sha256: sha, copy: 2, copies: 2 }).map((p) => p.payload)
  assert.match(reassembleCopy([parts[0], c2[1], c2[2]], { sha256: sha }).why, /another copy/)
  assert.match(reassembleCopy(parts, { lead: LEAD, sha256: sha }).why, /expected prefix/)
  assert.match(reassembleCopy([Uint8Array.from([0xff])], { sha256: sha }).why, /UTF-8/)
  assert.equal(reassembleCopy([], { sha256: sha }).ok, false)
  const tampered = parts.map((p) => p.slice()); tampered[2][tampered[2].length - 1] = 0x79
  assert.match(reassembleCopy(tampered, { sha256: sha }).why, /another sha256/)
})

test('previewParts keeps W2\'s shape (header bytes, chunk ranges, payload sizes) for both chains', () => {
  const text = 'q'.repeat(150_000), sha = sha256Hex(utf8(text))
  const pv = previewParts(text, sha)
  assert.equal(pv.eth.ok, true); assert.equal(pv.eth.max, ETH.TX_DATA_CAP); assert.equal(pv.eth.parts.length, 2)
  assert.deepEqual(Object.keys(pv.eth.parts[0]).sort(), ['end', 'header', 'i', 'n', 'size', 'start'])
  assert.equal(pv.eth.parts[0].header, `[1/2 ${sha.slice(0, 8)} sha256=${sha}]\n`.length)
  assert.equal(pv.eth.parts[1].end, 150_000); assert.equal(pv.eth.parts[0].size, ETH.TX_DATA_CAP)
  assert.equal(pv.sol.ok, true); assert.ok(pv.sol.parts.length > 100); assert.equal(pv.sol.parts.at(-1)!.end, 150_000)
  assert.deepEqual(previewParts('hi', sha256Hex(utf8('hi'))).eth.parts, [{ i: 1, n: 1, header: 0, start: 0, end: 2, size: 8 }])
})

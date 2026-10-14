import { test } from 'node:test'
import assert from 'node:assert/strict'
import { b64decode, b64encode, concat, equal, hex, latin1, sha256Hex, utf8 } from '../../src/text/bytes.ts'
import { fill } from './fixtures.ts'

test('b64encode/b64decode agree with Buffer for every length 0..200', () => {
  for (let n = 0; n <= 200; n++) {
    const b = new Uint8Array(fill(`b${n}`, n))
    const ref = Buffer.from(b).toString('base64')
    assert.equal(b64encode(b), ref, `len ${n}`)
    assert.deepEqual(b64decode(ref), b, `len ${n}`)
  }
})

test('b64decode is strict: null for padding errors, junk and whitespace', () => {
  for (const bad of ['QQ=', 'Q===', 'QQ==QQ==', '!!!!', 'QUJD\n', 'QU JD', 'QUJ']) assert.equal(b64decode(bad), null, bad)
  assert.deepEqual(b64decode(''), new Uint8Array(0))
})

test('latin1 maps every byte exactly like Buffer latin1', () => {
  const all = Uint8Array.from({ length: 256 }, (_, i) => i)
  assert.equal(latin1(all), Buffer.from(all).toString('latin1'))
  assert.equal(latin1(new Uint8Array(20000).fill(65)), 'A'.repeat(20000))
})

test('sha256Hex, hex, utf8, concat, equal', () => {
  assert.equal(sha256Hex(utf8('abc')), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  assert.equal(hex(Uint8Array.of(0, 15, 255)), '000fff')
  assert.deepEqual(utf8('é'), Uint8Array.of(0xc3, 0xa9))
  assert.deepEqual(concat(Uint8Array.of(1), Uint8Array.of(2, 3)), Uint8Array.of(1, 2, 3))
  assert.deepEqual(concat(), new Uint8Array(0))
  assert.ok(equal(Uint8Array.of(1, 2), Uint8Array.of(1, 2)))
  assert.ok(!equal(Uint8Array.of(1, 2), Uint8Array.of(1, 3)))
  assert.ok(!equal(Uint8Array.of(1, 2), Uint8Array.of(1)))
})

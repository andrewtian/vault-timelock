// The synchronous `crypto` shim the Privacy Cash SDK gets in the worker (src/privacycash/node-crypto.js) against node:crypto on
// random inputs: every function the SDK's withdraw path calls (research Q4), and the refusals.
import { test, expect } from 'vitest'
import * as real from 'node:crypto'
import { Buffer } from 'node:buffer'
import * as shim from '../src/privacycash/node-crypto.js'

const rnd = (n) => real.randomBytes(n)
const hex = (b) => Buffer.from(b).toString('hex')            // the npm `buffer` Buffer and node's do not .equals() each other: compare as hex

test('createHash sha256 and createHmac sha256 equal node:crypto (multi-update, string and bytes, hex output)', () => {
  for (let i = 0; i < 50; i++) {
    const a = rnd(i * 7), b = rnd(i), key = rnd(1 + (i % 40))
    expect(hex(shim.createHash('sha256').update(a).update(b).digest())).toBe(hex(real.createHash('sha256').update(a).update(b).digest()))
    expect(hex(shim.createHmac('sha256', key).update(a).update(b).digest())).toBe(hex(real.createHmac('sha256', key).update(a).update(b).digest()))
  }
  expect(shim.createHash('sha256').update('abc').digest('hex')).toBe(real.createHash('sha256').update('abc').digest('hex'))
  expect(shim.createHash('sha256').update('616263', 'hex').digest('hex')).toBe(real.createHash('sha256').update('abc').digest('hex'))
})

test('aes-256-gcm: shim and node:crypto open each other\'s output; the tag is checked', () => {
  for (let i = 0; i < 30; i++) {
    const key = rnd(32), iv = rnd(12), data = rnd(i * 13)
    const s = shim.createCipheriv('aes-256-gcm', key, iv)
    const ct = Buffer.concat([s.update(data), s.final()]), tag = s.getAuthTag()
    const r = real.createCipheriv('aes-256-gcm', key, iv)
    const rct = Buffer.concat([r.update(data), r.final()])
    expect(hex(ct)).toBe(hex(rct))
    expect(hex(tag)).toBe(hex(r.getAuthTag()))
    const d = shim.createDecipheriv('aes-256-gcm', key, iv); d.setAuthTag(tag)
    expect(hex(Buffer.concat([d.update(ct), d.final()]))).toBe(hex(data))
    const bad = Buffer.from(tag); bad[0] ^= 1
    const e = shim.createDecipheriv('aes-256-gcm', key, iv); e.setAuthTag(bad); e.update(ct)
    expect(() => e.final()).toThrow(/authenticate/)
    const f = shim.createDecipheriv('aes-256-gcm', key, iv); f.update(ct)
    expect(() => f.final()).toThrow(/authenticate/)                              // no tag at all
  }
})

test('aes-128-ctr equals node:crypto both ways', () => {
  for (let i = 0; i < 30; i++) {
    const key = rnd(16), iv = rnd(16), data = rnd(i * 11)
    const s = shim.createCipheriv('aes-128-ctr', key, iv), r = real.createCipheriv('aes-128-ctr', key, iv)
    const ct = Buffer.concat([s.update(data), s.final()])
    expect(hex(ct)).toBe(hex(Buffer.concat([r.update(data), r.final()])))
    const d = shim.createDecipheriv('aes-128-ctr', key, iv)
    expect(hex(Buffer.concat([d.update(ct), d.final()]))).toBe(hex(data))
  }
})

test('randomBytes: the right size, not constant, and bounded', () => {
  expect(shim.randomBytes(32)).toHaveLength(32)
  expect(hex(shim.randomBytes(16))).not.toBe(hex(shim.randomBytes(16)))
  expect(shim.randomBytes(0)).toHaveLength(0)
  expect(() => shim.randomBytes(-1)).toThrow(RangeError)
  expect(() => shim.randomBytes(1e9)).toThrow(RangeError)
})

test('anything outside the slice throws instead of being approximated', () => {
  expect(() => shim.createHash('sha1')).toThrow(/not supported/)
  expect(() => shim.createHmac('sha512', rnd(16))).toThrow(/not supported/)
  expect(() => shim.createCipheriv('aes-192-cbc', rnd(24), rnd(16))).toThrow(/not supported/)
  expect(() => shim.createCipheriv('aes-256-gcm', rnd(16), rnd(12))).toThrow(RangeError)        // wrong key size
  expect(() => shim.createCipheriv('aes-256-gcm', rnd(32), rnd(16))).toThrow(RangeError)        // wrong iv size
  expect(() => shim.createHash('sha256').update(5)).toThrow(TypeError)
  const c = shim.createCipheriv('aes-128-ctr', rnd(16), rnd(16)); c.final()
  expect(() => c.final()).toThrow(/finalised/)
  expect(() => c.getAuthTag()).toThrow(/no auth tag/)
})

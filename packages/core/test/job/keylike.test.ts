// assertNoSecretOrIp (structural fields: name, addresses, labels, API body strings) and looksLikeIp (spec §4.1).
// Mapped by test/mutation/guards.json: job.key-like, job.ip-like. ALL DATA IS SYNTHETIC (the canary and documentation
// ranges only; no key below has ever held funds).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { base58 } from '@scure/base'
import { english } from 'viem/accounts'
import { assertNoSecretOrIp, looksLikeIp } from '../../src/job/index.ts'
import { guardOf, refusalOf } from './helpers.ts'

const check = (s: string): string | null => guardOf(() => assertNoSecretOrIp(s, 'name'))
const HEX64 = 'ffdfb726351cc7ebad2ec2bf36d93e9ee918090b1217527b4ba49cdde595ef3d'
const b58of = (n: number, fill: number): string => base58.encode(new Uint8Array(n).fill(fill))
const B58_88 = b58of(64, 0xfe)
const B58_87 = (() => { for (let f = 1; f < 256; f++) { const s = b58of(64, f); if (s.length === 87) return s } throw new Error('no 87') })()
const words = (n: number, from = 0): string => english.slice(from, from + n).join(' ')

test('64 hex digits, with or without 0x, are key-like (any case, anywhere in the string)', () => {
  assert.equal(B58_88.length, 88)
  for (const s of [HEX64, `0x${HEX64}`, HEX64.toUpperCase(), `key ${HEX64} here`, `${HEX64}${HEX64}`, `x${HEX64}`]) assert.equal(check(s), 'job.key-like', s.slice(0, 8))
  assert.equal(check(HEX64.slice(0, 63)), null, '63 hex digits pass')
  assert.equal(check('0x8739Eb87B3d11f221Df63454F8D229a1A4F4049C'), null, 'an EIP-55 address passes')
})

test('base58 tokens of 87 or 88 characters (64-byte secrets) are key-like; shorter tokens (addresses) pass', () => {
  assert.equal(check(B58_88), 'job.key-like')
  assert.equal(check(B58_87), 'job.key-like')
  assert.equal(check(`token ${B58_88} end`), 'job.key-like')
  assert.equal(check('9xx7qC7uwTAeaSo7T5Gk9canYBosFh1pMQaDmQEa83Tb'), null, 'a 32-byte address passes')
  assert.equal(check(B58_88.slice(0, 86)), null, '86 base58 characters pass')
})

test('JSON arrays of 32 or 64 byte values are key-like', () => {
  const arr = (n: number): string => `[${Array.from({ length: n }, (_, i) => i + 1).join(',')}]`
  assert.equal(check(arr(64)), 'job.key-like', '[1,2,…64 items]')
  assert.equal(check(`[ ${Array.from({ length: 32 }, () => '255').join(' , ')} ]`), 'job.key-like', '32 items with spaces')
  assert.equal(check(arr(31)), null, '31 items pass')
  assert.equal(check(`[${Array.from({ length: 64 }, () => '256').join(',')}]`), null, 'values above 255 are not bytes')
})

test('AGE-SECRET-KEY-1… is key-like (any case)', () => {
  assert.equal(check(`AGE-SECRET-KEY-1${'Q'.repeat(58)}`), 'job.key-like')
  assert.equal(check('AGE-SECRET-KEY-1QQ…'), 'job.key-like')
  assert.equal(check('age-secret-key-1qq'), 'job.key-like')
})

test('12 consecutive BIP-39 words are key-like; 11 pass', () => {
  assert.equal(check(`${'abandon '.repeat(11)}about`), 'job.key-like')
  assert.equal(check(words(12, 100)), 'job.key-like')
  assert.equal(check(words(12, 2000).toUpperCase()), 'job.key-like', 'case does not hide a mnemonic')
  assert.equal(check(words(12, 300).replaceAll(' ', '\n')), 'job.key-like')
  assert.equal(check(words(11, 100)), null, '11 words pass')
  assert.equal(check(`${words(11, 100)} the ${words(11, 400)}`), null, 'a non-list word breaks the run')
})

test('URLs (scheme://) and .onion hosts are key-like', () => {
  assert.equal(check('https://example.com/x'), 'job.key-like')
  assert.equal(check('see socks5h://relay'), 'job.key-like')
  assert.equal(check(`${'a'.repeat(56)}.onion`), 'job.key-like')
  assert.equal(check('my.ONION'), 'job.key-like')
})

test('IPv4 and IPv6 literals are ip-like (the canary, documentation ranges, loopback, inside URLs)', () => {
  for (const [i, s] of ['203.0.113.77', 'node 203.0.113.77', 'ip=203.0.113.77.', '2001:db8::1', '[2001:db8::1]:8545', 'host fe80::1 down',
    '127.0.0.1', '::ffff:203.0.113.77', 'https://203.0.113.77/x', 'http://[2001:db8::1]/', 'ip:2001:db8::1'].entries()) {
    assert.equal(check(s), 'job.ip-like', `case ${i}`) // never print an address, even on failure
  }
})

test('timestamps, versions, ratios and C++-style paths are not IPs', () => {
  for (const [i, s] of ['12:30:45', 'at 12:30', '2026-10-09T00:00:00Z', 'v1.2.3', '1.2.3.4.5', '256.1.1.1', 'std::vector', 'Foo::Bar', '3:16', 'x :: y', 'eth drain to the null address'].entries()) {
    assert.equal(check(s), null, `case ${i}`)
  }
})

test('the refusal message names the field and never echoes the value', () => {
  for (const [i, s] of [HEX64, '203.0.113.77', B58_88, 'https://example.com'].entries()) {
    const e = refusalOf(() => assertNoSecretOrIp(s, 'chains.eth.label'))
    assert.ok(!e.message.includes(s), `value not echoed (case ${i})`)
    assert.ok(e.message.includes('chains.eth.label'))
  }
  const e = refusalOf(() => assertNoSecretOrIp(HEX64, HEX64))
  assert.ok(!e.message.includes(HEX64), 'a key-like field label is not echoed either')
})

test('looksLikeIp: strict IPv4 dotted quad 0-255; IPv6 by a bracketed URL parse', () => {
  for (const [i, t] of ['203.0.113.77', '0.0.0.0', '198.51.100.255', '127.0.0.1', '2001:db8::1', '[2001:db8::1]', '::1', '::', 'fe80::1%en0', '::ffff:203.0.113.77', '1:2:3:4:5:6:7:8'].entries()) {
    assert.equal(looksLikeIp(t), true, `case ${i}`)
  }
  for (const [i, t] of ['12:30:45', '256.1.1.1', '1.2.3', '1.2.3.4.5', '192.0.2.4 ', 'abc', '', '1:2:3:4:5:6:7:8:9', 'std::vector', 'g::1', '1.2.3.-4', '1e192.0.2.1'].entries()) {
    assert.equal(looksLikeIp(t), false, `case ${i}`)
  }
})

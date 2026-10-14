// validateMessage (spec §4.1, R50 + R72): refused, never rewritten. Mapped by test/mutation/guards.json: message.empty,
// message.nfc, message.control, message.utf8, message.too-long, message.secret, message.ip-like.
// ALL DATA IS SYNTHETIC. Never print an address: assertion labels use case indexes.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readdirSync, readFileSync } from 'node:fs'
import { base58 } from '@scure/base'
import { english } from 'viem/accounts'
import { MESSAGE_MAX } from '../../src/contracts/index.ts'
import { validateMessage } from '../../src/job/index.ts'
import { decode, fixture, guardOf, readJson, refusalOf } from './helpers.ts'

const v = (t: string): string | null => guardOf(() => validateMessage(t))
const nodeSha = (s: string): string => createHash('sha256').update(Buffer.from(s, 'utf8')).digest('hex')
const QUICKNET = '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971'

test('sealed-like.txt is accepted with a hex64 warning; multibyte-5k.txt with none', () => {
  const valid = readJson<Record<string, { bytes: number; sha256: string; warnings: string[] }>>('messages/valid.json')
  const sealed = decode(readFileSync(fixture('messages/sealed-like.txt')))
  assert.deepEqual(validateMessage(sealed), valid['sealed-like.txt'])
  assert.deepEqual(validateMessage(sealed).warnings, ['hex64'])
  const mb = decode(readFileSync(fixture('messages/multibyte-5k.txt')))
  assert.deepEqual(validateMessage(mb), valid['multibyte-5k.txt'])
  assert.equal(validateMessage(mb).sha256, nodeSha(mb))
  assert.equal(validateMessage(mb).bytes, Buffer.byteLength(mb, 'utf8'))
})

test('each messages/bad/* is refused with its guard (bytes decoded the contracted way)', () => {
  const bad = readJson<Record<string, string>>('messages/bad/expected.json')
  assert.deepEqual(readdirSync(fixture('messages/bad')).filter((f) => f !== 'expected.json').sort(), Object.keys(bad).sort())
  for (const [file, guard] of Object.entries(bad)) {
    let text: string
    try { text = decode(readFileSync(fixture(`messages/bad/${file}`))) } catch { assert.equal(guard, 'message.utf8', file); continue }
    assert.equal(v(text), guard, file)
  }
})

test('MESSAGE_MAX bytes are accepted; MESSAGE_MAX + 1 bytes are message.too-long (counted in UTF-8 bytes)', () => {
  const max = 'a'.repeat(MESSAGE_MAX)
  assert.deepEqual(validateMessage(max), { bytes: MESSAGE_MAX, sha256: nodeSha(max), warnings: [] })
  assert.equal(v(`${max}a`), 'message.too-long')
  const half = 'é'.repeat(MESSAGE_MAX / 2) // 2 bytes each: exactly MESSAGE_MAX bytes in half as many code units
  assert.equal(validateMessage(half).bytes, MESSAGE_MAX)
  assert.equal(v(`${half}a`), 'message.too-long')
  assert.equal(v(`${'😀'.repeat(MESSAGE_MAX / 4)}a`), 'message.too-long', '4-byte code points count 4')
})

test('lone surrogates and U+FFFD (a lossy decode) are message.utf8', () => {
  assert.equal(v('a\uD800b'), 'message.utf8')
  assert.equal(v('a\uDC00'), 'message.utf8')
  assert.equal(v('\uD83D'), 'message.utf8')
  assert.equal(v('abc\uFFFD def\n'), 'message.utf8')
  assert.equal(v('😀\n'), null, 'a surrogate pair is fine')
  assert.equal(v(3 as unknown as string), 'message.utf8', 'not a string')
})

test('NFC only: precomposed é is accepted, e + U+0301 is message.nfc (never normalized for you)', () => {
  assert.equal(v('caf\u00e9\n'), null)
  assert.equal(v('cafe\u0301\n'), 'message.nfc')
  assert.equal(v('\u212b'), 'message.nfc', 'ANGSTROM SIGN normalizes to Å')
})

test('LF only; every other C0/C1 control, bidi control, line/paragraph separator and BOM is message.control', () => {
  assert.equal(v('line one\nline two\n'), null)
  const bad = ['\r', '\t', '\u0000', '\u0007', '\u000b', '\u000c', '\u001b', '\u007f', '\u0080', '\u0085', '\u009f', '\u061c', '\u200e', '\u200f',
    '\u202a', '\u202e', '\u2066', '\u2069', '\u2028', '\u2029', '\ufeff']
  for (const c of bad) assert.equal(v(`a${c}b\n`), 'message.control', `U+${c.charCodeAt(0).toString(16).padStart(4, '0')}`)
  assert.equal(v('\ufeffleading BOM\n'), 'message.control')
  assert.equal(v('👨\u200d👩\u200d👧 family (ZWJ is not a control)\n'), null)
})

test('the empty text is message.empty', () => {
  assert.equal(v(''), 'message.empty')
  assert.equal(v('\n'), null, 'non-empty')
})

test('unambiguous secrets are message.secret', () => {
  assert.equal(v(`key: AGE-SECRET-KEY-1${'Q'.repeat(58)}\n`), 'message.secret')
  assert.equal(v(`age-secret-key-1${'q'.repeat(58)}\n`), 'message.secret')
  assert.equal(v(`${'abandon '.repeat(11)}about\n`), 'message.secret')
  assert.equal(v(`${english.slice(500, 512).join(' ')}\n`), 'message.secret')
  assert.equal(v(`1. ${english.slice(700, 712).join('\n2. ')}\n`), 'message.secret', 'numbered mnemonic')
  const b88 = base58.encode(new Uint8Array(64).fill(0xfe))
  assert.equal(b88.length, 88)
  assert.equal(v(`token ${b88}\n`), 'message.secret')
  assert.equal(v(`[${Array.from({ length: 64 }, (_, i) => (i * 7) % 256).join(', ')}]\n`), 'message.secret')
})

test('publication text may hold hashes, URLs, near-misses and SEALED.txt wording', () => {
  for (const t of [
    `drand: quicknet ${QUICKNET}\ncheck: https://api.drand.sh/${QUICKNET}/public/23456789\n`,
    'https://api.drand.sh/…\n',
    `${english.slice(100, 111).join(' ')}\n`, // 11 BIP-39 words
    `[${Array.from({ length: 32 }, (_, i) => i).join(',')}]\n`, // 32 byte values (only 64 is unambiguous here)
    '  - unlock-TIME.age: the one-time key, one AGE-SECRET-KEY-1... line, tlock-encrypted\n',
    `${base58.encode(new Uint8Array(32).fill(9))} is an address\n`,
    'tle v1.2.0 https://github.com/drand/tlock and age v1.3.1\n',
    'unlock: 2027-10-09T00:00:00Z at 12:30:45\n',
    'std::vector<int> and Foo::Bar\n',
    `${'a'.repeat(100)}\n`,
  ].entries()) assert.equal(v(t[1]), null, `case ${t[0]}`)
})

test('IP literals are message.ip-like: bare, in a URL host (any WHATWG spelling), bracketed IPv6', () => {
  for (const [i, t] of [
    'relay at 203.0.113.77 port 443\n', 'see https://203.0.113.77/x\n', 'http://3405803853/\n', 'http://0xcb.0.113.77/\n',
    'node [2001:db8::1]:8545\n', 'http://[2001:db8::1]/\n', 'host fe80::1 is down\n', 'ws://user@203.0.113.77:9000\n',
  ].entries()) assert.equal(v(t), 'message.ip-like', `case ${i}`)
})

test('loopback is not an identifying address: broadcast SEALED.txt open steps (Tor via 127.0.0.1:9050) pass', () => {
  const tor = 'env -u NO_PROXY -u no_proxy HTTPS_PROXY=socks5h://127.0.0.1:9050 '
  const steps = [
    '  3. recover identity.key with drand\'s signature for round 23456789, through Tor (SOCKS on',
    '     127.0.0.1:9050; without Tor, drop the env prefix and drand sees your IP ask for this round).',
    `     $ ${tor}tle --decrypt --output=identity.key unlock-TIME.age`,
    '',
  ].join('\n')
  assert.equal(v(steps), null)
  assert.equal(v('loopback http://[::1]:5181/ only\n'), null)
})

test('a refusal never echoes the text', () => {
  for (const [i, t] of ['relay at 203.0.113.77 port 443\n', `key: AGE-SECRET-KEY-1${'Q'.repeat(58)}\n`].entries()) {
    const e = refusalOf(() => validateMessage(t))
    assert.ok(!e.message.includes(t.trim()) && !e.message.includes('203.0.113'), `case ${i}`)
  }
})

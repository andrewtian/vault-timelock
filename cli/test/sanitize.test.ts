// cli/test/sanitize.test.ts — the filter between a sandboxed child's output and the operator's terminal (TTY-less round, ruling (c)).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Sanitizer, localeIsUtf8, sanitize } from '../src/ops/sanitize.ts'

test('plain text, newline and tab pass; CR, BEL, BS, NUL and DEL do not (CRLF becomes LF)', () => {
  assert.equal(sanitize('hello\tworld\nnext line ✓ é\n'), 'hello\tworld\nnext line ✓ é\n')
  assert.equal(sanitize('a\r\nb\x07c\x08d\x00e\x7ff'), 'a\nbcdef')
})

test('OSC 52 (clipboard), titles and every OSC are dropped, ended by BEL, ST (ESC \\) or the 8-bit ST', () => {
  assert.equal(sanitize('x\x1b]52;c;c2VjcmV0\x07y'), 'xy')
  assert.equal(sanitize('x\x1b]52;c;c2VjcmV0\x1b\\y'), 'xy')
  assert.equal(sanitize('x\x1b]0;title\x07y\x1b]8;;http://e/\x1b\\link\x1b]8;;\x1b\\'), 'xylink')
  assert.equal(sanitize('x\u009d52;c;c2VjcmV0\u009cy'), 'xy', '8-bit OSC ... ST')
  assert.ok(!sanitize('a\x1b]52;c;SECRET').includes('SECRET'), 'an unterminated OSC drops the rest of the stream')
})

test('CSI (colours, cursor, device reports, window ops), DCS, APC, PM, SOS and two-character escapes are dropped', () => {
  assert.equal(sanitize('\x1b[31mred\x1b[0m \x1b[2J\x1b[H\x1b[6n\x1b[?1049h\x1b[8;50;200t ok'), 'red  ok')
  assert.equal(sanitize('a\x1bP1$r0m\x1b\\b\x1b_apc\x1b\\c\x1b^pm\x1b\\d\x1bXsos\x1b\\e'), 'abcde')
  assert.equal(sanitize('a\x1bcb\x1b7c\x1b(Bd\x1b=e'), 'abcde')
  assert.equal(sanitize('a\x1b'), 'a', 'a trailing ESC is dropped')
  assert.equal(sanitize('a\x1b[31'), 'a', 'an unfinished CSI is dropped')
})

test('C1 controls in any form are dropped; 8-bit CSI too', () => {
  assert.equal(sanitize('a\u009b31mb\u0085c\u0090x\u009cd'), 'abcd')
  for (let c = 0x80; c <= 0x9f; c++) assert.ok(!/[\u0080-\u009f]/.test(sanitize(`a${String.fromCharCode(c)}b`)), c.toString(16))
})

test('a sequence split across chunks (also inside a UTF-8 character) is still recognised', () => {
  const s = new Sanitizer()
  const bytes = Buffer.from('ok\x1b]52;c;SECRET\x07é✓ done')
  let out = ''
  for (const b of bytes) out += s.push(Buffer.from([b]))
  out += s.end()
  assert.equal(out, 'oké✓ done')
  const t = new Sanitizer()
  assert.equal(t.push('a\x1b[') + t.push('31') + t.push('mb'), 'ab')
})

test('every C0 control but \\n and \\t is gone, whatever the surrounding text', () => {
  for (let c = 0; c < 0x20; c++) {
    if (c === 0x0a || c === 0x09 || c === 0x1b) continue
    assert.equal(sanitize(`a${String.fromCharCode(c)}b`), 'ab', c.toString(16))
  }
})

test('M-3: bidi controls, zero-width and other format characters, tag characters, separators and variation selectors are dropped; ordinary non-ASCII stays', () => {
  const bad = ['‪', '‫', '‬', '‭', '‮', '⁦', '⁧', '⁨', '⁩', '‎', '‏', '؜', '​', '‌', '‍',
    '⁠', '⁡', '⁤', '﻿', '­', 'ㅤ', ' ', ' ', '️', '\u{e0041}', '\u{e007f}']
  for (const b of bad) assert.equal(sanitize(`a${b}b`), 'ab', b.codePointAt(0)!.toString(16))
  assert.equal(sanitize('Type ‮esaeler‬ to continue'), 'Type esaeler to continue')
  assert.equal(sanitize('é ✓ ě 日本 😀'), 'é ✓ ě 日本 😀')
})

test('M-3: in a non-UTF-8 locale only ASCII is emitted and other characters are shown as \\u{hex}', () => {
  assert.equal(sanitize('ě✓ ok', true), '\\u{11b}\\u{2713} ok')
  assert.equal(localeIsUtf8({ LANG: 'en_US.UTF-8' }), true)
  assert.equal(localeIsUtf8({ LANG: 'en_US.utf8' }), true)
  assert.equal(localeIsUtf8({ LANG: 'C' }), false)
  assert.equal(localeIsUtf8({ LANG: 'en_US.UTF-8', LC_ALL: 'C' }), false, 'LC_ALL wins')
  assert.equal(localeIsUtf8({}), false)
})

test('N-3: the broker tag cannot be forged by child output: bracketed look-alikes (case, spaces, fillers, fullwidth, Cyrillic) lose their brackets, also split across chunks', () => {
  const forged = ['[vt broker]', '[VT BROKER]', '[vt  broker]', '[v​t br⠀oker]', '[vtᅟ broker]', '[ｖｔ ｂｒｏｋｅｒ]', '[vt brоker]', '[vt broker]', '[vt-broker]', '[\u03bdt broker]']
  for (const f of forged) {
    const out = sanitize(`${f} passphrase of the key backup x (eth)`)
    assert.ok(!out.includes('['), `${JSON.stringify(f)} -> ${out}`)
    assert.ok(out.startsWith('('), out)
  }
  const s = new Sanitizer()
  assert.equal(s.push('a [vt ') + s.push('bro') + s.push('ker] b') + s.end(), 'a (vt broker) b')
  assert.equal(sanitize('[ordinary] [1] [x y]'), '[ordinary] [1] [x y]')
  assert.equal(sanitize('progress [3/7]\n'), 'progress [3/7]\n')
  assert.equal(sanitize('unterminated [vt brok'), 'unterminated [vt brok')
  assert.equal(sanitize('a b　c'), 'a b c')
})

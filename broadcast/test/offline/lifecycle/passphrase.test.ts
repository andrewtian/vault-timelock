// Task 12b: the EFF wordlist pin, the passphrase rule (checkStrength) and the /dev/tty reader (readPassphrase).
// Every passphrase here is synthetic. readPassphrase is never called in-process on the default /dev/tty (that could be
// the operator's terminal): in-process calls name a non-terminal ttyPath, and real reads run in a child on its own pty
// (script(1), see pty.ts) or detached with no terminal at all.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Refusal } from '../../../src/guard.ts'
import { checkStrength, readPassphrase, strengthOf } from '../../../src/lifecycle/passphrase.ts'
import { loadWordlist, WORDLIST_PATH, WORDLIST_SHA256 } from '../../../src/lifecycle/wordlist.ts'
import { refused, refusedAsync, seededRandom } from './helpers.ts'
import { runInPty } from './pty.ts'

const CHILD = new URL('./passphrase-child.ts', import.meta.url).pathname
const sha = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex')
const ptyEnv = (home: string): Record<string, string> => ({
  PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home, LANG: 'en_US.UTF-8', TERM: 'dumb',
})

function withTmp<T>(f: (d: string) => Promise<T> | T): Promise<T> {
  const d = mkdtempSync(join(tmpdir(), 'vt-12b-pass-'))
  return Promise.resolve().then(() => f(d)).finally(() => rmSync(d, { recursive: true, force: true }))
}

// ---- wordlist

test('wordlist: the vendored EFF large list loads (7776 words, hyphenated ones included) and matches its pin', () => {
  const words = loadWordlist()
  assert.equal(words.size, 7776)
  for (const w of ['abacus', 'zoom', 't-shirt', 'drop-down']) assert.ok(words.has(w), w)
  assert.equal(createHash('sha256').update(readFileSync(WORDLIST_PATH)).digest('hex'), WORDLIST_SHA256)
})

test('wordlist: a file with another hash, or no file, refuses keystore.wordlist-hash', async () => {
  await withTmp((d) => {
    const bad = join(d, 'eff_large_wordlist.txt')
    copyFileSync(WORDLIST_PATH, bad)
    const bytes = readFileSync(bad)
    bytes[bytes.length - 2] ^= 1 // one bit of the last word
    writeFileSync(bad, bytes)
    refused(() => loadWordlist(bad), 'keystore.wordlist-hash')
    refused(() => loadWordlist(join(d, 'missing.txt')), 'keystore.wordlist-hash')
  })
})

// ---- checkStrength

const weak = (p: string): void => refused(() => checkStrength(p), 'passphrase.weak')
const WORD = Math.log2(7776)
const near = (got: number, want: number): void => assert.ok(Math.abs(got - want) < 0.01, `${got} != ${want}`)

test('strength (fix round 1 ruling): every reviewer probe is weak', () => {
  const probes = [
    'abacus.abdomen.abdominal.abide.abiding', 'abacus_abdomen_abdominal_abide_abiding', 'abacusabdomenabdominalabideabiding',
    'abacus abdomen abdominal abide abiding7', 'abacus_abdomen_abide', 'correctbatterystaple', 'passwordpasswordpassword',
    'aaaaaaaaaaaaaaaaaaaa', 'abcdefghijklmnopqrst', '12345678901234567890123456', 'abacus abacus abacus abacus abacus abacus',
  ]
  for (const p of probes) {
    weak(p)
    assert.ok(strengthOf(p).bits < 80, p)
  }
})

test('strength: 6 distinct EFF words pass with any separators (spaces, hyphens, dots, underscores, none, doubled, around)', () => {
  for (const p of [
    'abacus abdomen abdominal abide abiding ability', 'abacus-abdomen-abdominal-abide-abiding-ability',
    'abacus.abdomen.abdominal.abide.abiding.ability', 'abacus_abdomen_abdominal_abide_abiding_ability',
    'ablaze able-abacus ability.abide_abiding', '  abacus  abdomen abdominal   abide abiding ability  ',
    'Abacus Abdomen Abdominal Abide Abiding Ability', 'abacusabdomenabdominalabideabidingability',
  ]) {
    checkStrength(p)
    assert.equal(strengthOf(p).distinctWords, 6, p)
  }
})

test('strength: words are counted once (distinct), hyphenated list words count once, capitals add nothing', () => {
  weak('abacus abdomen abdominal abide abiding')
  weak('Abacus Abdomen Abdominal Abide Abiding')
  weak('abacus abacus abdomen abide abiding ability') // 5 distinct: 5 words + a repeat at ~1 bit = 65.6 bits
  near(strengthOf('abacus abacus abdomen abide abiding ability').bits, 5 * WORD + 1)
  weak('abacus t-shirt yo-yo drop-down felt-tip') // t-shirt is one list word, not "t" + "shirt"
  checkStrength('abacus t-shirt yo-yo drop-down felt-tip able')
  near(strengthOf('abacus_abdomen_abide').bits, 3 * WORD) // the reviewer's ~38.8 bits
})

test('strength: "correct horse" is weak; a 20-character random mixed string passes; runs, repeats and keyboard rows count ~1 bit', () => {
  weak('correct horse')
  weak('')
  weak('   ')
  checkStrength('Tq7#vL2!pZ9@wR4$kM8%')
  assert.equal([...'Tq7#vL2!pZ9@wR4$kM8%'].length, 20)
  near(strengthOf('Tq7#vL2!pZ9@wR4$kM8%').bits, 20 * Math.log2(95)) // its symbols are characters too: 131.4 bits
  weak('Tq7#vL2!pZ9') // 11 x log2(95) = 72.3 bits
  weak('qwertyuiopasdfghjklzxcvbnm')
  weak('zyxwvutsrqponmlkjihgfedcba')
  weak('a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p') // a run of letters, and the '.' seen before: ~1 bit each (40.8 bits)
  assert.ok(strengthOf('aaaaaaaaaaaaaaaaaaaa').bits < 12) // a, a, a, then ever longer repeats at ~1 bit each
})

test('strength: 5 EFF words plus one random 8-character mixed token are judged by the score (here 118.2 bits: ok)', () => {
  // 5 x 12.925 for the words (the spaces between them are free) + 1 for the last space (a symbol seen before, not
  // between two words) + 8 x log2(95) for X k 9 # m Q 2 v (a symbol not seen before is a character)
  const p = 'abacus abdomen abdominal abide abiding Xk9#mQ2v'
  near(strengthOf(p).bits, 5 * WORD + 1 + 8 * Math.log2(95))
  assert.equal(strengthOf(p).distinctWords, 0) // not all words: the all-words rule does not apply
  checkStrength(p)
  weak('abacus abdomen abdominal abide abiding 7') // 64.6 + 1 + log2(69) = 71.7 bits
})

// Fix round 2 (re-review ruling): a symbol run is free only between two words; otherwise a symbol is a character
// (~1 bit if seen before); runs and keyboard rows compare letters/digits with the previous letter/digit.
test('strength: random passwords with symbols pass; symbol tricks stay weak (re-review figures)', () => {
  const L95 = Math.log2(95)
  const L59 = Math.log2(59)
  const ok: Array<[string, number]> = [
    ['k#9!Qz@4^Lm&2*Rt%7$W', 18 * L95 + 2], // 120.3 (l-m and r-t are cheap)
    ['Tq7#vL2!pZ9@wR4$kM8%', 20 * L95], // 131.4
    // 128.8: 19 characters at log2(95), w-q cheap, the 3 repeated '-' ~1 bit each (the reviewer's scorer said ~145,
    // pricing the repeated '-' in full; rule 2 prices a symbol seen before at ~1 bit)
    ['m9Wq-Tz4-Lp7x-Hb2N-vR5c', 19 * L95 + 4],
  ]
  for (const [p, bits] of ok) {
    checkStrength(p)
    near(strengthOf(p).bits, bits)
  }
  const weakOnes: Array<[string, number]> = [
    ['a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p', 2 * L59 + 29], // 40.8
    ['abc!abc!abc!abc!abc', 2 * L59 + 5], // 16.8
    ['aaaa.aaaa.aaaa.aaaa', 2 * L59 + 5], // 16.8
    ['!!!!!!!!!!!!!!!!!!!!', Math.log2(33) + 5], // 10.0
    ['qwerty!asdfgh!zxcvbn!', 4 * L59 + 17], // 40.5
    ['abacus#abdomen#abdominal#abide#abiding#7', 5 * WORD + 1 + Math.log2(69)], // 71.7: the last '#' is not between words
  ]
  for (const [p, bits] of weakOnes) {
    weak(p)
    near(strengthOf(p).bits, bits)
  }
})

test('strength: random 20- and 24-character passwords over all 95 printable characters are never refused (seeded, 1000 each)', () => {
  for (const [len, seed] of [[20, 1220], [24, 1224]]) {
    const r = seededRandom(seed)
    let refusedCount = 0
    let lowest = Infinity
    for (let k = 0; k < 1000; k++) {
      let p = ''
      for (let i = 0; i < len; i++) p += String.fromCharCode(0x20 + r.int(95))
      try { checkStrength(p) } catch (e) {
        assert.ok(e instanceof Refusal && e.guardId === 'passphrase.weak')
        refusedCount++
      }
      lowest = Math.min(lowest, strengthOf(p).bits)
    }
    assert.equal(refusedCount, 0, `${len} characters: ${refusedCount} of 1000 refused (lowest ${lowest.toFixed(1)} bits)`)
  }
})

test('strength: a refusal never echoes the passphrase', () => {
  const p = 'synthetic weak secret'
  try { checkStrength(p); assert.fail('expected a refusal') } catch (e) {
    assert.ok(e instanceof Refusal && e.guardId === 'passphrase.weak')
    assert.ok(!e.message.includes(p) && !e.message.includes('synthetic'))
  }
})

// ---- readPassphrase: no terminal

test('readPassphrase: a path that is not a terminal refuses passphrase.no-tty', async () => {
  await withTmp(async (d) => {
    writeFileSync(join(d, 'file'), 'abacus abdomen abdominal abide abiding ability\n')
    await refusedAsync(() => readPassphrase({ confirm: false, ttyPath: '/dev/null' }), 'passphrase.no-tty')
    await refusedAsync(() => readPassphrase({ confirm: false, ttyPath: join(d, 'file') }), 'passphrase.no-tty')
    await refusedAsync(() => readPassphrase({ confirm: true, ttyPath: join(d, 'missing') }), 'passphrase.no-tty')
  })
})

test('readPassphrase: without a controlling terminal it refuses passphrase.no-tty and never falls back to stdin', async () => {
  await withTmp(async (d) => {
    // detached: setsid(), so the child has no controlling terminal; a passphrase waits on its stdin, unread
    const c = spawn(process.execPath, ['--disable-sigusr1', CHILD, 'once'], { env: ptyEnv(d), stdio: ['pipe', 'pipe', 'pipe'], detached: true })
    c.stdin.on('error', () => { /* the child may exit before reading */ })
    c.stdin.end('abacus abdomen abdominal abide abiding ability\n')
    let out = ''
    c.stdout.on('data', (b: Buffer) => { out += b.toString('utf8') })
    const code = await new Promise<number | null>((res) => c.on('close', res))
    assert.equal(code, 0)
    assert.match(out, /^refused passphrase\.no-tty restored=false\n$/)
  })
})

// ---- readPassphrase: on a pty

const PASS = 'ablaze able abacus ability abide abiding'

test('readPassphrase on a pty: reads to Enter with echo off (the pty output never shows it) and restores the tty mode', async () => {
  await withTmp(async (d) => {
    const r = await runInPty([process.execPath, '--disable-sigusr1', CHILD, 'once'], { env: ptyEnv(d), steps: [{ waitFor: 'Passphrase: ', send: PASS + '\r' }] })
    assert.equal(r.code, 0)
    assert.ok(r.out.includes(`read sha256=${sha(PASS)} restored=true`), 'read the passphrase, mode restored')
    assert.ok(!r.out.includes(PASS) && !r.out.includes('ablaze'), 'the passphrase was echoed')
    assert.equal(r.out.split('Passphrase: ').length, 2, 'asked once')
  })
})

test('readPassphrase on a pty with confirm: asks twice; equal entries pass, different ones refuse passphrase.mismatch', async () => {
  await withTmp(async (d) => {
    const ok = await runInPty([process.execPath, '--disable-sigusr1', CHILD, 'confirm'], {
      env: ptyEnv(d),
      steps: [{ waitFor: 'Passphrase: ', send: PASS + '\r' }, { waitFor: 'Repeat passphrase: ', send: PASS + '\r' }],
    })
    assert.ok(ok.out.includes(`read sha256=${sha(PASS)} restored=true`))
    assert.ok(!ok.out.includes(PASS))
    const other = 'ablaze able abacus ability abide abdomen'
    const bad = await runInPty([process.execPath, '--disable-sigusr1', CHILD, 'confirm'], {
      env: ptyEnv(d),
      steps: [{ waitFor: 'Passphrase: ', send: PASS + '\r' }, { waitFor: 'Repeat passphrase: ', send: other + '\r' }],
    })
    assert.ok(bad.out.includes('refused passphrase.mismatch restored=true'), 'mismatch refused, mode restored')
    assert.ok(!bad.out.includes(PASS) && !bad.out.includes(other))
  })
})

test('readPassphrase on a pty: Ctrl-C, Ctrl-D and other control characters refuse passphrase.aborted (mode restored)', async () => {
  await withTmp(async (d) => {
    for (const send of ['abc\x03def\r', '\x04', 'abc\x1b[Adef\r']) {
      const r = await runInPty([process.execPath, '--disable-sigusr1', CHILD, 'once'], { env: ptyEnv(d), steps: [{ waitFor: 'Passphrase: ', send }] })
      assert.ok(r.out.includes('refused passphrase.aborted restored=true'), JSON.stringify(send))
    }
  })
})

test('readPassphrase on a pty: backspace and Ctrl-U edit the line; UTF-8 input is read as typed', async () => {
  await withTmp(async (d) => {
    const cases: Array<[string, string]> = [
      ['abcX\x7fdef\r', 'abcdef'],
      ['abcX\bdef\r', 'abcdef'],
      ['zzz\x15ablaze\r', 'ablaze'],
      ['pässwörd\r', 'pässwörd'],
      ['aé\x7fb\r', 'ab'], // backspace removes the whole two-byte character
      ['\x7f\x7fab\n', 'ab'], // backspace on an empty line does nothing; LF ends the line too
    ]
    for (const [send, want] of cases) {
      const r = await runInPty([process.execPath, '--disable-sigusr1', CHILD, 'once'], { env: ptyEnv(d), steps: [{ waitFor: 'Passphrase: ', send }] })
      assert.ok(r.out.includes(`read sha256=${sha(want)} restored=true`), JSON.stringify(send))
    }
  })
})

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { armor, dearmor } from '../../src/armor.ts'
import { Refusal } from '../../src/guard.ts'
import { fill } from './fixtures.ts'

// Resolved from PATH (spawnSync searches PATH for a bare command name).
const AGE = 'age'
const KEYGEN = 'age-keygen'

function malformed(t: string) {
  assert.throws(() => dearmor(t), (e: unknown) => e instanceof Refusal && e.guardId === 'armor.malformed')
}

test('armor equals `age -a`, and `age -d` accepts our armored text', () => {
  const d = mkdtempSync(join(tmpdir(), 'vt-armor-'))
  try {
    const key = join(d, 'key.txt')
    const kg = spawnSync(KEYGEN, ['-o', key], { encoding: 'utf8' })
    assert.equal(kg.status, 0)
    const pub = /public key: (age1\S+)/i.exec(kg.stderr)![1]
    for (const n of [1, 47, 48, 49, 100, 1000]) {
      const plain = fill(`p${n}`, n)
      writeFileSync(join(d, 'plain'), plain)
      const bin = spawnSync(AGE, ['-r', pub, join(d, 'plain')])
      assert.equal(bin.status, 0)
      const asc = spawnSync(AGE, ['-a', '-r', pub, join(d, 'plain')])
      assert.equal(asc.status, 0)
      // age's armor of the *same binary*: re-armor ours and decrypt; and shape equals age -a's shape
      const ours = armor(bin.stdout)
      writeFileSync(join(d, 'ours.age'), ours)
      const dec = spawnSync(AGE, ['-d', '-i', key, join(d, 'ours.age')])
      assert.equal(dec.status, 0, dec.stderr?.toString())
      assert.ok(Buffer.from(dec.stdout).equals(plain))
      // age -a output (different ephemeral key) parses with our strict dearmor and re-armors identically
      const theirs = asc.stdout.toString('latin1')
      assert.equal(armor(dearmor(theirs)), theirs)
      assert.ok(Buffer.from(dearmor(ours)).equals(bin.stdout))
    }
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('armor line shape: 64-col lines, last 1..64, \\n only', () => {
  for (const n of [1, 3, 48, 49, 96, 97, 500]) {
    const t = armor(fill('s', n))
    const lines = t.split('\n')
    assert.equal(lines[0], '-----BEGIN AGE ENCRYPTED FILE-----')
    assert.equal(lines[lines.length - 1], '')
    assert.equal(lines[lines.length - 2], '-----END AGE ENCRYPTED FILE-----')
    const body = lines.slice(1, -2)
    body.slice(0, -1).forEach((l) => assert.equal(l.length, 64))
    assert.ok(body[body.length - 1].length >= 1 && body[body.length - 1].length <= 64)
    assert.ok(!t.includes('\r'))
  }
})

test('dearmor round-trips', () => {
  for (const n of [1, 2, 3, 47, 48, 49, 300]) {
    const b = fill('rt', n)
    assert.ok(Buffer.from(dearmor(armor(b))).equals(b))
  }
})

test('dearmor refuses non-canonical input (armor.malformed)', () => {
  const good = armor(fill('g', 200))
  malformed(good.replace(/\n/g, '\r\n'))
  malformed(good.replace(/\n$/, ''))                                    // no trailing newline
  malformed(good.replace('-----END AGE ENCRYPTED FILE-----\n', ''))    // missing footer
  malformed(good.replace('-----BEGIN AGE ENCRYPTED FILE-----\n', ''))  // missing header
  const lines = good.split('\n')
  const long = [...lines]
  long[1] = lines[1] + lines[2].slice(0, 1)
  long[2] = lines[2].slice(1)
  malformed(long.join('\n'))                                            // 65-char line
  malformed(armor(fill('x', 4)).replace(/=*\n-----END/, '\n-----END'))  // padding stripped
  malformed(armor(fill('x', 4)).replace('=\n-----END', '==\n-----END')) // bad padding
  malformed(good.replace(lines[1].slice(0, 4), '!!!!'))                 // alphabet
  malformed(good.replace('\n-----END', '\n\n-----END'))                 // blank line
  malformed(good.replace('\n-----END', ' \n-----END'))                  // trailing space
  malformed('-----BEGIN AGE ENCRYPTED FILE-----\n-----END AGE ENCRYPTED FILE-----\n') // empty body
  malformed(good + '\n')                                                // trailing junk
  malformed('')
  // non-zero trailing bits: "QR==" decodes like "QQ==" but is not canonical
  malformed('-----BEGIN AGE ENCRYPTED FILE-----\nQR==\n-----END AGE ENCRYPTED FILE-----\n')
})

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

// Invisible or confusable characters must be written as \u escapes, never literally.
// U+00B7 (middle dot) is allowed.
const BAD = new RegExp('[' + ['\\u00a0', '\\u200b-\\u200f', '\\u202a-\\u202e', '\\u2060-\\u2069', '\\ufeff'].join('') + ']', 'u')
const root = new URL('../../', import.meta.url).pathname

function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir).sort()) {
    const p = join(dir, n)
    if (statSync(p).isDirectory()) walk(p, out)
    else out.push(p)
  }
  return out
}

export function findInvisible(text: string): number[] {
  return text.split('\n').flatMap((l, i) => (BAD.test(l) ? [i + 1] : []))
}

test('no literal invisible characters in src/ or test/', () => {
  const hits: string[] = []
  for (const f of [...walk(join(root, 'src')), ...walk(join(root, 'test'))]) {
    for (const line of findInvisible(readFileSync(f, 'utf8'))) hits.push(`${f.slice(root.length)}:${line}`)
  }
  assert.deepEqual(hits, [])
})

test('the scanner catches each class and allows the middle dot', () => {
  for (const cp of [0xa0, 0x200b, 0x200f, 0x202a, 0x202e, 0x2060, 0x2069, 0xfeff]) {
    assert.deepEqual(findInvisible(`a\n${String.fromCodePoint(cp)}`), [2], cp.toString(16))
  }
  assert.deepEqual(findInvisible('a · b'), [])
})

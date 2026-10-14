import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

// A plain socks5:// URL resolves DNS locally (leaks the lookup); only socks5h:// is allowed.
// The needle is assembled so this file does not contain it literally.
const NEEDLE = 'socks5' + '://'
const root = new URL('../../', import.meta.url).pathname

function walk(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) return out
  for (const n of readdirSync(dir).sort()) {
    const p = join(dir, n)
    if (statSync(p).isDirectory()) walk(p, out)
    else out.push(p)
  }
  return out
}

test('no non-"h" socks5 scheme anywhere in src/, bin/ or the json files', () => {
  const files = [...walk(join(root, 'src')), ...walk(join(root, 'bin')),
    join(root, 'endpoints.json'), join(root, 'anchors.json')]
  assert.ok(files.length >= 2)
  for (const f of files) {
    assert.ok(existsSync(f), `${f} must exist`)
    assert.ok(!readFileSync(f, 'utf8').includes(NEEDLE), `${f} contains the non-h socks5 scheme`)
  }
})

test('the scanner would catch a violation', () => {
  assert.ok(('x ' + NEEDLE + '127.0.0.1').includes(NEEDLE))
  assert.ok(!('x socks5h' + '://127.0.0.1').includes(NEEDLE))
})

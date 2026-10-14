// The API's secrets (api.token-missing) and the bearer check (api.token, constant time on equal lengths).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { chmodSync, mkdirSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { assertToken, bearerMatches, readSecretHex } from '../src/auth.ts'
import { CANARY, TOKEN, tempDir } from './helpers.ts'

const refusal = (fn: () => unknown): { guardId: string; message: string } => {
  try { fn() } catch (e) { return e as { guardId: string; message: string } }
  assert.fail('expected a refusal')
}

test('readSecretHex: a private 64-hex file (one trailing newline allowed)', (t) => {
  const { dir, cleanup } = tempDir('vt-api-auth-')
  t.after(cleanup)
  writeFileSync(join(dir, 'a'), `${TOKEN}\n`, { mode: 0o600 })
  writeFileSync(join(dir, 'b'), TOKEN, { mode: 0o600 })
  assert.equal(readSecretHex(join(dir, 'a')), TOKEN)
  assert.equal(readSecretHex(join(dir, 'b')), TOKEN)
})

test('readSecretHex: missing, loose, symlinked, a directory, or not 64 hex → api.token-missing (no path, no contents)', (t) => {
  const { dir, cleanup } = tempDir('vt-api-auth-')
  t.after(cleanup)
  const cases: Record<string, () => void> = {
    missing: () => {},
    loose: () => { writeFileSync(join(dir, 'loose'), TOKEN, { mode: 0o600 }); chmodSync(join(dir, 'loose'), 0o644) },
    symlink: () => { writeFileSync(join(dir, 'target'), TOKEN, { mode: 0o600 }); symlinkSync(join(dir, 'target'), join(dir, 'symlink')) },
    directory: () => { mkdirSync(join(dir, 'directory'), { mode: 0o700 }) },
    short: () => { writeFileSync(join(dir, 'short'), TOKEN.slice(1), { mode: 0o600 }) },
    upper: () => { writeFileSync(join(dir, 'upper'), TOKEN.toUpperCase(), { mode: 0o600 }) },
    twoNewlines: () => { writeFileSync(join(dir, 'twoNewlines'), `${TOKEN}\n\n`, { mode: 0o600 }) },
    canary: () => { writeFileSync(join(dir, 'canary'), `${CANARY}\n`, { mode: 0o600 }) },
    empty: () => { writeFileSync(join(dir, 'empty'), '', { mode: 0o600 }) },
  }
  for (const [name, make] of Object.entries(cases)) {
    make()
    const e = refusal(() => readSecretHex(join(dir, name)))
    assert.equal(e.guardId, 'api.token-missing', name)
    assert.ok(!e.message.includes(dir) && !e.message.includes(CANARY), `${name}: the refusal names the path or echoes the contents`)
  }
})

test('bearer: exactly "Bearer <token>"', () => {
  assert.equal(bearerMatches(`Bearer ${TOKEN}`, TOKEN), true)
  for (const [i, h] of [undefined, '', TOKEN, `bearer ${TOKEN}`, `Bearer  ${TOKEN}`, `Bearer ${TOKEN} `, `Bearer ${TOKEN.slice(0, -1)}0`,
    `Bearer ${TOKEN.slice(0, -1)}`, `Basic ${TOKEN}`, `Bearer ${CANARY}`].entries()) assert.equal(bearerMatches(h, TOKEN), false, `header #${i}`)
})

test('bearer: a token that is not 64 hex authorizes nothing (fail closed)', () => {
  assert.equal(bearerMatches('Bearer ', ''), false)
  assert.equal(bearerMatches('Bearer abc', 'abc'), false)
})

test('assertToken → api.token', () => {
  assertToken(`Bearer ${TOKEN}`, TOKEN)
  for (const h of [undefined, 'Bearer wrong-token']) {
    const e = refusal(() => assertToken(h, TOKEN))
    assert.equal(e.guardId, 'api.token')
    assert.ok(!e.message.includes('wrong-token'))
  }
})

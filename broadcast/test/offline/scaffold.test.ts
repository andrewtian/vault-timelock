import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { Refusal, refuse, exitCodeFor } from '../../src/guard.ts'

const root = new URL('../../', import.meta.url)
const pkg = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'))

test('native TypeScript type stripping is active', () => {
  assert.equal(process.features.typescript, 'strip')
})

// The one first-party dependency: a file: link to packages/core (M4a: a `dependencies` entry, not an optional one, which npm may skip
// silently). It is the only spec that is not an exact version, and it is allowed by its exact text.
const CORE_NAME = '@vault-timelock/core'
const CORE_SPEC = 'file:../packages/core'
const deps: Record<string, string> = Object.fromEntries((Object.entries({ ...pkg.dependencies, ...pkg.devDependencies }) as Array<[string, string]>).filter(([n]) => n !== CORE_NAME))

test('core is a plain dependency by its exact file: spec (the link itself is checked by scripts/test-root.sh and the release)', () => {
  assert.equal(pkg.dependencies[CORE_NAME], CORE_SPEC)
  assert.equal(pkg.optionalDependencies, undefined)
  assert.equal(pkg.devDependencies?.[CORE_NAME], undefined)
})

test('every declared version is an exact pin', () => {
  assert.ok(Object.keys(deps).length > 0)
  for (const [name, v] of Object.entries(deps)) {
    assert.match(v, /^\d+\.\d+\.\d+$/, `${name}@${v} is not an exact version`)
  }
})

test('installed versions equal the pins', () => {
  for (const [name, v] of Object.entries(deps)) {
    const p = JSON.parse(readFileSync(new URL(`node_modules/${name}/package.json`, root), 'utf8'))
    assert.equal(p.version, v, name)
  }
})

test('refuse throws a Refusal carrying the guard id', () => {
  assert.throws(
    () => refuse('x.y-z', 'nope'),
    (e: unknown) => e instanceof Refusal && e.guardId === 'x.y-z' && e.message === 'nope',
  )
})

test('refuse rejects a malformed guard id', () => {
  for (const bad of ['', 'A', 'a b', '-a', 'a-', 'a..b', 'a_b']) {
    assert.throws(
      () => refuse(bad, 'm'),
      (e: unknown) => !(e instanceof Refusal) && e instanceof Error && e.message === 'bad guard id',
      bad,
    )
  }
})

test('exitCodeFor: Refusal 2, Error 1, non-Error 1', () => {
  let r: unknown
  try { refuse('some-guard', 'm') } catch (e) { r = e }
  assert.equal(exitCodeFor(r), 2)
  assert.equal(exitCodeFor(new Error('x')), 1)
  assert.equal(exitCodeFor('str'), 1)
  assert.equal(exitCodeFor(undefined), 1)
})

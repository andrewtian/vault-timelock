import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Refusal, isRefusal, refuse } from '../../src/text/guard.ts'

test('refuse throws a Refusal carrying the guard id', () => {
  assert.throws(() => refuse('x.y-z', 'nope'), (e: unknown) => e instanceof Refusal && isRefusal(e) && e.guardId === 'x.y-z' && e.message === 'nope' && e.name === 'Refusal')
})

test('guard-id-format: refuse rejects a malformed guard id with a plain Error', () => {
  for (const bad of ['', 'A', 'a b', '-a', 'a-', 'a..b', 'a_b']) {
    assert.throws(() => refuse(bad, 'm'), (e: unknown) => !(e instanceof Refusal) && e instanceof Error && e.message === 'bad guard id', bad)
  }
})

test('isRefusal: a Refusal yes; a plain Error, a lookalike without a valid id, a non-error no', () => {
  assert.equal(isRefusal(new Refusal('a.b', 'm')), true)
  assert.equal(isRefusal(new Error('m')), false)
  const fake = Object.assign(new Error('m'), { name: 'Refusal', guardId: 'Not Valid' })
  assert.equal(isRefusal(fake), false)
  assert.equal(isRefusal('a.b'), false)
  assert.equal(isRefusal(null), false)
})

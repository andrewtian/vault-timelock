// node --test test/keys.test.mjs — key import validation, passphrase rule (M7), backup file name (M8), saved-file check (I1).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { decryptKeyFile, encryptKey, ethFromSecret, keyFileName, newKey, passphraseCheck, SECP256K1_N, solFromSecret, verifySavedFile } from '../../src/engine/keys.js'

test('M7 passphrase: ≥ 6 distinct words with ≥ 25 letters, or ≥ 20 chars / 3 classes without repeats', () => {
  assert.equal(passphraseCheck('amber basil cobalt delta ember fable').ok, true)        // 31 letters, 6 distinct
  assert.equal(passphraseCheck('aaa aaa aaa aaa aaa aaa').ok, false)                     // the review's example
  assert.equal(passphraseCheck('cat dog owl bee ant elk').ok, false)                     // 18 letters < 25
  assert.equal(passphraseCheck('amber amber cobalt delta ember fable').ok, false)        // 5 distinct
  assert.equal(passphraseCheck('Password1Password1Pa').ok, false)                        // the review's example (repeat)
  assert.equal(passphraseCheck('Tz9#qLm2!vR7@kWp4$xN').ok, true)
  assert.equal(passphraseCheck('Tz9#qLm2!vRRRRp4$xNa').ok, false)                        // 4× the same char
})
test('M8 backup file name carries no address', () => {
  const k = newKey('eth'), name = keyFileName(k, new Date('2026-10-09T14:32:22.123Z'))
  assert.equal(name, 'vt-eth-key-20261009T143222Z.age')
  assert.ok(!name.toLowerCase().includes(k.address.slice(2, 8).toLowerCase()))
  assert.equal(keyFileName(newKey('sol'), new Date('2026-10-09T00:00:00Z')), 'vt-sol-key-20261009T000000Z.age')
})
test('key validation: ETH 0 < k < n, SOL 64-byte secret with a matching public half', () => {
  assert.throws(() => ethFromSecret('0x' + '0'.repeat(64)), /0 < k < n/)
  assert.throws(() => ethFromSecret('0x' + SECP256K1_N.toString(16)), /0 < k < n/)
  assert.throws(() => ethFromSecret('0x1234'), /64 hex/)
  assert.equal(ethFromSecret('0x' + (SECP256K1_N - 1n).toString(16)).chain, 'eth')
  const s = newKey('sol'); assert.equal(solFromSecret(s.secret).address, s.address)
  assert.throws(() => solFromSecret('[1,2,3]'), /64 numbers/)
})
test('I1: the SAVED file must decrypt (re-typed passphrase) to exactly the in-memory key', async () => {
  const k = newKey('sol'), other = newKey('sol'), pass = 'amber basil cobalt delta ember fable'
  const { ct } = await encryptKey(k, pass), { ct: ct2 } = await encryptKey(other, pass)
  assert.equal(await verifySavedFile(ct, pass, k), true)
  await assert.rejects(verifySavedFile(ct, 'wrong wrong wrong wrong wrong wrong', k), /wrong passphrase/)
  await assert.rejects(verifySavedFile(ct2, pass, k), /DIFFERENT key/)
  await assert.rejects(decryptKeyFile(ct, pass, 'eth'), /for sol, not eth/)
})

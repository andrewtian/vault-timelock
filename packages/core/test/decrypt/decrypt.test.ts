// vt decrypt core (lane E): the API every lane codes against. SYNTHETIC data only.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as api from '../../src/decrypt/index.ts'

test('API: the published functions and constants (lanes C and W build on these names and shapes)', async () => {
  for (const f of ['detectInput', 'decryptAge', 'tarGzSource', 'listArchive', 'extractOne', 'extractAll'] as const) assert.equal(typeof api[f], 'function', f)
  assert.deepEqual({ ...api.DECRYPT_LIMITS }, { input: 128 * 1024 * 1024, secret: 64 * 1024, scryptLogN: 20 })
  assert.deepEqual({ ...api.ARCHIVE_LIMITS }, { bytes: 64 * 1024 * 1024, entries: 10_000, meta: 64 * 1024, nameBytes: 4096 })
  assert.equal(api.PASTE_LIMIT, 1024 * 1024)
  assert.equal(api.SEALED_FORMAT_V1, 'vault-timelock-sealed/1')
  assert.deepEqual(api.SEALED_FORMATS, ['vault-timelock-sealed/1'])
  const viaPackage = await import('@vault-timelock/core/decrypt')
  assert.equal(viaPackage.decryptAge, api.decryptAge, 'the package export ./decrypt is this module')
})

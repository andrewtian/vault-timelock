// Every pinned dependency of packages/core resolves from this workspace (install-strategy=linked, npm 11.21.0).
import { test } from 'node:test'
import assert from 'node:assert/strict'

test('core dependencies resolve and work', async () => {
  const { getAddress } = await import('viem')
  const { PublicKey } = await import('@solana/web3.js')
  const { base58 } = await import('@scure/base')
  const { sha256 } = await import('@noble/hashes/sha2.js')
  const age = await import('age-encryption')
  assert.equal(getAddress('0x0000000000000000000000000000000000000000'), '0x0000000000000000000000000000000000000000')
  assert.equal(new PublicKey(base58.encode(new Uint8Array(32))).toBase58(), '11111111111111111111111111111111')
  assert.equal(sha256(new Uint8Array(0)).length, 32)
  assert.equal(typeof age.Encrypter, 'function')
})

// node --test test/links.test.mjs — explorer link builders, the null-address recipient, and the zero-value guard.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseTransaction, keccak256 } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { ethLinks, mayOpen, NULL_ADDRESS, solLinks } from '../../src/chains/links.js'
import { buildEthTx, recipientAddress, sign } from '../../src/chains/eth.js'

const H = '0x' + 'ab'.repeat(32), S = '5'.repeat(88), A = '0x1111111111111111111111111111111111111111', P = 'Pay1111111111111111111111111111111111111111'
test('ETH links — mainnet: copy-only Etherscan tx + Null Address page (null recipient) + signer; nothing opens', () => {
  const m = ethLinks('mainnet', H, A, NULL_ADDRESS)
  assert.deepEqual(m.map((x) => x.url), [`https://etherscan.io/tx/${H}`, 'https://etherscan.io/address/0x0000000000000000000000000000000000000000', `https://etherscan.io/address/${A}`])
  assert.ok(m.every((x) => x.open === false)); assert.match(m[1].note, /busy page/)
  assert.equal(ethLinks('mainnet', H, A, A).length, 2)                    // self-send: no Null Address link
})
test('ETH links — local: Otterscan tx + Null Address page + signer, and ONLY these open directly', () => {
  const l = ethLinks('local', H, A, NULL_ADDRESS)
  assert.deepEqual(l.map((x) => x.url), [`http://127.0.0.1:5100/tx/${H}`, 'http://127.0.0.1:5100/address/0x0000000000000000000000000000000000000000', `http://127.0.0.1:5100/address/${A}`])
  assert.ok(l.every((x) => x.open === true))
  assert.equal(mayOpen('https://etherscan.io/tx/x'), false); assert.equal(mayOpen('http://127.0.0.1:5100.evil.example/x'), false)
})
test('SOL links — mainnet: Explorer + Solscan + SolanaFM (+ address), copy-only; local: custom cluster with the “Apps on device” note, copy-only', () => {
  const m = solLinks('mainnet', S, P)
  assert.deepEqual(m.map((x) => x.url), [`https://explorer.solana.com/tx/${S}`, `https://solscan.io/tx/${S}`, `https://solana.fm/tx/${S}`, `https://explorer.solana.com/address/${P}`])
  assert.ok(m.every((x) => !x.open))
  const l = solLinks('local', S, P)
  assert.equal(l.length, 1); assert.equal(l[0].url, `https://explorer.solana.com/tx/${S}?cluster=custom&customUrl=http%3A%2F%2F127.0.0.1%3A8999`)
  assert.equal(l[0].open, false); assert.match(l[0].note, /Apps on device/)   // P2 (add7b-e540f8ae4d6b test/links.test.mjs)
})
test('recipient: null (default) → 0x000…000, self → the signer; any non-zero value is refused', async () => {
  assert.equal(NULL_ADDRESS, '0x0000000000000000000000000000000000000000')
  assert.equal(recipientAddress('null', A), NULL_ADDRESS); assert.equal(recipientAddress('self', A), A)
  const base = { chainId: 1, nonce: 0, to: NULL_ADDRESS, data: '0x646174613a2c6869', gas: 21320n, maxFee: 10n ** 9n, tip: 10n ** 8n }
  assert.equal(buildEthTx(base).value, 0n)
  assert.throws(() => buildEthTx({ ...base, value: 1n }), /refusing a non-zero value/)
  assert.throws(() => buildEthTx({ ...base, value: 10n ** 18n }), /burned forever/)
  assert.throws(() => buildEthTx({ ...base, to: '0x00' }), /bad recipient/)
  const acct = privateKeyToAccount(generatePrivateKey())
  await assert.rejects(sign(acct, 1, { ...base, value: 5n }), /non-zero value/)
  const { raw, id } = await sign(acct, 1, base)                           // signs to 0x0 with value 0
  const tx = parseTransaction(raw)
  assert.equal(tx.to, NULL_ADDRESS); assert.equal(tx.value ?? 0n, 0n); assert.equal(tx.data, base.data); assert.equal(id, keccak256(raw))
})

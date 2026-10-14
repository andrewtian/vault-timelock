// gates/backup.ts loadBackup and gates/caps.ts assertWithinCap. Backups are made with the engine's own encryptKey (the
// prototype's .age format, plus the optional trailing `network`), except the tampered and odd ones, which are built
// here with age directly (at a low scrypt work factor, to keep the suite fast). ALL KEYS ARE GENERATED HERE.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Decrypter, Encrypter } from 'age-encryption'
import { loadBackup } from '../../src/gates/backup.ts'
import { assertWithinCap } from '../../src/gates/caps.ts'
import { decryptKeyFile, encryptKey, newKey } from '../../src/engine/keys.js'
import { guardOf } from '../job/helpers.ts'

const PASS = 'amber basil cobalt delta ember fable'
const eth = newKey('eth'), sol = newKey('sol'), other = newKey('eth')
async function guardOfAsync(p: Promise<unknown>): Promise<string | null> {
  try { await p } catch (e) { const id = (e as { guardId?: unknown }).guardId; if (typeof id === 'string') return id; throw e }
  return null
}
async function craft(plain: unknown): Promise<Uint8Array> {
  const e = new Encrypter(); e.setPassphrase(PASS); e.setScryptWorkFactor(10)
  return e.encrypt(typeof plain === 'string' ? plain : JSON.stringify(plain))
}

const withNet = encryptKey(eth, PASS, 'local')
const prototypeStyle = encryptKey(eth, PASS)                       // no network: a backup made before R71

test('the backup format: the prototype\'s four keys in order, then the optional network (W2 carry-forward)', async () => {
  const d = new Decrypter(); d.addPassphrase(PASS)
  const a = JSON.parse(await d.decrypt((await withNet).ct, 'text')) as Record<string, unknown>
  assert.deepEqual(Object.keys(a), ['chain', 'address', 'secret', 'createdAt', 'network'])
  assert.equal(a.network, 'local'); assert.match(String(a.createdAt), /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/)
  const b = JSON.parse(await d.decrypt((await prototypeStyle).ct, 'text')) as Record<string, unknown>
  assert.deepEqual(Object.keys(b), ['chain', 'address', 'secret', 'createdAt'])
  assert.equal((await decryptKeyFile((await withNet).ct, PASS, 'eth')).network, 'local')
  assert.equal((await decryptKeyFile((await prototypeStyle).ct, PASS, 'eth')).network, null)
})

test('a backup in the MQ format with the right passphrase loads the key; same network → no warning', async () => {
  const r = await loadBackup((await withNet).ct, PASS, 'eth', { address: eth.address, network: 'local' })
  assert.equal(r.key.address, eth.address); assert.equal(r.key.chain, 'eth'); assert.equal(r.warnNetwork, false)
  assert.equal((r.key as { secret: string }).secret, eth.secret)
  const lower = await loadBackup((await withNet).ct, PASS, 'eth', { address: eth.address.toLowerCase(), network: 'local' })
  assert.equal(lower.key.address, eth.address, 'ETH addresses compare case-insensitively (EIP-55 is a checksum)')
  const s = await loadBackup((await encryptKey(sol, PASS, 'testnet')).ct, PASS, 'sol', { address: sol.address, network: 'testnet' })
  assert.equal(s.key.address, sol.address); assert.equal(s.warnNetwork, false)
})

test('another network, or none recorded (a prototype backup), sets warnNetwork — the operator ticks it', async () => {
  assert.equal((await loadBackup((await withNet).ct, PASS, 'eth', { address: eth.address, network: 'testnet' })).warnNetwork, true)
  assert.equal((await loadBackup((await prototypeStyle).ct, PASS, 'eth', { address: eth.address, network: 'local' })).warnNetwork, true)
})

test('a wrong passphrase, a non-backup file and non-JSON plaintext → backup.decrypt', async () => {
  assert.equal(await guardOfAsync(loadBackup((await withNet).ct, 'wrong wrong wrong wrong wrong wrong', 'eth', { address: eth.address, network: 'local' })), 'backup.decrypt')
  assert.equal(await guardOfAsync(loadBackup(new TextEncoder().encode('not an age file'), PASS, 'eth', { address: eth.address, network: 'local' })), 'backup.decrypt')
  assert.equal(await guardOfAsync(loadBackup(await craft('plain text, not JSON'), PASS, 'eth', { address: eth.address, network: 'local' })), 'backup.decrypt')
  assert.equal(await guardOfAsync(loadBackup(await craft({ chain: 'eth', address: eth.address }), PASS, 'eth', { address: eth.address, network: 'local' })), 'backup.decrypt', 'no secret member')
})

test('a SOL backup for chain eth → backup.chain (and the reverse)', async () => {
  const solCt = (await encryptKey(sol, PASS, 'local')).ct
  assert.equal(await guardOfAsync(loadBackup(solCt, PASS, 'eth', { address: eth.address, network: 'local' })), 'backup.chain')
  assert.equal(await guardOfAsync(loadBackup((await withNet).ct, PASS, 'sol', { address: sol.address, network: 'local' })), 'backup.chain')
})

test('a valid key that is not the job\'s keyAddress → backup.address-mismatch', async () => {
  assert.equal(await guardOfAsync(loadBackup((await withNet).ct, PASS, 'eth', { address: other.address, network: 'local' })), 'backup.address-mismatch')
  assert.equal(await guardOfAsync(loadBackup((await withNet).ct, PASS, 'eth', { address: '', network: 'local' })), 'backup.address-mismatch')
})

test('a tampered secret/address pair → backup.inconsistent, even when the address matches the job', async () => {
  const tampered = await craft({ chain: 'eth', address: eth.address, secret: other.secret, createdAt: '2026-10-09T00:00:00.000Z', network: 'local' })
  assert.equal(await guardOfAsync(loadBackup(tampered, PASS, 'eth', { address: eth.address, network: 'local' })), 'backup.inconsistent')
  const junk = await craft({ chain: 'eth', address: eth.address, secret: '0x1234', createdAt: '2026-10-09T00:00:00.000Z' })
  assert.equal(await guardOfAsync(loadBackup(junk, PASS, 'eth', { address: eth.address, network: 'local' })), 'backup.inconsistent', 'an invalid secret')
})

test('the refusals never echo the secret', async () => {
  const tampered = await craft({ chain: 'eth', address: eth.address, secret: other.secret })
  try { await loadBackup(tampered, PASS, 'eth', { address: eth.address, network: 'local' }); assert.fail('expected a refusal') } catch (e) {
    assert.ok(!String((e as Error).message).includes(other.secret.slice(2, 18)))
  }
})

test('assertWithinCap: spent + reserve ≤ cap passes; one wei over → engine.cap; a missing or malformed cap → engine.cap', () => {
  assert.equal(guardOf(() => assertWithinCap(10n, 15n, 25n)), null)
  assert.equal(guardOf(() => assertWithinCap(0n, 0n, 0n)), null)
  assert.equal(guardOf(() => assertWithinCap(10n, 16n, 25n)), 'engine.cap')
  assert.equal(guardOf(() => assertWithinCap(0n, 1n, 0n)), 'engine.cap')
  for (const bad of [undefined, null, 25, '25', -1n]) assert.equal(guardOf(() => assertWithinCap(0n, 0n, bad as unknown as bigint)), 'engine.cap', String(bad))
  assert.equal(guardOf(() => assertWithinCap(-1n, 0n, 25n)), 'engine.cap', 'a negative spend is malformed')
  assert.equal(guardOf(() => assertWithinCap(0n, 1 as unknown as bigint, 25n)), 'engine.cap')
})

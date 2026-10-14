// Task 12b: the keystore (spec C 5; profile binding K33; funding-source key slots R47, C 3.1). Synthetic keys and a
// temp $OUT only: every test makes its own directory under the OS temp dir (HOME is the suite's synthetic one) and
// never resolves the real $OUT. The scrypt work factor is the test-only logN 10 (NODE_ENV=test below) everywhere but
// keystore-cli.test.ts, the one production-path test that asserts logN 18.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, statSync, symlinkSync,
  unlinkSync, writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { Decrypter, Encrypter, generateIdentity, identityToRecipient } from 'age-encryption'
import { privateKeyToAccount } from 'viem/accounts'
import { requireExplicitProfile } from '../../../src/config.ts'
import { keystoreDir, lifecycleDir } from '../../../src/lifecycle/paths.ts'
import {
  assertKeystoreProfile, isSecp256k1Secret, Keystore, resolveKeyId, sourceKeyIds, SCRYPT_LOG_N,
} from '../../../src/lifecycle/keystore.ts'
import { assertNoSecretsInStore, fakeClock, refused, refusedAsync } from './helpers.ts'

process.env.NODE_ENV = 'test' // the test-only work factor option (keystore.workfactor outside NODE_ENV=test)

const PASS = 'ablaze able abacus ability abide abiding' // synthetic: 6 EFF words
const LOGN = 10
const hex = (b: Uint8Array): `0x${string}` => `0x${Buffer.from(b).toString('hex')}`
const evm = (b: Uint8Array): string => privateKeyToAccount(hex(b)).address
const EVM = /^0x[0-9a-fA-F]{40}$/

async function withOut<T>(f: (out: string) => Promise<T>): Promise<T> {
  const d = mkdtempSync(join(tmpdir(), 'vt-12b-ks-'))
  try { return await f(join(d, 'out')) } finally { rmSync(d, { recursive: true, force: true }) }
}
const ks = (out: string, profile: 'mainnet' | 'testnet' | 'local' = 'testnet', start = 1_800_000_000) =>
  new Keystore(out, profile, { testScryptLogN: LOGN, clock: fakeClock(start) })
async function initKs(out: string, profile: 'mainnet' | 'testnet' | 'local' = 'testnet'): Promise<Keystore> {
  const k = ks(out, profile)
  await k.init(PASS)
  return k
}
// The test's own view of master.age: the identity string (test-side only, for checks and the leak scan).
async function masterIdentity(out: string): Promise<string> {
  const d = new Decrypter()
  d.addPassphrase(PASS)
  return d.decrypt(readFileSync(join(keystoreDir(out), 'master.age')), 'text')
}
async function decryptKeyFile(out: string, id: string, identity: string): Promise<Uint8Array> {
  const d = new Decrypter()
  d.addIdentity(identity)
  return d.decrypt(readFileSync(join(keystoreDir(out), `${id}.age`)))
}
const mode = (p: string): number => statSync(p).mode & 0o777

// ---- round trip

test('init + createKey + unlock + withSecret round trip; the derived address equals .pub.json', async () => {
  await withOut(async (out) => {
    const k = await initKs(out)
    const dir = keystoreDir(out)
    const pub = readFileSync(join(dir, 'master.pub'), 'utf8')
    assert.match(pub, /^age1[02-9ac-hj-np-z]{58}\n$/)
    const { address } = await k.createKey('D-railgun-eth', 'evm')
    assert.match(address, EVM)
    assert.deepEqual(k.publicInfo('D-railgun-eth'), { keyId: 'D-railgun-eth', kind: 'evm', address, createdAt: 1_800_000_000 })
    assert.equal(readFileSync(join(dir, 'D-railgun-eth.pub.json'), 'utf8'),
      JSON.stringify({ keyId: 'D-railgun-eth', kind: 'evm', address, createdAt: 1_800_000_000 }) + '\n')
    const u = await k.unlock(PASS)
    const derived = await u.withSecret('D-railgun-eth', async (s) => { assert.equal(s.length, 32); return evm(s) })
    assert.equal(derived, address)
    // The file format Part D relies on: master.age holds exactly the identity, <id>.age exactly the 32 raw bytes.
    const identity = await masterIdentity(out)
    assert.match(identity, /^AGE-SECRET-KEY-1[0-9A-Z]{58}$/)
    assert.equal(await identityToRecipient(identity) + '\n', pub)
    const raw = await decryptKeyFile(out, 'D-railgun-eth', identity)
    assert.equal(raw.length, 32)
    assert.equal(evm(raw), address)
  })
})

test('withSecret zero-fills the secret afterwards, also when fn throws', async () => {
  await withOut(async (out) => {
    const k = await initKs(out)
    await k.createKey('pub-j1-eth', 'evm')
    const u = await k.unlock(PASS)
    let kept: Uint8Array | undefined
    await u.withSecret('pub-j1-eth', async (s) => { kept = s; assert.ok(s.some((b) => b !== 0)) })
    assert.ok(kept !== undefined && kept.length === 32 && kept.every((b) => b === 0), 'zero-filled after fn')
    let kept2: Uint8Array | undefined
    await assert.rejects(u.withSecret('pub-j1-eth', async (s) => { kept2 = s; throw new Error('fn failed') }), /fn failed/)
    assert.ok(kept2 !== undefined && kept2.every((b) => b === 0), 'zero-filled after a throw')
  })
})

test('a wrong passphrase, or no master.age, refuses keystore.unlock', async () => {
  await withOut(async (out) => {
    const k = await initKs(out)
    await refusedAsync(() => k.unlock('ablaze able abacus ability abide abdomen'), 'keystore.unlock')
    await refusedAsync(() => k.unlock(''), 'keystore.unlock')
    unlinkSync(join(keystoreDir(out), 'master.age'))
    await refusedAsync(() => k.unlock(PASS), 'keystore.unlock')
  })
})

test('master.age whose plaintext is not an age identity refuses keystore.unlock', async () => {
  await withOut(async (out) => {
    const k = await initKs(out)
    const e = new Encrypter()
    e.setPassphrase(PASS)
    e.setScryptWorkFactor(LOGN)
    writeFileSync(join(keystoreDir(out), 'master.age'), await e.encrypt('not an identity'), { mode: 0o600 })
    await refusedAsync(() => k.unlock(PASS), 'keystore.unlock')
  })
})

test('unlock refuses keystore.master-mismatch when master.pub is not the master identity\'s recipient', async () => {
  await withOut(async (out) => {
    const k = await initKs(out)
    const other = await identityToRecipient(await generateIdentity())
    writeFileSync(join(keystoreDir(out), 'master.pub'), other + '\n')
    await refusedAsync(() => k.unlock(PASS), 'keystore.master-mismatch')
  })
})

// ---- createKey

test('createKey needs only master.pub: no master.age, no passphrase', async () => {
  await withOut(async (out) => {
    const dir = keystoreDir(out)
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const identity = await generateIdentity() // the test holds the identity; the keystore never sees it
    writeFileSync(join(dir, 'master.pub'), await identityToRecipient(identity) + '\n', { mode: 0o600 })
    writeFileSync(join(dir, 'profile'), 'testnet\n', { mode: 0o600 })
    const k = ks(out)
    const { address } = await k.createKey('l1hop-j1', 'evm')
    assert.ok(!existsSync(join(dir, 'master.age')))
    const raw = await decryptKeyFile(out, 'l1hop-j1', identity)
    assert.equal(raw.length, 32)
    assert.equal(evm(raw), address)
    assert.ok(isSecp256k1Secret(raw))
  })
})

test('createKey refuses keystore.master-pub without a well-formed master.pub', async () => {
  await withOut(async (out) => {
    await refusedAsync(() => ks(out).createKey('D-railgun-eth', 'evm'), 'keystore.master-pub') // no keystore at all
    const k = await initKs(out)
    const mp = join(keystoreDir(out), 'master.pub')
    const good = readFileSync(mp, 'utf8')
    for (const bad of [good.trim(), good + '\n', 'age1short\n', good.toUpperCase(), '']) {
      writeFileSync(mp, bad)
      await refusedAsync(() => k.createKey('D-railgun-eth', 'evm'), 'keystore.master-pub')
    }
    unlinkSync(mp)
    await refusedAsync(() => k.createKey('D-railgun-eth', 'evm'), 'keystore.master-pub')
    assert.deepEqual(readdirSync(keystoreDir(out)).sort(), ['master.age', 'profile'])
  })
})

test('createKey never overwrites: keystore.no-overwrite', async () => {
  await withOut(async (out) => {
    const k = await initKs(out)
    const first = await k.createKey('swap-j1', 'evm')
    await refusedAsync(() => k.createKey('swap-j1', 'evm'), 'keystore.no-overwrite')
    assert.equal(k.publicInfo('swap-j1')?.address, first.address)
    // half a key (only one of the two files) is not overwritten either
    rmSync(join(keystoreDir(out), 'swap-j1.pub.json'))
    await refusedAsync(() => k.createKey('swap-j1', 'evm'), 'keystore.no-overwrite')
    await k.createKey('arweave-j2', 'evm')
    rmSync(join(keystoreDir(out), 'arweave-j2.age'))
    await refusedAsync(() => k.createKey('arweave-j2', 'evm'), 'keystore.no-overwrite')
  })
})

test('kinds: only evm is generated for now (keystore.kind-unsupported); a kind that does not fit the id refuses keystore.kind-mismatch', async () => {
  await withOut(async (out) => {
    const k = await initKs(out)
    await refusedAsync(() => k.createKey('pub-j1-sol', 'sol'), 'keystore.kind-unsupported')
    await refusedAsync(() => k.createKey('btcw-j1', 'btc-p2wpkh'), 'keystore.kind-unsupported')
    await refusedAsync(() => k.createKey('btck-j1', 'btc-p2tr'), 'keystore.kind-unsupported')
    await refusedAsync(() => k.createKey('pool-railgun-eth', 'railgun-mnemonic'), 'keystore.kind-unsupported')
    await refusedAsync(() => k.createKey('pub-j1-sol', 'evm'), 'keystore.kind-mismatch')
    await refusedAsync(() => k.createKey('btcw-j1', 'evm'), 'keystore.kind-mismatch')
    await refusedAsync(() => k.createKey('pool-railgun-eth', 'evm'), 'keystore.kind-mismatch')
    await refusedAsync(() => k.createKey('D-railgun-eth', 'sol'), 'keystore.kind-mismatch')
    await refusedAsync(() => k.createKey('D-railgun-eth', 'nope' as never), 'keystore.kind-mismatch')
    assert.deepEqual(readdirSync(keystoreDir(out)).sort(), ['master.age', 'master.pub', 'profile'])
    for (const id of ['pub-j1-eth', 'pub-j1-arb', 'pub-j1-base', 'l1hop-j1', 'l2-j1-base', 'swap-j1', 'arweave-j1', 'D-src-2']) {
      assert.match((await k.createKey(id, 'evm')).address, EVM, id)
    }
  })
})

test('secp256k1 secrets: 0 < k < n', () => {
  const n = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex')
  const nMinus1 = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140', 'hex')
  const one = new Uint8Array(32); one[31] = 1
  assert.equal(isSecp256k1Secret(new Uint8Array(32)), false)
  assert.equal(isSecp256k1Secret(n), false)
  assert.equal(isSecp256k1Secret(new Uint8Array(32).fill(0xff)), false)
  assert.equal(isSecp256k1Secret(nMinus1), true)
  assert.equal(isSecp256k1Secret(one), true)
  assert.equal(isSecp256k1Secret(new Uint8Array(31).fill(1)), false)
})

// ---- key ids and funding sources (R47)

test('key ids: resolveKeyId accepts the id grammar, maps l2-<job>-arb to l1hop-<job>, refuses anything else', () => {
  const good = [
    'D-railgun-eth', 'pool-railgun-eth', 'D-a', 'pool-0', 'D-' + 'a'.repeat(24), 'pub-j1-eth', 'pub-j1-arb', 'pub-j1-base',
    'pub-f2-0123456789-sol', 'l1hop-j1', 'l2-j1-base', 'btcw-j1', 'btck-j1', 'swap-j1', 'arweave-j1',
  ]
  for (const id of good) assert.equal(resolveKeyId(id), id, id)
  assert.equal(resolveKeyId('l2-x-arb'), 'l1hop-x')
  assert.equal(resolveKeyId('l2-job-7-arb'), 'l1hop-job-7')
  assert.equal(resolveKeyId('l2-x-base'), 'l2-x-base')
  const bad = [
    '', 'pub-j1-btc', 'pub-f2-x-btc', 'D-', 'D-Railgun', 'D--x', 'D-' + 'a'.repeat(25), 'pool-', 'pool-A', 'pub-j1-doge', 'pub-j1', 'l2-x-eth', 'l2-x-sol',
    'l1hop-', 'master', 'master.age', '../D-x', 'D-x/../y', 'D-x\n', 'btcw-J', 'arweave_x', 'x-railgun-eth', 'l2--arb',
  ]
  for (const id of bad) refused(() => resolveKeyId(id), 'keystore.key-id')
  refused(() => resolveKeyId(42 as never), 'keystore.key-id')
})

test('funding sources: sourceKeyIds validates the label; D-railgun-eth/pool-railgun-eth stay valid; bad labels refuse keystore.key-id', () => {
  assert.deepEqual(sourceKeyIds('railgun-eth'), { deposit: 'D-railgun-eth', pool: 'pool-railgun-eth' })
  assert.deepEqual(sourceKeyIds('b2'), { deposit: 'D-b2', pool: 'pool-b2' })
  assert.deepEqual(sourceKeyIds('a'.repeat(24)), { deposit: 'D-' + 'a'.repeat(24), pool: 'pool-' + 'a'.repeat(24) })
  for (const bad of ['Railgun', 'a'.repeat(25), '-a', '', 'a b', 'a_b', 'a.b']) refused(() => sourceKeyIds(bad), 'keystore.key-id')
  for (const bad of ['D-Railgun', 'D-' + 'a'.repeat(25), 'D--a', 'pool-Railgun', 'pool-' + 'a'.repeat(25), 'pool--a']) {
    refused(() => resolveKeyId(bad), 'keystore.key-id')
  }
})

// Synthetic key-slot files (listSources looks only at which files exist).
function slot(out: string, id: string): void {
  writeFileSync(join(keystoreDir(out), `${id}.age`), 'synthetic', { mode: 0o600 })
  writeFileSync(join(keystoreDir(out), `${id}.pub.json`), '{}\n', { mode: 0o600 })
}

test('funding sources: listSources lists the labels that have both a D- and a pool- key, sorted', async () => {
  await withOut(async (out) => {
    const k = await initKs(out)
    assert.deepEqual(k.listSources(), [])
    for (const id of ['D-railgun-eth', 'pool-railgun-eth', 'pool-b2', 'D-b2', 'D-only', 'pool-lonely']) slot(out, id)
    writeFileSync(join(keystoreDir(out), 'D-half.age'), 'synthetic', { mode: 0o600 }) // D-half has no .pub.json
    slot(out, 'pool-half')
    assert.deepEqual(k.listSources(), ['b2', 'railgun-eth'])
    assert.deepEqual(ks(join(out, 'none')).listSources(), [])
  })
})

// ---- publicInfo

test('publicInfo reads .pub.json only; a valid optional pubkey is accepted; a missing key is undefined', async () => {
  await withOut(async (out) => {
    const k = await initKs(out)
    assert.equal(k.publicInfo('btcw-j1'), undefined)
    const info = { keyId: 'btcw-j1', kind: 'btc-p2wpkh', address: 'bcrt1q' + 'q'.repeat(38), createdAt: 7, pubkey: '02' + 'ab'.repeat(32) }
    writeFileSync(join(keystoreDir(out), 'btcw-j1.pub.json'), JSON.stringify(info) + '\n', { mode: 0o600 })
    assert.deepEqual(k.publicInfo('btcw-j1'), info)
    const tr = { keyId: 'btck-j1', kind: 'btc-p2tr', address: 'tb1p' + 'q'.repeat(58), createdAt: 8, pubkey: 'cd'.repeat(32) }
    writeFileSync(join(keystoreDir(out), 'btck-j1.pub.json'), JSON.stringify(tr) + '\n', { mode: 0o600 })
    assert.deepEqual(k.publicInfo('btck-j1'), tr)
    // the l2-<job>-arb alias reads l1hop-<job>
    const { address } = await k.createKey('l1hop-j9', 'evm')
    assert.equal(k.publicInfo('l2-j9-arb')?.address, address)
  })
})

test('publicInfo refuses keystore.pub-format for a malformed .pub.json', async () => {
  await withOut(async (out) => {
    const k = await initKs(out)
    const p = join(keystoreDir(out), 'pub-j1-eth.pub.json')
    const base = { keyId: 'pub-j1-eth', kind: 'evm', address: '0x' + '11'.repeat(20), createdAt: 1 }
    writeFileSync(p, JSON.stringify(base) + '\n', { mode: 0o600 })
    assert.deepEqual(k.publicInfo('pub-j1-eth'), base)
    const bad: unknown[] = [
      { ...base, keyId: 'pub-j2-eth' }, { ...base, kind: 'sol' }, { ...base, address: '0x1234' }, { ...base, createdAt: 1.5 },
      { ...base, createdAt: '1' }, { ...base, pubkey: 'AB'.repeat(32) }, { ...base, pubkey: 'ab'.repeat(31) }, { ...base, extra: 1 },
      [base], null, 'text',
    ]
    for (const b of bad) {
      writeFileSync(p, JSON.stringify(b) + '\n')
      refused(() => k.publicInfo('pub-j1-eth'), 'keystore.pub-format')
    }
    writeFileSync(p, '{not json')
    refused(() => k.publicInfo('pub-j1-eth'), 'keystore.pub-format')
  })
})

// ---- withSecret checks

test('a tampered .pub.json address refuses keystore.pub-mismatch', async () => {
  await withOut(async (out) => {
    const k = await initKs(out)
    const { address } = await k.createKey('D-railgun-eth', 'evm')
    const p = join(keystoreDir(out), 'D-railgun-eth.pub.json')
    const info = JSON.parse(readFileSync(p, 'utf8'))
    const other = await ks(join(out, 'other')).init(PASS).then(() => ks(join(out, 'other')).createKey('D-railgun-eth', 'evm'))
    assert.notEqual(other.address, address)
    writeFileSync(p, JSON.stringify({ ...info, address: other.address }) + '\n')
    const u = await k.unlock(PASS)
    let called = false
    await refusedAsync(() => u.withSecret('D-railgun-eth', async () => { called = true }), 'keystore.pub-mismatch')
    assert.equal(called, false)
    // case alone is not a mismatch (EVM addresses compare case-insensitively)
    writeFileSync(p, JSON.stringify({ ...info, address: address.toLowerCase() }) + '\n')
    assert.equal(await u.withSecret('D-railgun-eth', async (s) => evm(s)), address)
  })
})

test('a key the runner cannot verify yet (no address derivation for its kind) refuses keystore.pub-mismatch', async () => {
  await withOut(async (out) => {
    const k = await initKs(out)
    const dir = keystoreDir(out)
    const e = new Encrypter()
    e.addRecipient(readFileSync(join(dir, 'master.pub'), 'utf8').trim())
    writeFileSync(join(dir, 'btcw-j1.age'), await e.encrypt(new Uint8Array(32).fill(3)), { mode: 0o600 })
    writeFileSync(join(dir, 'btcw-j1.pub.json'), JSON.stringify({ keyId: 'btcw-j1', kind: 'btc-p2wpkh', address: 'bcrt1q' + 'q'.repeat(38), createdAt: 1 }) + '\n', { mode: 0o600 })
    const u = await k.unlock(PASS)
    await refusedAsync(() => u.withSecret('btcw-j1', async () => 1), 'keystore.pub-mismatch')
  })
})

test('a key file that does not decrypt to exactly 32 bytes with the master identity refuses keystore.key-file', async () => {
  await withOut(async (out) => {
    const k = await initKs(out)
    const dir = keystoreDir(out)
    await k.createKey('pub-j1-eth', 'evm')
    const u = await k.unlock(PASS)
    const enc = async (recipient: string, data: Uint8Array) => { const e = new Encrypter(); e.addRecipient(recipient); return e.encrypt(data) }
    const master = readFileSync(join(dir, 'master.pub'), 'utf8').trim()
    for (const n of [31, 33, 0]) {
      writeFileSync(join(dir, 'pub-j1-eth.age'), await enc(master, new Uint8Array(n).fill(5)))
      await refusedAsync(() => u.withSecret('pub-j1-eth', async () => 1), 'keystore.key-file')
    }
    writeFileSync(join(dir, 'pub-j1-eth.age'), await enc(await identityToRecipient(await generateIdentity()), new Uint8Array(32).fill(5)))
    await refusedAsync(() => u.withSecret('pub-j1-eth', async () => 1), 'keystore.key-file')
    writeFileSync(join(dir, 'pub-j1-eth.age'), 'garbage')
    await refusedAsync(() => u.withSecret('pub-j1-eth', async () => 1), 'keystore.key-file')
  })
})

test('withSecret on a key that is not in the keystore refuses keystore.no-key', async () => {
  await withOut(async (out) => {
    const k = await initKs(out)
    const u = await k.unlock(PASS)
    await refusedAsync(() => u.withSecret('pub-j1-eth', async () => 1), 'keystore.no-key')
    await k.createKey('pub-j1-eth', 'evm')
    renameSync(join(keystoreDir(out), 'pub-j1-eth.age'), join(keystoreDir(out), 'x'))
    await refusedAsync(() => u.withSecret('pub-j1-eth', async () => 1), 'keystore.no-key')
    await refusedAsync(() => u.withSecret('l2-j1-arb', async () => 1), 'keystore.no-key') // the alias, l1hop-j1, is absent too
    await refusedAsync(() => u.withSecret('nope', async () => 1), 'keystore.key-id')
  })
})

test('a key file holding 32 bytes that are not a secp256k1 key (0, or >= n) refuses keystore.key-file, not a library error', async () => {
  await withOut(async (out) => {
    const k = await initKs(out)
    const dir = keystoreDir(out)
    await k.createKey('pub-j1-eth', 'evm')
    const u = await k.unlock(PASS)
    const e = () => { const x = new Encrypter(); x.addRecipient(readFileSync(join(dir, 'master.pub'), 'utf8').trim()); return x }
    const n = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex')
    for (const bad of [new Uint8Array(32), Uint8Array.from(n), new Uint8Array(32).fill(0xff)]) {
      writeFileSync(join(dir, 'pub-j1-eth.age'), await e().encrypt(bad))
      await refusedAsync(() => u.withSecret('pub-j1-eth', async () => 1), 'keystore.key-file')
    }
    n[31] -= 1 // n - 1: a valid key, just not this key's
    writeFileSync(join(dir, 'pub-j1-eth.age'), await e().encrypt(Uint8Array.from(n)))
    await refusedAsync(() => u.withSecret('pub-j1-eth', async () => 1), 'keystore.pub-mismatch')
  })
})

// ---- atomic writes: <name>.tmp.<pid>.<hex> (O_EXCL, fsync), then link() to the final name, then unlink the temp

const TMP_NAME = /\.tmp\.\d+\.[0-9a-f]{12}$/
const tmpFiles = (dir: string): string[] => readdirSync(dir).filter((n) => TMP_NAME.test(n))
const deadPid = (): number => spawnSync(process.execPath, ['-e', '']).pid! // exited: its pid is not alive
const crashAt = (out: string, target: string) => new Keystore(out, 'testnet', {
  testScryptLogN: LOGN, beforeLink: (name) => { if (name === target) throw new Error('simulated crash') },
})

test('a crash between the write and the link leaves no final file (no truncated key, master or public info)', async () => {
  await withOut(async (out) => {
    await assert.rejects(crashAt(out, 'master.age').init(PASS), /simulated crash/)
    const dir = keystoreDir(out)
    assert.deepEqual(readdirSync(dir), ['profile'])
    await assert.rejects(crashAt(out, 'master.pub').init(PASS), /simulated crash/) // profile-only: init may run again
    assert.deepEqual(readdirSync(dir).sort(), ['master.age', 'profile'])
    rmSync(dir, { recursive: true })
    const k = await initKs(out)
    await assert.rejects(crashAt(out, 'pub-j1-eth.age').createKey('pub-j1-eth', 'evm'), /simulated crash/)
    assert.ok(!existsSync(join(dir, 'pub-j1-eth.age')) && !existsSync(join(dir, 'pub-j1-eth.pub.json')))
    await assert.rejects(crashAt(out, 'pub-j1-eth.pub.json').createKey('pub-j1-eth', 'evm'), /simulated crash/)
    assert.ok(existsSync(join(dir, 'pub-j1-eth.age')) && !existsSync(join(dir, 'pub-j1-eth.pub.json')))
    assert.deepEqual(tmpFiles(dir), [])
    assert.equal(k.publicInfo('pub-j1-eth'), undefined)
  })
})

test('a key or master file that appears between the write and the link is never replaced: keystore.no-overwrite / keystore.exists', async () => {
  await withOut(async (out) => {
    await initKs(out)
    const dir = keystoreDir(out)
    const racer = (o: string, target: string) => new Keystore(o, 'testnet', {
      testScryptLogN: LOGN, beforeLink: (name) => { if (name === target) writeFileSync(join(keystoreDir(o), name), 'racer', { mode: 0o600 }) },
    })
    await refusedAsync(() => racer(out, 'swap-j1.age').createKey('swap-j1', 'evm'), 'keystore.no-overwrite')
    assert.equal(readFileSync(join(dir, 'swap-j1.age'), 'utf8'), 'racer')
    assert.ok(!existsSync(join(dir, 'swap-j1.pub.json')))
    await refusedAsync(() => racer(out, 'arweave-j1.pub.json').createKey('arweave-j1', 'evm'), 'keystore.no-overwrite')
    assert.equal(readFileSync(join(dir, 'arweave-j1.pub.json'), 'utf8'), 'racer')
    assert.deepEqual(tmpFiles(dir), [])
    const out2 = join(out, 'second')
    await refusedAsync(() => racer(out2, 'master.age').init(PASS), 'keystore.exists')
    assert.equal(readFileSync(join(keystoreDir(out2), 'master.age'), 'utf8'), 'racer')
    assert.ok(!existsSync(join(keystoreDir(out2), 'master.pub')))
    assert.deepEqual(tmpFiles(keystoreDir(out2)), [])
  })
})

test('temp files of a dead writer are ignored by every reader and swept by the next init/createKey; a live writer\'s are kept', async () => {
  await withOut(async (out) => {
    const dir = keystoreDir(out)
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const dead = deadPid()
    const stray = `master.age.tmp.${dead}.0123456789ab`
    writeFileSync(join(dir, stray), 'partial', { mode: 0o600 })
    assertKeystoreProfile(out, 'mainnet') // crash leftovers alone are no keystore yet
    ks(out).assertCanInit()
    const k = await initKs(out)
    assert.ok(!existsSync(join(dir, stray)), 'swept by init')
    const strays = [`D-b2.age.tmp.${dead}.abcdefabcdef`, `D-b2.pub.json.tmp.${dead}.abcdefabcdef`, `pool-b2.age.tmp.${dead}.111111111111`]
    for (const s of strays) writeFileSync(join(dir, s), 'partial', { mode: 0o600 })
    slot(out, 'pool-b2')
    assert.equal(k.publicInfo('D-b2'), undefined)
    assert.deepEqual(k.listSources(), [])
    const live = `l1hop-j1.age.tmp.${process.pid}.0123456789ab` // this process: alive, never swept
    writeFileSync(join(dir, live), 'in flight', { mode: 0o600 })
    await k.createKey('D-b2', 'evm')
    assert.deepEqual(tmpFiles(dir), [live])
    assert.deepEqual(k.listSources(), ['b2'])
  })
})

// ---- init

test('init refuses keystore.exists when a keystore (or any key file) is already there', async () => {
  await withOut(async (out) => {
    const k = await initKs(out)
    await refusedAsync(() => k.init(PASS), 'keystore.exists')
    await refusedAsync(() => ks(out).init(PASS), 'keystore.exists')
    const out2 = join(out, 'second')
    mkdirSync(keystoreDir(out2), { recursive: true, mode: 0o700 })
    writeFileSync(join(keystoreDir(out2), 'profile'), 'testnet\n', { mode: 0o600 })
    writeFileSync(join(keystoreDir(out2), 'D-railgun-eth.age'), 'synthetic', { mode: 0o600 })
    refused(() => ks(out2).assertCanInit(), 'keystore.exists')
    await refusedAsync(() => ks(out2).init(PASS), 'keystore.exists')
    // a profile file alone (an init that stopped early, same profile) is not a keystore yet
    unlinkSync(join(keystoreDir(out2), 'D-railgun-eth.age'))
    await ks(out2).init(PASS)
  })
})

test('init refuses a weak passphrase itself (passphrase.weak), writing nothing', async () => {
  await withOut(async (out) => {
    await refusedAsync(() => ks(out).init('abacus abdomen abdominal abide abiding'), 'passphrase.weak')
    assert.ok(!existsSync(keystoreDir(out)) || readdirSync(keystoreDir(out)).length === 0)
  })
})

test('init: keystore/ 0700 with files 0600; lifecycle/ and lifecycle/trigger/ created 0700; profile recorded', async () => {
  await withOut(async (out) => {
    const k = await initKs(out, 'local')
    await k.createKey('D-railgun-eth', 'evm')
    const dir = keystoreDir(out)
    assert.equal(mode(dir), 0o700)
    assert.deepEqual(readdirSync(dir).sort(), ['D-railgun-eth.age', 'D-railgun-eth.pub.json', 'master.age', 'master.pub', 'profile'])
    for (const f of readdirSync(dir)) assert.equal(mode(join(dir, f)), 0o600, f)
    assert.equal(readFileSync(join(dir, 'profile'), 'utf8'), 'local\n')
    assert.equal(mode(lifecycleDir(out)), 0o700)
    assert.ok(statSync(join(lifecycleDir(out), 'trigger')).isDirectory())
    assert.equal(mode(join(lifecycleDir(out), 'trigger')), 0o700)
  })
})

test('a keystore directory with group/other access refuses store.perms', async () => {
  await withOut(async (out) => {
    const k = await initKs(out)
    chmodSync(keystoreDir(out), 0o755)
    await refusedAsync(() => k.createKey('D-railgun-eth', 'evm'), 'store.perms')
    await refusedAsync(() => k.unlock(PASS), 'store.perms')
    chmodSync(keystoreDir(out), 0o700)
  })
})

test('workfactor: the test option outside NODE_ENV=test, or outside 10..18, refuses keystore.workfactor', async () => {
  await withOut(async (out) => {
    const saved = process.env.NODE_ENV
    try {
      delete process.env.NODE_ENV
      refused(() => new Keystore(out, 'testnet', { testScryptLogN: 10 }), 'keystore.workfactor')
      process.env.NODE_ENV = 'production'
      refused(() => new Keystore(out, 'testnet', { testScryptLogN: 18 }), 'keystore.workfactor')
      new Keystore(out, 'testnet') // production: no option, nothing to refuse
    } finally { process.env.NODE_ENV = saved }
    for (const n of [9, 19, 10.5, Number.NaN]) refused(() => new Keystore(out, 'testnet', { testScryptLogN: n }), 'keystore.workfactor')
    assert.equal(SCRYPT_LOG_N, 18)
    await ks(out).init(PASS)
    const header = readFileSync(join(keystoreDir(out), 'master.age'), 'latin1').split('\n')
    assert.equal(header[0], 'age-encryption.org/v1')
    assert.match(header[1], /^-> scrypt [A-Za-z0-9+/]{22} 10$/) // the test work factor; logN 18 is asserted in keystore-cli.test.ts
  })
})

// ---- profile binding (K33)

test('profile binding: every operation under another profile than keystore/profile refuses keystore.profile', async () => {
  await withOut(async (out) => {
    const k = await initKs(out, 'testnet')
    await k.createKey('D-railgun-eth', 'evm')
    const u = await k.unlock(PASS)
    for (const p of ['mainnet', 'local'] as const) {
      const other = ks(out, p)
      refused(() => other.assertCanInit(), 'keystore.profile')
      await refusedAsync(() => other.init(PASS), 'keystore.profile')
      await refusedAsync(() => other.createKey('pub-j1-eth', 'evm'), 'keystore.profile')
      refused(() => other.publicInfo('D-railgun-eth'), 'keystore.profile')
      refused(() => other.listSources(), 'keystore.profile')
      await refusedAsync(() => other.unlock(PASS), 'keystore.profile')
      refused(() => assertKeystoreProfile(out, p), 'keystore.profile')
    }
    assertKeystoreProfile(out, 'testnet')
    // the binding is checked again on every withSecret, not only at unlock
    writeFileSync(join(keystoreDir(out), 'profile'), 'mainnet\n')
    await refusedAsync(() => u.withSecret('D-railgun-eth', async () => 1), 'keystore.profile')
  })
})

test('assertKeystoreProfile: no keystore passes; a keystore whose profile file is missing, malformed or a symlink refuses keystore.profile', async () => {
  await withOut(async (out) => {
    assertKeystoreProfile(out, 'mainnet') // no $OUT at all
    mkdirSync(keystoreDir(out), { recursive: true, mode: 0o700 })
    assertKeystoreProfile(out, 'mainnet') // an empty keystore directory: nothing to bind yet
    writeFileSync(join(keystoreDir(out), 'master.pub'), 'age1x\n', { mode: 0o600 })
    refused(() => assertKeystoreProfile(out, 'mainnet'), 'keystore.profile') // no profile file
    const pf = join(keystoreDir(out), 'profile')
    for (const bad of ['testnet', 'testnet\n\n', ' testnet\n', 'TESTNET\n', 'devnet\n', '']) {
      writeFileSync(pf, bad, { mode: 0o600 })
      refused(() => assertKeystoreProfile(out, 'testnet'), 'keystore.profile')
    }
    unlinkSync(pf)
    mkdirSync(pf)
    refused(() => assertKeystoreProfile(out, 'testnet'), 'keystore.profile') // a directory
    rmSync(pf, { recursive: true })
    writeFileSync(join(out, 'elsewhere'), 'testnet\n')
    symlinkSync(join(out, 'elsewhere'), pf)
    refused(() => assertKeystoreProfile(out, 'testnet'), 'keystore.profile') // a symlink
    unlinkSync(pf)
    writeFileSync(pf, 'testnet\n', { mode: 0o600 })
    assertKeystoreProfile(out, 'testnet')
  })
})

test('requireExplicitProfile: neither --profile nor VT_PROFILE refuses config.profile-required (never defaults to mainnet)', () => {
  refused(() => requireExplicitProfile([], {}), 'config.profile-required')
  refused(() => requireExplicitProfile([], { VT_PROFILE: '' }), 'config.profile-required')
  refused(() => requireExplicitProfile(['init'], { HOME: '/x' }), 'config.profile-required')
  assert.equal(requireExplicitProfile(['--profile', 'testnet'], {}), 'testnet')
  assert.equal(requireExplicitProfile([], { VT_PROFILE: 'local' }), 'local')
  assert.equal(requireExplicitProfile(['--profile', 'mainnet'], { VT_PROFILE: 'mainnet' }), 'mainnet')
  refused(() => requireExplicitProfile(['--profile', 'testnet'], { VT_PROFILE: 'local' }), 'config.profile-conflict')
  refused(() => requireExplicitProfile(['--profile', 'devnet'], {}), 'config.profile-invalid')
  refused(() => requireExplicitProfile(['--profile=testnet'], {}), 'config.flag-format')
})

// ---- leak scan

test('leak scan: after a full run no secret key (raw or hex), master identity or passphrase is in keystoreDir or TMPDIR', async () => {
  const d = mkdtempSync(join(tmpdir(), 'vt-12b-leak-'))
  const savedTmp = process.env.TMPDIR
  try {
    const tmp = join(d, 'tmp')
    mkdirSync(tmp, { mode: 0o700 })
    process.env.TMPDIR = tmp // anything the keystore wrote to a temp file would land here
    assert.equal(tmpdir(), tmp)
    const out = join(d, 'out')
    const k = await initKs(out)
    const ids = ['D-railgun-eth', 'pub-j1-eth', 'l1hop-j1']
    for (const id of ids) await k.createKey(id, 'evm')
    const u = await k.unlock(PASS)
    const secrets: Array<string | Uint8Array> = [PASS, await masterIdentity(out)]
    for (const id of ids) {
      await u.withSecret(id, async (s) => {
        const h = Buffer.from(s).toString('hex')
        secrets.push(new Uint8Array(s), h, h.toUpperCase(), '0x' + h)
      })
    }
    assert.equal(secrets.length, 2 + 4 * ids.length)
    assertNoSecretsInStore(keystoreDir(out), secrets)
    assertNoSecretsInStore(d, secrets) // $OUT (lifecycle/ too) and TMPDIR
    assert.deepEqual(readdirSync(tmp), [])
  } finally {
    if (savedTmp === undefined) delete process.env.TMPDIR
    else process.env.TMPDIR = savedTmp
    rmSync(d, { recursive: true, force: true })
  }
})

// vt decrypt core (lane E): one age file — every kind armored + binary, wrong secrets, the before-round refusal, malformed and
// oversize input. SYNTHETIC data only (fixtures.ts): made-up passphrases, fresh identities, a made-up drand chain.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as api from '../../src/decrypt/index.ts'
import { decryptAge, detectInput } from '../../src/decrypt/index.ts'
import { isRefusal } from '../../src/text/guard.ts'
import { QUICKNET, unlockIso } from '../../src/text/drand.ts'
import { latin1, utf8 } from '../../src/text/bytes.ts'
import {
  FUTURE_ROUND, PASSPHRASE, PAST_ROUND, armor, fakeFetcher, identityBin, keygenFile, newIdentity, passphraseBin, sha256, signatureFor,
  targz, text, tlockBin,
} from './fixtures.ts'

async function refused(p: Promise<unknown> | (() => unknown), guard: string, re?: RegExp): Promise<string> {
  try { await (typeof p === 'function' ? p() : p) } catch (e) {
    assert.ok(isRefusal(e), `expected a Refusal ${guard}, got ${String(e)}`)
    assert.equal(e.guardId, guard, e.message)
    if (re) assert.match(e.message, re)
    return e.message
  }
  assert.fail(`expected a refusal ${guard}, nothing was refused`)
}
const variants = (bin: Uint8Array): Array<[string, string | Uint8Array]> => [['binary', bin], ['armored text', armor(bin)], ['armored bytes', utf8(armor(bin))]]

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

test('passphrase (scrypt): detected and decrypted, armored and binary', async () => {
  const plain = 'synthetic secret: passphrase kind\n'
  const bin = await passphraseBin(plain)
  for (const [label, input] of variants(bin)) {
    const d = detectInput(input)
    assert.equal(d.kind, 'passphrase', label)
    assert.equal(d.form, label === 'binary' ? 'binary' : 'armored', label)
    assert.equal(d.round, null); assert.equal(d.opensAt, null); assert.equal(d.identityPath, false)
    const r = await decryptAge(input, { passphrase: PASSPHRASE })
    assert.equal(r.kind, 'passphrase'); assert.equal(r.via, 'passphrase')
    assert.equal(r.files.length, 1); assert.equal(r.files[0].name, 'plaintext')
    assert.equal(text(r.files[0].bytes), plain, label)
    assert.equal(r.files[0].size, utf8(plain).length); assert.equal(r.files[0].sha256, sha256(plain))
    assert.deepEqual(r.blocks, []); assert.equal(r.archive, null)
  }
})

test('passphrase: a wrong one is decrypt.passphrase, a missing one decrypt.kind; the message never holds it', async () => {
  const bin = await passphraseBin('synthetic\n')
  for (const [label, input] of variants(bin)) {
    const m = await refused(decryptAge(input, { passphrase: 'synthetic wrong passphrase' }), 'decrypt.passphrase')
    assert.ok(!m.includes('synthetic wrong passphrase') && !m.includes(PASSPHRASE), label)
    await refused(decryptAge(input, {}), 'decrypt.kind', /passphrase/)
    await refused(decryptAge(input, { passphrase: '' }), 'decrypt.kind', /passphrase/)
    await refused(decryptAge(input, { identity: 'AGE-SECRET-KEY-1QQQQ' }), 'decrypt.kind', /passphrase/)
  }
})

test('passphrase: an oversized passphrase and a scrypt work factor above the bound are decrypt.size, before any scrypt runs', async () => {
  const bin = await passphraseBin('synthetic\n')
  await refused(decryptAge(bin, { passphrase: 'x'.repeat(65 * 1024) }), 'decrypt.size', /passphrase/)
  await refused(decryptAge(bin, { passphrase: 'xxxx', limits: { secret: 3 } }), 'decrypt.size', /passphrase/)
  // the header says log2 N = 21 (the MAC no longer matches, but nothing gets that far): refused from the header alone
  const head = latin1(bin.subarray(0, 200))
  const at = head.indexOf(' 10\n')
  assert.ok(at > 0)
  const big = new Uint8Array(bin); big[at + 1] = 0x32; big[at + 2] = 0x31 // "10" → "21"
  await refused(() => detectInput(big), 'decrypt.size', /scrypt work factor/)
  await refused(decryptAge(big, { passphrase: PASSPHRASE }), 'decrypt.size', /scrypt work factor/)
  await refused(() => detectInput(bin, { scryptLogN: 9 }), 'decrypt.size', /scrypt work factor/)
  await refused(() => detectInput(big, { scryptLogN: 30 }), 'decrypt.size', /scrypt work factor/)  // a higher limit cannot pass age-encryption's 20
  assert.equal(detectInput(bin, { scryptLogN: 10 }).kind, 'passphrase')
})

test('identity (X25519): detected and decrypted, armored and binary; an age-keygen file with comments; several identities', async () => {
  const id = await newIdentity()
  const other = await newIdentity()
  const plain = 'synthetic secret: identity kind\n'
  const bin = await identityBin(plain, id.recipient)
  for (const [label, input] of variants(bin)) {
    const d = detectInput(input)
    assert.equal(d.kind, 'identity', label); assert.equal(d.identityPath, true)
    for (const identity of [id.identity, keygenFile(id.identity, id.recipient), `${other.identity}\n\n${id.identity}\r\n`]) {
      const r = await decryptAge(input, { identity })
      assert.equal(r.kind, 'identity'); assert.equal(r.via, 'identity')
      assert.equal(text(r.files[0].bytes), plain, label)
    }
  }
  // a file encrypted to two recipients opens with either identity
  const two = await identityBin(plain, other.recipient, id.recipient)
  assert.equal(text((await decryptAge(two, { identity: id.identity })).files[0].bytes), plain)
})

test('identity: the post-quantum hybrid kind (mlkem768x25519, AGE-SECRET-KEY-PQ-1) opens too', async () => {
  const pq = await newIdentity(true)
  const bin = await identityBin('synthetic pq\n', pq.recipient)
  assert.equal(detectInput(bin).kind, 'identity')
  assert.equal(text((await decryptAge(armor(bin), { identity: pq.identity })).files[0].bytes), 'synthetic pq\n')
})

test('identity: a wrong identity, a malformed identity text, an empty one are decrypt.identity; none given is decrypt.kind; nothing echoed', async () => {
  const id = await newIdentity()
  const wrong = await newIdentity()
  const bin = await identityBin('synthetic\n', id.recipient)
  for (const [label, input] of variants(bin)) {
    const m = await refused(decryptAge(input, { identity: wrong.identity }), 'decrypt.identity', /none of the given identities/)
    assert.ok(!m.includes(wrong.identity) && !m.includes(id.identity), label)
    const m2 = await refused(decryptAge(input, { identity: `# comment\nnot-an-identity-${id.identity}\n` }), 'decrypt.identity', /line 2/)
    assert.ok(!m2.includes(id.identity), 'the bad line is not echoed')
    await refused(decryptAge(input, { identity: '# only comments\n\n' }), 'decrypt.identity', /no AGE-SECRET-KEY-1/)
    // right shape, wrong checksum: age-encryption refuses it
    const bad = id.identity.slice(0, -1) + (id.identity.endsWith('Q') ? 'P' : 'Q')
    await refused(decryptAge(input, { identity: bad }), 'decrypt.identity')
    await refused(decryptAge(input, {}), 'decrypt.kind', /identity/)
    await refused(decryptAge(input, { passphrase: PASSPHRASE }), 'decrypt.kind', /identity/)
  }
  await refused(decryptAge(bin, { identity: `${id.identity}\n`.repeat(2000) }), 'decrypt.size', /identity text/)
})

test('timelocked (tlock): detected with its round and UTC time; decrypted with the fetcher\'s signature, armored and binary', async () => {
  const plain = 'synthetic secret: timelocked kind\n'
  const bin = await tlockBin(PAST_ROUND, plain)
  for (const [label, input] of variants(bin)) {
    const d = detectInput(input)
    assert.equal(d.kind, 'timelocked', label)
    assert.equal(d.round, PAST_ROUND); assert.equal(d.chainHash, QUICKNET.hash); assert.equal(d.opensAt, unlockIso(PAST_ROUND))
    assert.equal(d.identityPath, false)
    const f = fakeFetcher()
    const r = await decryptAge(input, { fetchRoundSignature: f.fetch })
    assert.equal(r.kind, 'timelocked'); assert.equal(r.via, 'timelock')
    assert.equal(text(r.files[0].bytes), plain, label)
    assert.deepEqual(f.calls, [[QUICKNET.hash, PAST_ROUND]], 'one call: the stanza\'s chain hash and round')
  }
})

test('timelocked: before the round it is decrypt.too-early "opens at <UTC>", and the fetcher is never asked', async () => {
  const bin = await tlockBin(FUTURE_ROUND, 'synthetic future\n')
  const f = fakeFetcher(() => true)  // this fake would sign any round: only the clock may stop it
  for (const [label, input] of variants(bin)) {
    const m = await refused(decryptAge(input, { fetchRoundSignature: f.fetch }), 'decrypt.too-early', /opens at /)
    assert.ok(m.includes(unlockIso(FUTURE_ROUND)), label)
    await refused(decryptAge(input, {}), 'decrypt.too-early', /opens at /)
  }
  assert.deepEqual(f.calls, [], 'nothing was fetched before the round')
  // by an injected clock: one period before the round is too early; at the round it opens
  const past = await tlockBin(PAST_ROUND, 'synthetic edge\n')
  const at = (QUICKNET.genesis_time + (PAST_ROUND - 1) * QUICKNET.period) * 1000
  await refused(decryptAge(past, { fetchRoundSignature: f.fetch, now: () => at - 1 }), 'decrypt.too-early', new RegExp(unlockIso(PAST_ROUND)))
  assert.deepEqual(f.calls, [])
  assert.equal(text((await decryptAge(past, { fetchRoundSignature: f.fetch, now: () => at })).files[0].bytes), 'synthetic edge\n')
})

test('timelocked: drand not yet published (the fetcher answers null) is decrypt.too-early; no fetcher is decrypt.kind', async () => {
  const bin = await tlockBin(PAST_ROUND, 'synthetic\n')
  const f = fakeFetcher(() => false)
  await refused(decryptAge(bin, { fetchRoundSignature: f.fetch }), 'decrypt.too-early', /drand has not published round 1000000 yet \(relay\)/)
  assert.equal(f.calls.length, 1)
  await refused(decryptAge(bin, {}), 'decrypt.kind', /signature/)
  await refused(decryptAge(bin, { passphrase: PASSPHRASE, identity: 'AGE-SECRET-KEY-1QQQQ' }), 'decrypt.kind', /signature/)
})

test('timelocked: a wrong or malformed signature is decrypt.format (the IBE check fails closed); a fetcher error passes through', async () => {
  const bin = await tlockBin(PAST_ROUND, 'synthetic\n')
  await refused(decryptAge(bin, { fetchRoundSignature: async () => signatureFor(PAST_ROUND + 1) }), 'decrypt.format', /signature does not open/)
  await refused(decryptAge(bin, { fetchRoundSignature: async () => 'ab'.repeat(47) }), 'decrypt.format', /48 bytes of hex/)
  await refused(decryptAge(bin, { fetchRoundSignature: async () => 'zz'.repeat(48) }), 'decrypt.format', /48 bytes of hex/)
  await refused(decryptAge(bin, { fetchRoundSignature: async () => 42 as unknown as string }), 'decrypt.format', /48 bytes of hex/)
  // 48 bytes of hex that are no G1 point
  await refused(decryptAge(bin, { fetchRoundSignature: async () => 'ff'.repeat(48) }), 'decrypt.format', /signature does not open/)
  // upper-case hex of the right signature is fine
  assert.equal(text((await decryptAge(bin, { fetchRoundSignature: async () => signatureFor(PAST_ROUND).toUpperCase() })).files[0].bytes), 'synthetic\n')
  const boom = new Error('relay down (synthetic)')
  await assert.rejects(decryptAge(bin, { fetchRoundSignature: async () => { throw boom } }), (e) => e === boom)
})

test('timelocked: another drand chain, or a tlock stanza beside another stanza, is decrypt.kind', async () => {
  const other = await tlockBin(PAST_ROUND, 'synthetic\n', { ...(await import('./fixtures.ts')).SYNTH_INFO, hash: 'ab'.repeat(32) })
  await refused(() => detectInput(other), 'decrypt.kind', /other than quicknet/)
  await refused(decryptAge(other, { fetchRoundSignature: fakeFetcher().fetch }), 'decrypt.kind', /other than quicknet/)
  // a header with a tlock stanza and an X25519 stanza
  const bin = await tlockBin(PAST_ROUND, 'synthetic\n')
  const h = latin1(bin.subarray(0, 400))
  const cut = h.indexOf('\n--- ')
  const extra = `\n-> X25519 ${'A'.repeat(43)}\n${'A'.repeat(43)}`
  const mixed = new Uint8Array([...utf8(h.slice(0, cut) + extra), ...bin.subarray(cut)])
  await refused(() => detectInput(mixed), 'decrypt.kind', /tlock stanza must be the only stanza/)
})

test('unsupported recipients (an ssh-ed25519 stanza) and a scrypt stanza beside another are decrypt.kind', async () => {
  const id = await newIdentity()
  const bin = await identityBin('synthetic\n', id.recipient)
  const h = latin1(bin.subarray(0, 300))
  const ssh = utf8(h.replace('-> X25519 ', '-> ssh-ed25519 Zm9vYmFy '))
  await refused(() => detectInput(new Uint8Array([...ssh, ...bin.subarray(300)])), 'decrypt.kind', /ssh-ed25519/)
  const pp = await passphraseBin('synthetic\n')
  const ph = latin1(pp.subarray(0, 300))
  const cut = ph.indexOf('\n--- ')
  const mixed = new Uint8Array([...utf8(`${ph.slice(0, cut)}\n-> X25519 ${'A'.repeat(43)}\n${'A'.repeat(43)}`), ...pp.subarray(cut)])
  // scrypt beside another stanza: age forbids it (a scrypt stanza must be alone), so it is no kind this tool opens
  await refused(() => detectInput(mixed), 'decrypt.kind', /scrypt, X25519/)
  const lone = utf8(ph.replace('-> scrypt ', '-> piv-p256 '))
  await refused(() => detectInput(new Uint8Array([...lone, ...pp.subarray(300)])), 'decrypt.kind', /piv-p256/)
})

test('malformed input is decrypt.format: not age, non-canonical armor, a broken header, binary given as text', async () => {
  const bin = await passphraseBin('synthetic\n')
  for (const bad of ['', 'hello', 'AGE-SECRET-KEY-1QQQQ', '-----BEGIN PGP MESSAGE-----\nxx\n-----END PGP MESSAGE-----\n', '{"json":true}']) {
    await refused(() => detectInput(bad), 'decrypt.format')
    await refused(decryptAge(bad, { passphrase: PASSPHRASE }), 'decrypt.format')
  }
  await refused(() => detectInput(new Uint8Array([0xff, 0xfe, 0x00, 0x01])), 'decrypt.format', /not UTF-8/)
  // 76-column armor (not what age writes): refused, not guessed at
  const b64 = Buffer.from(bin).toString('base64')
  const wide = `-----BEGIN AGE ENCRYPTED FILE-----\n${b64.match(/.{1,76}/g)!.join('\n')}\n-----END AGE ENCRYPTED FILE-----\n`
  await refused(() => detectInput(wide), 'decrypt.format', /canonical age ASCII armor/)
  // armor followed by something else
  await refused(() => detectInput(`${armor(bin)}trailing words\n`), 'decrypt.format')
  // a binary age file as a JS string
  await refused(() => detectInput(latin1(bin)), 'decrypt.format', /binary age file was given as text/)
  // the version line, then garbage
  await refused(() => detectInput(utf8('age-encryption.org/v1\nnot a stanza\n')), 'decrypt.format', /not an age file/)
  await refused(decryptAge(utf8('age-encryption.org/v1\n-> scrypt\n'), { passphrase: PASSPHRASE }), 'decrypt.format', /not an age file/)
  // a malformed scrypt stanza (no work factor)
  const noLog = utf8(latin1(bin).replace(/ 10\n/, '\n'))
  await refused(() => detectInput(noLog), 'decrypt.format', /scrypt stanza/)
})

test('damaged ciphertext is decrypt.format, never decrypt.passphrase: a flipped payload byte, a cut-off file, an edited header MAC', async () => {
  const bin = await passphraseBin('synthetic damaged payload\n'.repeat(10))
  const flipped = new Uint8Array(bin); flipped[flipped.length - 5] ^= 1
  await refused(decryptAge(flipped, { passphrase: PASSPHRASE }), 'decrypt.format', /payload does not decrypt/)
  await refused(decryptAge(bin.subarray(0, bin.length - 20), { passphrase: PASSPHRASE }), 'decrypt.format', /payload does not decrypt/)
  const h = latin1(bin.subarray(0, 300))
  const mac = h.indexOf('\n--- ') + 6
  const edited = new Uint8Array(bin); edited[mac] = edited[mac] === 0x41 ? 0x42 : 0x41
  await refused(decryptAge(edited, { passphrase: PASSPHRASE }), 'decrypt.format', /header MAC/)
  // and for the other kinds
  const id = await newIdentity()
  const ib = await identityBin('synthetic\n'.repeat(10), id.recipient)
  const ibf = new Uint8Array(ib); ibf[ibf.length - 3] ^= 1
  await refused(decryptAge(ibf, { identity: id.identity }), 'decrypt.format', /payload does not decrypt/)
  const tb = await tlockBin(PAST_ROUND, 'synthetic\n'.repeat(10))
  const tbf = new Uint8Array(tb); tbf[tbf.length - 3] ^= 1
  await refused(decryptAge(tbf, { fetchRoundSignature: fakeFetcher().fetch }), 'decrypt.format', /payload does not decrypt/)
})

test('oversize input is decrypt.size, as text and as bytes, before anything is parsed (PASTE_LIMIT for pastes)', async () => {
  const bin = await passphraseBin('synthetic\n')
  await refused(() => detectInput(bin, { input: bin.length - 1 }), 'decrypt.size', /the input/)
  await refused(() => detectInput(armor(bin), { input: 100 }), 'decrypt.size', /the input/)
  await refused(decryptAge(armor(bin), { passphrase: PASSPHRASE, limits: { input: 100 } }), 'decrypt.size', /the input/)
  const paste = 'A'.repeat(api.PASTE_LIMIT + 1)
  await refused(() => detectInput(paste, { input: api.PASTE_LIMIT }), 'decrypt.size')
  // multi-byte text is measured in bytes
  await refused(() => detectInput('é'.repeat(60), { input: 100 }), 'decrypt.size')
  assert.equal(detectInput(bin, { input: bin.length }).kind, 'passphrase')
})

test('pasted armor is read through a BOM, CRLF line ends and surrounding blank lines', async () => {
  const bin = await passphraseBin('synthetic paste\n')
  const messy = `﻿\n  ${armor(bin).replace(/\n/g, '\r\n')}\r\n\r\n`
  assert.equal(detectInput(messy).form, 'armored')
  assert.equal(text((await decryptAge(messy, { passphrase: PASSPHRASE })).files[0].bytes), 'synthetic paste\n')
  // the END line without its final newline (a paste stopped at the marker)
  assert.equal(detectInput(armor(bin).trimEnd()).kind, 'passphrase')
})

test('a decrypted .tar.gz is offered as an archive (the identity path for vault.tar.gz.age given alone)', async () => {
  const id = await newIdentity()
  const tgz = targz({ 'items/cccc.json': '{"synthetic":"c"}\n' })
  const r = await decryptAge(await identityBin(tgz, id.recipient), { identity: id.identity })
  assert.ok(r.archive !== null)
  assert.deepEqual(await api.listArchive(r.archive), [{ path: 'items/cccc.json', size: 18 }])
  assert.equal(text(await api.extractOne(r.archive, 'items/cccc.json')), '{"synthetic":"c"}\n')
})

test('nothing is logged: no console output from any kind (tlock-js included), success or refusal', async () => {
  const seen: unknown[] = []
  const saved = { log: console.log, info: console.info, warn: console.warn, error: console.error, debug: console.debug }
  for (const k of Object.keys(saved) as Array<keyof typeof saved>) console[k] = (...a: unknown[]) => { seen.push(a) }
  try {
    const id = await newIdentity()
    await decryptAge(await passphraseBin('synthetic\n'), { passphrase: PASSPHRASE })
    await decryptAge(await identityBin('synthetic\n', id.recipient), { identity: id.identity })
    await decryptAge(await tlockBin(PAST_ROUND, 'synthetic\n'), { fetchRoundSignature: fakeFetcher().fetch })
    await decryptAge(await passphraseBin('synthetic\n'), { passphrase: 'wrong synthetic' }).catch(() => {})
  } finally { Object.assign(console, saved) }
  assert.deepEqual(seen, [])
})

// vt decrypt core (lane E): a whole SEALED.txt, end to end — every package shape the seal-text path (buildSealedFrom) makes, bare and
// inside a published text; each block checked against its [file] line; the identity (recovery) path; the before-round refusal; an
// unknown format version; tampered texts. SYNTHETIC packages only (fixtures.ts makeSealed).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { decryptAge, detectInput, extractAll, extractOne, listArchive } from '../../src/decrypt/index.ts'
import { isRefusal } from '../../src/text/guard.ts'
import { QUICKNET, unlockIso } from '../../src/text/drand.ts'
import { utf8 } from '../../src/text/bytes.ts'
import { AR, FUTURE_ROUND, PAST_ROUND, VAULT_FILES, fakeFetcher, fileLines, makeSealed, newIdentity, sha256, text } from './fixtures.ts'

async function refused(p: Promise<unknown> | (() => unknown), guard: string, re?: RegExp): Promise<string> {
  try { await (typeof p === 'function' ? p() : p) } catch (e) {
    assert.ok(isRefusal(e), `expected a Refusal ${guard}, got ${String(e)}`)
    assert.equal(e.guardId, guard, e.message)
    if (re) assert.match(e.message, re)
    return e.message
  }
  assert.fail(`expected a refusal ${guard}, nothing was refused`)
}
const VAULT_LIST = Object.entries(VAULT_FILES).map(([path, c]) => ({ path, size: utf8(c).length }))

test('two-layer, full: unlock-TIME.age (tlock) → identity → vault.tar.gz.age, bare and published; every block checked against its [file] line', async () => {
  const s = await makeSealed()
  const lines = fileLines(s.sealed)
  assert.deepEqual([...lines.keys()], ['unlock-TIME.age', 'vault.tar.gz.age'])
  for (const [form, input] of [['sealed', s.sealed], ['published', s.published], ['sealed', utf8(s.sealed)]] as const) {
    const d = detectInput(input)
    assert.equal(d.kind, 'sealed'); assert.equal(d.form, form)
    assert.equal(d.format, 'vault-timelock-sealed/1'); assert.equal(d.layout, 'two-layer'); assert.equal(d.contents, 'full')
    assert.equal(d.round, PAST_ROUND); assert.equal(d.chainHash, QUICKNET.hash); assert.equal(d.opensAt, unlockIso(PAST_ROUND))
    assert.equal(d.identityPath, true)
    assert.deepEqual(d.blocks, [...lines].map(([name, l]) => ({ name, size: l.size, sha256: l.sha256 })))
    const f = fakeFetcher()
    const r = await decryptAge(input, { fetchRoundSignature: f.fetch })
    assert.equal(r.kind, 'sealed'); assert.equal(r.via, 'timelock')
    assert.deepEqual(r.files.map((x) => x.name), ['identity.key', 'vault.tar.gz'])
    assert.equal(text(r.files[0].bytes), `${s.identity}\n`)
    assert.deepEqual([...r.files[1].bytes], [...s.tgz])
    assert.equal(r.files[1].sha256, sha256(s.tgz)); assert.equal(r.files[1].size, s.tgz.length)
    assert.deepEqual(r.blocks, d.blocks)
    for (const b of r.blocks) assert.deepEqual({ size: b.size, sha256: b.sha256 }, lines.get(b.name), b.name)
    assert.deepEqual(f.calls, [[QUICKNET.hash, PAST_ROUND]])
    // per-file access to the archive
    assert.ok(r.archive !== null); assert.equal(r.archive.name, 'vault.tar.gz')
    assert.deepEqual(await listArchive(r.archive), VAULT_LIST)
    assert.equal(text(await extractOne(r.archive, 'items/bbbb.json')), VAULT_FILES['items/bbbb.json'])
    assert.deepEqual((await extractAll(r.archive)).map((x) => [x.path, text(x.bytes)]), Object.entries(VAULT_FILES))
    assert.deepEqual(r.notes, [])
  }
})

test('two-layer: the identity (recovery) path opens vault.tar.gz.age straight, at any time, with no fetcher; a wrong identity is decrypt.identity', async () => {
  const s = await makeSealed({ round: FUTURE_ROUND })
  const r = await decryptAge(s.sealed, { identity: s.identity! })
  assert.equal(r.via, 'identity')
  assert.deepEqual(r.files.map((x) => x.name), ['vault.tar.gz'])
  assert.deepEqual(await listArchive(r.archive!), VAULT_LIST)
  // given both, the identity path is taken and nothing is fetched
  const f = fakeFetcher()
  assert.equal((await decryptAge(s.published, { identity: s.identity!, fetchRoundSignature: f.fetch })).via, 'identity')
  assert.deepEqual(f.calls, [])
  const wrong = await newIdentity()
  const m = await refused(decryptAge(s.sealed, { identity: wrong.identity }), 'decrypt.identity', /vault\.tar\.gz\.age/)
  assert.ok(!m.includes(wrong.identity))
  await refused(decryptAge(s.sealed, { identity: 'not an identity' }), 'decrypt.identity')
})

test('a SEALED.txt before its round is decrypt.too-early "opens at <UTC>", and the fetcher is never asked', async () => {
  for (const kind of ['two-layer', 'vault'] as const) {
    const s = await makeSealed({ kind, round: FUTURE_ROUND })
    const f = fakeFetcher(() => true)
    const m = await refused(decryptAge(s.sealed, { fetchRoundSignature: f.fetch }), 'decrypt.too-early', /opens at /)
    assert.ok(m.includes(unlockIso(FUTURE_ROUND)), kind)
    assert.deepEqual(f.calls, [], kind)
    assert.equal(detectInput(s.sealed).opensAt, unlockIso(FUTURE_ROUND))
    await refused(decryptAge(s.sealed, {}), 'decrypt.too-early')
  }
  // past the round by the clock, but drand has not published it (the fetcher answers null)
  const s = await makeSealed()
  await refused(decryptAge(s.sealed, { fetchRoundSignature: fakeFetcher(() => false).fetch }), 'decrypt.too-early')
  await refused(decryptAge(s.sealed, {}), 'decrypt.kind', /signature/)
})

test('two-layer, key-only: the time lock yields identity.key and a note; an identity alone opens nothing (decrypt.kind)', async () => {
  const s = await makeSealed({ contents: 'key-only' })
  const d = detectInput(s.sealed)
  assert.equal(d.contents, 'key-only'); assert.equal(d.arId, AR); assert.equal(d.identityPath, false)
  assert.deepEqual(d.blocks.map((b) => b.name), ['unlock-TIME.age'])
  const r = await decryptAge(s.sealed, { fetchRoundSignature: fakeFetcher().fetch })
  assert.deepEqual(r.files.map((x) => x.name), ['identity.key'])
  assert.equal(r.archive, null)
  assert.match(r.notes.join('\n'), new RegExp(`ar://${AR}`))
  await refused(decryptAge(s.sealed, { identity: s.identity! }), 'decrypt.kind', /key-only/)
})

test('one-layer packages: vault, secret, raw payload and tar+gzip payload, each through its time lock', async () => {
  const want: Record<string, [string, string]> = { vault: ['vault', 'vault.tar.gz'], secret: ['secret', 'secret.tar.gz'], raw: ['payload', 'content'], 'tar+gzip': ['payload', 'content.tar.gz'] }
  for (const kind of ['vault', 'secret', 'raw', 'tar+gzip'] as const) {
    const s = await makeSealed({ kind })
    const d = detectInput(s.published)
    assert.equal(d.layout, want[kind][0], kind); assert.equal(d.identityPath, false)
    const r = await decryptAge(s.published, { fetchRoundSignature: fakeFetcher().fetch })
    assert.equal(r.via, 'timelock')
    assert.deepEqual(r.files.map((x) => x.name), [want[kind][1]], kind)
    if (kind === 'raw') { assert.equal(text(r.files[0].bytes), s.payload); assert.equal(r.archive, null) } else {
      assert.deepEqual([...r.files[0].bytes], [...s.tgz], kind)
      assert.deepEqual(await listArchive(r.archive!), VAULT_LIST, kind)
    }
    // an identity cannot open a one-layer package
    await refused(decryptAge(s.sealed, { identity: (await newIdentity()).identity }), 'decrypt.kind', /one layer/)
  }
})

test('a block that differs from its [file] line, or an edited text, is decrypt.format: nothing is decrypted, nothing fetched', async () => {
  const s = await makeSealed()
  const lines = fileLines(s.sealed)
  const f = fakeFetcher()
  // the [file] line's sha256 changed
  const sha = lines.get('vault.tar.gz.age')!.sha256
  const badSha = s.sealed.replace(sha, sha.slice(0, -1) + (sha.endsWith('0') ? '1' : '0'))
  await refused(decryptAge(badSha, { fetchRoundSignature: f.fetch }), 'decrypt.format', /block-mismatch/)
  await refused(() => detectInput(badSha), 'decrypt.format', /block-mismatch/)
  // the [file] line's size changed
  const size = lines.get('unlock-TIME.age')!.size
  await refused(decryptAge(s.sealed.replace(`unlock-TIME.age bytes=${size} `, `unlock-TIME.age bytes=${size + 1} `), { fetchRoundSignature: f.fetch }), 'decrypt.format', /block-mismatch/)
  // a base64 character inside a block changed (still canonical armor: same length, same alphabet)
  const at = s.sealed.indexOf('-----BEGIN AGE ENCRYPTED FILE-----\n', s.sealed.indexOf('[file vault.tar.gz.age')) + 100
  const c = s.sealed[at]
  const flipped = s.sealed.slice(0, at) + (c === 'A' ? 'B' : 'A') + s.sealed.slice(at + 1)
  await refused(decryptAge(flipped, { fetchRoundSignature: f.fetch }), 'decrypt.format')
  // a block removed, an extra line in the blocks, the end line missing
  await refused(decryptAge(s.sealed.replace(/\[file vault\.tar\.gz\.age[^]*?-----END AGE ENCRYPTED FILE-----\n/, ''), { fetchRoundSignature: f.fetch }), 'decrypt.format')
  await refused(decryptAge(s.sealed.replace('== end ==', 'stray\n== end =='), { fetchRoundSignature: f.fetch }), 'decrypt.format')
  await refused(decryptAge(s.sealed.replace('== end ==\n', ''), { fetchRoundSignature: f.fetch }), 'decrypt.format')
  assert.deepEqual(f.calls, [], 'a refused text is never opened')
})

test('the format: line dispatches: an unknown version (vault-timelock-sealed/2) or a missing format line is decrypt.format', async () => {
  const s = await makeSealed()
  for (const input of [s.sealed, s.published]) {
    const v2 = input.replace('format: vault-timelock-sealed/1', 'format: vault-timelock-sealed/2')
    const m = await refused(() => detectInput(v2), 'decrypt.format', /vault-timelock-sealed\/2/)
    assert.match(m, /opens vault-timelock-sealed\/1/)
    await refused(decryptAge(v2, { fetchRoundSignature: fakeFetcher().fetch }), 'decrypt.format', /not one this build opens/)
    await refused(() => detectInput(input.replace('format: vault-timelock-sealed/1\n', '')), 'decrypt.format', /format: line/)
  }
})

test('an inconsistent package is decrypt.format: the time-locked layer holds no age key, or a key that does not open the vault', async () => {
  const noKey = await makeSealed({ keyLayer: 'synthetic: not an age identity\n' })
  await refused(decryptAge(noKey.sealed, { fetchRoundSignature: fakeFetcher().fetch }), 'decrypt.format', /does not hold an age identity/)
  const other = await newIdentity()
  const wrongKey = await makeSealed({ keyLayer: `${other.identity}\n` })
  const m = await refused(decryptAge(wrongKey.sealed, { fetchRoundSignature: fakeFetcher().fetch }), 'decrypt.format', /inconsistent/)
  assert.ok(!m.includes(other.identity))
})

test('a SEALED.txt over the input bound is decrypt.size; pasted line ends and surrounding blanks are read', async () => {
  const s = await makeSealed()
  await refused(() => detectInput(s.sealed, { input: 1000 }), 'decrypt.size')
  await refused(decryptAge(s.sealed, { fetchRoundSignature: fakeFetcher().fetch, limits: { input: 1000 } }), 'decrypt.size')
  const pasted = `\n\n${s.sealed.replace(/\n/g, '\r\n').replace(/\r\n$/, '')}   \n`
  assert.equal(detectInput(pasted).layout, 'two-layer')
  assert.equal((await decryptAge(pasted, { fetchRoundSignature: fakeFetcher().fetch })).files.length, 2)
})

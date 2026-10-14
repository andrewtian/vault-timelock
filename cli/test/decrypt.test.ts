// cli/test/decrypt.test.ts — the SANDBOXED side of `vt decrypt` (src/decrypt.ts) in-process, inside the suite sandbox: every kind with
// synthetic fixtures (age passphrase, X25519 identity, tlock, SEALED.txt chains), what goes to the broker on the data channel (frames),
// --list (escaped for display, never a file's bytes), --only, full extraction checked against MANIFEST.csv / ATTACHMENTS.csv (vt.manifest),
// the relay's drand route (vt.relay-down) against a loopback test server on an ephemeral port, and that no passphrase, identity or
// plaintext reaches stdout / stderr. The mutation runner blanks vt.relay-down and vt.manifest; these tests must fail.
// SYNTHETIC only: core's test fixtures (packages/core/test/decrypt/fixtures.ts: a made-up BLS chain, fresh identities, made-up archives).
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createServer, type Server } from 'node:http'
import { createHash } from 'node:crypto'
import { PASTE_LIMIT } from '@vault-timelock/core/decrypt'
import { DATA_FD, PASTE_MAX, decryptPositions, foldKey, listName, unlistName } from '../src/decrypt-args.ts'
import { relayFetcher, runDecrypt, verifyManifests } from '../src/decrypt.ts'
import type { DecryptDeps } from '../src/decrypt.ts'
import { Sanitizer } from '../src/ops/sanitize.ts'
import { handedIndices, pathIndices } from '../src/ops/sandbox.ts'
import { UsageError } from '../src/args.ts'
import { CANARY, IPV4, rejectsWith, throwsWith } from './lib.ts'
import type * as Fixtures from '../../packages/core/test/decrypt/fixtures.ts'

const CORE_TEST = new URL('../../test/', import.meta.resolve('@vault-timelock/core/contracts'))
let F: typeof Fixtures
const PASS = 'decrypt-child-synthetic-passphrase'
const servers: Server[] = []
before(async () => { F = await import(new URL('decrypt/fixtures.ts', CORE_TEST).href) as typeof Fixtures })
after(async () => { for (const s of servers) { s.closeAllConnections(); await new Promise<void>((r) => s.close(() => r())) } })

interface Frame { path: string; bytes: Buffer }
interface Run { code: number; out: string; err: string; frames: Frame[]; ended: boolean; asked: number; fetched: Array<[string, number]> }
// The data channel as the broker reads it: header line, bytes, ..., {"end":true}.
function decodeFrames(all: Buffer): { frames: Frame[]; ended: boolean } {
  const frames: Frame[] = []
  let at = 0, ended = false
  while (at < all.length) {
    const nl = all.indexOf(0x0a, at)
    const h = JSON.parse(all.subarray(at, nl).toString('utf8')) as { path?: string; size?: number; end?: true }
    at = nl + 1
    if (h.end === true) { ended = true; continue }
    frames.push({ path: h.path as string, bytes: all.subarray(at, at + (h.size as number)) })
    at += h.size as number
  }
  return { frames, ended }
}
async function go(argv: string[], input: Uint8Array | string, o: Partial<DecryptDeps> & { idText?: string; published?: (r: number) => boolean } = {}): Promise<Run> {
  let out = '', err = '', asked = 0
  const sent: Buffer[] = []
  const fetcher = F.fakeFetcher(o.published ?? (() => true))
  const d: DecryptDeps = {
    network: 'local',
    input: async () => (typeof input === 'string' ? Buffer.from(input) : input),
    identity: () => o.idText ?? '',
    terminal: true,
    passphrase: async () => { asked++; return PASS },
    fetchRoundSignature: fetcher.fetch,
    send: async (b) => { sent.push(Buffer.from(b)) },
    close: async () => {},
    out: (t) => { out += t },
    err: (t) => { err += t },
    ...o,
  }
  const code = await runDecrypt(argv, d)
  return { code, out, err, asked, fetched: fetcher.calls, ...decodeFrames(Buffer.concat(sent)) }
}
const noSecrets = (r: Run, ...secrets: string[]): void => {
  for (const s of [PASS, ...secrets]) assert.ok(!r.out.includes(s) && !r.err.includes(s), 'no secret on stdout / stderr')
  assert.ok(!IPV4.test(r.out + r.err) && !(r.out + r.err).includes(CANARY), 'no address')
}

test('the shared constants and positions: PASTE_MAX is core\'s PASTE_LIMIT; data on fd 5; the handed files and the --out position', { timeout: 30_000 }, () => {
  assert.equal(PASTE_MAX, PASTE_LIMIT)
  assert.equal(DATA_FD, 5)
  const argv = ['decrypt', 'S.txt', '--identity', 'k.txt', '--out', 'o', '--only', 'x/y']
  assert.deepEqual(decryptPositions(argv), { handed: [1, 3], out: 5, input: 1, identity: 3 })
  assert.deepEqual(handedIndices(argv), [1, 3])
  assert.deepEqual(pathIndices(argv), [1, 3, 5])
  assert.deepEqual(handedIndices(['decrypt', '-', '--stdout']), [], 'stdin is no file')
  assert.deepEqual(handedIndices(['decrypt', '--out', 'o', '--list']), [], '--out is never handed to the sandbox')
})

test('passphrase (age scrypt, armored and binary): asked ONCE through the broker, after the input was read; the plaintext goes out as one frame; nothing secret printed', { timeout: 30_000 }, async () => {
  const bin = await F.passphraseBin('synthetic passphrase plaintext\n', PASS)
  for (const input of [bin, F.armor(bin)]) {
    const r = await go(['f.age', '--out', 'o'], input)
    assert.equal(r.code, 0); assert.equal(r.asked, 1); assert.equal(r.ended, true)
    assert.deepEqual(r.frames.map((f) => [f.path, f.bytes.toString()]), [['plaintext', 'synthetic passphrase plaintext\n']])
    assert.equal(r.out, '', 'nothing on stdout (stdout may be the plaintext sink)')
    assert.match(r.err, /opened with the passphrase/)
    noSecrets(r, 'synthetic passphrase plaintext')
  }
  // no terminal: refused before anything is asked
  await rejectsWith(() => go(['f.age', '--out', 'o'], bin, { terminal: false }), 'vt.tty-required')
  // a wrong passphrase: core's refusal, and nothing is sent
  await rejectsWith(() => go(['f.age', '--out', 'o'], bin, { passphrase: async () => 'not the synthetic passphrase' }), 'decrypt.passphrase')
})

test('identity (X25519, binary and armored) with --identity; without it the refusal says how; a wrong identity is decrypt.identity', { timeout: 30_000 }, async () => {
  const id = await F.newIdentity()
  const bin = await F.identityBin('synthetic identity plaintext\n', id.recipient)
  const idText = F.keygenFile(id.identity, id.recipient)
  for (const input of [bin, F.armor(bin)]) {
    const r = await go(['x.age', '--identity', 'k', '--stdout'], input, { idText })
    assert.equal(r.code, 0); assert.equal(r.asked, 0)
    assert.equal(r.frames[0].bytes.toString(), 'synthetic identity plaintext\n')
    noSecrets(r, id.identity, 'synthetic identity plaintext')
  }
  await assert.rejects(go(['x.age', '--stdout'], bin), (e: unknown) => (e as { guardId?: string }).guardId === 'decrypt.kind' && /--identity <file>/.test((e as Error).message))
  const other = await F.newIdentity()
  await rejectsWith(() => go(['x.age', '--identity', 'k', '--stdout'], bin, { idText: other.identity }), 'decrypt.identity')
})

test('timelocked (tlock): the round\'s signature through the relay fetcher; before the round decrypt.too-early and the relay is never asked', { timeout: 30_000 }, async () => {
  const bin = await F.tlockBin(F.PAST_ROUND, 'synthetic tlock plaintext\n')
  const r = await go(['t.age', '--out', 'o'], F.armor(bin))
  assert.equal(r.frames[0].bytes.toString(), 'synthetic tlock plaintext\n')
  assert.equal(r.fetched.length, 1); assert.equal(r.fetched[0][1], F.PAST_ROUND)
  assert.match(r.err, /through its time lock \(drand round 1000000/)
  const future = await F.tlockBin(F.FUTURE_ROUND, 'synthetic future plaintext\n')
  let fetched = 0
  await rejectsWith(() => go(['t.age', '--out', 'o'], future, { fetchRoundSignature: async () => { fetched++; return null } }), 'decrypt.too-early')
  assert.equal(fetched, 0)
  await rejectsWith(() => go(['t.age', '--out', 'o'], bin, { published: () => false }), 'decrypt.too-early')
})

const sha = (s: string | Uint8Array): string => createHash('sha256').update(s).digest('hex')
// A synthetic vault archive whose MANIFEST.csv / ATTACHMENTS.csv carry the digests the sealer would write.
function vault(o: { tamperItem?: boolean; tamperAttachment?: boolean; extraItem?: boolean; names?: string[] } = {}): Record<string, string> {
  const files: Record<string, string> = {
    'items/aaaa.json': '{"synthetic":"item one"}\n',
    'items/bbbb.json': '{"synthetic":"item two"}\n',
    'files/aaaa/ffff': 'synthetic attachment bytes\n',
  }
  const m = `item_id,sha256,field_count,section_count,file_count\naaaa,${sha(files['items/aaaa.json'])},1,0,1\nbbbb,${sha(files['items/bbbb.json'])},1,0,0\n`
  const a = `item_id,file_id,bytes,sha256\naaaa,ffff,${Buffer.byteLength(files['files/aaaa/ffff'])},${sha(files['files/aaaa/ffff'])}\n`
  if (o.tamperItem) files['items/bbbb.json'] = '{"synthetic":"item two, edited"}\n'
  if (o.tamperAttachment) files['files/aaaa/ffff'] = 'synthetic attachment bytes, edited\n'
  if (o.extraItem) files['items/cccc.json'] = '{"synthetic":"not in the manifest"}\n'
  for (const n of o.names ?? []) files[n] = `synthetic ${n.length}\n`
  return { ...files, 'MANIFEST.csv': m, 'ATTACHMENTS.csv': a }
}

test('SEALED.txt, full extraction (--out <dir>): every file of vault.tar.gz, checked against MANIFEST.csv and ATTACHMENTS.csv first; through its time lock and by the identity path', { timeout: 30_000 }, async () => {
  const files = vault()
  const s = await F.makeSealed({ vaultFiles: files })
  for (const [how, extra] of [['timelock', {}], ['identity', { idText: s.identity as string }]] as const) {
    const r = await go(how === 'identity' ? ['S.txt', '--identity', 'k', '--out', 'd'] : ['S.txt', '--out', 'd'], s.sealed, extra)
    assert.equal(r.code, 0)
    assert.deepEqual(Object.fromEntries(r.frames.map((f) => [f.path, f.bytes.toString()])), files, how)
    assert.match(r.err, /MANIFEST\.csv: 2 item\(s\) match; ATTACHMENTS\.csv: 1 attachment\(s\) match/)
    assert.equal(r.fetched.length, how === 'identity' ? 0 : 1)
    noSecrets(r, s.identity as string)
  }
  // published text, --stdout: the archive itself
  const p = await go(['P.txt', '--stdout'], s.published)
  assert.deepEqual(p.frames.map((f) => f.path), ['vault.tar.gz'])
  assert.deepEqual([...p.frames[0].bytes], [...s.tgz])
  // key-only: its one file (identity.key) and the note where the archive is; raw payload: content
  const k = await go(['K.txt', '--out', 'd'], (await F.makeSealed({ contents: 'key-only' })).sealed)
  assert.deepEqual(k.frames.map((f) => f.path), ['identity.key'])
  assert.match(k.err, /ar:\/\//)
  const raw = await go(['R.txt', '--out', 'd'], (await F.makeSealed({ kind: 'raw', payload: 'synthetic raw payload\n' })).sealed)
  assert.deepEqual(raw.frames.map((f) => [f.path, f.bytes.toString()]), [['content', 'synthetic raw payload\n']])
})

test('vt.manifest: an item or attachment that differs from its row, a file with no row, a malformed row — refused before ANY byte is sent', { timeout: 30_000 }, async () => {
  for (const o of [{ tamperItem: true }, { tamperAttachment: true }, { extraItem: true }]) {
    const s = await F.makeSealed({ vaultFiles: vault(o) })
    let sent = 0
    await rejectsWith(() => go(['S.txt', '--out', 'd'], s.sealed, { send: async () => { sent++ } }), 'vt.manifest')
    assert.equal(sent, 0, JSON.stringify(o))
  }
  const f = (path: string, body: string) => ({ path, size: Buffer.byteLength(body), bytes: Buffer.from(body) })
  throwsWith(() => verifyManifests([f('MANIFEST.csv', 'item_id,sha256\n../x,' + '0'.repeat(64) + '\n')]), 'vt.manifest')
  throwsWith(() => verifyManifests([f('MANIFEST.csv', 'no header\n')]), 'vt.manifest')
  throwsWith(() => verifyManifests([f('MANIFEST.csv', 'item_id,sha256\n'), f('files/a/b', 'x')]), 'vt.manifest')
  assert.deepEqual(verifyManifests([f('items/a.json', 'x')]), { items: null, attachments: null }, 'no manifest: nothing to check')
  const ok = verifyManifests([f('items/a.json', 'x'), f('MANIFEST.csv', `item_id,sha256,field_count,section_count,file_count\na,${sha('x')},0,0,0\n`)])
  assert.deepEqual(ok, { items: 1, attachments: null })
})

test('--list: path + size per file (no contents), on stdout; bidi / zero-width / control-looking names are escaped and survive the broker\'s filter; --only takes the shown path back', { timeout: 30_000 }, async () => {
  const odd = ['files/aaaa/r\u202eevil.txt', 'files/aaaa/zero\u200bwidth', 'files/aaaa/tab\u3164fill', 'files/aaaa/[U+0041]literal']
  const files = vault({ names: odd })
  const s = await F.makeSealed({ vaultFiles: files })
  const r = await go(['S.txt', '--identity', 'k', '--list'], s.sealed, { idText: s.identity as string })
  assert.equal(r.frames.length, 0); assert.equal(r.ended, false, 'no data channel output at all')
  for (const body of Object.values(files)) assert.ok(!r.out.includes(body.trim()), 'never a file\'s contents')
  assert.ok(r.out.includes('files/aaaa/r\\u{202e}evil.txt'), r.out)
  assert.ok(r.out.includes('zero\\u{200b}width'))
  assert.ok(r.out.includes('tab\\u{3164}fill'))
  assert.ok(r.out.includes('\\u{5b}U+0041\\u{5d}literal'), 'brackets are written out: nothing reads as an escape, and the filter has no bracket to rewrite')
  assert.ok(!/[\u202e\u200b\u3164]/.test(r.out))
  const filtered = new Sanitizer(false); assert.equal(filtered.push(r.out) + filtered.end(), r.out, 'the broker\'s output filter leaves the list intact')
  for (const n of odd) assert.equal(unlistName(listName(n)), n)
  const shown = listName(odd[0])
  const one = await go(['S.txt', '--identity', 'k', '--only', shown, '--out', 'o'], s.sealed, { idText: s.identity as string })
  assert.deepEqual(one.frames.map((f) => [f.path, f.bytes.toString()]), [[odd[0], files[odd[0]]]])
  const plain = await go(['S.txt', '--identity', 'k', '--only', 'items/bbbb.json', '--stdout'], s.sealed, { idText: s.identity as string })
  assert.equal(plain.frames[0].bytes.toString(), files['items/bbbb.json'])
  await rejectsWith(() => go(['S.txt', '--identity', 'k', '--only', 'items/none.json', '--stdout'], s.sealed, { idText: s.identity as string }), 'decrypt.format')
  // an input with no archive: --list / --only are usage errors
  await assert.rejects(go(['x.age', '--list'], await F.passphraseBin('synthetic\n', PASS)), UsageError)
  assert.equal(foldKey('A'), foldKey('a')); assert.equal(foldKey('caf\u00e9'), foldKey('cafe\u0301'))
})

// =============================== fix round 1 ===============================

test('fix1 M-1: --list escapes survive the broker\'s output filter exactly (UTF-8 and ASCII locales): bracketed non-ASCII names, NFC / NFD pairs, a tag lookalike, a backslash; --only takes them back', { timeout: 30_000 }, async () => {
  // core's strict reader refuses a backslash in a path, so those two are checked on the escaper alone
  const names = ['extra/[caf\u00e9]', 'extra/(caf\u00e9)', 'extra/x\u00e9.txt', 'extra/xe\u0301.txt', 'extra/[vt broker] y', 'extra/[U+0041]']
  const all = [...names, 'extra/back\\slash', 'extra/\\u{41}']
  const shown = all.map(listName)
  assert.equal(new Set(shown).size, all.length, 'distinct names stay distinct')
  for (const [i, n] of all.entries()) {
    assert.match(shown[i], /^[\x20-\x7e]*$/, 'printable ASCII only')
    for (const ascii of [false, true]) { const f = new Sanitizer(ascii); assert.equal(f.push(shown[i]) + f.end(), shown[i], `the filter leaves ${shown[i]} intact`) }
    assert.equal(unlistName(shown[i]), n)
  }
  const files = vault({ names })
  const s = await F.makeSealed({ vaultFiles: files })
  const l = await go(['S.txt', '--identity', 'k', '--list'], s.sealed, { idText: s.identity as string })
  for (const n of names) {
    assert.ok(l.out.includes(listName(n)), n)
    const one = await go(['S.txt', '--identity', 'k', '--only', listName(n), '--stdout'], s.sealed, { idText: s.identity as string })
    assert.equal(one.frames[0].path, n)
  }
})

test('fix1 M-5: the CLI escaper covers at least every code point core\'s showPath escapes (all of Unicode, pinned)', { timeout: 120_000 }, async () => {
  const { showPath } = await import('@vault-timelock/core/decrypt')
  let checked = 0
  for (let cp = 0; cp <= 0x10ffff; cp++) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue
    const ch = String.fromCodePoint(cp)
    if (showPath(ch) === ch) continue
    checked++
    assert.notEqual(listName(ch), ch, `U+${cp.toString(16)} is escaped by showPath but not by listName`)
    assert.equal(unlistName(listName(ch)), ch)
  }
  assert.ok(checked > 200, `showPath escapes ${checked} code points`)
})

test('fix1 I-2: a handed file the sandbox may not read is refused with its reason (vt.decrypt-input), never a bare EPERM', { timeout: 30_000 }, async () => {
  const eperm = (): never => { const e = new Error('EPERM: operation not permitted, open \'/x\'') as NodeJS.ErrnoException; e.code = 'EPERM'; throw e }
  await assert.rejects(go(['f.age', '--out', 'o'], '', { input: async () => eperm() }), (e: unknown) => {
    assert.equal((e as { guardId?: string }).guardId, 'vt.decrypt-input')
    assert.match((e as Error).message, /the input file/); assert.match((e as Error).message, /may not read/)
    return true
  })
  const bin = await F.identityBin('synthetic\n', (await F.newIdentity()).recipient)
  await assert.rejects(go(['x.age', '--identity', 'k', '--stdout'], bin, { identity: () => eperm() }), (e: unknown) => (e as { guardId?: string }).guardId === 'vt.decrypt-input' && /--identity/.test((e as Error).message))
})

test('fix1 M-3: the summary names the verified blocks and manifests, never a digest of the plaintext', { timeout: 30_000 }, async () => {
  const s = await F.makeSealed({ vaultFiles: vault() })
  const r = await go(['S.txt', '--out', 'd'], s.sealed)
  assert.match(r.err, /2 block\(s\) match their \[file\] lines/)
  for (const f of r.frames) assert.ok(!r.err.includes(sha(f.bytes)), 'no plaintext digest')
})

test('detectInput first: a non-age input is refused before any secret is asked or anything fetched; the paste cap applies to stdin', { timeout: 30_000 }, async () => {
  let asked = 0
  await rejectsWith(() => go(['-', '--out', 'o'], 'hello, not armor\n', { input: async () => Buffer.from('hello, not armor\n'), passphrase: async () => { asked++; return '' } }), 'decrypt.format')
  assert.equal(asked, 0)
  await rejectsWith(() => go(['--out', 'o'], '', { input: async () => Buffer.alloc(PASTE_LIMIT + 1, 0x41) }), 'decrypt.size')
})

// ---- the relay's drand route

async function server(handler: (path: string) => [number, string]): Promise<number> {
  const s = createServer((req, res) => { const [st, body] = handler(req.url ?? ''); res.writeHead(st, { 'content-type': 'application/json' }); res.end(body) })
  servers.push(s)
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', () => r()))
  return (s.address() as { port: number }).port
}
const HASH = '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971'

test('vt.relay-down: the relay fetcher — 200 beacon → the signature, 404 → null (too early); a closed port, another status, a wrong round or a malformed body refuse, naming no address', { timeout: 30_000 }, async () => {
  const sig = 'ab'.repeat(48)
  let seen = ''
  const port = await server((p) => {
    seen = p
    if (p.endsWith('/7')) return [200, JSON.stringify({ round: 7, randomness: sha(Buffer.from(sig, 'hex')), signature: sig })]
    if (p.endsWith('/8')) return [404, '{"error":{"message":"this drand round is not published yet"}}']
    if (p.endsWith('/9')) return [503, '{}']
    if (p.endsWith('/10')) return [200, JSON.stringify({ round: 11, signature: sig })]
    return [200, 'not json']
  })
  const f = relayFetcher({ network: 'local', port })
  assert.equal(await f(HASH, 7), sig)
  assert.equal(seen, `/relay/drand/${HASH}/public/7`)
  assert.equal(await f(HASH, 8), null)
  for (const round of [9, 10, 12]) await rejectsWith(() => f(HASH, round), 'vt.relay-down')
  // nothing listens: vt up is needed (a port that was just closed)
  const s = createServer(); await new Promise<void>((r) => s.listen(0, '127.0.0.1', () => r()))
  const closed = (s.address() as { port: number }).port
  await new Promise<void>((r) => s.close(() => r()))
  const down = relayFetcher({ network: 'testnet', port: closed })
  await assert.rejects(down(HASH, 7), (e: unknown) => {
    assert.equal((e as { guardId?: string }).guardId, 'vt.relay-down')
    assert.match((e as Error).message, /vt up --network testnet/)
    assert.ok(!IPV4.test((e as Error).message), 'no address in the message')
    return true
  })
  // and through runDecrypt: the fetcher's refusal passes through core unchanged
  const bin = await F.tlockBin(F.PAST_ROUND, 'synthetic tlock plaintext\n')
  await rejectsWith(() => go(['t.age', '--out', 'o'], bin, { fetchRoundSignature: down }), 'vt.relay-down')
})

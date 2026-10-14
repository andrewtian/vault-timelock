import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, symlinkSync, unlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { buildSealed, parseAgeHeader, parseTlockStanza } from '../../src/sealed.ts'
import { armor } from '../../src/armor.ts'
import { QUICKNET } from '../../src/drand.ts'
import { Refusal } from '../../src/guard.ts'
import { AR, CHAIN_INFO, HASH, NOW, ROUND, UNLOCK, fill, makePkg, pem, tlockFile, x25519File } from './fixtures.ts'
import type { Kind } from './fixtures.ts'

const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex')
// Independent armor for goldens (no use of src/armor.ts).
const arm = (b: Buffer) => `-----BEGIN AGE ENCRYPTED FILE-----\n${b.toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END AGE ENCRYPTED FILE-----\n`
const blk = (n: string, b: Buffer) => `[file ${n} bytes=${b.length} sha256=${sha(b)}]\n${arm(b)}`

function refused(f: () => unknown, id: string) {
  assert.throws(f, (e: unknown) => e instanceof Refusal && e.guardId === id, `expected ${id}`)
}

// ---- the expected self-contained text (Task S2 §5), written out here independently of src ----
const GEN_ISO = '2023-08-23T15:09:27Z'
const CUT = `awk '/^\\[file [A-Za-z0-9][A-Za-z0-9._-]* bytes=[0-9]+ sha256=[0-9a-f]+\\]$/ { f = $2; next } f != "" && /^-----BEGIN AGE ENCRYPTED FILE-----$/ { w = 1 } w { print > f } /^-----END AGE ENCRYPTED FILE-----$/ { if (w) close(f); w = 0; f = "" }' SEALED.txt`
const CHECK = `sed -n 's/^\\[file \\([A-Za-z0-9][A-Za-z0-9._-]*\\) bytes=\\([0-9]*\\) sha256=\\([0-9a-f]*\\)\\]$/\\1 \\2 \\3/p' SEALED.txt | while read -r n b s; do [ "$(sed '1d;$d' "$n" | base64 -d | wc -c | tr -d ' ') $(sed '1d;$d' "$n" | base64 -d | shasum -a 256 | cut -c1-64)" = "$b $s" ] && echo "OK $n" || { echo "BAD $n"; exit 1; }; done`
const MF = `(cd restored && { tail -n +2 MANIFEST.csv | awk -F, '{ print $2 "  items/" $1 ".json" }'; [ ! -f ATTACHMENTS.csv ] || tail -n +2 ATTACHMENTS.csv | awk -F, '{ print $4 "  files/" $1 "/" $2 }'; } | shasum -a 256 -c)`
const TLE_STEP = (n: number, out: string, inFile: string) => [
  `  ${n}. recover ${out} with drand's signature for round ${ROUND}, through Tor (SOCKS on`,
  '     127.0.0.1:9050; without Tor, drop the env prefix and drand sees your IP ask for this round).',
  `     If it fails (too early, or a network error), delete the empty ${out} it leaves, then retry;`,
  '     if api.drand.sh is gone, add --network=https://api2.drand.sh (or https://api3.drand.sh):',
  `     $ env -u NO_PROXY -u no_proxy HTTPS_PROXY=socks5h://127.0.0.1:9050 tle --decrypt --output=${out} ${inFile}`,
]
const EXTRACT = (n: number, tgz: string) => [`  ${n}. extract it into a new directory:`, `     $ mkdir restored && tar -xzf ${tgz} -C restored`]
const TL = (f: string, inner: string) => `  - ${f}: ${inner}, tlock-encrypted to drand round ${ROUND} (one "-> tlock ${ROUND} 52db9ba7..." age stanza)`
const SHAPE: Record<string, { what: string[]; layers: string[]; two: boolean; steps: string[] }> = {
  'two-layer': {
    what: ['an archive (vault.tar.gz) encrypted with age to a one-time key; that key is time-locked',
      'to a drand round with tlock. Once drand publishes the round, anyone holding this text can',
      'open it; the notes say what keeps it shut until then.'],
    layers: [TL('unlock-TIME.age', 'the one-time key, one AGE-SECRET-KEY-1... line'),
      '  - vault.tar.gz.age: the archive (tar.gz), age-encrypted to that key (one "-> X25519" stanza)'],
    two: true,
    steps: [...TLE_STEP(3, 'identity.key', UL_NAME()), '  4. open the archive with that key:',
      '     $ age -d -i identity.key -o vault.tar.gz vault.tar.gz.age', ...EXTRACT(5, 'vault.tar.gz'),
      '  6. check every item and attachment against the manifests sealed inside; every line must end in OK:', `     $ ${MF}`],
  },
  'one-layer': {
    what: ['an archive (vault.tar.gz) time-locked to a drand round with tlock. Once drand publishes',
      'the round, anyone holding this text can open it; the notes say what keeps it shut until then.'],
    layers: [TL('vault.tar.gz.age', 'the archive (tar.gz)')], two: false,
    steps: [...TLE_STEP(3, 'vault.tar.gz', 'vault.tar.gz.age'), ...EXTRACT(4, 'vault.tar.gz')],
  },
  secret: {
    what: ['a file or directory (secret.tar.gz) time-locked to a drand round with tlock. Once drand',
      'publishes the round, anyone holding this text can open it; the notes say what keeps it shut.'],
    layers: [TL('secret.tar.gz.age', 'the file or directory as a tar.gz')], two: false,
    steps: [...TLE_STEP(3, 'secret.tar.gz', 'secret.tar.gz.age'), ...EXTRACT(4, 'secret.tar.gz')],
  },
  raw: {
    what: ['bytes time-locked to a drand round with tlock. Once drand publishes the round, anyone',
      'holding this text can open it; the notes say what keeps it shut until then.'],
    layers: [TL('payload.age', 'the bytes exactly as sealed (no archive)')], two: false,
    steps: [...TLE_STEP(3, 'content', 'payload.age')],
  },
  'tar+gzip': {
    what: ['an archive (content.tar.gz) time-locked to a drand round with tlock. Once drand publishes',
      'the round, anyone holding this text can open it; the notes say what keeps it shut until then.'],
    layers: [TL('payload.age', 'the archive (tar.gz)')], two: false,
    steps: [...TLE_STEP(3, 'content.tar.gz', 'payload.age'), ...EXTRACT(4, 'content.tar.gz')],
  },
}
function UL_NAME() { return 'unlock-TIME.age' }
const NOTES = [
  'notes:',
  "  - after unlock-after, ANYONE holding this text can open it: the round's signature is public and",
  '    tlock has no recipient. That is the design, not a leak.',
  "  - before then it stays shut only while fewer than a threshold t of drand quicknet's key shares",
  '    are combined (t of n is set by the League of Entropy and changes at reshares; shares from',
  '    before a reshare count). t or more shares, pooled by colluding operators or by whoever steals',
  '    or compels them, yield the signature at any time, without trace. It also rests on',
  "    BLS12-381's pairing assumptions, which are not post-quantum: a large quantum computer would",
  '    open every copy kept or published now.',
  '  - nothing here is signed: anyone can build a package like this for any round, or re-post this',
  '    one with other notes. The sha256 values detect damage in transit, not forgery.',
  '  - if drand quicknet stops before the round, this cannot be opened.',
]
// head(kind, contents): everything before the first [file ...] line; key-only adds the 1b fetch
// step for the two-layer shape (the payload is not in the text)
const head = (kind: Kind, contents: string) => {
  const sh = SHAPE[kind]
  const keyOnly = contents.startsWith('contents: key-only') && kind === 'two-layer'
  return [
    '== vault-timelock sealed package: self-contained, age + drand timelock ==',
    'format: vault-timelock-sealed/1',
    `what-this-is: ${sh.what[0]}`, ...sh.what.slice(1).map((w) => `  ${w}`),
    'layers:', ...sh.layers,
    `unlock-after: ${UNLOCK}  (drand round ${ROUND})`,
    `  round time = genesis + (round - 1) * period; quicknet genesis 1692803367 (${GEN_ISO}), period 3 s`,
    `drand: quicknet ${HASH}  scheme bls-unchained-g1-rfc9380`,
    `drand-signature: https://api.drand.sh/${HASH}/public/${ROUND}`,
    `  mirrors: https://api2.drand.sh/${HASH}/public/${ROUND} https://api3.drand.sh/${HASH}/public/${ROUND}`,
    sh.two ? 'tools: tle v1.2.0 https://github.com/drand/tlock | age v1.3.1 https://age-encryption.org' : 'tools: tle v1.2.0 https://github.com/drand/tlock',
    `  install: go install github.com/drand/tlock/cmd/tle@v1.2.0${sh.two ? '; age: https://github.com/FiloSottile/age/releases (or: brew install age; apt install age)' : ''}`,
    contents,
    'open after unlock-after (POSIX sh; type each line that starts with "$ ", without the "$ "):',
    '  1. save this whole text as SEALED.txt in an empty directory, cd there, and cut out each',
    '     block below into the file named in its [file ...] line:',
    `     $ ${CUT}`,
    ...(keyOnly ? [`  1b. fetch ar://${AR} (a tar bundle; any Arweave gateway, e.g. https://arweave.net/${AR},`,
      '     through Tor) and extract vault.tar.gz.age from it into this directory'] : []),
    "  2. check each block's size and SHA-256 (of the decoded bytes) against its [file ...] line;",
    '     it prints OK for every file:',
    `     $ ${CHECK}`,
    ...sh.steps,
    ...NOTES,
    '',
  ].join('\n')
}

const full = { contents: 'full' as const, now: NOW }
const key = { contents: 'key-only' as const, arId: AR, now: NOW }
const UL = 'unlock-TIME.age'
const KINDS: Kind[] = ['two-layer', 'one-layer', 'secret', 'raw', 'tar+gzip']
const ageNames = (kind: Kind) => kind === 'two-layer' ? [UL, 'vault.tar.gz.age']
  : kind === 'one-layer' ? ['vault.tar.gz.age'] : kind === 'secret' ? ['secret.tar.gz.age'] : ['payload.age']


test('golden: two-layer full', () => {
  const { dir, files } = makePkg('two-layer')
  const want = head('two-layer', 'contents: full') + blk(UL, files[UL]) + blk('vault.tar.gz.age', files['vault.tar.gz.age']) + '== end ==\n'
  assert.equal(buildSealed(dir, full), want)
})

test('golden: two-layer key-only (tlock file only, ar pointer, 1b fetch step)', () => {
  const { dir, files } = makePkg('two-layer')
  const want = head('two-layer', `contents: key-only (payload: ar://${AR})`) + blk(UL, files[UL]) + '== end ==\n'
  assert.equal(buildSealed(dir, key), want)
})

for (const x of ['vault', 'secret'] as const) {
  test(`golden: one-layer ${x} full and key-only`, () => {
    const kind = x === 'vault' ? 'one-layer' : 'secret'
    const { dir, files } = makePkg(kind)
    const b = blk(`${x}.tar.gz.age`, files[`${x}.tar.gz.age`])
    assert.equal(buildSealed(dir, full), head(kind, 'contents: full') + b + '== end ==\n')
    assert.equal(buildSealed(dir, key), head(kind, `contents: key-only (payload: ar://${AR})`) + b + '== end ==\n')
  })
}

test('golden: content raw and tar+gzip, full and key-only', () => {
  for (const enc of ['raw', 'tar+gzip'] as const) {
    const { dir, files } = makePkg(enc)
    const b = blk('payload.age', files['payload.age'])
    assert.equal(buildSealed(dir, full), head(enc, 'contents: full') + b + '== end ==\n')
    assert.equal(buildSealed(dir, key), head(enc, `contents: key-only (payload: ar://${AR})`) + b + '== end ==\n')
  }
})

test('exact header lines, pure ASCII, no trailing whitespace, \\n only', () => {
  const t = buildSealed(makePkg('two-layer').dir, full)
  const lines = t.split('\n')
  assert.equal(lines[0], '== vault-timelock sealed package: self-contained, age + drand timelock ==')
  assert.equal(lines[1], 'format: vault-timelock-sealed/1')
  assert.ok(lines[2].startsWith('what-this-is: '))
  const at = (re: RegExp) => lines.findIndex((l) => re.test(l))
  assert.match(lines[at(/^unlock-after: /)], /^unlock-after: \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ  \(drand round 500000000\)$/)
  assert.equal(lines[at(/^drand: /)], `drand: quicknet ${HASH}  scheme bls-unchained-g1-rfc9380`)
  assert.equal(lines[at(/^contents: /)], 'contents: full')
  assert.ok(at(/^layers:$/) < at(/^unlock-after: /) && at(/^unlock-after: /) < at(/^tools: /) && at(/^tools: /) < at(/^open after unlock-after /) && at(/^open after unlock-after /) < at(/^notes:$/) && at(/^notes:$/) < at(/^\[file /))
  assert.equal(lines[lines.length - 2], '== end ==')
  assert.equal(lines[lines.length - 1], '')
  assert.ok(!/[ \t]$/m.test(t.replace(/^drand:.*$/m, '')))
  assert.ok(!t.includes('\r'))
  const nonAscii = [...t].filter((c) => c.charCodeAt(0) > 126)
  assert.deepEqual(nonAscii, [])
  assert.ok(lines.some((l) => /^\[file unlock-TIME\.age bytes=\d+ sha256=[0-9a-f]{64}\]$/.test(l)))
})

// ---- Task S2 §5: self-contained, and its printed steps work exactly as printed ------------------
// cmds(text): the literal commands, in order, from every line that starts with "     $ "
const cmds = (t: string) => t.split('\n').filter((l) => l.startsWith('     $ ')).map((l) => l.slice(7))
const shRun = (dir: string, cmd: string) => spawnSync('/bin/sh', ['-c', cmd], { cwd: dir, encoding: 'utf8' })

test('S2: steps 1 and 2 run exactly as printed (every kind): the blocks are cut out byte-exact and verified OK', () => {
  for (const kind of KINDS) {
    const p = makePkg(kind)
    const t = buildSealed(p.dir, full)
    const w = mkdtempSync(join(tmpdir(), 'vt-literal-'))
    try {
      // the published text: header, note and a blank line before SEALED.txt (B §5.0) do not disturb the cut
      writeFileSync(join(w, 'SEALED.txt'), `vault-timelock/1 unlock=${UNLOCK}\nar://${AR}\nnote [file x bytes=1 sha256=0]\n\n${t}`)
      const [cut, check] = cmds(t)
      assert.equal(shRun(w, cut).status, 0, `${kind} cut`)
      for (const n of ageNames(kind)) assert.equal(readFileSync(join(w, n), 'latin1'), pem(p.files[n]), `${kind} ${n} cut out as its armor block`)
      const r = shRun(w, check)
      assert.equal(r.status, 0, `${kind} check: ${r.stdout}${r.stderr}`)
      assert.deepEqual(r.stdout.trim().split('\n').sort(), ageNames(kind).map((n) => `OK ${n}`).sort())
      // negative control: one changed base64 character in a block -> BAD and exit 1
      const n0 = ageNames(kind)[0]
      const f = readFileSync(join(w, n0), 'latin1').split('\n')
      f[1] = (f[1][0] === 'A' ? 'B' : 'A') + f[1].slice(1)
      writeFileSync(join(w, n0), f.join('\n'), 'latin1')
      const bad = shRun(w, check)
      assert.notEqual(bad.status, 0, `${kind} tampered block passed`)
      assert.match(bad.stdout, new RegExp(`BAD ${n0.replace('.', '\\.')}`))
    } finally { rmSync(w, { recursive: true, force: true }) }
  }
})

test('S2: the open steps are literal commands: tle through Tor with the empty-output note, the pinned tools, no placeholders', () => {
  const t = buildSealed(makePkg('two-layer').dir, full)
  const c = cmds(t)
  assert.deepEqual(c.slice(2), [
    `env -u NO_PROXY -u no_proxy HTTPS_PROXY=socks5h://127.0.0.1:9050 tle --decrypt --output=identity.key ${UL}`,
    'age -d -i identity.key -o vault.tar.gz vault.tar.gz.age',
    'mkdir restored && tar -xzf vault.tar.gz -C restored',
    MF,
  ])
  assert.ok(t.includes('delete the empty identity.key it leaves, then retry'))
  for (const l of c) assert.ok(!/[<>]|\.\.\.|DURATION|ROUND/.test(l.replace(/ > f /, ' ')), `placeholder in: ${l}`)
  assert.ok(t.includes('\ntools: tle v1.2.0 https://github.com/drand/tlock | age v1.3.1 https://age-encryption.org\n'))
  assert.ok(t.includes('\n  install: go install github.com/drand/tlock/cmd/tle@v1.2.0;'))
})

test('S2: R44/R45/E6 in the text: no MANIFEST or README content, no unlock-KEY, no requested duration or random offset', () => {
  for (const kind of KINDS) {
    for (const c of [full, key]) {
      const t = buildSealed(makePkg(kind, { withKey: kind === 'two-layer', extra: { 'MANIFEST.csv': 'item_id,sha256\n', 'README.txt': 'readme\n' } }).dir, c)
      assert.ok(!t.includes('[file MANIFEST') && !t.includes('README') && !t.includes('unlock-KEY'), kind)
      assert.ok(!/requested|offset|jitter/i.test(t), `${kind}: the text must not date the seal (E6)`)
    }
  }
})

// Task S3: 1password-timelock.sh writes STRUCTURE.txt (the vault's shape, every value removed) into the
// package beside SEALED.txt. It is LOCAL ONLY (R44 class): the text is built from the package's .age
// files, chain-info.json and round alone, so STRUCTURE.txt never reaches it.
const STRUCT_CANARY = 'ZZCANARYS3STRUCTURE'
const STRUCTURE = '== vault-timelock structure: shape only, every value removed (LOCAL ONLY, never published) ==\n' +
  `format: vault-timelock-structure/1\nitem 1  LOGIN  items/${STRUCT_CANARY.toLowerCase()}.json\n  title          <set> ${STRUCT_CANARY}\n== end ==\n`
test('S3: STRUCTURE.txt is never published: SEALED.txt is byte-identical with and without it, never carries it, and never reads it (every kind, full and key-only)', () => {
  for (const kind of KINDS) {
    for (const c of [full, key]) {
      const plain = buildSealed(makePkg(kind).dir, c)
      const p = makePkg(kind, { extra: { 'STRUCTURE.txt': STRUCTURE } })
      const t = buildSealed(p.dir, c)
      assert.equal(t, plain, `${kind}: a STRUCTURE.txt beside the package changed SEALED.txt`)
      assert.ok(!t.includes(STRUCT_CANARY) && !t.toLowerCase().includes(STRUCT_CANARY.toLowerCase()), `${kind}: the canary reached SEALED.txt`)
      assert.ok(!t.includes('STRUCTURE') && !t.includes('vault-timelock-structure'), `${kind}: SEALED.txt names STRUCTURE.txt`)
      // not even read: an unreadable STRUCTURE.txt changes nothing
      chmodSync(join(p.dir, 'STRUCTURE.txt'), 0o000)
      assert.equal(buildSealed(p.dir, c), plain, `${kind}: SEALED.txt depends on reading STRUCTURE.txt`)
      chmodSync(join(p.dir, 'STRUCTURE.txt'), 0o600)
    }
  }
})

// Task SP (R74): `1password-timelock.sh open --plaintext` writes SEALED-plaintext.txt (every entry decrypted,
// LOCAL ONLY) into the package beside SEALED.txt, after the unlock time. The text is built from the
// package's .age files, chain-info.json and round alone, so SEALED-plaintext.txt never reaches it.
const PLAIN_CANARY = 'ZZCANARYSPPLAINTEXT'
const PLAINTEXT = '== vault-timelock plaintext: every entry, decrypted (LOCAL ONLY — contains secrets) ==\n' +
  `format: vault-timelock-plaintext/1\n\n[item 1] LOGIN  ${PLAIN_CANARY} title\n  password : s3cr3t-${PLAIN_CANARY}\n\n== end (1 items, 0 files) ==\n`
test('SP: SEALED-plaintext.txt is never published: SEALED.txt is byte-identical with and without it, never carries it, and never reads it (every kind, full and key-only)', () => {
  for (const kind of KINDS) {
    for (const c of [full, key]) {
      const plain = buildSealed(makePkg(kind).dir, c)
      const p = makePkg(kind, { extra: { 'SEALED-plaintext.txt': PLAINTEXT } })
      const t = buildSealed(p.dir, c)
      assert.equal(t, plain, `${kind}: a SEALED-plaintext.txt beside the package changed SEALED.txt`)
      assert.ok(!t.includes(PLAIN_CANARY) && !t.includes('s3cr3t-'), `${kind}: the canary reached SEALED.txt`)
      assert.ok(!t.includes('SEALED-plaintext') && !t.includes('vault-timelock-plaintext'), `${kind}: SEALED.txt names SEALED-plaintext.txt`)
      // not even read: an unreadable SEALED-plaintext.txt changes nothing
      chmodSync(join(p.dir, 'SEALED-plaintext.txt'), 0o000)
      assert.equal(buildSealed(p.dir, c), plain, `${kind}: SEALED.txt depends on reading SEALED-plaintext.txt`)
      chmodSync(join(p.dir, 'SEALED-plaintext.txt'), 0o600)
    }
  }
})

test('S2: the notes carry the threshold, the post-quantum caveat and "not signed", and no absolute claim', () => {
  const t = buildSealed(makePkg('secret').dir, full)
  for (const want of ['ANYONE holding this text can open it', 'threshold t of drand quicknet', 'shares from\n    before a reshare count', 'not post-quantum', 'nothing here is signed']) assert.ok(t.includes(want), want)
  assert.ok(!/nobody|not even|cannot be opened (early|before)|no one can/i.test(t))
})

test('unlock-after = genesis + (round-1) * period', () => {
  const { dir } = makePkg('one-layer')
  assert.ok(buildSealed(dir, full).includes(`unlock-after: ${UNLOCK}  (drand round ${ROUND})`))
  assert.equal(UNLOCK, new Date((1692803367 + (ROUND - 1) * 3) * 1000).toISOString().replace('.000Z', 'Z'))
})

test('stanza round differs from round file -> sealed.stanza', () => {
  refused(() => buildSealed(makePkg('two-layer', { stanzaRound: ROUND + 1 }).dir, full), 'sealed.stanza')
  refused(() => buildSealed(makePkg('one-layer', { round: ROUND + 1 }).dir, full), 'sealed.stanza')
})

test('chain hash mismatch -> sealed.stanza', () => {
  refused(() => buildSealed(makePkg('two-layer', { stanzaHash: '0'.repeat(64) }).dir, full), 'sealed.stanza')
})

test('malformed headers -> sealed.stanza', () => {
  const bad = (b: Buffer) => {
    const { dir } = makePkg('one-layer')
    writeFileSync(join(dir, 'vault.tar.gz.age'), b)
    refused(() => buildSealed(dir, full), 'sealed.stanza')
  }
  const good = tlockFile()
  bad(Buffer.from(good.toString('latin1').replace('age-encryption.org/v1', 'age-encryption.org/v2'), 'latin1'))
  bad(Buffer.from(good.toString('latin1').replace('-> tlock', '-> X25519'), 'latin1'))
  bad(Buffer.from(good.toString('latin1').replace(`${ROUND} ${HASH}`, `${ROUND}`), 'latin1'))
  bad(Buffer.from(good.toString('latin1').replace('\n--- ', '\n-- '), 'latin1'))
  bad(Buffer.from(good.toString('latin1').replace('\n--- ', '\n-> tlock 1 ' + HASH + '\nAAAA\n--- '), 'latin1'))
  bad(Buffer.from('not an age file'))
})

test('parseTlockStanza', () => {
  assert.deepEqual(parseTlockStanza(tlockFile()), { round: String(ROUND), hash: HASH })
  assert.equal(parseTlockStanza(new Uint8Array(0)), null)
})

test('unknown layouts -> sealed.format', () => {
  refused(() => buildSealed(makePkg('two-layer', { extra: { 'other.age': 'x' } }).dir, full), 'sealed.format')
  refused(() => buildSealed(makePkg('one-layer', { extra: { 'secret.tar.gz.age': 'x' } }).dir, full), 'sealed.format')
  refused(() => buildSealed(makePkg('raw', { extra: { 'vault.tar.gz.age': 'x' } }).dir, full), 'sealed.format')
  refused(() => buildSealed(makePkg('raw', { extra: { encoding: 'tar' } }).dir, full), 'sealed.format')
  refused(() => buildSealed(makePkg('raw', { extra: { encoding: 'raw ' } }).dir, full), 'sealed.format')
  const e = mkdtempSync(join(tmpdir(), 'vt-empty-'))
  refused(() => buildSealed(e, full), 'sealed.format')
  refused(() => buildSealed(join(e, 'nope'), full), 'sealed.format')
  const p = makePkg('two-layer')
  unlinkSync(join(p.dir, UL))
  refused(() => buildSealed(p.dir, full), 'sealed.stanza')
  rmSync(e, { recursive: true })
})

test('missing / non-regular package files -> sealed.file', () => {
  const p = makePkg('one-layer')
  unlinkSync(join(p.dir, 'round'))
  refused(() => buildSealed(p.dir, full), 'sealed.file')
  const q = makePkg('one-layer')
  unlinkSync(join(q.dir, 'chain-info.json'))
  symlinkSync('/etc/hosts', join(q.dir, 'chain-info.json'))
  refused(() => buildSealed(q.dir, full), 'sealed.file')
})

test('bad chain-info.json / round -> sealed.chain-info / sealed.round', () => {
  for (const content of ['{', '{}', JSON.stringify({ hash: 'zz', genesis_time: 1, period: 3, schemeID: 'x' }), JSON.stringify({ hash: HASH, genesis_time: 1, period: 0, schemeID: 'x' }), JSON.stringify({ hash: HASH, genesis_time: 1, period: 3, schemeID: 'a b' })]) {
    const { dir } = makePkg('one-layer')
    writeFileSync(join(dir, 'chain-info.json'), content)
    refused(() => buildSealed(dir, full), 'sealed.chain-info')
  }
  for (const r of ['0', '-1', 'abc', '', '1.5', '01']) {
    const { dir } = makePkg('one-layer')
    writeFileSync(join(dir, 'round'), r)
    refused(() => buildSealed(dir, full), 'sealed.round')
  }
})

test('already-open -> sealed.already-open (boundary exact)', () => {
  const { dir } = makePkg('two-layer')
  const unlockSec = 1692803367 + (ROUND - 1) * 3
  // round == current round: open, refuse
  refused(() => buildSealed(dir, { contents: 'full', now: unlockSec }), 'sealed.already-open')
  refused(() => buildSealed(dir, { contents: 'full', now: unlockSec + 100 }), 'sealed.already-open')
  // one second before: still locked
  assert.ok(buildSealed(dir, { contents: 'full', now: unlockSec - 1 }).startsWith('== vault-timelock sealed package: '))
  // a real clock: far future round is locked
  assert.ok(buildSealed(dir, { contents: 'full' }).startsWith('== vault-timelock sealed package: '))
})

test('key-only without a valid arId -> sealed.key-only-needs-ar', () => {
  const { dir } = makePkg('two-layer')
  refused(() => buildSealed(dir, { contents: 'key-only', now: NOW }), 'sealed.key-only-needs-ar')
  refused(() => buildSealed(dir, { contents: 'key-only', arId: 'short', now: NOW }), 'sealed.key-only-needs-ar')
})

test('tampered block (test seam) -> sealed.selfcheck', () => {
  const { dir } = makePkg('two-layer')
  refused(() => buildSealed(dir, { ...full, _armor: (b) => { const c = Uint8Array.from(b); c[c.length - 1] ^= 1; return armor(c) } }), 'sealed.selfcheck')
  refused(() => buildSealed(dir, { ...full, _armor: () => 'garbage' }), 'sealed.selfcheck')
})

test('output stable and reads only regular files', () => {
  const { dir } = makePkg('two-layer')
  assert.equal(buildSealed(dir, full), buildSealed(dir, full))
})

test('R32: sealed text is pure ASCII; non-ASCII output -> sealed.non-ascii', () => {
  const { dir } = makePkg('two-layer')
  const t = buildSealed(dir, full)
  assert.ok(/^[\x00-\x7f]*$/.test(t))
  assert.ok(t.includes('tools: tle v1.2.0 https://github.com/drand/tlock | age v1.3.1 https://age-encryption.org\n'))
  refused(() => buildSealed(dir, { ...full, _armor: (b) => armor(b) + '\u00b7\n' }), 'sealed.non-ascii')
})


// ---- Task S1 §3: armored packages, unlock-KEY.age (R45), sealed.not-age, the quicknet pin ----------


test('S1: an armored package gives a byte-identical SEALED.txt to the binary one (every kind, full and key-only)', () => {
  for (const kind of KINDS) {
    const bin = makePkg(kind)
    const arm = makePkg(kind, { armor: true })
    for (const n of ageNames(kind)) {
      const t = readFileSync(join(arm.dir, n), 'latin1')
      assert.ok(t.startsWith('-----BEGIN AGE ENCRYPTED FILE-----\n'), `${kind} ${n} is armored on disk`)
      assert.equal(t, pem(bin.files[n]))
    }
    assert.equal(buildSealed(arm.dir, full), buildSealed(bin.dir, full), `${kind} full`)
    assert.equal(buildSealed(arm.dir, key), buildSealed(bin.dir, key), `${kind} key-only`)
  }
  // a package with only SOME files armored is the same package
  const mixed = makePkg('two-layer', { armor: [UL] })
  assert.equal(buildSealed(mixed.dir, full), buildSealed(makePkg('two-layer').dir, full))
})

test('S1: the armored package uses the DECODED binary in the [file] line and the block (golden)', () => {
  const { dir, files } = makePkg('two-layer', { armor: true })
  const want = head('two-layer', 'contents: full') + blk(UL, files[UL]) + blk('vault.tar.gz.age', files['vault.tar.gz.age']) + '== end ==\n'
  assert.equal(buildSealed(dir, full), want)
})

// Re-wrap an armor text's base64 body at `w` columns (the canonical width is 64).
const rewrap = (t: string, w: number) => {
  const lines = t.split('\n')
  const b64 = lines.slice(1, -2).join('')
  return `${lines[0]}\n${b64.match(new RegExp(`.{1,${w}}`, 'g'))!.join('\n')}\n${lines[lines.length - 2]}\n`
}

test('S1: non-canonical armor -> sealed.armor-noncanonical', () => {
  const bad = (mutate: (t: string) => string, kind: Kind = 'two-layer', name = UL, contents = full) => {
    const p = makePkg(kind, { armor: true })
    const f = join(p.dir, name)
    const before = readFileSync(f, 'latin1')
    const after = mutate(before)
    assert.notEqual(after, before, 'the mutation must change the file')
    writeFileSync(f, after, 'latin1')
    refused(() => buildSealed(p.dir, contents), 'sealed.armor-noncanonical')
  }
  bad((t) => t.replace(/\n/g, '\r\n'))                                  // CRLF
  bad((t) => t + 'junk\n')                                              // trailing junk after the footer
  bad((t) => t.slice(0, -1))                                            // no final newline
  bad((t) => rewrap(t, 76))                                             // wrong line length
  bad((t) => rewrap(t, 48))
  bad((t) => t.replace(/\n([A-Za-z0-9+/])/, '\n*'))                     // a character outside base64
  bad((t) => t.replace(/=+\n-----END/, '\n-----END'))                   // padding stripped
  bad((t) => t.replace('-----END AGE ENCRYPTED FILE-----', '-----END AGE FILE-----'))
  bad((t) => t.replace('\n-----END', '\n\n-----END'))                   // a blank line in the body
  bad((t) => rewrap(t, 76), 'two-layer', 'vault.tar.gz.age')            // the non-tlock file too
})

test('S1: non-canonical armor is refused in every kind and on the non-tlock file, key-only too', () => {
  for (const kind of KINDS) {
    for (const n of ageNames(kind)) {
      const p = makePkg(kind, { armor: true })
      writeFileSync(join(p.dir, n), rewrap(readFileSync(join(p.dir, n), 'latin1'), 76), 'latin1')
      refused(() => buildSealed(p.dir, full), 'sealed.armor-noncanonical')
      refused(() => buildSealed(p.dir, key), 'sealed.armor-noncanonical')
    }
  }
})

test('S1: the ARMOR marker is ignored by the shape detection', () => {
  for (const kind of KINDS) {
    const a = makePkg(kind, { extra: { ARMOR: 'pem\n' } })
    assert.equal(buildSealed(a.dir, full), buildSealed(makePkg(kind).dir, full), kind)
    assert.equal(buildSealed(a.dir, key), buildSealed(makePkg(kind).dir, key), kind)
  }
})

test('R45: unlock-KEY.age is ignored and never emitted (same SEALED.txt with and without it)', () => {
  const plain = makePkg('two-layer')
  for (const o of [{}, { armor: true }]) {
    const k = makePkg('two-layer', { withKey: true, ...o })
    assert.ok(existsSync(join(k.dir, 'unlock-KEY.age')))
    for (const c of [full, key]) {
      const t = buildSealed(k.dir, c)
      assert.equal(t, buildSealed(plain.dir, c))
      assert.ok(!t.includes('unlock-KEY'))
    }
  }
  // two-layer is keyed on unlock-TIME.age: another unlock-*.age name is an unknown layout
  const other = makePkg('two-layer', { extra: { 'unlock-OTHER.age': tlockFile() } })
  refused(() => buildSealed(other.dir, full), 'sealed.format')
  const renamed = makePkg('one-layer', { extra: { 'unlock-2099-01-01T00-00-00Z.age': tlockFile() } })
  refused(() => buildSealed(renamed.dir, full), 'sealed.format')
})

test('S1: a package file that is not age -> sealed.not-age (binary and armored)', () => {
  const mac = `--- ${fill('m', 32).toString('base64').replace(/=+$/, '')}\n`
  const notAge: Array<[string, Buffer]> = [
    ['plaintext', fill('plain tar.gz', 600)],
    ['no stanza', Buffer.from(`age-encryption.org/v1\n${mac}payload`, 'latin1')],
    ['no MAC line', Buffer.from('age-encryption.org/v1\n-> X25519 abc\nAAAA\npayload', 'latin1')],
    ['a tlock stanza in the two-layer payload', tlockFile()],
    ['a full 64-char final body line', Buffer.from(`age-encryption.org/v1\n-> X25519 abc\n${'A'.repeat(64)}\n${mac}x`, 'latin1')],
  ]
  for (const [why, b] of notAge) {
    refused(() => buildSealed(makePkg('two-layer', { extra: { 'vault.tar.gz.age': b } }).dir, full), 'sealed.not-age')
    refused(() => buildSealed(makePkg('two-layer', { extra: { 'vault.tar.gz.age': pem(b) } }).dir, full), 'sealed.not-age')
    // checked even when key-only does not emit it: the bundle it points at would carry it
    refused(() => buildSealed(makePkg('two-layer', { extra: { 'vault.tar.gz.age': b } }).dir, key), 'sealed.not-age')
    assert.ok(why.length > 0)
  }
  // control: a real-shaped X25519 file passes
  assert.ok(buildSealed(makePkg('two-layer', { extra: { 'vault.tar.gz.age': x25519File('other', 100) } }).dir, full).startsWith('== vault-timelock sealed package: '))
})

test('S1: parseAgeHeader / parseTlockStanza enforce the age stanza grammar', () => {
  const H = `age-encryption.org/v1\n-> tlock ${ROUND} ${HASH}\n`
  const M = `--- ${'A'.repeat(43)}\n`
  const p = (s: string) => parseTlockStanza(Buffer.from(s + 'payload', 'latin1'))
  const want = { round: String(ROUND), hash: HASH }
  assert.deepEqual(p(H + 'A'.repeat(64) + '\n' + 'A'.repeat(43) + '\n' + M), want)
  assert.deepEqual(p(H + 'A'.repeat(64) + '\n\n' + M), want)            // an empty short line ends a 64n body
  assert.deepEqual(p(H + '\n' + M), want)                               // an empty body
  assert.equal(p(H + 'A'.repeat(64) + '\n' + M), null)                  // no short final line (the old fixture)
  assert.equal(p(H + 'A'.repeat(65) + '\n' + M), null)                  // a line wider than 64
  assert.equal(p(H + 'A'.repeat(43) + '\n' + 'A'.repeat(64) + '\n' + 'A\n' + M), null) // body after the short line
  assert.equal(p(H + 'AAAA==\n' + M), null)                             // padding
  assert.equal(p(H + 'AA*A\n' + M), null)                               // not base64
  assert.equal(p(H + 'AAAA\n' + '--- short\n'), null)                    // a MAC that is not 32 bytes
  assert.equal(p(H + 'AAAA\n'), null)                                   // no MAC line at all
  assert.equal(p(`age-encryption.org/v1\n-> tlock  ${ROUND} ${HASH}\nAAAA\n` + M), null) // an empty argument
  // the fixture has real tle's shape: 64, 64, 43, then a 43-char MAC
  const lines = tlockFile().toString('latin1').split('\n')
  assert.deepEqual(lines.slice(2, 5).map((l) => l.length), [64, 64, 43])
  assert.match(lines[5], /^--- [A-Za-z0-9+/]{43}$/)
  assert.deepEqual(parseAgeHeader(x25519File())?.stanzas.map((s) => s.type), ['X25519'])
})

test('S1: sealed.chain-info requires quicknet (hash, genesis_time, period, schemeID)', () => {
  const FASTNET = 'dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493'
  // a self-consistent non-quicknet package: the stanza names the same chain as chain-info.json
  const p = makePkg('two-layer', { stanzaHash: FASTNET })
  writeFileSync(join(p.dir, 'chain-info.json'), JSON.stringify({ ...CHAIN_INFO, hash: FASTNET }))
  refused(() => buildSealed(p.dir, full), 'sealed.chain-info')
  for (const wrong of [{ genesis_time: CHAIN_INFO.genesis_time + 1 }, { period: 30 }, { schemeID: 'pedersen-bls-chained' }]) {
    const q = makePkg('one-layer')
    writeFileSync(join(q.dir, 'chain-info.json'), JSON.stringify({ ...CHAIN_INFO, ...wrong }))
    refused(() => buildSealed(q.dir, full), 'sealed.chain-info')
  }
  assert.deepEqual(QUICKNET, { hash: HASH, genesis: 1692803367, period: 3, schemeID: 'bls-unchained-g1-rfc9380' })
})

test('S1: the pinned quicknet hash is the one anchors.json carries', () => {
  const anchors = JSON.parse(readFileSync(new URL('../../anchors.json', import.meta.url), 'utf8')) as Record<string, { address: string }>
  assert.equal(anchors['drand.quicknet'].address, QUICKNET.hash)
})

test('S1: key-only adds the 1b fetch step only when a file is left out (two-layer)', () => {
  const t = buildSealed(makePkg('two-layer').dir, key)
  assert.ok(t.includes(`SEALED.txt\n  1b. fetch ar://${AR} (a tar bundle; any Arweave gateway, e.g. https://arweave.net/${AR},\n     through Tor) and extract vault.tar.gz.age from it into this directory\n  2. check each block`))
  assert.ok(!buildSealed(makePkg('two-layer').dir, full).includes('1b.'))
  for (const kind of ['one-layer', 'secret', 'raw', 'tar+gzip'] as const) assert.ok(!buildSealed(makePkg(kind).dir, key).includes('1b.'), kind)
})

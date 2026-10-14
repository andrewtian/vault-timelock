// SEALED.txt format /2, layout per-file (lane B, 2026-10-14; .superpowers/sdd/2026-10-14-vt-decrypt/v2-format.md): the text
// `1password-timelock.sh seal --list` gets from seal-text. Synthetic packages only: fixtures.ts files for the text, and a
// real one (age-keygen, age, gzip; no tle: the time-locked file is a fixture) for the printed steps. No real data.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'
import { BLOCKS_OPEN, INDEX_CHECK, INDEX_GRAMMAR, INDEX_PATH, agePlaintextLength, padBucket } from '../../src/text/sealed-from.ts'
import { sealedFiles, checkPayload } from '../../src/text/payload.ts'
import { Refusal } from '../../src/text/guard.ts'
import { buildSealed } from './build-sealed.ts'
import { AR, CHAIN_INFO, HASH, NOW, ROUND, UNLOCK, fill, makePkg, pem, tlockFile, x25519File } from './fixtures.ts'

const sha = (b: Buffer | string) => createHash('sha256').update(b).digest('hex')
const arm = (b: Buffer) => `-----BEGIN AGE ENCRYPTED FILE-----\n${b.toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END AGE ENCRYPTED FILE-----\n`
const refused = (f: () => unknown, id: string) => assert.throws(f, (e: unknown) => e instanceof Refusal && e.guardId === id, `expected ${id}`)
const full = { contents: 'full' as const, now: NOW }
const UL = 'unlock-TIME.age'

// ---- a synthetic per-file package (parsing only: the blocks are age-shaped, nothing is encrypted) ----------------------
// index: an X25519-shaped file whose age plaintext length is `plain` (a 16-byte nonce + plain + one 16-byte tag)
const made: string[] = []
process.once('exit', () => { for (const d of made) rmSync(d, { recursive: true, force: true }) })
const tmp = (p: string) => { const d = mkdtempSync(join(tmpdir(), p)); made.push(d); return d }
type V2 = { n?: number; padding?: 'none' | 'buckets'; gz?: number; layout?: string; blocks?: string[]; armor?: boolean; extra?: Record<string, Buffer | string>; withKey?: boolean }
function makeV2(o: V2 = {}): { dir: string; files: Record<string, Buffer>; gz: number; blocks: string[] } {
  const dir = tmp('vt-v2-')
  const padding = o.padding ?? 'none'
  const gz = o.gz ?? 500
  const plain = padding === 'buckets' ? padBucket(gz) : gz
  const n = o.n ?? 3
  const blocks = o.blocks ?? Array.from({ length: n }, (_, i) => `b${String(i + 1).padStart(Math.max(4, String(n).length), '0')}`)
  const files: Record<string, Buffer> = { [UL]: tlockFile(ROUND, HASH, 'unlock', 300), index: x25519File('index', plain + 32) }
  blocks.forEach((b, i) => { files[b] = x25519File(`blk${i}`, 100 + ((37 * i) % 400)) })
  if (o.withKey === true) files['unlock-KEY.age'] = x25519File('recovery', 200)
  for (const [k, b] of Object.entries(files)) writeFileSync(join(dir, k), o.armor === true && k !== 'unlock-KEY.age' ? pem(b) : b)
  if (o.armor === true) writeFileSync(join(dir, 'ARMOR'), 'pem\n')
  writeFileSync(join(dir, 'layout'), o.layout ?? `layout: per-file\npadding: ${padding}\nindex-gzip: ${gz}\n`)
  writeFileSync(join(dir, 'chain-info.json'), JSON.stringify(CHAIN_INFO))
  writeFileSync(join(dir, 'round'), `${ROUND}\n`)
  for (const [k, b] of Object.entries(o.extra ?? {})) writeFileSync(join(dir, k), b)
  return { dir, files, gz, blocks }
}

// ---- the expected text, written out here independently of src ----------------------------------------------------------
const AWK = `'/^\\[file [A-Za-z0-9][A-Za-z0-9._-]* bytes=[0-9]+ sha256=[0-9a-f]+( gzip=[0-9]+)?\\]$/ { f = ($2 == n); next } f && /^-----BEGIN AGE ENCRYPTED FILE-----$/ { w = 1 } w { print > n } w && /^-----END AGE ENCRYPTED FILE-----$/ { close(n); exit }'`
const cut = (n: string, b: Buffer) => `( awk -v n=${n} ${AWK} SEALED.txt && [ "$(sed '1d;$d' ${n} | base64 -d | wc -c | tr -d ' ') $(sed '1d;$d' ${n} | base64 -d | shasum -a 256 | cut -c1-64)" = "${b.length} ${sha(b)}" ] && echo "OK ${n}" || { echo "BAD ${n}"; exit 1; } )`
// fix round 1 (C-1): the whole index is checked against the exact grammar before any field is used
const CHECK = `LC_ALL=C awk -F '\\t' -v P='^(items/[a-z0-9]+[.]json|files/[a-z0-9]+/[a-z0-9]+|MANIFEST[.]csv|ATTACHMENTS[.]csv)$' 'NR == FNR { if ($0 ~ /^\\[file b[0-9][0-9][0-9][0-9]+ bytes=[0-9]+ sha256=[0-9a-f]+\\]$/) { split($0, w, " "); h[w[2]] = 1 } next } { x++ } FNR == 1 { if ($0 != "vault-timelock-index/1") { print "BAD index.tsv line 1"; e = 1 } next } NF != 5 || $1 !~ /^b[0-9][0-9][0-9][0-9]+$/ || !($1 in h) || u[$1]++ || $2 !~ P || q[$2]++ || $3 !~ /^[0-9]+$/ || length($3) > 12 || $4 !~ /^[0-9a-f]+$/ || length($4) != 64 || $5 !~ /^[0-9]+$/ || length($5) > 12 { print "BAD index.tsv line " FNR; e = 1 } END { if (x < 2) { print "BAD index.tsv line " x + 1; e = 1 } exit e }' SEALED.txt index.tsv`
const LOOP = `( ${CHECK} && mkdir restored && tail -n +2 index.tsv | while IFS="$(printf '\\t')" read -r b p n s g || [ -n "$b" ]; do awk -v n="$b" ${AWK} SEALED.txt && mkdir -p "restored/$p" && rmdir "restored/$p" && age -d -i identity.key "./$b" | head -c "$g" | gunzip > "restored/$p" && printf '%s  %s\\n' "$s" "restored/$p" | shasum -a 256 -c > /dev/null && echo "OK $p" || { echo "BAD $p"; exit 1; }; done )`
const MF = `(cd restored && { tail -n +2 MANIFEST.csv | awk -F, '{ print $2 "  items/" $1 ".json" }'; [ ! -f ATTACHMENTS.csv ] || tail -n +2 ATTACHMENTS.csv | awk -F, '{ print $4 "  files/" $1 "/" $2 }'; } | shasum -a 256 -c)`
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
function golden(p: { files: Record<string, Buffer>; gz: number; blocks: string[] }, padding: 'none' | 'buckets'): string {
  const last = p.blocks[p.blocks.length - 1]
  const head = [
    '== vault-timelock sealed package: self-contained, age + drand timelock ==',
    'format: vault-timelock-sealed/2',
    'layout: per-file',
    'what-this-is: a vault, one block per file: each file gzip-compressed and encrypted with age to one',
    '  one-time key, its path and digest only in an encrypted index; that key is time-locked to a',
    '  drand round with tlock. Once drand publishes the round, anyone holding this text can open it;',
    '  the notes say what keeps it shut until then.',
    'layers:',
    `  - unlock-TIME.age: the one-time key, one AGE-SECRET-KEY-1... line, tlock-encrypted to drand round ${ROUND} (one "-> tlock ${ROUND} 52db9ba7..." age stanza)`,
    '  - index: which block is which file (vault-timelock-index/1: block, path, bytes, sha256, gzip bytes),',
    '    gzip-compressed, age-encrypted to that key (one "-> X25519" stanza)',
    `  - b0001 ... ${last}: one file each, gzip-compressed, age-encrypted to that key (one "-> X25519"`,
    '    stanza), numbered in a random order: only the index says which file is which',
    `unlock-after: ${UNLOCK}  (drand round ${ROUND})`,
    '  round time = genesis + (round - 1) * period; quicknet genesis 1692803367 (2023-08-23T15:09:27Z), period 3 s',
    `drand: quicknet ${HASH}  scheme bls-unchained-g1-rfc9380`,
    `drand-signature: https://api.drand.sh/${HASH}/public/${ROUND}`,
    `  mirrors: https://api2.drand.sh/${HASH}/public/${ROUND} https://api3.drand.sh/${HASH}/public/${ROUND}`,
    'tools: tle v1.2.0 https://github.com/drand/tlock | age v1.3.1 https://age-encryption.org',
    '  install: go install github.com/drand/tlock/cmd/tle@v1.2.0; age: https://github.com/FiloSottile/age/releases (or: brew install age; apt install age)',
    'contents: full',
    `blocks: ${p.blocks.length}`,
    `padding: ${padding}`,
    'open after unlock-after (POSIX sh; type each line that starts with "$ ", without the "$ "):',
    '  1. save this whole text as SEALED.txt in an empty directory and cd there. Cut out',
    '     unlock-TIME.age and check its size and SHA-256 (of the decoded bytes) against its [file ...]',
    `     line (it prints OK); then recover identity.key with drand's signature for round ${ROUND},`,
    '     through Tor (SOCKS on 127.0.0.1:9050; without Tor, drop the env prefix and drand sees your IP',
    '     ask for this round). If it fails (too early, or a network error), delete the empty',
    '     identity.key it leaves, then retry; if api.drand.sh is gone, add --network=https://api2.drand.sh',
    '     (or https://api3.drand.sh):',
    `     $ ${cut(UL, p.files[UL])}`,
    '     $ env -u NO_PROXY -u no_proxy HTTPS_PROXY=socks5h://127.0.0.1:9050 tle --decrypt --output=identity.key unlock-TIME.age',
    '  2. cut out the index and check it the same way; open it with identity.key, keep its first',
    `     ${p.gz} bytes (the gzip= of its [file ...] line; any rest is padding) and gunzip them into`,
    '     index.tsv: a first line vault-timelock-index/1, then one TAB-separated line per block:',
    '     block, path, bytes, sha256, gzip bytes:',
    `     $ ${cut('index', p.files.index)}`,
    `     $ ( age -d -i identity.key index | head -c ${p.gz} | gunzip > index.tsv && [ "$(head -n 1 index.tsv)" = vault-timelock-index/1 ] && echo "OK index.tsv" || { echo "BAD index.tsv"; exit 1; } )`,
    '  3. check EVERY line of index.tsv first (a block of this text, a sealed path, digits, a SHA-256;',
    '     anything else refuses the whole index, naming only line numbers, and nothing is written);',
    '     then for each line: cut out its block, open it with identity.key, keep its first <gzip bytes>,',
    "     gunzip them into restored/<path> and check that file's SHA-256; it prints OK for every file",
    "     (one file only: put grep -F -- '<its path>' index.tsv in place of tail -n +2 index.tsv):",
    `     $ ${LOOP}`,
    '  4. check every item and attachment against the manifests sealed inside; every line must end in OK:',
    `     $ ${MF}`,
    ...NOTES,
    ...(padding === 'buckets' ? [
      `  - without the key this text shows how many files the vault holds (blocks: ${p.blocks.length}) and, from each`,
      "    block's size, the size bucket of that file's gzip-compressed size (padding: buckets: 1, 2, 4, 8,",
      "    16, 32, 64 or 128 KiB, or a multiple of 128 KiB), and the index's exact compressed size (its",
      '    gzip=). Which file is which, the paths and the digests are only in the encrypted index.',
    ] : [
      `  - without the key this text shows how many files the vault holds (blocks: ${p.blocks.length}) and, from each`,
      "    block's size, that file's exact gzip-compressed size (padding: none), and the index's exact",
      '    compressed size (its gzip=). Which file is which, the paths and the digests are only in the',
      '    encrypted index.',
    ]),
    '',
  ].join('\n')
  const blk = (n: string, extra = '') => `[file ${n} bytes=${p.files[n].length} sha256=${sha(p.files[n])}${extra}]\n${arm(p.files[n])}`
  return head + blk(UL) + blk('index', ` gzip=${p.gz}`) + p.blocks.map((b) => blk(b)).join('') + '== end ==\n'
}

test('v2 golden: padding none, 3 blocks; unlock-TIME.age, index (with gzip=), b0001 ... in order; format /2, layout per-file', () => {
  const p = makeV2()
  assert.equal(buildSealed(p.dir, full), golden(p, 'none'))
})

test('v2 golden: padding buckets (the index plaintext is its bucket), 12 blocks', () => {
  const p = makeV2({ n: 12, padding: 'buckets', gz: 1500 })
  assert.equal(buildSealed(p.dir, full), golden(p, 'buckets'))
  assert.ok(buildSealed(p.dir, full).includes('\nblocks: 12\npadding: buckets\n'))
})

test('v2: 10000 blocks are b00001 ... b10000 (one width); the text names the last', () => {
  const p = makeV2({ blocks: ['b00001', 'b00002'] })
  refused(() => buildSealed(p.dir, full), 'sealed.blocks') // two blocks are four digits wide, not five
  const w = makeV2({ blocks: Array.from({ length: 10000 }, (_, i) => `b${String(i + 1).padStart(5, '0')}`) })
  const t = buildSealed(w.dir, full)
  assert.ok(t.includes('\n  - b0001 ... b10000: one file each'))
  assert.ok(t.includes('\n[file b00001 bytes=') && t.includes('\n[file b10000 bytes=') && t.includes('\nblocks: 10000\n'))
})

test('v2: an armored package gives the byte-identical text; unlock-KEY.age, MANIFEST.csv, README.txt, STRUCTURE.txt, SEALED-plaintext.txt beside it change nothing and are never read', () => {
  const plain = makeV2()
  const want = buildSealed(plain.dir, full)
  // the same block bytes, armored on disk (makeV2 is deterministic)
  assert.equal(buildSealed(makeV2({ armor: true }).dir, full), want)
  const x = makeV2({ withKey: true, extra: { 'MANIFEST.csv': 'item_id,sha256\nZZCANARYV2,x\n', 'README.txt': 'ZZCANARYV2 readme\n', 'STRUCTURE.txt': 'ZZCANARYV2\n', 'SEALED-plaintext.txt': 'ZZCANARYV2 s3cr3t\n' } })
  for (const f of ['MANIFEST.csv', 'README.txt', 'STRUCTURE.txt', 'SEALED-plaintext.txt']) chmodSync(join(x.dir, f), 0o000)
  const t = buildSealed(x.dir, full)
  assert.equal(t, want)
  assert.ok(!t.includes('ZZCANARYV2') && !t.includes('unlock-KEY') && !t.includes('[file layout'))
})

test('v2: the text is pure ASCII, \\n only, no trailing blank; gzip= only on the index line; no path of the vault', () => {
  const t = buildSealed(makeV2({ n: 5 }).dir, full)
  assert.ok(/^[\x00-\x7e]*$/.test(t) && !t.includes('\r') && !/[ \t]$/m.test(t))
  const fl = t.split('\n').filter((l) => l.startsWith('[file '))
  assert.deepEqual(fl.map((l) => l.split(' ')[1]), [UL, 'index', 'b0001', 'b0002', 'b0003', 'b0004', 'b0005'])
  assert.deepEqual(fl.filter((l) => l.includes(' gzip=')).map((l) => l.split(' ')[1]), ['index'])
  // the only paths the text names are the step commands' fixed names (restored/, MANIFEST.csv, ATTACHMENTS.csv, items/, files/)
  assert.ok(!/items\/[a-z0-9]+\.json|files\/[a-z0-9]+\//.test(t))
})

// ---- a REAL per-file package: age-keygen + age + gzip, as 1password-timelock.sh seal --list makes one (the time-locked
//      file is a fixture: tle is not run here; the steps after it are run exactly as printed) ---------------------------
type Real = { dir: string; key: string; index: string; text: () => string; setIndex: (index: string) => void }
function realV2(padding: 'none' | 'buckets', content: Record<string, Buffer>, order: string[]): Real {
  const dir = tmp('vt-v2real-')
  const key = join(dir, '.key')
  const kg = spawnSync('age-keygen', ['-o', key], { encoding: 'utf8' })
  assert.equal(kg.status, 0)
  const pub = /public key: (age1\S+)/i.exec(kg.stderr)![1]
  const enc = (name: string, bytes: Buffer) => {
    const g = gzipSync(bytes, { level: 9 })
    const padded = padding === 'buckets' ? Buffer.concat([g, Buffer.alloc(padBucket(g.length) - g.length)]) : g
    writeFileSync(join(dir, '.plain'), padded)
    const r = spawnSync('age', ['-r', pub, '-o', join(dir, name), join(dir, '.plain')])
    assert.equal(r.status, 0, String(r.stderr))
    return g.length
  }
  const w = Math.max(4, String(order.length).length)
  let index = 'vault-timelock-index/1\n'
  order.forEach((path, i) => {
    const b = `b${String(i + 1).padStart(w, '0')}`
    index += `${b}\t${path}\t${content[path].length}\t${sha(content[path])}\t${enc(b, content[path])}\n`
  })
  // setIndex: an index of the caller's own (the author of a text controls it), sealed to the same key
  const setIndex = (ix: string) => {
    const igz = enc('index', Buffer.from(ix, 'latin1'))
    writeFileSync(join(dir, 'layout'), `layout: per-file\npadding: ${padding}\nindex-gzip: ${igz}\n`)
  }
  setIndex(index)
  writeFileSync(join(dir, UL), tlockFile())
  writeFileSync(join(dir, 'chain-info.json'), JSON.stringify(CHAIN_INFO))
  writeFileSync(join(dir, 'round'), `${ROUND}\n`)
  return { dir, key, index, text: () => buildSealed(dir, full), setIndex }
}
// a synthetic vault: two items, one attachment, the two manifests (their digests right)
function vault(): Record<string, Buffer> {
  const A = Buffer.from('{"id":"aaaa","title":"synthetic ZZCANARYV2A","fields":[]}\n')
  const B = Buffer.from('{"id":"bbbb","title":"synthetic ZZCANARYV2B","fields":[{"value":"x"}]}\n')
  const F = fill('attachment', 70000) // > 64 KiB: two age chunks, and a 128 KiB bucket
  return {
    'items/aaaa.json': A, 'items/bbbb.json': B, 'files/aaaa/ffff': F,
    'MANIFEST.csv': Buffer.from(`item_id,sha256,field_count,section_count,file_count\naaaa,${sha(A)},0,0,1\nbbbb,${sha(B)},1,0,0\n`),
    'ATTACHMENTS.csv': Buffer.from(`item_id,file_id,bytes,sha256\naaaa,ffff,${F.length},${sha(F)}\n`),
  }
}
const ORDER = ['files/aaaa/ffff', 'MANIFEST.csv', 'items/bbbb.json', 'ATTACHMENTS.csv', 'items/aaaa.json']
// steps(text): the printed commands per step number
function steps(t: string): Map<number, string[]> {
  const m = new Map<number, string[]>()
  let n = 0
  for (const l of t.split('\n')) {
    const s = /^ {2}(\d+)\. /.exec(l)
    if (s !== null) n = Number(s[1])
    if (l.startsWith('     $ ')) m.set(n, [...(m.get(n) ?? []), l.slice(7)])
  }
  return m
}
const sh = (dir: string, cmd: string) => spawnSync('/bin/sh', ['-c', cmd], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
// run every printed command but tle (step 1's second) in a new directory holding only SEALED.txt (+ identity.key)
function literal(t: string, key: string): { dir: string; out: string; ok: boolean } {
  const w = tmp('vt-v2lit-')
  writeFileSync(join(w, 'SEALED.txt'), t)
  const s = steps(t)
  assert.deepEqual([...s.keys()], [1, 2, 3, 4])
  assert.equal(s.get(1)!.length, 2)
  assert.match(s.get(1)![1], /^env -u NO_PROXY -u no_proxy HTTPS_PROXY=socks5h:\/\/127\.0\.0\.1:9050 tle --decrypt --output=identity\.key unlock-TIME\.age$/)
  let out = ''
  const cmds = [s.get(1)![0], `cp '${key}' identity.key`, ...s.get(2)!, ...s.get(3)!, ...s.get(4)!]
  for (const c of cmds) {
    const r = sh(w, c)
    out += r.stdout + r.stderr
    if (r.status !== 0) return { dir: w, out, ok: false }
  }
  return { dir: w, out, ok: true }
}

for (const padding of ['none', 'buckets'] as const) {
  test(`v2 literal (${padding}): the printed steps, run exactly as printed in an empty directory, recover every file and say OK`, () => {
    const v = vault()
    const p = realV2(padding, v, ORDER)
    const r = literal(p.text(), p.key)
    assert.ok(r.ok, r.out)
    const lines = r.out.trim().split('\n')
    for (const want of ['OK unlock-TIME.age', 'OK index', 'OK index.tsv', ...ORDER.map((x) => `OK ${x}`), 'items/aaaa.json: OK', 'items/bbbb.json: OK', 'files/aaaa/ffff: OK']) {
      assert.equal(lines.filter((l) => l === want).length, 1, `${want} in:\n${r.out}`)
    }
    for (const [path, bytes] of Object.entries(v)) assert.ok(readFileSync(join(r.dir, 'restored', path)).equals(bytes), path)
  })
}

test('v2 literal, negative controls: a damaged block, a swapped block, a wrong gzip= and an index without its cut all fail', () => {
  const v = vault()
  const p = realV2('buckets', v, ORDER)
  const t = p.text()
  // one base64 character of b0003's armor changed: age refuses it (step 3 says BAD and stops)
  const i3 = t.indexOf('[file b0003 ')
  const body = t.indexOf('\n', t.indexOf('-----BEGIN AGE ENCRYPTED FILE-----', i3)) + 1
  const bad = t.slice(0, body + 10) + (t[body + 10] === 'A' ? 'B' : 'A') + t.slice(body + 11)
  let r = literal(bad, p.key)
  assert.ok(!r.ok && r.out.includes('BAD items/bbbb.json'), r.out)
  // b0002 and b0003 swapped in the text (their [file] names exchanged): the restored file's digest is not the index's
  const sw = t.replace('[file b0002 ', '[file bXXXX ').replace('[file b0003 ', '[file b0002 ').replace('[file bXXXX ', '[file b0003 ')
  r = literal(sw, p.key)
  assert.ok(!r.ok && r.out.includes('BAD MANIFEST.csv'), r.out)
  // the index cut at a wrong length: gunzip refuses (the padding is real)
  const igz = /gzip=(\d+)\]/.exec(t)![1]
  r = literal(t.replace(`head -c ${igz} |`, `head -c ${Number(igz) + 1} |`), p.key)
  assert.ok(!r.ok && r.out.includes('BAD index.tsv'), r.out)
  // step 2 without the cut at gzip=: a padded index does not gunzip
  r = literal(t.replace(`| head -c ${igz} |`, '|'), p.key)
  assert.ok(!r.ok && r.out.includes('BAD index.tsv'), r.out)
})

// ---- fix round 1 (C-1, I-1): index.tsv is AUTHOR-CONTROLLED for whoever opens someone else's text. The printed steps
//      check EVERY line against the exact grammar before any field is used; a hostile value in ANY column refuses the
//      whole index (only line numbers printed), and nothing is written: no restored/, no canary, nothing outside. --------
// the index's last line with column `col` (0 block, 1 path, 2 bytes, 3 sha256, 4 gzip bytes) set to `v`
const withCol = (ix: string, col: number, v: string) => {
  const l = ix.split('\n'); const k = l.length - 2; const f = l[k].split('\t'); f[col] = v; l[k] = f.join('\t'); return l.join('\n')
}
const PRINTABLE = /^[\n\x20-\x7e]*$/
function hostile(p: Real, cases: Array<[string, string]>, canaries: string[]) {
  for (const [why, ix] of cases) {
    p.setIndex(ix)
    const r = literal(p.text(), p.key)
    assert.ok(!r.ok, `${why}: the crafted index was OPENED:\n${r.out}`)
    assert.match(r.out, /^BAD index\.tsv( line \d+)?$/m, `${why}: not refused by the index check (step 3's, or step 2's header check):\n${r.out}`)
    assert.ok(!r.out.includes('OK items/') && !r.out.includes('OK files/'), `${why}: a block was opened`)
    assert.ok(!existsSync(join(r.dir, 'restored')), `${why}: restored/ was created`)
    for (const c of canaries) assert.ok(!existsSync(c), `${why}: ${c} was created`)
    assert.deepEqual(readdirSync(r.dir).sort(), ['SEALED.txt', 'identity.key', 'index', 'index.tsv', UL].sort(), `${why}: the work dir holds more`)
    assert.ok(PRINTABLE.test(r.out), `${why}: a byte outside printable ASCII reached the terminal`)
  }
}
test('C-1: a hostile value in EVERY column of index.tsv (block, path, bytes, sha256, gzip bytes) refuses the whole index before anything runs: no restored/, no canary, nothing outside, only printable output', () => {
  const p = realV2('none', vault(), ORDER)
  const out = tmp('vt-v2out-')
  const C = join(out, 'CANARY')
  const U = `ZZCANARYV2OUT${process.pid}`
  const ix = p.index
  const z = sha('x')
  const cols: Array<[number, string[]]> = [
    [0, [`-o${C}`, `$(touch ${C})`, `b0005;touch ${C}`, 'b1', 'b9999', 'B0005', ' b0005', 'b0005\x1b[2J', '../b0005', 'b0001', '']],
    [1, [`../${U}`, C, `items/../../${U}`, 'items//x.json', './items/x.json', 'items/./x.json', 'items/x.json/', `$(touch ${C})`, '-rf', 'items/x y.json',
      'items/x.json\x1b]0;pwned\x07', 'items/X.json', 'MANIFEST.csv', '']],
    [2, ['-1', '1e5', '$((1+1))', `$(touch ${C})`, '1234567890123', ' 5', '']],
    [3, [z.slice(1), z.toUpperCase(), `${z}x`, `$(touch ${C})`, '']],
    [4, ['-5', '0x10', '$((1+1))', `$(touch ${C})`, '1234567890123', '+5', '']],
  ]
  const cases: Array<[string, string]> = []
  for (const [col, vals] of cols) for (const v of vals) cases.push([`column ${col} = ${JSON.stringify(v)}`, withCol(ix, col, v)])
  const lines = ix.split('\n')
  cases.push(
    ['4 fields', ix.replace(/\t[0-9]+\n$/, '\n')],
    ['6 fields', ix.replace(/\n$/, '\textra\n')],
    ['a CR at the end of a line', ix.replace(/\n$/, '\r\n')],
    ['another header', ix.replace(/^vault-timelock-index\/1/, 'vault-timelock-index/2')],
    ['the header only', `${lines[0]}\n`],
    ['an empty line', `${ix}\n`],
  )
  hostile(p, cases, [C, join(tmpdir(), U), join(p.dir, '..', U)])
})

test('C-1 control: the same steps WITHOUT the index check write restored/ for a crafted index (the test above has teeth)', () => {
  const p = realV2('none', vault(), ORDER)
  p.setIndex(withCol(p.index, 1, 'items/x y.json'))
  const t = p.text()
  const check = t.slice(t.indexOf('( LC_ALL=C awk -F '), t.indexOf(' && mkdir restored && tail -n +2 index.tsv'))
  assert.ok(check.length > 100)
  const r = literal(t.replace(`${check} && mkdir restored`, '( mkdir restored'), p.key)
  assert.ok(!r.ok && existsSync(join(r.dir, 'restored', 'items')), r.out)
})

test('minor b: an index whose last line has no trailing newline is checked and restored like the others (nothing skipped)', () => {
  const v = vault()
  const p = realV2('none', v, ORDER)
  p.setIndex(p.index.replace(/\n$/, ''))
  const r = literal(p.text(), p.key)
  assert.ok(r.ok, r.out)
  for (const x of ORDER) assert.ok(r.out.split('\n').includes(`OK ${x}`), `${x}:\n${r.out}`)
  for (const [path, bytes] of Object.entries(v)) assert.ok(readFileSync(join(r.dir, 'restored', path)).equals(bytes), path)
})

test('C-1: the grammar the steps check (INDEX_GRAMMAR, INDEX_PATH) covers every column: the writer\'s own shapes pass, hostile ones fail', () => {
  const ok = { block: ['b0001', 'b10000'], path: ['items/ab12.json', 'files/ab12/cd34', 'MANIFEST.csv', 'ATTACHMENTS.csv'], bytes: ['0', '123456789012'], sha256: [sha('x')], gzip: ['1', '123456789012'] }
  const bad = {
    block: ['b001', 'B0001', '-o', 'b0001 ', '$(x)', '../b0001', ''], path: ['../x', '/x', 'items/../x', 'items//x.json', './items/x.json', 'items/x.json/', 'items/X.json', 'x', 'items/a b.json', ''],
    bytes: ['-1', '1e5', '1234567890123', ' 1', ''], sha256: [sha('x').toUpperCase(), sha('x').slice(1), ''], gzip: ['-5', '0x10', '+5', '1234567890123', ''],
  }
  for (const [k, vs] of Object.entries(ok)) for (const v of vs) assert.ok(INDEX_GRAMMAR[k as keyof typeof INDEX_GRAMMAR].test(v), `${k} ${v}`)
  for (const [k, vs] of Object.entries(bad)) for (const v of vs) assert.ok(!INDEX_GRAMMAR[k as keyof typeof INDEX_GRAMMAR].test(v), `${k} ${JSON.stringify(v)}`)
  const t = buildSealed(realV2('none', vault(), ORDER).dir, full)
  assert.ok(t.includes(`-v P='${INDEX_PATH}'`) && t.includes(BLOCKS_OPEN) && BLOCKS_OPEN.startsWith(`( ${INDEX_CHECK} && mkdir restored `))
})

// ---- the guards --------------------------------------------------------------------------------------------------------
test('sealed.layout: the layout file is exactly its three lines', () => {
  for (const layout of ['layout: per-file\npadding: none\nindex-gzip: 500', 'layout: per-file\npadding: some\nindex-gzip: 500\n',
    'layout: per-file\npadding: none\nindex-gzip: 0\n', 'layout: per-file\npadding: none\nindex-gzip: 0500\n', 'layout: single\npadding: none\nindex-gzip: 500\n',
    '\uFEFFlayout: per-file\npadding: none\nindex-gzip: 500\n', 'layout: per-file\npadding: none\nindex-gzip: 500\nextra: 1\n', 'layout: per-file\r\npadding: none\r\nindex-gzip: 500\r\n', '']) {
    refused(() => buildSealed(makeV2({ layout }).dir, full), 'sealed.layout')
  }
})

test('sealed.blocks: b0001 ... bN with no gap, no other width, at least one', () => {
  for (const blocks of [['b0001', 'b0003'], ['b0002'], ['b001', 'b002'], ['b0001', 'b00002'], [], ['b00001']]) {
    refused(() => buildSealed(makeV2({ blocks }).dir, full), 'sealed.blocks')
  }
  assert.ok(buildSealed(makeV2({ blocks: ['b0001'] }).dir, full).includes('\nblocks: 1\n'))
})

test('sealed.per-file-full-only: a per-file package has no key-only form', () => {
  refused(() => buildSealed(makeV2().dir, { contents: 'key-only', arId: AR, now: NOW }), 'sealed.per-file-full-only')
})

test('sealed.index-gzip: the index plaintext is exactly index-gzip (padding none) or its bucket (padding buckets)', () => {
  for (const [padding, plainGz, layoutGz] of [['none', 500, 501], ['none', 500, 499], ['buckets', 1500, 2049], ['buckets', 1500, 1024]] as const) {
    const p = makeV2({ padding, gz: plainGz })
    writeFileSync(join(p.dir, 'layout'), `layout: per-file\npadding: ${padding}\nindex-gzip: ${layoutGz}\n`)
    refused(() => buildSealed(p.dir, full), 'sealed.index-gzip')
  }
  // padding none with a bucket-sized plaintext, and buckets with an unpadded one
  const q = makeV2({ padding: 'buckets', gz: 1500 })
  writeFileSync(join(q.dir, 'layout'), 'layout: per-file\npadding: none\nindex-gzip: 1500\n')
  refused(() => buildSealed(q.dir, full), 'sealed.index-gzip')
  // control: 2048 is its own bucket
  assert.ok(buildSealed(makeV2({ padding: 'buckets', gz: 2048 }).dir, full).includes('gzip=2048]'))
})

test('sealed.format: a layout file beside any other shape, or without its index, is no known format', () => {
  refused(() => buildSealed(makeV2({ extra: { 'vault.tar.gz.age': x25519File() } }).dir, full), 'sealed.format')
  refused(() => buildSealed(makeV2({ extra: { 'b0004.age': x25519File() } }).dir, full), 'sealed.format')
  refused(() => buildSealed(makePkg('two-layer', { extra: { layout: 'layout: per-file\npadding: none\nindex-gzip: 500\n' } }).dir, full), 'sealed.format')
  const p = makeV2()
  rmSync(join(p.dir, 'index'))
  refused(() => buildSealed(p.dir, full), 'sealed.format')
  // and a block or the index that is not age, or carries a tlock stanza
  refused(() => buildSealed(makeV2({ extra: { b0002: 'not age' } }).dir, full), 'sealed.not-age')
  refused(() => buildSealed(makeV2({ extra: { index: tlockFile() } }).dir, full), 'sealed.not-age')
  const d = makeV2()
  rmSync(join(d.dir, 'b0002'))
  mkdirSync(join(d.dir, 'b0002'))
  refused(() => buildSealed(d.dir, full), 'sealed.file')
})

// ---- format /1 readers refuse format /2 on its format line --------------------------------------------------------------
test('a format /1 reader (core\'s published-text parser: Open and the publisher) refuses a v2 text on its format line', () => {
  const v2 = buildSealed(makeV2().dir, full)
  const wrap = (s: string) => `vault-timelock/1 unlock=${UNLOCK}\nar://${AR}\nsynthetic note\n\n${s}`
  const ids = checkPayload(wrap(v2)).issues.map((i) => i.id)
  assert.ok(ids.includes('payload.sealed-line'), ids.join(' '))
  assert.ok(checkPayload(wrap(v2)).issues.some((i) => i.id === 'payload.sealed-line' && i.message.includes('`format:`')))
  assert.throws(() => sealedFiles(wrap(v2)), (e: unknown) => e instanceof Refusal && e.guardId === 'payload.invalid' && e.message.includes('payload.sealed-line'))
  // control: the same parser reads a format /1 text
  const v1 = buildSealed(makePkg('two-layer').dir, full)
  assert.deepEqual([...sealedFiles(wrap(v1)).keys()], [UL, 'vault.tar.gz.age'])
})

// ---- the helpers -------------------------------------------------------------------------------------------------------
test('padBucket: 1, 2, 4 ... 128 KiB, then multiples of 128 KiB', () => {
  const t: Array<[number, number]> = [[1, 1024], [1024, 1024], [1025, 2048], [2049, 4096], [8192, 8192], [65537, 131072], [131072, 131072],
    [131073, 262144], [262144, 262144], [300000, 393216]]
  for (const [n, b] of t) assert.equal(padBucket(n), b, String(n))
})

test('agePlaintextLength agrees with age itself (0 B, 1 B, one full 64 KiB chunk, a chunk and a byte, three chunks)', () => {
  const d = tmp('vt-v2len-')
  const key = join(d, 'k')
  const kg = spawnSync('age-keygen', ['-o', key], { encoding: 'utf8' })
  const pub = /public key: (age1\S+)/i.exec(kg.stderr)![1]
  for (const n of [0, 1, 65536, 65537, 131072 + 5]) {
    writeFileSync(join(d, 'p'), fill(`len${n}`, n))
    const r = spawnSync('age', ['-r', pub, join(d, 'p')])
    assert.equal(r.status, 0)
    assert.equal(agePlaintextLength(new Uint8Array(r.stdout)), n, String(n))
  }
  assert.equal(agePlaintextLength(new Uint8Array(Buffer.from('not age'))), null)
})

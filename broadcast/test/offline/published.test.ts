import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { PUBLISH_CAP, ARB_CAP, SOL_MEMO_MAX, ETH_PREFIX, buildPublished } from '../../src/published.ts'
import type { Dest } from '../../src/published.ts'
import { HEADER_BYTES, buildEnvelope } from '../../src/envelope.ts'
import { buildSealed } from '../../src/sealed.ts'
import { Refusal } from '../../src/guard.ts'
import { AR, NOW, UNLOCK, makePkg } from './fixtures.ts'

const NOTE = 'synthetic note'
const A = { arId: AR, unlock: UNLOCK, note: NOTE }
const dec = (b: Uint8Array) => new TextDecoder().decode(b)

function refused(f: () => unknown, id: string) {
  assert.throws(f, (e: unknown) => e instanceof Refusal && e.guardId === id, `expected ${id}`)
}

// Synthetic sealed text of an exact byte length (filler lines before the end marker).
function sealedOf(contents: string, total: number): string {
  const base = `== vault-timelock sealed package: self-contained, age + drand timelock ==\nunlock-after: ${UNLOCK}  (drand round 500000000)\n${contents}\n`
  const end = '== end ==\n'
  const fill = total - base.length - end.length
  assert.ok(fill >= 0 && (fill === 0 || fill >= 2))
  return base + (fill ? 'x'.repeat(fill - 1) + '\n' : '') + end
}
const KEY = `contents: key-only (payload: ar://${AR})`
const envLen = buildEnvelope(A).bytes.length

test('caps and ETH_PREFIX (R32, R33)', () => {
  assert.equal(PUBLISH_CAP, 98304)
  assert.equal(ARB_CAP, 94000)
  assert.equal(SOL_MEMO_MAX, 1000)
  assert.equal(ETH_PREFIX, 'data:,')
  assert.equal(Buffer.byteLength(ETH_PREFIX), 6)
})

test('R32: the old data:text/plain prefix is not used', () => {
  const old = 'data:text/plain;charset=utf-8,'
  assert.notEqual(ETH_PREFIX, old)
  const { dir } = makePkg('two-layer')
  const f = buildSealed(dir, { contents: 'full', now: NOW })
  const k = buildSealed(dir, { contents: 'key-only', arId: AR, now: NOW })
  assert.ok(!dec(buildPublished(A, f, k, 'eth').bytes).startsWith(old))
})

test('eth = prefix + arb; text is two-line header, note, blank line, sealed', () => {
  const { dir } = makePkg('two-layer')
  const f = buildSealed(dir, { contents: 'full', now: NOW })
  const k = buildSealed(dir, { contents: 'key-only', arId: AR, now: NOW })
  const eth = buildPublished(A, f, k, 'eth')
  const arb = buildPublished(A, f, k, 'arb')
  assert.equal(eth.contents, 'full')
  assert.ok(dec(eth.bytes).startsWith(ETH_PREFIX + 'vault-timelock/1 unlock='))
  assert.deepEqual(Buffer.from(eth.bytes.subarray(6)), Buffer.from(arb.bytes))
  assert.equal(dec(arb.bytes), `vault-timelock/1 unlock=${UNLOCK}\nar://${AR}\n${NOTE}\n\n${f}`)
  for (const d of ['base', 'btc', 'arweave'] as Dest[]) assert.deepEqual(buildPublished(A, f, k, d), arb)
  assert.match(arb.sha256, /^[0-9a-f]{64}$/)
})

const sha256hex = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')

test('R34 sol: header + note + sha256 of the no-prefix text (full here: it fits)', () => {
  const { dir } = makePkg('two-layer')
  const f = buildSealed(dir, { contents: 'full', now: NOW })
  const k = buildSealed(dir, { contents: 'key-only', arId: AR, now: NOW })
  const sol = buildPublished(A, f, k, 'sol')
  const header = `vault-timelock/1 unlock=${UNLOCK}\nar://${AR}\n`
  const base = `${header}${NOTE}\n\n${f}` // independent computation, no chain prefix
  assert.equal(sol.contents, 'none')
  assert.equal(dec(sol.bytes), `${header}${NOTE}\nsha256:${sha256hex(base)}`)
  assert.ok(!dec(sol.bytes).includes('-----BEGIN AGE'))
  assert.ok(!dec(sol.bytes).includes('== vault-timelock sealed package'))
  assert.ok(!dec(sol.bytes).endsWith('\n'))
  // the hash is the same as the eth text's tail, i.e. independent of the destination prefix
  const eth = buildPublished(A, f, k, 'eth')
  assert.equal(sha256hex(dec(eth.bytes).slice(ETH_PREFIX.length)), sha256hex(base))
})

// R41 (operator decision B1; Task H0 item 8): the Solana pointer hashes the text exactly as the 98,304 B
// no-prefix destinations (Base, Bitcoin, the Arweave item) carry it in this publication: `full` if
// env + "\n\n" + sealedFull fits PUBLISH_CAP, else `key-only`.
const pointer = (sol: Uint8Array) => /\nsha256:([0-9a-f]{64})$/.exec(dec(sol))?.[1]
test('R41 sol: the pointer equals sha256(base bytes) for a full package (real fixture)', () => {
  const { dir } = makePkg('two-layer')
  const f = buildSealed(dir, { contents: 'full', now: NOW })
  const k = buildSealed(dir, { contents: 'key-only', arId: AR, now: NOW })
  const base = buildPublished(A, f, k, 'base')
  assert.equal(base.contents, 'full')
  assert.equal(pointer(buildPublished(A, f, k, 'sol').bytes), createHash('sha256').update(base.bytes).digest('hex'))
  assert.equal(pointer(buildPublished(A, f, k, 'sol').bytes), base.sha256)
  for (const d of ['btc', 'arweave'] as Dest[]) assert.equal(buildPublished(A, f, k, d).sha256, base.sha256, d)
})

test('R41 sol: an oversize package points at the key-only text that Base, Bitcoin and Arweave carry', () => {
  const full = sealedOf('contents: full', PUBLISH_CAP * 2)
  const key = sealedOf(KEY, 2000)
  const base = buildPublished(A, full, key, 'base')
  assert.equal(base.contents, 'key-only')
  const sol = buildPublished(A, full, key, 'sol')
  assert.equal(pointer(sol.bytes), createHash('sha256').update(base.bytes).digest('hex'))
  const header = `vault-timelock/1 unlock=${UNLOCK}\nar://${AR}\n`
  assert.equal(pointer(sol.bytes), sha256hex(`${header}${NOTE}\n\n${key}`), 'independent computation of the key-only text')
  assert.notEqual(pointer(sol.bytes), sha256hex(`${header}${NOTE}\n\n${full}`), 'not the full form, which is on no chain')
})

test('R41 sol: the boundary is the 98,304 B no-prefix cap, not Ethereum\'s prefix nor Arbitrum\'s cap', () => {
  const key = sealedOf(KEY, 2000)
  const fits = PUBLISH_CAP - envLen - 2 // base exactly at the cap: eth and arb have tipped to key-only
  for (const [n, want] of [[fits, 'full'], [fits + 2, 'key-only'], [ARB_CAP - envLen - 1, 'full']] as const) {
    const full = sealedOf('contents: full', n)
    const base = buildPublished(A, full, key, 'base')
    assert.equal(base.contents, want, String(n))
    assert.equal(pointer(buildPublished(A, full, key, 'sol').bytes), base.sha256, String(n))
  }
  assert.equal(buildPublished(A, sealedOf('contents: full', fits), key, 'eth').contents, 'key-only')
  assert.equal(buildPublished(A, sealedOf('contents: full', fits), key, 'arb').contents, 'key-only')
})

test('R41 sol: when not even key-only fits 98,304 B there is no text to point at: published.too-long', () => {
  refused(() => buildPublished(A, sealedOf('contents: full', PUBLISH_CAP), sealedOf(KEY, PUBLISH_CAP), 'sol'), 'published.too-long')
})

test('R34 sol: a note with a trailing LF is refused as note.whitespace, never stripped', () => {
  const f = sealedOf('contents: full', 500)
  refused(() => buildPublished({ ...A, note: 'x\n' }, f, sealedOf(KEY, 500), 'sol'), 'note.whitespace')
})

test('R34 sol: SOL_MEMO_MAX is measured in UTF-8 bytes of the whole memo', () => {
  const f = sealedOf('contents: full', 500)
  const k = sealedOf(KEY, 500)
  const fixed = HEADER_BYTES + '\nsha256:'.length + 64
  const ok = buildPublished({ ...A, note: 'a'.repeat(SOL_MEMO_MAX - fixed) }, f, k, 'sol')
  assert.equal(ok.bytes.length, SOL_MEMO_MAX)
  refused(() => buildPublished({ ...A, note: 'a'.repeat(SOL_MEMO_MAX - fixed + 1) }, f, k, 'sol'), 'published.sol-too-long')
  // bytes, not chars: one 2-byte char tips it where 1 byte would not
  const n = SOL_MEMO_MAX - fixed - 1
  assert.equal(buildPublished({ ...A, note: 'a'.repeat(n - 1) + 'é' }, f, k, 'sol').bytes.length, SOL_MEMO_MAX)
  refused(() => buildPublished({ ...A, note: 'a'.repeat(n) + 'é' }, f, k, 'sol'), 'published.sol-too-long')
})

test('R34 sol: over-long note refuses sol only', () => {
  const f = sealedOf('contents: full', 500)
  const k = sealedOf(KEY, 500)
  const big = { ...A, note: 'a'.repeat(2000) }
  refused(() => buildPublished(big, f, k, 'sol'), 'published.sol-too-long')
  for (const d of ['eth', 'arb', 'base', 'btc', 'arweave'] as Dest[]) assert.equal(buildPublished(big, f, k, d).contents, 'full')
})

test('cap boundary: exactly the cap stays full, one over switches to key-only', () => {
  const full = (n: number) => sealedOf('contents: full', n)
  const key = sealedOf(KEY, 2000)
  const fits = PUBLISH_CAP - envLen - 2
  const a = buildPublished(A, full(fits), key, 'base')
  assert.equal(a.contents, 'full')
  assert.equal(a.bytes.length, PUBLISH_CAP)
  const b = buildPublished(A, full(fits + 2), key, 'base')
  assert.equal(b.contents, 'key-only')
  assert.equal(dec(b.bytes), `vault-timelock/1 unlock=${UNLOCK}\nar://${AR}\n${NOTE}\n\n${key}`)
})

test('R33: Arbitrum cap is 94000; a text that fits Base/ETH tips only Arbitrum to key-only', () => {
  const key = sealedOf(KEY, 2000)
  const fitsArb = ARB_CAP - envLen - 2
  const at = sealedOf('contents: full', fitsArb)
  const over = sealedOf('contents: full', fitsArb + 1)
  assert.equal(buildPublished(A, at, key, 'arb').contents, 'full')
  assert.equal(buildPublished(A, at, key, 'arb').bytes.length, ARB_CAP)
  const res: Record<string, string> = {}
  for (const d of ['eth', 'arb', 'base', 'btc', 'arweave'] as Dest[]) res[d] = buildPublished(A, over, key, d).contents
  assert.deepEqual(res, { eth: 'full', arb: 'key-only', base: 'full', btc: 'full', arweave: 'full' })
})

test('R32: the 6-byte prefix tips eth alone to key-only (exact tip)', () => {
  const key = sealedOf(KEY, 2000)
  const dests = ['eth', 'base', 'btc', 'arweave'] as Dest[]
  const fits = PUBLISH_CAP - envLen - 2 // sealed size where base is exactly at the cap
  for (const spare of [0, 1, 3, 5]) {
    const full = sealedOf('contents: full', fits - spare)
    const res: Record<string, string> = {}
    for (const d of dests) res[d] = buildPublished(A, full, key, d).contents
    assert.deepEqual(res, { eth: 'key-only', base: 'full', btc: 'full', arweave: 'full' }, `spare ${spare}`)
    assert.equal(buildPublished(A, full, key, 'base').bytes.length, PUBLISH_CAP - spare)
  }
  const exact = sealedOf('contents: full', fits - 6)
  const eth = buildPublished(A, exact, key, 'eth')
  assert.equal(eth.contents, 'full')
  assert.equal(eth.bytes.length, PUBLISH_CAP)
  const tipped = buildPublished(A, sealedOf('contents: full', fits - 5), key, 'eth')
  assert.equal(tipped.contents, 'key-only')
  assert.ok(dec(tipped.bytes).startsWith(ETH_PREFIX + 'vault-timelock/1 '))
  assert.ok(tipped.bytes.length <= PUBLISH_CAP)
})

test('oversized key-only -> published.too-long', () => {
  const full = sealedOf('contents: full', PUBLISH_CAP)
  refused(() => buildPublished(A, full, sealedOf(KEY, PUBLISH_CAP), 'base'), 'published.too-long')
  // key-only fits for base but not for eth by prefix, and not for arb by its lower cap
  const k = sealedOf(KEY, PUBLISH_CAP - envLen - 2)
  assert.equal(buildPublished(A, full, k, 'base').contents, 'key-only')
  refused(() => buildPublished(A, full, k, 'eth'), 'published.too-long')
  refused(() => buildPublished(A, full, k, 'arb'), 'published.too-long')
})

test('unlock mismatch -> published.unlock-mismatch', () => {
  const f = sealedOf('contents: full', 500)
  const k = sealedOf(KEY, 500)
  refused(() => buildPublished({ ...A, unlock: '2099-01-01T00:00:00Z' }, f, k, 'arb'), 'published.unlock-mismatch')
  refused(() => buildPublished(A, f.replace(UNLOCK, '2099-01-01T00:00:00Z'), k, 'arb'), 'published.unlock-mismatch')
  refused(() => buildPublished(A, f, k.replace(UNLOCK, '2099-01-01T00:00:00Z'), 'arb'), 'published.unlock-mismatch')
  refused(() => buildPublished(A, 'no unlock line', k, 'sol'), 'published.unlock-mismatch')
})

// Task S3: STRUCTURE.txt (the vault's shape, local only, R44 class) beside the package never reaches
// any destination's published text.
test('S3: the published text of every destination, built from a package holding STRUCTURE.txt, never carries it', () => {
  const canary = 'ZZCANARYS3PUBLISHED'
  const { dir } = makePkg('two-layer', { withKey: true, extra: {
    'STRUCTURE.txt': `== vault-timelock structure: shape only, every value removed (LOCAL ONLY, never published) ==\nformat: vault-timelock-structure/1\n${canary}\n== end ==\n`,
    'MANIFEST.csv': 'item_id,sha256\n', 'README.txt': 'readme\n' } })
  const f = buildSealed(dir, { contents: 'full', now: NOW })
  const k = buildSealed(dir, { contents: 'key-only', arId: AR, now: NOW })
  for (const d of ['eth', 'arb', 'base', 'btc', 'arweave', 'sol'] as Dest[]) {
    const t = dec(buildPublished(A, f, k, d).bytes)
    assert.ok(!t.includes(canary) && !t.includes('STRUCTURE') && !t.includes('vault-timelock-structure'), `${d}: STRUCTURE.txt reached the published text`)
  }
})

// Task SP (R74): SEALED-plaintext.txt (every entry decrypted, written by open --plaintext, local only) beside
// the package never reaches any destination's published text.
test('SP: the published text of every destination, built from a package holding SEALED-plaintext.txt, never carries it', () => {
  const canary = 'ZZCANARYSPPUBLISHED'
  const { dir } = makePkg('two-layer', { withKey: true, extra: {
    'SEALED-plaintext.txt': `== vault-timelock plaintext: every entry, decrypted (LOCAL ONLY — contains secrets) ==\nformat: vault-timelock-plaintext/1\n  password : ${canary}\n== end (1 items, 0 files) ==\n`,
    'MANIFEST.csv': 'item_id,sha256\n', 'README.txt': 'readme\n' } })
  const f = buildSealed(dir, { contents: 'full', now: NOW })
  const k = buildSealed(dir, { contents: 'key-only', arId: AR, now: NOW })
  for (const d of ['eth', 'arb', 'base', 'btc', 'arweave', 'sol'] as Dest[]) {
    const t = dec(buildPublished(A, f, k, d).bytes)
    assert.ok(!t.includes(canary) && !t.includes('SEALED-plaintext') && !t.includes('vault-timelock-plaintext'), `${d}: SEALED-plaintext.txt reached the published text`)
  }
})

test('sealed texts must be the right forms -> published.sealed-form', () => {
  const f = sealedOf('contents: full', 500)
  const k = sealedOf(KEY, 500)
  refused(() => buildPublished(A, k, k, 'arb'), 'published.sealed-form')
  refused(() => buildPublished(A, f, f, 'arb'), 'published.sealed-form')
  refused(() => buildPublished(A, f, sealedOf(`contents: key-only (payload: ar://${'B'.repeat(43)})`, 500), 'arb'), 'published.sealed-form')
})

test('envelope rules still apply (note / ar id)', () => {
  const f = sealedOf('contents: full', 500)
  const k = sealedOf(KEY, 500)
  refused(() => buildPublished({ ...A, arId: 'short' }, f, k, 'arb'), 'envelope.ar-id')
  refused(() => buildPublished({ ...A, note: ' x' }, f, k, 'arb'), 'note.whitespace')
})

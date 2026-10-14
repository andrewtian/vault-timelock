// Synthetic package fixtures for the timelocked-text tests: a copy of broadcast/test/offline/fixtures.ts (core cannot depend on broadcast:
// a release treats a core devDependency on vt-broadcast as dev-only). No real keys, no real data.
import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

export const HASH = '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971'
export const GENESIS = 1692803367
export const PERIOD = 3
export const ROUND = 500000000
export const UNLOCK = new Date((GENESIS + (ROUND - 1) * PERIOD) * 1000).toISOString().replace('.000Z', 'Z')
export const AR = 'A'.repeat(43)
export const NOW = 1.8e9 // 2027, before ROUND is reached

export const CHAIN_INFO = {
  public_key: '83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a',
  period: PERIOD,
  genesis_time: GENESIS,
  hash: HASH,
  groupHash: 'f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e',
  schemeID: 'bls-unchained-g1-rfc9380',
  metadata: { beaconID: 'quicknet' },
}

// Deterministic pseudo-random bytes.
export function fill(seed: string, n: number): Buffer {
  const out: Buffer[] = []
  let len = 0
  for (let i = 0; len < n; i++) {
    const h = createHash('sha256').update(`${seed}:${i}`).digest()
    out.push(h)
    len += h.length
  }
  return Buffer.concat(out).subarray(0, n)
}

// An age stanza body as age writes it (Task S1, audit CD-minor): unpadded standard base64 in
// 64-column lines, ended by exactly one SHORT line (< 64 chars, possibly empty).
export function stanzaBody(bytes: Buffer): string {
  const b64 = bytes.toString('base64').replace(/=+$/, '')
  let out = ''
  for (let i = 0; i < b64.length; i += 64) out += b64.slice(i, i + 64) + '\n'
  return b64.length % 64 === 0 ? out + '\n' : out
}

// A synthetic binary age file with a tlock stanza (parsing only; nothing is encrypted). Its header
// has the shape of real `tle` output: a 128-byte body (lines of 64, 64 and 43) and a 43-char MAC.
export function tlockFile(round: string | number = ROUND, hash = HASH, seed = 'tlock', size = 700): Buffer {
  const head = `age-encryption.org/v1\n-> tlock ${round} ${hash}\n${stanzaBody(fill(seed + 'b', 128))}--- ${fill(seed + 'm', 32).toString('base64').replace(/=+$/, '')}\n`
  return Buffer.concat([Buffer.from(head, 'latin1'), fill(seed, size)])
}

// age ASCII armor, written independently of src/armor.ts: header, padded base64 in 64-column
// lines, footer, all "\n" (what `age -a` and `tle --armor` write).
export function pem(b: Buffer): string {
  return `-----BEGIN AGE ENCRYPTED FILE-----\n${b.toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END AGE ENCRYPTED FILE-----\n`
}

export function x25519File(seed = 'vault', size = 3000): Buffer {
  const head = `age-encryption.org/v1\n-> X25519 ${fill(seed + 'e', 32).toString('base64').replace(/=+$/, '')}\n${fill(seed + 'b', 32).toString('base64').replace(/=+$/, '')}\n--- ${fill(seed + 'm', 32).toString('base64').replace(/=+$/, '')}\n`
  return Buffer.concat([Buffer.from(head, 'latin1'), fill(seed, size)])
}

export type Kind = 'two-layer' | 'one-layer' | 'secret' | 'raw' | 'tar+gzip'

// Every package dir is removed when the test process exits (Task H0: they used to pile up in the temp
// dir, thousands per mutation run).
const made: string[] = []
function tempPkgDir(): string {
  if (made.length === 0) process.once('exit', () => { for (const d of made) rmSync(d, { recursive: true, force: true }) })
  const dir = mkdtempSync(join(tmpdir(), 'vt-pkg-'))
  made.push(dir)
  return dir
}

// `files` is always the BINARY content (what SEALED.txt describes). Options (Task S1):
//   armor: write every .age file (or the named ones) ASCII-armored, plus the ARMOR marker, as
//          `--armor` does; withKey: add the two-layer recovery file unlock-KEY.age (an X25519 file).
export function makePkg(kind: Kind, o: { round?: string | number; stanzaRound?: string | number; stanzaHash?: string; extra?: Record<string, Buffer | string>; armor?: boolean | string[]; withKey?: boolean } = {}): { dir: string; files: Record<string, Buffer> } {
  const dir = tempPkgDir()
  const sr = o.stanzaRound ?? ROUND
  const files: Record<string, Buffer> = {}
  if (kind === 'two-layer') {
    files['unlock-TIME.age'] = tlockFile(sr, o.stanzaHash ?? HASH, 'unlock', 300)
    files['vault.tar.gz.age'] = x25519File('vault', 3000)
    if (o.withKey === true) files['unlock-KEY.age'] = x25519File('recovery', 200)
  } else if (kind === 'one-layer') files['vault.tar.gz.age'] = tlockFile(sr, o.stanzaHash ?? HASH, 'one', 900)
  else if (kind === 'secret') files['secret.tar.gz.age'] = tlockFile(sr, o.stanzaHash ?? HASH, 'sec', 900)
  else {
    files['payload.age'] = tlockFile(sr, o.stanzaHash ?? HASH, 'pay', 1200)
    files['encoding'] = Buffer.from(kind)
  }
  const armored = (n: string) => n.endsWith('.age') && (o.armor === true || (Array.isArray(o.armor) && o.armor.includes(n)))
  for (const [n, b] of Object.entries(files)) writeFileSync(join(dir, n), armored(n) ? pem(b) : b)
  if (o.armor !== undefined && o.armor !== false) writeFileSync(join(dir, 'ARMOR'), 'pem\n')
  writeFileSync(join(dir, 'chain-info.json'), JSON.stringify(CHAIN_INFO))
  writeFileSync(join(dir, 'round'), `${o.round ?? ROUND}\n`)
  for (const [n, b] of Object.entries(o.extra ?? {})) writeFileSync(join(dir, n), b)
  return { dir, files }
}

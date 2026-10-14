// SYNTHETIC inputs for the vt decrypt tests. Everything is made here: a throw-away drand-shaped chain (a made-up BLS key, so a test
// can sign any round, past or future), made-up passphrases, freshly generated age identities, made-up archive files. Nothing real,
// nothing from disk or the network. (The chain is the web Open fixtures' construction, web/test/open-fixtures.js.)
import { createHash } from 'node:crypto'
import { gzipSync } from 'node:zlib'
import { bls12_381 as bls } from '@noble/curves/bls12-381'
import { Encrypter, generateHybridIdentity, generateX25519Identity, identityToRecipient } from 'age-encryption'
import { createTimelockEncrypter } from 'tlock-js/drand/timelock-encrypter.js'
import { encryptAge } from 'tlock-js/age/age-encrypt-decrypt.js'
import { encodeArmor } from 'tlock-js/age/armor.js'
import { armor, dearmor } from '../../src/text/armor.ts'
import { QUICKNET } from '../../src/text/drand.ts'
import { buildSealedFrom, mapReader } from '../../src/text/sealed-from.ts'
import type { FetchRoundSignature } from '../../src/decrypt/index.ts'

const SK = 0x1234567890abcdef1234567890abcdef1234567890abcdefn
const DST = 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_'
const roundId = (round: number): Buffer => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(round)); return createHash('sha256').update(b).digest() }

/** The synthetic chain: quicknet's shape and hash, a made-up public key (G2). */
export const SYNTH_INFO = { ...QUICKNET, public_key: bls.G2.ProjectivePoint.BASE.multiply(SK).toHex(true) }
/** The synthetic chain's signature for `round` (hex, 48-byte G1): what the relay would answer for drand quicknet. */
export const signatureFor = (round: number): string => {
  const h = bls.G1.hashToCurve(roundId(round), { DST }) as unknown as InstanceType<typeof bls.G1.ProjectivePoint>   // a projective G1 point at runtime
  return h.multiply(SK).toHex(true)
}

export const roundAtMs = (ms: number): number => Math.ceil((ms / 1000 - QUICKNET.genesis_time) / QUICKNET.period) + 1
export const PAST_ROUND = 1_000_000                       // 2023-09: long published
export const FUTURE_ROUND = roundAtMs(Date.UTC(2100, 0, 1))
export const AR = 'B'.repeat(43)

/** A fake relay: answers the synthetic signature for rounds `published` says are out, null otherwise; records every call. */
export function fakeFetcher(published: (round: number) => boolean = () => true): { fetch: FetchRoundSignature; calls: Array<[string, number]> } {
  const calls: Array<[string, number]> = []
  return { calls, fetch: async (hash, round) => { calls.push([hash, round]); return published(round) ? signatureFor(round) : null } }
}

const client = (info: object = SYNTH_INFO) => ({ chain: () => ({ info: async () => info }) }) as unknown as Parameters<typeof createTimelockEncrypter>[0]
/** tlock-js's encryption (what `tle` / Open's timelockEncrypt write) to the synthetic chain → BINARY age. */
export async function tlockBin(round: number, plain: Uint8Array | string, info: object = SYNTH_INFO): Promise<Uint8Array> {
  const bytes = typeof plain === 'string' ? Buffer.from(plain) : Buffer.from(plain)
  return dearmor(encodeArmor(await encryptAge(bytes, createTimelockEncrypter(client(info), round))))
}

export const PASSPHRASE = 'synthetic correct horse battery staple'
/** age scrypt; a low work factor keeps the tests fast. */
export async function passphraseBin(plain: Uint8Array | string, passphrase = PASSPHRASE, logN = 10): Promise<Uint8Array> {
  const e = new Encrypter()
  e.setPassphrase(passphrase)
  e.setScryptWorkFactor(logN)
  return e.encrypt(plain)
}

export async function newIdentity(pq = false): Promise<{ identity: string; recipient: string }> {
  const identity = pq ? await generateHybridIdentity() : await generateX25519Identity()
  return { identity, recipient: await identityToRecipient(identity) }
}
export async function identityBin(plain: Uint8Array | string, ...recipients: string[]): Promise<Uint8Array> {
  const e = new Encrypter()
  for (const r of recipients) e.addRecipient(r)
  return e.encrypt(plain)
}

/** An age-keygen style identity file around `identity`. */
export const keygenFile = (identity: string, recipient: string): string =>
  `# created: 2026-10-14T00:00:00Z\n# public key: ${recipient}\n${identity}\n`

export { armor }

// a ustar archive of [[name, content, type?], …] (repeated names and any type allowed: tests build hostile archives)
export function tar(files: Array<[string, string | Uint8Array, string?]> | Record<string, string | Uint8Array>): Buffer {
  const blocks: Buffer[] = []
  const octal = (n: number, w: number): string => n.toString(8).padStart(w - 1, '0') + '\0'
  for (const [name, content, type = '0'] of Array.isArray(files) ? files : Object.entries(files)) {
    const body = Buffer.from(content as string)
    const h = Buffer.alloc(512)
    h.write(name, 0, 'utf8'); h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116)
    h.write(octal(body.length, 12), 124); h.write(octal(0, 12), 136); h.write('        ', 148); h.write(type, 156); h.write('ustar\0', 257); h.write('00', 263)
    let sum = 0; for (const b of h) sum += b
    h.write(octal(sum, 7).slice(0, 6) + '\0 ', 148)
    blocks.push(h, body, Buffer.alloc((512 - (body.length % 512)) % 512))
  }
  blocks.push(Buffer.alloc(1024))
  return Buffer.concat(blocks)
}
export const targz = (files: Parameters<typeof tar>[0]): Uint8Array => new Uint8Array(gzipSync(tar(files)))

/** pax extended header body: one `path` record whose length counts BYTES. */
export const pax = (path: string): Buffer => {
  const body = Buffer.from(` path=${path}\n`)
  let len = body.length + 1
  while (String(len).length + body.length !== len) len = String(len).length + body.length
  return Buffer.concat([Buffer.from(String(len)), body])
}

export const VAULT_FILES: Record<string, string> = {
  'items/aaaa.json': '{"synthetic":"item one"}\n',
  'items/bbbb.json': '{"synthetic":"item two"}\n',
  'MANIFEST.csv': 'id,sha\naaaa,00\nbbbb,11\n',
}

export type SealedKind = 'two-layer' | 'vault' | 'secret' | 'raw' | 'tar+gzip'
/**
 * A synthetic package, sealed by the repo's own seal-text path (buildSealedFrom). -> { sealed (bare SEALED.txt), published
 * (with the two header lines and a note), identity (two-layer: the one-time key), tgz (the archive), payload }.
 */
export async function makeSealed({ kind = 'two-layer', round = PAST_ROUND, contents = 'full', payload = 'synthetic payload bytes\n',
  vaultFiles = VAULT_FILES, keyLayer }: { kind?: SealedKind; round?: number; contents?: 'full' | 'key-only'; payload?: string;
  vaultFiles?: Parameters<typeof tar>[0]; keyLayer?: string } = {}) {
  const base: Record<string, Uint8Array | string> = {
    'chain-info.json': JSON.stringify({ hash: QUICKNET.hash, genesis_time: QUICKNET.genesis_time, period: QUICKNET.period, schemeID: QUICKNET.schemeID }),
    round: `${round}\n`,
  }
  const tgz = targz(vaultFiles)
  let pkg: Record<string, Uint8Array | string>
  let identity: string | null = null
  if (kind === 'two-layer') {
    const id = await newIdentity()
    identity = id.identity
    pkg = { ...base, 'unlock-TIME.age': await tlockBin(round, keyLayer ?? `${id.identity}\n`), 'vault.tar.gz.age': await identityBin(tgz, id.recipient) }
  } else if (kind === 'vault') pkg = { ...base, 'vault.tar.gz.age': await tlockBin(round, tgz) }
  else if (kind === 'secret') pkg = { ...base, 'secret.tar.gz.age': await tlockBin(round, tgz) }
  else if (kind === 'raw') pkg = { ...base, 'payload.age': await tlockBin(round, payload), encoding: 'raw' }
  else pkg = { ...base, 'payload.age': await tlockBin(round, tgz), encoding: 'tar+gzip' }
  const files = new Map(Object.entries(pkg).map(([k, v]) => [k, typeof v === 'string' ? new TextEncoder().encode(v) : new Uint8Array(v)]))
  const sealed = buildSealedFrom(mapReader(files), { contents, arId: contents === 'key-only' ? AR : undefined, now: QUICKNET.genesis_time })
  const iso = new Date((QUICKNET.genesis_time + (round - 1) * QUICKNET.period) * 1000).toISOString().replace('.000Z', 'Z')
  const published = `vault-timelock/1 unlock=${iso}\nar://${AR}\nsynthetic note\n\n${sealed}`
  return { sealed, published, identity, tgz, payload, iso, files }
}

/** The [file] lines of a SEALED.txt, read by the test itself: name → { size, sha256 }. */
export function fileLines(sealed: string): Map<string, { size: number; sha256: string }> {
  const out = new Map<string, { size: number; sha256: string }>()
  for (const m of sealed.matchAll(/^\[file ([A-Za-z0-9][A-Za-z0-9._-]*) bytes=(\d+) sha256=([0-9a-f]{64})\]$/gm)) out.set(m[1], { size: Number(m[2]), sha256: m[3] })
  return out
}

export const sha256 = (b: Uint8Array | string): string => createHash('sha256').update(b).digest('hex')
export const text = (b: Uint8Array): string => new TextDecoder().decode(b)

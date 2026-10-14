// SYNTHETIC timelocked texts for the Open and New job tests. Everything is made here: a throw-away drand-shaped chain (a made-up BLS
// key, so the test can sign any round), made-up files, a made-up age identity. Nothing real, nothing from disk or the network.
import { createHash } from 'node:crypto'
import { gzipSync } from 'node:zlib'
import { bls12_381 as bls } from '@noble/curves/bls12-381'
import { Encrypter, generateIdentity, identityToRecipient } from 'age-encryption'
import { timelockEncrypt } from 'tlock-js'
import { dearmor } from '@vault-timelock/core/text/armor.ts'
import { QUICKNET } from '@vault-timelock/core/text/drand.ts'
import { buildSealedFrom, mapReader } from '@vault-timelock/core/text/sealed-from.ts'

const SK = 0x1234567890abcdef1234567890abcdef1234567890abcdefn
const DST = 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_'
const roundId = (round) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(round)); return createHash('sha256').update(b).digest() }

// The synthetic chain's info: quicknet's shape and hash, a made-up public key (G2).
export const SYNTH_INFO = { ...QUICKNET, public_key: bls.G2.ProjectivePoint.BASE.multiply(SK).toHex(true) }
export const beaconFor = (round) => {
  const signature = bls.G1.hashToCurve(roundId(round), { DST }).multiply(SK).toHex(true)
  return { round, randomness: createHash('sha256').update(Buffer.from(signature, 'hex')).digest('hex'), signature }
}
const encClient = { options: { disableBeaconVerification: true, noCache: true }, chain: () => ({ baseUrl: '', info: async () => SYNTH_INFO }), latest: async () => { throw new Error('unused') }, get: async () => { throw new Error('unused') } }
const tlock = async (round, bytes) => dearmor(await timelockEncrypt(round, Buffer.from(bytes), encClient))

export const roundAtMs = (ms) => Math.ceil((ms / 1000 - QUICKNET.genesis_time) / QUICKNET.period) + 1
export const PAST_ROUND = 1_000_000      // 2023-09: long published
export const FUTURE_ROUND = roundAtMs(Date.UTC(2100, 0, 1))
export const AR = 'B'.repeat(43)

// a ustar archive of {name: string|Uint8Array} or of [[name, content], …] (the array form allows repeated names and a chosen type: [name, content, type])
export function tar(files) {
  const blocks = []
  const octal = (n, w) => n.toString(8).padStart(w - 1, '0') + '\0'
  for (const [name, content, type = '0'] of Array.isArray(files) ? files : Object.entries(files)) {
    const body = Buffer.from(content)
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
export const targz = (files) => gzipSync(tar(files))

export const VAULT_FILES = { 'items/aaaa.json': '{"synthetic":"item one"}\n', 'items/bbbb.json': '{"synthetic":"item two"}\n', 'MANIFEST.csv': 'id,sha\naaaa,00\nbbbb,11\n' }

// -> { text (published form), sealed (bare SEALED.txt), files (what Open must restore: name → string) }
export async function makeTexts({ kind = 'two-layer', round = PAST_ROUND, contents = 'full', payload = 'synthetic payload bytes\n', vaultFiles = VAULT_FILES } = {}) {
  const base = { 'chain-info.json': JSON.stringify({ hash: QUICKNET.hash, genesis_time: QUICKNET.genesis_time, period: QUICKNET.period, schemeID: QUICKNET.schemeID }), round: `${round}\n` }
  let pkg, restored
  if (kind === 'two-layer') {
    const id = await generateIdentity()
    const e = new Encrypter(); e.addRecipient(await identityToRecipient(id))
    const tgz = targz(vaultFiles)
    pkg = { ...base, 'unlock-TIME.age': await tlock(round, `${id}\n`), 'vault.tar.gz.age': await e.encrypt(tgz) }
    restored = { 'identity.key': `${id}\n`, 'vault.tar.gz': tgz, ...(Array.isArray(vaultFiles) ? {} : vaultFiles) }
  } else if (kind === 'vault') {
    const tgz = targz(vaultFiles)
    pkg = { ...base, 'vault.tar.gz.age': await tlock(round, tgz) }
    restored = { 'vault.tar.gz': tgz, ...VAULT_FILES }
  } else {
    pkg = { ...base, 'payload.age': await tlock(round, payload), encoding: 'raw' }
    restored = { content: payload }
  }
  const files = new Map(Object.entries(pkg).map(([k, v]) => [k, typeof v === 'string' ? new TextEncoder().encode(v) : new Uint8Array(v)]))
  const sealed = buildSealedFrom(mapReader(files), { contents, arId: contents === 'key-only' ? AR : undefined, now: QUICKNET.genesis_time })
  const iso = new Date((QUICKNET.genesis_time + (round - 1) * QUICKNET.period) * 1000).toISOString().replace('.000Z', 'Z')
  const text = `vault-timelock/1 unlock=${iso}\nar://${AR}\nsynthetic note\n\n${sealed}`
  return { text, sealed, restored, round, iso }
}

// A fake drand behind the relay's route: serves /relay/drand/<hash>/public/{latest,<round>} for rounds <= `latest`.
export function fakeDrand({ latest }) {
  const calls = []
  const fetch = async (url) => {
    const u = String(url); calls.push(u)
    const m = new RegExp(`^/relay/drand/${QUICKNET.hash}/public/(latest|[1-9][0-9]*)$`).exec(u)
    const ok = (b) => new Response(JSON.stringify(b), { status: 200, headers: { 'content-type': 'application/json' } })
    if (!m) return new Response('{}', { status: 404 })
    if (m[1] === 'latest') return ok(beaconFor(latest()))
    return Number(m[1]) > latest() ? new Response('{}', { status: 404 }) : ok(beaconFor(Number(m[1])))
  }
  return { fetch, calls }
}

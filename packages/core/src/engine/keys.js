// @ts-check
// PORTED (R69) from the prototype, tag add7-00927d6ade7f, src/mainnet/keys.js (sha256 7d30e431a4a4e1296380cdc3e7fda24962dd36aac6a7adf6498fc044f24dad3f).
// PER-CHAIN keys: a new or imported EOA for each chain, with a downloaded backup for each; that key broadcasts the chain's
// txs. Keys live in this tab's memory only. The ONLY persisted secret is each operator-downloaded age file
// (typage passphrase mode = scrypt): plaintext `{ chain, address, secret, createdAt }` (createdAt = UTC ISO-8601, "Z").
// Nothing goes to browser storage, URLs, logs or the relay. (Port: comment reworded — the static scan bans the storage API names.)
// Canonical changes (E2, binding carry-forward from W2 and R71): new backups APPEND an optional `network` after the four
// prototype keys, so the file stays byte-compatible with the prototype's (same age passphrase mode, same JSON key
// order); a prototype backup has no `network` (decryptKeyFile returns null; gates/backup.ts asks for the operator's
// tick). `openBackup` is the one place the age file is opened (decryptKeyFile and gates/backup.ts loadBackup use it).
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { Keypair } from '@solana/web3.js'
import { base58 } from '@scure/base'
import { Decrypter, Encrypter } from 'age-encryption'
import { randomPrivateKeyBytes } from '@scure/btc-signer/utils.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { btcFromSecret } from '../chains/btc.js'

export const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
/** @typedef {import('../chains/types.ts').EthKey} EthKey @typedef {import('../chains/types.ts').SolKey} SolKey @typedef {import('../chains/types.ts').Key} Key */
/** @type {(m: string) => never} */
const fail = (m) => { throw new Error(m) }

// E3 review m-6: the secret (and the SOL Keypair, which holds it) are non-enumerable — JSON.stringify, object spread,
// Object.keys and util.inspect never show them; code that needs them names them (key.secret, key.kp).
/** @template T @param {Record<string, unknown>} o @param {Record<string, unknown>} h @returns {T} */
function hidden(o, h) {
  for (const [k, v] of Object.entries(h)) Object.defineProperty(o, k, { value: v, enumerable: false, writable: false, configurable: false })
  return /** @type {T} */ (/** @type {unknown} */ (o))
}
// ETH: 0x + 64 hex, 0 < k < n (secp256k1 order)
/** @param {unknown} input @returns {EthKey} */
export function ethFromSecret(input) {
  const hex = String(input).trim()
  if (!/^0x[0-9a-fA-F]{64}$/.test(hex)) fail('ETH key must be 0x followed by exactly 64 hex characters')
  const k = BigInt(hex)
  if (k === 0n || k >= SECP256K1_N) fail('not a valid secp256k1 private key (need 0 < k < n)')
  const secret = hex.toLowerCase(), account = privateKeyToAccount(/** @type {`0x${string}`} */ (secret))
  return /** @type {EthKey} */ (hidden({ chain: 'eth', account, address: account.address }, { secret }))
}
// SOL: base58 64-byte secret key, or the Solana CLI JSON array of 64 numbers; the public half must match (fromSecretKey checks)
/** @param {unknown} input @returns {SolKey} */
export function solFromSecret(input) {
  const t = String(input).trim()
  /** @type {Uint8Array} */
  let bytes
  if (t.startsWith('[')) {
    /** @type {unknown} */
    let arr; try { arr = JSON.parse(t) } catch { fail('SOL key: not a JSON array') }
    if (!Array.isArray(arr) || arr.length !== 64 || !arr.every((x) => Number.isInteger(x) && x >= 0 && x <= 255)) fail('SOL key: the JSON array must hold exactly 64 numbers 0–255')
    bytes = Uint8Array.from(/** @type {number[]} */ (arr))
  } else {
    if (!/^[1-9A-HJ-NP-Za-km-z]+$/.test(t)) fail('SOL key: not base58 (or a JSON array)')
    try { bytes = base58.decode(t) } catch { fail('SOL key: not base58') }
  }
  if (bytes.length !== 64) fail(`SOL key: ${bytes.length} bytes, need the 64-byte secret key`)
  /** @type {Keypair} */
  let kp; try { kp = Keypair.fromSecretKey(bytes) } catch { fail('SOL key: the public half does not match the secret (corrupted key)') }
  return /** @type {SolKey} */ (hidden({ chain: 'sol', address: kp.publicKey.toBase58() }, { kp, secret: base58.encode(bytes) }))
}
// BTC (E7b): the backup holds the same fields as eth / sol — { chain: 'btc', address (the bech32 p2wpkh lane address), secret (64 hex),
// network } — but the address depends on the network, so a btc key is made WITH its network (a backup without one is not a btc key).
/** @param {unknown} input @param {unknown} network @returns {import('../chains/types.ts').BtcKey} */
export function btcKeyFromSecret(input, network) {
  if (network !== 'local' && network !== 'testnet' && network !== 'mainnet') fail('a BTC key needs its network (local, testnet or mainnet): its address depends on it')
  return /** @type {any} */ (btcFromSecret(input, /** @type {'local' | 'testnet' | 'mainnet'} */ (network)))
}
/** @type {(chain: string, s: unknown, network?: unknown) => Key} */
export const fromSecret = (chain, s, network = null) => (chain === 'eth' ? ethFromSecret(s) : chain === 'btc' ? btcKeyFromSecret(s, network) : solFromSecret(s))
/** @type {(chain: string, network?: unknown) => Key} */
export const newKey = (chain, network = null) => (chain === 'eth' ? ethFromSecret(generatePrivateKey()) : chain === 'btc' ? btcKeyFromSecret(bytesToHex(randomPrivateKeyBytes()), network) : solFromSecret(base58.encode(Keypair.generate().secretKey)))

// Passphrase (M7): ≥ 6 DISTINCT EFF-style words with ≥ 25 letters in total, or ≥ 20 chars from ≥ 3 classes without repeats.
/** @param {string} p @returns {{ ok: boolean, hint: string }} */
export function passphraseCheck(p) {
  const words = p.trim().split(/[\s-]+/).filter(Boolean)
  const letters = words.join('').length
  const wordsOk = words.length >= 6 && words.every((w) => /^[a-z]{3,}$/i.test(w)) && new Set(words.map((w) => w.toLowerCase())).size >= 6 && letters >= 25
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9\s]/].filter((r) => r.test(p)).length
  const repeats = /(.{3,})\1/i.test(p) || /(.)\1{3,}/.test(p)
  const charsOk = p.length >= 20 && classes >= 3 && !repeats
  return { ok: wordsOk || charsOk, hint: wordsOk ? `${words.length} words ✓` : charsOk ? `${p.length} chars, ${classes} classes ✓` : repeats ? 'repeated pieces are not allowed' : 'need ≥ 6 distinct words (≥ 25 letters, e.g. six EFF dice words) or ≥ 20 chars with ≥ 3 of a-z A-Z 0-9 symbols' }
}
export const utcStamp = (d = new Date()) => d.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z')
// M8: the file name carries no address (it would link the disk to the address); the address is inside, encrypted
/** @type {(key: { chain: string }, d?: Date) => string} */
export const keyFileName = (key, d = new Date()) => `vt-${key.chain}-key-${utcStamp(d)}.age`
/** @param {Key} key @param {string} passphrase @param {string | null} [network] @returns {Promise<{ ct: Uint8Array }>} */
export async function encryptKey(key, passphrase, network = null) {
  const net = network ?? (key.chain === 'btc' ? key.network : null)
  if (key.chain === 'btc' && net !== key.network) fail('a BTC backup records the network its address was made for')
  const plain = JSON.stringify({ chain: key.chain, address: key.address, secret: key.secret, createdAt: new Date().toISOString(), ...(net ? { network: net } : {}) })
  const e = new Encrypter(); e.setPassphrase(passphrase)
  return { ct: await e.encrypt(plain) }
}
// I1: verify the SAVED FILE (re-selected by the operator, passphrase typed again) decrypts to exactly this key
/** @param {Uint8Array} bytes @param {string} passphrase @param {Key} key @returns {Promise<true>} */
export async function verifySavedFile(bytes, passphrase, key) {
  const { key: k } = await decryptKeyFile(bytes, passphrase, key.chain)
  if (k.address !== key.address || k.secret !== key.secret) fail('the selected file decrypts to a DIFFERENT key — pick the file you just saved')
  return true
}
// Import FROM a backup file: decrypt, check the chain and that the secret derives the recorded address.
// The decrypted plaintext of an age backup file (parsed JSON), or an Error: 'wrong passphrase or not a backup file' /
// 'not a key backup'. Nothing about the key is checked here.
/** @param {Uint8Array} bytes @param {string} passphrase @returns {Promise<any>} */
export async function openBackup(bytes, passphrase) {
  const d = new Decrypter(); d.addPassphrase(passphrase)
  /** @type {any} */
  let j; try { j = JSON.parse(await d.decrypt(bytes, 'text')) } catch (e) { fail(/JSON/.test(String(e)) ? 'not a key backup' : 'wrong passphrase or not a backup file') }
  return j
}
/** @param {Uint8Array} bytes @param {string} passphrase @param {string} chain @returns {Promise<{ key: Key, createdAt: string, network: string | null }>} */
export async function decryptKeyFile(bytes, passphrase, chain) {
  const j = await openBackup(bytes, passphrase)
  if (j?.chain !== chain) fail(`this backup is for ${j?.chain ?? 'an unknown chain'}, not ${chain}`)
  const key = fromSecret(chain, j.secret, j.network)
  if (key.address !== j.address) fail('backup is inconsistent: the secret does not derive the recorded address')
  return { key, createdAt: j.createdAt, network: typeof j.network === 'string' ? j.network : null }
}

// The one seam between the page and the core modules (W2 → W3). Everything the page needs from keys, message
// validation, part planning, links, prices and the executor is imported from HERE, so each rule has one source (core).
// W2's interim copies (web/src/ported/) are gone: these are the real modules of @vault-timelock/core.
import './polyfills.js'
import { refuse } from '@vault-timelock/core/contracts'
import { ethParts, solParts } from '@vault-timelock/core/chains/plan.js'
import { layoutMaxMemo } from '@vault-timelock/core/chains/sol.js'
import { ETH, SOL } from '@vault-timelock/core/chains/constants.js'

import * as coreKeys from '@vault-timelock/core/engine/keys.js'
import { btcFromSecret } from '@vault-timelock/core/chains/btc.js'

export const { encryptKey, openBackup, passphraseCheck, keyFileName } = coreKeys

// W7b: the keys of the three lanes. Core's engine/keys.js makes eth and sol keys; a BTC lane key is core's chains/btc.js
// btcFromSecret (64 hex secp256k1 secret → p2wpkh address on the NETWORK, so btc needs the network; the backup file is the
// same age file with { chain: 'btc', address, secret (hex), network }).
const hexOf = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('')
export function newKey(chain, network = null) {
  if (chain !== 'btc') return coreKeys.newKey(chain)
  for (;;) {
    try { return btcFromSecret(hexOf(globalThis.crypto.getRandomValues(new Uint8Array(32))), network) } catch { /* out of range: draw again */ }
  }
}
export function fromSecret(chain, secret, network = null) {
  return chain === 'btc' ? btcFromSecret(secret, network) : coreKeys.fromSecret(chain, secret)
}
// network: the page's network, used only for a btc backup that records none (the p2wpkh address is network-bound)
export async function decryptKeyFile(bytes, passphrase, chain, network = null) {
  if (chain !== 'btc') return coreKeys.decryptKeyFile(bytes, passphrase, chain)
  const j = await coreKeys.openBackup(bytes, passphrase)
  if (j?.chain !== 'btc') throw new Error(`this backup is for ${j?.chain ?? 'an unknown chain'}, not btc`)
  const made = typeof j.network === 'string' ? j.network : null
  const key = btcFromSecret(j.secret, made ?? network)
  if (key.address !== j.address) throw new Error('backup is inconsistent: the secret does not derive the recorded address')
  return { key, createdAt: j.createdAt, network: made }
}
export async function verifySavedFile(bytes, passphrase, key) {
  if (key.chain !== 'btc') return coreKeys.verifySavedFile(bytes, passphrase, key)
  const { key: k } = await decryptKeyFile(bytes, passphrase, 'btc', key.network)
  if (k.address !== key.address || k.secret !== key.secret) throw new Error('the selected file decrypts to a DIFFERENT key — pick the file you just saved')
  return true
}
export { validateMessage, sha256Hex } from '@vault-timelock/core/job'
export { MESSAGE_MAX } from '@vault-timelock/core/contracts'
// W7: the timelocked text. The ONE parser and validator of a published text (core: the parser-differential fix) and the
// pinned drand quicknet constants. The page has no second parser.
export { checkPayload, sealedFiles } from '@vault-timelock/core/text/payload.ts'
export { parseTlockStanza } from '@vault-timelock/core/text/sealed-from.ts'
export { armor } from '@vault-timelock/core/text/armor.ts'
export { QUICKNET, roundTime, roundAt, unlockIso } from '@vault-timelock/core/text/drand.ts'

// Message bytes are decoded strictly (Task 0 ruling 7): a decode failure IS message.utf8; nothing is replaced.
export function decodeUtf8(bytes) {
  let text
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes) } catch { refuse('message.utf8', 'the bytes are not valid UTF-8 (nothing was replaced or rewritten)') }
  return text
}

const enc = new TextEncoder()
// Per-chain part preview of a validated message, from the core planner (chains/plan.js, R72):
// { eth: { ok, parts: [{ i, n, size, header }], max, why }, sol: … }. size = payload bytes (lead + header + chunk).
export function previewParts(text, sha256) {
  const bytes = enc.encode(text), out = {}
  let solMax = SOL.MEMO_MAX
  try { solMax = Math.min(SOL.MEMO_MAX, layoutMaxMemo()) } catch { /* the cap stays MEMO_MAX */ }
  const lead = { eth: enc.encode(ETH.PREFIX).length, sol: 0 }
  for (const [chain, run, max] of [
    ['eth', () => ethParts(bytes, { sha256 }), ETH.TX_DATA_CAP],
    ['sol', () => solParts(bytes, solMax, { sha256 }), solMax],
  ]) {
    try {
      const parts = run().map((p) => ({ i: p.i, n: p.n, size: p.payload.length, header: p.payload.length - lead[chain] - p.chunk.length }))
      out[chain] = { ok: true, parts, max, why: '' }
    } catch (e) { out[chain] = { ok: false, parts: [], max, why: String(e?.message || e) } }
  }
  return out
}

// Decrypt (vt decrypt, lane W): the page's glue to @vault-timelock/core/decrypt. Every decision about the input (kind, form, refusals,
// archive safety) is core's; this file only (a) turns a dropped file into core's input, (b) wraps the relay's drand route as core's
// signature fetcher, and (c) lists an archive for display. Plaintext, passphrases and identities live in the caller's memory only:
// nothing here stores, logs or sends them.
import './polyfills.js'
import { PASTE_LIMIT, decryptAge, detectInput, listArchive, extractOne } from '@vault-timelock/core/decrypt'
import { isRefusal } from '@vault-timelock/core/contracts'
import { QUICKNET } from './core.js'
import { DrandError, escapeName, finalizeNames, relayDrandClient } from './open.js'

export { PASTE_LIMIT, isRefusal }

const AGE_BINARY_MAGIC = new TextEncoder().encode('age-encryption.org/v1\n')
const startsWith = (b, magic) => b.length >= magic.length && magic.every((x, i) => b[i] === x)

// A dropped / picked file → core's input: a binary .age stays bytes; anything that is strict UTF-8 text (armor, SEALED.txt, a
// published text) becomes a string; anything else stays bytes, so core refuses it with its own guard.
export function inputOfFile(bytes) {
  if (startsWith(bytes, AGE_BINARY_MAGIC)) return bytes
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes) } catch { return bytes }
}

// core's FetchRoundSignature over the relay's drand route (same path Open uses). null = drand has not published the round.
export function relaySignatureFetcher(client = relayDrandClient()) {
  return async (chainHash, round) => {
    if (chainHash !== QUICKNET.hash) throw new Error('this time lock is for a drand chain the relay does not serve')   // @guard:web.decrypt-chain
    let b
    try { b = await client.get(round) } catch (e) {
      if (e instanceof DrandError && (e.status === 404 || e.status === 425)) return null
      throw e
    }
    if (b.round !== round) throw new Error('the relay answered with another round')   // @guard:web.decrypt-round-echo
    return b.signature
  }
}

// -> { ok: true, detected } | { ok: false, guard, message }; never throws a refusal
export function readInput(input, limits) {
  try { return { ok: true, detected: detectInput(input, limits) } } catch (e) {
    if (isRefusal(e)) return { ok: false, guard: e.guardId, message: e.message }
    throw e
  }
}

// -> { ok: true, result } | { ok: false, guard, message }
export async function runDecrypt(input, how) {
  try { return { ok: true, result: await decryptAge(input, how) } } catch (e) {
    if (isRefusal(e)) return { ok: false, guard: e.guardId, message: e.message }
    throw e
  }
}

// The archive among a result: [{ orig, path (escaped, unique), name (download name), size, renamed }] or { error } when core refuses
// the archive (the raw file is still offered by the caller).
export async function listFiles(archive) {
  try {
    const entries = await listArchive(archive)
    return { entries: finalizeNames(entries.map((e) => ({ orig: e.path, path: e.path, size: e.size }))) }
  } catch (e) {
    if (isRefusal(e)) return { error: `${e.guardId}: ${e.message}` }
    throw e
  }
}

export const extractFile = (archive, orig) => extractOne(archive, orig)
export { escapeName }

// Overwrite the bytes the page owns (the decrypted files) with zeros. Safe to call twice.
export function wipeResult(result) { if (result) for (const f of result.files) f.bytes.fill(0) }

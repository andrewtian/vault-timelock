// One age file: what it is (from its header stanzas) and how it opens. Browser-safe.
//   scrypt                   → a passphrase (age-encryption's scrypt identity; the work factor is bounded first)
//   X25519 / mlkem768x25519  → identities: AGE-SECRET-KEY-1… / AGE-SECRET-KEY-PQ-1… lines (age-keygen's file)
//   tlock <round> <hash>     → drand quicknet's signature for the round, from the CALLER's fetcher (the relay), never before the
//                              round by how.now; the IBE is tlock-js's (crypto/ibe.js: decryptOnG2, the code Open's timelockDecrypt
//                              runs for quicknet), framed by age-encryption as a custom identity. Its FO check (U = rP) fails closed
//                              on any other signature, so the signature needs no separate verification.
// Every refusal is a decrypt.* guard (refuse.ts). Nothing logs; no message carries plaintext, a passphrase or an identity.
import { Decrypter } from 'age-encryption'
import type { Identity, Stanza } from 'age-encryption'
import { decryptOnG2 } from 'tlock-js/crypto/ibe.js'
import { dearmor } from '../text/armor.ts'
import { latin1 } from '../text/bytes.ts'
import { QUICKNET, roundTime, unlockIso } from '../text/drand.ts'
import { isRefusal } from '../text/guard.ts'
import { parseAgeHeader, parseTlockStanza } from '../text/sealed-from.ts'
import type { AgeKind, DecryptHow, DecryptLimits, FetchRoundSignature } from './api.ts'
import { DECRYPT_LIMITS } from './api.ts'
import { bounded, refuseFormat, refuseIdentity, refuseKind, refusePassphrase, refuseTooEarly } from './refuse.ts'

const AGE_MAGIC = 'age-encryption.org/v1\n'
const ARMOR_BEGIN = '-----BEGIN AGE ENCRYPTED FILE-----'
export const SEALED_TITLE = '== vault-timelock sealed package: self-contained, age + drand timelock =='
const PUBLISHED_HEAD = 'vault-timelock/1 unlock='
const IDENTITY_TYPES = new Set(['X25519', 'mlkem768x25519'])
const IDENTITY_LINE = /^AGE-SECRET-KEY-(?:PQ-)?1[0-9A-Z]+$/
const SCRYPT_LOGN_MAX = 20                   // age-encryption 0.3.1 refuses more itself; a higher limits.scryptLogN cannot raise it
const SIG_HEX = /^[0-9a-f]{96}$/          // quicknet (bls-unchained-g1-rfc9380): a compressed G1 point, 48 bytes
const enc = new TextEncoder()

export const limitsOf = (l: Partial<DecryptLimits> | undefined): DecryptLimits => ({ ...DECRYPT_LIMITS, ...(l ?? {}) })

/** The input, classified: binary age bytes, or the (normalized) text of armor / a SEALED.txt / a published text. */
export type Classified =
  | { form: 'armored' | 'binary'; bin: Uint8Array }
  | { form: 'sealed' | 'published'; text: string }

/**
 * Classify the raw input. Bounded first (limits.input). Text is normalized only in ways that cannot change what is decrypted: a
 * leading BOM and surrounding whitespace dropped, CRLF read as LF, exactly one final LF. Armor is then de-armored strictly (canonical
 * age armor only); a SEALED.txt is left to its one parser (payload.ts).
 */
export function classify(input: string | Uint8Array, limits: DecryptLimits): Classified {
  if (typeof input !== 'string' && !(input instanceof Uint8Array)) refuseFormat('the input is neither text nor bytes')
  if (typeof input === 'string') bounded(input.length, limits.input, 'the input')
  const raw = typeof input === 'string' ? enc.encode(input) : input
  bounded(raw.length, limits.input, 'the input')
  if (latin1(raw.subarray(0, AGE_MAGIC.length)) === AGE_MAGIC) {
    if (typeof input === 'string') refuseFormat('a binary age file was given as text: give its bytes')
    return { form: 'binary', bin: raw }
  }
  let text = ''
  try { text = typeof input === 'string' ? input : new TextDecoder('utf-8', { fatal: true }).decode(raw) } catch { refuseFormat('the input is not age armor, a binary .age file or a SEALED.txt (not UTF-8 text)') }
  text = `${text.replace(/^﻿/, '').replace(/\r\n/g, '\n').trim()}\n`
  if (text.startsWith(ARMOR_BEGIN)) {
    let bin: Uint8Array | null = null
    try { bin = dearmor(text) } catch (e) { if (!isRefusal(e)) throw e }
    if (bin === null) refuseFormat('the armor is not canonical age ASCII armor (one BEGIN line, 64-column base64, one END line, nothing else)')
    return { form: 'armored', bin }
  }
  if (text.startsWith(SEALED_TITLE)) return { form: 'sealed', text }
  if (text.startsWith(PUBLISHED_HEAD)) return { form: 'published', text }
  return refuseFormat('the input is not age armor, a binary .age file or a SEALED.txt')
}

/** What one age file needs, from its header. */
export interface AgeInfo { kind: AgeKind; round: number | null; chainHash: string | null; logN: number | null }

export function ageInfo(bin: Uint8Array, limits: DecryptLimits, what = 'the input'): AgeInfo {
  const h = parseAgeHeader(bin)
  if (h === null) refuseFormat(`${what} is not an age file (version line, stanzas, MAC line)`)
  const types = h.stanzas.map((s) => s.type)
  if (types.length === 1 && types[0] === 'scrypt') {
    const [, logS] = h.stanzas[0].args
    if (h.stanzas[0].args.length !== 2 || !/^[1-9]\d{0,2}$/.test(logS)) refuseFormat(`${what}: a malformed scrypt stanza`)
    bounded(Number(logS), Math.min(limits.scryptLogN, SCRYPT_LOGN_MAX), `${what}: the scrypt work factor (log2 N = ${logS})`)
    return { kind: 'passphrase', round: null, chainHash: null, logN: Number(logS) }
  }
  if (types.includes('tlock')) {
    const st = parseTlockStanza(bin)
    if (st === null) refuseKind(`${what}: a tlock stanza must be the only stanza, "-> tlock <round> <64-hex chain hash>"`)
    if (st.hash !== QUICKNET.hash) refuseKind(`${what} is time-locked to a drand chain other than quicknet (${st.hash.slice(0, 8)}…): this tool opens quicknet only`)
    const round = Number(st.round)
    if (!Number.isSafeInteger(round) || !Number.isFinite(roundTime(round) * 1000) || !isDate(round)) refuseFormat(`${what}: the tlock round is out of range`)
    return { kind: 'timelocked', round, chainHash: st.hash, logN: null }
  }
  if (types.some((t) => IDENTITY_TYPES.has(t)) && !types.includes('scrypt')) return { kind: 'identity', round: null, chainHash: null, logN: null }
  const shown = [...new Set(types)].slice(0, 4).map((t) => t.slice(0, 40)).join(', ')
  return refuseKind(`${what} is encrypted to recipients this tool cannot open (${shown}): it opens scrypt (passphrase), X25519 (identity) and drand quicknet tlock`)
}

const isDate = (round: number): boolean => { try { unlockIso(round); return true } catch { return false } }

/** Identity text → identity strings. Blank and `#` lines are skipped; anything else must be an age identity line. */
export function parseIdentities(text: string, limits: DecryptLimits): string[] {
  bounded(enc.encode(text).length, limits.secret, 'the identity text')
  const out: string[] = []
  const lines = text.replace(/^﻿/, '').split(/\r?\n/)
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i].trim()
    if (l === '' || l.startsWith('#')) continue
    if (!IDENTITY_LINE.test(l)) refuseIdentity(`line ${i + 1} of the identity text is not an age identity (AGE-SECRET-KEY-1…)`)
    out.push(l)
  }
  if (out.length === 0) refuseIdentity('the identity text holds no AGE-SECRET-KEY-1… line')
  return out
}

// age-encryption's Decrypter says exactly this when no identity / passphrase unwraps the file key (age-encryption 0.3.1, pinned;
// the tests pin the mapping: a wrong secret → decrypt.passphrase / decrypt.identity, a damaged file → decrypt.format).
const NO_MATCH = /no identity matched any of the file's recipients/
class TlockFailed extends Error {}

async function run(d: Decrypter, bin: Uint8Array, wrong: () => never, what: string): Promise<Uint8Array> {
  let out: Uint8Array | null = null
  let why = ''
  try { out = await d.decrypt(bin) } catch (e) {
    if (isRefusal(e)) throw e
    if (e instanceof TlockFailed) why = 'tlock'
    else if (NO_MATCH.test(String((e as Error)?.message))) why = 'wrong'
    else why = /header HMAC/.test(String((e as Error)?.message)) ? 'mac' : 'payload'
  }
  if (why === 'wrong') wrong()
  if (why === 'tlock') refuseFormat(`${what}: the drand signature does not open its time lock (a wrong round signature from the relay, or a damaged stanza)`)
  if (why === 'mac') refuseFormat(`${what}: its header MAC does not verify (the file is damaged or was edited)`)
  if (why !== '' || out === null) refuseFormat(`${what}: its payload does not decrypt (the file is damaged or cut short)`)
  return out
}

/** The tlock stanza as an age-encryption identity: the file key from tlock-js's IBE with the round's signature. */
function tlockIdentity(sig: Uint8Array, round: number, hash: string): Identity {
  return {
    async unwrapFileKey(stanzas: Stanza[]): Promise<Uint8Array | null> {
      const s = stanzas.find((x) => x.args[0] === 'tlock')
      if (s === undefined) return null
      if (s.args.length !== 3 || s.args[1] !== String(round) || s.args[2] !== hash || s.body.length !== 96 + 32) throw new TlockFailed('stanza')
      try {
        return await decryptOnG2(sig, { U: s.body.subarray(0, 96), V: s.body.subarray(96, 112), W: s.body.subarray(112) })
      } catch { throw new TlockFailed('ibe') }
    },
  }
}

/** The round's signature, never asked before the round (how.now): decrypt.too-early "opens at <UTC>". */
export async function roundSignature(round: number, how: DecryptHow, what: string): Promise<Uint8Array> {
  const nowMs = how.now?.() ?? Date.now()
  if (!(nowMs >= roundTime(round) * 1000)) refuseTooEarly(round)
  const fetch: FetchRoundSignature | undefined = how.fetchRoundSignature
  if (typeof fetch !== 'function') refuseKind(`${what} is time-locked (drand quicknet round ${round}): it needs the round's signature, through the relay`)
  const sig = await fetch(QUICKNET.hash, round)
  if (sig === null) refuseTooEarly(round)
  const hex = typeof sig === 'string' ? sig.trim().toLowerCase() : ''
  if (!SIG_HEX.test(hex)) refuseFormat(`the drand signature for round ${round} is not 48 bytes of hex`)
  const out = new Uint8Array(48)
  for (let i = 0; i < 48; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16)
  return out
}

/** Open one age file whose kind is known (ageInfo). `wrongIdentity` lets a chain step say what a non-matching key means. */
export async function openAge(bin: Uint8Array, info: AgeInfo, how: DecryptHow, limits: DecryptLimits, what = 'the input',
  identities?: string[], wrongIdentity?: () => never): Promise<Uint8Array> {
  const d = new Decrypter()
  if (info.kind === 'passphrase') {
    const p = how.passphrase
    if (typeof p !== 'string' || p.length === 0) refuseKind(`${what} is passphrase-encrypted (age scrypt): it needs the passphrase`)
    bounded(enc.encode(p).length, limits.secret, 'the passphrase')
    d.addPassphrase(p)
    return run(d, bin, refusePassphrase, what)
  }
  if (info.kind === 'identity') {
    let ids = identities
    if (ids === undefined) {
      if (typeof how.identity !== 'string') refuseKind(`${what} is encrypted to an age identity (X25519): it needs the identity (AGE-SECRET-KEY-1…)`)
      ids = parseIdentities(how.identity, limits)
    }
    for (const id of ids) {
      try { d.addIdentity(id) } catch { refuseIdentity('an identity line is not a valid age identity (its checksum or length is wrong)') }
    }
    return run(d, bin, wrongIdentity ?? (() => refuseIdentity(`none of the given identities opens ${what}`)), what)
  }
  const round = info.round as number
  const sig = await roundSignature(round, how, what)
  d.addIdentity(tlockIdentity(sig, round, info.chainHash as string))
  return run(d, bin, () => refuseFormat(`${what}: the tlock stanza did not yield its file key`), what)
}

// Open (W7): a published timelocked text or a SEALED.txt → its files, in the browser.
//   parse    core only: sealedFiles (the parser-differential fix: the page has no parser of its own) and checkPayload for the
//            contents line. The ONE thing done here is the wrapper for a bare SEALED.txt (below), which only builds the two
//            header lines core's parser wants; every decision about the text stays core's.
//   time     round → unlock time by core's pinned quicknet math (drand.ts).
//   drand    the relay's drand route (S6: /relay/drand/<quicknet hash>/public/<round|latest>), read through a ChainClient for
//            tlock-js. The chain info is the PINNED quicknet (core), never fetched; tlock-js verifies the beacon against the
//            pinned public key, and the IBE decryption fails closed on a wrong signature.
//   decrypt  tlock-js for the tlock layer, age (age-encryption, X25519 identity) for the two-layer vault. Plaintext lives in memory
//            only: it is returned to the caller, never stored, logged or sent.
import './polyfills.js'
import { timelockDecrypt } from 'tlock-js'
import { Decrypter } from 'age-encryption'
import { QUICKNET, armor, checkPayload, parseTlockStanza, roundTime, sealedFiles, sha256Hex, unlockIso } from './core.js'
import { isGzip, readTarGz } from './tar.js'

const SEALED_PREFIX = '== vault-timelock sealed package'
const ROUND_LINE = /^unlock-after: [^\n]*\(drand round ([1-9]\d{0,15})\)$/m
const KEY_ONLY_LINE = /^contents: key-only \(payload: ar:\/\/([A-Za-z0-9_-]{43})\)$/m
const AGE_KEY = /^AGE-SECRET-KEY-1[0-9A-Z]+$/

// A bare SEALED.txt has no `vault-timelock/1 unlock=…` and `ar://…` header lines. Wrap it in the two lines core's parser
// requires, built from the text's own round (the unlock time is core's roundTime) and its key-only id. Core then checks
// everything, including that the header agrees with the section (payload.unlock-mismatch, payload.contents, …). A text that is
// not recognisably a SEALED.txt is returned unchanged, so core refuses it with its own guard.
export function asPublished(text) {
  if (!text.startsWith(SEALED_PREFIX)) return text
  const round = ROUND_LINE.exec(text)
  if (round === null) return text
  let iso
  try { iso = unlockIso(Number(round[1])) } catch { return text }
  const ar = KEY_ONLY_LINE.exec(text)
  return `vault-timelock/1 unlock=${iso}\nar://${ar ? ar[1] : 'A'.repeat(43)}\nopened from a SEALED.txt\n\n${text}`
}

// -> { text, files: Map<name, bytes>, tlockName, round, unlockMs, unlockIso, kind, contents, arId, issues }; throws core's Refusal.
export function prepareOpen(raw) {
  const text = asPublished(raw)
  const files = sealedFiles(text)
  const info = checkPayload(text)
  let tlockName = null, round = null
  for (const [name, bin] of files) {
    const st = parseTlockStanza(bin)
    if (st !== null) { tlockName = name; round = Number(st.round); break }
  }
  if (tlockName === null || !Number.isSafeInteger(round)) throw new Error('open: no time-locked block (core accepted the text)')
  const kind = files.has('unlock-TIME.age') ? 'two-layer' : files.has('vault.tar.gz.age') ? 'vault' : files.has('secret.tar.gz.age') ? 'secret' : 'payload'
  // M-1: Open stays permissive (core's sealedFiles accepts older texts), but it does not hide what the exact check says.
  const issues = info.issues.map((i) => ({ id: i.id, message: i.message }))
  return { text, files, tlockName, round, unlockMs: roundTime(round) * 1000, unlockIso: unlockIso(round), kind, contents: info.contents, arId: info.arId, issues }
}

export class DrandError extends Error {
  constructor(status, message) { super(message); this.name = 'DrandError'; this.status = status }
}

// A tlock-js ChainClient over the relay. `fetch` is injectable (tests). `info` is the pinned quicknet unless a test injects a chain
// with its own key.
export function relayDrandClient({ fetch = (u, i) => globalThis.fetch(u, i), info = QUICKNET, base = '/relay/drand' } = {}) {
  const get = async (path) => {
    let res
    try { res = await fetch(`${base}/${QUICKNET.hash}/${path}`, { cache: 'no-store', credentials: 'same-origin', redirect: 'error', headers: { accept: 'application/json' } }) } catch { throw new DrandError(0, 'the relay is not reachable') }
    if (res.status === 404 || res.status === 425) throw new DrandError(res.status, 'drand has not published that round yet')
    if (!res.ok) throw new DrandError(res.status, `the relay answered HTTP ${res.status}`)
    let b
    try { b = JSON.parse(await res.text()) } catch { throw new DrandError(res.status, 'the relay answered with something that is not JSON') }
    if (!b || !Number.isSafeInteger(b.round) || b.round < 1 || typeof b.signature !== 'string' || typeof b.randomness !== 'string') throw new DrandError(res.status, 'the relay answered with something that is not a drand beacon')
    return b
  }
  return {
    options: { disableBeaconVerification: false, noCache: true },
    chain: () => ({ baseUrl: base, info: async () => info }),
    latest: () => get('public/latest'),
    get: (round) => { if (!Number.isSafeInteger(round) || round < 1) throw new DrandError(0, 'bad round'); return get(`public/${round}`) },
  }
}

// The latest published round: the only thing fetched before the unlock round.
export async function latestRound(client) { return (await client.latest()).round }

// M-3: a name from an archive is shown and offered only after every control, format (bidi, zero-width, BOM, soft hyphen), line
// separator and non-ASCII space character is written out as [U+XXXX], so a name can neither reorder or hide text nor look like
// another name; two names that come out the same get " (2)", " (3)", … (the page's own identity.key and vault.tar.gz come first).
const HIDDEN = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Zs}\p{Co}\p{Cn}]/gu
// A "[" that would open something that reads as escape notation is itself written out, so the notation is unambiguous: a name that really
// holds the text "[U+202E]" is shown "[U+005B]U+202E]", never as if it held U+202E (Wfix4 parked item).
const HIDDEN_OR_LOOKS_ESCAPED = new RegExp(`${HIDDEN.source}|\\[(?=U\\+[0-9A-F]{4,6}\\])`, 'giu')   // one pass over the ORIGINAL name
const hex = (c) => `[U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}]`
export function escapeName(n) {
  return n.replace(HIDDEN_OR_LOOKS_ESCAPED, (c) => (c === ' ' ? c : hex(c)))
}
const nameOf = (n) => n.replace(/\//g, '_')
const entry = (name, bytes, extra = {}) => ({ path: name, bytes, size: bytes.length, sha256: sha256Hex(bytes), ...extra })
function uniq(base, seen) {
  let c = base, i = 1
  while (seen.has(c)) c = `${base} (${++i})`
  seen.add(c)
  return c
}
// -> the same entries with `path` (shown) and `name` (download name / test id) escaped and unique; `renamed` says either changed.
export function finalizeNames(list) {
  const paths = new Set(), names = new Set()
  return list.map((f) => {
    const shown = escapeName(f.path)
    const path = uniq(shown, paths)
    const name = uniq(nameOf(path), names)
    return { ...f, path, name, renamed: path !== f.path }
  })
}

// -> { files: [{ name, path, bytes, size, sha256, renamed }], skipped: [{ name, why }], notes: string[] }
export async function decryptSealed(prep, client) {
  const notes = [], skipped = []
  let plain
  // tlock-js console.logs "beacon received: …" (the PUBLIC beacon). Its console.log is silenced for exactly this call and restored
  // after, so nothing from the library reaches the console; the page itself logs nothing.
  const log = console.log
  console.log = () => {}
  try { plain = new Uint8Array(await timelockDecrypt(armor(prep.files.get(prep.tlockName)), client)) } catch (e) {
    // tlock-js compares the round's time with THIS device's clock before it fetches anything; the page only got here because drand
    // itself reported the round as published.
    if (/too early/i.test(String(e?.message))) throw new DrandError(0, 'drand has published this round, but this device\'s clock says it is still too early: your clock may be behind. Set the clock right (automatic time) and try again.')
    throw new DrandError(e?.status ?? 0, e instanceof DrandError ? e.message : `could not decrypt: ${String(e?.message || e)}`)
  } finally { console.log = log }
  const archive = async (tgz, label) => {
    if (!isGzip(tgz)) { notes.push(`${label} is not a gzip archive; it is offered as it is`); return [entry(label, tgz)] }
    const out = [entry(label, tgz)]
    try { const r = await readTarGz(tgz); skipped.push(...r.skipped); out.push(...r.files.map((f) => entry(f.name, f.bytes))) } catch (e) { notes.push(`${label}: ${String(e?.message || e)}; only the archive itself is offered (save it and unpack it with tar)`) }
    return out
  }
  let files
  if (prep.kind === 'two-layer') {
    const key = new TextDecoder().decode(plain).trim()
    plain.fill(0)                                      // the page's own copy of the key bytes (the string and the entry below remain)
    if (!AGE_KEY.test(key)) throw new Error('the time-locked layer did not hold an age key')
    files = [entry('identity.key', new TextEncoder().encode(key + '\n'))]
    if (prep.files.has('vault.tar.gz.age')) {
      const d = new Decrypter()
      d.addIdentity(key)
      const raw = await d.decrypt(prep.files.get('vault.tar.gz.age'))
      const tgz = new Uint8Array(raw)
      if (raw instanceof Uint8Array) raw.fill(0)       // `tgz` is the copy that is kept
      files.push(...await archive(tgz, 'vault.tar.gz'))
    } else notes.push(`key-only text: the archive is at ar://${prep.arId}. Fetch it (any Arweave gateway) and open it with identity.key: age -d -i identity.key -o vault.tar.gz vault.tar.gz.age`)
  } else if (prep.kind === 'vault') files = await archive(plain, 'vault.tar.gz')
  else if (prep.kind === 'secret') files = await archive(plain, 'secret.tar.gz')
  else if (isGzip(plain)) files = await archive(plain, 'content.tar.gz')
  else files = [entry('content', plain)]
  return { files: finalizeNames(files), skipped: skipped.map((k) => ({ ...k, name: escapeName(k.name) })), notes }
}

// M-4: overwrite the bytes the page owns (every restored file) with zeros. Safe to call twice.
export function wipe(result) { if (result) for (const f of result.files) f.bytes.fill(0) }

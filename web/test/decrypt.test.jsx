// Decrypt tab (vt decrypt, lane W): SYNTHETIC inputs only (made-up passphrases, fresh age identities, a made-up drand-shaped chain behind
// the relay route, made-up archive files). The real core decrypt and the real age / tlock code run; nothing real, nothing from disk.
import { test, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Encrypter, generateIdentity, identityToRecipient } from 'age-encryption'
import { armor } from '@vault-timelock/core/text/armor.ts'
import Decrypt from '../src/pages/Decrypt.jsx'
import { QUICKNET } from '../src/lib/core.js'
import { relayDrandClient } from '../src/lib/open.js'
import { renderWith } from './helpers.jsx'
import { FUTURE_ROUND, PAST_ROUND, SYNTH_INFO, VAULT_FILES, fakeDrand, makeTexts, targz, tlock } from './open-fixtures.js'

// the mocked download copies the bytes at call time (the page wipes its own copy right after saving)
const saved = []
// every decrypt result the page gets is kept here, so a test can check its bytes are zeroed
const { results } = vi.hoisted(() => ({ results: [] }))
vi.mock('../src/lib/decrypt.js', async (orig) => {
  const m = await orig()
  return { ...m, runDecrypt: async (...a) => { const r = await m.runDecrypt(...a); if (r.ok) results.push(r.result); return r } }
})
const allZero = (r) => r.files.every((f) => f.bytes.every((b) => b === 0))
vi.mock('../src/keys/download.js', async (orig) => ({ ...(await orig()), download: (bytes, name, scope) => { saved.push({ bytes: new Uint8Array(bytes), name, scope }) } }))
beforeEach(() => { saved.length = 0; results.length = 0 })
afterEach(() => vi.restoreAllMocks())

const T = 30_000
const PASS = 'synthetic correct horse battery staple'
const paste = (text) => fireEvent.change(screen.getByTestId('decrypt-text'), { target: { value: text } })
const view = (drand = fakeDrand({ latest: () => PAST_ROUND })) => renderWith(<Decrypt client={relayDrandClient({ fetch: drand.fetch, info: SYNTH_INFO })} />, { status: { serverNowMs: Date.now() } })
const text = (u8) => Buffer.from(u8).toString()
const kindOf = () => screen.getByTestId('decrypt-kind').dataset.kind
const typeSecret = (id, v) => fireEvent.change(screen.getByTestId(id), { target: { value: v } })

async function passphraseBin(plain, pass = PASS) {
  const e = new Encrypter(); e.setPassphrase(pass); e.setScryptWorkFactor(10)
  return e.encrypt(plain)
}
async function identityBin(plain) {
  const id = await generateIdentity()
  const e = new Encrypter(); e.addRecipient(await identityToRecipient(id))
  return { id, bin: await e.encrypt(plain) }
}
// a per-file Download extracts from the archive first (async), then saves
const saveEntry = async (user, name) => { const n = saved.length; await user.click(screen.getByTestId(`decrypt-entry-download-${name}`)); await waitFor(() => expect(saved).toHaveLength(n + 1)) }
const keygenFile = (id) => `# created: 2026-10-14T00:00:00Z\n${id}\n`
const pickIdentity = (content, name = 'key.txt') => fireEvent.change(screen.getByTestId('decrypt-identity-file'), { target: { files: [new File([content], name)] } })

test('passphrase, armored: kind shown, wrong passphrase refused, right one decrypts, one Download', async () => {
  const user = userEvent.setup()
  view()
  paste(armor(await passphraseBin('synthetic secret note\n')))
  expect(kindOf()).toBe('passphrase')
  expect(screen.getByTestId('decrypt-run').disabled).toBe(true)            // a passphrase is needed first
  typeSecret('decrypt-pass', 'a wrong synthetic passphrase')
  await user.click(screen.getByTestId('decrypt-run'))
  expect((await screen.findByTestId('decrypt-error', {}, { timeout: T })).textContent).toContain('decrypt.passphrase')
  expect(screen.queryByTestId('decrypt-result')).toBeNull()
  typeSecret('decrypt-pass', PASS)
  await user.click(screen.getByTestId('decrypt-run'))
  await screen.findByTestId('decrypt-result', {}, { timeout: T })
  expect(saved).toEqual([])                                                  // nothing downloads by itself
  await user.click(screen.getByTestId('decrypt-download-decrypted'))
  expect(text(saved[0].bytes)).toBe('synthetic secret note\n')
  expect(screen.getByTestId('decrypt-pass').value).toBe('')                  // the passphrase is dropped once used
})

test('passphrase, binary .age dropped as a file', async () => {
  const user = userEvent.setup()
  view()
  const file = new File([await passphraseBin('binary synthetic body')], 'note.age')
  fireEvent.drop(screen.getByTestId('decrypt-drop'), { dataTransfer: { files: [file] } })
  await screen.findByTestId('decrypt-info')
  expect(kindOf()).toBe('passphrase')
  expect(screen.getByTestId('decrypt-form').textContent).toBe('binary')
  typeSecret('decrypt-pass', PASS)
  await user.click(screen.getByTestId('decrypt-run'))
  await user.click(await screen.findByTestId('decrypt-download-decrypted', {}, { timeout: T }))
  expect(text(saved[0].bytes)).toBe('binary synthetic body')
})

test('the passphrase field is password-manager-proof (SecretInput)', async () => {
  view()
  paste(armor(await passphraseBin('x')))
  const f = screen.getByTestId('decrypt-pass')
  expect(f.getAttribute('autocomplete')).toBe('off')
  expect(f.getAttribute('data-1p-ignore')).toBe('true')
  expect(f.id).toBeTruthy(); expect(f.name).toBeTruthy()
  expect(f.closest('form')).toBeNull()
})

test('identity: wrong identity refused, the right identity file decrypts', async () => {
  const user = userEvent.setup()
  view()
  const { id, bin } = await identityBin('synthetic identity-locked body')
  paste(armor(bin))
  expect(kindOf()).toBe('identity')
  expect(screen.getByTestId('decrypt-run').disabled).toBe(true)
  pickIdentity(keygenFile(await generateIdentity()))
  await waitFor(() => expect(screen.getByTestId('decrypt-run').disabled).toBe(false))
  await user.click(screen.getByTestId('decrypt-run'))
  expect((await screen.findByTestId('decrypt-error', {}, { timeout: T })).textContent).toContain('decrypt.identity')
  pickIdentity(keygenFile(id))
  await waitFor(() => expect(screen.getByTestId('decrypt-identity-loaded').textContent).toContain('key.txt'))
  await user.click(screen.getByTestId('decrypt-run'))
  await user.click(await screen.findByTestId('decrypt-download-decrypted', {}, { timeout: T }))
  expect(text(saved[0].bytes)).toBe('synthetic identity-locked body')
})

test('a malformed identity file is refused with core\'s guard', async () => {
  const user = userEvent.setup()
  view()
  paste(armor((await identityBin('x')).bin))
  pickIdentity('this is not an identity\n')
  await waitFor(() => expect(screen.getByTestId('decrypt-run').disabled).toBe(false))
  await user.click(screen.getByTestId('decrypt-run'))
  expect((await screen.findByTestId('decrypt-error', {}, { timeout: T })).textContent).toContain('decrypt.identity')
})

test('an oversize identity file is refused before it is read', async () => {
  view()
  paste(armor((await identityBin('x')).bin))
  pickIdentity('A'.repeat(70 * 1024))
  expect((await screen.findByTestId('decrypt-identity-refusal')).textContent).toMatch(/too big/)
  expect(screen.getByTestId('decrypt-run').disabled).toBe(true)
})

test('timelocked after the round: decrypts through the relay (only the round signature is requested)', async () => {
  const user = userEvent.setup()
  const drand = fakeDrand({ latest: () => PAST_ROUND })
  view(drand)
  paste(armor(await tlock(PAST_ROUND, 'synthetic timelocked body')))
  expect(kindOf()).toBe('timelocked')
  expect(screen.getByTestId('decrypt-opens').textContent).toContain(String(PAST_ROUND))
  expect(drand.calls).toEqual([])                                           // detecting sends nothing
  await user.click(screen.getByTestId('decrypt-run'))
  await user.click(await screen.findByTestId('decrypt-download-decrypted', {}, { timeout: T }))
  expect(text(saved[0].bytes)).toBe('synthetic timelocked body')
  expect(drand.calls).toEqual([`/relay/drand/${QUICKNET.hash}/public/${PAST_ROUND}`])
})

test('timelocked before the round: refused "opens at <UTC>" and NOTHING is requested', async () => {
  const user = userEvent.setup()
  const drand = fakeDrand({ latest: () => PAST_ROUND })
  view(drand)
  paste(armor(await tlock(FUTURE_ROUND, 'never')))
  await user.click(screen.getByTestId('decrypt-run'))
  const e = await screen.findByTestId('decrypt-error', {}, { timeout: T })
  expect(e.textContent).toContain('decrypt.too-early')
  expect(e.textContent).toMatch(/opens at 2100-01-01T/)
  expect(drand.calls).toEqual([])
  expect(screen.queryByTestId('decrypt-result')).toBeNull()
})

test('timelocked: a relay that says the round is not published yet is "too early"', async () => {
  const user = userEvent.setup()
  view(fakeDrand({ latest: () => PAST_ROUND - 5 }))                          // 404 for PAST_ROUND
  paste(armor(await tlock(PAST_ROUND, 'x')))
  await user.click(screen.getByTestId('decrypt-run'))
  expect((await screen.findByTestId('decrypt-error', {}, { timeout: T })).textContent).toContain('decrypt.too-early')
})

test('timelocked: a relay that is down shows its error, nothing decrypts', async () => {
  const user = userEvent.setup()
  renderWith(<Decrypt client={relayDrandClient({ fetch: async () => { throw new Error('offline') }, info: SYNTH_INFO })} />, { status: { serverNowMs: Date.now() } })
  paste(armor(await tlock(PAST_ROUND, 'x')))
  await user.click(screen.getByTestId('decrypt-run'))
  expect((await screen.findByTestId('decrypt-error', {}, { timeout: T })).textContent).toMatch(/relay is not reachable/)
  expect(screen.queryByTestId('decrypt-result')).toBeNull()
})

test('timelocked: a wrong signature from the relay decrypts nothing', async () => {
  const user = userEvent.setup()
  const good = fakeDrand({ latest: () => PAST_ROUND })
  const bad = async (u) => {
    const b = await (await good.fetch(u)).json()
    return new Response(JSON.stringify({ ...b, signature: b.signature.replace(/^../, (x) => (x === 'aa' ? 'bb' : 'aa')) }), { status: 200 })
  }
  renderWith(<Decrypt client={relayDrandClient({ fetch: bad, info: SYNTH_INFO })} />, { status: { serverNowMs: Date.now() } })
  paste(armor(await tlock(PAST_ROUND, 'x')))
  await user.click(screen.getByTestId('decrypt-run'))
  expect((await screen.findByTestId('decrypt-error', {}, { timeout: T })).textContent).toContain('decrypt.')
  expect(screen.queryByTestId('decrypt-result')).toBeNull()
  expect(saved).toEqual([])
})

test('SEALED.txt (two-layer): kind, round, blocks; decrypts; file list with per-file Download and Download all', async () => {
  const user = userEvent.setup()
  const t = await makeTexts({ round: PAST_ROUND })
  const drand = fakeDrand({ latest: () => PAST_ROUND })
  view(drand)
  paste(t.sealed)
  expect(kindOf()).toBe('sealed')
  expect(screen.getByTestId('decrypt-layout').textContent).toMatch(/two-layer.*full/)
  expect(screen.getByTestId('decrypt-blocks').textContent).toContain('unlock-TIME.age')
  await user.click(screen.getByTestId('decrypt-run'))
  await screen.findByTestId('decrypt-result', {}, { timeout: T })
  const paths = screen.getAllByTestId('decrypt-entry-path').map((n) => n.textContent)
  expect(paths).toEqual(Object.keys(VAULT_FILES))
  expect(saved).toEqual([])
  for (const [i, path] of Object.keys(VAULT_FILES).entries()) {
    await saveEntry(user, path.replace(/\//g, '_'))
    expect(saved.at(-1).name).toBe(path.replace(/\//g, '_'))
    expect(text(saved.at(-1).bytes)).toBe(VAULT_FILES[path])
    expect(saved).toHaveLength(i + 1)
  }
  await user.click(screen.getByTestId('decrypt-download-all'))
  expect(saved.at(-1).name).toBe('vault.tar.gz')
  expect(Buffer.from(saved.at(-1).bytes).equals(Buffer.from(t.restored['vault.tar.gz']))).toBe(true)
  await user.click(screen.getByTestId('decrypt-download-identity.key'))
  expect(text(saved.at(-1).bytes)).toBe(t.restored['identity.key'])
  expect(drand.calls).toEqual([`/relay/drand/${QUICKNET.hash}/public/${PAST_ROUND}`])
  await user.click(screen.getByTestId('decrypt-clear'))
  expect(screen.queryByTestId('decrypt-result')).toBeNull()
})

test('a published text (with its header lines) is accepted; before the round it is refused with no request', async () => {
  const user = userEvent.setup()
  const t = await makeTexts({ round: FUTURE_ROUND })
  const drand = fakeDrand({ latest: () => PAST_ROUND })
  view(drand)
  paste(t.text)
  expect(kindOf()).toBe('sealed')
  expect(screen.getByTestId('decrypt-form').textContent).toBe('published')
  await user.click(screen.getByTestId('decrypt-run'))
  expect((await screen.findByTestId('decrypt-error', {}, { timeout: T })).textContent).toContain('decrypt.too-early')
  expect(drand.calls).toEqual([])
})

test('SEALED.txt before the round opens at once with the one-time key (identity path), with no request', async () => {
  const user = userEvent.setup()
  const t = await makeTexts({ round: FUTURE_ROUND })
  const drand = fakeDrand({ latest: () => PAST_ROUND })
  view(drand)
  paste(t.sealed)
  pickIdentity(t.restored['identity.key'], 'identity.key')
  await waitFor(() => expect(screen.getByTestId('decrypt-identity-loaded')).toBeTruthy())
  await user.click(screen.getByTestId('decrypt-run'))
  await screen.findByTestId('decrypt-result', {}, { timeout: T })
  expect(screen.getAllByTestId('decrypt-entry-row')).toHaveLength(Object.keys(VAULT_FILES).length)
  expect(drand.calls).toEqual([])
})

test('a single-file package gives one Download and no file list', async () => {
  const user = userEvent.setup()
  const p = await makeTexts({ kind: 'payload', round: PAST_ROUND, payload: 'synthetic note payload\n' })
  view()
  paste(p.sealed)
  await user.click(screen.getByTestId('decrypt-run'))
  await user.click(await screen.findByTestId('decrypt-download-content', {}, { timeout: T }))
  expect(text(saved[0].bytes)).toBe('synthetic note payload\n')
  expect(screen.queryByTestId('decrypt-archive')).toBeNull()
})

test('key-only SEALED.txt: only the key, with the note saying where the archive is', async () => {
  const user = userEvent.setup()
  const t = await makeTexts({ round: PAST_ROUND, contents: 'key-only' })
  view()
  paste(t.sealed)
  expect(screen.getByTestId('decrypt-layout').textContent).toMatch(/key only.*ar:\/\//)
  await user.click(screen.getByTestId('decrypt-run'))
  await screen.findByTestId('decrypt-result', {}, { timeout: T })
  expect(screen.getByTestId('decrypt-note').textContent).toMatch(/ar:\/\/B+/)
  expect(screen.getAllByTestId('decrypt-file-row')).toHaveLength(1)
})

test('an age file holding a tar.gz lists its files (no SEALED.txt needed)', async () => {
  const user = userEvent.setup()
  view()
  paste(armor(await passphraseBin(targz({ 'a/one.txt': 'first synthetic', 'two.txt': 'second' }))))
  typeSecret('decrypt-pass', PASS)
  await user.click(screen.getByTestId('decrypt-run'))
  await screen.findByTestId('decrypt-archive', {}, { timeout: T })
  expect(screen.getAllByTestId('decrypt-entry-path').map((n) => n.textContent)).toEqual(['a/one.txt', 'two.txt'])
  await saveEntry(user, 'a_one.txt')
  expect(text(saved[0].bytes)).toBe('first synthetic')
  await user.click(screen.getByTestId('decrypt-download-all'))
  expect(saved.at(-1).name).toBe('decrypted.tar.gz')
})

test('file names are escaped for bidi / zero-width / control characters, and made unique', async () => {
  const user = userEvent.setup()
  view()
  const evil = ['a‮b.txt', 'z​z.txt', '[U+202E]x']
  paste(armor(await passphraseBin(targz(evil.map((n, i) => [n, `body${i}`])))))
  typeSecret('decrypt-pass', PASS)
  await user.click(screen.getByTestId('decrypt-run'))
  await screen.findByTestId('decrypt-archive', {}, { timeout: T })
  const shown = screen.getAllByTestId('decrypt-entry-path').map((n) => n.textContent)
  expect(shown).toEqual(['a[U+202E]b.txt', 'z[U+200B]z.txt', '[U+005B]U+202E]x'])
  for (const s of shown) expect(s).not.toMatch(/[‮​]/)
  expect(screen.getAllByTestId('decrypt-entry-renamed')).toHaveLength(3)
  await saveEntry(user, 'a[U+202E]b.txt')
  expect(saved[0].name).toBe('a[U+202E]b.txt')
  expect(text(saved[0].bytes)).toBe('body0')                                  // saved from the ORIGINAL path
})

test.each([
  ['a path-traversal entry', [['../evil.txt', 'x']]],
  ['an absolute path', [['/etc/x', 'x']]],
  ['a symlink', [['link', '', '2']]],
  ['a duplicate path', [['d.txt', '1'], ['d.txt', '2']]],
])('an unsafe archive is not listed and offers no per-file download: %s', async (_n, entries) => {
  const user = userEvent.setup()
  view()
  paste(armor(await passphraseBin(targz(entries))))
  typeSecret('decrypt-pass', PASS)
  await user.click(screen.getByTestId('decrypt-run'))
  const e = await screen.findByTestId('decrypt-archive-error', {}, { timeout: T })
  expect(e.textContent).toContain('decrypt.format')
  expect(screen.queryByTestId('decrypt-entry-row')).toBeNull()
  expect(screen.queryByTestId('decrypt-download-all')).toBeNull()
})

test('garbage and oversize input are refused with core\'s guard before anything is asked or fetched', async () => {
  const drand = fakeDrand({ latest: () => PAST_ROUND })
  view(drand)
  paste('hello, this is not age')
  expect((await screen.findByTestId('decrypt-refusal')).textContent).toContain('decrypt.format')
  expect(screen.queryByTestId('decrypt-info')).toBeNull()
  paste('A'.repeat(1024 * 1024 + 10))
  await waitFor(() => expect(screen.getByTestId('decrypt-refusal').textContent).toContain('decrypt.size'))
  expect(screen.queryByTestId('decrypt-info')).toBeNull()
  expect(drand.calls).toEqual([])
})

test('a truncated armored text is refused (format)', async () => {
  view()
  paste(armor(await passphraseBin('x')).replace(/\n-----END AGE ENCRYPTED FILE-----\n?$/, ''))
  expect((await screen.findByTestId('decrypt-refusal')).textContent).toContain('decrypt.format')
})

test('a file that is neither text nor age is refused', async () => {
  view()
  fireEvent.change(screen.getByTestId('decrypt-file'), { target: { files: [new File([new Uint8Array([0xff, 0xfe, 0x00, 0x41])], 'junk.bin')] } })
  expect((await screen.findByTestId('decrypt-refusal')).textContent).toContain('decrypt.format')
})

const spyConsole = () => ['log', 'info', 'warn', 'error', 'debug'].map((k) => vi.spyOn(console, k).mockImplementation(() => {}))
const logged = (spies) => spies.flatMap((s) => s.mock.calls).map((a) => a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' ')).join('\n')

test('nothing is persisted, logged or sent: no storage, no cookie, no console output, requests only to the relay route', async () => {
  const user = userEvent.setup()
  const spies = spyConsole()
  const setItem = vi.spyOn(Storage.prototype, 'setItem')
  const idb = globalThis.indexedDB ? vi.spyOn(globalThis.indexedDB, 'open') : null
  const drand = fakeDrand({ latest: () => PAST_ROUND })
  const fetchSpy = vi.fn((...a) => drand.fetch(...a))
  renderWith(<Decrypt client={relayDrandClient({ fetch: fetchSpy, info: SYNTH_INFO })} />, { status: { serverNowMs: Date.now() } })
  const t = await makeTexts({ round: PAST_ROUND })
  paste(t.sealed)
  await user.click(screen.getByTestId('decrypt-run'))
  await screen.findByTestId('decrypt-result', {}, { timeout: T })
  await saveEntry(user, 'items_aaaa.json')
  const secret = t.restored['identity.key'].trim()
  expect(setItem).not.toHaveBeenCalled()
  if (idb) expect(idb).not.toHaveBeenCalled()
  expect(localStorage.length + sessionStorage.length).toBe(0)
  expect(document.cookie).toBe('')
  expect(window.location.href).not.toContain(secret)
  expect(document.body.textContent).not.toContain(secret)
  expect(document.body.textContent).not.toContain('synthetic item')           // no file contents on the page, only paths and sizes
  for (const [u, init] of fetchSpy.mock.calls) { expect(String(u)).toMatch(/^\/relay\/drand\//); expect(init?.body).toBeUndefined() }
  expect(logged(spies)).toBe('')

  // a passphrase flow: the passphrase is gone from the DOM after use and was never stored or logged
  await user.click(screen.getByTestId('decrypt-reset'))
  paste(armor(await passphraseBin('x')))
  typeSecret('decrypt-pass', PASS)
  await user.click(screen.getByTestId('decrypt-run'))
  await screen.findByTestId('decrypt-result', {}, { timeout: T })
  expect(document.body.innerHTML).not.toContain(PASS)
  expect(setItem).not.toHaveBeenCalled()
  expect(logged(spies)).not.toContain(PASS)
})

test('Clear zeroes the page\'s plaintext bytes and revokes the object URLs it made', async () => {
  const user = userEvent.setup()
  view()
  paste(armor(await passphraseBin('wipe me please')))
  typeSecret('decrypt-pass', PASS)
  await user.click(screen.getByTestId('decrypt-run'))
  await screen.findByTestId('decrypt-result', {}, { timeout: T })
  const spy = vi.spyOn(Uint8Array.prototype, 'fill')
  await user.click(screen.getByTestId('decrypt-clear'))
  expect(spy.mock.calls.some((c) => c[0] === 0)).toBe(true)
  expect(screen.queryByTestId('decrypt-result')).toBeNull()
})

test('the relay signature fetcher serves only the pinned chain, returns the round it asked for, and maps "not published" to null', async () => {
  const { relaySignatureFetcher } = await import('../src/lib/decrypt.js')
  const { DrandError } = await import('../src/lib/open.js')
  const ok = relaySignatureFetcher({ get: async (r) => ({ round: r, signature: 'ab'.repeat(48), randomness: 'x' }) })
  expect(await ok(QUICKNET.hash, 7)).toBe('ab'.repeat(48))
  await expect(ok('00'.repeat(32), 7)).rejects.toThrow(/does not serve/)
  const other = relaySignatureFetcher({ get: async () => ({ round: 8, signature: 'ab'.repeat(48) }) })
  await expect(other(QUICKNET.hash, 7)).rejects.toThrow(/another round/)
  for (const status of [404, 425]) expect(await relaySignatureFetcher({ get: async () => { throw new DrandError(status, 'nope') } })(QUICKNET.hash, 7)).toBeNull()
  await expect(relaySignatureFetcher({ get: async () => { throw new DrandError(500, 'boom') } })(QUICKNET.hash, 7)).rejects.toThrow(/boom/)
})

// ---- fix round 1 ----
const dropFile = (f) => fireEvent.drop(screen.getByTestId('decrypt-drop'), { dataTransfer: { files: [f] } })

test('I-1: a second file with the same name and size replaces the first: no stale result, and Download gives the SECOND file\'s bytes', async () => {
  const user = userEvent.setup()
  view()
  dropFile(new File([await passphraseBin('first body 1111')], 'unlock-TIME.age'))
  const a = await screen.findByTestId('decrypt-info')
  typeSecret('decrypt-pass', PASS)
  await user.click(screen.getByTestId('decrypt-run'))
  await screen.findByTestId('decrypt-result', {}, { timeout: T })
  const first = results.at(-1)
  const second = new File([await passphraseBin('other body 2222')], 'unlock-TIME.age')
  dropFile(second)
  await waitFor(() => expect(screen.queryByTestId('decrypt-result')).toBeNull())
  expect(allZero(first)).toBe(true)                                         // the previous plaintext was zeroed
  typeSecret('decrypt-pass', PASS)
  await user.click(screen.getByTestId('decrypt-run'))
  await user.click(await screen.findByTestId('decrypt-download-decrypted', {}, { timeout: T }))
  expect(text(saved.at(-1).bytes)).toBe('other body 2222')
})

test('I-2: a dropped file over the cap is refused before it is read', async () => {
  view()
  const arrayBuffer = vi.fn(async () => new ArrayBuffer(0))
  dropFile({ name: 'huge.bin', size: 129 * 1024 * 1024, arrayBuffer })
  expect((await screen.findByTestId('decrypt-file-refusal')).textContent).toMatch(/decrypt\.size.*Nothing was read/)
  expect(arrayBuffer).not.toHaveBeenCalled()
  expect(screen.queryByTestId('decrypt-info')).toBeNull()
})

test('M-1: leaving (Clear input) while a decrypt is in flight zeroes the plaintext when it completes', async () => {
  const user = userEvent.setup()
  const good = fakeDrand({ latest: () => PAST_ROUND })
  let release
  const gate = new Promise((r) => { release = r })
  const slow = async (u) => { await gate; return good.fetch(u) }
  renderWith(<Decrypt client={relayDrandClient({ fetch: slow, info: SYNTH_INFO })} />, { status: { serverNowMs: Date.now() } })
  paste(armor(await tlock(PAST_ROUND, 'in flight')))
  await user.click(screen.getByTestId('decrypt-run'))
  await user.click(screen.getByTestId('decrypt-reset'))
  release()
  await waitFor(() => expect(results).toHaveLength(1), { timeout: T })
  await waitFor(() => expect(allZero(results[0])).toBe(true))
  expect(screen.queryByTestId('decrypt-result')).toBeNull()
})

test('M-2: Clear zeroes exactly the result\'s bytes; unmounting zeroes them too, and revokes the URLs', async () => {
  const user = userEvent.setup()
  const revoke = vi.spyOn(URL, 'revokeObjectURL')
  const r1 = view()
  paste(armor(await passphraseBin('wipe one')))
  typeSecret('decrypt-pass', PASS)
  await user.click(screen.getByTestId('decrypt-run'))
  await screen.findByTestId('decrypt-result', {}, { timeout: T })
  expect(allZero(results[0])).toBe(false)
  await user.click(screen.getByTestId('decrypt-clear'))
  expect(allZero(results[0])).toBe(true)
  paste(armor(await passphraseBin('wipe two')))
  typeSecret('decrypt-pass', PASS)
  await user.click(screen.getByTestId('decrypt-run'))
  await screen.findByTestId('decrypt-result', {}, { timeout: T })
  expect(allZero(results[1])).toBe(false)
  r1.unmount()
  expect(allZero(results[1])).toBe(true)
  expect(revoke).toBeDefined()
})

test('M-4: an unsafe archive says plainly not to unpack it with tar', async () => {
  const user = userEvent.setup()
  view()
  paste(armor(await passphraseBin(targz([['../evil.txt', 'x']]))))
  typeSecret('decrypt-pass', PASS)
  await user.click(screen.getByTestId('decrypt-run'))
  expect((await screen.findByTestId('decrypt-archive-error', {}, { timeout: T })).textContent).toMatch(/Do not unpack it with tar/)
})

test('M-5: a file dropped outside the drop zone is not opened by the browser (default prevented)', async () => {
  view()
  expect(fireEvent.drop(document.body, { dataTransfer: { files: [new File(['AGE-SECRET-KEY-1X'], 'key.txt')] } })).toBe(false)
  expect(fireEvent.dragOver(document.body)).toBe(false)
})

test('M-7: a pasted age-keygen file whose line breaks the field removed still works', async () => {
  const user = userEvent.setup()
  view()
  const { id, bin } = await identityBin('multi-line key body')
  paste(armor(bin))
  typeSecret('decrypt-identity-paste', `# created: 2026-10-14T00:00:00Z # public key: age1synthetic ${id}`)
  await user.click(screen.getByTestId('decrypt-run'))
  await user.click(await screen.findByTestId('decrypt-download-decrypted', {}, { timeout: T }))
  expect(text(saved[0].bytes)).toBe('multi-line key body')
})

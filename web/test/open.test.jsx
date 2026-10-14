// Open (W7): a SYNTHETIC sealed text, a fake drand behind the relay route, the real core parser, the real tlock-js + age decrypt.
import { test, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import Open from '../src/pages/Open.jsx'
import { QUICKNET } from '../src/lib/core.js'
import { relayDrandClient } from '../src/lib/open.js'
import { renderWith } from './helpers.jsx'
import { FUTURE_ROUND, PAST_ROUND, SYNTH_INFO, fakeDrand, makeTexts } from './open-fixtures.js'

const saved = []
vi.mock('../src/keys/download.js', async (orig) => ({ ...(await orig()), download: (bytes, name, scope) => { saved.push({ bytes, name, scope }) } }))
beforeEach(() => { saved.length = 0 })
afterEach(() => vi.restoreAllMocks())

const T = 30_000
const paste = (text) => fireEvent.change(screen.getByTestId('open-text'), { target: { value: text } })
const open = (drand, status = {}) => renderWith(<Open client={relayDrandClient({ fetch: drand.fetch, info: SYNTH_INFO })} />, { status: { serverNowMs: Date.now(), ...status } })
const bytesOf = (v) => (typeof v === 'string' ? new TextEncoder().encode(v) : new Uint8Array(v))

test('before the round: unlock time, round and countdown, a clear "not yet", and nothing is fetched', async () => {
  const t = await makeTexts({ round: FUTURE_ROUND })
  const drand = fakeDrand({ latest: () => PAST_ROUND })
  open(drand)
  expect(screen.queryByTestId('open-info')).toBeNull()
  paste(t.text)
  expect(screen.getByTestId('open-unlock').textContent).toContain(t.iso)
  expect(screen.getByTestId('open-round').textContent).toBe(String(FUTURE_ROUND))
  expect(screen.getByTestId('open-countdown').getAttribute('data-done')).toBe('false')
  expect(screen.getByTestId('open-notyet').textContent).toMatch(/Not yet/)
  expect(screen.queryByTestId('open-decrypt')).toBeNull()
  await new Promise((r) => setTimeout(r, 300))
  expect(drand.calls).toEqual([])
})

test('before the round, "Check drand now" asks for public/latest and nothing else', async () => {
  const t = await makeTexts({ round: FUTURE_ROUND })
  const drand = fakeDrand({ latest: () => PAST_ROUND })
  const user = userEvent.setup()
  open(drand)
  paste(t.text)
  await user.click(screen.getByTestId('open-check'))
  await waitFor(() => expect(screen.getByTestId('open-notyet').textContent).toContain(`the latest is ${PAST_ROUND}`))
  expect(drand.calls).toEqual([`/relay/drand/${QUICKNET.hash}/public/latest`])
  expect(screen.queryByTestId('open-decrypt')).toBeNull()
})

test('after the round the text opens: the files match, and nothing downloads until a button is pressed', async () => {
  const t = await makeTexts({ round: PAST_ROUND })
  const drand = fakeDrand({ latest: () => PAST_ROUND + 7 })
  const user = userEvent.setup()
  open(drand)
  paste(t.text)
  await user.click(await screen.findByTestId('open-decrypt', {}, { timeout: T }))
  const rows = await screen.findAllByTestId('open-file-row', {}, { timeout: T })
  expect(rows.map((r) => r.querySelector('.font-mono').textContent).sort()).toEqual(Object.keys(t.restored).sort())
  expect(saved).toEqual([])                                                    // no auto-download
  for (const name of Object.keys(t.restored)) {
    await user.click(screen.getByTestId(`open-download-${name.replace(/\//g, '_')}`))
    const got = saved.at(-1)
    expect(got.name).toBe(name.replace(/\//g, '_'))
    expect(Buffer.from(got.bytes).equals(Buffer.from(bytesOf(t.restored[name])))).toBe(true)
  }
  expect(saved).toHaveLength(Object.keys(t.restored).length)
  expect(drand.calls).toContain(`/relay/drand/${QUICKNET.hash}/public/${PAST_ROUND}`)
  await user.click(screen.getByTestId('open-clear'))
  expect(screen.queryByTestId('open-result')).toBeNull()
})

test('a bare SEALED.txt opens too (the wrapper only builds the header lines; core checks everything)', async () => {
  const t = await makeTexts({ kind: 'payload', round: PAST_ROUND, payload: 'synthetic note payload\n' })
  const user = userEvent.setup()
  open(fakeDrand({ latest: () => PAST_ROUND }))
  paste(t.sealed)
  await user.click(await screen.findByTestId('open-decrypt', {}, { timeout: T }))
  await user.click(await screen.findByTestId('open-download-content', {}, { timeout: T }))
  expect(Buffer.from(saved[0].bytes).toString()).toBe('synthetic note payload\n')
})

test('the round is not published yet when the clock says it is: still "not yet", with drand\'s latest round', async () => {
  const t = await makeTexts({ round: PAST_ROUND })
  const drand = fakeDrand({ latest: () => PAST_ROUND - 1 })
  open(drand)
  paste(t.text)
  await waitFor(() => expect(screen.getByTestId('open-notyet').textContent).toContain(`the latest is ${PAST_ROUND - 1}`), { timeout: T })
  expect(screen.queryByTestId('open-decrypt')).toBeNull()
  expect(drand.calls.every((u) => u.endsWith('/public/latest'))).toBe(true)
})

test('a wrong signature from the relay decrypts nothing', async () => {
  const t = await makeTexts({ round: PAST_ROUND })
  const good = fakeDrand({ latest: () => PAST_ROUND })
  const bad = async (u) => {                                              // the right shape for the wrong round
    const r = await good.fetch(u)
    const b = await r.json()
    return new Response(JSON.stringify(u.endsWith('latest') ? b : { ...b, signature: b.signature.replace(/^../, (x) => (x === 'aa' ? 'bb' : 'aa')) }), { status: 200 })
  }
  const user = userEvent.setup()
  renderWith(<Open client={relayDrandClient({ fetch: bad, info: SYNTH_INFO })} />, { status: { serverNowMs: Date.now() } })
  paste(t.text)
  await user.click(await screen.findByTestId('open-decrypt', {}, { timeout: T }))
  await screen.findByTestId('open-error', {}, { timeout: T })
  expect(screen.queryByTestId('open-result')).toBeNull()
  expect(saved).toEqual([])
})

test('key-only text: only the key is restored, and the page says where the payload is', async () => {
  const t = await makeTexts({ round: PAST_ROUND, contents: 'key-only' })
  const user = userEvent.setup()
  open(fakeDrand({ latest: () => PAST_ROUND }))
  paste(t.text)
  expect(screen.getByTestId('open-contents').textContent).toMatch(/key only.*ar:\/\//)
  await user.click(await screen.findByTestId('open-decrypt', {}, { timeout: T }))
  await screen.findByTestId('open-result', {}, { timeout: T })
  expect(screen.getAllByTestId('open-file-row')).toHaveLength(1)
  expect(screen.getByTestId('open-note').textContent).toMatch(/ar:\/\/B+/)
})

test.each([
  ['not a timelocked text at all', () => 'hello', 'payload.header'],
  ['a cut-off text', (t) => t.text.slice(0, t.text.length - 40), 'payload.sealed-end'],
  ['a block changed by one character', (t) => t.text.replace(/(-----BEGIN AGE ENCRYPTED FILE-----\n.{30})A/s, '$1B').replace(/(-----BEGIN AGE ENCRYPTED FILE-----\n.{30})(?!B)(.)/s, '$1B'), 'payload.'],
  ['a bare SEALED.txt with an edited unlock line', (t) => t.sealed.replace(/^unlock-after: \d{4}/m, 'unlock-after: 1999'), 'payload.'],
])('a malformed text is refused with core\'s guard and nothing is fetched: %s', async (_name, mutate, guard) => {
  const t = await makeTexts({ round: PAST_ROUND })
  const drand = fakeDrand({ latest: () => PAST_ROUND })
  open(drand)
  paste(mutate(t))
  const r = await screen.findByTestId('open-refusal')
  expect(r.textContent).toContain(guard)
  expect(screen.queryByTestId('open-info')).toBeNull()
  await new Promise((x) => setTimeout(x, 200))
  expect(drand.calls).toEqual([])
})

test('plaintext never reaches storage, the network or the page text', async () => {
  const t = await makeTexts({ round: PAST_ROUND })
  const drand = fakeDrand({ latest: () => PAST_ROUND })
  const setItem = vi.spyOn(Storage.prototype, 'setItem')
  const user = userEvent.setup()
  const fetchSpy = vi.fn((...a) => drand.fetch(...a))
  renderWith(<Open client={relayDrandClient({ fetch: fetchSpy, info: SYNTH_INFO })} />, { status: { serverNowMs: Date.now() } })
  paste(t.text)
  await user.click(await screen.findByTestId('open-decrypt', {}, { timeout: T }))
  await screen.findByTestId('open-result', {}, { timeout: T })
  expect(setItem).not.toHaveBeenCalled()
  expect(localStorage.length + sessionStorage.length).toBe(0)
  expect(document.cookie).toBe('')
  expect(window.location.href).not.toContain(t.restored['identity.key'].trim())
  const page = document.body.textContent
  expect(page).not.toContain(t.restored['identity.key'].trim())
  expect(page).not.toContain('synthetic item')
  for (const [u, init] of fetchSpy.mock.calls) { expect(String(u)).toMatch(/^\/relay\/drand\//); expect(init?.body).toBeUndefined() }
})

test('the default client asks the relay\'s drand route for the pinned quicknet chain', async () => {
  const t = await makeTexts({ round: FUTURE_ROUND })
  const drand = fakeDrand({ latest: () => PAST_ROUND })
  const user = userEvent.setup()
  const spy = vi.spyOn(globalThis, 'fetch').mockImplementation((...a) => drand.fetch(...a))
  renderWith(<Open />, { status: { serverNowMs: Date.now() } })
  paste(t.text)
  await user.click(screen.getByTestId('open-check'))
  await waitFor(() => expect(spy).toHaveBeenCalled())
  expect(drand.calls).toEqual([`/relay/drand/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest`])
})

test('loading a file puts its text in the field; a file that is not UTF-8 is refused', async () => {
  const t = await makeTexts({ round: FUTURE_ROUND })
  open(fakeDrand({ latest: () => 1 }))
  fireEvent.change(screen.getByTestId('open-file'), { target: { files: [new File([t.text], 'SEALED.txt')] } })
  await screen.findByTestId('open-info')
  fireEvent.change(screen.getByTestId('open-file'), { target: { files: [new File([new Uint8Array([0xff, 0xfe, 0x41])], 'bad.txt')] } })
  await screen.findByTestId('open-file-refusal')
})

test('a file with CRLF line ends is refused with core\'s guard (a text field would have normalized them silently; a file does not)', async () => {
  const t = await makeTexts({ round: FUTURE_ROUND })
  open(fakeDrand({ latest: () => 1 }))
  fireEvent.change(screen.getByTestId('open-file'), { target: { files: [new File([t.text.replace(/\n/g, '\r\n')], 'SEALED.txt')] } })
  expect((await screen.findByTestId('open-refusal')).textContent).toContain('payload.control')
})

// ---- fix round 1 ----
const spyConsole = () => ['log', 'info', 'warn', 'error', 'debug'].map((k) => vi.spyOn(console, k).mockImplementation(() => {}))
const logged = (spies) => spies.flatMap((s) => s.mock.calls).map((a) => a.map((x) => (x instanceof Uint8Array ? Buffer.from(x).toString('latin1') : typeof x === 'string' ? x : JSON.stringify(x))).join(' ')).join('\n')

test('I-3: nothing is logged during the whole decrypt and download flow (tlock-js\'s beacon line is silenced, scoped and restored)', async () => {
  const t = await makeTexts({ round: PAST_ROUND })
  const user = userEvent.setup()
  const spies = spyConsole()
  const before = console.log
  open(fakeDrand({ latest: () => PAST_ROUND }))
  paste(t.text)
  await user.click(await screen.findByTestId('open-decrypt', {}, { timeout: T }))
  await screen.findByTestId('open-result', {}, { timeout: T })
  for (const name of Object.keys(t.restored)) await user.click(screen.getByTestId(`open-download-${name.replace(/\//g, '_')}`))
  const out = logged(spies)
  expect(console.log).toBe(before)                         // restored
  expect(out).toBe('')
  const secrets = [t.restored['identity.key'].trim(), 'synthetic item', 'MANIFEST', Buffer.from(t.restored['identity.key']).toString('base64')]
  for (const s of secrets) expect(out).not.toContain(s)
})

test('I-3: the silencing is restored when decrypt fails', async () => {
  const t = await makeTexts({ round: PAST_ROUND })
  const before = console.log
  const { decryptSealed, prepareOpen } = await import('../src/lib/open.js')
  const dead = { options: { disableBeaconVerification: false, noCache: true }, chain: () => ({ info: async () => SYNTH_INFO }), latest: async () => { throw new Error('x') }, get: async () => { throw new Error('offline') } }
  await expect(decryptSealed(prepareOpen(t.text), dead)).rejects.toThrow()
  expect(console.log).toBe(before)
})

test('I-1: after the countdown ends with the round unpublished, at most one drand request at a time and no faster than the quicknet period', async () => {
  const t = await makeTexts({ round: PAST_ROUND })
  let inflight = 0, maxInflight = 0
  const times = []
  const fetch = async (u) => {
    times.push(Date.now()); inflight++; maxInflight = Math.max(maxInflight, inflight)
    await new Promise((r) => setTimeout(r, 150))
    inflight--
    return new Response(JSON.stringify({ round: PAST_ROUND - 1, randomness: 'x', signature: 'y' }), { status: 200 })
  }
  const { unmount } = renderWith(<Open client={relayDrandClient({ fetch, info: SYNTH_INFO })} />, { status: { serverNowMs: Date.now() } })
  paste(t.text)
  await new Promise((r) => setTimeout(r, 7500))
  expect(maxInflight).toBe(1)
  expect(times.length).toBeGreaterThanOrEqual(2)
  expect(times.length).toBeLessThanOrEqual(3)              // 53 before the fix
  for (let i = 1; i < times.length; i++) expect(times[i] - times[i - 1]).toBeGreaterThanOrEqual(3000)
  unmount()
  const n = times.length
  await new Promise((r) => setTimeout(r, 4500))
  expect(times.length).toBe(n)                              // stops on unmount
}, 20_000)

test('M-2: a beacon that fails verification (wrong key / wrong signature) is refused, so disabling verification is caught', async () => {
  const t = await makeTexts({ round: PAST_ROUND })
  const { decryptSealed, prepareOpen } = await import('../src/lib/open.js')
  const good = fakeDrand({ latest: () => PAST_ROUND })
  // the chain info names the REAL quicknet key, the beacons are signed by the synthetic key: verification must fail
  const client = relayDrandClient({ fetch: good.fetch, info: QUICKNET })
  const err = await decryptSealed(prepareOpen(t.text), client).catch((e) => e)
  expect(err).toBeInstanceOf(Error)
  expect(String(err.message)).toMatch(/not valid|beacon/i)
  expect(client.options.disableBeaconVerification).toBe(false)
})

const decryptAll = async (t, drand = fakeDrand({ latest: () => PAST_ROUND })) => {
  const user = userEvent.setup()
  const view = open(drand)
  paste(t.text)
  await user.click(await screen.findByTestId('open-decrypt', {}, { timeout: T }))
  await screen.findAllByTestId('open-file-row', {}, { timeout: T })
  return { user, view }
}
const allZero = (b) => b.every((x) => x === 0)

test('M-1: a text core reads but the publisher\'s check would refuse opens, with the check\'s own ids shown as a warning', async () => {
  const t = await makeTexts({ round: PAST_ROUND })
  const edited = t.text.replace('install: go install', 'install: go  install')
  expect(edited).not.toBe(t.text)
  open(fakeDrand({ latest: () => PAST_ROUND }))
  paste(t.text)
  expect(screen.queryByTestId('open-warning')).toBeNull()
  paste(edited)
  expect(screen.getByTestId('open-warning').textContent).toMatch(/would not pass the publisher/)
  expect(screen.getAllByTestId('open-warning-issue').map((e) => e.querySelector('b').textContent)).toEqual(['payload.sealed-text'])
  expect(await screen.findByTestId('open-decrypt', {}, { timeout: T })).toBeTruthy()    // still permissive
})

test('M-3: control, bidi and zero-width characters in archive names are written out; repeated and look-alike names are numbered', async () => {
  const t = await makeTexts({ round: PAST_ROUND, vaultFiles: [['a\u202Etxt.exe', 'one'], ['a/b', 'two'], ['a_b', 'three'], ['a/b', 'four'], ['zero\u200Bwidth', 'z'], ['bell\u0007', 'b'], ['identity.key', 'spoof'], ['vault.tar.gz', 'spoof2']] })
  const { user } = await decryptAll(t)
  const rows = screen.getAllByTestId('open-file-row').map((r) => r.querySelector('.font-mono').textContent)
  expect(rows).toEqual(['identity.key', 'vault.tar.gz', 'a[U+202E]txt.exe', 'a/b', 'a_b', 'a/b (2)', 'zero[U+200B]width', 'bell[U+0007]', 'identity.key (2)', 'vault.tar.gz (2)'])
  expect(rows.join('')).not.toMatch(/[\u202E\u200B\u0007]/)
  expect(screen.getAllByTestId('open-file-renamed').length).toBe(6)
  const ids = screen.getAllByRole('button', { name: 'Download' }).map((b) => b.getAttribute('data-testid'))
  expect(new Set(ids).size).toBe(ids.length)                         // unique: no clash between a/b and a_b
  await user.click(screen.getByTestId('open-download-a_b (2)'))
  expect(saved.at(-1).name).toBe('a_b (2)')
  expect(Buffer.from(saved.at(-1).bytes).toString()).toBe('three')
})

test('M-3 (Wfix4): a name that holds the literal text "[U+202E]" cannot pass for an escaped name', async () => {
  const { escapeName, finalizeNames } = await import('../src/lib/open.js')
  expect(escapeName('a\u202Etxt')).toBe('a[U+202E]txt')
  expect(escapeName('a[U+202E]txt')).toBe('a[U+005B]U+202E]txt')
  expect(escapeName('a[u+202e]txt')).toBe('a[U+005B]u+202e]txt')
  expect(escapeName('[U+005B]')).toBe('[U+005B]U+005B]')                // the escape of "[" is itself unambiguous
  expect(escapeName('plain [brackets] and [U+12] stay')).toBe('plain [brackets] and [U+12] stay')
  const [lit, real] = finalizeNames([{ path: 'a[U+202E]txt' }, { path: 'a\u202Etxt' }])
  expect(lit.path).not.toBe(real.path)                                  // two different names, two different shown names
  expect(lit.renamed).toBe(true)                                        // and the literal one is flagged as shown differently
  expect(real.path).toBe('a[U+202E]txt')
})

test('M-4: Clear zeroes every byte the page holds and revokes its object URLs', async () => {
  const t = await makeTexts({ round: PAST_ROUND })
  const { user } = await decryptAll(t)
  const buttons = screen.getAllByRole('button', { name: 'Download' })
  for (const b of buttons) await user.click(b)
  expect(saved.length).toBe(buttons.length)
  expect(saved.every((s) => !allZero(s.bytes))).toBe(true)
  await user.click(screen.getByTestId('open-clear'))
  expect(saved.every((s) => allZero(s.bytes))).toBe(true)
})

test('M-4: leaving the page (unmount) zeroes the bytes too', async () => {
  const t = await makeTexts({ round: PAST_ROUND })
  const { user, view } = await decryptAll(t)
  for (const b of screen.getAllByRole('button', { name: 'Download' })) await user.click(b)
  view.unmount()
  expect(saved.length).toBeGreaterThan(0)
  expect(saved.every((s) => allZero(s.bytes))).toBe(true)
})

test('M-4: the object URLs made for downloads are revoked on unmount, not left to the 30 s timer', async () => {
  const { download } = await vi.importActual('../src/keys/download.js')
  const made = [], revoked = []
  URL.createObjectURL = () => { const u = `blob:x${made.length}`; made.push(u); return u }
  URL.revokeObjectURL = (u) => { revoked.push(u) }
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  const t = await makeTexts({ round: PAST_ROUND })
  const { user, view } = await decryptAll(t)
  await user.click(screen.getAllByRole('button', { name: 'Download' })[0])
  const live = saved.at(-1).scope
  expect(live).toBeInstanceOf(Set)
  download(new Uint8Array([1]), 'f', live)
  download(new Uint8Array([2]), 'g', live)
  expect(made.length).toBe(2); expect(revoked).toEqual([])
  view.unmount()
  expect(revoked.sort()).toEqual(made.sort())
  expect(live.size).toBe(0)
})

test('ruling 3: drand has published but this device\'s clock says too early: the page says the clock may be behind', async () => {
  const t = await makeTexts({ round: FUTURE_ROUND })
  const user = userEvent.setup()
  open(fakeDrand({ latest: () => FUTURE_ROUND }))
  paste(t.text)
  await user.click(await screen.findByTestId('open-check'))
  await user.click(await screen.findByTestId('open-decrypt', {}, { timeout: T }))
  const e = await screen.findByTestId('open-error', {}, { timeout: T })
  expect(e.textContent).toMatch(/your clock may be behind/)
  expect(screen.queryByTestId('open-result')).toBeNull()
})

test('M-7: the intro and the not-yet box say exactly what is sent before the round', async () => {
  const t = await makeTexts({ round: FUTURE_ROUND })
  open(fakeDrand({ latest: () => PAST_ROUND }))
  paste(t.text)
  const page = screen.getByTestId('open').textContent
  expect(page).toMatch(/sends nothing except drand.s latest round number \(through your relay\), on your click or once the countdown ends/)
  expect(page).not.toMatch(/nothing is sent anywhere/i)
  expect(screen.getByTestId('open-notyet').textContent).toMatch(/Nothing has been fetched except, at most, drand.s latest round number/)
})

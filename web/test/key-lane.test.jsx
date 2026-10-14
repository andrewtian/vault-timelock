import { useState } from 'react'
import { test, expect, vi, beforeEach } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import KeyLane from '../src/keys/KeyLane.jsx'
import SecretInput from '../src/keys/SecretInput.jsx'
import { encryptKey, fromSecret, newKey, openBackup } from '../src/lib/core.js'
import { lastBusy, renderWith } from './helpers.jsx'

const saved = []
vi.mock('../src/keys/download.js', () => ({ download: (bytes, name) => { saved.push({ bytes, name }) } }))
beforeEach(() => { saved.length = 0 })

const PASS = 'correct horse battery staple orchid lantern'
const OTHER = 'seven plum bicycle marble window rocket'
const fileOf = (bytes, name) => new File([bytes], name, { type: 'application/octet-stream' })
const T = 60_000

async function makeNewKey(user, chain = 'eth') {
  await user.click(screen.getByTestId(`keychoice-${chain}-new`))
  await user.type(screen.getByTestId(`kpass1-${chain}`), PASS)
  await user.type(screen.getByTestId(`kpass2-${chain}`), PASS)
  await user.click(screen.getByTestId(`kbackup-${chain}`))
  await waitFor(() => expect(saved).toHaveLength(1), { timeout: T })
}

test('new key: backup is downloaded, the SAVED file is re-selected and verified, the tick shows the address', async () => {
  const user = userEvent.setup()
  renderWith(<KeyLane chain="eth" />)
  await makeNewKey(user)
  expect(saved[0].name).toMatch(/^vt-eth-key-\d{8}T\d{6}Z\.age$/)
  expect(screen.queryByTestId('kaddr-eth')).toBeNull()
  await user.upload(screen.getByTestId('kverifyfile-eth'), fileOf(saved[0].bytes, saved[0].name))
  await user.type(screen.getByTestId('kverifypass-eth'), PASS)
  await user.click(screen.getByTestId('kverify-eth'))
  await screen.findByTestId('kverified-eth', {}, { timeout: T })
  expect(screen.queryByTestId('kaddr-eth')).toBeNull()                       // not yet: the tick is required
  await user.click(screen.getByTestId('ksaved-eth'))
  expect(screen.getByTestId('kaddr-eth').textContent).toMatch(/^0x[0-9a-fA-F]{40}$/)
  expect(screen.getByTestId('keylane-eth').dataset.step).toBe('ready')
  expect(lastBusy().reason).toContain('Ethereum key loaded')                // busy while a key is loaded
}, T * 2)

// Wredl: the download may never arrive; the verify box offers a way back that keeps the key and retains no ciphertext.
test('redo: back to the passphrase step with the same key and clean fields; a second backup verifies and finishes; the first still verifies', async () => {
  const user = userEvent.setup()
  const { container } = renderWith(<KeyLane chain="eth" />)
  await makeNewKey(user)
  const box = screen.getByTestId('kverifybox-eth')
  expect(box.textContent).toMatch(/Download started: vt-eth-key-/)
  expect(box.textContent).not.toMatch(/Downloaded/)
  const redo = screen.getByTestId('kredo-eth')
  expect(redo.textContent).toBe('The file did not arrive — make the backup again')
  // leave state behind in the verify box: a chosen file, a typed passphrase and a real error
  await user.upload(screen.getByTestId('kverifyfile-eth'), fileOf(saved[0].bytes, saved[0].name))
  await user.type(screen.getByTestId('kverifypass-eth'), OTHER)
  await user.click(screen.getByTestId('kverify-eth'))
  await screen.findByTestId('kerr-eth', {}, { timeout: T })
  await user.click(redo)
  expect(screen.queryByTestId('kverifybox-eth')).toBeNull()
  expect(screen.getByTestId('keylane-eth').dataset.step).toBe('backup')
  expect(screen.getByTestId('kpass1-eth').value).toBe('')
  expect(screen.getByTestId('kpass2-eth').value).toBe('')
  expect(screen.queryByTestId('kerr-eth')).toBeNull()                          // the error shown before the redo is gone
  expect(screen.queryByTestId('kaddr-eth')).toBeNull()
  await user.type(screen.getByTestId('kpass1-eth'), OTHER)
  await user.type(screen.getByTestId('kpass2-eth'), OTHER)
  await user.click(screen.getByTestId('kbackup-eth'))
  await waitFor(() => expect(saved).toHaveLength(2), { timeout: T })
  // the new verify box starts empty: no passphrase, and no file kept from before (typing a passphrase alone does not enable Verify)
  expect(screen.getByTestId('kverifypass-eth').value).toBe('')
  expect(screen.getByTestId('kverifyfile-eth').files).toHaveLength(0)
  await user.type(screen.getByTestId('kverifypass-eth'), PASS)
  expect(screen.getByTestId('kverify-eth').disabled).toBe(true)
  await user.clear(screen.getByTestId('kverifypass-eth'))
  const a = await openBackup(saved[0].bytes, PASS), b = await openBackup(saved[1].bytes, OTHER)
  expect(b.address).toBe(a.address); expect(b.secret).toBe(a.secret)         // the redo neither generated nor dropped the key
  expect(Buffer.from(saved[1].bytes).equals(Buffer.from(saved[0].bytes))).toBe(false)   // fresh salt
  // (b) the second backup verifies from its own file ...
  await user.upload(screen.getByTestId('kverifyfile-eth'), fileOf(saved[1].bytes, saved[1].name))
  await user.type(screen.getByTestId('kverifypass-eth'), OTHER)
  await user.click(screen.getByTestId('kverify-eth'))
  await screen.findByTestId('kverified-eth', {}, { timeout: T })
  expect(container.querySelector('[data-testid="kredo-eth"]')).toBeNull()
  await user.click(screen.getByTestId('ksaved-eth'))
  expect(screen.getByTestId('kaddr-eth').textContent).toBe(a.address)          // ... and the lane finishes with the same key
}, T * 5)

test('redo: the FIRST backup, which did arrive, still verifies after a redo', async () => {
  const user = userEvent.setup()
  renderWith(<KeyLane chain="eth" />)
  await makeNewKey(user)
  await user.click(screen.getByTestId('kredo-eth'))
  await user.type(screen.getByTestId('kpass1-eth'), OTHER)
  await user.type(screen.getByTestId('kpass2-eth'), OTHER)
  await user.click(screen.getByTestId('kbackup-eth'))
  await waitFor(() => expect(saved).toHaveLength(2), { timeout: T })
  await user.upload(screen.getByTestId('kverifyfile-eth'), fileOf(saved[0].bytes, saved[0].name))
  await user.type(screen.getByTestId('kverifypass-eth'), PASS)
  await user.click(screen.getByTestId('kverify-eth'))
  await screen.findByTestId('kverified-eth', {}, { timeout: T })
}, T * 4)

test('redo is disabled while a verify is running (busy) and while the lane is locked', async () => {
  const user = userEvent.setup()
  function Lockable() {
    const [l, setL] = useState(false)
    return <><button data-testid="lock" onClick={() => setL(true)}>lock</button><KeyLane chain="eth" locked={l} /></>
  }
  renderWith(<Lockable />)
  await makeNewKey(user)
  expect(screen.getByTestId('kredo-eth').disabled).toBe(false)
  await user.upload(screen.getByTestId('kverifyfile-eth'), fileOf(saved[0].bytes, saved[0].name))
  await user.type(screen.getByTestId('kverifypass-eth'), PASS)
  fireEvent.click(screen.getByTestId('kverify-eth'))                           // synchronous: the decrypt is still pending
  expect(screen.getByTestId('kverify-eth').textContent).toBe('Decrypting…')   // busy
  expect(screen.getByTestId('kredo-eth').disabled).toBe(true)
  await screen.findByTestId('kverified-eth', {}, { timeout: T })
}, T * 3)

test('redo is disabled while locked', async () => {
  const user = userEvent.setup()
  function Lockable() {
    const [l, setL] = useState(false)
    return <><button data-testid="lock" onClick={() => setL(true)}>lock</button><KeyLane chain="eth" locked={l} /></>
  }
  renderWith(<Lockable />)
  await makeNewKey(user)
  expect(screen.getByTestId('kredo-eth').disabled).toBe(false)
  await user.click(screen.getByTestId('lock'))
  expect(screen.getByTestId('kredo-eth').disabled).toBe(true)
}, T * 2)

test('redo on an imported key: the same address after the redo (the redo never drops the key)', async () => {
  const user = userEvent.setup()
  const k = newKey('eth')
  renderWith(<KeyLane chain="eth" />)
  await user.click(screen.getByTestId('keychoice-eth-import'))
  await user.click(screen.getByTestId('kimport-eth-key'))
  await user.type(screen.getByTestId('ksecret-eth'), k.secret)
  await user.click(screen.getByTestId('kcheck-eth'))
  await user.click(screen.getByTestId('kuse-eth'))
  await user.type(screen.getByTestId('kpass1-eth'), PASS)
  await user.type(screen.getByTestId('kpass2-eth'), PASS)
  await user.click(screen.getByTestId('kbackup-eth'))
  await waitFor(() => expect(saved).toHaveLength(1), { timeout: T })
  await user.click(screen.getByTestId('kredo-eth'))
  await user.type(screen.getByTestId('kpass1-eth'), OTHER)
  await user.type(screen.getByTestId('kpass2-eth'), OTHER)
  await user.click(screen.getByTestId('kbackup-eth'))
  await waitFor(() => expect(saved).toHaveLength(2), { timeout: T })
  expect((await openBackup(saved[1].bytes, OTHER)).address).toBe(k.address)
}, T * 4)

test('a wrong-passphrase re-select keeps the lane locked', async () => {
  const user = userEvent.setup()
  renderWith(<KeyLane chain="eth" />)
  await makeNewKey(user)
  await user.upload(screen.getByTestId('kverifyfile-eth'), fileOf(saved[0].bytes, saved[0].name))
  await user.type(screen.getByTestId('kverifypass-eth'), OTHER)
  await user.click(screen.getByTestId('kverify-eth'))
  expect((await screen.findByTestId('kerr-eth', {}, { timeout: T })).textContent).toMatch(/does not open with that passphrase/)
  expect(screen.queryByTestId('kverified-eth')).toBeNull()
  expect(screen.queryByTestId('ksaved-eth')).toBeNull()
  expect(screen.queryByTestId('kaddr-eth')).toBeNull()
  expect(screen.getByTestId('keylane-eth').dataset.step).toBe('backup')
  expect(lastBusy().busy).toBe(false)
}, T * 2)

test("a different key's backup is refused: decrypts to a DIFFERENT key", async () => {
  const user = userEvent.setup()
  renderWith(<KeyLane chain="eth" />)
  await makeNewKey(user)
  const { ct } = await encryptKey(newKey('eth'), PASS, 'local')            // another key, same passphrase
  await user.upload(screen.getByTestId('kverifyfile-eth'), fileOf(ct, 'other.age'))
  await user.type(screen.getByTestId('kverifypass-eth'), PASS)
  await user.click(screen.getByTestId('kverify-eth'))
  expect((await screen.findByTestId('kerr-eth', {}, { timeout: T })).textContent).toMatch(/decrypts to a DIFFERENT key/)
  expect(screen.queryByTestId('kaddr-eth')).toBeNull()
}, T * 2)

test('the backup is byte-compatible with the prototype: same age JSON keys first, network appended', async () => {
  const user = userEvent.setup()
  renderWith(<KeyLane chain="sol" />)
  await makeNewKey(user, 'sol')
  const j = await openBackup(saved[0].bytes, PASS)                       // core's one age opener: JSON.parse(decrypt(…))
  expect(Object.keys(j)).toEqual(['chain', 'address', 'secret', 'createdAt', 'network'])
  expect(j.chain).toBe('sol'); expect(j.network).toBe('local'); expect(j.createdAt).toMatch(/Z$/)
  expect(fromSecret('sol', j.secret).address).toBe(j.address)
}, T * 2)

async function oldBackup(chain, network) {
  const key = newKey(chain)
  const { ct } = await encryptKey(key, PASS, network)
  return { key, ct }
}

test("import from a backup of this network: no extra tick; the old page's backup (no network) needs one", async () => {
  const user = userEvent.setup()
  const { key, ct } = await oldBackup('eth', 'local')
  const first = renderWith(<KeyLane chain="eth" />)
  await user.click(screen.getByTestId('keychoice-eth-import'))
  await user.click(screen.getByTestId('kimport-eth-file'))
  await user.upload(screen.getByTestId('kfile-eth'), fileOf(ct, 'a.age'))
  await user.type(screen.getByTestId('kfilepass-eth'), PASS)
  await user.click(screen.getByTestId('kfileload-eth'))
  await waitFor(() => expect(screen.getByTestId('kaddr-eth').textContent).toBe(key.address), { timeout: T })
  expect(screen.getByTestId('ksource-eth').textContent).toBe('from backup')
  first.unmount()

  // a backup exactly as the prototype wrote it: { chain, address, secret, createdAt } only
  const k2 = newKey('eth')
  const { ct: old } = await encryptKey(k2, PASS)                         // no network: the prototype's four keys only
  expect(Object.keys(await openBackup(old, PASS))).toEqual(['chain', 'address', 'secret', 'createdAt'])
  renderWith(<KeyLane chain="eth" />)
  await user.click(screen.getByTestId('keychoice-eth-import'))
  await user.click(screen.getByTestId('kimport-eth-file'))
  await user.upload(screen.getByTestId('kfile-eth'), fileOf(old, 'old.age'))
  await user.type(screen.getByTestId('kfilepass-eth'), PASS)
  await user.click(screen.getByTestId('kfileload-eth'))
  const warn = await screen.findByTestId('knetwarn-eth', {}, { timeout: T })
  expect(warn.textContent).toMatch(/does not record a network/)
  expect(screen.getByTestId('kfileuse-eth').disabled).toBe(true)
  expect(screen.queryByTestId('kaddr-eth')).toBeNull()
  await user.click(screen.getByTestId('knetack-eth'))
  await user.click(screen.getByTestId('kfileuse-eth'))
  expect(screen.getByTestId('kaddr-eth').textContent).toBe(k2.address)
}, T * 3)

async function importBackup(user, chain, ct, name = 'b.age') {
  await user.click(screen.getByTestId(`keychoice-${chain}-import`))
  await user.click(screen.getByTestId(`kimport-${chain}-file`))
  await user.upload(screen.getByTestId(`kfile-${chain}`), fileOf(ct, name))
  await user.type(screen.getByTestId(`kfilepass-${chain}`), PASS)
  await user.click(screen.getByTestId(`kfileload-${chain}`))
}

// W6 (M1 issue 1, spec §3.4, guard web.backup-network): a backup made on another network is REFUSED; no tick, no override.
test.each([['local', 'testnet'], ['testnet', 'mainnet'], ['mainnet', 'local']])('page on %s: a backup made on %s is refused, naming both networks, with no way past it', async (page, made) => {
  const user = userEvent.setup()
  const { ct } = await oldBackup('sol', made)
  renderWith(<KeyLane chain="sol" />, { network: page })
  await importBackup(user, 'sol', ct)
  const err = (await screen.findByTestId('kerr-sol', {}, { timeout: T })).textContent
  expect(err).toContain(`made on the ${made} network`)
  expect(err).toContain(`this page is on ${page}`)
  expect(err).toMatch(/backup\.network/)
  expect(screen.queryByTestId('knetwarn-sol')).toBeNull()                 // no tick offered
  expect(screen.queryByTestId('knetack-sol')).toBeNull()
  expect(screen.queryByTestId('kfileuse-sol')).toBeNull()
  expect(screen.queryByTestId('kaddr-sol')).toBeNull()
  expect(screen.getByTestId('keylane-sol').dataset.step).toBe('import')
  expect(lastBusy().busy).toBe(false)                                     // no key held
  await user.click(screen.getByTestId('kimport-sol-key'))                 // the refused key's address must not linger where the key-import panel would show it
  expect(screen.queryByTestId('kderived-sol')).toBeNull()
}, T * 2)

test.each(['local', 'testnet', 'mainnet'])('page on %s: a backup made on %s is accepted with no tick', async (net) => {
  const user = userEvent.setup()
  const { key, ct } = await oldBackup('eth', net)
  renderWith(<KeyLane chain="eth" />, { network: net })
  await importBackup(user, 'eth', ct)
  await waitFor(() => expect(screen.getByTestId('kaddr-eth').textContent).toBe(key.address), { timeout: T })
  expect(screen.queryByTestId('knetwarn-eth')).toBeNull()
}, T * 2)

test('a wrong passphrase on import shows an error and loads nothing', async () => {
  const user = userEvent.setup()
  const { ct } = await oldBackup('eth', 'local')
  renderWith(<KeyLane chain="eth" />)
  await user.click(screen.getByTestId('keychoice-eth-import'))
  await user.click(screen.getByTestId('kimport-eth-file'))
  await user.upload(screen.getByTestId('kfile-eth'), fileOf(ct, 'a.age'))
  await user.type(screen.getByTestId('kfilepass-eth'), OTHER)
  await user.click(screen.getByTestId('kfileload-eth'))
  expect((await screen.findByTestId('kerr-eth', {}, { timeout: T })).textContent).toMatch(/wrong passphrase/)
  expect(screen.queryByTestId('kaddr-eth')).toBeNull()
}, T)

test('private-key import shows the derived address', async () => {
  const user = userEvent.setup()
  const k = newKey('eth')
  renderWith(<KeyLane chain="eth" />)
  await user.click(screen.getByTestId('keychoice-eth-import'))
  await user.click(screen.getByTestId('kimport-eth-key'))
  await user.type(screen.getByTestId('ksecret-eth'), k.secret)
  await user.click(screen.getByTestId('kcheck-eth'))
  expect(screen.getByTestId('kderived-eth').textContent).toBe(k.address)
  await user.clear(screen.getByTestId('ksecret-eth'))
  await user.type(screen.getByTestId('ksecret-eth'), '0x1234')
  await user.click(screen.getByTestId('kcheck-eth'))
  expect(screen.getByTestId('kerr-eth').textContent).toMatch(/0x followed by exactly 64 hex/)
})

test('SecretInput attributes (MQ I4), an id and a name, and no <form> in the lane', async () => {
  const user = userEvent.setup()
  const { container } = renderWith(<><KeyLane chain="eth" /><SecretInput data-testid="s1" /><SecretInput data-testid="s2" /></>)
  const s = screen.getByTestId('s1')
  expect(s.getAttribute('type')).toBe('text')
  expect(s.getAttribute('autocomplete')).toBe('off')
  expect(s.getAttribute('autocorrect')).toBe('off')
  expect(s.getAttribute('autocapitalize')).toBe('off')
  expect(s.getAttribute('spellcheck')).toBe('false')
  for (const a of ['data-1p-ignore', 'data-lpignore', 'data-bwignore']) expect(s.getAttribute(a)).toBe('true')
  expect(s.getAttribute('data-form-type')).toBe('other')
  expect(s.classList.contains('secret-input')).toBe(true)                   // masked by .secret-input (index.css) and inline
  expect(s.id).not.toBe(''); expect(s.name).toMatch(/^f[a-z0-9]+$/)
  expect(s.name).not.toBe(screen.getByTestId('s2').name)                  // a random name per field
  await user.click(screen.getByTestId('keychoice-eth-import'))
  await user.click(screen.getByTestId('kimport-eth-key'))
  const secret = screen.getByTestId('ksecret-eth')
  expect(secret.getAttribute('autocomplete')).toBe('off'); expect(secret.getAttribute('data-1p-ignore')).toBe('true')
  expect(container.querySelector('form')).toBeNull()
  for (const el of container.querySelectorAll('input,select,textarea')) { expect(el.id, el.outerHTML).not.toBe(''); expect(el.name, el.outerHTML).not.toBe('') }
  expect(within(screen.getByTestId('keylane-eth')).getByText('Ethereum key')).toBeTruthy()
})

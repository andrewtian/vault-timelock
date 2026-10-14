import { test, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { useState } from 'react'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import MessageInput, { checkMessage } from '../src/jobs/MessageInput.jsx'
import { renderWith } from './helpers.jsx'

const FIX = join(import.meta.dirname, '../../packages/core/contract/fixtures/messages')
const SRC = join(import.meta.dirname, '../src')
const fixture = (n) => new Uint8Array(readFileSync(join(FIX, n)))
const file = (bytes, name = 'm.txt') => new File([bytes], name, { type: 'text/plain' })

function Host() {
  const [v, setV] = useState('')
  return <MessageInput value={v} onChange={setV} />
}
const load = (user, bytes, name) => user.upload(screen.getByTestId('message-file'), file(bytes, name))

const walk = (d, out = []) => { for (const f of readdirSync(d)) { const p = join(d, f); if (statSync(p).isDirectory()) walk(p, out); else out.push(p) } return out }

test('the message field is empty on mount; no sample text exists in web/src', () => {
  renderWith(<Host />)
  expect(screen.getByTestId('message').value).toBe('')
  expect(screen.queryByTestId('message-ok')).toBeNull()
  const hits = walk(SRC).filter((p) => /\.(jsx?|html|css)$/.test(p)).filter((p) => /lorem ipsum|sample text|sample message|example message|hello,? world|the quick brown fox/i.test(readFileSync(p, 'utf8')))
  expect(hits).toEqual([])
})

test('the loader decodes with a strict UTF-8 decoder: no FileReader anywhere in web/src', () => {
  const all = walk(SRC).filter((p) => /\.jsx?$/.test(p)).map((p) => readFileSync(p, 'utf8')).join('\n')
  expect(all).not.toMatch(/new\s+FileReader|readAsText\s*\(/)
  expect(readFileSync(join(SRC, 'lib/core.js'), 'utf8')).toContain("new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })")
})

test('Load text file: a valid file shows bytes, sha256 and the hex64 warning, and goes into the field', async () => {
  const user = userEvent.setup()
  renderWith(<Host />)
  await load(user, fixture('sealed-like.txt'), 'sealed-like.txt')
  await waitFor(() => expect(screen.getByTestId('message-ok')).toBeTruthy())
  expect(screen.getByTestId('message-loaded').textContent).toMatch(/514 bytes, sha256 ee3d6ce1f65081ef7d4ba1d47f3fa0af53bf627f1d91048a6151fde91da9f5dc/)
  expect(screen.getByTestId('message-sha').textContent).toBe('ee3d6ce1f65081ef7d4ba1d47f3fa0af53bf627f1d91048a6151fde91da9f5dc')
  expect(screen.getByTestId('message-hex64')).toBeTruthy()
  expect(screen.getByTestId('message').value.length).toBeGreaterThan(0)
})

test('multibyte file: the bytes and sha256 are the contract fixture values', async () => {
  const user = userEvent.setup()
  renderWith(<Host />)
  await load(user, fixture('multibyte-5k.txt'), 'multibyte-5k.txt')
  await waitFor(() => expect(screen.getByTestId('message-ok')).toBeTruthy())
  expect(screen.getByTestId('message-ok').textContent).toContain('5048 bytes')
  expect(screen.getByTestId('message-sha').textContent).toBe('5d51f8d98fc40a56013f1ecd939905c3f52f727aee0c754398b69b004c515f52')
  expect(screen.queryByTestId('message-hex64')).toBeNull()
})

test('a CRLF file is refused with the guard text and nothing is loaded', async () => {
  const user = userEvent.setup()
  renderWith(<Host />)
  await load(user, fixture('bad/crlf.txt'), 'crlf.txt')
  const r = await screen.findByTestId('message-refusal')
  expect(r.textContent).toContain('message.control')
  expect(r.textContent).toMatch(/only LF line breaks/)
  expect(r.textContent).toMatch(/sha256 [0-9a-f]{64}/)
  expect(screen.getByTestId('message').value).toBe('')
})

test('invalid UTF-8 is message.utf8 (never replaced), a BOM is message.control', async () => {
  const user = userEvent.setup()
  renderWith(<Host />)
  await load(user, fixture('bad/invalid-utf8.txt'), 'bad.txt')
  expect((await screen.findByTestId('message-refusal')).textContent).toContain('message.utf8')
  expect(screen.getByTestId('message').value).toBe('')
  await load(user, fixture('bad/bom.txt'), 'bom.txt')
  await waitFor(() => expect(screen.getByTestId('message-refusal').textContent).toContain('message.control'))
  expect(screen.getByTestId('message').value).toBe('')
})

// The page-side checks agree with the contract fixtures for every refusal the page makes itself.
test.each([['nfd.txt', 'message.nfc'], ['bidi.txt', 'message.control'], ['crlf.txt', 'message.control'], ['bom.txt', 'message.control'], ['empty.txt', 'message.empty']])(
  'fixture %s -> %s', (name, guard) => {
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(fixture(`bad/${name}`))
    const r = checkMessage(text)
    expect(r.ok).toBe(false); expect(r.guard).toBe(guard)
  })

test('the 100 KB file: the parts preview shows ETH 2 and SOL about 100', async () => {
  const user = userEvent.setup()
  renderWith(<Host />)
  const line = 'The quick vault lines, one by one.\n'
  const bytes = new TextEncoder().encode(line.repeat(Math.ceil(102400 / line.length)).slice(0, 102400))
  expect(bytes.length).toBe(102400)
  await load(user, bytes, 'big.txt')
  await waitFor(() => expect(screen.getByTestId('parts-preview')).toBeTruthy(), { timeout: 20000 })
  expect(screen.getByTestId('parts-eth').textContent).toMatch(/: 2 transaction/); expect(screen.getByTestId('parts-eth').dataset.count).toBe('2')
  const sol = Number(screen.getByTestId('parts-sol').dataset.count)
  expect(sol).toBeGreaterThanOrEqual(100); expect(sol).toBeLessThanOrEqual(110)
  expect(screen.getByTestId('parts-eth').textContent).toMatch(/header \d+ B on part 1/)
}, 30000)

test('typing shows the issue for a refused text and the preview for a good one', async () => {
  const user = userEvent.setup()
  renderWith(<Host />)
  await user.type(screen.getByTestId('message'), 'one line')
  expect(screen.getByTestId('message-ok').textContent).toContain('8 bytes')
  expect(screen.getByTestId('parts-eth').dataset.count).toBe('1')
  expect(screen.getByTestId('parts-eth').textContent).toMatch(/no header/)
  await user.clear(screen.getByTestId('message'))
  expect(screen.queryByTestId('message-ok')).toBeNull()
})

// ---- normalize line endings / tabs (E1 ruling 4): explicit, operator-triggered, with a summary ----
test('CR/CRLF/TAB in the field are refused as written; Normalize rewrites only those, on click, and says what changed', async () => {
  const user = userEvent.setup()
  function Seeded() {
    const [v, setV] = useState('first\r\nsecond\rthird\tcolumn')
    return <MessageInput value={v} onChange={setV} />
  }
  renderWith(<Seeded />)
  expect(screen.getByTestId('message-issue').textContent).toContain('message.control')
  const offer = screen.getByTestId('normalize-offer')
  expect(offer.textContent).toMatch(/1 CRLF → LF, 1 lone CR → LF, 1 TAB → 4 spaces/)
  // nothing is rewritten by itself: the text stays refused (the DOM shows CR as LF, the HTML textarea rule; the text
  // the page validates and would send is the component's own value)
  expect(screen.getByTestId('message').value).toContain('\t')
  expect(screen.queryByTestId('message-ok')).toBeNull()
  expect(screen.queryByTestId('normalize-summary')).toBeNull()
  await user.click(screen.getByTestId('normalize'))
  expect(screen.getByTestId('message').value).toBe('first\nsecond\nthird    column')
  const sum = screen.getByTestId('normalize-summary').textContent
  expect(sum).toMatch(/Normalized on your request: 1 CRLF → LF, 1 lone CR → LF, 1 TAB → 4 spaces/)
  expect(sum).toContain(`now 28 bytes, sha256 ${checkMessage('first\nsecond\nthird    column').sha256}`)
  expect(screen.getByTestId('message-ok')).toBeTruthy()
  expect(screen.queryByTestId('normalize-offer')).toBeNull()
  // typing again clears the summary (it described an earlier text)
  await user.type(screen.getByTestId('message'), '!')
  expect(screen.queryByTestId('normalize-summary')).toBeNull()
})

test('a file refused only for its line endings can be loaded normalized on click; other refusals offer nothing', async () => {
  const user = userEvent.setup()
  renderWith(<Host />)
  await load(user, fixture('bad/crlf.txt'), 'crlf.txt')
  const r = await screen.findByTestId('message-refusal')
  expect(r.textContent).toMatch(/Only its line endings \/ tabs are refused \(\d+ CRLF → LF\)/)
  expect(screen.getByTestId('message').value).toBe('')
  await user.click(screen.getByTestId('normalize-file'))
  expect(screen.queryByTestId('message-refusal')).toBeNull()
  expect(screen.getByTestId('message').value).not.toMatch(/\r/)
  expect(screen.getByTestId('message-loaded').textContent).toMatch(/Loaded crlf\.txt/)
  expect(screen.getByTestId('normalize-summary').textContent).toMatch(/CRLF → LF/)
  expect(screen.getByTestId('message-ok')).toBeTruthy()
  await load(user, fixture('bad/nfd.txt'), 'nfd.txt')
  expect((await screen.findByTestId('message-refusal')).textContent).toContain('message.nfc')
  expect(screen.queryByTestId('normalize-file')).toBeNull()
})

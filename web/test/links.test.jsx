// Explorer links per network, the receipt download, and the by-hand reassembly commands (W4).
// Mainnet: copy-only, no href anywhere. Testnet: a dialog with copy or open. Local: Otterscan opens; the Solana
// custom-cluster link comes with W1's LocalExplorerNote.
import { spawnSync } from 'node:child_process'
import { test, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import LinkButtons, { txLinks } from '../src/jobs/LinkButtons.jsx'
import ReceiptButton from '../src/jobs/ReceiptButton.jsx'
import { ETH_SCRIPT, SOL_SCRIPT, copyIds, handReassembly } from '../src/jobs/handReassembly.js'
import { partPrefix } from '@vault-timelock/core/contracts'
import { sha256Hex } from '@vault-timelock/core/job'
import { json } from './helpers.jsx'

const ETH_TX = '0x' + 'ab'.repeat(32)
const SOL_SIG = '5'.repeat(88)
const SIGNER = '0x8739Eb87B3d11f221Df63454F8D229a1A4F4049C'
const NULL = '0x0000000000000000000000000000000000000000'
afterEach(() => { vi.restoreAllMocks() })

test('Sepolia: tx and /address/0x0 on sepolia.etherscan.io; Solana devnet on the three explorers with the devnet cluster', () => {
  const eth = txLinks('testnet', 'eth', ETH_TX, SIGNER, NULL).map((l) => l.url)
  expect(eth).toContain(`https://sepolia.etherscan.io/tx/${ETH_TX}`)
  expect(eth).toContain(`https://sepolia.etherscan.io/address/${NULL}`)
  expect(eth).toContain(`https://sepolia.etherscan.io/address/${SIGNER}`)
  const sol = txLinks('testnet', 'sol', SOL_SIG, '9xx7qC7uwTAeaSo7T5Gk9canYBosFh1pMQaDmQEa83Tb').map((l) => l.url)
  expect(sol).toContain(`https://explorer.solana.com/tx/${SOL_SIG}?cluster=devnet`)
  expect(sol).toContain(`https://solscan.io/tx/${SOL_SIG}?cluster=devnet`)
  expect(sol).toContain(`https://solana.fm/tx/${SOL_SIG}?cluster=devnet-solana`)
  expect(txLinks('testnet', 'eth', ETH_TX, SIGNER, NULL).every((l) => l.use === 'dialog')).toBe(true)
})

test('testnet: Open… shows a dialog with Copy and Open (noopener); nothing is fetched', async () => {
  const user = userEvent.setup()
  const f = vi.fn(); globalThis.fetch = f
  const writeText = vi.fn(async () => {}); Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
  render(<LinkButtons network="testnet" chain="eth" txId={ETH_TX} signer={SIGNER} to={NULL} />)
  expect(document.querySelectorAll('a[href]')).toHaveLength(0)              // no navigation until the dialog's Open
  await user.click(screen.getByTestId('link-eth-dialog-0'))
  expect(screen.getByTestId('link-dialog-url').textContent).toBe(`https://sepolia.etherscan.io/tx/${ETH_TX}`)
  const open = screen.getByTestId('link-dialog-open')
  expect(open.getAttribute('href')).toBe(`https://sepolia.etherscan.io/tx/${ETH_TX}`)
  expect(open.getAttribute('rel')).toMatch(/noopener/)
  await user.click(screen.getByTestId('link-dialog-copy'))
  expect(writeText).toHaveBeenCalledWith(`https://sepolia.etherscan.io/tx/${ETH_TX}`)
  expect(f).not.toHaveBeenCalled()
})

test('mainnet links have no href navigation: copy-only text for ETH and SOL', async () => {
  for (const [chain, id, signer, to] of [['eth', ETH_TX, SIGNER, NULL], ['sol', SOL_SIG, '9xx7qC7uwTAeaSo7T5Gk9canYBosFh1pMQaDmQEa83Tb', undefined]]) {
    const { container, unmount } = render(<LinkButtons network="mainnet" chain={chain} txId={id} signer={signer} to={to} />)
    expect(container.querySelectorAll('a')).toHaveLength(0)
    expect(container.querySelectorAll('[href]')).toHaveLength(0)
    const rows = container.querySelectorAll(`[data-testid^="link-${chain}-"][data-use]`)
    expect(rows.length).toBeGreaterThan(0)
    for (const r of rows) expect(r.dataset.use).toBe('copy')
    expect(screen.getByTestId(`link-${chain}-text-0`).textContent).toMatch(/^https:\/\//)
    unmount()
  }
})

test('local: the Otterscan link opens directly; the Solana custom-cluster link comes with the Apps-on-device note', () => {
  const { container, unmount } = render(<LinkButtons network="local" chain="eth" txId={ETH_TX} signer={SIGNER} to={NULL} />)
  const a = container.querySelector('a[href]')
  expect(a.getAttribute('href')).toBe(`http://127.0.0.1:5100/tx/${ETH_TX}`)
  expect(screen.queryByTestId('local-explorer-note')).toBeNull()
  unmount()
  const sol = render(<LinkButtons network="local" chain="sol" txId={SOL_SIG} signer="9xx7qC7uwTAeaSo7T5Gk9canYBosFh1pMQaDmQEa83Tb" />)
  expect(sol.container.querySelector('a[href]').getAttribute('href')).toMatch(/explorer\.solana\.com\/tx\/.*cluster=custom/)
  expect(screen.getByTestId('local-explorer-note').textContent).toMatch(/Apps on device/)
})

test('an unknown network gets no links (never another network’s explorer)', () => {
  expect(txLinks('elsewhere', 'eth', ETH_TX, SIGNER, NULL)).toEqual([])
})

// ---- the receipt: the API's bytes, as served ----
test('Receipt downloads the API bytes exactly and reports the size', async () => {
  const user = userEvent.setup()
  const body = '{"format":"vt-receipt/1",\n  "jobId":"0011223344556677"}\n'
  globalThis.fetch = async (u) => (String(u) === '/api/jobs/0011223344556677/receipt' ? new Response(body, { status: 200, headers: { 'content-type': 'application/json' } }) : json(404, {}))
  let blob = null, name = null
  URL.createObjectURL = (b) => { blob = b; return 'blob:x' }; URL.revokeObjectURL = () => {}
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function () { name = this.download })
  render(<ReceiptButton jobId="0011223344556677" />)
  await user.click(screen.getByTestId('job-receipt'))
  await waitFor(() => expect(screen.getByTestId('job-receipt-msg').textContent).toMatch(/saved vt-receipt-0011223344556677\.json/))
  expect(click).toHaveBeenCalled()
  expect(name).toBe('vt-receipt-0011223344556677.json')
  const text = await new Promise((res) => { const r = new FileReader(); r.onload = () => res(r.result); r.readAsText(blob) })
  expect(text).toBe(body)
})

test('Receipt: an API refusal is shown, nothing is saved', async () => {
  const user = userEvent.setup()
  globalThis.fetch = async () => json(404, { error: { guard: 'job.missing', message: 'no such job' } })
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  render(<ReceiptButton jobId="0011223344556677" />)
  await user.click(screen.getByTestId('job-receipt'))
  await waitFor(() => expect(screen.getByTestId('job-receipt-msg').textContent).toMatch(/job\.missing/))
  expect(click).not.toHaveBeenCalled()
})

// ---- by-hand reassembly: the generated scripts really reassemble vt-parts/1 parts ----
const TEXTV = 'héllo wörld — 日本語 and an emoji 😀 at the end\n'.repeat(3)
const SHA = sha256Hex(TEXTV)
function chunks(text, n) {
  const cps = [...text], size = Math.ceil(cps.length / n)
  return Array.from({ length: n }, (_, i) => cps.slice(i * size, (i + 1) * size).join(''))
}
const partTexts = chunks(TEXTV, 3).map((c, i) => partPrefix({ part: i + 1, parts: 3, sha256: SHA, copy: null, copies: null }) + c)
const py = (script, stdin, sha = SHA, signer = SIGNER) => spawnSync('python3', ['-I', '-c', script, sha, signer], { input: stdin, encoding: 'utf8' })
const ethObj = (t, from = SIGNER) => JSON.stringify({ from, to: NULL, input: '0x' + Buffer.from('data:,' + t, 'utf8').toString('hex') }, null, 2)
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function b58(buf) {
  let n = BigInt('0x' + (buf.toString('hex') || '0')), s = ''
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n }
  return '1'.repeat([...buf].findIndex((b) => b !== 0) === -1 ? buf.length : [...buf].findIndex((b) => b !== 0)) + s
}
const MEMO = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'
const SOL_PAYER = '9xx7qC7uwTAeaSo7T5Gk9canYBosFh1pMQaDmQEa83Tb'
const solObj = (t, payer = SOL_PAYER) => JSON.stringify({ jsonrpc: '2.0', id: 1, result: { transaction: { message: { accountKeys: [payer, MEMO], instructions: [{ programIdIndex: 1, accounts: [0], data: b58(Buffer.from(t, 'utf8')) }] } } } })

test('ETH script: parts in any order → the text, sha256 verified', () => {
  const r = py(ETH_SCRIPT, [partTexts[2], partTexts[0], partTexts[1]].map((t) => ethObj(t)).join('\n'))
  expect(r.status).toBe(0)
  expect(r.stdout).toBe(TEXTV)
  expect(r.stderr).toMatch(new RegExp(`reassembled OK sha256 ${SHA}`))
})

test('ETH script refuses: a missing part, a tampered chunk, another sender, a different expected digest', () => {
  expect(py(ETH_SCRIPT, [partTexts[0], partTexts[2]].map((t) => ethObj(t)).join('\n')).status).not.toBe(0)
  const bad = partTexts[1].replace('wörld', 'world')
  const t = py(ETH_SCRIPT, [partTexts[0], bad, partTexts[2]].map((x) => ethObj(x)).join('\n'))
  expect(t.status).not.toBe(0); expect(t.stderr).toMatch(/MISMATCH/); expect(t.stdout).toBe('')
  expect(py(ETH_SCRIPT, partTexts.map((x, i) => ethObj(x, i === 1 ? '0x' + '11'.repeat(20) : SIGNER)).join('\n')).stderr).toMatch(/publishing address/)
  expect(py(ETH_SCRIPT, partTexts.map((x) => ethObj(x)).join('\n'), 'f'.repeat(64)).stderr).toMatch(/MISMATCH/)
})

test('SOL script: memo bytes (base58 instruction data) from the fee payer → the text', () => {
  const r = py(SOL_SCRIPT, partTexts.map((t) => solObj(t)).join('\n'), SHA, SOL_PAYER)
  expect(r.status).toBe(0)
  expect(r.stdout).toBe(TEXTV)
  expect(py(SOL_SCRIPT, partTexts.map((t, i) => solObj(t, i === 2 ? '1'.repeat(32) : SOL_PAYER)).join('\n'), SHA, SOL_PAYER).stderr).toMatch(/publishing address/)
})

test('handReassembly: one command per chain, from the first complete copy in part order; no URL, no IP', () => {
  const tx = (copy, part, parts, id, state = 'included') => ({ copy, part, parts, state, landedId: state === 'included' ? id : null, attempts: [] })
  const txs = [tx(1, 2, 3, 'B'), tx(1, 1, 3, 'A'), tx(1, 3, 3, 'C'), tx(2, 1, 3, 'D')]
  expect(copyIds(txs)).toMatchObject({ copy: 1, parts: 3, complete: true, ids: ['A', 'B', 'C'] })
  const h = handReassembly({ chain: 'eth', txs, signer: SIGNER, messageSha256: SHA, network: 'mainnet' })
  expect(h.format).toBe('vt-parts/1')
  expect(h.idsFile).toBe('A\nB\nC\n')
  expect(h.command).toMatch(/^while read -r t; do cast tx "\$t" --json; done < eth-txids\.txt \| python3 -I -c '/)
  expect(h.command).toContain(SHA); expect(h.command).toContain(SIGNER)
  expect(h.note).toMatch(/over Tor/)
  const s = handReassembly({ chain: 'sol', txs, signer: SOL_PAYER, messageSha256: SHA, network: 'testnet' })
  expect(s.command).toMatch(/getTransaction/); expect(s.command).toContain('$SOL_RPC_URL')
  for (const c of [h.command, s.command]) { expect(c).not.toMatch(/https?:\/\//); expect(c).not.toMatch(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/) }
  expect(handReassembly({ chain: 'eth', txs: [], signer: SIGNER, messageSha256: SHA, network: 'local' })).toBeNull()
  expect(copyIds([tx(1, 1, 3, 'A'), tx(2, 1, 3, 'D')])).toMatchObject({ copy: 1, complete: false })
})

// The virtualized parts table, reassembly chips and the lane's progress helpers (W3, R72).
import { test, expect } from 'vitest'
import { render, screen, fireEvent, within } from '@testing-library/react'
import PartsTable, { ROW_PX, VIRT_FROM, windowOf } from '../src/jobs/PartsTable.jsx'
import Reassembly from '../src/jobs/Reassembly.jsx'
import { etaOf, progressOf, ranges } from '../src/jobs/ChainLane.jsx'

const SIG = (i) => `${'5'.repeat(40)}${String(i).padStart(8, '0')}`
const ETH_SIGNER = '0x8739Eb87B3d11f221Df63454F8D229a1A4F4049C'
function rows(n, parts = 100, landed = n) {
  return Array.from({ length: n }, (_, k) => {
    const copy = Math.floor(k / parts) + 1, part = (k % parts) + 1, done = k < landed
    return { copy, part, parts, attempts: [{ txId: SIG(k), gen: 1, state: done ? 'included' : 'sent', sol: { blockhash: 'b', lastValidBlockHeight: 1, cuPrice: 0, cuLimit: 30000, rung: null, fee: '5000' } }],
      state: done ? 'included' : 'open', landedId: done ? SIG(k) : null, block: done ? String(1000 + k) : null, fee: done ? '5000' : null, readback: done ? true : null }
  })
}

test('10,000 parts render fewer than 200 DOM rows, and scrolling moves the window', () => {
  const { container } = render(<PartsTable chain="sol" rows={rows(10_000)} network="mainnet" signer="9xx7qC7uwTAeaSo7T5Gk9canYBosFh1pMQaDmQEa83Tb" />)
  const box = screen.getByTestId('parts-table-sol')
  expect(box.dataset.rows).toBe('10000')
  expect(box.dataset.virtual).toBe('true')
  expect(container.querySelectorAll('tr').length).toBeLessThan(200)
  expect(screen.getAllByTestId('part-row-sol')[0].dataset.part).toBe('1')
  // scroll to row 5,000: that row is rendered, the first one is not, still < 200 rows
  box.scrollTop = 5000 * ROW_PX
  fireEvent.scroll(box)
  const shown = screen.getAllByTestId('part-row-sol')
  expect(container.querySelectorAll('tr').length).toBeLessThan(200)
  expect(shown.some((r) => r.dataset.copy === '51' && r.dataset.part === '1')).toBe(true)          // k = 5000 → copy 51 part 1
  expect(shown.some((r) => r.dataset.copy === '1' && r.dataset.part === '1')).toBe(false)
  // the spacers keep the full height: rows above and below the window
  const spacers = [...container.querySelectorAll('tr[aria-hidden]')].map((r) => parseInt(r.style.height, 10))
  expect(spacers.reduce((a, b) => a + b, 0) + shown.length * ROW_PX).toBe(10_000 * ROW_PX)
})

test('windowOf: small tables are not virtualized; the window is bounded by the overscan', () => {
  expect(windowOf(VIRT_FROM, 0, 420)).toEqual({ virt: false, first: 0, last: VIRT_FROM })
  const w = windowOf(10_000, 0, 420)
  expect(w.first).toBe(0)
  expect(w.last).toBe(Math.ceil(420 / ROW_PX) + 10)
  const end = windowOf(10_000, 10_000 * ROW_PX, 420)
  expect(end.last).toBe(10_000)
})

test('rows: state, readback ✓, fee paid; mainnet links are copy-only (no anchor), local Otterscan opens', () => {
  const r = rows(3, 3, 2)
  const { container, unmount } = render(<PartsTable chain="eth" rows={r.map((x) => ({ ...x, attempts: [{ txId: '0x' + 'ab'.repeat(32), gen: 1, state: x.state === 'included' ? 'included' : 'sent', eth: { nonce: 0, tip: '1000000', maxFee: '2000000000', gas: '21000', to: '0x0' } }], landedId: x.landedId ? '0x' + 'ab'.repeat(32) : null }))}
    network="mainnet" signer={ETH_SIGNER} to="0x0000000000000000000000000000000000000000" />)
  const trs = screen.getAllByTestId('part-row-eth')
  expect(trs.map((t) => t.dataset.state)).toEqual(['included', 'included', 'open'])
  expect(screen.getAllByTestId('readback-eth').map((t) => t.textContent)).toEqual(['✓', '✓', '—'])
  expect(trs[0].textContent).toMatch(/0\.000000000000005 ETH/)
  expect(trs[0].textContent).toMatch(/tip 0\.001 \/ maxFee 2 gwei/)
  expect(container.querySelectorAll('a')).toHaveLength(0)
  expect(within(trs[0]).getAllByRole('button').length).toBeGreaterThan(0)            // copy buttons
  unmount()
  render(<PartsTable chain="eth" rows={rows(1, 1).map((x) => ({ ...x, landedId: '0x' + 'cd'.repeat(32) }))} network="local" signer={ETH_SIGNER} to="0x0000000000000000000000000000000000000000" />)
  const a = screen.getAllByRole('link')
  expect(a.length).toBeGreaterThan(0)
  for (const l of a) { expect(l.getAttribute('href')).toMatch(/^http:\/\/127\.0\.0\.1:5100\//); expect(l.getAttribute('rel')).toBe('noopener noreferrer') }
})

test('reassembled ✓ per copy with its sha256; a copy in progress shows its landed count', () => {
  const r = rows(10, 5, 8)                 // copy 1 complete, copy 2: 3/5
  const cs = { txs: r, reassembled: [{ copy: 1, ok: true }], copiesIncluded: 1 }
  render(<Reassembly chain="sol" cs={cs} sha={new Map([[1, 'ab'.repeat(32)]])} messageSha256={'ab'.repeat(32)} />)
  expect(screen.getByTestId('reasm-sol-1').textContent).toBe('copy 1: reassembled ✓ sha256 abababab…')
  expect(screen.getByTestId('reasm-sol-1').dataset.ok).toBe('true')
  expect(screen.getByTestId('reasm-sol-2').textContent).toBe('copy 2: 3/5 parts')
  expect(screen.getByTestId('reassembly-sol').dataset.ok).toBe('1')
})

test('progress: copies mode counts every part; drain counts the current copy; ETA from the landing times', () => {
  const cs = { txs: rows(10, 5, 8), resume: { copy: 2, nextPart: 4 } }
  expect(progressOf({ mode: { copies: 3 } }, cs)).toMatchObject({ parts: 5, done: 8, total: 15, inCopy: [1, 2, 3] })
  expect(progressOf({ mode: 'drain' }, cs)).toMatchObject({ parts: 5, current: 2, done: 3, total: 5 })
  expect(progressOf({ mode: 'drain' }, { txs: [], resume: null })).toMatchObject({ parts: null, total: null })
  const landed = [0, 2000, 4000, 6000].map((at, i) => ({ at, copy: 1, part: i + 1 }))
  expect(etaOf(landed, 5)).toEqual({ perPart: 2000, eta: 10_000 })
  expect(etaOf(landed.slice(0, 1), 5)).toEqual({ perPart: null, eta: null })
  expect(ranges([5, 1, 2, 3, 7, 8])).toBe('1–3, 5, 7–8')
})

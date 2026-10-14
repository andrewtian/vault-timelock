import { test, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import AppShell from '../src/shell/AppShell.jsx'
import RegimeBanner from '../src/shell/RegimeBanner.jsx'
import { StatusProvider, computeMismatch, networkOfPort } from '../src/lib/status.js'
import { TabBusyProvider } from '../src/lib/busy.js'

const NAMES = {
  local: { eth: 'anvil · 31337', sol: 'Solana local' },
  testnet: { eth: 'Sepolia · 11155111', sol: 'Solana devnet' },
  mainnet: { eth: 'Ethereum mainnet · 1', sol: 'Solana mainnet-beta' },
}
const status = (network, over = {}) => ({
  network, networks: NAMES[network], mainnetSends: 'LOCKED', jobSends: 'LOCKED', build: 'b1c2d3e4f5a6', confined: true, legacyLatch: 'clear', serverNowMs: 1, ...over,
})
const relay = (network) => ({ network, build: 'r', confined: true, identity: { eth: { ok: true }, sol: { ok: true } }, endpoints: { eth: 1, sol: 1 } })
const withStatus = (ui, s, r, port = '') => render(<StatusProvider value={{ status: s, relay: r, error: null }} port={port}><TabBusyProvider>{ui}</TabBusyProvider></StatusProvider>)

test.each([
  ['local', '[LOCAL]', 'bg-sky-100'],
  ['testnet', '[TESTNET]', 'bg-amber-200'],
  ['mainnet', '[MAINNET]', 'bg-red-700'],
])('banner %s: label, colour, per-chain names, title prefix', (network, label, colour) => {
  withStatus(<RegimeBanner />, status(network), relay(network))
  const banner = screen.getByTestId('regime-banner')
  expect(banner.dataset.network).toBe(network)
  expect(banner.className).toContain(colour)
  expect(banner.textContent).toContain(label)
  expect(banner.textContent).toContain(`eth: ${NAMES[network].eth}`)
  expect(banner.textContent).toContain(`sol: ${NAMES[network].sol}`)
  expect(document.title).toBe(`${label} vt`)
})

test('banner shows the mainnet send lock', () => {
  const { unmount } = withStatus(<RegimeBanner />, status('mainnet'), relay('mainnet'))
  expect(screen.getByTestId('regime-banner').textContent).toContain('mainnet sends: LOCKED')
  unmount()
  withStatus(<RegimeBanner />, status('mainnet', { jobSends: 'ENABLED', mainnetSends: 'ENABLED' }), relay('mainnet'))
  expect(screen.getByTestId('regime-banner').textContent).toContain('mainnet sends: ENABLED (jobs)')
})

test('API/relay network mismatch blocks the page and names the command', () => {
  withStatus(<AppShell><p>the page</p></AppShell>, status('mainnet'), relay('testnet'))
  const alert = screen.getByRole('alert')
  expect(alert.textContent).toContain('vt up --network mainnet')
  expect(screen.queryByText('the page')).toBeNull()
})

test('page port vs API network mismatch blocks, with the page network command', () => {
  withStatus(<AppShell><p>the page</p></AppShell>, status('testnet'), relay('testnet'), '5180')
  expect(screen.getByRole('alert').textContent).toContain('vt up --network local')
  expect(screen.queryByText('the page')).toBeNull()
})

test('agreeing networks render the page', () => {
  withStatus(<AppShell><p>the page</p></AppShell>, status('local'), relay('local'), '5183')
  expect(screen.queryByRole('alert')).toBeNull()
  expect(screen.getByText('the page')).toBeTruthy()
})

test('computeMismatch and networkOfPort', () => {
  expect(computeMismatch(status('local'), relay('local'))).toBeNull()
  expect(computeMismatch(status('local'), null)).toBeNull()
  expect(computeMismatch(status('local'), relay('mainnet')).command).toBe('vt up --network local')
  expect(networkOfPort('5183')).toBe('local')
  expect(networkOfPort('5190')).toBe('testnet')
  expect(networkOfPort('5200')).toBe('mainnet')
  expect(networkOfPort('3000')).toBeNull()
})

test('StatusProvider polls /api/status and /relay/status', async () => {
  const { vi } = await import('vitest')
  const { waitFor } = await import('@testing-library/react')
  const calls = []
  globalThis.fetch = vi.fn(async (url) => {
    calls.push(url)
    const body = url === '/api/status' ? status('testnet') : relay('testnet')
    return new Response(JSON.stringify(body), { status: 200 })
  })
  render(<StatusProvider intervalMs={20} port="5190"><RegimeBanner /></StatusProvider>)
  await waitFor(() => expect(screen.getByTestId('regime-banner').dataset.network).toBe('testnet'))
  await waitFor(() => expect(calls.filter((u) => u === '/api/status').length).toBeGreaterThan(1))
  expect(calls).toContain('/relay/status')
})

test('local Status page names the Chrome "Apps on device" permission; testnet does not', async () => {
  const { default: Status } = await import('../src/pages/Status.jsx')
  const { unmount } = withStatus(<Status />, status('local'), relay('local'))
  expect(screen.getByTestId('local-explorer-note').textContent).toMatch(/Apps on device/)
  expect(screen.getByTestId('local-explorer-note').textContent).toMatch(/Chrome 145/)
  unmount()
  withStatus(<Status />, status('testnet'), relay('testnet'))
  expect(screen.queryByTestId('local-explorer-note')).toBeNull()
})

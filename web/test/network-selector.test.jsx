import { test, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useEffect } from 'react'
import NetworkSelector from '../src/shell/NetworkSelector.jsx'
import { StatusProvider } from '../src/lib/status.js'
import { TabBusyProvider, useTabBusy } from '../src/lib/busy.js'

const stacks = [
  { network: 'local', up: true, pageUrl: 'http://127.0.0.1:5180/', build: 'a' },
  { network: 'testnet', up: true, pageUrl: 'http://127.0.0.1:5190/', build: 'a' },
  { network: 'mainnet', up: false, pageUrl: 'http://127.0.0.1:5200/', build: null },
]
const status = { network: 'local', networks: {}, mainnetSends: 'LOCKED', jobSends: 'LOCKED', build: 'x', confined: true, legacyLatch: 'clear', serverNowMs: 1 }

beforeEach(() => {
  globalThis.fetch = vi.fn(async (url) => {
    if (url === '/__stacks') return new Response(JSON.stringify(stacks), { status: 200 })
    return new Response('{}', { status: 404 })
  })
})

function Busy({ reason }) {
  const { set } = useTabBusy()
  useEffect(() => { set(reason) }, [reason, set])
  return null
}
const mount = (assign, busyReason = null) =>
  render(
    <StatusProvider value={{ status, relay: null, error: null }}>
      <TabBusyProvider>
        {busyReason ? <Busy reason={busyReason} /> : null}
        <NetworkSelector assign={assign} />
      </TabBusyProvider>
    </StatusProvider>,
  )

test('lists the three networks with up/down', async () => {
  mount(vi.fn())
  const group = screen.getByRole('group', { name: 'Network' })
  await waitFor(() => expect(within(group).getByRole('button', { name: /Testnet/ }).textContent).toContain('up'))
  expect(within(group).getAllByRole('button').map((b) => b.dataset.network)).toEqual(['local', 'testnet', 'mainnet'])
  expect(within(group).getByRole('button', { name: /Mainnet/ }).textContent).toContain('down')
  expect(within(group).getByRole('button', { name: /Mainnet/ }).disabled).toBe(true)
  expect(within(group).getByRole('button', { name: /Local/ }).getAttribute('aria-current')).toBe('true')
})

test('while busy: disabled with the reason', async () => {
  const assign = vi.fn()
  mount(assign, 'a key is loaded in this tab')
  await waitFor(() => expect(screen.getByTestId('selector-reason').textContent).toContain('a key is loaded in this tab'))
  const testnet = screen.getByRole('button', { name: /Testnet/ })
  expect(testnet.disabled).toBe(true)
  await userEvent.click(testnet)
  expect(screen.queryByRole('alertdialog')).toBeNull()
  expect(assign).not.toHaveBeenCalled()
})

test('idle: an AlertDialog, then location assign to the page URL; cancel does nothing', async () => {
  const assign = vi.fn()
  const confirmSpy = vi.fn(() => true)
  globalThis.confirm = confirmSpy
  mount(assign)
  const testnet = await waitFor(() => {
    const b = screen.getByRole('button', { name: /Testnet/ })
    expect(b.disabled).toBe(false)
    return b
  })
  await userEvent.click(testnet)
  const dialog = await screen.findByRole('alertdialog')
  expect(dialog.textContent).toContain('cleared')
  expect(assign).not.toHaveBeenCalled()
  await userEvent.click(within(dialog).getByRole('button', { name: 'Stay here' }))
  expect(assign).not.toHaveBeenCalled()
  await userEvent.click(testnet)
  await userEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: /Switch to Testnet/ }))
  expect(assign).toHaveBeenCalledExactlyOnceWith('http://127.0.0.1:5190/')
  expect(confirmSpy).not.toHaveBeenCalled()
})

test('a page URL that is not that network\'s loopback origin is never followed', async () => {
  stacks[1] = { network: 'testnet', up: true, pageUrl: 'https://example.invalid/', build: 'a' }
  try {
    mount(vi.fn())
    await waitFor(() => expect(screen.getByRole('button', { name: /Local/ })).toBeTruthy())
    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalled())
    expect(screen.getByRole('button', { name: /Testnet/ }).disabled).toBe(true)
  } finally {
    stacks[1] = { network: 'testnet', up: true, pageUrl: 'http://127.0.0.1:5190/', build: 'a' }
  }
})

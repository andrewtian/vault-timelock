// How pages (W5): the who-sees-what hop list is generated from the endpoint table and the live relay answers (never
// hard-coded, never an address); the publication modes come from the contracts' table; the two local-only files are
// explained; the ported diagrams render from synthetic data only.
import { test, expect, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { PUBLISH_MODES, PERMANENCE_CLASSES } from '@vault-timelock/core/contracts'
import How from '../src/how/How.jsx'
import { buildPath, providersFor } from '../src/how/hops.js'
import { NetworkPath } from '../src/how/NetworkPath.jsx'
import { parseRoute } from '../src/routes.jsx'
import { json, relayOf, renderWith } from './helpers.jsx'

const IP = /\b\d{1,3}(?:\.\d{1,3}){3}\b|\[[0-9a-f:]{6,}\]/i
const TOR = { isTor: true, checkedAt: 1, roles: { eth: { gen: 3, ageSec: 42 }, sol: { gen: 1, ageSec: 5 } } }
beforeEach(() => {
  globalThis.fetch = async (url) => (String(url) === '/relay/tor' ? json(200, TOR) : json(404, {}))
})

test('routes: #/how and its three sub-pages', () => {
  expect(parseRoute('#/how')).toEqual({ name: 'how', tab: 'vault' })
  expect(parseRoute('#/how/network')).toEqual({ name: 'how', tab: 'network' })
  expect(parseRoute('#/how/modes/')).toEqual({ name: 'how', tab: 'modes' })
  expect(parseRoute('#/how/files')).toEqual({ name: 'how', tab: 'files' })
  expect(parseRoute('#/how/nope')).toEqual({ name: 'missing' })
})

test('hop list: generated per network from the endpoint table; Tor hops and the link cut only where Tor is used', () => {
  const main = buildPath({ network: 'mainnet', chain: 'eth' })
  expect(main.hops.map((h) => h.id)).toEqual(['browser', 'relay', 'tor', 'guard', 'middle', 'exit', 'rpc', 'node'])
  expect(main.cutAfter).toBe('middle')
  expect(main.hops.find((h) => h.id === 'rpc').sub).toEqual(providersFor('mainnet', 'eth'))
  expect(providersFor('mainnet', 'eth')).toContain('ethereum-rpc.publicnode.com')
  expect(providersFor('mainnet', 'sol')).toContain('api.mainnet-beta.solana.com')
  // testnet names different providers, from the same table
  expect(providersFor('testnet', 'eth')).toContain('ethereum-sepolia-rpc.publicnode.com')
  expect(providersFor('testnet', 'sol')).toContain('api.devnet.solana.com')
  expect(buildPath({ network: 'testnet', chain: 'sol' }).hops.find((h) => h.id === 'rpc').sub).not.toEqual(providersFor('mainnet', 'sol'))
  // guard sees the IP, exit does not; the RPC sees the exit's address, never yours
  const guard = main.hops.find((h) => h.id === 'guard'), exit = main.hops.find((h) => h.id === 'exit'), rpc = main.hops.find((h) => h.id === 'rpc')
  expect(guard.sees).toContain('YOUR IP'); expect(exit.notSees).toContain('YOUR IP'); expect(rpc.notSees).toContain('YOUR IP')
  // local: direct loopback, nothing to cut, no address anywhere (the table's loopback hosts are IP literals)
  const local = buildPath({ network: 'local', chain: 'eth' })
  expect(local.hops.map((h) => h.id)).toEqual(['browser', 'relay', 'node'])
  expect(local.cutAfter).toBeNull()
  for (const net of ['local', 'testnet', 'mainnet']) for (const chain of ['eth', 'sol']) expect(JSON.stringify(buildPath({ network: net, chain }))).not.toMatch(IP)
})

test('hop list: live relay answers (endpoint count, confinement, IsTor, circuit generation) enter the hops', () => {
  const p = buildPath({ network: 'mainnet', chain: 'eth', names: { eth: 'Ethereum mainnet · 1', sol: 'x' }, relay: { ...relayOf('mainnet'), endpoints: { eth: 2, sol: 1 } }, tor: TOR, live: true })
  expect(p.hops.find((h) => h.id === 'relay').sub).toEqual(expect.arrayContaining(['confinement proof ✓', '2 endpoints passed the identity check']))
  expect(p.hops.find((h) => h.id === 'tor').sub).toEqual(expect.arrayContaining(['circuit generation 3, age 42 s', 'IsTor ✓']))
  expect(p.hops.find((h) => h.id === 'node').title).toBe('Ethereum mainnet · 1')
  expect(buildPath({ network: 'mainnet', chain: 'sol', relay: { ...relayOf('mainnet'), endpoints: { eth: 2, sol: 1 }, confined: false }, tor: { ...TOR, isTor: false }, live: true }).hops.find((h) => h.id === 'relay').sub).toEqual(expect.arrayContaining(['confinement proof ✗', '1 endpoint passed the identity check']))
})

test('network page: per-hop sees / does not see, the link-cut marker, the honest caveats, no address on screen', async () => {
  renderWith(<NetworkPath />, { network: 'mainnet' })
  const eth = screen.getByTestId('lane-eth')
  expect(within(eth).getByTestId('hop-guard').textContent).toMatch(/sees:.*YOUR IP/)
  expect(within(eth).getByTestId('hop-exit').textContent).toMatch(/✗ YOUR IP/)
  expect(within(eth).getByTestId('link-cut').textContent).toMatch(/link cut here/)
  expect(within(screen.getByTestId('lane-sol')).getByTestId('hop-rpc').textContent).toMatch(/api\.mainnet-beta\.solana\.com/)
  expect(screen.getByText(/What still links \(be honest\)/)).toBeTruthy()
  expect(screen.getByText(/On-chain funding:/)).toBeTruthy()
  expect(screen.getByText(/Tor doesn't defeat a global observer/)).toBeTruthy()
  await waitFor(() => expect(within(eth).getByTestId('hop-tor').textContent).toMatch(/circuit generation 3/))
  expect(screen.getByTestId('how-network').textContent).not.toMatch(IP)
})

test('network page: LOCAL has no Tor and no cut; another network is shown statically, labelled so', async () => {
  const user = userEvent.setup()
  renderWith(<NetworkPath />, { network: 'local' })
  expect(screen.getByTestId('path-local-note').textContent).toMatch(/no Tor and no link to cut/)
  expect(screen.queryByTestId('link-cut')).toBeNull()
  await user.click(screen.getByTestId('path-net-testnet'))
  expect(screen.getByTestId('path-static-note').textContent).toMatch(/endpoint table only/)
  expect(within(screen.getByTestId('lane-eth')).getByTestId('link-cut')).toBeTruthy()
  expect(within(screen.getByTestId('lane-eth')).getByTestId('hop-rpc').textContent).toMatch(/ethereum-sepolia-rpc\.publicnode\.com/)
})

test('publication modes: every contract row shows its permanence class and trust note; reserved rows are not selectable', () => {
  renderWith(<How tab="modes" />)
  for (const c of PERMANENCE_CLASSES) expect(screen.getByTestId(`class-${c}`)).toBeTruthy()
  for (const r of PUBLISH_MODES) {
    const row = screen.getByTestId(`mode-${r.id}`)
    expect(row.dataset.permanence).toBe(r.permanence)
    expect(within(row).getByTestId(`mode-${r.id}-trust`).textContent).toContain(r.trustNote)
    expect(within(row).getByTestId(`mode-${r.id}-status`).textContent).toMatch(r.status === 'available' ? /^available$/ : /reserved: not selectable yet/)
  }
  expect(screen.getByTestId('mode-eth.calldata.null-permanence').textContent).toBe('permanence: history')
  expect(screen.getByTestId('mode-eth.sstore2-permanence').textContent).toBe('permanence: state')
  expect(screen.getByTestId('mode-sol.arweave-anchor-permanence').textContent).toBe('permanence: arweave')
  expect(screen.getByTestId('mode-sol.noop').textContent).toMatch(/fallback/)
  for (const s of ['passive', 'economy', 'prompt']) expect(screen.getByTestId(`strategy-${s}`)).toBeTruthy()
  expect(screen.getByTestId('strategy-passive').textContent).toMatch(/median 95 min/)
  expect(screen.getByTestId('cost-table').textContent).toMatch(/Passive.*Economy.*Prompt/)
})

test('local files: STRUCTURE.txt and SEALED-plaintext.txt are local only; the plaintext comes only from open --plaintext', () => {
  renderWith(<How tab="files" />)
  expect(screen.getByTestId('files-local-only').textContent).toMatch(/never published/)
  expect(screen.getByTestId('file-structure').textContent).toMatch(/every value removed/)
  expect(screen.getByTestId('plaintext-only-open').textContent).toMatch(/only by open --plaintext, after the unlock time/)
  expect(screen.getByTestId('file-plaintext').textContent).toMatch(/holds every secret/)
  expect(document.body.textContent).not.toMatch(IP)
})

test('vault diagram: synthetic entries, real digests, the sealed payload split into labelled segments', async () => {
  render(<How tab="vault" />)
  await waitFor(() => expect(screen.getAllByText(/= MANIFEST row ✓/).length).toBeGreaterThan(0))
  expect(screen.getByText(/Representative output/)).toBeTruthy()
  expect(screen.getByText(/unlock-TIME.age: the data key, time-locked/)).toBeTruthy()
  expect(screen.getByTestId('how-vault').textContent).toMatch(/SYNTHETIC|synthetic/)
  // The ported SEALED sample stays faithful (M1 ruling): its loopback Tor proxy example is shown verbatim. Loopback is
  // allowed; any other address is not.
  const body = document.body.textContent
  expect(body).toContain('HTTPS_PROXY=socks5h://127.0.0.1:9050')
  expect(body.replaceAll('127.0.0.1', 'loopback')).not.toMatch(IP)
})

test('How page: the four tabs link to their routes and mark the current one', () => {
  render(<How tab="network" />)
  expect(screen.getByTestId('how-tab-network').getAttribute('aria-current')).toBe('page')
  expect(screen.getByTestId('how-tab-modes').getAttribute('href')).toBe('#/how/modes')
})

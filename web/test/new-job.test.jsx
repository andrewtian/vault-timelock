import { test, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor, within, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import NewJob, { buildJobInput, exportJobFile } from '../src/jobs/NewJob.jsx'
import Funding, { requestAirdrop } from '../src/jobs/Funding.jsx'
import PriceLine, { priceStatus } from '../src/jobs/PriceLine.jsx'
import TorPanel from '../src/tor/TorPanel.jsx'
import { defaultChainConfig, chainIssues } from '../src/jobs/ChainConfig.jsx'
import { newKey, validateMessage } from '../src/lib/core.js'
import { json, lastBusy, renderWith } from './helpers.jsx'

const ethKey = newKey('eth')
const solKey = newKey('sol')
const fileOf = (text, name) => new File([text], name, { type: 'application/json' })

let calls
beforeEach(() => {
  calls = []
  globalThis.fetch = vi.fn(async (url, init = {}) => {
    calls.push({ url: String(url), init })
    if (String(url) === '/relay/price') return json(404, { error: { message: 'no price' } })
    if (String(url).startsWith('/api/messages/')) return json(201, { sha256: 'x', bytes: 1 })
    if (String(url) === '/api/jobs') return json(201, { id: 'e3d45f73cf65abaa', def: {}, state: {} })
    return json(404, {})
  })
})

const fillBasics = async (user, text = 'one line of text') => {
  await user.type(screen.getByTestId('job-name'), 'first job')
  await user.type(screen.getByTestId('message'), text)
}

test('mount: name and message start empty, Create is disabled with the reasons listed', () => {
  renderWith(<NewJob />)
  expect(screen.getByTestId('job-name').value).toBe('')
  expect(screen.getByTestId('message').value).toBe('')
  expect(screen.getByTestId('job-create').disabled).toBe(true)
  expect(screen.getByTestId('job-problems').textContent).toMatch(/enable at least one chain/)
})

test('every form field has an id and a name (E2E finding L2-2), and there is no <form>', async () => {
  const user = userEvent.setup()
  const { container } = renderWith(<NewJob />)
  await user.click(screen.getByTestId('enabled-eth')); await user.click(screen.getByTestId('enabled-sol'))
  await user.click(screen.getByTestId('keychoice-eth-import')); await user.click(screen.getByTestId('kimport-eth-key'))
  await user.click(screen.getByTestId('mode-copies-sol'))
  const fields = [...container.querySelectorAll('input,select,textarea')]
  expect(fields.length).toBeGreaterThan(15)
  for (const el of fields) { expect(el.id, el.outerHTML).not.toBe(''); expect(el.name, el.outerHTML).not.toBe('') }
  expect(container.querySelector('form')).toBeNull()
  // each label points at an existing field
  for (const l of container.querySelectorAll('label[for]')) expect(container.querySelector(`[id="${l.htmlFor}"]`), l.outerHTML).not.toBeNull()
})

test('defaults: publishMode eth.calldata.null, feeStrategy passive for drain, economy for copies N, unless chosen', async () => {
  const user = userEvent.setup()
  renderWith(<NewJob />)
  await user.click(screen.getByTestId('enabled-eth'))
  expect(screen.getByTestId('publish-mode-eth').value).toBe('eth.calldata.null')
  expect(screen.getByTestId('fee-strategy-eth').value).toBe('passive')
  await user.click(screen.getByTestId('mode-copies-eth'))
  expect(screen.getByTestId('fee-strategy-eth').value).toBe('economy')
  await user.selectOptions(screen.getByTestId('fee-strategy-eth'), 'prompt')
  await user.click(screen.getByTestId('mode-drain-eth'))
  expect(screen.getByTestId('fee-strategy-eth').value).toBe('prompt')          // a chosen strategy stays
  expect(screen.getByTestId('distinct-eth').checked).toBe(true)
})

test('reserved publish modes are listed as not yet available and cannot be chosen', async () => {
  const user = userEvent.setup()
  renderWith(<NewJob />)
  await user.click(screen.getByTestId('enabled-eth')); await user.click(screen.getByTestId('enabled-sol'))
  const eth = within(screen.getByTestId('publish-mode-eth'))
  expect(eth.getByRole('option', { name: 'eth.calldata.null' }).disabled).toBe(false)
  expect(eth.getByRole('option', { name: 'eth.calldata.self' }).disabled).toBe(false)
  for (const id of ['eth.sstore2', 'arweave.turbo']) { // CC-1 (I1): eth.blob dropped, arweave.irys renamed
    const o = eth.getByRole('option', { name: `${id} (not yet available)` }); expect(o.disabled).toBe(true)
  }
  expect(within(screen.getByTestId('publish-mode-sol')).getByRole('option', { name: 'sol.noop (not yet available)' }).disabled).toBe(true)
  await user.selectOptions(screen.getByTestId('publish-mode-eth'), 'eth.calldata.self')
  expect(screen.getByTestId('publish-mode-eth').value).toBe('eth.calldata.self')
})

test('Create: PUT the message by digest, then POST the job (no key material, no recipient), then go to the job page', async () => {
  const user = userEvent.setup()
  const go = vi.fn()
  renderWith(<NewJob navigate={go} />, { seed: [['eth', ethKey], ['sol', solKey]] })
  await fillBasics(user)
  await user.click(screen.getByTestId('enabled-eth'))
  await user.click(screen.getByTestId('enabled-sol')); await user.click(screen.getByTestId('mode-copies-sol'))
  await user.clear(screen.getByTestId('n-sol')); await user.type(screen.getByTestId('n-sol'), '3')
  await user.selectOptions(screen.getByTestId('publish-mode-eth'), 'eth.calldata.self')
  await waitFor(() => expect(screen.getByTestId('job-create').disabled).toBe(false))
  await user.click(screen.getByTestId('job-create'))
  await waitFor(() => expect(go).toHaveBeenCalledWith('#/jobs/e3d45f73cf65abaa'))
  const apiCalls = calls.filter((c) => c.url.startsWith('/api/'))
  const sha = validateMessage('one line of text').sha256
  expect(apiCalls[0].url).toBe(`/api/messages/${sha}`); expect(apiCalls[0].init.method).toBe('PUT'); expect(apiCalls[0].init.body).toBe('one line of text')
  expect(apiCalls[1].url).toBe('/api/jobs'); expect(apiCalls[1].init.method).toBe('POST')
  const body = JSON.parse(apiCalls[1].init.body)
  expect(body).toEqual({
    format: 'vt-job/1', network: 'local', name: 'first job', messageSha256: sha, messageBytes: 16,
    chains: {
      eth: { mode: 'drain', publishMode: 'eth.calldata.self', feeStrategy: 'passive', distinctCopies: true, keyAddress: ethKey.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: null },
      sol: { mode: { copies: 3 }, publishMode: 'sol.memo', feeStrategy: 'economy', distinctCopies: true, keyAddress: solKey.address, budgetUsd: 10, clawbackTo: null },
    },
  })
  const raw = apiCalls[1].init.body
  expect(raw).not.toContain(ethKey.secret); expect(raw).not.toContain(solKey.secret); expect(raw).not.toContain('recipient')
  expect(raw).not.toContain('"message"')
  expect(lastBusy().reason).toMatch(/Ethereum key loaded/)                      // key busy outlives the form busy
  expect(lastBusy().reason).not.toMatch(/creating/)
})

test('an API refusal is shown with its guard id and nothing navigates', async () => {
  const user = userEvent.setup()
  const go = vi.fn()
  globalThis.fetch = vi.fn(async (url) => (String(url).startsWith('/api/messages/') ? json(201, {}) : json(409, { error: { guard: 'job.key-busy', message: 'that key is in use' } })))
  renderWith(<NewJob navigate={go} />, { seed: [['eth', ethKey]] })
  await fillBasics(user)
  await user.click(screen.getByTestId('enabled-eth'))
  await waitFor(() => expect(screen.getByTestId('job-create').disabled).toBe(false))
  await user.click(screen.getByTestId('job-create'))
  expect((await screen.findByTestId('job-msg')).textContent).toBe('job.key-busy: that key is in use')
  expect(go).not.toHaveBeenCalled()
})

test('form checks: budget, copies and addresses', () => {
  const c = { ...defaultChainConfig('eth'), enabled: true, mode: 'copies', copies: '0', budgetUsd: '10.123', clawbackTo: 'nope', maxTip: '0.01' }
  expect(chainIssues('eth', c)).toHaveLength(4)
  expect(chainIssues('eth', { ...defaultChainConfig('eth'), enabled: true })).toEqual([])
  expect(chainIssues('sol', { ...defaultChainConfig('sol'), enabled: true, maxCuPrice: '3000000' })).toHaveLength(1)
  expect(chainIssues('eth', { ...defaultChainConfig('eth'), enabled: true, publishMode: 'eth.sstore2' })).toEqual(['publish mode: not yet available'])
  // PF-S fix round 1 (N-6): on mainnet the claw-back address is required (eth and sol); off mainnet it stays optional
  for (const c of ['eth', 'sol']) {
    expect(chainIssues(c, { ...defaultChainConfig(c), enabled: true }, 'mainnet')).toEqual(['claw-back address: required on mainnet (the one address the remainder may go back to)'])
    expect(chainIssues(c, { ...defaultChainConfig(c), enabled: true }, 'testnet')).toEqual([])
  }
  expect(chainIssues('eth', { ...defaultChainConfig('eth'), enabled: true, clawbackTo: '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6' }, 'mainnet')).toEqual([])
})

test('job file export and import round-trip; a file for another network is refused', async () => {
  const user = userEvent.setup()
  const cfgs = { eth: { ...defaultChainConfig('eth'), enabled: true, mode: 'copies', copies: '5' }, sol: defaultChainConfig('sol') }
  const out = JSON.parse(exportJobFile({ network: 'local', name: 'rt', text: 'abc', cfgs, addresses: { eth: ethKey.address, sol: '' } }))
  expect(out.chains.eth.mode).toEqual({ copies: 5 }); expect(out.message).toBe('abc'); expect(out.chains.sol).toBeUndefined()
  expect(buildJobInput({ network: 'local', name: 'rt', check: validateMessage('abc'), cfgs, addresses: { eth: ethKey.address, sol: '' } }).messageBytes).toBe(3)

  renderWith(<NewJob />)
  await user.upload(screen.getByTestId('job-file'), fileOf(JSON.stringify(out), 'job.json'))
  await waitFor(() => expect(screen.getByTestId('job-name').value).toBe('rt'))
  expect(screen.getByTestId('message').value).toBe('abc')
  expect(screen.getByTestId('mode-copies-eth').checked).toBe(true); expect(screen.getByTestId('n-eth').value).toBe('5')
  expect(screen.getByTestId('job-msg').textContent).toMatch(/no keys/)

  await user.upload(screen.getByTestId('job-file'), fileOf(JSON.stringify({ ...out, network: 'mainnet', name: 'other' }), 'm.json'))
  expect((await screen.findByTestId('job-msg')).textContent).toMatch(/job.network: the file is for mainnet, this page is on local/)
  expect(screen.getByTestId('job-name').value).toBe('rt')
  await user.upload(screen.getByTestId('job-file'), fileOf('{ nope', 'bad.json'))
  await waitFor(() => expect(screen.getByTestId('job-msg').textContent).toMatch(/not JSON/))
})

// ---- funding ----
test('local funding is a stand-in note, and the Solana explorer link carries the Apps-on-device note', () => {
  renderWith(<Funding network="local" addresses={{ eth: ethKey.address, sol: solKey.address }} />)
  expect(screen.getByTestId('funding-local').textContent).toMatch(/Local stand-in/)
  expect(screen.queryByTestId('airdrop')).toBeNull()
  expect(screen.getByTestId('local-explorer-note').textContent).toMatch(/Apps on device/)
  expect(screen.getByTestId('fund-addr-sol').textContent).toBe(solKey.address)
})

test('Sepolia funding: address, copy, operator faucet step', () => {
  renderWith(<Funding network="testnet" addresses={{ eth: ethKey.address, sol: '' }} />)
  expect(screen.getByTestId('fund-addr-eth').textContent).toBe(ethKey.address)
  expect(screen.getByTestId('funding-sepolia').textContent).toMatch(/Operator faucet step/)
  expect(screen.getByTestId('faucet-eth').textContent).toContain(ethKey.address)
})

test('devnet airdrop: requestAirdrop through /relay/sol, success shows the signature', async () => {
  const user = userEvent.setup()
  globalThis.fetch = vi.fn(async () => json(200, { jsonrpc: '2.0', id: 1, result: 'SigAirdrop1111' }))
  renderWith(<Funding network="testnet" addresses={{ eth: '', sol: solKey.address }} />)
  await user.click(screen.getByTestId('airdrop'))
  expect((await screen.findByTestId('airdrop-done')).textContent).toContain('SigAirdrop1111')
  const [url, init] = globalThis.fetch.mock.calls[0]
  expect(url).toBe('/relay/sol')
  expect(JSON.parse(init.body)).toEqual({ jsonrpc: '2.0', id: 1, method: 'requestAirdrop', params: [solKey.address, 1_000_000_000] })
})

test('a REFUSED airdrop shows the faucet link, the address and "operator step"', async () => {
  const user = userEvent.setup()
  globalThis.fetch = vi.fn(async () => json(403, { error: { message: 'airdrop not allowed through Tor' } }))
  renderWith(<Funding network="testnet" addresses={{ eth: '', sol: solKey.address }} />)
  await user.click(screen.getByTestId('airdrop'))
  const failed = await screen.findByTestId('airdrop-failed')
  expect(failed.textContent).toMatch(/the relay refused it \(403\): airdrop not allowed through Tor/)
  const help = screen.getByTestId('faucet-sol')
  expect(help.textContent).toMatch(/Operator step/); expect(help.textContent).toContain(solKey.address)
  expect(within(help).getByRole('link').getAttribute('href')).toBe('https://faucet.solana.com')
  expect(globalThis.fetch).toHaveBeenCalledTimes(1)                              // no retry
})

test('requestAirdrop classifies refusal, rpc error and transport failure', async () => {
  const f = (r) => async () => r
  expect((await requestAirdrop('A', 1, f(json(503, {})))).kind).toBe('refused')
  expect((await requestAirdrop('A', 1, f(json(200, { error: { code: -32005, message: 'rate limited' } })))).kind).toBe('rpc')
  expect((await requestAirdrop('A', 1, async () => { throw new TypeError('x') })).kind).toBe('transport')
  expect((await requestAirdrop('A', 1, f(new Response('<html>', { status: 502 })))).kind).toBe('transport')
})

test('mainnet funding links are copy-only text, never anchors', () => {
  const { container } = renderWith(<Funding network="mainnet" addresses={{ eth: ethKey.address, sol: solKey.address }} />, { network: 'mainnet' })
  expect(screen.getByTestId('funding-mainnet')).toBeTruthy()
  expect(container.querySelectorAll('a')).toHaveLength(0)
  expect(screen.getAllByTestId('copy-only-link').length).toBeGreaterThan(1)
})

// ---- price ----
test('price line: fresh price ok; testnet says TEST FUNDS; stale or thin liquidity disables USD entry', () => {
  const now = Date.now()
  const p = (over = {}) => ({ prices: { SOL: { usd: 150.1234, mint: 'So11', liquidity: 5e7 }, ETH: { usd: 3000.5, mint: '7vfC', liquidity: 5e7 } }, fetchedAt: now - 3000, source: 'jup', ...over })
  expect(priceStatus(p(), now)).toMatchObject({ ok: true, age: 3 })
  expect(priceStatus(p({ fetchedAt: now - 130_000 }), now).ok).toBe(false)
  expect(priceStatus(p({ prices: { SOL: { usd: 1, mint: 'abcdefg', liquidity: 10 }, ETH: { usd: 1 } } }), now).why).toMatch(/liquidity/)
  // testnet: the uppercase label, and never a price (whatever the relay answers: a fixture or a real quote)
  const t = renderWith(<PriceLine price={p()} />, { network: 'testnet' })
  expect(screen.getByTestId('price-testnet').textContent).toBe('TEST FUNDS — NO VALUE')
  expect(screen.getByTestId('price').textContent).not.toMatch(/\$150/)
  expect(priceStatus({ fixture: true, source: 'TEST FUNDS — NO VALUE', prices: p().prices, fetchedAt: now }, now)).toMatchObject({ ok: false, none: true })
  t.unmount()
  renderWith(<PriceLine price={p()} />, { network: 'mainnet' })
  expect(screen.getByTestId('price').textContent).toMatch(/1 SOL = \$150\.1234/)
  expect(screen.queryByTestId('price-disabled')).toBeNull()
})

test('price line: no price disables USD entry with the reason', () => {
  renderWith(<PriceLine price={null} err="relay HTTP 404" />)
  expect(screen.getByTestId('price-disabled').textContent).toMatch(/USD entry disabled: relay HTTP 404/)
})

// ---- Tor panel ----
const torState = (over = {}) => ({ isTor: true, auto: false, checkedAt: Date.UTC(2026, 9, 9, 12, 0, 0), roles: { eth: { gen: 2, ageSec: 30, okCount: 5, failCount: 0, lastStatus: 200, lastError: null }, check: { gen: 1, ageSec: 3600, okCount: 1, failCount: 0, lastStatus: 200, lastError: null } }, ...over })

test('Tor panel (testnet): IsTor, role table, new circuit posts to the relay', async () => {
  const user = userEvent.setup()
  let state = torState()
  globalThis.fetch = vi.fn(async (url, init = {}) => {
    if (init.method === 'POST') { state = torState({ roles: { eth: { gen: 3, ageSec: 0, okCount: 5, failCount: 0, lastStatus: 200, lastError: null } } }); return json(200, { status: state }) }
    return json(200, state)
  })
  renderWith(<TorPanel />, { network: 'testnet' })
  await waitFor(() => expect(screen.getByTestId('tor-istor').textContent).toMatch(/IsTor ✓ · checked 12:00:00 UTC/))
  expect(screen.getByTestId('tor-gen-eth').textContent).toBe('gen 2')
  await user.click(screen.getByTestId('tor-new-eth'))
  await waitFor(() => expect(screen.getByTestId('tor-gen-eth').textContent).toBe('gen 3'))
  const post = globalThis.fetch.mock.calls.find(([, i]) => i?.method === 'POST')
  expect(post[0]).toBe('/relay/tor/new'); expect(JSON.parse(post[1].body)).toEqual({ role: 'eth' })
  expect(document.body.textContent).not.toMatch(/\d+\.\d+\.\d+\.\d+/)           // never an IP
})

test('Tor panel: IsTor false is shown as a failure; circuits locked while busy', async () => {
  globalThis.fetch = vi.fn(async () => json(200, torState({ isTor: false })))
  const first = renderWith(<TorPanel busy />, { network: 'mainnet' })
  await waitFor(() => expect(screen.getByTestId('tor-istor').textContent).toMatch(/IsTor ✗/))
  expect(screen.getByTestId('tor-new-all').disabled).toBe(true)
})

// M4a glue (S6 F1): the local panel reads /relay/tor (torRoles + the last drand IsTor check) and never says the local stack has no Tor
// while the relay uses it for drand. It makes read-only GETs only: no POST, no circuit controls.
test.each([
  ['drand via Tor, IsTor not checked yet', { isTor: null, torRoles: ['check', 'drand'] }, /local: drand via Tor \(IsTor not checked yet: on first use\); chains direct loopback/],
  ['drand via Tor, IsTor yes', { isTor: true, torRoles: ['check', 'drand'] }, /local: drand via Tor \(IsTor ✓\); chains direct loopback/],
  ['drand via Tor, IsTor no', { isTor: false, torRoles: ['check', 'drand'] }, /local: drand via Tor: unavailable \(IsTor ✗\); chains direct loopback/],
  ['no drand served', { isTor: null, torRoles: [] }, /local: n\/a — the local chains are direct loopback and this relay does not use Tor/],
])('Tor panel, local: %s', async (_name, over, line) => {
  globalThis.fetch = vi.fn(async () => json(200, torState(over)))
  renderWith(<TorPanel />, { network: 'local' })
  await waitFor(() => expect(screen.getByTestId('tor-local-line').textContent).toMatch(line))
  if (over.torRoles.length) expect(screen.getByTestId('tor-local-line').textContent).not.toMatch(/no Tor/)
  expect(globalThis.fetch.mock.calls.every(([u, i]) => u === '/relay/tor' && i?.method === undefined)).toBe(true)
  expect(screen.queryByTestId('tor-new-all')).toBeNull()
})

test('Tor panel, local: a relay that does not answer is "unknown", never "no Tor"', async () => {
  globalThis.fetch = vi.fn(async () => json(503, { error: { message: 'down' } }))
  renderWith(<TorPanel />, { network: 'local' })
  await waitFor(() => expect(screen.getByTestId('tor-local-line').textContent).toMatch(/Tor state unknown/))
  expect(screen.getByTestId('tor-local-line').textContent).not.toMatch(/no Tor|does not use Tor/)
})

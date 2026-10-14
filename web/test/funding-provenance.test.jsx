// Funding provenance in the page (plan W6, D-R21): the relay reads (src/funding/provenance.js), the Railgun tab, the attestation and the
// mainnet Arm gate. Recorded/synthetic Blockscout and JSON-RPC shapes; NO Sepolia or mainnet read is made. Core's gates/provenance.ts holds the
// rules (packages/core/test/gates/provenance.test.ts); these tests are about the page's reshaping and what it refuses to guess.
import { test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { RAILGUN_PROXY, RAILGUN_RELAYADAPT } from '@vault-timelock/core/gates/provenance.ts'
import { ProvenanceReadError, readEthProvenance } from '../src/funding/provenance.js'
import RailgunTab from '../src/funding/RailgunTab.jsx'
import ArmDialog from '../src/jobs/ArmDialog.jsx'
import { reduce } from '@vault-timelock/core/job'
import { newKey } from '../src/lib/core.js'
import { renderWith } from './helpers.jsx'
import { TEXT, created, ethChain, jobDef, journal, ready } from './job-fakes.js'

const EOA = '0x' + '11'.repeat(20)
const PROXY = RAILGUN_PROXY.mainnet
const ADAPT = RAILGUN_RELAYADAPT.mainnet                    // the PINNED RelayAdapt
const SPOOF = '0x' + 'dd'.repeat(20)                         // a contract that answers railgun() with the proxy and forwards ETH
const RELAY_INPUT = '0x28223a77' + '00'.repeat(64)
const parentOf = (to, over = {}) => ({ to: { hash: to }, value: '0', raw_input: RELAY_INPUT, ...over })
const OTHER = '0x' + 'cd'.repeat(20)
const H1 = '0x' + '22'.repeat(32), H2 = '0x' + '33'.repeat(32)
const wei = (n) => `0x${BigInt(n).toString(16)}`
const page = (items, next = null) => ({ items, next_page_params: next })
const ok = (o) => new Response(JSON.stringify(o), { status: 200, headers: { 'content-type': 'application/json' } })

// a fake relay: Blockscout pages, parent txs, and JSON-RPC (balance, nonce, railgun() of the adapt)
function relay(w, eoa = EOA) {
  const seen = []
  const f = async (url, init = {}) => {
    seen.push([String(url), init.method ?? 'GET'])
    const u = String(url)
    if (u === `/relay/blockscout/eth/addresses/${eoa}/transactions?filter=to`) return w.txs ? ok(w.txs) : new Response('{}', { status: 503 })
    if (u === `/relay/blockscout/eth/addresses/${eoa}/internal-transactions?filter=to`) return ok(w.internal ?? page([]))
    const parent = /\/relay\/blockscout\/eth\/transactions\/(0x[0-9a-f]{64})$/.exec(u)
    if (parent) return ok(w.parents?.[parent[1]] ?? {})
    if (u === '/relay/eth' && init.body && w.ethCallDown && JSON.parse(init.body).method === 'eth_call') return new Response('{}', { status: 503 })
    if (u === '/relay/eth') {
      const call = JSON.parse(init.body)
      const result = call.method === 'eth_getBalance' ? wei(w.balance ?? 0)
        : call.method === 'eth_getTransactionCount' ? wei(w.nonce ?? 0)
          : call.method === 'eth_call' ? (w.railgunOf?.[call.params[0].to] ? `0x${'0'.repeat(24)}${w.railgunOf[call.params[0].to].slice(2)}` : null)
            : null
      if (result === null) return ok({ jsonrpc: '2.0', id: 1, error: { code: -32000, message: 'execution reverted' } })
      return ok({ jsonrpc: '2.0', id: 1, result })
    }
    return new Response('{}', { status: 404 })
  }
  f.seen = seen
  return f
}
const passWorld = (eoa = EOA) => ({
  txs: page([]),
  internal: page([{ transaction_hash: H1, from: { hash: ADAPT }, to: { hash: eoa }, value: '50000000000000000', success: true }]),
  parents: { [H1]: parentOf(ADAPT) }, railgunOf: { [ADAPT]: PROXY }, balance: 50000000000000000n, nonce: 0,
})

test('PASS: the inbound was sent by the pinned RelayAdapt in a relay() call with value 0, nonce 0, total = balance → railgun', async () => {
  const f = relay(passWorld())
  const r = await readEthProvenance({ network: 'mainnet', address: EOA, fetch: f })
  expect(r.status).toBe('railgun')
  expect(r.verdict).toMatchObject({ ok: true, failures: [], railgunTxs: [H1] })
  // read-only: GETs on the two allowlisted Blockscout routes plus JSON-RPC reads; nothing else
  expect(f.seen.every(([u, m]) => (m === 'GET' && u.startsWith('/relay/blockscout/eth/')) || (m === 'POST' && u === '/relay/eth'))).toBe(true)
})

test('I-2 REGRESSION (review probe): a synthetic contract answering railgun() with the proxy is NOT a RelayAdapt: the badge must not say Railgun', async () => {
  const w = passWorld()
  const spoof = { ...w, internal: page([{ transaction_hash: H1, from: { hash: SPOOF }, to: { hash: EOA }, value: '50000000000000000', success: true }]), parents: { [H1]: parentOf(SPOOF) }, railgunOf: { [SPOOF]: PROXY, [ADAPT]: PROXY } }
  const r = await readEthProvenance({ network: 'mainnet', address: EOA, fetch: relay(spoof) })
  expect(r.status).toBe('elsewhere')
  expect(r.verdict.failures.map((x) => x.guard)).toEqual(['provenance.not-railgun'])
  expect(r.verdict.railgunTxs).toEqual([])
})

test('I-2: the pinned adapt as the parent\'s `to` is not enough: the value\'s sender must be Railgun\'s, and the parent must have run relay() with value 0', async () => {
  const run = async (internalFrom, parent) => (await readEthProvenance({ network: 'mainnet', address: EOA, fetch: relay({ ...passWorld(),
    internal: page([{ transaction_hash: H1, from: { hash: internalFrom }, to: { hash: EOA }, value: '50000000000000000', success: true }]), parents: { [H1]: parent } }) })).status
  expect(await run(ADAPT, parentOf(ADAPT))).toBe('railgun')
  expect(await run(SPOOF, parentOf(ADAPT))).toBe('elsewhere')                                           // a public wallet paying "through" the adapt
  expect(await run(ADAPT, parentOf(ADAPT, { raw_input: '0xe4899c13' + '00'.repeat(64) }))).toBe('elsewhere')   // multicall: open to anyone
  expect(await run(ADAPT, parentOf(ADAPT, { raw_input: '0x' }))).toBe('elsewhere')
  expect(await run(ADAPT, parentOf(ADAPT, { value: '1' }))).toBe('elsewhere')                          // ETH attached to relay()
  expect(await run(ADAPT, parentOf(PROXY))).toBe('railgun')                                             // the proxy as `to` needs no relay() call
  expect(await run(SPOOF, parentOf(PROXY))).toBe('elsewhere')
})

test('the pins are consistency-checked: if railgun() on the pinned adapt does not answer the proxy (or cannot be asked), nothing is concluded (unchecked)', async () => {
  for (const w of [{ ...passWorld(), railgunOf: {} }, { ...passWorld(), railgunOf: { [ADAPT]: OTHER } }, { ...passWorld(), ethCallDown: true }]) {
    await expect(readEthProvenance({ network: 'mainnet', address: EOA, fetch: relay(w) })).rejects.toThrow(ProvenanceReadError)
  }
})

test('a plain transfer from anyone, an extra inbound beside the Railgun one, a used address and unaccounted funds all fail with their guard', async () => {
  const plain = { txs: page([{ hash: H2, from: { hash: OTHER }, to: { hash: EOA }, value: '50000000000000000', status: 'ok' }]), internal: page([]), balance: 50000000000000000n, nonce: 0 }
  expect((await readEthProvenance({ network: 'mainnet', address: EOA, fetch: relay(plain) })).verdict.failures.map((x) => x.guard)).toEqual(['provenance.not-railgun'])
  const extra = { ...passWorld(), txs: page([{ hash: H2, from: { hash: OTHER }, to: { hash: EOA }, value: '1000', status: 'ok' }]), balance: 50000000000001000n }
  const e = await readEthProvenance({ network: 'mainnet', address: EOA, fetch: relay(extra) })
  expect(e.status).toBe('elsewhere'); expect(e.verdict.railgunTxs).toEqual([H1])
  expect((await readEthProvenance({ network: 'mainnet', address: EOA, fetch: relay({ ...passWorld(), nonce: 1 }) })).verdict.failures.map((x) => x.guard)).toEqual(['provenance.nonce'])
  expect((await readEthProvenance({ network: 'mainnet', address: EOA, fetch: relay({ ...passWorld(), balance: 60000000000000000n }) })).verdict.failures.map((x) => x.guard)).toEqual(['provenance.unaccounted'])
})

test('m-2: the status says WHY a check failed; red "elsewhere" is only for a transfer positively not from Railgun', async () => {
  const st = async (w) => (await readEthProvenance({ network: 'mainnet', address: EOA, fetch: relay(w) })).status
  expect(await st({ ...passWorld(), nonce: 1 })).toBe('sent')
  expect(await st({ ...passWorld(), balance: 60000000000000000n })).toBe('unaccounted')
  expect(await st({ txs: page([]), internal: page([]), balance: 0n, nonce: 0 })).toBe('unfunded')
  expect(await st({ ...passWorld(), txs: page([], { block_number: 1 }) })).toBe('paged')
  const plain = { txs: page([{ hash: H2, from: { hash: OTHER }, to: { hash: EOA }, value: '50000000000000000', status: 'ok' }]), internal: page([]), balance: 50000000000000000n, nonce: 0 }
  expect(await st(plain)).toBe('elsewhere')
  expect(await st({ ...plain, nonce: 2 })).toBe('elsewhere')                    // positively not Railgun wins over a used address
})

test('another page of transfers is refused (provenance.paged) on EITHER list, never partially checked', async () => {
  for (const over of [{ txs: page([], { block_number: 1 }) }, { internal: page([{ transaction_hash: H1, from: { hash: ADAPT }, to: { hash: EOA }, value: '50000000000000000', success: true }], { block_number: 1 }) }]) {
    const r = await readEthProvenance({ network: 'mainnet', address: EOA, fetch: relay({ ...passWorld(), ...over }) })
    expect(r.status).toBe('paged'); expect(r.verdict.failures.map((x) => x.guard)).toEqual(['provenance.paged'])
  }
})

test('an unreachable or odd indexer THROWS (unchecked), never passes: 503, not JSON, odd items, no parent, too many senders', async () => {
  const bad = async (w) => { try { await readEthProvenance({ network: 'mainnet', address: EOA, fetch: relay(w) }); return null } catch (e) { return e instanceof ProvenanceReadError ? e.message : `wrong: ${e}` } }
  expect(await bad({ ...passWorld(), txs: null })).toMatch(/503/)
  expect(await bad({ ...passWorld(), txs: { items: 'x' } })).toMatch(/not a Blockscout page/)
  expect(await bad({ ...passWorld(), internal: page([{ transaction_hash: 'x', to: { hash: EOA }, value: '1' }]) })).toMatch(/odd item/)
  expect(await bad({ ...passWorld(), internal: page([{ transaction_hash: H1, to: { hash: EOA }, value: '1', success: true }]) })).toMatch(/no sender/)
  expect(await bad({ ...passWorld(), parents: { [H1]: { to: { hash: ADAPT } } } })).toMatch(/no value or input/)
  expect(await bad({ ...passWorld(), parents: {} })).toMatch(/no recipient/)
  const many = Array.from({ length: 26 }, (_, i) => ({ transaction_hash: '0x' + i.toString(16).padStart(64, '0'), from: { hash: ADAPT }, to: { hash: EOA }, value: '1', success: true }))
  const parents = Object.fromEntries(many.map((m) => [m.transaction_hash, parentOf(ADAPT)]))
  expect(await bad({ ...passWorld(), internal: page(many), parents })).toMatch(/more than 25/)
  const f = async () => { throw new Error('offline') }
  await expect(readEthProvenance({ network: 'mainnet', address: EOA, fetch: f })).rejects.toThrow(/not reachable/)
  await expect(readEthProvenance({ network: 'local', address: EOA, fetch: relay(passWorld()) })).rejects.toThrow(/no indexer/)
  await expect(readEthProvenance({ network: 'mainnet', address: 'nope', fetch: relay(passWorld()) })).rejects.toThrow(/not an Ethereum address/)
})

test('the Railgun proxies and RelayAdapts are the ones broadcast pins (anchors.json)', () => {
  const anchors = JSON.parse(readFileSync(resolve(process.cwd(), '../broadcast/anchors.json'), 'utf8'))
  expect(anchors['railgun.proxy.eth'].address).toBe(RAILGUN_PROXY.mainnet)
  expect(anchors['railgun.proxy.sepolia'].address).toBe(RAILGUN_PROXY.testnet)
  expect(anchors['railgun.relayadapt.eth']).toMatchObject({ address: RAILGUN_RELAYADAPT.mainnet, network: 'mainnet' })
  expect(anchors['railgun.relayadapt.sepolia']).toMatchObject({ address: RAILGUN_RELAYADAPT.testnet, network: 'testnet' })
})

test('Railgun tab: manual instructions + the lane address + the badge; it reads only on a click, and never offers to sign', async () => {
  const user = userEvent.setup()
  const f = relay(passWorld())
  const reads = []
  renderWith(<RailgunTab network="mainnet" address={EOA} read={async (a) => { reads.push(a); return readEthProvenance({ ...a, fetch: f }) }} />, { network: 'mainnet' })
  expect(screen.getByTestId('rg-manual').textContent).toMatch(/never signs or sends a Railgun transaction/)
  expect(screen.getByTestId('rg-address').textContent).toBe(EOA)
  expect(screen.getByTestId('rg-badge').dataset.status).toBe('unchecked')
  expect(reads).toEqual([]); expect(f.seen).toEqual([])                                          // nothing is read on render
  await user.click(screen.getByTestId('rg-check'))
  await waitFor(() => expect(screen.getByTestId('rg-badge').dataset.status).toBe('railgun'))
  expect(screen.getByTestId('prov-ok')).toBeTruthy()
  expect(reads).toEqual([{ network: 'mainnet', address: EOA }])
  expect(screen.getAllByRole('button').map((b) => b.textContent).filter((t) => /sign|send|unshield|shield/i.test(t))).toEqual([])   // buttons: Copy, Check provenance
})

test('Railgun tab: a failed check lists every guard; an indexer error is "not checked: this is not a pass"; local has no gate', async () => {
  const user = userEvent.setup()
  const { unmount } = renderWith(<RailgunTab network="testnet" address={EOA} read={async (a) => readEthProvenance({ ...a, fetch: relay({ ...passWorld(), nonce: 3 }) })} />, { network: 'testnet' })
  await user.click(screen.getByTestId('rg-check'))
  await waitFor(() => expect(screen.getByTestId('rg-badge').dataset.status).toBe('elsewhere'))
  expect(screen.getByTestId('prov-reasons').textContent).toMatch(/provenance\.nonce/)
  unmount()
  const u2 = renderWith(<RailgunTab network="testnet" address={EOA} read={async () => { throw new ProvenanceReadError('the relay answered 503 for a provenance read') }} />, { network: 'testnet' })
  await user.click(screen.getByTestId('rg-check'))
  expect((await screen.findByTestId('rg-error')).textContent).toMatch(/503.*not a pass/)
  expect(screen.getByTestId('rg-badge').dataset.status).toBe('unchecked')
  u2.unmount()
  renderWith(<RailgunTab network="local" address={EOA} />, { network: 'local' })
  expect(screen.getByTestId('rg-local')).toBeTruthy(); expect(screen.queryByTestId('rg-check')).toBeNull()
})

// ---- the Arm gate (D-R21)
const ID = '00112233aabbccdd'
const ethKey = newKey('eth'), solKey = newKey('sol')
const inputs = (chains) => async () => ({ text: TEXT, prices: null, chains })
const cap = () => ({ nativeCap: '4000000000000000', usd: 10, priceAt: 1, overCap: false, planned: '0.004', fullCopyCost: '100000000000000', parts: 1, affordable: true })
async function openArm(network, readProvenance, balance = 1n, capOver = {}) {
  const user = userEvent.setup()
  const def = jobDef({ network, chains: { eth: ethChain(ethKey.address) } })
  const st = reduce(def, journal([created(ID), ...ready('eth', ethKey.address)]))
  globalThis.fetch = async (u) => (String(u) === '/relay/tor' ? ok({ isTor: true, roles: {}, checkedAt: Date.now() }) : new Response('{}', { status: 404 }))
  renderWith(<ArmDialog jobId={ID} def={def} state={st} inputs={inputs({ eth: { cap: { ...cap(), ...capOver }, balance, history: 0, error: '' } })} readProvenance={readProvenance} />, { network, status: { jobSends: 'ENABLED' } })
  await user.click(screen.getByTestId('arm-open'))
  await waitFor(() => expect(screen.getByTestId('arm-chain-eth')).toBeTruthy())
  return user
}

test('mainnet Arm (R76): proceeds with funds present and NO provenance check or attestation; a failed check only informs', async () => {
  const f = relay({ ...passWorld(ethKey.address), nonce: 2 }, ethKey.address)
  const user = await openArm('mainnet', (a) => readEthProvenance({ ...a, fetch: f }), 5_000_000_000_000_000n)
  expect(screen.getByTestId('arm-balance-eth').textContent).toMatch(/0\.005 ETH/)
  expect(screen.queryByTestId('arm-attest-eth')).toBeNull()
  await user.type(screen.getByTestId('arm-typed'), 'broadcast')
  expect(screen.queryByTestId('arm-problems')).toBeNull()
  expect(screen.getByTestId('arm-confirm').disabled).toBe(false)
  expect(screen.getByTestId('arm-prov-badge-eth').dataset.status).toBe('unchecked')
  await user.click(screen.getByTestId('arm-prov-check-eth'))
  await waitFor(() => expect(screen.getByTestId('arm-prov-badge-eth').dataset.status).toBe('sent'))
  expect(screen.getByTestId('arm-confirm').disabled).toBe(false)                              // informational: never blocking
})

test('mainnet Arm: a passing check shows the Railgun badge', async () => {
  const user = await openArm('mainnet', (a) => readEthProvenance({ ...a, fetch: relay(passWorld(ethKey.address), ethKey.address) }))
  await user.click(screen.getByTestId('arm-prov-check-eth'))
  await waitFor(() => expect(screen.getByTestId('arm-prov-badge-eth').dataset.status).toBe('railgun'))
  expect(screen.getByTestId('arm-confirm')).toBeTruthy()
})

test('mainnet Arm: an indexer failure shows an error and does not block', async () => {
  const u2 = await openArm('mainnet', async () => { throw new ProvenanceReadError('the relay is not reachable') })
  await u2.click(screen.getByTestId('arm-prov-check-eth'))
  expect((await screen.findByTestId('arm-prov-error-eth')).textContent).toMatch(/not reachable/)
})

test('mainnet Arm: no funds in the lane wallet (not READY / unaffordable) still blocks, as before W6', async () => {
  await openArm('mainnet', async () => { throw new Error('unused') }, 0n, { affordable: false })
  expect(screen.getByTestId('arm-balance-eth').textContent).toMatch(/no funds present/)
  expect(screen.getByTestId('arm-problems').textContent).toMatch(/not affordable/)
})

test('local Arm has no provenance section', async () => {
  await openArm('local', async () => { throw new Error('unused') })
  expect(screen.queryByTestId('arm-provenance')).toBeNull()
})

test('nothing in the provenance code touches storage or the clock, and the page makes no read before a click', () => {
  for (const f of ['funding/provenance.js', 'funding/FundingProvenance.jsx', 'funding/RailgunTab.jsx']) {
    const src = readFileSync(resolve(process.cwd(), 'src', f), 'utf8')
    expect(src, f).not.toMatch(/localStorage|sessionStorage|indexedDB|document\.cookie/)
  }
})

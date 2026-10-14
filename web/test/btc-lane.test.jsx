// The BTC lane in the page (W7 part B): the form, the funding panel, the job page for a synthetic btc journal, and the links.
// Everything is made up: a throwaway key (fixed hex), made-up txids, a fake same-origin stack. No chain, no ord, no network.
import { test, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { normalizeJob, reduce, sha256Hex } from '@vault-timelock/core/job'
import NewJob, { buildJobInput } from '../src/jobs/NewJob.jsx'
import ChainLane from '../src/jobs/ChainLane.jsx'
import JobView from '../src/jobs/JobView.jsx'
import BtcCopies, { btcCopiesOf } from '../src/jobs/BtcCopies.jsx'
import Funding from '../src/jobs/Funding.jsx'
import { addressLinks } from '../src/jobs/AddressLinks.jsx'
import { chainInput, chainIssues, configFromInput, defaultChainConfig } from '../src/jobs/ChainConfig.jsx'
import { BTC_MAX_FEE_RATE, BTC_POSTAGE, LOCAL_ORD, btcCapability, btcTxLinks, inscriptionId, ordLinks, parseFeeRate } from '../src/lib/btc.js'
import { fromSecret } from '../src/lib/core.js'
import { json, renderWith } from './helpers.jsx'
import { TEXT, fakeStack, journal } from './job-fakes.js'

const SECRET = '11'.repeat(32)                                   // a throwaway secp256k1 key made up for the tests
const KEY = fromSecret('btc', SECRET, 'local')
const COMMIT = 'c0'.repeat(32), REVEAL = 'e1'.repeat(32), FUND = 'f2'.repeat(32)
const REVEAL2 = 'e2'.repeat(32), COMMIT2 = 'c3'.repeat(32)
const ID = '0123456789abcdef'

beforeEach(() => {
  globalThis.fetch = vi.fn(async (url) => {
    if (String(url) === '/relay/price') return json(404, { error: { message: 'no price' } })
    return json(404, {})
  })
})

// ---------- Eminors fix 1 (I-1): the suggested ceiling ----------
test('the ceiling prefill rule: min(500, max(10, 4 x the relay estimate)), 25 with none; the estimate is the node\'s 2-block feerate in sat/vB', async () => {
  const { relayFeeEstimate, suggestedBtcFeeCeiling } = await import('../src/lib/btc.js')
  expect(await relayFeeEstimate(async () => ({ feerate: 0.00003 }))).toBe(3)                    // 0.00003 BTC/kvB = 3 sat/vB
  expect(await relayFeeEstimate(async () => ({ errors: ['Insufficient data'] }))).toBeNull()
  expect(await relayFeeEstimate(async () => { throw new Error('down') })).toBeNull()
  expect([null, 1, 3, 40, 200].map((e) => suggestedBtcFeeCeiling(e))).toEqual([25, 10, 12, 160, 500])
})

// ---------- lib/btc.js ----------
test('fee rate: empty means the node estimate; a whole number from 1 to the ticket cap; nothing else', () => {
  expect(BTC_MAX_FEE_RATE).toBe(500)                              // core btc-ord.ts BTC_MAX_FEE_RATE, not retyped here
  expect(BTC_POSTAGE).toBe(546)
  expect(parseFeeRate('')).toMatchObject({ ok: true, value: null })
  expect(parseFeeRate(' 12 ')).toMatchObject({ ok: true, value: 12 })
  expect(parseFeeRate('500')).toMatchObject({ ok: true, value: 500 })
  for (const bad of ['0', '501', '1.5', '-3', '1e2', 'abc', '99999']) expect(parseFeeRate(bad).ok, bad).toBe(false)
})

test('ord links: the local ord opens (inscription = <reveal txid>i0); testnet4 and mainnet are copy-only', () => {
  expect(inscriptionId(REVEAL)).toBe(`${REVEAL}i0`)
  const local = ordLinks('local', REVEAL)
  expect(local[0]).toMatchObject({ url: `${LOCAL_ORD}/inscription/${REVEAL}i0`, open: true })
  expect(LOCAL_ORD).toBe('http://127.0.0.1:8090')
  for (const n of ['testnet', 'mainnet']) {
    const l = ordLinks(n, REVEAL)
    expect(l.length, n).toBeGreaterThan(0)
    expect(l.every((x) => x.open === false && x.url.startsWith('https://')), n).toBe(true)
    expect(btcTxLinks(n, COMMIT).every((x) => x.open === false), n).toBe(true)
  }
  expect(btcTxLinks('local', COMMIT)).toEqual([{ label: 'ord (local) · transaction', url: `${LOCAL_ORD}/tx/${COMMIT}`, open: true }])
  expect(ordLinks('local', 'not a txid')).toEqual([])             // never a link built from a malformed id
  expect(ordLinks('mars', REVEAL)).toEqual([])
  expect(addressLinks('local', 'btc', KEY.address)[0]).toMatchObject({ url: `${LOCAL_ORD}/address/${KEY.address}`, open: true })
  expect(addressLinks('mainnet', 'btc', KEY.address).every((l) => !l.open)).toBe(true)
})

test('capability: both on since E7b (the job layer row is read from core), and the switches follow core', () => {
  expect(btcCapability()).toEqual({ jobs: true, executor: true })
  expect(btcCapability({ executorWired: false })).toEqual({ jobs: true, executor: false })
  expect(btcCapability({ table: () => ({ status: 'available' }), executorWired: true })).toEqual({ jobs: true, executor: true })
  expect(btcCapability({ table: () => ({ status: 'reserved' }) }).jobs).toBe(false)
})

// ---------- the form ----------
test('config: copies only, publish mode btc.inscription, fee rate checked, claw-back null', () => {
  const d = defaultChainConfig('btc')
  expect(d).toMatchObject({ enabled: false, mode: 'copies', copies: '1', publishMode: 'btc.inscription', maxFeeRate: '' })
  expect(chainIssues('btc', d).join()).toMatch(/max fee rate: required/)                 // Eminors fix 1: the ceiling is required
  expect(chainIssues('btc', { ...d, maxFeeRate: '25' })).toEqual([])
  expect(chainIssues('btc', { ...d, maxFeeRate: '25', mode: 'drain' }).join()).toMatch(/copies only/)
  expect(chainIssues('btc', { ...d, copies: '0' }).join()).toMatch(/copies/)
  expect(chainIssues('btc', { ...d, copies: '10001' }).join()).toMatch(/copies/)
  expect(chainIssues('btc', { ...d, maxFeeRate: '501' }).join()).toMatch(/500/)
  expect(chainIssues('btc', { ...d, publishMode: 'btc.ordinal-jpeg' }).join()).toMatch(/only btc\.inscription/)
  expect(chainIssues('btc', { ...d, budgetUsd: '0' }).join()).toMatch(/budget/)
  const input = chainInput('btc', { ...d, copies: '3', maxFeeRate: '25' }, KEY.address)
  expect(input).toEqual({ mode: { copies: 3 }, publishMode: 'btc.inscription', feeStrategy: 'economy', distinctCopies: true, keyAddress: KEY.address, budgetUsd: 10, maxFeeRateSatVb: 25, clawbackTo: null })
  expect(chainInput('btc', d, KEY.address)).not.toHaveProperty('maxFeeRateSatVb')   // (the form refuses to submit it empty: chainIssues)
  expect(configFromInput('btc', input)).toMatchObject({ enabled: true, mode: 'copies', copies: '3', maxFeeRate: '25' })   // job-file import round trip
})

test('new job on local: the BTC lane shows copies only, the publish mode, the postage and the fee rate', async () => {
  const user = userEvent.setup()
  renderWith(<NewJob />)
  expect(screen.getByTestId('chain-btc')).toBeTruthy()
  await user.click(screen.getByTestId('enabled-btc'))
  expect(screen.getByTestId('btc-copies-only').textContent).toMatch(/N copies only/)
  expect(screen.queryByTestId('mode-drain-btc')).toBeNull()                        // no drain mode for Bitcoin
  expect(screen.getByTestId('publish-mode-btc').textContent).toBe('btc.inscription (text/plain)')
  expect(screen.getByTestId('btc-postage').textContent).toMatch(/546 sat/)
  expect(screen.getByTestId('fee-rate-btc')).toBeTruthy()
  await user.clear(screen.getByTestId('n-btc')); await user.type(screen.getByTestId('n-btc'), '2')
  await waitFor(() => expect(screen.getByTestId('fee-rate-btc').value).toBe('25'))        // Eminors fix 1: prefilled (no relay estimate here: 25), editable
  await user.clear(screen.getByTestId('fee-rate-btc')); await user.type(screen.getByTestId('fee-rate-btc'), '501')
  expect(screen.getByTestId('issues-btc').textContent).toMatch(/1 to 500/)
  await user.clear(screen.getByTestId('fee-rate-btc'))
  expect(screen.getByTestId('issues-btc').textContent).toMatch(/required/)
  await new Promise((r) => setTimeout(r, 50))
  expect(screen.getByTestId('fee-rate-btc').value).toBe('')                               // an operator who cleared it is not overwritten again
  await user.type(screen.getByTestId('fee-rate-btc'), '7')
  expect(screen.queryByTestId('issues-btc')).toBeNull()
  expect(screen.queryByTestId('btc-jobs-unavailable')).toBeNull()                  // the job layer accepts the lane now
  await user.type(screen.getByTestId('job-name'), 'btc job'); await user.type(screen.getByTestId('message'), 'one line')
  expect(screen.getByTestId('job-create').disabled).toBe(true)
  expect(screen.getByTestId('job-problems').textContent).not.toMatch(/job service does not accept/)
  expect(screen.getByTestId('job-problems').textContent).toMatch(/btc: key and backup not done/)
  expect(screen.getByTestId('keylane-btc')).toBeTruthy()
})

test('Eminors fix 2: a LATE fee estimate fills only the fee field - copies and budget the operator edited meanwhile stay; an edited fee field is not overwritten', async () => {
  const user = userEvent.setup()
  let release
  const gate = new Promise((r) => { release = r })
  const seen = []
  globalThis.fetch = vi.fn(async (url, init = {}) => {
    seen.push(String(url))
    if (String(url).includes('/relay/btc')) { await gate; return json(200, { jsonrpc: '2.0', id: 1, result: { feerate: 0.00003 } }) }   // 3 sat/vB -> suggestion 12
    return json(404, {})
  })
  renderWith(<NewJob />)
  await user.click(screen.getByTestId('enabled-btc'))
  await waitFor(() => expect(seen.some((u) => u.includes('/relay/btc'))).toBe(true))      // the estimate is in flight
  await user.clear(screen.getByTestId('n-btc')); await user.type(screen.getByTestId('n-btc'), '7')
  await user.clear(screen.getByTestId('budget-btc')); await user.type(screen.getByTestId('budget-btc'), '3.5')
  expect(screen.getByTestId('fee-rate-btc').value).toBe('')
  release()
  await waitFor(() => expect(screen.getByTestId('fee-rate-btc').value).toBe('12'))
  expect(screen.getByTestId('n-btc').value).toBe('7')
  expect(screen.getByTestId('budget-btc').value).toBe('3.5')
})

test('Eminors fix 2: the operator typed the fee field before the estimate arrived - it is not overwritten', async () => {
  const user = userEvent.setup()
  let release
  const gate = new Promise((r) => { release = r })
  globalThis.fetch = vi.fn(async (url) => {
    if (String(url).includes('/relay/btc')) { await gate; return json(200, { jsonrpc: '2.0', id: 1, result: { feerate: 0.0001 } }) }
    return json(404, {})
  })
  renderWith(<NewJob />)
  await user.click(screen.getByTestId('enabled-btc'))
  await user.type(screen.getByTestId('fee-rate-btc'), '33')
  release()
  await new Promise((r) => setTimeout(r, 100))
  expect(screen.getByTestId('fee-rate-btc').value).toBe('33')
})

test('new job on testnet and mainnet: the BTC lane says "not available yet" and cannot be switched on', () => {
  for (const network of ['testnet', 'mainnet']) {
    const { unmount } = renderWith(<NewJob />, { network })
    expect(screen.getByTestId('btc-unavailable').textContent).toMatch(/not available yet/)
    expect(screen.getByTestId('enabled-btc').disabled).toBe(true)
    expect(screen.queryByTestId('keylane-btc')).toBeNull()
    unmount()
  }
})

test('the job input carries the btc lane the way the contract names it (when a job service accepts it)', () => {
  const cfgs = { eth: defaultChainConfig('eth'), sol: defaultChainConfig('sol'), btc: { ...defaultChainConfig('btc'), enabled: true, copies: '2', maxFeeRate: '9' } }
  const out = buildJobInput({ network: 'local', name: 'n', check: { sha256: 'a'.repeat(64), bytes: 5 }, cfgs, addresses: { btc: KEY.address } })
  expect(Object.keys(out.chains)).toEqual(['btc'])
  expect(out.chains.btc).toMatchObject({ mode: { copies: 2 }, publishMode: 'btc.inscription', keyAddress: KEY.address, maxFeeRateSatVb: 9, clawbackTo: null })
})

// ---------- funding ----------
test('funding: the lane\'s p2wpkh address with the regtest hint on local; none of the hint elsewhere; the address is copy-only off local', () => {
  expect(KEY.address).toMatch(/^bcrt1q[02-9ac-hj-np-z]{38}$/)                      // p2wpkh on regtest
  const { unmount } = render(<Funding network="local" addresses={{ btc: KEY.address }} />)
  expect(screen.getByTestId('fund-addr-btc').textContent).toBe(KEY.address)
  expect(screen.getByTestId('funding-btc').textContent).toMatch(/p2wpkh/)
  const hint = screen.getByTestId('funding-btc-regtest').textContent
  expect(hint).toContain(`bitcoin-cli -regtest generatetoaddress 101 ${KEY.address}`)
  expect(hint).toMatch(/sendtoaddress/)
  expect(screen.getByTestId('links-btc').querySelector('a').href).toBe(`${LOCAL_ORD}/address/${KEY.address}`)
  unmount()
  const t = fromSecret('btc', SECRET, 'testnet')
  render(<Funding network="testnet" addresses={{ btc: t.address }} />)
  expect(t.address).toMatch(/^tb1q/)
  expect(screen.queryByTestId('funding-btc-regtest')).toBeNull()
  expect(screen.getByTestId('links-btc').querySelector('a')).toBeNull()            // copy-only
})

// ---------- the job page ----------
const PUB = KEY.pubkey
const DEF = {
  format: 'vt-job/1', network: 'local', name: 'w7b btc job', messageSha256: sha256Hex(TEXT), messageBytes: new TextEncoder().encode(TEXT).length,
  chains: { btc: { mode: { copies: 2 }, publishMode: 'btc.inscription', feeStrategy: 'economy', distinctCopies: true, keyAddress: KEY.address, budgetUsd: 10, clawbackTo: null } },
}
const intent = (txId, copy, part, btc, reserved) => ({ chain: 'btc', by: 'browser', gen: 1, type: 'intent', data: { txId, copy, part, parts: 2, attempt: 1, replaces: null, rawSha256: 'a'.repeat(64), payloadSha256: 'b'.repeat(64), reserved, btc } })
const sent = (txId) => ({ chain: 'btc', by: 'browser', gen: 1, type: 'sent', data: { txId, outcome: 'accepted', reason: null } })
const included = (txId, copy, part, fee, block) => ({ chain: 'btc', by: 'browser', gen: 1, type: 'included', data: { txId, copy, part, attempt: 1, block, fee, ms: 1000 } })
const readback = (txId, ok, detail) => ({ chain: 'btc', by: 'browser', gen: 1, type: 'readback', data: { txId, ok, detail } })
const EVENTS = journal([
  { type: 'created', data: { jobId: ID, defSha256: 'a'.repeat(64) } },
  { chain: 'btc', type: 'lease-acquired', gen: 1, data: { gen: 1, holder: 'browser', ttlMs: 15000 } },
  { chain: 'btc', by: 'browser', gen: 1, type: 'key-loaded', data: { address: KEY.address } },
  { chain: 'btc', by: 'browser', gen: 1, type: 'funds', data: { balance: '500000', affordable: true, nextCopyCost: '2000' } },
  { type: 'armed', data: { armedAt: 1_800_000_009_000, releaseAt: 1_800_000_024_000, countdownSec: 15, schedule: { order: ['btc'], offsetSec: { btc: 0 } }, caps: { btc: { nativeCap: '100000', usd: 10, priceAt: 1_800_000_009_000, overCap: false, planned: '0.001' } }, sources: {} } },
  // copy 1: commit + reveal landed, the reveal read back equal to the part bytes
  intent(COMMIT, 1, 1, { kind: 'commit', pubkey: PUB, fee: '300', value: '1100', inputs: [`${FUND}:0`] }, '1400'),
  sent(COMMIT), included(COMMIT, 1, 1, '300', '102'), readback(COMMIT, true, 'commit output pays the inscription address'),
  intent(REVEAL, 1, 2, { kind: 'reveal', pubkey: PUB, fee: '554', commitVout: 0 }, '0'),
  sent(REVEAL), included(REVEAL, 1, 2, '554', '103'), readback(REVEAL, true, 'inscription 45 B = part bytes ✓ · text/plain'),
  { chain: 'btc', by: 'browser', gen: 1, type: 'reassembled', data: { copy: 1, ok: true, sha256: sha256Hex(TEXT) } },
  // copy 2: the commit landed, the reveal is still in flight
  intent(COMMIT2, 2, 1, { kind: 'commit', pubkey: PUB, fee: '300', value: '1100', inputs: [`${FUND}:1`] }, '1400'),
  sent(COMMIT2), included(COMMIT2, 2, 1, '300', '104'), readback(COMMIT2, true, 'commit output pays the inscription address'),
  intent(REVEAL2, 2, 2, { kind: 'reveal', pubkey: PUB, fee: '554', commitVout: 0 }, '0'),
  sent(REVEAL2),
])

test('the journal of a synthetic btc job folds to commit + reveal per copy, with the btc intent kept on the attempts', () => {
  const st = reduce(DEF, EVENTS)
  expect(st.corrupt ?? null).toBeNull()
  const txs = st.chains.btc.txs
  expect(txs.map((t) => `${t.copy}.${t.part}:${t.state}`)).toEqual(['1.1:included', '1.2:included', '2.1:included', '2.2:open'])
  expect(txs[1].attempts[0].btc).toMatchObject({ kind: 'reveal', commitVout: 0 })
  expect(btcCopiesOf(txs).map((c) => [c.copy, c.commit.part, c.reveal.part])).toEqual([[1, 1, 2], [2, 1, 2]])
})

function stack() {
  return fakeStack({ id: ID, def: DEF, events: EVENTS })
}

test('job page: per copy the commit and reveal txids, states, the ord link, and the readback ✓; Run here is on (E7b)', async () => {
  const s = stack()
  globalThis.fetch = s.fetch
  renderWith(<JobView id={ID} jobOptions={{ pollMs: 200, flushMs: 10 }} />, { seed: [['btc', KEY]] })
  const lane = await screen.findByTestId('lane-btc')
  expect(lane.textContent).toMatch(/Bitcoin · 2 copies/)
  const rows = await screen.findAllByTestId('btc-copy-row')
  expect(rows).toHaveLength(2)
  const r1 = within(rows[0]), r2 = within(rows[1])
  expect(r1.getByTestId('btc-commit').dataset.state).toBe('included')
  expect(r1.getByTestId('btc-reveal').dataset.state).toBe('included')
  expect(r1.getByTestId('btc-commit-txid').title).toBe(COMMIT)
  expect(r1.getByTestId('btc-reveal-txid').title).toBe(REVEAL)
  expect(r1.getByTestId('btc-inscription-id').title).toBe(`${REVEAL}i0`)
  const hrefs = [...rows[0].querySelectorAll('a[href]')].map((a) => a.href)
  expect(hrefs).toContain(`${LOCAL_ORD}/inscription/${REVEAL}i0`)
  expect(hrefs).toContain(`${LOCAL_ORD}/tx/${COMMIT}`)
  expect(r1.getByTestId('readback-btc').dataset.ok).toBe('true')
  expect(r1.getByTestId('readback-btc').textContent).toMatch(/body = part bytes/)
  expect(r1.getByTestId('btc-commit').textContent).toMatch(/fee 300 sat/)
  expect(r1.getByTestId('btc-commit').textContent).toMatch(/locks 1100 sat \(incl\. 546 postage\)/)
  // copy 2: the reveal is in flight, so there is no inscription link yet and no readback
  expect(r2.getByTestId('btc-reveal').dataset.state).toBe('open')
  expect(r2.queryByTestId('btc-inscription-id')).toBeNull()
  expect(rows[1].textContent).toMatch(/after the reveal lands/)
  expect(r2.getByTestId('readback-btc').dataset.ok).toBe('')
  expect(rows[1].querySelectorAll('a[href]').length).toBe(1)                                      // only the commit's tx link
  // E7b is merged: Run here for btc is offered (the key of this tab matches the job's)
  expect(screen.queryByTestId('btc-run-gated')).toBeNull()
  expect(screen.getByTestId('run-btc').disabled).toBe(false)
  expect(screen.getByTestId('progress-btc').dataset.total).toBe('4')                              // 2 copies x (commit + reveal)
  expect(screen.getByTestId('progress-btc').dataset.done).toBe('3')
})

test('Run here for btc turns on with the capability (and a matching key), not before', async () => {
  const state = reduce(DEF, EVENTS)
  const common = { jobId: ID, def: DEF, chain: 'btc', state, lease: null, extras: undefined, now: 1_800_000_030_000, network: 'local' }
  const gated = renderWith(<ChainLane {...common} capability={{ jobs: true, executor: false }} />, { seed: [['btc', KEY]] })
  await waitFor(() => expect(screen.getByTestId('run-btc')).toBeTruthy())
  expect(screen.getByTestId('run-btc').disabled).toBe(true)
  expect(screen.getByTestId('btc-run-gated')).toBeTruthy()
  gated.unmount()
  renderWith(<ChainLane {...common} />, { seed: [['btc', KEY]] })
  await waitFor(() => expect(screen.getByTestId('run-btc').disabled).toBe(false))
  expect(screen.queryByTestId('btc-run-gated')).toBeNull()
})

test('off local the ord and transaction links are text with a Copy button, never an anchor', () => {
  const rows = reduce({ ...DEF, network: 'mainnet' }, EVENTS).chains.btc.txs
  for (const network of ['testnet', 'mainnet']) {
    const { container, unmount } = render(<BtcCopies rows={rows} network={network} />)
    expect(container.querySelectorAll('a[href]').length, network).toBe(0)
    expect(container.textContent).toMatch(/copy inscription/)
    unmount()
  }
})

test('a failed readback is marked ✗ (the witness is not the one inscription of the part bytes)', () => {
  const events = [...EVENTS.slice(0, -1), ...journal([
    { chain: 'btc', by: 'browser', gen: 1, type: 'sent', data: { txId: REVEAL2, outcome: 'accepted', reason: null } },
    included(REVEAL2, 2, 2, '554', '105'), readback(REVEAL2, false, 'the witness is not the one inscription'),
  ].map((e) => ({ ...e, chain: 'btc' })))]
  const evs = events.map((e, i) => ({ ...e, seq: i }))
  const st = reduce(DEF, evs)
  const rows = st.chains.btc.txs
  const { container } = render(<BtcCopies rows={rows} network="local" />)
  const cells = [...container.querySelectorAll('[data-testid="readback-btc"]')].map((c) => c.dataset.ok)
  expect(cells).toEqual(['true', 'false'])
  expect(container.textContent).toMatch(/✗ body differs/)
})

test('a settled btc chain says it has no claw-back, and offers none', () => {
  const evs = [...EVENTS, ...journal([
    included(REVEAL2, 2, 2, '554', '105'), readback(REVEAL2, true, 'ok'),
    { chain: 'btc', by: 'browser', gen: 1, type: 'reassembled', data: { copy: 2, ok: true, sha256: sha256Hex(TEXT) } },
    { chain: 'btc', by: 'browser', gen: 1, type: 'copies-done', data: { copies: 2 } },
  ])].map((e, i) => ({ ...e, seq: i }))
  const state = reduce(DEF, evs)
  expect(state.chains.btc.phase).toBe('COPIES_DONE')
  renderWith(<ChainLane jobId={ID} def={DEF} chain="btc" state={state} lease={null} now={1_800_000_040_000} network="local" />)
  expect(screen.getByTestId('afterrun-btc').textContent).toMatch(/no claw-back/)
  expect(screen.queryByTestId('afterrun-claw-btc')).toBeNull()
  expect(screen.queryByTestId('btc-run-gated')).toBeNull()                         // settled: nothing to run
})

// ---------- the key ----------
test('key lane: a BTC private key (64 hex) imports as its p2wpkh address on this network', async () => {
  const user = userEvent.setup()
  renderWith(<NewJob />)
  await user.click(screen.getByTestId('enabled-btc'))
  await user.click(screen.getByTestId('keychoice-btc-import')); await user.click(screen.getByTestId('kimport-btc-key'))
  await user.type(screen.getByTestId('ksecret-btc'), SECRET)
  await user.click(screen.getByTestId('kcheck-btc'))
  expect(screen.getByTestId('kderived-btc').textContent).toBe(KEY.address)
  await user.clear(screen.getByTestId('ksecret-btc')); await user.type(screen.getByTestId('ksecret-btc'), 'zz')
  await user.click(screen.getByTestId('kcheck-btc'))
  expect(screen.getByTestId('kerr-btc').textContent).toMatch(/64 hex/)
})

test('btc backup file: encrypt, then open it again to the same key; a wrong chain is refused', async () => {
  const { newKey, encryptKey, decryptKeyFile, verifySavedFile } = await import('../src/lib/core.js')
  const k = newKey('btc', 'local')
  expect(k.address).toMatch(/^bcrt1q/)
  const { ct } = await encryptKey(k, 'correct horse battery staple orchid lantern', 'local')
  const back = await decryptKeyFile(ct, 'correct horse battery staple orchid lantern', 'btc', 'local')
  expect(back.key.address).toBe(k.address); expect(back.network).toBe('local')
  expect(await verifySavedFile(ct, 'correct horse battery staple orchid lantern', k)).toBe(true)
  await expect(decryptKeyFile(ct, 'correct horse battery staple orchid lantern', 'eth')).rejects.toThrow(/not eth/)
  await expect(verifySavedFile(ct, 'correct horse battery staple orchid lantern', newKey('btc', 'local'))).rejects.toThrow(/DIFFERENT key/)
  expect(JSON.stringify(k)).not.toContain(k.secret)                                // the secret never shows up in a serialisation
}, 120_000)

// ---------- Wfix5: create, Arm pricing ----------
test('Create posts the ratified btc lane: publishMode btc.inscription, copies, maxFeeRateSatVb, no claw-back', async () => {
  const user = userEvent.setup()
  const calls = []
  globalThis.fetch = vi.fn(async (url, init = {}) => {
    calls.push({ url: String(url), init })
    if (String(url) === '/relay/price') return json(404, {})
    if (String(url).startsWith('/api/messages/')) return json(201, { sha256: 'x', bytes: 1 })
    if (String(url) === '/api/jobs') return json(201, { id: ID, def: {}, state: {} })
    return json(404, {})
  })
  renderWith(<NewJob navigate={() => {}} />, { seed: [['btc', KEY]] })
  await user.click(screen.getByTestId('enabled-btc'))
  await user.type(screen.getByTestId('job-name'), 'btc job'); await user.type(screen.getByTestId('message'), 'one line')
  await user.clear(screen.getByTestId('n-btc')); await user.type(screen.getByTestId('n-btc'), '2')
  await waitFor(() => expect(screen.getByTestId('fee-rate-btc').value).toBe('25'))
  await user.clear(screen.getByTestId('fee-rate-btc')); await user.type(screen.getByTestId('fee-rate-btc'), '40')
  await waitFor(() => expect(screen.getByTestId('job-create').disabled).toBe(false))
  await user.click(screen.getByTestId('job-create'))
  await waitFor(() => expect(calls.some((c) => c.url === '/api/jobs')).toBe(true))
  const body = JSON.parse(calls.find((c) => c.url === '/api/jobs').init.body)
  expect(body.chains).toEqual({ btc: { mode: { copies: 2 }, publishMode: 'btc.inscription', feeStrategy: 'economy', distinctCopies: true, keyAddress: KEY.address, budgetUsd: 10, maxFeeRateSatVb: 40, clawbackTo: null } })
  // core's validator (job.fee-rate bounds, bech32 p2wpkh address) accepts exactly this input
  const { normalizeJob } = await import('@vault-timelock/core/job')
  const def = normalizeJob({ ...body, messageSha256: sha256Hex('one line'), messageBytes: 8 }, { network: 'local' }).def
  expect(def.chains.btc.maxFeeRateSatVb).toBe(40)
  expect(() => normalizeJob({ ...body, chains: { btc: { ...body.chains.btc, maxFeeRateSatVb: 501 } }, messageSha256: sha256Hex('one line'), messageBytes: 8 }, { network: 'local' })).toThrow(/fee-rate|maxFeeRateSatVb/)
})

test('the Arm dialog shows the btc fee rate, the worst-case commit + reveal fee, the postage and the lane balance', async () => {
  const user = userEvent.setup()
  const def = normalizedDef()
  const state = reduce(def, journal([
    { type: 'created', data: { jobId: ID, defSha256: 'a'.repeat(64) } },
    { chain: 'btc', type: 'lease-acquired', gen: 1, data: { gen: 1, holder: 'browser', ttlMs: 15000 } },
    { chain: 'btc', by: 'browser', gen: 1, type: 'key-loaded', data: { address: KEY.address } },
    { chain: 'btc', by: 'browser', gen: 1, type: 'funds', data: { balance: '500000', affordable: true, nextCopyCost: '2000' } },
  ]))
  const inputs = async () => ({ text: TEXT, prices: null, chains: { btc: {
    cap: { nativeCap: '5000', usd: 0, priceAt: null, overCap: false, planned: '0.00005', fullCopyCost: '2000', parts: 2, affordable: true },
    balance: 500000n, history: 0, reserve: 0n, windowNote: '', error: '', btc: { rate: 7n, commitFee: 1000n, revealFee: 900n, postage: 546n, perCopy: 2446n },
  } } })
  const ArmDialog = (await import('../src/jobs/ArmDialog.jsx')).default
  renderWith(<ArmDialog jobId={ID} def={def} state={state} inputs={inputs} />)
  await user.click(screen.getByTestId('arm-open'))
  await waitFor(() => expect(screen.getByTestId('arm-btc')).toBeTruthy())
  expect(screen.getByTestId('arm-btc-rate').textContent).toMatch(/worst case priced at 50 sat\/vB \(the job's maxFeeRateSatVb\).*estimate today is 7 sat\/vB/)
  expect(screen.getByTestId('arm-btc-fees').textContent).toMatch(/commit 1000 sat \+ reveal 900 sat \+ postage 546 sat = 2446 sat/)
  expect(screen.getByTestId('arm-btc-balance').textContent).toMatch(/lane balance 500000 sat \(0\.005 BTC\)/)
  expect(screen.getByTestId('permanence-btc').textContent).toMatch(/btc\.inscription/)
})

// Eminors fix 2: the Arm dialog's wording is pinned: the ceiling is named (the job's, or the 500 default), and a refusal says balance or cap.
test('the Arm dialog names the ceiling, says balance vs cap when a copy is not affordable, and says the cap is the fallback', async () => {
  const user = userEvent.setup()
  const def = normalizedDef()
  const state = reduce(def, journal([
    { type: 'created', data: { jobId: ID, defSha256: 'a'.repeat(64) } },
    { chain: 'btc', type: 'lease-acquired', gen: 1, data: { gen: 1, holder: 'browser', ttlMs: 15000 } },
    { chain: 'btc', by: 'browser', gen: 1, type: 'key-loaded', data: { address: KEY.address } },
    { chain: 'btc', by: 'browser', gen: 1, type: 'funds', data: { balance: '500000', affordable: true, nextCopyCost: '2000' } },
  ]))
  const ArmDialog = (await import('../src/jobs/ArmDialog.jsx')).default
  const cases = [
    { because: 'balance', want: /Bitcoin: the lane balance is below one worst-case copy \(priced at 50 sat\/vB, the job's maxFeeRateSatVb\)/ },
    { because: 'cap', want: /Bitcoin: one worst-case copy is above the cap \(priced at 50 sat\/vB, the job's maxFeeRateSatVb\)/ },
  ]
  for (const c of cases) {
    const inputs = async () => ({ text: TEXT, prices: null, chains: { btc: {
      cap: { nativeCap: '5000', usd: 0, priceAt: null, overCap: false, planned: '0.00005', fullCopyCost: '9000', parts: 2, affordable: false, notAffordableBecause: c.because, capVia: 'fallback', ceilingSatVb: 50, ceilingFromJob: true },
      balance: 500000n, history: 0, reserve: 0n, windowNote: '', error: '', btc: { rate: 7n, commitFee: 1000n, revealFee: 900n, postage: 546n, perCopy: 2446n },
    } } })
    const { unmount } = renderWith(<ArmDialog jobId={ID} def={def} state={state} inputs={inputs} />)
    await user.click(screen.getByTestId('arm-open'))
    await waitFor(() => expect(screen.getByTestId('arm-btc')).toBeTruthy())
    expect(screen.getByTestId('arm-problems').textContent).toMatch(c.want)
    expect(screen.getByTestId('arm-btc-cap-note').textContent).toMatch(/the cap is the 0\.01 BTC native fallback/)
    unmount()
  }
  // a job that names no ceiling (an old job): the row says the 500 default
  const oldDef = normalizeJob({ ...DEF, chains: { btc: { ...DEF.chains.btc } } }, { network: 'local', existing: true }).def
  expect(oldDef.chains.btc.maxFeeRateSatVb).toBeUndefined()
  const inputs = async () => ({ text: TEXT, prices: null, chains: { btc: {
    cap: { nativeCap: '5000', usd: 0, priceAt: null, overCap: false, planned: '0.00005', fullCopyCost: '2000', parts: 2, affordable: true, capVia: 'typed', ceilingSatVb: 500, ceilingFromJob: false },
    balance: 500000n, history: 0, reserve: 0n, windowNote: '', error: '', btc: { rate: 7n, commitFee: 1000n, revealFee: 900n, postage: 546n, perCopy: 2446n },
  } } })
  renderWith(<ArmDialog jobId={ID} def={oldDef} state={state} inputs={inputs} />)
  await user.click(screen.getByTestId('arm-open'))
  await waitFor(() => expect(screen.getByTestId('arm-btc')).toBeTruthy())
  expect(screen.getByTestId('arm-btc-rate').textContent).toMatch(/worst case priced at 500 sat\/vB \(the 500 sat\/vB default ceiling: this job names none\)/)
  expect(screen.queryByTestId('arm-btc-cap-note')).toBeNull()
})

function normalizedDef() {
  return normalizeJob({ ...DEF, chains: { btc: { ...DEF.chains.btc, maxFeeRateSatVb: 50 } } }, { network: 'local' }).def
}

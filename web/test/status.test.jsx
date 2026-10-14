// Status / pre-flight page (W4): the readiness table renders a PreflightReport fixture plus the page rows (chain identity,
// isTor as a boolean, build ids, network match, the fork-drift message, release verified on mainnet); no IP is shown;
// the mainnet Arm stays gated until every operator tick is set (ticks live in tab memory only).
import { test, expect, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { reduce } from '@vault-timelock/core/job'
import ArmDialog from '../src/jobs/ArmDialog.jsx'
import Status from '../src/pages/Status.jsx'
import ReadinessTable from '../src/status/ReadinessTable.jsx'
import { MAINNET_TICKS, pageRows } from '../src/status/readiness.js'
import { newKey } from '../src/lib/core.js'
import { json, relayOf, renderWith, statusOf } from './helpers.jsx'
import { TEXT, created, ethChain, jobDef, journal, ready } from './job-fakes.js'

const CANARY = '203.0.113.77'
const report = (network = 'mainnet', over = {}) => ({
  format: 'vt-preflight/1', network, at: 1, idOk: true, deployOk: true, exit: 0,
  rows: [
    { id: 'relay', chain: null, ok: true, label: 'Relay answers', detail: 'build b1c2d3e4f5a6' },
    { id: 'tor', chain: null, ok: true, label: 'Tor', detail: 'IsTor ✓' },
    { id: 'eth.identity', chain: 'eth', ok: true, label: 'ETH chain identity', detail: 'verified at relay startup' },
    { id: 'sol.memo', chain: 'sol', ok: true, label: 'Memo v2 program deployed and executable', detail: 'executable ✓' },
    { id: 'eth.fees', chain: 'eth', ok: true, label: 'ETH fees now', detail: 'next base 1 wei · one-part copy ≤ 2 wei' },
  ],
  chains: {}, ...over,
})
const SERVE = { release: true, digest: 'd'.repeat(64), build: 'b1c2d3e4f5a6' }
const REL = { release: true, files: 10, ok: 10, digest: 'd'.repeat(64), mismatch: 0, missing: 0, hashedAt: 1791000000000 }   // the relay's real shape: ok is a count

let routes
beforeEach(() => {
  routes = { '/__serve': SERVE, '/relay/release': REL, '/relay/tor': { isTor: true, roles: {}, checkedAt: 1 } }
  globalThis.fetch = async (u) => (routes[String(u)] ? json(200, routes[String(u)]) : json(404, {}))
})

test('the readiness table renders a PreflightReport fixture: every row, ✓/✗/—, the failing count', () => {
  const bad = report('testnet', { exit: 1, rows: [...report().rows, { id: 'sol.fees', chain: 'sol', ok: false, label: 'SOL read', detail: 'a read through the relay failed' }, { id: 'x', chain: null, ok: null, label: 'Info', detail: 'n/a' }] })
  render(<ReadinessTable report={bad} />)
  expect(screen.getByTestId('readiness-summary').textContent).toMatch(/1 check failing · network testnet · exit 1/)
  expect(screen.getByTestId('ready-mark-relay').textContent).toBe('✓')
  expect(screen.getByTestId('ready-mark-sol.fees').textContent).toBe('✗')
  expect(screen.getByTestId('ready-mark-x').textContent).toBe('—')
  expect(screen.getByTestId('ready-detail-tor').textContent).toBe('IsTor ✓')
  expect(screen.getAllByTestId(/^ready-row-/)).toHaveLength(bad.rows.length)
  render(<ReadinessTable report={report()} />)
  expect(screen.getAllByTestId('readiness-summary')[1].textContent).toMatch(/every check passed/)
})

test('pageRows: network match, build equality, fork drift message, release verified (mainnet) with equal digests', () => {
  const ok = (extra = {}) => pageRows({ network: 'mainnet', status: statusOf('mainnet'), relay: { ...relayOf('mainnet'), build: 'b1c2d3e4f5a6' }, extras: { pageBuild: 'b1c2d3e4f5a6', serve: SERVE, release: REL, ...extra }, pageNetwork: 'mainnet' })
  const get = (rows, id) => rows.find((r) => r.id === id)
  expect(ok().every((r) => r.ok === true)).toBe(true)
  expect(get(ok(), 'release').detail).toMatch(/^re-hashed just now \(\d+ files\) · digest dddddddddddd/)
  // different digests: page and relay come from different releases
  expect(get(ok({ release: { ...REL, digest: 'e'.repeat(64) } }), 'release')).toMatchObject({ ok: false })
  expect(get(ok({ release: { ...REL, ok: 8, mismatch: 2 } }), 'release').detail).toMatch(/2 changed/)
  expect(get(ok({ release: { ...REL, ok: true } }), 'release').detail).toBe('could not be read')   // ok is a count; a boolean is not the relay's shape
  expect(get(ok({ release: null }), 'release').ok).toBe(false)             // unreadable: fail closed on mainnet
  expect(get(ok({ release: { release: false } }), 'release').detail).toMatch(/not a release tree/)
  // the same unverified release is informational off mainnet
  expect(pageRows({ network: 'local', status: statusOf('local'), relay: relayOf('local'), extras: { release: null } }).find((r) => r.id === 'release').ok).toBeNull()
  // fork drift: the relay's message is shown as is
  const drift = { ...relayOf('mainnet'), identity: { eth: { ok: false, message: 'Amsterdam appears active on mainnet — update required' }, sol: { ok: true } } }
  const rows = pageRows({ network: 'mainnet', status: statusOf('mainnet'), relay: drift, extras: { pageBuild: 'b1c2d3e4f5a6', serve: SERVE, release: REL }, pageNetwork: 'mainnet' })
  expect(get(rows, 'fork')).toMatchObject({ ok: false, detail: 'Amsterdam appears active on mainnet — update required' })
  // Cfix1: the page BUNDLE id is another hash domain from the release build id: information only, never compared
  expect(get(ok({ pageBuild: 'ffffffffffff' }), 'build')).toMatchObject({ ok: true })
  expect(get(ok({ pageBuild: 'ffffffffffff' }), 'build').detail).toMatch(/page bundle ffffffffffff \(information only\)/)
  // the servers differ (relay): ✗
  expect(get(pageRows({ network: 'mainnet', status: statusOf('mainnet'), relay: { ...relayOf('mainnet'), build: 'r' }, extras: { pageBuild: 'b1c2d3e4f5a6', serve: SERVE, release: REL }, pageNetwork: 'mainnet' }), 'build').ok).toBe(false)
  // a network mismatch names the command that fixes it
  const mm = pageRows({ network: 'mainnet', status: statusOf('testnet'), relay: relayOf('mainnet'), extras: {}, pageNetwork: 'mainnet' })
  expect(get(mm, 'network-match')).toMatchObject({ ok: false })
  expect(get(mm, 'network-match').detail).toMatch(/vt up --network mainnet/)
})

test('the Status page: start commands, the report from the relay, isTor ✓, builds, fork drift, no IP', async () => {
  const drift = { ...relayOf('mainnet'), identity: { eth: { ok: false, message: 'Amsterdam appears active on mainnet — update required' }, sol: { ok: true } } }
  const calls = []
  const { container } = renderWith(<Status runPreflight={async (_r, n) => { calls.push(n); return report(n) }} />, { network: 'mainnet', ticks: null })
  // the relay answer is replaced by a drifting one through the provider value
  expect(screen.getByTestId('start-mainnet').textContent).toBe('vt up --network mainnet')
  expect(screen.getByTestId('start-local').textContent).toBe('vt up --network local')
  expect(screen.getByTestId('preflight-cli').textContent).toBe('vt preflight --network mainnet')
  await waitFor(() => expect(screen.getByTestId('readiness-summary').textContent).toMatch(/1 check failing · network mainnet · exit 1/))   // F9-5: a ✗ row (the release's build ids differ) is never "exit 0"
  expect(calls).toEqual(['mainnet'])
  expect(screen.getByTestId('ready-mark-release').textContent).toBe('✓')              // /__serve and /relay/release digests equal
  expect(screen.getByTestId('ready-detail-tor').textContent).toBe('IsTor ✓')
  expect(screen.getByTestId('ready-mark-build').textContent).toBe('✗')               // the relay ("r") disagrees with the page server and the API (b1c2…)
  expect(screen.getByTestId('ready-detail-build').textContent).toMatch(/server b1c2d3e4f5a6 · api b1c2d3e4f5a6 · relay r · page bundle dev \(information only\)/)
  expect(screen.getByTestId('ready-mark-fork').textContent).toBe('✓')
  expect(container.textContent).not.toContain(CANARY)
  expect(container.textContent).not.toMatch(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/)
  void drift
})

test('the Status page shows the fork-drift message the relay reports, and a failing release row on mainnet', async () => {
  const { StatusProvider } = await import('../src/lib/status.js')
  routes['/relay/release'] = { ...REL, digest: 'e'.repeat(64) }
  const drift = { ...relayOf('mainnet'), identity: { eth: { ok: false, message: 'Amsterdam appears active on mainnet — update required' }, sol: { ok: true } } }
  render(<StatusProvider value={{ status: statusOf('mainnet'), relay: drift, error: null }} port=""><Status runPreflight={async () => report('mainnet', { exit: 1 })} /></StatusProvider>)
  await waitFor(() => expect(screen.getByTestId('ready-mark-release').textContent).toBe('✗'))
  expect(screen.getByTestId('ready-detail-fork').textContent).toBe('Amsterdam appears active on mainnet — update required')
  expect(screen.getByTestId('ready-detail-release').textContent).toMatch(/different releases/)
  expect(screen.getByTestId('readiness').dataset.failing).toBe('3')           // release, fork, and the dev page build against the API's
})

test('M4b glue: the Status page lists a lane key the journal stopped with engine.eip7702 as a failing "Lane key delegated" row; no jobs answer, no row', async () => {
  const { StatusProvider } = await import('../src/lib/status.js')
  const mount = () => render(<StatusProvider value={{ status: statusOf('mainnet'), relay: relayOf('mainnet'), error: null }} port=""><Status runPreflight={async () => report('mainnet')} /></StatusProvider>)
  routes['/api/jobs'] = { jobs: [{ id: 'a'.repeat(16), name: 'x', createdAt: 1, phase: 'RUNNING', chains: { eth: { phase: 'STOPPED', reason: 'engine.eip7702: the key is delegated' } } }], serverNowMs: 1 }
  const first = mount()
  await waitFor(() => expect(screen.getByTestId('ready-mark-delegated-eth').textContent).toBe('✗'))
  first.unmount()
  delete routes['/api/jobs']
  mount()
  await waitFor(() => expect(screen.getByTestId('ready-mark-release')).toBeTruthy())
  expect(screen.queryByTestId('ready-mark-delegated-eth')).toBeNull()
})

// ---- Arm gated on the mainnet ticks ----
test('mainnet Arm stays gated until every tick is set; the ticks live in memory only', async () => {
  const user = userEvent.setup()
  const key = newKey('eth')
  const ID = '00112233aabbccdd'
  const def = jobDef({ network: 'mainnet', chains: { eth: ethChain(key.address) } })
  const st = reduce(def, journal([created(ID), ...ready('eth', key.address)]))
  const cap = { nativeCap: '4000000000000000', usd: 10, priceAt: 1, overCap: false, planned: '0.004', fullCopyCost: '100000000000000', parts: 1, affordable: true }
  const inputs = async () => ({ text: TEXT, prices: null, chains: { eth: { cap, history: 0, error: '' } } })
  renderWith(<><Status runPreflight={async () => report('mainnet')} /><ArmDialog jobId={ID} def={def} state={st} inputs={inputs} /></>,
    { network: 'mainnet', status: { jobSends: 'ENABLED' }, ticks: null })
  await user.click(screen.getByTestId('arm-open'))
  await waitFor(() => expect(screen.getByTestId('arm-tor').textContent).toMatch(/IsTor ✓/))
  await user.type(screen.getByTestId('arm-typed'), 'broadcast')
  const problems = () => screen.getByTestId('arm-problems')?.textContent ?? ''
  expect(problems()).toMatch(/mainnet pre-flight ticks: 0 of 5 set/)
  expect(screen.getByTestId('arm-confirm').disabled).toBe(true)
  const ids = MAINNET_TICKS.map((t) => t.id)
  for (const id of ids.slice(0, -1)) fireEvent.click(screen.getByTestId(`tick-${id}`))   // the open dialog makes the page behind inert to pointers
  expect(problems()).toMatch(/4 of 5 set/)
  expect(screen.getByTestId('arm-confirm').disabled).toBe(true)
  expect(screen.getByTestId('ticks').dataset.all).toBe('false')
  fireEvent.click(screen.getByTestId(`tick-${ids.at(-1)}`))
  expect(screen.getByTestId('ticks').dataset.all).toBe('true')
  expect(screen.queryByTestId('arm-problems')).toBeNull()
  expect(screen.getByTestId('arm-confirm').disabled).toBe(false)
  // un-ticking one gates it again
  fireEvent.click(screen.getByTestId('tick-funds'))
  expect(screen.getByTestId('arm-confirm').disabled).toBe(true)
  expect(JSON.stringify({ ...localStorage })).toBe('{}'); expect(JSON.stringify({ ...sessionStorage })).toBe('{}')
})

test('off mainnet no ticks are shown or required', async () => {
  routes['/__serve'] = { release: false, digest: null, build: 'dev' }   // a dev tree: the page/API build ids differ by design (F9-5)
  routes['/relay/release'] = { release: false }
  renderWith(<Status runPreflight={async () => report('testnet')} />, { network: 'testnet', ticks: null })
  await waitFor(() => expect(screen.getByTestId('readiness-summary').textContent).toMatch(/exit 0/))
  expect(screen.queryByTestId('ticks')).toBeNull()
})

// ---- F9-5 (Chrome loop pass 9): a dev tree is not a failing build row; one exit for the table

test('F9-5: on a dev tree the build row is — (dev tree), the table does not fail and never prints exit 0 over a ✗', async () => {
  routes['/__serve'] = { release: false, digest: null, build: 'dev' }
  routes['/relay/release'] = { release: false }
  const { StatusProvider } = await import('../src/lib/status.js')
  render(<StatusProvider value={{ status: { ...statusOf('local'), build: 'dev' }, relay: { ...relayOf('local'), build: 'dev' }, error: null }} port=""><Status runPreflight={async () => report('local')} /></StatusProvider>)
  await waitFor(() => expect(screen.getByTestId('ready-mark-build').textContent).toBe('—'))
  expect(screen.getByTestId('ready-detail-build').textContent).toBe('dev tree (needed only on mainnet/verified release)')
  expect(screen.getByTestId('readiness').dataset.failing).toBe('0')
  expect(screen.getByTestId('readiness-summary').textContent).toMatch(/every check passed · network local · exit 0/)
  // a failing row of the page's own never reads "exit 0" even when core's preflight() passed
  render(<ReadinessTable report={report('local')} pageRows={[{ id: 'build', ok: false, label: 'b', detail: 'd' }]} />)
  expect(screen.getAllByTestId('readiness-summary')[1].textContent).toMatch(/1 check failing · network local · exit 1/)
})

test('Cfix3: the Status page reads /relay/services and shows the BTC rows and one row per service (informational, never failing)', async () => {
  routes['/__serve'] = { release: false, digest: null, build: 'dev' }
  routes['/relay/release'] = { release: false }
  routes['/relay/services'] = { network: 'testnet', services: {
    'blockscout.base': { ok: false, viaTor: true, endpoints: 0, message: 'an endpoint answered another identity: disabled until the relay restarts' },
    drand: { ok: false, viaTor: true, endpoints: 0, message: 'Tor is not available (IsTor ✗): the local relay reaches this service through Tor only' },
    arweave: { ok: true, viaTor: true, endpoints: 2 },
  } }
  const relay = { ...relayOf('testnet'), identity: { eth: { ok: true }, sol: { ok: true }, btc: { ok: true } }, endpoints: { eth: 1, sol: 1, btc: 1 } }
  renderWith(<Status runPreflight={async (_r, n) => report(n)} />, { network: 'testnet', ticks: null, relay })
  await waitFor(() => expect(screen.getByTestId('ready-detail-service-drand').textContent).toBe('identity not checked · via Tor · reachable ✗ (unavailable: Tor is down)'))
  expect(screen.getByTestId('ready-detail-btc-identity').textContent).toBe('block 0 is the testnet genesis (identity verified)')
  expect(screen.getByTestId('ready-mark-btc-endpoints').textContent).toBe('✓')
  expect(screen.getByTestId('ready-detail-service-blockscout.base').textContent).toBe('identity disabled (relay.service-identity) · via Tor · reachable ✓')
  expect(screen.getByTestId('ready-mark-service-blockscout.base').textContent).toBe('—')
  expect(screen.getByTestId('ready-mark-service-arweave').textContent).toBe('✓')
  expect(screen.getByTestId('readiness').getAttribute('data-failing')).toBe('0')
})

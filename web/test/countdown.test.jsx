// The countdown (W3): the API's clock, never the local wall clock; Skip only with IsTor ✓ and a fresh passing
// simulation of every armed chain (here: a real core executor reaching its countdown against a synthetic relay).
import { test, expect, vi, afterEach } from 'vitest'
import { render, screen, act, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ethDataGas } from '@vault-timelock/core/contracts'
import Countdown, { remainingOf } from '../src/jobs/Countdown.jsx'
import JobView, { armSummary } from '../src/jobs/JobView.jsx'
import { createServerClock } from '../src/lib/serverClock.js'
import { newKey } from '../src/lib/core.js'
import { json, renderWith } from './helpers.jsx'
import { created, ethChain, fakeStack, jobDef, journal, ready } from './job-fakes.js'

afterEach(() => vi.useRealTimers())

test('server clock: null before the first sync; monotonic between syncs; a re-sync replaces the offset', () => {
  let perf = 1000
  const c = createServerClock({ perf: () => perf })
  expect(c.now()).toBeNull()
  expect(c.synced()).toBe(false)
  c.sync(5_000_000)
  expect(c.now()).toBe(5_000_000)
  perf += 2500
  expect(c.now()).toBe(5_002_500)
  c.sync(9_000_000)
  expect(c.now()).toBe(9_000_000)
  c.sync(Number.NaN)                                       // a bad answer changes nothing
  expect(c.now()).toBe(9_000_000)
  expect(remainingOf(9_010_000, c.now)).toBe(10)
  expect(remainingOf(1, () => null)).toBeNull()
})

test('the countdown never completes before the first server sync, follows the API clock, and jumps on a clock skip', () => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'setTimeout', 'clearTimeout', 'Date'] })
  let perf = 0
  const clock = createServerClock({ perf: () => perf })
  const done = vi.fn()
  const T = 2_000_000_000_000                             // the release, server time
  const tick = (ms) => act(() => { perf += ms; vi.advanceTimersByTime(ms) })
  render(<Countdown target={T} total={60} label="Release in" now={clock.now} onComplete={done} tickMs={100} />)
  const el = screen.getByTestId('countdown')
  // no sync yet: the local clock is far past the target, still nothing completes
  vi.setSystemTime(T + 3_600_000)
  tick(5000)
  expect(el.dataset.synced).toBe('false')
  expect(el.dataset.remaining).toBe('')
  expect(screen.getByTestId('countdown-text').textContent).toMatch(/syncing with the API clock/)
  expect(done).not.toHaveBeenCalled()
  // the first sync: 30 s left by the API
  act(() => clock.sync(T - 30_000))
  tick(100)
  expect(el.dataset.synced).toBe('true')
  expect(el.dataset.remaining).toBe('30')
  tick(10_000)
  expect(el.dataset.remaining).toBe('20')
  // the LOCAL wall clock jumps an hour back: nothing moves (the elapsed time is monotonic)
  vi.setSystemTime(T - 3_600_000)
  tick(100)
  expect(el.dataset.remaining).toBe('20')
  // a re-sync where the API says 5 s are left: the countdown jumps to it
  act(() => clock.sync(T - 5_000))
  tick(100)
  expect(el.dataset.remaining).toBe('5')
  expect(done).not.toHaveBeenCalled()
  // Skip: the API moved the release to its own now — the countdown jumps to zero and completes once
  render(<Countdown target={clock.now()} total={60} label="Skipped" now={clock.now} onComplete={done} tickMs={100} testid="countdown-skip" />)
  tick(100)
  expect(screen.getByTestId('countdown-skip').dataset.done).toBe('true')
  expect(done).toHaveBeenCalledTimes(1)
  tick(1000)
  expect(done).toHaveBeenCalledTimes(1)
})

test('armSummary words the arm record’s own countdown and stagger (L2-1), not the mainnet constants', () => {
  expect(armSummary({ countdownSec: 10, schedule: { order: ['sol', 'eth'], offsetSec: { sol: 0, eth: 7 } } }))
    .toBe('Countdown 0:10 from arm (this job’s arm record), then Solana at release, Ethereum +7 s.')
})

// ---- Skip through the real executor ----
const ID = 'fedcba9876543210'
const ethKey = newKey('eth')
const hex = (n) => '0x' + BigInt(n).toString(16)
function relayEth({ body }) {
  const { method, params, id } = body
  const r = (result) => json(200, { jsonrpc: '2.0', id, result })
  if (method === 'eth_chainId') return r('0x1')
  if (method === 'eth_feeHistory') return r({ oldestBlock: '0x0', baseFeePerGas: ['0x3b9aca00', '0x3b9aca00', '0x3b9aca00'], gasUsedRatio: [0.5, 0.5], reward: [['0x1'], ['0x1']] })
  if (method === 'eth_getBalance') return r(hex(10n ** 18n))
  if (method === 'eth_getTransactionCount') return r('0x0')
  if (method === 'eth_estimateGas') return r(hex(ethDataGas((params[0].data.length - 2) / 2, { amsterdam: false, toSelf: false })))
  if (method === 'eth_call') return r('0x')
  return json(200, { jsonrpc: '2.0', id, error: { code: -32601, message: `no fake for ${method}` } })
}
function armedMainnet(serverNow) {
  const def = jobDef({ network: 'mainnet', chains: { eth: ethChain(ethKey.address) } })
  const armed = { armedAt: serverNow, releaseAt: serverNow + 60_000, countdownSec: 60, schedule: { order: ['eth'], offsetSec: { eth: 0 } }, caps: { eth: { nativeCap: '4000000000000000', usd: 10, priceAt: serverNow, overCap: false, planned: '0.004' } }, sources: {} }
  return { def, events: journal([created(ID), ...ready('eth', ethKey.address), { type: 'armed', data: armed }]) }
}
function stackFor(tor) {
  const now = Date.now()
  const { def, events } = armedMainnet(now)
  const grant = () => json(200, { gen: 1, ttlMs: 15000, expiresAt: Date.now() + 15000, holder: 'browser', openIntents: [] })
  return fakeStack({ id: ID, def, events, tor, routes: {
    [`POST /api/jobs/${ID}/chains/eth/lease`]: ({ body }) => (body.op === 'release' ? json(200, {}) : grant()),
    [`POST /api/jobs/${ID}/chains/eth/events`]: ({ s }) => json(200, { seq: s.events.length }),
    [`POST /api/jobs/${ID}/skip`]: () => json(200, { releaseAt: Date.now() }),
    'POST /relay/eth': relayEth,
  } })
}

test('mainnet: Skip waits for a fresh passing simulation in this tab and IsTor ✓, then asks the executor (which re-checks)', async () => {
  const user = userEvent.setup()
  const st = stackFor(true)
  globalThis.fetch = st.fetch
  renderWith(<JobView id={ID} jobOptions={{ pollMs: 300, flushMs: 10 }} />, { network: 'mainnet', seed: [['eth', ethKey]] })
  const skip = await screen.findByTestId('skip')
  expect(skip.disabled).toBe(true)                                          // nothing runs here: no simulation
  await waitFor(() => expect(screen.getByTestId('skip-why').textContent).toMatch(/fresh passing simulation/))   // once IsTor ✓ is known
  expect(skip.disabled).toBe(true)
  expect(screen.getByTestId('countdown').dataset.synced).toBe('true')
  expect(Number(screen.getByTestId('countdown').dataset.remaining)).toBeGreaterThan(50)
  await user.click(screen.getByTestId('run-eth'))
  await waitFor(() => expect(screen.getByTestId('skip').disabled).toBe(false), { timeout: 8000 })
  expect(screen.getByTestId('run-state-eth').textContent).toMatch(/countdown/)
  await user.click(screen.getByTestId('skip'))
  await waitFor(() => expect(st.calls.filter((c) => c.method === 'POST' && c.url.endsWith('/skip'))).toHaveLength(1))
  // the real-byte simulation ran through the relay before Skip was offered
  const methods = st.calls.filter((c) => c.url === '/relay/eth').map((c) => c.body.method)
  expect(methods).toContain('eth_estimateGas')
  expect(methods).toContain('eth_call')
  await user.click(screen.getByTestId('stop-eth'))
  await waitFor(() => expect(screen.getByTestId('run-state-eth').dataset.status).toBe('ended'), { timeout: 8000 })
}, 20_000)

test('Skip stays disabled when tor() is false, even with a fresh simulation', async () => {
  const user = userEvent.setup()
  const st = stackFor(false)
  globalThis.fetch = st.fetch
  renderWith(<JobView id={ID} jobOptions={{ pollMs: 300, flushMs: 10 }} />, { network: 'mainnet', seed: [['eth', ethKey]] })
  await user.click(await screen.findByTestId('run-eth'))
  await waitFor(() => expect(screen.getByTestId('run-state-eth').textContent).toMatch(/simulation ✓/), { timeout: 8000 })
  await waitFor(() => expect(screen.getByTestId('skip-why').textContent).toMatch(/IsTor is not ✓/))
  expect(screen.getByTestId('skip').disabled).toBe(true)
  expect(st.calls.filter((c) => c.url.endsWith('/skip'))).toHaveLength(0)
  await user.click(screen.getByTestId('stop-eth'))
  await waitFor(() => expect(screen.getByTestId('run-state-eth').dataset.status).toBe('ended'), { timeout: 8000 })
}, 20_000)

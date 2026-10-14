// Run here (W3): the browser executor wired into the job page, against a synthetic same-origin API and relay.
import { test, expect, beforeEach, afterEach } from 'vitest'
import { screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import JobView from '../src/jobs/JobView.jsx'
import { windowNoteOf } from '@vault-timelock/core/engine/lane.js'
import { pageDeps } from '../src/jobs/RunHere.js'
import { newKey } from '../src/lib/core.js'
import { lastBusy, renderWith, json } from './helpers.jsx'
import { append, created, ethChain, fakeStack, fixture, jobDef, journal, ready } from './job-fakes.js'

const ID = '0123456789abcdef'
const ethKey = newKey('eth')
const FAST = { pollMs: 200, flushMs: 10 }
let stack
const install = (st) => { stack = st; globalThis.fetch = st.fetch }
beforeEach(() => { stack = null })
afterEach(() => { document.title = '' })

const posts = (re) => stack.calls.filter((c) => c.method === 'POST' && re.test(c.url))

test('a lease.held reply shows "running in cli": the page watches, Run here stays off', async () => {
  const user = userEvent.setup()
  const def = jobDef({ chains: { eth: ethChain(ethKey.address) } })
  install(fakeStack({ id: ID, def, events: journal([created(ID)]), leases: { eth: null }, routes: {
    [`POST /api/jobs/${ID}/chains/eth/lease`]: ({ s }) => {
      s.leases = { eth: { holder: 'cli', gen: 2, expiresAt: Date.now() + 60_000 } }       // the CLI took it first
      return json(409, { error: { guard: 'lease.held', message: 'another executor holds this lease' } })
    },
  } }))
  renderWith(<JobView id={ID} jobOptions={FAST} />, { seed: [['eth', ethKey]] })
  const run = await screen.findByTestId('run-eth')
  expect(run.disabled).toBe(false)
  expect(run.textContent).toBe('Run here')
  await user.click(run)
  await waitFor(() => expect(screen.getByTestId('holder-eth').textContent).toMatch(/running in cli/))
  expect(screen.getByTestId('holder-eth').dataset.holder).toBe('cli')
  expect(screen.getByTestId('run-error-eth').textContent).toMatch(/lease\.held: running in cli/)
  expect(screen.getByTestId('watching-eth').textContent).toMatch(/vt job run holds the lease/)
  expect(screen.getByTestId('run-eth').disabled).toBe(true)
  // the executor checked the network and the key BEFORE asking for the lease, and sent nothing else
  const order = stack.calls.map((c) => `${c.method} ${c.url.replace(/\?.*/, '')}`)
  expect(order.indexOf('GET /api/status')).toBeLessThan(order.indexOf(`POST /api/jobs/${ID}/chains/eth/lease`))
  expect(order.indexOf('GET /relay/status')).toBeLessThan(order.indexOf(`POST /api/jobs/${ID}/chains/eth/lease`))
  expect(posts(/\/events$/)).toHaveLength(0)
  expect(posts(/\/lease$/)[0].body).toEqual({ op: 'acquire', holder: 'browser' })
})

test('a browser lease after this tab\'s own run ended is not claimed to be another tab\'s (the lease names only "browser")', async () => {
  const user = userEvent.setup()
  const def = jobDef({ chains: { eth: ethChain(ethKey.address) } })
  install(fakeStack({ id: ID, def, events: journal([created(ID)]), leases: { eth: null }, routes: {
    [`POST /api/jobs/${ID}/chains/eth/lease`]: ({ s }) => {
      s.leases = { eth: { holder: 'browser', gen: 1, expiresAt: Date.now() + 15_000 } }
      return json(409, { error: { guard: 'lease.held', message: 'held' } })
    },
  } }))
  renderWith(<JobView id={ID} jobOptions={FAST} />, { seed: [['eth', ethKey]] })
  expect(screen.queryByTestId('holder-eth')?.textContent ?? '').not.toMatch(/another tab/)
  await user.click(await screen.findByTestId('run-eth'))
  await waitFor(() => expect(screen.getByTestId('holder-eth').textContent).toMatch(/a browser tab holds this chain \(this one/))
  expect(screen.getByTestId('holder-eth').textContent).toMatch(/the lease lapses in a few seconds unless another tab renews it\)/)   // M4f glue (d): the lease cannot tell this tab from another
  expect(screen.getByTestId('holder-eth').textContent).not.toMatch(/running in another tab/)
  expect(screen.getByTestId('watching-eth').textContent).toMatch(/this one, just ended, or another/)
})

test('useTabBusy is set while the executor runs, and cleared when it ends', async () => {
  const user = userEvent.setup()
  const def = jobDef({ chains: { eth: ethChain(ethKey.address) } })
  let release
  const st = fakeStack({ id: ID, def, events: journal([created(ID)]), routes: {
    [`POST /api/jobs/${ID}/chains/eth/lease`]: () => new Promise((r) => { release = () => r(json(409, { error: { guard: 'lease.held', message: 'held' } })) }),
  } })
  install(st)
  renderWith(<JobView id={ID} jobOptions={FAST} />, { seed: [['eth', ethKey]] })
  await waitFor(() => expect(lastBusy().reason).toMatch(/Ethereum key loaded/))
  expect(lastBusy().reason).not.toMatch(/run in this tab/)
  await user.click(await screen.findByTestId('run-eth'))
  await waitFor(() => expect(release).toBeTypeOf('function'))
  expect(lastBusy().busy).toBe(true)
  expect(lastBusy().reason).toMatch(/Ethereum run in this tab/)
  expect(screen.getByTestId('run-state-eth').dataset.status).toBe('running')
  expect(screen.getByTestId('keep-visible')).toBeTruthy()
  expect(screen.getByTestId('keeptab-eth')).toBeTruthy()
  // MQ M1: hidden while running → the title says so
  Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true })
  act(() => { document.dispatchEvent(new Event('visibilitychange')) })
  expect(document.title).toBe('[LOCAL] ⚠ KEEP THIS TAB VISIBLE')
  Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true })
  act(() => { document.dispatchEvent(new Event('visibilitychange')) })
  expect(document.title).toBe('[LOCAL] vt')
  await act(async () => { release() })
  await waitFor(() => expect(screen.getByTestId('run-state-eth').dataset.status).toBe('ended'))
  expect(lastBusy().reason).not.toMatch(/run in this tab/)
})

test('Run here needs this job’s key: another key shows the mismatch and never starts an executor', async () => {
  const other = newKey('eth')
  const def = jobDef({ chains: { eth: ethChain(ethKey.address) } })
  install(fakeStack({ id: ID, def, events: journal([created(ID)]) }))
  renderWith(<JobView id={ID} jobOptions={FAST} />, { seed: [['eth', other]] })
  expect((await screen.findByTestId('key-mismatch-eth')).textContent).toContain(ethKey.address)
  expect(screen.getByTestId('run-eth').disabled).toBe(true)
  expect(stack.calls.filter((c) => /lease/.test(c.url))).toHaveLength(0)
})

test('after a reload nothing runs: the state comes from the API, the key must be imported, Run here resumes at the next part', async () => {
  const { def, events, id } = fixture('13-resume-part')
  install(fakeStack({ id, def, events: events.slice(0, 40) }))          // copy 2 parts 1–3 landed; nobody holds the lease
  renderWith(<JobView id={id} jobOptions={FAST} />)
  await waitFor(() => expect(screen.getByTestId('phase-sol').dataset.phase).toBe('RUNNING'))
  expect(screen.getByTestId('keylane-sol')).toBeTruthy()                 // import the key again (only Import is offered)
  expect(screen.queryByTestId('keychoice-sol-new')).toBeNull()
  expect(screen.getByTestId('keychoice-sol-import')).toBeTruthy()
  const run = screen.getByTestId('run-sol')
  expect(run.textContent).toBe('Resume copy 2 at part 4')
  expect(run.disabled).toBe(true)
  expect(screen.getByTestId('landed-sol').textContent).toMatch(/Interrupted in copy 2: parts 1–3 of 5 landed \(not landed: 4–5\)/)
  expect(screen.getByTestId('landed-sol').textContent).toMatch(/continues at the next part/)
  expect(screen.getByTestId('progress-sol').dataset.done).toBe('8')
  expect(screen.getByTestId('progress-sol').dataset.total).toBe('10')
  expect(screen.getByTestId('reasm-sol-1').dataset.ok).toBe('true')
  await waitFor(() => expect(screen.getByTestId('reasm-sol-1').textContent).toMatch(/reassembled ✓ sha256 49886435/))   // the sha256 comes with the journal stream
  expect(screen.getByTestId('reasm-sol-2').textContent).toBe('copy 2: 3/5 parts')
})

test('a CLI-run job is watched live: the SSE journal moves the parts, Stop reaches the API, the stop shows which parts landed', async () => {
  const user = userEvent.setup()
  const { def, events, id } = fixture('13-resume-part')
  const lines = events.slice(0, 28).map((e) => (e.type === 'lease-acquired' ? { ...e, data: { ...e.data, holder: 'cli' } } : e))
  install(fakeStack({ id, def, events: lines, leases: { sol: { holder: 'cli', gen: 1, expiresAt: Date.now() + 60_000 } } }))
  renderWith(<JobView id={id} jobOptions={FAST} />)
  await waitFor(() => expect(screen.getByTestId('holder-sol').textContent).toMatch(/running in cli/))
  expect(screen.getByTestId('run-sol').disabled).toBe(true)
  expect(screen.queryByTestId('keylane-sol')).toBeNull()                 // nothing to import while the CLI runs it
  await waitFor(() => expect(screen.getByTestId('progress-sol').dataset.done).toBe('5'))
  // the CLI lands copy 2 parts 1 and 2: the page follows the journal
  for (const e of events.slice(28, 36)) append(stack, e)
  await waitFor(() => expect(screen.getByTestId('progress-sol').dataset.done).toBe('7'))
  expect(screen.getAllByTestId('part-row-sol').filter((r) => r.dataset.copy === '2' && r.dataset.state === 'included')).toHaveLength(2)
  // Stop from the page while the CLI runs: the API's stop (the CLI executor follows it)
  await user.click(screen.getByTestId('stop-sol'))
  await waitFor(() => expect(posts(/\/stop$/)).toHaveLength(1))
  expect(posts(/\/stop$/)[0].body).toEqual({ chain: 'sol' })
  append(stack, { chain: null, type: 'stop-requested', data: { chain: 'sol' } })
  await waitFor(() => expect(screen.getByTestId('phase-sol').textContent).toMatch(/stop requested/))
  expect(screen.queryByTestId('stop-sol')).toBeNull()
  // the CLI's executor stops after its in-flight part and releases the lease
  append(stack, { chain: 'sol', by: 'cli', gen: 1, type: 'stopped', data: { reason: 'stopped by the operator' } })
  append(stack, { chain: 'sol', type: 'lease-released', gen: 1, data: { gen: 1 } })
  stack.s.leases = { sol: null }
  await waitFor(() => expect(screen.getByTestId('phase-sol').dataset.phase).toBe('STOPPED'))
  await waitFor(() => expect(screen.getByTestId('landed-sol').textContent).toMatch(/Stopped in copy 2: parts 1–2 of 5 landed \(not landed: 3–5\)/))
  expect(screen.getByTestId('landed-sol').textContent).toMatch(/never sent again/)
  expect(screen.queryByTestId('run-sol')).toBeNull()                      // settled: no Run here on a STOPPED chain
})

test('Stop of this tab’s run: the executor is asked and the API journals the stop; a pending stop can be cancelled', async () => {
  const user = userEvent.setup()
  const def = jobDef({ chains: { eth: ethChain(ethKey.address) } })
  const lines = journal([created(ID), ...ready('eth', ethKey.address), { chain: null, type: 'armed', data: { armedAt: 1, releaseAt: 2, countdownSec: 5, schedule: { order: ['eth'], offsetSec: { eth: 0 } }, caps: { eth: { nativeCap: '4000000000000000', usd: 10, priceAt: null, overCap: false, planned: '0.004' } }, sources: {} } }])
  let hold
  install(fakeStack({ id: ID, def, events: lines, routes: {
    [`POST /api/jobs/${ID}/chains/eth/lease`]: () => new Promise((r) => { hold = r }),
  } }))
  renderWith(<JobView id={ID} jobOptions={FAST} />, { seed: [['eth', ethKey]] })
  await user.click(await screen.findByTestId('run-eth'))
  await waitFor(() => expect(hold).toBeTypeOf('function'))
  await user.click(screen.getByTestId('stop-eth'))
  await waitFor(() => expect(posts(/\/stop$/)).toHaveLength(1))
  append(stack, { chain: null, type: 'stop-requested', data: { chain: 'eth' } })
  const cancel = await screen.findByTestId('resume-eth')
  expect(cancel.textContent).toBe('Cancel the stop')
  await user.click(cancel)
  await waitFor(() => expect(posts(/\/resume$/)).toHaveLength(1))
  expect(posts(/\/resume$/)[0].body).toEqual({ chain: 'eth' })
  await act(async () => { hold(json(409, { error: { guard: 'lease.held', message: 'held' } })) })
})

// W7 / F10-1: the running lane's status line shows the progress note core adds (windowNoteOf) while the passive window is
// truncated, and nothing for a full window. The executor holds at the lease request; the test feeds its onView.
test('the running lane status shows "(window N blocks, RPC limit)" from the executor view note; a full window shows nothing', async () => {
  const user = userEvent.setup()
  const def = jobDef({ chains: { eth: ethChain(ethKey.address, { feeStrategy: 'passive' }) } })
  let onView
  install(fakeStack({ id: ID, def, events: journal([created(ID)]), routes: { [`POST /api/jobs/${ID}/chains/eth/lease`]: () => new Promise(() => {}) } }))
  renderWith(<JobView id={ID} jobOptions={FAST} />, { seed: [['eth', ethKey]], deps: (extra) => { onView = extra.onView; return pageDeps(extra) } })
  await user.click(await screen.findByTestId('run-eth'))
  await waitFor(() => expect(onView).toBeTypeOf('function'))
  act(() => { onView({ phase: 'running', copy: 1, part: 1, parts: 1, note: `tx pending ${windowNoteOf(1024)}` }) })
  expect(screen.getByTestId('run-state-eth').textContent).toMatch(/running · copy 1 part 1\/1 · tx pending \(window 1024 blocks, RPC limit\)/)
  act(() => { onView({ phase: 'running', copy: 1, part: 1, parts: 1, note: 'tx pending' }) })
  expect(screen.getByTestId('run-state-eth').textContent).toMatch(/tx pending/)
  expect(screen.getByTestId('run-state-eth').textContent).not.toMatch(/window/)
})

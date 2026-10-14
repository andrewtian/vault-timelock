// Wresume (R79): the page resumes a stop-latched STOPPED chain (the operator resume route, like `vt job resume <id> --chain c`),
// then Run here reopens it. Resume is offered only on a latched STOPPED chain; Stop running here = detach, Stop job = every executor.
import { test, expect, beforeEach } from 'vitest'
import { screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import JobView from '../src/jobs/JobView.jsx'
import { DETACH_TIP, STOP_TIP } from '../src/jobs/ChainLane.jsx'
import { newKey } from '../src/lib/core.js'
import { renderWith, json } from './helpers.jsx'
import { reduce } from '@vault-timelock/core/job'
import { append, created, ethChain, fakeStack, fixture, jobDef, journal, ready } from './job-fakes.js'

const ID = '0123456789abcdef'
const ethKey = newKey('eth')
const FAST = { pollMs: 200, flushMs: 10 }
let stack
const install = (st) => { stack = st; globalThis.fetch = st.fetch }
beforeEach(() => { stack = null })
const posts = (re) => stack.calls.filter((c) => c.method === 'POST' && re.test(c.url))

test('a latched STOPPED chain: Resume asks first, posts the chain to the resume route, then Run here is enabled', async () => {
  const user = userEvent.setup()
  const def = jobDef({ chains: { eth: ethChain(ethKey.address) } })
  // M5c: an operator stop carries its code (R79b: resumable); a stop with no code is FINAL (fail closed) and offers no Resume
  const lines = journal([created(ID), ...ready('eth', ethKey.address), { chain: 'eth', by: 'browser', gen: 1, type: 'stopped', data: { reason: 'stopped by the operator', code: 'operator-stop' } }, { chain: 'eth', type: 'lease-released', gen: 1, data: { gen: 1 } }])
  install(fakeStack({ id: ID, def, events: lines, leases: { eth: null } }))
  renderWith(<JobView id={ID} jobOptions={FAST} />, { seed: [['eth', ethKey]] })
  await waitFor(() => expect(screen.getByTestId('phase-eth').dataset.phase).toBe('STOPPED'))
  expect(screen.queryByTestId('run-eth')).toBeNull()                      // latched: settled, no Run here
  expect(screen.queryByTestId('reopened-eth')).toBeNull()
  const resume = await screen.findByTestId('resume-latched-eth')
  expect(resume.textContent).toBe('Resume')
  await user.click(resume)
  expect(screen.getByTestId('resume-confirm-eth').textContent).toMatch(/Resume publishing on .*\? The next part of copy .* is sent after you press Run here\./)
  expect(posts(/\/resume$/)).toHaveLength(0)                              // nothing is sent before the confirmation
  await user.click(screen.getByTestId('resume-go-eth'))
  await waitFor(() => expect(posts(/\/resume$/)).toHaveLength(1))
  expect(posts(/\/resume$/)[0].body).toEqual({ chain: 'eth' })
  append(stack, { chain: null, type: 'resume-requested', data: { chain: 'eth' } })      // the API journals the operator's resume
  await waitFor(() => expect(screen.getByTestId('run-eth').disabled).toBe(false))
  expect(screen.getByTestId('run-eth').textContent).toBe('Run here')
  expect(screen.queryByTestId('resume-latched-eth')).toBeNull()
  expect(screen.queryByTestId('resume-confirm-eth')).toBeNull()
  // M5c (lane E concern 4): resumed but not yet reopened — still STOPPED until a run passes its pre-start checks; a failed check journals nothing
  expect(screen.getByTestId('reopened-eth').textContent).toMatch(/Resumed, but still STOPPED: Run here reopens it once its pre-start checks pass.*nothing was journaled and the resume still stands: fix the cause and run again/)
})

test('M5c: a FINAL stop whose latch something cleared (a journal from before R79b: no code) is settled — no Run here, no Resume; the reason and the way out are shown', async () => {
  const def = jobDef({ chains: { eth: ethChain(ethKey.address) } })
  const lines = journal([created(ID), ...ready('eth', ethKey.address), { chain: 'eth', by: 'browser', gen: 1, type: 'stopped', data: { reason: 'stopped by the operator' } }, { chain: 'eth', type: 'lease-released', gen: 1, data: { gen: 1 } }, { chain: null, type: 'resume-requested', data: { chain: 'eth' } }])
  install(fakeStack({ id: ID, def, events: lines, leases: { eth: null } }))
  renderWith(<JobView id={ID} jobOptions={FAST} />, { seed: [['eth', ethKey]] })
  await waitFor(() => expect(screen.getByTestId('phase-eth').dataset.phase).toBe('STOPPED'))
  expect(screen.getByTestId('resume-final-eth').textContent).toMatch(/This stop is final, so Resume is not offered: stopped by the operator\. The way out is to claw back the remainder or close the chain/)
  expect(screen.queryByTestId('run-eth')).toBeNull()
  expect(screen.queryByTestId('reopened-eth')).toBeNull()
  expect(screen.queryByTestId('resume-latched-eth')).toBeNull()
})

test('Cancel in the confirmation sends nothing', async () => {
  const user = userEvent.setup()
  const { def, events, id } = fixture('14-stopped')
  install(fakeStack({ id, def, events }))
  renderWith(<JobView id={id} jobOptions={FAST} />)
  await user.click(await screen.findByTestId('resume-latched-eth'))
  await user.click(screen.getByTestId('resume-cancel-eth'))
  expect(screen.queryByTestId('resume-confirm-eth')).toBeNull()
  expect(screen.getByTestId('resume-latched-eth')).toBeTruthy()
  expect(posts(/\/resume$/)).toHaveLength(0)
})

test('mainnet: Resume is still offered (it only lifts the latch)', async () => {
  const { def, events, id } = fixture('14-stopped')
  install(fakeStack({ id, def: { ...def, network: 'mainnet' }, events }))
  renderWith(<JobView id={id} jobOptions={FAST} />)
  expect(await screen.findByTestId('resume-latched-eth')).toBeTruthy()
})

test.each([
  ['04-intent', 'eth', 'RUNNING'], ['10a-paused', 'eth', 'PAUSED'], ['03-armed', 'eth', 'ARMED'], ['02-ready', 'eth', 'READY'],
  ['09a-stuck', 'eth', 'STUCK'], ['11-drained', 'eth', 'DRAINED'], ['05a-copies-done', 'eth', 'COPIES_DONE'], ['05b-closed', 'eth', 'DONE'],
  ['12-clawback', 'eth', 'CLAWED_BACK'], ['15a-skipped', 'sol', 'SKIPPED'],
])('%s (%s %s): no latched-Resume', async (name, chain, phase) => {
  const { def, events, id } = fixture(name)
  install(fakeStack({ id, def, events }))
  renderWith(<JobView id={id} jobOptions={FAST} />)
  await waitFor(() => expect(screen.getByTestId(`phase-${chain}`).dataset.phase).toBe(phase))
  expect(screen.queryByTestId(`resume-latched-${chain}`)).toBeNull()
  expect(screen.queryByTestId(`resume-confirm-${chain}`)).toBeNull()
})

test('a stop that is requested but not yet journaled offers no latched-Resume (only "Cancel the stop")', async () => {
  const { def, events, id } = fixture('04-intent')
  install(fakeStack({ id, def, events: [...events, { v: 1, seq: events.length, at: Date.now(), prev: '', chain: null, by: 'api', gen: null, type: 'stop-requested', data: { chain: 'eth' } }] }))
  renderWith(<JobView id={id} jobOptions={FAST} />)
  expect((await screen.findByTestId('resume-eth')).textContent).toBe('Cancel the stop')
  expect(screen.queryByTestId('resume-latched-eth')).toBeNull()
})

test('labels: the job-level Stop stops every executor (latched until Resume); Stop running here detaches this tab only', async () => {
  const user = userEvent.setup()
  const def = jobDef({ chains: { eth: ethChain(ethKey.address) } })
  const lines = journal([created(ID), ...ready('eth', ethKey.address), { chain: null, type: 'armed', data: { armedAt: 1, releaseAt: 2, countdownSec: 5, schedule: { order: ['eth'], offsetSec: { eth: 0 } }, caps: { eth: { nativeCap: '4000000000000000', usd: 10, priceAt: null, overCap: false, planned: '0.004' } }, sources: {} } }])
  let hold
  install(fakeStack({ id: ID, def, events: lines, routes: { [`POST /api/jobs/${ID}/chains/eth/lease`]: () => new Promise((r) => { hold = r }) } }))
  renderWith(<JobView id={ID} jobOptions={FAST} />, { seed: [['eth', ethKey]] })
  await user.click(await screen.findByTestId('run-eth'))
  await waitFor(() => expect(hold).toBeTypeOf('function'))
  const stop = screen.getByTestId('stop-eth'), here = await screen.findByTestId('stop-here-eth')
  expect(stop.textContent).toMatch(/^Stop job \(all executors\)/)
  expect(stop.title).toBe(STOP_TIP)
  expect(STOP_TIP).toMatch(/every executor.*journaled.*latched until you press Resume/)
  expect(here.textContent).toBe('Stop running here')
  expect(here.title).toBe(DETACH_TIP)
  expect(DETACH_TIP).toMatch(/this tab stops.*Nothing is journaled.*job keeps running.*another executor/)
  await act(async () => { hold(json(409, { error: { guard: 'lease.held', message: 'held' } })) })
})

// Fix round 1: the gate is phase STOPPED *and* the latch. A state that carries stopLatched on any other phase (the API's state, shown
// until the stream catches up: the seq is far ahead of the stream, so the page keeps showing it) must not offer Resume.
test.each(['STUCK', 'DRAINED', 'COPIES_DONE', 'RUNNING', 'PAUSED', 'ARMED', 'CLAWING_BACK'])('stopLatched on phase %s (not STOPPED): no Resume', async (phase) => {
  const { def, events, id } = fixture('14-stopped')
  const state = reduce(def, events)
  const patched = { ...state, seq: 9999, chains: { ...state.chains, eth: { ...state.chains.eth, phase, stopLatched: true } } }
  install(fakeStack({ id, def, events, routes: { [`GET /api/jobs/${id}`]: () => json(200, { id, def, state: patched, leases: {}, seq: 9999, serverNowMs: Date.now() }) } }))
  renderWith(<JobView id={id} jobOptions={FAST} />)
  await waitFor(() => expect(screen.getByTestId('phase-eth').dataset.phase).toBe(phase))
  expect(screen.queryByTestId('resume-latched-eth')).toBeNull()
})

test.each(['RUNNING', 'PAUSED'])('labels on a %s chain with a run in this tab: Stop running here (detach) vs Stop job (all executors)', async (phase) => {
  const user = userEvent.setup()
  const def = jobDef({ chains: { eth: ethChain(ethKey.address) } })
  const lines = journal([created(ID), ...ready('eth', ethKey.address), { chain: null, type: 'armed', data: { armedAt: 1, releaseAt: 2, countdownSec: 5, schedule: { order: ['eth'], offsetSec: { eth: 0 } }, caps: { eth: { nativeCap: '4000000000000000', usd: 10, priceAt: null, overCap: false, planned: '0.004' } }, sources: {} } }])
  const state = reduce(def, lines)
  const patched = { ...state, seq: 9999, chains: { ...state.chains, eth: { ...state.chains.eth, phase } } }
  let hold
  install(fakeStack({ id: ID, def, events: lines, routes: {
    [`GET /api/jobs/${ID}`]: () => json(200, { id: ID, def, state: patched, leases: {}, seq: 9999, serverNowMs: Date.now() }),
    [`POST /api/jobs/${ID}/chains/eth/lease`]: () => new Promise((r) => { hold = r }),
  } }))
  renderWith(<JobView id={ID} jobOptions={FAST} />, { seed: [['eth', ethKey]] })
  await waitFor(() => expect(screen.getByTestId('phase-eth').dataset.phase).toBe(phase))
  await user.click(await screen.findByTestId('run-eth'))
  await waitFor(() => expect(hold).toBeTypeOf('function'))
  const stop = screen.getByTestId('stop-eth'), here = await screen.findByTestId('stop-here-eth')
  expect(stop.textContent).toMatch(/^Stop job \(all executors\)/)
  expect(stop.title).toBe(STOP_TIP)
  expect(here.textContent).toBe('Stop running here')
  expect(here.title).toBe(DETACH_TIP)
  await act(async () => { hold(json(409, { error: { guard: 'lease.held', message: 'held' } })) })
})

// R79b (M-9 d): a FINAL stop shows its reason and the way out, never Resume; mainnet needs the typed word `resume`.
test('the API refuses a resume with resume.final-stop: the page shows the reason and the way out, and Resume goes away', async () => {
  const user = userEvent.setup()
  const { def, events, id } = fixture('14-stopped')
  install(fakeStack({ id, def, events, routes: { [`POST /api/jobs/${id}/resume`]: () => json(409, { error: { guard: 'resume.final-stop', message: 'eth stopped on a readback mismatch (final)' } }) } }))
  renderWith(<JobView id={id} jobOptions={FAST} />)
  await user.click(await screen.findByTestId('resume-latched-eth'))
  await user.click(screen.getByTestId('resume-go-eth'))
  const fin = await screen.findByTestId('resume-final-eth')
  expect(fin.textContent).toMatch(/final.*readback mismatch.*claw back the remainder or close the chain/)
  expect(screen.queryByTestId('resume-latched-eth')).toBeNull()
  expect(screen.queryByTestId('resume-confirm-eth')).toBeNull()
})

test('a state that classes the stop final shows the reason and the way out at once, no Resume', async () => {
  const { def, events, id } = fixture('14-stopped')
  const state = reduce(def, events)
  const patched = { ...state, seq: 9999, chains: { ...state.chains, eth: { ...state.chains.eth, stopClass: 'final', stopCode: 'spend-cap' } } }
  install(fakeStack({ id, def, events, routes: { [`GET /api/jobs/${id}`]: () => json(200, { id, def, state: patched, leases: {}, seq: 9999, serverNowMs: Date.now() }) } }))
  renderWith(<JobView id={id} jobOptions={FAST} />)
  expect((await screen.findByTestId('resume-final-eth')).textContent).toMatch(/This stop is final \(spend-cap\), so Resume is not offered: .*claw back/)   // M5c: ChainState.stopCode
  expect(screen.queryByTestId('resume-latched-eth')).toBeNull()
})

test('M5c: a latched STOPPED chain whose state carries no stopClass is read as final (fail closed, like the executor): no Resume', async () => {
  const { def, events, id } = fixture('14-stopped')
  const state = reduce(def, events)
  const { stopClass: _gone, ...eth } = state.chains.eth
  const patched = { ...state, seq: 9999, chains: { ...state.chains, eth } }
  install(fakeStack({ id, def, events, routes: { [`GET /api/jobs/${id}`]: () => json(200, { id, def, state: patched, leases: {}, seq: 9999, serverNowMs: Date.now() }) } }))
  renderWith(<JobView id={id} jobOptions={FAST} />)
  expect((await screen.findByTestId('resume-final-eth')).textContent).toMatch(/This stop is final/)
  expect(screen.queryByTestId('resume-latched-eth')).toBeNull()
})

test('mainnet: Resume needs the typed word `resume`; off mainnet there is no word field', async () => {
  const user = userEvent.setup()
  const { def, events, id } = fixture('14-stopped')
  install(fakeStack({ id, def: { ...def, network: 'mainnet' }, events }))
  renderWith(<JobView id={id} jobOptions={FAST} />)
  await user.click(await screen.findByTestId('resume-latched-eth'))
  const go = screen.getByTestId('resume-go-eth')
  expect(go.disabled).toBe(true)
  await user.type(screen.getByTestId('resume-word-eth'), 'resum')
  expect(go.disabled).toBe(true)
  await user.type(screen.getByTestId('resume-word-eth'), 'e')
  expect(go.disabled).toBe(false)
  await user.click(go)
  await waitFor(() => expect(posts(/\/resume$/)).toHaveLength(1))
  expect(posts(/\/resume$/)[0].body).toEqual({ chain: 'eth' })
})

test('off mainnet the confirmation has no typed word', async () => {
  const user = userEvent.setup()
  const { def, events, id } = fixture('14-stopped')
  install(fakeStack({ id, def, events }))
  renderWith(<JobView id={id} jobOptions={FAST} />)
  await user.click(await screen.findByTestId('resume-latched-eth'))
  expect(screen.queryByTestId('resume-word-eth')).toBeNull()
  expect(screen.getByTestId('resume-go-eth').disabled).toBe(false)
})

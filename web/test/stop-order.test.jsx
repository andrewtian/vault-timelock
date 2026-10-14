// R79b M-7: the page's job-level Stop POSTs /stop FIRST and stops this tab's executor after, so it can never degrade into a detach.
import { test, expect, vi } from 'vitest'
import { screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import JobView from '../src/jobs/JobView.jsx'
import { newKey } from '../src/lib/core.js'
import { renderWith, json } from './helpers.jsx'
import { append, created, ethChain, fakeStack, jobDef, journal, ready } from './job-fakes.js'

const order = []
vi.mock('@vault-timelock/core/executor', async (orig) => {
  const m = await orig()
  return { ...m, createExecutor: (o) => { const ex = m.createExecutor(o); const rs = ex.requestStop.bind(ex); ex.requestStop = () => { order.push('local'); rs() }; const rr = ex.requestResume.bind(ex); ex.requestResume = (o) => { order.push('resume-local'); rr(o) }; return ex } }
})

const ID = '0123456789abcdef'
const ethKey = newKey('eth')

test('job-level Stop: the API stop is sent before this tab’s executor is told; a refused POST never stops the executor locally', async () => {
  const user = userEvent.setup()
  const def = jobDef({ chains: { eth: ethChain(ethKey.address) } })
  const lines = journal([created(ID), ...ready('eth', ethKey.address), { chain: null, type: 'armed', data: { armedAt: 1, releaseAt: 2, countdownSec: 5, schedule: { order: ['eth'], offsetSec: { eth: 0 } }, caps: { eth: { nativeCap: '4000000000000000', usd: 10, priceAt: null, overCap: false, planned: '0.004' } }, sources: {} } }])
  let holdLease, releaseStop
  const stack = fakeStack({ id: ID, def, events: lines, routes: {
    [`POST /api/jobs/${ID}/chains/eth/lease`]: () => new Promise((r) => { holdLease = r }),
    [`POST /api/jobs/${ID}/stop`]: () => new Promise((r) => { order.push('post'); releaseStop = r }),
  } })
  globalThis.fetch = stack.fetch
  renderWith(<JobView id={ID} jobOptions={{ pollMs: 200, flushMs: 10 }} />, { seed: [['eth', ethKey]] })
  await user.click(await screen.findByTestId('run-eth'))
  await waitFor(() => expect(holdLease).toBeTypeOf('function'))
  await user.click(screen.getByTestId('stop-eth'))
  await waitFor(() => expect(order).toEqual(['post']))
  await new Promise((r) => setTimeout(r, 50))
  expect(order).toEqual(['post'])                                         // the API has not answered: the executor is not stopped yet
  await act(async () => { releaseStop(json(200, { seq: 9 })) })
  await waitFor(() => expect(order).toEqual(['post', 'local']))
  await act(async () => { holdLease(json(409, { error: { guard: 'lease.held', message: 'held' } })) })
})

const armed = () => journal([created(ID), ...ready('eth', ethKey.address), { chain: null, type: 'armed', data: { armedAt: 1, releaseAt: 2, countdownSec: 5, schedule: { order: ['eth'], offsetSec: { eth: 0 } }, caps: { eth: { nativeCap: '4000000000000000', usd: 10, priceAt: null, overCap: false, planned: '0.004' } }, sources: {} } }])

test('a refused POST /stop is shown and never becomes a local-only stop', async () => {
  order.length = 0
  const user = userEvent.setup()
  const def = jobDef({ chains: { eth: ethChain(ethKey.address) } })
  let holdLease
  const stack = fakeStack({ id: ID, def, events: armed(), routes: {
    [`POST /api/jobs/${ID}/chains/eth/lease`]: () => new Promise((r) => { holdLease = r }),
    [`POST /api/jobs/${ID}/stop`]: () => json(409, { error: { guard: 'job.state', message: 'the API refused the stop' } }),
  } })
  globalThis.fetch = stack.fetch
  renderWith(<JobView id={ID} jobOptions={{ pollMs: 200, flushMs: 10 }} />, { seed: [['eth', ethKey]] })
  await user.click(await screen.findByTestId('run-eth'))
  await waitFor(() => expect(holdLease).toBeTypeOf('function'))
  await user.click(screen.getByTestId('stop-eth'))
  const msg = await screen.findByTestId('lane-msg-eth')
  expect(msg.textContent).toMatch(/stop: job\.state — the API refused the stop/)
  expect(order).not.toContain('local')
  await act(async () => { holdLease(json(409, { error: { guard: 'lease.held', message: 'held' } })) })
})

// R79b m-1: executor.requestResume clears the executor's local stop, so after "Stop running here" the page must not call it.
test.each([[true, []], [false, ['resume-local']]])('Cancel the stop after a detach=%s: the API resume is sent; this tab’s executor is told to resume only without a detach', async (detach, want) => {
  order.length = 0
  const user = userEvent.setup()
  const def = jobDef({ chains: { eth: ethChain(ethKey.address) } })
  let holdLease
  const stack = fakeStack({ id: ID, def, events: armed(), routes: { [`POST /api/jobs/${ID}/chains/eth/lease`]: () => new Promise((r) => { holdLease = r }) } })
  globalThis.fetch = stack.fetch
  renderWith(<JobView id={ID} jobOptions={{ pollMs: 200, flushMs: 10 }} />, { seed: [['eth', ethKey]] })
  await user.click(await screen.findByTestId('run-eth'))
  await waitFor(() => expect(holdLease).toBeTypeOf('function'))
  if (detach) await user.click(await screen.findByTestId('stop-here-eth'))
  append(stack, { chain: null, type: 'stop-requested', data: { chain: 'eth' } })
  const cancel = await screen.findByTestId('resume-eth')
  expect(cancel.textContent).toBe('Cancel the stop')
  await user.click(cancel)
  await waitFor(() => expect(stack.calls.filter((c) => c.method === 'POST' && /\/resume$/.test(c.url))).toHaveLength(1))
  expect(order.filter((x) => x === 'resume-local')).toEqual(want)
  await act(async () => { holdLease(json(409, { error: { guard: 'lease.held', message: 'held' } })) })
})

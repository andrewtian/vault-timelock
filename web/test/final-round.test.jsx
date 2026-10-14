// Final pre-flip round (lane W): F18-1 the real copy/part in the resume text; m-7 mainnet typed word on every resume that lets sends
// continue (PAUSED Resume, Cancel the stop) and a Cancel for a STOPPED chain with a new stop request pending.
import { test, expect, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import JobView from '../src/jobs/JobView.jsx'
import { renderWith, json } from './helpers.jsx'
import { reduce } from '@vault-timelock/core/job'
import { fakeStack, fixture } from './job-fakes.js'

const FAST = { pollMs: 200, flushMs: 10 }
let stack
beforeEach(() => { stack = null })
const posts = () => stack.calls.filter((c) => c.method === 'POST' && /\/resume$/.test(c.url))
// the API's state, patched; seq far ahead of the stream so the page keeps showing it
function setup(name, chain, patch, network) {
  const { def, events, id } = fixture(name)
  const state = reduce(def, events)
  const patched = { ...state, seq: 9999, chains: { ...state.chains, [chain]: { ...state.chains[chain], ...patch } } }
  stack = fakeStack({ id, def: network ? { ...def, network } : def, events, routes: { [`GET /api/jobs/${id}`]: () => json(200, { id, def: network ? { ...def, network } : def, state: patched, leases: {}, seq: 9999, serverNowMs: Date.now() }) } })
  globalThis.fetch = stack.fetch
  renderWith(<JobView id={id} jobOptions={FAST} />)
}

test('F18-1: the resume text names the real copy and part', async () => {
  const user = userEvent.setup()
  setup('13-resume-part', 'sol', { phase: 'STOPPED', stopLatched: true, stopClass: 'resumable', stopRequested: false })
  await user.click(await screen.findByTestId('resume-latched-sol'))
  const t = screen.getByTestId('resume-confirm-sol').textContent
  expect(t).toMatch(/The next part of copy 2 \(part 4\) is sent after you press Run here\./)
  expect(t).not.toMatch(/copy c/)
})

test('F18-1: a stopped chain with nothing sent says copy 1 (part 1)', async () => {
  const user = userEvent.setup()
  setup('14-stopped', 'eth', { stopClass: 'resumable' })
  await user.click(await screen.findByTestId('resume-latched-eth'))
  expect(screen.getByTestId('resume-confirm-eth').textContent).toMatch(/copy 1 \(part 1\)/)
})

test.each([['10a-paused', {}, 'Resume'], ['04-intent', { stopRequested: true }, 'Cancel the stop']])('mainnet %s: %s needs the typed word `resume`', async (name, patch, label) => {
  const user = userEvent.setup()
  setup(name, 'eth', patch, 'mainnet')
  const b = await screen.findByTestId('resume-eth')
  expect(b.textContent).toBe(label)
  expect(b.disabled).toBe(true)
  await user.type(screen.getByTestId('resume-word-eth'), 'resum')
  expect(b.disabled).toBe(true)
  await user.type(screen.getByTestId('resume-word-eth'), 'e')
  expect(b.disabled).toBe(false)
  await user.click(b)
  await waitFor(() => expect(posts()).toHaveLength(1))
  expect(posts()[0].body).toEqual({ chain: 'eth' })
})

test('off mainnet the PAUSED Resume has no typed word', async () => {
  setup('10a-paused', 'eth', {})
  const b = await screen.findByTestId('resume-eth')
  expect(screen.queryByTestId('resume-word-eth')).toBeNull()
  expect(b.disabled).toBe(false)
})

test('a resumable STOPPED chain with a NEW stop request pending offers "Cancel the stop"', async () => {
  const user = userEvent.setup()
  setup('14-stopped', 'eth', { stopClass: 'resumable', stopLatched: undefined, stopRequested: true })
  const b = await screen.findByTestId('resume-eth')
  expect(b.textContent).toBe('Cancel the stop')
  await user.click(b)
  await waitFor(() => expect(posts()).toHaveLength(1))
})

// M5d: a refused Cancel the stop / Resume (409 resume.final-stop) shows the final-stop panel; a served stopClass 'final' hides both
test('a refused "Cancel the stop" (resume.final-stop) shows the final panel with the reason and the way out, not a generic line', async () => {
  const user = userEvent.setup()
  setup('04-intent', 'eth', { stopRequested: true })
  const orig = globalThis.fetch
  globalThis.fetch = async (u, i = {}) => (String(u).endsWith('/resume') && i.method === 'POST' ? json(409, { error: { guard: 'resume.final-stop', message: 'eth stopped on a readback mismatch (final)' } }) : orig(u, i))
  await user.click(await screen.findByTestId('resume-eth'))
  const p = await screen.findByTestId('resume-final-eth')
  expect(p.textContent).toMatch(/readback mismatch.*claw back the remainder or close the chain/)
  expect(screen.queryByTestId('lane-msg-eth')).toBeNull()
  expect(screen.queryByTestId('resume-eth')).toBeNull()
})

test('a served stopClass final hides Cancel the stop and Resume and shows the panel', async () => {
  setup('14-stopped', 'eth', { stopClass: 'final', stopLatched: undefined, stopRequested: true })
  expect(await screen.findByTestId('resume-final-eth')).toBeTruthy()
  expect(screen.queryByTestId('resume-eth')).toBeNull()
  expect(screen.queryByTestId('resume-latched-eth')).toBeNull()
})

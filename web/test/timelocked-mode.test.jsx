// The message mode switch Timelocked | Plain on the New job form (W7): the timelocked text is validated by core's checkPayload,
// every refusal is shown, textKind follows the mode, and the page says honestly that timelocked publishing is not enabled yet.
import { test, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import NewJob, { TIMELOCKED_PUBLISHING, buildJobInput, exportJobFile } from '../src/jobs/NewJob.jsx'
import { checkTimelocked } from '../src/jobs/MessageInput.jsx'
import { checkPayload } from '../src/lib/core.js'
import { defaultChainConfig } from '../src/jobs/ChainConfig.jsx'
import { json, renderWith } from './helpers.jsx'
import { FUTURE_ROUND, makeTexts } from './open-fixtures.js'

let calls
beforeEach(() => {
  calls = []
  globalThis.fetch = vi.fn(async (url) => {
    calls.push(String(url))
    return json(404, {})
  })
})
const setText = (v) => fireEvent.change(screen.getByTestId('message'), { target: { value: v } })

test('the mode switch starts on Plain; Timelocked shows the not-enabled notice and keeps Create off', async () => {
  const user = userEvent.setup()
  renderWith(<NewJob />)
  expect(screen.getByTestId('mode-plain').checked).toBe(true)
  expect(screen.queryByTestId('timelocked-unavailable')).toBeNull()
  await user.click(screen.getByTestId('mode-timelocked'))
  expect(screen.getByTestId('mode-timelocked').checked).toBe(true)
  expect(screen.getByTestId('timelocked-unavailable').textContent).toMatch(/Timelocked publishing is not enabled yet/)
  expect(screen.getByTestId('timelocked-unavailable').textContent).toContain('job.publish-mode-unavailable')
  expect(screen.getByTestId('job-problems').textContent).toMatch(/timelocked publishing is not enabled yet/)
  expect(screen.getByTestId('job-create').disabled).toBe(true)
  expect(TIMELOCKED_PUBLISHING).toBe(false)
  await user.click(screen.getByTestId('mode-plain'))
  expect(screen.queryByTestId('timelocked-unavailable')).toBeNull()
})

test('Timelocked mode validates with core checkPayload and shows every refusal in core\'s words', async () => {
  const user = userEvent.setup()
  renderWith(<NewJob />)
  await user.click(screen.getByTestId('mode-timelocked'))
  setText('just a plain sentence')
  const want = checkPayload('just a plain sentence').issues
  expect(want.length).toBeGreaterThan(0)
  const shown = screen.getAllByTestId('payload-issue').map((e) => e.textContent)
  expect(shown).toEqual(want.map((i) => `${i.id}: ${i.message}`))
  expect(screen.getByTestId('message-issue').textContent).toContain('payload.header')
  expect(screen.getByTestId('message-issue').textContent).toContain('payload.sealed-missing')
  expect(screen.queryByTestId('message-ok')).toBeNull()
})

test('a text edited after sealing is refused (several ids at once), a clean one shows its facts', async () => {
  const t = await makeTexts({ round: FUTURE_ROUND, kind: 'payload' })
  const user = userEvent.setup()
  renderWith(<NewJob />)
  await user.click(screen.getByTestId('mode-timelocked'))
  setText(t.text.replace('unlock-after:', 'unlock-after:  ').replace('\n\n== vault', '\n$ rm -rf x\n\n== vault'))
  const ids = screen.getAllByTestId('payload-issue').map((e) => e.textContent.split(':')[0])
  expect(ids.length).toBeGreaterThanOrEqual(1)
  expect(ids.every((i) => i.startsWith('payload.') || i.startsWith('note.'))).toBe(true)
  setText(t.text)
  expect(screen.queryByTestId('payload-issue')).toBeNull()
  expect(screen.getByTestId('timelocked-facts').textContent).toContain(t.iso)
  expect(screen.getByTestId('timelocked-facts').textContent).toContain('contents full')
  expect(screen.getByTestId('timelocked-fits').textContent).toMatch(/eth (yes|no) · btc (yes|no) · sol (yes|no)/)
  expect(screen.getByTestId('message-sha').textContent).toBe(checkPayload(t.text).textSha256)
  expect(screen.queryByTestId('parts-preview')).toBeNull()
})

test('no request is made for the ar id: a valid timelocked text on a real network sends nothing', async () => {
  const t = await makeTexts({ round: FUTURE_ROUND, kind: 'payload' })
  const user = userEvent.setup()
  renderWith(<NewJob />, { network: 'testnet' })
  await user.click(screen.getByTestId('mode-timelocked'))
  setText(t.text)
  expect(screen.getByTestId('timelocked-facts')).toBeTruthy()
  await new Promise((r) => setTimeout(r, 300))
  expect(screen.queryByTestId('ar-check')).toBeNull()
  expect(calls.filter((c) => c.includes('arweave'))).toEqual([])
})

test('textKind follows the mode: timelocked jobs carry it, plain jobs do not', async () => {
  const t = await makeTexts({ round: FUTURE_ROUND, kind: 'payload' })
  const check = checkTimelocked(t.text)
  expect(check.ok).toBe(true)
  const cfgs = { eth: { ...defaultChainConfig('eth'), enabled: false }, sol: { ...defaultChainConfig('sol'), enabled: false } }
  const a = { network: 'local', name: 'n', check, cfgs, addresses: { eth: '', sol: '' } }
  expect(buildJobInput({ ...a, mode: 'timelocked' }).textKind).toBe('timelocked')
  expect('textKind' in buildJobInput({ ...a, mode: 'plain' })).toBe(false)
  expect('textKind' in buildJobInput(a)).toBe(false)
  expect(JSON.parse(exportJobFile({ network: 'local', name: 'n', text: t.text, cfgs, addresses: {}, mode: 'timelocked' })).textKind).toBe('timelocked')
  expect('textKind' in JSON.parse(exportJobFile({ network: 'local', name: 'n', text: 'x', cfgs, addresses: {} }))).toBe(false)
})

test('a job file with textKind timelocked switches the form to Timelocked', async () => {
  const t = await makeTexts({ round: FUTURE_ROUND, kind: 'payload' })
  renderWith(<NewJob />)
  const file = new File([JSON.stringify({ format: 'vt-job/1', network: 'local', name: 'tl', message: t.text, textKind: 'timelocked', chains: {} })], 'job.json')
  fireEvent.change(screen.getByTestId('job-file'), { target: { files: [file] } })
  await waitFor(() => expect(screen.getByTestId('mode-timelocked').checked).toBe(true))
  expect(screen.getByTestId('message').value).toBe(t.text)
})

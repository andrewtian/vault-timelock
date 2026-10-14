// The funding-source picker in the Arm dialog (W5, R47): shown only when the API supports sources; once one exists every
// armed chain needs one picked (no default); Arm carries `sources`; the S5 guards are explained; labels are validated.
import { test, expect, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { reduce } from '@vault-timelock/core/job'
import ArmDialog from '../src/jobs/ArmDialog.jsx'
import { listSources } from '../src/jobs/sources.js'
import { newKey } from '../src/lib/core.js'
import { json, renderWith } from './helpers.jsx'
import { created, ethChain, jobDef, journal, ready, solChain } from './job-fakes.js'

const ID = '00112233aabbccdd'
const ethKey = newKey('eth'), solKey = newKey('sol')
const cap = (o = {}) => ({ nativeCap: '4000000000000000', usd: 10, priceAt: 1, overCap: false, planned: '0.004', fullCopyCost: '100000000000000', parts: 1, affordable: true, ...o })
const inputs = async () => ({ text: 'x', prices: null, chains: { eth: { cap: cap(), history: 0, error: '' }, sol: { cap: cap({ nativeCap: '70000000', planned: '0.07', fullCopyCost: '20000' }), history: 0, error: '' } } })
const def = jobDef({ chains: { eth: ethChain(ethKey.address), sol: solChain(solKey.address) } })
const st = () => reduce(def, journal([created(ID), ...ready('eth', ethKey.address), ...ready('sol', solKey.address)]))
let calls, sourcesBody, armAnswer
beforeEach(() => {
  calls = []; armAnswer = () => json(200, { armed: { releaseAt: 1 } })
  globalThis.fetch = async (url, init = {}) => {
    const u = String(url)
    calls.push({ url: u, method: init.method || 'GET', body: init.body ? JSON.parse(init.body) : undefined })
    if (u === '/relay/tor') return json(200, { isTor: true, roles: {}, checkedAt: Date.now() })
    if (u === '/api/sources' && (init.method || 'GET') === 'GET') return sourcesBody === null ? json(404, {}) : json(200, sourcesBody)
    if (u === '/api/sources') { sourcesBody = { sources: [...(sourcesBody?.sources ?? []), JSON.parse(init.body).label] }; return json(201, { label: JSON.parse(init.body).label }) }
    if (u.endsWith('/arm')) return armAnswer()
    return json(404, {})
  }
})
const armPosts = () => calls.filter((c) => c.method === 'POST' && c.url === `/api/jobs/${ID}/arm`)
const open = async (user) => { renderWith(<ArmDialog jobId={ID} def={def} state={st()} inputs={inputs} />); await user.click(screen.getByTestId('arm-open')); await waitFor(() => expect(screen.getByTestId('arm-cap-eth')).toBeTruthy()) }

test('an API without sources (404): no picker, and Arm carries no `sources`', async () => {
  sourcesBody = null
  const user = userEvent.setup()
  await open(user)
  expect(screen.queryByTestId('source-picker')).toBeNull()
  await user.click(screen.getByTestId('arm-confirm'))
  await waitFor(() => expect(armPosts()).toHaveLength(1))
  expect(armPosts()[0].body.sources).toBeUndefined()
  expect(await listSources()).toMatchObject({ supported: false })
})

test('with sources declared: every armed chain needs one picked (no default), then Arm carries { chain: label }', async () => {
  sourcesBody = { sources: ['railgun-eth', 'pool-b'] }
  const user = userEvent.setup()
  await open(user)
  await waitFor(() => expect(screen.getByTestId('source-select-eth')).toBeTruthy())
  expect(screen.getByTestId('source-select-eth').value).toBe('')       // never pre-chosen
  expect(screen.getByTestId('arm-problems').textContent).toMatch(/Ethereum: pick a funding source for this try/)
  expect(screen.getByTestId('arm-confirm').disabled).toBe(true)
  await user.selectOptions(screen.getByTestId('source-select-eth'), 'railgun-eth')
  expect(screen.getByTestId('arm-confirm').disabled).toBe(true)        // Solana still unpicked
  await user.selectOptions(screen.getByTestId('source-select-sol'), 'pool-b')
  expect(screen.getByTestId('arm-confirm').disabled).toBe(false)
  expect(screen.getByTestId('source-rules').textContent).toMatch(/source\.reused.*source\.exhausted/s)
  expect(screen.getByTestId('source-rules').textContent).toContain('Each chain signs with the key shown on its lane (new or imported); its backup must be verified first.')
  expect(screen.getByTestId('source-rules').textContent).not.toMatch(/fresh per-chain keys/)
  await user.click(screen.getByTestId('arm-confirm'))
  await waitFor(() => expect(armPosts()).toHaveLength(1))
  expect(armPosts()[0].body.sources).toEqual({ eth: 'railgun-eth', sol: 'pool-b' })
})

test('an unarmed chain needs no source', async () => {
  sourcesBody = { sources: ['a'] }
  const user = userEvent.setup()
  await open(user)
  await waitFor(() => expect(screen.getByTestId('source-select-sol')).toBeTruthy())
  await user.click(screen.getByTestId('arm-select-sol'))
  expect(screen.queryByTestId('source-select-sol')).toBeNull()
  await user.selectOptions(screen.getByTestId('source-select-eth'), 'a')
  expect(screen.getByTestId('arm-confirm').disabled).toBe(false)
  await user.click(screen.getByTestId('arm-confirm'))
  await waitFor(() => expect(armPosts()).toHaveLength(1))
  expect(armPosts()[0].body.sources).toEqual({ eth: 'a' })
})

test('declaring a source: label validated (source.label) before it is sent; the new label appears', async () => {
  sourcesBody = { sources: [] }
  const user = userEvent.setup()
  await open(user)
  await waitFor(() => expect(screen.getByTestId('source-none')).toBeTruthy())
  await user.type(screen.getByTestId('source-new'), 'Bad Label')
  expect(screen.getByTestId('source-label-hint').textContent).toMatch(/source\.label/)
  expect(screen.getByTestId('source-add').disabled).toBe(true)
  await user.clear(screen.getByTestId('source-new')); await user.type(screen.getByTestId('source-new'), 'pool-c')
  await user.click(screen.getByTestId('source-add'))
  await waitFor(() => expect(screen.getByTestId('source-select-eth')).toBeTruthy())
  expect(calls.find((c) => c.method === 'POST' && c.url === '/api/sources').body).toEqual({ label: 'pool-c' })
  expect([...screen.getByTestId('source-select-eth').options].map((o) => o.value)).toContain('pool-c')
})

test.each([['source.reused', /already paid an earlier try/], ['source.exhausted', /no unused source is left/], ['source.unknown', /not declared/]])('Arm refused with %s is explained, with the id', async (guard, re) => {
  sourcesBody = { sources: ['a', 'b'] }
  armAnswer = () => json(409, { error: { guard, message: 'refused by the API' } })
  const user = userEvent.setup()
  await open(user)
  await waitFor(() => expect(screen.getByTestId('source-select-eth')).toBeTruthy())
  await user.selectOptions(screen.getByTestId('source-select-eth'), 'a'); await user.selectOptions(screen.getByTestId('source-select-sol'), 'b')
  await user.click(screen.getByTestId('arm-confirm'))
  await waitFor(() => expect(screen.getByTestId('arm-refused')).toBeTruthy())
  expect(screen.getByTestId('arm-refused').textContent).toContain(guard)
  expect(screen.getByTestId('arm-refused').textContent).toMatch(re)
  expect(screen.getByTestId('arm-refused').textContent).not.toMatch(/refused by the API/)   // ONE line: the page's text, not the API's too
})

test('an unknown source.* guard shows the API message alone', async () => {
  sourcesBody = { sources: ['a', 'b'] }
  armAnswer = () => json(409, { error: { guard: 'source.future', message: 'brand new refusal' } })
  const user = userEvent.setup()
  await open(user)
  await waitFor(() => expect(screen.getByTestId('source-select-eth')).toBeTruthy())
  await user.selectOptions(screen.getByTestId('source-select-eth'), 'a'); await user.selectOptions(screen.getByTestId('source-select-sol'), 'b')
  await user.click(screen.getByTestId('arm-confirm'))
  await waitFor(() => expect(screen.getByTestId('arm-refused').textContent).toBe('source.future: brand new refusal'))
})

test('no ledger read exists: before any refusal nothing is marked; after source.reused the label is marked and disabled', async () => {
  sourcesBody = { sources: ['pool-a', 'pool-b'] }
  armAnswer = () => json(409, { error: { guard: 'source.reused', message: 'x' } })
  const user = userEvent.setup()
  await open(user)
  await waitFor(() => expect(screen.getByTestId('source-select-eth')).toBeTruthy())
  const opts = () => [...screen.getByTestId('source-select-eth').options].map((o) => [o.textContent, o.disabled])
  expect(opts()).toEqual([['pick a source…', false], ['pool-a', false], ['pool-b', false]])
  await user.click(screen.getByTestId('arm-select-sol'))                       // one chain: the refused label is unambiguous
  await user.selectOptions(screen.getByTestId('source-select-eth'), 'pool-a')
  await user.click(screen.getByTestId('arm-confirm'))
  await waitFor(() => expect(screen.getByTestId('arm-refused')).toBeTruthy())
  expect(opts()).toEqual([['pick a source…', false], ['pool-a — used for this message', true], ['pool-b', false]])
  expect(screen.getByTestId('source-select-eth').value).toBe('')              // the refused pick is cleared; Arm disabled again
  expect(screen.getByTestId('arm-confirm').disabled).toBe(true)
})

test('source.reused with two different labels cannot say which: nothing is marked', async () => {
  sourcesBody = { sources: ['pool-a', 'pool-b'] }
  armAnswer = () => json(409, { error: { guard: 'source.reused', message: 'x' } })
  const user = userEvent.setup()
  await open(user)
  await waitFor(() => expect(screen.getByTestId('source-select-eth')).toBeTruthy())
  await user.selectOptions(screen.getByTestId('source-select-eth'), 'pool-a'); await user.selectOptions(screen.getByTestId('source-select-sol'), 'pool-b')
  await user.click(screen.getByTestId('arm-confirm'))
  await waitFor(() => expect(screen.getByTestId('arm-refused')).toBeTruthy())
  expect([...screen.getByTestId('source-select-eth').options].some((o) => o.disabled)).toBe(false)
})

test('S5 durable marks: on open the picker reads GET /sources/tries/<messageSha256> and marks the used labels (disabled)', async () => {
  sourcesBody = { sources: ['railgun-eth', 'pool-b'] }
  const base = globalThis.fetch
  globalThis.fetch = async (url, init = {}) => String(url).startsWith('/api/sources/tries/') ? (calls.push({ url: String(url), method: 'GET' }), json(200, { labelsUsed: ['railgun-eth'] })) : base(url, init)
  const user = userEvent.setup()
  await open(user)
  await waitFor(() => expect(screen.getByTestId('source-select-eth')).toBeTruthy())
  expect(calls.some((c) => c.url === `/api/sources/tries/${def.messageSha256}`)).toBe(true)
  await waitFor(() => expect(screen.getAllByRole('option', { name: 'railgun-eth — used for this message', hidden: true }).map((o) => o.disabled)).toEqual([true, true]))
  expect(screen.getAllByRole('option', { name: 'pool-b', hidden: true }).map((o) => o.disabled)).toEqual([false, false])
})

test('F14-1: a btc lane is named Bitcoin everywhere in the Arm dialog (never "undefined")', async () => {
  sourcesBody = { sources: ['a'] }
  const btcKey = newKey('btc', 'local')
  const bdef = jobDef({ chains: { btc: { ...solChain(btcKey.address, { mode: { copies: 1 }, distinctCopies: true }), publishMode: 'btc.inscription', maxFeeRateSatVb: 25 } } })
  const bst = reduce(bdef, journal([created(ID), ...ready('btc', btcKey.address)]))
  const user = userEvent.setup()
  renderWith(<ArmDialog jobId={ID} def={bdef} state={bst} inputs={async () => ({ text: 'x', prices: null, chains: { btc: { cap: cap(), history: 0, error: '' } } })} />)
  await user.click(screen.getByTestId('arm-open'))
  await waitFor(() => expect(screen.getByTestId('source-select-btc')).toBeTruthy())
  expect(screen.getByTestId('arm-confirm').textContent).toBe('Arm Bitcoin')
  expect(screen.getByTestId('arm-problems').textContent).toMatch(/Bitcoin: pick a funding source/)
  expect(document.body.textContent).not.toMatch(/undefined/)
})

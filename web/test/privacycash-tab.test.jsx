// The Privacy Cash tab (src/privacycash/PrivacyCash.jsx) with a FAKE worker client (the lane authorization is minted inside the worker's
// guarded fetch: guard.js / privacycash-guard.test.js). Synthetic values only; no network, no real key.
import { test, expect, beforeEach } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import PrivacyCash, { MAINNET_FUNDING_LOCKED } from '../src/privacycash/PrivacyCash.jsx'
import FundingTabs from '../src/funding/FundingTabs.jsx'
import { LINKAGE_WARNING } from '../src/privacycash/limits.js'
import { renderWith } from './helpers.jsx'

const ADDR = 'LaneLaneLaneLaneLaneLaneLaneLaneLaneLane1'
const SECRET = 'SUPERSECRETSIGNATUREVALUE'.repeat(4)
let calls, clients, behave, tries
function fakeClient({ onStatus }) {
  const c = {
    alive: true, stopped: [], onStatus,
    call: async (cmd, args) => { calls.push([cmd, args]); if (!c.alive) throw Object.assign(new Error('stopped'), { code: 'pc.stopped', stopped: true }); return behave[cmd](args, c) },
    stop(code, message) { c.alive = false; c.stopped.push([code, message]) },
  }
  clients.push(c); return c
}
const newTry = () => { tries.push(1); return 4242 }
beforeEach(() => {
  calls = []; clients = []; tries = []
  behave = {
    unlock: async () => ({ ok: true }),
    balance: async () => ({ lamports: 5_000_000_000, notes: 2, top2: 5_000_000_000 }),
    quote: async ({ net }) => ({ gross: net + 6_100_000, fee: 6_100_000, net, top2: 5_000_000_000, minimum: 10_000_000 }),
    withdraw: async ({ net }) => ({ signature: '5'.repeat(88), net, fee: 6_100_000, isPartial: false, indexerConfirmed: true }),
    lock: async () => ({ ok: true }),
  }
})
const view = (props = {}) => renderWith(<PrivacyCash network="mainnet" address={ADDR} jobId="0123456789abcdef" createClient={fakeClient} newTry={newTry} fundingLocked={false} {...props} />, { network: 'mainnet' })
async function unlock(user, key = SECRET) {
  await user.type(screen.getByTestId('pc-pubkey'), 'DepositDepositDepositDepositDeposit11')
  await user.type(screen.getByTestId('pc-key'), key)
  await user.click(screen.getByTestId('pc-unlock'))
  await screen.findByTestId('pc-unlocked')
}

test('off mainnet the tab offers nothing (Privacy Cash has no devnet): no key field, no worker', () => {
  for (const n of ['local', 'testnet']) {
    const { unmount } = renderWith(<PrivacyCash network={n} address={ADDR} createClient={fakeClient} newTry={newTry} />, { network: n })
    expect(screen.getByTestId('pc-not-mainnet').textContent).toMatch(/mainnet only/)
    expect(screen.queryByTestId('pc-key')).toBeNull(); expect(clients).toHaveLength(0)
    unmount()
  }
})

test('the linkage warning is on the page before anything; the key field is the project SecretInput (no password type); no worker exists until Unlock', () => {
  view()
  expect(screen.getByTestId('pc-warning').textContent).toContain(LINKAGE_WARNING)
  const k = screen.getByTestId('pc-key')
  expect(k.type).toBe('text')                                        // I-1: never type=password (the browser would offer to save the wallet key)
  expect(k.classList.contains('secret-input')).toBe(true)            // the project's SecretInput: masked by CSS, autocomplete off, ignore hints
  expect(k.getAttribute('autocomplete')).toBe('off'); expect(k.getAttribute('data-1p-ignore')).toBe('true'); expect(k.getAttribute('data-lpignore')).toBe('true')
  expect(k.closest('form')).toBeNull()
  expect(document.querySelectorAll('input[type="password"]')).toHaveLength(0)       // no password-type input anywhere in the tab
  expect(screen.getByTestId('pc-unlock').disabled).toBe(true)
  expect(clients).toHaveLength(0)
})

test('the key leaves the input (and the page\'s state) the moment Unlock is clicked, and is never rendered or stored', async () => {
  const user = userEvent.setup()
  view()
  await unlock(user)
  expect(calls[0][0]).toBe('unlock')
  expect(calls[0][1]).toMatchObject({ mode: 'signature', input: SECRET, publicKey: 'DepositDepositDepositDepositDeposit11' })
  expect(document.body.innerHTML).not.toContain(SECRET)
  expect(screen.queryByTestId('pc-key')).toBeNull()
  expect(JSON.stringify({ ...localStorage })).toBe('{}'); expect(JSON.stringify({ ...sessionStorage })).toBe('{}')
})

test('EVERY balance check and EVERY withdrawal needs the linkage box ticked again', async () => {
  const user = userEvent.setup()
  view()
  await unlock(user)
  const bal = () => screen.getByTestId('pc-balance-btn')
  expect(bal().disabled).toBe(true)
  await user.click(screen.getByTestId('pc-ack')); expect(bal().disabled).toBe(false)
  await user.click(bal()); await screen.findByTestId('pc-balance')
  expect(screen.getByTestId('pc-ack').checked).toBe(false); expect(bal().disabled).toBe(true)        // cleared after use
  expect(screen.getByTestId('pc-balance').textContent).toMatch(/5\.0 SOL.*2 note/)
  await user.click(screen.getByTestId('pc-ack')); await user.click(bal()); await waitFor(() => expect(calls.filter((c) => c[0] === 'balance')).toHaveLength(2))
  // quote → withdraw
  await user.clear(screen.getByTestId('pc-amount')); await user.type(screen.getByTestId('pc-amount'), '0.5')
  await user.click(screen.getByTestId('pc-review'))
  const q = await screen.findByTestId('pc-quote')
  expect(q.textContent).toMatch(/relayer fee 0\.0061 SOL.*the lane receives 0\.5 SOL/)
  const wd = () => screen.getByTestId('pc-withdraw')
  expect(wd().disabled).toBe(true)                                                                     // not ticked
  await user.click(screen.getByTestId('pc-ack')); expect(wd().disabled).toBe(false)
  await user.click(wd())
  await screen.findByTestId('pc-result')
  expect(screen.getByTestId('pc-ack').checked).toBe(false)
})

test('a withdrawal hands the worker the job and a fresh try (it mints the v2 authorization itself), sends the lane address as recipient, then terminates the worker (the wipe)', async () => {
  const user = userEvent.setup()
  view()
  await unlock(user)
  await user.click(screen.getByTestId('pc-ack')); await user.click(screen.getByTestId('pc-balance-btn')); await screen.findByTestId('pc-balance')
  await user.click(screen.getByTestId('pc-review')); await screen.findByTestId('pc-quote')
  expect(screen.getByTestId('pc-recipient').textContent).toBe(ADDR)
  await user.click(screen.getByTestId('pc-ack')); await user.click(screen.getByTestId('pc-withdraw'))
  const res = await screen.findByTestId('pc-result')
  expect(tries).toHaveLength(1)
  const w = calls.find((c) => c[0] === 'withdraw')[1]
  expect(w).toEqual({ net: 10_000_000, recipient: ADDR, job: '0123456789abcdef', tryIndex: 4242 })
  expect(within(res).getByTestId('pc-signature').textContent).toBe('5'.repeat(88))
  expect(clients[0].alive).toBe(false)                                                                 // locked + terminated after the withdrawal
  expect(calls.map((c) => c[0])).toContain('lock')
  expect(screen.queryByTestId('pc-unlocked')).toBeNull()                                               // back to the locked form
})

test('without a job there is nothing to bind: the withdraw button stays off and says why', async () => {
  const user = userEvent.setup()
  view({ jobId: null })
  await unlock(user)
  await user.click(screen.getByTestId('pc-ack')); await user.click(screen.getByTestId('pc-balance-btn')); await screen.findByTestId('pc-balance')
  expect(screen.getByTestId('pc-needs-job')).toBeTruthy()
  await user.click(screen.getByTestId('pc-review')); await screen.findByTestId('pc-quote')
  await user.click(screen.getByTestId('pc-ack'))
  expect(screen.getByTestId('pc-withdraw').disabled).toBe(true)
})

test('errors are shown with their code (the relay\'s funding lock included) and the worker stays usable; a partial refusal comes from the quote, before proving', async () => {
  const user = userEvent.setup()
  view()
  await unlock(user)
  await user.click(screen.getByTestId('pc-ack')); await user.click(screen.getByTestId('pc-balance-btn')); await screen.findByTestId('pc-balance')
  behave.quote = async () => { throw Object.assign(new Error('the two largest notes hold less'), { code: 'pc.partial' }) }
  await user.click(screen.getByTestId('pc-review'))
  expect((await screen.findByTestId('pc-error')).textContent).toMatch(/pc\.partial.*two largest/)
  expect(clients[0].alive).toBe(true)
  expect(screen.queryByTestId('pc-quote')).toBeNull()
  behave.quote = async ({ net }) => ({ gross: net + 6_100_000, fee: 6_100_000, net, top2: 1, minimum: 1 })
  behave.withdraw = async () => { throw Object.assign(new Error('funding sends are locked'), { code: 'release.mainnet-locked' }) }
  await user.click(screen.getByTestId('pc-review')); await screen.findByTestId('pc-quote')
  await user.click(screen.getByTestId('pc-ack')); await user.click(screen.getByTestId('pc-withdraw'))
  expect((await screen.findByTestId('pc-error')).textContent).toMatch(/release\.mainnet-locked.*locked/)
  expect(screen.queryByTestId('pc-result')).toBeNull()
})

test('a stopped worker (watchdog or Stop) returns to the locked form; if /withdraw had already left, the page says funds may have moved', async () => {
  const user = userEvent.setup()
  view()
  await unlock(user)
  await user.click(screen.getByTestId('pc-ack')); await user.click(screen.getByTestId('pc-balance-btn')); await screen.findByTestId('pc-balance')
  await user.click(screen.getByTestId('pc-review')); await screen.findByTestId('pc-quote')
  behave.withdraw = async () => { throw Object.assign(new Error('no sign of life'), { code: 'pc.watchdog', stopped: true, sentAtStop: true }) }
  await user.click(screen.getByTestId('pc-ack')); await user.click(screen.getByTestId('pc-withdraw'))
  const e = await screen.findByTestId('pc-error')
  expect(e.textContent).toMatch(/pc\.watchdog/)
  expect(screen.getByTestId('pc-sent-warning').textContent).toMatch(/Funds may have moved/)
  expect(screen.getByTestId('pc-key')).toBeTruthy()                                                  // locked again: the key must be entered again
  expect(screen.queryByTestId('pc-balance')).toBeNull()
})

test('a failed unlock terminates the worker and shows why', async () => {
  const user = userEvent.setup()
  behave.unlock = async () => { throw Object.assign(new Error('not the deposit wallet\'s signature'), { code: 'pc.signature' }) }
  view()
  await user.type(screen.getByTestId('pc-pubkey'), 'DepositDepositDepositDepositDeposit11')
  await user.type(screen.getByTestId('pc-key'), SECRET)
  await user.click(screen.getByTestId('pc-unlock'))
  expect((await screen.findByTestId('pc-error')).textContent).toMatch(/pc\.signature/)
  expect(clients[0].alive).toBe(false)
  expect(document.body.innerHTML).not.toContain(SECRET)
})

test('leaving the page terminates the worker', async () => {
  const user = userEvent.setup()
  const { unmount } = view()
  await unlock(user)
  unmount()
  expect(clients[0].alive).toBe(false)
})

test('the secret-key mode is offered, with its own wording, and is sent as mode secret', async () => {
  const user = userEvent.setup()
  view()
  await user.click(screen.getByTestId('pc-mode-secret'))
  await unlock(user, 'k'.repeat(44))
  expect(calls[0][1].mode).toBe('secret')
})

test('MAINNET FUNDING LOCK: by default the tab explains that mints and withdrawals are locked and the Withdraw button stays off, ticked or not (the balance check still works)', async () => {
  expect(MAINNET_FUNDING_LOCKED).toBe(true)
  const user = userEvent.setup()
  renderWith(<PrivacyCash network="mainnet" address={ADDR} jobId="0123456789abcdef" createClient={fakeClient} newTry={newTry} />, { network: 'mainnet' })
  await unlock(user)
  await user.click(screen.getByTestId('pc-ack')); await user.click(screen.getByTestId('pc-balance-btn')); await screen.findByTestId('pc-balance')
  expect(screen.getByTestId('pc-funding-locked').textContent).toMatch(/LOCKED on mainnet.*no Privacy Cash authorization.*withdrawals/s)
  await user.click(screen.getByTestId('pc-review')); await screen.findByTestId('pc-quote')
  await user.click(screen.getByTestId('pc-ack'))
  expect(screen.getByTestId('pc-withdraw').disabled).toBe(true)
  expect(calls.map((c) => c[0])).not.toContain('withdraw'); expect(tries).toHaveLength(0)
})

test('the API\'s refusal of the authorization (api.pc-lock) reaches the page by its guard id', async () => {
  const user = userEvent.setup()
  behave.withdraw = async () => { throw Object.assign(new Error('Privacy Cash authorizations are not minted on mainnet in this build'), { code: 'api.pc-lock' }) }
  view()
  await unlock(user)
  await user.click(screen.getByTestId('pc-ack')); await user.click(screen.getByTestId('pc-balance-btn')); await screen.findByTestId('pc-balance')
  await user.click(screen.getByTestId('pc-review')); await screen.findByTestId('pc-quote')
  await user.click(screen.getByTestId('pc-ack')); await user.click(screen.getByTestId('pc-withdraw'))
  expect((await screen.findByTestId('pc-error')).textContent).toMatch(/api\.pc-lock/)
})

test('FundingTabs: three separate tabs; Privacy Cash and Railgun are not rendered until chosen; Address is the default', async () => {
  const user = userEvent.setup()
  renderWith(<FundingTabs network="mainnet" addresses={{ eth: '0x' + '11'.repeat(20), sol: ADDR }} createClient={fakeClient} newTry={newTry} />, { network: 'mainnet' })
  expect(screen.getByTestId('funding-mainnet')).toBeTruthy()
  expect(screen.queryByTestId('pc-tab')).toBeNull(); expect(screen.queryByTestId('rg-tab')).toBeNull()
  await user.click(screen.getByTestId('tab-privacycash')); expect(await screen.findByTestId('pc-tab')).toBeTruthy(); expect(screen.queryByTestId('rg-tab')).toBeNull()
  await user.click(screen.getByTestId('tab-railgun')); expect(await screen.findByTestId('rg-tab')).toBeTruthy()
  expect(clients).toHaveLength(0)                                                                      // viewing a tab starts nothing
})

test('m-3: while a Privacy Cash call is in flight the other funding tabs are shut and leaving the page asks first; both clear when it ends', async () => {
  const user = userEvent.setup()
  let release
  behave.balance = () => new Promise((res) => { release = () => res({ lamports: 5_000_000_000, notes: 2, top2: 5_000_000_000 }) })
  renderWith(<FundingTabs network="mainnet" addresses={{ eth: '0x' + '11'.repeat(20), sol: ADDR }} createClient={fakeClient} newTry={newTry} />, { network: 'mainnet' })
  await user.click(screen.getByTestId('tab-privacycash'))
  await unlock(user)
  const leave = () => { const e = new Event('beforeunload', { cancelable: true }); window.dispatchEvent(e); return e.defaultPrevented }
  expect(leave()).toBe(false)                                                                          // idle: nothing to protect
  await user.click(screen.getByTestId('pc-ack')); await user.click(screen.getByTestId('pc-balance-btn'))
  await waitFor(() => expect(screen.getByTestId('tab-address').disabled).toBe(true))
  expect(screen.getByTestId('tab-railgun').disabled).toBe(true); expect(screen.getByTestId('tab-privacycash').disabled).toBe(false)
  await user.click(screen.getByTestId('tab-address')); expect(screen.getByTestId('pc-tab')).toBeTruthy()   // still here
  expect(clients[0].alive).toBe(true)
  expect(leave()).toBe(true)
  release()
  await screen.findByTestId('pc-balance')
  await waitFor(() => expect(screen.getByTestId('tab-address').disabled).toBe(false))
  expect(leave()).toBe(false)
})

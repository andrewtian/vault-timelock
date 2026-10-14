// Claw-back (W3; CC-2a): over the remaining armed cap the operator types the exact amount, which rides as
// clawbackConfirm (base units) beside the clawback-intent only; the destination class sets the ETH gas (a fresh
// destination after Amsterdam: 204,600). Driven through the real core executor against a synthetic API and relay.
import { test, expect } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import JobView from '../src/jobs/JobView.jsx'
import { clawBudget } from '../src/jobs/Clawback.jsx'
import { newKey } from '../src/lib/core.js'
import { json, renderWith } from './helpers.jsx'
import { created, ethChain, fakeStack, jobDef, journal, ready } from './job-fakes.js'

const ID = '1122334455667788'
const ethKey = newKey('eth')
const dest = newKey('eth').address                                 // EIP-55, a fresh (empty) account
const hex = (n) => '0x' + BigInt(n).toString(16)
const BAL = 10n ** 16n                                             // 0.01 ETH left on the lane; the armed cap is 0.004

function stoppedTestnetJob() {
  const def = jobDef({ network: 'testnet', chains: { eth: ethChain(ethKey.address, { feeStrategy: 'prompt' }) } })
  const armed = { armedAt: 1, releaseAt: 2, countdownSec: 60, schedule: { order: ['eth'], offsetSec: { eth: 0 } }, caps: { eth: { nativeCap: '4000000000000000', usd: 0, priceAt: null, overCap: false, planned: '0.004' } }, sources: {} }
  return { def, events: journal([created(ID), ...ready('eth', ethKey.address), { type: 'armed', data: armed }, { chain: 'eth', by: 'browser', gen: 1, type: 'stopped', data: { reason: 'stopped by the operator' } }]) }
}

test('clawBudget: room = cap − spent; the typed amount is needed only when the balance does not fit', () => {
  expect(clawBudget('100', '30', 70n)).toEqual({ room: 70n, need: 70n, typed: false })
  expect(clawBudget('100', '30', 71n)).toEqual({ room: 70n, need: 71n, typed: true })
  expect(clawBudget(undefined, '0', 1n)).toBeNull()
})

test('over the cap: the exact amount is typed, the fresh-destination gas is shown, and clawbackConfirm rides with the clawback-intent', async () => {
  const user = userEvent.setup()
  const { def, events } = stoppedTestnetJob()
  const intents = []
  const st = fakeStack({ id: ID, def, events, routes: {
    [`POST /api/jobs/${ID}/chains/eth/lease`]: ({ body }) => json(200, body.op === 'release' ? {} : { gen: 2, ttlMs: 15000, expiresAt: Date.now() + 15000, holder: 'browser', openIntents: [] }),
    [`POST /api/jobs/${ID}/chains/eth/events`]: ({ body }) => { intents.push(body); return json(409, { error: { guard: 'job.state', message: 'synthetic stop: nothing is sent in this test' } }) },
    'POST /relay/eth': ({ body }) => {
      const r = (result) => json(200, { jsonrpc: '2.0', id: body.id, result })
      const a = String(body.params?.[0]?.from ?? body.params?.[0] ?? '').toLowerCase()
      switch (body.method) {
        case 'eth_chainId': return r('0xaa36a7')
        case 'eth_getTransactionCount': return r(a === dest.toLowerCase() ? '0x0' : '0x3')
        case 'eth_getBalance': return r(a === dest.toLowerCase() ? '0x0' : hex(BAL))
        case 'eth_getCode': return r('0x')
        case 'eth_feeHistory': return r({ oldestBlock: '0x10', baseFeePerGas: Array(21).fill('0x3b9aca00'), gasUsedRatio: Array(20).fill(0.5), reward: Array(20).fill(['0x3b9aca00']) })
        case 'eth_estimateGas': return r(hex(204600))
        default: return json(200, { jsonrpc: '2.0', id: body.id, error: { code: -32601, message: body.method } })
      }
    },
  } })
  globalThis.fetch = st.fetch
  renderWith(<JobView id={ID} jobOptions={{ pollMs: 300, flushMs: 10 }} />, { network: 'testnet', seed: [['eth', ethKey]] })
  await waitFor(() => expect(screen.getByTestId('phase-eth').dataset.phase).toBe('STOPPED'))
  expect(screen.getByTestId('claw-gaswarn-eth').textContent).toMatch(/FRESH \(empty\) destination costs 204600 gas/)
  expect(screen.getByTestId('claw-regime-eth').textContent).toMatch(/\[TESTNET\]/)
  await waitFor(() => expect(screen.getByTestId('claw-budget-eth').textContent).toMatch(/remainder \(value \+ fee\) 0\.01 ETH · left of the armed cap 0\.004 ETH/))
  await user.type(screen.getByTestId('claw-dest-eth'), dest)
  await waitFor(() => expect(screen.getByTestId('claw-gas-eth').dataset.gas).toBe('204600'))
  expect(screen.getByTestId('claw-gas-eth').textContent).toMatch(/EMPTY \(a fresh account\)/)
  expect(screen.getByTestId('claw-over-eth').textContent).toMatch(/Type 0\.01 to approve clawing back exactly this amount \(10000000000000000 base units\)/)
  expect(screen.getByTestId('claw-go-eth').disabled).toBe(true)
  await user.type(screen.getByTestId('claw-amount-eth'), '0.009')
  expect(screen.getByTestId('claw-go-eth').disabled).toBe(true)
  await user.clear(screen.getByTestId('claw-amount-eth')); await user.type(screen.getByTestId('claw-amount-eth'), '0.010')
  expect(screen.getByTestId('claw-go-eth').disabled).toBe(false)
  await user.click(screen.getByTestId('claw-go-eth'))
  await waitFor(() => expect(intents).toHaveLength(1), { timeout: 8000 })
  const req = intents[0]
  expect(req.type).toBe('clawback-intent')
  expect(req.clawbackConfirm).toEqual({ amount: String(BAL) })                     // exact base units = value + gas × maxFee
  expect(BigInt(req.data.value) + BigInt(req.data.eth.gas) * BigInt(req.data.eth.maxFee)).toBe(BAL)
  expect(req.data.eth.gas).toBe('204600')
  expect(req.data.to).toBe(dest)
  await waitFor(() => expect(screen.getByTestId('claw-result-eth').textContent).toMatch(/claw-back failed/))
  // never beside another event type
  expect(st.calls.filter((c) => c.body && c.body.clawbackConfirm && c.body.type !== 'clawback-intent')).toHaveLength(0)
}, 20_000)

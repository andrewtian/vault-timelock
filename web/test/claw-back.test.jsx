// The after-run panel (W4): it reaches the claw-back for DRAINED / COPIES_DONE / STOPPED chains, shows links, the
// permanence note and the by-hand reassembly command, offers the receipt; and the resolve-STUCK UI records the
// operator's outcome (mark-failed frees NO cap). Journals are the contract fixtures, driven through the real job page.
import { test, expect, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import JobView from '../src/jobs/JobView.jsx'
import { validateEthDest } from '@vault-timelock/core/chains/economy.js'
import Clawback from '../src/jobs/Clawback.jsx'
import ResolveStuck, { chainEvidence, resolveCommand } from '../src/jobs/ResolveStuck.jsx'
import { json, renderWith } from './helpers.jsx'
import { fakeStack, fixture } from './job-fakes.js'

const FAST = { pollMs: 300, flushMs: 10 }
let stack
const install = (st) => { stack = st; globalThis.fetch = st.fetch }
beforeEach(() => { stack = null })
const posts = (re) => stack.calls.filter((c) => c.method === 'POST' && re.test(c.url))
const asNetwork = (def, network) => ({ ...def, network })

test.each([['11-drained', 'DRAINED'], ['05a-copies-done', 'COPIES_DONE'], ['14-stopped', 'STOPPED']])('%s: the after-run panel reaches the claw-back (%s)', async (name, phase) => {
  const { def, events, id } = fixture(name)
  install(fakeStack({ id, def, events }))
  renderWith(<JobView id={id} jobOptions={FAST} />)
  await waitFor(() => expect(screen.getByTestId('phase-eth').dataset.phase).toBe(phase))
  const panel = screen.getByTestId('afterrun-eth')
  expect(panel.dataset.phase).toBe(phase)
  expect(panel.querySelector('[data-testid="afterrun-claw-eth"]')).toBeTruthy()
  // the claw-back UI W3 built (typed destination, regime line); the key must be loaded in this tab
  expect(panel.querySelector('[data-testid="claw-eth"], [data-testid="claw-wait-eth"]')).toBeTruthy()
  expect(screen.getByTestId('claw-dest-eth')).toBeTruthy()
  expect(screen.getByTestId('afterrun-permanence-eth').textContent).toMatch(/eth\.calldata\.null: public immediately and permanently/)
  expect(screen.getByTestId('afterrun-close-eth').textContent).toMatch(/vt backup import <backup file> --chain eth/)   // L2-3
  expect(screen.getByTestId('afterrun').dataset.all).toBe('true')
  expect(screen.getByTestId('afterrun-receipt')).toBeTruthy()
})

test('the panel lists the last landed transaction’s links per network and the by-hand command; mainnet links are copy-only', async () => {
  const { def, events, id } = fixture('11-drained')
  install(fakeStack({ id, def: asNetwork(def, 'mainnet'), events }))
  const { container } = renderWith(<JobView id={id} jobOptions={FAST} />, { network: 'mainnet' })
  await waitFor(() => expect(screen.getByTestId('afterrun-eth')).toBeTruthy())
  expect(screen.getAllByTestId(/^afterrun-link-eth-\d+$/).every((r) => r.dataset.use === 'copy')).toBe(true)
  expect(container.querySelectorAll('[data-testid^="afterrun-link-eth"] a, [data-testid^="afterrun-links"] a, [data-testid="afterrun-eth"] a[href]')).toHaveLength(0)
  expect(screen.getByTestId('afterrun-link-eth-text-0').textContent).toMatch(/^https:\/\/etherscan\.io\/tx\/0x/)
  // a one-part message still gets its by-hand block (the plain-text case is explained by the command itself)
  expect(screen.getByTestId('byhand-eth')).toBeTruthy()
  expect(screen.getByTestId('byhand-cmd-eth').textContent).toContain(def.messageSha256)
  expect(screen.getByTestId('byhand-ids-eth').textContent).toMatch(/^0x[0-9a-f]{64}\n$/)
})

test('claw-back is disabled while a transaction is in flight, and says why', () => {
  const def = fixture('11-drained').def
  const cs = { phase: 'DRAINED', reason: null, address: null, copy: 1, attempt: null, copiesIncluded: 1, reassembled: [], spent: '0', openIntents: ['0xaa'], resume: null, stopRequested: false, clawback: null,
    txs: [{ copy: 1, part: 1, parts: 1, attempts: [], state: 'open', landedId: null, block: null, fee: null, readback: null }] }
  renderWith(<Clawback jobId="0011223344556677" def={def} chain="eth" cs={cs} armed={null} entry={null} keyOk={false} run={{ status: 'idle' }} network="mainnet" />, { network: 'mainnet' })
  expect(screen.queryByTestId('claw-go-eth')).toBeNull()
  expect(screen.getByTestId('claw-wait-eth').textContent).toMatch(/once the chain has settled.*nothing in flight/)
  // settled with nothing in flight: the button exists and is disabled until the mainnet typed word and the rest are in
  const settled = { ...cs, txs: [{ ...cs.txs[0], state: 'included', landedId: '0xaa' }], openIntents: [] }
  renderWith(<Clawback jobId="0011223344556677" def={def} chain="eth" cs={settled} armed={null} entry={null} keyOk={false} run={{ status: 'idle' }} network="mainnet" />, { network: 'mainnet' })
  expect(screen.getByTestId('claw-go-eth').disabled).toBe(true)
  expect(screen.getByTestId('claw-problems-eth').textContent).toMatch(/type claw back to confirm/)
})

test('claw-back refuses an ETH precompile or reserved destination (0x…0001 to 0x…ffff); 0x…010000 is not', async () => {
  const user = userEvent.setup()
  const fx = fixture('11-drained').def
  const def = { ...fx, chains: { ...fx.chains, eth: { ...fx.chains.eth, clawbackTo: null } } }   // the destination input is read-only when the job names one
  const cs = { phase: 'DRAINED', reason: null, address: null, copy: 1, attempt: null, copiesIncluded: 1, reassembled: [], spent: '0', openIntents: [], resume: null, stopRequested: false, clawback: null,
    txs: [{ copy: 1, part: 1, parts: 1, attempts: [], state: 'included', landedId: '0xaa', block: null, fee: null, readback: null }] }
  renderWith(<Clawback jobId="0011223344556677" def={def} chain="eth" cs={cs} armed={null} entry={null} keyOk={false} run={{ status: 'idle' }} network="local" />, { network: 'local' })
  const low = (n) => {   // the EIP-55 form (core's validator names it for the lowercase one)
    const l = `0x${n.toString(16).padStart(40, '0')}`, v = validateEthDest(l, '')
    return v.ok ? v.address : /expected (0x[0-9a-fA-F]{40})/.exec(v.why)[1]
  }
  for (const n of [1n, 9n, 0x11n, 0x100n, 0xffffn]) {
    await user.clear(screen.getByTestId('claw-dest-eth'))
    await user.type(screen.getByTestId('claw-dest-eth'), low(n))
    expect(screen.getByTestId('claw-problems-eth').textContent, n.toString(16)).toMatch(/precompile or reserved system address/)
    expect(screen.getByTestId('claw-go-eth').disabled).toBe(true)
  }
  await user.clear(screen.getByTestId('claw-dest-eth'))
  await user.type(screen.getByTestId('claw-dest-eth'), low(0x10000n))
  expect(screen.getByTestId('claw-problems-eth').textContent).not.toMatch(/precompile/)
})

test('claw-back says burn/null for 0x…dEaD and 0x0 (ethReservedKind), precompile only for 0x…0001 to 0x…ffff', async () => {
  const user = userEvent.setup()
  const fx = fixture('11-drained').def
  const def = { ...fx, chains: { ...fx.chains, eth: { ...fx.chains.eth, clawbackTo: null } } }
  const cs = { phase: 'DRAINED', reason: null, address: null, copy: 1, attempt: null, copiesIncluded: 1, reassembled: [], spent: '0', openIntents: [], resume: null, stopRequested: false, clawback: null,
    txs: [{ copy: 1, part: 1, parts: 1, attempts: [], state: 'included', landedId: '0xaa', block: null, fee: null, readback: null }] }
  renderWith(<Clawback jobId="0011223344556677" def={def} chain="eth" cs={cs} armed={null} entry={null} keyOk={false} run={{ status: 'idle' }} network="local" />, { network: 'local' })
  const dest = screen.getByTestId('claw-dest-eth')
  await user.clear(dest)
  await user.type(dest, '0x000000000000000000000000000000000000dEaD')
  expect(screen.getByTestId('claw-problems-eth').textContent).toMatch(/null or burn address/)
  expect(screen.getByTestId('claw-problems-eth').textContent).not.toMatch(/precompile/)
  expect(screen.getByTestId('claw-go-eth').disabled).toBe(true)
  await user.clear(dest)
  await user.type(dest, '0x0000000000000000000000000000000000000000')
  expect(screen.getByTestId('claw-problems-eth').textContent).toMatch(/null address burns funds/)
  expect(screen.getByTestId('claw-problems-eth').textContent).not.toMatch(/precompile/)
  expect(screen.getByTestId('claw-go-eth').disabled).toBe(true)
})

// ---- resolve STUCK ----
const STUCK_TX = '0x36fdade817f9f181a52d8200201bb8da61413fde25cb34a147c4e9e4c35cadb4'

test('STUCK on mainnet: the attempt and its evidence are shown; typed resolve gates both outcomes; the API route records the outcome', async () => {
  const user = userEvent.setup()
  const { def, events, id } = fixture('09a-stuck')
  install(fakeStack({ id, def: asNetwork(def, 'mainnet'), events, routes: {
    [`POST /api/jobs/${fixture('09a-stuck').id}/chains/eth/resolve`]: () => json(200, { seq: 99 }),
    'POST /relay/eth': ({ body }) => json(200, { jsonrpc: '2.0', id: body.id, result: body.method === 'eth_getTransactionReceipt' ? null : null }),
  } }))
  renderWith(<JobView id={id} jobOptions={FAST} />, { network: 'mainnet' })
  await waitFor(() => expect(screen.getByTestId('phase-eth').dataset.phase).toBe('STUCK'))
  const att = screen.getByTestId(`stuck-attempt-eth-${STUCK_TX}`)
  expect(att.textContent).toContain(STUCK_TX)
  expect(screen.getByTestId('resolve-warning-eth').textContent).toMatch(/Mark failed frees NO cap\. Only chain evidence frees a cap/)
  expect(screen.getByTestId('resolve-cli-eth').textContent).toBe(`vt job resolve ${id} --chain eth --tx ${STUCK_TX} mark-done|mark-failed`)
  expect(resolveCommand(id, 'eth', STUCK_TX, 'mark-failed')).toBe(`vt job resolve ${id} --chain eth --tx ${STUCK_TX} mark-failed`)
  await user.click(screen.getByTestId('stuck-check-eth'))
  await waitFor(() => expect(screen.getByTestId('stuck-evidence-eth').textContent).toMatch(/does not know this transaction/))
  // mainnet: typed `resolve`
  expect(screen.getByTestId('resolve-failed-eth').disabled).toBe(true)
  expect(screen.getByTestId('resolve-done-eth').disabled).toBe(true)
  await user.type(screen.getByTestId('resolve-typed-eth'), 'Resolve')
  expect(screen.getByTestId('resolve-failed-eth').disabled).toBe(true)
  await user.clear(screen.getByTestId('resolve-typed-eth')); await user.type(screen.getByTestId('resolve-typed-eth'), 'resolve')
  await user.click(screen.getByTestId('resolve-failed-eth'))
  await waitFor(() => expect(posts(/\/chains\/eth\/resolve$/)).toHaveLength(1))
  expect(posts(/\/chains\/eth\/resolve$/)[0].body).toEqual({ txId: STUCK_TX, action: 'mark-failed', typed: 'resolve' })
  await waitFor(() => expect(screen.getByTestId('resolve-msg-eth').textContent).toBe('recorded mark-failed'))
})

test('STUCK off mainnet needs no typed word; the body carries no typed member', async () => {
  const user = userEvent.setup()
  const { def, events, id } = fixture('09a-stuck')
  install(fakeStack({ id, def, events, routes: { [`POST /api/jobs/${id}/chains/eth/resolve`]: () => json(409, { error: { guard: 'job.state', message: 'resolve only an open transaction of a STUCK chain' } }) } }))
  renderWith(<JobView id={id} jobOptions={FAST} />)
  await waitFor(() => expect(screen.getByTestId('phase-eth').dataset.phase).toBe('STUCK'))
  expect(screen.queryByTestId('resolve-typed-eth')).toBeNull()
  await user.click(screen.getByTestId('resolve-done-eth'))
  await waitFor(() => expect(posts(/resolve$/)).toHaveLength(1))
  expect(posts(/resolve$/)[0].body).toEqual({ txId: STUCK_TX, action: 'mark-done' })
  await waitFor(() => expect(screen.getByTestId('resolve-msg-eth').textContent).toMatch(/job\.state/))      // the API's refusal is shown
})

test('chainEvidence: ETH receipt / pending / unknown, SOL status / none (read-only relay calls)', async () => {
  const relay = (answers) => ({ rpc: async (chain, method) => answers[method] ?? null })
  expect((await chainEvidence('eth', '0x1', relay({ eth_getTransactionReceipt: { blockNumber: '0x10', status: '0x1' } }))).text).toBe('included in block 16 (status success)')
  expect((await chainEvidence('eth', '0x1', relay({ eth_getTransactionByHash: { hash: '0x1' } }))).text).toMatch(/pending/)
  expect((await chainEvidence('eth', '0x1', relay({}))).found).toBe(false)
  expect((await chainEvidence('sol', 's', relay({ getSignatureStatuses: { value: [{ slot: 5, err: null, confirmationStatus: 'finalized' }] } }))).text).toBe('landed at slot 5 (finalized)')
  expect((await chainEvidence('sol', 's', relay({ getSignatureStatuses: { value: [null] } }))).found).toBe(false)
})

test('ResolveStuck renders nothing unless the chain is STUCK', () => {
  const { container } = render(<ResolveStuck jobId="0011223344556677" chain="eth" cs={{ phase: 'RUNNING', openIntents: [], txs: [] }} network="local" />)
  expect(container.innerHTML).toBe('')
})

test('btc STUCK: only mark-failed is offered (the API refuses mark-done for a commit); the CLI line says so; chainEvidence does not misread btc as a Solana signature', async () => {
  const txId = 'ab'.repeat(32)
  const cs = { phase: 'STUCK', reason: 'input spent elsewhere', openIntents: [txId], txs: [{ copy: 1, part: 1, parts: 2, attempts: [{ txId, state: 'stuck' }] }] }
  renderWith(<ResolveStuck jobId="0011223344556677" chain="btc" cs={cs} network="local" />)
  expect(screen.queryByTestId('resolve-done-btc')).toBeNull()
  expect(screen.getByTestId('resolve-failed-btc')).toBeTruthy()
  expect(screen.getByTestId('resolve-cli-btc').textContent).toBe(`vt job resolve 0011223344556677 --chain btc --tx ${txId} mark-failed`)
  await expect(chainEvidence('btc', txId, { rpc: async () => { throw new Error('must not be called') } })).rejects.toThrow(/Bitcoin/)
})

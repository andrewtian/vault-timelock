// The Arm dialog (W3): READY gating, SKIPPED chains, the mainnet typed checks, the exact over-cap amount (full
// precision, compared in base units), `again`, the >10× warning, and the arm request the API receives.
import { test, expect, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { reduce } from '@vault-timelock/core/job'
import { startingFees } from '@vault-timelock/core/engine/assess.js'
import { copyQuote } from '@vault-timelock/core/engine/arm-caps.js'
import ArmDialog from '../src/jobs/ArmDialog.jsx'
import { armInputs, sameAmount, tenX } from '../src/jobs/armInputs.js'
import { newKey } from '../src/lib/core.js'
import { json, renderWith } from './helpers.jsx'
import { TEXT, created, ethChain, fakeStack, jobDef, journal, ready, solChain } from './job-fakes.js'

const ID = '00112233aabbccdd'
const ethKey = newKey('eth'), solKey = newKey('sol')
let calls
beforeEach(() => {
  calls = []
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), method: init.method || 'GET', body: init.body ? JSON.parse(init.body) : undefined })
    if (String(url) === '/relay/tor') return json(200, { isTor: true, roles: {}, checkedAt: Date.now() })
    if (String(url).endsWith('/arm')) return json(200, { armed: { releaseAt: 1 } })
    return json(404, {})
  }
})
const armPosts = () => calls.filter((c) => c.method === 'POST' && c.url === `/api/jobs/${ID}/arm`)
const cap = (o = {}) => ({ nativeCap: '4000000000000000', usd: 10, priceAt: 1, overCap: false, planned: '0.004', fullCopyCost: '100000000000000', parts: 1, affordable: true, ...o })
const fakeInputs = (chains) => async () => ({ text: TEXT, prices: null, chains })
const stateOf = (def, lines) => reduce(def, journal(lines))

test('the Arm button is disabled until every armed chain is READY; an unarmed chain is shown as SKIPPED', async () => {
  const user = userEvent.setup()
  const def = jobDef({ chains: { eth: ethChain(ethKey.address), sol: solChain(solKey.address) } })
  const none = stateOf(def, [created(ID)])
  const { unmount } = renderWith(<ArmDialog jobId={ID} def={def} state={none} inputs={fakeInputs({})} />)
  expect(screen.getByTestId('arm-open').disabled).toBe(true)                // nothing READY: nothing to arm
  unmount()

  const half = stateOf(def, [created(ID), ...ready('eth', ethKey.address), { chain: 'sol', type: 'lease-acquired', gen: 1, data: { gen: 1, holder: 'cli', ttlMs: 15000 } }, { chain: 'sol', by: 'cli', gen: 1, type: 'key-loaded', data: { address: solKey.address } }])
  expect(half.chains.sol.phase).toBe('AWAITING_FUNDS')
  renderWith(<ArmDialog jobId={ID} def={def} state={half} inputs={fakeInputs({ eth: { cap: cap(), history: 0, error: '' }, sol: { cap: cap({ nativeCap: '70000000', planned: '0.07', fullCopyCost: '20000' }), history: 0, error: '' } })} />)
  await user.click(screen.getByTestId('arm-open'))
  await waitFor(() => expect(screen.getByTestId('arm-cap-eth')).toBeTruthy())
  expect(screen.getByTestId('arm-confirm').disabled).toBe(true)
  expect(screen.getByTestId('arm-problems').textContent).toMatch(/Solana is AWAITING_FUNDS, not READY/)
  expect(screen.getByTestId('arm-chain-sol').dataset.phase).toBe('AWAITING_FUNDS')
  // local: no typed word; the regime line and the permanence of each publish mode are repeated
  expect(screen.queryByTestId('arm-typed')).toBeNull()
  expect(screen.getByTestId('arm-regime').textContent).toMatch(/\[LOCAL\]/)
  expect(screen.getByTestId('permanence-eth').textContent).toMatch(/eth\.calldata\.null: public immediately and permanently/)
  expect(screen.getByTestId('permanence-sol').textContent).toMatch(/validators keep only recent ledger/)
  // arm Ethereum only: Solana becomes SKIPPED (said before it happens)
  await user.click(screen.getByTestId('arm-select-sol'))
  expect(screen.getByTestId('arm-skip-sol').textContent).toMatch(/SKIPPED: final for this job/)
  expect(screen.getByTestId('arm-confirm').disabled).toBe(false)
  await user.clear(screen.getByTestId('arm-countdown')); await user.type(screen.getByTestId('arm-countdown'), '4')
  expect(screen.getByTestId('arm-confirm').disabled).toBe(true)              // 5..300 s
  await user.clear(screen.getByTestId('arm-countdown')); await user.type(screen.getByTestId('arm-countdown'), '15')
  await user.click(screen.getByTestId('arm-confirm'))
  await waitFor(() => expect(armPosts()).toHaveLength(1))
  expect(armPosts()[0].body).toEqual({
    chains: ['eth'], confirm: { typed: null, amounts: {} },
    caps: { eth: { nativeCap: '4000000000000000', usd: 10, priceAt: 1, overCap: false, planned: '0.004' } },
    countdownSec: 15, stagger: [0, 10],
  })
})

test('mainnet: typed broadcast, again for a used key, and the over-cap amount typed exactly (18 decimals, base units)', async () => {
  const user = userEvent.setup()
  const def = jobDef({ network: 'mainnet', chains: { eth: ethChain(ethKey.address) } })
  const st = stateOf(def, [created(ID), ...ready('eth', ethKey.address)])
  const planned = '0.012345678901234567'
  renderWith(<ArmDialog jobId={ID} def={def} state={st} inputs={fakeInputs({ eth: { cap: cap({ nativeCap: '12345678901234567', overCap: true, planned, usd: 30.86 }), history: 3, error: '' } })} />,
    { network: 'mainnet', status: { jobSends: 'ENABLED' } })
  await user.click(screen.getByTestId('arm-open'))
  await waitFor(() => expect(screen.getByTestId('arm-planned-eth')).toBeTruthy())
  expect(screen.getByTestId('arm-planned-eth').textContent).toBe(planned)    // in full, never rounded
  expect(screen.getByTestId('arm-countdown-fixed').textContent).toMatch(/fixed 1:00 countdown/)
  expect(screen.queryByTestId('arm-countdown')).toBeNull()
  expect(screen.getByTestId('arm-history-eth').textContent).toMatch(/already sent 3 transaction/)
  expect(screen.getByTestId('arm-10x-eth').textContent).toMatch(/more than 10× one copy/)
  await waitFor(() => expect(screen.getByTestId('arm-tor').textContent).toMatch(/IsTor ✓/))
  const confirm = () => screen.getByTestId('arm-confirm')
  const problems = () => screen.getByTestId('arm-problems').textContent
  expect(confirm().disabled).toBe(true)
  expect(problems()).toMatch(/type broadcast/)
  await user.type(screen.getByTestId('arm-typed'), 'Broadcast')               // exactly "broadcast"
  expect(problems()).toMatch(/type broadcast/)
  await user.clear(screen.getByTestId('arm-typed')); await user.type(screen.getByTestId('arm-typed'), 'broadcast')
  expect(problems()).not.toMatch(/type broadcast/)
  expect(problems()).toMatch(/type again/)
  await user.type(screen.getByTestId('arm-again'), 'again')
  expect(problems()).toMatch(/type the planned amount exactly/)
  await user.type(screen.getByTestId('arm-amount-eth'), '0.012345678901234568')   // one wei more
  expect(confirm().disabled).toBe(true)
  await user.clear(screen.getByTestId('arm-amount-eth')); await user.type(screen.getByTestId('arm-amount-eth'), '0.0123456789012346')   // rounded: refused
  expect(confirm().disabled).toBe(true)
  await user.clear(screen.getByTestId('arm-amount-eth')); await user.type(screen.getByTestId('arm-amount-eth'), '0.0123456789012345670')   // 19 decimals: refused, as the API does
  expect(confirm().disabled).toBe(true)
  await user.clear(screen.getByTestId('arm-amount-eth')); await user.type(screen.getByTestId('arm-amount-eth'), ` ${planned} `)   // the same base units
  expect(confirm().disabled).toBe(false)
  await user.click(confirm())
  await waitFor(() => expect(armPosts()).toHaveLength(1))
  const body = armPosts()[0].body
  expect(body.confirm).toEqual({ typed: 'broadcast', amounts: { eth: planned } })     // the exact planned string
  expect(body.caps.eth).toEqual({ nativeCap: '12345678901234567', usd: 30.86, priceAt: 1, overCap: true, planned })
  expect('countdownSec' in body || 'stagger' in body).toBe(false)              // mainnet: the API's fixed 60 s
})

test('mainnet: job sends LOCKED in this build, or IsTor ✗, keep Arm disabled', async () => {
  const user = userEvent.setup()
  globalThis.fetch = async (url) => (String(url) === '/relay/tor' ? json(200, { isTor: false, roles: {} }) : json(404, {}))
  const def = jobDef({ network: 'mainnet', chains: { eth: ethChain(ethKey.address) } })
  const st = stateOf(def, [created(ID), ...ready('eth', ethKey.address)])
  renderWith(<ArmDialog jobId={ID} def={def} state={st} inputs={fakeInputs({ eth: { cap: cap(), history: 0, error: '' } })} />, { network: 'mainnet' })
  await user.click(screen.getByTestId('arm-open'))
  await user.type(await screen.findByTestId('arm-typed'), 'broadcast')
  await waitFor(() => expect(screen.getByTestId('arm-problems').textContent).toMatch(/IsTor ✗/))
  expect(screen.getByTestId('arm-problems').textContent).toMatch(/LOCKED in this build/)
  expect(screen.getByTestId('arm-confirm').disabled).toBe(true)
})

test('an API refusal is shown with its guard, and the dialog stays open', async () => {
  const user = userEvent.setup()
  globalThis.fetch = async (url) => (String(url).endsWith('/arm') ? json(400, { error: { guard: 'arm.amount', message: 'not the cap' } }) : json(404, {}))
  const def = jobDef({ chains: { eth: ethChain(ethKey.address) } })
  renderWith(<ArmDialog jobId={ID} def={def} state={stateOf(def, [created(ID), ...ready('eth', ethKey.address)])} inputs={fakeInputs({ eth: { cap: cap(), history: 0, error: '' } })} />)
  await user.click(screen.getByTestId('arm-open'))
  await waitFor(() => expect(screen.getByTestId('arm-confirm').disabled).toBe(false))
  await user.click(screen.getByTestId('arm-confirm'))
  expect((await screen.findByTestId('arm-refused')).textContent).toBe('arm.amount: not the cap')
  expect(screen.getByTestId('arm-dialog')).toBeTruthy()
})

test('sameAmount compares in base units; tenX flags a planned spend over 10 copies', () => {
  expect(sameAmount('0.10', '0.1', 'eth')).toBe(true)
  expect(sameAmount(' 0.1 ', '0.1', 'sol')).toBe(true)
  expect(sameAmount('0.1000000001', '0.1', 'sol')).toBe(false)                // more decimals than SOL has
  expect(sameAmount('1e-1', '0.1', 'eth')).toBe(false)
  expect(sameAmount('', '0', 'eth')).toBe(false)
  expect(tenX(cap({ planned: '0.001', fullCopyCost: '100000000000000' }), 'eth')).toBeNull()        // exactly 10×
  expect(tenX(cap({ planned: '0.0011', fullCopyCost: '100000000000000' }), 'eth')).toEqual({ copies: 11n, one: '0.0001', reserve: '0', spendable: '0.0011' })
})

// W6 (F9-2): a SOL drain lane keeps rent + one claw-back fee; only the rest buys copies.
test('tenX: the SOL drain reserve is taken off before counting copies', () => {
  const c = cap({ planned: '0.002', fullCopyCost: '15000' })               // 2,000,000 lamports planned, one copy 15,000
  expect(tenX(c, 'sol')?.copies).toBe(133n)                                  // the old, wrong count
  const w = tenX(c, 'sol', 895_880n)                                         // rent 890,880 + 5,000 kept
  expect(w).toEqual({ copies: 73n, one: '0.000015', reserve: '0.00089588', spendable: '0.00110412' })
  expect(tenX(cap({ planned: '0.001', fullCopyCost: '15000' }), 'sol', 895_880n)).toBeNull()   // 104,120 spendable = 6 copies
  expect(tenX(cap({ planned: '0.0005', fullCopyCost: '15000' }), 'sol', 895_880n)).toBeNull()  // below the reserve: nothing spendable
})

test('the Arm dialog shows the SOL drain reserve and counts copies from what is spendable', async () => {
  const user = userEvent.setup()
  const def = jobDef({ chains: { sol: solChain(solKey.address, { mode: 'drain' }) } })
  const c = cap({ planned: '0.002', fullCopyCost: '15000', nativeCap: '2000000' })
  renderWith(<ArmDialog jobId={ID} def={def} state={stateOf(def, [created(ID), ...ready('sol', solKey.address)])} inputs={fakeInputs({ sol: { cap: c, history: 0, error: '', reserve: 895_880n } })} />)
  await user.click(screen.getByTestId('arm-open'))
  const reserve = await screen.findByTestId('arm-reserve-sol')
  expect(reserve.textContent).toMatch(/keeps 0\.00089588 SOL \(rent-exempt minimum \+ one claw-back fee\).*0\.00110412 SOL is spendable/)
  const w = screen.getByTestId('arm-10x-sol').textContent
  expect(w).toMatch(/buys about 73 copies/)
  expect(w).not.toMatch(/133/)
})

test('armInputs: a SOL drain lane reports rent + claw-back fee as its reserve; a copies lane none', async () => {
  for (const [mode, want] of [['drain', 890_880n + 5000n], [{ copies: 2 }, 0n]]) {
    const def = jobDef({ chains: { sol: solChain(solKey.address, { mode }) } })
    const st = fakeStack({ id: ID, def, routes: relayRoutes() })
    const out = await armInputs({ def, network: 'local', now: Date.now(), fetch: st.fetch })
    expect(out.chains.sol.error).toBe('')
    expect(out.chains.sol.reserve).toBe(want)
  }
})

test('armInputs: fees and balance through the relay (pre-arm, no text leaves), core computeArmCaps, the key history', async () => {
  const def = jobDef({ chains: { eth: ethChain(ethKey.address, { mode: { copies: 2 } }) } })
  const rpcs = []
  const st = fakeStack({ id: ID, def, routes: {
    'POST /relay/eth': ({ body }) => {
      rpcs.push(body)
      const r = (result) => json(200, { jsonrpc: '2.0', id: body.id, result })
      if (body.method === 'eth_feeHistory') return r({ oldestBlock: '0x10', baseFeePerGas: Array(21).fill('0x3b9aca00'), gasUsedRatio: Array(20).fill(0.5), reward: Array(20).fill(['0x2540be400', '0x2540be400']) })
      if (body.method === 'eth_getBalance') return r('0xde0b6b3a7640000')
      if (body.method === 'eth_getTransactionCount') return r('0x5')
      return json(200, { jsonrpc: '2.0', id: body.id, error: { code: -32601, message: 'no' } })
    },
  } })
  const out = await armInputs({ def, network: 'local', now: Date.now(), fetch: st.fetch })
  expect(out.text).toBe(TEXT)
  const row = out.chains.eth
  expect(row.error).toBe('')
  expect(row.balance).toBe(10n ** 18n)
  expect(row.history).toBe(5)
  expect(row.cap.overCap).toBe(false)
  expect(row.cap.affordable).toBe(true)
  expect(BigInt(row.cap.fullCopyCost)).toBeGreaterThan(0n)
  expect(row.cap.planned).toMatch(/^0\.\d+$/)
  // before Arm nothing text-bearing goes to the relay: no estimateGas, no eth_call
  expect(rpcs.map((r) => r.method)).not.toContain('eth_estimateGas')
  expect(rpcs.map((r) => r.method)).not.toContain('eth_call')
  expect(JSON.stringify(rpcs)).not.toContain(Buffer.from(TEXT).toString('hex').slice(0, 40))
})

// W6 (M1 issue 2): the page prices arm with core's startingFees, the one source the CLI and the engine use — for both chains.
const relayRoutes = () => {
  const r = (body, result) => json(200, { jsonrpc: '2.0', id: body.id, result })
  return {
    'POST /relay/eth': ({ body }) => {
      if (body.method === 'eth_feeHistory') {
        const n = Number(BigInt(body.params[0])), pcts = body.params[2] || []
        return r(body, { oldestBlock: '0x64', baseFeePerGas: Array.from({ length: n + 1 }, (_, i) => '0x' + (BigInt(7 + (i % 13)) * 10n ** 9n).toString(16)), gasUsedRatio: Array(n).fill(0.5), reward: Array.from({ length: n }, (_, i) => pcts.map((_p, j) => '0x' + (BigInt(1 + ((i + j) % 5)) * 10n ** 8n).toString(16))) })
      }
      if (body.method === 'eth_getBalance') return r(body, '0x' + (5n * 10n ** 18n).toString(16))
      if (body.method === 'eth_getTransactionCount') return r(body, '0x0')
      return json(200, { jsonrpc: '2.0', id: body.id, error: { code: -32601, message: 'no' } })
    },
    'POST /relay/sol': ({ body }) => {
      if (body.method === 'getMinimumBalanceForRentExemption') return r(body, 890880)
      if (body.method === 'getBalance') return r(body, { context: { slot: 1 }, value: 5_000_000_000 })
      if (body.method === 'getSignaturesForAddress') return r(body, [])
      return json(200, { jsonrpc: '2.0', id: body.id, error: { code: -32601, message: 'no' } })
    },
  }
}
const tuples = []
for (const network of ['local', 'testnet', 'mainnet']) for (const strategy of ['passive', 'economy', 'prompt']) for (const chain of ['eth', 'sol']) tuples.push([network, strategy, chain])
const seen = {}

test.each(tuples)('armInputs on %s with %s on %s equals core startingFees (page, CLI and engine price arm alike)', async (network, strategy, chain) => {
  const key = chain === 'eth' ? ethKey : solKey
  const mk = chain === 'eth' ? ethChain : solChain
  const def = jobDef({ network, chains: { [chain]: mk(key.address, { mode: { copies: 2 }, feeStrategy: strategy }) } })
  expect(def.chains[chain].feeStrategy).toBe(strategy)
  const st = fakeStack({ id: ID, def, network, routes: relayRoutes() })
  const out = await armInputs({ def, network, now: Date.now(), fetch: st.fetch })
  const row = out.chains[chain]
  expect(row.error).toBe('')
  const sf = await startingFees(network, chain, strategy)                  // same relay client, same fake chain
  const want = copyQuote(chain, def.chains[chain], TEXT, chain === 'eth' ? sf.fees : sf.fees, { network })
  expect(row.cap.fullCopyCost).toBe(String(want.a.perCopy))
  expect(row.cap.parts).toBe(want.parts)
  if (chain === 'sol') expect(sf.fees.priorityLamports).toBe(strategy === 'prompt' ? 12500 : 0)
  seen[`${network}/${chain}/${strategy}`] = row.cap.fullCopyCost
})

test('the startingFees fixtures tell the strategies apart (so the equality above has teeth)', () => {
  for (const network of ['local', 'testnet', 'mainnet']) {
    expect(seen[`${network}/sol/prompt`]).not.toBe(seen[`${network}/sol/passive`])
    expect(new Set(['passive', 'economy', 'prompt'].map((x) => seen[`${network}/eth/${x}`])).size).toBeGreaterThan(1)
  }
})

// E5 / M1.1a: the page prices prompt arm under the job's maxTipGwei, like `vt job arm` and the executor (the fake chain pays an 8 gwei tip).
test('armInputs prices the prompt tip under the job\'s maxTipGwei (a 5 gwei cap), like core startingFees', async () => {
  const routes = relayRoutes()
  const base = routes['POST /relay/eth']
  const gwei8 = '0x' + (8n * 10n ** 9n).toString(16)
  routes['POST /relay/eth'] = (ctx) => {
    if (ctx.body.method !== 'eth_feeHistory') return base(ctx)
    const n = Number(BigInt(ctx.body.params[0])), pcts = ctx.body.params[2] || []
    return json(200, { jsonrpc: '2.0', id: ctx.body.id, result: { oldestBlock: '0x64', baseFeePerGas: Array(n + 1).fill('0x' + (10n ** 9n).toString(16)), gasUsedRatio: Array(n).fill(0.5), reward: Array.from({ length: n }, () => pcts.map(() => gwei8)) } })
  }
  const run = async (maxTipGwei) => {
    const def = jobDef({ network: 'local', chains: { eth: ethChain(ethKey.address, { mode: { copies: 2 }, feeStrategy: 'prompt', ...(maxTipGwei === undefined ? {} : { maxTipGwei }) }) } })
    const out = await armInputs({ def, network: 'local', now: Date.now(), fetch: fakeStack({ id: ID, def, network: 'local', routes }).fetch })
    expect(out.chains.eth.error).toBe('')
    return { def, row: out.chains.eth }
  }
  const dflt = await run(undefined), five = await run(5)
  const sf3 = await startingFees('local', 'eth', 'prompt'), sf5 = await startingFees('local', 'eth', 'prompt', { maxTipGwei: 5 })
  expect([sf3.fees.tip, sf5.fees.tip]).toEqual([3n * 10n ** 9n, 5n * 10n ** 9n])
  expect(dflt.row.cap.fullCopyCost).toBe(String(copyQuote('eth', dflt.def.chains.eth, TEXT, sf3.fees, { network: 'local' }).a.perCopy))
  expect(five.row.cap.fullCopyCost).toBe(String(copyQuote('eth', five.def.chains.eth, TEXT, sf5.fees, { network: 'local' }).a.perCopy))
  expect(five.row.cap.fullCopyCost).not.toBe(dflt.row.cap.fullCopyCost)
})

// W7 / F10-1: the passive window an RPC limit cut short is stated on the ETH line; a full window shows nothing.
const limitedRoutes = (limit) => {   // eth_feeHistory served only when the range ends at "latest", at most `limit` blocks (null = no limit)
  const routes = relayRoutes(), base = routes['POST /relay/eth']
  routes['POST /relay/eth'] = (ctx) => {
    const { body } = ctx
    if (body.method !== 'eth_feeHistory') return base(ctx)
    if (limit !== null && body.params[1] !== 'latest') return json(200, { jsonrpc: '2.0', id: body.id, error: { code: -32602, message: 'requested block range is out of bounds' } })
    const n = Math.min(Number(BigInt(body.params[0])), limit ?? 7200), pcts = body.params[2] || []
    return json(200, { jsonrpc: '2.0', id: body.id, result: { oldestBlock: '0x2710', baseFeePerGas: Array(n + 1).fill('0x' + (10n ** 9n).toString(16)), gasUsedRatio: Array(n).fill(0.5), reward: Array.from({ length: n }, () => pcts.map(() => '0x' + (10n ** 9n).toString(16))) } })
  }
  return routes
}
test.each([[1024, '(window 1024 blocks, RPC limit)'], [null, '']])('armInputs: a passive ETH lane on an RPC with fee-history limit %s carries the window note %j', async (limit, want) => {
  const def = jobDef({ network: 'local', chains: { eth: ethChain(ethKey.address, { mode: { copies: 2 }, feeStrategy: 'passive' }) } })
  const out = await armInputs({ def, network: 'local', now: Date.now(), fetch: fakeStack({ id: ID, def, network: 'local', routes: limitedRoutes(limit) }).fetch })
  expect(out.chains.eth.error).toBe('')
  expect(out.chains.eth.windowNote).toBe(want)
})

test('the Arm dialog appends "(window N blocks, RPC limit)" to the ETH line when truncated, and nothing for a full window', async () => {
  const user = userEvent.setup()
  const def = jobDef({ chains: { eth: ethChain(ethKey.address, { mode: { copies: 2 } }) } })
  const st = stateOf(def, [created(ID), ...ready('eth', ethKey.address)])
  const { unmount } = renderWith(<ArmDialog jobId={ID} def={def} state={st} inputs={fakeInputs({ eth: { cap: cap(), history: 0, error: '', reserve: 0n, windowNote: '(window 1024 blocks, RPC limit)' } })} />)
  await user.click(screen.getByTestId('arm-open'))
  expect((await screen.findByTestId('arm-window-eth')).textContent).toMatch(/\(window 1024 blocks, RPC limit\)/)
  expect(screen.getByTestId('arm-cap-eth').textContent).toMatch(/planned spend .*\(window 1024 blocks, RPC limit\)/)
  unmount()
  renderWith(<ArmDialog jobId={ID} def={def} state={st} inputs={fakeInputs({ eth: { cap: cap(), history: 0, error: '', reserve: 0n, windowNote: '' } })} />)
  await user.click(screen.getByTestId('arm-open'))
  await screen.findByTestId('arm-cap-eth')
  expect(screen.queryByTestId('arm-window-eth')).toBeNull()
  expect(screen.getByTestId('arm-cap-eth').textContent).not.toMatch(/window/)
})

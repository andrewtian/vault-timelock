// armInputs for a btc lane (Wfix5): core's startingFees(network, 'btc', ...) prices one copy; the balance is the lane's.
// startingFees and balanceOf are replaced (no node here); everything else is core's real code.
import { test, expect, vi } from 'vitest'

const calls = { fees: [] }
vi.mock('@vault-timelock/core/engine/assess.js', async (orig) => ({
  ...(await orig()),
  startingFees: vi.fn(async (network, chain, strategy, inputs) => { calls.fees.push({ network, chain, strategy, inputs }); return { chain, fees: { rate: 9n, commitFee: 1800n, revealFee: 1000n, postage: 546n }, perCopy: 3346n } }),
}))
vi.mock('@vault-timelock/core/chains/btc.js', async (orig) => ({ ...(await orig()), balanceOf: vi.fn(async () => 123456n) }))

const { armInputs } = await import('../src/jobs/armInputs.js')
const { normalizeJob, sha256Hex } = await import('@vault-timelock/core/job')
const { fromSecret } = await import('../src/lib/core.js')
const { json } = await import('./helpers.jsx')

test('btc row: fee rate, worst-case fees, postage, perCopy, the lane balance and a sat cap', async () => {
  const key = fromSecret('btc', '22'.repeat(32), 'local')
  const text = 'btc arm line\n'
  const def = normalizeJob({ format: 'vt-job/1', network: 'local', name: 'a', messageSha256: sha256Hex(text), messageBytes: text.length,
    chains: { btc: { mode: { copies: 3 }, keyAddress: key.address, budgetUsd: 5, distinctCopies: true, clawbackTo: null, maxFeeRateSatVb: 20 } } }, { network: 'local' }).def
  const fetch = async (url) => (String(url).startsWith('/api/messages/') ? new Response(text, { status: 200 }) : json(404, {}))
  const out = await armInputs({ def, network: 'local', fetch })
  const row = out.chains.btc
  expect(row.error).toBe('')
  expect(row.btc).toEqual({ rate: 9n, commitFee: 1800n, revealFee: 1000n, postage: 546n, perCopy: 3346n })
  expect(row.balance).toBe(123456n)
  expect(row.cap.parts).toBe(2)
  expect(BigInt(row.cap.nativeCap)).toBeGreaterThan(0n)
  const c = calls.fees[0]
  expect([c.network, c.chain, c.inputs.maxFeeRateSatVb]).toEqual(['local', 'btc', 20])
  expect(c.inputs.parts).toHaveLength(2); expect(c.inputs.altParts).toHaveLength(2)      // the widest [copy 3/3] marker is priced too
})

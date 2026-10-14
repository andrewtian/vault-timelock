// E5: the passive ETH base-fee window must survive an RPC that limits fee history (anvil, some public providers serve only
// about the newest 1,024 blocks), and a job's maxTipGwei prices the prompt starting fee. ALL DATA IS SYNTHETIC: a fake
// chain of LATEST blocks whose block k has base fee (k + 1) wei·10⁶, behind the fake relay.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as eth from '../../src/chains/eth.js'
import { assessChain, startingFees } from '../../src/engine/assess.js'
import { ethPassiveTarget } from '../../src/chains/economy.js'
import { ethParts, utf8 } from '../../src/chains/plan.js'
import { fakeRelay } from './fakes.ts'

const GWEI = 10n ** 9n
const hx = (n: bigint | number): string => `0x${BigInt(n).toString(16)}`
const baseOf = (k: number): bigint => BigInt(k + 1) * 1_000_000n
// A chain of blocks 0..latest. limit: the RPC serves eth_feeHistory only when `latest - newest < limit` (null = no limit).
function chain(latest: number, limit: number | null, o: { firstFails?: boolean; shortOlder?: boolean } = {}) {
  const calls: Array<{ count: number; newest: number }> = []
  const handler = (m: string, p: any[]): unknown => {
    if (m === 'eth_getBalance') return hx(10n ** 18n)
    if (m !== 'eth_feeHistory') return undefined
    const count = Number(BigInt(p[0])), newest = p[1] === 'latest' ? latest : Number(BigInt(p[1]))
    calls.push({ count, newest })
    if (o.firstFails && calls.length === 1) throw new Error('-32603: node is syncing')
    if (limit !== null && latest - newest >= limit) throw new Error('-32602: requested block range is out of bounds')
    if (o.shortOlder && calls.length > 1) return { oldestBlock: hx(newest), baseFeePerGas: [hx(baseOf(newest))] }
    const n = Math.min(count, newest + 1), oldest = newest - n + 1
    return { oldestBlock: hx(oldest), baseFeePerGas: Array.from({ length: n + 1 }, (_, i) => hx(baseOf(oldest + i))), reward: Array.from({ length: n }, () => (p[2] as unknown[]).map(() => hx(2n * GWEI))) }
  }
  return { calls, handler }
}
const relayFor = (handler: (m: string, p: any[]) => unknown) => fakeRelay({ eth: handler })

test('fee history limited to ~1,024 blocks: the older chunk errors, the target comes from the first chunk, truncated=true, windowBlocks=1024', async () => {
  const c = chain(5000, 1024)
  relayFor(c.handler)
  const w = await eth.baseFeeWindow()
  assert.equal(w.truncated, true)
  assert.equal(w.windowBlocks, 1024)
  assert.equal(w.bases.length, 1024)
  assert.equal(w.latest, 5000)
  assert.equal(w.nextBase, baseOf(5001))
  assert.equal(c.calls.length, 2, 'one good call, ONE failing older call, no retry of an older chunk')
  const r = await startingFees('local', 'eth', 'passive')
  const target = ethPassiveTarget(Array.from({ length: 1024 }, (_, i) => baseOf(5000 - 1023 + i)))
  assert.deepEqual([r.fees.target, r.fees.windowBlocks, r.fees.truncated], [target, 1024, true])
  assert.equal(r.fees.maxFee, target + 1_000_000n)
})

test('a later chunk that returns < 2 base fees also ends the walk with what was collected', async () => {
  relayFor(chain(5000, null, { shortOlder: true }).handler)
  const w = await eth.baseFeeWindow()
  assert.deepEqual([w.truncated, w.windowBlocks], [true, 1024])
})

test('the first chunk failing still throws engine.fee-window-first (error or < 2 base fees)', async () => {
  relayFor(chain(5000, null, { firstFails: true }).handler)
  await assert.rejects(eth.baseFeeWindow(), (e: Error & { guardId?: string }) => e.guardId === 'engine.fee-window-first')
  relayFor(() => ({ oldestBlock: '0x0', baseFeePerGas: ['0x1'] }))
  await assert.rejects(eth.baseFeeWindow(), (e: Error & { guardId?: string }) => e.guardId === 'engine.fee-window-first')
  relayFor((m) => (m === 'eth_feeHistory' ? undefined : hx(1)))   // the node does not answer eth_feeHistory at all
  await assert.rejects(startingFees('local', 'eth', 'passive'), (e: Error & { guardId?: string }) => e.guardId === 'engine.fee-window-first')
})

test('a full window (no RPC limit) gives truncated=false and windowBlocks = 7,200; a young chain (< 1,024 blocks) too', async () => {
  const c = chain(20_000, null)
  relayFor(c.handler)
  const w = await eth.baseFeeWindow()
  assert.deepEqual([w.truncated, w.windowBlocks, w.bases.length], [false, 7200, 7200])
  assert.equal(c.calls.length, 8)
  relayFor(chain(300, 1024).handler)
  const y = await eth.baseFeeWindow()
  assert.deepEqual([y.truncated, y.windowBlocks], [false, 301])
})

test('assessChain on a limited RPC: the passive precheck passes and says "passive window N blocks (RPC limit)"', async () => {
  relayFor(chain(5000, 1024).handler)
  const parts = ethParts(utf8('hello'))
  const a = await assessChain('eth', parts, { real: false, network: 'local', address: '0x' + '11'.repeat(20), strategy: 'passive', gasRule: { amsterdam: false, toSelf: false }, msSha: 'x', cfgKey: 'k' } as any) as any
  assert.equal(a.fees.truncated, true)
  assert.match(a.cost, /passive window 1024 blocks \(RPC limit\)/)
})

test('prompt: feeInputs.maxTipGwei caps the starting tip like the executor will; absent = the 3 gwei default', async () => {
  relayFor(chain(5000, null).handler)   // every reward is 2 gwei
  const dflt = await startingFees('local', 'eth', 'prompt')
  assert.deepEqual([dflt.fees.tip, (dflt.fees as any).tipCap], [2n * GWEI, 3n * GWEI])
  const capped = await startingFees('local', 'eth', 'prompt', { maxTipGwei: 0.5 })
  assert.deepEqual([capped.fees.tip, (capped.fees as any).tipCap], [GWEI / 2n, GWEI / 2n])
  const str = await startingFees('local', 'eth', 'prompt', { maxTipGwei: '1.25' })
  assert.equal((str.fees as any).tipCap, 1_250_000_000n)
  const wide = await startingFees('local', 'eth', 'prompt', { maxTipGwei: 100 })
  assert.equal(wide.fees.tip, 2n * GWEI)
})

test('maxTipGwei outside 0.1..100 or not a decimal is refused (engine.fee-tip-input), never priced at a default', async () => {
  relayFor(chain(5000, null).handler)
  for (const bad of [0.05, 0, -1, 101, NaN, Infinity, '1e2', '0x10', '', '1.1234567891']) {
    await assert.rejects(startingFees('local', 'eth', 'prompt', { maxTipGwei: bad as number }), (e: Error & { guardId?: string }) => e.guardId === 'engine.fee-tip-input', String(bad))
  }
})

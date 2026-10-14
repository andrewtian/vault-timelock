// One fee formula (I2, S4 review m-2): for every intent the API ACCEPTS, the ticket's `f` (what the relay lets the signed
// bytes cost at most: gas × maxFee ≤ f, 5,000 + ⌈limit × price / 10⁶⌉ ≤ f) equals the worst case the API's cap ledger
// reserved for that attempt (ledger.ts, worstCaseFee), and equals core's worstFeeOf of the same data (the reducer's and the
// engine cap ledger's worst case: the API's fee floors make a SOL declared fee at least its compute-budget fee). A
// claw-back's reservation is f + its value. Random intents (seeded), both chains, through the real HTTP send path:
// refused ones mint nothing and reserve nothing.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { worstFeeOf } from '@vault-timelock/core/job'
import { ethGasBudget, ethGasFormula, solCuEstimate, solCuLimit } from '@vault-timelock/core/chains/plan.js'
import { verifyTicket } from '../src/tickets.ts'
import { CLAWBACK_TO, JOB2, JOB2_INPUT, TICKET_KEY, armed, call, ethTx, guardOf, idOf, plannedParts, plannedPayloads, rawOf, solHash, solSig, startApi } from './helpers.ts'
import type { TestApi } from './helpers.ts'

process.env.NODE_ENV = 'test'

function rng(seed: number): { r(): number; ri(lo: number, hi: number): number } {
  let x = seed >>> 0 || 1
  const r = (): number => { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; return x / 4294967296 }
  return { r, ri: (lo, hi) => lo + Math.floor(r() * (hi - lo + 1)) }
}

async function leased(t: { after(fn: () => Promise<void>): void }, input: Record<string, unknown> = JOB2_INPUT): Promise<TestApi> {
  const a = await startApi({ jobs: [input] })
  t.after(() => a.close())
  const id = idOf(input)
  await armed(a, id, ['eth', 'sol'])
  for (const c of ['eth', 'sol']) assert.equal((await call(a.port, { path: `/jobs/${id}/chains/${c}/lease`, body: { op: 'acquire', holder: 'cli' } })).status, 200)
  return a
}
// JOB2 with both lanes until drained: every copy is a new (copy, part 1) group, each with its own planned part (PF-S I-1)
const BOTH_DRAIN = { ...JOB2_INPUT, name: 'fee agreement: both lanes until drained',
  chains: { ...(JOB2_INPUT.chains as Record<string, Record<string, unknown>>), sol: { ...(JOB2_INPUT.chains as Record<string, Record<string, unknown>>).sol, mode: 'drain' } } }
const DRAIN_ID = idOf(BOTH_DRAIN)

test('for random accepted intents (both chains), ticket f = the cap ledger\'s reservation = core worstFeeOf; refused ones reserve nothing', async (t) => {
  for (const seed of [3, 17, 20261009]) {
    const a = await leased(t, BOTH_DRAIN)
    const { r, ri } = rng(seed)
    const job = await a.api.registry.load(DRAIN_ID)
    let accepted = 0, refused = 0, n = 0
    const next: Record<string, number> = { eth: 1, sol: 1 }   // PF-S fix round 1 (N-2): the next copy of each chain (a refused one is tried again)
    for (let i = 0; i < 60; i++) {
      const chain = r() < 0.5 ? 'eth' : 'sol'
      n++
      // both lanes until drained: a new (copy, part) group each time, the planned part of that copy (PF-S I-1); ETH: its own nonce too
      const copy = next[chain], part = 1, parts = 1, payloadSha256 = plannedParts(BOTH_DRAIN, chain, copy)[0]
      const planned = plannedPayloads(BOTH_DRAIN, chain, copy)[0], size = planned.length
      let data: Record<string, unknown>
      // PF-S fix round 2 (R1-1): the fee members within vt's plan (ticket.fee-plan), a few outside it (refused, nothing reserved):
      // ETH gas in [formula, budget] of the planned part under either local fork; SOL a CU limit up to the model's, a price up to
      // the lane's maxCuPrice (JOB2: 2,000,000)
      const outside = r() < 0.1
      if (chain === 'eth') {
        const rule = { amsterdam: r() < 0.5, toSelf: false }
        const lo = Number(ethGasFormula(size, rule)), hi = Number(ethGasBudget(size, rule))
        const top = Math.max(...[false, true].map((amsterdam) => Number(ethGasBudget(size, { amsterdam, toSelf: false }))))   // above both forks' windows
        const low = Math.min(...[false, true].map((amsterdam) => Number(ethGasFormula(size, { amsterdam, toSelf: false }))))   // below both
        const gas = String(outside ? (r() < 0.5 ? low - ri(1, 2_000) : ri(top + 1, 2_000_000)) : ri(lo, hi))
        const maxFee = String(ri(1, 50) * 10 ** ri(6, 9)), tip = r() < 0.2 ? maxFee : '1'
        data = { txId: ethTx(1000 + n), copy, part, parts, attempt: 1, replaces: null, rawSha256: rawOf(1000 + n), payloadSha256, reserved: '1',
          eth: { nonce: 1000 + n, tip, maxFee, gas, to: '0x0000000000000000000000000000000000000000' } }
      } else {
        const cuMax = solCuLimit(solCuEstimate(planned))
        const cuLimit = outside && r() < 0.5 ? ri(cuMax + 1, 1_400_000) : ri(1, cuMax)
        const cuPrice = outside ? ri(2_000_001, 8_000_000) : r() < 0.3 ? 0 : ri(1, 2_000_000)
        const implied = 5000n + (BigInt(cuLimit) * BigInt(cuPrice) + 999_999n) / 1_000_000n
        const fee = r() < 0.15 ? implied - 1n : implied + BigInt(r() < 0.5 ? 0 : ri(1, 20_000)) // some under the floor: refused
        data = { txId: solSig(1000 + n), copy, part, parts, attempt: 1, replaces: null, rawSha256: rawOf(1000 + n), payloadSha256, reserved: '1',
          sol: { blockhash: solHash(1000 + n), lastValidBlockHeight: 1000, cuPrice, cuLimit, rung: null, fee: String(fee) } }
      }
      const res = await call(a.port, { path: `/jobs/${DRAIN_ID}/chains/${chain}/events`, body: { gen: 1, type: 'intent', data } })
      const ledger = a.api.registry.ledgerOf(job, chain)
      const txId = data.txId as string
      if (res.status !== 200) {
        refused++
        assert.ok(['event.shape', 'arm.amount', 'ticket.fee-plan'].includes(String(guardOf(res))), res.text)
        if (outside) assert.ok(['ticket.fee-plan', 'event.shape', 'arm.amount'].includes(String(guardOf(res))), res.text)
        assert.equal(ledger.byTx.get(txId), undefined, 'a refused intent reserves nothing')
        continue
      }
      assert.ok(!outside, `seed ${seed} ${chain} #${i}: fee members outside the plan were accepted`)
      accepted++
      next[chain]++
      const p = verifyTicket(TICKET_KEY, (res.json as { ticket: string }).ticket, a.clock.now())
      const reserved = ledger.byTx.get(txId)!.fee
      assert.equal(BigInt(p.f), reserved, `seed ${seed} ${chain} #${i}: f = the reservation`)
      assert.equal(BigInt(p.f), worstFeeOf(data), `seed ${seed} ${chain} #${i}: f = core worstFeeOf`)
    }
    assert.ok(accepted >= 10 && refused >= 1, `seed ${seed}: ${accepted} accepted, ${refused} refused`)
  }
})

test('a claw-back\'s ticket f + value = its reservation in the cap ledger (ETH and SOL)', async (t) => {
  const a = await leased(t)
  const job = await a.api.registry.load(JOB2)
  // settle both chains (nothing in flight), then one claw-back each
  for (const c of ['eth', 'sol'] as const) {
    assert.equal((await call(a.port, { path: `/jobs/${JOB2}/chains/${c}/events`, body: { gen: 1, type: c === 'eth' ? 'drained' : 'copies-done', data: c === 'eth' ? { balance: '1', nextCost: '2', copy: 1 } : { copies: 3 } } })).status, 200)
  }
  const eth = { txId: ethTx(7), to: CLAWBACK_TO, value: '12345', rawSha256: rawOf(7), eth: { nonce: 7, tip: '1', maxFee: '3000000', gas: '21000', to: CLAWBACK_TO } }
  const sol = { txId: solSig(7), to: 'G147qVmzynHL3EjQ8tvBGDms7u6FDCWbFfFmzNMZmg1x', value: '777', rawSha256: rawOf(8), sol: { blockhash: solHash(7), lastValidBlockHeight: 1, cuPrice: 3, cuLimit: 495, rung: null, fee: '5002' } }   // a priced transfer as the engine sizes it (PF-S fix round 3, R2-1)
  for (const [c, data] of [['eth', eth], ['sol', sol]] as const) {
    const res = await call(a.port, { path: `/jobs/${JOB2}/chains/${c}/events`, body: { gen: 1, type: 'clawback-intent', data } })
    assert.equal(res.status, 200, res.text)
    const p = verifyTicket(TICKET_KEY, (res.json as { ticket: string }).ticket, a.clock.now())
    const att = a.api.registry.ledgerOf(job, c).byTx.get(data.txId)!
    assert.equal(BigInt(p.f), att.fee)
    assert.equal(BigInt(p.f) + BigInt(p.value!), att.fee + att.value)
    assert.equal(a.api.registry.ledgerOf(job, c).inFlight, att.fee + att.value)
    assert.equal(BigInt(p.f), worstFeeOf(data))
  }
})

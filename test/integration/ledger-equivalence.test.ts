// I2: the core-vs-API cap ledger equivalence (ledger-compare.ts). Journals are made by S2's REAL job service (createRegistry
// over a temp state dir; every line through its gate, so only journals the API accepts are compared), then folded by
// both ledgers line by line. Pinned:
//   · the known conservative differences, one constructed case each, with the exact amounts (sol-resign, claim-held,
//     claw-failed, claw-value) — the API is above core by exactly the documented amount;
//   · the equal-by-construction case (a fee-less landing, then its fee): both stay at the worst case;
//   · seeded random sequences on both chains (intents, bumps, re-signs, claims, landings with and without fees,
//     reconciles, stuck / resolve, settles, claw-back families with and without the typed amount): after EVERY accepted
//     line the API total is ≥ core's, and with no claim, failure, re-sign or value mismatch involved they are equal.
// Synthetic data only; nothing listens but the in-process API on 127.0.0.1 port 0 (helpers.startApi).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { Chain, JobDef, JournalEvent } from '../../packages/core/src/contracts/index.ts'
import { ethGasBudget } from '../../packages/core/src/chains/plan.js'
import { CLAWBACK_TO, JOB2_INPUT, armed, call, ethTx, idOf, plannedCuLimit, plannedGas, plannedParts, plannedPayloads, rawOf, solHash, solSig, startApi } from '../../api/test/helpers.ts'
import type { TestApi } from '../../api/test/helpers.ts'
import { createComparator } from './ledger-compare.ts'
import type { Comparator, Totals } from './ledger-compare.ts'

process.env.NODE_ENV = 'test'
const NULL = '0x0000000000000000000000000000000000000000'
const SOL_DEST = 'G147qVmzynHL3EjQ8tvBGDms7u6FDCWbFfFmzNMZmg1x'
type T = { after(fn: () => Promise<void>): void }
// JOB2 with both lanes until drained: every intent is a new (copy, part 1) group of its own, carrying the part the API plans for that
// copy (PF-S I-1: the API binds an eth / sol intent to its own plan of the stored message)
const INPUT = { ...JOB2_INPUT, name: 'ledger equivalence: both lanes until drained',
  chains: { ...(JOB2_INPUT.chains as Record<string, Record<string, unknown>>), sol: { ...(JOB2_INPUT.chains as Record<string, Record<string, unknown>>).sol, mode: 'drain' } } }
const ID = idOf(INPUT)

interface Run { a: TestApi; def: JobDef; cmp: Comparator; seen: number; append(chain: Chain, type: string, data: Record<string, unknown>, o?: { confirm?: unknown; by?: 'cli' | 'operator' }): Promise<boolean>; totals(c: Chain): Totals }
async function run(t: T): Promise<Run> {
  const a = await startApi({ jobs: [INPUT] })
  t.after(() => a.close())
  await armed(a, ID, ['eth', 'sol'])
  const job = await a.api.registry.load(ID)
  const cmp = createComparator(job.def)
  t.after(async () => cmp.close())
  const r: Run = {
    a, def: job.def, cmp, seen: 0,
    async append(chain, type, data, o = {}) {
      try {
        await job.journal.append({ chain, by: o.by ?? 'cli', gen: o.by === 'operator' ? null : 1, type: type as JournalEvent['type'], data }, o.confirm === undefined ? undefined : { clawbackConfirm: o.confirm })
      } catch (e) {
        if ((e as { guardId?: string }).guardId === undefined) throw e
        return false
      }
      return true
    },
    totals(c) {
      const all = job.journal.all()
      for (; r.seen < all.length; r.seen++) cmp.apply(all[r.seen])
      return cmp.totals(c)!
    },
  }
  return r
}
// PF-S fix round 2 (R1-1): the fee members are within the API's plan of the part (ticket.fee-plan): ETH gas in [the formula, the
// budget] of the planned payload (pre-Amsterdam, local's default), SOL the model's CU limit for it
const gasWindow = (copy: number): [number, number] =>
  [Number(plannedGas(INPUT, copy)), Number(ethGasBudget(plannedPayloads(INPUT, 'eth', copy)[0].length, { amsterdam: false, toSelf: false }))]
const ethI = (n: number, o: { copy?: number; attempt?: number; replaces?: string | null; nonce?: number; maxFee?: string; gas?: string } = {}) => ({
  txId: ethTx(n), copy: o.copy ?? n, part: 1, parts: 1, attempt: o.attempt ?? 1, replaces: o.replaces ?? null, rawSha256: rawOf(n), payloadSha256: plannedParts(INPUT, 'eth', o.copy ?? n)[0], reserved: '1',
  eth: { nonce: o.nonce ?? n, tip: '1', maxFee: o.maxFee ?? '1000000000', gas: o.gas ?? plannedGas(INPUT, o.copy ?? n), to: NULL } })
const W1 = BigInt(plannedGas(INPUT, 1)) * 1_000_000_000n   // ethI(1)'s worst case: the planned gas × 1 gwei
const solI = (n: number, o: { copy?: number; part?: number; attempt?: number; replaces?: string | null; fee?: number } = {}) => ({
  txId: solSig(n), copy: o.copy ?? 1, part: o.part ?? 1, parts: 1, attempt: o.attempt ?? 1, replaces: o.replaces ?? null, rawSha256: rawOf(n), payloadSha256: plannedParts(INPUT, 'sol', o.copy ?? 1)[(o.part ?? 1) - 1], reserved: '1',
  sol: { blockhash: solHash(n), lastValidBlockHeight: 1000, cuPrice: 0, cuLimit: plannedCuLimit(INPUT, o.copy ?? 1, o.part ?? 1), rung: null, fee: String(o.fee ?? 5000) } })
const ethClaw = (n: number, value: string, maxFee = '1000000000') => ({ txId: ethTx(n), to: CLAWBACK_TO, value, rawSha256: rawOf(n), eth: { nonce: n, tip: '1', maxFee, gas: '21000', to: CLAWBACK_TO } })
async function ok(r: Run, chain: Chain, type: string, data: Record<string, unknown>, o?: { confirm?: unknown; by?: 'cli' | 'operator' }): Promise<void> {
  assert.equal(await r.append(chain, type, data, o), true, `${chain} ${type} refused: ${JSON.stringify(data).slice(0, 120)}`)
}
// ETH settled: copy 1 landed (fee 1,000) and read back, then drained.
async function ethDrained(r: Run): Promise<void> {
  await ok(r, 'eth', 'intent', ethI(1))
  await ok(r, 'eth', 'included', { txId: ethTx(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '1000', ms: 1 })
  await ok(r, 'eth', 'readback', { txId: ethTx(1), ok: true, detail: 'x' })
  await ok(r, 'eth', 'drained', { balance: '1', nextCost: '2', copy: 2 })
}

test('pinned: sol-resign — two SOL signatures of one (copy, part) in flight: the API holds both, core the larger', async (t) => {
  const r = await run(t)
  await ok(r, 'sol', 'intent', solI(1, { fee: 6000 }))
  await ok(r, 'sol', 'intent', solI(2, { attempt: 2, replaces: solSig(1), fee: 7000 }))
  const x = r.totals('sol')
  assert.deepEqual([x.api, x.core], [13_000n, 7_000n])
})

test('pinned: claim-held — a SOL signature claimed rejected, its re-sign landed: core frees the group, the API keeps the claim until a reconcile', async (t) => {
  const r = await run(t)
  await ok(r, 'sol', 'intent', solI(1, { fee: 6000 }))
  await ok(r, 'sol', 'sent', { txId: solSig(1), outcome: 'rejected', reason: 'claimed' })
  await ok(r, 'sol', 'intent', solI(2, { attempt: 2, replaces: solSig(1), fee: 7000 }))
  await ok(r, 'sol', 'included', { txId: solSig(2), copy: 1, part: 1, attempt: 2, block: '9', fee: '5000', ms: 1 })
  let x = r.totals('sol')
  assert.deepEqual([x.api, x.core], [5_000n + 6_000n, 5_000n])
  await ok(r, 'sol', 'reconcile', { txId: solSig(1), outcome: 'expired' }) // chain evidence: it can never land
  x = r.totals('sol')
  assert.deepEqual([x.api, x.core], [5_000n, 5_000n])
})

test('pinned: claw-failed — a claw-back that failed on chain: core charges the reported fee and frees it; the API charges the worst case and holds the value until a reconcile', async (t) => {
  const r = await run(t)
  await ethDrained(r)
  await ok(r, 'eth', 'clawback-intent', ethClaw(2, '500000'))          // worst fee 21,000 × 1 gwei = 2.1e13
  let x = r.totals('eth')
  assert.deepEqual([x.api, x.core], [1_000n + 21_000_000_000_000n + 500_000n, 1_000n + 21_000_000_000_000n + 500_000n])
  await ok(r, 'eth', 'clawback-failed', { txId: ethTx(2), reason: 'status 0', fee: '15000000000000' })
  x = r.totals('eth')
  assert.deepEqual([x.api, x.core], [1_000n + 21_000_000_000_000n + 500_000n, 1_000n + 15_000_000_000_000n])
  await ok(r, 'eth', 'reconcile', { txId: ethTx(2), outcome: 'nonce-consumed' })
  x = r.totals('eth')
  assert.deepEqual([x.api, x.core], [1_000n + 21_000_000_000_000n, 1_000n + 15_000_000_000_000n]) // the API keeps the worst-case fee
})

test('pinned: claw-value — a claw-back landed with less value than it declared: the API charges the declared value, core the chain\'s', async (t) => {
  const r = await run(t)
  await ethDrained(r)
  await ok(r, 'eth', 'clawback-intent', ethClaw(2, '500000'))
  await ok(r, 'eth', 'clawback-included', { txId: ethTx(2), value: '499900', fee: '21000000000000' })
  const x = r.totals('eth')
  assert.deepEqual([x.api, x.core], [1_000n + 21_000_000_000_000n + 500_000n, 1_000n + 21_000_000_000_000n + 499_900n])
})

test('pinned equal: a landing without a fee is charged its worst case by both; a fee reported later does not lower either total', async (t) => {
  const r = await run(t)
  await ok(r, 'eth', 'intent', ethI(1))                                  // worst W1 = the planned gas × 1 gwei
  await ok(r, 'eth', 'reconcile', { txId: ethTx(1), outcome: 'included', block: '9' })
  let x = r.totals('eth')
  assert.deepEqual([x.api, x.core], [W1, W1])
  await ok(r, 'eth', 'included', { txId: ethTx(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '7', ms: 1 })
  x = r.totals('eth')
  assert.equal(x.apiCharged, 7n, 'the API ledger alone would drop to the real fee')
  assert.deepEqual([x.api, x.core], [W1, W1])
})

test('pinned equal (I2 fix): a lowered fee plus a landed claw-back value — the API base adds the landed value to the reducer\'s spent, so it never falls below core', async (t) => {
  const r = await run(t)
  await ok(r, 'eth', 'intent', ethI(1))                                  // worst W1
  await ok(r, 'eth', 'reconcile', { txId: ethTx(1), outcome: 'included', block: '9' })
  await ok(r, 'eth', 'included', { txId: ethTx(1), copy: 1, part: 1, attempt: 1, block: '9', fee: '7', ms: 1 })   // the API ledger: 7
  await ok(r, 'eth', 'readback', { txId: ethTx(1), ok: true, detail: 'x' })
  await ok(r, 'eth', 'drained', { balance: '1', nextCost: '2', copy: 2 })
  await ok(r, 'eth', 'clawback-intent', ethClaw(2, '900000000000000'), { confirm: { amount: String(900_000_000_000_000n + 21_000_000_000_000n) } })
  await ok(r, 'eth', 'clawback-included', { txId: ethTx(2), value: '900000000000000', fee: '21000000000000' })
  const x = r.totals('eth')
  // the ledger alone (7 + value + fee) would sit W1 − 7 below core (worst + fee + value)
  assert.equal(x.apiCharged, 7n + 900_000_000_000_000n + 21_000_000_000_000n)
  assert.deepEqual([x.api, x.core], [W1 + 21_000_000_000_000n + 900_000_000_000_000n, W1 + 21_000_000_000_000n + 900_000_000_000_000n])
})

test('pinned (PF-S fix round 4, PF-E I-2): stuck → resolve mark-failed → stopped → a claw-back AT THAT NONCE, through the gate: the API holds both worst cases as core does (never below it); the nonce-consumed evidence frees the job attempt in both', async (t) => {
  const r = await run(t)
  await ok(r, 'eth', 'intent', ethI(1))                                  // nonce 1, worst W1
  await ok(r, 'eth', 'sent', { txId: ethTx(1), outcome: 'unknown', reason: 'timeout' })
  await ok(r, 'eth', 'stuck', { txId: ethTx(1), reason: 'unseen by every endpoint' })
  await ok(r, 'eth', 'resolved', { txId: ethTx(1), action: 'mark-failed', typed: null }, { by: 'operator' })
  await ok(r, 'eth', 'stopped', { reason: 'stopped by the operator' })
  const value = 900_000_000_000_000n
  await ok(r, 'eth', 'clawback-intent', { ...ethClaw(2, String(value)), eth: { nonce: 1, tip: '1', maxFee: '1000000000', gas: '21000', to: CLAWBACK_TO } },
    { confirm: { amount: String(value + 21_000_000_000_000n) } })
  let x = r.totals('eth')
  assert.ok(x.api >= x.core, `${x.api} >= ${x.core}`)
  assert.deepEqual([x.apiInFlight, x.api, x.core], [W1 + value + 21_000_000_000_000n, W1 + value + 21_000_000_000_000n, W1 + value + 21_000_000_000_000n], 'both kinds held, equal')
  await ok(r, 'eth', 'clawback-included', { txId: ethTx(2), value: String(value), fee: '21000000000000' })
  x = r.totals('eth')
  assert.ok(x.api >= x.core, `${x.api} >= ${x.core}`)
  assert.equal(x.apiInFlight, W1, 'the marked-failed attempt stays held until chain evidence')
  await ok(r, 'eth', 'reconcile', { txId: ethTx(1), outcome: 'nonce-consumed' })
  x = r.totals('eth')
  assert.deepEqual([x.apiInFlight, x.api >= x.core], [0n, true])
})

// ---- seeded random sequences through the gate

function rng(seed: number) {
  let x = seed >>> 0 || 1
  const r = (): number => { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; return x / 4294967296 }
  return { r, ri: (lo: number, hi: number) => lo + Math.floor(r() * (hi - lo + 1)), pick: <V>(xs: readonly V[]): V => xs[Math.floor(r() * xs.length)] }
}
interface Att { chain: Chain; txId: string; copy: number; part: number; attempt: number; nonce: number | null; claw: boolean; worst: bigint; value: bigint }

test('seeded random sequences (both chains, every event kind): after every line the API is never below core; equal while nothing conservative is involved', { timeout: 300_000 }, async (t) => {
  let accepted = 0, above = 0, equalPlain = 0
  // plain: no claim, failure, re-sign or value mismatch is generated (the two ledgers must then agree exactly)
  for (const [seed, plain] of [[11, false], [4242, false], [20261009, false], [7, true], [99, true]] as const) {
    const r = await run(t)
    const { r: rnd, ri, pick } = rng(seed)
    const atts: Att[] = []
    let n = 100, ethNonce = 10, ethCopy = 1, solGroup = 0   // copies go in order from 1 (PF-S fix round 1, N-2)
    const conservative = new Set<Chain>()                                 // a known conservative mechanism happened on the chain
    let clawNonce: number | null = null
    // fee-raised: a second landing report for a (copy, part), or for the claw-back family, that already landed — the API
    // ledger keeps the larger fee (and, for a claw-back, value), core the first landing's record
    const landedGroups = new Set<string>()
    const groupOf = (a: Att): string => (a.claw ? `${a.chain}:claw` : `${a.chain}:${a.copy}:${a.part}`)
    const landing = (a: Att): void => {
      const g = groupOf(a)
      if (landedGroups.has(g)) conservative.add(a.chain)
      landedGroups.add(g)
    }
    for (let i = 0; i < 700; i++) {
      const chain: Chain = rnd() < 0.5 ? 'eth' : 'sol'
      const mine = atts.filter((a) => a.chain === chain)
      const job = mine.filter((a) => !a.claw), claws = mine.filter((a) => a.claw)
      const kind = pick(['new', 'new', 'bump', 'sent', 'sent', 'included', 'included', 'reconcile', 'reconcile', 'readback', 'stuck', 'resolve', 'settle', 'claw', 'claw-out', 'claw-out'] as const)
      if (plain && kind === 'bump' && chain === 'sol') continue
      let done = false
      if (kind === 'new' || (kind === 'bump' && job.length > 0)) {
        // copies go in order (N-2): a bump replaces an attempt of the chain's top copy; a new copy is the next one, counted once accepted
        const topCopy = job.reduce((m, x) => (x.copy > m ? x.copy : m), 0)
        const prev = kind === 'bump' ? pick(job.filter((x) => x.copy === topCopy)) : null
        const id = ++n
        let data: Record<string, unknown>, a: Att
        if (chain === 'eth') {
          const nonce = prev?.nonce ?? ethNonce++, copy = prev?.copy ?? ethCopy
          const maxFee = String(ri(1, 9) * 1_000_000_000)
          data = ethI(id, { copy, nonce, attempt: (prev?.attempt ?? 0) + 1, replaces: prev?.txId ?? null, maxFee, gas: String(ri(...gasWindow(copy))) })
          a = { chain, txId: ethTx(id), copy, part: 1, attempt: (prev?.attempt ?? 0) + 1, nonce, claw: false, worst: BigInt((data.eth as { gas: string }).gas) * BigInt(maxFee), value: 0n }
        } else {
          const g = prev ?? { copy: solGroup + 1, part: 1, attempt: 0 }
          const fee = ri(5_000, 9_000)
          data = solI(id, { copy: g.copy, part: g.part, attempt: g.attempt + 1, replaces: prev?.txId ?? null, fee })
          a = { chain, txId: solSig(id), copy: g.copy, part: g.part, attempt: g.attempt + 1, nonce: null, claw: false, worst: BigInt(fee), value: 0n }
        }
        done = await r.append(chain, 'intent', data)
        if (done && prev === null) { if (chain === 'eth') ethCopy++; else solGroup++ }
        if (done) { atts.push(a); if (chain === 'sol' && prev !== null) conservative.add('sol') }
      } else if (kind === 'sent' && mine.length > 0) {
        const a = pick(mine)
        const outcome = pick(plain ? ['accepted', 'unknown'] as const : ['accepted', 'unknown', 'rejected'] as const)
        done = await r.append(chain, a.claw ? 'clawback-sent' : 'sent', a.claw ? { txId: a.txId, outcome: outcome === 'rejected' ? 'accepted' : outcome } : { txId: a.txId, outcome, reason: null })
        if (done && outcome === 'rejected' && !a.claw) conservative.add(chain)
      } else if (kind === 'included' && job.length > 0) {
        const a = pick(job)
        if (plain && landedGroups.has(groupOf(a))) continue
        done = await r.append(chain, 'included', { txId: a.txId, copy: a.copy, part: a.part, attempt: a.attempt, block: String(ri(1, 99)), fee: String(ri(1, Number(a.worst > 9_000_000_000_000n ? 9_000_000_000_000n : a.worst))), ms: 1 })
        if (done) landing(a)
      } else if (kind === 'reconcile' && mine.length > 0) {
        const a = pick(mine)
        const outcome = pick(['included', 'included-nofee', 'expired', 'nonce-consumed', 'adopted'] as const)
        if (plain && outcome.startsWith('included') && landedGroups.has(groupOf(a))) continue
        done = await r.append(chain, 'reconcile', outcome === 'included-nofee' ? { txId: a.txId, outcome: 'included', block: '7' } : outcome === 'included' ? { txId: a.txId, outcome, block: '7', fee: String(ri(1, 5000)) } : { txId: a.txId, outcome })
        if (done && outcome.startsWith('included')) landing(a)
      } else if (kind === 'readback' && job.length > 0) {
        done = await r.append(chain, 'readback', { txId: pick(job).txId, ok: rnd() < 0.8, detail: 'x' })
      } else if (kind === 'stuck' && mine.length > 0) {
        done = await r.append(chain, 'stuck', { txId: pick(mine).txId, reason: 'unknowable' })
      } else if (kind === 'resolve' && job.length > 0) {
        const a = pick(job)
        const action = pick(plain ? ['mark-done'] as const : ['mark-done', 'mark-failed'] as const)
        const res = await call(r.a.port, { path: `/jobs/${ID}/chains/${chain}/resolve`, body: { txId: a.txId, action } })
        done = res.status === 200
        if (done && action === 'mark-failed') conservative.add(chain)
      } else if (kind === 'settle') {
        done = await r.append(chain, 'drained', { balance: '1', nextCost: '2', copy: chain === 'eth' ? ethCopy : solGroup + 1 })
      } else if (kind === 'claw') {
        const id = ++n
        const value = rnd() < 0.5 ? String(ri(1, 1_000_000)) : String(BigInt(ri(1, 9)) * 10n ** 15n)
        let data: Record<string, unknown>, a: Att
        if (chain === 'eth') {
          const open = claws.some((x) => r.cmp.totals('eth') !== null) && clawNonce !== null
          const nonce = open ? clawNonce! : ethNonce++
          const maxFee = String(ri(1, 9) * 1_000_000_000)
          data = { ...ethClaw(id, value, maxFee), eth: { nonce, tip: '1', maxFee, gas: '21000', to: CLAWBACK_TO } }
          a = { chain, txId: ethTx(id), copy: 0, part: 0, attempt: 1, nonce, claw: true, worst: 21_000n * BigInt(maxFee), value: BigInt(value) }
        } else {
          const fee = ri(5_000, 9_000)
          data = { txId: solSig(id), to: SOL_DEST, value, rawSha256: rawOf(id), sol: { blockhash: solHash(id), lastValidBlockHeight: 1000, cuPrice: 0, cuLimit: 200_000, rung: null, fee: String(fee) } }
          a = { chain, txId: solSig(id), copy: 0, part: 0, attempt: 1, nonce: null, claw: true, worst: BigInt(fee), value: BigInt(value) }
        }
        done = await r.append(chain, 'clawback-intent', data, rnd() < 0.7 ? { confirm: { amount: String(a.value + a.worst) } } : undefined)
        if (!done && chain === 'eth') ethNonce--
        if (done) { atts.push(a); if (chain === 'eth') clawNonce = a.nonce }
      } else if (kind === 'claw-out' && claws.length > 0) {
        const a = pick(claws)
        const what = pick(plain ? ['included', 'readback'] as const : ['included', 'included-less', 'failed', 'readback'] as const)
        if (what === 'readback') done = await r.append(chain, 'clawback-readback', { txId: a.txId, ok: true, destReceived: String(a.value), laneBalance: '0' })
        else if (what === 'failed') { done = await r.append(chain, 'clawback-failed', { txId: a.txId, reason: 'status 0', fee: String(rnd() < 0.2 ? a.worst * 2n : a.worst / 2n) }); if (done) conservative.add(chain) }
        else {
          if (plain && landedGroups.has(groupOf(a))) continue
          done = await r.append(chain, 'clawback-included', { txId: a.txId, value: String(what === 'included-less' && a.value > 1n ? a.value - 1n : a.value), fee: String(a.worst / 2n) })
          if (done) { landing(a); if (what === 'included-less') conservative.add(chain) }
        }
      }
      if (!done) continue
      accepted++
      for (const c of ['eth', 'sol'] as const) {
        const x = r.totals(c)
        assert.ok(x.api >= x.core, `seed ${seed} line ${i} ${c}: API ${x.api} < core ${x.core} (${JSON.stringify(x, (_k, v) => (typeof v === 'bigint' ? String(v) : v))})`)
        if (x.api > x.core) {
          above++
          assert.ok(conservative.has(c), `seed ${seed} line ${i} ${c}: API ${x.api} > core ${x.core} without a known conservative mechanism (${JSON.stringify(x, (_k, v) => (typeof v === 'bigint' ? String(v) : v))})${process.env.VT_I2_DEBUG ? `\n${r.a.api.registry.journalOf(ID).all().filter((e) => e.chain === c).map((e) => `${e.type} ${JSON.stringify(e.data)}`).join('\n')}` : ''}`)
        } else if (!conservative.has(c)) equalPlain++
      }
    }
    r.cmp.close() // the engine allows one cap ledger per key per process: the next seed builds its own
  }
  console.log(`ledger equivalence (random): ${accepted} accepted lines, ${above} checks with the API above core (all explained), ${equalPlain} plain checks equal`)
  assert.ok(accepted > 800 && equalPlain > 300, `${accepted} accepted, ${equalPlain} plain`)
})

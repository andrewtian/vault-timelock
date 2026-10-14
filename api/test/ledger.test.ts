// The spend ledger (ledger.ts, security review): its running sums equal an independent from-scratch oracle after every
// line of seeded adversarial journals (contradictory, late, missing and zero fees; landings after dead; claims of
// rejected and failed; claw-back families; sol and eth); the fee rules; claw-back value until settled; and a registry
// rebuilt over the same files equals the live one after a random HTTP session through the gate.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { Chain, JournalEvent } from '@vault-timelock/core/contracts'
import { createRegistry } from '../src/jobs.ts'
import { createLedger, worstFee } from '../src/ledger.ts'
import type { ChainLedger } from '../src/ledger.ts'
import {
  CLAWBACK_TO, JOB2, JOB2_INPUT, TICKET_KEY, armed, call, ethClawback, ethIntent, ethTx, fakeClock, rawOf, solIntent, solSig, startApi,
} from './helpers.ts'

process.env.NODE_ENV = 'test'

const ev = (seq: number, chain: Chain, type: string, data: Record<string, unknown>): JournalEvent =>
  ({ v: 1, seq, at: seq, prev: '', chain, by: 'cli', gen: 1, type: type as JournalEvent['type'], data })
const dec = (v: unknown): bigint | null => (typeof v === 'string' && /^(?:0|[1-9][0-9]*)$/.test(v) ? BigInt(v) : null)
const big = (a: bigint, b: bigint): bigint => (a > b ? a : b)

// The oracle: the ledger's rules computed from the whole prefix at once, without running sums or a family index.
function oracle(events: readonly JournalEvent[], chain: Chain): { charged: bigint; inFlight: bigint } {
  interface A { idx: number; claw: boolean; nonce: number | null; txId: string; fee: bigint; value: bigint }
  const at = new Map<string, A>()
  events.forEach((e, idx) => {
    if (e.chain !== chain || (e.type !== 'intent' && e.type !== 'clawback-intent')) return
    const txId = e.data.txId as string
    if (at.has(txId)) return
    const eth = e.data.eth as { nonce?: number } | undefined
    const nonce = chain === 'eth' && eth !== undefined && Number.isSafeInteger(eth.nonce) ? eth.nonce as number : null
    at.set(txId, { idx, claw: e.type === 'clawback-intent', nonce, txId, fee: worstFee(e.chain as 'eth' | 'sol', e.data) ?? 0n, value: e.type === 'clawback-intent' ? dec(e.data.value) ?? 0n : 0n })
  })
  interface R { status: 'pending' | 'landed' | 'dead'; failed: boolean; charge: bigint; fee: bigint; value: bigint; family: string }
  const rows: R[] = []
  for (const a of at.values()) {
    const later = events.filter((e, i) => i > a.idx && e.chain === chain && e.data.txId === a.txId)
    const landingIdx = later.findIndex((e) => e.type === 'included' || (e.type === 'reconcile' && e.data.outcome === 'included')
      || (e.type === 'resolved' && e.data.action === 'mark-done') || (e.type === 'clawback-included' && a.claw))
    const deadIdx = later.findIndex((e) => e.type === 'reconcile' && (e.data.outcome === 'expired' || e.data.outcome === 'nonce-consumed'))
    const failIdx = later.findIndex((e) => e.type === 'clawback-failed' && a.claw)
    const inf = (i: number): number => (i < 0 ? Infinity : i)
    const landed = landingIdx >= 0
    const dead = !landed && deadIdx >= 0
    const failed = failIdx >= 0 && inf(failIdx) < inf(landingIdx) && inf(failIdx) < inf(deadIdx)
    let paid: bigint | null = null
    let value = a.value
    for (const e of later) {
      const isLanding = e.type === 'included' || (e.type === 'reconcile' && e.data.outcome === 'included') || (e.type === 'clawback-included' && a.claw)
      if (!isLanding) continue
      const f = dec(e.data.fee)
      if (f !== null) paid = paid === null ? f : big(paid, f)
      if (e.type === 'clawback-included') { const v = dec(e.data.value); if (v !== null) value = big(value, v) }
    }
    // PF-S fix round 4: job attempts and claw-back members of one nonce count as two families (as core does)
    rows.push({ status: landed ? 'landed' : dead ? 'dead' : 'pending', failed, charge: value + (paid ?? a.fee), fee: a.fee, value, family: `${a.claw ? 'c' : 'j'}:${a.nonce !== null ? `n:${a.nonce}` : `t:${a.txId}`}` })
  }
  let charged = 0n, inFlight = 0n
  for (const key of new Set(rows.map((r) => r.family))) {
    const fam = rows.filter((r) => r.family === key)
    const landed = fam.filter((r) => r.status === 'landed')
    let c = 0n
    for (const r of landed) c = big(c, r.charge)
    for (const r of fam) if (r.failed && r.status !== 'landed') c = big(c, r.fee)
    charged += c
    if (landed.length === 0) {
      let f = 0n
      for (const r of fam) if (r.status === 'pending') f = big(f, r.failed ? r.value : r.fee + r.value)
      inFlight += f
    }
  }
  return { charged, inFlight }
}

// Seeded adversarial journals over both chains: anything the ledger's input can be, gate or not.
function adversarial(seed: number, n: number): JournalEvent[] {
  let x = seed >>> 0 || 1
  const r = (): number => { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; return x / 4294967296 }
  const ri = (lo: number, hi: number): number => lo + Math.floor(r() * (hi - lo + 1))
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)]
  const ids: Record<Chain, string[]> = { eth: [], sol: [], btc: [] }
  const out: JournalEvent[] = []
  let id = 0
  for (let seq = 0; seq < n; seq++) {
    const c: Chain = r() < 0.65 ? 'eth' : 'sol'
    const any = (): string => (ids[c].length === 0 || r() < 0.05 ? `x${ri(0, 99)}` : pick(ids[c]))
    const fee = (): string | undefined => (r() < 0.3 ? undefined : pick(['0', '1', String(ri(1, 9) * 1000), String(ri(1, 9) * 10 ** 15), 'bad']))
    const eth = () => ({ nonce: ri(0, 5), tip: '1', maxFee: String(ri(1, 9) * 10 ** 9), gas: String(ri(21, 30) * 1000), to: '0x' })
    const sol = () => ({ blockhash: 'b', lastValidBlockHeight: 1, cuPrice: 1, cuLimit: 1, rung: null, fee: String(ri(5, 20) * 1000) })
    const roll = r()
    let type: string, data: Record<string, unknown>
    if (roll < 0.22) { type = 'intent'; const t = `${c}${++id}`; ids[c].push(t); data = { txId: t, copy: ri(1, 3), part: 1, attempt: 1, ...(c === 'eth' ? { eth: eth() } : { sol: sol() }) } }
    else if (roll < 0.30) { type = 'clawback-intent'; const t = `${c}c${++id}`; ids[c].push(t); data = { txId: t, to: 'd', value: String(ri(0, 9) * 10 ** 15), ...(c === 'eth' ? { eth: eth() } : { sol: sol() }) } }
    else if (roll < 0.45) { type = 'included'; const f = fee(); data = { txId: any(), ...(f === undefined ? { fee: '0' } : { fee: f }) } }
    else if (roll < 0.62) { type = 'reconcile'; const f = fee(); data = { txId: any(), outcome: pick(['included', 'expired', 'nonce-consumed', 'adopted']), ...(f === undefined ? {} : { fee: f }) } }
    else if (roll < 0.70) { type = 'sent'; data = { txId: any(), outcome: pick(['accepted', 'unknown', 'rejected']) } }
    else if (roll < 0.76) { type = 'resolved'; data = { txId: any(), action: pick(['mark-done', 'mark-failed']) } }
    else if (roll < 0.84) { type = 'clawback-included'; const f = fee(); data = { txId: any(), value: String(ri(0, 9) * 10 ** 15), fee: f ?? '0' } }
    else if (roll < 0.92) { type = 'clawback-failed'; data = { txId: any(), reason: 'claimed' } }
    else { type = pick(['note', 'readback', 'stuck', 'clawback-sent']); data = { txId: any(), text: 't' } }
    out.push(ev(seq, c, type, data))
  }
  return out
}

test('after every line of seeded adversarial journals, the running sums equal the from-scratch oracle', () => {
  for (const seed of [1, 2, 3, 99, 2026]) {
    const events = adversarial(seed, 700)
    const live = createLedger()
    events.forEach((e, i) => {
      live.apply(e)
      for (const c of ['eth', 'sol'] as const) {
        const want = oracle(events.slice(0, i + 1), c)
        const got = live.chain(c)
        assert.deepEqual([got.charged, got.inFlight], [want.charged, want.inFlight], `seed ${seed} line ${i} ${c}`)
      }
    })
    // rebuilt = live: the same lines into a fresh ledger give the same sums and attempts
    const again = createLedger()
    for (const e of events) again.apply(e)
    for (const c of ['eth', 'sol'] as const) assert.deepEqual(snap(again.chain(c)), snap(live.chain(c)))
  }
})

const snap = (l: ChainLedger): unknown => ({
  charged: String(l.charged), inFlight: String(l.inFlight),
  attempts: [...l.byTx.values()].map((a) => [a.txId, a.status, a.failed, String(a.paid), String(a.charge), String(a.value), a.family]),
})

test('fees: a no-fee landing charges the worst case; the first reported fee of THAT attempt replaces it; later reports only raise it', () => {
  const l = createLedger()
  let seq = 0
  const put = (type: string, data: Record<string, unknown>): ChainLedger => { l.apply(ev(seq++, 'eth', type, data)); return l.chain('eth') }
  put('intent', { txId: 'a', copy: 1, part: 1, attempt: 1, eth: { nonce: 1, gas: '1000', maxFee: '1000', tip: '1' } }) // worst 1e6
  assert.deepEqual([put('reconcile', { txId: 'a', outcome: 'included' }).charged, l.chain('eth').inFlight], [1_000_000n, 0n])
  assert.equal(put('included', { txId: 'a', fee: '300' }).charged, 300n) // its real fee
  assert.equal(put('included', { txId: 'a', fee: '100' }).charged, 300n) // never lowered again
  assert.equal(put('reconcile', { txId: 'a', outcome: 'included', fee: '500' }).charged, 500n) // only raised
  // a family (one nonce): a bump that lands counts once; a fee reported for one attempt never lowers another's charge
  put('intent', { txId: 'b', copy: 2, part: 1, attempt: 1, eth: { nonce: 2, gas: '1000', maxFee: '2000', tip: '1' } }) // 2e6
  put('intent', { txId: 'c', copy: 2, part: 1, attempt: 2, eth: { nonce: 2, gas: '1000', maxFee: '3000', tip: '1' } }) // 3e6
  assert.equal(l.chain('eth').inFlight, 3_000_000n) // the family's largest, once
  put('resolved', { txId: 'b', action: 'mark-done' }) // b landed, no fee: worst 2e6
  assert.deepEqual([l.chain('eth').charged, l.chain('eth').inFlight], [500n + 2_000_000n, 0n])
  put('included', { txId: 'c', fee: '7' }) // contradictory: c landed too, with a real fee of 7 — b's 2e6 is not lowered
  assert.equal(l.chain('eth').charged, 500n + 2_000_000n)
})

test('claw-backs: value + fee in flight; failed keeps the fee charged and the value in flight; only expired / nonce-consumed releases', () => {
  const l = createLedger()
  let seq = 0
  const put = (type: string, data: Record<string, unknown>): ChainLedger => { l.apply(ev(seq++, 'sol', type, data)); return l.chain('sol') }
  put('clawback-intent', { txId: 'k', to: 'd', value: '1000000', sol: { fee: '5000', cuLimit: 0, cuPrice: 0 } })
  assert.deepEqual([l.chain('sol').charged, l.chain('sol').inFlight], [0n, 1_005_000n])
  put('sent', { txId: 'k', outcome: 'rejected' }) // a claim: nothing released
  put('resolved', { txId: 'k', action: 'mark-failed' }) // nor the operator's claim
  assert.deepEqual([l.chain('sol').charged, l.chain('sol').inFlight], [0n, 1_005_000n])
  put('clawback-failed', { txId: 'k', reason: 'claimed' })
  assert.deepEqual([l.chain('sol').charged, l.chain('sol').inFlight], [5000n, 1_000_000n])
  put('reconcile', { txId: 'k', outcome: 'expired' }) // evidence it can never land
  assert.deepEqual([l.chain('sol').charged, l.chain('sol').inFlight], [5000n, 0n])
  put('clawback-intent', { txId: 'm', to: 'd', value: '2000000', sol: { fee: '5000', cuLimit: 0, cuPrice: 0 } })
  assert.equal(l.chain('sol').clawValue, 0n, 'nothing landed yet')
  put('clawback-included', { txId: 'm', value: '1', fee: '4000' }) // landed: the declared value is never under-reported away
  assert.deepEqual([l.chain('sol').charged, l.chain('sol').inFlight], [5000n + 2_004_000n, 0n])
  assert.equal(l.chain('sol').clawValue, 2_000_000n, 'I2: the landed claw-back value the cap base adds to the reducer\'s spent')
})

test('a registry rebuilt over the same files equals the live one after a random session through the gate (adversarial evidence)', async (t) => {
  const a = await startApi({ jobs: [JOB2_INPUT] })
  t.after(() => a.close())
  await armed(a, JOB2, ['eth', 'sol'])
  for (const c of ['eth', 'sol']) assert.equal((await call(a.port, { path: `/jobs/${JOB2}/chains/${c}/lease`, body: { op: 'acquire', holder: 'cli' } })).status, 200)
  let x = 7
  const r = (): number => { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; return x / 4294967296 }
  const ri = (lo: number, hi: number): number => lo + Math.floor(r() * (hi - lo + 1))
  const send = (c: Chain, type: string, data: unknown) => call(a.port, { path: `/jobs/${JOB2}/chains/${c}/events`, body: { gen: 1, type, data } })
  let accepted = 0
  let n = 1
  const top: Record<string, number> = { eth: 0, sol: 0 }   // PF-S fix round 1 (N-2): an intent's copy is the chain's top copy or the next one
  for (let i = 0; i < 400; i++) {
    const c: Chain = r() < 0.6 ? 'eth' : 'sol'
    const k = ri(1, n)
    const txId = c === 'eth' ? ethTx(k) : (solIntent(k).txId as string)
    const roll = r()
    let res
    if (roll < 0.3) {
      n++
      const copy = Math.max(1, top[c] + ri(0, 1))
      const d = c === 'eth' ? { ...ethIntent(n, copy), eth: { nonce: ri(0, 6), tip: '1', maxFee: String(ri(1, 9) * 10 ** 9), gas: '30000', to: '0x0000000000000000000000000000000000000000' }, replaces: r() < 0.3 ? ethTx(k) : null } : solIntent(n, copy)
      res = await send(c, 'intent', d)
      if (res.status === 200) top[c] = Math.max(top[c], copy)
    } else if (roll < 0.45) res = await send(c, 'sent', { txId, outcome: ['accepted', 'unknown', 'rejected'][ri(0, 2)], reason: null })
    else if (roll < 0.6) res = await send(c, 'reconcile', { txId, outcome: ['included', 'expired', 'nonce-consumed', 'adopted'][ri(0, 3)], ...(r() < 0.5 ? { block: '1', fee: String(ri(0, 9) * 10 ** 12) } : {}) })
    else if (roll < 0.72) res = await send(c, 'included', { txId, copy: ri(1, 9), part: 1, attempt: 1, block: '1', fee: String(ri(0, 9) * 10 ** 12), ms: 1 })
    else if (roll < 0.8) res = await send(c, 'stuck', { txId, reason: 'x' })
    else if (roll < 0.86) res = await send(c, ['drained', 'resumed', 'paused'][ri(0, 2)], c === 'eth' && r() < 0.5 ? { balance: '1', nextCost: '1', copy: 1 } : { reason: 'r' })
    else if (roll < 0.94 && c === 'eth') { n++; res = await send(c, 'clawback-intent', ethClawback(n, CLAWBACK_TO, String(ri(0, 9) * 10 ** 12))) }
    else res = await send(c, ['clawback-failed', 'clawback-included'][ri(0, 1)], { txId, reason: 'r', value: '1', fee: '1' })
    if (res.status === 200) accepted++
  }
  assert.ok(accepted >= 40, `only ${accepted} events passed the gate`)
  const live = a.api.registry
  const again = createRegistry({ stateDir: a.state, network: 'local', clock: fakeClock(), out: a.out, ticketKey: TICKET_KEY })
  const job = await again.load(JOB2)
  assert.deepEqual(again.state(job), live.state(live.get(JOB2)))
  for (const c of ['eth', 'sol'] as const) assert.deepEqual(snap(again.ledgerOf(job, c)), snap(live.ledgerOf(live.get(JOB2), c)), c)
  again.close()
  void rawOf
})

test('openInFlight (lane-s re-review I-1): an eth family whose bump landed counts 0; a family with nothing landed counts its largest pending attempt; btc abandoned attempts are excluded', () => {
  const ledger = createLedger()
  const eth = (n: number, nonce: number, replaces: string | null) => ({ chain: 'eth' as const, type: 'intent', data: { ...ethIntent(n, nonce), eth: { nonce, tip: '1', maxFee: String(10 * n), gas: '100', to: '0x0000000000000000000000000000000000000000' }, replaces } })
  const ev = (e: { chain: 'eth'; type: string; data: Record<string, unknown> }) => ledger.apply({ v: 1, seq: 0, at: 0, prev: '', chain: e.chain, by: 'cli', gen: 1, type: e.type, data: e.data } as never)
  ev(eth(1, 5, null)); ev(eth(2, 5, ethTx(1)))
  assert.equal(ledger.chain('eth').openInFlight(), 2000n, 'nothing landed: the larger of the pair')
  ev({ chain: 'eth', type: 'included', data: { txId: ethTx(2), copy: 1, part: 1, attempt: 2, block: '5', fee: '1', ms: 1 } })
  assert.equal(ledger.chain('eth').openInFlight(), 0n, 'the bump landed: the replaced attempt no longer counts')
  assert.equal(ledger.chain('eth').inFlight, 0n)
  ev(eth(3, 6, null))
  assert.equal(ledger.chain('eth').openInFlight(), 3000n, 'another family, nothing landed: counts')
})

test('PF-S fix round 2 (R1-3): `top` follows the journaled job attempts — parts 1..N of copy c raise its part, copy c + 1 resets it to its own part; claw-backs and replays never move it', () => {
  const l = createLedger()
  const intentOf = (n: number, copy: number, part: number, parts: number) => ev(n, 'eth', 'intent', { ...ethIntent(n, copy, part, parts), eth: { nonce: n, tip: '1', maxFee: '10', gas: '30000', to: '0x0000000000000000000000000000000000000000' } })
  const top = () => ({ ...l.chain('eth').top })
  assert.deepEqual(top(), { copy: 0, part: 0 }, 'nothing journaled')
  for (let part = 1; part <= 4; part++) {
    l.apply(intentOf(part, 1, part, 4))
    assert.deepEqual(top(), { copy: 1, part }, `copy 1 part ${part}`)
  }
  l.apply(intentOf(5, 1, 2, 4))                                                   // a re-sign of an earlier part: the highest part stays
  assert.deepEqual(top(), { copy: 1, part: 4 })
  l.apply(intentOf(6, 2, 1, 4))                                                   // the next copy: its own part, not copy 1's
  assert.deepEqual(top(), { copy: 2, part: 1 })
  l.apply(intentOf(7, 2, 3, 4))
  assert.deepEqual(top(), { copy: 2, part: 3 })
  l.apply(intentOf(8, 1, 4, 4))                                                   // an older copy (a rebuild over an old journal) never lowers it
  assert.deepEqual(top(), { copy: 2, part: 3 })
  l.apply(ev(9, 'eth', 'clawback-intent', { txId: ethTx(9), to: '0x1111111111111111111111111111111111111111', value: '1', rawSha256: 'aa'.repeat(32), eth: { nonce: 9, tip: '1', maxFee: '10', gas: '21000', to: '0x1111111111111111111111111111111111111111' } }))
  assert.deepEqual(top(), { copy: 2, part: 3 }, 'a claw-back (copy 0) is no job attempt')
  assert.deepEqual(l.chain('sol').top, { copy: 0, part: 0 }, 'per chain')
})

test('PF-S fix round 4 (PF-E I-2): a resolve mark-failed flags an eth / sol job attempt (still pending, still in flight) for good — nothing clears it (fix round 5, R34-2); claw-backs and landed attempts are not flagged', () => {
  const l = createLedger()
  const eth = (n: number) => ev(n, 'eth', 'intent', { ...ethIntent(n, 1, 1, 1), eth: { nonce: 1, tip: '1', maxFee: '10', gas: '30000', to: '0x0000000000000000000000000000000000000000' } })
  l.apply(eth(1))
  const a = l.chain('eth').byTx.get(ethTx(1))!
  assert.deepEqual([a.status, a.markedFailed, l.chain('eth').inFlight], ['pending', false, 300_000n])
  l.apply(ev(2, 'eth', 'resolved', { txId: ethTx(1), action: 'mark-failed' }))
  assert.deepEqual([a.status, a.markedFailed, l.chain('eth').inFlight], ['pending', true, 300_000n], 'flagged; its reserve kept')
  assert.deepEqual(l.chain('eth').family('n:1').pending.map((x) => x.markedFailed), [true])
  // fail closed: no later line clears it (the gate refuses an `adopted` of an attempt that is not open: event.attempt)
  for (const [k, type, data] of [[3, 'reconcile', { txId: ethTx(1), outcome: 'adopted' }], [4, 'sent', { txId: ethTx(1), outcome: 'accepted', reason: null }],
    [5, 'stuck', { txId: ethTx(1), reason: 'x' }], [6, 'resolved', { txId: ethTx(1), action: 'mark-failed' }]] as const) {
    l.apply(ev(k, 'eth', type, data))
    assert.equal(a.markedFailed, true, type)
  }
  // a claw-back member marked failed is not flagged (its family has its own rules); nor is a landed attempt
  l.apply(ev(5, 'eth', 'clawback-intent', { txId: ethTx(5), to: '0x1111111111111111111111111111111111111111', value: '1', rawSha256: 'aa'.repeat(32), eth: { nonce: 5, tip: '1', maxFee: '10', gas: '21000', to: '0x1111111111111111111111111111111111111111' } }))
  l.apply(ev(6, 'eth', 'resolved', { txId: ethTx(5), action: 'mark-failed' }))
  assert.equal(l.chain('eth').byTx.get(ethTx(5))!.markedFailed, false)
  l.apply(ev(7, 'eth', 'intent', { ...ethIntent(7, 2, 1, 1), eth: { nonce: 7, tip: '1', maxFee: '10', gas: '30000', to: '0x0000000000000000000000000000000000000000' } }))
  l.apply(ev(8, 'eth', 'included', { txId: ethTx(7), copy: 2, part: 1, attempt: 1, block: '9', fee: '5', ms: 1 }))
  l.apply(ev(9, 'eth', 'resolved', { txId: ethTx(7), action: 'mark-failed' }))
  assert.equal(l.chain('eth').byTx.get(ethTx(7))!.markedFailed, false, 'a landed attempt is never flagged')
  // sol: flagged the same way (its family is the signature alone)
  l.apply(ev(10, 'sol', 'intent', solIntent(10)))
  l.apply(ev(11, 'sol', 'resolved', { txId: solSig(10), action: 'mark-failed' }))
  assert.equal(l.chain('sol').byTx.get(solSig(10))!.markedFailed, true)
})

test('PF-S fix round 4: a nonce family with both kinds (a claw-back on the nonce of a job attempt no longer open) counts each kind on its own, in inFlight and openInFlight, until chain evidence frees the job attempt; a marked-failed attempt is out of openInFlight (fix round 5: close)', () => {
  const C = 21_000n * 10n + 7n, W = 30_000n * 10n
  const claw = (k: number) => ev(k, 'eth', 'clawback-intent', { txId: ethTx(k), to: '0x1111111111111111111111111111111111111111', value: '7', rawSha256: 'aa'.repeat(32), eth: { nonce: 3, tip: '1', maxFee: '10', gas: '21000', to: '0x1111111111111111111111111111111111111111' } })
  const job = ev(1, 'eth', 'intent', { ...ethIntent(1, 1, 1, 1), eth: { nonce: 3, tip: '1', maxFee: '10', gas: '30000', to: '0x0000000000000000000000000000000000000000' } })
  // a job attempt CLAIMED rejected (not marked): it counts in both, per kind, until nonce-consumed
  const l = createLedger()
  l.apply(job); l.apply(ev(2, 'eth', 'sent', { txId: ethTx(1), outcome: 'rejected', reason: 'x' })); l.apply(claw(3))
  const c = l.chain('eth')
  assert.deepEqual([c.inFlight, c.openInFlight(), c.family('n:3').kindInFlight(false), c.family('n:3').kindInFlight(true)], [W + C, W + C, W, C])
  l.apply(ev(4, 'eth', 'clawback-included', { txId: ethTx(3), value: '7', fee: '210000' }))
  assert.deepEqual([c.charged, c.inFlight, c.openInFlight(), c.family('n:3').settled], [C, W, W, true], 'the claw-back landed; the job attempt is held until evidence')
  l.apply(ev(5, 'eth', 'reconcile', { txId: ethTx(1), outcome: 'nonce-consumed' }))
  assert.deepEqual([c.charged, c.inFlight, c.openInFlight()], [C, 0n, 0n])
  // a job attempt resolved mark-failed: in the cap (inFlight), not in what a close must see settled (openInFlight)
  const m = createLedger()
  m.apply(job); m.apply(ev(2, 'eth', 'resolved', { txId: ethTx(1), action: 'mark-failed' }))
  assert.deepEqual([m.chain('eth').inFlight, m.chain('eth').openInFlight()], [W, 0n])
  m.apply(claw(3))
  assert.deepEqual([m.chain('eth').inFlight, m.chain('eth').openInFlight()], [W + C, C])
})

test('M5 (merge gate I-1; the same rule as PF-S fix round 5): an eth / sol job attempt resolved mark-failed no longer holds a close (openInFlight) but keeps counting for the cap (inFlight); nothing brings it back (R34-2); an unflagged pending attempt still holds it', () => {
  const l = createLedger()
  const W = 30_000n * 10n
  l.apply(ev(1, 'eth', 'intent', { ...ethIntent(1, 1, 1, 1), eth: { nonce: 0, tip: '1', maxFee: '10', gas: '30000', to: '0x0000000000000000000000000000000000000000' } }))
  const c = l.chain('eth')
  assert.deepEqual([c.inFlight, c.openInFlight()], [W, W], 'pending: it holds a close')
  l.apply(ev(2, 'eth', 'resolved', { txId: ethTx(1), action: 'mark-failed' }))
  assert.deepEqual([c.inFlight, c.openInFlight()], [W, 0n], 'marked failed by the operator: a close may go ahead; the cap still counts it')
  // M5b: the flag is never cleared (PF-S fix round 5, R34-2; the gate refuses an `adopted` of an attempt that is not open)
  l.apply(ev(3, 'eth', 'reconcile', { txId: ethTx(1), outcome: 'adopted' }))
  assert.deepEqual([c.inFlight, c.openInFlight()], [W, 0n], 'an (ungated) adopted changes nothing: still marked')
  // a second, unflagged attempt in another family still holds the close
  l.apply(ev(5, 'eth', 'intent', { ...ethIntent(5, 2, 1, 1), eth: { nonce: 1, tip: '1', maxFee: '10', gas: '30000', to: '0x0000000000000000000000000000000000000000' } }))
  assert.deepEqual([c.inFlight, c.openInFlight()], [2n * W, W])
  // a bump beside a marked-failed attempt in ONE family: the unflagged member holds the close
  const m = createLedger()
  m.apply(ev(1, 'eth', 'intent', { ...ethIntent(1, 1, 1, 1), eth: { nonce: 0, tip: '1', maxFee: '10', gas: '30000', to: '0x0000000000000000000000000000000000000000' } }))
  m.apply(ev(2, 'eth', 'intent', { ...ethIntent(2, 1, 1, 1), replaces: ethTx(1), eth: { nonce: 0, tip: '2', maxFee: '20', gas: '30000', to: '0x0000000000000000000000000000000000000000' } }))
  m.apply(ev(3, 'eth', 'resolved', { txId: ethTx(1), action: 'mark-failed' }))
  assert.equal(m.chain('eth').openInFlight(), 2n * W, 'the open bump still holds it')
  m.apply(ev(4, 'eth', 'resolved', { txId: ethTx(2), action: 'mark-failed' }))
  assert.deepEqual([m.chain('eth').inFlight, m.chain('eth').openInFlight()], [2n * W, 0n], 'every member marked failed: the close may go ahead')
  // sol: the same (the family is the signature alone)
  l.apply(ev(10, 'sol', 'intent', solIntent(10)))
  const s = l.chain('sol'), S = s.inFlight
  assert.ok(S > 0n)
  assert.equal(s.openInFlight(), S)
  l.apply(ev(11, 'sol', 'resolved', { txId: solSig(10), action: 'mark-failed' }))
  assert.deepEqual([s.inFlight, s.openInFlight()], [S, 0n])
})

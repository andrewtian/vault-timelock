// api/src/ledger.ts — the API's spend ledger per chain: what the armed cap is checked against before a send is journaled
// (security review of 7409aff; S2 re-review N-2..N-4). Driven by the journal alone, one line at a time, in order: built
// on load and advanced after each fsync by the same apply(), so a ledger rebuilt on restart equals the live one. It is
// kept apart from the contract's reducer (whose ChainState.spent stays Σ reported fees, as core's reduce says); the cap
// check takes the larger of the two (jobs.ts).
//
// INVARIANT: charged + inFlight is never below what the journal's evidence implies was spent or may still be spent.
//
//   Attempts. Every journaled intent / claw-back intent is an attempt with its declared worst case — worstCaseFee
//   (tickets.ts), the ONE fee formula: exactly the ticket's `f` (I2), eth gas × maxFee | sol max(fee, 5,000 + ⌈cuLimit ×
//   cuPrice / 10⁶⌉), floored by jobs.ts — and, for a claw-back, its declared value. Status: pending → landed | dead
//   (controller ruling on NEW-2):
//     landed  `included`, reconcile `included`, resolve mark-done, `clawback-included` (from pending or dead: evidence
//             that it landed always wins).
//     marked  (a flag, eth / sol job attempts) after a resolve mark-failed, for good (PF-S fix round 5, R34-2: nothing clears it —
//             fail closed): still pending (it counts in flight), but its ETH nonce family may then take the chain's claw-back, no job
//             attempt joins it again (PF-S fix round 4, PF-E review I-2), and a close no longer waits for it (openInFlight: M5 merge
//             gate I-1 = PF-S fix round 5, one rule).
//     dead    ONLY a reconcile `expired` or `nonce-consumed`. BTC never dies: such a report (and a stuck + mark-failed) only makes the
//             attempt `abandoned` (not open, reserve kept) until it lands. A `sent rejected`, a resolve mark-failed or a
//             `clawback-failed` claim alone never releases the count: the bytes may have been accepted before.
//     failed  (a flag, claw-backs) after `clawback-failed`: its worst-case fee is kept as charged; its value stays in
//             flight until a reconcile `expired` / `nonce-consumed` shows it cannot land.
//   Families. Attempts that can never both land: eth, every attempt with one nonce (job or claw-back); sol, each
//     signature alone. A family is settled once a member landed.
//     charge   the largest of its landed members' charges (each its own reported fee, else its worst case: the landed
//              member's real fee is what it charges; contradictory landings of one family count once, the larger — a fee
//              reported for one attempt never lowers another's charge) and its failed claw-backs' fees.
//     inFlight unsettled: the largest of its pending members' worst case + value (a failed claw-back: its value).
//              Settled: 0.
//     A nonce family with both kinds (PF-S fix round 4: a claw-back on the nonce of job attempts resolved mark-failed) counts
//     its job attempts and its claw-back members as two families and adds them, as core's CapLedger holds both.
//   Charges. A landing charges value + the fee it reports, or the WORST CASE when it reports none (never 0). A landed BTC commit
//     charges at least its worst case (fee + the value it locks) even when it reports only its tx fee: the report is the tx's own fee. A fee
//     reported later, for that same attempt, replaces its worst-case charge once (the real fee); after that a report can
//     only raise it (never below a reported real fee). A claw-back charges the larger of its declared and reported value.
//   Sums. charged and inFlight are running sums of each family's cached contribution, recomputed only for the family a
//     line touches: O(family) per line, O(1) per check.
import type { Chain, JournalEvent } from '@vault-timelock/core/contracts'
import { worstCaseFee } from './tickets.ts'

export type AttemptStatus = 'pending' | 'landed' | 'dead'
export interface LedgerAttempt {
  readonly txId: string; readonly chain: Chain; readonly claw: boolean; readonly copy: number; readonly part: number
  readonly attempt: number | null; readonly nonce: number | null; readonly to: string | null; readonly family: string
  readonly fee: bigint; value: bigint
  status: AttemptStatus
  // BTC: no longer an OPEN attempt of its (copy, part) (a new one may be admitted) but still pending for the cap: its reserve is kept
  // until evidence that it landed (then its real charge). Set by a reconcile expired and by a stuck + mark-failed; never released.
  abandoned: boolean
  // A claw-back the executor reported failed (clawback-failed).
  failed: boolean
  // PF-S fix round 4 (PF-E review I-2): an ETH / SOL job attempt the operator resolved mark-failed (it stays pending: its bytes may
  // have been accepted). Never cleared (fix round 5, R34-2). An ETH family whose pending members are all no longer open may take the
  // claw-back (jobs.ts); no job attempt joins a family with a marked member.
  markedFailed: boolean
  // The fee landing evidence reported (the first report replaces the worst case; later ones can only raise it).
  paid: bigint | null
  // landed: value + (paid ?? fee).
  charge: bigint; feeKnown: boolean
}
interface Family { readonly key: string; readonly members: LedgerAttempt[]; charge: bigint; inFlight: bigint }
export interface ChainLedger {
  readonly byTx: ReadonlyMap<string, LedgerAttempt>
  readonly copies: ReadonlySet<number>
  // PF-S fix round 1 (N-2): the highest copy with a journaled job attempt (0: none yet) and the highest part journaled in it
  readonly top: { readonly copy: number; readonly part: number }
  readonly charged: bigint
  readonly inFlight: bigint
  // inFlight without the abandoned BTC attempts (stuck + mark-failed) and without the eth / sol job attempts the operator resolved
  // mark-failed (markedFailed; the operator's word, as for BTC; the watch-only recovery ends in claw-back or close — M5 merge gate
  // I-1 and PF-S fix round 5, one rule): what a close must see settled. Both still count for the cap.
  openInFlight(): bigint
  // A claw-back attempt of this chain has landed (evidence): the chain is clawed back.
  readonly clawLanded: boolean
  // The largest value (max(declared, reported)) among the landed claw-back attempts; 0 when none. Core counts a landed
  // claw-back's value in its spend; the API's cap base adds it to the reducer's (fees-only) spent (jobs.ts, I2).
  readonly clawValue: bigint
  // The family key an attempt with this nonce / txId belongs to.
  familyKey(nonce: number | null, txId: string): string
  // A family's cached contribution and whether a member landed. kindInFlight: what its job attempts (claw false) or its claw-back
  // members (claw true) alone keep in flight (PF-S fix round 4: the two kinds of one nonce add up, familyContribution).
  family(key: string): { settled: boolean; charge: bigint; inFlight: bigint; pending: readonly LedgerAttempt[]; kindInFlight(claw: boolean): bigint }
  // Pending job attempts of one (copy, part).
  pendingIn(copy: number, part: number): readonly LedgerAttempt[]
  // Pending claw-back attempts of unsettled families (the open claw-back family).
  pendingClaws(): readonly LedgerAttempt[]
}
export interface Ledger {
  apply(e: JournalEvent): void
  chain(c: Chain): ChainLedger
}

type Obj = Record<string, unknown>
const DEC = /^(?:0|[1-9][0-9]{0,77})$/
const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v)
const dec = (v: unknown): bigint | null => (typeof v === 'string' && DEC.test(v) ? BigInt(v) : null)
const int = (v: unknown): number | null => (typeof v === 'number' && Number.isSafeInteger(v) ? v : null)
const max = (a: bigint, b: bigint): bigint => (a > b ? a : b)

// The worst-case fee of an attempt of `chain` (its intent data): worstCaseFee, the formula the ticket's `f` is (I2: one
// formula, so the cap reserves exactly what the relay lets the signed bytes cost); null when it cannot be formed.
//   BTC (CC-8, S6b fix round 2): what leaves the lane's spendable coins, in sats, checked once per copy: a COMMIT reserves its fee
//   plus the value it locks into the commit output (the reveal's fee and the 546-sat postage, which stays with the inscription);
//   a REVEAL reserves 0 (it moves only what the commit locked). The ticket's f stays the tx's own fee bound (tickets.ts).
export function worstFee(chain: Chain, data: Record<string, unknown>): bigint | null {
  if (chain === 'btc') {
    const b = data.btc
    if (!isObj(b) || (b.kind !== 'commit' && b.kind !== 'reveal')) return null
    const fee = dec(b.fee)
    if (fee === null || fee < 1n) return null
    if (b.kind === 'reveal') return 0n
    const value = dec(b.value)
    return value === null ? null : fee + value
  }
  return worstCaseFee(chain, data)
}

const familyKeyOf = (nonce: number | null, txId: string): string => (nonce !== null ? `n:${nonce}` : `t:${txId}`)

// A family's contribution, from scratch (see the header). PF-S fix round 4: a nonce family that holds both job attempts and claw-back
// members (the claw-back took the nonce of job attempts resolved mark-failed) counts each kind on its own and adds them — as core's
// CapLedger does (it holds a marked-failed attempt until chain evidence frees it), so the API, the outer gate, is never below the
// engine (test/integration/ledger-compare.ts). A family of one kind is unchanged.
export function familyContribution(members: readonly LedgerAttempt[]): { charge: bigint; inFlight: bigint } {
  const jobs = members.filter((m) => !m.claw), claws = members.filter((m) => m.claw)
  if (jobs.length > 0 && claws.length > 0) {
    const a = kindContribution(jobs), b = kindContribution(claws)
    return { charge: a.charge + b.charge, inFlight: a.inFlight + b.inFlight }
  }
  return kindContribution(members)
}
function kindContribution(members: readonly LedgerAttempt[]): { charge: bigint; inFlight: bigint } {
  const landed = members.filter((m) => m.status === 'landed')
  const failedFee = members.filter((m) => m.failed && m.status !== 'landed').reduce((x, m) => max(x, m.fee), 0n)
  const charge = max(landed.reduce((x, m) => max(x, m.charge), 0n), failedFee)
  if (landed.length > 0) return { charge, inFlight: 0n }
  return { charge, inFlight: members.filter((m) => m.status === 'pending').reduce((x, m) => max(x, m.failed ? m.value : m.fee + m.value), 0n) }
}

function createChainLedger(): ChainLedger & { touch(a: LedgerAttempt): void; add(a: LedgerAttempt): void } {
  const byTx = new Map<string, LedgerAttempt>()
  const families = new Map<string, Family>()
  const groups = new Map<string, Set<LedgerAttempt>>()
  const claws = new Set<LedgerAttempt>()
  const copies = new Set<number>()
  const top = { copy: 0, part: 0 }
  let charged = 0n
  let inFlight = 0n
  let clawLanded = false
  let clawValue = 0n
  const recompute = (f: Family): void => {
    const next = familyContribution(f.members)
    charged += next.charge - f.charge
    inFlight += next.inFlight - f.inFlight
    f.charge = next.charge
    f.inFlight = next.inFlight
  }
  const settled = (f: Family): boolean => f.members.some((m) => m.status === 'landed')
  const index = (a: LedgerAttempt): void => {
    const k = `${a.copy}:${a.part}`
    if (!a.claw) {
      let g = groups.get(k)
      if (g === undefined) { g = new Set(); groups.set(k, g) }
      if (a.status === 'pending' && !a.abandoned) g.add(a)
      else g.delete(a)
    } else if (a.status === 'pending') claws.add(a)
    else claws.delete(a)
  }
  return {
    byTx, copies, top,
    get charged() { return charged },
    get inFlight() { return inFlight },
    // Per family and kind, as inFlight is: a kind with a landed member counts 0, else its largest pending member that is not abandoned
    // (btc) nor marked failed (eth / sol; M5 merge gate I-1 = PF-S fix round 5): a close is accepted once every open attempt is marked
    // failed or settled — the operator's word, as for btc; the cap (inFlight) keeps counting them until chain evidence (PF-S fix round 4).
    openInFlight() {
      let sum = 0n
      for (const f of families.values()) {
        // per kind, as familyContribution (a mixed family: the claw-back on the nonce of job attempts resolved mark-failed)
        for (const kind of [false, true]) {
          const ms = f.members.filter((m) => m.claw === kind)
          if (ms.some((m) => m.status === 'landed')) continue
          sum += ms.filter((m) => m.status === 'pending' && !m.abandoned && !m.markedFailed).reduce((x, m) => max(x, m.failed ? m.value : m.fee + m.value), 0n)
        }
      }
      return sum
    },
    get clawLanded() { return clawLanded },
    get clawValue() { return clawValue },
    familyKey: familyKeyOf,
    family(key) {
      const f = families.get(key)
      if (f === undefined) return { settled: false, charge: 0n, inFlight: 0n, pending: [], kindInFlight: () => 0n }
      return { settled: settled(f), charge: f.charge, inFlight: f.inFlight, pending: f.members.filter((m) => m.status === 'pending'),
        kindInFlight: (claw) => kindContribution(f.members.filter((m) => m.claw === claw)).inFlight }
    },
    pendingIn(copy, part) {
      const g = groups.get(`${copy}:${part}`)
      return g === undefined ? [] : [...g].filter((a) => !settled(families.get(a.family)!))
    },
    pendingClaws: () => [...claws].filter((a) => !settled(families.get(a.family)!)),
    add(a) {
      byTx.set(a.txId, a)
      let f = families.get(a.family)
      if (f === undefined) { f = { key: a.family, members: [], charge: 0n, inFlight: 0n }; families.set(a.family, f) }
      f.members.push(a)
      if (!a.claw) {
        copies.add(a.copy)
        if (a.copy > top.copy) { top.copy = a.copy; top.part = a.part } else if (a.copy === top.copy && a.part > top.part) top.part = a.part
      }
      index(a)
      recompute(f)
    },
    touch(a) {
      if (a.claw && a.status === 'landed') { clawLanded = true; clawValue = max(clawValue, a.value) }
      index(a)
      recompute(families.get(a.family)!)
    },
  }
}

export function createLedger(): Ledger {
  const chains = new Map<Chain, ReturnType<typeof createChainLedger>>()
  const chain = (c: Chain): ReturnType<typeof createChainLedger> => {
    let l = chains.get(c)
    if (l === undefined) { l = createChainLedger(); chains.set(c, l) }
    return l
  }
  // Evidence that the attempt landed (see the header for the charge).
  const land = (l: ReturnType<typeof createChainLedger>, a: LedgerAttempt, fee: bigint | null, value: bigint | null): void => {
    if (a.claw && value !== null) a.value = max(a.value, value)
    if (fee !== null) a.paid = a.paid === null ? fee : max(a.paid, fee)
    a.status = 'landed'
    // BTC (fix round 2 review m-2): a landed commit charges at least the fee + the value it locked (its worst case, `fee`), whatever
    // fee the executor reports: that report is the tx's own fee, and the locked value left the lane's spendable coins all the same.
    a.charge = a.value + (a.chain === 'btc' ? max(a.paid ?? a.fee, a.fee) : a.paid ?? a.fee)
    a.feeKnown = a.paid !== null
    l.touch(a)
  }
  // Releases the attempt's reserve (eth / sol, on a reconcile expired / nonce-consumed). A BTC attempt is never released by a report:
  // nothing on chain proves a bitcoin commit can never land (a spend elsewhere may be conflicting or the same value), so it only stops
  // being OPEN and keeps counting against the cap (security review of fa39344).
  const die = (l: ReturnType<typeof createChainLedger>, a: LedgerAttempt): void => {
    if (a.status !== 'pending') return
    if (a.chain === 'btc') { a.abandoned = true; l.touch(a); return }
    a.status = 'dead'
    l.touch(a)
  }

  const stuckBtc = new Set<string>()   // btc attempts the engine journaled `stuck` (the evidence a mark-failed needs to release them)
  return {
    chain,
    apply(e) {
      if (e.chain !== 'eth' && e.chain !== 'sol' && e.chain !== 'btc') return
      const d: Obj = isObj(e.data) ? e.data : {}
      const txId = typeof d.txId === 'string' ? d.txId : null
      if (txId === null) return
      const l = chain(e.chain)
      const a = l.byTx.get(txId)
      switch (e.type) {
        case 'intent':
        case 'clawback-intent': {
          if (a !== undefined) return
          const claw = e.type === 'clawback-intent'
          const nonce = e.chain === 'eth' && isObj(d.eth) ? int(d.eth.nonce) : null
          l.add({
            txId, chain: e.chain, claw, copy: claw ? 0 : int(d.copy) ?? 0, part: claw ? 0 : int(d.part) ?? 0, attempt: claw ? null : int(d.attempt),
            nonce, to: claw && typeof d.to === 'string' ? d.to : null, family: familyKeyOf(nonce, txId),
            fee: worstFee(e.chain, d) ?? 0n, value: claw ? dec(d.value) ?? 0n : 0n, status: 'pending', abandoned: false, failed: false, markedFailed: false, paid: null, charge: 0n, feeKnown: false,
          })
          return
        }
        case 'included': if (a !== undefined) land(l, a, dec(d.fee), null); return
        case 'clawback-included': if (a !== undefined && a.claw) land(l, a, dec(d.fee), dec(d.value)); return
        case 'reconcile':
          if (a === undefined) return
          if (d.outcome === 'included') land(l, a, dec(d.fee), null)
          else if (d.outcome === 'nonce-consumed' || d.outcome === 'expired') die(l, a)
          return
        case 'resolved':
          if (a === undefined) return
          if (d.action === 'mark-done') land(l, a, null, null)
          // BTC recovery (E7 I-1): an attempt the engine journaled `stuck` and the operator then marked failed stops being OPEN (a new
          // commit may be admitted) but KEEPS its reserve: the stuck evidence is the executor's, and a conflicting spend may have moved
          // value. The new attempt reserves fresh; the operator raises the cap through the typed arm.amount path. eth / sol: a
          // mark-failed alone never releases.
          else if (d.action === 'mark-failed' && e.chain === 'btc' && !a.claw && stuckBtc.has(txId)) die(l, a)
          // PF-S fix round 4: an eth / sol job attempt marked failed keeps counting (pending) and is flagged
          else if (d.action === 'mark-failed' && e.chain !== 'btc' && !a.claw && a.status === 'pending') { a.markedFailed = true; l.touch(a) }
          return
        case 'stuck': if (e.chain === 'btc' && a !== undefined && a.status === 'pending') stuckBtc.add(txId); return
        case 'clawback-failed': if (a !== undefined && a.claw && a.status === 'pending') { a.failed = true; l.touch(a) } return
        default: return
      }
    },
  }
}

// test/integration/ledger-compare.ts — the core-vs-API cap ledger comparison (I2; not a test file).
//
// Two ledgers count what a chain has spent and may still spend against its armed cap, from the same journal:
//   · the API's (api/src/ledger.ts + core's reducer spent): total = max(ledger charged, reducer spent + the ledger's
//     landed claw-back value) + ledger in flight — what jobs.ts checks before it journals and tickets a send;
//   · the engine's (core gates/caps.ts CapLedger): total = spent + held — what the engine checks before every signature.
//     It is built by CapLedger.fromArmed from the state right after `armed` and then observes every later event of its
//     chain, exactly as a live run does.
// INVARIANT (asserted by the callers after every line): API total ≥ core total — the API, the outer gate, is never less
// conservative than the engine. Where they differ, the API is MORE conservative for one of these known reasons (pinned
// one by one in ledger-equivalence.test.ts):
//   sol-resign    SOL: the API holds every signature of a (copy, part) on its own (each one may land: a re-sign counts
//                 twice); core holds the group's largest;
//   claim-held    a claim (sent rejected, resolve mark-failed) on an attempt whose (copy, part) later landed through
//                 another SOL signature: core frees the group's claims at the landing; the API keeps that signature in
//                 flight until a reconcile expired / nonce-consumed;
//   claw-failed   clawback-failed: core frees the member and charges the fee the chain reported; the API charges the
//                 worst-case fee and keeps the value in flight until a reconcile expired / nonce-consumed;
//   claw-value    a landed claw-back: the API charges max(declared, reported) value; core the value the chain reported.
// Equal by construction (pinned too): a landing without a fee is charged its worst case by both; a fee reported later
// for that attempt lowers the API ledger's charge, but the API takes max(charged, reducer spent) and core's reducer keeps
// the first landing's worst case — so both totals stay at the worst case.
import { CapLedger } from '../../packages/core/src/gates/caps.ts'
import { createReducer } from '../../packages/core/src/job/reduce.ts'
import type { Chain, JobDef, JournalEvent } from '../../packages/core/src/contracts/index.ts'
import { createLedger } from '../../api/src/ledger.ts'

export interface Totals { api: bigint; core: bigint; apiCharged: bigint; apiInFlight: bigint; reducerSpent: bigint; coreSpent: bigint; coreHeld: bigint }
export interface Comparator {
  apply(e: JournalEvent): void
  // null before the arm (no core ledger yet) or for a chain the arm did not include
  totals(c: Chain): Totals | null
  close(): void
}

const max = (a: bigint, b: bigint): bigint => (a > b ? a : b)

export function createComparator(def: JobDef): Comparator {
  const reducer = createReducer(def)
  const api = createLedger()
  const core = new Map<Chain, CapLedger>()
  const chains = (['eth', 'sol'] as const).filter((c) => def.chains[c] !== undefined)
  return {
    apply(e) {
      reducer.apply(e)
      api.apply(e)
      if (e.chain === 'eth' || e.chain === 'sol') core.get(e.chain)?.observe({ type: e.type, chain: e.chain, ...e.data })
      if (e.type === 'armed' && core.size === 0) {
        const s = reducer.state()
        for (const c of chains) if (s.armed?.schedule.order.includes(c)) core.set(c, CapLedger.fromArmed(s, c, def.chains[c]!.keyAddress))
      }
    },
    totals(c) {
      const l = core.get(c)
      if (l === undefined) return null
      const cl = api.chain(c), rs = reducer.spent(c)
      return { api: max(cl.charged, rs + cl.clawValue) + cl.inFlight, core: l.spent + l.held, apiCharged: cl.charged, apiInFlight: cl.inFlight, reducerSpent: rs, coreSpent: l.spent, coreHeld: l.held }
    },
    close() { for (const l of core.values()) l.close() },
  }
}

export interface LedgerDiff { seq: number; chain: Chain; api: bigint; core: bigint }
export interface Comparison { lines: number; checked: number; below: LedgerDiff[]; above: LedgerDiff[]; final: Partial<Record<Chain, { api: bigint; core: bigint }>> }

// The whole journal: every line, both chains. below = the API under core (must be empty); above = conservative.
export function compareLedgers(def: JobDef, events: readonly JournalEvent[]): Comparison {
  const cmp = createComparator(def)
  const below: LedgerDiff[] = [], above: LedgerDiff[] = []
  let checked = 0
  try {
    for (const e of events) {
      cmp.apply(e)
      for (const c of ['eth', 'sol'] as const) {
        const t = cmp.totals(c)
        if (t === null) continue
        checked++
        if (t.api < t.core) below.push({ seq: e.seq, chain: c, api: t.api, core: t.core })
        else if (t.api > t.core) above.push({ seq: e.seq, chain: c, api: t.api, core: t.core })
      }
    }
    const final: Comparison['final'] = {}
    for (const c of ['eth', 'sol'] as const) { const t = cmp.totals(c); if (t !== null) final[c] = { api: t.api, core: t.core } }
    return { lines: events.length, checked, below, above, final }
  } finally {
    cmp.close()
  }
}

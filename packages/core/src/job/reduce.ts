// packages/core/src/job/reduce.ts — reduce(def, events) → JobState: a pure, deterministic fold (spec §4.2). The
// semantics are the contract's (src/contracts/types.ts header) and are pinned by contract/fixtures/journals/*. Inputs
// are never mutated; nothing in the result aliases them. Events of a chain the def does not have are ignored.
//
// Choices where the contract is silent (reported with E1), and the fail-closed rules (security review "reducer
// fail-open drift"): an event that does not fit what it names changes NOTHING — an unknown txId, outcome or action, an
// `included` for another (copy, part), a readback of an attempt that has not landed, a claw-back event for a txId that
// is not a member of the current family. Nothing defaults to permissive.
//   · `sent`, a reconcile other than included and a resolve mark-failed move only an attempt that is not final
//     (intent, sent, unknown, adopted, rejected); a reconcile expired / nonce-consumed (chain evidence) also closes one
//     the operator marked failed (resolved-failed: a claim, which the cap ledger keeps holding until such evidence);
//   · CHAIN EVIDENCE WINS (CC-2a, E2 re-review D-1): an inclusion — `included` of the attempt's own (copy, part), a
//     reconcile included, a resolve mark-done — lands ANY attempt that has not landed yet, whatever the journal said
//     before (expired, nonce-consumed, rejected, superseded, resolved-failed): a SOL signature whose expiry was journaled
//     may still land. Open siblings become superseded. Once any attempt of a part has landed the part is landed (never
//     sent again); a second landing is paid (spent) but never counted as progress; the TxView keeps the first landing;
//   · a reconcile with a known outcome, a resolve or an inclusion (of the attempt or of a sibling) clears an attempt's
//     stuck flag; the STUCK reason is the latest stuck event's among the attempts (and open claw-back members) flagged;
//   · spent counts every landed attempt once: its journaled fee, or — when the journal has none (a resolve mark-done,
//     a reconcile included without fee) — its worst case (eth gas × maxFee, sol fee), never 0 (CC-2a, E2 re-review);
//   · the claw-back is a FAMILY (CC-2a): one per chain — every clawback-intent until a member landed joins it (an ETH
//     same-nonce bump, a SOL re-sign after a proven expiry, or a later retry, which re-opens a failed family), so a late
//     event of an earlier member is never lost. Members are open or dead. The family
//     settles ONLY on chain evidence: a member LANDED (clawback-included with the chain's value and fee, or the
//     executor's reconcile included: the value its intent signed, the reconcile's fee or the member's worst-case fee)
//     → clawback.txId / value become that member's, landed true, CLAWED_BACK, even when later bumps exist; or EVERY
//     member is dead and none landed → it fails by itself (E2 re-review D-2): ok false, back to the settled phase
//     (nothing is in flight, so nothing stays locked). A member dies by reconcile expired / nonce-consumed, by
//     clawback-failed (with the fee it was charged if it failed ON CHAIN, spent once per txId, even after another
//     member landed) or by the operator's
//     resolve mark-failed; adopted keeps it open; a resolve mark-done of a member is not chain evidence and changes
//     nothing. While any member is open (unknown or stuck included) the chain stays CLAWING_BACK. A landed claw-back is
//     final: a later clawback-intent is ignored (the API refuses it);
//   · ABSORBING (S2 review I-1): an executor phase event (paused, resumed, drained, copies-done, stopped) or a job
//     intent never moves a chain out of DONE, CLAWED_BACK or CLAWING_BACK, and a clawback-intent never moves DONE (the
//     attempt is still tracked: it may land, so it stays open and keeps the key busy). The API refuses such events
//     first (job/intent.ts assertEventAllowed / assertIntentAllowed);
//   · key-loaded moves only AWAITING_KEY; funds moves only AWAITING_FUNDS ⇄ READY; armed moves only pre-arm phases;
//   · reassembled replaces the entry of the same copy in place;
//   · only the first `armed` event counts; later ones are ignored (E1 review I-1).
import type {
  ArmRecord, AttemptState, AttemptView, Chain, ChainPhase, ChainState, EthIntent, BtcIntent, JobDef, JobState, JournalEvent, SolIntent,
  TxView, StopCode,
} from '../contracts/index.ts'
import { isStopCode, stopClassOf } from '../contracts/stop.ts'

type Obj = Record<string, unknown>
const CHAINS: readonly Chain[] = ['eth', 'sol', 'btc']
export const OPEN_ATTEMPT: ReadonlySet<AttemptState> = new Set<AttemptState>(['intent', 'sent', 'unknown', 'adopted'])
// What the cap holds (S2 2fea217; gates/caps.ts): an open attempt, and — until a landing in its group or a reconcile
// expired / nonce-consumed (chain evidence) — one journaled `rejected` or marked failed (a claim, not evidence).
export const HELD_ATTEMPT: ReadonlySet<AttemptState> = new Set<AttemptState>([...OPEN_ATTEMPT, 'rejected', 'resolved-failed'])
const MOVABLE: ReadonlySet<AttemptState> = new Set<AttemptState>(['intent', 'sent', 'unknown', 'adopted', 'rejected'])
export const LANDED_ATTEMPT: ReadonlySet<AttemptState> = new Set<AttemptState>(['included', 'resolved-done'])
// Eminors (E7-fix2 m-3): the ONE definition of "a btc commit without its reveal" (a stranded commit). A part-1 group counts while any of its attempts
// is open, `rejected` (a claim, not evidence), or landed (included / resolved-done), and no part-2 group of the same copy has landed. Used by
// the reducer's btcStranded accessor, the API's JobState view (intent.ts), the lane's copyInFlight (engine/lane.js) and the executor's
// pre-start check, so the four can never drift. Dead states (expired, nonce-consumed, superseded, resolved-failed) never strand a commit.
export const STRANDING_ATTEMPT: ReadonlySet<AttemptState> = new Set<AttemptState>([...OPEN_ATTEMPT, 'rejected', ...LANDED_ATTEMPT])
export function btcCommitStranded(groups: Iterable<{ copy: number; part: number; attempts: ReadonlyArray<{ state: AttemptState }> }>, revealLanded: (copy: number) => boolean, copy?: number): boolean {
  for (const g of groups) if (g.part === 1 && (copy === undefined || g.copy === copy) && !revealLanded(g.copy) && g.attempts.some((x) => STRANDING_ATTEMPT.has(x.state))) return true
  return false
}
/** The same over a reduced chain's tx views (JobState.chains.btc.txs). */
export function btcStrandedIn(txs: ReadonlyArray<TxView>, copy?: number): boolean {
  return btcCommitStranded(txs, (c) => txs.some((u) => u.copy === c && u.part === 2 && u.state === 'included'), copy)
}
const PRE_ARM: ReadonlySet<ChainPhase> = new Set<ChainPhase>(['AWAITING_KEY', 'AWAITING_FUNDS', 'READY'])
const JOB_RUNNING: ReadonlySet<ChainPhase> = new Set<ChainPhase>(['RUNNING', 'PAUSED', 'STUCK', 'CLAWING_BACK'])
const FREES_KEY: ReadonlySet<ChainPhase> = new Set<ChainPhase>(['DONE', 'CLAWED_BACK', 'SKIPPED'])
const SENT: Readonly<Record<string, AttemptState>> = { accepted: 'sent', unknown: 'unknown', rejected: 'rejected' }
const RECONCILED: Readonly<Record<string, AttemptState>> = { expired: 'expired', 'nonce-consumed': 'nonce-consumed', adopted: 'adopted' }
const DEC = /^(?:0|[1-9][0-9]{0,77})$/

const json = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T
const str = (v: unknown): string | null => (typeof v === 'string' ? v : null)
const int = (v: unknown): number | null => (typeof v === 'number' && Number.isSafeInteger(v) ? v : null)
const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v)
const isChain = (v: unknown): v is Chain => v === 'eth' || v === 'sol' || v === 'btc'
const dec = (v: unknown): bigint | null => (typeof v === 'string' && DEC.test(v) ? BigInt(v) : null)

// The worst-case fee of an intent's chain data: ETH gas × maxFee, SOL the exact fee; null when unknown or malformed.
// Shared with the cap ledger (gates/caps.ts), so both count a landed attempt without a journaled fee the same way.
// E7: a BTC commit's worst case is everything that leaves the lane's spendable outputs for the copy — its fee plus the value it
// locks into the commit output (the reveal's fee and the postage); the reveal moves only what the commit locked, so it holds 0.
export function worstFeeOf(x: { eth?: unknown; sol?: unknown; btc?: unknown }): bigint | null {
  const e = isObj(x.eth) ? x.eth : null, s = isObj(x.sol) ? x.sol : null, b = isObj(x.btc) ? x.btc : null
  if (b !== null) {
    if (b.kind === 'reveal') return 0n
    const f = dec(b.fee), v = dec(b.value)
    return b.kind === 'commit' && f !== null && v !== null ? f + v : null
  }
  if (e !== null) { const g = dec(e.gas), m = dec(e.maxFee); return g !== null && m !== null ? g * m : null }
  if (s !== null) return dec(s.fee)
  return null
}

// What one journal event does to a job attempt in state `cur` (pure; the cap ledger's fold uses the same step, so a
// ledger rebuilt from the journal and a live one that saw the same events agree):
//   land   the attempt lands (as `as`), with the event's block and fee (null when the event has none);
//   to     the attempt's next state (no landing); null: unchanged;
//   clear  the event clears the attempt's stuck flag.
// Fail closed (security review "reducer fail-open drift"): an event whose members do not fit the attempt — an unknown
// outcome or action, an `included` naming another (copy, part) — changes nothing, not even a stuck flag.
export interface AttemptStep { land: { as: 'included' | 'resolved-done'; block: string | null; fee: string | null } | null; to: AttemptState | null; clear: boolean }
export function attemptStep(cur: AttemptState, type: string, d: Obj, at: { copy: number; part: number }): AttemptStep {
  const none: AttemptStep = { land: null, to: null, clear: false }
  const landed = LANDED_ATTEMPT.has(cur)
  switch (type) {
    case 'sent': {
      const to = str(d.outcome)
      return MOVABLE.has(cur) && to !== null && Object.hasOwn(SENT, to) ? { land: null, to: SENT[to], clear: false } : none
    }
    case 'reconcile': {
      const outcome = str(d.outcome)
      if (outcome === 'included') return landed ? none : { land: { as: 'included', block: str(d.block), fee: str(d.fee) }, to: null, clear: true }   // D-1
      // chain evidence over a claim: expired / nonce-consumed also closes an attempt the operator marked failed
      const from = MOVABLE.has(cur) || (cur === 'resolved-failed' && (outcome === 'expired' || outcome === 'nonce-consumed'))
      if (!from || outcome === null || !Object.hasOwn(RECONCILED, outcome)) return none
      return { land: null, to: RECONCILED[outcome], clear: true }
    }
    case 'included':                                                  // D-1; only for the attempt's own (copy, part)
      return landed || int(d.copy) !== at.copy || int(d.part) !== at.part ? none : { land: { as: 'included', block: str(d.block), fee: str(d.fee) }, to: null, clear: true }
    case 'resolved':
      if (d.action === 'mark-done') return landed ? none : { land: { as: 'resolved-done', block: null, fee: null }, to: null, clear: true }
      if (d.action === 'mark-failed' && MOVABLE.has(cur)) return { land: null, to: 'resolved-failed', clear: true }
      return none
    default: return none
  }
}

// What one journal event does to a member (open or dead) of a claw-back family (pure; shared with the cap ledger).
// Fail closed: the family settles only on chain evidence — a member LANDED (clawback-included with the chain's value and
// fee, or the executor's reconcile included) — or when every member is dead (reconcile expired / nonce-consumed,
// clawback-failed, the operator's resolve mark-failed). A resolve mark-done of a member is not chain evidence: it
// changes nothing (the API refuses it). clawback-failed kills only that member, with the fee it was charged on chain.
//   land   the family lands with this member; to: the member's next state (+ fee charged); clear: its stuck flag clears.
export type MemberStep = { land: { value: string | null; fee: string | null } } | { to: 'open' | 'dead'; fee: string | null; clear: boolean } | null
export function memberStep(cur: 'open' | 'dead', type: string, d: Obj): MemberStep {
  switch (type) {
    case 'clawback-included': return { land: { value: str(d.value), fee: str(d.fee) } }
    case 'clawback-failed': return { to: 'dead', fee: str(d.fee), clear: true }
    case 'reconcile': {
      const outcome = str(d.outcome)
      if (outcome === 'included') return { land: { value: null, fee: str(d.fee) } }
      if (cur !== 'open') return null                                 // dead is final
      if (outcome === 'expired' || outcome === 'nonce-consumed') return { to: 'dead', fee: null, clear: true }
      return outcome === 'adopted' ? { to: 'open', fee: null, clear: true } : null
    }
    case 'resolved': return cur === 'open' && d.action === 'mark-failed' ? { to: 'dead', fee: null, clear: true } : null
    default: return null
  }
}


// ---------------------------------------------------------------- the incremental reducer (S2 review I-3)
// createReducer(def) folds one event at a time; reduce(def, events) is the fold over it (one implementation). apply()
// is O(1) amortised: Maps and counters kept in place (per (copy, part) group: open / stuck / landed attempt counts and
// its hold; per chain: open, stuck, in-flight and spend totals), work bounded by the attempts of one group or the
// members of one claw-back family. state() builds the JobState (O(n)) lazily and memoizes it until the next apply —
// the returned object is shared: do not mutate it. The accessors answer the send path's questions in O(1).
export type TxFact =
  | { kind: 'job'; copy: number; part: number; state: AttemptState; open: boolean; landed: boolean; stuck: boolean }
  | { kind: 'claw'; open: boolean; landed: boolean; stuck: boolean }
export interface JobReducer {
  apply(e: JournalEvent): void
  state(): JobState
  readonly length: number                                 // events applied
  phase(chain: Chain): ChainPhase | null                  // with the STUCK and SKIPPED overlays, as state()
  tx(chain: Chain, txId: string): TxFact | null           // a job attempt or a member of the claw-back family; null: unknown
  landed(chain: Chain, copy: number, part: number): boolean
  inFlight(chain: Chain): boolean                         // a job tx is open or stuck (TxView.state open | stuck)
  copyLanded(chain: Chain, copy: number): boolean         // a part of that copy landed
  btcStranded(chain: Chain): boolean                      // E7 fix round 2: a btc copy whose commit is open or landed and whose reveal has not landed
  stopLatched(chain: Chain): boolean                      // PF-S fix round 5 (R34-1; CC-15 addendum): a journaled `stopped`, not yet cleared by an operator resume
  basePhase(chain: Chain): ChainPhase | null              // PF-S fix round 6 (CC-15 addendum): the phase under the STUCK overlay (SKIPPED for a skipped chain; null: no such chain)
  openIntents(chain: Chain): number                       // the length of ChainState.openIntents
  spent(chain: Chain): bigint                             // = BigInt(ChainState.spent)
  held(chain: Chain): bigint                              // the cap ledger's hold (gates/caps.ts): open worst cases + claims until evidence
  armed(): ArmRecord | null                               // a copy
}

const ABSORBING: ReadonlySet<ChainPhase> = new Set<ChainPhase>(['DONE', 'CLAWED_BACK'])
// S2 review I-1: executor phase events (paused, resumed, drained, copies-done, stopped) and job intents never move a
// chain out of DONE, CLAWED_BACK or CLAWING_BACK (the API refuses them first: assertEventAllowed, assertIntentAllowed).
const HOLDS: ReadonlySet<ChainPhase> = new Set<ChainPhase>(['DONE', 'CLAWED_BACK', 'CLAWING_BACK'])
// PF-S fix round 6: no executor event moves a chain whose BASE is settled back to a running phase — DRAINED and COPIES_DONE (never
// reopened by an executor: a new job or the operator's flows handle a top-up), a stop-latched STOPPED (until the operator's resume),
// and HOLDS. Phase events and job intents leave such a base as it is (the gate refuses them first: job/intent.ts).
const SETTLED_BASE: ReadonlySet<ChainPhase> = new Set<ChainPhase>(['DRAINED', 'COPIES_DONE'])
const frozen = (a: { base: ChainPhase; stopLatched: boolean }): boolean => HOLDS.has(a.base) || SETTLED_BASE.has(a.base) || (a.base === 'STOPPED' && a.stopLatched)

// E7: the BTC intent as journaled (events.ts btcIntent); the reduced AttemptView carries it as `btc` (a takeover rebuilds the very
// bytes from it). CC-12 ratified the type in contracts/types.ts (BtcIntent); this alias keeps the old name.
export type BtcIntentData = BtcIntent
interface Attempt { txId: string; gen: number; state: AttemptState; eth?: EthIntent; sol?: SolIntent; btc?: BtcIntentData; rawSha256?: string; stuck: { reason: string; at: number } | null; paid: bigint | null; worst: bigint | null; g: Group }
interface Group {
  copy: number; part: number; parts: number; attempts: Attempt[]; landedId: string | null; block: string | null; fee: string | null; readback: boolean | null
  open: number; stuck: number; landed: number; hold: bigint
}
interface Member { state: 'open' | 'dead'; value: string; worstFee: bigint | null; stuck: { reason: string; at: number } | null }
interface Claw { txId: string; to: string; value: string; ok: boolean | null; members: Map<string, Member>; open: number; done: boolean; landed: boolean }
interface Acc {
  base: ChainPhase; reason: string | null; delegated: boolean; skipped: boolean; settled: { phase: ChainPhase; reason: string | null } | null
  address: string | null; copy: number | null; attempt: number | null
  groups: Map<string, Group>; byTx: Map<string, Attempt>
  reassembled: Map<number, boolean>; stopRequested: boolean; claw: Claw | null; charged: Set<string>
  // PF-S fix round 5 (R34-1, the stop latch): set by a journaled `stopped`; cleared ONLY by the operator's resume-requested. While set,
  // no executor event moves the base out of STOPPED (paused, resumed, drained, copies-done, a job intent), STUCK overlay or not.
  stopLatched: boolean
  // R79b (contracts/stop.ts): the code of the journaled `stopped` that made the base STOPPED (null: none, or one this build does not
  // know — FINAL, fail closed); cleared with `delegated` by any later phase event that moves the base on.
  stopCode: StopCode | null
  openJob: number; stuckN: number; flight: number; spent: bigint; heldJob: bigint; landedParts: Map<number, number>
}

function fresh(): Acc {
  return {
    base: 'AWAITING_KEY', reason: null, delegated: false, skipped: false, settled: null, address: null, copy: null, attempt: null,
    groups: new Map(), byTx: new Map(), reassembled: new Map(), stopRequested: false, claw: null, charged: new Set(), stopLatched: false, stopCode: null,
    openJob: 0, stuckN: 0, flight: 0, spent: 0n, heldJob: 0n, landedParts: new Map(),
  }
}

function armRecord(d: Obj): ArmRecord | null {
  const s = d.schedule
  if (!isObj(s) || !Array.isArray(s.order) || !isObj(s.offsetSec) || int(d.armedAt) === null || int(d.releaseAt) === null) return null
  const r = json(d)
  return {
    armedAt: r.armedAt as number, releaseAt: r.releaseAt as number, countdownSec: r.countdownSec as number,
    schedule: r.schedule as ArmRecord['schedule'], caps: (isObj(r.caps) ? r.caps : {}) as ArmRecord['caps'],
    sources: (isObj(r.sources) ? r.sources : {}) as ArmRecord['sources'],
  }
}

const inFlightOf = (g: Group): boolean => g.landed === 0 && (g.open > 0 || g.stuck > 0)
// Every change of an attempt's state or stuck flag goes through here, so the counters stay exact.
function touch(a: Acc, at: Attempt, change: () => void): void {
  const g = at.g, wasFlight = inFlightOf(g), wasOpen = OPEN_ATTEMPT.has(at.state), wasLanded = LANDED_ATTEMPT.has(at.state), wasStuck = at.stuck !== null
  change()
  const isOpen = OPEN_ATTEMPT.has(at.state), isLanded = LANDED_ATTEMPT.has(at.state), isStuck = at.stuck !== null
  if (wasOpen !== isOpen) { g.open += isOpen ? 1 : -1; a.openJob += isOpen ? 1 : -1 }
  if (wasLanded !== isLanded) {
    const before = g.landed > 0
    g.landed += isLanded ? 1 : -1
    if (before !== g.landed > 0) a.landedParts.set(g.copy, (a.landedParts.get(g.copy) ?? 0) + (g.landed > 0 ? 1 : -1))
  }
  if (wasStuck !== isStuck) { g.stuck += isStuck ? 1 : -1; a.stuckN += isStuck ? 1 : -1 }
  if (wasFlight !== inFlightOf(g)) a.flight += inFlightOf(g) ? 1 : -1
  // the group's hold, as the cap ledger's (gates/caps.ts holdOf; E3 review m-1): the largest worst case of an attempt
  // that may still land — open, or a claim (rejected, resolved-failed) while the group has not landed
  let h = 0n
  for (const x of g.attempts) if ((OPEN_ATTEMPT.has(x.state) || (g.landed === 0 && HELD_ATTEMPT.has(x.state))) && (x.worst ?? 0n) > h) h = x.worst ?? 0n
  a.heldJob += h - g.hold; g.hold = h
}

// The attempt lands: open siblings are superseded, every stuck flag of the group clears. The first landing is the
// group's record (landedId, block, fee); every landing is paid: its fee, or its worst case when the fee is unknown.
function land(a: Acc, at: Attempt, as: 'included' | 'resolved-done', block: string | null, fee: string | null): void {
  const g = at.g
  for (const s of g.attempts) if (s !== at) touch(a, s, () => { if (OPEN_ATTEMPT.has(s.state)) s.state = 'superseded'; s.stuck = null })
  touch(a, at, () => { at.state = as; at.stuck = null })
  at.paid = dec(fee) ?? at.worst ?? 0n
  a.spent += at.paid
  if (g.landedId === null) { g.landedId = at.txId; g.block = block; g.fee = fee }
}

function chargeClaw(a: Acc, txId: string, fee: bigint | null): void {
  if (fee === null || a.charged.has(txId)) return
  a.charged.add(txId); a.spent += fee
}
function memberTo(a: Acc, c: Claw, m: Member, state: 'open' | 'dead', clear: boolean): void {
  if (m.state !== state) c.open += state === 'open' ? 1 : -1
  m.state = state
  if (clear && m.stuck !== null) { m.stuck = null; a.stuckN-- }
}
// The claw-back landed with member txId: the value it moved (the chain's, or what its intent signed) and its fee (the
// chain's, or the member's worst case when unknown). Every other member closes. A closed (DONE) chain stays DONE.
function landClaw(a: Acc, c: Claw, txId: string, value: string | null, fee: string | null): void {
  if (c.landed) return
  const m = c.members.get(txId)!
  if (!ABSORBING.has(a.base)) { a.base = 'CLAWED_BACK'; a.reason = null }
  c.txId = txId; c.value = value ?? m.value; c.ok = true; c.done = true; c.landed = true
  for (const x of c.members.values()) memberTo(a, c, x, 'dead', true)
  chargeClaw(a, txId, dec(fee) ?? m.worstFee ?? 0n)
}
// Every member is dead and none landed: nothing of the claw-back can land any more.
function failClaw(a: Acc, c: Claw): void {
  if (!ABSORBING.has(a.base)) { a.base = a.settled?.phase ?? a.base; a.reason = a.settled?.reason ?? null }
  c.ok = false; c.done = true
  for (const x of c.members.values()) memberTo(a, c, x, x.state, true)
}

function txState(g: Group): TxView['state'] {
  if (g.landed > 0) return 'included'
  if (g.stuck > 0) return 'stuck'
  return g.open > 0 ? 'open' : 'failed'
}
const phaseOf = (a: Acc): ChainPhase => (a.skipped ? 'SKIPPED' : a.stuckN > 0 ? 'STUCK' : a.base)
// PF-S fix round 5 (R34-1): the latch as ChainState shows it (and the gate reads it): not on a SKIPPED, CLAWED_BACK or DONE chain
const latchedOf = (a: Acc): boolean => a.stopLatched && !a.skipped && a.base !== 'CLAWED_BACK' && a.base !== 'DONE'

function finish(a: Acc): ChainState {
  const groups = [...a.groups.values()].sort((x, y) => x.copy - y.copy || x.part - y.part)
  const txs: TxView[] = groups.map((g) => ({
    copy: g.copy, part: g.part, parts: g.parts,
    attempts: g.attempts.map((t): AttemptView => ({ txId: t.txId, gen: t.gen, state: t.state, ...(t.eth ? { eth: json(t.eth) } : {}), ...(t.sol ? { sol: json(t.sol) } : {}), ...(t.btc ? { btc: json(t.btc), ...(t.rawSha256 !== undefined ? { rawSha256: t.rawSha256 } : {}) } : {}) })),
    state: txState(g), landedId: g.landedId, block: g.block, fee: g.fee, readback: g.readback,
  }))
  const openIntents = txs.flatMap((t) => t.attempts.filter((x) => OPEN_ATTEMPT.has(x.state)).map((x) => x.txId))
  if (a.claw !== null && !a.claw.done) for (const [id, m] of a.claw.members) if (m.state === 'open') openIntents.push(id)

  // Copies: a part is complete when its tx is included and read back ok. Linear in the number of txs.
  const complete = new Set(txs.filter((t) => t.state === 'included' && t.readback === true).map((t) => `${t.copy}:${t.part}`))
  const partsOf = new Map<number, number>()
  let current: number | null = null
  for (const t of txs) {
    partsOf.set(t.copy, Math.max(partsOf.get(t.copy) ?? 0, t.parts))
    if (current === null || t.copy > current) current = t.copy
  }
  const firstMissing = (copy: number): number | null => {
    for (let p = 1; p <= (partsOf.get(copy) ?? 0); p++) if (!complete.has(`${copy}:${p}`)) return p
    return null
  }
  let copiesIncluded = 0
  for (const c of partsOf.keys()) if (firstMissing(c) === null) copiesIncluded++
  const next = current === null ? null : firstMissing(current)

  let latest: { reason: string; at: number } | null = null
  const see = (s: { reason: string; at: number } | null): void => { if (s !== null && (latest === null || s.at > latest.at)) latest = s }
  for (const g of groups) for (const t of g.attempts) see(t.stuck)
  if (a.claw !== null) for (const m of a.claw.members.values()) see(m.stuck)
  const phase = phaseOf(a)
  const reason = a.skipped ? 'not armed' : latest !== null ? (latest as { reason: string }).reason : a.reason

  const cs: ChainState = {
    phase, reason, address: a.address, copy: a.copy, attempt: a.attempt, copiesIncluded,
    reassembled: [...a.reassembled].map(([copy, ok]) => ({ copy, ok })), spent: a.spent.toString(), txs, openIntents,
    resume: current !== null && next !== null ? { copy: current, nextPart: next } : null, stopRequested: a.stopRequested,
    clawback: a.claw === null ? null : { txId: a.claw.txId, to: a.claw.to, value: a.claw.value, ok: a.claw.ok, landed: a.claw.landed },
    ...(a.delegated && phase !== 'SKIPPED' && a.base !== 'CLAWED_BACK' && a.base !== 'DONE' ? { delegated: true as const } : {}),
    ...(latchedOf(a) ? { stopLatched: true as const } : {}),
    ...(phase === 'STUCK' ? { stuckBase: a.base } : {}),   // PF-S fix round 6: the base under the overlay (the gate judges phase events on it)
    ...(a.stopCode !== null && a.base === 'STOPPED' ? { stopCode: a.stopCode } : {}),   // R79b: the stop's code while the base is STOPPED
  }
  // R79b: the class of the stop (contracts/stop.ts) on a chain whose base is STOPPED — from its code and the journal's FINAL facts; fail closed
  if (a.base === 'STOPPED' && !a.skipped) cs.stopClass = stopClassOf(cs).cls
  return cs
}

export function createReducer(def: JobDef): JobReducer {
  const accs = new Map<Chain, Acc>()
  for (const c of CHAINS) if (def.chains[c] !== undefined) accs.set(c, fresh())
  let armed: ArmRecord | null = null
  let releaseAt: number | null = null
  let stuckClock = 0, n = 0, lastSeq = 0
  let memo: JobState | null = null
  const targets = (c: unknown): Acc[] => (c === null ? [...accs.values()] : isChain(c) && accs.has(c) ? [accs.get(c)!] : [])

  function apply(e: JournalEvent): void {
    n++; lastSeq = e.seq; memo = null
    const d: Obj = isObj(e.data) ? e.data : {}
    switch (e.type) {
      case 'armed': {
        // The first armed event wins (E1 review I-1): a second one (a malformed journal, or a check-then-append race
        // in the API) never re-arms, never moves releaseAt and never SKIPs a chain that may already be running.
        const r = armRecord(d)
        if (r === null || armed !== null) return
        armed = r
        releaseAt = r.releaseAt
        for (const [c, a] of accs) {
          if (!r.schedule.order.includes(c)) a.skipped = true
          else if (PRE_ARM.has(a.base)) { a.base = 'ARMED'; a.reason = null }
        }
        return
      }
      case 'skip': {
        const r = int(d.releaseAt)
        if (r !== null) { releaseAt = r; if (armed !== null) armed.releaseAt = r }
        return
      }
      case 'stop-requested': for (const a of targets(d.chain === undefined ? e.chain : d.chain)) a.stopRequested = true; return
      case 'resume-requested': for (const a of targets(d.chain === undefined ? e.chain : d.chain)) { a.stopRequested = false; a.stopLatched = false } return   // the operator's resume clears the latch
      case 'close': { // one chain only: a close never applies to "all"
        const c = d.chain === undefined || d.chain === null ? e.chain : d.chain
        const a = isChain(c) ? accs.get(c) : undefined
        if (a !== undefined) { a.base = 'DONE'; a.reason = null }
        return
      }
      default: break
    }
    if (!isChain(e.chain)) return
    const a = accs.get(e.chain)
    if (a === undefined) return
    const tx = str(d.txId)
    const hit = tx === null ? undefined : a.byTx.get(tx)
    const claw = a.claw !== null && tx !== null && a.claw.members.has(tx) ? a.claw : null
    switch (e.type) {
      case 'key-loaded':
        a.address = str(d.address) ?? a.address
        if (a.base === 'AWAITING_KEY') a.base = 'AWAITING_FUNDS'
        return
      case 'funds':
        if (a.base === 'AWAITING_FUNDS' || a.base === 'READY') a.base = d.affordable === true ? 'READY' : 'AWAITING_FUNDS'
        return
      case 'intent': {
        const copy = int(d.copy), part = int(d.part), parts = int(d.parts)
        if (tx === null || copy === null || part === null || parts === null || hit !== undefined) return
        const key = `${copy}:${part}`
        let g = a.groups.get(key)
        if (g === undefined) { g = { copy, part, parts, attempts: [], landedId: null, block: null, fee: null, readback: null, open: 0, stuck: 0, landed: 0, hold: 0n }; a.groups.set(key, g) }
        const at: Attempt = { txId: tx, gen: e.gen ?? 0, state: 'rejected', stuck: null, paid: null, worst: worstFeeOf(d), g }
        if (isObj(d.eth)) at.eth = json(d.eth) as unknown as EthIntent
        if (isObj(d.sol)) at.sol = json(d.sol) as unknown as SolIntent
        if (isObj(d.btc)) { at.btc = json(d.btc) as unknown as BtcIntentData; at.rawSha256 = str(d.rawSha256) ?? undefined }
        g.attempts.push(at)
        a.byTx.set(tx, at)
        touch(a, at, () => { at.state = 'intent' })                    // counted as it opens
        a.copy = copy
        a.attempt = int(d.attempt)
        if (!frozen(a)) { a.base = 'RUNNING'; a.reason = null; a.delegated = false; a.stopCode = null }   // tracked, but never revives a settled base (fix rounds 5, 6)
        return
      }
      case 'sent': case 'reconcile': case 'included': case 'resolved': case 'clawback-included': case 'clawback-failed': {
        const job = e.type === 'sent' || e.type === 'reconcile' || e.type === 'included' || e.type === 'resolved'
        if (hit !== undefined && job) {
          const s = attemptStep(hit.state, e.type, d, hit.g)
          if (s.land !== null) land(a, hit, s.land.as, s.land.block, s.land.fee)
          else touch(a, hit, () => { if (s.clear) hit.stuck = null; if (s.to !== null) hit.state = s.to })
        } else if (claw !== null && tx !== null && e.type !== 'sent' && e.type !== 'included') {
          const m = claw.members.get(tx)!
          const s = memberStep(m.state, e.type, d)
          if (s !== null && 'land' in s) landClaw(a, claw, tx, s.land.value, s.land.fee)
          else if (s !== null) {
            chargeClaw(a, tx, dec(s.fee))                                 // a member that failed ON CHAIN was charged its fee (also after a landing)
            if (!claw.landed) {
              memberTo(a, claw, m, s.to, s.clear)
              if (!claw.done && claw.open === 0) failClaw(a, claw)        // D-2: every member dead, none landed — nothing left in flight
            }
          }
        }
        return
      }
      case 'readback':                                                 // only a landed attempt's readback counts
        if (hit !== undefined && LANDED_ATTEMPT.has(hit.state)) hit.g.readback = d.ok === true
        return
      case 'stuck': {
        const reason = str(d.reason) ?? ''
        if (hit !== undefined && OPEN_ATTEMPT.has(hit.state)) touch(a, hit, () => { hit.stuck = { reason, at: ++stuckClock } })
        else if (claw !== null && tx !== null && !claw.done && claw.members.get(tx)!.state === 'open') {
          const m = claw.members.get(tx)!
          if (m.stuck === null) a.stuckN++
          m.stuck = { reason, at: ++stuckClock }
        }
        return
      }
      // PF-S fix round 5 (R34-1): a stop-latched chain stays STOPPED on every executor phase event (the API refuses them first)
      case 'paused': if (!frozen(a)) { a.base = 'PAUSED'; a.reason = str(d.reason); a.delegated = false; a.stopCode = null } return
      case 'resumed': if (!frozen(a)) { a.base = 'RUNNING'; a.reason = null; a.delegated = false; a.stopCode = null } return
      case 'drained': if (!frozen(a)) { a.base = 'DRAINED'; a.reason = null; a.delegated = false; a.stopCode = null } return
      case 'copies-done': if (!frozen(a)) { a.base = 'COPIES_DONE'; a.reason = null; a.delegated = false; a.stopCode = null } return
      // a stop of a running (or stopped) chain; a DRAINED / COPIES_DONE base stays as it is (fix round 6)
      case 'stopped': if (!HOLDS.has(a.base) && !SETTLED_BASE.has(a.base)) { a.base = 'STOPPED'; a.reason = str(d.reason); a.delegated = d.delegated === true; a.stopLatched = true; a.stopCode = isStopCode(d.code) ? d.code : null } return   // Eminors: the structured EIP-7702 stop; R79b: its code
      case 'clawback-intent': {
        if (tx === null || (a.claw !== null && (a.claw.landed || a.claw.members.has(tx)))) return   // final, or the same intent again
        const m: Member = { state: 'open', value: str(d.value) ?? '', worstFee: worstFeeOf(d), stuck: null }   // never a default value
        if (a.claw !== null) {                                       // a bump, a re-sign or a retry joins the family (re-opens a failed one)
          const c = a.claw
          c.members.set(tx, m); c.open++; c.txId = tx; c.to = str(d.to) ?? c.to; c.value = m.value
          if (c.done) { c.done = false; c.ok = null }
        } else {
          a.settled = { phase: a.base, reason: a.reason }
          a.claw = { txId: tx, to: str(d.to) ?? '', value: m.value, ok: null, members: new Map([[tx, m]]), open: 1, done: false, landed: false }
        }
        if (!ABSORBING.has(a.base)) { a.base = 'CLAWING_BACK'; a.reason = null }
        return
      }
      case 'clawback-readback':                                        // only the landed member's readback counts
        if (claw !== null && claw.landed && tx === claw.txId) claw.ok = d.ok === true
        return
      case 'reassembled': {
        const copy = int(d.copy)
        if (copy !== null) a.reassembled.set(copy, d.ok === true)       // in place: a Map keeps the first position
        return
      }
      default: return // created, lease-*, note, copy-built, replaced, clawback-sent: no state of their own
    }
  }

  function state(): JobState {
    if (memo !== null) return memo
    const chains: Partial<Record<Chain, ChainState>> = {}
    for (const [c, a] of accs) chains[c] = finish(a)
    const list = Object.values(chains) as ChainState[]
    // Final round (F18-2): the job is DONE only when every chain is terminal (isChainTerminal: DONE, CLAWED_BACK or SKIPPED, nothing open —
    // its key is free). A chain settled but not terminal (STOPPED — resumable or final —, DRAINED, COPIES_DONE) keeps the job ARMED, the
    // same label before and after a resume cycle (it was DONE while STOPPED and ARMED again after the resume and copies-done)
    const done = list.length > 0 && list.every(isChainTerminal)
    const phase = done ? 'DONE' : list.some((cs) => JOB_RUNNING.has(cs.phase)) ? 'RUNNING' : armed !== null ? 'ARMED' : 'DEFINED'
    memo = { phase, armed: armed === null ? null : json(armed), releaseAt, chains, seq: n === 0 ? 0 : lastSeq, corrupt: null }
    return memo
  }

  const acc = (c: Chain): Acc | undefined => accs.get(c)
  return {
    apply, state,
    get length() { return n },
    phase: (c) => { const a = acc(c); return a === undefined ? null : phaseOf(a) },
    tx: (c, txId) => {
      const a = acc(c)
      if (a === undefined) return null
      const at = a.byTx.get(txId)
      if (at !== undefined) return { kind: 'job', copy: at.g.copy, part: at.g.part, state: at.state, open: OPEN_ATTEMPT.has(at.state), landed: LANDED_ATTEMPT.has(at.state), stuck: at.stuck !== null }
      const m = a.claw?.members.get(txId)
      if (m === undefined || a.claw === null) return null
      return { kind: 'claw', open: !a.claw.done && m.state === 'open', landed: a.claw.landed && a.claw.txId === txId, stuck: m.stuck !== null }
    },
    landed: (c, copy, part) => (acc(c)?.groups.get(`${copy}:${part}`)?.landed ?? 0) > 0,
    inFlight: (c) => (acc(c)?.flight ?? 0) > 0,
    copyLanded: (c, copy) => (acc(c)?.landedParts.get(copy) ?? 0) > 0,
    btcStranded: (c) => {
      const a = acc(c)
      if (a === undefined || c !== 'btc') return false
      return btcCommitStranded(a.groups.values(), (copy) => (a.groups.get(`${copy}:2`)?.landed ?? 0) > 0)
    },
    stopLatched: (c) => { const a = acc(c); return a !== undefined && latchedOf(a) },
    basePhase: (c) => { const a = acc(c); return a === undefined ? null : a.skipped ? 'SKIPPED' : a.base },
    openIntents: (c) => { const a = acc(c); return a === undefined ? 0 : a.openJob + (a.claw !== null && !a.claw.done ? a.claw.open : 0) },
    spent: (c) => acc(c)?.spent ?? 0n,
    held: (c) => {
      const a = acc(c)
      if (a === undefined) return 0n
      let h = a.heldJob, m = 0n
      if (a.claw !== null && !a.claw.done) for (const x of a.claw.members.values()) if (x.state === 'open') { const w = (dec(x.value) ?? 0n) + (x.worstFee ?? 0n); if (w > m) m = w }
      return h + m
    },
    armed: () => (armed === null ? null : json(armed)),
  }
}

// The whole journal at once: the fold over createReducer (one implementation). The result is the caller's own.
export function reduce(def: JobDef, events: readonly JournalEvent[]): JobState {
  const r = createReducer(def)
  for (const e of events) r.apply(e)
  return r.state()
}

// Frees the key (job.key-busy): DONE, CLAWED_BACK or SKIPPED with no open intents. STOPPED, DRAINED and COPIES_DONE
// keep it busy until a claw-back or close (ruling 5).
export function isChainTerminal(cs: ChainState): boolean {
  return FREES_KEY.has(cs.phase) && cs.openIntents.length === 0
}

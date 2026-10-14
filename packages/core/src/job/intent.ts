// packages/core/src/job/intent.ts — assertIntentAllowed (E1 review X-1) and assertEventAllowed (S2 review I-1). The API
// (S2) calls them before the fsync and the send ticket, with the state reduced from the journal so far — a JobState,
// or the incremental reducer (createReducer, O(1) facts: S2 review I-3). They make the API's arm re-checks (typed
// confirmation, over-cap amount, countdown, stagger) binding on the send itself, and keep a settled chain settled: an
// executor or page bug can no longer send before arm, on a chain that was not armed, before its start time, or after it
// settled, and can no longer revive a DONE, CLAWED_BACK or CLAWING_BACK chain.
//
//   job.state  (one guard, one marker; the message names the rule) refused when:
//   assertIntentAllowed (intent, clawback-intent):
//     · the journal is CORRUPT;
//     · the job is not armed, or this chain is not in the arm order, or it is SKIPPED;
//     · intent: the phase is not ARMED, RUNNING or PAUSED (STUCK, settled, clawing back and terminal phases refuse;
//       a STUCK attempt is never resent and blocks the chain until resolved, spec §4.2);
//       nowMs < startAt(armed, chain) (the countdown, a Skip and the stagger);
//       target (copy, part) given and that part already landed (any attempt included or resolved done);
//     · clawback-intent: the phase is settled — DRAINED, COPIES_DONE or STOPPED — or CLAWING_BACK (a fee bump or a
//       re-sign joins the open claw-back), and no job attempt is open or stuck (nothing in flight, R64).
//   assertEventAllowed (every other executor event; fail closed — security review "reducer fail-open drift"):
//     · the journal is CORRUPT, the chain is not in the job, or the type is not an executor event;
//     · paused, resumed, drained, copies-done, stopped, copy-built: the phase is not ARMED, RUNNING, PAUSED or STUCK
//       (never on DONE, CLAWED_BACK, CLAWING_BACK, SKIPPED, a settled or a pre-arm chain);
//     · evidence must name what it is about: sent, reconcile, included, readback, replaced, stuck → a known job attempt
//       (or, for reconcile and stuck, a member of the claw-back family) of THIS chain; included → its own (copy, part);
//       readback → an attempt that landed; replaced → prevId of the same (copy, part); stuck → an open one;
//       clawback-sent, clawback-included, clawback-failed → a member of the family; clawback-readback → the member
//       that landed. An unknown txId is refused, never folded.
//     · reassembled: a copy with a landed part; key-loaded, funds and note are always allowed (they move only pre-arm
//       phases, or nothing).
// Pure: no I/O, no clock of its own (nowMs is the API's clock).
import { refuse } from '../contracts/index.ts'
import { refuseBtcOpen } from '../gates/btc.ts'
import type { ArmRecord, AttemptState, Chain, ChainPhase, JobDef, JobState } from '../contracts/index.ts'
import { LANDED_ATTEMPT, OPEN_ATTEMPT, btcStrandedIn } from './reduce.ts'
import type { JobReducer, TxFact } from './reduce.ts'
import { startAt } from './schedule.ts'

export type IntentKind = 'intent' | 'clawback-intent'
// The state these checks read: a reduced JobState, or the incremental reducer with the API's corrupt overlay.
export type JobView = JobState | { reducer: JobReducer; corrupt: string | null }

const SEND_PHASES: ReadonlySet<ChainPhase> = new Set<ChainPhase>(['ARMED', 'RUNNING', 'PAUSED'])
const CLAW_PHASES: ReadonlySet<ChainPhase> = new Set<ChainPhase>(['DRAINED', 'COPIES_DONE', 'STOPPED', 'CLAWING_BACK'])
// PF-S fix round 6: executor phase events are judged on the BASE phase (under the STUCK overlay), never the overlay itself: only a
// chain that runs (ARMED, RUNNING, PAUSED) — or a STOPPED one the operator resumed (no stop latch) — is moved by them. A settled base
// (STOPPED latched, DRAINED, COPIES_DONE, DONE, CLAWED_BACK, CLAWING_BACK) or a SKIPPED chain never is, STUCK or not.
const RUN_BASES: ReadonlySet<ChainPhase> = new Set<ChainPhase>(['ARMED', 'RUNNING', 'PAUSED'])
const PHASE_EVENTS: ReadonlySet<string> = new Set(['paused', 'resumed', 'drained', 'copies-done', 'stopped', 'copy-built'])
// E7 fix round 2: events that end a chain's run for good (a stopped / drained / copies-done chain is never revived)
const ENDING_EVENTS: ReadonlySet<string> = new Set(['drained', 'copies-done', 'stopped'])

// base: the phase under the STUCK overlay (SKIPPED for a skipped chain); a JobState without stuckBase under STUCK reads as STUCK (fail closed)
interface ChainFacts { btcStranded(): boolean; phase: ChainPhase; base: ChainPhase; inFlight(): boolean; landed(copy: number, part: number): boolean; tx(txId: string): TxFact | null; copyLanded(copy: number): boolean; stopLatched(): boolean }
interface Facts { corrupt: boolean; armed: ArmRecord | null; chain(c: Chain): ChainFacts | null }

// Facts from a JobState: indexes built per call. A claw-back member is known while open (openIntents) and as the
// family's latest or landed member (clawback.txId); an earlier dead member is not visible here → unknown (fail closed;
// the incremental reducer knows every member).
function factsOfState(state: JobState): Facts {
  return {
    corrupt: state.corrupt !== null || state.phase === 'CORRUPT',
    armed: state.armed,
    chain(c) {
      const cs = state.chains[c]
      if (cs === undefined) return null
      let byTx: Map<string, TxFact> | null = null
      const index = (): Map<string, TxFact> => {
        if (byTx !== null) return byTx
        byTx = new Map()
        for (const t of cs.txs) for (const x of t.attempts) {
          byTx.set(x.txId, { kind: 'job', copy: t.copy, part: t.part, state: x.state as AttemptState, open: OPEN_ATTEMPT.has(x.state), landed: LANDED_ATTEMPT.has(x.state), stuck: t.state === 'stuck' && OPEN_ATTEMPT.has(x.state) })
        }
        for (const id of cs.openIntents) if (!byTx.has(id)) byTx.set(id, { kind: 'claw', open: true, landed: false, stuck: cs.phase === 'STUCK' })
        const cb = cs.clawback
        if (cb !== null && !byTx.has(cb.txId)) byTx.set(cb.txId, { kind: 'claw', open: false, landed: cb.landed === true, stuck: false })
        else if (cb !== null && cb.landed === true) { const f = byTx.get(cb.txId)!; if (f.kind === 'claw') byTx.set(cb.txId, { ...f, landed: true }) }
        return byTx
      }
      return {
        btcStranded: () => c === 'btc' && btcStrandedIn(cs.txs),
        phase: cs.phase,
        base: cs.phase === 'STUCK' ? cs.stuckBase ?? 'STUCK' : cs.phase,
        inFlight: () => cs.txs.some((t) => t.state === 'open' || t.state === 'stuck'),
        landed: (copy, part) => cs.txs.some((t) => t.copy === copy && t.part === part && t.state === 'included'),
        tx: (txId) => index().get(txId) ?? null,
        copyLanded: (copy) => cs.txs.some((t) => t.copy === copy && t.state === 'included'),
        stopLatched: () => cs.stopLatched === true,
      }
    },
  }
}
function factsOfReducer(r: JobReducer, corrupt: string | null): Facts {
  return {
    corrupt: corrupt !== null,
    armed: r.armed(),
    chain(c) {
      const phase = r.phase(c)
      if (phase === null) return null
      return { btcStranded: () => r.btcStranded(c), phase, base: r.basePhase(c) ?? phase, inFlight: () => r.inFlight(c), landed: (copy, part) => r.landed(c, copy, part), tx: (txId) => r.tx(c, txId), copyLanded: (copy) => r.copyLanded(c, copy), stopLatched: () => r.stopLatched(c) }
    },
  }
}
const factsOf = (v: JobView): Facts => ('reducer' in v ? factsOfReducer(v.reducer, v.corrupt) : factsOfState(v))

// One marker for job.state (the mutation runner allows one per id): the intent refusals and the event refusals.
function assertState(why: string | null): void {
  if (why !== null) refuse('job.state', why) // @guard:job.state
}

// The reason an intent is refused, or null when it is allowed.
export function intentRefusal(def: JobDef, state: JobView, chain: Chain, nowMs: number, kind: IntentKind, target?: { copy: number; part: number }): string | null {
  const f = factsOf(state)
  if (f.corrupt) return 'the journal is corrupt: every send is refused'
  const armed = f.armed
  if (armed === null) return 'the job is not armed'
  const cs = f.chain(chain)
  if (def.chains[chain] === undefined || cs === null) return `${chain} is not in this job`
  if (cs.phase === 'SKIPPED') return `${chain} was skipped at arm`
  if (!armed.schedule.order.includes(chain)) return `${chain} is not armed in this job`
  if (kind === 'clawback-intent') {
    if (!CLAW_PHASES.has(cs.phase)) return `a claw-back needs a settled chain (DRAINED, COPIES_DONE or STOPPED); ${chain} is ${cs.phase}`
    if (cs.inFlight()) return `a claw-back waits until nothing is in flight on ${chain}`
    return null
  }
  if (cs.stopLatched()) return `${chain} was stopped: no new intent until the operator resumes it (vt job resume)`   // PF-S fix round 5 (R34-1)
  if (!SEND_PHASES.has(cs.phase)) return `${chain} is ${cs.phase}: no new intent`
  if (!Number.isFinite(nowMs) || nowMs < startAt(armed, chain)) return `${chain} has not started yet (countdown or stagger)`
  if (target !== undefined && cs.landed(target.copy, target.part)) return `copy ${target.copy} part ${target.part} already landed: it is never sent again`
  return null
}

export function assertIntentAllowed(def: JobDef, state: JobView, chain: Chain, nowMs: number, kind: IntentKind, target?: { copy: number; part: number }): void {
  assertState(intentRefusal(def, state, chain, nowMs, kind, target))
}

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v)

// The reason an executor event is refused, or null when it may be appended. Intents: see intentRefusal.
export function eventRefusal(def: JobDef, state: JobView, event: { chain: unknown; type: unknown; data: unknown }): string | null {
  const f = factsOf(state)
  if (f.corrupt) return 'the journal is corrupt: nothing more is journaled by an executor'
  const type = typeof event?.type === 'string' ? event.type : ''
  const chain = event.chain
  const cs = chain === 'eth' || chain === 'sol' || chain === 'btc' ? f.chain(chain) : null
  if (cs === null || def.chains[chain as Chain] === undefined) return 'the event names no chain of this job'
  const d: Obj = isObj(event.data) ? event.data : {}
  const txId = typeof d.txId === 'string' ? d.txId : null
  const t = txId === null ? null : cs.tx(txId)
  const unknown = `${type}: ${txId === null ? 'no txId' : 'an unknown txId'} on ${String(chain)} — evidence must name a known attempt`
  // PF-S fix round 5 (R34-1): a stop-latched chain takes no phase event until the operator resumes it (STUCK overlay or not)
  if (PHASE_EVENTS.has(type) && cs.stopLatched()) return `${type} on a stopped chain: it stays stopped until the operator resumes it (vt job resume)`
  // PF-S fix round 6: judged on the base phase — the STUCK overlay never lets a settled chain be moved again
  if (PHASE_EVENTS.has(type)) {
    const ok = RUN_BASES.has(cs.base) || cs.base === 'STOPPED'                 // STOPPED here: not latched — the operator resumed it
    return ok ? null : `${type} on a ${cs.base}${cs.phase !== cs.base ? ` (${cs.phase})` : ''} chain: a settled, clawing-back or terminal chain is never revived`
  }
  switch (type) {
    case 'intent': case 'clawback-intent': case 'key-loaded': case 'funds': case 'note': return null
    case 'sent': return t?.kind === 'job' ? null : unknown
    case 'replaced': {
      const p = typeof d.prevId === 'string' ? cs.tx(d.prevId) : null
      return t?.kind === 'job' && p?.kind === 'job' && p.copy === t.copy && p.part === t.part ? null : `${unknown} (replaced: both txIds of one (copy, part))`
    }
    case 'included': return t?.kind === 'job' && t.copy === d.copy && t.part === d.part ? null : `${unknown} (included: its own copy and part)`
    case 'readback': return t?.kind === 'job' && t.landed ? null : `${unknown} (readback: an attempt that landed)`
    case 'reconcile':
      if (chain === 'btc' && (d.outcome === 'expired' || d.outcome === 'nonce-consumed')) return `reconcile ${String(d.outcome)} on btc: a btc attempt is never dead (it stays open until it is seen by txid)`
      return t !== null ? null : unknown
    case 'stuck': return t !== null && t.open ? null : `${unknown} (stuck: an open one)`
    case 'clawback-sent': case 'clawback-included': case 'clawback-failed': return t?.kind === 'claw' ? null : `${unknown} (a member of the claw-back)`
    case 'clawback-readback': return t?.kind === 'claw' && t.landed ? null : `${unknown} (clawback-readback: the member that landed)`
    case 'reassembled': return typeof d.copy === 'number' && cs.copyLanded(d.copy) ? null : 'reassembled: a copy with no landed part'
    default: return 'not an executor event'
  }
}

// E7 fix round 2 (the shared append gate: core's assertEventAllowed is what the API's gate() and the fake journal both run): a btc chain is
// never ended (`stopped`, `drained`, `copies-done`) while a copy's commit is journaled (open or landed) without its landed reveal: the commit
// locked funds only the reveal can spend and a settled chain is never revived. The run ends `failed` and a rerun or takeover reconciles by txid.
export function btcOpenRefusal(state: JobView, event: { chain: unknown; type: unknown }): string | null {
  if (event.chain !== 'btc' || typeof event.type !== 'string' || !ENDING_EVENTS.has(event.type)) return null
  const cs = factsOf(state).chain('btc')
  return cs !== null && cs.btcStranded() ? `${event.type} on a btc chain with a commit and no landed reveal: the chain stays open for the reveal` : null
}
export function assertEventAllowed(def: JobDef, state: JobView, event: { chain: unknown; type: unknown; data: unknown }): void {
  const open = btcOpenRefusal(state, event)
  if (open !== null) refuseBtcOpen(open)
  assertState(eventRefusal(def, state, event))
}

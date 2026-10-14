// api/src/job-state.ts — a job's reduced state for the API, advanced one journal line at a time (S2 review I-3).
//
// I2: the reduce semantics are core's alone. This adapter wraps core's incremental reducer (createReducer, lane E:
// absorbing terminal phases, the claw-back family, chain evidence wins, fail-closed folding) and adds only the indexes
// the API's send path asks for in O(open attempts), never by building the whole state:
//   · reducer           core's JobReducer: phase, tx facts, landed, spent, held, armed (core's assertIntentAllowed /
//                       assertEventAllowed take it as { reducer, corrupt }, O(1) per check);
//   · state()           core's JobState (O(n), memoized by core until the next line): GET /jobs/:id, receipts, the twin,
//                       an arm / close / resolve / claw-back confirm, never a job intent;
//   · openIntentIds / openAttempts   the attempts in flight (job attempts in (copy, part, intent) order, then the open
//                       claw-back members), exactly ChainState.openIntents, kept as a small index that is re-checked
//                       against the reducer's tx facts after every line naming a txId (a landing supersedes siblings, a
//                       claw-back landing closes every member, a reconcile adopted re-opens one: all name a txId);
//   · stopRequested     stop-requested / resume-requested, as core folds them;
//   · stopLatched       core's stop latch (PF-S fix round 5): a journaled `stopped` until the operator's resume-requested;
//   · claw(chain)       the claw-back family: its members, whether one is open, whether one landed.
// test/job-state.test.ts pins every accessor to core's reduce(def, prefix) after every line of every contract journal
// and of seeded random journals.
import type { ArmRecord, Chain, ChainPhase, BtcIntent, EthIntent, JobDef, JobState, JournalEvent, SolIntent } from '@vault-timelock/core/contracts'
import { createReducer } from '@vault-timelock/core/job'
import type { JobReducer } from '@vault-timelock/core/job'

type Obj = Record<string, unknown>
const CHAINS: readonly Chain[] = ['eth', 'sol', 'btc']
const FREES_KEY: ReadonlySet<ChainPhase> = new Set<ChainPhase>(['DONE', 'CLAWED_BACK', 'SKIPPED'])

// An attempt in flight (open), with what leases and the cap need: a job attempt, or an open claw-back member (copy 0,
// part 0).
export interface OpenAttempt {
  txId: string; gen: number; copy: number; part: number; attempt: number; claw: boolean; value: string | null; eth?: EthIntent; sol?: SolIntent; btc?: BtcIntent
}
// The claw-back family of a chain (core: one per chain): its members in intent order, whether one is open (in flight),
// and whether one landed (the family is final).
export interface ClawFamily { members: readonly string[]; open: boolean; landed: boolean }
export interface JobStateAdapter {
  readonly reducer: JobReducer
  apply(e: JournalEvent): void
  readonly count: number
  state(): JobState
  phase(chain: Chain): ChainPhase | undefined
  armed(): ArmRecord | null
  openIntentIds(chain: Chain): string[]
  openAttempts(chain: Chain): OpenAttempt[]
  isOpen(chain: Chain, txId: string): boolean
  spent(chain: Chain): bigint
  landed(chain: Chain, copy: number, part: number): boolean
  stopRequested(chain: Chain): boolean
  // final round (m-4): the API's own sticky FINAL facts of a chain, and whether its last stop's resumable code was untrusted
  finalFacts(chain: Chain): ReadonlySet<ApiFinalFact>
  untrustedStop(chain: Chain): boolean
  // PF-S fix round 5 (R34-1): the stop latch — a journaled `stopped` not yet cleared by an operator resume (core's reducer)
  stopLatched(chain: Chain): boolean
  // PF-S fix round 6: the phase under the STUCK overlay (SKIPPED for a skipped chain; core's reducer)
  basePhase(chain: Chain): ChainPhase | undefined
  claw(chain: Chain): ClawFamily | null
  // isChainTerminal(state.chains[chain]) without building the state: DONE, CLAWED_BACK or SKIPPED with nothing open.
  terminal(chain: Chain): boolean
}

const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v)
const isChain = (v: unknown): v is Chain => v === 'eth' || v === 'sol' || v === 'btc'
const int = (v: unknown): number | null => (typeof v === 'number' && Number.isSafeInteger(v) ? v : null)
const json = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T

interface Entry extends OpenAttempt { no: number }
// Final round (R79b review m-4): the FINAL facts the API keeps itself, STICKY — once journaled, never undone by a later line (an executor
// that journals a second `readback ok:true`, or a stop code of its own choosing, cannot make a FINAL stop resumable again):
//   readback     a readback {ok:false} of a job attempt: a mismatch, ETH status 0 (lane-e c2ee98f journals status 0 as readback not ok,
//                whatever the calldata) and a SOL transaction that landed with an error
//   reassembly   a `reassembled` {ok:false}
//   delegated    a `stopped` {delegated:true} (the lane key's EIP-7702 delegation)
// and, per stop (reset by each `stopped`): untrusted — an executor's `stopped` with the resumable code `operator-stop` while no stop
// request was held (the operator's Stop always journals stop-requested first: an executor-chosen "operator stop" is not taken on trust).
export type ApiFinalFact = 'readback' | 'reassembly' | 'delegated'
interface Acc { known: Map<string, Entry>; open: Map<string, Entry>; claws: string[]; stop: boolean; facts: Set<ApiFinalFact>; untrustedStop: boolean }

export function createJobState(def: JobDef): JobStateAdapter {
  const reducer = createReducer(def)
  const accs = new Map<Chain, Acc>()
  for (const c of CHAINS) if (def.chains[c] !== undefined) accs.set(c, { known: new Map(), open: new Map(), claws: [], stop: false, facts: new Set(), untrustedStop: false })
  let no = 0
  const isOpenTx = (c: Chain, txId: string): boolean => reducer.tx(c, txId)?.open === true

  const apply = (e: JournalEvent): void => {
    reducer.apply(e)
    const d: Obj = isObj(e.data) ? e.data : {}
    if (e.type === 'stop-requested' || e.type === 'resume-requested') {
      const c = d.chain === undefined ? e.chain : d.chain
      for (const [k, a] of accs) if (c === null || c === k) a.stop = e.type === 'stop-requested'
      return
    }
    if (!isChain(e.chain)) return
    const a = accs.get(e.chain)
    // final round (m-4): the sticky FINAL facts, and whether this stop's code can be taken on trust
    if (a !== undefined) {
      if (e.type === 'readback' && d.ok === false) a.facts.add('readback')   // ETH status 0 included (lane E: readback not ok)
      if (e.type === 'reassembled' && d.ok === false) a.facts.add('reassembly')
      if (e.type === 'stopped') {
        if (d.delegated === true) a.facts.add('delegated')
        a.untrustedStop = (e.by === 'browser' || e.by === 'cli') && d.code === 'operator-stop' && !a.stop
      }
    }
    const txId = typeof d.txId === 'string' ? d.txId : null
    if (a === undefined || txId === null) return
    const c = e.chain
    if ((e.type === 'intent' || e.type === 'clawback-intent') && !a.known.has(txId)) {
      const fact = reducer.tx(c, txId)
      const claw = e.type === 'clawback-intent'
      // only what the reducer took in: an intent it ignored (malformed, a duplicate, a claw-back after a landing) is no attempt
      if (fact !== null && (fact.kind === 'claw') === claw) {
        const x: Entry = {
          txId, gen: e.gen ?? 0, copy: claw ? 0 : int(d.copy) ?? 0, part: claw ? 0 : int(d.part) ?? 0, attempt: claw ? 1 : int(d.attempt) ?? 0, claw,
          value: claw && typeof d.value === 'string' ? d.value : null, no: ++no,
          ...(isObj(d.eth) ? { eth: json(d.eth) as unknown as EthIntent } : {}), ...(isObj(d.sol) ? { sol: json(d.sol) as unknown as SolIntent } : {}), ...(isObj(d.btc) ? { btc: json(d.btc) as unknown as BtcIntent } : {}),
        }
        a.known.set(txId, x)
        if (claw) a.claws.push(txId)
      }
    }
    // Re-check the open set against the reducer: the named attempt may have opened or re-opened, and a landing or a
    // claw-back settling closes others of its group / family.
    const named = a.known.get(txId)
    if (named !== undefined && isOpenTx(c, txId)) a.open.set(txId, named)
    for (const id of [...a.open.keys()]) if (!isOpenTx(c, id)) a.open.delete(id)
  }

  const sorted = (a: Acc): Entry[] => [...a.open.values()].sort((x, y) => Number(x.claw) - Number(y.claw) || x.copy - y.copy || x.part - y.part || x.no - y.no)
  return {
    reducer,
    apply,
    get count() { return reducer.length },
    state: () => reducer.state(),
    phase: (c) => (accs.has(c) ? reducer.phase(c) ?? undefined : undefined),
    armed: () => reducer.armed(),
    openIntentIds: (c) => { const a = accs.get(c); return a === undefined ? [] : sorted(a).map((x) => x.txId) },
    openAttempts(c) {
      const a = accs.get(c)
      if (a === undefined) return []
      return sorted(a).map(({ no: _no, ...x }) => ({ ...x, ...(x.eth ? { eth: json(x.eth) } : {}), ...(x.sol ? { sol: json(x.sol) } : {}), ...(x.btc ? { btc: json(x.btc) } : {}) }))
    },
    isOpen: (c, txId) => accs.get(c)?.open.has(txId) === true,
    spent: (c) => (accs.has(c) ? reducer.spent(c) : 0n),
    landed: (c, copy, part) => accs.has(c) && reducer.landed(c, copy, part),
    stopRequested: (c) => accs.get(c)?.stop === true,
    finalFacts: (c) => accs.get(c)?.facts ?? new Set(),
    untrustedStop: (c) => accs.get(c)?.untrustedStop === true,
    stopLatched: (c) => accs.has(c) && reducer.stopLatched(c),
    basePhase: (c) => (accs.has(c) ? reducer.basePhase(c) ?? undefined : undefined),
    claw(c) {
      const a = accs.get(c)
      if (a === undefined || a.claws.length === 0) return null
      return { members: [...a.claws], open: a.claws.some((id) => a.open.has(id)), landed: a.claws.some((id) => reducer.tx(c, id)?.landed === true) }
    },
    terminal(c) {
      const p = reducer.phase(c)
      return accs.has(c) && p !== null && FREES_KEY.has(p) && reducer.openIntents(c) === 0
    },
  }
}

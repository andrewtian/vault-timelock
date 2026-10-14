// api/src/jobs.ts — the job service (spec §3.2, §4, §5.2–5.3): job records, their journals, their state, and the
// job-domain checks of the send path. The registry replaces S1's in-memory stand-in.
//
// Storage under <stateDir> (= $VT_HOME/<network>):
//   lifecycle/job/<id>.json   broadcast store record (kind 'job'): { def: the canonical vt-job/1, createdAt }
//   messages/<sha256>.txt     the message text, once by digest (messages.ts)
//   jobs/<id>/journal.jsonl   the append-only journal (journal.ts); jobs/<id>/trace.txt its ASCII twin (trace-text.ts)
//
// Create (POST /jobs): normalizeJob(body, { network }) (job.*, message.* — a job of another network is job.network) →
// an inline message is stored by digest, a digest must name a stored message of exactly messageBytes bytes
// (message.missing) → id = jobId(def) → the same definition again is the existing job (200); a new one is stored, then
// its journal opens with `created { jobId, defSha256 }` (201). Creates are serialized.
//
// Lazy open (S1 review m7): constructing the registry touches nothing. A job is read from the store and its journal
// opened (a torn tail repaired) only on the first request that names it, i.e. after listen, so a second API instance
// that lost the lock race fails on EADDRINUSE before it can write any journal.
// Every load re-checks the stored record: a canonical vt-job/1 (normalizeJob gives it back unchanged), its id is
// jobId(def), and its network is this API's (job.network). A record that fails is never used (thrown: 500).
//
// THE GATE (security review of 7409aff): one function, gate(), that every journal append (the journal wrapper below,
// whoever writes: an executor's event, the API's commands, the leases, `created`) and every send ticket (ticket(), the
// only place a ticket is minted: the registry holds the ticket key) passes before the fsync / before minting. Routes
// cannot reach a raw journal or the ticket key. test/gate-coverage.test.ts walks the route table and checks the sources.
//   every append      validateEvent(type, data, by)
//   arm.amount        a clawbackConfirm (CC-2a) beside anything but a clawback-intent
//   chain events      event.shape     the data fits its chain and job (fitsChain): tx ids in the chain's format, an
//                                     intent's eth / sol member is the chain's, a claw-back's eth `to` is its destination,
//                                     key-loaded names the job's key; for a send the
//                                     declared fee members are sane (NEW-3): eth gas >= the intrinsic gas of its payload
//                                     (fork and recipient aware), maxFee >= 1 and >= tip; sol cuPrice <= the network cap
//                                     and fee >= 5,000 × signatures + ⌈cuLimit × cuPrice / 10⁶⌉; and (CC-3, I2) its ticket
//                                     v2 binding can be formed — ticketBinding(chain, type, data, the job DEFINITION's
//                                     keyAddress): a, k, p, to, value, f = worstCaseFee (the one fee formula, ledger.ts
//                                     too), q = the declared eth nonce / sol blockhash — BEFORE it is journaled, so no
//                                     intent is ever journaled that cannot get a ticket (an eth / sol JOB intent's binding is
//                                     its plan: checked after the job-domain checks, below). BTC (CC-8): every field is the
//                                     API's own, from the STORED message and the journaled commit (btcMintOf, tickets.ts
//                                     btcBinding); f is the intent's fee, under the cap
//                     job.state       the API's phase rules (assertApiPhaseRules, N-1): nothing sets the phase of a DONE,
//                                     CLAWED_BACK, CLAWING_BACK or SKIPPED chain; clawback-included / -failed only while
//                                     the claw-back family's outcome is pending; on a chain that is over nothing reopens,
//                                     gets stuck or is sent. Once ANY claw-back attempt of the chain has landed (ledger),
//                                     the chain counts as CLAWED_BACK for these rules (NEW-1): only that claw-back's own
//                                     clawback-included / -readback and evidence pass. A lease is never acquired on a
//                                     chain that is over. A close needs a settled chain with nothing in flight, by the
//                                     reducer and by the ledger (openInFlight: an attempt resolved mark-failed by the
//                                     operator no longer holds a close; it still counts for the cap — M5).
//                     event.attempt   evidence names a known attempt of its chain (assertEvidence)
//                     job.state       then core's assertEventAllowed (I2: the one phase / evidence gate of executor events,
//                                     lane E) on the incremental reducer, for every event an executor writes
//   intents and       trigger.uncleared, release.mainnet-locked, then the job-domain checks (assertSendable):
//   claw-back intents job.state (core assertIntentAllowed; copies limit; an operator Stop), job.copy-order (PF-S fix round 1,
//                     N-2: an intent's copy is the highest journaled copy of its chain, at a part up to one past that copy's
//                     highest, or the next copy at part 1 — in both modes, so no copy number is skipped or made up: an
//                     until-drained copy number is published in the copy marker), event.duplicate, job.clawback,
//                     event.family, arm.amount (see below); then, for an eth / sol JOB intent (PF-S I-1, pre-flip review):
//                     ticket.payload-plan  it is the part the API plans ITSELF from the STORED message with the lane's own
//                                     planner (planOf: planLaneCopy(laneConfigOf(chain, def.chains[chain], text), copy), cached
//                                     per (chain, copy)): payloadSha256 = sha256(planned[part − 1].payload), parts = the planned
//                                     count, 1 ≤ part ≤ parts. The copy marker is part of the plan, so another copy's part is
//                                     refused (copies mode: copy ≤ copies is job.state above; until drained: any copy, but only
//                                     with its own marker)
//                     ticket.recipient     an eth job intent's eth.to is the recipient the publish mode sends to (0x000…000 /
//                                     the lane key, eth recipientAddress); the ticket binds that address as `to` and the
//                                     relay compares the signed tx's `to` with it (tickets.ts, decode.ts)
//                     event.shape     its binding forms (ticketBinding with the plan: the same checks once more)
//   a ticket          ticket.not-intent (a journaled intent of the chain whose v2 binding forms: for eth / sol, the planned
//                     part and recipient, so a journaled intent that is not the plan never gets a ticket), ticket.terminal (open),
//                     job.state (not STUCK, not over, no claw-back landed), trigger.uncleared, release.mainnet-locked; it
//                     binds the journaled rawSha256 and the binding of the journaled data: after a Stop only those
//                     identical bytes are relayed again.
//
// Indexes, advanced by the same apply() on load and after each fsync (so a rebuilt registry equals the live one):
//   · jobState(id): the reduced state — core's createReducer behind job-state.ts (I2); the send path reads its O(1)
//     accessors and hands core's checks { reducer, corrupt }, so a check costs the same at 1k and 80k lines;
//   · the ledger (ledger.ts): attempts, families, charged and in flight;
//   · the journaled intent txIds and the reconciles per (chain, gen) (lease reconcile-first).
// If advancing an index ever throws, everything is rebuilt from the journal; if that throws too, the job is refused
// from then on (job.state, fail closed).
// trace.txt is written when the journal is opened, then at most once per traceDelayMs while appends come in, and at
// once when a chain is closed or stopped by the operator and on close() (shutdown): never on every append.
// A corrupt journal overlays phase CORRUPT and its reason (every send is refused).
//
// One active job per (chain, key) (job.key-busy, spec §4.2): another job's chain with the same key address is active
// when that job is armed (or has an open intent) and the chain is not terminal (DONE, CLAWED_BACK or SKIPPED with no
// open intents). A corrupt job counts as active. Unarmed jobs (no funds touched) never block a key.
//
// The send path's job-domain checks (assertSendable), in order:
//   intent.after-stop a job intent on a chain with a stop request (not resumed) or a journaled stop (STOPPED): nothing new
//                     is signed after a Stop — no replacement, bump, next part or copy (PF-S fix round 3; it replaces the m2
//                     allowance of a replacement in flight) — except the ONE btc reveal of a copy whose commit is journaled
//                     (landed or open). Claw-back intents are not refused here (their own rules below and in core)
//   job.state         core assertIntentAllowed (E1); copies mode: copy <= the copy count
//   event.duplicate   the txId is already journaled as an intent or claw-back intent of this job
//   job.clawback      a claw-back to the null / burn address or the lane's own key, or not to clawbackTo when set; on
//                     MAINNET only to the job's stored clawbackTo (PF-S fix round 1, N-6: a typed amount from the executor is
//                     no destination check; a stored mainnet job without clawbackTo gets no claw-back from vt)
//   job.clawback-precompile  a claw-back to an ETH address at or below 0xffff (precompiles and the reserved range)
//   event.family      eth: a nonce whose family already landed is refused; a nonce in flight belongs to one (copy, part)
//                     and a replacement names one of its attempts in flight in `replaces`; one (copy, part) never has two
//                     families in flight; a sol `replaces` names an attempt of its (copy, part); a btc (copy, part) never has two
//                     attempts open at once (no replacement exists for btc). One claw-back family per
//                     chain: while a claw-back is in flight (a failed one included) a new one keeps its eth nonce and
//                     destination (a sol claw-back waits) (N-2, N-3). PF-S fix round 4 (PF-E review I-2): an eth nonce whose
//                     pending members are all job attempts no longer open (resolved mark-failed, or claimed rejected) may take
//                     the FIRST claw-back (the engine's recovery: stuck → mark-failed → claw back at that nonce); no job attempt
//                     joins a family with a member resolved mark-failed.
//   arm.amount        the CONSERVATIVE total: max(ledger charged, the reducer's spent + the ledger's landed claw-back
//                     value) + the ledger's in flight, with this send joining its family (eth: the larger of the
//                     family's worst case and this one) <= the limit. (The reducer's spent is fees only; core's cap
//                     ledger also counts a landed claw-back's value, so the API adds it before comparing: I2's
//                     core-vs-API ledger test pins API total >= core total after every line.)
//                     The worst case is worstCaseFee (tickets.ts), the very `f` the ticket binds (+ value for a claw-back).
//                     BTC: ledger.ts worstFee: a commit reserves its fee + the value it locks (the ticket's f is the fee alone),
//                     a reveal 0; a landed commit charges at least fee + value.
//                     The limit is nativeCap. A claw-back (CC-2a, I2) first passes core's checkClawbackConfirm (no typed
//                     amount: value + fee <= nativeCap − spent − a landed claw-back's value; a typed amount: exactly value
//                     + fee); with the operator's typed amount (clawbackConfirm.amount, EXACTLY value + worst-case fee in
//                     base units, compared as integers here too) the limit of THAT intent only is nativeCap + that amount:
//                     everything else charged and in flight must still fit the armed cap, and the lane's cap never moves.
import { join } from 'node:path'
import { ethAmsterdam, ethDataGas, stopClassOf, stopCodeClass } from '@vault-timelock/core/contracts'
import type { Chain, ChainPhase, EthIntent, JobDef, JobState, JournalEvent, Network, OpenIntent, StopVerdict } from '@vault-timelock/core/contracts'
import * as constantsModule from '@vault-timelock/core/chains/constants.js'
import { ethReservedKind, solReservedKind } from '@vault-timelock/core/chains/reserved.js'
import { assertEventAllowed, assertIntentAllowed, canonicalJson, checkClawbackConfirm, jobId, normalizeJob, sha256Hex, validateEvent } from '@vault-timelock/core/job'
import type { IntentKind, JobView } from '@vault-timelock/core/job'
import { assertJobSendAllowed } from 'vt-broadcast/src/config.ts'
import { refuse } from 'vt-broadcast/src/guard.ts'
import { createStore } from 'vt-broadcast/src/lifecycle/store.ts'
import { assertTestMode } from './clock.ts'
import type { Clock } from './clock.ts'
import { createJobState } from './job-state.ts'
import type { ClawFamily, JobStateAdapter } from './job-state.ts'
import { openJournal } from './journal.ts'
import type { AppendOptions, Journal, JournalFs, JournalInput } from './journal.ts'
import { createLedger, worstFee } from './ledger.ts'
import { BTC_BODY_MAX } from '@vault-timelock/core/chains/btc-ord.ts'
import { recipientAddress } from '@vault-timelock/core/chains/eth.js'
import { ethGasBudget, ethGasFormula, solCuEstimate, solCuLimit, splitText } from '@vault-timelock/core/chains/plan.js'
import { planLaneCopy } from '@vault-timelock/core/engine/lane.js'
import { laneConfigOf } from '@vault-timelock/core/executor'
import type { ChainLedger, Ledger, LedgerAttempt } from './ledger.ts'
import { createLegacyLatch } from './legacy-latch.ts'
import type { LegacyLatch } from './legacy-latch.ts'
import { createMessages } from './messages.ts'
import { createLaneMint } from './privacycash-mint.ts'
import type { LaneMintOptions } from './privacycash-mint.ts'
import type { MessageStore } from './messages.ts'
import { createSources } from './sources.ts'
import type { SourceStore } from './sources.ts'
import { issueTicket, ticketBinding } from './tickets.ts'
import type { BtcMint, JobPlan } from './tickets.ts'
import type { TicketBinding } from './tickets.ts'
import { renderTrace, writeTrace } from './trace-text.ts'

export interface JobEntry {
  readonly id: string
  readonly def: JobDef
  readonly defSha256: string
  readonly createdAt: number
  readonly chains: readonly Chain[]
  readonly dir: string
  // The gated, indexing journal: every append passes gate() first.
  readonly journal: Journal
}
// A journaled intent or claw-back intent.
export interface IntentLine { chain: Chain; type: 'intent' | 'clawback-intent'; gen: number | null; data: Record<string, unknown> }
// A journaled intent a ticket may be minted for, with its v2 binding (CC-3).
type Ticketable = IntentLine & { binding: TicketBinding }
// PF-S I-1 / fix round 2: the API's plan of one copy: per part, the payload's sha256, its length and (SOL) the CU limit vt's model
// allows it (solCuLimit(solCuEstimate(payload)), the estimate path of chains/sol.js prepare; a simulated need is never above it).
interface Plan { readonly digests: readonly string[]; readonly sizes: readonly number[]; readonly cuMax: readonly number[] }
export interface Registry {
  readonly network: Network
  readonly messages: MessageStore
  readonly sources: SourceStore
  readonly latch: LegacyLatch
  create(input: unknown): Promise<{ created: boolean; job: JobEntry }>
  // Reads (once) and returns the job; job.missing for an unknown id, or a chain the job does not have.
  load(id: string, chain?: Chain | null): Promise<JobEntry>
  // A job already loaded (the lease queue's synchronous view); job.missing otherwise.
  get(id: string, chain?: Chain | null): JobEntry
  journalOf(id: string): Journal
  // Every stored job, oldest first.
  list(): Promise<JobEntry[]>
  // The I2 swap point: the job's reduced state, advanced per journal line.
  jobState(id: string): JobStateAdapter
  // The ledger of one chain of a loaded job (read-only use: tests, the twin).
  ledgerOf(job: JobEntry, chain: Chain): ChainLedger
  // Final round (R79b review m-4 / m-5): the class of a STOPPED chain's stop as the API decides it (null: its base is not STOPPED)
  stopVerdict(job: JobEntry, chain: Chain): StopVerdict | null
  // The full JobState (with the CORRUPT overlay), memoized per line.
  state(job: JobEntry): JobState
  intentOf(job: JobEntry, txId: string): IntentLine | undefined
  // LeaseGrant.openIntents and the reconciles per (chain, gen): what leases.ts asks.
  openIntents(id: string, chain: Chain): OpenIntent[]
  reconciled(id: string, chain: Chain, gen: number): ReadonlySet<string>
  assertKeyFree(job: JobEntry, chain: Chain): Promise<void>
  // A send ticket for a journaled open intent of the chain, under gen: through gate(), then minted.
  ticket(job: JobEntry, chain: Chain, gen: number, txId: string): Promise<string>
  // The job-send lock (C2's assertJobSendAllowed(network)): the gate's send and ticket paths and the arm (arm.ts) call it.
  assertJobSendsAllowed(): void
  // Sfix-PC: the Privacy Cash withdrawal authorization (x-vt-pc-lane v2) for the job's SOL lane, after RESERVING `amount`
  // lamports against the lane cap in the API's own ledger (privacycash-mint.ts). Through the shared gate() first (job phase of the
  // SOL chain, latch, broken journal); then synchronous: check, reserve, fsync, sign.
  mintPrivacyCash(job: JobEntry, req: { tryIndex: number; bodySha256: string; amount: bigint }): Promise<string>
  // How many times gate() ran (tests: the route table's coverage).
  gates(): number
  // trace.txt now, for one job / every job with a write pending; close() flushes and stops the timers (shutdown).
  flushTrace(job: JobEntry): void
  flushTraces(): void
  close(): void
}

const { SOL, ECON, CANON } = constantsModule as { SOL: { CU_PRICE_CAP: number }; ECON: { SOL_RUNG_CAP: number }
  CANON: { ETH_CLAW_GAS_EXISTING: bigint; ETH_CLAW_GAS_EMPTY_AMSTERDAM: bigint } }
const CHAINS: readonly Chain[] = ['eth', 'sol', 'btc']
// PF-S fix round 3 (R2-1): a SOL claw-back as the engine sizes it (chains/sol.js transferFee, engine/lane.js): unpriced it journals the
// default limit (no ComputeBudget instruction is in the tx); priced, solCuLimit(simulated units || 1,000) — the transfer simulates at
// about 450 units, so the unsimulated fallback is the ceiling.
const SOL_CLAW_DEFAULT_LIMIT = 200_000
const SOL_CLAW_CU_MAX = solCuLimit(1_000)
const HEX16 = /^[0-9a-f]{16}$/
const DEC = /^(?:0|[1-9][0-9]*)$/
const DATA_PREFIX_BYTES = 6 // `data:,` before the text of every eth calldata payload (contracts/parts.ts)
const SOL_FEE_PER_SIGNATURE = 5000n
const SOL_SIGNATURES = 1n // a memo tx and a claw-back transfer are signed by the lane key alone
const PLAN_CACHE = 64     // PF-S I-1: planned copies kept per job (the oldest is dropped first; a miss re-plans, it never refuses)
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
const TX_ID: Readonly<Record<Chain, RegExp>> = { eth: /^0x[0-9a-f]{64}$/, sol: /^[1-9A-HJ-NP-Za-km-z]{64,88}$/, btc: /^[0-9a-f]{64}$/ }
const ADDRESS: Readonly<Record<Chain, RegExp>> = { eth: /^0x[0-9a-fA-F]{40}$/, sol: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/, btc: /^(?:bcrt|tb|bc)1[02-9ac-hj-np-z]{11,87}$/ }
// Addresses nobody controls: core's one source (chains/reserved.js); an ETH string that is not 0x + 40 hex has no kind here.
const reservedKind = (chain: Chain, to: string): string | null =>
  chain === 'eth' ? (ADDRESS.eth.test(to) ? ethReservedKind(to) : null) : solReservedKind(to)
// Executor events that set a chain's phase outright, and the phases nothing may move a chain out of (review I-1).
const MOVES: ReadonlySet<string> = new Set(['paused', 'resumed', 'drained', 'copies-done', 'stopped'])
const FINISHED: ReadonlySet<ChainPhase> = new Set<ChainPhase>(['DONE', 'CLAWED_BACK', 'CLAWING_BACK', 'SKIPPED'])
// A chain that is over: nothing reopens there, nothing is sent (re-review N-1, N-5).
export const OVER: ReadonlySet<ChainPhase> = new Set<ChainPhase>(['DONE', 'CLAWED_BACK', 'SKIPPED'])
const SETTLED: ReadonlySet<ChainPhase> = new Set<ChainPhase>(['DRAINED', 'COPIES_DONE', 'STOPPED'])
export const sameAddress = (c: Chain, a: string, b: string): boolean => (c === 'eth' ? a.toLowerCase() === b.toLowerCase() : a === b)
// PF-S fix round 1 (N-6): the destination rule of a claw-back beside the reserved / own-key ones: the job's clawbackTo when set; on
// mainnet ONLY the stored clawbackTo (new mainnet jobs must name one: normalizeJob job.clawback-required); off mainnet, with none set, any.
export const clawbackToAllowed = (network: Network, chain: Chain, clawbackTo: string | null, to: string): boolean =>
  clawbackTo !== null ? sameAddress(chain, to, clawbackTo) : network !== 'mainnet'
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)
const bigMax = (a: bigint, b: bigint): bigint => (a > b ? a : b)

function assertFound(ok: boolean): asserts ok {
  if (!ok) refuse('job.missing', 'no such job, or the job has no such chain') // @guard:job.missing
}

function assertJobNetwork(ok: boolean): void {
  if (!ok) refuse('job.network', 'this job belongs to another network: a job never runs on another network') // @guard:job.network
}

// The one job.state refusal of the API.
export function assertJobState(ok: boolean, why: string): void {
  if (!ok) refuse('job.state', why) // @guard:job.state
}

// The one arm.amount refusal of the API: the armed cap and the typed amount bound to it.
export function assertWithinCap(ok: boolean, why: string): void {
  if (!ok) refuse('arm.amount', why) // @guard:arm.amount
}

// The one event.shape refusal of the API (the body's { gen, type, data } in routes.ts; fitsChain here).
export function assertEventShape(ok: boolean): asserts ok {
  if (!ok) refuse('event.shape', 'the event is not { gen, type, data } with the fields its type needs, in the formats of its chain and job, with sane fee members') // @guard:event.shape
}

// The API's own phase rules (S2 review I-1, re-review N-1; kept at I2 in ADDITION to core's assertEventAllowed, which is
// the phase gate of executor events): a finished chain is never revived, so it never gets another send ticket and never
// occupies a key it has freed. `phase` is the chain's phase as the gate sees it (CLAWED_BACK once the ledger saw any
// claw-back attempt land, NEW-1); `claw` is the claw-back family (core: one per chain). Pure evidence (note, readback,
// reassembled, included, reconcile other than adopted, …) stays allowed here, and so is the landed claw-back's own outcome
// (`own`: clawback-included / -readback of a member of the family that landed, which the executor journals after its
// reconcile included, E1 ruling 5 — core's reducer has already settled the family, so it changes no phase).
export function assertApiPhaseRules(f: { corrupt: boolean; phase: ChainPhase; claw: ClawFamily | null; own: boolean; latched?: boolean; base?: ChainPhase; stopRequested?: boolean; finalStop?: () => boolean }, event: { chain: Chain | null; type: string; data: Record<string, unknown> }): void {
  if (event.chain === null) return
  const t = event.type, d = event.data, claw = f.claw
  const clawInFlight = claw !== null && claw.open
  // The family's outcome is pending: no member landed, and one is in flight (or the chain is CLAWING_BACK). Core (CC-2a,
  // D-2): a family whose members are all dead has failed by itself and is back in its settled phase, so its outcome is
  // no longer pending: a later clawback-included / -failed is refused here (the executor journals clawback-failed only
  // for a member that failed ON CHAIN, before its reconcile nonce-consumed, E3).
  const clawPending = claw !== null && !claw.landed && (clawInFlight || f.phase === 'CLAWING_BACK')
  const adopted = t === 'reconcile' && d.outcome === 'adopted'
  let why: string | null = null
  if (MOVES.has(t) && (f.corrupt || FINISHED.has(f.phase) || clawInFlight)) why = 'a finished chain is never moved again'
  // PF-S fix round 5 (R34-1): a stop-latched chain (a journaled `stopped`) is moved again only after the operator's resume
  else if (MOVES.has(t) && f.latched === true) why = 'a stopped chain stays stopped until the operator resumes it (vt job resume)'
  // PF-S fix round 6: a settled base (DRAINED, COPIES_DONE), STUCK overlay or not, is never moved by an executor
  else if (MOVES.has(t) && (f.base === 'DRAINED' || f.base === 'COPIES_DONE')) why = 'a drained or copies-done chain is never moved again by an executor'
  // R79b (review M-4): a STOPPED chain the operator resumed (unlatched) is not reopened while a NEW stop request is pending — the
  // executor's `resumed` (or any phase event but `stopped`) waits for the operator's next resume
  else if ((MOVES.has(t) || t === 'copy-built') && t !== 'stopped' && f.base === 'STOPPED' && f.stopRequested === true) why = 'a stop request is pending: the stopped chain is not reopened until the operator resumes it again (vt job resume)'
  // Final round (R79b review m-5): a STOPPED chain whose stop is FINAL is never reopened, latched or not (a journal from before R79b with
  // a resume in it, or a FINAL fact that appeared after the resume) — not only the executor's own guard refuses it
  else if ((MOVES.has(t) || t === 'copy-built') && t !== 'stopped' && f.base === 'STOPPED' && f.finalStop?.() === true) why = 'its stop is FINAL: it is never reopened — claw back what is left or close the chain, then make a new job'
  // m-a (M5d review): the `stopped` exemption is no downgrade path — on a STOPPED chain whose stop is FINAL, a `stopped` with a
  // resumable code is refused; a FINAL-coded one (m-3's evidence and stop) or one with no code (FINAL itself) is still taken
  else if (t === 'stopped' && f.base === 'STOPPED' && stopCodeClass(d.code) !== 'final' && f.finalStop?.() === true) why = 'its stop is FINAL: a later stop with a resumable code never lowers it — claw back what is left or close the chain, then make a new job'
  else if ((t === 'clawback-included' || t === 'clawback-failed') && !(t === 'clawback-included' && f.own) && (!clawPending || OVER.has(f.phase))) why = 'no claw-back outcome is pending on it'
  else if (OVER.has(f.phase) && (t === 'sent' || t === 'stuck' || t === 'intent' || t === 'clawback-intent' || t === 'clawback-sent' || t === 'resolved' || adopted)) why = 'nothing reopens or is sent on a chain that is over'
  else if (clawInFlight && !(typeof d.txId === 'string' && claw.members.includes(d.txId)) && (t === 'sent' || adopted)) why = 'no job attempt reopens while a claw-back is in flight'
  assertJobState(why === null, `${event.chain} is ${f.phase}${clawInFlight ? ' with a claw-back in flight' : ''}: ${why ?? ''}`)
}

// The job key's address on a chain: the job DEFINITION's keyAddress (never a journaled key-loaded). Required: a chain of
// the job always has one (the vt-job/1 validator); anything else is a broken record and throws (fail closed).
export function keyAddressOf(job: JobEntry, chain: Chain): string {
  const a = job.def.chains[chain]?.keyAddress
  if (typeof a !== 'string' || a === '') throw new Error(`job ${job.id}: no ${chain} key address in the definition`)
  return a
}
// The least gas an eth tx of n calldata bytes can use (contracts/gas.ts). Local may run an Amsterdam anvil (an override
// the API cannot see): the smaller of the two forks there; testnet and mainnet follow their fork flag.
function ethGasFloor(network: Network, n: number, toSelf: boolean): bigint {
  const fork = (amsterdam: boolean): number => ethDataGas(n, { amsterdam, toSelf })
  return BigInt(network === 'local' ? Math.min(fork(false), fork(true)) : fork(ethAmsterdam(network)))
}

// True when an event's data (through validateEvent) fits its chain and job; for a send, its fee members are sane.
function fitsChain(job: JobEntry, network: Network, chain: Chain, type: string, d: Record<string, unknown>): boolean {
  for (const k of ['txId', 'prevId', 'replaces']) {
    const v = d[k]
    if (typeof v === 'string' && !TX_ID[chain].test(v)) return false
  }
  if (type === 'key-loaded' && !(typeof d.address === 'string' && sameAddress(chain, d.address, job.def.chains[chain]!.keyAddress))) return false
  if (type !== 'intent' && type !== 'clawback-intent') return true
  if (chain === 'btc') {
    // CC-8: a btc copy is two lane txs, part 1 = the commit and part 2 = the reveal (E7); a btc intent never replaces another, and
    // its members are re-derived by ticketBinding (the body from the stored message, the key from the pubkey, the commit from the journal)
    const b = d.btc
    return type === 'intent' && isObj(b) && d.eth === undefined && d.sol === undefined && d.parts === 2 && d.part === (b.kind === 'commit' ? 1 : b.kind === 'reveal' ? 2 : 0) && d.replaces === null
  }
  const own = chain === 'eth' ? d.eth : d.sol
  const other = chain === 'eth' ? d.sol : d.eth
  if (!isObj(own) || other !== undefined) return false
  const claw = type === 'clawback-intent'
  if (claw && !(typeof d.to === 'string' && ADDRESS[chain].test(d.to))) return false
  if (chain === 'eth') {
    const pm = job.def.chains.eth!.publishMode
    // a claw-back's eth.to is its destination; a job intent's recipient is ticket.recipient's (PF-S I-1), checked after this
    if (typeof own.to !== 'string' || !ADDRESS.eth.test(own.to) || (claw && !sameAddress('eth', own.to, d.to as string))) return false
    const gas = BigInt(own.gas as string), maxFee = BigInt(own.maxFee as string), tip = BigInt(own.tip as string)
    // A one-part payload is at least `data:,` + the whole message; any part is at least one byte.
    const n = claw ? 0 : d.parts === 1 ? job.def.messageBytes + DATA_PREFIX_BYTES : 1
    return gas >= ethGasFloor(network, n, !claw && pm === 'eth.calldata.self') && maxFee >= 1n && maxFee >= tip
  }
  const cuPrice = own.cuPrice as number, cuLimit = own.cuLimit as number
  const priority = (BigInt(cuLimit) * BigInt(cuPrice) + 999_999n) / 1_000_000n
  return cuPrice <= SOL.CU_PRICE_CAP && BigInt(own.fee as string) >= SOL_FEE_PER_SIGNATURE * SOL_SIGNATURES + priority
}

export function createRegistry(o: {
  stateDir: string; network: Network; clock: Clock; out: string; ticketKey: Uint8Array; fs?: JournalFs; traceDelayMs?: number
  // Sfix-PC: the Privacy Cash lane mint. Absent: no lane cap, so every mint refuses (api.pc-ledger).
  privacyCash?: Pick<LaneMintOptions, 'capLamports' | 'nonce' | 'io'>
  // PF-S fix round 2 (R1-2), a TEST SEAM (NODE_ENV=test only, api.test-only): the job-send lock as a later build has it (the M2 flip),
  // so the mainnet branches behind it (the N-6 claw-back destination) are reachable in tests while this build keeps mainnet locked.
  // Production (main.ts) never passes it: the lock is C2's assertJobSendAllowed.
  jobSendLock?: (network: Network) => void
}): Registry {
  const { stateDir, network, clock } = o
  if (o.jobSendLock !== undefined) assertTestMode()
  const jobSendLock = o.jobSendLock ?? ((n: Network): void => { assertJobSendAllowed(n) })
  const traceDelayMs = o.traceDelayMs ?? 3000
  const store = createStore(stateDir, { clock: { now: () => Math.floor(clock.now() / 1000) }, log: () => {} })
  const messages = createMessages(stateDir)
  const sources = createSources(stateDir, { now: () => clock.now() })
  const latch = createLegacyLatch(o.out)
  // The lane mint touches nothing until its first use (lazy, like the journals).
  const laneMint = createLaneMint({ stateDir, network, key: o.ticketKey, capLamports: o.privacyCash?.capLamports ?? 0n, now: () => clock.now(),
    ...(o.privacyCash?.nonce !== undefined ? { nonce: o.privacyCash.nonce } : {}),
    ...(o.privacyCash?.io !== undefined ? { io: o.privacyCash.io } : {}) })
  interface Loaded {
    entry: JobEntry; raw: Journal; js: JobStateAdapter; ledger: Ledger
    intents: Map<string, IntentLine>; reconciled: Map<string, Set<string>>; broken: boolean
    plans: Map<string, Plan>                  // PF-S I-1: `${chain}/${copy}` → the planned parts (planOf)
    solResumeCap: number                      // PF-S fix round 2 (R1-1): the highest cuPriceCap a journaled sol / all-chain resume set (0: none)
    finalStops: Map<Chain, StopVerdict>       // m-a: a FINAL verdict, held for the chain's whole STOPPED stretch (never lowered by a later line)
    text: string | null                       // PF-S I-1: the stored message, read (and digest-checked) once, on the first plan
  }
  const jobs = new Map<string, Loaded>()

  // CC-8 (S6b fix round 2, C-1): the API's own context for a btc ticket — the body of this copy's one inscription, sliced from the
  // STORED message exactly as the lane plans it (the part planner, cap BTC_BODY_MAX, the copy marker when copies are distinct), and,
  // for a reveal, the txid of the commit LANDED in the ledger for the same copy (the journal's, never the request's).
  const btcMintOf = (l: Loaded, d: Record<string, unknown>): BtcMint => {
    const def = l.entry.def, c = def.chains.btc
    let body: Uint8Array | null = null
    let commitTxId: string | null = null
    try {
      const copy = d.copy
      if (c !== undefined && typeof copy === 'number' && Number.isSafeInteger(copy) && copy >= 1) {
        const text = new Uint8Array(messages.read(def.messageSha256))
        const planned = splitText(text, { cap: BTC_BODY_MAX, sha256: def.messageSha256, copy: c.distinctCopies ? copy : null, copies: c.distinctCopies && c.mode !== 'drain' ? c.mode.copies : null })
        if (planned.length === 1) body = planned[0].payload
        if (d.part === 2) {
          // the commit that LANDED wins; only when none did, and only during a Stop, the (single) open one (fix round 2 review m-1)
          let open: string | null = null
          for (const a of l.ledger.chain('btc').byTx.values()) {
            const b = l.intents.get(a.txId)?.data.btc
            if (a.copy !== copy || a.part !== 1 || a.claw || !isObj(b) || b.kind !== 'commit') continue
            if (a.status === 'landed') { commitTxId = a.txId; break }
            if (a.status === 'pending' && !a.abandoned && l.js.stopRequested('btc') && open === null) open = a.txId
          }
          commitTxId ??= open
        }
      }
    } catch { body = null; commitTxId = null }
    return { network, body, commitTxId }
  }
  // PF-S I-1 (pre-flip review): the API's OWN plan of copy `copy` of an eth / sol chain — the lane's planner over the STORED message,
  // exactly as the executor plans it (planLaneCopy(laneConfigOf(chain, def.chains[chain], text), copy): the same functions, the job's
  // distinctCopies / copies / layoutMaxMemo, the copy marker included) — as the sha256 of each planned part. Cached per (chain, copy),
  // the oldest of PLAN_CACHE dropped first. null when it cannot be planned (fail closed: the intent is refused).
  const planOf = (l: Loaded, chain: 'eth' | 'sol', copy: unknown): Plan | null => {
    if (typeof copy !== 'number' || !Number.isSafeInteger(copy) || copy < 1) return null
    const key = `${chain}/${copy}`
    const hit = l.plans.get(key)
    if (hit !== undefined) return hit
    let plan: Plan | null = null
    try {
      const def = l.entry.def, ch = def.chains[chain]
      if (ch !== undefined) {
        l.text ??= UTF8.decode(new Uint8Array(messages.read(def.messageSha256)))
        const planned = planLaneCopy(laneConfigOf(chain, ch, l.text), copy) as Array<{ payload: Uint8Array }>
        plan = planned.length < 1 ? null : {
          digests: planned.map((x) => sha256Hex(x.payload)), sizes: planned.map((x) => x.payload.length),
          cuMax: planned.map((x) => solCuLimit(solCuEstimate(x.payload))),
        }
      }
    } catch { plan = null }
    if (plan === null) return null
    if (l.plans.size >= PLAN_CACHE) l.plans.delete(l.plans.keys().next().value as string)
    l.plans.set(key, plan)
    return plan
  }
  // The recipient of the job's eth txs (the lane's own rule, eth recipientAddress: eth.calldata.self → the lane key, else 0x000…000).
  const recipientOf = (job: JobEntry): string => recipientAddress(job.def.chains.eth?.publishMode === 'eth.calldata.self' ? 'self' : 'null', keyAddressOf(job, 'eth'))
  const jobPlanOf = (l: Loaded, chain: 'eth' | 'sol', data: Record<string, unknown>): JobPlan | undefined => {
    const plan = planOf(l, chain, data.copy)
    return plan === null ? undefined : { digests: plan.digests, to: chain === 'eth' ? recipientOf(l.entry) : null }
  }
  // Final round (R79b review m-4): the API does not take the executor-chosen stop code on trust. The class of a STOPPED chain's stop is
  // core's stopClassOf (its code, and the FINAL facts of the reduced journal: readback not ok, a failed reassembly, a delegated key, a
  // stuck or mark-failed attempt), made stricter by the API's own STICKY facts (job-state finalFacts: a readback or reassembly that ever
  // failed, a delegated key ever reported — a later line never undoes them) and by an executor's `operator-stop` journaled while no stop
  // request was held (the operator's Stop always journals stop-requested first). A missing or unknown code stays FINAL. null: the
  // chain's base is not STOPPED (a resume then only clears a request).
  // m-a (M5d review): once the verdict on a STOPPED chain is FINAL it stays FINAL for the whole stopped stretch — a later `stopped`
  // with a resumable code (core's reducer replaces stopCode), a cleared stuck flag or anything else never lowers it (l.finalStops, kept
  // by index(); the stretch ends only when the base leaves STOPPED and CLAWING_BACK: a reopen, close or a landed claw-back).
  const stopVerdictOf = (l: Loaded, chain: Chain): StopVerdict | null => {
    const held = l.finalStops.get(chain)
    if (held !== undefined && l.js.basePhase(chain) === 'STOPPED') return held
    return currentVerdictOf(l, chain)
  }
  const currentVerdictOf = (l: Loaded, chain: Chain): StopVerdict | null => {
    const cs = l.js.state().chains[chain]
    if (cs === undefined || cs.stopClass === undefined) return null
    const v = stopClassOf(cs)
    if (v.cls === 'final') return v
    const facts = l.js.finalFacts(chain)
    const fact = facts.has('readback') ? 'a landed part did not read back from the chain, or failed on it (a readback failed: a mismatch, ETH status 0; a later report does not undo it)'
        : facts.has('reassembly') ? 'a copy did not reassemble from the chain (a later report does not undo it)'
          : facts.has('delegated') ? 'the lane key\'s account has an EIP-7702 delegation'
            : l.js.untrustedStop(chain) ? 'its stop says operator-stop, but no stop request was held when the executor journaled it (not taken on trust)'
              : null
    return fact === null ? v : { cls: 'final', code: v.code, why: fact }
  }
  // PF-S fix round 2 (R1-1): the SOL CU price cap of the lane: the job's maxCuPrice, raised by a journaled resume's cap. Without a
  // maxCuPrice, the engine's lane default (PF-S fix round 3, R2-1): lane.js LANE_DEFAULTS.cuPriceCap = ECON.SOL_RUNG_CAP, 2,000,000
  // (validateLaneConfig refuses more, as the job validator does for maxCuPrice and the event validator for a resume's cuPriceCap).
  const solLaneCap = (l: Loaded): number => Math.max(l.entry.def.chains.sol?.maxCuPrice ?? ECON.SOL_RUNG_CAP, l.solResumeCap)
  // PF-S fix round 2 (R1-1): the declared fee members are within the plan (the ticket binds them as x and the relay compares them with
  // the signed bytes): an ETH job intent's gas lies in [the gas formula, + the estimate tolerance] of its planned payload (chains/plan.js:
  // what the engine signs, gas = max(formula, an estimate inside that window); local: either fork); a SOL job intent's CU limit is at most
  // the model's limit for its planned payload and its CU price at most the lane's cap; a SOL claw-back is sized as the engine sizes it
  // (chains/sol.js transferFee; PF-S fix round 3, R2-1): unpriced, no ComputeBudget instruction and the journaled default limit 200,000;
  // priced, a price up to ECON.SOL_RUNG_CAP and a limit up to solCuLimit(1,000) (the engine's limit for the transfer's simulated units,
  // about 450, or 1,000 when the simulation reports none); an ETH claw-back's gas is the builder's own for its destination class (economy.js ethClawGas: an
  // existing account, or an empty one under Amsterdam — the API cannot see which, so either where Amsterdam may run).
  const assertFeePlan = (l: Loaded, chain: Chain, type: string, d: Record<string, unknown>): void => {
    let ok = true
    if (chain === 'eth' && type === 'intent') {
      const plan = planOf(l, 'eth', d.copy), n = plan?.sizes[(d.part as number) - 1]
      const gas = BigInt((d.eth as { gas: string }).gas), toSelf = l.entry.def.chains.eth?.publishMode === 'eth.calldata.self'
      const forks = network === 'local' ? [false, true] : [ethAmsterdam(network)]
      ok = n !== undefined && forks.some((amsterdam) => gas >= ethGasFormula(n, { amsterdam, toSelf }) && gas <= ethGasBudget(n, { amsterdam, toSelf }))
    } else if (chain === 'eth') {
      const gas = BigInt((d.eth as { gas: string }).gas), amsterdam = network === 'local' || ethAmsterdam(network)
      ok = gas === CANON.ETH_CLAW_GAS_EXISTING || (amsterdam && gas === CANON.ETH_CLAW_GAS_EMPTY_AMSTERDAM)
    } else if (chain === 'sol') {
      const sol = d.sol as { cuLimit: number; cuPrice: number }
      if (type === 'intent') {
        const max = planOf(l, 'sol', d.copy)?.cuMax[(d.part as number) - 1]
        ok = max !== undefined && sol.cuLimit <= max && sol.cuPrice <= solLaneCap(l)
      } else ok = sol.cuPrice === 0 ? sol.cuLimit === SOL_CLAW_DEFAULT_LIMIT : sol.cuPrice <= ECON.SOL_RUNG_CAP && sol.cuLimit <= SOL_CLAW_CU_MAX
    }
    if (!ok) refuse('ticket.fee-plan', "the intent's declared fee members are outside what vt plans for it (ETH gas: the formula of its planned payload up to the estimate tolerance, a claw-back's the transfer gas; SOL: a CU limit up to the model's for its payload, a CU price up to the lane's cap; a claw-back sized as the engine sizes a transfer)") // @guard:ticket.fee-plan
  }
  // CC-3 ticket v2: a, k, p, to, value, f and q of a send intent of this job; null when it cannot be formed.
  const bindingOf = (l: Loaded, chain: Chain, type: string, data: Record<string, unknown>): TicketBinding | null =>
    ticketBinding(chain, type, data, keyAddressOf(l.entry, chain), chain === 'btc' ? btcMintOf(l, data) : type === 'intent' ? jobPlanOf(l, chain, data) : undefined)
  // PF-S I-1: an eth / sol job intent is the planned part (ticket.payload-plan) and an eth one goes to the planned recipient
  // (ticket.recipient). The binding (bindingOf) re-checks both, so a ticket is never minted for an intent that is not the plan.
  const assertPlanned = (l: Loaded, chain: 'eth' | 'sol', d: Record<string, unknown>): void => {
    const plan = jobPlanOf(l, chain, d)
    const part = d.part
    const planned = plan !== undefined && d.parts === plan.digests.length && Number.isSafeInteger(part) && (part as number) >= 1
      && (part as number) <= plan.digests.length && d.payloadSha256 === plan.digests[(part as number) - 1]
    if (!planned) refuse('ticket.payload-plan', "the intent is not the part the API plans from the job's stored message for this copy: payloadSha256, parts and part must be the planned ones (the copy marker included)") // @guard:ticket.payload-plan
    if (chain !== 'eth') return
    const to = isObj(d.eth) ? d.eth.to : undefined
    const recipientOk = typeof to === 'string' && sameAddress('eth', to, recipientOf(l.entry))
    if (!recipientOk) refuse('ticket.recipient', "the intent's eth.to is not the recipient the job's publish mode sends to (eth.calldata.null: 0x000…000; eth.calldata.self: the lane key)") // @guard:ticket.recipient
  }
  const loading = new Map<string, Promise<Loaded>>()
  const traceTimers = new Map<string, ReturnType<typeof setTimeout>>()
  let creates: Promise<unknown> = Promise.resolve()
  let closed = false
  let gateRuns = 0

  const loadedOf = (job: JobEntry): Loaded => {
    const l = jobs.get(job.id)
    assertFound(l !== undefined && l.entry === job)
    return l!
  }
  const overlay = (l: Loaded, s0: JobState): JobState => {
    const s = projectStopClass(l, s0)
    const corrupt = l.raw.corrupt()
    return corrupt === null ? s : { ...s, phase: 'CORRUPT', corrupt }
  }
  // Projection fix (M5d report issue 1): the state the API serves (GET /jobs, GET /jobs/:id, the trace, every reader of
  // Registry.state) shows the API's own stop verdict — the class the resume route decides with (stopVerdictOf: core's class made
  // stricter by the sticky FINAL facts and an untrusted operator-stop) — never core's looser one. stopCode stays as journaled. Core's
  // memoized state is shared: copied, never mutated, and only when a chain's class changes.
  const projectStopClass = (l: Loaded, s: JobState): JobState => {
    let chains: JobState['chains'] | null = null
    for (const [c, cs] of Object.entries(s.chains) as Array<[Chain, NonNullable<JobState['chains'][Chain]>]>) {
      if (cs.stopClass !== 'resumable') continue
      const v = stopVerdictOf(l, c)
      if (v === null || v.cls === cs.stopClass) continue
      chains ??= { ...s.chains }
      chains[c] = { ...cs, stopClass: v.cls }
    }
    return chains === null ? s : { ...s, chains }
  }
  // What core's checks read: the incremental reducer with the journal's corrupt overlay (O(1) facts).
  const jobView = (l: Loaded): JobView => ({ reducer: l.js.reducer, corrupt: l.raw.corrupt() })

  // One journal line into the indexes.
  const index = (l: Loaded, e: JournalEvent): void => {
    l.js.apply(e)
    l.ledger.apply(e)
    if (e.type === 'resume-requested' && (e.chain === 'sol' || e.chain === null) && Number.isSafeInteger(e.data.cuPriceCap)) l.solResumeCap = Math.max(l.solResumeCap, e.data.cuPriceCap as number)
    const txId = e.data.txId
    if ((e.type === 'intent' || e.type === 'clawback-intent') && typeof txId === 'string' && (e.chain === 'eth' || e.chain === 'sol' || e.chain === 'btc') && !l.intents.has(txId)) {
      l.intents.set(txId, { chain: e.chain, type: e.type, gen: e.gen, data: e.data })
    }
    if (e.type === 'reconcile' && e.gen !== null && typeof txId === 'string' && e.chain !== null) {
      const k = `${e.chain}/${e.gen}`
      let set = l.reconciled.get(k)
      if (set === undefined) { set = new Set(); l.reconciled.set(k, set) }
      set.add(txId)
    }
    // m-a: hold a FINAL verdict for the chain's stopped stretch (only lines of a STOPPED chain cost a state build; once held, none)
    if (e.chain === 'eth' || e.chain === 'sol' || e.chain === 'btc') {
      const base = l.js.basePhase(e.chain)
      if (base !== 'STOPPED' && base !== 'CLAWING_BACK') l.finalStops.delete(e.chain)
      else if (base === 'STOPPED' && !l.finalStops.has(e.chain)) {
        const v = currentVerdictOf(l, e.chain)
        if (v !== null && v.cls === 'final') l.finalStops.set(e.chain, v)
      }
    }
  }
  const rebuild = (l: Loaded): void => {
    try {
      l.js = createJobState(l.entry.def)
      l.ledger = createLedger()
      l.intents.clear()
      l.reconciled.clear()
      l.solResumeCap = 0
      l.finalStops = new Map()
      for (const e of l.raw.all()) index(l, e)
    } catch {
      l.broken = true
    }
  }

  const writeTraceNow = (l: Loaded): void => {
    const t = traceTimers.get(l.entry.id)
    if (t !== undefined) { clearTimeout(t); traceTimers.delete(l.entry.id) }
    try { writeTrace(l.entry.dir, renderTrace({ id: l.entry.id, def: l.entry.def, state: overlay(l, l.js.state()), network })) } catch { /* the journal is the record */ }
  }
  const touchTrace = (l: Loaded): void => {
    if (closed) { writeTraceNow(l); return }
    if (traceTimers.has(l.entry.id)) return
    const t = setTimeout(() => { traceTimers.delete(l.entry.id); writeTraceNow(l) }, traceDelayMs)
    t.unref()
    traceTimers.set(l.entry.id, t)
  }

  // A claw-back of the chain has landed (ledger evidence): the chain counts as CLAWED_BACK for the gate (NEW-1).
  const landedClaw = (cl: ChainLedger): boolean => cl.clawLanded
  const ofLandedClawFamily = (cl: ChainLedger, a: LedgerAttempt | undefined): boolean =>
    a !== undefined && a.claw && cl.family(a.family).settled

  // event.attempt (see the header): evidence names a known attempt of its chain.
  const assertEvidence = (l: Loaded, chain: Chain, type: string, d: Record<string, unknown>): void => {
    const cl = l.ledger.chain(chain)
    const a = typeof d.txId === 'string' ? cl.byTx.get(d.txId) : undefined
    const open = (): boolean => a !== undefined && l.js.isOpen(chain, a.txId)
    let ok = true
    switch (type) {
      case 'sent': ok = a !== undefined && !a.claw && open(); break
      case 'readback': ok = a !== undefined && !a.claw; break
      case 'included': ok = a !== undefined && !a.claw && a.copy === d.copy && a.part === d.part && a.attempt === d.attempt; break
      case 'reconcile': ok = a !== undefined && (d.outcome !== 'adopted' || (a.claw ? a.status === 'pending' && !a.failed : open())); break
      case 'stuck': case 'resolved': ok = a !== undefined; break
      case 'replaced': {
        const p = typeof d.prevId === 'string' ? cl.byTx.get(d.prevId) : undefined
        ok = a !== undefined && p !== undefined && a !== p && a.claw === p.claw && a.copy === p.copy && a.part === p.part && a.nonce === p.nonce
        break
      }
      case 'clawback-sent': case 'clawback-readback': ok = a !== undefined && a.claw; break
      case 'clawback-included': ok = a !== undefined && a.claw && a.status !== 'dead'; break
      case 'clawback-failed': ok = a !== undefined && a.claw && a.status !== 'landed'; break
      case 'reassembled': ok = typeof d.copy === 'number' && cl.copies.has(d.copy); break
      default: break
    }
    if (!ok) refuse('event.attempt', `${type}: it names no known attempt of this chain (or not one it can apply to): evidence is accepted only for journaled attempts`) // @guard:event.attempt
  }

  // The job-domain checks of an intent / claw-back intent (see the header).
  const assertSendable = (l: Loaded, chain: Chain, kind: IntentKind, data: Record<string, unknown>, nowMs: number, confirm: unknown): void => {
    const job = l.entry
    const intent = kind === 'intent'
    const target = intent ? { copy: data.copy as number, part: data.part as number } : undefined
    const cl = l.ledger.chain(chain)
    // CC-8: after a Stop the API admits exactly ONE btc reveal for a copy whose commit intent is journaled (landed or still open): the
    // commit locked value that only its reveal can move, so refusing it would strand that value. Its binding is the same server-computed
    // one (q = the journaled commit). A second reveal, a replacement, and any new commit stay refused.
    const strandedReveal = (): boolean => {
      if (chain !== 'btc' || data.part !== 2 || !isObj(data.btc) || data.btc.kind !== 'reveal') return false
      let commit = false
      for (const a of cl.byTx.values()) {
        if (a.copy !== data.copy || a.claw) continue
        if (a.part === 2) return false
        if (a.part === 1 && (a.status === 'landed' || a.status === 'pending') && isObj(l.intents.get(a.txId)?.data.btc) && (l.intents.get(a.txId)!.data.btc as Record<string, unknown>).kind === 'commit') commit = true
      }
      return commit
    }
    // PF-S fix round 3: once a chain has a stop request (stop-requested, not resumed) or a journaled stop, NO new job intent: no
    // replacement, fee bump or re-sign of an attempt in flight, no next part, no next copy — the executor signs nothing new after a
    // Stop (PF-E). The one exception is the reveal of a btc copy whose commit is already out (strandedReveal). Claw-back intents are
    // not job intents: they stay allowed under their own rules (a settled chain, nothing in flight) — they are the way out.
    // PF-S fix round 5 (R34-1): the journaled stop is core's STOP LATCH, not the (overlaid) phase: it holds through STUCK and every
    // later executor event until the operator's resume (POST /jobs/:id/resume, resume-requested) clears it.
    if (intent && (l.js.stopRequested(chain) || l.js.stopLatched(chain)) && !strandedReveal()) {
      refuse('intent.after-stop', `${chain} has a stop request: nothing new is signed after a Stop (no replacement, bump, next part or copy; only the reveal of a btc copy whose commit is out). A claw-back stays allowed on a settled chain; resume to continue.`) // @guard:intent.after-stop
    }
    assertIntentAllowed(job.def, jobView(l), chain, nowMs, kind, target)
    const d = job.def.chains[chain]!
    assertJobState(!intent || d.mode === 'drain' || (data.copy as number) <= d.mode.copies, `copy ${String(data.copy)} is beyond this job's copy count`)
    if (intent) {
      const { copy, part } = target!, top = cl.top
      const inOrder = (copy === top.copy && part >= 1 && part <= top.part + 1) || (copy === top.copy + 1 && part === 1)
      if (!inOrder) refuse('job.copy-order', `copy ${String(copy)} part ${String(part)} is out of order: the next intent is copy ${top.copy} (a part up to ${top.part + 1}) or copy ${top.copy + 1} part 1`) // @guard:job.copy-order
    }
    const replaces = intent ? data.replaces as string | null : null
    const inGroup = intent ? cl.pendingIn(target!.copy, target!.part) : []
    const fresh = !l.intents.has(data.txId as string)
    if (!fresh) refuse('event.duplicate', 'this txId is already journaled as an intent: ask POST …/tickets for a fresh ticket instead') // @guard:event.duplicate
    if (!intent) {
      const to = data.to as string
      const kind = reservedKind(chain, to)
      const destOk = (kind === null || kind === 'precompile') && !sameAddress(chain, to, d.keyAddress) && clawbackToAllowed(network, chain, d.clawbackTo, to)
      if (destOk && kind === 'precompile') refuse('job.clawback-precompile', 'the claw-back destination is an Ethereum precompile or reserved system address (0x…0001 to 0x…ffff): nobody controls it and value sent there is lost') // @guard:job.clawback-precompile
      if (!destOk) refuse('job.clawback', "a claw-back goes only to the job's clawbackTo (when set; on mainnet always, and only there), never to the null or burn address or to the lane's own key") // @guard:job.clawback
    }
    const eth = data.eth as EthIntent | undefined
    const key = cl.familyKey(eth !== undefined ? eth.nonce : null, data.txId as string)
    const fam = cl.family(key)
    let familyOk: boolean
    if (intent) {
      const { copy, part } = target!
      const sameGroupKnown = (txId: string | null): boolean => { const p = txId === null ? undefined : cl.byTx.get(txId); return p !== undefined && !p.claw && p.copy === copy && p.part === part }
      if (eth !== undefined) {
        // PF-S fix round 4: a nonce whose attempt the operator marked failed is the claw-back's (below): no job attempt joins it again
        familyOk = !fam.settled && !fam.pending.some((x) => x.markedFailed) && (fam.pending.length > 0
          ? fam.pending.every((x) => !x.claw && x.copy === copy && x.part === part) && fam.pending.some((x) => x.txId === replaces)
          : inGroup.length === 0 && (replaces === null || sameGroupKnown(replaces)))
      } else familyOk = (replaces === null || sameGroupKnown(replaces)) && (chain !== 'btc' || inGroup.length === 0)   // btc: never two open attempts for one (copy, part): E7's own rule, now at the gate (fix round 2 review m-1)
    } else {
      const claws = cl.pendingClaws()
      // PF-S fix round 4 (PF-E review I-2): the first claw-back takes a fresh nonce, or (ETH) the nonce of an unsettled family whose
      // pending members are all job attempts that are no longer OPEN — each open one resolved mark-failed by the operator (core's
      // check above already refuses a claw-back while anything is open or stuck), or a claim the executor reported rejected. This is
      // the engine's recovery for an attempt dropped at an unused nonce: stuck → resolve mark-failed → claw back at that nonce. One
      // nonce: only one of them can land; the cap still counts both kinds, as core's CapLedger does (ledger.ts familyContribution).
      familyOk = claws.length === 0
        ? !fam.settled && (fam.pending.length === 0 || (eth !== undefined && fam.pending.every((x) => !x.claw && l.js.reducer.tx(chain, x.txId)?.open !== true)))
        : eth !== undefined && !fam.settled && claws.every((x) => x.nonce === eth.nonce && x.to !== null && sameAddress(chain, x.to, data.to as string))
    }
    if (!familyOk) refuse('event.family', 'not a new family and not a replacement of the attempt in flight: eth bumps keep their (copy, part) and nonce and name it in replaces; a used nonce is never signed again; one claw-back family at a time') // @guard:event.family
    const cap = l.js.armed()?.caps[chain]
    const fee = worstFee(chain, data) // = the ticket's f (one formula)
    const worst = fee === null ? null : fee + (intent ? 0n : BigInt(data.value as string))
    const base = bigMax(cl.charged, l.js.spent(chain) + cl.clawValue) + cl.inFlight
    // eth: this send joins its nonce family's members of ITS kind (the larger worst case); a claw-back on the nonce of job attempts
    // resolved mark-failed adds to theirs (PF-S fix round 4: ledger.ts familyContribution, as core's CapLedger holds both)
    const famIn = fam.kindInFlight(!intent)
    const total = worst === null ? null : eth !== undefined ? base - famIn + bigMax(famIn, worst) : base + worst
    let limit = cap !== undefined && DEC.test(cap.nativeCap) ? BigInt(cap.nativeCap) : null
    if (!intent) {
      // CC-2a: core's rule (the contract's), then the API's own exact binding of the typed amount to this one intent.
      checkClawbackConfirm(overlay(l, l.js.state()), chain, data, confirm)
      if (confirm !== undefined) {
        const typed = isObj(confirm) && typeof confirm.amount === 'string' && DEC.test(confirm.amount) ? BigInt(confirm.amount) : null
        assertWithinCap(typed !== null && worst !== null && typed === worst, 'the typed claw-back amount is not exactly value + worst-case fee of this claw-back (base units)')
        if (limit !== null) limit += worst!
      }
    }
    const fits = limit !== null && total !== null && total <= limit
    assertWithinCap(fits, intent
      ? "this intent's worst-case fee does not fit what is left of the armed cap (charged and every attempt in flight counted)"
      : confirm === undefined
        ? "the claw-back's value + worst-case fee does not fit what is left of the armed cap (charged and in flight counted): the operator types that exact amount (clawbackConfirm) to confirm it"
        : 'with the typed claw-back amount, everything else charged and in flight must still fit the armed cap')
  }

  // THE gate (see the header). Returns, for a ticket, the journaled intent with its v2 binding.
  type GateOp = { append: JournalInput; confirm?: unknown } | { ticket: { chain: Chain; txId: string } } | { pcMint: { chain: Chain } }
  async function gate(l: Loaded, op: GateOp): Promise<Ticketable | null> {
    gateRuns++
    assertJobState(!l.broken, "this job's state could not be rebuilt from its journal: nothing more is written or sent")
    if ('pcMint' in op) {
      // Sfix-PC fix round 1 (review M-5): a Privacy Cash authorization funds a lane, so it passes the lane's checks: the job is
      // intact, the chain is in a live phase (not over, stuck, clawed back), the legacy latch is clear.
      const chain = op.pcMint.chain
      const phase = l.js.phase(chain)
      assertJobState(phase !== undefined && phase !== 'STUCK' && !OVER.has(phase) && !landedClaw(l.ledger.chain(chain)) && l.raw.corrupt() === null,
        `${chain} is ${String(phase)}: no Privacy Cash authorization (a chain that is over, stuck, clawed back or corrupt is not funded)`)
      await latch.assertClear()
      return null
    }
    if ('ticket' in op) {
      const { chain, txId } = op.ticket
      const line = l.intents.get(txId)
      const intent = line !== undefined && line.chain === chain ? line : undefined
      const binding = intent === undefined ? null : bindingOf(l, chain, intent.type, intent.data)
      if (intent === undefined || binding === null) refuse('ticket.not-intent', 'no journaled intent of this chain has that txId (with a complete ticket binding)') // @guard:ticket.not-intent
      const open = l.js.isOpen(chain, txId)
      if (!open) refuse('ticket.terminal', 'that intent is settled: no fresh ticket') // @guard:ticket.terminal
      const phase = l.js.phase(chain)
      assertJobState(phase !== undefined && phase !== 'STUCK' && !OVER.has(phase) && !landedClaw(l.ledger.chain(chain)) && l.raw.corrupt() === null && l.raw.writable(),
        `${chain} is ${String(phase)}: no fresh ticket (a stuck attempt is never resent; a chain that is over or clawed back sends nothing)`)
      await latch.assertClear()
      jobSendLock(network)
      return { ...intent, binding }
    }
    const e = op.append
    validateEvent(e.type, e.data, e.by)
    assertWithinCap(op.confirm === undefined || e.type === 'clawback-intent', 'a typed claw-back amount (clawbackConfirm) goes only with a clawback-intent')
    if (e.chain === null) return null
    const chain = e.chain, t = e.type, d = e.data
    const send = t === 'intent' || t === 'clawback-intent'
    // an eth / sol job intent's binding is the API's plan (PF-S I-1): it is formed after the job-domain checks, below
    const planned = t === 'intent' && (chain === 'eth' || chain === 'sol')
    assertEventShape(fitsChain(l.entry, network, chain, t, d) && (!send || planned || bindingOf(l, chain, t, d) !== null))
    const cl = l.ledger.chain(chain)
    const realPhase = l.js.phase(chain)!
    const corrupt = l.raw.corrupt() !== null
    // NEW-1: after a claw-back landed, the chain is CLAWED_BACK for the API's rules, except for that claw-back's own outcome.
    const own = (t === 'clawback-included' || t === 'clawback-readback') && ofLandedClawFamily(cl, typeof d.txId === 'string' ? cl.byTx.get(d.txId) : undefined)
    const phase: ChainPhase = landedClaw(cl) && !own ? 'CLAWED_BACK' : realPhase
    assertApiPhaseRules({ corrupt, phase, claw: l.js.claw(chain), own, latched: l.js.stopLatched(chain), base: l.js.basePhase(chain), stopRequested: l.js.stopRequested(chain),
      finalStop: () => stopVerdictOf(l, chain)?.cls === 'final' }, { chain, type: t, data: d })
    if (t === 'lease-acquired') assertJobState(!OVER.has(realPhase), `${chain} is ${realPhase}: no lease on a chain that is over`)
    if (t === 'close') {
      assertJobState(SETTLED.has(realPhase) && l.js.reducer.openIntents(chain) === 0 && cl.openInFlight() === 0n,
        'close only a settled chain with nothing in flight (every attempt landed, reconciled expired / nonce-consumed, or resolved mark-failed)')
    }
    assertEvidence(l, chain, t, d)
    if (e.by === 'browser' || e.by === 'cli') assertEventAllowed(l.entry.def, jobView(l), { chain, type: t, data: d })
    if (send) {
      await latch.assertClear()
      jobSendLock(network)
      assertSendable(l, chain, t, d, clock.now(), op.confirm)
      if (planned) {
        assertPlanned(l, chain, d)
        assertEventShape(bindingOf(l, chain, t, d) !== null)
      }
      assertFeePlan(l, chain, t, d)
    }
    return null
  }

  // The stored record, checked: { def, createdAt } with a canonical def of this id and this network.
  const readRecord = async (id: string): Promise<{ def: JobDef; createdAt: number } | null> => {
    const rec = await store.read<unknown>('job', id)
    if (rec === undefined) return null
    const v = rec.value
    const def: unknown = isObj(v) ? v.def : undefined
    const createdAt: unknown = isObj(v) ? v.createdAt : undefined
    if (!isObj(def) || !Number.isSafeInteger(createdAt)) throw new Error('job record: not { def, createdAt }')
    const again = normalizeJob(def, { network: def.network as Network, existing: true }).def
    if (canonicalJson(again) !== canonicalJson(def) || jobId(again) !== id) throw new Error('job record: not the canonical definition of this id')
    assertJobNetwork(again.network === network)
    return { def: again, createdAt: createdAt as number }
  }

  const open = async (id: string): Promise<Loaded> => {
    const rec = HEX16.test(id) ? await readRecord(id) : null
    assertFound(rec !== null)
    const dir = join(stateDir, 'jobs', id)
    const raw = openJournal(dir, { clock, ...(o.fs !== undefined ? { fs: o.fs } : {}) })
    const def = rec!.def
    const l = {} as Loaded
    const entry: JobEntry = {
      id, def, defSha256: sha256Hex(canonicalJson(def)), createdAt: rec!.createdAt, dir,
      chains: CHAINS.filter((c) => def.chains[c] !== undefined),
      journal: {
        async append(e, o?: AppendOptions) {
          await gate(l, { append: e, confirm: o?.clawbackConfirm })
          const ev = await raw.append(e)
          try { index(l, ev) } catch { rebuild(l) }
          touchTrace(l)
          return ev
        },
        all: () => raw.all(),
        corrupt: () => raw.corrupt(),
        writable: () => raw.writable(),
        subscribe: (fn) => raw.subscribe(fn),
        close: () => raw.close(),
      },
    }
    Object.assign(l, { entry, raw, js: createJobState(def), ledger: createLedger(), intents: new Map(), reconciled: new Map(), broken: false, plans: new Map(), text: null, solResumeCap: 0, finalStops: new Map() })
    rebuild(l)
    if (raw.all().length === 0 && raw.corrupt() === null) {
      await entry.journal.append({ chain: null, by: 'api', gen: null, type: 'created', data: { jobId: id, defSha256: entry.defSha256 } })
    }
    writeTraceNow(l)
    jobs.set(id, l)
    return l
  }

  const withChain = (job: JobEntry, chain: Chain | null | undefined): JobEntry => {
    assertFound(chain === null || chain === undefined || job.chains.includes(chain))
    return job
  }

  const load = async (id: string, chain?: Chain | null): Promise<JobEntry> => {
    const known = jobs.get(id)
    if (known !== undefined) return withChain(known.entry, chain)
    let p = loading.get(id)
    if (p === undefined) {
      p = open(id)
      loading.set(id, p)
      p.then(() => loading.delete(id), () => loading.delete(id))
    }
    return withChain((await p).entry, chain)
  }

  const get = (id: string, chain?: Chain | null): JobEntry => {
    const l = jobs.get(id)
    assertFound(l !== undefined)
    return withChain(l!.entry, chain)
  }

  const list = async (): Promise<JobEntry[]> => {
    const out: JobEntry[] = []
    for (const id of await store.list('job')) out.push(await load(id))
    return out
  }

  const active = (l: Loaded, chain: Chain): boolean => {
    if (l.raw.corrupt() !== null || l.broken) return true
    if (l.js.phase(chain) === undefined) return false
    return !l.js.terminal(chain) && (l.js.armed() !== null || l.js.reducer.openIntents(chain) > 0)
  }

  return {
    network,
    messages,
    sources,
    latch,
    load,
    get,
    list,
    journalOf: (id) => get(id).journal,
    jobState: (id) => loadedOf(get(id)).js,
    ledgerOf: (job, chain) => loadedOf(job).ledger.chain(chain),
    stopVerdict: (job, chain) => stopVerdictOf(loadedOf(job), chain),
    state: (job) => { const l = loadedOf(job); return overlay(l, l.js.state()) },
    intentOf: (job, txId) => loadedOf(job).intents.get(txId),
    gates: () => gateRuns,
    assertJobSendsAllowed: () => jobSendLock(network),

    create(input) {
      const run = async (): Promise<{ created: boolean; job: JobEntry }> => {
        const { def, text } = normalizeJob(input, { network })
        if (text !== null) messages.storeText(text, def.messageSha256)
        else messages.assertStored(def.messageSha256, def.messageBytes)
        const id = jobId(def)
        if (await store.read<unknown>('job', id) === undefined) {
          await store.update<unknown>('job', id, (cur) => cur ?? { def, createdAt: clock.now() })
          return { created: true, job: await load(id) }
        }
        const job = await load(id)
        if (canonicalJson(job.def) !== canonicalJson(def)) throw new Error('job record: another definition holds this id')
        return { created: false, job }
      }
      const next = creates.then(run, run)
      creates = next.then(() => undefined, () => undefined)
      return next
    },

    openIntents(id, chain) {
      return loadedOf(get(id)).js.openAttempts(chain).map((oa): OpenIntent => ({
        txId: oa.txId, gen: oa.gen, copy: oa.copy, part: oa.part, attempt: oa.attempt,
        ...(oa.eth !== undefined ? { eth: oa.eth } : {}), ...(oa.sol !== undefined ? { sol: oa.sol } : {}), ...(oa.btc !== undefined ? { btc: oa.btc } : {}),
      }))
    },
    reconciled: (id, chain, gen) => loadedOf(get(id)).reconciled.get(`${chain}/${gen}`) ?? new Set<string>(),

    async assertKeyFree(job, chain) {
      const mine = job.def.chains[chain]
      if (mine === undefined) return
      let busy = false
      for (const other of await list()) {
        const theirs = other.def.chains[chain]
        if (other.id !== job.id && theirs !== undefined && sameAddress(chain, theirs.keyAddress, mine.keyAddress) && active(loadedOf(other), chain)) busy = true
      }
      if (busy) refuse('job.key-busy', 'another job is active on this key (armed and not yet DONE, CLAWED_BACK or SKIPPED): finish it, claw back or close it first') // @guard:job.key-busy
    },

    async ticket(job, chain, gen, txId) {
      const intent = await gate(loadedOf(job), { ticket: { chain, txId } })
      return issueTicket(o.ticketKey, { j: job.id, w: network, c: chain, g: gen, t: txId, r: intent!.data.rawSha256 as string, ...intent!.binding }, clock.now())
    },

    async mintPrivacyCash(job, req) {
      await gate(loadedOf(job), { pcMint: { chain: 'sol' } })
      return laneMint.mint({ lane: keyAddressOf(job, 'sol'), job: job.id, tryIndex: req.tryIndex, bodySha256: req.bodySha256, amount: req.amount })
    },

    flushTrace: (job) => { const l = jobs.get(job.id); if (l !== undefined) writeTraceNow(l) },
    flushTraces() { for (const id of [...traceTimers.keys()]) { const l = jobs.get(id); if (l !== undefined) writeTraceNow(l) } },
    close() {
      for (const id of [...traceTimers.keys()]) { const l = jobs.get(id); if (l !== undefined) writeTraceNow(l) }
      closed = true
    },
  }
}

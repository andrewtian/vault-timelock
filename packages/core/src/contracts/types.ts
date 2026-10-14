// packages/core/src/contracts/types.ts — types only (erasable). The shared contract every lane codes against.
// Changes only through the controller ("contract change"); see the Task 0 brief and task-0-report.md.
//
// Rulings folded in after the brief's verbatim text (Task 0, 2026-10-09):
//   · R73: `publishMode` (contracts/publish.ts table) REPLACES `recipient`; `feeStrategy` added. In JobInput both are
//     optional (defaults below); in the canonical JobDef both are always present.
//   · ruling 8: ChainPhase 'SKIPPED' — at `armed`, every chain of the def NOT in the arm becomes SKIPPED (terminal,
//     absorbing; no funds touched; never armed later in that job).
//   · ruling 6: RelayStatus identity entries may carry the fork-drift message (contracts/gas.ts).
//   · CC-1 (I1): job-level `arweaveCopy` (contracts/publish.ts ARWEAVE_COPY). JobInput: optional boolean. JobDef: the
//     member is present only when true (false and absent are the same job with the same jobId), so a job without an
//     Arweave copy keeps its id. Reserved for now: true is refused job.publish-mode-unavailable; not a boolean,
//     job.arweave-copy.
//   · CC-2a (E3, controller-approved): the claw-back is a FAMILY of attempts (reducer semantics below), ChainState
//     .clawback.landed, clawback-failed may carry the fee a failed-on-chain claw-back was charged, chain evidence wins
//     over an earlier journaled outcome, a landed attempt without a journaled fee is spent at its worst case, and the
//     typed claw-back amount (`clawbackConfirm`, EventAppendRequest). Corrected by the security review "reducer
//     fail-open drift" (controller): the family settles only on chain evidence or when every member is dead; one family
//     per chain; events that do not fit change nothing.
//
// Reducer semantics (reduce(def, events) → JobState; pinned by contract/fixtures/journals/*):
//   · JobState.seq = seq of the last event folded. corrupt is never set by reduce (the API's journal loader sets
//     phase CORRUPT + corrupt on a bad hash link, seq gap or unparsable line).
//   · Chain base phase: AWAITING_KEY →(key-loaded) AWAITING_FUNDS →(funds affordable) READY (funds not affordable →
//     AWAITING_FUNDS; funds only move these two) →(armed, if armed) ARMED, else SKIPPED →(intent) RUNNING ⇄
//     (paused/resumed) PAUSED → drained DRAINED | copies-done COPIES_DONE | stopped (by api or executor) STOPPED →
//     clawback-intent CLAWING_BACK → clawback-included CLAWED_BACK (clawback-failed → back to the settled phase) |
//     close → DONE. STUCK overlays the base phase while any attempt is stuck. SKIPPED overrides everything.
//   · reason: paused/stopped/stuck reason; 'not armed' for SKIPPED; null otherwise.
//   · copy/attempt: from the latest job `intent` (claw-backs excluded); null before.
//   · Attempt states: intent → sent | unknown | rejected (sent.outcome accepted|unknown|rejected); reconcile.outcome →
//     included | expired | nonce-consumed | adopted; included → included (open siblings → superseded);
//     resolved mark-done → resolved-done (counts as landed, block/fee null), mark-failed → resolved-failed.
//     Open = intent | sent | unknown | adopted. stuck {txId} flags an attempt until resolved/reconcile/included.
//     sent, a reconcile other than included and mark-failed move only an attempt that is not final (intent, sent,
//     unknown, adopted, rejected); a reconcile expired | nonce-consumed also closes a resolved-failed one (evidence
//     over a claim; E3, after S2 2fea217; approved at CC-2b). CHAIN EVIDENCE WINS (CC-2a): an inclusion (included of
//     the attempt's own (copy, part), reconcile included, resolved mark-done) lands ANY attempt that has not landed yet —
//     also one journaled expired, nonce-consumed, rejected, superseded or resolved-failed (a SOL signature whose expiry
//     was journaled may still land). Once any attempt of a part has landed the part is landed and never sent again; a
//     second landing is paid (spent) but never counted as progress; the TxView keeps the first landing's landedId,
//     block and fee.
//     FAIL CLOSED (security review, reducer fail-open drift): an event that does not fit what it names changes
//     nothing — an unknown txId, outcome or action, an included naming another (copy, part), a readback of an attempt
//     that has not landed, a claw-back event for a txId that is not a member, a clawback-readback of a member that did
//     not land. The API refuses such events first (core assertEventAllowed).
//   · BTC amounts (CC-12, E7): a btc intent's `reserved`, the `fee` of its `included` / `reconcile included` and so ChainState.spent / TxView.fee
//     are what LEAVES THE LANE'S SPENDABLE OUTPUTS for that tx: a commit = its fee + the value it locks in the commit output (the reveal's
//     fee + the 546 sat postage), a reveal = 0 (it moves only what the commit locked). Receipts show them under that label; the real
//     per-tx fee is in the intent's btc.fee.
//   · TxView.state: included (an attempt included or resolved-done) > stuck > open (any attempt open) > failed.
//     txs sorted by (copy, part); attempts in intent order. readback from `readback` of the group's landed attempt.
//   · openIntents: txIds of open attempts (txs order), then every OPEN member of the claw-back family.
//   · spent: decimal string = Σ over every landed job attempt of its fee — the journaled fee, or, when the journal
//     carries none (resolved mark-done, a reconcile included without fee), the attempt's worst case (eth gas × maxFee,
//     sol fee), never 0 (CC-2a) — + every claw-back fee charged on chain (the landed member's, and any member that
//     failed on chain), once per txId. (BTC: a commit's cap charge is its fee + the value it locks; the API's ledger charges
//     a landed commit at least that, whatever fee is reported, so an executor may report either.)
//   · clawback (CC-2a: ONE FAMILY of attempts per chain): null → {txId, to, value, ok: null, landed: false} at the
//     first clawback-intent. Every later clawback-intent until a member landed joins the family as an open member — an
//     ETH same-nonce bump, a SOL re-sign after a proven expiry, or a retry (which re-opens a failed family: ok null,
//     CLAWING_BACK) — and txId/to/value show the latest member. All open members are listed in openIntents. The family
//     settles ONLY on chain evidence: a member LANDED — clawback-included {value, fee} (the chain's) or the executor's
//     reconcile included (the value its intent signed; the reconcile's fee, else the member's worst-case fee) — and
//     the claw-back shows THAT member (txId, value), ok true, landed true, CLAWED_BACK, every other member closed, even
//     when later bumps exist; or EVERY member is dead and none landed — it fails by itself: ok false, back to the
//     settled phase (nothing is in flight, so nothing stays locked). A member dies by reconcile expired |
//     nonce-consumed, by clawback-failed {fee?} (fee = what it was charged if it failed ON CHAIN) or by the operator's
//     resolved mark-failed; adopted keeps it open; a resolved mark-done of a member is not chain evidence and changes
//     nothing. While any member is open (unknown or stuck included) the chain stays CLAWING_BACK. A landed claw-back is
//     final: a later clawback-intent is ignored. clawback-readback of the landed member sets ok = data.ok. A stuck
//     member flags STUCK until a reconcile, a resolve or the family settles.
//   · resume: current copy = highest copy with a job intent; nextPart = lowest p in 1..parts without (included +
//     readback true); null when no intent yet or the current copy is complete.
//   · copiesIncluded: copies whose parts 1..parts all have included + readback true.
//   · reassembled: in event order, a later event for the same copy replaces the earlier entry.
//   · stopRequested: set by stop-requested (chain or null = all), cleared by resume-requested (same rule).
//   · stopLatched (PF-S fix round 5, R34-1, the stop latch): set by a journaled `stopped`; cleared ONLY by the operator's
//     resume-requested (the API's resume route, chain or null). While set, no executor event moves the chain out of STOPPED:
//     paused, resumed, drained, copies-done and job intents leave the base STOPPED (the gate refuses them first), with or
//     without the STUCK overlay; evidence about existing attempts (sent, reconcile, included, readback, stuck), resolve,
//     claw-back and close still apply. Shown (true) only while set and the chain is not SKIPPED, CLAWED_BACK or DONE. The reducer
//     view: JobReducer.stopLatched(c) (CC-15 addendum).
//   · base phase (PF-S fix round 6): executor phase events (paused, resumed, drained, copies-done, stopped, copy-built) are judged on
//     the phase under the STUCK overlay (ChainState.stuckBase while STUCK): only ARMED, RUNNING, PAUSED — or a STOPPED chain the
//     operator resumed (no latch) — is moved by them. DRAINED, COPIES_DONE, a latched STOPPED, DONE, CLAWED_BACK, CLAWING_BACK and
//     SKIPPED never are, STUCK or not; job intents never move them either. Evidence about existing attempts, resolve, claw-back and
//     close still apply. The reducer view: JobReducer.basePhase(c) (CC-15 addendum; every production gate reads it).
//   · skip {releaseAt} sets JobState.releaseAt AND armed.releaseAt (so startAt(armed, c) follows the skip).
//   · Job phase: CORRUPT (API only) > DONE (every chain ∈ {DONE, CLAWED_BACK, STOPPED, SKIPPED}, none with open
//     intents) > RUNNING (any chain RUNNING, PAUSED, STUCK or CLAWING_BACK) > ARMED (armed record) > DEFINED.
//   · isChainTerminal (frees the key, job.key-busy): phase ∈ {DONE, CLAWED_BACK, SKIPPED} and no open intents.
//     STOPPED/DRAINED/COPIES_DONE keep the key busy until claw-back or close (ruling 5).
import type { FeeStrategy, PublishMode } from './publish.ts'
import type { StopClass, StopCode } from './stop.ts'

export type Network = 'local' | 'testnet' | 'mainnet'
export type Chain = 'eth' | 'sol' | 'btc'                           // CC-7: 'btc' is in the union; CC-12: the btc lane runs on local (job.chain-unsupported = btc off local)
export type TextKind = 'plain' | 'timelocked'
export type Holder = 'browser' | 'cli'
export type Mode = 'drain' | { copies: number }                    // copies 1..10000
export type { FeeStrategy, PublishMode }
// Canonical per-chain definition (in JobDef: publishMode and feeStrategy always present).
export interface JobChainDef {
  mode: Mode; publishMode: PublishMode; feeStrategy: FeeStrategy; distinctCopies: boolean; keyAddress: string
  budgetUsd: number; maxTipGwei?: number; maxCuPrice?: number; clawbackTo: string | null
  maxFeeRateSatVb?: number   // btc only (CC-12; CC-14: REQUIRED when a btc job is created (job.btc-fee-ceiling), optional in a stored job: 500 sat/vB fallback): the highest fee rate (sat/vB) the lane pays, 1..500 (btc-ord BTC_MAX_FEE_RATE); the engine clamps its rate to it
}
// Per-chain input: publishMode defaults to DEFAULT_PUBLISH_MODE[chain]; feeStrategy to defaultFeeStrategy(mode)
// ('passive' for drain, 'economy' for copies). `recipient` is gone (R73): it is an unknown key now.
export type JobChainInput = Omit<JobChainDef, 'publishMode' | 'feeStrategy'> & { publishMode?: PublishMode; feeStrategy?: FeeStrategy }
// Input accepted by vt / POST /jobs: exactly one of message | messageFile (vt only) | messageSha256+messageBytes
export interface JobInput {
  format: 'vt-job/1'; network: Network; name: string; chains: Partial<Record<Chain, JobChainInput>>
  message?: string; messageFile?: string; messageSha256?: string; messageBytes?: number; arweaveCopy?: boolean
  textKind?: TextKind   // CC-7: default (and absent) 'plain'; 'timelocked' is refused job.publish-mode-unavailable until E6/W7
}
// Canonical stored form (jobId hashes this)
export interface JobDef {
  format: 'vt-job/1'; network: Network; name: string; messageSha256: string; messageBytes: number
  chains: Partial<Record<Chain, JobChainDef>>; arweaveCopy?: true
}
export type ChainPhase = 'AWAITING_KEY' | 'AWAITING_FUNDS' | 'READY' | 'ARMED' | 'RUNNING' | 'PAUSED' | 'DRAINED'
  | 'COPIES_DONE' | 'STOPPED' | 'CLAWING_BACK' | 'CLAWED_BACK' | 'DONE' | 'STUCK' | 'SKIPPED'
// Final round (F18-2): DONE = every chain terminal (job/reduce.ts isChainTerminal: DONE, CLAWED_BACK or SKIPPED with nothing open — its key
// free); RUNNING = a chain RUNNING, PAUSED, STUCK or CLAWING_BACK; ARMED = armed and neither (also every chain settled but not terminal:
// STOPPED — resumable or final —, DRAINED, COPIES_DONE: the same label before and after a resume); DEFINED = not armed.
export type JobPhase = 'DEFINED' | 'ARMED' | 'RUNNING' | 'DONE' | 'CORRUPT'
export type ApiEventType = 'created' | 'armed' | 'skip' | 'stop-requested' | 'resume-requested' | 'close' | 'resolved'
  | 'lease-acquired' | 'lease-released' | 'lease-expired' | 'stopped' | 'note'
export type ExecEventType = 'key-loaded' | 'funds' | 'reconcile' | 'copy-built' | 'intent' | 'sent' | 'replaced'
  | 'included' | 'readback' | 'reassembled' | 'paused' | 'resumed' | 'drained' | 'copies-done' | 'stopped'
  | 'clawback-intent' | 'clawback-sent' | 'clawback-included' | 'clawback-readback' | 'clawback-failed' | 'stuck' | 'note'
// One journal line, written as JSON.stringify in exactly this key order. prev = sha256 hex of the previous line's
// UTF-8 bytes (without its '\n'); '' at seq 0. chain = the event's chain (null for job-level events).
export interface JournalEvent {
  v: 1; seq: number; at: number; prev: string; chain: Chain | null; by: Holder | 'api' | 'operator'
  gen: number | null; type: ApiEventType | ExecEventType; data: Record<string, unknown>
}
export interface EthIntent { nonce: number; tip: string; maxFee: string; gas: string; to: string }
export interface SolIntent { blockhash: string; lastValidBlockHeight: number; cuPrice: number; cuLimit: number; rung: number | null; fee: string }
// CC-12 (E7, E7b): the BTC intent as journaled in an `intent` event's data (`btc`; exactly one of eth | sol | btc). commit: the lane
// pubkey (33-byte compressed, hex), its fee, the value it locks in the commit output (both decimal sats) and 1..8 outpoints
// `<txid>:<vout>` in strictly ascending order; reveal: the lane pubkey, its fee and the vout of the commit output it spends. A takeover
// rebuilds the very bytes from it (rawSha256 pins them). The API mints the ticket from these and from values it computes itself.
export type BtcIntent = { kind: 'commit'; pubkey: string; fee: string; value: string; inputs: string[] }
  | { kind: 'reveal'; pubkey: string; fee: string; commitVout: number }
export interface IntentData {
  txId: string; copy: number; part: number; parts: number; attempt: number; replaces: string | null
  rawSha256: string; payloadSha256: string; reserved: string; eth?: EthIntent; sol?: SolIntent; btc?: BtcIntent
}
export type AttemptState = 'intent' | 'sent' | 'unknown' | 'rejected' | 'superseded' | 'included' | 'expired'
  | 'nonce-consumed' | 'adopted' | 'resolved-done' | 'resolved-failed'
// CC-12: a btc attempt carries its intent (`btc`) and the sha256 of the raw tx it was journaled with (`rawSha256`, when the intent had one).
export interface AttemptView { txId: string; gen: number; state: AttemptState; eth?: EthIntent; sol?: SolIntent; btc?: BtcIntent; rawSha256?: string }
export interface TxView {
  copy: number; part: number; parts: number; attempts: AttemptView[]; state: 'open' | 'included' | 'failed' | 'stuck'
  landedId: string | null; block: string | null; fee: string | null; readback: boolean | null
}
export interface ChainState {
  phase: ChainPhase; reason: string | null; address: string | null; copy: number | null; attempt: number | null
  copiesIncluded: number; reassembled: Array<{ copy: number; ok: boolean }>; spent: string; txs: TxView[]
  openIntents: string[]; resume: { copy: number; nextPart: number } | null; stopRequested: boolean
  clawback: { txId: string; to: string; value: string; ok: boolean | null; landed: boolean } | null   // landed: CC-2a
  // Eminors: present (true) only while the chain's journaled `stopped` event says the lane key is EIP-7702-delegated (its `delegated: true`)
  // and the chain is not yet settled (CLAWED_BACK, DONE, SKIPPED); absent otherwise. Cleared by any later phase event that moves the chain on.
  delegated?: true
  // PF-S fix round 5 (R34-1; CC-15 addendum): present (true) only while the chain is stop-latched (see stopLatched above); absent otherwise.
  stopLatched?: true
  // PF-S fix round 6 (CC-15 addendum): present only while phase is STUCK — the base phase under the overlay (what the event gate judges
  // phase events on); absent otherwise. A JobState without it under STUCK reads as STUCK (fail closed).
  stuckBase?: ChainPhase
  // R79b (stop.ts): present only while the chain's base is STOPPED and its journaled `stopped` carried a code this build knows; absent
  // otherwise (a journal from before R79b, an unknown code: FINAL, fail closed). stopClassOf(ChainState) gives the class of the stop.
  stopCode?: StopCode
  // R79b (stop.ts): present only while the chain's base is STOPPED (phase STOPPED, or STUCK over a STOPPED base): stopClassOf(this chain).cls —
  // 'resumable' (vt job resume / the page's Resume may continue it) or 'final' (resume.final-stop: claw back or close). A missing or
  // unknown code, or a FINAL fact of the journal (readback not ok, a failed reassembly, a delegated key, a stuck or mark-failed attempt), is 'final'.
  stopClass?: StopClass
}
// Spend cap (R60; armed.caps[c], fixed at arm). Every signature on a chain checks spent + held + this signature's worst
// case <= nativeCap (engine gates/caps.ts; held = the worst case of every open intent).
// Claw-back (CC-1 note; ruling on the E2 report, 2026-10-09, consistent with MQ 7b): a claw-back's VALUE plus its
// worst-case FEE count against the REMAINING armed cap (nativeCap - spent - held; a bump or re-sign of the same family
// is held at the largest member, never summed). A claw-back whose value + fee does not fit is refused unless the
// operator types the exact amount (base units, as the over-cap arm confirmation does): a typed exact-amount override
// bound to that one claw-back (its value and destination), never a raised cap for the lane. Reducer `spent` stays fees
// only (the value is reported in ChainState.clawback.value; the engine's cap ledger adds a LANDED claw-back's value).
// CC-2a — the override's request shape: POST …/chains/:c/events with type 'clawback-intent' may carry
// `clawbackConfirm: { amount }` beside { gen, type, data } (EventAppendRequest below; never journaled). amount is a
// decimal base-unit string that must EQUAL value + worst-case fee of that intent exactly (eth: value + gas × maxFee;
// sol: value + sol.fee) — for an ETH bump or a SOL re-sign that is the lane's balance again, so one typed amount covers
// the family. The API (S2, guard arm.amount): refuses a claw-back intent whose value + worst-case fee exceeds
// nativeCap − spent unless clawbackConfirm is present and equal; refuses ANY clawbackConfirm that is not exactly
// value + fee (a typed amount that does not match what is signed), malformed (not decimal base units), or sent with
// another event type. The engine (gates/caps.ts reserveClawback) applies the same rule before signing.
export interface ClawbackConfirm { amount: string }
// POST /jobs/:id/chains/:c/events body (spec §5.2). clawbackConfirm only with type 'clawback-intent' (CC-2a).
export interface EventAppendRequest { gen: number; type: ExecEventType; data: Record<string, unknown>; clawbackConfirm?: ClawbackConfirm }
// ArmCap (CC-2b defines `planned`): nativeCap is the enforced cap in base units (decimal string). planned is the planned
// spend in the chain's native unit (ETH 18 decimals, SOL 9), a plain decimal rendered EXACTLY — never rounded (engine
// computeArmCaps: formatUnits). For an overCap chain the operator types it (confirm.amounts[c] === planned, core
// checkArmConfirm), and the API compares it EXACTLY in base units: the typed decimal, parsed without rounding (no more
// decimals than the chain has), must equal nativeCap (api arm.ts, arm.amount) — the number typed is the number enforced
// (I2; S2 review m5 compared 6 significant digits).
export interface ArmCap { nativeCap: string; usd: number; priceAt: number | null; overCap: boolean; planned: string }
export interface ArmRequest {
  chains: Chain[]; confirm: { typed: string | null; amounts: Partial<Record<Chain, string>> }
  caps: Partial<Record<Chain, ArmCap>>; countdownSec?: number; stagger?: [number, number]; sources?: Partial<Record<Chain, string>>
}
export interface ArmRecord {
  armedAt: number; releaseAt: number; countdownSec: number
  schedule: { order: Chain[]; offsetSec: Partial<Record<Chain, number>> }
  caps: Partial<Record<Chain, ArmCap>>; sources: Partial<Record<Chain, string>>
}
export interface JobState { phase: JobPhase; armed: ArmRecord | null; releaseAt: number | null; chains: Partial<Record<Chain, ChainState>>; seq: number; corrupt: string | null }
// A claw-back intent appears in LeaseGrant.openIntents with copy 0, part 0.
export interface OpenIntent { txId: string; gen: number; copy: number; part: number; attempt: number; eth?: EthIntent; sol?: SolIntent; btc?: BtcIntent }   // btc: CC-12
export interface LeaseGrant { gen: number; ttlMs: number; expiresAt: number; holder: Holder; openIntents: OpenIntent[] }
export interface LeaseView { holder: Holder; gen: number; expiresAt: number }
export interface Status {
  network: Network; networks: Partial<Record<Chain, string>>; mainnetSends: 'LOCKED' | 'ENABLED'; jobSends: 'LOCKED' | 'ENABLED'
  build: string; confined: true; legacyLatch: 'clear' | 'open'; serverNowMs: number
}
// identity[c].message: set when the check fails with a specific reason, e.g. checkForkDrift's
// "Amsterdam appears active on mainnet — update required" (contracts/gas.ts).
export interface RelayStatus { network: Network; build: string; confined: boolean; identity: Partial<Record<Chain, { ok: boolean; message?: string }>>; endpoints: Partial<Record<Chain, number>> }
export interface StackInfo { network: Network; up: boolean; pageUrl: string; build: string | null }
export interface ApiError { error: { guard: string; message: string } }
export interface ReceiptTx { copy: number; part: number; txId: string; attempts: number; block: string; fee: string; readback: boolean; links: Array<{ label: string; href: string; copyOnly: boolean }> }
export interface ReceiptChain {
  address: string; network: string; mode: Mode; phase: ChainPhase; copiesIncluded: number
  reassembled: Array<{ copy: number; ok: boolean }>; spent: string; clawback: { txId: string; to: string; value: string } | null; txs: ReceiptTx[]
}
export interface Receipt { format: 'vt-receipt/1'; jobId: string; name: string; network: Network; messageSha256: string; build: string; chains: Partial<Record<Chain, ReceiptChain>> }

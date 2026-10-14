// packages/core/src/contracts/executor.ts — the engine/executor seam (E3 implements; W3/C6 call). Task 0, verbatim, plus
// CC-2a: JournalClient.append's optional clawbackConfirm (the typed claw-back amount, types.ts claw-back note).
import type { Chain, Holder, LeaseGrant, JobDef, JobState, ArmRecord, Network, Status, RelayStatus, ClawbackConfirm } from './types.ts'
export interface LoadedKey { chain: Chain; address: string; network: Network | null /* from the backup (R71) */ }
export interface JournalClient {
  status(): Promise<Status>
  job(id: string): Promise<{ def: JobDef; state: JobState; seq: number; serverNowMs: number }>
  message(sha256: string): Promise<string>
  lease(id: string, chain: Chain, op: 'acquire' | 'renew' | 'release', holder: Holder, gen?: number): Promise<LeaseGrant>
  // o.clawbackConfirm (CC-2a): the operator's typed exact amount, sent beside a 'clawback-intent' only (types.ts note).
  append(id: string, chain: Chain, gen: number, type: string, data: Record<string, unknown>, o?: { clawbackConfirm?: ClawbackConfirm }): Promise<{ seq: number; ticket?: string }>
  ticket(id: string, chain: Chain, gen: number, txId: string): Promise<string>
  skip(id: string): Promise<{ releaseAt: number }>
  stream(id: string, from: number, on: (e: import('./types.ts').JournalEvent) => void): () => void
}
export interface RelayClient {
  status(): Promise<RelayStatus>
  rpc(chain: Chain, method: string, params: unknown[], o?: { ticket?: string; ep?: number }): Promise<unknown>
  // torRoles (M4a glue, S6 F1): the relay roles whose requests go through Tor. On local that is ['check', 'drand'] when the relay serves drand
  // (the Open lane; `isTor` is then the LAST drand IsTor check, null until drand is first used) and [] otherwise. Absent from an older relay.
  tor(): Promise<{ isTor: boolean | null; torRoles?: readonly string[] }>
  price(): Promise<{ fixture: boolean; source: string; prices: Record<'SOL' | 'ETH', { usd: number }> }>
}
export type RunOutcome = 'drained' | 'copies-done' | 'stopped' | 'clawed-back' | 'lease-lost' | 'failed'
export interface ChainRunView { phase: string; copy: number | null; part: number | null; parts: number | null; note: string; startsInMs: number | null
  // Efix3 (planE5 ruling C2): true once an ETH claw-back saw that the key is EIP-7702-delegated (the note then carries the warning
  // "this key is delegated (EIP-7702); someone holding the authorization may move funds — claw back now"). Optional: absent = false.
  delegated?: boolean }
export interface ExecutorDeps {
  journal: JournalClient; relay: RelayClient; clock: { now(): number; sleep(ms: number): Promise<void> }
  random: { int(maxExclusive: number): number }; onView?: (v: ChainRunView) => void
}
export interface Executor {
  start(): Promise<RunOutcome>; requestStop(): void; requestResume(o?: { tipCapGwei?: string; cuPriceCap?: number }): void
  skip(): Promise<void>; view(): ChainRunView
}
// ArmRecord is re-exported for executor implementers (startAt(armed, chain) lives in the job module, E1).
export type { ArmRecord }

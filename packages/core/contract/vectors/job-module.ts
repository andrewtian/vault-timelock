// The E1 job module as the vectors see it. The import is dynamic on purpose: before E1 lands, every vector test FAILS
// at run time (module not found) while packages/core still typechecks. At I1 the controller may switch to a static
// import (contract change). The interface is E1's produced list, verbatim from the plan.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { isRefusal } from '../../src/contracts/index.ts'
import type { ArmRecord, ArmRequest, Chain, ChainState, JobDef, JobState, JournalEvent, Network } from '../../src/contracts/index.ts'

export interface JobModule {
  canonicalJson(v: unknown): string
  sha256Hex(b: Uint8Array | string): string
  jobId(def: JobDef): string
  validateMessage(text: string): { bytes: number; sha256: string; warnings: Array<'hex64'> }
  normalizeJob(input: unknown, o: { network: Network; existing?: boolean }): { def: JobDef; text: string | null }
  assertNoSecretOrIp(s: string, field: string): void
  looksLikeIp(token: string): boolean
  validateEvent(type: string, data: unknown, by: string): void
  reduce(def: JobDef, events: readonly JournalEvent[]): JobState
  isChainTerminal(cs: ChainState): boolean
  drawSchedule(chains: readonly Chain[], range: readonly [number, number], randInt: (maxExclusive: number) => number): ArmRecord['schedule']
  startAt(armed: ArmRecord, chain: Chain): number
  checkArmConfirm(network: Network, req: ArmRequest): void
  // CC-2a: the typed claw-back amount (types.ts claw-back note); returns need = value + worst-case fee
  checkClawbackConfirm(state: JobState, chain: Chain, data: Record<string, unknown>, confirm?: unknown): bigint
}

const SPEC = new URL('../../src/job/index.ts', import.meta.url).href
export async function loadJobModule(): Promise<JobModule> {
  return (await import(SPEC)) as JobModule
}

export const fixture = (p: string): string => fileURLToPath(new URL(`../fixtures/${p}`, import.meta.url))
export const readJson = <T>(p: string): T => JSON.parse(readFileSync(fixture(p), 'utf8')) as T

// The refusal's guard id, null when fn returns; anything that is not a Refusal is rethrown.
export function guardOf(fn: () => unknown): string | null {
  try { fn() } catch (e) { if (isRefusal(e)) return e.guardId; throw e }
  return null
}

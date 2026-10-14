// cli/src/job/list.ts — `vt job list [--json]` (spec §5.2 GET /jobs, §8; plan Task C5): every job of this network's
// API, with its phase and each chain's phase (and reason). --json prints the API's body exactly.
import type { Chain, ChainPhase, JobPhase } from '@vault-timelock/core/contracts'
import { UsageError } from '../args.ts'
import type { JobIo } from './client.ts'
import { apiClient, emitJson, parseFlags, printLines } from './client.ts'

export interface JobListEntry { id: string; name: string; createdAt: number; phase: JobPhase; chains: Partial<Record<Chain, { phase: ChainPhase; reason: string | null }>> }
export interface JobList { jobs: JobListEntry[]; serverNowMs: number }

const USAGE = 'usage: vt job list [--json]'

const iso = (ms: unknown): string => (typeof ms === 'number' && Number.isFinite(ms) ? new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z') : '?')

export function renderList(l: JobList, network: string): string {
  if (!Array.isArray(l.jobs) || l.jobs.length === 0) return `no jobs on ${network}`
  return l.jobs.map((j) => {
    const chains = Object.entries(j.chains ?? {}).map(([c, s]) => `${c} ${s?.phase ?? '?'}${s?.reason ? ` (${s.reason})` : ''}`).join(', ')
    return `${j.id}  ${String(j.phase).padEnd(7)}  ${iso(j.createdAt)}  ${chains}  "${j.name}"`
  }).join('\n')
}

export async function listCommand(args: readonly string[], io: JobIo): Promise<number> {
  const { flags, pos } = parseFlags(args, { valued: [], bool: ['--json'], usage: USAGE })
  if (pos.length !== 0) throw new UsageError(USAGE)
  const r = await apiClient(io).json<JobList>('GET', '/jobs')
  if (flags.has('--json')) emitJson(io, r.text)
  else printLines(io, renderList(r.value, io.network))
  return 0
}

// cli/src/job/source.ts — `vt source list [--json]` and `vt source add <label>` (F12-1; spec §8; API Task S5): the CLI's
// twin of the job page's funding-source picker. A client command (the client sandbox, no /dev/tty): it calls GET /sources
// and POST /sources {label} of the network's API. A source is only a LABEL the operator picks for each try, so no typed
// confirmation. Sources are NEVER deleted; once one exists every `vt job arm` needs --source <chain>=<label>.
// The label is sent as typed: the API decides (a refused label comes back as its `source.label` guard, exit 2).
// --json prints the API's body exactly (list: { sources: [{ label, addedAt }] }; add: { label, addedAt }).
import { UsageError } from '../args.ts'
import type { JobIo } from './client.ts'
import { apiClient, emitJson, parseFlags, printLines } from './client.ts'

export const SOURCE_USAGE = 'usage: vt source list [--json] | vt source add <label>   (a label: lowercase letters, digits, hyphens; 1 to 24; never deleted)'
export interface SourceEntry { label: string; addedAt: number }

const iso = (ms: unknown): string => (typeof ms === 'number' && Number.isFinite(ms) ? new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z') : '?')

export function renderSources(list: { sources?: SourceEntry[] }, network: string): string {
  const s = Array.isArray(list.sources) ? list.sources : []
  if (s.length === 0) return `no funding sources on ${network} (vt source add <label>; once one exists, every vt job arm needs --source <chain>=<label>)`
  return s.map((x) => `${String(x.label).padEnd(24)}  added ${iso(x.addedAt)}`).join('\n')
}

export async function sourceCommand(argv: readonly string[], io: JobIo): Promise<number> {
  const [sub, ...rest] = argv
  if (sub === 'list') {
    const { flags, pos } = parseFlags(rest, { valued: [], bool: ['--json'], usage: SOURCE_USAGE })
    if (pos.length !== 0) throw new UsageError(SOURCE_USAGE)
    const r = await apiClient(io).json<{ sources?: SourceEntry[] }>('GET', '/sources')
    if (flags.has('--json')) emitJson(io, r.text)
    else printLines(io, renderSources(r.value, io.network))
    return 0
  }
  if (sub === 'add') {
    const { flags, pos } = parseFlags(rest, { valued: [], bool: ['--json'], usage: SOURCE_USAGE })
    if (pos.length !== 1) throw new UsageError(SOURCE_USAGE)
    const r = await apiClient(io).json<SourceEntry>('POST', '/sources', { label: pos[0] })
    if (flags.has('--json')) emitJson(io, r.text)
    else printLines(io, r.status === 201
      ? `added funding source "${r.value.label}" on ${io.network}; sources are never deleted, and every vt job arm now needs --source <chain>=<label>`
      : `funding source "${r.value.label}" already exists on ${io.network} (added ${iso(r.value.addedAt)}); nothing changed`)
    return 0
  }
  throw new UsageError(SOURCE_USAGE)
}

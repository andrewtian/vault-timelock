// api/src/sources.ts — funding sources and the per-text try ledger (spec §3.2, §5.4 check 8; R47; plan Task S5).
//
// A SOURCE is only a LABEL the operator declares ("railgun-eth", "pool-b", ...): the API never sees what funds from it.
//   GET  /sources          → 200 { sources: [{ label, addedAt }] }, oldest first
//   GET  /sources/tries/<messageSha256>  → 200 { labelsUsed: [label…] }: the labels that paid an earlier try of that text (sorted,
//                          each once). LABELS ONLY: no job id, time or chain, nothing of the funds. A text never armed → [].
//                          The page's "used for this message" marks read this, so they survive a reload (S5 / Wfix3 follow-up).
//   POST /sources {label}  → 201 { label, addedAt } for a new label, 200 for one already declared (idempotent)
//   source.label           a label that is not ^[a-z0-9][a-z0-9-]{0,23}$ (or the 64th+ label): refused
// Labels are never deleted: a label that paid an earlier try stays on record, so a try can never be re-linked by
// removing and re-adding a name. The file is <stateDir>/sources.json (0600, in the 0700 state directory).
//
// THE TRY LEDGER, <stateDir>/tries/<messageSha256>.json (0600): one entry per job that armed this text, with the label
// each of its chains was funded from. Arm (arm.ts) calls reserve() AFTER every other check passed and BEFORE the
// `armed` event is journaled: the entry is on disk (temp file + fsync + rename + directory fsync) before the ack. If
// the journal append then fails, the try stays on record and its labels stay spent (fail closed: a source is never
// reused for the same publication because a write half-failed). The same job arming again after such a crash replaces
// its own entry (a job id is one try; it cannot count as its own earlier try).
//
// reserve(), in order, once at least one source is declared (the sources of the request are required):
//   source.unknown    a chain being armed has no label in the request, or a label that is not declared; or, with no
//                     source declared at all, a request that names any
//   source.exhausted  every declared source already paid an earlier try of this same text: nothing is left to fund a
//                     new publication of it. Checked before reuse, so the fourth try of three sources says exhausted
//   source.reused     a label named here already paid an earlier try of this text (a label may fund several chains of
//                     the SAME try)
// A file that does not read back as exactly what this module writes (not a private regular file, bad JSON, wrong
// shape) is never used: reserve() and list() throw (a 500 api.internal), so arm fails closed.
import { closeSync, constants, fstatSync, fsyncSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { join } from 'node:path'
import type { Chain } from '@vault-timelock/core/contracts'
import { refuse } from 'vt-broadcast/src/guard.ts'
import { ensureDir } from 'vt-broadcast/src/lifecycle/paths.ts'

export const SOURCE_LABEL = /^[a-z0-9][a-z0-9-]{0,23}$/
export const MAX_SOURCES = 64
const HEX64 = /^[0-9a-f]{64}$/
const HEX16 = /^[0-9a-f]{16}$/

export interface Source { label: string; addedAt: number }
interface Try { jobId: string; at: number; sources: Partial<Record<Chain, string>> }
interface TryFile { format: 'vt-tries/1'; messageSha256: string; tries: Try[] }
interface SourceFile { format: 'vt-sources/1'; sources: Source[] }

export interface SourceStore {
  list(): Source[]
  add(label: unknown): { source: Source; created: boolean }
  // The labels that paid an earlier try of this text, sorted, each once (GET /sources/tries/<messageSha256>); [] for a text never
  // armed with a source. A ledger that does not read back as exactly what this module writes throws (a 500), as in reserve().
  triesLabels(messageSha256: string): string[]
  // The arm check (see above) and, when it passes, the durable try record. Returns the sources to journal in `armed`.
  reserve(o: { messageSha256: string; jobId: string; chains: readonly Chain[]; sources: Partial<Record<Chain, string>> | undefined }): Partial<Record<Chain, string>>
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)

function fsyncDir(dir: string): void {
  const fd = openSync(dir, constants.O_RDONLY)
  try { fsyncSync(fd) } finally { closeSync(fd) }
}

// Atomic and durable: a temp file beside the target, fsync, rename over it, fsync the directory.
function writeAtomic(dir: string, file: string, text: string): void {
  const tmp = `${file}.tmp.${process.pid}.${randomBytes(6).toString('hex')}`
  try {
    const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
    try {
      const bytes = Buffer.from(text, 'utf8')
      let off = 0
      while (off < bytes.length) {
        const w = writeSync(fd, bytes, off, bytes.length - off)
        if (!(w > 0)) throw new Error('the write made no progress')
        off += w
      }
      fsyncSync(fd)
    } finally {
      closeSync(fd)
    }
    renameSync(tmp, file)
  } catch (e) {
    try { unlinkSync(tmp) } catch { /* already gone */ }
    throw e
  }
  fsyncDir(dir)
}

// The parsed JSON of a private regular file, null when it does not exist; any other trouble throws (fail closed).
function readPrivate(file: string): unknown {
  let fd = -1
  try {
    fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW)
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw new Error('sources: a state file cannot be opened')
  }
  try {
    const st = fstatSync(fd)
    if (!st.isFile() || (st.mode & 0o077) !== 0 || st.size > 1 << 20) throw new Error('sources: a state file is not a private regular file')
    return JSON.parse(readFileSync(fd, 'utf8')) as unknown
  } finally {
    closeSync(fd)
  }
}

function parseSources(v: unknown): Source[] {
  const ok = v === null || (isObj(v) && v.format === 'vt-sources/1' && Array.isArray(v.sources) && Object.keys(v).length === 2
    && v.sources.length <= MAX_SOURCES
    && v.sources.every((s) => isObj(s) && Object.keys(s).length === 2 && typeof s.label === 'string' && SOURCE_LABEL.test(s.label) && Number.isSafeInteger(s.addedAt)))
  if (!ok) throw new Error('sources: sources.json is malformed')
  const list = v === null ? [] : (v as unknown as SourceFile).sources
  if (new Set(list.map((s) => s.label)).size !== list.length) throw new Error('sources: sources.json repeats a label')
  return list
}

function parseTries(v: unknown, sha: string): Try[] {
  const chain = (c: string): boolean => c === 'eth' || c === 'sol'
  const ok = v === null || (isObj(v) && v.format === 'vt-tries/1' && v.messageSha256 === sha && Array.isArray(v.tries) && Object.keys(v).length === 3
    && v.tries.every((t) => isObj(t) && Object.keys(t).length === 3 && typeof t.jobId === 'string' && HEX16.test(t.jobId) && Number.isSafeInteger(t.at)
      && isObj(t.sources) && Object.entries(t.sources).every(([c, l]) => chain(c) && typeof l === 'string' && SOURCE_LABEL.test(l))))
  if (!ok) throw new Error('sources: a try ledger is malformed')
  return v === null ? [] : (v as unknown as TryFile).tries
}

export function createSources(stateDir: string, o: { now: () => number }): SourceStore {
  const sourcesFile = join(stateDir, 'sources.json')
  const triesDir = join(stateDir, 'tries')
  const read = (): Source[] => parseSources(readPrivate(sourcesFile))

  return {
    list: read,

    add(label) {
      const cur = read()
      const have = typeof label === 'string' ? cur.find((s) => s.label === label) : undefined
      const labelOk = typeof label === 'string' && SOURCE_LABEL.test(label) && (have !== undefined || cur.length < MAX_SOURCES)
      if (!labelOk) refuse('source.label', `a source label is 1 to 24 characters: lowercase letters, digits and hyphens, starting with a letter or digit (at most ${MAX_SOURCES} labels, never deleted)`) // @guard:source.label
      const l = label as string
      if (have !== undefined) return { source: have, created: false }
      const source: Source = { label: l, addedAt: o.now() }
      ensureDir(stateDir)
      const file: SourceFile = { format: 'vt-sources/1', sources: [...cur, source] }
      writeAtomic(stateDir, sourcesFile, JSON.stringify(file) + '\n')
      return { source, created: true }
    },

    triesLabels(messageSha256) {
      if (!HEX64.test(messageSha256)) throw new Error('sources: not a digest')
      const used = parseTries(readPrivate(join(triesDir, `${messageSha256}.json`)), messageSha256).flatMap((t) => Object.values(t.sources))
      return [...new Set(used)].sort()
    },

    reserve({ messageSha256, jobId, chains, sources }) {
      if (!HEX64.test(messageSha256) || !HEX16.test(jobId)) throw new Error('sources: not a digest or job id')
      const declared = new Set(read().map((s) => s.label))
      const named = sources ?? {}
      const picked: Partial<Record<Chain, string>> = {}
      let known = declared.size > 0 || Object.keys(named).length === 0 // nothing declared: nothing may be named
      if (declared.size > 0) {
        for (const c of chains) {
          const l = named[c]
          if (typeof l === 'string' && declared.has(l)) picked[c] = l
          else known = false
        }
      }
      if (!known) refuse('source.unknown', 'every chain being armed needs a declared funding source (a label from GET /sources); with none declared, none may be named') // @guard:source.unknown
      if (declared.size === 0) return {}
      const file = join(triesDir, `${messageSha256}.json`)
      const earlier = parseTries(readPrivate(file), messageSha256).filter((t) => t.jobId !== jobId)
      const spent = new Set(earlier.flatMap((t) => Object.values(t.sources)))
      const room = [...declared].some((l) => !spent.has(l))
      if (!room) refuse('source.exhausted', 'every declared funding source already paid an earlier try of this text: declare another source') // @guard:source.exhausted
      const fresh = Object.values(picked).every((l) => !spent.has(l))
      if (!fresh) refuse('source.reused', 'that source already paid an earlier try of this same text: pick another (a source is never reused for the same publication)') // @guard:source.reused
      ensureDir(stateDir)
      ensureDir(triesDir)
      const out: TryFile = { format: 'vt-tries/1', messageSha256, tries: [...earlier, { jobId, at: o.now(), sources: picked }] }
      writeAtomic(triesDir, file, JSON.stringify(out) + '\n')
      return picked
    },
  }
}

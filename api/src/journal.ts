// api/src/journal.ts — the per-job append-only journal <stateDir>/jobs/<jobId>/journal.jsonl (spec §5.3).
//
// One JSON object per line, written as JSON.stringify in the key order v, seq, at, prev, chain, by, gen, type, data.
// prev = sha256 hex of the previous line's UTF-8 bytes (without its '\n'); '' at seq 0.
//
// Durability (intent before send): append() writes line + '\n' with one fd opened O_APPEND|O_CREAT|O_NOFOLLOW 0600,
// then fsyncs it (libuv uses F_FULLFSYNC on macOS), and only then resolves. Any write or fsync error rejects with
// journal.write and nothing is resolved, so the executor never gets an ack (and never sends). The file is cut back to
// its last good length, and the journal refuses every later append (journal.write) until the API restarts: after a
// failed fsync the state of the page cache is unknown, so nothing more is acknowledged from this process. A newly
// created journal file also fsyncs its directory and the jobs directory.
//
// Load (recovery):
//   · a trailing fragment without '\n' was never acknowledged: it is cut off and `note {text: 'recovered tail'}` is
//     journaled (the next seq continues from the last complete line);
//   · a line that is not UTF-8, not JSON, not exactly the event shape and key order, not canonical (re-serialising it
//     must give the same bytes), out of seq order, or whose prev is not the previous line's hash makes the journal
//     corrupt: corrupt() names the line, all() holds the events before it, and every append refuses journal.corrupt.
//     A journal file that is a symlink, not a regular file, or readable by group or others is corrupt too. A corrupt
//     journal is never modified.
//   · Residual: the hash chain links each line to the one before it, so a change inside the LAST line alone is only
//     caught when it breaks the shape, the JSON or the canonical form.
//
// The fs seam (tests only, NODE_ENV=test, else api.test-only) replaces the write path: writeSync, fsyncSync and
// ftruncateSync. Events returned by append() and all() are deeply frozen.
import { closeSync, constants, fstatSync, fsyncSync, ftruncateSync, lstatSync, openSync, readFileSync, writeSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, join } from 'node:path'
import type { ApiEventType, ExecEventType, JournalEvent } from '@vault-timelock/core/contracts'
import { refuse } from 'vt-broadcast/src/guard.ts'
import { ensureDir } from 'vt-broadcast/src/lifecycle/paths.ts'
import { assertTestMode, systemClock } from './clock.ts'
import type { Clock } from './clock.ts'

export interface JournalFs {
  writeSync(fd: number, buf: Uint8Array, offset: number, length: number): number
  fsyncSync(fd: number): void
  ftruncateSync(fd: number, len: number): void
}
export type JournalInput = Omit<JournalEvent, 'v' | 'seq' | 'at' | 'prev'>
// What rides beside an append without being journaled: the operator's typed claw-back amount (CC-2a), which only the job
// service's gate reads (jobs.ts); the raw journal ignores it.
export interface AppendOptions { clawbackConfirm?: unknown }
export interface Journal {
  append(e: JournalInput, o?: AppendOptions): Promise<JournalEvent>
  all(): readonly JournalEvent[]
  corrupt(): string | null
  // Appends can still be acknowledged: not corrupt, no write or fsync failure in this process, not closed (S1 review m4).
  writable(): boolean
  // Called synchronously after each successful append (after the fsync), in append order.
  subscribe(fn: (e: JournalEvent) => void): () => void
  close(): void
}

export const JOURNAL_FILE = 'journal.jsonl'
export const API_EVENT_TYPES = ['created', 'armed', 'skip', 'stop-requested', 'resume-requested', 'close', 'resolved',
  'lease-acquired', 'lease-released', 'lease-expired', 'stopped', 'note'] as const satisfies readonly ApiEventType[]
export const EXEC_EVENT_TYPES = ['key-loaded', 'funds', 'reconcile', 'copy-built', 'intent', 'sent', 'replaced', 'included',
  'readback', 'reassembled', 'paused', 'resumed', 'drained', 'copies-done', 'stopped', 'clawback-intent', 'clawback-sent',
  'clawback-included', 'clawback-readback', 'clawback-failed', 'stuck', 'note'] as const satisfies readonly ExecEventType[]
// Compile-time: the lists name every member of the contract unions.
type Missing<U, L extends readonly unknown[]> = Exclude<U, L[number]>
const listsComplete: [Missing<ApiEventType, typeof API_EVENT_TYPES>, Missing<ExecEventType, typeof EXEC_EVENT_TYPES>] extends [never, never] ? true : false = true
void listsComplete

const TYPES: ReadonlySet<string> = new Set<string>([...API_EVENT_TYPES, ...EXEC_EVENT_TYPES])
const BY: ReadonlySet<unknown> = new Set(['browser', 'cli', 'api', 'operator'])
const KEY_ORDER = 'v,seq,at,prev,chain,by,gen,type,data'
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
const realFs: JournalFs = {
  writeSync: (fd, buf, offset, length) => writeSync(fd, buf, offset, length),
  fsyncSync: (fd) => fsyncSync(fd),
  ftruncateSync: (fd, len) => ftruncateSync(fd, len),
}

export const sha256Hex = (b: Uint8Array | string): string => createHash('sha256').update(b).digest('hex')
const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype

function deepFreeze<T>(v: T): T {
  if (typeof v === 'object' && v !== null && !Object.isFrozen(v)) {
    for (const k of Object.keys(v)) deepFreeze((v as Record<string, unknown>)[k])
    Object.freeze(v)
  }
  return v
}

// Why `o` is not the event at `seq` after a line hashing to `prev` (null when it is).
function shapeProblem(o: unknown, seq: number, prev: string): string | null {
  if (!isPlainObject(o) || Object.keys(o).join(',') !== KEY_ORDER) return 'not the event shape'
  if (o.v !== 1) return 'unknown version'
  if (o.seq !== seq) return 'seq out of order'
  if (o.prev !== prev) return 'bad hash link'
  if (!Number.isSafeInteger(o.at) || (o.at as number) < 0) return 'bad time'
  if (!(o.chain === null || o.chain === 'eth' || o.chain === 'sol' || o.chain === 'btc')) return 'bad chain'
  if (!BY.has(o.by)) return 'bad writer'
  if (!(o.gen === null || (Number.isSafeInteger(o.gen) && (o.gen as number) >= 1))) return 'bad generation'
  if (typeof o.type !== 'string' || !TYPES.has(o.type)) return 'unknown type'
  if (!isPlainObject(o.data)) return 'bad data'
  return null
}

function lineProblem(line: Uint8Array, seq: number, prev: string): { event: JournalEvent } | { problem: string } {
  let text: string
  let parsed: unknown
  try { text = UTF8.decode(line) } catch { return { problem: 'not UTF-8' } }
  try { parsed = JSON.parse(text) } catch { return { problem: 'not JSON' } }
  const p = shapeProblem(parsed, seq, prev)
  if (p !== null) return { problem: p }
  if (JSON.stringify(parsed) !== text) return { problem: 'not in canonical form' }
  return { event: parsed as JournalEvent }
}

function fsyncDir(fs: JournalFs, dir: string): void {
  const fd = openSync(dir, constants.O_RDONLY)
  try { fs.fsyncSync(fd) } finally { closeSync(fd) }
}

export function openJournal(dir: string, o: { clock?: Clock; fs?: JournalFs } = {}): Journal {
  if (o.fs !== undefined) assertTestMode()
  const fs = o.fs ?? realFs
  const clock = o.clock ?? systemClock
  ensureDir(dir)
  const file = join(dir, JOURNAL_FILE)
  let existed = true
  try { lstatSync(file) } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e
    existed = false
  }

  const events: JournalEvent[] = []
  const listeners = new Set<(e: JournalEvent) => void>()
  let corruptReason: string | null = null
  let poisoned = false // a write or fsync failed in this process: nothing more is acknowledged
  let lastHash = ''
  let size = 0
  let fd = -1
  try {
    fd = openSync(file, constants.O_RDWR | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW, 0o600)
  } catch {
    corruptReason = 'the journal file cannot be opened as a regular file'
  }

  // Writes one event; refuses journal.corrupt / journal.write. Synchronous, so appends are serialized per journal.
  const write = (input: JournalInput): JournalEvent => {
    if (corruptReason !== null) refuse('journal.corrupt', 'this job journal is corrupt: nothing more is written to it') // @guard:journal.corrupt
    const draft = { v: 1, seq: events.length, at: clock.now(), prev: lastHash, chain: input.chain, by: input.by, gen: input.gen, type: input.type, data: input.data }
    const line = JSON.stringify(draft)
    const checked = lineProblem(Buffer.from(line, 'utf8'), draft.seq, lastHash)
    if (!('event' in checked)) throw new Error(`journal: refusing to write an event that would not load back (${checked.problem})`)
    const bytes = Buffer.from(`${line}\n`, 'utf8')
    let ok = !poisoned && fd >= 0
    if (ok) {
      try {
        let off = 0
        while (off < bytes.length) {
          const n = fs.writeSync(fd, bytes, off, bytes.length - off)
          if (!(n > 0)) throw new Error('the write made no progress')
          off += n
        }
        fs.fsyncSync(fd)
      } catch {
        ok = false
        poisoned = true
        try { fs.ftruncateSync(fd, size); fs.fsyncSync(fd) } catch { /* the load-time checks still apply */ }
      }
    }
    if (!ok) refuse('journal.write', 'the journal write or fsync failed: the event was not recorded and nothing was acknowledged') // @guard:journal.write
    size += bytes.length
    lastHash = sha256Hex(bytes.subarray(0, bytes.length - 1))
    const event = deepFreeze(checked.event)
    events.push(event)
    for (const fn of listeners) {
      try { fn(event) } catch { /* a listener never affects the append */ }
    }
    return event
  }

  if (fd >= 0) {
    const st = fstatSync(fd)
    if (!st.isFile() || (st.mode & 0o077) !== 0) corruptReason = 'the journal file is not a private (0600) regular file'
    else {
      if (!existed) {
        try { fsyncDir(fs, dir); fsyncDir(fs, dirname(dir)) } catch { poisoned = true }
      }
      const buf = readFileSync(fd)
      const complete = buf.lastIndexOf(0x0a) + 1
      let off = 0
      while (off < complete) {
        const nl = buf.indexOf(0x0a, off)
        const line = buf.subarray(off, nl)
        const r = lineProblem(line, events.length, lastHash)
        if (!('event' in r)) {
          corruptReason = `line ${events.length + 1}: ${r.problem}`
          break
        }
        events.push(deepFreeze(r.event))
        lastHash = sha256Hex(line)
        off = nl + 1
      }
      size = buf.length
      if (corruptReason === null && complete < buf.length) {
        // A trailing fragment was never acknowledged: cut it off, then say so in the journal.
        try {
          fs.ftruncateSync(fd, complete)
          fs.fsyncSync(fd)
          size = complete
        } catch {
          poisoned = true
        }
        try { write({ chain: null, by: 'api', gen: null, type: 'note', data: { text: 'recovered tail' } }) } catch { /* poisoned: appends refuse */ }
      }
    }
  }

  return {
    append: async (e) => write(e),
    all: () => events.slice(),
    corrupt: () => corruptReason,
    writable: () => corruptReason === null && !poisoned && fd >= 0,
    subscribe(fn) {
      listeners.add(fn)
      return () => { listeners.delete(fn) }
    },
    close() {
      if (fd >= 0) closeSync(fd)
      fd = -1
      poisoned = true
    },
  }
}

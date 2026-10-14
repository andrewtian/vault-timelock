// Atomic JSON state with compare-and-swap semantics (spec C 6.2).
//   $OUT/lifecycle/<kind>/<id>.json  (0600)  =  { rev, value, updatedAt }
// update(): per-file lock -> read -> fn -> write <file>.tmp.<pid>.<rand> + fsync -> rename -> fsync(dir) -> unlock.
// rev increases by exactly 1.
// Lock: a directory `<file>.lock` that is built COMPLETELY first (`<file>.lock.new.<token>` containing `owner`,
// the token `<pid>.<random hex>`) and then published with one rename(). A published lock therefore always
// has a non-empty owner, and rename() onto an existing non-empty directory fails (ENOTEMPTY): that is "held".
// Release is token-checked: only the holder's own token removes the lock (rename away, verify, remove);
// if the lock is no longer ours the (already committed) update reports store.lock-lost.
// A lock dir older than staleLockMs whose owner is dead is stale and may be broken. "Dead" is only: the owner token's
// pid is not alive, or the owner file is missing (ENOENT), empty or not a token. Any other read error is NOT dead: a
// corrupt lock (owner is a directory, lock path is a file) is refused as store.lock-corrupt, and a transient error
// (EMFILE, EIO) propagates. A break is informational (`store.stale-lock-broken <kind>/<id>` on stderr, never file
// contents), not a refusal. A live owner is never displaced, however old its lock: a waiter gets store.lock-timeout,
// which names the lock dir and the owner's pid (the pid only, never file contents). Residuals (documented, not
// eliminated): (1) pid reuse: a dead owner whose pid now belongs to an unrelated live process looks alive, so the
// lock stays held until that process exits or an operator removes the lock dir by hand; (2) crashed breaker: a
// `.break` left by a dead breaker is aged out (old AND owner dead), and only that age-out can race with a new
// breaker, so two breakers may overlap. The identity checks still never delete a live lock, but in the worst
// interleaving a live lock is moved aside and cannot be put back: two holders overlap, and the displaced one reports
// store.lock-lost (its update is committed).
// Values never contain keys or passphrases: that is the caller's job (see assertNoSecretsInStore in the tests).
// Scope: single host, single PID namespace (liveness is kill(pid, 0)), local filesystem. NOT FAIR across
// processes: a process looping update() on one id can starve others, so fold a multi-step transition into ONE
// fn. As a mitigation each Store waits FAIR_GAP_MS after its own last release of a file before its next first
// attempt (longer than a waiter's maximum backoff). Callers not in a burst pay nothing.
// ★ Tests may shorten that gap (0..FAIR_GAP_MS) only through the option fairGapMs, which refuses store.fair-gap
//   unless NODE_ENV=test (Task P1, the keystore work factor's pattern: bin/vt-broadcast's env -i never passes
//   NODE_ENV, so the CLI can't reach it). Only tests that do not test fairness use it; the fairness tests keep 60 ms.
// Stale-lock breaking: breakers are serialized by `<lock>.break`, itself a token-owned published directory that
// is aged out only if old AND its owner pid is dead. Under it we re-check age, dead owner and the lock's
// identity (inode + birthtime), rename the lock away, verify the identity again, and delete it. If the moved
// directory turns out not to be the one we checked, we try to put it back and keep waiting. The owner token is
// only trusted if the lock's identity is unchanged after reading it (a release/re-publish in between is retried).
import {
  closeSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, unlinkSync, writeFileSync, writeSync,
} from 'node:fs'
import { randomBytes } from 'node:crypto'
import { performance } from 'node:perf_hooks'
import { basename, dirname, join, relative } from 'node:path'
import { refuse } from '../guard.ts'
import { systemClock } from './clock.ts'
import type { Clock } from './clock.ts'
import { checkPrivateDir, ensureDir, lifecycleDir } from './paths.ts'

// trigger + latch: the trigger latch (Task T1, B §6.6): lifecycle/trigger/<id>.json and the one lifecycle/latch/trigger.json.
export type Kind = 'reserve' | 'job' | 'intent' | 'trigger' | 'latch'
const KINDS: readonly string[] = ['reserve', 'job', 'intent', 'trigger', 'latch']
const ID = /^[a-z0-9][a-z0-9-]{0,63}$/
const FAIR_GAP_MS = 60
const TOKEN = /^([1-9][0-9]{0,9})\.[0-9a-f]{16}$/
const FILE = /^([a-z0-9][a-z0-9-]{0,63})\.json$/

export interface StoreOptions {
  lockTimeoutMs?: number // default 5000
  staleLockMs?: number // default 60000
  clock?: Clock
  log?: (line: string) => void // default: stderr
  beforeRename?: () => void // test seam: runs after the tmp file is durable, before the rename
  afterLockStat?: (lock: string) => void // test seam: between the breaker's lstat of the lock and its owner read
  afterBuild?: (built: string, target: string) => void // test seam: lock fully built, not yet published
  afterBreakCheck?: (lock: string) => void // test seam: between the breaker's re-check and its rename
  beforeWait?: (ms: number, left: number) => void // test seam: a waiter's backoff, just before it sleeps ms (left = ms to the deadline)
  fairGapMs?: number // tests only (NODE_ENV=test), 0..FAIR_GAP_MS; production is FAIR_GAP_MS
}
export interface Rev<T> { rev: number; value: T }
export interface Store {
  read<T>(kind: Kind, id: string): Promise<Rev<T> | undefined>
  update<T>(kind: Kind, id: string, fn: (cur?: T) => T): Promise<Rev<T>>
  list(kind: Kind): Promise<string[]>
}

const sleep = (ms: number) => new Promise<void>((res) => setTimeout(res, ms))
const errCode = (e: unknown) => (e as NodeJS.ErrnoException).code

function pidAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true } catch (e) { return errCode(e) !== 'ESRCH' } // EPERM: exists
}
const lockName = (p: string) => `${basename(dirname(p))}/${basename(p)}` // <kind>/<name>: no $OUT, no contents
// The owner token; '' (reads as dead) only if the owner file is missing (ENOENT) or empty. A corrupt lock is
// refused; any other read error propagates.
function readOwner(lock: string): string {
  try { return readFileSync(join(lock, 'owner'), 'utf8').trim() } catch (e) {
    if (errCode(e) === 'ENOENT') return ''
    const sane = errCode(e) !== 'EISDIR' && errCode(e) !== 'ENOTDIR' // owner is a directory / lock path is a file
    if (!sane) refuse('store.lock-corrupt', `${lockName(lock)} is corrupt (not a directory holding an owner file); remove it by hand`) // @guard:store.lock-corrupt
    throw e // a transient EMFILE/EIO must not make a live lock look dead
  }
}

function fsyncDir(dir: string): void {
  const fd = openSync(dir, 'r')
  try { fsyncSync(fd) } finally { closeSync(fd) }
}

export function createStore(out: string, opts: StoreOptions = {}): Store {
  const g = opts.fairGapMs
  const okGap = g === undefined || (process.env.NODE_ENV === 'test' && Number.isInteger(g) && g >= 0 && g <= FAIR_GAP_MS)
  if (!okGap) refuse('store.fair-gap', `the store's fairness gap is ${FAIR_GAP_MS} ms; a shorter one (0..${FAIR_GAP_MS}) is a test-only option that needs NODE_ENV=test`) // @guard:store.fair-gap
  const fairGapMs = g ?? FAIR_GAP_MS
  const lockTimeoutMs = opts.lockTimeoutMs ?? 5000
  const staleLockMs = opts.staleLockMs ?? 60_000
  const clock = opts.clock ?? systemClock
  const log = opts.log ?? ((line: string) => { process.stderr.write(line + '\n') })

  function check(kind: string, id?: string): void {
    const okKind = KINDS.includes(kind)
    if (!okKind) refuse('store.kind', 'kind must be reserve, job, intent, trigger or latch') // @guard:store.kind
    if (id === undefined) return
    const okId = typeof id === 'string' && ID.test(id)
    if (!okId) refuse('store.id', 'id must match ^[a-z0-9][a-z0-9-]{0,63}$') // @guard:store.id
  }
  const kindDir = (kind: Kind) => join(lifecycleDir(out), kind)

  function parse<T>(file: string, text: string): Rev<T> {
    let v: unknown
    try { v = JSON.parse(text) } catch { v = undefined }
    const o = v as { rev?: unknown; value?: unknown; updatedAt?: unknown } | null | undefined
    const ok = typeof o === 'object' && o !== null && !Array.isArray(o)
      && Number.isSafeInteger(o.rev) && (o.rev as number) >= 1 && 'value' in o && typeof o.updatedAt === 'number'
    if (!ok) refuse('store.corrupt', `${relative(out, file)} is not a valid state file`) // @guard:store.corrupt
    return { rev: (o as { rev: number }).rev, value: (o as { value: T }).value }
  }

  function readFile<T>(file: string): Rev<T> | undefined {
    let text: string
    try { text = readFileSync(file, 'utf8') } catch (e) {
      if (errCode(e) === 'ENOENT') return undefined
      throw e
    }
    return parse<T>(file, text)
  }

  const identity = (st: { ino: number; birthtimeMs: number }) => `${st.ino}:${st.birthtimeMs}`
  const newToken = () => `${process.pid}.${randomBytes(8).toString('hex')}`
  const exists = (p: string) => { try { lstatSync(p); return true } catch (e) { if (errCode(e) === 'ENOENT') return false; throw e } }
  const tokenAlive = (tok: string) => { const m = TOKEN.exec(tok); return m !== null && pidAlive(Number(m[1])) }

  // Build `target` completely (owner inside), then publish it with one rename. undefined = held.
  function publishDir(target: string): string | undefined {
    if (exists(target)) return undefined // also covers an (impossible for us) empty dir that rename would replace
    const token = newToken()
    const tmp = `${target}.new.${token}`
    mkdirSync(tmp, { mode: 0o700 })
    try {
      writeFileSync(join(tmp, 'owner'), token, { mode: 0o600 })
      opts.afterBuild?.(tmp, target)
      renameSync(tmp, target)
      return token
    } catch (e) {
      rmSync(tmp, { recursive: true, force: true })
      if (errCode(e) === 'ENOTEMPTY' || errCode(e) === 'EEXIST') return undefined
      throw e
    }
  }

  // Remove `target` only if its owner is still `token`: rename away, verify, delete. Never plain rm by path.
  // 'gone' = absent; 'lost' = owned by someone else (left in place / restored).
  function removeDir(target: string, token: string): 'ok' | 'gone' | 'lost' {
    if (readOwner(target) !== token) return exists(target) ? 'lost' : 'gone'
    const moved = `${target}.rm.${newToken()}`
    try { renameSync(target, moved) } catch (e) {
      if (errCode(e) === 'ENOENT') return 'gone'
      throw e
    }
    if (readOwner(moved) !== token) { // swapped under us: put it back if the name is free
      try { renameSync(moved, target) } catch { /* the name is taken: leave it aside for the age-out sweep */ }
      return 'lost'
    }
    rmSync(moved, { recursive: true, force: true })
    return 'ok'
  }

  // Drop dead-pid leftovers (`.new.<token>`, `.rm.<token>`) around a lock. Called under the break lock.
  function sweepLockLeftovers(lock: string): void {
    const dir = dirname(lock), base = basename(lock)
    const re = new RegExp(`^${base.replace(/[.]/g, '\\.')}(?:\\.break)?\\.(?:new|rm)\\.(.+)$`)
    for (const name of readdirSync(dir)) {
      const m = re.exec(name)
      if (m !== null && TOKEN.test(m[1]) && !tokenAlive(m[1])) rmSync(join(dir, name), { recursive: true, force: true })
    }
  }

  // True: the lock is gone (broken by us or someone else), retry at once. False: keep waiting.
  function tryBreakStale(lock: string, label: string): boolean {
    const brk = lock + '.break'
    const old = (mtimeMs: number) => Date.now() - mtimeMs > staleLockMs
    try { if (!old(lstatSync(lock).mtimeMs)) return false } catch (e) { // only take .break for an old lock
      if (errCode(e) === 'ENOENT') return true
      throw e
    }
    const mine = publishDir(brk)
    if (mine === undefined) {
      // someone is breaking; age the marker out only if it is old AND its owner is dead
      let st
      try { st = lstatSync(brk) } catch { return false }
      const tok = readOwner(brk)
      if (old(st.mtimeMs) && !tokenAlive(tok)) removeDir(brk, tok)
      return false
    }
    try {
      sweepLockLeftovers(lock)
      let st
      try { st = lstatSync(lock) } catch (e) {
        if (errCode(e) === 'ENOENT') return true
        throw e
      }
      if (!old(st.mtimeMs)) return false // young
      opts.afterLockStat?.(lock)
      const tok = readOwner(lock)
      let st2
      try { st2 = lstatSync(lock) } catch (e) {
        if (errCode(e) === 'ENOENT') return true // released meanwhile
        throw e
      }
      if (identity(st2) !== identity(st)) return false // not the dir the token came from: retry
      if (tokenAlive(tok)) return false
      opts.afterBreakCheck?.(lock)
      const moved = `${lock}.rm.${newToken()}`
      try { renameSync(lock, moved) } catch (e) {
        if (errCode(e) === 'ENOENT') return true // already broken by someone else
        throw e
      }
      if (identity(lstatSync(moved)) !== identity(st)) { // not the lock we checked: restore it, keep waiting
        try { renameSync(moved, lock) } catch { /* the name is taken: leave it aside */ }
        return false
      }
      rmSync(moved, { recursive: true, force: true })
      log(`store.stale-lock-broken ${label}`)
      return true
    } finally { removeDir(brk, mine) }
  }

  const lastRelease = new Map<string, number>()
  async function acquire(file: string, label: string): Promise<string> {
    const lock = file + '.lock'
    const last = lastRelease.get(file)
    if (last !== undefined) { const w = last + fairGapMs - performance.now(); if (w > 0) await sleep(w) }
    const deadline = performance.now() + lockTimeoutMs // after the gap, so an uncontended update never times out on it
    let delay = 1
    for (;;) {
      const token = publishDir(lock)
      if (token !== undefined) return token
      const broke = tryBreakStale(lock, label)
      const left = deadline - performance.now()
      if (left <= 0) { // out of time: after a break, one last attempt; otherwise the attempt above was the final one
        if (broke) { const t = publishDir(lock); if (t !== undefined) return t }
        break
      }
      if (broke) continue
      const ms = Math.min(left, delay + Math.floor(Math.random() * delay)) // contention jitter only
      opts.beforeWait?.(ms, left)
      await sleep(ms)
      delay = Math.min(delay * 2, 25)
    }
    // Name the lock dir and its owner's pid (parsed from the token: the pid only, never file contents), so an
    // operator can check that pid and clear a pid-reuse wedge by hand.
    let tok = ''
    try { tok = readOwner(lock) } catch { /* corrupt or unreadable: the owner is reported as unknown */ }
    const pid = TOKEN.exec(tok)?.[1]
    const who = pid === undefined ? 'an unknown owner' : `pid ${pid}`
    const acquired = false
    if (!acquired) refuse('store.lock-timeout', `could not lock ${label} within ${lockTimeoutMs} ms: ${lockName(lock)} is held by ${who} or being broken; if that is not a running vault-timelock process (pid reuse), remove that directory by hand`) // @guard:store.lock-timeout
    throw new Error('unreachable')
  }

  // Under the lock: drop tmp files left by writers that died (owner pid dead).
  function sweepTmp(dir: string, id: string): void {
    const prefix = `${id}.json.tmp.`
    for (const name of readdirSync(dir)) {
      if (!name.startsWith(prefix)) continue
      const pid = Number(name.slice(prefix.length).split('.')[0])
      if (Number.isInteger(pid) && pid > 0 && !pidAlive(pid)) { try { unlinkSync(join(dir, name)) } catch { /* gone */ } }
    }
  }

  function writeAtomic(dir: string, file: string, data: string): void {
    const tmp = `${file}.tmp.${process.pid}.${randomBytes(6).toString('hex')}`
    try {
      const fd = openSync(tmp, 'wx', 0o600)
      try { writeSync(fd, data); fsyncSync(fd) } finally { closeSync(fd) }
      opts.beforeRename?.()
      renameSync(tmp, file)
    } catch (e) {
      try { unlinkSync(tmp) } catch { /* already gone */ }
      throw e
    }
    fsyncDir(dir)
  }

  return {
    async read<T>(kind: Kind, id: string) {
      check(kind, id)
      checkPrivateDir(lifecycleDir(out), out)
      checkPrivateDir(kindDir(kind), out)
      return readFile<T>(join(kindDir(kind), `${id}.json`))
    },

    async update<T>(kind: Kind, id: string, fn: (cur?: T) => T) {
      check(kind, id)
      ensureDir(lifecycleDir(out), out)
      ensureDir(kindDir(kind), out)
      const dir = kindDir(kind)
      const file = join(dir, `${id}.json`)
      const token = await acquire(file, `${kind}/${id}`)
      const lock = file + '.lock'
      let result: Rev<T>
      try {
        sweepTmp(dir, id)
        const cur = readFile<T>(file)
        const next = fn(cur?.value)
        const okValue = next !== undefined
        if (!okValue) refuse('store.value', 'update fn must return a value') // @guard:store.value
        const rev = (cur?.rev ?? 0) + 1
        writeAtomic(dir, file, JSON.stringify({ rev, value: next, updatedAt: clock.now() }) + '\n')
        result = { rev, value: next }
      } catch (e) {
        try { removeDir(lock, token) } catch { /* the original error wins */ }
        lastRelease.set(file, performance.now())
        throw e
      }
      const released = removeDir(lock, token)
      lastRelease.set(file, performance.now())
      const kept = released === 'ok' // 'gone' (swapped away and released by someone else) is lost too
      // the update is already committed (rename); report that the lock was taken from us, do not undo
      if (!kept) refuse('store.lock-lost', `the lock on ${kind}/${id} was taken over while held; the update was committed`) // @guard:store.lock-lost
      return result
    },

    async list(kind: Kind) {
      check(kind)
      checkPrivateDir(lifecycleDir(out), out)
      if (!checkPrivateDir(kindDir(kind), out)) return []
      const rows: { id: string; createdAt?: number }[] = []
      for (const name of readdirSync(kindDir(kind))) {
        const m = FILE.exec(name)
        if (m === null) continue
        const cur = readFile<{ createdAt?: unknown } | null>(join(kindDir(kind), name))
        const c = cur?.value?.createdAt
        rows.push({ id: m[1], createdAt: typeof c === 'number' && Number.isFinite(c) ? c : undefined })
      }
      rows.sort((a, b) => {
        if (a.createdAt !== undefined && b.createdAt !== undefined && a.createdAt !== b.createdAt) return a.createdAt - b.createdAt
        if ((a.createdAt === undefined) !== (b.createdAt === undefined)) return a.createdAt === undefined ? 1 : -1
        return a.id < b.id ? -1 : a.id > b.id ? 1 : 0
      })
      return rows.map((r) => r.id)
    },
  }
}

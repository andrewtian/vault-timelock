// api/src/privacycash-ledger.ts — the relay's DURABLE withdrawal ledger for the Privacy Cash proxy (S7 fix round 2, I-1).
// <relay state dir>/privacycash-withdrawals.jsonl, append-only, one JSON object per line, 0600, fsynced BEFORE a withdrawal
// is forwarded. It does two jobs with one line:
//   · single use: a withdrawal authorization carries a nonce; the nonce is burned by its reserve line and stays burned for
//     ever (a restart reloads the file, so a replay after a restart is refused). Entries are never dropped, so a nonce
//     outlives its expiry.
//   · a cumulative per-lane allowance, with the semantics of the spend-cap ledger (api/src/ledger.ts, core CapLedger):
//     the amount is RESERVED before forwarding and the reservation is released ONLY on a proven failure (an outcome that
//     shows the relayer never accepted it: 403/429/451 or a SOCKS failure). An ambiguous result (timeout, 5xx, reset, a
//     rejected status, an unreadable answer) stays reserved; a 200 turns it into spent. The check is
//         reserved + spent + new ≤ the lane's allowance        (allowance: MAC'd in the authorization)
//     with the whole check-and-set synchronous (no await between the check, the in-memory set and the fsynced line), so two
//     concurrent withdrawals cannot both pass.
// Fail closed: a ledger that is missing (no state dir), unreadable, corrupt (bad line, bad transition, wrong mode, symlink),
// or whose append/fsync fails refuses every withdrawal (relay.pc-ledger); after a failed write nothing more is acknowledged
// by this process. A trailing fragment without a newline was never acknowledged (nothing was forwarded for it): it is cut off.
// Lines: {"v":1,"t":"reserve","n","lane","job","try","h","e","amount","allowance","exp","at"} | {"v":1,"t":"spent","n","sig"} |
//        {"v":1,"t":"release","n"} | {"v":1,"t":"reconcile","n","why"} | {"v":1,"t":"resolved","n","as"[,"sig"]}.
//        amount = |extAmount| + fee in lamports; e = the withdrawal's first encrypted output (lower hex), the key the
//        /utxos/check gate looks up (Sfix-PC item 5); sig = the withdrawal signature the relayer answered with.
// Sfix-PC additions:
//   · ONE process per state dir (N-2): an exclusive pid lock file (privacycash-withdrawals.lock, the API's takeLock
//     rules) is taken at open and released by close(); a second relay on the same dir is refused relay.pc-ledger-lock.
//   · The reserve line is written and fsynced through the `io` seam (N-1), so a test can pin write → fsync → forward.
//   · A 200 settles to `spent` only WITH a valid signature (recorded). Every other outcome that leaves the amount
//     reserved but is not a proven refusal (a 4xx/5xx status the relayer answered with, a 200 without a signature or in
//     the wrong form, an ambiguous transport result) is FLAGGED for reconciliation: the amount stays reserved (it counts
//     against the allowance exactly as before), the entry is listed by reconciling(), and an operator resolves it
//     (resolve(nonce, 'spent' | 'released')) once the chain / the relayer has been checked (M-6 / N-3).
import { closeSync, constants, fstatSync, fsyncSync, ftruncateSync, lstatSync, openSync, readFileSync, writeSync } from 'node:fs'
import { join } from 'node:path'
import { isRefusal } from '@vault-timelock/core/contracts'
import { refuse } from 'vt-broadcast/src/guard.ts'
import { takeLock } from './lock.ts'
import type { ApiLock } from './lock.ts'
import { ENC_HEX_RE, decodeLine, encodeLine, splitLedger, syncDir } from './pc-record.ts'
import type { Rec } from './pc-record.ts'

export const LEDGER_FILE = 'privacycash-withdrawals.jsonl'
export const LEDGER_LOCK_FILE = 'privacycash-withdrawals.lock'
export interface Reservation { nonce: string; lane: string; job: string; tryIndex: number; bodySha256: string; enc1: string; amount: bigint; allowance: bigint; exp: number }
type State = 'reserved' | 'spent' | 'released'
export type ReconcileWhy = 'http-400' | 'http-404' | 'http-status' | 'no-signature' | 'bad-answer' | 'ambiguous'
const WHYS: readonly string[] = ['http-400', 'http-404', 'http-status', 'no-signature', 'bad-answer', 'ambiguous']
interface Entry extends Reservation { state: State; sig: string | null; why: ReconcileWhy | null }
export interface ReconcileItem { nonce: string; lane: string; job: string; tryIndex: number; amount: bigint; why: ReconcileWhy }
// The seam for the durable write (tests record the order write → fsync; production uses node:fs).
export interface LedgerIo { write(fd: number, b: Buffer): number; fsync(fd: number): void }
const REAL_IO: LedgerIo = { write: (fd, b) => writeSync(fd, b, 0, b.length), fsync: (fd) => fsyncSync(fd) }
const SIG_RE = /^[1-9A-HJ-NP-Za-km-z]{64,100}$/
const NONCE_RE = /^[0-9a-f]{32}$/
const LANE_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/
const HEX16 = /^[0-9a-f]{16}$/
const HEX64 = /^[0-9a-f]{64}$/
const DEC_RE = /^(?:0|[1-9][0-9]{0,29})$/
const safeInt = (v: unknown): boolean => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0
// THE record validator of this ledger (Sfix-PC fix round 1, I-1): the very function that checks a record before it is
// written and when it is read, so the writer cannot produce a line the reader rejects.
export function validRecord(o: Rec): boolean {
  if (o.v !== 1 || typeof o.n !== 'string' || !NONCE_RE.test(o.n)) return false
  switch (o.t) {
    case 'reserve': return typeof o.lane === 'string' && LANE_RE.test(o.lane) && typeof o.job === 'string' && HEX16.test(o.job) && safeInt(o.try)
      && typeof o.h === 'string' && HEX64.test(o.h) && typeof o.e === 'string' && ENC_HEX_RE.test(o.e) && typeof o.amount === 'string' && DEC_RE.test(o.amount)
      && typeof o.allowance === 'string' && DEC_RE.test(o.allowance) && safeInt(o.exp) && safeInt(o.at)
    case 'spent': return typeof o.sig === 'string' && SIG_RE.test(o.sig)
    case 'release': return true
    case 'reconcile': return typeof o.why === 'string' && WHYS.includes(o.why)
    case 'resolved': return o.as === 'spent' || o.as === 'released'
    default: return false
  }
}
export interface WithdrawalLedger {
  reserve(r: Reservation, now: number): void        // refuses relay.pc-ledger / relay.pc-replay / relay.pc-allowance
  settle(nonce: string, sig: string): void          // reserved → spent (the relayer answered 200 with this signature)
  release(nonce: string): void                      // reserved → released (proven not accepted); the nonce stays burned
  flag(nonce: string, why: ReconcileWhy): void      // stays reserved, listed for the operator (M-6 / N-3)
  resolve(nonce: string, as: 'spent' | 'released'): void   // the operator's answer for a flagged entry
  reconciling(): ReconcileItem[]
  recorded(enc1: string): boolean                   // a withdrawal with this first encrypted output was forwarded (reserved or spent)
  signatureOf(nonce: string): string | null
  committed(lane: string): bigint                   // reserved + spent
  broken(): string | null
  close(): void
}

// THE relay.pc-ledger line (one marker): the ledger cannot be trusted or written, so nothing is forwarded.
function ledgerOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.pc-ledger', 'the Privacy Cash withdrawal ledger is missing, corrupt or not writable: no withdrawal is forwarded') // @guard:relay.pc-ledger
}
// THE relay.pc-replay line (one marker): this authorization's nonce was already used (this process, or an earlier one).
function replayOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.pc-replay', 'this withdrawal authorization was already used: each is single-use') // @guard:relay.pc-replay
}
// THE relay.pc-ledger-lock line (one marker): another relay process holds this state dir's ledger (one process per dir).
function ledgerLockOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.pc-ledger-lock', 'another relay process holds this state directory\'s Privacy Cash withdrawal ledger: one relay per state directory') // @guard:relay.pc-ledger-lock
}
// THE relay.pc-allowance line (one marker): reserved + spent + this withdrawal above the lane's allowance.
function allowanceOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.pc-allowance', "the lane's cumulative withdrawals (reserved and spent, with this one) would exceed its allowance") // @guard:relay.pc-allowance
}

const DEC = /^(?:0|[1-9][0-9]{0,29})$/
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)

export function openWithdrawalLedger(stateDir: string | null, io: LedgerIo = REAL_IO): WithdrawalLedger {
  let lock: ApiLock | null = null
  let lockFailed = false
  let lockHeld = false
  if (stateDir !== null) {
    try { lock = takeLock(join(stateDir, LEDGER_LOCK_FILE)) } catch (e) {
      // Another live process holds the lock (or a stale file names a live pid): ONLY the Privacy Cash routes are refused
      // (relay.pc-ledger-lock on a withdrawal, relay.pc-check on a check); the rest of the relay starts (review M-4).
      if (isRefusal(e) && e.guardId === 'api.already-running') lockHeld = true
      else lockFailed = true                         // any other failure (no such directory, read-only): the ledger below is bad
    }
  }
  const entries = new Map<string, Entry>()
  const committedBy = new Map<string, bigint>()
  let bad: string | null = null
  let fd: number | null = null
  const file = stateDir === null ? null : join(stateDir, LEDGER_FILE)
  const add = (lane: string, d: bigint): void => { committedBy.set(lane, (committedBy.get(lane) ?? 0n) + d) }

  function apply(o: unknown): string | null {
    if (!isObj(o) || !validRecord(o)) return 'shape'
    if (typeof o.n !== 'string') return 'shape'
    if (o.t === 'reserve') {
      const { n, lane, job, h } = o
      const amount = typeof o.amount === 'string' && DEC.test(o.amount) ? BigInt(o.amount) : null
      const allowance = typeof o.allowance === 'string' && DEC.test(o.allowance) ? BigInt(o.allowance) : null
      const enc1 = typeof o.e === 'string' && ENC_HEX_RE.test(o.e) ? o.e : null
      if (typeof n !== 'string' || typeof lane !== 'string' || typeof job !== 'string' || typeof h !== 'string' || amount === null || allowance === null || enc1 === null
        || !Number.isSafeInteger(o.try) || !Number.isSafeInteger(o.exp) || entries.has(n)) return 'reserve'
      entries.set(n, { nonce: n, lane, job, tryIndex: o.try as number, bodySha256: h, enc1, amount, allowance, exp: o.exp as number, state: 'reserved', sig: null, why: null })
      add(lane, amount)
      return null
    }
    const e = entries.get(o.n)
    if (e === undefined || e.state !== 'reserved') return 'transition'
    if (o.t === 'spent') {
      if (typeof o.sig !== 'string' || !SIG_RE.test(o.sig)) return 'spent'
      e.state = 'spent'; e.sig = o.sig; e.why = null
      return null
    }
    if (o.t === 'release') { e.state = 'released'; e.why = null; add(e.lane, -e.amount); return null }
    if (o.t === 'reconcile') {
      if (typeof o.why !== 'string' || !WHYS.includes(o.why)) return 'reconcile'
      e.why = o.why as ReconcileWhy
      return null
    }
    if (o.t === 'resolved') {
      if (e.why === null || (o.as !== 'spent' && o.as !== 'released')) return 'resolved'
      if (o.as === 'spent') e.state = 'spent'
      else { e.state = 'released'; add(e.lane, -e.amount) }
      e.why = null
      return null
    }
    return 'type'
  }

  if (file === null) bad = 'no state directory'
  else if (lockHeld) bad = 'another relay process holds this ledger'
  else if (lockFailed) bad = 'cannot take the ledger lock'
  else {
    try {
      let text = ''
      try {
        const st = lstatSync(file)
        if (!st.isFile() || st.isSymbolicLink() || (st.mode & 0o077) !== 0) bad = 'not a private regular file'
        else text = readFileSync(file, 'utf8')
      } catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e }
      if (bad === null && text !== '') {
        const { lines, tornAt } = splitLedger(text)
        if (tornAt !== null) {                        // an unacknowledged tail (a crash mid-append): cut it off
          const h = openSync(file, constants.O_WRONLY | constants.O_NOFOLLOW)
          try { ftruncateSync(h, Buffer.byteLength(text.slice(0, tornAt))); fsyncSync(h) } finally { closeSync(h) }
        }
        for (const line of lines) {
          const d = decodeLine(line)
          if (!d.ok) { bad = 'corrupt line'; break }
          const why = apply(d.rec)
          if (why !== null) { bad = `corrupt ledger (${why})`; break }
        }
      }
    } catch { bad = 'unreadable' }
  }

  // false: nothing was written. A record that does not pass the validator is never written (and does not break the ledger);
  // a failed write/fsync breaks it: no further append in this process (a torn tail is cut on the next start).
  function append(o: Rec): boolean {
    if (file === null || bad !== null || stateDir === null) return false
    const rec = { v: 1, ...o }
    if (!validRecord(rec)) return false
    const line = encodeLine(rec)
    if (line === null) return false
    try {
      if (fd === null) {
        fd = openSync(file, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW, 0o600)
        const st = fstatSync(fd)
        if (!st.isFile() || (st.mode & 0o077) !== 0) throw new Error('mode')
        syncDir(stateDir)                                // the directory entry of a created file is durable too
      }
      const b = Buffer.from(line)
      if (io.write(fd, b) !== b.length) throw new Error('short')
      io.fsync(fd)
      return true
    } catch {
      bad = 'a write failed: nothing more is acknowledged until restart'
      return false
    }
  }

  return {
    reserve(r, now) {
      ledgerLockOk(!lockHeld)
      ledgerOk(bad === null)
      const rec = { t: 'reserve', n: r.nonce, lane: r.lane, job: r.job, try: r.tryIndex, h: r.bodySha256, e: r.enc1, amount: String(r.amount), allowance: String(r.allowance), exp: r.exp, at: now }
      ledgerOk(validRecord({ v: 1, ...rec }))            // before anything is set or written; a request value that fails is refused, the ledger stays usable
      replayOk(!entries.has(r.nonce))
      allowanceOk((committedBy.get(r.lane) ?? 0n) + r.amount <= r.allowance)
      const e: Entry = { ...r, state: 'reserved', sig: null, why: null }
      entries.set(r.nonce, e); add(r.lane, r.amount)                 // in memory first: no await before the line is durable
      const ok = append(rec)
      if (!ok) { entries.delete(r.nonce); add(r.lane, -r.amount) }
      ledgerOk(ok)
    },
    settle(nonce, sig) {
      const e = entries.get(nonce)
      if (e === undefined || e.state !== 'reserved' || !SIG_RE.test(sig)) return
      if (!append({ t: 'spent', n: nonce, sig })) return   // not durable: it stays reserved (the same count); the next start lists it
      e.state = 'spent'; e.sig = sig; e.why = null
    },
    release(nonce) {
      const e = entries.get(nonce)
      if (e === undefined || e.state !== 'reserved') return
      if (!append({ t: 'release', n: nonce })) return      // not durable: it stays reserved (fail closed)
      e.state = 'released'; e.why = null; add(e.lane, -e.amount)
    },
    flag(nonce, why) {
      const e = entries.get(nonce)
      if (e === undefined || e.state !== 'reserved') return
      if (append({ t: 'reconcile', n: nonce, why })) e.why = why   // in memory only after a durable line (M-1)
    },
    resolve(nonce, as) {
      const e = entries.get(nonce)
      if (e === undefined || e.state !== 'reserved' || e.why === null) return
      if (!append({ t: 'resolved', n: nonce, as })) return          // not durable: it stays flagged and reserved
      e.why = null
      if (as === 'spent') e.state = 'spent'
      else { e.state = 'released'; add(e.lane, -e.amount) }
    },
    reconciling: () => [...entries.values()].filter((e) => e.state === 'reserved' && e.why !== null)
      .map((e) => ({ nonce: e.nonce, lane: e.lane, job: e.job, tryIndex: e.tryIndex, amount: e.amount, why: e.why as ReconcileWhy })),
    recorded: (enc1) => bad === null && [...entries.values()].some((e) => e.enc1 === enc1 && e.state !== 'released'),
    signatureOf: (nonce) => entries.get(nonce)?.sig ?? null,
    committed: (lane) => committedBy.get(lane) ?? 0n,
    broken: () => bad,
    close() {
      if (fd !== null) { try { closeSync(fd) } catch { /* nothing */ } fd = null }
      if (lock !== null) { lock.release(); lock = null }
    },
  }
}

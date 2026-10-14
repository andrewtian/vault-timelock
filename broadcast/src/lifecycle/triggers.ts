// The trigger latch (spec B §6.6; R39, amended by R43; Task T1). Requirement: once the app is triggered, the per-chain
// traces are recorded persistently for confirmation, and further use is gated until they are cleared. A trigger is any release that can put bytes on a chain; it is written BEFORE the first signature of a
// transaction that will be submitted, and every further money-moving or publishing entry point refuses until it is
// cleared.
//
//   $OUT/lifecycle/trigger/<id>.json   one record per trigger (store kind `trigger`, CAS, 0600); never deleted
//   $OUT/lifecycle/latch/trigger.json  THE latch, { open: <id> | null } (store kind `latch`, id `trigger`), shared by
//                                      the CLI and the web server
//   $OUT/triggers/<id>.txt             the plain-text twin (ASCII), regenerated after every write (atomic, 0600, 0700)
//
// ★★★ The gate fails closed. assertNoUncleared refuses while any record other than `continuing` is uncleared, reading
//   BOTH the latch and every record file: a corrupt or unreadable record propagates store.corrupt, a tampered one
//   trigger.hash-mismatch (never "cleared"); a malformed latch counts as uncleared; a latch naming a missing record, or
//   a keystore (keystore/master.pub) without lifecycle/trigger/, refuses trigger.store-missing. Nothing here creates
//   lifecycle/trigger/ behind the gate's back: only openTrigger does, after its own gate passed.
//   The one exception (T1 review I1): while the latch names `continuing`, an uncleared record whose chains are ALL
//   `planned` is skipped. It never won the latch, so it cannot sign: it is a losing opener between its record and its
//   failed latch CAS (it ends itself at once), or one that crashed there (the next plain gate still refuses on it).
// ★★ Latch exits (T1 review I2). The record scan is authoritative; the latch only names the open trigger.
//   · malformed (not { open: null | <trigger id> }) or naming a missing record: the gate refuses (trigger.uncleared /
//     trigger.store-missing) until the operator runs `vt-broadcast triggers reset-latch`, which CASes exactly those two
//     cases to { open: null } and refuses anything else (trigger.reset-latch). A missing record may hide chains in
//     flight: restore it if you can, and read its last text twin triggers/<id>.txt first.
//   · naming a cleared record: the next gate resets it by CAS (clearTrigger's crash window); nothing to do.
//   · a latch FILE that is not a valid state file (store.corrupt): the store cannot rewrite it, so move
//     lifecycle/latch/trigger.json aside by hand. An absent latch reads as { open: null }; every record is still scanned.
// ★★ "Is any trigger open?" (canonical plan, ruling 2: jobs never open T1 triggers, and an OPEN legacy trigger blocks
//   job sends) is assertNoUncleared(t) with no options. Stable: (t: { out, store }) => Promise<void>; it resolves when
//   none is open, and ANY refusal (trigger.uncleared, trigger.store-missing, store.corrupt, trigger.hash-mismatch, ...)
//   means "treat as open". Its only write is the CAS reset of a latch naming a cleared record.
// ★★ Ordering (12a's update() locks ONE record with a synchronous fn, so the record and the latch never change in one
//   step). openTrigger: (0) the gate, (1) create the record, every chain `planned` (trigger.exists if present), (2) CAS
//   the latch null -> id. The loser of (2) (a concurrent opener won) ends its own record at once: every chain
//   `not-broadcast` (reason `latch busy`), cleared, then trigger.uncleared. A crash between (1) and (2) leaves an
//   uncleared all-planned record and a null latch: the gate still refuses (it scans the records) and the operator ends
//   it with `resolve ... mark-not-broadcast` + `clear`. clearTrigger: stamp the record FIRST, then CAS the latch
//   id -> null; a latch that is already null or names another id is left alone (never an error). A crash between the two
//   leaves a latch naming a cleared record, which the next gate resets by CAS.
// ★ Traces only move forward (LEGAL below). advanceTrace never moves signed to confirmed nor anything out of unknown:
//   only read-only evidence (observe) or the operator (resolveTrigger, typed `resolve` on a mainnet record) end those
//   (R43). Nothing here ever resends. Every write re-checks the stored traceSha256 first (a tampered record is refused,
//   never re-hashed) and recomputes it. Refusals name paths relative to $OUT, never absolute ones.
//
// ★ The text twin is a convenience copy written AFTER the commit (openTrigger: after the latch CAS; clearTrigger: after
//   the latch CAS). If it cannot be written the committed write still stands and is returned: one non-refusal warning
//   line `warn trigger.twin-stale: ...` (t.warn, default stderr; relative paths and an error code only), never a
//   refusal (T1 review m2).
//
// START points call assertSendAllowed then assertNoUncleared(t); openTrigger comes after both. CONTINUATION points (the
// open trigger's own submits, readback, polling) call assertNoUncleared(t, { continuing: id }), which refuses
// trigger.continuing unless `id` is an existing, uncleared record (T1 review m3): before the record exists, or after it is
// cleared, nothing continues under it. Read-only use is never gated. Every submit is preceded by advanceTrace(t, id, dest,
// { state: 'signed', txId, txIds }).
import { closeSync, fsyncSync, lstatSync, openSync, renameSync, unlinkSync, writeSync } from 'node:fs'
import { createHash, randomBytes } from 'node:crypto'
import { join } from 'node:path'
import { refuse, Refusal } from '../guard.ts'
import { networkName, PROFILES } from '../config.ts'
import type { Profile } from '../config.ts'
import type { Clock } from './clock.ts'
import { ensureDir, keystoreDir, lifecycleDir } from './paths.ts'
import type { Store } from './store.ts'

export type TraceState = 'planned' | 'signed' | 'submitted' | 'confirmed' | 'failed' | 'not-broadcast' | 'unknown'
export type Dest = 'eth' | 'arb' | 'base' | 'btc' | 'sol' | 'arweave'
export interface ChainTrace {
  dest: Dest
  network: string // networkName(profile, chain), e.g. 'Ethereum mainnet · 1', 'Sepolia · 11155111'
  state: TraceState
  address: string | null
  txId: string | null // set at 'signed', never changed afterwards; the id explorers key on:
  //                     the ETH hash, the first Solana signature, the BTC reveal
  txIds: string[] | null // every id in broadcast order, set at 'signed' (Bitcoin: [commit, reveal])
  block: string | null // block number / slot / block hash, set at 'confirmed'
  confirmations: number | null
  readback: boolean | null // byte-equal readback result, set at 'confirmed'
  feePaid: string | null // smallest unit, decimal string
  explorer: string | null
  bytesSha256: string // sha256 of the exact on-chain bytes
  reason: string | null // for failed / not-broadcast / unknown
  updatedAt: number
}
export interface Trigger {
  id: string; createdAt: number; profile: 'mainnet' | 'testnet' | 'local'
  source: 'flow2' | 'flow1' | 'cli'; ref: string // flow2 id / job id. A Flow 2 trigger id IS the Flow 2 id
  //                                                (`f2-<10 hex>`); Flow 1 uses the job id
  payloadSha256: string; chains: ChainTrace[] // canonical order: eth, arb, base, btc, sol, arweave
  clearedAt: number | null; clearedBy: 'cli' | 'web' | null
  traceSha256: string // sha256 of canonical JSON of the record without this field
}
export type Evidence = { kind: 'found'; block: string; confirmations: number; readback?: boolean } | {
  kind: 'nonce-consumed' | 'blockhash-expired' | 'input-spent'; detail: string
}
export type ResolveAction =
  | { action: 'mark-done'; tx: string; block: string | null; confirmations: number | null; readback: boolean | null }
  | { action: 'mark-failed' }
  | { action: 'mark-not-broadcast' }
// The store exposes no `out`, and the text twin needs it. warn: the twin-stale warning's sink (default: stderr).
export interface TriggerCtx { out: string; store: Store; warn?: (line: string) => void }
export type ChainPlan = Pick<ChainTrace, 'dest' | 'network' | 'address' | 'bytesSha256' | 'explorer'>
export interface OpenTrigger {
  id: string; profile: Profile; source: Trigger['source']; ref: string; payloadSha256: string; chains: ChainPlan[]
}

const DESTS: readonly Dest[] = ['eth', 'arb', 'base', 'btc', 'sol', 'arweave'] // the canonical order
const STATES: readonly TraceState[] = ['planned', 'signed', 'submitted', 'confirmed', 'failed', 'not-broadcast', 'unknown']
const TERMINAL: readonly TraceState[] = ['confirmed', 'failed', 'not-broadcast']
// advanceTrace's moves. signed -> confirmed and every move out of unknown go through observe or resolveTrigger (R43).
const LEGAL: Readonly<Record<TraceState, readonly TraceState[]>> = {
  planned: ['signed', 'not-broadcast'], signed: ['submitted', 'unknown', 'failed'], submitted: ['confirmed', 'failed', 'unknown'],
  confirmed: [], failed: [], 'not-broadcast': [], unknown: [],
}
const OBSERVABLE: readonly TraceState[] = ['signed', 'unknown'] // observe: -> confirmed | failed
const RESOLVABLE: readonly TraceState[] = ['signed', 'submitted', 'unknown'] // mark-done | mark-failed
const NEEDS_REASON: readonly TraceState[] = ['failed', 'not-broadcast', 'unknown']
// Failure evidence, each for its own chains only: EVM nonce moved past the tx under another hash; Solana blockhash
// expired with no signature status; Bitcoin input confirmed spent by another tx. Arweave has none (found or resolve).
const FAILURE_EVIDENCE: Readonly<Record<string, readonly Dest[]>> = {
  'nonce-consumed': ['eth', 'arb', 'base'], 'blockhash-expired': ['sol'], 'input-spent': ['btc'],
}
const ACTIONS: readonly string[] = ['mark-done', 'mark-failed', 'mark-not-broadcast']
const SOURCES: readonly string[] = ['flow2', 'flow1', 'cli']
// What a caller may name in advanceTrace's `next` (updatedAt is the clock's).
const NEXT_KEYS: readonly string[] = [
  'state', 'dest', 'network', 'address', 'txId', 'txIds', 'block', 'confirmations', 'readback', 'feePaid', 'explorer', 'bytesSha256', 'reason',
]
const LATCH_ID = 'trigger'
const TRIGGER_ID = /^[a-z0-9][a-z0-9-]{0,63}$/ // the store's id rule: a latch naming anything else is malformed
const HEX64 = /^[0-9a-f]{64}$/
const DECIMAL = /^(?:0|[1-9][0-9]*)$/
const REF = /^[\x21-\x7e]{1,128}$/

type Latch = { open: string | null }
type Rec = Record<string, unknown>
const isRec = (v: unknown): v is Rec => typeof v === 'object' && v !== null && !Array.isArray(v)
const isLatch = (v: unknown): v is Latch => isRec(v) && (v.open === null || (typeof v.open === 'string' && TRIGGER_ID.test(v.open)))
const nil = (v: unknown): v is null | undefined => v === null || v === undefined
const nilOr = (v: unknown, ok: (x: unknown) => boolean): boolean => nil(v) || ok(v)
const isStr = (v: unknown): v is string => typeof v === 'string'
const isText = (v: unknown): v is string => typeof v === 'string' && v !== ''
const isPosInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 1
const rel = (id: string): string => `lifecycle/trigger/${id}.json`
const nonTerminal = (tr: Trigger): number => tr.chains.filter((c) => !TERMINAL.includes(c.state)).length
const sameIds = (a: unknown, b: string[] | null): boolean =>
  a === b || (Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => x === b[i]))

// ---- guards (one refuse line per id; the helpers are called wherever the rule applies)

function input(ok: boolean, msg: string): asserts ok {
  if (!ok) refuse('trigger.input', msg) // @guard:trigger.input
}
function transition(ok: boolean, msg: string): asserts ok {
  if (!ok) refuse('trigger.transition', msg) // @guard:trigger.transition
}
function present(ok: boolean, msg: string): asserts ok {
  if (!ok) refuse('trigger.store-missing', msg) // @guard:trigger.store-missing
}
function noOther(ok: boolean, msg: string): void {
  if (!ok) refuse('trigger.uncleared', msg) // @guard:trigger.uncleared
}
function stillOpen(tr: Trigger): void {
  const ok = tr.clearedAt === null
  if (!ok) refuse('trigger.cleared', `trigger ${tr.id} is cleared: a cleared record is never written again (a retry is a new release with a new trigger)`) // @guard:trigger.cleared
}
// Mainnet records need the typed word; the RECORD's own profile decides, never the caller's.
function typedWord(tr: Trigger, typed: unknown, word: 'clear' | 'resolve'): void {
  const ok = tr.profile !== 'mainnet' || typed === word
  if (!ok) refuse('trigger.clear-typed', `trigger ${tr.id} is a mainnet record: to ${word} it, type "${word}" (from /dev/tty on the CLI, in the dialog on the web)`) // @guard:trigger.clear-typed
}
// reset-latch touches only a malformed latch or one naming a missing record (I2); everything else is refused here.
function latchReset(ok: boolean, msg: string): asserts ok {
  if (!ok) refuse('trigger.reset-latch', msg) // @guard:trigger.reset-latch
}
const unclearedMsg = (tr: Trigger): string =>
  `trigger ${tr.id} is not cleared (${nonTerminal(tr)} of ${tr.chains.length} chains not terminal; ${rel(tr.id)}): end its chains (evidence or vt-broadcast triggers resolve), then vt-broadcast triggers clear ${tr.id}`
const LATCH_FILE = 'lifecycle/latch/trigger.json'
const RESET_REMEDY = 'remedy: vt-broadcast triggers reset-latch (it resets only a malformed latch or one naming a missing record; the gate still scans every record)'
const malformedMsg = `the latch ${LATCH_FILE} is malformed (not { open: null | <trigger id> }): counted as uncleared; ${RESET_REMEDY}`
const ghostMsg = (id: string): string =>
  `the latch names ${id}, but ${rel(id)} is missing (records are never deleted: restore it if you can; its last text twin is triggers/${id}.txt); ${RESET_REMEDY}`

// ---- integrity

// Canonical JSON: object keys sorted, no whitespace; undefined members are dropped, as JSON.stringify does.
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`
  if (isRec(v)) return `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`
  return JSON.stringify(v)
}
function shaOf(tr: Rec): string {
  const { traceSha256: _ignored, ...rest } = tr
  return createHash('sha256').update(canonical(rest)).digest('hex')
}
function seal(tr: Omit<Trigger, 'traceSha256'> & { traceSha256?: string }): Trigger {
  const { traceSha256: _old, ...rest } = tr
  return { ...rest, traceSha256: shaOf(rest) }
}

export function verifyTraceSha(tr: Trigger): boolean {
  if (!isRec(tr)) return false
  const h = (tr as Rec).traceSha256
  return typeof h === 'string' && HEX64.test(h) && shaOf(tr as Rec) === h
}

function isChain(c: unknown): c is ChainTrace {
  return isRec(c) && DESTS.includes(c.dest as Dest) && STATES.includes(c.state as TraceState) && isStr(c.network) && isStr(c.bytesSha256)
    && (c.txIds === null || (Array.isArray(c.txIds) && c.txIds.every(isStr))) && nilOr(c.txId, isStr) && nilOr(c.reason, isStr)
}
function isTrigger(v: unknown): v is Trigger {
  return isRec(v) && isStr(v.id) && typeof v.createdAt === 'number' && (PROFILES as readonly unknown[]).includes(v.profile)
    && SOURCES.includes(v.source as string) && isStr(v.ref) && isStr(v.payloadSha256) && Array.isArray(v.chains) && v.chains.length > 0
    && v.chains.every(isChain) && (v.clearedAt === null || typeof v.clearedAt === 'number')
    && (v.clearedBy === null || v.clearedBy === 'cli' || v.clearedBy === 'web')
}
// The stored value as a Trigger: the right shape, its own id, and a matching traceSha256 (tamper/corruption evidence).
function verified(v: unknown, id: string): Trigger {
  const ok = isTrigger(v) && v.id === id && verifyTraceSha(v)
  if (!ok) refuse('trigger.hash-mismatch', `${rel(id)} does not match its traceSha256, or is not the trigger record for ${id} (tampered or corrupt): it is not used`) // @guard:trigger.hash-mismatch
  return v as Trigger
}

// ---- the text twin

function writeTwin(out: string, id: string, text: string): void {
  const dir = join(out, 'triggers')
  ensureDir(dir, out)
  const file = join(dir, `${id}.txt`)
  const tmp = `${file}.tmp.${process.pid}.${randomBytes(6).toString('hex')}`
  try {
    const fd = openSync(tmp, 'wx', 0o600)
    try { writeSync(fd, text); fsyncSync(fd) } finally { closeSync(fd) }
    renameSync(tmp, file)
  } catch (e) {
    try { unlinkSync(tmp) } catch { /* already gone */ }
    throw e
  }
  const dfd = openSync(dir, 'r')
  try { fsyncSync(dfd) } finally { closeSync(dfd) }
}
// After a committed write: render the record as stored now. Writers do not hold the record lock here, so if the
// record changed meanwhile (another writer), render again: the last twin written always reflects the latest record.
// Never throws (m2): the write is committed, so a failure here is one warning line, not a refusal. The line names only
// relative paths and an error code or guard id (an fs error's message holds the absolute path).
async function syncTwin(t: TriggerCtx, id: string): Promise<void> {
  try {
    for (let i = 0; i < 8; i++) {
      const a = await t.store.read<unknown>('trigger', id)
      present(a !== undefined, `no trigger record ${rel(id)}`)
      writeTwin(t.out, id, renderTraceText(verified(a.value, id)))
      const b = await t.store.read<unknown>('trigger', id)
      if (b?.rev === a.rev) return
    }
  } catch (e) {
    const code = (e as NodeJS.ErrnoException | undefined)?.code
    const why = e instanceof Refusal ? e.guardId : typeof code === 'string' && /^[A-Z0-9_]{1,32}$/.test(code) ? code : 'error'
    const warn = t.warn ?? ((line: string) => { process.stderr.write(line + '\n') })
    warn(`warn trigger.twin-stale: triggers/${id}.txt was not rewritten (${why}); the write to ${rel(id)} is committed and authoritative (vt-broadcast triggers show ${id} prints it; the next write regenerates the twin)`)
  }
}

// ---- reads

export async function readTrigger(t: TriggerCtx, id: string): Promise<Trigger> {
  const r = await t.store.read<unknown>('trigger', id)
  present(r !== undefined, `no trigger record ${rel(id)}`)
  return verified(r.value, id)
}

// Every record, oldest first, each verified (a corrupt or tampered one refuses the whole list).
export async function listTriggers(t: TriggerCtx): Promise<Trigger[]> {
  const out: Trigger[] = []
  for (const id of await t.store.list('trigger')) out.push(await readTrigger(t, id))
  return out
}

// ---- the gate

const exists = (p: string): boolean => {
  try { lstatSync(p); return true } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return false
    throw e // EACCES, EIO, ...: fail closed
  }
}

export async function assertNoUncleared(t: TriggerCtx, opts: { continuing?: string } = {}): Promise<void> {
  const cont = opts.continuing
  const store = exists(join(lifecycleDir(t.out), 'trigger'))
  const keystore = exists(join(keystoreDir(t.out), 'master.pub'))
  present(store || !keystore, 'lifecycle/trigger/ is missing while keystore/master.pub exists: refusing rather than reading "no triggers" (restore the trigger store)')
  if (cont !== undefined) { // m3: only an existing, uncleared trigger continues (a tampered one refuses hash-mismatch)
    const own = await t.store.read<unknown>('trigger', cont)
    const live = own !== undefined && verified(own.value, cont).clearedAt === null
    if (!live) refuse('trigger.continuing', `continuing ${cont}: ${own === undefined ? 'there is no such trigger record' : 'that trigger is cleared'} (${rel(cont)}); only an open trigger's own steps continue under it, anything else is a START point (the plain gate)`) // @guard:trigger.continuing
  }
  const latch = await t.store.read<unknown>('latch', LATCH_ID)
  noOther(latch === undefined || isLatch(latch.value), malformedMsg)
  const open = latch === undefined ? null : (latch.value as Latch).open
  let contHolds = false // the latch names `continuing`, and that record is uncleared
  if (open !== null) {
    const rec = await t.store.read<unknown>('trigger', open)
    present(rec !== undefined, ghostMsg(open))
    const tr = verified(rec.value, open)
    noOther(tr.clearedAt !== null || open === cont, unclearedMsg(tr))
    contHolds = tr.clearedAt === null && open === cont
    // a latch naming a cleared record: clearTrigger crashed between its two steps; reset it by CAS
    if (tr.clearedAt !== null) await t.store.update<unknown>('latch', LATCH_ID, (cur) => (isLatch(cur) && cur.open === open ? { open: null } : (cur ?? { open: null })))
  }
  for (const id of await t.store.list('trigger')) {
    const tr = await readTrigger(t, id)
    // I1: while `continuing` holds the latch, an all-planned record never won it and cannot sign (see the header)
    const lostOpener = contHolds && tr.chains.every((c) => c.state === 'planned')
    noOther(tr.clearedAt !== null || id === cont || lostOpener, unclearedMsg(tr))
  }
}

// ---- reset-latch (I2): the operator's exit from a latch the gate cannot use

type LatchFault = 'malformed' | 'missing'
// Synchronous (it also runs inside the latch's update fn): malformed, naming a missing record, or fine (null).
function latchFault(out: string, v: unknown): LatchFault | null {
  if (!isLatch(v)) return 'malformed'
  if (v.open === null) return null
  return exists(join(lifecycleDir(out), 'trigger', `${v.open}.json`)) ? null : 'missing'
}

// CASes the latch to { open: null } only if it is malformed or names a missing record; refuses trigger.reset-latch
// otherwise. Never touches a record: the gate keeps scanning every one of them.
export async function resetLatch(t: TriggerCtx): Promise<{ was: 'malformed' } | { was: 'missing'; named: string }> {
  let l: Awaited<ReturnType<Store['read']>>
  try { l = await t.store.read<unknown>('latch', LATCH_ID) } catch (e) {
    if (!(e instanceof Refusal && e.guardId === 'store.corrupt')) throw e
    l = undefined
    latchReset(false, `${LATCH_FILE} is not a valid state file, which the store cannot rewrite: move it aside by hand (an absent latch reads as { open: null }; the gate still scans every record)`)
  }
  const named = l !== undefined && isLatch(l.value) ? l.value.open : null
  const nothing = l === undefined ? `there is no latch (${LATCH_FILE})` : named === null ? 'the latch is { open: null }' : `the latch names ${named}, whose record ${rel(named)} exists`
  const why = l === undefined ? null : latchFault(t.out, l.value)
  latchReset(why !== null, `${nothing}: nothing to reset (reset-latch resets only a malformed latch or one naming a missing record; an uncleared trigger ends with evidence or vt-broadcast triggers resolve, then clear; a latch naming a cleared record is reset by the gate itself)`)
  const seen: { fault: LatchFault | null; named: string | null } = { fault: null, named: null }
  await t.store.update<unknown>('latch', LATCH_ID, (cur) => {
    seen.fault = cur === undefined ? null : latchFault(t.out, cur) // re-checked under the latch's lock (CAS)
    seen.named = seen.fault === 'missing' ? (cur as Latch).open : null
    return seen.fault === null ? (cur ?? { open: null }) : { open: null }
  })
  latchReset(seen.fault !== null, 'the latch changed meanwhile and no longer needs a reset: nothing was reset')
  return seen.fault === 'missing' && seen.named !== null ? { was: 'missing', named: seen.named } : { was: 'malformed' }
}

// ---- open

function checkOpen(p: unknown): ChainPlan[] {
  input(isRec(p), 'openTrigger needs { id, profile, source, ref, payloadSha256, chains }')
  input((PROFILES as readonly unknown[]).includes(p.profile), 'profile must be mainnet, testnet or local')
  input(SOURCES.includes(p.source as string), 'source must be flow2, flow1 or cli')
  input(isStr(p.ref) && REF.test(p.ref), 'ref must be 1 to 128 printable ASCII characters (the Flow 2 id or the job id)')
  input(isStr(p.payloadSha256) && HEX64.test(p.payloadSha256), 'payloadSha256 must be 64 lowercase hex digits')
  input(Array.isArray(p.chains) && p.chains.length >= 1 && p.chains.length <= DESTS.length, 'chains must list 1 to 6 destinations')
  const seen = new Set<unknown>()
  for (const c of p.chains as unknown[]) {
    input(isRec(c) && DESTS.includes(c.dest as Dest) && !seen.has(c.dest), 'each chain needs a distinct dest: eth, arb, base, btc, sol or arweave')
    seen.add(c.dest)
    input(isStr(c.bytesSha256) && HEX64.test(c.bytesSha256), `${c.dest}: bytesSha256 must be 64 lowercase hex digits`)
    input(nilOr(c.address, isStr) && nilOr(c.explorer, isStr), `${c.dest}: address and explorer must be strings or null`)
    input(c.network === networkName(p.profile as Profile, c.dest as Dest), `${c.dest}: network must be networkName(profile, dest)`)
  }
  return [...(p.chains as ChainPlan[])].sort((a, b) => DESTS.indexOf(a.dest) - DESTS.indexOf(b.dest))
}

// Opens the trigger: (0) the gate, (1) the record with every chain planned, (2) the latch CAS null -> id (see the header).
export async function openTrigger(t: TriggerCtx, p: OpenTrigger, clock: Clock): Promise<Trigger> {
  const plan = checkOpen(p)
  await assertNoUncleared(t)
  const now = clock.now()
  const record = seal({
    id: p.id, createdAt: now, profile: p.profile, source: p.source, ref: p.ref, payloadSha256: p.payloadSha256,
    chains: plan.map((c) => ({
      dest: c.dest, network: c.network, state: 'planned' as const, address: c.address ?? null, txId: null, txIds: null, block: null,
      confirmations: null, readback: null, feePaid: null, explorer: c.explorer ?? null, bytesSha256: c.bytesSha256, reason: null, updatedAt: now,
    })),
    clearedAt: null, clearedBy: null,
  })
  await t.store.update<unknown>('trigger', p.id, (cur) => {
    const fresh = cur === undefined
    if (!fresh) refuse('trigger.exists', `${rel(p.id)} already exists: a trigger record is never rewritten (a retry is a new release with a new trigger)`) // @guard:trigger.exists
    return record
  })
  let won = false
  await t.store.update<unknown>('latch', LATCH_ID, (cur) => {
    won = cur === undefined || (isLatch(cur) && cur.open === null)
    return won ? { open: p.id } : cur
  })
  if (!won) {
    // A concurrent opener holds the latch: this attempt never signs anything. End its record at once.
    const by = p.source === 'flow2' ? 'web' : 'cli'
    await mutate(t, p.id, (tr) => {
      const at = clock.now()
      const chains = tr.chains.map((c) => (c.state === 'planned' ? { ...c, state: 'not-broadcast' as const, reason: 'latch busy', updatedAt: at } : c))
      const done = chains.every((c) => TERMINAL.includes(c.state))
      return { ...tr, chains, clearedAt: done ? at : tr.clearedAt, clearedBy: done ? by : tr.clearedBy }
    })
  } else await syncTwin(t, p.id) // m2: the twin only after the CAS (the loser's mutate writes its own)
  noOther(won, won ? '' : `${await holder(t)} holds the latch; this attempt was recorded as ${p.id} (every chain not-broadcast: latch busy) and cleared`)
  return record
}

// Who holds the latch, for the loser's message (best effort: the refusal is certain either way).
async function holder(t: TriggerCtx): Promise<string> {
  try {
    const l = await t.store.read<unknown>('latch', LATCH_ID)
    const open = l !== undefined && isLatch(l.value) ? l.value.open : null
    if (open === null) return 'another trigger'
    const tr = await readTrigger(t, open)
    return `trigger ${open} (${nonTerminal(tr)} of ${tr.chains.length} chains not terminal; ${rel(open)})`
  } catch { return 'another trigger' }
}

// ---- writes (each under the record's lock; the stored hash is checked before anything changes)

async function commit(t: TriggerCtx, id: string, f: (tr: Trigger) => Omit<Trigger, 'traceSha256'>): Promise<Trigger> {
  await readTrigger(t, id) // present and intact; never creates lifecycle/trigger/ (unlike update)
  const r = await t.store.update<unknown>('trigger', id, (cur) => {
    present(cur !== undefined, `no trigger record ${rel(id)}`)
    return seal(f(verified(cur, id)))
  })
  return r.value as Trigger
}
async function mutate(t: TriggerCtx, id: string, f: (tr: Trigger) => Omit<Trigger, 'traceSha256'>): Promise<Trigger> {
  const tr = await commit(t, id, f)
  await syncTwin(t, id)
  return tr
}

function chainIn(tr: Trigger, dest: unknown): ChainTrace {
  const c = DESTS.includes(dest as Dest) ? tr.chains.find((x) => x.dest === dest) : undefined
  input(c !== undefined, `dest must be one of this trigger's chains (${tr.chains.map((x) => x.dest).join(', ')})`)
  return c
}
const withChain = (tr: Trigger, c: ChainTrace): Trigger => ({ ...tr, chains: tr.chains.map((x) => (x.dest === c.dest ? c : x)) })

function checkNext(next: unknown): Rec & { state: TraceState } {
  input(isRec(next) && STATES.includes(next.state as TraceState), 'next must be an object with a state: planned, signed, submitted, confirmed, failed, not-broadcast or unknown')
  input(Object.keys(next).every((k) => NEXT_KEYS.includes(k)), `next may name only ${NEXT_KEYS.join(', ')} (updatedAt is the clock's)`)
  input(nilOr(next.feePaid, (v) => isStr(v) && DECIMAL.test(v)), 'feePaid must be a decimal string in the smallest unit, or null')
  input(['dest', 'network', 'address', 'explorer', 'bytesSha256'].every((k) => nilOr(next[k], isStr)), 'dest, network, address, explorer and bytesSha256 must be strings or null')
  return next as Rec & { state: TraceState }
}

// The chain after the legal move cur.state -> n.state (legality is checked by the caller).
function applyNext(cur: ChainTrace, n: Rec & { state: TraceState }, now: number): ChainTrace {
  const d = cur.dest
  const out: ChainTrace = { ...cur, state: n.state, updatedAt: now }
  transition((n.dest === undefined || n.dest === d) && (n.network === undefined || n.network === cur.network) && (n.bytesSha256 === undefined || n.bytesSha256 === cur.bytesSha256), `${d}: dest, network and bytesSha256 are fixed when the trigger opens`)
  transition(nil(n.address) || cur.address === null || n.address === cur.address, `${d}: the address is fixed once recorded`)
  if (isStr(n.address)) out.address = n.address
  if (n.state === 'signed') {
    const ids = n.txIds
    const okIds = Array.isArray(ids) && ids.length >= 1 && ids.every(isText) && new Set(ids).size === ids.length && isText(n.txId) && ids.includes(n.txId)
    // Bitcoin: [commit, reveal], and txId is the reveal (the id explorers key on)
    const okBtc = d !== 'btc' || (Array.isArray(ids) && ids.length === 2 && n.txId === ids[1])
    transition(okIds && okBtc, `${d}: signed needs txId and txIds (every id in broadcast order, txId among them; Bitcoin exactly [commit, reveal] with txId = reveal)`)
    out.txId = n.txId as string
    out.txIds = [...(ids as string[])]
  } else {
    transition((n.txId === undefined || n.txId === cur.txId) && (n.txIds === undefined || sameIds(n.txIds, cur.txIds)), `${d}: txId and txIds are recorded at signed and never change`)
  }
  if (n.state === 'confirmed') {
    transition(isText(n.block) && isPosInt(n.confirmations) && typeof n.readback === 'boolean', `${d}: confirmed needs block, confirmations >= 1 and readback (true or false)`)
    out.block = n.block
    out.confirmations = n.confirmations
    out.readback = n.readback
    out.reason = null
  } else {
    transition(nil(n.block) && nil(n.confirmations) && nil(n.readback), `${d}: block, confirmations and readback are set at confirmed only`)
  }
  if (NEEDS_REASON.includes(n.state)) {
    transition(isText(n.reason), `${d}: ${n.state} needs a reason`)
    out.reason = n.reason
  } else {
    transition(nil(n.reason), `${d}: a reason is recorded for failed, not-broadcast and unknown only`)
  }
  if (isStr(n.feePaid)) out.feePaid = n.feePaid
  if (isStr(n.explorer)) out.explorer = n.explorer
  return out
}

// Forward-only moves (LEGAL); txId/txIds at signed (immutable after); confirmed with block, confirmations >= 1, readback.
export async function advanceTrace(t: TriggerCtx, id: string, dest: Dest, next: Partial<ChainTrace> & { state: TraceState }, clock: Clock): Promise<Trigger> {
  return mutate(t, id, (tr) => {
    stillOpen(tr)
    const cur = chainIn(tr, dest)
    const n = checkNext(next)
    transition(LEGAL[cur.state].includes(n.state), `${dest}: ${cur.state} -> ${n.state} is not a legal move (planned -> signed|not-broadcast; signed -> submitted|unknown|failed; submitted -> confirmed|failed|unknown; signed -> confirmed and unknown -> * only by evidence or resolve)`)
    return withChain(tr, applyNext(cur, n, clock.now()))
  })
}

// Read-only evidence (R43): signed|unknown -> confirmed (found, with readback) | failed (the tx can never land).
export async function observe(t: TriggerCtx, id: string, dest: Dest, evidence: Evidence, clock: Clock): Promise<Trigger> {
  return mutate(t, id, (tr) => {
    stillOpen(tr)
    const cur = chainIn(tr, dest)
    const ev: unknown = evidence
    input(isRec(ev) && (ev.kind === 'found' || Object.hasOwn(FAILURE_EVIDENCE, ev.kind as string)), 'evidence kind must be found, nonce-consumed, blockhash-expired or input-spent')
    transition(OBSERVABLE.includes(cur.state), `${dest}: evidence ends signed and unknown chains only, not ${cur.state}`)
    const now = clock.now()
    if (ev.kind === 'found') {
      transition(isText(ev.block) && isPosInt(ev.confirmations) && typeof ev.readback === 'boolean', `${dest}: found needs block, confirmations >= 1 and readback (confirmed needs them)`)
      return withChain(tr, { ...cur, state: 'confirmed', block: ev.block, confirmations: ev.confirmations, readback: ev.readback, reason: null, updatedAt: now })
    }
    const kind = ev.kind as string
    transition(FAILURE_EVIDENCE[kind].includes(dest) && isText(ev.detail), `${dest}: ${kind} evidence needs a detail and fits ${FAILURE_EVIDENCE[kind].join('/')} chains only`)
    return withChain(tr, { ...cur, state: 'failed', reason: `${kind}: ${ev.detail}`, updatedAt: now })
  })
}

// The operator's exits when no evidence is observable (R43). Mainnet records need typed `resolve`. mark-done records
// WHICH of the chain's txIds the operator named, in the reason `operator: mark-done <tx>` (m1: Bitcoin has two).
export async function resolveTrigger(t: TriggerCtx, id: string, dest: Dest, p: ResolveAction, p2: { by: 'cli' | 'web'; typed?: string }, clock: Clock): Promise<Trigger> {
  return mutate(t, id, (tr) => {
    stillOpen(tr)
    const cur = chainIn(tr, dest)
    const a: unknown = p
    const w: unknown = p2
    input(isRec(w) && (w.by === 'cli' || w.by === 'web'), 'by must be cli or web')
    input(isRec(a) && ACTIONS.includes(a.action as string), 'action must be mark-done <tx>, mark-failed or mark-not-broadcast')
    const done = a.action === 'mark-done'
    input(!done || (nilOr(a.block, isText) && nilOr(a.confirmations, isPosInt) && nilOr(a.readback, (v) => typeof v === 'boolean')), 'mark-done: block (non-empty), confirmations (>= 1) and readback (true/false) are each a value or null')
    const from = a.action === 'mark-not-broadcast' ? ['planned'] : RESOLVABLE
    transition(from.includes(cur.state), `${dest}: ${a.action as string} applies to ${from.join('/')} chains, not ${cur.state}`)
    transition(!done || (isStr(a.tx) && (cur.txIds ?? []).includes(a.tx)), `${dest}: mark-done must name one of the recorded txIds (${(cur.txIds ?? []).join(' ')})`)
    typedWord(tr, w.typed, 'resolve')
    const now = clock.now()
    if (done) {
      return withChain(tr, {
        ...cur, state: 'confirmed', block: (a.block ?? null) as string | null, confirmations: (a.confirmations ?? null) as number | null,
        readback: (a.readback ?? null) as boolean | null, reason: `operator: mark-done ${a.tx as string}`, updatedAt: now,
      })
    }
    const state = a.action === 'mark-failed' ? 'failed' : 'not-broadcast'
    return withChain(tr, { ...cur, state, reason: `operator: ${a.action as string}`, updatedAt: now })
  })
}

// ---- clear

// Every chain terminal; mainnet records typed `clear`. Stamps the record first, then CASes the latch id -> null (a
// no-op when the latch is null or names another id), then writes the twin.
export async function clearTrigger(t: TriggerCtx, id: string, p: { by: 'cli' | 'web'; typed?: string }, clock: Clock): Promise<Trigger> {
  const w: unknown = p
  input(isRec(w) && (w.by === 'cli' || w.by === 'web'), 'by must be cli or web')
  const tr = await commit(t, id, (cur) => {
    stillOpen(cur)
    const left = nonTerminal(cur)
    const ok = left === 0
    if (!ok) refuse('trigger.not-terminal', `trigger ${id}: ${left} of ${cur.chains.length} chains not terminal (planned, signed, submitted or unknown): end them first (evidence or vt-broadcast triggers resolve)`) // @guard:trigger.not-terminal
    typedWord(cur, w.typed, 'clear')
    return { ...cur, clearedAt: clock.now(), clearedBy: w.by as 'cli' | 'web' }
  })
  const l = await t.store.read<unknown>('latch', LATCH_ID)
  if (l !== undefined && isLatch(l.value) && l.value.open === id) {
    await t.store.update<unknown>('latch', LATCH_ID, (cur) => (isLatch(cur) && cur.open === id ? { open: null } : (cur ?? { open: null })))
  }
  await syncTwin(t, id) // m2: after the latch CAS
  return tr
}

// ---- text (pure, ASCII-only, public data only)

// Printable ASCII passes; backslash, CR, LF and TAB get short escapes; anything else is \uXXXX (UTF-16 units). So free
// text (a node's error message as a reason) can neither forge a line nor bring non-ASCII into the twin.
function esc(s: string): string {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c === 0x5c) out += '\\\\'
    else if (c === 0x0a) out += '\\n'
    else if (c === 0x0d) out += '\\r'
    else if (c === 0x09) out += '\\t'
    else if (c >= 0x20 && c < 0x7f) out += s[i]
    else out += `\\u${c.toString(16).padStart(4, '0')}`
  }
  return out
}
const val = (v: string | number | null | undefined): string => (v === null || v === undefined ? '-' : esc(String(v)))
function iso(sec: number): string {
  try { return new Date(sec * 1000).toISOString().replace(/\.000Z$/, 'Z') } catch { return val(sec) }
}
const asciiNetwork = (n: string): string => esc(n.replaceAll(' \u00b7 ', ' | '))

export function renderChainText(c: ChainTrace): string {
  const readback = c.readback === true ? 'ok (byte-equal)' : c.readback === false ? 'MISMATCH (on-chain bytes differ)' : c.state === 'confirmed' ? 'not checked (operator)' : '-'
  return [
    `chain ${val(c.dest)}: ${asciiNetwork(String(c.network))}`,
    `  state: ${val(c.state)}`,
    `  address: ${val(c.address)}`,
    `  tx id: ${val(c.txId)}`,
    `  tx ids: ${c.txIds === null || c.txIds.length === 0 ? '-' : c.txIds.map((x) => esc(String(x))).join(' ')}`,
    `  block: ${val(c.block)}`,
    `  confirmations: ${val(c.confirmations)}`,
    `  readback: ${readback}`,
    `  fee paid: ${val(c.feePaid)}`,
    `  explorer: ${val(c.explorer)}`,
    `  bytes sha256: ${val(c.bytesSha256)}`,
    `  reason: ${val(c.reason)}`,
    `  updated: ${iso(c.updatedAt)}`,
  ].join('\n') + '\n'
}

const statusOf = (tr: Trigger): string => (tr.clearedAt === null ? `OPEN (${nonTerminal(tr)} of ${tr.chains.length} chains not terminal)` : 'CLEARED')

// One line per trigger (the CLI's `triggers list`).
export function summarizeTrigger(tr: Trigger): string {
  return `${val(tr.id)}  ${val(tr.profile)}  ${val(tr.source)}  ${statusOf(tr)}  ${tr.chains.map((c) => `${val(c.dest)}=${val(c.state)}`).join(' ')}`
}

export function renderTraceText(tr: Trigger): string {
  const status = tr.clearedAt === null ? statusOf(tr) : `CLEARED ${iso(tr.clearedAt)} by ${val(tr.clearedBy)}`
  return [
    `trigger ${val(tr.id)}`,
    `profile: ${val(tr.profile)}`,
    `source: ${val(tr.source)} (ref ${val(tr.ref)})`,
    `created: ${iso(tr.createdAt)}`,
    `payload sha256: ${val(tr.payloadSha256)}`,
    `status: ${status}`,
    '',
    tr.chains.map(renderChainText).join('\n'),
    `trace sha256: ${val(tr.traceSha256)}`,
  ].join('\n') + '\n'
}

// packages/core/src/gates/caps.ts — the R60 hard spend cap, enforced by the engine (spec §5.4, §13).
//
// Invariant: on every path that signs, spent + held + the worst case of the signature about to be made never exceeds
// the cap the chain was ARMED with (ArmRecord.caps[chain].nativeCap, base units; the typed over-R60 amount of the arm
// is already folded into it). Base units (bigint) only: no float, no mixed units.
//   · spent = the fee of every landed job attempt (its journaled fee, or its worst case when the journal has none) +
//     the fee of every claw-back that landed or failed on chain + the VALUE of a landed claw-back. Data txs carry value
//     0 (chains/eth.js refuses anything else).
//   · held = per (copy, part) the LARGEST worst case of its attempts that may still land (a same-nonce bump family or a
//     SOL re-sign: at most one lands, so the max, never the sum) + the claw-back in progress: the largest value +
//     worst-case fee of its open members.
//
// The ledger follows the journal and the chain evidence it records (security review "cap-ledger drift"): it is a fold
// over the SAME events, with the SAME steps, as the reducer (job/reduce.ts attemptStep, memberStep, worstFeeOf). A
// ledger is built only by fromArmed() from the reduced job state and then observes every event its runner journals
// (engine.js jappend / jintent call observe() after the API acked it). So a ledger rebuilt from the journal (a
// takeover, a reload) holds exactly the numbers of the live one, and every reservation is released or converted
// exactly once:
//   · an attempt that lands → its actual fee (the receipt's, journaled with included) is spent; the group's hold goes;
//     a claw-back that lands → its fee and the value the chain moved are spent;
//   · an attempt proven dead by chain evidence (reconcile expired / nonce-consumed) → released; a `sent rejected` or a
//     resolve mark-failed is a claim and keeps its hold until that evidence or a landing in its group (S2 2fea217);
//   · a claw-back that failed on chain → only the fee it was charged; every member dead and none landed → released
//     (the reducer fails the claw-back by itself: nothing in flight never stays locked, E2 re-review D-2);
//   · stuck and unknown attempts keep their reservation (fail closed) until a reconcile (the next run reconciles every
//     open intent from chain evidence before anything else) or the operator's resolve records an outcome — the
//     refusals name that exit.
// The only extra live state is the reservation of the signature being made (reserve / reserveClawback), replaced by
// the attempt's own hold when its intent is acked.
//
//   engine.cap            spent + held + this signature's worst case > cap (or malformed amounts) — every signature
//   engine.cap-copy       spent + held + the next copy's worst case > cap — before a copy (or a resumed copy) starts
//   engine.cap-clawback   spent + held + the claw-back's value + worst-case fee > cap and no typed amount equal to it,
//                         or a typed amount that is not exactly that (contracts/types.ts claw-back note, CC-2a)
//   engine.cap-armed      no armed cap for this chain, a malformed cap, spend or open attempt, a corrupt journal, a
//                         state for another key, a claw-back in progress (an open member), or an event the ledger
//                         cannot account for
//   engine.cap-busy       another lane or claw-back already holds this chain's key in this process, or another
//                         signature of the same (copy, part) is being made
//   engine.cap-ledger     a signing path was called without a ledger built by fromArmed
// (engine.cap is a contract id; the other five are lane-internal ids, in the contracts union since CC-1.)
import { refuse } from '../contracts/index.ts'
import type { AttemptState, Chain, ClawbackConfirm, JobState } from '../contracts/index.ts'
import { HELD_ATTEMPT, LANDED_ATTEMPT, OPEN_ATTEMPT, attemptStep, memberStep, worstFeeOf } from '../job/reduce.ts'

// What the cap holds (S2 security fix 2fea217, relayed by the controller): ONLY CHAIN EVIDENCE frees capacity — a
// landing in the group (with its real fee), or a reconcile expired / nonce-consumed of that attempt. An attempt journaled
// `sent rejected` or resolved mark-failed is a claim, not evidence: it stays held, like an open one. One definition
// with the reducer's held() (job/reduce.ts HELD_ATTEMPT).
const HELD: ReadonlySet<AttemptState> = HELD_ATTEMPT

const units = (v: unknown): v is bigint => typeof v === 'bigint' && v >= 0n
const DEC = /^(?:0|[1-9][0-9]{0,77})$/
const dec = (v: unknown): bigint | null => (typeof v === 'string' && DEC.test(v) ? BigInt(v) : null)
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v)
const EXIT = 'they stay held until chain evidence frees them: a landing, or a reconcile expired / nonce-consumed — the next run (vt job run or Run here) reconciles every attempt that may still land first; a STUCK one needs the operator (vt job resolve <job> --chain <c> --tx <txId> mark-done|mark-failed) so the run can reconcile or replace it'

export function assertWithinCap(spent: bigint, reserve: bigint, cap: bigint): void {
  const typed = units(spent) && units(reserve) && units(cap)
  const ok = typed && spent + reserve <= cap
  const why = typed ? `spend cap: ${spent} + ${reserve} would exceed the lane cap ${cap} (base units)` : 'spend cap: the lane cap is missing or malformed'
  if (!ok) refuse('engine.cap', why) // @guard:engine.cap
}

const ACTIVE = new Set<string>()
const TOKEN = Symbol('CapLedger')
const CLAW = 'claw-back'

interface Att { state: AttemptState; worst: bigint | null }
interface Group { copy: number; part: number; atts: Map<string, Att>; pending: bigint; owner: unknown }   // owner: the tx being signed
interface Member { state: 'open' | 'dead'; value: string; fee: bigint; hold: bigint }   // hold = value + worst-case fee
// The claw-back family the ledger can account for: one started after the ledger was built (members known).
interface Claw { members: Map<string, Member>; landed: boolean; charged: Set<string> }   // held: its open members (none once landed or all dead)
type Ev = { type?: unknown; chain?: unknown; [k: string]: unknown }

// The ledger's view of a reduced chain (for fromArmed and for tests: live and rebuilt ledgers must agree on it).
export interface CapView { spent: bigint; held: bigint }

export class CapLedger {
  readonly chain: Chain
  readonly #cap: bigint
  #spent: bigint
  #groups = new Map<string, Group>()
  #byTx = new Map<string, Group>()
  #claw: Claw | null = null
  #clawPending = 0n
  #before: { landed: boolean } | null       // the claw-back family settled before this ledger was built (members unknown)
  #poisoned: string | null = null
  #key: string
  #closed = false

  constructor(token: symbol, chain: Chain, cap: bigint, spent: bigint, groups: Map<string, Group>, before: { landed: boolean } | null, key: string) {
    if (token !== TOKEN) throw new TypeError('CapLedger: use CapLedger.fromArmed(state, chain, address)')
    this.chain = chain; this.#cap = cap; this.#spent = spent; this.#groups = groups; this.#before = before; this.#key = key
    for (const g of groups.values()) for (const id of g.atts.keys()) this.#byTx.set(id, g)
    Object.freeze(this)
  }

  // The ledger of `chain` for the key `address`, from the job state reduced from the journal.
  static fromArmed(state: JobState, chain: Chain, address: string): CapLedger {
    const v = CapLedger.#read(state, chain, address)
    if (!v.ok) refuse('engine.cap-armed', v.why) // @guard:engine.cap-armed
    const key = `${chain}:${String(address).toLowerCase()}`
    assertFree(!ACTIVE.has(key), `another lane or claw-back already holds this ${chain} key in this process`)
    ACTIVE.add(key)
    return new CapLedger(TOKEN, chain, v.cap, v.spent, v.groups, v.before, key)
  }

  // Pure read of the state (no ledger, no hold on the key): the ledger's spent and held, or why none can be built.
  static view(state: JobState, chain: Chain, address: string): CapView {
    const v = CapLedger.#read(state, chain, address)
    if (!v.ok) refuse('engine.cap-armed', v.why)
    let held = 0n
    for (const g of v.groups.values()) held += holdOf(g)
    return { spent: v.spent, held }
  }

  static #read(state: JobState, chain: Chain, address: string):
    { ok: true; cap: bigint; spent: bigint; groups: Map<string, Group>; before: { landed: boolean } | null } | { ok: false; why: string } {
    const bad = (why: string): { ok: false; why: string } => ({ ok: false, why })
    if (state?.corrupt != null || state?.phase === 'CORRUPT') return bad('the journal is corrupt: nothing is signed')
    const cap = dec(state?.armed?.schedule?.order?.includes(chain) ? state.armed.caps?.[chain]?.nativeCap : undefined)
    const cs = state?.chains?.[chain]
    const spent0 = dec(cs?.spent)
    if (cap === null || cs === undefined || spent0 === null) return bad(`no armed spend cap for ${chain} in the job state (or a malformed cap or spend)`)
    if (typeof address !== 'string' || address.length === 0) return bad('a key address is required')
    const same = cs.address === null || (chain === 'eth' ? cs.address.toLowerCase() === address.toLowerCase() : cs.address === address)
    if (!same) return bad(`the job state is for another ${chain} key`)
    const groups = new Map<string, Group>()
    const jobOpen = new Set<string>()
    for (const t of cs.txs ?? []) {
      const g: Group = { copy: t.copy, part: t.part, atts: new Map(), pending: 0n, owner: null }
      for (const a of t.attempts ?? []) {
        const worst = worstFeeOf(a)
        if (OPEN_ATTEMPT.has(a.state)) jobOpen.add(a.txId)
        if (HELD.has(a.state) && t.state !== 'included' && worst === null) return bad(`an attempt that may still land without fee data (${a.txId}): its worst case is unknown`)
        g.atts.set(a.txId, { state: a.state, worst })
      }
      groups.set(`${t.copy}:${t.part}`, g)
    }
    const clawOpen = (cs.openIntents ?? []).filter((id) => !jobOpen.has(id))
    if (clawOpen.length > 0) {
      return bad(`a claw-back is in progress (open: ${clawOpen.join(', ')}): reconcile it first — the next run (vt job run, vt job clawback or Run here) settles it from chain evidence (clawback-included, or clawback-failed when every member is proven dead); if the chain cannot decide, the operator resolves each open member (vt job resolve <job> --chain ${chain} --tx <txId> mark-failed)`)
    }
    const c = cs.clawback
    const value = c !== null && c.landed === true ? dec(c.value) : 0n
    if (value === null) return bad('a landed claw-back with a malformed value')
    return { ok: true, cap, spent: spent0 + value, groups, before: c === null ? null : { landed: c.landed === true } }
  }

  get cap(): bigint { return this.#cap }
  get spent(): bigint { return this.#spent }
  get held(): bigint {
    let s = this.#clawHold()
    for (const g of this.#groups.values()) s += holdOf(g)
    return s
  }
  get remaining(): bigint { return this.#cap - this.#spent - this.held }
  // Why this ledger refuses everything (an event it cannot account for, or an intent without fee data), or null.
  get poisoned(): string | null { return this.#poisoned }
  // Nothing may still land: no open attempt, no open claw-back member and no reservation being signed.
  get idle(): boolean { return this.held === 0n }
  // The journal records an inclusion of this (copy, part): its spend is counted. A runner that sees a tx confirmed
  // without it stops (fail closed: the ledger counts only journaled spend).
  landed(tx: { copy: unknown; part: unknown }): boolean {
    const g = this.#groups.get(`${String(tx?.copy)}:${String(tx?.part)}`)
    return g !== undefined && [...g.atts.values()].some((a) => LANDED_ATTEMPT.has(a.state))
  }

  #clawHold(): bigint {
    let m = this.#clawPending
    if (this.#claw !== null) for (const x of this.#claw.members.values()) if (x.state === 'open' && x.hold > m) m = x.hold
    return m
  }
  #heldOpen(): string {
    const ids: string[] = []
    for (const g of this.#groups.values()) if (!landedOf(g)) for (const [id, a] of g.atts) if (HELD.has(a.state)) ids.push(id)
    if (this.#claw !== null) for (const [id, x] of this.#claw.members) if (x.state === 'open') ids.push(id)
    return ids.length === 0 ? '' : ` ${this.held} base units are held by attempt(s) that may still land (${ids.slice(0, 4).join(', ')}${ids.length > 4 ? ', …' : ''}): ${EXIT}.`
  }
  #usable(): boolean { return !this.#closed && this.#poisoned === null }

  // Before a copy starts: its worst case must fit beside everything spent and held (nothing is reserved).
  check(amount: bigint): void {
    const ok = this.#usable() && units(amount) && this.#spent + this.held + amount <= this.#cap
    if (!ok) refuse('engine.cap-copy', `spend cap: the next copy's worst case ${String(amount)} does not fit the ${this.remaining} base units left of the cap ${this.#cap}.${this.#heldOpen()}${this.#poisoned ?? ''}`) // @guard:engine.cap-copy
  }

  // Before every signature of a lane tx (copy, part): reserve its worst case. The group's hold is the largest of its
  // attempts that may still land and this one; the reservation becomes the attempt's own hold when its intent is acked.
  reserve(tx: { copy: unknown; part: unknown }, amount: bigint): void {
    if (!this.#usable()) throw new TypeError(`CapLedger: ${this.#closed ? 'closed' : 'poisoned'}`)
    const key = `${String(tx?.copy)}:${String(tx?.part)}`
    const g = this.#groups.get(key) ?? { copy: Number(tx?.copy), part: Number(tx?.part), atts: new Map<string, Att>(), pending: 0n, owner: null }
    assertFree(g.owner === null || g.owner === tx, `another signature of copy ${String(tx?.copy)} part ${String(tx?.part)} is being made in this process`)
    const before = holdOf(g), after = holdOf({ ...g, pending: units(amount) ? amount : 0n })
    const landed = [...g.atts.values()].some((a) => LANDED_ATTEMPT.has(a.state))
    if (landed) throw new TypeError(`CapLedger: copy ${String(tx?.copy)} part ${String(tx?.part)} already landed: it is never signed again`)
    try { assertWithinCap(this.#spent + this.held - before, units(amount) ? after : -1n, this.#cap) } catch (e) {
      const ex = e as Error; ex.message += this.#heldOpen(); throw ex
    }
    g.pending = amount; g.owner = tx
    this.#groups.set(key, g)
  }

  // Before a claw-back is signed (each bump or re-sign): its value + worst-case fee must fit beside everything spent and
  // held (the family is held at its largest member), or the operator typed exactly that amount (CC-2a).
  reserveClawback(amount: bigint, confirm?: ClawbackConfirm | null): void {
    const prev = this.#clawHold()
    const next = units(amount) && amount > prev ? amount : prev
    const typed = confirm === undefined || confirm === null ? null : isObj(confirm) && Object.keys(confirm).length === 1 && typeof confirm.amount === 'string' ? confirm.amount : false
    const fits = units(amount) && this.#spent + this.held - prev + next <= this.#cap
    const ok = this.#usable() && units(amount) && (typed === null ? fits : typed === String(amount))
    const why = typed === null
      ? `spend cap: the claw-back is over the armed cap — the operator may type exactly ${String(amount)} (its value + worst-case fee, base units) to confirm that one claw-back; ${this.remaining} of the cap ${this.#cap} are left.${this.#heldOpen()}`
      : 'the typed claw-back amount is not exactly value + worst-case fee of this claw-back (base units)'
    if (!ok) refuse('engine.cap-clawback', `${why}${this.#poisoned ?? ''}`) // @guard:engine.cap-clawback
    this.#clawPending = amount
  }

  // Fold one journaled event (flat { type, chain, ...data }, as the engine journals it) into the ledger — the reducer's
  // steps exactly. Events of another chain and on a closed ledger change nothing.
  observe(ev: Ev): void {
    if (this.#closed || !isObj(ev) || ev.chain !== this.chain) return
    const type = typeof ev.type === 'string' ? ev.type : ''
    const d = ev as Record<string, unknown>
    const tx = typeof d.txId === 'string' ? d.txId : null
    if (type === 'intent') return this.#intent(d, tx)
    if (type === 'clawback-intent') return this.#clawIntent(d, tx)
    if (tx === null) return
    const g = this.#byTx.get(tx)
    // the reducer's order: a job attempt first (sent, reconcile, included, resolved), else a claw-back member
    if (g !== undefined && (type === 'sent' || type === 'reconcile' || type === 'included' || type === 'resolved')) {
      const a = g.atts.get(tx)!
      const s = attemptStep(a.state, type, d, g)
      if (s.land !== null) {
        for (const x of g.atts.values()) if (x !== a && OPEN_ATTEMPT.has(x.state)) x.state = 'superseded'
        a.state = s.land.as
        this.#spent += dec(s.land.fee) ?? a.worst ?? 0n
        g.pending = 0n; g.owner = null
      } else if (s.to !== null) a.state = s.to
      return
    }
    if (type !== 'reconcile' && type !== 'resolved' && type !== 'clawback-included' && type !== 'clawback-failed') return
    const c = this.#claw
    if (c === null || !c.members.has(tx)) {
      // maybe a member of the claw-back family settled before this ledger was built (members unknown here): the reducer
      // may still land it or charge its fee (chain evidence wins), which this ledger cannot mirror — it refuses from here
      // on (fail closed; a new ledger built from the journal is exact)
      const settles = type === 'clawback-included' || (type === 'clawback-failed' && d.fee !== undefined) || (type === 'reconcile' && d.outcome === 'included')
      if (this.#before !== null && settles) this.#poisoned = ' An event of an earlier claw-back the ledger cannot account for was journaled: rebuild from the journal (start a new run).'
      return
    }
    const m = c.members.get(tx)!
    const s = memberStep(m.state, type, d)
    if (s === null) return
    if (c.landed) { if (!('land' in s)) { const f = dec(s.fee); if (f !== null) this.#charge(c, tx, f) } return }   // a failed-on-chain fee is spent even after the landing
    if ('land' in s) {                                              // chain evidence: the claw-back landed with this member
      const value = dec(s.land.value ?? m.value) ?? 0n
      c.landed = true
      for (const x of c.members.values()) x.state = 'dead'
      this.#charge(c, tx, dec(s.land.fee) ?? m.fee)
      this.#spent += value
      this.#clawPending = 0n
      return
    }
    m.state = s.to
    const fee = dec(s.fee)
    if (fee !== null) this.#charge(c, tx, fee)                      // a member that failed ON CHAIN was charged its fee
    // D-2: when every member is dead nothing of the family is held any more (the reducer fails it by itself)
  }

  #intent(d: Record<string, unknown>, tx: string | null): void {
    const copy = d.copy, part = d.part, parts = d.parts
    const ints = [copy, part, parts].every((x) => typeof x === 'number' && Number.isSafeInteger(x))
    if (tx === null || !ints || this.#byTx.has(tx)) return
    const key = `${String(copy)}:${String(part)}`
    let g = this.#groups.get(key)
    if (g === undefined) { g = { copy: copy as number, part: part as number, atts: new Map(), pending: 0n, owner: null }; this.#groups.set(key, g) }
    const worst = worstFeeOf(d)
    if (worst === null) this.#poisoned = ` An intent without fee data was journaled (${tx}): its worst case is unknown.`   // fromArmed refuses it too
    g.atts.set(tx, { state: 'intent', worst })
    g.pending = 0n; g.owner = null                                  // the reservation is now this attempt's own hold
    this.#byTx.set(tx, g)
  }
  #clawIntent(d: Record<string, unknown>, tx: string | null): void {
    const c = this.#claw
    if (tx === null) return
    if (c !== null ? c.landed || c.members.has(tx) : this.#before?.landed === true) return   // a landed claw-back is final
    const fee = worstFeeOf(d), value = typeof d.value === 'string' ? d.value : '0'
    if (fee === null || dec(value) === null) this.#poisoned = ` A claw-back intent without fee data or a decimal value was journaled (${tx}).`
    const m: Member = { state: 'open', value, fee: fee ?? 0n, hold: (dec(value) ?? 0n) + (fee ?? 0n) }
    if (c !== null) c.members.set(tx, m)                            // the one family of the chain: joins, re-opens a failed one
    else this.#claw = { members: new Map([[tx, m]]), landed: false, charged: new Set() }
    this.#clawPending = 0n
  }
  #charge(c: Claw, tx: string, fee: bigint): void {
    if (c.charged.has(tx)) return
    c.charged.add(tx); this.#spent += fee
  }

  // Release this process's hold on the key (the runner calls it when the lane or claw-back ends).
  close(): void { if (!this.#closed) { this.#closed = true; ACTIVE.delete(this.#key) } }
}

const landedOf = (g: Group): boolean => [...g.atts.values()].some((a) => LANDED_ATTEMPT.has(a.state))
// A group's hold: the largest of the reservation being signed and the worst case of every attempt that may still land —
// open, or rejected / resolved-failed until a landing or a reconcile expired / nonce-consumed (chain evidence). A landing
// supersedes its open siblings and frees the group's claims; an attempt still open in a landed group (the API refuses
// one) stays held.
function holdOf(g: Group): bigint {
  let m = g.pending
  const landed = landedOf(g)
  for (const a of g.atts.values()) if ((OPEN_ATTEMPT.has(a.state) || (!landed && HELD.has(a.state))) && (a.worst ?? 0n) > m) m = a.worst ?? 0n
  return m
}

// One marker for engine.cap-busy: one holder per key per process, one signature per (copy, part) at a time.
function assertFree(ok: boolean, why: string): void {
  if (!ok) refuse('engine.cap-busy', why) // @guard:engine.cap-busy
}

// The ledger a signing path must carry.
export function ledgerOf(o: { ledger?: unknown } | null | undefined): CapLedger {
  const l = o?.ledger
  const ok = l instanceof CapLedger
  if (!ok) refuse('engine.cap-ledger', 'no spend-cap ledger: a lane signs only with the cap of its armed job state') // @guard:engine.cap-ledger
  return l
}
// Fold a journaled event into the ledger the options carry (the engine's jappend / jintent call it after the API acked).
export function observeLedger(o: { ledger?: unknown } | null | undefined, ev: Ev): void {
  const l = o?.ledger
  if (l instanceof CapLedger) l.observe(ev)
}

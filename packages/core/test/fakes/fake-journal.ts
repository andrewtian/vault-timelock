// The jobs API in memory, with the contract's semantics (not a test file). ALL DATA IS SYNTHETIC.
//   · leases: one per (job, chain); live while now < expiresAt (TTL LEASE_TTL_MS on the shared clock); acquire →
//     lease.held while live, else gen = 1 + the highest journaled gen (lease-expired journaled for a lapsed one);
//     renew / release fenced by gen (lease.lost); every executor event needs the live gen (lease.stale);
//   · intents: validateEvent, reconcile-first (lease.reconcile-first: an earlier-gen open intent without a reconcile
//     from the live gen), assertIntentAllowed (job.state, by the SERVER clock), event.duplicate, the typed claw-back
//     amount (checkClawbackConfirm, arm.amount); every other executor event assertEventAllowed (job.state);
//   · Stop (S2 jobs.ts, PF-S fix round 3): after stop-requested (or on a stop-latched chain: a journaled `stopped` until the operator's
//     resume, PF-S fix round 5 — STUCK overlay or not) no intent at all (intent.after-stop), except the one reveal of a btc copy whose
//     commit is out;
//   · tickets: opaque, of the strict TICKET_PREFIX form (with q, CC-3a); POST …/tickets for a journaled open intent of this gen's
//     holder (ticket.not-intent, ticket.terminal; an earlier-gen intent needs its own reconcile first);
//   · serverNowMs = clock.now() + offset (a server clock that differs from the executor's).
// Test hooks: loseNextReply (the append is journaled but the reply is lost), apiEvent (operator / API lines), expire.
import { base64urlnopad } from '@scure/base'
import { LEASE_TTL_MS, Refusal, TICKET_PREFIX } from '../../src/contracts/index.ts'
import type { ArmRecord, Chain, ClawbackConfirm, Holder, JobDef, JobState, JournalClient, JournalEvent, LeaseGrant, OpenIntent, Status } from '../../src/contracts/index.ts'
import { assertEventAllowed, assertIntentAllowed, checkClawbackConfirm, createReducer, jobId, reduce, sha256Hex, validateEvent } from '../../src/job/index.ts'
import type { JobReducer } from '../../src/job/index.ts'
import { JournalUnreachable } from '../../src/executor/journal-client.ts'

export interface VClock { now(): number; sleep(ms: number): Promise<void>; jump(ms: number): void }
// Virtual time: sleep(ms) resolves when the virtual clock reaches now + ms; the clock jumps to the next timer once the
// event loop is idle (setImmediate), so waits cost no real time and stay ordered.
export function virtualClock(start = 1_791_504_000_000): VClock {
  let t = start, n = 0, armed = false
  const q: Array<{ at: number; seq: number; go: () => void }> = []
  const tick = (): void => {
    armed = false
    if (q.length === 0) return
    q.sort((a, b) => a.at - b.at || a.seq - b.seq)
    const x = q.shift()!
    if (x.at > t) t = x.at
    x.go(); arm()
  }
  const arm = (): void => { if (!armed && q.length > 0) { armed = true; setImmediate(tick) } }
  return { now: () => t, sleep: (ms) => new Promise<void>((go) => { q.push({ at: t + Math.max(0, ms), seq: n++, go }); arm() }), jump: (ms) => { t += ms } }
}

// q (CC-3a): the attempt's declared identity — the ETH nonce (decimal) or the SOL recentBlockhash of its intent
const declaredOf = (c: Chain, d: Record<string, unknown>): string => (c === 'eth' ? String((d.eth as { nonce?: unknown } | undefined)?.nonce) : String((d.sol as { blockhash?: unknown } | undefined)?.blockhash))
const HELD_STATES = new Set(['intent', 'sent', 'unknown', 'adopted', 'rejected', 'resolved-failed'])
// p: the journaled payloadSha256 of a job intent; to / value: a claw-back intent's destination and value (the real API binds them,
// api tickets.ts ticketBinding; the relay checks them against the signed tx)
const ticketOf = (o: { j: string; c: Chain; g: number; t: string; r: string; p?: unknown; to?: unknown; value?: unknown; q: string; e: number }): string =>
  `${TICKET_PREFIX}${base64urlnopad.encode(new TextEncoder().encode(JSON.stringify({ j: o.j, w: 'local', c: o.c, g: o.g, t: o.t, r: o.r, ...(typeof o.p === 'string' ? { p: o.p } : {}), ...(typeof o.to === 'string' ? { to: o.to } : {}), ...(typeof o.value === 'string' ? { value: o.value } : {}), q: o.q, e: o.e, n: '0'.repeat(16) })))}.${'A'.repeat(43)}`

export function fakeJournal(o: { def: JobDef; text: string; clock: VClock; network?: 'local' | 'testnet' | 'mainnet'; serverOffsetMs?: number }) {
  const def = o.def, id = jobId(def), network = o.network ?? def.network
  const events: JournalEvent[] = []
  const r: JobReducer = createReducer(def)
  const leases = new Map<Chain, { gen: number; holder: Holder; expiresAt: number; released: boolean }>()
  let lose = 0, offset = o.serverOffsetMs ?? 0
  const calls: string[] = []
  const serverNow = (): number => o.clock.now() + offset
  const push = (chain: Chain | null, by: JournalEvent['by'], gen: number | null, type: JournalEvent['type'], data: Record<string, unknown>): JournalEvent => {
    const e: JournalEvent = { v: 1, seq: events.length, at: serverNow(), prev: '', chain, by, gen, type, data: JSON.parse(JSON.stringify(data)) }
    events.push(e); r.apply(e)
    return e
  }
  push(null, 'api', null, 'created', { jobId: id, defSha256: sha256Hex(JSON.stringify(def)) })
  const state = (): JobState => r.state()
  const fail = (guard: string, why: string): never => { throw new Refusal(guard, why) }
  const live = (c: Chain): { gen: number; holder: Holder } | null => { const l = leases.get(c); return l && !l.released && serverNow() < l.expiresAt ? l : null }
  const maxGen = (c: Chain): number => events.filter((e) => e.chain === c && e.type === 'lease-acquired').reduce((m, e) => Math.max(m, e.data.gen as number), 0)
  const intentLine = (c: Chain, txId: string): JournalEvent | undefined => events.find((e) => e.chain === c && (e.type === 'intent' || e.type === 'clawback-intent') && e.data.txId === txId)
  const openIntents = (c: Chain): OpenIntent[] => state().chains[c]!.openIntents.map((txId) => {
    const e = intentLine(c, txId)!, d = e.data as Record<string, any>, claw = e.type === 'clawback-intent'
    return { txId, gen: e.gen!, copy: claw ? 0 : d.copy, part: claw ? 0 : d.part, attempt: claw ? 1 : d.attempt, ...(d.eth ? { eth: d.eth } : {}), ...(d.sol ? { sol: d.sol } : {}) }
  })
  const reconciled = (c: Chain, gen: number, txId: string): boolean => events.some((e) => e.chain === c && e.gen === gen && e.type === 'reconcile' && e.data.txId === txId)
  const grantOf = (c: Chain, l: { gen: number; holder: Holder; expiresAt: number }): LeaseGrant => ({ gen: l.gen, ttlMs: LEASE_TTL_MS, expiresAt: l.expiresAt, holder: l.holder, openIntents: openIntents(c) })
  const job = (jid: string) => { if (jid !== id) fail('job.missing', 'no such job'); return id }

  const client: JournalClient = {
    async status(): Promise<Status> { calls.push('status'); return { network, networks: {}, mainnetSends: 'LOCKED', jobSends: 'LOCKED', build: 'fake', confined: true, legacyLatch: 'clear', serverNowMs: serverNow() } },
    async job(jid) { calls.push('job'); job(jid); return { def, state: JSON.parse(JSON.stringify(state())) as JobState, seq: events.length - 1, serverNowMs: serverNow() } },
    async message(sha) { if (sha !== def.messageSha256) fail('message.missing', 'no such message'); return o.text },
    async lease(jid, c, op, holder, gen) {
      calls.push(`lease:${op}`); job(jid)
      const l = leases.get(c)
      if (op === 'acquire') {
        if (live(c)) fail('lease.held', 'another holder has a live lease')
        if (l && !l.released) push(c, 'api', l.gen, 'lease-expired', { gen: l.gen })
        const g = maxGen(c) + 1
        const nl = { gen: g, holder, expiresAt: serverNow() + LEASE_TTL_MS, released: false }
        leases.set(c, nl)
        push(c, 'api', g, 'lease-acquired', { gen: g, holder, ttlMs: LEASE_TTL_MS })
        return grantOf(c, nl)
      }
      const cur = live(c)
      if (!cur || cur.gen !== gen) fail('lease.lost', 'the lease is lost')
      if (op === 'renew') { l!.expiresAt = serverNow() + LEASE_TTL_MS; return grantOf(c, l!) }
      l!.released = true
      push(c, 'api', gen!, 'lease-released', { gen: gen! })
      return { ...grantOf(c, l!), ttlMs: 0, expiresAt: serverNow() }
    },
    async append(jid, c, gen, type, data, x?: { clawbackConfirm?: ClawbackConfirm }) {
      calls.push(`append:${type}`); job(jid)
      const l = live(c)
      if (!l || l.gen !== gen) fail('lease.stale', 'not the live generation')
      validateEvent(type, data, l!.holder)
      const send = type === 'intent' || type === 'clawback-intent'
      if (send) {
        for (const oi of openIntents(c)) if (oi.gen < gen && !reconciled(c, gen, oi.txId)) fail('lease.reconcile-first', 'reconcile the earlier generation\'s open intents first')
        if (type === 'intent' && (state().chains[c]!.stopRequested || r.stopLatched(c))) {   // S2 jobs.ts (PF-S fix rounds 3, 5): nothing new after a Stop (the latch, as the API reads it)
          // Eminors (E7b m-5 / E7-fix2 m-2), mirroring api jobs.ts strandedReveal (d8c6756): after a Stop the API admits exactly ONE btc reveal for a copy whose
          // commit is journaled (open or landed): the commit locked value only its reveal can move. A second reveal, a replacement and a new commit stay refused.
          const txs = state().chains[c]!.txs
          const strandedReveal = c === 'btc' && data.part === 2 && (data.btc as { kind?: string } | undefined)?.kind === 'reveal'
            && !txs.some((t) => t.copy === data.copy && t.part === 2 && t.attempts.length > 0)
            && txs.some((t) => t.copy === data.copy && t.part === 1 && t.attempts.some((a) => a.state === 'included' || a.state === 'resolved-done' || HELD_STATES.has(a.state) && a.state !== 'rejected' && a.state !== 'resolved-failed'))
          if (!strandedReveal) fail('intent.after-stop', 'stop requested: nothing new is signed after a Stop (no replacement, bump, next part or copy); only the reveal of a btc copy whose commit is out')
        }
        assertIntentAllowed(def, { reducer: r, corrupt: null }, c, serverNow(), type, type === 'intent' ? { copy: data.copy as number, part: data.part as number } : undefined)
        if (intentLine(c, data.txId as string) !== undefined) fail('event.duplicate', 'this txId is already journaled')
        if (type === 'clawback-intent') checkClawbackConfirm(state(), c, data, x?.clawbackConfirm)
      } else assertEventAllowed(def, { reducer: r, corrupt: null }, { chain: c, type, data })
      const e = push(c, l!.holder, gen, type as JournalEvent['type'], data)
      const out = send ? { seq: e.seq, ticket: ticketOf({ j: id, c, g: gen, t: data.txId as string, r: data.rawSha256 as string, p: data.payloadSha256, to: data.to, value: data.value, q: declaredOf(c, data), e: serverNow() + 120_000 }) } : { seq: e.seq }
      if (lose > 0) { lose--; throw new JournalUnreachable('the reply was lost (test)') }
      return out
    },
    async ticket(jid, c, gen, txId) {
      calls.push('ticket'); job(jid)
      const l = live(c)
      if (!l || l.gen !== gen) fail('lease.stale', 'not the live generation')
      const e = intentLine(c, txId)
      if (e === undefined) fail('ticket.not-intent', 'no journaled intent has that txId')
      if (!state().chains[c]!.openIntents.includes(txId)) fail('ticket.terminal', 'that intent is settled')
      if (e!.gen! < gen && !reconciled(c, gen, txId)) fail('lease.reconcile-first', 'reconcile that intent first')
      return ticketOf({ j: id, c, g: gen, t: txId, r: e!.data.rawSha256 as string, p: e!.data.payloadSha256, to: e!.data.to, value: e!.data.value, q: declaredOf(c, e!.data), e: serverNow() + 120_000 })
    },
    async skip(jid) {
      calls.push('skip'); job(jid)
      const a = state().armed
      if (a === null || serverNow() >= a.releaseAt) fail('job.state', 'Skip only during the countdown')
      push(null, 'api', null, 'skip', { releaseAt: serverNow() })
      return { releaseAt: serverNow() }
    },
    stream() { return () => {} },
  }
  return {
    client, id, events, calls, state,
    // API / operator lines
    apiEvent: (type: JournalEvent['type'], data: Record<string, unknown>, chain: Chain | null = null, by: JournalEvent['by'] = 'api') => push(chain, by, null, type, data),
    arm(order: Chain[], o2: { caps: Partial<Record<Chain, string>>; releaseAt: number; offsetSec?: Partial<Record<Chain, number>> }) {
      const rec: ArmRecord = { armedAt: o2.releaseAt - 15_000, releaseAt: o2.releaseAt, countdownSec: 15,
        schedule: { order, offsetSec: Object.fromEntries(order.map((c, i) => [c, o2.offsetSec?.[c] ?? i * 30])) },
        caps: Object.fromEntries(order.map((c) => [c, { nativeCap: o2.caps[c] ?? '1000000000000000000', usd: 0, priceAt: null, overCap: false, planned: '0' }])), sources: {} }
      push(null, 'api', null, 'armed', rec as unknown as Record<string, unknown>)
      return rec
    },
    // an executor line written by an earlier holder (journaled under that holder's gen, as the API would have)
    asHolder(gen: number, holder: Holder, chain: Chain, type: JournalEvent['type'], data: Record<string, unknown>) { validateEvent(type, data, holder); return push(chain, holder, gen, type, data) },
    loseNextReply: () => { lose++ },
    requestStop: (c: Chain) => push(null, 'api', null, 'stop-requested', { chain: c }),
    expire: (c: Chain) => { const l = leases.get(c); if (l) l.expiresAt = serverNow() },
    setOffset: (ms: number) => { offset = ms },
    serverNow,
    reduced: () => reduce(def, events),
    openIntents,
  }
}

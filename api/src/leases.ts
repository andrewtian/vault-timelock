// api/src/leases.ts — per-(job, chain) executor leases with fencing generations (spec §5.5; leases.json vectors).
//
//   · A lease is live while now < expiresAt (expiresAt = acquire/renew time + LEASE_TTL_MS). At expiresAt it is gone.
//   · acquire: lease.held while a live lease exists, whoever holds it. Otherwise gen = 1 + the highest gen journaled
//     (`lease-acquired` events written by the API), so generations survive an API restart. A previous lease that was
//     neither released nor journaled as expired gets `lease-expired {gen}` first, then `lease-acquired`. The grant is
//     handed out only after both lines are fsynced.
//   · renew (heartbeat) and release need the live gen, else lease.lost. Renew journals nothing; release journals
//     `lease-released`.
//   · assertLive: every executor event needs the live gen (lease.stale); it returns the holder (the event's `by`).
//   · assertReconciled: an `intent` / `clawback-intent` is refused (lease.reconcile-first) while an intent opened under
//     an earlier gen is still open without a `reconcile` journaled under the current gen. A fresh ticket for one
//     intent (`only`) needs just that intent reconciled, when it was opened under an earlier gen (adopted first).
//   · Refused steps journal nothing. Leases live in memory only: after a restart every lease is gone.
//
// Serialization: every lease operation, and every executor append (through run()), runs in one queue per job, so a
// lease decision always sees every earlier append, and a check (assertLive, assertReconciled) and the append it
// guards are never split by a takeover.
import { LEASE_TTL_MS } from '@vault-timelock/core/contracts'
import type { BtcIntent, Chain, EthIntent, Holder, JournalEvent, LeaseGrant, LeaseView, OpenIntent, SolIntent } from '@vault-timelock/core/contracts'
import { refuse } from 'vt-broadcast/src/guard.ts'
import type { Clock } from './clock.ts'
import type { Journal } from './journal.ts'

export const CHAINS: readonly Chain[] = ['eth', 'sol']

export interface Leases {
  acquire(jobId: string, chain: Chain, holder: Holder): Promise<LeaseGrant>
  renew(jobId: string, chain: Chain, gen: number): Promise<LeaseGrant>
  release(jobId: string, chain: Chain, gen: number): Promise<void>
  assertLive(jobId: string, chain: Chain, gen: number): Holder
  // only: check just this txId (a fresh ticket for one intent); otherwise every open intent of the chain.
  assertReconciled(jobId: string, chain: Chain, gen: number, only?: string): void
  view(jobId: string): Partial<Record<Chain, LeaseView | null>>
  // Runs fn in the job's queue (after every earlier lease operation and append has finished).
  run<T>(jobId: string, fn: () => Promise<T>): Promise<T>
}

interface Lease { holder: Holder; gen: number; expiresAt: number }

export function assertHolder(h: unknown): asserts h is Holder {
  const ok = h === 'browser' || h === 'cli'
  if (!ok) refuse('lease.holder', 'holder must be browser or cli') // @guard:lease.holder
}

const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined)

// The open intents of `chain` (S1's reading of the reducer semantics in contracts/types.ts; S2 injects core's reduce):
// attempts open while intent | sent accepted/unknown | adopted; closed by sent rejected, reconcile included / expired /
// nonce-consumed, included (which also supersedes the open siblings of its copy and part), resolved. A claw-back is
// open from clawback-intent until clawback-included, clawback-failed or a reconcile of it other than adopted; it is
// listed last, as copy 0, part 0. Order: (copy, part), then intent order.
export function openIntentsFromEvents(events: readonly JournalEvent[], chain: Chain): OpenIntent[] {
  interface Attempt { oi: OpenIntent; open: boolean; order: number }
  const attempts = new Map<string, Attempt>()
  const clawRef: { a: Attempt | null } = { a: null }
  const closeGroup = (copy: number, part: number): void => {
    for (const a of attempts.values()) if (a.oi.copy === copy && a.oi.part === part) a.open = false
  }
  for (const e of events) {
    if (e.chain !== chain) continue
    const d = e.data
    const txId = str(d.txId)
    if (txId === undefined) continue
    if (e.type === 'intent' && e.gen !== null) {
      const oi: OpenIntent = {
        txId, gen: e.gen, copy: Number(d.copy), part: Number(d.part), attempt: Number(d.attempt),
        ...(d.eth !== undefined ? { eth: d.eth as EthIntent } : {}), ...(d.sol !== undefined ? { sol: d.sol as SolIntent } : {}), ...(d.btc !== undefined ? { btc: d.btc as BtcIntent } : {}),
      }
      attempts.set(txId, { oi, open: true, order: attempts.size })
    } else if (e.type === 'clawback-intent' && e.gen !== null) {
      const oi: OpenIntent = {
        txId, gen: e.gen, copy: 0, part: 0, attempt: 1,
        ...(d.eth !== undefined ? { eth: d.eth as EthIntent } : {}), ...(d.sol !== undefined ? { sol: d.sol as SolIntent } : {}), ...(d.btc !== undefined ? { btc: d.btc as BtcIntent } : {}),
      }
      clawRef.a = { oi, open: true, order: 0 }
    } else if (e.type === 'clawback-included' || e.type === 'clawback-failed') {
      if (clawRef.a !== null && clawRef.a.oi.txId === txId) clawRef.a.open = false
    } else {
      const claw = clawRef.a
      const a = attempts.get(txId) ?? (claw !== null && claw.oi.txId === txId ? claw : undefined)
      if (a === undefined) continue
      if (e.type === 'sent' && d.outcome === 'rejected') a.open = false
      else if (e.type === 'reconcile') {
        if (d.outcome === 'adopted') a.open = true
        else if (d.outcome === 'included' && a !== claw) closeGroup(a.oi.copy, a.oi.part)
        else a.open = false
      } else if (e.type === 'included' && a !== claw) closeGroup(a.oi.copy, a.oi.part)
      else if (e.type === 'resolved') {
        if (d.action === 'mark-done' && a !== claw) closeGroup(a.oi.copy, a.oi.part)
        else a.open = false
      }
    }
  }
  const open = [...attempts.values()].filter((a) => a.open)
    .sort((x, y) => x.oi.copy - y.oi.copy || x.oi.part - y.oi.part || x.order - y.order)
    .map((a) => a.oi)
  const c = clawRef.a
  return c !== null && c.open ? [...open, c.oi] : open
}

// The reconciles journaled on `chain` under `gen`, by txId (a full scan; the API uses the job service's index).
export function reconciledFromEvents(events: readonly JournalEvent[], chain: Chain, gen: number): ReadonlySet<string> {
  const out = new Set<string>()
  for (const e of events) {
    if (e.chain === chain && e.type === 'reconcile' && e.gen === gen && typeof e.data.txId === 'string') out.add(e.data.txId)
  }
  return out
}

// openIntentsOf / reconciledOf answer from the job's current journal (the API: the job service's incremental index, so
// a lease check costs the same at any journal length; unit tests: the full scans above).
export function createLeases(o: {
  clock: Clock
  journalOf: (jobId: string) => Journal
  openIntentsOf: (jobId: string, chain: Chain) => OpenIntent[]
  reconciledOf: (jobId: string, chain: Chain, gen: number) => ReadonlySet<string>
}): Leases {
  const live = new Map<string, Lease>() // `${jobId}/${chain}` → the lease (live or lapsed)
  const queues = new Map<string, Promise<unknown>>()
  const keyOf = (jobId: string, chain: Chain): string => `${jobId}/${chain}`
  const isLive = (l: Lease | undefined, now: number): l is Lease => l !== undefined && now < l.expiresAt

  const run = <T>(jobId: string, fn: () => Promise<T>): Promise<T> => {
    const prev = queues.get(jobId) ?? Promise.resolve()
    const next = prev.then(fn, fn)
    const tail = next.then(() => undefined, () => undefined)
    queues.set(jobId, tail)
    void tail.then(() => { if (queues.get(jobId) === tail) queues.delete(jobId) })
    return next
  }

  const grant = (jobId: string, chain: Chain, l: Lease): LeaseGrant => ({
    gen: l.gen, ttlMs: LEASE_TTL_MS, expiresAt: l.expiresAt, holder: l.holder,
    openIntents: o.openIntentsOf(jobId, chain),
  })

  // The lease for (jobId, chain) when `gen` is its live generation; lease.lost otherwise.
  const liveWithGen = (jobId: string, chain: Chain, gen: number): Lease => {
    const l = live.get(keyOf(jobId, chain))
    const ok = isLive(l, o.clock.now()) && l.gen === gen
    if (!ok) refuse('lease.lost', 'this lease has expired or was taken over: stop starting new transactions') // @guard:lease.lost
    return l!
  }

  return {
    run,
    acquire: (jobId, chain, holder) => run(jobId, async () => {
      assertHolder(holder)
      const key = keyOf(jobId, chain)
      const free = !isLive(live.get(key), o.clock.now())
      if (!free) refuse('lease.held', 'another executor holds this lease') // @guard:lease.held
      const journal = o.journalOf(jobId)
      let maxGen = 0
      let dangling: number | null = null
      for (const e of journal.all()) {
        if (e.chain !== chain || e.by !== 'api' || e.gen === null) continue
        if (e.type === 'lease-acquired') { maxGen = Math.max(maxGen, e.gen); dangling = e.gen }
        else if ((e.type === 'lease-released' || e.type === 'lease-expired') && e.gen === dangling) dangling = null
      }
      if (dangling !== null) await journal.append({ chain, by: 'api', gen: dangling, type: 'lease-expired', data: { gen: dangling } })
      const gen = maxGen + 1
      await journal.append({ chain, by: 'api', gen, type: 'lease-acquired', data: { gen, holder, ttlMs: LEASE_TTL_MS } })
      const lease: Lease = { holder, gen, expiresAt: o.clock.now() + LEASE_TTL_MS }
      live.set(key, lease)
      return grant(jobId, chain, lease)
    }),
    renew: (jobId, chain, gen) => run(jobId, async () => {
      const l = liveWithGen(jobId, chain, gen)
      const renewed: Lease = { ...l, expiresAt: o.clock.now() + LEASE_TTL_MS }
      live.set(keyOf(jobId, chain), renewed)
      return grant(jobId, chain, renewed)
    }),
    release: (jobId, chain, gen) => run(jobId, async () => {
      liveWithGen(jobId, chain, gen)
      await o.journalOf(jobId).append({ chain, by: 'api', gen, type: 'lease-released', data: { gen } })
      live.delete(keyOf(jobId, chain))
    }),
    assertLive(jobId, chain, gen) {
      const l = live.get(keyOf(jobId, chain))
      const ok = isLive(l, o.clock.now()) && l.gen === gen
      if (!ok) refuse('lease.stale', 'this generation does not hold the live lease: nothing is journaled') // @guard:lease.stale
      return l!.holder
    },
    assertReconciled(jobId, chain, gen, only) {
      const reconciled = o.reconciledOf(jobId, chain, gen)
      const ok = o.openIntentsOf(jobId, chain).every((oi) => (only !== undefined && oi.txId !== only) || oi.gen >= gen || reconciled.has(oi.txId))
      if (!ok) refuse('lease.reconcile-first', 'journal a reconcile for every open intent of an earlier generation first') // @guard:lease.reconcile-first
    },
    view(jobId) {
      const now = o.clock.now()
      const out: Partial<Record<Chain, LeaseView | null>> = {}
      for (const c of CHAINS) {
        const l = live.get(keyOf(jobId, c))
        out[c] = isLive(l, now) ? { holder: l.holder, gen: l.gen, expiresAt: l.expiresAt } : null
      }
      return out
    },
  }
}

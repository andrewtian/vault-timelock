// packages/core/src/executor/lease.ts — the executor's lease (spec §5.5): acquire, a heartbeat every LEASE_RENEW_MS,
// release. Fail closed: the lease counts as LOST — and no new tx may start — as soon as
//   · a renew is refused (lease.lost, lease.stale, lease.holder: a takeover happened, or the gen is wrong), or
//   · no renew was acknowledged before the local deadline: the TTL counted from BEFORE the last acknowledged request
//     was sent (local clock; the API's expiresAt is server time and is not compared across clocks).
// Each tick also reports the job back (onTick): the executor follows stop requests made elsewhere (the API's stop).
import { LEASE_RENEW_MS, isRefusal } from '../contracts/index.ts'
import type { Chain, Holder, JournalClient, LeaseGrant } from '../contracts/index.ts'

export interface Clock { now(): number; sleep(ms: number): Promise<void> }
export interface Lease {
  acquire(): Promise<LeaseGrant>
  readonly gen: number
  alive(): boolean                      // held, and its local deadline not passed
  lost(): string | null                 // why it is lost (or null)
  release(): Promise<void>
  stop(): void                          // stop the heartbeat (no release)
}

const LOST = new Set(['lease.lost', 'lease.stale', 'lease.holder'])

export function createLease(o: { journal: JournalClient; jobId: string; chain: Chain; holder: Holder; clock: Clock; renewMs?: number; onTick?: () => Promise<void> | void; onLost?: (why: string) => void }): Lease {
  const renewMs = o.renewMs ?? LEASE_RENEW_MS
  let gen = 0, deadline = 0, lostWhy: string | null = null, running = false, released = false
  const lose = (why: string): void => { if (lostWhy === null) { lostWhy = why; running = false; o.onLost?.(why) } }
  async function beat(): Promise<void> {
    while (running) {
      await o.clock.sleep(renewMs)
      if (!running) return
      const t0 = o.clock.now()
      try {
        const g = await o.journal.lease(o.jobId, o.chain, 'renew', o.holder, gen)
        if (g.gen !== gen) { lose(`the renewed lease has another generation (${g.gen} ≠ ${gen})`); return }
        deadline = t0 + g.ttlMs
      } catch (e) {
        if (isRefusal(e) && LOST.has(e.guardId)) { lose(`${e.guardId}: the lease was taken over or expired`); return }
      }
      // no answer (or another error): lost once the deadline passed — never revived by a later renew (fail closed)
      if (o.clock.now() >= deadline) { lose('no renewal was acknowledged before the lease deadline'); return }
      try { await o.onTick?.() } catch { /* the tick is advisory */ }
    }
  }
  return {
    async acquire() {
      const t0 = o.clock.now()
      const g = await o.journal.lease(o.jobId, o.chain, 'acquire', o.holder)
      gen = g.gen; deadline = t0 + g.ttlMs; running = true
      void beat()
      return g
    },
    get gen() { return gen },
    alive: () => lostWhy === null && !released && gen > 0 && o.clock.now() < deadline,
    lost: () => lostWhy ?? (gen > 0 && !released && o.clock.now() >= deadline ? 'the lease deadline passed' : null),
    async release() {
      running = false
      if (released || gen === 0) return
      released = true
      try { await o.journal.lease(o.jobId, o.chain, 'release', o.holder, gen) } catch { /* expiry frees it anyway */ }
    },
    stop() { running = false },
  }
}

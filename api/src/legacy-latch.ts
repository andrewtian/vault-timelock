// api/src/legacy-latch.ts — the legacy T1 trigger latch, read-only (spec §12; canonical note on the T1 fix round).
//
// The API calls broadcast's PLAIN "any trigger open" query, assertNoUncleared(ctx) WITHOUT { continuing }: jobs never
// open or continue a T1 trigger, so any uncleared legacy trigger blocks every job send. It is checked at arm, before
// every intent / claw-back intent is acknowledged and before every fresh send ticket, and reported by GET /status.
//
// Fail closed: every way the query does not pass is `trigger.uncleared` (423) — an open latch or record, a malformed
// latch, a tampered or unreadable record, a loose lifecycle/ directory (store.perms), a missing trigger store next to a
// keystore, or any I/O error. Under the API's sandbox profile $OUT is readable and not writable: the one write the query
// can attempt (resetting a latch that names an already-cleared record, after clearTrigger crashed between its two
// steps) fails there, and that too counts as uncleared until the operator's own tools reset it.
//
// $OUT is VAULT_TIMELOCK_DIR's rule (broadcast resolveOut); main.ts passes it, tests pass a temp dir. Nothing here is
// created, and nothing reads $OUT before the first request.
import { refuse } from 'vt-broadcast/src/guard.ts'
import { createStore } from 'vt-broadcast/src/lifecycle/store.ts'
import { assertNoUncleared } from 'vt-broadcast/src/lifecycle/triggers.ts'

export interface LegacyLatch {
  // True only when the query passed.
  clear(): Promise<boolean>
  // trigger.uncleared unless the query passed.
  assertClear(): Promise<void>
}

export function createLegacyLatch(out: string): LegacyLatch {
  const ctx = { out, store: createStore(out, { log: () => {} }) }
  const clear = async (): Promise<boolean> => {
    try {
      await assertNoUncleared(ctx)
      return true
    } catch {
      return false
    }
  }
  return {
    clear,
    async assertClear() {
      const ok = await clear()
      if (!ok) refuse('trigger.uncleared', 'a legacy trigger is not cleared (or the latch cannot be read): job sends are blocked until it is cleared with vt-broadcast triggers') // @guard:trigger.uncleared
    },
  }
}

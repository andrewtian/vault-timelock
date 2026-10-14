// packages/core/src/executor/adapters/browser.ts — the page's executor adapter: the wall clock, a CSPRNG and the
// same-origin clients (the page server proxies /api/* with its token and /relay/* to this network's relay; the page
// never holds the API token). No node: imports (spec §7.1).
import { httpJournalClient } from '../journal-client.ts'
import type { Fetch } from '../journal-client.ts'
import { httpRelayClient } from '../relay-client.ts'

export function browserAdapter(): { clock: { now(): number; sleep(ms: number): Promise<void> }; random: { int(maxExclusive: number): number } } {
  return {
    clock: { now: () => Date.now(), sleep: (ms) => new Promise((r) => setTimeout(r, Math.max(0, ms))) },
    random: { int: (max) => uniform(max) },
  }
}
// A uniform integer in [0, max) from crypto.getRandomValues (rejection sampling: no modulo bias).
export function uniform(max: number): number {
  if (!(Number.isSafeInteger(max) && max > 0 && max <= 2 ** 32)) throw new RangeError('random.int: 0 < max ≤ 2^32')
  const lim = Math.floor(2 ** 32 / max) * max, b = new Uint32Array(1)
  for (;;) { globalThis.crypto.getRandomValues(b); if (b[0] < lim) return b[0] % max }
}
export function browserClients(o: { fetch?: Fetch } = {}) {
  const f: Fetch = o.fetch ?? ((url, init) => globalThis.fetch(url, init))
  return { journal: httpJournalClient({ base: '/api', fetch: f }), relay: httpRelayClient({ base: '', fetch: f }) }
}

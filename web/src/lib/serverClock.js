// The API's clock in the page (W3). Countdowns and start times follow the server (serverNowMs of GET /api/jobs/:id),
// never the local wall clock: between syncs the elapsed time comes from a MONOTONIC clock (performance.now), so a local
// clock jump (NTP step, manual change, sleep) moves nothing, and a re-sync makes the countdown jump to the server's
// answer. Before the first sync now() is null: nothing that waits on the server's time may complete.
export function createServerClock({ perf = () => performance.now() } = {}) {
  let base = null           // { serverMs, perfMs } of the latest sync
  const subs = new Set()
  return {
    // A reply's serverNowMs; sentPerf (optional, perf() before the request) takes half the round trip into account.
    sync(serverNowMs, sentPerf = null) {
      if (typeof serverNowMs !== 'number' || !Number.isFinite(serverNowMs)) return
      const now = perf()
      const rtt = typeof sentPerf === 'number' && now >= sentPerf ? now - sentPerf : 0
      base = { serverMs: serverNowMs + rtt / 2, perfMs: now }
      for (const f of subs) f()
    },
    synced: () => base !== null,
    now: () => (base === null ? null : base.serverMs + (perf() - base.perfMs)),
    subscribe(f) { subs.add(f); return () => subs.delete(f) },
  }
}

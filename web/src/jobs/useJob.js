// One job, live (W3): GET /api/jobs/:id (definition, state, lease holders, the API's clock) and the journal over SSE
// from seq 0, folded in the page by core's own reducer (createReducer: the same fold the API serves, O(1) per line).
// The page shows the folded state once it has caught up with the GET; until then (and whenever the API reports the
// journal CORRUPT) it shows the API's state. The GET is repeated every pollMs and at once after a lease line, for the
// lease holders (browser / cli, no host details) and to re-sync the server clock.
// Per chain the stream also keeps what the state does not: when each part landed (progress and ETA), the reassembled
// sha256 per copy, and the latest note.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { P } from '@vault-timelock/core/contracts'
import { createReducer } from '@vault-timelock/core/job'
import { api } from '@/lib/api.js'
import { subscribe } from '@/lib/sse.js'
import { createServerClock } from '@/lib/serverClock.js'

const LEASE_LINES = new Set(['lease-acquired', 'lease-released', 'lease-expired'])
const emptyExtras = () => ({ landed: [], sha: new Map(), note: '', lastAt: null })

export function useJob(id, { pollMs = 5000, flushMs = 100, clock: injected = null, sseFetch = undefined } = {}) {
  const clock = useMemo(() => injected || createServerClock(), [injected])
  const [snap, setSnap] = useState(null)               // { def, state, leases, seq }
  const [error, setError] = useState(null)
  const [stream, setStream] = useState('connecting')
  const [, setVer] = useState(0)
  const live = useRef(null)                             // { reducer, applied, extras: { eth, sol } }
  const defRef = useRef(null)
  const timers = useRef({ flush: null, refresh: null })

  const refresh = useCallback(async () => {
    const sent = typeof performance === 'undefined' ? null : performance.now()
    try {
      const j = await api(P.job(id))
      clock.sync(j.serverNowMs, sent)
      defRef.current = j.def
      setSnap({ def: j.def, state: j.state, leases: j.leases || {}, seq: j.seq })
      setError(null)
    } catch (e) { setError({ guard: e.guard || 'api.http', message: e.message }) }
  }, [id, clock])

  // the GET: at once, every pollMs, and soon after a lease line
  useEffect(() => {
    let dead = false
    live.current = null; defRef.current = null; setSnap(null); setError(null)
    const tick = () => { if (!dead) refresh() }
    tick()
    const poll = setInterval(tick, pollMs)
    return () => { dead = true; clearInterval(poll) }
  }, [id, pollMs, refresh])

  // the journal over SSE from seq 0, as soon as the definition is known (the reducer needs it)
  const hasDef = snap !== null
  useEffect(() => {
    if (!hasDef || defRef.current === null) return undefined
    let dead = false
    const t = timers.current
    const def = defRef.current
    const flush = () => { t.flush = null; if (!dead) setVer((v) => v + 1) }
    const soon = () => { clearTimeout(t.refresh); t.refresh = setTimeout(() => { if (!dead) refresh() }, 50) }
    live.current = { reducer: createReducer(def), applied: -1, extras: Object.fromEntries(Object.keys(def.chains).map((c) => [c, emptyExtras()])) }
    const close = subscribe(id, 0, ({ event }) => {
      const L = live.current
      if (dead || !L || !event || typeof event.seq !== 'number' || event.seq <= L.applied) return
      L.reducer.apply(event); L.applied = event.seq
      const x = event.chain ? L.extras[event.chain] : null
      if (x) {
        x.lastAt = event.at
        const d = event.data || {}
        if (event.type === 'included') x.landed.push({ at: event.at, copy: d.copy, part: d.part })
        else if (event.type === 'reassembled' && typeof d.sha256 === 'string') x.sha.set(d.copy, d.sha256)
        else if (event.type === 'note' || event.type === 'paused' || event.type === 'stopped') x.note = String(d.text ?? d.reason ?? '')
      }
      if (LEASE_LINES.has(event.type)) soon()
      if (t.flush === null) t.flush = setTimeout(flush, flushMs)
    }, {
      ...(sseFetch ? { fetch: sseFetch } : {}),
      onState: (st) => { if (!dead) setStream(st) },
      onError: (e) => { if (!dead) setError({ guard: e.guard, message: `the journal stream stopped (${e.status})` }) },
    })
    return () => { dead = true; close(); clearTimeout(t.flush); clearTimeout(t.refresh); t.flush = null; live.current = null }
  }, [id, hasDef, flushMs, refresh, sseFetch])

  const L = live.current
  let state = snap?.state ?? null
  const caught = !!(L && snap && L.applied >= snap.seq)
  if (caught && snap.state.phase !== 'CORRUPT' && snap.state.corrupt === null) state = L.reducer.state()
  return {
    def: snap?.def ?? null, state, leases: snap?.leases ?? {}, seq: L ? Math.max(L.applied, snap?.seq ?? -1) : snap?.seq ?? -1,
    extras: L?.extras ?? {}, caught, stream, error, clock, refresh,
  }
}

// A lease is live while the API's now < expiresAt (spec §5.5); its holder is 'browser' or 'cli' (never a host).
export function liveLease(lease, serverNow) {
  return !!lease && typeof lease.expiresAt === 'number' && serverNow !== null && serverNow < lease.expiresAt ? lease : null
}

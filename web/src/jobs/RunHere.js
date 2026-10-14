// "Run here" (W3): the browser executor. One core createExecutor per (job, chain) with the browser adapter — the wall
// clock, a CSPRNG, and the same-origin clients httpJournalClient('/api') + httpRelayClient('' → /relay/*): the page server
// adds the API token and the page never holds it. The executor does everything that matters (spec §7.3): network and
// key checks before any lease, the lease and its heartbeat, reconcile before any new intent, the start by the API's
// clock, the pre-start check, the lane (a landed part is never sent again), Stop after the in-flight tx.
// This module only keeps the runs of this tab alive across route changes (RunsProvider, at the App level) and shows
// them: the latest ChainRunView, the outcome, the refusal (lease.held → another holder runs it), and the time of the
// latest passing real-byte simulation (Skip needs it fresh on every armed chain).
//   · the key is the KeyStore's in-memory object (handle); nothing about it leaves the tab except its public address;
//   · while a run is live: the tab is busy (network selector off), the title says KEEP THIS TAB VISIBLE whenever the tab
//     is hidden (MQ M1), and leaving the page asks first;
//   · after a reload nothing runs: the state comes back from the API, and running again needs the key re-imported; the
//     executor then reconciles from the chain first and resumes at the next part.
import { createContext, createElement, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { P, isRefusal } from '@vault-timelock/core/contracts'
import { browserAdapter, browserClients, createExecutor } from '@vault-timelock/core/executor'
import { FRESH_MS } from '@vault-timelock/core/engine/assess.js'
import { api } from '@/lib/api.js'
import { useTabBusy } from '@/lib/busy.js'
import { NETWORK_LABEL, currentNetwork, useStatus } from '@/lib/status.js'

export const CHAIN_LABEL = { eth: 'Ethereum', sol: 'Solana', btc: 'Bitcoin' }
export const runKey = (jobId, chain) => `${jobId}:${chain}`
const SIM_OK = 'simulation ✓'
const monotonic = () => (typeof performance === 'undefined' ? Date.now() : performance.now())

// The executor's LoadedKey from a KeyStore entry { key, source, file, network? }: the handle is the key object itself.
export function loadedKeyOf(chain, entry) {
  return { chain, address: entry.key.address, network: entry.network ?? null, handle: entry.key }
}

// The executor deps of this page: the browser adapter and the same-origin clients (base '/api' and the page's /relay).
export function pageDeps(extra = {}) {
  return { ...browserAdapter(), ...browserClients(), ...extra }
}

const RunsContext = createContext(null)

// options (tests): deps(extra) builds the executor deps (default pageDeps).
export function RunsProvider({ children, deps = pageDeps }) {
  const [runs, setRuns] = useState({})                     // key → { status, view, outcome, error, simAt, kind }
  const detached = useRef(new Set())                        // R79b m-1: keys whose executor this tab detached (Stop running here): sticky until Run here
  const exs = useRef(new Map())                            // key → executor (not in React state: it holds the key)
  const busy = useTabBusy()
  const ctx = useStatus()
  const label = NETWORK_LABEL[currentNetwork(ctx)] || '?'
  const [hiddenAt, setHiddenAt] = useState(null)

  const patch = useCallback((k, p) => setRuns((r) => ({ ...r, [k]: { ...(r[k] || {}), ...p } })), [])
  const live = Object.entries(runs).filter(([, r]) => r.status === 'running')

  // busy while any run holds (or is taking) a lease in this tab
  useEffect(() => {
    for (const [k, r] of Object.entries(runs)) busy.set(r.status === 'running' ? `${CHAIN_LABEL[k.split(':')[1]]} ${r.kind === 'clawback' ? 'claw-back' : 'run'} in this tab` : null, `run-${k}`)
  }, [runs, busy.set])

  // MQ M1: keep the tab visible while it runs; the title says so when hidden; leaving asks first
  const anyLive = live.length > 0
  useEffect(() => {
    if (!anyLive) return undefined
    const base = `[${label}] vt`
    const upd = () => {
      const hidden = typeof document !== 'undefined' && document.visibilityState === 'hidden'
      document.title = hidden ? `[${label}] ⚠ KEEP THIS TAB VISIBLE` : base
      if (hidden) setHiddenAt((x) => x ?? Date.now())
    }
    const leave = (e) => { e.preventDefault(); e.returnValue = '' }
    upd()
    document.addEventListener('visibilitychange', upd)
    window.addEventListener('beforeunload', leave)
    return () => { document.removeEventListener('visibilitychange', upd); window.removeEventListener('beforeunload', leave); document.title = base }
  }, [anyLive, label])

  const launch = useCallback((jobId, chain, entry, kind, go, extra = {}) => {
    const k = runKey(jobId, chain)
    if (exs.current.get(k)?.live) return null
    detached.current.delete(k)                             // an explicit Run here / claw-back starts a fresh executor
    const onView = (v) => patch(k, { view: v, ...(v.phase === 'countdown' && v.note === SIM_OK ? { simAt: monotonic() } : {}) })
    const ex = createExecutor({ jobId, chain, key: loadedKeyOf(chain, entry), holder: 'browser', deps: deps({ onView, ...extra }) })
    exs.current.set(k, { ex, live: true })
    patch(k, { status: 'running', kind, view: null, outcome: null, error: null, simAt: null, startedAt: Date.now() })
    const p = go(ex)
    p.then((outcome) => patch(k, { outcome }), (e) => patch(k, { error: isRefusal(e) ? { guard: e.guardId, message: e.message } : { guard: 'error', message: String(e?.message || e).slice(0, 300) } }))
      .finally(() => { exs.current.set(k, { ex, live: false }); patch(k, { status: 'ended' }) })
    return p
  }, [deps, patch])

  const value = useMemo(() => ({
    runs, hiddenAt,
    start: (jobId, chain, entry) => launch(jobId, chain, entry, 'run', (ex) => ex.start()),
    clawback: (jobId, chain, entry, to, amount) => launch(jobId, chain, entry, 'clawback', (ex) => ex.clawback(to), amount ? { clawbackConfirm: { amount } } : {}),
    // Stop: the operator's stop at the API (stop-requested: it also stops a CLI run) and this tab's executor; either way
    // it takes effect after the in-flight tx resolves (R64), never by abandoning it.
    async stop(jobId, chain) {
      // R79b M-7: the API first, this tab's executor after. The other way round the executor could reach its end-of-run check before
      // the API journaled stop-requested and degrade into a detach (nothing journaled) while the page says "stopped".
      await api(P.stop(jobId), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ chain }) })
      exs.current.get(runKey(jobId, chain))?.ex.requestStop()
    },
    // Before the arm: stop only this tab's executor (it releases the lease); the chain stays ready for another holder.
    // (An API stop there would end the chain for this job: STOPPED before any transaction.)
    stopHere(jobId, chain) { detached.current.add(runKey(jobId, chain)); exs.current.get(runKey(jobId, chain))?.ex.requestStop() },
    // Resume a paused lane, or cancel a stop that has not taken effect yet (resume-requested), optionally with new caps.
    async resume(jobId, chain, o = {}) {
      await api(P.resume(jobId), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ chain, ...o }) })
      // m-1: executor.requestResume clears the executor's local stop, which would undo this tab's detach: after a detach this tab's
      // executor never signs again until the operator presses Run here (the API's resume is journaled either way).
      if (!detached.current.has(runKey(jobId, chain))) exs.current.get(runKey(jobId, chain))?.ex.requestResume(o)
    },
    // Skip (executor.skip): IsTor ✓ (testnet, mainnet) and a fresh passing simulation, checked again by the executor.
    async skip(jobId, chain) {
      const x = exs.current.get(runKey(jobId, chain))
      if (!x?.live) throw new Error('Skip needs this chain running in this tab')
      await x.ex.skip()
    },
  }), [runs, hiddenAt, launch])
  return createElement(RunsContext.Provider, { value }, children)
}

export function useRuns() {
  const v = useContext(RunsContext)
  if (v === null) throw new Error('useRuns needs a RunsProvider')
  return v
}

// The run of one (job, chain) in this tab, or an idle record.
export function useRun(jobId, chain) {
  const r = useRuns()
  return r.runs[runKey(jobId, chain)] || { status: 'idle', view: null, outcome: null, error: null, simAt: null }
}

// A passing real-byte simulation within FRESH_MS (the executor re-simulates every second during the countdown).
export const simFresh = (run, now = monotonic()) => typeof run?.simAt === 'number' && now - run.simAt < FRESH_MS

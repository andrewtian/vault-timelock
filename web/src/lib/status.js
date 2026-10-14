// Status polling and the network regime (W1). One poll for the whole page (StatusProvider); useStatus() reads it.
import { createContext, createElement, useContext, useEffect, useState } from 'react'
import { PORTS, isNetwork } from '@vault-timelock/core/contracts'
import { api } from './api.js'

export const NETWORK_LABEL = { local: 'LOCAL', testnet: 'TESTNET', mainnet: 'MAINNET' }
export const upCommand = (network) => `vt up --network ${network}`

// The network this page was served for, from its own port (page ports and the local Vite dev port). null when the
// port is none of them (tests, a custom port): then only API and relay are compared with each other.
export function networkOfPort(port) {
  const n = Number(port)
  for (const [network, p] of Object.entries(PORTS)) if (n === p.page || (p.dev !== null && n === p.dev)) return network
  return null
}

// mismatch = null | { expected, api, relay, command, message }. The page, the API and the relay must all name the
// same network. `expected` is the page's own network when known, else the API's.
export function computeMismatch(status, relay, pageNetwork = null) {
  if (!status || !isNetwork(status.network)) return null
  const names = { api: status.network, relay: relay && isNetwork(relay.network) ? relay.network : null }
  const expected = pageNetwork || status.network
  const bad = names.api !== expected || (names.relay !== null && names.relay !== expected)
  if (!bad) return null
  const command = upCommand(expected)
  return {
    expected, api: names.api, relay: names.relay, command,
    message: `This page is for ${expected}, but the API says ${names.api}` + (names.relay ? ` and the relay says ${names.relay}` : '') + '.',
  }
}

export const StatusContext = createContext({ status: null, relay: null, mismatch: null, pageNetwork: null, error: null })

export async function readStatus() {
  const [status, relay] = await Promise.allSettled([api('/status'), fetch('/relay/status', { cache: 'no-store', credentials: 'same-origin' }).then((r) => (r.ok ? r.json() : null))])
  return {
    status: status.status === 'fulfilled' ? status.value : null,
    relay: relay.status === 'fulfilled' ? relay.value : null,
    error: status.status === 'rejected' ? status.reason : null,
  }
}

// Polls /api/status + /relay/status every intervalMs (default 10 s). `value` (tests) replaces the polling.
export function StatusProvider({ children, intervalMs = 10_000, value = null, port = typeof location === 'undefined' ? '' : location.port }) {
  const pageNetwork = networkOfPort(port)
  const [state, setState] = useState({ status: null, relay: null, error: null })
  useEffect(() => {
    if (value) return undefined
    let dead = false
    const tick = () => readStatus().then((s) => { if (!dead) setState(s) })
    tick()
    const t = setInterval(tick, intervalMs)
    return () => { dead = true; clearInterval(t) }
  }, [intervalMs, value])
  const cur = value || state
  const ctx = { status: cur.status, relay: cur.relay, error: cur.error ?? null, pageNetwork, mismatch: computeMismatch(cur.status, cur.relay, pageNetwork) }
  return createElement(StatusContext.Provider, { value: ctx }, children)
}

// useStatus() -> { status, relay, mismatch, pageNetwork, error }
export function useStatus() {
  return useContext(StatusContext)
}

// The network the UI is in: the API's answer, else the page's own port, else null.
export function currentNetwork(ctx) {
  return (ctx.status && isNetwork(ctx.status.network) && ctx.status.network) || ctx.pageNetwork || null
}

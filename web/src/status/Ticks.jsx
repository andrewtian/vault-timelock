// Operator ticks for the mainnet Arm (W4): in tab memory only, never stored. Arm on mainnet stays gated until every tick
// is set (ArmDialog reads useTicks().all). Other networks are not gated by ticks.
import { createContext, createElement, useCallback, useContext, useMemo, useState } from 'react'
import { MAINNET_TICKS } from './readiness.js'

const NONE = { ticks: {}, all: false, count: 0, total: MAINNET_TICKS.length, set: () => {} }
const TicksContext = createContext(NONE)

export function TicksProvider({ children, value = null }) {
  const [ticks, setTicks] = useState({})
  const set = useCallback((id, on) => setTicks((t) => ({ ...t, [id]: !!on })), [])
  const ctx = useMemo(() => {
    const cur = value ?? ticks
    const count = MAINNET_TICKS.filter((t) => cur[t.id] === true).length
    return { ticks: cur, all: count === MAINNET_TICKS.length, count, total: MAINNET_TICKS.length, set }
  }, [ticks, value, set])
  return createElement(TicksContext.Provider, { value: ctx }, children)
}

export const useTicks = () => useContext(TicksContext)
export const ALL_TICKS = Object.fromEntries(MAINNET_TICKS.map((t) => [t.id, true]))

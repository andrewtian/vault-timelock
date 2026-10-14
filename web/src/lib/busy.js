// Tab-busy state (W1): the network selector is disabled while this tab holds a key, a lease, or an armed or running
// job. W2/W3 call set(reason) (a string) to mark busy and set(null) to clear. Several holders may coexist: pass a
// key as the second argument (default 'tab'); busy while any key holds a reason.
import { createContext, createElement, useCallback, useContext, useMemo, useState } from 'react'

const TabBusyContext = createContext({ busy: false, reason: null, set: () => {} })

export function TabBusyProvider({ children }) {
  const [held, setHeld] = useState({})
  const set = useCallback((reason, key = 'tab') => {
    setHeld((h) => {
      if (reason == null || reason === '') {
        if (!(key in h)) return h
        const { [key]: _gone, ...rest } = h
        return rest
      }
      return h[key] === reason ? h : { ...h, [key]: String(reason) }
    })
  }, [])
  const value = useMemo(() => {
    const reasons = Object.values(held)
    return { busy: reasons.length > 0, reason: reasons.length ? reasons.join('; ') : null, set }
  }, [held, set])
  return createElement(TabBusyContext.Provider, { value }, children)
}

export function useTabBusy() {
  return useContext(TabBusyContext)
}

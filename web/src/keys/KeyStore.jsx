// The keys of this tab, in memory only (never storage, URL, log or API body). A lane's key is put here when its backup is
// verified (or it was loaded from a backup); the job page reads it from here. While any key is held the tab is busy
// (one busy key per chain: `key-eth`, `key-sol`), which disables the network selector.
import { createContext, createElement, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { useTabBusy } from '@/lib/busy.js'

export const CHAIN_NAME = { eth: 'Ethereum', sol: 'Solana', btc: 'Bitcoin' }
const KeysContext = createContext({ keys: {}, setKey: () => {}, clearKey: () => {} })

export function KeysProvider({ children }) {
  const [keys, setKeys] = useState({})                       // { eth?: { key, source, file }, sol?: … }
  const busy = useTabBusy()
  const setKey = useCallback((chain, entry) => setKeys((k) => ({ ...k, [chain]: entry })), [])
  const clearKey = useCallback((chain) => setKeys((k) => { const { [chain]: _gone, ...rest } = k; return rest }), [])
  useEffect(() => {
    for (const chain of Object.keys(CHAIN_NAME)) busy.set(keys[chain] ? `${CHAIN_NAME[chain]} key loaded in this tab` : null, `key-${chain}`)
  }, [keys, busy.set])
  const value = useMemo(() => ({ keys, setKey, clearKey }), [keys, setKey, clearKey])
  return createElement(KeysContext.Provider, { value }, children)
}

// -> { keys, setKey(chain, { key, source, file }), clearKey(chain) }
export function useKeys() {
  return useContext(KeysContext)
}

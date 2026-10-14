// Shared test wiring (W2): providers and a seeded key store. Keys here are generated in memory for the test; nothing real.
import { useEffect } from 'react'
import { render } from '@testing-library/react'
import { StatusProvider } from '../src/lib/status.js'
import { TabBusyProvider, useTabBusy } from '../src/lib/busy.js'
import { KeysProvider, useKeys } from '../src/keys/KeyStore.jsx'
import { RunsProvider } from '../src/jobs/RunHere.js'
import { ALL_TICKS, TicksProvider } from '../src/status/Ticks.jsx'

export const NAMES = {
  local: { eth: 'anvil · 31337', sol: 'Solana local' },
  testnet: { eth: 'Sepolia · 11155111', sol: 'Solana devnet' },
  mainnet: { eth: 'Ethereum mainnet · 1', sol: 'Solana mainnet-beta' },
}
export const statusOf = (network) => ({
  network, networks: NAMES[network], mainnetSends: 'LOCKED', jobSends: 'LOCKED', build: 'b1c2d3e4f5a6', confined: true, legacyLatch: 'clear', serverNowMs: 1,
})
// endpoints: a healthy relay's verified count — on mainnet at least 2 per job chain (PF-S M-2: executor.endpoints-quorum; M5 glue)
export const relayOf = (network) => { const n = network === 'mainnet' ? 2 : 1; return { network, build: 'r', confined: true, identity: { eth: { ok: true }, sol: { ok: true } }, endpoints: { eth: n, sol: n } } }

export const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json; charset=utf-8' } })

let busyNow = { busy: false, reason: null }
export const lastBusy = () => busyNow
function BusyProbe() { busyNow = useTabBusy(); return null }

// Seeds the key store with the given [chain, key] pairs once.
function Seed({ keys, network }) {
  const { setKey } = useKeys()
  useEffect(() => { for (const [chain, key] of keys) setKey(chain, { key, source: 'test', file: 'test.age', network }) }, [keys, setKey, network])
  return null
}

// status: overrides of the /status answer (e.g. { jobSends: 'ENABLED' }); deps: the RunsProvider's executor deps.
// ticks: the operator's mainnet ticks (default: all set, so the older mainnet Arm tests stay about their own checks;
// null = the real in-memory ticks, for the Status page).
export function renderWith(ui, { network = 'local', seed = [], status = {}, relay = null, deps, ticks = ALL_TICKS } = {}) {
  return render(
    <StatusProvider value={{ status: { ...statusOf(network), ...status }, relay: relay ?? relayOf(network), error: null }} port="">
      <TabBusyProvider>
        <KeysProvider>
          <RunsProvider {...(deps ? { deps } : {})}>
            <TicksProvider value={ticks}>
            <BusyProbe />
            {seed.length > 0 ? <Seed keys={seed} network={network} /> : null}
            {ui}
            </TicksProvider>
          </RunsProvider>
        </KeysProvider>
      </TabBusyProvider>
    </StatusProvider>,
  )
}

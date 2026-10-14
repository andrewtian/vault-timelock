// The regime banner (W1): always visible, coloured by network, and it prefixes document.title.
// LOCAL neutral/sky · TESTNET amber · MAINNET red. The mainnet send lock is shown verbatim from /api/status.
import { useEffect } from 'react'
import { NETWORK_LABEL, currentNetwork, useStatus } from '@/lib/status.js'

// Static class strings (Tailwind scans source text).
export const REGIME_STYLE = {
  local: 'bg-sky-100 text-sky-950 border-sky-300',
  testnet: 'bg-amber-200 text-amber-950 border-amber-400',
  mainnet: 'bg-red-700 text-white border-red-900',
}

export function sendsLabel(status) {
  if (status.jobSends === 'ENABLED') return 'ENABLED (jobs)'
  return status.mainnetSends === 'ENABLED' ? 'ENABLED' : 'LOCKED'
}

// The regime in one line (repeated in the Arm and claw-back dialogs, W3): network, chain names, the mainnet lock.
export function RegimeLine({ testid = 'regime-line' }) {
  const ctx = useStatus()
  const network = currentNetwork(ctx)
  const status = ctx.status
  return (
    <div data-testid={testid} data-network={network || 'unknown'} className={`rounded border px-2 py-1 text-xs font-medium ${network ? REGIME_STYLE[network] : 'bg-muted'}`}>
      <strong>{network ? `[${NETWORK_LABEL[network]}]` : '[?]'}</strong>
      {status ? <> {Object.entries(status.networks || {}).map(([c, n]) => `${c}: ${n}`).join(' · ')} · mainnet sends: {sendsLabel(status)}</> : ' API not reachable'}
    </div>
  )
}

export default function RegimeBanner() {
  const ctx = useStatus()
  const network = currentNetwork(ctx)
  const label = network ? NETWORK_LABEL[network] : null

  useEffect(() => {
    document.title = label ? `[${label}] vt` : 'vt'
  }, [label])

  const status = ctx.status
  const chains = status ? Object.entries(status.networks || {}) : []
  return (
    <div
      data-testid="regime-banner"
      data-network={network || 'unknown'}
      role="status"
      className={`flex flex-wrap items-center gap-x-4 gap-y-1 border-b px-4 py-2 text-sm font-medium ${network ? REGIME_STYLE[network] : 'bg-muted text-muted-foreground border-border'}`}
    >
      <strong className="tracking-wide">{label ? `[${label}]` : '[?]'}</strong>
      {status ? (
        <>
          {chains.map(([chain, name]) => (
            <span key={chain}>{chain}: {name}</span>
          ))}
          <span>mainnet sends: {sendsLabel(status)}</span>
        </>
      ) : (
        <span>{ctx.error ? 'API not reachable' : 'connecting…'}</span>
      )}
    </div>
  )
}

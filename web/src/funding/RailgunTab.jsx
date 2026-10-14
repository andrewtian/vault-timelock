// The Railgun tab (plan W6, D2a, R27/R47): Ethereum lane. L1 MANUAL unshield: the operator unshields from their own Railgun wallet
// to the lane address; this page shows the instructions, the address and the provenance badge, and NEVER signs or sends a Railgun
// transaction and holds no Railgun key. The check reads the lane address's history through the relay (Blockscout + JSON-RPC, over
// Tor) only when the operator clicks it; core's gates/provenance.ts decides.
import { Button } from '@/components/ui/button.jsx'
import { copyText } from '@/jobs/AddressLinks.jsx'
import { ProvenanceBadge, VerdictList, statusOf, useEthProvenance } from './FundingProvenance.jsx'

export default function RailgunTab({ network, address, read }) {
  const p = useEthProvenance({ network, address, read })
  const result = p.result
  if (!address) return <p data-testid="rg-none" className="text-xs text-muted-foreground">The Ethereum lane address appears here once its key and backup are done.</p>
  const status = statusOf({ network, result })
  return (
    <div data-testid="rg-tab" className="space-y-3 text-sm">
      <p data-testid="rg-manual" className="rounded-md border border-amber-500 bg-amber-50 p-2 text-xs text-amber-950">
        <b>Manual step, in your own wallet.</b> This page never signs or sends a Railgun transaction and holds no Railgun key. In your Railgun wallet, unshield
        ETH (L1, Ethereum {network === 'mainnet' ? 'mainnet' : 'Sepolia'}) to the address below, <b>to this address only and from nothing else</b>: a second sender, or any
        transaction sent from it first, makes the provenance check fail.
      </p>
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <b>Lane address</b> <span data-testid="rg-address" className="break-all font-mono">{address}</span>
        <Button type="button" size="xs" variant="outline" data-testid="rg-copy" onClick={() => copyText(address)}>Copy</Button>
      </div>
      {network === 'local'
        ? <p data-testid="rg-local" className="text-xs text-muted-foreground">Local stack: fund the lane from the local dev accounts (a stand-in); there is no Railgun here and no provenance gate.</p>
        : (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <ProvenanceBadge status={status} testid="rg-badge" />
              <Button type="button" size="sm" variant="outline" data-testid="rg-check" disabled={p.busy} onClick={p.check}>{p.busy ? 'Reading…' : 'Check provenance'}</Button>
              <span className="text-muted-foreground">reads the address&apos;s history through the relay, over Tor, when you click</span>
            </div>
            {p.error && <p data-testid="rg-error" className="text-xs text-red-700">{p.error} (not checked: this is not a pass)</p>}
            <VerdictList verdict={result?.verdict} />
            {network === 'mainnet' && <p data-testid="rg-gate" className="text-xs text-muted-foreground">Informational only: Arm relies on the funds present in the lane wallet, not on this badge.</p>}
          </div>
        )}
    </div>
  )
}

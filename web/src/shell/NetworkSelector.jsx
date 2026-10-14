// Network selector (W1, R71): Local · Testnet · Mainnet, each marked up or down. Switching is a full navigation to
// that stack's page origin, so tab memory (any loaded key) is dropped; it is allowed only while this tab is idle,
// and an AlertDialog names what will be cleared first.
import { useState } from 'react'
import { NETWORKS } from '@vault-timelock/core/contracts'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription,
  AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog.jsx'
import { useTabBusy } from '@/lib/busy.js'
import { NETWORK_LABEL, currentNetwork, useStatus } from '@/lib/status.js'
import { safePageUrl, useStacks } from '@/lib/stacks.js'

const DOT = { local: 'bg-sky-500', testnet: 'bg-amber-500', mainnet: 'bg-red-600' }
const NAME = { local: 'Local', testnet: 'Testnet', mainnet: 'Mainnet' }

// `assign` is the navigation (default: location.assign); tests inject a spy.
export default function NetworkSelector({ assign = (url) => window.location.assign(url) }) {
  const stacks = useStacks()
  const busy = useTabBusy()
  const current = currentNetwork(useStatus())
  const [target, setTarget] = useState(null) // { network, url }

  return (
    <nav aria-label="Network" className="flex items-center gap-2" data-testid="network-selector">
      <div className="flex gap-1" role="group" aria-label="Network">
        {NETWORKS.map((n) => {
          const stack = stacks.find((s) => s.network === n)
          const up = stack?.up === true
          const url = stack ? safePageUrl(n, stack.pageUrl) : null
          const here = n === current
          const disabled = !here && (busy.busy || !up || !url)
          return (
            <button
              key={n}
              type="button"
              data-network={n}
              aria-current={here ? 'true' : undefined}
              disabled={disabled}
              onClick={() => { if (!here && url) setTarget({ network: n, url }) }}
              className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-sm disabled:opacity-50 ${here ? 'border-foreground font-semibold' : 'border-border'}`}
            >
              <span aria-hidden="true" className={`size-2 rounded-full ${up || here ? DOT[n] : 'bg-muted-foreground/40'}`} />
              {NAME[n]}
              <span className="text-xs text-muted-foreground">{here || up ? 'up' : 'down'}</span>
            </button>
          )
        })}
      </div>
      {busy.busy ? (
        <span className="text-xs text-muted-foreground" data-testid="selector-reason">Switching is off: {busy.reason}</span>
      ) : null}
      <AlertDialog open={target !== null} onOpenChange={(o) => { if (!o) setTarget(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Switch to {target ? NETWORK_LABEL[target.network] : ''}?</AlertDialogTitle>
            <AlertDialogDescription>
              This opens the {target ? NAME[target.network] : ''} page. Everything in this tab is cleared: any loaded key,
              lease and unsaved input. Nothing is stored, so nothing carries over. Keys are per network.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Stay here</AlertDialogCancel>
            <AlertDialogAction onClick={() => { const u = target.url; setTarget(null); assign(u) }}>
              Switch to {target ? NAME[target.network] : ''}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </nav>
  )
}

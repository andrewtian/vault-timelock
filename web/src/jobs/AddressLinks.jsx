// Explorer links for an address (pure data + a small view). Mainnet links are COPY-ONLY (paste into Tor Browser): this
// page never opens an external URL on mainnet. Testnet links open (public test networks). Local: Otterscan on this
// machine, and the Solana explorer pointed at the local validator, with the "Apps on device" note (W1's component).
import { Button } from '@/components/ui/button.jsx'
import { LOCAL_ORD } from '@/lib/btc.js'
import LocalExplorerNote from '@/shell/LocalExplorerNote.jsx'

const OTTERSCAN = 'http://127.0.0.1:5100'
const LOCAL_SOL_RPC = 'http://127.0.0.1:8999'

export function addressLinks(network, chain, address) {
  if (chain === 'btc') {
    if (network === 'local') return [{ label: 'ord (local) · address', url: `${LOCAL_ORD}/address/${address}`, open: true }]
    if (network === 'testnet') return [{ label: 'mempool.space (testnet4) · address', url: `https://mempool.space/testnet4/address/${address}`, open: false }]
    return [{ label: 'mempool.space · address', url: `https://mempool.space/address/${address}`, open: false }]
  }
  if (chain === 'eth') {
    if (network === 'local') return [{ label: 'Otterscan (local) · address', url: `${OTTERSCAN}/address/${address}`, open: true }]
    if (network === 'testnet') return [{ label: 'Etherscan (Sepolia) · address', url: `https://sepolia.etherscan.io/address/${address}`, open: true }]
    return [{ label: 'Etherscan · address', url: `https://etherscan.io/address/${address}`, open: false }]
  }
  if (network === 'local') return [{ label: 'Solana Explorer · custom cluster → local validator', url: `https://explorer.solana.com/address/${address}?cluster=custom&customUrl=${encodeURIComponent(LOCAL_SOL_RPC)}`, open: true }]
  if (network === 'testnet') return [{ label: 'Solana Explorer (devnet) · address', url: `https://explorer.solana.com/address/${address}?cluster=devnet`, open: true }]
  return [{ label: 'Solana Explorer · address', url: `https://explorer.solana.com/address/${address}`, open: false }, { label: 'Solscan · address', url: `https://solscan.io/address/${address}`, open: false }]
}

export const copyText = (t) => navigator.clipboard?.writeText(t).catch(() => {})

export default function AddressLinks({ network, chain, address }) {
  const links = addressLinks(network, chain, address)
  return (
    <div className="space-y-1" data-testid={`links-${chain}`}>
      {links.map((l) => (
        <div key={l.url} className="flex flex-wrap items-center gap-2 text-xs">
          <span>{l.label}</span>
          {l.open
            ? <a href={l.url} target="_blank" rel="noopener noreferrer" className="break-all underline">{l.url}</a>
            : <span className="break-all font-mono" data-testid="copy-only-link">{l.url}</span>}
          <Button type="button" size="xs" variant="outline" onClick={() => copyText(l.url)}>Copy link</Button>
          {!l.open && <span className="text-muted-foreground">copy-only: paste into Tor Browser</span>}
        </div>
      ))}
      {chain === 'sol' && network === 'local' && <LocalExplorerNote />}
    </div>
  )
}

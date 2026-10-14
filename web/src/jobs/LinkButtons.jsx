// Explorer links for one transaction (W4), from core links.js (the per-network table), never fetched by the page:
//   · local   — the Otterscan link opens directly; the Solana Explorer custom-cluster link opens too, with W1's
//               LocalExplorerNote ("Apps on device") beside it;
//   · testnet — Sepolia Etherscan, Solana Explorer / Solscan / SolanaFM on devnet: a dialog with Copy or Open;
//   · mainnet — COPY-ONLY text, no href at all (paste into Tor Browser, R46).
import { useState } from 'react'
import { ethLinks, solLinks } from '@vault-timelock/core/chains/links.js'
import { Button } from '@/components/ui/button.jsx'
import LocalExplorerNote from '@/shell/LocalExplorerNote.jsx'
import { copyText } from './AddressLinks.jsx'

// The links of a transaction, each with how it may be used: 'open' | 'dialog' | 'copy'.
export function txLinks(network, chain, txId, signer, to) {
  if (!txId || !network) return []
  let raw
  try { raw = chain === 'eth' ? ethLinks(network, txId, signer, to ?? '') : solLinks(network, txId, signer) } catch { return [] }
  return raw.map((l) => ({
    ...l,
    use: network === 'mainnet' ? 'copy' : network === 'testnet' ? 'dialog' : (l.open || chain === 'sol') ? 'open' : 'copy',
  }))
}

function Row({ l, i, prefix, onDialog }) {
  return (
    <li className="flex flex-wrap items-center gap-2 text-xs" data-testid={`${prefix}-${i}`} data-use={l.use}>
      <span>{l.label}</span>
      {l.use === 'copy' && <span className="break-all font-mono" data-testid={`${prefix}-text-${i}`}>{l.url}</span>}
      {l.use === 'open' && <a href={l.url} target="_blank" rel="noopener noreferrer" className="break-all underline" data-testid={`${prefix}-open-${i}`}>{l.url}</a>}
      <Button type="button" size="xs" variant="outline" data-testid={`${prefix}-copy-${i}`} onClick={() => copyText(l.url)}>Copy link</Button>
      {l.use === 'dialog' && <Button type="button" size="xs" variant="outline" data-testid={`${prefix}-dialog-${i}`} onClick={() => onDialog(l)}>Open…</Button>}
      {l.use === 'copy' && <span className="text-muted-foreground">copy-only: paste into Tor Browser</span>}
      {l.note && <span className="text-muted-foreground">{l.note}</span>}
    </li>
  )
}

export default function LinkButtons({ network, chain, txId, signer, to, prefix = `link-${chain}` }) {
  const [dlg, setDlg] = useState(null)
  const links = txLinks(network, chain, txId, signer, to)
  if (links.length === 0) return null
  return (
    <div className="space-y-1" data-testid={`${prefix}s`} data-network={network}>
      <ul className="space-y-1">{links.map((l, i) => <Row key={l.label + i} l={l} i={i} prefix={prefix} onDialog={setDlg} />)}</ul>
      {network === 'local' && chain === 'sol' && <LocalExplorerNote />}
      {dlg && (
        <div role="dialog" aria-label="Open an explorer" data-testid="link-dialog" className="space-y-2 rounded-md border bg-background p-3 text-xs shadow">
          <p>{dlg.label} — a public test network explorer. Opening it sends this transaction id to that site.</p>
          <p className="break-all font-mono" data-testid="link-dialog-url">{dlg.url}</p>
          <div className="flex gap-2">
            <Button type="button" size="xs" variant="outline" data-testid="link-dialog-copy" onClick={() => copyText(dlg.url)}>Copy link</Button>
            <Button asChild size="xs"><a href={dlg.url} target="_blank" rel="noopener noreferrer" data-testid="link-dialog-open" onClick={() => setDlg(null)}>Open</a></Button>
            <Button type="button" size="xs" variant="ghost" data-testid="link-dialog-close" onClick={() => setDlg(null)}>Cancel</Button>
          </div>
        </div>
      )}
    </div>
  )
}

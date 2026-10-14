// The Bitcoin lane's copies on the job page (W7b). A copy is ONE text inscription, made of two lane transactions: part 1 the
// COMMIT, part 2 the REVEAL (core chains/btc.js, E7). One row per copy: the commit and the reveal txid with their states, the
// inscription id (<reveal txid>i0), ord links (the local ord opens; testnet4 / mainnet links are copy-only), the fee paid and the
// readback: the reveal's witness holds exactly ONE inscription whose body equals the part's bytes (✓), read from the chain.
// Virtualized like the parts table (a copies job can have thousands of rows).
import { useState } from 'react'
import { Button } from '@/components/ui/button.jsx'
import { BTC_POSTAGE, btcTxLinks, inscriptionId, ordLinks } from '@/lib/btc.js'
import { copyText } from './AddressLinks.jsx'
import { ROW_PX, native, windowOf } from './PartsTable.jsx'

const short = (id) => (id && id.length > 20 ? `${id.slice(0, 10)}…${id.slice(-6)}` : id || '—')
const STATE_STYLE = { included: 'text-emerald-700', open: 'text-sky-700', stuck: 'text-amber-700', failed: 'text-red-700' }

// The copies of a btc chain's reduced txs: [{ copy, commit: TxView | null, reveal: TxView | null }] in copy order.
export function btcCopiesOf(txs) {
  const by = new Map()
  for (const t of txs) {
    const c = by.get(t.copy) || { copy: t.copy, commit: null, reveal: null }
    if (t.part === 1) c.commit = t; else if (t.part === 2) c.reveal = t
    by.set(t.copy, c)
  }
  return [...by.values()].sort((a, b) => a.copy - b.copy)
}

const idOf = (t) => (t ? t.landedId || t.attempts.at(-1)?.txId || null : null)
const sum = (a, b) => (a == null && b == null ? null : String(BigInt(a ?? 0) + BigInt(b ?? 0)))

function LinkRow({ links }) {
  return (
    <span className="inline-flex flex-wrap gap-1">
      {links.map((l) => (
        <span key={l.url} className="inline-flex items-center gap-1">
          <Button type="button" size="xs" variant="outline" className="h-5 px-1 text-[10px]" title={l.url} onClick={() => copyText(l.url)}>copy {l.label.split(' · ').pop()}</Button>
          {l.open && <a href={l.url} target="_blank" rel="noopener noreferrer" className="text-[10px] underline" data-testid="ord-link">open {l.label.split(' · ').pop()}</a>}
        </span>
      ))}
    </span>
  )
}

function Tx({ t, network, kind }) {
  const id = idOf(t)
  if (!t) return <span className="text-muted-foreground">—</span>
  const a = t.attempts.at(-1)?.btc
  return (
    <div data-testid={`btc-${kind}`} data-state={t.state}>
      <span className={STATE_STYLE[t.state] || ''}>{t.state === 'included' ? 'landed' : t.state}</span>{' '}
      <span className="font-mono" title={id || ''} data-testid={`btc-${kind}-txid`}>{short(id)}</span>
      {a ? <div className="text-muted-foreground">fee {a.fee} sat{a.kind === 'commit' ? ` · locks ${a.value} sat (incl. ${BTC_POSTAGE} postage)` : ''}</div> : null}
      {t.landedId ? <LinkRow links={btcTxLinks(network, t.landedId)} /> : null}
    </div>
  )
}

export default function BtcCopies({ rows, network, height = 420 }) {
  const [top, setTop] = useState(0)
  const copies = btcCopiesOf(rows)
  const { virt, first, last } = windowOf(copies.length, top, height, ROW_PX * 2)
  return (
    <div data-testid="btc-copies" data-rows={copies.length} data-virtual={String(virt)} className="mt-2 overflow-auto rounded-md border" style={{ maxHeight: height }}
      onScroll={(e) => { if (virt) setTop(e.currentTarget.scrollTop) }}>
      <table className="w-full text-left text-[11px]">
        <thead className="sticky top-0 z-10 bg-background text-muted-foreground">
          <tr><th className="px-1 py-1">copy</th><th>commit</th><th>reveal</th><th>inscription · ord</th><th>fees paid</th><th>readback</th></tr>
        </thead>
        <tbody>
          {virt && first > 0 && <tr aria-hidden style={{ height: first * ROW_PX * 2 }}><td colSpan={6} /></tr>}
          {copies.slice(first, last).map((c) => {
            const reveal = c.reveal?.landedId || null
            const rb = c.reveal?.readback ?? null
            return (
              <tr key={c.copy} data-testid="btc-copy-row" data-copy={c.copy} className="border-t align-top" style={virt ? { height: ROW_PX * 2 } : undefined}>
                <td className="px-1 font-mono">#{c.copy}</td>
                <td><Tx t={c.commit} network={network} kind="commit" /></td>
                <td><Tx t={c.reveal} network={network} kind="reveal" /></td>
                <td>
                  {reveal
                    ? <><span className="font-mono" data-testid="btc-inscription-id" title={inscriptionId(reveal)}>{short(inscriptionId(reveal))}</span> <LinkRow links={ordLinks(network, reveal)} /></>
                    : <span className="text-muted-foreground">after the reveal lands</span>}
                </td>
                <td className="font-mono">{native('btc', sum(c.commit?.fee, c.reveal?.fee))}</td>
                <td data-testid="readback-btc" data-ok={rb === null ? '' : String(rb)} className={rb ? 'text-emerald-700' : rb === false ? 'text-red-700' : 'text-muted-foreground'}
                  title="the reveal's witness holds one inscription whose body equals the part's bytes">
                  {rb === null ? '—' : rb ? '✓ body = part bytes' : '✗ body differs'}
                </td>
              </tr>
            )
          })}
          {virt && last < copies.length && <tr aria-hidden style={{ height: (copies.length - last) * ROW_PX * 2 }}><td colSpan={6} /></tr>}
        </tbody>
      </table>
    </div>
  )
}

// The per-part table of one chain (R72), VIRTUALIZED: a 16 MiB text is ~16k SOL parts per copy, so only the rows in view
// (plus an overscan) are in the DOM, between two spacer rows (ported from the prototype's LaneRun.jsx VTable, tag
// add7b-e540f8ae4d6b: fixed row height, windowing from 150 rows). One row per (copy, part) from the reduced state
// (TxView): state, the landed (or latest) tx id, every attempt with the fee it declared, the fee paid, the block,
// readback ✓, and the explorer links — COPY-ONLY (paste into Tor Browser); only the local Otterscan opens (core links.js).
import { useState } from 'react'
import { formatUnits } from '@vault-timelock/core/chains/plan.js'
import { ethLinks, solLinks } from '@vault-timelock/core/chains/links.js'
import { Button } from '@/components/ui/button.jsx'
import { copyText } from './AddressLinks.jsx'

export const ROW_PX = 34, VIRT_FROM = 150, OVERSCAN = 10
const DEC = { eth: 18, sol: 9, btc: 8 }, UNIT = { eth: 'ETH', sol: 'SOL', btc: 'BTC' }
const short = (id) => (id && id.length > 20 ? `${id.slice(0, 10)}…${id.slice(-6)}` : id || '—')
export const native = (chain, v) => (v == null || v === '' ? '—' : `${formatUnits(BigInt(v), DEC[chain])} ${UNIT[chain]}`)

// the window [first, last) of rows to render for a scroll position
export function windowOf(n, scrollTop, height, row = ROW_PX, overscan = OVERSCAN) {
  if (n <= VIRT_FROM) return { virt: false, first: 0, last: n }
  const first = Math.max(0, Math.floor(scrollTop / row) - overscan)
  const last = Math.min(n, Math.ceil((scrollTop + height) / row) + overscan)
  return { virt: true, first, last }
}

const gwei = (v) => (v == null ? '?' : formatUnits(BigInt(v), 9))
function feeOf(chain, a) {
  if (chain === 'eth' && a.eth) return `nonce ${a.eth.nonce} · tip ${gwei(a.eth.tip)} / maxFee ${gwei(a.eth.maxFee)} gwei`
  if (chain === 'sol' && a.sol) return `${a.sol.cuPrice} µL/CU · fee ${a.sol.fee}`
  return ''
}
const STATE_STYLE = { included: 'text-emerald-700', open: 'text-sky-700', stuck: 'text-amber-700', failed: 'text-red-700' }

function Links({ chain, network, id, signer, to }) {
  if (!id || !network) return null
  let links = []
  try { links = chain === 'eth' ? ethLinks(network, id, signer, to) : solLinks(network, id, signer) } catch { return null }
  return (
    <span className="inline-flex flex-wrap gap-1">
      {links.map((l) => (
        <span key={l.label} className="inline-flex items-center gap-1">
          <Button type="button" size="xs" variant="outline" className="h-5 px-1 text-[10px]" title={l.url} onClick={() => copyText(l.url)}>copy {l.label.split(' · ').pop()}</Button>
          {l.open && <a href={l.url} target="_blank" rel="noopener noreferrer" className="text-[10px] underline">open</a>}
        </span>
      ))}
    </span>
  )
}

export default function PartsTable({ chain, rows, network, signer, to, height = 420, testid = `parts-table-${chain}` }) {
  const [top, setTop] = useState(0)
  const { virt, first, last } = windowOf(rows.length, top, height)
  return (
    <div data-testid={testid} data-rows={rows.length} data-virtual={String(virt)} className="mt-2 overflow-auto rounded-md border" style={{ maxHeight: height }}
      onScroll={(e) => { if (virt) setTop(e.currentTarget.scrollTop) }}>
      <table className="w-full text-left text-[11px]">
        <thead className="sticky top-0 z-10 bg-background text-muted-foreground">
          <tr><th className="px-1 py-1">copy</th><th>part</th><th>state</th><th>tx id · links</th><th>attempts (fees declared)</th><th>fee paid</th><th>block</th><th>readback</th></tr>
        </thead>
        <tbody>
          {virt && first > 0 && <tr aria-hidden style={{ height: first * ROW_PX }}><td colSpan={8} /></tr>}
          {rows.slice(first, last).map((t) => {
            const id = t.landedId || t.attempts.at(-1)?.txId || null
            return (
              <tr key={`${t.copy}:${t.part}`} data-testid={`part-row-${chain}`} data-copy={t.copy} data-part={t.part} data-state={t.state}
                className="border-t align-top" style={virt ? { height: ROW_PX } : undefined}>
                <td className="px-1 font-mono">#{t.copy}</td>
                <td className="font-mono">{t.part}/{t.parts}</td>
                <td className={STATE_STYLE[t.state] || ''}>{t.state === 'included' ? 'landed' : t.state}</td>
                <td><span className="font-mono" title={id || ''}>{short(id)}</span> <Links chain={chain} network={network} id={t.landedId} signer={signer} to={to} /></td>
                <td className={virt ? 'max-w-[260px] overflow-hidden' : ''}>
                  {t.attempts.map((a, i) => <div key={a.txId} className={a.txId === t.landedId ? 'text-emerald-700' : 'text-muted-foreground'}>{i + 1}. {a.state} · {feeOf(chain, a)}{a.txId === t.landedId ? ' ✓' : ''}</div>)}
                </td>
                <td className="font-mono">{native(chain, t.fee)}</td>
                <td className="font-mono">{t.block ?? '—'}</td>
                <td data-testid={`readback-${chain}`} data-ok={t.readback === null ? '' : String(t.readback)} className={t.readback ? 'text-emerald-700' : t.readback === false ? 'text-red-700' : 'text-muted-foreground'}>
                  {t.readback === null ? '—' : t.readback ? '✓' : '✗'}
                </td>
              </tr>
            )
          })}
          {virt && last < rows.length && <tr aria-hidden style={{ height: (rows.length - last) * ROW_PX }}><td colSpan={8} /></tr>}
        </tbody>
      </table>
    </div>
  )
}

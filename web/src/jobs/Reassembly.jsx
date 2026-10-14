// Per-copy "reassembled ✓" (R72): after a copy's last part the executor reads every part back from the chain, strips
// the headers, joins them by index and checks the sha256 against part 1; the journal's `reassembled {copy, ok, sha256}`
// is shown here per copy (the latest 24, plus totals). A copy with landed parts and no reassembly yet shows its count.
const LAST = 24

export function copiesOf(txs) {
  const by = new Map()
  for (const t of txs) {
    const c = by.get(t.copy) || { copy: t.copy, parts: t.parts, landed: 0 }
    if (t.state === 'included') c.landed++
    c.parts = Math.max(c.parts, t.parts)
    by.set(t.copy, c)
  }
  return [...by.values()].sort((a, b) => a.copy - b.copy)
}

export default function Reassembly({ chain, cs, sha = new Map(), messageSha256 = '' }) {
  if (!cs || cs.txs.length === 0) return null
  const ok = new Map(cs.reassembled.map((r) => [r.copy, r.ok]))
  const copies = copiesOf(cs.txs)
  const good = cs.reassembled.filter((r) => r.ok).length
  const shown = copies.slice(-LAST)
  return (
    <div data-testid={`reassembly-${chain}`} data-ok={good} className="space-y-1 text-[11px]">
      <div className="text-muted-foreground">
        copies landed {cs.copiesIncluded} · reassembled ✓ {good}{cs.reassembled.length > good ? ` · ✗ ${cs.reassembled.length - good}` : ''}
        {copies.length > LAST ? ` (latest ${LAST} of ${copies.length} shown)` : ''}
      </div>
      <div className="flex flex-wrap gap-1">
        {shown.map((c) => {
          const r = ok.get(c.copy)
          const s = sha.get(c.copy)
          return (
            <span key={c.copy} data-testid={`reasm-${chain}-${c.copy}`} data-ok={r === undefined ? '' : String(r)}
              title={s ? `sha256 ${s}${messageSha256 && s !== messageSha256 ? ' (≠ the message)' : ''}` : ''}
              className={`rounded px-1.5 py-0.5 ${r === true ? 'bg-emerald-100 text-emerald-900' : r === false ? 'bg-red-100 text-red-900' : 'bg-muted text-muted-foreground'}`}>
              copy {c.copy}: {r === true ? `reassembled ✓${s ? ` sha256 ${s.slice(0, 8)}…` : ''}` : r === false ? 'reassembly ✗' : `${c.landed}/${c.parts} parts`}
            </span>
          )
        })}
      </div>
    </div>
  )
}

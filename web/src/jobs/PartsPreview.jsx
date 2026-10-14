// Per-chain part preview of the message (the planner's R72 split; see lib/core.js). Counts, sizes and the header of
// part 1. Copy markers of later copies are not shown (copy 1 carries none).
import { useMemo } from 'react'
import { previewParts } from '@/lib/core.js'
import { CHAIN_NAME } from '@/keys/KeyStore.jsx'

export default function PartsPreview({ text, sha256 }) {
  const per = useMemo(() => (text && sha256 ? previewParts(text, sha256) : null), [text, sha256])
  if (!per) return null
  return (
    <div data-testid="parts-preview" className="space-y-1 rounded-md border p-2 text-xs">
      <div className="font-semibold">Parts per copy</div>
      {['eth', 'sol'].map((c) => {
        const x = per[c]
        if (!x.ok) return <div key={c} data-testid={`parts-${c}`} className="text-red-700">{CHAIN_NAME[c]}: cannot be split — {x.why}</div>
        const sizes = x.parts.map((p) => p.size)
        return (
          <div key={c} data-testid={`parts-${c}`} data-count={x.parts.length}>
            {CHAIN_NAME[c]}: <b>{x.parts.length}</b> transaction{x.parts.length === 1 ? '' : 's'} per copy
            <span className="text-muted-foreground"> · up to {x.max} B each · largest {Math.max(...sizes)} B · smallest {Math.min(...sizes)} B{x.parts.length > 1 ? ` · header ${x.parts[0].header} B on part 1` : ' · no header'}</span>
          </div>
        )
      })}
    </div>
  )
}

// The funding-source picker of the Arm dialog (W5, R47). The operator picks the source for EVERY try: there is no default
// and no automatic choice. Each armed chain needs one; a source that already paid an earlier try of the same message is
// refused by the API (source.reused), and with none unused left Arm is refused (source.exhausted). Each chain signs with
// its lane's key (new or imported). The guards are shown here so the refusal is expected, not a surprise.
import { useEffect, useId, useState } from 'react'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { SOURCE_GUARDS, SOURCE_LABEL, addSource, listSources } from './sources.js'

const NAME = { eth: 'Ethereum', sol: 'Solana', btc: 'Bitcoin' }

// useSources(active) -> { supported, labels, reload }  (loads when `active` turns on)
export function useSources(active) {
  const [st, setSt] = useState({ supported: false, labels: [], loaded: false })
  const reload = () => listSources().then((r) => setSt({ ...r, loaded: true }))
  useEffect(() => { if (active) reload() }, [active])
  return { ...st, reload }
}

export default function SourcePicker({ chains, value, onChange, sources, used = [] }) {
  const uid = useId()
  const [label, setLabel] = useState(''), [err, setErr] = useState(''), [busy, setBusy] = useState(false)
  if (!sources.supported) return null
  const add = async () => {
    setBusy(true); setErr('')
    try { await addSource(label); setLabel(''); await sources.reload() } catch (e) { setErr(`${e.guard || 'error'}: ${e.message}`) } finally { setBusy(false) }
  }
  const labelOk = SOURCE_LABEL.test(label)
  return (
    <fieldset data-testid="source-picker" className="space-y-2 rounded-md border p-2 text-xs">
      <legend className="px-1 font-semibold">Funding source for this try</legend>
      {sources.labels.length === 0
        ? <p data-testid="source-none" className="text-muted-foreground">No source is declared yet. Arm needs none until you declare one (below); once one exists, every try must name one.</p>
        : chains.map((c) => (
          <div key={c} className="flex items-center gap-2">
            <Label htmlFor={`${uid}-${c}`} className="w-20 text-xs">{NAME[c]}</Label>
            <select id={`${uid}-${c}`} name={`${uid}-${c}`} data-testid={`source-select-${c}`} value={value[c] ?? ''} onChange={(e) => onChange({ ...value, [c]: e.target.value })}
              className="h-8 rounded-md border bg-background px-2 text-xs">
              <option value="">pick a source…</option>
              {sources.labels.map((l) => <option key={l} value={l} disabled={used.includes(l)}>{used.includes(l) ? `${l} — used for this message` : l}</option>)}
            </select>
          </div>
        ))}
      <div className="flex items-end gap-2">
        <div className="space-y-1">
          <Label htmlFor={`${uid}-new`} className="text-xs">declare a source (label only; never deleted)</Label>
          <Input id={`${uid}-new`} name={`${uid}-new`} data-testid="source-new" value={label} onChange={(e) => setLabel(e.target.value)} autoComplete="off" spellCheck={false} placeholder="e.g. railgun-eth" />
        </div>
        <Button type="button" size="xs" variant="outline" data-testid="source-add" disabled={!labelOk || busy} onClick={add}>Add</Button>
      </div>
      {label !== '' && !labelOk && <p data-testid="source-label-hint" className="text-red-700"><b>source.label</b>: {SOURCE_GUARDS['source.label']}</p>}
      {err && <p data-testid="source-add-error" className="text-red-700">{err}</p>}
      <ul data-testid="source-rules" className="list-inside list-disc text-muted-foreground">
        <li>You pick the source for every try; nothing is chosen for you.</li>
        <li><b>source.reused</b>: {SOURCE_GUARDS['source.reused']}.</li>
        <li><b>source.exhausted</b>: {SOURCE_GUARDS['source.exhausted']}.</li>
        <li>Each chain signs with the key shown on its lane (new or imported); its backup must be verified first.</li>
      </ul>
    </fieldset>
  )
}

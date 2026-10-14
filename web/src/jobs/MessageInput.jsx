// The message field (R50): it starts EMPTY, nothing is pre-filled and the app ships no default text. "Load text file"
// decodes the bytes with TextDecoder('utf-8', { fatal: true, ignoreBOM: true }) (never FileReader.readAsText, which
// replaces invalid bytes without a word), then the same validation as typing; a refused file is not loaded. A loaded file
// is placed in the field for review and is never sent by itself. Shows bytes, sha256, the hex64 warning and the parts.
// Normalize (E1 ruling 4): CR, CRLF, U+2028/2029 and TAB stay refused, never rewritten silently. When the text (or a
// refused file) holds them, an explicit "Normalize line endings / tabs" button rewrites exactly those, and the page says
// what changed (lib/normalize.js).
import { useId, useMemo, useRef, useState } from 'react'
import { isRefusal } from '@vault-timelock/core/contracts'
import { Button } from '@/components/ui/button.jsx'
import { Label } from '@/components/ui/label.jsx'
import { Textarea } from '@/components/ui/textarea.jsx'
import { checkPayload, decodeUtf8, sha256Hex, validateMessage } from '@/lib/core.js'
import { describeSummary, normalizeSummary, normalizeText } from '@/lib/normalize.js'
import PartsPreview from './PartsPreview.jsx'

// -> { ok: true, ...{ bytes, sha256, warnings } } | { ok: false, guard, message }
export function checkMessage(text) {
  try { return { ok: true, ...validateMessage(text) } } catch (e) {
    if (isRefusal(e)) return { ok: false, guard: e.guardId, message: e.message }
    throw e
  }
}

// Timelocked mode (W7): the text is a whole published timelocked text, validated by core's checkPayload (the one validator).
// -> { ok: true, bytes, sha256, warnings: [], unlock, arId, contents, blocks, fits } | { ok: false, guard, message, issues }
// `guard`/`message` are the first refusal; `issues` lists every payload.* refusal, each in core's own plain words.
export function checkTimelocked(text) {
  const r = checkPayload(text)
  if (!r.ok) return { ok: false, guard: r.issues[0].id, message: r.issues[0].message, issues: r.issues }
  return { ok: true, bytes: new TextEncoder().encode(text).length, sha256: r.textSha256, warnings: r.warnings.map((w) => w.id), warningIssues: r.warnings, unlock: r.unlock, arId: r.arId, contents: r.contents, blocks: r.blocks, fits: r.fits }
}
export const checkText = (text, mode) => (mode === 'timelocked' ? checkTimelocked(text) : checkMessage(text))

export default function MessageInput({ value, onChange, disabled = false, mode = 'plain' }) {
  const timelocked = mode === 'timelocked'
  const fid = useId()
  const fileRef = useRef(null)
  const [loaded, setLoaded] = useState(null)        // { name, bytes, sha256 } of the last file looked at
  const [refusal, setRefusal] = useState(null)      // { guard, message } for a refused file
  const [normalized, setNormalized] = useState(null) // { what, bytes, sha256 } after the operator pressed Normalize
  const check = useMemo(() => (value === '' ? null : checkText(value, mode)), [value, mode])
  const pending = useMemo(() => (value === '' || timelocked ? null : normalizeSummary(value)), [value, timelocked])

  // The operator's explicit action: rewrite only line endings and tabs, then say what changed.
  const normalize = (text, after) => {
    const r = normalizeText(text)
    const b = new TextEncoder().encode(r.text)
    setNormalized({ what: describeSummary(r.summary), bytes: b.length, sha256: sha256Hex(b) })
    if (after) after(r.text)
    onChange(r.text)
  }

  const load = async (file) => {
    if (!file) return
    setRefusal(null); setLoaded(null); setNormalized(null)
    const raw = new Uint8Array(await file.arrayBuffer())
    const info = { name: file.name, bytes: raw.length, sha256: sha256Hex(raw) }
    try {
      const text = decodeUtf8(raw)
      const r = checkText(text, mode)
      if (!r.ok) {
        // a file refused only for its line endings / tabs can be loaded normalized, on the operator's click (plain mode only:
        // a timelocked text is refused, never rewritten)
        const fix = !timelocked && normalizeSummary(text).total > 0 && checkMessage(normalizeText(text).text).ok ? text : null
        setRefusal({ guard: r.guard, message: r.message, ...info, fix }); return
      }
      setLoaded(info); onChange(text)
    } catch (e) {
      if (isRefusal(e)) setRefusal({ guard: e.guardId, message: e.message, ...info }); else throw e
    }
  }

  return (
    <div className="space-y-2">
      <Label htmlFor={`${fid}-text`}>{timelocked ? 'Timelocked text (the whole published text, header line, ar:// line, note and SEALED.txt section)' : 'Message (plain text, published as written)'}</Label>
      <Textarea id={`${fid}-text`} name="message" data-testid="message" value={value} onChange={(e) => { setNormalized(null); onChange(e.target.value) }} disabled={disabled} rows={6} spellCheck={false} placeholder={timelocked ? 'Paste or load the timelocked text…' : 'Type the text to publish…'} className="font-mono" />
      <div className="flex flex-wrap items-center gap-2">
        <input ref={fileRef} id={`${fid}-file`} name="message-file" data-testid="message-file" type="file" accept=".txt,text/plain" className="hidden" disabled={disabled}
          onChange={(e) => { load(e.target.files?.[0]); e.target.value = '' }} />
        <Button type="button" size="sm" variant="outline" data-testid="load-text-file" disabled={disabled} onClick={() => fileRef.current?.click()}>Load text file</Button>
        <span className="text-xs text-muted-foreground">UTF-8, LF line breaks, NFC. Loaded into the field for review; never sent by itself.</span>
      </div>
      {refusal && (
        <p data-testid="message-refusal" className="rounded-md border border-red-600 bg-red-50 p-2 text-xs text-red-900">
          {refusal.name} refused ({refusal.bytes} bytes, sha256 <span className="font-mono">{refusal.sha256}</span>) — <b>{refusal.guard}</b>: {refusal.message}. Nothing was loaded.
          {refusal.fix !== null && refusal.fix !== undefined && (
            <span className="mt-1 block">
              Only its line endings / tabs are refused ({describeSummary(normalizeSummary(refusal.fix))}).{' '}
              <Button type="button" size="xs" variant="outline" data-testid="normalize-file" disabled={disabled}
                onClick={() => { const f = refusal; setRefusal(null); normalize(f.fix, () => setLoaded({ name: f.name, bytes: f.bytes, sha256: f.sha256 })) }}>
                Normalize line endings / tabs and load
              </Button>
            </span>
          )}
        </p>
      )}
      {pending && pending.total > 0 && (
        <div data-testid="normalize-offer" className="rounded-md border border-amber-500 bg-amber-50 p-2 text-xs text-amber-950">
          The text holds {describeSummary(pending).replace(/ → [^,]+/g, '')} — refused as written. Nothing is rewritten unless you press{' '}
          <Button type="button" size="xs" variant="outline" data-testid="normalize" disabled={disabled} onClick={() => normalize(value)}>Normalize line endings / tabs</Button>
          {' '}({describeSummary(pending)}).
        </div>
      )}
      {normalized && (
        <p data-testid="normalize-summary" className="rounded-md border border-sky-400 bg-sky-50 p-2 text-xs text-sky-950">
          Normalized on your request: {normalized.what}. Review the text: it is now {normalized.bytes} bytes, sha256 <span className="font-mono break-all">{normalized.sha256}</span>.
        </p>
      )}
      {loaded && <p data-testid="message-loaded" className="text-xs">Loaded <b>{loaded.name}</b>: {loaded.bytes} bytes, sha256 <span className="font-mono break-all">{loaded.sha256}</span></p>}
      {check && !check.ok && !timelocked && <p data-testid="message-issue" className="text-xs text-red-700"><b>{check.guard}</b>: {check.message}</p>}
      {check && !check.ok && timelocked && (
        <ul data-testid="message-issue" className="list-inside list-disc space-y-0.5 rounded-md border border-red-600 bg-red-50 p-2 text-xs text-red-900">
          {check.issues.map((i, n) => <li key={`${i.id}-${n}`} data-testid="payload-issue"><b>{i.id}</b>: {i.message}</li>)}
        </ul>
      )}
      {check?.ok && timelocked && (
        <div className="space-y-1 text-xs" data-testid="message-ok">
          <p>{check.bytes} bytes · sha256 <span data-testid="message-sha" className="font-mono break-all">{check.sha256}</span></p>
          <p data-testid="timelocked-facts">Unlocks <b>{check.unlock}</b> · contents <b>{check.contents}</b> · ar://<span className="font-mono">{check.arId}</span> · blocks {check.blocks.map((b) => `${b.name} (${b.bytes} B)`).join(', ')}</p>
          <p data-testid="timelocked-fits">Fits in one transaction: {['eth', 'btc', 'sol'].map((c) => `${c} ${check.fits[c] ? 'yes' : 'no'}`).join(' · ')}</p>
          {check.warningIssues.map((w) => <p key={w.id} data-testid="payload-warning" className="text-amber-900"><b>{w.id}</b>: {w.message}</p>)}
        </div>
      )}
      {check?.ok && !timelocked && (
        <div className="space-y-2" data-testid="message-ok">
          <p className="text-xs">{check.bytes} bytes · sha256 <span data-testid="message-sha" className="font-mono break-all">{check.sha256}</span></p>
          {check.warnings.includes('hex64') && (
            <p data-testid="message-hex64" className="rounded-md border border-amber-500 bg-amber-50 p-2 text-xs text-amber-950">
              Warning: the text contains a run of 64 hex characters. If that is a private key, stop: this text becomes public and permanent.
            </p>
          )}
          <PartsPreview text={value} sha256={check.sha256} />
        </div>
      )}
    </div>
  )
}

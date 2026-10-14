// Open (W7, #/open): paste or load a published timelocked text or a SEALED.txt, see when it opens, and once drand has published
// the round, decrypt it in this tab and offer each restored file as a download (lib/open.js).
//   · the text is parsed by core (sealedFiles); a refused text shows core's guard and message;
//   · before the round: "not yet", a countdown by the API's clock, and the only request ever made is drand's public/latest
//     (on the user's click, or once the countdown ends);
//   · after the round: the user presses a button; the page fetches that round through the relay, decrypts with tlock-js (+ age),
//     and lists the files. A download is a click on its own button: nothing downloads by itself;
//   · plaintext lives in this component's state only: never in storage, a URL, the log or a request. "Clear" drops it.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { isRefusal } from '@vault-timelock/core/contracts'
import { Button } from '@/components/ui/button.jsx'
import { Label } from '@/components/ui/label.jsx'
import { Textarea } from '@/components/ui/textarea.jsx'
import Countdown from '@/jobs/Countdown.jsx'
import { download, revokeAll } from '@/keys/download.js'
import { decodeUtf8 } from '@/lib/core.js'
import { decryptSealed, DrandError, latestRound, prepareOpen, relayDrandClient, wipe } from '@/lib/open.js'
import { createServerClock } from '@/lib/serverClock.js'
import { useStatus } from '@/lib/status.js'

const POLL_MS = 3000      // the quicknet period: a new round cannot appear faster

// -> { ok: true, prep } | { ok: false, guard, message }
export function readText(text) {
  try { return { ok: true, prep: prepareOpen(text) } } catch (e) {
    if (isRefusal(e)) return { ok: false, guard: e.guardId, message: e.message }
    throw e
  }
}

export default function Open({ client: injected = null }) {
  const { status } = useStatus()
  const [text, setText] = useState('')
  const [fileMsg, setFileMsg] = useState('')
  const fileRef = useRef(null)
  const clock = useMemo(() => createServerClock(), [])
  const client = useMemo(() => injected || relayDrandClient(), [injected])
  useEffect(() => { if (status && typeof status.serverNowMs === 'number') clock.sync(status.serverNowMs) }, [status, clock])
  const parsed = useMemo(() => (text.trim() === '' ? null : readText(text)), [text])

  const load = async (file) => {
    if (!file) return
    setFileMsg('')
    try { setText(decodeUtf8(new Uint8Array(await file.arrayBuffer()))) } catch (e) {
      if (isRefusal(e)) setFileMsg(`${file.name} refused (${e.guardId}): ${e.message}. Nothing was loaded.`); else throw e
    }
  }

  return (
    <section className="space-y-4" data-testid="open">
      <h1 className="text-lg font-semibold">Open</h1>
      <p className="text-sm text-muted-foreground">
        Paste a published timelocked text, or a SEALED.txt, or load it from a file. Before the unlock round this page sends nothing except drand&apos;s latest round number (through your relay), on your click or once the countdown ends; after it, it asks for that round&apos;s public signature. The decrypted files stay in this tab; you save each one with its button.
      </p>
      <div className="space-y-2">
        <Label htmlFor="open-text">Timelocked text or SEALED.txt</Label>
        <Textarea id="open-text" name="open-text" data-testid="open-text" value={text} onChange={(e) => setText(e.target.value)} rows={8} spellCheck={false} className="font-mono" placeholder="Paste the text…" />
        <div className="flex flex-wrap items-center gap-2">
          <input ref={fileRef} id="open-file" name="open-file" data-testid="open-file" type="file" accept=".txt,text/plain" className="hidden" onChange={(e) => { load(e.target.files?.[0]); e.target.value = '' }} />
          <Button type="button" size="sm" variant="outline" data-testid="open-load" onClick={() => fileRef.current?.click()}>Load text file</Button>
          {text !== '' && <Button type="button" size="sm" variant="outline" data-testid="open-reset" onClick={() => { setText(''); setFileMsg('') }}>Clear text</Button>}
        </div>
        {fileMsg && <p data-testid="open-file-refusal" className="text-xs text-red-700">{fileMsg}</p>}
      </div>
      {parsed && !parsed.ok && (
        <p data-testid="open-refusal" className="rounded-md border border-red-600 bg-red-50 p-2 text-sm text-red-900">
          This is not a valid timelocked text — <b>{parsed.guard}</b>: {parsed.message}. Nothing was fetched.
        </p>
      )}
      {parsed?.ok && <OpenPanel key={parsed.prep.text} prep={parsed.prep} client={client} clock={clock} />}
    </section>
  )
}

// Everything after a good parse. Keyed by the text: a new text is a new panel with nothing carried over.
function OpenPanel({ prep, client, clock }) {
  const [latest, setLatest] = useState(null)       // the latest published round, once asked
  const [drandErr, setDrandErr] = useState('')
  const [phase, setPhase] = useState('idle')       // idle | checking | decrypting | done | error
  const [result, setResult] = useState(null)       // { files, skipped, notes }
  const [err, setErr] = useState('')
  const [reached, setReached] = useState(false)    // the API clock reached the unlock time
  const published = latest !== null && latest >= prep.round

  const inFlight = useRef(false)
  const check = useCallback(async () => {
    if (inFlight.current) return false                 // exactly one check in flight
    inFlight.current = true
    setDrandErr(''); setPhase((p) => (p === 'idle' ? 'checking' : p))
    let ok = false
    try { setLatest(await latestRound(client)); ok = true } catch (e) { setDrandErr(e instanceof DrandError ? e.message : String(e?.message || e)) }
    inFlight.current = false
    setPhase((p) => (p === 'checking' ? 'idle' : p))
    return ok
  }, [client])

  // Once the API clock says the time has come, ask drand (public/latest only) until the round is published: one request at a
  // time, the next scheduled after the previous finishes, no faster than the quicknet period, backing off gently on failure
  // or while the round stays unpublished. The loop is keyed on `reached`/`published` only, and stops on unmount.
  useEffect(() => {
    if (!reached || published) return undefined
    let live = true, timer = null, n = 0
    const step = async () => {
      const ok = await check()
      if (!live) return
      n = ok ? Math.min(n + 1, 4) : Math.min(n + 2, 6)
      timer = setTimeout(step, POLL_MS * (1 + n * 0.5))
    }
    step()
    return () => { live = false; clearTimeout(timer) }
  }, [reached, published, check])

  const onComplete = useCallback(() => setReached(true), [])
  // M-4: plaintext is dropped explicitly, not left to GC: on Clear, on a new text, on leaving the page, the page zeroes every byte
  // array it owns and revokes the object URLs it made. (The browser's own copies of a saved file are out of the page's hands.)
  const urls = useRef(new Set())
  const held = useRef(null)
  const drop = useCallback(() => { wipe(held.current); held.current = null; revokeAll(urls.current) }, [])
  useEffect(() => drop, [drop])
  const decrypt = async () => {
    drop()
    setPhase('decrypting'); setErr(''); setResult(null)
    try { const r = await decryptSealed(prep, client); held.current = r; setResult(r); setPhase('done') } catch (e) { setErr(String(e?.message || e)); setPhase('error') }
  }
  const clear = () => { drop(); setResult(null); setPhase('idle'); setErr('') }
  const total = Math.max(1, Math.ceil((prep.unlockMs - (clock.now() ?? prep.unlockMs)) / 1000))

  return (
    <>
        <div className="space-y-3" data-testid="open-info">
          <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted-foreground">Unlocks</dt><dd data-testid="open-unlock">{prep.unlockIso} <span className="text-xs text-muted-foreground">({new Date(prep.unlockMs).toLocaleString()} your time)</span></dd>
            <dt className="text-muted-foreground">drand round</dt><dd data-testid="open-round" className="font-mono">{prep.round}</dd>
            <dt className="text-muted-foreground">Files</dt><dd data-testid="open-blocks" className="font-mono text-xs">{[...prep.files].map(([n, b]) => `${n} (${b.length} B)`).join(', ')}</dd>
            <dt className="text-muted-foreground">Contents</dt><dd data-testid="open-contents">{prep.contents === 'key-only' ? `key only (the payload is at ar://${prep.arId})` : 'full'}</dd>
          </dl>
          <Countdown target={prep.unlockMs} total={total} label="Unlocks in" now={clock.now} onComplete={onComplete} testid="open-countdown" />

          {prep.issues.length > 0 && (
            <div data-testid="open-warning" className="space-y-1 rounded-md border border-amber-500 bg-amber-50 p-3 text-sm text-amber-950">
              <p><b>Warning.</b> This text would not pass the publisher&apos;s check, so it is not exactly what this tool publishes (edited, or from another version). Open reads it anyway, as it does older texts; the encrypted blocks decrypt only if they are intact. Check where the text came from.</p>
              <ul className="list-inside list-disc text-xs">{prep.issues.map((i, n) => <li key={`${i.id}-${n}`} data-testid="open-warning-issue"><b>{i.id}</b>: {i.message}</li>)}</ul>
            </div>
          )}

          {!published && (
            <div data-testid="open-notyet" className="space-y-2 rounded-md border border-amber-500 bg-amber-50 p-3 text-sm text-amber-950">
              <p><b>Not yet.</b> Round {prep.round} has not been published by drand{latest !== null ? ` (the latest is ${latest})` : ''}. Until it is, nobody can open this, including this page.
                Nothing has been fetched except, at most, drand&apos;s latest round number.</p>
              {drandErr && <p data-testid="open-drand-error" className="text-xs">drand: {drandErr}</p>}
              <Button type="button" size="sm" variant="outline" data-testid="open-check" disabled={phase === 'checking'} onClick={check}>Check drand now</Button>
            </div>
          )}

          {published && phase !== 'done' && (
            <div data-testid="open-ready" className="space-y-2 rounded-md border border-emerald-600 bg-emerald-50 p-3 text-sm text-emerald-950">
              <p><b>Round {prep.round} is published.</b> The page can fetch its signature through the relay and decrypt in this tab.</p>
              <Button type="button" data-testid="open-decrypt" disabled={phase === 'decrypting'} onClick={decrypt}>{phase === 'decrypting' ? 'Decrypting…' : 'Fetch the round and decrypt'}</Button>
            </div>
          )}
          {err && <p data-testid="open-error" className="rounded-md border border-red-600 bg-red-50 p-2 text-sm text-red-900">{err}</p>}
        </div>

      {result && (
        <div className="space-y-2" data-testid="open-result">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold">Restored files ({result.files.length})</h2>
            <Button type="button" size="sm" variant="outline" data-testid="open-clear" onClick={clear}>Clear from this tab</Button>
          </div>
          {result.notes.map((n) => <p key={n} data-testid="open-note" className="text-xs text-amber-900">{n}</p>)}
          {result.skipped.map((s, i) => <p key={i} data-testid="open-skipped" className="text-xs text-amber-900">Skipped {s.name}: {s.why}</p>)}
          <ul className="space-y-1">
            {result.files.map((f, i) => (
              <li key={i} data-testid="open-file-row" className="flex flex-wrap items-center gap-2 rounded-md border px-3 py-1.5 text-sm">
                <span className="font-mono">{f.path}</span>
                {f.renamed && <span data-testid="open-file-renamed" className="text-xs text-amber-900">(the name held hidden characters or repeated another name; shown escaped or numbered, and saved under that name)</span>}
                <span className="text-xs text-muted-foreground">{f.size} B · sha256 <span className="font-mono">{f.sha256}</span></span>
                <Button type="button" size="xs" variant="outline" data-testid={`open-download-${f.name}`} onClick={() => download(f.bytes, f.name, urls.current)}>Download</Button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  )
}

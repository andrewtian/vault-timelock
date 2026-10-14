// Decrypt (vt decrypt, lane W, #/decrypt): paste or drop an armored age text, a binary .age or a SEALED.txt; the page shows what it is
// (core's detectInput), asks only for what that kind needs (a passphrase, an identity file, or, for a time lock, the relay), decrypts
// in this tab and offers the files as downloads. An archive is listed (path, size; names escaped) with a Download per file and
// "Download all (.tar.gz)".
//   · every decision is core's (@vault-timelock/core/decrypt via lib/decrypt.js); a refusal shows core's guard id and message;
//   · a time lock is judged BEFORE any request: core refuses decrypt.too-early without calling the relay, so before the round the
//     page sends nothing; after it, the only request is the relay's drand route for that round (the path Open uses);
//   · plaintext, the passphrase and the identity live in this component's state only: never in storage, a URL, the log or a request.
//     "Clear" (and leaving the page) zeroes every byte array the page owns and revokes the object URLs it made.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Button } from '@/components/ui/button.jsx'
import { Label } from '@/components/ui/label.jsx'
import { Textarea } from '@/components/ui/textarea.jsx'
import { download, revokeAll } from '@/keys/download.js'
import SecretInput from '@/keys/SecretInput.jsx'
import { DECRYPT_LIMITS, PASTE_LIMIT, escapeName, extractFile, identityText, inputOfFile, listFiles, readInput, relaySignatureFetcher, runDecrypt, wipeResult } from '@/lib/decrypt.js'
import { relayDrandClient } from '@/lib/open.js'

const KIND = {
  passphrase: 'passphrase (age scrypt)',
  identity: 'identity (age key)',
  timelocked: 'time-locked (tlock / drand)',
  sealed: 'SEALED.txt package',
}
const LAYOUT_LABEL = { 'two-layer': 'two-layer (time-locked key + vault)', vault: 'vault', secret: 'secret', payload: 'payload' }

export default function Decrypt({ client: injected = null }) {
  const client = useMemo(() => injected || relayDrandClient(), [injected])
  const [pasted, setPasted] = useState('')
  const [file, setFile] = useState(null)               // { name, input } from a drop / pick; replaces the paste field
  const [fileMsg, setFileMsg] = useState('')
  const [dragging, setDragging] = useState(false)
  const fileRef = useRef(null)
  const input = file ? file.input : pasted.trim() === '' ? null : pasted
  const parsed = useMemo(() => (input === null ? null : readInput(input, file ? undefined : { input: PASTE_LIMIT })), [input, file])

  const seq = useRef(0)
  const load = async (f) => {
    if (!f) return
    setFileMsg('')
    if (f.size > DECRYPT_LIMITS.input) { setFileMsg(`${escapeName(f.name)} is over the ${DECRYPT_LIMITS.input / (1024 * 1024)} MiB limit (decrypt.size). Nothing was read.`); return }   // @guard:web.decrypt-file-cap
    try {
      const bytes = new Uint8Array(await f.arrayBuffer())
      seq.current += 1   // @guard:web.decrypt-input-id
      setFile({ id: seq.current, name: f.name, input: inputOfFile(bytes) }); setPasted('')
    } catch { setFileMsg(`${escapeName(f.name)} could not be read. Nothing was loaded.`) }
  }
  const reset = () => { setPasted(''); setFile(null); setFileMsg('') }
  // A file dropped anywhere else on the page must not be opened by the browser (a dropped key would be shown in clear): while this tab is
  // mounted, the window's default for dragover / drop is cancelled; the drop zone above handles its own drops.
  useEffect(() => {
    const stop = (e) => { e.preventDefault() }   // @guard:web.decrypt-drop-default
    window.addEventListener('dragover', stop); window.addEventListener('drop', stop)
    return () => { window.removeEventListener('dragover', stop); window.removeEventListener('drop', stop) }
  }, [])
  const onDrop = (e) => { e.preventDefault(); setDragging(false); load(e.dataTransfer?.files?.[0]) }

  return (
    <section className="space-y-4" data-testid="decrypt">
      <h1 className="text-lg font-semibold">Decrypt</h1>
      <p className="text-sm text-muted-foreground">
        Paste or drop an age-encrypted text (<span className="font-mono">-----BEGIN AGE ENCRYPTED FILE-----</span>), a <span className="font-mono">.age</span> file, or a SEALED.txt. This page tells you what it is and asks only for what it needs. Everything is decrypted in this tab; nothing is stored. A time lock is checked before any request: before its round the page sends nothing, after it only the relay&apos;s request for that round&apos;s public signature.
      </p>
      <div className="space-y-2" onDragOver={(e) => { e.preventDefault(); setDragging(true) }} onDragLeave={() => setDragging(false)} onDrop={onDrop} data-testid="decrypt-drop" data-dragging={dragging}>
        <Label htmlFor="decrypt-text">Encrypted text, or drop a file here</Label>
        {file ? (
          <p data-testid="decrypt-filename" className="rounded-md border border-dashed p-3 text-sm">Loaded <span className="font-mono">{escapeName(file.name)}</span></p>
        ) : (
          <Textarea id="decrypt-text" name="decrypt-text" data-testid="decrypt-text" value={pasted} onChange={(e) => setPasted(e.target.value)} rows={8} spellCheck={false} className={`font-mono ${dragging ? 'border-primary' : ''}`} placeholder="Paste the armored text or the SEALED.txt…" />
        )}
        <div className="flex flex-wrap items-center gap-2">
          <input ref={fileRef} id="decrypt-file" name="decrypt-file" data-testid="decrypt-file" type="file" accept=".age,.txt,text/plain,application/octet-stream" className="hidden" onChange={(e) => { load(e.target.files?.[0]); e.target.value = '' }} />
          <Button type="button" size="sm" variant="outline" data-testid="decrypt-load" onClick={() => fileRef.current?.click()}>Load a file</Button>
          {(file || pasted !== '') && <Button type="button" size="sm" variant="outline" data-testid="decrypt-reset" onClick={reset}>Clear input</Button>}
        </div>
        {fileMsg && <p data-testid="decrypt-file-refusal" className="text-xs text-red-700">{fileMsg}</p>}
      </div>
      {parsed && !parsed.ok && (
        <p data-testid="decrypt-refusal" className="rounded-md border border-red-600 bg-red-50 p-2 text-sm text-red-900">
          This cannot be decrypted here — <b>{parsed.guard}</b>: {parsed.message}. Nothing was fetched.
        </p>
      )}
      {parsed?.ok && <DecryptPanel key={file ? `f:${file.id}` : pasted} input={input} detected={parsed.detected} client={client} />}
    </section>
  )
}

// Everything after a good detection. Keyed by the input: new input is a new panel with nothing carried over.
function DecryptPanel({ input, detected, client }) {
  const [passphrase, setPassphrase] = useState('')
  const [identity, setIdentity] = useState('')
  const [identityName, setIdentityName] = useState('')
  const [idMsg, setIdMsg] = useState('')
  const [phase, setPhase] = useState('idle')           // idle | working | done
  const [err, setErr] = useState(null)                 // { guard, message }
  const [view, setView] = useState(null)               // { result, listing }
  const idRef = useRef(null)
  const urls = useRef(new Set())
  const held = useRef(null)
  const fetcher = useMemo(() => relaySignatureFetcher(client), [client])

  // Plaintext is dropped explicitly: on Clear, on new input, on leaving the page.
  const drop = useCallback(() => {
    wipeResult(held.current)   // @guard:web.decrypt-wipe
    held.current = null; revokeAll(urls.current)
  }, [])
  const live = useRef(true)
  useEffect(() => { live.current = true; return () => { live.current = false; drop() } }, [drop])

  const { kind } = detected
  const needsPass = kind === 'passphrase'
  const needsIdentity = kind === 'identity'
  const timeLock = kind === 'timelocked' || kind === 'sealed'
  const recoveryOk = kind === 'sealed' && detected.identityPath          // a SEALED.txt may also open with its one-time key, any time
  const ready = phase !== 'working' && (needsPass ? passphrase !== '' : needsIdentity ? identity !== '' : true)

  const pickIdentity = async (f) => {
    if (!f) return
    setIdMsg('')
    if (f.size > DECRYPT_LIMITS.secret) { setIdMsg(`${escapeName(f.name)} is too big to be an identity file. Nothing was loaded.`); return }   // @guard:web.decrypt-identity-cap
    try { setIdentity(await f.text()); setIdentityName(f.name) } catch { setIdMsg(`${escapeName(f.name)} could not be read. Nothing was loaded.`) }
  }

  const run = async () => {
    drop(); setView(null); setErr(null); setPhase('working')
    await new Promise((r) => setTimeout(r, 0))          // let the "Decrypting…" state paint before scrypt blocks the thread
    const how = { fetchRoundSignature: fetcher }
    if (needsPass) how.passphrase = passphrase
    if ((needsIdentity || recoveryOk) && identity !== '') how.identity = identityText(identity)
    const out = await runDecrypt(input, how).catch((e) => ({ ok: false, guard: 'error', message: String(e?.message || e) }))
    if (!out.ok) { if (!live.current) return; setErr({ guard: out.guard, message: out.message }); setPhase('idle'); return }
    held.current = out.result
    let listing = null
    try { listing = out.result.archive ? await listFiles(out.result.archive) : null } catch (e) { listing = { error: `${String(e?.message || e)}` } }
    if (!live.current) { wipeResult(out.result); held.current = null; return }   // @guard:web.decrypt-live
    setView({ result: out.result, listing })
    setPassphrase(''); setIdentity(''); setIdentityName('')   // @guard:web.decrypt-secrets-dropped
    setPhase('done')
  }
  const clear = () => { drop(); setView(null); setErr(null); setPhase('idle') }

  // One extracted file → download → wipe the page's copy (the Blob has its own).
  const saveOne = async (archive, e) => {
    let bytes
    try { bytes = await extractFile(archive, e.orig) } catch { return }   // the bytes were cleared meanwhile: nothing to save
    try { download(bytes, e.name, urls.current) } finally { bytes.fill(0) }
  }

  return (
    <div className="space-y-3" data-testid="decrypt-info">
      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-muted-foreground">Kind</dt><dd data-testid="decrypt-kind" data-kind={kind}>{KIND[kind]}</dd>
        <dt className="text-muted-foreground">Form</dt><dd data-testid="decrypt-form">{detected.form}</dd>
        {detected.opensAt && <><dt className="text-muted-foreground">Opens at</dt><dd data-testid="decrypt-opens">{detected.opensAt} <span className="text-xs text-muted-foreground">(drand round {detected.round})</span></dd></>}
        {kind === 'sealed' && <>
          <dt className="text-muted-foreground">Package</dt><dd data-testid="decrypt-layout">{LAYOUT_LABEL[detected.layout]}, {detected.contents === 'key-only' ? `key only (the archive is at ar://${detected.arId})` : 'full'}</dd>
          <dt className="text-muted-foreground">Blocks</dt><dd data-testid="decrypt-blocks" className="font-mono text-xs">{detected.blocks.map((b) => `${escapeName(b.name)} (${b.size} B)`).join(', ')}</dd>
        </>}
      </dl>

      {needsPass && (
        <div className="space-y-1">
          <Label htmlFor="decrypt-pass" className="text-xs">Passphrase</Label>
          <SecretInput id="decrypt-pass" data-testid="decrypt-pass" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} />
        </div>
      )}
      {(needsIdentity || recoveryOk) && (
        <div className="space-y-1">
          <p className="text-xs font-medium">{needsIdentity ? 'Identity file (AGE-SECRET-KEY-1…)' : 'Optional: the one-time key (identity.key / the recovery key), to open without waiting for the time lock'}</p>
          <input ref={idRef} data-testid="decrypt-identity-file" aria-label="Identity file" type="file" className="hidden" onChange={(e) => { pickIdentity(e.target.files?.[0]); e.target.value = '' }} />
          <div className="flex flex-wrap items-center gap-2">
            <Button type="button" size="sm" variant="outline" data-testid="decrypt-identity-pick" onClick={() => idRef.current?.click()}>Choose identity file</Button>
            {identity !== '' && <span data-testid="decrypt-identity-loaded" className="text-xs text-muted-foreground">Loaded {escapeName(identityName || 'a pasted key')} (kept in this tab only)</span>}
          </div>
          <Label htmlFor="decrypt-identity-paste" className="text-xs">or paste the key</Label>
          <SecretInput id="decrypt-identity-paste" data-testid="decrypt-identity-paste" value={identity} onChange={(e) => { setIdentity(e.target.value); setIdentityName('') }} />
          {idMsg && <p data-testid="decrypt-identity-refusal" className="text-xs text-red-700">{idMsg}</p>}
        </div>
      )}
      {timeLock && !(identity !== '' && (needsIdentity || recoveryOk)) && (
        <p data-testid="decrypt-timelock-note" className="rounded-md border border-amber-500 bg-amber-50 p-2 text-xs text-amber-950">
          Opens at <b>{detected.opensAt}</b>. Before then nobody can open it, including this page, and the page sends nothing. After it, the page asks the relay for that round&apos;s public signature (nothing else leaves this tab).
        </p>
      )}

      <Button type="button" data-testid="decrypt-run" disabled={!ready} onClick={run}>{phase === 'working' ? 'Decrypting…' : timeLock && !(identity !== '' && recoveryOk) ? 'Fetch the round and decrypt' : 'Decrypt'}</Button>
      {err && <p data-testid="decrypt-error" role="alert" className="rounded-md border border-red-600 bg-red-50 p-2 text-sm text-red-900"><b>{err.guard}</b>: {escapeName(err.message)}</p>}
      {view && <Result view={view} urls={urls} saveOne={saveOne} onClear={clear} />}
    </div>
  )
}

function Result({ view, urls, saveOne, onClear }) {
  const { result, listing } = view
  const archive = result.archive
  const archiveFile = archive ? result.files.find((f) => f.name === archive.name) ?? null : null
  const others = result.files.filter((f) => f !== archiveFile)
  const outName = (f) => (f.name === 'plaintext' ? 'decrypted' : f.name)
  const archiveName = archive && archive.name.endsWith('.tar.gz') ? archive.name : 'decrypted.tar.gz'
  return (
    <div className="space-y-2" data-testid="decrypt-result">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold">Decrypted ({result.via})</h2>
        <Button type="button" size="sm" variant="outline" data-testid="decrypt-clear" onClick={onClear}>Clear from this tab</Button>
      </div>
      {result.notes.map((n) => <p key={n} data-testid="decrypt-note" className="text-xs text-amber-900">{n}</p>)}
      {others.length > 0 && (
        <ul className="space-y-1">
          {others.map((f) => (
            <li key={f.name} data-testid="decrypt-file-row" className="flex flex-wrap items-center gap-2 rounded-md border px-3 py-1.5 text-sm">
              <span className="font-mono">{escapeName(outName(f))}</span>
              <span className="text-xs text-muted-foreground">{f.size} B · sha256 <span className="font-mono">{f.sha256}</span></span>
              <Button type="button" size="xs" variant="outline" data-testid={`decrypt-download-${outName(f)}`} onClick={() => download(f.bytes, outName(f), urls.current)}>Download</Button>
            </li>
          ))}
        </ul>
      )}
      {archive && (
        <div className="space-y-1" data-testid="decrypt-archive">
          {listing?.error ? (
            <p data-testid="decrypt-archive-error" className="text-xs text-amber-900">
              This archive is not safe: it holds entries that write outside a folder or link elsewhere, or is damaged ({escapeName(listing.error)}). Do not unpack it with tar. {archiveFile ? 'The decrypted file as a whole can still be saved for inspection.' : ''}
            </p>
          ) : null}
          {listing?.error ? (
            archiveFile && <Button type="button" size="xs" variant="outline" data-testid="decrypt-download-whole" onClick={() => download(archiveFile.bytes, outName(archiveFile), urls.current)}>Download</Button>
          ) : (
            <>
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold">Files ({listing.entries.length})</h3>
                {archiveFile && <Button type="button" size="xs" variant="outline" data-testid="decrypt-download-all" onClick={() => download(archiveFile.bytes, archiveName, urls.current)}>Download all (.tar.gz)</Button>}
              </div>
              <ul className="space-y-1">
                {listing.entries.map((e) => (
                  <li key={e.name} data-testid="decrypt-entry-row" className="flex flex-wrap items-center gap-2 rounded-md border px-3 py-1.5 text-sm">
                    <span className="font-mono" data-testid="decrypt-entry-path">{e.path}</span>
                    {e.renamed && <span data-testid="decrypt-entry-renamed" className="text-xs text-amber-900">(the name held hidden characters or repeated another name; shown escaped or numbered, and saved under that name)</span>}
                    <span className="text-xs text-muted-foreground">{e.size} B</span>
                    <Button type="button" size="xs" variant="outline" data-testid={`decrypt-entry-download-${e.name}`} onClick={() => saveOne(archive, e)}>Download</Button>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
      {!archive && others.length === 0 && <p className="text-xs text-muted-foreground">Nothing was restored.</p>}
    </div>
  )
}

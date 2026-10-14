// One key per chain lane (ported from the prototype's KeyLane.jsx). A required choice New | Import (no default), then a
// REQUIRED per-chain encrypted backup that is verified FROM THE SAVED FILE (I1, R58): the operator re-selects the
// downloaded file and types its passphrase again; the lane unlocks only if that file decrypts to exactly the in-memory
// key. A key imported FROM such a backup needs no new backup. A backup made for another network is REFUSED (R71, spec §3.4; web.backup-network); one that
// records no network (the prototype's) needs an explicit tick. The key lives in the KeyStore (tab memory) and signs every transaction of its lane. Secret fields are
// password-manager-proof (I4); nothing is stored or logged. No <form> anywhere.
// W3: `importOnly` (the job page: a job's key already exists, so only Import is offered), and the KeyStore entry records
// the network its backup names (`network`; null for a prototype backup), which the executor's LoadedKey carries.
import { useId, useRef, useState } from 'react'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { decryptKeyFile, encryptKey, fromSecret, keyFileName, newKey, passphraseCheck, verifySavedFile } from '@/lib/core.js'
import { currentNetwork, useStatus } from '@/lib/status.js'
import { download } from './download.js'
import { CHAIN_NAME as NAME, useKeys } from './KeyStore.jsx'
import SecretInput from './SecretInput.jsx'

const HINT = { eth: '0x + 64 hex private key', sol: 'base58 64-byte secret key, or the Solana CLI JSON array [n,…] of 64 numbers', btc: '64 hex characters (a secp256k1 private key; the lane address is its p2wpkh)' }
const short = (e) => String(e?.message || e).slice(0, 200)
const bytesOf = async (file) => new Uint8Array(await file.arrayBuffer())

function Check({ id, checked, onChange, testid, children }) {
  return (
    <label htmlFor={id} className="flex items-start gap-2 text-xs">
      <input id={id} name={id} type="checkbox" data-testid={testid} checked={checked} onChange={(e) => onChange(e.target.checked)} className="mt-0.5" />
      <span>{children}</span>
    </label>
  )
}

export default function KeyLane({ chain, locked = false, importOnly = false }) {
  const uid = useId()
  const id = (s) => `${uid}-${s}`
  const { keys, setKey, clearKey } = useKeys()
  const ctx = useStatus()
  const network = currentNetwork(ctx)
  const held = keys[chain] || null

  const [step, setStep] = useState('choose')            // choose → import → backup | netack → (held)
  const [mode, setMode] = useState(null)                // import: 'key' | 'file'
  const keyRef = useRef(null)                           // the key while the lane is being set up
  const [source, setSource] = useState(null)            // new | imported | from backup
  const [secret, setSecret] = useState(''), [derived, setDerived] = useState(null), [err, setErr] = useState('')
  const [file, setFile] = useState(null), [fpass, setFpass] = useState('')
  const [p1, setP1] = useState(''), [p2, setP2] = useState('')
  const [bk, setBk] = useState(null)                    // { name, size, verified, checked }
  const [vfile, setVfile] = useState(null), [vpass, setVpass] = useState('')
  const [saved, setSaved] = useState(false)
  const [netAck, setNetAck] = useState(false)
  const [made, setMade] = useState(null)                // the network a loaded backup names (null: none recorded)
  const [busy, setBusy] = useState(false)
  const pc = passphraseCheck(p1)

  const reset = () => {
    keyRef.current = null
    setStep('choose'); setMode(null); setSource(null); setSecret(''); setDerived(null); setErr(''); setFile(null); setFpass('')
    setP1(''); setP2(''); setBk(null); setVfile(null); setVpass(''); setSaved(false); setNetAck(false); setMade(null)
  }
  // a new backup records this page's network; a loaded one the network it names
  const finish = (src, fileName, net = network) => { const key = keyRef.current; reset(); setKey(chain, { key, source: src, file: fileName, network: net ?? null }) }

  const chooseNew = () => { keyRef.current = newKey(chain, network); setSource('new'); setStep('backup') }
  const check = () => { try { const k = fromSecret(chain, secret, network); keyRef.current = k; setDerived(k.address); setErr('') } catch (e) { keyRef.current = null; setDerived(null); setErr(short(e)) } }
  const useKey = () => { setSource('imported'); setSecret(''); setStep('backup') }
  const loadFile = async () => {
    setBusy(true); setErr('')
    try {
      const { key, network: made } = await decryptKeyFile(await bytesOf(file), fpass, chain, network)
      keyRef.current = key; setFpass(''); setSource('from backup'); setDerived(key.address); setMade(made)
      if (made == null) { setNetAck(false); setStep('netack') }      // no network recorded: the tick, as before
      else if (made !== network) {                                                                 // R71 / spec §3.4: another network is REFUSED, no override
        keyRef.current = null; setDerived(null); setSource(null); setMade(null)                    // @guard:web.backup-network
        setErr(`This backup was made on the ${made} network, but this page is on ${network}. A key backup is never used on another network (backup.network); open the page for ${made}, or use a backup made on ${network}.`)
      } else finish('from backup', file.name, made)
    } catch (e) { keyRef.current = null; setErr(short(e)) } finally { setBusy(false) }
  }
  const makeBackup = async () => {
    setBusy(true); setErr('')
    try {
      const { ct } = await encryptKey(keyRef.current, p1, network)
      const name = keyFileName(keyRef.current)
      download(ct, name)
      setBk({ name, size: ct.length, verified: false }); setP1(''); setP2('')
    } catch (e) { setErr(short(e)) } finally { setBusy(false) }
  }
  // The download may never have arrived (blocked, cancelled, disk full): back to the passphrase step with the SAME key. No ciphertext
  // is kept; the next makeBackup re-encrypts with a fresh salt and a new file name.
  const redoBackup = () => { setBk(null); setVfile(null); setVpass(''); setP1(''); setP2(''); setErr('') }   // @guard:web.backup-redo
  const verifyFile = async () => {                                     // I1: decrypt the re-selected SAVED file
    setBusy(true); setErr('')
    try { await verifySavedFile(await bytesOf(vfile), vpass, keyRef.current); setBk((b) => ({ ...b, verified: true, checked: vfile.name })); setVpass('') }
    catch (e) { setErr(/passphrase|backup file/i.test(short(e)) ? 'the selected file does not open with that passphrase — pick the file you just saved and type its passphrase' : short(e)) }
    finally { setBusy(false) }
  }
  const tickSaved = (v) => { setSaved(v); if (v && bk?.verified) finish(source, bk.name) }

  return (
    <div data-testid={`keylane-${chain}`} data-step={held ? 'ready' : step} className="min-w-0 space-y-2 rounded-lg border p-3 text-sm">
      <div className="flex items-center justify-between">
        <b>{NAME[chain]} key</b>
        {held && !locked && <Button variant="outline" size="xs" data-testid={`kreplace-${chain}`} onClick={() => { clearKey(chain); reset() }}>Replace key</Button>}
      </div>
      {held ? (
        <div className="space-y-1 text-xs">
          <div>address <span data-testid={`kaddr-${chain}`} className="break-all font-mono">{held.key.address}</span></div>
          <div>key source: <b data-testid={`ksource-${chain}`}>{held.source}</b>{held.file ? <> · backup <span className="font-mono">{held.file}</span></> : ''}</div>
          <div className="text-muted-foreground">This key signs every transaction of the {NAME[chain]} lane (all copies and parts). It exists only in this tab&apos;s memory. {locked ? 'Locked while armed.' : ''}</div>
        </div>
      ) : step === 'choose' ? (
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground">Required: choose how this lane gets its key. Nothing else in the {NAME[chain]} lane is enabled until the key and its backup are done.</p>
          <div className="flex gap-2">
            {!importOnly && <Button size="sm" data-testid={`keychoice-${chain}-new`} disabled={locked} onClick={chooseNew}>New key</Button>}
            <Button size="sm" variant="outline" data-testid={`keychoice-${chain}-import`} disabled={locked} onClick={() => setStep('import')}>Import</Button>
          </div>
        </div>
      ) : step === 'import' ? (
        <div className="space-y-2">
          <div className="flex gap-2">
            <Button size="xs" variant={mode === 'key' ? 'default' : 'outline'} data-testid={`kimport-${chain}-key`} onClick={() => { setMode('key'); setErr('') }}>Private key</Button>
            <Button size="xs" variant={mode === 'file' ? 'default' : 'outline'} data-testid={`kimport-${chain}-file`} onClick={() => { setMode('file'); setErr('') }}>Backup file</Button>
            <Button size="xs" variant="ghost" onClick={reset}>Back</Button>
          </div>
          {mode === 'key' && (
            <div className="space-y-2">
              <Label htmlFor={id('secret')} className="text-xs">{HINT[chain]}</Label>
              <SecretInput id={id('secret')} data-testid={`ksecret-${chain}`} value={secret} onChange={(e) => { setSecret(e.target.value); setDerived(null); keyRef.current = null }} />
              <Button size="xs" variant="outline" data-testid={`kcheck-${chain}`} disabled={!secret} onClick={check}>Check key</Button>
              {derived && (
                <div className="rounded-md border p-2 text-xs">derived address <span data-testid={`kderived-${chain}`} className="break-all font-mono">{derived}</span>
                  <div className="mt-1"><Button size="xs" data-testid={`kuse-${chain}`} onClick={useKey}>Use this key → backup</Button></div></div>
              )}
            </div>
          )}
          {mode === 'file' && (
            <div className="space-y-2">
              <Label htmlFor={id('file')} className="text-xs">Backup file (.age, from this page or the earlier page)</Label>
              <input id={id('file')} name={id('file')} data-testid={`kfile-${chain}`} type="file" accept=".age" onChange={(e) => setFile(e.target.files?.[0] || null)} className="block text-xs" />
              <Label htmlFor={id('fpass')} className="text-xs">Passphrase of that backup</Label>
              <SecretInput id={id('fpass')} data-testid={`kfilepass-${chain}`} value={fpass} onChange={(e) => setFpass(e.target.value)} />
              <Button size="xs" variant="outline" data-testid={`kfileload-${chain}`} disabled={busy || !file || !fpass} onClick={loadFile}>{busy ? 'Decrypting…' : 'Load key from backup'}</Button>
            </div>
          )}
        </div>
      ) : step === 'netack' ? (
        <div className="space-y-2 text-xs" data-testid={`knetwarn-${chain}`}>
          <div>address <span className="break-all font-mono">{derived}</span></div>
          <div className="rounded-md border border-amber-500 bg-amber-50 p-2 text-amber-950">
            <>This backup does not record a network (it was made before networks existed), and this page is on <b>{network}</b>.</>
            {' '}The same key is valid on every network; reusing it here links your activity across networks.
          </div>
          <Check id={id('netack')} testid={`knetack-${chain}`} checked={netAck} onChange={setNetAck}>I understand; use this key on {network}.</Check>
          <div className="flex gap-2">
            <Button size="xs" data-testid={`kfileuse-${chain}`} disabled={!netAck} onClick={() => finish('from backup', file.name, made)}>Use this key</Button>
            <Button size="xs" variant="ghost" onClick={reset}>Cancel</Button>
          </div>
        </div>
      ) : (
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground">{source === 'new' ? "A new key was generated in this tab's memory." : 'Key imported (address checked above).'} Required: download its encrypted backup, then prove the SAVED file opens. This file and its passphrase are the only way back to the key.</p>
          {!bk && (
            <>
              <Label htmlFor={id('p1')} className="text-xs">Backup passphrase</Label>
              <SecretInput id={id('p1')} data-testid={`kpass1-${chain}`} value={p1} onChange={(e) => setP1(e.target.value)} />
              <Label htmlFor={id('p2')} className="text-xs">Repeat passphrase</Label>
              <SecretInput id={id('p2')} data-testid={`kpass2-${chain}`} value={p2} onChange={(e) => setP2(e.target.value)} />
              <p className={`text-xs ${pc.ok && p1 === p2 ? 'text-emerald-700' : 'text-muted-foreground'}`}>{p1 ? pc.hint : 'need ≥ 6 distinct words or ≥ 20 mixed chars (a separate passphrase per chain is fine)'}{p1 && p2 && p1 !== p2 ? ' · the two entries differ' : ''}</p>
              <Button size="sm" data-testid={`kbackup-${chain}`} disabled={busy || !pc.ok || p1 !== p2} onClick={makeBackup}>{busy ? 'Encrypting (scrypt)…' : `Download ${NAME[chain]} key backup`}</Button>
            </>
          )}
          {bk && !bk.verified && (
            <div className="space-y-2 rounded-md border border-amber-500 bg-amber-50 p-2 text-xs text-amber-950" data-testid={`kverifybox-${chain}`}>
              <div>Download started: <b className="font-mono">{bk.name}</b> ({bk.size} B). Check your downloads folder, then prove it was saved: select <b>that file</b> where you saved it and type its passphrase again, from memory.</div>
              <Label htmlFor={id('vfile')} className="text-xs">The saved backup file</Label>
              <input id={id('vfile')} name={id('vfile')} data-testid={`kverifyfile-${chain}`} type="file" accept=".age" onChange={(e) => setVfile(e.target.files?.[0] || null)} className="block text-xs" />
              <Label htmlFor={id('vpass')} className="text-xs">Passphrase of the saved file</Label>
              <SecretInput id={id('vpass')} data-testid={`kverifypass-${chain}`} value={vpass} onChange={(e) => setVpass(e.target.value)} />
              <Button size="xs" variant="outline" data-testid={`kverify-${chain}`} disabled={busy || !vfile || !vpass} onClick={verifyFile}>{busy ? 'Decrypting…' : 'Verify the saved file'}</Button>
              <div><Button size="xs" variant="ghost" data-testid={`kredo-${chain}`} disabled={busy || locked} onClick={redoBackup}>The file did not arrive — make the backup again</Button></div>
            </div>
          )}
          {bk?.verified && (
            <div className="space-y-2 rounded-md border border-emerald-600 bg-emerald-50 p-2 text-xs text-emerald-950">
              <div data-testid={`kverified-${chain}`} data-ok="true">verified ✓ — the saved file <span className="font-mono">{bk.checked}</span> decrypts with the typed passphrase to exactly this key</div>
              <Check id={id('saved')} testid={`ksaved-${chain}`} checked={saved} onChange={tickSaved}>I saved this backup</Check>
            </div>
          )}
        </div>
      )}
      {err && <p className="text-xs text-red-700" data-testid={`kerr-${chain}`}>{err}</p>}
    </div>
  )
}

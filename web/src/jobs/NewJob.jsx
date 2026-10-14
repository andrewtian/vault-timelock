// New job (W2): name, message (starts empty), per-chain lane (config + key + backup), funding, then Create:
// PUT /messages/<sha> followed by POST /jobs with the canonical input (message by digest, never inline, no key material:
// only the public key address). Job files (vt-job/1 JSON) can be imported into and exported from the form; they carry
// no keys, so the key lanes decide the addresses.
import { useMemo, useRef, useState } from 'react'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { api, putMessage } from '@/lib/api.js'
import { useTabBusy } from '@/lib/busy.js'
import { currentNetwork, NETWORK_LABEL, useStatus } from '@/lib/status.js'
import { BTC_BODY_MAX, btcAvailable, btcCapability } from '@/lib/btc.js'
import { download } from '@/keys/download.js'
import KeyLane from '@/keys/KeyLane.jsx'
import { useKeys } from '@/keys/KeyStore.jsx'
import ChainConfig, { chainInput, chainIssues, configFromInput, defaultChainConfig } from './ChainConfig.jsx'
import FundingTabs from '@/funding/FundingTabs.jsx'
import MessageInput, { checkText } from './MessageInput.jsx'
import PriceLine, { usePrice } from './PriceLine.jsx'

const CHAINS = ['eth', 'sol', 'btc']
// W7: the API (core's validator) still refuses textKind 'timelocked' with job.publish-mode-unavailable until a backend task enables
// it. The page says so and does not offer Create for that kind. When the backend lands, this is the one line to flip.
export const TIMELOCKED_PUBLISHING = false
const NAME_OK = /^[\x20-\x7e]{1,64}$/

// The vt-job/1 input from the form state (message by digest).
// textKind is sent only for a timelocked text; absent means plain (CC-7: the same job, the same id).
export function buildJobInput({ network, name, check, cfgs, addresses, mode = 'plain' }) {
  const chains = {}
  for (const c of CHAINS) if (cfgs[c]?.enabled) chains[c] = chainInput(c, cfgs[c], addresses[c])
  return { format: 'vt-job/1', network, name, messageSha256: check.sha256, messageBytes: check.bytes, chains, ...(mode === 'timelocked' ? { textKind: 'timelocked' } : {}) }
}

export function exportJobFile({ network, name, text, cfgs, addresses, mode = 'plain' }) {
  const chains = {}
  for (const c of CHAINS) if (cfgs[c]?.enabled) chains[c] = chainInput(c, cfgs[c], addresses[c] || '')
  return JSON.stringify({ format: 'vt-job/1', network, name, message: text, chains, ...(mode === 'timelocked' ? { textKind: 'timelocked' } : {}) }, null, 2) + '\n'
}

export default function NewJob({ navigate = (hash) => { window.location.hash = hash } }) {
  const ctx = useStatus()
  const network = currentNetwork(ctx)
  const { keys } = useKeys()
  const busy = useTabBusy()
  const { price, err: priceErr } = usePrice()
  const [name, setName] = useState('')
  const [text, setText] = useState('')
  const [mode, setMode] = useState('plain')           // 'plain' | 'timelocked' (textKind)
  const [cfgs, setCfgs] = useState({ eth: defaultChainConfig('eth'), sol: defaultChainConfig('sol'), btc: defaultChainConfig('btc') })
  const [msg, setMsg] = useState({ kind: '', text: '' })
  const [imported, setImported] = useState(null)      // { addresses } named by the imported job file
  const [creating, setCreating] = useState(false)
  const fileRef = useRef(null)

  const addresses = useMemo(() => ({ eth: keys.eth?.key.address || '', sol: keys.sol?.key.address || '', btc: keys.btc?.key.address || '' }), [keys])
  const check = useMemo(() => (text === '' ? null : checkText(text, mode)), [text, mode])
  const enabled = CHAINS.filter((c) => cfgs[c].enabled)
  const cap = btcCapability()
  const problems = []
  if (!network) problems.push('the network is not known yet (is the API running?)')
  if (ctx.mismatch) problems.push(ctx.mismatch.message)
  if (!NAME_OK.test(name)) problems.push('name: 1 to 64 printable ASCII characters')
  if (!check?.ok) problems.push(mode === 'timelocked' ? 'message: paste or load a valid timelocked text' : 'message: type or load a valid text')
  if (mode === 'timelocked' && !TIMELOCKED_PUBLISHING) problems.push('timelocked publishing is not enabled yet')
  if (enabled.length === 0) problems.push('enable at least one chain')
  if (enabled.includes('btc')) {
    if (!btcAvailable(network)) problems.push('btc: the Bitcoin lane is not available yet on this network (local only for now)')
    else if (!cap.jobs) problems.push('btc: the job service does not accept a Bitcoin lane yet (job.chain-unsupported until the btc.inscription publish mode is enabled)')
    if (check?.ok && check.bytes > BTC_BODY_MAX) problems.push(`btc: one copy is one inscription of at most ${BTC_BODY_MAX} bytes; this text has ${check.bytes}`)
  }
  for (const c of enabled) {
    if (!addresses[c]) problems.push(`${c}: key and backup not done`)
    for (const i of chainIssues(c, cfgs[c], network)) problems.push(`${c} ${i}`)
  }

  const create = async () => {
    setMsg({ kind: '', text: '' }); setCreating(true); busy.set('creating the job', 'job-create')
    try {
      await putMessage(check.sha256, text)
      const out = await api('/jobs', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(buildJobInput({ network, name, check, cfgs, addresses, mode })) })
      setMsg({ kind: 'ok', text: `created job ${out.id}` })
      navigate(`#/jobs/${out.id}`)
    } catch (e) {
      setMsg({ kind: 'err', text: `${e.guard || 'error'}: ${e.message}` })
    } finally { setCreating(false); busy.set(null, 'job-create') }
  }

  const exportFile = () => {
    const body = exportJobFile({ network, name, text, cfgs, addresses, mode })
    download(new TextEncoder().encode(body), `vt-job-${name.replace(/[^A-Za-z0-9._-]+/g, '-').slice(0, 40) || 'job'}.json`)
  }

  const importFile = async (file) => {
    if (!file) return
    setMsg({ kind: '', text: '' })
    let j
    try { j = JSON.parse(await file.text()) } catch { setMsg({ kind: 'err', text: 'job file: not JSON' }); return }
    if (!j || typeof j !== 'object' || j.format !== 'vt-job/1') { setMsg({ kind: 'err', text: 'job file: not a vt-job/1 file' }); return }
    if (j.network !== network) { setMsg({ kind: 'err', text: `job.network: the file is for ${j.network}, this page is on ${network}. Nothing was imported.` }); return }
    if (typeof j.message !== 'string') { setMsg({ kind: 'err', text: 'job file: it has no inline message (a messageFile is for the vt CLI). Use Load text file.' }); return }
    setName(typeof j.name === 'string' ? j.name : '')
    setText(j.message)
    setMode(j.textKind === 'timelocked' ? 'timelocked' : 'plain')
    setCfgs({ eth: configFromInput('eth', j.chains?.eth), sol: configFromInput('sol', j.chains?.sol), btc: configFromInput('btc', j.chains?.btc) })
    setImported({ addresses: { eth: j.chains?.eth?.keyAddress || '', sol: j.chains?.sol?.keyAddress || '', btc: j.chains?.btc?.keyAddress || '' } })
    setMsg({ kind: 'ok', text: 'job file imported; the key lanes below still decide the addresses (job files carry no keys)' })
  }

  return (
    <section className="space-y-4" data-testid="new-job">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-lg font-semibold">New job {network ? <span className="text-sm font-normal text-muted-foreground">on {NETWORK_LABEL[network]}</span> : null}</h1>
        <div className="flex gap-2">
          <input ref={fileRef} id="job-file" name="job-file" data-testid="job-file" type="file" accept=".json,application/json" className="hidden" onChange={(e) => { importFile(e.target.files?.[0]); e.target.value = '' }} />
          <Button type="button" size="sm" variant="outline" data-testid="job-import" onClick={() => fileRef.current?.click()}>Import job file</Button>
          <Button type="button" size="sm" variant="outline" data-testid="job-export" disabled={enabled.length === 0} onClick={exportFile}>Export job file</Button>
        </div>
      </div>
      <PriceLine price={price} err={priceErr} />
      <div className="space-y-1">
        <Label htmlFor="job-name">Job name</Label>
        <Input id="job-name" name="job-name" data-testid="job-name" maxLength={64} value={name} onChange={(e) => setName(e.target.value)} />
      </div>
      <fieldset className="space-y-1" data-testid="text-mode">
        <legend className="text-sm font-medium">Message mode</legend>
        <div className="flex flex-wrap gap-4 text-sm">
          {[['plain', 'Plain', 'Plain text, published as written.'], ['timelocked', 'Timelocked', 'A sealed text that opens after a drand round.']].map(([k, label, hint]) => (
            <label key={k} htmlFor={`mode-${k}`} className="flex items-center gap-1.5">
              <input type="radio" id={`mode-${k}`} name="text-mode" data-testid={`mode-${k}`} checked={mode === k} onChange={() => setMode(k)} disabled={creating} />
              <span><b>{label}</b> <span className="text-xs text-muted-foreground">{hint}</span></span>
            </label>
          ))}
        </div>
      </fieldset>
      {mode === 'timelocked' && !TIMELOCKED_PUBLISHING && (
        <p data-testid="timelocked-unavailable" className="rounded-md border border-amber-500 bg-amber-50 p-2 text-xs text-amber-950">
          Timelocked publishing is not enabled yet. The text is checked here with the same rules the publisher uses, but the API refuses a job of this kind
          (<b>job.publish-mode-unavailable</b>) until a backend step enables it, so Create stays off.
        </p>
      )}
      <MessageInput value={text} onChange={setText} mode={mode} />
      {/* No automatic Arweave-id check: a request would reveal the id (via Tor) with no user action, and timelocked publishing is
          off (review W7a I-2). A user-clicked check may return if the Arweave hold lifts. */}
      <div className="grid gap-4 lg:grid-cols-2">
        {CHAINS.map((c) => (
          <div key={c} className="space-y-2">
            <ChainConfig chain={c} network={network} cfg={cfgs[c]} onChange={(v) => setCfgs((s) => ({ ...s, [c]: typeof v === 'function' ? v(s[c]) : v }))} />
            {cfgs[c].enabled && (c !== 'btc' || btcAvailable(network)) && <KeyLane chain={c} />}
            {cfgs[c].enabled && imported?.addresses[c] && addresses[c] && imported.addresses[c] !== addresses[c] && (
              <p data-testid={`import-addr-${c}`} className="text-xs text-amber-900">The imported file named a different {c} key address; the job uses the key loaded here.</p>
            )}
          </div>
        ))}
      </div>
      <div className="space-y-2">
        <h2 className="text-sm font-semibold">Funding</h2>
        <FundingTabs network={network} addresses={addresses} />
      </div>
      <div className="space-y-2">
        {problems.length > 0 && <ul data-testid="job-problems" className="list-inside list-disc text-xs text-muted-foreground">{problems.map((p) => <li key={p}>{p}</li>)}</ul>}
        <Button type="button" data-testid="job-create" disabled={problems.length > 0 || creating} onClick={create}>{creating ? 'Creating…' : 'Create job'}</Button>
        {msg.text && <p data-testid="job-msg" className={`text-sm ${msg.kind === 'err' ? 'text-red-700' : 'text-emerald-800'}`}>{msg.text}</p>}
      </div>
    </section>
  )
}

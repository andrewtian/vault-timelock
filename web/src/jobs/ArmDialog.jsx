// The Arm dialog (W3; spec §5.4; MQ arm dialog, prototype tag add7b-e540f8ae4d6b MainnetView.jsx). Arming fixes, per
// armed chain, the spend cap every signature is checked against (R60), the countdown and the stagger; chains NOT armed
// become SKIPPED (ruling 8: terminal for this job, never armed later). The API re-checks everything (checkArmConfirm,
// exact base units); this dialog collects it:
//   · every armed chain READY (its executor loaded the key and saw one copy affordable) — else Arm stays disabled;
//   · the caps from core computeArmCaps; over the cap the operator types the EXACT planned amount, shown in full
//     precision (up to 18 decimals for an ETH drain) and compared in base units;
//   · typed `again` when a key already sent transactions (MQ I2); the >10× warning; the regime line repeated;
//   · typed `broadcast` on testnet (the mainnet rehearsal) and mainnet; mainnet is a fixed 1:00 countdown and needs
//     IsTor ✓ and job sends ENABLED in this build; local and testnet choose the countdown (5–300 s), local the stagger;
//   · the permanence of each chain's publish mode (contracts/publish.ts trustNote).
// `sources` (R47): the funding-source picker (SourcePicker, W5). When the API declares at least one source, every armed
// chain needs one picked by the operator for this try (no default); an API without sources carries none.
import { useEffect, useId, useState } from 'react'
import { MAINNET_COUNTDOWN_S, P, STAGGER_S, publishModeRow } from '@vault-timelock/core/contracts'
import { formatUnits } from '@vault-timelock/core/chains/plan.js'
import { Button } from '@/components/ui/button.jsx'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { api } from '@/lib/api.js'
import { useStatus } from '@/lib/status.js'
import { useTicks } from '@/status/Ticks.jsx'
import { RegimeLine } from '@/shell/RegimeBanner.jsx'
import { torGate, useTor } from '@/tor/TorPanel.jsx'
import { DEC, UNIT, armInputs, sameAmount, spendableOf, tenX, toArmCap } from './armInputs.js'
import { mmss } from './Countdown.jsx'
import FundingProvenance from '@/funding/FundingProvenance.jsx'
import { ProvenanceReadError, readEthProvenance } from '@/funding/provenance.js'
import SourcePicker, { useSources } from './SourcePicker.jsx'
import { SOURCE_GUARDS, listTries } from './sources.js'

const NAME = { eth: 'Ethereum', sol: 'Solana', btc: 'Bitcoin' }
const DEFAULT_COUNTDOWN = { local: 10, testnet: 60 }
const DEFAULT_STAGGER = [0, 10]
const typedRequired = (network) => network === 'testnet' || network === 'mainnet'
const intIn = (s, a, b) => /^\d+$/.test(String(s).trim()) && Number(s) >= a && Number(s) <= b

export function Permanence({ chain, mode, testid = `permanence-${chain}` }) {
  const row = publishModeRow(mode)
  const trust = row?.trustNote ?? (chain === 'btc' ? 'The text is an ordinals inscription (text/plain) in a reveal transaction on Bitcoin; once mined it is permanent, and the lane key owns the 546-sat inscription output.' : undefined)
  return (
    <p data-testid={testid} className="text-[11px] text-amber-900">
      {NAME[chain]} · <span className="font-mono">{mode}</span>: public immediately and permanently, and it cannot be taken back. {trust}
    </p>
  )
}

function Field({ id, label, testid, value, onChange, className = '' }) {
  return (
    <div className={`space-y-1 ${className}`}>
      <Label htmlFor={id} className="text-xs">{label}</Label>
      <Input id={id} name={id} data-testid={testid} value={value} onChange={(e) => onChange(e.target.value)} autoComplete="off" spellCheck={false} />
    </div>
  )
}

export default function ArmDialog({ jobId, def, state, onArmed, inputs = armInputs, readProvenance = readEthProvenance }) {
  const uid = useId()
  const id = (s) => `${uid}-${s}`
  const ctx = useStatus()
  const ticks = useTicks()
  const network = def.network
  const tor = useTor(10_000, network !== 'local')
  const [open, setOpen] = useState(false)
  const [data, setData] = useState(null)                  // armInputs() result
  const [loadErr, setLoadErr] = useState('')
  const [armed, setArmedSel] = useState(() => Object.fromEntries(Object.keys(def.chains).map((c) => [c, true])))
  const [typed, setTyped] = useState(''), [again, setAgain] = useState('')
  const [amounts, setAmounts] = useState({ eth: '', sol: '', btc: '' })
  const [cd, setCd] = useState(String(DEFAULT_COUNTDOWN[network] ?? MAINNET_COUNTDOWN_S))
  const [st, setSt] = useState(DEFAULT_STAGGER.map(String))
  const [busy, setBusy] = useState(false), [err, setErr] = useState(null)
  const [src, setSrc] = useState({})
  const [used, setUsed] = useState([])   // labels that paid an earlier try of this message: read on open (GET /sources/tries/<sha>) and added when the API refuses source.reused
  const sources = useSources(open)
  // R76: funding provenance is informational (the user-clicked Railgun check, ETH); it never gates Arm
  const [prov, setProv] = useState({ results: {}, errors: {}, busy: {} })
  const checkProv = async (c) => {
    setProv((p) => ({ ...p, busy: { ...p.busy, [c]: true }, errors: { ...p.errors, [c]: '' } }))
    try {
      const r = await readProvenance({ network, address: def.chains[c].keyAddress })
      setProv((p) => ({ ...p, busy: { ...p.busy, [c]: false }, results: { ...p.results, [c]: r } }))
    } catch (e) {
      const msg = e instanceof ProvenanceReadError ? e.message : `the check failed (${String(e?.message ?? e).slice(0, 120)})`
      setProv((p) => ({ ...p, busy: { ...p.busy, [c]: false }, results: { ...p.results, [c]: null }, errors: { ...p.errors, [c]: msg } }))
    }
  }

  const chains = Object.keys(def.chains)
  const phases = Object.fromEntries(chains.map((c) => [c, state?.chains?.[c]?.phase ?? '?']))
  const anyReady = chains.some((c) => phases[c] === 'READY')

  const load = async () => {
    setData(null); setLoadErr('')
    try { setData(await inputs({ def, network, now: Date.now() })) } catch (e) { setLoadErr(`${e.guardId || e.guard || 'error'}: ${String(e.message).slice(0, 200)}`) }
  }
  useEffect(() => { if (open) { setTyped(''); setAgain(''); setAmounts({ eth: '', sol: '', btc: '' }); setErr(null); setSrc({}); setProv({ results: {}, errors: {}, busy: {} }); load()
    // S5 durable marks: the labels that already paid an earlier try of this message are marked on open (the API's source.reused stays the authority)
    listTries(def.messageSha256).then((l) => { if (l.length > 0) setUsed((u) => [...new Set([...u, ...l])]) })
  } }, [open])

  const sel = chains.filter((c) => armed[c])
  const skipped = chains.filter((c) => !armed[c])
  const row = (c) => data?.chains?.[c] ?? null
  const overCap = sel.filter((c) => row(c)?.cap?.overCap)
  const hist = sel.filter((c) => (row(c)?.history ?? 0) > 0)
  const tg = torGate(network, tor.st)
  const locked = network === 'mainnet' && ctx.status?.jobSends !== 'ENABLED'

  const problems = []
  if (sel.length === 0) problems.push('arm at least one chain')
  for (const c of sel) {
    if (phases[c] !== 'READY') problems.push(`${NAME[c]} is ${phases[c]}, not READY: run it (here or vt job run) until its key is loaded and one copy is affordable`)
    else if (!data) problems.push(`${NAME[c]}: reading fees and balances through the relay…`)
    else if (row(c)?.error) problems.push(`${NAME[c]}: ${row(c).error}`)
    else if (row(c)?.cap && !row(c).cap.affordable) problems.push(`${NAME[c]}: ${row(c).cap.notAffordableBecause === 'balance' ? 'the lane balance is below one worst-case copy' : row(c).cap.notAffordableBecause === 'cap' ? 'one worst-case copy is above the cap' : 'one full copy is not affordable'}${c === 'btc' && row(c).cap.ceilingSatVb != null ? ` (priced at ${row(c).cap.ceilingSatVb} sat/vB, ${row(c).cap.ceilingFromJob ? "the job's maxFeeRateSatVb" : 'the 500 sat/vB default'})` : ''}`)
  }
  for (const c of overCap) if (!sameAmount(amounts[c], row(c).cap.planned, c)) problems.push(`${NAME[c]}: type the planned amount exactly to arm over the cap`)
  if (sources.supported && sources.labels.length > 0) for (const c of sel) if (!src[c]) problems.push(`${NAME[c]}: pick a funding source for this try`)
  if (hist.length > 0 && again !== 'again') problems.push('type again: a key already sent transactions')
  if (typedRequired(network) && typed !== 'broadcast') problems.push('type broadcast to arm')
  if (!tg.ok) problems.push(`Tor: ${tg.why}`)
  if (network === 'mainnet' && !ticks.all) problems.push(`mainnet pre-flight ticks: ${ticks.count} of ${ticks.total} set (Status page)`)
  if (locked) problems.push('mainnet job sends are LOCKED in this build (release.mainnet-locked)')
  if (network !== 'mainnet' && !intIn(cd, 5, 300)) problems.push('countdown: a whole number of seconds, 5 to 300')
  if (network === 'local' && !(intIn(st[0], 0, 300) && intIn(st[1], 0, 300) && Number(st[0]) <= Number(st[1]))) problems.push('stagger: 0 ≤ min ≤ max ≤ 300 seconds')

  const countdownSec = network === 'mainnet' ? MAINNET_COUNTDOWN_S : Number(cd)
  const stagger = network === 'local' ? [Number(st[0]), Number(st[1])] : [...STAGGER_S]

  const arm = async () => {
    setBusy(true); setErr(null)
    try {
      const caps = Object.fromEntries(sel.map((c) => [c, toArmCap(row(c).cap)]))
      const body = {
        chains: sel,
        confirm: { typed: typedRequired(network) ? typed : null, amounts: Object.fromEntries(overCap.map((c) => [c, row(c).cap.planned])) },
        caps,
        ...(sources.supported && sources.labels.length > 0 ? { sources: Object.fromEntries(sel.map((c) => [c, src[c]])) } : {}),
        ...(network === 'mainnet' ? {} : { countdownSec }),
        ...(network === 'local' ? { stagger } : {}),
      }
      const out = await api(P.arm(jobId), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
      setOpen(false)
      onArmed?.(out.armed)
    } catch (e) {
      setErr({ guard: e.guard || 'error', message: e.message })
      // source.reused names no label. Only when every armed chain was sent the SAME label is it certain which one it was.
      const sent = [...new Set(sel.map((c) => src[c]))]
      if (e.guard === 'source.reused' && sent.length === 1 && sent[0]) {
        setUsed((u) => (u.includes(sent[0]) ? u : [...u, sent[0]]))
        setSrc((v) => Object.fromEntries(Object.entries(v).filter(([, l]) => l !== sent[0])))
      }
    } finally { setBusy(false) }
  }

  return (
    <>
      <Button type="button" data-testid="arm-open" disabled={!anyReady} onClick={() => setOpen(true)}
        title={anyReady ? 'review the caps and arm' : 'no chain is READY yet: run it (here or vt job run) first'}>Arm…</Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl" data-testid="arm-dialog">
          <DialogHeader>
            <DialogTitle>Arm “{def.name}”</DialogTitle>
            <DialogDescription>
              After {mmss(countdownSec)} (or Skip) the executors sign and broadcast this text: public immediately and permanently.
              The chains start in random order, the second {stagger[0]}–{stagger[1]} s after the first. From Arm on, RPC providers see the text in simulations.
            </DialogDescription>
          </DialogHeader>
          <RegimeLine testid="arm-regime" />
          {loadErr && <p data-testid="arm-load-error" className="text-xs text-red-700">{loadErr} <Button size="xs" variant="outline" onClick={load}>Try again</Button></p>}
          <div className="space-y-3">
            {chains.map((c) => {
              const r = row(c), cap = r?.cap
              const reserve = r?.reserve ?? 0n
              const warn = cap ? tenX(cap, c, reserve) : null
              return (
                <div key={c} data-testid={`arm-chain-${c}`} data-phase={phases[c]} className="space-y-1 rounded-md border p-2 text-xs">
                  <label htmlFor={id(`sel-${c}`)} className="flex items-center gap-2 font-semibold">
                    <input id={id(`sel-${c}`)} name={id(`sel-${c}`)} type="checkbox" data-testid={`arm-select-${c}`} checked={!!armed[c]} onChange={(e) => setArmedSel((a) => ({ ...a, [c]: e.target.checked }))} />
                    Arm {NAME[c]} <span className="font-normal text-muted-foreground">· {phases[c]}</span>
                  </label>
                  {!armed[c] && <p data-testid={`arm-skip-${c}`} className="text-amber-800">Not armed → SKIPPED: final for this job (it can never be armed later; a new job is needed).</p>}
                  <Permanence chain={c} mode={def.chains[c].publishMode} />
                  {r?.error && <p className="text-red-700" data-testid={`arm-error-${c}`}>{r.error}</p>}
                  {typeof r?.balance === 'bigint' && <p data-testid={`arm-balance-${c}`} className="text-muted-foreground">lane wallet balance <b className="font-mono">{formatUnits(r.balance, DEC[c])} {UNIT[c]}</b> <span className="font-mono">{def.chains[c].keyAddress}</span>{r.balance === 0n && <span className="text-red-700"> — no funds present</span>}</p>}
                  {c === 'btc' && r?.btc && (
                    <div data-testid="arm-btc" className="space-y-0.5 rounded bg-muted p-2 font-mono text-[11px]">
                      <div data-testid="arm-btc-rate">worst case priced at {String(r.cap?.ceilingSatVb ?? def.chains.btc.maxFeeRateSatVb ?? 500)} sat/vB ({def.chains.btc.maxFeeRateSatVb != null ? "the job's maxFeeRateSatVb" : 'the 500 sat/vB default ceiling: this job names none'}); the node&apos;s estimate today is {String(r.btc.rate)} sat/vB</div>
                      <div data-testid="arm-btc-fees">worst case per copy: commit {String(r.btc.commitFee)} sat + reveal {String(r.btc.revealFee)} sat + postage {String(r.btc.postage)} sat = {String(r.btc.perCopy)} sat</div>
                      <div data-testid="arm-btc-balance">lane balance {r.balance == null ? '?' : `${String(r.balance)} sat`} ({formatUnits(r.balance ?? 0n, DEC.btc)} BTC)</div>
                      {r.cap?.capVia === 'fallback' && <div data-testid="arm-btc-cap-note">the cap is the 0.01 BTC native fallback (a Bitcoin lane has no USD price)</div>}
                    </div>
                  )}
                  {cap && (
                    <div className="space-y-1">
                      <div data-testid={`arm-cap-${c}`}>spend cap <b className="font-mono">{formatUnits(BigInt(cap.nativeCap), DEC[c])} {UNIT[c]}</b> ({cap.nativeCap} base units{cap.usd ? ` ≈ $${cap.usd.toFixed(2)}` : network === 'testnet' ? ' · TEST FUNDS — NO VALUE' : ''}) · one copy {formatUnits(BigInt(cap.fullCopyCost), DEC[c])} {UNIT[c]} · {cap.parts} part{cap.parts === 1 ? '' : 's'}/copy · planned spend <span className="font-mono">{cap.planned} {UNIT[c]}</span>
                        {r.windowNote && <span data-testid={`arm-window-${c}`}> {r.windowNote}</span>}
                        {reserve > 0n && <span data-testid={`arm-reserve-${c}`}> · the lane keeps {formatUnits(reserve, DEC[c])} {UNIT[c]} (rent-exempt minimum + one claw-back fee), so only {formatUnits(spendableOf(cap, c, reserve), DEC[c])} {UNIT[c]} is spendable</span>}</div>
                      {warn && armed[c] && <p data-testid={`arm-10x-${c}`} className="text-amber-800">⚠ the planned spend is more than 10× one copy ({warn.one} {UNIT[c]}){reserve > 0n ? ' of spendable funds' : ''}: it buys about {String(warn.copies)} copies{reserve > 0n ? ` (planned ${cap.planned} − ${warn.reserve} kept = ${warn.spendable} ${UNIT[c]} spendable)` : ''}. Intended?</p>}
                      {cap.overCap && armed[c] && (
                        <div data-testid={`arm-over-${c}`} className="rounded border border-amber-500 bg-amber-50 p-2 text-amber-950">
                          The planned spend is over the $10 cap. To arm above it, type the planned amount exactly:{' '}
                          <b data-testid={`arm-planned-${c}`} className="break-all font-mono">{cap.planned}</b> {UNIT[c]}
                          <Field id={id(`amount-${c}`)} testid={`arm-amount-${c}`} label={`planned ${UNIT[c]} amount`} value={amounts[c]} onChange={(v) => setAmounts((a) => ({ ...a, [c]: v }))} />
                        </div>
                      )}
                      {r.history > 0 && armed[c] && <p data-testid={`arm-history-${c}`}>This key already sent {r.history}{c === 'sol' && r.history >= 10 ? '+' : ''} transaction(s): continuing may publish again (the executor reconciles from the chain first).</p>}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
          {skipped.length > 0 && sel.length > 0 && <p className="text-xs text-amber-800" data-testid="arm-skipped">{skipped.map((c) => NAME[c]).join(', ')} will be SKIPPED.</p>}
          <div className="grid gap-2 sm:grid-cols-3">
            {network === 'mainnet'
              ? <p className="text-xs sm:col-span-3" data-testid="arm-countdown-fixed">Mainnet: a fixed {mmss(MAINNET_COUNTDOWN_S)} countdown with Skip; stagger {STAGGER_S[0]}–{STAGGER_S[1]} s.</p>
              : <Field id={id('countdown')} testid="arm-countdown" label="countdown (s, 5–300)" value={cd} onChange={setCd} />}
            {network === 'local' && <>
              <Field id={id('st0')} testid="arm-stagger-min" label="stagger min (s)" value={st[0]} onChange={(v) => setSt((x) => [v, x[1]])} />
              <Field id={id('st1')} testid="arm-stagger-max" label="stagger max (s)" value={st[1]} onChange={(v) => setSt((x) => [x[0], v])} />
            </>}
          </div>
          {network !== 'local' && <p data-testid="arm-tor" className={`text-xs ${tg.ok ? 'text-emerald-700' : 'text-red-700'}`}>IsTor {tg.ok ? '✓' : `✗ — ${tg.why}`}</p>}
          <FundingProvenance network={network} chains={sel.map((c) => ({ chain: c, address: def.chains[c].keyAddress }))} 
            results={prov.results} errors={prov.errors} busy={prov.busy} onCheck={checkProv} />
          <SourcePicker chains={sel} value={src} onChange={setSrc} sources={sources} used={used} />
          {hist.length > 0 && <Field id={id('again')} testid="arm-again" label="type again to continue anyway" value={again} onChange={setAgain} />}
          {typedRequired(network) && <Field id={id('typed')} testid="arm-typed" label="type broadcast to arm" value={typed} onChange={setTyped} />}
          {problems.length > 0 && <ul data-testid="arm-problems" className="list-inside list-disc text-xs text-muted-foreground">{problems.map((p) => <li key={p}>{p}</li>)}</ul>}
          {err && <p data-testid="arm-refused" className="text-xs text-red-700"><b>{err.guard}</b>: {SOURCE_GUARDS[err.guard] ?? err.message}</p>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button type="button" data-testid="arm-confirm" disabled={problems.length > 0 || busy} onClick={arm}>{busy ? 'Arming…' : `Arm ${sel.map((c) => NAME[c]).join(' + ') || ''}`}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

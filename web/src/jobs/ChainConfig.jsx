// One chain's part of the job form: mode (until drained | N copies), publish mode, fee strategy, distinct copies,
// budget, fee caps, claw-back address. The key lane is separate (KeyLane). The result is a JobChainInput (contracts/types.ts).
import { useEffect, useId } from 'react'
import { DEFAULT_PUBLISH_MODE, PUBLISH_MODES, defaultFeeStrategy, FEE_STRATEGIES } from '@vault-timelock/core/contracts'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { BTC_MAX_FEE_RATE, BTC_POSTAGE, BTC_PUBLISH_LABEL, BTC_PUBLISH_MODE, btcAvailable, btcCapability, parseFeeRate, relayFeeEstimate, suggestedBtcFeeCeiling } from '@/lib/btc.js'
import { CHAIN_NAME } from '@/keys/KeyStore.jsx'

const ADDR = { eth: /^0x[0-9a-fA-F]{40}$/, sol: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/ }
const BTC_ONLY_COPIES = 'Bitcoin: N copies only (no drain); one text inscription per copy'
const FEE_NOTE = {
  passive: 'unattended, lowest cost per transaction; waits for cheap blocks (the default for until-drained)',
  economy: 'the fee ladder: starts low and climbs only when a transaction stalls (the default for N copies)',
  prompt: 'median/p90 fees at send time',
}

export function defaultChainConfig(chain) {
  // BTC (W7b): copies only, one inscription per copy; the fee rate (sat/vB) is a ceiling, empty = the node's estimate
  if (chain === 'btc') return { enabled: false, mode: 'copies', copies: '1', publishMode: BTC_PUBLISH_MODE, feeStrategy: 'economy', feeTouched: false, distinctCopies: true, budgetUsd: '10', maxTip: '', maxCuPrice: '', maxFeeRate: '', maxFeeRateTouched: false, clawbackTo: '' }
  return { enabled: false, mode: 'drain', copies: '1', publishMode: DEFAULT_PUBLISH_MODE[chain], feeStrategy: defaultFeeStrategy('drain'), feeTouched: false, distinctCopies: true, budgetUsd: '10', maxTip: chain === 'eth' ? '3' : '', maxCuPrice: '', clawbackTo: '' }
}

// Problems the form can see; the API's normalizeJob decides authoritatively (EIP-55, 2-decimal budgets, …).
// PF-S fix round 1 (N-6): on mainnet an eth / sol lane names its claw-back address (normalizeJob job.clawback-required).
export function chainIssues(chain, cfg, network = null) {
  const out = []
  if (chain === 'btc') {
    if (cfg.mode !== 'copies') out.push(BTC_ONLY_COPIES)
    const fr = parseFeeRate(cfg.maxFeeRate); if (!fr.ok) out.push(fr.why)
    else if (fr.value === null) out.push(`max fee rate: required (a whole number of sat/vB from 1 to ${BTC_MAX_FEE_RATE}); every copy is quoted and capped at it`)
  }
  if (cfg.mode === 'copies') { const n = Number(cfg.copies); if (!/^\d+$/.test(cfg.copies.trim()) || n < 1 || n > 10000) out.push('copies: a whole number from 1 to 10000') }
  const b = cfg.budgetUsd.trim()
  if (!/^\d+(\.\d{1,2})?$/.test(b) || !(Number(b) > 0) || Number(b) > 1000) out.push('budget: USD above 0 and at most 1000, at most 2 decimals')
  if (chain === 'eth' && cfg.maxTip.trim() !== '' && !(Number(cfg.maxTip) >= 0.1 && Number(cfg.maxTip) <= 100)) out.push('max tip: 0.1 to 100 gwei, or empty')
  if (chain === 'sol' && cfg.maxCuPrice.trim() !== '' && !(/^\d+$/.test(cfg.maxCuPrice.trim()) && Number(cfg.maxCuPrice) <= 2000000)) out.push('max CU price: a whole number up to 2000000, or empty')
  if (chain !== 'btc' && cfg.clawbackTo.trim() !== '' && !ADDR[chain].test(cfg.clawbackTo.trim())) out.push('claw-back address: not a valid address')
  if (chain !== 'btc' && network === 'mainnet' && cfg.clawbackTo.trim() === '') out.push('claw-back address: required on mainnet (the one address the remainder may go back to)')
  const row = PUBLISH_MODES.find((r) => r.id === cfg.publishMode)
  if (chain === 'btc') { if (cfg.publishMode !== BTC_PUBLISH_MODE) out.push(`publish mode: only ${BTC_PUBLISH_MODE} (R75)`) }
  else if (!row || row.status !== 'available') out.push('publish mode: not yet available')
  return out
}

export function chainInput(chain, cfg, keyAddress) {
  if (chain === 'btc') {
    const fr = parseFeeRate(cfg.maxFeeRate)
    return {
      mode: { copies: Number(cfg.copies) }, publishMode: BTC_PUBLISH_MODE, feeStrategy: cfg.feeStrategy, distinctCopies: cfg.distinctCopies, keyAddress,
      budgetUsd: Number(cfg.budgetUsd), ...(fr.ok && fr.value !== null ? { maxFeeRateSatVb: fr.value } : {}), clawbackTo: null,
    }
  }
  return {
    mode: cfg.mode === 'drain' ? 'drain' : { copies: Number(cfg.copies) },
    publishMode: cfg.publishMode, feeStrategy: cfg.feeStrategy, distinctCopies: cfg.distinctCopies, keyAddress,
    budgetUsd: Number(cfg.budgetUsd),
    ...(chain === 'eth' && cfg.maxTip.trim() !== '' ? { maxTipGwei: Number(cfg.maxTip) } : {}),
    ...(chain === 'sol' && cfg.maxCuPrice.trim() !== '' ? { maxCuPrice: Number(cfg.maxCuPrice) } : {}),
    clawbackTo: cfg.clawbackTo.trim() === '' ? null : cfg.clawbackTo.trim(),
  }
}

// The inverse, for job-file import. Unknown shapes fall back to the defaults.
export function configFromInput(chain, c) {
  const d = defaultChainConfig(chain)
  if (!c || typeof c !== 'object') return d
  if (chain === 'btc') {
    const n = typeof c.mode === 'object' && c.mode ? c.mode.copies : null
    return { ...d, enabled: true, copies: n != null ? String(n) : d.copies, distinctCopies: typeof c.distinctCopies === 'boolean' ? c.distinctCopies : d.distinctCopies, budgetUsd: c.budgetUsd != null ? String(c.budgetUsd) : d.budgetUsd, maxFeeRate: c.maxFeeRateSatVb != null ? String(c.maxFeeRateSatVb) : '' }
  }
  const copies = typeof c.mode === 'object' && c.mode ? c.mode.copies : null
  const mode = copies != null ? 'copies' : 'drain'
  return {
    ...d, enabled: true, mode, copies: copies != null ? String(copies) : d.copies,
    publishMode: typeof c.publishMode === 'string' ? c.publishMode : d.publishMode,
    feeStrategy: FEE_STRATEGIES.includes(c.feeStrategy) ? c.feeStrategy : defaultFeeStrategy(mode === 'drain' ? 'drain' : { copies: 1 }), feeTouched: FEE_STRATEGIES.includes(c.feeStrategy),
    distinctCopies: typeof c.distinctCopies === 'boolean' ? c.distinctCopies : d.distinctCopies,
    budgetUsd: c.budgetUsd != null ? String(c.budgetUsd) : d.budgetUsd,
    maxTip: c.maxTipGwei != null ? String(c.maxTipGwei) : (chain === 'eth' ? '' : d.maxTip),
    maxCuPrice: c.maxCuPrice != null ? String(c.maxCuPrice) : '',
    clawbackTo: typeof c.clawbackTo === 'string' ? c.clawbackTo : '',
  }
}

const select = 'h-9 w-full rounded-md border bg-background px-2 text-sm'

export default function ChainConfig({ chain, cfg, onChange, disabled = false, network = null }) {
  const uid = useId()
  const f = (s) => `${uid}-${s}`
  const set = (patch) => onChange({ ...cfg, ...patch })
  const setMode = (mode) => set({ mode, ...(cfg.feeTouched ? {} : { feeStrategy: defaultFeeStrategy(mode === 'drain' ? 'drain' : { copies: 1 }) }) })
  const modes = PUBLISH_MODES.filter((r) => r.chains.includes(chain))
  const issues = cfg.enabled ? chainIssues(chain, cfg, network) : []
  if (chain === 'btc') return <BtcConfig cfg={cfg} set={set} onChange={onChange} issues={issues} disabled={disabled} network={network} uid={uid} />
  return (
    <fieldset disabled={disabled} data-testid={`chain-${chain}`} className="space-y-3 rounded-lg border p-3 text-sm">
      <legend className="px-1 font-semibold">{CHAIN_NAME[chain]} lane</legend>
      <label htmlFor={f('enabled')} className="flex items-center gap-2">
        <input id={f('enabled')} name={`${chain}-enabled`} type="checkbox" data-testid={`enabled-${chain}`} checked={cfg.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> publish on {CHAIN_NAME[chain]}
      </label>
      {cfg.enabled && (
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1 sm:col-span-2">
            <span className="text-xs font-medium">Mode</span>
            <div className="flex flex-wrap gap-4">
              <label htmlFor={f('drain')} className="flex items-center gap-1.5"><input id={f('drain')} name={`${chain}-mode`} type="radio" data-testid={`mode-drain-${chain}`} checked={cfg.mode === 'drain'} onChange={() => setMode('drain')} /> until drained</label>
              <label htmlFor={f('copies')} className="flex items-center gap-1.5"><input id={f('copies')} name={`${chain}-mode`} type="radio" data-testid={`mode-copies-${chain}`} checked={cfg.mode === 'copies'} onChange={() => setMode('copies')} /> N copies</label>
              {cfg.mode === 'copies' && (
                <span className="flex items-center gap-1.5"><Label htmlFor={f('n')} className="text-xs">Copies (N)</Label>
                  <Input id={f('n')} name={`${chain}-copies`} data-testid={`n-${chain}`} inputMode="numeric" className="h-8 w-24" value={cfg.copies} onChange={(e) => set({ copies: e.target.value })} /></span>
              )}
            </div>
          </div>
          <div className="space-y-1">
            <Label htmlFor={f('pm')} className="text-xs">Publish mode</Label>
            <select id={f('pm')} name={`${chain}-publish-mode`} data-testid={`publish-mode-${chain}`} className={select} value={cfg.publishMode} onChange={(e) => set({ publishMode: e.target.value })}>
              {modes.map((r) => <option key={r.id} value={r.id} disabled={r.status !== 'available'}>{r.id}{r.status !== 'available' ? ' (not yet available)' : ''}</option>)}
            </select>
            <p className="text-[11px] text-muted-foreground">{PUBLISH_MODES.find((r) => r.id === cfg.publishMode)?.note}</p>
          </div>
          <div className="space-y-1">
            <Label htmlFor={f('fs')} className="text-xs">Fee strategy</Label>
            <select id={f('fs')} name={`${chain}-fee-strategy`} data-testid={`fee-strategy-${chain}`} className={select} value={cfg.feeStrategy} onChange={(e) => set({ feeStrategy: e.target.value, feeTouched: true })}>
              {FEE_STRATEGIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <p className="text-[11px] text-muted-foreground">{FEE_NOTE[cfg.feeStrategy]}</p>
          </div>
          <div className="space-y-1">
            <Label htmlFor={f('budget')} className="text-xs">Budget (USD, spend cap for fees)</Label>
            <Input id={f('budget')} name={`${chain}-budget`} data-testid={`budget-${chain}`} inputMode="decimal" value={cfg.budgetUsd} onChange={(e) => set({ budgetUsd: e.target.value })} />
          </div>
          {chain === 'eth'
            ? <div className="space-y-1"><Label htmlFor={f('tip')} className="text-xs">Max tip (gwei, optional)</Label><Input id={f('tip')} name="eth-max-tip" data-testid="max-tip-eth" inputMode="decimal" value={cfg.maxTip} onChange={(e) => set({ maxTip: e.target.value })} /></div>
            : <div className="space-y-1"><Label htmlFor={f('cu')} className="text-xs">Max CU price (µlamports per CU, optional)</Label><Input id={f('cu')} name="sol-max-cu-price" data-testid="max-cu-sol" inputMode="numeric" value={cfg.maxCuPrice} onChange={(e) => set({ maxCuPrice: e.target.value })} /></div>}
          <div className="space-y-1">
            <Label htmlFor={f('claw')} className="text-xs">Claw-back address ({network === 'mainnet' ? 'required on mainnet' : 'optional'})</Label>
            <Input id={f('claw')} name={`${chain}-clawback`} data-testid={`clawback-${chain}`} className="font-mono" value={cfg.clawbackTo} onChange={(e) => set({ clawbackTo: e.target.value })} />
          </div>
          <label htmlFor={f('distinct')} className="flex items-start gap-2 sm:col-span-2">
            <input id={f('distinct')} name={`${chain}-distinct`} type="checkbox" data-testid={`distinct-${chain}`} className="mt-1" checked={cfg.distinctCopies} onChange={(e) => set({ distinctCopies: e.target.checked })} />
            <span>make copies distinct (index every copy)<span className="block text-[11px] text-muted-foreground">{cfg.distinctCopies ? 'ON: copies 2.. carry a [copy c/N] marker, so each is its own indexed record.' : 'OFF: identical copies; an indexer may list only the first.'}</span></span>
          </label>
        </div>
      )}
      {issues.length > 0 && <ul data-testid={`issues-${chain}`} className="list-inside list-disc text-xs text-red-700">{issues.map((i) => <li key={i}>{i}</li>)}</ul>}
    </fieldset>
  )
}

// The BTC lane's part of the form (W7b). Local network only for now; copies only (no drain); one text inscription per copy
// (a commit and a reveal transaction), so the postage is fixed and shown; the fee rate is a ceiling in sat/vB.
function BtcConfig({ cfg, set, onChange, issues, disabled, network, uid }) {
  const f = (x) => `${uid}-${x}`
  const here = btcAvailable(network)
  const cap = btcCapability()
  // Eminors fix 1 (I-1): the ceiling is required; prefill it (editable) once, from the relay's current estimate - min(500, max(10, 4 x estimate)), 25 with none
  const want = here && cfg.enabled && cfg.maxFeeRate === '' && cfg.maxFeeRateTouched !== true
  useEffect(() => {
    if (!want) return undefined
    let live = true
    // a LATE estimate must fill only the fee field, on the CURRENT config (a functional update): never copies, budget or anything else the operator edited since
    relayFeeEstimate().then((e) => { if (live) onChange((cur) => (cur.maxFeeRate === '' && cur.maxFeeRateTouched !== true ? { ...cur, maxFeeRate: String(suggestedBtcFeeCeiling(e)) } : cur)) })
    return () => { live = false }
  }, [want]) // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <fieldset disabled={disabled} data-testid="chain-btc" className="space-y-3 rounded-lg border p-3 text-sm">
      <legend className="px-1 font-semibold">{CHAIN_NAME.btc} lane</legend>
      <label htmlFor={f('enabled')} className="flex items-center gap-2">
        <input id={f('enabled')} name="btc-enabled" type="checkbox" data-testid="enabled-btc" checked={cfg.enabled && here} disabled={!here} onChange={(e) => set({ enabled: e.target.checked })} /> publish on {CHAIN_NAME.btc}
      </label>
      {!here && (
        <p data-testid="btc-unavailable" className="rounded-md border border-amber-500 bg-amber-50 p-2 text-xs text-amber-950">
          The Bitcoin lane is not available yet on {network === 'testnet' ? 'testnet (testnet4)' : network === 'mainnet' ? 'mainnet' : 'this network'}: it runs on the local regtest network only for now.
        </p>
      )}
      {here && cfg.enabled && (
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1 sm:col-span-2">
            <span className="text-xs font-medium">Mode</span>
            <div className="flex flex-wrap items-center gap-3">
              <span data-testid="btc-copies-only" className="text-xs text-muted-foreground">N copies only (a Bitcoin lane has no drain mode)</span>
              <span className="flex items-center gap-1.5"><Label htmlFor={f('n')} className="text-xs">Copies (N)</Label>
                <Input id={f('n')} name="btc-copies" data-testid="n-btc" inputMode="numeric" className="h-8 w-24" value={cfg.copies} onChange={(e) => set({ copies: e.target.value })} /></span>
            </div>
          </div>
          <div className="space-y-1">
            <span className="text-xs font-medium">Publish mode</span>
            <div data-testid="publish-mode-btc" className="h-9 rounded-md border bg-muted px-2 py-2 text-sm">{BTC_PUBLISH_LABEL}</div>
            <p className="text-[11px] text-muted-foreground">One text inscription per copy: a commit transaction and a reveal transaction. The ordinals body is the copy&apos;s text, content type text/plain.</p>
          </div>
          <div className="space-y-1">
            <Label htmlFor={f('rate')} className="text-xs">Max fee rate (sat/vB)</Label>
            <Input id={f('rate')} name="btc-max-fee-rate" data-testid="fee-rate-btc" inputMode="numeric" value={cfg.maxFeeRate} onChange={(e) => set({ maxFeeRate: e.target.value, maxFeeRateTouched: true })} placeholder="required" />
            <p className="text-[11px] text-muted-foreground">Required. Prefilled as the larger of 10 and 4 x the node&apos;s current 2-block estimate (at most {BTC_MAX_FEE_RATE}); edit it. This is the highest rate the job may pay, and every copy is quoted and capped at it. Never above {BTC_MAX_FEE_RATE} sat/vB: the relay&apos;s tickets refuse a higher rate.</p>
          </div>
          <div className="space-y-1">
            <Label htmlFor={f('budget')} className="text-xs">Budget (USD, spend cap for fees)</Label>
            <Input id={f('budget')} name="btc-budget" data-testid="budget-btc" inputMode="decimal" value={cfg.budgetUsd} onChange={(e) => set({ budgetUsd: e.target.value })} />
          </div>
          <p data-testid="btc-postage" className="text-[11px] text-muted-foreground">
            Postage: <b>{BTC_POSTAGE} sat</b> per copy stays on the inscription output (to the lane&apos;s taproot address); it is part of what the commit locks, besides both fees.
          </p>
          <label htmlFor={f('distinct')} className="flex items-start gap-2 sm:col-span-2">
            <input id={f('distinct')} name="btc-distinct" type="checkbox" data-testid="distinct-btc" className="mt-1" checked={cfg.distinctCopies} onChange={(e) => set({ distinctCopies: e.target.checked })} />
            <span>make copies distinct (index every copy)<span className="block text-[11px] text-muted-foreground">{cfg.distinctCopies ? 'ON: copies 2.. carry a [copy c/N] marker, so each is its own indexed inscription.' : 'OFF: identical copies.'}</span></span>
          </label>
          {!cap.jobs && (
            <p data-testid="btc-jobs-unavailable" className="rounded-md border border-amber-500 bg-amber-50 p-2 text-xs text-amber-950 sm:col-span-2">
              The job service does not accept a Bitcoin lane yet (it answers <b>job.chain-unsupported</b> until the btc.inscription publish mode is enabled), so Create stays off while this lane is on.
            </p>
          )}
        </div>
      )}
      {issues.length > 0 && <ul data-testid="issues-btc" className="list-inside list-disc text-xs text-red-700">{issues.map((i) => <li key={i}>{i}</li>)}</ul>}
    </fieldset>
  )
}

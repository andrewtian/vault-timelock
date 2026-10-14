// One chain of a job (W3): its state badge and the lease holder (browser / cli — never host details), the key of this
// tab, Run here / Stop / Resume, the executor's live line, progress and ETA, "which parts landed" after a stop or an
// interruption, per-copy reassembled ✓, the virtualized parts table, and the claw-back. Ported in spirit from the
// prototype's LaneRun.jsx (tag add7b-e540f8ae4d6b); the state is the API's journal, folded by core.
import { useState } from 'react'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { P } from '@vault-timelock/core/contracts'
import { formatUnits } from '@vault-timelock/core/chains/plan.js'
import { api } from '@/lib/api.js'
import { btcCapability } from '@/lib/btc.js'
import KeyLane from '@/keys/KeyLane.jsx'
import { useKeys } from '@/keys/KeyStore.jsx'
import { Permanence } from './ArmDialog.jsx'
import { ChainAfterRun } from './AfterRun.jsx'
import ResolveStuck from './ResolveStuck.jsx'
import PartsTable from './PartsTable.jsx'
import BtcCopies from './BtcCopies.jsx'
import Reassembly from './Reassembly.jsx'
import { CHAIN_LABEL, useRun, useRuns } from './RunHere.js'

const DEC = { eth: 18, sol: 9, btc: 8 }, UNIT = { eth: 'ETH', sol: 'SOL', btc: 'BTC' }
const NULL_ADDRESS = '0x0000000000000000000000000000000000000000'
export const SETTLED = new Set(['DRAINED', 'COPIES_DONE', 'STOPPED', 'CLAWING_BACK', 'CLAWED_BACK', 'DONE', 'SKIPPED'])
// R79: a STOPPED chain whose stop latch the operator's resume lifted is not settled: its executor reopens it (Run here).
// M5c: the same rule as the executor's reopens() and cli/src/job/run.ts — only a RESUMABLE stop (ChainState.stopClass; absent = final)
export const isReopened = (cs) => cs.phase === 'STOPPED' && cs.stopLatched !== true && cs.stopRequested !== true && cs.stopClass === 'resumable'
export const isSettled = (cs) => SETTLED.has(cs.phase) && !isReopened(cs)
export const DETACH_TIP = 'Detach: this tab stops sending. Nothing is journaled and the job keeps running; another executor (vt job run, or another tab) may continue it.'
export const STOP_TIP = 'Stop the job for every executor (this tab, vt job run, any tab). The stop is journaled and stays latched until you press Resume.'
const LIVE_PHASES = new Set(['ARMED', 'RUNNING', 'PAUSED', 'STUCK'])
const PRE_ARM = new Set(['AWAITING_KEY', 'AWAITING_FUNDS', 'READY'])
const FINAL = new Set(['DONE', 'CLAWED_BACK', 'SKIPPED'])                    // nothing left that needs this chain's key
const PHASE_STYLE = {
  RUNNING: 'bg-sky-100 text-sky-900', ARMED: 'bg-sky-50 text-sky-900', PAUSED: 'bg-amber-100 text-amber-900', STUCK: 'bg-red-100 text-red-900',
  READY: 'bg-emerald-50 text-emerald-900', DRAINED: 'bg-emerald-100 text-emerald-900', COPIES_DONE: 'bg-emerald-100 text-emerald-900',
  CLAWED_BACK: 'bg-emerald-100 text-emerald-900', DONE: 'bg-emerald-100 text-emerald-900', STOPPED: 'bg-amber-100 text-amber-900',
  SKIPPED: 'bg-muted text-muted-foreground', CLAWING_BACK: 'bg-sky-100 text-sky-900',
}
const sameAddr = (chain, a, b) => (chain === 'eth' ? String(a).toLowerCase() === String(b).toLowerCase() : a === b)
export const dur = (ms) => (ms == null || !Number.isFinite(ms) ? '—' : ms < 90_000 ? `${Math.round(ms / 1000)} s` : ms < 5_400_000 ? `${Math.round(ms / 60_000)} min` : `${(ms / 3_600_000).toFixed(1)} h`)

// "1–4, 6, 8–9"
export function ranges(ns) {
  const s = [...new Set(ns)].sort((a, b) => a - b), out = []
  for (let i = 0; i < s.length; i++) {
    let j = i
    while (j + 1 < s.length && s[j + 1] === s[j] + 1) j++
    out.push(i === j ? `${s[i]}` : `${s[i]}–${s[j]}`)
    i = j
  }
  return out.join(', ')
}

// Progress of a chain from the reduced state: copies mode → every part of every copy; drain → the current copy.
export function progressOf(ch, cs) {
  const copies = typeof ch.mode === 'object' && ch.mode !== null ? ch.mode.copies : null
  const parts = cs.txs.reduce((m, t) => Math.max(m, t.parts), 0)
  const current = cs.resume?.copy ?? cs.txs.reduce((m, t) => Math.max(m, t.copy), 0)
  const landedAll = cs.txs.filter((t) => t.state === 'included').length
  const inCopy = cs.txs.filter((t) => t.copy === current && t.state === 'included').map((t) => t.part)
  if (parts === 0) return { copies, parts: null, current: null, done: 0, total: null, landedAll, inCopy: [] }
  return copies !== null
    ? { copies, parts, current, done: landedAll, total: copies * parts, landedAll, inCopy }
    : { copies, parts, current, done: inCopy.length, total: parts, landedAll, inCopy }
}

// ETA from the journal's landing times (the latest 20): seconds per part × parts left.
export function etaOf(landed, left) {
  const w = landed.slice(-20)
  if (w.length < 2 || left == null) return { perPart: null, eta: null }
  const perPart = (w.at(-1).at - w[0].at) / (w.length - 1)
  return { perPart, eta: perPart * left }
}

function HolderBadge({ chain, run, lease }) {
  let text = 'no executor', kind = 'none'
  if (run.status === 'running') { text = run.kind === 'clawback' ? 'claw-back running here' : 'running here'; kind = 'here' }
  else if (lease?.holder === 'cli') { text = 'running in cli'; kind = 'cli' }
  // the lease names only 'browser': after this tab's own run ended it cannot tell this tab from another until the lease lapses
  else if (lease?.holder === 'browser') { text = run.status === 'ended' ? 'a browser tab holds this chain (this one, whose run just ended, or another; the lease lapses in a few seconds unless another tab renews it)' : 'running in another tab'; kind = 'browser' }
  else if (run.error?.guard === 'lease.held') { text = 'another executor holds the lease'; kind = 'other' }
  return <span data-testid={`holder-${chain}`} data-holder={kind} className="rounded bg-muted px-1.5 py-0.5 text-[11px]">{text}{lease ? ` · lease gen ${lease.gen}` : ''}</span>
}

export default function ChainLane({ jobId, def, chain, state, lease, extras, now, network, plannedParts: plannedIn = null, capability = btcCapability() }) {
  const ch = def.chains[chain]
  const plannedParts = chain === 'btc' ? 2 : plannedIn                    // a BTC copy is two transactions: the commit and the reveal
  const cs = state?.chains?.[chain]
  const run = useRun(jobId, chain)
  const runs = useRuns()
  const { keys } = useKeys()
  const entry = keys[chain] || null
  const keyOk = !!entry && sameAddr(chain, entry.key.address, ch.keyAddress)
  const [msg, setMsg] = useState(null)
  const [tipCap, setTipCap] = useState('')
  const [closing, setClosing] = useState(false)
  const [resuming, setResuming] = useState(false)
  const [word, setWord] = useState('')
  const [finalReason, setFinalReason] = useState(null)      // R79b: the API's resume.final-stop message for this chain
  if (!cs) return null

  const phase = cs.phase
  const other = lease && run.status !== 'running' ? lease : null           // a live lease that is not this tab's run
  const reopened = isReopened(cs)
  const settled = isSettled(cs)
  const finalStop = cs.stopClass !== 'resumable' || finalReason !== null   // R79b: a FINAL stop (readback / status 0 / reassembly / EIP-7702 / marked-failed ...) is never resumed; the API (resume.final-stop) is the authority. M5c: fail closed like the executor (no class = final)
  const needsWord = network === 'mainnet'                              // R79b m-7: every mainnet action that lets sends continue asks the typed word `resume`
  const latched = phase === 'STOPPED' && cs.stopLatched === true         // Resume is offered only here (never DRAINED, COPIES_DONE, DONE, CLAWED_BACK, SKIPPED or STUCK)
  const canResume = phase === 'PAUSED' || (cs.stopRequested === true && (!settled || (phase === 'STOPPED' && !latched && !finalStop)))   // PAUSED, a pending stop, or a STOPPED chain with a NEW stop request pending (its latch lifted)
  const inFlight = cs.txs.some((t) => t.state === 'open')
  const prog = progressOf(ch, cs)
  const left = prog.total === null ? null : prog.total - prog.done
  const { perPart, eta } = etaOf(extras?.landed ?? [], left)
  const running = run.status === 'running' && run.kind !== 'clawback'
  const liveRun = running || !!other
  const resumeAt = cs.resume
  const partial = prog.parts !== null && prog.inCopy.length > 0 && prog.inCopy.length < prog.parts
  const to = chain === 'eth' ? (ch.publishMode === 'eth.calldata.self' ? ch.keyAddress : NULL_ADDRESS) : undefined

  const act = async (label, f, handled) => {
    setMsg(null)
    try { await f(); setMsg({ ok: true, text: `${label}: sent` }) } catch (e) { if (handled?.(e)) return; setMsg({ ok: false, text: `${label}: ${e.guard || e.guardId || 'error'} — ${e.message}` }) }
  }
  // W7b: core's createExecutor still refuses chain btc (executor.chain-unsupported) until E7b wires it; Run here is off until then
  const btcGated = chain === 'btc' && !capability.executor
  const canRun = keyOk && !running && run.status !== 'running' && !other && !settled && !btcGated
  const runLabel = !reopened && resumeAt && cs.txs.length > 0 ? `Resume copy ${resumeAt.copy} at part ${resumeAt.nextPart}` : 'Run here'

  return (
    <section data-testid={`lane-${chain}`} data-phase={phase} className="space-y-2 rounded-xl border p-3 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <b>{CHAIN_LABEL[chain]} · {prog.copies !== null ? `${prog.copies} cop${prog.copies === 1 ? 'y' : 'ies'}` : 'until drained'} · {ch.feeStrategy}
          <span className="font-normal text-muted-foreground"> · {(prog.parts ?? plannedParts) ?? '?'} part{(prog.parts ?? plannedParts) === 1 ? '' : 's'}/copy · key <span className="font-mono">{ch.keyAddress}</span></span></b>
        <span className="flex items-center gap-2">
          <span data-testid={`phase-${chain}`} data-phase={phase} className={`rounded px-1.5 py-0.5 text-[11px] font-semibold ${PHASE_STYLE[phase] || 'bg-muted'}`}>{phase}{cs.stopRequested && !settled ? ' · stop requested' : ''}</span>
          <HolderBadge chain={chain} run={run} lease={lease} />
        </span>
      </div>
      {cs.reason && <p data-testid={`reason-${chain}`} className="text-xs text-muted-foreground">{cs.reason}</p>}
      <Permanence chain={chain} mode={ch.publishMode} />

      {!keyOk && !FINAL.has(phase) && !other && (
        <div className="space-y-1">
          {entry && <p data-testid={`key-mismatch-${chain}`} className="text-xs text-red-700">This tab holds {CHAIN_LABEL[chain]} key {entry.key.address}, not this job’s key {ch.keyAddress}. Replace it with the job’s key (its backup file).</p>}
          {!entry && <p className="text-xs text-muted-foreground">To {settled ? 'claw back' : 'run'} {CHAIN_LABEL[chain]} here, load this job’s key ({ch.keyAddress}) from its backup. Keys live only in this tab’s memory: after a reload, load it again.</p>}
          <KeyLane chain={chain} importOnly />
        </div>
      )}

      {btcGated && !settled && (
        <p data-testid="btc-run-gated" className="rounded-md border border-amber-500 bg-amber-50 p-2 text-xs text-amber-950">
          Run here is not available for the Bitcoin lane yet: the browser executor does not run chain btc until the Bitcoin executor step (E7b) is merged
          (it answers <b>executor.chain-unsupported</b>). The page shows the lane&apos;s journal as soon as an executor writes it.
        </p>
      )}

      {other && <p data-testid={`watching-${chain}`} className="text-xs">Watching: {other.holder === 'cli' ? 'vt job run' : run.status === 'ended' ? 'a browser tab (this one, just ended, or another)' : 'another browser tab'} holds the lease. Run here is off until that lease is released or expires.</p>}

      <div className="flex flex-wrap items-center gap-2">
        {!settled && <Button type="button" size="sm" data-testid={`run-${chain}`} disabled={!canRun} onClick={() => { setMsg(null); runs.start(jobId, chain, entry) }}>{runLabel}</Button>}
        {LIVE_PHASES.has(phase) && !cs.stopRequested && (
          <Button type="button" size="sm" variant="outline" data-testid={`stop-${chain}`} title={STOP_TIP} onClick={() => act('stop', () => runs.stop(jobId, chain))}>{inFlight ? 'Stop job (all executors) after the in-flight tx' : 'Stop job (all executors)'}</Button>
        )}
        {running && (
          <Button type="button" size="sm" variant="outline" data-testid={`stop-here-${chain}`} title={DETACH_TIP} onClick={() => runs.stopHere(jobId, chain)}>Stop running here</Button>
        )}
        {latched && !finalStop && !resuming && (
          <Button type="button" size="sm" variant="outline" data-testid={`resume-latched-${chain}`} onClick={() => setResuming(true)}>Resume</Button>
        )}
        {canResume && finalReason === null && (
          <>
            {needsWord && <Input name={`resume-word-${chain}`} aria-label="type resume to continue" placeholder="type resume" data-testid={`resume-word-${chain}`} className="h-7 w-28" value={word} onChange={(e) => setWord(e.target.value)} />}
            {phase === 'PAUSED' && chain === 'eth' && (
              <span className="flex items-center gap-1">
                <Label htmlFor={`tipcap-${jobId}-${chain}`} className="text-xs">tip cap (gwei)</Label>
                <Input id={`tipcap-${jobId}-${chain}`} name={`tipcap-${chain}`} data-testid={`tipcap-${chain}`} className="h-7 w-24" value={tipCap} onChange={(e) => setTipCap(e.target.value)} />
              </span>
            )}
            <Button type="button" size="sm" variant="outline" data-testid={`resume-${chain}`} disabled={needsWord && word !== 'resume'}
              onClick={async () => { await act('resume', () => runs.resume(jobId, chain, tipCap.trim() ? { tipCapGwei: tipCap.trim() } : {}), (e) => { if (e.guard === 'resume.final-stop') { setFinalReason(e.message); return true } return false }); setWord('') }}>{phase === 'PAUSED' ? 'Resume' : 'Cancel the stop'}</Button>
          </>
        )}
        {settled && phase !== 'SKIPPED' && phase !== 'DONE' && phase !== 'CLAWED_BACK' && phase !== 'CLAWING_BACK' && cs.openIntents.length === 0 && (
          closing
            ? <Button type="button" size="sm" variant="destructive" data-testid={`close-confirm-${chain}`} onClick={() => act('close', () => api(P.close(jobId), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ chain }) }))}>Close {CHAIN_LABEL[chain]} without claw-back</Button>
            : <Button type="button" size="sm" variant="ghost" data-testid={`close-${chain}`} onClick={() => setClosing(true)}>Close…</Button>
        )}
      </div>
      {((phase === 'STOPPED' && finalStop) || finalReason !== null) && (
        <p data-testid={`resume-final-${chain}`} className="rounded-md border border-red-300 bg-red-50 p-2 text-xs text-red-900">
          This stop is final{cs.stopCode ? ` (${cs.stopCode})` : ''}, so Resume is not offered: {finalReason ?? cs.reason ?? 'the chain stopped on an integrity failure'}. The way out is to claw back the remainder or close the chain (below), and a new job for more copies.
        </p>
      )}
      {reopened && (
        <p data-testid={`reopened-${chain}`} className="rounded-md border border-amber-300 bg-amber-50 p-2 text-xs text-amber-950">
          Resumed, but still STOPPED: Run here reopens it once its pre-start checks pass (the reconcile, the re-read of a landed part, the check at the start). If a run's check failed, nothing was journaled and the resume still stands: fix the cause and run again.
        </p>
      )}
      {latched && !finalStop && resuming && (
        <div data-testid={`resume-confirm-${chain}`} className="flex flex-wrap items-center gap-2 rounded-md border border-amber-400 bg-amber-50 p-2 text-xs text-amber-950">
          <span>Resume publishing on {CHAIN_LABEL[chain]}? The next part of copy {resumeAt?.copy ?? 1} (part {resumeAt?.nextPart ?? 1}) is sent after you press Run here.</span>
          {needsWord && <Input name={`resume-word-${chain}`} aria-label="type resume to continue" placeholder="type resume" data-testid={`resume-word-${chain}`} className="h-7 w-28" value={word} onChange={(e) => setWord(e.target.value)} />}
          <Button type="button" size="sm" data-testid={`resume-go-${chain}`} disabled={needsWord && word !== 'resume'} onClick={async () => {
            setMsg(null)
            try { await runs.resume(jobId, chain); setMsg({ ok: true, text: 'resume: sent' }) } catch (e) {
              if (e.guard === 'resume.final-stop') setFinalReason(e.message)
              else setMsg({ ok: false, text: `resume: ${e.guard || e.guardId || 'error'} — ${e.message}` })
            }
            setResuming(false); setWord('')
          }}>Resume</Button>
          <Button type="button" size="sm" variant="ghost" data-testid={`resume-cancel-${chain}`} onClick={() => setResuming(false)}>Cancel</Button>
        </div>
      )}
      {msg && <p data-testid={`lane-msg-${chain}`} className={`text-xs ${msg.ok ? 'text-emerald-800' : 'text-red-700'}`}>{msg.text}</p>}

      {run.status !== 'idle' && run.kind !== 'clawback' && (
        <div data-testid={`run-state-${chain}`} data-status={run.status} data-outcome={run.outcome || ''} className="rounded-md bg-muted px-2 py-1 text-xs">
          {run.status === 'running' ? 'Running here' : 'Run here ended'}
          {run.view ? ` — ${run.view.phase}${run.view.copy ? ` · copy ${run.view.copy} part ${run.view.part}/${run.view.parts}` : ''}${run.view.startsInMs ? ` · starts in ${dur(run.view.startsInMs)}` : ''}${run.view.note ? ` · ${run.view.note}` : ''}` : ''}
          {run.outcome ? ` · outcome: ${run.outcome}` : ''}
          {run.error ? <span data-testid={`run-error-${chain}`}> · {run.error.guard}: {run.error.guard === 'lease.held' ? (lease?.holder === 'cli' ? 'running in cli — this tab watches' : 'another executor holds the lease — this tab watches') : run.error.message}</span> : null}
        </div>
      )}
      {running && <p data-testid={`keeptab-${chain}`} className="text-xs text-amber-800">Keep this tab open and visible: the key and the loop live only in this page. Closing it detaches this tab: sending pauses, nothing is journaled and the job keeps running; a transaction already in flight may still land — load the key again and Run here reconciles from the chain before anything new (it continues at the next part). To stop the job for every executor, use Stop job (it stays stopped until you press Resume).</p>}

      <div data-testid={`progress-${chain}`} data-done={prog.done} data-total={prog.total ?? ''} className="flex items-center gap-2 text-[11px] text-muted-foreground">
        <div className="h-2 flex-1 overflow-hidden rounded bg-muted"><div className="h-full bg-emerald-600" style={{ width: `${prog.total ? Math.min(100, (100 * prog.done) / prog.total).toFixed(1) : 0}%` }} /></div>
        <span className="font-mono">{prog.total === null ? 'no part sent yet' : prog.copies !== null ? `${prog.done}/${prog.total} parts` : `copy ${prog.current}: ${prog.done}/${prog.total} parts`}</span>
        <span data-testid={`eta-${chain}`} className="font-mono">ETA {phase === 'RUNNING' && eta !== null ? dur(eta) : '—'}{perPart !== null ? ` · ${(perPart / 1000).toFixed(1)} s/part` : ''}</span>
        <span className="font-mono">spent {formatUnits(BigInt(cs.spent || '0'), DEC[chain])} {UNIT[chain]}</span>
      </div>

      {partial && !liveRun && (
        <p data-testid={`landed-${chain}`} className="rounded-md border border-amber-400 bg-amber-50 p-2 text-xs text-amber-950">
          {phase === 'STOPPED' ? 'Stopped' : settled ? phase : 'Interrupted'} in copy {prog.current}: parts <b>{ranges(prog.inCopy)}</b> of {prog.parts} landed
          {' '}(not landed: {ranges(Array.from({ length: prog.parts }, (_, i) => i + 1).filter((p) => !prog.inCopy.includes(p)))}).
          {' '}{settled
            ? 'This chain is settled: a landed part is never sent again; claw back the remainder or close the chain.'
            : `${runLabel === 'Run here' ? 'Run here' : runLabel} (here or vt job run) reconciles from the chain first and continues at the next part.`}
        </p>
      )}
      {phase === 'STUCK' && <p data-testid={`stuck-${chain}`} className="text-xs text-red-700">A transaction is STUCK and is never re-sent blindly: Run here reconciles it from the chain, or resolve it below (<span className="font-mono">vt job resolve {jobId} --chain {chain} --tx &lt;txId&gt; {chain === 'btc' ? 'mark-failed' : 'mark-done|mark-failed'}</span>).</p>}
      {phase === 'STUCK' && <ResolveStuck jobId={jobId} chain={chain} cs={cs} network={network} />}

      <Reassembly chain={chain} cs={cs} sha={extras?.sha} messageSha256={def.messageSha256} />
      {cs.txs.length > 0 && chain === 'btc' && <BtcCopies rows={cs.txs} network={network} />}
      {cs.txs.length > 0 && chain !== 'btc' && <PartsTable chain={chain} rows={cs.txs} network={network} signer={ch.keyAddress} to={to} />}

      {settled && phase !== 'SKIPPED' && chain === 'btc' && (
        <div data-testid="afterrun-btc" data-phase={phase} className="space-y-1 rounded-lg border border-emerald-300 bg-emerald-50/40 p-2 text-xs">
          <div className="font-semibold">After the run · Bitcoin · {phase}</div>
          <p>{cs.copiesIncluded} cop{cs.copiesIncluded === 1 ? 'y' : 'ies'} complete · reassembled ✓ {cs.reassembled.filter((r) => r.ok).length}. The Bitcoin lane has no claw-back: coins left at the lane address ({ch.keyAddress}) stay there, spendable with the key&apos;s backup.</p>
        </div>
      )}
      {settled && phase !== 'SKIPPED' && chain !== 'btc' && (
        <ChainAfterRun jobId={jobId} def={def} chain={chain} state={state} cs={cs} entry={entry} keyOk={keyOk} run={run} network={network} heldElsewhere={!!other} />
      )}
    </section>
  )
}

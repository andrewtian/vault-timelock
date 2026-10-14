// The job page, #/jobs/<id> (W3; spec §15): the job's state from the API (GET + the journal over SSE, folded by core),
// the Arm dialog, the countdown with Skip and the stagger, and one lane per chain (Run here, Stop / Resume, parts,
// reassembly, claw-back). A job run by the CLI (`vt job run`) is watched live in the same view: Run here is off while
// another holder has a chain's lease. Every number shown about the countdown and the stagger comes from the job's arm
// record, never from the mainnet constants (E2E finding L2-1).
import { useEffect, useState } from 'react'
import { P } from '@vault-timelock/core/contracts'
import FundingTabs from '@/funding/FundingTabs.jsx'
import { startAt } from '@vault-timelock/core/job'
import { Button } from '@/components/ui/button.jsx'
import { NETWORK_LABEL, currentNetwork, useStatus } from '@/lib/status.js'
import { torGate, useTor } from '@/tor/TorPanel.jsx'
import JobAfterRun from './AfterRun.jsx'
import ArmDialog from './ArmDialog.jsx'
import ReceiptButton from './ReceiptButton.jsx'
import ChainLane, { isSettled } from './ChainLane.jsx'
import Countdown, { mmss } from './Countdown.jsx'
import { CHAIN_LABEL, runKey, simFresh, useRuns } from './RunHere.js'
import { liveLease, useJob } from './useJob.js'
import { useMessageParts } from './useMessageParts.js'

const hhmmss = (ms) => new Date(ms).toISOString().slice(11, 19)

// The arm record in words (L2-1): its own countdown and stagger, the order and each chain's offset.
export function armSummary(armed) {
  const o = armed.schedule.order
  const offs = o.map((c, i) => (i === 0 ? `${CHAIN_LABEL[c]} at release` : `${CHAIN_LABEL[c]} +${armed.schedule.offsetSec[c] ?? 0} s`))
  return `Countdown ${mmss(armed.countdownSec)} from arm (this job’s arm record), then ${offs.join(', ')}.`
}

function useTick(on, ms = 1000) {
  const [, set] = useState(0)
  useEffect(() => { if (!on) return undefined; const t = setInterval(() => set((x) => x + 1), ms); return () => clearInterval(t) }, [on, ms])
}

export default function JobView({ id, jobOptions }) {
  const job = useJob(id, jobOptions)
  const { def, state, leases, extras, clock, error, stream } = job
  const ctx = useStatus()
  const runs = useRuns()
  const network = def?.network ?? currentNetwork(ctx)
  const plannedParts = useMessageParts(def?.messageSha256)
  const tor = useTor(10_000, !!def && network !== 'local' && !!state?.armed)
  const [skipMsg, setSkipMsg] = useState(null)
  const now = clock.now()
  const armed = state?.armed ?? null
  const beforeRelease = !!armed && (now === null || now < armed.releaseAt)
  const anyRunHere = Object.keys(def?.chains ?? {}).some((c) => runs.runs[runKey(id, c)]?.status === 'running')
  useTick(!!armed || anyRunHere)

  if (error && !def) return <section data-testid="job-error" className="text-sm text-red-700">Job {id}: {error.guard} — {error.message}</section>
  if (!def || !state) return <section data-testid="job-loading" className="text-sm text-muted-foreground">Loading job {id}…</section>

  const chains = Object.keys(def.chains)
  const order = armed ? armed.schedule.order : []
  const torOk = torGate(network, tor.st).ok
  const fresh = order.length > 0 && order.every((c) => { const r = runs.runs[runKey(id, c)]; return r?.status === 'running' && simFresh(r) })
  const skipReady = beforeRelease && now !== null && torOk && fresh
  const skipWhy = !beforeRelease ? '' : now === null ? 'waiting for the API clock' : !torOk ? 'IsTor is not ✓' : !fresh ? 'every armed chain needs a fresh passing simulation in this tab' : ''
  const skip = async () => {
    setSkipMsg(null)
    try { await runs.skip(id, order[0]); job.refresh() } catch (e) { setSkipMsg(`${e.guardId || e.guard || 'error'}: ${e.message}`) }
  }
  return (
    <section data-testid="job-view" data-job={id} data-phase={state.phase} className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-lg font-semibold">{def.name} <span className="font-mono text-sm font-normal text-muted-foreground">{id} · {NETWORK_LABEL[def.network]}</span></h1>
        <div className="flex items-center gap-2 text-xs">
          <span data-testid="job-phase" className="rounded bg-muted px-1.5 py-0.5 font-semibold">{state.phase}</span>
          <span data-testid="job-stream" data-state={stream} className="text-muted-foreground">journal {stream === 'open' ? 'live' : stream} · seq {job.seq}</span>
          <ReceiptButton jobId={id} />
        </div>
      </div>
      {error && <p data-testid="job-error" className="text-xs text-red-700">{error.guard}: {error.message}</p>}
      {state.corrupt && <p data-testid="job-corrupt" className="rounded border border-red-600 bg-red-50 p-2 text-xs text-red-900">The journal is CORRUPT ({state.corrupt}): every send is refused.</p>}
      <p className="text-xs text-muted-foreground">message {def.messageBytes} bytes · sha256 <span className="font-mono break-all">{def.messageSha256}</span></p>

      {anyRunHere && (
        <div data-testid="keep-visible" className="rounded-md border border-amber-500 bg-amber-50 p-2 text-xs text-amber-950">
          Keep this tab open and visible while it runs: the keys and the loop live only in this page.
          {runs.hiddenAt ? ` The tab was hidden at ${hhmmss(runs.hiddenAt)} UTC while running.` : ''}
        </div>
      )}

      {!armed && (
        <div className="space-y-1">
          <ArmDialog jobId={id} def={def} state={state} onArmed={() => job.refresh()} />
          <p className="text-xs text-muted-foreground">Arm needs every armed chain READY: start each chain (Run here, or <span className="font-mono">vt job run {id}</span>) so its executor loads the key and sees one copy affordable.</p>
        </div>
      )}

      {!armed && (
        <div data-testid="job-funding" className="space-y-2">
          <h2 className="text-sm font-semibold">Funding</h2>
          <FundingTabs network={def.network} jobId={id} addresses={{ eth: def.chains.eth?.keyAddress ?? '', sol: def.chains.sol?.keyAddress ?? '' }} />
        </div>
      )}

      {armed && (
        <div data-testid="armed" className="space-y-2">
          <p data-testid="arm-summary" className="text-xs">{armSummary(armed)}</p>
          {beforeRelease && (
            <div className="space-y-2">
              <Countdown target={armed.releaseAt} total={armed.countdownSec} label="Release in" now={clock.now} />
              <div className="flex flex-wrap items-center justify-center gap-2 text-xs">
                <Button type="button" variant="destructive" data-testid="skip" disabled={!skipReady} onClick={skip} title={skipWhy || 'release now: the same checks as at zero'}>Skip countdown</Button>
                {skipWhy && <span data-testid="skip-why" className="text-muted-foreground">{skipWhy}</span>}
                {skipMsg && <span data-testid="skip-error" className="text-red-700">{skipMsg}</span>}
              </div>
            </div>
          )}
          <ul data-testid="stagger" className="text-xs">
            {order.map((c) => {
              const at = startAt(armed, c), leftMs = now === null ? null : at - now
              return <li key={c} data-testid={`start-${c}`}>{CHAIN_LABEL[c]}: starts {armed.schedule.offsetSec[c] ? `${armed.schedule.offsetSec[c]} s after the release` : 'at the release'}{leftMs !== null && leftMs > 0 ? ` — in ${mmss(Math.ceil(leftMs / 1000))}` : leftMs !== null ? ' — started (or starting)' : ''}</li>
            })}
            {chains.filter((c) => !order.includes(c)).map((c) => <li key={c}>{CHAIN_LABEL[c]}: not armed (SKIPPED)</li>)}
          </ul>
        </div>
      )}

      <JobAfterRun jobId={id} def={def} state={state} network={def.network}
        settledChains={chains.filter((c) => state.chains?.[c] && isSettled(state.chains[c]) && state.chains[c].phase !== 'SKIPPED')} />

      <div className="grid gap-4">
        {chains.map((c) => (
          <ChainLane key={c} jobId={id} def={def} chain={c} state={state} lease={liveLease(leases[c], now)} extras={extras[c]} now={now} network={def.network} plannedParts={plannedParts[c] ?? null} />
        ))}
      </div>
    </section>
  )
}

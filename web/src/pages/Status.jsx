// Status / pre-flight page (W1, W4): start commands (`vt up --network …`), the readiness table (the `vt preflight`
// equivalent from core, plus what the API, relay and page server report about themselves), the operator's mainnet
// ticks (tab memory only; Arm on mainnet waits for all of them), the Tor panel and the raw answers.
import { useCallback, useEffect, useState } from 'react'
import { NETWORKS } from '@vault-timelock/core/contracts'
import { browserClients, delegatedFromJobs, preflight } from '@vault-timelock/core/executor'
import { api } from '@/lib/api.js'
import { PAGE_BUILD } from '@/shell/BuildBadge.jsx'
import LocalExplorerNote from '@/shell/LocalExplorerNote.jsx'
import { currentNetwork, upCommand, useStatus } from '@/lib/status.js'
import TorPanel from '@/tor/TorPanel.jsx'
import { MAINNET_TICKS, pageRows } from '@/status/readiness.js'
import ReadinessTable from '@/status/ReadinessTable.jsx'
import { useTicks } from '@/status/Ticks.jsx'

const getJson = (path) => fetch(path, { cache: 'no-store', credentials: 'same-origin' }).then((r) => (r.ok ? r.json() : null)).catch(() => null)

const defaultPreflight = (relay, network) => preflight(relay, network)

export default function Status({ runPreflight = defaultPreflight }) {
  const ctx = useStatus()
  const { status, relay, error } = ctx
  const network = currentNetwork(ctx)
  const ticks = useTicks()
  const [report, setReport] = useState(null), [running, setRunning] = useState(false), [perr, setPerr] = useState(null)
  const [extras, setExtras] = useState({ pageBuild: PAGE_BUILD, serve: null, release: null, services: null })

  const run = useCallback(async () => {
    if (!network) return
    setRunning(true); setPerr(null)
    try {
      const [serve, release, services, jobs] = await Promise.all([getJson('/__serve'), getJson('/relay/release'), getJson('/relay/services'),
        Promise.resolve().then(() => api('/jobs')).then((j) => j?.jobs, () => null)])      // M4b: a delegated lane key (EIP-7702) from the journal's stops
      setExtras({ pageBuild: PAGE_BUILD, serve, release, services, servicesWhy: services === null ? 'could not be read' : undefined, chains: delegatedFromJobs(jobs) })
      setReport(await runPreflight(browserClients().relay, network))
    } catch (e) { setPerr(`pre-flight: ${String(e?.message || e).slice(0, 160)}`) } finally { setRunning(false) }
  }, [network, runPreflight])
  useEffect(() => { run() }, [run])

  return (
    <section className="space-y-3">
      <h1 className="text-lg font-semibold">Status</h1>
      {network === 'local' ? <LocalExplorerNote /> : null}
      <div data-testid="start-commands" className="rounded border p-3 text-xs">
        Start a network’s stack with:{' '}
        {NETWORKS.map((n) => <span key={n} className={`mr-3 font-mono ${n === network ? 'font-semibold' : 'text-muted-foreground'}`} data-testid={`start-${n}`}>{upCommand(n)}</span>)}
        <span className="text-muted-foreground"> · terminal equivalent of this table: </span><span className="font-mono" data-testid="preflight-cli">vt preflight --network {network ?? '<network>'}</span>
      </div>
      {error ? <p data-testid="api-error">API: {error.guard}</p> : null}
      <ReadinessTable report={report} running={running} error={perr} onRun={network ? run : null}
        pageRows={network ? pageRows({ network, status, relay, extras, pageNetwork: ctx.pageNetwork }) : []} />
      {network === 'mainnet' && (
        <section data-testid="ticks" data-all={String(ticks.all)} className="space-y-1 rounded-lg border p-3 text-xs">
          <b className="text-sm">Before the mainnet Arm</b> <span className="text-muted-foreground">({ticks.count} of {ticks.total} set · kept in this tab only)</span>
          {MAINNET_TICKS.map((t) => (
            <label key={t.id} htmlFor={`tick-${t.id}`} className="flex items-start gap-2">
              <input id={`tick-${t.id}`} name={`tick-${t.id}`} type="checkbox" data-testid={`tick-${t.id}`} checked={ticks.ticks[t.id] === true} onChange={(e) => ticks.set(t.id, e.target.checked)} />
              <span>{t.label}</span>
            </label>
          ))}
          <p className="text-muted-foreground">Arm stays disabled on mainnet until every tick is set.</p>
        </section>
      )}
      <TorPanel />
      <details className="text-xs"><summary className="cursor-pointer">Raw API and relay answers</summary>
        {status ? <pre className="overflow-auto rounded border p-3" data-testid="api-status">{JSON.stringify(status, null, 2)}</pre> : null}
        {relay ? <pre className="overflow-auto rounded border p-3" data-testid="relay-status">{JSON.stringify(relay, null, 2)}</pre> : null}
      </details>
    </section>
  )
}

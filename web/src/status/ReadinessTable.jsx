// The readiness table (W4): the page rows (status/readiness.js) and core's PreflightReport rows (`vt preflight`
// equivalent), one table. ok: ✓ / ✗ / — (informational). No row carries an IP or an endpoint.
import { readinessVerdict } from '@vault-timelock/core/executor'
import { Button } from '@/components/ui/button.jsx'

const MARK = (ok) => (ok === true ? '✓' : ok === false ? '✗' : '—')
const TONE = (ok) => (ok === true ? 'text-emerald-700' : ok === false ? 'text-red-700' : 'text-muted-foreground')

export default function ReadinessTable({ report = null, pageRows = [], running = false, onRun = null, error = null }) {
  const rows = [...pageRows, ...(report?.rows ?? [])]
  const failing = rows.filter((r) => r.ok === false).length
  const exit = report ? readinessVerdict(report, pageRows).exit : 1       // one verdict with `vt preflight`: a ✗ is never "exit 0"
  return (
    <section data-testid="readiness" data-failing={failing} className="space-y-2 rounded-lg border p-3 text-xs">
      <div className="flex flex-wrap items-center gap-3">
        <b className="text-sm">Pre-flight</b>
        <span data-testid="readiness-summary" className={failing === 0 && report ? 'text-emerald-700' : 'text-red-700'}>
          {running ? 'checking…' : !report ? 'pre-flight not run yet' : failing === 0 ? 'every check passed' : `${failing} check${failing === 1 ? '' : 's'} failing`}
          {report ? ` · network ${report.network} · exit ${exit}` : ''}
        </span>
        {error && <span data-testid="readiness-error" className="text-red-700">{error}</span>}
        {onRun && <Button type="button" size="xs" variant="outline" data-testid="readiness-run" disabled={running} onClick={onRun}>Run again</Button>}
      </div>
      <table className="w-full text-left">
        <thead className="text-muted-foreground"><tr><th className="w-6 font-normal" /><th className="font-normal">check</th><th className="font-normal">result</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} data-testid={`ready-row-${r.id}`} data-ok={String(r.ok)} className="border-t align-top">
              <td className={`py-0.5 font-semibold ${TONE(r.ok)}`} data-testid={`ready-mark-${r.id}`}>{MARK(r.ok)}</td>
              <td className="pr-3">{r.label}</td>
              <td className="break-words text-muted-foreground" data-testid={`ready-detail-${r.id}`}>{r.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}

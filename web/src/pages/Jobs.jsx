// The jobs of this stack (W3): GET /api/jobs every 5 s, newest first, with each chain's phase. A job started by the CLI
// is reached from here and watched live on its page.
import { useEffect, useState } from 'react'
import { api } from '@/lib/api.js'

export default function Jobs({ intervalMs = 5000 }) {
  const [jobs, setJobs] = useState(null), [err, setErr] = useState('')
  useEffect(() => {
    let on = true
    const go = () => api('/jobs').then((j) => { if (on) { setJobs([...(j.jobs || [])].sort((a, b) => b.createdAt - a.createdAt)); setErr('') } }, (e) => on && setErr(`${e.guard}: ${e.message}`))
    go(); const t = setInterval(go, intervalMs)
    return () => { on = false; clearInterval(t) }
  }, [intervalMs])
  return (
    <section className="space-y-3" data-testid="jobs">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">Jobs</h1>
        <a href="#/new" className="text-sm underline">New job</a>
      </div>
      {err && <p className="text-xs text-red-700" data-testid="jobs-error">{err}</p>}
      {jobs === null && !err && <p className="text-sm text-muted-foreground">Loading…</p>}
      {jobs?.length === 0 && <p className="text-sm text-muted-foreground">No jobs yet on this network.</p>}
      <ul className="space-y-1">
        {(jobs || []).map((j) => (
          <li key={j.id} data-testid={`job-${j.id}`} className="flex flex-wrap items-center gap-2 rounded-md border px-3 py-2 text-sm">
            <a href={`#/jobs/${j.id}`} className="font-medium underline">{j.name}</a>
            <span className="font-mono text-xs text-muted-foreground">{j.id}</span>
            <span className="rounded bg-muted px-1.5 py-0.5 text-[11px] font-semibold">{j.phase}</span>
            {Object.entries(j.chains || {}).map(([c, s]) => <span key={c} className="text-xs text-muted-foreground">{c}: {s.phase}</span>)}
          </li>
        ))}
      </ul>
    </section>
  )
}

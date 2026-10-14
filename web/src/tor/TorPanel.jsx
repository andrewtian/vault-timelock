// Tor control (ported from the prototype's TorPanel.jsx). Talks only to the relay: GET /relay/tor, POST /relay/tor/new
// {role}, POST /relay/tor/auto {on}. Shows IsTor (never an IP), per-role circuit generation, age, ok/fail counts and the
// last error. The page's sends are disabled while IsTor is not true (fail closed) on testnet and mainnet; the local
// network talks to loopback chains directly, so its panel is a note. That note is read from /relay/tor (M4a glue, S6 F1):
// the local relay still uses Tor for drand (Open), so it says "drand via Tor; chains direct loopback" and the last drand
// IsTor check, never just "no Tor". The note makes one read-only request per refresh; it never starts a Tor check.
import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button.jsx'
import { currentNetwork, useStatus } from '@/lib/status.js'
import { localTorView } from '@vault-timelock/core/executor'

const ROLE_NOTE = { eth: 'Ethereum RPC', sol: 'Solana RPC', price: 'Jupiter price', check: 'Tor check' }
const age = (s) => (s == null ? '—' : s < 90 ? `${s} s` : s < 5400 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`)

export async function fetchTor() {
  const r = await fetch('/relay/tor', { cache: 'no-store' }); const j = await r.json().catch(() => null)
  if (!r.ok || !j?.roles) throw new Error(j?.error?.message || `relay HTTP ${r.status}`)
  return j
}
async function post(path, body) {
  const r = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  const j = await r.json().catch(() => null); return { status: r.status, j }
}

export function useTor(intervalMs = 10000, enabled = true) {
  const [st, setSt] = useState(null), [err, setErr] = useState('')
  const refresh = () => fetchTor().then((j) => { setSt(j); setErr('') }, (e) => { setSt(null); setErr(String(e.message)) })
  useEffect(() => {
    if (!enabled) return undefined
    refresh(); const t = setInterval(refresh, intervalMs); return () => clearInterval(t)
  }, [intervalMs, enabled])
  return { st, err, refresh, setSt }
}

// The send gate on the page: local needs no Tor; otherwise IsTor must be true.
export const torGate = (network, st) => (network === 'local' ? { ok: true } : st?.isTor === true ? { ok: true } : { ok: false, why: st?.isTor === false ? 'IsTor ✗ — the relay is not reaching the network through Tor' : 'IsTor unknown — Tor not confirmed yet' })

export default function TorPanel({ busy = false, intervalMs }) {
  const network = currentNetwork(useStatus())
  const { st, err, refresh, setSt } = useTor(intervalMs)
  const [msg, setMsg] = useState('')
  if (network === 'local') {
    const v = localTorView(st)
    return (
      <section data-testid="tor-panel" className="rounded-lg border px-4 py-2 text-xs text-muted-foreground">
        Tor · <b data-testid="tor-local-line">{st === null ? (err ? 'local: Tor state unknown (the relay did not answer)' : 'local: reading the relay…') : `local: ${v.detail}`}</b>
        {' '}(the local relay talks to anvil, bitcoind and the test validator directly; only drand, for Open, goes through Tor; circuit controls are testnet and mainnet only)
        {err ? <span data-testid="tor-local-err"> · {err}</span> : null}
      </section>
    )
  }
  const act = async (path, body, label) => {
    setMsg(`${label}…`)
    const { status, j } = await post(path, body)
    if (j?.status) setSt(j.status); else if (j?.roles) setSt(j)
    const limited = j?.results ? Object.entries(j.results).filter(([, v]) => !v.ok).map(([k, v]) => `${k} (wait ${v.retryInSec} s)`) : []
    setMsg(status === 200 ? `${label}: done${limited.length ? ` · rate-limited: ${limited.join(', ')}` : ''}` : `${label}: ${j?.error?.message || (limited.length ? `rate-limited: ${limited.join(', ')}` : `HTTP ${status}`)}`)
    refresh()
  }
  const ok = st?.isTor === true
  return (
    <section data-testid="tor-panel" className={`rounded-lg border p-3 text-xs ${ok ? '' : 'border-red-600 bg-red-50'}`}>
      <div className="flex flex-wrap items-center gap-3">
        <b className="text-sm">Tor</b>
        <span data-testid="tor-istor" className={ok ? 'text-emerald-700' : 'text-red-700'}>IsTor {ok ? '✓' : st?.isTor === false ? '✗' : 'unknown'}{st?.checkedAt ? ` · checked ${new Date(st.checkedAt).toISOString().slice(11, 19)} UTC` : ''}{err ? ` · ${err}` : ''}</span>
        <span className="text-muted-foreground">(check.torproject.org via the relay, role “check”; only the boolean is kept, never an IP)</span>
        <label htmlFor="tor-auto" className="ml-auto flex items-center gap-1.5">
          <input id="tor-auto" name="tor-auto" type="checkbox" data-testid="tor-auto" checked={!!st?.auto} disabled={!st || busy} onChange={(e) => act('/relay/tor/auto', { on: e.target.checked }, `auto-rotate ${e.target.checked ? 'on' : 'off'}`)} /> auto-rotate on blocks/timeouts
        </label>
        <Button size="xs" variant="outline" data-testid="tor-new-all" disabled={!st || busy} onClick={() => act('/relay/tor/new', { role: 'all' }, 'new circuits (all)')}>New circuits (all)</Button>
      </div>
      {st && (
        <table className="mt-2 w-full text-left font-mono text-[11px]">
          <thead className="text-muted-foreground"><tr><th className="py-0.5 font-normal">role</th><th className="font-normal">circuit</th><th className="font-normal">age</th><th className="font-normal">ok / fail</th><th className="font-normal">last</th><th className="font-normal">last error</th><th /></tr></thead>
          <tbody>
            {Object.entries(st.roles).map(([r, x]) => (
              <tr key={r} data-testid={`tor-role-${r}`} className="border-t">
                <td className="py-0.5">{r} <span className="text-muted-foreground">· {ROLE_NOTE[r]}</span></td>
                <td data-testid={`tor-gen-${r}`}>gen {x.gen}</td><td>{age(x.ageSec)}</td><td>{x.okCount} / {x.failCount}</td><td>{x.lastStatus ?? '—'}</td>
                <td className={x.lastError ? 'text-amber-700' : 'text-muted-foreground'}>{x.lastError ?? '—'}</td>
                <td className="text-right"><Button size="xs" variant="outline" data-testid={`tor-new-${r}`} disabled={busy} onClick={() => act('/relay/tor/new', { role: r }, `new circuit (${r})`)}>New circuit</Button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {busy && <div className="mt-1 text-muted-foreground">Circuit controls are locked while armed or sending (a new circuit would cut in-flight requests).</div>}
      {msg && <div data-testid="tor-msg" className="mt-1 text-muted-foreground">{msg}</div>}
    </section>
  )
}

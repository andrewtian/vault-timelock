// Funding provenance in the page (plan W6, D-R21): the badge, the user-clicked check (Ethereum only: the relay's indexer reads),
// and the verdict. Every rule is core's (gates/provenance.ts). R76: INFORMATIONAL only: nothing here blocks Arm
// (mainnet relies on funds being present in each lane wallet, shown in the Arm dialog). No attestation, no gate.
//   status of a chain = 'railgun' (the check passed) > what the check found ('elsewhere' only for a transfer positively not from Railgun; 'unfunded',
//   'paged', 'sent', 'unaccounted' for the other failures) > 'unchecked'; local: 'stand-in'.
import { useState } from 'react'
import { Badge } from '@/components/ui/badge.jsx'
import { Button } from '@/components/ui/button.jsx'
import { ProvenanceReadError, readEthProvenance } from './provenance.js'

const NAME = { eth: 'Ethereum', sol: 'Solana', btc: 'Bitcoin' }
const LOOK = {
  railgun: ['bg-emerald-100 text-emerald-900', 'Railgun ✓'],
  elsewhere: ['bg-red-100 text-red-900', 'not from Railgun'],
  unfunded: ['bg-slate-100 text-slate-900', 'not funded yet'],
  paged: ['bg-amber-100 text-amber-900', 'unchecked (too long to read)'],
  sent: ['bg-amber-100 text-amber-900', 'has sent since funding (check the funding transactions only)'],
  unaccounted: ['bg-amber-100 text-amber-900', 'balance not explained (indexer lag, or other funds)'],
  unchecked: ['bg-amber-100 text-amber-900', 'unchecked'],
  'stand-in': ['bg-slate-100 text-slate-900', 'local stand-in'],
}
export function ProvenanceBadge({ status, testid = 'prov-badge' }) {
  const [cls, label] = LOOK[status] ?? LOOK.unchecked
  return <Badge data-testid={testid} data-status={status} className={cls}>{label}</Badge>
}

// useEthProvenance({network, address, read}) -> { result, error, busy, check }   (result = readEthProvenance's answer or null)
export function useEthProvenance({ network, address, read = readEthProvenance }) {
  const [st, setSt] = useState({ result: null, error: '', busy: false })
  const check = async () => {
    setSt({ result: null, error: '', busy: true })
    try { setSt({ result: await read({ network, address }), error: '', busy: false }) } catch (e) {
      setSt({ result: null, error: e instanceof ProvenanceReadError ? e.message : `the check failed (${String(e?.message ?? e).slice(0, 120)})`, busy: false })
    }
  }
  return { ...st, check }
}

// The status shown for one chain (informational).
export function statusOf({ network, result }) {
  if (network === 'local') return 'stand-in'
  if (result?.status === 'railgun') return 'railgun'
  return result?.status ?? 'unchecked'
}

export function VerdictList({ verdict }) {
  if (!verdict) return null
  return (
    <ul data-testid="prov-reasons" className="list-inside list-disc text-xs">
      {verdict.ok
        ? <li data-testid="prov-ok">Every inbound transfer came through the Railgun proxy or its RelayAdapt, the address has never sent, and the inbound total is the balance.</li>
        : verdict.failures.map((f, i) => <li key={i}><b>{f.guard}</b>: {f.message}</li>)}
    </ul>
  )
}

// The Arm dialog's section: one row per armed chain. props: network, chains [{chain, address}], results {chain: result}, onCheck(chain), busy {chain}
export default function FundingProvenance({ network, chains, results, errors = {}, busy = {}, onCheck }) {
  if (network === 'local') return null
  return (
    <fieldset data-testid="arm-provenance" className="space-y-2 rounded-md border p-2 text-xs">
      <legend className="px-1 font-semibold">Funding provenance (informational)</legend>
      <p className="text-muted-foreground">For your information only: Arm does not wait for it. What Arm relies on is the funds present in each lane wallet (shown above).</p>
      {chains.map(({ chain, address }) => {
        const status = statusOf({ network, result: results[chain] ?? null })
        return (
          <div key={chain} data-testid={`arm-prov-${chain}`} data-status={status} className="space-y-1 rounded border p-2">
            <div className="flex flex-wrap items-center gap-2"><b>{NAME[chain]}</b> <ProvenanceBadge status={status} testid={`arm-prov-badge-${chain}`} />
              {chain === 'eth' && <Button type="button" size="xs" variant="outline" data-testid="arm-prov-check-eth" disabled={!!busy[chain] || !address} onClick={() => onCheck(chain)}>{busy[chain] ? 'Reading…' : 'Check Railgun provenance'}</Button>}
              {chain !== 'eth' && <span className="text-muted-foreground">no automatic check for {NAME[chain]} funding</span>}
            </div>
            {errors[chain] && <p data-testid={`arm-prov-error-${chain}`} className="text-red-700">{errors[chain]}</p>}
            <VerdictList verdict={results[chain]?.verdict} />
          </div>
        )
      })}
    </fieldset>
  )
}

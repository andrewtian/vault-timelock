// Claw back the remainder (W3; CC-2a; prototype LaneRun.jsx "Claw back remainder", tag add7b-e540f8ae4d6b). Only on a
// settled chain (DRAINED, COPIES_DONE, STOPPED; or CLAWING_BACK to finish one) with no job transaction in flight. The
// executor's claw-back (core: same network and key checks, the lease, reconcile first, the lane's fee strategy) sends
// value = balance − worst-case fee, so value + fee = the lane's balance.
//   · That amount counts against what is left of the ARMED cap (nativeCap − spent). When it does not fit, the operator
//     types it exactly (shown in full precision, compared in base units) and it rides as clawbackConfirm { amount } in
//     base units beside the clawback-intent only — a one-off approval of THIS claw-back, never a raised cap.
//   · ETH destination class (PM finding 1): 21,000 gas to an existing account, 204,600 to an EMPTY one after Amsterdam
//     (EIP-8037); a contract destination is refused. The page reads the class through the relay before you send.
//   · Mainnet: typed `claw back`. The destination is linked to the lane key on-chain (R47/R57).
import { useEffect, useId, useState } from 'react'
import { ethAmsterdam } from '@vault-timelock/core/contracts'
import { CANON } from '@vault-timelock/core/chains/constants.js'
import { ethClawGas, ethReservedKind, validateEthDest, validateSolDest } from '@vault-timelock/core/chains/economy.js'
import * as eth from '@vault-timelock/core/chains/eth.js'
import { formatUnits } from '@vault-timelock/core/chains/plan.js'
import * as sol from '@vault-timelock/core/chains/sol.js'
import { useRelayClient } from '@vault-timelock/core/engine/rpc.js'
import { browserClients } from '@vault-timelock/core/executor'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { RegimeLine } from '@/shell/RegimeBanner.jsx'
import { DEC, UNIT, sameAmount } from './armInputs.js'
import { useRuns } from './RunHere.js'

export const CLAW_PHASES = new Set(['DRAINED', 'COPIES_DONE', 'STOPPED', 'CLAWING_BACK'])
const short = (e) => String(e?.message || e).replace(/\s+/g, ' ').slice(0, 160)

// The claw-back's budget: room = nativeCap − spent (base units); need = the lane's balance (= value + worst-case fee).
export function clawBudget(cap, spent, balance) {
  if (cap == null || balance == null) return null
  const room = BigInt(cap) - BigInt(spent || '0')
  return { room, need: balance, typed: balance > room }
}

export async function readBalance(chain, address) {
  useRelayClient(browserClients().relay)
  return chain === 'eth' ? eth.balance(address) : sol.solBalance(address)
}
export async function destClass(address) {
  useRelayClient(browserClients().relay)
  return eth.accountClass(address)
}

export default function Clawback({ jobId, def, chain, cs, armed, entry, keyOk, run, network, heldElsewhere = false }) {
  const uid = useId()
  const runs = useRuns()
  const ch = def.chains[chain], addr = ch.keyAddress
  const [dest, setDest] = useState(ch.clawbackTo ?? '')
  const [bal, setBal] = useState(null), [balErr, setBalErr] = useState('')
  const [cls, setCls] = useState(null)
  const [typedAmount, setTypedAmount] = useState(''), [typedWord, setTypedWord] = useState('')
  const settled = cs && CLAW_PHASES.has(cs.phase) && !cs.txs.some((t) => t.state === 'open' || t.state === 'stuck')
  const done = cs?.phase === 'CLAWED_BACK'

  useEffect(() => {
    if (!settled || done) return undefined
    let on = true
    const go = () => readBalance(chain, addr).then((b) => { if (on) { setBal(b); setBalErr('') } }, (e) => on && setBalErr(short(e)))
    go(); const t = setInterval(go, 10_000)
    return () => { on = false; clearInterval(t) }
  }, [settled, done, chain, addr])

  const dv = dest ? (chain === 'eth' ? validateEthDest(dest, addr) : validateSolDest(dest, addr)) : null
  useEffect(() => {
    if (chain !== 'eth' || !dv?.ok) { setCls(null); return undefined }
    let on = true
    setCls({ checking: true })
    destClass(dv.address).then((c) => on && setCls(c), (e) => on && setCls({ error: short(e) }))
    return () => { on = false }
  }, [chain, dv?.ok, dv?.address])

  if (done) {
    return <div data-testid={`claw-done-${chain}`} className="text-xs text-emerald-800">Clawed back {cs.clawback ? `${formatUnits(BigInt(cs.clawback.value || '0'), DEC[chain])} ${UNIT[chain]} to ${cs.clawback.to}` : ''}{cs.clawback?.ok === false ? ' (readback differs)' : ' ✓'}</div>
  }
  if (!settled) return <p className="text-xs text-muted-foreground" data-testid={`claw-wait-${chain}`}>Claw back: available once the chain has settled (drained, copies done or stopped) with nothing in flight.</p>

  const budget = clawBudget(armed?.caps?.[chain]?.nativeCap, cs.spent, bal)
  const need = budget ? formatUnits(budget.need, DEC[chain]) : ''
  const amsterdam = chain === 'eth' ? ethAmsterdam(network) : false
  const gas = chain === 'eth' && cls && !cls.checking && !cls.error ? ethClawGas({ amsterdam, empty: cls.empty }) : null
  const problems = []
  if (!keyOk) problems.push('load this chain’s key in this tab')
  if (run.status === 'running') problems.push('this tab is already running this chain')
  if (heldElsewhere) problems.push('another executor holds this chain’s lease (vt job clawback, or wait for it to end)')
  if (!dv) problems.push('enter the destination')
  else if (!dv.ok) problems.push(dv.why)
  else if (chain === 'eth' && ethReservedKind(dv.address) !== null) problems.push(ethReservedKind(dv.address) === 'precompile' ? 'an Ethereum precompile or reserved system address (0x…0001 to 0x…ffff): nobody controls it and value sent there is lost' : 'the null or burn address: nobody controls it and funds sent there are burned') // @guard:job.clawback-precompile
  else if (ch.clawbackTo && dv.address !== ch.clawbackTo) problems.push(`the job names the claw-back destination ${ch.clawbackTo}`)
  if (chain === 'eth' && cls?.code) problems.push('a contract destination is refused')
  if (chain === 'eth' && dv?.ok && (!cls || cls.checking)) problems.push('checking the destination class…')
  if (chain === 'eth' && cls?.error) problems.push(`could not classify the destination: ${cls.error}`)
  if (!budget) problems.push(balErr ? `balance: ${balErr}` : 'reading the balance…')
  else if (budget.need <= 0n) problems.push('nothing to claw back')
  else if (budget.typed && !sameAmount(typedAmount, need, chain)) problems.push('type the exact amount to approve it over the armed cap')
  if (network === 'mainnet' && typedWord !== 'claw back') problems.push('type claw back to confirm')

  const go = () => runs.clawback(jobId, chain, entry, dv.address, budget.typed ? String(budget.need) : null)

  return (
    <div data-testid={`claw-${chain}`} className="space-y-1 rounded-md border p-2 text-xs">
      <div className="font-semibold">Claw back the remainder <span className="font-normal text-muted-foreground">· at the lane’s fee strategy ({ch.feeStrategy})</span></div>
      <RegimeLine testid={`claw-regime-${chain}`} />
      <p className="text-amber-900">This links the lane key to that address on-chain (R47/R57).</p>
      {chain === 'eth'
        ? <p data-testid={`claw-gaswarn-${chain}`} className="text-amber-900">Gas by destination: {String(CANON.ETH_CLAW_GAS_EXISTING)} to an existing account; after Amsterdam a FRESH (empty) destination costs {String(CANON.ETH_CLAW_GAS_EMPTY_AMSTERDAM)} gas — about 10× more. Amsterdam is {amsterdam ? 'active' : 'not active'} on this network.</p>
        : <p className="text-amber-900">SOL: balance − the exact fee, so the lane ends at 0 lamports; a new destination needs at least the rent-exempt minimum.</p>}
      <Label htmlFor={`${uid}-dest`} className="text-xs">Destination</Label>
      <Input id={`${uid}-dest`} name={`${uid}-dest`} data-testid={`claw-dest-${chain}`} value={dest} readOnly={!!ch.clawbackTo} onChange={(e) => setDest(e.target.value.trim())}
        placeholder={chain === 'eth' ? '0x… (EIP-55 checksummed)' : 'base58 address'} autoComplete="off" spellCheck={false} />
      {gas !== null && <p data-testid={`claw-gas-${chain}`} data-gas={String(gas)} className={gas > CANON.ETH_CLAW_GAS_EXISTING ? 'font-semibold text-amber-800' : 'text-muted-foreground'}>
        gas {String(gas)}: the destination is {cls.empty ? 'EMPTY (a fresh account)' : 'an existing account'}{gas > CANON.ETH_CLAW_GAS_EXISTING ? ' — the fresh-destination price after Amsterdam' : ''}.</p>}
      {budget && <p data-testid={`claw-budget-${chain}`}>remainder (value + fee) <b className="font-mono">{need} {UNIT[chain]}</b> · left of the armed cap {formatUnits(budget.room < 0n ? 0n : budget.room, DEC[chain])} {UNIT[chain]}</p>}
      {budget?.typed && (
        <div data-testid={`claw-over-${chain}`} className="rounded border border-amber-500 bg-amber-50 p-2 text-amber-950">
          The remainder is over what is left of the cap confirmed at Arm. Type <b className="break-all font-mono">{need}</b> to approve clawing back exactly this amount ({String(budget.need)} base units).
          <Label htmlFor={`${uid}-amount`} className="text-xs">exact amount ({UNIT[chain]})</Label>
          <Input id={`${uid}-amount`} name={`${uid}-amount`} data-testid={`claw-amount-${chain}`} value={typedAmount} onChange={(e) => setTypedAmount(e.target.value)} autoComplete="off" spellCheck={false} />
        </div>
      )}
      {network === 'mainnet' && <>
        <Label htmlFor={`${uid}-word`} className="text-xs">type claw back to confirm</Label>
        <Input id={`${uid}-word`} name={`${uid}-word`} data-testid={`claw-typed-${chain}`} value={typedWord} onChange={(e) => setTypedWord(e.target.value)} autoComplete="off" spellCheck={false} />
      </>}
      {problems.length > 0 && <ul data-testid={`claw-problems-${chain}`} className="list-inside list-disc text-muted-foreground">{problems.map((p) => <li key={p}>{p}</li>)}</ul>}
      <Button type="button" size="sm" data-testid={`claw-go-${chain}`} disabled={problems.length > 0} onClick={go}>{run.kind === 'clawback' && run.status === 'running' ? 'Clawing back…' : 'Claw back remainder'}</Button>
      {run.kind === 'clawback' && run.status === 'ended' && <p data-testid={`claw-result-${chain}`} className={run.outcome === 'clawed-back' ? 'text-emerald-800' : 'text-red-700'}>
        {run.outcome === 'clawed-back' ? 'clawed back ✓' : `claw-back ${run.outcome || 'refused'}${run.error ? ` — ${run.error.guard}: ${run.error.message}` : run.view?.note ? ` — ${run.view.note}` : ''}`}</p>}
    </div>
  )
}

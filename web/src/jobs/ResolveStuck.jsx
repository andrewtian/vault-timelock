// Resolve a STUCK chain (W4; moved from W3). A transaction is STUCK when the engine could not tell from the chain whether
// it landed; it is never re-sent blindly. This panel shows each open attempt with what is known about it (its declared
// fee and nonce / blockhash, the journal's reason, and — on request — what the chain says, read through the relay) and
// records the OPERATOR'S outcome through POST /jobs/:id/chains/:c/resolve { txId, action, typed? }.
//   · mark-done   — "it landed": counts its worst-case fee as spent.
//   · mark-failed — "it did not land": frees NO cap. Only chain evidence frees a cap; a wrong "failed" can leave a
//                   transaction that lands later on top of your retry.
//   · mainnet needs the typed word `resolve`.
// btc: only mark-failed (the API refuses mark-done for a commit: it would wedge the chain with no reveal).
// CLI equivalent: vt job resolve <id> --chain c --tx <txId> mark-done|mark-failed
import { useState } from 'react'
import { P } from '@vault-timelock/core/contracts'
import { browserClients } from '@vault-timelock/core/executor'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { api } from '@/lib/api.js'

export const resolveCommand = (jobId, chain, txId, action) => `vt job resolve ${jobId} --chain ${chain} --tx ${txId} ${action}`
const short = (e) => String(e?.message || e).replace(/\s+/g, ' ').slice(0, 160)

// What the chain says about one attempt (a read through the relay; never a send).
export async function chainEvidence(chain, txId, relay = browserClients().relay) {
  if (chain === 'eth') {
    const r = await relay.rpc('eth', 'eth_getTransactionReceipt', [txId])
    if (r) return { found: true, text: `included in block ${Number(BigInt(r.blockNumber))} (status ${r.status === '0x1' ? 'success' : 'reverted'})` }
    const t = await relay.rpc('eth', 'eth_getTransactionByHash', [txId])
    return t ? { found: true, text: 'known to the network, not mined yet (pending)' } : { found: false, text: 'the network does not know this transaction (not in a block, not pending)' }
  }
  if (chain === 'btc') throw new Error('the page does not read Bitcoin here: check the commit with your own node or ord')
  const r = await relay.rpc('sol', 'getSignatureStatuses', [[txId], { searchTransactionHistory: true }])
  const s = r?.value?.[0]
  return s ? { found: true, text: `${s.err ? 'landed with an error' : 'landed'} at slot ${s.slot} (${s.confirmationStatus || 'unknown commitment'})` } : { found: false, text: 'no signature status: not landed on the nodes queried (it may still land until its blockhash expires)' }
}

function Attempt({ jobId, chain, network, a, tx, evidenceFor }) {
  const [typed, setTyped] = useState('')
  const [ev, setEv] = useState(null)
  const [msg, setMsg] = useState(null)
  const [busy, setBusy] = useState(false)
  const needTyped = network === 'mainnet'
  const typedOk = !needTyped || typed === 'resolve'
  const fee = chain === 'eth' && a.eth ? `nonce ${a.eth.nonce}, maxFee ${a.eth.maxFee} wei` : chain === 'sol' && a.sol ? `fee ${a.sol.fee} lamports` : ''
  const check = async () => { setEv({ checking: true }); try { setEv(await evidenceFor(chain, a.txId)) } catch (e) { setEv({ error: short(e) }) } }
  const post = async (action) => {
    setBusy(true); setMsg(null)
    try {
      await api(P.resolve(jobId, chain), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ txId: a.txId, action, ...(needTyped ? { typed } : {}) }) })
      setMsg({ ok: true, text: `recorded ${action}` })
    } catch (e) { setMsg({ ok: false, text: `${e.guard || 'error'}: ${e.message}` }) } finally { setBusy(false) }
  }
  return (
    <li data-testid={`stuck-attempt-${chain}-${a.txId}`} className="space-y-1 rounded border p-2">
      <div>copy {tx?.copy ?? '?'} part {tx?.part ?? '?'}/{tx?.parts ?? '?'} · attempt <span className="break-all font-mono">{a.txId}</span> · {a.state}{fee ? ` · ${fee}` : ''}</div>
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" size="xs" variant="outline" data-testid={`stuck-check-${chain}`} onClick={check}>Check the chain</Button>
        {ev && <span data-testid={`stuck-evidence-${chain}`} data-found={ev.found === undefined ? '' : String(ev.found)}>{ev.checking ? 'reading the chain…' : ev.error ? `could not read the chain: ${ev.error}` : `chain evidence: ${ev.text}`}</span>}
      </div>
      {needTyped && (
        <div>
          <Label htmlFor={`resolve-word-${chain}-${a.txId}`} className="text-xs">type resolve to confirm</Label>
          <Input id={`resolve-word-${chain}-${a.txId}`} name={`resolve-word-${chain}`} data-testid={`resolve-typed-${chain}`} value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
        </div>
      )}
      <div className="flex flex-wrap gap-2">
        {chain !== 'btc' && <Button type="button" size="xs" data-testid={`resolve-done-${chain}`} disabled={!typedOk || busy} onClick={() => post('mark-done')}>It landed (mark done)</Button>}
        <Button type="button" size="xs" variant="outline" data-testid={`resolve-failed-${chain}`} disabled={!typedOk || busy} onClick={() => post('mark-failed')}>It did not land (mark failed)</Button>
      </div>
      <p className="font-mono text-[11px] text-muted-foreground" data-testid={`resolve-cli-${chain}`}>{resolveCommand(jobId, chain, a.txId, chain === 'btc' ? 'mark-failed' : 'mark-done|mark-failed')}</p>
      {msg && <p data-testid={`resolve-msg-${chain}`} className={msg.ok ? 'text-emerald-800' : 'text-red-700'}>{msg.text}</p>}
    </li>
  )
}

export default function ResolveStuck({ jobId, chain, cs, network, evidenceFor = chainEvidence }) {
  if (cs?.phase !== 'STUCK') return null
  const open = new Set(cs.openIntents)
  const rows = cs.txs.flatMap((tx) => tx.attempts.filter((a) => open.has(a.txId)).map((a) => ({ a, tx })))
  return (
    <div data-testid={`resolve-${chain}`} className="space-y-2 rounded-md border border-red-400 bg-red-50 p-2 text-xs text-red-950">
      <div className="font-semibold">STUCK: a transaction’s outcome is unknown</div>
      {cs.reason && <p data-testid={`resolve-reason-${chain}`}>{cs.reason}</p>}
      <p data-testid={`resolve-warning-${chain}`}><b>Mark failed frees NO cap.</b> Only chain evidence frees a cap: Run here / <span className="font-mono">vt job run</span> reconciles the attempt from the chain. Mark failed records your word, and a transaction that lands later still counts. Use Check the chain first.</p>
      {rows.length === 0 && <p>No open attempt is listed; Run here reconciles from the chain.</p>}
      <ul className="space-y-2">{rows.map(({ a, tx }) => <Attempt key={a.txId} jobId={jobId} chain={chain} network={network} a={a} tx={tx} evidenceFor={evidenceFor} />)}</ul>
    </div>
  )
}

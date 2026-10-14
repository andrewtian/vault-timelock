// The Privacy Cash funding tab (plan W6, spec §4a, research-privacycash.md). The operator's Privacy Cash wallet key is entered
// HERE and lives in memory only: it is handed to a module worker (worker.js) that derives the keys and forgets the input; nothing
// is stored (no storage, no cookie, no IndexedDB, no log) and the only requests are the SDK's own, rewritten to the relay's
// /relay/privacycash/* by the worker's guarded fetch. A withdrawal pays THIS lane's address, through the relayer, over Tor.
//
//   · the linkage warning is shown above every control and must be ticked for EVERY balance check and EVERY withdrawal (the box
//     clears after each one);
//   · the relayer fee is capped (0.006 SOL + 0.40 % of the gross, the relay's clamp) and a partial withdrawal is refused BEFORE proving;
//   · a watchdog stops a stuck worker (client.js); Stop does the same on demand; after a withdrawal, a lock, a stop or leaving the
//     page the worker is terminated, which is the wipe;
//   · mainnet only: Privacy Cash has no devnet. On the local and testnet stacks the tab explains and offers nothing;
//   · the relay needs a lane AUTHORIZATION (v2, x-vt-pc-lane) on /withdraw: single-use, bound to the exact withdrawal body. The worker's
//     guarded fetch mints it from POST /api/jobs/<id>/privacycash/lane when the SDK posts the body (guard.js), so this page only passes
//     the job id and a fresh try index; without a job there is nothing to bind, so the withdrawal waits for the job page;
//   · FUNDING IS LOCKED on mainnet: the API mints no authorization there (api.pc-lock, 423) and the relay refuses withdrawals while funding
//     sends are locked (release.mainnet-locked). The tab says so and offers no withdrawal; checking the balance still works.
import { useEffect, useId, useRef, useState } from 'react'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { copyText } from '@/jobs/AddressLinks.jsx'
import SecretInput from '@/keys/SecretInput.jsx'
import { createPcClient } from './client.js'
import { LINKAGE_WARNING, MIN_NET_LAMPORTS, feeCeiling, parseSol, sol } from './limits.js'

// The funding lock (controller ruling, Sfix-PC review I-2): no Privacy Cash authorization is minted on mainnet and no withdrawal opens.
// Lifting it is a deliberate change here AND in api/src/privacycash-mint.ts (api.pc-lock).
export const MAINNET_FUNDING_LOCKED = true
// A fresh try index for each withdrawal (the API mints one authorization per job and try, ever; a reused index is refused api.pc-allowance).
const freshTry = () => globalThis.crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_001

const say = (e) => `${e?.code ?? 'error'}: ${e?.message ?? e}`

export default function PrivacyCash({ network, address, jobId = null, createClient = createPcClient, newTry = freshTry, fundingLocked = MAINNET_FUNDING_LOCKED, onBusy = () => {} }) {
  const uid = useId()
  const [ack, setAck] = useState(false)
  const [mode, setMode] = useState('signature')
  const [pub, setPub] = useState(''), [key, setKey] = useState('')
  const [phase, setPhase] = useState('locked')              // locked | unlocking | ready | busy
  const [status, setStatus] = useState('')
  const [err, setErr] = useState(null)
  const [balance, setBalance] = useState(null)
  const [amount, setAmount] = useState('0.01')
  const [quote, setQuote] = useState(null)
  const [done, setDone] = useState(null)
  const clientRef = useRef(null)
  const unlocked = phase === 'ready' || phase === 'busy'

  const stop = (code, msg) => { clientRef.current?.stop(code, msg); clientRef.current = null }
  useEffect(() => () => { clientRef.current?.stop(); clientRef.current = null }, [])
  // m-3: while a call is in flight (unlocking or busy) the parent keeps the other funding tabs shut, and leaving the page asks first
  const inFlight = phase === 'busy' || phase === 'unlocking'
  useEffect(() => {
    onBusy(inFlight)
    if (!inFlight) return undefined
    const leave = (e) => { e.preventDefault(); e.returnValue = '' }
    window.addEventListener('beforeunload', leave)
    return () => { window.removeEventListener('beforeunload', leave); onBusy(false) }
  }, [inFlight])      // eslint-disable-line react-hooks/exhaustive-deps

  const fail = (e) => {
    setErr({ code: e?.code ?? 'error', message: e?.message ?? String(e), sentAtStop: !!e?.sentAtStop })
    if (e?.stopped) { clientRef.current = null; setPhase('locked'); setBalance(null); setQuote(null) } else setPhase('ready')
  }
  const reset = () => { setErr(null); setStatus('') }

  if (network !== 'mainnet') {
    return (
      <div data-testid="pc-tab" className="space-y-2 text-sm">
        <p data-testid="pc-not-mainnet" className="rounded-md border border-amber-500 bg-amber-50 p-2 text-xs text-amber-950">
          Privacy Cash exists on Solana mainnet only (it has no devnet), so this tab does nothing on the {network === 'local' ? 'local' : 'testnet'} stack: a
          withdrawal would pay real mainnet funds to an address whose key only this {network} job holds. Use it from a mainnet job.
        </p>
      </div>
    )
  }

  const unlock = async () => {
    reset()
    const secret = key
    setKey('')                                              // the input leaves the page's state at once
    setPhase('unlocking')
    const c = createClient({ onStatus: setStatus })
    clientRef.current = c
    try {
      await c.call('unlock', { mode, input: secret, publicKey: pub.trim() })
      setPhase('ready')
    } catch (e) { stop(); fail(Object.assign(e, { stopped: true })) }
  }
  const lock = async (why) => {
    const c = clientRef.current
    if (c?.alive) { try { await c.call('lock') } catch { /* terminated below */ } }
    stop()
    setPhase('locked'); setBalance(null); setQuote(null); setStatus('')
    if (why) setStatus(why)
  }
  const checkBalance = async () => {
    reset(); setPhase('busy'); setBalance(null); setQuote(null); setAck(false)
    try { setBalance(await clientRef.current.call('balance')); setPhase('ready') } catch (e) { fail(e) }
  }
  const net = parseSol(amount)
  const review = async () => {
    reset(); setPhase('busy'); setQuote(null)
    try { setQuote(await clientRef.current.call('quote', { net })); setPhase('ready') } catch (e) { fail(e) }
  }
  const withdraw = async () => {
    reset(); setPhase('busy'); setAck(false)
    try {
      const r = await clientRef.current.call('withdraw', { net, recipient: address, job: jobId, tryIndex: newTry() })
      setDone(r); setQuote(null)
      await lock('The worker was terminated after the withdrawal; the key is forgotten.')
    } catch (e) { fail(e) }
  }

  const keyOk = key.trim().length >= 32 && pub.trim().length >= 32
  const amountOk = net !== null && net >= MIN_NET_LAMPORTS
  return (
    <div data-testid="pc-tab" className="space-y-3 text-sm">
      <p data-testid="pc-warning" role="note" className="rounded-md border border-red-600 bg-red-50 p-2 text-xs text-red-900"><b>Linkage.</b> {LINKAGE_WARNING}</p>
      <label htmlFor={`${uid}-ack`} className="flex items-start gap-2 text-xs">
        <input id={`${uid}-ack`} name={`${uid}-ack`} type="checkbox" data-testid="pc-ack" checked={ack} onChange={(e) => setAck(e.target.checked)} disabled={phase === 'busy' || phase === 'unlocking'} />
        <span>I understand this. (Tick it again before every balance check and every withdrawal.)</span>
      </label>

      {!unlocked && (
        <fieldset className="space-y-2 rounded-md border p-2" disabled={phase === 'unlocking'}>
          <legend className="px-1 text-xs font-semibold">Privacy Cash wallet key (kept in this tab&apos;s memory only)</legend>
          <div className="flex gap-4 text-xs">
            {[['signature', 'Signature (recommended)'], ['secret', 'Wallet secret key']].map(([k, label]) => (
              <label key={k} htmlFor={`${uid}-m-${k}`} className="flex items-center gap-1">
                <input type="radio" id={`${uid}-m-${k}`} name={`${uid}-mode`} data-testid={`pc-mode-${k}`} checked={mode === k} onChange={() => setMode(k)} /> {label}
              </label>
            ))}
          </div>
          <p className="text-[11px] text-muted-foreground">
            {mode === 'signature'
              ? 'The base58 64-byte signature of the exact text "Privacy Money account sign in" by the deposit wallet (raw ed25519: a wallet\'s signMessage, not an off-chain message). It controls the Privacy Cash balance only, not the wallet\'s own SOL.'
              : 'The deposit wallet\'s Solana secret key (base58, or the CLI\'s JSON array). The signature is derived and the key is wiped at once. Prefer the signature.'}
          </p>
          <div className="space-y-1">
            <Label htmlFor={`${uid}-pub`} className="text-xs">Deposit wallet address</Label>
            <Input id={`${uid}-pub`} name={`${uid}-pub`} data-testid="pc-pubkey" value={pub} onChange={(e) => setPub(e.target.value)} autoComplete="off" spellCheck={false} />
          </div>
          <div className="space-y-1">
            <Label htmlFor={`${uid}-key`} className="text-xs">{mode === 'signature' ? 'Signature' : 'Secret key'}</Label>
            <SecretInput id={`${uid}-key`} data-testid="pc-key" value={key} onChange={(e) => setKey(e.target.value)} />
          </div>
          <Button type="button" size="sm" data-testid="pc-unlock" disabled={!keyOk} onClick={unlock}>{phase === 'unlocking' ? 'Checking…' : 'Unlock (in memory)'}</Button>
        </fieldset>
      )}

      {unlocked && (
        <div className="space-y-3">
          <p data-testid="pc-unlocked" className="text-xs text-emerald-800">Unlocked. The key is in this tab&apos;s memory only (a worker); Lock or Stop terminates it.</p>
          <div className="flex flex-wrap items-center gap-2">
            <Button type="button" size="sm" data-testid="pc-balance-btn" disabled={!ack || phase === 'busy'} onClick={checkBalance}>Check Privacy Cash balance</Button>
            <Button type="button" size="sm" variant="outline" data-testid="pc-lock" disabled={phase === 'busy'} onClick={() => lock('Locked: the worker was terminated and the key forgotten.')}>Lock</Button>
            {phase === 'busy' && <Button type="button" size="sm" variant="destructive" data-testid="pc-stop" onClick={() => stop('pc.stopped', 'stopped by you: the worker was terminated and the key forgotten')}>Stop</Button>}
          </div>
          {balance && (
            <p data-testid="pc-balance" className="text-xs">
              Private balance <b className="font-mono">{sol(balance.lamports)}</b> in {balance.notes} note(s); one withdrawal spends at most the two largest ({sol(balance.top2)}).
            </p>
          )}
          {balance && (
            <fieldset className="space-y-2 rounded-md border p-2">
              <legend className="px-1 text-xs font-semibold">Withdraw to this lane</legend>
              <div className="text-xs">Recipient (this job&apos;s Solana address) <span data-testid="pc-recipient" className="break-all font-mono">{address}</span></div>
              {fundingLocked && <p data-testid="pc-funding-locked" className="rounded border border-amber-500 bg-amber-50 p-2 text-xs text-amber-950">Funding is LOCKED on mainnet: the API mints no Privacy Cash authorization and the relay refuses withdrawals while funding sends are locked, so a withdrawal cannot be made from here. You can still check the balance.</p>}
              {jobId === null && <p data-testid="pc-needs-job" className="text-xs text-amber-900">The relay binds a withdrawal to a job&apos;s lane: create the job first, then withdraw from its page.</p>}
              <div className="space-y-1">
                <Label htmlFor={`${uid}-amt`} className="text-xs">Net amount (SOL, at least 0.01)</Label>
                <Input id={`${uid}-amt`} name={`${uid}-amt`} data-testid="pc-amount" value={amount} onChange={(e) => { setAmount(e.target.value); setQuote(null) }} autoComplete="off" spellCheck={false} />
              </div>
              <Button type="button" size="sm" variant="outline" data-testid="pc-review" disabled={!amountOk || phase === 'busy'} onClick={review}>Review fee</Button>
              {quote && (
                <div data-testid="pc-quote" className="space-y-1 rounded border p-2 text-xs">
                  <div>Debited from Privacy Cash <b className="font-mono">{sol(quote.gross)}</b> · relayer fee <b className="font-mono">{sol(quote.fee)}</b> (cap {sol(feeCeiling(quote.net))}) · the lane receives <b className="font-mono">{sol(quote.net)}</b></div>
                  <Button type="button" size="sm" data-testid="pc-withdraw" disabled={fundingLocked || !ack || jobId === null || phase === 'busy'} onClick={withdraw}>Withdraw {sol(quote.net)} to this address</Button>
                </div>
              )}
            </fieldset>
          )}
        </div>
      )}

      {status && <p data-testid="pc-status" className="text-xs text-muted-foreground">{status}</p>}
      {err && (
        <div data-testid="pc-error" className="space-y-1 text-xs text-red-700">
          <p><b>{err.code}</b>: {err.message}</p>
          {err.sentAtStop && <p data-testid="pc-sent-warning" className="font-semibold">The withdrawal request had already left. Funds may have moved: check this address and your Privacy Cash balance before trying again.</p>}
        </div>
      )}
      {done && (
        <div data-testid="pc-result" className="space-y-1 rounded border border-emerald-600 bg-emerald-50 p-2 text-xs text-emerald-950">
          <div>Withdrawal sent: <b className="font-mono">{sol(done.net)}</b> (fee {sol(done.fee)}) to this address.{!done.indexerConfirmed && ' Privacy Cash\'s own indexer had not confirmed it yet; the chain decides.'}</div>
          <div className="break-all">signature <span data-testid="pc-signature" className="font-mono">{done.signature}</span> <Button type="button" size="xs" variant="outline" onClick={() => copyText(done.signature)}>Copy</Button></div>
          <div>Check it on a Solana explorer in Tor Browser. Arm relies on the funds now present in the lane wallet, shown in the Arm dialog.</div>
        </div>
      )}
    </div>
  )
}

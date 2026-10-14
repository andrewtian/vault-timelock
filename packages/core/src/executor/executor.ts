// packages/core/src/executor/executor.ts — createExecutor: the one runtime both executors use (spec §7.3): the page
// (browser adapter) and `vt job run` (node adapter, C6). It drives signing under a lease; every rule below fails closed.
//
// start():
//   1. NETWORK before anything: the job's network = the API's = the relay's (executor.network-mismatch), and the relay
//      verified this chain's identity; the key is the job's key for this chain (executor.key-mismatch).
//   2. A chain that is settled with nothing open needs nothing: its outcome, no lease.
//   3. Lease (gen g) + heartbeat every LEASE_RENEW_MS; a lost lease stops every new tx at once ('lease-lost').
//   4. Before arm: key-loaded, funds (balance and one copy's worst case), then wait for the arm.
//   5. RECONCILE every open intent from chain evidence before any new intent (reconcile.ts; S1 reconcile-first).
//   6. Wait for startAt(armed, chain) by the API's clock (serverNowMs), re-read every second: a local clock jump never
//      starts a chain early; the assess loop keeps a fresh real-byte simulation for Skip and the pre-start check.
//   7. The pre-start check (assess.js startCheck: Tor, relay identity, a fresh passing simulation) or the chain stops.
//   8. The lane (runDrainLane / runCopiesLane) with the REDUCED job state as deps.state (the cap ledger is built from
//      it; deps.cap is never passed) and resume = { copy, nextPart, landed, adopted }: a landed part is never sent again.
//      The relay's verified endpoint counts go with it (E5: the ETH nonce quorum; every SOL send to every endpoint).
//      A lane refused engine.eip7702 (a delegated key, or an endpoint saying so) ends the chain cleanly (E5 fix round 1):
//      every open intent reconciled from the chain first, then `stopped` with the reason — so it can be clawed back.
//   9. Release the lease.
// Events reach the API flat ({ type, chain, ...data } split into (type, data)) under the live gen. A lost intent reply
// is recovered with POST …/tickets (a fresh ticket for THAT intent), never a new intent (event.duplicate).
//   executor.network-mismatch  the job, the API and the relay are not on one network, or the relay did not verify this
//                              chain's identity
//   executor.key-mismatch      the loaded key is not this job's key for this chain
//   executor.skip              Skip without IsTor ✓ (testnet, mainnet) or without a fresh passing simulation
//   executor.endpoints-quorum  (PF-S M-2, pre-flip review) a MAINNET eth / sol chain is not started (no lease, nothing signed) while
//                              the relay verified fewer than 2 endpoints for it (gates/agree.ts endpointsNeeded): the nonce / code
//                              agreement and the SOL expiry proof would rest on one provider's word. A claw-back is not refused
//                              (it is the way out); local, testnet and btc are unchanged
import { refuse, isRefusal, finalStopText, stopClassOf } from '../contracts/index.ts'
import type { Chain, ChainRunView, ChainState, Executor, ExecutorDeps, Holder, JobChainDef, JobDef, JobState, LeaseGrant, LoadedKey, Network, RunOutcome } from '../contracts/index.ts'
import { startAt } from '../job/schedule.ts'
import { btcStrandedIn } from '../job/reduce.ts'
import { sha256Hex, canonicalJson } from '../job/canonical.ts'
import { ethAmsterdam } from '../contracts/index.ts'
import { useRelayClient } from '../engine/rpc.js'
import * as eth from '../chains/eth.js'
import * as sol from '../chains/sol.js'
import * as btcc from '../chains/btc.js'
import { JournalError, journalText } from '../engine/engine.js'
import { clawbackEth, clawbackSol, newLaneState, planLaneCopy, runCopiesLane, runDrainLane, validateLaneConfig, watchAdoptedEth } from '../engine/lane.js'
import { assessChain, isFresh, startCheck, torGate } from '../engine/assess.js'
import { CANON } from '../chains/constants.js'
import { createLease } from './lease.ts'
import type { Lease } from './lease.ts'
import { JournalUnreachable } from './journal-client.ts'
import { reconcileChain } from './reconcile.ts'
import { DELEGATED_CLAWBACK_WARNING, endpointsNeeded } from '../gates/agree.ts'
import type { AdoptedEth, EngineJournal } from './reconcile.ts'

export type ExecutorKey = LoadedKey & { handle: unknown }
type Flat = { type: string; chain: Chain; [k: string]: unknown }
export interface ExecutorOptions { poll?: number; passiveWaitMs?: number; clawbackConfirm?: { amount: string }; rounds?: number }

// The API's refusals of a new job intent after a Stop it already holds (job.state; intent.after-stop, PF-S fix round 3): a raced Stop.
const STOP_REFUSALS: ReadonlySet<string> = new Set(['job.state', 'intent.after-stop'])
// PF-E fix round 2 (I-1): settled phases whose ETH job attempt may still be open (a Stop with it pending, a STUCK it was journaled
// beside): a rerun watches that attempt (lane.js watchAdoptedEth) instead of entering the lane, whose phase events are refused there.
const WATCH_ONLY: ReadonlySet<string> = new Set(['STOPPED', 'DRAINED', 'COPIES_DONE'])
const SETTLED: Readonly<Partial<Record<string, RunOutcome>>> = { DRAINED: 'drained', COPIES_DONE: 'copies-done', STOPPED: 'stopped', CLAWED_BACK: 'clawed-back', DONE: 'stopped', SKIPPED: 'stopped' }
const PRE_ARM = new Set(['AWAITING_KEY', 'AWAITING_FUNDS', 'READY'])
const sameAddress = (c: Chain, a: string, b: string): boolean => (c === 'eth' ? a.toLowerCase() === b.toLowerCase() : a === b)   // sol: base58, btc: lower-case bech32 (exact)
const short = (e: unknown): string => journalText((e as Error)?.message ?? e, 400)

function assertNetworks(ok: boolean, why: string): void {
  if (!ok) refuse('executor.network-mismatch', why) // @guard:executor.network-mismatch
}
function assertKey(ok: boolean, why: string): void {
  if (!ok) refuse('executor.key-mismatch', why) // @guard:executor.key-mismatch
}
// PF-S M-2: a mainnet eth / sol chain runs only on at least 2 relay-verified endpoints (the relay's live count when the run starts).
function assertEndpointQuorum(network: Network, chain: Chain, endpoints: number): void {
  const ok = network !== 'mainnet' || chain === 'btc' || endpoints >= endpointsNeeded(network, chain)
  if (!ok) refuse('executor.endpoints-quorum', `the relay verified ${endpoints} ${chain} endpoint(s) on mainnet: a chain is started only with at least ${endpointsNeeded(network, chain)} (one endpoint's word is never enough for the nonce agreement and the SOL expiry proof) — wait for the relay's re-check (vt status), fix endpoints.json or restart the stack, then run again`) // @guard:executor.endpoints-quorum
}

// What the takeover reconcile must look at (E3 review m-3, I-2): every open intent (job or claw-back), and every (copy,
// part) group that has not landed but has attempts — open ones, claims that may still land (rejected, mark-failed), and
// dead ones the chain may still contradict (re-checked before the part is ever signed again).
function needsReconcile(cs: ChainState, grant: LeaseGrant): boolean {
  return cs.openIntents.length > 0 || grant.openIntents.length > 0 || cs.txs.some((t) => t.state !== 'included' && t.attempts.length > 0)
}

// The lane config of a job chain (the lane runner's plain object; never key material).
export function laneConfigOf(chain: Chain, ch: JobChainDef, text: string): Record<string, unknown> {
  const copies = typeof ch.mode === 'object' && ch.mode !== null ? ch.mode.copies : null
  const v = validateLaneConfig({
    chain, mode: copies === null ? 'drain' : 'copies', ...(copies === null ? {} : { copies }), text, distinct: ch.distinctCopies, feeStrategy: ch.feeStrategy,
    ...(chain === 'eth' ? { recipient: ch.publishMode === 'eth.calldata.self' ? 'self' : 'null' } : {}),
    ...(ch.maxFeeRateSatVb !== undefined ? { maxFeeRateSatVb: ch.maxFeeRateSatVb } : {}),
    ...(ch.maxTipGwei !== undefined ? { tipCapGwei: String(ch.maxTipGwei) } : {}), ...(ch.maxCuPrice !== undefined ? { cuPriceCap: ch.maxCuPrice } : {}),
    ...(ch.clawbackTo !== null ? { clawbackTo: ch.clawbackTo } : {}),
  })
  if (!v.ok) throw new Error(`the job's ${chain} lane config is not runnable: ${v.errors.join('; ')}`)
  return v.cfg
}

// resume = { copy, nextPart, landed } from the reduced state (R72): landed maps the parts of that copy that landed and
// read back; null when nothing was sent yet. A copy that is complete resumes at the next copy — unless it was never
// reassembled (the earlier holder died before `reassembled`): then it resumes at that copy past its last part, so the
// lane sends nothing for it and reassembles it from the chain first.
export function resumeOf(cs: ChainState): { copy: number; nextPart: number; landed: Record<number, string> } | null {
  if (cs.txs.length === 0) return null
  const current = cs.txs.reduce((m, t) => (t.copy > m ? t.copy : m), 0)
  const parts = cs.txs.reduce((m, t) => (t.copy === current && t.parts > m ? t.parts : m), 0)
  const r = cs.resume ?? (cs.reassembled.some((x) => x.copy === current) ? { copy: current + 1, nextPart: 1 } : { copy: current, nextPart: parts + 1 })
  const landed: Record<number, string> = {}
  for (const t of cs.txs) if (t.copy === r.copy && t.state === 'included' && t.readback === true && t.landedId !== null) landed[t.part] = t.landedId
  return { copy: r.copy, nextPart: r.nextPart, landed }
}

export function createExecutor(p: { jobId: string; chain: Chain; key: ExecutorKey; holder: Holder; deps: ExecutorDeps & ExecutorOptions }): Executor & { clawback(to: string): Promise<RunOutcome> } {
  const { jobId, chain, key, holder, deps } = p
  const engineChain: Chain = chain // E7b: eth | sol | btc (btc on a local network only: checked at start, once the job's network is known)
  const { journal, relay, clock } = deps
  const poll = deps.poll ?? 2_000
  let started = false, stopFlag = false, resumeFlag = false, localStop = false, tipCap: string | null = null, cuCap: number | null = null   // localStop: requestStop() (Ctrl-C, the page's Stop)
  let lease: Lease | null = null, network: Network | null = null, last: Awaited<ReturnType<typeof assessChain>> | null = null
  let msSha = '', cfgKey = '', apiStop = false, leaseRefused: string | null = null, stopRefused = false
  // an API refusal of the lease (lease.stale, lease.lost, lease.holder): the lease is gone, whatever the heartbeat thinks
  const watch = async <T>(f: () => Promise<T>): Promise<T> => {
    try { return await f() } catch (e) { if (isRefusal(e) && e.guardId.startsWith('lease.') && e.guardId !== 'lease.reconcile-first') leaseRefused = e.guardId; throw e }
  }
  const leaseGone = (): boolean => leaseRefused !== null || (lease !== null && lease.lost() !== null)
  const view: ChainRunView = { phase: 'idle', copy: null, part: null, parts: null, note: '', startsInMs: null, delegated: false }
  const show = (o: Partial<ChainRunView>): void => { Object.assign(view, o); try { deps.onView?.({ ...view }) } catch { /* the view is advisory */ } }

  // the engine's journal seam, under the live gen; flat events split for the API
  const ej: EngineJournal = {
    async append(ev: Flat) { const { type, chain: c, ...data } = ev; await watch(() => journal.append(jobId, c, lease!.gen, type, data)) },
    async intent(ev: Flat) {
      const { type, chain: c, ...data } = ev
      const x = type === 'clawback-intent' && deps.clawbackConfirm !== undefined ? { clawbackConfirm: deps.clawbackConfirm } : undefined
      try {
        const r = await watch(() => journal.append(jobId, c, lease!.gen, type, data, x))
        if (typeof r.ticket !== 'string') throw new Error('the intent was acked without a send ticket')
        return { ticket: r.ticket }
      } catch (e) {
        // the API refused a new intent because a Stop arrived after our last read (S2: after stop-requested no new intent is
        // signed, intent.after-stop since PF-S fix round 3; job.state before; STOP_REFUSALS): nothing new is in flight from this
        // intent — the run ends `stopped` (journaled only when nothing is open, PF-E M-3, below)
        if (isRefusal(e) && STOP_REFUSALS.has(e.guardId) && type === 'intent') { await syncStop().catch(() => {}); if (apiStop) stopRefused = true }
        if (!(e instanceof JournalUnreachable)) throw e
        // the reply was lost: the intent may be journaled — a fresh ticket of THAT intent, never a new intent
        for (let i = 0; i < 3; i++) {
          try { return { ticket: await watch(() => journal.ticket(jobId, c, lease!.gen, String(data.txId))) } } catch (t) {
            if (!(t instanceof JournalUnreachable)) throw t                // ticket.not-intent: it was never journaled (nothing is sent)
            await clock.sleep(1_000)
          }
        }
        throw e
      }
    },
    ticket: (txId: string) => watch(() => journal.ticket(jobId, chain, lease!.gen, txId)),
  }

  // R79 (c): a STOPPED chain whose stop latch the operator's resume cleared (resume-requested is the only thing that clears it; no stop
  // request pending) is not settled: the next executor reopens it (`resumed`, which the gate takes only without the latch — an executor
  // never reopens a chain on its own) and continues at the next part of the current copy.
  // R79b: and only a RESUMABLE stop (contracts/stop.ts; ChainState.stopClass, absent = final): a FINAL stop is never reopened, whatever
  // cleared its latch (the API refuses its resume, resume.final-stop) — the chain stays STOPPED: claw back or close.
  const finalStop = (cs: ChainState): boolean => {
    if (cs.stopClass !== 'resumable') return true // @guard:resume.final-stop
    return false
  }
  const reopens = (cs: ChainState): boolean => cs.phase === 'STOPPED' && cs.stopLatched !== true && cs.stopRequested !== true && !finalStop(cs)
  const outcomeOf = (cs: ChainState): RunOutcome | null => (cs.openIntents.length === 0 && !reopens(cs) ? SETTLED[cs.phase] ?? null : null)
  // a settled chain as the run shows it; a FINAL stop names its reason and the way out (R79b: contracts/stop.ts finalStopText)
  const settledView = (cs: ChainState): Partial<ChainRunView> => ({ phase: cs.phase.toLowerCase(), ...(cs.phase === 'STOPPED' && cs.stopClass !== 'resumable' ? { note: finalStopText(chain, stopClassOf(cs)) } : {}) })
  // R79 (a): a DETACH — requestStop() alone (Ctrl-C in `vt job run`, the page's "Stop running here", the tab closing) with no stop
  // request at the API — ends this run after its in-flight window without journaling `stopped` (no phase event); the chain stays as it
  // is for the next executor. A stop request at the API (`vt job stop`, the page's job Stop) is a STOP: journaled, latched.
  const detachOnly = (): boolean => localStop && !apiStop
  // R79b (M-8): the operator's Stop in the countdown is journaled `stopped` (operator-stop) — unless the API journaled it already (its stop
  // route does for a chain that never started): the chain is then STOPPED and latched, and the executor's own `stopped` (refused) is success.
  const countdownStop = async (): Promise<RunOutcome> => {
    const latched = async (): Promise<boolean> => { const c = (await journal.job(jobId)).state.chains[chain]; return c?.phase === 'STOPPED' && c.stopLatched === true }
    if (!(await latched())) {
      try { await ej.append({ type: 'stopped', chain, reason: 'stopped by the operator before the start', code: 'operator-stop' }) } catch (e) {
        if (!(isRefusal(e) && STOP_REFUSALS.has(e.guardId)) || !(await latched())) throw e   // a stop the API journaled meanwhile
      }
    }
    show({ phase: 'stopped' }); return 'stopped'
  }
  const DETACHED = 'detached: nothing final was journaled — the job keeps running; run it again (vt job run, Run here) and it reconciles and continues'
  // The API's stop state (E3 review I-1): read at start, on every lease tick and before each new intent (the lane's
  // refreshStop). A stop-requested sets the Stop; a resume-requested after it clears it and resumes a paused lane.
  const syncStop = async (): Promise<void> => {
    const j = await journal.job(jobId)
    const req = j.state.chains[chain]?.stopRequested === true
    if (req && !apiStop) stopFlag = true
    // R79b (M-3): a local detach (requestStop: Ctrl-C, "Stop running here") is sticky in this process — the API's resume lifts only its own stop
    if (!req && apiStop) { resumeFlag = true; stopFlag = localStop }  // resume-requested at the API
    apiStop = req
  }

  // The chain's record of a landed part, re-read (never re-sent): ETH needs a status-1 receipt and the same calldata to
  // the same recipient; SOL a confirmed tx without error carrying the same Memo bytes. A few polls; else not ok.
  // R79b: definitive — the chain answered (other bytes, status 0, …) or the journal lacks what the reread needs; false: it could not be
  // read now (an RPC error, the tx not found yet), which a later run reads again.
  async function rereadLanded(g: { landedId: string | null; part: number; attempts?: Array<{ txId: string; btc?: unknown }> }, payload: Uint8Array | null, cfg: Record<string, unknown>): Promise<{ ok: boolean; detail: string; definitive: boolean }> {
    if (g.landedId === null || payload === null) return { ok: false, detail: 'no landed tx id or no planned bytes', definitive: true }
    let detail = 'the transaction cannot be read'
    for (let i = 0; i < 5; i++) {
      try {
        if (chain === 'btc') {
          const tx = await btcc.getTx(g.landedId)
          const pa = g.attempts?.find((a) => a.txId === g.landedId)?.btc
          if (tx != null && pa !== undefined) {
            const rb = g.part === 1 ? btcc.readbackCommit(key.handle as never, payload, tx, BigInt((pa as { value?: string }).value ?? '0')) : btcc.readbackReveal(key.handle as never, payload, tx)
            return { ok: rb.ok, detail: rb.detail, definitive: true }
          }
        } else if (chain === 'eth') {
          const rc = await eth.receipt(g.landedId)
          if (rc && rc.status !== '0x1') return { ok: false, detail: 'landed with status 0', definitive: true }
          const rb = rc ? await eth.readback(g.landedId, payload, eth.recipientAddress(cfg.recipient as string, key.address)) : null
          if (rb) return { ok: rb.ok, detail: rb.detail, definitive: true }
        } else {
          const rb = await sol.readback(g.landedId, payload)
          if (rb) return { ok: rb.ok, detail: rb.detail, definitive: true }
        }
      } catch (e) { detail = short(e) }
      await clock.sleep(Math.max(poll, 1_000))
    }
    return { ok: false, detail, definitive: false }
  }

  // 1. one network, one key (before any lease) — shared by start() and clawback()
  async function open() {
    if (started) throw new Error('an executor starts once')
    started = true
    const [st, rs, job0] = await Promise.all([journal.status(), relay.status(), journal.job(jobId)])
    const def: JobDef = job0.def
    assertNetworks(def.network === st.network && def.network === rs.network, `the job is on ${def.network}, the API on ${st.network}, the relay on ${rs.network}: a job never runs on another network`)
    assertNetworks(rs.identity?.[chain]?.ok === true, `the relay did not verify the ${chain} chain's identity for ${def.network}`)
    if (chain === 'btc' && def.network !== 'local') refuse('executor.chain-unsupported', `the btc lane runs on a local network only (this job is on ${def.network}): testnet4 and mainnet need Esplora reads, which do not exist yet`) // @guard:executor.chain-unsupported
    network = def.network
    const ch = def.chains[chain]
    const h = key.handle as { chain?: unknown; address?: unknown; account?: unknown; kp?: unknown } | null
    const keyOk = ch !== undefined && key.chain === chain && sameAddress(chain, key.address, ch.keyAddress) && h !== null && typeof h === 'object'
      && h.chain === chain && h.address === key.address && (chain === 'eth' ? h.account !== undefined : chain === 'btc' ? (h as { secret?: unknown }).secret !== undefined : h.kp !== undefined)
    assertKey(keyOk, `the loaded key is not this job's ${chain} key`)
    if (key.network !== network) show({ note: `this key's backup was made ${key.network === null ? 'before networks were recorded' : `on ${key.network}`}, not ${network}` })
    return { rs, job0, def, ch: ch!, h: h as Record<string, unknown> }
  }

  async function start(): Promise<RunOutcome> {
    const { rs, job0, def, ch, h } = await open()
    const net: Network = def.network
    // 2. settled with nothing open
    const done0 = outcomeOf(job0.state.chains[chain]!)
    if (done0 !== null && !PRE_ARM.has(job0.state.chains[chain]!.phase)) { show(settledView(job0.state.chains[chain]!)); return done0 }
    apiStop = job0.state.chains[chain]!.stopRequested === true       // a Stop requested before this run applies at once
    if (apiStop) stopFlag = true
    assertEndpointQuorum(net, chain, Number(rs.endpoints?.[chain] ?? 0))   // PF-S M-2: before any lease
    // 3. lease
    lease = createLease({ journal, jobId, chain, holder, clock, onTick: syncStop, onLost: (why) => show({ note: `lease lost: ${why} — no new transaction starts` }) })
    const grant = await lease.acquire()
    useRelayClient(relay)
    try {
      const text = await journal.message(def.messageSha256)
      const cfg = laneConfigOf(chain, ch, text)
      msSha = def.messageSha256
      cfgKey = sha256Hex(canonicalJson({ chain, cfg: { ...cfg, text: undefined }, network })).slice(0, 16)
      const chainId = chain === 'eth' ? Number(BigInt(await relay.rpc('eth', 'eth_chainId', []) as string)) : null
      const gasRule = chain === 'eth' ? { amsterdam: ethAmsterdam(net), toSelf: cfg.recipient === 'self' } : undefined
      // E7b: a copy whose commit was already journaled (landed, or open for the takeover) needs no new funding for its commit: the check
      // skips the coin plan (the reveal moves only what the commit locked)
      const btcCommitExists = (copy: number): boolean => chain === 'btc' && (state.chains.btc?.txs ?? []).some((g) => g.copy === copy && g.part === 1 && g.attempts.length > 0)
      const assess = (real: boolean, copy: number) => assessChain(engineChain, planLaneCopy(cfg, copy), {
        real, network: network!, address: key.address, ...(chain === 'sol' ? { kp: (h as { kp: never }).kp } : {}), ...(chain === 'btc' ? { btcKey: h as never, btcCommitExists: btcCommitExists(copy) } : {}), recipient: cfg.recipient as 'null' | 'self', gasRule,
        strategy: cfg.feeStrategy as 'passive' | 'economy' | 'prompt', priorityLamports: cfg.feeStrategy === 'prompt' ? CANON.SOL_PROMPT_LAMPORTS : 0, cuPriceCap: cfg.cuPriceCap as number, ...(cfg.maxFeeRateSatVb !== undefined ? { maxFeeRateSatVb: cfg.maxFeeRateSatVb } : {}),
        msSha, cfgKey, now: () => clock.now() }, relay)
      let state: JobState = job0.state
      const live = (): boolean => lease!.alive() && !leaseGone()   // a Stop is NOT an abort: the in-flight tx resolves first (R64)

      // 4. before arm: key-loaded, funds; then the arm
      if (state.chains[chain]!.phase === 'AWAITING_KEY') await ej.append({ type: 'key-loaded', chain, address: key.address })
      let affordable: boolean | null = null
      for (;;) {
        state = (await journal.job(jobId)).state
        if (state.armed !== null) break
        if (!lease.alive() || leaseGone()) return 'lease-lost'
        if (stopFlag) { show({ phase: 'stopped', note: 'stopped before the arm' }); return 'stopped' }
        const q = await assess(false, 1)
        const bal = chain === 'eth' ? await eth.balance(key.address) : chain === 'btc' ? await btcc.balanceOf(key.address) : await sol.solBalance(key.address)
        const cost = (q as { perCopy?: bigint }).perCopy ?? 0n, reserve = (q as { reserve?: bigint }).reserve ?? 0n
        const ok = bal >= cost + reserve
        if (ok !== affordable) { affordable = ok; await ej.append({ type: 'funds', chain, balance: String(bal), affordable: ok, nextCopyCost: String(cost + reserve) }) }
        show({ phase: ok ? 'ready' : 'awaiting funds', note: ok ? 'ready to arm' : `balance ${bal} < one copy ${cost + reserve} (base units)` })
        await clock.sleep(Math.max(poll, 1_000))
      }
      const cs1 = state.chains[chain]!
      if (cs1.phase === 'SKIPPED') { show({ phase: 'skipped', note: 'not armed' }); return 'stopped' }

      // 5. reconcile before any new intent
      let adopted: AdoptedEth | null = null
      const reconcileFrom = (st: JobState) => reconcileChain({ chain, state: st, grant, journal: ej, clock, poll, alive: () => lease!.alive(), stopRequested: () => stopFlag, detach: detachOnly, address: key.address, network: net, ...(chain === 'btc' ? { btcKey: h as never } : {}), ...(chain === 'eth' ? { ethAccount: h.account } : {}),
        solEndpoints: Math.max(1, rs.endpoints?.sol ?? 1), payloadOf: (c, pt) => planLaneCopy(cfg, c)[pt - 1]?.payload ?? null, to: chain === 'eth' ? eth.recipientAddress(cfg.recipient as string, key.address) : undefined, ...(deps.rounds !== undefined ? { rounds: deps.rounds } : {}) })
      if (needsReconcile(cs1, grant)) {
        show({ phase: 'reconciling', note: 'reconciling from the chain before anything else' })
        const r = await reconcileFrom(cs1 === state.chains[chain] ? state : (await journal.job(jobId)).state)
        if (!r.ok) { show({ phase: 'failed', note: r.why }); return lease.alive() && !leaseGone() ? 'failed' : 'lease-lost' }
        adopted = r.adopted
        state = (await journal.job(jobId)).state
      }
      let cs2 = state.chains[chain]!
      // R79 (c): the operator resumed this STOPPED chain — it is reopened (`resumed`; no executor can on its own: the gate refuses it while
      // latched) at the next part of the current copy. R79b (I-1): only after EVERY pre-start check passed (the reread of a landed part, the
      // check at the start, below): a check that fails journals nothing, so the chain stays STOPPED — never RUNNING with no run behind it.
      const reopen = reopens(cs2)
      const settled = outcomeOf(cs2)
      if (settled !== null) { show(settledView(cs2)); return settled }
      if (cs2.phase === 'CLAWING_BACK' || cs2.phase === 'STUCK') { show({ phase: cs2.phase.toLowerCase(), note: cs2.reason ?? '' }); return 'failed' }
      // PF-E fix round 2 (I-1): a settled chain with a job attempt still open is never a dead end: a watch-only run (no phase event, no new
      // signature) re-sends that attempt's identical bytes in bounded windows — it lands (settled), or STUCK with the exact reason (resolve,
      // then claw back or close), or it is still pending (run again later). The Stop that settled the chain is not a Stop of this run; a
      // requestStop() (Ctrl-C, the page's Stop) or a later stop request ends it at the end of its window.
      if (!reopen && WATCH_ONLY.has(cs2.phase) && cs2.openIntents.length > 0) {   // (a resumed STOPPED chain is reopened below, then runs)
        if (chain !== 'eth' || adopted === null) { show({ phase: 'failed', note: `${chain} is ${cs2.phase} with ${cs2.openIntents.length} open transaction(s) the reconcile did not settle — run again` }); return 'failed' }
        show({ phase: 'watching', copy: adopted.copy, part: adopted.part, note: `${chain} is ${cs2.phase.toLowerCase()} with copy ${adopted.copy} part ${adopted.part} still open: watching it (its same signed bytes only)` })
        const api0 = apiStop
        let said = ''
        // R79b (M-1): a detach (requestStop alone: Ctrl-C) journals nothing here either — no `stuck` at a window's end; the stop that
        // settled the chain (api0) is not a stop of this run, only a later stop request is
        const watchStop = (): boolean => localStop || (apiStop && !api0)
        const w = await watchAdoptedEth(cfg, h, { journal: ej, network, chainId, state, poll, alive: live, clock, ethEndpoints: Math.max(1, rs.endpoints?.eth ?? 1),
          stopRequested: watchStop, detachOnly: () => localStop && !(apiStop && !api0), resume: { copy: adopted.copy, nextPart: adopted.part, landed: {}, adopted },
          onTx: (t: { copy: number; part: number; parts: number; note?: string; reason?: string; pendingAtStop?: boolean; state?: string }) => {
            said = journalText(t.pendingAtStop === true || t.state === 'stuck' ? t.reason ?? '' : t.note ?? '', 400)
            show({ copy: t.copy, part: t.part, parts: t.parts, note: said })
          } })
        const cs3 = (await journal.job(jobId)).state.chains[chain]!
        show({ phase: cs3.phase.toLowerCase(), note: said || (cs3.reason ?? '') })
        if (leaseGone() || !lease.alive()) return 'lease-lost'
        if (w === 'confirmed') return outcomeOf(cs3) ?? 'stopped'
        return w === 'stopped' ? 'stopped' : 'failed'
      }
      // A part that landed but has no passing readback (the earlier holder died between included and readback, or its
      // readback could not be read then) is NEVER sent again: its bytes are read back from the chain now; when they do
      // not match (or the tx failed) the copy cannot complete and the run stops.
      let resume = resumeOf(cs2)
      for (let k = 0; resume !== null && k < 64; k++) {
        const r0 = resume
        const g = state.chains[chain]!.txs.find((t) => t.copy === r0.copy && t.part === r0.nextPart)
        if (g === undefined || g.state !== 'included' || g.readback === true) break
        const rb = await rereadLanded(g, planLaneCopy(cfg, g.copy)[g.part - 1]?.payload ?? null, cfg)
        if (!rb.ok) {
          const note = `copy ${g.copy} part ${g.part} landed but does not read back (${rb.detail}) — it is never sent again, so the copy cannot complete; claw back or close`
          // R79b (I-1) + final round (m-3): the chain ANSWERED (other bytes, status 0) — a verdict on a running chain (its holder died between
          // `included` and `readback`) and on a resumed STOPPED chain alike: the evidence is journaled (`readback` ok false, the journal FACT
          // stopClassOf reads) and then `stopped` with its FINAL code, so the chain settles (claw back or close) and a resume never stays
          // resumable for good. A chain that could not be read now is no verdict: nothing is journaled (a later run reads it again), unless
          // the operator's Stop is pending on a running chain — then that Stop is journaled (operator-stop: its resume re-reads the part)
          if (rb.definitive) {
            if (g.landedId !== null) await ej.append({ type: 'readback', chain, txId: g.landedId, ok: false, detail: journalText(`re-read: ${rb.detail}`) })
            await ej.append({ type: 'stopped', chain, reason: journalText(note), code: /status 0/.test(rb.detail) ? 'reverted' : 'readback-mismatch' })
            show({ phase: 'stopped', note })
            return 'failed'
          }
          if (!reopen) {
            await syncStop().catch(() => {})
            if (apiStop) { await ej.append({ type: 'stopped', chain, reason: journalText(`stopped by the operator; ${note.replace(/; claw back or close$/, '')}: it is read again at the resume`), code: 'operator-stop' }); show({ phase: 'stopped', note }); return 'stopped' }
          }
          // M5c (text): a resumed chain whose reread gave no verdict stays STOPPED with the resume standing — it is read again at the next run
          show({ phase: reopen ? 'stopped' : 'failed', note: `copy ${g.copy} part ${g.part} landed but cannot be read back now (${rb.detail}) — nothing journaled${reopen ? '; resumed, but the chain stays stopped and the resume still stands' : ''}; run the job again` })
          return 'failed'
        }
        await ej.append({ type: 'readback', chain, txId: g.landedId!, ok: true, detail: journalText(`re-read at the takeover: ${rb.detail}`) })
        state = (await journal.job(jobId)).state
        resume = resumeOf(state.chains[chain]!)
      }

      // 6. the start time, by the API's clock; the assess loop meanwhile. The simulation plans the resumed copy, never one
      // past the last copy of a copies job: a run that died after its last copy reassembled (before copies-done) resumes
      // past it, and the lane then only journals copies-done (E4 crash matrix).
      const simCopy = Math.min(resume?.copy ?? 1, cfg.mode === 'copies' ? (cfg.copies as number) : Number.MAX_SAFE_INTEGER)
      for (;;) {
        const j = await journal.job(jobId)
        if (!lease.alive() || leaseGone()) return 'lease-lost'
        const at = startAt(j.state.armed!, chain), left = at - j.serverNowMs
        last = await assess(true, simCopy)
        if (left <= 0) break
        if (stopFlag) {
          await syncStop().catch(() => {})
          if (detachOnly()) { show({ phase: 'detached', note: DETACHED }); return 'stopped' }   // R79 (a): nothing journaled
          if (apiStop) return await countdownStop()
          // m-b: the stop request was lifted before it was journaled (vt job resume, "Cancel the stop") — no stop: the countdown goes on.
          // If the API journaled a stop of this never-started chain meanwhile, the run ends here and the next run reopens it (`resumed`)
          if ((await journal.job(jobId)).state.chains[chain]?.phase === 'STOPPED') { show({ phase: 'stopped', note: 'the stop was cancelled after the API journaled it: run the job again to reopen it' }); return 'stopped' }
        }
        show({ phase: 'countdown', startsInMs: left, note: last.ok ? 'simulation ✓' : `simulation: ${last.reason}` })
        await clock.sleep(Math.min(1_000, left))
      }
      show({ startsInMs: 0 })
      // 7. the pre-start check
      const sc = await startCheck(engineChain, last, { msSha, cfgKey, network: net, relay, now: clock.now() })
      // E7 fix round 2: a btc chain with a journaled commit and no landed reveal is never journaled `stopped` (the shared gate refuses it): it ends `failed`
      const fresh = chain === 'btc' && !sc.ok ? (await journal.job(jobId)).state.chains.btc?.txs ?? [] : []
      const stranded = btcStrandedIn(fresh)                           // Eminors (E7-fix2 m-3): the one predicate (job/reduce.ts)
      if (!sc.ok && stranded) { show({ phase: 'failed', note: `${sc.why} — a commit is journaled without its reveal: the chain stays open; run again once the check passes` }); return 'failed' }
      // R79b (I-1): a resumed chain that fails the check is not reopened — nothing journaled, it stays STOPPED (run again once it passes)
      if (!sc.ok && reopen) { show({ phase: 'stopped', note: `resumed, but the check at its start failed: ${sc.why} — the chain stays stopped (nothing journaled) and the resume still stands; run it again once the check passes` }); return 'failed' }
      if (!sc.ok) { await ej.append({ type: 'stopped', chain, reason: journalText(sc.why), code: 'start-check' }); show({ phase: 'stopped', note: sc.why }); return 'failed' }
      // R79 (c) / R79b (I-1): every pre-start check passed — now the operator's resume reopens the chain (re-read: a Stop since keeps it stopped)
      if (reopen) {
        // final round (m-2, m-6): the last look before `resumed`. A detach (Ctrl-C, "Stop running here" during the checks) journals nothing —
        // the chain stays STOPPED with the resume standing. A stop requested since the resume is the operator's Stop: journaled
        // (operator-stop), it latches the chain again. A chain no longer to reopen otherwise (latched, final) is left as it is.
        await syncStop().catch(() => {})
        if (detachOnly()) { show({ phase: 'detached', note: `${DETACHED} (the chain stays stopped; the resume still stands)` }); return 'stopped' }
        const cur = (await journal.job(jobId)).state.chains[chain]!
        if (!reopens(cur)) {
          if (cur.phase === 'STOPPED' && cur.stopRequested === true && cur.stopLatched !== true) {
            await ej.append({ type: 'stopped', chain, reason: 'stopped by the operator before the resumed chain reopened', code: 'operator-stop' })
            show({ phase: 'stopped', note: 'stopped by the operator before it reopened' }); return 'stopped'
          }
          show({ phase: 'stopped', note: 'stopped again before it reopened: nothing journaled' }); return 'stopped'
        }
        await ej.append({ type: 'resumed', chain, reason: 'the operator resumed the job (vt job resume): it continues at the next part of the current copy' })
        state = (await journal.job(jobId)).state
      }

      // 8. the lane
      show({ phase: 'running', note: '' })
      const lane = newLaneState(cfg)
      const ld: Record<string, unknown> = {
        journal: ej, network, chainId, state, poll, alive: live, clock, reconciled: true, jobId, notify: (x?: unknown) => {
          void x
          const t = lane.txs.find((y: { state: string }) => !['confirmed', 'not-sent', 'planned'].includes(y.state))
          const wn = typeof lane.windowNote === 'string' ? lane.windowNote : ''                        // E6: "(window N blocks, RPC limit)" while the passive window is truncated
          if (t) show({ copy: t.copy, part: t.part, parts: t.parts, note: [journalText(t.note ?? '', 160), wn].filter((x2) => x2 !== '').join(' ') })
          else if (wn !== '') show({ note: wn })
        },
        // a lost lease is not a Stop (alive covers it: the lane aborts without journaling, E3 review m-4)
        // (a BTC copy is one in-flight unit for Stop: the lane's atomicCopy, lane.js)
        stopRequested: () => stopFlag, detachOnly, refreshStop: () => syncStop().catch(() => {}), takeResume: () => { const r = resumeFlag; resumeFlag = false; return r },
        getTipCapGwei: () => tipCap ?? cfg.tipCapGwei, solEndpoints: Math.max(1, rs.endpoints?.sol ?? 1), ethEndpoints: Math.max(1, rs.endpoints?.eth ?? 1),   // E5: every verified endpoint
        ...(network === 'local' ? {} : { torOk: async () => (await relay.tor().catch(() => ({ isTor: null }))).isTor === true }),
        ...(deps.passiveWaitMs !== undefined ? { passiveWaitMs: deps.passiveWaitMs } : {}),
        ...(resume !== null ? { resume: { ...resume, ...(adopted !== null ? { adopted } : {}) } } : {}),
      }
      if (cuCap !== null) (cfg as { cuPriceCap: number }).cuPriceCap = cuCap
      const engineKey = h
      let r: string
      try { r = cfg.mode === 'copies' ? await runCopiesLane(cfg, engineKey, lane, ld) : await runDrainLane(cfg, engineKey, lane, ld) } catch (e) {
        // fix round 1 (I-1): engine.eip7702 — the lane started no new send (the refusal stands). The chain ENDS cleanly so
        // it settles and can be clawed back (C2): FIRST every open intent is reconciled from the chain (read-only
        // lookups, never skipped, nothing resent), THEN `stopped` is journaled with the delegation reason.
        if (!(isRefusal(e) && e.guardId === 'engine.eip7702') || leaseGone() || !lease.alive()) throw e
        show({ delegated: true })
        show({ phase: 'reconciling', note: 'an EIP-7702 delegation: reconciling every open intent, then the chain stops — nothing new is signed' })
        const rr = await reconcileFrom((await journal.job(jobId)).state)
        // planE5 m-7: a reconcile that did not finish (an open attempt still unresolved, or stopped while watching it) leaves
        // the chain exactly as the journal has it — nothing new is signed, no `stopped` is written — and says so
        if (!rr.ok) { show({ phase: 'failed', note: journalText(`${rr.why} — the EIP-7702 delegation stands and nothing new was signed; the chain is not settled until its open attempt resolves: run it again`) }); return lease.alive() && !leaseGone() ? 'failed' : 'lease-lost' }
        const why = journalText(`engine.eip7702: ${e.message} — the chain stops; nothing new is signed (claw back the remainder)`)
        await ej.append({ type: 'stopped', chain, reason: why, delegated: true, code: 'eip7702' })   // Eminors: structured, beside the text; R79b: FINAL
        show({ phase: 'stopped', note: why })
        return 'stopped'
      }
      show({ phase: r, note: r === 'detached' ? DETACHED : lane.reason ?? '' })
      if ((leaseGone() || !lease.alive()) && r !== 'drained' && r !== 'copies-done') return 'lease-lost'
      return r === 'drained' || r === 'copies-done' || r === 'stopped' ? r : r === 'detached' ? 'stopped' : 'failed'
    } catch (e) {
      if (leaseGone()) { show({ phase: 'lease lost', note: lease?.lost() ?? `${leaseRefused}: the lease is gone — no new transaction starts` }); return 'lease-lost' }
      if (stopRefused && lease !== null && lease.alive()) {           // a Stop raced the next intent: nothing new was signed
        try {
          // PF-E fix round 2 (M-3): `stopped` is journaled only when nothing of the chain is in flight. A refused bump leaves the attempt it
          // would have replaced open: the run ends without `stopped`, so the next run takes the Stop path (that attempt's same bytes for one
          // window: it lands, `stopped` with it pending, or STUCK) — never a settled chain with an attempt it cannot see to the end.
          const open = (await journal.job(jobId)).state.chains[chain]?.openIntents ?? []
          if (open.length > 0) { show({ phase: 'stopped', note: `stopped by the operator: the API refused a new signature after the Stop; ${open.length} transaction(s) stay open — run the job again: it watches them to the end of one window, nothing new is signed` }); return 'stopped' }
          await ej.append({ type: 'stopped', chain, reason: 'stopped by the operator: the API refused the next intent after the Stop (nothing was in flight)', code: 'operator-stop' })
          show({ phase: 'stopped', note: 'stopped by the operator' }); return 'stopped'
        } catch { /* fall through: failed */ }
      }
      if (e instanceof JournalError || isRefusal(e) || e instanceof JournalUnreachable) { show({ phase: 'failed', note: short(e) }); return 'failed' }
      throw e
    } finally {
      await lease?.release()
    }
  }

  // The claw-back (`vt job clawback`, the page's claw-back dialog): the same network and key checks, the lease, the
  // reconcile of every open intent first, then the engine's claw-back at the lane's fee strategy with the operator's
  // typed exact amount when value + fee exceeds what is left of the armed cap (deps.clawbackConfirm, CC-2a).
  async function clawback(to: string): Promise<RunOutcome> {
    // Eminors (E7b m-7): there is no BTC claw-back in this build — say so before any lease or reconcile (the lane's funds stay put; nothing is signed)
    if (chain === 'btc') {
      show({ phase: 'failed', note: 'there is no claw-back for a bitcoin lane yet: the lane key and its funds are untouched; nothing was signed' })
      refuse('engine.btc-clawback', 'there is no claw-back for a bitcoin lane yet: the lane key and its funds are untouched; nothing was signed') // @guard:engine.btc-clawback
    }
    const { rs, job0, ch, h } = await open()
    const cs0 = job0.state.chains[chain]!
    if (cs0.phase === 'CLAWED_BACK' && cs0.openIntents.length === 0) return 'clawed-back'
    // PF-E fix 1: the Stop that settled the chain (still stop-requested at the API) is not a Stop of this claw-back — only a later
    // stop request (or requestStop) is (the lease tick's syncStop would otherwise cancel every claw-back of an operator-stopped chain)
    apiStop = cs0.stopRequested === true
    lease = createLease({ journal, jobId, chain, holder, clock, onTick: syncStop, onLost: (why) => show({ note: `lease lost: ${why}` }) })
    const grant = await lease.acquire()
    useRelayClient(relay)
    try {
      let state = (await journal.job(jobId)).state
      const cs1 = state.chains[chain]!
      if (needsReconcile(cs1, grant)) {
        show({ phase: 'reconciling', note: 'reconciling from the chain before the claw-back' })
        const text = await journal.message(job0.def.messageSha256)
        const cfg = laneConfigOf(chain, ch, text)
        const r = await reconcileChain({ chain, state, grant, journal: ej, clock, poll, alive: () => lease!.alive(), stopRequested: () => stopFlag, address: key.address, network: network!, ...(chain === 'eth' ? { ethAccount: h.account } : {}),
          solEndpoints: Math.max(1, rs.endpoints?.sol ?? 1), payloadOf: (c, pt) => planLaneCopy(cfg, c)[pt - 1]?.payload ?? null, to: chain === 'eth' ? eth.recipientAddress(cfg.recipient as string, key.address) : undefined, ...(deps.rounds !== undefined ? { rounds: deps.rounds } : {}) })
        if (!r.ok) { show({ phase: 'failed', note: r.why }); return leaseGone() ? 'lease-lost' : 'failed' }
        state = (await journal.job(jobId)).state
      }
      const cs2 = state.chains[chain]!
      if (cs2.phase === 'CLAWED_BACK') return 'clawed-back'
      show({ phase: 'clawing back', note: '' })
      const chainId = chain === 'eth' ? Number(BigInt(await relay.rpc('eth', 'eth_chainId', []) as string)) : null
      const d = { journal: ej, network, chainId, state, poll, clock, alive: () => lease!.alive() && !leaseGone(), stopRequested: () => stopFlag, feeStrategy: ch.feeStrategy,
        getTipCapGwei: () => tipCap ?? (ch.maxTipGwei !== undefined ? String(ch.maxTipGwei) : undefined), solEndpoints: Math.max(1, rs.endpoints?.sol ?? 1), ethEndpoints: Math.max(1, rs.endpoints?.eth ?? 1),
        delegated: (w: string) => show({ delegated: true, note: journalText(w, 160) }),                   // Efix3: planE5 ruling C2
        windowNote: (w: string) => show({ note: [view.delegated === true ? DELEGATED_CLAWBACK_WARNING : '', w].filter((x) => x !== '').join(' ') }),   // Efix3: the passive claw-back's truncated window
        ...(deps.clawbackConfirm !== undefined ? { clawbackConfirm: deps.clawbackConfirm } : {}), ...(deps.passiveWaitMs !== undefined ? { passiveWaitMs: deps.passiveWaitMs } : {}) }
      const res = chain === 'eth' ? await clawbackEth(h, to, d) : await clawbackSol(h, to, d)
      const landedNote = res.ok ? 'the destination received the remainder ✓' : 'landed; the readback differs from the plan'
      show({ phase: 'clawed back', note: [res.delegated === true ? DELEGATED_CLAWBACK_WARNING : '', landedNote].filter((x) => x !== '').join(' · '), delegated: res.delegated === true })
      return 'clawed-back'
    } catch (e) {
      if (leaseGone()) return 'lease-lost'
      show({ phase: 'failed', note: short(e) })
      return 'failed'
    } finally {
      await lease?.release()
    }
  }

  return {
    start,
    clawback,
    requestStop() { stopFlag = true; localStop = true },
    requestResume(o) { resumeFlag = true; stopFlag = false; localStop = false; if (o?.tipCapGwei !== undefined) tipCap = o.tipCapGwei; if (o?.cuPriceCap !== undefined) cuCap = o.cuPriceCap },
    async skip() {
      const ts = await relay.tor().catch(() => null)
      const tg = torGate(ts, network ?? 'mainnet')
      const fresh = last !== null && last.ok === true && isFresh(last, msSha, cfgKey, clock.now())
      const ok = network !== null && tg.ok && fresh
      if (!ok) refuse('executor.skip', !tg.ok ? `Skip needs Tor: ${tg.why}` : 'Skip needs a fresh passing simulation (the last one is stale or failed)') // @guard:executor.skip
      await journal.skip(jobId)
    },
    view: () => ({ ...view }),
  }
}

// @ts-check
// PORTED (R69) from the prototype, tag add7-00927d6ade7f, src/mainnet/lane.js (sha256 053bcfabc3dbffb7d4e4babe95e173da8425fa403b42b41719db66acd0df3739).
// R64 lane runner — "Until drained" (default) | Copies N. DOM-free core (addition 8 will drive it from a Node CLI too):
//   • a lane is configured by ONE plain serializable object (validateLaneConfig) — never key material;
//   • the runner is a function of that object + the in-memory key + injected deps (relay client via rpc.js configureRelay,
//     journal, clock {now, sleep}, notify, torOk, stop/resume flags, live tip cap);
//   • every transition is a discrete event through deps.journal (copy-built, intent [hash/signature journaled and acked
//     BEFORE the broadcast], sent, replaced, included, readback, paused, resumed, drained, stopped, clawback-*).
// One tx in flight per lane, strictly sequential; Stop takes effect after the in-flight tx resolves.
//
// Canonical changes (E2; spec §7.2, R72, R73/PM):
//   · deps.journal replaces the prototype's onEvent sink (engine.js: append awaited, intent awaited before every send, JournalError
//     stops the lane). Events are flat { type, chain, ...data } in the contract's shapes (job/events.ts): copy-built
//     level is a number (SOL rung, ETH 0); `drained` always carries {balance, nextCost, copy}; the adapters' MQ-only
//     `reconcile {reason}` waits are journaled as `note {text}`.
//   · deps.resume = { copy, nextPart, landed? } (R72): the run starts at that copy and builds only parts ≥ nextPart of
//     it (parts 1..nextPart−1 are never built, never sent). landed (part → txId of the landed parts) lets the copy be
//     reassembled afterwards.
//   · R72 parts: one text, one digest; the copy marker is in the header (copy = i when distinct, copies = N in copies
//     mode, null in drain mode). After a copy's last part the copy is REASSEMBLED from the chain bytes (by index,
//     headers stripped, sha256 checked) and `reassembled {copy, ok, sha256}` is journaled; a failure stops the lane.
//   · runCopiesLane = the same controller with a copy limit (`copies-done {copies}` after copy N).
//   · Fee strategies (lane config feeStrategy; default passive for drain, economy for copies, as contracts/publish.ts):
//     ETH passive (target T = p10 of the trailing 24 h base fees, tip 0.001 gwei, maxFee T + tip, wait, never escalate),
//     economy (the R64 ladder), prompt (the classic p50 fees + bumps); SOL passive (no priority, ever), economy (rungs in
//     lamports per tx, PM finding 4), prompt (the p90 lamports rung, ×2 per proven expiry).
//   · Gas: the exact fork- and recipient-aware formula of deps.network (contracts ethAmsterdam).
//   · The R60 cap: a CapLedger (gates/caps.ts) built ONLY from the armed job state (deps.state: the reduced journal —
//     armed cap, spend so far, open intents), one per key per process; the lane config has no cap field. Checked
//     before every copy (engine.cap-copy), every signature (engine.cap) and every claw-back (engine.cap-clawback).
//   · Claw-back: journaled like the lane (clawback-intent awaited for its ticket); ETH gas sized by destination class
//     and checked against eth_estimateGas (fail closed).
//   · Endpoint agreement (E5, gates/agree.ts): the nonce an ETH lane starts from and a claw-back signs at is read from
//     every verified endpoint (deps.ethEndpoints) — they must agree (engine.nonce-disagree: the lane pauses, the
//     claw-back is refused) — and a lane never starts from an account with code: endpoints that disagree about the
//     code pause it (engine.code-disagree); an agreed EIP-7702 delegation refuses engine.eip7702 (the run ends the
//     chain `stopped`, executor.ts). Every SOL send and rebroadcast goes to every verified endpoint with the same ticket (engine.js postSol).
import { hexToBytes, toHex } from 'viem'
import { base58, base64 } from '@scure/base'
import { CANON, ECON, ETH, LANE, SOL, networkOf } from '../chains/constants.js'
import { checkText } from '../chains/text.js'
import { ethParts, formatUnits, parseDecimal, reassembleCopy, replacementFees, solFee, solParts, tipCapOk, utf8 } from '../chains/plan.js'
import { ethClawGas, ethCopyCost, ethDrainDecision, ethEconomyBump, ethEconomyInitial, ethPassiveBump, ethPassiveDecision, ethPassiveInitial, ethPassiveTarget, ethStartTip, solClawback, solDrainDecision, solNextRung, solStartRung, validateEthDest, validateSolDest } from '../chains/economy.js'
import { ethReservedKind, solReservedKind } from '../chains/reserved.js'
import { ethRpc } from './rpc.js'
import * as eth from '../chains/eth.js'
import * as sol from '../chains/sol.js'
import * as btcc from '../chains/btc.js'
import { btcTx } from './btc-tx.js'
import { btcReconcileGroup } from './btc-reconcile.js'
import { JournalError, ethRebuild, ethTx, jappend, jintent, journalOutcome, journalText, nowOf, post, postSol, solTx, ticketFor, _solWait } from './engine.js'
import { ethAmsterdam, estimateMatches, FEE_STRATEGIES, isRefusal } from '../contracts/index.ts'
import { CapLedger, ledgerOf } from '../gates/caps.ts'
import { assertCodeAgreement, assertNoDelegation, assertNonceAgreement, DELEGATED_CLAWBACK_WARNING, isDelegationCode } from '../gates/agree.ts'
import { sha256Hex } from '../job/canonical.ts'
import { btcStrandedIn } from '../job/reduce.ts'

// ---------- the lane configuration object ----------
// No spend-cap field (the MQ `capBase` is gone): the cap comes only from the armed job state (gates/caps.ts CapLedger).
export const LANE_DEFAULTS = { mode: LANE.MODE_DEFAULT, copies: 1, recipient: ETH.RECIPIENT_DEFAULT, distinct: true, tipCapGwei: ECON.ETH_TIP_CAP_DEFAULT, cuPriceCap: ECON.SOL_RUNG_CAP, startCopy: 1, feeStrategy: null }
const ALLOWED = new Set(['chain', 'mode', 'copies', 'text', 'recipient', 'distinct', 'tipCapGwei', 'cuPriceCap', 'startCopy', 'clawbackTo', 'label', 'feeStrategy', 'maxFeeRateSatVb'])
/** @typedef {any} Lane @typedef {any} Deps @typedef {any} Adapter @typedef {any} Cfg */
/** @param {any} input */
export function validateLaneConfig(input) {
  /** @type {string[]} */
  const errors = []; const cfg = { ...LANE_DEFAULTS, ...input }
  for (const k of Object.keys(input || {})) if (!ALLOWED.has(k)) errors.push(`unknown field "${k}" (key material is never part of a lane config)`)
  if (!['eth', 'sol', 'btc'].includes(cfg.chain)) errors.push('chain must be "eth", "sol" or "btc"')
  if (!LANE.MODES.includes(cfg.mode)) errors.push(`mode must be one of ${LANE.MODES.join(', ')}`)
  if (cfg.chain === 'btc' && cfg.mode !== 'copies') errors.push('btc runs in copies mode only (no drain for BTC in M4)')
  if (cfg.mode === 'copies' && !(Number.isInteger(cfg.copies) && cfg.copies >= 1)) errors.push('copies must be an integer ≥ 1')
  if (typeof cfg.text !== 'string') errors.push('text must be a string')
  else { const c = checkText(cfg.text); if (!c.ok) errors.push(`text: ${c.issues.join('; ')}`) }
  if (cfg.chain === 'eth' && !['null', 'self'].includes(cfg.recipient)) errors.push('recipient must be "null" or "self"')
  if (typeof cfg.distinct !== 'boolean') errors.push('distinct must be a boolean')
  try { if (!tipCapOk(parseDecimal(String(cfg.tipCapGwei), 9))) errors.push('tipCapGwei must be ≥ 0.1') } catch { errors.push('tipCapGwei must be a decimal gwei amount') }
  if (!(Number.isInteger(cfg.cuPriceCap) && cfg.cuPriceCap >= 0 && cfg.cuPriceCap <= ECON.SOL_RUNG_CAP)) errors.push(`cuPriceCap must be an integer 0…${ECON.SOL_RUNG_CAP}`)
  if (!(Number.isInteger(cfg.startCopy) && cfg.startCopy >= 1)) errors.push('startCopy must be an integer ≥ 1')
  if (cfg.maxFeeRateSatVb != null && !(cfg.chain === 'btc' && Number.isSafeInteger(cfg.maxFeeRateSatVb) && cfg.maxFeeRateSatVb >= 1 && cfg.maxFeeRateSatVb <= 500)) errors.push('maxFeeRateSatVb is a btc field: an integer 1..500 (sat/vB)')
  if (cfg.chain === 'btc' && cfg.clawbackTo != null && cfg.clawbackTo !== '') errors.push('clawbackTo: there is no BTC claw-back in M4')
  else if (cfg.clawbackTo != null && cfg.clawbackTo !== '') { const v = cfg.chain === 'eth' ? validateEthDest(cfg.clawbackTo) : validateSolDest(cfg.clawbackTo); if (!v.ok) errors.push(`clawbackTo: ${v.why}`) }
  cfg.feeStrategy ??= cfg.mode === 'copies' ? 'economy' : 'passive'               // contracts defaultFeeStrategy
  if (!FEE_STRATEGIES.includes(cfg.feeStrategy)) errors.push(`feeStrategy must be one of ${FEE_STRATEGIES.join(', ')}`)
  try { JSON.stringify(cfg) } catch { errors.push('the config must be JSON-serializable') }
  return { ok: errors.length === 0, errors, cfg }
}
/** @type {(cfg: Cfg) => Lane} */
export const newLaneState = (cfg) => ({ chain: cfg.chain, mode: cfg.mode, state: 'armed', reason: '', copies: [], txs: [], inFlight: 0, spent: 0n, balance: null, nextCost: null, nextCopy: cfg.startCopy, log: [], claw: null })

// ---------- the generic drain controller (unit-tested with a fake adapter) ----------
// A = { reconcile?, planCopy(i), startLevel(), balance(), decide(parts, lvl, bal) → {send, tight, cost, spend}, sendTx(t, ctx), learn(t),
//       reassemble?(copy, txs) → {ok, sha256, why} | null }
// d.copiesLimit (copies mode): after copy N the lane ends `copies-done`. d.resume: see the header.
/** @param {Lane} lane @param {Adapter} A @param {Deps} d @returns {Promise<string>} */
export async function runDrain(lane, A, d) {
  const sleep = sleepOf(d), now = d.clock ? () => d.clock.now() : d.now || Date.now
  const emit = async (/** @type {any} */ e) => { const ev = { chain: lane.chain, ...e }
    if (ev.type === 'paused') { lane.state = 'paused'; lane.reason = ev.reason } else if (ev.type === 'resumed') { lane.state = 'waiting'; lane.reason = '' }
    lane.log.push({ ...ev, at: now() }); if (lane.log.length > 500) lane.log.shift()
    await jappend(d, ev); d.notify?.() }
  // R79b: every journaled `stopped` carries its machine code (contracts/stop.ts; a stop without one would be FINAL: integrity, fail closed)
  const end = async (/** @type {string} */ state, /** @type {string} */ reason, type = state, /** @type {string} */ code = 'integrity') => { lane.state = state; lane.reason = reason; await emit({ type, reason: journalText(reason), ...(type === 'stopped' ? { code, ...(code === 'eip7702' ? { delegated: true } : {}) } : {}) }); return state }   // final round (m-4): an EIP-7702 stop carries its fact (delegated) too
  const ledger = ledgerOf(d)                                                // the armed spend cap (engine.cap-ledger)
  const resume = d.resume ?? null
  if (resume !== null && !(Number.isSafeInteger(resume.copy) && resume.copy >= 1 && Number.isSafeInteger(resume.nextPart) && resume.nextPart >= 1)) throw new Error('invariant violated: resume must be { copy ≥ 1, nextPart ≥ 1 }')
  if (resume !== null) lane.nextCopy = resume.copy
  lane.state = 'running'; lane.reason = ''
  // E3 review m-4: a lost lease (d.alive false) is not a Stop — nothing is journaled (a `stopped` would end the chain for
  // good, and the next holder could not continue it); the lane returns 'aborted' and the next holder reconciles.
  const aborted = () => { lane.state = 'aborted'; lane.reason = 'the lease is lost — nothing more is signed; the next holder reconciles'; d.notify?.(); return 'aborted' }
  const gone = () => !!d.alive && !d.alive()
  // E3 review I-1 (R64, the API rule, prototype add7b lane.js:135): Stop takes effect once the in-flight tx resolved —
  // between parts as between copies. d.refreshStop (the executor) re-reads the API's stop state before each new intent.
  const stopNow = async () => { await d.refreshStop?.(); return !!d.stopRequested?.() }
  // R79 (PF-E fix round 3): a stop the operator asked for ends here. The API's stop request (`vt job stop`, the page's job Stop) is
  // journaled `stopped` — it latches the chain until the operator's resume. A DETACH (d.detachOnly: requestStop() alone — Ctrl-C in
  // `vt job run`, the page's "Stop running here", a closed tab) journals nothing final: no phase event, the chain stays as it is and
  // the next executor (a takeover) reconciles and continues it. The engine's own stops (a cap, a readback or reassembly mismatch,
  // a failure) are journaled whatever the operator asked.
  // m-b (M5d review): the callers act on the stop flag as last synced (up to one lease tick old). When the re-read shows that the operator's
  // stop request was LIFTED meanwhile (vt job resume, the page's "Cancel the stop"), it is no stop: nothing is journaled (an operator-stop
  // without a held request is FINAL at the API) and opStop returns null — the caller goes on from where it is, nothing new is signed here,
  // the lane's next normal step decides. Only with the API's stop state behind the flag (d.refreshStop); the engine's own codes (eip7702,
  // rpc-unavailable from the reconcile) are journaled whatever the request.
  const opStop = async (/** @type {string} */ reason, code = 'operator-stop') => {
    await d.refreshStop?.()
    if (d.detachOnly?.() === true) { lane.state = 'detached'; lane.reason = `detached: ${reason} — nothing final is journaled; the job keeps running: run it again (vt job run, Run here) to continue`; d.notify?.(); return 'detached' }
    if (code === 'operator-stop' && d.refreshStop !== undefined && d.stopRequested?.() !== true) { lane.state = 'running'; lane.reason = ''; d.notify?.(); return null }   // m-b: cancelled
    return end('stopped', reason, 'stopped', code)
  }
  if (A.reconcile) {
    for (;;) {
      const r = await A.reconcile(lane, emit)
      if (r === 'aborted') return aborted()                             // planE5 m-4: a lost lease in the reconcile ends the run here, never with nonce = null
      if (r === 'stopped' || r?.stopped) {
        const s = await opStop(r?.stopped ?? 'stopped during reconcile', r?.code ?? 'operator-stop')
        if (s !== null) return s
        continue                                                       // m-b: the stop was cancelled — reconcile again (it is read-only)
      }
      break
    }
  }
  for (let i = lane.nextCopy ?? 1; ; i++) {
    if (gone()) return aborted()
    if (d.copiesLimit != null && i > d.copiesLimit) { lane.state = 'copies-done'; lane.reason = ''; await emit({ type: 'copies-done', copies: d.copiesLimit }); return 'copies-done' }
    // an attempt adopted at a takeover is in flight in the resumed copy: it resolves (bumps allowed) before a Stop applies
    // E7 fix round 1 (I-2): an adapter with atomicCopy (btc) has a copy as ONE in-flight unit for Stop: a resumed copy past its first part is
    // not stopped at its start either (its earlier part locked funds only the later part can spend)
    const adoptedHere = resume !== null && i === resume.copy && (resume.adopted != null || (A.atomicCopy === true && (resume.nextPart > 1 || A.copyInFlight?.(i) === true)))
    if (!adoptedHere && await stopNow()) { const s = await opStop('stopped by the operator'); if (s !== null) return s }   // m-b: null = cancelled, go on
    let torPaused = false
    while (d.torOk && !(await d.torOk())) {                            // relay not isTor → pause (fail closed), resume when it is
      if (!torPaused) { torPaused = true; await emit({ type: 'paused', reason: 'relay is not on Tor (IsTor ✗)' }) }
      if (d.stopRequested?.()) { const s = await opStop('stopped while paused (Tor)'); if (s !== null) return s }
      await sleep(5000)
    }
    if (torPaused) await emit({ type: 'resumed', reason: 'Tor ✓ again' })
    // R72 resume: in the resumed copy, parts before nextPart landed already — they are never built or sent again
    const from = resume !== null && i === resume.copy ? resume.nextPart : 1
    // planning reads (fee level, balance, cost) happen BEFORE anything is signed for copy i, so a transient relay/RPC
    // error here is retried (pause → resume) instead of ending the lane; RETRY_MAX consecutive errors end it (failed)
    /** @type {any} */ let parts, /** @type {any} */ todo, /** @type {any} */ lvl, /** @type {any} */ bal, /** @type {any} */ dec, rpcPaused = false
    for (let errs = 0; ; errs++) {
      try { parts = A.planCopy(i); todo = parts.filter((/** @type {any} */ p) => p.i >= from)
        // E7 fix round 2: a copy whose commit is journaled (open or landed) is finished BEFORE anything else — it needs no fee level, no balance and
        // no funding decision, so a flaky node can never end the planning loop (and the chain) over a stranded commit
        if (A.copyInFlight?.(i) === true) { lvl = { level: 0, label: 'finishing the copy' }; bal = lane.balance ?? 0n; dec = { send: true, cost: 0n, spend: 0n }; break }
        lvl = await A.startLevel(); bal = await A.balance(); dec = todo.length ? await A.decide(todo, lvl, bal) : { send: true, cost: 0n, spend: 0n }; break } catch (/** @type {any} */ e) {
        if (/fail closed|invariant/.test(e?.message || '') || e?.name === 'Refusal' || e?.name === 'JournalError') throw e
        if (errs + 1 >= (d.retryMax ?? 60)) return end('failed', `RPC unavailable while planning copy ${i} (${errs + 1} consecutive errors): ${String(e?.message || e).slice(0, 120)}`, 'stopped', 'rpc-unavailable')
        if (!rpcPaused) rpcPaused = true, await emit({ type: 'paused', reason: journalText(`RPC error while planning copy ${i} — retrying every ${(d.retryMs ?? 5000) / 1000} s (${String(e?.message || e).slice(0, 80)})`) })
        if (d.stopRequested?.()) { const s = await opStop('stopped while retrying'); if (s !== null) return s }
        await sleep(d.retryMs ?? 5000)
      }
    }
    if (rpcPaused) await emit({ type: 'resumed', reason: 'RPC reachable again' })
    lane.balance = bal
    lane.nextCost = dec.cost; lane.level = lvl.label ?? null
    if (!dec.send) { lane.state = 'drained'; lane.reason = `balance ${bal} < next full copy ${dec.cost} (${A.unit || 'base units'})`; await emit({ type: 'drained', balance: String(bal), nextCost: String(dec.cost), copy: i }); return 'drained' }
    try { ledger.check(dec.spend) } catch (e) { if (/** @type {any} */ (e)?.guardId !== 'engine.cap-copy') throw e; return end('stopped', /** @type {Error} */ (e).message, 'stopped', 'spend-cap') }
    /** @type {any} */
    const copy = { i, txs: todo.map((/** @type {any} */ p, /** @type {number} */ j) => ({ k: lane.txs.length + j, copy: i, part: p.i, parts: p.n, payload: p.payload, textBytes: p.chunk.length, state: 'planned' })), tight: !!dec.tight, startedAt: now(), from }
    if (A.adopt && resume !== null && i === resume.copy) for (const t of copy.txs) await A.adopt(t)   // E3: an attempt adopted at a takeover keeps its nonce (PF-E: and its rebuilt bytes)
    lane.copies.push(copy); lane.txs.push(...copy.txs)
    await emit({ type: 'copy-built', copy: i, parts: parts.length, bytes: parts.map((/** @type {any} */ p) => p.payload.length), tight: !!dec.tight, level: Number.isSafeInteger(lvl.level) ? lvl.level : 0 })
    for (const t of copy.txs) {
      if (t !== copy.txs[0]) {                                         // a new part: the previous one resolved
        if (gone()) return aborted()
        if (!A.atomicCopy && await stopNow()) { const s = await opStop(`stopped by the operator after copy ${i} part ${t.part - 1} (the in-flight tx resolved first; part ${t.part} not signed)`); if (s !== null) return s }
      }
      let r
      for (;;) {
        if (lane.inFlight !== 0) throw new Error('invariant violated: a second tx would be in flight')
        lane.inFlight = 1; lane.state = 'waiting'; d.notify?.()
        try { r = await A.sendTx(t, { lvl, tight: !!dec.tight }) } finally { lane.inFlight = 0 }
        if (r !== 'stopped') break
        const s = await opStop(t.pendingAtStop === true ? `stopped by the operator (${t.reason})` : `stopped by the operator (copy ${i} part ${t.part} not sent)`)   // PF-E: a Passive Stop at a window's end, its attempt pending
        if (s !== null) return s
        delete t.pendingAtStop                                         // m-b: the stop was cancelled — this part goes on (its open attempt, or its first signature)
      }
      if (r === 'confirmed') {
        if (!t.readback?.ok) return end('stopped', `readback mismatch on copy ${i} part ${t.part} — lane stopped (fail closed)`, 'stopped', 'readback-mismatch')
        if (!ledger.landed(t)) return end('failed', `copy ${i} part ${t.part} confirmed without a journaled inclusion — lane stopped (fail closed: the cap counts only journaled spend)`, 'stopped', 'integrity')
        lane.spent += t.actual ?? 0n; A.learn(t); lane.state = 'running'
      } else if (r === 'unaffordable') { lane.state = 'drained'; lane.reason = `balance below the next tx (copy ${i} part ${t.part}${t.reason ? `: ${t.reason}` : ''})`; await emit({ type: 'drained', balance: String(bal < 0n ? 0n : bal), nextCost: String(t.reserved ?? dec.cost), copy: i }); return 'drained' }
      else if (r === 'aborted') return aborted()
      else return end('failed', `${r}: ${t.reason || ''}`, 'stopped', failCodeOf(r, t))
    }
    // R72: reassemble the copy from chain bytes and check its digest (a resumed copy needs the earlier parts' tx ids)
    if (A.reassemble) {
      const ra = await A.reassemble(i, copy.txs, from > 1 ? resume?.landed ?? null : null)
      if (ra === null) await emit({ type: 'note', text: `copy ${i}: not reassembled (the tx ids of parts before ${from} are unknown here)` })
      else {
        await emit({ type: 'reassembled', copy: i, ok: ra.ok, sha256: ra.sha256 ?? A.sha256 })
        if (!ra.ok) return end('stopped', `copy ${i} did not reassemble from the chain (${ra.why}) — lane stopped (fail closed)`, 'stopped', 'reassembly-mismatch')
      }
    }
    copy.doneAt = now(); lane.nextCopy = i + 1
  }
}

// R79b: the stop code of a part's transaction that did not end confirmed / unaffordable / stopped / aborted (contracts/stop.ts): a landed
// tx that failed on the chain (ETH status 0, a SOL tx that landed with an error) is `reverted`; any other failure `tx-failed`; a stuck
// attempt `stuck`; exhausted fees, balance or cap `exhausted`; anything else `integrity`. All FINAL.
/** @param {string} r @param {any} t @returns {string} */
export function failCodeOf(r, t) {
  if (r === 'failed') return t?.landedId ? 'reverted' : 'tx-failed'
  return r === 'stuck' ? 'stuck' : r === 'exhausted' ? 'exhausted' : 'integrity'
}

// ---------- chain adapters ----------
const tipCapWei = (/** @type {Deps} */ d, /** @type {Cfg} */ cfg) => { try { return parseDecimal(String(d.getTipCapGwei?.() ?? cfg.tipCapGwei), 9) } catch { return parseDecimal(String(cfg.tipCapGwei), 9) } }
// the network's fork (contracts/network.ts; a local Amsterdam anvil may set deps.amsterdamOverride) and the recipient
const gasRuleOf = (/** @type {Cfg} */ cfg, /** @type {Deps} */ d) => ({ amsterdam: ethAmsterdam(d.network, d.amsterdamOverride === undefined ? {} : { localOverride: d.amsterdamOverride }), toSelf: cfg.recipient === 'self' })
// R72: copy i's parts carry the copy marker when copies are distinct (M = N in copies mode, unknown in drain mode)
const partOpts = (/** @type {Cfg} */ cfg, /** @type {string} */ sha, /** @type {number} */ i) => ({ sha256: sha, copy: cfg.distinct ? i : null, copies: cfg.distinct && cfg.mode === 'copies' ? cfg.copies : null })
// The planned parts of copy i of this lane (the executor's reconcile reads back landed parts against them).
/** @param {Cfg} cfg @param {number} i */
export function planLaneCopy(cfg, i) {
  const bytes = utf8(cfg.text), sha = sha256Hex(bytes)
  if (cfg.chain === 'btc') return btcc.planBtcCopy(bytes, partOpts(cfg, sha, i))   // E7: part 1 = the commit, part 2 = the reveal, one body
  return cfg.chain === 'eth' ? ethParts(bytes, partOpts(cfg, sha, i)) : solParts(bytes, sol.layoutMaxMemo(), partOpts(cfg, sha, i))
}
// the clock seam (E3 ruling 5): d.clock { now, sleep } first (the executor's adapter clock), then the ported d.sleep
const sleepOf = (/** @type {Deps} */ d) => (d.clock ? (/** @type {number} */ ms) => d.clock.sleep(ms) : d.sleep || ((/** @type {number} */ ms) => new Promise((r) => setTimeout(r, ms))))
/** The progress text of a passive window the RPC cut short (E6): the adapter label, lane.windowNote and the page / `vt job run` line. @param {number} blocks */
export const windowNoteOf = (blocks) => `(window ${blocks} blocks, RPC limit)`
// E5 (gates/agree.ts): the account as every verified ETH endpoint saw it (d.ethEndpoints, the relay's count): one nonce
// pair (engine.nonce-disagree) and, unless o.code is false, no code at the address on any endpoint (engine.eip7702). An
// attempt adopted at a takeover (nonce n) may sit in some endpoints' pools and not in others': a pending of n or n + 1
// counts as n + 1 (that attempt), so only the latest nonce or a tx beyond it can disagree.
/** @param {string} addr @param {Deps} d @param {{ adopted?: number | null, code?: boolean, warn?: boolean }} [o] */
async function agreedAccount(addr, d, { adopted = null, code = true, warn = false } = {}) {
  const eps = Math.max(1, d.ethEndpoints || 1)
  const rs = await eth.accountsAt(addr, eps)
  if (code) assertNoDelegation(assertCodeAgreement(rs.map((r) => r.code), eps))   // fix round 2: disagreeing endpoints pause; only an agreed delegation ends the chain
  const pending = rs.map((r) => (adopted !== null && (r.pending === adopted || r.pending === adopted + 1) ? adopted + 1 : r.pending))
  // planE5 ruling C2: `delegated` — any answering endpoint shows an EIP-7702 delegation designator (a claw-back, which does not
  // refuse on it, warns on it; the lane's own start refuses via assertNoDelegation above)
  const delegated = rs.some((r) => isDelegationCode(r.code))
  try { return { ...assertNonceAgreement(rs.map((r) => r.latest), pending, eps), delegated } } catch (e) {
    // Eminors (Efix3 m-D): a claw-back refused for disagreeing nonces still says the key is delegated — exactly the case where
    // someone holding the authorization may be moving funds (the refusal keeps its guard id; only its text and the progress line grow)
    if (warn && delegated && isRefusal(e)) { d.delegated?.(DELEGATED_CLAWBACK_WARNING); e.message = `${e.message} — ${DELEGATED_CLAWBACK_WARNING}` }
    throw e
  }
}
/** @param {Cfg} cfg @param {any} key @param {Deps} d @returns {Adapter} */
export function ethAdapter(cfg, key, d) {
  const addr = key.account.address, to = eth.recipientAddress(cfg.recipient, addr), rule = gasRuleOf(cfg, d)
  const textBytes = utf8(cfg.text), sha = sha256Hex(textBytes), strategy = cfg.feeStrategy ?? 'passive'
  /** @type {any} */ let learned = null, /** @type {any} */ nonce = null
  /** @type {{ target: bigint, at: number, windowBlocks: number, truncated: boolean } | null} */ let passive = null
  const passiveFees = async () => {                                     // T from the trailing 24 h, refreshed every 300 blocks
    const h = await ethRpc('eth_feeHistory', ['0x1', 'latest', []]), nextBase = BigInt(h.baseFeePerGas.at(-1)), latest = Number(BigInt(h.oldestBlock))
    if (passive === null || latest - passive.at >= CANON.PASSIVE_ETH_REFRESH_BLOCKS) { const w = await eth.baseFeeWindow(); passive = { target: ethPassiveTarget(w.bases), at: w.latest, windowBlocks: w.windowBlocks, truncated: w.truncated } }
    const tip = CANON.PASSIVE_ETH_TIP
    if (d.lane) d.lane.windowNote = passive.truncated ? windowNoteOf(passive.windowBlocks) : ''   // E6: the running lane's progress text shows a truncated window (the executor's notify reads lane.windowNote)
    return { nextBase, target: passive.target, tip, tip0: tip, maxFee: passive.target + tip, windowBlocks: passive.windowBlocks, truncated: passive.truncated }
  }
  return {
    unit: 'wei', sha256: sha,
    async reconcile(/** @type {Lane} */ lane, /** @type {(e: any) => Promise<void>} */ emit) {   // never send behind a tx that might still land
      const ad = d.resume?.adopted ?? null                              // E3: OUR pending attempt, adopted at a takeover (its nonce)
      let n = 0, disagree = false, readErrs = 0
      for (;;) {
        if (d.alive && !d.alive()) return 'aborted'                     // a lost lease ends the wait (runDrain then aborts)
        // E5: every verified endpoint's nonces (they must agree) and no code at the address (engine.eip7702: the lane stops)
        /** @type {{ latest: number, pending: number }} */ let q
        try { q = await agreedAccount(addr, d, { adopted: ad ? ad.nonce : null }) } catch (e) {
          // fix round 1 (I-1): a requested Stop is honoured before anything else — before any rethrow, so a chain whose
          // key turned delegated (or that one endpoint says is) can always be stopped and then clawed back
          // (fix round 2: the journaled `stopped` names what was found — a delegation, a disagreement, an unreadable set)
          if (d.stopRequested?.()) return { stopped: `stopped during reconcile — ${isRefusal(e) ? `${e.guardId}: ` : ''}${String(/** @type {Error} */ (e)?.message ?? e).slice(0, 300)}`, code: /** @type {any} */ (e)?.guardId === 'engine.eip7702' ? 'eip7702' : 'operator-stop' }   // R79b
          const gid = /** @type {any} */ (e)?.guardId, dis = gid === 'engine.nonce-disagree' || gid === 'engine.code-disagree'
          // engine.eip7702 & co: the lane starts no new send (the refusal stands); the executor reconciles every open
          // intent and journals `stopped` with this reason (executor.ts), so the chain settles and can be clawed back
          if (!dis && (isRefusal(e) || e instanceof JournalError)) throw e
          // the endpoints disagree, or none could be read (the read THREW): paused, nothing signed — read again. A Stop
          // ends it (an adopted attempt stays open in the journal for the next reconcile: nothing is resent or closed
          // here), so does a lost lease; a read error that persists for retryMax rounds ends the run `stopped` (nothing signed)
          // planE5 m-1: ... and settles the chain: `stopped` is journaled (like the planning loop does), so the chain does not
          // stay PAUSED (a Stop would no longer settle it) and can be clawed back or run again
          // (security finding, single-endpoint trust: with an adopted attempt still open the old behaviour stays — the error ends the
          // run with that attempt open for the next reconcile; `stopped` is journaled only when nothing of ours is in flight)
          if (!dis && ++readErrs >= (d.retryMax ?? 60) && ad) throw e
          if (!dis && readErrs >= (d.retryMax ?? 60)) return { stopped: `the verified ETH endpoints could not be read for ${readErrs} rounds — nothing was signed (${String(/** @type {Error} */ (e)?.message ?? e).slice(0, 160)})`, code: 'rpc-unavailable' }   // R79b
          if (dis) readErrs = 0
          const why = dis ? `${gid}: ${/** @type {Error} */ (e).message}` : `the verified ETH endpoints could not be read (${String(/** @type {Error} */ (e)?.message ?? e).slice(0, 120)}) — nothing is signed until they answer and agree (restart the stack or fix endpoints.json if one stays down; Stop, then run again)`
          if (!disagree) { disagree = true; await emit({ type: 'paused', reason: journalText(why) }) }
          await sleepOf(d)(Math.max(d.poll, 3000)); continue
        }
        readErrs = 0
        if (disagree) { disagree = false; await emit({ type: 'resumed', reason: 'the verified ETH endpoints answer and agree on the nonce' }) }
        const { latest, pending } = q
        if (ad && latest > ad.nonce) throw new Error(`invariant violated: the adopted attempt's nonce ${ad.nonce} is already used — reconcile again (fail closed)`)
        if (ad && latest === ad.nonce && pending <= latest + 1) { nonce = ad.nonce; return 'ok' }
        if (!ad && latest === pending) { nonce = latest; if (n) await emit({ type: 'note', text: 'pending = latest — continuing' }); return 'ok' }
        if (n === 0) await emit({ type: 'note', text: `${pending - latest} pending tx(s) from this address — waiting until they resolve` })
        n++
        if (d.stopRequested?.()) return 'stopped'
        await sleepOf(d)(Math.max(d.poll, 3000))
      }
    },
    planCopy: (/** @type {number} */ i) => ethParts(textBytes, partOpts(cfg, sha, i)),
    async startLevel() {
      if (strategy === 'passive') { const f = await passiveFees(); return { ...f, startTip: f.tip, level: 0, label: `passive: target ${formatUnits(f.target, 9)} gwei + tip ${formatUnits(f.tip, 9)} gwei${f.truncated ? ` ${windowNoteOf(f.windowBlocks)}` : ''}` } }
      if (strategy === 'prompt') { const f = await eth.fees(tipCapWei(d, cfg)); return { ...f, startTip: f.tip, level: 0, label: `prompt: tip ${formatUnits(f.tip, 9)} gwei` } }
      const f = await eth.economyFees(networkOf(d.network).eth.tipFloor); const startTip = ethStartTip(f.tip0, learned); return { ...f, startTip, level: 0, label: `tip ${formatUnits(startTip, 9)} gwei` }
    },
    balance: () => eth.balance(addr),
    async decide(/** @type {any} */ parts, /** @type {any} */ lvl, /** @type {bigint} */ bal) {
      const lens = parts.map((/** @type {any} */ p) => p.payload.length)
      if (strategy === 'passive') { const r = ethPassiveDecision(bal, lens, lvl.target, lvl.tip, rule); return { ...r, spend: r.cost } }
      if (strategy === 'prompt') { const cost = ethCopyCost(lens, lvl.nextBase, lvl.tip, false, rule); return bal >= cost ? { send: true, tight: false, cost, spend: cost } : { send: false, drained: true, cost, spend: cost } }
      const r = ethDrainDecision(bal, lens, lvl.nextBase, lvl.startTip, rule); return { ...r, spend: r.cost }
    },
    async sendTx(/** @type {any} */ t, /** @type {any} */ { tight }) {
      t.nonce = nonce
      const policy = strategy === 'passive' ? {
        fees: passiveFees,
        ready: (/** @type {any} */ f) => ethPassiveInitial({ nextBase: f.nextBase, target: f.target, tip: f.tip }).wait ?? null,
        initial: (/** @type {any} */ f) => ethPassiveInitial({ nextBase: f.nextBase, target: f.target, tip: f.tip }),
        bump: () => ethPassiveBump(),
        noEscalate: true, replaceAfterBlocks: CANON.PASSIVE_ETH_REBROADCAST_BLOCKS, waitPollMs: d.passiveWaitMs ?? 12000,
      } : strategy === 'prompt' ? undefined : {
        fees: () => eth.economyFees(networkOf(d.network).eth.tipFloor),
        initial: (/** @type {any} */ f) => ({ ...ethEconomyInitial({ nextBase: f.nextBase, startTip: ethStartTip(f.tip0, learned), tight, cap: tipCapWei(d, cfg) }), tight }),
        bump: (/** @type {any} */ prev, /** @type {any} */ f) => ({ ...ethEconomyBump(prev, { nextBase: f.nextBase, tip0: f.tip0, tight, cap: tipCapWei(d, cfg), balance: f.balance, gas: f.gas }), tight }),
      }
      const r = await ethTx(t, { ...d, policy, to, account: key.account, chainId: d.chainId, lane: d.lane, gasRule: rule, tipCap: tipCapWei(d, cfg) })
      if (r === 'confirmed') nonce = t.nonce + 1
      return r
    },
    learn(/** @type {any} */ t) { learned = t.landedTip ?? learned },
    // E3 takeover: the journaled attempts of a pending part, rebuilt so ethTx watches them, bumps the open one with the
    // highest fee (same nonce, replaces it) and never rebroadcasts bytes it does not hold.
    // PF-E (pre-flip review I-2): the signed bytes of every attempt adopted OPEN are rebuilt from its journaled intent and the planned
    // payload of this (copy, part) (engine.js ethRebuild: kept only when keccak256 is the journaled tx id), so a Passive lane rebroadcasts
    // them when the pools dropped them (after the send ticket shows they are the journaled rawSha256's); when they cannot be rebuilt the
    // attempt keeps `unbuilt` (the reason) and a Passive lane journals it stuck. An attempt adopted only as a claim (open: false —
    // journaled rejected, marked failed) is watched, never re-sent.
    async adopt(/** @type {any} */ t) {
      const ad = d.resume?.adopted
      if (!ad || t.copy !== ad.copy || t.part !== ad.part) return
      /** @type {Record<string, string>} */ const raws = {}
      /** @type {any[]} */ const attempts = []
      for (const x of ad.attempts) {
        /** @type {any} */ const a = { id: x.id, n: x.n, gas: x.gas, tip: x.tip, maxFee: x.maxFee, reserved: x.gas * x.maxFee, at: 0, ticketAt: 0, adopted: true, open: x.open !== false }
        if (a.open) { const r = await ethRebuild(key.account, d.chainId, x, ad.nonce, t.payload, to); if ('raw' in r) raws[x.id] = r.raw; else a.unbuilt = r.why }
        attempts.push(a)
      }
      Object.assign(t, { nonce: ad.nonce, raws, state: 'sent', firstAt: null, attempts })
    },
    async reassemble(/** @type {number} */ i, /** @type {any[]} */ txs, /** @type {Record<number, string> | null} */ landed) {
      const parts = ethParts(textBytes, partOpts(cfg, sha, i))
      /** @type {Uint8Array[]} */ const bytes = []
      for (const p of parts) {
        const t = txs.find((x) => x.part === p.i)
        let b = t?.chainBytes ?? null
        if (b === null) { const id = t?.landedId ?? landed?.[p.i]; if (!id) return null; b = (await eth.readback(id, p.payload, to))?.bytes ?? null }
        if (b === null) return { ok: false, sha256: null, why: `part ${p.i}: not found on chain` }
        bytes.push(b)
      }
      return reassembleCopy(bytes, { lead: utf8(ETH.PREFIX), sha256: sha })
    },
  }
}
/** @param {Cfg} cfg @param {any} key @param {Deps} d @returns {Adapter} */
export function solAdapter(cfg, key, d) {
  const pk = key.kp.publicKey, addr = pk.toBase58(), used = new Map()
  const textBytes = utf8(cfg.text), sha = sha256Hex(textBytes), strategy = cfg.feeStrategy ?? 'passive'
  const reserve = cfg.mode === 'drain' ? ECON.SOL_CLAW_RESERVE : 0n          // a drained lane keeps one claw-back fee (MQ laneCalc)
  /** @type {any} */ let landedRung = null, /** @type {any} */ rent = null
  const rungsOf = () => (strategy === 'passive' ? [0] : strategy === 'prompt' ? [CANON.SOL_PROMPT_LAMPORTS] : CANON.SOL_RUNG_LAMPORTS)
  return {
    unit: 'lamports', sha256: sha,
    async reconcile(/** @type {Lane} */ lane, /** @type {(e: any) => Promise<void>} */ emit) {   // a tx signed before a reload may still land: wait one blockhash window
      rent = await sol.rentMin()
      if (d.reconciled === true) return 'ok'                            // E3: the executor reconciled every journaled intent from the chain
      const prior = await sol.sentCount(addr)
      if (!prior) return 'ok'
      // Eminors (Efix3 m-4): the old "wait one blockhash window" heuristic read ONE endpoint's finalized height and had no history check or
      // resume. No production path reaches it (the executor sets `reconciled`), so it now fails closed: an address with earlier sends is
      // never driven without the executor's reconcile (executor/reconcile.ts: isBlockhashValid on every endpoint, history included).
      throw new Error(`this address already sent ${prior} memo tx(s) and the lane was started without the executor's reconcile — refusing (fail closed); start it through the executor`)
    },
    planCopy: (/** @type {number} */ i) => solParts(textBytes, sol.layoutMaxMemo(), partOpts(cfg, sha, i)),
    async startLevel() {
      rent ??= await sol.rentMin()
      const rungs = rungsOf()
      const rung = strategy === 'economy' ? Math.min(solStartRung(landedRung), rungs.length - 1) : 0
      return { rungs, rung, level: rung, label: `${strategy}: rung ${rung} (${rungs[rung]} lamports/tx of [${rungs.join(', ')}])` }
    },
    balance: () => sol.solBalance(addr),
    async decide(/** @type {any} */ parts, /** @type {any} */ lvl, /** @type {bigint} */ bal) {
      /** @type {bigint[]} */
      const fees = []; for (const p of parts) fees.push((await sol.prepare(pk, p.payload, { priorityLamports: lvl.rungs[lvl.rung], cuPriceCap: cfg.cuPriceCap })).fee)
      const r = solDrainDecision(bal, fees, rent, reserve); return { ...r, spend: r.fees }
    },
    async sendTx(/** @type {any} */ t, /** @type {any} */ { lvl }) {
      let cur = lvl.rung, retryTop = false
      const policy = strategy === 'passive' ? {
        price: async () => ({ lamports: 0, rung: 0 }),                         // no priority, ever; re-sign at 0 after proven expiry
      } : strategy === 'prompt' ? {
        price: async (/** @type {any} */ tt) => (tt.attempts.length >= SOL.MAX_ATTEMPTS ? { pause: `${SOL.MAX_ATTEMPTS} signatures, every one proven expired` } : { lamports: CANON.SOL_PROMPT_LAMPORTS * 2 ** tt.attempts.length, rung: null }),
      } : {
        price: async (/** @type {any} */ _t, /** @type {any} */ last) => {
          if (retryTop) { retryTop = false; return { lamports: lvl.rungs[cur], rung: cur } }
          if (!last) return { lamports: lvl.rungs[cur], rung: cur }
          const n = solNextRung(last.rung ?? cur, lvl.rungs); if (n.pause) return n
          cur = /** @type {number} */ (n.rung); return { lamports: lvl.rungs[cur], rung: cur }
        },
        resumeAtTop: () => { retryTop = true },
      }
      return solTx(t, { ...d, policy, kp: key.kp, rent, payerFloor: rent + reserve, used, lane: d.lane, cuPriceCap: cfg.cuPriceCap })
    },
    learn(/** @type {any} */ t) { landedRung = t.landedRung ?? landedRung },
    async reassemble(/** @type {number} */ i, /** @type {any[]} */ txs, /** @type {Record<number, string> | null} */ landed) {
      const parts = solParts(textBytes, sol.layoutMaxMemo(), partOpts(cfg, sha, i))
      /** @type {Uint8Array[]} */ const bytes = []
      for (const p of parts) {
        const t = txs.find((x) => x.part === p.i)
        let b = t?.chainBytes ?? null
        if (b === null) { const id = t?.landedId ?? landed?.[p.i]; if (!id) return null; b = (await sol.readback(id, p.payload))?.bytes ?? null }
        if (b === null) return { ok: false, sha256: null, why: `part ${p.i}: not found on chain` }
        bytes.push(b)
      }
      return reassembleCopy(bytes, { sha256: sha })
    },
  }
}
/** E7: the BTC copies lane. A copy is two lane txs: part 1 the commit, part 2 the reveal of ONE text inscription (chains/btc.js); each is
 * driven by engine/btc-tx.js (intent before every send, reconcile by txid, the reveal only after its commit landed).
 * @param {Cfg} cfg @param {any} key @param {Deps} d @returns {Adapter} */
export function btcAdapter(cfg, key, d) {
  if (d.network !== 'local') throw new Error('the BTC lane runs on a local network only in M4 (testnet4 / mainnet reads need the relay Esplora client)')
  if (key.network !== d.network) throw new Error(`invariant violated: a ${key.network} BTC key on the ${d.network} network`)
  const textBytes = utf8(cfg.text), sha = sha256Hex(textBytes)
  let copy = 1
  return {
    unit: 'sats', sha256: sha,
    // a copy of this lane whose commit is journaled (open, or landed without its landed reveal)
    copyInFlight: (/** @type {number} */ i) => btcStrandedIn(d.state?.chains?.btc?.txs ?? [], i),   // Eminors (E7-fix2 m-3): the one predicate (job/reduce.ts)
    atomicCopy: true,                                                    // commit + reveal are ONE in-flight unit for Stop (a commit alone locks funds only the reveal can spend)
    // the by-txid reconcile of every journaled attempt that has not landed: included (+ readback) or adopted; it never sends and never
    // closes an attempt (btc-reconcile.js). A read that fails ends the run `failed` (engine.btc-open), never `stopped`.
    async reconcile(/** @type {Lane} */ _lane, /** @type {(e: any) => Promise<void>} */ emit) {
      if (d.reconciled === true) return 'ok'                              // the executor reconciled every journaled attempt before the lane (executor/reconcile.ts)
      const cs = d.state?.chains?.btc
      for (const g of cs?.txs ?? []) {
        if (g.state === 'included' || g.attempts.length === 0) continue
        if (d.alive && !d.alive()) return 'aborted'
        await btcReconcileGroup(g, { emit, key, payloadOf: (/** @type {number} */ c) => btcc.planBtcCopy(textBytes, partOpts(cfg, sha, c))[0].payload })
      }
      return 'ok'
    },
    planCopy: (/** @type {number} */ i) => { copy = i; return btcc.planBtcCopy(textBytes, partOpts(cfg, sha, i)) },
    async startLevel() { const rate = await btcc.cappedFeeRate(cfg.maxFeeRateSatVb);   // the job's maxFeeRateSatVb caps the rate
      return { rate, level: 0, label: `${rate} sat/vB` } },
    balance: () => btcc.balanceOf(key.address),
    async decide(/** @type {any} */ parts, /** @type {any} */ lvl, /** @type {bigint} */ bal) {
      if (!parts.some((/** @type {any} */ p) => p.i === 1)) return { send: true, tight: false, cost: 0n, spend: 0n }   // only the reveal is left: it moves what the commit locked
      // a commit an earlier holder journaled is taken over (reconciled by txid, rebuilt from its intent): it needs no new funds, and
      // a lane whose coins it already spent must not call itself drained and leave it unexamined
      if (d.state?.chains?.btc?.txs?.some((/** @type {any} */ g) => g.copy === copy && g.part === 1 && g.state !== 'included' && g.attempts.some((/** @type {any} */ a) => ['intent', 'sent', 'unknown', 'adopted'].includes(a.state)))) return { send: true, tight: false, cost: 0n, spend: 0n }
      const p = btcc.planCommit(key, parts[0].payload, await btcc.utxosOf(key.address), lvl.rate)
      const cost = p.fee + p.value
      return { send: p.inputs !== null && bal >= cost, tight: false, cost: p.inputs === null ? p.value : cost, spend: cost }
    },
    sendTx: (/** @type {any} */ t, /** @type {any} */ { lvl }) => btcTx(t, { ...d, key, rate: lvl.rate }),
    learn() {},
    async reassemble(/** @type {number} */ i, /** @type {any[]} */ txs, /** @type {Record<number, string> | null} */ landed) {
      const rev = txs.find((x) => x.part === 2)
      let b = rev?.chainBytes ?? null
      if (b === null) {
        const id = rev?.landedId ?? landed?.[2]
        if (!id) return null
        const tx = await btcc.getTx(id)
        b = (tx ? btcc.readbackReveal(key, utf8(cfg.text), tx).bytes : null) ?? null   // the inscription body as the witness holds it
      }
      if (b === null) return { ok: false, sha256: null, why: 'part 2: the inscription is not on chain' }
      return reassembleCopy([b], { sha256: sha })
    },
  }
}
// The canonical entry points: config object + in-memory key + injected deps (journal, network, state, resume, …).
// deps.state is the job state reduced from the journal: the spend cap, the spend so far and the open intents come from
// it (CapLedger.fromArmed); any deps.cap / deps.ledger the caller passes is ignored.
// async: a refusal at setup (engine.cap-armed, contract.network) is a rejection like every later one, never a sync throw
/** @param {Cfg} cfg @param {any} key @param {Lane} lane @param {Deps} deps @param {'drain' | 'copies'} mode @returns {Promise<string>} */
async function runLane(cfg, key, lane, deps, mode) {
  const modeOk = cfg.mode === mode && cfg.chain === key.chain
  if (!modeOk) throw new Error(`invariant violated: a ${cfg.mode} ${cfg.chain} config on the ${mode} runner with a ${key.chain} key`)
  const ledger = CapLedger.fromArmed(deps.state, cfg.chain, key.chain === 'eth' ? key.account.address : key.chain === 'btc' ? key.address : key.kp.publicKey.toBase58())
  try {
    const d = { ...deps, cap: undefined, lane, ledger, copiesLimit: mode === 'copies' ? cfg.copies : null }
    return await runDrain(lane, cfg.chain === 'eth' ? ethAdapter(cfg, key, d) : cfg.chain === 'btc' ? btcAdapter(cfg, key, d) : solAdapter(cfg, key, d), d)
  } finally { ledger.close() }
}
// run one lane in drain mode
/** @param {Cfg} cfg @param {any} key @param {Lane} lane @param {Deps} deps */
export function runDrainLane(cfg, key, lane, deps) { return runLane(cfg, key, lane, deps, 'drain') }
// run one lane in copies mode (R65 `mode: { copies: N }`): the same controller, ending `copies-done` after copy N
/** @param {Cfg} cfg @param {any} key @param {Lane} lane @param {Deps} deps */
export function runCopiesLane(cfg, key, lane, deps) { return runLane(cfg, key, lane, deps, 'copies') }

// PF-E fix round 2 (I-1): the WATCH-ONLY run of a chain already settled (STOPPED, DRAINED, COPIES_DONE) whose ETH job attempt is still
// open (deps.resume.adopted, from the takeover reconcile). Such a chain never enters the lane (its phase events — copy-built, stopped — are
// refused there), and it must never be a dead end: the attempt's signed bytes are rebuilt (ethAdapter.adopt: identical, or `unbuilt`) and
// sent again as they are — never a new signature — in windows of CANON.PASSIVE_ETH_REBROADCAST_BLOCKS (engine.js ethTx watchOnly):
//   · it lands → `included` + `readback` (evidence: accepted on a settled chain) → 'confirmed'; the chain is settled with nothing open;
//   · not known to every verified endpoint for CANON.PASSIVE_ETH_UNSEEN_WINDOWS windows, or bytes that cannot be rebuilt → `stuck` with
//     the exact reason → 'stuck' (vt job resolve; after mark-failed the chain is settled: claw-back and close);
//   · still pending everywhere after that many windows, or a Stop (deps.stopRequested) → 'stopped': nothing journaled, run again later.
// No phase event is journaled. Returns the ethTx outcome.
/** @param {Cfg} cfg @param {any} key @param {Deps} deps @returns {Promise<string>} */
export async function watchAdoptedEth(cfg, key, deps) {
  const ad = deps.resume?.adopted
  if (cfg.chain !== 'eth' || !ad) throw new Error('invariant violated: a watch-only run needs an adopted ETH attempt')
  const ledger = CapLedger.fromArmed(deps.state, 'eth', key.account.address)
  try {
    const d = { ...deps, cap: undefined, ledger, lane: { txs: [] } }
    const A = ethAdapter(cfg, key, d)
    const p = A.planCopy(ad.copy).find((/** @type {any} */ x) => x.i === ad.part)
    if (p === undefined) throw new Error(`invariant violated: copy ${ad.copy} has no part ${ad.part}`)
    /** @type {any} */ const t = { k: 0, copy: ad.copy, part: ad.part, parts: p.n, payload: p.payload, textBytes: p.chunk.length, state: 'planned' }
    await A.adopt(t)
    deps.onTx?.(t)
    return await ethTx(t, { ...d, account: key.account, chainId: d.chainId, gasRule: gasRuleOf(cfg, d), to: eth.recipientAddress(cfg.recipient, key.account.address), tipCap: tipCapWei(d, cfg),
      notify: () => deps.onTx?.(t), watchOnly: true, policy: { noEscalate: true, replaceAfterBlocks: CANON.PASSIVE_ETH_REBROADCAST_BLOCKS } })
  } finally { ledger.close() }
}

// ---------- claw back remainder (only when nothing is in flight) ----------
// Claw-back journal integrity (security review): the journal never claims an outcome the chain has not proven.
//   · clawback-failed only when the bytes are provably dead (an ETH first attempt rejected for a consumed nonce or as
//     consensus-invalid — no other attempt of ours exists; SOL: every attempt's blockhash expiry proven by the evidence
//     gate with no signature status) or when the tx landed with an error (then with the fee it was charged);
//   · any other outcome leaves the claw-back open (clawback-sent unknown; `stuck` when the nonce is used and no receipt
//     of ours is found), so the next holder reconciles before anything else;
//   · the ETH bump family settles on ANY attempt that lands: clawback-included names that txId with the value and fee
//     the chain recorded; clawback-readback reports what the chain shows (the landed tx's own transfer, the measured lane
//     balance);
//   · a member that landed with an error is journaled clawback-failed with its fee; on ETH it consumed the nonce, so every
//     other member is journaled reconcile nonce-consumed (chain evidence: none can land) and the family fails;
//   · the cap ledger reserves value + worst-case fee of the family (largest attempt; or the operator's typed exact
//     amount, d.clawbackConfirm, CC-2a) and observes every event journaled through `dl`: a landed claw-back spends the
//     chain's value + fee, a failed-on-chain one its fee, a family whose members are all dead nothing (contracts/types.ts
//     claw-back cap note; security review: cap-ledger drift).
/** @param {any} key @param {string} dest @param {Deps} d */
export async function clawbackEth(key, dest, d) {
  const addr = key.account.address, v = validateEthDest(dest, addr)
  if (!v.ok) throw new Error(v.why)
  const rk = ethReservedKind(v.address)                                          // E6: the one reserved-address source (chains/reserved.js)
  if (rk !== null) throw new Error(`that is ${rk === 'precompile' ? 'an Ethereum precompile or reserved system address (0x…0001 to 0x…ffff)' : `the ${rk} address`}: nobody controls it and value sent there is lost`)
  const sleep = sleepOf(d)
  // E5: the nonce it signs at is one every verified endpoint agrees on (engine.nonce-disagree refuses the claw-back). No
  // engine.eip7702 here: a claw-back is the way the remainder leaves a delegated account — a transfer FROM it runs none of
  // its code (EIP-7702 runs the delegate only for calls TO it), and its destination is refused when it has code (below).
  const { latest, pending, delegated } = await agreedAccount(addr, d, { code: false, warn: true })
  if (delegated) d.delegated?.(DELEGATED_CLAWBACK_WARNING)
  if (latest !== pending) throw new Error(`${pending - latest} tx(s) from this lane are still pending — claw back waits until nothing is in flight${delegated ? ` — ${DELEGATED_CLAWBACK_WARNING}` : ''}`)
  // PM finding 1: gas by destination class (a contract destination is refused), cross-checked with eth_estimateGas
  const amsterdam = ethAmsterdam(d.network, d.amsterdamOverride === undefined ? {} : { localOverride: d.amsterdamOverride })
  const cls = await eth.accountClass(v.address)
  if (cls.code) throw new Error('the claw-back destination is a contract — refusing (use a plain account)')
  const gas = ethClawGas({ amsterdam, empty: cls.empty })
  const ledger = CapLedger.fromArmed(d.state, 'eth', addr)                       // the armed spend cap covers value + fee
  const dl = { ...d, ledger }, emit = (/** @type {any} */ e) => jappend(dl, { chain: 'eth', ...e })   // the ledger observes every event
  try {
  // planE5 ruling C2 (core side): the claw-back of a delegated key goes ahead (it is the rescue path) and says so — a journal
  // note, the progress line (d.delegated) and the result's `delegated` / `warning`
  if (delegated) { d.delegated?.(DELEGATED_CLAWBACK_WARNING); await emit({ type: 'note', text: DELEGATED_CLAWBACK_WARNING }) }
  /** @type {string} */ let windowNote = ''
  /** @type {any[]} */
  const attempts = []
  const landedOf = async () => { for (const x of attempts) { const r = await eth.receipt(x.id); if (r) return { x, r } } return null }
  // a member of the family landed: journal exactly what the chain recorded for THAT tx
  const settleLanded = async (/** @type {{ x: any, r: any }} */ { x, r }) => {
    /** @type {any} */
    let tx = null
    for (let i = 0; i < 6 && !tx; i++) { tx = await ethRpc('eth_getTransactionByHash', [x.id]); if (!tx) await sleep(d.poll) }
    if (!tx) throw new Error('claw back: a receipt without its transaction — still open; reconcile before anything else')
    const fee = BigInt(r.gasUsed) * BigInt(r.effectiveGasPrice), value = BigInt(tx.value ?? 0)
    if (r.status !== '0x1') {                                          // landed with an error: nothing moved, the fee was charged
      await emit({ type: 'clawback-failed', txId: x.id, reason: 'the claw-back landed with an error: nothing moved; the fee was charged', fee: String(fee) })
      // chain evidence: that member consumed the nonce (its own bytes too), so no member can ever land — each one is
      // reconciled nonce-consumed (only that frees the cap: S2 2fea217)
      for (const y of attempts) await emit({ type: 'reconcile', txId: y.id, outcome: 'nonce-consumed' })
      throw new Error('claw back landed with an error (the fee was charged)')
    }
    const toDest = String(tx.to ?? '').toLowerCase() === v.address.toLowerCase(), received = toDest ? value : 0n
    await emit({ type: 'clawback-included', txId: x.id, value: String(value), fee: String(fee) })
    const laneAfter = await eth.balance(addr)
    const ok = toDest && value === x.value
    await emit({ type: 'clawback-readback', txId: x.id, ok, destReceived: String(received), laneBalance: String(laneAfter) })
    return { ok, id: x.id, value, to: v.address, destReceived: received, laneBalance: laneAfter, attempts: attempts.length, delegated, warning: delegated ? DELEGATED_CLAWBACK_WARNING : '', windowNote }
  }
  // the nonce is used and none of our receipts shows up: not proof that another tx took it (receipts lag) — stuck, open
  const nonceGone = async () => {
    for (let i = 0; i < 6; i++) { const L = await landedOf(); if (L) return settleLanded(L); await sleep(d.poll) }
    await emit({ type: 'stuck', txId: attempts.at(-1).id, reason: `nonce ${latest} is used and no receipt of this claw-back was found yet — reconcile before anything else` })
    throw new Error('claw back: the nonce is used but no receipt of ours was found — stuck; reconcile')
  }
  // G1 (P2 delta): the claw-back's fees follow the lane's fee strategy — Passive waits for a cheap block before anything is
  // signed (T = p10 of the 24 h base fees, maxFee T + tip) and never escalates: the same signed bytes are rebroadcast if
  // the pool drops them; Economy starts at the floor-clamped p10 tip and bumps ×1.125 within the tip cap; Prompt (the
  // default when the caller names none: E2's behaviour) uses the p50 tip and ×1.125 bumps.
  const strategy = d.feeStrategy ?? 'prompt', floor = networkOf(d.network).eth.tipFloor
  const tipCap = () => parseDecimal(String(d.getTipCapGwei?.() ?? ECON.ETH_TIP_CAP_DEFAULT), 9)
  /** @param {any} prev @returns {Promise<{ tip: bigint, maxFee: bigint } | { wait: string }>} */
  const feeFor = async (prev) => {
    if (strategy === 'passive') {
      const w = await eth.baseFeeWindow()
      windowNote = w.truncated ? windowNoteOf(w.windowBlocks) : ''      // Efix3: the claw-back's own passive fee path shows the truncated window too (journal note + progress line + result)
      if (windowNote !== '') d.windowNote?.(windowNote)
      const r = ethPassiveInitial({ nextBase: w.nextBase, target: ethPassiveTarget(w.bases), tip: CANON.PASSIVE_ETH_TIP })
      return r.wait ? { wait: r.wait } : { tip: /** @type {bigint} */ (r.tip), maxFee: /** @type {bigint} */ (r.maxFee) }
    }
    if (strategy === 'economy') {
      const f = await eth.economyFees(floor)
      const r = prev ? ethEconomyBump(prev, { nextBase: f.nextBase, tip0: f.tip0, cap: tipCap() }) : ethEconomyInitial({ nextBase: f.nextBase, startTip: f.tip0, cap: tipCap() })
      return 'pause' in r && r.pause ? { wait: r.pause } : 'wait' in r && r.wait ? { wait: r.wait } : { tip: /** @type {bigint} */ (r.tip), maxFee: /** @type {bigint} */ (r.maxFee) }
    }
    const f = await eth.fees(tipCap())
    return prev ? replacementFees(prev, f) : { tip: f.tip, maxFee: f.maxFee }
  }
  /** @type {any} */
  let prev = null, waitNoted = false
  for (let bump = 0; bump <= ETH.MAX_BUMPS; bump++) {
    if (attempts.length) { const L = await landedOf(); if (L) return settleLanded(L) }   // a member may have landed meanwhile
    const fee = await feeFor(prev)
    if ('wait' in fee) {
      if (prev) { const L = await landedOf(); if (L) return settleLanded(L); throw new Error(`claw back: ${fee.wait} — the earlier attempts are still open; reconcile`) }
      if (strategy !== 'passive') throw new Error(`nothing signed: ${fee.wait}`)
      if (!waitNoted) { waitNoted = true; await emit({ type: 'note', text: journalText(`claw back (passive): ${fee.wait}${windowNote !== '' ? ` ${windowNote}` : ''}`, 200) }) }
      if (d.stopRequested?.() || (d.alive && !d.alive())) throw new Error('claw back cancelled while waiting for a cheap block — nothing was signed')
      bump--; await sleep(Math.max(d.poll ?? 1000, d.passiveWaitMs ?? 12000)); continue
    }
    const bal = await eth.balance(addr)
    const { tip, maxFee } = fee
    const value = bal - gas * maxFee                                   // the lane ends at 0 if the tx uses its whole gas × maxFee
    if (value <= 0n) {
      if (prev) { const L = await landedOf(); if (L) return settleLanded(L); throw new Error('claw back: a bump no longer fits the balance — the earlier attempts are still open; reconcile') }
      throw new Error(`nothing to claw back at ${strategy} fees: remainder ${formatUnits(bal, 18)} ETH ≤ ${gas} × maxFee ${formatUnits(maxFee, 9)} gwei = ${formatUnits(gas * maxFee, 18)} ETH`)
    }
    const est = BigInt(await ethRpc('eth_estimateGas', [{ from: addr, to: v.address, value: toHex(value) }]))
    if (!estimateMatches(est, Number(gas))) throw new Error(`eth_estimateGas ${est} does not match the ${cls.empty ? 'empty' : 'existing'} destination's ${gas} gas${amsterdam ? ' (Amsterdam)' : ''} — refusing (fail closed)`)
    // PF-E fix 1 (5): a Stop means no new signature — neither the first claw-back nor a bump (an attempt in flight stays open)
    if (d.stopRequested?.()) throw new Error(prev ? `claw back stopped by the operator: attempt ${attempts.length} (nonce ${latest}) stays open and may still land — nothing new is signed; run the claw-back again to watch it` : 'claw back cancelled by a Stop — nothing was signed')
    ledger.reserveClawback(value + gas * maxFee, d.clawbackConfirm)   // before signing: value + worst-case fee, or the typed amount (engine.cap-clawback)
    const { raw, id: rawId } = await eth.signClawback(key.account, { chainId: d.chainId, nonce: latest, to: v.address, value, maxFee, tip, gas })
    const id = rawId.toLowerCase()
    const ticket = await jintent(dl, { type: 'clawback-intent', chain: 'eth', txId: id, to: v.address, value: String(value), rawSha256: sha256Hex(hexToBytes(raw)),
      eth: { nonce: latest, tip: String(tip), maxFee: String(maxFee), gas: String(gas), to: v.address } })   // journaled + acked BEFORE broadcast
    /** @type {any} */ const a = { id, value, maxFee, tip, raw, at: nowOf(d), ticket, ticketAt: nowOf(d), unseen: 0 }; attempts.push(a); prev = a
    d.claw?.({ state: 'sent', attempts })
    const out = await post(() => eth.send(raw, ticket))
    const outcome = journalOutcome('eth', out)
    await emit({ type: 'clawback-sent', txId: id, outcome })
    if (out.kind === 'rejected') {
      if (attempts.length === 1) {                                       // no other attempt of ours exists
        // provably dead (a used nonce, or invalid by consensus): reconciled from that evidence — the family (this one
        // member) fails by itself; a clawback-failed is only for a claw-back that failed ON CHAIN
        if (outcome === 'rejected') { await emit({ type: 'reconcile', txId: id, outcome: /nonce too low/i.test(out.msg) ? 'nonce-consumed' : 'expired' }); throw new Error(`rejected: ${out.msg}`) }
        throw new Error(`rejected: ${out.msg} — the claw-back stays open; reconcile`)
      }
      if (/nonce too low/i.test(out.msg)) return nonceGone()            // an earlier member may have taken the nonce
      // the earlier members are still live: keep watching them (the next bump recomputes its fees)
    }
    // PF-E fix 1 (4): windows like the lane's (engine.js windowEnd) — the claw-back is the way out and never waits without end. Passive
    // (and any strategy after a Stop: nothing new is signed) sends the SAME signed bytes again when no node has them; at the end of a
    // window an attempt not known to EVERY verified endpoint (fix round 2, M-6: one endpoint's word is never enough), its nonce unused,
    // is unseen: CANON.PASSIVE_ETH_UNSEEN_WINDOWS unseen windows in a row, or a Stop, journal it `stuck` (vt job resolve); a Stop with it
    // still pending ends the run, the claw-back open. Economy / prompt (no Stop): a same-nonce replacement after REPLACE_AFTER_BLOCKS.
    const win = strategy === 'passive' ? CANON.PASSIVE_ETH_REBROADCAST_BLOCKS : ETH.REPLACE_AFTER_BLOCKS
    let start = await eth.blockNumber()
    for (;;) {
      await sleep(d.poll)
      if (d.alive && !d.alive()) throw new Error('claw back aborted — the claw-back stays open; reconcile')
      const L = await landedOf(); if (L) return settleLanded(L)
      if ((await eth.nonceAt(addr, 'latest')) > latest) return nonceGone()
      const stop = !!d.stopRequested?.()
      if ((strategy === 'passive' || stop) && !(await eth.known(a.id))) await post(async () => eth.send(a.raw, await ticketFor(a, dl)))   // never escalate: the SAME signed bytes again if the pool dropped them
      if ((await eth.blockNumber()) < start + win) continue
      if (strategy !== 'passive' && !stop) break                         // same-nonce replacement (never a second transfer)
      const k = await eth.knownByEvery(a.id, d.ethEndpoints), known = k.known
      a.unseen = known ? 0 : (a.unseen ?? 0) + 1
      if (!known && (stop || a.unseen >= CANON.PASSIVE_ETH_UNSEEN_WINDOWS)) {
        const why = `claw back: attempt ${attempts.length} (nonce ${latest}) is not known to every verified endpoint (${k.why}) ${stop ? 'at a Stop' : `after ${a.unseen} passive windows of ${win} blocks of same-bytes rebroadcasts`}, its nonce unused — nothing else is signed at that nonce; look it up: if it never landed, resolve it with vt job resolve mark-failed and claw back again; if it landed, run the claw-back again (the landing is read from the chain)`
        for (const x of attempts) await emit({ type: 'stuck', txId: x.id, reason: journalText(why) })
        throw new Error(why)
      }
      if (stop) throw new Error(`claw back stopped by the operator: attempt ${attempts.length} (nonce ${latest}) is still pending at the nodes and may land — nothing new is signed; the claw-back stays open: run it again to watch it`)
      start = await eth.blockNumber()
    }
  }
  // the attempts may still land: the claw-back stays open for the next holder's reconcile (no clawback-failed)
  throw new Error('claw back not included after the maximum bumps — still open; reconcile before anything else')
  } finally { ledger.close() }
}
/** @param {any} key @param {string} dest @param {Deps} d */
export async function clawbackSol(key, dest, d) {
  const pk = key.kp.publicKey, addr = pk.toBase58(), v = validateSolDest(dest, addr)
  if (!v.ok) throw new Error(v.why)
  const rk = solReservedKind(v.address)                                          // E6: the System Program is refused too (the incinerator already is)
  if (rk !== null) throw new Error(`that is the ${rk === 'system' ? 'System Program' : 'incinerator'}: nobody controls it and value sent there is lost`)
  const ledger = CapLedger.fromArmed(d.state, 'sol', addr)                       // the armed spend cap covers value + fee
  const dl = { ...d, ledger }, emit = (/** @type {any} */ e) => jappend(dl, { chain: 'sol', ...e })   // the ledger observes every event
  const strategy = d.feeStrategy ?? 'passive'                                   // G1: the lane's fee strategy (a plain transfer unless prompt)
  try {
  const rent = await sol.rentMin(), destBefore = await sol.solBalance(v.address)
  /** @type {any} */
  const t = { copy: 'claw-back', part: 1, attempts: [], raws: {} }
  for (let n = 0; n < SOL.MAX_ATTEMPTS; n++) {
    // PF-E fix 1 (5): a Stop means no new signature (after a proven expiry every member is dead: the claw-back failed by itself)
    if (d.stopRequested?.()) throw new Error(n === 0 ? 'claw back cancelled by a Stop — nothing was signed' : 'claw back stopped by the operator: every attempt was proven expired and nothing is re-signed — run the claw-back again')
    const bal = await sol.solBalance(addr)
    // G1 (P2 delta): Prompt adds a priority of SOL_PROMPT_LAMPORTS × 2^n lamports per tx (×2 per proven expiry); Passive and
    // Economy claw back with a plain transfer (5,000 lamports). The fee is cross-checked against the formula (fail closed).
    const lamports = strategy === 'prompt' ? CANON.SOL_PROMPT_LAMPORTS * 2 ** n : 0
    const { fee, blockhash, lastValidBlockHeight, slot, cuLimit, cuPrice } = await sol.transferFee(pk, v.address, { priorityLamports: lamports })
    const expect = solFee(1, cuLimit || 1, cuPrice)
    if (fee !== expect) throw new Error(`fee cross-check failed: getFeeForMessage ${fee} ≠ ${expect} — fail closed`)
    const c = solClawback(bal, fee, destBefore, rent)
    if (!c.ok) throw new Error(c.why)
    const tx = sol.buildTransfer(pk, v.address, c.amount, blockhash, { cuLimit, cuPrice })
    const simErr = await sol.simulateUnsigned(tx)
    if (simErr) throw new Error(`simulation refused the transfer: ${simErr}`)
    // fix round 2 (M-1): a Stop that came while this claw-back was prepared (three reads over Tor): nothing is signed
    if (d.stopRequested?.()) throw new Error(n === 0 ? 'claw back cancelled by a Stop — nothing was signed' : 'claw back stopped by the operator: every attempt was proven expired and nothing is re-signed — run the claw-back again')
    ledger.reserveClawback(c.amount + fee, d.clawbackConfirm)         // before signing: value + fee, or the typed amount (engine.cap-clawback)
    tx.sign([key.kp])
    const rawBytes = tx.serialize(), raw = base64.encode(rawBytes), id = base58.encode(tx.signatures[0])
    // a plain transfer has no ComputeBudget instructions: the default limit (200,000 CU per instruction) and no priority
    const ticket = await jintent(dl, { type: 'clawback-intent', chain: 'sol', txId: id, to: v.address, value: String(c.amount), rawSha256: sha256Hex(rawBytes),
      sol: { blockhash, lastValidBlockHeight, cuPrice, cuLimit: cuPrice > 0 ? cuLimit : 200000, rung: null, fee: String(fee) } })   // journaled + acked BEFORE broadcast
    /** @type {any} */
    const a = { id, blockhash, slot, lastValidBlockHeight, amount: c.amount, fee, at: nowOf(d), ticket, ticketAt: nowOf(d) }
    t.attempts.push(a); t.raws[id] = raw
    d.claw?.({ state: 'sent', attempts: t.attempts })
    const out = await postSol(dl, id, (ep) => sol.send(raw, slot, ticket, ep), a)   // E5: every verified endpoint, one ticket
    await emit({ type: 'clawback-sent', txId: id, outcome: journalOutcome('sol', out) })
    if (out.kind === 'rejected') throw new Error(`rejected by preflight: ${out.msg} — the bytes stay valid until their blockhash expires: still open, reconcile`)
    /** @type {any} */
    let done = null
    const r = await _solWait(t, a, { ...dl, finish: async (/** @type {any} */ _t, /** @type {any} */ landed) => { done = landed; return 'confirmed' } })
    if (r === 'confirmed' || r === 'failed') {
      const lid = r === 'confirmed' ? done.id : t.landedId
      /** @type {any} */
      let res = null
      for (let i = 0; i < 20 && !res; i++) { res = await sol.transferResult(lid, v.address).catch(() => null); if (!res) await sleepOf(d)(d.poll) }
      if (!res) throw new Error('claw back: landed, but its transaction cannot be read yet — still open; reconcile')
      if (res.err != null) {                                             // landed with an error: nothing moved, the fee was charged
        await emit({ type: 'clawback-failed', txId: lid, reason: journalText(`landed with error ${JSON.stringify(res.err)}`), fee: String(res.fee) })
        await emit({ type: 'reconcile', txId: lid, outcome: 'nonce-consumed' })   // its signature is used: it never lands again (frees the cap, S2 2fea217)
        throw new Error('claw back landed with an error (the fee was charged)')
      }
      if (res.received === null || res.received < 0n) throw new Error('claw back: landed, but the transfer to the destination cannot be measured — still open; reconcile')
      await emit({ type: 'clawback-included', txId: lid, value: String(res.received), fee: String(res.fee) })
      const laneAfter = await sol.solBalance(addr)
      const ok = res.received === (done?.amount ?? -1n) && laneAfter === 0n
      await emit({ type: 'clawback-readback', txId: lid, ok, destReceived: String(res.received), laneBalance: String(laneAfter) })
      return { ok, id: lid, amount: res.received, to: v.address, destReceived: res.received, laneBalance: laneAfter, attempts: t.attempts.length, delegated: false, warning: '', windowNote: '' }
    }
    if (r === 'unproven') {                                             // fix round 2 (M-4): after a Stop, the expiry could not be proven in bounded time
      await emit({ type: 'stuck', txId: id, reason: journalText(t.reason) })
      throw new Error(`claw back: ${t.reason}`)
    }
    if (r !== 'expired') throw new Error(`claw back ${r}: ${t.reason || ''} — the bytes may still land: still open, reconcile`)
    a.expired = true                                                    // proven expired on every endpoint → re-sign with a fresh blockhash
    await emit({ type: 'reconcile', txId: id, outcome: 'expired' })     // this member is dead (expiry proven, no signature status)
  }
  // every attempt's expiry was proven by the evidence gate and journaled (reconcile expired): every member is dead, so
  // the claw-back failed by itself (CC-2a, D-2) — no clawback-failed (that is for a claw-back that failed ON CHAIN)
  throw new Error('claw back: every attempt expired')
  } finally { ledger.close() }
}
// for tests: the gas rule this deps object selects
export { gasRuleOf as _gasRuleOf }

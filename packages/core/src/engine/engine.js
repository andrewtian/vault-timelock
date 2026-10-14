// @ts-check
// PORTED (R69) from the prototype, tag add7-00927d6ade7f, src/mainnet/engine.js (sha256 7b3aeeea62515cf1c8e31092ec6f2adeec1abe903626a0e5bd9a73a9c9f4fd86).
// Sequential sending per chain lane ("one after another, retried until exhausted"). Lanes run in parallel with each
// other; inside a lane tx k+1 is sent only after tx k is confirmed (ETH: receipt; SOL: confirmed).
// Retries can never double-publish:
//   ETH — only SAME-NONCE replacements (⌈+12.5 %⌉+1 wei on tip and maxFee) after 3 blocks without inclusion (at once
//         if the next base fee exceeds maxFee); ≤ 6 bumps per nonce; every hash of a nonce is tracked, whichever lands
//         is the record.
//   SOL — the same signed bytes are re-broadcast every 2 s; re-sign (new blockhash, CU price ×2) ONLY after evidence the
//         previous signature can never land: isBlockhashValid(its blockhash) is false (Efix3) AND the finalized height is past its lastValidBlockHeight AND
//         getSignatureStatuses(…, searchTransactionHistory:true) is null, on EVERY verified endpoint; any error, disagreement or
//         unreadable answer is no proof (wait, recheck, never re-sign).
// Re-broadcasting the identical signed bytes (same tx id) is never a new transaction.
// A tx stops as "exhausted" when the balance cannot cover the next attempt's reserved cost or after MAX_ATTEMPTS; the
// rest of the lane is then marked "not sent" (never silently dropped).
//
// Canonical changes (E2, spec §7.2 — the only behavioural edits):
//   · INTENT AWAITED: after signing and BEFORE the bytes leave, the engine journals the intent and awaits the API's
//     ack: `const ticket = (await o.journal.intent(ev)).ticket`. A rejection ends the attempt with nothing sent (the
//     attempt is not even recorded); the lane stops (JournalError, fail closed).
//   · TICKET CARRIED: every send (eth.send, sol.send, sol.rebroadcast) carries the attempt's relay send ticket
//     (gates/send.ts refuses a send without one: engine.no-ticket). A re-send of identical bytes refreshes the ticket
//     through journal.ticket(txId) when it is older than CANON.TICKET_REFRESH_MS (optional member).
//   · EVENTS JOURNALED: every former onEvent call is `await o.journal.append(ev)`; a rejection stops the lane
//     (JournalError). Events are flat: { type, chain, ...data } with data exactly the contract's (validateEvent):
//     the executor splits off type and chain. A journaled outcome closes an attempt only when its exact signed bytes
//     can never land (journalOutcome): `sent rejected` for an ETH consumed nonce or a consensus-invalid tx,
//     `reconcile expired` for a SOL attempt proven expired, included + readback(false) for a SOL tx that landed with an
//     error. Every other rejection is journaled `sent unknown` and an ETH nonce taken without a receipt of ours is
//     journaled `stuck`, so the attempt stays open: the next holder reconciles it and its cap ledger holds its fee
//     (E2 review I-1). Free text is cleaned by journalText (no key- or IP-like text reaches the API).
//   · CAP: every signature reserves its worst case (gas limit × maxFee; the exact SOL fee) in the lane's CapLedger
//     (gates/caps.ts, built from the ARMED job state) before signing, keyed by its (copy, part); the ledger observes
//     every event jappend / jintent journal (after the ack), so a landed tx settles its actual fee, a dead attempt is
//     released, and a ledger rebuilt from the journal equals the live one (security review: cap-ledger drift). No
//     ledger, no signature (engine.cap-ledger); over the cap → the tx ends exhausted before anything is signed.
//   · GAS: ethTx needs o.gasRule (fork + recipient, plan.js) — the estimate is checked against the exact formula.
//   · POLICIES: o.policy may also be Passive (initial → {wait} before anything is signed; noEscalate: a stall keeps
//     the same bytes and rebroadcasts them, replaceAfterBlocks 25) or price SOL in lamports per tx ({ lamports }).
//   · ENDPOINT AGREEMENT (E5): every SOL send and rebroadcast goes to every verified endpoint with the same ticket
//     (postSol); the ETH nonce quorum and the EIP-7702 check are taken where a lane or claw-back reads its nonce
//     (lane.js, gates/agree.ts).
//   · ADOPTED ETH ATTEMPTS (PF-E, pre-flip review I-2): an attempt adopted at a takeover gets its signed bytes back by a
//     deterministic rebuild (ethRebuild: the journaled nonce, recipient, gas, tip and maxFee, the network's chain id and the
//     planned payload; RFC 6979 signing), kept only when keccak256 is the journaled tx id; before those bytes first leave,
//     the send ticket must bind exactly them (the journaled rawSha256, payloadSha256, tx id and nonce: adoptedSendWhy). A
//     Passive lane rebroadcasts them like its own; bytes it cannot rebuild are journaled `stuck` with the exact reason (it
//     never signs another tx at that nonce by itself). Passive windows are bounded (windowEnd): an attempt not known to
//     every verified endpoint (fix round 2), its nonce unused, for CANON.PASSIVE_ETH_UNSEEN_WINDOWS windows in a row is journaled
//     `stuck` (vt job resolve), and a Stop ends the lane at the end of the window — `stopped` with the attempt still
//     pending at the nodes, or `stuck` when no endpoint knows it. Never an endless wait.
import { formatEther, formatGwei, hexToBytes, toHex } from 'viem'
import { base64, base64urlnopad } from '@scure/base'
import { CANON, ETH, SOL } from '../chains/constants.js'
import { formatUnits, replacementFees, solResignPrice } from '../chains/plan.js'
import { RelayRefused, RpcError, TransportError } from './rpc.js'
import * as eth from '../chains/eth.js'
import * as sol from '../chains/sol.js'
import { TICKET_PREFIX, isRefusal } from '../contracts/index.ts'
import { ledgerOf, observeLedger } from '../gates/caps.ts'
import { sha256Hex } from '../job/canonical.ts'
import { assertNoSecretOrIp } from '../job/keylike.ts'

const ALREADY = /already known|known transaction|AlreadyProcessed|already been processed/i
/** @typedef {any} LaneTx A lane tx (plan entry + attempts + state); see the header. @typedef {any} EngineOpts */
/** @typedef {{ type: string, chain: 'eth' | 'sol' | 'btc', [k: string]: unknown }} EngineEvent flat: the executor splits off type and chain */
/** @typedef {{ intent(ev: EngineEvent): Promise<{ ticket: string }>, append(ev: EngineEvent): Promise<void>, ticket?(txId: string): Promise<string> }} EngineJournal */
const sleep = (/** @type {number} */ ms) => new Promise((r) => setTimeout(r, ms))
// The clock seam (E3 ruling 5): o.clock = { now(), sleep(ms) } — the executor passes its adapter clock, tests a fake one
// (the SOL expiry proof's 2 s polls and 4 s confirmation run instantly). Without it, the wall clock.
const nowOf = (/** @type {any} */ o) => (o?.clock ? o.clock.now() : Date.now())
const waitOf = (/** @type {any} */ o, /** @type {number} */ ms) => (o?.clock ? o.clock.sleep(ms) : sleep(ms))
const spent = (/** @type {any} */ lane) => (lane?.txs || []).reduce((/** @type {bigint} */ a, /** @type {any} */ t) => a + (t.landedId && t.actual != null ? t.actual : 0n), 0n)
export const short = (/** @type {any} */ e) => String(e?.shortMessage || e?.message || e).replace(/\s+/g, ' ').slice(0, 240)
const fmtSol = (/** @type {bigint} */ l) => `${formatUnits(l, 9)} SOL`

// ---------- the journal seam (spec §7.2) ----------
// A journal call that fails (no journal, a refusal by the API, a lost lease, a dead API) stops the lane: nothing more
// is signed or sent. JournalError is never retried as an RPC error.
export class JournalError extends Error {
  /** @param {string} m */
  constructor(m) { super(m); this.name = 'JournalError' }
}
/** @param {unknown} e */
const fatal = (e) => e instanceof JournalError || isRefusal(e)
/** @param {unknown} e */
const rethrowFatal = (e) => { if (fatal(e)) throw e }
/** @param {EngineOpts} o @param {EngineEvent} ev */
export async function jappend(o, ev) {
  try { await o.journal.append(ev) } catch (e) { if (isRefusal(e) && e.guardId === 'engine.btc-open') throw e   // the shared gate: a btc chain with a commit and no reveal is never ended
    throw new JournalError(`journal append (${ev.type}) failed — the lane stops (fail closed): ${short(e)}`) }
  observeLedger(o, ev)                                                    // the cap ledger follows the journal (gates/caps.ts)
}
/** @param {EngineOpts} o @param {EngineEvent} ev @returns {Promise<string>} the relay send ticket */
export async function jintent(o, ev) {
  /** @type {any} */
  let r
  try { r = await o.journal.intent(ev) } catch (e) { throw new JournalError(`${ev.type} not acked — nothing was sent: ${short(e)}`) }
  observeLedger(o, ev)                                                    // the reservation becomes this attempt's hold
  return r?.ticket
}
// A stored ticket is refreshed (journal.ticket) before re-sending identical bytes once it is CANON.TICKET_REFRESH_MS old.
/** @param {any} a @param {EngineOpts} o @returns {Promise<string | undefined>} */
export async function ticketFor(a, o) {
  if (typeof o.journal?.ticket === 'function' && nowOf(o) - (a.ticketAt ?? 0) >= CANON.TICKET_REFRESH_MS) {
    try { a.ticket = await o.journal.ticket(a.id) } catch (e) { throw new JournalError(`send ticket refresh failed — nothing re-sent: ${short(e)}`) }
    a.ticketAt = nowOf(o)
  }
  return a.ticket
}
// Free text for the journal (reasons, details): one line, ≤ max characters, ids and URLs elided, and never anything the
// API's body check would refuse as key- or IP-like (it would refuse the whole event and stop the lane).
/** @param {unknown} s @param {number} [max] */
export function journalText(s, max = 512) {
  const t = String(s ?? '').replace(/\s+/g, ' ').replace(/[a-z][a-z0-9+.-]*:\/\/\S*/gi, '<url>').replace(/(?:0x)?[0-9a-fA-F]{24,}/g, '<hex>')
    .replace(/[1-9A-HJ-NP-Za-km-z]{32,}/g, '<id>').slice(0, max)
  try { assertNoSecretOrIp(t, 'text') } catch { return '(detail withheld: it looked key- or IP-like)' }
  return t
}
// E2 review I-1: the outcome a `sent` (or `clawback-sent`) journals. `rejected` closes the attempt for the next holder,
// so it is written only when those exact signed bytes can never be included: an ETH nonce already used ("nonce too low")
// or a tx invalid by consensus (gas below the intrinsic or the EIP-7623 floor gas). Any other rejection — a pool rule
// (underpriced, insufficient funds), a SOL preflight hiccup or failure (the bytes stay valid until their blockhash
// expires, and the engine itself may rebroadcast them) — is `unknown`: the attempt stays open.
const ETH_DEAD = /nonce too low|intrinsic gas too low|floor data gas/i
/** @param {'eth' | 'sol'} chain @param {{ kind: string, msg: string }} out @returns {'accepted' | 'unknown' | 'rejected'} */
export const journalOutcome = (chain, out) => (out.kind === 'accepted' ? 'accepted' : out.kind === 'rejected' && chain === 'eth' && ETH_DEAD.test(out.msg) ? 'rejected' : 'unknown')
const rawEth = (/** @type {string} */ raw) => sha256Hex(hexToBytes(/** @type {`0x${string}`} */ (raw)))
const rawSol = (/** @type {string} */ raw) => sha256Hex(base64.decode(raw))
const msSince = (/** @type {number | null | undefined} */ at, /** @type {number} */ now) => (at ? Math.max(0, now - at) : 0)

/** @param {() => Promise<unknown>} fn @returns {Promise<{ kind: 'accepted' | 'rejected' | 'unknown', msg: string }>} */
async function post(fn) {
  try { await fn(); return { kind: 'accepted', msg: '' } } catch (e) {
    rethrowFatal(e)                                                       // engine.no-ticket: nothing left; stop the lane
    if (e instanceof RpcError && ALREADY.test(e.message)) return { kind: 'accepted', msg: 'node: already known' }
    if (e instanceof RpcError || e instanceof RelayRefused) return { kind: 'rejected', msg: short(e) }
    return { kind: 'unknown', msg: short(e) }
  }
}
// E5 (spec: SOL sends go to every verified endpoint with the same ticket): the identical signed bytes — one txId — go
// to each verified SOL endpoint (/relay/sol/ep/<i>, o.solEndpoints ≥ 2; else the preferred route), in parallel, so one
// endpoint that drops or never forwards them cannot hold a part back. Every answer must name OUR signature: another
// one is no definitive answer. Combined: accepted when any endpoint accepted (the bytes are in flight); else unknown when
// any answer was not definitive; else rejected — with a node-side hiccup's message when any endpoint gave one, so the
// same bytes are rebroadcast and never declared dead on one endpoint's word.
// Security review (rescue path): when the RELAY ITSELF refused a per-endpoint send (RelayRefused: before forwarding,
// nothing left the machine — today's relay.mjs refuses every send on /ep/<i>) and no endpoint accepted, the same bytes
// with the same ticket also go through the preferred route (the pre-E5 path) and its answer counts like any other. So no
// SOL send — a part, a rebroadcast, the claw-back that rescues the remainder — depends on per-endpoint sends existing.
// Sfix1 (the relay takes one ticket ONCE per endpoint: a repeat is refused relay.ticket-endpoint-reused): an attempt's
// ticket makes ONE per-endpoint round (att.epRound remembers which ticket did); later sends of the same bytes under that
// ticket — the 2 s rebroadcasts — go through the preferred route only. A fresh ticket (ticketFor, about every
// CANON.TICKET_REFRESH_MS) gets a new round.
const SOL_RETRY = /blockhash ?not ?found|node is behind|behind by|minContextSlot|minimum context slot/i
/** @param {EngineOpts} o @param {string} txId @param {(ep: number | null) => Promise<unknown>} fn @param {{ ticket?: string, epRound?: string } | null} [att] the attempt (its current ticket) @returns {Promise<{ kind: 'accepted' | 'rejected' | 'unknown', msg: string }>} */
export async function postSol(o, txId, fn, att = null) {
  const eps = Math.max(1, o.solEndpoints || 1)
  const ticket = typeof att?.ticket === 'string' ? att.ticket : null
  const fan = eps > 1 && !(ticket !== null && att?.epRound === ticket)
  const one = async (/** @type {number | null} */ ep) => {
    let refused = false
    const out = await post(async () => {
      try { const r = await fn(ep); if (r !== txId) throw new TransportError(`endpoint ${ep ?? 0} answered another signature`) } catch (e) { refused = e instanceof RelayRefused; throw e }
    })
    return { ...out, refused }
  }
  const outs = await Promise.all(fan ? Array.from({ length: eps }, (_, i) => one(i)) : [one(null)])
  if (fan && att && ticket !== null) att.epRound = ticket
  const fellBack = fan && !outs.some((x) => x.kind === 'accepted') && outs.some((x) => x.refused)
  if (fellBack) outs.push(await one(null))
  // planE5 m-3 (Efix3, security finding single-endpoint trust): MIXED answers are not a rejection. When one endpoint gives a
  // definitive preflight rejection (a program error, insufficient funds: not a hiccup, not the relay refusing) and another a
  // node-side hiccup, nothing accepted and nothing proves the bytes dead: the result is `unknown` (the attempt stays open and is
  // tracked by signature; re-sign only after the expiry proof) — never `rejected`, which would fail/expire the part on ONE
  // endpoint's word. `rejected` needs every answering route to reject (a refusal of the relay itself counts only when the
  // fallback ran and refused too). The residual (a rebroadcast of bytes one endpoint calls failing) is bounded by that expiry.
  // planE5 m-2: when every route refused, the reason is the fallback's (the preferred route's own refusal: the job-send lock,
  // a ticket refusal), not endpoint 0's "sends go through /relay/<chain> only".
  const live = outs.filter((x) => !x.refused)
  const hiccup = live.find((x) => SOL_RETRY.test(x.msg)), definitive = live.find((x) => !SOL_RETRY.test(x.msg))
  const r = outs.find((x) => x.kind === 'accepted') ?? outs.find((x) => x.kind === 'unknown')
    ?? (hiccup && definitive ? { kind: 'unknown', msg: `endpoints disagree (${definitive.msg} / ${hiccup.msg}) — tracking by signature` } : null)
    ?? hiccup ?? definitive ?? outs[fellBack ? outs.length - 1 : 0]
  return { kind: r.kind, msg: r.msg }
}
/** @param {any} lane @param {number} k @param {string} why @param {() => void} notify */
function stopRest(lane, k, why, notify) {
  for (let j = k + 1; j < lane.txs.length; j++) if (lane.txs[j].state !== 'confirmed') Object.assign(lane.txs[j], { state: 'not-sent', reason: `lane stopped at tx #${k + 1} (${why})` })
  lane.stopped = { at: k, why }; notify()
}
// The R60 cap at a signature (gates/caps.ts CapLedger.reserve, keyed by the tx's (copy, part) like the journal): null
// when reserved, else the refusal's reason.
/** @param {import('../gates/caps.ts').CapLedger} L @param {{ copy: unknown, part: unknown }} t @param {bigint} worst */
function capRefusal(L, t, worst) {
  try { L.reserve(t, worst); return null } catch (e) { if (isRefusal(e) && e.guardId === 'engine.cap') return e.message; throw e }
}

// ---------- PF-E (pre-flip review I-2): adopted ETH attempts ----------
// An attempt that may still land: one this lane signed and was not proven dead, or one adopted OPEN at a takeover (an attempt adopted
// only as a claim — journaled rejected, marked failed — has open: false: it is not in flight and the API takes no `stuck` for it).
const liveAttempt = (/** @type {any} */ x) => !x.dead && x.open !== false
// The bytes of an attempt adopted at a takeover, rebuilt from its journaled intent: nonce, recipient, gas, tip, maxFee, the network's
// chain id, and data = the PLANNED payload of its (copy, part) (the lane's own planner). Signing is RFC 6979 deterministic, so an
// honest earlier holder's bytes come back exactly; they are kept only when keccak256(raw) is the journaled tx id (it covers every
// byte of a type-2 tx) and the recipient is this lane's. The journaled rawSha256 is compared before the bytes first leave
// (adoptedSendWhy). { why } otherwise: the attempt is watched, never re-sent, and a Passive lane journals it stuck.
/** @param {any} account @param {number} chainId @param {{ id: string, gas: bigint, tip: bigint, maxFee: bigint, to: string }} x
 * @param {number} nonce @param {Uint8Array} payload @param {string} laneTo @returns {Promise<{ raw: string } | { why: string }>} */
export async function ethRebuild(account, chainId, x, nonce, payload, laneTo) {
  if (String(x.to).toLowerCase() !== String(laneTo).toLowerCase()) return { why: 'its journaled recipient is not this lane\'s recipient' }
  try {
    const s = await eth.sign(account, chainId, { nonce, to: x.to, data: toHex(payload), gas: x.gas, maxFee: x.maxFee, tip: x.tip })
    if (s.id.toLowerCase() === String(x.id).toLowerCase()) return { raw: s.raw }
    return { why: 'rebuilt from its journaled intent (nonce, recipient, gas, tip, maxFee, chain id) and the planned payload, its keccak256 is not the journaled tx id: the journaled attempt is not the planned tx' }
  } catch (e) { return { why: `it cannot be rebuilt from its journaled intent (${short(e)})` } }
}
// What a relay send ticket binds (contracts/http.ts: TICKET_PREFIX + b64url(JSON payload) + '.' + MAC; only the relay checks the MAC,
// the payload is read here): t the tx id, r the sha256 of the raw bytes, p the payload digest, q the declared nonce, and for a
// claw-back to / value — all from the JOURNALED intent (the API mints them from it). null when it does not decode.
/** @param {unknown} ticket @returns {{ t: unknown, r: unknown, p: unknown, q: unknown, to: unknown, value: unknown } | null} */
export function ticketBinds(ticket) {
  try {
    if (typeof ticket !== 'string' || !ticket.startsWith(TICKET_PREFIX)) return null
    const j = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(base64urlnopad.decode(ticket.slice(TICKET_PREFIX.length).split('.')[0])))
    return j !== null && typeof j === 'object' ? { t: j.t, r: j.r, p: j.p, q: j.q, to: j.to, value: j.value } : null
  } catch { return null }
}
// Rebuilt bytes leave only under a ticket that binds exactly them: the journaled rawSha256 (the reduced state carries it for btc attempts
// only, CC-12, so it comes through the ticket the API mints for that intent), tx id, payloadSha256 (the relay checks it against the
// calldata) and nonce. null: they may go; else why not (the relay would refuse them for ever).
/** @param {any} a @param {string} raw @param {unknown} ticket @param {LaneTx} t @returns {string | null} */
function adoptedSendWhy(a, raw, ticket, t) {
  const b = ticketBinds(ticket)
  if (b === null) return 'its send ticket does not decode, so the journaled rawSha256 cannot be compared'
  if (b.t !== a.id) return 'its send ticket names another tx id'
  if (b.r !== rawEth(raw)) return 'the sha256 of the rebuilt bytes is not the journaled rawSha256'
  if (b.p !== sha256Hex(t.payload)) return 'the journaled payloadSha256 is not the planned payload\'s digest'
  if (b.q !== String(t.nonce)) return 'its send ticket declares another nonce'
  return null
}
const attemptAt = (/** @type {LaneTx} */ t, /** @type {any} */ a) => `copy ${t.copy} part ${t.part}: attempt ${a.n ?? t.attempts.indexOf(a) + 1} (nonce ${t.nonce})`
const resolveHint = 'look it up on the chain, then record the truth with vt job resolve (mark-done if it landed, mark-failed if it never will); the chain is then stopped and can be clawed back'
// The part cannot go on by itself: every attempt of it that may still land is journaled `stuck` with the exact reason (the chain is
// STUCK until the operator resolves it); nothing new is signed at that nonce. The lane ends ('stuck': runDrain journals `stopped`).
/** @param {LaneTx} t @param {EngineOpts} o @param {string} why @returns {Promise<string>} */
async function ethStuck(t, o, why) {
  Object.assign(t, { state: 'stuck', reason: why }); o.notify()
  for (const x of t.attempts) if (liveAttempt(x)) await jappend(o, { type: 'stuck', chain: 'eth', txId: x.id, reason: journalText(why) })
  return 'stuck'
}
// The end of a window (replaceAfterBlocks without inclusion; the nonce was unused at the last poll) of a lane that keeps the same bytes —
// Passive, an economy `wait`, any lane after a Stop (no strategy signs anything new then), a watch-only run of a settled chain. Fix
// round 2 (M-6): the attempt counts as seen only when EVERY verified endpoint answers that it knows it (eth.knownByEvery: one endpoint's
// word, the preferred route's poll or a rebroadcast it took, is never enough; on mainnet that is ≥ 2 agreeing). An attempt not seen is
// UNSEEN: after CANON.PASSIVE_ETH_UNSEEN_WINDOWS unseen windows in a row, or at a Stop, it is journaled stuck (vt job resolve). A Stop with
// it seen ends the lane `stopped`, the attempt open; a watch-only run (fix round 2, I-1) ends so after that many windows. null: next window.
/** @param {LaneTx} t @param {any} a @param {EngineOpts} o @param {bigint} after @returns {Promise<string | null>} */
async function windowEnd(t, a, o, after) {
  const k = await eth.knownByEvery(a.id, o.ethEndpoints)
  a.unseen = k.known ? 0 : (a.unseen ?? 0) + 1
  a.windows = (a.windows ?? 0) + 1
  const stop = !!o.stopRequested?.(), at = attemptAt(t, a), N = CANON.PASSIVE_ETH_UNSEEN_WINDOWS
  // R79: a detach (requestStop alone) escalates nothing: the attempt stays open for the next executor, which reconciles it
  const detach = stop && o.detachOnly?.() === true
  if (!k.known && stop && !detach) return ethStuck(t, o, `stopped by the operator while ${at} is not known to every verified endpoint (${k.why}) and its nonce is unused — nothing else is signed at that nonce; ${resolveHint}`)
  if (!k.known && a.unseen >= N) {
    return ethStuck(t, o, `${at} is not known to every verified endpoint (${k.why}) after ${a.unseen} windows of ${after} blocks of same-bytes rebroadcasts, its nonce unused — it was dropped and is not taken again; nothing else is signed at that nonce; ${resolveHint}`)
  }
  if (stop && detach) { Object.assign(t, { state: 'pending', pendingAtStop: true, reason: `${at} stays open (${k.known ? 'pending at the nodes' : `not known to every verified endpoint: ${k.why}`}) — nothing new is signed; the next run reconciles it` }); o.notify(); return 'stopped' }
  if (stop) { Object.assign(t, { state: 'pending', pendingAtStop: true, reason: `${at} is still pending at the nodes and may land — nothing new is signed; run the job again to watch it (a claw-back waits until it resolves)` }); o.notify(); return 'stopped' }
  if (o.watchOnly && a.windows >= N) { Object.assign(t, { state: 'pending', pendingAtStop: true, reason: `${at} is still pending at every verified endpoint after ${a.windows} windows of ${after} blocks — nothing new is signed; run the job again later to watch it` }); o.notify(); return 'stopped' }
  return null
}

// ============================== Ethereum ==============================
/** @param {any} lane @param {EngineOpts} o */
export async function runEthLane(lane, o) {
  const addr = o.account.address
  lane.stopped = null
  const first = lane.txs.findIndex((/** @type {any} */ t) => t.state !== 'confirmed')
  if (first < 0) return
  const [latest, pending] = await Promise.all([eth.nonceAt(addr, 'latest'), eth.nonceAt(addr, 'pending')])
  if (lane.txs[first].nonce == null && pending !== latest) return stopRest(lane, first - 1, `account has ${pending - latest} pending tx(s) — refusing to queue behind them`, o.notify)
  let next = lane.txs[first].nonce ?? pending
  for (let k = first; k < lane.txs.length; k++) {
    if (k > first && o.stopRequested?.()) return stopRest(lane, k - 1, 'stopped by the operator after the previous tx', o.notify)
    const t = lane.txs[k]
    t.nonce ??= next
    const r = await ethTx(t, { ...o, lane })
    if (r !== 'confirmed') return stopRest(lane, k, r, o.notify)
    next = t.nonce + 1
  }
}
// o.policy (R64 drain, optional): { fees() → {nextBase, tip0, …}, initial(f) → {tip,maxFee}|{pause}|{wait}, bump(prev, f) → {tip,maxFee}|{pause}|{wait},
//   ready?(f) → null | why-not-yet, waitPollMs?, noEscalate?, replaceAfterBlocks? } — Passive: ready() holds the first
//   attempt (nothing estimated or signed) until the base fee is at the target; bump returns {wait} (the same bytes stay). Without a policy: the classic copies-mode fees (p50 tip, ×1.125
//   bumps, ≤ 6 bumps). o.journal receives the discrete events (spec §7.2); o.gasRule is required.
/** @param {LaneTx} t @param {EngineOpts} o @returns {Promise<string>} */
export async function ethTx(t, o) {
  const { account, chainId, notify, alive, poll, tipCap } = o, addr = account.address, P = o.policy
  const ledger = ledgerOf(o)                                              // the armed spend cap; no ledger, no signature
  if (!o.gasRule) throw new Error('ethTx: no gas rule (the network fork and the recipient) — fail closed')
  const to = o.to ?? addr
  t.attempts ??= []; t.raws ??= {}; t.firstAt ??= null
  const landed = async () => { for (const a of t.attempts) { const r = await eth.receipt(a.id); if (r) return { r, a } } return null }
  let errs = 0, waiting = false
  for (;;) {
    if (!alive()) return 'aborted'
    // ---- A: prepare, sign, journal the intent (awaited), show, send (no attempt is created unless signed AND acked) ----
    /** @type {any} */ let a, /** @type {any} */ raw, reuse = false, held = false   // held: this round keeps the same signed bytes (Passive, an economy `wait`, a Stop, a watch)
    try {
      const L = await landed(); if (L) return ethFinish(t, L, o)
      if (!P && t.attempts.length > ETH.MAX_BUMPS) return ethExhaust(t, `${ETH.MAX_BUMPS} fee bumps without inclusion`, o)
      if ((await eth.nonceAt(addr, 'latest')) > t.nonce) return await ethNonceGone(t, o, landed)
      // PF-E: a lane that never escalates (Passive) keeps alive the newest attempt that may still land; an attempt adopted only as a
      // claim (not open) is not in flight, so with none open the part is signed afresh in that nonce family (`replaces` the claim, m-3)
      const last = t.attempts.at(-1), live = [...t.attempts].reverse().find(liveAttempt), prev = P?.noEscalate ? live : last
      // PF-E fix 1 (5): a Stop means NO new signature, whatever the strategy — no next attempt, no fee bump, no replacement, not even
      // for a part whose only attempts are claims. The attempt in flight keeps its signed bytes (sent again as they are) until the end
      // of its window (windowEnd: it lands, or `stopped` while it is pending, or `stuck` when no endpoint knows it).
      // Fix round 2 (I-1): a watch-only run (a settled chain whose ETH attempt is still open: lane.js watchAdoptedEth) never signs either.
      const stopping = !!o.stopRequested?.() || o.watchOnly === true
      if (stopping) {
        if (live === undefined) { Object.assign(t, { state: 'not-sent', reason: last === undefined ? 'stopped before this part was signed' : 'stopped: nothing of this part is in flight (its journaled attempts are claims: rejected or marked failed); nothing new is signed' }); notify(); return 'stopped' }
        a = live; raw = t.raws[live.id]; reuse = true; held = true; t.note = o.watchOnly ? 'watching the open transaction: its same signed bytes only, nothing new is signed' : 'stop requested: nothing new is signed; the transaction in flight keeps its signed bytes until the end of its window'; notify()
        if (raw === undefined && !!o.stopRequested?.() && o.detachOnly?.() === true) { Object.assign(t, { state: 'pending', pendingAtStop: true, reason: `${attemptAt(t, live)} stays open (${live.unbuilt ?? 'its signed bytes are not held here'}) — nothing new is signed; the next run reconciles it` }); notify(); return 'stopped' }   // R79: a detach escalates nothing
        if (raw === undefined) return await ethStuck(t, o, `${o.watchOnly ? 'the chain is settled and' : 'stopped by the operator:'} ${attemptAt(t, live)} cannot be sent again (${live.unbuilt ?? 'its signed bytes are not held here'}) and nothing new is signed${o.watchOnly ? '' : ' after a Stop'}; ${resolveHint}`)
      }
      if (!stopping) {
        const f = P ? await P.fees() : await eth.fees(tipCap)
        const notYet = !prev && P?.ready ? P.ready(f) : null              // Passive: nothing is signed (or estimated) until the base fee is at the target
        if (notYet) {
          if (o.stopRequested?.()) { Object.assign(t, { state: 'not-sent', reason: `stopped while waiting (${notYet})` }); notify(); return 'stopped' }
          if (!waiting) { waiting = true; await jappend(o, { type: 'paused', chain: 'eth', reason: journalText(notYet) }) }
          Object.assign(t, { state: 'waiting', note: notYet }); notify(); await waitOf(o, Math.max(poll, P.waitPollMs ?? 0)); continue
        }
        const q = await eth.quote(addr, t.payload, f, to, o.gasRule)
        if (!q.check.ok) return ethExhaust(t, q.check.why, o)
        const gas = /** @type {bigint} */ (prev && prev.gas > q.gasLimit ? prev.gas : q.gasLimit)
        const bal = await eth.balance(addr)
        /** @type {any} */
        let fee
        if (P) {
          fee = prev ? P.bump(prev, { ...f, balance: bal, gas }) : P.initial(f, { balance: bal, gas })
          if (fee.pause) { const r = await ethPaused(t, fee.pause, o, landed); if (r === 'resume' || r === 'stop') continue; return r }
          if (fee.wait && !prev) { await waitOf(o, poll); continue }       // the base fee rose between the two reads: wait again
          if (fee.wait) {
            // Fix round 2 (M-5): an economy `wait` (a bump would not fit the balance) keeps its bytes like Passive: re-sent, windowEnd-bounded
            a = prev; raw = t.raws[prev.id]; reuse = true; held = true; t.note = fee.wait; notify()
            // PF-E: these very bytes are the only way forward now: an adopted attempt whose bytes could not be rebuilt is stuck
            if (raw === undefined) return await ethStuck(t, o, `copy ${t.copy} part ${t.part}: attempt ${prev.n ?? t.attempts.length} (adopted at the takeover, nonce ${t.nonce}) cannot be rebroadcast: ${prev.unbuilt ?? 'its signed bytes are not held here'} — nothing else is signed at that nonce; ${resolveHint}`)
          }
        } else fee = prev ? replacementFees(prev, q) : { tip: q.tip, maxFee: q.maxFee }
        if (!reuse) {
          const { tip, maxFee } = fee, reserved = gas * maxFee
          if (bal < reserved) {
            if (P && !prev) { Object.assign(t, { state: 'planned', reason: `balance ${formatEther(bal)} ETH < reserved ${formatEther(reserved)} ETH` }); notify(); return 'unaffordable' }
            return ethExhaust(t, `balance ${formatEther(bal)} ETH < reserved ${formatEther(reserved)} ETH for ${prev ? 'a replacement' : 'this tx'}`, o)
          }
          await o.refreshStop?.()                                              // fix round 2 (M-3): the API's stop state, read before EVERY new signature (bumps too)
          if (o.stopRequested?.()) continue                                    // PF-E fix 1: a Stop that came while this tx was prepared: nothing is signed
          const over = capRefusal(ledger, t, reserved)                        // R60 hard cap: spent + held + this attempt's gasLimit × maxFee
          if (over !== null) return ethExhaust(t, over, o)
          const signed = await eth.sign(account, chainId, { nonce: t.nonce, to, data: q.data, gas, maxFee, tip })
          const id = signed.id.toLowerCase(), attempt = t.attempts.length + 1
          // PF-E: the very bytes of an attempt already journaled (a claim adopted at the takeover, signed at the same fees): never a second
          // intent for them (event.duplicate) — nothing new can be sent at that nonce, so the part ends here
          if (t.attempts.some((/** @type {any} */ x) => x.id === id)) { Object.assign(t, { state: 'failed', reason: `copy ${t.copy} part ${t.part}: the tx this lane would sign at nonce ${t.nonce} is byte for byte an attempt already journaled (not open: rejected or marked failed) — nothing new is signed at that nonce; claw back, or resolve and run again later at other fees` }); notify(); return 'failed' }
          const ticket = await jintent(o, { type: 'intent', chain: 'eth', txId: id, copy: t.copy, part: t.part, parts: t.parts, attempt, replaces: (prev ?? last)?.id ?? null,
            rawSha256: rawEth(signed.raw), payloadSha256: sha256Hex(t.payload), reserved: String(reserved),
            eth: { nonce: t.nonce, tip: String(tip), maxFee: String(maxFee), gas: String(gas), to } })   // journaled + acked BEFORE broadcast
          if (waiting) { waiting = false; await jappend(o, { type: 'resumed', chain: 'eth', reason: 'the base fee reached the target' }) }
          raw = signed.raw
          a = { id, gas, tip, maxFee, reserved, estimate: q.estimate, rule: q.check.rule, at: nowOf(o), tight: !!fee.tight, ticket, ticketAt: nowOf(o) }
          t.attempts.push(a); t.raws[a.id] = raw; t.firstAt ??= a.at
          Object.assign(t, { state: prev ? 'replacing' : 'signed', id: a.id, reserved, note: `gas ${gas} (estimate ${q.estimate} = ${q.check.rule}) · tip ${formatGwei(tip)} · maxFee ${formatGwei(maxFee)} gwei${fee.tight ? ' (tight final copy: waits for the base fee to fall)' : ''}` })
          await notify({ paint: true })                                  // tx id on screen BEFORE the bytes leave the page
        }
      }
    } catch (e) { rethrowFatal(e); errs++; t.note = `RPC error ${errs}: ${short(e)}`; notify(); if (errs >= 30) return ethExhaust(t, 'RPC unavailable (30 consecutive errors)', o); await waitOf(o, poll); continue }
    errs = 0
    /** @type {{ kind: string, msg: string }} */
    let out = reuse ? { kind: 'accepted', msg: '' } : await post(() => eth.send(raw, a.ticket))
    if (!reuse) {
      const outcome = journalOutcome('eth', out)
      if (outcome === 'rejected') a.dead = true                          // these bytes can never land
      await jappend(o, { type: 'sent', chain: 'eth', txId: a.id, outcome, reason: out.kind === 'accepted' ? null : journalText(out.msg) })
      if (out.kind !== 'rejected' && t.attempts.length > 1) await jappend(o, { type: 'replaced', chain: 'eth', txId: a.id, prevId: t.attempts.at(-2).id, reason: 'stall: same-nonce replacement' })
    }
    if (out.kind === 'rejected') {
      if (/nonce too low/i.test(out.msg)) return await ethNonceGone(t, o, landed)
      if (/insufficient funds|intrinsic gas too low|floor data gas|oversized data/i.test(out.msg)) return ethExhaust(t, out.msg, o)
      Object.assign(t, { state: 'retrying', reason: `attempt ${t.attempts.length} rejected before acceptance: ${out.msg}` }); notify(); await waitOf(o, poll); continue
    }
    Object.assign(t, { state: out.kind === 'unknown' ? 'unknown' : 'sent', reason: out.kind === 'unknown' ? `no definitive answer (${out.msg}) — tracking by tx id` : t.reason })
    notify()
    // ---- B: wait up to REPLACE_AFTER_BLOCKS for any of this nonce's hashes (bump at once if the base fee overtakes;
    //      Passive never escalates: it rebroadcasts the same bytes when the pool dropped them, every replaceAfterBlocks) ----
    const after = P?.replaceAfterBlocks ?? ETH.REPLACE_AFTER_BLOCKS
    /** @type {bigint | null} */
    // seen: in this window a poll found the attempt known, or a node took a same-bytes rebroadcast (accepted, or "already known": some
    // providers never show a pending tx by hash); blind: failed status checks in a row after a Stop
    let start = null, blind = 0
    for (;;) {
      await waitOf(o, poll); if (!alive()) return 'aborted'
      try {
        start ??= await eth.blockNumber()
        const L = await landed(); if (L) return ethFinish(t, L, o)
        if (raw && (t.state === 'unknown' || P?.noEscalate || held || o.stopRequested?.())) {   // PF-E fix 1/2: held or after a Stop, every strategy re-sends the same bytes
          if (!(await eth.known(a.id))) {                                // the same signed bytes again (never a new tx); whether it is SEEN is windowEnd's
            const ticket = await ticketFor(a, o)
            // PF-E: rebuilt bytes of an adopted attempt leave only under a ticket that binds exactly them (the journaled rawSha256, …)
            const bad = a.adopted === true && a.bound !== true ? adoptedSendWhy(a, raw, ticket, t) : null
            if (bad !== null) {
              a.unbuilt = bad; delete t.raws[a.id]; raw = undefined             // never sent: watched only
              // R79b (M-2): a detach escalates nothing — the attempt stays open (nothing journaled); the next run handles it
              if (o.stopRequested?.() && o.detachOnly?.() === true) { Object.assign(t, { state: 'pending', pendingAtStop: true, reason: `${attemptAt(t, a)} stays open (${bad}) — nothing new is signed; the next run reconciles it` }); notify(); return 'stopped' }
              if (P?.noEscalate || held || o.stopRequested?.()) return await ethStuck(t, o, `copy ${t.copy} part ${t.part}: attempt ${a.n ?? t.attempts.length} (adopted at the takeover, nonce ${t.nonce}) cannot be rebroadcast: ${bad} — nothing else is signed at that nonce; ${resolveHint}`)
            } else {
              a.bound = true
              out = await post(() => eth.send(raw, ticket))
              if (out.kind === 'accepted' && t.state !== 'sent') { Object.assign(t, { state: 'sent', reason: '' }); await jappend(o, { type: 'sent', chain: 'eth', txId: a.id, outcome: 'accepted', reason: null }) }
            }
          }
        }
        if ((await eth.nonceAt(addr, 'latest')) > t.nonce) return await ethNonceGone(t, o, landed)
        const [bn, f] = await Promise.all([eth.blockNumber(), eth.fees(tipCap)])
        t.note = `attempt ${t.attempts.length}: ${bn - start} of ${after} blocks without inclusion · next base ${formatGwei(f.nextBase)} gwei`; notify()
        if (!P?.noEscalate && !held && !o.stopRequested?.() && f.nextBase > a.maxFee) { Object.assign(t, { state: 'replacing', reason: `next base fee ${formatGwei(f.nextBase)} > maxFee ${formatGwei(a.maxFee)} gwei → replacement now` }); notify(); break }
        if (bn >= start + after) {
          if (P?.noEscalate || held || o.stopRequested?.()) { const r = await windowEnd(t, a, o, after); if (r !== null) return r }   // PF-E: bounded; a Stop applies here (every strategy)
          Object.assign(t, { state: 'replacing', reason: P?.noEscalate ? `attempt ${t.attempts.length} not mined within ${after} blocks → the same bytes stay (passive)` : `attempt ${t.attempts.length} not mined within ${after} blocks → same-nonce replacement (⌈+12.5 %⌉+1 wei)` }); notify(); break
        }
        blind = 0
      } catch (e) {
        rethrowFatal(e); t.note = `status check: ${short(e)}`; notify()
        // PF-E: a Stop needs no chain answer to apply: after as many failed status checks in a row as the window has blocks, the lane
        // ends `stopped` with the attempt open (it may still land; the next run reconciles it) — never a wait without end
        if ((o.stopRequested?.() || o.watchOnly) && ++blind >= Number(after)) {
          Object.assign(t, { state: 'pending', pendingAtStop: true, reason: `${attemptAt(t, a)}: its status cannot be read (${journalText(short(e), 120)}) and it may still land — nothing new is signed; run the job again to reconcile it` }); notify(); return 'stopped'
        }
      }
    }
  }
}
// R64 pause (per-tx cap reached): never abandon an attempt that might still land — keep watching it; Resume re-tries the
// bump (with the operator's new cap). PF-E fix 1: a Stop signs nothing new — with an attempt in flight it returns 'stop' and ethTx
// watches that attempt to the end of one window (its same bytes, never a bump), so a Stop never waits for a Resume.
/** @param {LaneTx} t @param {string} reason @param {EngineOpts} o @param {() => Promise<any>} landed */
async function ethPaused(t, reason, o, landed) {
  Object.assign(t, { state: 'paused', reason }); await jappend(o, { type: 'paused', chain: 'eth', reason: journalText(reason) }); o.notify()
  for (;;) {
    await waitOf(o, o.poll); if (!o.alive()) return 'aborted'
    try {
      const L = await landed(); if (L) { await jappend(o, { type: 'resumed', chain: 'eth', reason: 'the paused tx was included' }); return ethFinish(t, L, o) }
      if (o.stopRequested?.()) {
        if (!t.attempts.length) { Object.assign(t, { state: 'not-sent', reason: `stopped while paused (${reason})` }); o.notify(); return 'stopped' }
        return 'stop'
      }
      if (o.takeResume?.()) { await jappend(o, { type: 'resumed', chain: 'eth', reason: 'operator' }); Object.assign(t, { state: 'sent', reason: '' }); return 'resume' }
      if ((await eth.nonceAt(o.account.address, 'latest')) > t.nonce) return await ethNonceGone(t, o, landed)
      t.note = `paused: ${reason} — raise the cap and Resume, or Stop`; o.notify()
    } catch (e) { rethrowFatal(e); t.note = `status check: ${short(e)}`; o.notify() }
  }
}
/** @param {LaneTx} t @param {EngineOpts} o @param {() => Promise<any>} landed */
async function ethNonceGone(t, o, landed) {           // nonce consumed: one of ours (receipt may lag on load-balanced RPCs) or foreign
  for (let i = 0; i < 6; i++) { const L = await landed(); if (L) return ethFinish(t, L, o); await waitOf(o, o.poll) }
  Object.assign(t, { state: 'failed', reason: `nonce ${t.nonce} was consumed by a transaction this page did not sign` }); o.notify()
  // not proof: a lagging receipt index may hide one of ours — the attempts stay open, flagged for the next holder's reconcile
  // (PF-E: an attempt adopted only as a claim is not open: the API takes no `stuck` for it)
  for (const a of t.attempts) if (liveAttempt(a)) await jappend(o, { type: 'stuck', chain: 'eth', txId: a.id, reason: `nonce ${t.nonce} is used and no receipt of this attempt was found yet — reconcile before any new intent` })
  return 'failed'
}
/** @param {LaneTx} t @param {string} why @param {EngineOpts} o */
function ethExhaust(t, why, o) {
  Object.assign(t, { state: 'exhausted', reason: why }); o.notify()
  if (t.attempts?.some((/** @type {any} */ x) => !x.dead)) ethWatchLate(t, o)   // a signed attempt may still land: keep watching, never drop it
  return 'exhausted'
}
/** @param {LaneTx} t @param {EngineOpts} o */
async function ethWatchLate(t, o) {
  for (let i = 0; i < 400 && o.alive() && t.state === 'exhausted'; i++) {
    await waitOf(o, Math.max(o.poll, 6000))
    try { for (const a of t.attempts) { const r = await eth.receipt(a.id); if (r) { await ethFinish(t, { r, a }, o); t.reason = `landed late (after the lane stopped) · ${t.reason || ''}`; o.notify(); return } } } catch (e) { if (fatal(e)) return /* cannot journal: the next holder reconciles it */ }
  }
}
/** @param {LaneTx} t @param {{ r: any, a: any }} landedAt @param {EngineOpts} o */
async function ethFinish(t, { r, a }, o) {
  const idx = t.attempts.findIndex((/** @type {any} */ x) => x.id === a.id)
  const id = String(r.transactionHash).toLowerCase()
  t.landedTip = a.tip; t.includedAt = nowOf(o)
  Object.assign(t, { id, landedId: id, block: BigInt(r.blockNumber), actual: BigInt(r.gasUsed) * BigInt(r.effectiveGasPrice),
    state: r.status === '0x1' ? 'confirmed' : 'failed', note: '',
    reason: t.attempts.length > 1 ? `landed: attempt ${idx + 1} of ${t.attempts.length} (the others share nonce ${t.nonce} and can never be mined)` : '' })
  o.notify()
  // the journaled inclusion settles the cap ledger (its observe): the actual fee is spent, the reservation released
  await jappend(o, { type: 'included', chain: 'eth', txId: id, copy: t.copy, part: t.part, attempt: a.n ?? idx + 1, block: String(t.block), fee: String(t.actual), ms: msSince(t.firstAt, t.includedAt) })   // a.n: the journaled attempt number of an attempt adopted at a takeover
  for (let i = 0; i < 20 && o.alive(); i++) {
    try { const rb = await eth.readback(t.landedId, t.payload, o.to ?? o.account.address); if (rb) { t.readback = rb; t.chainBytes = rb.bytes; o.notify(); break } } catch { /* retry */ }
    await waitOf(o, o.poll)
  }
  // final round (m-4): a part that landed with status 0 (reverted) is journaled readback NOT ok, whatever its calldata — the journal FACT
  // the stop classes read (contracts/stop.ts finalFactOf), so its stop is FINAL from the journal, not only from the code the lane picks
  const reverted = t.state !== 'confirmed'
  await jappend(o, { type: 'readback', chain: 'eth', txId: id, ok: !reverted && !!t.readback?.ok, detail: journalText(`${reverted ? 'landed with status 0 (reverted) · ' : ''}${t.readback?.detail ?? 'no readback (transaction not found)'}`) })
  return t.state === 'confirmed' ? 'confirmed' : 'failed'
}

// ============================== Solana ==============================
/** @param {any} lane @param {EngineOpts} o */
export async function runSolLane(lane, o) {
  lane.stopped = null
  const used = new Map()   // part → blockhashes already used: identical bytes + blockhash would be the identical signature
  const first = lane.txs.findIndex((/** @type {any} */ t) => t.state !== 'confirmed')
  if (first < 0) return
  for (let k = first; k < lane.txs.length; k++) {
    if (k > first && o.stopRequested?.()) return stopRest(lane, k - 1, 'stopped by the operator after the previous tx', o.notify)
    const r = await solTx(lane.txs[k], { ...o, used, lane })
    if (r !== 'confirmed') return stopRest(lane, k, r, o.notify)
  }
}
// o.policy (R64 drain, optional): price(t, last) → {price, rung}|{lamports, rung}|{pause} — first attempt at the start rung,
// one rung up only after a PROVEN expiry ({lamports}: priority lamports per tx, PM; capped by o.cuPriceCap). Without a
// policy: the classic auto price ×2 per re-sign, ≤ MAX_ATTEMPTS.
/** @param {LaneTx} t @param {EngineOpts} o @returns {Promise<string>} */
export async function solTx(t, o) {
  const { kp, notify, alive, poll, rent, used } = o, P = o.policy, floor = o.payerFloor ?? rent   // drain: rent + claw-back fee reserve
  const addr = kp.publicKey.toBase58()
  const ledger = ledgerOf(o)                                              // the armed spend cap; no ledger, no signature
  t.attempts ??= []; t.raws ??= {}; t.firstAt ??= null
  let errs = 0
  for (;;) {
    if (!alive()) return 'aborted'
    const last = t.attempts.at(-1)
    if (last && !last.expired) {                                       // wait (also on resume) until confirmed or PROVEN expired
      const r = await solWait(t, last, o)
      if (r === 'unproven' && o.detachOnly?.() === true) { Object.assign(t, { state: 'pending', pendingAtStop: true, reason: `attempt ${t.attempts.length} stays open (neither confirmed nor proven expired yet) — nothing is re-signed; the next run reconciles it` }); notify(); return 'stopped' }   // R79: a detach escalates nothing
      if (r === 'unproven') { await jappend(o, { type: 'stuck', chain: 'sol', txId: last.id, reason: journalText(t.reason) }); Object.assign(t, { state: 'stuck' }); notify(); return 'stuck' }   // fix round 2 (M-4)
      if (r !== 'expired') return r
      last.expired = true
      await jappend(o, { type: 'reconcile', chain: 'sol', txId: last.id, outcome: 'expired' })   // the journal closes it too
      // E3 review I-1: nothing is in flight now — after a Stop a proven-expired signature is never re-signed
      if (o.stopRequested?.()) { Object.assign(t, { state: 'not-sent', reason: `stopped: attempt ${t.attempts.length} proven expired, nothing re-signed` }); notify(); return 'stopped' }
      continue
    }
    if (!P && t.attempts.length >= SOL.MAX_ATTEMPTS) { Object.assign(t, { state: 'exhausted', reason: `${SOL.MAX_ATTEMPTS} signatures, every one proven expired` }); notify(); return 'exhausted' }
    if (o.stopRequested?.()) { Object.assign(t, { state: 'not-sent', reason: last ? `stopped: attempt ${t.attempts.length} proven expired, nothing re-signed` : 'stopped before this part was signed' }); notify(); return 'stopped' }   // PF-E fix 1: no new signature after a Stop
    /** @type {any} */ let a, /** @type {any} */ slot, /** @type {any} */ rung = null
    try {
      /** @type {{ cuPrice?: number, priorityLamports?: number, cuPriceCap?: number }} */
      let pricing
      if (P) {                                                         // nothing is in flight here: every earlier attempt is proven expired
        const pr = await P.price(t, last)
        if (pr.pause) {
          Object.assign(t, { state: 'paused', reason: pr.pause }); await jappend(o, { type: 'paused', chain: 'sol', reason: journalText(pr.pause) }); notify()
          for (;;) { await waitOf(o, poll); if (!alive()) return 'aborted'; if (o.stopRequested?.()) { Object.assign(t, { state: 'not-sent', reason: `stopped while paused (${pr.pause})` }); notify(); return 'stopped' } if (o.takeResume?.()) { await jappend(o, { type: 'resumed', chain: 'sol', reason: 'operator' }); break } }
          P.resumeAtTop?.(); continue
        }
        pricing = pr.lamports != null ? { priorityLamports: pr.lamports, cuPriceCap: o.cuPriceCap } : { cuPrice: pr.price }; rung = pr.rung ?? null
      } else pricing = { cuPrice: last ? solResignPrice(last.cuPrice) : await sol.autoCuPrice() }   // ×2 per re-sign (cap 8M)
      const p = await sol.prepare(kp.publicKey, t.payload, pricing)
      const cuPrice = p.cuPrice
      const seen = used.get(t.part) || new Set()
      if (seen.has(p.blockhash)) { await waitOf(o, 400); continue }       // wait for a fresh blockhash → a distinct signature per copy
      if (p.err) {
        if (/AccountNotFound|InsufficientFunds/i.test(p.err)) { Object.assign(t, { state: 'exhausted', reason: `simulation: ${p.err}` }); notify(); return 'exhausted' }
        if (/refused/.test(p.err)) { Object.assign(t, { state: 'failed', reason: p.err }); notify(); return 'failed' }
        throw new Error(`simulation failed: ${p.err}`)
      }
      const bal = await sol.solBalance(addr)
      const after = bal - p.fee
      if (!(after === 0n || after >= floor)) {                         // the payer must end at ≥ rent (drain: + claw-back reserve) or exactly 0 (measured)
        if (P) { Object.assign(t, { state: last ? 'expired' : 'planned', reason: `balance ${fmtSol(bal)} < fee ${p.fee} lamports${rung != null ? ` (rung ${rung})` : ''} + rent-exempt minimum ${fmtSol(rent)}${floor > rent ? ` + claw-back fee reserve ${floor - rent} lamports` : ''}${last ? ' — earlier attempt(s) proven expired, nothing in flight' : ''}` }); notify(); return 'unaffordable' }   // drain: the lane is drained
        Object.assign(t, { state: 'exhausted', reason: `balance ${fmtSol(bal)} < fee ${p.fee} lamports + rent-exempt minimum ${fmtSol(rent)}` }); notify(); return 'exhausted'
      }
      const over = capRefusal(ledger, t, p.fee)                             // R60 hard cap: spent + held + this signature's exact fee
      if (over !== null) { Object.assign(t, { state: 'exhausted', reason: over }); notify(); return 'exhausted' }
      if (o.stopRequested?.()) continue                                  // PF-E fix 1: a Stop that came while this tx was prepared: nothing is signed
      const s = sol.sign(kp, p)
      const ticket = await jintent(o, { type: 'intent', chain: 'sol', txId: s.id, copy: t.copy, part: t.part, parts: t.parts, attempt: t.attempts.length + 1, replaces: last?.id ?? null,
        rawSha256: rawSol(s.raw), payloadSha256: sha256Hex(t.payload), reserved: String(p.fee),
        sol: { blockhash: p.blockhash, lastValidBlockHeight: p.lastValidBlockHeight, cuPrice, cuLimit: p.cuLimit, rung, fee: String(p.fee) } })   // journaled + acked BEFORE broadcast
      a = { id: s.id, blockhash: p.blockhash, slot: p.slot, lastValidBlockHeight: p.lastValidBlockHeight, fee: p.fee, cuLimit: p.cuLimit, cuPrice, rung, units: p.units, size: s.size, at: nowOf(o), ticket, ticketAt: nowOf(o) }
      t.attempts.push(a); t.raws[a.id] = s.raw; seen.add(p.blockhash); used.set(t.part, seen); t.firstAt ??= a.at
      Object.assign(t, { state: t.attempts.length > 1 ? 're-signed' : 'signed', id: a.id, reserved: p.fee, note: `tx ${s.size} B · CU limit ${p.cuLimit} (simulated ${p.units}) · price ${cuPrice} µL/CU${rung != null ? ` (rung ${rung})` : ''} · fee ${p.fee}` })
      slot = p.slot
      if (last) await jappend(o, { type: 'replaced', chain: 'sol', txId: a.id, prevId: last.id, reason: 'previous signature proven expired' })
      await notify({ paint: true })                                    // tx id on screen BEFORE the bytes leave the page
    } catch (e) { rethrowFatal(e); errs++; t.note = `prepare error ${errs}: ${short(e)}`; notify(); if (errs >= 30 || /fail closed/.test(/** @type {Error} */ (e).message)) { Object.assign(t, { state: 'exhausted', reason: /fail closed/.test(/** @type {Error} */ (e).message) ? short(e) : 'RPC unavailable (30 consecutive errors)' }); notify(); return 'exhausted' } await waitOf(o, poll); continue }
    errs = 0
    const out = await postSol(o, a.id, (ep) => sol.send(t.raws[a.id], slot, a.ticket, ep), a)   // E5: every verified endpoint, one ticket
    await jappend(o, { type: 'sent', chain: 'sol', txId: a.id, outcome: journalOutcome('sol', out), reason: out.kind === 'accepted' ? null : journalText(out.msg) })
    if (out.kind === 'rejected') {
      if (/insufficient|AccountNotFound/i.test(out.msg)) { a.expired = true; Object.assign(t, { state: 'exhausted', reason: `attempt ${t.attempts.length} rejected by preflight: ${out.msg}` }); notify(); return 'exhausted' }
      // M9: only a node-side preflight hiccup (blockhash not yet seen, node behind, min context slot) is rebroadcast; a PROGRAM
      // error would land as a failed, fee-charged tx — it was not forwarded, so stop here
      if (!SOL_RETRY.test(out.msg)) { a.expired = true; Object.assign(t, { state: 'failed', reason: `attempt ${t.attempts.length} refused by preflight (${out.msg}) — not forwarded, not rebroadcast` }); notify(); return 'failed' }
      Object.assign(t, { state: 'retrying', reason: `attempt ${t.attempts.length} rejected by preflight (${out.msg}) — rebroadcasting the same bytes; re-sign only after proven expiry` })
    } else Object.assign(t, { state: out.kind === 'unknown' ? 'unknown' : 'sent', reason: out.kind === 'unknown' ? `no definitive answer (${out.msg}) — tracking by signature` : '' })
    notify()
  }
}
// A SOL tx that landed with an error: it is included (the fee is charged) and its readback fails — journaled so.
/** @param {LaneTx} t @param {any} a @param {any} st @param {EngineOpts} o @param {string} why */
async function solLandedFailed(t, a, st, o, why) {
  Object.assign(t, { state: 'failed', id: a.id, landedId: a.id, reason: why }); o.notify?.()   // a claw-back's deps carry no notify
  if (o.finish) return 'failed'                                          // claw back: its caller journals clawback-failed
  // the journaled inclusion spends the fee it was charged (the cap ledger observes it)
  await jappend(o, { type: 'included', chain: 'sol', txId: a.id, copy: t.copy, part: t.part, attempt: t.attempts.indexOf(a) + 1, block: String(st?.slot ?? 0), fee: String(a.fee ?? 0n), ms: msSince(t.firstAt, nowOf(o)) })
  await jappend(o, { type: 'readback', chain: 'sol', txId: a.id, ok: false, detail: journalText(why) })
  return 'failed'
}
// I3 + Efix3: a re-sign needs proof from EVERY verified SOL endpoint (one endpoint's word is never enough) that the attempt can
// never land: isBlockhashValid(its blockhash) is false there (asked with minContextSlot = the slot the blockhash was fetched
// at when we signed it) AND its finalized height > lastValidBlockHeight (the pre-Efix3 rule, kept: never weaker) AND
// getSignatureStatuses(searchTransactionHistory) null with a context slot ≥ the validity answer's and the finalized slot —
// two such complete rounds ≥ 4 s apart. Any error, timeout, disagreement or unreadable answer is NOT proof: the round throws or
// resets, nothing is declared expired, nothing is re-signed. If ANY endpoint FINDS the signature, it landed: finish (or fail)
// — never loop.
/** @param {LaneTx} t @param {any} a @param {EngineOpts} o @returns {Promise<string>} */
async function solWait(t, a, o) {
  const { alive } = o, notify = typeof o.notify === 'function' ? o.notify : () => {}   // the executor's claw-back deps carry no notify
  const eps = Math.max(1, o.solEndpoints || 1)
  /** @type {number | null} */
  let firstProof = null, stopSince = null
  for (;;) {
    await waitOf(o, SOL.REBROADCAST_MS); if (!alive()) return 'aborted'
    // fix round 2 (M-4): after a Stop the wait is bounded even when one verified endpoint keeps failing the proof (its reads, its lag):
    // CANON.SOL_STOP_PROOF_MS after the Stop with the signature neither seen nor proven expired → 'unproven' (the caller journals stuck)
    if (o.stopRequested?.()) {
      stopSince ??= nowOf(o)
      if (nowOf(o) - stopSince >= CANON.SOL_STOP_PROOF_MS) {
        t.reason = `stopped by the operator: attempt ${t.attempts.indexOf(a) + 1} is neither confirmed nor proven expired on every verified endpoint ${Math.round(CANON.SOL_STOP_PROOF_MS / 1000)} s after the Stop (last check: ${journalText(t.note ?? '', 160)}) — nothing is re-signed; look it up, then resolve it with vt job resolve (mark-done if it landed, mark-failed if it never will)`
        return 'unproven'
      }
    }
    try {
      const sts = await sol.statuses(t.attempts.map((/** @type {any} */ x) => x.id))
      const bad = sts.findIndex((s) => s?.err)
      if (bad >= 0) return solLandedFailed(t, t.attempts[bad], sts[bad], o, `landed with error ${JSON.stringify(sts[bad].err)}`)
      const hit = sts.findIndex((s) => s && ['confirmed', 'finalized'].includes(s.confirmationStatus))
      if (hit >= 0) return solFinish(t, t.attempts[hit], o, sts[hit].slot)
      const fin0 = await sol.finalizedAt(null)
      // Eminors (Efix3 m-2): an unreadable / stale answer on the preferred route is NO PROOF (v0 = null), but it must not stop the SAME-bytes
      // rebroadcast either — a provider that rate-limits isBlockhashValid would otherwise leave a part un-rebroadcast until Stop. The answer
      // counts as "may still be valid" for the rebroadcast decision only; it is never proof of anything, and no expiry is judged this round.
      /** @type {{ valid: boolean, slot: number } | null} */
      let v0 = null, v0why = ''
      try { v0 = await sol.blockhashValidAt(null, a.blockhash, a.slot) } catch (e) {   // a well-formed boolean answer from a bank at or past the fetch slot, else no answer
        if (!(isRefusal(e) && e.guardId.startsWith('engine.sol-expiry-'))) rethrowFatal(e)
        v0why = short(e)
      }
      if (v0 === null || v0.valid || fin0.height <= a.lastValidBlockHeight) {   // still valid by either rule (or unknown): the SAME signed bytes again (never a new tx)
        firstProof = null
        if (t.raws?.[a.id]) {                                         // an attempt adopted at a takeover has no raw bytes here: watch only
          const ticket = await ticketFor(a, o)
          const out = await postSol(o, a.id, (ep) => sol.rebroadcast(t.raws[a.id], ticket, ep), a)   // E5: every endpoint once per ticket, then the preferred route
          if (out.kind === 'accepted' && t.state !== 'sent') { Object.assign(t, { state: 'sent', reason: '' }); if (!o.finish) await jappend(o, { type: 'sent', chain: 'sol', txId: a.id, outcome: 'accepted', reason: null }) }
        }
        t.note = `attempt ${t.attempts.length}: blockhash ${v0 === null ? `validity unreadable on the preferred route (no proof; rebroadcasting the same bytes): ${v0why}` : v0.valid ? 'still valid (isBlockhashValid)' : 'not yet past'} · finalized height ${fin0.height}, declared valid until ${a.lastValidBlockHeight}${sts.at(-1) ? ` · ${sts.at(-1).confirmationStatus}` : ''} · price ${a.cuPrice} µL/CU`; notify()
        continue
      }
      let all = true; const seen = []
      for (let i = 0; i < eps; i++) {
        const ep = eps > 1 ? i : null
        const v = await sol.blockhashValidAt(ep, a.blockhash, a.slot)     // first: the history below must be at least as new as this answer. An error or an ambiguous answer THROWS: no proof, nothing is re-signed
        const [f, h] = await Promise.all([sol.finalizedAt(ep), sol.statusesAt(ep, [a.id], true)])
        const found = h.value[0]
        if (found) {                                                  // ANY endpoint that sees the signature wins over every "invalid"
          if (found.err) return solLandedFailed(t, a, found, o, `landed with error ${JSON.stringify(found.err)} (seen by endpoint ${i})`)
          if (['confirmed', 'finalized'].includes(found.confirmationStatus)) return solFinish(t, a, o, found.slot)
          all = false; seen.push(`ep${i}: ${found.confirmationStatus}`); continue    // landed but not yet confirmed: keep waiting, never re-sign
        }
        if (v.valid) { all = false; seen.push(`ep${i}: blockhash still valid`); continue }
        if (!(f.height > a.lastValidBlockHeight)) { all = false; seen.push(`ep${i}: finalized height ${f.height} not past ${a.lastValidBlockHeight}`); continue }
        if (!(v.slot >= f.slot)) { all = false; seen.push(`ep${i}: validity answer older than the finalized bank`); continue }   // m-3: also bounds an adopted attempt (no fetch slot)
        if (!(h.slot >= v.slot && h.slot >= f.slot)) { all = false; seen.push(`ep${i}: history lagging`); continue }
        seen.push(`ep${i}: expired ✓`)
      }
      if (!all) firstProof = null
      else if (firstProof == null) firstProof = nowOf(o)
      t.note = `attempt ${t.attempts.length}: expiry proof ${seen.join(', ')}${firstProof ? ` · confirming (${Math.round((nowOf(o) - firstProof) / 1000)} s)` : ''}`; notify()
      if (all && nowOf(o) - /** @type {number} */ (firstProof) >= 4000) {
        Object.assign(t, { state: 'expired', reason: `attempt ${t.attempts.length}: on all ${eps} endpoint(s), isBlockhashValid says the blockhash is no longer valid and the signature is absent from history (twice, ≥ 4 s apart) — it can never land; re-signing with a new blockhash (${o.policy ? 'one rung up' : 'CU price ×2'})` })
        notify(); return 'expired'
      }
    } catch (e) {
      // Efix3: an unreadable / stale isBlockhashValid answer is NO PROOF this round (never a stop, never an expiry): wait and ask again
      if (!(isRefusal(e) && e.guardId.startsWith('engine.sol-expiry-'))) rethrowFatal(e)
      firstProof = null; t.note = `status check: ${short(e)}`; notify()
    }
  }
}
/** @param {LaneTx} t @param {any} a @param {EngineOpts} o @param {number | undefined} [slot] @returns {Promise<string>} */
async function solFinish(t, a, o, slot) {
  if (o.finish) return o.finish(t, a, o)                              // claw back: its own readback
  t.landedRung = a.rung; t.landedPrice = a.cuPrice; t.includedAt = nowOf(o)
  Object.assign(t, { id: a.id, landedId: a.id, state: 'confirmed', note: '', reason: t.attempts.length > 1 ? `landed: attempt ${t.attempts.indexOf(a) + 1} of ${t.attempts.length} (earlier ones proven expired)` : '' })
  o.notify()
  // the journaled inclusion spends the exact fee (getFeeForMessage) in the cap ledger
  await jappend(o, { type: 'included', chain: 'sol', txId: a.id, copy: t.copy, part: t.part, attempt: t.attempts.indexOf(a) + 1, block: String(slot ?? 0), fee: String(a.fee ?? 0n), ms: msSince(t.firstAt, t.includedAt) })
  for (let i = 0; i < 20 && o.alive(); i++) {
    try { const rb = await sol.readback(a.id, t.payload); if (rb) { Object.assign(t, { readback: rb, actual: rb.fee, chainBytes: rb.bytes }); o.notify(); break } } catch { /* retry */ }
    await waitOf(o, o.poll)
  }
  await jappend(o, { type: 'readback', chain: 'sol', txId: a.id, ok: !!t.readback?.ok, detail: journalText(t.readback?.detail ?? 'no readback (transaction not found)') })
  return 'confirmed'
}
export { solWait as _solWait }   // for test/engine-sol.test.mjs
export { post, sleep, spent, nowOf, waitOf }

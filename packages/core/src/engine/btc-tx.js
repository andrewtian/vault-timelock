// @ts-check
// E7: one BTC lane tx — a COMMIT (part 1) or a REVEAL (part 2) of a copy's text inscription — from intent to a block and its
// readback. Sequential per lane (runDrain): the reveal of a copy is built only after its commit LANDED (was seen by txid in a
// block), and every tx has its intent journaled and acked BEFORE its bytes leave (engine.js jintent).
//
// Nothing a send answers ever means "not sent". The relay's answers are: 200 {txid}; a 403 refusal (relay.btc-prevout is also what
// an identical re-send of an ACCEPTED commit gets — its input is spent in the mempool); a 502 (bitcoind answers HTTP 200 for a
// JSON-RPC error and the relay turns it into relay.upstream-shape, an HTTP 500 is "send outcome unknown"); a transport failure.
// So after EVERY send the tx is looked up BY TXID (getrawtransaction, a txindex answer): seen → it was accepted (or is on chain);
// absent → the very same bytes are sent again (the same txid, never a second transaction); unreadable → read again. The bytes
// are deterministic (chains/btc.js), so a takeover rebuilds them from the journaled intent and checks the txid before sending.
// A tx is never declared dead here: an attempt that cannot be rebuilt or whose inputs were spent by something else ends the run
// `failed` with the attempt left open for the operator (fail closed), never with a second commit built beside it.
//
//   · cap: the commit reserves fee + the value it locks (the whole copy's outlay, ledger-checked once); the reveal reserves 0.
//   · journal: intent {…, btc: {kind, pubkey, fee, value, inputs | commitVout}} → sent → included {block, fee = the cost above} →
//     readback. A takeover journals reconcile adopted (seen in the mempool, or rebuilt and sent again) or reconcile included.
import { isRefusal } from '../contracts/index.ts'
import { assertBtcOrder, assertBtcRebuild, refuseBtcOpen } from '../gates/btc.ts'
import { sha256Hex } from '../job/canonical.ts'
import { ledgerOf } from '../gates/caps.ts'
import * as b from '../chains/btc.js'
import { BTC_POSTAGE, commitAddress } from '../chains/btc-ord.ts'
import { hexToBytes } from '@noble/hashes/utils.js'
import { JournalError, jappend, jintent, journalText, nowOf, short, ticketFor, waitOf } from './engine.js'

/** @typedef {any} LaneTx @typedef {any} Deps */
const OPEN = new Set(['intent', 'sent', 'unknown', 'adopted'])           // the reducer's open attempt states
const MOVABLE = new Set([...OPEN, 'rejected'])                            // states a reconcile adopted may move
/** @param {unknown} e */
const fatal = (e) => e instanceof JournalError || isRefusal(e)
const sats = (/** @type {number} */ x) => BigInt(Math.round(x * 1e8))

/** @param {any} ledger @param {{ copy: unknown, part: unknown }} t @param {bigint} worst */
function capRefusal(ledger, t, worst) {
  try { ledger.reserve(t, worst); return null } catch (e) { if (isRefusal(e) && e.guardId === 'engine.cap') return e.message; throw e }
}
/** Eminors (E7b m-6): a raw read error (a node blip) is never a bare TypeError/Error out of the engine: the attempt stays open and the run ends `failed`
 * with engine.btc-open (like every other unreadable chain answer here). @template T @param {string} what @param {() => Promise<T>} f @returns {Promise<T>} */
async function readOrOpen(what, f) {
  try { return await f() } catch (e) { if (fatal(e)) throw e; return refuseBtcOpen(`the chain cannot be read (${short(e)}) — ${what}; run again to reconcile it by txid`) }
}
/** The landed txid of part `part` of copy `copy` in a reduced job state. @param {any} state @param {number} copy @param {number} part */
const landedIn = (state, copy, part) => state?.chains?.btc?.txs?.find((/** @type {any} */ g) => g.copy === copy && g.part === part && g.state === 'included')?.landedId ?? null

/** @param {LaneTx} t @param {Deps} o @returns {Promise<string>} */
export async function btcTx(t, o) {
  const ledger = ledgerOf(o), key = o.key, body = /** @type {Uint8Array} */ (t.payload)
  const poll = o.poll ?? 2000, retryMax = o.retryMax ?? 60, notify = () => o.notify?.()
  t.attempts ??= []; t.firstAt ??= null
  /** @param {string} state @param {string} reason */
  const end = (state, reason) => { Object.assign(t, { state, reason }); notify(); return state }

  // ---- a landed tx: included (unless a reconcile already landed it), then its readback
  /** @param {any} a @param {any} tx @param {boolean | null} viaReconcile null: the journal already has the landing (only the readback is missing) */
  async function landed(a, tx, viaReconcile) {
    const height = await readOrOpen('the landed tx stays open', () => b.heightOf(tx.blockhash))
    t.includedAt = nowOf(o)
    Object.assign(t, { id: a.id, landedId: a.id, state: 'confirmed', note: '', reason: t.attempts.length > 1 ? `landed: attempt ${a.n}` : '' }); notify()
    if (viaReconcile === null) { /* already landed in the journal */ } else if (viaReconcile) await jappend(o, { type: 'reconcile', chain: 'btc', txId: a.id, outcome: 'included', block: String(height), fee: String(a.cost) })
    else await jappend(o, { type: 'included', chain: 'btc', txId: a.id, copy: t.copy, part: t.part, attempt: a.n, block: String(height), fee: String(a.cost), ms: t.firstAt ? Math.max(0, nowOf(o) - t.firstAt) : 0 })
    const rb = t.part === 1 ? b.readbackCommit(key, body, tx, a.value) : b.readbackReveal(key, body, tx)
    Object.assign(t, { readback: rb, actual: a.cost, chainBytes: rb.bytes }); notify()
    await jappend(o, { type: 'readback', chain: 'btc', txId: a.id, ok: rb.ok, detail: journalText(rb.detail) })
    return 'confirmed'
  }

  // ---- one send of the SAME bytes, then the lookup by txid decides
  /** @param {any} a @returns {Promise<{ kind: 'accepted' | 'unknown', msg: string }>} */
  async function sendOnce(a) {
    const ticket = await ticketFor(a, o)
    try {
      const id = await b.send(a.raw, ticket)
      return id === a.id ? { kind: 'accepted', msg: '' } : { kind: 'unknown', msg: 'the relay answered another txid' }
    } catch (e) {
      if (fatal(e)) throw e                                            // engine.no-ticket: nothing left; the lane stops
      return { kind: 'unknown', msg: short(e) }
    }
  }
  /** @param {any} a @param {boolean} sendFirst @returns {Promise<string>} */
  async function drive(a, sendFirst) {
    let needSend = sendFirst, bad = 0
    /** @type {string | null} */ let told = a.told ?? null
    const tell = async (/** @type {'accepted' | 'unknown'} */ outcome, /** @type {string | null} */ reason) => {
      if (told === outcome) return
      told = a.told = outcome
      await jappend(o, { type: 'sent', chain: 'btc', txId: a.id, outcome, reason: reason === null || reason === '' ? null : journalText(reason) })
    }
    for (;;) {
      if (!o.alive()) return 'aborted'
      if (needSend) {
        needSend = false
        const out = await sendOnce(a)
        if (out.kind === 'accepted') await tell('accepted', null)
        else { await tell('unknown', `no definitive answer (${out.msg}) — looked up by txid`); Object.assign(t, { state: 'unknown', reason: `no definitive answer to the send (${out.msg}) — tracking by txid` }); notify() }
      }
      /** @type {any} */ let tx
      try { tx = await b.getTx(a.id) } catch (e) { if (fatal(e)) throw e; tx = undefined }
      if (tx != null && (tx.confirmations ?? 0) >= b.BTC_CONFIRMATIONS) return landed(a, tx, false)
      if (tx != null) {                                                 // accepted: in the mempool (or short of the depth)
        bad = 0
        await tell('accepted', 'seen by txid')
        Object.assign(t, { state: 'sent', reason: '', note: `${t.part === 1 ? 'commit' : 'reveal'} accepted — waiting for a block` }); notify()
      } else if (tx === null) {                                         // not in the mempool or on chain: the same bytes again
        if (a.raw == null) return refuseBtcOpen(`the ${t.part === 1 ? 'commit' : 'reveal'} left the mempool and its bytes cannot be rebuilt — it stays open: run again to reconcile it by txid`)
        if (++bad > retryMax) return refuseBtcOpen(`the ${t.part === 1 ? 'commit' : 'reveal'} is not on the chain after ${bad} sends (outcome unknown) — it stays open: run again to reconcile it by txid`)
        needSend = true
      } else if (++bad > retryMax) return refuseBtcOpen(`the chain cannot be read (${bad} rounds) — the ${t.part === 1 ? 'commit' : 'reveal'} stays open: run again to reconcile it by txid`)
      await waitOf(o, poll)
    }
  }

  // ---- what an earlier holder journaled for this (copy, part): reconcile by txid, rebuild, never build a second tx beside it
  /** @param {any} pa @param {number} n */
  const attemptOf = (pa, n) => ({ id: pa.txId, n, kind: pa.btc.kind, cost: pa.btc.kind === 'commit' ? BigInt(pa.btc.fee) + BigInt(pa.btc.value) : 0n, value: pa.btc.kind === 'commit' ? BigInt(pa.btc.value) : 0n, told: null, ticketAt: 0 })
  // the rebuilt tx is the journaled one: the same txid AND the same bytes (the txid does not cover the witness: a wrong input amount in the
  // sighash gives the same txid with other bytes, which the relay's r binding would refuse for ever)
  const same = (/** @type {any} */ x, /** @type {any} */ pa) => x.txid === pa.txId && (pa.rawSha256 === undefined || x.rawSha256 === pa.rawSha256)
  /** true only when the output exists (its tx is in a block) and the chainstate, mempool excluded, no longer holds it. @param {string} txid @param {number} vout */
  async function spentInBlock(txid, vout) {
    const f = await b.getTx(txid)
    if (f == null || (f.confirmations ?? 0) < b.BTC_CONFIRMATIONS || f.vout?.[vout] === undefined) return false
    return (await b.txOut(txid, vout, false)) == null
  }
  /** @param {any} pa @returns {Promise<{ raw: string, why?: undefined, dead?: undefined, seen?: undefined } | { why: string, dead?: boolean, seen?: boolean }>} */
  async function rebuild(pa) {
    try {
      if (pa.btc.kind === 'commit') {
        const inputs = []
        for (const op of pa.btc.inputs) {
          const [txid, vout] = op.split(':'), u = await b.txOut(txid, Number(vout))
          if (u == null) {
            // POSITIVE evidence that this commit can never land: its input is spent IN A BLOCK by another tx (the funding tx is confirmed, the
            // output exists, and the chainstate — mempool excluded — no longer holds it). A mempool-only spend, a drop or an unreadable
            // answer is not evidence: the attempt stays open and is looked at again.
            let dead = await spentInBlock(txid, Number(vout))
            // E7-fix3 m-1: the lookup that said "absent" is older than this check — a commit mined in between would otherwise be journaled `stuck`
            // with "can never land". Read the commit by txid once more: seen → NOT dead (the run fails closed, the next one sees it first).
            if (dead && await readOrOpen('the commit stays open', () => b.getTx(pa.txId)) != null) {
              return { why: `its input ${txid.slice(0, 8)}…:${vout} is spent in a block, and that spender is this commit itself: it is on the chain now`, seen: true }
            }
            return { why: `its input ${txid.slice(0, 8)}…:${vout} is spent${dead ? ' in a block by another transaction' : ' (in the mempool, by this tx or another)'}`, dead }
          }
          inputs.push({ txid, index: Number(vout), amount: sats(u.value) })
        }
        const x = b.buildCommit({ key, body, inputs, value: BigInt(pa.btc.value), fee: BigInt(pa.btc.fee) })
        return same(x, pa) ? { raw: x.hex } : { why: 'rebuilt, the bytes differ from the journaled intent' }
      }
      const c = await commitRef(landedIn(o.state, t.copy, 1) ?? o.resume?.landed?.[1] ?? null, pa.btc.commitVout)
      if (c.why !== undefined) return { why: c.why }
      const x = b.buildReveal({ key, body, commitTxid: c.txid, commitVout: c.vout, amount: c.amount })
      return same(x, pa) ? { raw: x.hex } : { why: 'rebuilt, the bytes differ from the journaled intent' }
    } catch (e) { if (fatal(e)) throw e; return { why: `cannot rebuild (${short(e)})` } }
  }
  /** The commit output a reveal spends, read from the chain. @param {string | null} txid @param {number} vout @returns {Promise<{ why: string } | { why?: undefined, txid: string, vout: number, amount: bigint }>} */
  async function commitRef(txid, vout) {
    if (txid === null) return { why: 'the commit has not landed: the reveal is never sent before it' }
    const c = await readOrOpen('the reveal is not built', () => b.getTx(txid))
    if (c == null || (c.confirmations ?? 0) < b.BTC_CONFIRMATIONS) return { why: 'the commit is not in a block yet: the reveal is never sent before it' }
    const o0 = c.vout?.[vout]
    if (!o0 || o0.scriptPubKey?.address !== commitAddress(key.network, hexToBytes(key.xonly), body)) return { why: 'the commit output does not pay the commit address' }
    return { txid, vout, amount: sats(o0.value) }
  }
  /** @param {any} g the reduced group @returns {Promise<string | null>} */
  async function settlePrior(g) {
    if (g.state === 'included' && typeof g.landedId === 'string') {      // landed; the holder died before its readback (or it could not be read)
      const pa = g.attempts.find((/** @type {any} */ x) => x.txId === g.landedId)
      if (!pa?.btc) return refuseBtcOpen('a landed attempt without its btc data')
      const tx = await readOrOpen('the landed tx is never sent again', () => b.getTx(/** @type {string} */ (g.landedId)))
      if (tx == null) return refuseBtcOpen('a landed tx cannot be read back now — it is never sent again; run again')
      return landed(attemptOf(pa, g.attempts.indexOf(pa) + 1), tx, null)
    }
    const atts = g.attempts.map((/** @type {any} */ pa, /** @type {number} */ i) => ({ pa, n: i + 1 })).filter((/** @type {any} */ x) => x.pa.btc).reverse()   // newest first
    // 1. chain evidence over every journaled claim: any of them seen by txid wins
    for (const { pa, n } of atts) {
      /** @type {any} */ let tx
      try { tx = await b.getTx(pa.txId) } catch (e) { if (fatal(e)) throw e; return refuseBtcOpen(`the chain cannot be read (${short(e)}) — the earlier attempt stays open; run again to reconcile it by txid`) }
      if (tx == null) continue
      const a = attemptOf(pa, n)
      t.attempts.push(a)
      if ((tx.confirmations ?? 0) >= b.BTC_CONFIRMATIONS) return landed(a, tx, true)
      if (MOVABLE.has(pa.state)) await jappend(o, { type: 'reconcile', chain: 'btc', txId: pa.txId, outcome: 'adopted' })
      return rebuildThenDrive(pa, a, false)                              // in the mempool: watched, its bytes rebuilt in case it is dropped
    }
    // 2. none seen: an open attempt is rebuilt from its intent and sent again (the same txid) — or the run fails closed
    for (const { pa, n } of atts) {
      if (!OPEN.has(pa.state)) continue
      const a = attemptOf(pa, n)
      t.attempts.push(a)
      return rebuildThenDrive(pa, a, true)
    }
    return null                                                          // nothing journaled can still land: a new attempt may be built
  }
  /** @param {any} pa @param {any} a @param {boolean} sendFirst */
  async function rebuildThenDrive(pa, a, sendFirst) {
    const r = await rebuild(pa)
    if (r.why !== undefined) {
      if (sendFirst && r.seen === true) assertBtcRebuild(false, `the earlier ${a.kind} (${pa.txId.slice(0, 8)}…) was absent by txid but is on the chain now (${r.why}) — nothing was journaled stuck; run again and it is reconciled by txid`)
      if (sendFirst && r.dead === true) {                                 // journal `stuck` so the operator can resolve it (mark-failed) and a rerun builds attempt N+1
        await jappend(o, { type: 'stuck', chain: 'btc', txId: pa.txId, reason: journalText(`${r.why} — the commit was absent by txid when looked up and again after that in-block spend was seen, so it can never land: resolve it: vt job resolve with job id ${o.jobId ?? '(this job)'}, chain btc, the commit starting ${pa.txId.slice(0, 12)} (vt job status lists it in full), outcome mark-failed - then run again`) })
      }
      if (sendFirst) assertBtcRebuild(false, `the earlier ${a.kind} (${pa.txId.slice(0, 8)}…) is not on the chain and ${r.why} — it stays open for the operator (nothing new is built beside it)`)
      a.raw = null                                                        // in the mempool: watched without its bytes
      return drive({ ...a, raw: null }, false)
    }
    a.raw = r.raw
    if (sendFirst && MOVABLE.has(pa.state)) await jappend(o, { type: 'reconcile', chain: 'btc', txId: pa.txId, outcome: 'adopted' })
    t.firstAt ??= nowOf(o)
    return drive(a, sendFirst)
  }

  if (!o.alive()) return 'aborted'
  const g = o.state?.chains?.btc?.txs?.find((/** @type {any} */ x) => x.copy === t.copy && x.part === t.part)
  if (g !== undefined && t.attempts.length === 0 && g.attempts.length > 0) {
    const r = await settlePrior(g)
    if (r !== null) return r
  }

  // ---- a new attempt
  const n = (g?.attempts.length ?? 0) + t.attempts.length + 1
  /** @type {{ built: any, intent: any, cost: bigint, value: bigint }} */ let plan
  if (t.part === 1) {
    const p = b.planCommit(key, body, await b.utxosOf(key.address), o.rate)
    if (p.inputs === null) { Object.assign(t, { state: 'planned', reason: `balance ${p.total} sat < ${p.value} sat for the inscription + the commit fee` }); notify(); return 'unaffordable' }
    const cost = p.fee + p.value
    const over = capRefusal(ledger, t, cost)                            // the whole copy's outlay: spent + held + this signature's worst case
    if (over !== null) return end('exhausted', over)
    // PF-E fix round 2 (M-2): a Stop that came while this copy was planned (its level, balance, coins): no commit is signed — never a
    // check before a reveal (a commit already out is finished: the copy is one unit)
    await o.refreshStop?.()
    if (o.stopRequested?.()) { Object.assign(t, { state: 'not-sent', reason: 'stopped before the commit was signed' }); notify(); return 'stopped' }
    const built = b.buildCommit({ key, body, inputs: p.inputs, value: p.value, fee: p.fee })
    plan = { built, cost, value: p.value, intent: { kind: 'commit', pubkey: key.pubkey, fee: String(built.fee), value: String(p.value), inputs: b.outpointsOf(p.inputs) } }
  } else {
    const c = await commitRef(landedIn(o.state, t.copy, 1) ?? o.lane?.txs?.find((/** @type {any} */ x) => x.copy === t.copy && x.part === 1)?.landedId ?? o.resume?.landed?.[1] ?? null, 0)
    assertBtcOrder(c.why === undefined, String(c.why))
    if (c.why !== undefined) throw new Error('invariant violated: engine.btc-order did not refuse')
    if (c.amount <= BTC_POSTAGE) return end('failed', 'the commit output cannot pay a reveal')
    const over = capRefusal(ledger, t, 0n)
    if (over !== null) return end('exhausted', over)
    const built = b.buildReveal({ key, body, commitTxid: c.txid, commitVout: c.vout, amount: c.amount })
    plan = { built, cost: 0n, value: 0n, intent: { kind: 'reveal', pubkey: key.pubkey, fee: String(built.fee), commitVout: c.vout } }
  }
  const { built } = plan
  const ticket = await jintent(o, { type: 'intent', chain: 'btc', txId: built.txid, copy: t.copy, part: t.part, parts: t.parts, attempt: n, replaces: null,   // lane-s's API requires null for btc: attempts of a (copy, part) are tracked by attempt number, never chained
   
    rawSha256: built.rawSha256, payloadSha256: sha256Hex(body), reserved: String(plan.cost), btc: plan.intent })   // journaled + acked BEFORE broadcast
  const a = { id: built.txid, n, kind: plan.intent.kind, raw: built.hex, cost: plan.cost, value: plan.value, ticket, ticketAt: nowOf(o), told: null }
  t.attempts.push(a); t.firstAt ??= nowOf(o)
  Object.assign(t, { state: 'signed', id: a.id, reserved: plan.cost, note: `${plan.intent.kind} ${built.vsize} vB · fee ${built.fee} sat` }); notify()
  return drive(a, true)
}

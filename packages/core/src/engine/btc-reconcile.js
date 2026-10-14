// @ts-check
// E7 fix round 1: the by-txid reconcile of one BTC (copy, part) group, shared by the lane (btcAdapter.reconcile) and the executor's takeover
// (executor/reconcile.ts). Every attempt is looked up BY TXID (the node's txindex): confirmed in a block → `reconcile included` + a readback;
// in the mempool, or not seen → `reconcile adopted` for an open one (the lane rebuilds the very bytes from the journaled intent and sends
// them again if need be, or refuses engine.btc-rebuild). It never sends and never closes an attempt (absence is not evidence). A read that
// fails ends the run with engine.btc-open (failed, never `stopped`): a rerun finds the attempt again.
import { journalText } from './engine.js'
import * as b from '../chains/btc.js'
import { refuseBtcOpen } from '../gates/btc.ts'

const OPEN = new Set(['intent', 'sent', 'unknown', 'adopted'])
/** @param {any} g the reduced group @param {{ emit: (e: any) => Promise<void>, key: any, payloadOf: (copy: number, part: number) => Uint8Array | null }} o */
export async function btcReconcileGroup(g, { emit, key, payloadOf }) {
  for (const a of [...g.attempts].reverse()) {                       // newest first
    /** @type {any} */ let tx
    try { tx = await b.getTx(a.txId) } catch (e) { return refuseBtcOpen(`copy ${g.copy} part ${g.part}: the chain cannot be read (${journalText(/** @type {Error} */ (e)?.message ?? e, 120)}) — the attempt stays open; run again`) }
    if (tx == null || (tx.confirmations ?? 0) < b.BTC_CONFIRMATIONS) continue
    const bt = a.btc
    /** @type {number} */ let height
    try { height = await b.heightOf(tx.blockhash) } catch { return refuseBtcOpen(`copy ${g.copy} part ${g.part}: the block of ${a.txId.slice(0, 8)}… cannot be read — the attempt stays open; run again`) }
    // btc cost semantics (CC-12): what leaves the lane's spendable outputs for this tx — a commit: its fee + the value it locks, a reveal: 0
    const cost = bt?.kind === 'commit' ? String(BigInt(bt.fee) + BigInt(bt.value ?? '0')) : '0'
    await emit({ type: 'reconcile', txId: a.txId, outcome: 'included', block: String(height), fee: cost })
    const body = payloadOf(g.copy, g.part)
    const rb = key && body !== null && bt ? (g.part === 1 ? b.readbackCommit(key, body, tx, BigInt(bt.value ?? '0')) : b.readbackReveal(key, body, tx)) : null
    await emit({ type: 'readback', txId: a.txId, ok: rb?.ok === true, detail: journalText(rb?.detail ?? 'no readback') })
    return
  }
  for (const a of g.attempts) if (OPEN.has(a.state)) await emit({ type: 'reconcile', txId: a.txId, outcome: 'adopted' })
}

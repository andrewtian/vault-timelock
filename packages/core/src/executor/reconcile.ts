// packages/core/src/executor/reconcile.ts — the takeover reconcile (spec §3.3 "Takeover", §7.3 step 2; S1 rule: a
// `reconcile` from the current generation for every earlier-generation open intent before any new intent). It runs
// after the lease is acquired and before anything is signed; it never sends a byte. Chain evidence decides; what the
// chain cannot decide stays open (fail closed) — the attempt is adopted and watched, or journaled stuck for the
// operator's resolve.
//
// Job attempts, per (copy, part) group with an open attempt:
//   ETH  (one nonce per group; every journaled attempt is checked, also those journaled dead: chain evidence wins)
//        · a receipt of any attempt → reconcile included {block, fee = gasUsed × effectiveGasPrice}, then readback
//          (status 0: landed with an error → readback ok:false);
//        · the nonce is used: ONLY positive evidence decides (E3 review I-2) — the tx at that nonce from this sender is
//          found (the block where the account's nonce passed it, eth_getTransactionCount by block + eth_getBlockByNumber):
//          not one of ours → reconcile nonce-consumed for every attempt that may still land, and the run fails closed
//          (another holder of this key); ours, or not identifiable (a lagging index, no archive state) after `rounds`
//          polls → stuck with the reason (the next run looks again), NEVER nonce-consumed;
//        · the nonce is not used yet → reconcile adopted for every open attempt; the lane resumes AT that part with the
//          journaled attempts rebuilt (same nonce; bumps replace the open attempt with the highest fee).
//   SOL  · a signature status of any attempt → reconcile included {block = slot, fee} + readback (an error: ok:false);
//        · otherwise each open attempt is watched until it lands or its expiry is proven on every endpoint (the
//          engine's evidence gate, Efix3: isBlockhashValid false for the journaled blockhash and no status in history, on
//          every endpoint, and the finalized height past the declared lastValidBlockHeight; any error or disagreement is no proof) → reconcile expired. Never re-signed before.
// The claw-back family (open members):
//   ETH  · a receipt of a member → clawback-included {value, fee} from the chain + clawback-readback; status 0 →
//          clawback-failed {fee} and every other open member reconcile nonce-consumed (the nonce is spent);
//        · the nonce used: the same positive evidence — a foreign tx at that nonce → nonce-consumed per open member
//          (every member dead: the claw-back fails by itself, D-2) and fail; ours or unidentifiable → stuck;
//        · still pending → reconcile adopted per member, then watched for at most `pendingPolls` polls (or until a
//          Stop), then stuck with the exit named (run again later, or resolve mark-failed and claw back again).
//          PF-E fix 1 (4): a member no endpoint has (dropped) gets its very bytes again — rebuilt from its journaled intent
//          (nonce, gas, tip, maxFee, destination) and the value its send ticket binds, signed by the lane key (RFC 6979),
//          and sent only when keccak256 is its tx id and sha256 the journaled rawSha256 (the ticket's r); bytes that cannot
//          be rebuilt journal every open member stuck with the exact reason. Never anything new at that nonce.
// Dead attempts of a part that has not landed (expired, nonce-consumed, superseded…) are re-checked once per run before
// the part can be signed again (E3 review I-2, defence in depth): a late landing → reconcile included (D-1) + readback.
//   SOL  · a status found → clawback-included {value received, fee} or clawback-failed {fee}; otherwise watched until
//          landed or its expiry is proven → reconcile expired.
import type { AttemptView, Chain, ChainState, JobState, LeaseGrant, Network, TxView } from '../contracts/index.ts'
import { OPEN_ATTEMPT } from '../job/reduce.ts'
import * as eth from '../chains/eth.js'
import * as sol from '../chains/sol.js'
import { btcReconcileGroup } from '../engine/btc-reconcile.js'
import { isRefusal } from '../contracts/index.ts'
import type { BtcKey } from '../chains/btc.js'
import { ethRpc } from '../engine/rpc.js'
import { journalText, post, ticketBinds, ticketFor, _solWait } from '../engine/engine.js'
import { hexToBytes } from 'viem'
import { sha256Hex } from '../job/canonical.ts'
import type { Clock } from './lease.ts'

type Flat = { type: string; chain: Chain; [k: string]: unknown }
export interface EngineJournal { append(ev: Flat): Promise<void>; intent(ev: Flat): Promise<{ ticket: string }>; ticket?(txId: string): Promise<string> }
// n: the journaled attempt number; to: its journaled recipient; open: journaled `reconcile adopted` here (false: a claim — rejected,
// marked failed — held for the cap, never re-sent). PF-E: the lane rebuilds an open attempt's bytes from these (engine.js ethRebuild).
export interface AdoptedEth { copy: number; part: number; nonce: number; attempts: Array<{ id: string; n: number; gas: bigint; tip: bigint; maxFee: bigint; to: string; open: boolean }> }
export type ReconcileResult = { ok: true; adopted: AdoptedEth | null; journaled: number } | { ok: false; why: string; journaled: number }
export interface ReconcileDeps {
  chain: Chain; state: JobState; grant: LeaseGrant; journal: EngineJournal; clock: Clock; poll: number
  alive(): boolean; address: string; network: Network; solEndpoints: number
  payloadOf(copy: number, part: number): Uint8Array | null
  to?: string                                       // the ETH data recipient (readback); the signer when absent
  btcKey?: BtcKey                                   // a BTC lane's key (readback of a landed commit / reveal)
  rounds?: number                                   // polls before an undecidable ETH outcome is decided (default 10)
  pendingPolls?: number                             // polls an adopted pending claw-back is watched (default 90)
  stopRequested?(): boolean                         // the operator's Stop ends a wait
  ethAccount?: unknown                              // PF-E fix 1: the ETH lane key's signer, to rebuild an adopted claw-back member's bytes
  detach?(): boolean                                // R79: the stop is a detach (requestStop alone): an unproven SOL expiry is not escalated to stuck
}
// The tx this sender sent at `nonce`, found by positive evidence (E3 review I-2): the first block whose post-state
// account nonce is past `nonce` (exponential back-off from the head, then binary search on eth_getTransactionCount by
// block), and that block's tx from this address with that nonce. Unreadable (no archive state, an index lagging, an RPC
// error) → { kind: 'none' } with the reason: never a guess.
type AtNonce = { kind: 'tx'; hash: string; block: number } | { kind: 'none'; why: string }
export async function txAtNonce(address: string, nonce: number): Promise<AtNonce> {
  try {
    const hex = (b: number): string => `0x${b.toString(16)}`
    const countAt = async (b: number): Promise<number> => Number(BigInt(await ethRpc('eth_getTransactionCount', [address, hex(b)]) as string))
    const head = Number(BigInt(await ethRpc('eth_blockNumber', []) as string))
    if ((await countAt(head)) <= nonce) return { kind: 'none', why: `the head block ${head} does not show nonce ${nonce} used yet` }
    let hi = head, lo = -1
    for (let step = 1; ; step *= 2) {                                   // count(lo) ≤ nonce < count(hi)
      const b = head - step
      if (b < 0) break
      if ((await countAt(b)) <= nonce) { lo = b; break }
      hi = b
      if (step > 1 << 24) return { kind: 'none', why: 'the block that used the nonce was not found' }
    }
    while (hi - lo > 1) { const mid = Math.floor((lo + hi) / 2); if ((await countAt(mid)) <= nonce) lo = mid; else hi = mid }
    const blk = await ethRpc('eth_getBlockByNumber', [hex(hi), true]) as { transactions?: Array<{ hash?: string; from?: string; nonce?: string } | string> } | null
    const tx = (blk?.transactions ?? []).find((t) => typeof t === 'object' && t !== null && String(t.from ?? '').toLowerCase() === address.toLowerCase() && Number(BigInt(t.nonce ?? '0x0')) === nonce)
    if (typeof tx !== 'object' || tx === null || typeof tx.hash !== 'string') return { kind: 'none', why: `block ${hi} (where the nonce was used) does not show the tx yet` }
    return { kind: 'tx', hash: tx.hash.toLowerCase(), block: hi }
  } catch (e) {
    return { kind: 'none', why: `the tx at nonce ${nonce} cannot be read (${journalText((e as Error)?.message ?? e, 120)})` }
  }
}

const big = (v: unknown): bigint => BigInt(v as string)
const isOpen = (a: AttemptView): boolean => OPEN_ATTEMPT.has(a.state)
// May still land as far as the cap is concerned (S2 2fea217: only a landing or a reconcile expired / nonce-consumed is
// evidence): open, or journaled rejected / resolved-failed.
const isHeld = (a: AttemptView): boolean => isOpen(a) || a.state === 'rejected' || a.state === 'resolved-failed'

export async function reconcileChain(d: ReconcileDeps): Promise<ReconcileResult> {
  const cs = d.state.chains[d.chain] as ChainState | undefined
  if (cs === undefined) return { ok: false, why: `${d.chain} is not in this job`, journaled: 0 }
  let n = 0
  const emit = async (ev: Omit<Flat, 'chain'>): Promise<void> => { await d.journal.append({ chain: d.chain, ...ev } as Flat); n++ }
  const rounds = d.rounds ?? 10
  const lost = (): ReconcileResult | null => (d.alive() ? null : { ok: false, why: 'the lease was lost during the reconcile', journaled: n })
  let adopted: AdoptedEth | null = null
  const rebuiltClaw = new Map<string, { id: string; ticket: string; ticketAt: number; raw: `0x${string}` }>()   // PF-E fix 1: adopted claw-back bytes
  // a journaled SOL attempt: only its blockhash is bound by the relay (CC-3a), its lastValidBlockHeight is declared — the
  // engine's expiry proof is isBlockhashValid (false on EVERY endpoint) and the finalized height past the declared one (Efix3)
  const declared = (blockhash: string) => ({ blockhash })

  const groups = cs.txs.filter((t) => t.state !== 'included' && t.attempts.some(isHeld))
  for (const g of groups) {
    const r = d.chain === 'eth' ? await ethGroup(g) : d.chain === 'btc' ? await btcGroup(g) : await solGroup(g)
    if (r !== null) return r
  }
  // dead attempts only (expired, nonce-consumed, superseded…): re-checked before the part can ever be signed again
  for (const g of cs.txs.filter((t) => t.state !== 'included' && t.attempts.length > 0 && !t.attempts.some(isHeld))) {
    const l = lost(); if (l) return l
    if (d.chain === 'eth') {
      for (const a of g.attempts) {
        const rc = await eth.receipt(a.txId)
        if (rc) { await ethLanded(g, a.txId, rc); break }
      }
    } else if (d.chain === 'sol') {                                  // (a btc attempt is never dead: engine.btc-open leaves it open; E7b N-2)
      const ids = g.attempts.map((a) => a.txId)
      let hit: string | null = null
      for (let i = 0; i < Math.max(1, d.solEndpoints) && hit === null; i++) {
        const st = await sol.statusesAt(d.solEndpoints > 1 ? i : null, ids, true)
        const k = st.value.findIndex((x: { err?: unknown; confirmationStatus?: string } | null) => x !== null && (x.err != null || x.confirmationStatus === 'confirmed' || x.confirmationStatus === 'finalized'))
        if (k >= 0) hit = ids[k]
      }
      if (hit !== null) await solLanded(g, hit)
    } else if (d.chain === 'btc') {
      // a btc attempt is never dead (engine.btc-open leaves it open; the append gate refuses `expired` / `nonce-consumed` for btc): a group that
      // is, came from a foreign or buggy writer, and nothing may plan a new commit beside a tx that was never looked up by txid (Eminors fix 1, m-7)
      return { ok: false, why: `copy ${g.copy} part ${g.part}: its btc attempt(s) are journaled dead (expired / nonce-consumed), which a btc attempt never is — they were not looked up by txid; resolve them with the operator before running again`, journaled: n }
    }
  }
  const jobIds = new Set(cs.txs.flatMap((t) => t.attempts.map((a) => a.txId)))
  const members = d.grant.openIntents.filter((oi) => !jobIds.has(oi.txId) && cs.openIntents.includes(oi.txId))
  if (members.length > 0) {
    const r = d.chain === 'eth' ? await ethClaw(members) : await solClaw(members)
    if (r !== null) return r
  }
  return { ok: true, adopted, journaled: n }

  // ---------------- BTC job group (E7b) ----------------
  // Every attempt of the (copy, part) is looked up BY TXID (the node's txindex): confirmed in a block → reconcile included (+ readback);
  // in the mempool, or not seen at all → reconcile adopted (the lane, engine/btc-tx.js, rebuilds the very bytes from the journaled
  // intent, sends them again if need be, and refuses engine.btc-rebuild when it cannot). Absence is never evidence that a tx is dead:
  // nothing here closes an attempt as expired, and an unreadable chain stops the reconcile (fail closed).
  async function btcGroup(g: TxView): Promise<ReconcileResult | null> {
    const l = lost(); if (l) return l
    try { await btcReconcileGroup(g, { emit: (e) => emit(e as never), key: d.btcKey, payloadOf: d.payloadOf }) } catch (e) {
      if (isRefusal(e) && e.guardId === 'engine.btc-open') return { ok: false, why: e.message, journaled: n }
      throw e
    }
    return null
  }

  // ---------------- ETH job group ----------------
  async function ethGroup(g: TxView): Promise<ReconcileResult | null> {
    const nonce = g.attempts.find((a) => a.eth !== undefined)?.eth?.nonce
    if (nonce === undefined) return { ok: false, why: `copy ${g.copy} part ${g.part}: an attempt without its nonce`, journaled: n }
    if (g.attempts.some((a) => a.eth !== undefined && a.eth.nonce !== nonce)) return { ok: false, why: `copy ${g.copy} part ${g.part}: its attempts declare different nonces (fail closed)`, journaled: n }
    const ids = new Set(g.attempts.map((a) => a.txId))
    for (let round = 0; ; round++) {
      const l = lost(); if (l) return l
      for (const a of g.attempts) {
        const rc = await eth.receipt(a.txId)
        if (rc) return ethLanded(g, a.txId, rc)
      }
      const latest = await eth.nonceAt(d.address, 'latest')
      if (latest <= nonce) {                                          // not used: still pending — adopt it, the lane watches and bumps it
        for (const a of g.attempts) if (isOpen(a)) await emit({ type: 'reconcile', txId: a.txId, outcome: 'adopted' })   // never for a rejected one
        const open = g.attempts.filter(isHeld).filter((a) => a.eth !== undefined)
          .sort((x, y) => (big(x.eth!.maxFee) < big(y.eth!.maxFee) ? -1 : big(x.eth!.maxFee) > big(y.eth!.maxFee) ? 1 : 0))
        const dead = g.attempts.filter((a) => !isHeld(a) && a.eth !== undefined)
        const num = (a: AttemptView): number => g.attempts.indexOf(a) + 1   // attempts are in intent order: the journaled number
        adopted = { copy: g.copy, part: g.part, nonce, attempts: [...dead, ...open].map((a) => ({ id: a.txId, n: num(a), gas: big(a.eth!.gas), tip: big(a.eth!.tip), maxFee: big(a.eth!.maxFee), to: a.eth!.to, open: isOpen(a) })) }
        return null
      }
      // the nonce is used: only the tx found at that nonce decides (positive evidence, never absence)
      const at = await txAtNonce(d.address, nonce)
      if (at.kind === 'tx' && !ids.has(at.hash)) {
        for (const a of g.attempts) if (isHeld(a)) await emit({ type: 'reconcile', txId: a.txId, outcome: 'nonce-consumed' })
        // every tx of this lane is journaled before it is sent, so a foreign tx used this key: stop (fail closed)
        return { ok: false, why: `nonce ${nonce} was consumed by ${at.hash} (block ${at.block}), a transaction this executor did not sign — another holder of this key? The lane stops (fail closed)`, journaled: n }
      }
      if (round + 1 >= rounds) {
        const why = at.kind === 'tx' ? `our attempt ${at.hash} is in block ${at.block} but its receipt is not readable yet` : at.why
        for (const a of g.attempts) if (isOpen(a)) await emit({ type: 'stuck', txId: a.txId, reason: journalText(`nonce ${nonce} is used; ${why} — run again later (the chain is read again), or resolve it (vt job resolve)`) })
        return { ok: false, why: `copy ${g.copy} part ${g.part}: nonce ${nonce} is used and its outcome cannot be read yet (${why}) — stuck; run again later`, journaled: n }
      }
      await d.clock.sleep(d.poll)
    }
  }

  async function ethLanded(g: TxView, txId: string, rc: { blockNumber: string; gasUsed: string; effectiveGasPrice: string; status: string }): Promise<null> {
    await emit({ type: 'reconcile', txId, outcome: 'included', block: String(big(rc.blockNumber)), fee: String(big(rc.gasUsed) * big(rc.effectiveGasPrice)) })
    const bytes = d.payloadOf(g.copy, g.part)
    const rb = rc.status === '0x1' && bytes !== null ? await eth.readback(txId, bytes, d.to ?? d.address).catch(() => null) : null
    await emit({ type: 'readback', txId, ok: rb?.ok === true, detail: journalText(rc.status !== '0x1' ? 'landed with status 0: the calldata is on chain but the tx failed' : rb?.detail ?? 'no readback (transaction not found)') })
    return null
  }

  // ---------------- SOL job group ----------------
  async function solGroup(g: TxView): Promise<ReconcileResult | null> {
    const atts = g.attempts.filter((a) => a.sol !== undefined)
    const t: Record<string, any> = { copy: g.copy, part: g.part, parts: g.parts, attempts: atts.map((a) => ({ id: a.txId, lastValidBlockHeight: a.sol!.lastValidBlockHeight, cuPrice: a.sol!.cuPrice, fee: big(a.sol!.fee), rung: a.sol!.rung, ...declared(a.sol!.blockhash) })), raws: {}, payload: d.payloadOf(g.copy, g.part) ?? new Uint8Array() }
    const sts = await sol.statuses(atts.map((a) => a.txId), true)
    const hit = sts.findIndex((s) => s !== null && (s.err != null || s.confirmationStatus === 'confirmed' || s.confirmationStatus === 'finalized'))
    if (hit >= 0) return solLanded(g, atts[hit].txId)
    for (const a of g.attempts.filter(isHeld)) {
      const att = t.attempts.find((x: { id: string }) => x.id === a.txId)
      if (att === undefined) return { ok: false, why: `copy ${g.copy} part ${g.part}: an open attempt without its blockhash data`, journaled: n }
      let landedId: string | null = null
      const r = await _solWait(t, att, { notify: () => {}, alive: d.alive, poll: d.poll, solEndpoints: d.solEndpoints, clock: d.clock, journal: d.journal, stopRequested: d.stopRequested,
        finish: async (_t: unknown, x: { id: string }) => { landedId = x.id; return 'confirmed' } })
      if (r === 'confirmed' || r === 'failed') return solLanded(g, landedId ?? (t.landedId as string))
      if (r === 'unproven') { if (isOpen(a) && d.detach?.() !== true) await emit({ type: 'stuck', txId: a.txId, reason: journalText(String(t.reason)) }); return { ok: false, why: String(t.reason), journaled: n } }   // fix round 2 (M-4); R79: a detach escalates nothing
      if (r !== 'expired') return lost() ?? { ok: false, why: `copy ${g.copy} part ${g.part}: ${r}`, journaled: n }
      await emit({ type: 'reconcile', txId: a.txId, outcome: 'expired' })
    }
    return null
  }
  async function solLanded(g: TxView, txId: string): Promise<ReconcileResult | null> {
    const bytes = d.payloadOf(g.copy, g.part)
    const rb = await sol.readback(txId, bytes ?? new Uint8Array()).catch(() => null)
    const fee = rb?.fee ?? big(g.attempts.find((a) => a.txId === txId)?.sol?.fee ?? '0')
    await emit({ type: 'reconcile', txId, outcome: 'included', block: String((rb as { slot?: number } | null)?.slot ?? 0), fee: String(fee) })
    await emit({ type: 'readback', txId, ok: rb?.ok === true && bytes !== null, detail: journalText(rb?.detail ?? 'no readback (transaction not found)') })
    return null
  }

  // ---------------- the ETH claw-back family ----------------
  async function ethClaw(open: LeaseGrant['openIntents']): Promise<ReconcileResult | null> {
    const nonce = open.find((m) => m.eth !== undefined)?.eth?.nonce
    if (nonce === undefined) return { ok: false, why: 'a claw-back member without its nonce', journaled: n }
    const ids = [...new Set([...open.map((m) => m.txId), cs!.clawback?.txId ?? ''])].filter(Boolean)
    let adoptedClaw = false, pending = 0
    const maxPending = d.pendingPolls ?? 90
    for (let round = 0; ; round++) {
      const l = lost(); if (l) return l
      for (const id of ids) {
        const rc = await eth.receipt(id)
        if (!rc) continue
        const fee = big(rc.gasUsed) * big(rc.effectiveGasPrice)
        if (rc.status !== '0x1') {
          await emit({ type: 'clawback-failed', txId: id, reason: 'the claw-back landed with an error: nothing moved; the fee was charged', fee: String(fee) })
          for (const x of new Set([id, ...open.map((m) => m.txId)])) await emit({ type: 'reconcile', txId: x, outcome: 'nonce-consumed' })   // only evidence frees the cap
          return null
        }
        const tx = await ethRpc('eth_getTransactionByHash', [id])
        if (!tx) break                                                // a receipt without its tx: read again next round
        const to = String(tx.to ?? '').toLowerCase(), want = (cs!.clawback?.to ?? '').toLowerCase(), value = big(tx.value ?? '0x0')
        await emit({ type: 'clawback-included', txId: id, value: String(value), fee: String(fee) })
        const laneAfter = await eth.balance(d.address)
        await emit({ type: 'clawback-readback', txId: id, ok: to === want, destReceived: String(to === want ? value : 0n), laneBalance: String(laneAfter) })
        return null
      }
      const latest = await eth.nonceAt(d.address, 'latest')
      if (latest <= nonce) {                                          // pending: adopt (reconcile-first) and watch, bounded (E3 review m-2)
        if (!adoptedClaw) { adoptedClaw = true; for (const m of open) await emit({ type: 'reconcile', txId: m.txId, outcome: 'adopted' }) }
        // PF-E fix 1 (4): a member no endpoint has gets its identical bytes again (or every open member is stuck: they cannot be rebuilt)
        for (const m of open) {
          if (d.ethAccount === undefined || await eth.known(m.txId)) continue
          const bad = await resendClaw(m)
          if (bad !== null) {
            const why = `the claw-back ${m.txId.slice(0, 10)}… (nonce ${nonce}) is not at the nodes and cannot be sent again: ${bad} — nothing else is signed at that nonce; look it up: if it never landed, resolve it with vt job resolve mark-failed and claw back again; if it landed, run the claw-back again (the landing is read from the chain)`
            for (const x of open) await emit({ type: 'stuck', txId: x.txId, reason: journalText(why) })
            return { ok: false, why, journaled: n }
          }
        }
        const exit = `the claw-back (nonce ${nonce}) is still pending and may still land — run the claw-back again later to keep watching it; if it was dropped, resolve it (vt job resolve <job> --chain eth --tx <txId> mark-failed) and claw back again at the same nonce`
        if (d.stopRequested?.()) return { ok: false, why: `stopped while watching: ${exit}`, journaled: n }
        if (++pending >= maxPending) {
          for (const m of open) await emit({ type: 'stuck', txId: m.txId, reason: journalText(exit) })
          return { ok: false, why: exit, journaled: n }
        }
        await d.clock.sleep(Math.max(d.poll, 1))
        round = -1                                                    // the nonce is not used: the `rounds` count restarts
        continue
      }
      // the nonce is used: only the tx found at that nonce decides (positive evidence, never absence)
      const at = await txAtNonce(d.address, nonce)
      if (at.kind === 'tx' && !ids.includes(at.hash)) {
        for (const m of open) await emit({ type: 'reconcile', txId: m.txId, outcome: 'nonce-consumed' })   // every member dead: the claw-back fails by itself
        return { ok: false, why: `the claw-back's nonce ${nonce} was consumed by ${at.hash} (block ${at.block}), a transaction this executor did not sign — another holder of this key? (fail closed)`, journaled: n }
      }
      if (round + 1 >= rounds) {
        const why = at.kind === 'tx' ? `our claw-back ${at.hash} is in block ${at.block} but its receipt is not readable yet` : at.why
        for (const m of open) await emit({ type: 'stuck', txId: m.txId, reason: journalText(`nonce ${nonce} is used; ${why} — run the claw-back again later (the chain is read again), or resolve it (vt job resolve)`) })
        return { ok: false, why: `the claw-back's nonce ${nonce} is used and its outcome cannot be read yet (${why}) — stuck; run again later`, journaled: n }
      }
      await d.clock.sleep(d.poll)
    }
  }

  // PF-E fix 1 (4): the bytes of an adopted claw-back member, rebuilt and sent again (identical, or not at all). Its value and destination
  // come from the send ticket the API mints for it (the journaled clawback-intent: the reduced state keeps only the latest member's).
  // null: sent (any answer: the next poll looks again); else why the bytes cannot be the journaled ones.
  async function resendClaw(m: LeaseGrant['openIntents'][number]): Promise<string | null> {
    const built = rebuiltClaw.get(m.txId)
    if (built !== undefined) { await post(async () => eth.send(built.raw, await ticketFor(built, d))); return null }
    if (m.eth === undefined) return 'the member has no journaled nonce and fees'
    if (typeof d.journal.ticket !== 'function') return 'no send ticket can be asked for here'
    const a = { id: m.txId, ticket: '', ticketAt: 0 }
    const b = ticketBinds(await ticketFor(a, d))
    if (b === null || b.t !== m.txId || typeof b.to !== 'string' || typeof b.value !== 'string' || !/^[1-9][0-9]*$/.test(b.value)) return 'its send ticket does not bind a claw-back (destination and value) to rebuild'
    if (b.q !== String(m.eth.nonce)) return 'its send ticket declares another nonce'
    if (b.to.toLowerCase() !== m.eth.to.toLowerCase() || (cs!.clawback?.to !== undefined && b.to.toLowerCase() !== cs!.clawback.to.toLowerCase())) return 'its destination is not the claw-back\'s'
    /** the lane's signer, the network's chain id, the journaled fields */
    let s: { raw: `0x${string}`; id: string }
    try {
      const chainId = Number(BigInt(await ethRpc('eth_chainId', []) as string))
      s = await eth.signClawback(d.ethAccount as never, { chainId, nonce: m.eth.nonce, to: b.to, value: BigInt(b.value), maxFee: big(m.eth.maxFee), tip: big(m.eth.tip), gas: big(m.eth.gas) })
    } catch (e) { return `it cannot be rebuilt from its journaled intent (${journalText((e as Error)?.message ?? e, 120)})` }
    if (s.id.toLowerCase() !== m.txId.toLowerCase()) return 'rebuilt from its journaled intent and its ticket\'s value, its keccak256 is not the journaled tx id'
    if (sha256Hex(hexToBytes(s.raw)) !== b.r) return 'the sha256 of the rebuilt bytes is not the journaled rawSha256'
    const x = { ...a, raw: s.raw }
    rebuiltClaw.set(m.txId, x)
    await post(async () => eth.send(x.raw, await ticketFor(x, d)))
    return null
  }

  // ---------------- the SOL claw-back family ----------------
  async function solClaw(open: LeaseGrant['openIntents']): Promise<ReconcileResult | null> {
    const to = cs!.clawback?.to ?? ''
    for (const m of open) {
      if (m.sol === undefined) return { ok: false, why: 'a claw-back member without its blockhash data', journaled: n }
      const att = { id: m.txId, lastValidBlockHeight: m.sol.lastValidBlockHeight, cuPrice: m.sol.cuPrice, fee: big(m.sol.fee), ...declared(m.sol.blockhash) }
      const t: Record<string, any> = { copy: 'claw-back', part: 1, attempts: [att], raws: {} }
      const [st0] = await sol.statuses([m.txId], true)
      const st = st0 !== null && (st0.err != null || st0.confirmationStatus === 'confirmed' || st0.confirmationStatus === 'finalized') ? st0 : null
      let r: string = st ? (st.err ? 'failed' : 'confirmed') : ''
      if (!st) {
        r = await _solWait(t, att, { notify: () => {}, alive: d.alive, poll: d.poll, solEndpoints: d.solEndpoints, clock: d.clock, journal: d.journal, stopRequested: d.stopRequested, finish: async () => 'confirmed' })
      }
      if (r === 'unproven') { await emit({ type: 'stuck', txId: m.txId, reason: journalText(String(t.reason)) }); return { ok: false, why: String(t.reason), journaled: n } }   // fix round 2 (M-4)
      if (r === 'confirmed' || r === 'failed') {
        const res = await sol.transferResult(m.txId, to).catch(() => null)
        if (!res) return { ok: false, why: 'a claw-back landed but its transaction cannot be read yet — run again', journaled: n }
        if (res.err != null) {
          await emit({ type: 'clawback-failed', txId: m.txId, reason: journalText(`landed with error ${JSON.stringify(res.err)}`), fee: String(res.fee) })
          await emit({ type: 'reconcile', txId: m.txId, outcome: 'nonce-consumed' })   // its signature is used: it never lands again
        } else if (res.received === null) return { ok: false, why: 'a claw-back landed but what it moved cannot be measured yet — run again', journaled: n }
        else {
          await emit({ type: 'clawback-included', txId: m.txId, value: String(res.received), fee: String(res.fee) })
          await emit({ type: 'clawback-readback', txId: m.txId, ok: true, destReceived: String(res.received), laneBalance: String(await sol.solBalance(d.address)) })
        }
        return null
      }
      if (r !== 'expired') return lost() ?? { ok: false, why: `a claw-back member: ${r}`, journaled: n }
      await emit({ type: 'reconcile', txId: m.txId, outcome: 'expired' })
    }
    return null
  }
}

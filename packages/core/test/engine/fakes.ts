// Shared fakes for the engine tests (not a test file). ALL DATA IS SYNTHETIC; nothing listens on a port: the relay is a
// fetch function injected with configureRelay. Every journaled event is checked with E1's validateEvent.
import { base58, base64, base64urlnopad } from '@scure/base'
import { keccak256, parseTransaction, toHex } from 'viem'
import { VersionedTransaction } from '@solana/web3.js'
import { TICKET_PREFIX } from '../../src/contracts/index.ts'
import { validateEvent } from '../../src/job/index.ts'
import { configureRelay } from '../../src/engine/rpc.js'
import { CapLedger } from '../../src/gates/caps.ts'

export type Ev = { type: string; chain: 'eth' | 'sol'; [k: string]: unknown }
export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

// A syntactically valid ticket of the contract's TICKET_PREFIX (the relay, not the engine, checks the MAC).
export function ticketFor(label: string): string {
  const payload = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify({ j: '0123456789abcdef', w: 'local', c: 'eth', g: 1, t: label, r: 'a'.repeat(64), q: '0', e: 1, n: '0'.repeat(16) })))
  return `${TICKET_PREFIX}${payload}.${'A'.repeat(43)}`
}

// A journal that validates every event against the contract (by 'cli') and records it in order.
export function recordingJournal(o: { intent?: (ev: Ev) => Promise<{ ticket: string }> } = {}) {
  const events: Ev[] = []
  const check = (ev: Ev): void => {
    const { type, chain: _chain, ...data } = ev
    validateEvent(type, data, 'cli')
  }
  return {
    events,
    journal: {
      async append(ev: Ev): Promise<void> { check(ev); events.push(ev) },
      async intent(ev: Ev): Promise<{ ticket: string }> {
        check(ev)
        const r = o.intent ? await o.intent(ev) : { ticket: ticketFor(String(ev.txId)) }
        events.push(ev)
        return r
      },
    },
  }
}

export interface Call { chain: string; ep: string | null; method: string; params: unknown[]; ticket: string | null; at: number }

// The fake relay: one handler per chain; records every call (with the x-vt-send-ticket header).
export function fakeRelay(handlers: { eth?: (m: string, p: any[], ep: string | null) => unknown; sol?: (m: string, p: any[], ep: string | null) => unknown }) {
  const calls: Call[] = []
  const fetch = async (url: string, init: RequestInit): Promise<Response> => {
    const m = /\/relay\/(eth|sol)(?:\/ep\/(\d+))?$/.exec(url)
    if (m === null) return new Response(JSON.stringify({ error: { message: 'bad route' } }), { status: 403 })
    const body = JSON.parse(String(init.body)) as { id: number; method: string; params: unknown[] }
    const headers = (init.headers ?? {}) as Record<string, string>
    calls.push({ chain: m[1], ep: m[2] ?? null, method: body.method, params: body.params, ticket: headers['x-vt-send-ticket'] ?? null, at: performance.now() })
    const h = m[1] === 'eth' ? handlers.eth : handlers.sol
    try {
      const result = h === undefined ? undefined : await h(body.method, body.params as any[], m[2] ?? null)
      if (result === undefined) return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, error: { code: -32601, message: `no fake for ${body.method}` } }), { status: 200 })
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result }), { status: 200 })
    } catch (e) {
      // a TransportFailure is the relay's 502 "all endpoints failed" (no definitive answer: the engine reads `unknown`)
      if ((e as Error).name === 'TransportFailure') return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, error: { code: -32099, message: 'upstream timeout' } }), { status: 502 })
      // a RelayRefusal is the relay's own 403 before forwarding (e.g. today's relay.mjs: "sends go through /relay/<chain> only")
      if ((e as Error).name === 'RelayRefusal') return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, error: { code: -32601, message: (e as Error).message } }), { status: 403 })
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, error: { code: -32000, message: (e as Error).message } }), { status: 200 })
    }
  }
  configureRelay({ base: 'http://relay.test', fetch })
  return { calls, sends: () => calls.filter((c) => c.method === 'eth_sendRawTransaction' || c.method === 'sendTransaction') }
}

// A minimal anvil: pre-Amsterdam gas (21000 + 40·n), a fixed base fee, one block per send.
// from (optional): the one sender of this fake (eth_getBlockByNumber reports it, for the reconcile's search of the tx at a
// nonce); eth_getTransactionCount with a block number counts the txs mined up to that block.
export function fakeEthChain(o: { balance?: bigint; baseFee?: bigint; next?: () => bigint; mine?: boolean; tip?: bigint; afterSend?: () => void; from?: string } = {}) {
  let block = 100, nonce = 0, paid = 0n
  let base = o.baseFee ?? 1_000_000_000n
  const mined = new Map<string, { raw: string; block: number; input: string; to: string; nonce: number; gasUsed: bigint; price: bigint }>()
  const hx = (n: bigint | number): string => `0x${BigInt(n).toString(16)}`
  const handler = (m: string, p: any[]): unknown => {
    switch (m) {
      case 'eth_getTransactionCount': {
        const tag = p[1]
        if (typeof tag === 'string' && /^0x[0-9a-f]+$/i.test(tag)) { const b = Number(BigInt(tag)); return hx([...mined.values()].filter((t) => t.block <= b).length) }
        return hx(nonce)
      }
      case 'eth_getBlockByNumber': {
        const b = p[0] === 'latest' ? block : Number(BigInt(p[0]))
        const txs = [...mined.entries()].filter(([, t]) => t.block === b).map(([hash, t]) => {
          const tx = parseTransaction(t.raw as `0x${string}`)
          return p[1] === true ? { hash, from: o.from ?? '0x0000000000000000000000000000000000000000', nonce: hx(t.nonce), to: tx.to, value: hx(tx.value ?? 0n), input: tx.data ?? '0x' } : hash
        })
        return b > block ? null : { number: hx(b), transactions: txs }
      }
      case 'eth_getBalance': return hx((o.balance ?? 10n ** 18n) - paid)   // the fee of every mined tx is paid from the one account
      case 'eth_blockNumber': if (o.mine === false) block++; return hx(block)
      case 'eth_feeHistory': {
        const newest = p[1] === 'latest' ? block : Number(BigInt(p[1])), n = Math.min(Number(BigInt(p[0])), newest + 1)
        const fees = Array.from({ length: n + 1 }, (_, k) => hx(k === n && p[1] === 'latest' && o.next ? o.next() : base))
        return { oldestBlock: hx(newest - n + 1), baseFeePerGas: fees, reward: Array.from({ length: n }, () => [hx(o.tip ?? 1_000_000_000n), hx(o.tip ?? 1_000_000_000n)]) }
      }
      case 'eth_estimateGas': return hx(21000 + 40 * ((String(p[0].data ?? '0x').length - 2) / 2))
      case 'eth_call': return '0x'
      case 'eth_getCode': return '0x'                       // a plain account (E5: a lane refuses one with code)
      case 'eth_sendRawTransaction': {
        const raw = String(p[0]), id = keccak256(raw as `0x${string}`)
        o.afterSend?.()
        if (o.mine === false) return id                       // accepted into the pool, never mined
        const ptx = parseTransaction(raw as `0x${string}`), n = (String(ptx.data ?? '0x').length - 2) / 2
        const gasUsed = BigInt(21000 + 40 * n), price = ptx.maxFeePerGas !== undefined && base + (ptx.maxPriorityFeePerGas ?? 0n) > ptx.maxFeePerGas ? ptx.maxFeePerGas : base + (ptx.maxPriorityFeePerGas ?? 0n)
        block++; mined.set(id, { raw, block, input: '', to: '', nonce, gasUsed, price }); nonce++; paid += gasUsed * price
        return id
      }
      case 'eth_getTransactionReceipt': { const t = mined.get(String(p[0])); return t ? { transactionHash: p[0], blockNumber: hx(t.block), gasUsed: hx(t.gasUsed), effectiveGasPrice: hx(t.price), status: '0x1' } : null }
      case 'eth_getTransactionByHash': {
        const t = mined.get(String(p[0]))
        if (!t) return null
        const tx = parseTransaction(t.raw as `0x${string}`)
        return { hash: p[0], blockNumber: hx(t.block), nonce: hx(t.nonce), to: tx.to, value: hx(tx.value ?? 0n), input: tx.data ?? '0x' }
      }
      default: return undefined
    }
  }
  return { handler, mined, hx, setBase: (b: bigint) => { base = b } }
}

// A minimal Solana validator: price 0 (fee 5,000), 10,000 CU per simulation, confirmed right after a send.
export function fakeSolChain(o: { balance?: bigint } = {}) {
  const sent = new Map<string, Uint8Array>()   // signature → the signed tx bytes
  const handler = (m: string, p: any[]): unknown => {
    switch (m) {
      case 'getLatestBlockhash': return { context: { slot: 500 }, value: { blockhash: base58.encode(new Uint8Array(32).fill(7)), lastValidBlockHeight: 1_000 } }
      case 'simulateTransaction': return { context: { slot: 500 }, value: { err: null, unitsConsumed: 10_000 } }
      case 'getFeeForMessage': return { context: { slot: 500 }, value: 5000 }
      case 'isBlockhashValid': return { context: { slot: Math.max(600, Number(p[1]?.minContextSlot ?? 0)) }, value: true }   // Efix3: the expiry oracle — valid unless a test says otherwise
      case 'getBalance': return { context: { slot: 500 }, value: Number(o.balance ?? 10n ** 9n) }
      case 'getMinimumBalanceForRentExemption': return 890_880
      case 'sendTransaction': {
        const raw = base64.decode(String(p[0])), sig = base58.encode(VersionedTransaction.deserialize(raw).signatures[0])
        sent.set(sig, raw)
        return sig
      }
      case 'getTransaction': {
        const raw = sent.get(String(p[0]))
        if (!raw) return null
        const m = VersionedTransaction.deserialize(raw).message
        return { slot: 501, meta: { err: null, fee: 5000, computeUnitsConsumed: 10_000 },
          transaction: { message: { accountKeys: m.staticAccountKeys.map((k) => k.toBase58()), instructions: m.compiledInstructions.map((ix) => ({ programIdIndex: ix.programIdIndex, data: base58.encode(ix.data) })) } } }
      }
      case 'getSignatureStatuses': return { context: { slot: 600 }, value: (p[0] as string[]).map((s) => (sent.has(s) ? { slot: 501, confirmations: 1, err: null, confirmationStatus: 'confirmed' } : null)) }
      default: return undefined
    }
  }
  return { handler, sent }
}
export { toHex }

// A reduced job state with `chain` ARMED at `cap` (base units), as CapLedger.fromArmed reads it.
let ledgers = 0
export function armedState(chain: 'eth' | 'sol', cap: bigint, o: { spent?: bigint; txs?: unknown[]; openIntents?: string[]; clawback?: unknown; order?: Array<'eth' | 'sol'> } = {}): any {
  const order = o.order ?? [chain]
  return {
    phase: 'ARMED', releaseAt: 15_000, seq: 3, corrupt: null,
    armed: { armedAt: 0, releaseAt: 15_000, countdownSec: 15, schedule: { order, offsetSec: Object.fromEntries(order.map((c, i) => [c, i * 30])) },
      caps: Object.fromEntries(order.map((c) => [c, { nativeCap: String(cap), usd: 0, priceAt: null, overCap: false, planned: '0' }])), sources: {} },
    chains: { [chain]: { phase: 'ARMED', reason: null, address: null, copy: null, attempt: null, copiesIncluded: 0, reassembled: [], spent: String(o.spent ?? 0n),
      txs: o.txs ?? [], openIntents: o.openIntents ?? [], resume: null, stopRequested: false, clawback: o.clawback ?? null } },
  }
}
// A ledger for one test (a fresh synthetic key address each time, so tests never share a process-wide hold).
export function armedLedger(chain: 'eth' | 'sol', cap: bigint, o: Parameters<typeof armedState>[2] = {}): CapLedger {
  return CapLedger.fromArmed(armedState(chain, cap, o), chain, `test-key-${++ledgers}`)
}
export function transportFailure(): Error { const e = new Error('transport'); e.name = 'TransportFailure'; return e }
export function relayRefusal(message = 'sends go through /relay/<chain> only'): Error { const e = new Error(message); e.name = 'RelayRefusal'; return e }

// The engine's flat events as journal lines (by the lease holder, gen 1), after API lines (armed, …).
export function asJournal(api: Array<{ type: string; chain: 'eth' | 'sol' | null; data: Record<string, unknown> }>, engine: Ev[]): any[] {
  const lines: any[] = []
  for (const e of api) lines.push({ v: 1, seq: lines.length, at: lines.length, prev: '', chain: e.chain, by: 'api', gen: null, type: e.type, data: e.data })
  for (const ev of engine) { const { type, chain, ...data } = ev; lines.push({ v: 1, seq: lines.length, at: lines.length, prev: '', chain, by: 'cli', gen: 1, type, data }) }
  return lines
}
export const armedEvent = (chains: Array<'eth' | 'sol'>, cap: bigint) => ({ type: 'armed', chain: null, data: { armedAt: 0, releaseAt: 1, countdownSec: 5,
  schedule: { order: chains, offsetSec: Object.fromEntries(chains.map((c, i) => [c, i * 30])) },
  caps: Object.fromEntries(chains.map((c) => [c, { nativeCap: String(cap), usd: 0, priceAt: null, overCap: false, planned: '0' }])), sources: {} } })

// What the engine journals for a tx that landed (intent, then included with its fee), folded into a cap ledger — for
// fake adapters that stand in for ethTx / solTx: the ledger follows the journal (security review: cap-ledger drift).
export function journalLanding(ledger: CapLedger, t: { copy: number; part: number; parts: number }, fee: bigint): void {
  const n = t.copy * 100_000 + t.part
  const txId = ledger.chain === 'eth' ? `0x${n.toString(16).padStart(64, '0')}` : base58.encode(new Uint8Array(64).fill(n % 251 + 1).map((b, i) => (i < 8 ? (n >> (i * 4)) & 0xff : b)))
  const data = ledger.chain === 'eth' ? { eth: { nonce: t.copy, tip: '1', maxFee: String(fee), gas: '1', to: '0x0000000000000000000000000000000000000000' } }
    : { sol: { blockhash: base58.encode(new Uint8Array(32).fill(7)), lastValidBlockHeight: 1, cuPrice: 0, cuLimit: 1, rung: null, fee: String(fee) } }
  ledger.observe({ type: 'intent', chain: ledger.chain, txId, copy: t.copy, part: t.part, parts: t.parts, ...data })
  ledger.observe({ type: 'included', chain: ledger.chain, txId, copy: t.copy, part: t.part, attempt: 1, block: '1', fee: String(fee), ms: 1 })
}

// A fake clock for the engine's clock seam (E3 ruling 5): sleep advances time at once (and yields to the event loop).
export function fakeClock(start = 1_791_504_000_000) {
  let t = start
  return { now: (): number => t, sleep: async (ms: number): Promise<void> => { t += ms; await new Promise((r) => setImmediate(r)) } }
}

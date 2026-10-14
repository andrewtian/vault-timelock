// Shared builders for the executor tests (not a test file). ALL DATA IS SYNTHETIC: generated keys, fake chains, the
// in-memory API (test/fakes/fake-journal.ts) and relay (test/fakes/fake-relay.ts); nothing listens on a port.
import { Keypair, VersionedMessage, VersionedTransaction } from '@solana/web3.js'
import { base58, base64, base64urlnopad } from '@scure/base'
import { generatePrivateKey } from 'viem/accounts'
import { hexToBytes, keccak256, parseTransaction } from 'viem'
import { sha256Hex } from '../../src/job/canonical.ts'
import { normalizeJob } from '../../src/job/index.ts'
import type { Chain, JobDef, Network } from '../../src/contracts/index.ts'
import { fromSecret } from '../../src/engine/keys.js'
import type { ExecutorKey } from '../../src/executor/executor.ts'
import { fakeJournal, virtualClock } from '../fakes/fake-journal.ts'
import type { VClock } from '../fakes/fake-journal.ts'
import { fakeRelayClient } from '../fakes/fake-relay.ts'
import { fakeEthChain, fakeSolChain } from '../engine/fakes.ts'

export const T0 = 1_791_504_000_000
// the recentBlockhash of a base64 message (a getFeeForMessage probe; the expiry evidence is isBlockhashValid, Efix3)
export const recentBlockhashOf = (b64: unknown): string => VersionedMessage.deserialize(base64.decode(String(b64))).recentBlockhash
// Every ticketed send the fake relay saw that was NOT exactly its journaled intent (CC-3a: the declared ETH nonce / SOL
// blockhash — the ticket's q — is the signed one; the tx id and the raw bytes are the intent's). The executor tests
// assert it stays empty.
export const sendViolations: string[] = []
export const sendStats = { checked: 0 }
type Ev = { type: string; data: Record<string, any> }
export function checkSend(events: readonly Ev[], chain: Chain, params: any[], ticket: string | null): string | null {
  if (ticket === null) return null                                              // a test seeding the chain (an earlier holder)
  let t: { t?: unknown; r?: unknown; q?: unknown }
  try { t = JSON.parse(new TextDecoder().decode(base64urlnopad.decode(ticket.split('.')[1]))) } catch { return 'an unreadable ticket' }
  const intent = events.find((e) => (e.type === 'intent' || e.type === 'clawback-intent') && e.data.txId === t.t)
  if (intent === undefined) return `no journaled intent for ${String(t.t)}`
  if (chain === 'eth') {
    const raw = String(params[0]) as `0x${string}`, tx = parseTransaction(raw)
    if (keccak256(raw).toLowerCase() !== intent.data.txId) return 'another tx id than the intent'
    if (sha256Hex(hexToBytes(raw)) !== intent.data.rawSha256 || t.r !== intent.data.rawSha256) return 'other bytes than the intent'
    if (tx.nonce !== intent.data.eth?.nonce) return `nonce ${tx.nonce} ≠ declared ${intent.data.eth?.nonce}`
    if (t.q !== String(tx.nonce)) return `ticket q ${String(t.q)} ≠ the signed nonce ${tx.nonce}`
  } else {
    const bytes = base64.decode(String(params[0])), vt = VersionedTransaction.deserialize(bytes)
    if (base58.encode(vt.signatures[0]) !== intent.data.txId) return 'another signature than the intent'
    if (sha256Hex(bytes) !== intent.data.rawSha256 || t.r !== intent.data.rawSha256) return 'other bytes than the intent'
    if (vt.message.recentBlockhash !== intent.data.sol?.blockhash) return `blockhash ${vt.message.recentBlockhash} ≠ declared ${intent.data.sol?.blockhash}`
    if (t.q !== vt.message.recentBlockhash) return `ticket q ${String(t.q)} ≠ the signed blockhash`
  }
  return null
}
export function newKey(chain: Chain): ExecutorKey & { handle: any } {
  const k = chain === 'eth' ? fromSecret('eth', generatePrivateKey()) : fromSecret('sol', base58.encode(Keypair.generate().secretKey))
  return { chain, address: k.address, network: 'local', handle: k }
}
export function jobFor(chain: Chain, key: { address: string }, o: { copies?: number | null; text?: string; network?: Network; feeStrategy?: string; distinct?: boolean } = {}): { def: JobDef; text: string } {
  const text = o.text ?? 'Executor test message.\n'
  // a new mainnet job names its claw-back address (PF-S fix round 1, N-6: job.clawback-required): synthetic ones here
  const clawbackTo = o.network === 'mainnet' && chain !== 'btc' ? (chain === 'eth' ? '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6' : 'G147qVmzynHL3EjQ8tvBGDms7u6FDCWbFfFmzNMZmg1x') : null
  const ch: Record<string, unknown> = { mode: o.copies === null ? 'drain' : { copies: o.copies ?? 1 }, keyAddress: key.address, budgetUsd: 5, clawbackTo, distinctCopies: o.distinct ?? true, feeStrategy: o.feeStrategy ?? (chain === 'eth' ? 'prompt' : 'passive') }
  const { def } = normalizeJob({ format: 'vt-job/1', network: o.network ?? 'local', name: `executor ${chain}`, message: text, chains: { [chain]: ch } }, { network: o.network ?? 'local' })
  return { def, text }
}
// A stack: the fake API with the job, the key loaded + funded by an earlier tab (gen 1, released), armed; a fake chain
// behind a fake relay. releaseAt is `startIn` ms after now on the server clock.
export function stack(chain: Chain, o: { copies?: number | null; text?: string; network?: Network; serverOffsetMs?: number; startIn?: number; cap?: string; feeStrategy?: string; relayNetwork?: Network; apiNetwork?: Network; endpoints?: number; ethEndpoints?: number; isTor?: boolean | null; sol?: (m: string, p: any[], ep: number | null, base: (m: string, p: any[]) => unknown) => unknown; eth?: (m: string, p: any[], base: (m: string, p: any[]) => unknown, ep: number | null) => unknown; arm?: boolean; key?: ReturnType<typeof newKey>; clock?: VClock; ethBalance?: bigint } = {}) {
  const clock = o.clock ?? virtualClock(T0)
  const key = o.key ?? newKey(chain)
  const { def, text } = jobFor(chain, key, o)
  const j = fakeJournal({ def, text, clock, network: o.apiNetwork ?? def.network, serverOffsetMs: o.serverOffsetMs ?? 0 })
  const ethChain = fakeEthChain({ balance: o.ethBalance ?? 10n ** 18n, from: key.address })
  const solChain = fakeSolChain({ balance: 10n ** 10n })
  const ethH = (m: string, p: any[]) => (m === 'eth_chainId' ? '0x7a69' : m === 'eth_getCode' ? '0x' : ethChain.handler(m, p))
  let bh = 0                                                                     // a fresh blockhash per read: one signature per part and copy
  const solH = (m: string, p: any[]): unknown => {
    if (m === 'getLatestBlockhash' && p[0]?.commitment !== 'finalized') { bh++; return { context: { slot: 500 + bh }, value: { blockhash: base58.encode(new Uint8Array(32).fill(bh % 250 + 1)), lastValidBlockHeight: 1_000 } } }
    return solChain.handler(m, p)
  }
  const relay = fakeRelayClient({ network: o.relayNetwork ?? def.network, endpoints: { eth: o.ethEndpoints ?? 1, sol: o.endpoints ?? 1 }, ...(o.isTor !== undefined ? { isTor: o.isTor } : {}),
    onSend: (c, params, ticket) => { const why = checkSend(j.events, c, params, ticket); if (ticket !== null) sendStats.checked++; if (why !== null) { sendViolations.push(why); throw new Error(`relay: the signed tx is not the journaled intent (${why})`) } },
    eth: (m, p, ep) => (o.eth ? o.eth(m, p, ethH, ep) : ethH(m, p)), sol: (m, p, ep) => (o.sol ? o.sol(m, p, ep, solH) : solH(m, p)) })
  // the earlier tab: key-loaded, funds (gen 1), released
  j.client.lease(j.id, chain, 'acquire', 'browser')
  j.asHolder(1, 'browser', chain, 'key-loaded', { address: key.address })
  j.asHolder(1, 'browser', chain, 'funds', { balance: '1000000000', affordable: true, nextCopyCost: '1' })
  void j.client.lease(j.id, chain, 'release', 'browser', 1)
  if (o.arm !== false) j.arm([chain], { caps: { [chain]: o.cap ?? (chain === 'eth' ? '100000000000000000' : '100000000') }, releaseAt: j.serverNow() + (o.startIn ?? 5_000) })
  return { clock, key, def, text, j, relay, ethChain, solChain }
}
export const deps = (s: ReturnType<typeof stack>, extra: Record<string, unknown> = {}) => ({ journal: s.j.client, relay: s.relay.client, clock: s.clock, random: { int: () => 0 }, poll: 1_000, passiveWaitMs: 1_000, ...extra })
export const types = (evs: Array<{ type: string; chain: string | null; by: string }>, chain: Chain) => evs.filter((e) => e.chain === chain && e.by !== 'api').map((e) => e.type)

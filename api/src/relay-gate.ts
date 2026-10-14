// api/src/relay-gate.ts — the relay's gates (spec §5.6, §6.1 items 1, 3 and 6, §13), in TypeScript so the mutation
// runner covers them. The ported relay (api/relay/relay.mjs) calls them on every request.
//
// checkRelayHeaders (every request; CSRF and DNS rebinding):
//   · every header at most once (a repeated Host, Origin or ticket would be read differently by different parsers);
//   · Host: 127.0.0.1 and this network's relay port, page port, or (local only) the Vite dev port (PORTS);
//   · Origin: absent (the CLI executor, curl), or this network's page origin, or (local only) the Vite dev origin;
//   · Sec-Fetch-Site: absent, same-origin or none (cross-site and same-site are refused, as at the API).
// checkMethodForNetwork: requestAirdrop (the devnet faucet, R71d) only on the sol route of the local and testnet relays.
// classifyMethod (S3 review I-1: DEFAULT-DENY, the single method table of the relay): a method is a READ only when it is
//   on READ_METHODS[network][chain] (exact names, pinned by a test); it is forwarded without a ticket. Every other method
//   is a SEND, and only the chain's known job send (JOB_SEND_METHODS) may be forwarded, through checkSend. Anything
//   else is refused outright (relay.method). So a method nobody classified can never skip the ticket or the lock.
// checkSend (every send; spec §5.6; async since S4): no send without a valid ticket from the API, and only the bytes it
// ticketed.
//   1. format and MAC (constant time), then e > now: S1's verifyTicket (relay.send-ticket, relay.ticket-expired); a v1
//      ticket is refused there (CC-3: no downgrade);
//   2. w = this relay's network (relay.ticket-network); c = the route's chain (relay.ticket-chain);
//   3. r = sha256 of the raw bytes the relay will forward (relay.ticket-raw). The raw bytes are ETH params[0] (0x-hex,
//      the only param), SOL params[0] (canonical padded base64, with params[1].encoding exactly 'base64', so the
//      upstream decodes the very string that was hashed) or BTC params[0] (lowercase hex, the only param; S6b);
//      anything else has no unambiguous bytes and is refused;
//   4. C2's job-send lock with the identity this relay verified at startup: assertJobSendAllowed(network,
//      { chain, id }) → release.mainnet-locked on mainnet (and for any mainnet identity), config.identity-mismatch for
//      a foreign one. The relay has its own SOCKS code (it does not use createNet), so the lock is called here. A BTC send
//      off local takes the all-scope lock too (PF-S M-1: MAINNET_SEND_ENABLED; the job-send flip never opens mainnet BTC);
//   5. S4 decode verification (decode.ts, relay.decode-mismatch): the bytes decode to a tx of the ticket's kind, by the
//      ticket's sender a, with txId t, payload p or destination/value to/value, and a worst-case fee ≤ f. BTC (CC-8, S6b):
//      commit | reveal, the inputs q, the outputs to/value (+ the change to a), the fee from the relay's own chain read of
//      the input values (btcPrevouts; relay.btc-prevout when it finds nothing), the reveal's inscription p.
// The caller must AWAIT checkSend and forward nothing unless it resolves (relay.mjs; pinned over HTTP).
// On /relay/<chain> a ticket is stateless and reusable until e: an identical-bytes SOL rebroadcast within the TTL passes
// again (§5.6).
// Per-endpoint routes (Sfix1): checkSend is also the ONLY gate of /relay/<chain>/ep/<i> (SendCheck.route), for reads
// and sends alike, so both routes run exactly the checks above. The route adds, before them, that i names an endpoint
// that passed identity at startup (relay.endpoint-unverified) and that only SOL sends there (ETH per-endpoint routes stay
// read-only: relay.endpoint-read-only); and, after every check passed, the endpoint's budget: one ticket goes to each
// verified endpoint at most once while it is valid (relay.ticket-endpoint-reused; EndpointLedger). Other bytes under the
// ticket fail step 3 (relay.ticket-raw) on every route.
// The ticket (CC-3, v2) binds (job, network, chain, gen, txId, rawSha256, sender, kind, payload or destination and
// value, worst-case fee) of the API-journaled intent.
// Messages never echo a header, a ticket, a param or an address.
import { createHash } from 'node:crypto'
import { PORTS } from '@vault-timelock/core/contracts'
import type { Network, TicketPayload } from '@vault-timelock/core/contracts'
import { assertJobSendAllowed } from 'vt-broadcast/src/config.ts'
import { refuse } from 'vt-broadcast/src/guard.ts'
import { BTC_RAW_MAX, assertDecodedMatches } from './decode.ts'
import type { BtcPrevouts } from './decode.ts'
import { verifyTicket } from './tickets.ts'

// The JSON-RPC chain routes: POST /relay/eth, /relay/sol and (S6, local only) /relay/btc, the local bitcoind.
export type RelayChain = 'eth' | 'sol' | 'btc'
// The chains whose sends the relay forwards (ticket v2's c). BTC (CC-8, S6b): POST /relay/btc/send, one ticketed raw tx.
export type SendChain = 'eth' | 'sol' | 'btc'
export const AIRDROP_METHOD = 'requestAirdrop'

// ---- the method table (the only one: relay.mjs forwards exactly these)

// Reads: answered upstream without a ticket. relay.mjs adds parameter guards to some (simulateTransaction: zero
// signatures and sigVerify false; eth_feeHistory: ≤ 1024 blocks, base fee only above 64; requestAirdrop: ≤ 1 SOL).
const ETH_READS = Object.freeze(['eth_chainId', 'eth_blockNumber', 'eth_getBalance', 'eth_getTransactionCount', 'eth_estimateGas', 'eth_call',
  'eth_feeHistory', 'eth_maxPriorityFeePerGas', 'eth_getBlockByNumber', 'eth_getTransactionReceipt', 'eth_getTransactionByHash',
  'eth_getCode'])                                   // 7b: the claw-back destination class
const SOL_READS = Object.freeze(['getGenesisHash', 'getLatestBlockhash', 'getBalance', 'getFeeForMessage', 'simulateTransaction',
  'getSignatureStatuses', 'getTransaction', 'getMinimumBalanceForRentExemption',
  'getRecentPrioritizationFees',                    // the CU-price rule (research §8)
  'getSignaturesForAddress',                        // the address-history check before Arm (security review I2)
  'getAccountInfo',                                 // E3 preflight: the Memo v2 program is deployed and executable (I3)
  'isBlockhashValid'])                              // E3 SOL expiry evidence for a declared blockhash (I3; read-only)
// requestAirdrop is the devnet faucet (R71d): a read of the local and testnet sol routes only (checkMethodForNetwork).
const SOL_FAUCET_READS = Object.freeze([...SOL_READS, AIRDROP_METHOD])
// S6: the local bitcoind (regtest; its credential is added by the relay, never by the caller). Reads only: chain and
// block data, a tx and its outputs, the mempool entry of a tx, the fee estimate, the UTXOs of addresses (scantxoutset
// 'start' with addr() descriptors only: checkBtcParams in relay-routes.ts) and testmempoolaccept, which validates signed
// bytes against the local node's mempool rules WITHOUT relaying them (the commit/reveal dry run). No wallet method, no
// sendrawtransaction (a BTC send is the ticketed POST /relay/btc/send, S6b, never this JSON-RPC route), no mining, no node control. Testnet4 and mainnet have no
// bitcoind: their BTC reads are Esplora GET routes (relay-routes.ts), so their lists are empty.
const BTC_LOCAL_READS = Object.freeze(['getblockchaininfo', 'getblockcount', 'getbestblockhash', 'getblockhash', 'getblockheader', 'getblock',
  'getrawtransaction', 'gettxout', 'getmempoolentry', 'estimatesmartfee', 'testmempoolaccept', 'scantxoutset'])
const NO_READS: readonly string[] = Object.freeze([])
export const READ_METHODS: Readonly<Record<Network, Readonly<Record<RelayChain, readonly string[]>>>> = Object.freeze({
  local: Object.freeze({ eth: ETH_READS, sol: SOL_FAUCET_READS, btc: BTC_LOCAL_READS }),
  testnet: Object.freeze({ eth: ETH_READS, sol: SOL_FAUCET_READS, btc: NO_READS }),
  mainnet: Object.freeze({ eth: ETH_READS, sol: SOL_READS, btc: NO_READS }),
})
// The job sends (spec §5.6): the only sends the relay forwards, each with a ticket and the job-send lock.
// btc is not a JSON-RPC method: 'btc_send' names the one ticketed send of POST /relay/btc/send (relay.mjs refuses it, and every
// other send, on the JSON-RPC route /relay/btc).
export const BTC_SEND_METHOD = 'btc_send'
export const JOB_SEND_METHODS: Readonly<Record<SendChain, string>> = Object.freeze({ eth: 'eth_sendRawTransaction', sol: 'sendTransaction', btc: BTC_SEND_METHOD })
// The same set as relay-core.mjs SEND_METHODS (its no-retry policy for sends; pinned by a test): the JSON-RPC sends. The btc
// send is not a JSON-RPC method; relay.mjs asks exchange() for the no-retry policy directly.
export const SEND_METHODS: readonly string[] = Object.freeze([JOB_SEND_METHODS.eth, JOB_SEND_METHODS.sol])

export const isReadMethod = (network: Network, chain: RelayChain, method: string): boolean => READ_METHODS[network][chain].includes(method)

// THE relay.method line (one marker): a JSON-RPC method off the route's list, or an HTTP method a route does not take
// (the S6 breadth routes are GET only: relay-routes.ts resolveRest).
export function methodOk(ok: boolean): asserts ok {
  if (!ok) refuse('relay.method', "this method is not on the relay's list for this route and network (JSON-RPC: the read list, or this chain's job send; the breadth routes: GET only)") // @guard:relay.method
}

// 'read' or 'send'; any other method is refused (default deny).
export function classifyMethod(network: Network, chain: RelayChain, method: string): 'read' | 'send' {
  if (isReadMethod(network, chain, method)) return 'read'
  methodOk(method === JOB_SEND_METHODS[chain])
  return 'send'
}

// ---- headers (shared with serve-gate.ts)

// The first header name sent more than once (case-insensitive), or null.
export function repeatedHeader(raw: readonly string[]): string | null {
  const seen = new Set<string>()
  for (let i = 0; i < raw.length; i += 2) {
    const name = raw[i].toLowerCase()
    if (seen.has(name)) return name
    seen.add(name)
  }
  return null
}

// The value of header `name` (lower case), or undefined when absent. Callers refuse repeats first.
export function headerValue(raw: readonly string[], name: string): string | undefined {
  for (let i = 0; i < raw.length; i += 2) if (raw[i].toLowerCase() === name) return raw[i + 1]
  return undefined
}

const loopback = (port: number): string => `127.0.0.1:${port}`

export function relayHosts(network: Network): string[] {
  const p = PORTS[network]
  return [p.relay, p.page, ...(p.dev === null ? [] : [p.dev])].map(loopback)
}

export function relayOrigins(network: Network): string[] {
  const p = PORTS[network]
  return [p.page, ...(p.dev === null ? [] : [p.dev])].map((port) => `http://${loopback(port)}`)
}

export function checkRelayHeaders(raw: readonly string[], network: Network): void {
  const once = repeatedHeader(raw) === null
  if (!once) refuse('relay.header-repeated', 'a request header was sent more than once') // @guard:relay.header-repeated
  const host = headerValue(raw, 'host')
  const hostOk = host !== undefined && relayHosts(network).includes(host)
  if (!hostOk) refuse('relay.host', "requests must be addressed to this network's relay (or its page) on loopback") // @guard:relay.host
  const origin = headerValue(raw, 'origin')
  const originOk = origin === undefined || relayOrigins(network).includes(origin)
  if (!originOk) refuse('relay.origin', "only this network's own page may call the relay") // @guard:relay.origin
  const site = headerValue(raw, 'sec-fetch-site')
  const siteOk = site === undefined || site === 'same-origin' || site === 'none'
  if (!siteOk) refuse('relay.fetch-site', 'cross-site and same-site requests are refused') // @guard:relay.fetch-site
}

// ---- methods per network

export function checkMethodForNetwork(network: Network, chain: string, method: string): void {
  const ok = method !== AIRDROP_METHOD || (chain === 'sol' && (network === 'local' || network === 'testnet'))
  if (!ok) refuse('relay.airdrop-network', 'requestAirdrop is the devnet faucet: allowed on the sol route of the local and testnet relays only') // @guard:relay.airdrop-network
}

// ---- sends

const ETH_RAW = /^0x(?:[0-9a-fA-F]{2})+$/
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
const BTC_RAW = /^(?:[0-9a-f]{2})+$/                 // CC-8: lowercase hex only, so the bytes hashed are the string forwarded

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype

// The exact bytes a send forwards, or null when params do not name them unambiguously.
export function rawBytes(chain: SendChain, params: unknown): Buffer | null {
  if (!Array.isArray(params) || params.length === 0) return null
  const raw: unknown = params[0]
  if (typeof raw !== 'string') return null
  if (chain === 'eth') return params.length === 1 && ETH_RAW.test(raw) ? Buffer.from(raw.slice(2), 'hex') : null
  if (chain === 'btc') return params.length === 1 && raw.length <= 2 * BTC_RAW_MAX && BTC_RAW.test(raw) ? Buffer.from(raw, 'hex') : null
  const cfg: unknown = params[1]
  if (params.length !== 2 || !isPlainObject(cfg) || cfg.encoding !== 'base64' || raw === '' || !B64.test(raw)) return null
  const bytes = Buffer.from(raw, 'base64')
  return bytes.toString('base64') === raw ? bytes : null
}

// ---- per-endpoint routes (Sfix1)

// The chains whose per-endpoint routes take the job send: SOL only. The engine sends the same signed SOL bytes with the
// same ticket to every verified SOL endpoint (E5, packages/core engine.js postSol). ETH per-endpoint routes are read-only.
export const EP_SEND_CHAINS: readonly RelayChain[] = Object.freeze(['sol'])

// Which verified endpoints each ticket has been sent to through /relay/<chain>/ep/<i>. One ticket goes to each endpoint
// at most once while it is valid; a second send is REFUSED (not answered from memory): the relay never makes up an
// upstream answer, a refusal tells the client that nothing left the machine, and the engine then sends the same bytes
// through /relay/<chain>, which keeps the §5.6 stateless reuse for its 2-s rebroadcasts. A ticket is its verified
// payload (every field, so another encoding of the same payload is the same ticket); a new ticket for the same intent
// (POST …/tickets) is a new budget. In memory: an entry lives until its ticket's e (verifyTicket refuses the ticket
// from then on) and is pruned at the next claim; a relay restart starts empty (the 120-s TTL bounds that to one more
// send per endpoint). claim() is synchronous, so two concurrent sends of one ticket to one endpoint cannot both pass.
export interface EndpointLedger {
  claim(p: TicketPayload, ep: number, now: number): void
  readonly size: number                     // live entries (tests)
}
export function createEndpointLedger(): EndpointLedger {
  const sent = new Map<string, { e: number; eps: Set<number> }>()
  return {
    claim(p, ep, now) {
      for (const [k, v] of sent) if (v.e <= now) sent.delete(k)
      const id = createHash('sha256').update(JSON.stringify([p.j, p.w, p.c, p.g, p.t, p.r, p.a, p.k, p.p, p.to, p.value, p.f, p.q, p.e, p.n])).digest('hex')
      const entry = sent.get(id) ?? { e: p.e, eps: new Set<number>() }
      const first = !entry.eps.has(ep)
      if (!first) refuse('relay.ticket-endpoint-reused', 'this send ticket was already used on this endpoint route: each verified endpoint takes a ticket once (rebroadcasts go through the chain route); nothing was forwarded') // @guard:relay.ticket-endpoint-reused
      entry.eps.add(ep)
      sent.set(id, entry)
    },
    get size() { return sent.size },
  }
}

// /relay/<chain>/ep/<i> (relay.mjs passes it; absent or null = /relay/<chain>, the preferred endpoint with failover).
export interface EndpointRoute {
  ep: number                                // the route's index i
  verified: number                          // this chain's endpoints that passed identity at startup (relay status)
  ledger: EndpointLedger                    // the relay's one ledger
}

// Before any other check, reads and sends alike: i is exactly a verified endpoint, and a send is on a chain whose
// per-endpoint routes take sends.
function checkEndpointRoute(chain: RelayChain, kind: 'read' | 'send', r: EndpointRoute): void {
  const indexOk = Number.isSafeInteger(r.ep) && r.ep >= 0 && r.ep < r.verified
  if (!indexOk) refuse('relay.endpoint-unverified', 'the endpoint index names no endpoint that passed the identity check at startup') // @guard:relay.endpoint-unverified
  const sendOk = kind === 'read' || EP_SEND_CHAINS.includes(chain)
  if (!sendOk) refuse('relay.endpoint-read-only', "this chain's per-endpoint routes are read-only: its sends go through the chain route") // @guard:relay.endpoint-read-only
}

export interface SendCheck {
  network: Network
  chain: RelayChain                         // the route's chain (/relay/<chain>); btc: reads on /relay/btc, the ticketed send on /relay/btc/send (S6b)
  method: string
  params: unknown
  ticketHeader: string | null | undefined   // the x-vt-send-ticket value (headers are checked for repeats first)
  key: Uint8Array                           // relay-ticket.key (32 bytes)
  now: number
  observedId: string                        // the identity verified at startup: eth_chainId / getGenesisHash
  route?: EndpointRoute | null              // /relay/<chain>/ep/<i>; absent or null: /relay/<chain>
  btcPrevouts?: BtcPrevouts                 // btc sends: the relay's own chain read of an input outpoint (absent: relay.btc-prevout)
}

// Resolves for a read; rejects every other method unless it is this chain's job send and every check above holds.
// The same function gates /relay/<chain> and /relay/<chain>/ep/<i> (Sfix1: one code path).
// Resolves with the verified ticket payload of a send (null for a read).
export async function checkSend(o: SendCheck): Promise<TicketPayload | null> {
  const kind = classifyMethod(o.network, o.chain, o.method)
  const route = o.route ?? null
  if (route !== null) checkEndpointRoute(o.chain, kind, route)
  if (kind === 'read') return null
  const chain = o.chain
  const p = verifyTicket(o.key, typeof o.ticketHeader === 'string' ? o.ticketHeader : '', o.now)
  const networkOk = p.w === o.network
  if (!networkOk) refuse('relay.ticket-network', "the send ticket was issued for another network's stack") // @guard:relay.ticket-network
  const chainOk = p.c === chain
  if (!chainOk) refuse('relay.ticket-chain', "the send ticket was issued for another chain's route") // @guard:relay.ticket-chain
  const raw = rawBytes(chain, o.params)
  const rawOk = raw !== null && createHash('sha256').update(raw).digest('hex') === p.r
  if (!rawOk) refuse('relay.ticket-raw', 'the raw transaction is not the journaled one (sha256 differs, or params[0] is not exact 0x-hex / base64 with encoding base64)') // @guard:relay.ticket-raw
  assertJobSendAllowed(o.network, { chain, id: o.observedId })
  await assertDecodedMatches(p, raw ?? new Uint8Array(0), o.network, o.btcPrevouts === undefined ? {} : { btcPrevouts: o.btcPrevouts })
  if (route !== null) route.ledger.claim(p, route.ep, o.now)   // last: only a send that passed every check spends its endpoint
  return p
}

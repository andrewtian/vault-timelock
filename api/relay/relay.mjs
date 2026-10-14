// @ts-check
// PORTED (R69) from the prototype, tag add7b-e540f8ae4d6b, relay.mjs (sha256 b9afd954223b13c78b3628aaf60a4b7659bd5a3096e08a2101328be8e398ac0c).
// Changes (spec §6.1 items 1–6; everything else is the prototype's behaviour):
//   1. ports and page origins from PORTS[network] (--network; MQ's --profile is an alias); the Vite dev origin :5183 on
//      local only. Host / Origin / Sec-Fetch-Site / repeated headers: api/src/relay-gate.ts checkRelayHeaders (the
//      localhost:<port> spellings are no longer accepted, as at the API).
//   2. upstreams from broadcast/endpoints.json through loadConfig (1rpc.io demoted to the end of a list: it refuses
//      reads over Tor); identities through config.ts identityMatches (one source: the relay's own copies are gone).
//   3. send tickets and the job-send lock: relay-gate.ts checkSend (relay-ticket.key from <home>/<network>/, read on
//      every send so a key `vt up` rewrote is honoured, and a missing key refuses). The method table is relay-gate.ts's
//      READ_METHODS / JOB_SEND_METHODS (S3 review I-1): default deny, so nothing unlisted skips the ticket or the lock.
//      S4: checkSend also decodes the signed bytes and checks them against the ticket v2 (decode.ts:
//      relay.decode-mismatch): sender, kind, txId, payload or destination and value, and the worst-case fee ≤ f.
//      Sfix1: checkSend is also the gate of /relay/<chain>/ep/<i> (the route is passed in), so a SOL send there runs
//      exactly the checks of /relay/sol, then spends that endpoint's once-per-ticket budget (createEndpointLedger).
//   4. GET /relay/status → RelayStatus. identity.eth also carries the fork-drift check (ruling Q4: one eth_estimateGas
//      of a FORK_PROBE_BYTES data tx at startup; a drift is reported with checkForkDrift's message, ok false).
//   5. VT_TEST_ETH_RPC / VT_TEST_SOL_RPC stay local-only (refused on testnet and mainnet) and loopback-only; they reach
//      loadConfig as overrides. The SOL pressure filter is a test harness and never imported here.
//   6. networks (R71): testnet = Sepolia + Solana devnet over Tor (endpoints.json `testnet`); requestAirdrop on the sol
//      route of local and testnet only (relay-gate checkMethodForNetwork → relay.airdrop-network), ≤ 1 SOL; the testnet
//      price is a labelled nominal fixture, "TEST FUNDS — NO VALUE".
//   8. breadth routes (S6, M4; the gates are api/src/relay-routes.ts): read-only, each with its allowlist, its Tor role
//      and its identity check. BTC is a chain: on local the regtest bitcoind (POST /relay/btc, JSON-RPC, the read list of
//      relay-gate.ts; the credential is read ONCE at startup from $OUT/local/btc-rpc.auth by loadBitcoindAuth, $OUT being
//      VAULT_TIMELOCK_DIR as `vt up` passes it, never a default; it goes only into the Authorization header of requests
//      to that loopback bitcoind, never into a response, a log line, an error, argv or a child's env), and the regtest ord
//      beside it (GET /relay/btc/ord/…); on testnet4 / mainnet Esplora (GET /relay/btc/esplora/…). Its block 0 is checked
//      at startup like eth and sol (a mismatch is fatal); it is in /relay/status. The services (Blockscout eth/arb/base
//      provenance reads, the Arweave tags of an ar id, drand quicknet; ord) are checked on first use (and from startup in
//      the background): an endpoint that answers another identity disables its service until restart
//      (relay.service-identity), one that does not answer is not used and is checked again after 30 s. Every
//      non-loopback upstream goes through Tor on its own role's circuit: testnet and mainnet as before; on local only
//      drand is not loopback (D-R15: the testnet section's endpoints, the same public beacon), and it goes through Tor
//      after an IsTor check, never direct. GET /relay/services reports each service. Every other path under /relay is
//      refused relay.path (an unknown path) or relay.method (a known path with the wrong HTTP method).
//   Also: the confinement probes run the local ones first and stop at the first that is not EPERM (S1's runProbes), so
//   an unconfined relay never sends a probe packet off the machine; identity refusals never echo an upstream value;
//   refusals carry their guard id in error.data.guard and in the log line.
//   Structure: createRelay(options) holds the handler and the startup checks with the transport injected (as
//   relay-core.mjs injects it), so tests run it in process against fake upstreams; main() (when run as a program) adds
//   the arguments, the confinement proof, the real SOCKS transport and the listening socket.
//
// Start ONLY through `vt up` (C3), under C1's relayProfile(network, chainPorts); the relay proves it and exits 2 otherwise:
//   node api/relay/relay.mjs --network local|testnet|mainnet --home <VT_HOME> [--price-fixture SOL=<usd>,ETH=<usd>]
//   --price-fixture: local only (refused on testnet and mainnet). --build <id>: optional; by default the release
//   directory's id, else 'dev'. --port 0 (an ephemeral port): NODE_ENV=test only (api.test-only).
//   Ready: stdout `vt-relay ready network=<n> port=<p>` (the line `vt up` waits for), after the proof, Tor and identity.
//
// Routes (the page server proxies /relay/* from the page; checkRelayHeaders on every route):
//   POST /relay/eth, /relay/sol  ONE JSON-RPC request (method allowlist); the canonical envelope goes upstream with params
//                                unchanged (testnet/mainnet: Tor SOCKS, a separate circuit per role) and the upstream JSON
//                                comes back. Never builds or alters a tx. eth_sendRawTransaction / sendTransaction need a
//                                valid x-vt-send-ticket for exactly those signed bytes (checkSend, awaited).
//   POST /relay/<chain>/ep/<i>   at exactly verified endpoint i (I3; relay.endpoint-unverified otherwise): reads; and on
//                                SOL (Sfix1) the ticketed sendTransaction, through the same checkSend as /relay/sol, each
//                                ticket at most once per endpoint (relay.ticket-endpoint-reused). ETH: reads only
//                                (relay.endpoint-read-only). Never retried on another endpoint.
//   GET  /relay/price            Jupiter USD prices via Tor (mainnet); the --price-fixture (local); nominal (testnet)
//   GET  /relay/tor              { profile, tor, isTor, checkedAt, auto, roles, torRoles, endpoints, confinement }; torRoles
//                                = the roles that go through Tor (testnet/mainnet: all; local: check + drand, or none);
//                                local isTor/checkedAt = the last IsTor check for drand (null before its first use)
//   POST /relay/tor/new {role}   new circuit for a role or "all" (≤ 1 per role per 10 s);  POST /relay/tor/auto {on}
//   GET  /relay/release          re-hash of the release tree vs its SHA256SUMS → { release, files, ok, mismatch, missing, digest, hashedAt };
//                                every answer is a re-hash started after the request, with hashedAt (ms); never cached; a failed one answers 503
//   GET  /relay/status           { network, build, confined, identity: { eth, sol[, btc] }, endpoints: { eth, sol[, btc] } }
//                                (btc when the network has a BTC upstream: local bitcoind, testnet4/mainnet Esplora); the counts
//                                are LIVE (PF-S M-2): a chain endpoint that did not answer its identity check at startup is checked
//                                again in the background every SERVICE_RETRY_MS (main: relay.recheck), and one that answers this
//                                network's identity joins its chain's verified list at the END (the /ep/<i> indices never move); one
//                                that answers ANOTHER identity disables that chain until the relay restarts (at startup: fatal)
//   S6 breadth routes (reads only; relay-routes.ts has the exact patterns):
//   POST /relay/btc              local only: ONE JSON-RPC request to the regtest bitcoind (relay-gate BTC_LOCAL_READS)
//   POST /relay/btc/send         (S6b, CC-8) { "hex": <raw tx> } + x-vt-send-ticket: ONE ticketed commit | reveal tx through the same
//                                checkSend as eth and sol (ticket v2 btc fields, w, c, r, the job-send lock, decode verification with the
//                                relay's own chain read of the input values: relay.btc-prevout); local: bitcoind sendrawtransaction,
//                                testnet4/mainnet: Esplora POST /tx via Tor; never retried when ambiguous; answers { txid } only
//   GET  /relay/btc/esplora/<p>  testnet/mainnet: Esplora (blocks, block-height, address, utxo, txs, tx, hex, outspend, fees)
//   GET  /relay/btc/ord/<p>      local: ord's JSON API (status, r/blockheight, r/blockhash, tx, output, inscription)
//   GET  /relay/blockscout/<eth|arb|base>/<p>  testnet/mainnet: an address's inbound transactions and internal
//                                transactions (?filter=to), a transaction (D2a provenance)
//   GET  /relay/arweave/tags/<ar id>           testnet/mainnet: { id, found, tags: [{ name, value }] } (fixed GraphQL query)
//   GET  /relay/drand/<quicknet hash>/info | public/latest | public/<round>  every network (local: through Tor)
//   GET  /relay/services         { network, services: { <name>: { ok: true | false | null, viaTor, endpoints, message? } } }
// Logs: chain/role, method, status, duration, guard, circuit gen — never params, never an IP (the Tor check yields only IsTor).
//   A breadth route logs its pattern (e.g. `btc esplora:tx/:txid/status 200 41ms`), never the path it was asked.
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import { createHash } from 'node:crypto'
import { existsSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { isAbsolute, join, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { SocksProxyAgent } from 'socks-proxy-agent'
import { FORK_PROBE_BYTES, PORTS, TICKET_HEADER, checkForkDrift, isNetwork, isRefusal } from '@vault-timelock/core/contracts'
import { PRICE } from '@vault-timelock/core/chains/constants.js'
import { assertNoKeyEnv, endpoint, expectedIdentity, identityMatches, isLoopback, loadBitcoindAuth, loadConfig } from 'vt-broadcast/src/config.ts'
import { checkPrivateDir } from 'vt-broadcast/src/lifecycle/paths.ts'
import { readSecretHex } from '../src/auth.ts'
import { assertTestMode } from '../src/clock.ts'
import { DENIED, probePlan, runProbes } from '../src/confine.ts'
import { BTC_SEND_METHOD, checkMethodForNetwork, checkRelayHeaders, checkSend, classifyMethod, createEndpointLedger, headerValue, methodOk } from '../src/relay-gate.ts'
import {
  EVM_CHAINS, MIN_CREDENTIAL_PASS, assertNoSecret, bitcoindAuthHeader, bitcoindSecrets, breadthTag, btcSendTxid, checkAnswer, checkBtcParams, credentialLongEnough, esploraPrevout, identityProbe, isBreadthPath,
  refuseRoute, resolveRest, rpcShape, serviceIdentity, textValue, upstreamRequest,
} from '../src/relay-routes.ts'
import { createTor, exchange, ROLES, TIMEOUT_MS } from './relay-core.mjs'
import { PC_RELAYER, createPrivacyCash } from './privacycash.mjs'
import { isPrivacyCashPath } from '../src/privacycash.ts'

/** @typedef {import('@vault-timelock/core/contracts').Network} Network */
/** @typedef {import('@vault-timelock/core/contracts').RelayStatus} RelayStatus */
/** @typedef {import('./relay-core.mjs').Role} Role */
/** @typedef {{ status: number, body: Buffer }} UpRes */
/** @typedef {(url: string, r: { method: string, body?: Buffer, role: Role, user: string, headers?: Record<string, string>, timeoutMs?: number }) => Promise<UpRes>} Transport */
/**
 * @typedef {object} Breadth  S6: the breadth upstreams of a network (relayBreadth), in preference order
 * @property {string[]} btc      local: the regtest bitcoind; testnet/mainnet: Esplora bases
 * @property {string[]} ord      local only: the regtest ord (served only while the bitcoind is)
 * @property {Partial<Record<'eth' | 'arb' | 'base', string[]>>} blockscout   testnet/mainnet: Blockscout /api/v2 bases
 * @property {string[]} arweave  testnet/mainnet: Arweave gateways
 * @property {string[]} drand    every network (local: the testnet section's, through Tor)
 */
/** @typedef {import('../src/relay-routes.ts').ProbeService} ProbeService */
/** @typedef {import('../src/relay-routes.ts').EvmChain} EvmChain */
/**
 * @typedef {object} Svc  a breadth service and what its endpoints answered
 * @property {string} name          'btc.ord' | 'blockscout.<eth|arb|base>' | 'arweave' | 'drand'
 * @property {ProbeService} svc
 * @property {EvmChain | null} sub
 * @property {Role} role
 * @property {string[]} urls        configured, in preference order
 * @property {boolean} localTor     local, and not loopback: through Tor after an IsTor check (drand, D-R15)
 * @property {string[]} verified    the endpoints that passed the identity check, in preference order
 * @property {'unchecked' | 'ok' | 'down' | 'mismatch'} state
 * @property {number} checkedAt
 * @property {Promise<void> | null} inflight
 * @property {string} note
 */
/** @typedef {{ SOL: number, ETH: number }} Fixture */
/** @typedef {{ ok: boolean, probes?: number, result?: string }} Confinement */
/**
 * @typedef {object} RelayOptions
 * @property {Network} network
 * @property {string} build
 * @property {{ eth: string[], sol: string[] }} upstream   upstream lists in preference order (relayUpstreams)
 * @property {Fixture | null} priceFixture                 local only
 * @property {Transport} transport                         one upstream request (socksTransport in production)
 * @property {() => Uint8Array} ticketKey                  relay-ticket.key, read on every send
 * @property {Confinement} confinement                     the startup proof's result (main)
 * @property {() => number} [now]
 * @property {(line: string) => void} [log]
 * @property {() => string} [rand]                         Tor session ids (relay-core createTor)
 * @property {string} [releaseRoot]                        the tree /relay/release re-hashes (default: this module's own release root)
 * @property {(root: string) => Promise<object>} [rehash]  the re-hash itself (default rehashRelease); a test seam
 * @property {Breadth} [breadth]                           S6: the breadth upstreams (relayBreadth); absent: none
 * @property {string | null} [bitcoindAuth]                local: the bitcoind credential line (readBitcoindCredential);
 *                                                         null or absent: the local BTC lane (bitcoind, ord) is off
 * @property {import('./privacycash.mjs').PrivacyCashOptions} [privacycash]  S7: the Privacy Cash proxy's upstreams (relayPrivacyCash);
 *                                                         absent: /relay/privacycash/* answers 503 (the circuit files need artifactDir)
 */

const TOR = { host: '127.0.0.1', port: 9050 }
const TOR_CHECK = 'https://check.torproject.org/api/ip'
const TOR_CHECK_CACHE_MS = 60000
// S6: a breadth service none of whose endpoints answered its identity check is checked again after this long.
export const SERVICE_RETRY_MS = 30000
const MAX_BODY = 256 * 1024
// S7: the longest per-route upstream timeout a request may ask for (Privacy Cash utxos/range: 120 s); the default stays TIMEOUT_MS.
export const MAX_TIMEOUT_MS = 120000
const NULL_ADDRESS = '0x0000000000000000000000000000000000000000'
// The fork probe's sender: any address other than the recipient. Without `from`, eth_estimateGas sends from the zero
// address, which makes a probe to 0x0 a self-transfer (the Amsterdam to-self formula, 12000 + 64·n).
const PROBE_FROM = '0x1111111111111111111111111111111111111111'
// Demoted to the end of any upstream list: refused reads over Tor ("usage limit for your current plan", a quota shared
// per exit; publication-modes-elite.md §0.7). Kept as a last resort. Mainnet eth.rpc lists it second (demoted here to
// last). Testnet eth.rpc is publicnode only: 1rpc.io/sepolia timed out over Tor on both attempts (S3 fix round,
// controller ruling), and rpc.sepolia.org answers 404; endpoints.json has no comments, so it is noted here.
export const DEMOTED_HOSTS = ['1rpc.io']
// requestAirdrop (R71d): one 32-byte address, at most 1 SOL per request, never through /ep.
export const AIRDROP_MAX_LAMPORTS = 1000000000n
// Testnet price: a nominal fixture, so the cap math still runs; the label says what it is (spec §3.4).
export const TESTNET_PRICE_LABEL = 'TEST FUNDS — NO VALUE'
export const TESTNET_PRICE = Object.freeze({ SOL: 150, ETH: 3000 })
export const BUILD_ID = /^[A-Za-z0-9._-]{1,64}$/
const JSON_CT = /^application\/json\s*(;|$)/i
// The method table lives in api/src/relay-gate.ts (READ_METHODS, JOB_SEND_METHODS; S3 review I-1): default deny, so a
// method is forwarded without a ticket only when it is on that network's and chain's read list.

/** @param {string} msg */
const fatal = (msg) => Object.assign(new Error(msg), { name: 'RelayFatal', exitCode: 2 })
/** @param {Buffer | undefined} buf @returns {any} */
const parseJson = (buf) => { try { return JSON.parse((buf ?? Buffer.alloc(0)).toString('utf8')) } catch { return undefined } }
/** @param {string} method @param {unknown[]} [params] */
const rpcBody = (method, params = []) => Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }))
// Hostname for logs; never an IP literal (loopback upstreams print as "loopback:<port>").
/** @param {string} url */
const hostOf = (url) => { const u = new URL(url); return net.isIP(u.hostname) ? (u.hostname.startsWith('127.') ? `loopback:${u.port}` : '[ip-literal]') : u.host }

/** @param {string[]} list */
export const demote = (list) => [...list.filter((u) => !DEMOTED_HOSTS.includes(new URL(u).hostname)), ...list.filter((u) => DEMOTED_HOSTS.includes(new URL(u).hostname))]

// The upstream lists of a network: endpoints.json through loadConfig (one source), plus the local-only test overrides.
/** @param {Network} network @param {Readonly<Record<string, string | undefined>>} env */
export function relayUpstreams(network, env) {
  /** @type {Record<string, string>} */
  const overrides = {}
  for (const [k, key] of [['VT_TEST_ETH_RPC', 'eth.rpc'], ['VT_TEST_SOL_RPC', 'sol.rpc']]) {
    const v = env[k]
    if (!v) continue
    if (network !== 'local') throw fatal(`${k} is a local test override — refused with --network ${network}`)
    if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(v)) throw fatal(`${k} must be http://127.0.0.1:<port>`)
    overrides[key] = v
  }
  const cfg = loadConfig(network, env, overrides)
  return { eth: demote(endpoint(cfg, 'eth.rpc')), sol: demote(endpoint(cfg, 'sol.rpc')) }
}

// S6: the breadth upstreams of a network, from endpoints.json through loadConfig (one source), plus the local-only test
// overrides of the regtest bitcoind and ord. Local has no Blockscout or Arweave (config.local-scope); its drand list is
// the testnet section's (D-R15: the same public beacon, reached through Tor).
/** @param {Network} network @param {Readonly<Record<string, string | undefined>>} env @returns {Breadth} */
export function relayBreadth(network, env) {
  /** @type {Record<string, string>} */
  const overrides = {}
  for (const [k, key] of [['VT_TEST_BTC_RPC', 'btc.bitcoind'], ['VT_TEST_ORD_RPC', 'btc.ord']]) {
    const v = env[k]
    if (!v) continue
    if (network !== 'local') throw fatal(`${k} is a local test override — refused with --network ${network}`)
    if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(v)) throw fatal(`${k} must be http://127.0.0.1:<port>`)
    overrides[key] = v
  }
  const cfg = loadConfig(network, env, overrides)
  const list = (/** @type {string} */ key) => (Object.hasOwn(cfg.endpoints, key) ? endpoint(cfg, key) : [])
  if (network === 'local') return { btc: list('btc.bitcoind'), ord: list('btc.ord'), blockscout: {}, arweave: [], drand: endpoint(loadConfig('testnet', env), 'drand') }
  return { btc: list('btc.esplora'), ord: [], blockscout: { eth: list('eth.blockscout'), arb: list('arb.blockscout'), base: list('base.blockscout') }, arweave: list('arweave.gateway'), drand: list('drand') }
}

// S7: the Privacy Cash upstreams. A mainnet service (no devnet): off local nothing else than the fixed relayer and the
// MAINNET Solana RPC list is ever used, through Tor, whichever stack carries the relay (a withdrawal is gated as a mainnet
// send either way: api/src/privacycash.ts assertWithdrawAllowed). Local: none (tests inject loopback fakes). The circuit
// files are the release tree's assets/privacycash/ (sha256-pinned at boot).
/** @param {Network} network @param {Readonly<Record<string, string | undefined>>} env @returns {import('./privacycash.mjs').PrivacyCashOptions} */
export function relayPrivacyCash(network, env) {
  const artifactDir = join(HERE, 'assets', 'privacycash')
  if (network === 'local') return { relayer: [], rpc: [], artifactDir }
  return { relayer: [PC_RELAYER], rpc: demote(endpoint(loadConfig('mainnet', env), 'sol.rpc')), artifactDir }
}

// S6: the local bitcoind's credential, read ONCE at startup: only from $OUT/local/btc-rpc.auth (broadcast
// loadBitcoindAuth: a regular 0600 file you own, no symlink, one <user>:<pass> line), $OUT being VAULT_TIMELOCK_DIR as
// `vt up` passes it (an absolute path). Never a default $OUT, never a URL or an env value. null (the local BTC lane off)
// when it cannot be read; the log line names only the reason's guard, never the path's contents or the credential.
/** @param {string | undefined} out @param {(line: string) => void} log @returns {string | null} */
export function readBitcoindCredential(out, log) {
  if (typeof out !== 'string' || !isAbsolute(out) || out.includes('\0')) {
    log('btc: the bitcoind credential is not read: VAULT_TIMELOCK_DIR is not an absolute path (it is never defaulted); the local BTC lane is off')
    return null
  }
  try {
    const line = loadBitcoindAuth(out)
    if (credentialLongEnough(line)) return line
    log(`btc: the bitcoind password is shorter than ${MIN_CREDENTIAL_PASS} characters: it is refused, the local BTC lane is off (generate one with bitcoind's share/rpcauth/rpcauth.py)`)
    return null
  } catch (e) {
    log(`btc: the bitcoind credential is unavailable (${isRefusal(e) ? `refused ${e.guardId}` : errName(e)}); the local BTC lane is off`)
    return null
  }
}

// ---------- base58 (local genesis well-formedness, airdrop address) ----------
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
/** @param {unknown} s */
function b58len(s) {
  if (typeof s !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]+$/.test(s)) return -1
  let n = 0n; for (const c of s) n = n * 58n + BigInt(B58.indexOf(c))
  let bytes = 0; while (n > 0n) { n >>= 8n; bytes++ }
  for (const c of s) { if (c === '1') bytes++; else break }
  return bytes
}

// ---------- Solana wire helpers (simulate guard) ----------
/** @param {Buffer} buf @param {number} off @returns {[number, number]} */
function shortvec(buf, off) { let len = 0, size = 0
  for (;;) { if (off + size >= buf.length) throw new Error('short'); const b = buf[off + size]; len |= (b & 0x7f) << (size * 7); size++; if ((b & 0x80) === 0) break; if (size > 3) throw new Error('shortvec') }
  return [len, size] }
/** @param {string} b64 */
function allSignaturesZero(b64) {
  const tx = Buffer.from(b64, 'base64')
  const [n, sz] = shortvec(tx, 0)
  if (n < 1 || tx.length < sz + n * 64) return false
  for (let i = sz; i < sz + n * 64; i++) if (tx[i] !== 0) return false
  return true
}

/** @param {http.ServerResponse} res @param {number} code @param {unknown} obj */
function reply(res, code, obj) { const b = Buffer.from(JSON.stringify(obj)); res.writeHead(code, { 'content-type': 'application/json', 'content-length': b.length, 'cache-control': 'no-store' }); res.end(b) }
/** @param {unknown} id @param {number} code @param {string} message @param {string} [guard] */
const err = (id, code, message, guard) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message, ...(guard ? { data: { guard } } : {}) } })
const SEND_GUARD = /^(?:relay\.(?:send-ticket|ticket-[a-z]+(?:-[a-z]+)*|decode-mismatch)|release\.mainnet-locked|config\.identity-[a-z]+|api\.token-missing)$/
/** @param {http.IncomingMessage} req @returns {Promise<Buffer | null>} */
function readBody(req) {
  return new Promise((resolve) => {
    /** @type {Buffer[]} */
    const chunks = []
    let n = 0, over = false
    req.on('data', (/** @type {Buffer} */ c) => { n += c.length; if (n > MAX_BODY) { over = true; chunks.length = 0 } else if (!over) chunks.push(c) })
    req.on('end', () => resolve(over ? null : Buffer.concat(chunks)))
    req.on('error', () => resolve(null)) })
}

// ---------- release integrity (GET /relay/release): re-hash the release tree against its SHA256SUMS ----------
// Reports only counts and the SHA256SUMS digest — never file names or contents. Not a release tree → { release: false }.
// The tree's root is two levels above this file (<release>/api/relay/relay.mjs, spec §9).
const HERE = fileURLToPath(new URL('../../', import.meta.url))
// The build id when no --build is given (`vt up` passes none): the release directory's name (<VT_HOME>/releases/<12 hex>/,
// spec §9) when running from a release, else 'dev'.
/** @param {string} root */
export function buildOf(root) { const p = root.split(sep).filter(Boolean); const id = p.at(-1) ?? ''; return p.at(-2) === 'releases' && /^[0-9a-f]{12}$/.test(id) ? id : 'dev' }
/**
 * Re-hash a release tree against its SHA256SUMS. THE producer of GET /relay/release (and what readiness.ts consumes):
 * { release: false } when there is no SHA256SUMS; else { release: true, files, ok, mismatch, missing, digest } where
 * `files` is the number of lines, `ok` is a COUNT of files that re-hashed equal (not a boolean), and
 * files = ok + mismatch + missing. Only counts and the digest of SHA256SUMS itself; never a file name or content.
 * @param {string} root the release root (any trailing separator)
 */
export async function rehashRelease(root) {
  const base = root.endsWith(sep) ? root : root + sep
  const sums = join(base, 'SHA256SUMS')
  if (!existsSync(sums)) return { release: false }
  const text = await readFile(sums, 'utf8'), lines = text.split('\n').filter(Boolean)
  let ok = 0, mismatch = 0, missing = 0
  // Async reads, a few at a time: a release is tens of thousands of files, and the relay must keep answering (its event
  // loop is never held by the re-hash, Cfix2).
  let next = 0
  const worker = async () => {
    for (let i = next++; i < lines.length; i = next++) {
      const m = /^([0-9a-f]{64}) [ *](.+)$/.exec(lines[i]); if (!m) { mismatch++; continue }
      const f = join(base, m[2])
      if (!f.startsWith(base)) { missing++; continue }
      /** @type {Buffer} */ let data
      try { data = await readFile(f) } catch { missing++; continue }
      createHash('sha256').update(data).digest('hex') === m[1] ? ok++ : mismatch++
    }
  }
  await Promise.all(Array.from({ length: Math.min(8, lines.length) }, worker))
  return { release: true, files: lines.length, ok, mismatch, missing, digest: createHash('sha256').update(text).digest('hex') }
}

/** @param {RelayOptions} o */
export function createRelay(o) {
  const { network } = o
  const now = o.now ?? (() => Date.now())
  const log = o.log ?? ((/** @type {string} */ l) => { console.log(l) })
  const TOR_PROFILE = network !== 'local'
  // ---------- S6 breadth: BTC (a chain) and the services ----------
  /** @type {Breadth} */
  const B = o.breadth ?? { btc: [], ord: [], blockscout: {}, arweave: [], drand: [] }
  // local: the bitcoind credential line, held only here; it goes only into btcHeaders (requests to the bitcoind list)
  // (S6 review m2: a password under MIN_CREDENTIAL_PASS characters is no credential: the lane stays off)
  const BTC_AUTH = network === 'local' && typeof o.bitcoindAuth === 'string' && o.bitcoindAuth !== '' && credentialLongEnough(o.bitcoindAuth) ? o.bitcoindAuth : null
  const btcConfigured = B.btc.length > 0
  const btcOn = btcConfigured && (network !== 'local' || BTC_AUTH !== null)
  /** @type {Record<string, string> | undefined} */
  const btcHeaders = BTC_AUTH === null ? undefined : { authorization: bitcoindAuthHeader(BTC_AUTH) }
  const btcSecrets = BTC_AUTH === null ? [] : bitcoindSecrets(BTC_AUTH)
  /** @type {Role[]} */
  const roles = [...ROLES]
  if (btcConfigured) roles.push('btc')
  if (EVM_CHAINS.some((c) => (B.blockscout[c] ?? []).length > 0)) roles.push('blockscout')
  if (B.arweave.length) roles.push('arweave')
  if (B.drand.length) roles.push('drand')
  const PC = o.privacycash ?? { relayer: [], rpc: [] }
  if (PC.relayer.length) roles.push('privacycash')           // S7: the relayer and the RPC each have their own circuit (no correlation)
  if (PC.rpc.length) roles.push('privacycash-rpc')
  const tor = createTor({ profile: network, tor: TOR_PROFILE, now, roles, ...(o.rand ? { rand: o.rand } : {}) })
  /** @type {{ eth: string[], sol: string[], btc: string[] }} */
  const status = { eth: [], sol: [], btc: [] }          // endpoints that passed identity, in preference order
  /** @type {{ eth: string | null, sol: string | null, btc: string | null }} */
  const observed = { eth: null, sol: null, btc: null }    // the identity they answered (checkSend's observedId)
  // PF-S M-2: the endpoints that did not answer their identity check (checked again by recheck), and a chain disabled by a re-check
  /** @type {{ eth: string[], sol: string[], btc: string[] }} */
  const unverified = { eth: [], sol: [], btc: [] }
  /** @type {{ eth: string | null, sol: string | null, btc: string | null }} */
  const disabled = { eth: null, sol: null, btc: null }
  /** @type {Promise<void> | null} */
  let recheckInflight = null
  /** @type {string | null} */
  let forkMessage = null
  // ---------- release re-hash (GET /relay/release) ----------
  // ★ Never stale (Cfix2 fix round 1, security review): EVERY answer comes from a re-hash that STARTED no earlier than the
  // request that gets it, and carries `hashedAt` (ms, when that re-hash started). Nothing is cached: not a success (a file
  // changed after it would still read ✓) and not a failure. The startup re-hash only warms the file cache and occupies the
  // single slot (`running`); its result is dropped and never served. At most ONE re-hash runs at a time. A request that
  // finds none running schedules one for the next tick, so requests of the same tick share it; a request that finds one
  // running waits for it to end and then shares the single follow-up with every other request that arrived meanwhile.
  const rehash = o.rehash ?? rehashRelease, releaseRoot = o.releaseRoot ?? HERE
  /** @typedef {{ v: object } | { err: true }} RehashResult */
  /** @type {Promise<RehashResult> | null} */
  let running = null
  /** @type {Promise<RehashResult> | null} */
  let pending = null
  /** @returns {Promise<RehashResult>} never rejects */
  function startRehashNow() {
    const at = now()
    const job = (async () => {
      try { return { v: { .../** @type {object} */ (await rehash(releaseRoot)), hashedAt: at } } }
      catch (e) { log(`release re-hash failed (${errName(e)})`); return /** @type {RehashResult} */ ({ err: true }) }
    })()
    running = job
    void job.then(() => { if (running === job) running = null })
    return job
  }
  /** @returns {Promise<RehashResult>} */
  function freshRehash() {
    if (pending) return pending
    const prev = running
    pending = (async () => {
      if (prev) await prev
      else await new Promise((r) => setImmediate(r))
      pending = null
      return startRehashNow()
    })()
    return pending
  }
  /** @returns {Promise<object>} */
  async function releaseStatus() {
    const r = await freshRehash()
    if ('err' in r) throw new Error('release re-hash failed')
    return r.v
  }
  const sentTo = createEndpointLedger()        // Sfix1: which verified endpoint each ticket has been sent to (/relay/<chain>/ep/<i>)

  /** @param {Role} role @param {string[]} endpoints @param {{ method?: string, body?: Buffer, send?: boolean, headers?: Record<string, string>, timeoutMs?: number }} [opts] */
  const via = (role, endpoints, opts = {}) => exchange(tor, { role, endpoints, send: !!opts.send, log, clock: now,
    doRequest: (url, user) => o.transport(url, { method: opts.method || 'POST', ...(opts.body ? { body: opts.body } : {}), ...(opts.headers ? { headers: opts.headers } : {}), ...(opts.timeoutMs ? { timeoutMs: opts.timeoutMs } : {}), role, user }) })

  // ---------- Tor check (IsTor only — the exit IP in the response is discarded unread) ----------
  /** @type {Promise<boolean | null> | null} */
  let torCheckInflight = null
  /** @returns {Promise<boolean | null>} */
  async function checkTor(force = false) {
    if (!TOR_PROFILE) return null
    if (!force && tor.state.checkedAt && now() - tor.state.checkedAt < TOR_CHECK_CACHE_MS) return tor.state.isTor
    torCheckInflight ??= (async () => {
      try {
        const r = await via('check', [TOR_CHECK], { method: 'GET' })
        tor.state.isTor = r.res && r.res.body ? parseJson(r.res.body)?.IsTor === true : false
      } catch { tor.state.isTor = false } finally { tor.state.checkedAt = now(); torCheckInflight = null }
      return tor.state.isTor
    })()
    return torCheckInflight
  }

  // S7: /relay/privacycash/* (api/relay/privacycash.mjs; the gates are api/src/privacycash.ts). Role `privacycash`, over Tor
  // off local (fail closed: the cached IsTor check), a withdrawal behind the FUNDING lock (MAINNET_SEND_ENABLED), never the job-send lock.
  const privacycash = createPrivacyCash({ network, config: PC, via: (role, endpoints, opts) => via(role, endpoints, opts), torOk: () => checkTor(), ticketKey: o.ticketKey, now, log })

  // ---------- startup: Tor, then every endpoint's identity (a mismatch anywhere is fatal), then the fork probe ----------
  /** @param {'eth' | 'sol' | 'btc'} chain @param {string} url @returns {Promise<{ ok: boolean, note: string, id?: string }>} */
  async function identity(chain, url) {
    if (chain === 'btc') return btcIdentity(url)
    const method = chain === 'eth' ? 'eth_chainId' : 'getGenesisHash'
    const r = await via(chain, [url], { body: rpcBody(method) })
    if (!r.res) return { ok: false, note: `unreachable/refused (${r.label})` }
    const j = r.res.status === 200 ? parseJson(r.res.body) : undefined
    if (!j || j.result === undefined) return { ok: false, note: `refused/blocked (HTTP ${r.res.status})` }
    const id = j.result
    if (typeof id !== 'string' || !identityMatches(network, chain, id)) {
      throw fatal(chain === 'eth'
        ? `eth identity MISMATCH at ${hostOf(url)}: the chain id is not ${network}'s (${expectedIdentity(network, 'eth')})`
        : `sol identity MISMATCH at ${hostOf(url)}: ${network === 'local' ? 'the genesis is public or malformed' : `not the pinned ${network} genesis`}`)
    }
    return { ok: true, id, note: chain === 'eth' ? `eth_chainId ${id} OK` : network === 'local' ? 'genesis non-public (local test-validator) OK' : `genesis ${id} (${network === 'testnet' ? 'devnet' : 'mainnet-beta'}) OK` }
  }
  // S6: BTC block 0 — local: the regtest bitcoind's getblockhash 0 (with the credential); testnet/mainnet: Esplora's
  // block-height/0. A well-formed hash that is not this network's genesis is fatal, as for eth and sol.
  /** @param {string} url @returns {Promise<{ ok: boolean, note: string, id?: string }>} */
  async function btcIdentity(url) {
    const local = network === 'local'
    const r = local ? await via('btc', [url], { body: rpcBody('getblockhash', [0]), headers: btcHeaders })
      : await via('btc', [`${url.replace(/\/+$/, '')}/block-height/0`], { method: 'GET' })
    if (!r.res) return { ok: false, note: `unreachable/refused (${r.label})` }
    const id = r.res.status !== 200 ? null : local ? parseJson(r.res.body)?.result : textValue(r.res.body ?? Buffer.alloc(0), 'hash')
    if (id === null || id === undefined) return { ok: false, note: `refused/blocked (HTTP ${r.res.status})` }
    const name = local ? 'regtest' : network === 'testnet' ? 'testnet4' : 'mainnet'
    if (typeof id !== 'string' || !identityMatches(network, 'btc', id)) throw fatal(`btc identity MISMATCH at ${hostOf(url)}: block 0 is not the ${name} genesis`)
    return { ok: true, id, note: `block 0 = the ${name} genesis OK` }
  }
  // Ruling Q4: does eth_estimateGas match this network's fork? A drift is reported (identity.eth), never guessed around.
  async function forkProbe() {
    if (!status.eth.length) return
    const data = `0x${'61'.repeat(FORK_PROBE_BYTES)}`
    const r = await via('eth', [status.eth[0]], { body: rpcBody('eth_estimateGas', [{ from: PROBE_FROM, to: NULL_ADDRESS, data }]) })
    const j = r.res && r.res.status === 200 ? parseJson(r.res.body) : undefined
    const est = typeof j?.result === 'string' && /^0x[0-9a-f]{1,15}$/i.test(j.result) ? BigInt(j.result) : null
    if (est === null) { log('fork probe eth: no estimate (not checked)'); return }
    const d = checkForkDrift(network, { estimate: est, n: FORK_PROBE_BYTES, toSelf: false })
    forkMessage = d.ok ? null : d.message
    log(`fork probe eth: ${d.ok ? `${d.observed} OK` : d.message}`)
  }
  async function startup() {
    startRehashNow()                              // Cfix2: a warm-up from the start (file cache); its result is never served
    if (TOR_PROFILE) {
      const isTor = await checkTor(true)
      log(`IsTor: ${isTor === true}`)
      if (isTor !== true) throw fatal('Tor check failed')
    }
    // every endpoint in parallel (preference order kept); a mismatch anywhere is fatal (exit 2). BTC (S6) when the
    // network has a BTC upstream; locally only with the bitcoind credential (otherwise not one request goes to it).
    /** @type {{ eth: string[], sol: string[], btc: string[] }} */
    const lists = { eth: o.upstream.eth, sol: o.upstream.sol, btc: btcOn ? B.btc : [] }
    /** @type {Array<'eth' | 'sol' | 'btc'>} */
    const chains = btcConfigured ? ['eth', 'sol', 'btc'] : ['eth', 'sol']
    const results = await Promise.all(chains.flatMap((chain) => lists[chain].map(async (url) => { const t0 = now(); return { chain, url, r: await identity(chain, url), ms: now() - t0 } })))
    for (const chain of chains) {
      for (const { url, r, ms } of results.filter((x) => x.chain === chain)) {
        log(`identity ${chain} ${hostOf(url)}: ${r.note} (${ms} ms)`)
        if (r.ok) { status[chain].push(url); observed[chain] ??= r.id ?? null } else unverified[chain].push(url)
      }
      if (chain === 'btc' && !btcOn) log('identity btc: DISABLED — the bitcoind credential is unavailable ($OUT/local/btc-rpc.auth); /relay/btc answers 503, ord is not served')
      else if (!status[chain].length) log(`identity ${chain}: DISABLED — no endpoint passed identity; /relay/${chain} answers 503`)
    }
    if (!status.eth.length && !status.sol.length) throw fatal('no chain passed identity')
    await forkProbe()
    // the services: checked from now on in the background (local drand waits for its first request: Tor first)
    for (const sv of services.values()) if (!sv.localTor) void ready(sv).catch(() => {})
  }

  // ---------- PF-S M-2: dropped chain endpoints, checked again (the background re-check) ----------
  // One round: every chain endpoint that has not passed its identity check yet is asked again (in parallel, through Tor off local after
  // the cached IsTor check). One that answers this network's identity is APPENDED to its chain's verified list (the indices of the
  // endpoints already verified never move, so a running executor's /ep/<i> routes stay where they were); one that answers another
  // identity (or a check that throws) disables the whole chain until the relay restarts: its routes answer 503 and /relay/status says
  // why. A round never runs twice at once; main() runs one every SERVICE_RETRY_MS.
  /** @returns {Promise<void>} */
  function recheck() {
    recheckInflight ??= (async () => {
      try {
        /** @type {Array<'eth' | 'sol' | 'btc'>} */
        const chains = (/** @type {Array<'eth' | 'sol' | 'btc'>} */ (['eth', 'sol', 'btc'])).filter((c) => disabled[c] === null && unverified[c].length > 0 && (c !== 'btc' || btcOn))
        if (!chains.length) return
        if (TOR_PROFILE && (await checkTor()) !== true) { log('identity re-check: not run — Tor is not available'); return }
        for (const chain of chains) {
          const urls = [...unverified[chain]]
          const results = await Promise.all(urls.map(async (url) => {
            const t0 = now()
            try { return { url, r: await identity(chain, url), bad: false, ms: now() - t0 } } catch { return { url, r: null, bad: true, ms: now() - t0 } }
          }))
          const wasEmpty = status[chain].length === 0
          for (const x of results) {
            if (x.bad || x.r === null) { log(`identity ${chain} ${hostOf(x.url)}: MISMATCH on re-check (${x.ms} ms)`); continue }
            log(`identity ${chain} ${hostOf(x.url)}: ${x.r.note} (re-check, ${x.ms} ms)`)
            if (!x.r.ok) continue
            status[chain].push(x.url)
            observed[chain] ??= x.r.id ?? null
            unverified[chain] = unverified[chain].filter((u) => u !== x.url)
          }
          if (results.some((x) => x.bad || x.r === null)) {
            disabled[chain] = 'an endpoint answered another identity on a re-check: the chain is disabled until the relay restarts'
            status[chain].splice(0)
            unverified[chain] = []
            log(`identity ${chain}: DISABLED — an endpoint answered another identity on a re-check; /relay/${chain} answers 503 until the relay restarts`)
            continue
          }
          if (chain === 'eth' && wasEmpty && status.eth.length) await forkProbe()
        }
      } finally { recheckInflight = null }
    })()
    return recheckInflight
  }

  // ---------- S6 services: checked on first use; a mismatch disables the service until restart ----------
  /** @type {Map<string, Svc>} */
  const services = new Map()
  /** @param {string} name @param {ProbeService} svc @param {EvmChain | null} sub @param {Role} role @param {string[]} urls */
  const addService = (name, svc, sub, role, urls) => {
    if (urls.length) services.set(name, { name, svc, sub, role, urls, localTor: network === 'local' && urls.some((u) => !isLoopback(u)), verified: [], state: 'unchecked', checkedAt: 0, inflight: null, note: '' })
  }
  if (network === 'local') addService('btc.ord', 'ord', null, 'btc', btcOn ? B.ord : [])   // the local BTC lane: with the bitcoind only
  for (const c of EVM_CHAINS) if (network !== 'local') addService(`blockscout.${c}`, 'blockscout', c, 'blockscout', B.blockscout[c] ?? [])
  if (network !== 'local') addService('arweave', 'arweave', null, 'arweave', B.arweave)
  addService('drand', 'drand', null, 'drand', B.drand)

  // local drand (D-R15) goes through Tor: an IsTor check first (cached TOR_CHECK_CACHE_MS), fail closed. The transport
  // never sends a non-loopback request directly (socksTransport), so this only refuses early and clearly.
  let localTor = { ok: false, at: -Infinity }
  /** @type {Promise<boolean> | null} */
  let localTorInflight = null
  /** @returns {Promise<boolean>} */
  function localTorOk() {
    if (localTor.ok && now() - localTor.at < TOR_CHECK_CACHE_MS) return Promise.resolve(true)
    localTorInflight ??= (async () => {
      let ok = false
      try {
        const r = await via('check', [TOR_CHECK], { method: 'GET' })
        ok = !!r.res && r.res.status === 200 && parseJson(r.res.body)?.IsTor === true
      } catch { ok = false }
      localTor = { ok, at: now() }
      localTorInflight = null
      return ok
    })()
    return localTorInflight
  }

  /** @param {Svc} sv @returns {Promise<string[]>} the verified endpoints (none while unchecked, down or mismatched) */
  async function ready(sv) {
    if (sv.state === 'ok' || sv.state === 'mismatch') return sv.verified
    if (sv.state === 'down' && now() - sv.checkedAt < SERVICE_RETRY_MS) return sv.verified
    sv.inflight ??= verifyService(sv).finally(() => { sv.inflight = null })
    await sv.inflight
    return sv.verified
  }
  /** @param {Svc} sv */
  async function verifyService(sv) {
    if (sv.localTor && !(await localTorOk())) {
      Object.assign(sv, { state: 'down', checkedAt: now(), note: 'Tor is not available (IsTor ✗): the local relay reaches this service through Tor only' })
      log(`identity ${sv.name}: not checked — Tor is not available`)
      return
    }
    const results = await Promise.all(sv.urls.map(async (url) => {
      const t0 = now()
      const p = identityProbe(sv.svc, url)
      if (p === null) return { url, ok: false, mismatch: false, note: 'no identity endpoint for this base', ms: 0 }
      const r = await via(sv.role, [p.url], { method: p.method, ...(p.body ? { body: p.body } : {}) })
      if (!r.res) return { url, ok: false, mismatch: false, note: `unreachable/refused (${r.label})`, ms: now() - t0 }
      try {
        const ok = serviceIdentity(network, sv.svc, sv.sub, r.res.status, r.res.body ?? Buffer.alloc(0))
        return { url, ok, mismatch: false, note: ok ? 'identity OK' : `no identity answer (HTTP ${r.res.status})`, ms: now() - t0 }
      } catch (e) {
        if (!isRefusal(e)) throw e
        return { url, ok: false, mismatch: true, note: `identity MISMATCH (${e.guardId})`, ms: now() - t0 }
      }
    }))
    for (const x of results) log(`identity ${sv.name} ${hostOf(x.url)}: ${x.note} (${x.ms} ms)`)
    const bad = results.some((x) => x.mismatch)
    sv.verified = bad ? [] : results.filter((x) => x.ok).map((x) => x.url)
    sv.state = bad ? 'mismatch' : sv.verified.length ? 'ok' : 'down'
    sv.note = bad ? 'an endpoint answered another identity: disabled until the relay restarts' : sv.verified.length ? '' : 'no endpoint answered the identity check (checked again on a later request)'
    sv.checkedAt = now()
    if (bad) log(`identity ${sv.name}: DISABLED — an endpoint answered another identity (relay.service-identity); until restart`)
  }
  // viaTor (fix round 1, I-1): whether this service's requests go through Tor (testnet/mainnet: all; local: drand only)
  /** @returns {Promise<{ network: Network, services: Record<string, { ok: boolean | null, viaTor: boolean, endpoints: number, message?: string }> }>} */
  async function servicesStatus() {
    await Promise.all([...services.values()].map((sv) => ready(sv).catch(() => [])))
    /** @type {Record<string, { ok: boolean | null, viaTor: boolean, endpoints: number, message?: string }>} */
    const out = {}
    for (const sv of services.values()) {
      out[sv.name] = { ok: sv.state === 'ok' ? true : sv.state === 'unchecked' ? null : false, viaTor: TOR_PROFILE || sv.localTor, endpoints: sv.verified.length, ...(sv.state !== 'ok' && sv.note ? { message: sv.note } : {}) }
    }
    return { network, services: out }
  }

  // ---------- price (GET /relay/price): Jupiter via Tor (mainnet), the fixture (local), nominal (testnet) ----------
  /** @type {any} */ let priceCache = null
  /** @type {Promise<any> | null} */ let priceInflight = null
  /** @returns {Promise<any>} */
  async function price() {
    const fx = network === 'testnet' ? TESTNET_PRICE : o.priceFixture
    if (fx && network !== 'mainnet') {
      return { source: network === 'testnet' ? TESTNET_PRICE_LABEL : 'LOCAL FIXTURE PRICE (--price-fixture)', fixture: true, fetchedAt: now(),
        prices: { SOL: { usd: fx.SOL, mint: PRICE.MINTS.SOL }, ETH: { usd: fx.ETH, mint: PRICE.MINTS.ETH } } }
    }
    if (network !== 'mainnet') throw Object.assign(new Error('no price source on the local network (start with --price-fixture)'), { status: 503 })
    if (priceCache && now() - priceCache.fetchedAt < PRICE.RELAY_CACHE_MS) return priceCache
    priceInflight ??= (async () => {
      try {
        let last = null
        for (const src of PRICE.SOURCES) {                 // api.jup.ag first, lite-api.jup.ag as fallback (same path)
          const r = await via('price', [`${src}?ids=${PRICE.MINTS.SOL},${PRICE.MINTS.ETH}`], { method: 'GET' })
          if (!r.res) { last = r.label; continue }
          const j = r.res.status === 200 ? parseJson(r.res.body) : undefined
          if (!j) { last = `HTTP ${r.res.status}`; continue }
          /** @param {string} m */
          const pick = (m) => { const x = j[m]; return x && Number.isFinite(x.usdPrice) && x.usdPrice > 0 ? { usd: x.usdPrice, mint: m, blockId: x.blockId, decimals: x.decimals, liquidity: x.liquidity } : null }
          const SOL = pick(PRICE.MINTS.SOL), ETH = pick(PRICE.MINTS.ETH)
          if (!SOL || !ETH) { last = 'a mint is missing from the response'; continue }
          const thin = [SOL, ETH].find((x) => !(Number.isFinite(x.liquidity) && x.liquidity >= PRICE.MIN_LIQUIDITY_USD))   // M6: missing = thin
          if (thin) throw Object.assign(new Error(`liquidity for ${thin.mint.slice(0, 6)}… is below $${PRICE.MIN_LIQUIDITY_USD.toLocaleString('en-US')} — refusing`), { status: 502 })
          priceCache = { source: src, fixture: false, fetchedAt: now(), prices: { SOL, ETH } }
          return priceCache
        }
        throw Object.assign(new Error(`price unavailable (${last})`), { status: 502 })
      } finally { priceInflight = null }
    })()
    return priceInflight
  }

  // The roles whose requests go through Tor: every role on testnet and mainnet; on local only drand (D-R15) and its IsTor
  // check — empty when the local relay serves no drand (fix round 1, I-1: the relay never says "no Tor" while it uses it).
  /** @returns {Role[]} */
  function torRoles() {
    if (TOR_PROFILE) return [...roles]
    const viaTor = [...services.values()].filter((sv) => sv.localTor).map((sv) => sv.role)
    return viaTor.length ? ['check', ...viaTor] : []
  }
  // /relay/tor. On local, isTor and checkedAt are the LAST local IsTor check (null until drand is first asked for):
  // /relay/tor never starts one there (the executor reads /relay/tor on every network; a local stack only goes to Tor
  // for drand). torRoles names what goes through Tor.
  async function torStatus() {
    await checkTor()
    const local = TOR_PROFILE ? {} : { isTor: localTor.at === -Infinity ? null : localTor.ok, checkedAt: localTor.at === -Infinity ? null : localTor.at }
    return { ...tor.status(), ...local, torRoles: torRoles(), endpoints: { eth: status.eth.length, sol: status.sol.length }, confinement: o.confinement }
  }
  /** @returns {RelayStatus} */
  function relayStatus() {
    /** @param {'eth' | 'sol' | 'btc'} c */
    const id = (c) => c === 'btc' && !btcOn ? { ok: false, message: 'the bitcoind credential is unavailable ($OUT/local/btc-rpc.auth)' }
      : disabled[c] !== null ? { ok: false, message: disabled[c] }
      : !status[c].length ? { ok: false, message: 'no endpoint passed the identity check yet (a dropped endpoint is checked again every 30 s)' }
      : c === 'eth' && forkMessage !== null ? { ok: false, message: forkMessage } : { ok: true }
    return { network, build: o.build, confined: o.confinement.ok === true,
      identity: { eth: id('eth'), sol: id('sol'), ...(btcConfigured ? { btc: id('btc') } : {}) },
      endpoints: { eth: status.eth.length, sol: status.sol.length, ...(btcConfigured ? { btc: status.btc.length } : {}) } }
  }

  // ---------- S6b: the ticketed BTC send (POST /relay/btc/send) ----------
  // The relay's OWN chain read of one input outpoint, for the decode verification's fee check (decode.ts BtcPrevouts): never a
  // value from the caller. Local: the regtest bitcoind's gettxout (unspent outputs, the mempool included, so a reveal can
  // spend a commit the node accepted but has not mined). Testnet4 / mainnet: Esplora's raw tx hex, hashed to the txid. null = not found / unreadable /
  // not in the shape: the send is refused relay.btc-prevout (fail closed). Reads use the verified BTC endpoints only.
  /** @param {string} txid @param {number} vout @returns {Promise<{ value: bigint, script: Uint8Array } | null>} */
  async function btcPrevout(txid, vout) {
    try {
      if (!/^[0-9a-f]{64}$/.test(txid) || !Number.isSafeInteger(vout) || vout < 0 || !status.btc.length) return null
      if (network === 'local') {
        const r = await via('btc', status.btc, { body: rpcBody('gettxout', [txid, vout, true]), headers: btcHeaders })
        if (!r.res || r.res.status !== 200) return null
        const body = r.res.body ?? Buffer.alloc(0)
        assertNoSecret(body, btcSecrets)
        const o = parseJson(body)?.result
        const sats = typeof o?.value === 'number' && Number.isFinite(o.value) ? Math.round(o.value * 1e8) : -1
        const hex = o?.scriptPubKey?.hex
        return sats >= 0 && Number.isSafeInteger(sats) && typeof hex === 'string' && /^(?:[0-9a-f]{2})+$/.test(hex) ? { value: BigInt(sats), script: Buffer.from(hex, 'hex') } : null
      }
      // Esplora (S6b review m-2): the raw tx, whose double-SHA256 (non-witness) must BE the txid; the value and script are read from
      // those verified bytes, so the server is trusted for nothing but the bytes themselves
      const r = await via('btc', status.btc.map((b) => `${b.replace(/\/+$/, '')}/tx/${txid}/hex`), { method: 'GET' })
      if (!r.res || r.res.status !== 200) return null
      const hex = textValue(r.res.body ?? Buffer.alloc(0), 'hex')
      return hex === null ? null : esploraPrevout(hex, txid, vout)
    } catch { return null }
  }

  // ---------- request handling ----------
  /** @param {http.IncomingMessage} req @param {http.ServerResponse} res */
  async function route(req, res) {
    const t0 = now()
    const path = req.url || ''
    // /relay/<chain> (preferred endpoint + failover) or /relay/<chain>/ep/<i> (exactly verified endpoint i — I3; SOL sends: Sfix1)
    // S6: /relay/btc (local: the regtest bitcoind, reads only) is a JSON-RPC chain route too, without /ep/<i>
    const m = /^\/relay\/(?:(eth|sol)(?:\/ep\/(\d))?|(btc))$/.exec(path)
    const chain = m ? /** @type {'eth' | 'sol' | 'btc'} */ (m[1] ?? m[3]) : null, epIdx = m && m[2] != null ? Number(m[2]) : null
    let method = '-'
    const tag = chain || breadthTag(path) || (path.startsWith('/relay/tor') ? 'tor' : path === '/relay/price' ? 'price' : path === '/relay/release' ? 'release' : path === '/relay/status' ? 'status' : path === '/relay/services' ? 'services' : '-')
    /** @param {number} code @param {unknown} obj @param {string} [guard] */
    const done = (code, obj, guard) => { reply(res, code, obj); log(`${tag} ${method} ${code} ${now() - t0}ms${guard ? ` ${guard}` : ''}`) }
    /** @param {unknown} e @param {unknown} id */
    const refused = (e, id) => {
      if (!isRefusal(e)) return done(500, err(id, -32603, 'relay gate error: nothing was forwarded'))
      done(403, err(id, SEND_GUARD.test(e.guardId) ? -32003 : -32601, e.message, e.guardId), e.guardId)
    }
    // an upstream answer the relay withholds (relay.upstream-shape, relay.upstream-secret): 502, nothing of it passed on
    /** @param {unknown} e @param {unknown} id */
    const withheld = (e, id) => {
      if (!isRefusal(e)) return done(500, err(id, -32603, 'relay internal error'))
      done(502, err(id, -32097, e.message, e.guardId), e.guardId)
    }
    try { checkRelayHeaders(req.rawHeaders, network) } catch (e) { req.resume(); return refused(e, null) }
    // ---- S6b: POST /relay/btc/send { "hex": <raw tx, lowercase hex> } with x-vt-send-ticket: ONE ticketed raw tx (commit | reveal) ----
    // The same checkSend as eth and sol (ticket v2, w, c, r, the job-send lock, decode verification with the relay's own chain
    // read of the input values), then local: bitcoind sendrawtransaction; testnet4 / mainnet: Esplora POST /tx via Tor. Never
    // retried or failed over when the outcome is ambiguous. The answer is { txid } and nothing else; the raw tx is never logged.
    if (path === '/relay/btc/send') {
      method = BTC_SEND_METHOD
      /** @param {unknown} e */
      const refusedPlain = (e) => {
        if (!isRefusal(e)) return done(500, { error: { message: 'relay gate error: nothing was forwarded' } })
        done(403, { error: { guard: e.guardId, message: e.message } }, e.guardId)
      }
      if (req.method !== 'POST') { req.resume(); try { refuseRoute(true) } catch (e) { return refusedPlain(e) } return }
      if (!JSON_CT.test(String(req.headers['content-type'] || ''))) { req.resume(); return done(403, { error: { message: 'content-type must be application/json' } }) }
      const body = await readBody(req)
      if (!body) return done(413, { error: { message: 'body > 256 KiB' } })
      const j = parseJson(body)
      const hex = j !== null && typeof j === 'object' && !Array.isArray(j) && Object.keys(j).join() === 'hex' && typeof j.hex === 'string' ? j.hex : null
      if (!status.btc.length) return done(503, { error: { message: 'btc disabled (identity not verified at startup)' } })
      /** @type {import('@vault-timelock/core/contracts').TicketPayload | null} */ let ticket
      try {
        ticket = await checkSend({ network, chain: 'btc', method: BTC_SEND_METHOD, params: hex === null ? [] : [hex], ticketHeader: headerValue(req.rawHeaders, TICKET_HEADER),
          key: o.ticketKey(), now: now(), observedId: observed.btc ?? '', btcPrevouts: btcPrevout })
      } catch (e) { return refusedPlain(e) }
      if (ticket === null || hex === null) return done(500, { error: { message: 'relay gate error: nothing was forwarded' } })
      const local = network === 'local'
      const r = local
        ? await via('btc', status.btc, { body: rpcBody('sendrawtransaction', [hex]), send: true, ...(btcHeaders ? { headers: btcHeaders } : {}) })
        : await via('btc', status.btc.map((b) => `${b.replace(/\/+$/, '')}/tx`), { method: 'POST', body: Buffer.from(hex), send: true, headers: { 'content-type': 'text/plain' } })
      if (r.res) {
        const upBody = r.res.body ?? Buffer.alloc(0)
        try {
          if (local) assertNoSecret(upBody, btcSecrets)
          if (r.res.status !== 200) return done(502, { error: { message: `upstream HTTP ${r.res.status}: the transaction was not accepted as sent` } })
          return done(200, { txid: btcSendTxid(local ? 'bitcoind' : 'esplora', upBody, ticket.t) })
        } catch (e) {
          if (!isRefusal(e)) return done(500, { error: { message: 'relay internal error' } })
          return done(502, { error: { guard: e.guardId, message: e.message } }, e.guardId)
        }
      }
      if (r.ambiguous) return done(502, { error: { message: `send outcome unknown (${r.label}) — not retried; check by txid` } })
      if (r.notAccepted) return done(503, { error: { message: `every endpoint refused the send before processing (${r.label}) — not accepted` } })
      return done(502, { error: { message: `upstream unavailable on every endpoint (${r.label})` } })
    }
    if (isPrivacyCashPath(path)) return privacycash.handle(req, res)   // S7: its own routes, gates and log lines
    // ---- GET routes ----
    if (req.method === 'GET' && path === '/relay/price') {
      req.resume(); method = 'GET'
      return price().then((p) => done(200, p), (e) => done(e.status || 502, { error: { message: e.status ? e.message : `price source unreachable (${e.code || 'error'})` } }))
    }
    if (req.method === 'GET' && path === '/relay/tor') { req.resume(); method = 'GET'; return done(200, await torStatus()) }
    if (req.method === 'GET' && path === '/relay/release') { req.resume(); method = 'GET'; return releaseStatus().then((v) => done(200, v), () => done(503, { error: { message: 'the release re-hash failed' } })) }
    if (req.method === 'GET' && path === '/relay/status') { req.resume(); method = 'GET'; return done(200, relayStatus()) }
    if (req.method === 'GET' && path === '/relay/services') { req.resume(); method = 'GET'; return done(200, await servicesStatus()) }
    // ---- S6 breadth GET routes (relay-routes.ts: GET only, exact patterns per network) ----
    if (isBreadthPath(path)) {
      req.resume()
      /** @type {import('../src/relay-routes.ts').RestRoute} */ let r
      try { r = resolveRest(network, req.method ?? '', path) } catch (e) { method = 'disallowed'; return refused(e, null) }
      method = r.name                                          // the pattern, never the path asked
      const sv = r.service === 'esplora' ? null : services.get(r.service === 'ord' ? 'btc.ord' : r.service === 'blockscout' ? `blockscout.${r.sub}` : r.service) ?? null
      if (r.service !== 'esplora' && sv === null) return done(503, { error: { message: 'this service is not configured on this network' } })
      if (sv?.localTor && !(await localTorOk())) return done(503, { error: { message: 'Tor is not available (IsTor ✗): the local relay reaches this service through Tor only' } })
      const bases = sv === null ? status.btc : await ready(sv)
      if (!bases.length) return done(503, { error: { message: sv === null ? 'btc disabled (identity not verified at startup)' : `${sv.name} disabled (${sv.note || 'not verified'})` } })
      const ups = bases.map((b) => upstreamRequest(r, b))
      const role = r.service === 'esplora' || r.service === 'ord' ? 'btc' : r.service
      const up = await via(role, ups.map((x) => x.url), { method: ups[0].method, ...(ups[0].body ? { body: ups[0].body } : {}) })
      if (!up.res) return done(502, { error: { message: `upstream unavailable on every endpoint (${up.label})` } })
      /** @type {import('../src/relay-routes.ts').Answer} */ let a
      try {
        // S6 review m5: ord is often started with the bitcoind credential, so its answers are scanned like bitcoind's
        if (network === 'local' && r.service === 'ord') assertNoSecret(up.res.body ?? Buffer.alloc(0), btcSecrets)
        a = checkAnswer(r, up.res.status, up.res.body ?? Buffer.alloc(0))
      } catch (e) { return withheld(e, null) }
      res.writeHead(a.status, { 'content-type': a.contentType, 'content-length': a.body.length, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' })
      res.end(a.body)
      log(`${tag} ${method} ${a.status} ${now() - t0}ms`); return
    }
    if (req.method !== 'POST' || !(chain || path === '/relay/tor/new' || path === '/relay/tor/auto')) {
      req.resume(); method = 'disallowed'
      // every other request under /relay: a known path asked with the wrong HTTP method → relay.method, else relay.path
      const known = chain !== null || ['/relay/tor/new', '/relay/tor/auto', '/relay/price', '/relay/tor', '/relay/release', '/relay/status', '/relay/services'].includes(path)
      try { refuseRoute(known) } catch (e) { return refused(e, null) }
      return done(403, err(null, -32601, 'forbidden'))
    }
    if (!JSON_CT.test(String(req.headers['content-type'] || ''))) { req.resume(); return done(403, err(null, -32601, 'content-type must be application/json')) }
    const body = await readBody(req)
    if (!body) return done(413, err(null, -32600, 'body > 256 KiB'))
    const j = parseJson(body)
    // ---- Tor control ----
    if (!chain) {
      method = path === '/relay/tor/new' ? 'new' : 'auto'
      if (!TOR_PROFILE) return done(403, { error: { message: 'local network: direct loopback, no Tor' } })
      if (path === '/relay/tor/auto') {
        if (typeof j?.on !== 'boolean') return done(400, { error: { message: 'body {on: true|false}' } })
        tor.state.auto = j.on; log(`tor auto-rotate ${j.on ? 'on' : 'off'}`); return done(200, await torStatus())
      }
      const which = j?.role === 'all' ? roles : roles.includes(j?.role) ? [/** @type {Role} */ (j.role)] : null
      if (!which) return done(400, { error: { message: `role must be one of ${roles.join(', ')}, all` } })
      /** @type {Record<string, ReturnType<typeof tor.manual>>} */
      const results = {}
      for (const r of which) { const before = tor.roles[r].gen; results[r] = tor.manual(r); if (results[r].ok) log(`tor ${r} gen ${before}→${results[r].gen} manual`) }
      if (which.includes('check') && results.check.ok) await checkTor(true)
      return done(Object.values(results).some((x) => x.ok) ? 200 : 429, { results, status: tor.status() })
    }
    // ---- JSON-RPC relay ----
    if (!j || Array.isArray(j) || typeof j !== 'object' || j.jsonrpc !== '2.0' || typeof j.method !== 'string' || (j.params !== undefined && !Array.isArray(j.params)))
      return done(403, err(j?.id, -32600, 'one JSON-RPC 2.0 request object required'))
    /** @type {'read' | 'send'} */ let kind
    try {                                                      // default deny: a listed read, or this chain's job send
      checkMethodForNetwork(network, chain, j.method)
      kind = classifyMethod(network, chain, j.method)
      if (chain === 'btc') { methodOk(kind === 'read'); checkBtcParams(j.method, j.params) }  // S6: reads only here (S6b: the ticketed send is POST /relay/btc/send); scantxoutset 'start' with addr() descriptors only
    } catch (e) { method = 'disallowed'; return refused(e, j.id) }
    method = j.method                                          // a name from the table, never free input
    if (j.method === 'simulateTransaction') {
      const cfg = j.params?.[1]
      let zero = false; try { zero = cfg?.encoding === 'base64' && typeof j.params[0] === 'string' && allSignaturesZero(j.params[0]) } catch { zero = false }
      if (cfg?.sigVerify !== false || !zero) return done(403, err(j.id, -32602, 'simulate requires sigVerify:false, encoding base64 and all-zero signatures'))
    }
    if (j.method === 'eth_feeHistory') {                     // R73 Passive 24 h window: ≤ 1024 blocks per call; > 64 blocks only base-fee-only ([] percentiles)
      const [count, , pcts] = j.params || [], n = typeof count === 'string' ? parseInt(count, 16) : Number(count)
      if (!(n >= 1 && n <= 1024) || (n > 64 && Array.isArray(pcts) && pcts.length > 0)) return done(403, err(j.id, -32602, 'eth_feeHistory: blockCount 1…1024; above 64 blocks base-fee only (rewardPercentiles [])'))
    }
    if (j.method === 'requestAirdrop') {                     // R71: devnet faucet (checkMethodForNetwork), one 32-byte address, ≤ 1 SOL, never via /ep
      const [to, lamports] = j.params || []
      if (epIdx != null || b58len(to) !== 32 || !Number.isSafeInteger(lamports) || lamports <= 0 || BigInt(lamports) > AIRDROP_MAX_LAMPORTS) return done(403, err(j.id, -32602, `requestAirdrop: one base58 address and 1…${AIRDROP_MAX_LAMPORTS} lamports`))
    }
    if (!status[chain].length) return done(503, err(j.id, -32000, `${chain} disabled (identity not verified at startup)`))
    const send = kind === 'send'                              // never retried or failed over when ambiguous (relay-core)
    // the send gate (spec §5.6): a valid ticket bound to these exact bytes, this network and this chain; the job-send lock;
    // the bytes decoded and checked against the ticket (S4). AWAITED: nothing is forwarded unless it resolves. The same
    // call gates /relay/<chain>/ep/<i> (Sfix1): i a verified endpoint, ETH there read-only, a ticket once per endpoint.
    try {
      await checkSend({ network, chain, method: j.method, params: j.params, ticketHeader: headerValue(req.rawHeaders, TICKET_HEADER),
        key: send ? o.ticketKey() : new Uint8Array(0), now: now(), observedId: observed[chain] ?? '',
        route: epIdx == null ? null : { ep: epIdx, verified: status[chain].length, ledger: sentTo } })
    } catch (e) { return refused(e, j.id) }
    const at = epIdx == null ? null : status[chain][epIdx]   // checkSend proved it exists; never forward to a hole
    if (epIdx != null && typeof at !== 'string') return done(500, err(j.id, -32603, 'relay gate error: nothing was forwarded'))
    // M5: forward a canonical envelope (no duplicate keys can smuggle a second method); params — incl. the raw tx string — unchanged
    const fwd = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: j.id ?? null, method: j.method, ...(j.params !== undefined ? { params: j.params } : {}) }))
    // S6: the bitcoind credential goes only to the bitcoind list, and never comes back (relay.upstream-secret)
    const r = await via(chain, at !== null ? [at] : status[chain], { body: fwd, send, ...(chain === 'btc' && btcHeaders ? { headers: btcHeaders } : {}) })
    if (r.res) {
      const upBody = r.res.body ?? Buffer.alloc(0)
      if (chain === 'btc') { try { assertNoSecret(upBody, btcSecrets) } catch (e) { return withheld(e, j.id) } }
      // S6 review m6: a /relay/btc answer is strict UTF-8 JSON or it is relay.upstream-shape (eth and sol keep their lenient check)
      if (chain === 'btc') { try { rpcShape(upBody) } catch (e) { return withheld(e, j.id) } }
      else if (parseJson(upBody) === undefined) return done(502, err(j.id, -32099, `upstream HTTP ${r.res.status}, non-JSON body`))
      res.writeHead(r.res.status, { 'content-type': 'application/json', 'content-length': upBody.length, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }); res.end(upBody)   // upstream bytes as received
      log(`${chain} ${method} ${r.res.status} ${now() - t0}ms`); return
    }
    if (r.ambiguous) return done(502, err(j.id, -32098, `send outcome unknown (${r.label}) — not retried; check by tx id`))
    if (send && r.notAccepted) return done(503, err(j.id, -32000, `every endpoint refused the send before processing (${r.label}) — not accepted`))
    done(502, err(j.id, -32098, `upstream unavailable on every endpoint (${r.label})`))
  }
  // Never throws (an escaped error would end the process): an unexpected failure answers 500 and forwards nothing more.
  /** @param {http.IncomingMessage} req @param {http.ServerResponse} res */
  async function handle(req, res) {
    try { await route(req, res) } catch {
      if (!res.headersSent) reply(res, 500, err(null, -32603, 'relay internal error'))
      else res.destroy()
      log('- - 500 relay-internal')
    }
  }
  return { startup, handle, status: relayStatus, recheck, tor, torRoles, privacycash, close: () => privacycash.close() }
}

// ---------- the real transport: one upstream request (testnet/mainnet: a SOCKS agent per role and generation) ----------
// socks5h: the host name goes to Tor and is resolved by the exit, never by the local resolver (S3 review m2: pinned by
// relay-networks.test.ts through `agentFor`). S6: on local only a loopback URL goes direct; any other URL (local drand,
// D-R15, and its Tor check) goes through Tor like every request of testnet and mainnet, never direct. An Authorization
// header (the local bitcoind's) goes to a loopback URL only: anything else is refused before a socket is opened.
/** @param {string} user */
export const torAgent = (user) => new SocksProxyAgent(`socks5h://${user}:x@${TOR.host}:${TOR.port}`)
/** @typedef {Transport & { agentFor: (role: Role, user: string, url?: string) => SocksProxyAgent | undefined }} SocksTransport */
/** @param {Network} network @returns {SocksTransport} */
export function socksTransport(network) {
  /** @type {Map<string, { user: string, agent: SocksProxyAgent }>} */
  const agents = new Map()   // role → { user, agent }
  /** @param {Role} role @param {string} user @param {string} [url] */
  function agentFor(role, user, url) {
    const useTor = network !== 'local' || (url !== undefined && !isLoopback(url))
    if (!useTor) return undefined
    const cur = agents.get(role)
    if (cur?.user === user) return cur.agent
    if (cur) setTimeout(() => cur.agent.destroy?.(), MAX_TIMEOUT_MS + 5000).unref()   // M3: let in-flight requests finish; the old generation is never reused
    const agent = torAgent(user)
    agents.set(role, { user, agent }); return agent
  }
  /** @type {Transport} */
  const transport = (url, { method, body, role, user, headers: extra, timeoutMs }) => new Promise((resolve, reject) => {
    const u = new URL(url)
    const mod = u.protocol === 'https:' ? https : http
    if (extra !== undefined && Object.keys(extra).some((k) => k.toLowerCase() === 'authorization') && !isLoopback(url)) {
      reject(Object.assign(new Error('credential refused off loopback'), { code: 'ECREDENTIAL' })); return
    }
    /** @type {Record<string, string | number>} */
    const headers = { accept: 'application/json', ...(extra ?? {}) }
    if (body) { if (!Object.keys(headers).some((k) => k.toLowerCase() === 'content-type')) headers['content-type'] = 'application/json'; headers['content-length'] = body.length }
    const agent = agentFor(role, user, url)
    const req = mod.request(u, { method, ...(agent ? { agent } : {}), headers, timeout: timeoutMs ?? TIMEOUT_MS }, (res) => {
      /** @type {Buffer[]} */ const chunks = []; let n = 0
      res.on('data', (/** @type {Buffer} */ c) => { n += c.length; if (n > 16 * 1024 * 1024) req.destroy(Object.assign(new Error('too large'), { code: 'ETOOLARGE' })); else chunks.push(c) })
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks) }))
      res.on('error', reject)
    })
    req.on('timeout', () => req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })))
    req.on('error', reject)
    req.end(body)
  })
  return Object.assign(transport, { agentFor })   // agentFor: the agent every request of a role and circuit uses
}

// ---------- the confinement proof: direct connects must be refused by the sandbox (EPERM) ----------
// S1's probe plan minus the API-only probes (the write probe, the relay port, Tor :9050): loopback :9, the DNS socket,
// then TEST-NET-1 :9/:443/:80. runProbes stops at the first that is not EPERM, so nothing leaves an unconfined relay.
export const RELAY_PROBES = probePlan(0).filter((p) => p.kind === 'unix' || (p.kind === 'tcp' && (p.host !== '127.0.0.1' || p.port === 9)))
/** @returns {Promise<Confinement>} */
export async function proveConfined() {
  const results = await runProbes(RELAY_PROBES)
  const ok = RELAY_PROBES.length === 5 && results.length === RELAY_PROBES.length && results.every((r) => r.outcome === DENIED)
  if (!ok) throw fatal(`not confined: direct probes returned ${results.map((r) => r.outcome.slice(0, 20)).join('/')} (expected EPERM ×5) — start via vt up (sandbox-exec)`)
  return { ok: true, probes: results.length, result: 'EPERM ×5' }
}

// The ready banner's Tor part (fix round 1, I-1): it says what goes through Tor. Local: the chains go direct on loopback,
// and drand (D-R15), when served, through Tor with an IsTor check on first use.
/** @param {Network} network @param {readonly string[]} viaTor the relay's torRoles() */
export const torBanner = (network, viaTor) => (network !== 'local' ? 'circuits per role, auto-rotate on'
  : viaTor.includes('drand') ? 'drand only, via Tor (socks5h; IsTor checked on first use); chains direct loopback' : 'none (direct loopback)')

// ---------- the command line ----------
const USAGE = 'usage: node relay.mjs --network local|testnet|mainnet --home <absolute VT_HOME> [--build <id>] [--price-fixture SOL=<usd>,ETH=<usd>]'
const FLAGS = new Set(['--network', '--home', '--build', '--price-fixture', '--port'])
/**
 * @param {readonly string[]} argv
 * @returns {{ network: Network, home: string, build: string, priceFixture: Fixture | null, port: 0 | null }}
 */
export function parseRelayArgs(argv) {
  /** @type {Map<string, string>} */
  const seen = new Map()
  let ok = argv.length % 2 === 0
  for (let i = 0; ok && i < argv.length; i += 2) {
    const flag = argv[i] === '--profile' ? '--network' : argv[i], value = argv[i + 1]   // MQ's --profile: an alias
    ok = FLAGS.has(flag) && !seen.has(flag) && typeof value === 'string' && value !== '' && !value.startsWith('--')
    if (ok) seen.set(flag, value)
  }
  const network = seen.get('--network'), home = seen.get('--home'), build = seen.get('--build') ?? buildOf(HERE), port = seen.get('--port')
  if (!ok || !isNetwork(network) || home === undefined || !isAbsolute(home) || home.includes('\0') || !BUILD_ID.test(build)) throw fatal(USAGE)
  if (port !== undefined && port !== '0') throw fatal(USAGE)
  if (port !== undefined) assertTestMode()
  // --price-fixture (local only): a fixed synthetic price, served labelled "LOCAL FIXTURE PRICE" (no Tor to jup.ag locally)
  const fxArg = seen.get('--price-fixture')
  /** @type {Fixture | null} */
  let priceFixture = null
  if (fxArg !== undefined) {
    if (network !== 'local') throw fatal('--price-fixture is only allowed with --network local')
    const kv = Object.fromEntries(fxArg.split(',').map((x) => x.split('=')))
    priceFixture = { SOL: Number(kv.SOL), ETH: Number(kv.ETH) }
    if (!(priceFixture.SOL > 0 && priceFixture.ETH > 0)) throw fatal('--price-fixture SOL=<usd>,ETH=<usd>')
  }
  return { network, home, build, priceFixture, port: port === undefined ? null : 0 }
}

/** @param {unknown} e */
const errName = (e) => { const c = /** @type {{ code?: unknown, name?: unknown } | null} */ (e)?.code ?? /** @type {{ name?: unknown } | null} */ (e)?.name; return typeof c === 'string' && /^[A-Za-z0-9_]{1,32}$/.test(c) ? c : 'error' }

async function main() {
  /** @param {string} msg @returns {never} */
  const fail = (msg) => { process.stderr.write(`FATAL: ${msg}\n`); process.exit(2) }
  process.on('uncaughtException', (e) => fail(`uncaught ${errName(e)}`))
  process.on('unhandledRejection', (e) => fail(`unhandled ${errName(e)}`))
  try {
    const a = parseRelayArgs(process.argv.slice(2))
    assertNoKeyEnv(process.env)
    const upstream = relayUpstreams(a.network, process.env)
    const breadth = relayBreadth(a.network, process.env)
    const privacycash = relayPrivacyCash(a.network, process.env)
    const stateDir = join(a.home, a.network)
    checkPrivateDir(stateDir)
    const keyFile = join(stateDir, 'relay-ticket.key')
    const ticketKey = () => Buffer.from(readSecretHex(keyFile), 'hex')
    ticketKey()                                                  // present now (api.token-missing otherwise); re-read per send
    console.log(`vt relay · network ${a.network}`)
    const confinement = await proveConfined()
    console.log('confinement: direct TCP to loopback:9 and TEST-NET-1:9/:443/:80, and the mDNSResponder socket → EPERM ×5 ✓')
    // S6: the local bitcoind credential, read once now (never a default $OUT); null turns the local BTC lane off
    const bitcoindAuth = a.network === 'local' && breadth.btc.length > 0 ? readBitcoindCredential(process.env.VAULT_TIMELOCK_DIR, (l) => console.log(l)) : null
    const relay = createRelay({ network: a.network, build: a.build, upstream, breadth, privacycash: { ...privacycash, stateDir }, bitcoindAuth, priceFixture: a.priceFixture, transport: socksTransport(a.network), ticketKey, confinement })
    await relay.startup()
    // PF-S M-2: a chain endpoint that did not answer at startup (a Tor timeout at `vt up`) is checked again in the background
    const recheckTimer = setInterval(() => { void relay.recheck().catch(() => {}) }, SERVICE_RETRY_MS)
    recheckTimer.unref()
    const server = http.createServer(relay.handle)
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(a.port ?? PORTS[a.network].relay, '127.0.0.1', () => { server.off('error', reject); resolve(undefined) }) })
    for (const sig of /** @type {const} */ (['SIGINT', 'SIGTERM', 'SIGHUP'])) process.once(sig, () => { clearInterval(recheckTimer); server.close(); relay.close(); process.exit(0) })
    const addr = server.address()
    const s = relay.status()
    const port = typeof addr === 'object' && addr !== null ? addr.port : 0
    console.log(`listening on loopback :${port} build ${a.build} (eth ${s.endpoints.eth ? 'on' : 'OFF'}, sol ${s.endpoints.sol ? 'on' : 'OFF'}, price ${a.network === 'local' ? (a.priceFixture ? 'LOCAL FIXTURE' : 'none') : a.network === 'testnet' ? TESTNET_PRICE_LABEL : 'Jupiter via Tor'}, tor ${torBanner(a.network, relay.torRoles())})`)
    console.log(`vt-relay ready network=${a.network} port=${port}`)   // the readiness line `vt up` (C3) waits for
  } catch (e) {
    if (isRefusal(e)) fail(`refused ${e.guardId}: ${e.message}`)
    if (e instanceof Error && e.name === 'RelayFatal') fail(e.message)
    fail(`startup failed (${errName(e)})`)
  }
}

if (import.meta.main) await main()

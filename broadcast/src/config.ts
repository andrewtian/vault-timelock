// Configuration: profiles, endpoints, anchors, network identities, overrides.
// Spec B s6.2/s6.3. Every networked component reads its endpoints and identity checks from here.
//
// Fail closed: every function below either returns a validated value or throws a Refusal.
// Identities (chain ids, genesis hashes) are CODE CONSTANTS, never config, so editing a json
// file can never turn a mainnet network into a faucet network. isFaucetNetwork() is the only
// door to faucet mode.
import { closeSync, constants as fsc, fstatSync, openSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import { refuse } from './guard.ts'

export type Profile = 'mainnet' | 'testnet' | 'local'

// Cfix4 (C2 review m1): `as const` is type-only, and the locks read these constants at call time, so every identity
// constant is deep-frozen. An in-process write (`GENESIS.sol.mainnet = 'x'`) is refused (TypeError in strict mode).
function deepFreeze<T>(o: T): T {
  if (typeof o === 'object' && o !== null && !Object.isFrozen(o)) {
    Object.freeze(o)
    for (const v of Object.values(o)) deepFreeze(v)
  }
  return o
}

export const PROFILES: readonly Profile[] = deepFreeze(['mainnet', 'testnet', 'local'] as Profile[])

export const NETWORK_IDS = deepFreeze({
  mainnet: { eth: 1, arb: 42161, base: 8453 },
  testnet: { eth: 11155111, arb: 421614, base: 84532 },
  local: { eth: 31337 },
} as const)

export const GENESIS = deepFreeze({
  sol: {
    mainnet: '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d',
    devnet: 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG',
    // Known public network, but not a faucet network of this tool and never used locally.
    testnet: '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY',
  },
  btc: {
    mainnet: '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
    testnet4: '00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043',
    // Bitcoin Core's regtest genesis block (chainparams.cpp, CRegTestParams): the only local Bitcoin chain.
    // Source: https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp
    regtest: '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206',
  },
} as const)

const FAUCET_NUMBERS: readonly number[] = [NETWORK_IDS.testnet.eth, NETWORK_IDS.testnet.arb, NETWORK_IDS.testnet.base]
const FAUCET_STRINGS: readonly string[] = [GENESIS.sol.devnet, GENESIS.btc.testnet4]

// True only for the testnet identities. Numbers match numbers, strings match genesis hashes.
export function isFaucetNetwork(id: number | string): boolean {
  if (typeof id === 'number') return FAUCET_NUMBERS.includes(id)
  if (typeof id === 'string') return FAUCET_STRINGS.includes(id)
  return false
}

// True only for chain id 31337 in the local profile (an anvil fork must use --chain-id 31337).
export function isLocalNetwork(id: number | string, profile: string): boolean {
  return profile === 'local' && id === NETWORK_IDS.local.eth
}

// R35: the local profile's Solana chain is a solana-test-validator with its own ledger, whose genesis
// hash is random. So "local" is "a well-formed genesis hash that is none of the public networks".
// Pure: the adapters call it with what getGenesisHash returned. Malformed input is never local.
export function isLocalSolanaGenesis(hash: string): boolean {
  if (typeof hash !== 'string' || base58Length(hash) !== 32) return false
  return hash !== GENESIS.sol.mainnet && hash !== GENESIS.sol.devnet && hash !== GENESIS.sol.testnet
}

// True only for the regtest genesis (getblockhash 0 on bitcoind -regtest).
export function isLocalBitcoinGenesis(hash: string): boolean {
  return typeof hash === 'string' && hash === GENESIS.btc.regtest
}

// ---- R71: the testnet networks (canonical plan C2), measured over Tor on 2026-10-09
//
// - Ethereum Sepolia: chainId 11155111 (NETWORK_IDS.testnet.eth). Amsterdam is active from amsterdamTime 1791294816
//   (2026-10-06 13:53 UTC), from geth's params/chainspecs/sepolia.json.
// - Solana devnet: genesis EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG (GENESIS.sol.devnet), per
//   docs.anza.xyz/clusters/available, fetched via Tor.
// - Ethereum mainnet has no Amsterdam time yet; local (anvil) is pre-Amsterdam by default.
// packages/core's network table (contracts/network.ts ETH_FORKS) must agree, amsterdam === (time !== null):
// test/offline/send-lock-static.test.ts pins it.
export const ETH_AMSTERDAM_TIME: Readonly<Record<Profile, number | null>> = { mainnet: null, testnet: 1791294816, local: null }

// ---- chain identities by profile (M1a, spec B §6.5): one map, so no caller re-maps profile -> id or genesis
//
// An identity as OBSERVED (a string): an EVM chain id in decimal or JSON-RPC hex (eth_chainId answers "0xaa36a7"), a
// Solana genesis hash (getGenesisHash), a Bitcoin block-0 hash (Esplora /block-height/0, bitcoind getblockhash 0).
export type IdChain = 'eth' | 'arb' | 'base' | 'sol' | 'btc'
export type JobChain = 'eth' | 'sol' | 'btc'
const ID_CHAINS: readonly IdChain[] = ['eth', 'arb', 'base', 'sol', 'btc']
const JOB_CHAINS: readonly IdChain[] = ['eth', 'sol', 'btc']
const EVM_CHAINS: readonly IdChain[] = ['eth', 'arb', 'base']

const IDENTITY: Readonly<Record<Profile, Readonly<Partial<Record<IdChain, number | string>>>>> = deepFreeze({
  mainnet: {
    eth: NETWORK_IDS.mainnet.eth, arb: NETWORK_IDS.mainnet.arb, base: NETWORK_IDS.mainnet.base,
    sol: GENESIS.sol.mainnet, btc: GENESIS.btc.mainnet,
  },
  testnet: {
    eth: NETWORK_IDS.testnet.eth, arb: NETWORK_IDS.testnet.arb, base: NETWORK_IDS.testnet.base,
    sol: GENESIS.sol.devnet, btc: GENESIS.btc.testnet4,
  },
  // R35: no Arbitrum or Base locally, and local Solana's genesis is random (isLocalSolanaGenesis): no fixed id.
  local: { eth: NETWORK_IDS.local.eth, btc: GENESIS.btc.regtest },
})
const MAINNET_EVM_IDS: readonly bigint[] = Object.values(NETWORK_IDS.mainnet).map((n) => BigInt(n))

// An observed EVM chain id -> bigint, or null when malformed. Strict (for a match): canonical decimal or 0x-hex, as
// eth_chainId answers. Lenient (for spotting mainnet): surrounding space and leading zeros too, so an odd spelling of
// a mainnet id is still mainnet.
function evmId(id: string, lenient: boolean): bigint | null {
  const s = lenient ? id.trim() : id
  const dec = lenient ? /^[0-9]{1,20}$/ : /^(?:0|[1-9][0-9]{0,19})$/
  const hex = lenient ? /^0x[0-9a-f]{1,16}$/i : /^0x(?:0|[1-9a-f][0-9a-f]{0,15})$/i
  return dec.test(s) || hex.test(s) ? BigInt(s) : null
}

// The identity `profile` expects on `chain`: EVM chain id (number), Solana genesis or Bitcoin block-0 hash (string).
// Testnet (R71): eth 11155111 (Sepolia), sol GENESIS.sol.devnet. Local Arbitrum/Base refuse config.local-scope; local
// Solana has no fixed identity (use identityMatches, which applies isLocalSolanaGenesis).
export function expectedIdentity(profile: Profile, chain: IdChain): string | number {
  assertProfile(profile)
  if (chain === 'arb' || chain === 'base') scope(profile, chain)
  const row = IDENTITY[profile]
  const id = ID_CHAINS.includes(chain) && Object.hasOwn(row, chain) ? row[chain] : undefined
  if (id === undefined) refuse('config.identity-unknown', 'no fixed identity for this chain in this profile (local Solana has a random genesis: use identityMatches); the chain is not echoed') // @guard:config.identity-unknown
  return id
}

// True when the observed `id` is a mainnet identity: ANY EVM mainnet chain id (1, 42161, 8453) on any EVM chain, the
// Solana mainnet-beta genesis, the Bitcoin mainnet block 0 (any case). Lenient on purpose (see evmId): this is the
// "refuse" side. Unknown chains and non-strings are false here; the send locks refuse them as a mismatch instead.
export function isMainnetIdentity(chain: IdChain, id: string): boolean {
  if (typeof id !== 'string') return false
  if (EVM_CHAINS.includes(chain)) {
    const n = evmId(id, true)
    return n !== null && MAINNET_EVM_IDS.includes(n)
  }
  if (chain === 'sol') return id.trim() === GENESIS.sol.mainnet
  if (chain === 'btc') return id.trim().toLowerCase() === GENESIS.btc.mainnet
  return false
}

// True only when the observed `id` IS `profile`'s identity of `chain` (strict: anything malformed is false). Local
// Solana: a well-formed genesis that is none of the public ones (R35).
export function identityMatches(profile: Profile, chain: IdChain, id: string): boolean {
  const known = (PROFILES as readonly string[]).includes(profile) && ID_CHAINS.includes(chain) && typeof id === 'string'
  if (!known) return false
  if (profile === 'local' && chain === 'sol') return isLocalSolanaGenesis(id)
  const row = IDENTITY[profile]
  const want = Object.hasOwn(row, chain) ? row[chain] : undefined
  if (want === undefined) return false
  if (typeof want === 'number') return evmId(id, false) === BigInt(want)
  return id === want
}

// ---- mainnet send locks (M1a: spec B §6.5, R42; job scope: canonical spec §12)
//
// Code constants, each pinned as an exact line by test/offline/send-lock-static.test.ts, so lifting a lock is an
// explicit commit that also changes that test: never a flag, an env var or a file.
//   MAINNET_SEND_ENABLED       every mainnet signature and submission outside jobs: Flow 1, funding, the web relays.
//   MAINNET_JOB_SENDS_ENABLED  job sends only (ETH value-0 data txs, SOL Memo v2 txs, claw-back transfers). Only the
//                              operator-approved commit in canonical plan Task M2 Step 6 changes it.
export const MAINNET_SEND_ENABLED = false
export const MAINNET_JOB_SENDS_ENABLED = true

// What the locks hand out: createNet({ tick, permit }) needs one for any send-type request (net.send-permit). The
// brand is type-level; at run time a permit is an object this module made and recorded in ISSUED, which nothing
// exports, so a structural copy, a spread, Object.create(permit) or a permit-shaped literal is not one.
export type SendPermit = { readonly __permit: unique symbol; readonly profile: Profile; readonly scope: 'all' | 'job' }
const ISSUED = new WeakSet<object>()

export function isSendPermit(p: unknown): p is SendPermit {
  return typeof p === 'object' && p !== null && ISSUED.has(p)
}

// The one lock. Fail closed: only testnet and local pass while `enabled` is false (an unknown profile string counts as
// mainnet, behind assertProfile's own refusal), an observed mainnet identity refuses whatever the profile, and an
// observed identity must positively be the profile's own (a malformed or foreign one refuses config.identity-mismatch).
function lock(enabled: boolean, kind: 'all' | 'job', chains: readonly IdChain[], profile: Profile, observed: unknown): SendPermit {
  assertProfile(profile)
  // Each property is read once, so a getter cannot answer one value to a check and another to its use.
  const rawChain: unknown = isRecord(observed) ? observed.chain : undefined
  const rawId: unknown = isRecord(observed) ? observed.id : undefined
  const chain = ID_CHAINS.includes(rawChain as IdChain) ? (rawChain as IdChain) : null
  const id = typeof rawId === 'string' ? rawId : null
  const mainnetSeen = chain !== null && id !== null && isMainnetIdentity(chain, id)
  const mainnetOk = profile === 'mainnet' && enabled
  const ok = (profile === 'testnet' || profile === 'local' || mainnetOk) && (!mainnetSeen || mainnetOk)
  if (!ok) refuse('release.mainnet-locked', `mainnet sends are locked in this build (spec B §6.5; ${kind === 'job' ? 'job sends: MAINNET_JOB_SENDS_ENABLED' : 'MAINNET_SEND_ENABLED'}): refused for the mainnet profile and for any endpoint that answers with a mainnet identity; preflight is read-only`) // @guard:release.mainnet-locked
  const matches = observed === undefined || (chain !== null && id !== null && chains.includes(chain) && identityMatches(profile, chain, id))
  if (!matches) refuse('config.identity-mismatch', `the observed chain identity is not the ${profile} identity of its chain, or is malformed (chains: ${chains.join(', ')}); nothing may be signed or sent (the value is not echoed)`) // @guard:config.identity-mismatch
  const permit = Object.freeze({ profile, scope: kind }) as unknown as SendPermit
  ISSUED.add(permit)
  return permit
}

// The FIRST call of every entry point that signs or submits anything on a chain outside jobs (spec B §6.5: release,
// the runner's money-moving steps, swap-btc, lifecycle resolve … retry, Flow 2, funding auto-sign, the web relays),
// and again with the observed identity in the one intent writer and the one submit function per chain.
export function assertSendAllowed(profile: Profile, observed?: { chain: 'eth' | 'arb' | 'base' | 'sol' | 'btc'; id: string }): SendPermit {
  return lock(MAINNET_SEND_ENABLED, 'all', ID_CHAINS, profile, observed)
}

// The job scope (canonical spec §5.4 arm check 1, §5.6 relay send): API arm and intent ack, and on mainnet the relay
// with the observed identity. Covers only job sends (eth / sol / btc).
// PF-S M-1 (pre-flip review): a BTC send OFF the local network is not a job send. The BTC lane runs on local only (API
// job.chain-unsupported, executor.chain-unsupported), so a btc observation on testnet or mainnet (the relay's Esplora POST /tx)
// first takes the ALL-scope lock: on mainnet it stays behind MAINNET_SEND_ENABLED whatever MAINNET_JOB_SENDS_ENABLED says
// (testnet: unchanged, the all-scope lock passes it). The observed identity is read once, into a snapshot both locks read.
export function assertJobSendAllowed(profile: Profile, observed?: { chain: 'eth' | 'sol' | 'btc'; id: string }): SendPermit {
  const seen: unknown = observed
  if (isRecord(seen)) observed = { chain: seen.chain, id: seen.id } as typeof observed
  if (isRecord(observed) && observed.chain === 'btc' && profile !== 'local') assertSendAllowed(profile, observed)
  return lock(MAINNET_JOB_SENDS_ENABLED, 'job', JOB_CHAINS, profile, observed)
}

// ---- keys

export const RPC_CHAINS = ['eth', 'arb', 'base', 'sol'] as const
const RPC_KEYS: readonly string[] = RPC_CHAINS.map((c) => `${c}.rpc`)
const SERVICE_KEYS: readonly string[] = [
  'btc.esplora', 'btc.bitcoind', 'btc.ord', 'eth.blockscout', 'arb.blockscout', 'base.blockscout', 'thorchain',
  'drand', 'arweave.gateway', 'turbo.upload', 'turbo.payment',
]
const KNOWN_KEYS: readonly string[] = [...RPC_KEYS, ...SERVICE_KEYS]
const SECTIONS: readonly Profile[] = PROFILES

// anchor name -> kind of address
const ANCHOR_KINDS: Readonly<Record<string, 'evm' | 'solana' | 'hex64'>> = {
  'railgun.proxy.eth': 'evm',
  'railgun.proxy.sepolia': 'evm',
  'railgun.relayadapt.eth': 'evm',
  'railgun.relayadapt.sepolia': 'evm',
  'solana.memo': 'solana',
  'drand.quicknet': 'hex64',
  'arbitrum.inbox.mainnet': 'evm',
  'arbitrum.inbox.sepolia': 'evm',
  'base.l1StandardBridge.mainnet': 'evm',
  'base.l1StandardBridge.sepolia': 'evm',
}
const ANCHOR_CHAIN: Readonly<Record<string, string>> = { railgun: 'eth', arbitrum: 'arb', base: 'base', solana: 'sol' }

// ---- URL classification

const LOOPBACK = /^http:\/\/(?:127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})(?:\/[^\s?#@]*)?$/
// An onion is a v3 address over http or https (Task H0: https onions are onions too, for onion-order).
const ONION = /^https?:\/\/[a-z2-7]{56}\.onion(?:\/[^\s?#@]*)?$/
const ONION_HOST = /^[a-z2-7]{56}\.onion$/

function loopbackPort(url: string): number | null {
  const m = LOOPBACK.exec(url)
  if (m === null) return null
  const port = Number(m[1])
  return port <= 65535 ? port : null
}
// Exported for the net layer (src/net/fetch.ts), which classifies request origins with these.
export const isLoopback = (url: string): boolean => loopbackPort(url) !== null
export const isOnion = (url: string): boolean => ONION.test(url)

// After WHATWG parsing every IPv4 spelling (decimal, hex, short) is dotted-quad, and IPv6 is bracketed.
const isIpLiteral = (host: string): boolean => host.startsWith('[') || /^\d+(?:\.\d+){3}$/.test(host)

// A public https host: a DNS name. Never loopback-ish (loopback is plain http on a literal address), never
// an IP literal (Task H0: the net layer refuses those over Tor, so config refuses them up front), never a
// .onion (an onion is classified by ONION alone), never a trailing-dot name (refused by the net layer too).
function isPublicHttps(url: string): boolean {
  if (!url.startsWith('https://') || /\s/.test(url)) return false
  let h: URL
  try { h = new URL(url) } catch { return false }
  const host = h.hostname
  const odd = host === '' || host === 'localhost' || host.endsWith('.localhost') || host.startsWith('127.') || host.endsWith('.')
  if (odd || host.endsWith('.onion') || isIpLiteral(host)) return false
  return h.protocol === 'https:'
}

// ---- key-like URLs (spec B s6.1; Task H0 item 2, audit K28 / CD-I4 / SA-I7)
//
// Two tiers, both refused as config.url-key, both checked on the URL as WRITTEN and as the WHATWG parser
// reads it (a key in a segment the parser would resolve away, or percent-encoded, still counts):
//   1. certain keys, refused everywhere, endpoints.json included (never weaker than before H0):
//      userinfo, a known key query parameter, an Alchemy/Infura-style /v2|v3/<20+ of [A-Za-z0-9_-]>;
//   2. the inversion: ANY query string or fragment, and any path segment or host label of >= 16
//      characters that is hex, a UUID, or mixes letters and digits (a v3 onion's own 56-char label and
//      IP-literal hosts aside: the scheme check refuses IP literals other than loopback's).
//      Refused UNLESS the URL is one of endpoints.json's own URLs, compared after normalization
//      (controller ruling 1): scheme and host lower-cased, one trailing "/" ignored. Paths, queries and
//      everything else compare byte for byte: keys are case-sensitive. The scheme check still follows.
const KEY_PARAMS = ['api-key', 'apikey', 'api_key', 'key', 'token', 'dkey', 'access_token', 'x-api-key', 'secret', 'auth']
const RAW_URL = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)(.*)$/s
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const VERSIONED_KEY = /\/v[23]\/[A-Za-z0-9_-]{20,}/

function decoded(s: string): string {
  try { return decodeURIComponent(s) } catch { return s }
}
function keyLikeToken(t: string): boolean {
  if (t.length < 16) return false
  return /^[0-9a-f]+$/i.test(t) || UUID.test(t) || (/[A-Za-z]/.test(t) && /[0-9]/.test(t))
}
// The path (as written, and decoded) and the host labels of a URL, from the raw text and from the parser.
function urlParts(url: string): { paths: string[]; hosts: string[]; raw: RegExpExecArray | null; parsed: URL | null } {
  const raw = RAW_URL.exec(url)
  let parsed: URL | null = null
  try { parsed = new URL(url) } catch { /* the raw text is still checked */ }
  const paths: string[] = []
  const hosts: string[] = []
  if (raw !== null) {
    const path = raw[3].replace(/[?#].*$/s, '')
    paths.push(path, decoded(path))
    hosts.push(raw[2].replace(/^.*@/s, '').replace(/:[0-9]*$/, '').toLowerCase())
  }
  if (parsed !== null) {
    paths.push(parsed.pathname, decoded(parsed.pathname))
    hosts.push(parsed.hostname)
  }
  return { paths, hosts, raw, parsed }
}
function hasCertainKey(url: string): boolean {
  const { paths, raw, parsed } = urlParts(url)
  if (raw !== null && raw[2].includes('@')) return true
  if (parsed !== null && (parsed.username !== '' || parsed.password !== '')) return true
  if (paths.some((p) => VERSIONED_KEY.test(p))) return true
  if (parsed !== null) for (const k of parsed.searchParams.keys()) if (KEY_PARAMS.includes(k.toLowerCase())) return true
  return false
}
function hasKeyLikeShape(url: string): boolean {
  const { paths, hosts, parsed } = urlParts(url)
  if (url.includes('?') || url.includes('#')) return true
  if (parsed !== null && (parsed.search !== '' || parsed.hash !== '')) return true
  if (paths.some((p) => p.split('/').some(keyLikeToken))) return true
  return hosts.some((h) => !ONION_HOST.test(h) && !isIpLiteral(h) && h.split('.').some(keyLikeToken))
}
function normalizeUrl(url: string): string {
  const m = RAW_URL.exec(url)
  if (m === null) return url
  const rest = m[3].endsWith('/') ? m[3].slice(0, -1) : m[3]
  return `${m[1].toLowerCase()}://${m[2].toLowerCase()}${rest}`
}

const schemeClass = (url: string): string => (/^https:\/\//i.test(url) ? 'https' : /^http:\/\//i.test(url) ? 'http' : 'other')

// ---- mainnet Turbo/Arweave hosts (M1a, spec B §6.5: config.mainnet-host)
//
// Turbo and Arweave have no chain id to observe: the host is the identity. Outside mainnet a turbo.* or
// arweave.gateway endpoint (endpoints.json or an override) on one of these hosts, or on a subdomain of one, is
// refused, so a testnet run never buys mainnet credits or posts to the permaweb. Code constants, like the chain
// identities, joined by the hosts of endpoints.json's own mainnet section for those keys.
const MAINNET_HOST_KEY = /^(?:turbo\.[a-z]+|arweave\.gateway)$/
const MAINNET_HOSTS: readonly string[] = ['arweave.net', 'turbo-gateway.com', 'ardrive.io']

function hostOf(url: string): string | null {
  try { return new URL(url).hostname.toLowerCase() } catch { return null }
}
// Fail closed: a URL whose host cannot be read counts as a mainnet host.
function onMainnetHost(url: string, hosts: readonly string[]): boolean {
  const h = hostOf(url)
  return h === null || hosts.some((m) => h === m || h.endsWith(`.${m}`))
}

// K27: neither refusal ever echoes the URL (it may hold an API key or an IP); they name only `label` (an
// override key, or the endpoints.json section and key, all validated names) and the scheme class. The
// key check runs first. `known` = endpoints.json's URLs, normalized (the tier-2 exemption).
function validateUrl(label: string, url: string, known: ReadonlySet<string>): void {
  const keyOk = !hasCertainKey(url) && (known.has(normalizeUrl(url)) || !hasKeyLikeShape(url))
  if (!keyOk) refuse('config.url-key', `${label}: the endpoint URL carries an API key or a key-like part (userinfo, a query string or fragment, a long hex/UUID/letters-and-digits path segment or host label); the URL is not echoed`) // @guard:config.url-key
  const ok = isLoopback(url) || isOnion(url) || isPublicHttps(url)
  if (!ok) refuse('config.scheme', `${label}: the endpoint URL is not https://<name>, http(s)://<56 base32>.onion or http://127.0.0.1|[::1]:<port> (scheme class: ${schemeClass(url)}); the URL is not echoed`) // @guard:config.scheme
}

function validateOrder(key: string, urls: readonly string[]): void {
  const firstClear = urls.findIndex((u) => !isOnion(u))
  const lastOnion = urls.map(isOnion).lastIndexOf(true)
  const ok = firstClear === -1 || lastOnion === -1 || lastOnion < firstClear
  if (!ok) refuse('config.onion-order', `${key}: a clearnet URL precedes an onion URL`) // @guard:config.onion-order
}

// ---- scope

function chainOfKey(key: string): string { return key.split('.')[0] }
function chainOfAnchor(name: string): string {
  const seg = name.split('.')[0]
  return ANCHOR_CHAIN[seg] ?? seg
}
// The local profile covers Ethereum, Solana and Bitcoin (R35), never Arbitrum or Base. A sol/btc
// endpoint must be loopback: only a local chain (not a public network's node) may be talked to there.
const LOCAL_CHAINS: readonly string[] = ['eth', 'sol', 'btc']
function scope(profile: Profile, chain: string, url?: string): void {
  const ok = profile !== 'local' || (LOCAL_CHAINS.includes(chain) && (url === undefined || chain === 'eth' || isLoopback(url)))
  if (!ok) refuse('config.local-scope', `the local profile covers Ethereum, Solana and Bitcoin on loopback endpoints only, not ${JSON.stringify(chain)}`) // @guard:config.local-scope
}

export function chainId(profile: Profile, chain: 'eth' | 'arb' | 'base'): number {
  scope(profile, chain)
  return (NETWORK_IDS[profile] as Record<string, number>)[chain]
}

// The human name of each destination's network, by profile (Task T1): the trigger traces record it, and M1's
// preflight and Part D's regime banner print it, so there is one source. The EVM ids come from NETWORK_IDS.
// The `·` is U+00B7; ASCII-only renderings (the trigger text twin) substitute ` | `.
export type NetworkChain = 'eth' | 'arb' | 'base' | 'sol' | 'btc' | 'arweave'
const NETWORK_NAMES: Readonly<Record<Profile, Readonly<Partial<Record<NetworkChain, string>>>>> = {
  mainnet: {
    eth: `Ethereum mainnet · ${NETWORK_IDS.mainnet.eth}`, arb: `Arbitrum One · ${NETWORK_IDS.mainnet.arb}`, base: `Base · ${NETWORK_IDS.mainnet.base}`,
    sol: 'Solana mainnet-beta', btc: 'Bitcoin mainnet', arweave: 'Arweave mainnet',
  },
  testnet: {
    eth: `Sepolia · ${NETWORK_IDS.testnet.eth}`, arb: `Arbitrum Sepolia · ${NETWORK_IDS.testnet.arb}`, base: `Base Sepolia · ${NETWORK_IDS.testnet.base}`,
    sol: 'Solana devnet', btc: 'Bitcoin testnet4', arweave: 'Arweave dev sandbox (ar-io.dev)',
  },
  // R35: no Arbitrum or Base in local (config.local-scope); local Arweave is recorded as skipped.
  local: { eth: `anvil · ${NETWORK_IDS.local.eth}`, sol: 'Solana local', btc: 'Bitcoin regtest', arweave: 'Arweave (local: skipped)' },
}

export function networkName(profile: Profile, chain: NetworkChain): string {
  assertProfile(profile)
  if (profile === 'local' && (chain === 'arb' || chain === 'base')) scope(profile, chain)
  const names = NETWORK_NAMES[profile]
  const name = Object.hasOwn(names, chain) ? names[chain] : undefined
  if (name === undefined) refuse('config.network-name', 'unknown chain: use eth, arb, base, sol, btc or arweave (the value is not echoed)') // @guard:config.network-name
  return name
}

// ---- config

export interface Endpoint { readonly url: string; readonly direct: boolean }
export interface Anchor { readonly address: string | null; readonly source: string; readonly network: 'mainnet' | 'testnet' | 'any' }
export interface Config {
  readonly profile: Profile
  readonly endpoints: Readonly<Record<string, readonly Endpoint[]>>
  readonly anchors: Readonly<Record<string, Anchor>>
}

const DEFAULT_DIR = fileURLToPath(new URL('../', import.meta.url))
// Defence in depth behind env -i (Task H0, SA-I7): provider names, *_API_KEY, *_TOKEN, *_SECRET, *RPC_URL,
// anything holding PRIVATE_KEY or MNEMONIC.
const ENV_KEY_NAME = /^(?:ALCHEMY|INFURA|HELIUS|QUICKNODE|ANKR|MORALIS)|_API_?KEY$|_TOKEN$|_SECRET$|RPC_URL$|PRIVATE_KEY|MNEMONIC/i

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function base58Length(s: string): number {
  if (s.length === 0) return -1
  let zeros = 0
  while (zeros < s.length && s[zeros] === '1') zeros++
  let n = 0n
  for (const ch of s) {
    const d = B58.indexOf(ch)
    if (d < 0) return -1
    n = n * 58n + BigInt(d)
  }
  let bytes = 0
  while (n > 0n) { n >>= 8n; bytes++ }
  return zeros + bytes
}
function addressOk(kind: 'evm' | 'solana' | 'hex64', a: string): boolean {
  if (kind === 'evm') return /^0x[0-9a-fA-F]{40}$/.test(a)
  if (kind === 'hex64') return /^[0-9a-f]{64}$/.test(a)
  return base58Length(a) === 32
}

export function assertProfile(p: string): asserts p is Profile {
  const ok = (PROFILES as readonly string[]).includes(p)
  if (!ok) refuse('config.profile-invalid', 'unknown profile: use mainnet, testnet or local (the value is not echoed)') // @guard:config.profile-invalid
}

function readJson(dir: string, name: string): unknown {
  let parsed: unknown
  let ok = true
  try { parsed = JSON.parse(readFileSync(join(dir, name), 'utf8')) } catch { ok = false }
  if (!ok) refuse('config.load', `${name} is missing or is not valid JSON`) // @guard:config.load
  return parsed
}

function assertOverrideKey(key: string): void {
  const ok = KNOWN_KEYS.includes(key)
  if (!ok) refuse('config.override-key', `unknown chain or service for an override (--rpc ${RPC_CHAINS.join('|')}; --endpoint ${SERVICE_KEYS.join('|')}); the name is not echoed`) // @guard:config.override-key
}

// Spec B s6.1: no environment variable may hold a personal API key (ALCHEMY*, INFURA*, ...). Used by
// loadConfig and by the Tor gate (src/net/gate.ts), so the rule lives in one place.
export function assertNoKeyEnv(env: Readonly<Record<string, string | undefined>>): void {
  for (const [name, value] of Object.entries(env)) {
    const bad = ENV_KEY_NAME.test(name) && value !== undefined && value !== ''
    if (bad) refuse('config.env-key', `environment variable ${name} looks like an API key and is set; unset it (keys are never used)`) // @guard:config.env-key
  }
}

export function loadConfig(
  profile: Profile,
  env: Readonly<Record<string, string | undefined>> = process.env,
  overrides: Readonly<Record<string, string>> = {},
  dir: string = DEFAULT_DIR,
): Config {
  assertProfile(profile)
  assertNoKeyEnv(env)

  const rawE = readJson(dir, 'endpoints.json')
  const rawA = readJson(dir, 'anchors.json')

  const shapeE = isRecord(rawE) && Object.keys(rawE).length === SECTIONS.length && SECTIONS.every((s) => isRecord(rawE[s]))
  if (!shapeE) refuse('config.endpoints-shape', 'endpoints.json must have exactly the sections mainnet, testnet and local') // @guard:config.endpoints-shape
  const sections = rawE as Record<string, Record<string, unknown>>
  for (const s of SECTIONS) {
    for (const [key, list] of Object.entries(sections[s])) {
      const listOk = KNOWN_KEYS.includes(key) && Array.isArray(list) && list.length > 0 && list.every((u) => typeof u === 'string')
      if (!listOk) refuse('config.endpoints-list', `endpoints.json ${s}.${key}: unknown key or not a non-empty list of strings`) // @guard:config.endpoints-list
    }
  }
  // endpoints.json's own URLs, normalized: the key-like-shape exemption (see validateUrl).
  const known = new Set<string>()
  for (const s of SECTIONS) for (const list of Object.values(sections[s])) for (const u of list as string[]) known.add(normalizeUrl(u))
  for (const s of SECTIONS) {
    for (const [key, list] of Object.entries(sections[s])) {
      for (const u of list as string[]) validateUrl(`endpoints.json ${s}.${key}`, u, known)
      validateOrder(`${s}.${key}`, list as string[])
    }
  }

  const effective: Record<string, string[]> = {}
  for (const [k, v] of Object.entries(sections[profile])) effective[k] = [...(v as string[])]
  for (const [key, url] of Object.entries(overrides)) {
    assertOverrideKey(key)
    validateUrl(key, url, known)
    effective[key] = [url]
  }
  const mainnetHosts = [...MAINNET_HOSTS]
  for (const [key, list] of Object.entries(sections.mainnet)) {
    if (MAINNET_HOST_KEY.test(key)) for (const u of list as string[]) { const h = hostOf(u); if (h !== null) mainnetHosts.push(h) }
  }
  const ownHosts = new Set<string>()
  for (const [key, list] of Object.entries(sections[profile])) {
    if (MAINNET_HOST_KEY.test(key)) for (const u of list as string[]) { const h = hostOf(u); if (h !== null) ownHosts.add(h) }
  }
  for (const [key, urls] of Object.entries(effective)) {
    for (const u of urls) scope(profile, chainOfKey(key), u)
    const ok = profile !== 'local' || urls.every(isLoopback)
    if (!ok) refuse('config.local-loopback', `${key}: the local profile accepts loopback endpoints only`) // @guard:config.local-loopback
    // C2 m3: an ALLOWLIST outside mainnet. A turbo.* / arweave.gateway URL must be loopback or on a host of this profile's
    // own endpoints.json section (any such key); the mainnet denylist stays as the sharper reason. A host that cannot be
    // read is on neither list.
    const hostOk = profile === 'mainnet' || !MAINNET_HOST_KEY.test(key)
      || urls.every((u) => !onMainnetHost(u, mainnetHosts) && (isLoopback(u) || ownHosts.has(hostOf(u) ?? '')))
    if (!hostOk) refuse('config.mainnet-host', `${key}: the ${profile} profile accepts only loopback or its own endpoints.json Turbo/Arweave hosts, and never a mainnet one (spec B §6.5); the URL is not echoed`) // @guard:config.mainnet-host
  }
  const endpoints: Record<string, Endpoint[]> = {}
  for (const [key, urls] of Object.entries(effective)) endpoints[key] = urls.map((url) => ({ url, direct: isLoopback(url) }))

  const shapeA = isRecord(rawA)
  if (!shapeA) refuse('config.anchors-shape', 'anchors.json must be an object') // @guard:config.anchors-shape
  const anchors: Record<string, Anchor> = {}
  for (const [name, v] of Object.entries(rawA as Record<string, unknown>)) {
    const entryOk = Object.hasOwn(ANCHOR_KINDS, name) && isRecord(v)
      && (v.address === null || typeof v.address === 'string')
      && typeof v.source === 'string' && v.source.startsWith('https://')
      && (v.network === 'mainnet' || v.network === 'testnet' || v.network === 'any')
    if (!entryOk) refuse('config.anchors-entry', `anchors.json ${JSON.stringify(name.slice(0, 40))}: unknown name or malformed entry`) // @guard:config.anchors-entry
    const e = v as unknown as Anchor
    const fmtOk = e.address === null || addressOk(ANCHOR_KINDS[name], e.address)
    if (!fmtOk) refuse('config.anchor-format', `anchor ${name}: address is not a well-formed ${ANCHOR_KINDS[name]} value`) // @guard:config.anchor-format
    anchors[name] = { address: e.address, source: e.source, network: e.network }
  }
  return { profile, endpoints, anchors }
}

export function endpointInfo(cfg: Config, key: string): readonly Endpoint[] {
  scope(cfg.profile, chainOfKey(key))
  const list = Object.hasOwn(cfg.endpoints, key) ? cfg.endpoints[key] : undefined
  if (list === undefined) refuse('config.endpoint-missing', `no endpoint configured for ${JSON.stringify(key.slice(0, 40))} in the ${cfg.profile} profile`) // @guard:config.endpoint-missing
  return list
}

export function endpoint(cfg: Config, key: string): string[] {
  return endpointInfo(cfg, key).map((e) => e.url)
}

// Loopback ports of the effective config (for widening the sandbox to exactly those ports).
export function loopbackPorts(cfg: Config): number[] {
  const ports = new Set<number>()
  for (const list of Object.values(cfg.endpoints)) {
    for (const e of list) {
      const p = e.direct ? loopbackPort(e.url) : null
      if (p !== null) ports.add(p)
    }
  }
  return [...ports].sort((a, b) => a - b)
}

export function anchor(cfg: Config, name: string): string {
  scope(cfg.profile, chainOfAnchor(name))
  const e = Object.hasOwn(cfg.anchors, name) ? cfg.anchors[name] : undefined
  if (e === undefined || e.address === null) refuse('config.anchor-missing', `anchor ${JSON.stringify(name.slice(0, 40))} is not available (null or absent); it is not used`) // @guard:config.anchor-missing
  const netOk = e.network === 'any' || e.network === cfg.profile
  if (!netOk) refuse('config.anchor-network', `anchor ${name} belongs to the ${e.network} network, not ${cfg.profile}`) // @guard:config.anchor-network
  return e.address as string
}

// ---- bitcoind credential (R36)

// The brief's ^[A-Za-z0-9_.-]+:[^\s:]+$, minus control characters (a NUL has no place in a header).
const AUTH_LINE = /^[A-Za-z0-9_.-]+:[^\s:\x00-\x1f\x7f]+$/

// The bitcoind RPC credential: ONLY from $OUT/local/btc-rpc.auth, one line <user>:<pass>, mode 0600 or
// stricter. Never from a URL or an env var. The value is returned to the caller and appears in no
// message: a refusal says only that the file is unusable.
export function loadBitcoindAuth(out: string, getuid: () => number = () => process.getuid!()): string {
  let line = ''
  let ok = true
  try {
    const fd = openSync(join(out, 'local', 'btc-rpc.auth'), fsc.O_RDONLY | fsc.O_NOFOLLOW)
    try {
      const st = fstatSync(fd)
      if (!st.isFile() || (st.mode & 0o177) !== 0 || st.uid !== getuid()) ok = false
      else line = readFileSync(fd, 'utf8').replace(/\n$/, '')
    } finally { closeSync(fd) }
  } catch { ok = false }
  ok = ok && AUTH_LINE.test(line)
  if (!ok) refuse('config.bitcoind-auth', '$OUT/local/btc-rpc.auth is missing, unreadable, not a regular 0600 file you own (symlinks refused), or not one <user>:<pass> line') // @guard:config.bitcoind-auth
  return line
}

// ---- argv / env parsing

// Values of a repeatable `--flag value` (space form only: `--flag=value` is refused, never ignored).
function flagValues(argv: readonly string[], flag: string): string[] {
  const out: string[] = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    const isFlag = a === flag
    if (!isFlag && !a.startsWith(flag + '=')) continue
    const v = argv[i + 1]
    const ok = isFlag && v !== undefined && !v.startsWith('--')
    if (!ok) refuse('config.flag-format', `${flag} needs a separate value (${flag} <value>)`) // @guard:config.flag-format
    out.push(v)
    i++
  }
  return out
}
function singleFlag(argv: readonly string[], flag: string): string | undefined {
  const values = flagValues(argv, flag)
  const ok = values.length <= 1
  if (!ok) refuse('config.flag-duplicate', `${flag} given more than once`) // @guard:config.flag-duplicate
  return values[0]
}

function splitPair(flag: string, raw: string): [string, string] {
  const i = raw.indexOf('=')
  const ok = i > 0 && i < raw.length - 1
  if (!ok) refuse('config.override-format', `${flag} expects <name>=<url>`) // @guard:config.override-format
  return [raw.slice(0, i), raw.slice(i + 1)]
}

// R23: --rpc <chain>=<url> (chain RPCs only), --endpoint <service>=<url>, env VT_RPC_<CHAIN> and
// VT_ENDPOINT_<SERVICE> (dots become underscores). Flags win over env. Empty env values are unset.
// Returns dotted key -> url; loadConfig validates the URLs.
export function parseOverrides(argv: readonly string[], env: Readonly<Record<string, string | undefined>>): Record<string, string> {
  const out: Record<string, string> = {}
  const seen = new Set<string>()
  const put = (key: string, url: string, fromFlag: boolean) => {
    assertOverrideKey(key)
    if (fromFlag) {
      const fresh = !seen.has(key)
      if (!fresh) refuse('config.override-duplicate', `override for ${key} given more than once`) // @guard:config.override-duplicate
      seen.add(key)
      out[key] = url
    } else if (!seen.has(key)) {
      out[key] = url
    }
  }
  for (const raw of flagValues(argv, '--rpc')) {
    const [chain, url] = splitPair('--rpc', raw)
    put((RPC_CHAINS as readonly string[]).includes(chain) ? `${chain}.rpc` : `?${chain}`, url, true)
  }
  for (const raw of flagValues(argv, '--endpoint')) {
    const [svc, url] = splitPair('--endpoint', raw)
    put(SERVICE_KEYS.includes(svc) ? svc : `?${svc}`, url, true)
  }
  for (const [name, value] of Object.entries(env)) {
    const mine = /^VT_(?:RPC|ENDPOINT)_./.test(name)
    if (mine) {
      const set = value !== undefined && value !== ''
      if (!set) refuse('config.override-empty', `${name} is set but empty; unset it or give a URL`) // @guard:config.override-empty
    }
    if (value === undefined) continue
    const r = /^VT_RPC_(.+)$/.exec(name)
    if (r !== null) put(RPC_KEYS.find((k) => k.split('.')[0].toUpperCase() === r[1]) ?? `?${r[1]}`, value, false)
    const s = /^VT_ENDPOINT_(.+)$/.exec(name)
    if (s !== null) put(SERVICE_KEYS.find((k) => k.toUpperCase().replaceAll('.', '_') === s[1]) ?? `?${s[1]}`, value, false)
  }
  return out
}

// --profile <p> or VT_PROFILE; default mainnet; disagreement refuses.
export function parseProfile(argv: readonly string[], env: Readonly<Record<string, string | undefined>>): Profile {
  const flag = singleFlag(argv, '--profile')
  const fromEnv = env.VT_PROFILE === '' ? undefined : env.VT_PROFILE
  if (flag !== undefined) assertProfile(flag)
  if (fromEnv !== undefined) assertProfile(fromEnv)
  const ok = flag === undefined || fromEnv === undefined || flag === fromEnv
  if (!ok) refuse('config.profile-conflict', '--profile disagrees with VT_PROFILE (the values are not echoed)') // @guard:config.profile-conflict
  return (flag ?? fromEnv ?? 'mainnet') as Profile
}

// Like parseProfile, but with no default: neither --profile nor a non-empty VT_PROFILE refuses (audit K33/SA-N4).
// `keystore init` binds the keystore to this profile, and Task M1 reuses it for networked commands while locked, so a
// binding or a send never silently means mainnet. The ONE config.profile-required marker line.
export function requireExplicitProfile(argv: readonly string[], env: Readonly<Record<string, string | undefined>>): Profile {
  const given = argv.some((a) => a === '--profile' || a.startsWith('--profile=')) || (env.VT_PROFILE !== undefined && env.VT_PROFILE !== '')
  if (!given) refuse('config.profile-required', 'this command needs an explicit profile: --profile mainnet|testnet|local or VT_PROFILE (it never defaults to mainnet)') // @guard:config.profile-required
  return parseProfile(argv, env)
}

export interface Timing { tickSeconds?: number; coolingSeconds?: [number, number]; confirmations?: number }
const TIMING_FLAGS = ['--tick-seconds', '--cooling-seconds', '--confirmations']
const POS_INT = /^[1-9][0-9]{0,8}$/

// Timing overrides exist for testnet/local runs only. Railgun's own standby and PPOI are never overridable.
export function parseTimingOverrides(argv: readonly string[], profile: Profile): Timing {
  const present = TIMING_FLAGS.some((f) => argv.some((a) => a === f || a.startsWith(f + '=')))
  const ok = (profile === 'testnet' || profile === 'local') || !present
  if (!ok) refuse('network.override-mainnet', 'timing overrides (--tick-seconds, --cooling-seconds, --confirmations) are refused in mainnet') // @guard:network.override-mainnet
  const out: Timing = {}
  let bad: string | undefined
  const tick = singleFlag(argv, '--tick-seconds')
  if (tick !== undefined) { if (POS_INT.test(tick)) out.tickSeconds = Number(tick); else bad ??= '--tick-seconds' }
  const cool = singleFlag(argv, '--cooling-seconds')
  if (cool !== undefined) {
    const m = /^([1-9][0-9]{0,8})-([1-9][0-9]{0,8})$/.exec(cool)
    if (m !== null && Number(m[1]) <= Number(m[2])) out.coolingSeconds = [Number(m[1]), Number(m[2])]
    else bad ??= '--cooling-seconds'
  }
  const conf = singleFlag(argv, '--confirmations')
  if (conf !== undefined) { if (POS_INT.test(conf)) out.confirmations = Number(conf); else bad ??= '--confirmations' }
  if (bad !== undefined) refuse('config.timing-format', `${bad}: bad value (positive integers; --cooling-seconds MIN-MAX with MIN <= MAX)`) // @guard:config.timing-format
  return out
}

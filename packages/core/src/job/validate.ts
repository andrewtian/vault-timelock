// packages/core/src/job/validate.ts — normalizeJob: strict vt-job/1 input → the canonical JobDef (spec §4.1, R71, R73).
//
// Order of checks (each refusal a one-line guard; nothing echoes an input value):
//   contract.network      o.network (the caller's own network)
//   job.format            an object; format "vt-job/1"; chains a non-empty object whose members are objects
//   job.unknown-key       any member not in the format, at the top, in chains (eth, sol) or in a chain
//   job.network-field     network missing or not local | testnet | mainnet
//   job.network           network ≠ o.network: a job never runs on another network (R71)
//   job.name              1..64 printable ASCII; then job.ip-like / job.key-like (keylike.ts)
//   per chain, eth then sol:
//     job.field-chain     a member of the other chain (maxCuPrice on eth, maxTipGwei on sol)
//     job.mode            "drain" | { copies: 1..10000 }; distinctCopies a boolean
//     job.publish-mode    an id in contracts/publish.ts whose row lists this chain (default DEFAULT_PUBLISH_MODE)
//     job.publish-mode-unavailable   a reserved mode
//     job.fee-strategy    passive | economy | prompt (default: passive for drain, economy for copies)
//     job.address         keyAddress: EIP-55 (eth) / canonical base58 of 32 bytes (sol)
//     job.budget          budgetUsd: a finite number, > 0, <= 1000, at most 2 decimals
//     job.tip-cap         maxTipGwei (eth, optional): 0.1..100
//     job.cu-cap          maxCuPrice (sol, optional): an integer 0..2,000,000
//     job.clawback        clawbackTo: null, or a valid address of the chain that is not the null address, the burn
//                         address (eth 0x…dEaD), the System Program / incinerator (sol), or keyAddress
//     job.clawback-precompile   an ETH clawbackTo at 0x…0001 to 0x…ffff (the precompiles and the reserved range): what a
//                         claw-back would refuse is refused here, from chains/reserved.js (E6)
//     job.clawback-required     (PF-S fix round 1, N-6) a NEW mainnet job names clawbackTo on each eth / sol chain: the one
//                         address its remainder may ever go back to (the API refuses a mainnet claw-back to any other); a
//                         stored job (existing) keeps whatever it has
//   job.chain-unsupported chains.btc off the local network (E7b: the btc lane is local only); refused after job.unknown-key
//   job.fee-rate          maxFeeRateSatVb (btc, optional): an integer 1..500 (sat/vB)
//   job.text-kind         textKind (optional, CC-7): "plain" | "timelocked"; "timelocked" is refused job.publish-mode-unavailable until E6/W7
//                         (a reserved capability); plain and absent are the same job, with the same jobId (textKind is not in the JobDef)
//   job.arweave-copy      arweaveCopy (optional): a boolean (CC-1); true needs ARWEAVE_COPY available, else
//                         job.publish-mode-unavailable (a reserved capability, like a reserved mode)
//   job.message-file      messageFile is read by vt only and never reaches here
//   job.message-source    exactly one of message (a string) | messageSha256 (64 lowercase hex) + messageBytes
//                         (an integer 1..MESSAGE_MAX)
//   message.*             an inline message goes through validateMessage
// A member whose value is undefined counts as absent (as in JSON). The def is a fresh object (no input aliasing);
// publishMode and feeStrategy are always filled in, so jobId always covers them; arweaveCopy is written only when true
// (false and absent are the same job, with the same jobId).
import { getAddress } from 'viem'
import * as btcSigner from '@scure/btc-signer'
import { base58 } from '@scure/base'
import {
  ARWEAVE_COPY, DEFAULT_PUBLISH_MODE, FEE_STRATEGIES, MESSAGE_MAX, PUBLISH_MODES_VERSION, assertNetwork, defaultFeeStrategy,
  isNetwork, publishModeRow, refuse,
} from '../contracts/index.ts'
import type { Chain, FeeStrategy, JobChainDef, JobDef, Mode, Network } from '../contracts/index.ts'
import { BTC_MAX_FEE_RATE, btcNetwork } from '../chains/btc-ord.ts'
import { ethReservedKind, solReservedKind } from '../chains/reserved.js'
import { assertNoSecretOrIp } from './keylike.ts'
import { validateMessage } from './message.ts'

type Obj = Record<string, unknown>
// E7b (CC-12): btc is a lane on the LOCAL network (the regtest bitcoind + ord); on testnet / mainnet it is refused job.chain-unsupported
// until Esplora reads exist. Copies mode only, no claw-back, publish mode btc.inscription, optional maxFeeRateSatVb.
type Lane = Chain
const CHAINS: readonly Lane[] = ['eth', 'sol', 'btc']
const TOP = ['format', 'network', 'name', 'message', 'messageFile', 'messageSha256', 'messageBytes', 'chains', 'arweaveCopy', 'textKind'] as const
const ONLY: Readonly<Record<Lane, readonly string[]>> = { eth: ['maxTipGwei'], sol: ['maxCuPrice'], btc: ['maxFeeRateSatVb'] }
const CHAIN_KEYS = ['mode', 'publishMode', 'feeStrategy', 'distinctCopies', 'keyAddress', 'budgetUsd', 'clawbackTo', ...ONLY.eth, ...ONLY.sol, ...ONLY.btc]
const NAME = /^[\x20-\x7e]{1,64}$/
const HEX64 = /^[0-9a-f]{64}$/
const ETH_ADDRESS = /^0x[0-9a-fA-F]{40}$/
const SOL_ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/

function plain(v: unknown): v is Obj {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false
  const p: unknown = Object.getPrototypeOf(v)
  return p === Object.prototype || p === null
}
const present = (o: Obj): string[] => Object.keys(o).filter((k) => o[k] !== undefined)
const has = (o: Obj, k: string): boolean => Object.hasOwn(o, k) && o[k] !== undefined
const get = (o: Obj, k: string): unknown => (has(o, k) ? o[k] : undefined)

function checkKeys(o: Obj, allowed: readonly string[], where: string): void {
  const ok = present(o).every((k) => allowed.includes(k))
  if (!ok) refuse('job.unknown-key', `${where}: an unknown member (allowed: ${allowed.join(', ')}); its name is not echoed`) // @guard:job.unknown-key
}

// A reserved capability (a publish mode, or the job-level Arweave copy) is refused until its row is available.
function assertAvailable(ok: boolean, what: string): void {
  if (!ok) refuse('job.publish-mode-unavailable', `${what} is reserved, not yet available (${PUBLISH_MODES_VERSION})`) // @guard:job.publish-mode-unavailable
}

// A chain address in its canonical form: EIP-55 (eth), canonical base58 of exactly 32 bytes (sol).
function isChainAddress(c: Chain, v: unknown): v is string {
  if (typeof v !== 'string') return false
  if (c === 'eth') {
    if (!ETH_ADDRESS.test(v)) return false
    try { return getAddress(v) === v } catch { return false }
  }
  if (c === 'btc') {                                              // a lower-case bech32 p2wpkh address of the local (regtest) network
    try { return v === v.toLowerCase() && btcSigner.Address(btcNetwork('local')).decode(v).type === 'wpkh' && btcSigner.Address(btcNetwork('local')).encode(btcSigner.Address(btcNetwork('local')).decode(v)) === v } catch { return false }
  }
  if (!SOL_ADDRESS.test(v)) return false
  try { const b = base58.decode(v); return b.length === 32 && base58.encode(b) === v } catch { return false }
}
const same = (c: Chain, a: string): string => (c === 'eth' ? a.toLowerCase() : a)

function normMode(v: unknown): Mode | null {
  if (v === 'drain') return 'drain'
  if (!plain(v)) return null
  const keys = present(v)
  const n = v.copies
  return keys.length === 1 && keys[0] === 'copies' && typeof n === 'number' && Number.isSafeInteger(n) && n >= 1 && n <= 10_000 ? { copies: n } : null
}

/** The fee-rate ceiling a NEW btc job suggests (sat/vB): min(500, max(10, 4 x the node's current estimate)); 25 when there is no estimate. One rule for
 * the page's prefill, the CLI's error text and docs/vt.md (Eminors fix 1, I-1). */
export function suggestedBtcFeeCeiling(estimateSatVb?: number | bigint | null): number {
  const e = estimateSatVb === null || estimateSatVb === undefined ? NaN : Number(estimateSatVb)
  if (!Number.isFinite(e) || e < 1) return 25
  return Math.min(Number(BTC_MAX_FEE_RATE), Math.max(10, 4 * Math.ceil(e)))
}

function normalizeChain(c: Lane, raw: Obj, existing: boolean, network: Network): JobChainDef {
  const others = CHAINS.filter((x) => x !== c)
  const ownFields = !others.some((o) => ONLY[o].some((k) => has(raw, k)))
  if (!ownFields) refuse('job.field-chain', `chains.${c}: a member of another chain`) // @guard:job.field-chain
  const mode = normMode(get(raw, 'mode'))
  const distinctCopies = get(raw, 'distinctCopies')
  const modeOk = mode !== null && typeof distinctCopies === 'boolean' && (c !== 'btc' || mode !== 'drain')
  if (!modeOk) refuse('job.mode', `chains.${c}: mode must be ${c === 'btc' ? '{ "copies": 1..10000 } (no drain for btc)' : '"drain" or { "copies": 1..10000 }'}, and distinctCopies a boolean`) // @guard:job.mode
  const pm = has(raw, 'publishMode') ? raw.publishMode : DEFAULT_PUBLISH_MODE[c]
  const row = typeof pm === 'string' ? publishModeRow(pm) : undefined
  const pmOk = row !== undefined && row.chains.includes(c)
  if (!pmOk) refuse('job.publish-mode', `chains.${c}: publishMode must be one of the ${c} modes of ${PUBLISH_MODES_VERSION}`) // @guard:job.publish-mode
  assertAvailable(row.status === 'available', `chains.${c}: publish mode ${row.id}`)
  const fee = has(raw, 'feeStrategy') ? raw.feeStrategy : defaultFeeStrategy(mode)
  const feeOk = (FEE_STRATEGIES as readonly unknown[]).includes(fee)
  if (!feeOk) refuse('job.fee-strategy', `chains.${c}: feeStrategy must be ${FEE_STRATEGIES.join(', ')}`) // @guard:job.fee-strategy
  const key = get(raw, 'keyAddress')
  const keyOk = isChainAddress(c, key)
  if (!keyOk) refuse('job.address', `chains.${c}: keyAddress must be ${c === 'eth' ? 'an EIP-55 checksummed address' : c === 'btc' ? 'a lower-case bech32 p2wpkh address of the local network' : 'the canonical base58 of 32 bytes'}`) // @guard:job.address
  const budget = get(raw, 'budgetUsd')
  const budgetOk = typeof budget === 'number' && Number.isFinite(budget) && budget > 0 && budget <= 1000 && Math.round(budget * 100) / 100 === budget
  if (!budgetOk) refuse('job.budget', `chains.${c}: budgetUsd must be > 0 and <= 1000, with at most 2 decimals`) // @guard:job.budget
  const tip = get(raw, 'maxTipGwei')
  const tipOk = tip === undefined || (typeof tip === 'number' && Number.isFinite(tip) && tip >= 0.1 && tip <= 100)
  if (!tipOk) refuse('job.tip-cap', `chains.${c}: maxTipGwei must be 0.1..100`) // @guard:job.tip-cap
  const cu = get(raw, 'maxCuPrice')
  const cuOk = cu === undefined || (typeof cu === 'number' && Number.isSafeInteger(cu) && cu >= 0 && cu <= 2_000_000)
  if (!cuOk) refuse('job.cu-cap', `chains.${c}: maxCuPrice must be an integer 0..2000000`) // @guard:job.cu-cap
  const fr = get(raw, 'maxFeeRateSatVb')
  const frOk = fr === undefined || (typeof fr === 'number' && Number.isSafeInteger(fr) && fr >= 1 && fr <= Number(BTC_MAX_FEE_RATE))
  // Eminors fix 1 (I-1): a NEW btc job names its ceiling. The copy is quoted and capped at this rate, so a missing field would hide a 500 sat/vB ceiling.
  // A job that already exists (a stored record, a journal) keeps the 500 fallback: only creation requires the field.
  const ceilingOk = c !== 'btc' || existing || fr !== undefined
  if (!ceilingOk) refuse('job.btc-fee-ceiling', `chains.btc: maxFeeRateSatVb is required (an integer 1..${BTC_MAX_FEE_RATE} sat/vB): the highest fee rate this job may pay; every copy is quoted and capped at it. Suggested: ${suggestedBtcFeeCeiling(null)} (min(${BTC_MAX_FEE_RATE}, max(10, 4 x the node's current estimate)) when the estimate is known)`) // @guard:job.btc-fee-ceiling
  if (!frOk) refuse('job.fee-rate', `chains.${c}: maxFeeRateSatVb must be an integer 1..${BTC_MAX_FEE_RATE}`) // @guard:job.fee-rate
  const to = has(raw, 'clawbackTo') ? raw.clawbackTo : undefined
  // the precompile range is judged on the 40 hex digits whatever their case (a low address rarely has a valid checksum case)
  const kind = typeof to !== 'string' || c === 'btc' ? null : c === 'eth' ? (ETH_ADDRESS.test(to) ? ethReservedKind(to) : null) : (isChainAddress(c, to) ? solReservedKind(to) : null)
  const precompileOk = kind !== 'precompile'
  if (!precompileOk) refuse('job.clawback-precompile', `chains.${c}: clawbackTo is an Ethereum precompile or reserved system address (0x…0001 to 0x…ffff): nobody controls it and value sent there is lost`) // @guard:job.clawback-precompile
  const toOk = to === null || (c !== 'btc' && isChainAddress(c, to) && kind === null && same(c, to) !== same(c, key))
  if (!toOk) refuse('job.clawback', `chains.${c}: clawbackTo must be null or a valid ${c} address that is not the null, burn or System Program address and not keyAddress`) // @guard:job.clawback
  const requiredOk = existing || network !== 'mainnet' || c === 'btc' || to !== null
  if (!requiredOk) refuse('job.clawback-required', `chains.${c}.clawbackTo is required on mainnet: the one address (yours, reviewed now) the lane's remainder may be clawed back to — the API refuses a mainnet claw-back to any other address`) // @guard:job.clawback-required
  assertNoSecretOrIp(key, `chains.${c}.keyAddress`)
  if (to !== null) assertNoSecretOrIp(to as string, `chains.${c}.clawbackTo`)
  return {
    mode, publishMode: row.id, feeStrategy: fee as FeeStrategy, distinctCopies, keyAddress: key, budgetUsd: budget,
    ...(tip === undefined ? {} : { maxTipGwei: tip }), ...(cu === undefined ? {} : { maxCuPrice: cu }), ...(fr === undefined ? {} : { maxFeeRateSatVb: fr }), clawbackTo: to,
  }
}

/** @param o.existing true only when RE-reading a stored job (its canonical record): the btc fee ceiling may then be absent (the 500 sat/vB fallback),
 *  and a mainnet chain's clawbackTo may be null (job.clawback-required applies to new jobs only). */
export function normalizeJob(input: unknown, o: { network: Network; existing?: boolean }): { def: JobDef; text: string | null } {
  assertNetwork(o.network)
  const j = plain(input) ? input : null
  const chains = j !== null && plain(get(j, 'chains')) ? (j.chains as Obj) : null
  const shapeOk = j !== null && get(j, 'format') === 'vt-job/1' && chains !== null && present(chains).length > 0
    && present(chains).every((k) => plain(chains[k]))
  if (!shapeOk) refuse('job.format', 'not a vt-job/1 job: an object with format "vt-job/1" and chains, a non-empty object of chain objects') // @guard:job.format
  checkKeys(j, TOP, 'the job')
  checkKeys(chains, CHAINS, 'chains')
  const btcLane = !has(chains, 'btc') || o.network === 'local'
  if (!btcLane) refuse('job.chain-unsupported', `chains.btc: the btc lane runs on a local network only (this side serves ${o.network}): testnet4 and mainnet need Esplora reads, which do not exist yet`) // @guard:job.chain-unsupported
  for (const c of CHAINS) if (has(chains, c)) checkKeys(chains[c] as Obj, CHAIN_KEYS, `chains.${c}`)

  const network = get(j, 'network')
  const networkOk = isNetwork(network)
  if (!networkOk) refuse('job.network-field', 'network is required: local, testnet or mainnet') // @guard:job.network-field
  const sameNetwork = network === o.network
  if (!sameNetwork) refuse('job.network', `this job is for ${network}; this side serves ${o.network} (a job never runs on another network)`) // @guard:job.network

  const name = get(j, 'name')
  const nameOk = typeof name === 'string' && NAME.test(name)
  if (!nameOk) refuse('job.name', 'name must be 1..64 printable ASCII characters') // @guard:job.name
  assertNoSecretOrIp(name, 'name')

  const defChains: Partial<Record<Chain, JobChainDef>> = {}
  for (const c of CHAINS) if (has(chains, c)) defChains[c] = normalizeChain(c, chains[c] as Obj, o.existing === true, o.network)

  const arweaveCopy = get(j, 'arweaveCopy')
  const arweaveCopyOk = arweaveCopy === undefined || typeof arweaveCopy === 'boolean'
  if (!arweaveCopyOk) refuse('job.arweave-copy', 'arweaveCopy must be true or false') // @guard:job.arweave-copy
  if (arweaveCopy === true) assertAvailable(ARWEAVE_COPY.status === 'available', 'arweaveCopy: the Arweave copy')

  const textKind = get(j, 'textKind')
  const textKindOk = textKind === undefined || textKind === 'plain' || textKind === 'timelocked'
  if (!textKindOk) refuse('job.text-kind', 'textKind must be "plain" or "timelocked"') // @guard:job.text-kind
  assertAvailable(textKind !== 'timelocked', 'textKind timelocked: the timelocked text')

  const noFile = !has(j, 'messageFile')
  if (!noFile) refuse('job.message-file', 'messageFile is read by vt only: send the message, or upload it and send messageSha256 + messageBytes') // @guard:job.message-file
  const inline = has(j, 'message')
  const sha = get(j, 'messageSha256')
  const size = get(j, 'messageBytes')
  const sourceOk = inline
    ? typeof j.message === 'string' && sha === undefined && size === undefined
    : typeof sha === 'string' && HEX64.test(sha) && typeof size === 'number' && Number.isSafeInteger(size) && size >= 1 && size <= MESSAGE_MAX
  if (!sourceOk) refuse('job.message-source', `give exactly one of message, or messageSha256 (64 lowercase hex) + messageBytes (1..${MESSAGE_MAX})`) // @guard:job.message-source

  let text: string | null = null
  let messageSha256 = sha as string
  let messageBytes = size as number
  if (inline) {
    text = j.message as string
    const m = validateMessage(text)
    messageSha256 = m.sha256
    messageBytes = m.bytes
  }
  return { def: { format: 'vt-job/1', network, name, messageSha256, messageBytes, chains: defChains, ...(arweaveCopy === true ? { arweaveCopy } : {}) }, text }
}

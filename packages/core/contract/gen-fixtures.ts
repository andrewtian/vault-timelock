// packages/core/contract/gen-fixtures.ts — builds every contract fixture and the vt-job/1 JSON Schema, deterministically.
//   node packages/core/contract/gen-fixtures.ts --write   (re)write them
//   node packages/core/contract/gen-fixtures.ts --check   exit 1 if a committed file differs
// test/contracts/fixtures.test.ts runs the same check, so a contract change is: edit the contracts and this file,
// --write, review the diff, commit. ALL DATA IS SYNTHETIC (addresses and hashes derived from fixed labels; the drand
// quicknet chain hash is public). The expected reducer states are written out by hand per vector (not computed by a
// reducer), following the semantics stated in src/contracts/types.ts.
import { createHash, createHmac } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { base58, base64, base64urlnopad } from '@scure/base'
import {
  AddressLookupTableAccount, ComputeBudgetProgram, Keypair, Message, PublicKey, Secp256k1Program, SystemProgram, TransactionInstruction,
  TransactionMessage, VersionedTransaction,
} from '@solana/web3.js'
import * as btc from '@scure/btc-signer'
import { pubECDSA, pubSchnorr } from '@scure/btc-signer/utils.js'
import { OutOrdinalReveal, p2tr_ord_reveal } from 'micro-ordinals'
import { concatHex, getAddress, hexToBytes, keccak256, numberToHex, serializeTransaction, toHex, toRlp } from 'viem'
import { english, privateKeyToAccount } from 'viem/accounts'
import { planLaneCopy } from '../src/engine/lane.js'
import { laneConfigOf } from '../src/executor/index.ts'
import {
  DEFAULT_PUBLISH_MODE, FEE_STRATEGIES, LEASE_TTL_MS, MESSAGE_MAX, PART_FORMAT, PUBLISH_MODES_VERSION, TICKET_PREFIX,
  TICKET_TTL_MS, defaultFeeStrategy, ethDataGas, partPrefix, parsePart, publishModesFor,
} from '../src/contracts/index.ts'
import type {
  ArmCap, ArmRecord, AttemptView, Chain as ContractChain, ChainState, EthIntent, JobChainDef, JobDef, JobState, JournalEvent, LeaseGrant,
  OpenIntent, PartHeaderInput, SolIntent, TicketPayload, TxView,
} from '../src/contracts/index.ts'

type Chain = Exclude<ContractChain, 'btc'> // CC-7: the fixtures cover the lanes that exist (eth, sol); btc is a refusal fixture

const ROOT = fileURLToPath(new URL('../', import.meta.url)) // packages/core/

// ---------------------------------------------------------------- primitives

const enc = new TextEncoder()
export const sha256Hex = (b: string | Uint8Array): string => createHash('sha256').update(b).digest('hex')
const seed = (label: string): Buffer => createHash('sha256').update(`vt-fixture:${label}`).digest()
// Canonical JSON (spec §4.1): keys sorted, no whitespace, numbers as JSON.stringify writes them.
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v)
  if (typeof v === 'number') { if (!Number.isFinite(v)) throw new Error('non-finite number'); return JSON.stringify(v) }
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>
    return `{${Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(',')}}`
  }
  throw new Error(`not JSON: ${typeof v}`)
}
const pretty = (v: unknown): string => `${JSON.stringify(v, null, 2)}\n`
const jobIdOf = (def: JobDef): string => sha256Hex(canonicalJson(def)).slice(0, 16)

// Synthetic identities (no private key exists for any of them).
const ethAddr = (label: string): string => getAddress(`0x${seed(label).toString('hex').slice(0, 40)}`)
const solAddr = (label: string, bytes = 32): string => base58.encode(seed(label).subarray(0, bytes))
const ethTx = (label: string): string => `0x${seed(`tx:${label}`).toString('hex')}`
const solSig = (label: string): string => base58.encode(Buffer.concat([seed(`sig:${label}`), seed(`sig2:${label}`)]))
const hex64 = (label: string): string => seed(label).toString('hex')
const blockhash = (label: string): string => base58.encode(seed(`bh:${label}`))

export const ETH_A = ethAddr('eth key A')
export const ETH_B = ethAddr('eth destination B')
export const SOL_A = solAddr('sol key A')
export const SOL_B = solAddr('sol destination B')
const NULL_ETH = '0x0000000000000000000000000000000000000000'
export const T0 = 1_791_504_000_000 // 2026-10-09T00:00:00Z
const CANARY = '203.0.113.77'

// ---------------------------------------------------------------- messages

export const MSG_A = 'A synthetic vt fixture message.\nIt has two lines.\n'
const QUICKNET = '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971' // drand quicknet chain hash (public)
const SEALED_LIKE = [
  'SEALED (synthetic test package, not a real vault)',
  'format: vt-sealed/1',
  `drand: quicknet ${QUICKNET}`,
  'round: 23456789',
  'unlock: 2027-10-09T00:00:00Z',
  `check: https://api.drand.sh/${QUICKNET}/public/23456789`,
  `payload: payload.tar.gz.age sha256=${hex64('sealed payload digest')}`,
  'bytes: 123456',
  'To open: fetch the round from the URL above after the unlock time, then follow the open steps.',
  '',
].join('\n')

function multibyte5k(): string {
  const words = ['café', 'naïve façade', '漢字かな交じり文', '한국어 문장', '😀🚀🌍🎉', 'Ελληνικά', 'кириллица', 'ASCII text']
  let out = '', i = 0
  while (enc.encode(out).length < 5000) {
    out += `Line ${String(i + 1).padStart(3, '0')}: ${words[i % words.length]} ${words[(i * 3 + 1) % words.length]} ${words[(i * 5 + 2) % words.length]}.\n`
    i++
  }
  return out
}

function b58of88(): string {
  for (let k = 0; ; k++) {
    const s = base58.encode(Buffer.concat([seed(`b58-88:${k}`), seed(`b58-88b:${k}`)]))
    if (s.length === 88) return s
  }
}

function assertNoBip39Run(text: string, label: string): void {
  const set = new Set(english)
  let run = 0
  for (const w of text.split(/[^a-z]+/)) {
    run = w !== '' && set.has(w) ? run + 1 : 0
    if (run >= 12) throw new Error(`${label}: 12 consecutive BIP-39 words`)
  }
}

// ---------------------------------------------------------------- jobs

type Input = Record<string, unknown>
const ethChain = (o: Record<string, unknown> = {}): Record<string, unknown> => ({
  mode: 'drain', publishMode: 'eth.calldata.null', feeStrategy: 'passive', distinctCopies: true, keyAddress: ETH_A,
  budgetUsd: 10, maxTipGwei: 3, clawbackTo: null, ...o,
})
const solChain = (o: Record<string, unknown> = {}): Record<string, unknown> => ({
  mode: { copies: 3 }, publishMode: 'sol.memo', feeStrategy: 'economy', distinctCopies: true, keyAddress: SOL_A,
  budgetUsd: 5, maxCuPrice: 2_000_000, clawbackTo: SOL_B, ...o,
})
const BTC_JOB_ADDR = btc.p2wpkh(pubECDSA(seed('job btc lane')), { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef }).address as string
const btcChain = (o: Record<string, unknown> = {}): Record<string, unknown> => ({
  mode: { copies: 2 }, publishMode: 'btc.inscription', feeStrategy: 'economy', distinctCopies: true, keyAddress: BTC_JOB_ADDR,
  budgetUsd: 5, maxFeeRateSatVb: 25, clawbackTo: null, ...o,
})
const job = (o: Input = {}): Input => ({ format: 'vt-job/1', network: 'local', name: 'eth drain to the null address', message: MSG_A, chains: { eth: ethChain() }, ...o })

// The canonical def a valid input must normalize to (this encodes the contract's normalization).
function canonicalDef(input: Input): JobDef {
  const text = input.message as string | undefined
  const chains: Partial<Record<Chain, JobChainDef>> = {}
  for (const [c, raw] of Object.entries(input.chains as Record<string, Record<string, unknown>>)) {
    const chain = c as Chain
    const d = { ...raw } as unknown as JobChainDef
    d.publishMode ??= DEFAULT_PUBLISH_MODE[chain]
    d.feeStrategy ??= defaultFeeStrategy(d.mode)
    chains[chain] = d
  }
  return {
    format: 'vt-job/1', network: input.network as JobDef['network'], name: input.name as string,
    messageSha256: text !== undefined ? sha256Hex(text) : input.messageSha256 as string,
    messageBytes: text !== undefined ? enc.encode(text).length : input.messageBytes as number,
    chains,
    // CC-1: arweaveCopy is in the def only when true (false and absent are the same job, same id).
    ...(input.arweaveCopy === true ? { arweaveCopy: true as const } : {}),
  }
}

function jobFixtures(add: (p: string, c: string | Uint8Array) => void): { valid: Record<string, Input>; idOf: (n: string) => string; defOf: (n: string) => JobDef } {
  const valid: Record<string, Input> = {
    'eth-drain-null.json': job(),
    'sol-copies.json': job({ name: 'sol three copies', chains: { sol: solChain() } }),
    'btc-copies.json': job({ name: 'btc two copies (E7b)', chains: { btc: btcChain() } }),
    'btc-defaults.json': job({ name: 'btc defaults filled in', chains: { btc: (() => { const b = btcChain(); delete b.publishMode; delete b.feeStrategy; delete b.maxFeeRateSatVb; return b })() } }),
    'both-testnet.json': job({
      network: 'testnet', name: 'eth and sol on testnet',
      chains: {
        eth: ethChain({ mode: { copies: 2 }, publishMode: 'eth.calldata.self', feeStrategy: 'prompt', distinctCopies: false, budgetUsd: 2.5, maxTipGwei: 0.1, clawbackTo: ETH_B }),
        sol: solChain({ mode: 'drain', feeStrategy: 'passive', budgetUsd: 1000, maxCuPrice: 0, clawbackTo: null }),
      },
    }),
    'message-ref.json': (() => {
      const j = job({ name: 'message by digest', messageSha256: sha256Hex(SEALED_LIKE), messageBytes: enc.encode(SEALED_LIKE).length })
      delete j.message
      return j
    })(),
    // R73 defaults: publishMode → DEFAULT_PUBLISH_MODE[chain]; feeStrategy → passive (drain) / economy (copies).
    'defaults.json': (() => {
      const e = ethChain(), s = solChain()
      delete e.publishMode; delete e.feeStrategy; delete s.publishMode; delete s.feeStrategy
      return job({ name: 'defaults filled in', chains: { eth: e, sol: s } })
    })(),
    // CC-1: arweaveCopy false is the same job as eth-drain-null.json (same def, same id).
    'arweave-copy-false.json': job({ arweaveCopy: false }),
  }
  const expected: Record<string, { id: string; def: JobDef }> = {}
  for (const [f, input] of Object.entries(valid)) {
    add(`contract/fixtures/jobs/valid/${f}`, pretty(input))
    const def = canonicalDef(input)
    expected[f] = { id: jobIdOf(def), def }
  }
  add('contract/fixtures/jobs/valid/expected.json', pretty(expected))

  const lower = ETH_A.toLowerCase()
  if (lower === ETH_A) throw new Error('ETH_A has no mixed case')
  const invalid: Record<string, [Input, string]> = {
    'unknown-key-autoArm.json': [job({ autoArm: true }), 'job.unknown-key'],
    'format-v2.json': [job({ format: 'vt-job/2' }), 'job.format'],
    'network-missing.json': [(() => { const j = job(); delete j.network; return j })(), 'job.network-field'],
    'name-non-ascii.json': [job({ name: 'Café notes' }), 'job.name'],
    'name-65.json': [job({ name: 'n'.repeat(65) }), 'job.name'],
    'eth-address-lowercase.json': [job({ chains: { eth: ethChain({ keyAddress: lower }) } }), 'job.address'],
    'sol-address-31.json': [job({ chains: { sol: solChain({ keyAddress: solAddr('sol key short', 31) }) } }), 'job.address'],
    'budget-0.json': [job({ chains: { eth: ethChain({ budgetUsd: 0 }) } }), 'job.budget'],
    'budget-1000.01.json': [job({ chains: { eth: ethChain({ budgetUsd: 1000.01 }) } }), 'job.budget'],
    'budget-3.333.json': [job({ chains: { eth: ethChain({ budgetUsd: 3.333 }) } }), 'job.budget'],
    'tip-cap-0.05.json': [job({ chains: { eth: ethChain({ maxTipGwei: 0.05 }) } }), 'job.tip-cap'],
    'tip-cap-101.json': [job({ chains: { eth: ethChain({ maxTipGwei: 101 }) } }), 'job.tip-cap'],
    'cu-cap-2000001.json': [job({ chains: { sol: solChain({ maxCuPrice: 2_000_001 }) } }), 'job.cu-cap'],
    'copies-0.json': [job({ chains: { eth: ethChain({ mode: { copies: 0 } }) } }), 'job.mode'],
    'copies-10001.json': [job({ chains: { eth: ethChain({ mode: { copies: 10_001 } }) } }), 'job.mode'],
    'clawback-null-address.json': [job({ chains: { eth: ethChain({ clawbackTo: NULL_ETH }) } }), 'job.clawback'],
    'clawback-self.json': [job({ chains: { eth: ethChain({ clawbackTo: ETH_A }) } }), 'job.clawback'],
    'field-chain-tip-on-sol.json': [job({ chains: { sol: solChain({ maxTipGwei: 3 }) } }), 'job.field-chain'],
    'recipient-legacy.json': [job({ chains: { eth: ethChain({ recipient: 'null' }) } }), 'job.unknown-key'],
    'publish-mode-wrong-chain.json': [job({ chains: { sol: solChain({ publishMode: 'eth.calldata.null' }) } }), 'job.publish-mode'],
    'publish-mode-unknown.json': [job({ chains: { eth: ethChain({ publishMode: 'eth.calldata.zero' }) } }), 'job.publish-mode'],
    'publish-mode-reserved.json': [job({ chains: { eth: ethChain({ publishMode: 'eth.sstore2' }) } }), 'job.publish-mode-unavailable'],
    'publish-mode-dropped.json': [job({ chains: { eth: ethChain({ publishMode: 'eth.blob' }) } }), 'job.publish-mode'],
    'arweave-copy-reserved.json': [job({ arweaveCopy: true }), 'job.publish-mode-unavailable'],
    'chain-btc-unsupported.json': [job({ network: 'testnet', chains: { btc: btcChain() } }), 'job.chain-unsupported'],
    'chain-btc-mainnet.json': [job({ network: 'mainnet', chains: { btc: btcChain() } }), 'job.chain-unsupported'],
    // PF-S fix round 1 (N-6): a NEW mainnet job names clawbackTo on each eth / sol chain
    'clawback-required-mainnet-eth.json': [job({ network: 'mainnet', chains: { eth: ethChain({ clawbackTo: null }) } }), 'job.clawback-required'],
    'clawback-required-mainnet-sol.json': [job({ network: 'mainnet', chains: { sol: solChain({ clawbackTo: null }) } }), 'job.clawback-required'],
    'btc-drain.json': [job({ chains: { btc: btcChain({ mode: 'drain' }) } }), 'job.mode'],
    'btc-fee-rate-0.json': [job({ chains: { btc: btcChain({ maxFeeRateSatVb: 0 }) } }), 'job.fee-rate'],
    'btc-fee-rate-501.json': [job({ chains: { btc: btcChain({ maxFeeRateSatVb: 501 }) } }), 'job.fee-rate'],
    'btc-fee-rate-1.5.json': [job({ chains: { btc: btcChain({ maxFeeRateSatVb: 1.5 }) } }), 'job.fee-rate'],
    'btc-clawback.json': [job({ chains: { btc: btcChain({ clawbackTo: BTC_JOB_ADDR }) } }), 'job.clawback'],
    'btc-address-eth.json': [job({ chains: { btc: btcChain({ keyAddress: ETH_A }) } }), 'job.address'],
    'btc-address-upper.json': [job({ chains: { btc: btcChain({ keyAddress: BTC_JOB_ADDR.toUpperCase() }) } }), 'job.address'],
    'btc-publish-mode-wrong-chain.json': [job({ chains: { btc: btcChain({ publishMode: 'sol.memo' }) } }), 'job.publish-mode'],
    'btc-tip-field.json': [job({ chains: { btc: btcChain({ maxTipGwei: 3 }) } }), 'job.field-chain'],
    'fee-rate-on-eth.json': [job({ chains: { eth: ethChain({ maxFeeRateSatVb: 5 }) } }), 'job.field-chain'],
    'text-kind-timelocked-reserved.json': [job({ textKind: 'timelocked' }), 'job.publish-mode-unavailable'],
    'text-kind-unknown.json': [job({ textKind: 'sealed' }), 'job.text-kind'],
    'arweave-copy-not-boolean.json': [job({ arweaveCopy: 'yes' }), 'job.arweave-copy'],
    'fee-strategy-unknown.json': [job({ chains: { eth: ethChain({ feeStrategy: 'fast' }) } }), 'job.fee-strategy'],
    'message-and-sha.json': [job({ messageSha256: sha256Hex(MSG_A), messageBytes: enc.encode(MSG_A).length }), 'job.message-source'],
    'message-file.json': [(() => { const j = job({ messageFile: 'message.txt' }); delete j.message; return j })(), 'job.message-file'],
    'name-hex64.json': [job({ name: hex64('name looks like a key') }), 'job.key-like'],
    'name-ip.json': [job({ name: `node ${CANARY}` }), 'job.ip-like'],
  }
  const exp: Record<string, string> = {}
  for (const [f, [input, guard]] of Object.entries(invalid)) {
    add(`contract/fixtures/jobs/invalid/${f}`, pretty(input))
    exp[f] = guard
  }
  add('contract/fixtures/jobs/invalid/expected.json', pretty(exp))
  return { valid, idOf: (n) => expected[n].id, defOf: (n) => expected[n].def }
}

// ---------------------------------------------------------------- the JSON Schema (JobInput)

export function buildSchema(): Record<string, unknown> {
  const pm = (c: ContractChain) => ({ enum: publishModesFor(c), description: 'contracts/publish.ts; default DEFAULT_PUBLISH_MODE; reserved modes pass the schema and are refused by the validator (job.publish-mode-unavailable)' })
  const common = {
    mode: { $ref: '#/$defs/mode' },
    feeStrategy: { enum: [...FEE_STRATEGIES], description: 'default: passive for drain, economy for copies' },
    distinctCopies: { type: 'boolean' },
    budgetUsd: { type: 'number', exclusiveMinimum: 0, maximum: 1000, description: 'at most 2 decimals (checked by the validator, job.budget)' },
  }
  const required = ['mode', 'distinctCopies', 'keyAddress', 'budgetUsd', 'clawbackTo']
  const sources = ['message', 'messageFile', 'messageSha256']
  const only = (k: string) => ({ required: k === 'messageSha256' ? ['messageSha256', 'messageBytes'] : [k], not: { anyOf: sources.filter((s) => s !== k).map((s) => ({ required: [s] })).concat(k === 'messageSha256' ? [] : [{ required: ['messageBytes'] }]) } })
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://vault-timelock.invalid/schemas/vt-job-1.schema.json',
    title: 'vt-job/1 (JobInput)',
    description: `Structural rules only; the validator (normalizeJob) adds EIP-55 / base58 checks, 2-decimal budgets, the clawback rules, key-like and IP-like refusals, reserved modes (and the reserved Arweave copy) and network binding. Publish modes: ${PUBLISH_MODES_VERSION}. Generated by packages/core/contract/gen-fixtures.ts.`,
    type: 'object',
    additionalProperties: false,
    required: ['format', 'network', 'name', 'chains'],
    properties: {
      format: { const: 'vt-job/1' },
      network: { enum: ['local', 'testnet', 'mainnet'] },
      name: { type: 'string', pattern: '^[\\x20-\\x7e]{1,64}$' },
      message: { type: 'string', minLength: 1 },
      messageFile: { type: 'string', minLength: 1, description: 'vt only: a path relative to the job file; never posted to the API (job.message-file)' },
      messageSha256: { type: 'string', pattern: '^[0-9a-f]{64}$' },
      messageBytes: { type: 'integer', minimum: 1, maximum: MESSAGE_MAX },
      arweaveCopy: { type: 'boolean', description: 'contracts/publish.ts ARWEAVE_COPY (CC-1); optional, false = absent; true is reserved and refused by the validator (job.publish-mode-unavailable)' },
      textKind: { enum: ['plain', 'timelocked'], description: 'CC-7; optional, default (and absent) plain; timelocked is reserved and refused by the validator (job.publish-mode-unavailable) until E6/W7; not part of the stored JobDef' },
      chains: {
        type: 'object', additionalProperties: false, minProperties: 1,
        properties: { eth: { $ref: '#/$defs/ethChain' }, sol: { $ref: '#/$defs/solChain' }, btc: { $ref: '#/$defs/btcChain' } },
      },
    },
    oneOf: sources.map(only),
    $defs: {
      mode: {
        oneOf: [
          { const: 'drain' },
          { type: 'object', additionalProperties: false, required: ['copies'], properties: { copies: { type: 'integer', minimum: 1, maximum: 10_000 } } },
        ],
      },
      ethChain: {
        type: 'object', additionalProperties: false, required,
        properties: {
          ...common, publishMode: pm('eth'),
          keyAddress: { type: 'string', pattern: '^0x[0-9a-fA-F]{40}$', description: 'EIP-55 checksummed (job.address)' },
          maxTipGwei: { type: 'number', minimum: 0.1, maximum: 100 },
          clawbackTo: { oneOf: [{ type: 'null' }, { type: 'string', pattern: '^0x[0-9a-fA-F]{40}$' }], description: 'PF-S fix round 1 (N-6): optional (null) in a stored job and off mainnet, but REQUIRED (an address) when a mainnet job is created (job.clawback-required); on mainnet the API refuses a claw-back to any other address' },
        },
      },
      solChain: {
        type: 'object', additionalProperties: false, required,
        properties: {
          ...common, publishMode: pm('sol'),
          keyAddress: { type: 'string', pattern: '^[1-9A-HJ-NP-Za-km-z]{32,44}$', description: 'canonical base58 of 32 bytes (job.address)' },
          maxCuPrice: { type: 'integer', minimum: 0, maximum: 2_000_000 },
          clawbackTo: { oneOf: [{ type: 'null' }, { type: 'string', pattern: '^[1-9A-HJ-NP-Za-km-z]{32,44}$' }], description: 'PF-S fix round 1 (N-6): optional (null) in a stored job and off mainnet, but REQUIRED (an address) when a mainnet job is created (job.clawback-required); on mainnet the API refuses a claw-back to any other address' },
        },
      },
      btcChain: {
        type: 'object', additionalProperties: false, required,
        properties: {
          ...common, publishMode: pm('btc'),
          keyAddress: { type: 'string', pattern: '^bcrt1q[02-9ac-hj-np-z]{38}$', description: 'a lower-case bech32 p2wpkh address of the local (regtest) network (job.address)' },
          maxFeeRateSatVb: { type: 'integer', minimum: 1, maximum: 500, description: 'CC-12: the highest fee rate (sat/vB) the lane pays (job.fee-rate). CC-14: optional here (stored jobs keep the 500 sat/vB fallback) but REQUIRED at creation for btc chains (job.btc-fee-ceiling)' },
          clawbackTo: { type: 'null', description: 'there is no btc claw-back (job.clawback)' },
        },
      },
    },
  }
}

// ---------------------------------------------------------------- journals

class Journal {
  readonly lines: string[] = []
  readonly events: JournalEvent[] = []
  add(at: number, chain: Chain | null, by: JournalEvent['by'], gen: number | null, type: JournalEvent['type'], data: Record<string, unknown>): JournalEvent {
    const prev = this.lines.length === 0 ? '' : sha256Hex(this.lines[this.lines.length - 1])
    const e: JournalEvent = { v: 1, seq: this.lines.length, at, prev, chain, by, gen, type, data }
    this.lines.push(JSON.stringify(e))
    this.events.push(e)
    return e
  }
  text(): string { return `${this.lines.join('\n')}\n` }
  get last(): JournalEvent { return this.events[this.events.length - 1] }
}

const CAP: Record<Chain, ArmCap> = {
  eth: { nativeCap: '4000000000000000', usd: 10, priceAt: T0 + 9_000, overCap: false, planned: '0.004' },
  sol: { nativeCap: '70000000', usd: 10, priceAt: T0 + 9_000, overCap: false, planned: '0.07' },
}
const FEE_ETH = '25000300000000'
const ethIntent = (nonce: number, tip: string, n: number, to = NULL_ETH): EthIntent =>
  ({ nonce, tip, maxFee: String(2_000_000_000n + BigInt(tip)), gas: String(ethDataGas(n, { amsterdam: false, toSelf: to !== NULL_ETH })), to })
const solIntent = (label: string, lvbh: number, cuPrice: number, rung: number | null, fee: string): SolIntent =>
  ({ blockhash: blockhash(label), lastValidBlockHeight: lvbh, cuPrice, cuLimit: 30_000, rung, fee })

interface Ctx { j: Journal; def: JobDef; chain: Chain; holder: 'browser' | 'cli'; gen: number; t: number }
const tick = (x: Ctx, ms = 1_000): number => (x.t += ms)
const ex = (x: Ctx, type: JournalEvent['type'], data: Record<string, unknown>): JournalEvent => x.j.add(tick(x), x.chain, x.holder, x.gen, type, data)
const api = (x: Ctx, type: JournalEvent['type'], data: Record<string, unknown>, chain: Chain | null = x.chain, gen: number | null = null): JournalEvent =>
  x.j.add(tick(x), chain, 'api', gen, type, data)

function start(def: JobDef, chain: Chain): Ctx {
  const j = new Journal()
  j.add(T0, null, 'api', null, 'created', { jobId: jobIdOf(def), defSha256: sha256Hex(canonicalJson(def)) })
  return { j, def, chain, holder: 'browser', gen: 1, t: T0 }
}
function ready(x: Ctx): void {
  api(x, 'lease-acquired', { gen: x.gen, holder: x.holder, ttlMs: LEASE_TTL_MS }, x.chain, x.gen)
  ex(x, 'key-loaded', { address: x.def.chains[x.chain]!.keyAddress })
  ex(x, 'funds', { balance: x.chain === 'eth' ? '50000000000000000' : '500000000', affordable: true, nextCopyCost: x.chain === 'eth' ? FEE_ETH : '25000' })
}
function arm(x: Ctx, order: Chain[]): ArmRecord {
  const armedAt = tick(x, 6_000)
  const record: ArmRecord = {
    armedAt, releaseAt: armedAt + 15_000, countdownSec: 15,
    schedule: { order, offsetSec: Object.fromEntries(order.map((c, i) => [c, i === 0 ? 0 : 7])) },
    caps: Object.fromEntries(order.map((c) => [c, CAP[c]])), sources: {},
  }
  x.j.add(armedAt, null, 'api', null, 'armed', record as unknown as Record<string, unknown>)
  x.t = record.releaseAt
  return record
}
interface TxSpec { txId: string; copy: number; part: number; parts: number; attempt: number; replaces?: string | null; eth?: EthIntent; sol?: SolIntent }
function intent(x: Ctx, s: TxSpec): void {
  const data: Record<string, unknown> = {
    txId: s.txId, copy: s.copy, part: s.part, parts: s.parts, attempt: s.attempt, replaces: s.replaces ?? null,
    rawSha256: hex64(`raw:${s.txId}`), payloadSha256: hex64(`payload:${s.copy}:${s.part}`), reserved: x.chain === 'eth' ? '50000000000000' : '10000',
  }
  if (s.eth !== undefined) data.eth = s.eth
  if (s.sol !== undefined) data.sol = s.sol
  ex(x, 'intent', data)
}
const sent = (x: Ctx, txId: string, outcome: 'accepted' | 'unknown' | 'rejected', reason: string | null = null): void => { ex(x, 'sent', { txId, outcome, reason }) }
const included = (x: Ctx, s: TxSpec, block: string, fee: string): void => { ex(x, 'included', { txId: s.txId, copy: s.copy, part: s.part, attempt: s.attempt, block, fee, ms: 12_000 }) }
const readback = (x: Ctx, txId: string, ok = true): void => { ex(x, 'readback', { txId, ok, detail: ok ? 'payload bytes match' : 'payload bytes differ' }) }
const reassembled = (x: Ctx, copy: number): void => { ex(x, 'reassembled', { copy, ok: true, sha256: x.def.messageSha256 }) }
// One single-part ETH copy: intent / sent / included / readback (+ reassembled).
function ethCopy(x: Ctx, copy: number, nonce: number): TxSpec {
  const s: TxSpec = { txId: ethTx(`copy ${copy}`), copy, part: 1, parts: 1, attempt: 1, eth: ethIntent(nonce, '12000', 60) }
  intent(x, s); sent(x, s.txId, 'accepted'); included(x, s, String(100 + copy), FEE_ETH); readback(x, s.txId); reassembled(x, copy)
  return s
}

// Expected-state builders (plain data; every value below is the contract).
const cs = (o: Partial<ChainState>): ChainState => ({
  phase: 'AWAITING_KEY', reason: null, address: null, copy: null, attempt: null, copiesIncluded: 0, reassembled: [],
  spent: '0', txs: [], openIntents: [], resume: null, stopRequested: false, clawback: null, ...o,
})
const js = (o: Partial<JobState>): JobState => ({ phase: 'DEFINED', armed: null, releaseAt: null, chains: {}, seq: 0, corrupt: null, ...o })
const att = (s: TxSpec, gen: number, state: AttemptView['state']): AttemptView =>
  ({ txId: s.txId, gen, state, ...(s.eth !== undefined ? { eth: s.eth } : {}), ...(s.sol !== undefined ? { sol: s.sol } : {}) })
const tx = (s: TxSpec, attempts: AttemptView[], o: Partial<TxView> = {}): TxView =>
  ({ copy: s.copy, part: s.part, parts: s.parts, attempts, state: 'open', landedId: null, block: null, fee: null, readback: null, ...o })
const done = (s: TxSpec, block: string, fee: string, gen = 1): TxView => tx(s, [att(s, gen, 'included')], { state: 'included', landedId: s.txId, block, fee, readback: true })

interface Vector { name: string; description: string; def: JobDef; j: Journal; state: JobState }

function journalVectors(defs: Record<string, JobDef>): Vector[] {
  const out: Vector[] = []
  const push = (name: string, description: string, x: Ctx, state: Omit<JobState, 'seq'>): void => {
    out.push({ name, description, def: x.def, j: x.j, state: { ...state, seq: x.j.last.seq } })
  }
  const E = defs.ethDrain, EC = defs.ethCopies1, S1 = defs.solCopies1, S2 = defs.solCopies2, B = defs.both
  const addr = (d: JobDef, c: Chain): string => d.chains[c]!.keyAddress
  let x: Ctx, rec: ArmRecord

  x = start(E, 'eth')
  push('01-created', 'created only: every chain AWAITING_KEY, job DEFINED', x, js({ chains: { eth: cs({}) } }))

  x = start(E, 'eth'); ready(x)
  push('02-ready', 'lease, key-loaded, funds affordable: READY', x, js({ chains: { eth: cs({ phase: 'READY', address: addr(E, 'eth') }) } }))

  x = start(E, 'eth'); ready(x); rec = arm(x, ['eth'])
  push('03-armed', 'armed: chain ARMED, job ARMED, releaseAt set', x, js({ phase: 'ARMED', armed: rec, releaseAt: rec.releaseAt, chains: { eth: cs({ phase: 'ARMED', address: addr(E, 'eth') }) } }))

  {
    x = start(E, 'eth'); ready(x); rec = arm(x, ['eth'])
    const t1: TxSpec = { txId: ethTx('t1'), copy: 1, part: 1, parts: 1, attempt: 1, eth: ethIntent(0, '12000', 60) }
    intent(x, t1)
    push('04-intent', 'one open intent: RUNNING, openIntents [t1], resume at copy 1 part 1', x, js({
      phase: 'RUNNING', armed: rec, releaseAt: rec.releaseAt,
      chains: { eth: cs({ phase: 'RUNNING', address: addr(E, 'eth'), copy: 1, attempt: 1, txs: [tx(t1, [att(t1, 1, 'intent')])], openIntents: [t1.txId], resume: { copy: 1, nextPart: 1 } }) },
    }))
  }

  for (const close of [false, true]) {
    x = start(EC, 'eth'); ready(x); rec = arm(x, ['eth'])
    const s = ethCopy(x, 1, 0)
    ex(x, 'copies-done', { copies: 1 })
    if (close) api(x, 'close', { chain: 'eth' })
    const chain = cs({
      phase: close ? 'DONE' : 'COPIES_DONE', address: addr(EC, 'eth'), copy: 1, attempt: 1, copiesIncluded: 1,
      reassembled: [{ copy: 1, ok: true }], spent: FEE_ETH, txs: [done(s, '101', FEE_ETH)],
    })
    if (close) push('05b-closed', 'copies 1 settled, then close: DONE; job DONE', x, js({ phase: 'DONE', armed: rec, releaseAt: rec.releaseAt, chains: { eth: chain } }))
    else push('05a-copies-done', 'copies 1: intent, sent, included, readback, reassembled, copies-done: COPIES_DONE; job stays ARMED (settled, not closed)', x, js({ phase: 'ARMED', armed: rec, releaseAt: rec.releaseAt, chains: { eth: chain } }))
  }

  {
    x = start(E, 'eth'); ready(x); rec = arm(x, ['eth'])
    const a1: TxSpec = { txId: ethTx('a1'), copy: 1, part: 1, parts: 1, attempt: 1, eth: ethIntent(0, '12000', 60) }
    const a2: TxSpec = { txId: ethTx('a2'), copy: 1, part: 1, parts: 1, attempt: 2, replaces: a1.txId, eth: ethIntent(0, '13501', 60) }
    intent(x, a1); sent(x, a1.txId, 'accepted'); intent(x, a2); sent(x, a2.txId, 'accepted')
    ex(x, 'replaced', { txId: a2.txId, prevId: a1.txId, reason: 'stall: 3 blocks without a receipt' })
    included(x, a2, '205', FEE_ETH)
    push('06-eth-replacement', 'same-nonce replacement: a2 included, a1 superseded; no readback yet so resume stays at part 1', x, js({
      phase: 'RUNNING', armed: rec, releaseAt: rec.releaseAt,
      chains: { eth: cs({
        phase: 'RUNNING', address: addr(E, 'eth'), copy: 1, attempt: 2, spent: FEE_ETH,
        txs: [tx(a1, [att(a1, 1, 'superseded'), att(a2, 1, 'included')], { state: 'included', landedId: a2.txId, block: '205', fee: FEE_ETH })],
        resume: { copy: 1, nextPart: 1 },
      }) },
    }))
  }

  {
    x = start(S1, 'sol'); ready(x); rec = arm(x, ['sol'])
    const s1: TxSpec = { txId: solSig('s1'), copy: 1, part: 1, parts: 1, attempt: 1, sol: solIntent('s1', 1_000, 0, null, '5000') }
    const s2: TxSpec = { txId: solSig('s2'), copy: 1, part: 1, parts: 1, attempt: 2, replaces: s1.txId, sol: solIntent('s2', 1_200, 151_992, 1, '9560') }
    intent(x, s1); sent(x, s1.txId, 'accepted')
    ex(x, 'reconcile', { txId: s1.txId, outcome: 'expired' })
    intent(x, s2); sent(x, s2.txId, 'accepted'); included(x, s2, '3456', '9560'); readback(x, s2.txId)
    push('07-sol-expired', 'SOL s1 proven expired (reconcile), s2 re-signed and included with readback: copy complete', x, js({
      phase: 'RUNNING', armed: rec, releaseAt: rec.releaseAt,
      chains: { sol: cs({
        phase: 'RUNNING', address: addr(S1, 'sol'), copy: 1, attempt: 2, copiesIncluded: 1, spent: '9560',
        txs: [tx(s1, [att(s1, 1, 'expired'), att(s2, 1, 'included')], { state: 'included', landedId: s2.txId, block: '3456', fee: '9560', readback: true })],
      }) },
    }))
  }

  {
    x = start(E, 'eth'); ready(x); rec = arm(x, ['eth'])
    const t1: TxSpec = { txId: ethTx('t1'), copy: 1, part: 1, parts: 1, attempt: 1, eth: ethIntent(0, '12000', 60) }
    intent(x, t1); sent(x, t1.txId, 'accepted')
    api(x, 'lease-expired', { gen: 1 }, 'eth', 1)
    x.holder = 'cli'; x.gen = 2
    api(x, 'lease-acquired', { gen: 2, holder: 'cli', ttlMs: LEASE_TTL_MS }, 'eth', 2)
    push('08-takeover', 'gen 1 intent sent, lease expired, gen 2 acquired by cli: t1 stays open until reconciled', x, js({
      phase: 'RUNNING', armed: rec, releaseAt: rec.releaseAt,
      chains: { eth: cs({ phase: 'RUNNING', address: addr(E, 'eth'), copy: 1, attempt: 1, txs: [tx(t1, [att(t1, 1, 'sent')])], openIntents: [t1.txId], resume: { copy: 1, nextPart: 1 } }) },
    }))
  }

  for (const resolved of [false, true]) {
    x = start(E, 'eth'); ready(x); rec = arm(x, ['eth'])
    const t1: TxSpec = { txId: ethTx('t1'), copy: 1, part: 1, parts: 1, attempt: 1, eth: ethIntent(0, '12000', 60) }
    intent(x, t1); sent(x, t1.txId, 'unknown', 'no reply from the relay')
    const why = 'outcome unknowable: nonce 0 not consumed and the tx is not found'
    ex(x, 'stuck', { txId: t1.txId, reason: why })
    if (resolved) api(x, 'resolved', { txId: t1.txId, action: 'mark-done', typed: null })
    const chain = resolved
      ? cs({ phase: 'RUNNING', address: addr(E, 'eth'), copy: 1, attempt: 1, spent: String(BigInt(t1.eth!.gas) * BigInt(t1.eth!.maxFee)), txs: [tx(t1, [att(t1, 1, 'resolved-done')], { state: 'included', landedId: t1.txId })], resume: { copy: 1, nextPart: 1 } })
      : cs({ phase: 'STUCK', reason: why, address: addr(E, 'eth'), copy: 1, attempt: 1, txs: [tx(t1, [att(t1, 1, 'unknown')], { state: 'stuck' })], openIntents: [t1.txId], resume: { copy: 1, nextPart: 1 }, stuckBase: 'RUNNING' })   // PF-S fix round 6
    if (resolved) push('09b-resolved', 'stuck, then resolved mark-done: RUNNING; the attempt counts as landed (no block, fee or readback); spent counts its worst case, gas × maxFee (CC-2a: the journal has no fee, never 0)', x, js({ phase: 'RUNNING', armed: rec, releaseAt: rec.releaseAt, chains: { eth: chain } }))
    else push('09a-stuck', 'sent outcome unknown, then stuck: STUCK overrides RUNNING; the intent stays open', x, js({ phase: 'RUNNING', armed: rec, releaseAt: rec.releaseAt, chains: { eth: chain } }))
  }

  for (const resumed of [false, true]) {
    x = start(E, 'eth'); ready(x); rec = arm(x, ['eth'])
    const s = ethCopy(x, 1, 0)
    const why = 'tip cap reached (3 gwei)'
    ex(x, 'paused', { reason: why })
    if (resumed) { api(x, 'resume-requested', { chain: 'eth', tipCapGwei: '5' }); ex(x, 'resumed', { reason: 'tip cap raised to 5 gwei' }) }
    const chain = cs({
      phase: resumed ? 'RUNNING' : 'PAUSED', reason: resumed ? null : why, address: addr(E, 'eth'), copy: 1, attempt: 1,
      copiesIncluded: 1, reassembled: [{ copy: 1, ok: true }], spent: FEE_ETH, txs: [done(s, '101', FEE_ETH)],
    })
    push(resumed ? '10b-resumed' : '10a-paused', resumed ? 'paused, resume-requested, resumed: RUNNING' : 'drain copy 1 complete, then paused at the tip cap: PAUSED', x,
      js({ phase: 'RUNNING', armed: rec, releaseAt: rec.releaseAt, chains: { eth: chain } }))
  }

  for (const claw of [false, true]) {
    x = start(E, 'eth'); ready(x); rec = arm(x, ['eth'])
    const s = ethCopy(x, 1, 0)
    ex(x, 'drained', { balance: '1200000000000', nextCost: FEE_ETH, copy: 2 })
    const base = { address: addr(E, 'eth'), copy: 1, attempt: 1, copiesIncluded: 1, reassembled: [{ copy: 1, ok: true }], txs: [done(s, '101', FEE_ETH)] }
    if (!claw) {
      push('11-drained', 'drain: copy 1 complete, the next copy unaffordable (drained.copy = that next copy): DRAINED; job ARMED', x,
        js({ phase: 'ARMED', armed: rec, releaseAt: rec.releaseAt, chains: { eth: cs({ ...base, phase: 'DRAINED', spent: FEE_ETH }) } }))
      continue
    }
    const c1 = ethTx('claw-back')
    const value = '1179000000000', fee = '21000000000'
    ex(x, 'clawback-intent', { txId: c1, to: ETH_B, value, rawSha256: hex64(`raw:${c1}`), eth: { nonce: 1, tip: '12000', maxFee: '2000012000', gas: '21000', to: ETH_B } })
    ex(x, 'clawback-sent', { txId: c1, outcome: 'accepted' })
    ex(x, 'clawback-included', { txId: c1, value, fee })
    ex(x, 'clawback-readback', { txId: c1, ok: true, destReceived: value, laneBalance: '0' })
    push('12-clawback', 'drained, then claw-back intent/sent/included/readback: CLAWED_BACK; spent includes the claw-back fee; job DONE', x,
      js({ phase: 'DONE', armed: rec, releaseAt: rec.releaseAt, chains: { eth: cs({ ...base, phase: 'CLAWED_BACK', spent: String(BigInt(FEE_ETH) + BigInt(fee)), clawback: { txId: c1, to: ETH_B, value, ok: true, landed: true } }) } }))
  }

  {
    x = start(S2, 'sol'); ready(x); rec = arm(x, ['sol'])
    const txs: TxView[] = []
    const fee = '5000'
    for (const copy of [1, 2]) {
      ex(x, 'copy-built', { copy, parts: 5, bytes: [1010, 1010, 1010, 1010, 340], tight: false, level: 0 })
      for (let part = 1; part <= (copy === 1 ? 5 : 4); part++) {
        const s: TxSpec = { txId: solSig(`c${copy}p${part}`), copy, part, parts: 5, attempt: 1, sol: solIntent(`c${copy}p${part}`, 2_000 + copy * 10 + part, 0, null, fee) }
        intent(x, s)
        if (copy === 2 && part === 4) { txs.push(tx(s, [att(s, 1, 'intent')])); break }
        sent(x, s.txId, 'accepted'); included(x, s, String(5_000 + copy * 10 + part), fee); readback(x, s.txId)
        txs.push(done(s, String(5_000 + copy * 10 + part), fee))
      }
      if (copy === 1) reassembled(x, 1)
    }
    push('13-resume-part', 'R72: copy 1 (5 parts) complete; copy 2 parts 1-3 included + read back, part 4 intent open: resume {copy 2, nextPart 4}', x, js({
      phase: 'RUNNING', armed: rec, releaseAt: rec.releaseAt,
      chains: { sol: cs({
        phase: 'RUNNING', address: addr(S2, 'sol'), copy: 2, attempt: 1, copiesIncluded: 1, reassembled: [{ copy: 1, ok: true }],
        spent: String(8 * Number(fee)), txs, openIntents: [solSig('c2p4')], resume: { copy: 2, nextPart: 4 },
      }) },
    }))
  }

  {
    x = start(E, 'eth'); ready(x); rec = arm(x, ['eth'])
    api(x, 'stop-requested', { chain: 'eth' })
    const why = 'stop requested before any intent'
    api(x, 'stopped', { reason: why, code: 'operator-stop' })   // R79b: every journaled stop carries its code (contracts/stop.ts)
    push('14-stopped', 'stop-requested before any intent, the API journals stopped (code operator-stop): STOPPED, resumable; a STOPPED chain is not terminal → job ARMED (final round F18-2; the key stays busy until close)', x,
      js({ phase: 'ARMED', armed: rec, releaseAt: rec.releaseAt, chains: { eth: cs({ phase: 'STOPPED', reason: why, address: addr(E, 'eth'), stopRequested: true, stopLatched: true, stopCode: 'operator-stop', stopClass: 'resumable' }) } }))   // PF-S fix round 5: the stop latch; R79b: its code and class
  }

  for (const finish of [false, true]) {
    x = start(B, 'eth'); ready(x); rec = arm(x, ['eth'])
    const sol = cs({ phase: 'SKIPPED', reason: 'not armed' })
    if (!finish) {
      push('15a-skipped', 'job with eth + sol, armed with eth only: sol SKIPPED (terminal, no funds touched); job ARMED', x,
        js({ phase: 'ARMED', armed: rec, releaseAt: rec.releaseAt, chains: { eth: cs({ phase: 'ARMED', address: addr(B, 'eth') }), sol } }))
      continue
    }
    const s = ethCopy(x, 1, 0)
    ex(x, 'copies-done', { copies: 1 })
    api(x, 'close', { chain: 'eth' })
    push('15b-skipped-done', 'eth copies 1 done and closed, sol SKIPPED: job DONE', x, js({
      phase: 'DONE', armed: rec, releaseAt: rec.releaseAt,
      chains: { eth: cs({ phase: 'DONE', address: addr(B, 'eth'), copy: 1, attempt: 1, copiesIncluded: 1, reassembled: [{ copy: 1, ok: true }], spent: FEE_ETH, txs: [done(s, '101', FEE_ETH)] }), sol },
    }))
  }

  // CC-2a: chain evidence wins (E2 re-review D-1). s1's expiry was journaled and s2 re-signed; then s1 is found landed.
  {
    x = start(S1, 'sol'); ready(x); rec = arm(x, ['sol'])
    const s1: TxSpec = { txId: solSig('late s1'), copy: 1, part: 1, parts: 1, attempt: 1, sol: solIntent('late s1', 1_000, 0, null, '5000') }
    const s2: TxSpec = { txId: solSig('late s2'), copy: 1, part: 1, parts: 1, attempt: 2, replaces: s1.txId, sol: solIntent('late s2', 1_200, 0, null, '5000') }
    intent(x, s1); sent(x, s1.txId, 'accepted')
    ex(x, 'reconcile', { txId: s1.txId, outcome: 'expired' })
    intent(x, s2); sent(x, s2.txId, 'accepted')
    included(x, s1, '3400', '5000'); readback(x, s1.txId)
    push('16-sol-late-landing', 'CC-2a chain evidence wins: s1 journaled expired, s2 re-signed, then s1 included: s1 lands, s2 superseded, s1\'s fee spent, the part is complete (never sent again)', x, js({
      phase: 'RUNNING', armed: rec, releaseAt: rec.releaseAt,
      chains: { sol: cs({
        phase: 'RUNNING', address: addr(S1, 'sol'), copy: 1, attempt: 2, copiesIncluded: 1, spent: '5000',
        txs: [tx(s1, [att(s1, 1, 'included'), att(s2, 1, 'superseded')], { state: 'included', landedId: s1.txId, block: '3400', fee: '5000', readback: true })],
      }) },
    }))
  }

  // CC-2a: the claw-back family. Each variant: eth drain copy 1, drained, then claw-back members.
  const clawBase = (): { x: Ctx; rec: ArmRecord; base: Partial<ChainState> } => {
    const x = start(E, 'eth'); ready(x); const rec = arm(x, ['eth'])
    const s = ethCopy(x, 1, 0)
    ex(x, 'drained', { balance: '1200000000000', nextCost: FEE_ETH, copy: 2 })
    return { x, rec, base: { address: addr(E, 'eth'), copy: 1, attempt: 1, copiesIncluded: 1, reassembled: [{ copy: 1, ok: true }], txs: [done(s, '101', FEE_ETH)] } }
  }
  const clawIntent = (x: Ctx, txId: string, value: string, tip: string, maxFee: string): void => {
    ex(x, 'clawback-intent', { txId, to: ETH_B, value, rawSha256: hex64(`raw:${txId}`), eth: { nonce: 1, tip, maxFee, gas: '21000', to: ETH_B } })
  }
  {
    const { x: cx, rec: crec, base } = clawBase()
    const c1 = ethTx('claw c1'), c2 = ethTx('claw c2'), v1 = '1158000000000', v2 = '1152750000000', fee = '42000000000'
    clawIntent(cx, c1, v1, '1000000000', '2000000000'); ex(cx, 'clawback-sent', { txId: c1, outcome: 'unknown' })
    clawIntent(cx, c2, v2, '1125000001', '2250000001'); ex(cx, 'clawback-sent', { txId: c2, outcome: 'accepted' })
    ex(cx, 'clawback-included', { txId: c1, value: v1, fee })
    push('17a-clawback-bump-earlier-lands', 'CC-2a family: claw-back c1, then its same-nonce bump c2; c1 lands: the claw-back shows c1 (its value), landed, CLAWED_BACK; c2 closed; job DONE', cx,
      js({ phase: 'DONE', armed: crec, releaseAt: crec.releaseAt, chains: { eth: cs({ ...base, phase: 'CLAWED_BACK', spent: String(BigInt(FEE_ETH) + BigInt(fee)), clawback: { txId: c1, to: ETH_B, value: v1, ok: true, landed: true } }) } }))
  }
  {
    const { x: cx, rec: crec, base } = clawBase()
    const c1 = ethTx('claw dead c1'), c2 = ethTx('claw dead c2'), v1 = '1158000000000', v2 = '1152750000000'
    clawIntent(cx, c1, v1, '1000000000', '2000000000'); ex(cx, 'clawback-sent', { txId: c1, outcome: 'unknown' })
    clawIntent(cx, c2, v2, '1125000001', '2250000001'); ex(cx, 'clawback-sent', { txId: c2, outcome: 'unknown' })
    ex(cx, 'reconcile', { txId: c1, outcome: 'nonce-consumed' })
    ex(cx, 'stuck', { txId: c2, reason: 'nonce 1 is used and no receipt of this claw-back was found yet' })
    api(cx, 'resolved', { txId: c2, action: 'mark-failed', typed: null })
    push('17b-clawback-all-dead', 'CC-2a family (E2 re-review D-2): c1 reconciled nonce-consumed, c2 stuck (STUCK) then resolved mark-failed by the operator: every member dead and none landed → the claw-back fails by itself (ok false, back to DRAINED, nothing open)', cx,
      js({ phase: 'ARMED', armed: crec, releaseAt: crec.releaseAt, chains: { eth: cs({ ...base, phase: 'DRAINED', spent: FEE_ETH, clawback: { txId: c2, to: ETH_B, value: v2, ok: false, landed: false } }) } }))
  }
  {
    const { x: cx, rec: crec, base } = clawBase()
    const c1 = ethTx('claw failed c1'), v1 = '1158000000000', fee = '42000000000'
    clawIntent(cx, c1, v1, '1000000000', '2000000000'); ex(cx, 'clawback-sent', { txId: c1, outcome: 'accepted' })
    ex(cx, 'clawback-failed', { txId: c1, reason: 'the claw-back landed with an error: nothing moved; the fee was charged', fee })
    push('17c-clawback-failed-on-chain', 'CC-2a: a claw-back that failed ON CHAIN: clawback-failed carries the fee charged (spent); back to DRAINED, ok false, not landed', cx,
      js({ phase: 'ARMED', armed: crec, releaseAt: crec.releaseAt, chains: { eth: cs({ ...base, phase: 'DRAINED', spent: String(BigInt(FEE_ETH) + BigInt(fee)), clawback: { txId: c1, to: ETH_B, value: v1, ok: false, landed: false } }) } }))
  }
  return out
}

// ---------------------------------------------------------------- tickets (CC-3: vt-ticket/2) and the relay decode vectors
//
// Every valid vector carries a GENUINE signed transaction: ETH EIP-1559 txs serialized by viem, SOL legacy / v0 messages
// compiled and signed by @solana/web3.js, exactly as the engine builds them. The signing keys are derived from fixed
// labels (synthetic, never funded anywhere). ETH signatures are made synchronously through web3.js'
// Secp256k1Program.createInstructionWithPrivateKey (keccak256 of the unsigned tx, RFC 6979, low s): byte-identical to
// viem's signTransaction (checked by api/test/decode.test.ts), so this generator stays synchronous.

type Hex = `0x${string}`
const TICKET_KEY = seed('ticket key') // 32 bytes
const ETH_CHAIN_ID: Readonly<Record<TicketPayload['w'], number>> = { local: 31337, testnet: 11155111, mainnet: 1 } // = vt-broadcast NETWORK_IDS
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const ETH_SIGNER = seed('ticket eth signer'), ETH_OTHER_SIGNER = seed('ticket eth other signer')
const SOL_SIGNER = Keypair.fromSeed(seed('ticket sol signer')), SOL_OTHER_SIGNER = Keypair.fromSeed(seed('ticket sol other signer'))
const ethAddrOf = (key: Uint8Array): string => privateKeyToAccount(toHex(key)).address.toLowerCase()
const MEMO_V2 = new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr')
const TICKET_PAYLOAD = enc.encode('[1/1 ticket] A synthetic vt ticket vector part.\n')

// The v2 payload JSON, keys in the contract order (http.ts).
const ticketJson = (p: TicketPayload): string => JSON.stringify({ j: p.j, w: p.w, c: p.c, g: p.g, t: p.t, r: p.r, a: p.a, k: p.k, p: p.p, to: p.to, value: p.value, f: p.f, q: p.q, x: p.x, e: p.e, n: p.n })
const signTicketText = (prefix: string, json: string, key: Uint8Array = TICKET_KEY): string => {
  const body = base64urlnopad.encode(enc.encode(json))
  return `${prefix}${body}.${base64urlnopad.encode(createHmac('sha256', key).update(`${prefix}${body}`).digest())}`
}
function ticketOf(p: TicketPayload, key: Uint8Array = TICKET_KEY): string {
  return signTicketText(TICKET_PREFIX, ticketJson(p), key)
}

// ---- ETH

// keccak256(unsigned) signed with `key` (low s, RFC 6979); the 0x02 prefix is part of the signed bytes.
function ethSig(unsigned: Hex, key: Uint8Array): { r: bigint; s: bigint; yParity: 0 | 1 } {
  const d = Buffer.from(Secp256k1Program.createInstructionWithPrivateKey({ privateKey: key, message: hexToBytes(unsigned) }).data)
  const off = d.readUInt16LE(1) // SECP256K1_INSTRUCTION_LAYOUT: signature (64) at signatureOffset, then recoveryId
  return { r: BigInt(toHex(d.subarray(off, off + 32))), s: BigInt(toHex(d.subarray(off + 32, off + 64))), yParity: d[off + 64] as 0 | 1 }
}
const sigOf = (x: { r: bigint; s: bigint; yParity: 0 | 1 }): { r: Hex; s: Hex; yParity: 0 | 1 } => ({ r: numberToHex(x.r, { size: 32 }), s: numberToHex(x.s, { size: 32 }), yParity: x.yParity })
const q = (n: bigint | number): Hex => (BigInt(n) === 0n ? '0x' : numberToHex(BigInt(n)))

interface EthFields { chainId: number; nonce: number; tip: bigint; maxFee: bigint; gas: bigint; to: string | null; value: bigint; data: Hex; accessList?: Array<{ address: Hex; storageKeys: Hex[] }> }
// A genuine EIP-1559 tx, exactly as viem's signTransaction writes it.
function ethTx1559(x: EthFields, key: Uint8Array = ETH_SIGNER): Hex {
  const tx = { type: 'eip1559' as const, chainId: x.chainId, nonce: x.nonce, maxPriorityFeePerGas: x.tip, maxFeePerGas: x.maxFee, gas: x.gas,
    ...(x.to !== null ? { to: x.to as Hex } : {}), value: x.value, data: x.data, ...(x.accessList ? { accessList: x.accessList } : {}) }
  return serializeTransaction(tx, sigOf(ethSig(serializeTransaction(tx), key)))
}
// The same fields RLP-encoded by hand, for shapes viem refuses to write (tip > maxFee, a non-canonical integer, high s).
function ethRaw1559(x: EthFields, o: { nonceHex?: Hex; highS?: boolean } = {}, key: Uint8Array = ETH_SIGNER): Hex {
  const fields: Array<Hex | Hex[]> = [q(x.chainId), o.nonceHex ?? q(x.nonce), q(x.tip), q(x.maxFee), q(x.gas), (x.to ?? '0x') as Hex, q(x.value), x.data]
  const unsigned = concatHex(['0x02', toRlp([...fields, []] as never)])
  const sig = ethSig(unsigned, key)
  const s = o.highS ? SECP256K1_N - sig.s : sig.s, y = o.highS ? 1 - sig.yParity : sig.yParity
  return concatHex(['0x02', toRlp([...fields, [], q(y), q(sig.r), q(s)] as never)])
}
const ETH_JOB: EthFields = { chainId: ETH_CHAIN_ID.local, nonce: 7, tip: 1_000_000n, maxFee: 3_000_000_000n, gas: 60_000n, to: NULL_ETH, value: 0n, data: toHex(TICKET_PAYLOAD) }
const ETH_CLAW: EthFields = { chainId: ETH_CHAIN_ID.local, nonce: 8, tip: 1_000_000n, maxFee: 2_000_000_000n, gas: 21_000n, to: ETH_B.toLowerCase(), value: 2_500_000_000_000_000n, data: '0x' }
const ethFee = (x: EthFields): string => String(x.gas * x.maxFee)
// PF-S fix round 2 (R1-1): the ticket's x, the declared fee members the signed bytes carry exactly
const ethX = (x: EthFields): string => `${x.gas}:${x.tip}:${x.maxFee}`

// ---- SOL

const SOL_BH = blockhash('ticket sol')
const cuLimitIx = (units: number): TransactionInstruction => ComputeBudgetProgram.setComputeUnitLimit({ units })
const cuPriceIx = (microLamports: number): TransactionInstruction => ComputeBudgetProgram.setComputeUnitPrice({ microLamports })
const memoIx = (data: Uint8Array, keys: TransactionInstruction['keys'] = []): TransactionInstruction => new TransactionInstruction({ programId: MEMO_V2, keys, data: Buffer.from(data) })
const transferIx = (to: string, lamports: bigint, from: PublicKey = SOL_SIGNER.publicKey): TransactionInstruction => SystemProgram.transfer({ fromPubkey: from, toPubkey: new PublicKey(to), lamports })
function solTx(ixs: TransactionInstruction[], o: { payer?: Keypair; signers?: Keypair[]; v0?: boolean; tables?: AddressLookupTableAccount[]; blockhash?: string } = {}): VersionedTransaction {
  const payer = o.payer ?? SOL_SIGNER
  const m = new TransactionMessage({ payerKey: payer.publicKey, recentBlockhash: o.blockhash ?? SOL_BH, instructions: ixs })
  const tx = new VersionedTransaction(o.v0 ? m.compileToV0Message(o.tables) : m.compileToLegacyMessage())
  tx.sign([payer, ...(o.signers ?? [])])
  return tx
}
const solWire = (tx: VersionedTransaction): Uint8Array => tx.serialize()
const solFeeOf = (limit: number, price: number): string => String(5_000n + (BigInt(limit) * BigInt(price) + 999_999n) / 1_000_000n)
const SOL_JOB_IXS = (): TransactionInstruction[] => [cuLimitIx(30_000), cuPriceIx(12_500), memoIx(TICKET_PAYLOAD)]
const SOL_CLAW_TO = SOL_B, SOL_CLAW_VALUE = 1_234_567n

// ---- the vectors

type Raw = { encoding: 'hex'; value: Hex } | { encoding: 'base64'; value: string }
const ethRawOf = (hex: Hex): Raw => ({ encoding: 'hex', value: hex })
const solRawOf = (b: Uint8Array): Raw => ({ encoding: 'base64', value: base64.encode(b) })
const rawBytesOf = (r: Raw): Uint8Array => (r.encoding === 'hex' ? hexToBytes(r.value) : base64.decode(r.value))
const txIdOf = (c: Chain, r: Raw): string => (c === 'eth' ? keccak256(rawBytesOf(r)) : base58.encode(rawBytesOf(r).subarray(1, 65)))
// CC-3a: q = the attempt's declared identity: the ETH nonce (decimal) or the SOL recentBlockhash (base58).
type Binding = Pick<TicketPayload, 'a' | 'k' | 'p' | 'to' | 'value' | 'f' | 'q' | 'x'>
// PF-S I-1: an ETH job ticket's `to` is the job tx's recipient (the publish mode's: 0x000…000 or a); a SOL job ticket's is null.
const jobBinding = (a: string, f: string, q: string, to: string | null, x: string): Binding => ({ a, k: 'job', p: sha256Hex(TICKET_PAYLOAD), to, value: null, f, q, x })
const clawBinding = (a: string, to: string, value: bigint, f: string, q: string, x: string): Binding => ({ a, k: 'clawback', p: null, to, value: String(value), f, q, x })
const ethQ = (x: EthFields): string => String(x.nonce)

function ticketFixtures(jobId: string): { json: unknown; first: string; firstPayload: TicketPayload } {
  const ethA = ethAddrOf(ETH_SIGNER), solA = SOL_SIGNER.publicKey.toBase58()
  let i = 0
  const issue = (w: TicketPayload['w'], c: Chain, raw: Raw, b: Binding, o: { t?: string } = {}): { payload: TicketPayload; issuedAt: number; ticket: string } => {
    const issuedAt = T0 + 30_000 + i * 1_000
    const payload: TicketPayload = { j: jobId, w, c, g: 1 + (i % 3), t: o.t ?? txIdOf(c, raw), r: sha256Hex(rawBytesOf(raw)), ...b, e: issuedAt + TICKET_TTL_MS, n: seed(`ticket nonce ${i}`).toString('hex').slice(0, 16) }
    i++
    return { payload, issuedAt, ticket: ticketOf(payload) }
  }
  const valid = ([
    ['local eth job to the null address; f = gas × maxFee exactly', 'local', 'eth', ethRawOf(ethTx1559(ETH_JOB)), jobBinding(ethA, ethFee(ETH_JOB), ethQ(ETH_JOB), NULL_ETH, ethX(ETH_JOB))],
    ['testnet sol job: legacy message, CU limit + price + one Memo v2; f = the exact fee', 'testnet', 'sol', solRawOf(solWire(solTx(SOL_JOB_IXS()))), jobBinding(solA, solFeeOf(30_000, 12_500), SOL_BH, null, '30000:12500')],
    ['mainnet eth job (the relay refuses it while mainnet job sends are locked: release.mainnet-locked)', 'mainnet', 'eth', ethRawOf(ethTx1559({ ...ETH_JOB, chainId: ETH_CHAIN_ID.mainnet })), jobBinding(ethA, ethFee(ETH_JOB), ethQ(ETH_JOB), NULL_ETH, ethX(ETH_JOB))],
    ['local eth claw-back: value to the destination, no data', 'local', 'eth', ethRawOf(ethTx1559(ETH_CLAW)), clawBinding(ethA, ETH_CLAW.to!, ETH_CLAW.value, ethFee(ETH_CLAW), ethQ(ETH_CLAW), ethX(ETH_CLAW))],
    ['testnet sol claw-back: one System transfer, no compute budget (price 0: the declared limit is the default, not in the tx); f = 5000', 'testnet', 'sol', solRawOf(solWire(solTx([transferIx(SOL_CLAW_TO, SOL_CLAW_VALUE)]))), clawBinding(solA, SOL_CLAW_TO, SOL_CLAW_VALUE, '5000', SOL_BH, '200000:0')],
    ['local eth job to the sender itself (eth.calldata.self); f above the worst case', 'local', 'eth', ethRawOf(ethTx1559({ ...ETH_JOB, nonce: 9, to: ethA })), jobBinding(ethA, String(BigInt(ethFee(ETH_JOB)) + 1n), '9', ethA, ethX(ETH_JOB))],
    ['local sol job: CU limit only (passive: no price, fee 5000), as vt\'s builder makes it', 'local', 'sol', solRawOf(solWire(solTx([cuLimitIx(30_000), memoIx(TICKET_PAYLOAD)]))), jobBinding(solA, '5000', SOL_BH, null, '30000:0')],
    ['testnet sol claw-back with a priority fee (limit 450, price 27778 → ⌈12.5001⌉ = 13)', 'testnet', 'sol', solRawOf(solWire(solTx([cuLimitIx(450), cuPriceIx(27_778), transferIx(SOL_CLAW_TO, SOL_CLAW_VALUE)]))), clawBinding(solA, SOL_CLAW_TO, SOL_CLAW_VALUE, solFeeOf(450, 27_778), SOL_BH, '450:27778')],
    ['testnet eth job with tip = maxFee', 'testnet', 'eth', ethRawOf(ethTx1559({ ...ETH_JOB, chainId: ETH_CHAIN_ID.testnet, tip: ETH_JOB.maxFee })), jobBinding(ethA, ethFee(ETH_JOB), ethQ(ETH_JOB), NULL_ETH, ethX({ ...ETH_JOB, tip: ETH_JOB.maxFee }))],
    ['testnet sol job at the prompt rung (limit 33000, price ⌈12500 × 10⁶ / 33000⌉ = 378788); f = the exact fee', 'testnet', 'sol', solRawOf(solWire(solTx([cuLimitIx(33_000), cuPriceIx(378_788), memoIx(TICKET_PAYLOAD)]))), jobBinding(solA, solFeeOf(33_000, 378_788), SOL_BH, null, '33000:378788')],
  ] as const).map(([name, w, c, raw, b]) => ({ name, ...issue(w, c, raw, b), raw }))
  if (solFeeOf(450, 27_778) !== '5013' || solFeeOf(1_400_000, 7) !== '5010' || solFeeOf(33_000, 378_788) !== '17501') throw new Error('sol fee vector')

  // ---- format and binding negatives (one defect each; context = the relay's network, route chain and raw param)
  const v0 = valid[0]
  const ctx0 = { network: 'local', chain: 'eth', raw: v0.raw }
  const now0 = v0.issuedAt + 1_000
  const [prefix, body, mac] = [TICKET_PREFIX, v0.ticket.slice(TICKET_PREFIX.length).split('.')[0], v0.ticket.split('.').pop()!]
  const flip = (s: string, k: number): string => s.slice(0, k) + (s[k] === 'A' ? 'B' : 'A') + s.slice(k + 1)
  // The MAC is 32 bytes = 43 base64url chars; the last char carries 2 unused bits. Changing only those bits keeps the
  // decoded bytes: a verifier must still refuse (compare the canonical encoding, or re-encode and compare).
  const B64U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
  const nonCanonical = `${prefix}${body}.${mac.slice(0, 42)}${B64U[B64U.indexOf(mac[42]) ^ 1]}`
  const otherRaw = ethRawOf(ethTx1559({ ...ETH_JOB, nonce: 99 }))
  const p0 = v0.payload
  const v1Json = JSON.stringify({ j: p0.j, w: p0.w, c: p0.c, g: p0.g, t: p0.t, r: p0.r, e: p0.e, n: p0.n })
  const odd = (name: string, json: string): Record<string, unknown> => ({ name, ticket: signTicketText(TICKET_PREFIX, json), now: now0, context: ctx0, guard: 'relay.send-ticket' })
  const field = (over: Partial<Record<keyof TicketPayload, unknown>>): string => ticketJson({ ...p0, ...over } as TicketPayload)
  const negatives = [
    { name: 'bad-mac', ticket: `${prefix}${body}.${flip(mac, 0)}`, now: now0, context: ctx0, guard: 'relay.send-ticket' },
    { name: 'mac-non-canonical', ticket: nonCanonical, now: now0, context: ctx0, guard: 'relay.send-ticket' },
    { name: 'wrong-key', ticket: ticketOf(p0, seed('another key')), now: now0, context: ctx0, guard: 'relay.send-ticket' },
    { name: 'v1-ticket', ticket: signTicketText('vt-ticket/1.', v1Json), now: now0, context: ctx0, guard: 'relay.send-ticket' },
    odd('v1-payload-under-v2', v1Json),
    { name: 'bad-format-version', ticket: v0.ticket.replace(TICKET_PREFIX, 'vt-ticket/3.'), now: now0, context: ctx0, guard: 'relay.send-ticket' },
    { name: 'bad-format-parts', ticket: `${prefix}${body}`, now: now0, context: ctx0, guard: 'relay.send-ticket' },
    odd('v2-key-order', JSON.stringify({ j: p0.j, w: p0.w, c: p0.c, g: p0.g, t: p0.t, r: p0.r, e: p0.e, n: p0.n, a: p0.a, k: p0.k, p: p0.p, to: p0.to, value: p0.value, f: p0.f, q: p0.q })),
    odd('v2-extra-key', JSON.stringify({ ...JSON.parse(ticketJson(p0)), x: 1 })),
    odd('v2-kind-unknown', field({ k: 'publish' })),
    odd('v2-job-without-p', field({ p: null })),
    odd('v2-job-without-to', field({ to: null })),   // PF-S I-1: an ETH job ticket names its recipient
    odd('v2-job-with-value', field({ value: '0' })),
    odd('v2-clawback-with-p', field({ k: 'clawback', to: ETH_B.toLowerCase(), value: '1' })),
    odd('v2-clawback-value-0', field({ k: 'clawback', p: null, to: ETH_B.toLowerCase(), value: '0' })),
    odd('v2-clawback-without-to', field({ k: 'clawback', p: null, to: null, value: '1' })),
    odd('v2-fee-0', field({ f: '0' })),
    odd('v2-fee-leading-zero', field({ f: `0${p0.f}` })),
    odd('v2-fee-number', field({ f: Number(p0.f) })),
    odd('v2-sender-checksummed', field({ a: getAddress(p0.a) })),
    odd('v2-sender-sol-on-eth', field({ a: SOL_SIGNER.publicKey.toBase58() })),
    odd('v2-nonce-missing', JSON.stringify({ ...JSON.parse(ticketJson(p0)), q: undefined })),
    odd('v2-nonce-leading-zero', field({ q: `0${p0.q}` })),
    odd('v2-nonce-number', field({ q: Number(p0.q) })),
    odd('v2-nonce-blockhash-on-eth', field({ q: SOL_BH })),
    odd('v2-fee-members-missing', field({ x: null })),                 // PF-S fix round 2: an ETH ticket binds gas:tip:maxFee
    odd('v2-fee-members-two', field({ x: '60000:3000000000' })),
    { name: 'v2-blockhash-nonce-on-sol', ticket: signTicketText(TICKET_PREFIX, ticketJson({ ...valid[1].payload, q: '7' })), now: valid[1].issuedAt + 1_000,
      context: { network: 'testnet', chain: 'sol', raw: valid[1].raw }, guard: 'relay.send-ticket' },
    { name: 'v2-sol-job-with-to', ticket: signTicketText(TICKET_PREFIX, ticketJson({ ...valid[1].payload, to: SOL_B })), now: valid[1].issuedAt + 1_000,   // PF-S I-1: a memo tx has no recipient
      context: { network: 'testnet', chain: 'sol', raw: valid[1].raw }, guard: 'relay.send-ticket' },
    { name: 'expired-at-e', ticket: v0.ticket, now: p0.e, context: ctx0, guard: 'relay.ticket-expired' },
    { name: 'expired-after-e', ticket: v0.ticket, now: p0.e + 1, context: ctx0, guard: 'relay.ticket-expired' },
    { name: 'chain-mismatch', ticket: v0.ticket, now: now0, context: { ...ctx0, chain: 'sol' }, guard: 'relay.ticket-chain' },
    { name: 'network-mismatch', ticket: v0.ticket, now: now0, context: { ...ctx0, network: 'testnet' }, guard: 'relay.ticket-network' },
    { name: 'raw-mismatch', ticket: v0.ticket, now: now0, context: { ...ctx0, raw: otherRaw }, guard: 'relay.ticket-raw' },
  ]

  // ---- decode vectors: a valid ticket for exactly these bytes (r, t and the MAC hold), the binding of the genuine tx
  // it was derived from, and ONE defect in the signed transaction → relay.decode-mismatch.
  const decode: Array<Record<string, unknown>> = []
  const bad = (name: string, defect: string, w: TicketPayload['w'], c: Chain, raw: Raw, b: Binding, o: { t?: string } = {}): void => {
    const x = issue(w, c, raw, b, o)
    decode.push({ name, defect, ticket: x.ticket, now: x.issuedAt + 1_000, context: { network: w, chain: c, raw }, guard: 'relay.decode-mismatch' })
  }
  const jobB = jobBinding(ethA, ethFee(ETH_JOB), ethQ(ETH_JOB), NULL_ETH, ethX(ETH_JOB)), clawB = clawBinding(ethA, ETH_CLAW.to!, ETH_CLAW.value, ethFee(ETH_CLAW), ethQ(ETH_CLAW), ethX(ETH_CLAW))
  const e = (x: Partial<EthFields>, key?: Uint8Array): Raw => ethRawOf(ethTx1559({ ...ETH_JOB, ...x }, key))
  const legacy = { type: 'legacy' as const, chainId: ETH_JOB.chainId, nonce: ETH_JOB.nonce, gasPrice: ETH_JOB.maxFee, gas: ETH_JOB.gas, to: NULL_ETH as Hex, value: 0n, data: ETH_JOB.data }
  const ls = ethSig(serializeTransaction(legacy), ETH_SIGNER)
  bad('eth-type-legacy', 'a legacy (EIP-155) tx with the same fields', 'local', 'eth', ethRawOf(serializeTransaction(legacy, { ...sigOf(ls), v: BigInt(ETH_JOB.chainId * 2 + 35 + ls.yParity) })), jobB)
  const t1 = { type: 'eip2930' as const, chainId: ETH_JOB.chainId, nonce: ETH_JOB.nonce, gasPrice: ETH_JOB.maxFee, gas: ETH_JOB.gas, to: NULL_ETH as Hex, value: 0n, data: ETH_JOB.data, accessList: [] }
  bad('eth-type-2930', 'an EIP-2930 (type 1) tx', 'local', 'eth', ethRawOf(serializeTransaction(t1, sigOf(ethSig(serializeTransaction(t1), ETH_SIGNER)))), jobB)
  const t3 = { type: 'eip4844' as const, chainId: ETH_JOB.chainId, nonce: ETH_JOB.nonce, maxPriorityFeePerGas: ETH_JOB.tip, maxFeePerGas: ETH_JOB.maxFee, gas: ETH_JOB.gas, to: NULL_ETH as Hex,
    value: 0n, data: ETH_JOB.data, maxFeePerBlobGas: 1n, blobVersionedHashes: [`0x01${hex64('ticket blob').slice(2)}` as Hex] }
  bad('eth-type-blob', 'an EIP-4844 (type 3) blob tx', 'local', 'eth', ethRawOf(serializeTransaction(t3, sigOf(ethSig(serializeTransaction(t3), ETH_SIGNER)))), jobB)
  const auth = { address: ETH_B as Hex, chainId: ETH_JOB.chainId, nonce: 0, r: `0x${hex64('ticket auth r')}` as Hex, s: `0x${hex64('ticket auth s').replace(/^[89a-f]/, '1')}` as Hex, yParity: 0 }
  const t4 = { type: 'eip7702' as const, chainId: ETH_JOB.chainId, nonce: ETH_JOB.nonce, maxPriorityFeePerGas: ETH_JOB.tip, maxFeePerGas: ETH_JOB.maxFee, gas: ETH_JOB.gas, to: NULL_ETH as Hex,
    value: 0n, data: ETH_JOB.data, authorizationList: [auth] }
  bad('eth-type-7702', 'an EIP-7702 (type 4) tx with an authorization list', 'local', 'eth', ethRawOf(serializeTransaction(t4 as never, sigOf(ethSig(serializeTransaction(t4 as never), ETH_SIGNER)))), jobB)
  bad('eth-chain-id', 'signed for chain id 1 at the local relay', 'local', 'eth', e({ chainId: ETH_CHAIN_ID.mainnet }), jobB)
  bad('eth-sender', 'signed by another key (recovered from ≠ a)', 'local', 'eth', e({}, ETH_OTHER_SIGNER), jobB)
  bad('eth-fee-gas', 'gas + 1: gas × maxFee > f', 'local', 'eth', e({ gas: ETH_JOB.gas + 1n }), jobB)
  bad('eth-fee-max', 'maxFeePerGas + 1: gas × maxFee > f', 'local', 'eth', e({ maxFee: ETH_JOB.maxFee + 1n }), jobB)
  bad('eth-gas-zero', 'gas 0 (absent): gas × maxFee = 0 fits f, but gas must be present', 'local', 'eth', e({ gas: 0n }), jobB)
  bad('eth-max-fee-zero', 'maxFeePerGas 0 (absent)', 'local', 'eth', e({ maxFee: 0n, tip: 0n }), jobB)
  bad('eth-tip-over-max', 'maxPriorityFeePerGas > maxFeePerGas (RLP by hand)', 'local', 'eth', ethRawOf(ethRaw1559({ ...ETH_JOB, tip: ETH_JOB.maxFee + 1n })), jobB)
  bad('eth-job-value', 'a job tx with value 1', 'local', 'eth', e({ value: 1n }), jobB)
  bad('eth-job-to', 'a job tx to a third address', 'local', 'eth', e({ to: ETH_B.toLowerCase() }), jobB)
  bad('eth-job-create', 'a job tx with no recipient (contract creation)', 'local', 'eth', e({ to: null }), jobB)
  bad('eth-job-payload', 'one calldata byte changed: sha256(data) ≠ p', 'local', 'eth', e({ data: toHex(Uint8Array.from(TICKET_PAYLOAD, (b, k) => (k === 3 ? b ^ 1 : b))) }), jobB)
  bad('eth-access-list', 'a non-empty access list', 'local', 'eth', e({ accessList: [{ address: ETH_B as Hex, storageKeys: [] }] }), jobB)
  bad('eth-clawback-to', 'a claw-back to another address', 'local', 'eth', ethRawOf(ethTx1559({ ...ETH_CLAW, to: ethAddr('ticket other destination').toLowerCase() })), clawB)
  bad('eth-clawback-value', 'a claw-back of value + 1', 'local', 'eth', ethRawOf(ethTx1559({ ...ETH_CLAW, value: ETH_CLAW.value + 1n })), clawB)
  bad('eth-clawback-data', 'a claw-back with one data byte', 'local', 'eth', ethRawOf(ethTx1559({ ...ETH_CLAW, data: '0x00' })), clawB)
  bad('eth-kind', 'a genuine job tx under a claw-back ticket', 'local', 'eth', ethRawOf(ethTx1559(ETH_JOB)), clawBinding(ethA, NULL_ETH, 1n, ethFee(ETH_JOB), ethQ(ETH_JOB), ethX(ETH_JOB)))
  bad('eth-tx-id', 'the ticket t is another tx\'s id (r still binds these bytes)', 'local', 'eth', ethRawOf(ethTx1559(ETH_JOB)), jobB, { t: txIdOf('eth', otherRaw) })
  bad('eth-high-s', 'the same signature malleated to high s (it recovers the same sender)', 'local', 'eth', ethRawOf(ethRaw1559(ETH_JOB, { highS: true })), jobB)
  bad('eth-non-canonical-rlp', 'the nonce written with a leading zero byte', 'local', 'eth', ethRawOf(ethRaw1559(ETH_JOB, { nonceHex: '0x0007' })), jobB)
  bad('eth-trailing-byte', 'a genuine tx followed by one more byte', 'local', 'eth', ethRawOf(concatHex([ethTx1559(ETH_JOB), '0x00'])), jobB)
  bad('eth-nonce', 'signed at nonce 8 under a ticket declaring nonce 7 (a "bump" of the nonce-7 family that is really a new nonce)', 'local', 'eth', e({ nonce: ETH_JOB.nonce + 1 }), jobB)
  bad('eth-clawback-nonce', 'a claw-back signed at nonce 9 under a ticket declaring nonce 8', 'local', 'eth', ethRawOf(ethTx1559({ ...ETH_CLAW, nonce: ETH_CLAW.nonce + 1 })), clawB)

  const solJobB = jobBinding(solA, solFeeOf(30_000, 12_500), SOL_BH, null, '30000:12500'), solClawB = clawBinding(solA, SOL_CLAW_TO, SOL_CLAW_VALUE, '5000', SOL_BH, '200000:0')
  const s = (ixs: TransactionInstruction[], o: Parameters<typeof solTx>[1] = {}): Raw => solRawOf(solWire(solTx(ixs, o)))
  const genuineSol = solWire(solTx(SOL_JOB_IXS()))
  const flipped = Uint8Array.from(genuineSol); flipped[10] ^= 1
  const otherSig = solWire(solTx([cuLimitIx(30_001), cuPriceIx(12_500), memoIx(TICKET_PAYLOAD)]))
  const table = new AddressLookupTableAccount({ key: new PublicKey(seed('ticket lookup table')), state: { deactivationSlot: 2n ** 64n - 1n, lastExtendedSlot: 0, lastExtendedSlotStartIndex: 0, authority: undefined, addresses: [new PublicKey(seed('ticket table entry'))] } })
  bad('sol-fee-payer', 'the fee payer (and signer) is another key', 'testnet', 'sol', s(SOL_JOB_IXS(), { payer: SOL_OTHER_SIGNER }), solJobB)
  bad('sol-signature', 'one signature bit flipped (t = that signature)', 'testnet', 'sol', solRawOf(flipped), solJobB)
  bad('sol-tx-id', 'the ticket t is another tx\'s signature', 'testnet', 'sol', solRawOf(genuineSol), solJobB, { t: base58.encode(otherSig.subarray(1, 65)) })
  bad('sol-fee-price', 'CU price + 1: ⌈30000 × 12501 / 10⁶⌉ = 376, the fee exceeds f by one lamport', 'testnet', 'sol', s([cuLimitIx(30_000), cuPriceIx(12_501), memoIx(TICKET_PAYLOAD)]), solJobB)
  bad('sol-fee-limit', 'CU limit raised so the fee exceeds f', 'testnet', 'sol', s([cuLimitIx(110_000), cuPriceIx(12_500), memoIx(TICKET_PAYLOAD)]), solJobB)
  bad('sol-price-without-limit', 'a CU price without a CU limit (counted at 1,400,000 CU)', 'testnet', 'sol', s([cuPriceIx(12_500), memoIx(TICKET_PAYLOAD)]), solJobB)
  bad('sol-compute-budget-twice', 'two SetComputeUnitPrice instructions', 'testnet', 'sol', s([cuLimitIx(30_000), cuPriceIx(1), cuPriceIx(12_500), memoIx(TICKET_PAYLOAD)]), solJobB)
  bad('sol-heap-frame', 'a RequestHeapFrame instruction', 'testnet', 'sol', s([...SOL_JOB_IXS(), ComputeBudgetProgram.requestHeapFrame({ bytes: 64 * 1024 })]), solJobB)
  bad('sol-other-program', 'an instruction for a program outside the allowed set', 'testnet', 'sol', s([...SOL_JOB_IXS(), new TransactionInstruction({ programId: new PublicKey(seed('ticket other program')), keys: [], data: Buffer.from([1]) })]), solJobB)
  bad('sol-job-transfer', 'a System transfer inside a job tx', 'testnet', 'sol', s([...SOL_JOB_IXS(), transferIx(SOL_CLAW_TO, 1n)]), solJobB)
  bad('sol-job-payload', 'one memo byte changed: sha256(memo) ≠ p', 'testnet', 'sol', s([cuLimitIx(30_000), cuPriceIx(12_500), memoIx(Uint8Array.from(TICKET_PAYLOAD, (b, k) => (k === 3 ? b ^ 1 : b)))]), solJobB)
  bad('sol-job-two-memos', 'two Memo v2 instructions', 'testnet', 'sol', s([...SOL_JOB_IXS(), memoIx(TICKET_PAYLOAD)]), solJobB)
  bad('sol-job-writable', 'the memo names another writable account', 'testnet', 'sol', s([cuLimitIx(30_000), cuPriceIx(12_500), memoIx(TICKET_PAYLOAD, [{ pubkey: new PublicKey(SOL_B), isSigner: false, isWritable: true }])]), solJobB)
  bad('sol-two-signers', 'a second required signer', 'testnet', 'sol', s([cuLimitIx(30_000), cuPriceIx(12_500), memoIx(TICKET_PAYLOAD, [{ pubkey: SOL_OTHER_SIGNER.publicKey, isSigner: true, isWritable: false }])], { signers: [SOL_OTHER_SIGNER] }), solJobB)
  bad('sol-lookup-table', 'a v0 message that loads an account through an address lookup table', 'testnet', 'sol', s([cuLimitIx(30_000), cuPriceIx(12_500), memoIx(TICKET_PAYLOAD, [{ pubkey: table.state.addresses[0], isSigner: false, isWritable: false }])], { v0: true, tables: [table] }), solJobB)
  bad('sol-clawback-to', 'a claw-back to another destination', 'testnet', 'sol', s([transferIx(solAddr('ticket other destination'), SOL_CLAW_VALUE)]), solClawB)
  bad('sol-clawback-value', 'a claw-back of value + 1', 'testnet', 'sol', s([transferIx(SOL_CLAW_TO, SOL_CLAW_VALUE + 1n)]), solClawB)
  bad('sol-clawback-memo', 'a claw-back that also carries a memo', 'testnet', 'sol', s([transferIx(SOL_CLAW_TO, SOL_CLAW_VALUE), memoIx(TICKET_PAYLOAD)]), solClawB)
  bad('sol-clawback-two-transfers', 'two transfers', 'testnet', 'sol', s([transferIx(SOL_CLAW_TO, 1n), transferIx(SOL_CLAW_TO, SOL_CLAW_VALUE - 1n)]), solClawB)
  bad('sol-kind', 'a genuine job tx under a claw-back ticket', 'testnet', 'sol', solRawOf(genuineSol), clawBinding(solA, SOL_CLAW_TO, SOL_CLAW_VALUE, solFeeOf(30_000, 12_500), SOL_BH, '30000:12500'))
  bad('sol-trailing-byte', 'a genuine tx followed by one more byte', 'testnet', 'sol', solRawOf(Uint8Array.from([...genuineSol, 0])), solJobB)
  bad('sol-blockhash', 'signed over another recentBlockhash than the ticket declares', 'testnet', 'sol', s(SOL_JOB_IXS(), { blockhash: blockhash('ticket sol other') }), solJobB)
  bad('sol-clawback-blockhash', 'a claw-back signed over another recentBlockhash', 'testnet', 'sol', s([transferIx(SOL_CLAW_TO, SOL_CLAW_VALUE)], { blockhash: blockhash('ticket sol other') }), solClawB)
  bad('sol-price-without-limit-at-default-minus-1', 'a CU price without a limit, f one lamport under the 1,400,000-CU default (5010 - 1)', 'testnet', 'sol', s([cuPriceIx(7), memoIx(TICKET_PAYLOAD)]), jobBinding(solA, '5009', SOL_BH, null, '1400000:7'))
  // PF-S I-1: the ticket names ONE recipient (the publish mode's), never "0x000…000 or a"
  bad('eth-job-to-self-under-null', 'a job tx to the sender itself under a ticket whose recipient is 0x000…000 (eth.calldata.null)', 'local', 'eth', e({ to: ethA }), jobB)
  bad('eth-job-to-null-under-self', 'a job tx to 0x000…000 under a ticket whose recipient is the sender (eth.calldata.self)', 'local', 'eth', e({}), jobBinding(ethA, ethFee(ETH_JOB), ethQ(ETH_JOB), ethA, ethX(ETH_JOB)))
  // PF-S fix round 1 (N-1): every account key is one the tx uses; an extra READ-ONLY key (32 bytes the signer chose) is refused
  const withExtraKey = (ixs: TransactionInstruction[], label: string): Raw => {
    const m = new TransactionMessage({ payerKey: SOL_SIGNER.publicKey, recentBlockhash: SOL_BH, instructions: ixs }).compileToLegacyMessage()
    const extended = new Message({ header: { ...m.header, numReadonlyUnsignedAccounts: m.header.numReadonlyUnsignedAccounts + 1 },
      accountKeys: [...m.accountKeys, new PublicKey(seed(label))], recentBlockhash: m.recentBlockhash,
      instructions: m.instructions.map((ix) => ({ programIdIndex: ix.programIdIndex, accounts: [...ix.accounts], data: ix.data })) })
    const tx = new VersionedTransaction(extended)
    tx.sign([SOL_SIGNER])
    return solRawOf(solWire(tx))
  }
  bad('sol-job-extra-key', 'a job tx whose message carries one more read-only account key that no instruction uses', 'testnet', 'sol', withExtraKey(SOL_JOB_IXS(), 'ticket sol extra key'), solJobB)
  bad('sol-clawback-extra-key', 'a claw-back whose message carries one more read-only account key that no instruction uses', 'testnet', 'sol', withExtraKey([transferIx(SOL_CLAW_TO, SOL_CLAW_VALUE)], 'ticket sol extra key 2'), solClawB)
  // PF-S fix round 2 (R1-1): the signed bytes carry exactly the declared fee members, in exactly vt's builder layout
  bad('eth-gas-members', 'gas one below the declared gas (the fee fits f, but x says 60000)', 'local', 'eth', e({ gas: ETH_JOB.gas - 1n }), jobB)
  bad('eth-tip-members', 'a tip one below the declared tip', 'local', 'eth', e({ tip: ETH_JOB.tip - 1n }), jobB)
  bad('eth-max-fee-members', 'maxFeePerGas one below the declared maxFee', 'local', 'eth', e({ maxFee: ETH_JOB.maxFee - 1n }), jobB)
  bad('sol-job-v0', 'the builder\'s instructions in a v0 message (vt signs legacy messages only)', 'testnet', 'sol', s(SOL_JOB_IXS(), { v0: true }), solJobB)
  bad('sol-job-order', 'the memo before the ComputeBudget instructions', 'testnet', 'sol', s([memoIx(TICKET_PAYLOAD), cuLimitIx(30_000), cuPriceIx(12_500)]), solJobB)
  bad('sol-job-cu-limit-members', 'a CU limit one below the declared one (the fee still fits f)', 'testnet', 'sol', s([cuLimitIx(29_999), cuPriceIx(12_500), memoIx(TICKET_PAYLOAD)]), solJobB)
  bad('sol-job-price-without-limit', 'a CU price without the CU limit vt always sets', 'testnet', 'sol', s([cuPriceIx(7), memoIx(TICKET_PAYLOAD)]), jobBinding(solA, '5010', SOL_BH, null, '1400000:7'))
  bad('sol-job-limit-zero', 'a CU limit of 0 with a large CU price (64 free bits; the tx fails for lack of compute, the fee is 5000)', 'testnet', 'sol', s([cuLimitIx(0), cuPriceIx(4_000_000), memoIx(TICKET_PAYLOAD)]), jobBinding(solA, '5000', SOL_BH, null, '30000:0'))
  bad('sol-clawback-limit-without-price', 'a claw-back with a CU limit and no price (vt sets both or neither)', 'testnet', 'sol', s([cuLimitIx(200_000), transferIx(SOL_CLAW_TO, SOL_CLAW_VALUE)]), solClawB)

  return {
    json: {
      format: TICKET_PREFIX, key: TICKET_KEY.toString('hex'), ttlMs: TICKET_TTL_MS,
      signers: { eth: ethA, sol: solA },
      rules: [
        'ticket = "vt-ticket/2." + b64url(payload JSON, keys j,w,c,g,t,r,a,k,p,to,value,f,q,e,n in that order, no whitespace) + "." + b64url(HMAC-SHA256(key, "vt-ticket/2." + b64url(payload))); b64url = RFC 4648 §5, no padding; field formats: src/contracts/http.ts',
        'valid while now < e; e = issuedAt + ttlMs; n = 16 lowercase hex; a v1 ticket ("vt-ticket/1.", or a v1 payload under the v2 prefix) is refused: relay.send-ticket',
        'verifyTicket (S1) refuses format and MAC (relay.send-ticket) and expiry (relay.ticket-expired); the relay gate adds w = its network (relay.ticket-network), c = the route chain (relay.ticket-chain), r = sha256(raw bytes) (relay.ticket-raw), the job-send lock (release.mainnet-locked), then the decode verification (relay.decode-mismatch: src/contracts/http.ts)',
        'raw bytes: ETH = params[0] hex decoded; SOL = params[0] base64 decoded; every valid raw is a genuine signed tx by `signers`',
        'each negative and each decode vector has exactly one defect; context = the relay\'s network, the route chain and the raw param',
      ],
      valid: valid.map((v) => ({ name: v.name, payload: v.payload, issuedAt: v.issuedAt, ticket: v.ticket, raw: v.raw, now: v.issuedAt + 1_000, context: { network: v.payload.w, chain: v.payload.c, raw: v.raw } })),
      negatives,
      decode,
    },
    first: v0.ticket,
    firstPayload: v0.payload,
  }
}

// ---------------------------------------------------------------- BTC tickets (CC-8: commit | reveal) and the relay decode vectors
//
// Every valid vector carries a GENUINE signed transaction built by @scure/btc-signer + micro-ordinals exactly as the
// prototype's builder (and plan E7) builds an ordinals text inscription: a commit paying a taproot reveal address from
// P2WPKH lane UTXOs, and a reveal spending the commit output by the script path. The lane key is derived from a fixed
// label (synthetic, never funded anywhere); the funding outpoints are made-up txids. The relay reads the input values from
// the chain, so each vector's context carries `prevouts` (outpoint → { value sats, script hex }), what that read returns.
// The signatures are deterministic (RFC 6979 for ECDSA, a zero aux for Schnorr), so the file is reproducible.

const BTC_NETS: Readonly<Record<TicketPayload['w'], typeof btc.NETWORK>> = {
  local: { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef }, testnet: btc.TEST_NETWORK, mainnet: btc.NETWORK,
}
const BTC_PRIV = seed('ticket btc lane'), BTC_OTHER_PRIV = seed('ticket btc other')
const BTC_X = pubSchnorr(BTC_PRIV)
const BTC_CT = 'text/plain;charset=utf-8'
const BTC_RATE = 2n // sat/vB
const BTC_POSTAGE = 546n
const btcLane = (w: TicketPayload['w']) => btc.p2wpkh(pubECDSA(BTC_PRIV), BTC_NETS[w])
const btcOther = (w: TicketPayload['w']) => btc.p2wpkh(pubECDSA(BTC_OTHER_PRIV), BTC_NETS[w])
const btcDest = (w: TicketPayload['w']) => btc.p2tr(BTC_X, undefined, BTC_NETS[w])
const btcOtherTr = (w: TicketPayload['w']) => btc.p2tr(pubSchnorr(BTC_OTHER_PRIV), undefined, BTC_NETS[w])
type Inscr = { tags: Record<string, unknown>; body: Uint8Array }
const inscr = (o: { body?: Uint8Array; tags?: Record<string, unknown> } = {}): Inscr => ({ tags: o.tags ?? { contentType: BTC_CT }, body: o.body ?? TICKET_PAYLOAD })
const btcReveal = (w: TicketPayload['w'], list: Inscr[]) => btc.p2tr(undefined, p2tr_ord_reveal(BTC_X, list as never), BTC_NETS[w], false, [OutOrdinalReveal])
const hexOf = (b: Uint8Array): string => Buffer.from(b).toString('hex')
interface Utxo { txid: string; index: number; amount: bigint }
const FUND1: Utxo = { txid: hex64('ticket btc fund 1'), index: 0, amount: 100_000n }
const FUND2: Utxo = { txid: hex64('ticket btc fund 2'), index: 1, amount: 40_000n }
const outpointOf = (u: { txid: string; index: number }): string => `${u.txid}:${u.index}`
const qOf = (...us: Array<{ txid: string; index: number }>): string => us.map(outpointOf).sort().join(',')

interface TxOut { script: Uint8Array; amount: bigint }
interface Built { raw: Uint8Array; id: string }
function buildCommit(ins: Utxo[], outs: TxOut[], o: { lockTime?: number; sign?: boolean; script?: Uint8Array; key?: Uint8Array; sighash?: number } = {}): Built {
  const w = btcLane('local')
  const t = new btc.Transaction(o.lockTime !== undefined ? { lockTime: o.lockTime } : {})
  for (const u of ins) t.addInput({ txid: u.txid, index: u.index, witnessUtxo: { script: o.script ?? w.script, amount: u.amount }, ...(o.sighash !== undefined ? { sighashType: o.sighash } : {}) })
  for (const x of outs) t.addOutput({ script: x.script, amount: x.amount })
  if (o.sign === false) return { raw: t.unsignedTx, id: t.id }
  t.sign(o.key ?? BTC_PRIV, o.sighash !== undefined ? [o.sighash] : undefined); t.finalize()
  return { raw: t.extract(), id: t.id }
}
// A reveal: input 0 spends `commit` (the script path of `reveal`); `extra` are further P2WPKH inputs.
function buildReveal(reveal: ReturnType<typeof btcReveal>, commit: { txid: string; index: number; amount: bigint }, outs: TxOut[], o: { extra?: Utxo[]; lockTime?: number; sign?: boolean } = {}): Built {
  const t = new btc.Transaction({ customScripts: [OutOrdinalReveal], ...(o.lockTime !== undefined ? { lockTime: o.lockTime } : {}) })
  t.addInput({ ...reveal, txid: commit.txid, index: commit.index, witnessUtxo: { script: reveal.script, amount: commit.amount } })
  for (const u of o.extra ?? []) t.addInput({ txid: u.txid, index: u.index, witnessUtxo: { script: btcLane('local').script, amount: u.amount } })
  for (const x of outs) t.addOutput({ script: x.script, amount: x.amount })
  if (o.sign === false) return { raw: t.unsignedTx, id: t.id }
  t.sign(BTC_PRIV, undefined, new Uint8Array(32)); t.finalize()
  return { raw: t.extract(), id: t.id }
}
const vsizeOf = (raw: Uint8Array): bigint => BigInt(btc.Transaction.fromRaw(raw, { customScripts: [OutOrdinalReveal] }).vsize)

function btcTicketFixtures(jobId: string): unknown {
  const body = TICKET_PAYLOAD, p = sha256Hex(body)
  const L = (w: TicketPayload['w']) => btcLane(w)
  const rv0 = (w: TicketPayload['w']) => btcReveal(w, [inscr()])
  // The reveal's fee at 2 sat/vB is known from a dummy build; the commit's from an iteration (the prototype's buildPair).
  const revealFee = vsizeOf(buildReveal(rv0('local'), { txid: '00'.repeat(32), index: 0, amount: 10_000_000n }, [{ script: btcDest('local').script, amount: BTC_POSTAGE }]).raw) * BTC_RATE
  const revealAmount = BTC_POSTAGE + revealFee
  const commitOuts = (ins: Utxo[], fee: bigint, to = rv0('local').script, value = revealAmount): TxOut[] => {
    const change = ins.reduce((a, u) => a + u.amount, 0n) - value - fee
    return [{ script: to, amount: value }, ...(change >= 546n ? [{ script: L('local').script, amount: change }] : [])]
  }
  const commitFeeFor = (ins: Utxo[]): bigint => vsizeOf(buildCommit(ins, commitOuts(ins, 1_000n)).raw) * BTC_RATE
  const commitFee1 = commitFeeFor([FUND1]), commitFee2 = commitFeeFor([FUND1, FUND2])
  const commit1 = buildCommit([FUND1], commitOuts([FUND1], commitFee1))
  const commit2 = buildCommit([FUND1, FUND2], commitOuts([FUND1, FUND2], commitFee2))
  const fundOut = (u: Utxo, who: 'lane' | 'other' = 'lane') => ({ [outpointOf(u)]: { value: String(u.amount), script: hexOf((who === 'lane' ? L('local') : btcOther('local')).script) } })
  const commitOut = (c: Built, vout = 0) => ({ txid: c.id, index: vout, amount: revealAmount })
  const commitPrev = (c: Built) => ({ [`${c.id}:0`]: { value: String(revealAmount), script: hexOf(rv0('local').script) } })
  let n = 0
  const issue = (w: TicketPayload['w'], raw: Uint8Array, id: string, b: Pick<TicketPayload, 'a' | 'k' | 'p' | 'to' | 'value' | 'f' | 'q'>): { payload: TicketPayload; issuedAt: number; ticket: string } => {
    const issuedAt = T0 + 40_000 + n * 1_000
    const payload: TicketPayload = { j: jobId, w, c: 'btc', g: 1 + (n % 3), t: id, r: sha256Hex(raw), ...b, x: null, e: issuedAt + TICKET_TTL_MS, n: seed(`btc ticket nonce ${n}`).toString('hex').slice(0, 16) }
    n++
    return { payload, issuedAt, ticket: ticketOf(payload) }
  }
  const ctxOf = (w: TicketPayload['w'], raw: Uint8Array, prevouts: unknown): unknown => ({ network: w, chain: 'btc', raw: { encoding: 'hex', value: hexOf(raw) }, prevouts })
  const commitB = (w: TicketPayload['w'], ins: Utxo[], f: bigint): Pick<TicketPayload, 'a' | 'k' | 'p' | 'to' | 'value' | 'f' | 'q'> =>
    ({ a: L(w).address!, k: 'commit', p, to: rv0(w).address!, value: String(revealAmount), f: String(f), q: qOf(...ins) })
  const revealB = (w: TicketPayload['w'], c: { txid: string; index: number }, f: bigint, o: { to?: string; value?: bigint; p?: string } = {}): Pick<TicketPayload, 'a' | 'k' | 'p' | 'to' | 'value' | 'f' | 'q'> =>
    ({ a: L(w).address!, k: 'reveal', p: o.p ?? p, to: o.to ?? btcDest(w).address!, value: String(o.value ?? BTC_POSTAGE), f: String(f), q: qOf(c) })
  const revealFor = (w: TicketPayload['w'], c: Built, outs?: TxOut[]): Built => buildReveal(rv0(w), commitOut(c), outs ?? [{ script: btcDest(w).script, amount: BTC_POSTAGE }])

  // ---- valid vectors: genuine txs; the relay (checkSend) passes each, except mainnet, which the lock refuses
  const valid = ([
    ['local commit: one lane UTXO, the reveal output and the change; f = the fee exactly', 'local', commit1, commitB('local', [FUND1], commitFee1), { ...fundOut(FUND1) }],
    ['local reveal: spends the commit output by the script path, one postage output; f = the fee exactly', 'local', revealFor('local', commit1), revealB('local', { txid: commit1.id, index: 0 }, revealFee), commitPrev(commit1)],
    ['testnet commit: two lane UTXOs; f above the fee', 'testnet', commit2, commitB('testnet', [FUND1, FUND2], commitFee2 + 250n), { ...fundOut(FUND1), ...fundOut(FUND2) }],
    ['testnet reveal; f above the fee', 'testnet', revealFor('testnet', commit2), revealB('testnet', { txid: commit2.id, index: 0 }, revealFee + 7n), commitPrev(commit2)],
    ['mainnet commit (the relay refuses it while mainnet job sends are locked: release.mainnet-locked)', 'mainnet', commit1, commitB('mainnet', [FUND1], commitFee1), { ...fundOut(FUND1) }],
    ['local commit without change: the lane UTXO exactly covers the reveal output and the fee', 'local',
      buildCommit([{ ...FUND1, amount: revealAmount + commitFee1 }], commitOuts([{ ...FUND1, amount: revealAmount + commitFee1 }], commitFee1)),
      commitB('local', [FUND1], commitFee1), { [outpointOf(FUND1)]: { value: String(revealAmount + commitFee1), script: hexOf(L('local').script) } }],
  ] as const).map(([name, w, tx, b, prevouts]) => ({ name, ...issue(w, tx.raw, tx.id, b), raw: { encoding: 'hex' as const, value: hexOf(tx.raw) }, prevouts }))

  // ---- format negatives: a correctly MAC'd btc ticket with ONE malformed field → relay.send-ticket
  const v0 = valid[0], p0 = v0.payload
  const tjson = (over: Partial<Record<keyof TicketPayload, unknown>>): string => ticketJson({ ...p0, ...over } as TicketPayload)
  const fmt = (name: string, json: string): Record<string, unknown> => ({ name, ticket: signTicketText(TICKET_PREFIX, json), now: v0.issuedAt + 1_000, context: ctxOf('local', rawOfValid(v0), v0.prevouts), guard: 'relay.send-ticket' })
  function rawOfValid(v: { raw: { value: string } }): Uint8Array { return Buffer.from(v.raw.value, 'hex') }
  const op = (u: { txid: string; index: number }): string => outpointOf(u)
  const [qa, qb] = [op(FUND1), op(FUND2)].sort()
  const negatives = [
    fmt('btc-kind-job', tjson({ k: 'job' })),
    fmt('btc-kind-clawback', tjson({ k: 'clawback', p: null, to: p0.to, value: p0.value })),
    fmt('btc-commit-without-p', tjson({ p: null })),
    fmt('btc-commit-without-to', tjson({ to: null })),
    fmt('btc-commit-without-value', tjson({ value: null })),
    fmt('btc-value-0', tjson({ value: '0' })),
    fmt('btc-fee-0', tjson({ f: '0' })),
    fmt('btc-txid-0x', tjson({ t: `0x${p0.t}` })),
    fmt('btc-txid-uppercase', tjson({ t: p0.t.toUpperCase() })),
    fmt('btc-sender-uppercase', tjson({ a: p0.a.toUpperCase() })),
    fmt('btc-sender-other-hrp', tjson({ a: L('testnet').address })),
    fmt('btc-sender-base58', tjson({ a: '1BoatSLRHtKNngkdXEeobR76b53LETtpyT' })),
    fmt('btc-to-other-hrp', tjson({ to: rv0('mainnet').address })),
    fmt('btc-q-nonce', tjson({ q: '7' })),
    fmt('btc-q-blockhash', tjson({ q: SOL_BH })),
    fmt('btc-q-uppercase', tjson({ q: p0.q.toUpperCase() })),
    fmt('btc-q-vout-leading-zero', tjson({ q: `${FUND1.txid}:00` })),
    fmt('btc-q-empty', tjson({ q: '' })),
    fmt('btc-q-trailing-comma', tjson({ q: `${p0.q},` })),
    fmt('btc-q-descending', tjson({ q: `${qb},${qa}` })),
    fmt('btc-q-duplicate', tjson({ q: `${qa},${qa}` })),
    fmt('btc-q-nine-outpoints', tjson({ q: Array.from({ length: 9 }, (_, i) => `${hex64(`ticket btc many ${i}`)}:0`).sort().join(',') })),
    fmt('btc-reveal-two-outpoints', tjson({ k: 'reveal', q: `${qa},${qb}` })),
    fmt('btc-eth-kind-commit-on-eth', ticketJson({ ...valid[0].payload, c: 'eth', t: `0x${p0.t}`, a: ETH_A.toLowerCase(), q: '7' } as TicketPayload)),
    fmt('btc-sol-kind-reveal-on-sol', ticketJson({ ...valid[0].payload, c: 'sol', k: 'reveal', a: SOL_B, q: SOL_BH } as TicketPayload)),
  ]

  // ---- decode vectors: a valid ticket for exactly these bytes (r, t and the MAC hold), the binding of the genuine tx it
  // was derived from (or the stated change), and ONE defect → relay.decode-mismatch (relay.btc-prevout where named).
  const decode: Array<Record<string, unknown>> = []
  const bad = (name: string, defect: string, tx: Built, b: Pick<TicketPayload, 'a' | 'k' | 'p' | 'to' | 'value' | 'f' | 'q'>, prevouts: unknown, guard = 'relay.decode-mismatch', o: { t?: string; w?: TicketPayload['w'] } = {}): void => {
    const x = issue(o.w ?? 'local', tx.raw, o.t ?? tx.id, b)
    decode.push({ name, defect, ticket: x.ticket, now: x.issuedAt + 1_000, context: ctxOf(o.w ?? 'local', tx.raw, prevouts), guard })
  }
  const cB = commitB('local', [FUND1], commitFee1)
  const lane = L('local').script, otherLane = btcOther('local').script, to0 = rv0('local').script
  const both = { ...fundOut(FUND1), ...fundOut(FUND2) }
  const withFee = (fee: bigint): Built => buildCommit([FUND1], commitOuts([FUND1], fee))
  bad('btc-commit-extra-input', 'the tx spends FUND1 and FUND2; the ticket declares FUND1 only', commit2, cB, both)
  bad('btc-commit-missing-input', 'the tx spends FUND1; the ticket declares FUND1 and FUND2', commit1, commitB('local', [FUND1, FUND2], commitFee1), both)
  bad('btc-commit-other-input', 'the tx spends FUND2; the ticket declares FUND1', buildCommit([FUND2], commitOuts([FUND2], 1_000n)), cB, both)
  bad('btc-commit-extra-output', 'a third output pays an attacker', buildCommit([FUND1], [...commitOuts([FUND1], commitFee1 + 600n), { script: otherLane, amount: 546n }]), cB, fundOut(FUND1))
  bad('btc-commit-two-change-outputs', 'the change is split in two outputs, both to the lane', buildCommit([FUND1], [{ script: to0, amount: revealAmount }, { script: lane, amount: 10_000n }, { script: lane, amount: FUND1.amount - revealAmount - commitFee1 - 10_000n }]), cB, fundOut(FUND1))
  bad('btc-commit-change-foreign', 'the change pays another address', buildCommit([FUND1], [{ script: to0, amount: revealAmount }, { script: otherLane, amount: FUND1.amount - revealAmount - commitFee1 }]), cB, fundOut(FUND1))
  bad('btc-commit-value', 'the reveal output pays one sat more than the ticket value', buildCommit([FUND1], commitOuts([FUND1], commitFee1 - 1n, to0, revealAmount + 1n)), cB, fundOut(FUND1))
  bad('btc-commit-value-less', 'the reveal output pays one sat less than the ticket value', buildCommit([FUND1], commitOuts([FUND1], commitFee1 + 1n, to0, revealAmount - 1n)), cB, fundOut(FUND1))
  bad('btc-commit-to', 'the reveal output pays another taproot address', buildCommit([FUND1], commitOuts([FUND1], commitFee1, btcOtherTr('local').script)), cB, fundOut(FUND1))
  bad('btc-commit-fee', 'the change is one sat lower: fee = f + 1', withFee(commitFee1 + 1n), cB, fundOut(FUND1))
  bad('btc-commit-fee-no-change', 'no change output: everything above the reveal output is fee, more than f', buildCommit([FUND1], [{ script: to0, amount: revealAmount }]), cB, fundOut(FUND1))
  bad('btc-commit-outputs-exceed-inputs', 'the chain says the input is worth less than the outputs: fee < 0', commit1, cB, { [outpointOf(FUND1)]: { value: String(revealAmount), script: hexOf(lane) } })
  bad('btc-commit-input-not-lane', 'the input pays another address than a', commit1, cB, fundOut(FUND1, 'other'))
  bad('btc-commit-to-not-taproot', 'the ticket `to` and the output are a P2WPKH address, not a taproot one', buildCommit([FUND1], commitOuts([FUND1], commitFee1, otherLane)), { ...cB, to: btcOther('local').address! }, fundOut(FUND1))
  bad('btc-commit-to-is-lane', 'the ticket `to` is the lane address itself', buildCommit([FUND1], commitOuts([FUND1], commitFee1, lane)), { ...cB, to: L('local').address! }, fundOut(FUND1))
  bad('btc-commit-duplicate-to', 'two outputs to `to`', buildCommit([FUND1], [{ script: to0, amount: revealAmount }, { script: to0, amount: FUND1.amount - revealAmount - commitFee1 }]), cB, fundOut(FUND1))
  bad('btc-commit-locktime', 'locktime 1', buildCommit([FUND1], commitOuts([FUND1], commitFee1), { lockTime: 1 }), cB, fundOut(FUND1))
  bad('btc-commit-unsigned', 'the inputs carry no signature', buildCommit([FUND1], commitOuts([FUND1], commitFee1), { sign: false }), cB, fundOut(FUND1))
  bad('btc-commit-tx-id', 'the ticket t is another tx\'s id (r still binds these bytes)', commit1, cB, fundOut(FUND1), 'relay.decode-mismatch', { t: commit2.id })
  bad('btc-commit-trailing-byte', 'a genuine commit followed by one more byte', { raw: Uint8Array.from([...commit1.raw, 0]), id: commit1.id }, cB, fundOut(FUND1))
  const unsigned1 = buildCommit([FUND1], commitOuts([FUND1], commitFee1), { sign: false }).raw
  const markedEmpty = Buffer.concat([unsigned1.subarray(0, 4), Buffer.from([0, 1]), unsigned1.subarray(4, unsigned1.length - 4), Buffer.from([0]), unsigned1.subarray(unsigned1.length - 4)])
  bad('btc-commit-empty-witness-marker', 'the segwit marker with an empty witness for the input: not the canonical serialization', { raw: markedEmpty, id: commit1.id }, cB, fundOut(FUND1))
  const SH = btc.SigHash
  for (const [n, sh, why] of [['none', SH.NONE, 'SIGHASH_NONE: anyone may re-spend the public signature with other outputs'], ['none-anyonecanpay', SH.NONE_ANYONECANPAY, 'SIGHASH_NONE|ANYONECANPAY'], ['single', SH.SINGLE, 'SIGHASH_SINGLE: only output 0 is signed, the change is free'],
    ['single-anyonecanpay', SH.SINGLE_ANYONECANPAY, 'SIGHASH_SINGLE|ANYONECANPAY'], ['all-anyonecanpay', SH.ALL_ANYONECANPAY, 'SIGHASH_ALL|ANYONECANPAY: further inputs may be added by anyone']] as const) {
    bad(`btc-commit-sighash-${n}`, `a commit input signed ${why}`, buildCommit([FUND1], commitOuts([FUND1], commitFee1), { sighash: sh }), cB, fundOut(FUND1))
  }
  bad('btc-commit-reveal-bytes', 'a genuine reveal tx under a commit ticket', revealFor('local', commit1), { ...cB, q: qOf({ txid: commit1.id, index: 0 }) }, commitPrev(commit1))
  bad('btc-commit-prevout-missing', 'the relay\'s chain read finds no such unspent output', commit1, cB, {}, 'relay.btc-prevout')
  bad('btc-commit-prevout-one-of-two-missing', 'the chain read finds FUND1 but not FUND2', commit2, commitB('local', [FUND1, FUND2], commitFee2), fundOut(FUND1), 'relay.btc-prevout')

  const R = (c: Built = commit1) => ({ txid: c.id, index: 0 })
  const rB = revealB('local', R(), revealFee)
  const dest = btcDest('local').script
  const rOut = [{ script: dest, amount: BTC_POSTAGE }]
  const rvWith = (list: Inscr[], outs: TxOut[] = rOut, o?: Parameters<typeof buildReveal>[3]): Built => buildReveal(btcReveal('local', list), commitOut(commit1), outs, o)
  const prev1 = commitPrev(commit1)
  bad('btc-reveal-body', 'one body byte changed: sha256(body) ≠ p', rvWith([inscr({ body: Uint8Array.from(body, (b, k) => (k === 3 ? b ^ 1 : b)) })]), rB, prev1)
  bad('btc-reveal-body-empty', 'an empty body', rvWith([inscr({ body: new Uint8Array(0) })]), rB, prev1)
  bad('btc-reveal-content-type-bare', 'content type text/plain (no charset)', rvWith([inscr({ tags: { contentType: 'text/plain' } })]), rB, prev1)
  bad('btc-reveal-content-type-html', 'content type text/html;charset=utf-8', rvWith([inscr({ tags: { contentType: 'text/html;charset=utf-8' } })]), rB, prev1)
  bad('btc-reveal-content-type-case', 'content type text/plain;charset=UTF-8', rvWith([inscr({ tags: { contentType: 'text/plain;charset=UTF-8' } })]), rB, prev1)
  bad('btc-reveal-no-content-type', 'no content-type tag', rvWith([inscr({ tags: {} })]), rB, prev1)
  bad('btc-reveal-extra-tag', 'a metaprotocol tag besides the content type', rvWith([inscr({ tags: { contentType: BTC_CT, metaprotocol: 'brc-20' } })]), rB, prev1)
  // ---- hand-assembled reveal leaves: parsers disagree on these (ord 0.29 vs micro-ordinals), so the relay pins the leaf byte for
  // byte to the canonical one-inscription script. Each is a real signed script-path spend of an output of that leaf.
  const sc = {
    push: (b: Uint8Array | number[]): number[] => {
      const a = Array.from(b)
      return a.length <= 75 ? [a.length, ...a] : a.length <= 255 ? [0x4c, a.length, ...a] : [0x4d, a.length & 255, a.length >> 8, ...a]
    },
    nonMinimalEmpty: [0x4c, 0x00], zero: [0x00], IF: [0x63], ENDIF: [0x68], CHECKSIG: [0xac], one: [0x51],
  }
  const T = (x: string): number[] => Array.from(enc.encode(x))
  const keyPart = (xo: Uint8Array = BTC_X): number[] => [...sc.push(xo), ...sc.CHECKSIG]
  const head = (ct: number[][] = [sc.push(T(BTC_CT))]): number[] => [...sc.zero, ...sc.IF, ...sc.push(T('ord')), ...sc.push([1]), ...ct.flat()]
  const honestEnv = (b: Uint8Array = TICKET_PAYLOAD): number[] => [...head(), ...sc.zero, ...sc.push(b), ...sc.ENDIF]
  const craft = (leaf: number[], o: { key?: Uint8Array; internal?: Uint8Array; annex?: boolean } = {}): Built => {
    const out = btc.p2tr(o.internal, { script: Uint8Array.from(leaf), leafVersion: 0xc0 }, BTC_NETS.local, true)
    const t = new btc.Transaction()
    t.addInput({ ...out, txid: commit1.id, index: 0, witnessUtxo: { script: out.script, amount: revealAmount } })
    t.addOutput({ script: dest, amount: BTC_POSTAGE })
    t.sign(o.key ?? BTC_PRIV, undefined, new Uint8Array(32))
    const inp = t.getInput(0), [cb, scr] = inp.tapLeafScript![0]
    t.updateInput(0, { finalScriptWitness: [inp.tapScriptSig![0][1], scr.subarray(0, scr.length - 1), btc.TaprootControlBlock.encode(cb), ...(o.annex ? [Uint8Array.from([0x50, 1])] : [])] })
    return { raw: t.extract(), id: t.id }
  }
  const HTML = T('<html>attacker content</html>')
  const SUFFIX = T('\n[APPENDED BY ATTACKER] the text above is retracted.')
  const rbad = (name: string, defect: string, leaf: number[], o?: Parameters<typeof craft>[1]): void => bad(name, defect, craft(leaf, o), rB, prev1)
  rbad('btc-reveal-cursed', 'a cursed envelope: the content-type tag is pushed as OP_1', [...keyPart(), ...sc.zero, ...sc.IF, ...sc.push(T('ord')), ...sc.one, ...sc.push(T(BTC_CT)), ...sc.zero, ...sc.push(TICKET_PAYLOAD), ...sc.ENDIF])
  rbad('btc-reveal-parser-op0-mid-body', 'S1: body, OP_0, then more pushes: ord appends the attacker suffix, micro-ordinals stops at the OP_0', [...keyPart(), ...head(), ...sc.zero, ...sc.push(TICKET_PAYLOAD), ...sc.zero, ...sc.push(SUFFIX), ...sc.ENDIF])
  rbad('btc-reveal-parser-hidden-first-envelope', 'S2: a first envelope opened by OP_PUSHDATA1 0x00 inside an unexecuted OP_0 OP_IF: ord numbers the attacker\'s text/html i0', [...keyPart(), ...sc.zero, ...sc.IF, ...sc.nonMinimalEmpty, ...sc.IF, ...sc.push(T('ord')), ...sc.push([1]), ...sc.push(T('text/html;charset=utf-8')), ...sc.zero, ...sc.push(HTML), ...sc.ENDIF, ...sc.ENDIF, ...honestEnv()])
  rbad('btc-reveal-parser-split-content-type', 'S3: the content-type tag pushed twice ("t" + the rest): micro-ordinals concatenates, ord keeps the first', [...keyPart(), ...head([sc.push(T('t')), sc.push([1]), sc.push(T('ext/plain;charset=utf-8'))]), ...sc.zero, ...sc.push(TICKET_PAYLOAD), ...sc.ENDIF])
  rbad('btc-reveal-body-two-pushes', 'the same body in two pushes (ord and micro-ordinals agree, the canonical script has one)', [...keyPart(), ...head(), ...sc.zero, ...sc.push(TICKET_PAYLOAD.subarray(0, 5)), ...sc.push(TICKET_PAYLOAD.subarray(5)), ...sc.ENDIF])
  rbad('btc-reveal-body-pushdata1', 'the body pushed with OP_PUSHDATA1 although it is under 76 bytes (non-minimal)', [...keyPart(), ...head(), ...sc.zero, 0x4c, TICKET_PAYLOAD.length, ...Array.from(TICKET_PAYLOAD), ...sc.ENDIF])
  rbad('btc-reveal-trailing-op', 'an OP_NOP after OP_ENDIF', [...keyPart(), ...honestEnv(), 0x61])
  rbad('btc-reveal-leaf-without-checksig', 'the key push without OP_CHECKSIG', [...sc.push(BTC_X), ...honestEnv()])
  rbad('btc-reveal-foreign-key', 'the leaf names (and is signed by) another key: the destination is not that key\'s p2tr', [...keyPart(pubSchnorr(BTC_OTHER_PRIV)), ...honestEnv()], { key: BTC_OTHER_PRIV })
  rbad('btc-reveal-internal-key', 'a single-leaf control block over the lane key instead of NUMS', [...keyPart(), ...honestEnv()], { internal: BTC_X })
  rbad('btc-reveal-annex', 'a fourth witness item starting with 0x50 (an annex)', [...keyPart(), ...honestEnv()], { annex: true })
  bad('btc-reveal-two-inscriptions', 'two inscriptions in one envelope script', rvWith([inscr(), inscr()]), rB, prev1)
  bad('btc-reveal-other-outpoint', 'the reveal spends another commit\'s output; the ticket declares commit1:0', buildReveal(rv0('local'), commitOut(commit2), rOut), rB, { ...prev1, ...commitPrev(commit2) })
  bad('btc-reveal-extra-input', 'a second input (a lane UTXO) besides the commit output', rvWith([inscr()], rOut, { extra: [FUND2] }), rB, { ...prev1, ...fundOut(FUND2) })
  bad('btc-reveal-extra-output', 'a second output', rvWith([inscr()], [...rOut, { script: otherLane, amount: 100n }]), rB, prev1)
  bad('btc-reveal-destination', 'the inscription output pays another address', rvWith([inscr()], [{ script: btcOtherTr('local').script, amount: BTC_POSTAGE }]), rB, prev1)
  bad('btc-reveal-value', 'the inscription output pays one sat more', rvWith([inscr()], [{ script: dest, amount: BTC_POSTAGE + 1n }]), rB, prev1)
  bad('btc-reveal-fee', 'f is one sat below the fee', revealFor('local', commit1), revealB('local', R(), revealFee - 1n), prev1)
  bad('btc-reveal-outputs-exceed-input', 'the chain says the commit output is worth less than the postage', revealFor('local', commit1), rB, { [`${commit1.id}:0`]: { value: String(BTC_POSTAGE - 1n), script: hexOf(to0) } })
  bad('btc-reveal-p2wpkh-spend', 'a plain P2WPKH spend of the declared outpoint: no inscription envelope', buildCommit([FUND1], [{ script: dest, amount: BTC_POSTAGE }]), revealB('local', FUND1, revealFee), fundOut(FUND1))
  bad('btc-reveal-locktime', 'locktime 1', rvWith([inscr()], rOut, { lockTime: 1 }), rB, prev1)
  bad('btc-reveal-unsigned', 'the input carries no witness', rvWith([inscr()], rOut, { sign: false }), rB, prev1)
  bad('btc-reveal-commit-bytes', 'a genuine commit tx under a reveal ticket', commit1, revealB('local', FUND1, commitFee1), fundOut(FUND1))
  bad('btc-reveal-kind-p', 'the ticket p is the hash of another body', revealFor('local', commit1), revealB('local', R(), revealFee, { p: sha256Hex('another body') }), prev1)
  bad('btc-reveal-prevout-missing', 'the relay\'s chain read finds no such output', revealFor('local', commit1), rB, {}, 'relay.btc-prevout')

  return {
    format: TICKET_PREFIX, key: TICKET_KEY.toString('hex'), ttlMs: TICKET_TTL_MS,
    lane: { local: L('local').address, testnet: L('testnet').address, mainnet: L('mainnet').address },
    fee: { rateSatPerVb: Number(BTC_RATE), commit1: String(commitFee1), commit2: String(commitFee2), reveal: String(revealFee), revealAmount: String(revealAmount), postage: String(BTC_POSTAGE) },
    rules: [
      'CC-8: the v2 ticket format of tickets.json with c = "btc", k = "commit" | "reveal"; the field meanings are in src/contracts/http.ts',
      'context = the relay\'s network, the route chain (btc), the raw tx (hex) and `prevouts`: what the relay\'s own chain read returns for each input outpoint ("<txid>:<vout>" → { value sats, script hex }); an outpoint absent from `prevouts` is one the read did not find',
      'every valid raw is a genuine signed tx (txid t, sha256 r); the signatures are deterministic',
      'each negative has one malformed ticket field (relay.send-ticket); each decode vector has exactly one defect in the signed tx or the chain read',
    ],
    valid: valid.map((v) => ({ name: v.name, payload: v.payload, issuedAt: v.issuedAt, ticket: v.ticket, raw: v.raw, now: v.issuedAt + 1_000, context: { network: v.payload.w, chain: 'btc', raw: v.raw, prevouts: v.prevouts } })),
    negatives,
    decode,
  }
}

// ---------------------------------------------------------------- leases

// PF-S I-1: the API binds an eth / sol job intent to the part IT plans from the stored message with the lane's own planner, so an
// intent the API must accept carries that part's sha256 (the http and lease vectors' job: eth-drain-null, MSG_A).
const plannedSha = (def: JobDef, text: string, chain: 'eth' | 'sol', copy: number, part = 1): string =>
  sha256Hex((planLaneCopy(laneConfigOf(chain, def.chains[chain]!, text), copy) as Array<{ payload: Uint8Array }>)[part - 1].payload)
// PF-S fix round 2 (R1-1): the planned part's length — an intent the API must accept declares the gas of THAT payload (ticket.fee-plan)
const plannedLen = (def: JobDef, text: string, chain: 'eth' | 'sol', copy: number, part = 1): number =>
  (planLaneCopy(laneConfigOf(chain, def.chains[chain]!, text), copy) as Array<{ payload: Uint8Array }>)[part - 1].payload.length

function leaseFixtures(jobId: string, def: JobDef): unknown {
  const t1: TxSpec = { txId: ethTx('t1'), copy: 1, part: 1, parts: 1, attempt: 1, eth: ethIntent(0, '12000', 60) }
  const t2: TxSpec = { txId: ethTx('t2'), copy: 2, part: 1, parts: 1, attempt: 1, eth: ethIntent(1, '12000', plannedLen(def, MSG_A, 'eth', 2)) }
  const intentData = (s: TxSpec): Record<string, unknown> => ({
    txId: s.txId, copy: s.copy, part: s.part, parts: s.parts, attempt: s.attempt, replaces: null,
    rawSha256: hex64(`raw:${s.txId}`), payloadSha256: plannedSha(def, MSG_A, 'eth', s.copy, s.part), reserved: '50000000000000', eth: s.eth,
  })
  const open = (s: TxSpec, gen: number): OpenIntent => ({ txId: s.txId, gen, copy: s.copy, part: s.part, attempt: s.attempt, eth: s.eth })
  const grant = (gen: number, at: number, holder: 'browser' | 'cli', openIntents: OpenIntent[]): LeaseGrant => ({ gen, ttlMs: LEASE_TTL_MS, expiresAt: T0 + at + LEASE_TTL_MS, holder, openIntents })
  return {
    jobId, chain: 'eth', start: T0, ttlMs: LEASE_TTL_MS,
    rules: [
      'at = ms after start on a fake clock; the job exists (created at seq 0) and is ARMED with eth READY',
      'a lease is live while now < expiresAt (expiresAt = acquire/renew time + ttlMs); at exactly expiresAt it has expired',
      'acquire: lease.held while a live lease exists (whoever holds it); else gen = 1 + the highest gen journaled; journals lease-expired for a lapsed lease, then lease-acquired',
      'renew with a wrong or expired gen: lease.lost; renew journals nothing; a grant always lists the open intents at that time',
      'every executor event needs the live gen (lease.stale); intent and clawback-intent also need every intent opened under an earlier gen reconciled by the current gen (lease.reconcile-first)',
      'refused steps journal nothing',
    ],
    steps: [
      { at: 0, op: 'acquire', holder: 'browser', expect: { grant: grant(1, 0, 'browser', []) } },
      { at: 1_000, op: 'append', gen: 1, type: 'intent', data: intentData(t1), expect: { ok: true, ticket: true } },
      { at: 2_000, op: 'append', gen: 1, type: 'sent', data: { txId: t1.txId, outcome: 'accepted', reason: null }, expect: { ok: true, ticket: false } },
      { at: 5_000, op: 'acquire', holder: 'cli', expect: { guard: 'lease.held' } },
      { at: 15_000, op: 'renew', gen: 1, expect: { guard: 'lease.lost' } },
      { at: 16_000, op: 'acquire', holder: 'cli', expect: { grant: grant(2, 16_000, 'cli', [open(t1, 1)]) } },
      { at: 17_000, op: 'append', gen: 2, type: 'intent', data: intentData(t2), expect: { guard: 'lease.reconcile-first' } },
      { at: 17_500, op: 'append', gen: 2, type: 'reconcile', data: { txId: t1.txId, outcome: 'included', block: '101', fee: FEE_ETH }, expect: { ok: true, ticket: false } },
      { at: 18_000, op: 'append', gen: 2, type: 'intent', data: intentData(t2), expect: { ok: true, ticket: true } },
      { at: 19_000, op: 'append', gen: 1, type: 'note', data: { text: 'from the old holder' }, expect: { guard: 'lease.stale' } },
      { at: 20_000, op: 'renew', gen: 2, expect: { grant: grant(2, 20_000, 'cli', [open(t2, 2)]) } },
    ],
    journalAfter: [['created', null], ['lease-acquired', 1], ['intent', 1], ['sent', 1], ['lease-expired', 1], ['lease-acquired', 2], ['reconcile', 2], ['intent', 2]],
  }
}

// ---------------------------------------------------------------- http (request/response pairs)

interface HttpFixture {
  name: string; covers: string; after: string | null
  request: { method: string; path: string; headers: Record<string, string | null>; body?: unknown; bodyText?: string; bodyFill?: { char: string; length: number } }
  response: { status: number; headers: Record<string, string>; body?: unknown; bodyText?: string; sse?: { journal: string } }
  volatile: string[]
}

function httpFixtures(o: { input: Input; def: JobDef; id: string; ticket: TicketPayload; vectors: Vector[] }): HttpFixture[] {
  const JSONH = { 'content-type': 'application/json; charset=utf-8' }
  const auth = { host: '{{host}}', authorization: 'Bearer {{token}}' }
  const post = { ...auth, 'content-type': 'application/json' }
  const err = (guard: string): unknown => ({ error: { guard, message: '(any text that never echoes input)' } })
  const created = cs({})
  const state0 = js({ chains: { eth: created } })
  const t1: TxSpec = { txId: ethTx('t1'), copy: 1, part: 1, parts: 1, attempt: 1, eth: ethIntent(0, '12000', 60) }
  const intentData = { txId: t1.txId, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: hex64(`raw:${t1.txId}`), payloadSha256: plannedSha(o.def, MSG_A, 'eth', 1), reserved: '50000000000000', eth: t1.eth }
  const armReq = { chains: ['eth'], confirm: { typed: null, amounts: {} }, caps: { eth: CAP.eth }, countdownSec: 15, stagger: [5, 10] }
  const armedAt = T0 + 60_000
  const id = o.id
  const v05 = o.vectors.find((v) => v.name === '05a-copies-done')!
  const f = (x: Partial<HttpFixture> & Pick<HttpFixture, 'name' | 'covers' | 'request' | 'response'>): HttpFixture => ({ after: null, volatile: [], ...x })
  return [
    f({ name: 'status-200', covers: 'GET /status', request: { method: 'GET', path: '/status', headers: auth },
      response: { status: 200, headers: JSONH, body: { network: 'local', networks: { eth: 'anvil · 31337', sol: 'Solana local' }, mainnetSends: 'LOCKED', jobSends: 'LOCKED', build: 'b1c2d3e4f5a6', confined: true, legacyLatch: 'clear', serverNowMs: T0 } },
      volatile: ['serverNowMs', 'build'] }),
    f({ name: 'messages-put-201', covers: 'PUT /messages/:sha256 (raw UTF-8 body)', request: { method: 'PUT', path: `/messages/${sha256Hex(MSG_A)}`, headers: { ...auth, 'content-type': 'text/plain; charset=utf-8' }, bodyText: MSG_A },
      response: { status: 201, headers: JSONH, body: { sha256: sha256Hex(MSG_A), bytes: enc.encode(MSG_A).length } } }),
    f({ name: 'jobs-create-201', covers: 'POST /jobs (new job, inline message) → 201 { id, def (canonical), state }', request: { method: 'POST', path: '/jobs', headers: post, body: o.input },
      response: { status: 201, headers: JSONH, body: { id, def: o.def, state: state0 } } }),
    f({ name: 'jobs-create-200', covers: 'POST /jobs again with the identical definition → 200, the existing job', after: 'jobs-create-201', request: { method: 'POST', path: '/jobs', headers: post, body: o.input },
      response: { status: 200, headers: JSONH, body: { id, def: o.def, state: state0 } } }),
    f({ name: 'jobs-create-400', covers: 'POST /jobs with an unknown key → 400 job.unknown-key', request: { method: 'POST', path: '/jobs', headers: post, body: { ...o.input, autoArm: true } },
      response: { status: 400, headers: JSONH, body: err('job.unknown-key') }, volatile: ['error.message'] }),
    f({ name: 'jobs-get-200', covers: 'GET /jobs/:id', request: { method: 'GET', path: `/jobs/${id}`, headers: auth },
      response: { status: 200, headers: JSONH, body: { id, def: o.def, state: state0, leases: { eth: null }, seq: 0, serverNowMs: T0 } }, volatile: ['serverNowMs'] }),
    f({ name: 'jobs-get-404', covers: 'GET /jobs/:id for an unknown id → 404 job.missing', request: { method: 'GET', path: '/jobs/0000000000000000', headers: auth },
      response: { status: 404, headers: JSONH, body: err('job.missing') }, volatile: ['error.message'] }),
    f({ name: 'lease-acquire-200', covers: 'lease acquire → LeaseGrant gen 1', request: { method: 'POST', path: `/jobs/${id}/chains/eth/lease`, headers: post, body: { op: 'acquire', holder: 'browser' } },
      response: { status: 200, headers: JSONH, body: { gen: 1, ttlMs: LEASE_TTL_MS, expiresAt: T0 + LEASE_TTL_MS, holder: 'browser', openIntents: [] } }, volatile: ['expiresAt'] }),
    f({ name: 'lease-acquire-409-held', covers: 'a second acquire while the lease is live → 409 lease.held', after: 'lease-acquire-200', request: { method: 'POST', path: `/jobs/${id}/chains/eth/lease`, headers: post, body: { op: 'acquire', holder: 'cli' } },
      response: { status: 409, headers: JSONH, body: err('lease.held') }, volatile: ['error.message'] }),
    f({ name: 'events-append-intent-200', covers: 'append intent under the live gen → { seq, ticket }', request: { method: 'POST', path: `/jobs/${id}/chains/eth/events`, headers: post, body: { gen: 1, type: 'intent', data: intentData } },
      // CC-1 (S1): the example ticket binds this request's rawSha256 (r), as a real API's does. CC-3 (v2): and the job's key
      // (a, lower case), the kind, the payloadSha256 and the worst-case fee gas × maxFee of this intent; CC-3a: its nonce. PF-S I-1: p is the
      // API's plan of copy 1 part 1 (= this intent's payloadSha256) and to the publish mode's recipient (eth.calldata.null: 0x000…000).
      response: { status: 200, headers: JSONH, body: { seq: 5, ticket: ticketOf({
        ...o.ticket, t: intentData.txId, r: intentData.rawSha256, a: o.def.chains.eth!.keyAddress.toLowerCase(), k: 'job', p: intentData.payloadSha256, to: NULL_ETH, value: null,
        f: String(BigInt(t1.eth!.gas) * BigInt(t1.eth!.maxFee)), q: String(t1.eth!.nonce), x: `${t1.eth!.gas}:${t1.eth!.tip}:${t1.eth!.maxFee}`,
      }) } }, volatile: ['seq', 'ticket'] }),
    f({ name: 'events-append-409-stale', covers: 'append from the old holder after a takeover (gen 1, live gen 2) → 409 lease.stale', request: { method: 'POST', path: `/jobs/${id}/chains/eth/events`, headers: post, body: { gen: 1, type: 'note', data: { text: 'from the old holder' } } },
      response: { status: 409, headers: JSONH, body: err('lease.stale') }, volatile: ['error.message'] }),
    f({ name: 'events-append-409-reconcile-first', covers: 'intent under gen 2 before reconciling gen 1\'s open intent → 409 lease.reconcile-first', request: { method: 'POST', path: `/jobs/${id}/chains/eth/events`, headers: post, body: { gen: 2, type: 'intent', data: { ...intentData, txId: ethTx('t2'), copy: 2, payloadSha256: plannedSha(o.def, MSG_A, 'eth', 2), rawSha256: hex64(`raw:${ethTx('t2')}`), eth: ethIntent(1, '12000', plannedLen(o.def, MSG_A, 'eth', 2)) } } },
      response: { status: 409, headers: JSONH, body: err('lease.reconcile-first') }, volatile: ['error.message'] }),
    f({ name: 'arm-200-local', covers: 'arm on local, no typed confirmation → { armed: ArmRecord }', request: { method: 'POST', path: `/jobs/${id}/arm`, headers: post, body: armReq },
      response: { status: 200, headers: JSONH, body: { armed: { armedAt, releaseAt: armedAt + 15_000, countdownSec: 15, schedule: { order: ['eth'], offsetSec: { eth: 0 } }, caps: { eth: CAP.eth }, sources: {} } } },
      volatile: ['armed.armedAt', 'armed.releaseAt'] }),
    f({ name: 'status-401-token-missing', covers: 'no Authorization → 401 api.token', request: { method: 'GET', path: '/status', headers: { host: '{{host}}', authorization: null } },
      response: { status: 401, headers: JSONH, body: err('api.token') }, volatile: ['error.message'] }),
    f({ name: 'status-401-token-wrong', covers: 'wrong token → 401 api.token', request: { method: 'GET', path: '/status', headers: { host: '{{host}}', authorization: 'Bearer wrong-token' } },
      response: { status: 401, headers: JSONH, body: err('api.token') }, volatile: ['error.message'] }),
    f({ name: 'status-403-host', covers: 'Host other than 127.0.0.1:<port> → 403 api.host', request: { method: 'GET', path: '/status', headers: { ...auth, host: 'localhost:{{port}}' } },
      response: { status: 403, headers: JSONH, body: err('api.host') }, volatile: ['error.message'] }),
    f({ name: 'status-403-origin', covers: 'Origin of another network\'s page → 403 api.origin', request: { method: 'GET', path: '/status', headers: { ...auth, origin: 'http://127.0.0.1:5190' } },
      response: { status: 403, headers: JSONH, body: err('api.origin') }, volatile: ['error.message'] }),
    f({ name: 'status-403-fetch-site', covers: 'Sec-Fetch-Site: cross-site → 403 api.fetch-site', request: { method: 'GET', path: '/status', headers: { ...auth, 'sec-fetch-site': 'cross-site' } },
      response: { status: 403, headers: JSONH, body: err('api.fetch-site') }, volatile: ['error.message'] }),
    f({ name: 'jobs-create-415', covers: 'POST with text/plain → 415 api.content-type', request: { method: 'POST', path: '/jobs', headers: { ...auth, 'content-type': 'text/plain' }, bodyText: '{}' },
      response: { status: 415, headers: JSONH, body: err('api.content-type') }, volatile: ['error.message'] }),
    f({ name: 'jobs-create-413', covers: 'POST with a 65,537-byte body → 413 api.body-cap', request: { method: 'POST', path: '/jobs', headers: post, bodyFill: { char: 'a', length: 65_537 } },
      response: { status: 413, headers: JSONH, body: err('api.body-cap') }, volatile: ['error.message'] }),
    f({ name: 'stream-05a', covers: 'GET /jobs/:id/events?from=<seq> (SSE; Last-Event-ID honoured; heartbeat every 15 s)', request: { method: 'GET', path: `/jobs/${jobIdOf(v05.def)}/events`, headers: auth },
      response: { status: 200, headers: { 'content-type': 'text/event-stream; charset=utf-8' }, sse: { journal: 'journals/05a-copies-done.jsonl' } } }),
  ]
}

// ---------------------------------------------------------------- arm, events, parts

function armFixtures(): { confirm: unknown; schedule: unknown } {
  const over = { ...CAP.eth, overCap: true, usd: 14.2, planned: '0.0057' }
  const req = (o: Record<string, unknown> = {}): Record<string, unknown> => ({ chains: ['eth'], confirm: { typed: null, amounts: {} }, caps: { eth: CAP.eth }, ...o })
  const cases: Array<[string, string, Record<string, unknown>, string | null]> = [
    ['local without typed', 'local', req(), null],
    ['testnet without typed', 'testnet', req(), null],
    ['mainnet without typed', 'mainnet', req(), 'arm.typed'],
    ['mainnet typed "broadcast"', 'mainnet', req({ confirm: { typed: 'broadcast', amounts: {} } }), null],
    ['mainnet typed "Broadcast" (exact match only)', 'mainnet', req({ confirm: { typed: 'Broadcast', amounts: {} } }), 'arm.typed'],
    ['over the cap, exact planned amount', 'local', req({ caps: { eth: over }, confirm: { typed: null, amounts: { eth: '0.0057' } } }), null],
    ['over the cap, wrong amount', 'local', req({ caps: { eth: over }, confirm: { typed: null, amounts: { eth: '0.006' } } }), 'arm.amount'],
    ['over the cap, amount missing', 'local', req({ caps: { eth: over } }), 'arm.amount'],
    ['empty chains', 'local', req({ chains: [] }), 'arm.chains'],
    ['duplicate chains', 'local', req({ chains: ['eth', 'eth'] }), 'arm.chains'],
    ['unknown chain', 'local', req({ chains: ['doge'] }), 'arm.chains'],
    ['btc off the local network', 'testnet', req({ chains: ['btc'], caps: { btc: { nativeCap: '1000000', usd: 0, priceAt: null, overCap: false, planned: '0.00003472' } } }), 'arm.chains'],
    ['btc on local needs its cap', 'local', req({ chains: ['btc'] }), 'arm.amount'],
    ['btc on local with its cap', 'local', req({ chains: ['btc'], caps: { btc: { nativeCap: '1000000', usd: 0, priceAt: null, overCap: false, planned: '0.00003472' } } }), null],
    ['mainnet countdown 60', 'mainnet', req({ confirm: { typed: 'broadcast', amounts: {} }, countdownSec: 60 }), null],
    ['mainnet countdown 30', 'mainnet', req({ confirm: { typed: 'broadcast', amounts: {} }, countdownSec: 30 }), 'arm.countdown'],
    ['local countdown 5', 'local', req({ countdownSec: 5 }), null],
    ['local countdown 300', 'local', req({ countdownSec: 300 }), null],
    ['local countdown 4', 'local', req({ countdownSec: 4 }), 'arm.countdown'],
    ['local countdown 301', 'local', req({ countdownSec: 301 }), 'arm.countdown'],
    ['local countdown 7.5', 'local', req({ countdownSec: 7.5 }), 'arm.countdown'],
    ['local stagger [5, 10]', 'local', req({ stagger: [5, 10] }), null],
    ['local stagger [10, 5]', 'local', req({ stagger: [10, 5] }), 'arm.stagger'],
    ['testnet stagger (local only)', 'testnet', req({ stagger: [30, 300] }), 'arm.stagger'],
    ['mainnet stagger (local only)', 'mainnet', req({ confirm: { typed: 'broadcast', amounts: {} }, stagger: [30, 300] }), 'arm.stagger'],
  ]
  const armed: ArmRecord = { armedAt: T0, releaseAt: T0 + 60_000, countdownSec: 60, schedule: { order: ['sol', 'eth'], offsetSec: { sol: 0, eth: 123 } }, caps: { eth: CAP.eth, sol: CAP.sol }, sources: {} }
  return {
    confirm: { rules: ['checkArmConfirm(network, req) → refusal guard or none; each case has one defect'], cases: cases.map(([name, network, request, guard]) => ({ name, network, request, guard })) },
    schedule: {
      rules: [
        'drawSchedule(chains, range, randInt): order is a permutation of chains (CSPRNG via randInt); offsetSec[order[0]] = 0; offsetSec[order[1]] = range[0] + randInt(range[1] - range[0] + 1)',
        'rand "zero": randInt always returns 0; rand "max": randInt(m) returns m - 1',
        'startAt(armed, chain) = armed.releaseAt + armed.schedule.offsetSec[chain] * 1000',
      ],
      draws: [
        { chains: ['eth', 'sol'], range: [30, 300], rand: 'zero', secondOffset: 30 },
        { chains: ['eth', 'sol'], range: [30, 300], rand: 'max', secondOffset: 300 },
        { chains: ['eth', 'sol'], range: [5, 10], rand: 'zero', secondOffset: 5 },
        { chains: ['eth', 'sol'], range: [5, 10], rand: 'max', secondOffset: 10 },
        { chains: ['eth'], range: [30, 300], rand: 'max', secondOffset: null },
      ],
      startAt: [
        { armed, chain: 'sol', at: T0 + 60_000 },
        { armed, chain: 'eth', at: T0 + 60_000 + 123_000 },
      ],
    },
  }
}

function eventFixtures(): unknown {
  const t = ethTx('t1')
  const intentData = { txId: t, copy: 1, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: hex64(`raw:${t}`), payloadSha256: hex64('payload:1:1'), reserved: '1', eth: ethIntent(0, '12000', 60) }
  const { rawSha256: _drop, ...noRaw } = intentData
  return {
    rules: [
      'validateEvent(type, data, by): every line of every journals/*.jsonl passes (with its own type, data and by)',
      'each case below has one defect; strings in data are bounded (note.text ≤ 200, any other string ≤ 512)',
    ],
    cases: [
      { name: 'unknown type', type: 'teleport', data: {}, by: 'browser', guard: 'event.type' },
      { name: 'extra key', type: 'key-loaded', data: { address: ETH_A, secret: 'x' }, by: 'browser', guard: 'event.shape' },
      { name: 'intent without rawSha256', type: 'intent', data: noRaw, by: 'browser', guard: 'event.shape' },
      { name: 'intent with both eth and sol', type: 'intent', data: { ...intentData, sol: solIntent('x', 1, 0, null, '5000') }, by: 'browser', guard: 'event.shape' },
      { name: 'sent outcome not in the enum', type: 'sent', data: { txId: t, outcome: 'maybe', reason: null }, by: 'browser', guard: 'event.shape' },
      { name: 'note text of 201 chars', type: 'note', data: { text: 'n'.repeat(201) }, by: 'cli', guard: 'event.shape' },
      { name: 'string of 513 chars', type: 'paused', data: { reason: 'r'.repeat(513) }, by: 'cli', guard: 'event.shape' },
      { name: 'armed from a browser', type: 'armed', data: { armedAt: T0, releaseAt: T0 + 60_000, countdownSec: 60, schedule: { order: ['eth'], offsetSec: { eth: 0 } }, caps: { eth: CAP.eth }, sources: {} }, by: 'browser', guard: 'event.by' },
      { name: 'intent from the api', type: 'intent', data: intentData, by: 'api', guard: 'event.by' },
    ],
  }
}

// CC-2a: the typed claw-back amount. checkClawbackConfirm(state, chain, data, confirm?) → arm.amount or none. Only the
// members the rule reads are set in each state (armed caps, the chain's spent and clawback).
function clawbackConfirmFixtures(): unknown {
  const st = (spent: string, clawback: unknown = null, nativeCap = '1000000'): unknown =>
    ({ armed: { caps: { eth: { nativeCap }, sol: { nativeCap } } }, chains: { eth: { spent, clawback }, sol: { spent, clawback } } })
  const eth = (value: string): Record<string, unknown> => ({ txId: ethTx('claw'), to: ETH_B, value, rawSha256: hex64('raw:claw'), eth: { nonce: 1, tip: '1', maxFee: '10', gas: '21000', to: ETH_B } })
  const sol = (value: string): Record<string, unknown> => ({ txId: solSig('claw'), to: SOL_B, value, rawSha256: hex64('raw:sol claw'), sol: solIntent('claw', 9, 0, null, '5000') })
  const cases: Array<[string, 'eth' | 'sol', unknown, Record<string, unknown>, unknown, string | null]> = [
    ['fits: value + gas × maxFee = what is left of the cap (999,900)', 'eth', st('100'), eth('789900'), undefined, null],
    ['one wei over, no typed amount', 'eth', st('100'), eth('789901'), undefined, 'arm.amount'],
    ['over, the exact amount typed (value + gas × maxFee)', 'eth', st('100'), eth('789901'), { amount: '999901' }, null],
    ['over, a typed amount one wei short', 'eth', st('100'), eth('789901'), { amount: '999900' }, 'arm.amount'],
    ['fits, but a typed amount that is not value + fee', 'eth', st('100'), eth('789900'), { amount: '789900' }, 'arm.amount'],
    ['fits, the exact amount typed anyway', 'eth', st('100'), eth('789900'), { amount: '999900' }, null],
    ['typed amount with an extra member', 'eth', st('100'), eth('789901'), { amount: '999901', chain: 'eth' }, 'arm.amount'],
    ['typed amount not in decimal base units', 'eth', st('100'), eth('789901'), { amount: '999901.0' }, 'arm.amount'],
    ['typed amount as a number', 'eth', st('100'), eth('789901'), { amount: 999901 }, 'arm.amount'],
    ['sol: value + fee fits', 'sol', st('100'), sol('994900'), undefined, null],
    ['sol: one lamport over', 'sol', st('100'), sol('994901'), undefined, 'arm.amount'],
    ['sol: over, the exact amount typed', 'sol', st('100'), sol('994901'), { amount: '999901' }, null],
    ['a malformed spend', 'eth', st('1e3'), eth('1'), undefined, 'arm.amount'],
    ['no armed cap', 'eth', { armed: null, chains: { eth: { spent: '0', clawback: null } } }, eth('1'), undefined, 'arm.amount'],
    ['a landed claw-back\'s value counts against the cap', 'eth', st('100', { txId: ethTx('earlier'), to: ETH_B, value: '500000', ok: true, landed: true }), eth('289901'), undefined, 'arm.amount'],
  ]
  return {
    rules: [
      'checkClawbackConfirm(state, chain, data, confirm?) → arm.amount or none (types.ts claw-back note, CC-2a)',
      'need = value + worst-case fee (eth gas × maxFee, sol fee); room = nativeCap − spent − (a landed claw-back\'s value)',
      'no confirm: need ≤ room; a confirm: exactly { amount: String(need) } (decimal base units, no other member), whether or not need fits',
    ],
    cases: cases.map(([name, chain, state, data, confirm, guard]) => ({ name, chain, state, data, ...(confirm === undefined ? {} : { confirm }), guard })),
  }
}

function partFixtures(): unknown {
  const text = 'A text long enough to need parts.\n'
  const sha = sha256Hex(text)
  const inputs: Array<[string, PartHeaderInput, boolean?]> = [
    ['single tx, no copy marker', { part: 1, parts: 1, sha256: sha, copy: null, copies: null }],
    ['single tx, copy 1 of 5 (copy 1 never has a marker)', { part: 1, parts: 1, sha256: sha, copy: 1, copies: 5 }],
    ['single tx, copy 2 of 5', { part: 1, parts: 1, sha256: sha, copy: 2, copies: 5 }],
    ['single tx, drain copy 3 (M unknown)', { part: 1, parts: 1, sha256: sha, copy: 3, copies: null }],
    ['part 1 of 3', { part: 1, parts: 3, sha256: sha, copy: null, copies: null }],
    ['part 2 of 3', { part: 2, parts: 3, sha256: sha, copy: null, copies: null }],
    ['part 3 of 3, copy 1 of 2', { part: 3, parts: 3, sha256: sha, copy: 1, copies: 2 }],
    ['part 1 of 3, copy 2 of 2', { part: 1, parts: 3, sha256: sha, copy: 2, copies: 2 }],
    ['part 3 of 3, copy 2 of 2', { part: 3, parts: 3, sha256: sha, copy: 2, copies: 2 }],
    ['part 12 of 104, drain copy 7', { part: 12, parts: 104, sha256: sha, copy: 7, copies: null }],
    // CC-1a: the writer-forced one-part header
    ['single tx, forced header', { part: 1, parts: 1, sha256: sha, copy: null, copies: null }, true],
    ['single tx, forced header, copy 1 of 5 (no marker)', { part: 1, parts: 1, sha256: sha, copy: 1, copies: 5 }, true],
    ['single tx, forced header, copy 2 of 5', { part: 1, parts: 1, sha256: sha, copy: 2, copies: 5 }, true],
    ['single tx, forced header, drain copy 3', { part: 1, parts: 1, sha256: sha, copy: 3, copies: null }, true],
    ['part 2 of 3, force changes nothing', { part: 2, parts: 3, sha256: sha, copy: null, copies: null }, true],
  ]
  const headers = inputs.map(([name, input, force]) => ({ name, input, ...(force === true ? { force } : {}), prefix: partPrefix(input, { force: force === true }) }))
  const lookalike = `[2/3 ${sha.slice(0, 8)}]\nuser text whose first line looks like a header`, lsha = sha256Hex(lookalike)
  const h = sha.slice(0, 8)
  const payloads: Array<[string, string]> = [
    ['no header', 'plain text\n'],
    ['part 1 of 3', `[1/3 ${h} sha256=${sha}]\nchunk one`],
    ['part 2 of 3 with copy 2/2', `[2/3 ${h}] [copy 2/2]\nchunk two`],
    ['single tx copy 2 of 5', '[copy 2/5]\nthe whole text'],
    ['single tx drain copy 3', '[copy 3]\nthe whole text'],
    ['provisional "#" form (not this format)', `[2/3 #${h}] chunk`],
    ['header without LF (not this format)', `[2/3 ${h}] chunk`],
    ['leading zero', `[02/3 ${h}]\nchunk`],
    ['k > N', `[4/3 ${h}]\nchunk`],
    ['N = 1 header whose sha256 does not verify (plain text)', `[1/1 ${h} sha256=${sha}]\nchunk`],
    ['single tx, forced header (sha256 verifies)', `[1/1 ${h} sha256=${sha}]\n${text}`],
    ['single tx, forced header with copy 2/5', `[1/1 ${h} sha256=${sha}] [copy 2/5]\n${text}`],
    ['single tx, forced header with drain copy 3', `[1/1 ${h} sha256=${sha}] [copy 3]\n${text}`],
    ['single tx, forced header over a header-looking text', `[1/1 ${lsha.slice(0, 8)} sha256=${lsha}]\n${lookalike}`],
    ['single tx, forced header, h8 differs from the digest', `[1/1 00000000 sha256=${sha}]\n${text}`],
    ['single tx, forced header, copy marker 1', `[1/1 ${h} sha256=${sha}] [copy 1/5]\n${text}`],
    ['part 1 without sha256', `[1/3 ${h}]\nchunk`],
    ['part 2 with sha256', `[2/3 ${h} sha256=${sha}]\nchunk`],
    ['h8 differs from the digest', `[1/3 00000000 sha256=${sha}]\nchunk`],
    ['copy marker copy 1', `[2/3 ${h}] [copy 1/2]\nchunk`],
    ['copies < copy', `[2/3 ${h}] [copy 3/2]\nchunk`],
    ['single tx copy 1 marker', '[copy 1/5]\ntext'],
    ['uppercase hex', `[2/3 ${h.toUpperCase()}]\nchunk`],
  ]
  return {
    format: PART_FORMAT,
    text, sha256: sha,
    rules: [
      'partPrefix(input, { force }) = prefix exactly; parsePart(payload) = parsed exactly (a payload that does not match the grammar with every cross-field rule parses as "no header")',
      'CC-1a: a one-part header [1/1 <h8> sha256=<64hex>] parses only when sha256(body) verifies; force is what the writer sets when the text\'s own first line parses as a header',
    ],
    headers,
    parse: payloads.map(([name, payload]) => ({ name, payload, parsed: parsePart(payload) })),
  }
}

// ---------------------------------------------------------------- assemble

export function buildFixtures(): Map<string, string | Uint8Array> {
  const files = new Map<string, string | Uint8Array>()
  const add = (p: string, c: string | Uint8Array): void => { if (files.has(p)) throw new Error(`duplicate ${p}`); files.set(p, c) }

  add('src/contracts/vt-job-1.schema.json', pretty(buildSchema()))
  const jobs = jobFixtures(add)

  // messages
  assertNoBip39Run(SEALED_LIKE, 'sealed-like.txt')
  const mb = multibyte5k()
  if (mb.normalize('NFC') !== mb) throw new Error('multibyte-5k is not NFC')
  assertNoBip39Run(mb, 'multibyte-5k.txt')
  add('contract/fixtures/messages/sealed-like.txt', SEALED_LIKE)
  add('contract/fixtures/messages/multibyte-5k.txt', mb)
  add('contract/fixtures/messages/valid.json', pretty({
    'sealed-like.txt': { bytes: enc.encode(SEALED_LIKE).length, sha256: sha256Hex(SEALED_LIKE), warnings: ['hex64'] },
    'multibyte-5k.txt': { bytes: enc.encode(mb).length, sha256: sha256Hex(mb), warnings: [] },
  }))
  const bad: Array<[string, string | Uint8Array, string]> = [
    ['crlf.txt', 'first line\r\nsecond line\r\n', 'message.control'],
    ['nfd.txt', 'café au lait\n', 'message.nfc'],
    ['bidi.txt', 'abc ‮dcba‬\n', 'message.control'],
    ['bom.txt', '﻿starts with a byte order mark\n', 'message.control'],
    ['age-secret.txt', `key: AGE-SECRET-KEY-1${'Q'.repeat(58)}\n`, 'message.secret'],
    ['bip39-12.txt', `${'abandon '.repeat(11)}about\n`, 'message.secret'],
    ['b58-88.txt', `token ${b58of88()}\n`, 'message.secret'],
    ['ip.txt', `relay at ${CANARY} port 443\n`, 'message.ip-like'],
    ['ipv6.txt', 'node [2001:db8::1]:8545\n', 'message.ip-like'],
    ['empty.txt', '', 'message.empty'],
    ['invalid-utf8.txt', new Uint8Array([0x61, 0x62, 0x63, 0xff, 0xfe, 0x20, 0x64, 0x0a]), 'message.utf8'],
  ]
  for (const [f, c] of bad) add(`contract/fixtures/messages/bad/${f}`, c)
  add('contract/fixtures/messages/bad/expected.json', pretty(Object.fromEntries(bad.map(([f, , g]) => [f, g]))))

  // journals
  const msgJ = 'Journal vector text.\n'
  const jdef = (name: string, chains: Partial<Record<Chain, JobChainDef>>, text = msgJ): JobDef => ({ format: 'vt-job/1', network: 'local', name, messageSha256: sha256Hex(text), messageBytes: enc.encode(text).length, chains })
  const eDrain = ethChain({ clawbackTo: ETH_B }) as unknown as JobChainDef
  const eCopies = ethChain({ mode: { copies: 1 }, feeStrategy: 'economy', clawbackTo: ETH_B }) as unknown as JobChainDef
  const long = 'x'.repeat(4_380)
  const defs: Record<string, JobDef> = {
    ethDrain: jdef('journal vector eth drain', { eth: eDrain }),
    ethCopies1: jdef('journal vector eth copies 1', { eth: eCopies }),
    solCopies1: jdef('journal vector sol copies 1', { sol: solChain({ mode: { copies: 1 } }) as unknown as JobChainDef }),
    solCopies2: jdef('journal vector sol copies 2 of a 5-part text', { sol: solChain({ mode: { copies: 2 } }) as unknown as JobChainDef }, long),
    both: jdef('journal vector eth and sol', { eth: eCopies, sol: solChain() as unknown as JobChainDef }),
  }
  const vectors = journalVectors(defs)
  for (const v of vectors) {
    add(`contract/fixtures/journals/${v.name}.jsonl`, v.j.text())
    add(`contract/fixtures/journals/${v.name}.def.json`, pretty(v.def))
    add(`contract/fixtures/journals/${v.name}.state.json`, pretty(v.state))
  }
  add('contract/fixtures/journals/index.json', pretty({
    rules: [
      'reduce(def, events) deep-equals <name>.state.json; def = <name>.def.json; events = the parsed lines of <name>.jsonl',
      'the hash chain is valid: seq 0..n, prev = sha256 hex of the previous line\'s bytes (without its \\n), "" at seq 0; corruption vectors live in S1\'s tests',
      'created.data.jobId = jobId(def); created.data.defSha256 = sha256Hex(canonicalJson(def))',
      'reducer semantics: src/contracts/types.ts header',
    ],
    vectors: vectors.map((v) => ({ name: v.name, description: v.description, jobPhase: v.state.phase, chains: Object.fromEntries(Object.entries(v.state.chains).map(([c, s]) => [c, s!.phase])) })),
  }))

  // tickets, leases, http, arm, events, parts
  const tk = ticketFixtures(jobs.idOf('eth-drain-null.json'))
  add('contract/fixtures/tickets.json', pretty(tk.json))
  add('contract/fixtures/tickets-btc.json', pretty(btcTicketFixtures(jobs.idOf('eth-drain-null.json'))))
  add('contract/fixtures/leases.json', pretty(leaseFixtures(jobs.idOf('eth-drain-null.json'), jobs.defOf('eth-drain-null.json'))))
  for (const h of httpFixtures({ input: jobs.valid['eth-drain-null.json'], def: jobs.defOf('eth-drain-null.json'), id: jobs.idOf('eth-drain-null.json'), ticket: tk.firstPayload, vectors })) {
    add(`contract/fixtures/http/${h.name}.json`, pretty(h))
  }
  const armF = armFixtures()
  add('contract/fixtures/arm/confirm.json', pretty(armF.confirm))
  add('contract/fixtures/arm/clawback-confirm.json', pretty(clawbackConfirmFixtures()))
  add('contract/fixtures/arm/schedule.json', pretty(armF.schedule))
  add('contract/fixtures/events/invalid.json', pretty(eventFixtures()))
  add('contract/fixtures/parts/headers.json', pretty(partFixtures()))
  return files
}

export function fixtureDrift(files = buildFixtures()): string[] {
  const drift: string[] = []
  for (const [rel, want] of files) {
    let got: Buffer | null = null
    try { got = readFileSync(join(ROOT, rel)) } catch { /* missing */ }
    const w = typeof want === 'string' ? Buffer.from(want, 'utf8') : Buffer.from(want)
    if (got === null || !got.equals(w)) drift.push(rel)
  }
  return drift
}

if (import.meta.main) {
  const mode = process.argv[2]
  const files = buildFixtures()
  if (mode === '--write') {
    for (const [rel, c] of files) { mkdirSync(dirname(join(ROOT, rel)), { recursive: true }); writeFileSync(join(ROOT, rel), c) }
    console.log(`wrote ${files.size} files`)
  } else if (mode === '--check') {
    const d = fixtureDrift(files)
    for (const f of d) console.log(`DRIFT ${f}`)
    console.log(d.length === 0 ? `ok: ${files.size} files match` : `${d.length} file(s) differ`)
    process.exitCode = d.length === 0 ? 0 : 1
  } else {
    console.error('usage: node packages/core/contract/gen-fixtures.ts --write | --check')
    process.exitCode = 2
  }
}

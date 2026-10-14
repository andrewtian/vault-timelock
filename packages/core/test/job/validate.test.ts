// normalizeJob (vt-job/1, spec §4.1 + R71 + R73). Mapped by test/mutation/guards.json: every job.* guard of the
// validator. ALL DATA IS SYNTHETIC (fixture addresses are derived from labels; no key exists for any of them).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync } from 'node:fs'
import { base58 } from '@scure/base'
import { getAddress } from 'viem'
import { jobId, normalizeJob, suggestedBtcFeeCeiling, canonicalJson, sha256Hex } from '../../src/job/index.ts'
import type { JobDef, Network } from '../../src/contracts/index.ts'
import { fixture, guardOf, readJson, refusalOf } from './helpers.ts'

type Obj = Record<string, unknown>
const valid = readJson<Record<string, { id: string; def: JobDef }>>('jobs/valid/expected.json')
const invalid = readJson<Record<string, string>>('jobs/invalid/expected.json')
const reversed = (v: unknown): unknown => Array.isArray(v) ? v.map(reversed)
  : v !== null && typeof v === 'object' ? Object.fromEntries(Object.entries(v as object).reverse().map(([k, x]) => [k, reversed(x)])) : v
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T

const BASE = readJson<Obj>('jobs/valid/eth-drain-null.json')
const SOL = readJson<Obj>('jobs/valid/sol-copies.json')
const ETH_A = '0x8739Eb87B3d11f221Df63454F8D229a1A4F4049C'
const SOL_A = '9xx7qC7uwTAeaSo7T5Gk9canYBosFh1pMQaDmQEa83Tb'
const job = (patch: (j: Obj) => void, base: Obj = BASE): Obj => { const j = clone(base); patch(j); return j }
const eth = (j: Obj): Obj => (j.chains as Obj).eth as Obj
const sol = (j: Obj): Obj => (j.chains as Obj).sol as Obj
const g = (input: unknown, network: Network = 'local'): string | null => guardOf(() => normalizeJob(input, { network }))

test('every fixture file is listed in its expected.json', () => {
  assert.deepEqual(readdirSync(fixture('jobs/valid')).filter((f) => f !== 'expected.json').sort(), Object.keys(valid).sort())
  assert.deepEqual(readdirSync(fixture('jobs/invalid')).filter((f) => f !== 'expected.json').sort(), Object.keys(invalid).sort())
})

for (const [file, want] of Object.entries(valid)) {
  test(`valid ${file} → the pinned canonical def and id; stable under key reordering`, () => {
    const input = readJson<Obj>(`jobs/valid/${file}`)
    const network = input.network as Network
    // btc-defaults.json is an OLD job (no maxFeeRateSatVb): it loads as an existing record; creating it anew is job.btc-fee-ceiling (below)
    const existing = file === 'btc-defaults.json'
    if (existing) assert.equal(guardOf(() => normalizeJob(input, { network })), 'job.btc-fee-ceiling')
    const { def, text } = normalizeJob(input, { network, existing })
    assert.deepEqual(def, want.def)
    assert.equal(jobId(def), want.id)
    assert.equal(text, typeof input.message === 'string' ? input.message : null)
    const again = normalizeJob(reversed(input), { network, existing })
    assert.deepEqual(again.def, want.def)
    assert.equal(canonicalJson(again.def), canonicalJson(def))
    assert.equal(canonicalJson(reversed(def)), canonicalJson(def))
  })
}

for (const [file, guard] of Object.entries(invalid)) {
  test(`invalid ${file} → ${guard}`, () => {
    const input = readJson<Obj>(`jobs/invalid/${file}`)
    const network = (typeof input.network === 'string' && ['local', 'testnet', 'mainnet'].includes(input.network) ? input.network : 'local') as Network
    assert.equal(g(input, network), guard)
  })
}

test('network binding (R71): the same definition on another network is job.network', () => {
  const both = readJson<Obj>('jobs/valid/both-testnet.json')
  assert.equal(g(both, 'local'), 'job.network')
  assert.equal(g(both, 'mainnet'), 'job.network')
  assert.equal(g(both, 'testnet'), null)
  assert.equal(g(BASE, 'testnet'), 'job.network')
  assert.equal(g(job((j) => { j.network = 'devnet' })), 'job.network-field')
  assert.equal(g(job((j) => { j.network = null })), 'job.network-field')
  assert.equal(g(BASE, 'devnet' as Network), 'contract.network', 'the caller\'s own network is checked too')
})

test('the job shape: an object, format vt-job/1, chains a non-empty object of objects', () => {
  for (const input of [null, [], 'vt-job/1', 3, job((j) => { delete j.format }), job((j) => { j.format = 1 }), job((j) => { delete j.chains }),
    job((j) => { j.chains = {} }), job((j) => { j.chains = [] }), job((j) => { (j.chains as Obj).eth = 'drain' }), job((j) => { (j.chains as Obj).eth = null })]) {
    assert.equal(g(input), 'job.format')
  }
})

test('unknown keys anywhere are job.unknown-key (top level, chain names, chain fields, prototype names)', () => {
  assert.equal(g(job((j) => { j.force = true })), 'job.unknown-key')
  assert.equal(g(job((j) => { (j.chains as Obj).ltc = clone(eth(j)) })), 'job.unknown-key')
  assert.equal(g(job((j) => { eth(j).skipChecks = true })), 'job.unknown-key')
  assert.equal(g(JSON.parse('{"__proto__":{"x":1},' + JSON.stringify(BASE).slice(1))), 'job.unknown-key')
  assert.equal(g(job((j) => { Object.assign(j, { constructor: 'x' }) })), 'job.unknown-key')
  assert.equal(g(job((j) => { j.autoArm = undefined })), null, 'an undefined member is absent, as in JSON')
})

test('a field of the other chain is job.field-chain', () => {
  assert.equal(g(job((j) => { eth(j).maxCuPrice = 0 })), 'job.field-chain')
  assert.equal(g(job((j) => { sol(j).maxTipGwei = 1 }, SOL)), 'job.field-chain')
})

test('name: 1..64 printable ASCII, then the key-like / IP-like rules', () => {
  assert.equal(g(job((j) => { j.name = 'n'.repeat(64) })), null)
  assert.equal(g(job((j) => { j.name = ' ~' })), null)
  for (const name of ['', 'n'.repeat(65), 'tab\there', 'Café', 7, null]) assert.equal(g(job((j) => { j.name = name })), 'job.name')
  assert.equal(g(job((j) => { j.name = 'AB'.repeat(32) })), 'job.key-like', '64 hex fill the 64 characters')
  assert.equal(g(job((j) => { j.name = 'see https://example.com' })), 'job.key-like')
  assert.equal(g(job((j) => { j.name = 'host 2001:db8::1' })), 'job.ip-like')
})

test('addresses: EIP-55 for eth; canonical base58 of 32 bytes for sol', () => {
  assert.equal(g(job((j) => { eth(j).keyAddress = ETH_A.toLowerCase() })), 'job.address')
  assert.equal(g(job((j) => { eth(j).keyAddress = ETH_A.replace('Eb', 'eB') })), 'job.address', 'a broken checksum')
  assert.equal(g(job((j) => { eth(j).keyAddress = ETH_A.slice(0, 41) })), 'job.address')
  assert.equal(g(job((j) => { delete eth(j).keyAddress })), 'job.address')
  assert.equal(g(job((j) => { eth(j).keyAddress = SOL_A })), 'job.address')
  assert.equal(g(job((j) => { sol(j).keyAddress = ETH_A }, SOL)), 'job.address')
  assert.equal(g(job((j) => { sol(j).keyAddress = base58.encode(new Uint8Array(33).fill(7)) }, SOL)), 'job.address')
  assert.equal(g(job((j) => { sol(j).keyAddress = `1${SOL_A}` }, SOL)), 'job.address', 'a leading zero byte makes 33 bytes')
  assert.equal(g(job((j) => { sol(j).keyAddress = SOL_A.replace('9', '0') }, SOL)), 'job.address', '0 is not base58')
  assert.equal(g(job((j) => { sol(j).keyAddress = 7 }, SOL)), 'job.address')
})

test('budgetUsd: > 0, ≤ 1000, at most 2 decimals', () => {
  for (const b of [0.01, 10.07, 0.3, 999.99, 1000, 2.5]) assert.equal(g(job((j) => { eth(j).budgetUsd = b })), null, String(b))
  for (const b of [0, -1, 1000.01, 3.333, 0.001, Number.NaN, Number.POSITIVE_INFINITY, '10', null]) assert.equal(g(job((j) => { eth(j).budgetUsd = b })), 'job.budget', String(b))
  assert.equal(g(job((j) => { delete eth(j).budgetUsd })), 'job.budget')
})

test('maxTipGwei (eth): 0.1 ≤ x ≤ 100, optional; maxCuPrice (sol): integer 0..2,000,000, optional', () => {
  for (const t of [0.1, 100, 3.5]) assert.equal(g(job((j) => { eth(j).maxTipGwei = t })), null)
  for (const t of [0.09, 100.5, -1, '3', null, Number.NaN]) assert.equal(g(job((j) => { eth(j).maxTipGwei = t })), 'job.tip-cap', String(t))
  const noTip = normalizeJob(job((j) => { delete eth(j).maxTipGwei }), { network: 'local' }).def
  assert.equal(Object.hasOwn(noTip.chains.eth!, 'maxTipGwei'), false, 'an absent optional field stays absent')
  for (const c of [0, 2_000_000]) assert.equal(g(job((j) => { sol(j).maxCuPrice = c }, SOL)), null)
  for (const c of [-1, 2_000_001, 1.5, '0', null]) assert.equal(g(job((j) => { sol(j).maxCuPrice = c }, SOL)), 'job.cu-cap', String(c))
})

test('mode: "drain" or { copies: 1..10000 }; distinctCopies a boolean', () => {
  for (const m of ['drain', { copies: 1 }, { copies: 10_000 }]) assert.equal(g(job((j) => { eth(j).mode = m })), null)
  for (const m of ['Drain', 'copies', { copies: 0 }, { copies: 10_001 }, { copies: 2.5 }, { copies: '3' }, { copies: 3, extra: 1 }, {}, [3], null, 3]) {
    assert.equal(g(job((j) => { eth(j).mode = m })), 'job.mode', JSON.stringify(m))
  }
  assert.equal(g(job((j) => { delete eth(j).mode })), 'job.mode')
  assert.equal(g(job((j) => { eth(j).distinctCopies = 'yes' })), 'job.mode')
  assert.equal(g(job((j) => { delete eth(j).distinctCopies })), 'job.mode')
})

test('publishMode (R73, CC-1): unknown, dropped or wrong chain → job.publish-mode; reserved → job.publish-mode-unavailable; default per chain', () => {
  assert.equal(g(job((j) => { eth(j).publishMode = 'eth.calldata.self' })), null)
  for (const m of ['sol.memo', 'sol.arweave-anchor', 'eth.calldata', 'toString', '__proto__', 3, null]) assert.equal(g(job((j) => { eth(j).publishMode = m })), 'job.publish-mode', String(m))
  // CC-1 dropped eth.calldata.raw, eth.log and eth.blob, and renamed arweave.irys → arweave.turbo: unknown ids now.
  for (const m of ['eth.calldata.raw', 'eth.log', 'eth.blob', 'arweave.irys']) assert.equal(g(job((j) => { eth(j).publishMode = m })), 'job.publish-mode', m)
  assert.equal(g(job((j) => { sol(j).publishMode = 'arweave.irys' }, SOL)), 'job.publish-mode')
  for (const m of ['eth.sstore2', 'arweave.turbo']) assert.equal(g(job((j) => { eth(j).publishMode = m })), 'job.publish-mode-unavailable', m)
  for (const m of ['sol.arweave-anchor', 'sol.account', 'sol.noop', 'arweave.turbo']) assert.equal(g(job((j) => { sol(j).publishMode = m }, SOL)), 'job.publish-mode-unavailable', m)
  const d = normalizeJob(job((j) => { delete eth(j).publishMode }), { network: 'local' }).def
  assert.equal(d.chains.eth!.publishMode, 'eth.calldata.null')
})

test('arweaveCopy (CC-1): a boolean; true is reserved (job.publish-mode-unavailable); false is the same job as absent', () => {
  const plain = normalizeJob(BASE, { network: 'local' }).def
  const off = normalizeJob(job((j) => { j.arweaveCopy = false }), { network: 'local' }).def
  assert.deepEqual(off, plain)
  assert.equal(Object.hasOwn(off, 'arweaveCopy'), false)
  assert.equal(jobId(off), jobId(plain))
  assert.equal(g(job((j) => { j.arweaveCopy = undefined })), null)
  assert.equal(g(job((j) => { j.arweaveCopy = true })), 'job.publish-mode-unavailable')
  assert.equal(g(job((j) => { j.arweaveCopy = true }, SOL)), 'job.publish-mode-unavailable')
  for (const v of ['true', 1, 0, null, {}, []]) assert.equal(g(job((j) => { j.arweaveCopy = v })), 'job.arweave-copy', JSON.stringify(v))
  for (const v of ['yes', null]) assert.equal(g(job((j) => { j.arweaveCopy = v }, SOL)), 'job.arweave-copy', JSON.stringify(v))
})

const BTC_ADDR = 'bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw'
const btcLane = (o: Obj = {}): Obj => ({ mode: { copies: 2 }, distinctCopies: true, keyAddress: BTC_ADDR, budgetUsd: 5, clawbackTo: null, maxFeeRateSatVb: 25, ...o })
test('E7b (CC-12): the btc lane on LOCAL — copies only, publish mode btc.inscription, optional maxFeeRateSatVb, no claw-back; off local it is job.chain-unsupported', () => {
  const withBtc = (b: Obj, net: 'local' | 'testnet' | 'mainnet' = 'local') => job((j) => { j.network = net; j.chains = { btc: b } })
  const ok = normalizeJob(withBtc(btcLane({ maxFeeRateSatVb: 25 })), { network: 'local' }).def.chains.btc!
  assert.deepEqual([ok.publishMode, ok.feeStrategy, ok.maxFeeRateSatVb, ok.clawbackTo, ok.mode], ['btc.inscription', 'economy', 25, null, { copies: 2 }])
  // Eminors fix 1 (I-1): a NEW btc job must name its ceiling; an existing record without it still loads (the 500 sat/vB fallback)
  const noCeiling = (() => { const b = btcLane(); delete b.maxFeeRateSatVb; return b })()
  const refused = refusalOf(() => normalizeJob(withBtc(noCeiling), { network: 'local' }))
  assert.equal((refused as Error & { guardId?: string }).guardId, 'job.btc-fee-ceiling')
  assert.match(refused.message, /maxFeeRateSatVb is required.*1\.\.500.*Suggested: 25/)
  assert.equal(Object.hasOwn(normalizeJob(withBtc(noCeiling), { network: 'local', existing: true }).def.chains.btc!, 'maxFeeRateSatVb'), false)
  assert.equal(g(withBtc(btcLane({ maxFeeRateSatVb: null }))), 'job.fee-rate', 'present but null is a malformed ceiling, not a missing one')
  assert.deepEqual([suggestedBtcFeeCeiling(null), suggestedBtcFeeCeiling(undefined), suggestedBtcFeeCeiling(0), suggestedBtcFeeCeiling(1), suggestedBtcFeeCeiling(2), suggestedBtcFeeCeiling(3), suggestedBtcFeeCeiling(40), suggestedBtcFeeCeiling(124), suggestedBtcFeeCeiling(125), suggestedBtcFeeCeiling(9999n)], [25, 25, 25, 10, 10, 12, 160, 496, 500, 500])
  const both = normalizeJob(job((j) => { (j.chains as Obj).btc = btcLane() }), { network: 'local' }).def
  assert.deepEqual(Object.keys(both.chains).sort(), ['btc', 'eth'])
  for (const net of ['testnet', 'mainnet'] as const) assert.equal(g(withBtc(btcLane(), net), net), 'job.chain-unsupported', net)
  assert.equal(g(job((j) => { (j.chains as Obj).btc = btcLane(); j.network = 'testnet' }), 'testnet'), 'job.chain-unsupported', 'beside a valid lane too')
  assert.equal(g(withBtc(btcLane({ mode: 'drain' }))), 'job.mode')
  assert.equal(g(withBtc(btcLane({ publishMode: 'sol.memo' }))), 'job.publish-mode')
  for (const bad of [0, 501, 1.5, '25', null, Number.NaN]) assert.equal(g(withBtc(btcLane({ maxFeeRateSatVb: bad }))), 'job.fee-rate', String(bad))
  for (const good of [1, 500]) assert.equal(g(withBtc(btcLane({ maxFeeRateSatVb: good }))), null, String(good))
  assert.equal(g(withBtc(btcLane({ clawbackTo: BTC_ADDR }))), 'job.clawback')
  assert.equal(g(withBtc(btcLane({ maxTipGwei: 3 }))), 'job.field-chain')
  assert.equal(g(job((j) => { (j.chains as Obj).eth = { ...clone(eth(j)), maxFeeRateSatVb: 5 } })), 'job.field-chain')
  for (const addr of [BTC_ADDR.toUpperCase(), 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', `${BTC_ADDR.slice(0, -1)}q`, '0x' + '1'.repeat(40), 'bcrt1p9fjtrm3nwhemkjek0wxtswz2glmneu33w9lcylrvd7alttk0psmqqf08dg']) assert.equal(g(withBtc(btcLane({ keyAddress: addr })), 'local'), 'job.address', addr)
  assert.equal(g(job((j) => { (j.chains as Obj).bch = clone(eth(j)) })), 'job.unknown-key', 'any other name stays an unknown key')
  assert.equal(g(job((j) => { (j.chains as Obj).btc = 3 })), 'job.format', 'a non-object member is still the shape refusal')
})

test('textKind (CC-7): plain | timelocked, default plain; timelocked is reserved (job.publish-mode-unavailable); not part of the stored def', () => {
  const plain = normalizeJob(BASE, { network: 'local' }).def
  const withPlain = normalizeJob(job((j) => { j.textKind = 'plain' }), { network: 'local' }).def
  assert.deepEqual(withPlain, plain)
  assert.equal(jobId(withPlain), jobId(plain))
  assert.equal(Object.hasOwn(withPlain, 'textKind'), false)
  assert.equal(g(job((j) => { j.textKind = undefined })), null)
  assert.equal(g(job((j) => { j.textKind = 'timelocked' })), 'job.publish-mode-unavailable')
  assert.equal(g(job((j) => { j.textKind = 'timelocked' }, SOL)), 'job.publish-mode-unavailable')
  for (const v of ['Plain', 'sealed', '', 1, true, null, {}, []]) assert.equal(g(job((j) => { j.textKind = v })), 'job.text-kind', JSON.stringify(v))
})

test('feeStrategy (R73): passive | economy | prompt; default passive for drain, economy for copies', () => {
  for (const f of ['passive', 'economy', 'prompt']) assert.equal(g(job((j) => { eth(j).feeStrategy = f })), null)
  for (const f of ['fast', '', null, 1, 'constructor']) assert.equal(g(job((j) => { eth(j).feeStrategy = f })), 'job.fee-strategy', String(f))
  const drain = normalizeJob(job((j) => { delete eth(j).feeStrategy }), { network: 'local' }).def
  assert.equal(drain.chains.eth!.feeStrategy, 'passive')
  const copies = normalizeJob(job((j) => { delete eth(j).feeStrategy; eth(j).mode = { copies: 2 } }), { network: 'local' }).def
  assert.equal(copies.chains.eth!.feeStrategy, 'economy')
})

test('clawbackTo: null, or a valid address that is not the null address, the incinerator or keyAddress', () => {
  const ETH_B = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
  assert.equal(g(job((j) => { eth(j).clawbackTo = ETH_B })), null)
  for (const to of ['0x0000000000000000000000000000000000000000', '0x000000000000000000000000000000000000dEaD', ETH_A, ETH_A.toLowerCase(), ETH_B.toLowerCase(), SOL_A, '', 0]) {
    assert.equal(g(job((j) => { eth(j).clawbackTo = to })), 'job.clawback', String(to))
  }
  assert.equal(g(job((j) => { delete eth(j).clawbackTo })), 'job.clawback')
  assert.equal(g(job((j) => { sol(j).clawbackTo = null }, SOL)), null)
  for (const to of ['11111111111111111111111111111111', '1nc1nerator11111111111111111111111111111111', SOL_A, ETH_B]) {
    assert.equal(g(job((j) => { sol(j).clawbackTo = to }, SOL)), 'job.clawback', to)
  }
})

test('clawbackTo: every ETH destination a claw-back refuses is refused at validation (E6)', () => {
  const at = (n: bigint): string => '0x' + n.toString(16).padStart(40, '0')
  // precompiles and the reserved range 0x…0001 to 0x…ffff: job.clawback-precompile (any case, checksummed or not)
  for (const n of [1n, 9n, 0x11n, 0x100n, 0xfffen, 0xffffn]) {
    assert.equal(g(job((j) => { eth(j).clawbackTo = at(n) })), 'job.clawback-precompile', n.toString(16))
  }
  // 0x…0000 and 0x…dEaD stay job.clawback; just above the range is valid when EIP-55 (the checksum is not the reserved rule)
  assert.equal(g(job((j) => { eth(j).clawbackTo = at(0n) })), 'job.clawback')
  assert.equal(g(job((j) => { eth(j).clawbackTo = '0x000000000000000000000000000000000000dEaD' })), 'job.clawback')
  const above = getAddress(at(0x10000n))
  assert.equal(g(job((j) => { eth(j).clawbackTo = above })), null)
  assert.equal(normalizeJob(job((j) => { eth(j).clawbackTo = above }), { network: 'local' }).def.chains.eth!.clawbackTo, above)
  // the same job with a non-checksummed low address is still refused (never accepted as a destination)
  assert.notEqual(g(job((j) => { eth(j).clawbackTo = at(0x10000n) })), 'job.clawback-precompile')
})

test('clawbackTo: the SOL System Program and the incinerator are refused at validation; other addresses are valid (E6)', () => {
  const SOL_B = base58.encode(new Uint8Array(32).fill(7))
  for (const to of ['11111111111111111111111111111111', '1nc1nerator11111111111111111111111111111111']) {
    assert.equal(g(job((j) => { sol(j).clawbackTo = to }, SOL)), 'job.clawback', to)
  }
  assert.equal(g(job((j) => { sol(j).clawbackTo = SOL_B }, SOL)), null)
  assert.equal(normalizeJob(job((j) => { sol(j).clawbackTo = SOL_B }, SOL), { network: 'local' }).def.chains.sol!.clawbackTo, SOL_B)
})

test('message source: exactly one of message | messageSha256 + messageBytes; messageFile is never posted', () => {
  const ref = readJson<Obj>('jobs/valid/message-ref.json')
  assert.equal(g(job((j) => { delete j.message })), 'job.message-source', 'none')
  assert.equal(g(job((j) => { delete j.messageBytes }, ref)), 'job.message-source')
  assert.equal(g(job((j) => { delete j.messageSha256 }, ref)), 'job.message-source')
  assert.equal(g(job((j) => { j.messageSha256 = (j.messageSha256 as string).toUpperCase() }, ref)), 'job.message-source')
  for (const b of [0, MAX_PLUS_1(), 1.5, '514']) assert.equal(g(job((j) => { j.messageBytes = b }, ref)), 'job.message-source', String(b))
  assert.equal(g(job((j) => { j.messageBytes = 7 })), 'job.message-source', 'inline message with messageBytes')
  assert.equal(g(job((j) => { j.message = 7 })), 'job.message-source')
  assert.equal(g(job((j) => { j.messageFile = 'm.txt' })), 'job.message-file', 'messageFile with an inline message')
  assert.equal(g(job((j) => { j.messageFile = 'm.txt' }, ref)), 'job.message-file')
})
function MAX_PLUS_1(): number { return 16 * 1024 * 1024 + 1 }

test('an inline message goes through validateMessage (message.* guards); the def holds only its digest and size', () => {
  assert.equal(g(job((j) => { j.message = 'a\r\nb' })), 'message.control')
  assert.equal(g(job((j) => { j.message = '' })), 'message.empty')
  assert.equal(g(job((j) => { j.message = 'relay at 203.0.113.77\n' })), 'message.ip-like')
  const { def, text } = normalizeJob(job((j) => { j.message = 'héllo 😀\n' }), { network: 'local' })
  assert.equal(text, 'héllo 😀\n')
  assert.equal(def.messageSha256, sha256Hex('héllo 😀\n'))
  assert.equal(def.messageBytes, 12)
  assert.equal(Object.hasOwn(def, 'message'), false)
})

test('the def is a fresh object: changing the input afterwards changes nothing', () => {
  const input = job((j) => { eth(j).mode = { copies: 2 } })
  const { def } = normalizeJob(input, { network: 'local' })
  const before = canonicalJson(def)
  eth(input).mode = { copies: 9 }; eth(input).budgetUsd = 1; (input.chains as Obj).sol = {}
  assert.equal(canonicalJson(def), before)
})

test('a refusal never echoes the value it refused', () => {
  const secret = `0x${'cd'.repeat(32)}`
  const e = refusalOf(() => normalizeJob(job((j) => { j.name = secret }), { network: 'local' }))
  assert.ok(!e.message.includes(secret))
  const e2 = refusalOf(() => normalizeJob(job((j) => { j[secret] = 1 }), { network: 'local' }))
  assert.equal((e2 as unknown as { guardId: string }).guardId, 'job.unknown-key')
  assert.ok(!e2.message.includes(secret), 'an unknown key name is not echoed')
})

test('PF-S fix round 1 (N-6): a NEW mainnet job names clawbackTo on each eth / sol chain (job.clawback-required); a stored one, testnet and local keep null', () => {
  const ETH_DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
  const onMainnet = (base: Obj, patch: (j: Obj) => void = () => {}): Obj => job((j) => { j.network = 'mainnet'; patch(j) }, base)
  // eth without, sol without, and a two-chain job where only sol lacks it
  assert.equal(g(onMainnet(BASE), 'mainnet'), 'job.clawback-required')
  assert.equal(g(onMainnet(SOL, (j) => { sol(j).clawbackTo = null }), 'mainnet'), 'job.clawback-required')
  assert.equal(g(onMainnet(BASE, (j) => { eth(j).clawbackTo = ETH_DEST; (j.chains as Obj).sol = { ...sol(clone(SOL)), clawbackTo: null } }), 'mainnet'), 'job.clawback-required')
  const refused = refusalOf(() => normalizeJob(onMainnet(BASE), { network: 'mainnet' }))
  assert.match(refused.message, /^chains\.eth\.clawbackTo is required on mainnet/)                  // the CLI and the page show this text: it names the field
  // named: accepted, and the def keeps it
  assert.equal(normalizeJob(onMainnet(BASE, (j) => { eth(j).clawbackTo = ETH_DEST }), { network: 'mainnet' }).def.chains.eth!.clawbackTo, ETH_DEST)
  assert.equal(normalizeJob(onMainnet(SOL), { network: 'mainnet' }).def.chains.sol!.clawbackTo, sol(SOL).clawbackTo)
  // a stored mainnet job (existing) loads as it is; testnet and local jobs may leave it null; a malformed address stays job.clawback
  assert.equal(normalizeJob(onMainnet(BASE), { network: 'mainnet', existing: true }).def.chains.eth!.clawbackTo, null)
  for (const net of ['testnet', 'local'] as const) assert.equal(g(job((j) => { j.network = net }), net), null, net)
  assert.equal(g(onMainnet(BASE, (j) => { eth(j).clawbackTo = ETH_A }), 'mainnet'), 'job.clawback', 'the lane key itself')
})

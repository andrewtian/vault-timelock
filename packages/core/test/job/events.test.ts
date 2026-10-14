// validateEvent (spec §5.3): known type, allowed writer, exact data shape with bounded strings. Mapped by
// test/mutation/guards.json: event.type, event.by, event.shape. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { base58 } from '@scure/base'
import { validateEvent } from '../../src/job/index.ts'
import type { JournalEvent } from '../../src/contracts/index.ts'
import { fixture, guardOf, readJson } from './helpers.ts'

type Obj = Record<string, unknown>
const ETH_TX = `0x${'ab'.repeat(32)}`
const ETH_TX2 = `0x${'cd'.repeat(32)}`
const SOL_SIG = base58.encode(new Uint8Array(64).fill(7))
const H64 = 'ef'.repeat(32)
const ETH_A = '0x8739Eb87B3d11f221Df63454F8D229a1A4F4049C'
const SOL_A = '9xx7qC7uwTAeaSo7T5Gk9canYBosFh1pMQaDmQEa83Tb'
const BH = base58.encode(new Uint8Array(32).fill(9))
const ETH_I = { nonce: 0, tip: '12000', maxFee: '2000012000', gas: '23400', to: '0x0000000000000000000000000000000000000000' }
const SOL_I = { blockhash: BH, lastValidBlockHeight: 1000, cuPrice: 0, cuLimit: 30_000, rung: null, fee: '5000' }
const CAP = { nativeCap: '4000000000000000', usd: 10, priceAt: 1_791_504_009_000, overCap: false, planned: '0.004' }
const ARMED = { armedAt: 1_791_504_009_000, releaseAt: 1_791_504_024_000, countdownSec: 15, schedule: { order: ['eth', 'sol'], offsetSec: { eth: 0, sol: 42 } }, caps: { eth: CAP, sol: { ...CAP, priceAt: null } }, sources: {} }

// One valid sample per type; `opt` lists the members that may be left out.
const API: Record<string, { data: Obj; opt?: string[] }> = {
  created: { data: { jobId: 'e3d45f73cf65abaa', defSha256: H64 } },
  armed: { data: ARMED },
  skip: { data: { releaseAt: 1_791_504_030_000 } },
  'stop-requested': { data: { chain: null } },
  'resume-requested': { data: { chain: 'eth', tipCapGwei: '5', cuPriceCap: 1000 }, opt: ['tipCapGwei', 'cuPriceCap'] },
  close: { data: { chain: 'sol' } },
  resolved: { data: { txId: ETH_TX, action: 'mark-failed', typed: 'resolve' } },
  'lease-acquired': { data: { gen: 2, holder: 'cli', ttlMs: 15_000 } },
  'lease-released': { data: { gen: 2 } },
  'lease-expired': { data: { gen: 1 } },
}
const EXEC: Record<string, { data: Obj; opt?: string[] }> = {
  'key-loaded': { data: { address: SOL_A } },
  funds: { data: { balance: '0', affordable: false, nextCopyCost: '25000' } },
  reconcile: { data: { txId: SOL_SIG, outcome: 'included', block: '3456', fee: '5000' }, opt: ['block', 'fee'] },
  'copy-built': { data: { copy: 2, parts: 3, bytes: [1010, 1010, 340], tight: true, level: 1 } },
  intent: { data: { txId: ETH_TX2, copy: 1, part: 2, parts: 2, attempt: 2, replaces: ETH_TX, rawSha256: H64, payloadSha256: H64, reserved: '50000000000000', eth: ETH_I } },
  sent: { data: { txId: ETH_TX, outcome: 'unknown', reason: 'no reply from the relay' } },
  replaced: { data: { txId: ETH_TX2, prevId: ETH_TX, reason: 'stall: 3 blocks without a receipt' } },
  included: { data: { txId: ETH_TX, copy: 1, part: 1, attempt: 1, block: '205', fee: '25000300000000', ms: 12_000 } },
  readback: { data: { txId: SOL_SIG, ok: false, detail: 'payload bytes differ' } },
  paused: { data: { reason: 'tip cap reached (3 gwei)' } },
  resumed: { data: { reason: 'tip cap raised to 5 gwei' } },
  drained: { data: { balance: '1200000000000', nextCost: '25000300000000', copy: 2 } },
  'copies-done': { data: { copies: 3 } },
  'clawback-intent': { data: { txId: SOL_SIG, to: SOL_A, value: '499995000', rawSha256: H64, sol: SOL_I } },
  'clawback-sent': { data: { txId: SOL_SIG, outcome: 'accepted' } },
  'clawback-included': { data: { txId: SOL_SIG, value: '499995000', fee: '5000' } },
  'clawback-readback': { data: { txId: SOL_SIG, ok: true, destReceived: '499995000', laneBalance: '0' } },
  'clawback-failed': { data: { txId: SOL_SIG, reason: 'insufficient funds for the fee' } },
  stuck: { data: { txId: ETH_TX, reason: 'outcome unknowable' } },
  reassembled: { data: { copy: 1, ok: true, sha256: H64 } },
}
const BOTH: Record<string, { data: Obj }> = { stopped: { data: { reason: 'stop requested before any intent' } }, note: { data: { text: 'recovered tail' } } }
const ALL = { ...API, ...EXEC, ...BOTH }
const v = (type: string, data: unknown, by: string): string | null => guardOf(() => validateEvent(type, data, by))

test('every executor type with valid data passes from a lease holder (browser, cli) and is event.by from the api or the operator', () => {
  for (const [type, { data }] of Object.entries(EXEC)) {
    assert.equal(v(type, data, 'browser'), null, type)
    assert.equal(v(type, data, 'cli'), null, type)
    assert.equal(v(type, data, 'api'), 'event.by', type)
    assert.equal(v(type, data, 'operator'), 'event.by', type)
  }
})

test('every API type with valid data passes from the api (or the operator) and is event.by from an executor', () => {
  for (const [type, { data }] of Object.entries(API)) {
    assert.equal(v(type, data, 'api'), null, type)
    assert.equal(v(type, data, 'operator'), null, type)
    assert.equal(v(type, data, 'browser'), 'event.by', type)
    assert.equal(v(type, data, 'cli'), 'event.by', type)
  }
  for (const [type, { data }] of Object.entries(BOTH)) for (const by of ['api', 'operator', 'browser', 'cli']) assert.equal(v(type, data, by), null, `${type} by ${by}`)
  for (const by of ['root', '', 'Browser', 'toString', '__proto__']) assert.equal(v('note', { text: 'x' }, by), 'event.by', by)
})

test('unknown types (prototype names included) are event.type', () => {
  for (const type of ['teleport', '', 'Intent', 'toString', 'constructor', '__proto__', 'hasOwnProperty']) assert.equal(v(type, {}, 'browser'), 'event.type', type)
})

test('extra keys and missing keys are event.shape, for every type', () => {
  for (const [type, { data, opt }] of Object.entries(ALL) as Array<[string, { data: Obj; opt?: string[] }]>) {
    const by = Object.hasOwn(EXEC, type) ? 'browser' : 'api'
    assert.equal(v(type, { ...data, extra: 1 }, by), 'event.shape', `${type} + extra`)
    for (const k of Object.keys(data)) {
      const { [k]: _gone, ...rest } = data
      assert.equal(v(type, rest, by), (opt ?? []).includes(k) ? null : 'event.shape', `${type} - ${k}`)
    }
    for (const bad of [null, [], 'x', 3]) assert.equal(v(type, bad, by), 'event.shape', `${type} data ${JSON.stringify(bad)}`)
  }
})

test('intent without rawSha256, with both eth and sol, or with neither is event.shape', () => {
  const { rawSha256: _r, ...noRaw } = EXEC.intent.data
  assert.equal(v('intent', noRaw, 'browser'), 'event.shape')
  assert.equal(v('intent', { ...EXEC.intent.data, sol: SOL_I }, 'browser'), 'event.shape')
  const { eth: _e, ...neither } = EXEC.intent.data
  assert.equal(v('intent', neither, 'browser'), 'event.shape')
  assert.equal(v('intent', { ...neither, sol: SOL_I, txId: SOL_SIG, replaces: null }, 'cli'), null)
  assert.equal(v('intent', { ...EXEC.intent.data, part: 3 }, 'browser'), 'event.shape', 'part > parts')
  assert.equal(v('intent', { ...EXEC.intent.data, copy: 0 }, 'browser'), 'event.shape')
  assert.equal(v('intent', { ...EXEC.intent.data, replaces: ETH_TX2 }, 'browser'), 'event.shape', 'replaces itself')
  assert.equal(v('intent', { ...EXEC.intent.data, eth: { ...ETH_I, extra: 1 } }, 'browser'), 'event.shape', 'extra key one level down')
  assert.equal(v('clawback-intent', { ...EXEC['clawback-intent'].data, eth: ETH_I }, 'browser'), 'event.shape')
})

test('strings are bounded: note text ≤ 200, any other free text ≤ 512', () => {
  assert.equal(v('paused', { reason: 'r'.repeat(512) }, 'cli'), null)
  assert.equal(v('paused', { reason: 'r'.repeat(513) }, 'cli'), 'event.shape')
  assert.equal(v('note', { text: 'n'.repeat(200) }, 'cli'), null)
  assert.equal(v('note', { text: 'n'.repeat(201) }, 'cli'), 'event.shape')
  for (const [type, k] of [['sent', 'reason'], ['replaced', 'reason'], ['readback', 'detail'], ['stuck', 'reason'], ['clawback-failed', 'reason']]) {
    assert.equal(v(type, { ...EXEC[type].data, [k]: 'x'.repeat(513) }, 'browser'), 'event.shape', type)
  }
  assert.equal(v('stopped', { reason: 'x'.repeat(513) }, 'api'), 'event.shape')
  // Eminors: `delegated` is exactly `true`, optional, on `stopped` only
  assert.equal(v('stopped', { reason: 'x', delegated: true }, 'cli'), null)
  for (const bad of [false, 'true', 1, null]) assert.equal(v('stopped', { reason: 'x', delegated: bad }, 'cli'), 'event.shape')
  assert.equal(v('paused', { reason: 'x', delegated: true }, 'cli'), 'event.shape')
  assert.equal(v('armed', { ...ARMED, sources: { eth: 's'.repeat(513) } }, 'api'), 'event.shape')
})

test('ids, amounts and enums have exact formats', () => {
  const bad: Array<[string, Obj]> = [
    ['sent', { txId: ETH_TX.toUpperCase().replace('0X', '0x'), outcome: 'accepted', reason: null }],
    ['sent', { txId: `0x${'ab'.repeat(31)}`, outcome: 'accepted', reason: null }],
    ['sent', { txId: base58.encode(new Uint8Array(32).fill(7)), outcome: 'accepted', reason: null }],
    ['sent', { txId: ETH_TX, outcome: 'maybe', reason: null }],
    ['included', { ...EXEC.included.data, fee: '-1' }],
    ['included', { ...EXEC.included.data, fee: '01' }],
    ['included', { ...EXEC.included.data, block: 205 }],
    ['funds', { ...EXEC.funds.data, balance: '1.5' }],
    ['funds', { ...EXEC.funds.data, affordable: 'true' }],
    ['reconcile', { txId: ETH_TX, outcome: 'landed' }],
    ['reassembled', { copy: 1, ok: true, sha256: H64.toUpperCase() }],
    ['key-loaded', { address: '0x1234' }],
    ['copy-built', { ...EXEC['copy-built'].data, bytes: [1010, 1010] }],
    ['copy-built', { ...EXEC['copy-built'].data, bytes: [1010, 1010, 0] }],
    ['intent', { ...EXEC.intent.data, eth: { ...ETH_I, nonce: -1 } }],
    ['intent', { ...EXEC.intent.data, attempt: 1.5 }],
    ['clawback-intent', { ...EXEC['clawback-intent'].data, sol: { ...SOL_I, blockhash: 'short' } }],
  ]
  for (const [i, [type, data]] of bad.entries()) assert.equal(v(type, data, 'browser'), 'event.shape', `case ${i} ${type}`)
  const badApi: Array<[string, Obj]> = [
    ['created', { jobId: 'E3D45F73CF65ABAA', defSha256: H64 }],
    ['stop-requested', { chain: 'xrp' }],
    ['close', { chain: null }],
    ['resolved', { txId: ETH_TX, action: 'mark-maybe', typed: null }],
    ['lease-acquired', { gen: 0, holder: 'cli', ttlMs: 15_000 }],
    ['lease-acquired', { gen: 1, holder: 'api', ttlMs: 15_000 }],
    ['resume-requested', { chain: 'eth', tipCapGwei: '5 gwei' }],
    ['armed', { ...ARMED, releaseAt: ARMED.releaseAt + 1 }],
    ['armed', { ...ARMED, countdownSec: 4, releaseAt: ARMED.armedAt + 4_000 }],
    ['armed', { ...ARMED, schedule: { order: ['eth', 'sol'], offsetSec: { eth: 5, sol: 0 } } }],
    ['armed', { ...ARMED, schedule: { order: ['eth', 'eth'], offsetSec: { eth: 0 } } }],
    ['armed', { ...ARMED, schedule: { order: [], offsetSec: {} } }],
    ['armed', { ...ARMED, schedule: { order: ['eth', 'sol'], offsetSec: { eth: 0 } } }],
    ['armed', { ...ARMED, caps: { eth: CAP } }],
    ['armed', { ...ARMED, caps: { eth: CAP, sol: { ...CAP, overCap: 'no' } } }],
    ['armed', { ...ARMED, sources: { btc: 'x' } }],
  ]
  for (const [i, [type, data]] of badApi.entries()) assert.equal(v(type, data, 'api'), 'event.shape', `case ${i} ${type}`)
})

test('every line of every journal fixture validates with its own type, data and by', () => {
  const files = readdirSync(fixture('journals')).filter((f) => f.endsWith('.jsonl')).sort()
  assert.ok(files.length >= 14)
  for (const f of files) {
    for (const line of readFileSync(fixture(`journals/${f}`), 'utf8').split('\n').filter((l) => l !== '')) {
      const e = JSON.parse(line) as JournalEvent
      assert.equal(v(e.type, e.data, e.by), null, `${f} seq ${e.seq} ${e.type}`)
    }
  }
})

test('the contract\'s invalid event cases', () => {
  const inv = readJson<{ cases: Array<{ name: string; type: string; data: unknown; by: string; guard: string }> }>('events/invalid.json')
  for (const c of inv.cases) assert.equal(v(c.type, c.data, c.by), c.guard, c.name)
})

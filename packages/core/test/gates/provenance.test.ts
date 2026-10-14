// gates/provenance.ts (plan W6, D-R21): the §6.2 `eth` row, informational since R76. Synthetic
// addresses and hashes only. Each guard has a test that fails when its marker line is blanked.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { toFunctionSelector } from 'viem'
import {
  RAILGUN_GETTER, RAILGUN_PROXY, RAILGUN_RELAYADAPT, RELAY_SELECTOR, evaluateEthRow,
} from '../../src/gates/provenance.ts'
import type { EthRowInput, InboundTransfer } from '../../src/gates/provenance.ts'
import { isGuardId } from '../../src/contracts/index.ts'

const PROXY = RAILGUN_PROXY.mainnet
const RELAY = `0x${'ab'.repeat(20)}`
const EOA = `0x${'11'.repeat(20)}`
const H1 = `0x${'cd'.repeat(32)}`, H2 = `0x${'ee'.repeat(32)}`
const t = (viaTo: string, value: bigint, success = true, txHash = H1, from = viaTo, relayCall = true): InboundTransfer => ({ txHash, viaTo, from, relayCall, value, success })
const base: EthRowInput = { address: EOA, balance: 1000n, nonce: 0, inbound: [], proxy: PROXY, relayAdapts: new Set([RELAY]), truncated: false }
const ids = (i: Partial<EthRowInput>): string[] => evaluateEthRow({ ...base, ...i }).failures.map((f) => f.guard)

test('the pinned proxies and the railgun() selector', () => {
  assert.equal(RAILGUN_PROXY.mainnet, '0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9')
  assert.equal(RAILGUN_PROXY.testnet, '0xeCFCf3b4eC647c4Ca6D49108b311b7a7C9543fea')
  assert.equal(RAILGUN_GETTER, toFunctionSelector('railgun()'))
  assert.equal(RAILGUN_RELAYADAPT.mainnet, '0xAc9f360Ae85469B27aEDdEaFC579Ef2d052aD405')
  assert.equal(RAILGUN_RELAYADAPT.testnet, '0x7e3d929EbD5bDC84d02Bd3205c777578f33A214D')
  assert.equal(RELAY_SELECTOR, toFunctionSelector('relay((((uint256,uint256),(uint256[2],uint256[2]),(uint256,uint256)),bytes32,bytes32[],bytes32[],(uint16,uint72,uint8,uint64,address,bytes32,(bytes32[4],bytes32,bytes32,bytes,bytes)[]),(bytes32,(uint8,address,uint256),uint120))[],(bytes31,bool,uint256,(address,bytes,uint256)[]))'))
})

test('I-2 regressions: a spoof contract, a foreign sender, and a multicall / value-carrying call are NOT Railgun', () => {
  const SPOOF = `0x${'dd'.repeat(20)}`                      // answers railgun() with the proxy, forwards ETH: not pinned, so never a RelayAdapt
  assert.deepEqual(ids({ inbound: [t(SPOOF, 1000n)] }), ['provenance.not-railgun'])
  assert.deepEqual(ids({ inbound: [t(RELAY, 1000n, true, H1, SPOOF)] }), ['provenance.not-railgun'])          // the pinned adapt was only the parent tx's `to`: the value came from elsewhere
  assert.deepEqual(ids({ inbound: [t(RELAY, 1000n, true, H1, EOA)] }), ['provenance.not-railgun'])
  assert.deepEqual(ids({ inbound: [t(RELAY, 1000n, true, H1, RELAY, false)] }), ['provenance.not-railgun'])   // multicall / transfer, or relay() with ETH attached
  assert.match(evaluateEthRow({ ...base, inbound: [t(RELAY, 1000n, true, H1, RELAY, false)] }).failures[0].message, /relay\(\) with value 0/)
  assert.match(evaluateEthRow({ ...base, inbound: [t(RELAY, 1000n, true, H1, EOA)] }).failures[0].message, /sent by/)
  // the proxy as the parent's `to` needs no relay() call; the sender must still be Railgun's
  assert.equal(evaluateEthRow({ ...base, inbound: [t(PROXY, 1000n, true, H1, PROXY, false)] }).ok, true)
  assert.equal(evaluateEthRow({ ...base, inbound: [t(PROXY, 1000n, true, H1, RELAY, false)] }).ok, true)
  assert.deepEqual(ids({ inbound: [t(PROXY, 1000n, true, H1, EOA, false)] }), ['provenance.not-railgun'])
  // an address that is in the pinned set only by case still matches (the case of an address is not significant)
  assert.equal(evaluateEthRow({ ...base, inbound: [t(RELAY, 1000n, true, H1, RELAY.toUpperCase().replace('0X', '0x'))] }).ok, true)
})

test('passes: the only inbound came through the proxy or a RelayAdapt, nonce 0, total = balance', () => {
  assert.deepEqual(evaluateEthRow({ ...base, inbound: [t(RELAY, 1000n)] }), { ok: true, failures: [], railgunTxs: [H1] })
  assert.equal(evaluateEthRow({ ...base, inbound: [t(PROXY.toLowerCase(), 1000n)] }).ok, true)       // the case of the address is not significant
  assert.equal(evaluateEthRow({ ...base, inbound: [t(RELAY, 400n), t(PROXY, 600n, true, H2)] }).ok, true)
  // a failed tx moved nothing and a zero-value one funds nothing: neither counts, neither breaks the row
  assert.equal(evaluateEthRow({ ...base, inbound: [t(RELAY, 1000n), t(EOA, 5n, false, H2), t(EOA, 0n, true, H2)] }).ok, true)
})

test('provenance.not-railgun: an inbound through any other contract or an EOA', () => {
  assert.deepEqual(ids({ inbound: [t(EOA, 1000n)] }), ['provenance.not-railgun'])
  const mixed = evaluateEthRow({ ...base, balance: 1500n, inbound: [t(RELAY, 1000n), t(EOA, 500n, true, H2)] })
  assert.equal(mixed.ok, false)
  assert.deepEqual(mixed.failures.map((f) => f.guard), ['provenance.not-railgun'])
  assert.deepEqual(mixed.railgunTxs, [H1])
  // a contract that is not listed as a RelayAdapt (its railgun() was not the proxy) does not count
  assert.deepEqual(ids({ inbound: [t(`0x${'cc'.repeat(20)}`, 1000n)] }), ['provenance.not-railgun'])
})

test('provenance.no-inbound: nothing, or only failed / zero transfers', () => {
  assert.deepEqual(ids({ balance: 0n, inbound: [] }), ['provenance.no-inbound'])
  assert.deepEqual(ids({ balance: 0n, inbound: [t(RELAY, 1000n, false)] }), ['provenance.no-inbound'])
  assert.deepEqual(ids({ balance: 0n, inbound: [t(RELAY, 0n)] }), ['provenance.no-inbound'])
})

test('provenance.nonce: an address that has already sent', () => {
  assert.deepEqual(ids({ nonce: 1, inbound: [t(RELAY, 1000n)] }), ['provenance.nonce'])
  assert.deepEqual(ids({ nonce: 7, inbound: [t(RELAY, 1000n)] }), ['provenance.nonce'])
})

test('provenance.unaccounted: the balance is not the inbound total (more or less)', () => {
  assert.deepEqual(ids({ balance: 2000n, inbound: [t(RELAY, 1000n)] }), ['provenance.unaccounted'])
  assert.deepEqual(ids({ balance: 999n, inbound: [t(RELAY, 1000n)] }), ['provenance.unaccounted'])
})

test('provenance.paged: another page exists, so the reading is refused even if what is seen passes', () => {
  assert.deepEqual(ids({ truncated: true, inbound: [t(RELAY, 1000n)] }), ['provenance.paged'])
})

test('provenance.incomplete: a malformed reading is refused, never guessed (and no other check speaks)', () => {
  const bad: Array<Partial<EthRowInput>> = [
    { address: 'nope' }, { proxy: '0x12' }, { balance: -1n }, { balance: 1000 as unknown as bigint }, { nonce: 0.5 }, { nonce: -1 },
    { nonce: '0' as unknown as number }, { truncated: undefined as unknown as boolean },
    { relayAdapts: new Set([RELAY.toUpperCase().replace('0X', '0x')]) },            // a RelayAdapt entry must be lower case
    { relayAdapts: ['x'] as unknown as ReadonlySet<string> },
    { inbound: [{ ...t(RELAY, 1000n), txHash: '0x12' }] }, { inbound: [{ ...t(RELAY, 1000n), viaTo: 'x' }] },
    { inbound: [{ ...t(RELAY, 1000n), value: 1000 as unknown as bigint }] }, { inbound: [{ ...t(RELAY, 1000n), value: -5n }] },
    { inbound: [{ ...t(RELAY, 1000n), success: 'true' as unknown as boolean }] }, { inbound: null as unknown as InboundTransfer[] },
    { inbound: [null as unknown as InboundTransfer] },
  ]
  for (const b of bad) {
    const v = evaluateEthRow({ ...base, inbound: [t(RELAY, 1000n)], ...b })
    assert.equal(v.ok, false, JSON.stringify(Object.keys(b)))
    assert.deepEqual(v.failures.map((f) => f.guard), ['provenance.incomplete'], JSON.stringify(Object.keys(b)))
    assert.deepEqual(v.railgunTxs, [])
  }
})

test('the verdict lists every failed check at once, with messages that name no secret', () => {
  const v = evaluateEthRow({ ...base, nonce: 2, balance: 5n, inbound: [t(EOA, 1000n)] })
  assert.deepEqual(v.failures.map((f) => f.guard), ['provenance.not-railgun', 'provenance.nonce', 'provenance.unaccounted'])
  for (const f of v.failures) assert.ok(isGuardId(f.guard) && f.message.length > 10)
})

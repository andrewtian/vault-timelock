// R73 + CC-1 (I1, publication-modes-elite.md): the publication-mode table, the job-level Arweave copy and the fee
// strategies.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  ARWEAVE_COPY, DEFAULT_PUBLISH_MODE, defaultFeeStrategy, FEE_STRATEGIES, PERMANENCE_CLASSES, PUBLISH_MODE_IDS, PUBLISH_MODES,
  PUBLISH_MODES_VERSION, publishModeRow, publishModesFor,
} from '../../src/contracts/index.ts'

test('one row per id, ids unique, every row complete (permanence class + trustNote, no boolean permanent)', () => {
  assert.equal(PUBLISH_MODES_VERSION, 'vt-publish/3')
  assert.deepEqual([...PERMANENCE_CLASSES], ['state', 'history', 'arweave', 'ephemeral'])
  assert.deepEqual(PUBLISH_MODES.map((r) => r.id), [...PUBLISH_MODE_IDS])
  assert.equal(new Set(PUBLISH_MODE_IDS).size, PUBLISH_MODE_IDS.length)
  for (const r of PUBLISH_MODES) {
    assert.deepEqual(Object.keys(r).sort(), ['browserSignable', 'chains', 'id', 'indexedAsText', 'maxBytesPerTx', 'needsContract', 'note', 'permanence', 'status', 'trustNote'], r.id)
    assert.ok(r.chains.length > 0 && r.chains.every((c) => c === 'eth' || c === 'sol' || c === 'btc'), r.id)
    assert.ok((PERMANENCE_CLASSES as readonly string[]).includes(r.permanence), r.id)
    assert.ok(typeof r.trustNote === 'string' && r.trustNote.length > 0 && typeof r.note === 'string' && r.note.length > 0, r.id)
    for (const k of ['indexedAsText', 'needsContract', 'browserSignable'] as const) assert.equal(typeof r[k], 'boolean', `${r.id}.${k}`)
    assert.ok(r.maxBytesPerTx === null || (Number.isInteger(r.maxBytesPerTx) && r.maxBytesPerTx > 0), r.id)
  }
})

test('available now: exactly eth.calldata.null, eth.calldata.self, sol.memo, btc.inscription; the elite options and fallbacks are reserved', () => {
  assert.deepEqual(PUBLISH_MODES.filter((r) => r.status === 'available').map((r) => r.id), ['eth.calldata.null', 'eth.calldata.self', 'sol.memo', 'btc.inscription'])
  assert.deepEqual(PUBLISH_MODES.filter((r) => r.status === 'reserved').map((r) => r.id), ['eth.sstore2', 'sol.arweave-anchor', 'sol.account', 'sol.noop', 'arweave.turbo'])
  for (const id of ['eth.calldata.raw', 'eth.log', 'eth.blob', 'arweave.irys', 'nope']) assert.equal(publishModeRow(id), undefined, id)
})

test('CC-1 capabilities and permanence classes', () => {
  const row = (id: string) => publishModeRow(id)!
  const caps = (id: string) => { const r = row(id); return { chains: [...r.chains], permanence: r.permanence, indexedAsText: r.indexedAsText, maxBytesPerTx: r.maxBytesPerTx, needsContract: r.needsContract, browserSignable: r.browserSignable } }
  assert.deepEqual(caps('eth.calldata.null'), { chains: ['eth'], permanence: 'history', indexedAsText: true, maxBytesPerTx: 98_304, needsContract: false, browserSignable: true })
  assert.deepEqual(caps('eth.calldata.self'), { chains: ['eth'], permanence: 'history', indexedAsText: true, maxBytesPerTx: 98_304, needsContract: false, browserSignable: true })
  assert.deepEqual(caps('sol.memo'), { chains: ['sol'], permanence: 'history', indexedAsText: true, maxBytesPerTx: null, needsContract: false, browserSignable: true })
  // SSTORE2: plain CREATE (no factory), 10,599 B per chunk post-fork, state.
  assert.deepEqual(caps('eth.sstore2'), { chains: ['eth'], permanence: 'state', indexedAsText: false, maxBytesPerTx: 10_599, needsContract: false, browserSignable: true })
  // The anchor: text on Arweave, one SOL anchor memo per copy.
  assert.deepEqual(caps('sol.arweave-anchor'), { chains: ['sol'], permanence: 'arweave', indexedAsText: true, maxBytesPerTx: null, needsContract: false, browserSignable: true })
  // Loader-v3 frozen buffer: 972 B per Write, native loader, state.
  assert.deepEqual(caps('sol.account'), { chains: ['sol'], permanence: 'state', indexedAsText: false, maxBytesPerTx: 972, needsContract: false, browserSignable: true })
  assert.match(row('sol.account').note, /loader-v3 buffer/i)
  assert.deepEqual(caps('sol.noop'), { chains: ['sol'], permanence: 'history', indexedAsText: false, maxBytesPerTx: null, needsContract: true, browserSignable: true })
  assert.deepEqual(caps('arweave.turbo'), { chains: ['eth', 'sol'], permanence: 'arweave', indexedAsText: true, maxBytesPerTx: null, needsContract: false, browserSignable: true })
  assert.match(row('arweave.turbo').note, /arweave\.irys/)
})

test('E7b: btc.inscription — the btc lane\'s single mode: history, 100,000 B per copy, text/plain', () => {
  const r = publishModeRow('btc.inscription')!
  assert.deepEqual([r.chains, r.status, r.permanence, r.maxBytesPerTx, r.indexedAsText, r.needsContract], [['btc'], 'available', 'history', 100_000, true, false])
  assert.match(r.note, /text\/plain;charset=utf-8/)
})

test('job-level Arweave copy: reserved, Arweave permanence', () => {
  assert.deepEqual({ status: ARWEAVE_COPY.status, permanence: ARWEAVE_COPY.permanence }, { status: 'reserved', permanence: 'arweave' })
  assert.ok(ARWEAVE_COPY.trustNote.length > 0)
})

test('defaults and per-chain lists', () => {
  assert.deepEqual(DEFAULT_PUBLISH_MODE, { eth: 'eth.calldata.null', sol: 'sol.memo', btc: 'btc.inscription' })
  assert.deepEqual(publishModesFor('btc'), ['btc.inscription'])
  for (const c of ['eth', 'sol', 'btc'] as const) assert.ok(publishModesFor(c).includes(DEFAULT_PUBLISH_MODE[c]))
  assert.deepEqual(publishModesFor('eth'), ['eth.calldata.null', 'eth.calldata.self', 'eth.sstore2', 'arweave.turbo'])
  assert.deepEqual(publishModesFor('sol'), ['sol.memo', 'sol.arweave-anchor', 'sol.account', 'sol.noop', 'arweave.turbo'])
  assert.deepEqual([...FEE_STRATEGIES], ['passive', 'economy', 'prompt'])
  assert.equal(defaultFeeStrategy('drain'), 'passive')
  assert.equal(defaultFeeStrategy({ copies: 3 }), 'economy')
})

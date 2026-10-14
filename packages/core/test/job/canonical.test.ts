// canonicalJson / sha256Hex / jobId (spec §4.1). The expected id is computed here independently with node:crypto over a
// canonical string written out by hand. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { canonicalJson, jobId, normalizeJob, sha256Hex } from '../../src/job/index.ts'
import type { JobDef } from '../../src/contracts/index.ts'
import { readJson } from './helpers.ts'

const nodeSha = (b: string | Uint8Array): string => createHash('sha256').update(b).digest('hex')
const expected = readJson<Record<string, { id: string; def: JobDef }>>('jobs/valid/expected.json')

// eth-drain-null.json's canonical def, keys sorted at every level, no whitespace (written by hand).
const ETH_DRAIN_CANONICAL = '{"chains":{"eth":{"budgetUsd":10,"clawbackTo":null,"distinctCopies":true,"feeStrategy":"passive",'
  + '"keyAddress":"0x8739Eb87B3d11f221Df63454F8D229a1A4F4049C","maxTipGwei":3,"mode":"drain","publishMode":"eth.calldata.null"}},'
  + '"format":"vt-job/1","messageBytes":50,"messageSha256":"83be1d5879a59ca063ed2d02bcfde19e259cd991479d5ef45c899854f6900048",'
  + '"name":"eth drain to the null address","network":"local"}'

test('jobId(eth-drain-null) = the first 16 hex of node:crypto sha256 over the hand-written canonical JSON', () => {
  const input = readJson<Record<string, unknown>>('jobs/valid/eth-drain-null.json')
  const { def } = normalizeJob(input, { network: 'local' })
  assert.equal(canonicalJson(def), ETH_DRAIN_CANONICAL)
  const want = nodeSha(Buffer.from(ETH_DRAIN_CANONICAL, 'utf8')).slice(0, 16)
  assert.equal(jobId(def), want)
  assert.equal(want, expected['eth-drain-null.json'].id)
  assert.match(jobId(def), /^[0-9a-f]{16}$/)
})

test('the same text on two networks gives two ids (network is part of the canonical JSON)', () => {
  const input = readJson<Record<string, unknown>>('jobs/valid/eth-drain-null.json')
  const local = normalizeJob(input, { network: 'local' }).def
  const testnet = normalizeJob({ ...input, network: 'testnet' }, { network: 'testnet' }).def
  assert.equal(local.messageSha256, testnet.messageSha256)
  assert.notEqual(jobId(local), jobId(testnet))
})

test('every pinned valid fixture id equals jobId of its pinned def', () => {
  for (const [f, { id, def }] of Object.entries(expected)) assert.equal(jobId(def), id, f)
})

test('canonicalJson: keys sorted at every level, no whitespace, arrays keep their order', () => {
  assert.equal(canonicalJson({ b: 1, a: [3, 1, { d: true, c: null }], 'é': 'x', A: 'y' }), '{"A":"y","a":[3,1,{"c":null,"d":true}],"b":1,"é":"x"}')
  assert.equal(canonicalJson({ z: { y: { x: 'deep' } } }), '{"z":{"y":{"x":"deep"}}}')
  assert.equal(canonicalJson('a"b\n'), JSON.stringify('a"b\n'))
  assert.equal(canonicalJson([]), '[]')
  assert.equal(canonicalJson({}), '{}')
  assert.equal(canonicalJson(2.5), '2.5')
  assert.equal(canonicalJson(1e21), '1e+21', 'numbers as JSON.stringify writes them')
  assert.equal(canonicalJson({ a: undefined, b: 1 }), '{"b":1}', 'undefined members are dropped, as JSON.stringify does')
})

test('canonicalJson is stable under key reordering', () => {
  const a = { format: 'vt-job/1', chains: { sol: { b: 1, a: 2 }, eth: { y: [1, 2], x: 'q' } }, n: 1 }
  const b = { n: 1, chains: { eth: { x: 'q', y: [1, 2] }, sol: { a: 2, b: 1 } }, format: 'vt-job/1' }
  assert.equal(canonicalJson(a), canonicalJson(b))
})

test('canonicalJson refuses non-finite numbers and values JSON cannot hold', () => {
  for (const v of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, { a: Number.NaN }, [1, Number.POSITIVE_INFINITY]]) {
    assert.throws(() => canonicalJson(v), RangeError)
  }
  for (const v of [undefined, () => 1, Symbol('s'), 10n, [undefined]]) assert.throws(() => canonicalJson(v), TypeError)
})

test('sha256Hex: a string is hashed as its UTF-8 bytes; bytes as given', () => {
  assert.equal(sha256Hex(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  for (const s of ['abc', 'é', '😀 漢字', 'A synthetic vt fixture message.\nIt has two lines.\n']) {
    assert.equal(sha256Hex(s), nodeSha(Buffer.from(s, 'utf8')), s)
  }
  const bytes = new Uint8Array([0, 1, 2, 255])
  assert.equal(sha256Hex(bytes), nodeSha(bytes))
  assert.equal(sha256Hex('A synthetic vt fixture message.\nIt has two lines.\n'), '83be1d5879a59ca063ed2d02bcfde19e259cd991479d5ef45c899854f6900048')
})

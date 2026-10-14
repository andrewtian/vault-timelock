// The body check (bodycheck.ts, spec §5.1 "Strings in bodies"): every string of a JSON body, values and member names
// at any depth, through core's assertNoSecretOrIp, with job.key-like / job.ip-like mapped to api.key-like / api.ip-like;
// typed id fields (contracts TYPED_ID_FIELDS) skipped when they have THEIR field's id shape (S2 review m6); the top-level
// `message` (MESSAGE_TEXT_FIELDS) of POST /jobs never scanned (anywhere else it is). Synthetic values only; the canary is a documentation address.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { MESSAGE_TEXT_FIELDS, TYPED_ID_FIELDS } from '@vault-timelock/core/contracts'
import { bodycheck } from '../src/bodycheck.ts'
import { CANARY, JOB, JOB_INPUT, call, ethTx, guardOf, solSig, startApi } from './helpers.ts'

const HEX64 = 'c0ffee'.repeat(10) + 'c0ff'
function guard(body: unknown): string | null {
  try { bodycheck(body) } catch (e) { return (e as { guardId: string }).guardId }
  return null
}

test('a key-like or IP-like string anywhere → api.key-like / api.ip-like (core job.* ids mapped)', () => {
  for (const s of [HEX64, `0x${HEX64}`, 'AGE-SECRET-KEY-1QQQ', 'see https://example.org', 'abc.onion', 'a'.repeat(87),
    'abandon ability able about above absent absorb abstract absurd abuse access accident', JSON.stringify(Array.from({ length: 32 }, (_, i) => i))]) {
    assert.equal(guard({ text: s }), 'api.key-like', s.slice(0, 40))
    assert.equal(guard({ a: [{ b: { c: s } }] }), 'api.key-like')
    assert.equal(guard(s), 'api.key-like')
  }
  for (const s of [CANARY, `host ${CANARY}:443`, '127.0.0.1', '::1', 'fe80::1', `http://${CANARY}/`]) {
    assert.equal(guard({ reason: s }), 'api.ip-like', s)
    assert.equal(guard([[s]]), 'api.ip-like')
  }
  for (const s of ['drained: next copy unaffordable', '12:30:45', 'eth.calldata.null', '0.004', '4000000000000000', 'broadcast', '']) {
    assert.equal(guard({ text: s }), null, s)
  }
})

test('member names are scanned too', () => {
  assert.equal(guard({ [HEX64]: 1 }), 'api.key-like')
  assert.equal(guard({ caps: { [CANARY]: {} } }), 'api.ip-like')
})

// Each typed field has ITS id format (S2 review m6): a value that is an id of another field's shape is scanned like any string.
const OUTPOINT = `${HEX64}:3`, PUBKEY = `02${HEX64}`, BLOCKHASH = 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi'
const SHAPES: Record<string, string[]> = {
  txId: [ethTx(5), HEX64, solSig(5)], prevId: [ethTx(5), HEX64, solSig(5)], replaces: [ethTx(5), HEX64, solSig(5)],
  rawSha256: [HEX64], payloadSha256: [HEX64], sha256: [HEX64], messageSha256: [HEX64],
  blockhash: [BLOCKHASH], pubkey: [PUBKEY], inputs: [OUTPOINT],
}
test('typed id fields: a value of THAT field\'s id shape is skipped at any depth; anything else under those names is scanned', () => {
  assert.deepEqual(Object.keys(SHAPES).sort(), [...TYPED_ID_FIELDS].sort(), 'a shape for every typed field')
  const all = [...new Set(Object.values(SHAPES).flat())]
  for (const k of TYPED_ID_FIELDS) {
    for (const v of SHAPES[k]) {
      assert.equal(guard({ [k]: v }), null, `${k} ${v}`)
      assert.equal(guard({ gen: 1, type: 'intent', data: { [k]: v, eth: { [k]: v } } }), null, k)
    }
    // every id of ANOTHER field's shape that is key-like (64 hex, a 64..88 base58 run) is scanned here
    for (const v of all.filter((x) => !SHAPES[k].includes(x))) {
      const keyLike = /^(?:0x)?[0-9a-f]{64}(?::\d+)?$/.test(v) || /^[1-9A-HJ-NP-Za-km-z]{64,88}$/.test(v) || /^0[23][0-9a-f]{64}$/.test(v)
      if (keyLike) assert.equal(guard({ [k]: v }), 'api.key-like', `${k} must not skip ${v.slice(0, 12)}`)
    }
    assert.equal(guard({ [k]: `https://x.example/${HEX64}` }), 'api.key-like', k)
    assert.equal(guard({ [k]: `0x${HEX64.toUpperCase()}` }), 'api.key-like', k)
    assert.equal(guard({ [k]: CANARY }), 'api.ip-like', k)
    assert.equal(guard({ [k]: { nested: HEX64 } }), 'api.key-like', k)
  }
  // the cases the review names: an 87-character base58 run under blockhash, a base58 run under a digest field, hex under a txId-less name
  assert.equal(guard({ blockhash: solSig(5) }), 'api.key-like')
  assert.equal(guard({ sha256: solSig(5) }), 'api.key-like')
  assert.equal(guard({ payloadSha256: ethTx(5) }), 'api.key-like')
  assert.equal(guard({ pubkey: HEX64 }), 'api.key-like')
  assert.equal(guard({ inputs: [HEX64] }), 'api.key-like')
  assert.equal(guard({ inputs: [OUTPOINT] }), null)
  assert.equal(guard({ note: HEX64 }), 'api.key-like') // not a typed name
})

test('the top-level message of POST /jobs is never scanned (validateMessage governs it); anywhere else, and nested, it is', () => {
  const sealed = `drand quicknet ${HEX64}\nhttps://api.drand.sh/\nsocks 127.0.0.1:9050\n`
  const jobs = (body: unknown): string | null => { try { bodycheck(body, { messageText: true }) } catch (e) { return (e as { guardId: string }).guardId } return null }
  for (const k of MESSAGE_TEXT_FIELDS) {
    assert.equal(jobs({ [k]: sealed, name: 'x' }), null)
    assert.equal(guard({ [k]: sealed, name: 'x' }), 'api.ip-like', 'another route: scanned')
    assert.equal(jobs({ data: { [k]: sealed } }), 'api.ip-like')
    assert.equal(jobs({ [k]: { text: HEX64 } }), 'api.key-like')
  }
})

test('a deeply nested body is walked without overflowing the stack', () => {
  let deep: unknown = HEX64
  for (let i = 0; i < 50_000; i++) deep = i % 2 === 0 ? [deep] : { k: deep }
  assert.equal(guard(deep), 'api.key-like')
  let fine: unknown = 'ok'
  for (let i = 0; i < 50_000; i++) fine = [fine]
  assert.equal(guard(fine), null)
})

test('over HTTP: every JSON route checks its body (400, nothing journaled); POST /jobs keeps its own job.* ids', async (t) => {
  const a = await startApi()
  t.after(() => a.close())
  await call(a.port, { path: `/jobs/${JOB}/chains/eth/lease`, body: { op: 'acquire', holder: 'cli' } })
  const n = a.api.registry.journalOf(JOB).all().length
  const note = await call(a.port, { path: `/jobs/${JOB}/chains/eth/events`, body: { gen: 1, type: 'note', data: { text: `key ${HEX64}` } } })
  assert.equal(note.status, 400)
  assert.equal(guardOf(note), 'api.key-like')
  assert.ok(!note.text.includes(HEX64))
  assert.equal(guardOf(await call(a.port, { path: `/jobs/${JOB}/chains/eth/events`, body: { gen: 1, type: 'note', data: { text: CANARY } } })), 'api.ip-like')
  for (const [path, body] of [
    [`/jobs/${JOB}/arm`, { chains: ['eth'], confirm: { typed: HEX64, amounts: {} }, caps: {} }],
    [`/jobs/${JOB}/stop`, { chain: null, why: CANARY }],
    [`/jobs/${JOB}/skip`, { [HEX64]: true }],
    [`/jobs/${JOB}/resume`, { chain: 'eth', tipCapGwei: HEX64 }],
    [`/jobs/${JOB}/close`, { chain: 'eth', note: HEX64 }],
    [`/jobs/${JOB}/chains/eth/lease`, { op: 'renew', holder: CANARY, gen: 1 }],
    [`/jobs/${JOB}/chains/eth/tickets`, { gen: 1, txId: `https://${HEX64}` }],
    [`/jobs/${JOB}/chains/eth/resolve`, { txId: ethTx(1), action: 'mark-done', typed: HEX64 }],
  ] as const) {
    const r = await call(a.port, { path, body })
    assert.equal(r.status, 400, path)
    assert.ok(guardOf(r) === 'api.key-like' || guardOf(r) === 'api.ip-like', `${path}: ${guardOf(r)}`)
    assert.ok(!r.text.includes(HEX64) && !r.text.includes(CANARY))
  }
  assert.equal(a.api.registry.journalOf(JOB).all().length, n)
  assert.equal(guardOf(await call(a.port, { path: '/jobs', body: { ...JOB_INPUT, name: HEX64 } })), 'job.key-like')
  assert.equal(guardOf(await call(a.port, { path: '/jobs', body: { ...JOB_INPUT, name: CANARY } })), 'job.ip-like')
  // a SEALED-like inline message (URLs, 64 hex, the loopback SOCKS port) is message text: accepted
  const sealed = { ...JOB_INPUT, message: `drand quicknet ${HEX64}\nhttps://api.drand.sh/\nsocks 127.0.0.1:9050\n` }
  assert.equal((await call(a.port, { path: '/jobs', body: sealed })).status, 201)
})

// node --test test/engine-sol.test.mjs — I3 + Efix3: the SOL expiry proof needs EVERY endpoint (isBlockhashValid false, asked with
// minContextSlot = the fetch slot; history null with context slot ≥ that answer's slot; twice ≥ 4 s apart); a signature found
// by ANY endpoint finishes, never loops. An unreadable / ambiguous isBlockhashValid answer is NO proof (fail closed).
// The finalized-height rule (past the declared lastValidBlockHeight) is KEPT as well: the proof is never weaker than before.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { base58 } from '@scure/base'
import { _solWait } from '../../src/engine/engine.js'
import { armedLedger } from '../engine/fakes.ts'   // E2 security fix: a landed tx settles in the armed spend-cap ledger

const SIG = '5'.repeat(88), LVB = 100, BH = '1'.repeat(32), seenMin = []
function mockFetch(eps) {   // eps[i] = { height, slot, histSlot, found }  (endpoint index; null route = ep 0 = preferred)
  globalThis.fetch = async (url, { body }) => {
    const j = JSON.parse(body), m = /\/relay\/sol(?:\/ep\/(\d))?$/.exec(url), e = eps[m[1] == null ? 0 : Number(m[1])]
    let result
    if (j.method === 'getLatestBlockhash') result = { context: { slot: e.slot }, value: { blockhash: '1'.repeat(32), lastValidBlockHeight: e.height + 150 } }
    else if (j.method === 'isBlockhashValid') {
      seenMin.push(j.params[1]?.minContextSlot)
      if (e.bhErr) return new Response(JSON.stringify({ jsonrpc: '2.0', id: j.id, error: { code: -32005, message: 'node is unhealthy' } }), { status: 200 })
      result = e.bhRaw !== undefined ? e.bhRaw : { context: { slot: e.bhSlot ?? e.slot }, value: e.valid ?? e.height <= LVB }   // default: valid until the finalized height passes LVB
    }
    else if (j.method === 'getSignatureStatuses') result = { context: { slot: j.params[1].searchTransactionHistory ? e.histSlot : e.slot }, value: j.params[0].map(() => (j.params[1].searchTransactionHistory && e.found ? { confirmationStatus: 'confirmed', err: null, slot: 1 } : null)) }
    else if (j.method === 'sendTransaction') result = SIG
    else if (j.method === 'getTransaction') result = { slot: 1, meta: { err: null, fee: 5000, computeUnitsConsumed: 1 }, transaction: { message: { accountKeys: ['P', 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'], instructions: [{ programIdIndex: 1, data: base58.encode(Uint8Array.from([104, 105])) }] } } }
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: j.id, result }), { status: 200 })
  }
}
const tx = (slot) => ({ attempts: [{ id: SIG, blockhash: BH, lastValidBlockHeight: LVB, cuPrice: 100000, ...(slot ? { slot } : {}) }], raws: { [SIG]: 'AA==' }, payload: Uint8Array.from([104, 105]), state: 'sent' })
const run = (eps, ms, slot, watchOnly = false) => { mockFetch(eps); const t = tx(slot); if (watchOnly) t.raws = {}; const  until = Date.now() + ms; return _solWait(t, t.attempts[0], { notify: () => {}, alive: () => Date.now() < until, poll: 10, solEndpoints: eps.length, journal: JOURNAL, ledger: armedLedger('sol', 10n ** 9n) }).then((r) => ({ r, t })) }
// §7.2: the journal is mandatory (included + readback are appended; nothing is sent in these tests)
const JOURNAL = { append: async () => {}, intent: async () => { throw new Error('no sends here') } }

test('both endpoints prove expiry (twice, ≥ 4 s apart) → expired', { timeout: 30000 }, async () => {
  const { r, t } = await run([{ height: 120, slot: 500, histSlot: 510 }, { height: 121, slot: 501, histSlot: 505 }], 15000)
  assert.equal(r, 'expired'); assert.match(t.reason, /on all 2 endpoint/)
})
test('one lagging endpoint (height ≤ lastValidBlockHeight) → never expired', { timeout: 30000 }, async () => {
  const { r } = await run([{ height: 120, slot: 500, histSlot: 510 }, { height: 99, slot: 400, histSlot: 410 }], 9000)
  assert.equal(r, 'aborted')
})
test('history context slot behind the finalized slot → not a proof → never expired', { timeout: 30000 }, async () => {
  const { r } = await run([{ height: 120, slot: 500, histSlot: 510 }, { height: 121, slot: 501, histSlot: 480 }], 9000)
  assert.equal(r, 'aborted')
})
test('a signature found in history by ANY endpoint → confirmed + readback, no re-sign, no loop', { timeout: 30000 }, async () => {
  const { r, t } = await run([{ height: 120, slot: 500, histSlot: 510 }, { height: 121, slot: 501, histSlot: 505, found: true }], 15000)
  assert.equal(r, 'confirmed'); assert.equal(t.landedId, SIG); assert.equal(t.readback.ok, true)
})

// ---- Efix3: isBlockhashValid replaces the block-height reasoning ----
test('Efix3: valid blockhash on every endpoint → wait (never expired; a height past LVB does not matter)', { timeout: 30000 }, async () => {
  const { r, t } = await run([{ height: 120, slot: 500, histSlot: 510, valid: true }, { height: 121, slot: 501, histSlot: 505, valid: true }], 9000, 450, true)
  assert.equal(r, 'aborted'); assert.notEqual(t.state, 'expired')
})
test('Efix3: invalid on every endpoint AND the finalized height past LVB on every endpoint → expired; every ask carries minContextSlot', { timeout: 30000 }, async () => {
  seenMin.length = 0
  const { r, t } = await run([{ height: 120, slot: 500, histSlot: 510, valid: false }, { height: 121, slot: 501, histSlot: 505, valid: false }], 15000, 450)
  assert.equal(r, 'expired'); assert.match(t.reason, /isBlockhashValid/)
  assert.ok(seenMin.length > 0 && seenMin.every((m) => m === 450), 'every ask carries minContextSlot = the fetch slot')
})
test('Efix3 (single-endpoint trust): isBlockhashValid says invalid but the finalized height is NOT past LVB → never expired (no weaker than before)', { timeout: 30000 }, async () => {
  const { r } = await run([{ height: 50, slot: 500, histSlot: 510, valid: false }, { height: 50, slot: 501, histSlot: 505, valid: false }], 9000, 450, true)
  assert.equal(r, 'aborted')
})
test('Efix3 (single-endpoint trust): the finalized height is past LVB but one endpoint still calls the blockhash valid → never expired', { timeout: 30000 }, async () => {
  const { r } = await run([{ height: 120, slot: 500, histSlot: 510, valid: false }, { height: 121, slot: 501, histSlot: 505, valid: true }], 9000, 450)
  assert.equal(r, 'aborted')
})
test('Efix3 (single-endpoint trust): one endpoint errors on isBlockhashValid while the other says invalid → never expired', { timeout: 30000 }, async () => {
  const { r } = await run([{ height: 120, slot: 500, histSlot: 510, valid: false }, { height: 121, slot: 501, histSlot: 505, bhErr: true }], 9000, 450)
  assert.equal(r, 'aborted')
})
test('Efix3: an RPC error from isBlockhashValid is NOT proof → no expiry, no re-sign', { timeout: 30000 }, async () => {
  const { r, t } = await run([{ height: 120, slot: 500, histSlot: 510, bhErr: true }, { height: 121, slot: 501, histSlot: 505, bhErr: true }], 9000, 450, true)   // watch-only: no ticket in this harness (the rebroadcast on an unreadable answer is pinned in sol-expiry.test.ts)
  assert.equal(r, 'aborted'); assert.notEqual(t.state, 'expired')
})
test('Efix3: ambiguous answers (non-boolean value, missing value, no slot, a bank older than the fetch slot) are NOT proof', { timeout: 60000 }, async () => {
  for (const bhRaw of [{ context: { slot: 500 }, value: null }, { context: { slot: 500 }, value: 'false' }, { context: { slot: 500 } }, { value: false }, null, false, { context: { slot: 400 }, value: false }]) {
    const { r, t } = await run([{ height: 120, slot: 500, histSlot: 510, bhRaw }], 4500, 450, true)
    assert.equal(r, 'aborted', JSON.stringify(bhRaw)); assert.notEqual(t.state, 'expired')
  }
})
test('Efix3: history older than the validity answer (history lagging) → not a proof', { timeout: 30000 }, async () => {
  const { r } = await run([{ height: 120, slot: 500, histSlot: 499, bhSlot: 505, valid: false }], 9000, 450)
  assert.equal(r, 'aborted')
})

// CC-1a (E1 concern 1, E1 review X-2): how the API's body check classifies a JSON string member. S2's bodycheck must
// classify exactly like `classify` below:
//   · message text: a top-level member named in MESSAGE_TEXT_FIELDS (the inline `message` of POST /jobs) — governed by
//     validateMessage, never by the structural scan;
//   · typed id: a member named in TYPED_ID_FIELDS — skipped (its exact format is checked by normalizeJob or
//     validateEvent);
//   · structural: every other string — assertNoSecretOrIp (job.key-like / job.ip-like, mapped to api.* by S2).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { MESSAGE_TEXT_FIELDS, TYPED_ID_FIELDS } from '../../src/contracts/index.ts'
import { fixture, guardOf, loadJobModule, readJson } from './job-module.ts'
import type { JobModule } from './job-module.ts'

type Cls = 'message-text' | 'typed-id' | 'structural'
const MESSAGE_TEXT: readonly string[] = MESSAGE_TEXT_FIELDS
const TYPED: readonly string[] = TYPED_ID_FIELDS

function classify(path: readonly string[]): Cls {
  if (path.length === 1 && MESSAGE_TEXT.includes(path[0])) return 'message-text'
  const key = [...path].reverse().find((k) => !/^\d+$/.test(k)) ?? ''
  return TYPED.includes(key) ? 'typed-id' : 'structural'
}

// The reference body check: returns the first refusal's guard id, or null when the body passes.
function bodycheck(m: JobModule, body: unknown, path: string[] = []): string | null {
  if (typeof body === 'string') {
    const cls = classify(path)
    if (cls === 'typed-id') return null
    return guardOf(() => (cls === 'message-text' ? m.validateMessage(body) : m.assertNoSecretOrIp(body, path.join('.'))))
  }
  if (body !== null && typeof body === 'object') {
    for (const [k, v] of Object.entries(body)) {
      const g = bodycheck(m, v, [...path, k])
      if (g !== null) return g
    }
  }
  return null
}

const SEALED = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(readFileSync(fixture('messages/sealed-like.txt')))
const job = readJson<Record<string, unknown>>('jobs/valid/both-testnet.json')
const HEX = (c: string): string => c.repeat(64)
const ETH_TX = `0x${HEX('a')}`

test('a SEALED.txt-shaped inline message passes the field classification (message text, not structural)', async () => {
  const m = await loadJobModule()
  assert.equal(classify(['message']), 'message-text')
  assert.notEqual(guardOf(() => m.assertNoSecretOrIp(SEALED, 'message')), null, 'the structural scan alone would refuse it (URL, 64-hex)')
  assert.equal(guardOf(() => m.validateMessage(SEALED)), null)
  assert.equal(bodycheck(m, { ...job, message: SEALED }), null)
})

test('the by-digest form passes: messageSha256 is a typed id', async () => {
  const m = await loadJobModule()
  const { message: _drop, ...rest } = job
  const body = { ...rest, messageSha256: m.sha256Hex(SEALED), messageBytes: new TextEncoder().encode(SEALED).length }
  assert.equal(classify(['messageSha256']), 'typed-id')
  assert.equal(guardOf(() => m.assertNoSecretOrIp(body.messageSha256, 'messageSha256')), 'job.key-like', 'a digest is key-shaped')
  assert.equal(bodycheck(m, body), null)
})

test('an intent with replaces passes: replaces is a typed id', async () => {
  const m = await loadJobModule()
  const intent = {
    gen: 1, type: 'intent',
    data: { txId: `0x${HEX('b')}`, copy: 1, part: 1, parts: 1, attempt: 2, replaces: ETH_TX, rawSha256: HEX('c'), payloadSha256: HEX('d'), reserved: '1',
      eth: { nonce: 0, tip: '1', maxFee: '2', gas: '21240', to: '0x0000000000000000000000000000000000000000' } },
  }
  assert.equal(classify(['data', 'replaces']), 'typed-id')
  assert.equal(guardOf(() => m.assertNoSecretOrIp(ETH_TX, 'data.replaces')), 'job.key-like')
  assert.equal(bodycheck(m, intent), null)
})

test('message text is only the top-level member: the same text anywhere else is structural and refused', async () => {
  const m = await loadJobModule()
  assert.equal(classify(['chains', 'eth', 'message']), 'structural')
  assert.equal(classify(['data', 'message']), 'structural')
  assert.notEqual(bodycheck(m, { ...job, message: 'fine', name: SEALED }), null)
  assert.notEqual(bodycheck(m, { gen: 1, type: 'note', data: { text: 'ok', message: SEALED } }), null)
})

test('an inline message is still checked: validateMessage refuses an unambiguous secret in it', async () => {
  const m = await loadJobModule()
  assert.equal(bodycheck(m, { ...job, message: `${SEALED}AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n` }), 'message.secret')
})

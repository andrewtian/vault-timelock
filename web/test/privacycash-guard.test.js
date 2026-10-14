// The worker's guarded fetch (src/privacycash/guard.js) and the shims (install-shims.js). A fake `native` fetch records everything that
// would leave the worker. Synthetic values only.
import { test, expect } from 'vitest'
import { createGuardedFetch } from '../src/privacycash/guard.js'
import { installShims } from '../src/privacycash/install-shims.js'
import { KEY_BASE_PATH, SDK_RELAYER_URL } from '../src/privacycash/limits.js'

const ORIGIN = 'http://127.0.0.1:5180'
const HEXOUT = 'ab'.repeat(40)
const SIG = '5'.repeat(88)
const JOB = '0123456789abcdef', RECIPIENT = 'LaneLaneLaneLaneLaneLaneLaneLaneLaneLane1'
const LANE_REQ = { job: JOB, tryIndex: 3, allowance: 7_000_000, recipient: RECIPIENT }
const v2 = (m, o = {}) => `v2.${o.recipient ?? RECIPIENT}.${o.job ?? JOB}.${o.tryIndex ?? m.tryIndex}.${m.allowanceLamports}.${'ab'.repeat(16)}.${o.sha ?? m.bodySha256}.${1_900_000_000_000}.${'cd'.repeat(32)}`
const sha256 = async (t) => Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t))).toString('hex')
function rig(answer = () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }), mintAnswer = (m) => new Response(JSON.stringify({ authorization: v2(m) }), { status: 200 })) {
  const sent = [], mints = []
  const native = async (url, init) => {
    if (url.endsWith('/privacycash/lane')) { const m = JSON.parse(init.body); mints.push({ url, init, body: m }); return mintAnswer(m) }
    sent.push({ url, init }); return answer(url, init)
  }
  const g = createGuardedFetch({ origin: ORIGIN, native, timeout: () => new AbortController().signal })
  return { g, sent, mints }
}
const refused = async (p) => { try { await p; return null } catch (e) { return e instanceof TypeError ? e.message : `wrong error: ${e}` } }

test('the SDK\'s relayer calls go out as same-origin /relay/privacycash/relayer/* with the privacy flags', async () => {
  const { g, sent } = rig()
  await g.fetch(`${SDK_RELAYER_URL}/config`)
  await g.fetch(`${SDK_RELAYER_URL}/utxos/range?start=0&end=20000`)
  await g.fetch(`${SDK_RELAYER_URL}/merkle/proofv2/?commitments=1,2`)
  await g.fetch(`${SDK_RELAYER_URL}/utxos/check/${HEXOUT}`)
  await g.fetch(`${SDK_RELAYER_URL}/utxos/indices`, { method: 'POST', body: JSON.stringify({ encrypted_outputs: [HEXOUT] }), headers: { 'X-Evil': '1', Cookie: 'a=b' } })
  await g.fetch(`${ORIGIN}/relay/privacycash/rpc`, { method: 'POST', body: '{"jsonrpc":"2.0"}' })
  await g.fetch(`${ORIGIN}${KEY_BASE_PATH}.wasm`)
  expect(sent.map((s) => new URL(s.url).pathname + new URL(s.url).search)).toEqual([
    '/relay/privacycash/relayer/config', '/relay/privacycash/relayer/utxos/range?start=0&end=20000', '/relay/privacycash/relayer/merkle/proofv2/?commitments=1,2',
    `/relay/privacycash/relayer/utxos/check/${HEXOUT}`, '/relay/privacycash/relayer/utxos/indices', '/relay/privacycash/rpc', '/relay/privacycash/artifacts/transaction2.wasm'])
  for (const s of sent) {
    expect(s.url.startsWith(ORIGIN)).toBe(true)
    expect(s.init).toMatchObject({ credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', mode: 'same-origin' })
    expect([...s.init.headers.keys()].filter((k) => k !== 'content-type')).toEqual([])           // nothing from the caller crosses
  }
  expect(sent[4].init.headers.get('content-type')).toBe('application/json')
  expect(sent[0].init.headers.has('content-type')).toBe(false)
})

test('the SDK\'s hard-coded upstream host is rewritten to the relay, never fetched', async () => {
  const { g, sent } = rig()
  await g.fetch('https://api3.privacycash.org/config')
  await g.fetch('https://api3.privacycash.org/utxos/range?start=5&end=20005')
  expect(sent.map((s) => s.url)).toEqual([`${ORIGIN}/relay/privacycash/relayer/config`, `${ORIGIN}/relay/privacycash/relayer/utxos/range?start=5&end=20005`])
})

test('everything else is refused before a byte leaves: other hosts, paths, methods, queries, bodies, encodings, fragments, credentials', async () => {
  const { g, sent } = rig()
  const bad = [
    ['https://evil.example/relay/privacycash/relayer/config'], ['http://127.0.0.1:5181/relay/privacycash/relayer/config'], ['https://api3.privacycash.org.evil.example/config'],
    ['/relay/eth'], ['/api/status'], ['/relay/privacycash/relayer/deposit', { method: 'POST', body: '{}' }], ['/relay/privacycash/relayer/withdraw/spl', { method: 'POST', body: '{}' }],
    ['/relay/privacycash/relayer/merkle/root'], ['/relay/privacycash/relayer/config/'], ['/relay/privacycash/relayer/%2e%2e/config'], ['/relay/privacycash/relayer/config?token=usdc'],
    ['/relay/privacycash/relayer/utxos/range?start=0&end=20000&token=x'], ['/relay/privacycash/relayer/utxos/range'], ['/relay/privacycash/relayer/merkle/proofv2/?commitments=1'],
    ['/relay/privacycash/relayer/merkle/proofv2/?commitments=a,b'], [`/relay/privacycash/relayer/utxos/check/${HEXOUT}?x=1`], ['/relay/privacycash/relayer/utxos/check/xyz'],
    ['/relay/privacycash/relayer/config', { method: 'POST', body: '{}' }], ['/relay/privacycash/relayer/config', { method: 'POST' }], ['/relay/privacycash/relayer/config', { method: 'DELETE' }],
    ['/relay/privacycash/relayer/utxos/indices', { method: 'PUT', body: '{}' }], ['/relay/privacycash/relayer/utxos/indices', { method: 'GET' }], ['/relay/privacycash/relayer/utxos/indices'], ['/relay/privacycash/relayer/utxos/indices', { method: 'POST', body: 5 }],
    ['/relay/privacycash/relayer/config', { body: 'x' }], ['/relay/privacycash/rpc', { method: 'GET' }], ['/relay/privacycash/artifacts/transaction2.wasm#x'],
    ['http://user:pw@127.0.0.1:5180/relay/privacycash/relayer/config'], [123], [null], [{}],
  ]
  for (const [u, init] of bad) expect(await refused(g.fetch(u, init)), JSON.stringify([u, init])).toMatch(/^privacycash: blocked request/)
  expect(sent).toEqual([])
})

test('error messages never carry the URL, query, body or address', async () => {
  const { g } = rig()
  const secretUrl = `/relay/privacycash/relayer/merkle/proofv2/?commitments=123456789,987654321&secret=SOLANAADDRESSSOLANAADDRESSSOLANAADDR`
  const msg = await refused(g.fetch(secretUrl))
  expect(msg).not.toMatch(/123456789|SOLANAADDRESS|commitments/)
})

test('withdraw: no lane request, no request; with one the guard mints the v2 authorization for the exact body and sends it as x-vt-pc-lane; `sent` is set BEFORE the request leaves and fires once', async () => {
  let sentAtWire
  const { g, sent, mints } = rig()
  const body = JSON.stringify({ any: 'thing' })
  expect(await refused(g.fetch(`${SDK_RELAYER_URL}/withdraw`, { method: 'POST', body }))).toMatch(/no lane authorization/)
  expect(sent).toEqual([]); expect(mints).toEqual([]); expect(g.state.withdrawSent).toBe(false)
  let events = 0
  g.events.sent = () => { events++; sentAtWire = sent.length }
  g.setLane(LANE_REQ)
  await g.fetch(`${SDK_RELAYER_URL}/withdraw`, { method: 'POST', body })
  expect(sentAtWire).toBe(0)                                                                   // the event fired before native() ran
  expect(events).toBe(1)
  expect(mints).toHaveLength(1)
  expect(mints[0].url).toBe(`${ORIGIN}/api/jobs/${JOB}/privacycash/lane`)
  expect(mints[0].body).toEqual({ bodySha256: await sha256(body), allowanceLamports: '7000000', tryIndex: 3 })
  expect(mints[0].init).toMatchObject({ method: 'POST', credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', mode: 'same-origin' })
  expect(sent[0].init.headers.get('x-vt-pc-lane')).toBe(v2(mints[0].body))
  expect(g.state.withdrawSent).toBe(true)
  // the authorization is for THAT body: another body is another mint, another hash
  await g.fetch(`${SDK_RELAYER_URL}/withdraw`, { method: 'POST', body: '{"other":1}' })
  expect(mints[1].body.bodySha256).toBe(await sha256('{"other":1}')); expect(mints[1].body.bodySha256).not.toBe(mints[0].body.bodySha256)
  for (const bad of ['', null, {}, { ...LANE_REQ, job: 'xyz' }, { ...LANE_REQ, tryIndex: -1 }, { ...LANE_REQ, tryIndex: 1_000_001 }, { ...LANE_REQ, tryIndex: 1.5 }, { ...LANE_REQ, allowance: 0 }, { ...LANE_REQ, allowance: 1.5 }, { ...LANE_REQ, recipient: 'x' }]) {
    g.setLane(bad)                                                                              // a malformed or empty request is none
    expect(await refused(g.fetch(`${SDK_RELAYER_URL}/withdraw`, { method: 'POST', body }))).toMatch(/no lane authorization/)
  }
  expect(mints).toHaveLength(2)
  // the lane header goes ONLY to /withdraw (and nothing else is minted)
  g.setLane(LANE_REQ)
  await g.fetch(`${SDK_RELAYER_URL}/config`)
  expect(sent.at(-1).init.headers.has('x-vt-pc-lane')).toBe(false); expect(mints).toHaveLength(2)
})

test('withdraw: an answer of the mint that is not exactly what was asked for is refused and NOTHING is sent (other recipient, job, try, hash, a smaller allowance, a v1 binding, junk)', async () => {
  const body = '{"x":1}'
  const sha = await sha256(body)
  const cases = {
    'other recipient': (m) => v2(m, { recipient: 'Other'.repeat(8) + 'Other11' }),
    'other job': (m) => v2(m, { job: 'fedcba9876543210' }),
    'other try': (m) => v2(m, { tryIndex: 4 }),
    'other hash': (m) => v2(m, { sha: '00'.repeat(32) }),
    'smaller allowance': (m) => v2({ ...m, allowanceLamports: '6999999' }),
    'a v1 binding': () => `v1.${'A'.repeat(44)}.100.${Date.now() + 1000}.${'a'.repeat(64)}`,
    'junk': () => 'nope',
    'not a string': () => 5,
  }
  for (const [name, f] of Object.entries(cases)) {
    const { g, sent } = rig(undefined, (m) => new Response(JSON.stringify({ authorization: f(m) }), { status: 200 }))
    g.setLane(LANE_REQ)
    expect(await refused(g.fetch(`${SDK_RELAYER_URL}/withdraw`, { method: 'POST', body })), name).toMatch(/another authorization/)
    expect(sent, name).toEqual([]); expect(g.state.withdrawSent, name).toBe(false)
  }
  void sha
  const none = rig(undefined, () => new Response('not json', { status: 200 }))
  none.g.setLane(LANE_REQ)
  expect(await refused(none.g.fetch(`${SDK_RELAYER_URL}/withdraw`, { method: 'POST', body }))).toMatch(/another authorization/)
  const down = createGuardedFetch({ origin: ORIGIN, native: async () => { throw new Error('connection refused to 10.0.0.1') }, timeout: () => new AbortController().signal })
  down.setLane(LANE_REQ)
  const msg = await refused(down.fetch(`${SDK_RELAYER_URL}/withdraw`, { method: 'POST', body }))
  expect(msg).toMatch(/could not be reached/); expect(msg).not.toMatch(/10\.0\.0\.1/)
})

test('withdraw: the API refuses the mint (api.pc-lock 423 on mainnet): the guard id and message are kept for the page, nothing is sent, `sent` never fires', async () => {
  const { g, sent } = rig(undefined, () => new Response(JSON.stringify({ error: { guard: 'api.pc-lock', message: 'not minted on mainnet' } }), { status: 423 }))
  let events = 0
  g.events.sent = () => { events++ }
  g.setLane(LANE_REQ)
  expect(await refused(g.fetch(`${SDK_RELAYER_URL}/withdraw`, { method: 'POST', body: '{}' }))).toMatch(/refused the lane authorization/)
  expect(g.state.refusal).toEqual({ status: 423, guard: 'api.pc-lock', message: 'not minted on mainnet' })
  expect(sent).toEqual([]); expect(events).toBe(0); expect(g.state.withdrawSent).toBe(false)
  const html = rig(undefined, () => new Response('<html>', { status: 502 }))
  html.g.setLane(LANE_REQ)
  await refused(html.g.fetch(`${SDK_RELAYER_URL}/withdraw`, { method: 'POST', body: '{}' }))
  expect(html.g.state.refusal).toEqual({ status: 502, guard: 'api.http', message: 'HTTP 502' })
})

test('withdraw answers are recorded: the signature on success, the relay\'s guard and message on a refusal (not the SDK\'s "[object Object]")', async () => {
  const ok = rig(() => new Response(JSON.stringify({ signature: SIG }), { status: 200 }))
  ok.g.setLane(LANE_REQ)
  await ok.g.fetch(`${SDK_RELAYER_URL}/withdraw`, { method: 'POST', body: '{}' })
  expect(ok.g.state.signature).toBe(SIG)
  const no = rig(() => new Response(JSON.stringify({ error: { guard: 'release.mainnet-locked', message: 'locked' } }), { status: 423 }))
  no.g.setLane(LANE_REQ)
  await no.g.fetch(`${SDK_RELAYER_URL}/withdraw`, { method: 'POST', body: '{}' })
  expect(no.g.state.refusal).toEqual({ status: 423, guard: 'release.mainnet-locked', message: 'locked' })
  expect(no.g.state.signature).toBeNull()
  const junk = rig(() => new Response(JSON.stringify({ signature: 'not a signature!' }), { status: 200 }))
  junk.g.setLane(LANE_REQ)
  await junk.g.fetch(`${SDK_RELAYER_URL}/withdraw`, { method: 'POST', body: '{}' })
  expect(junk.g.state.signature).toBeNull()
  ok.g.reset(); expect(ok.g.state).toMatchObject({ withdrawSent: false, signature: null, refusal: null })
})

test('every request carries a timeout and the caller\'s abort signal', async () => {
  const seen = []
  const g = createGuardedFetch({ origin: ORIGIN, native: async (u, init) => { seen.push(init.signal); return new Response('{}') }, timeout: (ms) => { seen.push(ms); return new AbortController().signal } })
  const ac = new AbortController()
  await g.fetch(`${SDK_RELAYER_URL}/config`, { signal: ac.signal })
  expect(seen[0]).toBe(35_000)
  ac.abort()
  expect(seen[1].aborted).toBe(true)                                                          // the joined signal follows the caller's
})

test('installShims: Buffer, process.env with only the relayer URL, the guarded fetch, and the globals that could talk or store are gone', async () => {
  const g = { console: { log() { throw new Error('logged') }, warn() {}, error() {}, info() {}, debug() {} }, XMLHttpRequest: class {}, WebSocket: class {}, Worker: class {}, SharedWorker: class {},
    EventSource: class {}, ['indexed' + 'DB']: {}, caches: {}, BroadcastChannel: class {}, Other: 1 }
  const calls = []
  const guard = installShims(g, { origin: ORIGIN, native: async (...a) => { calls.push(a); return new Response('{}') } })
  expect(typeof g.Buffer).toBe('function')
  expect(g.process).toEqual({ env: { NEXT_PUBLIC_RELAYER_API_URL: SDK_RELAYER_URL }, versions: {}, browser: true })
  for (const k of ['XMLHttpRequest', 'WebSocket', 'Worker', 'SharedWorker', 'EventSource', 'indexed' + 'DB', 'caches', 'BroadcastChannel']) expect(g[k], k).toBeUndefined()
  expect(g.Other).toBe(1)
  expect(() => g.console.log('amount 123')).not.toThrow()                                      // console silenced
  expect(g.fetch).toBe(guard.fetch)
  expect(() => { 'use strict'; g.fetch = async () => new Response('x') }).toThrow(TypeError)      // m-5: not writable
  expect(() => Object.defineProperty(g, 'fetch', { value: () => {} })).toThrow(TypeError)        // nor configurable
  expect(() => { delete g.fetch }).toThrow(TypeError)
  expect(g.fetch).toBe(guard.fetch)
  await expect(g.fetch('https://example.org/x')).rejects.toThrow(/blocked/)
  expect(calls).toEqual([])
})

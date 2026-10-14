// M1a (spec B §6.5): createNet({ tick, permit? }) classes every request read / job / all and refuses a send its permit
// does not cover (net.send-permit), JSON-RPC batches element by element; a forged permit is refused at createNet; with
// a covering permit the request reaches the transport unchanged.
// C2 review: I-1, a 'job' permit (assertJobSendAllowed) covers ONLY the job sends, eth_sendRawTransaction and Solana
// sendTransaction to JSON-RPC endpoints; every other send class needs an 'all' permit (assertSendAllowed). I-2, the
// classifier fails closed: query-string sends (GET too), non-JSON / non-UTF-8 / UTF-16 bodies, GraphQL mutations and
// unknown POST shapes are sends. (send-lock-flip.test.ts repeats the scope checks with a mainnet job permit, on a copy
// of src/ with MAINNET_JOB_SENDS_ENABLED flipped.)
// Offline: a recording test transport answers everything (createNet's test seam); URLs are loopback literals (direct,
// no gate) unless a test shows that the refusal comes before the Tor gate. No socket is opened, nothing is signed.
import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { TOR_CHECK_URL, createNet } from '../../src/net/fetch.ts'
import { restoreGlobals } from '../../src/net/poison.ts'
import { GENESIS, assertJobSendAllowed, assertSendAllowed } from '../../src/config.ts'
import { Refusal } from '../../src/guard.ts'
import type { Init } from './send-lock-fixtures.ts'
import { ETH, NON_JOB_SENDS, READS, SENDS, SOL, RAW_TX, recorder, rpc, json } from './send-lock-fixtures.ts'

afterEach(restoreGlobals)

let seq = 0
const BASE_MS = Date.UTC(2026, 9, 9, 6, 0)
const fresh = (): string => `${new Date(BASE_MS + ++seq * 60_000).toISOString().slice(0, 16)}Z`

const isRefusal = (id: string) => (e: unknown) => e instanceof Refusal && e.guardId === id
const refused = (f: () => unknown, id: string, why = '') => assert.throws(f, isRefusal(id), `expected ${id} ${why}`)
const rejects = (p: Promise<unknown>, id: string, why = '') => assert.rejects(p, isRefusal(id), `expected ${id} ${why}`)
const dec = (b: Uint8Array | null) => (b === null ? '' : new TextDecoder().decode(b))

test('net.send-permit: every send-type request without a permit is refused before the transport, the log and the gate', async () => {
  const t = recorder()
  const net = createNet({ tick: fresh(), transport: t })
  for (const s of SENDS) await rejects(net.fetchFor('pub-j1-eth')(s.url, s.init), 'net.send-permit', s.why)
  // The same through jsonRpc.
  for (const [url, method] of [[ETH, 'eth_sendRawTransaction'], [ETH, 'eth_sendTransaction'], [SOL, 'sendTransaction'], [SOL, 'requestAirdrop'], ['http://127.0.0.1:65003/wallet/vt', 'sendrawtransaction'], ['http://127.0.0.1:65003/wallet/vt', 'sendtoaddress'], ['http://127.0.0.1:65003/wallet/vt', 'sendmany']]) {
    await rejects(net.jsonRpc('pub-j1-eth', url).request({ method, params: [] }), 'net.send-permit', method)
  }
  assert.equal(t.calls.length, 0, 'nothing reached the transport')
  assert.deepEqual(net.events(), [], 'nothing was logged')
  // Over Tor too: refused before the gate is even asked (the gate has not passed in this net).
  for (const url of ['https://mempool.space/api/tx', 'https://upload.services.ar-io.dev/v1/tx']) {
    await rejects(net.fetchFor('pub-j1-btc')(url, { method: 'POST', body: '00' }), 'net.send-permit', url)
  }
  await rejects(net.fetchFor('pub-j1-eth')('https://api.etherscan.example/v2/api?chainid=1&module=proxy&action=eth_sendRawTransaction&hex=0x02'), 'net.send-permit', 'Etherscan-style GET over Tor')
  await rejects(net.jsonRpc('pub-j1-eth', 'https://ethereum-sepolia-rpc.publicnode.com').request({ method: 'eth_sendRawTransaction', params: [RAW_TX] }), 'net.send-permit')
  assert.equal(t.calls.length, 0)
})

test('reads pass without a permit (JSON-RPC reads, read batches, GET and HEAD, GraphQL queries)', async () => {
  const t = recorder()
  const net = createNet({ tick: fresh(), transport: t })
  assert.equal(await net.jsonRpc('pub-j1-eth', ETH).request({ method: 'eth_chainId' }), '0x1')
  assert.equal(await net.jsonRpc('pub-j1-eth', SOL).request({ method: 'getGenesisHash' }), '0x1')
  assert.equal(await net.jsonRpc('pub-j1-eth', SOL).request({ method: 'simulateTransaction', params: ['AQID'] }), '0x1')
  assert.equal(await net.jsonRpc('pub-j1-eth', 'http://127.0.0.1:65003/').request({ method: 'getblockhash', params: [0] }), '0x1')
  const f = net.fetchFor('pub-j1-eth')
  for (const r of READS) assert.equal((await f(r.url, r.init)).status, 200, r.why)
  assert.equal(t.calls.length, 4 + READS.length)
})

// N-2: the only GET/HEAD broadcast makes today is the Tor check (src/net/gate.ts torGate, from `tor-check` in
// src/cli.ts: GET https://check.torproject.org/api/ip, role check, gate-exempt). It must stay a read with no permit.
test('the reads broadcast makes today (the Tor check GET) stay reads with no permit', async () => {
  assert.equal(TOR_CHECK_URL, 'https://check.torproject.org/api/ip', 'the read list below matches src/net/gate.ts')
  const t = recorder()
  const net = createNet({ tick: fresh(), transport: t })
  assert.equal((await net.fetchFor('check')(TOR_CHECK_URL)).status, 200)
  assert.deepEqual(t.calls.map((c) => [c.method, c.url]), [['GET', TOR_CHECK_URL]])
})

test('net.send-permit: a forged permit is refused at createNet', () => {
  const real = assertSendAllowed('testnet')
  const forged: unknown[] = [
    { profile: 'testnet', scope: 'all' }, Object.freeze({ profile: 'testnet', scope: 'all' }), { ...real }, Object.create(real),
    structuredClone(real), { __permit: Symbol('permit'), profile: 'testnet', scope: 'all' }, null, true, 'permit', 1,
  ]
  for (const permit of forged) refused(() => createNet({ tick: fresh(), transport: recorder(), permit: permit as never }), 'net.send-permit', String(permit))
})

test('an \'all\' permit (assertSendAllowed, testnet or local) lets every send class through to the transport unchanged', async () => {
  for (const permit of [assertSendAllowed('testnet'), assertSendAllowed('local'), assertSendAllowed('local', { chain: 'eth', id: '0x7a69' })]) {
    const t = recorder()
    const net = createNet({ tick: fresh(), transport: t, permit })
    for (const s of SENDS) assert.equal((await net.fetchFor('pub-j1-eth')(s.url, s.init)).status, 200, s.why)
    assert.equal(await net.jsonRpc('pub-j1-eth', ETH).request({ method: 'eth_sendRawTransaction', params: [RAW_TX] }), '0x1')
    assert.equal(await net.jsonRpc('pub-j1-eth', SOL).request({ method: 'requestAirdrop', params: ['x', 1] }), '0x1')
    assert.equal(t.calls.length, SENDS.length + 2)
    const last = JSON.parse(dec(t.calls[t.calls.length - 2].body)) as { method: string; params: unknown[] }
    assert.deepEqual([last.method, last.params], ['eth_sendRawTransaction', [RAW_TX]], 'the body is passed through as built')
    for (const [i, s] of SENDS.entries()) {
      const want = typeof s.init.body === 'string' ? new TextEncoder().encode(s.init.body) : s.init.body ?? null
      assert.deepEqual(t.calls[i].body === null ? null : [...t.calls[i].body!], want === null ? null : [...want], `${s.why}: bytes unchanged`)
    }
  }
})

test('I-1: a \'job\' permit (assertJobSendAllowed) covers the ETH and SOL job sends only; every other send class is refused', async () => {
  const jobs = SENDS.filter((s) => s.cls === 'job')
  assert.ok(jobs.length >= 6 && NON_JOB_SENDS.length >= 20)
  for (const permit of [assertJobSendAllowed('testnet'), assertJobSendAllowed('local'), assertJobSendAllowed('testnet', { chain: 'eth', id: '0xaa36a7' })]) {
    const t = recorder()
    const net = createNet({ tick: fresh(), transport: t, permit })
    for (const s of NON_JOB_SENDS) await rejects(net.fetchFor('pub-j1-eth')(s.url, s.init), 'net.send-permit', `job permit, ${s.why}`)
    await rejects(net.jsonRpc('pub-j1-eth', SOL).request({ method: 'requestAirdrop', params: ['x', 1] }), 'net.send-permit')
    await rejects(net.jsonRpc('pub-j1-eth', 'http://127.0.0.1:65003/wallet/vt').request({ method: 'sendtoaddress', params: [] }), 'net.send-permit')
    assert.equal(t.calls.length, 0, 'no non-job send reached the transport')
    for (const s of jobs) assert.equal((await net.fetchFor('pub-j1-eth')(s.url, s.init)).status, 200, `job permit, ${s.why}`)
    assert.equal(await net.jsonRpc('pub-j1-eth', ETH).request({ method: 'eth_sendRawTransaction', params: [RAW_TX] }), '0x1')
    assert.equal(await net.jsonRpc('pub-j1-eth', SOL).request({ method: 'sendTransaction', params: ['AQID'] }), '0x1')
    assert.equal(t.calls.length, jobs.length + 2)
    for (const r of READS) assert.equal((await net.fetchFor('pub-j1-eth')(r.url, r.init)).status, 200, `job permit, read ${r.why}`)
  }
})

test('a batch is inspected element by element: one send refuses it, the same batch without the send passes', async () => {
  const t = recorder()
  const net = createNet({ tick: fresh(), transport: t })
  const f = net.fetchFor('pub-j1-sol')
  const reads = [rpc('getGenesisHash'), rpc('getSlot'), rpc('getBalance', ['x'])]
  for (let i = 0; i <= reads.length; i++) {
    const withSend = [...reads.slice(0, i), rpc('sendTransaction', ['AQID']), ...reads.slice(i)]
    await rejects(f(SOL, json(withSend)), 'net.send-permit', `send at ${i}`)
  }
  assert.equal(t.calls.length, 0)
  assert.equal((await f(SOL, json(reads))).status, 200)
  assert.equal(t.calls.length, 1)
  // With a job permit, one non-job send in a batch of job sends refuses the whole batch.
  const job = createNet({ tick: fresh(), transport: t, permit: assertJobSendAllowed('testnet') })
  await rejects(job.fetchFor('pub-j1-eth')(ETH, json([rpc('eth_sendRawTransaction', [RAW_TX]), rpc('eth_sendTransaction', [{}])])), 'net.send-permit')
  assert.equal(t.calls.length, 1)
})

// C2 m6: ALL scope (never touched by the M2 flip) and JOB scope (edited by it) are separate tests.
test('ALL scope: no mainnet permit of the all scope exists in this build, so no net can be given one', () => {
  refused(() => assertSendAllowed('mainnet'), 'release.mainnet-locked')
  refused(() => assertSendAllowed('testnet', { chain: 'eth', id: '0x1' }), 'release.mainnet-locked')
})

// M2 FLIP (applied, operator R78): edited by the flip commit.
test('JOB scope (M2 FLIP): a mainnet job permit exists in this build; a net given one passes only the ETH/SOL job sends (every other send class stays refused)', async () => {
  const permits = [
    assertJobSendAllowed('mainnet'), assertJobSendAllowed('mainnet', { chain: 'eth', id: '0x1' }),
    assertJobSendAllowed('mainnet', { chain: 'sol', id: GENESIS.sol.mainnet }),
  ]
  const jobs = SENDS.filter((s) => s.cls === 'job')
  for (const permit of permits) {
    assert.deepEqual([permit.profile, permit.scope], ['mainnet', 'job'])
    const t = recorder()
    const net = createNet({ tick: fresh(), transport: t, permit })
    for (const s of NON_JOB_SENDS) await rejects(net.fetchFor('pub-j1-eth')(s.url, s.init), 'net.send-permit', `mainnet job permit, ${s.why}`)
    await rejects(net.jsonRpc('pub-j1-eth', SOL).request({ method: 'requestAirdrop', params: ['x', 1] }), 'net.send-permit')
    await rejects(net.jsonRpc('pub-j1-eth', 'http://127.0.0.1:65003/wallet/vt').request({ method: 'sendtoaddress', params: [] }), 'net.send-permit')
    assert.equal(t.calls.length, 0, 'no non-job send reached the transport')
    for (const s of jobs) assert.equal((await net.fetchFor('pub-j1-eth')(s.url, s.init)).status, 200, `mainnet job permit, ${s.why}`)
    assert.equal(t.calls.length, jobs.length)
  }
  // Mainnet BTC and a foreign identity still get no job permit; the all-scope lock is the ALL-scope test above.
  refused(() => assertJobSendAllowed('mainnet', { chain: 'btc', id: GENESIS.btc.mainnet }), 'release.mainnet-locked')
  refused(() => assertJobSendAllowed('mainnet', { chain: 'eth', id: '0xaa36a7' }), 'config.identity-mismatch')
  refused(() => assertJobSendAllowed('testnet', { chain: 'eth', id: '0x1' }), 'release.mainnet-locked')
})

// C2 m2: a LOCAL permit is bound to the local destination class. Send-type requests go to loopback targets only; a
// public-https, onion or any other non-loopback target is refused before the gate, the log and the transport.
test('m2: a local permit (either scope) refuses send-type requests to non-loopback targets; reads and loopback sends pass', async () => {
  const farSends: Array<[string, string, 'job' | 'all', Init]> = [
    ['public https job send', 'https://ethereum-sepolia-rpc.publicnode.com', 'job', json(rpc('eth_sendRawTransaction', [RAW_TX]))],
    ['public https Solana job send', 'https://api.devnet.solana.com', 'job', json(rpc('sendTransaction', ['AQID']))],
    ['public https Esplora POST /tx', 'https://mempool.space/testnet4/api/tx', 'all', { method: 'POST', body: '00' }],
    ['public https Turbo POST', 'https://upload.services.ar-io.dev/v1/tx', 'all', { method: 'POST', body: '00' }],
    ['onion Esplora POST', 'http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/testnet4/api/tx', 'all', { method: 'POST', body: '00' }],
    ['public https query send', 'https://api.etherscan.example/v2/api?module=proxy&action=eth_sendRawTransaction&hex=0x02', 'all', { method: 'GET' }],
  ]
  for (const permit of [assertSendAllowed('local'), assertJobSendAllowed('local'), assertSendAllowed('local', { chain: 'eth', id: '0x7a69' })]) {
    const t = recorder()
    const net = createNet({ tick: fresh(), transport: t, permit })
    for (const [why, url, cls, init] of farSends) {
      if (permit.scope === 'job' && cls === 'all') continue // refused by scope already; the destination rule is shown by the 'all' permit
      await rejects(net.fetchFor('pub-j1-eth')(url, init), 'net.send-permit', `${permit.scope}: ${why}`)
    }
    await rejects(net.jsonRpc('pub-j1-eth', 'https://ethereum-sepolia-rpc.publicnode.com').request({ method: 'eth_sendRawTransaction', params: [RAW_TX] }), 'net.send-permit', 'jsonRpc')
    assert.equal(t.calls.length, 0, 'nothing reached the transport')
    assert.deepEqual(net.events(), [], 'nothing was logged')
    // loopback sends still pass (the loopback arm is the local class)
    assert.equal(await net.jsonRpc('pub-j1-eth', ETH).request({ method: 'eth_sendRawTransaction', params: [RAW_TX] }), '0x1')
    assert.equal(t.calls.length, 1)
  }
})

test('m2: the destination rule belongs to the permit\'s profile: a testnet permit is not tied to loopback', async () => {
  // Reaching a public target needs the Tor gate, which is closed in this offline net: the request is refused by the gate
  // (net.gate-*), never by net.send-permit. Contrast with the local permit above.
  const net = createNet({ tick: fresh(), transport: recorder(), permit: assertSendAllowed('testnet') })
  await assert.rejects(
    net.fetchFor('pub-j1-eth')('https://mempool.space/testnet4/api/tx', { method: 'POST', body: '00' }),
    (e: unknown) => e instanceof Refusal && e.guardId !== 'net.send-permit',
  )
})

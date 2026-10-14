// httpJournalClient and httpRelayClient (E3): the HTTP shapes of spec §5.2 / §6.1 for both executors — the page's relative
// /api and /relay paths without a token, the CLI's loopback ports with the bearer token — refusals carried as their
// guard ids, no reply = JournalUnreachable, a message checked against its digest. ALL DATA IS SYNTHETIC; the "network" is
// test/fakes/fake-relay.ts stackFetch (nothing listens).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { httpJournalClient, JournalUnreachable } from '../../src/executor/journal-client.ts'
import { httpRelayClient } from '../../src/executor/relay-client.ts'
import { RpcError, TransportError } from '../../src/engine/rpc.js'
import { browserClients } from '../../src/executor/adapters/browser.ts'
import { nodeClients } from '../../src/executor/adapters/node.ts'
import { stackFetch } from '../fakes/fake-relay.ts'
import { stack } from './helpers.ts'

const TOKEN = 'ab'.repeat(32)
async function guardAsync(p: Promise<unknown>): Promise<string | null> {
  try { await p } catch (e) { const g = (e as { guardId?: unknown }).guardId; if (typeof g === 'string') return g; throw e }
  return null
}

test('the page (relative /api, no token) and the CLI (loopback API port + bearer token) reach the same API; refusals keep their guard id', async () => {
  const s = stack('eth', { copies: 1, startIn: 60_000 })
  const net = stackFetch({ network: 'local', journal: s.j.client, relay: s.relay.client, token: TOKEN })
  const page = browserClients({ fetch: net.fetch }), cli = nodeClients({ network: 'local', token: TOKEN, fetch: net.fetch })
  for (const c of [page, cli]) {
    assert.equal((await c.journal.status()).network, 'local')
    const j = await c.journal.job(s.j.id)
    assert.equal(j.def.messageSha256, s.def.messageSha256); assert.equal(j.state.chains.eth!.phase, 'ARMED')
    assert.equal(await c.journal.message(s.def.messageSha256), s.text)
    assert.equal(await guardAsync(c.journal.lease(s.j.id, 'eth', 'renew', 'cli', 7)), 'lease.lost')
  }
  assert.ok(net.seen.some((u) => u === 'http://127.0.0.1:5180/api/status'), 'the page used its own origin'); assert.ok(net.seen.includes('http://127.0.0.1:5182/status'), 'the CLI used the API port')
  const noToken = httpJournalClient({ base: 'http://127.0.0.1:5182', fetch: net.fetch })
  assert.equal(await guardAsync(noToken.status()), 'api.token')
  assert.throws(() => httpJournalClient({ base: '', fetch: net.fetch, token: 'short' }), /64 hex/)
  await assert.rejects(page.journal.job('../../etc'), TypeError)
  await assert.rejects(page.journal.message('A'.repeat(64)), TypeError)
})

test('a lease, an intent with its ticket, a fresh ticket, events: the request bodies are the contract\'s; clawbackConfirm only beside a clawback-intent', async () => {
  const s = stack('eth', { copies: 1, startIn: 0 })
  const bodies: unknown[] = []
  const net = stackFetch({ network: 'local', journal: s.j.client, relay: s.relay.client, token: TOKEN })
  const f = async (url: string, init?: RequestInit) => { if (init?.body) bodies.push(JSON.parse(String(init.body))); return net.fetch(url, init) }
  const c = httpJournalClient({ base: 'http://127.0.0.1:5182', fetch: f, token: TOKEN })
  const g = await c.lease(s.j.id, 'eth', 'acquire', 'cli')
  assert.deepEqual(bodies.at(-1), { op: 'acquire', holder: 'cli' })
  await c.append(s.j.id, 'eth', g.gen, 'note', { text: 'hello' }, { clawbackConfirm: { amount: '1' } })
  assert.deepEqual(bodies.at(-1), { gen: g.gen, type: 'note', data: { text: 'hello' } }, 'no clawbackConfirm on another type')
  assert.equal(await guardAsync(c.append(s.j.id, 'eth', g.gen + 5, 'note', { text: 'x' })), 'lease.stale')
  assert.equal(await guardAsync(c.ticket(s.j.id, 'eth', g.gen, `0x${'1'.repeat(64)}`)), 'ticket.not-intent')
  const r = await c.lease(s.j.id, 'eth', 'release', 'cli', g.gen)
  assert.equal(r.ttlMs, 0)
  const raw = httpJournalClient({ base: '', fetch: async (_u, init) => { bodies.push(JSON.parse(String(init!.body))); return new Response('{}', { status: 200 }) } })
  await raw.append('0123456789abcdef', 'eth', 3, 'clawback-intent', { txId: 'x' }, { clawbackConfirm: { amount: '42' } })
  assert.deepEqual(bodies.at(-1), { gen: 3, type: 'clawback-intent', data: { txId: 'x' }, clawbackConfirm: { amount: '42' } })
})

test('no definitive answer is JournalUnreachable (a network failure, a 5xx without a refusal, a body that is not JSON); a ticket answer without a ticket too', async () => {
  const id = '0123456789abcdef'
  const down = httpJournalClient({ base: '', fetch: async () => { throw new TypeError('fetch failed') } })
  await assert.rejects(down.status(), JournalUnreachable)
  const proxy = httpJournalClient({ base: '', fetch: async () => new Response('bad gateway', { status: 502 }) })
  await assert.rejects(proxy.job(id), JournalUnreachable)
  const garbled = httpJournalClient({ base: '', fetch: async () => new Response('{"seq":', { status: 200 }) })
  await assert.rejects(garbled.append(id, 'eth', 1, 'note', { text: 'x' }), JournalUnreachable)
  const noTicket = httpJournalClient({ base: '', fetch: async () => new Response('{}', { status: 200 }) })
  await assert.rejects(noTicket.ticket(id, 'eth', 1, 'x'), JournalUnreachable)
  const refused = httpJournalClient({ base: '', fetch: async () => new Response(JSON.stringify({ error: { guard: 'journal.write', message: 'nothing was acked' } }), { status: 503 }) })
  assert.equal(await guardAsync(refused.append(id, 'eth', 1, 'note', { text: 'x' })), 'journal.write', 'a refusal is definitive, not unreachable')
  const odd = httpJournalClient({ base: '', fetch: async () => new Response(JSON.stringify({ error: { guard: 'NOT A GUARD', message: 'x' } }), { status: 409 }) })
  await assert.rejects(odd.status(), JournalUnreachable)
})

test('a message is checked against its digest (message.digest) and decoded strictly', async () => {
  const sha = 'a'.repeat(64)
  const c = httpJournalClient({ base: '', fetch: async () => new Response('not that text', { status: 200 }) })
  assert.equal(await guardAsync(c.message(sha)), 'message.digest')
  const { sha256Hex } = await import('../../src/job/canonical.ts')
  const bad = new Uint8Array([0x61, 0xff, 0x62])
  const d = httpJournalClient({ base: '', fetch: async () => new Response(bad, { status: 200 }) })
  await assert.rejects(d.message(sha256Hex(bad)), TypeError, 'invalid UTF-8 is refused, never replaced')
})

test('the relay client: status (a RelayStatus or nothing), JSON-RPC with the engine\'s failure classes, tor, price', async () => {
  const s = stack('eth', { copies: 1 })
  const net = stackFetch({ network: 'local', journal: s.j.client, relay: s.relay.client, token: TOKEN })
  for (const r of [httpRelayClient({ base: '', fetch: net.fetch }), httpRelayClient({ base: 'http://127.0.0.1:5181', fetch: net.fetch })]) {
    assert.equal((await r.status()).network, 'local')
    assert.equal(await r.rpc('eth', 'eth_chainId', []), '0x7a69')
    await assert.rejects(r.rpc('eth', 'eth_nope', []), RpcError)
    assert.deepEqual(await r.tor(), { isTor: null })           // a relay that sends no torRoles (an older one)
    assert.equal((await r.price()).fixture, true)
  }
  const dead = httpRelayClient({ base: '', fetch: async () => { throw new TypeError('fetch failed') } })
  await assert.rejects(dead.status(), TransportError); await assert.rejects(dead.rpc('sol', 'getSlot', []), TransportError)
  const notStatus = httpRelayClient({ base: '', fetch: async () => new Response(JSON.stringify({ network: 'devnet' }), { status: 200 }) })
  await assert.rejects(notStatus.status(), TransportError)
})

test('the relay client: tor passes torRoles through only as a list of strings (M4a glue, S6 F1)', async () => {
  const via = (body: unknown) => httpRelayClient({ base: '', fetch: async () => new Response(JSON.stringify(body), { status: 200 }) }).tor()
  assert.deepEqual(await via({ isTor: null, torRoles: ['check', 'drand'] }), { isTor: null, torRoles: ['check', 'drand'] })
  assert.deepEqual(await via({ isTor: true, torRoles: [] }), { isTor: true, torRoles: [] })
  assert.deepEqual(await via({ isTor: false, torRoles: 'drand' }), { isTor: false })
  assert.deepEqual(await via({ isTor: true, torRoles: ['drand', 7] }), { isTor: true })
  assert.deepEqual(await via({ isTor: 'yes' }), { isTor: null })
})

test('E7 round 3: the journal client carries chain btc — lease, an intent with its btc member and ticket, a fresh ticket, events — to the API and back', { timeout: 30_000 }, async () => {
  const { btcFromSecret } = await import('../../src/chains/btc.js')
  const { jobFor, newKey, T0 } = await import('./helpers.ts')
  const { fakeJournal, virtualClock } = await import('../fakes/fake-journal.ts')
  const k = btcFromSecret('66'.repeat(32), 'local')
  const base = jobFor('eth', newKey('eth'), { copies: 1 })
  const def = { ...base.def, chains: { btc: { ...(base.def.chains.eth as object), keyAddress: k.address, publishMode: 'btc.inscription', feeStrategy: 'economy' } } } as unknown as typeof base.def
  const clock = virtualClock(T0)
  const j = fakeJournal({ def, text: base.text, clock })
  void j.client.lease(j.id, 'btc', 'acquire', 'browser')
  j.asHolder(1, 'browser', 'btc', 'key-loaded', { address: k.address })
  void j.client.lease(j.id, 'btc', 'release', 'browser', 1)
  j.arm(['btc'], { caps: { btc: '1000000' }, releaseAt: j.serverNow() - 1 })
  const { relay } = stack('eth', { copies: 1 })
  const net = stackFetch({ network: 'local', journal: j.client, relay: relay.client, token: TOKEN })
  const c = nodeClients({ network: 'local', token: TOKEN, fetch: net.fetch })
  const grant = await c.journal.lease(j.id, 'btc', 'acquire', 'cli')
  assert.equal(grant.holder, 'cli')
  const data = { txId: 'ab'.repeat(32), copy: 1, part: 1, parts: 2, attempt: 1, replaces: null, rawSha256: 'cd'.repeat(32), payloadSha256: 'ef'.repeat(32), reserved: '1132',
    btc: { kind: 'commit', pubkey: k.pubkey, fee: '300', value: '832', inputs: [`${'11'.repeat(32)}:0`] } }
  const r = await c.journal.append(j.id, 'btc', grant.gen, 'intent', data)
  assert.match(r.ticket ?? '', /^vt-ticket\/2\./)
  assert.match(await c.journal.ticket(j.id, 'btc', grant.gen, data.txId), /^vt-ticket\/2\./)
  assert.equal((await c.journal.job(j.id)).state.chains.btc!.openIntents[0], data.txId)
  await assert.rejects(async () => c.journal.append(j.id, 'doge' as never, grant.gen, 'note', { text: 'x' }), TypeError)
})

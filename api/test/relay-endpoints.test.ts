// Sfix1: the relay takes ticketed SOL sends on /relay/sol/ep/<i>. The E5 engine sends the same signed SOL bytes with the
// same ticket to every verified SOL endpoint; the relay gates them with exactly the gate of /relay/sol (one checkSend:
// method table, ticket v2, w, c, r, the job-send lock, decode verification) and one more rule: a ticket goes to each
// verified endpoint at most once while it is valid (relay.ticket-endpoint-reused). /relay/sol keeps §5.6's stateless
// reuse (the 2-s rebroadcast). <i> names an endpoint that passed identity at startup (relay.endpoint-unverified), and
// ETH per-endpoint routes stay read-only (relay.endpoint-read-only).
// Covers the gate (checkSend with a route; the endpoint ledger), the relay in process over HTTP with a fake transport,
// and an integration-style run: the real local transport and two fake SOL upstreams on loopback, which receive
// byte-identical bodies. Synthetic keys and data only; nothing leaves the machine.
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer, request } from 'node:http'
import type { Server } from 'node:http'
import { fileURLToPath } from 'node:url'
import { PORTS } from '@vault-timelock/core/contracts'
import type { Network, TicketPayload } from '@vault-timelock/core/contracts'
import { GENESIS } from 'vt-broadcast/src/config.ts'
import { createRelay, relayUpstreams, socksTransport } from '../relay/relay.mjs'
import { EP_SEND_CHAINS, READ_METHODS, checkSend, createEndpointLedger } from '../src/relay-gate.ts'
import type { EndpointLedger, SendCheck } from '../src/relay-gate.ts'
import { encodeTicket } from '../src/tickets.ts'
import type { TicketBinding } from '../src/tickets.ts'
import { genuineEth, genuineSol, txIdOf } from './genuine.ts'
import type { Genuine } from './genuine.ts'
import { CANARY, TICKET_KEY, fixture } from './helpers.ts'

const NOW = 1_791_504_000_000
const LOCAL_GENESIS = '8pUq7jxkLxNpHg6M9KxzRtNEC4pNEHsr4kDTLSE5uVRW'
const OBSERVED: Record<Network, Record<'eth' | 'sol', string>> = {
  local: { eth: '0x7a69', sol: LOCAL_GENESIS }, testnet: { eth: '0xaa36a7', sol: GENESIS.sol.devnet }, mainnet: { eth: '0x1', sol: GENESIS.sol.mainnet },
}
const ENDPOINTS = JSON.parse(readFileSync(fileURLToPath(import.meta.resolve('vt-broadcast/endpoints.json')), 'utf8')) as Record<Network, Record<string, string[]>>
const TOR_CHECK = 'https://check.torproject.org/api/ip'
// Synthetic upstream names for the fake transport (never resolved: the transport is injected).
const SOL_A = 'https://sol-a.example', SOL_B = 'https://sol-b.example', SOL_C = 'https://sol-c.example'
const ETH_A = 'https://eth-a.example', ETH_B = 'https://eth-b.example'

const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex')
const methodOf = (chain: 'eth' | 'sol'): string => (chain === 'eth' ? 'eth_sendRawTransaction' : 'sendTransaction')
const paramsOf = (chain: 'eth' | 'sol', raw: Uint8Array, cfg: Record<string, unknown> = { encoding: 'base64' }): unknown[] =>
  (chain === 'eth' ? [`0x${Buffer.from(raw).toString('hex')}`] : [Buffer.from(raw).toString('base64'), cfg])

// The ticket the API gives a genuine tx: t its id, the binding as given (genuine by default), n and e as given.
function ticketOf(network: Network, chain: 'eth' | 'sol', g: Genuine, o: { binding?: TicketBinding; n?: string; e?: number; raw?: Uint8Array } = {}): { ticket: string; payload: TicketPayload } {
  const payload: TicketPayload = { j: 'e3d45f73cf65abaa', w: network, c: chain, g: 1, t: txIdOf(chain, g.raw), r: sha(o.raw ?? g.raw), ...(o.binding ?? g.binding),
    e: o.e ?? NOW + 120_000, n: o.n ?? '0123456789abcdef' }
  return { ticket: encodeTicket(TICKET_KEY, payload), payload }
}
let nonce = 0
const freshN = (): string => (++nonce).toString(16).padStart(16, '0')

// ---------- the gate: checkSend with a route ----------

function sendCheck(network: Network, chain: 'eth' | 'sol', raw: Uint8Array, ticket: string | undefined, over: Partial<SendCheck> = {}): SendCheck {
  return { network, chain, method: methodOf(chain), params: paramsOf(chain, raw), ticketHeader: ticket, key: TICKET_KEY, now: NOW, observedId: OBSERVED[network][chain], ...over }
}
async function guard(o: SendCheck): Promise<string> {
  try { await checkSend(o) } catch (e) {
    const g = (e as { guardId?: unknown }).guardId
    assert.equal(typeof g, 'string', `not a refusal: ${String(e)}`)
    return g as string
  }
  return 'passed'
}
const ep = (i: number, ledger: EndpointLedger = createEndpointLedger(), verified = 2): SendCheck['route'] => ({ ep: i, verified, ledger })

interface Raw { encoding: 'hex' | 'base64'; value: string }
interface Vector { name?: string; ticket: string; now: number; context: { network: Network; chain: 'eth' | 'sol'; raw: Raw } }
const V = fixture<{ valid: Vector[]; negatives: Vector[]; decode: Vector[] }>('tickets.json')

test('one gate: every send gets on /relay/sol/ep/<i> exactly its /relay/sol outcome (contract vectors and each check of the gate); ETH there: relay.endpoint-read-only', async () => {
  const cases: Array<[string, SendCheck]> = []
  for (const v of [...V.valid, ...V.negatives, ...V.decode]) {
    const c = v.context
    const params = c.raw.encoding === 'hex' ? [c.raw.value] : [c.raw.value, { encoding: 'base64' }]
    cases.push([`${v.name ?? 'valid'} (${c.network} ${c.chain})`, { network: c.network, chain: c.chain, method: methodOf(c.chain), params, ticketHeader: v.ticket, key: TICKET_KEY, now: v.now, observedId: OBSERVED[c.network][c.chain] }])
  }
  const gs = genuineSol(), other = genuineSol(), ok = ticketOf('testnet', 'sol', gs)
  const base = sendCheck('testnet', 'sol', gs.raw, ok.ticket)
  cases.push(
    ['genuine', base],
    ['no ticket', { ...base, ticketHeader: undefined }],
    ['garbage ticket', { ...base, ticketHeader: `vt-ticket/2.${CANARY}` }],
    ['expired', { ...base, now: ok.payload.e }],
    ['a local ticket at the testnet relay', { ...base, ticketHeader: ticketOf('local', 'sol', gs).ticket }],
    ['other bytes', { ...base, params: paramsOf('sol', other.raw) }],
    ['non-canonical params', { ...base, params: [gs.b64, { encoding: 'base58' }] }],
    ['mainnet', sendCheck('mainnet', 'sol', gs.raw, ticketOf('mainnet', 'sol', gs).ticket)],
    ['a mainnet identity behind the testnet relay', { ...base, observedId: GENESIS.sol.mainnet }],
    ['a foreign identity', { ...base, observedId: LOCAL_GENESIS }],
    ['a fee above f', { ...base, ticketHeader: ticketOf('testnet', 'sol', gs, { binding: { ...gs.binding, f: '4999' } }).ticket }],
    ['another payload', { ...base, ticketHeader: ticketOf('testnet', 'sol', gs, { binding: { ...gs.binding, p: 'ab'.repeat(32) } }).ticket }],
    ['not the job send', { ...base, method: 'sendBundle' }],
  )
  const seen = new Set<string>()
  for (const [name, check] of cases) {
    const preferred = await guard(check)
    const onEp = await guard({ ...check, route: ep(1) })
    if (check.chain === 'sol') { assert.equal(onEp, preferred, name); seen.add(onEp) } else assert.equal(onEp, 'relay.endpoint-read-only', name)
  }
  assert.deepEqual([...seen].sort(), ['config.identity-mismatch', 'passed', 'relay.decode-mismatch', 'relay.method', 'relay.send-ticket', 'relay.ticket-chain',
    'relay.ticket-expired', 'relay.ticket-network', 'relay.ticket-raw', 'release.mainnet-locked'])
})

test('the endpoint index names exactly a verified endpoint, for reads and sends on both chains → relay.endpoint-unverified otherwise', async () => {
  const gs = genuineSol(), { ticket } = ticketOf('testnet', 'sol', gs)
  for (const i of [2, 3, 9, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.equal(await guard(sendCheck('testnet', 'sol', gs.raw, ticket, { route: ep(i) })), 'relay.endpoint-unverified', `send ep ${i}`)
    for (const chain of ['eth', 'sol'] as const) {
      const read: SendCheck = { network: 'testnet', chain, method: READ_METHODS.testnet[chain][0], params: [], ticketHeader: undefined, key: TICKET_KEY, now: NOW, observedId: OBSERVED.testnet[chain], route: ep(i) }
      assert.equal(await guard(read), 'relay.endpoint-unverified', `${chain} read ep ${i}`)
    }
  }
  assert.equal(await guard(sendCheck('testnet', 'sol', gs.raw, ticket, { route: ep(0, createEndpointLedger(), 0) })), 'relay.endpoint-unverified')   // no verified endpoint at all
  const ledger = createEndpointLedger()
  for (const i of [0, 1]) {
    assert.equal(await guard(sendCheck('testnet', 'sol', gs.raw, ticket, { route: ep(i, ledger) })), 'passed', `send ep ${i}`)
    for (const chain of ['eth', 'sol'] as const) {
      for (const method of READ_METHODS.testnet[chain]) {
        assert.equal(await guard({ network: 'testnet', chain, method, params: [], ticketHeader: undefined, key: TICKET_KEY, now: NOW, observedId: OBSERVED.testnet[chain], route: ep(i) }), 'passed', `${chain} ${method} ep ${i}`)
      }
    }
  }
  // a method outside the table is still relay.method first (default deny), on a good index and a bad one alike
  for (const i of [0, 7]) assert.equal(await guard({ ...sendCheck('testnet', 'sol', gs.raw, ticket, { route: ep(i) }), method: 'sendBundle' }), 'relay.method')
})

// M2 FLIP (applied, operator R78): the chain route now takes the mainnet send too (the job-send lock is lifted), behind mainnet's own identity only.
test('ETH per-endpoint routes stay read-only: a genuine ETH send with a valid ticket → relay.endpoint-read-only on every network; the chain route takes it (mainnet too, since the M2 flip)', async () => {
  assert.deepEqual(EP_SEND_CHAINS, ['sol'])
  assert.ok(Object.isFrozen(EP_SEND_CHAINS))
  for (const n of ['local', 'testnet', 'mainnet'] as const) {
    const ge = await genuineEth(n), { ticket } = ticketOf(n, 'eth', ge)
    for (const i of [0, 1]) {
      assert.equal(await guard(sendCheck(n, 'eth', ge.raw, ticket, { route: ep(i) })), 'relay.endpoint-read-only', `${n} ep ${i}`)
      assert.equal(await guard(sendCheck(n, 'eth', ge.raw, undefined, { route: ep(i) })), 'relay.endpoint-read-only', `${n} ep ${i} (no ticket)`)
    }
    assert.equal(await guard(sendCheck(n, 'eth', ge.raw, ticket)), 'passed', n)
    if (n === 'mainnet') {
      for (const id of ['0xaa36a7', '0x7a69', '0xa4b1', '']) assert.equal(await guard(sendCheck(n, 'eth', ge.raw, ticket, { observedId: id })), 'config.identity-mismatch', `mainnet behind ${id}`)
    }
  }
})

test('the endpoint ledger: a ticket once per verified endpoint; other bytes refused; a refused send spends nothing; the chain route unbudgeted; a new ticket, a new budget', async () => {
  const gs = genuineSol(), other = genuineSol()
  const t1 = ticketOf('testnet', 'sol', gs, { n: freshN() })
  const ledger = createEndpointLedger()
  const on = (i: number, raw: Uint8Array = gs.raw, ticket = t1.ticket, now = NOW): Promise<string> => guard(sendCheck('testnet', 'sol', raw, ticket, { route: ep(i, ledger, 3), now }))
  assert.equal(await on(0), 'passed')
  assert.equal(await on(0), 'relay.ticket-endpoint-reused')
  assert.equal(await on(1), 'passed')
  assert.equal(await on(1), 'relay.ticket-endpoint-reused')
  assert.equal(await on(0), 'relay.ticket-endpoint-reused')
  for (let k = 0; k < 5; k++) assert.equal(await guard(sendCheck('testnet', 'sol', gs.raw, t1.ticket)), 'passed', `chain route rebroadcast ${k}`)
  // other bytes under the ticket → relay.ticket-raw (on a spent endpoint and on a fresh one), and that spends nothing
  assert.equal(await on(0, other.raw), 'relay.ticket-raw')
  assert.equal(await on(2, other.raw), 'relay.ticket-raw')
  assert.equal(await on(2), 'passed')
  assert.equal(await on(2), 'relay.ticket-endpoint-reused')
  assert.equal(ledger.size, 1)
  // a refused send never spends: a decode mismatch, the lock, an expired ticket
  const lie = ticketOf('testnet', 'sol', gs, { n: freshN(), binding: { ...gs.binding, f: '4999' } }).ticket
  assert.equal(await on(0, gs.raw, lie), 'relay.decode-mismatch')
  assert.equal(ledger.size, 1)
  const t2 = ticketOf('testnet', 'sol', gs, { n: freshN(), e: NOW + 200_000 })
  assert.equal(await guard({ ...sendCheck('testnet', 'sol', gs.raw, t2.ticket, { route: ep(0, ledger, 3) }), observedId: GENESIS.sol.mainnet }), 'release.mainnet-locked')
  assert.equal(await on(0, gs.raw, t1.ticket, t1.payload.e), 'relay.ticket-expired')
  assert.equal(ledger.size, 1)
  // a new ticket for the same intent (POST …/tickets) is a new budget; the expired ticket's entry goes at the next claim
  assert.equal(await on(0, gs.raw, t2.ticket), 'passed')
  assert.equal(ledger.size, 2)
  assert.equal(await on(1, gs.raw, t2.ticket, t1.payload.e), 'passed')
  assert.equal(ledger.size, 1)
  assert.equal(await on(1, gs.raw, t2.ticket, t1.payload.e), 'relay.ticket-endpoint-reused')
  assert.equal(await on(0, gs.raw, t2.ticket, t1.payload.e + 1), 'relay.ticket-endpoint-reused')
  // two concurrent sends of one ticket to one endpoint: exactly one passes
  const t3 = ticketOf('testnet', 'sol', gs, { n: freshN() }).ticket
  const both = await Promise.all([on(1, gs.raw, t3), on(1, gs.raw, t3), on(1, gs.raw, t3)])
  assert.deepEqual(both.sort(), ['passed', 'relay.ticket-endpoint-reused', 'relay.ticket-endpoint-reused'])
  // the refusal never echoes the ticket or the bytes
  try { await checkSend(sendCheck('testnet', 'sol', gs.raw, t3, { route: ep(1, ledger, 3) })); assert.fail('expected a refusal') } catch (e) {
    const m = (e as Error).message
    assert.ok(!m.includes(t3.slice(12, 40)) && !m.includes(gs.b64.slice(0, 20)) && !m.includes(gs.txId), m)
  }
})

// ---------- the relay in process, over HTTP (an injected transport plays every upstream) ----------

interface Rpc { jsonrpc: string; id: unknown; method: string; params?: unknown[] }
interface Call { url: string; role: string; rpc: Rpc | null; body: Buffer | null }
interface UpRes { status: number; body: Buffer }
const json = (status: number, v: unknown): UpRes => ({ status, body: Buffer.from(JSON.stringify(v)) })
// A send's answer is the signature of the bytes it carried, as a node gives it.
const resultOf = (network: Network, url: string, r: Rpc): unknown => {
  if (r.method === 'eth_chainId') return OBSERVED[network].eth
  if (r.method === 'getGenesisHash') return OBSERVED[network].sol
  if (r.method === 'eth_estimateGas') return `0x${(network === 'testnet' ? 21_400 : 25_000).toString(16)}`
  if (r.method === 'sendTransaction') return txIdOf('sol', Buffer.from(String(r.params?.[0]), 'base64'))
  return `${r.method}@${url}`
}

interface Started { port: number; network: Network; logs: string[]; calls: Call[]; refuse: Set<string>; relay: ReturnType<typeof createRelay>; close(): Promise<void> }
const OPEN = new Set<{ close(): Promise<void> }>()
after(() => Promise.all([...OPEN].map((s) => s.close())))
async function start(network: Network, o: { upstream?: { eth: string[]; sol: string[] }; down?: (url: string) => boolean; identityOf?: (url: string, method: string) => string | undefined } = {}): Promise<Started> {
  const calls: Call[] = []
  const refuse = new Set<string>()   // upstreams that answer 429 from now on (filled after startup)
  const transport = async (url: string, r: { method: string; body?: Buffer; role: string; user: string }): Promise<UpRes> => {
    const rpc = r.body ? JSON.parse(r.body.toString('utf8')) as Rpc : null
    calls.push({ url, role: r.role, rpc, body: r.body ?? null })
    if (refuse.has(url)) return json(429, { error: 'rate limited' })
    if (o.down?.(url)) throw Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })
    if (url === TOR_CHECK) return json(200, { IsTor: true, IP: CANARY })
    if (rpc === null) return json(404, {})
    return json(200, { jsonrpc: '2.0', id: rpc.id, result: o.identityOf?.(url, rpc.method) ?? resultOf(network, url, rpc) })
  }
  const logs: string[] = []
  const relay = createRelay({
    network, build: 'test', upstream: o.upstream ?? relayUpstreams(network, {}), transport, priceFixture: network === 'local' ? { SOL: 150, ETH: 3000 } : null,
    ticketKey: () => TICKET_KEY, confinement: { ok: true, probes: 5, result: 'EPERM ×5' }, now: () => NOW, log: (l: string) => { logs.push(l) }, rand: () => 'sess',
  })
  await relay.startup()
  const server = createServer(relay.handle)
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const s: Started = { port: (server.address() as { port: number }).port, network, logs, calls, refuse, relay, close: () => closeServer(s, server) }
  OPEN.add(s)
  return s
}
function closeServer(s: { close(): Promise<void> }, server: Server): Promise<void> {
  OPEN.delete(s)
  return new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()) })
}

interface Reply { status: number; text: string; json: any }
function post(port: number, network: Network, path: string, body: unknown, ticket?: string): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const b = Buffer.from(JSON.stringify(body))
    const r = request({ host: '127.0.0.1', port, path, method: 'POST',
      headers: { host: `127.0.0.1:${PORTS[network].relay}`, 'content-type': 'application/json', 'content-length': String(b.length), ...(ticket !== undefined ? { 'x-vt-send-ticket': ticket } : {}) } }, (res) => {
      const c: Buffer[] = []
      res.on('data', (d: Buffer) => c.push(d))
      res.on('end', () => { const text = Buffer.concat(c).toString('utf8'); let j: unknown; try { j = JSON.parse(text) } catch { j = undefined } resolve({ status: res.statusCode ?? 0, text, json: j }) })
    })
    r.on('error', reject)
    r.end(b)
  })
}
const rpc = (method: string, params: unknown[] = [], id = 7): Rpc => ({ jsonrpc: '2.0', id, method, params })
const sendsOf = (calls: Call[], method: string): Call[] => calls.filter((c) => c.rpc?.method === method)
const guardOf = (r: Reply): string | undefined => r.json?.error?.data?.guard
const REBROADCAST = { encoding: 'base64', skipPreflight: true, maxRetries: 0 }   // as packages/core sol.js rebroadcast

test('over HTTP: one ticket, the same bytes → ep/0, ep/1 and /relay/sol, each forwarded once to its own endpoint; the same endpoint again → 403 relay.ticket-endpoint-reused; /relay/sol keeps taking rebroadcasts', { timeout: 30_000 }, async () => {
  const s = await start('testnet', { upstream: { eth: ENDPOINTS.testnet['eth.rpc'], sol: [SOL_A, SOL_B] } })
  try {
    const gs = genuineSol(), { ticket } = ticketOf('testnet', 'sol', gs, { n: freshN() })
    const body = rpc('sendTransaction', [gs.b64, { encoding: 'base64', preflightCommitment: 'confirmed' }])
    const [r0, r1] = await Promise.all([post(s.port, 'testnet', '/relay/sol/ep/0', body, ticket), post(s.port, 'testnet', '/relay/sol/ep/1', body, ticket)])
    const rp = await post(s.port, 'testnet', '/relay/sol', body, ticket)
    for (const r of [r0, r1, rp]) assert.deepEqual([r.status, r.json], [200, { jsonrpc: '2.0', id: 7, result: gs.txId }])
    const sent = sendsOf(s.calls, 'sendTransaction')
    assert.deepEqual(sent.map((c) => c.url).sort(), [SOL_A, SOL_A, SOL_B])
    assert.ok(sent.every((c) => c.role === 'sol' && c.body !== null && c.body.equals(sent[0].body!)), 'every endpoint got byte-identical bodies')
    assert.deepEqual(sent[0].rpc, body)
    // the same endpoint twice under one ticket: refused before anything is forwarded (the engine then uses /relay/sol)
    for (const path of ['/relay/sol/ep/0', '/relay/sol/ep/1']) {
      const again = await post(s.port, 'testnet', path, rpc('sendTransaction', [gs.b64, REBROADCAST]), ticket)
      assert.deepEqual([again.status, guardOf(again), again.json.error.code, again.json.id], [403, 'relay.ticket-endpoint-reused', -32003, 7], path)
      assert.ok(!again.text.includes(ticket.slice(12, 40)) && !again.text.includes(gs.b64.slice(0, 20)))
    }
    assert.equal(sendsOf(s.calls, 'sendTransaction').length, 3)
    for (let k = 0; k < 3; k++) assert.deepEqual([(await post(s.port, 'testnet', '/relay/sol', rpc('sendTransaction', [gs.b64, REBROADCAST]), ticket)).status], [200], `rebroadcast ${k}`)
    assert.deepEqual(sendsOf(s.calls, 'sendTransaction').map((c) => c.url), [...sent.map((c) => c.url), SOL_A, SOL_A, SOL_A])
    // other bytes under that ticket → relay.ticket-raw on an endpoint route; a refused send spends nothing
    const other = genuineSol()
    const t2 = ticketOf('testnet', 'sol', gs, { n: freshN() }).ticket
    const raw = await post(s.port, 'testnet', '/relay/sol/ep/1', rpc('sendTransaction', [other.b64, { encoding: 'base64' }]), t2)
    assert.deepEqual([raw.status, guardOf(raw), raw.json.error.code], [403, 'relay.ticket-raw', -32003])
    const ok = await post(s.port, 'testnet', '/relay/sol/ep/1', rpc('sendTransaction', [gs.b64, { encoding: 'base64' }]), t2)
    assert.deepEqual([ok.status, ok.json.result], [200, gs.txId])
    assert.equal(sendsOf(s.calls, 'sendTransaction').at(-1)?.url, SOL_B)
    // two concurrent sends of a fresh ticket to one endpoint: exactly one is forwarded
    const t3 = ticketOf('testnet', 'sol', gs, { n: freshN() }).ticket
    const before = sendsOf(s.calls, 'sendTransaction').length
    const race = await Promise.all([0, 1, 2].map(() => post(s.port, 'testnet', '/relay/sol/ep/0', body, t3)))
    assert.deepEqual(race.map((r) => r.status).sort(), [200, 403, 403])
    assert.equal(sendsOf(s.calls, 'sendTransaction').length, before + 1)
    // no ticket on an endpoint route → relay.send-ticket, as on /relay/sol
    const none = await post(s.port, 'testnet', '/relay/sol/ep/0', body)
    assert.deepEqual([none.status, guardOf(none)], [403, 'relay.send-ticket'])
    // the log: the guard, never a param or the ticket
    assert.ok(s.logs.some((l) => /^sol sendTransaction 403 \d+ms relay\.ticket-endpoint-reused$/.test(l)))
    for (const l of s.logs) assert.ok(!l.includes(gs.b64.slice(0, 20)) && !l.includes(ticket.slice(12, 40)) && !l.includes(gs.txId), l)
  } finally { await s.close() }
})

test('over HTTP: an ep send is never failed over — endpoint B answers 429 after startup: ep/1 gives the refusal, A receives nothing, the budget is spent; ep/0 still takes the ticket (Sfix1 review m-1)', { timeout: 30_000 }, async () => {
  const s = await start('testnet', { upstream: { eth: ENDPOINTS.testnet['eth.rpc'], sol: [SOL_A, SOL_B] } })
  try {
    s.refuse.add(SOL_B)
    const gs = genuineSol(), { ticket } = ticketOf('testnet', 'sol', gs, { n: freshN() })
    const body = rpc('sendTransaction', [gs.b64, { encoding: 'base64' }])
    const r1 = await post(s.port, 'testnet', '/relay/sol/ep/1', body, ticket)
    assert.notEqual(r1.status, 200)
    assert.equal(guardOf(r1), undefined, 'an upstream refusal, not a gate refusal')
    const sent = sendsOf(s.calls, 'sendTransaction')
    assert.ok(sent.length >= 1 && sent.every((c) => c.url === SOL_B), 'only B was asked (the relay may retry B itself); the send was not failed over to A')
    assert.ok(!r1.text.includes(gs.b64.slice(0, 20)))
    // the budget for ep/1 was spent when the request was forwarded; a second send there is refused at the gate, still nothing at A
    const r2 = await post(s.port, 'testnet', '/relay/sol/ep/1', body, ticket)
    assert.deepEqual([r2.status, guardOf(r2)], [403, 'relay.ticket-endpoint-reused'])
    assert.equal(sendsOf(s.calls, 'sendTransaction').length, sent.length, 'the refused second send forwarded nothing')
    // ep/0 has its own, unspent budget and reaches A (and A alone)
    const r0 = await post(s.port, 'testnet', '/relay/sol/ep/0', body, ticket)
    assert.deepEqual([r0.status, r0.json.result], [200, gs.txId])
    assert.deepEqual(sendsOf(s.calls, 'sendTransaction').map((c) => c.url), [...sent.map((c) => c.url), SOL_A])
  } finally { await s.close() }
})

test('over HTTP: an out-of-range index, and an endpoint that failed identity at startup, are not indexable → 403 relay.endpoint-unverified; ep/<i> counts verified endpoints only', { timeout: 30_000 }, async () => {
  const s = await start('testnet', { upstream: { eth: ENDPOINTS.testnet['eth.rpc'], sol: [SOL_A, SOL_B, SOL_C] }, down: (url) => url === SOL_B })
  try {
    assert.ok(s.logs.some((l) => /^identity sol sol-b\.example: unreachable\/refused/.test(l)))
    const gs = genuineSol(), { ticket } = ticketOf('testnet', 'sol', gs, { n: freshN() })
    const body = rpc('sendTransaction', [gs.b64, { encoding: 'base64' }])
    const ok = await post(s.port, 'testnet', '/relay/sol/ep/1', body, ticket)                       // the second VERIFIED endpoint: C
    assert.deepEqual([ok.status, ok.json.result], [200, gs.txId])
    assert.deepEqual(sendsOf(s.calls, 'sendTransaction').map((c) => c.url), [SOL_C])
    for (const i of [2, 3, 9]) {
      for (const [b, t] of [[body, ticket], [rpc('getBalance', ['11111111111111111111111111111111']), undefined]] as const) {
        const r = await post(s.port, 'testnet', `/relay/sol/ep/${i}`, b, t)
        assert.deepEqual([r.status, guardOf(r), r.json.error.code], [403, 'relay.endpoint-unverified', -32601], `ep ${i} ${b.method}`)
      }
      const e = await post(s.port, 'testnet', `/relay/eth/ep/${i}`, rpc('eth_blockNumber'))   // testnet ETH: one verified endpoint
      assert.deepEqual([e.status, guardOf(e)], [403, 'relay.endpoint-unverified'])
    }
    assert.deepEqual(sendsOf(s.calls, 'sendTransaction').map((c) => c.url), [SOL_C])
    assert.equal(s.calls.filter((c) => c.rpc?.method === 'getBalance' || c.rpc?.method === 'eth_blockNumber').length, 0)
    const read = await post(s.port, 'testnet', '/relay/sol/ep/0', rpc('getBalance', ['11111111111111111111111111111111']))
    assert.deepEqual([read.status, read.json.result], [200, `getBalance@${SOL_A}`])
  } finally { await s.close() }
})

test('PF-S M-2: a chain endpoint that did not answer at startup is checked again; it joins at the END (the /ep indices never move) and the status counts it live', { timeout: 30_000 }, async () => {
  const downs = new Set([SOL_B, ETH_B])
  const s = await start('testnet', { upstream: { eth: [ETH_A, ETH_B], sol: [SOL_A, SOL_B, SOL_C] }, down: (url) => downs.has(url) })
  try {
    assert.deepEqual(s.relay.status().endpoints, { eth: 1, sol: 2 })
    // still down: a round changes nothing
    await s.relay.recheck()
    assert.deepEqual(s.relay.status().endpoints, { eth: 1, sol: 2 })
    // the Tor timeout is over: the next round verifies both, appended after the endpoints already verified
    downs.clear()
    const before = s.calls.length
    await s.relay.recheck()
    assert.deepEqual(s.relay.status().endpoints, { eth: 2, sol: 3 })
    assert.deepEqual(s.relay.status().identity, { eth: { ok: true }, sol: { ok: true } })
    assert.deepEqual(s.calls.slice(before).filter((c) => c.rpc !== null).map((c) => [c.url, c.rpc!.method]).sort(),
      [[ETH_B, 'eth_chainId'], [SOL_B, 'getGenesisHash']], 'only the dropped endpoints were asked again (the eth fork probe ran once at startup)')
    assert.ok(s.logs.some((l) => /^identity sol sol-b\.example: .* \(re-check, \d+ ms\)$/.test(l)))
    const gs = genuineSol(), { ticket } = ticketOf('testnet', 'sol', gs, { n: freshN() })
    const body = rpc('sendTransaction', [gs.b64, { encoding: 'base64' }])
    for (const i of [0, 1, 2]) assert.equal((await post(s.port, 'testnet', `/relay/sol/ep/${i}`, body, ticket)).status, 200, `ep ${i}`)
    assert.deepEqual(sendsOf(s.calls, 'sendTransaction').map((c) => c.url), [SOL_A, SOL_C, SOL_B])   // ep/0 and ep/1 kept their endpoints; B is ep/2
    // nothing left to check: a round asks nothing
    const n = s.calls.length
    await s.relay.recheck()
    assert.equal(s.calls.length, n)
  } finally { await s.close() }
})

test('PF-S M-2: an endpoint that answers ANOTHER identity on a re-check disables its chain until restart (503 on every route, the status says why)', { timeout: 30_000 }, async () => {
  const downs = new Set([SOL_B])
  let liar = false
  const s = await start('testnet', { upstream: { eth: ENDPOINTS.testnet['eth.rpc'], sol: [SOL_A, SOL_B] }, down: (url) => downs.has(url),
    identityOf: (url, m) => (liar && url === SOL_B && m === 'getGenesisHash' ? GENESIS.sol.mainnet : undefined) })
  try {
    assert.equal(s.relay.status().endpoints.sol, 1)
    downs.clear(); liar = true
    await s.relay.recheck()
    const st = s.relay.status()
    assert.deepEqual([st.endpoints.sol, st.identity.sol?.ok], [0, false])
    assert.match(st.identity.sol?.message ?? '', /another identity on a re-check/)
    assert.equal(st.endpoints.eth, 1)                                                              // the other chain is untouched
    const before = s.calls.length
    for (const path of ['/relay/sol', '/relay/sol/ep/0']) assert.equal((await post(s.port, 'testnet', path, rpc('getBalance', ['11111111111111111111111111111111']))).status, 503, path)
    assert.equal(s.calls.length, before, 'nothing forwarded')
    assert.ok(s.logs.some((l) => /^identity sol: DISABLED/.test(l)))
    // and it stays disabled: no further round asks it
    liar = false
    const n = s.calls.length
    await s.relay.recheck()
    assert.deepEqual([s.relay.status().endpoints.sol, s.calls.length], [0, n])
  } finally { await s.close() }
})

// M2 FLIP (applied, operator R78): the endpoint routes take a mainnet SOL send under exactly the testnet rules; every other check still refuses.
test('over HTTP: mainnet (M2 flip: the job-send lock lifted) — refused sends (no ticket, a testnet ticket, other bytes, a lying binding) spend nothing; then one valid ticket → ep/0, ep/1 and /relay/sol each forwarded once, the same endpoint again → relay.ticket-endpoint-reused; ETH ep stays read-only', { timeout: 30_000 }, async () => {
  const m = await start('mainnet')
  try {
    const up = relayUpstreams('mainnet', {}).sol
    assert.equal(up.length, 2)
    const gs = genuineSol(), other = genuineSol(), { ticket } = ticketOf('mainnet', 'sol', gs, { n: freshN() })
    const body = rpc('sendTransaction', [gs.b64, { encoding: 'base64' }])
    for (const path of ['/relay/sol/ep/0', '/relay/sol/ep/1', '/relay/sol']) {
      for (const [want, b, t] of [
        ['relay.send-ticket', body, undefined],
        ['relay.ticket-network', body, ticketOf('testnet', 'sol', gs, { n: freshN() }).ticket],
        ['relay.ticket-raw', rpc('sendTransaction', [other.b64, { encoding: 'base64' }]), ticket],
        ['relay.decode-mismatch', body, ticketOf('mainnet', 'sol', gs, { n: freshN(), binding: { ...gs.binding, f: '4999' } }).ticket],
      ] as const) {
        const r = await post(m.port, 'mainnet', path, b, t)
        assert.deepEqual([r.status, guardOf(r), r.json.error.code], [403, want, -32003], `${path} ${want}`)
      }
    }
    assert.equal(sendsOf(m.calls, 'sendTransaction').length, 0, 'nothing refused was forwarded')
    for (const path of ['/relay/sol/ep/0', '/relay/sol/ep/1', '/relay/sol']) {
      const r = await post(m.port, 'mainnet', path, body, ticket)   // the refused sends above spent nothing of this ticket
      assert.deepEqual([r.status, r.json.result], [200, gs.txId], path)
    }
    assert.deepEqual(sendsOf(m.calls, 'sendTransaction').map((c) => c.url), [up[0], up[1], up[0]])
    for (const path of ['/relay/sol/ep/0', '/relay/sol/ep/1']) {
      const again = await post(m.port, 'mainnet', path, body, ticket)
      assert.deepEqual([again.status, guardOf(again)], [403, 'relay.ticket-endpoint-reused'], path)
    }
    assert.equal(sendsOf(m.calls, 'sendTransaction').length, 3)
    const ge = await genuineEth('mainnet')
    const e = await post(m.port, 'mainnet', '/relay/eth/ep/0', rpc('eth_sendRawTransaction', [ge.hex]), ticketOf('mainnet', 'eth', ge).ticket)
    assert.deepEqual([e.status, guardOf(e)], [403, 'relay.endpoint-read-only'])
    assert.equal(sendsOf(m.calls, 'eth_sendRawTransaction').length, 0)
  } finally { await m.close() }
})

test('over HTTP: decode verification applies on the endpoint routes (S4) → 403 relay.decode-mismatch, never forwarded', { timeout: 30_000 }, async () => {
  const s = await start('testnet', { upstream: { eth: ENDPOINTS.testnet['eth.rpc'], sol: [SOL_A, SOL_B] } })
  try {
    const gs = genuineSol()
    const lies: Array<[string, TicketBinding]> = [
      ['payload', { ...gs.binding, p: 'ab'.repeat(32) }], ['fee', { ...gs.binding, f: '4999' }], ['blockhash', { ...gs.binding, q: '11111111111111111111111111111111' }],
      ['sender', { ...gs.binding, a: '9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin' }],
      ['kind', { ...gs.binding, k: 'clawback', p: null, to: '9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin', value: '1' }],
    ]
    for (const [name, binding] of lies) {
      const t = ticketOf('testnet', 'sol', gs, { n: freshN(), binding }).ticket
      for (const path of ['/relay/sol/ep/0', '/relay/sol/ep/1']) {
        const r = await post(s.port, 'testnet', path, rpc('sendTransaction', [gs.b64, { encoding: 'base64' }]), t)
        assert.deepEqual([r.status, guardOf(r), r.json.error.code], [403, 'relay.decode-mismatch', -32003], `${name} ${path}`)
        assert.match(r.json.error.message, /^the signed transaction is not what the API ticketed \(sol\.[a-z-]+\): nothing was forwarded$/)
      }
    }
    assert.equal(sendsOf(s.calls, 'sendTransaction').length, 0)
    const good = await post(s.port, 'testnet', '/relay/sol/ep/1', rpc('sendTransaction', [gs.b64, { encoding: 'base64' }]), ticketOf('testnet', 'sol', gs, { n: freshN() }).ticket)
    assert.deepEqual([good.status, good.json.result], [200, gs.txId])
  } finally { await s.close() }
})

test('over HTTP: ETH per-endpoint routes stay read-only — a genuine ETH send with a valid ticket → 403 relay.endpoint-read-only on every ep, never forwarded; reads reach exactly endpoint i', { timeout: 30_000 }, async () => {
  const s = await start('testnet', { upstream: { eth: [ETH_A, ETH_B], sol: [SOL_A] } })
  try {
    const ge = await genuineEth('testnet'), { ticket } = ticketOf('testnet', 'eth', ge, { n: freshN() })
    for (const i of [0, 1]) {
      const r = await post(s.port, 'testnet', `/relay/eth/ep/${i}`, rpc('eth_sendRawTransaction', [ge.hex]), ticket)
      assert.deepEqual([r.status, guardOf(r), r.json.error.code], [403, 'relay.endpoint-read-only', -32601], `ep ${i}`)
    }
    assert.equal(sendsOf(s.calls, 'eth_sendRawTransaction').length, 0)
    const chainRoute = await post(s.port, 'testnet', '/relay/eth', rpc('eth_sendRawTransaction', [ge.hex]), ticket)   // the ticket is good
    assert.deepEqual([chainRoute.status, chainRoute.json.result], [200, `eth_sendRawTransaction@${ETH_A}`])
    for (const [i, url] of [[0, ETH_A], [1, ETH_B]] as const) {
      const r = await post(s.port, 'testnet', `/relay/eth/ep/${i}`, rpc('eth_getTransactionCount', [`0x${'11'.repeat(20)}`, 'pending']))
      assert.deepEqual([r.status, r.json.result], [200, `eth_getTransactionCount@${url}`])
    }
    const airdrop = await post(s.port, 'testnet', '/relay/sol/ep/0', rpc('requestAirdrop', ['9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin', 1]))   // R71d: never via /ep
    assert.equal(airdrop.status, 403)
    assert.equal(sendsOf(s.calls, 'requestAirdrop').length, 0)
  } finally { await s.close() }
})

// ---------- integration-style: the real local transport, two fake SOL upstreams on loopback ----------

interface FakeNode { url: string; bodies: Buffer[]; close(): Promise<void> }
async function fakeSolNode(): Promise<FakeNode> {
  const bodies: Buffer[] = []
  const server = createServer((req, res) => {
    const c: Buffer[] = []
    req.on('data', (d: Buffer) => c.push(d))
    req.on('end', () => {
      const body = Buffer.concat(c)
      const r = JSON.parse(body.toString('utf8')) as Rpc
      if (r.method === 'sendTransaction') bodies.push(body)
      const result = r.method === 'getGenesisHash' ? LOCAL_GENESIS : r.method === 'sendTransaction' ? txIdOf('sol', Buffer.from(String(r.params?.[0]), 'base64')) : null
      const out = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: r.id, result }))
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': out.length }); res.end(out)
    })
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const node: FakeNode = { url: `http://127.0.0.1:${(server.address() as { port: number }).port}`, bodies, close: () => closeServer(node, server) }
  OPEN.add(node)
  return node
}

test('integration: two SOL upstreams on loopback behind the real local transport receive byte-identical sendTransaction bodies, once each per ticket; the E5 rebroadcast round falls back to /relay/sol', { timeout: 30_000 }, async () => {
  const a = await fakeSolNode(), b = await fakeSolNode()
  const logs: string[] = []
  const relay = createRelay({ network: 'local', build: 'test', upstream: { eth: [], sol: [a.url, b.url] }, transport: socksTransport('local'), priceFixture: null,
    ticketKey: () => TICKET_KEY, confinement: { ok: true, probes: 5, result: 'EPERM ×5' }, log: (l: string) => { logs.push(l) } })
  await relay.startup()
  assert.deepEqual(relay.status().endpoints, { eth: 0, sol: 2 })
  const server = createServer(relay.handle)
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const handle = { close: (): Promise<void> => closeServer(handle, server) }
  OPEN.add(handle)
  const port = (server.address() as { port: number }).port
  try {
    const gs = genuineSol()
    const { ticket } = ticketOf('local', 'sol', gs, { n: freshN(), e: Date.now() + 120_000 })
    // E5 postSol: the same bytes, the same ticket, to every verified endpoint in parallel
    const body = rpc('sendTransaction', [gs.b64, { encoding: 'base64', preflightCommitment: 'confirmed' }], 41)
    const first = await Promise.all([post(port, 'local', '/relay/sol/ep/0', body, ticket), post(port, 'local', '/relay/sol/ep/1', body, ticket)])
    for (const r of first) assert.deepEqual([r.status, r.json], [200, { jsonrpc: '2.0', id: 41, result: gs.txId }])
    assert.deepEqual([a.bodies.length, b.bodies.length], [1, 1])
    assert.ok(a.bodies[0].equals(b.bodies[0]), 'the two upstreams received byte-identical bodies')
    assert.deepEqual(JSON.parse(a.bodies[0].toString('utf8')), body)
    assert.ok(Buffer.from((JSON.parse(a.bodies[0].toString('utf8')) as { params: string[] }).params[0], 'base64').equals(gs.raw))
    // the next E5 round (a rebroadcast under the same ticket): both endpoint routes refuse → the engine sends via /relay/sol
    const rb = rpc('sendTransaction', [gs.b64, REBROADCAST], 42)
    const refused = await Promise.all([post(port, 'local', '/relay/sol/ep/0', rb, ticket), post(port, 'local', '/relay/sol/ep/1', rb, ticket)])
    for (const r of refused) assert.deepEqual([r.status, guardOf(r)], [403, 'relay.ticket-endpoint-reused'])
    assert.deepEqual([a.bodies.length, b.bodies.length], [1, 1])
    const viaChain = await post(port, 'local', '/relay/sol', rb, ticket)
    assert.deepEqual([viaChain.status, viaChain.json.result], [200, gs.txId])
    assert.deepEqual([a.bodies.length, b.bodies.length], [2, 1])                       // the preferred endpoint is A
    assert.deepEqual(JSON.parse(a.bodies[1].toString('utf8')), rb)
    // a refreshed ticket (POST …/tickets) reaches every endpoint again, byte-identically
    const fresh = ticketOf('local', 'sol', gs, { n: freshN(), e: Date.now() + 120_000 }).ticket
    const second = await Promise.all([post(port, 'local', '/relay/sol/ep/0', rb, fresh), post(port, 'local', '/relay/sol/ep/1', rb, fresh)])
    for (const r of second) assert.equal(r.status, 200)
    assert.deepEqual([a.bodies.length, b.bodies.length], [3, 2])
    assert.ok(a.bodies[2].equals(b.bodies[1]) && a.bodies[2].equals(a.bodies[1]))
    assert.ok(logs.every((l) => !l.includes(gs.b64.slice(0, 20)) && !l.includes('127.0.0.1')), 'a param or an IP reached the log')
  } finally { await handle.close(); await a.close(); await b.close() }
})

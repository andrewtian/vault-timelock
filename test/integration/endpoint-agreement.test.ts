// M3prep glue: plan E5's SOL send fan-out (engine.js postSol) against Sfix1's REAL relay (api/relay/relay.mjs, in process,
// over HTTP, the real local transport) with two SOL endpoints. E5 was written against a relay that refused every send on
// /relay/sol/ep/<i>; Sfix1's relay now accepts them once per ticket per endpoint. Pinned together:
//   · the same signed bytes (one txId) reach BOTH endpoints, byte-identically, in one per-endpoint round per ticket;
//   · the rebroadcasts under that ticket go through /relay/sol only (the preferred endpoint), never /ep/<i> again;
//   · a refreshed ticket makes a new round;
//   · fallback still works: a relay that refuses the endpoint routes (relay.ticket-endpoint-reused, e.g. a takeover whose
//     new process has no epRound memory) is rescued through /relay/sol, which is unbudgeted; an endpoint that fails does not
//     hold the send back.
// Synthetic data; two fake SOL nodes on loopback port 0; no Tor, no testnet, no stack.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createServer, request } from 'node:http'
import type { Server } from 'node:http'
import { postSol } from '../../packages/core/src/engine/engine.js'
import { relayRpc } from '../../packages/core/src/engine/rpc.js'
import { createRelay, socksTransport } from '../../api/relay/relay.mjs'
import { encodeTicket } from '../../api/src/tickets.ts'
import type { TicketPayload } from '../../packages/core/src/contracts/index.ts'
import { PORTS } from '../../packages/core/src/contracts/index.ts'
import { genuineSol, txIdOf } from '../../api/test/genuine.ts'
import { TICKET_KEY } from '../../api/test/helpers.ts'

const LOCAL_GENESIS = '8pUq7jxkLxNpHg6M9KxzRtNEC4pNEHsr4kDTLSE5uVRW'
const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex')
let nonce = 0
const freshTicket = (g: ReturnType<typeof genuineSol>): string => {
  const payload: TicketPayload = { j: 'e3d45f73cf65abaa', w: 'local', c: 'sol', g: 1, t: txIdOf('sol', g.raw), r: sha(g.raw), ...g.binding,
    e: Date.now() + 120_000, n: (++nonce).toString(16).padStart(16, '0') }
  return encodeTicket(TICKET_KEY, payload)
}

interface FakeNode { url: string; bodies: Buffer[]; failSends: boolean; close(): Promise<void> }
async function fakeSolNode(): Promise<FakeNode> {
  const bodies: Buffer[] = []
  const server: Server = createServer((req, res) => {
    const c: Buffer[] = []
    req.on('data', (d: Buffer) => c.push(d))
    req.on('end', () => {
      const body = Buffer.concat(c)
      const r = JSON.parse(body.toString('utf8')) as { id: unknown; method: string; params?: string[] }
      if (r.method === 'sendTransaction') {
        bodies.push(body)
        if (node.failSends) { res.writeHead(503, { 'content-length': 0 }); res.end(); return }
      }
      const result = r.method === 'getGenesisHash' ? LOCAL_GENESIS : r.method === 'sendTransaction' ? txIdOf('sol', Buffer.from(String(r.params?.[0]), 'base64')) : null
      const out = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: r.id, result }))
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': out.length }); res.end(out)
    })
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const node: FakeNode = { url: `http://127.0.0.1:${(server.address() as { port: number }).port}`, bodies, failSends: false,
    close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()) }) }
  return node
}

async function setup(t: { after(fn: () => Promise<void>): void }): Promise<{ a: FakeNode; b: FakeNode; base: string; logs: string[] }> {
  const a = await fakeSolNode(), b = await fakeSolNode()
  const logs: string[] = []
  const relay = createRelay({ network: 'local', build: 'test', upstream: { eth: [], sol: [a.url, b.url] }, transport: socksTransport('local'), priceFixture: null,
    ticketKey: () => TICKET_KEY, confinement: { ok: true, probes: 5, result: 'EPERM ×5' }, log: (l: string) => { logs.push(l) } })
  await relay.startup()
  assert.deepEqual(relay.status().endpoints, { eth: 0, sol: 2 })
  const server = createServer(relay.handle)
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  t.after(async () => { await new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()) }); await a.close(); await b.close() })
  return { a, b, base: `http://127.0.0.1:${(server.address() as { port: number }).port}`, logs }
}

// fetch with the Host header the local relay requires (undici's fetch will not set Host): node:http, answering as a Response.
const hostedFetch = (base: string) => (url: string, init: RequestInit): Promise<Response> => new Promise((resolve, reject) => {
  const u = new URL(url), body = Buffer.from(String(init.body ?? ''))
  const r = request({ host: u.hostname, port: u.port, path: u.pathname, method: init.method, headers: { ...(init.headers as Record<string, string>), host: `127.0.0.1:${PORTS.local.relay}`, 'content-length': String(body.length) } }, (res) => {
    const c: Buffer[] = []
    res.on('data', (d: Buffer) => c.push(d))
    res.on('end', () => resolve(new Response(Buffer.concat(c), { status: res.statusCode ?? 0 })))
  })
  r.on('error', reject)
  r.end(body)
})
// What the engine does for a send: the chain module's send() through the relay client, ep = null (preferred) or an index.
const sender = (base: string, b64: string, ticket: string, mode: 'send' | 'rebroadcast') => (ep: number | null): Promise<unknown> => {
  const cfg = { encoding: 'base64', ...(mode === 'send' ? { preflightCommitment: 'confirmed' } : { skipPreflight: true, maxRetries: 0 }) }
  return relayRpc({ base, fetch: hostedFetch(base) },
    'sol', 'sendTransaction', [b64, cfg], { ticket, ep })
}

test('two SOL endpoints: one per-endpoint round per ticket (same txId, same signed bytes), rebroadcasts via /relay/sol only, a fresh ticket a new round', { timeout: 60_000 }, async (t) => {
  const { a, b, base } = await setup(t)
  const g = genuineSol(), ticket = freshTicket(g)
  const o = { solEndpoints: 2 }
  const att: { ticket?: string; epRound?: string } = { ticket }
  const first = await postSol(o, g.txId, sender(base, g.b64, ticket, 'send'), att)
  assert.equal(first.kind, 'accepted', first.msg)
  assert.deepEqual([a.bodies.length, b.bodies.length], [1, 1], 'one send to each endpoint')
  const params = (x: Buffer): unknown => (JSON.parse(x.toString('utf8')) as { method: string; params: unknown }).params   // the id is the client's counter
  assert.deepEqual(params(a.bodies[0]), params(b.bodies[0]), 'the same signed bytes and options (one txId)')
  assert.deepEqual(params(a.bodies[0]), [g.b64, { encoding: 'base64', preflightCommitment: 'confirmed' }])
  assert.equal(att.epRound, ticket, 'the attempt remembers the round')
  // the 2 s rebroadcasts under the same ticket: preferred route only (the per-endpoint routes would refuse a repeat)
  for (let k = 0; k < 3; k++) {
    const r = await postSol(o, g.txId, sender(base, g.b64, ticket, 'rebroadcast'), att)
    assert.equal(r.kind, 'accepted', r.msg)
  }
  assert.deepEqual([a.bodies.length, b.bodies.length], [4, 1], 'rebroadcasts went to the preferred endpoint only')
  // a refreshed ticket (ticketFor) makes the next round: every endpoint once more
  const fresh = freshTicket(g)
  const att2 = { ticket: fresh, epRound: ticket }
  const r2 = await postSol(o, g.txId, sender(base, g.b64, fresh, 'rebroadcast'), att2)
  assert.equal(r2.kind, 'accepted', r2.msg)
  assert.deepEqual([a.bodies.length, b.bodies.length], [5, 2])
  assert.equal(att2.epRound, fresh)
})

test('two SOL endpoints: fallback still works — the relay refuses the endpoint routes (ticket already used there) and /relay/sol rescues the send; a failing endpoint holds nothing back', { timeout: 60_000 }, async (t) => {
  const { a, b, base, logs } = await setup(t)
  const g = genuineSol(), ticket = freshTicket(g)
  const o = { solEndpoints: 2 }
  assert.equal((await postSol(o, g.txId, sender(base, g.b64, ticket, 'send'), { ticket })).kind, 'accepted')
  assert.deepEqual([a.bodies.length, b.bodies.length], [1, 1])
  // a takeover: a new attempt object has no epRound, so it fans out again; the relay refuses both routes (403 relay.ticket-endpoint-reused)
  // before forwarding, so nothing reaches the nodes from them, and the rescue goes through /relay/sol
  const taken = await postSol(o, g.txId, sender(base, g.b64, ticket, 'rebroadcast'), { ticket })
  assert.equal(taken.kind, 'accepted', taken.msg)
  assert.deepEqual([a.bodies.length, b.bodies.length], [2, 1], 'only the rescue reached a node (the preferred one)')
  assert.equal(logs.filter((l) => /^sol sendTransaction 403 \d+ms relay\.ticket-endpoint-reused$/.test(l)).length, 2)
  // endpoint B fails every send from now on: A's acceptance carries the round
  b.failSends = true
  const g2 = genuineSol({ payload: new Uint8Array([7, 7, 7]) }), t2 = freshTicket(g2)
  const att = { ticket: t2 } as { ticket?: string; epRound?: string }
  const r = await postSol(o, g2.txId, sender(base, g2.b64, t2, 'send'), att)
  assert.equal(r.kind, 'accepted', r.msg)
  assert.equal(a.bodies.filter((x) => x.toString('utf8').includes(g2.b64)).length, 1, 'A got the send once')
  assert.ok(b.bodies.filter((x) => x.toString('utf8').includes(g2.b64)).length >= 1, 'B was asked on its own route and failed it')
  assert.equal(att.epRound, t2)
})

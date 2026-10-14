// A relay in memory (not a test file): RelayClient over per-chain JSON-RPC handlers, with the engine's failure classes
// (a handler error = RpcError, a TransportFailure = TransportError), /relay/status, /relay/tor and /relay/price; and
// stackFetch, the same fake stack behind a fetch function (the page's relative /api and /relay paths, or the CLI's
// loopback ports with the token), for the HTTP clients and the parity test. ALL DATA IS SYNTHETIC; nothing listens.
import { PORTS, Refusal, httpStatusFor, isRefusal } from '../../src/contracts/index.ts'
import type { Chain, JournalClient, Network, RelayClient, RelayStatus } from '../../src/contracts/index.ts'
import { RelayRefused, RpcError, TransportError } from '../../src/engine/rpc.js'
import { JournalUnreachable } from '../../src/executor/journal-client.ts'

type Handler = (method: string, params: any[], ep: number | null) => unknown
export interface RelayCall { chain: Chain; method: string; params: unknown[]; ticket: string | null; ep: number | null }

// onSend (optional): the relay's own check of a ticketed send (S4 / CC-3a: the signed tx must be the journaled intent's —
// its id, its bytes, its declared ETH nonce or SOL blockhash); a throw refuses the send (RpcError), as the relay would.
const SENDS = new Set(['eth_sendRawTransaction', 'sendTransaction'])
export function fakeRelayClient(o: { network: Network; eth?: Handler; sol?: Handler; identity?: RelayStatus['identity']; endpoints?: RelayStatus['endpoints']; confined?: boolean; isTor?: boolean | null; torRoles?: readonly string[]; price?: unknown; down?: () => boolean; onSend?: (chain: Chain, params: any[], ticket: string | null) => void }) {
  const calls: RelayCall[] = []
  const down = (): void => { if (o.down?.()) throw new TransportError('relay unreachable (test)') }
  const client: RelayClient = {
    async status() { down(); return { network: o.network, build: 'fake-relay', confined: o.confined ?? true, identity: o.identity ?? { eth: { ok: true }, sol: { ok: true } }, endpoints: o.endpoints ?? { eth: 1, sol: 2 } } },
    async rpc(chain, method, params, x) {
      down()
      calls.push({ chain, method, params, ticket: x?.ticket ?? null, ep: x?.ep ?? null })
      const h = chain === 'eth' ? o.eth : o.sol
      let r: unknown
      try {
        if (SENDS.has(method)) o.onSend?.(chain, params as any[], x?.ticket ?? null)
        r = h === undefined ? undefined : await h(method, params as any[], x?.ep ?? null)
      } catch (e) {
        if ((e as Error).name === 'TransportFailure') throw new TransportError('relay: upstream timeout (test)')
        if ((e as Error).name === 'RelayRefusal') throw new RelayRefused(`relay refused (403): ${(e as Error).message}`)   // the relay's own refusal, nothing forwarded
        throw new RpcError({ code: -32000, message: (e as Error).message })
      }
      if (r === undefined) throw new RpcError({ code: -32601, message: `no fake for ${method}` })
      return r
    },
    async tor() { down(); return { isTor: o.isTor === undefined ? (o.network === 'local' ? null : true) : o.isTor, ...(o.torRoles !== undefined ? { torRoles: o.torRoles } : {}) } },
    async price() { down(); return (o.price ?? { fixture: true, source: 'LOCAL FIXTURE PRICE (--price-fixture)', fetchedAt: 0, prices: { SOL: { usd: 150 }, ETH: { usd: 3000 } } }) as never },
  }
  return { client, calls, sends: () => calls.filter((c) => c.method === 'eth_sendRawTransaction' || c.method === 'sendTransaction') }
}

// The fake stack behind fetch. Browser: relative '/api/<path>' (the page server injects the token) and '/relay/<path>'
// resolved against the page origin; CLI: http://127.0.0.1:<api port>/<path> with 'Bearer <token>' and
// http://127.0.0.1:<relay port>/relay/<path>. A JournalUnreachable becomes a network failure (no reply).
export function stackFetch(o: { network: Network; journal: JournalClient; relay: RelayClient; token: string; pageOrigin?: string }) {
  const page = o.pageOrigin ?? `http://127.0.0.1:${PORTS[o.network].page}`
  const api = `http://127.0.0.1:${PORTS[o.network].api}`, relayBase = `http://127.0.0.1:${PORTS[o.network].relay}`
  const seen: string[] = []
  const reply = (status: number, body: unknown): Response => new Response(typeof body === 'string' ? body : JSON.stringify(body, (_k, v) => (typeof v === 'bigint' ? String(v) : v)), { status, headers: { 'content-type': typeof body === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8' } })
  async function callApi(method: string, path: string, body: any): Promise<Response> {
    const m = (re: RegExp) => re.exec(path)
    try {
      if (method === 'GET' && path === '/status') return reply(200, await o.journal.status())
      let x
      if (method === 'GET' && (x = m(/^\/jobs\/([0-9a-f]{16})$/))) return reply(200, { id: x[1], ...(await o.journal.job(x[1])) })
      if (method === 'GET' && (x = m(/^\/messages\/([0-9a-f]{64})$/))) return reply(200, await o.journal.message(x[1]))
      if (method === 'POST' && (x = m(/^\/jobs\/([0-9a-f]{16})\/chains\/(eth|sol|btc)\/lease$/))) return reply(200, await o.journal.lease(x[1], x[2] as Chain, body.op, body.holder, body.gen))
      if (method === 'POST' && (x = m(/^\/jobs\/([0-9a-f]{16})\/chains\/(eth|sol|btc)\/events$/))) return reply(200, await o.journal.append(x[1], x[2] as Chain, body.gen, body.type, body.data, body.clawbackConfirm !== undefined ? { clawbackConfirm: body.clawbackConfirm } : undefined))
      if (method === 'POST' && (x = m(/^\/jobs\/([0-9a-f]{16})\/chains\/(eth|sol|btc)\/tickets$/))) return reply(200, { ticket: await o.journal.ticket(x[1], x[2] as Chain, body.gen, body.txId) })
      if (method === 'POST' && (x = m(/^\/jobs\/([0-9a-f]{16})\/skip$/))) return reply(200, await o.journal.skip(x[1]))
      return reply(404, { error: { guard: 'api.route', message: 'no such route' } })
    } catch (e) {
      if (e instanceof JournalUnreachable) throw new TypeError('fetch failed (test: the reply was lost)')
      if (isRefusal(e)) return reply(httpStatusFor(e.guardId), { error: { guard: e.guardId, message: e.message } })
      return reply(500, { error: { guard: 'api.internal', message: 'internal' } })
    }
  }
  async function callRelay(method: string, path: string, body: any, ticket: string | null): Promise<Response> {
    if (method === 'GET' && path === '/relay/status') return reply(200, await o.relay.status())
    if (method === 'GET' && path === '/relay/tor') return reply(200, await o.relay.tor())
    if (method === 'GET' && path === '/relay/price') return reply(200, await o.relay.price())
    const x = /^\/relay\/(eth|sol)(?:\/ep\/(\d+))?$/.exec(path)
    if (method !== 'POST' || !x) return reply(403, { error: { message: 'forbidden' } })
    try {
      const result = await o.relay.rpc(x[1] as Chain, body.method, body.params, { ...(ticket !== null ? { ticket } : {}), ...(x[2] !== undefined ? { ep: Number(x[2]) } : {}) })
      return reply(200, { jsonrpc: '2.0', id: body.id, result })
    } catch (e) {
      if (e instanceof TransportError) return reply(502, { jsonrpc: '2.0', id: body.id, error: { code: -32099, message: e.message } })
      const rpc = (e as { rpc?: { code: number; message: string } }).rpc
      return reply(200, { jsonrpc: '2.0', id: body.id, error: rpc ?? { code: -32000, message: (e as Error).message } })
    }
  }
  const fetchFn = async (input: string, init: RequestInit = {}): Promise<Response> => {
    const u = new URL(input, page), method = (init.method ?? 'GET').toUpperCase()
    const headers = new Headers(init.headers ?? {})
    const body = typeof init.body === 'string' ? JSON.parse(init.body) : undefined
    seen.push(`${u.origin}${u.pathname}`)
    if (u.origin === page && u.pathname.startsWith('/api/')) {
      if (headers.has('authorization')) return reply(400, { error: { guard: 'api.args', message: 'the page never sends a token' } })
      return callApi(method, u.pathname.slice(4), body)
    }
    if (u.origin === api) {
      if (headers.get('authorization') !== `Bearer ${o.token}`) return reply(401, { error: { guard: 'api.token', message: 'token' } })
      return callApi(method, u.pathname, body)
    }
    if (u.origin === page || u.origin === relayBase) return callRelay(method, u.pathname, body, headers.get('x-vt-send-ticket'))
    throw new TypeError('fetch failed (test: not this stack)')
  }
  return { fetch: fetchFn, seen }
}
void Refusal

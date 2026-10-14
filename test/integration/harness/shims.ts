// test/integration/harness/shims.ts — the fetch shims of the E4 harness (not a test file; no heavy imports, so the
// sandboxed executor processes load it too). Node's fetch cannot set Host, the only reason for them.
//   · nodeShim — what the CLI executor's nodeClients reach (the fixed PORTS.local.api / .relay) → a stack's ephemeral
//     ports, with the Host the guards want; optional hooks: hold a request (before), drop an answer (after);
//   · pageShim — what the page's browserClients reach (its own origin http://127.0.0.1:5180) → the stack's page server,
//     with a browser's same-origin headers (Host, Origin on writes, Sec-Fetch-Site: same-origin).
import { request } from 'node:http'
import { Readable } from 'node:stream'
import { PORTS } from '../../../packages/core/src/contracts/index.ts'
import type { Chain } from '../../../packages/core/src/contracts/index.ts'

export type Fetch = (url: string, init?: RequestInit) => Promise<Response>
export interface Req { target: 'api' | 'relay' | 'page'; method: string; path: string; body: any }
export interface Hooks {
  // runs before the request leaves; may wait (a hold) — never mutates it
  before?: (r: Req) => Promise<void> | void
  // runs after the whole answer arrived; 'drop' makes the caller see a network failure (the answer was lost)
  after?: (r: Req, status: number, text: string) => Promise<'deliver' | 'drop'> | 'deliver' | 'drop'
}
// A crash point for an executor process: SIGKILL itself right before / right after the nth matching request (its journal
// event type, or 'send' for the relay's eth_sendRawTransaction / sendTransaction), counted per chain.
export interface Crash { at: 'before' | 'after'; what: string; nth: number; chain?: Chain }

interface Route { port: number; host: string; target: Req['target']; extra?: (method: string) => Record<string, string> }
function shim(route: (u: URL) => Route | null, hooks: Hooks | null): Fetch {
  return async (url, init) => {
    const u = new URL(url)
    const r = route(u)
    if (u.protocol !== 'http:' || u.hostname !== '127.0.0.1' || r === null) throw new TypeError('stack fetch: not a URL of this stack')
    const method = init?.method ?? 'GET'
    const headers: Record<string, string> = {}
    new Headers(init?.headers).forEach((v, k) => { headers[k] = v })
    Object.assign(headers, r.extra?.(method) ?? {})
    headers.host = r.host
    const body = init?.body === undefined || init.body === null ? null : Buffer.from(String(init.body))
    if (body !== null) headers['content-length'] = String(body.length)
    const signal = init?.signal ?? undefined
    if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
    const parsed = (() => { try { return body === null ? null : JSON.parse(body.toString('utf8')) } catch { return null } })()
    const req: Req = { target: r.target, method, path: `${u.pathname}${u.search}`, body: parsed }
    const sse = /\/events(\?|$)/.test(u.pathname) && method === 'GET'
    if (hooks?.before && !sse) await hooks.before(req)
    const res = await new Promise<import('node:http').IncomingMessage>((resolve, reject) => {
      const q = request({ host: '127.0.0.1', port: r.port, method, path: req.path, headers, setHost: false, ...(signal ? { signal } : {}) }, resolve)
      q.on('error', reject)
      q.end(body ?? undefined)
    })
    const h = new Headers()
    for (const [k, v] of Object.entries(res.headers)) { if (typeof v === 'string') h.set(k, v); else if (Array.isArray(v)) for (const x of v) h.append(k, x) }
    const status = res.statusCode ?? 500
    if (sse || !hooks?.after) return new Response(status === 204 || status === 304 ? null : (Readable.toWeb(res) as unknown as ReadableStream<Uint8Array>), { status, headers: h })
    const chunks: Buffer[] = []
    await new Promise<void>((resolve, reject) => { res.on('data', (d: Buffer) => chunks.push(d)); res.on('end', resolve); res.on('error', reject) })
    const text = Buffer.concat(chunks).toString('utf8')
    if ((await hooks.after(req, status, text)) === 'drop') throw new TypeError('fetch failed (the answer was lost: the harness dropped it)')
    return new Response(status === 204 || status === 304 ? null : text, { status, headers: h })
  }
}
// What nodeClients reach (fixed PORTS.local.api / .relay) → these ports, with the Host the guards want.
export function nodeShim(ports: { api: number; relay: number }, hooks: Hooks | null = null): Fetch {
  return shim((u) => {
    const p = Number(u.port)
    if (p === PORTS.local.api) return { port: ports.api, host: `127.0.0.1:${PORTS.local.api}`, target: 'api' }
    if (p === PORTS.local.relay) return { port: ports.relay, host: `127.0.0.1:${PORTS.local.relay}`, target: 'relay' }
    return null
  }, hooks)
}
// What the page reaches: its own origin (http://127.0.0.1:5180) → this page server, with a browser's same-origin headers.
export const PAGE_ORIGIN = `http://127.0.0.1:${PORTS.local.page}`
export function pageShim(port: () => number): Fetch {
  return shim((u) => (Number(u.port) === PORTS.local.page ? {
    port: port(), host: `127.0.0.1:${PORTS.local.page}`, target: 'page',
    extra: (method) => ({ 'sec-fetch-site': 'same-origin', ...(method === 'GET' || method === 'HEAD' ? {} : { origin: PAGE_ORIGIN }) }),
  } : null), null)
}


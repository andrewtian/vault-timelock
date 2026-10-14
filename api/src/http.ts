// api/src/http.ts — the guards every request passes (spec §5.1, fail closed), the capped JSON body reader and the
// reply helpers. Error replies are { error: { guard, message } } with the contracts' status (httpStatusFor) and a
// fixed message: nothing from the request is ever echoed (headers, path, query or body).
//
// Order (spec §5.1 table): Host → Origin → Sec-Fetch-Site → token → content type; then, for a POST, the body (≤ 64 KiB,
// one JSON value). A header that appears more than once counts as wrong (the HTTP parser would keep only one of them).
import type { IncomingMessage, ServerResponse } from 'node:http'
import { API_JSON_CAP, JSON_CONTENT_TYPE, PORTS, httpStatusFor, isRefusal } from '@vault-timelock/core/contracts'
import type { ApiError, Network } from '@vault-timelock/core/contracts'
import { refuse } from 'vt-broadcast/src/guard.ts'
import { assertToken } from './auth.ts'

export interface GuardOptions { network: Network; token: string; pagePort: number; devPort: number | null }

// The value of a header sent exactly once; undefined when absent; null when repeated.
export function single(req: IncomingMessage, name: string): string | undefined | null {
  let found: string | undefined
  const raw = req.rawHeaders
  for (let i = 0; i < raw.length; i += 2) {
    if (raw[i].toLowerCase() !== name) continue
    if (found !== undefined) return null
    found = raw[i + 1]
  }
  return found
}

const JSON_TYPE = /^application\/json(?:[ \t]*;[ \t]*charset=(?:utf-8|"utf-8"))?$/i
const TEXT_TYPE = /^text\/plain(?:[ \t]*;[ \t]*charset=(?:utf-8|"utf-8"))?$/i

function declaresBody(req: IncomingMessage): boolean {
  const len = single(req, 'content-length')
  return single(req, 'transfer-encoding') !== undefined || (len !== undefined && len !== '0')
}

export function guardRequest(req: IncomingMessage, o: GuardOptions): void {
  const host = single(req, 'host')
  const hostOk = host === `127.0.0.1:${PORTS[o.network].api}`
  if (!hostOk) refuse('api.host', 'requests must be addressed to this API on its own loopback port') // @guard:api.host
  const origin = single(req, 'origin')
  const origins = [`http://127.0.0.1:${o.pagePort}`, ...(o.devPort === null ? [] : [`http://127.0.0.1:${o.devPort}`])]
  const originOk = origin === undefined || (typeof origin === 'string' && origins.includes(origin))
  if (!originOk) refuse('api.origin', "only this network's own page may call the API") // @guard:api.origin
  const site = single(req, 'sec-fetch-site')
  const siteOk = site === undefined || site === 'same-origin' || site === 'none'
  if (!siteOk) refuse('api.fetch-site', 'cross-site and same-site requests are refused') // @guard:api.fetch-site
  const auth = single(req, 'authorization')
  assertToken(auth ?? undefined, o.token)
  const type = single(req, 'content-type')
  const typeOk = req.method === 'POST' ? typeof type === 'string' && JSON_TYPE.test(type)
    : req.method === 'PUT' ? typeof type === 'string' && TEXT_TYPE.test(type)
      : !declaresBody(req)
  if (!typeOk) refuse('api.content-type', 'POST bodies must be application/json (message uploads text/plain; charset=utf-8)') // @guard:api.content-type
}

// The single api.json refusal (a body that is not JSON, and a JSON body that is not the shape the endpoint takes).
export function assertJson(ok: boolean): asserts ok {
  if (!ok) refuse('api.json', 'the request body is not one JSON value of the shape this endpoint takes') // @guard:api.json
}

// The body, or null as soon as it exceeds `cap` (the rest is discarded unread).
function readCapped(req: IncomingMessage, cap: number): Promise<Buffer | null> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let n = 0
    let done = false
    const onData = (c: Buffer): void => {
      if (done) return
      n += c.length
      if (n > cap) {
        done = true
        req.off('data', onData)
        req.resume()
        resolve(null)
        return
      }
      chunks.push(c)
    }
    req.on('data', onData)
    req.on('end', () => { if (!done) { done = true; resolve(Buffer.concat(chunks)) } })
    req.on('error', (e) => { if (!done) { done = true; reject(e) } })
    req.on('close', () => { if (!done) { done = true; reject(new Error('request aborted')) } })
  })
}

const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

export async function readJson(req: IncomingMessage, cap: number = API_JSON_CAP): Promise<unknown> {
  const declared = single(req, 'content-length')
  const declaredOk = declared === undefined || (typeof declared === 'string' && /^[0-9]{1,15}$/.test(declared) && Number(declared) <= cap)
  const body = declaredOk ? await readCapped(req, cap) : null
  if (body === null) refuse('api.body-cap', 'the request body is larger than the 64 KiB cap') // @guard:api.body-cap
  let value: unknown
  let ok = true
  try { value = JSON.parse(UTF8.decode(body)) } catch { ok = false }
  assertJson(ok)
  return value
}

export function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const text = JSON.stringify(body)
  res.writeHead(status, {
    'content-type': JSON_CONTENT_TYPE, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff',
    'content-length': String(Buffer.byteLength(text)), ...extra,
  })
  res.end(text)
}

// The reply for a thrown value: a Refusal maps to its guard and the contracts' status; anything else is a 500
// api.internal that never carries details.
export function errorReply(e: unknown): { status: number; body: ApiError } {
  if (isRefusal(e)) return { status: httpStatusFor(e.guardId), body: { error: { guard: e.guardId, message: e.message } } }
  return { status: 500, body: { error: { guard: 'api.internal', message: 'internal error' } } }
}

export function sendError(req: IncomingMessage, res: ServerResponse, e: unknown): string {
  const r = errorReply(e)
  if (!res.headersSent) sendJson(res, r.status, r.body, req.complete ? {} : { connection: 'close' })
  else res.destroy()
  return r.body.error.guard
}

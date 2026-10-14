// ReplayTransport: a Transport (src/net/transport.ts) that answers from recorded fixtures.
// It matches on HTTP method + URL + body: for a JSON-RPC fixture, on the JSON-RPC method and params
// (the id is echoed back, so fixtures don't depend on call order); otherwise on the exact body.
// Each fixture answers once. An UNMATCHED request throws a Refusal('replay.unmatched'), which the
// net layer passes through unchanged, so a test can't mistake a missing fixture for tor.unreachable.
// Fixtures are JSON files under test/fixtures/<svc>/<case>.json.
import { readFileSync } from 'node:fs'
import { isDeepStrictEqual } from 'node:util'
import { Refusal } from '../../src/guard.ts'
import type { Transport, TransportRequest, TransportResponse } from '../../src/net/transport.ts'

export interface Fixture {
  readonly request: {
    readonly method: string
    readonly url: string
    readonly rpc?: { readonly method: string; readonly params?: unknown }
    readonly body?: string
  }
  readonly response: {
    readonly status: number
    readonly headers?: Readonly<Record<string, string>>
    readonly body?: string
    readonly rpc?: { readonly result?: unknown; readonly error?: unknown }
  }
}

export type Replay = Transport & {
  readonly requests: readonly TransportRequest[]
  readonly unmatched: readonly string[]
  remaining(): number
}

const NAME = /^[a-z0-9][a-z0-9-]*$/
const DIR = new URL('../fixtures/', import.meta.url)

export function loadFixture(svc: string, name: string): Fixture {
  if (!NAME.test(svc) || !NAME.test(name)) throw new Error('bad fixture name')
  return JSON.parse(readFileSync(new URL(`${svc}/${name}.json`, DIR), 'utf8')) as Fixture
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function matches(f: Fixture, req: TransportRequest, text: string, rpc: unknown): boolean {
  if (f.request.method !== req.method || f.request.url !== req.url) return false
  if (f.request.rpc !== undefined) {
    return isRecord(rpc) && rpc.jsonrpc === '2.0' && Number.isSafeInteger(rpc.id)
      && rpc.method === f.request.rpc.method
      && isDeepStrictEqual(rpc.params ?? [], f.request.rpc.params ?? [])
  }
  if (f.request.body !== undefined) return text === f.request.body
  return req.body === null || req.body.length === 0
}

function respond(r: Fixture['response'], rpc: unknown): TransportResponse {
  const body = r.rpc !== undefined
    ? Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: isRecord(rpc) ? rpc.id : null, ...r.rpc }), 'utf8')
    : Buffer.from(r.body ?? '', 'utf8')
  return { status: r.status, headers: { ...(r.headers ?? {}) }, body: new Uint8Array(body) }
}

export function ReplayTransport(fixtures: readonly Fixture[]): Replay {
  const used = fixtures.map(() => false)
  const requests: TransportRequest[] = []
  const unmatched: string[] = []
  const t: Transport = async (req) => {
    requests.push(req)
    const text = req.body === null ? '' : new TextDecoder().decode(req.body)
    let rpc: unknown = null
    try { rpc = text === '' ? null : JSON.parse(text) } catch { rpc = null }
    const i = fixtures.findIndex((f, k) => !used[k] && matches(f, req, text, rpc))
    if (i < 0) {
      unmatched.push(`${req.method} ${req.url}`)
      throw new Refusal('replay.unmatched', `no fixture for ${req.method} ${req.url}`)
    }
    used[i] = true
    return respond(fixtures[i].response, rpc)
  }
  return Object.assign(t, { requests, unmatched, remaining: () => used.filter((u) => !u).length })
}

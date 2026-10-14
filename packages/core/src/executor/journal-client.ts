// packages/core/src/executor/journal-client.ts — the executor's HTTP client of the jobs API (spec §5.2), for both
// executors: the page uses base '/api' with no token (its page server injects it); the CLI uses
// http://127.0.0.1:<api port> and the token it read from $VT_HOME/<network>/api.token. The token travels only in the
// Authorization header and is never logged or echoed.
//   · An API refusal ({ error: { guard, message } }) is thrown as a Refusal with that guard id: definitive, nothing done.
//   · No definitive answer (the API unreachable, a reply without a guard, a broken body) is JournalUnreachable: the
//     request may or may not have been applied. For an intent the caller asks POST …/tickets (never a new intent).
//   · A message is fetched as bytes and its sha256 must equal the path (message.digest) and decode as strict UTF-8.
import { GUARD_ID, Refusal, refuse } from '../contracts/index.ts'
import type { Chain, ClawbackConfirm, Holder, JobDef, JobState, JournalClient, JournalEvent, LeaseGrant, Status } from '../contracts/index.ts'
import { sha256Hex } from '../job/canonical.ts'

export class JournalUnreachable extends Error {
  constructor(m: string) { super(m); this.name = 'JournalUnreachable' }
}
export type Fetch = (url: string, init?: RequestInit) => Promise<Response>

const ID = /^[0-9a-f]{16}$/, SHA = /^[0-9a-f]{64}$/, TOKEN = /^[0-9a-f]{64}$/
const chainOk = (c: unknown): c is Chain => c === 'eth' || c === 'sol' || c === 'btc'
const short = (e: unknown): string => String((e as Error)?.message ?? e).replace(/\s+/g, ' ').slice(0, 120)

function path(kind: 'id' | 'sha', v: unknown): string {
  const ok = typeof v === 'string' && (kind === 'id' ? ID : SHA).test(v)
  if (!ok) throw new TypeError(`journal client: a malformed ${kind === 'id' ? 'job id' : 'sha256'}`)
  return v as string
}
function chainPath(c: unknown): Chain {
  if (!chainOk(c)) throw new TypeError('journal client: chain must be eth, sol or btc')
  return c
}

export function httpJournalClient(o: { base: string; fetch: Fetch; token?: string }): JournalClient {
  if (typeof o?.base !== 'string' || typeof o.fetch !== 'function') throw new TypeError('httpJournalClient: { base, fetch } required')
  if (o.token !== undefined && !(typeof o.token === 'string' && TOKEN.test(o.token))) throw new TypeError('httpJournalClient: the API token must be 64 hex characters')
  const auth: Record<string, string> = o.token === undefined ? {} : { authorization: `Bearer ${o.token}` }

  async function request(method: 'GET' | 'POST', p: string, body?: unknown): Promise<Response> {
    let r: Response
    try {
      r = await o.fetch(`${o.base}${p}`, { method, cache: 'no-store', headers: { ...auth, ...(body === undefined ? {} : { 'content-type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) })
    } catch (e) { throw new JournalUnreachable(`the jobs API did not answer (${short(e)})`) }
    if (r.ok) return r
    const j = await r.json().catch(() => null) as { error?: { guard?: unknown; message?: unknown } } | null
    const g = j?.error?.guard
    if (typeof g === 'string' && GUARD_ID.test(g)) throw new Refusal(g, String(j?.error?.message ?? '').slice(0, 300))
    throw new JournalUnreachable(`the jobs API answered HTTP ${r.status} without a refusal`)
  }
  async function json<T>(method: 'GET' | 'POST', p: string, body?: unknown): Promise<T> {
    const r = await request(method, p, body)
    try { return await r.json() as T } catch { throw new JournalUnreachable('the jobs API answered without JSON') }
  }

  return {
    status: () => json<Status>('GET', '/status'),
    async job(id) {
      const j = await json<{ def: JobDef; state: JobState; seq: number; serverNowMs: number }>('GET', `/jobs/${path('id', id)}`)
      return { def: j.def, state: j.state, seq: j.seq, serverNowMs: j.serverNowMs }
    },
    async message(sha) {
      const r = await request('GET', `/messages/${path('sha', sha)}`)
      let bytes: Uint8Array
      try { bytes = new Uint8Array(await r.arrayBuffer()) } catch { throw new JournalUnreachable('the message body was cut') }
      const same = sha256Hex(bytes) === sha
      if (!same) refuse('message.digest', 'the message the API sent does not hash to its digest') // @guard:message.digest
      return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)
    },
    lease: (id: string, chain: Chain, op: 'acquire' | 'renew' | 'release', holder: Holder, gen?: number) =>
      json<LeaseGrant>('POST', `/jobs/${path('id', id)}/chains/${chainPath(chain)}/lease`, { op, holder, ...(gen === undefined ? {} : { gen }) }),
    append: (id: string, chain: Chain, gen: number, type: string, data: Record<string, unknown>, x?: { clawbackConfirm?: ClawbackConfirm }) =>
      json<{ seq: number; ticket?: string }>('POST', `/jobs/${path('id', id)}/chains/${chainPath(chain)}/events`,
        { gen, type, data, ...(x?.clawbackConfirm !== undefined && type === 'clawback-intent' ? { clawbackConfirm: x.clawbackConfirm } : {}) }),
    async ticket(id, chain, gen, txId) {
      const j = await json<{ ticket?: unknown }>('POST', `/jobs/${path('id', id)}/chains/${chainPath(chain)}/tickets`, { gen, txId })
      if (typeof j.ticket !== 'string') throw new JournalUnreachable('the jobs API answered a ticket request without a ticket')
      return j.ticket
    },
    skip: (id) => json<{ releaseAt: number }>('POST', `/jobs/${path('id', id)}/skip`, {}),
    stream(id, from, on) {
      // SSE over fetch (Last-Event-ID on reconnect, seq de-duplicated); stops on a refusal (4xx) or when unsubscribed
      const ctl = new AbortController()
      let last = from - 1, stopped = false
      const run = async (): Promise<void> => {
        for (let tries = 0; !stopped && tries < 1000; tries++) {
          try {
            const r = await o.fetch(`${o.base}/jobs/${path('id', id)}/events?from=${last + 1}`, { method: 'GET', cache: 'no-store', signal: ctl.signal, headers: { ...auth, ...(last >= 0 ? { 'last-event-id': String(last) } : {}) } })
            if (r.status >= 400 && r.status < 500) return
            if (!r.ok || r.body === null) { await new Promise((ok) => setTimeout(ok, 500)); continue }
            const reader = r.body.pipeThrough(new TextDecoderStream()).getReader()
            let buf = ''
            for (;;) {
              const { value, done } = await reader.read()
              if (done) break
              buf += value
              let i: number
              while ((i = buf.indexOf('\n\n')) >= 0) {
                const frame = buf.slice(0, i); buf = buf.slice(i + 2)
                const data = frame.split('\n').filter((l) => l.startsWith('data: ')).map((l) => l.slice(6)).join('\n')
                if (data === '') continue
                let e: JournalEvent
                try { e = JSON.parse(data) as JournalEvent } catch { continue }
                if (typeof e.seq === 'number' && e.seq > last) { last = e.seq; on(e) }
              }
            }
          } catch { if (stopped) return; await new Promise((ok) => setTimeout(ok, 500)) }
        }
      }
      void run()
      return () => { stopped = true; ctl.abort() }
    },
  }
}

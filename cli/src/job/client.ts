// cli/src/job/client.ts — the `vt job …` client of a network's jobs API (canonical vt spec §5.2, §8; plan Task C5).
// The client commands run inside loopbackProfile([page, relay, api]) of their network (bin/vt; `job arm` and
// `job resolve` also get /dev/tty for the typed word): loopback ports only, no file writes. Reads are allowed (the job
// file, its message file, $VT_HOME/<network>/api.token).
//
// Requests (spec §5.1): to 127.0.0.1:<api port>, Host exactly `127.0.0.1:<port>`, `Authorization: Bearer <api.token>`,
// no Origin, no Sec-Fetch-Site, no cookies. POST bodies are `application/json` (≤ 64 KiB: POST /jobs carries the
// canonical definition, never the text); a message is uploaded with PUT /messages/<sha256> as `text/plain;
// charset=utf-8`, its exact bytes. The token travels only in that header; it is never printed or put in argv.
//
// Answers:
//   · 2xx                      the JSON body (and its exact text, for --json);
//   · { error: { guard, … } }  a Refusal with that guard id (`refused <guard>: <message>`, exit 2). The message is
//                              the API's own text, capped and passed through C4's printer (renderLogLine: control
//                              sequences stripped, any address redacted) before it can reach the terminal;
//   · anything else            an Error with a fixed text (exit 1): the API did not answer, or answered without a
//                              refusal. A transport error's own text (which can name an address) is never shown.
//
// ★ Output. Every line a job command prints goes through printLines (C4's renderLogLine: terminal controls removed,
//   every IP literal redacted, a line that still fails the checks held back). --json prints the API's body EXACTLY as
//   it arrived (so it is the contract shape byte for byte), after the same two checks (assertNoControl,
//   assertNoAddress) on the whole text: a body that fails is not printed at all (fail closed, refusal vt.log-control
//   or vt.log-ip).
import type { Chain, Network } from '@vault-timelock/core/contracts'
import { GUARD_ID, NETWORKS, Refusal, refuse } from '@vault-timelock/core/contracts'
import { request } from 'node:http'
import { join } from 'node:path'
import { UsageError } from '../args.ts'
import { assertNoAddress, assertNoControl, renderLogLine } from '../ops/logs.ts'
import type { Env } from '../ops/paths.ts'
import type { WordKind } from './tty.ts'
import { stateDir, vtHome } from '../ops/paths.ts'
import { readSmallFile } from '../ops/stack.ts'

export interface Ports { page: number; relay: number; api: number }

// What a job command needs from the outside world (main.ts passes the real ones; tests pass their own).
export interface JobIo {
  network: Network
  env: Env
  cwd: string                                             // resolves a relative --message-file
  ports: Ports
  out(text: string): void                                 // stdout, raw (callers print through printLines / emitJson)
  err(text: string): void                                 // stderr, raw
  ask(prompt: string, kind?: WordKind): Promise<string | undefined>        // a typed word from the TERMINAL only (readTypedWord); undefined: no terminal
  now(): number
  signal?: AbortSignal                                    // watch: stop following (Ctrl-C)
}

const enc = new TextEncoder()

// One line of output text -> what may be printed (C4's printer). Never throws.
export const safeLine = (line: string): string => renderLogLine(enc.encode(line))

// Prints text line by line through the printer (to stdout, or stderr with toErr).
export function printLines(io: JobIo, text: string, toErr = false): void {
  const lines = text.split('\n')
  if (lines[lines.length - 1] === '') lines.pop()
  const safe = lines.map(safeLine).join('\n') + '\n'
  if (toErr) io.err(safe)
  else io.out(safe)
}

// --json: the body exactly as the API sent it, after the printer's two checks over the whole text (fail closed).
export function emitJson(io: JobIo, text: string): void {
  assertNoControl(text)
  assertNoAddress(text)
  io.out(text.endsWith('\n') ? text : `${text}\n`)
}

// A typed confirmation needs the terminal (readTypedWord answers undefined without one): the one vt.tty-required marker
// of this workspace (job arm, job resolve).
export function assertTerminal(ok: boolean, why: string): void {
  if (!ok) refuse('vt.tty-required', why) // @guard:vt.tty-required
}

// ---- argument shapes (usage errors never echo the value)

const JOB_ID = /^[0-9a-f]{16}$/
export function jobIdArg(v: string | undefined, usage: string): string {
  if (v === undefined || !JOB_ID.test(v)) throw new UsageError(`${usage} (a job id is 16 lowercase hex characters; vt job list shows them)`)
  return v
}
export function chainArg(v: string | undefined, usage: string): Chain {
  if (v !== 'eth' && v !== 'sol' && v !== 'btc') throw new UsageError(`${usage} (a chain is eth, sol or btc)`)
  return v
}

// Splits args into flags (each flag once) and positionals. `valued` flags take the next argument.
export function parseFlags(args: readonly string[], o: { valued: readonly string[]; bool: readonly string[]; usage: string }): { flags: Map<string, string | true>; pos: string[] } {
  const flags = new Map<string, string | true>()
  const pos: string[] = []
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a.startsWith('--')) {
      const known = o.valued.includes(a) || o.bool.includes(a)
      if (!known || flags.has(a)) throw new UsageError(o.usage)
      if (o.valued.includes(a)) {
        const v = args[i + 1]
        if (v === undefined || v.startsWith('--')) throw new UsageError(o.usage)
        flags.set(a, v)
        i++
      } else flags.set(a, true)
    } else pos.push(a)
  }
  return { flags, pos }
}

// ---- the API token

const TOKEN = /^[0-9a-f]{64}$/
// $VT_HOME/<network>/api.token: a private regular file (never through a symlink) holding exactly 64 lowercase hex (one
// trailing newline allowed), as `vt up` writes it. Never printed.
export function readApiToken(env: Env, n: Network): string {
  const text = readSmallFile(join(stateDir(vtHome(env), n), 'api.token'), { cap: 4096, privateOnly: true, whole: true })
  const v = text === null ? null : text.endsWith('\n') ? text.slice(0, -1) : text
  if (v === null || !TOKEN.test(v)) throw new Error(`no readable API token for ${n}: is the ${n} stack up? (vt up --network ${n})`)
  return v
}

// ---- HTTP

export interface Reply { status: number; body: Buffer }
const TIMEOUT_MS = 60_000
const JSON_CAP = 64 * 1024 * 1024

// One request to 127.0.0.1:<port>. null: no answer (refused, reset, timed out, over the cap). The transport error's
// own text is dropped on purpose: it can name an address.
export function httpCall(port: number, method: string, path: string, headers: Readonly<Record<string, string>>, body?: Uint8Array, o: { cap?: number; timeoutMs?: number } = {}): Promise<Reply | null> {
  const cap = o.cap ?? JSON_CAP
  return new Promise<Reply | null>((resolve) => {
    let done = false
    const finish = (v: Reply | null): void => { if (!done) { done = true; clearTimeout(timer); resolve(v) } }
    const h: Record<string, string> = { ...headers, host: `127.0.0.1:${port}` }
    if (body !== undefined) h['content-length'] = String(body.length)
    const req = request({ host: '127.0.0.1', port, path, method, agent: false, headers: h }, (res) => {
      const chunks: Buffer[] = []
      let n = 0
      res.on('data', (c: Buffer) => {
        n += c.length
        if (n > cap) { req.destroy(); finish(null) } else chunks.push(c)
      })
      res.on('end', () => finish({ status: res.statusCode ?? 0, body: Buffer.concat(chunks) }))
      res.on('error', () => finish(null))
    })
    const timer = setTimeout(() => { req.destroy(); finish(null) }, o.timeoutMs ?? TIMEOUT_MS)
    req.on('error', () => finish(null))
    req.end(body === undefined ? undefined : Buffer.from(body.buffer, body.byteOffset, body.byteLength))
  })
}

// An API refusal as the CLI shows it: the guard id (checked), the API's message capped and passed through the printer.
export function refusalFrom(guard: string, message: unknown): Refusal {
  return new Refusal(guard, safeLine(String(message ?? '').replace(/\s+/g, ' ').slice(0, 300)))
}

export interface ApiClient {
  readonly network: Network
  readonly port: number
  // JSON request: { value, text } of a 2xx answer; a refusal or an Error otherwise.
  json<T = unknown>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<{ value: T; text: string; status: number }>
  // PUT /messages/<sha256> with these exact bytes.
  putMessage(sha256: string, bytes: Uint8Array): Promise<{ value: unknown; text: string; status: number }>
  // GET /messages/<sha256>: the bytes.
  getMessage(sha256: string): Promise<Uint8Array>
  // SSE (GET /jobs/<id>/events): see stream() below.
  stream(id: string, from: number, onEvent: (line: string, event: Record<string, unknown>) => boolean | void, signal?: AbortSignal): Promise<void>
}

export function apiClient(io: JobIo, o: { token?: string } = {}): ApiClient {
  const n = io.network
  if (!(NETWORKS as readonly string[]).includes(n)) throw new UsageError('unknown network')
  const port = io.ports.api
  const token = o.token ?? readApiToken(io.env, n)
  const auth = { authorization: `Bearer ${token}` }
  // A request that got no answer may still have been applied (a change: check `vt job status` before repeating it).
  const unreachable = (method: string): Error => new Error(`the ${n} jobs API (port ${port}) did not answer: is the ${n} stack up? (vt status --network ${n})${method === 'GET' ? '' : '; the change may or may not have been applied: vt job status shows it'}`)

  function answer(r: Reply | null, method: string): { value: unknown; text: string; status: number } {
    if (r === null) throw unreachable(method)
    const text = r.body.toString('utf8')
    let value: unknown
    try { value = JSON.parse(text) } catch { value = undefined }
    if (r.status >= 200 && r.status < 300) {
      if (value === undefined) throw new Error(`the ${n} jobs API answered without JSON`)
      return { value, text, status: r.status }
    }
    const e = (value as { error?: { guard?: unknown; message?: unknown } } | undefined)?.error
    if (typeof e?.guard === 'string' && GUARD_ID.test(e.guard)) throw refusalFrom(e.guard, e.message)
    throw new Error(`the ${n} jobs API answered HTTP ${Number.isInteger(r.status) ? r.status : '?'} without a refusal`)
  }

  return {
    network: n,
    port,
    async json<T>(method: 'GET' | 'POST', path: string, body?: unknown) {
      const bytes = body === undefined ? undefined : enc.encode(JSON.stringify(body))
      const headers = { ...auth, ...(bytes === undefined ? {} : { 'content-type': 'application/json' }) }
      const r = answer(await httpCall(port, method, path, headers, bytes), method)
      return r as { value: T; text: string; status: number }
    },
    async putMessage(sha256, bytes) {
      return answer(await httpCall(port, 'PUT', `/messages/${sha256}`, { ...auth, 'content-type': 'text/plain; charset=utf-8' }, bytes, { timeoutMs: 300_000 }), 'PUT')
    },
    async getMessage(sha256) {
      const r = await httpCall(port, 'GET', `/messages/${sha256}`, auth, undefined, { cap: 17 * 1024 * 1024 })
      if (r !== null && r.status === 200) return new Uint8Array(r.body)
      answer(r, 'GET') // throws: a refusal, or no answer
      throw unreachable('GET')
    },
    stream: (id, from, onEvent, signal) => followEvents(io, port, auth, id, from, onEvent, signal),
  }
}

// ---- SSE (spec §5.2): GET /jobs/<id>/events?from=<seq>, `id: <seq>` + `data: <journal line>` frames, `: hb` comments.
// Each event is delivered once, in seq order (a seq at or below the last one delivered is dropped). When the stream
// ends or stalls (no byte for STALL_MS; the API sends a heartbeat every 15 s), it reconnects with
// `Last-Event-ID: <last seq>` (and ?from=<last + 1>), backing off up to 5 s, until the signal aborts or onEvent returns
// true. An API refusal (e.g. job.missing) ends it with that refusal.
const STALL_MS = 45_000
const FRAME_CAP = 8 * 1024 * 1024

function followEvents(io: JobIo, port: number, auth: Readonly<Record<string, string>>, id: string, from: number,
  onEvent: (line: string, event: Record<string, unknown>) => boolean | void, signal?: AbortSignal): Promise<void> {
  let last = from - 1
  let finished = false
  let warned = false
  return new Promise<void>((resolve, reject) => {
    let backoff = 250
    let current: ReturnType<typeof request> | null = null
    let retry: NodeJS.Timeout | null = null
    const end = (e?: unknown): void => {
      if (finished) return
      finished = true
      if (retry !== null) clearTimeout(retry)
      current?.destroy()
      signal?.removeEventListener('abort', onAbort)
      if (e === undefined) resolve()
      else reject(e)
    }
    const onAbort = (): void => end()
    if (signal?.aborted === true) { end(); return }
    signal?.addEventListener('abort', onAbort)

    const again = (): void => {
      if (finished) return
      if (!warned) { warned = true; printLines(io, `watch: the ${io.network} jobs API stream was interrupted; reconnecting (Ctrl-C to stop)`, true) }
      retry = setTimeout(connect, backoff)
      backoff = Math.min(backoff * 2, 5_000)
    }
    const connect = (): void => {
      retry = null
      if (finished) return
      // One reconnect per connection, whichever of end / close / error comes first.
      let gone = false
      const lost = (): void => { if (!gone) { gone = true; again() } }
      const headers: Record<string, string> = { ...auth, host: `127.0.0.1:${port}`, accept: 'text/event-stream' }
      if (last >= 0) headers['last-event-id'] = String(last)
      const req = request({ host: '127.0.0.1', port, path: `/jobs/${id}/events?from=${last + 1}`, method: 'GET', agent: false, headers }, (res) => {
        const status = res.statusCode ?? 0
        if (status !== 200) {
          const chunks: Buffer[] = []
          res.on('data', (c: Buffer) => { if (chunks.length < 64) chunks.push(c) })
          res.on('end', () => {
            gone = true
            let v: unknown
            try { v = JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch { v = undefined }
            const e = (v as { error?: { guard?: unknown; message?: unknown } } | undefined)?.error
            if (status >= 400 && status < 500 && typeof e?.guard === 'string' && GUARD_ID.test(e.guard)) end(refusalFrom(e.guard, e.message))
            else if (status >= 400 && status < 500) end(new Error(`the ${io.network} jobs API refused the event stream (HTTP ${status})`))
            else again()
          })
          res.on('error', lost)
          return
        }
        let buf = ''
        let stall = setTimeout(() => req.destroy(), STALL_MS)
        res.setEncoding('utf8')
        res.on('data', (chunk: string) => {
          clearTimeout(stall)
          stall = setTimeout(() => req.destroy(), STALL_MS)
          buf += chunk
          if (buf.length > FRAME_CAP) { req.destroy(); return }
          let i: number
          while ((i = buf.indexOf('\n\n')) >= 0) {
            const frame = buf.slice(0, i)
            buf = buf.slice(i + 2)
            const data = frame.split('\n').filter((l) => l.startsWith('data: ')).map((l) => l.slice(6)).join('\n')
            if (data === '') continue // a heartbeat comment, or an empty frame
            let ev: unknown
            try { ev = JSON.parse(data) } catch { continue }
            const seq = (ev as { seq?: unknown } | null)?.seq
            if (ev === null || typeof ev !== 'object' || Array.isArray(ev) || typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq <= last) continue
            last = seq
            backoff = 250
            warned = false
            let stop: boolean | void
            try { stop = onEvent(data, ev as Record<string, unknown>) } catch (e) { clearTimeout(stall); end(e); return }
            if (stop === true) { clearTimeout(stall); end(); return }
          }
        })
        const closed = (): void => { clearTimeout(stall); lost() }
        res.on('end', closed)
        res.on('error', closed)
        res.on('close', closed)
      })
      current = req
      req.on('error', lost)
      req.end()
    }
    connect()
  })
}

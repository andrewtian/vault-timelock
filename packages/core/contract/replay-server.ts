// packages/core/contract/replay-server.ts — replays contract/fixtures/http/*.json over HTTP on 127.0.0.1 (test-only).
// Used by C5 (cli/test/job-client.test.ts) and W1 (Vite dev proxy with VT_REPLAY=1). Never a real API: no state beyond
// the `after` order, no guards beyond what each fixture states.
//
//   node packages/core/contract/replay-server.ts [--port <n>]   prints `vt-replay ready port=<p>` (default port 0)
//
// Fixture format (contract/fixtures/http/<name>.json):
//   { name, covers, after: <name> | null,
//     request: { method, path, headers: { <lowercase name>: <value> | null }, body? | bodyText? | bodyFill?: { char, length } },
//     response: { status, headers, body? | bodyText? | sse?: { journal: 'journals/<vector>.jsonl' } },
//     volatile: ['<dotted path in the response body>', …] }
// Placeholders in request header values: {{token}} (the API token), {{host}} (127.0.0.1:<port>), {{port}}.
// Matching (first by specificity): method and pathname equal (the query is ignored); every listed header equal (null:
// must be absent); a JSON body equal by canonical JSON, a bodyText equal, a bodyFill equal in length; `after` only once
// that fixture has been served. Specificity = (after ? 1000 : 0) + listed headers + (body constraint ? 1 : 0).
// No match: 501 {"error":{"guard":"replay.unmatched",…}}. SSE: journal lines with seq ≥ ?from= (or > Last-Event-ID),
// framed as sseFrame(seq, line), then a heartbeat every SSE_HEARTBEAT_MS until the client leaves. Resume as the API
// (api/src/sse.ts, CC-1): a well-formed Last-Event-ID (decimal, no sign or leading zero, at most 15 digits) wins and
// resumes at seq + 1; a malformed one is ignored. Otherwise ?from= given once and well-formed; otherwise 0. A malformed
// or repeated `from` is 400 api.args (as the API answers), and nothing is streamed.
// `volatile` lists response fields a real API may legitimately differ in (clock, generated tickets, error text):
// contract-http tests compare everything else exactly.
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Socket } from 'node:net'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { JSON_CONTENT_TYPE, SSE_HEARTBEAT_MS, httpStatusFor, sseFrame, sseHeartbeat } from '../src/contracts/index.ts'

export const FIXTURES_DIR = fileURLToPath(new URL('./fixtures/', import.meta.url))
// The token the replay server expects (synthetic; a real api.token is 64 random hex written by `vt up`).
export const REPLAY_TOKEN = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'

export interface HttpFixture {
  name: string; covers: string; after: string | null
  request: { method: string; path: string; headers: Record<string, string | null>; body?: unknown; bodyText?: string; bodyFill?: { char: string; length: number } }
  response: { status: number; headers: Record<string, string>; body?: unknown; bodyText?: string; sse?: { journal: string } }
  volatile: string[]
}

export function loadHttpFixtures(dir = FIXTURES_DIR): HttpFixture[] {
  return readdirSync(join(dir, 'http')).filter((f) => f.endsWith('.json')).sort()
    .map((f) => JSON.parse(readFileSync(join(dir, 'http', f), 'utf8')) as HttpFixture)
}

export function substitute(value: string, vars: { token: string; port: number }): string {
  return value.replaceAll('{{token}}', vars.token).replaceAll('{{host}}', `127.0.0.1:${vars.port}`).replaceAll('{{port}}', String(vars.port))
}

function canon(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`
  if (v !== null && typeof v === 'object') {
    const o = v as Record<string, unknown>
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canon(o[k])}`).join(',')}}`
  }
  return JSON.stringify(v)
}

// A sequence number in a query parameter or header, as the API parses it (api/src/args.ts parseSeq).
export const parseSeq = (v: string): number | null => /^(?:0|[1-9][0-9]{0,14})$/.test(v) ? Number(v) : null

export interface ReplayRequest { method: string; path: string; headers: Record<string, string | undefined>; body: Buffer }

export function matchFixture(fixtures: readonly HttpFixture[], req: ReplayRequest, served: ReadonlySet<string>, vars: { token: string; port: number }): HttpFixture | null {
  const pathname = req.path.split('?')[0]
  let best: HttpFixture | null = null, bestScore = -1
  for (const f of fixtures) {
    if (f.request.method !== req.method || f.request.path !== pathname) continue
    if (f.after !== null && !served.has(f.after)) continue
    let ok = true
    for (const [name, want] of Object.entries(f.request.headers)) {
      const got = req.headers[name]
      if (want === null ? got !== undefined : got !== substitute(want, vars)) { ok = false; break }
    }
    if (!ok) continue
    let bodyRule = 0
    if (f.request.body !== undefined) {
      bodyRule = 1
      try { if (canon(JSON.parse(req.body.toString('utf8'))) !== canon(f.request.body)) continue } catch { continue }
    } else if (f.request.bodyText !== undefined) {
      bodyRule = 1
      if (req.body.toString('utf8') !== f.request.bodyText) continue
    } else if (f.request.bodyFill !== undefined) {
      bodyRule = 1
      if (req.body.length !== f.request.bodyFill.length) continue
    }
    const score = (f.after !== null ? 1000 : 0) + Object.keys(f.request.headers).length + bodyRule
    if (score > bestScore) { best = f; bestScore = score }
  }
  return best
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let n = 0
    req.on('data', (c: Buffer) => { n += c.length; if (n <= 32 * 1024 * 1024) chunks.push(c) })
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

export interface ReplayServer { url: string; port: number; token: string; served: Set<string>; close(): Promise<void> }

export async function startReplayServer(o: { port?: number; token?: string; fixturesDir?: string; now?: () => number } = {}): Promise<ReplayServer> {
  const dir = o.fixturesDir ?? FIXTURES_DIR
  const fixtures = loadHttpFixtures(dir)
  const token = o.token ?? REPLAY_TOKEN
  const now = o.now ?? Date.now
  const served = new Set<string>()
  const sockets = new Set<Socket>()
  const timers = new Set<NodeJS.Timeout>()
  let port = 0

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const body = await readBody(req)
    const headers: Record<string, string | undefined> = {}
    for (const [k, v] of Object.entries(req.headers)) headers[k] = Array.isArray(v) ? v.join(', ') : v
    const f = matchFixture(fixtures, { method: req.method ?? '', path: req.url ?? '', headers, body }, served, { token, port })
    if (f === null) {
      res.writeHead(501, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
      res.end(JSON.stringify({ error: { guard: 'replay.unmatched', message: 'no fixture matches this request' } }))
      return
    }
    served.add(f.name)
    const r = f.response
    if (r.sse !== undefined) {
      const lines = readFileSync(join(dir, r.sse.journal), 'utf8').split('\n').filter((l) => l !== '')
      const url = new URL(req.url ?? '/', 'http://replay.invalid')
      const last = headers['last-event-id']
      const lastSeq = last !== undefined ? parseSeq(last) : null
      const fromArgs = url.searchParams.getAll('from')
      const fromSeq = fromArgs.length === 1 ? parseSeq(fromArgs[0]) : null
      if (lastSeq === null && fromArgs.length > 0 && fromSeq === null) {
        res.writeHead(httpStatusFor('api.args'), { 'content-type': JSON_CONTENT_TYPE, 'cache-control': 'no-store' })
        res.end(JSON.stringify({ error: { guard: 'api.args', message: 'invalid arguments: from must be one sequence number; the value is not echoed' } }))
        return
      }
      const from = lastSeq !== null ? lastSeq + 1 : fromSeq ?? 0
      res.writeHead(r.status, { ...r.headers, 'cache-control': 'no-store' })
      for (const line of lines) {
        const seq = (JSON.parse(line) as { seq: number }).seq
        if (seq >= from) res.write(sseFrame(seq, line))
      }
      const t = setInterval(() => res.write(sseHeartbeat(now())), SSE_HEARTBEAT_MS)
      timers.add(t)
      res.on('close', () => { clearInterval(t); timers.delete(t) })
      return
    }
    res.writeHead(r.status, { ...r.headers, 'cache-control': 'no-store' })
    res.end(r.bodyText !== undefined ? r.bodyText : JSON.stringify(r.body))
  }

  const server = createServer((req, res) => { handle(req, res).catch(() => { if (!res.headersSent) res.writeHead(500); res.end() }) })
  server.on('connection', (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)) })
  await new Promise<void>((resolve) => server.listen(o.port ?? 0, '127.0.0.1', resolve))
  port = (server.address() as { port: number }).port
  return {
    url: `http://127.0.0.1:${port}`, port, token, served,
    close: () => new Promise<void>((resolve) => {
      for (const t of timers) clearInterval(t)
      for (const s of sockets) s.destroy()
      server.close(() => resolve())
    }),
  }
}

if (import.meta.main) {
  const i = process.argv.indexOf('--port')
  const port = i >= 0 ? Number(process.argv[i + 1]) : 0
  if (!Number.isInteger(port) || port < 0 || port > 65535) { console.error('usage: node packages/core/contract/replay-server.ts [--port <0-65535>]'); process.exit(2) }
  const s = await startReplayServer({ port })
  console.log(`vt-replay ready port=${s.port}`)
}

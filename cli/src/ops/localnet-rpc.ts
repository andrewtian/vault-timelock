// cli/src/ops/localnet-rpc.ts — the few loopback HTTP calls `vt localnet` makes (LN1): JSON-RPC to anvil, the validator and
// bitcoind, a plain GET for ord and Otterscan, and a TCP "is something listening" probe.
// ★ Loopback only: the host is the literal 127.0.0.1, never configurable. The bitcoind credential line (`vt:<pass>`) is passed
//   in by the caller and goes only into the Authorization header: no error, reply summary or log line built here contains it.
import { request } from 'node:http'
import { spawnSync } from 'node:child_process'
import { connect } from 'node:net'

// Anything a server could reflect of the credential it was sent: the line, its Basic form, its password / cookie value, and their base64.
export function scrub(text: string, line: string | undefined): string {
  if (line === undefined || line === '') return text
  const secret = line.slice(line.indexOf(':') + 1)
  const b64 = Buffer.from(line, 'utf8').toString('base64')
  let out = text
  for (const needle of [`Basic ${b64}`, b64, line, Buffer.from(secret, 'utf8').toString('base64'), secret]) if (needle.length >= 8) out = out.split(needle).join('[redacted]')
  return out
}

export type RpcReply = { ok: true; result: unknown } | { ok: false; status: number; error: string }

const BODY_CAP = 1_000_000

// One JSON-RPC call. `line` (<user>:<pass>) adds HTTP Basic auth; `path` is e.g. /wallet/vt. Never throws.
export function jsonRpc(port: number, method: string, params: unknown, o: { line?: string; path?: string; timeoutMs?: number } = {}): Promise<RpcReply> {
  return new Promise<RpcReply>((resolve) => {
    let done = false
    const finish = (v: RpcReply): void => { if (!done) { done = true; clearTimeout(timer); resolve(v) } }
    const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 'vt', method, params }), 'utf8')
    const headers: Record<string, string> = { 'content-type': 'application/json', 'content-length': String(body.length), host: `127.0.0.1:${port}` }
    if (o.line !== undefined) headers.authorization = `Basic ${Buffer.from(o.line, 'utf8').toString('base64')}`
    const req = request({ host: '127.0.0.1', port, path: o.path ?? '/', method: 'POST', agent: false, headers }, (res) => {
      const chunks: Buffer[] = []
      let n = 0
      res.on('data', (c: Buffer) => {
        n += c.length
        if (n > BODY_CAP) { req.destroy(); finish({ ok: false, status: res.statusCode ?? 0, error: 'reply too large' }) } else chunks.push(c)
      })
      res.on('error', () => finish({ ok: false, status: res.statusCode ?? 0, error: 'connection error' }))
      res.on('end', () => {
        const status = res.statusCode ?? 0
        let j: unknown
        try { j = JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch { j = undefined }
        if (typeof j === 'object' && j !== null && !Array.isArray(j)) {
          const o2 = j as { result?: unknown; error?: unknown }
          if (o2.error !== undefined && o2.error !== null) {
            const m = typeof o2.error === 'object' ? (o2.error as { message?: unknown }).message : o2.error
            return finish({ ok: false, status, error: typeof m === 'string' ? scrub(m, o.line).slice(0, 200) : 'rpc error' })
          }
          if ('result' in o2) return finish({ ok: true, result: o2.result })
        }
        finish({ ok: false, status, error: status === 401 ? 'unauthorized' : `HTTP ${status}, not a JSON-RPC reply` })
      })
    })
    const timer = setTimeout(() => { req.destroy(); finish({ ok: false, status: 0, error: 'timeout' }) }, o.timeoutMs ?? 5_000)
    req.on('error', () => finish({ ok: false, status: 0, error: 'no answer' }))
    req.end(body)
  })
}

// GET http://127.0.0.1:<port><path>. null: no answer.
export function httpText(port: number, path: string, timeoutMs = 3_000, headers: Record<string, string> = {}): Promise<{ status: number; body: string } | null> {
  return new Promise((resolve) => {
    let done = false
    const finish = (v: { status: number; body: string } | null): void => { if (!done) { done = true; clearTimeout(timer); resolve(v) } }
    const req = request({ host: '127.0.0.1', port, path, method: 'GET', agent: false, headers: { ...headers, host: `127.0.0.1:${port}` } }, (res) => {
      const chunks: Buffer[] = []
      let n = 0
      res.on('data', (c: Buffer) => {
        n += c.length
        if (n > BODY_CAP) { req.destroy(); finish(null) } else chunks.push(c)
      })
      res.on('error', () => finish(null))
      res.on('end', () => finish({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }))
    })
    const timer = setTimeout(() => { req.destroy(); finish(null) }, timeoutMs)
    req.on('error', () => finish(null))
    req.end()
  })
}

// True when something accepts a TCP connection on 127.0.0.1:<port> (any protocol, any owner).
export function tcpOpen(port: number, timeoutMs = 1_000): Promise<boolean> {
  return new Promise((resolve) => {
    let done = false
    const finish = (v: boolean): void => { if (!done) { done = true; clearTimeout(timer); s.destroy(); resolve(v) } }
    const s = connect({ host: '127.0.0.1', port })
    const timer = setTimeout(() => finish(false), timeoutMs)
    s.on('connect', () => finish(true))
    s.on('error', () => finish(false))
  })
}

export const sleepMs = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

// The single pid listening on 127.0.0.1:<port> (pid-and-port-scoped lsof, nothing broader), else null.
export function listenerPidOf(port: number, env: Readonly<Record<string, string | undefined>>): number | null {
  const e: Record<string, string> = {}
  for (const [k, v] of Object.entries(env)) if (v !== undefined) e[k] = v
  const r = spawnSync('/usr/sbin/lsof', ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN', '-t'], { env: e, encoding: 'utf8', timeout: 10_000, stdio: ['ignore', 'pipe', 'ignore'] })
  const pids = [...new Set((r.stdout ?? '').split('\n').filter((l) => /^[0-9]+$/.test(l)).map(Number))]
  return r.status === 0 && pids.length === 1 ? pids[0] : null
}

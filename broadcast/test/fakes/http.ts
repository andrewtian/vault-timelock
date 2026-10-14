// A local fixture HTTP server for offline net tests (plain HTTP on 127.0.0.1, random port).
// The fake SOCKS5 server routes every CONNECT here; loopback tests reach it directly.
// Routes are fixed; bodies are synthetic. CANARY stands in for an IP that must never escape.
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import type { Socket } from 'node:net'

export const CANARY = '203.0.113.77'

export interface Hit {
  readonly method: string
  readonly url: string
  readonly headers: Readonly<Record<string, string | string[] | undefined>>
  readonly body: string
}

export interface FixtureHttp {
  readonly port: number
  readonly hits: readonly Hit[]
  close(): Promise<void>
}

function route(req: IncomingMessage, body: string, res: ServerResponse): void {
  const url = req.url ?? '/'
  let m: RegExpExecArray | null
  if (url === '/ok') {
    res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}')
  } else if (url === '/echo') {
    res.writeHead(200, { 'content-type': 'application/json' })
      .end(JSON.stringify({ method: req.method, url, headers: req.headers, body }))
  } else if ((m = /^\/redirect\/(\d{3})$/.exec(url)) !== null) {
    res.writeHead(Number(m[1]), { location: `https://elsewhere.example/${CANARY}` }).end(`moved; your ip is ${CANARY}`)
  } else if (url === '/status/500') {
    res.writeHead(500, { 'content-type': 'text/plain' }).end(`internal error for client ${CANARY}`)
  } else if (url === '/status/404') {
    res.writeHead(404, { 'content-type': 'application/json' }).end('{"error":"not found"}')
  } else if (url === '/not-json') {
    res.writeHead(200, { 'content-type': 'text/html' }).end(`${CANARY}<html>client ${CANARY}</html>`)
  } else if ((m = /^\/size\/(\d+)$/.exec(url)) !== null) {
    const n = Number(m[1])
    res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(n) })
    res.end(Buffer.alloc(n, 0x61))
  } else if ((m = /^\/chunked\/(\d+)$/.exec(url)) !== null) {
    // No content-length: the cap must be enforced while streaming.
    let left = Number(m[1])
    res.writeHead(200, { 'content-type': 'application/octet-stream' })
    const step = 1 << 20
    const pump = () => {
      while (left > 0) {
        const n = Math.min(step, left)
        left -= n
        if (!res.write(Buffer.alloc(n, 0x62))) { res.once('drain', pump); return }
      }
      res.end()
    }
    pump()
  } else if (url === '/hang') {
    // Never answer.
  } else if (url === '/hang-body') {
    res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '100' })
    res.write('partial')
  } else if (url === '/reset') {
    req.socket.destroy()
  } else if (url === '/rpc') {
    let id: unknown = null
    let method: unknown = null
    try { const j = JSON.parse(body); id = j.id; method = j.method } catch { /* fall through */ }
    const out = method === 'eth_chainId'
      ? { jsonrpc: '2.0', id, result: '0x7a69' }
      : { jsonrpc: '2.0', id, error: { code: -32000, message: `rate limited ${CANARY}`, data: CANARY } }
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(out))
  } else {
    res.writeHead(404).end()
  }
}

export async function startFixtureHttp(host = '127.0.0.1'): Promise<FixtureHttp> {
  const hits: Hit[] = []
  const sockets = new Set<Socket>()
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8')
      hits.push(Object.freeze({ method: req.method ?? '', url: req.url ?? '', headers: { ...req.headers }, body }))
      route(req, body, res)
    })
  })
  server.on('connection', (s: Socket) => {
    sockets.add(s)
    s.on('close', () => sockets.delete(s))
  })
  // A TLS ClientHello sent here (https through the fake SOCKS) is a client error; just drop it.
  server.on('clientError', (_e, s: Socket) => s.destroy())
  await new Promise<void>((res) => server.listen(0, host, () => res()))
  const addr = server.address()
  if (addr === null || typeof addr === 'string') throw new Error('fixture http: no port')
  return {
    port: addr.port,
    hits,
    close: () => new Promise<void>((res) => {
      for (const s of sockets) s.destroy()
      server.close(() => res())
    }),
  }
}

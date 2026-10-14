// A minimal REAL SOCKS5 server for offline tests (RFC 1928 + RFC 1929 username/password).
// It listens on 127.0.0.1 on a random port, records { user, password, atyp, host, port } per
// CONNECT, and routes every CONNECT to a local fixture server, whatever host was requested.
// It never resolves names and never connects anywhere but 127.0.0.1:<targetPort>.
import { connect, createServer, type Socket } from 'node:net'

export interface SocksRecord {
  readonly user: string | null
  readonly password: string | null
  readonly atyp: 'domain' | 'ipv4' | 'ipv6'
  readonly host: string
  readonly port: number
}

export interface FakeSocks {
  readonly port: number
  // One entry per CONNECT request that got as far as the request stage.
  readonly records: readonly SocksRecord[]
  // The METHODS list of every RFC 1928 greeting received, in order (the gate's probe offers [0, 2]).
  readonly greetings: readonly (readonly number[])[]
  // Raw TCP connections accepted (including ones that failed the handshake).
  connections(): number
  close(): Promise<void>
}

export interface FakeSocksOptions {
  readonly targetPort: number
  // Non-zero: answer every CONNECT with this RFC 1928 REP code (e.g. 4 = host unreachable).
  readonly reply?: number
  // Refuse username/password auth (answer the greeting with 0xFF, "no acceptable methods").
  readonly refuseAuth?: boolean
  // Pick "no authentication" (0x00) whenever it is offered, as a non-Tor proxy may: circuit
  // isolation by SOCKS username would then be silently lost (the gate's probe must refuse this).
  readonly pickNoAuth?: boolean
  // Never answer the CONNECT request (to exercise timeouts during the SOCKS stage).
  readonly hangOnConnect?: boolean
}

export async function startSocks5(o: FakeSocksOptions): Promise<FakeSocks> {
  const records: SocksRecord[] = []
  const greetings: (readonly number[])[] = []
  const sockets = new Set<Socket>()
  let accepted = 0

  const server = createServer((client) => {
    accepted++
    sockets.add(client)
    client.on('close', () => sockets.delete(client))
    client.on('error', () => { /* client went away */ })
    let buf = Buffer.alloc(0)
    let stage: 'greet' | 'auth' | 'request' | 'done' = 'greet'
    let user: string | null = null
    let password: string | null = null

    const onData = (d: Buffer) => {
      buf = Buffer.concat([buf, d])
      for (;;) {
        if (stage === 'greet') {
          if (buf.length < 2) return
          const n = buf[1]
          if (buf.length < 2 + n) return
          if (buf[0] !== 5) { client.destroy(); stage = 'done'; return }
          const methods = [...buf.subarray(2, 2 + n)]
          greetings.push(Object.freeze(methods))
          buf = buf.subarray(2 + n)
          if (o.refuseAuth) { client.end(Buffer.from([5, 0xff])); stage = 'done'; return }
          if (o.pickNoAuth && methods.includes(0)) {
            client.write(Buffer.from([5, 0]))
            stage = 'request'
            continue
          }
          if (!methods.includes(2)) { client.end(Buffer.from([5, 0xff])); stage = 'done'; return }
          client.write(Buffer.from([5, 2]))
          stage = 'auth'
          continue
        }
        if (stage === 'auth') {
          if (buf.length < 2) return
          const ulen = buf[1]
          if (buf.length < 3 + ulen) return
          const plen = buf[2 + ulen]
          if (buf.length < 3 + ulen + plen) return
          if (buf[0] !== 1) { client.destroy(); stage = 'done'; return }
          user = buf.subarray(2, 2 + ulen).toString('utf8')
          password = buf.subarray(3 + ulen, 3 + ulen + plen).toString('utf8')
          buf = buf.subarray(3 + ulen + plen)
          client.write(Buffer.from([1, 0]))
          stage = 'request'
          continue
        }
        if (stage === 'request') {
          if (buf.length < 5) return
          if (buf[0] !== 5 || buf[1] !== 1) { client.destroy(); stage = 'done'; return }
          const t = buf[3]
          let need: number
          if (t === 1) need = 4 + 4 + 2
          else if (t === 3) need = 4 + 1 + buf[4] + 2
          else if (t === 4) need = 4 + 16 + 2
          else { client.destroy(); stage = 'done'; return }
          if (buf.length < need) return
          let atyp: SocksRecord['atyp']
          let host: string
          if (t === 1) { atyp = 'ipv4'; host = [...buf.subarray(4, 8)].join('.') }
          else if (t === 3) { atyp = 'domain'; host = buf.subarray(5, 5 + buf[4]).toString('latin1') }
          else { atyp = 'ipv6'; host = buf.subarray(4, 20).toString('hex') }
          const port = buf.readUInt16BE(need - 2)
          records.push(Object.freeze({ user, password, atyp, host, port }))
          const rest = buf.subarray(need)
          buf = Buffer.alloc(0)
          stage = 'done'
          client.removeListener('data', onData)
          if (o.hangOnConnect) return
          if (o.reply !== undefined && o.reply !== 0) {
            client.end(Buffer.from([5, o.reply, 0, 1, 0, 0, 0, 0, 0, 0]))
            return
          }
          client.pause()
          const upstream = connect(o.targetPort, '127.0.0.1', () => {
            client.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
            if (rest.length > 0) upstream.write(rest)
            client.pipe(upstream)
            upstream.pipe(client)
            client.resume()
          })
          sockets.add(upstream)
          // A clean upstream close must NOT destroy the client: pipe() already ends it once the
          // buffered bytes are flushed; destroy() would truncate them under load.
          upstream.on('close', () => sockets.delete(upstream))
          upstream.on('error', () => client.destroy())
          client.on('close', () => upstream.destroy())
          return
        }
        return
      }
    }
    client.on('data', onData)
  })

  await new Promise<void>((res) => server.listen(0, '127.0.0.1', () => res()))
  const addr = server.address()
  if (addr === null || typeof addr === 'string') throw new Error('fake socks: no port')
  return {
    port: addr.port,
    records,
    greetings,
    connections: () => accepted,
    close: () => new Promise<void>((res) => {
      for (const s of sockets) s.destroy()
      server.close(() => res())
    }),
  }
}

// A port that was just free (listen on 0, then close). Used for "closed SOCKS port" tests.
export async function closedPort(): Promise<number> {
  const s = createServer()
  await new Promise<void>((res) => s.listen(0, '127.0.0.1', () => res()))
  const addr = s.address()
  if (addr === null || typeof addr === 'string') throw new Error('no port')
  await new Promise<void>((res) => s.close(() => res()))
  return addr.port
}

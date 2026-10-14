// RFC 1928 method-selection probe for the Tor gate (spec B s6.1 "Circuit isolation"; Task 7).
//
// Circuit isolation rests on Tor's IsolateSOCKSAuth: every role sends its own SOCKS username, so it
// gets its own circuit. That only holds if the SOCKS server actually negotiates username/password
// auth (method 0x02). The socks library under SocksProxyAgent offers both 0x00 (no auth) and 0x02,
// so a proxy on the port that picked 0x00 would silently put every role on one circuit. This probe
// offers exactly that pair, [0x00, 0x02], and reports which method the server picked; the gate
// refuses unless it is 0x02. It sends nothing past the greeting and closes, so it never opens a
// circuit. It lives in src/net/ because it is a raw socket (to the loopback SOCKS port only).
import { connect } from 'node:net'

// Tor's SOCKS host, for this probe and for the net layer's SOCKS agents (fetch.ts imports it).
export const SOCKS_HOST = '127.0.0.1'
// A local SOCKS server answers the greeting at once; this only bounds a wedged port.
const PROBE_TIMEOUT_MS = 5_000

// 'userpass': the server picked 0x02. 'other': it answered, with anything else (0x00, 0xFF,
// not SOCKS5). 'unreachable': no connection, an error, a timeout, or a close before 2 bytes.
export type ProbeResult = 'userpass' | 'other' | 'unreachable'

export function probeSocksAuth(port: number): Promise<ProbeResult> {
  return new Promise<ProbeResult>((resolve) => {
    let done = false
    let buf = Buffer.alloc(0)
    const s = connect({ host: SOCKS_HOST, port })
    const finish = (r: ProbeResult): void => {
      if (done) return
      done = true
      clearTimeout(timer)
      s.destroy()
      resolve(r)
    }
    const timer = setTimeout(() => finish('unreachable'), PROBE_TIMEOUT_MS)
    s.on('connect', () => { s.write(Buffer.from([0x05, 0x02, 0x00, 0x02])) })
    s.on('data', (d: Buffer) => {
      buf = Buffer.concat([buf, d])
      if (buf.length < 2) return
      finish(buf[0] === 0x05 && buf[1] === 0x02 ? 'userpass' : 'other')
    })
    s.on('error', () => finish('unreachable'))
    s.on('close', () => finish('unreachable'))
  })
}

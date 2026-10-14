// test/integration/stack.ts — a whole LOCAL vt stack for the cross-lane tests (I2; not a test file). Synthetic data only.
//
//   · this test's OWN anvil (interval mining, 1 s blocks) and solana-test-validator (--limit-ledger-size 50000000) on
//     free high loopback ports, each under a loopback-only sandbox, stopped by their recorded pids — never the shared
//     :8545 / :8899 / :8999;
//   · S4's REAL relay process (api/relay/relay.mjs) under C1's relayProfile('local', <our chain ports>), reaching our
//     chains through VT_TEST_ETH_RPC / VT_TEST_SOL_RPC, on an ephemeral port (--port 0, NODE_ENV=test), with the local
//     price fixture;
//   · S2's REAL jobs API process (api/src/main.ts) under C1's apiProfile(<state dir>) (no outbound at all, writes only
//     its state dir), on an ephemeral port, over a temp VT_HOME and a temp $OUT;
//   · stackFetch: what E3's node clients (nodeClients, fixed PORTS.local) reach — it maps 127.0.0.1:<api port> and
//     :<relay port> to the ephemeral ports and sends the Host header the guards require (127.0.0.1:5182 / :5181),
//     streaming bodies (SSE) and honouring aborts. Node's fetch cannot set Host, which is the only reason for the shim.
// No IP other than 127.0.0.1 is used or printed; no testnet or mainnet traffic (the local relay has no Tor upstream).
import { spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { createSocket } from 'node:dgram'
import { mkdirSync } from 'node:fs'
import { request } from 'node:http'
import { createServer as createTcpServer } from 'node:net'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { fileURLToPath } from 'node:url'
import { PORTS } from '../../packages/core/src/contracts/index.ts'
import { apiProfile, relayProfile } from '../../cli/src/ops/sandbox.ts'
import { TOKEN, makeHome, tempDir } from '../../api/test/helpers.ts'

export const REPO = fileURLToPath(new URL('../../', import.meta.url))
const RELAY = join(REPO, 'api/relay/relay.mjs')
const API_MAIN = join(REPO, 'api/src/main.ts')
const LOOPBACK_ONLY = '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))'
export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))
export type T = { after(fn: () => unknown): void }

// ---- free ports (TCP and UDP) on 127.0.0.1, far from every fixed port of the project and the shared chains

async function portFree(port: number): Promise<boolean> {
  const tcp = await new Promise<boolean>((resolve) => {
    const s = createTcpServer()
    s.once('error', () => resolve(false))
    s.listen(port, '127.0.0.1', () => s.close(() => resolve(true)))
  })
  if (!tcp) return false
  return new Promise<boolean>((resolve) => {
    const u = createSocket('udp4')
    u.once('error', () => { u.close(); resolve(false) })
    u.bind(port, '127.0.0.1', () => u.close(() => resolve(true)))
  })
}
export async function freeRun(n: number): Promise<number> {
  for (let tries = 0; tries < 60; tries++) {
    const base = 20_000 + 10 * Math.floor(Math.random() * 3_000)
    let ok = true
    for (let p = base; ok && p < base + n; p++) ok = await portFree(p)
    if (ok) return base
  }
  throw new Error('no run of free ports')
}

// ---- children, stopped by their recorded pid

export interface Child { proc: ChildProcess; lines: string[]; stop(signal?: NodeJS.Signals): Promise<void> }
export function child(cmd: string, args: string[], env: Record<string, string>): Child {
  const proc = spawn(cmd, args, { env, stdio: ['ignore', 'pipe', 'pipe'] })
  const lines: string[] = []
  let buf = ''
  const onData = (d: Buffer): void => { buf += d.toString('utf8'); let i; while ((i = buf.indexOf('\n')) >= 0) { lines.push(buf.slice(0, i)); buf = buf.slice(i + 1) } }
  proc.stdout?.on('data', onData)
  proc.stderr?.on('data', onData)
  const stop = (signal: NodeJS.Signals = 'SIGTERM'): Promise<void> => new Promise((r) => {
    if (proc.exitCode !== null || proc.signalCode !== null) return r()
    const k = setTimeout(() => { try { proc.kill('SIGKILL') } catch { /* gone */ } r() }, 8_000)
    proc.once('exit', () => { clearTimeout(k); r() })
    proc.kill(signal)
  })
  return { proc, lines, stop }
}
export async function waitFor<V>(fn: () => Promise<V | null> | V | null, ms: number, what: string, every = 200): Promise<V> {
  const t0 = Date.now()
  for (;;) {
    const v = await fn()
    if (v !== null) return v
    if (Date.now() - t0 > ms) throw new Error(`timeout: ${what}`)
    await sleep(every)
  }
}
const baseEnv = (home: string): Record<string, string> => ({ PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home, LANG: 'en_US.UTF-8' })

// ---- direct JSON-RPC to this test's own chains (never through the relay; loopback only)

export function direct(port: number, method: string, params: unknown[] = []): Promise<any> {
  return new Promise((resolve, reject) => {
    const b = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }))
    const r = request({ host: '127.0.0.1', port, method: 'POST', path: '/', headers: { 'content-type': 'application/json', 'content-length': String(b.length) } }, (res) => {
      const c: Buffer[] = []
      res.on('data', (d: Buffer) => c.push(d))
      res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(c).toString('utf8'))) } catch (e) { reject(e) } })
    })
    r.on('error', reject)
    r.end(b)
  })
}
export async function rpcResult(port: number, method: string, params: unknown[] = []): Promise<any> {
  const j = await direct(port, method, params)
  if (j.error !== undefined) throw new Error(`${method}: ${JSON.stringify(j.error).slice(0, 200)}`)
  return j.result
}

// ---- the stack

export interface Stack {
  dir: string; home: string; state: string; out: string
  anvil: number; sol: number; relay: Child & { port: number }; api: Child & { port: number }
  fetch: (url: string, init?: RequestInit) => Promise<Response>
  stop(): Promise<void>
}

async function startAnvil(t: T, home: string): Promise<number> {
  const port = await freeRun(1)
  const c = child('/usr/bin/sandbox-exec', ['-p', LOOPBACK_ONLY, 'anvil', '--host', '127.0.0.1', '--port', String(port), '--block-time', '1', '--silent'], baseEnv(home))
  t.after(() => c.stop())
  await waitFor(async () => { try { return (await direct(port, 'eth_chainId')).result === '0x7a69' ? true : null } catch { return null } }, 30_000, 'anvil')
  return port
}
async function startValidator(t: T, home: string, dir: string): Promise<number> {
  const base = await freeRun(64) // rpc, rpc websocket, faucet, gossip, then the dynamic range
  const c = child('/usr/bin/sandbox-exec', ['-p', LOOPBACK_ONLY, 'solana-test-validator', '--ledger', join(dir, 'ledger'), '--reset', '--quiet',
    '--bind-address', '127.0.0.1', '--rpc-port', String(base), '--faucet-port', String(base + 2), '--gossip-port', String(base + 3),
    '--dynamic-port-range', `${base + 4}-${base + 64}`, '--limit-ledger-size', '50000000'], baseEnv(home))
  t.after(() => c.stop())
  await waitFor(async () => {
    if (c.proc.exitCode !== null) throw new Error(`solana-test-validator exited ${c.proc.exitCode}: ${c.lines.slice(-3).join(' | ')}`)
    try { return (await direct(base, 'getHealth')).result === 'ok' ? true : null } catch { return null }
  }, 120_000, 'solana-test-validator')
  return base
}
async function readyPort(c: Child, re: RegExp, what: string): Promise<number> {
  return waitFor(() => {
    const m = c.lines.map((l) => re.exec(l)).find((x) => x !== null)
    if (m) return Number(m[1])
    if (c.proc.exitCode !== null) throw new Error(`${what} exited ${c.proc.exitCode}: ${c.lines.slice(-6).join(' | ')}`)
    return null
  }, 120_000, `${what} ready`)
}

export async function startStack(t: T): Promise<Stack> {
  const { dir, cleanup } = tempDir('vt-i2-stack-')
  t.after(cleanup)
  const home = join(dir, 'home')
  const state = makeHome(home, 'local') // <home>/local: api.token, relay-ticket.key (synthetic)
  const out = join(dir, 'out')
  mkdirSync(out, { mode: 0o700 })
  const anvil = await startAnvil(t, home)
  const sol = await startValidator(t, home, dir)
  const rc = child('/usr/bin/sandbox-exec', ['-p', relayProfile('local', [anvil, sol]), process.execPath, RELAY, '--network', 'local', '--home', home, '--build', 'i2',
    '--port', '0', '--price-fixture', 'SOL=150,ETH=3000'], { ...baseEnv(home), NODE_ENV: 'test', VT_TEST_ETH_RPC: `http://127.0.0.1:${anvil}`, VT_TEST_SOL_RPC: `http://127.0.0.1:${sol}` })
  t.after(() => rc.stop())
  const relayPort = await readyPort(rc, /^vt-relay ready network=local port=(\d+)$/, 'relay')
  const ac = child('/usr/bin/sandbox-exec', ['-p', apiProfile(state), process.execPath, API_MAIN, '--network', 'local', '--home', home, '--build', 'i2', '--port', '0'],
    { ...baseEnv(home), NODE_ENV: 'test', VAULT_TIMELOCK_DIR: out })
  t.after(() => ac.stop())
  const apiPort = await readyPort(ac, /^vt-api ready network=local port=(\d+) build=i2$/, 'api')
  const relay = Object.assign(rc, { port: relayPort }), api = Object.assign(ac, { port: apiPort })
  return {
    dir, home, state, out, anvil, sol, relay, api, fetch: stackFetch({ api: apiPort, relay: relayPort }),
    async stop() { await api.stop(); await relay.stop() },
  }
}

// What nodeClients reach (fixed PORTS.local.api / .relay) → this stack's ephemeral ports, with the Host the guards want.
export function stackFetch(ports: { api: number; relay: number }): (url: string, init?: RequestInit) => Promise<Response> {
  const map = new Map<number, number>([[PORTS.local.api, ports.api], [PORTS.local.relay, ports.relay]])
  return (url, init) => new Promise((resolve, reject) => {
    const u = new URL(url)
    const port = map.get(Number(u.port))
    if (u.protocol !== 'http:' || u.hostname !== '127.0.0.1' || port === undefined) { reject(new TypeError('stackFetch: not a URL of this stack')); return }
    const headers: Record<string, string> = {}
    new Headers(init?.headers).forEach((v, k) => { headers[k] = v })
    headers.host = `127.0.0.1:${u.port}`
    const body = init?.body === undefined || init.body === null ? null : Buffer.from(String(init.body))
    if (body !== null) headers['content-length'] = String(body.length)
    const signal = init?.signal ?? undefined
    if (signal?.aborted) { reject(new DOMException('aborted', 'AbortError')); return }
    // agent: false (Cfix4): a fresh socket per call. The default agent keeps sockets alive, and the API closing an idle one made the next
    // poll fail with ECONNRESET (a flake of cli/test/run-real.test.ts, seen in Cfix2 and Cfix4).
    const req = request({ host: '127.0.0.1', port, method: init?.method ?? 'GET', path: `${u.pathname}${u.search}`, headers, setHost: false, agent: false, ...(signal ? { signal } : {}) }, (res) => {
      const h = new Headers()
      for (const [k, v] of Object.entries(res.headers)) { if (typeof v === 'string') h.set(k, v); else if (Array.isArray(v)) for (const x of v) h.append(k, x) }
      const status = res.statusCode ?? 500
      resolve(new Response(status === 204 || status === 304 ? null : (Readable.toWeb(res) as unknown as ReadableStream<Uint8Array>), { status, headers: h }))
    })
    req.on('error', reject)
    req.end(body ?? undefined)
  })
}

// One API call through the shim (the test's own setup calls: create, arm, read).
export async function apiCall(s: Stack, method: 'GET' | 'POST', path: string, body?: unknown): Promise<{ status: number; json: any }> {
  const r = await s.fetch(`http://127.0.0.1:${PORTS.local.api}${path}`, { method, headers: { authorization: `Bearer ${TOKEN}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) })
  const text = await r.text()
  let json: unknown = null
  try { json = JSON.parse(text) } catch { /* not JSON */ }
  return { status: r.status, json }
}
// A relay JSON-RPC request through the shim, with an optional send ticket.
export async function relayCall(s: Stack, chain: 'eth' | 'sol', method: string, params: unknown[], ticket?: string): Promise<{ status: number; json: any }> {
  const r = await s.fetch(`http://127.0.0.1:${PORTS.local.relay}/relay/${chain}`, { method: 'POST', headers: { 'content-type': 'application/json', ...(ticket === undefined ? {} : { 'x-vt-send-ticket': ticket }) },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) })
  const text = await r.text()
  let json: unknown = null
  try { json = JSON.parse(text) } catch { /* not JSON */ }
  return { status: r.status, json }
}

// ---- funding and reading this test's own chains (direct, loopback)

export async function fundEth(s: Stack, address: string, wei: bigint): Promise<void> {
  await rpcResult(s.anvil, 'anvil_setBalance', [address, `0x${wei.toString(16)}`])
}
export async function ethBalance(s: Stack, address: string): Promise<bigint> {
  return BigInt(await rpcResult(s.anvil, 'eth_getBalance', [address, 'latest']))
}
export async function ethNonce(s: Stack, address: string): Promise<number> {
  return Number(BigInt(await rpcResult(s.anvil, 'eth_getTransactionCount', [address, 'latest'])))
}
export async function fundSol(s: Stack, address: string, lamports: number): Promise<void> {
  const before = await solBalance(s, address)
  await rpcResult(s.sol, 'requestAirdrop', [address, lamports])
  await waitFor(async () => ((await solBalance(s, address)) >= before + BigInt(lamports) ? true : null), 60_000, 'airdrop')
}
export async function solBalance(s: Stack, address: string): Promise<bigint> {
  return BigInt((await rpcResult(s.sol, 'getBalance', [address, { commitment: 'confirmed' }])).value)
}

// Synthetic text that the message rules accept (no secrets, no IP literals): numbered lines of made-up words.
export function syntheticText(bytes: number, label: string): string {
  const words = ['vtfix', 'zorbel', 'quandle', 'mirtal', 'flonk', 'plimsy', 'trevvet', 'gausk', 'wendle', 'snarpt', 'oxlind', 'brumple']
  let s = `${label}\n`
  for (let i = 1; s.length < bytes; i++) s += `Line ${String(i).padStart(5, '0')}: ${words[i % words.length]} ${words[(i * 7) % words.length]} ${words[(i * 5 + 3) % words.length]}.\n`
  return s.slice(0, bytes - 1) + '\n'
}

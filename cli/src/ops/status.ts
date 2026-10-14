// cli/src/ops/status.ts — `vt status [--network N] [--json]` (canonical vt spec §8; plan Task C3). A client command:
// it runs inside loopbackProfile([page, relay, api]) of each network it reaches (every network without --network;
// controller ruling (2) on C1), with no file writes.
//
// For each network whose $VT_HOME/<network>/up.json is valid (src/ops/stack.ts readUpJson), it reads, on 127.0.0.1:
//   page   GET /__serve        { release, digest, build }
//   relay  GET /relay/status   { network, build, confined, identity, endpoints }
//   tor    GET /relay/tor      { isTor, torRoles } (torRoles: the roles that go through Tor; on local only drand and its
//                               IsTor check, S6 D-R15: the line then says "drand via Tor", never just "direct loopback")
//   api    GET /status         { network, build, confined, mainnetSends, jobSends, legacyLatch } (Bearer api.token)
// Each request sends Host 127.0.0.1:<port> and no Origin, no Sec-Fetch-Site (the API's guards, spec §5.1), and reads at
// most 64 KiB within 3 s.
// ★ Output is built ONLY from whitelisted fields, each checked against its type (booleans; a network name; LOCKED or
//   ENABLED; clear or open; a build id: dev or 12-64 hex; 64 hex; small counts). Anything else becomes null. No raw
//   body, no server message, no header, no path and no token is ever printed, so no IP address can reach the output
//   whatever a server answers. Errors are fixed words: unreachable, http <code>, not json, token unreadable.
// healthy = up, all four answered, relay and API name this network, both confined, and (testnet, mainnet) isTor.
// Exit: with --network, 0 only when that stack is healthy; without, 0 when every stack that is up is healthy (none up
// is fine). --json prints the array of entries (fields below); the first four are the contracts' StackInfo.
import type { Network } from '@vault-timelock/core/contracts'
import { PORTS, isNetwork } from '@vault-timelock/core/contracts'
import { request } from 'node:http'
import { join } from 'node:path'
import { UsageError } from '../args.ts'
import type { Env } from './paths.ts'
import { stateDir, vtHome } from './paths.ts'
import { pageUrl, readSmallFile, readUpJson } from './stack.ts'

type Bool = boolean | null
export interface PageView { ok: boolean; error: string | null; release: Bool; build: string | null; digest: string | null }
export interface RelayView {
  ok: boolean; error: string | null; network: Network | null; build: string | null; confined: Bool
  identity: { eth: Bool; sol: Bool }; endpoints: { eth: number | null; sol: number | null }
}
// drandViaTor: /relay/tor's torRoles names drand (S6 fix round 1, review I-1); null when the relay does not say.
export interface TorView { ok: boolean; error: string | null; isTor: Bool; drandViaTor: Bool }
export interface ApiView {
  ok: boolean; error: string | null; network: Network | null; build: string | null; confined: Bool
  mainnetSends: 'LOCKED' | 'ENABLED' | null; jobSends: 'LOCKED' | 'ENABLED' | null; legacyLatch: 'clear' | 'open' | null
}
export interface StatusEntry {
  network: Network; up: boolean; pageUrl: string; build: string | null; startedAt: number | null
  page: PageView | null; relay: RelayView | null; tor: TorView | null; api: ApiView | null; healthy: boolean
}

export interface Reply { status: number; body: string }
export interface StatusDeps {
  ports: (n: Network) => { page: number; relay: number; api: number }
  get: (port: number, path: string, headers: Readonly<Record<string, string>>, timeoutMs?: number) => Promise<Reply | null>
  out: (text: string) => void
}

const BODY_CAP = 65_536
const TIMEOUT_MS = 3_000

export function parseStatusArgs(args: readonly string[]): { json: boolean } {
  const ok = args.length === 0 || (args.length === 1 && args[0] === '--json')
  if (!ok) throw new UsageError('usage: vt status [--network local|testnet|mainnet] [--json]')
  return { json: args.length === 1 }
}

// GET http://127.0.0.1:<port><path>, Host 127.0.0.1:<port>, plus `headers`. null: no answer (refused, reset, timeout,
// over the cap).
export function httpGet(port: number, path: string, headers: Readonly<Record<string, string>>, timeoutMs: number = TIMEOUT_MS): Promise<Reply | null> {
  return new Promise<Reply | null>((resolve) => {
    let done = false
    const finish = (v: Reply | null): void => { if (!done) { done = true; clearTimeout(timer); resolve(v) } }
    const req = request({ host: '127.0.0.1', port, path, method: 'GET', agent: false, headers: { ...headers, host: `127.0.0.1:${port}` } }, (res) => {
      const chunks: Buffer[] = []
      let n = 0
      res.on('data', (c: Buffer) => {
        n += c.length
        if (n > BODY_CAP) { req.destroy(); finish(null) } else chunks.push(c)
      })
      res.on('end', () => finish({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }))
      res.on('error', () => finish(null))
    })
    const timer = setTimeout(() => { req.destroy(); finish(null) }, timeoutMs)
    req.on('error', () => finish(null))
    req.end()
  })
}

// ---- field checks (anything else: null)
type Obj = Record<string, unknown>
export const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v)
export const bool = (v: unknown): Bool => (typeof v === 'boolean' ? v : null)
// A build id as a server reports it: `dev`, or 12 to 64 lowercase hex (never anything that could be an address).
export const id = (v: unknown): string | null => (typeof v === 'string' && /^(?:dev|[0-9a-f]{12,64})$/.test(v) ? v : null)
export const hex64 = (v: unknown): string | null => (typeof v === 'string' && /^[0-9a-f]{64}$/.test(v) ? v : null)
export const net = (v: unknown): Network | null => (isNetwork(v) ? v : null)
const count = (v: unknown): number | null => (typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 1000 ? v : null)
export const lock = (v: unknown): 'LOCKED' | 'ENABLED' | null => (v === 'LOCKED' || v === 'ENABLED' ? v : null)
const latch = (v: unknown): 'clear' | 'open' | null => (v === 'clear' || v === 'open' ? v : null)
// RelayStatus.identity[c] is { ok, message? }; a bare boolean is accepted too. The message is never printed.
const identityOk = (v: unknown): Bool => (typeof v === 'boolean' ? v : isObj(v) ? bool(v.ok) : null)
const sub = (v: unknown, k: string): unknown => (isObj(v) ? v[k] : undefined)

export async function getJson(d: StatusDeps, port: number, path: string, headers: Readonly<Record<string, string>> = {}, timeoutMs?: number): Promise<{ v: Obj } | { error: string }> {
  const r = await (timeoutMs === undefined ? d.get(port, path, headers) : d.get(port, path, headers, timeoutMs))
  if (r === null) return { error: 'unreachable' }
  if (r.status !== 200) return { error: Number.isInteger(r.status) && r.status >= 100 && r.status <= 599 ? `http ${r.status}` : 'http ?' }
  try {
    const v: unknown = JSON.parse(r.body)
    return isObj(v) ? { v } : { error: 'not json' }
  } catch {
    return { error: 'not json' }
  }
}

// api.token: a private regular file (never through a symlink) holding exactly 64 lowercase hex (one trailing newline
// allowed), as the API itself requires. null otherwise.
export function readToken(dir: string): string | null {
  const text = readSmallFile(join(dir, 'api.token'), { cap: 4096, privateOnly: true, whole: true })
  if (text === null) return null
  const v = text.endsWith('\n') ? text.slice(0, -1) : text
  return /^[0-9a-f]{64}$/.test(v) ? v : null
}

export async function stackStatus(n: Network, env: Env, d: StatusDeps): Promise<StatusEntry> {
  const dir = stateDir(vtHome(env), n)
  const info = readUpJson(dir, n)
  const base = { network: n, pageUrl: pageUrl(n) }
  if (info === null) return { ...base, up: false, build: null, startedAt: null, page: null, relay: null, tor: null, api: null, healthy: false }
  const ports = d.ports(n)

  const p = await getJson(d, ports.page, '/__serve')
  const page: PageView = 'v' in p
    ? { ok: true, error: null, release: bool(p.v.release), build: id(p.v.build), digest: hex64(p.v.digest) }
    : { ok: false, error: p.error, release: null, build: null, digest: null }

  const r = await getJson(d, ports.relay, '/relay/status')
  const relay: RelayView = 'v' in r
    ? {
        ok: true, error: null, network: net(r.v.network), build: id(r.v.build), confined: bool(r.v.confined),
        identity: { eth: identityOk(sub(r.v.identity, 'eth')), sol: identityOk(sub(r.v.identity, 'sol')) },
        endpoints: { eth: count(sub(r.v.endpoints, 'eth')), sol: count(sub(r.v.endpoints, 'sol')) },
      }
    : { ok: false, error: r.error, network: null, build: null, confined: null, identity: { eth: null, sol: null }, endpoints: { eth: null, sol: null } }

  const t = await getJson(d, ports.relay, '/relay/tor')
  const tor: TorView = 'v' in t
    ? { ok: true, error: null, isTor: bool(t.v.isTor), drandViaTor: Array.isArray(t.v.torRoles) ? t.v.torRoles.includes('drand') : null }
    : { ok: false, error: t.error, isTor: null, drandViaTor: null }

  const token = readToken(dir)
  const a = token === null ? { error: 'token unreadable' } : await getJson(d, ports.api, '/status', { authorization: `Bearer ${token}` })
  const api: ApiView = 'v' in a
    ? {
        ok: true, error: null, network: net(a.v.network), build: id(a.v.build), confined: bool(a.v.confined),
        mainnetSends: lock(a.v.mainnetSends), jobSends: lock(a.v.jobSends), legacyLatch: latch(a.v.legacyLatch),
      }
    : { ok: false, error: a.error, network: null, build: null, confined: null, mainnetSends: null, jobSends: null, legacyLatch: null }

  const healthy = page.ok && relay.ok && tor.ok && api.ok && relay.network === n && api.network === n
    && relay.confined === true && api.confined === true && (n === 'local' || tor.isTor === true)
  return { ...base, up: true, build: info.build, startedAt: info.startedAt, page, relay, tor, api, healthy }
}

const yn = (v: Bool): string => (v === null ? '?' : v ? 'yes' : 'no')
const okv = (v: Bool): string => (v === null ? '?' : v ? 'ok' : 'FAIL')
const show = (v: string | number | null): string => (v === null ? '?' : String(v))
// /status's mainnetSends and jobSends are both MAINNET locks (broadcast config.ts): local and testnet job sends are never
// locked. So they are labelled as mainnet's on every network ("mainnet job sends: locked"; I3 minor #2).
const lockWord = (v: 'LOCKED' | 'ENABLED' | null): string => (v === null ? '?' : v.toLowerCase())
// The tor line. Local: the chains go direct on loopback; drand (S6, D-R15), when the relay serves it, goes through Tor, and
// its IsTor state is the relay's last check (made on drand's first use): "drand via Tor", or unavailable when Tor is down.
function torWords(n: Network, t: TorView): string {
  if (n !== 'local') return `isTor ${yn(t.isTor)}`
  if (t.drandViaTor !== true) return t.isTor === null ? 'isTor n/a (local: direct loopback)' : `isTor ${yn(t.isTor)}`
  const state = t.isTor === null ? ' (IsTor not checked yet: on first use)' : t.isTor ? ' (IsTor yes)' : ': unavailable (IsTor no)'
  return `drand via Tor${state}; chains direct loopback`
}

export function renderStatus(entries: readonly StatusEntry[]): string {
  const lines: string[] = []
  for (const e of entries) {
    if (!e.up) {
      lines.push(`${e.network.padEnd(8)} down`)
      continue
    }
    lines.push(`${e.network.padEnd(8)} up      ${e.pageUrl}  build ${show(e.build)}  ${e.healthy ? 'healthy' : 'NOT HEALTHY'}`)
    const pg = e.page!, rl = e.relay!, tr = e.tor!, ap = e.api!
    lines.push(pg.ok
      ? `  page   ok   release ${yn(pg.release)}  build ${show(pg.build)}  digest ${pg.digest === null ? '-' : `${pg.digest.slice(0, 16)}…`}`
      : `  page   ${pg.error}`)
    lines.push(rl.ok
      ? `  relay  ok   network ${show(rl.network)}  build ${show(rl.build)}  confined ${yn(rl.confined)}  identity eth ${okv(rl.identity.eth)} sol ${okv(rl.identity.sol)}  endpoints eth ${show(rl.endpoints.eth)} sol ${show(rl.endpoints.sol)}`
      : `  relay  ${rl.error}`)
    lines.push(tr.ok ? `  tor    ok   ${torWords(e.network, tr)}` : `  tor    ${tr.error}`)
    lines.push(ap.ok
      ? `  api    ok   network ${show(ap.network)}  build ${show(ap.build)}  confined ${yn(ap.confined)}  mainnet sends: ${lockWord(ap.mainnetSends)}  mainnet job sends: ${lockWord(ap.jobSends)}  legacy latch ${show(ap.legacyLatch)}`
      : `  api    ${ap.error}`)
  }
  return `${lines.join('\n')}\n`
}

export async function status(o: { networks: readonly Network[]; explicit: boolean; json: boolean; env: Env }, deps: Partial<StatusDeps> = {}): Promise<number> {
  const d: StatusDeps = { ports: (n) => PORTS[n], get: httpGet, out: (t) => { process.stdout.write(t) }, ...deps }
  const entries: StatusEntry[] = []
  for (const n of o.networks) entries.push(await stackStatus(n, o.env, d))
  d.out(o.json ? `${JSON.stringify(entries, null, 2)}\n` : renderStatus(entries))
  const ok = o.explicit ? entries.every((e) => e.healthy) : entries.every((e) => !e.up || e.healthy)
  return ok ? 0 : 1
}

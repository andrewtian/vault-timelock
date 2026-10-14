// cli/src/preflight.ts — `vt preflight [--network N] [--json]` (canonical vt spec §8; plan Task C7). A client command: it
// runs inside loopbackProfile([page, relay, api]) of its network (bin/vt), with no file writes, and only READS: the
// relay's status, Tor flag, fee history and fork probe through core's preflight(), the page server's /__serve, the
// relay's /relay/release and the API's /status (Bearer api.token, as `vt status` does). No transaction is sent, no
// key is read.
//
// ★ ONE TABLE with the page's Status screen (F9-5): core's preflight() rows plus core's pageRows() (executor/readiness.ts),
//   the same function the page calls, and the same verdict (readinessVerdict): exit 0 only when preflight() passed
//   (identity and deployments) AND no row anywhere is ✗. A development tree shows the build-id row as — (dev tree).
//   Below the table: the regime (network, chains, the mainnet lock), the API's mainnet/job send locks, and whether the
//   page server's and the relay's release digests are equal.
// ★ Output is built ONLY from whitelisted fields (src/ops/status.ts: network names, build ids, 64-hex digests, booleans,
//   LOCKED/ENABLED) and from core's rows, whose details already went through core's text cleaner. Every printed line then
//   passes C4's printer (control sequences removed, IP literals redacted); --json passes assertNoControl and
//   assertNoAddress as a whole and is withheld if either fails (fail closed).
// A stack that is not up (no valid up.json) is a failing preflight with a fixed line that names the start command.
import type { Network, RelayClient } from '@vault-timelock/core/contracts'
import { PORTS } from '@vault-timelock/core/contracts'
import { NETWORK } from '@vault-timelock/core/chains/constants.js'
import { delegatedFromJobs, httpRelayClient, pageRows, preflight, readinessVerdict } from '@vault-timelock/core/executor'
import type { PreflightReport, PreflightRow, ReadinessRow } from '@vault-timelock/core/executor'
import { UsageError } from './args.ts'
import { safeLine } from './job/client.ts'
import { assertNoAddress, assertNoControl } from './ops/logs.ts'
import type { Env } from './ops/paths.ts'
import { stateDir, vtHome } from './ops/paths.ts'
import { readUpJson } from './ops/stack.ts'
import type { StatusDeps } from './ops/status.ts'
import { bool, getJson, hex64, httpGet, id, isObj, lock, net, readToken } from './ops/status.ts'

export function parsePreflightArgs(args: readonly string[]): { json: boolean } {
  const ok = args.length === 0 || (args.length === 1 && args[0] === '--json')
  if (!ok) throw new UsageError('usage: vt preflight [--network local|testnet|mainnet] [--json]')
  return { json: args.length === 1 }
}

export interface PreflightDeps extends StatusDeps {
  // The relay client of a relay port (core's httpRelayClient over loopback fetch in the real command; a fake in tests).
  relay: (port: number) => RelayClient
  now: () => number
  err: (text: string) => void
}

export interface PreflightOutput extends Omit<PreflightReport, 'rows'> {
  up: boolean
  rows: Array<PreflightRow | (ReadinessRow & { chain: null })>
  regime: { label: string; sub: string }
  mainnetSends: 'LOCKED' | 'ENABLED' | null
  jobSends: 'LOCKED' | 'ENABLED' | null
  // kind: equal / differ; dev (a development tree: a server positively says release:false); unreadable (anything else)
  digests: { page: string | null; relay: string | null; equal: boolean | null; kind: 'equal' | 'differ' | 'dev' | 'unreadable'; why?: string }
  failing: number
}

const real = (port: number): RelayClient => httpRelayClient({ base: `http://127.0.0.1:${port}`, fetch: (url, init) => fetch(url, { ...init, signal: AbortSignal.timeout(120_000) }) })

// ---- the facts the page rows need, whitelisted (a server's own text is never passed on)
const count = (v: unknown): number | null => (typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 1_000_000 ? v : null)
const identity = (v: unknown): { ok: boolean | null; message?: string } => (isObj(v) ? { ok: bool(v.ok), ...(typeof v.message === 'string' ? { message: v.message.slice(0, 400) } : {}) } : { ok: null })

interface Facts {
  api: { network: Network | null; build: string | null; mainnetSends: 'LOCKED' | 'ENABLED' | null; jobSends: 'LOCKED' | 'ENABLED' | null } | null
  relay: { network: Network | null; build: string | null; identity: { eth: { ok: boolean | null; message?: string }; btc?: { ok: boolean | null; message?: string } }; endpoints?: { btc: number | null } } | null
  // GET /relay/services, whitelisted: names, booleans, counts and a short message that core only classifies (never prints)
  services: { network: Network | null; services: Record<string, { ok: boolean | null; viaTor: boolean | null; endpoints: number | null; message?: string }> } | null
  servicesWhy: 'timed out' | 'could not be read' | null     // why services is null (Cfix4: the service rows read "not checked (…)")
  chains: Record<string, { delegated: true }>             // M4b: lane keys the journal says are EIP-7702-delegated (GET /jobs; {} when unreadable)
  serve: { release: boolean | null; digest: string | null; build: string | null } | null
  release: { release: boolean | null; files: number | null; ok: number | null; digest: string | null; mismatch: number | null; missing: number | null; hashedAt?: number | null; error?: string } | null
}

// The relay's first /relay/release can wait on its release re-hash (tens of thousands of files); the other reads keep the
// short timeout. Cfix2.
export const RELEASE_TIMEOUT_MS = 180_000
// /relay/services waits for each service's first identity check (local drand: an IsTor check first).
export const SERVICES_TIMEOUT_MS = 60_000
// hashedAt: ms since the epoch, when the relay's re-hash started (a positive safe integer); anything else is null.
const stamp = (v: unknown): number | null => (typeof v === 'number' && Number.isSafeInteger(v) && v > 0 ? v : null)

const SERVICE_NAME = /^[a-z][a-z0-9.]{0,31}$/
function servicesOf(v: unknown): NonNullable<Facts['services']>['services'] {
  const out: NonNullable<Facts['services']>['services'] = {}
  if (!isObj(v)) return out
  for (const k of Object.keys(v).filter((n) => SERVICE_NAME.test(n)).slice(0, 16)) {
    const e = v[k]
    out[k] = isObj(e) ? { ok: bool(e.ok), viaTor: bool(e.viaTor), endpoints: count(e.endpoints), ...(typeof e.message === 'string' ? { message: e.message.slice(0, 400) } : {}) } : { ok: null, viaTor: null, endpoints: null }
  }
  return out
}

async function facts(n: Network, env: Env, d: PreflightDeps): Promise<Facts> {
  const ports = d.ports(n)
  const dir = stateDir(vtHome(env), n)
  const s = await getJson(d, ports.page, '/__serve')
  const r = await getJson(d, ports.relay, '/relay/status')
  const tSv = d.now()
  const sv = await getJson(d, ports.relay, '/relay/services', {}, SERVICES_TIMEOUT_MS)
  const servicesWhy = 'v' in sv ? null : sv.error === 'unreachable' && d.now() - tSv >= SERVICES_TIMEOUT_MS ? 'timed out' as const : 'could not be read' as const
  d.err("waiting for the relay's release re-hash…\n")
  const t0 = d.now()
  const rr = await getJson(d, ports.relay, '/relay/release', {}, RELEASE_TIMEOUT_MS)
  // Never accept an answer older than this request: the re-hash must have STARTED after we asked (same machine clock).
  if ('v' in rr && rr.v.release === true) { const h = stamp(rr.v.hashedAt); if (h !== null && h < t0) rr.v.hashedAt = null }
  const why = 'v' in rr ? '' : rr.error === 'unreachable' && d.now() - t0 >= RELEASE_TIMEOUT_MS ? `no answer within ${RELEASE_TIMEOUT_MS / 1000} s` : rr.error
  const token = readToken(dir)
  const a = token === null ? null : await getJson(d, ports.api, '/status', { authorization: `Bearer ${token}` })
  const jl = token === null ? null : await getJson(d, ports.api, '/jobs', { authorization: `Bearer ${token}` })
  const chains = jl !== null && 'v' in jl && isObj(jl.v) ? delegatedFromJobs(jl.v.jobs) : {}
  return {
    chains,
    serve: 'v' in s ? { release: bool(s.v.release), digest: hex64(s.v.digest), build: id(s.v.build) } : null,
    relay: 'v' in r ? {
      network: net(r.v.network), build: id(r.v.build),
      identity: { eth: identity(isObj(r.v.identity) ? r.v.identity.eth : undefined), ...(isObj(r.v.identity) && isObj(r.v.identity.btc) ? { btc: identity(r.v.identity.btc) } : {}) },
      ...(isObj(r.v.endpoints) && 'btc' in r.v.endpoints ? { endpoints: { btc: count(r.v.endpoints.btc) } } : {}),
    } : null,
    services: 'v' in sv ? { network: net(sv.v.network), services: servicesOf(sv.v.services) } : null,
    servicesWhy,
    release: 'v' in rr ? { release: bool(rr.v.release), files: count(rr.v.files), ok: count(rr.v.ok), digest: hex64(rr.v.digest), mismatch: count(rr.v.mismatch), missing: count(rr.v.missing), hashedAt: stamp(rr.v.hashedAt) }
      : { release: null, files: null, ok: null, digest: null, mismatch: null, missing: null, error: why },
    api: a !== null && 'v' in a ? { network: net(a.v.network), build: id(a.v.build), mainnetSends: lock(a.v.mainnetSends), jobSends: lock(a.v.jobSends) } : null,
  }
}

export async function runPreflight(n: Network, env: Env, d: PreflightDeps): Promise<PreflightOutput> {
  const { label, sub } = NETWORK[n] as { label: string; sub: string }
  const regime = { label, sub }                                  // NETWORK[n] also holds BigInt limits: only the words go out
  const base = { format: 'vt-preflight/1' as const, network: n, at: d.now(), regime, chains: {} }
  if (readUpJson(stateDir(vtHome(env), n), n) === null) {
    const row: ReadinessRow & { chain: null } = { id: 'stack', chain: null, ok: false, label: `The ${n} stack is up`, detail: `no ${n} stack is up; start it with: vt up --network ${n}` }
    return { ...base, up: false, idOk: false, deployOk: false, exit: 1, rows: [row], mainnetSends: null, jobSends: null, digests: { page: null, relay: null, equal: null, kind: 'unreadable' }, failing: 1 }
  }
  const f = await facts(n, env, d)
  const report = await preflight(d.relay(d.ports(n).relay), n, { now: d.now })
  // The page's rows from core, fed exactly what the page feeds them (its own build id aside: a terminal has no page bundle).
  const extras = { serve: f.serve, release: f.release, services: f.services, servicesWhy: f.servicesWhy, chains: f.chains }
  const rows = pageRows({ network: n, status: f.api, relay: f.relay, extras, pageNetwork: n })
  const v = readinessVerdict(report, rows)
  // "page": the page server's /__serve digest; "relay": the release the relay re-hashes (/relay/release): the same pair
  // the page's release row compares.
  const page = f.serve?.digest ?? null, relay = f.release?.digest ?? null
  const equal = page !== null && relay !== null ? page === relay : null
  // "development tree" only when the facts positively say release:false; unreadable facts are not a development tree.
  const dev = f.release?.release === false || f.serve?.release === false
  const kind = equal === true ? 'equal' : equal === false ? 'differ' : dev ? 'dev' : 'unreadable'
  const why = kind === 'unreadable' ? (f.release?.error || (f.serve === null ? 'the page server did not answer' : undefined)) : undefined
  return {
    ...base, up: true, idOk: report.idOk, deployOk: report.deployOk, chains: report.chains, exit: v.exit, failing: v.failing,
    rows: [...rows.map((r) => ({ ...r, chain: null })), ...report.rows],
    mainnetSends: f.api?.mainnetSends ?? null, jobSends: f.api?.jobSends ?? null,
    digests: { page, relay, equal, kind, ...(why ? { why } : {}) },
  }
}

const mark = (ok: boolean | null): string => (ok === true ? '✓' : ok === false ? '✗' : '—')
const lockWord = (v: 'LOCKED' | 'ENABLED' | null): string => (v === null ? '?' : v.toLowerCase())

export function renderPreflight(o: PreflightOutput): string {
  const lines = [`vt preflight — network ${o.network}`]
  for (const r of o.rows) lines.push(`  ${mark(r.ok)}  ${r.label} — ${r.detail}`)
  lines.push(`regime: ${o.regime.label}: ${o.regime.sub}`)
  lines.push(`mainnet sends: ${lockWord(o.mainnetSends)}  ·  mainnet job sends: ${lockWord(o.jobSends)}`)
  const dg = o.digests
  lines.push(`page and relay digests: ${dg.kind === 'equal' ? `equal (${String(dg.page).slice(0, 12)}…)` : dg.kind === 'differ' ? 'DIFFER (the page and the relay come from different releases)' : dg.kind === 'dev' ? 'n/a (a development tree has no release digest)' : `could not be read${dg.why ? ` (${dg.why})` : ''}`}`)
  lines.push(o.failing === 0 && o.exit === 0 ? `every check passed · exit 0` : `${o.failing} check${o.failing === 1 ? '' : 's'} failing · exit ${o.exit}`)
  return lines.map(safeLine).join('\n') + '\n'
}

export async function preflightCommand(o: { network: Network; env: Env; json: boolean }, deps: Partial<PreflightDeps> = {}): Promise<number> {
  const d: PreflightDeps = { ports: (n) => PORTS[n], get: httpGet, out: (t) => { process.stdout.write(t) }, relay: real, now: Date.now, err: (t) => { process.stderr.write(t) }, ...deps }
  const out = await runPreflight(o.network, o.env, d)
  if (o.json) {
    const text = JSON.stringify(out)                              // one line: a newline is a control character to the check
    assertNoControl(text)
    assertNoAddress(text)
    d.out(`${text}\n`)
  } else d.out(renderPreflight(out))
  return out.exit
}

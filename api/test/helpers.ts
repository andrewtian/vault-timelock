// Shared test helpers (not a test file). Synthetic data only; servers bind 127.0.0.1 port 0 only.
import { createHash } from 'node:crypto'
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import type { IncomingHttpHeaders, Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { ArmCap, ArmRecord, JobDef, JournalEvent, Network } from '@vault-timelock/core/contracts'
import { ethAmsterdam } from '@vault-timelock/core/contracts'
import { ethGasFormula, solCuEstimate, solCuLimit } from '@vault-timelock/core/chains/plan.js'
import { canonicalJson, jobId, normalizeJob } from '@vault-timelock/core/job'
import { recipientAddress } from '@vault-timelock/core/chains/eth.js'
import { planLaneCopy } from '@vault-timelock/core/engine/lane.js'
import { laneConfigOf } from '@vault-timelock/core/executor'
import { createStore } from 'vt-broadcast/src/lifecycle/store.ts'
import type { Clock } from '../src/clock.ts'
import { JOURNAL_FILE } from '../src/journal.ts'
import type { JournalFs } from '../src/journal.ts'
import { createApi, createRegistry } from '../src/routes.ts'
import type { Api, ApiOptions } from '../src/routes.ts'

export const CANARY = '203.0.113.77'
export const TOKEN = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
export const FIXTURES = fileURLToPath(new URL('../../contract/fixtures/', import.meta.resolve('@vault-timelock/core/contracts')))
export const fixture = <T = unknown>(rel: string): T => JSON.parse(readFileSync(join(FIXTURES, rel), 'utf8')) as T
export const TICKETS = fixture<{ key: string }>('tickets.json')
export const TICKET_KEY = Buffer.from(TICKETS.key, 'hex')
export const JOB = 'e3d45f73cf65abaa'
export const DEF_SHA = 'e3d45f73cf65abaa0000000000000000000000000000000000000000000000aa'
export const START = 1791504000000

export interface FakeClock extends Clock { set(t: number): void; advance(ms: number): void; timers(): number }
export function fakeClock(start = START): FakeClock {
  let now = start
  const timers = new Map<number, { every: number; next: number; fn: () => void }>()
  let id = 0
  return {
    now: () => now,
    every(ms, fn) {
      const k = ++id
      timers.set(k, { every: ms, next: now + ms, fn })
      return () => { timers.delete(k) }
    },
    set(t) { now = t },
    advance(ms) {
      const end = now + ms
      for (;;) {
        let due: { every: number; next: number; fn: () => void } | undefined
        for (const t of timers.values()) if (t.next <= end && (due === undefined || t.next < due.next)) due = t
        if (due === undefined) break
        now = due.next
        due.next += due.every
        due.fn()
      }
      now = end
    },
    timers: () => timers.size,
  }
}

// A private temp dir (realpath: the sandbox profiles name real paths); removed by the returned cleanup.
export function tempDir(prefix: string): { dir: string; cleanup(): void } {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), prefix)))
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

// <home>/<network>/ with api.token and relay-ticket.key as vt up writes them.
export function makeHome(home: string, network: Network = 'local', o: { token?: string; key?: string } = {}): string {
  const state = join(home, network)
  mkdirSync(state, { recursive: true, mode: 0o700 })
  writeFileSync(join(state, 'api.token'), `${o.token ?? TOKEN}\n`, { mode: 0o600 })
  writeFileSync(join(state, 'relay-ticket.key'), `${o.key ?? TICKETS.key}\n`, { mode: 0o600 })
  return state
}

export interface TestApi {
  api: Api; port: number; state: string; out: string; logs: string[]; clock: FakeClock; ids: string[]; root: string; close(keep?: boolean): Promise<void>
}
// A real API (job service, journals, store) on 127.0.0.1 port 0 over a temp state dir and a temp $OUT. `jobs`: vt-job/1
// inputs created before it listens (default: the eth-drain-null fixture, JOB, on local; none elsewhere).
export async function startApi(o: { network?: Network; clock?: FakeClock; jobs?: unknown[]; extra?: Partial<ApiOptions>; fs?: JournalFs; traceDelayMs?: number; reuse?: TestApi; privacyCash?: NonNullable<Parameters<typeof createRegistry>[0]['privacyCash']>; jobSendLock?: (n: Network) => void } = {}): Promise<TestApi> {
  const network = o.network ?? 'local'
  const clock = o.clock ?? fakeClock()
  // reuse: a restart over the state and $OUT of an earlier TestApi, which was closed with close(true) (keeps its files)
  const t = o.reuse !== undefined ? { dir: o.reuse.root, cleanup: () => rmSync(o.reuse!.root, { recursive: true, force: true }) } : tempDir('vt-api-test-')
  const state = o.reuse?.state ?? join(t.dir, network)
  if (o.reuse === undefined) mkdirSync(state, { mode: 0o700 })
  const out = o.reuse?.out ?? join(t.dir, 'out')
  const registry = createRegistry({
    stateDir: state, network, clock, out, ticketKey: TICKET_KEY,
    ...(o.fs !== undefined ? { fs: o.fs } : {}), ...(o.traceDelayMs !== undefined ? { traceDelayMs: o.traceDelayMs } : {}),
    ...(o.privacyCash !== undefined ? { privacyCash: o.privacyCash } : {}), ...(o.jobSendLock !== undefined ? { jobSendLock: o.jobSendLock } : {}),
  })
  const ids: string[] = []
  for (const input of o.jobs ?? (network === 'local' ? [JOB_INPUT] : [])) ids.push((await registry.create(input)).job.id)
  const logs: string[] = []
  const api = createApi({ network, token: TOKEN, build: 'test', clock, registry, log: (l) => logs.push(l), ...o.extra })
  const server: Server = createServer(api.handle)
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const port = (server.address() as { port: number }).port
  return {
    api, port, state, out, logs, clock, ids, root: t.dir,
    close: (keep = false) => new Promise<void>((r) => {
      registry.close()
      server.closeAllConnections()
      server.close(() => { if (!keep) t.cleanup(); r() })
    }),
  }
}

// ---- synthetic jobs (contract fixtures: jobs/valid/*.json)

export const jobFixture = (name: string): Record<string, unknown> => fixture<Record<string, unknown>>(`jobs/valid/${name}.json`)
// eth only, local, inline message: id JOB.
export const JOB_INPUT = jobFixture('eth-drain-null')
// eth + sol, local (the same eth key as JOB): id JOB2.
export const JOB2_INPUT = jobFixture('defaults')
export const JOB2 = '2e9e901ca97df6d5'
// The same job on another network (another id). On mainnet each eth / sol chain without a clawbackTo gets one (PF-S fix round 1, N-6:
// a new mainnet job must name it: job.clawback-required).
export const MAINNET_CLAWBACK_TO = { eth: '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6', sol: 'G147qVmzynHL3EjQ8tvBGDms7u6FDCWbFfFmzNMZmg1x' } as const
export const onNetwork = (input: Record<string, unknown>, network: Network): Record<string, unknown> => {
  if (network !== 'mainnet') return { ...input, network }
  const chains = { ...(input.chains as Record<string, Record<string, unknown>>) }
  for (const c of ['eth', 'sol'] as const) if (chains[c] !== undefined && chains[c].clawbackTo === null) chains[c] = { ...chains[c], clawbackTo: MAINNET_CLAWBACK_TO[c] }
  return { ...input, network, chains }
}
export const idOf = (input: unknown, network: Network = 'local'): string => jobId(normalizeJob(input, { network }).def)

export const CAPS: Record<'eth' | 'sol', ArmCap> = {
  eth: { nativeCap: '4000000000000000', usd: 10, priceAt: 1791504009000, overCap: false, planned: '0.004' },
  sol: { nativeCap: '50000000', usd: 5, priceAt: 1791504009000, overCap: false, planned: '0.05' },   // within JOB2's $5 sol budget (PF-S M-4)
}
export const KEYS = { eth: '0x8739Eb87B3d11f221Df63454F8D229a1A4F4049C', sol: '9xx7qC7uwTAeaSo7T5Gk9canYBosFh1pMQaDmQEa83Tb' } as const

// Test-only direct appends (the validating journal; no lease): the executor's key-loaded + funds affordable, so each
// chain is READY without a lease generation being used up.
export async function seedReady(a: TestApi, id: string, chains: ReadonlyArray<'eth' | 'sol'>): Promise<void> {
  const j = a.api.registry.journalOf(id)
  for (const c of chains) {
    await j.append({ chain: c, by: 'browser', gen: null, type: 'key-loaded', data: { address: KEYS[c] } })
    await j.append({ chain: c, by: 'browser', gen: null, type: 'funds', data: { balance: '50000000000000000', affordable: true, nextCopyCost: '25000300000000' } })
  }
}

export function armBody(chains: ReadonlyArray<'eth' | 'sol'>, o: { countdownSec?: number; stagger?: [number, number]; typed?: string | null } = {}): Record<string, unknown> {
  const caps: Record<string, ArmCap> = {}
  for (const c of chains) caps[c] = CAPS[c]
  return {
    chains: [...chains], confirm: { typed: o.typed ?? null, amounts: {} }, caps,
    ...(o.countdownSec !== undefined ? { countdownSec: o.countdownSec } : {}), ...(o.stagger !== undefined ? { stagger: o.stagger } : {}),
  }
}

// READY (seedReady), armed over HTTP (countdown 5 s, stagger [0, 0] on local), and the clock moved to the release.
export async function armed(a: TestApi, id: string, chains: ReadonlyArray<'eth' | 'sol'>, network: Network = 'local'): Promise<ArmRecord> {
  await seedReady(a, id, chains)
  const r = await call(a.port, { path: `/jobs/${id}/arm`, body: armBody(chains, network === 'local' ? { countdownSec: 5, stagger: [0, 0] } : { countdownSec: 5 }), network })
  if (r.status !== 200) throw new Error(`arm failed: ${r.text}`)
  const rec = (r.json as { armed: ArmRecord }).armed
  a.clock.set(rec.releaseAt + Math.max(0, ...Object.values(rec.schedule.offsetSec).map((s) => (s ?? 0) * 1000)))
  return rec
}

// A job's history written as files, as an earlier API process would have left them (not through this process's gate):
// the store record and the journal (`created` first, then `events`, hash-chained, canonical). Loaded on first request.
export async function writeJob(state: string, def: JobDef, events: ReadonlyArray<Pick<JournalEvent, 'chain' | 'by' | 'gen' | 'type' | 'data'>>, o: { at?: number } = {}): Promise<string> {
  const id = jobId(def)
  await createStore(state, { log: () => {} }).update('job', id, () => ({ def, createdAt: o.at ?? START }))
  const lines: string[] = []
  let prev = ''
  let at = o.at ?? START
  const put = (e: Pick<JournalEvent, 'chain' | 'by' | 'gen' | 'type' | 'data'>): void => {
    const line = JSON.stringify({ v: 1, seq: lines.length, at: at++, prev, chain: e.chain, by: e.by, gen: e.gen, type: e.type, data: e.data })
    lines.push(line)
    prev = createHash('sha256').update(line).digest('hex')
  }
  put({ chain: null, by: 'api', gen: null, type: 'created', data: { jobId: id, defSha256: createHash('sha256').update(canonicalJson(def)).digest('hex') } })
  for (const e of events) put(e)
  const dir = join(state, 'jobs', id)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  writeFileSync(join(dir, JOURNAL_FILE), lines.join('\n') + '\n', { mode: 0o600 })
  return id
}

// A contract journal vector (journals/<name>.def.json + .jsonl) installed as a stored job, as if written by an API.
export async function installJournal(a: TestApi, name: string): Promise<{ id: string; def: JobDef; lines: string[] }> {
  const def = fixture<JobDef>(`journals/${name}.def.json`)
  const id = jobId(def)
  await createStore(a.state, { log: () => {} }).update('job', id, () => ({ def, createdAt: START }))
  const dir = join(a.state, 'jobs', id)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  copyFileSync(join(FIXTURES, `journals/${name}.jsonl`), join(dir, JOURNAL_FILE))
  chmodSync(join(dir, JOURNAL_FILE), 0o600)
  return { id, def, lines: readFileSync(join(dir, JOURNAL_FILE), 'utf8').split('\n').filter((l) => l !== '') }
}

export interface Reply { status: number; headers: IncomingHttpHeaders; text: string; json: unknown }
// One request. `headers` are sent as given (null drops a default). Defaults: Host 127.0.0.1:<the network's API port>,
// the test token, and application/json for a body.
export function call(port: number, o: { method?: string; path: string; headers?: Record<string, string | null>; body?: unknown; raw?: string | Buffer; network?: Network }): Promise<Reply> {
  const apiPort = { local: 5182, testnet: 5192, mainnet: 5202 }[o.network ?? 'local']
  const payload = o.raw !== undefined ? Buffer.from(o.raw) : o.body !== undefined ? Buffer.from(JSON.stringify(o.body)) : null
  const base: Record<string, string | null> = {
    host: `127.0.0.1:${apiPort}`, authorization: `Bearer ${TOKEN}`,
    ...(payload !== null ? { 'content-type': 'application/json', 'content-length': String(payload.length) } : {}),
  }
  const merged = { ...base, ...o.headers }
  const headers: Record<string, string> = {}
  for (const [k, v] of Object.entries(merged)) if (v !== null) headers[k] = v
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, method: o.method ?? (payload !== null ? 'POST' : 'GET'), path: o.path, headers, setHost: false }, (res) => {
      const chunks: Buffer[] = []
      res.on('data', (c: Buffer) => chunks.push(c))
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8')
        let json: unknown = null
        try { json = JSON.parse(text) } catch { /* not JSON */ }
        resolve({ status: res.statusCode ?? 0, headers: res.headers, text, json })
      })
    })
    req.on('error', reject)
    req.setTimeout(10_000, () => { req.destroy(new Error('no complete reply within 10 s')) }) // a mutant never hangs a run
    if (payload !== null) req.end(payload)
    else req.end()
  })
}

// Base58 (Bitcoin alphabet) of bytes: synthetic Solana ids for tests.
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
export function b58(bytes: Uint8Array): string {
  let n = 0n
  for (const b of bytes) n = n * 256n + BigInt(b)
  let out = ''
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n }
  for (const b of bytes) { if (b !== 0) break; out = '1' + out }
  return out
}
export const solSig = (n: number): string => b58(Uint8Array.from({ length: 64 }, (_, i) => (i * 7 + n + 1) % 256))
export const solHash = (n: number): string => b58(Uint8Array.from({ length: 32 }, (_, i) => (i * 11 + n + 3) % 256))
export const ethTx = (n: number): string => '0x' + n.toString(16).padStart(64, '0')
export const rawOf = (n: number): string => n.toString(16).padStart(64, 'f')
export const NULL_ADDRESS = '0x0000000000000000000000000000000000000000'
export const CLAWBACK_TO = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
// PF-S I-1: the API binds an eth / sol job intent to the part IT plans from the stored message, with the lane's own planner. This is
// that plan for a vt-job/1 input with an inline message (the sha256 of each planned part of copy `copy`) and the eth recipient;
// [] for a copy the lane cannot plan (past a copies job's count). plannedPayloads: the planned parts' bytes themselves.
export function plannedPayloads(input: unknown, chain: 'eth' | 'sol', copy: number): Uint8Array[] {
  const network = (input as { network?: Network }).network ?? 'local'
  const { def, text } = normalizeJob(input, { network })
  if (text === null) throw new Error('plannedParts: the job input needs an inline message')
  const cfg = laneConfigOf(chain, def.chains[chain]!, text)
  try { return (planLaneCopy(cfg, copy) as Array<{ payload: Uint8Array }>).map((x) => x.payload) } catch { return [] }
}
export const plannedParts = (input: unknown, chain: 'eth' | 'sol', copy: number): string[] =>
  plannedPayloads(input, chain, copy).map((b) => createHash('sha256').update(b).digest('hex'))
export function plannedRecipient(input: unknown): string {
  const network = (input as { network?: Network }).network ?? 'local'
  const eth = normalizeJob(input, { network }).def.chains.eth!
  return recipientAddress(eth.publishMode === 'eth.calldata.self' ? 'self' : 'null', eth.keyAddress)
}
// PF-S fix round 2 (R1-1): the fee members the engine declares for a planned part, which the API bounds by its plan (ticket.fee-plan):
// ETH gas = the gas formula of the part's length (chains/plan.js ethGasFormula; local: pre-Amsterdam, anvil's default fork; the
// job's publish mode), SOL cuLimit = the model's limit for the part (solCuLimit(solCuEstimate)). An unplannable part (a refusal
// under test elsewhere) gets a fixed value.
export function plannedGas(input: unknown, copy = 1, part = 1): string {
  const network = (input as { network?: Network }).network ?? 'local'
  const b = plannedPayloads(input, 'eth', copy)[part - 1]
  if (b === undefined) return '23400'
  const toSelf = normalizeJob(input, { network }).def.chains.eth?.publishMode === 'eth.calldata.self'
  return String(ethGasFormula(b.length, { amsterdam: network === 'local' ? false : ethAmsterdam(network), toSelf }))
}
export function plannedCuLimit(input: unknown, copy = 1, part = 1): number {
  const b = plannedPayloads(input, 'sol', copy)[part - 1]
  return b === undefined ? 30_000 : solCuLimit(solCuEstimate(b))
}
// An eth / sol intent's data: copy, part, and the planned part count and payload of the job `input` (eth: JOB_INPUT, sol: JOB2_INPUT,
// single-part texts); `parts` overrides the planned count (a test of the refusal). The nonce follows n.
export const ethIntent = (n: number, copy = 1, part = 1, parts?: number, input: unknown = JOB_INPUT): Record<string, unknown> => {
  const plan = plannedParts(input, 'eth', copy)
  return {
    txId: ethTx(n), copy, part, parts: parts ?? Math.max(1, plan.length), attempt: 1, replaces: null, rawSha256: rawOf(n), payloadSha256: plan[part - 1] ?? 'ab'.repeat(32), reserved: '50000000000000',
    eth: { nonce: n, tip: '12000', maxFee: '2000012000', gas: plannedGas(input, copy, part), to: plannedRecipient(input) },
  }
}
export const solIntent = (n: number, copy = 1, part = 1, parts?: number, input: unknown = JOB2_INPUT): Record<string, unknown> => {
  const plan = plannedParts(input, 'sol', copy)
  return {
    txId: solSig(n), copy, part, parts: parts ?? Math.max(1, plan.length), attempt: 1, replaces: null, rawSha256: rawOf(n), payloadSha256: plan[part - 1] ?? 'cd'.repeat(32), reserved: '6000',
    sol: { blockhash: solHash(n), lastValidBlockHeight: 1000, cuPrice: 1, cuLimit: plannedCuLimit(input, copy, part), rung: null, fee: '6000' }, // >= 5000 + ⌈cuLimit × 1 / 10⁶⌉
  }
}
export const ethClawback = (n: number, to: string, value: string, o: { gas?: string; maxFee?: string } = {}): Record<string, unknown> => ({
  txId: ethTx(n), to, value, rawSha256: rawOf(n), eth: { nonce: n, tip: '12000', maxFee: o.maxFee ?? '2000012000', gas: o.gas ?? '21000', to },
})

export const guardOf = (r: Reply): string | undefined => (r.json as { error?: { guard?: string } } | null)?.error?.guard

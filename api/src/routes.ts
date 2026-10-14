// api/src/routes.ts — the API's request handler: every endpoint of spec §5.2 over the job service (jobs.ts).
//
// Every request: guardRequest (spec §5.1) → for a POST, the body (≤ 64 KiB, one JSON value) and the body check
// (bodycheck.ts: api.key-like / api.ip-like; POST /jobs runs normalizeJob first, so its own job.* refusals win) → the
// route. A PUT /messages body is streamed by messages.ts under its own 16 MiB cap. Replies are JSON with the
// contracts' status per guard: 201 for a new job and a message upload, 200 otherwise.
//
// Every journal append and every send ticket passes ONE gate, jobs.ts gate() (security review): the journal wrapper
// runs it before each fsync, and tickets are minted only by registry.ticket(), which runs it first. This file holds no
// raw journal and no ticket key. Mutating routes (ROUTES[].mutating) are listed for test/gate-coverage.test.ts.
//
// Events append (the send path), in order:
//   event.shape / event.type   the body is { gen, type, data } of an executor type (the API's own types, lease events
//                              among them, can never be appended by an executor), plus, beside a clawback-intent only,
//                              the operator's typed amount { clawbackConfirm: { amount } } (CC-2a; never journaled:
//                              the gate checks it, arm.amount beside any other type)
//   then, in the job's lease queue (checks and append in one turn):
//   lease.stale                the live gen (`by` = the lease holder)
//   lease.reconcile-first      intent / clawback-intent: every open intent of an earlier gen reconciled by this gen
//   the gate                   validateEvent, fit and fee floors, phase, evidence; for a send the latch, the mainnet
//                              lock and the job-domain checks (state, copies, Stop, duplicate, destination, family, cap)
//   the fsync → { seq }, plus for a send a ticket from registry.ticket() (the gate again: a journaled open intent, not
//   STUCK, not over, latch, lock), ticket v2 (CC-3/CC-3a) bound to (job, network, chain, gen, txId, rawSha256) and the
//   binding the gate formed before the append: the job definition's key a, k, p | to/value, f = worstCaseFee (what the
//   cap reserved), q = the declared eth nonce / sol blockhash.
// POST …/tickets: lease.stale, reconcile-first for that intent, then registry.ticket(): identical journaled bytes only.
import type { IncomingMessage, ServerResponse } from 'node:http'
import { PORTS, TEXT_CONTENT_TYPE } from '@vault-timelock/core/contracts'
import type { Chain, ChainPhase, JournalEvent, LeaseGrant, LeaseView, Network, Status } from '@vault-timelock/core/contracts'
import { normalizeJob } from '@vault-timelock/core/job'
import { MAINNET_JOB_SENDS_ENABLED, MAINNET_SEND_ENABLED, networkName } from 'vt-broadcast/src/config.ts'
import { refuse } from 'vt-broadcast/src/guard.ts'
import { createControls } from './arm.ts'
import type { Controls } from './arm.ts'
import { bodycheck } from './bodycheck.ts'
import type { Clock } from './clock.ts'
import { assertJson, guardRequest, readJson, sendError, sendJson } from './http.ts'
import { assertEventShape, assertJobState } from './jobs.ts'
import type { JobEntry, Registry } from './jobs.ts'
import { EXEC_EVENT_TYPES } from './journal.ts'
import { assertHolder, createLeases } from './leases.ts'
import type { Leases } from './leases.ts'
import type { LegacyLatch } from './legacy-latch.ts'
import { buildReceipt } from './receipt.ts'
import { createSse, resumeFrom } from './sse.ts'
import type { SseHub } from './sse.ts'

export { createRegistry } from './jobs.ts'
export type { JobEntry, Registry } from './jobs.ts'

const TX_ID: Record<Chain, RegExp> = { eth: /^0x[0-9a-f]{64}$/, sol: /^[1-9A-HJ-NP-Za-km-z]{64,88}$/, btc: /^[0-9a-f]{64}$/ }
const EXEC_TYPES: ReadonlySet<string> = new Set<string>(EXEC_EVENT_TYPES)

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype
const isPosInt = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 1
const keysWithin = (o: Record<string, unknown>, allowed: readonly string[]): boolean => Object.keys(o).every((k) => allowed.includes(k))
// A lease is refused on a chain that is over (review m8): nothing more may be sent or moved there.
const NO_LEASE: ReadonlySet<ChainPhase> = new Set<ChainPhase>(['SKIPPED', 'DONE', 'CLAWED_BACK'])

// ---- guards local to the routes

function assertExecType(type: string): void {
  const ok = EXEC_TYPES.has(type)
  if (!ok) refuse('event.type', 'unknown event type for an executor') // @guard:event.type
}

// ---- the handler

export interface ApiOptions {
  network: Network
  token: string
  build: string
  clock: Clock
  registry: Registry
  // One line per request: method, route name, status, ms and the guard of a refusal. Never a path, header, body or IP.
  log?: (line: string) => void
}
export interface Api {
  handle(req: IncomingMessage, res: ServerResponse): void
  readonly leases: Leases
  readonly sse: SseHub
  readonly registry: Registry
  readonly latch: LegacyLatch
  readonly controls: Controls
  // The route table: name, method, and whether it appends to a journal or mints a ticket.
  readonly routes: ReadonlyArray<{ name: string; method: string; mutating: boolean }>
}

interface Params { url: URL; body: unknown; id: string; chain: Chain | null }
type Handler = (req: IncomingMessage, res: ServerResponse, p: Params) => Promise<void>

export function createApi(o: ApiOptions): Api {
  const { network, registry, clock } = o
  if (registry.network !== network) throw new Error('createApi: the registry serves another network')
  const leases = createLeases({ clock, journalOf: registry.journalOf, openIntentsOf: registry.openIntents, reconciledOf: registry.reconciled })
  const sse = createSse({ clock })
  const latch = registry.latch
  const controls = createControls({ network, clock, registry, leases, latch })
  const guard = { network, token: o.token, pagePort: PORTS[network].page, devPort: PORTS[network].dev }
  const log = o.log ?? (() => {})
  const leasesOf = (job: JobEntry): Partial<Record<Chain, LeaseView | null>> => {
    const all = leases.view(job.id)
    const out: Partial<Record<Chain, LeaseView | null>> = {}
    for (const c of job.chains) out[c] = all[c] ?? null
    return out
  }

  const status: Handler = async (_req, res) => {
    const body: Status = {
      network, networks: { eth: networkName(network, 'eth'), sol: networkName(network, 'sol') },
      mainnetSends: MAINNET_SEND_ENABLED ? 'ENABLED' : 'LOCKED', jobSends: MAINNET_JOB_SENDS_ENABLED ? 'ENABLED' : 'LOCKED',
      build: o.build, confined: true, legacyLatch: (await latch.clear()) ? 'clear' : 'open', serverNowMs: clock.now(),
    }
    sendJson(res, 200, body)
  }

  const create: Handler = async (_req, res, p) => {
    normalizeJob(p.body, { network }) // its own refusals (job.*, message.*) come before the body check
    bodycheck(p.body, { messageText: true })   // the top-level `message` is publication text: validateMessage (in normalizeJob) governs it
    const { created, job } = await registry.create(p.body)
    sendJson(res, created ? 201 : 200, { id: job.id, def: job.def, state: registry.state(job) })
  }

  const list: Handler = async (_req, res) => {
    const jobs = (await registry.list()).map((job) => {
      const s = registry.state(job)
      const chains: Partial<Record<Chain, { phase: string; reason: string | null; delegated?: true }>> = {}
      // M4f glue (a): the structured EIP-7702 field (ChainState.delegated, from the journaled stop) is projected; absent = not delegated
      for (const c of job.chains) { const cs = s.chains[c]!; chains[c] = { phase: cs.phase, reason: cs.reason, ...(cs.delegated === true ? { delegated: true as const } : {}) } }
      return { id: job.id, name: job.def.name, createdAt: job.createdAt, phase: s.phase, chains }
    })
    sendJson(res, 200, { jobs, serverNowMs: clock.now() })
  }

  const job: Handler = async (_req, res, p) => {
    const j = await registry.load(p.id)
    const s = registry.state(j)
    sendJson(res, 200, { id: j.id, def: j.def, state: s, leases: leasesOf(j), seq: s.seq, serverNowMs: clock.now() })
  }

  const receipt: Handler = async (_req, res, p) => {
    const j = await registry.load(p.id)
    sendJson(res, 200, buildReceipt({ id: j.id, def: j.def, state: registry.state(j), network, build: o.build }))
  }

  const messagePut: Handler = async (req, res, p) => {
    sendJson(res, 201, await registry.messages.put(req, p.id))
  }

  const messageGet: Handler = async (_req, res, p) => {
    const bytes = registry.messages.read(p.id)
    res.writeHead(200, { 'content-type': TEXT_CONTENT_TYPE, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'content-length': String(bytes.length) })
    res.end(bytes)
  }

  const sourcesList: Handler = async (_req, res) => {
    sendJson(res, 200, { sources: registry.sources.list() })
  }

  const sourcesTries: Handler = async (_req, res, p) => {
    sendJson(res, 200, { labelsUsed: registry.sources.triesLabels(p.id) })
  }

  const sourcesAdd: Handler = async (_req, res, p) => {
    const ok = isPlainObject(p.body) && keysWithin(p.body, ['label']) && Object.hasOwn(p.body, 'label')
    assertJson(ok)
    const { source, created } = registry.sources.add((p.body as { label: unknown }).label)
    sendJson(res, created ? 201 : 200, source)
  }

  const command = (name: 'arm' | 'skip' | 'stop' | 'resume' | 'close'): Handler => async (_req, res, p) => {
    const j = await registry.load(p.id)
    const out = name === 'arm' ? { armed: await controls.arm(j, p.body) } : await controls[name](j, p.body)
    sendJson(res, 200, out)
  }

  const resolve: Handler = async (_req, res, p) => {
    const j = await registry.load(p.id, p.chain)
    sendJson(res, 200, await controls.resolve(j, p.chain!, p.body))
  }

  const lease: Handler = async (_req, res, p) => {
    const chain = p.chain!
    const j = await registry.load(p.id, chain)
    const b = p.body
    assertJson(isPlainObject(b) && keysWithin(b, ['op', 'holder', 'gen'])
      && (b.op === 'acquire' ? b.gen === undefined : (b.op === 'renew' || b.op === 'release') && isPosInt(b.gen)))
    assertHolder(b.holder)
    let grant: LeaseGrant
    if (b.op === 'acquire') {
      const phase = registry.jobState(j.id).phase(chain)!
      assertJobState(!NO_LEASE.has(phase), `${chain} is ${phase}: no lease on a chain that is over`)
      await registry.assertKeyFree(j, chain)
      grant = await leases.acquire(j.id, chain, b.holder)
    } else if (b.op === 'renew') grant = await leases.renew(j.id, chain, b.gen as number)
    else {
      await leases.release(j.id, chain, b.gen as number)
      // A release answers with the ended lease: ttlMs 0, expiresAt now, and the intents still open.
      grant = { gen: b.gen as number, ttlMs: 0, expiresAt: clock.now(), holder: b.holder, openIntents: registry.openIntents(j.id, chain) }
    }
    sendJson(res, 200, grant)
  }

  const eventsAppend: Handler = async (_req, res, p) => {
    const chain = p.chain!
    const j = await registry.load(p.id, chain)
    const b = p.body
    assertEventShape(isPlainObject(b) && keysWithin(b, ['gen', 'type', 'data', 'clawbackConfirm']) && Object.keys(b).length === (Object.hasOwn(b, 'clawbackConfirm') ? 4 : 3)
      && isPosInt(b.gen) && typeof b.type === 'string' && isPlainObject(b.data))
    assertExecType(b.type)
    const gen = b.gen, type = b.type as JournalEvent['type'], data = b.data
    const send = type === 'intent' || type === 'clawback-intent'
    const confirm = Object.hasOwn(b, 'clawbackConfirm') ? { clawbackConfirm: b.clawbackConfirm } : undefined
    const out = await leases.run(j.id, async () => {
      const holder = leases.assertLive(j.id, chain, gen)
      if (send) leases.assertReconciled(j.id, chain, gen)
      const ev = await j.journal.append({ chain, by: holder, gen, type, data }, confirm) // the gate, then the fsync
      return send ? { seq: ev.seq, ticket: await registry.ticket(j, chain, gen, data.txId as string) } : { seq: ev.seq }
    })
    sendJson(res, 200, out)
  }

  const tickets: Handler = async (_req, res, p) => {
    const chain = p.chain!
    const j = await registry.load(p.id, chain)
    const b = p.body
    assertJson(isPlainObject(b) && Object.keys(b).length === 2 && isPosInt(b.gen) && typeof b.txId === 'string' && TX_ID[chain].test(b.txId))
    const gen = b.gen, txId = b.txId
    const out = await leases.run(j.id, async () => {
      leases.assertLive(j.id, chain, gen)
      leases.assertReconciled(j.id, chain, gen, txId)
      return { ticket: await registry.ticket(j, chain, gen, txId) } // the gate, then minted
    })
    sendJson(res, 200, out)
  }

  // Sfix-PC: POST /jobs/<id>/privacycash/lane { bodySha256, allowanceLamports, tryIndex } → { authorization }. The body is exactly
  // those three members (api.json otherwise); the strings are fixed-form (64 hex, a canonical decimal), so the free-text body
  // scan does not apply (a 64-hex digest is exactly what it refuses). The job must have a SOL lane (job.missing otherwise).
  // The mint reserves in the API's ledger and answers the single-use authorization (privacycash-mint.ts).
  const pcLane: Handler = async (_req, res, p) => {
    const b = p.body
    const lamports = isPlainObject(b) ? b.allowanceLamports : undefined
    const amount = typeof lamports === 'string' && /^[1-9][0-9]{0,17}$/.test(lamports) ? BigInt(lamports)
      : typeof lamports === 'number' && Number.isSafeInteger(lamports) && lamports >= 1 ? BigInt(lamports) : null
    assertJson(isPlainObject(b) && Object.keys(b).length === 3 && typeof b.bodySha256 === 'string' && /^[0-9a-f]{64}$/.test(b.bodySha256)
      && amount !== null && amount <= 999_999_999_999_999_999n && typeof b.tryIndex === 'number' && Number.isSafeInteger(b.tryIndex) && b.tryIndex >= 0 && b.tryIndex <= 1_000_000)
    const j = await registry.load(p.id, 'sol')
    sendJson(res, 200, { authorization: await registry.mintPrivacyCash(j, { tryIndex: b.tryIndex, bodySha256: b.bodySha256, amount: amount! }) })
  }

  const stream: Handler = async (req, res, p) => {
    const j = await registry.load(p.id)
    sse.stream(res, j.journal, resumeFrom(req, p.url))
  }

  const J = '/jobs/([0-9a-f]{16})'
  const C = `${J}/chains/(eth|sol|btc)`
  const R = (s: string): RegExp => new RegExp(`^${s}$`)
  // bodycheck: run the body check before the route (every JSON body but POST /jobs, which checks after normalizeJob).
  // mutating: the route appends to a journal or mints a ticket (always through the gate, jobs.ts).
  const ROUTES: Array<{ name: string; method: string; path: RegExp; handler: Handler; bodycheck: boolean; mutating: boolean }> = [
    { name: 'status', method: 'GET', path: R('/status'), handler: status, bodycheck: false, mutating: false },
    { name: 'jobs-create', method: 'POST', path: R('/jobs'), handler: create, bodycheck: false, mutating: true },
    { name: 'jobs-list', method: 'GET', path: R('/jobs'), handler: list, bodycheck: false, mutating: false },
    { name: 'job', method: 'GET', path: R(J), handler: job, bodycheck: false, mutating: false },
    { name: 'receipt', method: 'GET', path: R(`${J}/receipt`), handler: receipt, bodycheck: false, mutating: false },
    { name: 'arm', method: 'POST', path: R(`${J}/arm`), handler: command('arm'), bodycheck: true, mutating: true },
    { name: 'skip', method: 'POST', path: R(`${J}/skip`), handler: command('skip'), bodycheck: true, mutating: true },
    { name: 'stop', method: 'POST', path: R(`${J}/stop`), handler: command('stop'), bodycheck: true, mutating: true },
    { name: 'resume', method: 'POST', path: R(`${J}/resume`), handler: command('resume'), bodycheck: true, mutating: true },
    { name: 'close', method: 'POST', path: R(`${J}/close`), handler: command('close'), bodycheck: true, mutating: true },
    { name: 'lease', method: 'POST', path: R(`${C}/lease`), handler: lease, bodycheck: true, mutating: true },
    { name: 'events-append', method: 'POST', path: R(`${C}/events`), handler: eventsAppend, bodycheck: true, mutating: true },
    { name: 'tickets', method: 'POST', path: R(`${C}/tickets`), handler: tickets, bodycheck: true, mutating: true },
    { name: 'resolve', method: 'POST', path: R(`${C}/resolve`), handler: resolve, bodycheck: true, mutating: true },
    { name: 'privacycash-lane', method: 'POST', path: R(`${J}/privacycash/lane`), handler: pcLane, bodycheck: false, mutating: false },
    { name: 'stream', method: 'GET', path: R(`${J}/events`), handler: stream, bodycheck: false, mutating: false },
    { name: 'sources-list', method: 'GET', path: R('/sources'), handler: sourcesList, bodycheck: false, mutating: false },
    { name: 'sources-tries', method: 'GET', path: R('/sources/tries/([0-9a-f]{64})'), handler: sourcesTries, bodycheck: false, mutating: false },
    { name: 'sources-add', method: 'POST', path: R('/sources'), handler: sourcesAdd, bodycheck: true, mutating: false },
    { name: 'message-put', method: 'PUT', path: R('/messages/([0-9a-f]{64})'), handler: messagePut, bodycheck: false, mutating: false },
    { name: 'message-get', method: 'GET', path: R('/messages/([0-9a-f]{64})'), handler: messageGet, bodycheck: false, mutating: false },
  ]

  const handle = (req: IncomingMessage, res: ServerResponse): void => {
    const t0 = performance.now()
    const method = req.method === 'GET' || req.method === 'POST' || req.method === 'PUT' ? req.method : 'OTHER'
    let name = 'unmatched'
    let guardId: string | null = null
    void (async () => {
      try {
        guardRequest(req, guard)
        const target = req.url ?? ''
        const url = new URL(target.startsWith('/') ? target : '/', 'http://api.invalid')
        const r = target.startsWith('/') ? ROUTES.find((x) => x.method === req.method && x.path.test(url.pathname)) : undefined
        const body = req.method === 'POST' ? await readJson(req) : undefined
        if (r === undefined) {
          guardId = 'api.route'
          sendJson(res, 404, { error: { guard: 'api.route', message: 'no such endpoint' } }, req.complete ? {} : { connection: 'close' })
          return
        }
        name = r.name
        if (r.bodycheck) bodycheck(body)
        const m = r.path.exec(url.pathname)!
        await r.handler(req, res, { url, body, id: m[1] ?? '', chain: (m[2] as Chain | undefined) ?? null })
      } catch (e) {
        guardId = sendError(req, res, e)
      } finally {
        log(`api ${method} ${name} ${res.statusCode} ${Math.round(performance.now() - t0)}ms${guardId === null ? '' : ` guard=${guardId}`}`)
      }
    })()
  }

  return { handle, leases, sse, registry, latch, controls, routes: ROUTES.map((r) => ({ name: r.name, method: r.method, mutating: r.mutating })) }
}

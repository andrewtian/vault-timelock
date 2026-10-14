// cli/test/job-client.test.ts — the `vt job …` client commands (src/job/*; plan Task C5), in-process and through a
// spawned stub (test/fixtures/job-stub.ts), against:
//   · the contract replay server (packages/core/contract/replay-server.ts) over the contract's HTTP fixtures, plus a
//     few derived ones (same response bodies; requests in the canonical by-digest form vt sends): the --json outputs
//     are the contract bodies byte for byte;
//   · test-owned fake API and relay servers on ephemeral 127.0.0.1 ports that record every request.
// The fixed stack ports are never bound. Every message, key and address is synthetic. Typed words come from a queue
// (JobIo.ask), as readTypedWord would read them from /dev/tty.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { cpSync, mkdirSync, readFileSync, realpathSync, symlinkSync, writeFileSync, truncateSync } from 'node:fs'
import { createServer, type IncomingHttpHeaders, type Server, type ServerResponse } from 'node:http'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Chain, JobDef, JobState, JournalEvent, Network } from '@vault-timelock/core/contracts'
import { MESSAGE_MAX, sseFrame, sseHeartbeat } from '@vault-timelock/core/contracts'
import { jobId, normalizeJob, reduce, sha256Hex } from '@vault-timelock/core/job'
import { computeArmCaps, toArmCap } from '@vault-timelock/core/engine/arm-caps.js'
import { CANON, GWEI } from '@vault-timelock/core/chains/constants.js'
import type { JobIo, Ports } from '../src/job/client.ts'
import { jobCommand } from '../src/job/index.ts'
import type { ArmDeps } from '../src/job/arm.ts'
import { MAINNET_TICKS, sameAmount } from '../src/job/arm.ts'
import { helpText } from '../src/help.ts'
import { normalizeText } from '../src/job/validate.ts'
import { deniedBecause, firstLine } from '../src/job/message-file.ts'
import { CANARY, CLI, IPV4, rejectsWith, removeDir, tempDir } from './lib.ts'
import type * as ReplayModule from '../../packages/core/contract/replay-server.ts'

const REPLAY_URL = new URL('../../contract/replay-server.ts', import.meta.resolve('@vault-timelock/core/contracts'))
const CONTRACT_FIXTURES = fileURLToPath(new URL('../../contract/fixtures/', import.meta.resolve('@vault-timelock/core/contracts')))
const STUB = join(CLI, 'test', 'fixtures', 'job-stub.ts')
const TOKEN = 'ab'.repeat(32)
const NOW = 1_791_504_000_000
const ETH_KEY = '0x8739Eb87B3d11f221Df63454F8D229a1A4F4049C'
const ETH_DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
const SOL_KEY = '9xx7qC7uwTAeaSo7T5Gk9canYBosFh1pMQaDmQEa83Tb'
const STUCK_TX = '0x36fdade817f9f181a52d8200201bb8da61413fde25cb34a147c4e9e4c35cadb4'

let T = ''
let VTH = ''
let replay: typeof ReplayModule
const servers: Server[] = []

before(async () => {
  T = tempDir('vt-c5-')
  VTH = join(T, 'vt-home')
  for (const n of ['local', 'testnet', 'mainnet'] as const) {
    mkdirSync(join(VTH, n), { recursive: true, mode: 0o700 })
    writeFileSync(join(VTH, n, 'api.token'), TOKEN, { mode: 0o600 })
  }
  replay = await import(REPLAY_URL.href) as typeof ReplayModule
})
after(async () => {
  for (const s of servers) { s.closeAllConnections(); await new Promise<void>((r) => s.close(() => r())) }
  removeDir(T)
})

// ---- io

interface Cap { io: JobIo; out: () => string; err: () => string; asked: string[] }
function mkIo(network: Network, ports: Partial<Ports>, o: { answers?: Array<string | undefined>; signal?: AbortSignal; home?: string; env?: Record<string, string> } = {}): Cap {
  let out = '', err = ''
  const asked: string[] = []
  const answers = [...(o.answers ?? [])]
  const io: JobIo = {
    network, env: o.env ?? { HOME: T, VT_HOME: o.home ?? VTH }, cwd: T, ports: { page: 1, relay: 1, api: 1, ...ports },
    out: (t) => { out += t }, err: (t) => { err += t },
    ask: async (p) => { asked.push(p); return answers.length > 0 ? answers.shift() : undefined },
    now: () => NOW,
    ...(o.signal === undefined ? {} : { signal: o.signal }),
  }
  return { io, out: () => out, err: () => err, asked }
}

// ---- a recording fake server (the API or the relay)

interface Seen { method: string; path: string; headers: IncomingHttpHeaders; body: Buffer }
type Handler = (req: Seen, res: ServerResponse) => void
interface Fake { port: number; seen: Seen[]; on(method: string, path: string | RegExp, h: Handler): void; reset(): void }

async function fake(): Promise<Fake> {
  const routes: Array<{ method: string; path: string | RegExp; h: Handler }> = []
  const seen: Seen[] = []
  const s = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      const r: Seen = { method: req.method ?? '', path: req.url ?? '', headers: req.headers, body: Buffer.concat(chunks) }
      seen.push(r)
      const pathname = r.path.split('?')[0]
      const route = [...routes].reverse().find((x) => x.method === r.method && (typeof x.path === 'string' ? x.path === pathname : x.path.test(pathname)))
      if (route === undefined) return json(res, 404, { error: { guard: 'api.route', message: 'no such endpoint' } })
      route.h(r, res)
    })
  })
  servers.push(s)
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', () => r()))
  const port = (s.address() as { port: number }).port
  return { port, seen, on: (method, path, h) => { routes.push({ method, path, h }) }, reset: () => { routes.length = 0; seen.length = 0 } }
}
function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify(body))
}
const bodyOf = (s: Seen): unknown => JSON.parse(s.body.toString('utf8'))
const only = (f: Fake, method: string, path: string | RegExp): Seen[] => f.seen.filter((s) => s.method === method && (typeof path === 'string' ? s.path.split('?')[0] === path : path.test(s.path)))

// ---- job helpers

function jobFile(dir: string, input: Record<string, unknown>, name = 'job.json'): string {
  mkdirSync(dir, { recursive: true })
  const p = join(dir, name)
  writeFileSync(p, JSON.stringify(input, null, 2))
  return p
}
const ethChain = (over: Record<string, unknown> = {}) => ({ mode: 'drain', publishMode: 'eth.calldata.null', feeStrategy: 'passive', distinctCopies: true, keyAddress: ETH_KEY, budgetUsd: 10, maxTipGwei: 3, clawbackTo: null, ...over })
const solChain = (over: Record<string, unknown> = {}) => ({ mode: { copies: 1 }, feeStrategy: 'economy', distinctCopies: true, keyAddress: SOL_KEY, budgetUsd: 10, maxCuPrice: 2_000_000, clawbackTo: null, ...over })
const TEXT = 'A synthetic vt fixture message.\nIt has two lines.\n'

// A job whose chains are READY (key loaded, funds affordable), as GET /jobs/:id answers it.
function readyView(input: Record<string, unknown>, network: Network, o: { phases?: Partial<Record<Chain, 'skip-funds'>> } = {}) {
  const { def } = normalizeJob(input, { network })
  const id = jobId(def)
  const ev: JournalEvent[] = []
  const add = (chain: Chain | null, by: JournalEvent['by'], type: string, data: Record<string, unknown>): void => {
    ev.push({ v: 1, seq: ev.length, at: NOW, prev: '', chain, by, gen: chain === null ? null : 1, type: type as JournalEvent['type'], data })
  }
  add(null, 'api', 'created', { jobId: id, defSha256: sha256Hex(JSON.stringify(def)) })
  for (const c of ['eth', 'sol'] as const) {
    if (def.chains[c] === undefined) continue
    add(c, 'cli', 'key-loaded', { address: def.chains[c]!.keyAddress })
    if (o.phases?.[c] !== 'skip-funds') add(c, 'cli', 'funds', { balance: '1', affordable: true, nextCopyCost: '1' })
  }
  const state = reduce(def, ev)
  return { id, def, state, view: { id, def, state, leases: Object.fromEntries(Object.keys(def.chains).map((c) => [c, null])), seq: state.seq, serverNowMs: NOW } }
}

// The fake API of one job: /status, GET /jobs/:id, GET /messages/:sha, POST /jobs/:id/arm (recorded).
function serveJob(api: Fake, network: Network, v: ReturnType<typeof readyView>, text: string, o: { statusNetwork?: Network } = {}): void {
  api.on('GET', '/status', (_r, res) => json(res, 200, { network: o.statusNetwork ?? network, networks: {}, mainnetSends: 'LOCKED', jobSends: 'LOCKED', build: 'dev', confined: true, legacyLatch: 'clear', serverNowMs: NOW }))
  api.on('GET', `/jobs/${v.id}`, (_r, res) => json(res, 200, v.view))
  api.on('GET', `/messages/${v.def.messageSha256}`, (_r, res) => { res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' }); res.end(Buffer.from(text, 'utf8')) })
  api.on('POST', `/jobs/${v.id}/arm`, (r, res) => {
    const b = bodyOf(r) as { chains: Chain[]; caps: Record<string, unknown> }
    json(res, 200, { armed: { armedAt: NOW, releaseAt: NOW + 15_000, countdownSec: 15, schedule: { order: b.chains, offsetSec: Object.fromEntries(b.chains.map((c, i) => [c, i * 30])) }, caps: b.caps, sources: {} } })
  })
}

// The fake relay: identity, a price, ETH fee history and balances, SOL rent and balances.
interface RelayOpts { network: Network; ethBalance?: bigint; solBalance?: bigint; identityOk?: boolean; price?: unknown; ethNonce?: number; solSigs?: number; isTor?: boolean | null }
function serveRelay(relay: Fake, o: RelayOpts): void {
  relay.on('GET', '/relay/status', (_r, res) => json(res, 200, { network: o.network, build: 'dev', confined: true, identity: { eth: { ok: o.identityOk ?? true }, sol: { ok: o.identityOk ?? true } }, endpoints: { eth: 1, sol: 1 } }))
  relay.on('GET', '/relay/tor', (_r, res) => json(res, 200, { isTor: o.isTor === undefined ? true : o.isTor, torRoles: [] }))
  relay.on('GET', '/relay/price', (_r, res) => json(res, 200, o.price ?? PRICE))
  const rpc = (r: Seen, res: ServerResponse, result: (m: string, p: unknown[]) => unknown): void => {
    const b = bodyOf(r) as { id: number; method: string; params: unknown[] }
    json(res, 200, { jsonrpc: '2.0', id: b.id, result: result(b.method, b.params) })
  }
  relay.on('POST', '/relay/eth', (r, res) => rpc(r, res, (m) => {
    if (m === 'eth_feeHistory') return { oldestBlock: '0x0', baseFeePerGas: ['0x3b9aca00', '0x3b9aca00'], gasUsedRatio: [0.5], reward: [['0x2dc6c0', '0x5f5e100']] }
    if (m === 'eth_getBalance') return `0x${(o.ethBalance ?? 10n ** 15n).toString(16)}`
    if (m === 'eth_getTransactionCount') return `0x${(o.ethNonce ?? 0).toString(16)}`
    throw new Error(`unexpected eth method ${m}`)
  }))
  relay.on('POST', '/relay/sol', (r, res) => rpc(r, res, (m) => {
    if (m === 'getMinimumBalanceForRentExemption') return 890_880
    if (m === 'getSignaturesForAddress') return Array.from({ length: o.solSigs ?? 0 }, (_, i) => ({ signature: `sig${i}`, memo: 'm' }))
    if (m === 'getTransaction') return { transaction: { message: { accountKeys: [SOL_KEY] } } }
    if (m === 'getBalance') return { context: { slot: 1 }, value: Number(o.solBalance ?? 10n ** 8n) }
    throw new Error(`unexpected sol method ${m}`)
  }))
}
const PRICE = { fixture: true, source: 'fixture', prices: { SOL: { usd: 150 }, ETH: { usd: 3000 } }, fetchedAt: NOW - 1_000 }
// The fees the fake relay implies for each strategy (assess.js): passive = p10 of the base fees + the passive tip.
const PASSIVE_FEES = { nextBase: GWEI, tip: CANON.PASSIVE_ETH_TIP, maxFee: GWEI + CANON.PASSIVE_ETH_TIP }

function headersOk(s: Seen, port: number): void {
  assert.equal(s.headers.host, `127.0.0.1:${port}`)
  assert.equal(s.headers.authorization, `Bearer ${TOKEN}`)
  for (const h of ['origin', 'sec-fetch-site', 'cookie', 'referer']) assert.equal(s.headers[h], undefined, `no ${h}`)
}

// =====================================================================================================================
// validate / create
// =====================================================================================================================

test('validate: offline, the canonical definition and the id the contract fixture names (inline, --message-file and by digest alike)', async () => {
  const d = join(T, 'validate')
  const fx = JSON.parse(readFileSync(join(CONTRACT_FIXTURES, 'http', 'jobs-create-201.json'), 'utf8'))
  const input = fx.request.body as Record<string, unknown>
  writeFileSync(join(d + '-msg.txt'), TEXT)
  const variants: string[][] = [
    [jobFile(d, input, 'inline.json')],
    [jobFile(d, { ...input, message: undefined }, 'file.json'), '--message-file', join(d + '-msg.txt')],
    [jobFile(d, { ...input, message: undefined, messageSha256: fx.response.body.def.messageSha256, messageBytes: 50 }, 'digest.json')],
  ]
  for (const [f, ...more] of variants) {
    const c = mkIo('local', {})
    assert.equal(await jobCommand(['validate', f, ...more, '--json'], c.io), 0)
    assert.deepEqual(JSON.parse(c.out()), { id: fx.response.body.id, def: fx.response.body.def })
    const h = mkIo('local', {})
    assert.equal(await jobCommand(['validate', f, ...more], h.io), 0)
    assert.match(h.out(), new RegExp(`job ${fx.response.body.id} {2}local`))
  }
  // Another network's job is refused for this one (core normalizeJob).
  await rejectsWith(() => jobCommand(['validate', variants[0][0]], mkIo('testnet', {}).io), 'job.network')
})

// PF-S fix round 1 (N-6): a NEW mainnet job names clawbackTo on each eth / sol chain; `vt job validate` / `create` refuse it with the
// core message, which names the field.
test('validate: a mainnet eth or sol lane without clawbackTo is refused (job.clawback-required) and the message names chains.<chain>.clawbackTo', async () => {
  const d = join(T, 'validate-clawback-required')
  const eth = { mode: 'drain', distinctCopies: true, keyAddress: '0x8739Eb87B3d11f221Df63454F8D229a1A4F4049C', budgetUsd: 10, clawbackTo: null }
  const sol = { mode: { copies: 1 }, distinctCopies: true, keyAddress: '9xx7qC7uwTAeaSo7T5Gk9canYBosFh1pMQaDmQEa83Tb', budgetUsd: 5, clawbackTo: null }
  for (const [c, lane] of [['eth', eth], ['sol', sol]] as const) {
    const job = { format: 'vt-job/1', network: 'mainnet', name: `mainnet ${c}`, message: TEXT, chains: { [c]: lane } }
    await assert.rejects(() => jobCommand(['validate', jobFile(d, job, `no-clawback-${c}.json`)], mkIo('mainnet', {}).io),
      (e: unknown) => (e as { guardId?: string }).guardId === 'job.clawback-required' && new RegExp(`^chains\\.${c}\\.clawbackTo is required on mainnet`).test((e as Error).message), c)
  }
  const ok = mkIo('mainnet', {})
  const named = { format: 'vt-job/1', network: 'mainnet', name: 'mainnet eth', message: TEXT, chains: { eth: { ...eth, clawbackTo: '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6' } } }
  assert.equal(await jobCommand(['validate', jobFile(d, named, 'with-clawback.json')], ok.io), 0)
})

// Eminors fix 1 (I-1): a NEW btc job without maxFeeRateSatVb is refused with the suggested value (the page prefills the same rule).
test('validate: a btc lane without maxFeeRateSatVb is refused (job.btc-fee-ceiling) and the message names the field, the range and the suggested value', async () => {
  const d = join(T, 'validate-btc-ceiling')
  const btcAddr = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080'
  const job = { format: 'vt-job/1', network: 'local', name: 'btc job', message: TEXT, chains: { btc: { mode: { copies: 1 }, distinctCopies: true, keyAddress: btcAddr, budgetUsd: 5, clawbackTo: null } } }
  await assert.rejects(() => jobCommand(['validate', jobFile(d, job, 'no-ceiling.json')], mkIo('local', {}).io), (e: unknown) => (e as { guardId?: string }).guardId === 'job.btc-fee-ceiling' && /maxFeeRateSatVb is required.*1\.\.500.*Suggested: 25/.test((e as Error).message))
  const ok = mkIo('local', {})
  assert.equal(await jobCommand(['validate', jobFile(d, { ...job, chains: { btc: { ...job.chains.btc, maxFeeRateSatVb: 25 } } }, 'with-ceiling.json')], ok.io), 0)
})

// M1.2 (c): a precompile clawbackTo is refused when the job is validated/created (core E6), with the claw-back's own guard id.
test('validate: a clawbackTo that is a precompile is refused (job.clawback-precompile); null stays job.clawback', async () => {
  const d = join(T, 'validate-precompile')
  const fx = JSON.parse(readFileSync(join(CONTRACT_FIXTURES, 'http', 'jobs-create-201.json'), 'utf8'))
  const input = fx.request.body as { chains: { eth: object } }
  const withTo = (to: string, name: string) => jobFile(d, { ...input, chains: { ...input.chains, eth: { ...input.chains.eth, clawbackTo: to } } }, name)
  await rejectsWith(() => jobCommand(['validate', withTo('0x0000000000000000000000000000000000000009', 'pre.json')], mkIo('local', {}).io), 'job.clawback-precompile')
  await rejectsWith(() => jobCommand(['validate', withTo('0x0000000000000000000000000000000000000000', 'null.json')], mkIo('local', {}).io), 'job.clawback')
})

test('create (replay server): the text is PUT by digest, then the canonical definition is POSTed; --json is the contract body exactly; 201 then 200', async () => {
  const dir = join(T, 'replay-create')
  cpSync(CONTRACT_FIXTURES, dir, { recursive: true })
  const read = (n: string) => JSON.parse(readFileSync(join(dir, 'http', `${n}.json`), 'utf8'))
  const c201 = read('jobs-create-201'), c200 = read('jobs-create-200')
  // Derived fixtures: the same answers, for the request vt sends (the canonical definition, by digest).
  const byDigest = (from: typeof c201, name: string, after: string | null) => ({ ...from, name, after, request: { ...from.request, body: from.response.body.def } })
  writeFileSync(join(dir, 'http', 'jobs-create-201-digest.json'), JSON.stringify(byDigest(c201, 'jobs-create-201-digest', null)))
  writeFileSync(join(dir, 'http', 'jobs-create-200-digest.json'), JSON.stringify(byDigest(c200, 'jobs-create-200-digest', 'jobs-create-201-digest')))
  const r = await replay.startReplayServer({ fixturesDir: dir, token: TOKEN })
  try {
    const f = jobFile(join(T, 'replay-create-job'), c201.request.body)
    const a = mkIo('local', { api: r.port })
    assert.equal(await jobCommand(['create', f, '--json'], a.io), 0, a.err())
    assert.deepEqual(JSON.parse(a.out()), c201.response.body)
    assert.equal(a.out(), `${JSON.stringify(c201.response.body)}\n`, 'byte for byte')
    assert.ok(r.served.has('messages-put-201') && r.served.has('jobs-create-201-digest'))
    const b = mkIo('local', { api: r.port })
    assert.equal(await jobCommand(['create', f], b.io), 0, b.err())
    assert.match(b.out(), /already exists/)
    assert.ok(r.served.has('jobs-create-200-digest'))
  } finally { await r.close() }
})

const LINE = (i: number) => `${String(i).padStart(6, '0')} vt-c5 synthetic payload ü 日本 🙂\n`
function bigText(min: number): string {
  let s = ''
  for (let i = 0; Buffer.byteLength(s) < min; i++) s += LINE(i)
  return s
}

test('create with a 100 KB --message-file (in-process): confirmed with `publish`, the exact file bytes go up by digest; POST /jobs carries the digest, never the text', async () => {
  const api = await fake()
  const text = bigText(100_000)
  const d = join(T, 'big')
  mkdirSync(join(d, 'texts'), { recursive: true })
  writeFileSync(join(d, 'texts', 'm.txt'), text)
  const f = jobFile(d, { format: 'vt-job/1', network: 'local', name: 'big text', chains: { eth: ethChain() } })
  const sha = sha256Hex(Buffer.from(text, 'utf8'))
  api.on('PUT', `/messages/${sha}`, (r, res) => json(res, 201, { sha256: sha256Hex(r.body), bytes: r.body.length }))
  api.on('POST', '/jobs', (r, res) => {
    const { def } = normalizeJob(bodyOf(r), { network: 'local' })
    json(res, 201, { id: jobId(def), def, state: { phase: 'DEFINED', chains: { eth: { phase: 'AWAITING_KEY' } } } })
  })
  const c = mkIo('local', { api: api.port }, { answers: ['publish'] })
  assert.equal(await jobCommand(['create', f, '--message-file', join(d, 'texts', 'm.txt')], c.io), 0, c.err())
  assert.equal(c.asked.length, 1)
  const [put] = only(api, 'PUT', `/messages/${sha}`)
  assert.ok(put.body.equals(readFileSync(join(d, 'texts', 'm.txt'))), 'the file bytes, unchanged')
  assert.ok(put.body.length >= 100_000)
  assert.equal(put.headers['content-type'], 'text/plain; charset=utf-8')
  headersOk(put, api.port)
  const [post] = only(api, 'POST', '/jobs')
  headersOk(post, api.port)
  assert.equal(post.headers['content-type'], 'application/json')
  const def = bodyOf(post) as JobDef & { message?: unknown; messageFile?: unknown }
  assert.equal(def.messageSha256, sha)
  assert.equal(def.messageBytes, put.body.length)
  assert.equal(def.message, undefined)
  assert.equal(def.messageFile, undefined)
  assert.ok(post.body.length < 64 * 1024 && !post.body.toString('utf8').includes('synthetic payload'))
  assert.equal(api.seen.length, 2, 'one upload, one create')
  assert.match(c.out(), /created/)
})

// Spawns the stub (src/job/index.ts as main.ts runs it) and resolves with its exit code and output.
function runStub(args: readonly string[], env: Record<string, string>): Promise<{ code: number | null; out: string; err: string; pid: number }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [STUB, ...args], { env, stdio: ['ignore', 'pipe', 'pipe'] })
    let out = '', err = ''
    child.stdout.setEncoding('utf8').on('data', (s: string) => { out += s })
    child.stderr.setEncoding('utf8').on('data', (s: string) => { err += s })
    child.on('error', reject)
    child.on('close', (code) => resolve({ code, out, err, pid: child.pid ?? -1 }))
  })
}
const stubEnv = () => ({ PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: T, VT_HOME: VTH })
const stubArgv = (err: string): { argv: string[]; execArgv: string[] } => JSON.parse(/^vt-job-stub argv (.*)$/m.exec(err)![1])

test('a spawned vt job create (100 KB --message-file): the uploading process\'s argv holds the paths and the digest, never a message byte', async () => {
  const api = await fake()
  const text = bigText(100_000)
  const d = join(T, 'stub-big')
  mkdirSync(d, { recursive: true })
  writeFileSync(join(d, 'message.txt'), text)
  const f = jobFile(d, { format: 'vt-job/1', network: 'local', name: 'stub text', chains: { eth: ethChain() } })
  const sha = sha256Hex(Buffer.from(text, 'utf8'))
  let putSeen = 0
  api.on('PUT', `/messages/${sha}`, (r, res) => { putSeen = r.body.length; json(res, 201, { sha256: sha256Hex(r.body), bytes: r.body.length }) })
  api.on('POST', '/jobs', (r, res) => {
    const { def } = normalizeJob(bodyOf(r), { network: 'local' })
    json(res, 201, { id: jobId(def), def, state: { phase: 'DEFINED', chains: { eth: { phase: 'AWAITING_KEY' } } } })
  })
  const args = ['create', f, '--message-file', join(d, 'message.txt'), '--yes-publish-file', sha] // no terminal here: the digest confirms
  const r = await runStub([String(api.port), '1', 'local', ...args], stubEnv())
  assert.equal(r.code, 0, r.err)
  assert.equal(putSeen, Buffer.byteLength(text), 'the whole text went up, by digest')
  const seen = stubArgv(r.err)
  assert.deepEqual(seen.argv.slice(1), [STUB, String(api.port), '1', 'local', ...args])
  const flat = JSON.stringify(seen)
  for (const probe of ['synthetic payload', '日本', '🙂', LINE(0).trim(), LINE(1234).trim(), text.slice(5_000, 5_040)]) assert.ok(!flat.includes(probe), `argv holds no message bytes (${probe.length})`)
  assert.equal(seen.execArgv.length, 0)
  const [post] = only(api, 'POST', '/jobs')
  assert.ok(!post.body.toString('utf8').includes('synthetic payload'), 'nor does the JSON body')
})

test('a spawned vt job command: an API refusal prints `refused <guard>: <message>` (sanitised) and exits 2; nothing on stdout', async () => {
  const api = await fake()
  const id = 'e3d45f73cf65abaa'
  api.on('POST', `/jobs/${id}/close`, (_r, res) => json(res, 409, { error: { guard: 'job.state', message: `close only a settled chain \u001b[2J\u001b]0;x\u0007 from ${CANARY}` } }))
  const r = await runStub([String(api.port), '1', 'local', 'close', id, '--chain', 'eth'], stubEnv())
  assert.equal(r.code, 2)
  assert.equal(r.out, '')
  const lines = r.err.split('\n').filter((l) => l !== '' && !l.startsWith('vt-job-stub argv'))
  assert.equal(lines.length, 1, r.err)
  assert.match(lines[0], /^refused job\.state: close only a settled chain/)
  assert.ok(!r.err.includes('\u001b') && !r.err.includes('\u0007') && !r.err.includes(CANARY) && !IPV4.test(lines[0]), lines[0])
  // A non-refusal answer is exit 1, a fixed text.
  api.on('POST', `/jobs/${id}/close`, (_r, res) => { res.writeHead(500); res.end(`boom ${CANARY}`) })
  const r2 = await runStub([String(api.port), '1', 'local', 'close', id, '--chain', 'eth'], stubEnv())
  assert.equal(r2.code, 1)
  assert.match(r2.err, /vt: error: the local jobs API answered HTTP 500 without a refusal/)
  assert.ok(!r2.err.includes(CANARY))
})

test('the API not answering: a fixed text that names no address (exit 1, not a refusal)', async () => {
  const s = await fake()
  const port = s.port
  await new Promise<void>((r) => { const srv = servers.pop()!; srv.close(() => r()) }) // nothing listens there now
  const c = mkIo('local', { api: port })
  await assert.rejects(jobCommand(['list'], c.io), (e: Error) => {
    assert.match(e.message, /^the local jobs API \(port \d+\) did not answer/)
    assert.ok(!IPV4.test(e.message), e.message)
    return true
  })
  // A change that got no answer may have been applied: the text says so (a read's does not).
  await assert.rejects(jobCommand(['stop', 'e3d45f73cf65abaa'], mkIo('local', { api: port }).io), /did not answer: .*; the change may or may not have been applied: vt job status shows it$/)
  // No token: the stack is not up.
  await assert.rejects(jobCommand(['list'], mkIo('local', { api: port }, { home: join(T, 'no-home') }).io), /no readable API token for local/)
})

test('create: message sources and strict decoding (job.message-source, message.utf8, message.too-long, message.control); the file is never rewritten', async () => {
  const api = await fake()
  const d = join(T, 'sources')
  mkdirSync(d, { recursive: true })
  const base = { format: 'vt-job/1', network: 'local', name: 'sources', chains: { eth: ethChain() } }
  const io = () => mkIo('local', { api: api.port }).io
  writeFileSync(join(d, 'ok.txt'), TEXT)
  const plain = jobFile(d, base, 'plain.json')
  const mf = (name: string) => ['--message-file', join(d, name), '--yes-publish-file', 'f'.repeat(64)]
  // Two sources at once.
  await rejectsWith(() => jobCommand(['create', jobFile(d, { ...base, message: TEXT }, 'two.json'), ...mf('ok.txt')], io()), 'job.message-source')
  await rejectsWith(() => jobCommand(['create', jobFile(d, { ...base, messageSha256: 'a'.repeat(64), messageBytes: 3 }, 'two2.json'), ...mf('ok.txt')], io()), 'job.message-source')
  // Undecodable bytes: refused, never replaced (a lossy decoder would have produced U+FFFD).
  writeFileSync(join(d, 'bad.txt'), Buffer.from([0x61, 0x62, 0xff, 0x0a]))
  await rejectsWith(() => jobCommand(['create', plain, ...mf('bad.txt')], io()), 'message.utf8')
  // Over 16 MiB: refused from the size alone (a sparse file; nothing is read).
  writeFileSync(join(d, 'huge.txt'), '')
  truncateSync(join(d, 'huge.txt'), MESSAGE_MAX + 1)
  // vt's own size check, before any byte is read (core's later check would refuse with the same id after reading 16 MiB).
  await assert.rejects(jobCommand(['create', plain, ...mf('huge.txt')], io()), (e: Error & { guardId?: string }) => e.guardId === 'message.too-long' && /it is not read$/.test(e.message))
  // CRLF, TAB and a BOM are refused (core validateMessage), never rewritten without --normalize.
  for (const [name, bytes] of [['crlf', 'a\r\nb\n'], ['tab', 'a\tb\n'], ['bom', '\ufeffab\n']] as const) {
    writeFileSync(join(d, `${name}.txt`), bytes)
    await rejectsWith(() => jobCommand(['create', plain, ...mf(`${name}.txt`)], io()), 'message.control')
  }
  assert.equal(api.seen.length, 0, 'nothing was sent for any of them')
  assert.equal(readFileSync(join(d, 'crlf.txt'), 'utf8'), 'a\r\nb\n', 'the file is unchanged')
})

test('create --normalize: only when given; CRLF/CR -> LF and TAB -> spaces (tab stops of 8), a summary, the normalized text uploaded', async () => {
  assert.deepEqual(normalizeText('a\r\nb\rc\td\n\tx\n12345678\ty\n'), {
    text: 'a\nb\nc       d\n        x\n12345678        y\n', summary: { crlf: 1, cr: 1, tabs: 3, changed: true },
  })
  assert.deepEqual(normalizeText('plain\n').summary, { crlf: 0, cr: 0, tabs: 0, changed: false })
  const api = await fake()
  const d = join(T, 'normalize')
  mkdirSync(d, { recursive: true })
  writeFileSync(join(d, 'w.txt'), 'line one\r\nline\ttwo\r\n')
  const f = jobFile(d, { format: 'vt-job/1', network: 'local', name: 'normalize', chains: { eth: ethChain() } })
  const want = 'line one\nline    two\n'
  const sha = sha256Hex(want)
  api.on('PUT', `/messages/${sha}`, (r, res) => json(res, 201, { sha256: sha256Hex(r.body), bytes: r.body.length }))
  api.on('POST', '/jobs', (r, res) => { const { def } = normalizeJob(bodyOf(r), { network: 'local' }); json(res, 201, { id: jobId(def), def, state: { phase: 'DEFINED', chains: {} } }) })
  const c = mkIo('local', { api: api.port })
  // The digest that confirms the upload is the NORMALIZED text's (the one vt shows); the file's own would not do.
  await rejectsWith(() => jobCommand(['create', f, '--message-file', join(d, 'w.txt'), '--normalize', '--yes-publish-file', sha256Hex(readFileSync(join(d, 'w.txt')))], mkIo('local', { api: api.port }).io), 'vt.publish-confirm')
  assert.equal(await jobCommand(['create', f, '--message-file', join(d, 'w.txt'), '--normalize', '--yes-publish-file', sha], c.io), 0, c.err())
  assert.match(c.err(), new RegExp(`sha256 ${sha} \\(after --normalize\\)`))
  assert.match(c.err(), /--normalize: 2 CRLF -> LF, 1 TAB -> spaces \(tab stops every 8 columns\)/)
  assert.equal(only(api, 'PUT', `/messages/${sha}`)[0].body.toString('utf8'), want)
  assert.equal(readFileSync(join(d, 'w.txt'), 'utf8'), 'line one\r\nline\ttwo\r\n', 'the file is unchanged')
  // Nothing to change: said so, and the bytes are the file's.
  const n = mkIo('local', {})
  writeFileSync(join(d, 'plain.txt'), TEXT)
  assert.equal(await jobCommand(['validate', jobFile(d, { format: 'vt-job/1', network: 'local', name: 'plain', chains: { eth: ethChain() } }, 'p.json'), '--message-file', join(d, 'plain.txt'), '--normalize'], n.io), 0)
  assert.match(n.err(), /--normalize: nothing to change/)
  await assert.rejects(jobCommand(['validate', jobFile(d, { format: 'vt-job/1', network: 'local', name: 'digest', messageSha256: 'a'.repeat(64), messageBytes: 3, chains: { eth: ethChain() } }, 'd.json'), '--normalize'], mkIo('local', {}).io), /--normalize needs the message text/)
})

test('create: the upload\'s answer must name the same digest and size (message.digest); no job is posted then', async () => {
  const api = await fake()
  const d = join(T, 'digest')
  const f = jobFile(d, { format: 'vt-job/1', network: 'local', name: 'digest', message: TEXT, chains: { eth: ethChain() } })
  api.on('PUT', /^\/messages\//, (_r, res) => json(res, 201, { sha256: 'b'.repeat(64), bytes: 50 }))
  await rejectsWith(() => jobCommand(['create', f], mkIo('local', { api: api.port }).io), 'message.digest')
  assert.equal(only(api, 'POST', '/jobs').length, 0)
  api.on('PUT', /^\/messages\//, (r, res) => json(res, 201, { sha256: sha256Hex(r.body), bytes: r.body.length + 1 }))
  await rejectsWith(() => jobCommand(['create', f], mkIo('local', { api: api.port }).io), 'message.digest')
  assert.equal(only(api, 'POST', '/jobs').length, 0)
})

// =====================================================================================================================
// the message file: argv only, realpath + denylist, explicit publish confirmation (security review)
// Every HOME, $OUT, VT_HOME and package here is synthetic, under this test's temp dir (never the real ~/.ssh or a real
// package); the checks look at names, links and file types only.
// =====================================================================================================================

const PKG = '1password-Test-timelock-20261009T000000Z'
const SYNTH = 'synthetic text, never a secret\n'
function synthHome(name: string): { home: string; out: string; env: Record<string, string> } {
  const home = join(T, `mf-home-${name}`), out = join(T, `mf-out-${name}`)
  mkdirSync(home, { recursive: true })
  mkdirSync(out, { recursive: true })
  return { home, out, env: { HOME: home, VT_HOME: VTH, VAULT_TIMELOCK_DIR: out } }
}
const put = (p: string, text = SYNTH): string => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); return p }
const mfJob = (dir: string) => jobFile(dir, { format: 'vt-job/1', network: 'local', name: 'message file', chains: { eth: ethChain() } }, 'mf-job.json')
async function validateWith(env: Record<string, string>, file: string): Promise<Cap> {
  const c = mkIo('local', {}, { env })
  assert.equal(await jobCommand(['validate', mfJob(join(T, 'mf-jobs')), '--message-file', file], c.io), 0, c.err())
  return c
}
const refusedPath = (env: Record<string, string>, file: string, why?: RegExp) => assert.rejects(
  jobCommand(['validate', mfJob(join(T, 'mf-jobs')), '--message-file', file], mkIo('local', {}, { env }).io),
  (e: Error & { guardId?: string }) => { assert.equal(e.guardId, 'vt.message-path', `${file}: ${e.message}`); if (why) assert.match(e.message, why); assert.ok(!e.message.includes(SYNTH.trim()), 'no content'); return true })

test('message file, argv only: a job JSON naming a file (messageFile) is refused before anything is read or sent', async () => {
  const api = await fake()
  const { env } = synthHome('argv')
  const canary = put(join(T, 'mf-canary', 'not-to-publish.txt'))
  const d = join(T, 'mf-argv')
  for (const messageFile of [canary, 'not-to-publish.txt', 7]) {
    const f = jobFile(d, { format: 'vt-job/1', network: 'local', name: 'json path', messageFile, chains: { eth: ethChain() } })
    for (const sub of ['validate', 'create']) {
      await assert.rejects(jobCommand([sub, f], mkIo('local', { api: api.port }, { env }).io), (e: Error & { guardId?: string }) => {
        assert.equal(e.guardId, 'vt.message-path')
        assert.match(e.message, /a job file may not name a message file .*--message-file <path>/)
        return true
      })
    }
  }
  assert.equal(api.seen.length, 0, 'nothing was uploaded or created')
})

test('message file path: ../ traversal, links into ~/.ssh, a FIFO, a directory, a missing or oversized file are refused', async () => {
  const { home, env } = synthHome('paths')
  const key = put(join(home, '.ssh', 'id_synthetic'))
  mkdirSync(join(home, 'docs', 'deep'), { recursive: true })
  await refusedPath(env, join(home, 'docs', 'deep', '..', '..', '.ssh', 'id_synthetic'), /a key or credential directory/)
  await refusedPath(env, `mf-home-paths/docs/../.ssh/id_synthetic`, /a key or credential directory/) // relative to cwd (T)
  symlinkSync(key, join(T, 'mf-link-to-key'))
  await refusedPath(env, join(T, 'mf-link-to-key'), /symbolic link/)
  symlinkSync(join(home, '.ssh'), join(T, 'mf-linkdir'))
  await refusedPath(env, join(T, 'mf-linkdir', 'id_synthetic'), /a key or credential directory/) // the real path decides
  const fifo = join(T, 'mf-fifo')
  assert.equal(spawnSync('/usr/bin/mkfifo', [fifo]).status, 0)
  await refusedPath(env, fifo, /not a regular file/)
  mkdirSync(join(T, 'mf-dir'), { recursive: true })
  await refusedPath(env, join(T, 'mf-dir'), /not a regular file/)
  await refusedPath(env, join(T, 'mf-missing.txt'), /does not exist/)
  const huge = put(join(T, 'mf-huge.txt'), '')
  truncateSync(huge, MESSAGE_MAX + 1)
  await assert.rejects(jobCommand(['validate', mfJob(join(T, 'mf-jobs')), '--message-file', huge], mkIo('local', {}, { env }).io), (e: Error & { guardId?: string }) => e.guardId === 'message.too-long' && /it is not read$/.test(e.message))
  // A plain file elsewhere is fine, and so is a link in a DIRECTORY on the way (it resolves to an allowed place).
  const ok = put(join(T, 'mf-plain', 'message.txt'))
  await validateWith(env, ok)
  symlinkSync(join(T, 'mf-plain'), join(T, 'mf-plain-link'))
  const c = await validateWith(env, join(T, 'mf-plain-link', 'message.txt'))
  assert.ok(c.err().includes(`message file  ${realpathSync.native(ok)}`), 'the REAL path is shown')
})

test('message file denylist: keys and credentials, VT_HOME, ~/p/1password-*, /tmp/vt-asdf.*, and the sealer\'s own file names, anywhere', async () => {
  const { home, env } = synthHome('deny')
  for (const d of ['.ssh', '.gnupg', join('Library', 'Keychains'), '.aws', join('.config', 'op'), '.op']) {
    await refusedPath(env, put(join(home, d, 'sub', 'notes.txt')), /a key or credential directory/)
  }
  await refusedPath(env, put(join(VTH, 'local', 'notes.txt')), /vt's state \(VT_HOME\)/)
  await refusedPath(env, put(join(home, '.local', 'state', 'vt', 'notes.txt')), /vt's state/)
  await refusedPath(env, put(join(home, 'p', '1password-Test-export', 'notes.txt')), /~\/p\/1password-\*/)
  await validateWith(env, put(join(home, 'p', 'other-project', 'message.txt'))) // the rest of ~/p is not denied
  // /tmp/vt-asdf.* is never created here: the rule is checked on the path alone.
  for (const p of ['/tmp/vt-asdf.c5-synthetic-nonexistent/m.txt', '/private/tmp/vt-asdf.c5-synthetic-nonexistent/m.txt']) assert.match(String(deniedBecause(p, env)), /vt-asdf/)
  for (const name of ['identity.key', 'vault.tar.gz.age', 'unlock-TIME.age', 'x.AGE', 'SEALED-plaintext.txt', 'STRUCTURE.txt', 'structure.txt', 'MANIFEST.csv', 'BLANK-AT-SEAL.txt', 'api.token', 'relay-ticket.key']) {
    await refusedPath(env, put(join(T, 'mf-names', name)), /never published/)
  }
})

test('message file in $OUT or a package: only the package\'s own SEALED.txt; STRUCTURE.txt, SEALED-plaintext.txt, README.txt, items/, files/, restored/ refused', async () => {
  const { out, env } = synthHome('pkg')
  const sealed = 'vault-timelock-sealed/1 (a synthetic package)\n'
  const pkgs = [join(out, PKG), join(T, 'mf-desk', PKG), join(T, 'mf-desk', 'notes.txt-timelock-20261009T000000Z')]
  // A package copied somewhere under another name is recognised by a sealer's file in it.
  const copy = join(T, 'mf-copy')
  put(join(copy, 'vault.tar.gz.age'), 'synthetic')
  for (const p of [...pkgs, copy]) {
    const c = await validateWith(env, put(join(p, 'SEALED.txt'), sealed))
    assert.match(c.err(), /first line: vault-timelock-sealed\/1 \(a synthetic package\)/)
    for (const name of ['STRUCTURE.txt', 'SEALED-plaintext.txt', 'README.txt', 'BLANK-AT-SEAL.txt', 'MANIFEST.csv', 'unlock-KEY.age', 'identity.key', 'notes.txt']) {
      await refusedPath(env, put(join(p, name)))
    }
    for (const sub of [['items', 'x.json'], ['files', 'a', 'b.txt'], ['restored', 'SEALED.txt'], ['Restored', 'SEALED.txt'], ['sub', 'SEALED.txt']]) {
      await refusedPath(env, put(join(p, ...sub), sealed), /only a package's own SEALED\.txt/)
    }
  }
  // $OUT itself: nothing but a package's SEALED.txt.
  await refusedPath(env, put(join(out, 'SEALED.txt'), sealed), /only a package's own SEALED\.txt/)
  await refusedPath(env, put(join(out, 'keystore', 'x.txt')), /only a package's own SEALED\.txt/)
  await refusedPath(env, put(join(out, 'lifecycle', 'notes.txt')), /only a package's own SEALED\.txt/)
  // $OUT's defaults count too ($XDG_DATA_HOME/vault-timelock, ~/.local/share/vault-timelock), whatever VAULT_TIMELOCK_DIR says.
  const h2 = synthHome('pkg-default')
  await refusedPath(h2.env, put(join(h2.home, '.local', 'share', 'vault-timelock', 'stray.txt')), /only a package's own SEALED\.txt/)
  await refusedPath({ ...h2.env, XDG_DATA_HOME: join(T, 'mf-xdg') }, put(join(T, 'mf-xdg', 'vault-timelock', 'stray.txt')), /only a package's own SEALED\.txt/)
})

test('message file under ~/p/1password-* (controller ruling, C6): a package\'s own SEALED.txt only; everything else there stays refused, also through a linked directory', async () => {
  const { home, env } = synthHome('p1pw')
  const sealed = 'vault-timelock-sealed/1 (a synthetic package in ~/p)\n'
  const pkg = join(home, 'p', PKG)
  const nested = join(home, 'p', '1password-Test-export', 'Test-timelock-20261009T000000Z')
  const marked = join(home, 'p', '1password-Test-copy') // not named like a package, but holding a sealer's file
  put(join(marked, 'unlock-TIME.age'), 'synthetic')
  for (const p of [pkg, nested, marked]) {
    const c = await validateWith(env, put(join(p, 'SEALED.txt'), sealed))
    assert.match(c.err(), /first line: vault-timelock-sealed\/1 \(a synthetic package in ~\/p\)/)
    for (const name of ['STRUCTURE.txt', 'SEALED-plaintext.txt', 'README.txt', 'BLANK-AT-SEAL.txt', 'MANIFEST.csv', 'notes.txt', 'sealed.txt', 'SEALED.txt.bak', 'SEALED.md']) {
      await refusedPath(env, put(join(p, name), sealed))
    }
    for (const sub of [['items', 'SEALED.txt'], ['files', 'SEALED.txt'], ['restored', 'SEALED.txt'], ['RESTORED', 'SEALED.txt'], ['sub', 'SEALED.txt']]) {
      await refusedPath(env, put(join(p, ...sub), sealed), /~\/p\/1password-\*/)
    }
  }
  // A ~/p/1password-* directory that is not a package (an export): even a SEALED.txt in it is refused, and so is a
  // package-named directory below items/ or files/.
  await refusedPath(env, put(join(home, 'p', '1password-Test-export', 'SEALED.txt'), sealed), /~\/p\/1password-\*\): from there only a package's own SEALED\.txt/)
  await refusedPath(env, put(join(home, 'p', '1password-Test-export', 'items', 'x-timelock-20261009T000000Z', 'SEALED.txt'), sealed), /~\/p\/1password-\*/)
  await refusedPath(env, put(join(home, 'p', '1password-Test-export', 'files', PKG, 'SEALED.txt'), sealed), /~\/p\/1password-\*/)
  // ~/p/1password-* as a LINK to another disk (here: another synthetic dir): the path as given still names it.
  const elsewhere = join(T, 'mf-p1pw-elsewhere')
  put(join(elsewhere, 'items', 'x.json'), '{"synthetic":true}\n')
  put(join(elsewhere, 'notes.txt'))
  symlinkSync(elsewhere, join(home, 'p', '1password-Test-linked'))
  await refusedPath(env, join(home, 'p', '1password-Test-linked', 'items', 'x.json'), /~\/p\/1password-\*/)
  await refusedPath(env, join(home, 'p', '1password-Test-linked', 'notes.txt'), /~\/p\/1password-\*/)
  put(join(elsewhere, 'SEALED.txt'), sealed)
  assert.equal(deniedBecause(join(elsewhere, 'SEALED.txt'), env), null, 'the real path alone looks harmless (not a package dir)')
  await refusedPath(env, join(home, 'p', '1password-Test-linked', 'SEALED.txt'), /~\/p\/1password-\*/)
  // ~/p itself a link: both the given and the real ~/p count.
  const h2 = synthHome('p1pw-linked-p')
  const realP = join(T, 'mf-real-p')
  put(join(realP, '1password-Test-export', 'notes.txt'))
  put(join(realP, PKG, 'SEALED.txt'), sealed)
  symlinkSync(realP, join(h2.home, 'p'))
  await refusedPath(h2.env, join(h2.home, 'p', '1password-Test-export', 'notes.txt'), /~\/p\/1password-\*/)
  await refusedPath(h2.env, join(realP, '1password-Test-export', 'notes.txt'), /~\/p\/1password-\*/)
  await validateWith(h2.env, join(h2.home, 'p', PKG, 'SEALED.txt'))
})

test('publishing a message file needs `publish` typed at the terminal, or --yes-publish-file naming its exact sha256; it shows the real path, size, digest and escaped first line first', async () => {
  const api = await fake()
  const { env } = synthHome('confirm')
  const text = `a​b${'x'.repeat(100)}\nsecond line\n`
  const file = put(join(T, 'mf-confirm', 'message.txt'), text)
  const sha = sha256Hex(text)
  api.on('PUT', `/messages/${sha}`, (r, res) => json(res, 201, { sha256: sha256Hex(r.body), bytes: r.body.length }))
  api.on('POST', '/jobs', (r, res) => { const { def } = normalizeJob(bodyOf(r), { network: 'local' }); json(res, 201, { id: jobId(def), def, state: { phase: 'DEFINED', chains: {} } }) })
  const job = mfJob(join(T, 'mf-confirm-job'))
  const create = (args: string[], answers: Array<string | undefined>) => { const c = mkIo('local', { api: api.port }, { env, answers }); return { c, p: jobCommand(['create', job, '--message-file', file, ...args], c.io) } }
  const puts = () => only(api, 'PUT', `/messages/${sha}`).length
  // No terminal and no digest; a wrong word; a wrong digest: refused, nothing uploaded.
  for (const [args, answers] of [[[], []], [[], ['Publish']], [[], ['yes']], [['--yes-publish-file', 'e'.repeat(64)], []]] as Array<[string[], string[]]>) {
    const { c, p } = create(args, answers)
    await rejectsWith(() => p, 'vt.publish-confirm')
    assert.match(c.err(), /PUBLISHED, permanently and publicly/)
  }
  assert.equal(puts(), 0)
  for (const bad of [['--yes-publish-file', 'E'.repeat(64)], ['--yes-publish-file', 'abc']]) await assert.rejects(create(bad, []).p, (e: Error) => e.name === 'UsageError')
  await assert.rejects(jobCommand(['create', jobFile(join(T, 'mf-inline'), { format: 'vt-job/1', network: 'local', name: 'inline', message: TEXT, chains: { eth: ethChain() } }), '--yes-publish-file', sha], mkIo('local', { api: api.port }, { env }).io), /confirms a --message-file; there is none/)
  assert.equal(puts(), 0)
  // `publish` typed: shown first, then uploaded.
  const typed = create([], ['publish'])
  assert.equal(await typed.p, 0, typed.c.err())
  assert.equal(typed.c.asked.length, 1)
  assert.match(typed.c.asked[0], /^Type publish to upload this file \(\d+ bytes, sha256 [0-9a-f]{16}…\) for publication: $/)
  const shown = typed.c.err()
  assert.ok(shown.includes(`message file  ${realpathSync.native(file)}\n  ${Buffer.byteLength(text)} bytes  sha256 ${sha}\n`), shown)
  assert.ok(shown.includes(`  first line: a\\u{200b}b${'x'.repeat(77)}…\n`), shown)
  assert.ok(!shown.includes('second line'), 'only the first line')
  assert.equal(firstLine('short\nnext'), 'short')
  assert.equal(puts(), 1)
  // The exact digest: no prompt at all.
  const flagged = create(['--yes-publish-file', sha], [])
  assert.equal(await flagged.p, 0, flagged.c.err())
  assert.deepEqual(flagged.c.asked, [])
  assert.equal(puts(), 2)
})

test('the confirmed digest binds the uploaded bytes: the file rewritten while the operator reads the prompt is never re-read', async () => {
  const api = await fake()
  const { env } = synthHome('bind')
  const text = 'the synthetic text that was shown and confirmed\n'
  const file = put(join(T, 'mf-bind', 'message.txt'), text)
  const sha = sha256Hex(text)
  api.on('PUT', /^\/messages\//, (r, res) => json(res, 201, { sha256: sha256Hex(r.body), bytes: r.body.length }))
  api.on('POST', '/jobs', (r, res) => { const { def } = normalizeJob(bodyOf(r), { network: 'local' }); json(res, 201, { id: jobId(def), def, state: { phase: 'DEFINED', chains: {} } }) })
  const c = mkIo('local', { api: api.port }, { env })
  c.io.ask = async (p) => { c.asked.push(p); writeFileSync(file, 'SWAPPED after the confirmation prompt was shown\n'); return 'publish' }
  assert.equal(await jobCommand(['create', mfJob(join(T, 'mf-bind-job')), '--message-file', file], c.io), 0, c.err())
  assert.match(c.err(), new RegExp(`sha256 ${sha}`))
  const sent = only(api, 'PUT', /^\/messages\//)
  assert.equal(sent.length, 1)
  assert.equal(sent[0].path, `/messages/${sha}`)
  assert.equal(sent[0].body.toString('utf8'), text, 'exactly the bytes read once and confirmed')
  assert.equal((bodyOf(only(api, 'POST', '/jobs')[0]) as { messageSha256: string }).messageSha256, sha)
})

// =====================================================================================================================
// list / status / watch / receipt
// =====================================================================================================================

test('list: --json is the API body exactly; the summary names each job', async () => {
  const api = await fake()
  const body = { jobs: [{ id: 'e3d45f73cf65abaa', name: 'eth drain', createdAt: NOW, phase: 'ARMED', chains: { eth: { phase: 'ARMED', reason: null }, sol: { phase: 'SKIPPED', reason: 'not armed' } } }], serverNowMs: NOW }
  api.on('GET', '/jobs', (_r, res) => json(res, 200, body))
  const j = mkIo('local', { api: api.port })
  assert.equal(await jobCommand(['list', '--json'], j.io), 0)
  assert.equal(j.out(), `${JSON.stringify(body)}\n`)
  const h = mkIo('local', { api: api.port })
  await jobCommand(['list'], h.io)
  assert.match(h.out(), /^e3d45f73cf65abaa {2}ARMED {4}2026-.*eth ARMED, sol SKIPPED \(not armed\) {2}"eth drain"$/m)
  headersOk(api.seen[0], api.port)
})

test('status (replay server): --json is GET /jobs/:id\'s contract body exactly; job.missing is a refusal (exit 2)', async () => {
  const r = await replay.startReplayServer({ token: TOKEN })
  try {
    const fx = JSON.parse(readFileSync(join(CONTRACT_FIXTURES, 'http', 'jobs-get-200.json'), 'utf8'))
    const j = mkIo('local', { api: r.port })
    assert.equal(await jobCommand(['status', 'e3d45f73cf65abaa', '--json'], j.io), 0)
    assert.equal(j.out(), `${JSON.stringify(fx.response.body)}\n`)
    const h = mkIo('local', { api: r.port })
    await jobCommand(['status', 'e3d45f73cf65abaa'], h.io)
    assert.match(h.out(), /job e3d45f73cf65abaa {2}local {2}"eth drain to the null address" {2}DEFINED/)
    assert.match(h.out(), /eth {2}AWAITING_KEY/)
    assert.match(h.out(), /not armed/)
    await rejectsWith(() => jobCommand(['status', '0000000000000000'], mkIo('local', { api: r.port }).io), 'job.missing')
  } finally { await r.close() }
  await assert.rejects(jobCommand(['status', 'NOT-AN-ID'], mkIo('local', {}).io), /a job id is 16 lowercase hex/)
})

test('status of a STUCK chain prints the exact resolve line for each open attempt', async () => {
  const api = await fake()
  const fx = (n: string) => JSON.parse(readFileSync(join(CONTRACT_FIXTURES, 'journals', n), 'utf8'))
  const def = fx('09a-stuck.def.json') as JobDef, state = fx('09a-stuck.state.json') as JobState
  const id = jobId(def)
  api.on('GET', `/jobs/${id}`, (_r, res) => json(res, 200, { id, def, state, leases: { eth: { holder: 'cli', gen: 2, expiresAt: NOW + 9_000 } }, seq: state.seq, serverNowMs: NOW }))
  const c = mkIo('local', { api: api.port })
  await jobCommand(['status', id], c.io)
  assert.match(c.out(), new RegExp(`STUCK copy 1 part 1/\\d+: ${STUCK_TX}`))
  assert.ok(c.out().includes(`vt job resolve ${id} --chain eth --tx ${STUCK_TX} mark-done|mark-failed`))
  assert.match(c.out(), /lease cli gen 2 \(expires in 9 s\)/)
})

test('M5c: status of a STOPPED chain names its stop (stopCode, stopClass): resumable → vt job resume; final → the reason and the way out; resumed but not yet reopened → still STOPPED, run again', async () => {
  const fx = (n: string) => JSON.parse(readFileSync(join(CONTRACT_FIXTURES, 'journals', n), 'utf8'))
  const def = fx('14-stopped.def.json') as JobDef, state = fx('14-stopped.state.json') as JobState
  const id = jobId(def)
  const show = async (eth: Partial<JobState['chains']['eth']>): Promise<string> => {
    const api = await fake()
    api.on('GET', `/jobs/${id}`, (_r, res) => json(res, 200, { id, def, state: { ...state, chains: { ...state.chains, eth: { ...state.chains.eth!, ...eth } } }, leases: { eth: null }, seq: state.seq, serverNowMs: NOW }))
    const c = mkIo('local', { api: api.port })
    assert.equal(await jobCommand(['status', id], c.io), 0)
    return c.out()
  }
  assert.equal(state.chains.eth!.stopClass, 'resumable')
  assert.match(await show({}), new RegExp(`stop operator-stop \\(resumable\\): vt job resume ${id} --chain eth lifts it`))
  const fin = await show({ stopCode: 'spend-cap', stopClass: 'final' })
  assert.match(fin, /eth is stopped for good: .*\(spend-cap\) — resume is refused; claw back what is left/)
  assert.ok(!/vt job resume/.test(fin))
  const resumed = await show({ stopLatched: undefined, stopRequested: false })
  assert.match(resumed, /resumed, but still STOPPED: the next vt job run \(or Run here\) reopens it once its pre-start checks pass; a check that failed journaled nothing/)
  assert.ok(!/resumed, but still STOPPED/.test(await show({ stopLatched: undefined, stopRequested: true })), 'a new stop request: not shown as resumed')
})

async function until(cond: () => boolean, ms = 10_000): Promise<void> {
  const end = Date.now() + ms
  while (!cond()) {
    if (Date.now() > end) throw new Error('timed out waiting')
    await new Promise((r) => setTimeout(r, 20))
  }
}

test('watch (replay server): every journal event once, in order; --json prints the journal lines exactly; Ctrl-C (abort) ends it, exit 0', async () => {
  const dir = join(T, 'replay-watch')
  cpSync(CONTRACT_FIXTURES, dir, { recursive: true })
  const def = JSON.parse(readFileSync(join(dir, 'journals', '05a-copies-done.def.json'), 'utf8'))
  const state = JSON.parse(readFileSync(join(dir, 'journals', '05a-copies-done.state.json'), 'utf8'))
  const id = jobId(def)
  writeFileSync(join(dir, 'http', 'jobs-get-05a.json'), JSON.stringify({
    name: 'jobs-get-05a', covers: 'derived (C5): GET /jobs/:id of the 05a journal', after: null,
    request: { method: 'GET', path: `/jobs/${id}`, headers: { host: '{{host}}', authorization: 'Bearer {{token}}' } },
    response: { status: 200, headers: { 'content-type': 'application/json; charset=utf-8' }, body: { id, def, state, leases: { eth: null }, seq: state.seq, serverNowMs: NOW } },
    volatile: [],
  }))
  const lines = readFileSync(join(dir, 'journals', '05a-copies-done.jsonl'), 'utf8').split('\n').filter((l) => l !== '')
  const r = await replay.startReplayServer({ fixturesDir: dir, token: TOKEN })
  try {
    for (const mode of ['--json', 'human'] as const) {
      const ctl = new AbortController()
      const c = mkIo('local', { api: r.port }, { signal: ctl.signal })
      const p = jobCommand(['watch', id, ...(mode === '--json' ? ['--json'] : [])], c.io)
      await until(() => c.out().split('\n').length > lines.length)
      ctl.abort()
      assert.equal(await p, 0)
      const out = c.out().split('\n').filter((l) => l !== '')
      if (mode === '--json') assert.deepEqual(out, lines)
      else {
        assert.deepEqual(out.map((l) => l.split(' ')[0]), lines.map((_l, i) => `#${i}`))
        assert.match(out[9], /eth reassembled .*copy 1 reassembled ✓/)
        assert.match(out[5], /eth intent \[browser gen 1\] copy 1 part 1\/1 attempt 1 0x30c0b7c7/)
      }
    }
    // status --watch continues after the status it printed (from seq + 1: nothing more in this journal).
    const ctl = new AbortController()
    const s = mkIo('local', { api: r.port }, { signal: ctl.signal })
    const p = jobCommand(['status', id, '--watch'], s.io)
    await until(() => s.out().includes('copies included 1'))
    await new Promise((x) => setTimeout(x, 200))
    ctl.abort()
    assert.equal(await p, 0)
    assert.ok(!s.out().includes('#10 '), 'no event at or below the status seq is printed again')
  } finally { await r.close() }
})

test('watch: a dropped stream resumes with Last-Event-ID (and from=last+1); a duplicate seq is never printed twice', async () => {
  const api = await fake()
  const id = 'e3d45f73cf65abaa'
  const ev = (seq: number, type = 'note', data: Record<string, unknown> = { text: `n${seq}` }) => JSON.stringify({ v: 1, seq, at: NOW + seq, prev: '', chain: 'eth', by: 'cli', gen: 1, type, data })
  api.on('GET', `/jobs/${id}`, (_r, res) => json(res, 200, { id, def: {}, state: { phase: 'RUNNING', chains: {} }, leases: {}, seq: 0, serverNowMs: NOW }))
  let calls = 0
  api.on('GET', `/jobs/${id}/events`, (_r, res) => {
    calls++
    res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8' })
    if (calls === 1) { res.write(sseFrame(0, ev(0)) + sseFrame(1, ev(1)) + sseHeartbeat(NOW) + sseFrame(2, ev(2))); setTimeout(() => res.destroy(), 50) }
    else res.write(sseFrame(2, ev(2)) + sseFrame(3, ev(3)) + sseFrame(4, ev(4)))
  })
  const ctl = new AbortController()
  const c = mkIo('local', { api: api.port }, { signal: ctl.signal })
  const p = jobCommand(['watch', id], c.io)
  await until(() => c.out().includes('#4 '))
  ctl.abort()
  assert.equal(await p, 0)
  const out = c.out().split('\n').filter((l) => l !== '').map((l) => l.split(' ')[0])
  assert.deepEqual(out, ['#0', '#1', '#2', '#3', '#4'])
  const streams = only(api, 'GET', `/jobs/${id}/events`)
  assert.equal(streams[0].path, `/jobs/${id}/events?from=0`)
  assert.equal(streams[0].headers['last-event-id'], undefined)
  assert.equal(streams[1].path, `/jobs/${id}/events?from=3`)
  assert.equal(streams[1].headers['last-event-id'], '2')
  headersOk(streams[1], api.port)
  assert.match(c.err(), /stream was interrupted; reconnecting/)
})

test('watch prints through C4\'s printer: an executor\'s free text cannot move the cursor or print an address', async () => {
  const api = await fake()
  const id = 'e3d45f73cf65abaa'
  const nasty = `go \u001b[2J\u001b[H\u001b]8;;x\u0007over\r‮evil ${CANARY} and [2001:db8::7]:443 and 0x7f.1 done`
  const ev = JSON.stringify({ v: 1, seq: 0, at: NOW, prev: '', chain: 'eth', by: 'cli', gen: 1, type: 'note', data: { text: nasty } })
  const ev2 = JSON.stringify({ v: 1, seq: 1, at: NOW, prev: '', chain: 'eth', by: 'cli', gen: 1, type: 'paused', data: { reason: `relay at ${CANARY}:5181 unreachable` } })
  api.on('GET', `/jobs/${id}`, (_r, res) => json(res, 200, { id, def: {}, state: { phase: 'RUNNING', chains: {} }, leases: {}, seq: 0, serverNowMs: NOW }))
  api.on('GET', `/jobs/${id}/events`, (_r, res) => { res.writeHead(200, { 'content-type': 'text/event-stream' }); res.write(sseFrame(0, ev) + sseFrame(1, ev2)) })
  for (const mode of [[], ['--json']]) {
    const ctl = new AbortController()
    const c = mkIo('local', { api: api.port }, { signal: ctl.signal })
    const p = jobCommand(['watch', id, ...mode], c.io)
    await until(() => c.out().split('\n').length > 2)
    ctl.abort()
    await p
    const out = c.out()
    assert.ok(!/[\u0000-\u0008\u000b-\u001f\u007f‮]/.test(out), JSON.stringify(out))
    for (const leak of [CANARY, '2001:db8::7', '0x7f.1']) assert.ok(!out.includes(leak), `${leak} redacted`)
    assert.match(out, /\[ip\]/)
  }
})

test('watch ends by itself once the job is DONE (checked after an event that can finish a chain)', async () => {
  const api = await fake()
  const fx = (n: string) => JSON.parse(readFileSync(join(CONTRACT_FIXTURES, 'journals', n), 'utf8'))
  const def = fx('05b-closed.def.json') as JobDef
  const id = jobId(def)
  const lines = readFileSync(join(CONTRACT_FIXTURES, 'journals', '05b-closed.jsonl'), 'utf8').split('\n').filter((l) => l !== '')
  const last = (JSON.parse(lines[lines.length - 1]) as { seq: number }).seq
  let phase = 'ARMED'
  api.on('GET', `/jobs/${id}`, (_r, res) => json(res, 200, { id, def, state: { phase, chains: {} }, leases: {}, seq: last, serverNowMs: NOW }))
  api.on('GET', `/jobs/${id}/events`, (_r, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' })
    res.write(lines.map((l) => sseFrame((JSON.parse(l) as { seq: number }).seq, l)).join(''))
    phase = 'DONE' // by the time vt asks again, the close has made it DONE; the stream stays open (heartbeats only)
  })
  const c = mkIo('local', { api: api.port })
  assert.equal(await jobCommand(['watch', id], c.io), 0)
  assert.match(c.out(), new RegExp(`#${last} .* close`))
  // A job that is DONE already: its events are printed, then it stops.
  const d = mkIo('local', { api: api.port })
  assert.equal(await jobCommand(['watch', id, '--json'], d.io), 0)
  assert.equal(d.out().split('\n').filter((l) => l !== '').length, lines.length)
})

test('receipt: stdout only (no --out); --json is the API\'s vt-receipt/1 exactly; the summary lists the landed transactions', async () => {
  const api = await fake()
  const id = 'e3d45f73cf65abaa'
  const receipt = {
    format: 'vt-receipt/1', jobId: id, name: 'eth drain', network: 'mainnet', messageSha256: 'c'.repeat(64), build: '0123456789ab',
    chains: { eth: { address: ETH_KEY, network: 'Ethereum mainnet · 1', mode: 'drain', phase: 'DONE', copiesIncluded: 1, reassembled: [{ copy: 1, ok: true }], spent: '21000', clawback: null,
      txs: [{ copy: 1, part: 1, txId: STUCK_TX, attempts: 2, block: '101', fee: '21000', readback: true, links: [{ label: 'Etherscan', href: `etherscan.io/tx/${STUCK_TX}`, copyOnly: true }] }] } },
  }
  api.on('GET', `/jobs/${id}/receipt`, (_r, res) => json(res, 200, receipt))
  const j = mkIo('mainnet', { api: api.port })
  assert.equal(await jobCommand(['receipt', id, '--json'], j.io), 0)
  assert.equal(j.out(), `${JSON.stringify(receipt)}\n`)
  const h = mkIo('mainnet', { api: api.port })
  await jobCommand(['receipt', id], h.io)
  assert.match(h.out(), /copy 1 part 1 {2}0x36fdade8.* {2}block 101 {2}fee 21000 {2}attempts 2 {2}readback ok/)
  assert.match(h.out(), /reassembled: copy 1 ✓/)
  await assert.rejects(jobCommand(['receipt', id, '--out', join(T, 'r.json')], mkIo('mainnet', { api: api.port }).io), /stdout only; there is no --out/)
  // A body that would print an address is not printed at all (fail closed).
  api.on('GET', `/jobs/${id}/receipt`, (_r, res) => json(res, 200, { ...receipt, name: `x ${CANARY}` }))
  const bad = mkIo('mainnet', { api: api.port })
  await rejectsWith(() => jobCommand(['receipt', id, '--json'], bad.io), 'vt.log-ip')
  assert.equal(bad.out(), '')
})

// =====================================================================================================================
// stop / resume / close / skip / resolve
// =====================================================================================================================

test('skip, stop, resume, close: the exact request bodies; usage errors never reach the API', async () => {
  const api = await fake()
  const id = 'e3d45f73cf65abaa'
  for (const sub of ['skip', 'stop', 'resume', 'close']) api.on('POST', `/jobs/${id}/${sub}`, (_r, res) => json(res, 200, sub === 'skip' ? { releaseAt: NOW } : { seq: 7 }))
  const run = async (args: string[]) => { const c = mkIo('local', { api: api.port }); assert.equal(await jobCommand(args, c.io), 0, c.err()); return c }
  await run(['skip', id])
  await run(['stop', id])
  await run(['stop', id, '--chain', 'sol'])
  await run(['resume', id, '--tip-cap-gwei', '2.5', '--cu-price-cap', '1000'])
  const close = await run(['close', id, '--chain', 'eth'])
  assert.match(close.out(), /closed eth of job e3d45f73cf65abaa \(seq 7\)/)
  assert.deepEqual(api.seen.map((s) => [s.path, bodyOf(s)]), [
    [`/jobs/${id}/skip`, {}],
    [`/jobs/${id}/stop`, { chain: null }],
    [`/jobs/${id}/stop`, { chain: 'sol' }],
    [`/jobs/${id}/resume`, { chain: null, tipCapGwei: '2.5', cuPriceCap: 1000 }],
    [`/jobs/${id}/close`, { chain: 'eth' }],
  ])
  for (const s of api.seen) { headersOk(s, api.port); assert.equal(s.headers['content-type'], 'application/json') }
  for (const args of [['close', id], ['stop', id, '--chain', 'doge'], ['resume', id, '--tip-cap-gwei', '1e3'], ['skip'], ['stop', id, '--chain'], ['bogus']]) {
    await assert.rejects(jobCommand(args, mkIo('local', { api: api.port }).io), (e: Error) => e.name === 'UsageError')
  }
  assert.equal(api.seen.length, 5)
})

test('R79b resume: lists the chains resumed and the ones refused with the API\'s reason; a final stop is a refusal; mainnet asks the typed word `resume` first', async () => {
  const api = await fake()
  const id = 'e3d45f73cf65abaa'
  api.on('POST', `/jobs/${id}/resume`, (_r, res) => json(res, 200, { seq: 9, resumed: ['eth'], refused: [{ chain: 'sol', guard: 'resume.final-stop', message: 'sol stopped on a readback mismatch; the way out is vt job close / clawback' }] }))
  const c = mkIo('local', { api: api.port })
  assert.equal(await jobCommand(['resume', id], c.io), 0, c.err())
  assert.match(c.out(), /resumed: eth/)
  assert.match(c.out(), /NOT resumed: sol — resume\.final-stop: sol stopped on a readback mismatch/)
  assert.match(c.out(), /a final stop is never lifted/)
  // a single-chain resume of a FINAL stop is the API's 409: printed as the refusal
  const f = await fake()
  f.on('POST', `/jobs/${id}/resume`, (_r, res) => json(res, 409, { error: { guard: 'resume.final-stop', message: 'eth is final-stopped (status 0)' } }))
  await rejectsWith(() => jobCommand(['resume', id, '--chain', 'eth'], mkIo('local', { api: f.port }).io), 'resume.final-stop')
  // an older answer without lists still prints the request line
  const o = await fake()
  o.on('POST', `/jobs/${id}/resume`, (_r, res) => json(res, 200, { seq: 3 }))
  const oc = mkIo('local', { api: o.port })
  assert.equal(await jobCommand(['resume', id], oc.io), 0)
  assert.match(oc.out(), /resume requested for every chain of job e3d45f73cf65abaa \(seq 3\)/)
  // mainnet: the typed word first, from the terminal; nothing is sent otherwise
  const m = await fake()
  m.on('POST', `/jobs/${id}/resume`, (_r, res) => json(res, 200, { seq: 4, resumed: ['eth'] }))
  await rejectsWith(() => jobCommand(['resume', id], mkIo('mainnet', { api: m.port }, { answers: ['Resume'] }).io), 'job.resume-typed')
  await rejectsWith(() => jobCommand(['resume', id], mkIo('mainnet', { api: m.port }, { answers: [] }).io), 'vt.tty-required')
  assert.equal(m.seen.length, 0, 'nothing was sent')
  const ok = mkIo('mainnet', { api: m.port }, { answers: ['resume'] })
  assert.equal(await jobCommand(['resume', id], ok.io), 0, ok.err())
  assert.match(ok.asked[0], /type resume/)
  assert.equal(m.seen.length, 1)
  // local: no question
  const lc = mkIo('local', { api: o.port })
  await jobCommand(['resume', id], lc.io)
  assert.deepEqual(lc.asked, [])
})

test('R79b text: help and the countdown hint say Ctrl-C detaches and s skips the countdown (nothing says it stops)', () => {
  const h = helpText()
  assert.match(h, /s skips the countdown; Ctrl-C DETACHES/)
  assert.ok(!/Ctrl-C stops each chain|status --watch\) follow the journal and resume after a dropped stream; Ctrl-C stops/.test(h))
  assert.match(h, /vt job resume <id> .*type resume/)
})

test('resolve: mark-failed says it frees no cap; local needs no typed word; mainnet needs `resolve` typed at the terminal', async () => {
  const api = await fake()
  const fx = (n: string) => JSON.parse(readFileSync(join(CONTRACT_FIXTURES, 'journals', n), 'utf8'))
  const def = fx('09a-stuck.def.json') as JobDef, state = fx('09a-stuck.state.json') as JobState
  const id = jobId(def)
  api.on('GET', `/jobs/${id}`, (_r, res) => json(res, 200, { id, def, state, leases: { eth: null }, seq: state.seq, serverNowMs: NOW }))
  api.on('POST', `/jobs/${id}/chains/eth/resolve`, (_r, res) => json(res, 200, { seq: 12 }))
  const local = mkIo('local', { api: api.port })
  assert.equal(await jobCommand(['resolve', id, '--chain', 'eth', '--tx', STUCK_TX, 'mark-failed'], local.io), 0)
  assert.match(local.out(), /frees NO cap capacity/)
  assert.match(local.out(), /recorded mark-failed for 0x36fdade8/)
  assert.deepEqual(local.asked, [])
  const posts = () => only(api, 'POST', `/jobs/${id}/chains/eth/resolve`)
  assert.deepEqual(bodyOf(posts()[0]), { txId: STUCK_TX, action: 'mark-failed' })
  // mainnet: the typed word, exactly
  const ok = mkIo('mainnet', { api: api.port }, { answers: ['resolve'] })
  assert.equal(await jobCommand(['resolve', id, '--chain', 'eth', '--tx', STUCK_TX, 'mark-done'], ok.io), 0)
  assert.equal(ok.asked.length, 1)
  assert.match(ok.out(), /mark-done counts the attempt as landed/)
  assert.deepEqual(bodyOf(posts()[1]), { txId: STUCK_TX, action: 'mark-done', typed: 'resolve' })
  await rejectsWith(() => jobCommand(['resolve', id, '--chain', 'eth', '--tx', STUCK_TX, 'mark-done'], mkIo('mainnet', { api: api.port }, { answers: ['Resolve'] }).io), 'job.resolve-typed')
  await rejectsWith(() => jobCommand(['resolve', id, '--chain', 'eth', '--tx', STUCK_TX, 'mark-done'], mkIo('mainnet', { api: api.port }, { answers: [] }).io), 'vt.tty-required')
  assert.equal(posts().length, 2, 'nothing was sent for the wrong word or without a terminal')
  for (const args of [['resolve', id, '--chain', 'eth', '--tx', 'nope', 'mark-done'], ['resolve', id, '--chain', 'eth', '--tx', STUCK_TX, 'mark-maybe'], ['resolve', id, '--tx', STUCK_TX, 'mark-done']]) {
    await assert.rejects(jobCommand(args, mkIo('local', { api: api.port }).io), (e: Error) => e.name === 'UsageError')
  }
})

// =====================================================================================================================
// arm
// =====================================================================================================================

interface ArmSetup { api: Fake; relay: Fake; v: ReturnType<typeof readyView>; io: (o?: { answers?: Array<string | undefined> }) => Cap }
async function armSetup(network: Network, input: Record<string, unknown>, relay: Omit<RelayOpts, 'network'> = {}, o: { statusNetwork?: Network; phases?: Partial<Record<Chain, 'skip-funds'>> } = {}): Promise<ArmSetup> {
  const api = await fake(), rl = await fake()
  const v = readyView(input, network, o)
  serveJob(api, network, v, TEXT, o)
  serveRelay(rl, { network, ...relay })
  return { api, relay: rl, v, io: (x = {}) => mkIo(network, { api: api.port, relay: rl.port }, x) }
}
// a new mainnet job names its claw-back address per eth / sol lane (PF-S fix round 1, N-6): filled in when the test leaves it null
const MAINNET_CLAWBACK: Record<string, string> = { eth: '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6', sol: 'G147qVmzynHL3EjQ8tvBGDms7u6FDCWbFfFmzNMZmg1x' }
const armInput = (network: Network, chains: Record<string, unknown>) => ({ format: 'vt-job/1', network, name: 'arm test', message: TEXT,
  chains: network !== 'mainnet' ? chains : Object.fromEntries(Object.entries(chains).map(([c, ch]) => [c, (ch as { clawbackTo?: unknown }).clawbackTo === null && MAINNET_CLAWBACK[c] ? { ...(ch as object), clawbackTo: MAINNET_CLAWBACK[c] } : ch])) })
const NO_LOCK: ArmDeps = { assertSendAllowed: () => {} }
const armPosts = (s: ArmSetup) => only(s.api, 'POST', `/jobs/${s.v.id}/arm`)

test('arm (local): caps from the relay through core computeArmCaps; no typed word below the cap; the ArmRequest is exact', async () => {
  const s = await armSetup('local', armInput('local', { eth: ethChain() }), { ethBalance: 10n ** 15n })
  const c = s.io()
  assert.equal(await jobCommand(['arm', s.v.id, '--countdown', '15', '--stagger', '5,10', '--json'], c.io), 0, c.err())
  assert.deepEqual(c.asked, [])
  const want = computeArmCaps(s.v.def, TEXT, { prices: PRICE, fees: { eth: PASSIVE_FEES }, balances: { eth: 10n ** 15n }, network: 'local', now: NOW })
  const [post] = armPosts(s)
  headersOk(post, s.api.port)
  assert.deepEqual(bodyOf(post), { chains: ['eth'], confirm: { typed: null, amounts: {} }, caps: { eth: toArmCap(want.eth) }, countdownSec: 15, stagger: [5, 10] })
  assert.equal(want.eth.overCap, false)
  assert.deepEqual(JSON.parse(c.out()).armed.caps, { eth: toArmCap(want.eth) }, '--json: the API body')
  assert.match(c.err(), /arm job [0-9a-f]{16} "arm test" on LOCAL/, 'the plan goes to stderr with --json')
  // The relay was read for the price, the fee history and the key's balance; never with the text.
  for (const r of s.relay.seen) assert.ok(!r.body.toString('utf8').includes('synthetic vt fixture'), 'no text leaves before Arm')
  assert.ok(only(s.relay, 'POST', '/relay/eth').some((r) => (bodyOf(r) as { method: string }).method === 'eth_feeHistory'))
})

test('arm over the R60 cap: `planned` shown in full, the typed amount compared in base units (0.0100 = 0.01; a rounded or longer value refused)', async () => {
  assert.equal(sameAmount('eth', '0.0100', '0.01'), true)
  assert.equal(sameAmount('eth', '0.01', '0.010000000000000001'), false)
  assert.equal(sameAmount('eth', '0.0100000000000000000', '0.01'), false, 'more decimals than ETH has')
  assert.equal(sameAmount('sol', '1.000000000', '1'), true)
  assert.equal(sameAmount('sol', '1.0000000001', '1'), false)
  assert.equal(sameAmount('eth', ' 0.01', '0.01'), false)
  const input = armInput('local', { eth: ethChain({ budgetUsd: 1000 }) })
  // 0.010000000000000001 ETH ($30) is over the $10 cap: 18 decimals, shown exactly.
  const bal = 10n ** 16n + 1n
  const s = await armSetup('local', input, { ethBalance: bal })
  const want = computeArmCaps(s.v.def, TEXT, { prices: PRICE, fees: { eth: PASSIVE_FEES }, balances: { eth: bal }, network: 'local', now: NOW }).eth
  assert.equal(want.planned, '0.010000000000000001')
  assert.equal(want.overCap, true)
  // A rounded amount: refused (arm.amount), nothing armed.
  const rounded = s.io({ answers: ['0.01'] })
  await rejectsWith(() => jobCommand(['arm', s.v.id], rounded.io), 'arm.amount')
  assert.equal(rounded.asked.length, 1)
  assert.ok(rounded.asked[0].includes('0.010000000000000001 ETH (= 10000000000000001 wei)'), rounded.asked[0])
  assert.match(rounded.out(), /planned 0\.010000000000000001 ETH/)
  // No terminal: refused before anything is armed.
  await rejectsWith(() => jobCommand(['arm', s.v.id], s.io({ answers: [] }).io), 'vt.tty-required')
  assert.equal(armPosts(s).length, 0)
  // One more decimal than ETH has: refused.
  await rejectsWith(() => jobCommand(['arm', s.v.id], s.io({ answers: ['0.0100000000000000010'] }).io), 'arm.amount')
  assert.equal(armPosts(s).length, 0)
  // The exact amount: armed, and the request carries `planned` itself.
  const exact = s.io({ answers: ['0.010000000000000001'] })
  assert.equal(await jobCommand(['arm', s.v.id], exact.io), 0, exact.err())
  assert.deepEqual((bodyOf(armPosts(s)[0]) as { confirm: unknown }).confirm, { typed: null, amounts: { eth: '0.010000000000000001' } })
  assert.match(exact.out(), /armed job [0-9a-f]{16}: release /)
  // Trailing zeros are the same base units: 0.0100 confirms a planned 0.01 ETH ($30), and `planned` is what is sent.
  const t = await armSetup('local', input, { ethBalance: 10n ** 16n })
  const z = t.io({ answers: ['0.0100'] })
  assert.equal(await jobCommand(['arm', t.v.id], z.io), 0, z.err())
  assert.ok(z.asked[0].includes('0.01 ETH (= 10000000000000000 wei)'), z.asked[0])
  assert.deepEqual((bodyOf(armPosts(t)[0]) as { confirm: unknown }).confirm, { typed: null, amounts: { eth: '0.01' } })
})

// M2 FLIP (applied, operator R78): the real client-side lock (C2's assertJobSendAllowed) no longer refuses a mainnet arm; the same input
// now reaches the ticks question and is refused there (arm.ticks), and `ticks` then `broadcast` must be typed exactly.
test('arm on mainnet: the job-send lock is lifted (the M2 flip), so the ticks question refuses the old input (arm.ticks) and nothing is armed; then `broadcast` typed exactly', async () => {
  const input = armInput('mainnet', { eth: ethChain() })
  const s = await armSetup('mainnet', input, { ethBalance: 10n ** 15n })
  const lifted = s.io({ answers: ['broadcast'] })
  await rejectsWith(() => jobCommand(['arm', s.v.id], lifted.io), 'arm.ticks')
  assert.equal(lifted.asked.length, 1, 'the ticks question was asked, and nothing after it')
  assert.match(lifted.asked[0], /^Type ticks/)
  await rejectsWith(() => jobCommand(['arm', s.v.id], s.io({ answers: ['ticks', 'Broadcast'] }).io), 'arm.typed')   // the real lock, the typed word
  assert.equal(armPosts(s).length, 0, 'nothing was armed')
  // With the client-side lock check stubbed (the API and the relay keep theirs), the typed word:
  await rejectsWith(() => jobCommand(['arm', s.v.id], s.io({ answers: ['ticks', 'Broadcast'] }).io, { arm: NO_LOCK }), 'arm.typed')
  await rejectsWith(() => jobCommand(['arm', s.v.id], s.io({ answers: [] }).io, { arm: NO_LOCK }), 'vt.tty-required')
  assert.equal(armPosts(s).length, 0)
  const ok = s.io({ answers: ['ticks', 'broadcast'] })
  assert.equal(await jobCommand(['arm', s.v.id], ok.io), 0, ok.err())   // the real lock: lifted
  assert.match(ok.asked[1], /^MAINNET: real funds; the publication is public and permanent\. Type broadcast to arm job [0-9a-f]{16} \(eth\): $/)
  assert.deepEqual((bodyOf(armPosts(s)[0]) as { confirm: unknown }).confirm, { typed: 'broadcast', amounts: {} })
  assert.match(ok.out(), /on MAINNET: real funds/)
})

// PF-C / M-5: `vt job arm` asks what the page asks.
test('arm: a lane key with history needs `again` typed per chain (ETH nonce > 0, SOL signed memos); none, no question', async () => {
  const input = armInput('local', { eth: ethChain(), sol: solChain() })
  const s = await armSetup('local', input, { ethBalance: 10n ** 15n, solBalance: 10n ** 8n, ethNonce: 3, solSigs: 2 })
  const no = s.io({ answers: ['yes', 'again'] })
  await rejectsWith(() => jobCommand(['arm', s.v.id], no.io), 'arm.again')
  assert.equal(armPosts(s).length, 0)
  assert.match(no.out(), /eth {2}KEY HISTORY: this lane key already sent 3 transactions/)
  assert.match(no.out(), /sol {2}KEY HISTORY: this lane key already sent 2 transactions/)
  const half = s.io({ answers: ['again', 'Again'] })
  await rejectsWith(() => jobCommand(['arm', s.v.id], half.io), 'arm.again')
  await rejectsWith(() => jobCommand(['arm', s.v.id], s.io({ answers: ['again'] }).io), 'vt.tty-required')
  assert.equal(armPosts(s).length, 0)
  const ok = s.io({ answers: ['again', 'again'] })
  assert.equal(await jobCommand(['arm', s.v.id], ok.io), 0, ok.err())
  assert.equal(ok.asked.length, 2)
  assert.equal(armPosts(s).length, 1)
  // only the chain with history is asked
  const t = await armSetup('local', input, { ethBalance: 10n ** 15n, solBalance: 10n ** 8n, ethNonce: 1 })
  const one = t.io({ answers: ['again'] })
  assert.equal(await jobCommand(['arm', t.v.id], one.io), 0, one.err())
  assert.deepEqual(one.asked.map((q) => q.split(':')[0]), ['eth'])
  // a history that cannot be read refuses (fail closed), nothing armed
  const u = await armSetup('local', armInput('local', { eth: ethChain() }), { ethBalance: 10n ** 15n })
  u.relay.on('POST', '/relay/eth', (r, res) => { const b = bodyOf(r) as { id: number; method: string }; if (b.method === 'eth_getTransactionCount') json(res, 500, { error: 'x' }); else json(res, 200, { jsonrpc: '2.0', id: b.id, result: b.method === 'eth_getBalance' ? '0x38d7ea4c68000' : { oldestBlock: '0x0', baseFeePerGas: ['0x3b9aca00', '0x3b9aca00'], gasUsedRatio: [0.5], reward: [['0x2dc6c0', '0x5f5e100']] } }) })
  await assert.rejects(jobCommand(['arm', u.v.id], u.io().io), /history cannot be read/)
  assert.equal(armPosts(u).length, 0)
})

test('arm on mainnet: the five ticks are shown (in order; wording pinned to the page by test/integration/ticks-agreement.test.ts) and `ticks` typed first; IsTor is required before anything is asked', async () => {
  assert.deepEqual(MAINNET_TICKS.map((t) => t.name), ['Backups', 'Funds', 'Permanence', 'Release', 'Pre-flight'])
  const input = armInput('mainnet', { eth: ethChain() })
  const s = await armSetup('mainnet', input, { ethBalance: 10n ** 15n })
  const c = s.io({ answers: ['yes', 'broadcast'] })
  await rejectsWith(() => jobCommand(['arm', s.v.id], c.io, { arm: NO_LOCK }), 'arm.ticks')
  assert.equal(c.asked.length, 1, 'refused at the first question')
  for (const t of MAINNET_TICKS) assert.ok(c.out().includes(`${t.name}: ${t.label}`), t.name)
  await rejectsWith(() => jobCommand(['arm', s.v.id], s.io({ answers: ['Ticks'] }).io, { arm: NO_LOCK }), 'arm.ticks')
  assert.equal(armPosts(s).length, 0)
  // IsTor false / unknown / missing route: refused before any question, before the text is read
  for (const isTor of [false, null] as const) {
    const t = await armSetup('mainnet', input, { ethBalance: 10n ** 15n, isTor })
    const q = t.io({ answers: ['ticks', 'broadcast'] })
    await rejectsWith(() => jobCommand(['arm', t.v.id], q.io, { arm: NO_LOCK }), 'arm.tor')
    assert.deepEqual(q.asked, [])
    assert.equal(armPosts(t).length, 0)
    assert.ok(!t.api.seen.some((r) => r.path.startsWith('/messages/')), 'the text was not even fetched')
  }
  // testnet is gated too; local is not
  const tn = await armSetup('testnet', armInput('testnet', { eth: ethChain() }), { ethBalance: 10n ** 15n, isTor: false })
  await rejectsWith(() => jobCommand(['arm', tn.v.id], tn.io().io, { arm: NO_LOCK }), 'arm.tor')
  const lo = await armSetup('local', armInput('local', { eth: ethChain() }), { ethBalance: 10n ** 15n, isTor: false })
  assert.equal(await jobCommand(['arm', lo.v.id], lo.io().io), 0)
  // the full mainnet order: ticks, broadcast, then again (key with history)
  const h = await armSetup('mainnet', input, { ethBalance: 10n ** 15n, ethNonce: 2 })
  const f = h.io({ answers: ['ticks', 'broadcast', 'again'] })
  assert.equal(await jobCommand(['arm', h.v.id], f.io, { arm: NO_LOCK }), 0, f.err())
  assert.deepEqual(f.asked.map((q) => q.split(' ')[0]), ['Type', 'MAINNET:', 'eth:'])
  assert.deepEqual((bodyOf(armPosts(h)[0]) as { confirm: unknown }).confirm, { typed: 'broadcast', amounts: {} })
})

test('arm (Cfix4, planE5 C4): a lane key core reports as delegated (EIP-7702) is a ✗ row; `delegated: false` or no field shows none (stub field: Efix3 adds it to core)', async () => {
  for (const [field, want] of [[true, true], [false, false], [undefined, false], ['yes', false]] as const) {
    const s = await armSetup('local', armInput('local', { eth: ethChain() }), { ethBalance: 10n ** 15n })
    const st = (s.v.view.state.chains as unknown as Record<string, Record<string, unknown>>).eth
    if (field !== undefined) st.delegated = field
    const c = s.io()
    assert.equal(await jobCommand(['arm', s.v.id], c.io), 0, c.err())
    const has = /^ {2}✗ {2}Lane key delegated \(EIP-7702\) — eth — someone holding the authorization may move funds/m.test(c.out())
    assert.equal(has, want, `${String(field)}: ${c.out()}`)
  }
})

test('arm --chains: the chains left out become SKIPPED (said before anything is asked); only the named ones are armed', async () => {
  const input = armInput('mainnet', { eth: ethChain(), sol: solChain() })
  const s = await armSetup('mainnet', input, { ethBalance: 10n ** 15n, solBalance: 10n ** 8n })
  const c = s.io({ answers: ['ticks', 'broadcast'] })
  assert.equal(await jobCommand(['arm', s.v.id, '--chains', 'eth'], c.io, { arm: NO_LOCK }), 0, c.err())
  assert.match(c.out(), /sol {2}NOT ARMED: it becomes SKIPPED at this arm/)
  assert.match(c.asked[1], /sol will be SKIPPED\./)
  assert.ok(c.out().indexOf('NOT ARMED') < c.out().indexOf('armed job'), 'said before the arm')
  const body = bodyOf(armPosts(s)[0]) as { chains: string[]; caps: Record<string, unknown> }
  assert.deepEqual(body.chains, ['eth'])
  assert.deepEqual(Object.keys(body.caps), ['eth'])
  assert.match(c.out(), /^ {2}sol SKIPPED$/m)
  assert.ok(!only(s.relay, 'POST', '/relay/sol').length, 'a chain that is not armed is not even priced')
  // Both chains by default.
  const t = await armSetup('local', armInput('local', { eth: ethChain(), sol: solChain() }), { ethBalance: 10n ** 15n, solBalance: 10n ** 8n })
  assert.equal(await jobCommand(['arm', t.v.id], t.io().io), 0)
  assert.deepEqual((bodyOf(armPosts(t)[0]) as { chains: string[] }).chains, ['eth', 'sol'])
  await assert.rejects(jobCommand(['arm', t.v.id, '--chains', 'eth,btc'], t.io().io), (e: Error) => e.name === 'UsageError')
})

test('arm refuses another network\'s API or relay, or an unverified chain identity (executor.network-mismatch); a chain that is not READY', async () => {
  const input = armInput('local', { eth: ethChain() })
  const a = await armSetup('local', input, {}, { statusNetwork: 'testnet' })
  await rejectsWith(() => jobCommand(['arm', a.v.id], a.io().io), 'executor.network-mismatch')
  const b = await armSetup('local', input, { identityOk: false })
  await rejectsWith(() => jobCommand(['arm', b.v.id], b.io().io), 'executor.network-mismatch')
  const r = await armSetup('local', input)
  r.relay.on('GET', '/relay/status', (_x, res) => json(res, 200, { network: 'testnet', build: 'dev', confined: true, identity: { eth: { ok: true } }, endpoints: {} }))
  await rejectsWith(() => jobCommand(['arm', r.v.id], r.io().io), 'executor.network-mismatch')
  const c = await armSetup('local', input, {}, { phases: { eth: 'skip-funds' } })
  await assert.rejects(jobCommand(['arm', c.v.id], c.io().io), /eth is AWAITING_FUNDS, not READY/)
  for (const s of [a, b, r, c]) assert.equal(armPosts(s).length, 0)
  // --source (M3, R47): passed through as the ArmRequest's sources; the API's refusal until M3 says why.
  const e = await armSetup('local', input)
  e.api.on('POST', `/jobs/${e.v.id}/arm`, (x, res) => json(res, 400, Object.hasOwn(bodyOf(x) as object, 'sources') ? { error: { guard: 'api.json', message: 'the request body is not one JSON value of the shape this endpoint takes' } } : { error: { guard: 'api.internal', message: '?' } }))
  await assert.rejects(jobCommand(['arm', e.v.id, '--source', 'eth=main-1'], e.io().io), (x: Error & { guardId?: string }) => x.guardId === 'api.json' && /--source: arm sources come with M3/.test(x.message))
  assert.deepEqual((bodyOf(armPosts(e)[0]) as { sources: unknown }).sources, { eth: 'main-1' })
  for (const bad of ['eth', 'btc=x', 'eth=a,eth=b', 'eth=a b', 'sol=x']) await assert.rejects(jobCommand(['arm', e.v.id, '--source', bad], e.io().io), (x: Error) => x.name === 'UsageError', bad)
  // An over-the-cap API answer is shown as the API's refusal.
  const d = await armSetup('local', input)
  d.api.on('POST', `/jobs/${d.v.id}/arm`, (_x, res) => json(res, 409, { error: { guard: 'job.key-busy', message: 'another active job holds this key' } }))
  await rejectsWith(() => jobCommand(['arm', d.v.id], d.io().io), 'job.key-busy')
})

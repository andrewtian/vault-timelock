// E7 (M4): the BTC inscription lane against REAL software — this test's OWN regtest bitcoind and ord, and the REAL relay process
// (api/relay/relay.mjs: ticket MAC, decode verification, the relay's own prevout reads, the pinned reveal leaf), on free high loopback
// ports (never the shared :18443 / :8090 / :8545 / :8999), each under a loopback-only sandbox and stopped by its recorded pid.
// OWN SANDBOX (listed in own-sandbox.list: test-root.sh runs it unsandboxed in phase B). Synthetic data only: coins mined on this
// regtest chain, a random lane key in memory, a random ticket key; nothing leaves the machine, no Tor.
//
// The engine under test is the real lane (core engine/lane.js runCopiesLane) with a journal that is the in-memory jobs API
// (fake-journal) plus the API's REAL ticket minting (api/src/tickets.ts ticketBinding('btc') + issueTicket): the intent shape the
// engine journals is exactly what the API binds, so the relay verifies server-computed fields.
//   1. copies = 2: each copy = commit + reveal; ord shows the text/plain inscription (its /content = the text); reassembly ok
//   2. a send whose reply is lost after the node accepted it (the lookup by txid sees it: no second send), and a send that never
//      reached the node (the same bytes go again): one tx each
//   3. a crash between the commit and the reveal: the takeover sends the reveal exactly once (the relay's log counts the sends)
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHmac, randomBytes } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { request } from 'node:http'
import { join } from 'node:path'
import { PORTS } from '../../../packages/core/src/contracts/index.ts'
import type { JobDef } from '../../../packages/core/src/contracts/index.ts'
import { sha256Hex } from '../../../packages/core/src/job/canonical.ts'
import { resumeOf } from '../../../packages/core/src/executor/executor.ts'
import { btcFromSecret, getTx } from '../../../packages/core/src/chains/btc.js'
import { newLaneState, planLaneCopy, runCopiesLane, validateLaneConfig } from '../../../packages/core/src/engine/lane.js'
import { configureRelay } from '../../../packages/core/src/engine/rpc.js'
import { fakeJournal } from '../../../packages/core/test/fakes/fake-journal.ts'
import { jobFor, newKey } from '../../../packages/core/test/executor/helpers.ts'
import { issueTicket, ticketBinding } from '../../../api/src/tickets.ts'
import { TICKET_KEY, makeHome, tempDir } from '../../../api/test/helpers.ts'
import { relayProfile } from '../../../cli/src/ops/sandbox.ts'
import { GENESIS } from '../../../broadcast/src/config.ts'
import { child, freeRun, stackFetch, waitFor, sleep } from '../stack.ts'
import type { Child } from '../stack.ts'
import { fileURLToPath } from 'node:url'

const RELAY = fileURLToPath(new URL('../../../api/relay/relay.mjs', import.meta.url))
const LOOPBACK_ONLY = '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))'
const NO_TOR = '(deny network-outbound (remote ip "localhost:9050"))'
const baseEnv = (home: string): Record<string, string> => ({ PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home, LANG: 'en_US.UTF-8' })
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s)

function http(port: number, path: string, o: { body?: unknown; headers?: Record<string, string> } = {}): Promise<{ status: number; text: string; j: any }> {
  return new Promise((resolve) => {
    const b = o.body == null ? null : Buffer.from(JSON.stringify(o.body))
    const r = request({ host: '127.0.0.1', port, path, method: b ? 'POST' : 'GET', headers: { ...(b ? { 'content-type': 'application/json', 'content-length': String(b.length) } : {}), ...o.headers } }, (res) => {
      const c: Buffer[] = []
      res.on('data', (d: Buffer) => c.push(d))
      res.on('end', () => { const text = Buffer.concat(c).toString('utf8'); let j: unknown; try { j = JSON.parse(text) } catch { j = undefined } resolve({ status: res.statusCode ?? 0, text, j }) })
    })
    r.on('error', (e: NodeJS.ErrnoException) => resolve({ status: 0, text: '', j: { err: e.code } }))
    r.end(b ?? undefined)
  })
}

test('the BTC lane on a real regtest: copies = commit + reveal, ord shows the text; lost replies; a crash between commit and reveal (E7)', { timeout: 600_000 }, async (t) => {
  const { dir, cleanup } = tempDir('vt-e7-btc-')
  t.after(cleanup)
  const home = join(dir, 'home')
  makeHome(home, 'local')
  const out = join(dir, 'out')
  mkdirSync(join(out, 'local'), { recursive: true, mode: 0o700 })
  const base = await freeRun(4)
  const [btcPort, ordPort, anvilPort, closedPort] = [base, base + 1, base + 2, base + 3]

  // ---- bitcoind (own, loopback, a synthetic credential: it gets only the salted hash; the relay reads the line from $OUT)
  const user = 'vtsynth', pass = `vt-${randomBytes(18).toString('hex')}`, salt = randomBytes(16).toString('hex')
  writeFileSync(join(out, 'local', 'btc-rpc.auth'), `${user}:${pass}\n`, { mode: 0o600 })
  const b64 = Buffer.from(`${user}:${pass}`).toString('base64')
  const datadir = join(dir, 'bitcoind')
  mkdirSync(datadir)
  const btcd = child('/usr/bin/sandbox-exec', ['-p', LOOPBACK_ONLY, 'bitcoind', '-regtest', `-datadir=${datadir}`, '-listen=0', '-connect=0', '-dnsseed=0', '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1',
    `-rpcport=${btcPort}`, `-rpcauth=${user}:${salt}$${createHmac('sha256', salt).update(pass).digest('hex')}`, '-txindex=1', '-printtoconsole=0'], baseEnv(home))
  t.after(() => btcd.stop())
  const direct = async (method: string, params: unknown[] = [], path = '/'): Promise<any> =>
    (await http(btcPort, path, { body: { jsonrpc: '2.0', id: 1, method, params }, headers: { authorization: `Basic ${b64}` } })).j
  await waitFor(async () => ((await direct('getblockcount'))?.result === 0 ? true : null), 60_000, 'bitcoind')
  assert.equal((await direct('getblockhash', [0])).result, GENESIS.btc.regtest)
  await direct('createwallet', ['w'])
  const miner = (await direct('getnewaddress', [], '/wallet/w')).result as string
  const mine = async (n: number, to = miner): Promise<void> => {
    for (let i = 0; ; i++) {                                              // bitcoind may answer a busy queue (several callers mine at once)
      const r = (await direct('generatetoaddress', [n, to])).result as string[] | undefined
      if (Array.isArray(r) && r.length === n) return
      if (i >= 20) throw new Error('generatetoaddress kept failing')
      await sleep(500)
    }
  }
  await mine(101)

  const ord = child('/usr/bin/sandbox-exec', ['-p', LOOPBACK_ONLY, 'ord', '--regtest', '--bitcoin-rpc-url', `http://127.0.0.1:${btcPort}`, '--cookie-file', join(datadir, 'regtest', '.cookie'),
    '--data-dir', join(dir, 'ord'), 'server', '--address', '127.0.0.1', '--http-port', String(ordPort), '--polling-interval', '1s'], baseEnv(home))
  t.after(() => ord.stop())
  mkdirSync(join(dir, 'ord'))
  const anvil = child('/usr/bin/sandbox-exec', ['-p', LOOPBACK_ONLY, 'anvil', '--host', '127.0.0.1', '--port', String(anvilPort), '--silent'], baseEnv(home))
  t.after(() => anvil.stop())
  await waitFor(async () => ((await http(anvilPort, '/', { body: { jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] } })).j?.result === '0x7a69' ? true : null), 30_000, 'anvil')

  // ---- the REAL relay: exactly these ports (and never Tor's)
  const relay: Child = child('/usr/bin/sandbox-exec', ['-p', relayProfile('local', [anvilPort, btcPort, ordPort]) + NO_TOR, process.execPath, RELAY, '--network', 'local', '--home', home, '--build', 'e7', '--port', '0'],
    { ...baseEnv(home), NODE_ENV: 'test', VAULT_TIMELOCK_DIR: out, VT_TEST_ETH_RPC: `http://127.0.0.1:${anvilPort}`, VT_TEST_SOL_RPC: `http://127.0.0.1:${closedPort}`, VT_TEST_BTC_RPC: `http://127.0.0.1:${btcPort}`, VT_TEST_ORD_RPC: `http://127.0.0.1:${ordPort}` })
  t.after(() => relay.stop())
  const relayPort = await waitFor(() => {
    const m = relay.lines.map((l) => /^vt-relay ready network=local port=(\d+)$/.exec(l)).find((x) => x !== null)
    if (m) return Number(m[1])
    if (relay.proc.exitCode !== null) throw new Error(`relay exited ${relay.proc.exitCode}: ${relay.lines.join(' | ')}`)
    return null
  }, 60_000, 'relay ready')
  await waitFor(async () => ((await http(ordPort, '/r/blockheight')).text === '101' ? true : null), 90_000, 'ord indexed')
  const relayFetch = stackFetch({ api: 0, relay: relayPort })
  /** The engine's relay fetch, with an optional fault on the next ticketed send. */
  let fault: 'lose-reply' | 'drop' | null = null
  configureRelay({ base: `http://127.0.0.1:${PORTS.local.relay}`, fetch: async (url, init) => {
    if (url.endsWith('/relay/btc/send') && fault !== null) {
      const f = fault; fault = null
      if (f === 'drop') throw new TypeError('fetch failed')                // never reached the relay
      await relayFetch(url, init)                                         // the node accepted it …
      throw new TypeError('fetch failed')                                 // … and the reply was lost
    }
    return relayFetch(url, init)
  } })
  const sendLines = (): string[] => relay.lines.filter((l) => /^btc btc_send /.test(l))

  // ---- a job: the lane key, its text, the journal (the in-memory API) with the REAL ticket minting
  async function job(text: string, copies: number, keyHex: string) {
    const key = btcFromSecret(keyHex, 'local')
    const base0 = jobFor('eth', newKey('eth'), { copies, text })
    const def: JobDef = { ...base0.def, chains: { btc: { ...(base0.def.chains.eth as object), keyAddress: key.address, publishMode: 'sol.memo', feeStrategy: 'economy' } } as unknown as JobDef['chains'] }
    const clock = { now: () => Date.now(), sleep: (ms: number) => sleep(ms), jump() {} }
    const j = fakeJournal({ def, text, clock })
    void j.client.lease(j.id, 'btc', 'acquire', 'browser')
    j.asHolder(1, 'browser', 'btc', 'key-loaded', { address: key.address })
    j.asHolder(1, 'browser', 'btc', 'funds', { balance: '1', affordable: true, nextCopyCost: '1' })
    void j.client.lease(j.id, 'btc', 'release', 'browser', 1)
    j.arm(['btc'], { caps: { btc: '100000000' }, releaseAt: j.serverNow() - 1 })
    const cfg = validateLaneConfig({ chain: 'btc', mode: 'copies', copies, text, distinct: true, feeStrategy: 'economy' }).cfg
    // the API's ticket for a journaled intent: server-computed fields only (api/src/tickets.ts), issued with the relay's key
    const mint = (gen: number, ev: any): string => {
      const bodyOf = (copy: number): Uint8Array => planLaneCopy(cfg, copy)[0].payload
      const commit = j.events.find((e) => e.type === 'intent' && e.chain === 'btc' && (e.data as any).copy === ev.copy && (e.data as any).part === 1)
      const b = ticketBinding('btc', 'intent', ev, key.address, { network: 'local', body: bodyOf(ev.copy), commitTxId: (commit?.data as any)?.txId ?? null })
      assert.ok(b !== null, 'the API refuses an intent it cannot bind')
      return issueTicket(TICKET_KEY, { j: j.id, w: 'local', c: 'btc', g: gen, t: ev.txId, r: ev.rawSha256, ...b }, Date.now())
    }
    async function run(o: { until?: (ev: any) => boolean; extra?: Record<string, unknown> } = {}) {
      const grant = await j.client.lease(j.id, 'btc', 'acquire', 'cli')
      let dead = false
      const ej = {
        async append(ev: any) { await j.client.lease(j.id, 'btc', 'renew', 'cli', grant.gen); const { type, chain, ...data } = ev; await j.client.append(j.id, chain, grant.gen, type, data); if (o.until?.(ev)) dead = true },
        async intent(ev: any) { await j.client.lease(j.id, 'btc', 'renew', 'cli', grant.gen); const { type, chain, ...data } = ev; await j.client.append(j.id, chain, grant.gen, type, data); if (o.until?.(ev)) dead = true; return { ticket: mint(grant.gen, data) } },
        ticket: async (txId: string) => { await j.client.lease(j.id, 'btc', 'renew', 'cli', grant.gen); const e = j.events.find((x) => x.type === 'intent' && (x.data as any).txId === txId)!; return mint(grant.gen, e.data) },
      }
      const state = j.state()
      const resume = resumeOf(state.chains.btc!)
      const lane = newLaneState(cfg)
      const d = { journal: ej, network: 'local', state, poll: 500, clock, alive: () => !dead, notify: () => {}, ...(resume !== null ? { resume } : {}), ...(o.extra ?? {}) }
      const res = await runCopiesLane(cfg, key, lane, d)
      return { res, lane }
    }
    const evs = () => j.events.filter((e) => e.chain === 'btc' && e.by !== 'api' && e.gen !== 1)
    return { key, j, cfg, run, evs, text }
  }
  // a miner thread: one block every 1.5 s while the lane waits for one
  let mining = true
  const minerLoop = (async () => { while (mining) { await sleep(1_500); if (mining) await mine(1).catch(() => {}) } })()
  t.after(async () => { mining = false; await minerLoop })

  // ======================================== 1. copies = 2: ord shows the text ========================================
  const A = await job('[BTC lane] héllo ₿ 漢字\nsecond line, ticketed end to end.\n', 2, randomBytes(32).toString('hex'))
  await mine(1, A.key.address); await mine(1, A.key.address)             // two coinbases to the lane address (100 more blocks mature them)
  await mine(100)
  {
    const { res, lane } = await A.run()
    assert.equal(res, 'copies-done', lane.reason)
    const intents = A.evs().filter((e) => e.type === 'intent')
    assert.equal(intents.length, 4)
    assert.deepEqual(A.evs().filter((e) => e.type === 'reassembled').map((e) => [(e.data as any).copy, (e.data as any).ok]), [[1, true], [2, true]])
    assert.ok(A.evs().filter((e) => e.type === 'readback').every((e) => (e.data as any).ok === true))
    for (const rv of intents.filter((e) => (e.data as any).btc.kind === 'reveal')) {
      const id = `${(rv.data as any).txId}i0`
      const insc = await waitFor(async () => { const r = await http(ordPort, `/inscription/${id}`, { headers: { accept: 'application/json' } }); return r.status === 200 ? r.j : null }, 90_000, `ord indexed ${id}`)
      assert.equal(insc.content_type, 'text/plain;charset=utf-8')
      const shown = await http(ordPort, `/content/${id}`)
      // copy 1 carries no marker; copy 2 carries `[copy 2/2]` in its first line
      const copy = (rv.data as any).copy as number
      assert.equal(shown.text, copy === 1 ? A.text : `[copy 2/2]\n${A.text}`)
    }
    assert.equal(sendLines().filter((l) => / 200 \d+ms$/.test(l)).length, 4, 'four accepted sends: one per tx')
    assert.equal(A.j.state().chains.btc!.copiesIncluded, 2)
    // the journal is the ledger of money: every commit's reserved = fee + value, the reveal 0
    for (const e of intents) assert.equal((e.data as any).reserved === '0', (e.data as any).btc.kind === 'reveal')
  }

  // ======================================== 2. lost replies ========================================
  const B = await job('lost replies\n', 1, randomBytes(32).toString('hex'))
  await mine(1, B.key.address); await mine(100)
  {
    const before = sendLines().length
    fault = 'lose-reply'                                                    // the first send reaches the node; its reply is lost
    const r1 = await B.run()
    assert.equal(r1.res, 'copies-done', r1.lane.reason)
    const sends = sendLines().slice(before)
    assert.equal(sends.length, 2, 'the commit was sent once (the lost reply was reconciled by txid), the reveal once')
    fault = null
    assert.equal(B.evs().filter((e) => e.type === 'intent').length, 2)
  }
  const C = await job('dropped sends\n', 1, randomBytes(32).toString('hex'))
  await mine(1, C.key.address); await mine(100)
  {
    const before = sendLines().length
    fault = 'drop'                                                         // the first send never reaches the relay: the same bytes go again
    const r = await C.run()
    assert.equal(r.res, 'copies-done', r.lane.reason)
    const intents = C.evs().filter((e) => e.type === 'intent')
    assert.equal(intents.length, 2, 'no second intent: the same transaction')
    assert.equal(sendLines().length - before, 2, 'the relay saw exactly the commit and the reveal (the dropped attempt never arrived)')
  }

  // ======================================== 3. a crash between the commit and the reveal ========================================
  const D = await job('crash between commit and reveal\n', 1, randomBytes(32).toString('hex'))
  await mine(1, D.key.address); await mine(100)
  {
    const before = sendLines().length
    const r1 = await D.run({ until: (e) => e.type === 'readback' })        // holder 1 dies right after the commit's readback
    assert.equal(r1.res, 'aborted')
    assert.equal(sendLines().length - before, 1, 'only the commit left')
    const commitId = (D.evs().find((e) => e.type === 'intent')!.data as any).txId as string
    assert.ok((await getTx(commitId))?.confirmations >= 1)
    D.j.expire('btc')
    const r2 = await D.run()                                                // the takeover
    assert.equal(r2.res, 'copies-done', r2.lane.reason)
    assert.equal(sendLines().length - before, 2, 'the takeover sent the reveal exactly once and never the commit again')
    const rid = (D.evs().filter((e) => e.type === 'intent')[1].data as any).txId as string
    const insc = await waitFor(async () => { const r = await http(ordPort, `/inscription/${rid}i0`, { headers: { accept: 'application/json' } }); return r.status === 200 ? r.j : null }, 90_000, 'ord indexed the reveal')
    assert.equal(insc.content_type, 'text/plain;charset=utf-8')
    assert.equal((await http(ordPort, `/content/${rid}i0`)).text, D.text)
    assert.equal(sha256Hex(utf8(D.text)), (D.evs().find((e) => e.type === 'intent')!.data as any).payloadSha256)
  }
  // the relay's log: a line per send, never the raw tx, a ticket, an address or the credential
  const log = relay.lines.join('\n')
  for (const needle of [pass, `${user}:${pass}`, b64, A.key.address, B.key.address]) assert.ok(!log.includes(needle), 'a secret or an address reached the relay log')
})

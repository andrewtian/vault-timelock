// E7b (M4): the EXECUTOR (createExecutor) runs a btc chain against REAL software: this test's own regtest bitcoind and ord and the REAL
// relay process, on free loopback ports (see btc-regtest.test.ts for the sandboxing). Tickets: the API's REAL minting
// (api/src/tickets.ts ticketBinding('btc') + issueTicket) in an in-test wrapper around the in-memory jobs API. WAITS FOR LANE-S: the
// end-to-end path through the real API process (S6b fix round 2 feeds ticketBinding the stored body and the journaled commit txid) is
// not exercised here; when it lands this wrapper is replaced by the stack's API.
// 1. one copy (commit + reveal) through the executor: ord shows the text; 2. the first executor dies after the commit's readback,
// the next takes over and sends the reveal exactly once.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHmac, randomBytes } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { request } from 'node:http'
import { join } from 'node:path'
import { PORTS } from '../../../packages/core/src/contracts/index.ts'
import type { JobDef } from '../../../packages/core/src/contracts/index.ts'
import { sha256Hex } from '../../../packages/core/src/job/canonical.ts'
import { btcFromSecret, getTx } from '../../../packages/core/src/chains/btc.js'
import { planLaneCopy, validateLaneConfig } from '../../../packages/core/src/engine/lane.js'
import { createExecutor } from '../../../packages/core/src/executor/executor.ts'
import { httpRelayClient } from '../../../packages/core/src/executor/relay-client.ts'
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

test('the executor runs a btc chain on a real regtest: one copy through the real relay and minted tickets; a takeover between commit and reveal; a Stop during the commit wait (E7b)', { timeout: 600_000 }, async (t) => {
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
  const relayClient = httpRelayClient({ base: `http://127.0.0.1:${PORTS.local.relay}`, fetch: relayFetch as never })
  const sendLines = (): string[] => relay.lines.filter((l) => /^btc btc_send /.test(l))

  async function job(text: string, copies: number, keyHex: string, hook?: (type: string) => void) {
    const key = btcFromSecret(keyHex, 'local')
    const base0 = jobFor('eth', newKey('eth'), { copies, text })
    const def: JobDef = { ...base0.def, chains: { btc: { ...(base0.def.chains.eth as object), keyAddress: key.address, publishMode: 'sol.memo', feeStrategy: 'economy' } } as unknown as JobDef['chains'] }
    const clock = { now: () => Date.now(), sleep: (ms: number) => sleep(ms), jump() {} }
    const j = fakeJournal({ def, text, clock })
    void j.client.lease(j.id, 'btc', 'acquire', 'browser')
    j.asHolder(1, 'browser', 'btc', 'key-loaded', { address: key.address })
    j.asHolder(1, 'browser', 'btc', 'funds', { balance: '1', affordable: true, nextCopyCost: '1' })
    void j.client.lease(j.id, 'btc', 'release', 'browser', 1)
    j.arm(['btc'], { caps: { btc: '100000000' }, releaseAt: j.serverNow() + 2_000 })
    const cfg = validateLaneConfig({ chain: 'btc', mode: 'copies', copies, text, distinct: true, feeStrategy: 'economy' }).cfg
    const mint = (gen: number, d: any): string => {
      const commit = j.events.find((e) => e.type === 'intent' && e.chain === 'btc' && (e.data as any).copy === d.copy && (e.data as any).part === 1)
      const b = ticketBinding('btc', 'intent', d, key.address, { network: 'local', body: planLaneCopy(cfg, d.copy)[0].payload, commitTxId: (commit?.data as any)?.txId ?? null })
      assert.ok(b !== null, 'the API refuses an intent it cannot bind')
      return issueTicket(TICKET_KEY, { j: j.id, w: 'local', c: 'btc', g: gen, t: d.txId, r: d.rawSha256, ...b }, Date.now())
    }
    const journal = { ...j.client,
      async append(id: string, c: any, gen: number, type: string, data: any, x?: any) {
        const r = await j.client.append(id, c, gen, type, data, x)
        hook?.(type)
        return type === 'intent' ? { ...r, ticket: mint(gen, data) } : r
      },
      async ticket(id: string, c: any, gen: number, txId: string) { await j.client.ticket(id, c, gen, txId); return mint(gen, j.events.find((x) => x.type === 'intent' && (x.data as any).txId === txId)!.data) },
    }
    const exKey = { chain: 'btc' as const, address: key.address, network: 'local' as const, handle: key }
    const make = () => createExecutor({ jobId: j.id, chain: 'btc', key: exKey, holder: 'cli', deps: { journal: journal as never, relay: relayClient, clock, random: { int: () => 0 }, poll: 500 } })
    return { key, j, make, text }
  }
  let mining = true
  const minerLoop = (async () => { while (mining) { await sleep(1_500); if (mining) await mine(1).catch(() => {}) } })()
  t.after(async () => { mining = false; await minerLoop })
  const inscription = async (txid: string) => waitFor(async () => { const r = await http(ordPort, `/inscription/${txid}i0`, { headers: { accept: 'application/json' } }); return r.status === 200 ? r.j : null }, 90_000, `ord indexed ${txid}`)

  // ======================================== 1. one copy through the executor ========================================
  const A = await job('[BTC executor] héllo ₿\nticketed end to end.\n', 1, randomBytes(32).toString('hex'))
  await mine(1, A.key.address); await mine(100)
  {
    const ex = A.make()
    assert.equal(await ex.start(), 'copies-done', JSON.stringify(ex.view()))
    const intents = A.j.events.filter((e) => e.type === 'intent')
    assert.equal(intents.length, 2)
    assert.equal(sendLines().filter((l) => / 200 \d+ms$/.test(l)).length, 2)
    const rid = (intents[1].data as any).txId as string
    assert.equal((await inscription(rid)).content_type, 'text/plain;charset=utf-8')
    assert.equal((await http(ordPort, `/content/${rid}i0`)).text, A.text)
    const st = A.j.state().chains.btc!
    assert.deepEqual([st.phase, st.copiesIncluded, st.openIntents], ['COPIES_DONE', 1, []])
  }

  // ======================================== 2. a takeover between the commit and the reveal ========================================
  let boom = false
  const B = await job('[BTC executor] takeover\n', 1, randomBytes(32).toString('hex'), (type) => { if (type === 'readback' && !boom) { boom = true; throw new Error('the connection died (test)') } })
  await mine(1, B.key.address); await mine(100)
  {
    const before = sendLines().length
    assert.equal(await B.make().start(), 'failed')
    assert.equal(sendLines().length - before, 1, 'only the commit left')
    B.j.expire('btc')
    const ex2 = B.make()
    assert.equal(await ex2.start(), 'copies-done', JSON.stringify(ex2.view()))
    assert.equal(sendLines().length - before, 2, 'the takeover sent the reveal exactly once and never the commit again')
    const rid = (B.j.events.filter((e) => e.type === 'intent')[1].data as any).txId as string
    assert.equal((await inscription(rid)).content_type, 'text/plain;charset=utf-8')
    assert.equal((await http(ordPort, `/content/${rid}i0`)).text, B.text)
  }
  // ======================================== 3. Stop while the commit waits for its block (I-2) ========================================
  let stopNow: (() => void) | null = null, stopped = false
  const C = await job('[BTC executor] stop during the commit wait\n', 2, randomBytes(32).toString('hex'), (type) => { if (type === 'sent' && !stopped) { stopped = true; stopNow?.() } })
  await mine(1, C.key.address); await mine(100)
  {
    const before = sendLines().length
    const ex = C.make()
    stopNow = () => ex.requestStop()
    assert.equal(await ex.start(), 'stopped')
    assert.equal(sendLines().length - before, 2, 'the commit and the reveal of copy 1 left; nothing of copy 2')
    const st = C.j.state().chains.btc!
    assert.deepEqual([st.copiesIncluded, st.openIntents], [1, []])
    const rid = (C.j.events.filter((e) => e.type === 'intent')[1].data as any).txId as string
    assert.equal((await inscription(rid)).content_type, 'text/plain;charset=utf-8')
  }
  const log = relay.lines.join('\n')
  for (const needle of [pass, `${user}:${pass}`, b64, A.key.address, B.key.address]) assert.ok(!log.includes(needle), 'a secret or an address reached the relay log')
})

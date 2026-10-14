// cli/test/run-btc-real.test.ts — `vt job run` for a btc lane THROUGH THE REAL STACK PIECES (Task Cbtc): this test's OWN regtest
// bitcoind and ord, and S6b's REAL relay process (api/relay/relay.mjs under relayProfile, no Tor), all on free loopback ports in
// 20000–50000 — never the shared bitcoind :18443 / ord :8090 / :8545 / :8999 / 5180–5183 / 5200–5202. The command runs in this
// process (jobCommand → openSession → loadKeys → createExecutor), with the relay reached through C6's loopbackFetch, the real
// jobs API process (journal, arm, ticket minting).
// OWN SANDBOX (test/own-sandbox.list): the children apply their own profiles, so test-root.sh runs it in phase B.
//
// M4d: the journal is S2's REAL jobs API process (api/src/main.ts under apiProfile, sharing this test's home so its relay-ticket.key is the
// relay's): the job is created through it, armed through it, and every intent's ticket is minted by its real btc wiring (lane-s) and
// accepted by the real relay. The in-test minter and the in-memory journal of the Cbtc round are gone. Core's httpJournalClient and
// checkArmConfirm accept btc (lane-e fix round 3); the command's clients wrap that real HTTP journal only to press Ctrl-C at an exact event.
// ALL DATA IS SYNTHETIC: keys made here, a made-up passphrase; regtest only, no testnet or mainnet traffic.
//   1. two copies: every commit and reveal confirmed on the regtest, ord shows each inscription's text, nothing secret printed;
//   2. Ctrl-C while the first commit waits for its block: the reveal is sent, then stopped; nothing of copy 2.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHmac, randomBytes } from 'node:crypto'
import { readFileSync, realpathSync } from 'node:fs'
import { mkdirSync, writeFileSync } from 'node:fs'
import { request } from 'node:http'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Chain, JobDef, JobState, JournalEvent, Network } from '@vault-timelock/core/contracts'
import { PORTS } from '@vault-timelock/core/contracts'
import { encryptKey, newKey } from '@vault-timelock/core/engine/keys.js'
import { httpRelayClient } from '@vault-timelock/core/executor'
import { GENESIS } from 'vt-broadcast/src/config.ts'
import { TOKEN, makeHome, tempDir } from '../../api/test/helpers.ts'
import { child, freeRun, sleep, waitFor } from '../../test/integration/stack.ts'
import type { Child } from '../../test/integration/stack.ts'
import { jobCommand } from '../src/job/index.ts'
import type { JobIo } from '../src/job/client.ts'
import type { RunDeps } from '../src/job/run.ts'
import { executorClients, loopbackFetch } from '../src/job/run.ts'
import { apiProfile, relayProfile } from '../src/ops/sandbox.ts'
import type { Key, TtyIo } from '../src/job/tty.ts'
import { CANARY, IPV4 } from './lib.ts'

process.env.NODE_ENV = 'test'
const RELAY = fileURLToPath(new URL('../../api/relay/relay.mjs', import.meta.url))
const API_MAIN = fileURLToPath(new URL('../../api/src/main.ts', import.meta.url))
const LOOPBACK_ONLY = '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))'
const NO_TOR = '(deny network-outbound (remote ip "localhost:9050"))'
const baseEnv = (home: string): Record<string, string> => ({ PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home, LANG: 'en_US.UTF-8' })
const PASS = 'cbtc-real-synthetic-passphrase-never-a-secret'

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

test('vt job run --backup-btc over a real regtest bitcoind, ord and relay: two copies confirmed and inscribed; Ctrl-C with a commit out sends the reveal first', { timeout: 900_000 }, async (t) => {
  const { dir, cleanup } = tempDir('vt-cbtc-real-')
  t.after(cleanup)
  const home = join(dir, 'home')
  makeHome(home, 'local')
  const out = join(dir, 'out')
  mkdirSync(join(out, 'local'), { recursive: true, mode: 0o700 })
  const base = await freeRun(4)
  const [btcPort, ordPort, anvilPort, closedPort] = [base, base + 1, base + 2, base + 3]

  // ---- bitcoind (own, loopback; a synthetic credential: it gets only the salted hash; the relay reads the line from $OUT)
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
    for (let i = 0; ; i++) {
      const r = (await direct('generatetoaddress', [n, to])).result as string[] | undefined
      if (Array.isArray(r) && r.length === n) return
      if (i >= 20) throw new Error('generatetoaddress kept failing')
      await sleep(500)
    }
  }
  await mine(101)
  mkdirSync(join(dir, 'ord'))
  const ord = child('/usr/bin/sandbox-exec', ['-p', LOOPBACK_ONLY, 'ord', '--regtest', '--bitcoin-rpc-url', `http://127.0.0.1:${btcPort}`, '--cookie-file', join(datadir, 'regtest', '.cookie'),
    '--data-dir', join(dir, 'ord'), 'server', '--address', '127.0.0.1', '--http-port', String(ordPort), '--polling-interval', '1s'], baseEnv(home))
  t.after(() => ord.stop())
  const anvil = child('/usr/bin/sandbox-exec', ['-p', LOOPBACK_ONLY, 'anvil', '--host', '127.0.0.1', '--port', String(anvilPort), '--silent'], baseEnv(home))
  t.after(() => anvil.stop())
  await waitFor(async () => ((await http(anvilPort, '/', { body: { jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] } })).j?.result === '0x7a69' ? true : null), 30_000, 'anvil')

  // ---- the REAL relay: exactly these ports (and never Tor's)
  const relay: Child = child('/usr/bin/sandbox-exec', ['-p', relayProfile('local', [anvilPort, btcPort, ordPort]) + NO_TOR, process.execPath, RELAY, '--network', 'local', '--home', home, '--build', 'cbtc', '--port', '0'],
    { ...baseEnv(home), NODE_ENV: 'test', VAULT_TIMELOCK_DIR: out, VT_TEST_ETH_RPC: `http://127.0.0.1:${anvilPort}`, VT_TEST_SOL_RPC: `http://127.0.0.1:${closedPort}`, VT_TEST_BTC_RPC: `http://127.0.0.1:${btcPort}`, VT_TEST_ORD_RPC: `http://127.0.0.1:${ordPort}` })
  t.after(() => relay.stop())
  const relayPort = await waitFor(() => {
    const m = relay.lines.map((l) => /^vt-relay ready network=local port=(\d+)$/.exec(l)).find((x) => x !== null)
    if (m) return Number(m[1])
    if (relay.proc.exitCode !== null) throw new Error(`relay exited ${relay.proc.exitCode}: ${relay.lines.join(' | ')}`)
    return null
  }, 60_000, 'relay ready')
  // ---- the REAL jobs API process (same home: the relay's ticket key; no outbound at all)
  const state = join(home, 'local')
  const api: Child = child('/usr/bin/sandbox-exec', ['-p', apiProfile(realpathSync(state), realpathSync(out)), process.execPath, API_MAIN, '--network', 'local', '--home', home, '--build', 'cbtc', '--port', '0'],
    { ...baseEnv(home), NODE_ENV: 'test', VAULT_TIMELOCK_DIR: out })
  t.after(() => api.stop())
  const apiPort = await waitFor(() => {
    const m = api.lines.map((l) => /^vt-api ready network=local port=(\d+) build=cbtc$/.exec(l)).find((x) => x !== null)
    if (m) return Number(m[1])
    if (api.proc.exitCode !== null) throw new Error(`api exited ${api.proc.exitCode}: ${api.lines.join(' | ')}`)
    return null
  }, 60_000, 'api ready')
  const apiCall = (path: string, body?: unknown): Promise<{ status: number; j: any; text: string }> =>
    http(apiPort, path, { ...(body === undefined ? {} : { body }), headers: { authorization: `Bearer ${TOKEN}`, host: `127.0.0.1:${PORTS.local.api}` } })
  const jobState = async (id: string): Promise<JobState> => (await apiCall(`/jobs/${id}`)).j.state
  const journalOf = (id: string): JournalEvent[] => readFileSync(join(state, 'jobs', id, 'journal.jsonl'), 'utf8').split('\n').filter((l) => l !== '').map((l) => JSON.parse(l) as JournalEvent)
  await waitFor(async () => ((await http(ordPort, '/r/blockheight')).text === '101' ? true : null), 90_000, 'ord indexed')
  const sendLines = (): string[] => relay.lines.filter((l) => /^btc btc_send /.test(l))
  // the command's relay client: C6's loopbackFetch (this network's fixed ports as Host, the connection to the test's ports)
  const relayClient = httpRelayClient({ base: `http://127.0.0.1:${PORTS.local.relay}`, fetch: loopbackFetch('local', { api: 1, relay: relayPort }) })

  let mining = true
  const minerLoop = (async () => { while (mining) { await sleep(1_500); if (mining) await mine(1).catch(() => {}) } })()
  t.after(async () => { mining = false; await minerLoop })
  const inscription = async (txid: string) => waitFor(async () => { const r = await http(ordPort, `/inscription/${txid}i0`, { headers: { accept: 'application/json' } }); return r.status === 200 ? r.j : null }, 90_000, `ord indexed ${txid}`)

  // ---- a job (through the API), a key backup and the command
  async function runJob(text: string, copies: number, hook?: (type: string, press: () => void) => void) {
    const h = newKey('btc', 'local') as unknown as { chain: Chain; address: string; secret: string; network: Network }
    const { ct } = await encryptKey(h as never, PASS, 'local')
    const bdir = join(dir, `bk${randomBytes(4).toString('hex')}`)
    mkdirSync(bdir)
    const file = join(bdir, 'vt-btc-key.age')
    writeFileSync(file, ct)
    const created = await apiCall('/jobs', { format: 'vt-job/1', network: 'local', name: 'btc real', message: text,
      chains: { btc: { mode: { copies }, publishMode: 'btc.inscription', feeStrategy: 'economy', distinctCopies: true, keyAddress: h.address, budgetUsd: 5, clawbackTo: null, maxFeeRateSatVb: 25 } } })
    assert.equal(created.status, 201, created.text)
    const id = created.j.id as string
    await mine(1, h.address); await mine(100)
    const clock = { now: () => Date.now(), sleep: (ms: number) => sleep(ms), jump() {} }
    // the REAL HTTP journal client of the stack API; wrapped only to press Ctrl-C right after an exact event was journaled
    const real = executorClients('local', { api: apiPort, relay: relayPort }, TOKEN)
    let press: (() => void) | null = null
    const journal = { ...real.journal,
      async append(jid: string, c: any, gen: number, type: string, data: any, x?: any) {
        const r = await real.journal.append(jid, c, gen, type, data, x)
        hook?.(type, () => press?.())
        return r
      },
    }
    let on: ((k: Key) => void) | null = null
    const tty: TtyIo = { available: () => true, passphrase: async () => PASS, word: async () => undefined, keys: (f) => { on = f; return () => { on = null } } }
    press = () => on?.('interrupt')
    let outText = ''
    const io: JobIo = { network: 'local', env: { HOME: dir, VT_HOME: join(dir, 'vt-home') }, cwd: dir, ports: { page: 1, relay: relayPort, api: apiPort }, out: (x) => { outText += x }, err: (x) => { outText += x }, ask: async () => undefined, now: () => Date.now() }
    const deps: RunDeps = { tty, signals: { on: () => {}, off: () => {} }, token: TOKEN, proc: { execArgv: ['--disable-sigusr1', '--no-addons'], nodeOptions: undefined, inspector: undefined },
      faults: { on: () => {}, off: () => {}, exit: () => {} }, clients: () => ({ journal: journal as never, relay: relayClient }), adapter: { clock: clock as never, random: { int: () => 0 } }, poll: 500 }
    const running = jobCommand(['run', id, '--backup-btc', file], io, { run: deps })
    // the command loads the key and journals READY; then the chain is armed through the API (core's real arm confirmation, btc)
    await waitFor(async () => ((await jobState(id)).chains.btc?.phase === 'READY' ? true : null), 120_000, 'btc READY')
    const armed = await apiCall(`/jobs/${id}/arm`, { chains: ['btc'], confirm: { typed: null, amounts: {} }, caps: { btc: { nativeCap: '100000000', usd: 0, priceAt: null, overCap: false, planned: '1' } }, countdownSec: 5, stagger: [0, 0] })
    assert.equal(armed.status, 200, armed.text)
    const code = await running
    return { code, id, st: () => jobState(id), events: () => journalOf(id), key: h, text, outText }
  }
  const clean = (r: { outText: string; key: { secret: string; address: string } }): void => {
    assert.ok(!r.outText.toLowerCase().includes(r.key.secret), 'the key secret was printed')
    assert.ok(!r.outText.includes(PASS) && !r.outText.includes(CANARY) && !IPV4.test(r.outText), 'a passphrase or an IP was printed')
  }

  // ======================================== 1. two copies ========================================
  {
    const before = sendLines().length
    const r = await runJob('[Cbtc] héllo ₿\ntwo copies through vt job run.\n', 2)
    assert.equal(r.code, 0, r.outText)
    assert.match(r.outText, /^btc: copies-done/m)
    const st = (await r.st()).chains.btc!
    assert.deepEqual([st.phase, st.copiesIncluded, st.openIntents], ['COPIES_DONE', 2, []])
    assert.equal(sendLines().length - before, 4)
    assert.equal(sendLines().slice(before).filter((l) => / 200 \d+ms$/.test(l)).length, 4, 'every send was accepted by the real relay (tickets minted by the real API)')
    const reveals = r.events().filter((e) => e.type === 'intent').filter((e) => (e.data as any).btc.kind === 'reveal').map((e) => (e.data as any).txId as string)
    assert.equal(reveals.length, 2)
    for (const rid of reveals) {
      assert.equal((await inscription(rid)).content_type, 'text/plain;charset=utf-8')
      assert.ok((await http(ordPort, `/content/${rid}i0`)).text.includes('two copies through vt job run.'))
    }
    clean(r)
  }

  // ======================================== 2. Ctrl-C with the first commit out ========================================
  {
    const before = sendLines().length
    let pressed = false
    const r = await runJob('[Cbtc] stop during the commit wait\n', 2, (type, press) => { if (type === 'sent' && !pressed) { pressed = true; press() } })
    assert.equal(r.code, 0, r.outText)
    assert.match(r.outText, /^btc: stopped/m)
    assert.match(r.outText, /a btc copy is a commit and its reveal/)
    assert.equal(sendLines().length - before, 2, 'the commit and the reveal of copy 1; nothing of copy 2')
    const st = (await r.st()).chains.btc!
    assert.deepEqual([st.phase, st.copiesIncluded, st.openIntents], ['RUNNING', 1, []], 'R79: a Ctrl-C detaches — the copy is complete, nothing journaled stopped')
    const rid = (r.events().filter((e) => e.type === 'intent')[1].data as any).txId as string
    assert.equal((await inscription(rid)).content_type, 'text/plain;charset=utf-8')
    clean(r)
  }
  const log = relay.lines.join('\n')
  for (const needle of [pass, `${user}:${pass}`, b64]) assert.ok(!log.includes(needle), 'a credential reached the relay log')
})

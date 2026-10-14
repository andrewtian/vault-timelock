// S6 (M4): the local BTC lane against REAL software — this test's OWN regtest bitcoind and ord, and the real relay
// process. OWN SANDBOX (listed in test/own-sandbox.list; test-root.sh runs it unsandboxed in phase B): bitcoind, ord and
// anvil run under a loopback-only profile on free high ports (never the shared :18443 / :8090 / :8545), each stopped by
// its recorded pid; the relay runs under C1's relayProfile with exactly those ports, plus a deny of Tor's port (this
// test never reaches Tor or the internet). The bitcoind credential is synthetic and random: bitcoind gets only its
// salted hash (-rpcauth), ord the node's cookie file, and the relay reads it once from a temp $OUT/local/btc-rpc.auth
// (VAULT_TIMELOCK_DIR). Synthetic data only: coins mined on this regtest chain, nothing leaves the machine.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { createHash, createHmac, randomBytes } from 'node:crypto'
import { createSocket } from 'node:dgram'
import { mkdirSync, writeFileSync } from 'node:fs'
import { createServer as createTcpServer } from 'node:net'
import { request } from 'node:http'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as btc from '@scure/btc-signer'
import { pubECDSA, pubSchnorr, randomPrivateKeyBytes } from '@scure/btc-signer/utils.js'
import { OutOrdinalReveal, p2tr_ord_reveal, parseWitness } from 'micro-ordinals'
import { TICKET_HEADER, TICKET_TTL_MS } from '@vault-timelock/core/contracts'
import type { TicketPayload } from '@vault-timelock/core/contracts'
import { GENESIS } from 'vt-broadcast/src/config.ts'
import { relayProfile } from '../../cli/src/ops/sandbox.ts'
import { encodeTicket } from '../src/tickets.ts'
import { TICKET_KEY, makeHome, tempDir } from './helpers.ts'

const RELAY = fileURLToPath(new URL('../relay/relay.mjs', import.meta.url))
const LOOPBACK_ONLY = '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))'
const NO_TOR = '(deny network-outbound (remote ip "localhost:9050"))'
const HOST = '127.0.0.1:5181'
const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))
type T = { after(fn: () => unknown): void }

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
async function freeRun(n: number): Promise<number> {
  for (let tries = 0; tries < 60; tries++) {
    const base = 20_000 + 10 * Math.floor(Math.random() * 3_000)
    let ok = true
    for (let p = base; ok && p < base + n; p++) ok = await portFree(p)
    if (ok) return base
  }
  throw new Error('no run of free ports')
}

interface Child { proc: ChildProcess; lines: string[]; stop(): Promise<void> }
function child(cmd: string, args: string[], env: Record<string, string>): Child {
  const proc = spawn(cmd, args, { env, stdio: ['ignore', 'pipe', 'pipe'] })
  const lines: string[] = []
  let buf = ''
  const onData = (d: Buffer): void => { buf += d.toString('utf8'); let i; while ((i = buf.indexOf('\n')) >= 0) { lines.push(buf.slice(0, i)); buf = buf.slice(i + 1) } }
  proc.stdout?.on('data', onData)
  proc.stderr?.on('data', onData)
  const stop = (): Promise<void> => new Promise((r) => {
    if (proc.exitCode !== null || proc.signalCode !== null) return r()
    const k = setTimeout(() => { try { proc.kill('SIGKILL') } catch { /* gone */ } r() }, 15_000)
    proc.once('exit', () => { clearTimeout(k); r() })
    proc.kill('SIGTERM')
  })
  return { proc, lines, stop }
}
async function waitFor<V>(fn: () => Promise<V | null> | V | null, ms: number, what: string): Promise<V> {
  const t0 = Date.now()
  for (;;) {
    const v = await fn()
    if (v !== null) return v
    if (Date.now() - t0 > ms) throw new Error(`timeout: ${what}`)
    await sleep(200)
  }
}
const baseEnv = (home: string): Record<string, string> => ({ PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home, LANG: 'en_US.UTF-8' })

interface Reply { status: number; type: string | undefined; text: string; j: any }
function http(port: number, path: string, o: { method?: string; body?: unknown; headers?: Record<string, string> } = {}): Promise<Reply> {
  return new Promise((resolve) => {
    const b = o.body == null ? null : Buffer.from(typeof o.body === 'string' ? o.body : JSON.stringify(o.body))
    const r = request({ host: '127.0.0.1', port, path, method: o.method ?? (b ? 'POST' : 'GET'),
      headers: { ...(b ? { 'content-type': 'application/json', 'content-length': String(b.length) } : {}), ...o.headers } }, (res) => {
      const c: Buffer[] = []
      res.on('data', (d: Buffer) => c.push(d))
      res.on('end', () => { const text = Buffer.concat(c).toString('utf8'); let j: unknown; try { j = JSON.parse(text) } catch { j = undefined } resolve({ status: res.statusCode ?? 0, type: res.headers['content-type'], text, j }) })
    })
    r.on('error', (e: NodeJS.ErrnoException) => resolve({ status: 0, type: undefined, text: '', j: { err: e.code } }))
    r.end(b ?? undefined)
  })
}
const rpc = (method: string, params: unknown[] = []): Record<string, unknown> => ({ jsonrpc: '2.0', id: 1, method, params })

test('the local BTC lane: the relay reads its own regtest bitcoind (with the credential, never echoed) and ord; sends, wallet and mining are refused; a ticketed commit and reveal inscribe a text (S6b)', { timeout: 240_000 }, async (t) => {
  const { dir, cleanup } = tempDir('vt-relay-btc-')
  t.after(cleanup)
  const home = join(dir, 'home')
  makeHome(home, 'local')
  const out = join(dir, 'out')
  mkdirSync(join(out, 'local'), { recursive: true, mode: 0o700 })
  const base = await freeRun(4)
  const [btcPort, ordPort, anvilPort, closedPort] = [base, base + 1, base + 2, base + 3]

  // ---- the synthetic credential: bitcoind gets only its salted HMAC; the relay reads the line from $OUT
  const user = 'vtsynth', pass = `vt-${randomBytes(18).toString('hex')}`, salt = randomBytes(16).toString('hex')
  const line = `${user}:${pass}`
  const b64 = Buffer.from(line).toString('base64')
  writeFileSync(join(out, 'local', 'btc-rpc.auth'), `${line}\n`, { mode: 0o600 })
  const rpcauth = `${user}:${salt}$${createHmac('sha256', salt).update(pass).digest('hex')}`
  const datadir = join(dir, 'bitcoind')
  mkdirSync(datadir)
  const btcd = child('/usr/bin/sandbox-exec', ['-p', LOOPBACK_ONLY, 'bitcoind', '-regtest', `-datadir=${datadir}`, '-listen=0', '-connect=0', '-dnsseed=0',
    '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1', `-rpcport=${btcPort}`, `-rpcauth=${rpcauth}`, '-txindex=1', '-printtoconsole=0'], baseEnv(home))
  t.after(() => btcd.stop())
  // the test's own direct calls to its own node (never through the relay)
  const direct = async (method: string, params: unknown[] = [], path = '/'): Promise<any> => (await http(btcPort, path, { body: rpc(method, params), headers: { authorization: `Basic ${b64}` } })).j
  await waitFor(async () => ((await direct('getblockcount'))?.result === 0 ? true : null), 60_000, 'bitcoind')
  assert.equal((await direct('getblockhash', [0])).result, GENESIS.btc.regtest)
  await direct('createwallet', ['w'])
  const addr = (await direct('getnewaddress', [], '/wallet/w')).result as string
  assert.match(addr, /^bcrt1/)
  assert.equal(((await direct('generatetoaddress', [101, addr])).result as string[]).length, 101)
  const coinbase = ((await direct('getblock', [(await direct('getblockhash', [1])).result])).result as { tx: string[] }).tx[0]

  const ordDir = join(dir, 'ord')
  mkdirSync(ordDir)
  const ord = child('/usr/bin/sandbox-exec', ['-p', LOOPBACK_ONLY, 'ord', '--regtest', '--bitcoin-rpc-url', `http://127.0.0.1:${btcPort}`, '--cookie-file', join(datadir, 'regtest', '.cookie'),
    '--data-dir', ordDir, 'server', '--address', '127.0.0.1', '--http-port', String(ordPort), '--polling-interval', '1s'], baseEnv(home))
  t.after(() => ord.stop())
  await waitFor(async () => ((await http(ordPort, '/r/blockheight')).text === '101' ? true : null), 90_000, 'ord indexed')

  const anvil = child('/usr/bin/sandbox-exec', ['-p', LOOPBACK_ONLY, 'anvil', '--host', '127.0.0.1', '--port', String(anvilPort), '--silent'], baseEnv(home))
  t.after(() => anvil.stop())
  await waitFor(async () => ((await http(anvilPort, '/', { body: rpc('eth_chainId') })).j?.result === '0x7a69' ? true : null), 30_000, 'anvil')

  // ---- the relay: exactly these ports (and never Tor's)
  const relay = child('/usr/bin/sandbox-exec', ['-p', relayProfile('local', [anvilPort, btcPort, ordPort]) + NO_TOR, process.execPath, RELAY, '--network', 'local', '--home', home,
    '--build', 'btc', '--port', '0'], { ...baseEnv(home), NODE_ENV: 'test', VAULT_TIMELOCK_DIR: out, VT_TEST_ETH_RPC: `http://127.0.0.1:${anvilPort}`,
    VT_TEST_SOL_RPC: `http://127.0.0.1:${closedPort}`, VT_TEST_BTC_RPC: `http://127.0.0.1:${btcPort}`, VT_TEST_ORD_RPC: `http://127.0.0.1:${ordPort}` })
  t.after(() => relay.stop())
  const P = await waitFor(() => {
    const m = relay.lines.map((l) => /^vt-relay ready network=local port=(\d+)$/.exec(l)).find((x) => x !== null)
    if (m) return Number(m[1])
    if (relay.proc.exitCode !== null) throw new Error(`relay exited ${relay.proc.exitCode}: ${relay.lines.join(' | ')}`)
    return null
  }, 60_000, 'relay ready')
  assert.ok(relay.lines.some((l) => /^confinement: .*EPERM ×5 ✓$/.test(l)))
  assert.ok(relay.lines.some((l) => new RegExp(`^identity btc loopback:${btcPort}: block 0 = the regtest genesis OK`).test(l)))
  const answers: string[] = []                                                // every reply text of the relay, checked for the credential below (S6 review m4)
  const R = async (path: string, o: { method?: string; body?: unknown; headers?: Record<string, string> } = {}): Promise<Reply> => {
    const r = await http(P, path, { ...o, headers: { host: HOST, ...(o.headers ?? {}) } })
    answers.push(r.text)
    return r
  }
  const st = (await R('/relay/status')).j
  assert.deepEqual([st.identity.btc, st.endpoints.btc, st.identity.eth], [{ ok: true }, 1, { ok: true }])

  // ---- reads through POST /relay/btc
  assert.equal((await R('/relay/btc', { body: rpc('getblockcount') })).j?.result, 101)
  assert.equal((await R('/relay/btc', { body: rpc('getblockchaininfo') })).j?.result?.chain, 'regtest')
  assert.equal((await R('/relay/btc', { body: rpc('getblockhash', [0]) })).j?.result, GENESIS.btc.regtest)
  const tx = (await R('/relay/btc', { body: rpc('getrawtransaction', [coinbase, true]) })).j?.result
  assert.equal(tx?.txid, coinbase)
  const scan = (await R('/relay/btc', { body: rpc('scantxoutset', ['start', [{ desc: `addr(${addr})` }]]) })).j?.result
  assert.ok(scan?.success === true && scan.unspents.length === 101)
  const est = await R('/relay/btc', { body: rpc('estimatesmartfee', [2]) })
  assert.ok(est.status === 200 && typeof est.j?.result === 'object')
  const tma = await R('/relay/btc', { body: rpc('testmempoolaccept', [['00']]) })
  assert.ok(tma.status === 200 && tma.j?.jsonrpc === '2.0' && tma.j?.id === 1)            // a definitive node answer (a decode error)
  const bad = await R('/relay/btc', { body: rpc('getblockhash', [999]) })
  assert.deepEqual([bad.status, bad.j?.error?.code], [200, -8])                             // the node's own error, passed on

  // ---- refused: sends, wallet, mining, node control; a scantxoutset other than 'start' — nothing reaches the node
  for (const [m, params] of [['sendrawtransaction', ['00']], ['sendtoaddress', [addr, 1]], ['generatetoaddress', [1, addr]], ['getnewaddress', []], ['dumpprivkey', [addr]],
    ['listunspent', []], ['stop', []], ['submitblock', ['00']], ['generateblock', [addr, []]]] as const) {
    const r = await R('/relay/btc', { body: rpc(m, [...params]) })
    assert.deepEqual([r.status, r.j?.error?.data?.guard], [403, 'relay.method'], m)
  }
  const abort = await R('/relay/btc', { body: rpc('scantxoutset', ['abort', []]) })
  assert.deepEqual([abort.status, abort.j?.error?.data?.guard], [403, 'relay.btc-params'])
  assert.equal((await direct('getblockcount')).result, 101, 'nothing was mined, and the node still answers')

  // ---- ord through GET /relay/btc/ord/…
  const h = await R('/relay/btc/ord/r/blockheight')
  assert.deepEqual([h.status, h.text, h.type], [200, '101', 'text/plain; charset=utf-8'])
  assert.deepEqual([(await R('/relay/btc/ord/r/blockhash/0')).j], [GENESIS.btc.regtest])
  assert.equal((await R('/relay/btc/ord/status')).j?.chain, 'regtest')
  assert.equal((await R(`/relay/btc/ord/output/${coinbase}:0`)).j?.value, 5_000_000_000)
  assert.ok(typeof (await R(`/relay/btc/ord/tx/${coinbase}`)).j?.transaction === 'object')
  assert.equal((await R(`/relay/btc/ord/inscription/${coinbase}i0`)).status, 404)
  const content = await R(`/relay/btc/ord/content/${coinbase}i0`)
  assert.deepEqual([content.status, content.j?.error?.data?.guard], [403, 'relay.path'])
  const post = await R('/relay/btc/ord/status', { method: 'POST', body: {} })
  assert.deepEqual([post.status, post.j?.error?.data?.guard], [403, 'relay.method'])
  const esplora = await R(`/relay/btc/esplora/tx/${coinbase}`)
  assert.deepEqual([esplora.status, esplora.j?.error?.data?.guard], [403, 'relay.path'])          // no Esplora on local

  // ---- the credential: never in an answer, a log line, or the relay's argv; the relay has no child
  // bitcoind echoes bad input in its errors: a param holding the password makes the REAL node answer with it, and the relay withholds that
  const echoed = await R('/relay/btc', { body: rpc('getrawtransaction', [`zz${pass}zz`]) })
  assert.deepEqual([echoed.status, echoed.j?.error?.data?.guard], [502, 'relay.upstream-secret'])
  const notEchoed = await R('/relay/btc', { body: rpc('getrawtransaction', ['zz-another-string-zz']) })     // a non-secret string: the node's own error
  assert.ok(notEchoed.status === 200 && typeof notEchoed.j?.error?.code === 'number')
  for (const s of [pass, line, b64]) assert.ok(!answers.some((a) => a.includes(s)), 'the credential reached an answer')
  await sleep(300)
  const seen = relay.lines.join('\n')
  for (const s of [pass, line, b64]) assert.ok(!seen.includes(s), 'the credential reached the relay log')
  assert.ok(!IPV4.test(seen.replaceAll('127.0.0.1:<port>', '')), 'an IP reached the relay log')
  assert.ok(relay.lines.some((l) => /^btc getblockcount 200 \d+ms$/.test(l)) && relay.lines.some((l) => /^btc ord:output\/:txid::n 200 \d+ms$/.test(l)))
  assert.ok(!seen.includes(coinbase) && !seen.includes(addr))
  const pid = relay.proc.pid!
  const ps = await new Promise<string>((resolve) => { const c = spawn('/bin/ps', ['-o', 'args=', '-p', String(pid)]); let o = ''; c.stdout.on('data', (d: Buffer) => { o += d.toString() }); c.on('exit', () => resolve(o)) })
  assert.ok(ps.includes('relay.mjs') && !ps.includes(pass) && !ps.includes(b64))
  const kids = await new Promise<string>((resolve) => { const c = spawn('/usr/bin/pgrep', ['-P', String(pid)]); let o = ''; c.stdout.on('data', (d: Buffer) => { o += d.toString() }); c.on('exit', () => resolve(o)) })
  assert.equal(kids.trim(), '', 'the relay started a child')

  // =====================================================================================================================
  // S6b: fund → commit → reveal → ord shows the text, every send through POST /relay/btc/send with a ticket
  // =====================================================================================================================
  const NET = { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef }
  const lanePriv = randomPrivateKeyBytes()                                  // synthetic, in memory only, regtest coins
  const lane = btc.p2wpkh(pubECDSA(lanePriv), NET)
  const xonly = pubSchnorr(lanePriv)
  const dest = btc.p2tr(xonly, undefined, NET)
  const text = new TextEncoder().encode(`[1/1 ${randomBytes(4).toString('hex')}] a synthetic regtest inscription, ticketed end to end.\n`)
  const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex')
  const hexOf = (b: Uint8Array): string => Buffer.from(b).toString('hex')

  // fund: one coinbase to the lane (mined directly: no wallet fee estimation on a fresh regtest chain), then 100 blocks to mature it
  assert.equal(((await direct('generatetoaddress', [1, lane.address!])).result as string[]).length, 1)
  assert.equal(((await direct('generatetoaddress', [100, addr])).result as string[]).length, 100)
  const scan2 = (await R('/relay/btc', { body: rpc('scantxoutset', ['start', [{ desc: `addr(${lane.address})` }]]) })).j?.result
  assert.ok(scan2?.success === true && scan2.unspents.length === 1)
  const fund = { txid: scan2.unspents[0].txid as string, index: scan2.unspents[0].vout as number, amount: BigInt(Math.round(scan2.unspents[0].amount * 1e8)) }
  assert.equal(fund.amount, 5_000_000_000n)

  // the pair, as the prototype's builder (plan E7) builds it
  const inscription = { tags: { contentType: 'text/plain;charset=utf-8' }, body: text }
  const reveal = btc.p2tr(undefined, p2tr_ord_reveal(xonly, [inscription]), NET, false, [OutOrdinalReveal])
  const mkReveal = (txid: string, amount: bigint, index = 0): btc.Transaction => {
    const t = new btc.Transaction({ customScripts: [OutOrdinalReveal] })
    t.addInput({ ...reveal, txid, index, witnessUtxo: { script: reveal.script, amount } })
    t.addOutputAddress(dest.address!, 546n, NET)
    t.sign(lanePriv, undefined, new Uint8Array(32)); t.finalize()
    return t
  }
  const RATE = 2n
  const revealFee = BigInt(mkReveal('00'.repeat(32), 10_000_000n).vsize) * RATE
  const revealAmount = 546n + revealFee
  const mkCommit = (fee: bigint, extra?: { script: Uint8Array; amount: bigint }): btc.Transaction => {
    const t = new btc.Transaction()
    t.addInput({ txid: fund.txid, index: fund.index, witnessUtxo: { script: lane.script, amount: fund.amount } })
    t.addOutputAddress(reveal.address!, revealAmount, NET)
    if (extra) t.addOutput(extra)
    t.addOutputAddress(lane.address!, fund.amount - revealAmount - fee - (extra?.amount ?? 0n), NET)
    t.sign(lanePriv); t.finalize()
    return t
  }
  const commitFee = BigInt(mkCommit(1_000n).vsize) * RATE
  const commit = mkCommit(commitFee)
  const rev = mkReveal(commit.id, revealAmount)
  const ticketFor = (kind: 'commit' | 'reveal', tx: btc.Transaction, o: { f: bigint; q: string; to: string; value: bigint }): { header: string; hex: string } => {
    const raw = tx.extract()
    const payload: TicketPayload = { j: 'e3d45f73cf65abaa', w: 'local', c: 'btc', g: 1, t: tx.id, r: sha(raw), a: lane.address!, k: kind, p: sha(text), to: o.to, value: String(o.value),
      f: String(o.f), q: o.q, x: null, e: Date.now() + TICKET_TTL_MS, n: randomBytes(8).toString('hex') }
    return { header: encodeTicket(TICKET_KEY, payload), hex: hexOf(raw) }
  }
  const send = (t: { header: string; hex: string }, ticket: string | null = t.header): Promise<Reply> => R('/relay/btc/send', { body: { hex: t.hex }, ...(ticket === null ? {} : { headers: { [TICKET_HEADER]: ticket } }) })
  const commitT = ticketFor('commit', commit, { f: commitFee, q: `${fund.txid}:${fund.index}`, to: reveal.address!, value: revealAmount })
  const revealT = ticketFor('reveal', rev, { f: revealFee, q: `${commit.id}:0`, to: dest.address!, value: 546n })
  const mempool = async (): Promise<string[]> => (await direct('getrawmempool')).result as string[]

  // refused, and the node's mempool stays empty: unticketed; a reveal before its commit exists (the relay's own chain read finds
  // no such output: relay.btc-prevout); the commit with an extra output; the commit with a fee over f
  const unticketed = await send(commitT, null)
  assert.deepEqual([unticketed.status, unticketed.j?.error?.guard], [403, 'relay.send-ticket'])
  const early = await send(revealT)
  assert.deepEqual([early.status, early.j?.error?.guard], [403, 'relay.btc-prevout'])
  const fat = ticketFor('commit', mkCommit(commitFee, { script: btc.p2wpkh(pubECDSA(randomPrivateKeyBytes()), NET).script, amount: 1_000n }), { f: commitFee + 5_000n, q: `${fund.txid}:${fund.index}`, to: reveal.address!, value: revealAmount })
  const extraOut = await send(fat)
  assert.deepEqual([extraOut.status, extraOut.j?.error?.guard], [403, 'relay.decode-mismatch'])
  const lowF = ticketFor('commit', commit, { f: commitFee - 1n, q: `${fund.txid}:${fund.index}`, to: reveal.address!, value: revealAmount })
  assert.equal((await send({ ...lowF, hex: commitT.hex })).j?.error?.guard, 'relay.decode-mismatch')
  assert.deepEqual(await mempool(), [], 'nothing reached the node')

  // the commit, then the reveal
  const c = await send(commitT)
  assert.deepEqual([c.status, c.j], [200, { txid: commit.id }])
  assert.deepEqual(await mempool(), [commit.id])
  const rv = await send(revealT)
  assert.deepEqual([rv.status, rv.j], [200, { txid: rev.id }])
  assert.deepEqual((await mempool()).sort(), [commit.id, rev.id].sort())
  // an identical-bytes rebroadcast of the accepted commit: its input is spent in the node's mempool, so the relay's own chain
  // read (gettxout, mempool included) finds no such unspent output and refuses relay.btc-prevout: nothing leaves the machine,
  // and the engine reconciles by the txid (a read), not by a second send
  const again = await send(commitT)
  assert.deepEqual([again.status, again.j?.error?.guard], [403, 'relay.btc-prevout'])
  assert.equal((await mempool()).length, 2)

  // mine them: ord indexes the reveal and shows the text
  assert.equal(((await direct('generatetoaddress', [1, addr])).result as string[]).length, 1)
  const id = `${rev.id}i0`
  const insc = await waitFor(async () => { const r = await R(`/relay/btc/ord/inscription/${id}`); return r.status === 200 ? r : null }, 90_000, 'ord indexed the inscription')
  assert.equal(insc.j?.content_type, 'text/plain;charset=utf-8')
  assert.equal(insc.j?.content_length, text.length)
  const shown = await http(ordPort, `/content/${id}`)                       // this test's own ord, direct (the relay never serves /content)
  assert.deepEqual([shown.status, shown.text], [200, new TextDecoder().decode(text)])
  assert.equal(sha(Buffer.from(shown.text)), sha(text), 'ord\'s content hashes to p')
  assert.equal((await http(ordPort, `/inscription/${rev.id}i1`, { headers: { accept: 'application/json' } })).status, 404, 'no second inscription')
  // and the engine's read-back path: the reveal's witness through the relay's getrawtransaction
  const raw = (await R('/relay/btc', { body: rpc('getrawtransaction', [rev.id, true]) })).j?.result
  const found = parseWitness((raw.vin[0].txinwitness as string[]).map((x) => Uint8Array.from(Buffer.from(x, 'hex'))))
  assert.equal(found?.length, 1)
  assert.equal(sha(found![0].body), sha(text))

  // =====================================================================================================================
  // S6b fix round 1 (I-1): three reveals whose leaf script ord and micro-ordinals read differently. The relay must refuse each
  // (btc.envelope); sent to the node directly they inscribe other content than the ticketed text, which is why.
  // =====================================================================================================================
  assert.equal(((await direct('generatetoaddress', [3, lane.address!])).result as string[]).length, 3)
  assert.equal(((await direct('generatetoaddress', [100, addr])).result as string[]).length, 100)
  const scan3 = (await R('/relay/btc', { body: rpc('scantxoutset', ['start', [{ desc: `addr(${lane.address})` }]]) })).j?.result
  const coins = (scan3.unspents as Array<{ txid: string; vout: number; amount: number }>).filter((u) => u.amount >= 1 && u.amount < 50).slice(0, 3)   // fresh coinbases (the halving makes them 25 BTC)
  assert.equal(coins.length, 3)
  const T = (x: string): number[] => Array.from(new TextEncoder().encode(x))
  const push = (b: Uint8Array | number[]): number[] => { const a = Array.from(b); return a.length <= 75 ? [a.length, ...a] : [0x4c, a.length, ...a] }
  const Z = [0x00], IF = [0x63], END = [0x68], KEY = [...push(xonly), 0xac]
  const head = [...Z, ...IF, ...push(T('ord')), ...push([1]), ...push(T('text/plain;charset=utf-8'))]
  const crafted: Array<{ name: string; leaf: number[]; shows: (i: any, content: string) => void }> = [
    { name: 'S1 OP_0 mid-body', leaf: [...KEY, ...head, ...Z, ...push(text), ...Z, ...push(T('[APPENDED BY ATTACKER]')), ...END],
      shows: (_i, c) => assert.ok(c.includes('[APPENDED BY ATTACKER]') && c.startsWith(new TextDecoder().decode(text)), 'ord appends the suffix') },
    { name: 'S2 hidden first envelope', leaf: [...KEY, ...Z, ...IF, 0x4c, 0x00, ...IF, ...push(T('ord')), ...push([1]), ...push(T('text/html;charset=utf-8')), ...Z, ...push(T('<b>attacker</b>')), ...END, ...END,
      ...head, ...Z, ...push(text), ...END], shows: (i, c) => assert.ok(i.content_type === 'text/html;charset=utf-8' && c === '<b>attacker</b>', 'ord numbers the attacker as i0') },
    { name: 'S3 split content type', leaf: [...KEY, ...Z, ...IF, ...push(T('ord')), ...push([1]), ...push(T('t')), ...push([1]), ...push(T('ext/plain;charset=utf-8')), ...Z, ...push(text), ...END],
      shows: (i) => assert.equal(i.content_type, 't', 'ord keeps the first content-type push') },
  ]
  for (const [n, c] of crafted.entries()) {
    const fundC = { txid: coins[n].txid, index: coins[n].vout, amount: BigInt(Math.round(coins[n].amount * 1e8)) }
    const leafOut = btc.p2tr(undefined, { script: Uint8Array.from(c.leaf), leafVersion: 0xc0 }, NET, true)
    const cm = new btc.Transaction()
    cm.addInput({ txid: fundC.txid, index: fundC.index, witnessUtxo: { script: lane.script, amount: fundC.amount } })
    cm.addOutput({ script: leafOut.script, amount: revealAmount })
    cm.addOutputAddress(lane.address!, fundC.amount - revealAmount - commitFee, NET)
    cm.sign(lanePriv); cm.finalize()
    const cmT = ticketFor('commit', cm, { f: commitFee, q: `${fundC.txid}:${fundC.index}`, to: leafOut.address!, value: revealAmount })
    assert.equal((await send(cmT)).status, 200, `${c.name}: the commit is a plain taproot payment, ticketed`)
    const rv2 = new btc.Transaction()
    rv2.addInput({ ...leafOut, txid: cm.id, index: 0, witnessUtxo: { script: leafOut.script, amount: revealAmount } })
    rv2.addOutputAddress(dest.address!, 546n, NET)
    rv2.sign(lanePriv, undefined, new Uint8Array(32))
    const inp = rv2.getInput(0), [cb, scr] = inp.tapLeafScript![0]
    rv2.updateInput(0, { finalScriptWitness: [inp.tapScriptSig![0][1], scr.subarray(0, scr.length - 1), btc.TaprootControlBlock.encode(cb)] })
    const rv2T = ticketFor('reveal', rv2, { f: revealFee, q: `${cm.id}:0`, to: dest.address!, value: 546n })
    const refusedHere = await send(rv2T)
    assert.deepEqual([refusedHere.status, refusedHere.j?.error?.guard], [403, 'relay.decode-mismatch'], c.name)
    const raw2 = hexOf(rv2.extract())
    const direct2 = await direct('sendrawtransaction', [raw2])
    assert.equal(direct2.result, rv2.id, `${c.name}: the node itself accepts it (standard policy)`)
    assert.equal(((await direct('generatetoaddress', [1, addr])).result as string[]).length, 1)
    const id2 = `${rv2.id}i0`
    const i2 = await waitFor(async () => { const r = await http(ordPort, `/inscription/${id2}`, { headers: { accept: 'application/json' } }); return r.status === 200 ? r.j : null }, 90_000, `ord indexed ${c.name}`)
    c.shows(i2, (await http(ordPort, `/content/${id2}`)).text)
  }

  // =====================================================================================================================
  // S6b fix round 2 (I-3): a commit input signed SIGHASH_NONE|ANYONECANPAY (or SINGLE|ANYONECANPAY, ...) is public once relayed, and
  // anyone can re-spend its signature. The relay must refuse every non-ALL commit; sent to the node directly, the theft is real.
  // =====================================================================================================================
  assert.equal(((await direct('generatetoaddress', [4, lane.address!])).result as string[]).length, 4)
  assert.equal(((await direct('generatetoaddress', [100, addr])).result as string[]).length, 100)
  const scan4 = (await R('/relay/btc', { body: rpc('scantxoutset', ['start', [{ desc: `addr(${lane.address})` }]]) })).j?.result
  const fresh = (scan4.unspents as Array<{ txid: string; vout: number; amount: number; height: number }>).filter((u) => u.amount >= 1 && u.amount < 50).sort((p, q) => q.height - p.height).slice(0, 4)
  assert.equal(fresh.length, 4)
  const sigs = [['NONE|ANYONECANPAY', btc.SigHash.NONE_ANYONECANPAY], ['SINGLE|ANYONECANPAY', btc.SigHash.SINGLE_ANYONECANPAY], ['NONE', btc.SigHash.NONE], ['ALL|ANYONECANPAY', btc.SigHash.ALL_ANYONECANPAY]] as const
  for (const [n, [name, sh]] of sigs.entries()) {
    const f4 = { txid: fresh[n].txid, index: fresh[n].vout, amount: BigInt(Math.round(fresh[n].amount * 1e8)) }
    const cm = new btc.Transaction()
    cm.addInput({ txid: f4.txid, index: f4.index, witnessUtxo: { script: lane.script, amount: f4.amount }, sighashType: sh })
    cm.addOutputAddress(reveal.address!, revealAmount, NET)
    cm.addOutputAddress(lane.address!, f4.amount - revealAmount - commitFee, NET)
    cm.sign(lanePriv, [sh]); cm.finalize()
    const t4 = ticketFor('commit', cm, { f: commitFee, q: `${f4.txid}:${f4.index}`, to: reveal.address!, value: revealAmount })
    const r4 = await send(t4)
    assert.deepEqual([r4.status, r4.j?.error?.guard], [403, 'relay.decode-mismatch'], name)
    if (n === 0) {
      // the theft the refusal prevents: the same signature, lifted, pays an attacker (no lane key involved)
      const thief = btc.p2wpkh(pubECDSA(randomPrivateKeyBytes()), NET)
      assert.equal((await direct('sendrawtransaction', [hexOf(cm.extract())])).result, cm.id, 'the node accepts the commit')
      const steal = new btc.Transaction()
      steal.addInput({ txid: f4.txid, index: f4.index, witnessUtxo: { script: lane.script, amount: f4.amount } })
      steal.addOutputAddress(thief.address!, f4.amount - 50_000n, NET)
      steal.updateInput(0, { finalScriptWitness: cm.getInput(0).finalScriptWitness })
      const stolen = await direct('sendrawtransaction', [hexOf(steal.extract())])
      assert.equal(stolen.result, steal.id, `${name}: anyone replaces the public commit and takes the coin`)
    }
  }

  // the relay's log: one line per send, never the raw tx, a ticket, a txid, an address or the credential
  await sleep(300)
  const log = relay.lines.join('\n')
  assert.ok(relay.lines.some((l) => /^btc btc_send 200 \d+ms$/.test(l)) && relay.lines.some((l) => /^btc btc_send 403 \d+ms relay\.btc-prevout$/.test(l)))
  for (const needle of [commitT.hex.slice(12, 80), revealT.hex.slice(12, 80), commitT.header, revealT.header, commit.id, rev.id, lane.address!, dest.address!, pass, line, b64]) assert.ok(!log.includes(needle), 'a send leaked into the relay log')
  for (const s of [pass, line, b64]) assert.ok(!answers.some((a) => a.includes(s)), 'the credential reached an answer (read, ord or send)')   // S6 review m4

})

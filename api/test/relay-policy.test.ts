// PORTED from the prototype, tag add7b-e540f8ae4d6b, test/relay-policy.mjs (sha256 01f1a463fae8b54dd48aae69b721db1bfa3f28948c90d2c3a9b6991e84964d2d),
// adapted to node --test. LOCAL relay policy + confinement checks, against the real relay process (no mainnet or testnet
// traffic: those relays are only started to prove they refuse before any network, under a deny-all profile).
//
// OWN SANDBOX (listed in test/own-sandbox.list; test-root.sh runs it unsandboxed in phase B, because macOS refuses to
// apply a profile inside a sandbox). Each relay runs under C1's relayProfile (cli/src/ops/sandbox.ts, the string `vt up`
// uses) plus this harness's own chain ports, and proves its confinement itself. The chains are this test's OWN anvil and
// solana-test-validator on free high ports (never the shared :8545 / :8999), each under a loopback-only profile, stopped
// by their recorded pids. The relay reaches them through VT_TEST_ETH_RPC / VT_TEST_SOL_RPC (local only) and listens on
// an ephemeral port (--port 0, NODE_ENV=test). Keys are random and funded on these chains only. Synthetic data only.
//
// Adaptations from the prototype: ports from PORTS (Host 127.0.0.1:5181, page 5180, dev 5183); requestAirdrop is now
// allowed on local (R71d) and refused on the eth route; /relay/release answers { release: false } in a dev tree; the
// sends go through the ticket gate (a real ETH and a real SOL tx land with a ticket; without one nothing is forwarded);
// web3.js only (no @scure/base in api); the off-loopback override uses the canary. S4 (CC-3 ticket v2): the tickets bind
// the sender, kind, payload or destination/value and the worst-case fee; a real ETH and SOL claw-back land too, and
// bytes that are not what the ticket binds are refused relay.decode-mismatch with nothing forwarded (the chain shows it).
// Sfix1: the SOL memo job's bytes also go through /relay/sol/ep/0 with the same ticket, once (a second time: refused
// relay.ticket-endpoint-reused); an ETH send on /relay/eth/ep/0 is refused (read-only). S6: with no VAULT_TIMELOCK_DIR the
// local relay reads no bitcoind credential and reports btc off; the real BTC lane is relay-btc.test.ts.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { createSocket } from 'node:dgram'
import { createServer as createTcpServer } from 'node:net'
import { createServer, request } from 'node:http'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { ComputeBudgetProgram, Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction, TransactionMessage, VersionedTransaction } from '@solana/web3.js'
import { keccak256, toHex } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import type { TicketPayload } from '@vault-timelock/core/contracts'
import { relayProfile } from '../../cli/src/ops/sandbox.ts'
import { encodeTicket } from '../src/tickets.ts'
import { CANARY, TICKET_KEY, makeHome, tempDir } from './helpers.ts'

const RELAY = fileURLToPath(new URL('../relay/relay.mjs', import.meta.url))
const DENY_ALL = '(version 1)(allow default)(deny network-outbound)'
const LOOPBACK_ONLY = '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))'
const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/
const HOST = '127.0.0.1:5181'
const MEMO = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))
type T = { after(fn: () => unknown): void }

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
async function freeRun(n: number): Promise<number> {
  for (let tries = 0; tries < 60; tries++) {
    const base = 20_000 + 10 * Math.floor(Math.random() * 3_000)
    let ok = true
    for (let p = base; ok && p < base + n; p++) ok = await portFree(p)
    if (ok) return base
  }
  throw new Error('no run of free ports')
}

// ---- children, stopped by their recorded pid

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
    const k = setTimeout(() => { try { proc.kill('SIGKILL') } catch { /* gone */ } r() }, 8_000)
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

// Direct JSON-RPC to this test's own chain (never through the relay; loopback, phase B).
function direct(port: number, method: string, params: unknown[] = []): Promise<any> {
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

async function startAnvil(t: T, home: string): Promise<number> {
  const port = await freeRun(1)
  const c = child('/usr/bin/sandbox-exec', ['-p', LOOPBACK_ONLY, 'anvil', '--host', '127.0.0.1', '--port', String(port), '--silent'], baseEnv(home))
  t.after(() => c.stop())
  await waitFor(async () => { try { return (await direct(port, 'eth_chainId')).result === '0x7a69' ? true : null } catch { return null } }, 30_000, 'anvil')
  return port
}
async function startValidator(t: T, home: string, dir: string): Promise<number> {
  const base = await freeRun(64)   // rpc, rpc websocket, faucet, gossip, then the dynamic range
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

interface Relay extends Child { port: number }
async function startRelay(t: T, o: { home: string; chainPorts: number[]; env?: Record<string, string>; extra?: string[] }): Promise<Relay> {
  const c = child('/usr/bin/sandbox-exec', ['-p', relayProfile('local', o.chainPorts), process.execPath, RELAY, '--network', 'local', '--home', o.home, '--build', 'policy', '--port', '0', ...(o.extra ?? [])],
    { ...baseEnv(o.home), NODE_ENV: 'test', ...o.env })
  t.after(() => c.stop())
  const port = await waitFor(() => {
    const m = c.lines.map((l) => /^vt-relay ready network=local port=(\d+)$/.exec(l)).find((x) => x !== null)
    if (m) return Number(m[1])
    if (c.proc.exitCode !== null) throw new Error(`relay exited ${c.proc.exitCode}: ${c.lines.join(' | ')}`)
    return null
  }, 120_000, 'relay ready')
  return { ...c, port }
}

interface Reply { status: number; j: any }
function req(port: number, path: string, o: { method?: string; body?: unknown; headers?: Record<string, string | string[]> } = {}): Promise<Reply> {
  return new Promise((resolve) => {
    const b = o.body == null ? null : Buffer.isBuffer(o.body) ? o.body : Buffer.from(typeof o.body === 'string' ? o.body : JSON.stringify(o.body))
    const r = request({ host: '127.0.0.1', port, path, method: o.method ?? 'POST',
      headers: { host: HOST, 'content-type': 'application/json', ...(b ? { 'content-length': String(b.length) } : {}), ...o.headers } }, (res) => {
      const c: Buffer[] = []
      res.on('data', (d: Buffer) => c.push(d))
      res.on('end', () => { let j: unknown; try { j = JSON.parse(Buffer.concat(c).toString('utf8')) } catch { j = undefined } resolve({ status: res.statusCode ?? 0, j }) })
    })
    r.on('error', (e: NodeJS.ErrnoException) => resolve({ status: 0, j: { err: e.code } }))
    r.end(b ?? undefined)
  })
}
const rpc = (method: string, params: unknown[] = []): Record<string, unknown> => ({ jsonrpc: '2.0', id: 1, method, params })
const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex')
const ticket = (p: Omit<TicketPayload, 'j' | 'w' | 'g' | 'e' | 'n'>): string =>
  encodeTicket(TICKET_KEY, { j: 'e3d45f73cf65abaa', w: 'local', c: p.c, g: 1, t: p.t, r: p.r, a: p.a, k: p.k, p: p.p, to: p.to, value: p.value, f: p.f, q: p.q, x: p.x,
    e: Date.now() + 120_000, n: randomBytes(8).toString('hex') })
function setup(t: T): { dir: string; home: string } {
  const { dir, cleanup } = tempDir('vt-relay-policy-')
  t.after(cleanup)
  const home = join(dir, 'home')
  makeHome(home, 'local')
  return { dir, home }
}
const run = (args: string[], env: Record<string, string>): { code: number | null; out: string } => {
  const r = spawnSync(args[0], args.slice(1), { encoding: 'utf8', env, timeout: 60_000 })
  return { code: r.status, out: `${r.stdout}${r.stderr}` }
}
// The same without blocking this process (its own fake chains must answer meanwhile).
const runAsync = (args: string[], env: Record<string, string>): Promise<{ code: number | null; out: string }> => new Promise((resolve) => {
  const c = child(args[0], args.slice(1), env)
  const k = setTimeout(() => { void c.stop() }, 60_000)
  c.proc.once('exit', (code) => { clearTimeout(k); setImmediate(() => resolve({ code, out: c.lines.join('\n') })) })
})

test('confinement and the refusals before any network: unsandboxed, a looser profile, mainnet/testnet test overrides, the fixture off local', { timeout: 180_000 }, async (t) => {
  const { home } = setup(t)
  const closed = await freeRun(2)                     // closed loopback ports: even a broken relay would reach nothing
  const env = { ...baseEnv(home), VT_TEST_ETH_RPC: `http://127.0.0.1:${closed}`, VT_TEST_SOL_RPC: `http://127.0.0.1:${closed + 1}` }
  const relayArgs = (n: string, extra: string[] = []): string[] => [process.execPath, RELAY, '--network', n, '--home', home, ...extra]
  const plain = run(relayArgs('local'), env)
  assert.equal(plain.code, 2)
  assert.match(plain.out, /^vt relay · network local\nFATAL: not confined: direct probes returned ECONNREFUSED \(expected EPERM ×5\)/)
  const loose = run(['/usr/bin/sandbox-exec', '-p', LOOPBACK_ONLY, ...relayArgs('local')], env)
  assert.equal(loose.code, 2)
  assert.match(loose.out, /FATAL: not confined: direct probes returned ECONNREFUSED/)
  const fx = run(['/usr/bin/sandbox-exec', '-p', DENY_ALL, ...relayArgs('mainnet', ['--price-fixture', 'SOL=1,ETH=1'])], baseEnv(home))
  assert.equal(fx.code, 2)
  assert.match(fx.out, /^FATAL: --price-fixture is only allowed with --network local$/m)
  for (const n of ['mainnet', 'testnet']) {
    for (const k of ['VT_TEST_ETH_RPC', 'VT_TEST_SOL_RPC']) {
      const r = run(['/usr/bin/sandbox-exec', '-p', DENY_ALL, ...relayArgs(n)], { ...baseEnv(home), [k]: `http://127.0.0.1:${closed}` })
      assert.equal(r.code, 2)
      assert.match(r.out, new RegExp(`^FATAL: ${k} is a local test override — refused with --network ${n}$`, 'm'))
    }
  }
  const off = run(['/usr/bin/sandbox-exec', '-p', DENY_ALL, ...relayArgs('local')], { ...baseEnv(home), VT_TEST_SOL_RPC: `http://${CANARY}:8899` })
  assert.equal(off.code, 2)
  assert.match(off.out, /^FATAL: VT_TEST_SOL_RPC must be http:\/\/127\.0\.0\.1:<port>$/m)
  const port = run(['/usr/bin/sandbox-exec', '-p', DENY_ALL, ...relayArgs('local', ['--port', '0'])], env)   // NODE_ENV unset
  assert.equal(port.code, 2)
  assert.match(port.out, /^FATAL: refused api\.test-only: /m)
  const { dir: other, cleanup } = tempDir('vt-relay-nokey-')
  t.after(cleanup)
  const nokey = run(['/usr/bin/sandbox-exec', '-p', DENY_ALL, process.execPath, RELAY, '--network', 'local', '--home', other], env)
  assert.equal(nokey.code, 2)
  assert.match(nokey.out, /^FATAL: refused api\.token-missing: /m)
  for (const r of [plain, loose, fx, off, port, nokey]) {
    assert.ok(!r.out.includes(CANARY) && !IPV4.test(r.out.replaceAll('127.0.0.1:<port>', '')), r.out)
    assert.ok(!/vt-relay ready/.test(r.out))
  }
})

test('identity mismatch at startup (a fake anvil answering chainId 0x1) → exit 2 before listening, naming only loopback:<port>', { timeout: 120_000 }, async (t) => {
  const { home } = setup(t)
  const fakeChain = (result: string): Promise<{ port: number; close(): void }> => new Promise((resolve) => {
    const s = createServer((rq, rs) => { rq.resume(); rq.on('end', () => { rs.writeHead(200, { 'content-type': 'application/json' }); rs.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result })) }) })
    s.listen(0, '127.0.0.1', () => resolve({ port: (s.address() as { port: number }).port, close: () => s.close() }))
  })
  const eth = await fakeChain('0x1'), sol = await fakeChain('8pUq7jxkLxNpHg6M9KxzRtNEC4pNEHsr4kDTLSE5uVRW')
  t.after(() => { eth.close(); sol.close() })
  const r = await runAsync(['/usr/bin/sandbox-exec', '-p', relayProfile('local', [eth.port, sol.port]), process.execPath, RELAY, '--network', 'local', '--home', home, '--port', '0'],
    { ...baseEnv(home), NODE_ENV: 'test', VT_TEST_ETH_RPC: `http://127.0.0.1:${eth.port}`, VT_TEST_SOL_RPC: `http://127.0.0.1:${sol.port}` })
  assert.equal(r.code, 2)
  assert.match(r.out, /confinement: .*EPERM ×5 ✓/)
  assert.match(r.out, new RegExp(`^FATAL: eth identity MISMATCH at loopback:${eth.port}: the chain id is not local's \\(31337\\)$`, 'm'))
  assert.ok(!/vt-relay ready/.test(r.out) && !IPV4.test(r.out))
})

test('the local relay against its own anvil + validator: policy, the simulate guard, the send gate, a real ETH and SOL send', { timeout: 300_000 }, async (t) => {
  const { dir, home } = setup(t)
  const anvil = await startAnvil(t, home)
  const sol = await startValidator(t, home, dir)
  const relay = await startRelay(t, { home, chainPorts: [anvil, sol], env: { VT_TEST_ETH_RPC: `http://127.0.0.1:${anvil}`, VT_TEST_SOL_RPC: `http://127.0.0.1:${sol}` }, extra: ['--price-fixture', 'SOL=150,ETH=3000'] })
  const P = relay.port
  assert.ok(relay.lines.some((l) => /^confinement: .*EPERM ×5 ✓$/.test(l)), 'sandboxed start: loopback :9, the mDNSResponder socket and TEST-NET :9/:443/:80 → EPERM ×5')
  assert.ok(relay.lines.some((l) => new RegExp(`^identity eth loopback:${anvil}: eth_chainId 0x7a69 OK`).test(l)))
  assert.ok(relay.lines.some((l) => new RegExp(`^identity sol loopback:${sol}: genesis non-public \\(local test-validator\\) OK`).test(l)))
  const big = Buffer.alloc(256 * 1024 + 1, 0x20)
  const cases: Array<[string, Promise<Reply>, number]> = [
    ['GET /relay/eth', req(P, '/relay/eth', { method: 'GET' }), 403],
    ['POST /relay/other', req(P, '/relay/other', { body: rpc('eth_chainId') }), 403],
    ['eth_accounts (not allowlisted)', req(P, '/relay/eth', { body: rpc('eth_accounts') }), 403],
    ['eth_sign (not allowlisted)', req(P, '/relay/eth', { body: rpc('eth_sign', ['0x0', '0x0']) }), 403],
    ['eth_getStorageAt (not allowlisted)', req(P, '/relay/eth', { body: rpc('eth_getStorageAt', ['0x0000000000000000000000000000000000000000', '0x0', 'latest']) }), 403],
    ['eth_getCode (allowlisted since 7b)', req(P, '/relay/eth', { body: rpc('eth_getCode', ['0x0000000000000000000000000000000000000000', 'latest']) }), 200],
    ['eth_feeHistory(1024, latest, []) — Passive 24 h window, base-fee only', req(P, '/relay/eth', { body: rpc('eth_feeHistory', ['0x400', 'latest', []]) }), 200],
    ['eth_feeHistory(1024, …, [10]) refused', req(P, '/relay/eth', { body: rpc('eth_feeHistory', ['0x400', 'latest', [10]]) }), 403],
    ['eth_feeHistory(4096, …) refused', req(P, '/relay/eth', { body: rpc('eth_feeHistory', ['0x1000', 'latest', []]) }), 403],
    ['requestAirdrop on /relay/eth', req(P, '/relay/eth', { body: rpc('requestAirdrop', ['11111111111111111111111111111111', 1]) }), 403],
    ['eth method on /relay/sol', req(P, '/relay/sol', { body: rpc('eth_chainId') }), 403],
    ['JSON-RPC batch', req(P, '/relay/eth', { body: [rpc('eth_chainId'), rpc('eth_chainId')] }), 403],
    ['content-type text/plain', req(P, '/relay/eth', { body: rpc('eth_chainId'), headers: { 'content-type': 'text/plain' } }), 403],
    ['foreign Origin', req(P, '/relay/eth', { body: rpc('eth_chainId'), headers: { origin: 'http://evil.example' } }), 403],
    ['foreign Host (DNS rebinding)', req(P, '/relay/eth', { body: rpc('eth_chainId'), headers: { host: 'evil.example:5181' } }), 403],
    ['localhost Host', req(P, '/relay/eth', { body: rpc('eth_chainId'), headers: { host: 'localhost:5181' } }), 403],
    ['cross-site', req(P, '/relay/eth', { body: rpc('eth_chainId'), headers: { 'sec-fetch-site': 'cross-site' } }), 403],
    ['a repeated header', req(P, '/relay/eth', { body: rpc('eth_chainId'), headers: { origin: ['http://127.0.0.1:5180', 'http://127.0.0.1:5180'] } }), 403],
    ['body > 256 KiB', req(P, '/relay/eth', { body: big }), 413],
    ['content-type application/jsonx (M5)', req(P, '/relay/eth', { body: rpc('eth_chainId'), headers: { 'content-type': 'application/jsonx' } }), 403],
    ['an unticketed send on /relay/sol/ep/0 (Sfix1: the gate of /relay/sol)', req(P, '/relay/sol/ep/0', { body: rpc('sendTransaction', ['AA==', { encoding: 'base64' }]) }), 403],
    ['a send on /relay/eth/ep/0 (ETH endpoint routes are read-only)', req(P, '/relay/eth/ep/0', { body: rpc('eth_sendRawTransaction', ['0x02']) }), 403],
    ['endpoint index out of range /relay/sol/ep/7', req(P, '/relay/sol/ep/7', { body: rpc('getGenesisHash') }), 403],
    ['the page Host and Origin (:5180)', req(P, '/relay/eth', { body: rpc('eth_chainId'), headers: { host: '127.0.0.1:5180', origin: 'http://127.0.0.1:5180', 'sec-fetch-site': 'same-origin' } }), 200],
    ['the Vite dev Origin (:5183, local only)', req(P, '/relay/eth', { body: rpc('eth_chainId'), headers: { origin: 'http://127.0.0.1:5183' } }), 200],
  ]
  for (const [name, r, want] of cases) assert.equal((await r).status, want, name)
  // simulate guard: unsigned (all-zero signatures) + sigVerify:false only
  const kp = Keypair.generate()
  const { result: { value: { blockhash } } } = (await req(P, '/relay/sol', { body: rpc('getLatestBlockhash', [{ commitment: 'confirmed' }]) })).j
  const vtx = new VersionedTransaction(new TransactionMessage({ payerKey: kp.publicKey, recentBlockhash: blockhash, instructions: [new TransactionInstruction({ programId: new PublicKey(MEMO), keys: [], data: Buffer.from('policy test') })] }).compileToLegacyMessage())
  const unsigned = Buffer.from(vtx.serialize()).toString('base64'); vtx.sign([kp]); const signed = Buffer.from(vtx.serialize()).toString('base64')
  const s1 = await req(P, '/relay/sol', { body: rpc('simulateTransaction', [unsigned, { encoding: 'base64', sigVerify: false, replaceRecentBlockhash: true }]) })
  const s2 = await req(P, '/relay/sol', { body: rpc('simulateTransaction', [signed, { encoding: 'base64', sigVerify: false }]) })
  const s3 = await req(P, '/relay/sol', { body: rpc('simulateTransaction', [unsigned, { encoding: 'base64', sigVerify: true }]) })
  const s4 = await req(P, '/relay/sol', { body: rpc('simulateTransaction', [unsigned]) })
  assert.equal(s1.status, 200)
  assert.equal(JSON.stringify(s1.j?.result?.value?.err), '"AccountNotFound"', 'unsigned simulate of an unfunded payer')
  assert.deepEqual([s2.status, s3.status, s4.status], [403, 403, 403])
  const sg = await req(P, '/relay/sol', { body: rpc('getSignaturesForAddress', [kp.publicKey.toBase58(), { limit: 10, commitment: 'confirmed' }]) })
  assert.ok(sg.status === 200 && Array.isArray(sg.j?.result))
  const ep = await req(P, '/relay/sol/ep/0', { body: rpc('getLatestBlockhash', [{ commitment: 'finalized' }]) })
  assert.ok(ep.status === 200 && ep.j?.result?.value?.lastValidBlockHeight > 0)
  const dup = await req(P, '/relay/eth', { body: '{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","method":"eth_chainId","params":[]}' })
  assert.ok(dup.status === 200 && dup.j?.result === '0x7a69', 'duplicate "method" keys → the relay forwards ITS parsed method only (canonical envelope, M5)')
  const pf = await req(P, '/relay/sol', { body: rpc('getRecentPrioritizationFees', []) })
  assert.ok(pf.status === 200 && Array.isArray(pf.j?.result))
  const pr = await req(P, '/relay/price', { method: 'GET' })
  assert.ok(pr.status === 200 && pr.j?.fixture === true && pr.j.prices.SOL.usd === 150 && pr.j.prices.ETH.usd === 3000)
  assert.equal((await req(P, '/relay/price', { body: {} })).status, 403)
  const tg = await req(P, '/relay/tor', { method: 'GET' })
  assert.ok(tg.status === 200 && tg.j?.profile === 'local' && tg.j?.tor === false && tg.j?.isTor === null && Object.keys(tg.j?.roles || {}).join() === 'eth,sol,price,check,btc,drand' && tg.j?.endpoints?.sol === 1)   // S6: btc and drand roles (endpoints.json local; drand: the testnet section's, D-R15)
  // S6 fix round 1 (review I-1): the local relay says what goes through Tor (drand and its IsTor check; not checked yet), and
  // its ready banner says so too, never "none (direct loopback)" while it serves drand
  assert.deepEqual([tg.j?.torRoles, tg.j?.checkedAt], [['check', 'drand'], null])
  assert.ok(relay.lines.some((l) => new RegExp(`^listening on loopback :${P} build policy \\(.*, tor drand only, via Tor \\(socks5h; IsTor checked on first use\\); chains direct loopback\\)$`).test(l)), relay.lines.join(' | '))
  assert.deepEqual(tg.j.confinement, { ok: true, probes: 5, result: 'EPERM ×5' })
  assert.equal((await req(P, '/relay/tor/new', { body: { role: 'eth' } })).status, 403)
  { const rr = (await req(P, '/relay/release', { method: 'GET' })).j; assert.deepEqual(Object.keys(rr).sort(), ['hashedAt', 'release']); assert.equal(rr.release, false); assert.ok(Number.isSafeInteger(rr.hashedAt)) }   // a dev tree
  const st = await req(P, '/relay/status', { method: 'GET' })
  // S6: endpoints.json local names a regtest bitcoind, but this relay has no VAULT_TIMELOCK_DIR, so it reads no credential and
  // sends nothing to it (or to ord): btc is reported off, never checked
  assert.deepEqual(st.j, { network: 'local', build: 'policy', confined: true, identity: { eth: { ok: true }, sol: { ok: true }, btc: { ok: false, message: 'the bitcoind credential is unavailable ($OUT/local/btc-rpc.auth)' } }, endpoints: { eth: 1, sol: 1, btc: 0 } })
  assert.ok(relay.lines.some((l) => l.startsWith('btc: the bitcoind credential is not read: VAULT_TIMELOCK_DIR is not an absolute path')))
  assert.ok(relay.lines.includes('identity btc: DISABLED — the bitcoind credential is unavailable ($OUT/local/btc-rpc.auth); /relay/btc answers 503, ord is not served'))
  assert.ok(!relay.lines.some((l) => /loopback:(?:18443|8090)/.test(l)), 'the shared bitcoind / ord were asked')
  const id = await req(P, '/relay/eth', { body: rpc('eth_chainId') })
  assert.equal(id.j?.result, '0x7a69')

  // ---- the send gate, with real transactions on this test's own chains
  const acct = privateKeyToAccount(generatePrivateKey())
  assert.equal((await direct(anvil, 'anvil_setBalance', [acct.address, '0xde0b6b3a7640000'])).result, null)
  const ethData = Buffer.from('data:,relay policy')
  const raw = await acct.signTransaction({ chainId: 31337, type: 'eip1559', nonce: 0, to: '0x0000000000000000000000000000000000000000', value: 0n,
    data: toHex(ethData), gas: 60_000n, maxFeePerGas: 20_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n })
  const txId = keccak256(raw)
  const ethJob = { c: 'eth' as const, t: txId, r: sha(Buffer.from(raw.slice(2), 'hex')), a: acct.address.toLowerCase(), k: 'job' as const, p: sha(ethData), to: '0x0000000000000000000000000000000000000000', value: null, f: String(60_000n * 20_000_000_000n), q: '0', x: '60000:1000000000:20000000000' }
  const ethNo = await req(P, '/relay/eth', { body: rpc('eth_sendRawTransaction', [raw]) })
  assert.deepEqual([ethNo.status, ethNo.j?.error?.data?.guard], [403, 'relay.send-ticket'])
  const wrong = await req(P, '/relay/eth', { body: rpc('eth_sendRawTransaction', [raw]), headers: { 'x-vt-send-ticket': ticket({ ...ethJob, r: sha(randomBytes(32)) }) } })
  assert.deepEqual([wrong.status, wrong.j?.error?.data?.guard], [403, 'relay.ticket-raw'])
  // S4: the ticket's worst-case fee one wei under gas × maxFee, another payload digest, another sender, another declared
  // nonce (CC-3a) → refused
  for (const over of [{ f: String(60_000n * 20_000_000_000n - 1n) }, { p: sha(Buffer.from('another payload')) }, { a: `0x${'44'.repeat(20)}` }, { q: '1' }]) {
    const d = await req(P, '/relay/eth', { body: rpc('eth_sendRawTransaction', [raw]), headers: { 'x-vt-send-ticket': ticket({ ...ethJob, ...over }) } })
    assert.deepEqual([d.status, d.j?.error?.data?.guard, d.j?.error?.code], [403, 'relay.decode-mismatch', -32003], JSON.stringify(over))
  }
  assert.equal((await direct(anvil, 'eth_getTransactionCount', [acct.address, 'latest'])).result, '0x0', 'nothing was forwarded')
  assert.equal((await direct(anvil, 'eth_getTransactionByHash', [txId])).result, null, 'not even in the pool')
  const ethOk = await req(P, '/relay/eth', { body: rpc('eth_sendRawTransaction', [raw]), headers: { 'x-vt-send-ticket': ticket(ethJob) } })
  assert.deepEqual([ethOk.status, ethOk.j?.result], [200, txId])
  const rcpt = await waitFor(async () => (await req(P, '/relay/eth', { body: rpc('eth_getTransactionReceipt', [txId]) })).j?.result ?? null, 30_000, 'eth receipt')
  assert.equal(rcpt.status, '0x1')
  // a real ETH claw-back: value to the destination, no data
  const dest = privateKeyToAccount(generatePrivateKey()).address
  const clawRaw = await acct.signTransaction({ chainId: 31337, type: 'eip1559', nonce: 1, to: dest, value: 123_456_789n, gas: 21_000n, maxFeePerGas: 20_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n })
  const clawId = keccak256(clawRaw)
  const claw = { c: 'eth' as const, t: clawId, r: sha(Buffer.from(clawRaw.slice(2), 'hex')), a: acct.address.toLowerCase(), k: 'clawback' as const, p: null, to: dest.toLowerCase(), value: '123456789', f: String(21_000n * 20_000_000_000n), q: '1', x: '21000:1000000000:20000000000' }
  const clawBad = await req(P, '/relay/eth', { body: rpc('eth_sendRawTransaction', [clawRaw]), headers: { 'x-vt-send-ticket': ticket({ ...claw, value: '123456788' }) } })
  assert.deepEqual([clawBad.status, clawBad.j?.error?.data?.guard], [403, 'relay.decode-mismatch'])
  const clawOk = await req(P, '/relay/eth', { body: rpc('eth_sendRawTransaction', [clawRaw]), headers: { 'x-vt-send-ticket': ticket(claw) } })
  assert.deepEqual([clawOk.status, clawOk.j?.result], [200, clawId])
  const crcpt = await waitFor(async () => (await req(P, '/relay/eth', { body: rpc('eth_getTransactionReceipt', [clawId]) })).j?.result ?? null, 30_000, 'eth claw-back receipt')
  assert.equal(crcpt.status, '0x1')
  assert.equal(BigInt((await direct(anvil, 'eth_getBalance', [dest, 'latest'])).result), 123_456_789n)

  const payer = Keypair.generate()
  const air = await req(P, '/relay/sol', { body: rpc('requestAirdrop', [payer.publicKey.toBase58(), 1_000_000_000]) })   // R71d: local + testnet
  assert.equal(air.status, 200)
  assert.equal(typeof air.j?.result, 'string')
  await waitFor(async () => ((await req(P, '/relay/sol', { body: rpc('getBalance', [payer.publicKey.toBase58(), { commitment: 'confirmed' }]) })).j?.result?.value > 0 ? true : null), 60_000, 'airdrop')
  const bh = (await req(P, '/relay/sol', { body: rpc('getLatestBlockhash', [{ commitment: 'confirmed' }]) })).j.result.value.blockhash
  // laid out as vt's builder lays it out (PF-S fix round 2: SetComputeUnitLimit, no price, the memo)
  const tx = new Transaction({ feePayer: payer.publicKey, recentBlockhash: bh }).add(ComputeBudgetProgram.setComputeUnitLimit({ units: 30_000 }), new TransactionInstruction({ programId: new PublicKey(MEMO), keys: [], data: Buffer.from('vt relay policy') }))
  tx.sign(payer)
  const wire = tx.serialize()
  const b64 = Buffer.from(wire).toString('base64')
  const sigBytes = tx.signature
  assert.ok(sigBytes !== null)
  const sigB58 = bs58(sigBytes)                                     // the tx id the API would journal
  const solNo = await req(P, '/relay/sol', { body: rpc('sendTransaction', [b64, { encoding: 'base64' }]) })
  assert.deepEqual([solNo.status, solNo.j?.error?.data?.guard], [403, 'relay.send-ticket'])
  const solJob = { c: 'sol' as const, t: sigB58, r: sha(wire), a: payer.publicKey.toBase58(), k: 'job' as const, p: sha(Buffer.from('vt relay policy')), to: null, value: null, f: '5000', q: bh, x: '30000:0' }
  for (const over of [{ f: '4999' }, { p: sha(Buffer.from('another memo')) }, { q: Keypair.generate().publicKey.toBase58() }]) {
    const d = await req(P, '/relay/sol', { body: rpc('sendTransaction', [b64, { encoding: 'base64' }]), headers: { 'x-vt-send-ticket': ticket({ ...solJob, ...over }) } })
    assert.deepEqual([d.status, d.j?.error?.data?.guard], [403, 'relay.decode-mismatch'], JSON.stringify(over))
  }
  const solTk = ticket(solJob)
  for (let i = 0; i < 2; i++) {                                     // the second is an identical-bytes rebroadcast
    const cfg = i === 0 ? { encoding: 'base64', preflightCommitment: 'confirmed' } : { encoding: 'base64', skipPreflight: true, maxRetries: 0 }   // as packages/core sol.js
    const ok = await req(P, '/relay/sol', { body: rpc('sendTransaction', [b64, cfg]), headers: { 'x-vt-send-ticket': solTk } })
    assert.equal(ok.status, 200)
    assert.equal(ok.j?.result, sigB58, JSON.stringify(ok.j?.error ?? null))
  }
  // Sfix1: the same bytes with the same ticket at verified endpoint 0 (as the E5 engine sends them), once per ticket
  const viaEp = await req(P, '/relay/sol/ep/0', { body: rpc('sendTransaction', [b64, { encoding: 'base64', skipPreflight: true, maxRetries: 0 }]), headers: { 'x-vt-send-ticket': solTk } })
  assert.deepEqual([viaEp.status, viaEp.j?.result], [200, sigB58], JSON.stringify(viaEp.j?.error ?? null))
  const epTwice = await req(P, '/relay/sol/ep/0', { body: rpc('sendTransaction', [b64, { encoding: 'base64', skipPreflight: true, maxRetries: 0 }]), headers: { 'x-vt-send-ticket': solTk } })
  assert.deepEqual([epTwice.status, epTwice.j?.error?.data?.guard], [403, 'relay.ticket-endpoint-reused'])
  const conf = await waitFor(async () => {
    const v = (await req(P, '/relay/sol', { body: rpc('getSignatureStatuses', [[sigB58]]) })).j?.result?.value?.[0]
    return v && (v.confirmationStatus === 'confirmed' || v.confirmationStatus === 'finalized') ? v : null
  }, 60_000, 'sol confirmation')
  assert.equal(conf.err, null)
  // a real SOL claw-back: one System transfer from the payer
  const solDest = Keypair.generate().publicKey
  const bh2 = (await req(P, '/relay/sol', { body: rpc('getLatestBlockhash', [{ commitment: 'confirmed' }]) })).j.result.value.blockhash
  const ctx = new Transaction({ feePayer: payer.publicKey, recentBlockhash: bh2 }).add(SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: solDest, lamports: 2_000_000 }))
  ctx.sign(payer)
  const cwire = ctx.serialize(), cb64 = Buffer.from(cwire).toString('base64'), csig = bs58(ctx.signature!)
  const solClaw = { c: 'sol' as const, t: csig, r: sha(cwire), a: payer.publicKey.toBase58(), k: 'clawback' as const, p: null, to: solDest.toBase58(), value: '2000000', f: '5000', q: bh2, x: '200000:0' }
  const cBad = await req(P, '/relay/sol', { body: rpc('sendTransaction', [cb64, { encoding: 'base64' }]), headers: { 'x-vt-send-ticket': ticket({ ...solClaw, to: Keypair.generate().publicKey.toBase58() }) } })
  assert.deepEqual([cBad.status, cBad.j?.error?.data?.guard], [403, 'relay.decode-mismatch'])
  const cOk = await req(P, '/relay/sol', { body: rpc('sendTransaction', [cb64, { encoding: 'base64', preflightCommitment: 'confirmed' }]), headers: { 'x-vt-send-ticket': ticket(solClaw) } })
  assert.equal(cOk.j?.result, csig, JSON.stringify(cOk.j?.error ?? null))
  await waitFor(async () => ((await req(P, '/relay/sol', { body: rpc('getBalance', [solDest.toBase58(), { commitment: 'confirmed' }]) })).j?.result?.value === 2_000_000 ? true : null), 60_000, 'sol claw-back')

  // the log: chain, method, status, ms (and the guard on a refusal) — never params, never an IP
  const reqLines = relay.lines.filter((l) => /^(?:eth|sol|price|tor|release|status|-) /.test(l))
  assert.ok(reqLines.length > 40)
  for (const l of reqLines) assert.match(l, /^(?:eth|sol|price|tor|release|status|-) (?:[A-Za-z_]+|-) \d{3} \d+ms(?: [a-z0-9]+(?:[.-][a-z0-9]+)*)?$/)
  const all = relay.lines.join('\n')
  assert.ok(!IPV4.test(all), 'an IPv4 literal in the relay output')
  for (const secret of [raw.slice(2, 40), b64.slice(0, 40), acct.address.slice(2).toLowerCase(), payer.publicKey.toBase58(), solTk.slice(12, 60)]) assert.ok(!all.toLowerCase().includes(secret.toLowerCase()), 'a param reached the log')
})

// base58 (Bitcoin alphabet) for the signature
function bs58(b: Uint8Array): string {
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  let n = 0n
  for (const x of b) n = n * 256n + BigInt(x)
  let s = ''
  while (n > 0n) { s = A[Number(n % 58n)] + s; n /= 58n }
  for (const x of b) { if (x === 0) s = `1${s}`; else break }
  return s
}

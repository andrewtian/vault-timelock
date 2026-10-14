// cli/test/localnet.test.ts — `vt localnet` (LN1): argument parsing, the command lines it builds (no secret on any argv), the port
// and identity decisions, the credential file (0600, atomic, the relay's own loader accepts it), `fund` (address validation, local-only
// refusal), --reset's path guard, and the stop order. Every server here is a fake on 127.0.0.1:0; no chain, no tmux server, no docker
// (the real thing is test/integration/localnet.test.ts). Synthetic data only.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, createHmac, randomBytes } from 'node:crypto'
import { createServer as createHttp } from 'node:http'
import type { Server } from 'node:http'
import { spawn } from 'node:child_process'
import { createServer as createTcp } from 'node:net'
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { GENESIS, endpoint, loadBitcoindAuth, loadConfig } from 'vt-broadcast/src/config.ts'
import { btcFromSecret } from '@vault-timelock/core/chains/btc.js'
import { COMMANDS } from '../src/args.ts'
import { main } from '../src/main.ts'
import {
  ANVIL_CHAIN_ID, DEFAULT_PORTS, ORD_VERSION, OTTERSCAN_IMAGE, SERVICE_SCRIPT, SESSION, SOLANA_PROFILE, STOP_ORDER,
  allPorts, anvilArgv, assertOrdVersion, assertPorts, assertTools, bitcoinConf, bitcoindArgv, containerName, decide, findTool, formatUnits,
  isBtcRegtestAddress, isEthAddress, isSolAddress, keccak256Hex, localnetCommand, localnetDown, localnetFund, localnetPaths, localnetStatus, localnetUp,
  minerAlive, minerArgv, ownedCookie, ordArgv, otterscanArgv, parseAmount, parseLocalnetArgs, probeAnvil, probeBitcoind, probeOrd, probeSolana, readCookieLine, readCredentialLine,
  readOrMakePass, resetData, rpcAuthLine, solanaArgv, windowArgv, writeCredential,
} from '../src/ops/localnet.ts'
import type { Identity, LocalnetPorts, Tools } from '../src/ops/localnet.ts'
import { jsonRpc, tcpOpen } from '../src/ops/localnet-rpc.ts'
import { mineLoop, ownerOk } from '../src/ops/localnet-miner.ts'
import type { Tmux, TmuxResult } from '../src/ops/tmux.ts'
import { UsageError } from '../src/args.ts'
import { NODE, PATH0, rejectsWith, removeDir, tempDir, throwsWith, writeExe } from './lib.ts'

let T = ''
before(() => { T = tempDir('vt-localnet-') })
after(() => removeDir(T))
let n = 0
const fresh = (): string => { const d = join(T, `d${++n}`); mkdirSync(d, { mode: 0o700 }); return d }

// ---- fakes

interface Call { method: string; params: unknown; path: string; auth: string | undefined }
type Handler = (method: string, params: unknown, path: string) => unknown // a result, or { error: string }
async function fakeRpc(handler: Handler, authOk: (auth: string | undefined) => boolean = () => true): Promise<{ port: number; calls: Call[]; server: Server }> {
  const calls: Call[] = []
  const server = createHttp((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      let j: { method?: string; params?: unknown } = {}
      try { j = JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch { /* GET */ }
      calls.push({ method: j.method ?? req.method ?? '', params: j.params, path: req.url ?? '', auth: req.headers.authorization })
      if (!authOk(req.headers.authorization)) { res.statusCode = 401; res.end(); return }
      const r = handler(j.method ?? '', j.params, req.url ?? '')
      res.setHeader('content-type', 'application/json')
      if (typeof r === 'object' && r !== null && 'error' in r) res.end(JSON.stringify({ jsonrpc: '2.0', id: 'vt', error: { code: -1, message: String((r as { error: string }).error) } }))
      else res.end(JSON.stringify({ jsonrpc: '2.0', id: 'vt', result: r }))
    })
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  return { port: (server.address() as { port: number }).port, calls, server }
}
const stop = (s: Server): Promise<void> => new Promise((r) => { s.close(() => r()); s.closeAllConnections() })

// A tmux that records its calls and has the windows it was told about.
function fakeTmux(windows: string[] | null): Tmux & { calls: string[][]; windows: string[] | null } {
  const t = {
    calls: [] as string[][],
    windows,
    run(args: readonly string[]): TmuxResult {
      t.calls.push([...args])
      const [cmd] = args
      if (cmd === 'has-session') return { code: t.windows === null ? 1 : 0, err: '' }
      if (cmd === 'list-windows') return t.windows === null ? { code: 1, err: '' } : { code: 0, err: '', out: t.windows.join('\n') + '\n' }
      if (cmd === 'kill-window') {
        const name = (args[2] ?? '').split(':=')[1]
        t.windows = (t.windows ?? []).filter((w) => w !== name)
        if (t.windows.length === 0) t.windows = null
        return { code: 0, err: '' }
      }
      if (cmd === 'kill-session') { t.windows = null; return { code: 0, err: '' } }
      return { code: 0, err: '' }
    },
  }
  return t
}

// I2: tests never use the shared chains' ports (8545/8999/18443/8090/5100): every service gets its own high port, unless a test says otherwise
const HI = { anvil: 46001, solana: 46002, solanaFaucet: 46004, solanaGossip: 46005, solanaDynFrom: 46010, solanaDynTo: 46040, bitcoind: 46006, ord: 46007, otterscan: 46008 }
const ports = (over: Partial<LocalnetPorts> = {}): LocalnetPorts => ({ ...HI, ...over })
const TOOLS: Tools = { anvil: '/x/anvil', solana: '/x/solana-test-validator', bitcoind: '/x/bitcoind', ord: '/x/ord', docker: null }
const PASS = randomBytes(16).toString('hex')

// ---- arguments

test('parseLocalnetArgs: up flags (each at most once), status, down, fund', () => {
  assert.deepEqual(parseLocalnetArgs(['up']), { sub: 'up', btc: true, otterscan: true, reset: false, mineEvery: 5 })
  assert.deepEqual(parseLocalnetArgs(['up', '--no-btc', '--no-otterscan', '--reset', '--mine-every', '2']), { sub: 'up', btc: false, otterscan: false, reset: true, mineEvery: 2 })
  for (const bad of [['up', '--no-btc', '--no-btc'], ['up', '--mine-every'], ['up', '--mine-every', '0'], ['up', '--mine-every', '3601'], ['up', '--mine-every', '2.5'], ['up', '--mine-every', '2', '--mine-every', '3'],
    ['up', '--open'], ['up', 'extra'], ['status', '--yaml'], ['status', '--json', 'x'], ['down', 'x'], ['fund'], ['fund', 'doge', 'x'], ['fund', 'eth'], ['fund', 'eth', 'a', '1', 'z'], [], ['nope']]) {
    assert.throws(() => parseLocalnetArgs(bad), UsageError, bad.join(' '))
  }
  assert.deepEqual(parseLocalnetArgs(['status']), { sub: 'status', json: false })
  assert.deepEqual(parseLocalnetArgs(['status', '--json']), { sub: 'status', json: true })
  assert.deepEqual(parseLocalnetArgs(['down']), { sub: 'down' })
  assert.deepEqual(parseLocalnetArgs(['fund', 'sol', 'abc']), { sub: 'fund', chain: 'sol', address: 'abc', amount: null })
  assert.deepEqual(parseLocalnetArgs(['fund', 'btc', 'abc', '0.5']), { sub: 'fund', chain: 'btc', address: 'abc', amount: '0.5' })
})

test('localnet is an unsandboxed orchestration command, listed in vt help', () => {
  assert.equal(COMMANDS.localnet, 'none')
})

// ---- ports

test('the default ports are the endpoints of broadcast/endpoints.json `local` and Otterscan 5100', () => {
  const cfg = loadConfig('local', {})
  const port = (key: string): number => Number(new URL(endpoint(cfg, key)[0]).port)
  assert.equal(DEFAULT_PORTS.anvil, port('eth.rpc'))
  assert.equal(DEFAULT_PORTS.solana, port('sol.rpc'))
  assert.equal(DEFAULT_PORTS.bitcoind, port('btc.bitcoind'))
  assert.equal(DEFAULT_PORTS.ord, port('btc.ord'))
  assert.equal(DEFAULT_PORTS.otterscan, 5100)
  assertPorts(DEFAULT_PORTS)
})

test('localnet.port-forbidden: :8899 and :8900 (the validator\'s defaults, left to other validators) are never used, also as the validator\'s pubsub or faucet or range', () => {
  for (const over of [{ anvil: 8899 }, { solana: 8899 }, { solana: 8898 }, { solana: 8899 + 0, solanaFaucet: 9911 }, { solanaFaucet: 8900 }, { solanaGossip: 8899 }, { ord: 8900 },
    { solanaDynFrom: 8880, solanaDynTo: 8910 }]) throwsWith(() => assertPorts(ports(over)), 'localnet.port-forbidden')
  assert.ok(!allPorts(DEFAULT_PORTS).includes(8899) && !allPorts(DEFAULT_PORTS).includes(8900), 'the defaults never touch them')
  // malformed or colliding ports are usage errors
  assert.throws(() => assertPorts(ports({ anvil: 80 })), UsageError)
  assert.throws(() => assertPorts(ports({ ord: HI.anvil })), UsageError)
  assert.throws(() => assertPorts(ports({ solanaDynTo: HI.solanaDynFrom + 3 })), UsageError)
})

// ---- the command lines

test('command lines: the exact flags of the brief, and no secret on any argv', () => {
  const p = DEFAULT_PORTS
  const env = { PATH: '/usr/bin:/bin', HOME: '/h' }
  assert.deepEqual(anvilArgv('anvil', p, '/d/anvil').slice(0, 9), ['anvil', '--host', '127.0.0.1', '--port', '8545', '--chain-id', '31337', '--block-time', '1'])
  assert.ok(anvilArgv('anvil', p, '/d/anvil').join(' ').includes('--state /d/anvil/state.json'))
  const sol = solanaArgv('stv', p, '/d/solana/ledger')
  assert.deepEqual(sol.slice(0, 4), ['/usr/bin/sandbox-exec', '-p', SOLANA_PROFILE, 'stv'])
  const solText = sol.join(' ')
  for (const need of ['--ledger /d/solana/ledger', '--bind-address 127.0.0.1', '--rpc-port 8999', '--limit-ledger-size 50000000', '--faucet-port 9910', '--gossip-port 8110', '--dynamic-port-range 8111-8160']) assert.ok(solText.includes(need), need)
  assert.ok(!/\b(8899|8900|9900|8001)\b/.test(solText), ':8899/:8900 and the validator defaults are never named')
  const btc = bitcoindArgv('bitcoind', p, '/d/bitcoind')
  for (const need of ['-regtest', '-server=1', '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1', '-rpcport=18443', '-datadir=/d/bitcoind', '-conf=/d/bitcoind/bitcoin.conf', '-listen=0']) assert.ok(btc.includes(need), need)
  const ord = ordArgv('ord', p, '/d/bitcoind', '/d/ord')
  assert.deepEqual(ord.slice(0, 3), ['ord', '--regtest', '--bitcoin-rpc-url'])
  assert.ok(ord.join(' ').includes('--cookie-file /d/bitcoind/regtest/.cookie') && ord.join(' ').includes('server --address 127.0.0.1 --http-port 8090'))
  const ot = otterscanArgv('docker', p)
  assert.ok(ot.includes('127.0.0.1:5100:80') && ot.includes(OTTERSCAN_IMAGE) && OTTERSCAN_IMAGE === 'otterscan/otterscan:v2.11.0')
  assert.ok(!ot.join(' ').includes('0.0.0.0') && !ot.includes('5100:80') && !ot.some((a) => a === '--network=host' || a === '--net=host'), 'bound to 127.0.0.1 only')
  assert.ok(ot.includes('ERIGON_URL=http://127.0.0.1:8545'))
  assert.equal(containerName(p), 'vt-localnet-otterscan-5100')
  // no secret: nothing in any window command (including the env words and the miner) holds the password or its hash
  const conf = bitcoinConf('vt', PASS)
  const hash = /^rpcauth=vt:([0-9a-f]{32})\$([0-9a-f]{64})$/m.exec(conf)
  assert.ok(hash !== null, 'bitcoin.conf holds the salted rpcauth line')
  assert.equal(hash[2], createHmac('sha256', hash[1]).update(PASS).digest('hex'), 'rpcauth is HMAC-SHA256(salt, password)')
  assert.ok(!conf.includes(PASS), 'the conf holds the hash, not the password')
  const all = [
    windowArgv('anvil', '/l/anvil.log', env, anvilArgv('anvil', p, '/d/anvil')),
    windowArgv('solana', '/l/solana.log', env, sol),
    windowArgv('bitcoind', '/l/bitcoind.log', env, btc),
    windowArgv('miner', '/l/miner.log', env, minerArgv('/n/node', '/o/local/btc-rpc.auth', '/h/localnet/state.json', p, 5)),
    windowArgv('ord', '/l/ord.log', env, ord),
    windowArgv('otterscan', '/l/otterscan.log', env, ot),
  ]
  for (const argv of all) {
    const text = argv.join('\0')
    assert.ok(!text.includes(PASS) && !text.includes(hash[2]) && !/rpcpassword|rpcauth|-rpcuser|authorization/i.test(text), `no credential on argv: ${argv[3]}`)
    assert.deepEqual(argv.slice(0, 3), ['/bin/sh', '-c', SERVICE_SCRIPT])
    assert.equal(argv[5], '20', 'the KILL grace')
  }
  assert.deepEqual(windowArgv('ord', '/l/ord.log', env, ord).slice(3, 7), ['vt-ord', 'INT', '20', '/l/ord.log'], 'ord stops on INT; the others on TERM')
  assert.equal(windowArgv('anvil', '/l/a.log', env, ['x'])[4], 'TERM')
  assert.deepEqual(minerArgv('/n/node', '/o/local/btc-rpc.auth', '/h/localnet/state.json', p, 5).slice(0, 2), ['/n/node', '--disable-sigusr1'])
  assert.deepEqual(minerArgv('/n/node', '/o/local/btc-rpc.auth', '/h/localnet/state.json', p, 5).slice(3), ['/o/local/btc-rpc.auth', '/h/localnet/state.json', '18443', '5'], 'the miner gets the credential FILE path, never its contents')
  assert.ok(rpcAuthLine('vt', PASS).startsWith('vt:'))
})

test('the window script: stop signal on HUP, one KILL fallback, no killing by pattern', () => {
  assert.ok(SERVICE_SCRIPT.includes('trap stop HUP INT TERM') && SERVICE_SCRIPT.includes('kill -"$sig" "$p"'))
  for (const w of [['pk', 'ill'], ['kill', 'all'], ['pg', 'rep'], ['ls', 'of']]) assert.ok(!SERVICE_SCRIPT.includes(w.join('')), `the window script never looks processes up by name (${w.join('')})`)
  assert.ok(SERVICE_SCRIPT.includes('vt: exited with status'))
})

// ---- tools

test('localnet.tool-missing: every missing tool is named with its install hint; docker is optional; --no-btc needs no bitcoind/ord', () => {
  const none: Tools = { anvil: null, solana: null, bitcoind: null, ord: null, docker: null }
  try { assertTools(none, { btc: true }); assert.fail('refused') } catch (e) {
    assert.equal((e as { guardId?: string }).guardId, 'localnet.tool-missing')
    const m = (e as Error).message
    for (const t of ['anvil', 'solana-test-validator', 'bitcoind', `ord ${ORD_VERSION}`]) assert.ok(m.includes(t), t)
    assert.ok(/foundry/i.test(m) && /anza/i.test(m) && /bitcoin/i.test(m) && /ordinals/i.test(m), 'install hints')
  }
  throwsWith(() => assertTools({ ...TOOLS, anvil: null }, { btc: false }), 'localnet.tool-missing')
  throwsWith(() => assertTools({ ...TOOLS, ord: null }, { btc: true }), 'localnet.tool-missing')
  assertTools({ ...TOOLS, bitcoind: null, ord: null, docker: null }, { btc: false })
  assertTools(TOOLS, { btc: true })
  // findTool walks PATH, ignores relative entries and non-executables
  const bin = fresh()
  writeExe(join(bin, 'anvil'), '#!/bin/sh\n')
  writeFileSync(join(bin, 'ord'), 'x')
  chmodSync(join(bin, 'ord'), 0o644)
  assert.equal(findTool('anvil', `rel/dir:${bin}`), join(bin, 'anvil'))
  assert.equal(findTool('ord', bin), null)
  assert.equal(findTool('anvil', undefined), null)
})

test('localnet.ord-version: only exactly ord 0.29.0', () => {
  assertOrdVersion('ord 0.29.0\n')
  for (const bad of ['ord 0.28.0', 'ord 0.29.1', 'ord 0.30.0', 'ord 0.29.0-rc1', '', 'bitcoind 0.29.0', 'ord  0.29.0']) throwsWith(() => assertOrdVersion(bad), 'localnet.ord-version')
})

// ---- identity and the reuse decision

test('decide: free -> start; right identity -> reuse; any other taken port -> refuse', () => {
  const ok: Identity = { right: true, version: 'v', why: '' }
  const bad: Identity = { right: false, version: '-', why: 'x' }
  assert.equal(decide(false, null), 'start')
  assert.equal(decide(false, ok), 'start')
  assert.equal(decide(true, ok), 'reuse')
  assert.equal(decide(true, bad), 'refuse')
  assert.equal(decide(true, null), 'refuse')
})

test('identity probes: anvil chain id 31337, the validator\'s RECORDED genesis, bitcoind regtest by vt\'s datadir COOKIE (the credential only after that), ord tied to THIS bitcoind', async () => {
  const eth = await fakeRpc((m) => (m === 'eth_chainId' ? `0x${ANVIL_CHAIN_ID.toString(16)}` : m === 'web3_clientVersion' ? 'anvil/v9' : { error: 'x' }))
  const mainnetEth = await fakeRpc((m) => (m === 'eth_chainId' ? '0x1' : { error: 'x' }))
  const web = await fakeRpc(() => ({ error: 'nope' }))
  const GEN = '4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZAMdL4VZHirAn'
  const sol = await fakeRpc((m) => (m === 'getGenesisHash' ? GEN : m === 'getVersion' ? { 'solana-core': '9.9.9' } : { error: 'x' }))
  const solMain = await fakeRpc((m) => (m === 'getGenesisHash' ? GENESIS.sol.mainnet : { error: 'x' }))
  const cookie = `__cookie__:${randomBytes(32).toString('hex')}`
  const cred = `vt:${PASS}`
  const hdr = (l: string): string => `Basic ${Buffer.from(l).toString('base64')}`
  // a bitcoind: answers only to its cookie and (when credOk) to the credential file's line
  const bitcoind = (credOk: boolean, chain = 'regtest', genesis: string = GENESIS.btc.regtest) => fakeRpc((m, params) => (
    m === 'getblockchaininfo' ? { chain } : m === 'getblockhash' ? ((params as number[])[0] === 0 ? genesis : (params as number[])[0] > 50 ? { error: 'Block height out of range' } : `h${(params as number[])[0]}`) : m === 'getnetworkinfo' ? { subversion: '/Satoshi:31.0.0/' } : m === 'getblockcount' ? 7 : { error: 'x' }), (auth) => auth === hdr(cookie) || (credOk && auth === hdr(cred)))
  const btc = await bitcoind(true), btcNoCred = await bitcoind(false), btcMain = await bitcoind(true, 'main', GENESIS.btc.mainnet)
  const squat = await fakeRpc(() => ({ error: 'I am a squatter' }), () => true)
  // ord: answers /status, /r/blockheight, /r/blockhash/<h>
  const ordOf = async (chain: string, height: number, hashOf: (h: number) => string): Promise<Server> => {
    const srv = createHttp((q, r) => {
      const u = q.url ?? ''
      r.setHeader('content-type', 'application/json')
      if (u === '/status') r.end(JSON.stringify({ chain, height }))
      else if (u === '/r/blockheight') r.end(String(height))
      else if (u.startsWith('/r/blockhash/')) r.end(JSON.stringify(hashOf(Number(u.slice(13)))))
      else { r.statusCode = 404; r.end('x') }
    })
    await new Promise<void>((res) => srv.listen(0, '127.0.0.1', res))
    return srv
  }
  const ordOurs = await ordOf('regtest', 5, (h) => `h${h}`)           // its tip hash is this bitcoind's
  const ordOther = await ordOf('regtest', 5, (h) => `other${h}`)      // regtest, same genesis, ANOTHER chain (a leftover index)
  const ordMain = await ordOf('main', 5, (h) => `h${h}`)
  const ordAhead = await ordOf('regtest', 99, (h) => `h${h}`)         // ahead of the bitcoind: not this chain
  const pOf = (s: Server): number => (s.address() as { port: number }).port
  const tie = { port: btc.port, cookie }
  try {
    assert.deepEqual(await probeAnvil(eth.port), { right: true, version: 'anvil/v9', why: '' })
    assert.equal((await probeAnvil(mainnetEth.port)).right, false)
    assert.equal((await probeAnvil(web.port)).right, false)
    assert.equal((await probeSolana(sol.port, GEN)).right, true)
    assert.equal((await probeSolana(sol.port, GEN)).version, 'solana-core 9.9.9')
    assert.equal((await probeSolana(sol.port, null)).right, false, 'unrecorded genesis: not reused')
    assert.equal((await probeSolana(sol.port, 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG')).right, false, 'another ledger')
    assert.equal((await probeSolana(solMain.port, GENESIS.sol.mainnet)).right, false, 'a public network is never local, even if "recorded"')
    // bitcoind: the cookie identifies it; M7: the credential file's password goes only to a listener the cookie identified
    const b = await probeBitcoind(btc.port, cookie, cred)
    assert.equal(b.right, true)
    assert.equal(b.version, 'Satoshi 31.0.0')
    assert.ok(btc.calls.some((c) => c.auth === hdr(cookie)) && btc.calls.some((c) => c.auth === hdr(cred)), 'cookie first, then the credential file')
    assert.equal((await probeBitcoind(btc.port, cookie)).right, true, 'status: cookie only')
    assert.equal((await probeBitcoind(btc.port, null)).right, false, 'no cookie: cannot be identified')
    assert.equal((await probeBitcoind(btcNoCred.port, cookie, cred)).right, false, 'vt\'s bitcoind that does not accept the credential file')
    assert.match((await probeBitcoind(btcNoCred.port, cookie, cred)).why, /credential file/)
    assert.equal((await probeBitcoind(btc.port, cookie, null)).right, false, 'no usable credential file')
    assert.equal((await probeBitcoind(btcMain.port, cookie, cred)).right, false)
    // M7: an unidentified listener never sees the credential
    assert.equal((await probeBitcoind(squat.port, `__cookie__:${'0'.repeat(64)}`, cred)).right, false)
    for (const c of [...squat.calls, ...btcMain.calls, ...btcNoCred.calls.slice(0, 0)]) assert.notEqual(c.auth, hdr(cred), 'the credential was sent to a listener that was not identified')
    // I1: ord is vt's only when its tip is on THIS bitcoind's chain
    const good = await probeOrd(pOf(ordOurs), tie)
    assert.equal(good.right, true)
    assert.ok(!/0\.29/.test(good.version), 'a reused ord shows no version it did not report')
    assert.equal((await probeOrd(pOf(ordOther), tie)).right, false, 'regtest genesis is shared: another regtest\'s index is refused')
    assert.match((await probeOrd(pOf(ordOther), tie)).why, /not the chain of vt's bitcoind/)
    assert.equal((await probeOrd(pOf(ordMain), tie)).right, false)
    assert.equal((await probeOrd(pOf(ordAhead), tie)).right, false, 'ahead of this bitcoind')
    assert.equal((await probeOrd(pOf(ordOurs), null)).right, false, 'no bitcoind of vt\'s to tie it to')
    assert.equal((await probeOrd(1, tie)).right, false)
  } finally {
    for (const x of [eth, mainnetEth, web, sol, solMain, btc, btcNoCred, btcMain, squat]) await stop(x.server)
    for (const x of [ordOurs, ordOther, ordMain, ordAhead]) await stop(x)
  }
})

// ---- up: a port taken by anything else refuses before anything starts

function upEnv(): Record<string, string> {
  const h = fresh(), o = fresh()
  return { PATH: PATH0, HOME: h, VT_HOME: join(h, 'vt'), VAULT_TIMELOCK_DIR: o }
}
// vt's bitcoind datadir cookie (what vt's own calls to bitcoind use), written 0600 like bitcoind does; returns the line
function writeCookie(env: Record<string, string>): string {
  const dir = join(localnetPaths(vtHomeOf(env)).bitcoind, 'regtest')
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const line = `__cookie__:${randomBytes(32).toString('hex')}`
  writeFileSync(join(dir, '.cookie'), line)
  chmodSync(join(dir, '.cookie'), 0o600)
  return line
}
const vtHomeOf = (env: Record<string, string>): string => env.VT_HOME
// the pid `vt localnet up` recorded for its bitcoind (state.json), and a listenerPid that agrees / disagrees with it
function recordOwner(env: Record<string, string>, pid: number): void {
  const paths = localnetPaths(vtHomeOf(env))
  mkdirSync(paths.root, { recursive: true, mode: 0o700 })
  writeFileSync(paths.state, `${JSON.stringify({ pids: { bitcoind: pid } })}\n`)
  chmodSync(paths.state, 0o600)
}
const cookieGate = (line: string) => (auth: string | undefined): boolean => auth === `Basic ${Buffer.from(line).toString('base64')}`
const upDeps = (tmux: Tmux, p: LocalnetPorts) => ({ loopbackOnly: () => true, dockerRun: () => ({ code: 0 }), tmux, ports: p, tools: TOOLS, node: process.execPath, ordVersionOutput: () => `ord ${ORD_VERSION}\n`, dockerReady: () => false, out: () => {}, err: () => {} })

test('localnet.port-taken: a port answered by anything but the right identity refuses, names the port, and starts nothing', async () => {
  const squat = createTcp((s) => s.end())
  await new Promise<void>((r) => squat.listen(0, '127.0.0.1', r))
  const port = (squat.address() as { port: number }).port
  const web = await fakeRpc(() => ({ error: 'I am not an Ethereum node' }))
  try {
    for (const [which, p] of [['anvil', port], ['anvil', web.port]] as const) {
      const tmux = fakeTmux(null)
      const env = upEnv()
      await assert.rejects(() => localnetUp({ btc: true, otterscan: false, reset: false, mineEvery: 5, env }, upDeps(tmux, ports({ [which]: p }))), (e: unknown) => {
        assert.equal((e as { guardId?: string }).guardId, 'localnet.port-taken')
        assert.ok((e as Error).message.includes(`port ${p} (anvil)`), (e as Error).message)
        assert.ok(!/\b\d{1,3}(?:\.\d{1,3}){3}\b/.test((e as Error).message), 'no IP in the message')
        return true
      })
      assert.ok(!tmux.calls.some((c) => c[0] === 'new-session' || c[0] === 'new-window' || c[0] === 'kill-session'), 'nothing was started or killed')
    }
    // --reset refuses any answering port, even a right identity would be reused otherwise
    const tmux = fakeTmux(null)
    await rejectsWith(() => localnetUp({ btc: false, otterscan: false, reset: true, mineEvery: 5, env: upEnv() }, upDeps(tmux, ports({ anvil: port }))), 'localnet.port-taken')
    // the validator also needs rpc+1 and the faucet: a squatter there refuses too, naming THAT port (every other port is a free high one,
    // so nothing else can be what refuses)
    for (const over of [{ solanaFaucet: port }, { solana: port - 1 }] as const) {
      const t = fakeTmux(null)
      await assert.rejects(() => localnetUp({ btc: false, otterscan: false, reset: false, mineEvery: 5, env: upEnv() }, upDeps(t, ports(over))), (e: unknown) => {
        assert.equal((e as { guardId?: string }).guardId, 'localnet.port-taken')
        assert.match((e as Error).message, new RegExp(`port ${port} \\(solana\\).*the validator also needs`), (e as Error).message)
        return true
      })
      assert.ok(t.calls.every((c) => c[0] === 'has-session'), 'nothing started')
    }
    // I1: a taken ord with no bitcoind of vt's to tie it to (bitcoind is about to be started) refuses; so does one outside our session
    await rejectsWith(() => localnetUp({ btc: true, otterscan: false, reset: false, mineEvery: 5, env: upEnv() }, upDeps(fakeTmux(null), ports({ ord: port }))), 'localnet.port-taken')
    // M6: a reused Otterscan must be bound to 127.0.0.1 only
    const ot = createHttp((q, r) => r.end('<html>Otterscan</html>'))
    await new Promise<void>((r) => ot.listen(0, '127.0.0.1', r))
    try {
      const op = (ot.address() as { port: number }).port
      const wide = fakeTmux(null)
      await assert.rejects(() => localnetUp({ btc: false, otterscan: true, reset: false, mineEvery: 5, env: upEnv() }, { ...upDeps(wide, ports({ otterscan: op })), dockerReady: () => true, loopbackOnly: () => false }), (e: unknown) => {
        assert.equal((e as { guardId?: string }).guardId, 'localnet.port-taken')
        assert.match((e as Error).message, /more than 127\.0\.0\.1/)
        return true
      })
      assert.ok(wide.calls.every((c) => c[0] === 'has-session'))
    } finally { await stop(ot) }
  } finally {
    squat.close(); await stop(web.server)
  }
})

test('localnet.tool-missing and localnet.ord-version come before any port is probed; --reset needs the localnet stopped; non-local network refused', async () => {
  const tmux = fakeTmux(null)
  await rejectsWith(() => localnetUp({ btc: true, otterscan: false, reset: false, mineEvery: 5, env: upEnv() }, { ...upDeps(tmux, DEFAULT_PORTS), tools: { ...TOOLS, anvil: null } }), 'localnet.tool-missing')
  await rejectsWith(() => localnetUp({ btc: true, otterscan: false, reset: false, mineEvery: 5, env: upEnv() }, { ...upDeps(tmux, DEFAULT_PORTS), ordVersionOutput: () => 'ord 0.28.0' }), 'localnet.ord-version')
  await rejectsWith(() => localnetUp({ btc: true, otterscan: false, reset: false, mineEvery: 5, env: upEnv() }, upDeps(tmux, ports({ solana: 8899 }))), 'localnet.port-forbidden')
  assert.equal(tmux.calls.length, 0, 'no tmux call at all')
  await assert.rejects(() => localnetUp({ btc: false, otterscan: false, reset: true, mineEvery: 5, env: upEnv() }, upDeps(fakeTmux(['anvil']), DEFAULT_PORTS)), UsageError)
  for (const network of ['testnet', 'mainnet']) await rejectsWith(() => localnetCommand({ args: ['status'], env: upEnv(), network }), 'localnet.network')
})

// ---- the credential

test('the credential: 32 random hex, 0600, written atomically, kept across restarts, and the relay\'s own loader accepts it', () => {
  const out = fresh()
  const a = readOrMakePass(out)
  assert.equal(a.fresh, true)
  assert.match(a.pass, /^[0-9a-f]{32}$/)
  assert.notEqual(readOrMakePass(out).pass, a.pass, 'nothing written yet: a new one each time')
  const file = writeCredential(out, a.pass)
  assert.equal(file, join(out, 'local', 'btc-rpc.auth'))
  assert.equal(statSync(file).mode & 0o777, 0o600)
  assert.equal(statSync(join(out, 'local')).mode & 0o077, 0, 'the directory is private')
  assert.equal(readFileSync(file, 'utf8'), `vt:${a.pass}\n`)
  assert.equal(loadBitcoindAuth(out), `vt:${a.pass}`, 'the relay\'s loader (0600, one user:pass line) accepts it')
  assert.ok(a.pass.length >= 16)
  assert.deepEqual(readOrMakePass(out), { pass: a.pass, fresh: false }, 'kept: a running relay needs no restart')
  assert.equal(readCredentialLine(out), `vt:${a.pass}`)
  // atomic: a rewrite renames a new file over the old (new inode), leaves no temp file behind
  const ino = statSync(file).ino
  writeCredential(out, 'f'.repeat(32))
  assert.notEqual(statSync(file).ino, ino, 'replaced by rename, not written in place')
  assert.deepEqual(readdirSync(join(out, 'local')), ['btc-rpc.auth'])
  assert.equal(statSync(file).mode & 0o777, 0o600)
  // M1: exactly the relay loader's rule: mode 0700 (owner x) and a control character in the password are refused, as loadBitcoindAuth does
  chmodSync(file, 0o700)
  assert.equal(readCredentialLine(out), null, 'mode 0700 is not 0600')
  assert.equal(readOrMakePass(out).fresh, true)
  chmodSync(file, 0o600)
  writeFileSync(file, `vt:${'a'.repeat(15)}\u0001\n`)
  chmodSync(file, 0o600)
  assert.equal(readCredentialLine(out), null, 'a control character')
  assert.equal(readOrMakePass(out).fresh, true)
  writeFileSync(file, `vt:${'a'.repeat(32)}\n`)
  chmodSync(file, 0o600)
  assert.equal(readCredentialLine(out), `vt:${'a'.repeat(32)}`)
  // a file with a loose mode, a short password or another user is not reused
  chmodSync(file, 0o644)
  assert.equal(readOrMakePass(out).fresh, true)
  assert.equal(readCredentialLine(out), null)
  chmodSync(file, 0o600)
  writeFileSync(file, 'vt:short\n')
  chmodSync(file, 0o600)
  assert.equal(readOrMakePass(out).fresh, true)
  writeFileSync(file, `other:${'a'.repeat(32)}\n`)
  chmodSync(file, 0o600)
  assert.equal(readOrMakePass(out).fresh, true)
})

// ---- fund

test('address validation per chain', () => {
  // M10: EIP-55 (and the keccak-256 under it)
  assert.equal(keccak256Hex(''), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
  assert.equal(keccak256Hex('abc'), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')
  for (const ok of ['0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359', '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB', '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
    '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed', '0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED']) assert.ok(isEthAddress(ok), ok)
  for (const bad of ['0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD', '0x5AaeB6053F3E94C9b9A09f33669435E7Ef1BeAed', '0xFb6916095ca1df60bB79Ce92cE3Ea74c37c5d359']) assert.ok(!isEthAddress(bad), `bad checksum: ${bad}`)
  assert.ok(isEthAddress(`0x${'ab'.repeat(20)}`) && !isEthAddress('0x1234') && !isEthAddress(`0x${'zz'.repeat(20)}`) && !isEthAddress('ab'.repeat(20)))
  assert.ok(isSolAddress('11111111111111111111111111111111') && isSolAddress('Vote111111111111111111111111111111111111111'))
  assert.ok(!isSolAddress('0OIl') && !isSolAddress('abc') && !isSolAddress('1'.repeat(45)) && !isSolAddress(`0x${'ab'.repeat(20)}`))
  const reg = btcFromSecret(randomBytes(32).toString('hex'), 'local').address
  assert.ok(reg.startsWith('bcrt1') && isBtcRegtestAddress(reg), 'a regtest p2wpkh address')
  const flipped = reg.slice(0, -1) + (reg.endsWith('q') ? 'p' : 'q')
  assert.ok(!isBtcRegtestAddress(flipped), 'bad checksum')
  assert.ok(isBtcRegtestAddress(reg.toUpperCase()), 'BIP-173: an all-uppercase bech32 address is valid')
  assert.ok(!isBtcRegtestAddress(reg.slice(0, 10) + reg.slice(10).toUpperCase()), 'mixed case is not')
  for (const bad of ['bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy', '', 'bcrt1', 'bcrt1qqqqqqqq']) {
    assert.ok(!isBtcRegtestAddress(bad), bad)
  }
  // a legacy regtest address: version 0x6f + 20 bytes + checksum
  const body = Buffer.concat([Buffer.from([0x6f]), randomBytes(20)])
  const chk = createHmacless(body)
  assert.ok(isBtcRegtestAddress(base58(Buffer.concat([body, chk]))), 'base58check regtest p2pkh')
  const main = Buffer.concat([Buffer.from([0x00]), randomBytes(20)])
  assert.ok(!isBtcRegtestAddress(base58(Buffer.concat([main, createHmacless(main)]))), 'a mainnet p2pkh is refused')
})
function createHmacless(b: Buffer): Buffer { return createHash('sha256').update(createHash('sha256').update(b).digest()).digest().subarray(0, 4) }
function base58(b: Buffer): string {
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  let x = BigInt(`0x${b.toString('hex')}`)
  let s = ''
  while (x > 0n) { s = A[Number(x % 58n)] + s; x /= 58n }
  for (const byte of b) { if (byte === 0) s = `1${s}`; else break }
  return s
}

test('amounts: positive decimals in the unit, no more decimals than the unit has', () => {
  assert.equal(parseAmount('1', 18, 'ether'), 10n ** 18n)
  assert.equal(parseAmount('0.000000000000000001', 18, 'ether'), 1n)
  assert.equal(parseAmount('2', 9, 'SOL'), 2_000_000_000n)
  assert.equal(parseAmount('0.01', 8, 'BTC'), 1_000_000n)
  for (const bad of ['0', '0.0', '-1', '1e3', '1.', '.5', 'abc', '', '0.123456789', '1,5']) assert.throws(() => parseAmount(bad, 8, 'BTC'), UsageError, bad)
  assert.equal(formatUnits(1_000_000n, 8), '0.01')
  assert.equal(formatUnits(10n ** 18n, 18), '1')
  assert.equal(formatUnits(1_500_000_000n, 9), '1.5')
})

test('localnet.fund-address: a bad address refuses before any node is contacted', async () => {
  const eth = await fakeRpc(() => '0x7a69')
  try {
    const env = upEnv()
    for (const [chain, address] of [['eth', '0x12'], ['sol', 'nope'], ['btc', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'], ['btc', `0x${'ab'.repeat(20)}`], ['eth', '11111111111111111111111111111111']] as const) {
      await rejectsWith(() => localnetFund({ chain, address, amount: null, env }, { ports: ports({ anvil: eth.port }) }), 'localnet.fund-address')
    }
    assert.equal(eth.calls.length, 0, 'not one request left the process')
  } finally { await stop(eth.server) }
})

test('localnet.fund-network: a node that is not a local chain is refused, and nothing is sent to it', async () => {
  const env = upEnv()
  const eth = await fakeRpc((m) => (m === 'eth_chainId' ? '0x1' : '0x0'))
  const sol = await fakeRpc((m) => (m === 'getGenesisHash' ? GENESIS.sol.mainnet : { error: 'x' }))
  const sol2 = await fakeRpc((m) => (m === 'getGenesisHash' ? '4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZAMdL4VZHirAn' : { error: 'x' }))
  const ck = writeCookie(env)
  const btc = await fakeRpc((m) => (m === 'getblockchaininfo' ? { chain: 'main' } : m === 'getblockhash' ? GENESIS.btc.mainnet : { error: 'x' }), cookieGate(ck))
  const addr = { eth: `0x${'ab'.repeat(20)}`, sol: '11111111111111111111111111111111', btc: btcFromSecret(randomBytes(32).toString('hex'), 'local').address }
  try {
    await rejectsWith(() => localnetFund({ chain: 'eth', address: addr.eth, amount: null, env }, { ports: ports({ anvil: eth.port }) }), 'localnet.fund-network')
    await rejectsWith(() => localnetFund({ chain: 'sol', address: addr.sol, amount: null, env }, { ports: ports({ solana: sol.port }) }), 'localnet.fund-network')
    // a local-looking ledger that is not the recorded one
    const paths = localnetPaths(join(env.HOME, 'vt'))
    mkdirSync(paths.solana, { recursive: true, mode: 0o700 })
    writeFileSync(join(paths.solana, 'genesis-hash'), `${GENESIS.sol.devnet}\n`)
    await rejectsWith(() => localnetFund({ chain: 'sol', address: addr.sol, amount: null, env }, { ports: ports({ solana: sol2.port }) }), 'localnet.fund-network')
    recordOwner(env, 4242)
    await rejectsWith(() => localnetFund({ chain: 'btc', address: addr.btc, amount: null, env }, { ports: ports({ bitcoind: btc.port }), listenerPid: () => 4242 }), 'localnet.fund-network')
    for (const s of [eth, sol, sol2, btc]) assert.ok(!s.calls.some((c) => /send|airdrop/i.test(c.method)), 'nothing was sent')
  } finally { for (const s of [eth, sol, sol2, btc]) await stop(s.server) }
})

test('fund on local chains: eth from dev account 0 (default 1 ether), sol airdrop (default 2 SOL), btc sendtoaddress + 1 block (default 0.01 BTC)', async () => {
  const env = upEnv()
  const ck = writeCookie(env)
  const GEN = '4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZAMdL4VZHirAn'
  const dev0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
  const eth = await fakeRpc((m) => (m === 'eth_chainId' ? '0x7a69' : m === 'eth_accounts' ? [dev0] : m === 'eth_sendTransaction' ? `0x${'11'.repeat(32)}` : m === 'eth_getTransactionReceipt' ? { blockNumber: '0x5' } : { error: 'x' }))
  const sol = await fakeRpc((m) => (m === 'getGenesisHash' ? GEN : m === 'requestAirdrop' ? 'SIG' : m === 'getSignatureStatuses' ? { value: [{ confirmationStatus: 'confirmed' }] } : { error: 'x' }))
  const btc = await fakeRpc((m) => (m === 'getblockchaininfo' ? { chain: 'regtest' } : m === 'getblockhash' ? GENESIS.btc.regtest : m === 'sendtoaddress' ? 'ab'.repeat(32) : m === 'getnewaddress' ? 'bcrt1qminer' : m === 'generatetoaddress' ? ['h'] : { error: 'x' }), cookieGate(ck))
  const out: string[] = []
  recordOwner(env, 777)
  const d = (p: Partial<LocalnetPorts>) => ({ listenerPid: () => 777, ports: ports(p), out: (l: string) => { out.push(l) }, sleep: async () => {} })
  const addr = { eth: `0x${'cd'.repeat(20)}`, sol: '11111111111111111111111111111111', btc: btcFromSecret(randomBytes(32).toString('hex'), 'local').address }
  try {
    assert.equal(await localnetFund({ chain: 'eth', address: addr.eth, amount: null, env }, d({ anvil: eth.port })), 0)
    const send = eth.calls.find((c) => c.method === 'eth_sendTransaction') as Call
    assert.deepEqual(send.params, [{ from: dev0, to: addr.eth, value: `0x${(10n ** 18n).toString(16)}` }])
    assert.ok(out.some((l) => l.includes(`0x${'11'.repeat(32)}`)), 'prints the tx id')
    assert.equal(await localnetFund({ chain: 'sol', address: addr.sol, amount: null, env }, d({ solana: sol.port })), 0)
    assert.deepEqual((sol.calls.find((c) => c.method === 'requestAirdrop') as Call).params, [addr.sol, 2_000_000_000])
    assert.ok(out.some((l) => l.includes('SIG')))
    assert.equal(await localnetFund({ chain: 'btc', address: addr.btc, amount: null, env }, d({ bitcoind: btc.port })), 0)
    const pay = btc.calls.find((c) => c.method === 'sendtoaddress') as Call
    assert.equal(pay.path, '/wallet/vt')
    assert.deepEqual(pay.params, { address: addr.btc, amount: '0.01' })
    assert.ok(btc.calls.some((c) => c.method === 'generatetoaddress' && (c.params as unknown[])[0] === 1), 'one block mined')
    assert.ok(out.some((l) => l.includes('ab'.repeat(32))))
    assert.ok(out.every((l) => !l.includes(PASS) && !l.includes(ck)), 'no credential, no cookie is printed')
    // M7/M9: `fund btc` uses only the datadir cookie, and without one it refuses (nothing to authenticate with) and sends nothing
    writeCredential(env.VAULT_TIMELOCK_DIR, PASS)
    assert.ok(btc.calls.every((c) => c.auth === `Basic ${Buffer.from(ck).toString('base64')}`), 'only the cookie was ever sent')
    // PF-C: not the recorded owner (a foreign pid on the port, or no record) -> no request with auth, not even the cookie
    const before = btc.calls.length
    const foreign = { ...d({ bitcoind: btc.port }), listenerPid: () => 999 }
    await assert.rejects(() => localnetFund({ chain: 'btc', address: addr.btc, amount: null, env }, foreign), (e: Error) => e.name === 'UsageError' && /nothing was sent/.test(e.message))
    await assert.rejects(() => localnetFund({ chain: 'btc', address: addr.btc, amount: null, env: upEnv() }, d({ bitcoind: btc.port })), (e: Error) => e.name === 'UsageError')
    assert.equal(btc.calls.length, before, 'not one request')
    // custom amounts
    await localnetFund({ chain: 'sol', address: addr.sol, amount: '0.25', env }, d({ solana: sol.port }))
    assert.deepEqual((sol.calls.filter((c) => c.method === 'requestAirdrop')[1] as Call).params, [addr.sol, 250_000_000])
    await assert.rejects(() => localnetFund({ chain: 'eth', address: addr.eth, amount: '0', env }, d({ anvil: eth.port })), UsageError)
  } finally { for (const s of [eth, sol, btc]) await stop(s.server) }
})

// ---- --reset

test('localnet.reset-path: --reset removes the four data directories and nothing else; a link or a file there refuses', () => {
  const home = fresh()
  const p = localnetPaths(home)
  for (const d of [p.anvil, p.solana, p.bitcoind, p.ord, p.logs]) mkdirSync(d, { recursive: true, mode: 0o700 })
  for (const d of [p.anvil, p.solana, p.bitcoind, p.ord]) writeFileSync(join(d, 'data'), 'x')
  writeFileSync(p.state, '{}\n')
  writeFileSync(join(p.logs, 'anvil.log'), 'log')
  const keep = join(home, 'precious.txt')
  writeFileSync(keep, 'keep')
  assert.deepEqual(resetData(p), ['anvil', 'solana', 'bitcoind', 'ord'])
  for (const d of [p.anvil, p.solana, p.bitcoind, p.ord]) assert.ok(!existsSync(d), d)
  assert.ok(existsSync(p.state) && existsSync(join(p.logs, 'anvil.log')) && existsSync(keep), 'only the data dirs went')
  assert.deepEqual(resetData(p), [], 'nothing to remove is fine')
  // a symlink in place of a data dir: refused, and its target is untouched
  const elsewhere = fresh()
  writeFileSync(join(elsewhere, 'canary'), 'canary')
  symlinkSync(elsewhere, p.ord)
  mkdirSync(p.anvil, { mode: 0o700 })
  writeFileSync(join(p.anvil, 'data'), 'x')
  throwsWith(() => resetData(p), 'localnet.reset-path')
  assert.ok(existsSync(join(elsewhere, 'canary')), 'the link target is untouched')
  assert.ok(lstatSync(p.ord).isSymbolicLink())
  // a plain file where a directory belongs
  const p2 = localnetPaths(fresh())
  mkdirSync(p2.root, { mode: 0o700 })
  writeFileSync(p2.solana, 'file')
  throwsWith(() => resetData(p2), 'localnet.reset-path')
})

// ---- down and status

test('down: stops the windows in order (ord before its bitcoind, chains last), then the session; the recorded Otterscan container only', async () => {
  const env = upEnv()
  const paths = localnetPaths(join(env.HOME, 'vt'))
  mkdirSync(paths.root, { recursive: true, mode: 0o700 })
  writeFileSync(paths.state, `${JSON.stringify({ otterscan: { container: 'vt-localnet-otterscan-5100', port: 5100 } })}\n`)
  chmodSync(paths.state, 0o600)
  const tmux = fakeTmux(['anvil', 'solana', 'bitcoind', 'miner', 'ord', 'otterscan'])
  const docker: string[][] = []
  const out: string[] = []
  const free = ports({ anvil: 45001, solana: 45002, bitcoind: 45004, ord: 45005, solanaFaucet: 45008, solanaGossip: 45009, solanaDynFrom: 45010, solanaDynTo: 45040, otterscan: 45006 })
  const code = await localnetDown({ env }, { tmux, ports: free, dockerRun: (a) => { docker.push([...a]); return { code: 0 } }, out: (l) => { out.push(l) }, err: () => {}, sleep: async () => {} })
  assert.equal(code, 0, out.join('\n'))
  const killed = tmux.calls.filter((c) => c[0] === 'kill-window').map((c) => (c[2] ?? '').split(':=')[1])
  assert.deepEqual(killed, [...STOP_ORDER])
  assert.ok(STOP_ORDER.indexOf('ord') < STOP_ORDER.indexOf('bitcoind') && STOP_ORDER.indexOf('miner') < STOP_ORDER.indexOf('bitcoind') && STOP_ORDER.indexOf('bitcoind') < STOP_ORDER.indexOf('anvil'))
  assert.ok(tmux.calls.every((c) => c[0] !== 'kill-server' && !(c[0] === 'kill-session' && c[2] !== `=${SESSION}`)), 'only the exact session vt-localnet')
  assert.ok(tmux.calls.filter((c) => c.includes('-t')).every((c) => (c[c.indexOf('-t') + 1] ?? '').startsWith(`=${SESSION}`)), 'every target is an exact =vt-localnet target')
  assert.deepEqual(docker, [['rm', '-f', 'vt-localnet-otterscan-5100']])
  assert.deepEqual(readOrEmpty(paths.state), {}, 'the container record is cleared')
  // not running: nothing is killed, no container is touched (none recorded)
  const t2 = fakeTmux(null)
  const docker2: string[][] = []
  assert.equal(await localnetDown({ env }, { tmux: t2, ports: free, dockerRun: (a) => { docker2.push([...a]); return { code: 0 } }, out: () => {}, err: () => {} }), 0)
  assert.ok(t2.calls.every((c) => c[0] === 'has-session') && docker2.length === 0)
  // a container name that is not vt's exact pattern is never passed to docker
  writeFileSync(paths.state, `${JSON.stringify({ otterscan: { container: 'someone-elses-container', port: 5100 } })}\n`)
  chmodSync(paths.state, 0o600)
  await localnetDown({ env }, { tmux: fakeTmux(null), ports: free, dockerRun: (a) => { docker2.push([...a]); return { code: 0 } }, out: () => {}, err: () => {} })
  assert.equal(docker2.length, 0)
})
function readOrEmpty(p: string): unknown { return JSON.parse(readFileSync(p, 'utf8')) }

test('status: nothing running is not ready (exit 1, JSON says so); a service with the wrong identity is flagged', async () => {
  const env = upEnv()
  const free = ports({ anvil: 45101, solana: 45102, bitcoind: 45104, ord: 45105, otterscan: 45106, solanaFaucet: 45108, solanaGossip: 45109, solanaDynFrom: 45110, solanaDynTo: 45140 })
  const lines: string[] = []
  assert.equal(await localnetStatus({ json: true, env }, { tmux: fakeTmux(null), ports: free, out: (l) => { lines.push(l) } }), 1)
  const j = JSON.parse(lines[0]) as { ok: boolean; services: Array<{ name: string; reachable: boolean }> }
  assert.equal(j.ok, false)
  assert.deepEqual(j.services.map((s) => s.name), ['anvil', 'solana', 'bitcoind', 'miner', 'ord', 'otterscan'])
  assert.ok(j.services.every((s) => !s.reachable))
  const eth = await fakeRpc((m) => (m === 'eth_chainId' ? '0x1' : { error: 'x' }))
  try {
    const l2: string[] = []
    assert.equal(await localnetStatus({ json: true, env }, { tmux: fakeTmux(null), ports: { ...free, anvil: eth.port }, out: (l) => { l2.push(l) } }), 1)
    const a = (JSON.parse(l2[0]) as { services: Array<{ name: string; identity: string; who: string }> }).services[0]
    assert.deepEqual([a.identity, a.who], ['wrong', 'external'])
  } finally { await stop(eth.server) }
  assert.equal(await tcpOpen(45101), false)
})

test('F-R-3: status from a VT_HOME that did not start the localnet says so (no IDENTITY WRONG for a service it has no proof for); a wrong anvil is still IDENTITY WRONG', async () => {
  const env = upEnv()   // a fresh VT_HOME: no genesis record, no credential file
  const free = ports({ anvil: 45121, solana: 45122, bitcoind: 45124, ord: 45125, otterscan: 45126, solanaFaucet: 45128, solanaGossip: 45129, solanaDynFrom: 45130, solanaDynTo: 45160 })
  const btc = await fakeRpc(() => ({ error: 'x' }), () => true)
  const eth = await fakeRpc((m) => (m === 'eth_chainId' ? '0x1' : { error: 'x' }))
  try {
    const lines: string[] = []
    await localnetStatus({ json: false, env }, { tmux: fakeTmux(['anvil', 'solana', 'bitcoind', 'miner', 'ord', 'otterscan']), ports: { ...free, bitcoind: btc.port, anvil: eth.port }, out: (l) => { lines.push(l) } })
    const text = lines.join('\n')
    assert.match(text, /bitcoind.*started under another VT_HOME — run status with that VT_HOME/)
    assert.ok(!/bitcoind[^\n]*IDENTITY WRONG/.test(text), text)
    assert.match(text, /anvil[^\n]*IDENTITY WRONG/)
    const j: string[] = []
    await localnetStatus({ json: true, env }, { tmux: fakeTmux(['anvil', 'solana', 'bitcoind', 'miner', 'ord', 'otterscan']), ports: { ...free, bitcoind: btc.port }, out: (l) => { j.push(l) } })
    assert.equal((JSON.parse(j[0]) as { services: Array<{ name: string; identity: string }> }).services.find((x) => x.name === 'bitcoind')?.identity, 'other-home')
  } finally { await stop(btc.server); await stop(eth.server) }
})

test('main(): vt localnet dispatches with the test-only ports seam; usage errors exit 1 via UsageError', async () => {
  const saved = process.env.NODE_ENV
  const env = upEnv()
  try {
    process.env.NODE_ENV = 'test'
    const lines: string[] = []
    const w = process.stdout.write.bind(process.stdout)
    process.stdout.write = ((s: string | Uint8Array) => { lines.push(String(s)); return true }) as typeof process.stdout.write
    let code: number
    try { code = await main(['localnet', 'status', '--json'], env, { localnetPorts: { anvil: 45201, solana: 45202, solanaFaucet: 45208, solanaGossip: 45204, solanaDynFrom: 45210, solanaDynTo: 45240, bitcoind: 45205, ord: 45206, otterscan: 45207 } }) } finally { process.stdout.write = w }
    assert.equal(code, 1)
    assert.equal((JSON.parse(lines.find((l) => l.startsWith('{"ok"')) as string) as { ok: boolean }).ok, false)
    await assert.rejects(() => main(['localnet', 'bogus'], env), UsageError)
    await rejectsWith(() => main(['localnet', 'status'], { ...env, VT_NETWORK: 'mainnet' }), 'localnet.network')
    delete process.env.NODE_ENV
    await rejectsWith(() => main(['localnet', 'status'], env, { localnetPorts: { anvil: 45201 } }), 'vt.test-only')
  } finally { if (saved === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = saved }
})

// ---- M9: down's "still answers" path

test('down: a port that still answers after its window was killed is reported (exit 1), and nothing is killed by port', async () => {
  const env = upEnv()
  const squat = createTcp((c) => c.end())
  await new Promise<void>((r) => squat.listen(0, '127.0.0.1', r))
  try {
    const stuck = (squat.address() as { port: number }).port
    const tmux = fakeTmux(['anvil', 'bitcoind'])
    let t = 0
    const err: string[] = [], out: string[] = []
    const code = await localnetDown({ env }, { tmux, ports: ports({ bitcoind: stuck }), now: () => t, sleep: async (ms) => { t += ms }, out: (l) => { out.push(l) }, err: (l) => { err.push(l) }, dockerRun: () => ({ code: 0 }) })
    assert.equal(code, 1)
    assert.match(err.join('\n'), /bitcoind still answers.*does not kill by port/)
    assert.deepEqual(out, [], 'no "stopped" line')
    assert.deepEqual(tmux.calls.filter((c) => c[0] === 'kill-window').map((c) => (c[2] ?? '').split(':=')[1]), ['bitcoind', 'anvil'], 'only windows, in order; the stuck one did not block the rest')
    assert.ok(tmux.calls.every((c) => ['has-session', 'list-windows', 'kill-window', 'kill-session'].includes(c[0])), 'tmux only')
    assert.ok(t >= 40_000, 'it waited for the port before giving up')
  } finally { squat.close() }
})

// ---- M6: a miner whose window is still there but has exited is dead

test('minerAlive: the window must exist and its log must not carry the exit marker', () => {
  const paths = localnetPaths(join(fresh(), 'vt'))
  mkdirSync(paths.logs, { recursive: true })
  const log = join(paths.logs, 'miner.log')
  assert.equal(minerAlive(paths, new Set(['miner'])), true, 'no log yet: still starting')
  writeFileSync(log, 'vt-miner ready every 5 s\n')
  assert.equal(minerAlive(paths, new Set(['miner'])), true)
  assert.equal(minerAlive(paths, new Set()), false, 'no window')
  writeFileSync(log, 'vt-miner ready every 5 s\nvt: exited with status 1\n')
  assert.equal(minerAlive(paths, new Set(['miner'])), false, 'exited: restarted, not "reused"')
})

// ---- M3: the window script keeps waiting through a second signal, then KILLs the service it started

test('SERVICE_SCRIPT: two signals do not orphan a TERM-ignoring service; the KILL fallback fires and the marker carries the real status', async () => {
  const d = fresh()
  const svc = join(d, 'svc.mjs'), log = join(d, 'svc.log')
  writeFileSync(svc, "process.on('SIGTERM', () => {}); process.on('SIGHUP', () => {}); console.log('pid ' + process.pid); setInterval(() => {}, 1000)\n")
  const sh = spawn('/bin/sh', ['-c', SERVICE_SCRIPT, 'vt-x', 'TERM', '2', log, NODE, svc], { stdio: 'ignore', detached: true })
  const t0 = Date.now()
  const read = (): string => (existsSync(log) ? readFileSync(log, 'utf8') : '')
  const until = async (f: () => boolean, ms: number): Promise<boolean> => { for (let i = 0; i < ms / 100; i++) { if (f()) return true; await new Promise((r) => setTimeout(r, 100)) } return false }
  try {
    assert.ok(await until(() => /^pid \d+$/m.test(read()), 10_000), 'the service started')
    const pid = Number(/^pid (\d+)$/m.exec(read())![1])
    process.kill(-(sh.pid as number), 'SIGHUP')              // the first stop signal (tmux kill-window sends HUP)
    await new Promise((r) => setTimeout(r, 700))
    process.kill(-(sh.pid as number), 'SIGHUP')              // a second one, while the first KILL is pending
    assert.ok(await until(() => /^vt: exited with status \d+$/m.test(read()), 15_000), `the marker appears: ${read()}`)
    assert.ok(Date.now() - t0 >= 2_000, 'not before the grace ran out: the second signal did not end the wait early')
    assert.match(read(), /^vt: exited with status 137$/m, 'the service\'s own status (KILL), not the interrupted wait\'s 129')
    assert.throws(() => process.kill(pid, 0), 'the service is gone, not orphaned')
  } finally { try { process.kill(-(sh.pid as number), 'SIGKILL') } catch { /* gone */ } }
})

// ---- PF-C credential disclosure

test('ownedCookie: the cookie is returned only when the listener IS the pid vt recorded; a record without a match, or no record, gives nothing', () => {
  const env = upEnv()
  const paths = localnetPaths(vtHomeOf(env))
  const ck = writeCookie(env)
  assert.equal(ownedCookie(paths, () => 5, 1), null, 'no record')
  recordOwner(env, 5)
  assert.equal(ownedCookie(paths, () => 5, 1), ck)
  assert.equal(ownedCookie(paths, () => 6, 1), null, 'another pid listens')
  assert.equal(ownedCookie(paths, () => null, 1), null, 'nobody / several listeners')
})

test('status: a foreign listener on the bitcoind port gets no request at all (no cookie, no credential); it is reported as wrong identity', async () => {
  const env = upEnv()
  const ck = writeCookie(env)
  recordOwner(env, 5)
  const squat = await fakeRpc(() => ({ error: 'squatter' }), () => true)
  try {
    const lines: string[] = []
    await localnetStatus({ json: true, env }, { tmux: fakeTmux(null), ports: ports({ bitcoind: squat.port }), listenerPid: () => 99, loopbackOnly: () => true, out: (l) => { lines.push(l) } })
    assert.deepEqual(squat.calls.map((c) => c.auth), [], 'no authenticated request reached the squatter')
    assert.equal((JSON.parse(lines[0]) as { services: Array<{ name: string; identity: string }> }).services.find((x) => x.name === 'bitcoind')?.identity, 'wrong')
    void ck
  } finally { await stop(squat.server) }
})

test('up: a foreign pid on the bitcoind port refuses (port-taken) before any authenticated request', async () => {
  const env = upEnv()
  writeCookie(env); recordOwner(env, 5)
  writeCredential(env.VAULT_TIMELOCK_DIR, PASS)
  const squat = await fakeRpc(() => ({ error: 'squatter' }), () => true)
  try {
    await rejectsWith(() => localnetUp({ btc: true, otterscan: false, reset: false, mineEvery: 5, env }, { ...upDeps(fakeTmux(null), ports({ bitcoind: squat.port })), listenerPid: () => 99 }), 'localnet.port-taken')
    assert.deepEqual(squat.calls.map((c) => c.auth), [])
  } finally { await stop(squat.server) }
})

test('scrub: server-reflected RPC errors lose the line, its Basic form, the password, the cookie and their base64', async () => {
  const cookie = `__cookie__:${randomBytes(32).toString('hex')}`
  const line = `vt:${PASS}`
  for (const secret of [line, cookie]) {
    const b64 = Buffer.from(secret).toString('base64')
    const srv = await fakeRpc(() => ({ error: `bad auth ${secret} / Basic ${b64} / ${b64} / ${secret.split(':')[1]} / ${Buffer.from(secret.split(':')[1]).toString('base64')}` }))
    try {
      const r = await jsonRpc(srv.port, 'x', [], { line: secret })
      assert.equal(r.ok, false)
      const text = JSON.stringify(r)
      for (const needle of [secret, b64, secret.split(':')[1], Buffer.from(secret.split(':')[1]).toString('base64')]) assert.ok(!text.includes(needle), `scrubbed: ${needle.slice(0, 6)}…`)
      assert.match(text, /redacted/)
    } finally { await stop(srv.server) }
  }
})

// ---- M-5: tests that fail if the M2 / M6 fixes are reverted; M-4 the miner's ownership check

// An "all reused except bitcoind-as-given" plan: fake anvil + validator + (optionally) ord on free ports, tmux that already has the windows
async function reusePlan(env: Record<string, string>, o: { bitcoind: 'reuse' | 'start' }) {
  const GEN = '4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZAMdL4VZHirAn'
  const paths = localnetPaths(vtHomeOf(env))
  mkdirSync(paths.solana, { recursive: true, mode: 0o700 })
  writeFileSync(join(paths.solana, 'genesis-hash'), `${GEN}\n`)
  const eth = await fakeRpc((m) => (m === 'eth_chainId' ? '0x7a69' : m === 'web3_clientVersion' ? 'anvil/v9' : { error: 'x' }))
  const sol = await fakeRpc((m) => (m === 'getGenesisHash' ? GEN : m === 'getVersion' ? { 'solana-core': '9' } : { error: 'x' }))
  const spacer = createTcp((c) => c.end())   // takes the next port: the validator also uses rpc+1, which assertPorts requires to differ
  await new Promise<void>((r) => spacer.listen(0, '127.0.0.1', r))
  const ck = writeCookie(env)
  const wallets: string[] = []
  const methods: string[] = []
  const btc = await fakeRpc((m, params) => {
    methods.push(m)
    if (m === 'getblockchaininfo') return { chain: 'regtest' }
    if (m === 'getblockhash') return (params as number[])[0] === 0 ? GENESIS.btc.regtest : `h${(params as number[])[0]}`
    if (m === 'getnetworkinfo') return { subversion: '/Satoshi:31.0.0/' }
    if (m === 'getblockcount') return 7
    if (m === 'listwallets') return wallets
    if (m === 'loadwallet') return { error: 'Wallet file not found' }
    if (m === 'createwallet') { wallets.push('vt'); return { name: 'vt' } }
    if (m === 'getbalance') return 50
    return { error: 'x' }
  }, (auth) => auth === `Basic ${Buffer.from(ck).toString('base64')}` || auth === `Basic ${Buffer.from(`vt:${PASS}`).toString('base64')}`)
  const ord = createHttp((q, r) => { const u = q.url ?? ''; if (u === '/status') r.end(JSON.stringify({ chain: 'regtest', height: 5 })); else if (u === '/r/blockheight') r.end('5'); else if (u.startsWith('/r/blockhash/')) r.end(JSON.stringify(`h${u.slice(13)}`)); else { r.statusCode = 404; r.end() } })
  await new Promise<void>((r) => ord.listen(0, '127.0.0.1', r))
  recordOwner(env, 4321)
  writeCredential(env.VAULT_TIMELOCK_DIR, PASS)
  const op = (ord.address() as { port: number }).port
  const pp = ports({ anvil: eth.port, solana: sol.port, bitcoind: btc.port, ord: op })
  const stopAll = async (): Promise<void> => { spacer.close(); await stop(eth.server); await stop(sol.server); await stop(btc.server); await stop(ord) }
  return { pp, paths, methods, wallets, stopAll, btc }
}

test('M6 (wallet on reuse): a reused bitcoind that has no wallet vt gets it created; a dead miner window is restarted, not reused', async () => {
  const env = upEnv()
  const x = await reusePlan(env, { bitcoind: 'reuse' })
  try {
    mkdirSync(x.paths.logs, { recursive: true, mode: 0o700 })
    writeFileSync(join(x.paths.logs, 'miner.log'), 'vt-miner ready every 5 s\nvt: exited with status 3\n')   // the miner exited
    const tmux = fakeTmux(['anvil', 'solana', 'bitcoind', 'miner', 'ord'])
    const lines: string[] = []
    // the miner relaunch cannot become ready with a fake tmux: it times out at once (now/sleep are faked), which is all this test needs to see
    let t = 0
    const code = await localnetUp({ btc: true, otterscan: false, reset: false, mineEvery: 5, env }, { ...upDeps(tmux, x.pp), listenerPid: () => 4321, now: () => (t += 10_000), sleep: async () => {}, out: (l) => { lines.push(l) }, err: () => {} })
    assert.ok(x.methods.includes('createwallet'), `the wallet was created on the reused bitcoind (${x.methods.join(',')})`)
    assert.ok(x.wallets.includes('vt'))
    assert.ok(tmux.calls.some((c) => c[0] === 'kill-window' && c[2] === `=${SESSION}:=miner`), 'the dead miner window was replaced')
    assert.ok(tmux.calls.some((c) => c[0] === 'new-window' && c.includes('miner')), 'and started again')
    void code
    assert.ok(!lines.some((l) => /^miner.*reused/.test(l)), 'not "reused"')
  } finally { await x.stopAll() }
})

test('M2: the credential file exists BEFORE bitcoind starts, and a failed start stops what this run started (nothing is left behind)', async () => {
  const env = upEnv()
  const GEN = '4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZAMdL4VZHirAn'
  const paths = localnetPaths(vtHomeOf(env))
  mkdirSync(paths.solana, { recursive: true, mode: 0o700 })
  writeFileSync(join(paths.solana, 'genesis-hash'), `${GEN}\n`)
  const eth = await fakeRpc((m) => (m === 'eth_chainId' ? '0x7a69' : m === 'web3_clientVersion' ? 'a' : { error: 'x' }))
  const sol = await fakeRpc((m) => (m === 'getGenesisHash' ? GEN : m === 'getVersion' ? { 'solana-core': '9' } : { error: 'x' }))
  const tmux = fakeTmux(null)
  const seen: boolean[] = []
  const origRun = tmux.run.bind(tmux)
  tmux.run = (args) => { if (args[0] === 'new-session' || args[0] === 'new-window') seen.push(readCredentialLine(env.VAULT_TIMELOCK_DIR) !== null && existsSync(join(paths.bitcoind, 'bitcoin.conf'))); return origRun(args) }
  let t = 0
  try {
    const err: string[] = []
    // bitcoind never becomes ready (fake tmux starts nothing): the run fails
    const code = await localnetUp({ btc: true, otterscan: false, reset: false, mineEvery: 5, env }, { ...upDeps(tmux, ports({ anvil: eth.port, solana: sol.port })), ourListener: () => 77, now: () => (t += 10_000), sleep: async () => {}, out: () => {}, err: (l) => { err.push(l) } })
    assert.equal(code, 1)
    assert.deepEqual(seen, [true], 'at the moment the bitcoind window was created, btc-rpc.auth and bitcoin.conf already existed')
    assert.ok(tmux.calls.some((c) => c[0] === 'kill-session'), 'the session this run created was stopped')
    assert.match(err.join('\n'), /bitcoind was not ready/)
    // and a THROW while starting (an unusable $OUT/local dir) is caught, reported and cleaned up too
    const bad = upEnv()
    mkdirSync(join(bad.VAULT_TIMELOCK_DIR, 'local'), { mode: 0o755 })      // ensureDir refuses a 0755 dir (store.perms)
    chmodSync(join(bad.VAULT_TIMELOCK_DIR, 'local'), 0o755)
    const p2 = localnetPaths(vtHomeOf(bad)); mkdirSync(p2.solana, { recursive: true, mode: 0o700 }); writeFileSync(join(p2.solana, 'genesis-hash'), `${GEN}\n`)
    const t2 = fakeTmux(null); const e2: string[] = []
    const c2 = await localnetUp({ btc: true, otterscan: false, reset: false, mineEvery: 5, env: bad }, { ...upDeps(t2, ports({ anvil: eth.port, solana: sol.port })), out: () => {}, err: (l) => { e2.push(l) } })
    assert.equal(c2, 1, e2.join('\n'))
    assert.ok(e2.length > 0, 'a message, not an uncaught throw')
  } finally { await stop(eth.server); await stop(sol.server) }
})

test('M-4: the miner sends nothing unless the pid listening on the bitcoind port is the one vt recorded', async () => {
  const env = upEnv()
  const paths = localnetPaths(vtHomeOf(env))
  recordOwner(env, 31)
  assert.equal(ownerOk(paths.state, 1, () => 31), true)
  assert.equal(ownerOk(paths.state, 1, () => 32), false, 'another pid')
  assert.equal(ownerOk(paths.state, 1, () => null), false, 'nobody')
  assert.equal(ownerOk(join(paths.root, 'missing.json'), 1, () => 31), false, 'no record')
  const squat = await fakeRpc(() => ({ error: 'x' }), () => true)
  const authFile = writeCredential(env.VAULT_TIMELOCK_DIR, PASS)
  const log: string[] = []
  try {
    const ok = await mineLoop({ authFile, stateFile: paths.state, port: squat.port, seconds: 1, log: (l) => { log.push(l) }, listenerPid: () => 32 })
    assert.equal(ok, false)
    assert.deepEqual(squat.calls, [], 'not one request reached the squatter')
    assert.match(log.join('\n'), /not the bitcoind vt started/)
  } finally { await stop(squat.server) }
})

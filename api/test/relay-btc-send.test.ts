// S6b (CC-8): the relay's ticketed BTC send, POST /relay/btc/send. The real createRelay in process; an injected transport plays
// every upstream (the bitcoind, Esplora, the eth chain id the relay needs to start; nothing leaves the machine: the URLs are
// only strings), the contract's tickets-btc.json plays the engine's tickets and txs. The bitcoind credential is synthetic.
//   · local: a ticketed commit and reveal reach the bitcoind's sendrawtransaction with the credential, after the relay's own
//     gettxout reads of the inputs; testnet4: the same through Esplora (GET /tx/<txid>/hex reads, hashed to the txid; POST /tx); the answer is { txid };
//   · mainnet and a mainnet identity: release.mainnet-locked, before any chain read or send;
//   · unticketed, badly ticketed, other bytes, a bad body: refused with the guard; nothing is forwarded;
//   · every decode vector (one defect each) refused over HTTP with its guard; a failing chain read refuses relay.btc-prevout;
//   · answers: only { txid }, only the txid the relay computed; an upstream's text, error or other id is withheld; an ambiguous
//     outcome is not retried; the raw tx, the ticket and the credential never reach a log line.
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { createServer, request } from 'node:http'
import type { Server } from 'node:http'
import * as btc from '@scure/btc-signer'
import { pubECDSA, pubSchnorr, randomPrivateKeyBytes } from '@scure/btc-signer/utils.js'
import { OutOrdinalReveal } from 'micro-ordinals'
import { btcNetwork, commitOutput, revealDestination } from '@vault-timelock/core/chains/btc-ord.ts'
import { PORTS, TICKET_HEADER, TICKET_TTL_MS } from '@vault-timelock/core/contracts'
import type { Network, TicketPayload } from '@vault-timelock/core/contracts'
import { GENESIS } from 'vt-broadcast/src/config.ts'
import { createRelay, relayUpstreams } from '../relay/relay.mjs'
import { esploraPrevout } from '../src/relay-routes.ts'
import { encodeTicket } from '../src/tickets.ts'
import { CANARY, TICKET_KEY, fixture } from './helpers.ts'

type Prevouts = Record<string, { value: string; script: string }>
interface Ctx { network: Network; raw: { value: string }; prevouts: Prevouts; rawTxs?: Record<string, string> }
interface Vector { name: string; ticket: string; now: number; context: Ctx; guard?: string }
interface Valid extends Vector { payload: TicketPayload }
const V = fixture<{ valid: Valid[]; negatives: Vector[]; decode: Vector[] }>('tickets-btc.json')
const NOW = 1_791_504_000_000
const AUTH_LINE = 'vtsynth:Synthetic-Pass-7f3a9c1e'
const AUTH_B64 = Buffer.from(AUTH_LINE).toString('base64')
const BTCD = 'http://127.0.0.1:18999'                    // a made-up port: only a string, the transport is fake
const IDS: Record<Network, { eth: string; sol: string; btc: string }> = {
  local: { eth: '0x7a69', sol: 'x', btc: GENESIS.btc.regtest }, testnet: { eth: '0xaa36a7', sol: GENESIS.sol.devnet, btc: GENESIS.btc.testnet4 },
  mainnet: { eth: '0x1', sol: GENESIS.sol.mainnet, btc: GENESIS.btc.mainnet },
}
const TOR_CHECK = 'https://check.torproject.org/api/ip'

interface UpRes { status: number; body: Buffer }
const json = (status: number, v: unknown): UpRes => ({ status, body: Buffer.from(JSON.stringify(v)) })
const text = (status: number, s: string): UpRes => ({ status, body: Buffer.from(s) })
interface Sent { url: string; hex: string; headers: Record<string, string> }
// The chain and the nodes, as the relay sees them. `prevouts` is what the chain holds for the next send.
interface World {
  prevouts: Prevouts
  txid: string                                        // what the node answers to an accepted send
  reads: string[]                                     // "<txid>:<vout>" of every input read (local: gettxout)
  rawTxs: Record<string, string>                      // testnet4 / mainnet Esplora: txid -> the raw tx hex GET /tx/<txid>/hex serves
  hexReads: string[]                                  // the txids Esplora was asked for
  sent: Sent[]
  calls: Array<{ url: string; method: string; headers: Record<string, string> }>
  onRead?: (outpoint: string) => UpRes | undefined    // override a read answer
  onSend?: (hex: string) => UpRes | Error | undefined // override a send answer
}
function makeWorld(network: Network): { world: World; transport: (url: string, r: { method: string; body?: Buffer; role: string; user: string; headers?: Record<string, string> }) => Promise<UpRes> } {
  const world: World = { prevouts: {}, txid: '', reads: [], rawTxs: {}, hexReads: [], sent: [], calls: [] }
  const transport = async (url: string, r: { method: string; body?: Buffer; role: string; user: string; headers?: Record<string, string> }): Promise<UpRes> => {
    const headers = { ...(r.headers ?? {}) }
    world.calls.push({ url, method: r.method, headers })
    if (url === TOR_CHECK) return json(200, { IsTor: true })
    const body = r.body ? r.body.toString('utf8') : null
    const rpc = body !== null && body.startsWith('{"jsonrpc"') ? JSON.parse(body) as { id: unknown; method: string; params?: unknown[] } : null
    const u = new URL(url)
    if (u.origin === BTCD) {
      if (headers.authorization !== `Basic ${AUTH_B64}`) return text(401, '')
      const reply = (result: unknown): UpRes => json(200, { result, error: null, id: rpc?.id ?? null })
      if (rpc?.method === 'getblockhash') return reply(IDS.local.btc)
      if (rpc?.method === 'gettxout') {
        const op = `${rpc.params![0] as string}:${rpc.params![1] as number}`
        world.reads.push(op)
        const o = world.onRead?.(op)
        if (o) return o
        const p = world.prevouts[op]
        return reply(p === undefined ? null : { bestblock: 'ab'.repeat(32), confirmations: 1, value: Number(p.value) / 1e8, scriptPubKey: { hex: p.script }, coinbase: false })
      }
      if (rpc?.method === 'sendrawtransaction') {
        const hex = rpc.params![0] as string
        world.sent.push({ url, hex, headers })
        const o = world.onSend?.(hex)
        if (o instanceof Error) throw o
        return o ?? reply(world.txid)
      }
      return reply(`${rpc?.method}-result`)
    }
    if (rpc && !u.pathname.includes('/tx')) return json(200, { jsonrpc: '2.0', id: rpc.id, result: rpc.method === 'eth_chainId' ? IDS[network].eth : rpc.method === 'getGenesisHash' ? IDS[network].sol : '0x5208' })
    if (u.pathname.endsWith('/block-height/0')) return text(200, IDS[network].btc)
    const read = /\/tx\/([0-9a-f]{64})\/hex$/.exec(u.pathname)         // S6b review m-2: the raw tx, whose double SHA-256 is its txid
    if (r.method === 'GET' && read) {
      world.hexReads.push(read[1])
      const o = world.onRead?.(read[1])
      if (o) return o
      const h = world.rawTxs[read[1]]
      return h === undefined ? text(404, 'Transaction not found') : text(200, h)
    }
    if (r.method === 'POST' && u.pathname.endsWith('/tx')) {
      world.sent.push({ url, hex: body ?? '', headers })
      const o = world.onSend?.(body ?? '')
      if (o instanceof Error) throw o
      return o ?? text(200, world.txid)
    }
    return json(404, {})
  }
  return { world, transport }
}

interface Started { port: number; network: Network; logs: string[]; world: World; clock: { t: number }; close(): Promise<void> }
const OPEN = new Set<{ close(): Promise<void> }>()
after(() => Promise.all([...OPEN].map((s) => s.close())))
async function start(network: Network, o: { auth?: string | null; btcUrls?: string[] } = {}): Promise<Started> {
  const { world, transport } = makeWorld(network)
  const logs: string[] = []
  const clock = { t: NOW }
  const upstream = network === 'local' ? { eth: ['http://127.0.0.1:18546'], sol: [] } : relayUpstreams(network, {})
  const breadth = network === 'local' ? { btc: [BTCD], ord: [], blockscout: {}, arweave: [], drand: [] } : { ...{ btc: o.btcUrls ?? ['https://esplora.example/api'], ord: [], blockscout: {}, arweave: [], drand: [] } }
  const relay = createRelay({
    network, build: 'test', upstream, breadth, bitcoindAuth: o.auth === undefined ? AUTH_LINE : o.auth, transport, priceFixture: network === 'local' ? { SOL: 150, ETH: 3000 } : null,
    ticketKey: () => TICKET_KEY, confinement: { ok: true, probes: 5, result: 'EPERM ×5' }, now: () => clock.t, log: (l: string) => { logs.push(l) }, rand: () => 'sess',
  })
  await relay.startup()
  const server: Server = createServer(relay.handle)
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const s: Started = { port: (server.address() as { port: number }).port, network, logs, world, clock, close: () => { OPEN.delete(s); return new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()) }) } }
  OPEN.add(s)
  return s
}
interface Reply { status: number; text: string; json: any }
function rq(s: Started, path: string, o: { method?: string; body?: unknown; headers?: Record<string, string>; contentType?: string | null } = {}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const b = o.body === undefined ? null : Buffer.from(typeof o.body === 'string' ? o.body : JSON.stringify(o.body))
    const ct = o.contentType === undefined ? 'application/json' : o.contentType
    const r = request({ host: '127.0.0.1', port: s.port, path, method: o.method ?? (b ? 'POST' : 'GET'),
      headers: { host: `127.0.0.1:${PORTS[s.network].relay}`, ...(b ? { 'content-length': String(b.length), ...(ct === null ? {} : { 'content-type': ct }) } : {}), ...o.headers } }, (res) => {
      const c: Buffer[] = []
      res.on('data', (d: Buffer) => c.push(d))
      res.on('end', () => { const t = Buffer.concat(c).toString('utf8'); let j: unknown; try { j = JSON.parse(t) } catch { j = undefined } resolve({ status: res.statusCode ?? 0, text: t, json: j }) })
    })
    r.on('error', reject)
    r.end(b ?? undefined)
  })
}
const g = (r: Reply): string | undefined => r.json?.error?.guard
// A ticketed send of a vector over HTTP, with the chain holding the vector's prevouts and answering its txid.
async function sendVector(s: Started, v: Vector, o: { hex?: string; body?: unknown; ticket?: string | null; txid?: string } = {}): Promise<Reply> {
  s.world.prevouts = v.context.prevouts
  s.world.rawTxs = v.context.rawTxs ?? {}
  s.world.txid = o.txid ?? (JSON.parse(Buffer.from(v.ticket.split('.')[1], 'base64url').toString('utf8')) as TicketPayload).t
  s.clock.t = v.now
  return rq(s, '/relay/btc/send', { body: 'body' in o ? o.body : { hex: o.hex ?? v.context.raw.value }, headers: o.ticket === null ? {} : { [TICKET_HEADER]: o.ticket ?? v.ticket } })
}
const validOn = (n: Network, k: string): Valid => V.valid.find((v) => v.payload.w === n && v.payload.k === k)!
const sentCount = (s: Started): number => s.world.sent.length

// ---- testnet4 vectors made of REAL transactions (S6b review m-2): the relay checks an Esplora answer by hashing it to the txid, so
// a prevout cannot be a made-up outpoint. A synthetic faucet funds the lane (tx F); the commit spends F:0; the reveal spends the
// commit's output 0. Synthetic keys, in memory only; nothing is signed for a real network.
const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex')
const hexOf = (b: Uint8Array): string => Buffer.from(b).toString('hex')
interface TnTx { tx: btc.Transaction; raw: Uint8Array; hex: string }
interface Testnet { commit: Valid; reveal: Valid; funding: TnTx; commitTx: TnTx; revealTx: TnTx; xonly: Uint8Array; lane: ReturnType<typeof btc.p2wpkh>; laneKey: Uint8Array }
function mkTestnet(): Testnet {
  const NET = btcNetwork('testnet')
  const laneKey = randomPrivateKeyBytes(), lanePub = pubECDSA(laneKey), xonly = pubSchnorr(laneKey)
  const lane = btc.p2wpkh(lanePub, NET)
  const faucetKey = randomPrivateKeyBytes(), faucet = btc.p2wpkh(pubECDSA(faucetKey), NET)
  const body = new TextEncoder().encode(`[1/1 ${randomBytes(4).toString('hex')}] a synthetic testnet4 inscription.\n`)
  const fin = (t: btc.Transaction): TnTx => { const raw = t.extract(); return { tx: t, raw, hex: hexOf(raw) } }
  const f = new btc.Transaction()
  f.addInput({ txid: 'aa'.repeat(32), index: 0, witnessUtxo: { script: faucet.script, amount: 6_000_000n } })
  f.addOutputAddress(lane.address!, 5_000_000n, NET)
  f.addOutputAddress(faucet.address!, 900_000n, NET)
  f.sign(faucetKey); f.finalize()
  const funding = fin(f)
  const rv = commitOutput('testnet', xonly, body)
  const revealFee = 400n, revealAmount = 546n + revealFee, commitFee = 300n
  const c = new btc.Transaction()
  c.addInput({ txid: f.id, index: 0, witnessUtxo: { script: lane.script, amount: 5_000_000n } })
  c.addOutputAddress(rv.address!, revealAmount, NET)
  c.addOutputAddress(lane.address!, 5_000_000n - revealAmount - commitFee, NET)
  c.sign(laneKey); c.finalize()
  const commitTx = fin(c)
  const dest = revealDestination('testnet', xonly)
  const r = new btc.Transaction({ customScripts: [OutOrdinalReveal] })
  r.addInput({ ...rv, txid: c.id, index: 0, witnessUtxo: { script: rv.script, amount: revealAmount } })
  r.addOutputAddress(dest, 546n, NET)
  r.sign(laneKey, undefined, new Uint8Array(32)); r.finalize()
  const revealTx = fin(r)
  const payload = (kind: 'commit' | 'reveal', t: TnTx, o: { f: bigint; q: string; to: string; value: bigint }): TicketPayload => ({ j: 'e3d45f73cf65abaa', w: 'testnet', c: 'btc', g: 1, t: t.tx.id, r: sha(t.raw),
    a: lane.address!, k: kind, p: sha(body), to: o.to, value: String(o.value), f: String(o.f), q: o.q, x: null, e: NOW + TICKET_TTL_MS, n: randomBytes(8).toString('hex') })
  const rawTxs = { [f.id]: funding.hex, [c.id]: commitTx.hex }
  const mk = (name: string, p: TicketPayload, t: TnTx): Valid => ({ name, ticket: encodeTicket(TICKET_KEY, p), now: NOW, context: { network: 'testnet', raw: { value: t.hex }, prevouts: {}, rawTxs }, payload: p })
  const commit = mk('testnet commit (real txs)', payload('commit', commitTx, { f: commitFee, q: `${f.id}:0`, to: rv.address!, value: revealAmount }), commitTx)
  const reveal = mk('testnet reveal (real txs)', payload('reveal', revealTx, { f: revealAmount - 546n, q: `${c.id}:0`, to: dest, value: 546n }), revealTx)
  return { commit, reveal, funding, commitTx, revealTx, xonly, lane, laneKey }
}

test('local: a ticketed commit then reveal reach the bitcoind after the relay\'s own reads of the inputs; the answer is { txid } only', async () => {
  const s = await start('local')
  try {
    for (const k of ['commit', 'reveal'] as const) {
      const v = validOn('local', k)
      s.world.reads.length = 0
      const r = await sendVector(s, v)
      assert.deepEqual([r.status, r.json], [200, { txid: v.payload.t }], k)
      assert.deepEqual(s.world.reads, v.payload.q.split(','), `${k}: one read per input`)
      const last = s.world.sent.at(-1)!
      assert.equal(last.hex, v.context.raw.value, `${k}: exactly the ticketed bytes`)
      assert.equal(last.headers.authorization, `Basic ${AUTH_B64}`)
      assert.equal(last.url, BTCD)
    }
    assert.equal(sentCount(s), 2)
    // an identical-bytes rebroadcast passes the gate again (§5.6: tickets are reusable for identical bytes until e)
    const again = await sendVector(s, validOn('local', 'commit'))
    assert.equal(again.status, 200); assert.equal(sentCount(s), 3)
    const nochange = V.valid.find((v) => v.name.startsWith('local commit without change'))!
    assert.equal((await sendVector(s, nochange)).status, 200)
  } finally { await s.close() }
})

test('testnet4: the same through Esplora (GET /tx/<txid>/hex reads, verified by the txid; POST /tx with the hex as text); nothing carries the bitcoind credential', async () => {
  const s = await start('testnet')
  try {
    const T = mkTestnet()
    for (const v of [T.commit, T.reveal]) {
      s.world.hexReads.length = 0
      const r = await sendVector(s, v)
      assert.deepEqual([r.status, r.json], [200, { txid: v.payload.t }], v.name)
      assert.deepEqual([...new Set(s.world.hexReads)].sort(), v.payload.q.split(',').map((x) => x.split(':')[0]).sort(), v.name)
      const last = s.world.sent.at(-1)!
      assert.equal(last.hex, v.context.raw.value)
      assert.match(last.url, /\/tx$/); assert.equal(last.headers['content-type'], 'text/plain')
    }
    assert.ok(s.world.calls.every((c) => c.headers.authorization === undefined))
    assert.ok(s.world.calls.filter((c) => /\/tx\//.test(c.url)).every((c) => c.method === 'GET' && c.url.endsWith('/hex')), 'the only per-tx read is the raw hex')
  } finally { await s.close() }
})

test('esploraPrevout (S6b review m-2): the value and script come from the raw tx only when its non-witness double SHA-256 IS the txid', () => {
  const T = mkTestnet()
  const F = T.funding, id = F.tx.id
  const out0 = esploraPrevout(F.hex, id, 0)!, out1 = esploraPrevout(F.hex, id, 1)!
  assert.deepEqual([out0.value, hexOf(out0.script)], [5_000_000n, hexOf(T.lane.script)])
  assert.equal(out1.value, 900_000n)
  assert.equal(esploraPrevout(F.hex, id, 2), null, 'no such output')
  assert.equal(esploraPrevout(F.hex, id, -1), null)
  assert.equal(esploraPrevout(F.hex, id, 1.5), null)
  assert.equal(esploraPrevout(F.hex, 'ab'.repeat(32), 0), null, 'another txid')
  assert.equal(esploraPrevout(F.hex, id.toUpperCase(), 0), null)
  // the witness is not part of the txid: a different witness for the same tx still verifies (it cannot change the outputs) ...
  const stripped = F.tx.toBytes(true, false)                                  // legacy serialization of the same tx
  assert.equal(esploraPrevout(hexOf(stripped), id, 0)!.value, 5_000_000n)
  // ... but every other byte is bound: flip each byte of the non-witness part, one at a time
  const flipped: string[] = []
  for (let i = 0; i < stripped.length; i++) { const b = Uint8Array.from(stripped); b[i] ^= 0x01; flipped.push(hexOf(b)) }
  for (const h of flipped) assert.equal(esploraPrevout(h, id, 0), null)
  // the outputs a lying server would change: the value and the script of the very output the relay reads
  const v = Uint8Array.from(F.raw); const at = hexOf(F.raw).indexOf(hexOf(T.lane.script)) / 2
  v[at - 9] ^= 0x10                                                           // a byte of output 0's 8-byte value
  assert.equal(esploraPrevout(hexOf(v), id, 0), null)
  // malformed: trailing bytes, truncation, bad hex, a wrong witness flag, an empty and an oversized answer
  assert.equal(esploraPrevout(`${F.hex}00`, id, 0), null)
  assert.equal(esploraPrevout(F.hex.slice(0, -2), id, 0), null)
  for (const n of [0, 10, 40, 80]) assert.equal(esploraPrevout(F.hex.slice(0, n), id, 0), null, `${n}`)
  assert.equal(esploraPrevout(`${F.hex.slice(0, 8)}0002${F.hex.slice(12)}`, id, 0), null, 'witness flag 02')
  for (const bad of ['', 'zz', F.hex.toUpperCase(), `${F.hex}\n`, `0x${F.hex}`, F.hex.slice(1)]) assert.equal(esploraPrevout(bad, id, 0), null)
  assert.equal(esploraPrevout('00'.repeat(4_000_001), id, 0), null)
  // a commit (one segwit input) and a reveal (a script-path witness) verify against their own ids
  assert.equal(esploraPrevout(T.commitTx.hex, T.commitTx.tx.id, 0)!.value, 946n)
  assert.equal(esploraPrevout(T.revealTx.hex, T.revealTx.tx.id, 0)!.value, 546n)
  assert.equal(esploraPrevout(T.commitTx.hex, T.revealTx.tx.id, 0), null)
})

test('mainnet (and a mainnet identity): release.mainnet-locked, before any chain read or send', async () => {
  const s = await start('mainnet')
  try {
    const v = validOn('mainnet', 'commit')
    const r = await sendVector(s, v)
    assert.deepEqual([r.status, g(r)], [403, 'release.mainnet-locked'])
    assert.deepEqual([s.world.reads, sentCount(s)], [[], 0])
    // PF-S M-1 (pre-flip review): a mainnet BTC send is NOT a job send — the relay's lock refuses it with the ALL-scope lock
    // (MAINNET_SEND_ENABLED), so lifting MAINNET_JOB_SENDS_ENABLED (the R78 flip) never opens it (send-lock-flip.test.ts pins
    // the lock itself on a flipped copy)
    const why = (r.json as { error: { message: string } }).error.message
    assert.match(why, /MAINNET_SEND_ENABLED\)/)
    assert.doesNotMatch(why, /job sends|MAINNET_JOB_SENDS_ENABLED/)
    for (const x of V.valid.filter((y) => y.payload.w !== 'mainnet')) assert.equal(g(await sendVector(s, x)), 'relay.ticket-network', x.name)
  } finally { await s.close() }
})

test('unticketed and badly ticketed sends are refused, whatever the bytes; the format negatives keep relay.send-ticket', async () => {
  const s = await start('local')
  try {
    const v = validOn('local', 'commit')
    assert.equal(g(await sendVector(s, v, { ticket: null })), 'relay.send-ticket')
    assert.equal(g(await sendVector(s, v, { ticket: '' })), 'relay.send-ticket')
    assert.equal(g(await sendVector(s, v, { ticket: v.ticket.slice(0, -3) })), 'relay.send-ticket')
    assert.equal(g(await sendVector(s, v, { ticket: `${v.ticket}x` })), 'relay.send-ticket')
    for (const n of V.negatives) assert.equal(g(await sendVector(s, n as Vector)), 'relay.send-ticket', n.name)
    const expired = await sendVector(s, v)
    assert.equal(expired.status, 200)
    s.clock.t = v.now + 200_000
    const late = await rq(s, '/relay/btc/send', { body: { hex: v.context.raw.value }, headers: { [TICKET_HEADER]: v.ticket } })
    assert.equal(g(late), 'relay.ticket-expired')
    assert.equal(sentCount(s), 1, 'only the genuine send was forwarded')
  } finally { await s.close() }
})

test('other bytes under a ticket, and a body that is not exactly { hex: lowercase hex }, are refused', async () => {
  const s = await start('local')
  try {
    const v = validOn('local', 'commit'), r = validOn('local', 'reveal')
    assert.equal(g(await sendVector(s, v, { hex: r.context.raw.value })), 'relay.ticket-raw')
    assert.equal(g(await sendVector(s, v, { hex: `${v.context.raw.value}00` })), 'relay.ticket-raw')
    assert.equal(g(await sendVector(s, v, { hex: v.context.raw.value.toUpperCase() })), 'relay.ticket-raw')
    assert.equal(g(await sendVector(s, v, { hex: `0x${v.context.raw.value}` })), 'relay.ticket-raw')
    assert.equal(g(await sendVector(s, v, { hex: '' })), 'relay.ticket-raw')
    for (const body of [{}, { hex: v.context.raw.value, extra: 1 }, { raw: v.context.raw.value }, [v.context.raw.value], v.context.raw.value, null, { hex: 5 }, { hex: [v.context.raw.value] }, '{"hex"']) {
      assert.equal(g(await sendVector(s, v, { body })), 'relay.ticket-raw', JSON.stringify(body)?.slice(0, 40))
    }
    // a duplicate key cannot smuggle other bytes: the relay parses the body once, JSON.parse keeps the last
    const dup = `{"hex":"${r.context.raw.value}","hex":"${v.context.raw.value}"}`
    s.world.prevouts = v.context.prevouts; s.world.txid = v.payload.t; s.clock.t = v.now
    const d = await rq(s, '/relay/btc/send', { body: dup, headers: { [TICKET_HEADER]: v.ticket } })
    assert.equal(d.status, 200); assert.equal(s.world.sent.at(-1)!.hex, v.context.raw.value)
    // content type, method, body cap
    const ct = await rq(s, '/relay/btc/send', { body: { hex: v.context.raw.value }, contentType: 'text/plain', headers: { [TICKET_HEADER]: v.ticket } })
    assert.equal(ct.status, 403)
    const get = await rq(s, '/relay/btc/send', { method: 'GET' })
    assert.deepEqual([get.status, g(get)], [403, 'relay.method'])
    const put = await rq(s, '/relay/btc/send', { method: 'PUT', body: { hex: '00' } })
    assert.deepEqual([put.status, g(put)], [403, 'relay.method'])
    const big = await rq(s, '/relay/btc/send', { body: JSON.stringify({ hex: '0'.repeat(300 * 1024) }), headers: { [TICKET_HEADER]: v.ticket } })
    assert.equal(big.status, 413)
    assert.equal(sentCount(s), 1, 'only the duplicate-key send (the genuine bytes) was forwarded')
  } finally { await s.close() }
})

test('every decode vector (one defect each) is refused over HTTP with its guard; nothing is forwarded', async () => {
  const s = await start('local')
  try {
    assert.ok(V.decode.length >= 40)
    const seen = new Set<string>()
    for (const d of V.decode) {
      const r = await sendVector(s, d)
      assert.equal(r.status, 403, d.name)
      assert.equal(g(r), d.guard, d.name)
      seen.add(g(r)!)
    }
    assert.deepEqual([...seen].sort(), ['relay.btc-prevout', 'relay.decode-mismatch'])
    assert.equal(sentCount(s), 0)
  } finally { await s.close() }
})

test('the chain read fails closed: nothing found, a 5xx, a timeout, a non-JSON answer, a wrong shape or the credential echoed → relay.btc-prevout', async () => {
  const s = await start('local')
  try {
    const v = validOn('local', 'commit')
    const cases: Array<[string, (op: string) => UpRes | undefined]> = [
      ['spent or unknown', () => json(200, { result: null, error: null, id: 9 })],
      ['http 500', () => text(500, '{"result":null,"error":{"code":-1}}')],
      ['not json', () => text(200, '<html>')],
      ['no value', () => json(200, { result: { scriptPubKey: { hex: '00' } }, error: null })],
      ['value as a string', () => json(200, { result: { value: '0.001', scriptPubKey: { hex: '00' } }, error: null })],
      ['negative value', () => json(200, { result: { value: -1, scriptPubKey: { hex: '00' } }, error: null })],
      ['script not hex', () => json(200, { result: { value: 0.001, scriptPubKey: { hex: 'zz' } }, error: null })],
      ['odd hex', () => json(200, { result: { value: 0.001, scriptPubKey: { hex: '001' } }, error: null })],
      ['the credential echoed', () => json(200, { result: { value: 0.001, scriptPubKey: { hex: '00' }, leak: AUTH_LINE }, error: null })],
    ]
    for (const [name, f] of cases) {
      s.world.onRead = f
      assert.equal(g(await sendVector(s, v)), 'relay.btc-prevout', name)
    }
    s.world.onRead = () => { throw new Error('socket hang up') }
    assert.equal(g(await sendVector(s, v)), 'relay.btc-prevout', 'transport error')
    s.world.onRead = undefined
    assert.equal(sentCount(s), 0)
    assert.equal((await sendVector(s, v)).status, 200)
  } finally { await s.close() }
  // Esplora (S6b review m-2): not found, JSON instead of the hex, another tx, a lying value or script, trailing or missing bytes
  const t = await start('testnet')
  try {
    const T = mkTestnet()
    const v = T.reveal                                                        // its input is the commit's output 0
    const good = T.commitTx.hex
    const lie = (patch: (b: Uint8Array) => void): string => { const b = Uint8Array.from(T.commitTx.raw); patch(b); return hexOf(b) }
    const valueAt = hexOf(T.commitTx.raw).indexOf('b203') / 2                  // output 0's value (946 = 0x03b2, little endian) in the commit
    assert.ok(valueAt > 0)
    for (const [name, f] of [['404', () => text(404, 'Transaction not found')], ['a JSON tx object', () => json(200, { txid: T.commitTx.tx.id, vout: [{ value: 946, scriptpubkey: '00' }] })],
      ['another tx', () => text(200, T.funding.hex)], ['the right tx with the output value raised', () => text(200, lie((b) => { b[valueAt] = 0xff }))],
      ['trailing byte', () => text(200, `${good}00`)], ['truncated', () => text(200, good.slice(0, -2))], ['empty', () => text(200, '')],
      ['HTTP 500', () => text(500, good)]] as const) {
      t.world.onRead = f
      assert.equal(g(await sendVector(t, v)), 'relay.btc-prevout', name)
    }
    t.world.onRead = () => { throw new Error('socket hang up') }
    assert.equal(g(await sendVector(t, v)), 'relay.btc-prevout', 'transport error')
    t.world.onRead = undefined
    assert.equal(sentCount(t), 0, 'nothing was sent after a failed or lying read')
    t.world.onRead = () => text(200, `${good}\n`)                             // Esplora may end its text with one newline
    assert.equal((await sendVector(t, v)).status, 200)
  } finally { await t.close() }
})

test('answers: only { txid }, only the txid the relay computed; another id, an error, the credential or a rejection is withheld; an ambiguous outcome is not retried', async () => {
  const s = await start('local')
  try {
    const v = validOn('local', 'commit')
    const other = 'ee'.repeat(32)
    // another txid
    assert.deepEqual([(await sendVector(s, v, { txid: other })).status, g(await sendVector(s, v, { txid: other }))], [502, 'relay.upstream-shape'])
    // an error answer with HTTP 200, a result with an error, a non-string result
    for (const body of [{ result: null, error: { code: -26, message: CANARY }, id: 9 }, { result: v.payload.t, error: { code: 1 }, id: 9 }, { result: 5, error: null }, { error: null }]) {
      s.world.onSend = () => json(200, body)
      const r = await sendVector(s, v)
      assert.deepEqual([r.status, g(r)], [502, 'relay.upstream-shape'], JSON.stringify(body))
      assert.ok(!r.text.includes(CANARY) && !r.text.includes(other))
    }
    // the credential in the answer
    // a JSON-RPC 2.0 success has no `error` member (Bitcoin Core 28+), a 1.0 success has error: null: both are accepted
    s.world.onSend = () => json(200, { jsonrpc: '2.0', result: v.payload.t, id: 9 })
    assert.deepEqual((await sendVector(s, v)).json, { txid: v.payload.t })
    s.world.onSend = () => json(200, { result: v.payload.t, error: null, leak: AUTH_B64 })
    const leak = await sendVector(s, v)
    assert.deepEqual([leak.status, g(leak)], [502, 'relay.upstream-secret'])
    assert.ok(!leak.text.includes(AUTH_B64))
    // bitcoind rejects with HTTP 500 and a message: ambiguous, not retried, the message not passed on
    const before = sentCount(s)
    s.world.onSend = () => text(500, JSON.stringify({ result: null, error: { code: -26, message: `${CANARY} bad-txns` }, id: 9 }))
    const rej = await sendVector(s, v)
    assert.equal(rej.status, 502); assert.match(rej.json.error.message, /send outcome unknown/)
    assert.ok(!rej.text.includes(CANARY))
    assert.equal(sentCount(s), before + 1, 'exactly one attempt')
    // a transport failure after the request was written: ambiguous too; a refusal before processing (HTTP 403): not accepted
    s.world.onSend = () => Object.assign(new Error('reset'), { code: 'ECONNRESET' })
    const reset = await sendVector(s, v)
    assert.equal(reset.status, 502); assert.match(reset.json.error.message, /send outcome unknown/)
    s.world.onSend = () => text(403, 'nope')
    const refused = await sendVector(s, v)
    assert.equal(refused.status, 503); assert.match(refused.json.error.message, /not accepted/)
    s.world.onSend = () => text(404, CANARY)
    const nf = await sendVector(s, v)
    assert.ok(nf.status === 502 && !nf.text.includes(CANARY))
  } finally { await s.close() }
  const t = await start('testnet')
  try {
    const v = mkTestnet().commit
    for (const [name, f] of [['another txid', () => text(200, 'ee'.repeat(32))], ['an error text', () => text(200, `error: ${CANARY}`)], ['empty', () => text(200, '')], ['two lines', () => text(200, `${v.payload.t}\n${v.payload.t}`)]] as const) {
      t.world.onSend = f
      const r = await sendVector(t, v)
      assert.deepEqual([r.status, g(r)], [502, 'relay.upstream-shape'], name)
      assert.ok(!r.text.includes(CANARY))
    }
    // Esplora answering 500: ambiguous, never retried (not even over Tor's auto-rotate) or failed over
    const n0 = sentCount(t)
    t.world.onSend = () => text(500, 'boom')
    const amb = await sendVector(t, v)
    assert.equal(amb.status, 502); assert.match(amb.json.error.message, /send outcome unknown/)
    assert.equal(sentCount(t), n0 + 1, 'exactly one attempt')
    t.world.onSend = () => text(200, `${v.payload.t}\n`)            // Esplora may end its text answer with one newline
    assert.deepEqual((await sendVector(t, v)).json, { txid: v.payload.t })
    t.world.onSend = () => text(400, `sendrawtransaction RPC error: {"code":-26,"message":"${CANARY}"}`)
    const rej = await sendVector(t, v)
    assert.equal(rej.status, 502); assert.match(rej.json.error.message, /HTTP 400/)
    assert.ok(!rej.text.includes(CANARY))
  } finally { await t.close() }
})

test('the JSON-RPC route /relay/btc stays read-only: btc_send, sendrawtransaction and every send are refused, even with a valid ticket', async () => {
  const s = await start('local')
  try {
    const v = validOn('local', 'commit')
    s.world.prevouts = v.context.prevouts; s.clock.t = v.now
    for (const [method, params] of [['btc_send', [v.context.raw.value]], ['sendrawtransaction', [v.context.raw.value]], ['submitpackage', [[v.context.raw.value]]]] as const) {
      const r = await rq(s, '/relay/btc', { body: { jsonrpc: '2.0', id: 1, method, params }, headers: { [TICKET_HEADER]: v.ticket } })
      assert.deepEqual([r.status, r.json?.error?.data?.guard], [403, 'relay.method'], method)
    }
    assert.deepEqual([sentCount(s), s.world.reads], [0, []])
  } finally { await s.close() }
})

test('btc disabled (no bitcoind credential on local): the send answers 503 and nothing is forwarded; no btc route exists for eth/sol paths', async () => {
  const s = await start('local', { auth: null })
  try {
    const v = validOn('local', 'commit')
    const r = await sendVector(s, v)
    assert.equal(r.status, 503)
    assert.deepEqual([sentCount(s), s.world.reads], [0, []])
    assert.ok(s.world.calls.every((c) => !c.url.startsWith(BTCD)), 'not one request reached the bitcoind')
  } finally { await s.close() }
})

test('logs: one line per send with the route and status; never the raw tx, the ticket, the txid or the credential', async () => {
  const s = await start('local')
  try {
    const v = validOn('local', 'commit')
    await sendVector(s, v)
    await sendVector(s, v, { hex: `${v.context.raw.value}00` })
    const log = s.logs.join('\n')
    assert.match(log, /^btc btc_send 200 \d+ms$/m)
    assert.match(log, /^btc btc_send 403 \d+ms relay\.ticket-raw$/m)
    for (const needle of [v.context.raw.value.slice(10, 60), v.ticket, v.ticket.split('.')[1], v.payload.t, v.payload.q.split(':')[0], 'Synthetic-Pass', AUTH_B64, v.payload.a, v.payload.to!]) assert.ok(!log.includes(needle), needle.slice(0, 20))
  } finally { await s.close() }
})

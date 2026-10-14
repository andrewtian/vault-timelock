// test/integration/harness/chains.ts — the E4 harness's OWN local chains, the ported fee-pressure harnesses, and the
// INDEPENDENT on-chain checks every scenario ends with (not a test file). ALL DATA IS SYNTHETIC.
//
//   · anvil (chain id 31337) and solana-test-validator (--limit-ledger-size 50000000, a temp ledger) on free loopback
//     ports of this file's own region (never the shared :8545 / :8899 / :8999, never the stack ports 5180–5202), each
//     under a loopback-only sandbox, stopped by its recorded pid. A start that loses a port race is retried (infra only).
//   · startEthPressure / startSolPressure: the prototype's R64 harnesses (eth-pressure-miner.mjs, sol-pressure-filter.mjs,
//     ported), as their own sandboxed processes, with their loopback control ports.
//   · checkPublished: reads the chain DIRECTLY (never through vt's relay) and proves, for one job chain, that every
//     landed (copy, part) is on chain exactly once with the planned bytes from the job's key — and that the key published
//     nothing else: the multiset of payloads the key put on chain equals the multiset of planned payloads of the landed
//     parts, and each payload's own vt-parts/1 header (copy marker, k/N) is unique.
// No IP other than 127.0.0.1 is used or printed.
import { spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createSocket } from 'node:dgram'
import { request } from 'node:http'
import { createServer as createTcpServer } from 'node:net'
import { basename, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parsePart } from '../../../packages/core/src/contracts/index.ts'
import type { Chain, ChainState, JobDef } from '../../../packages/core/src/contracts/index.ts'
import { laneConfigOf } from '../../../packages/core/src/executor/executor.ts'
import { planLaneCopy } from '../../../packages/core/src/engine/lane.js'

export const REPO = fileURLToPath(new URL('../../../', import.meta.url))
export const HARNESS = fileURLToPath(new URL('./', import.meta.url))
export const LOOPBACK_ONLY = '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))'
export const NULL_ADDRESS = '0x0000000000000000000000000000000000000000'
export const MEMO_PROGRAM = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'
export const SYSTEM_PROGRAM = '11111111111111111111111111111111'
export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))
export const sha256 = (b: Uint8Array | string): string => createHash('sha256').update(b).digest('hex')
export type T = { after(fn: () => unknown): void }
export const baseEnv = (home: string): Record<string, string> => ({ PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home, LANG: 'en_US.UTF-8' })

// ---- polling

export async function waitFor<V>(fn: () => Promise<V | null> | V | null, ms: number, what: string, every = 250): Promise<V> {
  const t0 = Date.now()
  let last: unknown = null
  for (;;) {
    try { const v = await fn(); if (v !== null) return v } catch (e) { last = e; if ((e as { fatal?: boolean })?.fatal === true) throw e }
    if (Date.now() - t0 > ms) throw new Error(`timeout after ${ms} ms: ${what}${last !== null ? ` (last error: ${String((last as Error)?.message ?? last).slice(0, 200)})` : ''}`)
    await sleep(every)
  }
}

// ---- children, stopped by their recorded pid (never by pattern)

export interface Child { proc: ChildProcess; lines: string[]; exited: Promise<number | null>; stop(signal?: NodeJS.Signals): Promise<void>; tail(n?: number): string }
export function child(cmd: string, args: string[], env: Record<string, string>, o: { stdin?: string; cwd?: string } = {}): Child {
  const proc = spawn(cmd, args, { env, cwd: o.cwd ?? REPO, stdio: [o.stdin === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'] })
  if (o.stdin !== undefined) { proc.stdin!.on('error', () => {}); proc.stdin!.end(o.stdin) }   // a secret travels through the pipe only (in memory)
  const lines: string[] = []
  let buf = ''
  const onData = (d: Buffer): void => {
    buf += d.toString('utf8')
    let i
    while ((i = buf.indexOf('\n')) >= 0) { lines.push(buf.slice(0, i)); buf = buf.slice(i + 1); if (lines.length > 20_000) lines.splice(0, 5_000) }
  }
  proc.stdout?.on('data', onData)
  proc.stderr?.on('data', onData)
  const exited = new Promise<number | null>((r) => proc.once('exit', (code) => r(code)))
  const stop = (signal: NodeJS.Signals = 'SIGTERM'): Promise<void> => new Promise((r) => {
    if (proc.exitCode !== null || proc.signalCode !== null) return r()
    const k = setTimeout(() => { try { proc.kill('SIGKILL') } catch { /* gone */ } r() }, 8_000)
    proc.once('exit', () => { clearTimeout(k); r() })
    try { proc.kill(signal) } catch { clearTimeout(k); r() }
  })
  return { proc, lines, exited, stop, tail: (n = 12) => lines.slice(-n).join(' | ') }
}
export async function readyLine(c: Child, re: RegExp, what: string, ms = 180_000): Promise<RegExpExecArray> {
  return waitFor(() => {
    for (const l of c.lines) { const m = re.exec(l); if (m) return m }
    if (c.proc.exitCode !== null || c.proc.signalCode !== null) throw Object.assign(new Error(`${what} exited (${c.proc.exitCode ?? c.proc.signalCode}): ${c.tail(6)}`), { fatal: true })
    return null
  }, ms, `${what} ready`, 200)
}

// ---- free ports: each scenario file draws from its own region (so parallel files never race for one), checked free

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
const REGION = (() => { const h = createHash('sha256').update(basename(process.argv[1] ?? 'x')).digest(); return h.readUInt16BE(0) % 24 })()
export async function freeRun(n: number): Promise<number> {
  for (let tries = 0; tries < 80; tries++) {
    // 21000–44999 (below the OS's ephemeral range, far from every fixed port of the project and the shared chains)
    const base = 21_000 + REGION * 1_000 + 10 * Math.floor(Math.random() * Math.max(1, Math.floor((1_000 - n) / 10)))
    let ok = true
    for (let p = base; ok && p < base + n; p++) ok = await portFree(p)
    if (ok) return base
  }
  throw new Error('no run of free ports')
}

// ---- direct JSON-RPC to the harness's own chains (never through the relay; loopback only)

export function rpc(port: number, method: string, params: unknown[] = [], timeoutMs = 30_000): Promise<any> {
  return new Promise((resolve, reject) => {
    const b = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }))
    const r = request({ host: '127.0.0.1', port, method: 'POST', path: '/', timeout: timeoutMs, headers: { 'content-type': 'application/json', 'content-length': String(b.length) } }, (res) => {
      const c: Buffer[] = []
      res.on('data', (d: Buffer) => c.push(d))
      res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(c).toString('utf8'))) } catch (e) { reject(e) } })
    })
    r.on('timeout', () => r.destroy(new Error(`${method}: timeout`)))
    r.on('error', reject)
    r.end(b)
  })
}
export async function rpcResult(port: number, method: string, params: unknown[] = []): Promise<any> {
  const j = await rpc(port, method, params)
  if (j.error !== undefined) throw new Error(`${method}: ${JSON.stringify(j.error).slice(0, 200)}`)
  return j.result
}

// ---- the chains

export interface Anvil { port: number; url: string; child: Child }
// blockTime null: --no-mining (the ETH pressure miner mines). baseFee: the starting base fee (7 wei stays 7: the
// EIP-1559 floor, so every cost in a run is deterministic).
export async function startAnvil(t: T, o: { home: string; blockTime?: number | null; baseFee?: bigint; gasLimit?: bigint }): Promise<Anvil> {
  for (let attempt = 1; ; attempt++) {
    const port = await freeRun(1)
    const mining = o.blockTime === null ? ['--no-mining'] : ['--block-time', String(o.blockTime ?? 1)]
    const c = child('/usr/bin/sandbox-exec', ['-p', LOOPBACK_ONLY, 'anvil', '--host', '127.0.0.1', '--port', String(port), '--chain-id', '31337', ...mining,
      ...(o.baseFee !== undefined ? ['--base-fee', String(o.baseFee)] : []), ...(o.gasLimit !== undefined ? ['--gas-limit', String(o.gasLimit)] : []), '--silent'], baseEnv(o.home))
    t.after(() => c.stop())
    try {
      await waitFor(async () => {
        if (c.proc.exitCode !== null) throw Object.assign(new Error(`anvil exited ${c.proc.exitCode}: ${c.tail(3)}`), { fatal: true })
        try { return (await rpc(port, 'eth_chainId')).result === '0x7a69' ? true : null } catch { return null }
      }, 60_000, 'anvil')
      return { port, url: `http://127.0.0.1:${port}`, child: c }
    } catch (e) { await c.stop('SIGKILL'); if (attempt >= 4) throw e }   // a port race lost: another run (infra retry)
  }
}

export interface Validator { port: number; url: string; child: Child }
export async function startValidator(t: T, o: { home: string; dir: string }): Promise<Validator> {
  for (let attempt = 1; ; attempt++) {
    const base = await freeRun(64) // rpc, rpc websocket, faucet, gossip, then the dynamic range
    const c = child('/usr/bin/sandbox-exec', ['-p', LOOPBACK_ONLY, 'solana-test-validator', '--ledger', join(o.dir, `ledger-${attempt}`), '--reset', '--quiet',
      '--bind-address', '127.0.0.1', '--rpc-port', String(base), '--faucet-port', String(base + 2), '--gossip-port', String(base + 3),
      '--dynamic-port-range', `${base + 4}-${base + 64}`, '--limit-ledger-size', '50000000'], baseEnv(o.home))
    t.after(() => c.stop())
    try {
      await waitFor(async () => {
        if (c.proc.exitCode !== null) throw Object.assign(new Error(`solana-test-validator exited ${c.proc.exitCode}: ${c.tail(3)}`), { fatal: true })
        try { return (await rpc(base, 'getHealth')).result === 'ok' ? true : null } catch { return null }
      }, 240_000, 'solana-test-validator', 500)
      return { port: base, url: `http://127.0.0.1:${base}`, child: c }
    } catch (e) { await c.stop('SIGKILL'); if (attempt >= 3) throw e }
  }
}

// ---- funding and reading (direct, loopback)

export async function fundEth(anvil: number, address: string, wei: bigint): Promise<void> {
  await rpcResult(anvil, 'anvil_setBalance', [address, `0x${wei.toString(16)}`])
}
export const ethBalance = async (anvil: number, address: string): Promise<bigint> => BigInt(await rpcResult(anvil, 'eth_getBalance', [address, 'latest']))
export const ethNonce = async (anvil: number, address: string): Promise<number> => Number(BigInt(await rpcResult(anvil, 'eth_getTransactionCount', [address, 'latest'])))
export const solBalance = async (sol: number, address: string): Promise<bigint> => BigInt((await rpcResult(sol, 'getBalance', [address, { commitment: 'confirmed' }])).value)
export async function fundSol(sol: number, address: string, lamports: bigint | number): Promise<void> {
  const want = BigInt(lamports), before = await solBalance(sol, address)
  // the faucet may refuse right after start-up: retried (infra only); the balance is what counts
  await waitFor(async () => { await rpcResult(sol, 'requestAirdrop', [address, Number(want)]); return true }, 60_000, 'airdrop accepted', 1_000)
  await waitFor(async () => ((await solBalance(sol, address)) >= before + want ? true : null), 90_000, 'airdrop landed', 500)
}
export const solRent = async (sol: number): Promise<bigint> => BigInt(await rpcResult(sol, 'getMinimumBalanceForRentExemption', [0]))

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
export function bs58decode(s: string): Uint8Array {
  let n = 0n
  for (const ch of s) { const i = B58.indexOf(ch); if (i < 0) throw new Error('not base58'); n = n * 58n + BigInt(i) }
  const out: number[] = []
  while (n > 0n) { out.unshift(Number(n % 256n)); n /= 256n }
  for (const ch of s) { if (ch !== '1') break; out.unshift(0) }
  return Uint8Array.from(out)
}

export function bs58encode(b: Uint8Array): string {
  let n = 0n
  for (const x of b) n = n * 256n + BigInt(x)
  let s = ''
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n }
  for (const x of b) { if (x !== 0) break; s = '1' + s }
  return s
}
// The signature (= tx id) of a serialized SOL tx (base64): the first of its shortvec-counted 64-byte signatures.
export function solTxIdOf(b64: string): string {
  const b = Buffer.from(b64, 'base64')
  return bs58encode(b.subarray(1, 65))
}

// Every tx the address sent, read from the blocks themselves (eth_getBlockByNumber with full txs), in nonce order.
export interface EthOnChain { hash: string; nonce: number; from: string; to: string | null; value: bigint; input: Buffer; block: number; status: string; fee: bigint; gasUsed: bigint; effectiveGasPrice: bigint }
export async function ethTxsFrom(anvil: number, address: string): Promise<EthOnChain[]> {
  const latest = Number(BigInt(await rpcResult(anvil, 'eth_blockNumber')))
  const want = address.toLowerCase(), found: EthOnChain[] = []
  for (let b = 0; b <= latest; b += 16) {
    const blocks = await Promise.all(Array.from({ length: Math.min(16, latest - b + 1) }, (_x, i) => rpcResult(anvil, 'eth_getBlockByNumber', [`0x${(b + i).toString(16)}`, true])))
    for (const blk of blocks) for (const tx of blk?.transactions ?? []) {
      if (String(tx.from).toLowerCase() !== want) continue
      const rc = await rpcResult(anvil, 'eth_getTransactionReceipt', [tx.hash])
      found.push({ hash: String(tx.hash).toLowerCase(), nonce: Number(BigInt(tx.nonce)), from: want, to: tx.to === null ? null : String(tx.to).toLowerCase(), value: BigInt(tx.value), input: Buffer.from(String(tx.input).slice(2), 'hex'),
        block: Number(BigInt(blk.number)), status: rc.status, gasUsed: BigInt(rc.gasUsed), effectiveGasPrice: BigInt(rc.effectiveGasPrice), fee: BigInt(rc.gasUsed) * BigInt(rc.effectiveGasPrice) })
    }
  }
  return found.sort((x, y) => x.nonce - y.nonce)
}

// Every confirmed tx the address signed as fee payer, read from the validator (getSignaturesForAddress + getTransaction).
export interface SolOnChain { sig: string; slot: number; err: unknown; fee: bigint; feePayer: string; memo: Buffer | null; transfer: { to: string; lamports: bigint } | null }
export async function solTxsOf(sol: number, address: string): Promise<SolOnChain[]> {
  const sigs: Array<{ signature: string }> = []
  let before: string | undefined
  for (;;) {
    const page = await rpcResult(sol, 'getSignaturesForAddress', [address, { limit: 1000, commitment: 'confirmed', ...(before ? { before } : {}) }]) as Array<{ signature: string }>
    sigs.push(...page)
    if (page.length < 1000) break
    before = page.at(-1)!.signature
  }
  const out: SolOnChain[] = []
  for (let i = 0; i < sigs.length; i += 16) {
    const txs = await Promise.all(sigs.slice(i, i + 16).map((s) => solTxOnChain(sol, s.signature)))
    for (const t of txs) if (t !== null && t.feePayer === address) out.push(t)
  }
  return out.sort((x, y) => x.slot - y.slot)
}
export async function solTxOnChain(sol: number, sig: string): Promise<SolOnChain | null> {
  const tx = await rpcResult(sol, 'getTransaction', [sig, { encoding: 'json', commitment: 'confirmed', maxSupportedTransactionVersion: 0 }])
  if (tx === null) return null
  const keys: string[] = tx.transaction.message.accountKeys
  let memo: Buffer | null = null, transfer: SolOnChain['transfer'] = null
  for (const ix of tx.transaction.message.instructions as Array<{ programIdIndex: number; accounts: number[]; data: string }>) {
    const prog = keys[ix.programIdIndex]
    const data = Buffer.from(bs58decode(ix.data))
    if (prog === MEMO_PROGRAM) memo = data
    if (prog === SYSTEM_PROGRAM && data.length === 12 && data.readUInt32LE(0) === 2) transfer = { to: keys[ix.accounts[1]], lamports: data.readBigUInt64LE(4) }
  }
  return { sig, slot: tx.slot, err: tx.meta.err, fee: BigInt(tx.meta.fee), feePayer: keys[0], memo, transfer }
}

// ---- the independent publication check

export interface PublishedPart { chain: Chain; copy: number; part: number; parts: number; txId: string; at: number; bytes: number; fee: string; payload: Buffer }
export interface Published { parts: PublishedPart[]; onChainJobTxs: number; others: Array<EthOnChain | SolOnChain> }
const hexOf = (b: Uint8Array): string => Buffer.from(b).toString('hex')
const ETH_LEAD = Buffer.from('data:,')

// For one job chain: every landed (copy, part) of the reduced state is on chain once, from the job's key, with exactly
// the planned bytes and its readback ✓; the key's on-chain payloads are exactly those (no duplicate, nothing extra);
// every on-chain payload's own header names a distinct (copy, part). `others`: the key's txs that carry no job payload
// (claw-backs), for the caller to check.
// scope 'job' (several jobs on one key, scenario C): only the key's payloads that are this job's planned payloads count;
// the caller checks the key's total separately.
export async function checkPublished(ports: { anvil?: number; sol?: number }, def: JobDef, text: string, cs: ChainState, chain: Chain, o: { scope?: 'key' | 'job' } = {}): Promise<Published> {
  const ch = def.chains[chain]
  if (ch === undefined) throw new Error(`the job has no ${chain} chain`)
  const cfg = laneConfigOf(chain, ch, text)
  const planned = new Map<string, Uint8Array>()
  const plannedOf = (copy: number, part: number): Uint8Array => {
    const k = `${copy}:${part}`
    if (!planned.has(k)) planned.set(k, planLaneCopy(cfg, copy)[part - 1]!.payload as Uint8Array)
    return planned.get(k)!
  }
  const landed = cs.txs.filter((t) => t.state === 'included')
  const fail = (m: string): never => { throw new Error(`${chain} on-chain check: ${m}`) }
  // what the chain itself says the key published
  const jobTxs: Array<{ id: string; payload: Buffer; at: number; fee: bigint; ok: boolean }> = []
  const others: Array<EthOnChain | SolOnChain> = []
  if (chain === 'eth') {
    const all = await ethTxsFrom(ports.anvil!, ch.keyAddress)
    const nonce = await ethNonce(ports.anvil!, ch.keyAddress)
    if (nonce !== all.length) fail(`the key's nonce ${nonce} ≠ ${all.length} txs found in the blocks`)
    const jobTo = ch.publishMode === 'eth.calldata.self' ? ch.keyAddress.toLowerCase() : NULL_ADDRESS
    for (const x of all) {
      if (x.input.length > 0 && x.to === jobTo && x.value === 0n) jobTxs.push({ id: x.hash, payload: x.input, at: x.block, fee: x.fee, ok: x.status === '0x1' })
      else others.push(x)
    }
  } else {
    for (const x of await solTxsOf(ports.sol!, ch.keyAddress)) {
      if (x.memo !== null) jobTxs.push({ id: x.sig, payload: x.memo, at: x.slot, fee: x.fee, ok: x.err === null })
      else others.push(x)
    }
  }
  if (o.scope === 'job') {
    const maxCopy = typeof ch.mode === 'object' && ch.mode !== null ? ch.mode.copies : landed.reduce((m, t) => Math.max(m, t.copy), 0) + 1
    const mine = new Set<string>()
    for (let c = 1; c <= maxCopy; c++) for (const p of planLaneCopy(cfg, c)) mine.add(hexOf(p.payload as Uint8Array))
    const keep = jobTxs.filter((x) => mine.has(hexOf(x.payload)))
    jobTxs.length = 0
    jobTxs.push(...keep)
  }
  // 1. every landed part: its tx, from the key, status ok, the planned bytes, readback ✓
  const parts: PublishedPart[] = []
  for (const t of landed) {
    const want = Buffer.from(plannedOf(t.copy, t.part))
    const tx = jobTxs.find((x) => x.id === String(t.landedId).toLowerCase() || x.id === t.landedId)
    if (tx === undefined) fail(`copy ${t.copy} part ${t.part}: its landed tx ${t.landedId} is not a payload tx of the key on chain`)
    if (!tx!.ok) fail(`copy ${t.copy} part ${t.part}: landed with an error`)
    if (!tx!.payload.equals(want)) fail(`copy ${t.copy} part ${t.part}: the chain's bytes are not the planned bytes`)
    if (t.readback !== true) fail(`copy ${t.copy} part ${t.part}: no readback ✓ in the journal`)
    parts.push({ chain, copy: t.copy, part: t.part, parts: t.parts, txId: tx!.id, at: tx!.at, bytes: want.length, fee: String(tx!.fee), payload: tx!.payload })
  }
  // 2. the key published exactly the planned payloads of the landed parts: nothing twice, nothing else
  const count = (xs: Uint8Array[]): Map<string, number> => { const m = new Map<string, number>(); for (const x of xs) m.set(hexOf(x), (m.get(hexOf(x)) ?? 0) + 1); return m }
  const onChain = count(jobTxs.map((x) => x.payload)), wanted = count(landed.map((t) => plannedOf(t.copy, t.part)))
  if (jobTxs.length !== landed.length) fail(`${jobTxs.length} payload txs from the key on chain, ${landed.length} landed parts in the journal`)
  for (const [k, n] of wanted) if (onChain.get(k) !== n) fail(`a planned payload is on chain ${onChain.get(k) ?? 0} times, expected ${n}`)
  // 3. each on-chain payload's own header: a distinct (copy, part) per tx (only meaningful when copies are distinct)
  if (ch.distinctCopies) {
    const seen = new Set<string>()
    for (const x of jobTxs) {
      const body = chain === 'eth' ? (x.payload.subarray(0, ETH_LEAD.length).equals(ETH_LEAD) ? x.payload.subarray(ETH_LEAD.length) : fail('an ETH payload without the data:, lead')) : x.payload
      const p = parsePart(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(body as Uint8Array))
      const k = `${p.copy}:${p.part}/${p.parts}`
      if (seen.has(k)) fail(`(copy ${p.copy}, part ${p.part}/${p.parts}) is on chain twice`)
      seen.add(k)
    }
  }
  return { parts: parts.sort((a, b) => a.copy - b.copy || a.part - b.part), onChainJobTxs: jobTxs.length, others }
}

// ---- the ported fee-pressure harnesses, as their own sandboxed processes

export interface EthPressure { control: number; child: Child; set(o: { T?: bigint | null; base?: bigint | null }): Promise<{ T: string; base: string | null }> }
// The miner mines one block every `every` ms on a --no-mining anvil and first drops every pending tx whose tip < T.
export async function startEthPressure(t: T, o: { home: string; anvil: number; every?: number; baseFee?: bigint; schedule?: string }): Promise<EthPressure> {
  const control = await freeRun(1)
  const c = child('/usr/bin/sandbox-exec', ['-p', LOOPBACK_ONLY, process.execPath, join(HARNESS, 'eth-pressure-miner.mjs'), '--rpc', `http://127.0.0.1:${o.anvil}`,
    '--every', String(o.every ?? 1500), '--schedule', o.schedule ?? '0:0', '--control', String(control), ...(o.baseFee !== undefined ? ['--base-fee', String(o.baseFee)] : [])], baseEnv(o.home))
  t.after(() => c.stop())
  await readyLine(c, /^eth pressure miner on /, 'eth pressure miner', 30_000)
  const set = async (b: { T?: bigint | null; base?: bigint | null }): Promise<{ T: string; base: string | null }> => {
    const body = JSON.stringify(Object.fromEntries(Object.entries(b).map(([k, v]) => [k, v === null ? null : String(v)])))
    return waitFor(() => new Promise((resolve, reject) => {
      const r = request({ host: '127.0.0.1', port: control, method: 'POST', path: '/', headers: { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) } }, (res) => {
        let s = ''; res.on('data', (d) => (s += d)); res.on('end', () => { try { resolve(JSON.parse(s)) } catch (e) { reject(e) } })
      })
      r.on('error', reject); r.end(body)
    }), 10_000, 'miner control')
  }
  return { control, child: c, set }
}
export interface SolPressure { port: number; url: string; child: Child; set(T: number | null): Promise<{ T: number; withheld: number; forwarded: number }> }
// The filter in front of the validator: sendTransaction with a CU price below T is answered as accepted, never forwarded.
export async function startSolPressure(t: T, o: { home: string; validator: number; schedule?: string }): Promise<SolPressure> {
  const port = await freeRun(1)
  const c = child('/usr/bin/sandbox-exec', ['-p', LOOPBACK_ONLY, process.execPath, join(HARNESS, 'sol-pressure-filter.mjs'), '--listen', String(port),
    '--upstream', `http://127.0.0.1:${o.validator}`, '--schedule', o.schedule ?? '0:0'], baseEnv(o.home))
  t.after(() => c.stop())
  await readyLine(c, /^sol pressure filter on 127\.0\.0\.1:/, 'sol pressure filter', 30_000)
  const set = async (T: number | null): Promise<{ T: number; withheld: number; forwarded: number }> => {
    const body = JSON.stringify({ T })
    return new Promise((resolve, reject) => {
      const r = request({ host: '127.0.0.1', port, method: 'POST', path: '/__control', headers: { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) } }, (res) => {
        let s = ''; res.on('data', (d) => (s += d)); res.on('end', () => { try { resolve(JSON.parse(s)) } catch (e) { reject(e) } })
      })
      r.on('error', reject); r.end(body)
    })
  }
  return { port, url: `http://127.0.0.1:${port}`, child: c, set }
}

// Reassembles each copy from the chain's own bytes by the reader rules (contracts/parts.ts parsePart: strip the header,
// concatenate in k order, check k = 1..N and the digest), independently of the engine's `reassembled` line.
export function reassembleFromChain(chain: Chain, parts: PublishedPart[]): Map<number, { text: string; sha256: string; parts: number }> {
  const out = new Map<number, { text: string; sha256: string; parts: number }>()
  for (const copy of [...new Set(parts.map((p) => p.copy))]) {
    const mine = parts.filter((p) => p.copy === copy).sort((a, b) => a.part - b.part)
    const bodies: string[] = []
    let digest: string | null = null
    for (const [k, p] of mine.entries()) {
      const raw = chain === 'eth' ? p.payload.subarray(ETH_LEAD.length) : p.payload
      const h = parsePart(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw))
      if (h.part !== k + 1 || h.parts !== mine.length || (mine.length > 1 && h.copy !== copy)) throw new Error(`${chain} copy ${copy}: part ${k + 1} of ${mine.length} has the header ${h.part}/${h.parts} copy ${h.copy}`)
      if (k === 0) digest = h.sha256
      bodies.push(h.body)
    }
    const text = bodies.join('')
    const sha = sha256(Buffer.from(text, 'utf8'))
    if (mine.length > 1 && sha !== digest) throw new Error(`${chain} copy ${copy}: the reassembled text does not hash to part 1's digest`)
    out.set(copy, { text, sha256: sha, parts: mine.length })
  }
  return out
}

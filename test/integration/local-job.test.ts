// I2 cross-lane test: E3's executor (node adapter, nodeClients) runs whole LOCAL jobs through S2's REAL jobs API process
// and S4's REAL relay process, on this test's own anvil and solana-test-validator (stack.ts). OWN SANDBOX (listed in
// test/integration/own-sandbox.list): every process it starts applies its own sandbox (the relay C1's relayProfile, the
// API C1's apiProfile, the chains loopback-only), so test-root.sh runs this file unsandboxed in phase B.
// ALL DATA IS SYNTHETIC (keys made here, funded on these chains only). No testnet or mainnet traffic, no IP but 127.0.0.1.
//
//   1. job A — ETH copies ×2 (1 part) + SOL drain (multi-part, passive: 5,000 lamports a part, so the armed cap binds
//      after exactly two copies), both executors in this process, armed when both chains are READY, then a claw-back
//      on each chain over the cap with the operator's typed exact amount (CC-2a, end to end). Checks: every part landed
//      once and reads back from the chain itself, every copy reassembled ✓, the journal states, spent ≤ the armed cap,
//      the SSE stream (httpJournalClient.stream) delivered every journal line once, in order;
//   2. job B — a takeover: ETH copies ×2 of a 2-part (≈ 120 KB) message, the executor in a child process SIGKILLed with
//      a part in flight; after the lease lapses a second executor (gen 2) reconciles from the chain and finishes, with
//      no part sent twice (the key's nonce = the number of parts);
//   3. tampering end to end: tickets the API issued for intents whose declared fee (f) or nonce / blockhash (q) is not
//      what the signed bytes carry are refused by the relay (relay.decode-mismatch) with nothing on chain; a ticket whose
//      payload was edited is refused (relay.send-ticket); the honest replacement lands;
//   4. the core-vs-API ledger equivalence over these real journals (ledger-compare.ts).
import { after, before, test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { PORTS, TICKET_PREFIX } from '../../packages/core/src/contracts/index.ts'
import type { ArmCap, Chain, JobDef, JobState, JournalEvent } from '../../packages/core/src/contracts/index.ts'
import { createExecutor, laneConfigOf } from '../../packages/core/src/executor/executor.ts'
import { httpJournalClient } from '../../packages/core/src/executor/journal-client.ts'
import { nodeAdapter, nodeClients } from '../../packages/core/src/executor/adapters/node.ts'
import { newKey } from '../../packages/core/src/engine/keys.js'
import { planLaneCopy } from '../../packages/core/src/engine/lane.js'
import { ethGasFormula, formatUnits, solCuEstimate, solCuLimit } from '../../packages/core/src/chains/plan.js'
import { TOKEN } from '../../api/test/helpers.ts'
import { compareLedgers } from './ledger-compare.ts'
import type { Stack } from './stack.ts'
import { REPO, apiCall, child, ethBalance, ethNonce, fundEth, fundSol, relayCall, rpcResult, solBalance, startStack, syntheticText, waitFor } from './stack.ts'

process.env.NODE_ENV = 'test'
const cleanups: Array<() => unknown> = []
const T = { after: (fn: () => unknown) => { cleanups.push(fn) } }
let S: Stack
before(async () => { S = await startStack(T) }, { timeout: 240_000 })
after(async () => { for (const fn of cleanups.reverse()) { try { await fn() } catch { /* best effort */ } } })

const sha = (b: Uint8Array | string): string => createHash('sha256').update(b).digest('hex')
type Key = ReturnType<typeof newKey> & { address: string; secret: string; kp?: any; account?: any }
const keyOf = (chain: Chain): Key => newKey(chain) as Key
const clients = () => nodeClients({ network: 'local', token: TOKEN, fetch: S.fetch })
function executor(jobId: string, chain: Chain, key: Key, o: { clawbackConfirm?: { amount: string } } = {}) {
  const { journal, relay } = clients()
  const { clock, random } = nodeAdapter()
  return createExecutor({ jobId, chain, key: { chain, address: key.address, network: 'local', handle: key }, holder: 'cli',
    deps: { journal, relay, clock, random, poll: 300, ...(o.clawbackConfirm !== undefined ? { clawbackConfirm: o.clawbackConfirm } : {}) } })
}
async function jobOf(id: string): Promise<{ def: JobDef; state: JobState; seq: number; leases: Record<string, unknown> }> {
  const r = await apiCall(S, 'GET', `/jobs/${id}`)
  assert.equal(r.status, 200, JSON.stringify(r.json))
  return r.json
}
function journalOf(id: string): JournalEvent[] {
  return readFileSync(join(S.state, 'jobs', id, 'journal.jsonl'), 'utf8').split('\n').filter((l) => l !== '').map((l) => JSON.parse(l) as JournalEvent)
}
async function createJob(input: Record<string, unknown>): Promise<{ id: string; def: JobDef }> {
  const r = await apiCall(S, 'POST', '/jobs', input)
  assert.equal(r.status, 201, JSON.stringify(r.json))
  return { id: r.json.id, def: r.json.def }
}
async function uploadMessage(text: string): Promise<{ sha256: string; bytes: number }> {
  const b = Buffer.from(text, 'utf8'), h = sha(b)
  const r = await S.fetch(`http://127.0.0.1:${PORTS.local.api}/messages/${h}`, { method: 'PUT', headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'text/plain; charset=utf-8' }, body: text })
  assert.equal(r.status, 201, await r.text())
  return { sha256: h, bytes: b.length }
}
async function waitReady(id: string, chains: Chain[]): Promise<void> {
  await waitFor(async () => { const j = await jobOf(id); return chains.every((c) => j.state.chains[c]?.phase === 'READY') ? true : null }, 90_000, `${id} READY`, 500)
}
async function arm(id: string, caps: Partial<Record<Chain, ArmCap>>): Promise<void> {
  const chains = Object.keys(caps) as Chain[]
  const amounts: Record<string, string> = {}
  for (const c of chains) if (caps[c]!.overCap) amounts[c] = caps[c]!.planned
  const r = await apiCall(S, 'POST', `/jobs/${id}/arm`, { chains, confirm: { typed: null, amounts }, caps, countdownSec: 5, stagger: [0, 0] })
  assert.equal(r.status, 200, JSON.stringify(r.json))
}
const cap = (nativeCap: bigint, decimals: number, overCap = false): ArmCap => ({ nativeCap: String(nativeCap), usd: 0, priceAt: null, overCap, planned: formatUnits(nativeCap, decimals) })

// The chain's own record of a landed part: ETH the calldata of the tx, SOL the memo bytes (direct, not via the relay).
async function chainBytes(chain: Chain, txId: string): Promise<Buffer> {
  if (chain === 'eth') {
    const tx = await rpcResult(S.anvil, 'eth_getTransactionByHash', [txId])
    const rc = await rpcResult(S.anvil, 'eth_getTransactionReceipt', [txId])
    assert.equal(rc.status, '0x1', `${txId} status`)
    return Buffer.from(String(tx.input).slice(2), 'hex')
  }
  const tx = await rpcResult(S.sol, 'getTransaction', [txId, { encoding: 'json', commitment: 'confirmed', maxSupportedTransactionVersion: 0 }])
  assert.equal(tx.meta.err, null, `${txId} err`)
  const keys: string[] = tx.transaction.message.accountKeys
  const memo = tx.transaction.message.instructions.find((ix: { programIdIndex: number }) => keys[ix.programIdIndex] === 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr')
  return Buffer.from(bs58decode(memo.data))
}
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function bs58decode(s: string): Uint8Array {
  let n = 0n
  for (const ch of s) n = n * 58n + BigInt(B58.indexOf(ch))
  const out: number[] = []
  while (n > 0n) { out.unshift(Number(n % 256n)); n /= 256n }
  for (const ch of s) { if (ch !== '1') break; out.unshift(0) }
  return Uint8Array.from(out)
}

// Every (copy, part) of a chain landed exactly once, reads back from the chain itself as the planned bytes, and every
// copy reassembled ✓. Returns the number of landed parts.
async function assertLandedOnce(id: string, chain: Chain, def: JobDef, text: string): Promise<number> {
  const cs = (await jobOf(id)).state.chains[chain]!
  const cfg = laneConfigOf(chain, def.chains[chain]!, text)
  const copies = new Set<number>()
  for (const t of cs.txs) {
    assert.equal(t.state, 'included', `${chain} copy ${t.copy} part ${t.part}`)
    assert.equal(t.readback, true, `${chain} copy ${t.copy} part ${t.part} readback`)
    const landed = t.attempts.filter((a) => a.state === 'included' || a.state === 'resolved-done')
    assert.equal(landed.length, 1, `${chain} copy ${t.copy} part ${t.part}: exactly one attempt landed`)
    const planned = planLaneCopy(cfg, t.copy)[t.part - 1].payload as Uint8Array
    assert.deepEqual(await chainBytes(chain, t.landedId!), Buffer.from(planned), `${chain} copy ${t.copy} part ${t.part}: the chain carries the planned bytes`)
    copies.add(t.copy)
  }
  const groups = new Set(cs.txs.map((t) => `${t.copy}:${t.part}`))
  assert.equal(groups.size, cs.txs.length, `${chain}: one group per (copy, part)`)
  for (const c of copies) assert.ok(cs.reassembled.some((r) => r.copy === c && r.ok), `${chain} copy ${c} reassembled ✓`)
  return cs.txs.length
}

const jobs: Array<{ id: string; def: JobDef }> = []

test('job A: ETH copies + SOL drain (multi-part) through the real API and relay; claw-backs over the cap with the typed amount; SSE complete', { timeout: 600_000 }, async () => {
  const ek = keyOf('eth'), sk = keyOf('sol')
  const ethDest = keyOf('eth').address, solDest = keyOf('sol').address
  await fundEth(S, ek.address, 10n ** 18n)
  await fundSol(S, sk.address, 100_000_000)
  await fundSol(S, solDest, 1_000_000) // an existing destination
  const text = syntheticText(1_500, 'I2 job A')
  const { id, def } = await createJob({
    format: 'vt-job/1', network: 'local', name: 'I2 job A', message: text,
    chains: {
      eth: { mode: { copies: 2 }, publishMode: 'eth.calldata.null', feeStrategy: 'economy', distinctCopies: true, keyAddress: ek.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: ethDest },
      sol: { mode: 'drain', feeStrategy: 'passive', distinctCopies: true, keyAddress: sk.address, budgetUsd: 5, maxCuPrice: 2_000_000, clawbackTo: solDest },
    },
  })
  jobs.push({ id, def })
  const solParts = planLaneCopy(laneConfigOf('sol', def.chains.sol!, text), 1).length
  assert.ok(solParts >= 2, `SOL is multi-part (${solParts})`)

  // the SSE stream, consumed by E3's journal client from line 0
  const seen: JournalEvent[] = []
  const stopStream = httpJournalClient({ base: `http://127.0.0.1:${PORTS.local.api}`, fetch: S.fetch, token: TOKEN }).stream(id, 0, (e) => { seen.push(e) })

  const eth = executor(id, 'eth', ek), sol = executor(id, 'sol', sk)
  const runs = Promise.all([eth.start(), sol.start()])
  await waitReady(id, ['eth', 'sol'])
  // SOL passive costs exactly 5,000 lamports a part: the cap allows two copies and refuses the third (engine.cap-copy)
  const solCap = BigInt(solParts) * 5_000n * 2n + 2_500n
  await arm(id, { eth: cap(10n ** 16n, 18), sol: cap(solCap, 9) })
  const [eo, so] = await runs
  assert.equal(eo, 'copies-done', `eth: ${eth.view().note}`)
  assert.equal(so, 'stopped', `sol: ${sol.view().note}`)
  let j = await jobOf(id)
  assert.deepEqual([j.state.chains.eth!.phase, j.state.chains.sol!.phase], ['COPIES_DONE', 'STOPPED'])
  assert.match(j.state.chains.sol!.reason ?? '', /spend cap/)
  assert.equal(j.state.chains.eth!.copiesIncluded, 2)
  assert.equal(j.state.chains.sol!.copiesIncluded, 2)
  assert.equal(await assertLandedOnce(id, 'eth', def, text), 2)
  assert.equal(await assertLandedOnce(id, 'sol', def, text), 2 * solParts)
  assert.equal(await ethNonce(S, ek.address), 2, 'two ETH txs from the key: nothing sent twice')
  const solSpent = BigInt(j.state.chains.sol!.spent)
  assert.equal(solSpent, BigInt(2 * solParts) * 5_000n)
  assert.ok(solSpent <= solCap && BigInt(j.state.chains.eth!.spent) <= 10n ** 16n, 'spent ≤ the armed cap on both chains')

  // claw-backs: value + fee is far over the cap, so each needs the operator's typed exact amount (the lane's balance)
  for (const [c, k, dest] of [['eth', ek, ethDest], ['sol', sk, solDest]] as const) {
    const bal = c === 'eth' ? await ethBalance(S, k.address) : await solBalance(S, k.address)
    const destBefore = c === 'eth' ? await ethBalance(S, dest) : await solBalance(S, dest)
    const refused = await executor(id, c, k).clawback(dest)                          // no typed amount: refused, nothing signed
    assert.equal(refused, 'failed')
    assert.equal(c === 'eth' ? await ethNonce(S, k.address) : Number((await jobOf(id)).state.chains.sol!.txs.length), c === 'eth' ? 2 : 2 * solParts)
    const outcome = await executor(id, c, k, { clawbackConfirm: { amount: String(bal) } }).clawback(dest)
    assert.equal(outcome, 'clawed-back', c)
    const destAfter = c === 'eth' ? await ethBalance(S, dest) : await solBalance(S, dest)
    const cb = (await jobOf(id)).state.chains[c]!.clawback!
    assert.deepEqual([cb.ok, cb.landed], [true, true])
    assert.equal(destAfter - destBefore, BigInt(cb.value), `${c}: the destination received the claw-back value`)
  }
  j = await jobOf(id)
  assert.equal(j.state.phase, 'DONE')
  assert.deepEqual([j.state.chains.eth!.phase, j.state.chains.sol!.phase], ['CLAWED_BACK', 'CLAWED_BACK'])
  assert.equal(await solBalance(S, sk.address), 0n, 'the SOL lane is empty')

  // the SSE stream: every journal line once, in order, equal to the journal on disk
  const lines = journalOf(id)
  await waitFor(() => (seen.length >= lines.length ? true : null), 20_000, 'SSE caught up')
  stopStream()
  assert.deepEqual(seen.map((e) => e.seq), lines.map((e) => e.seq))
  assert.deepEqual(seen, lines)
  assert.equal(new Set(seen.map((e) => e.seq)).size, seen.length, 'no duplicate SSE event')
})

test('job B: a takeover mid-job — the first executor (a child process) is SIGKILLed with a part in flight; the next one reconciles and finishes; no part twice', { timeout: 600_000 }, async () => {
  const ek = keyOf('eth')
  await fundEth(S, ek.address, 10n ** 18n)
  const text = syntheticText(120_000, 'I2 job B')                        // > 98,304 calldata bytes: two ETH parts a copy
  const m = await uploadMessage(text)
  const { id, def } = await createJob({
    format: 'vt-job/1', network: 'local', name: 'I2 job B', messageSha256: m.sha256, messageBytes: m.bytes,
    chains: { eth: { mode: { copies: 2 }, publishMode: 'eth.calldata.null', feeStrategy: 'economy', distinctCopies: true, keyAddress: ek.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: null } },
  })
  jobs.push({ id, def })
  const parts = planLaneCopy(laneConfigOf('eth', def.chains.eth!, text), 1).length
  assert.equal(parts, 2, 'ETH is multi-part')
  // the first executor, in its own process, under the CLI executor's loopback-only profile (the stack's two ports)
  const { loopbackProfile } = await import('../../cli/src/ops/sandbox.ts')
  const env = { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: S.home, LANG: 'en_US.UTF-8', NODE_ENV: 'test',
    VT_I2_CHILD: JSON.stringify({ jobId: id, chain: 'eth', secret: ek.secret, api: S.api.port, relay: S.relay.port, token: TOKEN }) }
  const c1 = child('/usr/bin/sandbox-exec', ['-p', loopbackProfile([S.api.port, S.relay.port]), process.execPath, join(REPO, 'test/integration/executor-child.ts')], env)
  T.after(() => c1.stop('SIGKILL'))
  await waitReady(id, ['eth'])
  await arm(id, { eth: cap(10n ** 17n, 18) })
  // SIGKILL once a part landed and another one is in flight (journaled, not landed)
  const atKill = await waitFor(async () => {
    const cs = (await jobOf(id)).state.chains.eth!
    return cs.txs.some((t) => t.state === 'included') && cs.openIntents.length > 0 ? cs : null
  }, 180_000, 'a part in flight after one landed', 30)
  await c1.stop('SIGKILL')
  assert.ok(!c1.lines.some((l) => l.startsWith('outcome ')), `the child was killed mid-job: ${c1.lines.join(' | ')}`)
  const inFlight = [...atKill.openIntents]
  console.log(`job B: SIGKILL with ${inFlight.length} attempt(s) in flight after ${atKill.txs.filter((t) => t.state === 'included').length} part(s) landed`)
  // its lease is still live: a second executor is refused (lease.held) until it lapses — no two holders
  const early = await executor(id, 'eth', ek).start().then(() => 'started', (e: { guardId?: string }) => e.guardId ?? String(e))
  assert.equal(early, 'lease.held')
  await waitFor(async () => ((await jobOf(id)).leases.eth === null ? true : null), 30_000, 'the killed holder\'s lease lapses', 500)
  const second = executor(id, 'eth', ek)
  assert.equal(await second.start(), 'copies-done', second.view().note)
  const j = await jobOf(id)
  assert.equal(j.state.chains.eth!.phase, 'COPIES_DONE')
  assert.equal(j.state.chains.eth!.copiesIncluded, 2)
  assert.equal(await assertLandedOnce(id, 'eth', def, text), 2 * parts)
  assert.equal(await ethNonce(S, ek.address), 2 * parts, 'the key sent exactly one tx per part: nothing twice')
  // the journal: gen 2 acquired the lease and reconciled every attempt that was in flight at the kill before any new intent
  const lines = journalOf(id)
  const gen2 = lines.findIndex((e) => e.type === 'lease-acquired' && e.data.gen === 2)
  assert.ok(gen2 > 0, 'gen 2 took the lease')
  const firstNewIntent = lines.findIndex((e, i) => i > gen2 && e.type === 'intent' && e.gen === 2 && !inFlight.includes(String(e.data.txId)))
  for (const txId of inFlight) {
    const r = lines.findIndex((e, i) => i > gen2 && e.gen === 2 && e.type === 'reconcile' && e.data.txId === txId)
    assert.ok(r > gen2, `${txId} reconciled by gen 2`)
    if (firstNewIntent >= 0) assert.ok(r < firstNewIntent, `${txId} reconciled before any new intent`)
  }
  assert.ok(lines.some((e) => e.type === 'lease-expired' && e.data.gen === 1), 'the dead holder\'s lease is journaled expired')
  console.log(`job B: gen 2 reconciled ${lines.filter((e) => e.gen === 2 && e.type === 'reconcile').map((e) => String(e.data.outcome)).join(', ')}; ${lines.filter((e) => e.type === 'intent').length} intents for ${2 * parts} parts`)
})

test('tampering end to end: a ticket for a wrong f or q is refused by the relay with nothing on chain; an edited ticket too; the honest replacement lands', { timeout: 300_000 }, async () => {
  const eth = await import('../../packages/core/src/chains/eth.js')
  const sol = await import('../../packages/core/src/chains/sol.js')
  const ek = keyOf('eth'), sk = keyOf('sol')
  await fundEth(S, ek.address, 10n ** 18n)
  await fundSol(S, sk.address, 50_000_000)
  const textC = syntheticText(200, 'I2 job C')
  const { id, def } = await createJob({
    format: 'vt-job/1', network: 'local', name: 'I2 job C', message: textC,
    chains: {
      eth: { mode: { copies: 3 }, publishMode: 'eth.calldata.null', feeStrategy: 'economy', distinctCopies: true, keyAddress: ek.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: null },
      sol: { mode: { copies: 3 }, feeStrategy: 'economy', distinctCopies: true, keyAddress: sk.address, budgetUsd: 5, maxCuPrice: 2_000_000, clawbackTo: null },
    },
  })
  jobs.push({ id, def })
  // by hand, as the lease holder: key-loaded, funds, the arm, then the start time
  const gen: Record<Chain, number> = { eth: 0, sol: 0, btc: 0 }
  for (const c of ['eth', 'sol'] as const) {
    const g = await apiCall(S, 'POST', `/jobs/${id}/chains/${c}/lease`, { op: 'acquire', holder: 'cli' })
    assert.equal(g.status, 200, JSON.stringify(g.json))
    gen[c] = g.json.gen
    for (const [type, data] of [['key-loaded', { address: c === 'eth' ? ek.address : sk.address }], ['funds', { balance: '50000000', affordable: true, nextCopyCost: '1' }]] as const) {
      assert.equal((await apiCall(S, 'POST', `/jobs/${id}/chains/${c}/events`, { gen: gen[c], type, data })).status, 200)
    }
  }
  await arm(id, { eth: cap(10n ** 17n, 18), sol: cap(10_000_000n, 9) })
  const releaseAt = (await jobOf(id)).state.releaseAt!
  await waitFor(async () => ((await apiCall(S, 'GET', '/status')).json.serverNowMs >= releaseAt + 500 ? true : null), 30_000, 'the start time')
  const renew = setInterval(() => { for (const c of ['eth', 'sol'] as const) void apiCall(S, 'POST', `/jobs/${id}/chains/${c}/lease`, { op: 'renew', holder: 'cli', gen: gen[c] }) }, 4_000)
  T.after(() => clearInterval(renew))
  const intent = async (c: Chain, data: Record<string, unknown>): Promise<string> => {
    const r = await apiCall(S, 'POST', `/jobs/${id}/chains/${c}/events`, { gen: gen[c], type: 'intent', data })
    assert.equal(r.status, 200, JSON.stringify(r.json))
    return r.json.ticket as string
  }
  const send = (c: 'eth' | 'sol', raw: string, ticket: string) => relayCall(S, c, c === 'eth' ? 'eth_sendRawTransaction' : 'sendTransaction', c === 'eth' ? [raw] : [raw, { encoding: 'base64', preflightCommitment: 'confirmed' }], ticket)
  const refusedFor = (r: { status: number; json: any }): string => `${r.status} ${r.json?.error?.data?.guard ?? r.json?.error?.guard ?? ''} ${r.json?.error?.message ?? ''}`

  // ETH, f: declared at the planned gas G (PF-S fix round 2: within the plan, ticket.fee-plan), signed with G + 1 → the ticket's
  // f = G × maxFee < what the bytes may cost
  const NULL = '0x0000000000000000000000000000000000000000'
  // PF-S I-1: every intent carries the part the API plans for its copy (the lane's planner over the stored text), and the bytes sign it
  const planned = (c: 'eth' | 'sol', copy: number): Uint8Array => (planLaneCopy(laneConfigOf(c, def.chains[c]!, textC), copy) as Array<{ payload: Uint8Array }>)[0].payload
  const dataOf = (copy: number) => `0x${Buffer.from(planned('eth', copy)).toString('hex')}` as `0x${string}`
  const ethData = (x: { id: string; raw: string }, o: { copy: number; nonce: number; gas: string; maxFee: bigint; attempt?: number; replaces?: string | null }) => ({
    txId: x.id, copy: o.copy, part: 1, parts: 1, attempt: o.attempt ?? 1, replaces: o.replaces ?? null, rawSha256: sha(Buffer.from(x.raw.slice(2), 'hex')), payloadSha256: sha(planned('eth', o.copy)), reserved: '1',
    eth: { nonce: o.nonce, tip: '1000000', maxFee: String(o.maxFee), gas: o.gas, to: NULL } })
  const gasOf = (copy: number): bigint => ethGasFormula(planned('eth', copy).length, { amsterdam: false, toSelf: false })   // the engine's formula gas
  const f1 = await eth.sign(ek.account, 31337, { nonce: 0, to: NULL, data: dataOf(1), gas: gasOf(1) + 1n, maxFee: 2_000_000_000n, tip: 1_000_000n })
  const t1 = await intent('eth', ethData(f1, { copy: 1, nonce: 0, gas: String(gasOf(1)), maxFee: 2_000_000_000n }))
  const r1 = await send('eth', f1.raw, t1)
  assert.match(refusedFor(r1), /^403 relay\.decode-mismatch .*\(eth\.fee\)/)
  // an edited ticket: f raised in the payload, the MAC no longer covers it
  const [p64, m64] = t1.slice(TICKET_PREFIX.length).split('.')
  const edited = { ...JSON.parse(Buffer.from(p64, 'base64url').toString('utf8')), f: String((gasOf(1) + 1n) * 2_000_000_000n) }
  const t1e = `${TICKET_PREFIX}${Buffer.from(JSON.stringify(edited)).toString('base64url')}.${m64}`
  assert.match(refusedFor(await send('eth', f1.raw, t1e)), /^403 relay\.send-ticket /)
  assert.equal(await ethNonce(S, ek.address), 0, 'nothing from the key reached the chain')
  assert.equal(await rpcResult(S.anvil, 'eth_getTransactionByHash', [f1.id]), null)
  // the honest replacement of the first attempt (same (copy, part) and nonce, a bump, declared exactly) lands; copies go in order
  // (PF-S fix round 1, N-2), so copy 1 is settled before copy 2 is tried
  const h1 = await eth.sign(ek.account, 31337, { nonce: 0, to: NULL, data: dataOf(1), gas: gasOf(1), maxFee: 2_300_000_000n, tip: 1_000_000n })
  const th = await intent('eth', ethData(h1, { copy: 1, nonce: 0, gas: String(gasOf(1)), maxFee: 2_300_000_000n, attempt: 2, replaces: f1.id }))
  const ok = await send('eth', h1.raw, th)
  assert.equal(ok.status, 200, refusedFor(ok))
  assert.equal(ok.json?.error, undefined, JSON.stringify(ok.json))
  await waitFor(async () => ((await ethNonce(S, ek.address)) === 1 ? true : null), 30_000, 'the honest tx lands')
  // ETH, q: copy 2 declared at nonce 2 (q = 2), signed at nonce 1
  const q1 = await eth.sign(ek.account, 31337, { nonce: 1, to: NULL, data: dataOf(2), gas: gasOf(2), maxFee: 2_100_000_000n, tip: 1_000_000n })
  const t2 = await intent('eth', ethData(q1, { copy: 2, nonce: 2, gas: String(gasOf(2)), maxFee: 2_100_000_000n }))
  assert.match(refusedFor(await send('eth', q1.raw, t2)), /^403 relay\.decode-mismatch .*\(eth\.nonce\)/)
  assert.equal(await rpcResult(S.anvil, 'eth_getTransactionByHash', [q1.id]), null)
  assert.equal(await ethNonce(S, ek.address), 1, 'only the honest tx reached the chain')

  // SOL: the payer is the job key; q = the declared blockhash, f = max(fee, 5,000 + ⌈limit × price / 10⁶⌉)
  const bh = async (): Promise<{ blockhash: string; lastValidBlockHeight: number }> => (await rpcResult(S.sol, 'getLatestBlockhash', [{ commitment: 'confirmed' }])).value
  // the CU limit: the model's for the planned part (PF-S fix round 2: what the API plans, ticket.fee-plan; the engine's estimate path)
  const cuOf = (copy: number): number => solCuLimit(solCuEstimate(planned('sol', copy)))
  const solSigned = (blockhash: string, cuPrice: number, copy: number) => {
    const s = sol.sign(sk.kp, { tx: sol.buildTx(sk.kp.publicKey, planned('sol', copy), blockhash, { cuLimit: cuOf(copy), cuPrice }) })
    return { id: s.id as string, raw: s.raw as string }
  }
  const solData = (x: { id: string; raw: string }, o: { copy: number; blockhash: string; lvb: number; cuPrice: number; fee: string }) => ({
    txId: x.id, copy: o.copy, part: 1, parts: 1, attempt: 1, replaces: null, rawSha256: sha(Buffer.from(x.raw, 'base64')), payloadSha256: sha(planned('sol', o.copy)), reserved: '1',
    sol: { blockhash: o.blockhash, lastValidBlockHeight: o.lvb, cuPrice: o.cuPrice, cuLimit: cuOf(o.copy), rung: null, fee: o.fee } })
  const b1 = await bh(), b2 = await waitFor(async () => { const b = await bh(); return b.blockhash !== b1.blockhash ? b : null }, 30_000, 'a second blockhash')
  // q: signed over b1, declared b2
  const sq = solSigned(b1.blockhash, 0, 1)
  assert.match(refusedFor(await send('sol', sq.raw, await intent('sol', solData(sq, { copy: 1, blockhash: b2.blockhash, lvb: b2.lastValidBlockHeight, cuPrice: 0, fee: '5000' })))), /^403 relay\.decode-mismatch .*\(sol\.blockhash\)/)
  // f: signed with a CU price (6,000 lamports), declared without one (f = 5,000)
  const sf = solSigned(b2.blockhash, 5_000, 2)
  assert.match(refusedFor(await send('sol', sf.raw, await intent('sol', solData(sf, { copy: 2, blockhash: b2.blockhash, lvb: b2.lastValidBlockHeight, cuPrice: 0, fee: '5000' })))), /^403 relay\.decode-mismatch .*\(sol\.fee\)/)
  for (const x of [sq, sf]) assert.equal((await rpcResult(S.sol, 'getSignatureStatuses', [[x.id], { searchTransactionHistory: true }])).value[0], null, 'nothing reached the chain')
  // the honest one (declared exactly) lands
  const b3 = await waitFor(async () => { const b = await bh(); return b.blockhash !== b2.blockhash ? b : null }, 30_000, 'a third blockhash')
  const sh = solSigned(b3.blockhash, 5_000, 3)
  const okSol = await send('sol', sh.raw, await intent('sol', solData(sh, { copy: 3, blockhash: b3.blockhash, lvb: b3.lastValidBlockHeight, cuPrice: 5_000, fee: '6000' })))
  assert.equal(okSol.status, 200, refusedFor(okSol))
  assert.equal(okSol.json?.error, undefined, JSON.stringify(okSol.json))
  await waitFor(async () => ((await rpcResult(S.sol, 'getSignatureStatuses', [[sh.id], { searchTransactionHistory: true }])).value[0]?.confirmationStatus ? true : null), 30_000, 'the honest SOL tx lands')
  clearInterval(renew)
})

test('the core-vs-API cap ledgers over these real journals agree line by line (the API is never below core; these jobs need no conservative difference)', { timeout: 60_000 }, async () => {
  assert.equal(jobs.length, 3)
  for (const { id, def } of jobs) {
    const c = compareLedgers(def, journalOf(id))
    assert.ok(c.checked > 0, id)
    assert.deepEqual(c.below, [], `${def.name}: the API total below core's`)
    // no claim, no failed claw-back, no SOL re-sign and every claw-back landed with its declared value: equal everywhere
    assert.deepEqual(c.above, [], `${def.name}: unexpected conservative differences`)
    for (const [ch, f] of Object.entries(c.final)) assert.equal(f.api, f.core, `${def.name} ${ch}: final totals`)
    console.log(`ledger agreement ${def.name}: ${c.lines} lines, ${c.checked} checks, equal after every line; final ${JSON.stringify(c.final, (_k, v) => (typeof v === 'bigint' ? String(v) : v))}`)
  }
})

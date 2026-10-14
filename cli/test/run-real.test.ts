// cli/test/run-real.test.ts — `vt job run` and `vt job clawback` END TO END (plan Task C6, carry-forward 6): S2's REAL
// jobs API process and S4's REAL relay process (test/integration/stack.ts: each under C1's profile) over this test's
// OWN anvil (1 s blocks) and solana-test-validator (--limit-ledger-size 50000000) on free high loopback ports — never
// the shared :8545 / :8899 / :8999, never the running stack on 5180–5183. vt runs as a real process at a real terminal
// (runInPty) inside the executor sandbox profile with the stack's two ports (loopbackProfile([api, relay], { tty, noListen }): the executor's real profile),
// started through the job stub (the stack listens on ephemeral ports; vt still sends the fixed ports as Host).
// OWN SANDBOX (test/own-sandbox.list): the processes it starts apply their own profiles, so test-root.sh runs it in
// phase B. ALL DATA IS SYNTHETIC: keys made here, funded on these chains only, a made-up passphrase. No testnet or
// mainnet traffic (the local relay has no Tor upstream); no IP but 127.0.0.1, and none printed.
//
//   1. a copies job (ETH copies ×2, SOL copies ×1, both chains in one `vt job run`, one passphrase), every part landed
//      once and read back from the chain itself; then an ETH claw-back UNDER the armed cap (nothing typed);
//   2. a drain job (SOL drain, the armed cap binds after exactly two copies); then a SOL claw-back OVER the cap: a wrong
//      typed amount is refused with nothing signed, the exact one lands and empties the lane;
//   3. Ctrl-C mid-copy (ETH, two parts per copy, anvil's mining paused while part 1 is in flight): vt keeps waiting,
//      journals nothing stopped while the tx is pending, and exits only after it landed; nothing new is signed after the
//      Ctrl-C: exactly ONE intent (copy 1 part 1), nonce 1; R79: a Ctrl-C DETACHES — nothing is journaled stopped, the job keeps running;
//   4. a takeover from the BROWSER executor's lease (E3's browser adapter in a child process, SIGKILLed with a part in
//      flight): `vt job run` gets lease.held while that lease lives, then reconciles from the chain before any new
//      intent and finishes; no part is sent twice.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { ArmCap, Chain, JobDef, JobState, JournalEvent } from '@vault-timelock/core/contracts'
import { PORTS } from '@vault-timelock/core/contracts'
import { encryptKey, newKey } from '@vault-timelock/core/engine/keys.js'
import { laneConfigOf } from '@vault-timelock/core/executor'
import { planLaneCopy } from '@vault-timelock/core/engine/lane.js'
import { formatUnits } from '@vault-timelock/core/chains/plan.js'
import { runInPty } from 'vt-broadcast/test/offline/lifecycle/pty.ts'
import type { PtyResult, PtyStep } from 'vt-broadcast/test/offline/lifecycle/pty.ts'
import { loopbackProfile } from '../src/ops/sandbox.ts'
import { TOKEN } from '../../api/test/helpers.ts'
import type { Stack } from '../../test/integration/stack.ts'
import { apiCall, child, ethBalance, ethNonce, fundEth, fundSol, rpcResult, solBalance, startStack, syntheticText, waitFor } from '../../test/integration/stack.ts'
import { CANARY, CLI, IPV4, NODE, PATH0, removeDir, tempDir } from './lib.ts'

process.env.NODE_ENV = 'test'
const STUB = join(CLI, 'test', 'fixtures', 'job-stub.ts')
const BROWSER = join(CLI, 'test', 'fixtures', 'browser-executor.ts')
const PASS = 'c6-real-synthetic-passphrase-never-a-secret'
const cleanups: Array<() => unknown> = []
const T = { after: (fn: () => unknown) => { cleanups.push(fn) } }
let S: Stack
let K = ''
before(async () => { S = await startStack(T); K = tempDir('vt-c6-real-keys-') }, { timeout: 240_000 })
after(async () => { for (const fn of cleanups.reverse()) { try { await fn() } catch { /* best effort */ } } removeDir(K) })

// ---- keys (synthetic), backups, jobs

type Handle = { chain: Chain; address: string; secret: string }
const keyOf = (c: Chain): Handle => newKey(c) as unknown as Handle
const secrets: string[] = [PASS]
let nb = 0
async function backupOf(h: Handle): Promise<string> {
  secrets.push(h.secret)
  const { ct } = await encryptKey(h as never, PASS, 'local')
  const f = join(K, `b${++nb}`, `vt-${h.chain}-key.age`)
  mkdirSync(join(K, `b${nb}`), { mode: 0o700 })
  writeFileSync(f, ct, { mode: 0o600 })
  return f
}
async function createJob(input: Record<string, unknown>): Promise<{ id: string; def: JobDef }> {
  const r = await apiCall(S, 'POST', '/jobs', input)
  assert.equal(r.status, 201, JSON.stringify(r.json))
  return { id: r.json.id, def: r.json.def }
}
async function uploadMessage(text: string): Promise<{ sha256: string; bytes: number }> {
  const { createHash } = await import('node:crypto')
  const b = Buffer.from(text, 'utf8'), h = createHash('sha256').update(b).digest('hex')
  const r = await S.fetch(`http://127.0.0.1:${PORTS.local.api}/messages/${h}`, { method: 'PUT', headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'text/plain; charset=utf-8' }, body: text })
  assert.equal(r.status, 201, await r.text())
  return { sha256: h, bytes: b.length }
}
async function jobOf(id: string): Promise<{ def: JobDef; state: JobState; seq: number; leases: Record<string, unknown> }> {
  const r = await apiCall(S, 'GET', `/jobs/${id}`)
  assert.equal(r.status, 200, JSON.stringify(r.json))
  return r.json
}
async function journalOf(id: string): Promise<JournalEvent[]> {
  const { readFileSync } = await import('node:fs')
  return readFileSync(join(S.state, 'jobs', id, 'journal.jsonl'), 'utf8').split('\n').filter((l) => l !== '').map((l) => JSON.parse(l) as JournalEvent)
}
const cap = (nativeCap: bigint, decimals: number): ArmCap => ({ nativeCap: String(nativeCap), usd: 0, priceAt: null, overCap: false, planned: formatUnits(nativeCap, decimals) })
async function armWhenReady(id: string, caps: Partial<Record<Chain, ArmCap>>): Promise<void> {
  const chains = Object.keys(caps) as Chain[]
  await waitFor(async () => { const j = await jobOf(id); return chains.every((c) => j.state.chains[c]?.phase === 'READY') ? true : null }, 120_000, `${id} READY`, 300)
  const r = await apiCall(S, 'POST', `/jobs/${id}/arm`, { chains, confirm: { typed: null, amounts: {} }, caps, countdownSec: 5, stagger: [0, 0] })
  assert.equal(r.status, 200, JSON.stringify(r.json))
}

// vt (the job stub) at a real terminal, inside the executor profile of this stack's two ports, started as bin/vt starts
// node (--disable-sigusr1: vt.inspector).
function vt(args: string[], steps: PtyStep[]): Promise<PtyResult> {
  const argv = ['/usr/bin/sandbox-exec', '-p', loopbackProfile([S.api.port, S.relay.port], { tty: true, noListen: true }), NODE, '--disable-sigusr1', '--no-addons', STUB, String(S.api.port), String(S.relay.port), 'local', ...args]
  return runInPty(argv, { env: { PATH: PATH0, HOME: S.home, LANG: 'en_US.UTF-8', TERM: 'xterm', VT_HOME: S.home, VT_JOB_STUB_POLL: '300' }, steps, timeoutMs: 300_000 })
}
const PASSPHRASE: PtyStep = { waitFor: 'Passphrase: ', send: `${PASS}\r` }
function clean(out: string): void {
  const low = out.toLowerCase()
  for (const s of secrets) assert.ok(!low.includes(s.toLowerCase()) && !low.includes(s.toLowerCase().replace(/^0x/, '')), 'a key or the passphrase in the output')
  assert.ok(!out.includes(CANARY) && !IPV4.test(out), 'an IP in the output')
}

// The chain's own record of a landed part (direct to our chains, never through vt): ETH calldata, SOL memo bytes.
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function bs58decode(s: string): Uint8Array {
  let v = 0n
  for (const ch of s) v = v * 58n + BigInt(B58.indexOf(ch))
  const out: number[] = []
  while (v > 0n) { out.unshift(Number(v % 256n)); v /= 256n }
  for (const ch of s) { if (ch !== '1') break; out.unshift(0) }
  return Uint8Array.from(out)
}
async function chainBytes(c: Chain, txId: string): Promise<Buffer> {
  if (c === 'eth') {
    const tx = await rpcResult(S.anvil, 'eth_getTransactionByHash', [txId])
    assert.equal((await rpcResult(S.anvil, 'eth_getTransactionReceipt', [txId])).status, '0x1')
    return Buffer.from(String(tx.input).slice(2), 'hex')
  }
  const tx = await rpcResult(S.sol, 'getTransaction', [txId, { encoding: 'json', commitment: 'confirmed', maxSupportedTransactionVersion: 0 }])
  assert.equal(tx.meta.err, null)
  const keys: string[] = tx.transaction.message.accountKeys
  const memo = tx.transaction.message.instructions.find((ix: { programIdIndex: number }) => keys[ix.programIdIndex] === 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr')
  return Buffer.from(bs58decode(memo.data))
}
// Every (copy, part) landed exactly once, reads back from the chain as the planned bytes, every copy reassembled ✓.
async function landedOnce(id: string, c: Chain, def: JobDef, text: string): Promise<number> {
  const cs = (await jobOf(id)).state.chains[c]!
  const cfg = laneConfigOf(c, def.chains[c]!, text)
  for (const t of cs.txs) {
    assert.equal(t.state, 'included', `${c} copy ${t.copy} part ${t.part}`)
    assert.equal(t.readback, true)
    assert.equal(t.attempts.filter((a) => a.state === 'included').length, 1, `${c} copy ${t.copy} part ${t.part}: one attempt landed`)
    assert.deepEqual(await chainBytes(c, t.landedId!), Buffer.from(planLaneCopy(cfg, t.copy)[t.part - 1].payload as Uint8Array))
  }
  assert.equal(new Set(cs.txs.map((t) => `${t.copy}:${t.part}`)).size, cs.txs.length)
  for (const copy of new Set(cs.txs.map((t) => t.copy))) assert.ok(cs.reassembled.some((r) => r.copy === copy && r.ok), `${c} copy ${copy} reassembled ✓`)
  return cs.txs.length
}

// =====================================================================================================================

test('1. a copies job (ETH ×2, SOL ×1) by one `vt job run`, one passphrase; then an ETH claw-back under the armed cap', { timeout: 600_000 }, async () => {
  const ek = keyOf('eth'), sk = keyOf('sol'), dest = keyOf('eth').address
  await fundEth(S, ek.address, 10n ** 16n)
  await fundSol(S, sk.address, 50_000_000)
  const text = syntheticText(1_500, 'C6 job A (copies)')
  const { id, def } = await createJob({ format: 'vt-job/1', network: 'local', name: 'C6 copies', message: text, chains: {
    eth: { mode: { copies: 2 }, publishMode: 'eth.calldata.null', feeStrategy: 'economy', distinctCopies: true, keyAddress: ek.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: null },
    sol: { mode: { copies: 1 }, feeStrategy: 'passive', distinctCopies: true, keyAddress: sk.address, budgetUsd: 5, maxCuPrice: 2_000_000, clawbackTo: null } } })
  const [fe, fs] = [await backupOf(ek), await backupOf(sk)]
  const run = vt(['run', id, '--backup-eth', fe, '--backup-sol', fs], [PASSPHRASE])
  await armWhenReady(id, { eth: cap(10n ** 18n, 18), sol: cap(10_000_000n, 9) })
  const r = await run
  assert.equal(r.code, 0, r.out)
  assert.equal(r.out.split('Passphrase: ').length - 1, 1, 'one passphrase for both backups')
  assert.match(r.out, /eth: copies-done/)
  assert.match(r.out, /sol: copies-done/)
  assert.match(r.out, /eth intent \[cli gen 1\] copy 1 part 1\/1/, 'the journal events, through the printer')
  assert.equal(await landedOnce(id, 'eth', def, text), 2)
  const solParts = await landedOnce(id, 'sol', def, text)
  assert.ok(solParts >= 2, `SOL multi-part (${solParts})`)
  assert.equal(await ethNonce(S, ek.address), 2, 'two ETH txs: nothing twice')
  clean(r.out)

  // the ETH remainder (≈ 0.01 ETH) fits what is left of the 1 ETH armed cap: no amount is typed
  const before = await ethBalance(S, dest)
  const c = await vt(['clawback', id, '--chain', 'eth', '--to', dest, '--backup-eth', fe], [PASSPHRASE])
  assert.equal(c.code, 0, c.out)
  assert.ok(!c.out.includes('to approve clawing back'), 'nothing typed under the cap')
  assert.match(c.out, /gas 21000: the destination is EMPTY \(a fresh account\); Amsterdam is not active on local/)
  assert.match(c.out, /links the lane key .* on-chain/)
  assert.match(c.out, /eth: clawed-back/)
  const cs = (await jobOf(id)).state.chains.eth!
  assert.deepEqual([cs.phase, cs.clawback!.landed, cs.clawback!.ok], ['CLAWED_BACK', true, true])
  assert.equal((await ethBalance(S, dest)) - before, BigInt(cs.clawback!.value), 'the destination received the claw-back value')
  clean(c.out)
})

test('2. a drain job (SOL drain: the armed cap binds after two copies); then a SOL claw-back over the cap — a wrong typed amount is refused, the exact one lands', { timeout: 600_000 }, async () => {
  const sk = keyOf('sol'), dest = keyOf('sol').address
  await fundSol(S, sk.address, 100_000_000)
  await fundSol(S, dest, 1_000_000)
  const text = syntheticText(1_500, 'C6 job B (drain)')
  const { id, def } = await createJob({ format: 'vt-job/1', network: 'local', name: 'C6 drain', message: text, chains: {
    sol: { mode: 'drain', feeStrategy: 'passive', distinctCopies: true, keyAddress: sk.address, budgetUsd: 5, maxCuPrice: 2_000_000, clawbackTo: dest } } })
  const parts = planLaneCopy(laneConfigOf('sol', def.chains.sol!, text), 1).length
  const fsk = await backupOf(sk)
  const run = vt(['run', id, '--backup-sol', fsk], [PASSPHRASE])
  const solCap = BigInt(parts) * 5_000n * 2n + 2_500n
  await armWhenReady(id, { sol: cap(solCap, 9) })
  const r = await run
  assert.equal(r.code, 0, r.out)
  assert.match(r.out, /sol: stopped/)
  const j = await jobOf(id)
  assert.equal(j.state.chains.sol!.phase, 'STOPPED')
  assert.match(j.state.chains.sol!.reason ?? '', /spend cap/)
  assert.equal(await landedOnce(id, 'sol', def, text), 2 * parts)
  assert.ok(BigInt(j.state.chains.sol!.spent) <= solCap)
  clean(r.out)

  // the remainder (≈ 0.1 SOL) is far over what is left of the cap: typed exactly, else nothing is signed
  const bal = await solBalance(S, sk.address)
  const exact = formatUnits(bal, 9)
  const wrong = await vt(['clawback', id, '--chain', 'sol', '--to', dest, '--backup-sol', fsk], [PASSPHRASE, { waitFor: 'to approve clawing back exactly', send: `${formatUnits(bal - 1n, 9)}\r` }])
  assert.equal(wrong.code, 2, wrong.out)
  assert.match(wrong.out, /refused arm\.amount: /)
  assert.ok(!(await journalOf(id)).some((e) => e.type === 'clawback-intent'), 'nothing signed')
  const other = keyOf('sol').address
  const notTo = await vt(['clawback', id, '--chain', 'sol', '--to', other, '--backup-sol', fsk], [])
  assert.equal(notTo.code, 2, notTo.out)
  assert.match(notTo.out, /refused job\.clawback: this job sends its sol claw-back only to its clawbackTo/)
  const destBefore = await solBalance(S, dest)
  const c = await vt(['clawback', id, '--chain', 'sol', '--to', dest, '--backup-sol', fsk], [PASSPHRASE, { waitFor: 'to approve clawing back exactly', send: `${exact}\r` }])
  assert.equal(c.code, 0, c.out)
  assert.match(c.out, /sol: clawed-back/)
  const cs = (await jobOf(id)).state.chains.sol!
  assert.deepEqual([cs.phase, cs.clawback!.landed], ['CLAWED_BACK', true])
  assert.equal(await solBalance(S, sk.address), 0n, 'the SOL lane is empty')
  assert.equal((await solBalance(S, dest)) - destBefore, BigInt(cs.clawback!.value))
  clean(c.out + wrong.out)
})

test('3. Ctrl-C with part 1 of 2 in flight (anvil paused): it resolves first; vt keeps waiting and exits after it landed; exactly one intent; R79: a detach, nothing journaled stopped', { timeout: 600_000 }, async () => {
  const ek = keyOf('eth')
  await fundEth(S, ek.address, 10n ** 18n)
  const text = syntheticText(120_000, 'C6 job C (Ctrl-C)')                     // > 98,304 calldata bytes: two ETH parts a copy
  const m = await uploadMessage(text)
  const { id, def } = await createJob({ format: 'vt-job/1', network: 'local', name: 'C6 ctrl-c', messageSha256: m.sha256, messageBytes: m.bytes, chains: {
    eth: { mode: { copies: 2 }, publishMode: 'eth.calldata.null', feeStrategy: 'economy', distinctCopies: true, keyAddress: ek.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: null } } })
  assert.equal(planLaneCopy(laneConfigOf('eth', def.chains.eth!, text), 1).length, 2, 'two parts a copy')
  let exited = 0
  const run = vt(['run', id, '--backup-eth', await backupOf(ek)], [PASSPHRASE, { waitFor: 'eth sent [cli gen', send: '\x03' }]).finally(() => { exited = Date.now() })
  await armWhenReady(id, { eth: cap(10n ** 17n, 18) })
  await rpcResult(S.anvil, 'evm_setIntervalMining', [0])                     // nothing is mined from here
  let resumed = 0
  try {
    const sent = await waitFor(async () => { const evs = await journalOf(id); const s = evs.find((e) => e.type === 'sent' && e.chain === 'eth'); return s ?? null }, 120_000, 'the first part sent', 100)
    await new Promise((r) => setTimeout(r, 4_000))                          // vt has had the Ctrl-C for seconds now
    assert.equal(exited, 0, 'vt is still running: it waits for the in-flight transaction')
    const evs = await journalOf(id)
    assert.ok(!evs.some((e) => e.type === 'stopped'), 'nothing journaled stopped while the tx is in flight')
    assert.equal((await jobOf(id)).state.chains.eth!.openIntents.length, 1, 'one tx in flight')
    void sent
  } finally {
    resumed = Date.now()
    await rpcResult(S.anvil, 'evm_setIntervalMining', [1])
  }
  const r = await run
  assert.equal(r.code, 0, r.out)
  assert.ok(exited >= resumed, 'vt exited only after mining resumed and the tx landed')
  assert.match(r.out, /stopping after the in-flight transaction/)
  assert.match(r.out, /eth: stopped/)
  const evs = (await journalOf(id)).filter((e) => e.chain === 'eth')
  const lastIncluded = evs.map((e) => e.type).lastIndexOf('included'), stopped = evs.findIndex((e) => e.type === 'stopped')
  assert.ok(lastIncluded >= 0 && stopped < 0, 'R79: the part landed; a Ctrl-C journals no stop')
  const j = await jobOf(id)
  assert.equal(j.state.chains.eth!.phase, 'RUNNING', 'the job keeps running (the next vt job run continues it)')
  assert.equal(j.state.chains.eth!.openIntents.length, 0, 'nothing left in flight')
  // E3 fix round 1 (Stop between parts): the Ctrl-C came with part 1 of 2 in flight, so part 2 is never signed.
  const intents = evs.filter((e) => e.type === 'intent').map((e) => [e.data.copy, e.data.part])
  assert.deepEqual(intents, [[1, 1]], 'exactly one intent: copy 1 part 1 (part 2 and copy 2 never signed)')
  assert.equal(await ethNonce(S, ek.address), 1, 'the one signed part landed once')
  assert.ok(evs.findIndex((e) => e.type === 'intent') < lastIncluded, 'the intent precedes its included')
  console.log('C6 Ctrl-C mid-copy: 1 of 2 parts of copy 1 signed (in flight at the Ctrl-C); Stop between parts held')
  clean(r.out)
})

test('4. takeover from the browser executor\'s lease: lease.held while it lives; then vt reconciles first and finishes; no part twice', { timeout: 600_000 }, async () => {
  const ek = keyOf('eth')
  await fundEth(S, ek.address, 10n ** 18n)
  const text = syntheticText(120_000, 'C6 job D (takeover)')
  const m = await uploadMessage(text)
  const { id, def } = await createJob({ format: 'vt-job/1', network: 'local', name: 'C6 takeover', messageSha256: m.sha256, messageBytes: m.bytes, chains: {
    eth: { mode: { copies: 2 }, publishMode: 'eth.calldata.null', feeStrategy: 'economy', distinctCopies: true, keyAddress: ek.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: null } } })
  const parts = planLaneCopy(laneConfigOf('eth', def.chains.eth!, text), 1).length
  const env = { PATH: PATH0, HOME: S.home, LANG: 'en_US.UTF-8', NODE_ENV: 'test',
    VT_C6_BROWSER: JSON.stringify({ jobId: id, chain: 'eth', secret: ek.secret, api: S.api.port, relay: S.relay.port, token: TOKEN }) }
  const page = child('/usr/bin/sandbox-exec', ['-p', loopbackProfile([S.api.port, S.relay.port]), NODE, BROWSER], env)
  T.after(() => page.stop('SIGKILL'))
  await armWhenReady(id, { eth: cap(10n ** 17n, 18) })
  const atKill = await waitFor(async () => {
    const cs = (await jobOf(id)).state.chains.eth!
    return cs.txs.some((t) => t.state === 'included') && cs.openIntents.length > 0 ? cs : null
  }, 180_000, 'a part in flight after one landed', 30)
  await page.stop('SIGKILL')                                                   // the tab closes
  assert.ok(!page.lines.some((l) => l.startsWith('outcome ')), page.lines.join(' | '))
  const inFlight = [...atKill.openIntents]
  const lease = (await jobOf(id)).leases.eth as { holder?: string } | null
  assert.equal(lease?.holder, 'browser', 'the page holds the lease')
  const f = await backupOf(ek)
  const early = await vt(['run', id, '--backup-eth', f], [PASSPHRASE])
  assert.equal(early.code, 2, early.out)
  assert.match(early.out, /refused lease\.held: /)
  await waitFor(async () => ((await jobOf(id)).leases.eth === null ? true : null), 30_000, 'the page\'s lease lapses', 500)
  const r = await vt(['run', id, '--backup-eth', f], [PASSPHRASE])
  assert.equal(r.code, 0, r.out)
  assert.match(r.out, /eth: copies-done/)
  assert.equal(await landedOnce(id, 'eth', def, text), 2 * parts)
  assert.equal(await ethNonce(S, ek.address), 2 * parts, 'one tx per part: nothing twice')
  const lines = await journalOf(id)
  const gen2 = lines.findIndex((e) => e.type === 'lease-acquired' && e.data.holder === 'cli')
  assert.ok(gen2 > 0, 'vt took the lease')
  const g = lines[gen2].data.gen as number
  const firstNew = lines.findIndex((e, i) => i > gen2 && e.type === 'intent' && e.gen === g && !inFlight.includes(String(e.data.txId)))
  for (const txId of inFlight) {
    const rc = lines.findIndex((e, i) => i > gen2 && e.gen === g && e.type === 'reconcile' && e.data.txId === txId)
    assert.ok(rc > gen2, `${txId} reconciled by vt`)
    if (firstNew >= 0) assert.ok(rc < firstNew, 'reconciled before any new intent')
  }
  assert.ok(lines.some((e) => e.type === 'lease-expired' && e.data.gen === g - 1), 'the page\'s lease journaled expired')
  clean(r.out + early.out)
})

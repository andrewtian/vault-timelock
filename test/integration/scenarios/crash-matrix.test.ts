// E4 scenario crash-matrix (M1; Review Focus 3): power loss at every journal transition, on both chains, through S2's
// REAL API and S4's REAL relay on the harness's own chains. Every case is its own job (copies 2 × 2 parts) and key.
//
// 1. THE EXECUTOR dies (the CLI's adapter in its own process SIGKILLs itself at the exact transition; a second executor
//    takes over once the lease lapses):
//      after intent #2     acked, the bytes never left        ETH: adopted, watched, then a same-nonce bump `replaces` it
//                                                             SOL: watched until PROVEN expired (every endpoint), re-signed
//      after send #2       the relay took the bytes, no `sent` → reconcile included from the chain
//      after sent #2       `sent`, no `included`             → reconcile included from the chain
//      after included #2   `included`, no `readback`         → the landed part is RE-READ, never re-sent
//      after readback #1   between parts                     → part 2 of copy 1 next
//      after readback #2   the copy's last part, no `reassembled` → reassembled from the chain, then copy 2
//      after reassembled #1 between copies                   → copy 2 part 1 next
//      after reassembled #2 no `copies-done`                 → copies-done, nothing signed
// 2. THE API dies (the plan's three points; a forwarder in front of the API kills it at that exact request), the
//    executor's run ends, the API restarts over the same state dir and rebuilds every job from its journal, a new
//    executor takes over:  (a) after the intent's fsync, before its reply (the reply is lost);  (b) after the send,
//    before `sent`;  (c) after `included`, before `readback`.  On both chains.
// Every case asserts: COPIES_DONE; every (copy, part) on chain exactly once with the planned bytes and nothing else from
// the key (read directly from the chain; ETH: the nonce = the number of parts); the takeover reconciled every open
// attempt before any new intent; the API's state = core reduce() over the journal file; the cap ledgers rebuilt from
// the journal (the API's and core's, line by line) agree and the spend equals the fees the chain charged.
// OWN SANDBOX. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { Chain, JobDef, JournalEvent } from '../../../packages/core/src/contracts/index.ts'
import { reduce } from '../../../packages/core/src/job/index.ts'
import { compareLedgers } from '../ledger-compare.ts'
import { startAnvil, startValidator, fundEth, fundSol, ethNonce, rpcResult, solTxOnChain, waitFor } from '../harness/chains.ts'
import { armOk, capOf, createJob, evidence, jobOf, journalOf, outcomesOf, spawnExecutor, startStack, uploadMessage, waitReady } from '../harness/stack.ts'
import type { Crash, Req, Stack } from '../harness/stack.ts'
import { assertPublished, keyOf, lifecycle, ms, scratch, syntheticText } from '../harness/kit.ts'

const T = lifecycle()
const KILLS: Crash[] = [
  { at: 'after', what: 'intent', nth: 2 }, { at: 'after', what: 'send', nth: 2 }, { at: 'after', what: 'sent', nth: 2 }, { at: 'after', what: 'included', nth: 2 },
  { at: 'after', what: 'readback', nth: 1 }, { at: 'after', what: 'readback', nth: 2 }, { at: 'after', what: 'reassembled', nth: 1 }, { at: 'after', what: 'reassembled', nth: 2 },
]
type ApiKill = 'a' | 'b' | 'c'
// a journal in one line (for failure messages): seq type [copy.part] gen by
const summary = (lines: JournalEvent[]): string => lines.map((e) => `${e.seq}:${e.type}${e.data.copy !== undefined ? `[${e.data.copy}.${e.data.part}]` : ''}${e.data.outcome !== undefined ? `=${e.data.outcome}` : ''}@${e.gen ?? '-'}/${e.by}`).join(' ')

test('crash matrix: the executor killed at every journal transition and the API killed at the plan\'s three points, on both chains — no duplicate, state and ledgers rebuilt', { timeout: 1_500_000 }, async () => {
  const t0 = Date.now()
  const home = scratch(T)
  // a roomy block gas limit: many 2-part (≈ 4.7 M gas) ETH copies run at once without filling blocks (the base fee stays 7)
  const [anvil, sol] = await Promise.all([startAnvil(T, { home, blockTime: 1, baseFee: 7n, gasLimit: 1_000_000_000n }), startValidator(T, { home, dir: home })])
  const ports = { anvil: anvil.port, sol: sol.port }
  const ethText = syntheticText(120_000, 'E4 crash matrix: two ETH parts a copy')
  const solText = syntheticText(1_600, 'E4 crash matrix: two SOL parts a copy')
  const S1 = await startStack(T, { network: 'local', ethRpc: anvil.url, solRpc: sol.url, page: false })
  const ethMsg1 = await uploadMessage(S1, ethText)

  async function newJob(s: Stack, chain: Chain, name: string, ethMsg: { messageSha256: string; messageBytes: number }) {
    const key = keyOf(chain)
    if (chain === 'eth') await fundEth(anvil.port, key.address, 10n ** 18n); else await fundSol(sol.port, key.address, 100_000_000)
    const ch = chain === 'eth'
      ? { eth: { mode: { copies: 2 }, publishMode: 'eth.calldata.null', feeStrategy: 'economy', distinctCopies: true, keyAddress: key.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: null } }
      : { sol: { mode: { copies: 2 }, feeStrategy: 'economy', distinctCopies: true, keyAddress: key.address, budgetUsd: 5, maxCuPrice: 2_000_000, clawbackTo: null } }
    const { id, def } = await createJob(s, { format: 'vt-job/1', network: 'local', name, ...(chain === 'eth' ? ethMsg : { message: solText }), chains: ch })
    return { id, def, key, text: chain === 'eth' ? ethText : solText }
  }
  const capFor = (c: Chain) => ({ [c]: capOf(c, c === 'eth' ? 10n ** 17n : 10n ** 9n) })

  // the common closing checks of a case; returns the evidence
  async function closing(s: Stack, scenario: string, j: { id: string; def: JobDef; key: { address: string }; text: string }, chain: Chain, openAtDeath: string[], deathAt: number) {
    const st = (await jobOf(s, j.id)).state
    const lines = journalOf(s, j.id)
    const cs = st.chains[chain]!
    assert.equal(cs.phase, 'COPIES_DONE', `${scenario}: ${cs.reason ?? ''}`)
    assert.equal(cs.copiesIncluded, 2)
    const p = await assertPublished('crash-matrix', ports, j.def, j.text, st, chain, { copies: 2 })
    assert.equal(p.parts.length, 4)
    if (chain === 'eth') assert.equal(await ethNonce(anvil.port, j.key.address), 4, `${scenario}: the nonce = the parts: nothing twice`)
    // the API's state is the fold of its journal (core reduce over the file, line for line the same)
    assert.deepEqual(JSON.parse(JSON.stringify(st)), JSON.parse(JSON.stringify(reduce(j.def, lines))), `${scenario}: API state = reduce(journal)`)
    // the cap ledgers rebuilt from the journal: the API's never below core's, equal at the end, = the chain's fees
    const cmp = compareLedgers(j.def, lines)
    assert.deepEqual(cmp.below, [], `${scenario}: the API's ledger is never below core's`)
    const fin = cmp.final[chain]!
    const chainFees = p.parts.reduce((a, x) => a + BigInt(x.fee), 0n)
    assert.equal(fin.api, fin.core, `${scenario}: the rebuilt ledgers agree at the end`)
    assert.equal(fin.core, chainFees, `${scenario}: spent + held = the fees the chain charged (nothing held)`)
    assert.equal(BigInt(cs.spent), chainFees)
    // reconcile-first: the new generation reconciled every attempt open at the death before any new intent
    const lastGen = Math.max(...lines.filter((e) => e.chain === chain && e.type === 'lease-acquired').map((e) => Number(e.data.gen)))
    const acq = lines.findIndex((e) => e.chain === chain && e.type === 'lease-acquired' && e.data.gen === lastGen)
    const firstIntent = lines.findIndex((e: JournalEvent, i) => i > acq && e.chain === chain && e.type === 'intent')
    for (const tx of openAtDeath) {
      const r = lines.findIndex((e: JournalEvent, i) => i > acq && e.chain === chain && e.type === 'reconcile' && e.data.txId === tx)
      assert.ok(r > acq, `${scenario}: ${tx} reconciled by the new holder`)
      if (firstIntent >= 0) assert.ok(r < firstIntent, `${scenario}: ${tx} reconciled before any new intent`)
    }
    const after = lines.slice(acq)
    return {
      st, lines, after, p,
      ev: { gen: lastGen, openAtDeath: openAtDeath.length, reconciled: after.filter((e) => e.chain === chain && e.type === 'reconcile').map((e) => String(e.data.outcome)),
        intents: lines.filter((e) => e.chain === chain && e.type === 'intent').length, parts: p.parts.length, replaced: lines.filter((e) => e.type === 'replaced').length,
        firstNew: after.find((e) => e.type === 'intent') ? `copy ${after.find((e) => e.type === 'intent')!.data.copy} part ${after.find((e) => e.type === 'intent')!.data.part}` : 'none',
        ledgerChecks: cmp.checked, recoveredMs: Date.now() - deathAt },
    }
  }
  // An attempt whose bytes reached the relay but whose `sent` was never journaled: the new holder decides from the chain.
  // Mined by then → reconcile included. ETH still in the pool (a fast restart) → adopted: watched at its nonce, and the
  // engine's same-nonce bump replaces it — either way ONE tx at that nonce (closing() counts the key's nonce and payloads).
  // SOL is never re-signed before a proven expiry, so it is always reconciled included.
  function sentButOpen(name: string, chain: Chain, after: JournalEvent[], txId: string): void {
    const r = after.find((e) => e.type === 'reconcile' && e.data.txId === txId)
    assert.ok(r !== undefined, `${name}: reconciled — ${summary(after)}`)
    assert.ok(chain === 'eth' ? ['included', 'adopted'].includes(String(r!.data.outcome)) : r!.data.outcome === 'included', `${name}: ${String(r!.data.outcome)} — ${summary(after)}`)
  }
  // An acked intent whose bytes never left: ETH — adopted at its nonce, then a same-nonce bump `replaces` it (one nonce, one
  // tx); SOL — proven expired first (reconcile expired), only then a new signature for that (copy, part), which lands.
  function resignedOnce(name: string, chain: Chain, lines: JournalEvent[], after: JournalEvent[], txId: string): void {
    if (chain === 'eth') { assert.ok(lines.some((e) => e.type === 'replaced' && e.data.prevId === txId), `${name}: a same-nonce bump replaces it — ${summary(after)}`); return }
    const exp = after.findIndex((e) => e.type === 'reconcile' && e.data.txId === txId && e.data.outcome === 'expired')
    const next = after.findIndex((e) => e.type === 'intent' && e.data.copy === 1 && e.data.part === 2)
    assert.ok(exp >= 0 && next > exp, `${name}: proven expired before the new signature of copy 1 part 2 — ${summary(after)}`)
  }
  // what a never-sent attempt left: it is not on the chain
  async function neverLanded(chain: Chain, txId: string): Promise<void> {
    if (chain === 'eth') assert.equal(await rpcResult(anvil.port, 'eth_getTransactionByHash', [txId]), null, `${txId}: never on chain`)
    else assert.equal(await solTxOnChain(sol.port, txId), null, `${txId}: never on chain`)
  }

  // ---- 1. the executor dies at each transition
  async function executorCase(chain: Chain, crash: Crash) {
    const name = `${chain} executor ${crash.at} ${crash.what} #${crash.nth}`
    const j = await newJob(S1, chain, `E4 crash ${name}`, ethMsg1)
    const c1 = spawnExecutor(S1, { adapter: 'node', jobId: j.id, keys: [j.key], crash: { ...crash, chain } })
    T.after(() => c1.stop('SIGKILL'))
    await waitReady(S1, j.id, [chain])
    await armOk(S1, j.id, capFor(chain))
    await waitFor(() => (c1.proc.exitCode !== null || c1.proc.signalCode !== null ? true : null), 300_000, `${name}: the crash`, 100)
    assert.ok(c1.lines.some((l) => l.startsWith(`crash ${crash.at} ${crash.what} #${crash.nth} ${chain}`)), `${name}: died at its point: ${c1.tail(4)}`)
    const deathAt = Date.now()
    const atDeath = (await jobOf(S1, j.id)).state.chains[chain]!
    const open = [...atDeath.openIntents]
    const c2 = spawnExecutor(S1, { adapter: 'node', jobId: j.id, keys: [j.key] })
    T.after(() => c2.stop('SIGKILL'))
    assert.deepEqual(await outcomesOf(c2, [chain], 1_200_000), { [chain]: 'copies-done' }, `${name}: ${c2.tail(3)}`)
    const { lines, after, ev } = await closing(S1, name, j, chain, open, deathAt)
    // what each point must have produced
    if (crash.what === 'intent') {
      assert.equal(open.length, 1, `${name}: one attempt open at the death`)
      await neverLanded(chain, open[0])
      if (chain === 'eth') assert.ok(after.some((e) => e.type === 'reconcile' && e.data.txId === open[0] && e.data.outcome === 'adopted'), `${name}: adopted`)
      else assert.ok(after.some((e) => e.type === 'reconcile' && e.data.txId === open[0] && e.data.outcome === 'expired'), `${name}: proven expired`)
      resignedOnce(name, chain, lines, after, open[0])
    }
    if (crash.what === 'send' || crash.what === 'sent') sentButOpen(name, chain, after, open[0])
    if (crash.what === 'included') assert.ok(after.some((e) => e.type === 'readback' && e.data.ok === true && /re-read at the takeover/.test(String(e.data.detail))), `${name}: re-read, not re-sent`)
    if (crash.what !== 'intent') assert.equal(ev.intents, 4, `${name}: one intent per part`)
    if (crash.what === 'readback' && crash.nth === 1) assert.equal(ev.firstNew, 'copy 1 part 2')
    if (crash.what === 'readback' && crash.nth === 2) {
      const ra = after.findIndex((e) => e.type === 'reassembled' && e.data.copy === 1), fi = after.findIndex((e) => e.type === 'intent')
      assert.ok(ra >= 0 && ra < fi, `${name}: copy 1 reassembled from the chain before copy 2`)
      assert.equal(ev.firstNew, 'copy 2 part 1')
    }
    if (crash.what === 'reassembled' && crash.nth === 1) assert.equal(ev.firstNew, 'copy 2 part 1')
    if (crash.what === 'reassembled' && crash.nth === 2) assert.equal(ev.firstNew, 'none', `${name}: nothing signed after the last copy`)
    evidence('crash-matrix', name, { kill: 'executor', ...ev })
  }

  // ---- 2. the API dies at the plan's three points (a stack of its own per case: a restart ends every lease on it)
  async function apiCase(chain: Chain, point: ApiKill) {
    const name = `${chain} API ${point === 'a' ? '(a) after the intent fsync, before the reply' : point === 'b' ? '(b) after the send, before sent' : '(c) after included, before readback'}`
    const s = await startStack(T, { network: 'local', ethRpc: anvil.url, solRpc: sol.url, page: false })
    const ethMsg = chain === 'eth' ? await uploadMessage(s, ethText) : ethMsg1
    const j = await newJob(s, chain, `E4 crash ${name}`, ethMsg)
    let fired = false, dead = false, partTwo: string | null = null, landedTwo: string | null = null
    const ours = (r: Req, type: string): boolean => r.method === 'POST' && r.path === `/jobs/${j.id}/chains/${chain}/events` && r.body?.type === type
    const kill = async (): Promise<void> => { fired = true; dead = true; await s.killApi() }
    s.front.after = async (r, status) => {
      if (ours(r, 'intent') && r.body.data.copy === 1 && r.body.data.part === 2 && status === 200) {
        partTwo = String(r.body.data.txId)
        if (point === 'a' && !fired) { await kill(); return 'drop' }   // journaled and fsynced; the reply never arrives
      }
      if (ours(r, 'included') && r.body.data.copy === 1 && r.body.data.part === 2 && status === 200) landedTwo = String(r.body.data.txId)
      return 'deliver'
    }
    s.front.before = async (r) => {
      if (dead) throw new Error('the API is down')
      if (point === 'b' && !fired && ours(r, 'sent') && r.body.data.txId === partTwo) { await kill(); throw new Error('the API died') }
      if (point === 'c' && !fired && ours(r, 'readback') && landedTwo !== null && r.body.data.txId === landedTwo) { await kill(); throw new Error('the API died') }
    }
    const c1 = spawnExecutor(s, { adapter: 'node', jobId: j.id, keys: [j.key] })
    T.after(() => c1.stop('SIGKILL'))
    await waitReady(s, j.id, [chain])
    await armOk(s, j.id, capFor(chain))
    // the executor's run ends without its API (its journal refuses nothing: it cannot reach it)
    const o1 = await outcomesOf(c1, [chain], 300_000)
    assert.ok(fired, `${name}: the kill fired`)
    assert.notEqual(o1[chain], 'copies-done', `${name}: the first run could not finish`)
    const deathAt = Date.now()
    s.front.before = undefined; s.front.after = undefined
    dead = false
    await s.restartApi()
    // the restarted API rebuilt the job from its journal alone
    const rebuilt = (await jobOf(s, j.id)).state
    assert.deepEqual(JSON.parse(JSON.stringify(rebuilt)), JSON.parse(JSON.stringify(reduce(j.def, journalOf(s, j.id)))), `${name}: the restarted API's state = reduce(journal)`)
    const open = [...rebuilt.chains[chain]!.openIntents]
    if (point === 'a') assert.deepEqual(open, [partTwo], `${name}: the intent whose reply was lost is journaled and open`)
    const c2 = spawnExecutor(s, { adapter: 'node', jobId: j.id, keys: [j.key] })
    T.after(() => c2.stop('SIGKILL'))
    assert.deepEqual(await outcomesOf(c2, [chain], 1_200_000), { [chain]: 'copies-done' }, `${name}: ${c2.tail(3)}`)
    const { lines, after, ev } = await closing(s, name, j, chain, open, deathAt)
    if (point === 'a') {
      await neverLanded(chain, partTwo!)
      assert.ok(after.some((e) => e.type === 'reconcile' && e.data.txId === partTwo && e.data.outcome === (chain === 'eth' ? 'adopted' : 'expired')), `${name}: ${chain === 'eth' ? 'adopted' : 'proven expired'}`)
      resignedOnce(name, chain, lines, after, partTwo!)
    }
    if (point === 'b') sentButOpen(name, chain, after, partTwo!)
    if (point === 'c') assert.ok(after.some((e) => e.type === 'readback' && e.data.txId === landedTwo && e.data.ok === true && /re-read at the takeover/.test(String(e.data.detail))), `${name}: re-read, not re-sent`)
    evidence('crash-matrix', name, { kill: 'api', firstRun: o1[chain], ...ev })
  }

  const only = process.env.VT_E4_ONLY ?? ''
  await Promise.all([
    ...(['eth', 'sol'] as Chain[]).flatMap((c) => KILLS.filter((k) => `${c} executor ${k.what} ${k.nth}`.includes(only)).map((k) => executorCase(c, k))),
    ...(['eth', 'sol'] as Chain[]).flatMap((c) => (['a', 'b', 'c'] as ApiKill[]).filter((p) => `${c} api ${p}`.includes(only)).map((p) => apiCase(c, p))),
  ])
  evidence('crash-matrix', 'timing', { cases: KILLS.length * 2 + 6, totalMs: ms(t0) })
})

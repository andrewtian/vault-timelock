// E4 scenario takeover (M1; Review Focus 1): the page's executor (browser adapter, its own process through the REAL page
// server) dies mid-run — a tab closed or crashed — and the REAL `vt job run` (on a pty) takes over once
// the dead tab's lease lapses (~10–15 s: TTL 15 s, renewed every 5 s). The new holder reconciles every open intent from
// the chain before any new intent, then finishes; every (copy, part) is on chain exactly once.
//   T-eth-part  ETH, 2 parts a copy: the tab dies right after the relay accepted part 2 (its `sent` never journaled);
//   T-eth-copy  ETH, 2 parts a copy: the tab dies between parts (right after part 1's readback);
//   T-sol-part  SOL, 2 parts a copy: dies right after the relay accepted part 2;
//   T-sol-copy  SOL: dies between parts (after part 1's readback);
//   T-tab       ETH + SOL in one tab, SIGKILLed from outside once an ETH part has landed (the tab closed at a random point).
// Asserts per job: COPIES_DONE on every chain; gen 1 held by `browser`, gen 2 by `cli`; `lease-expired {gen 1}` journaled;
// gen 2's first lines reconcile every attempt open at the death before its first new intent; the CLI took over only
// after the lease lapsed; no (copy, part) twice and nothing else from the keys (read from the chain); the ETH nonce
// equals the number of parts. OWN SANDBOX. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { Chain, JournalEvent } from '../../../packages/core/src/contracts/index.ts'
import { startAnvil, startValidator, fundEth, fundSol, ethNonce, waitFor } from '../harness/chains.ts'
import { armOk, capOf, createJob, evidence, jobOf, journalOf, runCli, spawnExecutor, startStack, uploadMessage, waitReady } from '../harness/stack.ts'
import type { Crash, KeyHandle, Stack } from '../harness/stack.ts'
import { assertPublished, backupOf, keyOf, lifecycle, ms, passphrase, scratch, syntheticText } from '../harness/kit.ts'

const T = lifecycle()

test('takeover: the page executor dies mid-copy and mid-part; the CLI takes over after the lease lapses; every (copy, part) exactly once', { timeout: 900_000 }, async () => {
  const t0 = Date.now()
  const home = scratch(T)
  const [anvil, sol] = await Promise.all([startAnvil(T, { home, blockTime: 1, baseFee: 7n }), startValidator(T, { home, dir: home })])
  const s: Stack = await startStack(T, { network: 'local', ethRpc: anvil.url, solRpc: sol.url })
  const ports = { anvil: anvil.port, sol: sol.port }
  const ethText = syntheticText(120_000, 'E4 takeover: two ETH parts a copy')   // > 98,304 calldata bytes: 2 parts
  const solText = syntheticText(1_600, 'E4 takeover: two SOL parts a copy')
  const ethMsg = await uploadMessage(s, ethText)

  async function scenario(name: string, chains: Chain[], crash: Crash | 'external') {
    const keys: Partial<Record<Chain, KeyHandle>> = {}, pass = passphrase(), backups: Partial<Record<Chain, Uint8Array>> = {}
    for (const c of chains) { keys[c] = keyOf(c); backups[c] = await backupOf(keys[c]!, pass) }
    if (keys.eth) await fundEth(anvil.port, keys.eth.address, 10n ** 18n)
    if (keys.sol) await fundSol(sol.port, keys.sol.address, 100_000_000)
    const long = chains.length === 1 && chains[0] === 'eth'          // the two-chain tab carries the short text (ETH 1 part, SOL 2)
    const text = long ? ethText : solText
    const def0: Record<string, unknown> = {}
    if (keys.eth) def0.eth = { mode: { copies: 2 }, publishMode: 'eth.calldata.null', feeStrategy: 'economy', distinctCopies: true, keyAddress: keys.eth.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: null }
    if (keys.sol) def0.sol = { mode: { copies: 2 }, feeStrategy: 'economy', distinctCopies: true, keyAddress: keys.sol.address, budgetUsd: 5, maxCuPrice: 2_000_000, clawbackTo: null }
    const { id, def } = await createJob(s, { format: 'vt-job/1', network: 'local', name: `E4 takeover ${name}`, ...(long ? ethMsg : { message: text }), chains: def0 })
    const tab = spawnExecutor(s, { adapter: 'browser', jobId: id, keys: chains.map((c) => keys[c]!), ...(crash !== 'external' ? { crash } : {}) })
    T.after(() => tab.stop('SIGKILL'))
    await waitReady(s, id, chains)
    await armOk(s, id, Object.fromEntries(chains.map((c) => [c, capOf(c, c === 'eth' ? 10n ** 17n : 10n ** 9n)])))
    if (crash === 'external') {
      // the tab closes at a point it did not choose: once an ETH part has landed
      await waitFor(async () => ((await jobOf(s, id)).state.chains.eth!.txs.some((t) => t.state === 'included') ? true : null), 180_000, `${name}: an ETH part landed`, 100)
      await tab.stop('SIGKILL')
    } else {
      await waitFor(() => (tab.proc.exitCode !== null || tab.proc.signalCode !== null ? true : null), 180_000, `${name}: the tab crashed at ${crash.at} ${crash.what} #${crash.nth}`, 100)
      assert.ok(tab.lines.some((l) => l.startsWith(`crash ${crash.at} ${crash.what} #${crash.nth}`)), `${name}: the tab died at its crash point: ${tab.tail(4)}`)
    }
    const killedAt = Date.now()
    assert.ok(!tab.lines.some((l) => l.startsWith('outcome ')), `${name}: the tab died mid-job`)
    const atDeath = (await jobOf(s, id)).state
    const open = Object.fromEntries(chains.map((c) => [c, [...atDeath.chains[c]!.openIntents]]))
    const landedAtDeath = Object.fromEntries(chains.map((c) => [c, atDeath.chains[c]!.txs.filter((t) => t.state === 'included').length]))
    // the CLI, one per chain (as `vt job run` per lane), waits for the lease and takes over
    const runs = await Promise.all(chains.map((c) => runCli(s, { jobId: id, chain: c, address: keys[c]!.address, backup: backups[c]!, passphrase: pass })))
    for (const [i, c] of chains.entries()) assert.equal(runs[i].outcome, 'copies-done', `${name} ${c}: ${runs[i].out.slice(-400)}`)
    const st = (await jobOf(s, id)).state
    const lines = journalOf(s, id)
    const facts: Record<string, unknown> = {}
    for (const c of chains) {
      const cs = st.chains[c]!
      assert.equal(cs.phase, 'COPIES_DONE', `${name} ${c}`)
      assert.equal(cs.copiesIncluded, 2)
      const acq = lines.filter((e) => e.chain === c && e.type === 'lease-acquired')
      assert.deepEqual(acq.map((e) => [e.data.gen, e.data.holder]), [[1, 'browser'], [2, 'cli']], `${name} ${c}: the tab, then the CLI`)
      const gen2 = lines.indexOf(acq[1])
      // the CLI never took a live lease: the API journaled gen 1 expired (it lapsed: TTL 15 s, renewed every 5 s, so
      // ~10–15 s after the death) before granting gen 2; the CLI waited on lease.held meanwhile
      const takeoverMs = acq[1].at - killedAt
      const expiredAt = lines.findIndex((e) => e.chain === c && e.type === 'lease-expired' && e.data.gen === 1)
      assert.ok(expiredAt >= 0 && expiredAt < gen2 && takeoverMs > 0, `${name} ${c}: gen 1 lapsed and was journaled expired before gen 2 (${takeoverMs} ms after the death)`)
      const waited = /waiting: lease\.held/.test(runs[chains.indexOf(c)].out)
      // reconcile-first: every attempt open at the death is reconciled by gen 2 before gen 2's first new intent
      const firstIntent = lines.findIndex((e: JournalEvent, i) => i > gen2 && e.chain === c && e.type === 'intent' && e.gen === 2)
      for (const tx of open[c]) {
        const r = lines.findIndex((e: JournalEvent, i) => i > gen2 && e.chain === c && e.gen === 2 && e.type === 'reconcile' && e.data.txId === tx)
        assert.ok(r > gen2, `${name} ${c}: ${tx} reconciled by gen 2`)
        if (firstIntent >= 0) assert.ok(r < firstIntent, `${name} ${c}: ${tx} reconciled before any new intent`)
      }
      const p = await assertPublished('takeover', ports, def, text, st, c, { copies: 2 })
      if (c === 'eth') assert.equal(await ethNonce(anvil.port, keys.eth!.address), p.parts.length, `${name}: the key's nonce = the number of parts: nothing twice`)
      const intents = lines.filter((e) => e.chain === c && e.type === 'intent').length
      facts[c] = { parts: p.parts.length, intents, landedAtDeath: landedAtDeath[c], openAtDeath: open[c].length,
        gen2Reconciled: lines.filter((e) => e.chain === c && e.gen === 2 && e.type === 'reconcile').map((e) => String(e.data.outcome)), takeoverMs, cliWaitedOnLeaseHeld: waited }
    }
    evidence('takeover', name, { crash: crash === 'external' ? 'SIGKILL from outside after an ETH part landed' : `${crash.at} ${crash.what} #${crash.nth}`, ...facts, cliMs: runs.map((r) => r.ms) })
  }

  await Promise.all([
    scenario('T-eth-part', ['eth'], { at: 'after', what: 'send', nth: 2, chain: 'eth' }),
    scenario('T-eth-copy', ['eth'], { at: 'after', what: 'readback', nth: 1, chain: 'eth' }),
    scenario('T-sol-part', ['sol'], { at: 'after', what: 'send', nth: 2, chain: 'sol' }),
    scenario('T-sol-copy', ['sol'], { at: 'after', what: 'readback', nth: 1, chain: 'sol' }),
    scenario('T-tab', ['eth', 'sol'], 'external'),
  ])
  evidence('takeover', 'timing', { totalMs: ms(t0) })
})

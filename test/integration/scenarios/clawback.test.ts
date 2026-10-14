// E4 scenario clawback (M1): the claw-back by the REAL `vt job clawback` (on a pty, harness/stack.ts runCli) and by the page's
// executor (browser adapter, its own process through the REAL page server), within the armed cap and over it, on both
// chains, through S2's REAL API and S4's REAL relay on the harness's own chains:
//   K1 ETH within cap, page;   K2 SOL within cap, CLI;
//   K3 ETH OVER the cap, CLI:  no typed amount → refused by vt (arm.amount) before anything is signed; a typed amount
//                              off by one → refused (arm.amount); the exact amount (value + worst-case fee) typed at vt's
//                              prompt in full precision → lands (the engine re-checks it: engine.cap-clawback, K4);
//   K4 SOL OVER the cap, page: no typed amount → refused; the exact amount (clawbackConfirm) → lands.
// Every destination is FRESH (never funded). Asserts: the destination received exactly the claw-back value; the ETH lane
// is left with dust = gas × (maxFee − effective price), never more than gas × maxFee; the SOL lane holds 0 lamports;
// CLAWED_BACK, the job DONE; the copies' bytes on chain; nothing else from the keys.
// The Amsterdam fresh-destination case (204,600 gas) is UNIT-LEVEL here: this anvil (1.8.5) accepts `--hardfork
// amsterdam` but charges pre-Amsterdam gas, and the relay's fork probe pins local to pre-Amsterdam, so the engine's
// claw-back runs against a fake Amsterdam chain (amsterdamOverride, local only). OWN SANDBOX. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import type { Chain } from '../../../packages/core/src/contracts/index.ts'
import { clawbackEth } from '../../../packages/core/src/engine/lane.js'
import { CANON } from '../../../packages/core/src/chains/constants.js'
import { armedState, fakeClock, fakeEthChain, fakeRelay, recordingJournal } from '../../../packages/core/test/engine/fakes.ts'
import { startAnvil, startValidator, fundEth, fundSol, ethBalance, solBalance, ethNonce, ethTxsFrom, solTxsOf } from '../harness/chains.ts'
import type { EthOnChain, SolOnChain } from '../harness/chains.ts'
import { armOk, capOf, createJob, evidence, jobOf, journalOf, outcomesOf, runCli, spawnExecutor, startStack, waitReady } from '../harness/stack.ts'
import type { KeyHandle, Stack } from '../harness/stack.ts'
import { assertPublished, backupOf, keyOf, lifecycle, ms, passphrase, scratch, syntheticText } from '../harness/kit.ts'

const T = lifecycle()
// viem is packages/core's dependency (the workspace install is linked): resolved through it
const { parseTransaction } = await import(createRequire(new URL('../../../packages/core/package.json', import.meta.url)).resolve('viem')) as { parseTransaction(raw: `0x${string}`): { gas?: bigint; value?: bigint; maxFeePerGas?: bigint } }

test('clawback: CLI and page claw-backs within the cap and over it with the exact typed amount — destination paid, ETH lane ≤ dust, SOL lane 0', { timeout: 900_000 }, async () => {
  const t0 = Date.now()
  const home = scratch(T)
  const [anvil, sol] = await Promise.all([startAnvil(T, { home, blockTime: 1, baseFee: 7n }), startValidator(T, { home, dir: home })])
  const s = await startStack(T, { network: 'local', ethRpc: anvil.url, solRpc: sol.url })
  const ports = { anvil: anvil.port, sol: sol.port }
  const bal = (c: Chain, a: string) => (c === 'eth' ? ethBalance(anvil.port, a) : solBalance(sol.port, a))

  async function claw(name: string, chain: Chain, via: 'cli' | 'page', capKind: 'within' | 'over') {
    const key = keyOf(chain), dest = keyOf(chain).address, pass = passphrase(), backup = await backupOf(key, pass)
    if (chain === 'eth') await fundEth(anvil.port, key.address, 10n ** 16n); else await fundSol(sol.port, key.address, 100_000_000)
    const text = syntheticText(chain === 'eth' ? 500 : 1_500, `E4 clawback ${name}`)
    const chains = chain === 'eth'
      ? { eth: { mode: { copies: 1 }, publishMode: 'eth.calldata.null', feeStrategy: 'economy', distinctCopies: true, keyAddress: key.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: dest } }
      : { sol: { mode: { copies: 1 }, feeStrategy: 'economy', distinctCopies: true, keyAddress: key.address, budgetUsd: 5, maxCuPrice: 2_000_000, clawbackTo: dest } }
    const { id, def } = await createJob(s, { format: 'vt-job/1', network: 'local', name: `E4 clawback ${name}`, message: text, chains })
    // the copies run first (the claw-back is for the lane's remainder)
    const cap = capKind === 'within' ? (chain === 'eth' ? 10n ** 17n : 10n ** 9n) : (chain === 'eth' ? 10n ** 11n : 20_000n)
    if (via === 'page') {
      const p = spawnExecutor(s, { adapter: 'browser', jobId: id, keys: [key] })
      T.after(() => p.stop('SIGKILL'))
      await waitReady(s, id, [chain]); await armOk(s, id, { [chain]: capOf(chain, cap) })
      assert.deepEqual(await outcomesOf(p, [chain], 300_000), { [chain]: 'copies-done' })
    } else {
      const r = runCli(s, { jobId: id, chain, address: key.address, backup, passphrase: pass })
      await waitReady(s, id, [chain]); await armOk(s, id, { [chain]: capOf(chain, cap) })
      assert.equal((await r).outcome, 'copies-done')
    }
    const t1 = Date.now()
    const refusals: string[] = []
    const attempt = async (typed?: string): Promise<{ outcome: string | null; note: string }> => {
      if (via === 'page') {
        const p = spawnExecutor(s, { adapter: 'browser', jobId: id, keys: [key], mode: 'clawback', to: dest, ...(typed !== undefined ? { clawbackConfirm: { amount: typed } } : {}) })
        T.after(() => p.stop('SIGKILL'))
        const o = await outcomesOf(p, [chain], 300_000)
        return { outcome: o[chain], note: p.lines.find((l) => l.startsWith(`note ${chain} `))?.slice(9) ?? '' }
      }
      // the real vt asks for the amount whenever the remainder is over the cap: '' answers it with nothing typed
      const r = await runCli(s, { jobId: id, chain, address: key.address, backup, passphrase: pass, mode: 'clawback', to: dest, ...(typed !== undefined ? { typed } : capKind === 'over' ? { typed: '' } : {}) })
      return { outcome: r.outcome, note: r.note }
    }
    const before = await bal(chain, key.address)
    if (capKind === 'over') {
      // over the cap: refused before anything is signed, without the typed amount and with an inexact one
      for (const typed of [undefined, String(before - 1n)]) {
        const r = await attempt(typed)
        if (via === 'page') {
          assert.equal(r.outcome, 'failed', `${name}: ${typed === undefined ? 'no typed amount' : 'an inexact amount'} is refused`)
          assert.match(r.note, typed === undefined ? /over the armed cap.*type exactly/ : /typed claw-back amount is not exactly/)
        } else {
          // vt itself refuses an amount that is not exactly the remainder, before the engine is reached
          assert.equal(r.outcome, 'refused:arm.amount', `${name}: ${typed === undefined ? 'no typed amount' : 'an inexact amount'} is refused by vt`)
          assert.match(r.note, /typed amount is not exactly/)
        }
        assert.ok(!journalOf(s, id).some((e) => e.type === 'clawback-intent'), `${name}: nothing journaled for a refused claw-back`)
        assert.equal(await bal(chain, key.address), before, `${name}: nothing signed or sent`)
        const by = via === 'page' ? 'engine.cap-clawback' : 'vt arm.amount'
        refusals.push(typed === undefined ? `no typed amount → refused (${by})` : `balance − 1 typed → refused (${by})`)
      }
    }
    // value + worst-case fee = the lane's balance (ETH value = balance − gas × maxFee; SOL value = balance − fee)
    const ok = await attempt(capKind === 'over' ? String(before) : undefined)
    assert.equal(ok.outcome, 'clawed-back', `${name}: ${ok.note}`)
    const st = (await jobOf(s, id)).state, cs = st.chains[chain]!
    assert.equal(cs.phase, 'CLAWED_BACK')
    assert.equal(st.phase, 'DONE')
    assert.deepEqual([cs.clawback!.landed, cs.clawback!.ok], [true, true])
    const value = BigInt(cs.clawback!.value)
    assert.equal(await bal(chain, dest), value, `${name}: the fresh destination received exactly the claw-back value`)
    const left = await bal(chain, key.address)
    let dust = '0'
    if (chain === 'eth') {
      const tx = (await ethTxsFrom(anvil.port, key.address)).find((x) => x.to === dest.toLowerCase()) as EthOnChain
      const raw = await (await import('../harness/chains.ts')).rpcResult(anvil.port, 'eth_getTransactionByHash', [tx.hash])
      const gas = BigInt(raw.gas), maxFee = BigInt(raw.maxFeePerGas)
      assert.equal(tx.value, value)
      assert.equal(left, gas * maxFee - tx.fee, 'the ETH lane keeps only the unused part of gas × maxFee')
      assert.equal(left, gas * (maxFee - tx.effectiveGasPrice), 'dust = gas × (maxFee − effective price)')
      assert.ok(left <= gas * maxFee, 'ETH lane ≤ dust')
      assert.equal(gas, 21_000n, 'pre-Amsterdam claw-back gas (a fresh destination too)')
      dust = String(left)
      assert.equal(await ethNonce(anvil.port, key.address), 2, 'one copy + one claw-back from the key')
      evidence('clawback', `${name} tx`, { tx: tx.hash, block: tx.block, value, fee: tx.fee, gas, maxFee })
    } else {
      assert.equal(left, 0n, 'the SOL lane holds 0 lamports')
      const tx = (await solTxsOf(sol.port, key.address)).find((x) => x.transfer !== null) as SolOnChain
      assert.deepEqual([tx.transfer!.to, tx.transfer!.lamports], [dest, value])
      assert.equal(before, value + tx.fee, 'value + fee = the whole balance')
      evidence('clawback', `${name} tx`, { tx: tx.sig, slot: tx.slot, value, fee: tx.fee })
    }
    const pub = await assertPublished('clawback', ports, def, text, st, chain, { copies: 1 })
    assert.equal(pub.others.length, 1, `${name}: the claw-back is the key's only other tx`)
    evidence('clawback', name, { chain, via, cap: capKind, capNative: cap, laneBefore: before, value, laneAfter: left, dust, refusals, clawMs: ms(t1) })
  }

  await Promise.all([claw('K1 eth within page', 'eth', 'page', 'within'), claw('K2 sol within cli', 'sol', 'cli', 'within'),
    claw('K3 eth over cli', 'eth', 'cli', 'over'), claw('K4 sol over page', 'sol', 'page', 'over')])
  evidence('clawback', 'timing', { totalMs: ms(t0) })
})

// Unit-level (no chain): the Amsterdam fresh destination. Runs after the scenario above: the fake relay replaces the
// process-wide relay client (engine/rpc.js), and nothing else runs in this process by then.
test('clawback, unit-level: an Amsterdam fresh destination costs 204,600 gas; over the cap it needs the exact typed amount (= the balance)', { timeout: 60_000 }, async () => {
  const DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
  const run = async (o: { amsterdam: boolean; cap: bigint; confirm?: string }) => {
    const chain = fakeEthChain({ balance: 10n ** 16n, baseFee: 1_000_000_000n, mine: true })
    const sends: string[] = []
    fakeRelay({ eth: (m, p) => {
      if (m === 'eth_getCode') return '0x'
      if ((m === 'eth_getTransactionCount' || m === 'eth_getBalance') && String(p[0]).toLowerCase() === DEST.toLowerCase()) return '0x0'   // fresh: nonce 0, balance 0, no code
      if (m === 'eth_estimateGas') return `0x${(o.amsterdam ? CANON.ETH_CLAW_GAS_EMPTY_AMSTERDAM : CANON.ETH_CLAW_GAS_EXISTING).toString(16)}`
      if (m === 'eth_sendRawTransaction') sends.push(String(p[0]))
      return chain.handler(m, p)
    } })
    const { journal, events } = recordingJournal()
    const key = { account: keyOf('eth').account }
    const r = await clawbackEth(key, DEST, { journal, network: 'local', chainId: 31337, poll: 1, feeStrategy: 'economy', amsterdamOverride: o.amsterdam, clock: fakeClock(), state: armedState('eth', o.cap),
      ...(o.confirm !== undefined ? { clawbackConfirm: { amount: o.confirm } } : {}) }).then((x: unknown) => x, (e: { guardId?: string; message?: string }) => ({ refused: e.guardId ?? e.message }))
    return { r: r as Record<string, unknown>, sends, events }
  }
  // within the cap: 204,600 gas, value = balance − 204,600 × maxFee, the intent declares that gas
  const a = await run({ amsterdam: true, cap: 10n ** 18n })
  assert.equal(a.r.ok, true, JSON.stringify(a.r, (_k, v) => (typeof v === 'bigint' ? String(v) : v)))
  const tx = parseTransaction(a.sends[0] as `0x${string}`)
  assert.equal(tx.gas, 204_600n)
  assert.equal(tx.value! + 204_600n * tx.maxFeePerGas!, 10n ** 16n, 'value + gas × maxFee = the balance')
  assert.equal((a.events.find((e) => e.type === 'clawback-intent')!.eth as { gas: string }).gas, '204600')
  // the control: pre-Amsterdam, the same fresh destination is 21,000
  const pre = await run({ amsterdam: false, cap: 10n ** 18n })
  assert.equal(parseTransaction(pre.sends[0] as `0x${string}`).gas, 21_000n)
  // over the cap: refused without the typed amount (nothing sent), with an inexact one; the exact one (the balance) lands
  const none = await run({ amsterdam: true, cap: 10n ** 12n })
  assert.deepEqual([none.r.refused, none.sends.length], ['engine.cap-clawback', 0])
  const off = await run({ amsterdam: true, cap: 10n ** 12n, confirm: String(10n ** 16n - 1n) })
  assert.deepEqual([off.r.refused, off.sends.length], ['engine.cap-clawback', 0])
  const exact = await run({ amsterdam: true, cap: 10n ** 12n, confirm: String(10n ** 16n) })
  assert.equal(exact.r.ok, true)
  assert.equal(parseTransaction(exact.sends[0] as `0x${string}`).gas, 204_600n)
  evidence('clawback', 'amsterdam unit-level', { freshDestinationGas: 204_600, preAmsterdamGas: 21_000, overCap: 'none → engine.cap-clawback; balance−1 → engine.cap-clawback; balance → signed' })
})

// The P2 delta (R71/R72, prototype tag add7b-e540f8ae4d6b, diff against add7-00927d6ade7f) that lane E owns: the
// per-network table (labels, Tor and price policy, measured tip floors, testnet funding), testnet explorer links, price
// without a browser-relative URL, and the claw-back at the lane's fee strategy (G1). ALL DATA IS SYNTHETIC; relays are
// fake fetch functions.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Keypair } from '@solana/web3.js'
import { parseTransaction } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { NETWORK, TEST_FUNDS_LABEL, networkOf } from '../../src/chains/constants.js'
import { ethLinks, solLinks } from '../../src/chains/links.js'
import { fetchPrice, isTestFunds, priceStatus } from '../../src/chains/price.js'
import { computeArmCaps } from '../../src/engine/arm-caps.js'
import { solCuLimit, solFee } from '../../src/chains/plan.js'
import { solPriceForLamports } from '../../src/chains/sol.js'
import { clawbackEth, clawbackSol } from '../../src/engine/lane.js'
import { armedState, fakeClock, fakeEthChain, fakeRelay, fakeSolChain, recordingJournal } from './fakes.ts'

const H = '0x' + 'ab'.repeat(32), S = '5'.repeat(88), A = '0x1111111111111111111111111111111111111111', P = 'Pay1111111111111111111111111111111111111111'
const NULL = '0x0000000000000000000000000000000000000000', DEST = '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6'
const GWEI = 10n ** 9n

test('the network table: Tor on testnet and mainnet, test funds have no price, measured tip floors, testnet funding steps', () => {
  assert.deepEqual(Object.keys(NETWORK), ['local', 'testnet', 'mainnet'])
  assert.deepEqual([NETWORK.local.tor, NETWORK.testnet.tor, NETWORK.mainnet.tor], [false, true, true])
  assert.equal(NETWORK.testnet.price.kind, 'none'); assert.equal(NETWORK.testnet.price.note, TEST_FUNDS_LABEL); assert.equal(TEST_FUNDS_LABEL, 'TEST FUNDS — NO VALUE')
  assert.equal(NETWORK.mainnet.price.kind, 'jupiter')
  assert.deepEqual([NETWORK.local.eth.tipFloor, NETWORK.testnet.eth.tipFloor, NETWORK.mainnet.eth.tipFloor], [12000n, 1000000n, 12000n])
  assert.equal(NETWORK.testnet.sol.airdrop?.maxLamports, 10n ** 9n); assert.equal(NETWORK.mainnet.sol.airdrop, null)
  assert.ok((NETWORK.testnet.eth as { faucets?: unknown[] }).faucets!.length >= 1)
  assert.throws(() => networkOf('devnet'), /unknown network/); assert.throws(() => networkOf('__proto__'), /unknown network/)
  assert.equal(JSON.stringify(NETWORK, (_k, v) => (typeof v === 'bigint' ? String(v) : v)).includes('rpc'), false, 'no RPC endpoint here (broadcast/endpoints.json is the one source)')
})

test('testnet explorer links: Sepolia Etherscan (+ Null Address page), devnet Explorer / Solscan / SolanaFM — all copy-only; an unknown network is refused', () => {
  const e = ethLinks('testnet', H, A, NULL)
  assert.deepEqual(e.map((x) => x.url), [`https://sepolia.etherscan.io/tx/${H}`, `https://sepolia.etherscan.io/address/${NULL}`, `https://sepolia.etherscan.io/address/${A}`])
  assert.ok(e.every((x) => x.open === false)); assert.match(e[1].note!, /busy page/)
  assert.equal(ethLinks('testnet', H, A, A).length, 2)
  const s = solLinks('testnet', S, P)
  assert.deepEqual(s.map((x) => x.url), [`https://explorer.solana.com/tx/${S}?cluster=devnet`, `https://solscan.io/tx/${S}?cluster=devnet`, `https://solana.fm/tx/${S}?cluster=devnet-solana`, `https://explorer.solana.com/address/${P}?cluster=devnet`])
  assert.ok(s.every((x) => x.open === false))
  assert.deepEqual(solLinks('mainnet', S, P).map((x) => x.url), [`https://explorer.solana.com/tx/${S}`, `https://solscan.io/tx/${S}`, `https://solana.fm/tx/${S}`, `https://explorer.solana.com/address/${P}`])
  for (const bad of ['devnet', 'MAINNET', '']) { assert.throws(() => ethLinks(bad, H, A, NULL), RangeError); assert.throws(() => solLinks(bad, S, P), RangeError) }
})

test('price: an injected { base, fetch } (no browser-relative URL); the testnet fixture labelled TEST FUNDS is never a price', async () => {
  await assert.rejects(fetchPrice(undefined as never), /inject/)
  const urls: string[] = []
  const answer = (body: unknown) => async (url: string) => { urls.push(url); return new Response(JSON.stringify(body), { status: 200 }) }
  const live = { source: 'jupiter', fixture: false, fetchedAt: 1_000_000, prices: { SOL: { usd: 150, mint: 'So1' }, ETH: { usd: 3000, mint: '7vf' } } }
  assert.deepEqual(await fetchPrice({ base: 'http://127.0.0.1:5201', fetch: answer(live) as never }), live)
  assert.deepEqual(urls, ['http://127.0.0.1:5201/relay/price'])
  assert.equal(priceStatus(live, 1_000_500).ok, true)
  const testFunds = { ...live, fixture: true, source: TEST_FUNDS_LABEL }
  const st = priceStatus(await fetchPrice({ base: '', fetch: answer(testFunds) as never }), 1_000_500)
  assert.deepEqual([st.ok, st.none], [false, true]); assert.match(st.why!, /TEST FUNDS — NO VALUE/)
  assert.equal(isTestFunds({ none: true, source: 'test funds — no value' }), true)
  assert.equal(isTestFunds({ ...live, fixture: true, source: 'LOCAL FIXTURE PRICE (--price-fixture)' }), false, 'the local fixture is a (fake) price')
  // the arm caps fall back to the R60 native cap (usd 0) on test funds
  const caps = computeArmCaps({ format: 'vt-job/1', network: 'testnet', name: 'x', messageSha256: 'a'.repeat(64), messageBytes: 2, chains: { sol: { mode: { copies: 1 }, publishMode: 'sol.memo', feeStrategy: 'passive', distinctCopies: true, keyAddress: P, budgetUsd: 5, clawbackTo: null } } } as never, 'hi',
    { prices: testFunds, now: 1_000_500, balances: { sol: 10n ** 9n }, fees: { sol: { rent: 890_880n, priorityLamports: 0 } }, network: 'testnet' })
  const sol = (caps as Record<string, { usd: number; priceAt: number | null; nativeCap: string }>).sol
  assert.deepEqual([sol.usd, sol.priceAt, sol.nativeCap], [0, null, '70000000'], 'the R60 native fallback (0.07 SOL), no USD')
})

test('static: no browser-relative relay URL left in packages/core/src (the caller injects base + fetch)', () => {
  const root = fileURLToPath(new URL('../../src/', import.meta.url))
  const walk = (d: string): string[] => readdirSync(d).flatMap((f) => { const p = join(d, f); return statSync(p).isDirectory() ? walk(p) : [p] })
  for (const f of walk(root).filter((p) => /\.(?:js|ts)$/.test(p))) {
    const src = readFileSync(f, 'utf8').split('\n').filter((l) => !l.trim().startsWith('//')).join('\n')
    assert.ok(!/fetch\(\s*['"`]\/relay/.test(src), `${f}: a relative /relay fetch`)
  }
})

// ---- G1: the claw-back at the lane's fee strategy ----
function ethClaw(o: { next: () => bigint; mine?: () => boolean }) {
  const chain = fakeEthChain({ balance: 10n ** 16n, next: o.next, mine: true })
  const sends: string[] = []
  let drops = 0
  const relay = fakeRelay({ eth: (m, p) => {
    if (m === 'eth_getCode') return '0x'
    if (m === 'eth_getTransactionCount' && String(p[0]).toLowerCase() === DEST.toLowerCase()) return '0x3'
    if (m === 'eth_getBalance' && String(p[0]).toLowerCase() === DEST.toLowerCase()) return '0x5'
    if (m === 'eth_estimateGas') return '0x5208'
    if (m === 'eth_sendRawTransaction') { sends.push(String(p[0])); if (o.mine && !o.mine()) { drops++; return chain.hx(0) && `0x${'0'.repeat(64)}` } }
    if (m === 'eth_getTransactionByHash' && o.mine && !o.mine() && !chain.mined.has(String(p[0]))) return null
    return chain.handler(m, p)
  } })
  return { chain, relay, sends, drops: () => drops }
}

test('G1 ETH passive claw-back: nothing is signed while the next base fee is above T; then maxFee = T + 0.001 gwei; never a bump', { timeout: 30_000 }, async () => {
  let reads = 0
  const c = ethClaw({ next: () => (++reads < 4 ? 3n * GWEI : 1n * GWEI) })          // T = p10 of the window = 1 gwei
  const { journal, events } = recordingJournal()
  const key = { account: privateKeyToAccount(generatePrivateKey()) }
  const r = await clawbackEth(key, DEST, { journal, network: 'local', chainId: 31337, poll: 1, passiveWaitMs: 1, feeStrategy: 'passive', clock: fakeClock(), state: armedState('eth', 10n ** 18n) })
  assert.equal(r.ok, true)
  const intents = events.filter((e) => e.type === 'clawback-intent')
  assert.equal(intents.length, 1, 'passive never escalates')
  const ethI = intents[0].eth as Record<string, string>
  assert.deepEqual([ethI.tip, ethI.maxFee], ['1000000', String(GWEI + 1_000_000n)])
  assert.ok(events.findIndex((e) => e.type === 'note') < events.findIndex((e) => e.type === 'clawback-intent'), 'the wait is journaled before anything is signed')
  const tx = parseTransaction(c.sends[0] as `0x${string}`)
  assert.equal(tx.value! + 21_000n * tx.maxFeePerGas!, 10n ** 16n, 'value + gas × maxFee = the whole balance')
})

test('G1 ETH economy claw-back: the tip starts at the network floor (Sepolia 0.001 gwei, local 12,000 wei); prompt keeps the p50 tip', { timeout: 30_000 }, async () => {
  for (const [strategy, network, tip] of [['economy', 'local', 12_000n], ['economy', 'testnet', 1_000_000n], ['prompt', 'local', GWEI]] as const) {
    const c = ethClaw({ next: () => 1n * GWEI })
    const chain = c.chain
    c.chain.setBase(GWEI)
    const relay2 = fakeRelay({ eth: (m, p) => {
      if (m === 'eth_feeHistory') { const r = chain.handler(m, p) as { reward: string[][] }; r.reward = r.reward.map(() => ['0x0', '0x0']); return strategy === 'prompt' ? chain.handler(m, p) : r }
      if (m === 'eth_getCode') return '0x'
      if (m === 'eth_estimateGas') return '0x5208'
      return chain.handler(m, p)
    } })
    void relay2
    const { journal, events } = recordingJournal()
    const key = { account: privateKeyToAccount(generatePrivateKey()) }
    const r = await clawbackEth(key, DEST, { journal, network, chainId: network === 'testnet' ? 11155111 : 31337, poll: 1, feeStrategy: strategy, amsterdamOverride: undefined, state: armedState('eth', 10n ** 18n) })
    assert.equal(r.ok, true, `${strategy} ${network}`)
    const e = events.find((x) => x.type === 'clawback-intent')!.eth as Record<string, string>
    assert.equal(BigInt(e.tip), tip, `${strategy} on ${network}: tip ${e.tip}`)
  }
})

const PROMPT_CU = solCuLimit(10_000), PROMPT_FEE = solFee(1, PROMPT_CU, solPriceForLamports(12_500, PROMPT_CU, 2_000_000))
test('G1 SOL claw-back: prompt adds a priority (SetComputeUnitPrice) and pays more than 5,000; passive and economy are a plain 5,000-lamport transfer', { timeout: 30_000 }, async () => {
  for (const strategy of ['passive', 'economy', 'prompt'] as const) {
    const base = fakeSolChain()
    const relay = fakeRelay({ sol: (m, p) => {
      if (m === 'getFeeForMessage') return { context: { slot: 500 }, value: Number(PROMPT_FEE) * (strategy === 'prompt' ? 1 : 0) + (strategy === 'prompt' ? 0 : 5000) }
      if (m === 'getTransaction') { const t = base.handler(m, p) as Record<string, any> | null; if (!t) return null; const keys = t.transaction.message.accountKeys; return { ...t, meta: { ...t.meta, preBalances: keys.map(() => 1_000), postBalances: keys.map((_k: string, i: number) => (i === 1 ? 1_000 + 10 ** 9 - 5000 : 1_000)) } } }
      return base.handler(m, p)
    } })
    void relay
    const { journal, events } = recordingJournal()
    const kp = Keypair.generate(), dest = Keypair.generate().publicKey.toBase58()
    await clawbackSol({ chain: 'sol', kp }, dest, { journal, network: 'local', poll: 1, feeStrategy: strategy, clock: fakeClock(), state: armedState('sol', 10n ** 12n) }).catch(() => null)
    const i = events.find((x) => x.type === 'clawback-intent')
    assert.ok(i, strategy)
    const sol = i!.sol as Record<string, unknown>
    if (strategy === 'prompt') { assert.ok((sol.cuPrice as number) > 0, 'a priority price'); assert.equal(sol.fee, String(PROMPT_FEE)); assert.ok(PROMPT_FEE > 5000n) }
    else { assert.deepEqual([sol.cuPrice, sol.fee], [0, '5000'], strategy) }
  }
})

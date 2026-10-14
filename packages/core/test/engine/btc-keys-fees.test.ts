// E7b: the btc lane's job-layer pieces — startingFees / computeArmCaps for btc, the fee-rate cap, and the btc key backup (the same age
// backup form as eth / sol: { chain, address, secret, network }). ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { startingFees } from '../../src/engine/assess.js'
import { computeArmCaps } from '../../src/engine/arm-caps.js'
import { cappedFeeRate, copyCost, btcFromSecret, planCommit, buildCommit, buildReveal } from '../../src/chains/btc.js'
import { newKey, fromSecret, encryptKey, decryptKeyFile, openBackup, keyFileName } from '../../src/engine/keys.js'
import { loadBackup } from '../../src/gates/backup.ts'
import { validateLaneConfig, planLaneCopy } from '../../src/engine/lane.js'
import { revealVsizeBound, commitVsizeBound } from '../../src/chains/btc-ord.ts'
import { normalizeJob } from '../../src/job/index.ts'
import { fakeBtcChain } from './btc-fakes.ts'

const guardAsync = async (p: Promise<unknown>): Promise<string | null> => { try { await p } catch (e) { const g = (e as { guardId?: string }).guardId; if (g) return g; throw e } return null }
const SECRET = '55'.repeat(32)

test('the fee rate is the node\'s estimate clamped to maxFeeRateSatVb (and to 500); no estimate = 2 sat/vB', async () => {
  const chain = fakeBtcChain()
  assert.equal(await cappedFeeRate(undefined), 2n)
  assert.equal(await cappedFeeRate(1), 1n)
  assert.equal(await cappedFeeRate(500), 2n)
  void chain
  // an estimate above the cap is clamped to it
  const { configureRelay } = await import('../../src/engine/rpc.js')
  configureRelay({ base: 'http://relay.test', fetch: async () => new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { feerate: 0.0004 } }), { status: 200 }) })   // 40 sat/vB
  assert.equal(await cappedFeeRate(undefined), 40n)
  assert.equal(await cappedFeeRate(25), 25n)
  assert.equal(await cappedFeeRate(100), 40n)
})

test('startingFees(local, btc): the fee rate (capped), the worst-case commit + reveal fees, the postage and perCopy', async () => {
  fakeBtcChain()
  const parts = [{ payload: new TextEncoder().encode('hello'), i: 1 }]
  const r = await startingFees('local', 'btc', 'economy', { parts, maxFeeRateSatVb: 7 })
  assert.equal(r.chain, 'btc')
  assert.equal(r.fees.rate, 2n)                                         // the fake node has no estimate: 2 sat/vB, under the cap 7
  // E7b m-1: the quote is a TRUE worst case at the CEILING (the cap 7), 8 inputs, plus the largest change-less leftover (545 sat)
  assert.deepEqual([r.fees.commitFee, r.fees.revealFee, r.fees.postage], [commitVsizeBound(8) * 7n + 545n, revealVsizeBound(5) * 7n, 546n])
  assert.equal(r.perCopy, r.fees.commitFee + r.fees.revealFee + 546n)
  assert.equal(r.perCopy, copyCost(5, 7n).perCopy)
  assert.equal((await startingFees('local', 'btc', 'economy', { parts })).fees.commitFee, commitVsizeBound(8) * 500n + 545n, 'no job cap: the tickets\' 500 sat/vB')
  const capped = await startingFees('local', 'btc', 'economy', { parts, maxFeeRateSatVb: 1 })
  assert.equal(capped.fees.rate, 1n)
  assert.equal(capped.perCopy, copyCost(5, 1n).perCopy)
  assert.ok(capped.perCopy! < r.perCopy!)
  assert.equal((await startingFees('local', 'btc', 'economy', {})).perCopy, null, 'no parts, no perCopy')
  const alt = await startingFees('local', 'btc', 'economy', { parts, altParts: [{ payload: new Uint8Array(500) }] })
  assert.ok(alt.perCopy! > r.perCopy!, 'the costliest copy variant counts')
})

test('computeArmCaps prices a btc chain in sats (no BTC price): cap = the native fallback or the planned spend', () => {
  const { def } = normalizeJob({ format: 'vt-job/1', network: 'local', name: 'btc caps', message: 'hello', chains: { btc: { mode: { copies: 2 }, distinctCopies: true, keyAddress: btcFromSecret(SECRET, 'local').address, budgetUsd: 5, clawbackTo: null, maxFeeRateSatVb: 100 } } }, { network: 'local' })
  const fees = { rate: 2n }                                              // today's estimate: the quote ignores it (the ceiling, here the job's maxFeeRateSatVb 100, prices the copy)
  const caps = computeArmCaps(def, 'hello', { prices: { fixture: true, source: 'x', fetchedAt: 0, prices: { SOL: { usd: 150 }, ETH: { usd: 3000 } } }, fees: { btc: fees }, balances: { btc: 5_000_000n }, network: 'local', now: 1 })
  const full = BigInt(caps.btc.fullCopyCost)
  assert.ok(full > 0n && full <= copyCost(5, 100n).perCopy + 5_000n && full > copyCost(5, 2n).perCopy)         // the marker-free body of 5 bytes plus the copy variants
  assert.deepEqual([caps.btc.parts, caps.btc.usd, caps.btc.priceAt, caps.btc.affordable, caps.btc.overCap], [2, 0, null, true, false])
  const planned = 2n * full
  assert.equal(caps.btc.nativeCap, '1000000')                               // the native fallback cap (0.01 BTC): the planned spend is far below it
  assert.equal(caps.btc.planned, (Number(planned) / 1e8).toFixed(8).replace(/0+$/, '').replace(/\.$/, ''))
})

const PRICES = { fixture: true, source: 'x', fetchedAt: 0, prices: { SOL: { usd: 150 }, ETH: { usd: 3000 } } }
const btcJob = (copies: number, over: Record<string, unknown> = {}, message = 'hello', existing = false) => normalizeJob({ format: 'vt-job/1', network: 'local', name: 'btc caps', message, chains: { btc: { mode: { copies }, distinctCopies: true, keyAddress: btcFromSecret(SECRET, 'local').address, budgetUsd: 5, clawbackTo: null, ...over } } }, { network: 'local', existing }).def
const armBtc = (def: ReturnType<typeof btcJob>, text: string, balance = 50_000_000n) => computeArmCaps(def, text, { prices: PRICES, fees: { btc: { rate: 2n } }, balances: { btc: balance }, network: 'local', now: 1 }).btc

test('Eminors fix 1 (E7b m-1): fullCopyCost is EXACTLY the worst case at the ceiling for the widest body (the last copy marker); an old job without the field quotes at 500', () => {
  const text = 'hello'
  for (const [ceiling, copies] of [[25, 3], [100, 2], [1, 12]] as const) {
    const cap = armBtc(btcJob(copies, { maxFeeRateSatVb: ceiling }, text), text)
    const sha = createHash('sha256').update(text).digest('hex')
    const widest = Math.max(...[1, copies].map((c) => planLaneCopy(validateLaneConfig({ chain: 'btc', mode: 'copies', copies, text, distinct: true }).cfg, c)[0].payload.length))
    void sha
    assert.equal(cap.fullCopyCost, String(copyCost(widest, BigInt(ceiling)).perCopy), `ceiling ${ceiling}, ${copies} copies`)
    assert.equal(cap.ceilingSatVb, ceiling); assert.equal(cap.ceilingFromJob, true)
  }
  const old = btcJob(1, {}, 'hello', true)                                // an existing record: no maxFeeRateSatVb
  assert.equal('maxFeeRateSatVb' in old.chains.btc!, false)
  const cap = armBtc(old, 'hello')
  assert.equal(cap.fullCopyCost, String(copyCost(planLaneCopy(validateLaneConfig({ chain: 'btc', mode: 'copies', copies: 1, text: 'hello', distinct: true }).cfg, 1)[0].payload.length, 500n).perCopy))
  assert.deepEqual([cap.ceilingSatVb, cap.ceilingFromJob], [500, false])
  // reverting to today's estimate would put the quote at copyCost(.., 2n): far below
  assert.ok(BigInt(cap.fullCopyCost) > 100n * copyCost(5, 2n).perCopy / 2n)
})

test('Eminors fix 1: over-cap is reachable for btc (N = 2): planned = N x the worst case, nativeCap = planned, overCap true; why a copy is not affordable is named', () => {
  const text = 'hello', def = btcJob(2, { maxFeeRateSatVb: 500 }, text)
  const cap = armBtc(def, text)
  const full = BigInt(cap.fullCopyCost)
  assert.ok(full > 400_000n, 'a 500 sat/vB ceiling: one copy alone is over half the 0.01 BTC fallback')
  assert.equal(cap.overCap, true)
  assert.equal(cap.nativeCap, String(2n * full), 'the armed cap is N x the worst case, never clipped below it')
  assert.equal(cap.planned, (Number(2n * full) / 1e8).toFixed(8).replace(/0+$/, '').replace(/\.$/, ''))
  assert.equal(cap.affordable, true); assert.equal(cap.capVia, 'typed')
  const under = armBtc(btcJob(2, { maxFeeRateSatVb: 25 }, text), text)
  assert.deepEqual([under.overCap, under.nativeCap, under.capVia], [false, '1000000', 'fallback'])
  const poor = armBtc(def, text, 1000n)
  assert.deepEqual([poor.affordable, poor.notAffordableBecause], [false, 'balance'])
})

test('the lane config carries maxFeeRateSatVb: a btc integer 1..500 only', () => {
  assert.equal(validateLaneConfig({ chain: 'btc', mode: 'copies', copies: 1, text: 'x', maxFeeRateSatVb: 25 }).ok, true)
  for (const bad of [0, 501, 1.5, '3']) assert.equal(validateLaneConfig({ chain: 'btc', mode: 'copies', copies: 1, text: 'x', maxFeeRateSatVb: bad }).ok, false, String(bad))
  assert.equal(validateLaneConfig({ chain: 'eth', mode: 'copies', copies: 1, text: 'x', maxFeeRateSatVb: 5 }).ok, false)
  assert.equal(planLaneCopy(validateLaneConfig({ chain: 'btc', mode: 'copies', copies: 1, text: 'x' }).cfg, 1).length, 2)
})

test('the btc key backup is the eth / sol form: { chain, address (bech32 p2wpkh), secret hex, network }; written and read by the key helpers', async () => {
  const k = newKey('btc', 'local')
  assert.equal(k.chain, 'btc')
  assert.match(k.address, /^bcrt1q[02-9ac-hj-np-z]{38}$/)
  assert.equal(Object.keys(k).includes('secret'), false, 'the secret is not enumerable')
  assert.match(JSON.stringify(k), /^((?!secret).)*$/)
  assert.throws(() => newKey('btc'), /needs its network/)
  assert.throws(() => fromSecret('btc', SECRET), /needs its network/)
  assert.equal(fromSecret('btc', SECRET, 'local').address, btcFromSecret(SECRET, 'local').address)
  assert.notEqual(fromSecret('btc', SECRET, 'testnet').address, fromSecret('btc', SECRET, 'local').address)
  const key = fromSecret('btc', SECRET, 'local')
  const pass = 'correct horse battery staple plum'
  const { ct } = await encryptKey(key, pass, 'local')
  const plain = await openBackup(ct, pass)
  assert.deepEqual(Object.keys(plain), ['chain', 'address', 'secret', 'createdAt', 'network'])
  assert.deepEqual([plain.chain, plain.address, plain.secret, plain.network], ['btc', key.address, SECRET, 'local'])
  assert.match(keyFileName(key), /^vt-btc-key-/)
  const back = await decryptKeyFile(ct, pass, 'btc')
  assert.equal(back.key.address, key.address)
  assert.equal(back.network, 'local')
  await assert.rejects(encryptKey(key, pass, 'testnet'), /records the network/)
  // gates/backup.ts loadBackup (what `vt job run` and the page use)
  const got = await loadBackup(ct, pass, 'btc', { address: key.address, network: 'local' })
  assert.equal(got.key.address, key.address)
  assert.equal(got.warnNetwork, false)
  assert.equal(got.network, 'local')
  assert.equal((await loadBackup(ct, pass, 'btc', { address: key.address, network: 'testnet' })).warnNetwork, true)
  assert.equal(await guardAsync(loadBackup(ct, pass, 'btc', { address: newKey('btc', 'local').address, network: 'local' })), 'backup.address-mismatch')
  assert.equal(await guardAsync(loadBackup(ct, pass, 'eth', { address: key.address, network: 'local' })), 'backup.chain')
  assert.equal(await guardAsync(loadBackup(ct, 'wrong passphrase wrong passphrase', 'btc', { address: key.address, network: 'local' })), 'backup.decrypt')
  // a tampered pair (the address of another key) and a backup with no network are not btc keys
  const bad = async (o: Record<string, unknown>) => {
    const { Encrypter } = await import('age-encryption')
    const e = new Encrypter(); e.setPassphrase(pass)
    return e.encrypt(JSON.stringify({ chain: 'btc', address: key.address, secret: SECRET, createdAt: 'x', ...o }))
  }
  assert.equal(await guardAsync(loadBackup(await bad({ address: newKey('btc', 'local').address }), pass, 'btc', { address: key.address, network: 'local' })), 'backup.inconsistent')
  assert.equal(await guardAsync(loadBackup(await bad({ network: undefined }), pass, 'btc', { address: key.address, network: 'local' })), 'backup.inconsistent')
})

// E7b m-1: property — whatever the engine can actually spend for a copy (the commit's PAID fee, which includes a sub-dust leftover, plus the value the
// commit locks) is <= the quote at the ceiling it was priced at, for every body size, rate and input count the engine can reach; and the vsize bounds hold.
test('E7b m-1 property: actual per-copy spend <= copyCost at the ceiling, over body sizes, rates, input counts and leftovers; the vsize bounds hold', () => {
  const key = btcFromSecret(SECRET, 'local')
  let checked = 0, nMax = 0
  for (const len of [0, 5, 100, 520, 521, 2000]) {
    const body = new Uint8Array(len).map((_, i) => (i * 31 + 7) & 0xff)
    for (const rate of [1n, 7n, 500n]) {
      const reveal = buildReveal({ key, body, commitTxid: '00'.repeat(32), commitVout: 0, amount: 10_000_000n })
      assert.ok(BigInt(reveal.vsize) <= revealVsizeBound(len), `reveal vsize ${reveal.vsize} <= bound (body ${len})`)
      const value = 546n + BigInt(reveal.vsize) * rate
      for (const n of [1, 2, 3, 5, 8]) {
        const need = value + BigInt(buildCommit({ key, body, inputs: Array.from({ length: n }, (_, k) => ({ txid: `${k + 1}`.padStart(64, '0'), index: 0, amount: 1_000_000_000n })), value, fee: 1n }).vsize) * rate
        for (const extra of [0n, 100n, 545n, 546n, 5_000n]) {
          const amt = (need + BigInt(n) - 1n) / BigInt(n) + extra
          const utxos = Array.from({ length: n }, (_, k) => ({ txid: `${k + 1}`.padStart(64, '0'), index: 0, amount: amt }))
          let p
          try { p = planCommit(key, body, utxos, rate) } catch { continue }          // the ticket caps may refuse (500 sat/vB with a leftover): nothing is spent
          if (p.inputs === null) continue
          const built = buildCommit({ key, body, inputs: p.inputs, value: p.value, fee: p.fee })
          assert.ok(BigInt(built.vsize) <= commitVsizeBound(p.inputs.length), `commit vsize ${built.vsize} <= bound for ${p.inputs.length} inputs`)
          const spent = BigInt(built.fee) + p.value
          assert.ok(spent <= copyCost(len, rate).perCopy, `spend ${spent} <= quote ${copyCost(len, rate).perCopy} (body ${len}, rate ${rate}, ${p.inputs.length} inputs, extra ${extra})`)
          assert.ok(spent <= copyCost(len, 500n).perCopy, 'and under the default ceiling')
          nMax = Math.max(nMax, p.inputs.length); checked++
        }
      }
    }
  }
  assert.ok(checked > 100 && nMax >= 5, `${checked} cases, up to ${nMax} inputs`)
})

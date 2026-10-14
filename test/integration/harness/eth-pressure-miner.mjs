#!/usr/bin/env node
// PORTED (E4) from the prototype, tag add7b-e540f8ae4d6b, test/eth-pressure-miner.mjs
// (sha256 ceba6ed157992371b7078a055377bc354e3ec7a8bafcd24a51497e19e8ff4fc4). Byte-for-byte below this block: no change.
// The E4 harness (chains.ts startEthPressure) starts it under a loopback-only sandbox against the harness's OWN anvil
// (--no-mining, an ephemeral port; never the shared :8545, which it refuses itself), and drives T through --control.
// R64 TEST HARNESS (local only): inclusion pressure on YOUR OWN anvil (never the shared :8545). Start anvil with mining off:
//   anvil --port 8645 --chain-id 31337 --no-mining --silent
// then:  node test/eth-pressure-miner.mjs --rpc http://127.0.0.1:8645 --every 1500 --schedule "0:0,40:30000,110:0"
// Every --every ms: drop every pending tx whose tip (maxPriorityFeePerGas) < T (anvil_dropTransaction), then mine one block.
// --schedule "sec:T,…" steps the threshold T (wei) over time (here: none, then 30,000 wei from 40 s, then none from 110 s).
// --control <port> (optional): POST {"T": wei} to http://127.0.0.1:<port> overrides the schedule ({"T": null} releases it);
//   {"base": wei} re-pins the base fee ({"base": null} back to --base-fee).
// --base-fee <wei> (optional): pin every mined block's base fee (anvil_setNextBlockBaseFeePerGas) at a mainnet-like level.
const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : d }
const RPC = arg('rpc', 'http://127.0.0.1:8645'), EVERY = Number(arg('every', '1500')), BASE_FEE = arg('base-fee', null)
let baseFee = BASE_FEE
const SCHED = arg('schedule', '0:0').split(',').map((x) => x.split(':').map(Number)).sort((a, b) => a[0] - b[0])
if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(RPC) || RPC.endsWith(':8545')) { console.error('refusing: use your own anvil on 127.0.0.1 (not the shared :8545)'); process.exit(2) }
const rpc = async (method, params = []) => { const r = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }); const j = await r.json(); if (j.error) throw new Error(`${method}: ${j.error.message}`); return j.result }
if ((await rpc('eth_chainId')) !== '0x7a69') { console.error('refusing: not a chain-id 31337 anvil'); process.exit(2) }
await rpc('evm_setAutomine', [false]).catch(() => {})
const t0 = Date.now(); let override = null
const T = () => { if (override != null) return BigInt(override); let v = 0; for (const [s, x] of SCHED) if ((Date.now() - t0) / 1000 >= s) v = x; return BigInt(v) }
// optional loopback control port (tests): POST {"T": <wei>|null} overrides / releases the schedule
const CONTROL = arg('control', null)
if (CONTROL) { const http = await import('node:http'); http.createServer((q, r) => { let b = ''; q.on('data', (c) => (b += c)); q.on('end', () => { try { const j = JSON.parse(b || '{}'); if ('T' in j) override = j.T ?? null; if ('base' in j) baseFee = j.base == null ? BASE_FEE : String(j.base) } catch {} r.end(JSON.stringify({ T: String(T()), base: baseFee })) }) }).listen(Number(CONTROL), '127.0.0.1') }
console.log(`eth pressure miner on ${RPC}: every ${EVERY} ms, schedule ${SCHED.map(([s, x]) => `${s}s→${x}`).join(', ')}${BASE_FEE ? `, base fee pinned at ${BASE_FEE} wei` : ''}`)
let lastT = -1n
for (;;) {
  try {
    const thr = T(); if (thr !== lastT) { console.log(`t=${((Date.now() - t0) / 1000).toFixed(0)}s threshold T = ${thr} wei`); lastT = thr }
    const pool = await rpc('txpool_content'), dropped = []
    for (const byNonce of Object.values(pool.pending || {})) for (const tx of Object.values(byNonce)) {
      const tip = BigInt(tx.maxPriorityFeePerGas ?? tx.gasPrice ?? '0x0')
      if (tip < thr) { await rpc('anvil_dropTransaction', [tx.hash]); dropped.push(`${tx.hash.slice(0, 10)}… tip ${tip}`) }
    }
    if (baseFee) await rpc('anvil_setNextBlockBaseFeePerGas', ['0x' + BigInt(baseFee).toString(16)])
    await rpc('evm_mine')
    if (dropped.length) console.log(`t=${((Date.now() - t0) / 1000).toFixed(0)}s dropped ${dropped.join(', ')} (T=${thr})`)
  } catch (e) { console.log('miner error:', String(e.message).slice(0, 120)) }
  await new Promise((r) => setTimeout(r, EVERY))
}

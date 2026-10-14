#!/usr/bin/env node
// PORTED (E4) from the prototype, tag add7b-e540f8ae4d6b, test/sol-pressure-filter.mjs
// (sha256 8fc211414b463751235766b7e61dce5d90252280362de377e3e96145516260f3). One change, marked `E4:` below: the
// workspace install is linked (npm 11.21.0), so '@scure/base' resolves from packages/core, not from the repo root.
// Everything else is byte-for-byte. The E4 harness (chains.ts startSolPressure) starts it under a loopback-only sandbox
// in front of the harness's OWN solana-test-validator; the relay reaches it through VT_TEST_SOL_RPC (local only).
// R64 TEST HARNESS (local only; NOT part of the release): a JSON-RPC filter in front of the LOCAL solana-test-validator that
// WITHHOLDS sendTransaction when the tx's CU price (SetComputeUnitPrice; none = 0) is below T — it answers as if accepted
// (returns the signature) but never forwards, like a leader that drops low-priority txs. Everything else passes through.
//   node test/sol-pressure-filter.mjs --listen 8998 --upstream http://127.0.0.1:8999 --schedule "0:0,25:1,200:0"
// The relay is pointed at it for the test only: VT_TEST_SOL_RPC=http://127.0.0.1:8998 node relay.mjs --profile local …
// Tests may POST {"T": µL/CU|null} to http://127.0.0.1:<listen>/__control to override / release the schedule.
import http from 'node:http'
import { createRequire } from 'node:module'
// E4: was `import { base58 } from '@scure/base'` (the same package, resolved through packages/core's install)
const { base58 } = await import(createRequire(new URL('../../../packages/core/package.json', import.meta.url)).resolve('@scure/base'))
const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : d }
if (process.argv.includes('--profile') && arg('profile') !== 'local') { console.error('refusing: the SOL pressure filter is local-only'); process.exit(2) }
const LISTEN = Number(arg('listen', '8998')), UP = arg('upstream', 'http://127.0.0.1:8999')
const SCHED = arg('schedule', '0:0').split(',').map((x) => x.split(':').map(Number)).sort((a, b) => a[0] - b[0])
if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(UP)) { console.error('refusing: upstream must be a loopback validator'); process.exit(2) }
const PUBLIC = ['5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d', 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG', '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY']
const g = await (await fetch(UP, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getGenesisHash' }) })).json()
if (!g.result || PUBLIC.includes(g.result)) { console.error('refusing: the upstream is not a local test validator'); process.exit(2) }
const t0 = Date.now(); let override = null
const T = () => { if (override != null) return override; let v = 0; for (const [s, x] of SCHED) if ((Date.now() - t0) / 1000 >= s) v = x; return v }
const CB = 'ComputeBudget111111111111111111111111111111'
// legacy tx: shortvec sigs | sigs | header(3) | shortvec keys | keys | blockhash | shortvec ixs | ixs(progIdx, shortvec accts, accts, shortvec len, data)
function sv(b, o) { let len = 0, size = 0; for (;;) { const x = b[o + size]; len |= (x & 0x7f) << (size * 7); size++; if (!(x & 0x80)) return [len, size] } }
function cuPrice(b64) {
  const b = Buffer.from(b64, 'base64'); let [n, s] = sv(b, 0); let o = s + n * 64
  const sig = base58.encode(b.subarray(s, s + 64))
  o += 3; const [nk, sk] = sv(b, o); o += sk; const keys = []; for (let i = 0; i < nk; i++) { keys.push(base58.encode(b.subarray(o, o + 32))); o += 32 }
  o += 32; const [ni, si] = sv(b, o); o += si; let price = 0
  for (let i = 0; i < ni; i++) { const prog = keys[b[o]]; o += 1; const [na, sa] = sv(b, o); o += sa + na; const [dl, sd] = sv(b, o); o += sd
    if (prog === CB && b[o] === 3) price = Number(b.readBigUInt64LE(o + 1)); o += dl }
  return { sig, price }
}
let withheld = 0, forwarded = 0
http.createServer((req, res) => {
  const chunks = []; req.on('data', (c) => chunks.push(c)); req.on('end', async () => {
    const body = Buffer.concat(chunks)
    try {
      if (req.url === '/__control') { try { override = JSON.parse(body || '{}').T ?? null } catch {} res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ T: T(), withheld, forwarded })) }
      const j = JSON.parse(body)
      if (j.method === 'sendTransaction') {
        const { sig, price } = cuPrice(j.params[0]), thr = T()
        if (price < thr) { withheld++; console.log(`t=${((Date.now() - t0) / 1000).toFixed(0)}s WITHHELD ${sig.slice(0, 10)}… price ${price} < T ${thr} (withheld ${withheld})`); res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ jsonrpc: '2.0', id: j.id, result: sig })) }
        forwarded++
      }
    } catch { /* forward as is */ }
    const up = await fetch(UP, { method: 'POST', headers: { 'content-type': 'application/json' }, body })
    res.writeHead(up.status, { 'content-type': 'application/json' }); res.end(Buffer.from(await up.arrayBuffer()))
  })
}).listen(LISTEN, '127.0.0.1', () => console.log(`sol pressure filter on 127.0.0.1:${LISTEN} → ${UP}; schedule ${SCHED.map(([s, x]) => `${s}s→${x}`).join(', ')} µL/CU`))

// Fakes for the BTC lane tests (not a test file). ALL DATA IS SYNTHETIC; nothing listens on a port. The fake "bitcoind" speaks the
// relay's two BTC routes through an injected fetch: POST /relay/btc (JSON-RPC reads) and POST /relay/btc/send (the ticketed
// send, answer { txid }). It parses every raw tx it is sent with @scure/btc-signer, so what it holds is what was really built:
// outputs, the spends (a double spend is refused), the reveal witness. Blocks are mined by the test (mine()) or automatically
// after `blockAfterLookups` getrawtransaction calls on a mempool tx (a block arrives while the lane waits).
import * as btc from '@scure/btc-signer'
import { OutOrdinalReveal } from 'micro-ordinals'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { configureRelay } from '../../src/engine/rpc.js'
import { btcNetwork } from '../../src/chains/btc-ord.ts'

const NET = btcNetwork('local')
export type SendMode = 'ok' | 'accept-then-502' | 'drop-then-502' | 'accept-then-403' | 'transport-fail'
interface Out { amount: bigint; script: Uint8Array; address: string; spentBy: string | null }
interface Tx { hex: string; id: string; height: number | null; blockhash: string | null; tx: btc.Transaction; ins: string[] }

export function fakeBtcChain(o: { network?: 'local'; blockAfterLookups?: number; feerate?: number } = {}) {
  void o.network
  const outs = new Map<string, Out>()
  const txs = new Map<string, Tx>()
  const calls: Array<{ kind: 'read' | 'send'; method: string; params: unknown[]; ticket: string | null; txid?: string }> = []
  const lookups = new Map<string, number>()
  const funding = new Set<string>()                                      // coinbase-like funding txids: confirmed, outputs listed on demand
  let height = 100, sendMode: SendMode = 'ok', sendModeOnce: SendMode | null = null
  const afterLookups = o.blockAfterLookups ?? 2
  let forceUnreadable = 0, failScans = 0, failHeaders = 0
  const addr = (script: Uint8Array): string => btc.Address(NET).encode(btc.OutScript.decode(script))
  const hash = (h: number): string => h.toString(16).padStart(64, '0')

  // a coin on a script, confirmed (a funding output the lane owns)
  function fund(address: string, amount: bigint, txid = bytesToHex(crypto.getRandomValues(new Uint8Array(32))), vout = 0): { txid: string; vout: number } {
    const script = btc.OutScript.encode(btc.Address(NET).decode(address))
    outs.set(`${txid}:${vout}`, { amount, script, address, spentBy: null })
    funding.add(txid)
    return { txid, vout }
  }
  function accept(hex: string): { ok: true; id: string } | { ok: false; why: string } {
    let tx: btc.Transaction
    try { tx = btc.Transaction.fromRaw(hexToBytes(hex), { allowUnknownOutputs: true, customScripts: [OutOrdinalReveal] }) } catch (e) { return { ok: false, why: `TX decode failed: ${String((e as Error).message)}` } }
    const ins: string[] = []
    let total = 0n
    for (let i = 0; i < tx.inputsLength; i++) {
      const inp = tx.getInput(i), k = `${bytesToHex(inp.txid!)}:${inp.index}`
      const prev = outs.get(k)
      if (!prev) return { ok: false, why: 'bad-txns-inputs-missingorspent' }
      if (prev.spentBy !== null) return { ok: false, why: 'txn-mempool-conflict' }
      ins.push(k); total += prev.amount
    }
    let paid = 0n
    for (let i = 0; i < tx.outputsLength; i++) paid += tx.getOutput(i).amount!
    if (paid > total) return { ok: false, why: 'bad-txns-in-belowout' }
    const id = tx.id
    if (txs.has(id)) return { ok: true, id }
    for (const k of ins) outs.get(k)!.spentBy = id
    for (let i = 0; i < tx.outputsLength; i++) { const out = tx.getOutput(i); outs.set(`${id}:${i}`, { amount: out.amount!, script: out.script!, address: addr(out.script!), spentBy: null }) }
    txs.set(id, { hex, id, height: null, blockhash: null, tx, ins })
    return { ok: true, id }
  }
  function mine(): number {
    height++
    for (const t of txs.values()) if (t.height === null) { t.height = height; t.blockhash = hash(height) }
    return height
  }
  const view = (t: Tx): unknown => {
    const vin = []
    for (let i = 0; i < t.tx.inputsLength; i++) { const inp = t.tx.getInput(i); vin.push({ txid: bytesToHex(inp.txid!), vout: inp.index, txinwitness: (inp.finalScriptWitness ?? []).map((w: Uint8Array) => bytesToHex(w)) }) }
    const vout = []
    for (let i = 0; i < t.tx.outputsLength; i++) { const out = t.tx.getOutput(i); vout.push({ value: Number(out.amount!) / 1e8, n: i, scriptPubKey: { hex: bytesToHex(out.script!), address: addr(out.script!) } }) }
    return { txid: t.id, hex: t.hex, vin, vout, ...(t.height !== null ? { confirmations: height - t.height + 1, blockhash: t.blockhash } : {}) }
  }
  const rpcError = (code: number, message: string): Response => new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code, message } }), { status: 200 })
  const rpcResult = (result: unknown): Response => new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { status: 200 })

  const read = (method: string, p: any[]): Response => {
    switch (method) {
      case 'getrawtransaction': {
        if (forceUnreadable > 0) { forceUnreadable--; return new Response(JSON.stringify({ error: { message: 'upstream timeout', code: -32099 } }), { status: 502 }) }
        const t = txs.get(p[0])
        if (!t && funding.has(p[0])) return rpcResult({ txid: p[0], confirmations: 10, blockhash: hash(50), vout: [...outs].filter(([k]) => k.startsWith(`${p[0]}:`)).sort().map(([k, v]) => ({ value: Number(v.amount) / 1e8, n: Number(k.split(':')[1]), scriptPubKey: { address: v.address } })) })
        if (!t) return rpcError(-5, 'No such mempool or blockchain transaction. Use gettransaction for wallet transactions.')
        if (t.height === null) { const n = (lookups.get(t.id) ?? 0) + 1; lookups.set(t.id, n); if (afterLookups > 0 && n > afterLookups) { mine(); return rpcResult(view(t)) } }
        return rpcResult(view(t))
      }
      case 'gettxout': {
        const out = outs.get(`${p[0]}:${p[1]}`)
        const mempoolToo = p[2] !== false                                  // gettxout's include_mempool (default true)
        const spender = out?.spentBy == null ? null : txs.get(out.spentBy)
        if (!out || (out.spentBy !== null && (mempoolToo || spender?.height != null))) return rpcResult(null)
        return rpcResult({ value: Number(out.amount) / 1e8, scriptPubKey: { address: out.address } })
      }
      case 'scantxoutset': {
        if (failScans > 0) { failScans--; return new Response(JSON.stringify({ error: { message: 'upstream timeout', code: -32099 } }), { status: 502 }) }
        const m = /addr\((.+)\)/.exec(p[1][0].desc)!
        const confirmed = (k: string): boolean => { const t = txs.get(k.split(':')[0]); return t === undefined || t.height !== null }   // a funding coin, or a tx in a block
        const unspents = [...outs].filter(([k, v]) => v.address === m[1] && v.spentBy === null && confirmed(k))
          .map(([k, v]) => ({ txid: k.split(':')[0], vout: Number(k.split(':')[1]), amount: Number(v.amount) / 1e8, height: 100 }))
        return rpcResult({ success: true, unspents })
      }
      case 'getblockheader':
        if (failHeaders > 0) { failHeaders--; return new Response(JSON.stringify({ error: { message: 'upstream timeout', code: -32099 } }), { status: 502 }) }
        return rpcResult({ height: Number.parseInt(p[0], 16) })
      case 'testmempoolaccept': {
        const tx = btc.Transaction.fromRaw(hexToBytes(p[0][0]), { allowUnknownOutputs: true, customScripts: [OutOrdinalReveal] })
        let ok = true, total = 0n, paid = 0n
        for (let i = 0; i < tx.inputsLength; i++) { const inp = tx.getInput(i), prev = outs.get(`${bytesToHex(inp.txid!)}:${inp.index}`); if (!prev || prev.spentBy !== null) ok = false; else total += prev.amount }
        for (let i = 0; i < tx.outputsLength; i++) paid += tx.getOutput(i).amount!
        return rpcResult([ok && paid <= total ? { txid: tx.id, allowed: true } : { txid: tx.id, allowed: false, 'reject-reason': 'missing-inputs' }])
      }
      case 'estimatesmartfee': return rpcResult(o.feerate === undefined ? { errors: ['Insufficient data or no feerate found'] } : { feerate: o.feerate, blocks: 2 })   // feerate: BTC/kvB
      default: return rpcError(-32601, `no fake for ${method}`)
    }
  }
  async function fetch(url: string, init: RequestInit): Promise<Response> {
    const headers = (init.headers ?? {}) as Record<string, string>
    const ticket = headers['x-vt-send-ticket'] ?? null
    if (url.endsWith('/relay/btc/send')) {
      const { hex } = JSON.parse(String(init.body)) as { hex: string }
      const parsed = btc.Transaction.fromRaw(hexToBytes(hex), { allowUnknownOutputs: true, customScripts: [OutOrdinalReveal] })
      calls.push({ kind: 'send', method: 'btc_send', params: [hex], ticket, txid: parsed.id })
      const mode = sendModeOnce ?? sendMode; sendModeOnce = null
      const json = (status: number, body: unknown): Response => new Response(JSON.stringify(body), { status })
      if (mode === 'transport-fail') throw new TypeError('fetch failed')
      if (mode === 'drop-then-502') return json(502, { error: { message: 'relay.upstream-shape: not a result' } })
      const r = accept(hex)
      if (!r.ok) return json(r.why === 'txn-mempool-conflict' || r.why === 'bad-txns-inputs-missingorspent' ? 403 : 502, { error: { message: r.why === 'txn-mempool-conflict' || r.why === 'bad-txns-inputs-missingorspent' ? 'relay.btc-prevout' : 'send outcome unknown' } })
      if (mode === 'accept-then-502') return json(502, { error: { message: 'relay.upstream-shape: not a result' } })
      if (mode === 'accept-then-403') return json(403, { error: { message: 'relay.btc-prevout' } })
      return json(200, { txid: r.id })
    }
    const m = /\/relay\/btc$/.exec(url)
    if (!m) return new Response(JSON.stringify({ error: { message: 'bad route' } }), { status: 403 })
    const body = JSON.parse(String(init.body)) as { method: string; params: unknown[] }
    calls.push({ kind: 'read', method: body.method, params: body.params, ticket })
    return read(body.method, body.params as any[])
  }
  configureRelay({ base: 'http://relay.test', fetch })
  return {
    calls, outs, txs, fund, mine, accept, fetch,
    sends: () => calls.filter((c) => c.kind === 'send'),
    sendsOf: (txid: string) => calls.filter((c) => c.kind === 'send' && c.txid === txid),
    setSendMode: (m: SendMode) => { sendMode = m },
    nextSend: (m: SendMode) => { sendModeOnce = m },
    unreadable: (n: number) => { forceUnreadable = n },
    failScans: (n: number) => { failScans = n },
    failHeaders: (n: number) => { failHeaders = n },
    height: () => height,
    inMempool: (id: string) => txs.get(id)?.height === null,
    onChain: (id: string) => txs.get(id)?.height != null,
  }
}

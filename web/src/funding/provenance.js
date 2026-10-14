// Reads one Ethereum address's funding history through THIS stack's relay (read-only: Blockscout v2 and the JSON-RPC, both
// allowlisted by the relay and over Tor) and hands it to core's evaluateEthRow (gates/provenance.ts), which holds every rule.
// This file only fetches and reshapes; a failed or odd answer is "unchecked" with the reason, never a pass (fail closed).
//
//   GET  /relay/blockscout/eth/addresses/<a>/transactions?filter=to            inbound txs whose `to` is the address
//   GET  /relay/blockscout/eth/addresses/<a>/internal-transactions?filter=to   inbound internal transfers (a contract paying out)
//   GET  /relay/blockscout/eth/transactions/<hash>                             the parent tx of an internal transfer (its `to`)
//   POST /relay/eth  eth_getBalance, eth_getTransactionCount, eth_call railgun()   balance, nonce, "is this contract a RelayAdapt"
// No Blockscout on the local stack (no gate there: a stand-in), and no automatic call: the page reads only when asked.
import { RAILGUN_GETTER, RAILGUN_PROXY, RAILGUN_RELAYADAPT, RELAY_SELECTOR, evaluateEthRow } from '@vault-timelock/core/gates/provenance.ts'

const PARENTS_MAX = 25
const ADDR = /^0x[0-9a-fA-F]{40}$/, HASH = /^0x[0-9a-fA-F]{64}$/, DEC = /^\d{1,78}$/, HEXQ = /^0x[0-9a-fA-F]{1,64}$/

export class ProvenanceReadError extends Error { constructor(message) { super(message); this.name = 'ProvenanceReadError' } }
const bad = (why) => { throw new ProvenanceReadError(why) }

async function getJson(fetchFn, path) {
  let res
  try { res = await fetchFn(path, { cache: 'no-store', credentials: 'same-origin', redirect: 'error' }) } catch { bad('the relay is not reachable') }
  if (!res.ok) bad(`the relay answered ${res.status} for a provenance read`)
  try { return JSON.parse(await res.text()) } catch { return bad('a provenance read was not JSON') }
}
async function rpc(fetchFn, method, params) {
  let res
  try { res = await fetchFn('/relay/eth', { method: 'POST', cache: 'no-store', credentials: 'same-origin', redirect: 'error', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }) } catch { bad('the relay is not reachable') }
  if (!res.ok) bad(`the relay answered ${res.status} for ${method}`)
  let j
  try { j = JSON.parse(await res.text()) } catch { return bad(`${method} was not JSON`) }
  if (!j || j.jsonrpc !== '2.0' || typeof j.result !== 'string') bad(`${method} returned no result`)
  return j.result
}
const hexInt = (s, what) => { if (!HEXQ.test(s)) bad(`${what} is not a hex number`); return BigInt(s) }

function pageItems(page, what) {
  if (!page || typeof page !== 'object' || !Array.isArray(page.items)) bad(`${what}: not a Blockscout page`)
  if (page.next_page_params !== null && page.next_page_params !== undefined && typeof page.next_page_params !== 'object') bad(`${what}: odd paging`)
  return { items: page.items, truncated: page.next_page_params != null }
}
const addrOf = (o) => (o && typeof o === 'object' && typeof o.hash === 'string' && ADDR.test(o.hash) ? o.hash : null)

// What the verdict means for the badge (m-2). 'elsewhere' (red) is for funds the check POSITIVELY found outside Railgun (provenance.not-railgun); the
// other ways to fail are not that, and each gets its own wording: nothing inbound yet, a history too long to read, an address that has sent
// since (the check is about the funding transactions then), or a balance the inbound transfers do not explain (indexer lag, or other funds).
export function statusOfVerdict(verdict) {
  if (verdict.ok) return 'railgun'
  const g = new Set(verdict.failures.map((f) => f.guard))
  return g.has('provenance.not-railgun') ? 'elsewhere' : g.has('provenance.paged') ? 'paged' : g.has('provenance.no-inbound') ? 'unfunded'
    : g.has('provenance.nonce') ? 'sent' : g.has('provenance.unaccounted') ? 'unaccounted' : 'unchecked'
}

// -> { status: 'railgun' | 'elsewhere' | 'unfunded' | 'paged' | 'sent' | 'unaccounted' | 'unchecked', verdict, balance, nonce } or throws ProvenanceReadError
export async function readEthProvenance({ network, address, fetch: fetchFn = (...a) => globalThis.fetch(...a) }) {
  if (network !== 'testnet' && network !== 'mainnet') bad('there is no indexer on this stack: no provenance check')
  if (typeof address !== 'string' || !ADDR.test(address)) bad('not an Ethereum address')
  const proxy = RAILGUN_PROXY[network]
  const a = address.toLowerCase()
  const base = `/relay/blockscout/eth/addresses/${address}`
  const txPage = pageItems(await getJson(fetchFn, `${base}/transactions?filter=to`), 'transactions')
  const inPage = pageItems(await getJson(fetchFn, `${base}/internal-transactions?filter=to`), 'internal transactions')
  const adapt = RAILGUN_RELAYADAPT[network]
  const inbound = []
  for (const t of txPage.items) {
    // a plain transfer to the address: the parent is the tx itself, so its `to` is the address and it is never Railgun's
    if (!t || typeof t !== 'object' || typeof t.hash !== 'string' || !HASH.test(t.hash) || typeof t.value !== 'string' || !DEC.test(t.value)) bad('transactions: odd item')
    if (addrOf(t.to)?.toLowerCase() !== a) continue
    const from = addrOf(t.from)
    if (from === null) bad('transactions: an item has no sender')
    inbound.push({ txHash: t.hash.toLowerCase(), viaTo: addrOf(t.to), from, relayCall: false, value: BigInt(t.value), success: t.status === 'ok' })
  }
  const parents = new Map()
  for (const t of inPage.items) {
    if (!t || typeof t !== 'object' || typeof t.transaction_hash !== 'string' || !HASH.test(t.transaction_hash) || typeof t.value !== 'string' || !DEC.test(t.value)) bad('internal transactions: odd item')
    if (addrOf(t.to)?.toLowerCase() !== a) continue
    const from = addrOf(t.from)
    if (from === null) bad('internal transactions: an item has no sender')
    const h = t.transaction_hash.toLowerCase()
    if (!parents.has(h)) {
      if (parents.size >= PARENTS_MAX) bad('more than 25 funding transactions: refused rather than partially checked')
      const p = await getJson(fetchFn, `/relay/blockscout/eth/transactions/${h}`)
      const to = addrOf(p?.to)
      if (to === null) bad('a parent transaction has no recipient')
      if (typeof p.value !== 'string' || !DEC.test(p.value) || typeof p.raw_input !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(p.raw_input)) bad('a parent transaction has no value or input')
      // relay() with value 0 on the RelayAdapt: multicall / transfer are open to anyone, and ETH attached to relay() is somebody's own
      parents.set(h, { to, relayCall: p.value === '0' && p.raw_input.slice(0, 10).toLowerCase() === RELAY_SELECTOR })
    }
    const parent = parents.get(h)
    inbound.push({ txHash: h, viaTo: parent.to, from, relayCall: parent.relayCall, value: BigInt(t.value), success: t.success === true })
  }
  // The RelayAdapt is PINNED, never discovered (any contract can answer railgun() with the proxy). railgun() on the pin is a consistency check
  // only, made when a pinned RelayAdapt took part: if the node cannot answer it, or the pin does not answer the proxy, the pin is stale: unchecked.
  if (inbound.some((t) => t.viaTo.toLowerCase() === adapt.toLowerCase() || t.from.toLowerCase() === adapt.toLowerCase())) {
    const r = await rpc(fetchFn, 'eth_call', [{ to: adapt, data: RAILGUN_GETTER }, 'latest'])
    if (!(/^0x0{24}[0-9a-fA-F]{40}$/.test(r) && `0x${r.slice(26)}`.toLowerCase() === proxy.toLowerCase())) bad('the pinned RelayAdapt does not answer railgun() with the pinned proxy: the pins are stale, nothing was concluded')
  }
  const adapts = new Set([adapt.toLowerCase()])
  const balance = hexInt(await rpc(fetchFn, 'eth_getBalance', [address, 'latest']), 'the balance')
  const nonceBig = hexInt(await rpc(fetchFn, 'eth_getTransactionCount', [address, 'latest']), 'the nonce')
  if (nonceBig > BigInt(Number.MAX_SAFE_INTEGER)) bad('the nonce is out of range')
  const verdict = evaluateEthRow({ address, balance, nonce: Number(nonceBig), inbound, proxy, relayAdapts: adapts, truncated: txPage.truncated || inPage.truncated })
  return { status: statusOfVerdict(verdict), verdict, balance, nonce: Number(nonceBig) }
}

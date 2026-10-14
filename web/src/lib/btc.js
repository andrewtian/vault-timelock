// The BTC lane in the page (W7 part B). Pure data and small helpers; the lane itself (commit + reveal, one text inscription
// per copy) is core's chains/btc.js and engine/btc-tx.js (E7). Numbers come from core's btc-ord.ts, never retyped here.
//   · local network only for now (R75: no other publish mode than btc.inscription, text/plain);
//   · ord links: the LOCAL ord (http://127.0.0.1:8090, ord 0.29.0 regtest) opens; any other network is copy-only (paste into
//     Tor Browser), exactly like every other explorer link in this page. The CSP is unchanged: these are plain links.
import { BTC_MAX_FEE_RATE as MAX_RATE, BTC_POSTAGE as POSTAGE } from '@vault-timelock/core/chains/btc-ord.ts'
import { BTC_BODY_MAX } from '@vault-timelock/core/chains/btc.js'
import { publishModeRow } from '@vault-timelock/core/contracts'
import { btcRpc } from '@vault-timelock/core/engine/rpc.js'

export const BTC_MAX_FEE_RATE = Number(MAX_RATE)             // sat/vB, the highest rate a ticket's caps assume
export const BTC_POSTAGE = Number(POSTAGE)                   // sats on the inscription output
export { BTC_BODY_MAX }                                      // bytes of one inscription body
export const BTC_PUBLISH_MODE = 'btc.inscription'
export const BTC_PUBLISH_LABEL = 'btc.inscription (text/plain)'
export const LOCAL_ORD_PORT = 8090                           // btc.ord, local (web-frontend design D-R16)
export const LOCAL_ORD = `http://127.0.0.1:${LOCAL_ORD_PORT}`
// The ceiling a NEW btc job prefills (Eminors fix 1, I-1): core's one rule, min(500, max(10, 4 x the relay's current estimate)), 25 with no estimate.
// The estimate is the node's 2-block estimatesmartfee through the relay (BTC/kvB -> sat/vB); any failure or "no feerate" = no estimate.
export { suggestedBtcFeeCeiling } from '@vault-timelock/core/job'
export async function relayFeeEstimate(rpc = btcRpc) {
  try {
    const e = await rpc('estimatesmartfee', [2])
    return typeof e?.feerate === 'number' && e.feerate > 0 ? Math.ceil((e.feerate * 1e8) / 1000) : null
  } catch { return null }
}
export const BTC_NETWORKS = ['local']                        // testnet4 / mainnet need the relay's Esplora reads (E7 concern)

// What this build can do with a BTC lane (both true since E7b / CC-12; kept as explicit switches so a core regression shows):
//   jobs      core's publish-mode table has an AVAILABLE btc.inscription row (read from core, not retyped);
//   executor  core's createExecutor runs chain btc (local network only). "Run here" for btc is off while it is false.
export const BTC_EXECUTOR_WIRED = true     // E7b merged: core's createExecutor runs chain btc (local network only)
export function btcCapability({ table = publishModeRow, executorWired = BTC_EXECUTOR_WIRED } = {}) {
  return { jobs: table(BTC_PUBLISH_MODE)?.status === 'available', executor: executorWired === true }
}
export const btcAvailable = (network) => BTC_NETWORKS.includes(network)

// Fee rate (sat/vB): empty = the engine's own estimate (the node's estimatesmartfee, capped); else a whole number from 1 to
// the ticket cap. -> { ok, value: number | null, why }
export function parseFeeRate(text) {
  const s = String(text ?? '').trim()
  if (s === '') return { ok: true, value: null, why: '' }
  if (!/^\d{1,4}$/.test(s)) return { ok: false, value: null, why: `max fee rate: a whole number of sat/vB from 1 to ${BTC_MAX_FEE_RATE}, or empty` }
  const n = Number(s)
  if (n < 1 || n > BTC_MAX_FEE_RATE) return { ok: false, value: null, why: `max fee rate: a whole number of sat/vB from 1 to ${BTC_MAX_FEE_RATE}, or empty` }
  return { ok: true, value: n, why: '' }
}

// A reveal txid's one inscription: ord numbers it <revealTxid>i0 (the reveal carries exactly one).
export const inscriptionId = (revealTxid) => `${revealTxid}i0`

// Links for one copy's inscription. -> [{ label, url, open }]; open only for the local ord.
export function ordLinks(network, revealTxid) {
  if (!/^[0-9a-f]{64}$/.test(String(revealTxid))) return []
  const id = inscriptionId(revealTxid)
  if (network === 'local') {
    return [
      { label: 'ord (local) · inscription', url: `${LOCAL_ORD}/inscription/${id}`, open: true },
      { label: 'ord (local) · transaction', url: `${LOCAL_ORD}/tx/${revealTxid}`, open: true },
    ]
  }
  if (network === 'testnet') return [{ label: 'ordinals explorer (testnet4) · inscription', url: `https://testnet4.ordinals.com/inscription/${id}`, open: false }]
  if (network === 'mainnet') return [{ label: 'ordinals.com · inscription', url: `https://ordinals.com/inscription/${id}`, open: false }]
  return []
}

// A plain transaction link (commit or reveal).
export function btcTxLinks(network, txid) {
  if (!/^[0-9a-f]{64}$/.test(String(txid))) return []
  if (network === 'local') return [{ label: 'ord (local) · transaction', url: `${LOCAL_ORD}/tx/${txid}`, open: true }]
  if (network === 'testnet') return [{ label: 'mempool.space (testnet4) · transaction', url: `https://mempool.space/testnet4/tx/${txid}`, open: false }]
  if (network === 'mainnet') return [{ label: 'mempool.space · transaction', url: `https://mempool.space/tx/${txid}`, open: false }]
  return []
}

// The regtest hints under the local funding address (an operator step; the page never sends the funding).
export const regtestFundHint = (address) => `bitcoin-cli -regtest -rpcwallet=vt sendtoaddress ${address} 0.01`
export const regtestMineHint = (address) => `bitcoin-cli -regtest generatetoaddress 101 ${address}`

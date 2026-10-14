// What the Arm dialog needs, read through this network's relay (same origin) and computed by core:
//   · the text (journal client: the sha256 must match, strict UTF-8);
//   · per chain the lane strategy's starting fees and the balance — core assessChain in its PRE-ARM mode (local fee
//     math: no calldata or memo leaves the page before Arm, MQ I7), exactly as the executor quotes them;
//   · the price (mainnet / local fixture; testnet: none, TEST FUNDS — NO VALUE → the native fallback caps);
//   · the address history (MQ I2: ETH nonce, SOL sent memo txs) for the typed `again`;
//   · computeArmCaps (engine/arm-caps.js): nativeCap, usd, overCap, planned (EXACT, full precision), fullCopyCost, parts,
//     affordable. Errors stay per chain: a chain without inputs cannot be armed.
import { ECON, PLAN } from '@vault-timelock/core/chains/constants.js'
import { formatUnits, parseDecimal } from '@vault-timelock/core/chains/plan.js'
import { fetchPrice } from '@vault-timelock/core/chains/price.js'
import * as eth from '@vault-timelock/core/chains/eth.js'
import * as sol from '@vault-timelock/core/chains/sol.js'
import * as btcc from '@vault-timelock/core/chains/btc.js'
import { ethAmsterdam } from '@vault-timelock/core/contracts'
import { assessChain, startingFees } from '@vault-timelock/core/engine/assess.js'
import { windowNoteOf } from '@vault-timelock/core/engine/lane.js'
import { computeArmCaps, toArmCap } from '@vault-timelock/core/engine/arm-caps.js'
import { planLaneCopy } from '@vault-timelock/core/engine/lane.js'
import { useRelayClient } from '@vault-timelock/core/engine/rpc.js'
import { browserClients, laneConfigOf } from '@vault-timelock/core/executor'

export { toArmCap }
export const DEC = { eth: 18, sol: 9, btc: 8 }
export const UNIT = { eth: 'ETH', sol: 'SOL', btc: 'BTC' }
const short = (e) => String(e?.message || e).replace(/\s+/g, ' ').slice(0, 200)

// The typed over-cap amount equals `planned` when both parse to the same base units (no rounding; no more decimals
// than the chain has). "0.010" and "0.01" are the same amount; anything malformed is not.
export function sameAmount(typed, planned, chain) {
  try { return parseDecimal(String(typed).trim(), DEC[chain]) === parseDecimal(planned, DEC[chain]) } catch { return false }
}

// What a SOL drain lane keeps back (F9-2): rent-exempt minimum + one claw-back fee (laneCalc / engine payerFloor). Copies
// lanes and ETH keep none here. `planned` stays the exact spend the cap and the typed amount use; only what is SPENDABLE
// (planned − reserve) buys copies.
export const drainReserve = (chain, def, rent) => (chain === 'sol' && def.chains[chain]?.mode === 'drain' ? BigInt(rent) + ECON.SOL_CLAW_RESERVE : 0n)

export const spendableOf = (cap, chain, reserve = 0n) => { const p = parseDecimal(cap.planned, DEC[chain]); return p > reserve ? p - reserve : 0n }

// the >10× warning (MQ laneCalc warn): the SPENDABLE amount (planned − reserve) is more than PLAN.WARN_FACTOR × one full copy
export function tenX(cap, chain, reserve = 0n) {
  try {
    const one = BigInt(cap.fullCopyCost), spend = spendableOf(cap, chain, reserve)
    return one > 0n && spend > PLAN.WARN_FACTOR * one ? { copies: spend / one, one: formatUnits(one, DEC[chain]), reserve: formatUnits(reserve, DEC[chain]), spendable: formatUnits(spend, DEC[chain]) } : null
  } catch { return null }
}

export async function armInputs({ def, network, now = Date.now(), fetch: f = (u, i) => globalThis.fetch(u, i) }) {
  const { journal, relay } = browserClients({ fetch: f })
  useRelayClient(relay)                                   // the engine's RPC goes through this page's relay
  const text = await journal.message(def.messageSha256)
  const prices = network === 'testnet' ? null : await fetchPrice({ base: '', fetch: f }).catch(() => null)
  const out = { text, prices, chains: {} }
  for (const c of Object.keys(def.chains)) {
    const ch = def.chains[c]
    const row = { cap: null, balance: null, history: null, reserve: 0n, windowNote: '', error: '' }
    out.chains[c] = row
    try {
      const cfg = laneConfigOf(c, ch, text)
      if (c === 'btc') { await btcRow({ row, out, def, ch, cfg, text, network, prices, now }); continue }
      const sf = await startingFees(network, c, cfg.feeStrategy, c === 'eth' && ch.maxTipGwei != null ? { maxTipGwei: ch.maxTipGwei } : {})     // the job's tip cap (prompt pricing); ONE source: the page, `vt job arm` and the engine price arm identically
      row.windowNote = c === 'eth' && sf.fees.truncated ? windowNoteOf(sf.fees.windowBlocks) : ''   // W7/F10-1: the passive window an RPC limit cut short (core's one note text); a full window shows nothing
      const q = await assessChain(c, planLaneCopy(cfg, 1), {
        real: false, network, address: ch.keyAddress, recipient: cfg.recipient,
        ...(c === 'eth' ? { gasRule: { amsterdam: ethAmsterdam(network), toSelf: cfg.recipient === 'self' }, ethFees: sf.fees } : { priorityLamports: sf.fees.priorityLamports }),
        strategy: cfg.feeStrategy, cuPriceCap: cfg.cuPriceCap, msSha: def.messageSha256, cfgKey: 'arm', now: () => now,
      })
      if (typeof q.balance !== 'bigint') throw new Error(q.reason || 'no fee quote from the relay')
      row.balance = q.balance
      const fees = c === 'eth' ? { eth: sf.fees } : { sol: sf.fees }
      const caps = computeArmCaps({ ...def, chains: { [c]: ch } }, text, { prices, fees, balances: { [c]: q.balance }, network, now })
      row.cap = caps[c]
      row.reserve = drainReserve(c, def, c === 'sol' ? sf.fees.rent : 0n)
      row.history = c === 'eth' ? await eth.nonceAt(ch.keyAddress, 'latest') : await sol.sentCount(ch.keyAddress)
    } catch (e) { row.error = short(e) }
  }
  return out
}

// W7b/Wfix5: the BTC lane's Arm inputs (R76: the lane's balance is shown). One copy = a commit and a reveal, priced by core's
// startingFees(network, 'btc', …) at the node's fee rate clamped to the job's maxFeeRateSatVb: fee rate, worst-case commit and
// reveal fees, the 546-sat postage and perCopy. The lane is capped in sats (no BTC price; the local lane has no value).
async function btcRow({ row, def, ch, text, network, prices, now }) {
  const bytes = new TextEncoder().encode(text)
  const copies = typeof ch.mode === 'object' && ch.mode ? ch.mode.copies : null
  const o = { sha256: def.messageSha256, copy: null, copies: null }
  const parts = btcc.planBtcCopy(bytes, o)
  const widest = ch.distinctCopies && copies !== null && copies >= 2 ? btcc.planBtcCopy(bytes, { ...o, copy: copies, copies }) : null
  const sf = await startingFees(network, 'btc', ch.feeStrategy, { parts, ...(widest ? { altParts: widest } : {}), ...(ch.maxFeeRateSatVb != null ? { maxFeeRateSatVb: ch.maxFeeRateSatVb } : {}) })
  row.balance = await btcc.balanceOf(ch.keyAddress)
  row.btc = { rate: sf.fees.rate, commitFee: sf.fees.commitFee, revealFee: sf.fees.revealFee, postage: sf.fees.postage, perCopy: sf.perCopy }
  const caps = computeArmCaps({ ...def, chains: { btc: ch } }, text, { prices, fees: { btc: { rate: sf.fees.rate } }, balances: { btc: row.balance }, network, now })
  row.cap = caps.btc
  row.history = 0
}

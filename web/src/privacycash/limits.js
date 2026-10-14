// Privacy Cash funding: the numbers and the pure rules the page checks BEFORE it proves or sends anything (plan W6,
// research-privacycash.md D4/D6). Nothing here touches the network, a key or the DOM.
//
//   · ROUTES      the only requests the worker may make (same-origin /relay/privacycash/*, S7's proxy). The relay checks the same
//                 table again; this one stops a bug in the SDK or a changed dependency before a request leaves the worker.
//   · fee clamp   the relayer fee is capped at 0.006 SOL + 0.40 % of the GROSS (the published 0.35 % + a 0.05 % margin): the SAME clamp
//                 the relay applies to POST /withdraw (api/src/privacycash.ts FEE_BASE_LAMPORTS, FEE_RATE_PER_10K, FEE_MARGIN_PER_10K).
//                 The page refuses first.
//   · config clamp the relayer's /config values are bounded (rate <= 0.5 %, rent <= 0.01 SOL, minimum <= 0.05 SOL): an inflated
//                 /config would otherwise be accepted on-chain (the program only has a lower bound).
//   · solveGross  the smallest GROSS amount that nets the wanted amount, with the SDK's own floating-point fee formula.
//   · partial     the SDK silently does a partial withdrawal when its two largest notes cannot cover gross + fee: refused here.
export const LAMPORTS_PER_SOL = 1_000_000_000
export const RELAY_BASE = '/relay/privacycash'
export const SDK_RELAYER_URL = RELAY_BASE + '/relayer'
export const KEY_BASE_PATH = RELAY_BASE + '/artifacts/transaction2'
export const UPSTREAM_ORIGIN = 'https://api3.privacycash.org'      // the SDK's hard-coded default (belt and braces: rewritten, never fetched)
export const LANE_HEADER = 'x-vt-pc-lane'

export const FEE_BASE_LAMPORTS = 6_000_000                          // 0.006 SOL
export const FEE_RATE_PER_10K = 35                                  // the published 0.35 % of the gross, in ten-thousandths
export const FEE_MARGIN_PER_10K = 5                                 // + 0.05 % margin
export const MIN_NET_LAMPORTS = 10_000_000                          // 0.01 SOL: the relayer's minimum withdrawal
export const CONFIG_MAX = Object.freeze({ rate: 0.005, rent: 0.01, minimumSol: 0.05 })

// kind -> { method, re, timeoutMs } (timeouts = the relay's per-route timeouts + 5 s, so the relay answers first)
const HEX = '[0-9a-f]{72,400}'
export const ROUTES = Object.freeze([
  { kind: 'config', method: 'GET', re: /^\/relay\/privacycash\/relayer\/config$/, timeoutMs: 35_000 },
  { kind: 'range', method: 'GET', re: /^\/relay\/privacycash\/relayer\/utxos\/range$/, timeoutMs: 125_000 },
  { kind: 'indices', method: 'POST', re: /^\/relay\/privacycash\/relayer\/utxos\/indices$/, timeoutMs: 65_000 },
  { kind: 'proof', method: 'GET', re: /^\/relay\/privacycash\/relayer\/merkle\/proofv2\/$/, timeoutMs: 35_000 },
  { kind: 'withdraw', method: 'POST', re: /^\/relay\/privacycash\/relayer\/withdraw$/, timeoutMs: 95_000 },
  { kind: 'check', method: 'GET', re: new RegExp(`^/relay/privacycash/relayer/utxos/check/${HEX}$`), timeoutMs: 35_000 },
  { kind: 'rpc', method: 'POST', re: /^\/relay\/privacycash\/rpc$/, timeoutMs: 65_000 },
  { kind: 'artifact', method: 'GET', re: /^\/relay\/privacycash\/artifacts\/transaction2\.(?:wasm|zkey)$/, timeoutMs: 300_000 },
])

// The SDK's own fee formula, exactly as withdraw.js computes it (floating point, floor).
export const sdkFee = (gross, rate, rent) => Math.floor(gross * rate + LAMPORTS_PER_SOL * rent)

// The relay's clamp for a NET amount (lamports, integers): (BASE x 10^4 + RATE x net) / (10^4 - RATE) + 1 with RATE = 40, in exact integer
// arithmetic (api/src/privacycash.ts feeCeiling; gross = net + fee, so the schedule solves to this).
export const feeCeiling = (net) => {
  const rate = BigInt(FEE_RATE_PER_10K + FEE_MARGIN_PER_10K)
  return Number((BigInt(FEE_BASE_LAMPORTS) * 10_000n + rate * BigInt(net)) / (10_000n - rate) + 1n)
}

const num = (v) => typeof v === 'number' && Number.isFinite(v) && v >= 0
// -> { rate, rent, minimumLamports } or throws a plain Error('pc.config: …'). Fail closed on any shape change.
export function checkConfig({ rate, rent, minimum }) {
  if (!num(rate) || !num(rent) || !num(minimum)) throw new Error('pc.config: the relayer config is not numbers (withdraw_fee_rate, withdraw_rent_fee, minimum_withdrawal.sol): refused')
  if (rate > CONFIG_MAX.rate) throw new Error(`pc.config: the relayer's withdraw_fee_rate ${rate} is above the cap ${CONFIG_MAX.rate}`)
  if (rent > CONFIG_MAX.rent) throw new Error(`pc.config: the relayer's withdraw_rent_fee ${rent} SOL is above the cap ${CONFIG_MAX.rent}`)
  if (minimum > CONFIG_MAX.minimumSol) throw new Error(`pc.config: the relayer's minimum withdrawal ${minimum} SOL is above the cap ${CONFIG_MAX.minimumSol}`)
  return { rate, rent, minimumLamports: Math.round(minimum * LAMPORTS_PER_SOL) }
}

// The smallest gross A (lamports) with A - sdkFee(A) >= net. -> { gross, fee, net } where net = A - fee (>= the wanted net).
// Throws pc.amount for a non-integer / non-positive / below-minimum request, pc.fee when the fee is above the relay's clamp.
export function solveGross(wantedNet, cfg) {
  if (!Number.isSafeInteger(wantedNet) || wantedNet <= 0) throw new Error('pc.amount: the amount must be a whole number of lamports above 0')
  if (wantedNet < Math.max(MIN_NET_LAMPORTS, cfg.minimumLamports)) throw new Error(`pc.amount: below the relayer's minimum withdrawal (${Math.max(MIN_NET_LAMPORTS, cfg.minimumLamports)} lamports)`)
  // closed form first (net = gross - gross*rate - rent*1e9), then walk to the exact floor-formula boundary
  let gross = Math.max(wantedNet, Math.ceil((wantedNet + LAMPORTS_PER_SOL * cfg.rent) / (1 - cfg.rate)))
  for (let i = 0; i < 64 && gross - sdkFee(gross, cfg.rate, cfg.rent) < wantedNet; i++) gross += 1
  for (let i = 0; i < 64 && gross - 1 - sdkFee(gross - 1, cfg.rate, cfg.rent) >= wantedNet; i++) gross -= 1
  const fee = sdkFee(gross, cfg.rate, cfg.rent), net = gross - fee
  if (net < wantedNet) throw new Error('pc.amount: could not find a gross amount that nets the wanted amount')
  if (fee > feeCeiling(net)) throw new Error(`pc.fee: the relayer fee ${fee} lamports is above the cap of 0.006 SOL + 0.40 % of the gross (${feeCeiling(net)})`)
  return { gross, fee, net }
}

// The SDK spends at most the TWO largest notes; when they cannot cover gross it does a silent partial withdrawal. Refuse.
export function checkCovered(gross, noteAmounts) {
  const top2 = [...noteAmounts].sort((a, b) => b - a).slice(0, 2).reduce((s, x) => s + x, 0)
  if (gross > top2) throw new Error(`pc.partial: the two largest notes hold ${top2} lamports, below the ${gross} this withdrawal needs (the SDK would withdraw less, silently): ask for less, or consolidate first`)
  return top2
}

export const sol = (lamports) => `${(lamports / LAMPORTS_PER_SOL).toFixed(9).replace(/0+$/, '').replace(/\.$/, '.0')} SOL`

// "0.01" -> 10_000_000 (whole lamports only, up to 9 decimals); anything else -> null
export function parseSol(s) {
  const m = /^(\d{1,9})(?:\.(\d{1,9}))?$/.exec(String(s).trim())
  if (!m) return null
  const v = Number(m[1]) * LAMPORTS_PER_SOL + Number((m[2] ?? '').padEnd(9, '0'))
  return Number.isSafeInteger(v) && v > 0 ? v : null
}

// The linkage disclosure (research D8): shown before EVERY balance check and every withdrawal.
export const LINKAGE_WARNING = 'Checking your Privacy Cash balance sends Privacy Cash\'s relayer the list of your encrypted notes (/utxos/indices). Withdrawing also sends the notes you spend (/merkle/proofv2) and this address (/withdraw). The relayer can therefore link your deposit wallet and amounts to this address. Tor hides your IP, not this link. The relayer cannot change the recipient or amount.'

// @ts-check
// PORTED (R69) from the prototype, tag add7-00927d6ade7f, src/mainnet/constants.js (sha256 8d61bbf682f2cf49b0a1a163f663d1882a72e77b8a3a08d0ab5b3d624a4db0b4).
// Task MQ — every protocol constant used by the fee / part-size / price math, in ONE place.
// Sources: research-tx-optimization.md (2026-10-09, "research") and local measurements on anvil (hardfork Bpo1) and
// solana-test-validator by test/measure-*.mjs ("measured").
export const GWEI = 10n ** 9n
export const ETH = {
  PREFIX: 'data:,',                  // R32: 6 B, kept verbatim. Never `data:;rule=esip6,` (research §5).
  // Recipient: the NULL ADDRESS by default (listed at etherscan.io/address/0x000…000), or a self-send.
  // Value is ALWAYS 0 (code refuses anything else — ETH sent to 0x0 is burned forever). No code at 0x0: measured on anvil,
  // eth_estimateGas to 0x0 = the self-send formula (21000 + 40·n). As an Ethscription the owner becomes 0x0 (burned).
  NULL_ADDRESS: '0x0000000000000000000000000000000000000000',
  RECIPIENT_DEFAULT: 'null',
  TX_DATA_CAP: 98304,                // calldata bytes per tx: PREFIX + optional part prefix + chunk (R14; research §2)
  SIGNED_TX_MAX: 126976,             // guard: serialized signed tx ≤ 124 KiB (mempools cap at 128 KiB) — research §2
  // gasUsed of a value-0 self-send with n non-zero calldata bytes (U+0000 is rejected, so every byte is non-zero):
  //   Prague/Osaka (EIP-7623 floor):          21,000 + 40·n   ← measured on anvil: eth_estimateGas equals this exactly
  //   Amsterdam (EIP-2780 + EIP-7976; Sepolia since 2026-10-06, mainnet TBD): 12,000 + 64·n
  // gasLimit = max of both (valid across the fork; unused gas is refunded). No ×1.2. Funding/plan math budgets +1.5 %.
  GAS_FORMULAS: [{ name: '21000+40n (Prague/Osaka)', base: 21000n, perByte: 40n }, { name: '12000+64n (Amsterdam)', base: 12000n, perByte: 64n }],
  // eth_estimateGas must match one formula within geth's estimator overshoot (eth/gasestimator: optimistic (used+2300)·64/63,
  // bisect until (hi−lo)/hi < 0.015, return hi). MEASURED on mainnet via Tor (publicnode = drpc): +0.78 … +1.35 %. The review
  // (I6) showed the overshoot reaches +1.522 % → tolerance ⌈g·15/985⌉ (= the error ratio relative to hi) refuses no length.
  // Anything below the formula or above it → fail closed. gasLimit = max(formulas, estimate).
  ESTIMATE_TOL_NUM: 15n, ESTIMATE_TOL_DEN: 985n,
  FEE_HISTORY_BLOCKS: 20, TIP_PERCENTILE: 50,          // tip = median of the 20 per-block p50 rewards of eth_feeHistory
  TIP_MIN: GWEI / 10n,               // clamp low: 0.1 gwei
  TIP_CAP_DEFAULT: '3',              // operator cap field (gwei) for the FIRST attempt; replacements may bump to ≈ 2.03× (M10)
  MAXFEE_BASE_MULT: 2n,              // maxFeePerGas = 2 × NEXT block's base fee (last feeHistory baseFeePerGas) + tip
  BUMP_NUM: 1125n, BUMP_DEN: 1000n,  // replacement: ⌈1.125·x⌉ + 1 wei on BOTH tip and maxFee (clients need ≥ +10 %)
  REPLACE_AFTER_BLOCKS: 3n,          // stall = 3 blocks without a receipt (immediately if next base fee > maxFee)
  MAX_BUMPS: 6,                      // per nonce (1.125^6 ≈ 2.03×), then "exhausted"
}
export const SOL = {
  MEMO_PROGRAM: 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr',   // Memo v2, immutable (R31)
  TX_CAP: 1232,                      // signed tx bytes
  // Legacy message, keys [payer, ComputeBudget, Memo v2], memo instruction with ZERO accounts (research §6), ALWAYS both
  // ComputeBudget instructions (setComputeUnitLimit + setComputeUnitPrice). Max memo: 1,010 B (1,062 B without CB).
  // The page derives the same number from the serialized tx (sol.js layoutMaxMemo) and uses the smaller of the two.
  MEMO_MAX: 1010,
  LAMPORTS_PER_SIGNATURE: 5000n,
  CU_PROBE_LIMIT: 1400000,           // provisional limit for the simulation that measures a part's CU
  CU_MAX: 1400000,
  CU_MARGIN_NUM: 11, CU_MARGIN_DEN: 10,   // limit = ⌈1.1 × simulated unitsConsumed⌉
  CU_SPLIT: 1200000,                 // a part whose simulated CU exceeds this is refused (fail closed); the planner keeps parts below it
  // Memo v2 compute cost depends on the CHARACTERS (measured on the local validator, which runs the same MemoSq4 binary;
  // per char: 'a' ≈ 350, '\n' ≈ 330, 'é' ≈ 520, NBSP ≈ 1,000, '€' ≈ 9,100, '漢' ≈ 11,100, '😀' ≈ 17,300 CU; base ≈ 15k).
  // 1,020 B of '€', '漢' or '😀' exceeds 1.4M CU. Conservative per-char upper bounds by UTF-8 width, for the planner:
  CU_BASE: 25000,
  CU_PER_CHAR: [0, 400, 1600, 14000, 22000],
  CU_PLAN_BUDGET: 1200000,
  // CU price = clamp(p90 of the non-zero global getRecentPrioritizationFees values, 100,000, 2,000,000) µlamports/CU;
  // ×2 on each evidence-gated re-sign, capped at 8,000,000. getFeeForMessage of the FINAL message already includes it.
  CU_PRICE_PERCENTILE: 90, CU_PRICE_MIN: 100000, CU_PRICE_MAX: 2000000, CU_PRICE_RESIGN_MULT: 2, CU_PRICE_CAP: 8000000,
  REBROADCAST_MS: 2000,              // resend the same signed bytes every 2 s until confirmed or expired
  MAX_PROCESSING_AGE: 150,           // block height = latest blockhash's lastValidBlockHeight − 150 (at the given commitment)
  MAX_ATTEMPTS: 10,                  // signatures per tx (each re-sign only after proven expiry)
}
export const PRICE = {
  SOURCES: ['https://api.jup.ag/price/v3', 'https://lite-api.jup.ag/price/v3'],   // keyless (≤ 0.5 req/s); lite is being phased out
  MINTS: { SOL: 'So11111111111111111111111111111111111111112',      // wrapped SOL, 9 dp
    ETH: '7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs' },          // Wrapped Ether (Wormhole), 8 dp — Jupiter's ETH proxy
  MIN_LIQUIDITY_USD: 1000000,        // fail closed below $1M
  REFRESH_MS: 30000, MAX_AGE_MS: 120000, RELAY_CACHE_MS: 15000,
}
export const PLAN = {
  MAX_TXS_PER_CHAIN: 200,            // per arm (copies × parts)
  WARN_FACTOR: 10n,                  // warn when the amount is > 10 × the requirement for one copy
  // R60: per-lane hard spend cap (fees) — $10 via Jupiter; native fallback when the price is unavailable/stale.
  // Above it, Arm requires typing the exact planned spend; the engine also stops a lane before a signature would exceed it.
  SPEND_CAP_USD_CENTS: 1000n,
  SPEND_CAP_NATIVE: { eth: 4000000000000000n /* 0.004 ETH */, sol: 70000000n /* 0.07 SOL */, btc: 1000000n /* 0.01 BTC (regtest coins; the local lane has no price) */ },
  // R60: random stagger at zero — random chain order (CSPRNG); the first chain at 0:00, the second after U[30, 300] s.
  STAGGER_MIN_S: 30, STAGGER_MAX_S: 300,
  MAINNET_COUNTDOWN_S: 60,           // R60: mainnet countdown 1:00 with Skip (typed `broadcast` at Arm unchanged)
  DISTINCT_DEFAULT: true,            // R60: distinct copies (every copy indexed) ON by default
  partPrefix: (/** @type {number} */ i, /** @type {number} */ n) => (n > 1 ? `[${i}/${n}] ` : ''),       // ASCII, after `data:,` on ETH; only when the text needs > 1 part
  copySuffix: (/** @type {number} */ i, /** @type {number} */ n) => `\n[copy ${i}/${n}]`,                // ETH option "make copies distinct" (copies 2..N; default off)
  COPY_SUFFIX_MAX: 16,               // bytes of the widest suffix used for cost estimates ("\n[copy 999/999]" = 15 B)
}
export const DECIMALS = { eth: 18, sol: 9, btc: 8, usd: 2 }

// ---------- R64 "until drained" lanes: economy fee ladder ----------
// ETH: tip₀ = max(TIP_FLOOR, median over the last 20 blocks of the per-block p10 reward); maxFee = 2 × next base + tip.
// TIP_FLOOR is MEASURED (mainnet, read-only via Tor, 2026-10-09): eth_maxPriorityFeePerGas = 0.000012 gwei = 12,000 wei
// on BOTH verified endpoints (publicnode, drpc — geth's oracle reports the lowest tips actually included), and the
// per-block p5/p10 reward medians over 20 blocks were 12,000 wei (p10 over 100 blocks: 100,000 wei; p1: 0). Pools accept
// ≥ 1 wei (geth txpool PriceLimit); 12,000 wei is the lowest tip seen INCLUDED in recent blocks.
export const ECON = {
  ETH_TIP_FLOOR: 12000n,
  ETH_FEE_HISTORY_PCTS: [10, 50],
  ETH_TIP_CAP_DEFAULT: '3',            // gwei — per-tx cap; the ladder PAUSES there (operator Resume after raising, or Stop)
  ETH_TIGHT_NUM: 125n, ETH_TIGHT_DEN: 100n,   // final copy: maxFee = ⌈1.25 · base⌉ + tip when 2·base + tip is unaffordable
  LEARN_NUM: 1000n, LEARN_DEN: 1125n,  // next copy starts at max(tip₀, last included tip ÷ 1.125) — probes back down
  // SOL rungs: P₀ = 0 (no SetComputeUnitPrice, CU limit still set), then p25/p50/p75/p90 of the NON-ZERO
  // getRecentPrioritizationFees([payer, Memo v2]), capped at 2,000,000 µL/CU. Measured on mainnet 2026-10-09 for
  // [Memo v2]: 6/150 slots non-zero → p25 151,992 · p50 170,300 · p75 187,500 · p90 202,657 µL/CU.
  SOL_RUNG_PCTS: [25, 50, 75, 90],
  SOL_RUNG_CAP: 2000000,
  SOL_FALLBACK_RUNGS: [100000, 500000, 1000000, 2000000],   // when the RPC reports no non-zero fees (e.g. a quiet localnet)
  // Payer end state (MEASURED locally, test/measure-sol-payer.mjs): after any tx the fee payer must hold ≥ the rent-exempt
  // minimum or exactly 0. rent+5000 → memo → rent: accepted; rent+4999 → memo: InsufficientFundsForRent; a transfer of
  // balance − fee (ends at 0): accepted; leaving 1 lamport: refused. Mainnet minimum (0 data) = 650,240 = 128 B × 2 years ×
  // 2,540 lamports/byte-year (localnet 890,880 = 128 × 2 × 3,480, the old default).
  // R64 (measured on the local validator, simulateTransaction): the FEE PAYER must keep ≥ the rent-exempt minimum after
  // the fee is taken — before any instruction runs — or be exactly 0 (rent+3000 → transfer to 0: InsufficientFundsForRent;
  // rent+5000 → OK). So a drained lane keeps rent + one claw-back fee (5000 lamports, 1 signature, no priority fee):
  // its remainder can always be clawed back to 0 lamports.
  SOL_CLAW_RESERVE: 5000n,
  SOL_INCINERATOR: '1nc1nerator11111111111111111111111111111111',
  ETH_CLAW_GAS: 21000n,
}
export const LANE = {
  MODES: ['drain', 'copies'],
  MODE_DEFAULT: 'drain',
  drainSuffix: (/** @type {number} */ i) => `\n[copy ${i}]`,           // drain: N is unknown, so no "/N"
}

// ---------- canonical engine constants (E2) — not in the contracts yet; listed in task-E2-report.md for CC-1 ----------
// Source: publication-modes-elite.md (Task PM, R73 rehearsal, 2026-10-09: "PM") §0 findings 1–4 and §6.
export const CANON = {
  // Passive fee strategy, ETH (PM §6, findings 2–3): target T = p10 of the trailing 7,200 base fees (24 h), refreshed
  // every 300 blocks (8 × eth_feeHistory(1024, …, [])); tip 0.001 gwei; sign only when the next base fee ≤ T, with
  // maxFee = T + tip; never escalate: a stall keeps the same signed bytes and rebroadcasts them every 25 blocks.
  PASSIVE_ETH_TIP: 1000000n,
  PASSIVE_ETH_WINDOW_BLOCKS: 7200,
  PASSIVE_ETH_TARGET_PCT: 10,
  PASSIVE_ETH_REFRESH_BLOCKS: 300,
  FEE_HISTORY_MAX_BLOCKS: 1024,
  PASSIVE_ETH_REBROADCAST_BLOCKS: 25n,
  // PF-E (pre-flip review I-2): a Passive attempt that no verified endpoint knows, its nonce unused, at the end of this many windows in a
  // row (3 × 25 blocks, about 15 minutes on mainnet) of same-bytes rebroadcasts is journaled `stuck` (vt job resolve): never an endless wait.
  PASSIVE_ETH_UNSEEN_WINDOWS: 3,
  // Fix round 2 (M-4): after a Stop, a SOL signature neither confirmed nor proven expired on every verified endpoint this long after the
  // Stop (one endpoint failing its reads blocks the all-endpoint proof) is journaled `stuck`: the run ends in bounded time.
  SOL_STOP_PROOF_MS: 300_000,
  // ETH claw-back gas by destination class (PM finding 1): pre-Amsterdam 21,000 to any account without code; Amsterdam
  // 21,000 to an existing account and 204,600 to an EMPTY one (nonce 0, balance 0, no code: + EIP-8037 new account).
  // A destination with code is refused. eth_estimateGas must match the class within the 15/985 tolerance (fail closed).
  ETH_CLAW_GAS_EXISTING: 21000n,
  ETH_CLAW_GAS_EMPTY_AMSTERDAM: 204600n,
  // SOL priority in LAMPORTS PER TX (PM finding 4: Memo v2 costs ≈ 350 CU per ASCII byte, so µL/CU rungs overpay 4–6×).
  // A rung of L lamports prices a part at ⌈L·10⁶ / its CU limit⌉ µL/CU, capped by the lane's maxCuPrice. Rung 0 = no
  // SetComputeUnitPrice (passive). Measured per-tx market priority (mainnet, 5 sampled blocks): p50 ≈ 160, p90 ≈ 12,500
  // lamports; the middle rung is their geometric mean (≈ 1,400). Prompt starts at the p90 rung, ×2 per proven expiry.
  SOL_RUNG_LAMPORTS: [0, 160, 1400, 12500],
  SOL_PROMPT_LAMPORTS: 12500,
  // A stored relay send ticket (TTL 120 s, contracts TICKET_TTL_MS) is refreshed before re-sending identical bytes
  // once it is this old (needs journal.ticket; without it the stored ticket is reused and the relay may refuse it).
  TICKET_REFRESH_MS: 90000,
}

// ---------- R71 per-network facts (P2 delta: prototype tag add7b-e540f8ae4d6b src/mainnet/networks.js, E3) ----------
// What the engine and the page need per network beyond identity: labels, the Tor and price policy, the measured tip
// floors, explorer link bases (links.js builds the links) and the testnet funding steps. Identity pins (chain ids,
// genesis hashes) stay in vt-broadcast/src/config.ts and RPC endpoints in broadcast/endpoints.json (one source each);
// the Ethereum fork schedule is contracts/network.ts.
export const TEST_FUNDS_LABEL = 'TEST FUNDS — NO VALUE'
// explorer.solana.com honours a loopback customUrl only when Chrome lets the site reach local devices — since Chrome 145
// that site setting is "Apps on device" (Chrome 142–144: "Local network access") (prototype networks.js, controller D).
export const LOCAL_SOL_EXPLORER_NOTE = 'allow “Apps on device” for explorer.solana.com in Chrome’s site settings (Chrome 142–144: “Local network access”) — your Solana txs stay viewable because the local validator now keeps history'
export const NETWORK = {
  local: {
    id: 'local', label: 'LOCAL', sub: 'anvil 31337 · solana-test-validator · same code as mainnet', tor: false,
    price: { kind: 'fixture', note: 'local fixture price' },
    eth: { name: 'anvil (local 31337)', tipFloor: 12000n, passiveTip: 1000000n, explorer: { name: 'Otterscan (local)', base: 'http://127.0.0.1:5100', open: true } },
    sol: { name: 'solana-test-validator (local)', explorer: { cluster: 'custom', customUrl: 'http://127.0.0.1:8999' }, airdrop: null },
  },
  testnet: {
    id: 'testnet', label: 'TESTNET', sub: 'Ethereum Sepolia · Solana devnet · test funds — no value', tor: true,
    price: { kind: 'none', note: TEST_FUNDS_LABEL },
    // tipFloor: measured (2026-10-09, via Tor): p1 of every block and eth_maxPriorityFeePerGas = 0.001 gwei on Sepolia
    eth: { name: 'Ethereum Sepolia', tipFloor: 1000000n, passiveTip: 1000000n, explorer: { name: 'Sepolia Etherscan', base: 'https://sepolia.etherscan.io', open: false },
      faucets: [['Google Cloud Web3 faucet (Sepolia)', 'https://cloud.google.com/application/web3/faucet/ethereum/sepolia'], ['Alchemy Sepolia faucet', 'https://www.alchemy.com/faucets/ethereum-sepolia'], ['PoW faucet (no account)', 'https://sepolia-faucet.pk910.de']] },
    sol: { name: 'Solana devnet', explorer: { cluster: 'devnet' }, airdrop: { maxLamports: 1000000000n, faucet: 'https://faucet.solana.com' } },
  },
  mainnet: {
    id: 'mainnet', label: 'MAINNET', sub: 'real funds · publication is public and permanent', tor: true,
    price: { kind: 'jupiter', note: 'Jupiter via Tor' },
    eth: { name: 'Ethereum mainnet', tipFloor: 12000n, passiveTip: 1000000n, explorer: { name: 'Etherscan', base: 'https://etherscan.io', open: false } },
    sol: { name: 'Solana mainnet-beta', explorer: { cluster: null }, airdrop: null },
  },
}
// The table row of an injected network; any other value is refused (never another network's facts).
/** @param {string} network */
export function networkOf(network) {
  if (network !== 'local' && network !== 'testnet' && network !== 'mainnet') throw new RangeError(`unknown network "${network}"`)
  return NETWORK[network]
}

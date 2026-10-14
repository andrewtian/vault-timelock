// Publication-mode presentation data (R73). The MODE rows themselves (permanence class, trust note, status, size per
// tx) come from the contracts' PUBLISH_MODES at render time and are never copied here. What is here is the editorial
// layer of publication-modes-elite.md (Task PM, 2026-10-09): the elite set, UI labels, "when to choose", and the
// measured Passive / Economy / Prompt cost notes. Prices are those of the day (ETH $2,477.56, SOL $108.94, 7-day
// mainnet fee distribution to 2026-10-09 19:53 UTC); they date quickly and are shown with their date.
export const COST_AS_OF = '2026-10-09'

// §5 "Elite set". Anything in PUBLISH_MODES that is not listed here is shown as a reserved fallback.
export const ELITE = {
  'eth.calldata.null': { label: 'Ethscription (to 0x0)', when: 'always, unless a reason below applies (the default)', strategy: 'passive for “until drained”, economy for “copies N”' },
  'eth.calldata.self': { label: 'Ethscription (owned by the lane key)', when: 'you want the lane key to own the inscriptions, or want the 3,000 gas/tx saving after Glamsterdam', strategy: 'same as 0x0' },
  'eth.sstore2': { label: 'Contract storage (state copy)', when: 'an extra copy that survives history expiry; best for texts up to 10 KB', strategy: 'passive',
    warning: 'Not an ethscription and not shown as text. Costs 5× calldata today and 24× after Glamsterdam (100 KB ≈ $5.7 now, ≈ $41 then, passive).' },
  'sol.memo': { label: 'Memo (text in Solana history)', when: 'always (the default)', strategy: 'passive for drain, economy for copies N, with lamport-denominated rungs' },
  'sol.arweave-anchor': { label: 'Arweave copy + Solana anchor', when: 'long texts (100 KB = 1 Solana tx instead of 104), or when durability matters more than reading on Solana', strategy: 'passive (1 tx)' },
  'sol.account': { label: 'Solana state (permanent)', when: 'an on-Solana copy every validator must keep', strategy: 'passive',
    warning: 'Locks about 0.0051 SOL of rent per KB forever (about $0.56/KB today). Not shown as text in explorers. Needs the operator\'s consent to the rent lock.' },
}

// Plain-language meaning of each permanence class (contracts PERMANENCE_CLASSES).
export const PERMANENCE_NOTE = {
  state: 'Kept in chain state: every full node/validator must hold it; no expiry is scheduled.',
  history: 'Kept in chain history: full nodes or validators hold it today; archives or a history-expiry change may decide later.',
  arweave: 'Kept by the Arweave endowment: depends on the upload service and the Arweave network.',
  ephemeral: 'Pruned on a protocol schedule (blobs, about 18 days). No elite mode uses it: eth.blob was dropped for this reason.',
}

// §6 "Fee strategy": what each does, then the measured cost per unit on mainnet today.
export const STRATEGIES = [
  { id: 'passive', name: 'Passive', what: 'Unattended and patient, lowest cost. ETH: tip at the measured floor (0.001 gwei), signs only when the next base fee is at or under the 10th percentile of the trailing 24 h, never escalates. SOL: priority fee 0 always; re-signs only after proven expiry, still at price 0.',
    wait: 'ETH first send opportunity: median 95 min, 90th percentile 12.5 h, worst seen 20.4 h. Keep the tab open (or run vt job run). SOL: no wait.', default: 'the default for “until drained”' },
  { id: 'economy', name: 'Economy', what: 'The R64 ladder: sends without waiting for a cheap window (priced at the average base fee, about 0.47 gwei) and bumps only when a send stalls. SOL starts at priority 0 too and moves to rung 1 only after an expiry.',
    wait: 'Minutes. Costs about 4–5× Passive on ETH; SOL rungs cost more only after an expiry.', default: 'the default for “copies N”' },
  { id: 'prompt', name: 'Prompt', what: 'The old p50/p90 behaviour: pays for quick inclusion (ETH base plus a tip of at least 0.1 gwei).',
    wait: 'Next blocks. Highest cost.', default: 'never a default' },
]

// §6 "Expected cost per tx and per KB, mainnet today" (USD at the prices above; the ETH rows are pre-Glamsterdam).
export const COSTS = [
  { chain: 'ETH', unit: 'minimal tx (21,000 gas, e.g. a claw-back)', passive: '$0.0053', economy: '$0.0245', prompt: '$0.0297' },
  { chain: 'ETH', unit: '1 KB part (62,200 gas)', passive: '$0.0158 ($0.0205 after the fork)', economy: '$0.0727', prompt: '$0.0881' },
  { chain: 'ETH', unit: 'full 98,304 B part (3,953,160 gas)', passive: '$1.00 ($1.60 after the fork)', economy: '$4.62', prompt: '$5.60' },
  { chain: 'ETH', unit: 'per KB, marginal (40 gas/byte)', passive: '$0.0104', economy: '$0.048', prompt: '$0.058' },
  { chain: 'SOL', unit: 'any tx (1 signature, 5,000 lamports base)', passive: '$0.000545', economy: 'starts at 0 priority; after an expiry rung 1 is $0.0071 per 1 KB memo part', prompt: '$0.0092 per 1 KB memo part' },
  { chain: 'SOL', unit: 'per KB of memo (1,010 B parts)', passive: '$0.00055', economy: 'as above', prompt: 'as above' },
]

// packages/core/src/contracts/publish.ts — publication modes and fee strategies (R73, controller rulings 3–4; CC-1 at
// I1 from publication-modes-elite.md, the rehearsed elite set).
//
// `publishMode` names HOW the bytes are published. It REPLACES the old `recipient` field: eth.calldata.null and
// eth.calldata.self are the recipient choice (one source of truth). The list is DATA-DRIVEN: one table, one row per
// mode, with capability flags. Adding or enabling a mode is a contract change to this table only (bump
// PUBLISH_MODES_VERSION). Reserved modes are refused by the job validator with `job.publish-mode-unavailable`; an
// unknown id (including the dropped eth.calldata.raw, eth.log, eth.blob and the renamed arweave.irys), or a mode on a
// chain its row does not list, with `job.publish-mode`. Neither publishMode nor feeStrategy changes a job's network
// binding or any gate.
//
// Flags (reserved rows carry the rehearsed capabilities; each is enabled by its own E-lane task and loop):
//   permanence       who must keep the bytes (PERMANENCE_CLASSES): 'state' (chain state, no expiry scheduled),
//                    'history' (chain history: full nodes / validators today, archives later), 'arweave' (the Arweave
//                    endowment), 'ephemeral' (pruned on a protocol schedule, e.g. blobs ~18 days)
//   trustNote        what that permanence depends on, in one sentence (shown beside the mode)
//   indexedAsText    common explorers/indexers show the bytes as text
//   maxBytesPerTx    bytes of payload per transaction (header included); null = no fixed size (sized by simulation
//                    per tx, or the text is not in the chain tx at all: the arweave rows)
//   needsContract    needs an on-chain program/contract beyond the chain's built-ins (system, Memo v2, the native
//                    BPF loaders)
//   browserSignable  the browser executor can build and sign it with the pinned libraries
import type { Chain, Mode } from './types.ts'

export const PUBLISH_MODES_VERSION = 'vt-publish/3'   // /3 (E7b, CC-12): + btc.inscription

export const PERMANENCE_CLASSES = ['state', 'history', 'arweave', 'ephemeral'] as const
export type Permanence = typeof PERMANENCE_CLASSES[number]

export const PUBLISH_MODE_IDS = [
  'eth.calldata.null', 'eth.calldata.self', 'sol.memo',
  'btc.inscription',
  'eth.sstore2', 'sol.arweave-anchor', 'sol.account', 'sol.noop', 'arweave.turbo',
] as const
export type PublishMode = typeof PUBLISH_MODE_IDS[number]

export interface PublishModeRow {
  readonly id: PublishMode
  readonly chains: readonly Chain[]
  readonly status: 'available' | 'reserved'
  readonly permanence: Permanence
  readonly trustNote: string
  readonly indexedAsText: boolean
  readonly maxBytesPerTx: number | null
  readonly needsContract: boolean
  readonly browserSignable: boolean
  readonly note: string
}

const HISTORY_ETH = 'Kept in Ethereum history by full nodes today; EIP-4444 may let nodes drop old history. The Ethscriptions AppChain keeps a decoded state copy.'

export const PUBLISH_MODES: readonly PublishModeRow[] = [
  { id: 'eth.calldata.null', chains: ['eth'], status: 'available', permanence: 'history', trustNote: HISTORY_ETH,
    indexedAsText: true, maxBytesPerTx: 98_304, needsContract: false, browserSignable: true,
    note: 'data:, + text as calldata to 0x0, value 0 (the default, R62). Ethscription owned by 0x0, creator = the key.' },
  { id: 'eth.calldata.self', chains: ['eth'], status: 'available', permanence: 'history', trustNote: `${HISTORY_ETH} The lane key owns the inscriptions and could transfer them.`,
    indexedAsText: true, maxBytesPerTx: 98_304, needsContract: false, browserSignable: true,
    note: 'data:, + text as calldata to the key itself, value 0.' },
  { id: 'sol.memo', chains: ['sol'], status: 'available', permanence: 'history',
    trustNote: 'Not guaranteed long-term: validators keep only recent ledger; older history depends on providers\' archives (BigTable, Old Faithful).',
    indexedAsText: true, maxBytesPerTx: null, needsContract: false, browserSignable: true,
    note: 'Memo v2, part size by simulation (bytes and CU). The default.' },
  { id: 'btc.inscription', chains: ['btc'], status: 'available', permanence: 'history',
    trustNote: 'Kept in Bitcoin history (the reveal\'s witness) by full nodes; pruned nodes may drop it, and ordinals indexers show it as an inscription. Local regtest only for now.',
    indexedAsText: true, maxBytesPerTx: 100_000, needsContract: false, browserSignable: true,
    note: 'An ordinals text inscription (content type text/plain;charset=utf-8): a commit tx and a reveal tx per copy, 546 sat postage back to the lane key. Copies mode only (no drain).' },
  { id: 'eth.sstore2', chains: ['eth'], status: 'reserved', permanence: 'state',
    trustNote: 'Kept in Ethereum state (no expiry scheduled). Not an ethscription; chunk addresses derive from the lane key and nonce.',
    indexedAsText: false, maxBytesPerTx: 10_599, needsContract: false, browserSignable: true,
    note: 'Contract storage (state copy): a plain CREATE whose 14-byte initcode returns 0x00 ‖ part as runtime code (no factory, no deployed contract); 10,599 B per chunk (post-Glamsterdam safe); gas by eth_simulateV1. Elite option, enabled later.' },
  { id: 'sol.arweave-anchor', chains: ['sol'], status: 'reserved', permanence: 'arweave',
    trustNote: 'The text is on Arweave, not on Solana: it depends on the Turbo upload and the Arweave network; Solana carries only its id and sha256.',
    indexedAsText: true, maxBytesPerTx: null, needsContract: false, browserSignable: true,
    note: 'Arweave copy + Solana anchor: the text as one ANS-104 item (Turbo, R11 funding), and one SOL tx per copy with the anchor memo [ar:<43-char id> sha256=<64hex> bytes=<n>]. Elite option for long texts, enabled later.' },
  { id: 'sol.account', chains: ['sol'], status: 'reserved', permanence: 'state',
    trustNote: 'Kept in Solana state while rent-exempt; the rent (about 0.0051 SOL per KB) is locked forever. Native loader, no third-party upgrade key; a future loader-v3 deprecation could stop NEW buffers (existing ones stay).',
    indexedAsText: false, maxBytesPerTx: 972, needsContract: false, browserSignable: true,
    note: 'Loader-v3 buffer (BPFLoaderUpgradeable): createAccount + InitializeBuffer, Write <= 972 B per tx, then SetAuthority to an unsignable key (frozen). Gated behind a devnet loop and the operator\'s consent to the rent lock.' },
  { id: 'sol.noop', chains: ['sol'], status: 'reserved', permanence: 'history',
    trustNote: 'Solana history only, as memo; the Noop program is upgradeable by its authority.',
    indexedAsText: false, maxBytesPerTx: null, needsContract: true, browserSignable: true,
    note: 'SPL Noop instruction data: a fallback if zero-priority memo txs stop landing; not shown as text.' },
  { id: 'arweave.turbo', chains: ['eth', 'sol'], status: 'reserved', permanence: 'arweave',
    trustNote: 'Depends on the Turbo upload service and the Arweave network (endowment, ~200-year design).',
    indexedAsText: true, maxBytesPerTx: null, needsContract: false, browserSignable: true,
    note: 'Arweave copy uploaded through Turbo (renamed from arweave.irys: the Irys SDK is deprecated); credits per R11.' },
]

// Job-level Arweave copy (`arweaveCopy`, types.ts JobInput/JobDef; publication-modes-elite.md §5, the hybrid): when on,
// the message is also uploaded to Arweave on the existing R11 Turbo pipeline (credits from Railgun ETH, the
// arweave-<job> key signs; never a second payment path from a lane key), and every sol.memo lane appends one anchor
// memo `[ar:<43-char id> sha256=<64hex> bytes=<n>]` after the last part of copy 1. Reserved like a reserved mode:
// `arweaveCopy: true` is refused job.publish-mode-unavailable until this status is 'available'.
export const ARWEAVE_COPY: { readonly status: 'available' | 'reserved'; readonly permanence: Permanence; readonly trustNote: string } = {
  status: 'reserved', permanence: 'arweave',
  trustNote: 'An extra copy on Arweave; it depends on the Turbo upload and the Arweave network.',
}

export const DEFAULT_PUBLISH_MODE: Readonly<Record<Chain, PublishMode>> = { eth: 'eth.calldata.null', sol: 'sol.memo', btc: 'btc.inscription' }

export function publishModeRow(id: string): PublishModeRow | undefined {
  return PUBLISH_MODES.find((r) => r.id === id)
}
// The ids a chain may name (available and reserved): the schema's per-chain enum.
export function publishModesFor(chain: Chain): PublishMode[] {
  return PUBLISH_MODES.filter((r) => r.chains.includes(chain)).map((r) => r.id)
}

// Fee strategy (R73). The numbers belong to the engine (E2/E3: chains/constants.js CANON), not to the contracts.
//   passive  unattended, lowest cost per tx. ETH: tip at the measured floor, maxFee at a low base-fee target, waits
//            for cheap blocks, never escalates above the floor tip, a time budget instead of bumps. SOL: priority fee 0
//            always; re-sign only after proven expiry, still at price 0.
//   economy  the R64 ladder.
//   prompt   the old p50/p90 behaviour.
export const FEE_STRATEGIES = ['passive', 'economy', 'prompt'] as const
export type FeeStrategy = typeof FEE_STRATEGIES[number]
export function defaultFeeStrategy(mode: Mode): FeeStrategy {
  return mode === 'drain' ? 'passive' : 'economy'
}

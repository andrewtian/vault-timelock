// packages/core/src/contracts/network.ts — network names and the per-network table (Task 0; ruling 6).
// Chain identities (chain ids, genesis hashes) stay in vt-broadcast/src/config.ts (one source, C2). This table holds
// what the engine needs per network beyond identity: the Ethereum fork activation.
import type { Network } from './types.ts'
import { refuse } from './guard.ts'

export const NETWORKS: readonly Network[] = ['local', 'testnet', 'mainnet']

export function isNetwork(v: unknown): v is Network {
  return v === 'local' || v === 'testnet' || v === 'mainnet'
}

export function assertNetwork(v: unknown): asserts v is Network {
  const ok = v === 'local' || v === 'testnet' || v === 'mainnet'
  if (!ok) refuse('contract.network', 'network must be local, testnet or mainnet') // @guard:contract.network
}

// Amsterdam (EIP-2780 + EIP-7976) changes the intrinsic gas of every data tx (contracts/gas.ts).
//   local    false: anvil's default is pre-Amsterdam. An Amsterdam-capable anvil sets the override (local only).
//   testnet  true: Sepolia runs Amsterdam (since 2026-10-06).
//   mainnet  false until a reviewed contract change flips it. Until then the engine's estimate check fails closed on
//            Amsterdam gas, and checkForkDrift names the cause ("Amsterdam appears active on mainnet — update required").
export interface EthForkRow { readonly amsterdam: boolean; readonly overridable: boolean }
export const ETH_FORKS: Readonly<Record<Network, EthForkRow>> = {
  local: { amsterdam: false, overridable: true },
  testnet: { amsterdam: true, overridable: false },
  mainnet: { amsterdam: false, overridable: false },
}

// The fork the engine must assume on `network`. `localOverride` (e.g. a harness running an Amsterdam anvil) is
// accepted on local only; anywhere else it is refused, so a flag can never move a public network's fork.
export function ethAmsterdam(network: Network, o: { localOverride?: boolean } = {}): boolean {
  assertNetwork(network)
  const ok = o.localOverride === undefined || ETH_FORKS[network].overridable
  if (!ok) refuse('contract.fork-override', 'the Amsterdam override applies to the local network only') // @guard:contract.fork-override
  return o.localOverride ?? ETH_FORKS[network].amsterdam
}

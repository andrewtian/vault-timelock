// packages/core/src/chains/types.ts — JSDoc types for the ported (`// @ts-check`) chain and engine modules (E2).
// Types only (erasable): the .js modules import them with `@typedef {import('./types.ts').X} X`.
import type { PrivateKeyAccount } from 'viem/accounts'
import type { Keypair } from '@solana/web3.js'

export type Bytes = Uint8Array
// One planned part of one copy: i of n, the text chunk and the exact payload bytes (lead + header + chunk).
export interface Part { i: number; n: number; chunk: Uint8Array; payload: Uint8Array }
// One planned transaction (buildPlan): copy-major order.
export interface PlanTx { k: number; copy: number; part: number; parts: number; payload: Uint8Array; textBytes: number }
export interface EthKey { chain: 'eth'; account: PrivateKeyAccount; address: string; secret: string }
export interface SolKey { chain: 'sol'; kp: Keypair; address: string; secret: string }
// E7b: the BTC lane key (chains/btc.js btcFromSecret): the secret is non-enumerable
export interface BtcKey { chain: 'btc'; network: 'local' | 'testnet' | 'mainnet'; address: string; pubkey: string; xonly: string; p2tr: string; readonly secret: string }
export type Key = EthKey | SolKey | BtcKey
export interface Link { label: string; url: string; note?: string; open: boolean }
// The relay's /relay/price answer (the prototype's shape).
export interface PriceData { prices: Record<string, { usd: number; liquidity?: number | null; mint: string }>; fetchedAt: number; source?: string; fixture?: boolean }
// A JSON-RPC answer is untyped by nature: the modules narrow what they read.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Json = any

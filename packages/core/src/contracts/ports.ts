// packages/core/src/contracts/ports.ts — fixed ports and limits (Task 0, verbatim). Tests bind port 0 only.
// A lease is live while now < expiresAt (expiresAt = acquire/renew time + LEASE_TTL_MS); at expiresAt it has expired.
// A ticket is valid while now < e (e = issue time + TICKET_TTL_MS).
export const PORTS = {
  local: { page: 5180, relay: 5181, api: 5182, dev: 5183 },
  testnet: { page: 5190, relay: 5191, api: 5192, dev: null },
  mainnet: { page: 5200, relay: 5201, api: 5202, dev: null },
} as const
export const LEASE_TTL_MS = 15_000, LEASE_RENEW_MS = 5_000, TICKET_TTL_MS = 120_000
export const API_JSON_CAP = 65_536, MESSAGE_MAX = 16 * 1024 * 1024, SSE_HEARTBEAT_MS = 15_000
export const MAINNET_COUNTDOWN_S = 60, STAGGER_S = [30, 300] as const, COUNTDOWN_RANGE_S = [5, 300] as const

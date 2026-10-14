// Network roles (spec B s6.1 "Circuit isolation"). Every request carries the SOCKS username
// `<role>.<tick>`, so Tor's IsolateSOCKSAuth gives each role its own circuit, rotating per tick.
// The side of a role drives the temporal separation guard in fetch.ts: a tick never makes
// deposit-side requests and publication-side requests.
import { refuse } from '../guard.ts'

export type Role = string
export type Side = 'deposit' | 'publication' | 'neutral'

const ROLE = /^(d-railgun-eth|pool-railgun-eth|pub-[a-z0-9-]+-(eth|arb|base|sol|btc)|l1hop-[a-z0-9-]+|l2-[a-z0-9-]+-(arb|base)|btcw-[a-z0-9-]+|btck-[a-z0-9-]+|swap-[a-z0-9-]+|arweave-[a-z0-9-]+|waku-[a-z0-9-]+|drand|check|artifacts)$/

// Keeps `<role>.<tick>` well under the 255-byte RFC 1929 username limit.
export const ROLE_MAX = 96

// First '-'-separated segment -> side. Every role the grammar accepts has an entry.
const SIDE: Readonly<Record<string, Side>> = {
  d: 'deposit',
  pub: 'publication', l1hop: 'publication', l2: 'publication', btcw: 'publication', btck: 'publication',
  swap: 'publication', arweave: 'publication', waku: 'publication',
  pool: 'neutral', drand: 'neutral', check: 'neutral', artifacts: 'neutral',
}

const head = (role: string): string => role.split('-')[0]

// The role value is never echoed: a caller bug must not put arbitrary text into an error message.
export function assertRole(role: unknown): asserts role is Role {
  const ok = typeof role === 'string' && role.length <= ROLE_MAX && ROLE.test(role) && Object.hasOwn(SIDE, head(role))
  if (!ok) refuse('net.role', 'not a network role (see src/net/roles.ts for the grammar)') // @guard:net.role
}

export function sideOf(role: Role): Side {
  assertRole(role)
  return SIDE[head(role)]
}

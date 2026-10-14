// api/src/args.ts — the API's command line, and the one refusal for malformed arguments (CLI flags and query
// parameters alike: api.args).
//
//   node api/src/main.ts --network <local|testnet|mainnet> --home <VT_HOME> [--build <id>] [--port 0 (tests only)]
//
// Every flag appears at most once and takes exactly one value. Values are never echoed: a refusal names the problem,
// not the input. The network name is checked by the contracts (contract.network).
import { isAbsolute } from 'node:path'
import { assertNetwork } from '@vault-timelock/core/contracts'
import type { Network } from '@vault-timelock/core/contracts'
import { refuse } from 'vt-broadcast/src/guard.ts'
import { assertTestMode } from './clock.ts'

export interface ApiArgs {
  network: Network
  home: string
  build: string
  // null: the network's fixed API port (PORTS[network].api). 0 only in tests (an ephemeral port).
  port: 0 | null
}

const FLAGS = new Set(['--network', '--home', '--build', '--port'])
const BUILD = /^[A-Za-z0-9._-]{1,64}$/
export const DEFAULT_BUILD = 'dev'

// The single api.args refusal (CLI arguments and HTTP query parameters).
export function assertArgs(ok: boolean): asserts ok {
  if (!ok) refuse('api.args', 'invalid arguments (usage: --network <local|testnet|mainnet> --home <absolute dir> [--build <id>]); the values are not echoed') // @guard:api.args
}

export function parseArgs(argv: readonly string[]): ApiArgs {
  const seen = new Map<string, string>()
  let wellFormed = argv.length % 2 === 0
  for (let i = 0; wellFormed && i < argv.length; i += 2) {
    const flag = argv[i], value = argv[i + 1]
    wellFormed = FLAGS.has(flag) && !seen.has(flag) && typeof value === 'string' && value !== '' && !value.startsWith('--')
    if (wellFormed) seen.set(flag, value)
  }
  const home = seen.get('--home')
  const build = seen.get('--build') ?? DEFAULT_BUILD
  const port = seen.get('--port')
  assertArgs(wellFormed && seen.has('--network') && home !== undefined && isAbsolute(home) && !home.includes('\0')
    && BUILD.test(build) && (port === undefined || port === '0'))
  const network: unknown = seen.get('--network')
  assertNetwork(network)
  if (port !== undefined) assertTestMode()
  return { network, home: home!, build, port: port === undefined ? null : 0 }
}

// A non-negative sequence number in a query parameter or header: decimal, no sign, at most 15 digits (a safe integer).
export function parseSeq(v: string): number | null {
  return /^(?:0|[1-9][0-9]{0,14})$/.test(v) ? Number(v) : null
}

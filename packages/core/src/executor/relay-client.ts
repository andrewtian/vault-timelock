// packages/core/src/executor/relay-client.ts — the executor's client of its stack's relay (spec §6.1): the page uses
// base '' (its own origin, the page server proxies /relay/*), the CLI http://127.0.0.1:<relay port>. One HTTP
// implementation for JSON-RPC (engine/rpc.js relayRpc), so the engine's failure classes hold for both executors:
// RpcError (definitive upstream answer), RelayRefused (refused before forwarding), TransportError (no definitive answer).
import type { Chain, Network, RelayClient, RelayStatus } from '../contracts/index.ts'
import { isNetwork } from '../contracts/index.ts'
import { RelayRefused, TransportError, relayRpc } from '../engine/rpc.js'
import type { Fetch } from './journal-client.ts'

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v)

export function httpRelayClient(o: { base: string; fetch: Fetch }): RelayClient {
  if (typeof o?.base !== 'string' || typeof o.fetch !== 'function') throw new TypeError('httpRelayClient: { base, fetch } required')
  const cfg = { base: o.base, fetch: o.fetch as (url: string, init: RequestInit) => Promise<Response> }
  async function get(p: string): Promise<unknown> {
    let r: Response
    try { r = await o.fetch(`${o.base}${p}`, { method: 'GET', cache: 'no-store' }) } catch (e) { throw new TransportError(`relay unreachable (${String((e as Error).message).slice(0, 80)})`) }
    const j: unknown = await r.json().catch(() => null)
    if ([403, 413, 503].includes(r.status)) throw new RelayRefused(`relay refused (${r.status})`)
    if (!r.ok || j === null) throw new TransportError(`relay HTTP ${r.status}`)
    return j
  }
  return {
    async status() {
      const j = await get('/relay/status')
      const ok = isObj(j) && isNetwork(j.network) && isObj(j.identity) && isObj(j.endpoints)
      if (!ok) throw new TransportError('relay status: not a RelayStatus')
      return j as unknown as RelayStatus & { network: Network }
    },
    rpc: (chain: Chain, method: string, params: unknown[], x?: { ticket?: string; ep?: number }) => relayRpc(cfg, chain, method, params, x ?? {}),
    async tor() {
      const j = await get('/relay/tor')
      const t = isObj(j) ? j.isTor : undefined
      const roles: unknown = isObj(j) ? j.torRoles : undefined
      const isTor = t === true ? true : t === false ? false : null
      return Array.isArray(roles) && roles.every((r) => typeof r === 'string') ? { isTor, torRoles: roles as string[] } : { isTor }
    },
    async price() {
      const j = await get('/relay/price')
      if (!isObj(j) || !isObj(j.prices)) throw new TransportError('relay price: no prices')
      return j as unknown as { fixture: boolean; source: string; prices: Record<'SOL' | 'ETH', { usd: number }>; fetchedAt?: number }
    },
  }
}

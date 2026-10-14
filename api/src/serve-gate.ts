// api/src/serve-gate.ts — the page server's gates and its proxy headers (spec §6.2, S1 review N3), in TypeScript so the
// mutation runner covers them. The ported page server (api/serve/serve.mjs) calls them on every request.
//
// checkPageRequest (every request):
//   · every header at most once (serve.header-repeated): Node keeps the first Host and joins a repeated Origin, so a
//     repeat would be read one way here and another way upstream;
//   · Host exactly 127.0.0.1:<this network's page port> (serve.host; DNS rebinding);
//   · for /api/* and /relay/* only (S1 review N3: the page server holds the API token, so it must not lend it to
//     another site): Origin this page's own origin (serve.origin) — absent only on a GET: PF-S M-3b (pre-flip review), every
//     other method (POST, PUT, …) needs Origin === pageOrigin, which every browser sends on such a request, so a caller that
//     omits it (curl, a script) cannot borrow the token to arm, skip, stop or resume a job. Any local process can still SET the
//     header (re-review N-4): a CSRF control, not a boundary between local users — docs/vt.md asks for a single-user Mac until a
//     per-launch page capability exists
//     (the CLI talks to the API and the relay on their own ports with its own token, never through the page server);
//     Sec-Fetch-Site absent, same-origin or none (serve.fetch-site). Both are also forwarded, so the API and the relay check
//     them again.
//   Static files, /__serve and /__stacks are plain GETs (a selector navigation from another network's page is
//   same-site, and a top-level navigation may be cross-site), so only the first two checks apply to them.
// proxyHeaders builds the upstream request headers from an ALLOWLIST, so nothing else crosses: no Authorization or
// Cookie from the browser, no hop-by-hop header. Host is the target's loopback port (S1 ruling: the API accepts only
// Host 127.0.0.1:<api port>). The bearer token is added for the API only; x-vt-send-ticket goes to the relay only.
// responseHeaders keeps only what the page needs from an upstream reply.
import type { IncomingHttpHeaders, OutgoingHttpHeaders } from 'node:http'
import { PORTS, TICKET_HEADER } from '@vault-timelock/core/contracts'
import type { Network } from '@vault-timelock/core/contracts'
import { refuse } from 'vt-broadcast/src/guard.ts'
import { headerValue, repeatedHeader } from './relay-gate.ts'

export type ProxyTarget = 'api' | 'relay'
const HEX64 = /^[0-9a-f]{64}$/

export const pageHost = (network: Network): string => `127.0.0.1:${PORTS[network].page}`
export const pageOrigin = (network: Network): string => `http://${pageHost(network)}`

export function checkPageRequest(raw: readonly string[], o: { network: Network; proxied: boolean; method: string | undefined }): void {
  const once = repeatedHeader(raw) === null
  if (!once) refuse('serve.header-repeated', 'a request header was sent more than once') // @guard:serve.header-repeated
  const hostOk = headerValue(raw, 'host') === pageHost(o.network)
  if (!hostOk) refuse('serve.host', "requests must be addressed to this network's page on 127.0.0.1") // @guard:serve.host
  if (!o.proxied) return
  const origin = headerValue(raw, 'origin')
  const originOk = origin === pageOrigin(o.network) || (origin === undefined && o.method === 'GET')
  if (!originOk) refuse('serve.origin', 'only this page may call /api and /relay (a request other than GET must carry this page\'s Origin)') // @guard:serve.origin
  const site = headerValue(raw, 'sec-fetch-site')
  const siteOk = site === undefined || site === 'same-origin' || site === 'none'
  if (!siteOk) refuse('serve.fetch-site', 'cross-site and same-site requests to /api and /relay are refused') // @guard:serve.fetch-site
}

// The Privacy Cash withdrawal authorization (S7 fix round 2): forwarded to the relay ONLY on /relay/privacycash/* (Sfix-PC).
export const PC_LANE_HEADER = 'x-vt-pc-lane'
export const PC_PATH_PREFIX = '/relay/privacycash/'

// Request headers that cross the proxy, per target (lower case). Everything else is dropped.
const FORWARD: Readonly<Record<ProxyTarget, readonly string[]>> = {
  api: ['accept', 'content-type', 'content-length', 'origin', 'sec-fetch-site', 'last-event-id'],
  relay: ['accept', 'content-type', 'content-length', 'origin', 'sec-fetch-site', TICKET_HEADER],
}

export function proxyHeaders(incoming: IncomingHttpHeaders, target: ProxyTarget, token: string, network: Network, path: string = ''): OutgoingHttpHeaders {
  const out: OutgoingHttpHeaders = {}
  const names = target === 'relay' && path.startsWith(PC_PATH_PREFIX) ? [...FORWARD.relay, PC_LANE_HEADER] : FORWARD[target]
  for (const name of names) {
    const v = incoming[name]
    if (typeof v === 'string') out[name] = v
  }
  out.host = `127.0.0.1:${PORTS[network][target]}`
  if (target === 'api') {
    if (!HEX64.test(token)) throw new Error('the API token is not 64 hex')
    out.authorization = `Bearer ${token}`
  }
  return out
}

// Reply headers kept from the upstream (content type and length, nosniff); cache-control is always no-store.
const KEEP_REPLY = ['content-type', 'content-length', 'x-content-type-options']
export function responseHeaders(upstream: IncomingHttpHeaders): OutgoingHttpHeaders {
  const out: OutgoingHttpHeaders = {}
  for (const name of KEEP_REPLY) {
    const v = upstream[name]
    if (typeof v === 'string') out[name] = v
  }
  out['cache-control'] = 'no-store'
  return out
}

// The who-sees-what hop list (R57), GENERATED from live data rather than hard-coded:
//   · the endpoint table of the network (broadcast/endpoints.json: the same file the relay loads its upstreams from),
//   · the network names from GET /api/status (`networks`) and the loopback ports from the contracts' PORTS,
//   · the relay's own answers: GET /relay/status (endpoints that passed the identity check, confined) and
//     GET /relay/tor (IsTor and the circuit generation of each role).
// Diagrams name hops, never addresses: a host that is an IP literal is shown as "loopback", the relay and Tor client are
// named by role and port, and nothing here ever prints a visitor, exit or guard address.
import { PORTS } from '@vault-timelock/core/contracts'
import TABLE from '../../../broadcast/endpoints.json'

export const CHAINS = ['eth', 'sol']
const IP_LITERAL = /^(?:\d{1,3}(?:\.\d{1,3}){3}|\[?[0-9a-f:]*:[0-9a-f:]*\]?)$/i

// Provider host NAMES for a chain on a network, from the endpoint table (never an address).
export function providersFor(network, chain) {
  const urls = TABLE?.[network]?.[`${chain}.rpc`] ?? []
  const out = []
  for (const u of urls) {
    let host = ''
    try { host = new URL(u).hostname } catch { continue }
    const name = IP_LITERAL.test(host) || host === 'localhost' ? 'loopback node' : host
    if (!out.includes(name)) out.push(name)
  }
  return out
}

// What this path carries, per chain (the RPC method names stay in the chain modules and the relay: a contract test).
export const SEND_CALL = { eth: 'the signed EIP-1559 transaction, submitted raw to an RPC node', sol: 'the signed Memo v2 transaction, submitted to an RPC node' }

const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`

// buildPath({ network, chain, names, relay, tor }) -> { network, chain, viaTor, cutAfter, hops, live }
//   names  GET /status `networks` ({eth, sol}) or null        relay  GET /relay/status or null
//   tor    GET /relay/tor or null (testnet and mainnet only)  `live` = the relay/Tor answers were used
export function buildPath({ network, chain, names = null, relay = null, tor = null, live = false }) {
  const ports = PORTS[network]
  const providers = providersFor(network, chain)
  const chainName = names?.[chain] ?? (chain === 'eth' ? 'Ethereum' : chain === 'btc' ? 'Bitcoin' : 'Solana')
  const viaTor = network !== 'local'
  const nEndpoints = live && relay?.endpoints ? relay.endpoints[chain] : null
  const role = live && tor?.roles ? tor.roles[chain] : null
  const you = { id: 'browser', tone: 'you', title: 'Your browser', sub: ['builds + signs', 'keys never leave the tab', "CSP connect-src 'self'"], sees: ['everything (your machine)'], notSees: ['never contacts an RPC'] }
  const relaySub = [`loopback · port ${ports.relay}`, viaTor ? 'sandbox: out only to Tor' : 'direct to the local chain', 'bytes forwarded as-is']
  if (live && relay) relaySub.push(relay.confined === true ? 'confinement proof ✓' : 'confinement proof ✗')
  if (nEndpoints !== null) relaySub.push(`${plural(nEndpoints, 'endpoint')} passed the identity check`)
  const relayHop = { id: 'relay', tone: 'local', title: 'Local relay', sub: relaySub, sees: ['the signed transaction', 'your machine'], notSees: viaTor ? ['cannot dial out directly'] : [] }

  if (!viaTor) {
    return {
      network, chain, viaTor, cutAfter: null, live,
      hops: [you, relayHop, { id: 'node', tone: 'pub', title: chainName, sub: ['a chain on this machine', `loopback only (${providers.join(', ') || 'local node'})`], sees: ['the transaction'], notSees: ['nothing leaves this machine on the local network'] }],
    }
  }
  const torSub = ['local SOCKS5 (socks5h)', `user ${chain}.<session>.<generation>`, 'own circuit per role']
  if (role) torSub.push(`circuit generation ${role.gen}, age ${role.ageSec} s`)
  if (live && tor) torSub.push(tor.isTor === true ? 'IsTor ✓' : tor.isTor === false ? 'IsTor ✗' : 'IsTor unknown')
  return {
    network, chain, viaTor, cutAfter: 'middle', live,
    hops: [
      you, relayHop,
      { id: 'tor', tone: 'tor', title: 'Tor client', sub: torSub, sees: ['your machine'], notSees: ['no local DNS lookup (socks5h)'] },
      { id: 'guard', tone: 'tor', title: 'Guard relay', sub: ['Tor hop 1', 'encrypted cells'], sees: ['YOUR IP'], notSees: ['the destination', 'the content'] },
      { id: 'middle', tone: 'tor', title: 'Middle relay', sub: ['Tor hop 2', 'encrypted cells'], sees: ['the guard and the exit only'], notSees: ['you', 'the destination'] },
      { id: 'exit', tone: 'tor', title: 'Exit relay', sub: ['Tor hop 3', 'TLS to the RPC host'], sees: ['the RPC hostname (SNI)'], notSees: ['YOUR IP', 'the transaction (inside TLS)'] },
      { id: 'rpc', tone: 'ext', title: 'Public RPC endpoint', sub: providers.length ? providers : ['(no endpoint in the table)'], sees: ["the exit's IP", 'the signed transaction + time'], notSees: ['YOUR IP'] },
      { id: 'node', tone: 'pub', title: chainName, sub: chain === 'eth' ? ['provider node → gossip → public mempool', '→ builder/proposer → block'] : ['RPC node → QUIC to the current and next leaders', '(no public mempool) → block'], sees: ["the transaction, from the RPC provider's node", 'sender = the in-browser address (public)'], notSees: ['anything about you or Tor'] },
    ],
  }
}

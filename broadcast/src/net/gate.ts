// The Tor gate (spec B s6.1, s6.3 "Tor is lazy"; Task 7). Fail closed at every step:
//   1. no API key in the environment (config.env-key, the same rule loadConfig applies);
//   2. the SOCKS port negotiates username/password auth (socks-probe.ts), else circuit isolation by
//      role is not real (tor.socks-noauth);
//   3. GET https://check.torproject.org/api/ip through the net layer (role `check`, the one request
//      allowed before the gate) answers JSON with a boolean IsTor (tor.check-malformed), and it is
//      true (tor.not-tor). A transport failure is the net layer's tor.unreachable.
// Only then is the gate open, for that net instance only.
//
// The answer also carries the exit's IP. It never leaves this function: the body is parsed here,
// only the IsTor boolean is read, the messages are fixed strings, and the return value is a fresh
// `{ isTor: true }`.
//
// Only this module can open a gate: the open nets are a module-private WeakSet, and the opener
// (passGate) is not exported. The net layer asks gatePassedFor(net) before every SOCKS request
// (net.gate-required). A static scan (test/offline/static-net.test.ts) keeps the opener's name
// inside this file.
import { refuse } from '../guard.ts'
import { assertNoKeyEnv } from '../config.ts'
import { probeSocksAuth } from './socks-probe.ts'
import type { TorNet } from './fetch.ts'

export const TOR_CHECK_URL = 'https://check.torproject.org/api/ip'

const open = new WeakSet<object>()

function passGate(net: TorNet): void {
  open.add(net)
}

// Read-only: has torGate passed for exactly this net instance?
export function gatePassedFor(net: object): boolean {
  return open.has(net)
}

// The one tor.unreachable guard, shared by the net layer (a SOCKS-stage failure) and the probe.
export function checkTorReached(reached: boolean, what: string): void {
  if (!reached) refuse('tor.unreachable', `Tor's SOCKS proxy did not carry ${what} (is tor running?)`) // @guard:tor.unreachable
}

function isTorField(body: string): boolean | null {
  let v: unknown
  try { v = JSON.parse(body) } catch { return null }
  if (typeof v !== 'object' || v === null || Array.isArray(v) || !Object.hasOwn(v, 'IsTor')) return null
  const isTor = (v as Record<string, unknown>).IsTor
  return typeof isTor === 'boolean' ? isTor : null
}

export async function torGate(net: TorNet, env: Readonly<Record<string, string | undefined>> = process.env): Promise<{ isTor: true }> {
  assertNoKeyEnv(env)

  const method = await probeSocksAuth(net.socksPort)
  checkTorReached(method !== 'unreachable', `the auth probe of local port ${net.socksPort}`)
  if (method !== 'userpass') refuse('tor.socks-noauth', `the SOCKS server on port ${net.socksPort} did not select username/password auth (RFC 1929), so per-role circuits would not be isolated; is it Tor with IsolateSOCKSAuth?`) // @guard:tor.socks-noauth

  const res = await net.fetchFor('check')(TOR_CHECK_URL)
  const isTor = res.status === 200 ? isTorField(await res.text()) : null
  if (isTor === null) refuse('tor.check-malformed', `the Tor check answered HTTP ${res.status} without a JSON object holding a boolean IsTor`) // @guard:tor.check-malformed
  if (isTor !== true) refuse('tor.not-tor', 'the Tor check says this connection does not come from Tor (IsTor is false)') // @guard:tor.not-tor

  passGate(net)
  return { isTor: true }
}

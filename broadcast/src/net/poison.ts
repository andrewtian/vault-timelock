// Poisoned globals (spec B s6.1: "a stray fetch ... cannot reach the network directly").
// After createNet() (without a test transport):
// - globalThis.fetch, WebSocket and, if present, EventSource throw Refusal('net.poisoned');
// - http.globalAgent and https.globalAgent are replaced by agents whose createConnection throws
//   net.poisoned. That covers node:http/https callers with the default agent, and `agent: false`
//   too (Node builds that from the global agent's class), e.g. SDKs and axios.
// So an SDK default can't open a connection behind the net layer's back. The net layer itself never
// uses a global agent (SOCKS agents per role; a one-off plain agent for loopback). The OS sandbox
// (bin/vt-broadcast, confine.ts) is the second wall; this is the first.
//
// What this does NOT cover (Task 7b review), and what does:
// - http(s).request({ createConnection }) and a caller's own Agent subclass bypass every agent,
//   global or not: the socket comes from the caller's function. So does a raw node:net / node:tls
//   socket. Only the OS sandbox stops those (EPERM at connect(); tor-check and every networked
//   command prove it first, confine.ts). Outside src/net/ the static scan
//   (test/offline/static-net.test.ts) flags http.request / https.request / net.connect /
//   tls.connect and any networking import; inside src/net/ it limits raw sockets to confine.ts and
//   socks-probe.ts.
// - The `ws` package and other WebSocket clients do not use globalThis.WebSocket: importing `ws`
//   is flagged by the static scan, and their sockets meet the sandbox like any other.
//
// restoreGlobals() undoes it (tests). The static scan allows that name in src/ only in this file.
import http from 'node:http'
import https from 'node:https'
import { refuse } from '../guard.ts'

// Unconditional on purpose (Task 7 review item 8): this IS the poisoned function's body, there is no
// condition to test. Blanking it makes the poisoned functions return undefined instead of opening a
// connection, and the net.poisoned tests fail.
function poisoned(): never {
  refuse('net.poisoned', 'direct network access is disabled in this process; go through src/net (createNet)') // @guard:net.poisoned
}

// Plain functions (not arrows), so `new WebSocket(...)` reaches poisoned() too.
function fetchPoisoned(): never { return poisoned() }
function WebSocketPoisoned(): never { return poisoned() }
function EventSourcePoisoned(): never { return poisoned() }

class PoisonedHttpAgent extends http.Agent {
  override createConnection(): never { return poisoned() }
}
class PoisonedHttpsAgent extends https.Agent {
  override createConnection(): never { return poisoned() }
}

const NAMES = ['fetch', 'WebSocket', 'EventSource'] as const
interface Saved {
  readonly globals: ReadonlyMap<string, PropertyDescriptor | undefined>
  readonly httpAgent: http.Agent
  readonly httpsAgent: https.Agent
}
// The true originals, saved by the first poisonGlobals() and cleared by restoreGlobals().
let saved: Saved | null = null

function put(name: string, value: unknown): void {
  Object.defineProperty(globalThis, name, { value, writable: true, configurable: true, enumerable: true })
}
const modules = { http: http as { globalAgent: http.Agent }, https: https as { globalAgent: https.Agent } }

// Idempotent: a second call never saves the poisoned values as the "originals".
export function poisonGlobals(): void {
  if (saved === null) {
    saved = {
      globals: new Map(NAMES.map((n) => [n, Object.getOwnPropertyDescriptor(globalThis, n)])),
      httpAgent: modules.http.globalAgent,
      httpsAgent: modules.https.globalAgent,
    }
  }
  put('fetch', fetchPoisoned)
  put('WebSocket', WebSocketPoisoned)
  if ('EventSource' in globalThis) put('EventSource', EventSourcePoisoned)
  modules.http.globalAgent = new PoisonedHttpAgent({ keepAlive: false })
  modules.https.globalAgent = new PoisonedHttpsAgent({ keepAlive: false })
}

// Puts the saved originals back (exact property descriptors). A no-op if nothing is poisoned.
export function restoreGlobals(): void {
  if (saved === null) return
  for (const [name, d] of saved.globals) {
    if (d === undefined) Reflect.deleteProperty(globalThis, name)
    else Object.defineProperty(globalThis, name, d)
  }
  modules.http.globalAgent = saved.httpAgent
  modules.https.globalAgent = saved.httpsAgent
  saved = null
}

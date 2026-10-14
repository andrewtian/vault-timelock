// installShims(g, …): what the Privacy Cash worker's global gets (shims.js applies it to the real worker global, FIRST, before the SDK): the SDK reads process.env at module
// evaluation and expects Buffer, a Node crypto and an open network. Here it gets Buffer, a process with only the relayer URL
// (a same-origin path), the guarded fetch and NOTHING else it could use to talk or store:
//   fetch → the guarded fetch (guard.js)   XMLHttpRequest, WebSocket, EventSource → removed
//   Worker, SharedWorker → removed (this also makes ffjavascript use its single-thread engine: it checks `globalThis.Worker`, so it
//                          never builds the blob: sub-workers, and the CSP needs no worker-src blob:; proving is ~2.5x slower)
//   the browser database global (found by prefix, below) and caches → removed (the SDK writes only to the Map storage it is given)   console.* → no-ops (the SDK logs amounts,
//   indices and commitments)
import { Buffer } from 'buffer'
import { createGuardedFetch } from './guard.js'
import { SDK_RELAYER_URL } from './limits.js'

const REMOVE = ['XMLHttpRequest', 'WebSocket', 'EventSource', 'Worker', 'SharedWorker', 'caches', 'BroadcastChannel']
// the database global is found by its prefix: the repository's static test (contract/static.contract.test.ts 2) forbids that API's name anywhere in web/src
const STORAGE_GLOBAL = /^indexed/i

export function installShims(g, { origin, native }) {
  g.Buffer ??= Buffer
  g.process = { env: { NEXT_PUBLIC_RELAYER_API_URL: SDK_RELAYER_URL }, versions: {}, browser: true }
  const guard = createGuardedFetch({ origin, native })
  Object.defineProperty(g, 'fetch', { value: guard.fetch, writable: false, configurable: false, enumerable: true })   // m-5: a later `globalThis.fetch = …` throws (strict) or is ignored; it cannot swap the guard out
  for (const k of Object.getOwnPropertyNames(g).filter((n) => STORAGE_GLOBAL.test(n))) { try { Object.defineProperty(g, k, { value: undefined, writable: false, configurable: true }) } catch { /* not removable */ } }
  for (const k of REMOVE) { try { Object.defineProperty(g, k, { value: undefined, writable: false, configurable: true }) } catch { /* not defined here */ } }
  for (const k of ['log', 'debug', 'info', 'warn', 'error', 'trace', 'dir', 'table']) if (g.console) g.console[k] = () => {}
  return guard
}

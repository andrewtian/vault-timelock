// @ts-check
// PORTED (R69) from the prototype, tag add7b-e540f8ae4d6b, serve.mjs (sha256 9f37a0f6862cd323b2d197122bc0063b3e312bfb958425741f0153207a3e349b).
// Kept (spec §6.2): the CSP, X-DNS-Prefetch-Control off, no-referrer, nosniff, no-store, the Host check, static files
// (no hot reload, no file watching) and /relay/* → the relay.
// Changes (spec §6.2 only):
//   · --network <n>: the page port, the relay and API ports and the page origin come from PORTS[network]; static files
//     from --root (web/dist); /__serve and the release digest from the release root (<release>/SHA256SUMS, spec §9);
//   · /api/* → the API (the /api prefix stripped). The request headers are rebuilt from an allowlist
//     (api/src/serve-gate.ts proxyHeaders): an incoming Authorization or Cookie never crosses; the bearer token, read
//     from <home>/<network>/api.token on every request, is added for the API only; x-vt-send-ticket goes to the relay
//     only; Host is the target's own loopback port; Origin and Sec-Fetch-Site are forwarded for the API and relay to
//     check again. checkPageRequest refuses repeated headers, a foreign Host, and for /api and /relay a foreign Origin,
//     a request other than GET without this page's Origin (PF-S M-3b: the token is lent to the page only), or a
//     cross-site / same-site Sec-Fetch-Site;
//   · replies stream unbuffered (SSE): headers are flushed at once and every upstream chunk is written as it arrives;
//     a client that leaves closes the upstream request, and an upstream that breaks off closes the client's;
//   · GET /__serve → { release, digest, build }; GET /__stacks → readStacks(<home>) (W1's selector, spec §3.4);
//   · static files are served only when their realpath lies inside realpath(--root): a symlink out of web/dist is 404
//     (S3 review m1; MQ followed it).
//   Structure: createServe(options) is the handler (tests run it in process); main() (when run as a program) parses
//   the arguments and listens.
// Start ONLY through `vt up` (C3), under C1's loopbackProfile([relay, api]) (outbound: this stack's relay and API ports;
// no file writes):
//   node api/serve/serve.mjs --network <local|testnet|mainnet> --home <VT_HOME> --root <web/dist>
//   --build <id>: optional; by default the release directory's id, else 'dev'.
//   --port 0, --relay-port <p>, --api-port <p>: NODE_ENV=test only (api.test-only).
//   Ready: stdout `vt-page ready network=<n> port=<p>` (the line `vt up` waits for).
// Logs: method, status, ms and the guard, for refusals and errors only. Never a path, a header, a body or an address.
import http from 'node:http'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs'
import { extname, isAbsolute, join, normalize, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { PORTS, isNetwork, isRefusal } from '@vault-timelock/core/contracts'
import { readSecretHex } from '../src/auth.ts'
import { assertTestMode } from '../src/clock.ts'
import { checkPageRequest, pageHost, proxyHeaders, responseHeaders } from '../src/serve-gate.ts'
import { readStacks } from '../src/stacks.ts'

/** @typedef {import('@vault-timelock/core/contracts').Network} Network */
/**
 * @typedef {object} ServeOptions
 * @property {Network} network
 * @property {string} home                                  VT_HOME: api.token in <home>/<network>/, up.json files for /__stacks
 * @property {string} root                                  the built page (web/dist), an absolute directory
 * @property {string} build
 * @property {string} [sums]                                SHA256SUMS path for /__serve (tests; default: this release's)
 * @property {{ relay: number, api: number }} [upstreamPorts]  default: PORTS[network] (tests: ephemeral ports)
 * @property {(line: string) => void} [log]
 */

/** @type {Record<string, string>} */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json', '.wasm': 'application/wasm', '.woff2': 'font/woff2' }
// W6 / m-1 (Privacy Cash in a Web Worker): the SDK's ZK stack compiles WebAssembly at run time (hasher.rs instantiates its embedded modules;
// ffjavascript builds its curve module with WebAssembly.compile/instantiate; the circuit is a .wasm), but ONLY in the worker realm, and a worker
// takes its CSP from its own response. So `'wasm-unsafe-eval'` is sent for exactly one path, the worker script (a fixed name, web/vite.config.js
// worker.rollupOptions), as SEC_WASM; every other response, the page included, gets SEC, which cannot compile WebAssembly. No `worker-src blob:`:
// the page's worker is a same-origin module script (worker-src falls back to script-src 'self') and the worker pins ffjavascript to its
// single-thread engine, which never creates the blob: sub-workers (web/src/privacycash/shims.js).
export const WASM_PATH = '/assets/privacycash-worker.js'
export const SEC = {
  'content-security-policy': "default-src 'self'; connect-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; frame-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'",
  'x-dns-prefetch-control': 'off', 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff', 'cross-origin-opener-policy': 'same-origin', 'cache-control': 'no-store',
}
export const SEC_WASM = { ...SEC, 'content-security-policy': SEC['content-security-policy'].replace("script-src 'self'", "script-src 'self' 'wasm-unsafe-eval'") }
const JSON_TYPE = { 'content-type': 'application/json' }
// the page compares this with the relay's /relay/release digest: page and relay must come from the same release
const SUMS = fileURLToPath(new URL('../../SHA256SUMS', import.meta.url))
// The build id when no --build is given (`vt up` passes none): the release directory's name, else 'dev' (as relay.mjs).
const RELEASE_ROOT = fileURLToPath(new URL('../../', import.meta.url))
/** @param {string} root */
export function buildOf(root) { const p = root.split(sep).filter(Boolean); const id = p.at(-1) ?? ''; return p.at(-2) === 'releases' && /^[0-9a-f]{12}$/.test(id) ? id : 'dev' }
/** @param {string} build @param {string} [sums] the SHA256SUMS path (tests only; default: this release's) */
export function serveInfo(build, sums = SUMS) {
  const release = existsSync(sums)
  return { release, digest: release ? createHash('sha256').update(readFileSync(sums)).digest('hex') : null, build }
}

/** @param {ServeOptions} o @returns {(req: http.IncomingMessage, res: http.ServerResponse) => void} */
export function createServe(o) {
  const { network } = o
  const ROOT = o.root.endsWith(sep) ? o.root : o.root + sep
  const REAL_ROOT = realpathSync(o.root) + sep   // S3 review m1: a served file's realpath must lie inside this
  const ports = o.upstreamPorts ?? { relay: PORTS[network].relay, api: PORTS[network].api }
  const tokenFile = join(o.home, network, 'api.token')
  // Read per request, never cached (a SHA256SUMS changed after startup shows in the digest at once)
  const info = () => JSON.stringify(serveInfo(o.build, o.sums))
  const log = o.log ?? ((/** @type {string} */ l) => { console.log(l) })

  /** @param {http.IncomingMessage} req @param {http.ServerResponse} res */
  function handle(req, res) {
    const t0 = Date.now()
    /** @param {number} code @param {string | Buffer | undefined} body @param {Record<string, string>} [headers] @param {string} [guard] */
    const done = (code, body, headers = {}, guard) => { res.writeHead(code, { ...SEC, ...headers }); res.end(body); if (code >= 400) log(`${req.method} ${code} ${Date.now() - t0}ms${guard ? ` ${guard}` : ''}`) }
    /** @param {number} code @param {string} guard @param {string} message */
    const fail = (code, guard, message) => done(code, JSON.stringify({ error: { guard, message } }), JSON_TYPE, guard)
    /** @type {URL} */ let url
    try { url = new URL(req.url || '/', `http://${pageHost(network)}`) } catch { req.resume(); return done(400, 'bad request') }
    const target = url.pathname === '/api' || url.pathname.startsWith('/api/') ? 'api' : url.pathname.startsWith('/relay/') ? 'relay' : null
    try { checkPageRequest(req.rawHeaders, { network, proxied: target !== null, method: req.method }) } catch (e) {   // DNS rebinding, CSRF; a proxied non-GET needs this page's Origin (PF-S M-3b)
      req.resume()
      return isRefusal(e) ? fail(403, e.guardId, e.message) : done(500, 'error')
    }
    if (target !== null) {                                                                          // same-origin proxy
      const methods = target === 'api' ? ['GET', 'POST', 'PUT'] : ['GET', 'POST']
      if (!methods.includes(req.method ?? '')) { req.resume(); return done(405, 'method not allowed') }
      /** @type {http.OutgoingHttpHeaders} */ let headers
      try { headers = proxyHeaders(req.headers, target, target === 'api' ? readSecretHex(tokenFile) : '', network, url.pathname) } catch (e) {
        req.resume()
        return fail(503, isRefusal(e) ? e.guardId : 'api.token-missing', 'the page server cannot read this stack\'s API token: run vt up')
      }
      const path = target === 'api' ? (url.pathname.slice(4) || '/') + url.search : url.pathname + url.search
      const up = http.request({ host: '127.0.0.1', port: ports[target], method: req.method, path, headers }, (r) => {
        res.writeHead(r.statusCode ?? 502, { ...SEC, ...responseHeaders(r.headers) })
        res.flushHeaders()                                     // SSE: the client sees the headers now, each event as it comes
        r.on('close', () => { if (!r.complete) res.destroy() })   // an upstream that breaks off ends the client's stream too
        r.pipe(res)
      })
      up.on('error', () => { if (!res.headersSent) fail(502, `${target}.unreachable`, `${target === 'api' ? 'the API' : 'the relay'} is not reachable on this stack's loopback port — vt up`); else res.destroy() })
      res.on('close', () => { if (!res.writableFinished) up.destroy() })                          // the client left
      req.pipe(up)
      return
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') { req.resume(); return done(405, 'method not allowed') }
    if (url.pathname === '/__serve') return done(200, info(), JSON_TYPE)
    if (url.pathname === '/__stacks') return done(200, JSON.stringify(readStacks(o.home)), JSON_TYPE)
    /** @type {string} */ let rel
    try { rel = decodeURIComponent(url.pathname) } catch { return done(404, 'not found') }
    const file = normalize(join(ROOT, url.pathname === '/' ? 'index.html' : rel))
    if (!file.startsWith(ROOT)) return done(403, 'forbidden')
    try {
      const real = realpathSync(file)                      // every symlink resolved: nothing outside realpath(--root) is served
      if (!real.startsWith(REAL_ROOT) || !statSync(real).isFile()) throw new Error('outside the root, or not a file')
      done(200, req.method === 'HEAD' ? undefined : readFileSync(real), { ...(url.pathname === WASM_PATH ? { 'content-security-policy': SEC_WASM['content-security-policy'] } : {}), 'content-type': MIME[extname(file)] || 'application/octet-stream' })
    } catch { done(404, 'not found') }
  }
  // Never throws (an escaped error would end the process).
  return (req, res) => {
    try { handle(req, res) } catch {
      if (!res.headersSent) { res.writeHead(500, SEC); res.end('error') } else res.destroy()
    }
  }
}

// ---------- the command line ----------
const USAGE = 'usage: node serve.mjs --network <local|testnet|mainnet> --home <absolute VT_HOME> --root <absolute web/dist> [--build <id>]'
const FLAGS = new Set(['--network', '--home', '--root', '--build', '--port', '--relay-port', '--api-port'])
const BUILD_ID = /^[A-Za-z0-9._-]{1,64}$/
/** @param {string | undefined} v */
const portOf = (v) => (v !== undefined && /^[1-9][0-9]{0,4}$/.test(v) && Number(v) <= 65535 ? Number(v) : null)
/**
 * @param {readonly string[]} argv
 * @returns {{ network: Network, home: string, root: string, build: string, port: number, upstreamPorts: { relay: number, api: number } }}
 */
export function parseServeArgs(argv) {
  /** @type {Map<string, string>} */
  const seen = new Map()
  let ok = argv.length % 2 === 0
  for (let i = 0; ok && i < argv.length; i += 2) {
    const flag = argv[i], value = argv[i + 1]
    ok = FLAGS.has(flag) && !seen.has(flag) && typeof value === 'string' && value !== '' && !value.startsWith('--')
    if (ok) seen.set(flag, value)
  }
  const network = seen.get('--network'), home = seen.get('--home'), root = seen.get('--root'), build = seen.get('--build') ?? buildOf(RELEASE_ROOT)
  const abs = (/** @type {string | undefined} */ p) => p !== undefined && isAbsolute(p) && !p.includes('\0')
  if (!ok || !isNetwork(network) || !abs(home) || !abs(root) || !BUILD_ID.test(build)) throw new Error(USAGE)
  const port = seen.get('--port'), relayPort = seen.get('--relay-port'), apiPort = seen.get('--api-port')
  if ((port !== undefined && port !== '0') || (relayPort !== undefined && portOf(relayPort) === null) || (apiPort !== undefined && portOf(apiPort) === null)) throw new Error(USAGE)
  if (port !== undefined || relayPort !== undefined || apiPort !== undefined) assertTestMode()
  return {
    network, home: /** @type {string} */ (home), root: /** @type {string} */ (root), build,
    port: port === undefined ? PORTS[network].page : 0,
    upstreamPorts: { relay: portOf(relayPort) ?? PORTS[network].relay, api: portOf(apiPort) ?? PORTS[network].api },
  }
}

async function main() {
  /** @param {string} msg @returns {never} */
  const fail = (msg) => { process.stderr.write(`FATAL: ${msg}\n`); process.exit(2) }
  try {
    const a = parseServeArgs(process.argv.slice(2))
    let rootOk = false
    try { rootOk = statSync(a.root).isDirectory() } catch { rootOk = false }
    if (!rootOk) fail('--root is not a directory (build the page first: npm run -w web build)')
    const server = http.createServer(createServe({ network: a.network, home: a.home, root: a.root, build: a.build, upstreamPorts: a.upstreamPorts }))
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(a.port, '127.0.0.1', () => { server.off('error', reject); resolve(undefined) }) })
    for (const sig of /** @type {const} */ (['SIGINT', 'SIGTERM', 'SIGHUP'])) process.once(sig, () => { server.close(); process.exit(0) })
    const addr = server.address()
    const port = typeof addr === 'object' && addr !== null ? addr.port : 0
    console.log(`page server on loopback :${port} build ${a.build} (relay → :${a.upstreamPorts.relay}, api → :${a.upstreamPorts.api})`)
    console.log(`vt-page ready network=${a.network} port=${port}`)   // the readiness line `vt up` (C3) waits for
  } catch (e) {
    if (isRefusal(e)) fail(`refused ${e.guardId}: ${e.message}`)
    const code = /** @type {{ code?: unknown } | null} */ (e)?.code
    fail(e instanceof Error && e.message === USAGE ? USAGE : `startup failed${typeof code === 'string' && /^[A-Z0-9_]{1,32}$/.test(code) ? ` (${code})` : ''}`)
  }
}

if (import.meta.main) await main()

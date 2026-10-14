// @ts-check
// S7 (M4) Privacy Cash proxy: the HTTP glue of /relay/privacycash/* (the gates are api/src/privacycash.ts). relay.mjs
// creates one per relay (createRelay's `privacycash` option) and hands it every request under that prefix after the relay
// headers check; nothing else of the relay is touched.
//
// Per request, in this order (the first failure answers, nothing is forwarded):
//   1. resolvePc: exactly one route of the list (relay.path / relay.method / relay.pc-query), else 403 with the guard id;
//   2. the circuit files (GET artifacts/transaction2.{wasm,zkey}): served from memory, loaded and sha256-checked at
//      boot (relay.pc-artifact: a file that is not the pinned one answers 503); never upstream, never through Tor;
//   3. the upstreams must be configured (mainnet / testnet: the fixed relayer and the mainnet Solana RPC list, over Tor;
//      local: none unless a test injects loopback fakes) else 503;
//   4. a withdrawal: the FUNDING lock first (privacycash.ts assertWithdrawAllowed → assertSendAllowed, MAINNET_SEND_ENABLED;
//      relay.pc-send-lock → release.mainnet-locked), before the body is read — never the job-send lock, so the R78 flip of
//      MAINNET_JOB_SENDS_ENABLED does not open withdrawals;
//   5. Tor, fail closed: off local the IsTor check must hold, else 503 (the role `privacycash` has its own circuit);
//   5b. /utxos/check/<hex>: only for the first encrypted output of a withdrawal this relay forwarded (ledger; relay.pc-check);
//   6. the body, read with its cap (relay.pc-body-cap, 413) and checked (relay.pc-body); a POST is application/json;
//   7. forward on role `privacycash` (a withdrawal is a send: never retried unless it provably was not accepted);
//   8. the answer is shape-checked (relay.pc-upstream-shape → 502, nothing of it passed on).
//   9. a withdrawal's outcome is written to the ledger: 200 with a signature → spent + the signature; a 200 without one or in
//      the wrong form, any other status the relayer answered with (400/404 …) and an ambiguous transport result → the amount
//      STAYS reserved and the entry is flagged for reconciliation (logged: `privacycash withdraw RECONCILE <why> <nonce>`;
//      listed by `reconciling()`); a proven refusal (403/429/451, SOCKS failure) → released.
// Headers upstream: the transport sends only Accept and (with a body) Content-Type; no cookie, Origin, Referer or
// X-Forwarded-*; no redirect is followed. Responses: our own headers only (no-store, nosniff). Logs: the route NAME
// (e.g. `privacycash utxos/indices POST 200 41ms`), status and timing; never a body, a query or a path parameter.
import { isRefusal } from '@vault-timelock/core/contracts'
import { ARTIFACT_TYPES, GENESIS_BODY, LANE_HEADER, PC_PINS, PC_RELAYER, assertWithdrawAllowed, bodyCapOk, checkPcAnswer, checkPcBody, checkRecordedOk, checkWithdrawSemantics, forwardBody, loadArtifact, pcRpcIdentity, resolvePc, torRequired } from '../src/privacycash.ts'
import { headerValue } from '../src/relay-gate.ts'
import { openWithdrawalLedger } from '../src/privacycash-ledger.ts'
import { createHash } from 'node:crypto'

export { PC_RELAYER }
/** The withdrawal signature of a 200 answer (checked form), or null. @param {Buffer} body @returns {string | null} */
function signatureOf(body) {
  try { const j = JSON.parse(body.toString('utf8')); return j && typeof j.signature === 'string' && /^[1-9A-HJ-NP-Za-km-z]{64,100}$/.test(j.signature) ? j.signature : null } catch { return null }
}
const JSON_CT = /^application\/json\s*(;|$)/i

/**
 * @typedef {object} PrivacyCashOptions
 * @property {string[]} relayer  relayer base URLs (mainnet / testnet: [PC_RELAYER]); empty: the relayer routes answer 503
 * @property {string[]} rpc      Solana RPC URLs (the mainnet sol.rpc list); empty: the rpc route answers 503
 * @property {string | null} [artifactDir]  the vendored circuit files; null or absent: they answer 503
 * @property {Record<string, { size: number, sha256: string }>} [pins]  a test seam: the pins (default PC_PINS)
 * @property {string | null} [stateDir]  the relay's state dir: the durable withdrawal ledger lives there (absent: every withdrawal is refused relay.pc-ledger)
 * @property {import('../src/privacycash.ts').FundingLock} [lock]  a test seam: the funding lock (default C2's assertSendAllowed)
 */
/**
 * @param {object} o
 * @param {'local' | 'testnet' | 'mainnet'} o.network
 * @param {PrivacyCashOptions} o.config
 * @param {(role: 'privacycash' | 'privacycash-rpc', endpoints: string[], opts: { method?: string, body?: Buffer, send?: boolean, timeoutMs?: number }) => Promise<any>} o.via   relay.mjs `via`
 * @param {() => Uint8Array} o.ticketKey   relay-ticket.key (the lane binding's MAC key), read per withdrawal
 * @param {() => Promise<boolean | null>} o.torOk   the relay's IsTor check (cached); only asked off local
 * @param {() => number} o.now
 * @param {(line: string) => void} o.log
 */
export function createPrivacyCash({ network, config: cfg, via, torOk, ticketKey, now, log }) {
  // Own properties only (a polluted Object.prototype must not supply the lock, the pins or a state dir).
  const own = /** @type {(k: string) => any} */ ((k) => (Object.hasOwn(cfg, k) ? /** @type {any} */ (cfg)[k] : undefined))
  /** @type {{ relayer: string[], rpc: string[], artifactDir: string | null, pins: any, lock: any, stateDir: string | null }} */
  const config = { relayer: own('relayer') ?? [], rpc: own('rpc') ?? [], artifactDir: own('artifactDir') ?? null, pins: own('pins'), lock: own('lock'), stateDir: own('stateDir') ?? null }
  const ledger = openWithdrawalLedger(config.stateDir)
  /** @type {Map<string, Buffer>} */
  const files = new Map()
  const pins = /** @type {any} */ (config.pins ?? PC_PINS)
  if (config.artifactDir) {
    for (const name of /** @type {const} */ (['transaction2.wasm', 'transaction2.zkey'])) {
      try { files.set(name, loadArtifact(config.artifactDir, name, pins)) } catch (e) {
        log(`privacycash: ${name} is not served (${isRefusal(e) ? e.guardId : 'error'})`)
      }
    }
  }
  // The RPC endpoints that passed the genesis check (mainnet's), in order. Checked on first use: a definitive other genesis disables the route until restart (relay.pc-rpc-identity); no answer: not used,
  // checked again after 30 s. Role privacycash-rpc, its own circuit.
  const rpcId = { state: /** @type {'unchecked' | 'ok' | 'down' | 'mismatch'} */ ('unchecked'), verified: /** @type {string[]} */ ([]), at: 0, inflight: /** @type {Promise<void> | null} */ (null) }
  async function verifyRpc() {
    const results = await Promise.all(config.rpc.map(async (url) => {
      const r = await via('privacycash-rpc', [url], { body: GENESIS_BODY, timeoutMs: 30000 })
      if (!r.res) return { url, ok: false, mismatch: false }
      try { return { url, ok: pcRpcIdentity(r.res.status, r.res.body ?? Buffer.alloc(0)), mismatch: false } } catch (e) {
        if (!isRefusal(e)) throw e
        return { url, ok: false, mismatch: true }
      }
    }))
    const bad = results.some((x) => x.mismatch)
    rpcId.verified = bad ? [] : results.filter((x) => x.ok).map((x) => x.url)
    rpcId.state = bad ? 'mismatch' : rpcId.verified.length ? 'ok' : 'down'
    rpcId.at = now()
    log(bad ? 'privacycash rpc: DISABLED, an endpoint answered another genesis (relay.pc-rpc-identity); until restart' : `privacycash rpc: ${rpcId.verified.length}/${config.rpc.length} endpoint(s) verified`)
  }
  /** @returns {Promise<string[]>} */
  async function rpcEndpoints() {
    if (rpcId.state === 'ok' || rpcId.state === 'mismatch') return rpcId.verified
    if (rpcId.state === 'down' && now() - rpcId.at < 30000) return rpcId.verified
    rpcId.inflight ??= verifyRpc().finally(() => { rpcId.inflight = null })
    await rpcId.inflight
    return rpcId.verified
  }
  /** @param {import('node:http').ServerResponse} res @param {number} code @param {string} type @param {Buffer} body */
  const send = (res, code, type, body) => {
    res.writeHead(code, { 'content-type': type, 'content-length': body.length, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' })
    res.end(body)
  }
  /** @param {import('node:http').IncomingMessage} req @param {number} cap @returns {Promise<Buffer | null>} null when over the cap */
  const readCapped = (req, cap) => new Promise((resolve) => {
    /** @type {Buffer[]} */ const chunks = []
    let n = 0, over = false
    req.on('data', (/** @type {Buffer} */ c) => { n += c.length; if (n > cap) { over = true; chunks.length = 0 } else if (!over) chunks.push(c) })
    req.on('end', () => resolve(over ? null : Buffer.concat(chunks)))
    req.on('error', () => resolve(null))
  })

  /** @param {import('node:http').IncomingMessage} req @param {import('node:http').ServerResponse} res */
  async function handle(req, res) {
    const t0 = now()
    let name = '-'
    /** @param {number} code @param {string} message @param {string} [guard] */
    const fail = (code, message, guard) => {
      send(res, code, 'application/json', Buffer.from(JSON.stringify({ error: { message, ...(guard ? { data: { guard } } : {}) } })))
      log(`privacycash ${name} ${req.method} ${code} ${now() - t0}ms${guard ? ` ${guard}` : ''}`)
    }
    /** @param {unknown} e */
    const refused = (e) => (isRefusal(e) ? fail(e.guardId === 'relay.pc-body-cap' ? 413 : 403, e.message, e.guardId) : fail(500, 'relay gate error: nothing was forwarded'))
    /** @type {ReturnType<typeof resolvePc>} */ let r
    try { r = resolvePc(req.method ?? '', req.url ?? '') } catch (e) { req.resume(); name = 'disallowed'; return refused(e) }
    name = r.name
    if (r.kind === 'artifact') {
      req.resume()
      const buf = files.get(r.artifact ?? '')
      if (!buf) return fail(503, 'this circuit file is not available (not vendored, or not the pinned file)')
      send(res, 200, ARTIFACT_TYPES[/** @type {'transaction2.wasm' | 'transaction2.zkey'} */ (r.artifact)], buf)
      return void log(`privacycash ${name} GET 200 ${now() - t0}ms`)
    }
    if (r.kind === 'check') {
      try { checkRecordedOk(ledger.recorded(r.upstream.slice('/utxos/check/'.length))) } catch (e) { req.resume(); return refused(e) }
    }
    const urls = r.kind === 'rpc' ? config.rpc : config.relayer.map((b) => `${b.replace(/\/+$/, '')}${r.upstream}`)
    if (urls.length === 0) { req.resume(); return fail(503, 'Privacy Cash is not available on this network') }
    if (r.kind === 'withdraw') {
      try { assertWithdrawAllowed(config.lock) } catch (e) { req.resume(); return refused(e) }
    }
    try { torRequired(network === 'local' || (await torOk()) === true) } catch (e) { req.resume(); return isRefusal(e) ? fail(503, e.message, e.guardId) : fail(500, 'relay gate error: nothing was forwarded') }
    /** @type {Buffer | null} */ let body = null
    if (r.method === 'POST') {
      if (!JSON_CT.test(String(req.headers['content-type'] || ''))) { req.resume(); return fail(403, 'content-type must be application/json') }
      body = await readCapped(req, r.reqCap)
      try { bodyCapOk(r, body === null ? r.reqCap + 1 : body.length); checkPcBody(r, /** @type {Buffer} */ (body)) } catch (e) { return refused(e) }
    } else req.resume()
    /** @type {string | null} */ let nonce = null
    if (r.kind === 'withdraw') {
      try {
        const c = checkWithdrawSemantics(/** @type {Buffer} */ (body), { header: headerValue(req.rawHeaders, LANE_HEADER), key: ticketKey(), network, now: now() })
        // burn the nonce and reserve the amount, durably, BEFORE forwarding (synchronous from here to the forward)
        ledger.reserve({ nonce: c.auth.nonce, lane: c.auth.recipient, job: c.auth.job, tryIndex: c.auth.tryIndex, bodySha256: c.auth.bodySha256, enc1: c.enc1, amount: c.amount, allowance: c.auth.allowance, exp: c.auth.exp }, now())
        nonce = c.auth.nonce
      } catch (e) { return refused(e) }
    }
    const out = body === null ? undefined : forwardBody(r, body)
    let targets = urls
    if (r.kind === 'rpc') {
      targets = await rpcEndpoints()
      if (targets.length === 0) return fail(503, rpcId.state === 'mismatch' ? 'the Privacy Cash RPC is disabled (another genesis answered)' : 'no Privacy Cash RPC endpoint passed the genesis check')
    }
    const up = await via(r.kind === 'rpc' ? 'privacycash-rpc' : 'privacycash', targets, { method: r.method, ...(out ? { body: out } : {}), send: r.kind === 'withdraw', timeoutMs: r.timeoutMs })
    /** @param {import('../src/privacycash-ledger.ts').ReconcileWhy} why */
    const reconcile = (why) => { if (nonce !== null) { ledger.flag(nonce, why); log(`privacycash withdraw RECONCILE ${why} ${nonce.slice(0, 8)}: the amount stays reserved; check the chain / the relayer, then resolve it`) } }
    if (!up.res) {
      // release ONLY on proof the relayer never accepted it (refused before processing / never delivered); an ambiguous
      // outcome stays reserved against the lane's allowance, flagged for reconciliation
      if (nonce !== null && up.notAccepted) ledger.release(nonce)
      else if (up.ambiguous) reconcile('ambiguous')
      if (up.ambiguous) return fail(502, `send outcome unknown (${up.label}): do not withdraw again; the amount stays reserved. Check the balance / run the provenance check`)
      return fail(up.notAccepted && r.kind === 'withdraw' ? 503 : 502, `upstream unavailable (${up.label})`)
    }
    /** @type {import('../src/privacycash.ts').PcAnswer | null} */ let a = null
    /** @type {unknown} */ let answerErr = null
    try { a = checkPcAnswer(r, up.res.status, up.res.body ?? Buffer.alloc(0)) } catch (e) { answerErr = e }
    if (nonce !== null) {
      const status = up.res.status
      if (status !== 200) reconcile(status === 400 ? 'http-400' : status === 404 ? 'http-404' : 'http-status')
      else if (a === null) reconcile('bad-answer')
      else {
        const sig = signatureOf(/** @type {Buffer} */ (up.res.body))
        if (sig === null) reconcile('no-signature'); else ledger.settle(nonce, sig)    // M-6 / N-3: the signature is recorded
      }
    }
    if (a === null) return isRefusal(answerErr) ? fail(502, answerErr.message, answerErr.guardId) : fail(500, 'relay internal error')
    send(res, a.status, a.contentType, a.body)
    log(`privacycash ${name} ${r.method} ${a.status} ${now() - t0}ms`)
  }
  return { handle, artifacts: () => [...files.keys()], rpcEndpoints, reconciling: () => ledger.reconciling(), resolve: (/** @type {string} */ nonce, /** @type {'spent' | 'released'} */ as) => ledger.resolve(nonce, as), close: () => ledger.close() }
}

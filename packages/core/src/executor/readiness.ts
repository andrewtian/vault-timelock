// packages/core/src/executor/readiness.ts — the readiness rows beyond preflight(): what the API, the relay and the page
// server say about themselves (W4, C7). ONE source for the page's Status table (web/src/status/readiness.js delegates here)
// and for `vt preflight` (cli/src/preflight.ts), so both show the same rows with the same verdicts (Chrome loop pass 9,
// F9-5). Pure: no I/O, browser-safe. Every row is { id, ok: true|false|null, label, detail }; null = informational.
// Nothing here carries an IP or an endpoint: builds are 12-hex ids or `dev`, digests are SHA256SUMS hashes, and the one
// free text (the relay's fork-drift message) goes through journalText.
import type { Network } from '../contracts/index.ts'
import { isNetwork } from '../contracts/index.ts'
import { journalText } from '../engine/engine.js'

export interface ReadinessRow { id: string; ok: boolean | null; label: string; detail: string }
export interface ReadinessStatus { network?: unknown; build?: unknown }
export interface ReadinessRelay { network?: unknown; build?: unknown; identity?: { eth?: { ok?: unknown; message?: unknown } | null; sol?: unknown; btc?: { ok?: unknown; message?: unknown } | null } | null; endpoints?: { btc?: unknown } | null }
// GET /relay/services: { network, services: { <name>: { ok: true | false | null, viaTor, endpoints, message? } } } (api/relay/relay.mjs servicesStatus)
export interface ReadinessServices { network?: unknown; services?: unknown }
export interface ReadinessServe { release?: unknown; digest?: unknown; build?: unknown }
export interface ReadinessRelease { release?: unknown; files?: unknown; ok?: unknown; digest?: unknown; mismatch?: unknown; missing?: unknown; hashedAt?: unknown; error?: unknown }
export interface ReadinessInput {
  network: Network
  status: ReadinessStatus | null | undefined
  relay: ReadinessRelay | null | undefined
  extras?: { pageBuild?: unknown; serve?: ReadinessServe | null; release?: ReadinessRelease | null; services?: ReadinessServices | null; required?: readonly string[]
    servicesWhy?: unknown
    // Per armed chain, what core reports about the lane key (Efix3 adds `delegated` to the assess / claw-back result; absent until then)
    chains?: Readonly<Record<string, { delegated?: unknown } | null | undefined>> | null }
  pageNetwork?: Network | null
}

// The local Tor line (M4a glue, S6 F1). The local relay reaches its chains on loopback, but it does use Tor for drand (Open, D-R15):
// /relay/tor names the roles that go through Tor (torRoles) and the last drand IsTor check (isTor, null until drand is first used).
// ONE source for `vt preflight`, the page's readiness table and the Tor panel, so none of them says "no Tor" while the relay uses it.
// ok is true only for IsTor ✓; null (informational) otherwise: the local chains need no Tor, so a Tor that is down never fails local.
export interface LocalTorView { drandViaTor: boolean; ok: boolean | null; detail: string }
export function localTorView(t: { isTor?: unknown; torRoles?: unknown } | null | undefined): LocalTorView {
  const drandViaTor = Array.isArray(t?.torRoles) && (t.torRoles as unknown[]).includes('drand')
  if (!drandViaTor) return { drandViaTor, ok: null, detail: 'n/a — the local chains are direct loopback and this relay does not use Tor' }
  const tail = 'chains direct loopback'
  if (t?.isTor === true) return { drandViaTor, ok: true, detail: `drand via Tor (IsTor ✓); ${tail}` }
  if (t?.isTor === false) return { drandViaTor, ok: null, detail: `drand via Tor: unavailable (IsTor ✗); ${tail}` }
  return { drandViaTor, ok: null, detail: `drand via Tor (IsTor not checked yet: on first use); ${tail}` }
}

const FORK = /amsterdam|fork/i
// What a build row shows when the tree is a development tree (no release): the build ids differ there by design.
export const DEV_TREE_BUILD_DETAIL = 'dev tree (needed only on mainnet/verified release)'

const isCount = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0
// The relay's /relay/release (api/relay/relay.mjs rehashRelease): { release: true, files, ok, mismatch, missing, digest }
// where files, ok, mismatch and missing are COUNTS. Verified only when files is a positive integer, every file re-hashed
// ok (ok === files, mismatch 0, missing 0) and the page's and the relay's digests are equal. Anything else, including a
// shape that is not that (hashedAt, the ms the re-hash started, must be there: an answer without it is not a fresh
// re-hash), is NOT verified, and the detail says which (Cfix1).
// `error` (optional, set by a client that could not read the facts): a short plain reason, shown only when it is one.
const REASON = /^[A-Za-z0-9 ?.,:-]{1,60}$/
function releaseCheck(rel: ReadinessRelease | null | undefined, digestEq: boolean): { verified: boolean; detail: string } {
  if (!rel || rel.release !== true || !isCount(rel.files) || rel.files < 1 || !isCount(rel.ok) || !isCount(rel.mismatch) || !isCount(rel.missing) || !isCount(rel.hashedAt) || rel.hashedAt < 1) {
    return { verified: false, detail: typeof rel?.error === 'string' && REASON.test(rel.error) ? `could not be read (${rel.error})` : 'could not be read' }
  }
  if (rel.mismatch > 0 || rel.missing > 0) return { verified: false, detail: `files differ (${rel.mismatch} changed, ${rel.missing} missing)` }
  if (rel.ok !== rel.files) return { verified: false, detail: `only ${rel.ok} of ${rel.files} files re-hashed ok` }
  if (!digestEq) return { verified: false, detail: 'the page and the relay come from different releases' }
  return { verified: true, detail: `re-hashed just now (${rel.files} files)` }
}

export function pageRows({ network, status, relay, extras = {}, pageNetwork = null }: ReadinessInput): ReadinessRow[] {
  const rows: ReadinessRow[] = []
  const row = (id: string, ok: boolean | null, label: string, detail: string): void => { rows.push({ id, ok, label, detail }) }
  row('api', status ? true : false, 'API answers', status ? `build ${String(status.build)}` : 'the API did not answer')

  // network-match: the page, the API and the relay must all name the same network (`expected`: the page's own when known)
  const apiNet = status && isNetwork(status.network) ? status.network : null
  const relNet = relay && isNetwork(relay.network) ? relay.network : null
  const expected = pageNetwork || apiNet
  const bad = apiNet !== null && (apiNet !== expected || (relNet !== null && relNet !== expected))
  const command = `vt up --network ${String(expected)}`
  row('network-match', status ? !bad : false, 'Page, API and relay serve the same network',
    bad ? `This page is for ${String(expected)}, but the API says ${String(apiNet)}${relNet ? ` and the relay says ${relNet}` : ''}. Start it with: ${command}` : status ? `all ${String(status.network)}` : 'unknown')

  const rel = extras.release, srv = extras.serve
  // A development tree has no release: the page bundle, the API and the relay carry different build ids by design, so
  // equality is a hard check only on a release (mainnet needs one). F9-5.
  const devTree = rel?.release === false || srv?.release === false
  // On a release the three SERVERS must agree: the page server's build (/__serve .build), the API's and the relay's, all
  // the release's build id. The page BUNDLE id (vite: a hash over web/src, index.html and the lockfile) is a different
  // hash domain from the release build id (a hash over every tracked file), so it is shown for information only and
  // never compared (Cfix1). An unknown build fails closed.
  const buildOf = (v: unknown): string | null => (typeof v === 'string' && v !== '' ? v : null)
  const servers: Array<[string, string | null]> = [['server', buildOf(srv?.build)], ['api', buildOf(status?.build)], ['relay', buildOf(relay?.build)]]
  const known = servers.every(([, b]) => b !== null)
  const same = known && servers.every(([, b]) => b === servers[0][1])
  const bundle = buildOf(extras.pageBuild)
  const shown = servers.map(([n, b]) => `${n} ${b ?? 'unknown'}`).join(' · ') + (bundle ? ` · page bundle ${bundle} (information only)` : '')
  if (devTree) row('build', null, 'Build id equal across page, API and relay', DEV_TREE_BUILD_DETAIL)
  else row('build', same, 'Build id equal across page, API and relay', same ? shown : `${shown} — the page server, the API and the relay must report one build id`)

  const eth = relay?.identity?.eth
  const drift = !!eth && eth.ok === false && typeof eth.message === 'string' && FORK.test(eth.message)
  row('fork', relay ? !drift : null, 'Ethereum fork matches this network', drift ? journalText(eth!.message, 200) : relay ? 'no fork drift reported by the relay' : 'the relay did not answer')

  const digestEq = typeof rel?.digest === 'string' && rel.digest !== '' && typeof srv?.digest === 'string' && srv.digest !== '' && rel.digest === srv.digest
  const check = releaseCheck(rel, digestEq)
  const verified = check.verified
  const short = typeof rel?.digest === 'string' ? rel.digest.slice(0, 12) : ''
  if (network === 'mainnet') row('release', verified, 'Release verified (files re-hashed; page and relay digests equal)', verified ? `${check.detail} · digest ${short}…` : rel?.release === false ? 'not a release tree: mainnet needs a verified release' : check.detail)
  else row('release', null, 'Release verified', verified ? `${check.detail} · digest ${short}…` : rel?.release === false || srv?.release === false ? 'dev tree (needed only on mainnet)' : 'unknown (needed only on mainnet)')
  rows.push(...breadthRows(network, relay, extras.services, extras.required ?? REQUIRED_BREADTH, extras.servicesWhy))
  rows.push(...delegatedRows(extras.chains))
  return rows
}

// ---- the S6 relay breadth rows (Cfix3): BTC and the relay's services (Blockscout eth/arb/base, Arweave, drand, ord).
// INFORMATIONAL: ok is true when the check is good and null (—) when it is not, never false, so they cannot fail an exit,
// unless a job on this network needs them. `required` names what a job needs ('btc', or a service name such as 'drand'); for
// now none is (BTC and timelocked publishing are not enabled), so REQUIRED_BREADTH is empty. A required thing that is not
// good is ✗. The relay's own free text is never printed, only classified (a fixed phrase is shown); the one text that is
// shown, the BTC identity message, goes through journalText.
export const REQUIRED_BREADTH: readonly string[] = []
const SERVICE_NAME = /^[a-z][a-z0-9.]{0,31}$/
const MAX_SERVICES = 16
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)

// The service rows a network's relay has (api/relay/relay.mjs addService): shown as "not checked" when /relay/services itself could
// not be read, so the rows do not vanish with the answer (Cfix4, parked from Cfix3). Local: the regtest ord and drand; testnet and
// mainnet: Blockscout per EVM chain, Arweave and drand.
export const EXPECTED_SERVICES: Readonly<Record<Network, readonly string[]>> = Object.freeze({
  local: Object.freeze(['btc.ord', 'drand']),
  testnet: Object.freeze(['blockscout.eth', 'blockscout.arb', 'blockscout.base', 'arweave', 'drand']),
  mainnet: Object.freeze(['blockscout.eth', 'blockscout.arb', 'blockscout.base', 'arweave', 'drand']),
})
// Why /relay/services gave no answer: only these two phrases are ever shown (a caller's other text is ignored).
const SERVICES_WHY = ['timed out', 'could not be read'] as const

function breadthRows(network: Network, relay: ReadinessRelay | null | undefined, services: ReadinessServices | null | undefined, required: readonly string[], why?: unknown): ReadinessRow[] {
  const rows: ReadinessRow[] = []
  const need = (name: string): boolean => required.includes(name)
  const verdict = (name: string, good: boolean): boolean | null => (good ? true : need(name) ? false : null)
  const btc = relay?.identity?.btc
  if (relay && btc !== undefined && btc !== null) {                  // only when the relay serves btc on this network
    const id = isObj(btc) ? btc : {}
    const good = id.ok === true
    const detail = good ? `block 0 is the ${network} genesis (identity verified)`
      : id.ok === false ? `identity not verified${typeof id.message === 'string' && id.message !== '' ? `: ${journalText(id.message, 120)}` : ''}` : 'identity not checked'
    rows.push({ id: 'btc-identity', ok: verdict('btc', good), label: 'BTC chain identity', detail })
    const n = relay.endpoints?.btc
    const have = isCount(n) ? n : null
    rows.push({ id: 'btc-endpoints', ok: verdict('btc', have !== null && have > 0), label: 'BTC endpoints',
      detail: have === null ? 'could not be read' : `${have} verified endpoint${have === 1 ? '' : 's'}` })
  }
  const list = isObj(services) && isObj(services.services) ? services.services : null
  if (!list && relay && (SERVICES_WHY as readonly unknown[]).includes(why)) {
    for (const name of EXPECTED_SERVICES[network]) rows.push({ id: `service-${name}`, ok: verdict(name, false), label: `Service ${name}`, detail: `not checked (${String(why)})` })
  }
  if (list) {
    for (const name of Object.keys(list).filter((k) => SERVICE_NAME.test(k)).sort().slice(0, MAX_SERVICES)) {
      const v = list[name]
      const label = `Service ${name}`
      if (!isObj(v) || (v.ok !== true && v.ok !== false && v.ok !== null)) { rows.push({ id: `service-${name}`, ok: verdict(name, false), label, detail: 'could not be read' }); continue }
      const msg = typeof v.message === 'string' ? v.message : ''
      const mismatch = v.ok === false && /another identity/i.test(msg)
      const torDown = v.ok === false && /Tor is not available/i.test(msg)
      const identity = v.ok === true ? 'ok' : mismatch ? 'disabled (relay.service-identity)' : 'not checked'
      const route = v.viaTor === true ? 'via Tor' : v.viaTor === false ? 'loopback' : 'route unknown'
      const reach = v.ok === true || mismatch ? 'reachable ✓' : v.ok === null ? 'reachable: not checked' : torDown ? 'reachable ✗ (unavailable: Tor is down)' : 'reachable ✗'
      rows.push({ id: `service-${name}`, ok: verdict(name, v.ok === true), label, detail: `identity ${identity} · ${route} · ${reach}` })
    }
  }
  return rows
}

// ---- the lane key's EIP-7702 delegation (planE5 ruling C4; core reports `delegated: true`, Efix3). One row per chain whose
// key core says is delegated, nothing when it says false or says nothing (a feature check: an older core has no field). ✗, not
// informational: the engine refuses to sign for such a key (engine.eip7702), and someone holding the authorization may move funds.
export const DELEGATED_LABEL = 'Lane key delegated (EIP-7702)'
export const DELEGATED_DETAIL = 'someone holding the authorization may move funds; nothing new is signed for this key — claw back now'
export function delegatedRows(chains: Readonly<Record<string, { delegated?: unknown } | null | undefined>> | null | undefined): ReadinessRow[] {
  if (!isObj(chains)) return []
  return Object.keys(chains).filter((c) => /^[a-z]{2,8}$/.test(c) && isObj(chains[c]) && (chains[c] as { delegated?: unknown }).delegated === true).sort()
    .map((c) => ({ id: `delegated-${c}`, ok: false, label: `${DELEGATED_LABEL} — ${c}`, detail: DELEGATED_DETAIL }))
}

// M4b glue: where `delegated` comes from outside a running executor. The executor's view carries it in process only; the journal
// carries the durable fact: the chain's `stopped` event has `delegated: true` (Eminors; the reducer surfaces it as ChainState.delegated,
// and GET /jobs lists a chain's {phase, reason, delegated?}). Journals written before Eminors carry it in the stop-reason TEXT only
// (it begins "engine.eip7702:"); that is still read. A chain counts as delegated while that stop stands (STOPPED, or any phase not yet
// settled by a claw-back, DONE or SKIPPED). Anything not shaped like that adds nothing (fail quiet: the row is a warning, the engine's
// refusal is the gate).
const SETTLED = new Set(['CLAWED_BACK', 'DONE', 'SKIPPED'])
export function delegatedFromJobs(jobs: unknown): Record<string, { delegated: true }> {
  const out: Record<string, { delegated: true }> = {}
  if (!Array.isArray(jobs)) return out
  for (const j of jobs) {
    if (!isObj(j) || !isObj(j.chains)) continue
    for (const [c, st] of Object.entries(j.chains)) {
      if (!/^[a-z]{2,8}$/.test(c) || !isObj(st)) continue
      if (typeof st.phase !== 'string' || SETTLED.has(st.phase)) continue
      if (st.delegated === true || (st.delegated === undefined && typeof st.reason === 'string' && st.reason.startsWith('engine.eip7702:'))) out[c] = { delegated: true }
    }
  }
  return out
}

// One verdict for a table: the failing count over all rows (page rows first, then preflight()'s) and the exit code.
// Exit 0 only when preflight()'s own exit is 0 (identity and deployments) AND no row anywhere fails. The page and
// `vt preflight` both use this, so a table with a ✗ never reports "exit 0" (F9-5).
export function readinessVerdict(report: { exit: 0 | 1; rows: ReadonlyArray<{ ok: boolean | null }> }, rows: ReadonlyArray<{ ok: boolean | null }>): { failing: number; exit: 0 | 1 } {
  const failing = [...rows, ...report.rows].filter((r) => r.ok === false).length
  return { failing, exit: report.exit === 0 && failing === 0 ? 0 : 1 }
}

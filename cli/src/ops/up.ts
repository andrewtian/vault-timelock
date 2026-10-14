// cli/src/ops/up.ts — `vt up [--network local|testnet|mainnet] [--open] [--dev]` (canonical vt spec §3.1, §8; plan C3).
// Orchestration: runs unsandboxed (it applies the sandboxes; macOS refuses nesting). In order:
//   1. mainnet only from a release tree (vt.mainnet-dev-tree), and only when that tree verifies, checked EVERY time
//      (src/ops/release.ts verify + assertVerified: release.test-only-present, release.mismatch);
//   2. testnet and mainnet need the system Tor: 127.0.0.1:9050 must answer a SOCKS5 greeting (vt.tor-required);
//   3. the session vt-<network> must not exist yet (else exit 1: vt down first; nothing is touched, so the running
//      stack keeps its token);
//   4. $OUT (vt-broadcast resolveOut) must be an absolute, profile-safe path (vt.path): the API gets it as
//      VAULT_TIMELOCK_DIR (its real path) and may only read there (src/ops/sandbox.ts apiProfile);
//      $VT_HOME/<network>/ (0700; vt-broadcast ensureDir: store.perms on a looser or non-directory one); a stale
//      up.json (left by a stack that died without vt down) is removed; then api.token and relay-ticket.key: 64 random
//      hex each, 0600, written atomically, fresh per up, never printed;
//   5. tmux session vt-<network> (on vt's own tmux server, -L vt) with windows relay, api, page (+ vite with --dev,
//      local only), each its exact sandboxed command (src/ops/stack.ts), its log rotated to <name>.log.1 and created
//      empty;
//   6. waits for every readiness line, per network (READY_TIMEOUT_MS): local 60 s; testnet and mainnet 120 s, because
//      their relay checks each chain's identity over Tor before it prints its line (S3 measured 55 s with one slow
//      endpoint). A window that exits first, or prints none in time: the session is
//      killed, and exit 1 naming the window (its log stays: vt logs <window>);
//      mainnet only (Cfix2): then waits for the relay's release re-hash to finish (GET /relay/release answers when it has)
//      and prints "relay: release re-hashed (N files, 0 mismatches)"; a failed, damaged or timed-out re-hash stops the
//      session (exit 1), so the first `vt preflight` never meets a re-hash still running. Testnet and local: unchanged;
//   7. writes up.json, then prints the page URL and the build id (and, for local, the two local-explorer notes);
//   8. --open: Chrome with its own profile ($VT_HOME/chrome), no first-run, no extensions, at the page URL.
// Refusals throw (exit 2); other failures return 1.
import type { Network } from '@vault-timelock/core/contracts'
import { PORTS, assertNetwork, refuse } from '@vault-timelock/core/contracts'
import { loadConfig, loopbackPorts } from 'vt-broadcast/src/config.ts'
import { ensureDir, resolveOut } from 'vt-broadcast/src/lifecycle/paths.ts'
import { spawnSync } from 'node:child_process'
import { realpathSync, rmSync } from 'node:fs'
import { connect } from 'node:net'
import { join } from 'node:path'
import { UsageError } from '../args.ts'
import type { Env } from './paths.ts'
import { stateDir, vtHome } from './paths.ts'
import { httpGet, isObj } from './status.ts'
import type { Reply } from './status.ts'
import { assertVerified, releasesDir, verify } from './release.ts'
import { assertProfilePath } from './sandbox.ts'
import {
  DEV_BUILD, SECRET_FILES, UP_JSON, freshLog, pageUrl, realPathOf, stackWindows, upJsonText, windowCommand,
  windowState, writePrivateFile, writeSecretFile,
} from './stack.ts'
import type { WindowSpec } from './stack.ts'
import { VT_TMUX_SOCKET, hasSession, killSession, newSession, newWindow, sessionName, systemTmux } from './tmux.ts'
import type { Tmux } from './tmux.ts'

export interface UpOptions {
  network: Network
  open: boolean
  dev: boolean
  env: Env
  repo: string            // the tree's root (holds api/ and web/)
  release: string | null  // the release build id when running from $VT_HOME/releases/<id>/, else null (a dev tree)
  node?: string           // absolute path of node (default: this process's)
}

export interface UpDeps {
  tmux: Tmux
  torProbe: () => Promise<boolean>
  verifyRelease: (id: string) => void // refuses (release.*) unless releases/<id> verifies
  openChrome: (args: readonly string[]) => boolean
  now: () => number
  sleep: (ms: number) => Promise<void>
  readyTimeoutMs?: number // tests only: replaces the per-network READY_TIMEOUT_MS
  relayRelease: (port: number, timeoutMs: number) => Promise<Reply | null> // GET /relay/release (answers when the re-hash is done)
  rehashTimeoutMs?: number // tests only: replaces REHASH_TIMEOUT_MS
  pollMs: number
  out: (line: string) => void
  err: (line: string) => void
}

// How long vt up waits for the readiness lines. Testnet and mainnet: at least 90 s (Tor identity checks at relay start).
export const READY_TIMEOUT_MS: Readonly<Record<Network, number>> = { local: 60_000, testnet: 120_000, mainnet: 120_000 }
export function readyTimeoutFor(n: Network): number {
  assertNetwork(n)
  return READY_TIMEOUT_MS[n]
}
// How long mainnet `vt up` waits for the relay's release re-hash (tens of thousands of files).
export const REHASH_TIMEOUT_MS = 300_000
export const TOR_SOCKS = { host: '127.0.0.1', port: 9050 } as const

// `vt up` flags: --open and --dev, each at most once. The network comes from VT_NETWORK (bin/vt's --network).
export function parseUpArgs(args: readonly string[]): { open: boolean; dev: boolean } {
  const seen = new Set<string>()
  for (const a of args) {
    if ((a !== '--open' && a !== '--dev') || seen.has(a)) throw new UsageError('usage: vt up [--network local|testnet|mainnet] [--open] [--dev]')
    seen.add(a)
  }
  return { open: seen.has('--open'), dev: seen.has('--dev') }
}

// Step 1: a development tree never starts mainnet; a release tree only when it verifies now (verifyRelease refuses).
export function assertMainnetAllowed(n: Network, release: string | null, verifyRelease: (id: string) => void): void {
  const ok = n !== 'mainnet' || release !== null
  if (!ok) refuse('vt.mainnet-dev-tree', 'a mainnet stack starts only from a verified release tree (vt release build, then that release\'s cli/bin/vt); this is a development tree') // @guard:vt.mainnet-dev-tree
  if (n === 'mainnet') verifyRelease(release as string)
}

// The real check: $VT_HOME/releases/<id> must verify (release.test-only-present, then release.mismatch).
export function verifyReleaseIn(env: Env): (id: string) => void {
  return (id) => { assertVerified(verify(join(releasesDir(vtHome(env)), id))) }
}

// Step 2. Local reaches its chains on loopback and needs no Tor.
export async function assertTor(n: Network, probe: () => Promise<boolean>): Promise<void> {
  const ok = n === 'local' || (await probe()) === true
  if (!ok) refuse('vt.tor-required', 'testnet and mainnet stacks need the system Tor: nothing answered a SOCKS5 greeting on 127.0.0.1:9050 (start it: brew services start tor)') // @guard:vt.tor-required
}

// True when host:port answers a SOCKS5 greeting (05 01 00: one method, no authentication) with 05 00. Nothing else is
// sent: no CONNECT, so no circuit is built and nothing leaves the machine.
export function socksAnswers(o: { host: string; port: number; timeoutMs?: number }): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    let done = false
    let got = Buffer.alloc(0)
    const finish = (v: boolean): void => {
      if (done) return
      done = true
      clearTimeout(timer)
      s.destroy()
      resolve(v)
    }
    const s = connect({ host: o.host, port: o.port })
    const timer = setTimeout(() => finish(false), o.timeoutMs ?? 3_000)
    s.on('connect', () => { s.write(Buffer.from([0x05, 0x01, 0x00])) })
    s.on('data', (d: Buffer) => {
      got = Buffer.concat([got, d])
      if (got.length >= 2) finish(got[0] === 0x05 && got[1] === 0x00)
    })
    s.on('error', () => finish(false))
    s.on('close', () => finish(false))
  })
}

// Chrome through LaunchServices: a new instance (-n) so that its own --user-data-dir applies.
export function chromeArgs(profileDir: string, url: string): string[] {
  return ['-na', 'Google Chrome', '--args', `--user-data-dir=${profileDir}`, '--no-first-run', '--disable-extensions', url]
}

function envRecord(env: Env): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(env)) if (v !== undefined) out[k] = v
  return out
}

export function defaultUpDeps(env: Env): UpDeps {
  return {
    tmux: systemTmux({ env }),
    torProbe: () => socksAnswers(TOR_SOCKS),
    verifyRelease: verifyReleaseIn(env),
    openChrome: (args) => spawnSync('open', [...args], { env: envRecord(env), stdio: 'ignore', timeout: 30_000 }).status === 0,
    relayRelease: (port, timeoutMs) => httpGet(port, '/relay/release', {}, timeoutMs),
    now: () => Date.now(),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    pollMs: 100,
    out: (l) => { process.stdout.write(`${l}\n`) },
    err: (l) => { process.stderr.write(`${l}\n`) },
  }
}

// Step 6: every window ready, or the first (in start order) that exited or printed no readiness line in time.
async function waitReady(windows: readonly WindowSpec[], timeoutMs: number, d: UpDeps): Promise<{ window: string; why: string } | null> {
  const deadline = d.now() + timeoutMs
  for (;;) {
    let pending: string | null = null
    for (const w of windows) {
      const s = windowState(w)
      if (s.exited !== null) return { window: w.name, why: `exited (status ${s.exited})${s.ready ? ' after' : ' before'} its readiness line` }
      if (!s.ready && pending === null) pending = w.name
    }
    if (pending === null) return null
    if (d.now() >= deadline) return { window: pending, why: `printed no readiness line within ${timeoutMs / 1000} s` }
    await d.sleep(d.pollMs)
  }
}

// Mainnet step 6b: the relay's release re-hash finished clean. null: yes (`line` is what to print); else why not.
export async function awaitRehash(port: number, timeoutMs: number, d: Pick<UpDeps, 'relayRelease'>): Promise<{ line: string } | { fail: string }> {
  const r = await d.relayRelease(port, timeoutMs)
  if (r === null) return { fail: `the relay's release re-hash did not finish within ${timeoutMs / 1000} s (or the relay did not answer)` }
  if (r.status !== 200) return { fail: `the relay's release re-hash failed (HTTP ${Number.isInteger(r.status) ? r.status : '?'})` }
  let v: unknown
  try { v = JSON.parse(r.body) } catch { return { fail: "the relay's release re-hash answered something that is not JSON" } }
  const n = (x: unknown): number | null => (typeof x === 'number' && Number.isInteger(x) && x >= 0 ? x : null)
  if (!isObj(v) || v.release !== true) return { fail: 'the relay says this is not a release tree' }
  const files = n(v.files), ok = n(v.ok), bad = n(v.mismatch), gone = n(v.missing)
  if (files === null || files < 1 || ok === null || bad === null || gone === null) return { fail: "the relay's release re-hash answered an unreadable result" }
  if (bad > 0 || gone > 0 || ok !== files) return { fail: `the release does not re-hash clean (${bad} changed, ${gone} missing, ${ok} of ${files} ok)` }
  return { line: `relay: release re-hashed (${files} files, 0 mismatches)` }
}

export async function up(o: UpOptions, deps: Partial<UpDeps> = {}): Promise<number> {
  const d: UpDeps = { ...defaultUpDeps(o.env), ...deps }
  const n = o.network
  assertNetwork(n)
  if (o.dev && n !== 'local') throw new UsageError('--dev (the Vite dev server on 127.0.0.1:5183) is for the local network only')
  assertMainnetAllowed(n, o.release, d.verifyRelease)
  await assertTor(n, d.torProbe)

  const session = sessionName(n)
  if (hasSession(d.tmux, session)) {
    d.err(`vt up: ${session} is already running (vt status --network ${n}; to restart: vt down --network ${n}, then vt up --network ${n})`)
    return 1
  }

  // $OUT, absolute and by its real path (the API reads the legacy latch there, read only).
  const out = resolveOut(o.env)
  assertProfilePath(out)
  const outReal = realPathOf(out)
  // The state dir, by its real path (C1 review M2: the API profile and every server's --home use it).
  const home = vtHome(o.env)
  ensureDir(stateDir(home, n))
  const homeReal = realpathSync(home)
  assertProfilePath(homeReal)
  const stateReal = join(homeReal, n)
  if (realpathSync(stateDir(home, n)) !== stateReal) throw new Error(`$VT_HOME/${n} must be a directory, not a link`)
  let viteCache: string | null = null
  if (o.dev) {
    try { viteCache = `${realpathSync(join(o.repo, 'web', 'node_modules'))}/.vite` } catch { throw new UsageError('--dev needs the web workspace installed (at the repository root: npx --yes npm@11.21.0 ci --ignore-scripts)') }
  }

  const build = o.release ?? DEV_BUILD
  const windows = stackWindows({
    network: n, homeReal, outReal, repo: o.repo, node: o.node ?? process.execPath, build, viteCache, env: o.env,
    chainPorts: n === 'local' ? loopbackPorts(loadConfig('local', o.env)) : [],
  })

  rmSync(join(stateReal, UP_JSON), { force: true }) // left by a stack that died without vt down: it is not up
  for (const f of SECRET_FILES) writeSecretFile(stateReal, f)
  ensureDir(join(stateReal, 'logs'))
  for (const w of windows) freshLog(w.log)

  // Step 5.
  for (const [i, w] of windows.entries()) {
    const r = i === 0 ? newSession(d.tmux, session, w.name, windowCommand(w)) : newWindow(d.tmux, session, w.name, windowCommand(w))
    if (r.code !== 0) {
      if (i > 0) killSession(d.tmux, session)
      d.err(`vt up: tmux could not start the ${w.name} window of ${session}${r.code === null ? ` (${r.err})` : ''}; nothing is running`)
      return 1
    }
  }

  // Step 6.
  const failed = await waitReady(windows, d.readyTimeoutMs ?? readyTimeoutFor(n), d)
  if (failed !== null) {
    killSession(d.tmux, session)
    d.err(`vt up: the ${failed.window} window ${failed.why}; ${session} was stopped. Its log: vt logs ${failed.window} --network ${n}`)
    return 1
  }

  // Step 6b (mainnet): the stack is ready only once the relay has re-hashed the release.
  if (n === 'mainnet') {
    d.out("vt up: waiting for the relay's release re-hash…")
    const h = await awaitRehash(PORTS[n].relay, d.rehashTimeoutMs ?? REHASH_TIMEOUT_MS, d)
    if ('fail' in h) {
      killSession(d.tmux, session)
      d.err(`vt up: ${h.fail}; ${session} was stopped. Its log: vt logs relay --network ${n}`)
      return 1
    }
    d.out(`vt up: ${h.line}`)
  }

  // Step 7.
  writePrivateFile(stateReal, UP_JSON, upJsonText({ network: n, pagePort: PORTS[n].page, build, startedAt: d.now() }))
  const url = pageUrl(n)
  d.out(`vt up: the ${n} stack is running in tmux session ${session} (windows ${windows.map((w) => w.name).join(', ')})`)
  d.out(`  page   ${url}`)
  if (o.dev) d.out(`  vite   http://127.0.0.1:${PORTS.local.dev}/ (dev server, hot reload)`)
  d.out(`  build  ${build}`)
  d.out(`  tmux   tmux -L ${VT_TMUX_SOCKET} attach -t ${session}`)
  if (n === 'local') {
    d.out('  note   the local Solana validator must run with --limit-ledger-size 50000000, or explorer links lose their history;')
    d.out('         the explorer site needs Chrome\'s "Apps on device" permission to read the local validator (docs/E2E.md)')
  }

  // Step 8.
  if (o.open) {
    const profileDir = join(homeReal, 'chrome')
    ensureDir(profileDir)
    if (!d.openChrome(chromeArgs(profileDir, url))) d.err(`vt up: Chrome could not be started; open ${url} yourself`)
  }
  return 0
}

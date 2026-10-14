// cli/src/ops/stack.ts — one network's stack: its windows, their exact sandboxed commands, readiness, the secret files
// and up.json (canonical vt spec §3.1, §3.2; plan Task C3). `vt up` (up.ts) and `vt down` (down.ts) drive it; `vt status`
// (status.ts) and `vt logs` (logs.ts) read what it writes.
//
// Every window runs (tmux argv, src/ops/tmux.ts):
//   /bin/sh -c WINDOW_SCRIPT vt-<name> <log> /usr/bin/sandbox-exec -p <profile> /usr/bin/env -i <env> <node> <script> …
// ★ Each server starts under its own profile (src/ops/sandbox.ts) and env -i: node gets exactly PATH HOME LANG TERM
//   VT_HOME VAULT_TIMELOCK_DIR, plus XDG_DATA_HOME when set. VAULT_TIMELOCK_DIR is ALWAYS given, as the absolute real
//   path of $OUT as vt resolved it (broadcast resolveOut: VAULT_TIMELOCK_DIR, else $XDG_DATA_HOME/vault-timelock, else
//   ~/.local/share/vault-timelock): the API reads the legacy latch there (S2), and without it would fall back to the
//   default $OUT even for an agent that gave a temp dir. Absolute binaries (sandbox-exec, env, tee, sh): nothing in
//   the command is looked up on a PATH.
//   · relay  relayProfile: Tor's SOCKS port; on local also the loopback chain ports of endpoints.json `local`. On local
//            ONLY it gets `--price-fixture SOL=150,ETH=3000` (S3's relay serves it labelled "LOCAL FIXTURE PRICE" and
//            refuses the flag on testnet and mainnet, which have their own price sources);
//   · api    apiProfile(<real path of $VT_HOME/<network>>, <real path of $OUT>): no outbound at all, writes only below
//            its state dir, $OUT read only. The REAL paths (C1 review M2): sandbox rules match resolved paths, so
//            /tmp/… (= /private/tmp/…) would deny every write. vt also hands every server the real VT_HOME, so the
//            API's own state dir is that same path;
//   · page   loopbackProfile([relay, api]): those two ports, no writes;
//   · vite   (--dev, local only) viteProfile([relay, api], <web/node_modules/.vite>): no writes but its cache.
// ★ The window script is fixed text; every value reaches it as a positional parameter, never as shell source. It tees
//   the server's output (stdout and stderr) to <state>/logs/<name>.log (0600, created by vt before the start), appends
//   `vt: exited with status <n>` when the server ends, then keeps the window open (sleep) so its last lines stay
//   visible in tmux until `vt down`. tee runs outside the server's sandbox: spec §3.1 "its log via tmux tee".
import type { Network } from '@vault-timelock/core/contracts'
import { PORTS, assertNetwork } from '@vault-timelock/core/contracts'
import { randomBytes } from 'node:crypto'
import { closeSync, constants, fchmodSync, fstatSync, fsyncSync, lstatSync, openSync, readSync, realpathSync, renameSync, rmSync, writeSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import type { Env } from './paths.ts'
import { apiProfile, loopbackProfile, relayProfile, viteProfile } from './sandbox.ts'

export type WindowName = 'relay' | 'api' | 'page' | 'vite'
export const STACK_WINDOWS: readonly WindowName[] = ['relay', 'api', 'page']
export const LOG_NAMES: readonly WindowName[] = ['relay', 'api', 'page', 'vite']
export const isLogName = (s: string | undefined): s is WindowName => s !== undefined && (LOG_NAMES as readonly string[]).includes(s)

export const SH = '/bin/sh'
export const SANDBOX_EXEC = '/usr/bin/sandbox-exec'
export const ENV_BIN = '/usr/bin/env'
export const WINDOW_SCRIPT = 'log=$1; shift; { "$@" 2>&1; echo "vt: exited with status $?"; } | /usr/bin/tee -a "$log"; exec /bin/sleep 2147483647'
export const EXIT_MARKER = /^vt: exited with status (\d+)$/

// The build ids vt passes and accepts: a release's 12 hex (its $VT_HOME/releases/<id>/), or `dev` from a development
// tree. Narrower than what the API accepts ([A-Za-z0-9._-]{1,64}), on purpose: such a value could be an IP literal.
export const BUILD = /^(?:dev|[0-9a-f]{12})$/
export const DEV_BUILD = 'dev'

export const pageUrl = (n: Network): string => `http://127.0.0.1:${PORTS[n].page}/`

// The local relay's synthetic USD prices (S3: `--price-fixture SOL=<usd>,ETH=<usd>`, local only). Never passed for testnet
// or mainnet: the relay refuses it there, and their prices are the labelled testnet fixture and Jupiter via Tor.
export const LOCAL_PRICE_FIXTURE = 'SOL=150,ETH=3000'
export function relayArgs(n: Network): string[] {
  assertNetwork(n)
  return n === 'local' ? ['--price-fixture', LOCAL_PRICE_FIXTURE] : []
}

export interface WindowSpec { readonly name: WindowName; readonly argv: readonly string[]; readonly ready: readonly RegExp[]; readonly log: string }

// The tmux command of a window (an argv).
export function windowCommand(w: WindowSpec): string[] {
  return [SH, '-c', WINDOW_SCRIPT, `vt-${w.name}`, w.log, ...w.argv]
}

// Readiness lines (complete lines of the window's log, ANSI colour codes removed). The API's is S1's
// (`vt-api ready network=<n> port=<p> build=<b>`). For the relay and the page server (S3, porting the MQ servers) two
// forms are accepted: the canonical `vt-relay|vt-page ready network=<n> port=<p>[ …]`, proposed to S3 to mirror the
// API's, and the MQ lines the port keeps (`listening on loopback :<p> (…)`, `release build on http://127.0.0.1:<p>/…`).
// Each names the network's fixed port, so a stray line of another stack never counts.
export function readyPatterns(name: WindowName, n: Network, build: string): RegExp[] {
  assertNetwork(n)
  const p = PORTS[n]
  const b = build.replace(/[.]/g, '\\.')
  switch (name) {
    case 'relay': return [new RegExp(`^vt-relay ready network=${n} port=${p.relay}(?: |$)`), new RegExp(`^listening on loopback :${p.relay} `)]
    case 'api': return [new RegExp(`^vt-api ready network=${n} port=${p.api} build=${b}$`)]
    case 'page': return [new RegExp(`^vt-page ready network=${n} port=${p.page}(?: |$)`), new RegExp(`^release build on http://127\\.0\\.0\\.1:${p.page}/`)]
    case 'vite': return [new RegExp(`Local:\\s+http://127\\.0\\.0\\.1:${p.dev ?? 0}/`)]
  }
}

// The environment every server gets (after env -i), as NAME=value words.
export function serverEnv(env: Env, homeReal: string, outReal: string): string[] {
  const words = [`PATH=${env.PATH ?? '/usr/bin:/bin'}`, `HOME=${env.HOME ?? ''}`, `LANG=${env.LANG ?? 'en_US.UTF-8'}`, `TERM=${env.TERM ?? 'dumb'}`,
    `VT_HOME=${homeReal}`, `VAULT_TIMELOCK_DIR=${outReal}`]
  if (env.XDG_DATA_HOME !== undefined) words.push(`XDG_DATA_HOME=${env.XDG_DATA_HOME}`)
  return words
}

// The real path of p, also when p (or some of its last components) does not exist yet: the real path of its nearest
// existing ancestor, plus the rest. p must be absolute.
export function realPathOf(p: string): string {
  const rest: string[] = []
  let cur = p
  for (;;) {
    try {
      return join(realpathSync(cur), ...rest)
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e
    }
    const parent = dirname(cur)
    if (parent === cur) return p
    rest.unshift(basename(cur))
    cur = parent
  }
}

export interface StackPlan {
  readonly network: Network
  readonly homeReal: string          // realpath of VT_HOME
  readonly outReal: string           // realPathOf($OUT): the API's read-only VAULT_TIMELOCK_DIR
  readonly repo: string              // the tree's root (holds api/, web/)
  readonly node: string              // absolute path of node
  readonly build: string
  readonly chainPorts: readonly number[]   // local only: endpoints.json `local` loopback ports
  readonly viteCache: string | null  // --dev: realpath of web/node_modules + /.vite; null without --dev
  readonly env: Env
}

// The windows of a stack, in start order: relay, api, page (+ vite with --dev, local only).
export function stackWindows(p: StackPlan): WindowSpec[] {
  const n = p.network
  assertNetwork(n)
  const P = PORTS[n]
  const stateReal = join(p.homeReal, n)
  const logs = join(stateReal, 'logs')
  const env = serverEnv(p.env, p.homeReal, p.outReal)
  const wrap = (profile: string, argv: readonly string[]): string[] => [SANDBOX_EXEC, '-p', profile, ENV_BIN, '-i', ...env, p.node, ...argv]
  const common = ['--network', n, '--home', p.homeReal]
  const spec = (name: WindowName, profile: string, argv: readonly string[]): WindowSpec =>
    ({ name, argv: wrap(profile, argv), ready: readyPatterns(name, n, p.build), log: join(logs, `${name}.log`) })
  const windows = [
    spec('relay', relayProfile(n, n === 'local' ? p.chainPorts : []), [join(p.repo, 'api', 'relay', 'relay.mjs'), ...common, ...relayArgs(n)]),
    spec('api', apiProfile(stateReal, p.outReal), [join(p.repo, 'api', 'src', 'main.ts'), ...common, '--build', p.build]),
    spec('page', loopbackProfile([P.relay, P.api]), [join(p.repo, 'api', 'serve', 'serve.mjs'), ...common, '--root', join(p.repo, 'web', 'dist')]),
  ]
  if (p.viteCache !== null) {
    if (n !== 'local' || P.dev === null) throw new Error('the Vite dev server runs for the local network only')
    windows.push(spec('vite', viteProfile([P.relay, P.api], p.viteCache), [
      join(p.repo, 'web', 'node_modules', 'vite', 'bin', 'vite.js'), join(p.repo, 'web'),
      '--configLoader', 'native', '--host', '127.0.0.1', '--port', String(P.dev), '--strictPort',
    ]))
  }
  return windows
}

// ---- files: logs, secrets, up.json

const ANSI = /\u001b\[[0-9;?]*[A-Za-z]/g
const LOG_SCAN_CAP = 4 * 1024 * 1024

// Reads at most `cap` bytes of a regular file, never through a symlink and never blocking on a FIFO. null: missing,
// not a regular file, or (privateOnly) readable by group or others.
export function readSmallFile(path: string, o: { cap: number; privateOnly?: boolean; whole?: boolean }): string | null {
  let fd: number
  try { fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK) } catch { return null }
  try {
    const st = fstatSync(fd)
    if (!st.isFile()) return null
    if (o.privateOnly === true && (st.mode & 0o077) !== 0) return null
    if (o.whole === true && st.size > o.cap) return null
    const len = Math.min(st.size, o.cap)
    const buf = Buffer.alloc(len)
    let off = 0
    while (off < len) {
      const r = readSync(fd, buf, off, len - off, off)
      if (r === 0) break
      off += r
    }
    return buf.subarray(0, off).toString('utf8')
  } catch {
    return null
  } finally {
    closeSync(fd)
  }
}

// What a window's log says so far: a readiness line seen, and the exit marker (with the status) seen. Only complete
// lines count (a line being written is not matched halfway).
export function scanLog(text: string, ready: readonly RegExp[]): { ready: boolean; exited: number | null } {
  let isReady = false
  let exited: number | null = null
  const lines = text.split('\n')
  lines.pop()
  for (const raw of lines) {
    const line = raw.replace(/\r$/, '').replace(ANSI, '')
    const m = EXIT_MARKER.exec(line)
    if (m !== null) exited = Number(m[1])
    else if (ready.some((r) => r.test(line))) isReady = true
  }
  return { ready: isReady, exited }
}

export function windowState(w: WindowSpec): { ready: boolean; exited: number | null } {
  return scanLog(readSmallFile(w.log, { cap: LOG_SCAN_CAP }) ?? '', w.ready)
}

function fsyncDir(dir: string): void {
  const fd = openSync(dir, constants.O_RDONLY)
  try { fsyncSync(fd) } finally { closeSync(fd) }
}

// Writes `text` to dir/name atomically: a fresh temp file (O_EXCL, O_NOFOLLOW, mode 0600) in the same directory, fsync,
// rename over the target (rename never follows a symlink at the target), fsync the directory.
export function writePrivateFile(dir: string, name: string, text: string): void {
  const tmp = join(dir, `.${name}.${randomBytes(8).toString('hex')}.tmp`)
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  let open = true
  let done = false
  try {
    fchmodSync(fd, 0o600)
    const b = Buffer.from(text, 'utf8')
    let off = 0
    while (off < b.length) off += writeSync(fd, b, off, b.length - off)
    fsyncSync(fd)
    closeSync(fd)
    open = false
    renameSync(tmp, join(dir, name))
    done = true
  } finally {
    if (open) closeSync(fd)
    if (!done) rmSync(tmp, { force: true })
  }
  fsyncDir(dir)
}

// api.token / relay-ticket.key: 32 random bytes as 64 lowercase hex, no newline, 0600, fresh per `vt up`. Never
// printed, logged or returned.
export const SECRET_FILES = ['api.token', 'relay-ticket.key'] as const
export function writeSecretFile(dir: string, name: (typeof SECRET_FILES)[number]): void {
  writePrivateFile(dir, name, randomBytes(32).toString('hex'))
}

// Before a window starts: its previous log becomes <name>.log.1 (replacing an older one), and an empty <name>.log is
// created 0600 (O_EXCL), so the readiness scan sees only this run.
export function freshLog(path: string): void {
  try {
    lstatSync(path)
    renameSync(path, `${path}.1`)
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e
  }
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  try { fchmodSync(fd, 0o600) } finally { closeSync(fd) }
}

// $VT_HOME/<network>/up.json, 0600: exactly { network, pagePort, build, startedAt } (spec §3.2), startedAt in ms since
// the epoch. S3's readStacks (api/src/stacks.ts) reads it for the page's GET /__stacks; vt status reads it too.
export interface UpInfo { network: Network; pagePort: number; build: string; startedAt: number }
export const UP_JSON = 'up.json'
const UP_KEYS = ['network', 'pagePort', 'build', 'startedAt']

export function upJsonText(i: UpInfo): string {
  return `${JSON.stringify({ network: i.network, pagePort: i.pagePort, build: i.build, startedAt: i.startedAt })}\n`
}

// null when missing or malformed: not a small regular file, not exactly those four keys, another network, not this
// network's page port, a bad build id or start time.
export function readUpJson(stateDir: string, n: Network): UpInfo | null {
  const text = readSmallFile(join(stateDir, UP_JSON), { cap: 4096, whole: true })
  if (text === null) return null
  let v: unknown
  try { v = JSON.parse(text) } catch { return null }
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return null
  const o = v as Record<string, unknown>
  const keys = Object.keys(o)
  const ok = keys.length === UP_KEYS.length && UP_KEYS.every((k) => keys.includes(k))
    && o.network === n && o.pagePort === PORTS[n].page
    && typeof o.build === 'string' && BUILD.test(o.build)
    && typeof o.startedAt === 'number' && Number.isSafeInteger(o.startedAt) && o.startedAt >= 0
  return ok ? { network: n, pagePort: PORTS[n].page, build: o.build as string, startedAt: o.startedAt as number } : null
}

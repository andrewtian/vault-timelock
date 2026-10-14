// cli/src/passthrough.ts — `vt seal|open vault|file …` and the vt-broadcast pass-throughs (canonical vt spec §8, §11;
// plan Task C1).
//
// ★★ The sealers are the operator's. vt prints the command, then runs 1password-timelock.sh (vault) or
//   timelock-key.sh (file) with the same arguments, stdin/stdout/stderr attached, and exits with its status. The
//   printed line never shows an address or a URL: such an argument is shown as <redacted> (it is still passed).
//   VT_SEALER replaces the target FOR TESTS ONLY, and only with a stub that resolves (real path) inside this
//   workspace's test/fixtures/ (vt.sealer-stub-only). A VT_SEALER that is set to anything else, even the empty
//   string, is refused: it never falls back to the real sealer. A release tree has no test/fixtures/, so there
//   VT_SEALER is always refused.
// ★ vt-broadcast pass-throughs exec broadcast/bin/vt-broadcast with the words of spec §11 and the remaining
//   arguments unchanged; that wrapper applies its own env -i and sandbox. --network (VT_NETWORK) becomes its
//   VT_PROFILE (network = broadcast profile). Nothing is printed: vt-broadcast never echoes its override values
//   (an --rpc URL can hold a key), so vt does not either.
// ★ The child's environment is rebuilt from an allowlist here too (defence in depth when main.ts is started without
//   bin/vt): PATH HOME LANG TERM VAULT_TIMELOCK_DIR XDG_DATA_HOME, then
//   · for a sealer (controller ruling (1), C1 fix round 1): TMPDIR, OP_ACCOUNT, OP_SESSION_<A-Za-z0-9_>, and
//     TOR_SOCKS only when it is a literal loopback address (bin/vt has already refused any other, vt.tor-socks);
//     never OP_SERVICE_ACCOUNT_TOKEN, OP_CONNECT_*, OP (the sealer's own `op` override), VT_* or anything else;
//   · for vt-broadcast: VT_PROFILE (= VT_NETWORK), and none of the sealer's settings.
import { refuse } from '@vault-timelock/core/contracts'
import { spawn } from 'node:child_process'
import { realpathSync, statSync } from 'node:fs'
import { constants as osc } from 'node:os'
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { UsageError } from './args.ts'
import type { Env } from './ops/paths.ts'

const FIXTURES = fileURLToPath(new URL('../test/fixtures/', import.meta.url))

function realOrEmpty(p: string): string {
  try { return realpathSync(p) } catch { return '' }
}
function isFileUnder(p: string, dir: string): boolean {
  if (p === '' || dir === '') return false
  const rel = relative(dir, p)
  let file = false
  try { file = statSync(p).isFile() } catch { /* not a file */ }
  return rel !== '' && rel.split(sep)[0] !== '..' && !isAbsolute(rel) && file
}

// The program `vt seal|open <kind>` runs: the real sealer beside the repository root, or (VT_SEALER set) a test stub.
export function sealTarget(kind: 'vault' | 'file', env: Env, repo: string): string {
  if (kind !== 'vault' && kind !== 'file') throw new UsageError('vt seal|open takes `vault` or `file`')
  const script = kind === 'vault' ? '1password-timelock.sh' : 'timelock-key.sh'
  if (env.VT_SEALER === undefined) return join(repo, script)
  const stub = env.VT_SEALER === '' ? '' : realOrEmpty(resolve(env.VT_SEALER))
  const ok = isFileUnder(stub, realOrEmpty(FIXTURES))
  if (!ok) refuse('vt.sealer-stub-only', 'VT_SEALER may only name a test stub inside cli/test/fixtures/ (tests only; it never replaces the sealer with anything else, and the value is not echoed)') // @guard:vt.sealer-stub-only
  return stub
}

// `vt <sub> …` -> `vt-broadcast <mapped…> …` (spec §11).
const BROADCAST: Readonly<Record<string, readonly string[]>> = {
  note: ['validate-note'], 'seal-text': ['seal-text'], 'tor-check': ['tor-check'], keystore: ['keystore'], triggers: ['triggers'],
}
export type BroadcastSub = 'note' | 'seal-text' | 'tor-check' | 'keystore' | 'triggers'

export function broadcastTarget(sub: BroadcastSub): { argv0: string; mapped: string[] } {
  if (!Object.hasOwn(BROADCAST, sub)) throw new UsageError('not a vt-broadcast pass-through')
  const pkg = realpathSync(dirname(fileURLToPath(import.meta.resolve('vt-broadcast/package.json'))))
  return { argv0: join(pkg, 'bin', 'vt-broadcast'), mapped: [...BROADCAST[sub]] }
}

// The whole vt-broadcast command line for `vt <sub> <rest…>`. `note` takes exactly the word `validate` first.
export function broadcastCommand(sub: BroadcastSub, rest: readonly string[]): { file: string; args: string[] } {
  const { argv0, mapped } = broadcastTarget(sub)
  if (sub === 'note' && rest[0] !== 'validate') throw new UsageError('usage: vt note validate [--max-bytes N]   (note bytes on stdin)')
  return { file: argv0, args: [...mapped, ...(sub === 'note' ? rest.slice(1) : rest)] }
}

const CHILD_NAMES = ['PATH', 'HOME', 'LANG', 'TERM', 'VAULT_TIMELOCK_DIR', 'XDG_DATA_HOME'] as const
const SEALER_NAMES = ['TMPDIR', 'OP_ACCOUNT'] as const
const OP_SESSION = /^OP_SESSION_[A-Za-z0-9_]+$/
// 127.0.0.1:<port> or [::1]:<port>, port 1-65535 without leading zeros (the same rule as bin/vt's check_tor_socks).
export function isLoopbackSocks(v: string): boolean {
  const m = /^(?:127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})$/.exec(v)
  return m !== null && Number(m[1]) <= 65535
}

// The environment of a sealer or of vt-broadcast.
export function childEnv(env: Env, o: { for: 'sealer' | 'broadcast' }): Record<string, string> {
  const out: Record<string, string> = {}
  const copy = (n: string): void => {
    const v = env[n]
    if (v !== undefined) out[n] = v
  }
  for (const n of CHILD_NAMES) copy(n)
  if (o.for === 'sealer') {
    for (const n of SEALER_NAMES) copy(n)
    for (const n of Object.keys(env).sort()) if (OP_SESSION.test(n)) copy(n)
    if (env.TOR_SOCKS !== undefined && isLoopbackSocks(env.TOR_SOCKS)) out.TOR_SOCKS = env.TOR_SOCKS
  } else if (o.for === 'broadcast') {
    if (env.VT_NETWORK !== undefined && env.VT_NETWORK !== '') out.VT_PROFILE = env.VT_NETWORK
  }
  return out
}

// An argument that may hold an address (IPv4 dotted quad, IPv6 groups) or a URL (which can carry a key or a host).
const SENSITIVE = /\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}:[0-9A-Fa-f]{0,4}:|:\/\//

// How a command line is shown: plain words as they are, anything else single-quoted (control characters escaped),
// and an argument that may hold an address or a URL as <redacted> (never printed, never logged).
export function showCommand(argv: readonly string[]): string {
  return argv.map((a) => {
    if (SENSITIVE.test(a)) return '<redacted>'
    if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(a)) return a
    if (/[\u0000-\u001f\u007f]/.test(a)) return JSON.stringify(a)
    return `'${a.replaceAll("'", `'\\''`)}'`
  }).join(' ')
}

// Runs the command with the terminal attached (printing it first on stderr when `show`) and resolves to its exit
// status (128 + n for a signal). Ctrl-C reaches the child from the terminal (same process group); vt ignores it
// meanwhile, so it neither exits before the child has cleaned up nor sends the child a second SIGINT. SIGTERM and
// SIGHUP sent to vt are forwarded.
export function runCommand(file: string, args: readonly string[], env: Record<string, string>, o: { show: boolean }): Promise<number> {
  // Cfix4 (C1 review M5): the program is shown by its base name; its absolute path holds the operator's user name.
  if (o.show) process.stderr.write(`vt: running ${showCommand([basename(file), ...args])}\n`)
  return new Promise<number>((res, rej) => {
    const child = spawn(file, args, { stdio: 'inherit', env })
    const handlers: Array<[NodeJS.Signals, () => void]> = [
      ['SIGINT', () => {}],
      ['SIGTERM', () => { child.kill('SIGTERM') }],
      ['SIGHUP', () => { child.kill('SIGHUP') }],
    ]
    for (const [s, h] of handlers) process.on(s, h)
    const done = (): void => { for (const [s, h] of handlers) process.off(s, h) }
    child.on('error', (e) => { done(); rej(e) })
    child.on('exit', (code, signal) => {
      done()
      res(code ?? (signal !== null ? 128 + (osc.signals[signal] ?? 0) : 1))
    })
  })
}

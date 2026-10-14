// cli/src/ops/tmux.ts — the few tmux calls `vt up` / `vt down` make (canonical vt spec §3.1 "tmux"; plan Task C3).
//
// ★ vt has its OWN tmux server: `tmux -L vt` (socket /tmp/tmux-<uid>/vt). It never talks to the operator's default
//   server, so it can neither kill one of the operator's sessions nor start that server with vt's reduced (env -i)
//   environment, which tmux would keep as the global environment of every later session. Attach with
//   `tmux -L vt attach -t vt-local`.
// ★★ vt's server NEVER loads a tmux configuration (I3 finding): every call is `tmux -L vt -f /dev/null …`, so the
//   server that `vt up`'s first `new-session -d` starts reads /dev/null instead of /etc/tmux.conf, ~/.tmux.conf or
//   ~/.config/tmux/tmux.conf. The operator's config, hooks and plugins (a tmux-resurrect / continuum `session-created`
//   hook added an `autosave` window to vt-local that would overwrite the operator's own resurrect save) never run in
//   vt's server: no hook, no plugin, no option, no window but relay, api, page (and vite). `-f` matters only to the
//   call that starts the server, and is passed on every call so that no call can start it without. A vt server
//   started BEFORE this fix keeps what it loaded until it ends (docs/vt.md: stop every vt stack, then
//   `tmux -L vt kill-server` once).
// ★ Sessions are always addressed EXACTLY: `-t =vt-<network>`. Without the `=`, tmux also accepts a unique PREFIX
//   (`-t vt-loc` finds vt-local), so a typo or a future session name could kill a session vt does not own. vt never
//   lists, renames or kills anything but its own `vt-<network>` sessions, and never kills the server.
// ★ Window commands are given as an argv (after `--`), never as one shell string: tmux then runs them directly, so a
//   sandbox profile (quotes, parentheses) or a path with spaces reaches the process unchanged. The only shell is the
//   fixed window script of src/ops/stack.ts, whose values arrive as positional parameters.
// The tmux binary is found on PATH (bin/vt passes the caller's PATH). Tests put a fake first on PATH
// (test/fakes/tmux.sh, which refuses any call without `-L vt`), or give their own private server
// (`tmux -L <socket>` in a private TMUX_TMPDIR, test/up-real.test.ts): no test talks to a real `vt` or default server.
import { spawnSync } from 'node:child_process'
import type { Env } from './paths.ts'

export interface TmuxResult { code: number | null; err: string; out?: string }
export interface Tmux { run(args: readonly string[]): TmuxResult }

const SOCKET = /^[A-Za-z0-9._-]{1,64}$/
const TMUX_TIMEOUT_MS = 15_000
export const VT_TMUX_SOCKET = 'vt'
// The configuration file every vt tmux call names: none at all.
export const VT_TMUX_CONFIG = '/dev/null'

// The system tmux, on vt's own server (`-L vt`; o.socket: another private server, for tests), never with a config
// (`-f /dev/null`). The client gets exactly `env` (bin/vt has already reduced it to its allowlist), never this process's
// whole environment.
export function systemTmux(o: { socket?: string; env: Env }): Tmux {
  const socket = o.socket ?? VT_TMUX_SOCKET
  if (!SOCKET.test(socket)) throw new Error('tmux socket name: [A-Za-z0-9._-]{1,64}')
  const env: Record<string, string> = {}
  for (const [k, v] of Object.entries(o.env)) if (v !== undefined) env[k] = v
  const prefix = ['-L', socket, '-f', VT_TMUX_CONFIG]
  return {
    run(args) {
      const r = spawnSync('tmux', [...prefix, ...args], { env, encoding: 'utf8', timeout: TMUX_TIMEOUT_MS, stdio: ['ignore', 'pipe', 'pipe'] })
      if (r.error !== undefined) {
        const code = (r.error as NodeJS.ErrnoException).code
        return { code: null, err: code === 'ENOENT' ? 'tmux is not installed (or not on PATH)' : `tmux could not be run (${typeof code === 'string' ? code : 'error'})` }
      }
      return { code: r.status, err: r.stderr, out: r.stdout }
    },
  }
}

export const sessionName = (network: string): string => `vt-${network}`
const exact = (session: string): string => `=${session}`

export function hasSession(t: Tmux, session: string): boolean {
  return t.run(['has-session', '-t', exact(session)]).code === 0
}

// A detached session whose first window runs `command` (an argv).
export function newSession(t: Tmux, session: string, window: string, command: readonly string[]): TmuxResult {
  return t.run(['new-session', '-d', '-s', session, '-n', window, '--', ...command])
}

// Another window of that session (detached: the operator's current window does not change).
export function newWindow(t: Tmux, session: string, window: string, command: readonly string[]): TmuxResult {
  return t.run(['new-window', '-d', '-t', `${exact(session)}:`, '-n', window, '--', ...command])
}

// Kills exactly that session (tmux sends SIGHUP to every process of its windows).
export function killSession(t: Tmux, session: string): TmuxResult {
  return t.run(['kill-session', '-t', exact(session)])
}

// The window names of that session (exact target), or null when the session does not exist.
export function listWindows(t: Tmux, session: string): string[] | null {
  const r = t.run(['list-windows', '-t', exact(session), '-F', '#{window_name}'])
  if (r.code !== 0) return null
  return (r.out ?? '').split('\n').filter((l) => l !== '')
}

// Kills exactly that window of that session (tmux sends SIGHUP to its processes).
export function killWindow(t: Tmux, session: string, window: string): TmuxResult {
  return t.run(['kill-window', '-t', `${exact(session)}:=${window}`])
}

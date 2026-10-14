// cli/src/ops/down.ts — `vt down [--network N]` (canonical vt spec §8; plan Task C3). Orchestration (unsandboxed).
//   tmux -L vt kill-session -t =vt-<network> (exactly that session, on vt's own tmux server: tmux sends SIGHUP to its
//   relay, API and page; the API releases api.lock on SIGHUP), then removes $VT_HOME/<network>/up.json so the page's
//   network selector shows the stack down. A stack that is not running is not an error: up.json is removed all the same (a stale one would show
//   a dead stack as up). Nothing is ever killed by pattern; the tokens and the logs stay.
import type { Network } from '@vault-timelock/core/contracts'
import { assertNetwork } from '@vault-timelock/core/contracts'
import { rmSync } from 'node:fs'
import { join } from 'node:path'
import { UsageError } from '../args.ts'
import type { Env } from './paths.ts'
import { stateDir, vtHome } from './paths.ts'
import { UP_JSON } from './stack.ts'
import { hasSession, killSession, sessionName, systemTmux } from './tmux.ts'
import type { Tmux } from './tmux.ts'

export interface DownDeps { tmux: Tmux; out: (line: string) => void; err: (line: string) => void }

export function parseDownArgs(args: readonly string[]): void {
  if (args.length !== 0) throw new UsageError('usage: vt down [--network local|testnet|mainnet]')
}

export function down(o: { network: Network; env: Env }, deps: Partial<DownDeps> = {}): number {
  const d: DownDeps = {
    tmux: systemTmux({ env: o.env }),
    out: (l) => { process.stdout.write(`${l}\n`) },
    err: (l) => { process.stderr.write(`${l}\n`) },
    ...deps,
  }
  assertNetwork(o.network)
  const session = sessionName(o.network)
  const running = hasSession(d.tmux, session)
  if (running) {
    const r = killSession(d.tmux, session)
    if (r.code !== 0) {
      d.err(`vt down: tmux could not stop ${session}${r.code === null ? ` (${r.err})` : ''}; up.json was kept`)
      return 1
    }
  }
  rmSync(join(stateDir(vtHome(o.env), o.network), UP_JSON), { force: true })
  d.out(running ? `vt down: stopped ${session}` : `vt down: ${session} was not running`)
  return 0
}

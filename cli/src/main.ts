// cli/src/main.ts — the vt dispatcher (canonical vt spec §8; plan Task C1). Started only by bin/vt (cli/bin/vt),
// under env -i, unsandboxed for orchestration and pass-throughs, and inside sandbox-exec (VT_CONFINED=1) for client
// and executor commands.
//
// Before anything runs:
//   1. assertNoKeyEnv (vt-broadcast's config.ts): an API-key-like variable refuses config.env-key (only reachable
//      when someone starts this file without bin/vt);
//   2. confinement is PROVEN (src/ops/confine.ts, vt.not-confined) whenever VT_CONFINED=1 is set and for every
//      command args.ts sandboxes: a hand-set hint, a sandbox-exec that dropped the profile, or a drift between bin/vt
//      and args.ts fails closed;
//   3. every command but help needs explicit VT_HOME and VAULT_TIMELOCK_DIR in a development tree
//      (vt.dev-dirs-required); a release tree may use the defaults.
// Exit codes: 2 for a refusal (`refused <id>: <message>`), 1 for anything else, else the command's own status.
//
// ★ TEST-ONLY SEAM (M1 glue), unreachable from bin/vt: main()'s `seams.ports` replaces the network's fixed page, relay
//   and API ports for `vt job …`, so the E4 integration harness runs THIS dispatcher (`vt job run`, `vt job clawback`:
//   the env checks, the confinement proof, the dev-dirs rule, the network, the job commands) against a local stack on
//   ephemeral ports. Only cli/test/fixtures/vt-entry.ts passes it: a test fixture, never copied into a release (COPY is
//   cli/src and cli/bin), and a release holding it is refused (release.test-only-present). The file run as a program
//   (bin/vt) never passes it. Even so, a seam is refused (vt.test-only) unless this process runs as a test
//   (NODE_ENV=test, which bin/vt's env -i never passes), from a development tree (never a release), on local.
import { PORTS, refuse } from '@vault-timelock/core/contracts'
import { assertNoKeyEnv } from 'vt-broadcast/src/config.ts'
import { realpathSync } from 'node:fs'
import { dirname, isAbsolute } from 'node:path'
import { fileURLToPath } from 'node:url'
import { UsageError, isCommand, networksFor, sandboxFor } from './args.ts'
import { helpText } from './help.ts'
import { broadcastCommand, childEnv, runCommand, sealTarget } from './passthrough.ts'
import type { BroadcastSub } from './passthrough.ts'
import { importBackup, parseBackupArgs } from './ops/backup.ts'
import { assertConfined } from './ops/confine.ts'
import { down, parseDownArgs } from './ops/down.ts'
import { logs, parseLogsArgs } from './ops/logs.ts'
import { assertDevDirs, releaseId, vtHome } from './ops/paths.ts'
import type { Env } from './ops/paths.ts'
import type { Ports } from './job/client.ts'
import type { LocalnetPorts } from './ops/localnet.ts'
import { releaseCommand } from './ops/release.ts'
import { parseStatusArgs, status } from './ops/status.ts'
import { parseUpArgs, up } from './ops/up.ts'
import { failure } from './report.ts'

const SELF = realpathSync(fileURLToPath(import.meta.url))
const REPO = dirname(dirname(dirname(SELF))) // <repo>/cli/src/main.ts (a release tree has the same layout)

// The seams main() accepts (tests only; see the header): the job commands' ports.
export interface MainSeams { ports?: Ports; localnetPorts?: Partial<LocalnetPorts> }

// Refuses a test-only seam outside a test (NODE_ENV=test), in a release, or on testnet / mainnet (vt.test-only).
export function assertTestSeam(o: { nodeEnv: string | undefined; release: string | null; network: string | undefined }): void {
  const ok = o.nodeEnv === 'test' && o.release === null && (o.network === undefined || o.network === '' || o.network === 'local')
  if (!ok) refuse('vt.test-only', 'a test-only seam (the job ports or localnet ports override) needs NODE_ENV=test, a development tree and the local network; bin/vt and a release never offer it') // @guard:vt.test-only
}

export async function main(argv: readonly string[], env: Env, seams: MainSeams = {}): Promise<number> {
  assertNoKeyEnv(env)
  if (env.VT_BROKER === '1') (await import('./job/tty.ts')).watchBroker(env)
  if (seams.ports !== undefined || seams.localnetPorts !== undefined) assertTestSeam({ nodeEnv: process.env.NODE_ENV, release: releaseId(SELF, vtHome(env)), network: env.VT_NETWORK })
  if (env.VT_CONFINED === '1' || sandboxFor(argv) !== 'none') await assertConfined({ strict: true, writeDirs: isAbsolute(env.VT_HOME ?? '') ? [env.VT_HOME as string] : [] })

  const [cmd, ...rest] = argv
  if (cmd === undefined || cmd === 'help' || cmd === '--help' || cmd === '-h') {
    process.stdout.write(helpText())
    return 0
  }
  if (!isCommand(cmd)) throw new UsageError(`unknown command (run vt help for the list)`)
  const release = releaseId(SELF, vtHome(env))
  assertDevDirs(env, release !== null)
  // The network of up/down/logs: VT_NETWORK (bin/vt's --network), else local. status: that one, else all three.
  const network = networksFor([cmd], env.VT_NETWORK)[0]

  switch (cmd) {
    case 'up':
      return await up({ network, ...parseUpArgs(rest), env, repo: REPO, release })
    case 'down':
      parseDownArgs(rest)
      return down({ network, env })
    case 'logs':
      return await logs({ network, env, ...parseLogsArgs(rest) })
    case 'localnet': {
      // Loaded only for `vt localnet …`: it pulls in the tmux, http and bitcoind helpers no other command needs.
      const { localnetCommand } = await import('./ops/localnet.ts')
      return await localnetCommand({ args: rest, env, network: env.VT_NETWORK, ports: seams.localnetPorts })
    }
    case 'release':
      return releaseCommand({ args: rest, env, repo: REPO, release })
    case 'backup':
      return importBackup({ ...parseBackupArgs(rest), env, cwd: process.cwd() })
    case 'job': {
      // Ctrl-C ends a watch (vt job watch, vt job status --watch) cleanly, exit 0. Every other job command keeps the
      // default: Ctrl-C ends the process (a typed-word prompt included).
      const watching = rest[0] === 'watch' || (rest[0] === 'status' && rest.includes('--watch'))
      const ctl = new AbortController()
      if (watching) process.once('SIGINT', () => ctl.abort())
      // Loaded only for `vt job …`: the job client pulls in core's job, engine and chain modules (viem, web3.js), which
      // no other command needs.
      const { jobCommand, processIo } = await import('./job/index.ts')
      return await jobCommand(rest, processIo({ network, env, ports: seams.ports ?? PORTS[network], signal: ctl.signal }))
    }
    case 'source': {
      const { sourceCommand } = await import('./job/source.ts')
      const { processIo } = await import('./job/index.ts')
      return await sourceCommand(rest, processIo({ network, env, ports: seams.ports ?? PORTS[network] }))
    }
    case 'preflight': {
      // Loaded only for `vt preflight`: it pulls in core's executor (preflight reads through the relay), like `vt job …`.
      const { parsePreflightArgs, preflightCommand } = await import('./preflight.ts')
      return await preflightCommand({ network, env, json: parsePreflightArgs(rest).json })
    }
    case 'status':
      return await status({ networks: networksFor(['status'], env.VT_NETWORK), explicit: (env.VT_NETWORK ?? '') !== '', json: parseStatusArgs(rest).json, env })
    case 'seal':
    case 'open': {
      const [kind, ...args] = rest
      if (kind !== 'vault' && kind !== 'file') throw new UsageError(`usage: vt ${cmd} vault ... | vt ${cmd} file ...`)
      return await runCommand(sealTarget(kind, env, REPO), [cmd, ...args], childEnv(env, { for: 'sealer' }), { show: true })
    }
    case 'note':
    case 'seal-text':
    case 'tor-check':
    case 'keystore':
    case 'triggers': {
      const { file, args } = broadcastCommand(cmd as BroadcastSub, rest)
      return await runCommand(file, args, childEnv(env, { for: 'broadcast' }), { show: false })
    }
    default:
      throw new UsageError(`unknown command (run vt help for the list)`)
  }
}

// main() with the failure line and exit code (bin/vt's path, and the test fixture's).
export async function runMain(argv: readonly string[], env: Env, seams: MainSeams = {}): Promise<void> {
  try {
    process.exitCode = await main(argv, env, seams)
  } catch (e) {
    const f = failure(e)
    process.stderr.write(f.line)
    process.exitCode = f.code
  }
}

// Run as a program (bin/vt: `node cli/src/main.ts …`): never with a seam.
if (import.meta.main) await runMain(process.argv.slice(2), process.env)

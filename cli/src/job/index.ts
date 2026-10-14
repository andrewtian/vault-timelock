// cli/src/job/index.ts — `vt job <subcommand> …`: the client commands of plan Task C5 (spec §8), inside the client
// sandbox (bin/vt; src/args.ts), and the executor commands of Task C6, inside the executor sandbox:
//
//   validate <file> [--message-file F] [--normalize] [--json]      offline: the canonical definition and its id
//   create <file> [--message-file F] [--yes-publish-file SHA256] [--normalize] [--json]
//                                                    confirm the file, upload the text by digest, post the definition
//   list [--json]                                    every job of this network
//   status <id> [--watch] [--json]                   one job; --watch then follows it
//   watch <id> [--from N] [--json]                   follow the journal (SSE, resumes with Last-Event-ID)
//   arm <id> [--chains eth,sol] [--source eth=a,sol=b] [--countdown S] [--stagger MIN,MAX] [--json]
//   skip <id> · stop <id> [--chain c] · resume <id> [--chain c] [--tip-cap-gwei X] [--cu-price-cap N] · close <id> --chain c
//   resolve <id> --chain c --tx <txId> mark-done|mark-failed
//   receipt <id> [--json]                            stdout only (no --out)
//   run <id> [--chain c] --backup-eth F --backup-sol F --backup-btc F   the executor: decrypts the keys in memory, signs (run.ts)
//   clawback <id> --chain c --to <address> --backup-<c> F   send a settled chain's remainder (clawback.ts)
// Unexpected errors are reported through C4's printer too (an error text never prints an address or a control
// sequence); refusals keep their guard id (client.ts sanitises an API refusal's message when it is made).
import { isRefusal } from '@vault-timelock/core/contracts'
import { readTypedWord } from 'vt-broadcast/src/lifecycle/typed.ts'
import { sharedBrokerTty } from './tty.ts'
import { UsageError } from '../args.ts'
import type { Env } from '../ops/paths.ts'
import { armCommand } from './arm.ts'
import type { ArmDeps } from './arm.ts'
import { clawbackCommand } from './clawback.ts'
import type { JobIo, Ports } from './client.ts'
import { safeLine } from './client.ts'
import { controlCommand, resolveCommand } from './control.ts'
import { createCommand } from './create.ts'
import { listCommand } from './list.ts'
import { receiptCommand } from './receipt.ts'
import { runCommand } from './run.ts'
import type { RunDeps } from './run.ts'
import { statusCommand, watchCommand } from './status.ts'
import { validateCommand } from './validate.ts'

export const JOB_USAGE = 'usage: vt job validate|create|list|status|watch|arm|skip|stop|resume|close|resolve|receipt|run|clawback … (vt help)'

// The real outside world of a job command (main.ts).
export function processIo(o: { network: JobIo['network']; env: Env; ports: Ports; signal?: AbortSignal }): JobIo {
  return {
    network: o.network, env: o.env, cwd: process.cwd(), ports: o.ports,
    out: (t) => { process.stdout.write(t) },
    err: (t) => { process.stderr.write(t) },
    ask: (prompt, kind) => (process.env.VT_BROKER === '1' ? sharedBrokerTty().word(prompt, kind) : readTypedWord(prompt)),
    now: () => Date.now(),
    ...(o.signal === undefined ? {} : { signal: o.signal }),
  }
}

export interface JobDeps { arm?: ArmDeps; run?: RunDeps }

async function dispatch(argv: readonly string[], io: JobIo, deps: JobDeps): Promise<number> {
  const [sub, ...rest] = argv
  switch (sub) {
    case 'validate': return validateCommand(rest, io)
    case 'create': return await createCommand(rest, io)
    case 'list': return await listCommand(rest, io)
    case 'status': return await statusCommand(rest, io)
    case 'watch': return await watchCommand(rest, io)
    case 'arm': return await armCommand(rest, io, deps.arm)
    case 'skip':
    case 'stop':
    case 'resume':
    case 'close': return await controlCommand(sub, rest, io)
    case 'resolve': return await resolveCommand(rest, io)
    case 'receipt': return await receiptCommand(rest, io)
    case 'run': return await runCommand(rest, io, deps.run)
    case 'clawback': return await clawbackCommand(rest, io, deps.run)
    default: throw new UsageError(JOB_USAGE)
  }
}

export async function jobCommand(argv: readonly string[], io: JobIo, deps: JobDeps = {}): Promise<number> {
  try {
    return await dispatch(argv, io, deps)
  } catch (e) {
    if (isRefusal(e) || e instanceof UsageError) throw e
    throw new Error(safeLine(e instanceof Error ? e.message : String(e)))
  }
}

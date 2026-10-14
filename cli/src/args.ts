// cli/src/args.ts — the dispatcher's command table (canonical vt spec §8; plan Task C1).
//
// Which sandbox each command runs in (spec §3.1):
//   none      orchestration and pass-throughs: node runs unsandboxed (they apply sandboxes themselves, exec a tool that
//             applies its own, or exec the sealer; macOS refuses nesting);
//   client    status, preflight and every `job` subcommand except run/clawback: loopbackProfile([page, relay, api])
//             (controller ruling (2) on C1); no file writes;
//   executor  job run, job clawback (holds a key in memory): loopbackProfile([relay, api]);
//   decrypt   vt decrypt (design 2026-10-14-vt-decrypt): loopbackProfile([relay]) — the relay port only (a time lock's drand round), reads
//             only the files it is handed (the input, --identity), no file writes (the broker writes --out), no api.token or up.json.
// TTY-less round: no sandboxed command gets a terminal (the profile denies /dev/tty and every pty device); the unsandboxed broker
// (src/ops/broker.ts) asks every typed confirmation (`publish`, `broadcast`, an over-cap amount, `resolve`, `resume`) and the
// passphrase, and passes the answers over a pipe.
// bin/vt classifies with the same rule in sh (status|preflight|job -> sandboxed); test/args.test.ts pins that the two
// agree for every command, and src/main.ts proves confinement for every command this table sandboxes, so a drift
// fails closed (vt.not-confined), never open.
import type { Network } from '@vault-timelock/core/contracts'
import { NETWORKS, assertNetwork } from '@vault-timelock/core/contracts'

export type Sandbox = 'none' | 'client' | 'executor' | 'decrypt'

// Every top-level command (spec §8). `job`'s subcommands decide between client and executor (sandboxFor).
export const COMMANDS: Readonly<Record<string, Sandbox>> = {
  help: 'none', up: 'none', down: 'none', logs: 'none', release: 'none', backup: 'none', localnet: 'none',
  seal: 'none', open: 'none',
  note: 'none', 'seal-text': 'none', 'tor-check': 'none', keystore: 'none', triggers: 'none',
  status: 'client', preflight: 'client', job: 'client', source: 'client',
  decrypt: 'decrypt',
}

export function isCommand(cmd: string | undefined): cmd is string {
  return cmd !== undefined && Object.hasOwn(COMMANDS, cmd)
}

export function sandboxFor(argv: readonly string[]): Sandbox {
  const [cmd, sub] = argv
  if (cmd === 'job') return sub === 'run' || sub === 'clawback' ? 'executor' : 'client'
  return isCommand(cmd) ? COMMANDS[cmd] : 'none'
}

// Client commands that read a typed word (C5). Since the TTY-less round their profile gets no terminal: the broker asks the word
// (commandProfile no longer reads this; kept for the tests that pin the list).
export const CLIENT_TTY: readonly string[] = ['create', 'arm', 'resolve']
export function clientTty(argv: readonly string[]): boolean {
  return argv[0] === 'job' && CLIENT_TTY.includes(argv[1] ?? '')
}

// The networks a sandboxed command may reach: VT_NETWORK when set (checked against the three names; bin/vt has
// already refused anything else, vt.network-invalid), else every network for `status` (spec §8: "every network's
// stack, or one"), else local.
export function networksFor(argv: readonly string[], network: string | undefined): Network[] {
  if (network !== undefined && network !== '') {
    assertNetwork(network)
    return [network]
  }
  return argv[0] === 'status' ? [...NETWORKS] : ['local']
}

// A command line vt cannot run (wrong or missing words). Exit 1 with a hint, never a guard refusal.
export class UsageError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'UsageError'
  }
}

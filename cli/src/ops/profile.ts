// cli/src/ops/profile.ts — prints the sandbox profile bin/vt applies to a sandboxed command (plan Task C1).
//   node src/ops/profile.ts <command> [args...]      (VT_NETWORK from the environment)
// bin/vt runs it under env -i, before any sandbox exists, and checks that the output starts with the deny-all prefix;
// it prints the profile and nothing else (no newline). The strings come from sandbox.ts (one source) and the
// dispatch rule from args.ts. Exit 1 when the command is not a sandboxed one (bin/vt asked for a profile that the
// table does not give: a drift between the sh and args.ts), exit 2 on a refusal; bin/vt then refuses vt.no-sandbox.
// It also resolves what the file-read allow-list names (PF-C follow-up 2): the real paths of $VT_HOME and $VAULT_TIMELOCK_DIR, of the
// code tree this file belongs to (cli/src/ops/ -> the tree root), of the node binary that runs it (the same one bin/vt starts inside the
// sandbox: both come from PATH), of the working directory, of $HOME, and of every file named on the command line.
import { isRefusal } from '@vault-timelock/core/contracts'
import { resolveOut } from 'vt-broadcast/src/lifecycle/paths.ts'
import { vtHome } from './paths.ts'
import { realpathSync } from 'node:fs'
import { resolve } from 'node:path'
import { commandProfile, handedIndices } from './sandbox.ts'
import { scopeFor } from './scope.ts'
import { realPathOf } from './stack.ts'

// `profile.ts --args <argv...>`: the arguments bin/vt must run the sandboxed command with, as ONE line of single-quoted words for `eval set --`:
// every file the command is handed (--backup-<chain>, --message-file, the job file) becomes its absolute real path, so the sandboxed process can
// start in `/` and never needs to list the directories above it (follow-up 3).
if (process.argv[2] === '--args') {
  const argv = process.argv.slice(3)
  const idx = new Set(handedIndices(argv))
  const cwd = realpathSync(process.cwd())
  const q = (w: string): string => `'${w.replaceAll("'", "'\\''")}'`
  process.stdout.write(argv.map((a, i) => q(idx.has(i) ? realPathOf(resolve(cwd, a)) : a)).join(' '))
  process.exit(0)
}
try {
  const argv = process.argv.slice(2)
  const profile = commandProfile(argv, process.env.VT_NETWORK, realPathOf(vtHome(process.env)), realPathOf(resolveOut(process.env)), scopeFor(argv, process.env))
  if (profile === null) {
    process.stderr.write('vt: internal: bin/vt asked for the profile of a command that runs unsandboxed\n')
    process.exitCode = 1
  } else {
    process.stdout.write(profile)
  }
} catch (e) {
  process.stderr.write(isRefusal(e) ? `refused ${e.guardId}: ${e.message}\n` : 'vt: internal: cannot build the sandbox profile\n')
  process.exitCode = isRefusal(e) ? 2 : 1
}

// cli/src/help.ts — `vt help`: the whole workflow in order, then every command of canonical vt spec §8 (plan C1).

// The workflow, in the order the operator runs it: seal → up → job create → arm → run → status → receipt → down.
export const WORKFLOW: ReadonlyArray<readonly [string, string]> = [
  ['vt seal vault <vault> [DURATION] [...]', 'seal a 1Password vault into a timelocked package (or: vt seal file <path|-> ...)'],
  ['vt up --network local', 'start the relay, the jobs API and the page for one network'],
  ['vt job create <file>', 'create a vt-job/1 job; its message is uploaded by digest, never put in argv'],
  ['vt job arm <id>', 'arm it (typed confirmations on mainnet)'],
  ['vt job run <id>', 'run it here at the terminal (or press Run in the page)'],
  ['vt job status <id> --watch', 'follow it'],
  ['vt job receipt <id>', 'its vt-receipt/1 (no keys, no IPs, no message text)'],
  ['vt down --network local', 'stop that network\'s stack'],
]

// Every command, grouped by the sandbox it runs in.
export const SECTIONS: ReadonlyArray<readonly [string, readonly string[]]> = [
  ['Stacks and releases (orchestration: unsandboxed; they start the sandboxed processes)', [
    'vt localnet up [--no-btc] [--no-otterscan] [--reset] [--mine-every S]   (local only: anvil, solana-test-validator, bitcoind regtest + miner + wallet vt, ord 0.29.0, Otterscan; tmux session vt-localnet; data in $VT_HOME/localnet)',
    'vt localnet status [--json] | down   (down stops exactly vt-localnet; data kept)',
    'vt localnet fund eth|sol|btc <address> [amount]   (local chains only: 1 ETH / 2 SOL / 0.01 BTC by default; prints the tx id)',
    'vt up [--network local|testnet|mainnet] [--open] [--dev]',
    'vt down [--network N]',
    'vt logs relay|api|page|vite [--network N] [-n N] [-f]   (vite: vt up --dev, local only; IPs and control sequences redacted)',
    'vt release build | verify [<id>] | list',
    'vt backup import <file> [--chain eth|sol|btc]   (moves it: the original is removed after a durable 0600 copy; never decrypted)',
  ]],
  ['Client commands (sandbox: the network\'s page, relay and API ports only; no file writes; no terminal: vt\'s unsandboxed broker asks every typed word)', [
    'vt status [--network N] [--json]',
    'vt preflight [--network N] [--json]',
    'vt source list [--json]   (funding sources: labels only, NEVER deleted; once one exists every vt job arm needs --source <chain>=<label>)',
    'vt source add <label>   (1 to 24 lowercase letters, digits, hyphens; no typed confirmation: a source is only a label)',
    'vt job validate <file> [--message-file <path>] [--normalize] [--json]',
    'vt job create <file> [--message-file <path>] [--yes-publish-file <sha256>] [--normalize] [--json]',
    'vt job list [--json]',
    'vt job status <id> [--watch] [--json]',
    'vt job watch <id> [--from N] [--json]',
    'vt job arm <id> [--chains eth,sol] [--source eth=a,sol=b] [--countdown S] [--stagger MIN,MAX] [--json]',
    'vt job skip <id>',
    'vt job stop <id> [--chain c]',
    'vt job resume <id> [--chain c] [--tip-cap-gwei X] [--cu-price-cap N]   (lists which chains resumed and which were refused, with the reason: a final stop is never lifted; mainnet: type resume)',
    'vt job close <id> --chain c',
    'vt job resolve <id> --chain c --tx <id> mark-done|mark-failed',
    'vt job receipt <id> [--json]   (stdout only, no --out: vt job receipt <id> --json > receipt.json)',
  ]],
  ['Executor (sandbox: relay and API ports, no terminal: vt\'s broker asks the passphrase; needs a terminal; holds the key in memory only)', [
    'vt job run <id> [--chain eth|sol|btc] [--backup-eth F] [--backup-sol F] [--backup-btc F]   (a backup for each chain that runs)',
    'vt job clawback <id> --chain c --to <addr> [--backup-<c> F]   (the backup of that chain\'s key; eth and sol only: a btc claw-back is not available yet)',
  ]],
  ['Decrypt (sandbox: the network\'s relay port only, for a time lock; reads only the files it is handed; vt\'s broker reads a paste, asks the passphrase and writes --out)', [
    'vt decrypt [<file>|-] [--identity F] [--out <path|dir>] [--stdout] [--list] [--only <path>]   (age passphrase / identity / tlock files and SEALED.txt; no file or -: paste or pipe, 1 MiB at most)',
    '  plaintext goes only where asked: --out (0600, never overwriting; a new directory for a SEALED.txt, checked against its MANIFEST.csv / ATTACHMENTS.csv) or --stdout;',
    '  --list prints path + size of the archive\'s files (no contents); --only <path> one of them. A time lock needs vt up for that network (its relay fetches drand).',
  ]],
  ['Sealing (prints the command, then runs 1password-timelock.sh / timelock-key.sh with the same arguments)', [
    'vt seal vault ...',
    'vt seal file ...',
    'vt open vault ...',
    'vt open file ...',
  ]],
  ['vt-broadcast pass-throughs (bin/vt-broadcast applies its own sandbox; arguments unchanged)', [
    'vt note validate [...]                -> vt-broadcast validate-note',
    'vt seal-text <pkg> [...]              -> vt-broadcast seal-text',
    'vt tor-check                          -> vt-broadcast tor-check',
    'vt keystore init [...]                -> vt-broadcast keystore init',
    'vt triggers list|show|clear|resolve   -> vt-broadcast triggers',
  ]],
  ['Help', ['vt help']],
]

// How the job commands behave (C5), after the command list.
export const JOB_NOTES: readonly string[] = [
  'Jobs:',
  '  The message comes from an inline "message" in the job file, or from --message-file <path> on the command line',
  '  (never from the job file: a job JSON naming a file is refused). vt checks the path first: no link, a regular',
  '  file, never keys or credentials (~/.ssh, ~/.gnupg, ~/Library/Keychains, ~/.aws, ~/.config/op, ~/.op), never',
  '  vt\'s state, and inside $OUT, ~/p/1password-* or any package only a package\'s SEALED.txt (vt.message-path).',
  '  It shows the file\'s real path, size, sha256 and first line, and publishes it only after you type publish (or',
  '  --yes-publish-file <sha256> names that exact digest). The text is decoded strictly (invalid UTF-8 is refused,',
  '  never replaced), checked, uploaded by digest and referenced by it: it is never put in argv or a JSON body.',
  '  Text is refused, never rewritten. Only --normalize rewrites, and only when given: CRLF and CR become LF, each',
  '  TAB becomes spaces to the next tab stop (8 columns); it prints what it changed, and never writes the file.',
  '  vt job arm computes each chain\'s cap through the relay. On mainnet it is refused while job sends are locked,',
  '  then needs the word broadcast typed at the terminal. A chain over the R60 cap needs its planned amount typed',
  '  exactly (shown in full, compared in base units). Chains left out of --chains become SKIPPED for good.',
  '  vt job resolve records your outcome for an attempt of a STUCK chain (mainnet: type resolve). mark-failed frees',
  '  no cap: only chain evidence (an executor\'s reconcile) does.',
  '  vt job watch (and status --watch) follow the journal and resume after a dropped stream; Ctrl-C ends the watch only.',
  '  vt job run decrypts each key backup in memory, after the passphrase typed at the terminal (not echoed; never',
  '  stdin, argv or the environment: no terminal is refused). The key must be the job\'s keyAddress and the backup',
  '  made on the job\'s network (a backup that records none needs again typed). Mainnet is refused while job sends',
  '  are locked. Then it holds each chain\'s lease and runs it: s skips the countdown; Ctrl-C DETACHES (no stop is',
  '  journaled: the chains stay as they are, an in-flight transaction is not abandoned, and the next vt job run or Run here takes over).',
  '  To STOP a job use vt job stop <id> (after the in-flight transaction); vt job resume <id> continues RESUMABLE stopped chains only (mainnet: type resume).',
  '  vt job clawback sends a settled chain\'s remainder (value + fee = the lane\'s balance) to --to: checksummed,',
  '  never the lane itself or a burn address, the job\'s clawbackTo when it names one. Over what is left of the',
  '  armed cap the exact amount is typed; mainnet needs claw back typed. It links the key to --to on-chain.',
  'Stacks: vt up runs relay, api and page in tmux on vt\'s own server: tmux -L vt attach -t vt-<network>',
  '  (never the default tmux server); vt logs <window> --network <network> shows a window\'s log.',
]

export function helpText(): string {
  const w = Math.max(...WORKFLOW.map(([c]) => c.length))
  const lines = [
    'vt: vault-timelock (seal, publish by job, receipts)',
    '',
    'usage: vt [--network local|testnet|mainnet] <command> [args]',
    '  --network may appear anywhere, once (or set VT_NETWORK). Client commands default to local;',
    '  `vt status` without a network shows every network.',
    '',
    'Workflow, in order:',
    ...WORKFLOW.map(([c, d], i) => `  ${i + 1}. ${c.padEnd(w)}  ${d}`),
    '',
    'Commands:',
  ]
  for (const [title, cmds] of SECTIONS) lines.push(`  ${title}:`, ...cmds.map((c) => `    ${c}`))
  lines.push('', ...JOB_NOTES)
  lines.push(
    '',
    'Environment: only PATH HOME LANG TERM VT_HOME VAULT_TIMELOCK_DIR XDG_DATA_HOME VT_NETWORK VT_SEALER reach vt',
    '(env -i). VT_HOME defaults to ~/.local/state/vt. From a development tree, VT_HOME and VAULT_TIMELOCK_DIR must',
    'both be set. VT_SEALER is for tests only: a stub inside cli/test/fixtures/, never the real sealer.',
    'vt seal|open also pass the sealer TMPDIR, TOR_SOCKS (127.0.0.1:<port> or [::1]:<port> only), OP_ACCOUNT and',
    'OP_SESSION_*; never OP_SERVICE_ACCOUNT_TOKEN or OP_CONNECT_* (a note says so when they are set).',
    'Refusals print "refused <id>: <reason>" and exit 2.',
  )
  return lines.join('\n') + '\n'
}

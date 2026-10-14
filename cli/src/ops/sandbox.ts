// cli/src/ops/sandbox.ts — the sandbox-exec profiles of every vt process (canonical vt spec §3.1; plan Tasks C1, C3).
// One source: bin/vt applies loopbackProfile through src/ops/profile.ts, and `vt up` (C3, src/ops/stack.ts) starts the
// relay, the API and the page server with relayProfile / apiProfile / loopbackProfile (and, with --dev, the Vite dev
// server with viteProfile). Pure: strings in, strings out.
//
// ★ Every value that goes into a profile is checked first, because a profile is code (SBPL):
//   · ports are integers 1..65535 (vt.port), written as decimal digits, sorted and de-duplicated;
//   · paths are absolute, normalised, not "/", no trailing "/", and free of the characters that could end or
//     escape an SBPL string or form ( " ) ( \ ; ) and of control characters (vt.path). The value is never echoed.
// ★ Rule order matters: a later rule overrides an earlier one, so each profile is "allow default", then the denies,
//   then the narrow allows.
import type { Network } from '@vault-timelock/core/contracts'
import { NETWORKS, PORTS, assertNetwork, refuse } from '@vault-timelock/core/contracts'
import { dirname, isAbsolute, normalize } from 'node:path'
import { clientTty, networksFor, sandboxFor } from '../args.ts'
import { decryptPositions } from '../decrypt-args.ts'

// Every profile starts with this: nothing leaves the process except what a later rule allows.
export const DENY_NETWORK = '(version 1)(allow default)(deny network-outbound)'
// The executor holds decrypted keys: it also never listens or accepts a connection (C7, parked from C6 fix round 1). A
// listener is the way a debugger, a log tap or a reverse shell would be reached; the executor needs none.
export const DENY_LISTEN = '(deny network-bind)(deny network-inbound)'
const TOR = '(allow network-outbound (remote ip "localhost:9050"))'
const allowPort = (p: number): string => `(allow network-outbound (remote ip "localhost:${p}"))`

// The ports, checked (vt.port), sorted ascending and de-duplicated.
export function sandboxPorts(ports: readonly number[]): number[] {
  for (const p of ports) {
    const ok = Number.isInteger(p) && p >= 1 && p <= 65535
    if (!ok) refuse('vt.port', 'a sandbox port must be an integer from 1 to 65535 (the value is not echoed)') // @guard:vt.port
  }
  return [...new Set(ports)].sort((a, b) => a - b)
}

// A path that goes into a profile (or becomes the root of one: VT_HOME, a state dir). Refuses vt.path.
// A file NAMED by the operator or inherited (a handed backup, a redirected stdout): inside an SBPL string literal only `"`, `\` and control
// characters are special, so spaces, parentheses and `;` are fine (Chrome's "eth-key (1).age"); absolute and normalised as above.
export function assertProfileFile(p: string): void {
  // spaces, parentheses and `;` are harmless in an SBPL string: check the same rule on the name with them replaced by `_`
  assertProfilePath(typeof p === 'string' ? p.replace(/[ ();]/g, '_') : p)
}
export function assertProfilePath(p: string): void {
  const ok = typeof p === 'string' && isAbsolute(p) && normalize(p) === p && !p.endsWith('/') && !/["()\\;\u0000-\u001f\u007f]/.test(p)
  if (!ok) refuse('vt.path', 'a sandboxed path must be absolute and normalised (not "/", no trailing "/"), without quotes, parentheses, backslashes, semicolons or control characters (the value is not echoed)') // @guard:vt.path
}

// The relay: Tor's SOCKS port only; on the local network also the loopback chain ports (endpoints.json `local`).
// Chain ports on testnet or mainnet are refused (vt.relay-ports): those relays reach their chains through Tor only.
export function relayProfile(network: Network, chainPorts: readonly number[]): string {
  assertNetwork(network)
  const ok = network === 'local' || chainPorts.length === 0
  if (!ok) refuse('vt.relay-ports', 'loopback chain ports are allowed for the local relay only; testnet and mainnet relays reach their chains through Tor') // @guard:vt.relay-ports
  return DENY_NETWORK + TOR + sandboxPorts(chainPorts).map(allowPort).join('')
}

// The jobs API: no outbound connection at all, and file writes only below its state dir (plus /dev/null).
// ★ SBPL matches RESOLVED paths (C1 review M2): a subpath through a symlink (/tmp/... on macOS is /private/tmp/...)
//   denies every write. Callers pass the real path of the state dir (src/ops/stack.ts stackWindows does).
// outDir ($OUT, VAULT_TIMELOCK_DIR; S2 reads its legacy latch there): READ ONLY. `(allow default)` already allows
// reads everywhere; the two rules name the scope and, coming last, deny every write below $OUT even when $OUT lies
// inside the state dir.
export function apiProfile(stateDir: string, outDir?: string): string {
  assertProfilePath(stateDir)
  const base = `${DENY_NETWORK}(deny file-write*)(allow file-write* (subpath "${stateDir}") (literal "/dev/null"))`
  if (outDir === undefined) return base
  assertProfilePath(outDir)
  return `${base}(allow file-read* (subpath "${outDir}"))(deny file-write* (subpath "${outDir}"))`
}

// The page server, the CLI executor and the client commands: the given loopback ports only, and no file writes but
// /dev/null; with tty (the executor: the passphrase prompt, the countdown keys) also /dev/tty; with noListen (the
// executor and, since Cfix4, every client command) no bind and no inbound connection either (the page server must
// listen, so it never gets noListen).
export function loopbackProfile(ports: readonly number[], o: { tty?: boolean; noListen?: boolean } = {}): string {
  const writes = o.tty === true
    ? '(allow file-write* (literal "/dev/null") (literal "/dev/tty"))'
    : '(allow file-write* (literal "/dev/null"))'
  return DENY_NETWORK + sandboxPorts(ports).map(allowPort).join('') + '(deny file-write*)' + writes + (o.noListen === true ? DENY_LISTEN : '')
}

// The Vite dev server (`vt up --dev`, local only): the given loopback ports (the relay and the API it proxies to), and
// file writes only to /dev/null and its dependency cache (web/node_modules/.vite, a real path: Vite pre-bundles the
// dependencies there and cannot serve without it; it is started with --configLoader native, so it needs no
// .vite-temp). It holds no key and no token on disk.
export function viteProfile(ports: readonly number[], cacheDir: string): string {
  assertProfilePath(cacheDir)
  return DENY_NETWORK + sandboxPorts(ports).map(allowPort).join('') + `(deny file-write*)(allow file-write* (literal "/dev/null") (subpath "${cacheDir}"))`
}

// The profile bin/vt applies to a command line (after --network became VT_NETWORK), for each network the command may
// reach (networksFor):
//   client    (status, preflight, job … except run/clawback): no listening or inbound connection (Cfix4, C1 review M3),
//             and the page, relay and API ports (controller ruling (2) on
//             C1: `vt status` reads the page server's /__serve, and C7's preflight compares the page and relay digests);
//             no terminal (TTY-less round: the unsandboxed broker asks the typed confirmations of `job create`, `job arm`,
//             `job resolve` and `job resume`; C5);
//   executor  (job run, job clawback): the relay and API ports, no terminal (the broker asks the passphrase), and no listening
//             or inbound connection at all (network-bind and network-inbound denied; C7).
// null: the command is not sandboxed.
export function commandProfile(argv: readonly string[], network: string | undefined, home: string, out: string, scope: ReadScope): string | null {
  const kind = sandboxFor(argv)
  if (kind === 'none') return null
  // Fail closed (PF-C follow-up (a)): the file-read rules need the REAL paths of $VT_HOME, $VAULT_TIMELOCK_DIR, the code tree, the node
  // install, the working directory and the files the command was handed; a missing or unsafe one refuses (vt.path) instead of silently
  // leaving the profile without its allow-list or its denies.
  const nets = networksFor(argv, network)
  // vt decrypt: the relay port only (a time lock's drand signature), never the API or the page, and none of their tokens (below)
  if (kind === 'decrypt') {
    return loopbackProfile(nets.map((n) => PORTS[n].relay), { tty: false, noListen: true }) + readAllowList(home, nets, scope, out, false, false) + denyProtectedFiles(home, out, nets, scope.userHomes ?? scope.userHome) + hardening(scope, false) + denyTerminals()
  }
  const ports = nets.flatMap((n) => kind === 'client'
    ? [PORTS[n].page, PORTS[n].relay, PORTS[n].api]
    : [PORTS[n].relay, PORTS[n].api])
  // TTY-less round: no sandboxed command gets a terminal, whatever it prompts for. The unsandboxed broker (src/ops/broker.ts) asks on /dev/tty and passes
  // answers through a pipe; /dev/tty and the pty devices are denied for read, write and ioctl (denyTerminals), so TIOCSTI, termios and escape-sequence
  // writes to the terminal are impossible, also through an inherited descriptor.
  void clientTty
  return loopbackProfile(ports, { tty: false, noListen: true }) + readAllowList(home, nets, scope, out, false) + denyProtectedFiles(home, out, nets, scope.userHomes ?? scope.userHome) + hardening(scope, false) + denyTerminals()
}

// I-2: `(allow default)` leaves the other channels open, so a compromised dependency could use system brokers (preferences via cfprefsd, the
// pasteboard, LaunchServices `open`, Apple Events) or exec helpers, even though its file reads are confined. Closed here, for client and
// executor processes only: no exec but the launcher chain (sh, env, the vt launcher script, node), no mach service lookup, no Apple Events,
// no POSIX/SysV shared memory or semaphores (raw IPC), no AF_SYSTEM sockets, no ioctl but on /dev/null and (prompting commands) /dev/tty. no process-fork (TTY-less round 3: bin/vt's sandboxed branch and the launcher only exec, never fork; measured). Each was measured against the real command paths
// (test/ticket-key-real.test.ts, wrapper.test.ts, run-real.test.ts).
// The terminals: /dev/tty (the controlling terminal), the pty slaves and masters, the console. A later rule than every allow, for all three operations.
export const TERMINAL_RE = '^/dev/(tty[a-z0-9]*|pty[a-z0-9]*|ptmx|console)$'
export function denyTerminals(): string {
  return `(deny file-read* file-write* file-ioctl (literal "/dev/tty") (regex #"${TERMINAL_RE}"))`
}
export function hardening(scope: ReadScope, tty: boolean): string {
  const execs = [...EXEC_SYSTEM, scope.launcher, ...scope.node].map((p) => `(literal "${p}")`).join(' ')
  // I-2 (fix round): NO native code may be mapped into the sandboxed process or ANY process it starts, however node is started (a second node without --no-addons
  // could otherwise dlopen a .node file from node_modules): only the system libraries, the shell chain and the node binary with the dylibs it loads (measured: node starts and
  // `vt status` runs with exactly this). M-1: signals only to itself, so the child cannot signal the broker, the relay, the API or another executor.
  const maps = [...EXEC_SYSTEM, ...scope.node].map((p) => `(literal "${p}")`).join(' ')
  return `(deny process-exec*)(allow process-exec* ${execs})(deny file-map-executable)(allow file-map-executable (subpath "/usr/lib") (subpath "/System") ${maps})(deny signal)(allow signal (target self))(deny process-fork)(deny mach-lookup)(deny appleevent-send)(deny ipc-posix*)(deny ipc-sysv*)(deny system-socket)(deny file-ioctl)(allow file-ioctl (literal "/dev/null")${tty ? ' (literal "/dev/tty")' : ''})`
}

// PF-C follow-up 2: an ALLOW-LIST for file reads (a deny list cannot be complete). Under client and executor profiles a process can read
// file CONTENTS only of: the system paths node and the shell scripts need (measured with the real-sandbox probes), the vt code tree in use
// (dev repo root or release dir), the node install, /dev/null /dev/tty /dev/urandom, the working directory's ancestors as directories
// (so `getcwd` works; their listings, never their files), the api.token and up.json (`vt status`) of the networks the command talks to, and the files the command
// was HANDED (each --backup-<chain>, --message-file and a job file, as literal real paths). Metadata (stat) stays readable: node's realpath
// and the shell's path checks need it, and it shows no contents. Nothing else under $HOME. The explicit denies of denyProtectedFiles come
// AFTER this (belt and braces: a later rule wins), and cover the default locations too.
export interface ReadScope {
  tree: readonly string[]      // real subpaths of the vt code tree in use that the command imports (dev: cli/src, packages/core/src, broadcast/src, node_modules ...; a release: the release dir)
  treeFiles: readonly string[] // real files of that tree it reads by name (package.json files, broadcast/endpoints.json)
  node: readonly string[]      // the node binary as PATH finds it, each symlink on the way, its real file, and exactly the non-system dylibs it loads (otool -L, recursively), as literals
  launcher: string             // real path of cli/bin/vt of the tree in use: the one script sandbox-exec execs (and /bin/sh runs)
  stdio: readonly string[]     // real paths of the regular files fds 0-2 are redirected to (`> receipt.json`): node fstat()s them at start
  userHome: string             // real path of the home directory from the password database (os.userInfo().homedir), not $HOME
  userHomes?: readonly string[]  // that and $HOME when it differs: the default-location denies name each
  handed: readonly string[]    // real paths of the files the command was handed (bin/vt rewrites the arguments to exactly these)
}
// /usr/local (a Homebrew prefix on Intel Macs) is NOT included; /usr/bin and /bin are only what the exec chain needs (below)
export const SYSTEM_READ: readonly string[] = ['/usr/lib', '/usr/share', '/System']
export const EXEC_SYSTEM: readonly string[] = ['/bin/sh', '/bin/bash', '/usr/bin/env']
// '/' itself: dyld/the kernel read the root directory at process start (measured: without it every process aborts). That also lets the process list `/`
// (its entry names, nothing below); every other directory stays unlistable. /dev/tty is added only for commands that prompt (commandProfile).
export const DEV_READ: readonly string[] = ['/', '/private/var/select/sh', '/dev/null', '/dev/urandom']
const FILE_FLAGS: ReadonlySet<string> = new Set(['--backup-eth', '--backup-sol', '--backup-btc', '--message-file'])
const VALUE_FLAGS: ReadonlySet<string> = new Set(['--yes-publish-file', '--chain', '--chains', '--source', '--countdown', '--stagger', '--tx', '--to', '--from', '--tip-cap-gwei', '--cu-price-cap', '-n'])
// The positions (in argv) of the files named on a command line: --backup-<chain> F, --message-file F, and the job file of
// `job create|validate <file>`; vt decrypt's input file and --identity F (src/decrypt-args.ts decryptPositions).
export function handedIndices(argv: readonly string[]): number[] {
  const out: number[] = []
  if (argv[0] === 'decrypt') return decryptPositions(argv).handed
  if (argv[0] !== 'job') return out
  const wantsFile = argv[1] === 'create' || argv[1] === 'validate'
  let gotFile = false
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]
    if (FILE_FLAGS.has(a)) { if (argv[i + 1] !== undefined) out.push(++i) } else if (VALUE_FLAGS.has(a)) i++
    else if (wantsFile && !gotFile && !a.startsWith('-')) { out.push(i); gotFile = true }
  }
  return out
}
export function handedFiles(argv: readonly string[]): string[] {
  return handedIndices(argv).map((i) => argv[i])
}
// The positions bin/vt rewrites to absolute real paths (profile.ts --args): the handed files, and vt decrypt's --out (never handed to the
// sandbox: the unsandboxed broker, which runs in `/`, creates it).
export function pathIndices(argv: readonly string[]): number[] {
  const out = argv[0] === 'decrypt' ? decryptPositions(argv).out : null
  return [...handedIndices(argv), ...(out === null ? [] : [out])]
}
// Fail closed (follow-up 3, item 5): no allowed SUBPATH may be, or contain, a place that holds vt's secrets or the operator's state:
// $HOME itself (or any ancestor), $HOME/.local, the default $OUT, the default state dir, ~/p, or the current $VT_HOME / $VAULT_TIMELOCK_DIR
// roots. Literals are exact files and are not checked (they are the tokens and the handed files, named one by one).
export function assertAllowListSafe(subpaths: readonly string[], userHome: string | readonly string[], extraRoots: readonly string[]): void {
  const homes = typeof userHome === 'string' ? [userHome] : userHome
  for (const h of homes) assertProfilePath(h)
  const protectedRoots = [...homes.flatMap((h) => [h, `${h}/.local`, `${h}/.local/share/vault-timelock`, `${h}/.local/state/vt`, `${h}/p`]), ...extraRoots]
  for (const sub of subpaths) {
    const bad = protectedRoots.some((r) => r === sub || r.startsWith(`${sub}/`) || sub === '/')
    if (bad) refuse('vt.read-allow', 'a sandbox read allow-list entry would cover $HOME, vt\'s state or credential directories, or the operator\'s package directories: refused (the value is not echoed)') // @guard:vt.read-allow
  }
}
export const ROOT_LINKS: readonly string[] = ['/tmp', '/var', '/etc']
const ancestorsOf = (p: string): string[] => { const out: string[] = []; for (let d = dirname(p); ; d = dirname(d)) { out.push(d); if (d === '/' || dirname(d) === d) break } return out }
// tokens = false (vt decrypt): the networks' api.token and up.json are not in the list either: that command talks to the relay only.
export function readAllowList(home: string, nets: readonly string[], scope: ReadScope, out: string = '', tty: boolean = true, tokens: boolean = true): string {
  assertProfilePath(home)
  if (out !== '') assertProfilePath(out)
  assertAllowListSafe([...SYSTEM_READ, ...scope.tree], scope.userHomes ?? scope.userHome, [home, ...(out === '' ? [] : [out])])
  for (const p of [...scope.tree, ...scope.treeFiles, ...scope.node, home]) assertProfilePath(p)
  for (const p of [...scope.handed, ...scope.stdio, scope.launcher]) assertProfileFile(p)
  const subs = [...SYSTEM_READ, ...scope.tree].map((p) => `(subpath "${p}")`)
  const states = tokens ? [...nets.map((n) => `${home}/${n}/api.token`), ...nets.map((n) => `${home}/${n}/up.json`)] : []
  const files = [...DEV_READ.filter((p) => tty || p !== '/dev/tty'), ...EXEC_SYSTEM, scope.launcher, ...scope.node, ...scope.treeFiles, ...states, ...scope.handed]
  // metadata (stat, the realpath walk) only for what is allowed plus the directories ABOVE it; never a listing, never a content
  // + the macOS root symlinks (/tmp, /var, /etc -> /private/...): a VT_HOME given as /tmp/x is opened through the link, and stat-ing the link is a metadata read
  const above = [...new Set([...scope.tree, ...files, ...scope.stdio].flatMap(ancestorsOf)), ...ROOT_LINKS, ...scope.stdio]
  return `(deny file-read*)(allow file-read-metadata ${above.map((p) => `(literal "${p}")`).join(' ')} ${[...scope.tree, ...SYSTEM_READ].map((p) => `(subpath "${p}")`).join(' ')})(allow file-read* ${[...subs, ...files.map((p) => `(literal "${p}")`)].join(' ')})`
}

// M-3a (pre-flip review): the relay's ticket key ($VT_HOME/<network>/relay-ticket.key, one per network) lets its holder mint tickets
// the relay forwards, bypassing every API gate. Neither the executor (which holds a decrypted lane key in memory) nor a client
// command has any use for it, so every sandboxed command denies reading it, for all three networks. `home` is the REAL path of
// $VT_HOME (SBPL matches resolved paths). What the executor does need stays readable: api.token (the API client), the backup
// files it is handed (also under $VT_HOME/backups) and the message files. Appended last: a later rule overrides the allow default.
export const TICKET_KEY = 'relay-ticket.key'
export function denyTicketKeys(home: string): string {
  assertProfilePath(home)
  return NETWORKS.map((n) => `(deny file-read* (literal "${home}/${n}/${TICKET_KEY}"))`).join('')
}
// PF-C follow-up (c): neither a client command nor the executor ever reads the relay's bitcoind credential
// ($VAULT_TIMELOCK_DIR/local/btc-rpc.auth: the relay, the miner and the localnet tools read it, none of them under these profiles),
// and each needs only the api.token of the networks it talks to (networksFor), never another network's.
//
// Why a `literal` deny is enough against a hard link (follow-up (b)): link()/rename()/symlink() need file-write* on the new name, and
// every profile built here is `(deny file-write*)` except /dev/null (and /dev/tty): there is nowhere to create a second name for the
// key, and nothing the processes need is writable (node needs no temp dir to run; measured by the real-sandbox probes in
// test/ticket-key-real.test.ts, which try link(), symlink() and rename() onto the key and read it back through each).
export const BTC_AUTH = 'btc-rpc.auth'
export function denyProtectedFiles(home: string, out: string, networks: readonly string[], userHome?: string | readonly string[]): string {
  assertProfilePath(out)
  const others = NETWORKS.filter((n) => !networks.includes(n))
  let defaults = ''
  // the DEFAULT locations, whatever $VT_HOME / $VAULT_TIMELOCK_DIR are now (a release tree uses them), for every home given (the password database's, and $HOME)
  for (const h of userHome === undefined ? [] : typeof userHome === 'string' ? [userHome] : userHome) {
    assertProfilePath(h)
    defaults += denyTicketKeys(`${h}/.local/state/vt`) + `(deny file-read* (subpath "${h}/.local/share/vault-timelock"))`
  }
  return denyTicketKeys(home)
    + `(deny file-read* (literal "${out}/local/${BTC_AUTH}"))`
    + others.map((n) => `(deny file-read* (literal "${home}/${n}/api.token"))`).join('')
    + defaults
}

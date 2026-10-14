// cli/src/ops/localnet.ts — `vt localnet up|status|down|fund` (LN1; R77: the local network works from a purely local environment setup).
// Orchestration (unsandboxed, like `vt up`): ONE supported command brings up every endpoint the local profile uses, so a fresh
// operator runs `vt localnet up`, `vt up --network local --open`, `vt preflight --network local` and the whole local flow works.
//
//   service    endpoint (broadcast/endpoints.json `local`)   what it is
//   anvil      127.0.0.1:8545                                 chain id 31337, one block per second, state kept
//   solana     127.0.0.1:8999                                 solana-test-validator, --limit-ledger-size 50000000, ledger kept
//   bitcoind   127.0.0.1:18443                                regtest, wallet `vt`, 101 blocks mined to it on a fresh chain
//   miner      (no port)                                      one regtest block every N s (default 5), so commits/reveals confirm
//   ord        127.0.0.1:8090                                 ord 0.29.0, regtest, indexing that bitcoind
//   otterscan  127.0.0.1:5100                                 docker otterscan/otterscan:v2.11.0 (optional; skipped without docker)
//
// ★ Every service is a window of the session `vt-localnet` on vt's own tmux server (`tmux -L vt -f /dev/null`, exact targets).
//   Data lives under $VT_HOME/localnet/<service>/ and survives `down`; `--reset` wipes ONLY those directories.
// ★ BTC: the lane reads (relay) only getblockchaininfo/getblock*/gettxout/estimatesmartfee/testmempoolaccept/... and sends the
//   ticketed raw tx; NOTHING in vt mines, and a reveal's confirmation needs a block. So a `miner` window mines every N s. The
//   wallet `vt` exists for `vt localnet fund btc` (sendtoaddress) and receives the miner's coinbases.
// ★ The bitcoind password is 32 random hex characters. It is written ONLY to $VAULT_TIMELOCK_DIR/local/btc-rpc.auth (`vt:<pass>`,
//   0600, atomic) and, as bitcoind's salted rpcauth HASH, to $VT_HOME/localnet/bitcoind/bitcoin.conf (0600; never on argv). It is
//   on no command line and in no log; ord and the miner use the datadir cookie / the 0600 file (their argv holds paths only).
//   A password already in the file (>= 16 chars) is kept across restarts, so a running relay needs no restart.
// ★ Fail closed: every port is probed BEFORE anything starts. A port that answers with the right identity (anvil chain id 31337;
//   the validator's recorded genesis hash; bitcoind regtest, authenticated with our file; ord regtest; Otterscan) is reused and
//   said so; a port taken by anything else refuses (localnet.port-taken). vt never kills a process it did not start: `down`
//   kills exactly the session vt-localnet (+ the Otterscan container recorded as started by vt). :8899 (another project) is
//   never used: a port override naming 8899 or 8900 is refused (localnet.port-forbidden).
// ★ Test seam: LocalnetDeps.ports (cli main()'s `localnetPorts` seam, NODE_ENV=test only) replaces the fixed ports; bin/vt never
//   offers it. Tests never touch the shared chains.
import { GENESIS, isLocalSolanaGenesis, loadBitcoindAuth } from 'vt-broadcast/src/config.ts'
import { ensureDir, resolveOut } from 'vt-broadcast/src/lifecycle/paths.ts'
import { refuse } from '@vault-timelock/core/contracts'
import { createHash, createHmac, randomBytes } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { accessSync, constants, existsSync, lstatSync, realpathSync, rmSync, statSync } from 'node:fs'
import { delimiter, isAbsolute, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { UsageError } from '../args.ts'
import { jsonRpc, httpText, listenerPidOf, sleepMs, tcpOpen } from './localnet-rpc.ts'
import type { RpcReply } from './localnet-rpc.ts'
import { MINER_READY, WALLET } from './localnet-miner.ts'
import type { Env } from './paths.ts'
import { vtHome } from './paths.ts'
import { SH, freshLog, readSmallFile, scanLog, writePrivateFile } from './stack.ts'
import { assertProfilePath } from './sandbox.ts'
import { hasSession, killSession, killWindow, listWindows, newSession, newWindow, systemTmux } from './tmux.ts'
import type { Tmux } from './tmux.ts'

export const SESSION = 'vt-localnet'
export const SERVICES = ['anvil', 'solana', 'bitcoind', 'miner', 'ord', 'otterscan'] as const
export type Service = (typeof SERVICES)[number]
export const ORD_VERSION = '0.29.0'
export const OTTERSCAN_IMAGE = 'otterscan/otterscan:v2.11.0'
export const ANVIL_CHAIN_ID = 31337
export const RPC_USER = 'vt'
export const BTC_AUTH_FILE = 'btc-rpc.auth'
export const DEFAULT_MINE_EVERY = 5
export const MIN_PASS = 16
// solana-test-validator's default ports (RPC :8899, pubsub :8900) are left to any other local validator: never ours.
export const FORBIDDEN_PORTS: readonly number[] = [8899, 8900]

export interface LocalnetPorts {
  anvil: number
  solana: number          // the JSON-RPC port; the validator's pubsub takes solana + 1
  solanaFaucet: number
  solanaGossip: number
  solanaDynFrom: number   // --dynamic-port-range <from>-<to>
  solanaDynTo: number
  bitcoind: number
  ord: number
  otterscan: number
}
// The endpoints of broadcast/endpoints.json `local` (test/localnet.test.ts pins the agreement) and Otterscan's 5100. The
// validator's faucet, gossip and dynamic ports are chosen away from the validator defaults (9900, 8001, 8000-10000), which
// would collide with :8899/:8900/:8999/:9000.
export const DEFAULT_PORTS: Readonly<LocalnetPorts> = Object.freeze({
  anvil: 8545, solana: 8999, solanaFaucet: 9910, solanaGossip: 8110, solanaDynFrom: 8111, solanaDynTo: 8160, bitcoind: 18443, ord: 8090, otterscan: 5100,
})

// Every port the localnet binds, for the port checks: tcp listeners only matter to the probe.
export function allPorts(p: LocalnetPorts): number[] {
  const dyn: number[] = []
  for (let x = p.solanaDynFrom; x <= p.solanaDynTo; x++) dyn.push(x)
  return [p.anvil, p.solana, p.solana + 1, p.solanaFaucet, p.solanaGossip, p.bitcoind, p.ord, p.otterscan, ...dyn]
}

// The ports are well-formed, distinct, and never :8899 / :8900 (localnet.port-forbidden).
export function assertPorts(p: LocalnetPorts): LocalnetPorts {
  const bad = (n: number): boolean => !Number.isInteger(n) || n < 1024 || n > 65534
  const vals = [p.anvil, p.solana, p.solanaFaucet, p.solanaGossip, p.solanaDynFrom, p.solanaDynTo, p.bitcoind, p.ord, p.otterscan]
  if (vals.some(bad) || p.solanaDynTo < p.solanaDynFrom + 24) throw new UsageError('localnet ports: integers 1024..65534, and a validator dynamic range of at least 25 ports')
  const all = allPorts(p)
  if (new Set(all).size !== all.length) throw new UsageError('localnet ports must all differ (the validator also uses its RPC port + 1)')
  const hit = all.find((x) => FORBIDDEN_PORTS.includes(x))
  if (hit !== undefined) refuse('localnet.port-forbidden', `port ${hit} belongs to another project on this machine and is never used by vt localnet`) // @guard:localnet.port-forbidden
  return p
}

// ---- arguments

export type LocalnetCommand =
  | { sub: 'up'; btc: boolean; otterscan: boolean; reset: boolean; mineEvery: number }
  | { sub: 'status'; json: boolean }
  | { sub: 'down' }
  | { sub: 'fund'; chain: 'eth' | 'sol' | 'btc'; address: string; amount: string | null }

const USAGE = 'usage: vt localnet up [--no-btc] [--no-otterscan] [--reset] [--mine-every <seconds>] | status [--json] | down | fund <eth|sol|btc> <address> [amount]'

export function parseLocalnetArgs(args: readonly string[]): LocalnetCommand {
  const [sub, ...rest] = args
  switch (sub) {
    case 'up': {
      const seen = new Set<string>()
      let mineEvery = DEFAULT_MINE_EVERY
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i]
        if (a === '--mine-every') {
          const v = rest[++i]
          if (seen.has(a) || v === undefined || !/^[1-9][0-9]{0,3}$/.test(v) || Number(v) > 3600) throw new UsageError(`--mine-every needs whole seconds from 1 to 3600. ${USAGE}`)
          seen.add(a)
          mineEvery = Number(v)
        } else if ((a === '--no-btc' || a === '--no-otterscan' || a === '--reset') && !seen.has(a)) seen.add(a)
        else throw new UsageError(USAGE)
      }
      return { sub, btc: !seen.has('--no-btc'), otterscan: !seen.has('--no-otterscan'), reset: seen.has('--reset'), mineEvery }
    }
    case 'status':
      if (rest.length > 1 || (rest.length === 1 && rest[0] !== '--json')) throw new UsageError(USAGE)
      return { sub, json: rest.length === 1 }
    case 'down':
      if (rest.length !== 0) throw new UsageError(USAGE)
      return { sub }
    case 'fund': {
      const [chain, address, amount, ...extra] = rest
      if ((chain !== 'eth' && chain !== 'sol' && chain !== 'btc') || address === undefined || extra.length > 0) throw new UsageError(USAGE)
      return { sub, chain, address, amount: amount ?? null }
    }
    default:
      throw new UsageError(USAGE)
  }
}

// ---- address and amount validation (fund). Pure.

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function base58Decode(s: string): Buffer | null {
  if (s.length === 0) return null
  let n = 0n
  for (const ch of s) {
    const d = B58.indexOf(ch)
    if (d < 0) return null
    n = n * 58n + BigInt(d)
  }
  let hex = n.toString(16)
  if (hex.length % 2 === 1) hex = `0${hex}`
  let zeros = 0
  while (zeros < s.length && s[zeros] === '1') zeros++
  return Buffer.concat([Buffer.alloc(zeros), n === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex')])
}
const sha256 = (b: Buffer): Buffer => createHash('sha256').update(b).digest()

// keccak-256 (EIP-55 needs it; core's viem is not a dependency of this workspace). Input: a short ASCII string.
const RC = [0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an, 0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n]
const ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
const M64 = (1n << 64n) - 1n
const rotl = (x: bigint, n: number): bigint => (n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M64)
export function keccak256Hex(input: string): string {
  const rate = 136
  const msg = Buffer.from(input, 'latin1')
  const padded = Buffer.alloc(Math.ceil((msg.length + 1) / rate) * rate)
  msg.copy(padded)
  padded[msg.length] ^= 0x01
  padded[padded.length - 1] ^= 0x80
  const st: bigint[] = Array.from({ length: 25 }, () => 0n)
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) st[i] ^= padded.readBigUInt64LE(off + i * 8)
    for (let r = 0; r < 24; r++) {
      const c = [0, 1, 2, 3, 4].map((x) => st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20])
      for (let x = 0; x < 5; x++) { const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1); for (let y = 0; y < 5; y++) st[x + 5 * y] ^= d }
      const b: bigint[] = Array.from({ length: 25 }, () => 0n)
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(st[x + 5 * y], ROT[x][y])
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) st[x + 5 * y] = b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & M64 & b[((x + 2) % 5) + 5 * y])
      st[0] ^= RC[r]
    }
  }
  const out = Buffer.alloc(32)
  for (let i = 0; i < 4; i++) out.writeBigUInt64LE(st[i], i * 8)
  return out.toString('hex')
}
// 0x + 40 hex. A mixed-case address must carry its EIP-55 checksum; all-lowercase or all-uppercase hex is accepted as is.
export function isEthAddress(a: string): boolean {
  if (!/^0x[0-9a-fA-F]{40}$/.test(a)) return false
  const hex = a.slice(2)
  if (hex === hex.toLowerCase() || hex === hex.toUpperCase()) return true
  const h = keccak256Hex(hex.toLowerCase())
  return [...hex].every((ch, i) => (/[a-f]/i.test(ch) ? (parseInt(h[i], 16) >= 8 ? ch === ch.toUpperCase() : ch === ch.toLowerCase()) : true))
}
export function isSolAddress(a: string): boolean {
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a) && base58Decode(a)?.length === 32
}

const BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
function bech32Polymod(values: readonly number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  let chk = 1
  for (const v of values) {
    const top = chk >>> 25
    chk = ((chk & 0x1ffffff) << 5) ^ v
    for (let i = 0; i < 5; i++) if (((top >>> i) & 1) === 1) chk ^= GEN[i]
  }
  return chk >>> 0
}
// A regtest address: bech32/bech32m `bcrt1…` with a valid checksum, witness version and program length; or a base58check
// P2PKH / P2SH one (version byte 0x6f / 0xc4). Mainnet (`bc1`, 1…, 3…) and testnet (`tb1`, m…/n…/2… are regtest-shared, tb1 is not)
// are refused: only `bcrt1` carries the regtest hrp.
export function isBtcRegtestAddress(a: string): boolean {
  if (/^bcrt1/i.test(a)) {
    if ((a !== a.toLowerCase() && a !== a.toUpperCase()) || a.length < 14 || a.length > 90) return false // BIP-173: all one case
    a = a.toLowerCase()
    const data = [...a.slice(5)].map((c) => BECH32.indexOf(c))
    if (data.some((x) => x < 0) || data.length < 7) return false
    const hrp = [...'bcrt'].map((c) => c.charCodeAt(0))
    const expand = [...hrp.map((c) => c >> 5), 0, ...hrp.map((c) => c & 31)]
    const chk = bech32Polymod([...expand, ...data])
    const ver = data[0]
    const want = ver === 0 ? 1 : 0x2bc830a3
    if (chk !== want || ver > 16) return false
    // 5-bit groups -> bytes: the program length must be right and the padding clean.
    const words = data.slice(1, -6)
    let acc = 0, bits = 0
    const prog: number[] = []
    for (const w of words) { acc = (acc << 5) | w; bits += 5; while (bits >= 8) { bits -= 8; prog.push((acc >> bits) & 255) } acc &= (1 << bits) - 1 }
    if (bits >= 5 || acc !== 0) return false
    return ver === 0 ? prog.length === 20 || prog.length === 32 : prog.length >= 2 && prog.length <= 40
  }
  if (!/^[1-9A-HJ-NP-Za-km-z]{26,35}$/.test(a)) return false
  const raw = base58Decode(a)
  if (raw === null || raw.length !== 25) return false
  const body = raw.subarray(0, 21)
  if (!sha256(sha256(body)).subarray(0, 4).equals(raw.subarray(21))) return false
  return body[0] === 0x6f || body[0] === 0xc4
}

// A positive decimal with at most `decimals` fraction digits, as an integer of the smallest unit.
export function parseAmount(text: string, decimals: number, unit: string): bigint {
  const m = /^(\d{1,12})(?:\.(\d{1,18}))?$/.exec(text)
  if (m === null || (m[2] ?? '').length > decimals) throw new UsageError(`the amount must be a positive decimal in ${unit} with at most ${decimals} decimals`)
  const v = BigInt(m[1]) * 10n ** BigInt(decimals) + BigInt((m[2] ?? '').padEnd(decimals, '0') || '0')
  if (v <= 0n) throw new UsageError(`the amount must be greater than zero ${unit}`)
  return v
}
export function formatUnits(v: bigint, decimals: number): string {
  const s = v.toString().padStart(decimals + 1, '0')
  const whole = s.slice(0, -decimals) || '0'
  const frac = s.slice(-decimals).replace(/0+$/, '')
  return frac === '' ? whole : `${whole}.${frac}`
}

// ---- tools

export interface Tools { anvil: string | null; solana: string | null; bitcoind: string | null; ord: string | null; docker: string | null }

export function findTool(name: string, pathEnv: string | undefined): string | null {
  for (const dir of (pathEnv ?? '').split(delimiter)) {
    if (dir === '' || !isAbsolute(dir)) continue
    const p = join(dir, name)
    try {
      if (statSync(p).isFile()) { accessSync(p, constants.X_OK); return p }
    } catch { /* next */ }
  }
  return null
}
export function findTools(env: Env): Tools {
  const f = (n: string): string | null => findTool(n, env.PATH)
  return { anvil: f('anvil'), solana: f('solana-test-validator'), bitcoind: f('bitcoind'), ord: f('ord'), docker: f('docker') }
}

const INSTALL: Readonly<Record<string, string>> = {
  anvil: 'anvil (Foundry): brew install foundry, or https://getfoundry.sh',
  'solana-test-validator': 'solana-test-validator (Agave CLI): https://docs.anza.xyz/cli/install',
  bitcoind: 'bitcoind (Bitcoin Core): brew install bitcoin, or https://bitcoincore.org/en/download/',
  ord: `ord ${ORD_VERSION}: https://github.com/ordinals/ord/releases/tag/${ORD_VERSION}`,
}

// Refuses (localnet.tool-missing), naming every missing tool and how to install it. docker is optional (Otterscan only).
export function assertTools(t: Tools, want: { btc: boolean }): void {
  const missing: string[] = []
  if (t.anvil === null) missing.push(INSTALL.anvil)
  if (t.solana === null) missing.push(INSTALL['solana-test-validator'])
  if (want.btc && t.bitcoind === null) missing.push(INSTALL.bitcoind)
  if (want.btc && t.ord === null) missing.push(INSTALL.ord)
  if (missing.length > 0) refuse('localnet.tool-missing', `not on PATH (install, then run vt localnet up again): ${missing.join('; ')}`) // @guard:localnet.tool-missing
}

// `ord --version` -> "ord 0.29.0"; anything but exactly ORD_VERSION refuses (localnet.ord-version).
export function assertOrdVersion(output: string): void {
  const ok = output.trim() === `ord ${ORD_VERSION}`
  if (!ok) refuse('localnet.ord-version', `ord ${ORD_VERSION} is required (the inscription format and its API are pinned to it); found "${output.trim().slice(0, 40)}"`) // @guard:localnet.ord-version
}

// ---- the command lines. Pure: nothing here holds a secret (asserted by the tests: no password, no hash on any argv).

export interface Paths { root: string; anvil: string; solana: string; bitcoind: string; ord: string; logs: string; state: string }
export function localnetPaths(home: string): Paths {
  assertProfilePath(home)
  const root = join(home, 'localnet')
  return { root, anvil: join(root, 'anvil'), solana: join(root, 'solana'), bitcoind: join(root, 'bitcoind'), ord: join(root, 'ord'), logs: join(root, 'logs'), state: join(root, 'state.json') }
}

export function anvilArgv(tool: string, p: LocalnetPorts, dir: string): string[] {
  return [tool, '--host', '127.0.0.1', '--port', String(p.anvil), '--chain-id', String(ANVIL_CHAIN_ID), '--block-time', '1', '--state', join(dir, 'state.json'), '--state-interval', '10']
}
// ★ FINDING (measured, Agave 4.2.2): solana-test-validator binds its JSON-RPC, pubsub and faucet sockets to ALL interfaces whatever
//   --bind-address says, and no sandbox-exec inbound rule restricts that on macOS (a listen on a wildcard address needs
//   network-inbound; the rules that allow it also admit the LAN address). vt runs it under the same outbound-loopback-only profile as
//   the integration harness (it can reach nothing but this machine) and docs/vt.md tells the operator to keep the macOS firewall on.
//   The exposure is a faucet and a node of a worthless local ledger, never a key or a real coin.
export const SOLANA_PROFILE = '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))'
export function solanaArgv(tool: string, p: LocalnetPorts, ledger: string): string[] {
  return ['/usr/bin/sandbox-exec', '-p', SOLANA_PROFILE, tool, '--ledger', ledger, '--bind-address', '127.0.0.1', '--rpc-port', String(p.solana), '--faucet-port', String(p.solanaFaucet),
    '--gossip-port', String(p.solanaGossip), '--dynamic-port-range', `${p.solanaDynFrom}-${p.solanaDynTo}`,
    '--limit-ledger-size', '50000000', '--quiet']
}
// rpcauth lives in <datadir>/bitcoin.conf (0600), never on argv.
export function bitcoindArgv(tool: string, p: LocalnetPorts, dir: string): string[] {
  return [tool, '-regtest', '-server=1', `-datadir=${dir}`, `-conf=${join(dir, 'bitcoin.conf')}`, '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1', `-rpcport=${p.bitcoind}`,
    '-listen=0', '-connect=0', '-dnsseed=0', '-txindex=1', '-fallbackfee=0.0001', '-printtoconsole=1']
}
export function ordArgv(tool: string, p: LocalnetPorts, btcDir: string, dataDir: string): string[] {
  return [tool, '--regtest', '--bitcoin-rpc-url', `http://127.0.0.1:${p.bitcoind}`, '--cookie-file', join(btcDir, 'regtest', '.cookie'), '--data-dir', dataDir,
    'server', '--address', '127.0.0.1', '--http-port', String(p.ord), '--polling-interval', '1s']
}
export function minerArgv(node: string, authFile: string, stateFile: string, p: LocalnetPorts, seconds: number): string[] {
  return [node, '--disable-sigusr1', fileURLToPath(new URL('./localnet-miner.ts', import.meta.url)), authFile, stateFile, String(p.bitcoind), String(seconds)]
}
export function containerName(p: LocalnetPorts): string { return `vt-localnet-otterscan-${p.otterscan}` }
// Bound to 127.0.0.1 only; the browser (not the container) calls ERIGON_URL, so it names the host's anvil.
export function otterscanArgv(docker: string, p: LocalnetPorts): string[] {
  return [docker, 'run', '--rm', '--name', containerName(p), '-p', `127.0.0.1:${p.otterscan}:80`, '-e', `ERIGON_URL=http://127.0.0.1:${p.anvil}`, OTTERSCAN_IMAGE]
}

// bitcoind's rpcauth value for a password: <user>:<salt>$<HMAC-SHA256(key = salt, msg = password)>.
export function rpcAuthLine(user: string, pass: string, salt: string = randomBytes(16).toString('hex')): string {
  return `${user}:${salt}$${createHmac('sha256', salt).update(pass).digest('hex')}`
}
export function bitcoinConf(user: string, pass: string): string {
  return `# written by vt localnet (regtest); rpcauth is a salted hash, not the password\nrpcauth=${rpcAuthLine(user, pass)}\n`
}

// Every window runs as: /bin/sh -c SERVICE_SCRIPT vt-<name> <signal> <grace s> <log> /usr/bin/env -i <env> <tool> <args>. The script prints
// where the log is (the pane shows only that line: `tail -f` the log), tees the service's output to <log>, turns the window's SIGHUP
// (tmux kill-window) into the service's stop signal (TERM; ord stops only on INT and ignores TERM -- measured with ord 0.29.0;
// bitcoind treats SIGHUP as "reopen the log" and would otherwise outlive the session), and keeps waiting until the service is really
// gone: a second signal only interrupts one `wait`, and the loop goes on. A service still alive <grace> s after the first signal gets
// KILL (the pid is the one this script started; the timer is cancelled when it exits). The exit marker carries the service's own
// status. The service runs in its own process group (set -m: tmux's SIGHUP reaches the script only), and tee runs under nohup so
// the service can still print while it shuts down (ord panics on a closed pipe and never finishes).
export const SERVICE_SCRIPT = 'sig=$1; grace=$2; log=$3; shift 3; echo "vt: this service logs to $log (tail -f it); this pane shows only this line"; { set -m; "$@" 2>&1 </dev/null & p=$!; k=; stop() { kill -"$sig" "$p" 2>/dev/null; if [ -z "$k" ]; then { /bin/sleep "$grace"; kill -KILL "$p" 2>/dev/null; } & k=$!; fi; }; trap stop HUP INT TERM; while :; do wait "$p"; s=$?; kill -0 "$p" 2>/dev/null || break; done; [ -z "$k" ] || kill "$k" 2>/dev/null; echo "vt: exited with status $s"; } | /usr/bin/nohup /usr/bin/tee -a "$log" >/dev/null 2>&1; exec /bin/sleep 2147483647'
export const KILL_GRACE_S = 20
export function serviceEnv(env: Env): string[] {
  return ['/usr/bin/env', '-i', `PATH=${env.PATH ?? '/usr/bin:/bin'}`, `HOME=${env.HOME ?? ''}`, `LANG=${env.LANG ?? 'en_US.UTF-8'}`, `TERM=${env.TERM ?? 'dumb'}`]
}
export const STOP_SIGNAL: Readonly<Record<Service, 'TERM' | 'INT'>> = { anvil: 'TERM', solana: 'TERM', bitcoind: 'TERM', miner: 'TERM', ord: 'INT', otterscan: 'TERM' }
export function windowArgv(name: Service, log: string, env: Env, argv: readonly string[]): string[] {
  return [SH, '-c', SERVICE_SCRIPT, `vt-${name}`, STOP_SIGNAL[name], String(KILL_GRACE_S), log, ...serviceEnv(env), ...argv]
}

// ---- the credential

// M1: the relay's own loader (vt-broadcast loadBitcoindAuth: a regular file you own, mode 0600 exactly, no symlink, one <user>:<pass>
// line without control characters) decides whether a credential is reusable, plus the relay's other rule (a password of at least 16
// characters, MIN_CREDENTIAL_PASS) and the user `vt`. Anything else is replaced.
export const MIN_PASS_LEN = 16
export function readCredentialLine(out: string): string | null {
  try {
    const line = loadBitcoindAuth(out)
    return line.startsWith(`${RPC_USER}:`) && line.length - RPC_USER.length - 1 >= MIN_PASS_LEN ? line : null
  } catch { return null }
}
// The password already in <out>/local/btc-rpc.auth when the relay would accept it, else 32 random hex characters.
export function readOrMakePass(out: string): { pass: string; fresh: boolean } {
  const l = readCredentialLine(out)
  return l !== null ? { pass: l.slice(RPC_USER.length + 1), fresh: false } : { pass: randomBytes(16).toString('hex'), fresh: true }
}
// Writes the credential line atomically with mode 0600 (writePrivateFile: temp file O_EXCL, fsync, rename).
export function writeCredential(out: string, pass: string): string {
  const dir = join(out, 'local')
  ensureDir(dir, out)
  writePrivateFile(dir, BTC_AUTH_FILE, `${RPC_USER}:${pass}\n`)
  return join(dir, BTC_AUTH_FILE)
}
// M7: vt's own calls to bitcoind use the datadir COOKIE of $VT_HOME/localnet/bitcoind (bitcoind writes it 0600 at start): only a bitcoind
// that vt started with that datadir accepts it, and a stale cookie says nothing about a squatter. The password of btc-rpc.auth is
// sent to a listener only after the cookie identified it (probeBitcoind), and by the relay and the miner alone otherwise.
export function readCookieLine(paths: Paths): string | null {
  const t = readSmallFile(join(paths.bitcoind, 'regtest', '.cookie'), { cap: 256, privateOnly: true })
  const l = t === null ? '' : t.trim()
  return /^__cookie__:[0-9a-f]{32,128}$/.test(l) ? l : null
}

// ---- identity probes

export interface Identity { right: boolean; version: string; why: string }
const no = (why: string): Identity => ({ right: false, version: '-', why })
const str = (r: RpcReply): string | null => (r.ok && typeof r.result === 'string' ? r.result : null)

export async function probeAnvil(port: number): Promise<Identity> {
  const c = await jsonRpc(port, 'eth_chainId', [])
  if (str(c) !== `0x${ANVIL_CHAIN_ID.toString(16)}`) return no(c.ok ? 'chain id is not 31337' : 'not an Ethereum JSON-RPC node')
  const v = str(await jsonRpc(port, 'web3_clientVersion', []))
  return { right: true, version: v ?? 'anvil', why: '' }
}
export async function probeSolana(port: number, recorded: string | null): Promise<Identity> {
  const g = str(await jsonRpc(port, 'getGenesisHash', []))
  if (g === null) return no('not a Solana JSON-RPC node')
  if (recorded === null) return no('its genesis hash was not recorded by vt localnet (stop it, or start the validator with vt localnet up)')
  if (g !== recorded || !isLocalSolanaGenesis(g)) return no('another ledger than the one vt localnet recorded')
  const v = await jsonRpc(port, 'getVersion', [])
  const core = v.ok && typeof v.result === 'object' && v.result !== null ? (v.result as { 'solana-core'?: unknown })['solana-core'] : undefined
  return { right: true, version: typeof core === 'string' ? `solana-core ${core}` : 'solana', why: '' }
}
// cookie: vt's datadir cookie line (readCookieLine); null -> cannot be confirmed. cred: when given (not undefined), the credential file's
// line is tried too -- but only after the cookie identified a regtest bitcoind, never against an unidentified listener.
export async function probeBitcoind(port: number, cookie: string | null, cred?: string | null): Promise<Identity> {
  if (cookie === null) return no('vt\'s bitcoind datadir has no cookie, so this listener cannot be identified (it is not a bitcoind that vt localnet started)')
  const i = await jsonRpc(port, 'getblockchaininfo', [], { line: cookie })
  if (!i.ok) return no(i.status === 401 ? 'it does not accept the cookie of vt\'s bitcoind datadir' : 'not a bitcoind JSON-RPC node')
  const chain = typeof i.result === 'object' && i.result !== null ? (i.result as { chain?: unknown }).chain : undefined
  const g = str(await jsonRpc(port, 'getblockhash', [0], { line: cookie }))
  if (chain !== 'regtest' || g !== GENESIS.btc.regtest) return no('not a regtest chain')
  if (cred !== undefined) {
    if (cred === null) return no('there is no usable credential file ($VAULT_TIMELOCK_DIR/local/btc-rpc.auth: 0600, vt:<password of 16+ characters>) for the relay')
    const c = await jsonRpc(port, 'getblockcount', [], { line: cred })
    if (!c.ok) return no('vt\'s bitcoind does not accept the credential file the relay reads (run vt localnet down, then up: it restarts with the file\'s password)')
  }
  const n = await jsonRpc(port, 'getnetworkinfo', [], { line: cookie })
  const sub = n.ok && typeof n.result === 'object' && n.result !== null ? (n.result as { subversion?: unknown }).subversion : undefined
  return { right: true, version: typeof sub === 'string' ? sub.replace(/^\/|\/$/g, '').replace(':', ' ') : 'bitcoind', why: '' }
}
// I1: regtest's genesis is the same for every regtest chain, so it identifies nothing. An ord is vt's only when its indexed tip is ON THIS
// bitcoind's chain: its height h exists on the bitcoind and /r/blockhash/h equals getblockhash h (the cookie line of the bitcoind that
// was just identified; null -> cannot be tied, refused). ord 0.29.0 reports no version at all (/status has none), so a reused ord is
// shown without one; a started ord is the binary this run checked (ORD_VERSION).
export async function probeOrd(port: number, btc: { port: number; cookie: string } | null): Promise<Identity> {
  if (btc === null) return no('there is no bitcoind of vt\'s to tie it to')
  const st = await httpText(port, '/status', 3_000, { accept: 'application/json' })
  let chain: unknown
  try { chain = st !== null && st.status === 200 ? (JSON.parse(st.body) as { chain?: unknown }).chain : undefined } catch { chain = undefined }
  if (chain !== 'regtest') return no(st === null ? 'no HTTP answer' : 'not an ord on a regtest chain')
  const hr = await httpText(port, '/r/blockheight')
  const h = hr !== null && hr.status === 200 && /^(?:0|[1-9][0-9]{0,8})$/.test(hr.body.trim()) ? Number(hr.body.trim()) : null
  if (h === null) return no('it reports no block height')
  const oh = await httpText(port, `/r/blockhash/${h}`)
  const ordHash = oh === null || oh.status !== 200 ? null : oh.body.trim().replace(/^"|"$/g, '')
  const mine = str(await jsonRpc(btc.port, 'getblockhash', [h], { line: btc.cookie }))
  if (ordHash === null || mine === null || ordHash !== mine) return no('its indexed chain is not the chain of vt\'s bitcoind (a leftover index of another regtest)')
  return { right: true, version: 'ord (version not reported)', why: '' }
}
export async function probeOtterscan(port: number): Promise<Identity> {
  const r = await httpText(port, '/')
  if (r === null || r.status !== 200 || !/otterscan/i.test(r.body)) return no('not Otterscan')
  return { right: true, version: OTTERSCAN_IMAGE.split(':')[1], why: '' }
}

// The reuse decision for one service: free port -> start; right identity -> reuse; anything else -> refuse.
export function decide(taken: boolean, id: Identity | null): 'start' | 'reuse' | 'refuse' {
  if (!taken) return 'start'
  return id !== null && id.right ? 'reuse' : 'refuse'
}
export function assertNotTaken(service: string, port: number, why: string): never {
  refuse('localnet.port-taken', `port ${port} (${service}) is in use by something that is not vt's ${service}: ${why}. vt localnet never stops a process it did not start; stop it, then run vt localnet up again`) // @guard:localnet.port-taken
  throw new Error('unreachable')
}

// ---- state ($VT_HOME/localnet/)

export function readLastSlot(paths: Paths): number {
  const t = readSmallFile(join(paths.solana, 'last-slot'), { cap: 32 })
  const v = t === null ? NaN : Number(t.trim())
  return Number.isSafeInteger(v) && v >= 0 ? v : 0
}

export function readGenesisRecord(paths: Paths): string | null {
  const t = readSmallFile(join(paths.solana, 'genesis-hash'), { cap: 128 })
  const h = t === null ? '' : t.trim()
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(h) ? h : null
}
interface LocalnetState { otterscan?: { container: string; port: number }; pids?: { bitcoind?: number } }
export function readState(paths: Paths): LocalnetState {
  const t = readSmallFile(paths.state, { cap: 4096, privateOnly: true })
  try {
    const j = t === null ? null : (JSON.parse(t) as { otterscan?: { container?: unknown; port?: unknown }; pids?: { bitcoind?: unknown } })
    const o = j?.otterscan
    const r: LocalnetState = {}
    if (o !== undefined && typeof o.container === 'string' && /^vt-localnet-otterscan-\d{1,5}$/.test(o.container) && typeof o.port === 'number') r.otterscan = { container: o.container, port: o.port }
    const b = j?.pids?.bitcoind
    if (typeof b === 'number' && Number.isSafeInteger(b) && b > 1) r.pids = { bitcoind: b }
    return r
  } catch { /* none */ }
  return {}
}
function writeState(paths: Paths, patch: Partial<LocalnetState>, drop: ReadonlyArray<keyof LocalnetState> = []): void {
  const cur = readState(paths)
  for (const k of drop) delete cur[k]
  ensureDir(paths.root)
  writePrivateFile(paths.root, 'state.json', `${JSON.stringify({ ...cur, ...patch })}\n`)
}

// PF-C credential-disclosure fix (a): NO credential -- the datadir cookie included -- is sent to a listener that was not identified without
// one. The identification is OWNERSHIP: the process listening on the bitcoind port (port-scoped lsof) must be the pid `vt localnet up`
// recorded when it started bitcoind (its parent was that window's script). Only then is the cookie returned; otherwise null, and every
// caller treats null as "cannot be identified" (no request with auth is made).
export function ownedCookie(paths: Paths, listenerPid: (port: number) => number | null, port: number): string | null {
  const rec = readState(paths).pids?.bitcoind
  const now = listenerPid(port)
  return rec !== undefined && now !== null && now === rec ? readCookieLine(paths) : null
}

const DATA_DIRS = ['anvil', 'solana', 'bitcoind', 'ord'] as const
// --reset: removes the four service data directories below $VT_HOME/localnet and nothing else. Each must be a real directory
// (never a link) whose real path lies inside the real $VT_HOME/localnet (localnet.reset-path).
export function resetData(paths: Paths): string[] {
  if (!existsSync(paths.root)) return []
  const rootReal = realpathSync(paths.root)
  const removed: string[] = []
  for (const name of DATA_DIRS) {
    const dir = join(paths.root, name)
    let st
    try { st = lstatSync(dir) } catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') continue; throw e }
    const inside = !st.isSymbolicLink() && st.isDirectory() && realpathSync(dir) === join(rootReal, name)
    if (!inside) refuse('localnet.reset-path', `$VT_HOME/localnet/${name} is not a plain directory inside $VT_HOME/localnet (a link or a file?): nothing was removed`) // @guard:localnet.reset-path
    rmSync(dir, { recursive: true, force: true })
    removed.push(name)
  }
  return removed
}

// ---- up

export interface LocalnetDeps {
  tmux: Tmux
  ports: LocalnetPorts
  tools: Tools
  node: string
  ordVersionOutput: () => string
  dockerReady: () => boolean
  dockerRun: (args: readonly string[]) => { code: number | null }
  listenerPid: (port: number) => number | null            // the single pid listening on 127.0.0.1:<port> (lsof, port-scoped), else null
  ourListener: (port: number, window: string, tmux: Tmux) => number | null   // that pid, only if its parent is the script of OUR tmux window
  loopbackOnly: (port: number) => boolean   // every listener on the port is bound to 127.0.0.1 / ::1 (lsof, port-scoped)
  now: () => number
  sleep: (ms: number) => Promise<void>
  timeouts: { anvil: number; solana: number; bitcoind: number; ord: number; otterscan: number; miner: number }
  out: (line: string) => void
  err: (line: string) => void
}

function spawnOut(cmd: string, args: readonly string[], env: Env, timeout = 10_000): { code: number | null; out: string } {
  const e: Record<string, string> = {}
  for (const [k, v] of Object.entries(env)) if (v !== undefined) e[k] = v
  const r = spawnSync(cmd, [...args], { env: e, encoding: 'utf8', timeout, stdio: ['ignore', 'pipe', 'pipe'] })
  return { code: r.error !== undefined ? null : r.status, out: `${r.stdout ?? ''}${r.stderr ?? ''}` }
}

export function defaultLocalnetDeps(env: Env, ports: LocalnetPorts = DEFAULT_PORTS): LocalnetDeps {
  const tools = findTools(env)
  return {
    tmux: systemTmux({ env }),
    ports,
    tools,
    node: process.execPath,
    ordVersionOutput: () => (tools.ord === null ? '' : spawnOut(tools.ord, ['--version'], env).out),
    dockerReady: () => tools.docker !== null && spawnOut(tools.docker, ['info', '--format', '{{.ServerVersion}}'], env, 15_000).code === 0,
    dockerRun: (args) => (tools.docker === null ? { code: null } : { code: spawnOut(tools.docker, args, env, 30_000).code }),
    listenerPid: (port) => listenerPidOf(port, env),
    ourListener: (port, window, tmux) => {
      const pid = listenerPidOf(port, env)
      if (pid === null) return null
      const pane = tmux.run(['list-panes', '-t', `=${SESSION}:=${window}`, '-F', '#{pane_pid}'])
      const panePid = Number((pane.out ?? '').trim().split('\n')[0])
      if (!Number.isSafeInteger(panePid) || panePid <= 1) return null
      // the service is a descendant of the window's script (the script's pipeline subshell is its direct parent): walk up at most 4 levels
      let cur = pid
      for (let i = 0; i < 4 && cur > 1; i++) {
        cur = Number(spawnOut('/bin/ps', ['-o', 'ppid=', '-p', String(cur)], env).out.trim())
        if (cur === panePid) return pid
      }
      return null
    },
    loopbackOnly: (port) => {
      const r = spawnOut('/usr/sbin/lsof', ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN', '-Fn'], env)
      const names = r.out.split('\n').filter((l) => l.startsWith('n')).map((l) => l.slice(1))
      return r.code === 0 && names.length > 0 && names.every((n) => n.startsWith('127.0.0.1:') || n.startsWith('[::1]:'))
    },
    now: () => Date.now(),
    sleep: sleepMs,
    timeouts: { anvil: 30_000, solana: 120_000, bitcoind: 60_000, ord: 120_000, otterscan: 180_000, miner: 30_000 },
    out: (l) => { process.stdout.write(`${l}\n`) },
    err: (l) => { process.stderr.write(`${l}\n`) },
  }
}

const endpointOf = (s: Service, p: LocalnetPorts): string => {
  switch (s) {
    case 'anvil': return `http://127.0.0.1:${p.anvil}`
    case 'solana': return `http://127.0.0.1:${p.solana}`
    case 'bitcoind': return `http://127.0.0.1:${p.bitcoind}`
    case 'ord': return `http://127.0.0.1:${p.ord}`
    case 'otterscan': return `http://127.0.0.1:${p.otterscan}`
    case 'miner': return '-'
  }
}
const line = (name: string, ep: string, ver: string, how: string): string => `${name.padEnd(10)}${ep.padEnd(26)}${ver.padEnd(26)}${how}`

interface Step { name: Service; action: 'start' | 'reuse'; version: string; stale?: boolean }

export interface UpOptions { btc: boolean; otterscan: boolean; reset: boolean; mineEvery: number; env: Env }

export const minerAlive = (paths: Paths, windows: ReadonlySet<string>): boolean =>
  windows.has('miner') && scanLog(readSmallFile(join(paths.logs, 'miner.log'), { cap: 1024 * 1024 }) ?? '', []).exited === null

export async function localnetUp(o: UpOptions, deps: Partial<LocalnetDeps> = {}): Promise<number> {
  const d: LocalnetDeps = { ...defaultLocalnetDeps(o.env, deps.ports), ...deps }
  const p = assertPorts(d.ports)
  assertTools(d.tools, { btc: o.btc })
  if (o.btc) assertOrdVersion(d.ordVersionOutput())
  const home = vtHome(o.env)
  const paths = localnetPaths(home)
  const out = resolveOut(o.env)
  if (!isAbsolute(out)) throw new UsageError('VAULT_TIMELOCK_DIR must be an absolute path')
  assertProfilePath(out)

  const sessionUp = hasSession(d.tmux, SESSION)
  const windows = new Set(sessionUp ? (listWindows(d.tmux, SESSION) ?? []) : [])
  if (o.reset && sessionUp) throw new UsageError('--reset needs the localnet stopped: run vt localnet down first')

  ensureDir(paths.root)
  const record = readGenesisRecord(paths)
  const credLine = readCredentialLine(out)
  // the cookie, only for a listener that is the bitcoind vt recorded (ownedCookie); a fresh start records its own pid first
  const cookie = (): string | null => ownedCookie(paths, d.listenerPid, p.bitcoind)

  // ---- 1. plan: probe every port BEFORE anything starts; a foreign listener refuses the whole run.
  const want: Service[] = ['anvil', 'solana', ...(o.btc ? (['bitcoind', 'miner', 'ord'] as const) : []), ...(o.otterscan ? (['otterscan'] as const) : [])]
  const plan: Step[] = []
  const skipped: string[] = []
  const strict = o.reset // a fresh start: nothing may already answer
  let btcAction: 'start' | 'reuse' = 'start'
  for (const s of want) {
    if (s === 'miner') {
      // M6: a miner whose window is still there but has exited is dead: it is restarted, not "reused"
      plan.push({ name: s, action: minerAlive(paths, windows) ? 'reuse' : 'start', version: 'every ' + o.mineEvery + ' s' })
      continue
    }
    if (s === 'otterscan' && !d.dockerReady()) { skipped.push(d.tools.docker === null ? 'otterscan: docker is not installed (skipped; --no-otterscan to silence)' : 'otterscan: the docker daemon is not running (skipped; --no-otterscan to silence)'); continue }
    const port = { anvil: p.anvil, solana: p.solana, bitcoind: p.bitcoind, ord: p.ord, otterscan: p.otterscan }[s]
    const extra = s === 'solana' ? [p.solana + 1, p.solanaFaucet] : []
    const taken = await tcpOpen(port)
    let id: Identity | null = null
    if (taken) {
      id = s === 'anvil' ? await probeAnvil(port)
        : s === 'solana' ? await probeSolana(port, record)
        : s === 'bitcoind' ? await probeBitcoind(port, cookie(), credLine)
        : s === 'ord' ? await probeOrd(port, btcAction === 'reuse' && cookie() !== null ? { port: p.bitcoind, cookie: cookie() as string } : null)
        : await probeOtterscan(port)
      // M6: a reused Otterscan must be bound to 127.0.0.1 only (a container published as -p 5100:80 listens on every interface)
      if (s === 'otterscan' && id.right && !d.loopbackOnly(port)) id = no('it listens on more than 127.0.0.1 (a container published without the 127.0.0.1: prefix)')
    }
    if (taken && strict) assertNotTaken(s, port, 'a --reset start needs every port free')
    let dec = decide(taken, id)
    // I1: a taken ord that is not tied to this run's bitcoind is vt's own stale ord only if its window is in our session: then it is
    // restarted; a foreign one refuses.
    let stale = false
    if (s === 'ord' && dec === 'refuse' && windows.has('ord')) { dec = 'start'; stale = true }
    if (dec === 'refuse') assertNotTaken(s, port, (id as Identity).why)
    if (dec === 'start' && !stale) {
      for (const x of extra) if (await tcpOpen(x)) assertNotTaken(s, x, 'a port the validator also needs')
    }
    if (s === 'bitcoind') btcAction = dec
    plan.push({ name: s, action: dec, version: id?.version ?? '', ...(stale ? { stale: true } : {}) })
  }
  if (o.btc && plan.some((x) => x.name === 'ord' && x.action === 'start') && btcAction === 'reuse' && cookie() === null) {
    assertNotTaken('bitcoind', p.bitcoind, 'ord needs the datadir cookie of a bitcoind started by vt localnet; this bitcoind was not (stop it, then run vt localnet up)')
  }

  // ---- 2. act
  if (o.reset) for (const r of resetData(paths)) d.out(`reset: removed ${r} data`)
  for (const dir of [paths.anvil, paths.solana, paths.bitcoind, paths.ord, paths.logs]) ensureDir(dir)
  const createdSession = !sessionUp
  let haveSession = sessionUp
  const started: Service[] = []
  const results: string[] = []

  // M2: any failure stops what THIS run started (the whole session when this run created it)
  const fail = (msg: string): number => {
    d.err(`vt localnet: ${msg}`)
    if (createdSession && haveSession) { killSession(d.tmux, SESSION); d.err('vt localnet: the session vt-localnet was stopped; nothing is left running that vt started') }
    else if (haveSession) { for (const n of started.reverse()) killWindow(d.tmux, SESSION, n); if (started.length > 0) d.err(`vt localnet: stopped what this run started (${started.join(', ')})`) }
    return 1
  }
  const launch = async (name: Service, argv: readonly string[], ready: () => Promise<boolean>, timeoutMs: number, freePort?: number): Promise<string | null> => {
    const log = join(paths.logs, `${name}.log`)
    if (windows.has(name)) { killWindow(d.tmux, SESSION, name); windows.delete(name) } // a dead (or stale) service's open window
    if (freePort !== undefined) { // the stopped service must let go of its port before the next one binds it
      const until = d.now() + 45_000
      while (await tcpOpen(freePort)) { if (d.now() >= until) return `port ${freePort} (${name}) is still held after stopping its old window: nothing was started`; await d.sleep(250) }
    }
    freshLog(log)
    const cmd = windowArgv(name, log, o.env, argv)
    const r = haveSession ? newWindow(d.tmux, SESSION, name, cmd) : newSession(d.tmux, SESSION, name, cmd)
    if (r.code !== 0) return `tmux could not start the ${name} window${r.code === null ? ` (${r.err})` : ''}`
    haveSession = true
    windows.add(name)
    started.push(name)
    const deadline = d.now() + timeoutMs
    for (;;) {
      const text = readSmallFile(log, { cap: 4 * 1024 * 1024 }) ?? ''
      const st = scanLog(text, [])
      if (st.exited !== null) return `${name} exited (status ${st.exited}) before it was ready: see ${log}`
      if (await ready()) return null
      if (d.now() >= deadline) return `${name} was not ready within ${timeoutMs / 1000} s: see ${log}`
      await d.sleep(250)
    }
  }

  try {
    for (const step of plan) {
      const s = step.name
      const ep = endpointOf(s, p)
      if (step.action === 'reuse') {
        if (s === 'bitcoind') { // M6: the wallet the miner and `fund btc` need exists on a reused bitcoind too
          const w = await ensureWallet(p.bitcoind, cookie() as string)
          if (w !== null) return fail(w)
        }
        results.push(line(s, ep, step.version, s === 'miner' ? 'reused (already running)' : 'reused (already running, identity confirmed)'))
        continue
      }
      let err: string | null = null
      switch (s) {
        case 'anvil':
          err = await launch(s, anvilArgv(d.tools.anvil as string, p, paths.anvil), async () => (await probeAnvil(p.anvil)).right, d.timeouts.anvil)
          if (err === null) step.version = (await probeAnvil(p.anvil)).version
          break
        case 'solana': {
          let lastSlot = -1
          // A restarted validator answers getHealth ok, and even moves its slot, while it still replays its ledger (balances read as
          // 0 until it has). `down` records the processed slot it stopped at: ready = healthy, slots moving, and at least that slot
          // (a soft wait of 40 s: a crash recorded nothing, and unrooted slots can be lost, which only makes the chain shorter).
          const wasAt = readLastSlot(paths)
          const soft = d.now() + 40_000
          err = await launch(s, solanaArgv(d.tools.solana as string, p, join(paths.solana, 'ledger')), async () => {
            const g = await jsonRpc(p.solana, 'getHealth', [])
            if (!g.ok || g.result !== 'ok') return false
            const sl = await jsonRpc(p.solana, 'getSlot', [{ commitment: 'processed' }])
            const slot = sl.ok && typeof sl.result === 'number' ? sl.result : -1
            const moved = slot >= 0 && lastSlot >= 0 && slot > lastSlot
            if (slot > lastSlot) lastSlot = slot
            return moved && (slot >= wasAt || d.now() > soft)
          }, d.timeouts.solana)
          if (err === null) {
            const g = str(await jsonRpc(p.solana, 'getGenesisHash', []))
            if (g === null || !isLocalSolanaGenesis(g)) { err = 'the validator answered a genesis hash that is not a local ledger'; break }
            writePrivateFile(paths.solana, 'genesis-hash', `${g}\n`)
            step.version = (await probeSolana(p.solana, g)).version
          }
          break
        }
        case 'bitcoind': {
          // M2: the credential file first (the relay reads only it), then the conf with its salted hash, then bitcoind
          const cred = readOrMakePass(out)
          if (cred.fresh) writeCredential(out, cred.pass)
          writePrivateFile(paths.bitcoind, 'bitcoin.conf', bitcoinConf(RPC_USER, cred.pass))
          writeState(paths, {}, ['pids'])   // the old owner is gone with its window; the new one is recorded below
          err = await launch(s, bitcoindArgv(d.tools.bitcoind as string, p, paths.bitcoind), async () => {
            if (readState(paths).pids?.bitcoind === undefined) { // the port was free before this run started it: whoever listens now must be a child of OUR window's script
              const pid = d.ourListener(p.bitcoind, 'bitcoind', d.tmux)
              if (pid === null) return false
              writeState(paths, { pids: { bitcoind: pid } })
            }
            const c = cookie()
            return c !== null && (await probeBitcoind(p.bitcoind, c, `${RPC_USER}:${cred.pass}`)).right
          }, d.timeouts.bitcoind)
          if (err === null) {
            const w = await ensureWallet(p.bitcoind, cookie() as string)
            if (w !== null) { err = w; break }
            step.version = (await probeBitcoind(p.bitcoind, cookie())).version
          }
          break
        }
        case 'miner': {
          const file = join(out, 'local', BTC_AUTH_FILE)
          const log = join(paths.logs, 'miner.log')
          err = await launch(s, minerArgv(d.node, file, paths.state, p, o.mineEvery), async () => scanLog(readSmallFile(log, { cap: 1024 * 1024 }) ?? '', [MINER_READY]).ready, d.timeouts.miner)
          break
        }
        case 'ord': {
          // a stale ord indexed ANOTHER chain: its index is of no use to this bitcoind (ord would exit on the first block that differs)
          if (step.stale === true) { killWindow(d.tmux, SESSION, 'ord'); windows.delete('ord'); rmSync(paths.ord, { recursive: true, force: true }); ensureDir(paths.ord) }
          err = await launch(s, ordArgv(d.tools.ord as string, p, paths.bitcoind, paths.ord), async () => {
            const c = cookie()
            return c !== null && (await probeOrd(p.ord, { port: p.bitcoind, cookie: c })).right
          }, d.timeouts.ord, step.stale === true ? p.ord : undefined)
          if (err === null) step.version = `ord ${ORD_VERSION}`
          break
        }
        case 'otterscan': {
          err = await launch(s, otterscanArgv(d.tools.docker as string, p), async () => (await probeOtterscan(p.otterscan)).right, d.timeouts.otterscan)
          if (err === null) { step.version = OTTERSCAN_IMAGE.split(':')[1]; writeState(paths, { otterscan: { container: containerName(p), port: p.otterscan } }) }
          else {
            // M8: Otterscan is optional: its failure (offline image pull, a container-name conflict, ...) is a warning, the rest stays up
            killWindow(d.tmux, SESSION, 'otterscan')
            windows.delete('otterscan')
            started.splice(started.indexOf('otterscan'), 1)
            d.dockerRun(['rm', '-f', containerName(p)])
            skipped.push(`otterscan: NOT started (warning, the rest is up): ${err}`)
            err = null
            continue
          }
          break
        }
      }
      if (err !== null) return fail(err)
      results.push(line(s, ep, step.version, 'started'))
    }
  } catch (e) {
    return fail(e instanceof Error ? e.message : 'unexpected error')
  }
  for (const r of results) d.out(r)
  for (const s of skipped) d.out(s)
  d.out(`logs: ${paths.logs} (tail -f <service>.log)   tmux -L vt attach -t ${SESSION} shows the log paths   stop: vt localnet down`)
  return 0
}

// Wallet `vt`: loaded, else created; on a fresh chain (balance under 1 BTC) 101 blocks are mined to it so it can spend. `l` is the cookie line.
async function ensureWallet(port: number, l: string): Promise<string | null> {
  const lw = await jsonRpc(port, 'listwallets', [], { line: l })
  const loaded = lw.ok && Array.isArray(lw.result) && (lw.result as unknown[]).includes(WALLET)
  if (!loaded) {
    const ld = await jsonRpc(port, 'loadwallet', [WALLET], { line: l })
    if (!ld.ok) {
      const cr = await jsonRpc(port, 'createwallet', { wallet_name: WALLET }, { line: l })
      if (!cr.ok) return `bitcoind: could not create the wallet "${WALLET}" (${cr.error})`
    }
  }
  const bal = await jsonRpc(port, 'getbalance', [], { line: l, path: `/wallet/${WALLET}` })
  if (!bal.ok) return `bitcoind: could not read the wallet balance (${bal.error})`
  if (Number(bal.result) < 1) {
    const a = await jsonRpc(port, 'getnewaddress', [], { line: l, path: `/wallet/${WALLET}` })
    if (!a.ok) return `bitcoind: getnewaddress failed (${a.error})`
    const g = await jsonRpc(port, 'generatetoaddress', [101, a.result], { line: l, timeoutMs: 120_000 })
    if (!g.ok) return `bitcoind: mining the first 101 blocks failed (${g.error})`
  }
  return null
}

// ---- status

export interface ServiceStatus { name: Service; endpoint: string; reachable: boolean; identity: 'ok' | 'wrong' | 'other-home' | '-'; version: string; who: 'vt' | 'external' | '-' }

export async function localnetStatus(o: { json: boolean; env: Env }, deps: Partial<LocalnetDeps> = {}): Promise<number> {
  const d: LocalnetDeps = { ...defaultLocalnetDeps(o.env, deps.ports), ...deps }
  const p = assertPorts(d.ports)
  const paths = localnetPaths(vtHome(o.env))
  const out = resolveOut(o.env)
  const wins = new Set(hasSession(d.tmux, SESSION) ? (listWindows(d.tmux, SESSION) ?? []) : [])
  const record = readGenesisRecord(paths)
  const cookie = ownedCookie(paths, d.listenerPid, p.bitcoind)
  const rows: ServiceStatus[] = []
  for (const s of SERVICES) {
    if (s === 'miner') {
      const log = readSmallFile(join(paths.logs, 'miner.log'), { cap: 1024 * 1024 }) ?? ''
      const up = wins.has('miner') && scanLog(log, []).exited === null
      rows.push({ name: s, endpoint: '-', reachable: up, identity: up ? 'ok' : '-', version: up ? 'mining' : '-', who: up ? 'vt' : '-' })
      continue
    }
    const port = { anvil: p.anvil, solana: p.solana, bitcoind: p.bitcoind, ord: p.ord, otterscan: p.otterscan }[s]
    const taken = await tcpOpen(port)
    let id: Identity | null = null
    if (taken) {
      id = s === 'anvil' ? await probeAnvil(port) : s === 'solana' ? await probeSolana(port, record) : s === 'bitcoind' ? await probeBitcoind(port, cookie)
        : s === 'ord' ? await probeOrd(port, cookie === null ? null : { port: p.bitcoind, cookie })
        : await probeOtterscan(port)
      if (s === 'otterscan' && id.right && !d.loopbackOnly(port)) id = { right: false, version: '-', why: 'it listens on more than 127.0.0.1' }
    }
    // F-R-3: the genesis record and the credential file live under the VT_HOME that started the localnet; without them a healthy service cannot be identified from here
    const noProof = wins.has(s) && ((s === 'solana' && record === null) || ((s === 'bitcoind' || s === 'ord') && cookie === null))   // only for a window of vt's own session: a listener nobody started through vt stays IDENTITY WRONG
    rows.push({ name: s, endpoint: endpointOf(s, p), reachable: taken, identity: !taken ? '-' : (id as Identity).right ? 'ok' : noProof ? 'other-home' : 'wrong', version: id?.right === true ? id.version : '-', who: !taken ? '-' : wins.has(s) ? 'vt' : 'external' })
  }
  // green: anvil and solana are up with the right identity, and nothing that answers has the wrong one
  const need = rows.filter((r) => r.name === 'anvil' || r.name === 'solana')
  const ok = need.every((r) => r.identity === 'ok') && rows.every((r) => r.identity !== 'wrong')
  if (o.json) d.out(JSON.stringify({ ok, session: wins.size > 0 ? SESSION : null, services: rows }))
  else {
    for (const r of rows) d.out(line(r.name, r.endpoint, r.reachable ? `${r.version}` : 'not running', r.reachable ? (r.identity === 'other-home' ? `started under another VT_HOME — run status with that VT_HOME` : `${r.identity === 'ok' ? 'identity ok' : 'IDENTITY WRONG'}, started by ${r.who}`) : ''))
    d.out(ok ? 'localnet: ok' : 'localnet: not ready (vt localnet up)')
  }
  return ok ? 0 : 1
}

// ---- down

// The stop order: whatever reads a service stops before it (ord before its bitcoind: an ord whose bitcoind is already gone
// never exits on SIGTERM), the miner before bitcoind, the chains last.
export const STOP_ORDER: readonly Service[] = ['otterscan', 'ord', 'miner', 'bitcoind', 'solana', 'anvil']

export async function localnetDown(o: { env: Env }, deps: Partial<LocalnetDeps> = {}): Promise<number> {
  const d: LocalnetDeps = { ...defaultLocalnetDeps(o.env, deps.ports), ...deps }
  const p = assertPorts(d.ports)
  const paths = localnetPaths(vtHome(o.env))
  const running = hasSession(d.tmux, SESSION)
  const portOf: Partial<Record<Service, number>> = { anvil: p.anvil, solana: p.solana, bitcoind: p.bitcoind, ord: p.ord, otterscan: p.otterscan }
  const waitFree = async (port: number, ms: number): Promise<boolean> => {
    const deadline = d.now() + ms
    for (;;) {
      if (!(await tcpOpen(port))) return true
      if (d.now() >= deadline) return false
      await d.sleep(300)
    }
  }
  const still: string[] = []
  if (running) {
    const wins = listWindows(d.tmux, SESSION) ?? []
    if (wins.includes('solana')) { // best effort: where the validator is, so the next start can wait until it has replayed that far
      const sl = await jsonRpc(p.solana, 'getSlot', [{ commitment: 'processed' }], { timeoutMs: 2_000 })
      if (sl.ok && typeof sl.result === 'number') { try { writePrivateFile(paths.solana, 'last-slot', `${sl.result}\n`) } catch { /* best effort */ } }
    }
    for (const name of STOP_ORDER) {
      if (!wins.includes(name)) continue
      const k = killWindow(d.tmux, SESSION, name)
      if (k.code !== 0 && hasSession(d.tmux, SESSION)) { d.err(`vt localnet down: tmux could not stop the ${name} window${k.code === null ? ` (${k.err})` : ''}`); return 1 }
      const port = portOf[name]
      if (port !== undefined && name !== 'otterscan' && !(await waitFree(port, 40_000))) still.push(name)
    }
    if (hasSession(d.tmux, SESSION)) {
      const r = killSession(d.tmux, SESSION)
      if (r.code !== 0) { d.err(`vt localnet down: tmux could not stop ${SESSION}${r.code === null ? ` (${r.err})` : ''}`); return 1 }
    }
  }
  if (running) writeState(paths, {}, ['pids'])
  // The Otterscan container vt started (recorded), by its exact name.
  const st = readState(paths)
  if (st.otterscan !== undefined && st.otterscan.container === containerName({ ...p, otterscan: st.otterscan.port })) {
    d.dockerRun(['rm', '-f', st.otterscan.container])
    writeState(paths, {}, ['otterscan'])
  }
  if (still.length > 0) {
    d.err(`vt localnet down: ${SESSION} was stopped, but ${still.join(', ')} still answer${still.length === 1 ? 's' : ''} (one that vt did not start, or one still shutting down); vt does not kill by port`)
    return 1
  }
  d.out(running ? `vt localnet down: stopped ${SESSION} (data kept in $VT_HOME/localnet)` : `vt localnet down: ${SESSION} was not running`)
  return 0
}

// ---- fund

export interface FundDeps { listenerPid: (port: number) => number | null; ports: LocalnetPorts; out: (l: string) => void; sleep: (ms: number) => Promise<void>; now: () => number }
export async function localnetFund(o: { chain: 'eth' | 'sol' | 'btc'; address: string; amount: string | null; env: Env }, deps: Partial<FundDeps> = {}): Promise<number> {
  const d: FundDeps = { listenerPid: (port) => listenerPidOf(port, o.env), ports: DEFAULT_PORTS, out: (l) => { process.stdout.write(`${l}\n`) }, sleep: sleepMs, now: () => Date.now(), ...deps }
  const p = assertPorts(d.ports)
  // 1. the address, for that chain (before anything is contacted)
  const okAddr = o.chain === 'eth' ? isEthAddress(o.address) : o.chain === 'sol' ? isSolAddress(o.address) : isBtcRegtestAddress(o.address)
  if (!okAddr) refuse('localnet.fund-address', `not a valid ${o.chain === 'btc' ? 'regtest (bcrt1… or m/n/2…) ' : ''}${o.chain} address`) // @guard:localnet.fund-address
  const paths = localnetPaths(vtHome(o.env))
  const notLocal = (what: string): never => {
    refuse('localnet.fund-network', `the ${o.chain} node on the localnet port is not a local chain (${what}): vt localnet fund sends on local chains only`) // @guard:localnet.fund-network
    throw new Error('unreachable')
  }
  const down = (): never => { throw new UsageError(`nothing answers for ${o.chain} on its localnet port: run vt localnet up`) }
  if (o.chain === 'eth') {
    const wei = parseAmount(o.amount ?? '1', 18, 'ether')
    const c = await jsonRpc(p.anvil, 'eth_chainId', [])
    if (!c.ok) down()
    if (c.ok && c.result !== `0x${ANVIL_CHAIN_ID.toString(16)}`) notLocal('chain id is not 31337')
    const acc = await jsonRpc(p.anvil, 'eth_accounts', [])
    const from = acc.ok && Array.isArray(acc.result) && typeof acc.result[0] === 'string' ? acc.result[0] : null
    if (from === null) throw new UsageError('anvil has no unlocked dev account 0')
    const tx = await jsonRpc(p.anvil, 'eth_sendTransaction', [{ from, to: o.address, value: `0x${wei.toString(16)}` }])
    if (!tx.ok || typeof tx.result !== 'string') throw new Error(`anvil refused the transaction (${tx.ok ? 'no hash' : tx.error})`)
    const deadline = d.now() + 15_000
    let block: string | null = null
    while (block === null && d.now() < deadline) {
      const r = await jsonRpc(p.anvil, 'eth_getTransactionReceipt', [tx.result])
      if (r.ok && typeof r.result === 'object' && r.result !== null) block = String((r.result as { blockNumber?: unknown }).blockNumber ?? '')
      else await d.sleep(300)
    }
    d.out(`fund eth: ${formatUnits(wei, 18)} ETH -> ${o.address}`)
    d.out(`tx ${tx.result}${block !== null ? ` (block ${Number(BigInt(block))})` : ' (not mined yet)'}`)
    return 0
  }
  if (o.chain === 'sol') {
    const lamports = parseAmount(o.amount ?? '2', 9, 'SOL')
    const g = await jsonRpc(p.solana, 'getGenesisHash', [])
    if (!g.ok) down()
    const hash = str(g) ?? ''
    const rec = readGenesisRecord(paths)
    if (!isLocalSolanaGenesis(hash)) notLocal('its genesis hash is a public network\'s or malformed')
    if (rec !== null && rec !== hash) notLocal('another ledger than the one vt localnet recorded')
    const a = await jsonRpc(p.solana, 'requestAirdrop', [o.address, Number(lamports)])
    if (!a.ok || typeof a.result !== 'string') throw new Error(`the airdrop was refused (${a.ok ? 'no signature' : a.error})`)
    const deadline = d.now() + 30_000
    let confirmed = false
    while (!confirmed && d.now() < deadline) {
      const s = await jsonRpc(p.solana, 'getSignatureStatuses', [[a.result]])
      const v = s.ok && typeof s.result === 'object' && s.result !== null ? (s.result as { value?: unknown[] }).value?.[0] : null
      confirmed = typeof v === 'object' && v !== null && ['confirmed', 'finalized'].includes(String((v as { confirmationStatus?: unknown }).confirmationStatus))
      if (!confirmed) await d.sleep(400)
    }
    d.out(`fund sol: ${formatUnits(lamports, 9)} SOL -> ${o.address}`)
    d.out(`signature ${a.result}${confirmed ? ' (confirmed)' : ' (not confirmed yet)'}`)
    return 0
  }
  // btc: vt's own bitcoind only, identified with the datadir cookie (M7: the credential file's password is never sent from here)
  const sats = parseAmount(o.amount ?? '0.01', 8, 'BTC')
  const cookie = ownedCookie(paths, d.listenerPid, p.bitcoind)
  if (cookie === null) throw new UsageError('no bitcoind that vt localnet started answers on its port (no recorded owner, or another process listens there): nothing was sent; run vt localnet up')
  const info = await jsonRpc(p.bitcoind, 'getblockchaininfo', [], { line: cookie })
  if (!info.ok) { if (info.status === 401) notLocal('it does not accept the cookie of vt\'s bitcoind datadir'); down() }
  const chain = info.ok && typeof info.result === 'object' && info.result !== null ? (info.result as { chain?: unknown }).chain : undefined
  const g0 = str(await jsonRpc(p.bitcoind, 'getblockhash', [0], { line: cookie }))
  if (chain !== 'regtest' || g0 !== GENESIS.btc.regtest) notLocal('not a regtest chain')
  const wp = `/wallet/${WALLET}`
  const send = await jsonRpc(p.bitcoind, 'sendtoaddress', { address: o.address, amount: formatUnits(sats, 8) }, { line: cookie, path: wp })
  if (!send.ok || typeof send.result !== 'string') throw new Error(`bitcoind refused the payment (${send.ok ? 'no txid' : send.error})`)
  const mine = await jsonRpc(p.bitcoind, 'getnewaddress', [], { line: cookie, path: wp })
  const blk = mine.ok ? await jsonRpc(p.bitcoind, 'generatetoaddress', [1, mine.result], { line: cookie }) : null
  d.out(`fund btc: ${formatUnits(sats, 8)} BTC -> ${o.address}`)
  d.out(`txid ${send.result}${blk !== null && blk.ok ? ' (mined in 1 block)' : ' (in the mempool; the miner confirms it)'}`)
  return 0
}

// ---- the command

export async function localnetCommand(o: { args: readonly string[]; env: Env; network: string | undefined; ports?: Partial<LocalnetPorts> }): Promise<number> {
  const c = parseLocalnetArgs(o.args)
  const nonLocal = o.network !== undefined && o.network !== '' && o.network !== 'local'
  if (nonLocal) refuse('localnet.network', 'vt localnet is for the local network only (R77: testnet is held, mainnet has no local setup)') // @guard:localnet.network
  const ports: LocalnetPorts = { ...DEFAULT_PORTS, ...(o.ports ?? {}) }
  switch (c.sub) {
    case 'up': return await localnetUp({ btc: c.btc, otterscan: c.otterscan, reset: c.reset, mineEvery: c.mineEvery, env: o.env }, { ports })
    case 'status': return await localnetStatus({ json: c.json, env: o.env }, { ports })
    case 'down': return await localnetDown({ env: o.env }, { ports })
    case 'fund': return await localnetFund({ chain: c.chain, address: c.address, amount: c.amount, env: o.env }, { ports })
  }
}

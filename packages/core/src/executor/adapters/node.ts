// packages/core/src/executor/adapters/node.ts — the CLI executor's adapter (`vt job run`, `vt job clawback`; C6 owns the
// CLI and its TTY): the wall clock, node:crypto randomInt, the loopback clients of this network's stack, the API token
// read from its file, and the key loaded from its encrypted backup. The only node: imports of packages/core (spec §7.1).
// The passphrase comes from the caller (C6 reads it from /dev/tty with no echo); the key stays in memory only.
import { randomInt } from 'node:crypto'
import { constants, fstatSync, openSync, readSync, closeSync, readFileSync } from 'node:fs'
import { PORTS, isNetwork } from '../../contracts/index.ts'
import type { Chain, Network } from '../../contracts/index.ts'
import { loadBackup } from '../../gates/backup.ts'
import { httpJournalClient } from '../journal-client.ts'
import type { Fetch } from '../journal-client.ts'
import { httpRelayClient } from '../relay-client.ts'
import type { ExecutorKey } from '../executor.ts'

export function nodeAdapter(): { clock: { now(): number; sleep(ms: number): Promise<void> }; random: { int(maxExclusive: number): number } } {
  return {
    clock: { now: () => Date.now(), sleep: (ms) => new Promise((r) => setTimeout(r, Math.max(0, ms))) },
    random: { int: (max) => randomInt(max) },
  }
}
// The loopback clients of this network's stack (the CLI executor's sandbox allows exactly these two ports).
export function nodeClients(o: { network: Network; token: string; fetch?: Fetch }) {
  if (!isNetwork(o.network)) throw new TypeError('nodeClients: network must be local, testnet or mainnet')
  const f: Fetch = o.fetch ?? ((url, init) => globalThis.fetch(url, init))
  return {
    journal: httpJournalClient({ base: `http://127.0.0.1:${PORTS[o.network].api}`, fetch: f, token: o.token }),
    relay: httpRelayClient({ base: `http://127.0.0.1:${PORTS[o.network].relay}`, fetch: f }),
  }
}
// The API token file ($VT_HOME/<network>/api.token): a regular file, mode 0600 or stricter, exactly 64 lowercase hex.
// Read through one fd (no symlink followed, no TOCTOU). The refusal never names the path or the content.
export function readApiToken(path: string): string {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
  try {
    const st = fstatSync(fd)
    if (!st.isFile() || (st.mode & 0o077) !== 0 || st.size > 4096) throw new Error('the API token file must be a regular file of mode 0600 (or stricter)')
    const b = Buffer.alloc(st.size), n = readSync(fd, b, 0, st.size, 0)
    const t = b.subarray(0, n).toString('utf8').trim()
    if (!/^[0-9a-f]{64}$/.test(t)) throw new Error('the API token file does not hold a token')
    return t
  } finally { closeSync(fd) }
}
// The executor's key from its encrypted backup (gates/backup.ts loadBackup: backup.decrypt, backup.chain,
// backup.inconsistent, backup.address-mismatch). warnNetwork: the backup was made on another network (or before R71):
// the caller asks the operator to confirm before running.
export async function loadKeyFile(path: string, passphrase: string, chain: Chain, expect: { address: string; network: Network }): Promise<{ key: ExecutorKey; warnNetwork: boolean }> {
  const { key, warnNetwork, network } = await loadBackup(new Uint8Array(readFileSync(path)), passphrase, chain, expect)
  return { key: { chain, address: key.address, network, handle: key }, warnNetwork }
}

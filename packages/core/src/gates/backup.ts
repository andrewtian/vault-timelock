// packages/core/src/gates/backup.ts — loading a key from its encrypted backup (spec §13 "Address equals keyAddress"),
// for the CLI executor and the page. The file format is engine/keys.js's (the prototype's .age backup, plus the optional
// trailing `network`, R71). The key stays in memory only; nothing here logs or returns the secret text.
//   backup.decrypt           the passphrase does not open the file, or the plaintext is not a key backup
//   backup.chain             the backup is for another chain
//   backup.inconsistent      the backup's secret does not derive the address recorded next to it (a tampered pair)
//   backup.address-mismatch  the backup holds a valid key, but not the job's keyAddress for this chain
// warnNetwork: the backup was made on another network, or before R71 (no network recorded). Not a refusal: the caller
// shows a warning that needs the operator's tick (W2 "backup network warning").
import type { Chain, Network } from '../contracts/index.ts'
import { refuse } from '../contracts/index.ts'
import type { Key } from '../chains/types.ts'
import { fromSecret, openBackup } from '../engine/keys.js'

type Obj = Record<string, unknown>
const isBackup = (j: unknown): j is Obj & { chain: string; address: string; secret: string } => {
  if (j === null || typeof j !== 'object' || Array.isArray(j)) return false
  const o = j as Obj
  return typeof o.chain === 'string' && typeof o.address === 'string' && typeof o.secret === 'string'
}
// ETH addresses compare case-insensitively (EIP-55 is a checksum of the same bytes); SOL base58 is exact.
const sameAddress = (chain: Chain, a: string, b: string): boolean => (chain === 'eth' ? a.toLowerCase() === b.toLowerCase() : a === b)

export async function loadBackup(bytes: Uint8Array, passphrase: string, chain: Chain, expect: { address: string; network: Network }): Promise<{ key: Key; warnNetwork: boolean; network: Network | null }> {
  const plain: unknown = await openBackup(bytes, passphrase).catch(() => undefined)
  const opened = isBackup(plain)
  if (!opened) refuse('backup.decrypt', 'wrong passphrase, or not a key backup file') // @guard:backup.decrypt
  const chainOk = plain.chain === chain
  if (!chainOk) refuse('backup.chain', `this backup is not for ${chain}`) // @guard:backup.chain
  const secret = plain.secret
  const key: Key | null = (() => { try { return fromSecret(chain, secret, plain.network) } catch { return null } })()
  const consistent = key !== null && key.chain === chain && key.address === plain.address
  if (!consistent) refuse('backup.inconsistent', 'the backup is inconsistent: its secret does not derive the address recorded with it') // @guard:backup.inconsistent
  const matches = sameAddress(chain, key.address, String(expect.address))
  if (!matches) refuse('backup.address-mismatch', `the backup holds a different ${chain} key than the job names`) // @guard:backup.address-mismatch
  const recorded = plain.network === 'local' || plain.network === 'testnet' || plain.network === 'mainnet' ? plain.network as Network : null
  return { key, warnNetwork: plain.network !== expect.network, network: recorded }
}

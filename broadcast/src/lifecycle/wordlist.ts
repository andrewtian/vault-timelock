// The EFF large wordlist (spec C 5: the passphrase rule accepts 6 words from it). 7776 lines `NNNNN\tword` (dice
// indices 11111..66666), vendored at vendor/eff_large_wordlist.txt. Fetched once, read-only, through Tor (Task 12b):
//   curl -sS --socks5-hostname 127.0.0.1:9050 https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
// and pinned here by SHA-256. A file with any other hash (edited, truncated, swapped, missing) refuses
// keystore.wordlist-hash: a padded list would let short phrases pass as "6 words".
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { refuse } from '../guard.ts'

export const WORDLIST_SHA256 = 'addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e'
export const WORDLIST_PATH = fileURLToPath(new URL('../../vendor/eff_large_wordlist.txt', import.meta.url))

// The words of the list at `path` (default: the vendored one), after checking its hash. The format needs no check of
// its own: only the pinned file gets this far.
export function loadWordlist(path: string = WORDLIST_PATH): ReadonlySet<string> {
  let bytes: Buffer = Buffer.alloc(0)
  try { bytes = readFileSync(path) } catch { /* missing or unreadable: the empty hash refuses below */ }
  const ok = createHash('sha256').update(bytes).digest('hex') === WORDLIST_SHA256
  if (!ok) refuse('keystore.wordlist-hash', 'vendor/eff_large_wordlist.txt is missing or is not the pinned EFF large wordlist (SHA-256 mismatch)') // @guard:keystore.wordlist-hash
  return new Set(bytes.toString('utf8').split('\n').filter((l) => l !== '').map((l) => l.slice(l.indexOf('\t') + 1)))
}

let cached: ReadonlySet<string> | undefined
export function effWords(): ReadonlySet<string> {
  cached ??= loadWordlist()
  return cached
}

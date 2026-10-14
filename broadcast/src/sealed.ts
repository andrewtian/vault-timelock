// SEALED.txt from a package directory: read the directory, then run the browser-safe builder in @vault-timelock/core
// (moved there by E6: packages/core/src/text/sealed-from.ts). buildSealed(pkgDir) and dirReader stay here: they read files.
import { lstatSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { buildSealedFrom, type PackageReader, type SealedOpts } from '@vault-timelock/core/text/sealed-from.ts'
export {
  CHECK, CUT, MANIFEST_CHECK, TOR, mapReader, parseAgeHeader, parseTlockStanza,
  type AgeHeader, type PackageReader, type SealedOpts,
} from '@vault-timelock/core/text/sealed-from.ts'

// A package directory as a PackageReader: names = the directory's entries (none if unreadable), read = the bytes of a
// REGULAR file (lstat: a symlink or a directory reads as null, and so is refused as sealed.file).
export function dirReader(dir: string): PackageReader {
  return {
    names: () => { try { return readdirSync(dir) } catch { return [] } },
    read: (name) => {
      try { return lstatSync(join(dir, name)).isFile() ? new Uint8Array(readFileSync(join(dir, name))) : null } catch { return null }
    },
  }
}

export function buildSealed(pkgDir: string, opts: SealedOpts): string {
  return buildSealedFrom(dirReader(pkgDir), opts)
}

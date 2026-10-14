// buildSealed(dir) for the moved tests: a directory reader (lstat: only REGULAR files read; same rule as
// broadcast's dirReader) over core's buildSealedFrom.
import { lstatSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { buildSealedFrom, type PackageReader, type SealedOpts } from '../../src/text/sealed-from.ts'

export function dirReader(dir: string): PackageReader {
  return {
    names: () => { try { return readdirSync(dir) } catch { return [] } },
    read: (name) => {
      try { return lstatSync(join(dir, name)).isFile() ? new Uint8Array(readFileSync(join(dir, name))) : null } catch { return null }
    },
  }
}

export const buildSealed = (dir: string, opts: SealedOpts): string => buildSealedFrom(dirReader(dir), opts)

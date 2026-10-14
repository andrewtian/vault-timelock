// drand-client 1.2.5 (tlock-js's chain client) imports `@noble/hashes/sha256` but does not declare @noble/hashes: it works only
// when the package manager hoists it. Under this repository's linked install (install-strategy=linked) the import cannot be
// resolved from drand-client's own directory. This plugin resolves it, for drand-client importers only, from tlock-js's directory,
// where @noble/hashes ^1 IS a declared dependency (the same version tlock-js itself uses). Build, dev and vitest all use it.
import { createRequire } from 'node:module'

export function drandNobleHashes() {
  const require = createRequire(import.meta.url)
  return {
    name: 'vt-drand-client-noble-hashes',
    enforce: 'pre',
    resolveId(source, importer, opts) {
      if (!source.startsWith('@noble/hashes/') || !importer || !/[\\/]node_modules[\\/]\.store[\\/]drand-client@[^\\/]+[\\/]node_modules[\\/]drand-client[\\/]/.test(importer) || source.includes('..')) return null
      return this.resolve(source, require.resolve('tlock-js'), { ...opts, skipSelf: true })
    },
  }
}

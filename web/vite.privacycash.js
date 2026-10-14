// The Privacy Cash worker bundle (W6). The SDK imports Node's `crypto` (createHash, createHmac, randomBytes, aes-256-gcm,
// aes-128-ctr; research Q4). Inside the worker bundle ONLY, `crypto` / `node:crypto` resolve to src/privacycash/node-crypto.js,
// a synchronous noble-based shim of exactly that slice. The page's own bundle never sees the alias, and the shim is
// compared with node:crypto by test/privacycash-crypto.test.js.
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'

const SHIM = fileURLToPath(new URL('./src/privacycash/node-crypto.js', import.meta.url))

export function privacyCashCrypto() {
  return {
    name: 'vt-privacycash-node-crypto',
    enforce: 'pre',
    resolveId(source) { return source === 'crypto' || source === 'node:crypto' ? SHIM : null },
  }
}

// @lightprotocol/hasher.rs 0.2.1 imports `bn.js` but does not declare it (the same shape as drand-client and @noble/hashes, vite.drand.js):
// it works only when the package manager hoists it. Under the linked install it cannot be resolved from hasher.rs's own directory, so
// for hasher.rs importers only it is resolved from privacycash's directory, where bn.js ^5.2.2 IS a declared dependency.
export function hasherBn() {
  const require = createRequire(import.meta.url)
  return {
    name: 'vt-hasher-rs-bn',
    enforce: 'pre',
    resolveId(source, importer, opts) {
      if (source !== 'bn.js' || !importer || !/[\\/]node_modules[\\/]\.store[\\/]@lightprotocol[\\/]hasher\.rs@[^\\/]+[\\/]node_modules[\\/]@lightprotocol[\\/]hasher\.rs[\\/]/.test(importer)) return null
      return this.resolve(source, require.resolve('privacycash'), { ...opts, skipSelf: true })
    },
  }
}

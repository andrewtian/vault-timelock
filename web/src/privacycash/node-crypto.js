// The slice of Node's `crypto` the Privacy Cash SDK uses in its withdraw path (research Q4): createHash('sha256'),
// createHmac('sha256'), randomBytes, and createCipheriv / createDecipheriv for aes-256-gcm (getAuthTag / setAuthTag) and
// aes-128-ctr. SYNCHRONOUS (WebCrypto is async and cannot stand in), on the audited @noble libraries. Aliased in as
// `crypto` for the worker bundle only (vite.config.js); nothing else in the page imports it. Anything outside that slice
// throws: an unknown algorithm is never silently approximated.
//   test/privacycash-crypto.test.js compares every function with node:crypto on random inputs.
import { Buffer } from 'buffer'
import { ctr, gcm } from '@noble/ciphers/aes.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'

const bytes = (v, enc) => {
  if (typeof v === 'string') return Buffer.from(v, enc)
  if (v instanceof Uint8Array) return v
  throw new TypeError('crypto shim: data must be a string or bytes')
}
const out = (u8, enc) => { const b = Buffer.from(u8); return enc ? b.toString(enc) : b }

export function createHash(alg) {
  if (alg !== 'sha256') throw new Error(`crypto shim: createHash(${JSON.stringify(alg)}) is not supported`)
  const parts = []
  return {
    update(d, enc) { parts.push(Buffer.from(bytes(d, enc))); return this },
    digest(enc) { return out(sha256(Buffer.concat(parts)), enc) },
  }
}

export function createHmac(alg, key) {
  if (alg !== 'sha256') throw new Error(`crypto shim: createHmac(${JSON.stringify(alg)}) is not supported`)
  const k = Buffer.from(bytes(key))
  const parts = []
  return {
    update(d, enc) { parts.push(Buffer.from(bytes(d, enc))); return this },
    digest(enc) { return out(hmac(sha256, k, Buffer.concat(parts)), enc) },
  }
}

export function randomBytes(n) {
  if (!Number.isSafeInteger(n) || n < 0 || n > 65536) throw new RangeError('crypto shim: randomBytes size')
  const b = Buffer.alloc(n)
  globalThis.crypto.getRandomValues(b)
  return b
}

const SPEC = { 'aes-256-gcm': { key: 32, iv: 12 }, 'aes-128-ctr': { key: 16, iv: 16 } }
function check(alg, key, iv) {
  const s = SPEC[alg]
  if (!s) throw new Error(`crypto shim: cipher ${JSON.stringify(alg)} is not supported`)
  if (!(key instanceof Uint8Array) || key.length !== s.key) throw new RangeError(`crypto shim: ${alg} needs a ${s.key}-byte key`)
  if (!(iv instanceof Uint8Array) || iv.length !== s.iv) throw new RangeError(`crypto shim: ${alg} needs a ${s.iv}-byte iv`)
}

// Streaming is not needed (the SDK calls update once, then final): update collects, final does the work. update() returns an
// empty buffer, so Buffer.concat([update(x), final()]) is the whole output, as with Node.
export function createCipheriv(alg, key, iv) {
  check(alg, key, iv)
  const parts = []
  let tag = null, done = false
  return {
    update(d, enc) { if (done) throw new Error('crypto shim: cipher already finalised'); parts.push(Buffer.from(bytes(d, enc))); return Buffer.alloc(0) },
    final() {
      if (done) throw new Error('crypto shim: cipher already finalised')
      done = true
      const data = Buffer.concat(parts)
      if (alg === 'aes-128-ctr') return Buffer.from(ctr(key, iv).encrypt(data))
      const sealed = gcm(key, iv).encrypt(data)            // ciphertext || 16-byte tag
      tag = Buffer.from(sealed.subarray(sealed.length - 16))
      return Buffer.from(sealed.subarray(0, sealed.length - 16))
    },
    getAuthTag() { if (alg !== 'aes-256-gcm' || tag === null) throw new Error('crypto shim: no auth tag'); return tag },
  }
}

export function createDecipheriv(alg, key, iv) {
  check(alg, key, iv)
  const parts = []
  let tag = null, done = false
  return {
    update(d, enc) { if (done) throw new Error('crypto shim: decipher already finalised'); parts.push(Buffer.from(bytes(d, enc))); return Buffer.alloc(0) },
    setAuthTag(t) { if (alg !== 'aes-256-gcm') throw new Error('crypto shim: no auth tag for this cipher'); tag = Buffer.from(bytes(t)); return this },
    final() {
      if (done) throw new Error('crypto shim: decipher already finalised')
      done = true
      const data = Buffer.concat(parts)
      if (alg === 'aes-128-ctr') return Buffer.from(ctr(key, iv).decrypt(data))
      if (tag === null || tag.length !== 16) throw new Error('Unsupported state or unable to authenticate data')
      try { return Buffer.from(gcm(key, iv).decrypt(Buffer.concat([data, tag]))) } catch { throw new Error('Unsupported state or unable to authenticate data') }
    },
  }
}

export default { createHash, createHmac, randomBytes, createCipheriv, createDecipheriv }

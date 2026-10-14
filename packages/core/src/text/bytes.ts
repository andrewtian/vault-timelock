// Browser-safe byte helpers for the timelocked-text modules: plain Uint8Array, no Buffer, no node:*.
// SHA-256 from @noble/hashes (sync); base64 is written out here (strict), so the only dependency is @noble/hashes.
import { sha256 } from '@noble/hashes/sha2.js'

const ENC = new TextEncoder()
export const utf8 = (s: string): Uint8Array => ENC.encode(s)

export function hex(b: Uint8Array): string {
  let s = ''
  for (const x of b) s += x.toString(16).padStart(2, '0')
  return s
}

export const sha256Hex = (b: Uint8Array): string => hex(sha256(b))

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0
  for (const p of parts) n += p.length
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) { out.set(p, o); o += p.length }
  return out
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

// Byte -> U+00XX, exactly like Buffer's 'latin1' (TextDecoder('latin1') is windows-1252, which differs).
export function latin1(b: Uint8Array): string {
  let s = ''
  for (let i = 0; i < b.length; i += 8192) s += String.fromCharCode(...b.subarray(i, i + 8192))
  return s
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
const B64_REV = new Map([...B64].map((c, i) => [c, i] as const))

export function b64encode(b: Uint8Array): string {
  let s = ''
  for (let i = 0; i < b.length; i += 3) {
    const n = (b[i] << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0)
    s += B64[(n >> 18) & 63] + B64[(n >> 12) & 63]
    s += i + 1 < b.length ? B64[(n >> 6) & 63] : '='
    s += i + 2 < b.length ? B64[n & 63] : '='
  }
  return s
}

// Strict: standard alphabet, length % 4 === 0, '=' only as 1-2 trailing pad characters, no whitespace; else null.
// Non-zero trailing bits decode; armor's canonical re-encoding check rejects them.
export function b64decode(s: string): Uint8Array | null {
  if (s.length % 4 !== 0) return null
  const pad = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0
  const body = s.slice(0, s.length - pad)
  const out = new Uint8Array((s.length / 4) * 3 - pad)
  let o = 0
  for (let i = 0; i < body.length; i += 4) {
    let n = 0
    let k = 0
    for (; k < 4 && i + k < body.length; k++) {
      const v = B64_REV.get(body[i + k])
      if (v === undefined) return null
      n |= v << (18 - 6 * k)
    }
    for (let j = 0; j < k - 1; j++) out[o++] = (n >> (16 - 8 * j)) & 255
  }
  return o === out.length ? out : null
}

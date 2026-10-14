// packages/core/src/job/canonical.ts — canonical JSON, sha256 and the job id (spec §4.1).
//   canonicalJson: keys sorted (UTF-16 code-unit order, as Array.prototype.sort), no whitespace, numbers and strings as
//   JSON.stringify writes them; an object member whose value is undefined is left out (as JSON.stringify does). It
//   refuses what JSON cannot hold faithfully: non-finite numbers (RangeError); undefined outside an object member,
//   functions, symbols and bigints (TypeError). These are programming errors, not operator input: no guard id.
//   jobId(def) = sha256Hex(canonicalJson(def)).slice(0, 16) — the canonical def carries `network`, so the same text on
//   two networks gives two ids. Browser-safe: no node: imports (contract static scan 4).
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import type { JobDef } from '../contracts/index.ts'

const utf8 = new TextEncoder()

export function canonicalJson(v: unknown): string {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v)
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new RangeError('canonicalJson: a non-finite number has no JSON form')
    return JSON.stringify(v)
  }
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>
    const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort()
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(',')}}`
  }
  throw new TypeError(`canonicalJson: a ${typeof v} has no JSON form`)
}

// A string is hashed as its UTF-8 bytes. (A string with a lone surrogate would be hashed with U+FFFD in its place:
// message text is refused message.utf8 before it is ever hashed.)
export function sha256Hex(b: Uint8Array | string): string {
  return bytesToHex(sha256(typeof b === 'string' ? utf8.encode(b) : b))
}

export function jobId(def: JobDef): string {
  return sha256Hex(canonicalJson(def)).slice(0, 16)
}

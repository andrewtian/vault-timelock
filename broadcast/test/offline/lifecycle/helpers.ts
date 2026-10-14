// Shared test helpers for the lifecycle tasks (12a onward). Test-only: the PRNG here is NOT for production.
import assert from 'node:assert/strict'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { Refusal } from '../../../src/guard.ts'
import type { Clock, Random } from '../../../src/lifecycle/clock.ts'

export function refused(f: () => unknown, id: string): void {
  assert.throws(f, (e: unknown) => e instanceof Refusal && e.guardId === id, `expected refusal ${id}`)
}
export async function refusedAsync(f: () => Promise<unknown>, id: string): Promise<void> {
  await assert.rejects(f, (e: unknown) => e instanceof Refusal && e.guardId === id, `expected refusal ${id}`)
}

// mulberry32: small, fast, deterministic. Tests only.
export function seededRandom(seed: number): Random {
  let a = seed >>> 0
  const next = (): number => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
  return {
    uniform: (lo, hi) => lo + next() * (hi - lo),
    int: (n) => Math.floor(next() * n),
  }
}

export function fakeClock(start: number): Clock & { set(t: number): void } {
  let t = start
  return { now: () => t, set: (v) => { t = v } }
}

// Later tasks reuse this: no file under `dir` (recursively, names included) may contain any secret.
// Task 12b extends it to key material: a string secret is searched in every file as its UTF-8, UTF-16LE and Latin-1
// bytes (and in every path); a Uint8Array secret (raw key bytes) as those exact bytes. Failures never print the secret.
export function assertNoSecretsInStore(dir: string, secrets: readonly (string | Uint8Array)[]): void {
  assert.ok(secrets.length > 0 && secrets.every((s) => s.length >= 4), 'secrets must be non-trivial')
  const needles = secrets.flatMap((s) => (typeof s === 'string'
    ? [Buffer.from(s, 'utf8'), Buffer.from(s, 'utf16le'), Buffer.from(s, 'latin1')]
    : [Buffer.from(s)]))
  const names = secrets.filter((s): s is string => typeof s === 'string')
  const walk = (d: string): void => {
    for (const name of readdirSync(d)) {
      const p = join(d, name)
      for (const s of names) assert.ok(!p.includes(s), 'a secret appears in a path under the store')
      if (statSync(p).isDirectory()) { walk(p); continue }
      const data = readFileSync(p)
      for (const n of needles) assert.ok(data.indexOf(n) < 0, 'a secret appears in a stored file')
    }
  }
  walk(dir)
}

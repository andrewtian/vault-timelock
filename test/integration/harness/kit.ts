// test/integration/harness/kit.ts — the glue every E4 scenario file shares (not a test file): cleanup, synthetic keys,
// texts and passphrases, and the closing on-chain check with its report evidence. ALL DATA IS SYNTHETIC.
import { after } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import type { Chain, JobDef, JobState } from '../../../packages/core/src/contracts/index.ts'
import { encryptKey, newKey, passphraseCheck } from '../../../packages/core/src/engine/keys.js'
import { checkPublished } from './chains.ts'
import type { Published, T } from './chains.ts'
import { evidence } from './stack.ts'
import { tempDir } from '../../../api/test/helpers.ts'
import type { KeyHandle } from './stack.ts'

process.env.NODE_ENV = 'test'

// One cleanup list per file, run in reverse at the end (children stopped by pid, temp dirs removed).
export function lifecycle(): T {
  const cleanups: Array<() => unknown> = []
  after(async () => { for (const fn of cleanups.reverse()) { try { await fn() } catch { /* best effort */ } } })
  return { after: (fn) => { cleanups.push(fn) } }
}
// A private temp dir (the chains' HOME and ledgers), removed at the end.
export function scratch(t: T): string {
  const { dir, cleanup } = tempDir('vt-e4-')
  t.after(cleanup)
  return dir
}
export const keyOf = (chain: Chain): KeyHandle => newKey(chain) as KeyHandle
export function passphrase(): string {
  for (;;) {   // ~1 % of random hex has a repeated piece the rule refuses: draw again
    const p = `E4-synthetic-${randomBytes(9).toString('hex')}-Zq!`
    if (passphraseCheck(p).ok) return p
  }
}
export async function backupOf(key: KeyHandle, pass: string): Promise<Uint8Array> {
  return (await encryptKey(key as never, pass, 'local')).ct as Uint8Array
}
// Synthetic text the message rules accept (no secrets, no IP literals): numbered lines of made-up words.
export function syntheticText(bytes: number, label: string): string {
  const words = ['vtfix', 'zorbel', 'quandle', 'mirtal', 'flonk', 'plimsy', 'trevvet', 'gausk', 'wendle', 'snarpt', 'oxlind', 'brumple']
  let s = `${label}\n`
  for (let i = 1; s.length < bytes; i++) s += `Line ${String(i).padStart(6, '0')}: ${words[i % words.length]} ${words[(i * 7) % words.length]} ${words[(i * 5 + 3) % words.length]}.\n`
  return s.slice(0, bytes - 1) + '\n'
}
export const ms = (t0: number): number => Date.now() - t0

// The closing check of every publishing scenario: the chain itself (read directly) carries every landed (copy, part)
// once with the planned bytes, nothing else from the key; every copy reassembled ✓. Logs the evidence for the report.
export async function assertPublished(scenario: string, ports: { anvil?: number; sol?: number }, def: JobDef, text: string, st: JobState, chain: Chain, o: { copies?: number; scope?: 'key' | 'job' } = {}): Promise<Published> {
  const cs = st.chains[chain]!
  const p = await checkPublished(ports, def, text, cs, chain, { scope: o.scope ?? 'key' })
  const copies = [...new Set(p.parts.map((x) => x.copy))]
  for (const c of copies) {
    const n = p.parts.filter((x) => x.copy === c).length, parts = p.parts.find((x) => x.copy === c)!.parts
    if (n === parts) assert.ok(cs.reassembled.some((r) => r.copy === c && r.ok), `${chain} copy ${c} reassembled ✓`)
  }
  if (o.copies !== undefined) assert.equal(copies.length, o.copies, `${chain}: ${o.copies} copies on chain`)
  evidence(scenario, `${chain} published`, { job: def.name, parts: p.parts.map((x) => ({ copy: x.copy, part: `${x.part}/${x.parts}`, tx: x.txId, [chain === 'eth' ? 'block' : 'slot']: x.at, bytes: x.bytes, fee: x.fee })) })
  return p
}

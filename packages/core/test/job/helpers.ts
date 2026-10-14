// Shared helpers for the job-domain unit tests (not a test file itself). ALL DATA IS SYNTHETIC.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { base58 } from '@scure/base'
import { isRefusal } from '../../src/contracts/index.ts'
import type { Chain, JobDef, JobState, JournalEvent } from '../../src/contracts/index.ts'
import { reduce } from '../../src/job/index.ts'

type Obj = Record<string, unknown>

export const fixture = (p: string): string => fileURLToPath(new URL(`../../contract/fixtures/${p}`, import.meta.url))
export const readJson = <T>(p: string): T => JSON.parse(readFileSync(fixture(p), 'utf8')) as T

// The refusal's guard id, null when fn returns; anything that is not a Refusal is rethrown.
export function guardOf(fn: () => unknown): string | null {
  try { fn() } catch (e) { if (isRefusal(e)) return e.guardId; throw e }
  return null
}

// The refusal itself (to check that its message never echoes the input).
export function refusalOf(fn: () => unknown): Error {
  try { fn() } catch (e) { if (isRefusal(e)) return e; throw e }
  throw new Error('expected a refusal')
}

// The one contracted way to decode message bytes (Task 0 ruling 7).
export const decode = (b: Uint8Array): string => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(b)

// Deterministic PRNG (mulberry32) for schedule tests: randInt(max) in [0, max).
export function seeded(seed: number): (maxExclusive: number) => number {
  let a = seed >>> 0
  return (maxExclusive: number): number => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    const r = ((t ^ (t >>> 14)) >>> 0) / 4294967296
    return Math.floor(r * maxExclusive)
  }
}

export function deepFreeze<T>(v: T): T {
  if (v !== null && typeof v === 'object') {
    for (const x of Object.values(v as object)) deepFreeze(x)
    Object.freeze(v)
  }
  return v
}

// ---- a small journal builder for the rules the vectors do not reach (reduce, intent tests) --------------------------
export const BOTH = readJson<JobDef>('journals/15a-skipped.def.json') // eth { copies: 1 } + sol { copies: 3 }
export const ethTx = (n: number): string => `0x${n.toString(16).padStart(64, '0')}`
export const solSig = (n: number): string => base58.encode(new Uint8Array(64).fill(n))
export const H = 'ab'.repeat(32)
export const CAP = { nativeCap: '1', usd: 1, priceAt: null, overCap: false, planned: '0.1' }
export function journal(def: JobDef = BOTH) {
  const evs: JournalEvent[] = []
  const add = (chain: Chain | null, by: JournalEvent['by'], type: JournalEvent['type'], data: Obj, gen: number | null = chain === null || by === 'api' ? null : 1): JournalEvent[] => {
    evs.push({ v: 1, seq: evs.length, at: 1_000 + evs.length, prev: '', chain, by, gen, type, data })
    return evs
  }
  const api = (type: JournalEvent['type'], data: Obj, chain: Chain | null = null) => add(chain, 'api', type, data)
  const ex = (chain: Chain, type: JournalEvent['type'], data: Obj, gen = 1) => add(chain, 'browser', type, data, gen)
  const ready = (c: Chain) => { ex(c, 'key-loaded', { address: def.chains[c]!.keyAddress }); ex(c, 'funds', { balance: '9', affordable: true, nextCopyCost: '1' }) }
  const arm = (order: Chain[]) => api('armed', { armedAt: 0, releaseAt: 15_000, countdownSec: 15, schedule: { order, offsetSec: Object.fromEntries(order.map((c, i) => [c, i * 30])) }, caps: Object.fromEntries(order.map((c) => [c, CAP])), sources: {} })
  const intent = (c: Chain, txId: string, copy: number, part: number, parts: number, attempt = 1, gen = 1) => ex(c, 'intent', {
    txId, copy, part, parts, attempt, replaces: null, rawSha256: H, payloadSha256: H, reserved: '1',
    ...(c === 'eth' ? { eth: { nonce: copy, tip: '1', maxFee: '2', gas: '21000', to: '0x0000000000000000000000000000000000000000' } } : { sol: { blockhash: base58.encode(new Uint8Array(32).fill(1)), lastValidBlockHeight: 1, cuPrice: 0, cuLimit: 1, rung: null, fee: '5000' } }),
  }, gen)
  const land = (c: Chain, txId: string, copy: number, part: number, fee = '10', ok: boolean | null = true) => {
    ex(c, 'sent', { txId, outcome: 'accepted', reason: null })
    ex(c, 'included', { txId, copy, part, attempt: 1, block: '7', fee, ms: 1 })
    if (ok !== null) ex(c, 'readback', { txId, ok, detail: ok ? 'payload bytes match' : 'payload bytes differ' })
  }
  return { evs, add, api, ex, ready, arm, intent, land, state: (): JobState => reduce(def, evs) }
}

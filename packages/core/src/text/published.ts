// Per-destination published text (spec B §5.0, R32-R34): two-line header + note + "\n\n" +
// SEALED.txt text; `full` if it fits the destination's cap, else `key-only`, else refuse.
// Solana carries header + note + "\nsha256:<hex>" only (Memo v2, <= SOL_MEMO_MAX bytes), where <hex>
// is the SHA-256 of the text exactly as the 98,304 B no-prefix destinations (Base, Bitcoin, the Arweave
// item) carry it in this publication (R41): `full` if it fits PUBLISH_CAP, else `key-only`. So the
// pointer always names bytes that are on a public chain.
// Moved from broadcast/src/published.ts (E6); browser-safe.
import { refuse } from './guard.ts'
import { buildEnvelope } from './envelope.ts'
import { concat, sha256Hex, utf8 } from './bytes.ts'

export const PUBLISH_CAP = 98304 // eth, base, btc, arweave
export const ARB_CAP = 94000 // R33
export const SOL_MEMO_MAX = 1000 // UTF-8 bytes of the whole memo; the exact tx-size check is Task 14's
export const ETH_PREFIX = 'data:,' // R32: Ethscription, 6 bytes, raw text after it

export type Dest = 'eth' | 'arb' | 'base' | 'btc' | 'arweave' | 'sol'
export type Published = { bytes: Uint8Array; contents: 'full' | 'key-only' | 'none'; sha256: string }

const UNLOCK_LINE = /^unlock-after: (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)  \(drand round [1-9]\d*\)$/m

const sha = sha256Hex
export const CAPS: Record<Exclude<Dest, 'sol'>, number> = { eth: PUBLISH_CAP, arb: ARB_CAP, base: PUBLISH_CAP, btc: PUBLISH_CAP, arweave: PUBLISH_CAP }
const capOf = (d: Exclude<Dest, 'sol'>): number => {
  const cap = Object.hasOwn(CAPS, d) ? CAPS[d] : undefined
  // planE6 M-5: never an uncapped build
  if (typeof cap !== 'number') refuse('published.dest', `unknown publish destination: ${String(d)}`) // @guard:published.dest
  return cap
}

export function buildPublished(
  a: { arId: string; unlock: string; note: string },
  sealedFull: string,
  sealedKeyOnly: string,
  dest: Dest,
): Published {
  const env = buildEnvelope(a)
  const fu = UNLOCK_LINE.exec(sealedFull)?.[1]
  const ku = UNLOCK_LINE.exec(sealedKeyOnly)?.[1]
  if (fu !== a.unlock || ku !== a.unlock) refuse('published.unlock-mismatch', 'envelope unlock differs from the sealed text unlock-after') // @guard:published.unlock-mismatch
  const fullOk = /^contents: full$/m.test(sealedFull)
  const keyOk = sealedKeyOnly.split('\n').includes(`contents: key-only (payload: ar://${a.arId})`)
  if (!fullOk || !keyOk) refuse('published.sealed-form', 'sealed texts are not the expected full / key-only forms for this ar id') // @guard:published.sealed-form

  const body = (sealed: string) => utf8(`\n\n${sealed}`)
  const join = concat

  // One rule for every destination that carries the text: `full` if it fits `cap`, else `key-only`,
  // else refuse.
  const pick = (prefix: Uint8Array, cap: number): { bytes: Uint8Array; contents: 'full' | 'key-only' } => {
    const full = join(prefix, env.bytes, body(sealedFull))
    if (full.length <= cap) return { bytes: full, contents: 'full' }
    const key = join(prefix, env.bytes, body(sealedKeyOnly))
    if (key.length > cap) refuse('published.too-long', `published text exceeds ${cap} bytes even as key-only`) // @guard:published.too-long
    return { bytes: key, contents: 'key-only' }
  }

  if (dest === 'sol') {
    // R41: the pointer names the no-prefix 98,304 B text of this publication (what Base, Bitcoin and the
    // Arweave item carry). If not even key-only fits, those destinations refuse, and so does Solana.
    const carried = pick(new Uint8Array(0), PUBLISH_CAP)
    const memo = join(env.bytes, utf8(`\nsha256:${sha(carried.bytes)}`))
    if (memo.length > SOL_MEMO_MAX) refuse('published.sol-too-long', `solana memo exceeds ${SOL_MEMO_MAX} bytes`) // @guard:published.sol-too-long
    return { bytes: memo, contents: 'none', sha256: sha(memo) }
  }

  const p = pick(dest === 'eth' ? utf8(ETH_PREFIX) : new Uint8Array(0), capOf(dest))
  return { bytes: p.bytes, contents: p.contents, sha256: sha(p.bytes) }
}

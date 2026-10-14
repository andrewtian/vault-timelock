// packages/core/src/job/events.ts — validateEvent(type, data, by) (spec §5.3). The API runs it on every journal line it
// writes; an executor posts only {gen, type, data} and the API sets `by` to the lease holder, so an executor can never
// write an API event (event.by).
//   event.type   type is not a journal event type (prototype names included)
//   event.by     API types: by api or operator; executor types: by browser or cli (the lease holder); stopped and
//                note: any of the four
//   event.shape  data is not exactly the type's members: no extra, none missing, every value in its exact format.
//                Free text (reasons, details, sources) <= 512 characters, note.text <= 200; base-unit amounts and block
//                numbers are decimal strings (no sign, no leading zero, <= 78 digits); ids are exact (eth tx 0x + 64
//                lowercase hex, sol signature canonical base58 of 64 bytes, sha256 64 lowercase hex). intent and
//                clawback-intent carry exactly one of eth / sol. armed is a full ArmRecord: releaseAt = armedAt +
//                countdownSec * 1000, order a non-empty list of distinct chains, offsetSec over exactly those chains
//                with the first at 0, caps over exactly those chains, sources a subset.
import { base58 } from '@scure/base'
import { COUNTDOWN_RANGE_S, MESSAGE_MAX, STOP_CODE_LIST, refuse } from '../contracts/index.ts'
import type { ApiEventType, ExecEventType } from '../contracts/index.ts'

type Obj = Record<string, unknown>
type Check = (v: unknown) => boolean

function plain(v: unknown): v is Obj {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false
  const p: unknown = Object.getPrototypeOf(v)
  return p === Object.prototype || p === null
}
const str = (max: number): Check => (v) => typeof v === 'string' && v.length <= max
const text = str(512)
const int = (min: number, max: number = Number.MAX_SAFE_INTEGER): Check => (v) => typeof v === 'number' && Number.isSafeInteger(v) && v >= min && v <= max
const bool: Check = (v) => typeof v === 'boolean'
const re = (r: RegExp): Check => (v) => typeof v === 'string' && r.test(v)
const oneOf = (...xs: readonly unknown[]): Check => (v) => xs.includes(v)
const nullable = (f: Check): Check => (v) => v === null || f(v)
const B58 = /^[1-9A-HJ-NP-Za-km-z]+$/
const b58bytes = (n: number): Check => (v) => {
  if (typeof v !== 'string' || v.length > 90 || !B58.test(v)) return false
  try { const b = base58.decode(v); return b.length === n && base58.encode(b) === v } catch { return false }
}

const dec = re(/^(?:0|[1-9][0-9]{0,77})$/) // base units (wei, lamports), gas, block numbers
const hex64 = re(/^[0-9a-f]{64}$/)
const ethTx = re(/^0x[0-9a-f]{64}$/)
const solSig = b58bytes(64)
const btcTx = hex64                                                  // E7: a bitcoin txid (64 lowercase hex, the id Core / Esplora / ord show)
const txId: Check = (v) => ethTx(v) || solSig(v) || btcTx(v)
const ethAddress = re(/^0x[0-9a-fA-F]{40}$/)
const btcAddress = re(/^(?:bcrt|tb|bc)1[02-9ac-hj-np-z]{11,87}$/)    // E7: lower-case bech32 / bech32m of a network (the checksum is the relay's)
const address: Check = (v) => ethAddress(v) || b58bytes(32)(v) || btcAddress(v)
const CHAIN_IDS = ['eth', 'sol', 'btc'] as const
const chain = oneOf(...CHAIN_IDS)
const gwei = re(/^(?:0|[1-9][0-9]{0,5})(?:\.[0-9]{1,9})?$/)
const amount = re(/^[0-9]{1,40}(?:\.[0-9]{1,40})?$/) // a formatted native amount, e.g. "0.004"
const usd: Check = (v) => typeof v === 'number' && Number.isFinite(v) && v >= 0
const seconds = int(0, 86_400)

// Exactly the members of req (all present) plus any of opt, each passing its check, then the cross-member rule.
function obj(req: Readonly<Record<string, Check>>, opt: Readonly<Record<string, Check>> = {}, rule?: (d: Obj) => boolean): Check {
  return (v) => {
    if (!plain(v)) return false
    for (const k of Object.keys(v)) if (!Object.hasOwn(req, k) && !Object.hasOwn(opt, k)) return false
    for (const k of Object.keys(req)) if (!Object.hasOwn(v, k) || !req[k](v[k])) return false
    for (const k of Object.keys(opt)) if (Object.hasOwn(v, k) && !opt[k](v[k])) return false
    return rule === undefined || rule(v)
  }
}
const sameKeys = (o: Obj, keys: readonly unknown[]): boolean => Object.keys(o).length === keys.length && keys.every((k) => typeof k === 'string' && Object.hasOwn(o, k))

const ethIntent = obj({ nonce: int(0), tip: dec, maxFee: dec, gas: dec, to: ethAddress })
const solIntent = obj({ blockhash: b58bytes(32), lastValidBlockHeight: int(0), cuPrice: int(0), cuLimit: int(1, 1_400_000), rung: nullable(int(0, 1_000)), fee: dec })
// E7 (CC-8): the BTC intent. commit: the lane pubkey, its fee, the value locked in the commit output, 1..8 outpoints in strictly
// ascending order; reveal: the lane pubkey, its fee and the vout of the commit output it spends. The API mints the ticket from
// these and from values it computes itself (api/src/tickets.ts btcBinding), never from the rest.
const outpoint = re(/^[0-9a-f]{64}:(?:0|[1-9][0-9]{0,9})$/)
const btcIntent: Check = (v) => {
  if (!plain(v)) return false
  const pubkey = re(/^0[23][0-9a-f]{64}$/), fee = re(/^[1-9][0-9]{0,77}$/)
  if (v.kind === 'commit') {
    return sameKeys(v, ['kind', 'pubkey', 'fee', 'value', 'inputs']) && pubkey(v.pubkey) && fee(v.fee) && fee(v.value)
      && Array.isArray(v.inputs) && v.inputs.length >= 1 && v.inputs.length <= 8 && v.inputs.every((x, i, a) => outpoint(x) && (i === 0 || (a[i - 1] as string) < (x as string)))
  }
  return v.kind === 'reveal' && sameKeys(v, ['kind', 'pubkey', 'fee', 'commitVout']) && pubkey(v.pubkey) && fee(v.fee) && int(0, 999_999_999)(v.commitVout)
}
const oneIntent = (d: Obj): boolean => ['eth', 'sol', 'btc'].filter((k) => Object.hasOwn(d, k)).length === 1

// The cap the engine enforces at every signature (spec §5.4). Shared with checkArmConfirm.
export const isArmCap = obj({ nativeCap: dec, usd, priceAt: nullable(int(0)), overCap: bool, planned: amount })

const isArmRecord = obj(
  { armedAt: int(0), releaseAt: int(0), countdownSec: int(COUNTDOWN_RANGE_S[0], COUNTDOWN_RANGE_S[1]), schedule: obj({ order: Array.isArray, offsetSec: plain }), caps: plain, sources: plain },
  {},
  (d) => {
    const s = d.schedule as { order: unknown[]; offsetSec: Obj }
    const order = s.order
    const caps = d.caps as Obj, sources = d.sources as Obj
    return d.releaseAt === (d.armedAt as number) + (d.countdownSec as number) * 1000
      && order.length >= 1 && order.every(chain) && new Set(order).size === order.length
      && sameKeys(s.offsetSec, order) && s.offsetSec[order[0] as string] === 0 && order.every((c) => seconds(s.offsetSec[c as string]))
      && sameKeys(caps, order) && order.every((c) => isArmCap(caps[c as string]))
      && Object.keys(sources).every((c) => order.includes(c) && text(sources[c]))
  },
)

const API_BY = ['api', 'operator'] as const
const EXEC_BY = ['browser', 'cli'] as const
const ANY_BY = [...API_BY, ...EXEC_BY] as const
interface Spec { readonly by: readonly string[]; readonly data: Check }
const api = (data: Check): Spec => ({ by: API_BY, data })
const ex = (data: Check): Spec => ({ by: EXEC_BY, data })

const SPECS: Readonly<Record<ApiEventType | ExecEventType, Spec>> = {
  // written by the API
  created: api(obj({ jobId: re(/^[0-9a-f]{16}$/), defSha256: hex64 })),
  armed: api(isArmRecord),
  skip: api(obj({ releaseAt: int(0) })),
  'stop-requested': api(obj({ chain: nullable(chain) })),
  'resume-requested': api(obj({ chain: nullable(chain) }, { tipCapGwei: gwei, cuPriceCap: int(0, 2_000_000) })),
  close: api(obj({ chain })),
  resolved: api(obj({ txId, action: oneOf('mark-done', 'mark-failed'), typed: nullable(str(64)) })),
  'lease-acquired': api(obj({ gen: int(1), holder: oneOf(...EXEC_BY), ttlMs: int(1) })),
  'lease-released': api(obj({ gen: int(1) })),
  'lease-expired': api(obj({ gen: int(1) })),
  // written by either
  stopped: { by: ANY_BY, data: obj({ reason: text }, { delegated: oneOf(true), code: oneOf(...STOP_CODE_LIST) }) },   // Eminors: delegated — the EIP-7702 stop, structured; R79b: code (contracts/stop.ts; optional only for old journals)
  note: { by: ANY_BY, data: obj({ text: str(200) }) },
  // written by the executor holding the lease
  'key-loaded': ex(obj({ address })),
  funds: ex(obj({ balance: dec, affordable: bool, nextCopyCost: dec })),
  reconcile: ex(obj({ txId, outcome: oneOf('included', 'expired', 'nonce-consumed', 'adopted') }, { block: dec, fee: dec })),
  'copy-built': ex(obj({ copy: int(1), parts: int(1, MESSAGE_MAX), bytes: Array.isArray, tight: bool, level: int(0, 1_000) }, {},
    (d) => (d.bytes as unknown[]).length === d.parts && (d.bytes as unknown[]).every(int(1, MESSAGE_MAX)))),
  intent: ex(obj(
    { txId, copy: int(1), part: int(1), parts: int(1, MESSAGE_MAX), attempt: int(1), replaces: nullable(txId), rawSha256: hex64, payloadSha256: hex64, reserved: dec },
    { eth: ethIntent, sol: solIntent, btc: btcIntent },
    (d) => oneIntent(d) && (d.part as number) <= (d.parts as number) && d.replaces !== d.txId,
  )),
  sent: ex(obj({ txId, outcome: oneOf('accepted', 'unknown', 'rejected'), reason: nullable(text) })),
  replaced: ex(obj({ txId, prevId: txId, reason: text })),
  included: ex(obj({ txId, copy: int(1), part: int(1), attempt: int(1), block: dec, fee: dec, ms: int(0) })),
  readback: ex(obj({ txId, ok: bool, detail: text })),
  paused: ex(obj({ reason: text })),
  resumed: ex(obj({ reason: text })),
  drained: ex(obj({ balance: dec, nextCost: dec, copy: int(1) })),
  'copies-done': ex(obj({ copies: int(1, 10_000) })),
  'clawback-intent': ex(obj({ txId, to: address, value: dec, rawSha256: hex64 }, { eth: ethIntent, sol: solIntent }, oneIntent)),
  'clawback-sent': ex(obj({ txId, outcome: oneOf('accepted', 'unknown', 'rejected') })),
  'clawback-included': ex(obj({ txId, value: dec, fee: dec })),
  'clawback-readback': ex(obj({ txId, ok: bool, destReceived: dec, laneBalance: dec })),
  'clawback-failed': ex(obj({ txId, reason: text }, { fee: dec })),   // fee: charged when the claw-back failed ON CHAIN (security review)
  stuck: ex(obj({ txId, reason: text })),
  reassembled: ex(obj({ copy: int(1), ok: bool, sha256: hex64 })),
}

export function validateEvent(type: string, data: unknown, by: string): void {
  const spec = typeof type === 'string' && Object.hasOwn(SPECS, type) ? SPECS[type as keyof typeof SPECS] : undefined
  if (spec === undefined) refuse('event.type', 'not a journal event type') // @guard:event.type
  const byOk = spec.by.includes(by)
  if (!byOk) refuse('event.by', `a ${type} event is written only by ${spec.by.join(' or ')}`) // @guard:event.by
  const shapeOk = spec.data(data)
  if (!shapeOk) refuse('event.shape', `${type}: data must be exactly the event's members, each in its exact format (free text <= 512 characters, note text <= 200)`) // @guard:event.shape
}

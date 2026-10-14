// api/src/bodycheck.ts — spec §5.1 "Strings in bodies": every string in a JSON request body (member values and member
// names, at any depth) goes through core's assertNoSecretOrIp, with core's ids mapped to the API's (E1 ruling 3):
//   job.ip-like  → api.ip-like    an IPv4 or IPv6 literal (loopback included), bare or as a URL host;
//   job.key-like → api.key-like   64+ hex, a 64-byte base58 run or byte array, an age key, a BIP-39 phrase, a URL, an
//                                 onion host (and, fail closed, any other refusal of the scan).
// Fields are classified exactly as contracts/http.ts says:
//   · TYPED_ID_FIELDS (txId, prevId, rawSha256, payloadSha256, blockhash, sha256, replaces, messageSha256, pubkey, inputs): a string
//     value under one of these names, at any depth, is skipped when it has the shape of THAT field's id (S2 review m6): a txId /
//     prevId / replaces is 0x + 64 lowercase hex (eth), 64 lowercase hex (btc) or one base58 run of 64..88 (sol); a digest field
//     is 64 lowercase hex; a blockhash is one base58 run of 32..44; a pubkey is 33 bytes in 66 hex (CC-8); an `inputs` element
//     is a `<txid>:<vout>` outpoint (the elements of an `inputs` array count as values under `inputs`). Any other value under
//     those names is scanned like every string. validateEvent / normalizeJob then check each id's exact format.
//   · MESSAGE_TEXT_FIELDS (message): the top-level string member of a POST /jobs body is publication text (`messageText`).
//     validateMessage (inside normalizeJob) governs it; it is never scanned here. On any other route it is scanned like
//     every string.
// The walk is iterative (an explicit stack), so a deeply nested body cannot overflow the call stack. Nothing echoes the
// value that was looked at; a field label is echoed only as core's labelOf allows (a plain dotted path).
import { MESSAGE_TEXT_FIELDS, TYPED_ID_FIELDS, isRefusal } from '@vault-timelock/core/contracts'
import { assertNoSecretOrIp } from '@vault-timelock/core/job'
import { refuse } from 'vt-broadcast/src/guard.ts'

const TYPED: ReadonlySet<string> = new Set<string>(TYPED_ID_FIELDS)
const MESSAGE: ReadonlySet<string> = new Set<string>(MESSAGE_TEXT_FIELDS)
const TX_ID = /^(?:0x[0-9a-f]{64}|[0-9a-f]{64}|[1-9A-HJ-NP-Za-km-z]{64,88})$/   // eth | btc | sol
const DIGEST = /^[0-9a-f]{64}$/
const FIELD_SHAPE: Readonly<Record<(typeof TYPED_ID_FIELDS)[number], RegExp>> = {
  txId: TX_ID, prevId: TX_ID, replaces: TX_ID,
  rawSha256: DIGEST, payloadSha256: DIGEST, sha256: DIGEST, messageSha256: DIGEST,
  blockhash: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/,
  pubkey: /^0[23][0-9a-f]{64}$/,                                                     // CC-8: a compressed btc key
  inputs: /^[0-9a-f]{64}:(?:0|[1-9][0-9]{0,9})$/,                                    // CC-8: a btc outpoint
}

// One string: the scan, then the API's refusal for what it found (the IP check first, as in core).
function scan(s: string, label: string): void {
  let found: string | null = null
  try {
    assertNoSecretOrIp(s, label)
  } catch (e) {
    found = isRefusal(e) ? e.guardId : 'error'
  }
  const noIp = found !== 'job.ip-like'
  if (!noIp) refuse('api.ip-like', `${label === '' ? 'the body' : 'a body field'} holds an IP address literal (the value is not echoed)`) // @guard:api.ip-like
  const noKey = found === null
  if (!noKey) refuse('api.key-like', `${label === '' ? 'the body' : 'a body field'} looks like a key or secret, a URL or an onion host (the value is not echoed)`) // @guard:api.key-like
}

// True when `key` (a member of an object `depth` levels down) holding the string `value` is exempt from the scan.
// `messageText`: this body is a POST /jobs body, whose top-level `message` is publication text.
export function exempt(key: string, value: string, depth: number, messageText = false): boolean {
  if (messageText && depth === 0 && MESSAGE.has(key)) return true
  return TYPED.has(key) && FIELD_SHAPE[key as keyof typeof FIELD_SHAPE].test(value)
}

export function bodycheck(body: unknown, o: { messageText?: boolean } = {}): void {
  const messageText = o.messageText === true
  const stack: Array<{ v: unknown; key: string | null; path: string; depth: number }> = [{ v: body, key: null, path: '', depth: -1 }]
  while (stack.length > 0) {
    const { v, key, path, depth } = stack.pop()!
    if (typeof v === 'string') {
      if (key === null || !exempt(key, v, depth, messageText)) scan(v, path)
    } else if (Array.isArray(v)) {
      for (let i = v.length - 1; i >= 0; i--) stack.push({ v: v[i], key: key === 'inputs' ? 'inputs' : null, path, depth: depth + 1 })
    } else if (v !== null && typeof v === 'object') {
      const o = v as Record<string, unknown>
      const keys = Object.keys(o)
      for (let i = keys.length - 1; i >= 0; i--) {
        const k = keys[i]
        const p = path === '' ? k : `${path}.${k}`
        scan(k, p)
        stack.push({ v: o[k], key: k, path: p, depth: depth + 1 })
      }
    }
  }
}

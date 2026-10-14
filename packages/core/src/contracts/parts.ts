// packages/core/src/contracts/parts.ts — the R72 part header. THE ONLY PLACE ITS BYTES ARE DEFINED. The planner
// (packages/core/src/chains/plan.js, E2), the reassembler and the "by hand" instructions call these functions; a
// format change edits this file, bumps PART_FORMAT and regenerates contract/fixtures/parts/headers.json.
//
// vt-parts/1 (final; research-long-messages.md §7.2, controller rulings 2026-10-09):
//   N = 1, copy 1 or no marker:   <text>                                   (no header)
//   N = 1, copies 2..M:           [copy c/M]\n<text>                       (drain, M unknown: [copy c]\n<text>)
//   N = 1, forced (CC-1a):        [1/1 <h8> sha256=<64hex>]\n<text>        (+ ' [copy c/M]' inside the line for c >= 2)
//     The WRITER forces this header when the one-part text's own first line would parse as a header (Task 0 ruling on
//     concern 3), so a reader never takes user text for a header. partPrefix(h, { force: true }) writes it.
//   part 1 of N (N ≥ 2):          [1/N <h8> sha256=<64 lowercase hex>]\n<chunk>
//   part k of N (2 ≤ k ≤ N):      [k/N <h8>]\n<chunk>
//   copies 2..M, N ≥ 2:           the marker inside the header line: [k/N <h8>] [copy c/M]\n<chunk>
//                                 (part 1: [1/N <h8> sha256=<64hex>] [copy c/M]\n<chunk>)
//   h8 = the first 8 lowercase hex chars of sha256(UTF-8 of the full text); k, N, c, M decimal, no leading zeros.
//   Copy 1 never carries a marker; with distinctCopies off no copy does. The header line always ends with LF, so the
//   first line never carries chunk text (the Ethscriptions DataUri base64 check then never sees user text), and it
//   holds no '#' (a data-URL fragment delimiter) and no ','. On ETH the payload is 'data:,' + header + chunk.
// Reader rules (whoever reassembles; the hashing lives with the caller):
//   1. accept parts only from the publishing address (ETH: from = the key, to = 0x0 or the key; SOL: fee payer);
//   2. group by (sender, h8, N, copy); strip exactly the header line (parsePart);
//   3. concatenate in k order; refuse a missing k or two different payloads for one k;
//   4. check sha256(result) = part 1's digest and h8 = digest[0:8];
//   5. read raw calldata / memo bytes, never an indexer's decoded `content` (percent-decoding differs per part).
//   6. a one-part header ([1/1 <h8> sha256=<64hex>]) counts only when sha256(UTF-8 of the body) equals it; otherwise
//      the payload is plain text. Without a header a one-part text is plain text, as before (CC-1a).
export const PART_FORMAT = 'vt-parts/1'

export interface PartHeaderInput {
  part: number            // k, 1..parts
  parts: number           // N ≥ 1
  sha256: string          // 64 lowercase hex: sha256 of the full text's UTF-8
  copy: number | null     // the copy index when distinct copies are on, else null; copy 1 gets no marker
  copies: number | null   // M in copies mode; null in drain mode (M unknown)
}

import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'

const HEX64 = /^[0-9a-f]{64}$/
const isCount = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 1

export function h8(sha256: string): string {
  if (!HEX64.test(sha256)) throw new RangeError('sha256 must be 64 lowercase hex')
  return sha256.slice(0, 8)
}

function marker(copy: number | null, copies: number | null): string {
  if (copy === null || copy < 2) return ''
  return copies === null ? `[copy ${copy}]` : `[copy ${copy}/${copies}]`
}

// The bytes that precede the chunk ('' when there are none). ASCII only, so its UTF-8 length is its .length.
// o.force (CC-1a): for N = 1, write the explicit one-part header [1/1 <h8> sha256=<64hex>] (marker inside the line);
// for N >= 2 a header is always written, so force changes nothing.
export interface PartPrefixOptions { force?: boolean }
export function partPrefix(h: PartHeaderInput, o: PartPrefixOptions = {}): string {
  if (!isCount(h.parts) || !isCount(h.part) || h.part > h.parts) throw new RangeError('part must be 1..parts')
  if (!HEX64.test(h.sha256)) throw new RangeError('sha256 must be 64 lowercase hex')
  if (h.copy !== null && !isCount(h.copy)) throw new RangeError('copy must be null or ≥ 1')
  if (h.copies !== null && (!isCount(h.copies) || (h.copy !== null && h.copies < h.copy))) throw new RangeError('copies must be null or ≥ copy')
  const m = marker(h.copy, h.copies)
  if (h.parts === 1 && o.force !== true) return m === '' ? '' : `${m}\n`
  const head = h.part === 1 ? `[1/${h.parts} ${h8(h.sha256)} sha256=${h.sha256}]` : `[${h.part}/${h.parts} ${h8(h.sha256)}]`
  return `${head}${m === '' ? '' : ` ${m}`}\n`
}

export interface ParsedPart {
  part: number; parts: number
  h8: string | null       // null for N = 1
  sha256: string | null   // part 1 of N ≥ 2 only
  copy: number            // 1 when no marker
  copies: number | null
  headerLength: number    // characters (= UTF-8 bytes) stripped before the chunk
  body: string            // the chunk (or the whole text when there is no header)
}

const verifies = (body: string, sha: string): boolean => bytesToHex(sha256(new TextEncoder().encode(body))) === sha
const MULTI = /^\[([1-9][0-9]{0,8})\/([1-9][0-9]{0,8}) ([0-9a-f]{8})(?: sha256=([0-9a-f]{64}))?\](?: \[copy ([1-9][0-9]{0,8})(?:\/([1-9][0-9]{0,8}))?\])?\n/
const SINGLE = /^\[copy ([1-9][0-9]{0,8})(?:\/([1-9][0-9]{0,8}))?\]\n/

// Splits one payload (ETH: after stripping 'data:,') into header fields and chunk. A first line that does not match
// the grammar exactly, with every cross-field rule, means "no header": the whole payload is the text. N = 1 in the
// header form is accepted only when the body's sha256 verifies (reader rule 6).
export function parsePart(payload: string): ParsedPart {
  const none: ParsedPart = { part: 1, parts: 1, h8: null, sha256: null, copy: 1, copies: null, headerLength: 0, body: payload }
  const m = MULTI.exec(payload)
  if (m !== null) {
    const k = Number(m[1]), n = Number(m[2]), sha = m[4] ?? null
    const copy = m[5] === undefined ? 1 : Number(m[5]), copies = m[6] === undefined ? null : Number(m[6])
    const ok = k <= n && (k === 1) === (sha !== null) && (sha === null || sha.startsWith(m[3]))
      && (m[5] === undefined || copy >= 2) && (copies === null || copies >= copy)
      && (n >= 2 || (sha !== null && verifies(payload.slice(m[0].length), sha)))
    if (!ok) return none
    return { part: k, parts: n, h8: m[3], sha256: sha, copy, copies, headerLength: m[0].length, body: payload.slice(m[0].length) }
  }
  const s = SINGLE.exec(payload)
  if (s !== null) {
    const copy = Number(s[1]), copies = s[2] === undefined ? null : Number(s[2])
    if (copy < 2 || (copies !== null && copies < copy)) return none
    return { part: 1, parts: 1, h8: null, sha256: null, copy, copies, headerLength: s[0].length, body: payload.slice(s[0].length) }
  }
  return none
}

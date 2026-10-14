// @ts-check
// PORTED (R69) from the prototype, tag add7-00927d6ade7f, src/mainnet/text.js (sha256 2a119ac97d44d9c0e0e2a60eabf33950820e165e364ee99c40bacdf3d40ca610).
// Plain-text mode (R50): the operator types into an EMPTY field. Refused, never rewritten.
// Per chain the text becomes as few transactions as possible, each as large as possible (plan.js).
import { ETH, PLAN, SOL } from './constants.js'
import { ethParts, solParts, utf8 } from './plan.js'
import { layoutMaxMemo } from './sol.js'
// C0 controls except LF, DEL, C1 (incl. NEL), ALM, LRM/RLM, LS/PS, bidi embeddings/overrides/isolates, BOM/ZWNBSP
const BAD = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]/u
export const hex = (/** @type {Uint8Array} */ b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
export const preview = (/** @type {Uint8Array} */ b) => (b.length <= 64 ? hex(b) : `${hex(b.slice(0, 32))} … ${hex(b.slice(-32))}`)
/** @typedef {import('./types.ts').Part} Part */
/** @param {string} text @param {{ cuPrice?: number }} [_o] */
export function checkText(text, { cuPrice = 0 } = {}) {
  const issues = []
  if (!text) issues.push('empty — type the text to publish')
  if (text && typeof text.isWellFormed === 'function' && !text.isWellFormed()) issues.push('contains an unpaired surrogate (not valid Unicode)')
  if (text.includes('\r')) issues.push('CR found — LF line breaks only')
  if (BAD.test(text.replace(/\r/g, ''))) issues.push('control or bidi characters are not allowed (only LF line breaks)')
  if (text !== text.normalize('NFC')) issues.push('not NFC-normalized (refused, never rewritten)')
  const bytes = utf8(text), solMax = layoutMaxMemo()
  /** @type {Record<'eth' | 'sol', { ok: boolean, parts: Part[], maxPart?: number, why: string }>} */
  const per = /** @type {any} */ ({})
  for (const [c, f] of /** @type {Array<['eth' | 'sol', () => Part[]]>} */ ([['eth', () => ethParts(bytes)], ['sol', () => solParts(bytes, solMax)]])) {
    try { const parts = f(); per[c] = { ok: true, parts, maxPart: c === 'eth' ? ETH.TX_DATA_CAP : solMax, why: '' } }
    catch (e) { per[c] = { ok: false, parts: [], why: /** @type {Error} */ (e).message } }
  }
  return { ok: issues.length === 0, issues, per, text, bytes, ethBytes: utf8(ETH.PREFIX + text), solMax }
}
export const MAX_TXS = PLAN.MAX_TXS_PER_CHAIN
// Canonical (E2): the part preview of a validated message, per chain — the shape of W2's temporary web/src/ported
// previewParts (web/src/lib/core.js): { eth|sol: { ok, parts: [{ i, n, header, start, end, size }], max, why } }, where
// header = header bytes, start/end = the chunk's byte range in the text, size = payload bytes (lead + header + chunk).
// The planner is the engine's (R72 header, writer rule); copy 1, so no copy marker.
/** @param {string} text @param {string} [sha256] */
export function previewParts(text, sha256) {
  const bytes = utf8(text), solMax = layoutMaxMemo()
  /** @type {Record<'eth' | 'sol', { ok: boolean, parts: Array<{ i: number, n: number, header: number, start: number, end: number, size: number }>, max: number, why: string }>} */
  const out = /** @type {any} */ ({})
  for (const [chain, run, max, lead] of /** @type {Array<['eth' | 'sol', () => Part[], number, number]>} */ ([
    ['eth', () => ethParts(bytes, { sha256 }), ETH.TX_DATA_CAP, utf8(ETH.PREFIX).length],
    ['sol', () => solParts(bytes, solMax, { sha256 }), Math.min(SOL.MEMO_MAX, solMax), 0],
  ])) {
    try {
      let off = 0
      const parts = run().map((p) => { const start = off; off += p.chunk.length; return { i: p.i, n: p.n, header: p.payload.length - lead - p.chunk.length, start, end: off, size: p.payload.length } })
      out[chain] = { ok: true, parts, max, why: '' }
    } catch (e) { out[chain] = { ok: false, parts: [], max, why: /** @type {Error} */ (e).message } }
  }
  return out
}

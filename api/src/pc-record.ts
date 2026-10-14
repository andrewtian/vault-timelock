// api/src/pc-record.ts — the ONE record format of both Privacy Cash ledgers (Sfix-PC fix round 1, review I-1): the relay's
// privacycash-withdrawals.jsonl and the API's privacycash-lane-mints.jsonl.
//   · one validator per ledger, used BEFORE a line is written and again when it is read, so the writer can never produce a
//     line the reader rejects (the I-1 parser differential);
//   · a line is canonical JSON in a fixed key order followed by a checksum member "c" (first 16 hex of sha256 of the
//     record without "c"), printable ASCII only, no newline inside;
//   · read: a line without its trailing newline is a TORN tail (a crash or short write mid-append). Nothing is acknowledged
//     before its fsync, so a torn tail was never acknowledged and is cut off: it cannot under-count. Any other bad line (bad
//     JSON, bad checksum, failed validator) is corruption and refuses the ledger.
//   · createDirEntry: the directory is fsynced when a ledger file is created, so the entry cannot be lost with the first line.
import { createHash } from 'node:crypto'
import { closeSync, constants, fsyncSync, openSync } from 'node:fs'

// The encrypted outputs of a withdrawal: 36..200 bytes (72..400 hex chars). One definition for the request bounds, the
// /utxos/check and /utxos/indices routes, and the ledger.
export const ENC_MIN_BYTES = 36
export const ENC_MAX_BYTES = 200
export const ENC_HEX_RE = /^[0-9a-f]{72,400}$/

export type Rec = Record<string, unknown>
const PRINTABLE = /^[\x20-\x7e]+$/

const sum = (body: string): string => createHash('sha256').update(body).digest('hex').slice(0, 16)

// The line (with its newline) for a record whose keys are in their fixed order; null when it cannot be written safely.
export function encodeLine(rec: Rec): string | null {
  if (Object.hasOwn(rec, 'c')) return null
  let body: string
  try { body = JSON.stringify(rec) } catch { return null }
  if (typeof body !== 'string') return null
  const line = `${body.slice(0, -1)},"c":"${sum(body)}"}`
  return PRINTABLE.test(line) ? `${line}\n` : null
}

export type Decoded = { ok: true; rec: Rec } | { ok: false }
export function decodeLine(line: string): Decoded {
  if (!PRINTABLE.test(line)) return { ok: false }
  let o: unknown
  try { o = JSON.parse(line) } catch { return { ok: false } }
  if (typeof o !== 'object' || o === null || Array.isArray(o)) return { ok: false }
  const rec = { ...(o as Rec) }
  const c = rec.c
  delete rec.c
  if (typeof c !== 'string' || !/^[0-9a-f]{16}$/.test(c)) return { ok: false }
  // the checksum is over the canonical re-encoding of the record without "c" (the key order of the line itself)
  return sum(JSON.stringify(rec)) === c && `${JSON.stringify(rec).slice(0, -1)},"c":"${c}"}` === line ? { ok: true, rec } : { ok: false }
}

// Splits a ledger file's text: the complete lines, and whether a torn tail (text after the last newline) was found.
export function splitLedger(text: string): { lines: string[]; tornAt: number | null } {
  const cut = text.lastIndexOf('\n') + 1
  const lines = text.slice(0, cut).split('\n').filter((l) => l !== '')
  return { lines, tornAt: cut < text.length ? cut : null }
}

// fsync of a directory (the entry of a newly created ledger file). Throws on failure.
export function syncDir(dir: string): void {
  const fd = openSync(dir, constants.O_RDONLY | constants.O_DIRECTORY)
  try { fsyncSync(fd) } finally { closeSync(fd) }
}

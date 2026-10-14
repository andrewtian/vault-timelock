// cli/src/job/validate.ts — reading a vt-job/1 file (spec §4.1; plan Task C5) and `vt job validate <file>`.
//
// The message comes from exactly one source:
//   --message-file <path>                              ON THE COMMAND LINE ONLY (security review): vt reads the file
//                                                      itself, after the path checks of message-file.ts (realpath,
//                                                      regular file, the denylist of keys, vault data and state). A
//                                                      job JSON never names a file: `messageFile` there is refused
//                                                      (vt.message-path);
//   "message": "<inline text>"                         the text, in the job JSON;
//   "messageSha256": "<64 hex>", "messageBytes": n     a text already uploaded (the canonical form).
// The text is never put in argv: vt is given a path, reads the bytes itself, and uploads them by digest (create.ts),
// after the operator confirmed that file for publication (create.ts: typed `publish`, or --yes-publish-file <sha256>).
//
// ★ The bytes are decoded with the FATAL decoder (TextDecoder('utf-8', { fatal: true, ignoreBOM: true }); Task 0
//   ruling 7), so an undecodable byte is refused (message.utf8), never replaced, and a BOM is kept (and then refused
//   by validateMessage, message.control). The text is then checked by core validateMessage inside normalizeJob
//   (message.*: refused, NEVER rewritten). What is uploaded is the file's own bytes, unchanged: their sha256 and size
//   must be the canonical definition's (message.digest otherwise).
// ★ --normalize (E1 ruling 4: the operator's explicit action, never a default) is the only rewrite: CRLF and a lone CR
//   become LF, and each TAB becomes spaces to the next tab stop (every 8 columns, counted in code points, as
//   expand(1)). Nothing else changes (NFC, BOM, other controls stay refused). It prints a summary of what it changed,
//   and the uploaded text (and so the job id) is then the normalized one. The file itself is never written (the client
//   sandbox allows no file writes anyway).
import type { JobDef, Network } from '@vault-timelock/core/contracts'
import { MESSAGE_MAX, refuse } from '@vault-timelock/core/contracts'
import { jobId, normalizeJob, sha256Hex, validateMessage } from '@vault-timelock/core/job'
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs'
import { UsageError } from '../args.ts'
import type { Env } from '../ops/paths.ts'
import type { JobIo } from './client.ts'
import { emitJson, parseFlags, printLines } from './client.ts'
import { assertMessagePath, firstLine, readMessageFile } from './message-file.ts'

// A job file holds JSON; an inline message may be up to MESSAGE_MAX bytes, written with JSON escapes (\uXXXX: 6
// bytes per character at most).
export const JOB_FILE_MAX = 6 * MESSAGE_MAX + 64 * 1024
const FATAL = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
const enc = new TextEncoder()

// A regular file (followed through links: the operator names it): its size, and its bytes when the size is at most
// `cap` (null: over the cap, nothing read). null when it cannot be opened or is not a regular file (a FIFO would block;
// a directory has no text).
export function readFileBytes(path: string, cap: number): { size: number; bytes: Uint8Array | null } | null {
  let fd: number
  try { fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK) } catch { return null }
  try {
    const st = fstatSync(fd)
    if (!st.isFile()) return null
    if (st.size > cap) return { size: st.size, bytes: null }
    const buf = Buffer.alloc(st.size)
    let off = 0
    while (off < st.size) {
      const r = readSync(fd, buf, off, st.size - off, off)
      if (r === 0) break
      off += r
    }
    return { size: off, bytes: new Uint8Array(buf.buffer, buf.byteOffset, off) }
  } catch {
    return null
  } finally {
    closeSync(fd)
  }
}

// The text of message bytes, decoded strictly. message.utf8 when a byte sequence is not UTF-8 (nothing is replaced).
export function decodeMessage(bytes: Uint8Array): string {
  let text: string | null
  try { text = FATAL.decode(bytes) } catch { text = null }
  if (text === null) refuse('message.utf8', 'the message file is not valid UTF-8 (decoded strictly: an invalid byte is refused, never replaced); the text is not echoed') // @guard:message.utf8
  return text
}

export interface NormalizeSummary { crlf: number; cr: number; tabs: number; changed: boolean }

// --normalize: CRLF / CR -> LF, TAB -> spaces to the next multiple of 8 columns (code points since the line start).
export function normalizeText(text: string): { text: string; summary: NormalizeSummary } {
  let crlf = 0, cr = 0, tabs = 0
  const lf = text.replace(/\r\n?/g, (m) => { if (m.length === 2) crlf++; else cr++; return '\n' })
  const lines = lf.split('\n').map((line) => {
    if (!line.includes('\t')) return line
    let col = 0
    let out = ''
    for (const ch of line) {
      if (ch === '\t') {
        tabs++
        const n = 8 - (col % 8)
        out += ' '.repeat(n)
        col += n
      } else {
        out += ch
        col++
      }
    }
    return out
  })
  const result = lines.join('\n')
  return { text: result, summary: { crlf, cr, tabs, changed: crlf + cr + tabs > 0 } }
}

export function summaryLine(s: NormalizeSummary): string {
  if (!s.changed) return '--normalize: nothing to change (no CR and no TAB in the text)'
  const parts: string[] = []
  if (s.crlf > 0) parts.push(`${s.crlf} CRLF -> LF`)
  if (s.cr > 0) parts.push(`${s.cr} CR -> LF`)
  if (s.tabs > 0) parts.push(`${s.tabs} TAB -> spaces (tab stops every 8 columns)`)
  return `--normalize: ${parts.join(', ')}; the normalized text is what is checked and uploaded (the file is unchanged)`
}

export interface LoadedJob {
  def: JobDef
  id: string
  // The message bytes to upload, exactly (null: the file named an uploaded text by digest).
  bytes: Uint8Array | null
  normalized: NormalizeSummary | null
  warnings: string[]
  // --message-file: the real path read, the sha256 of the bytes read from its verified descriptor (message-file.ts),
  // and the first line of the text as shown to the operator.
  file: { path: string; sha256: string; firstLine: string } | null
}

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v)
const has = (o: Obj, k: string): boolean => Object.hasOwn(o, k) && o[k] !== undefined

// The one message.digest marker of this workspace: the bytes are exactly the text the definition names (here, and the
// upload's answer in create.ts).
export function assertDigest(ok: boolean, why: string): void {
  if (!ok) refuse('message.digest', why) // @guard:message.digest
}

function assertOneSource(ok: boolean): void {
  if (!ok) refuse('job.message-source', 'give exactly one message source: --message-file <path>, an inline message, or messageSha256 + messageBytes') // @guard:job.message-source
}

// Reads and checks a job file for `network`; the canonical definition, its id, and the exact bytes to upload.
// messageFile: the --message-file argument (the only way a file becomes the message); cwd resolves it.
export function loadJobFile(path: string, o: { network: Network; normalize: boolean; messageFile: string | null; env: Env; cwd: string }): LoadedJob {
  const raw = readFileBytes(path, JOB_FILE_MAX)
  if (raw === null) throw new UsageError('cannot read the job file (a regular file is needed)')
  if (raw.bytes === null) throw new UsageError(`the job file is over ${JOB_FILE_MAX} bytes`)
  let input: unknown
  try { input = JSON.parse(FATAL.decode(raw.bytes)) } catch { throw new UsageError('the job file is not one JSON value in UTF-8') }
  if (!isObj(input)) throw new UsageError('the job file is not a JSON object (vt-job/1)')
  // A job file never names a file to read (a job file can come from anyone; what is read is published).
  assertMessagePath(!Object.hasOwn(input, 'messageFile'), 'a job file may not name a message file (messageFile): give the file on the command line, --message-file <path>; nothing was read')

  // The message: --message-file (vt reads it), inline, or by digest.
  let text: string | null = null
  let bytes: Uint8Array | null = null
  let file: LoadedJob['file'] = null
  const job: Obj = { ...input }
  if (o.messageFile !== null) {
    assertOneSource(!has(job, 'message') && !has(job, 'messageSha256') && !has(job, 'messageBytes'))
    // Read ONCE from a verified descriptor (vt.message-path, vt.message-changed, vt.message-hardlink, message.too-long);
    // these bytes are decoded, checked, hashed, shown, confirmed and uploaded, and the path is never opened again.
    const f = readMessageFile(o.messageFile, { env: o.env, cwd: o.cwd })
    text = decodeMessage(f.bytes)
    bytes = f.bytes
    file = { path: f.path, sha256: f.sha256, firstLine: '' }
    job.message = text
  } else if (typeof job.message === 'string') {
    text = job.message
  }

  let normalized: NormalizeSummary | null = null
  if (o.normalize) {
    if (text === null) throw new UsageError('--normalize needs the message text (--message-file, or an inline message), not a digest')
    const n = normalizeText(text)
    normalized = n.summary
    if (n.summary.changed) {
      text = n.text
      bytes = null // the normalized text is uploaded, encoded below
      job.message = text
    }
  }

  const { def } = normalizeJob(job, { network: o.network }) // job.*, message.* (validateMessage), job.network
  const warnings: string[] = []
  if (text !== null) {
    bytes ??= enc.encode(text)
    // Never rewritten: the bytes uploaded are exactly the ones the canonical definition names.
    assertDigest(sha256Hex(bytes) === def.messageSha256 && bytes.length === def.messageBytes,
      'the message bytes do not hash to the definition\'s messageSha256 (they would have been rewritten); nothing is uploaded')
    // A file's bytes, unnormalized: the digest taken at the read is the definition's.
    if (file !== null && normalized?.changed !== true) assertDigest(file.sha256 === def.messageSha256, 'the message file\'s bytes are not the ones read from it; nothing is uploaded')
    if (validateMessage(text).warnings.includes('hex64')) warnings.push('the message holds a bare 64-hex token: if this is a private key, do not publish it')
  }
  return { def, id: jobId(def), bytes, normalized, warnings, file: file === null ? null : { ...file, firstLine: firstLine(text!) } }
}

export function describeDef(id: string, def: JobDef): string {
  const lines = [`job ${id}  ${def.network}  "${def.name}"`, `  message  sha256 ${def.messageSha256}  ${def.messageBytes} bytes`]
  for (const c of ['eth', 'sol', 'btc'] as const) {
    const ch = def.chains[c]
    if (ch === undefined) continue
    const mode = ch.mode === 'drain' ? 'drain' : `${ch.mode.copies} copies`
    const caps = c === 'eth' ? (ch.maxTipGwei !== undefined ? `  max tip ${ch.maxTipGwei} gwei` : '') : c === 'btc' ? (ch.maxFeeRateSatVb !== undefined ? `  max fee rate ${ch.maxFeeRateSatVb} sat/vB` : '') : (ch.maxCuPrice !== undefined ? `  max CU price ${ch.maxCuPrice}` : '')
    lines.push(`  ${c}  ${mode}  ${ch.publishMode}  ${ch.feeStrategy}  key ${ch.keyAddress}  budget $${ch.budgetUsd}${caps}  claw-back to ${ch.clawbackTo ?? '(chosen at claw-back)'}`)
  }
  return lines.join('\n')
}

// What the operator sees of a message file before anything is uploaded (stderr): its real path, size, sha256 and
// first line (escaped, at most 80 characters), through the printer.
export function describeFile(j: LoadedJob): string {
  if (j.file === null || j.bytes === null) return ''
  return [
    `message file  ${j.file.path}`,
    `  ${j.bytes.length} bytes  sha256 ${j.def.messageSha256}${j.normalized?.changed === true ? ' (after --normalize)' : ''}`,
    `  first line: ${j.file.firstLine}`,
  ].join('\n')
}

const USAGE = 'usage: vt job validate <file> [--message-file <path>] [--normalize] [--json]'

// vt job validate <file>: offline (no request): the definition's id, digest and chains, as `vt job create` would post it.
export function validateCommand(args: readonly string[], io: JobIo): number {
  const { flags, pos } = parseFlags(args, { valued: ['--message-file'], bool: ['--normalize', '--json'], usage: USAGE })
  if (pos.length !== 1) throw new UsageError(USAGE)
  const mf = flags.get('--message-file')
  const j = loadJobFile(pos[0], { network: io.network, normalize: flags.has('--normalize'), messageFile: typeof mf === 'string' ? mf : null, env: io.env, cwd: io.cwd })
  if (j.file !== null) printLines(io, describeFile(j), true)
  if (j.normalized !== null) printLines(io, summaryLine(j.normalized), true)
  for (const w of j.warnings) printLines(io, `warning: ${w}`, true)
  if (flags.has('--json')) emitJson(io, JSON.stringify({ id: j.id, def: j.def }))
  else printLines(io, `${describeDef(j.id, j.def)}\nvalid (nothing was sent; vt job create uploads the text by digest and posts this definition)`)
  return 0
}

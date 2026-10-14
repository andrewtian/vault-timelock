// cli/src/ops/decrypt-broker.ts — the UNSANDBOXED side of `vt decrypt` (design 2026-10-14-vt-decrypt, lane C): what src/ops/broker.ts does
// for this one command before and around the sandboxed child. Node builtins, src/decrypt-args.ts and core's guard module only (this is the
// process that types the passphrase).
//
// Before the child starts (prepareDecrypt), from the broker's OWN parse of the argv:
//   1. where the plaintext goes. --list: nowhere (the child prints path + size). --stdout: the broker's real stdout, raw (also a terminal:
//      it was asked). --out: a file, or for a SEALED.txt without --only a NEW directory; it must not exist and its directory must
//      (vt.out-exists). Neither: refused (vt.decrypt-output), and on a terminal especially: a decrypted key never lands on screen by
//      accident. All of this is decided before the paste is read and before any prompt.
//   2. the input. A file: the broker reads at most its first 256 KiB to learn the age header's kind. `-` or none: stdin. On a terminal the
//      broker reads the PASTE itself (echo on: ciphertext is not secret): the first non-blank line must be age armor's BEGIN line or a
//      SEALED.txt / published text's first line, else it is refused at once (decrypt.format); it ends at -----END AGE ENCRYPTED FILE-----
//      (armor) or `== end ==` (SEALED.txt), or at Ctrl-D (then the end line must have been seen); over 1 MiB is refused at once
//      (decrypt.size). What is left in the terminal's input after it (the rest of a paste, type-ahead) is discarded, never handed to the
//      shell or the passphrase prompt. A pipe is read to EOF under the same cap and checks (binary age is accepted there too). All of this
//      happens BEFORE any prompt, and the child gets exactly the validated bytes on its stdin.
//   3. the prompt policy: exactly one echo-off passphrase, and only when the input is an age file whose only stanza is `scrypt`. A
//      SEALED.txt, an identity file and a time lock never get a prompt (the identity is a handed file; the time lock goes to the relay).
// While the child runs, its plaintext arrives on fd 5 (DATA_FD) as frames; OutputWriter writes them: every file O_CREAT|O_EXCL|O_NOFOLLOW,
// mode 0600, directories 0700, nothing ever overwritten or merged (two paths one case- / normalization-insensitive disk would store as
// one file are refused: vt.out-exists), paths checked here again (relative, no `.` / `..` / empty segment, no backslash, no control
// character), sizes bounded. If the command fails, ends early or breaks the frame rules, everything the writer created is removed.
import { closeSync, constants, fchmodSync, fstatSync, linkSync, lstatSync, mkdirSync, openSync, readSync, realpathSync, renameSync, rmSync, statSync, unlinkSync, writeSync } from 'node:fs'
import { homedir, userInfo } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { refuse } from '@vault-timelock/core/text/guard.ts'
import {
  AGE_MAGIC, ARMOR_BEGIN, ARMOR_END, DecryptUsage, FRAME_HEADER_MAX, OUT_FILES_MAX, OUT_FILE_MAX, OUT_TOTAL_MAX, PASTE_MAX, PUBLISHED_HEAD,
  SEALED_END, SEALED_TITLE, checkInputPath, decryptPositions, foldKey, parseDecryptArgs, refuseInputFormat, refuseInputPath, refuseInputSize, refuseOutExists,
} from '../decrypt-args.ts'
import type { DecryptArgs } from '../decrypt-args.ts'

export type OutputSpec =
  | { readonly kind: 'none' }                              // --list
  | { readonly kind: 'stdout' }
  | { readonly kind: 'file'; readonly path: string }
  | { readonly kind: 'dir'; readonly path: string }

export interface DecryptPlan {
  readonly args: DecryptArgs
  readonly output: OutputSpec
  readonly passLabel: string | null   // the one passphrase prompt this command may ask (an age scrypt input), and what it is called; null: none
  readonly stdin: Buffer | null       // the validated paste / pipe (or a protected file the launcher read), for the child's stdin; null: a handed file
  readonly fromTty: boolean           // the input was pasted at the terminal
  readonly childArgs: readonly string[]   // the argv the child gets (a launcher-read input becomes `-`)
}

// ---- inputs in protected places (fix round 1, I-2)
// Every sandboxed profile denies reading the default package directory (~/.local/share/vault-timelock, for each home) and vt's credentials
// there (denyProtectedFiles). vt decrypt never widens that: a file under $VAULT_TIMELOCK_DIR or a default package directory is opened HERE,
// by the unsandboxed launcher — a regular file, never through a link, never a vt credential, at most PASTE_MAX bytes (as a paste) — and its
// bytes reach the child on stdin exactly like a paste. An --identity there is refused (copy it out): a secret is never read by the launcher.
const CREDENTIALS = new Set(['btc-rpc.auth', 'relay-ticket.key', 'api.token'])
const realOrSelf = (p: string): string => { try { return realpathSync(p) } catch { return p } }
const exists = (p: string): boolean => { try { lstatSync(p); return true } catch (e) { return (e as NodeJS.ErrnoException).code !== 'ENOENT' } }
export function protectedRoots(env: Readonly<Record<string, string | undefined>>): string[] {
  const set = (v: string | undefined): v is string => v !== undefined && v !== ''
  const out = set(env.VAULT_TIMELOCK_DIR) ? env.VAULT_TIMELOCK_DIR : set(env.XDG_DATA_HOME) ? join(env.XDG_DATA_HOME, 'vault-timelock') : join(set(env.HOME) ? env.HOME : homedir(), '.local', 'share', 'vault-timelock')
  const homes = [userInfo().homedir, ...(set(env.HOME) ? [env.HOME] : [])]
  return [...new Set([out, ...homes.map((h) => join(h, '.local', 'share', 'vault-timelock'))].map(realOrSelf))]
}
const under = (p: string, roots: readonly string[]): boolean => roots.some((r) => p === r || p.startsWith(`${r}/`))

// The launcher's read of a protected input: refuses (vt.decrypt-input / decrypt.size) naming the reason.
export function launcherRead(path: string): Buffer {
  if (CREDENTIALS.has(basename(path))) refuseInputPath('the input is one of vt\'s credential files: vt decrypt never reads it')
  let fd = -1
  try { fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK) } catch (e) {
    const code = (e as NodeJS.ErrnoException).code
    if (code === 'ELOOP') refuseInputPath('the input under $VAULT_TIMELOCK_DIR is a link: vt opens only the file itself there')
    refuseInputPath(`the input under $VAULT_TIMELOCK_DIR cannot be opened (${code ?? 'error'})`)
  }
  try {
    const st = fstatSync(fd)
    if (!st.isFile()) refuseInputPath('the input under $VAULT_TIMELOCK_DIR is not a regular file')
    if (st.size > PASTE_MAX) refuseInputSize(`the input is larger than ${PASTE_MAX} bytes: files under $VAULT_TIMELOCK_DIR are read by vt's launcher up to 1 MiB (as a paste); copy it out of there to decrypt a larger one`)
    const b = Buffer.alloc(st.size)
    let off = 0
    while (off < b.length) { const n = readSync(fd, b, off, b.length - off, off); if (n === 0) break; off += n }
    return b.subarray(0, off)
  } finally { closeSync(fd) }
}

// No destination for the plaintext. The one vt.decrypt-output marker.
export function refuseNoOutput(stdoutIsTty: boolean): never {
  refuse('vt.decrypt-output', stdoutIsTty
    ? 'the plaintext would be printed on this terminal: vt never shows a decrypted file by accident. Give --out <path> (written 0600, never overwriting), or --stdout to print it anyway (or --list for the archive\'s paths and sizes)'
    : 'say where the plaintext goes: --out <path> (written 0600, never overwriting) or --stdout (or --list for the archive\'s paths and sizes)') // @guard:vt.decrypt-output
}

// --out must not exist (lstat: a link counts) and must sit in an existing directory. Checked before anything is read or asked, and
// again by the writer's O_EXCL at the moment of creation.
export function checkOutPath(path: string): void {
  let exists = true
  try { lstatSync(path) } catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') exists = false; else refuseOutExists('--out cannot be checked (it is not echoed): nothing was written') }
  if (exists) refuseOutExists('--out names something that already exists: vt never overwrites. Name a new file or directory')
  let parentOk = false
  try { parentOk = statSync(dirname(path)).isDirectory() } catch { parentOk = false }
  if (!parentOk) refuseOutExists('the directory --out would be created in does not exist')
}

// The output, from the argv and what the input is (a SEALED.txt without --only extracts into a directory). Refuses before any input.
export function outputFor(a: DecryptArgs, o: { stdoutIsTty: boolean; sealed: boolean }): OutputSpec {
  if (a.list) return { kind: 'none' }
  if (a.stdout) return { kind: 'stdout' }
  if (a.out === null) refuseNoOutput(o.stdoutIsTty)
  checkOutPath(a.out)
  return a.only === null && o.sealed ? { kind: 'dir', path: a.out } : { kind: 'file', path: a.out }
}

// ---- what an input is, by the broker's own reading (never the child's)

export type Shape = 'armor' | 'sealed' | 'binary'
const firstLineShape = (line: string): Shape | null => {
  const l = line.replace(/^\ufeff/, '').trim()
  if (l === ARMOR_BEGIN) return 'armor'
  if (l === SEALED_TITLE || l.startsWith(PUBLISHED_HEAD)) return 'sealed'
  return null
}

// age header stanza types (`-> <type> …` lines up to the `--- ` MAC line) of binary age bytes; null when it is no complete header.
export function stanzaTypes(bin: Uint8Array): string[] | null {
  const text = Buffer.from(bin.subarray(0, Math.min(bin.length, 65536))).toString('latin1')
  if (!text.startsWith(AGE_MAGIC)) return null
  const types: string[] = []
  for (const line of text.slice(AGE_MAGIC.length).split('\n')) {
    if (line.startsWith('-> ')) types.push(line.slice(3).split(' ')[0] ?? '')
    else if (line.startsWith('--- ')) return types
  }
  return null
}

// The binary bytes of (the start of) an age armor text: the base64 lines after BEGIN, up to END or `maxLines`.
function dearmorHead(text: string, maxLines = 1024): Buffer | null {
  const lines = text.replace(/^\ufeff/, '').replace(/\r\n/g, '\n').trim().split('\n')
  if (lines[0] !== ARMOR_BEGIN) return null
  const body: string[] = []
  for (const l of lines.slice(1, maxLines)) {
    if (l === ARMOR_END) break
    if (!/^[A-Za-z0-9+/=]*$/.test(l)) return null
    body.push(l)
  }
  return Buffer.from(body.join(''), 'base64')
}

// Is the input an age file whose ONLY stanza is scrypt (the one kind that asks a passphrase)?
export function isScrypt(bytes: Uint8Array): boolean {
  let bin: Uint8Array | null = bytes
  if (Buffer.from(bytes.subarray(0, AGE_MAGIC.length)).toString('latin1') !== AGE_MAGIC) bin = dearmorHead(Buffer.from(bytes).toString('utf8'))
  const types = bin === null ? null : stanzaTypes(bin)
  return types !== null && types.length === 1 && types[0] === 'scrypt'
}

// The first bytes of a handed input file (the broker never reads more of it). Unreadable: an empty buffer (the child reports it).
export function peekFile(path: string, max = 256 * 1024): Buffer {
  let fd: number
  try { fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK) } catch { return Buffer.alloc(0) }
  try {
    if (!fstatSync(fd).isFile()) return Buffer.alloc(0)
    const b = Buffer.alloc(max)
    const n = readSync(fd, b, 0, max, 0)
    return b.subarray(0, n)
  } catch { return Buffer.alloc(0) } finally { closeSync(fd) }
}
export function shapeOfBytes(b: Uint8Array): Shape | null {
  if (Buffer.from(b.subarray(0, AGE_MAGIC.length)).toString('latin1') === AGE_MAGIC) return 'binary'
  const text = Buffer.from(b.subarray(0, 4096)).toString('utf8')
  const first = text.replace(/^\ufeff/, '').split('\n').find((l) => l.trim() !== '')
  return first === undefined ? null : firstLineShape(first)
}

// ---- the paste / pipe scanner: line rules, cap, the end line

// Feed it the input; it refuses (decrypt.format / decrypt.size) as soon as the text can no longer be valid. `tty` (a paste): the lines are
// checked as they arrive and push() says when the end line of the text's shape was seen (nothing more is read). A pipe: kept to EOF under
// the cap and checked by end() (binary age is accepted there; text by the same line rules).
export class PasteScanner {
  private bytes = 0
  private readonly kept: Buffer[] = []
  private partial: Buffer = Buffer.alloc(0)
  private readonly tty: boolean
  private readonly limit: number
  shape: Shape | null = null
  complete = false
  constructor(tty: boolean, limit: number = PASTE_MAX) { this.tty = tty; this.limit = limit }

  push(chunk: Buffer): boolean {
    if (this.complete && this.tty) return true
    this.bytes += chunk.length
    if (this.bytes > this.limit) refuseInputSize(`the ${this.tty ? 'pasted' : 'piped'} input is larger than ${this.limit} bytes (1 MiB): give the file instead (vt decrypt <file>)`)
    if (!this.tty) { this.kept.push(chunk); return false }
    if (this.lines(Buffer.concat([this.partial, chunk]))) return true
    // A terminal in canonical mode hands over whole lines; a piece without its newline comes only from Ctrl-D typed after it: that piece is a
    // finished line (so an end line pasted without its newline completes the paste at the first Ctrl-D).
    if (this.partial.length > 0) {
      const l = this.partial
      this.partial = Buffer.alloc(0)
      this.kept.push(l)
      if (this.line(l)) return true
    }
    return false
  }

  private lines(b: Buffer): boolean {
    let buf = b
    let i: number
    while ((i = buf.indexOf(0x0a)) >= 0) {
      const line = buf.subarray(0, i + 1)
      buf = buf.subarray(i + 1)
      this.kept.push(line)
      if (this.line(line) && this.tty) { this.partial = Buffer.alloc(0); return true }
    }
    this.partial = buf
    return false
  }

  // One line; true when it is the end line of the shape.
  private line(raw: Buffer): boolean {
    let text = ''
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(raw) } catch { refuseInputFormat('the input is not UTF-8 text: not age armor or a SEALED.txt (refused before anything was asked)') }
    const l = text.replace(/\r?\n$/, '').replace(/\r$/, '')
    if (this.shape === null) {
      if (l.replace(/^\uFEFF/, '').trim() === '') return false
      this.shape = firstLineShape(l)
      if (this.shape === null) refuseInputFormat(`the ${this.tty ? 'pasted' : 'piped'} text is not age armor (${ARMOR_BEGIN}) or a SEALED.txt: refused before anything was asked`)
      return false
    }
    if (this.complete) {
      // a pipe: only blank lines may follow the end line (core reads the text strictly)
      if (l.trim() !== '') refuseInputFormat('text follows the end line of the input')
      return false
    }
    if (this.shape === 'armor') {
      if (l.trim() === ARMOR_END) { this.complete = true; return true }
      if (!/^[A-Za-z0-9+/=]*$/.test(l.trim())) refuseInputFormat('a line of the armor is not base64: not age armor (refused before anything was asked)')
      return false
    }
    if (l.trim() === SEALED_END) { this.complete = true; return true }
    return false
  }

  // End of input (Ctrl-D, EOF): the whole input, checked complete.
  end(): Buffer {
    if (!this.tty) {
      const all = Buffer.concat(this.kept)
      if (all.subarray(0, AGE_MAGIC.length).toString('latin1') === AGE_MAGIC) {
        this.shape = 'binary'
        if (stanzaTypes(all) === null) refuseInputFormat('the piped binary input is not an age file (no complete header)')
        return all
      }
      this.kept.length = 0
      this.lines(all)
    }
    if (this.partial.length > 0) {
      const rest = this.partial
      this.partial = Buffer.alloc(0)
      this.kept.push(rest)
      if (!(this.complete && this.tty)) this.line(rest)
    }
    if (this.shape === null) refuseInputFormat(`nothing was ${this.tty ? 'pasted' : 'piped'}: give age armor, a SEALED.txt or a file`)
    if (!this.complete) refuseInputFormat(this.shape === 'armor' ? `the input ended before ${ARMOR_END}` : `the input ended before its ${SEALED_END} line`)
    return Buffer.concat(this.kept)
  }
}

// Reads stdin through the scanner. tty: a paste (ends at its end line or Ctrl-D; then the rest of the terminal's input is drained until it
// has been quiet for `quietMs`, and the caller flushes the queue). Never longer than the cap. Rejects with the scanner's refusal.
export function readInput(stdin: NodeJS.ReadableStream, o: { tty: boolean; quietMs?: number; limit?: number }): Promise<Buffer> {
  const sc = new PasteScanner(o.tty, o.limit)
  return new Promise<Buffer>((resolve, reject) => {
    let settled = false
    let timer: NodeJS.Timeout | null = null
    const stop = (): void => { stdin.removeListener('data', onData); stdin.removeListener('end', onEnd); stdin.removeListener('error', onErr); stdin.pause() }
    // After the end (or a refusal) on a terminal: keep reading and DISCARDING until the input is quiet, so the rest of a paste is not left
    // for the shell (the caller then flushes the terminal's queue as well).
    const drainThen = (f: () => void): void => {
      if (!o.tty) { stop(); f(); return }
      settled = true
      const quiet = (): void => { if (timer !== null) clearTimeout(timer); timer = setTimeout(() => { stop(); f() }, o.quietMs ?? 200) }
      stdin.removeListener('data', onData)
      stdin.on('data', (c: Buffer) => { if (Buffer.isBuffer(c)) c.fill(0); quiet() })
      stdin.removeListener('end', onEnd)
      stdin.once('end', () => { if (timer !== null) clearTimeout(timer); stop(); f() })
      quiet()
    }
    const fail = (e: unknown): void => { if (settled) return; drainThen(() => reject(e)) }
    const onData = (c: Buffer | string): void => {
      if (settled) return
      try {
        if (sc.push(typeof c === 'string' ? Buffer.from(c) : c)) { let all: Buffer; try { all = sc.end() } catch (e) { fail(e); return } drainThen(() => resolve(all)) }
      } catch (e) { fail(e) }
    }
    const onEnd = (): void => { if (settled) return; settled = true; stop(); try { resolve(sc.end()) } catch (e) { reject(e) } }
    const onErr = (): void => { if (settled) return; settled = true; stop(); try { resolve(sc.end()) } catch (e) { reject(e) } }
    stdin.on('data', onData)
    stdin.on('end', onEnd)
    stdin.on('error', onErr)
    stdin.resume()
  })
}

export interface PrepareDeps {
  protectedRoots?: readonly string[]   // where the sandbox may not read: the launcher reads an input there (default: none)
  stdin: NodeJS.ReadableStream
  stdinIsTty: boolean
  stdoutIsTty: boolean
  note(text: string): void         // a broker line to the terminal (the paste instructions)
  flush(): void                    // discard the terminal's input queue
  quietMs?: number
}

// Everything the broker decides for `vt decrypt` before the child starts. Throws DecryptUsage (exit 1) or a Refusal (exit 2).
export async function prepareDecrypt(argv: readonly string[], d: PrepareDeps): Promise<DecryptPlan> {
  const args = parseDecryptArgs(argv.slice(1))
  const roots = d.protectedRoots ?? []
  if (args.identity !== null) {
    checkInputPath(args.identity, 'the --identity file')
    if (under(args.identity, roots)) refuseInputPath('the --identity file lies under $VAULT_TIMELOCK_DIR (or the default package directory), which sandboxed commands may not read and vt\'s launcher never reads a secret from: copy it out first')
  }
  if (args.input !== null) {
    checkInputPath(args.input, 'the input file')
    if (under(args.input, roots)) {
      outputFor(args, { stdoutIsTty: d.stdoutIsTty, sealed: false })     // refused before anything is read
      const bytes = launcherRead(args.input)
      const shape = shapeOfBytes(bytes)
      const output = outputFor(args, { stdoutIsTty: d.stdoutIsTty, sealed: shape === 'sealed' })
      const childArgs = [...argv]
      const at = decryptPositions(argv).input
      if (at !== null) childArgs[at] = '-'
      return { args, output, passLabel: shape !== 'sealed' && isScrypt(bytes) ? basename(args.input) : null, stdin: bytes, fromTty: false, childArgs }
    }
    const head = peekFile(args.input)
    const shape = shapeOfBytes(head)
    const output = outputFor(args, { stdoutIsTty: d.stdoutIsTty, sealed: shape === 'sealed' })
    return { args, output, passLabel: shape !== 'sealed' && isScrypt(head) ? basename(args.input) : null, stdin: null, fromTty: false, childArgs: [...argv] }
  }
  // stdin: decide the output first (nothing is read when it would be refused). Whether a SEALED.txt comes is known after the paste: a
  // directory --out is checked now (it must not exist either way) and settled below.
  outputFor(args, { stdoutIsTty: d.stdoutIsTty, sealed: false })
  if (d.stdinIsTty) {
    d.note('paste the age armor or the SEALED.txt now (it is shown: ciphertext is not secret); it ends at -----END AGE ENCRYPTED FILE-----, at == end ==, or with Ctrl-D\n')
  }
  let bytes: Buffer
  try {
    bytes = await readInput(d.stdin, { tty: d.stdinIsTty, quietMs: d.quietMs })
  } finally {
    if (d.stdinIsTty) d.flush()
  }
  const shape = shapeOfBytes(bytes)
  const output = args.list ? { kind: 'none' as const } : args.stdout ? { kind: 'stdout' as const }
    : { kind: args.only === null && shape === 'sealed' ? 'dir' as const : 'file' as const, path: args.out as string }
  return { args, output, passLabel: shape !== 'sealed' && isScrypt(bytes) ? (d.stdinIsTty ? 'the pasted age file' : 'the piped age file') : null, stdin: bytes, fromTty: d.stdinIsTty, childArgs: [...argv] }
}
export { DecryptUsage }

// ---- the writer: frames from fd 5 → the output

export class OutputViolation extends Error {}
const SEG_BAD = /[\u0000-\u001f\u007f-\u009f\\]/

// A relative path of the archive as the writer accepts it (the child already refused unsafe ones: this is the broker's own check).
export function safeSegments(path: string): string[] {
  if (typeof path !== 'string' || path === '' || path.length > 4096 || path.startsWith('/') || SEG_BAD.test(path)) throw new OutputViolation('an unsafe output path')
  const segs = path.split('/')
  if (segs.length > 64 || segs.some((s) => s === '' || s === '.' || s === '..' || Buffer.byteLength(s) > 255)) throw new OutputViolation('an unsafe output path')
  return segs
}

export interface Written { files: number; bytes: number }   // no digest of the plaintext is kept or printed (fix round 1, M-3)
// The partial name beside --out (fix round 1, M-6): the output is built there and appears under its final name only when complete.
const partialName = (out: string): string => join(dirname(out), `.${basename(out)}.vt-partial-${randomBytes(6).toString('hex')}`)

export class OutputWriter {
  private buf: Buffer = Buffer.alloc(0)
  private cur: { fd: number | null; left: number } | null = null
  private files = 0
  private total = 0
  private ended = false
  private rootMade = false
  private readonly dirs = new Map<string, string>()     // fold key of a directory path → the path as created
  private readonly names = new Set<string>()            // fold keys of every path written (files and directories)
  private temp: string | null = null                   // the partial file / directory beside --out
  private readonly spec: OutputSpec
  private readonly data: (b: Buffer) => boolean
  constructor(spec: OutputSpec, data: (b: Buffer) => boolean = () => true) { this.spec = spec; this.data = data }

  get complete(): boolean { return this.ended }
  get started(): boolean { return this.files > 0 || this.cur !== null }

  // Feeds bytes of the stream. Returns false when the stdout sink asks to wait (backpressure). Throws OutputViolation or a Refusal.
  push(chunk: Buffer): boolean {
    let ok = true
    let b = chunk
    while (b.length > 0) {
      if (this.ended) throw new OutputViolation('data after the end of the output')
      if (this.cur !== null) {
        const n = Math.min(this.cur.left, b.length)
        const part = b.subarray(0, n)
        if (this.cur.fd !== null) { let off = 0; while (off < part.length) off += writeSync(this.cur.fd, part, off, part.length - off) } else if (!this.data(Buffer.from(part))) ok = false
        this.cur.left -= n
        b = b.subarray(n)
        if (this.cur.left === 0) this.closeFile()
        continue
      }
      this.buf = Buffer.concat([this.buf, b])
      b = Buffer.alloc(0)
      const i = this.buf.indexOf(0x0a)
      if (i < 0) { if (this.buf.length > FRAME_HEADER_MAX) throw new OutputViolation('an oversized output header'); break }
      const head = this.buf.subarray(0, i).toString('utf8')
      const rest = this.buf.subarray(i + 1)
      this.buf = Buffer.alloc(0)
      this.header(head)
      b = rest
      const opened = this.cur as { left: number } | null
      if (opened !== null && opened.left === 0) this.closeFile()
    }
    return ok
  }

  private header(line: string): void {
    let h: unknown
    try { h = JSON.parse(line) } catch { throw new OutputViolation('a malformed output header') }
    if (typeof h !== 'object' || h === null || Array.isArray(h)) throw new OutputViolation('a malformed output header')
    const keys = Object.keys(h).sort().join(',')
    const r = h as { path?: unknown; size?: unknown; end?: unknown }
    if (keys === 'end' && r.end === true) { this.ended = true; return }
    if (keys !== 'path,size' || typeof r.path !== 'string' || typeof r.size !== 'number' || !Number.isSafeInteger(r.size) || r.size < 0) throw new OutputViolation('a malformed output header')
    if (r.size > OUT_FILE_MAX || this.total + r.size > OUT_TOTAL_MAX || this.files + 1 > OUT_FILES_MAX) throw new OutputViolation('an output over the size bounds')
    if (this.spec.kind === 'none') throw new OutputViolation('output from a command that prints only a list')
    if (this.spec.kind !== 'dir' && this.files > 0) throw new OutputViolation('a second output file where one was asked')
    this.files++
    this.total += r.size
    this.cur = { fd: this.open(r.path), left: r.size }
  }

  // The descriptor the next file's bytes go to (null: the stdout sink). O_EXCL: never an existing file; O_NOFOLLOW: never through a link.
  private open(path: string): number | null {
    if (this.spec.kind === 'stdout') return null
    const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW
    let target = ''
    if (this.spec.kind === 'file') { this.temp = partialName(this.spec.path); target = this.temp }
    if (this.spec.kind === 'dir') {
      const segs = safeSegments(path)
      const root = this.makeRoot()
      let at = ''
      for (const s of segs.slice(0, -1)) {
        at = at === '' ? s : `${at}/${s}`
        const k = foldKey(at)
        const had = this.dirs.get(k)
        if (had === at) continue
        if (had !== undefined || this.names.has(k)) refuseOutExists('two paths of the archive differ only in letter case or Unicode normalization: on this disk (APFS) they would be ONE directory; nothing was merged and nothing is kept')
        try { mkdirSync(join(root, at), 0o700) } catch (e) {
          if ((e as NodeJS.ErrnoException).code === 'EEXIST') refuseOutExists('a directory of the archive would merge with one already written (the disk treats their names as one): nothing is kept')
          throw e
        }
        this.dirs.set(k, at)
        this.names.add(k)
      }
      const k = foldKey(path)
      if (this.names.has(k)) refuseOutExists('two files of the archive differ only in letter case or Unicode normalization: on this disk (APFS) they would be ONE file; the second is refused, nothing was overwritten and nothing is kept')
      this.names.add(k)
      target = join(root, path)
    }
    let fd: number
    try { fd = openSync(target, flags, 0o600) } catch (e) {
      if (this.spec.kind === 'file') this.temp = null
      if ((e as NodeJS.ErrnoException).code === 'EEXIST' || (e as NodeJS.ErrnoException).code === 'ELOOP') refuseOutExists(this.spec.kind === 'file' ? '--out appeared while decrypting: vt never overwrites' : 'a file of the archive would overwrite one already written (the disk treats their names as one): nothing is kept')
      throw e
    }
    try { fchmodSync(fd, 0o600) } catch { /* the create mode already is 0600 (umask can only narrow it) */ }
    return fd
  }

  // The directory's partial root beside --out (0700, exclusive), made on the first file or at the end for an empty archive.
  private makeRoot(): string {
    if (!this.rootMade) {
      this.temp = partialName((this.spec as { path: string }).path)
      mkdirSync(this.temp, 0o700)
      this.rootMade = true
    }
    return this.temp as string
  }

  private closeFile(): void {
    if (this.cur === null) return
    if (this.cur.fd !== null) closeSync(this.cur.fd)
    this.cur = null
  }

  // The complete output takes its final name, never over anything: a file by link() (EEXIST: refused), a directory by rename() after
  // checking the name is free (rename could only replace an EMPTY directory made in that instant: nothing is lost). Then the partial name
  // is gone.
  private commit(): void {
    if (this.spec.kind !== 'file' && this.spec.kind !== 'dir') return
    const final = this.spec.path
    if (this.spec.kind === 'dir') this.makeRoot()
    const temp = this.temp as string
    if (this.spec.kind === 'file') {
      try { linkSync(temp, final) } catch (e) {
        const code = (e as NodeJS.ErrnoException).code
        if (code === 'EEXIST') refuseOutExists('--out appeared while decrypting: vt never overwrites; nothing was written')
        // a disk without hard links (FAT, some network shares): the same name check, then rename
        if (code !== 'EPERM' && code !== 'ENOTSUP' && code !== 'EOPNOTSUPP' && code !== 'EMLINK') throw e
        if (exists(final)) refuseOutExists('--out appeared while decrypting: vt never overwrites; nothing was written')
        renameSync(temp, final)
        this.temp = null
        return
      }
      unlinkSync(temp)
      this.temp = null
      return
    }
    if (exists(final)) refuseOutExists('--out appeared while decrypting: vt never writes into an existing directory; nothing was written')
    try { renameSync(temp, final) } catch (e) {
      const code = (e as NodeJS.ErrnoException).code
      if (code === 'EEXIST' || code === 'ENOTEMPTY' || code === 'ENOTDIR') refuseOutExists('--out appeared while decrypting: vt never writes into an existing directory; nothing was written')
      throw e
    }
    this.temp = null
    this.rootMade = false
  }

  // ok: the command exited 0. Returns what was written, or null after removing everything this writer created.
  finish(ok: boolean): Written | null {
    const good = ok && this.ended && this.cur === null && (this.spec.kind === 'none' || this.files > 0 || this.spec.kind === 'dir')
    if (this.cur !== null && this.cur.fd !== null) { try { closeSync(this.cur.fd) } catch { /* closed */ } }
    this.cur = null
    if (good) {
      try { this.commit() } catch (e) { this.discard(); throw e }
      return { files: this.files, bytes: this.total }
    }
    this.discard()
    return null
  }

  // Removes the partial output (never anything under the final name: that exists only once complete).
  discard(): void {
    if (this.cur !== null && this.cur.fd !== null) { try { closeSync(this.cur.fd) } catch { /* closed */ } this.cur = null }
    if (this.temp !== null) { try { rmSync(this.temp, { recursive: true, force: true }) } catch { /* best effort */ } this.temp = null; this.rootMade = false }
  }
}

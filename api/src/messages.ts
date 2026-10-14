// api/src/messages.ts — message texts, stored once by digest at <stateDir>/messages/<sha256>.txt (0600 in a 0700
// directory; spec §3.2, §4.1, §5.2; R72).
//
// PUT /messages/:sha256 (raw UTF-8 body, text/plain; charset=utf-8, checked by guardRequest):
//   message.too-long  more than MESSAGE_MAX (16 MiB) bytes. A declared Content-Length over the cap is refused before a
//                     byte is read; a chunked body is counted while it streams and refused as soon as it passes the
//                     cap, so at most MESSAGE_MAX bytes (plus the chunk in hand) are ever buffered. The rest is drained
//                     and discarded, and the reply closes the connection.
//   message.digest    sha256 of the body bytes is not the path's digest.
//   message.utf8      the bytes do not decode as UTF-8 (TextDecoder fatal: true, ignoreBOM: true — Task 0 ruling 7: a
//                     BOM is kept, so validateMessage refuses it message.control, never strips it).
//   message.*         validateMessage (core): empty, controls, NFC, secrets, IP literals. Refused, never rewritten.
//   → stored (temp file + fsync + rename + directory fsync), then 201 { sha256, bytes }. Idempotent.
// GET /messages/:sha256 → the stored bytes, re-hashed on every read. Missing, not a private regular file, or not
// hashing to its name: message.missing (never a partial or a different text).
// POST /jobs by digest needs the message stored with exactly messageBytes bytes (message.missing otherwise); an inline
// message is stored here by create, after normalizeJob validated it.
import { closeSync, constants, fstatSync, fsyncSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs'
import { createHash, randomBytes } from 'node:crypto'
import type { IncomingMessage } from 'node:http'
import { join } from 'node:path'
import { MESSAGE_MAX } from '@vault-timelock/core/contracts'
import { validateMessage } from '@vault-timelock/core/job'
import { refuse } from 'vt-broadcast/src/guard.ts'
import { ensureDir } from 'vt-broadcast/src/lifecycle/paths.ts'
import { single } from './http.ts'

export interface MessageStore {
  // Reads, checks and stores an uploaded text; the reply body of PUT /messages/:sha256.
  put(req: IncomingMessage, sha256: string): Promise<{ sha256: string; bytes: number }>
  // The stored bytes, verified against their name (message.missing).
  read(sha256: string): Buffer
  // message.missing unless the text with this digest is stored with exactly `bytes` bytes.
  assertStored(sha256: string, bytes: number): void
  // Stores a text normalizeJob already validated (an inline message of POST /jobs).
  storeText(text: string, sha256: string): void
}

const HEX64 = /^[0-9a-f]{64}$/
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
const sha256Hex = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex')

function assertFits(ok: boolean): void {
  if (!ok) refuse('message.too-long', `the message is over ${MESSAGE_MAX} bytes`) // @guard:message.too-long
}

function assertPresent(ok: boolean): void {
  if (!ok) refuse('message.missing', 'no stored message with that sha256 (and size): upload it first with PUT /messages/<sha256>') // @guard:message.missing
}

// The body, or null as soon as it is over `cap` bytes (declared or counted). The rest is read and discarded.
function readCapped(req: IncomingMessage, cap: number): Promise<Buffer | null> {
  const declared = single(req, 'content-length')
  const declaredOk = declared === undefined || (typeof declared === 'string' && /^[0-9]{1,15}$/.test(declared) && Number(declared) <= cap)
  if (!declaredOk) {
    req.resume()
    return Promise.resolve(null)
  }
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let n = 0
    let done = false
    const onData = (c: Buffer): void => {
      if (done) return
      n += c.length
      if (n > cap) {
        done = true
        chunks.length = 0
        req.off('data', onData)
        req.resume()
        resolve(null)
        return
      }
      chunks.push(c)
    }
    req.on('data', onData)
    req.on('end', () => { if (!done) { done = true; resolve(Buffer.concat(chunks, n)) } })
    req.on('error', (e) => { if (!done) { done = true; reject(e) } })
    req.on('close', () => { if (!done) { done = true; reject(new Error('request aborted')) } })
  })
}

function fsyncDir(dir: string): void {
  const fd = openSync(dir, constants.O_RDONLY)
  try { fsyncSync(fd) } finally { closeSync(fd) }
}

export function createMessages(stateDir: string, o: { cap?: number } = {}): MessageStore {
  const cap = o.cap ?? MESSAGE_MAX
  const dir = join(stateDir, 'messages')
  const fileOf = (sha: string): string => {
    if (!HEX64.test(sha)) throw new Error('messages: not a sha256')
    return join(dir, `${sha}.txt`)
  }

  // The stored bytes when they are a private regular file of at most `cap` bytes hashing to `sha`; else null.
  const load = (sha: string): Buffer | null => {
    let fd = -1
    try {
      fd = openSync(fileOf(sha), constants.O_RDONLY | constants.O_NOFOLLOW)
      const st = fstatSync(fd)
      if (!st.isFile() || (st.mode & 0o077) !== 0 || st.size > cap) return null
      const buf = readFileSync(fd)
      return sha256Hex(buf) === sha ? buf : null
    } catch {
      return null
    } finally {
      if (fd >= 0) closeSync(fd)
    }
  }

  // Atomic and durable: a temp file in the same directory, fsync, rename over the name, fsync the directory.
  const write = (sha: string, bytes: Uint8Array): void => {
    if (load(sha) !== null) return
    ensureDir(dir)
    const file = fileOf(sha)
    const tmp = `${file}.tmp.${process.pid}.${randomBytes(6).toString('hex')}`
    try {
      const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
      try {
        let off = 0
        while (off < bytes.length) {
          const w = writeSync(fd, bytes, off, bytes.length - off)
          if (!(w > 0)) throw new Error('the write made no progress')
          off += w
        }
        fsyncSync(fd)
      } finally {
        closeSync(fd)
      }
      renameSync(tmp, file)
    } catch (e) {
      try { unlinkSync(tmp) } catch { /* already gone */ }
      throw e
    }
    fsyncDir(dir)
  }

  return {
    async put(req, sha) {
      if (!HEX64.test(sha)) throw new Error('messages: not a sha256')
      const body = await readCapped(req, cap)
      assertFits(body !== null)
      const digestOk = sha256Hex(body!) === sha
      if (!digestOk) refuse('message.digest', 'the sha256 of the uploaded bytes is not the digest in the path') // @guard:message.digest
      let text = ''
      let utf8 = true
      try { text = UTF8.decode(body!) } catch { utf8 = false }
      if (!utf8) refuse('message.utf8', 'the message is not valid UTF-8 (the bytes are not echoed)') // @guard:message.utf8
      const m = validateMessage(text)
      write(sha, body!)
      return { sha256: sha, bytes: m.bytes }
    },
    read(sha) {
      const buf = HEX64.test(sha) ? load(sha) : null
      assertPresent(buf !== null)
      return buf!
    },
    assertStored(sha, bytes) {
      const buf = HEX64.test(sha) ? load(sha) : null
      assertPresent(buf !== null && buf.length === bytes)
    },
    storeText(text, sha) {
      const bytes = Buffer.from(text, 'utf8')
      if (sha256Hex(bytes) !== sha) throw new Error('messages: the text does not hash to its digest')
      write(sha, bytes)
    },
  }
}

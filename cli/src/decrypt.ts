// cli/src/decrypt.ts — `vt decrypt`, the SANDBOXED side (design 2026-10-14-vt-decrypt, lane C). bin/vt runs it as a child of the
// unsandboxed broker (src/ops/broker.ts + src/ops/decrypt-broker.ts) under the decrypt profile (src/ops/sandbox.ts): the network's relay
// port only, reads only the files it is handed (the input file and --identity, as absolute real paths), no file writes, no terminal.
//
//   vt decrypt [<file> | -] [--identity F] [--out <path|dir>] [--stdout] [--list] [--only <path>]
//
// One shared core (@vault-timelock/core/decrypt): detectInput first (no secret, no decryption: what the input is), then exactly what that
// kind needs:
//   passphrase (age scrypt)  the passphrase, asked by the BROKER at the terminal (echo off; the child names no text, only the request);
//                            no terminal refuses vt.tty-required;
//   identity (X25519)        --identity F, an age-keygen identity file (read here, from the handed path; never printed);
//   timelocked (tlock)       the drand round's signature through the running stack's relay (GET /relay/drand/<quicknet>/public/<round>
//                            on the network's relay port): `vt up` must run for that network, else vt.relay-down. Before the round core
//                            refuses decrypt.too-early ("opens at <UTC>") and nothing is fetched;
//   a SEALED.txt             its whole chain: through its time lock (the relay), or with --identity (the one-time key, the recovery
//                            path) straight to vault.tar.gz.age, at any time.
// Output: this process writes NO file. The plaintext goes to the broker on fd 5 (DATA_FD) as frames — a JSON header {"path","size"}, the
// bytes, and finally {"end":true} — and the BROKER writes --out (0600, never overwriting) or its stdout (--stdout). Where it goes is the
// broker's decision from its own parse of the argv; this side only decides WHAT is sent:
//   one age file             its plaintext (one frame);
//   --only <path>            that one file of the archive (one frame; the path as --list printed it);
//   a SEALED.txt, --out      every file of its archive (vault.tar.gz / secret.tar.gz / content.tar.gz), each one frame, after the archive
//                            was checked against its MANIFEST.csv / ATTACHMENTS.csv digests when they are in it (vt.manifest: nothing is
//                            sent); a key-only text or a raw payload: its one file (identity.key, content);
//   a SEALED.txt, --stdout   the archive file itself (or the one file).
// --list prints `<size>  <path>` per file of the archive on stdout (paths escaped for display: listName); nothing else is ever printed on
// stdout (a summary goes to stderr). Nothing here logs a passphrase, an identity or plaintext.
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs'
import { request } from 'node:http'
import { Socket } from 'node:net'
import { createHash } from 'node:crypto'
import type { Network } from '@vault-timelock/core/contracts'
import { PORTS, Refusal, isRefusal, refuse } from '@vault-timelock/core/contracts'
import { DECRYPT_LIMITS, PASTE_LIMIT, decryptAge, detectInput, extractAll, extractOne, listArchive } from '@vault-timelock/core/decrypt'
import type { ArchiveFile, DecryptHow, DecryptResult, FetchRoundSignature } from '@vault-timelock/core/decrypt'
import { UsageError } from './args.ts'
import { DATA_FD, DecryptUsage, listName, parseDecryptArgs, refuseInputPath, refuseInputSize, unlistName } from './decrypt-args.ts'
import type { DecryptArgs } from './decrypt-args.ts'
import { assertTerminal } from './job/client.ts'

export interface DecryptDeps {
  readonly network: Network
  input(a: DecryptArgs): Promise<Uint8Array>            // the handed file, or stdin (the broker's validated paste / pipe)
  identity(path: string): string                         // the --identity file's text
  readonly terminal: boolean                             // the broker can ask (VT_TTY=1)
  passphrase(): Promise<string>                          // asked by the broker
  fetchRoundSignature: FetchRoundSignature
  send(bytes: Uint8Array): Promise<void>                 // the data channel to the broker
  close(): Promise<void>                                 // end of the data channel
  out(text: string): void
  err(text: string): void
  now?(): number
}

// ---- the relay's drand route (vt.relay-down: the one marker)

export function refuseRelay(message: string): never {
  refuse('vt.relay-down', message) // @guard:vt.relay-down
}

const BEACON_CAP = 4096
// GET /relay/drand/<hash>/public/<round> on the network's relay port: the signature (96 hex), or null when drand has not published the round
// (the relay answers 404). Anything else refuses vt.relay-down; the message names no address.
export function relayFetcher(o: { network: Network; port: number; timeoutMs?: number }): FetchRoundSignature {
  return (hash, round) => new Promise<string | null>((resolve, reject) => {
    if (!/^[0-9a-f]{64}$/.test(hash) || !Number.isSafeInteger(round) || round < 1) { reject(new Error('a malformed drand round')); return }
    let done = false
    const fail = (message: string): void => { if (done) return; done = true; clearTimeout(timer); try { refuseRelay(message) } catch (e) { reject(e) } }
    const ok = (v: string | null): void => { if (done) return; done = true; clearTimeout(timer); resolve(v) }
    const down = `the ${o.network} relay is not running: a time lock needs drand round ${round}'s signature through it. Start the stack with: vt up --network ${o.network} (and see vt status)`
    const req = request({ host: '127.0.0.1', port: o.port, path: `/relay/drand/${hash}/public/${round}`, method: 'GET', agent: false,
      headers: { host: `127.0.0.1:${o.port}`, accept: 'application/json' } }, (res) => {
      const chunks: Buffer[] = []
      let n = 0
      res.on('data', (c: Buffer) => { n += c.length; if (n > BEACON_CAP) { req.destroy(); fail(`the ${o.network} relay answered something that is not a drand beacon`) } else chunks.push(c) })
      res.on('end', () => {
        const status = res.statusCode ?? 0
        if (status === 404) { ok(null); return }
        if (status !== 200) { fail(`the ${o.network} relay could not give drand round ${round} (HTTP ${status}): check vt status --network ${o.network} (drand goes through Tor)`); return }
        let b: { round?: unknown; signature?: unknown } | null = null
        try { b = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { round?: unknown; signature?: unknown } } catch { b = null }
        if (b === null || typeof b !== 'object' || b.round !== round || typeof b.signature !== 'string' || !/^[0-9a-f]{96}$/.test(b.signature)) {
          fail(`the ${o.network} relay answered something that is not drand round ${round}'s beacon`)
          return
        }
        ok(b.signature)
      })
      res.on('error', () => fail(down))
    })
    const timer = setTimeout(() => { req.destroy(); fail(`the ${o.network} relay did not answer in time: check vt status --network ${o.network}`) }, o.timeoutMs ?? 30_000)
    req.on('error', () => fail(down))
    req.end()
  })
}

// ---- MANIFEST.csv / ATTACHMENTS.csv (vt.manifest: the one marker)

export function refuseManifest(message: string): never {
  refuse('vt.manifest', message) // @guard:vt.manifest
}

const SEG = /^[A-Za-z0-9][A-Za-z0-9._-]*$/
const sha256 = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex')
const csvRows = (b: Uint8Array, name: string): string[] => {
  let text = ''
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(b) } catch { refuseManifest(`${name} is not UTF-8 text: the archive was not written`) }
  const rows = text.split('\n')
  if (rows[rows.length - 1] === '') rows.pop()
  if (rows.length === 0 || !rows[0].startsWith('item_id,')) refuseManifest(`${name} has no header line: the archive was not written`)
  return rows.slice(1)
}

// The archive against the digests it carries (the sealer's MANIFEST.csv: item_id,sha256,… → items/<id>.json; ATTACHMENTS.csv:
// item_id,file_id,bytes,sha256 → files/<id>/<file_id>). Every row must name a file of the archive with that digest (and size), and every
// items/*.json and files/** entry must have its row. Neither file in the archive: nothing to check. Counts only in messages (no path, no id).
export function verifyManifests(files: readonly ArchiveFile[]): { items: number | null; attachments: number | null } {
  const by = new Map(files.map((f) => [f.path, f]))
  let items: number | null = null, attachments: number | null = null
  const m = by.get('MANIFEST.csv')
  if (m !== undefined) {
    const listed = new Set<string>()
    let bad = 0
    const rows = csvRows(m.bytes, 'MANIFEST.csv')
    for (const r of rows) {
      const x = /^([^,]+),([0-9a-f]{64})(?:,[^,]*)*$/.exec(r)
      if (x === null || !SEG.test(x[1]) || listed.has(`items/${x[1]}.json`)) refuseManifest('MANIFEST.csv has a malformed or repeated row (not printed): the archive was not written')
      const p = `items/${x[1]}.json`
      listed.add(p)
      const f = by.get(p)
      if (f === undefined || sha256(f.bytes) !== x[2]) bad++
    }
    const unlisted = files.filter((f) => /^items\/[^/]+$/.test(f.path) && !listed.has(f.path)).length
    if (bad > 0 || unlisted > 0) refuseManifest(`${bad} of ${rows.length} item(s) are missing or differ from MANIFEST.csv${unlisted > 0 ? `, and ${unlisted} item file(s) are not in it` : ''}: the archive was not written`)
    items = rows.length
  }
  const a = by.get('ATTACHMENTS.csv')
  if (a !== undefined) {
    const listed = new Set<string>()
    let bad = 0
    const rows = csvRows(a.bytes, 'ATTACHMENTS.csv')
    for (const r of rows) {
      const x = /^([^,]+),([^,]+),(0|[1-9][0-9]{0,14}),([0-9a-f]{64})$/.exec(r)
      if (x === null || !SEG.test(x[1]) || !SEG.test(x[2]) || listed.has(`files/${x[1]}/${x[2]}`)) refuseManifest('ATTACHMENTS.csv has a malformed or repeated row (not printed): the archive was not written')
      const p = `files/${x[1]}/${x[2]}`
      listed.add(p)
      const f = by.get(p)
      if (f === undefined || f.size !== Number(x[3]) || sha256(f.bytes) !== x[4]) bad++
    }
    const unlisted = files.filter((f) => f.path.startsWith('files/') && !listed.has(f.path)).length
    if (bad > 0 || unlisted > 0) refuseManifest(`${bad} of ${rows.length} attachment(s) are missing or differ from ATTACHMENTS.csv${unlisted > 0 ? `, and ${unlisted} attachment file(s) are not in it` : ''}: the archive was not written`)
    attachments = rows.length
  } else if (m !== undefined && files.some((f) => f.path.startsWith('files/'))) {
    refuseManifest('the archive holds attachments (files/) but no ATTACHMENTS.csv to check them against: the archive was not written')
  }
  return { items, attachments }
}

// ---- the command

async function frame(d: DecryptDeps, path: string, bytes: Uint8Array): Promise<void> {
  await d.send(Buffer.from(`${JSON.stringify({ path, size: bytes.length })}\n`))
  await d.send(bytes)
}

const what = (r: DecryptResult): string => r.kind === 'sealed' ? 'the SEALED.txt' : `the age file (${r.kind})`
const via = (r: DecryptResult, round: number | null, at: string | null): string => r.via === 'timelock' ? `through its time lock (drand round ${round}, ${at}; the signature came through the relay)` : r.via === 'identity' ? 'with the identity' : 'with the passphrase'

// fix round 1 (I-2): a handed file the sandbox may not read is refused with its reason, never a bare EPERM
async function readable<T>(what: string, f: () => T | Promise<T>): Promise<T> {
  try { return await f() } catch (e) {
    const code = (e as NodeJS.ErrnoException | null)?.code
    if (code === 'EPERM' || code === 'EACCES') refuseInputPath(`the sandbox may not read ${what}: vt's sandboxed commands never read vt's state and credentials, or (except through vt's launcher) its package directory; copy the file elsewhere and hand it again`)
    throw e
  }
}

export async function runDecrypt(argv: readonly string[], d: DecryptDeps): Promise<number> {
  let a: DecryptArgs
  try { a = parseDecryptArgs(argv) } catch (e) { if (e instanceof DecryptUsage) throw new UsageError(e.message); throw e }
  const input = await readable('the input file', () => d.input(a))
  // What the input is, before any secret is asked: decrypt.format / decrypt.size / decrypt.kind refuse here.
  const det = detectInput(input, a.input === null ? { input: PASTE_LIMIT } : undefined)
  const how: { passphrase?: string; identity?: string; fetchRoundSignature?: FetchRoundSignature; now?: () => number } = {}
  if (d.now !== undefined) how.now = d.now
  if (a.identity !== null) { const p = a.identity; how.identity = await readable('the --identity file', () => d.identity(p)) }
  if (det.kind === 'passphrase') {
    assertTerminal(d.terminal, 'this input is passphrase-encrypted (age scrypt): vt asks the passphrase at the terminal only (never stdin, argv or the environment), and there is none')
    how.passphrase = await d.passphrase()
  }
  if (det.kind === 'timelocked' || (det.kind === 'sealed' && how.identity === undefined)) how.fetchRoundSignature = d.fetchRoundSignature
  let r: DecryptResult
  try {
    r = await decryptAge(input, how as DecryptHow)
  } catch (e) {
    if (isRefusal(e) && e.guardId === 'decrypt.kind' && det.kind === 'identity' && a.identity === null) throw new Refusal(e.guardId, `${e.message}: give it with --identity <file>`)
    throw e
  }
  d.err(`vt decrypt: ${what(r)} opened ${via(r, det.round, det.opensAt)}\n`)
  if (r.kind === 'sealed') d.err(`vt decrypt: ${r.blocks.length} block(s) match their [file] lines (size and sha256)\n`)
  for (const n of r.notes) d.err(`vt decrypt: ${n}\n`)

  if (a.list || a.only !== null) {
    if (r.archive === null) throw new UsageError(`${a.list ? '--list' : '--only'} needs an archive (a SEALED.txt's vault.tar.gz, or an age file holding a .tar.gz); this one decrypted to one file: use --out <file> or --stdout`)
    if (a.list) {
      const entries = await listArchive(r.archive)
      const w = Math.max(1, ...entries.map((e) => String(e.size).length))
      for (const e of entries) d.out(`${String(e.size).padStart(w)}  ${listName(e.path)}\n`)
      d.err(`vt decrypt: ${entries.length} file(s), ${entries.reduce((s, e) => s + e.size, 0)} bytes in ${r.archive.name} (paths as stored; control and invisible characters shown as [U+XXXX])\n`)
      return 0
    }
    const path = unlistName(a.only as string)
    const bytes = await extractOne(r.archive, path)
    await frame(d, path, bytes)
  } else if (r.kind !== 'sealed') {
    await frame(d, r.files[0].name, r.files[0].bytes)
  } else if (a.stdout) {
    const f = r.archive !== null ? r.files.find((x) => x.name === r.archive?.name) ?? r.files[r.files.length - 1] : r.files[r.files.length - 1]
    await frame(d, f.name, f.bytes)
  } else if (r.archive !== null) {
    const all = await extractAll(r.archive)
    const v = verifyManifests(all)
    d.err(`vt decrypt: ${r.archive.name}: ${all.length} file(s); ${v.items === null ? 'no MANIFEST.csv in it (not checked)' : `MANIFEST.csv: ${v.items} item(s) match`}${v.attachments === null ? '' : `; ATTACHMENTS.csv: ${v.attachments} attachment(s) match`}\n`)
    for (const f of all) await frame(d, f.path, f.bytes)
  } else {
    for (const f of r.files) await frame(d, f.name, f.bytes)
  }
  await d.send(Buffer.from(`${JSON.stringify({ end: true })}\n`))
  await d.close()
  return 0
}

// ---- the real dependencies (inside the sandbox, under the broker)

function readHanded(path: string, max: number, what: string): Buffer {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK)
  try {
    const st = fstatSync(fd)
    if (!st.isFile()) throw new UsageError(`${what} is not a regular file`)
    if (st.size > max) refuseInputSize(`${what} is larger than ${max} bytes`)
    const b = Buffer.alloc(st.size)
    let off = 0
    while (off < b.length) { const n = readSync(fd, b, off, b.length - off, off); if (n === 0) break; off += n }
    return b.subarray(0, off)
  } finally { closeSync(fd) }
}

async function readStdin(max: number): Promise<Buffer> {
  const chunks: Buffer[] = []
  let n = 0
  for await (const c of process.stdin) {
    const b = Buffer.isBuffer(c) ? c : Buffer.from(c as string)
    n += b.length
    if (n > max) refuseInputSize(`the input on stdin is larger than ${max} bytes`)
    chunks.push(b)
  }
  return Buffer.concat(chunks)
}

function dataChannel(): { send(b: Uint8Array): Promise<void>; close(): Promise<void> } {
  let sock: Socket | null = null
  const open = (): Socket => (sock ??= new Socket({ fd: DATA_FD, readable: false, writable: true }))
  return {
    send: (b) => new Promise<void>((resolve, reject) => {
      const s = open()
      const onErr = (e: Error): void => reject(new Error(`the broker's output channel closed (${e.message.slice(0, 60)})`))
      s.once('error', onErr)
      if (s.write(b)) { s.off('error', onErr); resolve() } else s.once('drain', () => { s.off('error', onErr); resolve() })
    }),
    close: () => new Promise<void>((resolve) => { const s = open(); s.end(() => resolve()) }),
  }
}

export async function decryptMain(argv: readonly string[], o: { network: Network; env: Readonly<Record<string, string | undefined>> }): Promise<number> {
  const { sharedBrokerTty } = await import('./job/tty.ts')
  const ch = dataChannel()
  return runDecrypt(argv, {
    network: o.network,
    input: async (a) => (a.input === null ? readStdin(PASTE_LIMIT) : readHanded(a.input, DECRYPT_LIMITS.input, 'the input file')),
    identity: (p) => readHanded(p, DECRYPT_LIMITS.secret, 'the identity file').toString('utf8'),
    terminal: o.env.VT_BROKER === '1' && o.env.VT_TTY === '1',
    passphrase: () => { const t = sharedBrokerTty(); if (t.agePassphrase === undefined) throw new Error('no passphrase channel'); return t.agePassphrase() },
    fetchRoundSignature: relayFetcher({ network: o.network, port: PORTS[o.network].relay }),
    send: ch.send,
    close: ch.close,
    out: (t) => { process.stdout.write(t) },
    err: (t) => { process.stderr.write(t) },
  })
}

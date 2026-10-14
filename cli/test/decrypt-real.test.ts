// cli/test/decrypt-real.test.ts — `vt decrypt` end to end through the REAL bin/vt, the real broker and the real sandbox-exec, in real ptys
// (`script`, vt-broadcast's runInPty) where a terminal matters:
//   · paste mode: it ends at the end line, at Ctrl-D (an end line without its newline), and is refused before any prompt when it is not
//     armor / SEALED.txt, incomplete, or over 1 MiB; whatever follows a paste is discarded, never left for the shell;
//   · the passphrase comes from the terminal (echo off) even when the input is piped, and appears in NO capture; the plaintext only in --out;
//   · plaintext never lands on a terminal unasked (vt.decrypt-output); --stdout prints it when asked; raw bytes pass unfiltered to a pipe;
//   · every kind with synthetic fixtures: age passphrase (file, paste, pipe), X25519 identity, tlock (a FAKE relay on testnet's relay port
//     serving a made-up chain's signature), SEALED.txt (time lock and identity path): --list (escaped, allowed on a terminal), --only, full
//     extraction checked against MANIFEST.csv / ATTACHMENTS.csv (0700 / 0600), a mismatch writes nothing; vt.relay-down with no relay;
//   · the decrypt sandbox: the relay port only, the handed files only, no writes, no terminal, no token.
// OWN SANDBOX (own-sandbox.list: it applies sandboxes itself). SYNTHETIC data only (core's test fixtures); loopback only: the fake relay
// binds testnet's relay port 127.0.0.1:5191 (local's 5180-5182 may be used by a running stack: never touched here).
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createServer, type Server } from 'node:http'
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { runInPty } from 'vt-broadcast/test/offline/lifecycle/pty.ts'
import { PORTS } from '@vault-timelock/core/contracts'
import { CLI, NODE, PATH0, WRAPPER, connectOutcome, removeDir, tempDir, writeExe } from './lib.ts'
import { denyTerminals } from '../src/ops/sandbox.ts'
import type * as Fixtures from '../../packages/core/test/decrypt/fixtures.ts'

const CORE_TEST = new URL('../../test/', import.meta.resolve('@vault-timelock/core/contracts'))
let F: typeof Fixtures
const PASS = 'decrypt-real-synthetic-passphrase-0001'
const PLAIN = 'synthetic decrypt-real plaintext 7f3c\n'
let T = ''
const at = (n: string): string => join(T, n)
const env = (): Record<string, string> => ({ PATH: PATH0, HOME: at('home'), VT_HOME: at('vt-home'), VAULT_TIMELOCK_DIR: at('out'), LANG: 'en_US.UTF-8', TERM: 'xterm' })
const q = (s: string): string => `'${s.replaceAll("'", "'\\''")}'`
const vt = (args: string[]): string => [WRAPPER, ...args].map(q).join(' ')
// A shell line run in the pty: the command, its exit status, then whatever the terminal still holds for the next reader (must be nothing).
const sh = (line: string): string[] => ['/bin/sh', '-c', `cd ${q(T)} && ${line}; echo "VT-EXIT=$?"; IFS= read -t 1 LEFT || true; echo "LEFTOVER=[$LEFT]"`]
const runVt = (args: string[], o: { input?: string | Buffer; cwd?: string } = {}): { code: number | null; out: Buffer; err: string } => {
  const r = spawnSync(WRAPPER, args, { env: env(), input: o.input ?? '', cwd: o.cwd ?? T, timeout: 120_000 })
  return { code: r.status, out: r.stdout, err: r.stderr.toString('utf8') }
}
// The same, without blocking this process (the fake relay below answers from it).
const runVtAsync = (args: string[]): Promise<{ code: number | null; out: Buffer; err: string }> => new Promise((resolve, reject) => {
  const c = spawn(WRAPPER, args, { env: env(), cwd: T, stdio: ['ignore', 'pipe', 'pipe'] })
  const out: Buffer[] = [], err: Buffer[] = []
  const timer = setTimeout(() => c.kill('SIGKILL'), 120_000)
  c.stdout.on('data', (d: Buffer) => out.push(d)); c.stderr.on('data', (d: Buffer) => err.push(d))
  c.on('error', reject)
  c.on('close', (code) => { clearTimeout(timer); resolve({ code, out: Buffer.concat(out), err: Buffer.concat(err).toString('utf8') }) })
})
const sha = (s: string | Uint8Array): string => createHash('sha256').update(s).digest('hex')
const mode = (p: string): number => lstatSync(p).mode & 0o777
const plainOut = (out: string): string => out.replace(/\r/g, '')

let ID = { identity: '', recipient: '' }
let SCRYPT_ARMOR = ''
before(async () => {
  F = await import(new URL('decrypt/fixtures.ts', CORE_TEST).href) as typeof Fixtures
  T = tempDir('vt-decrypt-real-')
  for (const d of ['home', 'vt-home', 'out']) mkdirSync(at(d), { mode: 0o700 })
  SCRYPT_ARMOR = F.armor(await F.passphraseBin(PLAIN, PASS))
  writeFileSync(at('p.age.txt'), SCRYPT_ARMOR)
  ID = await F.newIdentity()
  writeFileSync(at('id.txt'), F.keygenFile(ID.identity, ID.recipient))
  // binary plaintext with an ESC sequence, NUL and 0xff: the --stdout sink must pass it raw
  writeFileSync(at('x.age'), await F.identityBin(Buffer.from([0x1b, 0x5d, 0x35, 0x32, 0x3b, 0x00, 0xff, 0x0a]), ID.recipient))
})
after(() => removeDir(T))

// ---- paste mode (pty)

test('paste: armor ends AT its end line, then the BROKER asks the passphrase (echo off); the passphrase and the plaintext appear in no capture; --out is 0600; the rest of the paste never reaches the shell', { timeout: 120_000 }, async () => {
  const r = await runInPty(sh(vt(['decrypt', '--out', 'pasted.txt'])), { env: env(), steps: [
    { waitFor: 'Ctrl-D', send: `${SCRYPT_ARMOR}printf 'X%sY\\n' Z\n` },
    { waitFor: 'Passphrase: ', send: `${PASS}\r` },
  ] })
  const out = plainOut(r.out)
  assert.match(out, /VT-EXIT=0/, out)
  assert.match(out, /\[vt broker\] passphrase of the pasted age file \(age scrypt\)/)
  assert.ok(!out.includes(PASS), 'the passphrase is in no capture')
  assert.ok(!out.includes(PLAIN.trim()), 'the plaintext went to --out only')
  assert.equal(readFileSync(at('pasted.txt'), 'utf8'), PLAIN)
  assert.equal(mode(at('pasted.txt')), 0o600)
  assert.ok(!out.includes('XZY'), 'the line after the paste was never run')
  assert.match(out, /LEFTOVER=\[\]/, 'nothing was left in the terminal for the shell')
})

test('paste: Ctrl-D — after an end line typed without its newline it completes; before the end line, or on nothing, it is refused BEFORE any prompt', { timeout: 120_000 }, async () => {
  const ok = await runInPty(sh(vt(['decrypt', '--out', 'ctrl-d.txt'])), { env: env(), steps: [
    { waitFor: 'Ctrl-D', send: SCRYPT_ARMOR.trimEnd() }, { waitFor: '-----END AGE ENCRYPTED FILE-----', send: '\u0004' },
    { waitFor: 'Passphrase: ', send: `${PASS}\r` },
  ] })
  assert.match(plainOut(ok.out), /VT-EXIT=0/, ok.out)
  assert.equal(readFileSync(at('ctrl-d.txt'), 'utf8'), PLAIN)
  for (const [name, paste] of [['incomplete', SCRYPT_ARMOR.split('\n').slice(0, 2).join('\n') + '\n\u0004'], ['empty', '\u0004']] as const) {
    const r = await runInPty(sh(vt(['decrypt', '--out', `never-${name}.txt`])), { env: env(), steps: [{ waitFor: 'Ctrl-D', send: paste }] })
    const out = plainOut(r.out)
    assert.match(out, /refused decrypt\.format: /, `${name}: ${out}`)
    assert.match(out, /VT-EXIT=2/)
    assert.ok(!out.includes('Passphrase') && !out.includes('passphrase of'), `${name}: no prompt`)
    assert.equal(existsSync(at(`never-${name}.txt`)), false)
  }
})

test('paste: not armor / SEALED.txt is refused at its FIRST line, before any prompt; the rest of the paste is discarded, never run by the shell', { timeout: 120_000 }, async () => {
  const r = await runInPty(sh(vt(['decrypt', '--out', 'never.txt'])), { env: env(), steps: [{ waitFor: 'Ctrl-D', send: "this is not armor\nprintf 'X%sY\\n' Z\nmore text\n" }] })
  const out = plainOut(r.out)
  assert.match(out, /refused decrypt\.format: the pasted text is not age armor/, out)
  assert.ok(!out.includes('Passphrase') && !out.includes('passphrase of'))
  assert.ok(!out.includes('XZY'))
  assert.match(out, /LEFTOVER=\[\]/)
})

test('paste: over 1 MiB is refused (decrypt.size) before any prompt; the rest is discarded', { timeout: 180_000 }, async () => {
  const line = `${'A'.repeat(63)}\n`
  const big = `${SCRYPT_ARMOR.split('\n')[0]}\n${line.repeat(Math.ceil((1024 * 1024) / line.length) + 64)}`
  const r = await runInPty(sh(vt(['decrypt', '--out', 'never-big.txt'])), { env: env(), timeoutMs: 170_000, steps: [{ waitFor: 'Ctrl-D', send: big }] })
  const out = plainOut(r.out)
  assert.match(out, /refused decrypt\.size: the pasted input is larger than 1048576 bytes/, out.slice(-500))
  assert.ok(!out.includes('Passphrase'))
  assert.match(out, /LEFTOVER=\[\]/)
  assert.equal(existsSync(at('never-big.txt')), false)
})

test('a PIPED input still gets its passphrase from the terminal (the broker, echo off), never from the pipe', { timeout: 120_000 }, async () => {
  const r = await runInPty(sh(`cat p.age.txt | ${vt(['decrypt', '-', '--out', 'piped.txt'])}`), { env: env(), steps: [{ waitFor: 'Passphrase: ', send: `${PASS}\r` }] })
  const out = plainOut(r.out)
  assert.match(out, /VT-EXIT=0/, out)
  assert.match(out, /passphrase of the piped age file/)
  assert.ok(!out.includes(PASS))
  assert.equal(readFileSync(at('piped.txt'), 'utf8'), PLAIN)
  // without any terminal: refused, nothing asked
  const n = runVt(['decrypt', '-', '--out', 'never-pipe.txt'], { input: SCRYPT_ARMOR })
  assert.equal(n.code, 2); assert.match(n.err, /^refused vt\.tty-required: /m)
})

// ---- where the plaintext goes

test('vt.decrypt-output: plaintext never lands on a terminal unasked; --stdout prints it when asked; to a pipe the bytes pass RAW (no output filter)', { timeout: 120_000 }, async () => {
  const r = await runInPty(sh(vt(['decrypt', 'x.age', '--identity', 'id.txt'])), { env: env(), steps: [] })
  assert.match(plainOut(r.out), /refused vt\.decrypt-output: the plaintext would be printed on this terminal/)
  const p = runVt(['decrypt', 'p.age.txt'])
  assert.equal(p.code, 2); assert.match(p.err, /^refused vt\.decrypt-output: say where the plaintext goes/m)
  const asked = await runInPty(sh(vt(['decrypt', 'p.age.txt', '--stdout'])), { env: env(), steps: [{ waitFor: 'Passphrase: ', send: `${PASS}\r` }] })
  assert.ok(plainOut(asked.out).includes(PLAIN.trim()), 'asked: shown')
  const raw = runVt(['decrypt', 'x.age', '--identity', 'id.txt', '--stdout'])
  assert.equal(raw.code, 0, raw.err)
  assert.deepEqual([...raw.out], [0x1b, 0x5d, 0x35, 0x32, 0x3b, 0x00, 0xff, 0x0a])
  assert.ok(!raw.err.includes(ID.identity), 'the identity is never printed')
  // --out never overwrites
  writeFileSync(at('taken.txt'), 'theirs')
  const t = runVt(['decrypt', 'x.age', '--identity', 'id.txt', '--out', 'taken.txt'])
  assert.equal(t.code, 2); assert.match(t.err, /^refused vt\.out-exists: /m)
  assert.equal(readFileSync(at('taken.txt'), 'utf8'), 'theirs')
})

// ---- SEALED.txt: --list, --only, full extraction

function vault(o: { tamper?: boolean; names?: string[] } = {}): Record<string, string> {
  const files: Record<string, string> = { 'items/aaaa.json': '{"synthetic":"one"}\n', 'items/bbbb.json': '{"synthetic":"two"}\n', 'files/aaaa/ffff': 'synthetic attachment\n' }
  for (const n of o.names ?? []) files[n] = 'synthetic odd name\n'
  const m = `item_id,sha256,field_count,section_count,file_count\naaaa,${sha(files['items/aaaa.json'])},1,0,1\nbbbb,${sha(files['items/bbbb.json'])},1,0,0\n`
  const a = `item_id,file_id,bytes,sha256\naaaa,ffff,${Buffer.byteLength(files['files/aaaa/ffff'])},${sha(files['files/aaaa/ffff'])}\n`
  if (o.tamper) files['items/bbbb.json'] = '{"synthetic":"edited"}\n'
  return { ...files, 'MANIFEST.csv': m, 'ATTACHMENTS.csv': a }
}

test('SEALED.txt by the identity path: --list on a TERMINAL (escaped names, no contents), --only, full extraction (0700 / 0600, manifests checked); a mismatch writes nothing', { timeout: 180_000 }, async () => {
  const odd = 'extra/r\u202etxt.exe'   // outside items/ and files/: no manifest row is needed
  const files = vault({ names: [odd] })
  const s = await F.makeSealed({ vaultFiles: files })
  writeFileSync(at('S.txt'), s.sealed)
  writeFileSync(at('onetime.key'), `${s.identity}\n`)
  const l = await runInPty(sh(vt(['decrypt', 'S.txt', '--identity', 'onetime.key', '--list'])), { env: env(), steps: [] })
  const lo = plainOut(l.out)
  assert.match(lo, /VT-EXIT=0/, lo)
  assert.match(lo, /extra\/r\[U\+202E\]txt\.exe/)
  assert.match(lo, /\b20 {2}items\/bbbb\.json\b/)
  assert.ok(!lo.includes('synthetic attachment') && !lo.includes('"synthetic"'), 'no contents')
  assert.ok(!lo.includes(String(s.identity)))
  const one = runVt(['decrypt', 'S.txt', '--identity', 'onetime.key', '--only', 'extra/r[U+202E]txt.exe', '--out', 'one.bin'])
  assert.equal(one.code, 0, one.err)
  assert.equal(readFileSync(at('one.bin'), 'utf8'), files[odd])
  const full = runVt(['decrypt', 'S.txt', '--identity', 'onetime.key', '--out', 'restored'])
  assert.equal(full.code, 0, full.err)
  assert.match(full.err, /MANIFEST\.csv: 2 item\(s\) match; ATTACHMENTS\.csv: 1 attachment\(s\) match/)
  for (const [p, body] of Object.entries(files)) { assert.equal(readFileSync(join(at('restored'), p), 'utf8'), body, p); assert.equal(mode(join(at('restored'), p)), 0o600, p) }
  for (const d of ['', 'items', 'files', 'files/aaaa']) assert.equal(mode(join(at('restored'), d)), 0o700, d)
  // a package whose archive differs from its MANIFEST.csv: refused, nothing written
  const bad = await F.makeSealed({ vaultFiles: vault({ tamper: true }) })
  writeFileSync(at('BAD.txt'), bad.sealed); writeFileSync(at('bad.key'), `${bad.identity}\n`)
  const b = runVt(['decrypt', 'BAD.txt', '--identity', 'bad.key', '--out', 'never-restored'])
  assert.equal(b.code, 2); assert.match(b.err, /^refused vt\.manifest: /m)
  assert.equal(existsSync(at('never-restored')), false)
})

test('M-5 through the real broker: an archive holding `A` and `a` (and NFC / NFD \u00e9) is refused at the second, and nothing is kept', { timeout: 120_000 }, async () => {
  for (const [name, a, b] of [['case', 'items/A', 'items/a'], ['nfd', 'items/caf\u00e9', 'items/cafe\u0301']] as const) {
    const s = await F.makeSealed({ vaultFiles: [[a, 'first\n'], [b, 'second\n']] })
    writeFileSync(at(`M5-${name}.txt`), s.sealed); writeFileSync(at(`m5-${name}.key`), `${s.identity}\n`)
    const r = runVt(['decrypt', `M5-${name}.txt`, '--identity', `m5-${name}.key`, '--out', `m5-${name}`])
    assert.equal(r.code, 2, r.err); assert.match(r.err, /^refused vt\.out-exists: /m)
    assert.equal(existsSync(at(`m5-${name}`)), false, name)
  }
})

// ---- tlock through the running stack's relay

async function fakeRelay(port: number): Promise<{ server: Server; hits: string[] }> {
  const hits: string[] = []
  const server = createServer((req, res) => {
    hits.push(`${req.method} ${req.url} host=${req.headers.host}`)
    const m = /^\/relay\/drand\/([0-9a-f]{64})\/public\/(\d+)$/.exec(req.url ?? '')
    const round = m === null ? 0 : Number(m[2])
    if (m === null || round !== F.PAST_ROUND) { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{"error":{"message":"this drand round is not published yet"}}'); return }
    const signature = F.signatureFor(round)
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ round, randomness: sha(Buffer.from(signature, 'hex')), signature }))
  })
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', () => resolve()) }).catch((e: NodeJS.ErrnoException) => {
    throw new Error(`testnet's relay port ${port} is taken (${e.code}): another stack runs; this test needs it free (deferred, not run)`)
  })
  return { server, hits }
}

test('tlock: the round\'s signature comes through the network\'s relay (a FAKE relay on testnet\'s port, a made-up chain); a SEALED.txt opens by its time lock; with no relay: vt.relay-down', { timeout: 180_000 }, async () => {
  const port = PORTS.testnet.relay
  writeFileSync(at('t.age.txt'), F.armor(await F.tlockBin(F.PAST_ROUND, PLAIN)))
  const s = await F.makeSealed({ vaultFiles: vault() })
  writeFileSync(at('TS.txt'), s.sealed)
  const { server, hits } = await fakeRelay(port)
  try {
    const r = await runVtAsync(['--network', 'testnet', 'decrypt', 't.age.txt', '--out', 'tl.txt'])
    assert.equal(r.code, 0, r.err)
    assert.equal(readFileSync(at('tl.txt'), 'utf8'), PLAIN)
    assert.match(r.err, /through its time lock \(drand round 1000000/)
    assert.deepEqual(hits, [`GET /relay/drand/${F.SYNTH_INFO.hash}/public/${F.PAST_ROUND} host=127.0.0.1:${port}`])
    const sd = await runVtAsync(['--network', 'testnet', 'decrypt', 'TS.txt', '--out', 'tl-restored'])
    assert.equal(sd.code, 0, sd.err)
    assert.deepEqual(readdirSync(at('tl-restored')).sort(), ['ATTACHMENTS.csv', 'MANIFEST.csv', 'files', 'items'])
    // before its round: refused by the clock, the relay is not asked
    writeFileSync(at('future.age.txt'), F.armor(await F.tlockBin(F.FUTURE_ROUND, PLAIN)))
    const n = hits.length
    const f = await runVtAsync(['--network', 'testnet', 'decrypt', 'future.age.txt', '--out', 'never-future.txt'])
    assert.equal(f.code, 2); assert.match(f.err, /^refused decrypt\.too-early: too early: this time lock opens at 2100-/m)
    assert.equal(hits.length, n)
  } finally {
    server.closeAllConnections()
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }
  assert.equal(await connectOutcome(port), 'ECONNREFUSED', 'nothing listens on testnet\'s relay port now')
  const d = await runVtAsync(['--network', 'testnet', 'decrypt', 't.age.txt', '--out', 'never-down.txt'])
  assert.equal(d.code, 2)
  assert.match(d.err, /^refused vt\.relay-down: the testnet relay is not running: .*vt up --network testnet/m)
  assert.ok(!/\b127\.0\.0\.1\b/.test(d.err), 'no address printed')
  assert.equal(existsSync(at('never-down.txt')), false)
})

// ---- the broker's decrypt policy against a child that asks what it may not (a fake child under the real sandbox-exec, in a pty)

test('broker policy for decrypt: ONE age passphrase for a scrypt input (a second is refused and the child killed); for an X25519 input no prompt channel at all; no output is left', { timeout: 120_000 }, async () => {
  const BROKER = join(CLI, 'src', 'ops', 'broker.ts')
  const TTYJS = join(CLI, 'src', 'job', 'tty.ts')
  const child = (name: string, body: string): string => {
    const js = at(`${name}.mjs`)
    writeFileSync(js, `import { brokerTty } from ${JSON.stringify(TTYJS)}\nconst tty = brokerTty()\n${body}\nconsole.log('CHILD-SURVIVED')\nprocess.exit(0)\n`)
    writeExe(at(name), `#!/bin/sh\nexec ${JSON.stringify(NODE)} --disable-sigusr1 --no-addons ${JSON.stringify(js)}\n`)
    return at(name)
  }
  const brokerLine = (launcher: string, args: string[]): string => [NODE, '--disable-sigusr1', BROKER, '/usr/bin/sandbox-exec', `(version 1)(allow default)${denyTerminals()}`, launcher, ...args].map(q).join(' ')
  const twice = child('age-twice', `const a = await tty.agePassphrase(); console.log('GOT-LEN ' + a.length); await tty.agePassphrase()`)
  const r = await runInPty(sh(brokerLine(twice, ['decrypt', at('p.age.txt'), '--out', at('never-twice.txt')])), { env: env(), steps: [{ waitFor: 'Passphrase: ', send: `${PASS}\r` }, { waitFor: 'Press Enter', send: '\r' }] })
  const out = plainOut(r.out)
  assert.match(out, /GOT-LEN 38/, out)
  assert.match(out, /refused: the sandboxed command asked for something its command may not ask \(the passphrase a second time\)/)
  assert.match(out, /VT-EXIT=2/)
  assert.ok(!out.includes('CHILD-SURVIVED') && !out.includes(PASS))
  assert.equal(existsSync(at('never-twice.txt')), false)
  const x = child('age-x25519', `await tty.agePassphrase()`)
  const r2 = await runInPty(sh(brokerLine(x, ['decrypt', at('x.age'), '--identity', at('id.txt'), '--out', at('never-x.txt')])), { env: env(), steps: [] })
  const out2 = plainOut(r2.out)
  assert.match(out2, /this command has no prompt channel/, out2)
  assert.ok(!out2.includes('Passphrase: ') && !out2.includes('[vt broker] passphrase'), out2)
  assert.equal(existsSync(at('never-x.txt')), false)
})

// ---- the decrypt sandbox itself

test('the decrypt sandbox (real profile): reads only the handed files, writes nothing, reaches the RELAY port only, no API token, no terminal', { timeout: 120_000 }, async () => {
  const pd = at('probe-bin')
  mkdirSync(pd)
  writeFileSync(at('sibling-not-handed.txt'), 'synthetic')
  mkdirSync(join(at('vt-home'), 'testnet'), { recursive: true })
  writeFileSync(join(at('vt-home'), 'testnet', 'api.token'), 'cd'.repeat(32), { mode: 0o600 })
  const p = PORTS.testnet
  writeExe(join(pd, 'node'), `#!${NODE}
const { spawnSync } = require('node:child_process')
const argv = process.argv.slice(2)
const flags = []
while (argv.length > 0 && argv[0].startsWith('--')) flags.push(argv.shift())
const [cli, ...args] = argv
if (typeof cli === 'string' && (cli.endsWith('/src/ops/profile.ts') || cli.endsWith('/src/ops/broker.ts'))) {
  const r = spawnSync(${JSON.stringify(NODE)}, [...flags, cli, ...args], { stdio: 'inherit', env: process.env }); process.exit(r.status ?? 1)
}
const fs = require('node:fs'), net = require('node:net')
const read = (f) => { try { fs.readFileSync(f); return 'ok' } catch (e) { return e.code } }
const tcp = (port) => new Promise((res) => { const s = net.connect({ host: '127.0.0.1', port }); s.on('connect', () => { s.destroy(); res('connected') }); s.on('error', (e) => res(e.code)) })
;(async () => {
  const out = {
    input: read(args[1]), identity: read(args[3]), sibling: read(${JSON.stringify(at('sibling-not-handed.txt'))}),
    token: read(${JSON.stringify(join(at('vt-home'), 'testnet', 'api.token'))}),
    write: (() => { try { fs.writeFileSync(${JSON.stringify(at('written-by-child.txt'))}, 'x'); return 'ok' } catch (e) { return e.code } })(),
    tty: (() => { try { fs.closeSync(fs.openSync('/dev/tty', fs.constants.O_RDWR | fs.constants.O_NOCTTY)); return 'ok' } catch (e) { return e.code } })(),
    relay: await tcp(${p.relay}), api: await tcp(${p.api}), page: await tcp(${p.page}),
  }
  process.stdout.write(JSON.stringify({ confined: process.env.VT_CONFINED, out }) + '\\n')
})()
`)
  const r = spawnSync(WRAPPER, ['--network', 'testnet', 'decrypt', 'x.age', '--identity', 'id.txt', '--list'], { env: { ...env(), PATH: `${pd}:${PATH0}` }, cwd: T, encoding: 'utf8', timeout: 120_000 })
  assert.equal(r.status, 0, r.stderr)
  const got = JSON.parse(r.stdout) as { confined: string; out: Record<string, string> }
  assert.equal(got.confined, '1')
  assert.deepEqual(got.out, { input: 'ok', identity: 'ok', sibling: 'EPERM', token: 'EPERM', write: 'EPERM', tty: 'EPERM', relay: got.out.relay === 'connected' ? 'connected' : 'ECONNREFUSED', api: 'EPERM', page: 'EPERM' })
  assert.notEqual(got.out.relay, 'EPERM', 'the relay port is reachable')
  assert.equal(existsSync(at('written-by-child.txt')), false)
})

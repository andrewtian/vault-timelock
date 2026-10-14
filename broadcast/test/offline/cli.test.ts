import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'

const CLI = new URL('../../src/cli.ts', import.meta.url).pathname

function run(args: string[], stdin: Uint8Array | string) {
  const r = spawnSync(process.execPath, [CLI, ...args], { input: stdin, encoding: 'utf8' })
  return { code: r.status, out: r.stdout, err: r.stderr }
}

test('ok <byteLength>, never echoes the note', () => {
  const note = 'secret café note'
  const r = run(['validate-note'], note)
  assert.equal(r.code, 0)
  assert.equal(r.out, `ok ${Buffer.byteLength(note)}\n`)
  assert.ok(!r.out.includes('secret'))
  assert.ok(!r.err.includes('secret'))
})

test('refusal: exit 2, guard id on stderr, stdout empty', () => {
  const r = run(['validate-note'], Uint8Array.from([0xc3, 0x28]))
  assert.equal(r.code, 2)
  assert.match(r.err, /^refused note\.utf8: /)
  assert.equal(r.out, '')
})

test('refusal does not echo the note', () => {
  const r = run(['validate-note'], 'topsecret\r')
  assert.equal(r.code, 2)
  assert.match(r.err, /^refused note\.control: /)
  assert.ok(!r.err.includes('topsecret'))
})

test('env-names: the sorted NAMES of the environment, one per line, never a value', () => {
  const r = spawnSync(process.execPath, [CLI, 'env-names'], {
    encoding: 'utf8',
    env: { PATH: process.env.PATH ?? '', HOME: '/tmp', ZZ_LAST: 'v-secret-1', AA_FIRST: 'v-secret-2', MM: '' },
  })
  assert.equal(r.status, 0)
  assert.equal(r.stderr, '')
  const names = r.stdout.trim().split('\n')
  // __CF_USER_TEXT_ENCODING is synthesised by macOS inside the child (feasibility/F5.txt).
  assert.deepEqual(names.filter((n) => n !== '__CF_USER_TEXT_ENCODING'), ['AA_FIRST', 'HOME', 'MM', 'PATH', 'ZZ_LAST'])
  assert.ok(!r.stdout.includes('v-secret') && !r.stdout.includes('='))
})

test('empty stdin refused', () => {
  const r = run(['validate-note'], '')
  assert.equal(r.code, 2)
  assert.match(r.err, /^refused note\.empty: /)
})

test('--max-bytes cap', () => {
  assert.equal(run(['validate-note', '--max-bytes', '5'], 'abcde').out, 'ok 5\n')
  const r = run(['validate-note', '--max-bytes', '5'], 'abcdef')
  assert.equal(r.code, 2)
  assert.match(r.err, /^refused cli\.max-bytes: /)
})

test('bad --max-bytes value, unknown flag, unknown subcommand: exit 64', () => {
  for (const args of [['validate-note', '--max-bytes', 'x'], ['validate-note', '--max-bytes'], ['validate-note', '--bogus'], ['nope'], [], ['validate-note', 'extra'], ['env-names', 'x'], ['tor-check', 'x']]) {
    const r = run(args, 'abc')
    assert.equal(r.code, 64, JSON.stringify(args))
    assert.match(r.err, /usage/i)
    assert.equal(r.out, '')
  }
})

// ---- seal-text -------------------------------------------------------------
import { mkdtempSync, readFileSync, writeFileSync, existsSync, readdirSync, chmodSync, statSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { buildSealed } from '../../src/sealed.ts'
import { AR, makePkg } from './fixtures.ts'

test('seal-text prints exactly the sealed text on stdout', () => {
  const { dir } = makePkg('two-layer')
  const r = run(['seal-text', dir], '')
  assert.equal(r.code, 0)
  assert.equal(r.err, '')
  assert.ok(r.out.startsWith('== vault-timelock sealed package: self-contained, age + drand timelock ==\n'))
  assert.ok(r.out.endsWith('== end ==\n'))
  assert.equal(r.out, buildSealed(dir, { contents: 'full' }))
  assert.equal(readdirSync(dir).includes('SEALED.txt'), false)
})

test('seal-text --contents key-only --ar prints the key-only form (stdout only)', () => {
  const { dir } = makePkg('two-layer')
  const r = run(['seal-text', dir, '--contents', 'key-only', '--ar', AR], '')
  assert.equal(r.code, 0)
  assert.ok(r.out.includes(`contents: key-only (payload: ar://${AR})\n`))
  const r2 = run(['seal-text', dir, '--contents', 'key-only'], '')
  assert.equal(r2.code, 2)
  assert.match(r2.err, /^refused sealed\.key-only-needs-ar: /)
  assert.equal(r2.out, '')
})

test('seal-text --write: creates 0644 file, prints only the wrote line, idempotent', () => {
  const { dir } = makePkg('two-layer')
  const target = join(dir, 'SEALED.txt')
  const r = run(['seal-text', dir, '--write'], '')
  assert.equal(r.code, 0)
  assert.equal(r.err, '')
  const bytes = readFileSync(target)
  assert.equal(r.out, `wrote ${target} ${bytes.length}\n`)
  assert.equal(statSync(target).mode & 0o777, 0o644)
  assert.equal(bytes.toString('utf8'), buildSealed(dir, { contents: 'full' }))
  assert.ok(bytes.toString('utf8').includes('\ncontents: full\n'))
  assert.deepEqual(readdirSync(dir).filter((n) => n.includes('tmp')), [])
  const r2 = run(['seal-text', dir, '--write'], '')
  assert.equal(r2.code, 0)
  assert.equal(r2.out, r.out)
  assert.ok(readFileSync(target).equals(bytes))
})

test('seal-text --write refuses to overwrite a differing SEALED.txt', () => {
  const { dir } = makePkg('two-layer')
  const target = join(dir, 'SEALED.txt')
  writeFileSync(target, 'operator edited\n')
  const r = run(['seal-text', dir, '--write'], '')
  assert.equal(r.code, 2)
  assert.match(r.err, /^refused sealed\.exists-differs: /)
  assert.equal(r.out, '')
  assert.equal(readFileSync(target, 'utf8'), 'operator edited\n')
})

test('S3: seal-text --write on a package holding STRUCTURE.txt: SEALED.txt never carries it, nothing echoes it, STRUCTURE.txt is untouched', () => {
  const canary = 'ZZCANARYS3CLI'
  const body = `== vault-timelock structure: shape only, every value removed (LOCAL ONLY, never published) ==\n${canary}\n== end ==\n`
  const { dir } = makePkg('two-layer', { extra: { 'STRUCTURE.txt': body } })
  const r = run(['seal-text', dir, '--write'], '')
  assert.equal(r.code, 0)
  const sealed = readFileSync(join(dir, 'SEALED.txt'), 'utf8')
  assert.equal(sealed, buildSealed(makePkg('two-layer').dir, { contents: 'full' }), 'the same text as a package without STRUCTURE.txt')
  assert.ok(!sealed.includes(canary) && !sealed.includes('STRUCTURE'))
  assert.ok(!r.out.includes(canary) && !r.err.includes(canary))
  assert.equal(readFileSync(join(dir, 'STRUCTURE.txt'), 'utf8'), body)
})

test('SP: seal-text --write on a package holding SEALED-plaintext.txt: SEALED.txt never carries it, nothing echoes it, SEALED-plaintext.txt is untouched', () => {
  const canary = 'ZZCANARYSPCLI'
  const body = `== vault-timelock plaintext: every entry, decrypted (LOCAL ONLY — contains secrets) ==\n  password : ${canary}\n== end (1 items, 0 files) ==\n`
  const { dir } = makePkg('two-layer', { extra: { 'SEALED-plaintext.txt': body } })
  const r = run(['seal-text', dir, '--write'], '')
  assert.equal(r.code, 0)
  const sealed = readFileSync(join(dir, 'SEALED.txt'), 'utf8')
  assert.equal(sealed, buildSealed(makePkg('two-layer').dir, { contents: 'full' }), 'the same text as a package without SEALED-plaintext.txt')
  assert.ok(!sealed.includes(canary) && !sealed.includes('SEALED-plaintext'))
  assert.ok(!r.out.includes(canary) && !r.err.includes(canary))
  assert.equal(readFileSync(join(dir, 'SEALED-plaintext.txt'), 'utf8'), body)
})

test('R16: --write with key-only refuses and writes nothing', () => {
  const { dir } = makePkg('two-layer')
  const r = run(['seal-text', dir, '--write', '--contents', 'key-only', '--ar', AR], '')
  assert.equal(r.code, 2)
  assert.match(r.err, /^refused sealed\.write-full-only: /)
  assert.equal(r.out, '')
  assert.equal(existsSync(join(dir, 'SEALED.txt')), false)
})

test('seal-text usage errors: exit 64, empty stdout', () => {
  const { dir } = makePkg('two-layer')
  for (const args of [['seal-text'], ['seal-text', dir, '--bogus'], ['seal-text', dir, '--contents', 'x'], ['seal-text', dir, 'extra'], ['seal-text', dir, '--ar']]) {
    const r = run(args, '')
    assert.equal(r.code, 64, JSON.stringify(args))
    assert.equal(r.out, '')
  }
})

test('seal-text refusals from the builder surface as exit 2', () => {
  const e = mkdtempSync(join(tmpdir(), 'vt-empty-'))
  const r = run(['seal-text', e], '')
  assert.equal(r.code, 2)
  assert.match(r.err, /^refused sealed\.format: /)
  rmSync(e, { recursive: true })
})

test('generic exit-1 path: a non-Refusal error prints only the fixed generic text', () => {
  const { dir } = makePkg('two-layer')
  chmodSync(dir, 0o555) // read-only dir: the atomic write throws EACCES (not a Refusal)
  try {
    const r = run(['seal-text', dir, '--write'], '')
    assert.equal(r.code, 1)
    assert.equal(r.err, 'error: unexpected failure\n')
    assert.equal(r.out, '')
    assert.ok(!r.err.includes(dir) && !r.err.includes('EACCES'))
  } finally { chmodSync(dir, 0o755) }
})

test('R32: non-ASCII note warns on stderr, still ok on stdout, exit 0', () => {
  const note = 'caf\u00e9 \u2603' // 2 non-ASCII chars
  const r = run(['validate-note'], note)
  assert.equal(r.code, 0)
  assert.equal(r.out, `ok ${Buffer.byteLength(note)}\n`)
  assert.equal(r.err, 'warn note.non-ascii: 2 non-ASCII chars (Solana memo cost; explorer rendering)\n')
  assert.ok(!r.err.includes('caf'))
})

test('R32: ASCII note prints no warning', () => {
  const r = run(['validate-note'], 'plain ascii')
  assert.equal(r.code, 0)
  assert.equal(r.err, '')
})

// Task B-SIGUSR1: a node started with an inspector is refused at the entry point (cli.inspector). Options that
// do not open a listener (--inspect-port, --debug-port) are used where possible; --inspect-brk would wait for a
// debugger, so it is never started, and the refusal is also checked on a NODE_OPTIONS value (which node accepts).
const BASE_ENV = { PATH: process.env.PATH ?? '', HOME: '/tmp' }
function inspectorRun(execArgv: string[], nodeOptions?: string) {
  const env: Record<string, string> = { ...BASE_ENV }
  if (nodeOptions !== undefined) env.NODE_OPTIONS = nodeOptions
  const r = spawnSync(process.execPath, [...execArgv, CLI, 'env-names'], { encoding: 'utf8', env, timeout: 30_000 })
  return { code: r.status, out: r.stdout, err: r.stderr }
}

test('cli.inspector: an inspector option on the command line is refused (exit 2, one line, nothing runs)', () => {
  for (const opt of ['--inspect-port=0', '--inspect=127.0.0.1:0', '--debug-port=0']) {
    const r = inspectorRun([opt])
    assert.equal(r.code, 2, opt)
    assert.match(r.err, /^refused cli\.inspector: /m, opt)
    assert.equal(r.out, '', `${opt}: the command did not run`)
  }
})

test('cli.inspector: an inspector option in NODE_OPTIONS is refused', () => {
  for (const o of ['--inspect-port=0', '--no-warnings --inspect-port=0', '--inspect=127.0.0.1:0']) {
    const r = inspectorRun([], o)
    assert.equal(r.code, 2, o)
    assert.match(r.err, /^refused cli\.inspector: /m, o)
    assert.equal(r.out, '', `${o}: the command did not run`)
  }
})

test('cli.inspector: harmless node options and NODE_OPTIONS still run', () => {
  assert.equal(inspectorRun(['--disable-sigusr1', '--no-warnings']).code, 0)
  assert.equal(inspectorRun([], '--no-warnings').code, 0)
})

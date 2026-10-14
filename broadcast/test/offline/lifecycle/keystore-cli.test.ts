// Task 12b: `vt-broadcast keystore init` end to end (src/cli.ts), on a pty, the way the operator runs it. This file holds
// the ONE production-path test (controller ruling 3): no test-only option exists on this path, so master.age carries
// the production scrypt work factor, logN 18, and the real `age -d` opens it with the passphrase typed on a pty (the
// interop proof). Synthetic passphrase; temp HOME, VAULT_TIMELOCK_DIR and TMPDIR. Every child either runs on its own
// pty (script(1)) or detached with no controlling terminal, so none can reach the operator's terminal.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { identityToRecipient } from 'age-encryption'
import { keystoreDir, lifecycleDir } from '../../../src/lifecycle/paths.ts'
import { assertNoSecretsInStore } from './helpers.ts'
import { runInPty } from './pty.ts'

const CLI = new URL('../../../src/cli.ts', import.meta.url).pathname
const PASS = 'abiding ablaze able ability abacus abide' // synthetic: 6 EFF words

interface Env { d: string; out: string; env: Record<string, string> }
async function withEnv<T>(f: (e: Env) => Promise<T>, profile?: string): Promise<T> {
  const d = mkdtempSync(join(tmpdir(), 'vt-12b-cli-'))
  try {
    for (const sub of ['home', 'tmp']) mkdirSync(join(d, sub), { mode: 0o700 })
    const out = join(d, 'out')
    const env: Record<string, string> = {
      PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: join(d, 'home'), LANG: 'en_US.UTF-8', TERM: 'dumb',
      TMPDIR: join(d, 'tmp'), VAULT_TIMELOCK_DIR: out,
    }
    if (profile !== undefined) env.VT_PROFILE = profile
    return await f({ d, out, env })
  } finally { rmSync(d, { recursive: true, force: true }) }
}

// No controlling terminal (detached = setsid): a refusal that should come before any prompt.
function runDetached(args: string[], env: Record<string, string>): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((res) => {
    const c = spawn(process.execPath, ['--disable-sigusr1', CLI, ...args], { env, stdio: ['ignore', 'pipe', 'pipe'], detached: true })
    let out = ''
    let err = ''
    c.stdout.on('data', (b: Buffer) => { out += b.toString('utf8') })
    c.stderr.on('data', (b: Buffer) => { err += b.toString('utf8') })
    c.on('close', (code) => res({ code, out, err }))
  })
}

const twice = (a: string, b: string = a) => [{ waitFor: 'Passphrase: ', send: a + '\r' }, { waitFor: 'Repeat passphrase: ', send: b + '\r' }]

test('keystore init on a pty: asks twice without echo, prints only "keystore initialized: <master.pub>"; master.age is scrypt logN 18 and `age -d` opens it', { timeout: 180_000 }, async () => {
  await withEnv(async ({ d, out, env }) => {
    const r = await runInPty([process.execPath, '--disable-sigusr1', CLI, 'keystore', 'init'], { env, steps: twice(PASS), timeoutMs: 150_000 })
    const dir = keystoreDir(out)
    const pub = readFileSync(join(dir, 'master.pub'), 'utf8')
    assert.equal(r.code, 0, 'exit status')
    assert.ok(!r.out.includes(PASS) && !r.out.includes('ablaze'), 'the passphrase was echoed')
    // Everything the command printed: its two prompts (to /dev/tty) and the one line on stdout.
    const printed = r.out.replace(/\r/g, '').split('\n').map((l) => l.trim()).filter((l) => l !== '')
    assert.deepEqual(printed, ['Passphrase:', 'Repeat passphrase:', `keystore initialized: ${pub.trim()}`])
    assert.match(pub, /^age1[02-9ac-hj-np-z]{58}\n$/)
    assert.equal(readFileSync(join(dir, 'profile'), 'utf8'), 'testnet\n')
    assert.equal(statSync(join(lifecycleDir(out), 'trigger')).mode & 0o777, 0o700)

    // The production work factor, read from the scrypt stanza `-> scrypt <salt> <logN>`.
    const header = readFileSync(join(dir, 'master.age'), 'latin1').split('\n')
    assert.equal(header[0], 'age-encryption.org/v1')
    const stanza = /^-> scrypt ([A-Za-z0-9+/]{22}) (\d+)$/.exec(header[1])
    assert.ok(stanza !== null, 'a scrypt stanza')
    assert.equal(stanza[2], '18')
    assert.equal(header[2].length, 43) // the wrapped file key; one stanza only
    assert.ok(header[3].startsWith('--- '))

    // Interop: the real age CLI decrypts master.age with the passphrase typed on its pty, giving the identity whose
    // recipient is master.pub. The identity stays in this process's memory (never written to disk).
    const a = await runInPty(['age', '-d', join(dir, 'master.age')], { env, steps: [{ waitFor: 'passphrase', send: PASS + '\r' }], timeoutMs: 60_000 })
    assert.equal(a.code, 0, 'age -d exit status')
    assert.ok(!a.out.includes(PASS), 'age echoed the passphrase')
    const ids = a.out.match(/AGE-SECRET-KEY-1[0-9A-Z]{58}/g) ?? []
    assert.equal(ids.length, 1, 'age -d printed one identity')
    assert.equal(await identityToRecipient(ids[0]) + '\n', pub)

    // Leak scan: neither the passphrase nor the master identity is anywhere under $OUT, HOME or TMPDIR.
    assertNoSecretsInStore(d, [PASS, ids[0]])
    assert.deepEqual(readdirSync(join(d, 'tmp')), [])
  }, 'testnet')
})

test('keystore init with neither --profile nor VT_PROFILE refuses config.profile-required before any prompt', async () => {
  await withEnv(async ({ out, env }) => {
    const r = await runDetached(['keystore', 'init'], env)
    assert.equal(r.code, 2)
    assert.match(r.err, /^refused config\.profile-required: /)
    assert.equal(r.out, '')
    assert.deepEqual(readdirSync(join(out, '..')).sort(), ['home', 'tmp']) // nothing created
  })
})

test('keystore init: --profile in argv works like VT_PROFILE; an existing keystore refuses keystore.exists before any prompt', async () => {
  await withEnv(async ({ env }) => {
    // no terminal: with a valid profile the command gets as far as the prompt, and refuses passphrase.no-tty there
    const r = await runDetached(['keystore', 'init', '--profile', 'local'], env)
    assert.equal(r.code, 2)
    assert.match(r.err, /^refused passphrase\.no-tty: /)
    const e = await runDetached(['keystore', 'init', '--profile', 'local', 'extra'], env)
    assert.equal(e.code, 64)
    assert.match(e.err, /usage/)
  })
  await withEnv(async ({ out, env }) => {
    mkdirSync(keystoreDir(out), { recursive: true, mode: 0o700 })
    for (const [name, text] of [['profile', 'local\n'], ['master.pub', 'synthetic\n']]) {
      writeFileSync(join(keystoreDir(out), name), text, { mode: 0o600 })
    }
    const r = await runDetached(['keystore', 'init'], env)
    assert.equal(r.code, 2)
    assert.match(r.err, /^refused keystore\.exists: /)
    const p = await runDetached(['keystore', 'init'], { ...env, VT_PROFILE: 'testnet' })
    assert.match(p.err, /^refused keystore\.profile: /)
  }, 'local')
})

test('keystore init on a pty: a weak passphrase refuses passphrase.weak and writes no keystore', { timeout: 60_000 }, async () => {
  await withEnv(async ({ out, env }) => {
    const weak = 'abacus abdomen abdominal abide abiding'
    const r = await runInPty([process.execPath, '--disable-sigusr1', CLI, 'keystore', 'init'], { env, steps: twice(weak) })
    assert.equal(r.code, 2)
    assert.match(r.out, /refused passphrase\.weak: /)
    assert.ok(!r.out.includes(weak))
    assert.ok(!existsSync(keystoreDir(out)) || readdirSync(keystoreDir(out)).length === 0)
  }, 'testnet')
})

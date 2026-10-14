// vt-broadcast CLI. Subcommands are added by later tasks. Run it through bin/vt-broadcast, which
// scrubs the environment (env -i) and confines Node (sandbox-exec); networked commands prove the
// confinement themselves (assertConfined) before any socket.
import { refuse, exitCodeFor, Refusal } from './guard.ts'
import { isAscii, validateNote } from './envelope.ts'
import { buildSealed } from './sealed.ts'
import { assertConfined } from './net/confine.ts'
import { createNet } from './net/fetch.ts'
import { torGate } from './net/gate.ts'
import { requireExplicitProfile } from './config.ts'
import { resolveOut } from './lifecycle/paths.ts'
import { lstatSync, readFileSync, writeFileSync, renameSync, chmodSync, unlinkSync } from 'node:fs'
import { resolve, join } from 'node:path'
import { randomBytes } from 'node:crypto'

const USAGE =
  'usage: cli.ts validate-note [--max-bytes N]   (note bytes on stdin)\n' +
  '       cli.ts seal-text <pkgDir> [--contents full|key-only] [--ar <arId>] [--write]\n' +
  '       cli.ts tor-check                        (prints only IsTor: true)\n' +
  '       cli.ts env-names                        (environment variable NAMES, never values)\n' +
  '       cli.ts keystore init [--profile mainnet|testnet|local]   (or VT_PROFILE; passphrase from /dev/tty, asked twice)\n' +
  '       cli.ts triggers list | show <id> | clear <id> | reset-latch\n' +
  '       cli.ts triggers resolve <id> <dest> mark-done <tx> [--block <b>] [--confirmations <n>] | mark-failed | mark-not-broadcast\n' +
  '                                               (a mainnet record asks for the typed word on /dev/tty)\n'

async function readStdin(): Promise<Uint8Array> {
  const chunks: Buffer[] = []
  for await (const c of process.stdin) chunks.push(c as Buffer)
  return Buffer.concat(chunks)
}

function usage(): never {
  process.stderr.write(USAGE)
  process.exit(64)
}

async function validateNoteCmd(args: string[]): Promise<void> {
  let max: number | undefined
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--max-bytes' && i + 1 < args.length && /^\d+$/.test(args[i + 1])) max = Number(args[++i])
    else usage()
  }
  const raw = await readStdin()
  const note = validateNote(raw)
  if (max !== undefined && raw.length > max) refuse('cli.max-bytes', `note exceeds --max-bytes ${max}`) // @guard:cli.max-bytes
  if (!isAscii(note)) {
    const n = [...note].filter((c) => c.charCodeAt(0) > 127).length
    process.stderr.write(`warn note.non-ascii: ${n} non-ASCII chars (Solana memo cost; explorer rendering)\n`)
  }
  process.stdout.write(`ok ${raw.length}\n`)
}

function sealTextCmd(args: string[]): void {
  let dir: string | undefined
  let contents: 'full' | 'key-only' = 'full'
  let ar: string | undefined
  let write = false
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a === '--contents' && i + 1 < args.length && (args[i + 1] === 'full' || args[i + 1] === 'key-only')) contents = args[++i] as 'full' | 'key-only'
    else if (a === '--ar' && i + 1 < args.length) ar = args[++i]
    else if (a === '--write') write = true
    else if (!a.startsWith('-') && dir === undefined) dir = a
    else usage()
  }
  if (dir === undefined) usage()
  if (write && contents !== 'full') refuse('sealed.write-full-only', 'SEALED.txt on disk is always the full form') // @guard:sealed.write-full-only
  const text = buildSealed(dir, { contents, arId: ar })
  if (!write) {
    process.stdout.write(text)
    return
  }
  const target = join(resolve(dir), 'SEALED.txt')
  const bytes = Buffer.from(text, 'utf8')
  if (lstatSyncOrNull(target) !== null) {
    const st = lstatSync(target)
    if (!st.isFile() || !readFileSync(target).equals(bytes)) refuse('sealed.exists-differs', 'SEALED.txt exists and differs: not overwritten') // @guard:sealed.exists-differs
  } else {
    const tmp = join(resolve(dir), `.SEALED.txt.tmp-${process.pid}-${randomBytes(4).toString('hex')}`)
    try {
      writeFileSync(tmp, bytes, { flag: 'wx', mode: 0o644 })
      chmodSync(tmp, 0o644)
      renameSync(tmp, target)
    } catch (e) {
      try { unlinkSync(tmp) } catch { /* nothing to clean */ }
      throw e
    }
  }
  process.stdout.write(`wrote ${target} ${bytes.length}\n`)
}

// Spec B s6.1: confined, then the Tor gate. Prints only the boolean; never the IP.
async function torCheckCmd(args: string[]): Promise<void> {
  if (args.length > 0) usage()
  await assertConfined()
  const tick = `${new Date().toISOString().slice(0, 16)}Z` // the ISO minute, e.g. 2026-10-08T03:15Z
  await torGate(createNet({ tick }))
  process.stdout.write('IsTor: true\n')
}

// Diagnostic for the env -i scrub: names only, sorted, one per line.
function envNamesCmd(args: string[]): void {
  if (args.length > 0) usage()
  const names = Object.keys(process.env).sort()
  process.stdout.write(names.map((n) => `${n}\n`).join(''))
}

// Spec C 5: `keystore init`. The profile must be explicit (config.profile-required: the keystore is bound to it, K33),
// and the profile binding and "no keystore yet" are checked before the passphrase is asked for. The passphrase comes
// from /dev/tty only (asked twice); prints only `keystore initialized: <master.pub>`. The keystore modules (age, viem)
// load only here.
async function keystoreCmd(args: string[]): Promise<void> {
  if (args[0] !== 'init') usage()
  const rest = args.slice(1)
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '--profile' && i + 1 < rest.length) i++
    else usage()
  }
  const profile = requireExplicitProfile(rest, process.env)
  const { Keystore } = await import('./lifecycle/keystore.ts')
  const { checkStrength, readPassphrase } = await import('./lifecycle/passphrase.ts')
  const ks = new Keystore(resolveOut(process.env), profile)
  ks.assertCanInit()
  const passphrase = await readPassphrase({ confirm: true })
  checkStrength(passphrase)
  const recipient = await ks.init(passphrase)
  process.stdout.write(`keystore initialized: ${recipient}\n`)
}

function lstatSyncOrNull(p: string) {
  try { return lstatSync(p) } catch { return null }
}

// Entry point: refuse a node started with an inspector (the process holds passphrases and keys). bin/vt-broadcast
// starts node with --disable-sigusr1 and a cleared NODE_OPTIONS; this is the second wall, for a node started by hand.
const INSPECTOR_OPTION = /^--(inspect|debug)/
const inspectorOption = (): boolean =>
  process.execArgv.some((a) => INSPECTOR_OPTION.test(a)) ||
  (process.env.NODE_OPTIONS ?? '').split(/\s+/).some((a) => INSPECTOR_OPTION.test(a))

try {
  if (inspectorOption()) refuse('cli.inspector', 'node was started with an inspector option (--inspect*/--debug*, in its arguments or NODE_OPTIONS): this process holds passphrases and keys') // @guard:cli.inspector
  switch (process.argv[2]) {
    case 'validate-note':
      await validateNoteCmd(process.argv.slice(3))
      break
    case 'seal-text':
      sealTextCmd(process.argv.slice(3))
      break
    case 'tor-check':
      await torCheckCmd(process.argv.slice(3))
      break
    case 'env-names':
      envNamesCmd(process.argv.slice(3))
      break
    case 'keystore':
      await keystoreCmd(process.argv.slice(3))
      break
    case 'triggers': { // spec B §6.6 (Task T1): the trigger latch; never needs a profile (the record's decides)
      const { triggersCmd } = await import('./lifecycle/triggers-cli.ts')
      await triggersCmd(process.argv.slice(3), process.env, usage)
      break
    }
    default:
      usage()
  }
} catch (e) {
  if (e instanceof Refusal) process.stderr.write(`refused ${e.guardId}: ${e.message}\n`)
  else process.stderr.write('error: unexpected failure\n')
  process.exitCode = exitCodeFor(e)
}

// The keystore (spec C 5; profile binding K33; funding-source key slots R47, C 3.1).
//
//   $OUT/keystore/            0700
//     master.age              the age X25519 identity `AGE-SECRET-KEY-1…` (exactly that text), encrypted with the
//                             passphrase: one scrypt stanza, logN 18 (`age -d` opens it)
//     master.pub              its recipient, exactly `age1…\n`
//     <keyId>.age             a secret encrypted to master.pub; plaintext = exactly the 32 raw secret bytes (secp256k1
//                             private key for EVM/BTC ids, ed25519 seed for *-sol), no encoding. Part D's browser key
//                             generator writes the same format (D-R7).
//     <keyId>.pub.json        { keyId, kind, address, createdAt[, pubkey] } in clear, so fund/status work while locked
//     profile                 the profile `keystore init` ran under, `<mainnet|testnet|local>\n`
//   every file 0600, written to a temp file <name>.tmp.<pid>.<hex> (O_EXCL, fsync) and then link()ed to its name:
//   nothing here is ever overwritten, and a crash leaves no truncated file (at most a temp file, which every reader
//   ignores and the next init/createKey removes once its writer is dead).
//
// ★★ CREATING needs no passphrase (master.pub only); only the runner DECRYPTS (unlock -> withSecret). No decrypted key
//   and never the master identity is written to disk or logged; withSecret zero-fills the key bytes in a `finally`.
//   (Residual: JavaScript strings can't be wiped: the identity string while unlocked, the passphrase, and the hex
//   string viem's privateKeyToAccount needs live until garbage collection.)
// ★★ PROFILE BINDING (K33): `keystore init` records the profile; every operation compares it with the active one and
//   refuses keystore.profile on a mismatch, or when a keystore has no readable profile file (fail closed). Each
//   non-mainnet profile uses its own VAULT_TIMELOCK_DIR, so testnet/local activity never touches the D-/pool- keys
//   later used on mainnet.
// ★ Tampering: withSecret derives the address from the decrypted key and refuses keystore.pub-mismatch unless it is
//   .pub.json's; unlock refuses keystore.master-mismatch unless master.pub is the master identity's own recipient (a
//   swapped master.pub would make createKey encrypt new keys to someone else).
// ★ Work factor: scrypt logN 18 in production. Tests may lower it (10..18) only through the constructor option
//   testScryptLogN, which refuses keystore.workfactor unless NODE_ENV=test (bin/vt-broadcast's env -i never passes
//   NODE_ENV, so the CLI can't reach it).
import {
  closeSync, constants, fchmodSync, fstatSync, fsyncSync, linkSync, lstatSync, openSync, readFileSync, readdirSync,
  unlinkSync, writeSync,
} from 'node:fs'
import { getRandomValues, randomBytes } from 'node:crypto'
import { join } from 'node:path'
import { Decrypter, Encrypter, generateIdentity, identityToRecipient } from 'age-encryption'
import { privateKeyToAccount } from 'viem/accounts'
import { refuse } from '../guard.ts'
import { assertProfile, PROFILES } from '../config.ts'
import type { Profile } from '../config.ts'
import { systemClock } from './clock.ts'
import type { Clock } from './clock.ts'
import { checkStrength } from './passphrase.ts'
import { checkPrivateDir, ensureDir, keystoreDir, lifecycleDir } from './paths.ts'

export const SCRYPT_LOG_N = 18
const TEST_MIN_LOG_N = 10

export type KeyKind = 'evm' | 'sol' | 'btc-p2wpkh' | 'btc-p2tr' | 'railgun-mnemonic'
export interface PubInfo { keyId: string; kind: KeyKind; address: string; createdAt: number; pubkey?: string }
export interface KeystoreOptions {
  testScryptLogN?: number // tests only (NODE_ENV=test), 10..18; production is SCRYPT_LOG_N
  clock?: Clock // createdAt
  beforeLink?: (name: string) => void // test seam: a file's bytes are durable in its temp file, not yet linked
}

// ---- key ids

// R47: one D-/pool- pair per funding-source label (default label railgun-eth). Checked after the arb alias resolves.
const KEY_ID = /^(D-[a-z0-9][a-z0-9-]{0,23}|pool-[a-z0-9][a-z0-9-]{0,23}|pub-[a-z0-9-]+-(eth|arb|base|sol|btc)|l1hop-[a-z0-9-]+|l2-[a-z0-9-]+-base|btcw-[a-z0-9-]+|btck-[a-z0-9-]+|swap-[a-z0-9-]+|arweave-[a-z0-9-]+)$/
// R8: l2-<job>-arb is the l1hop-<job> key (no file of its own); l2-<job>-base is a real key.
const ARB_ALIAS = /^l2-([a-z0-9-]+)-arb$/
// pub-<job>-btc is in the brief's grammar, but no task defines what it holds (Bitcoin publications use btcw-/btck-,
// B 5.5), so it is refused until one does (Task 12b review).
const PUB_BTC = /^pub-.+-btc$/

// Part D's interface contract imports exactly this.
export function resolveKeyId(id: string): string {
  const alias = typeof id === 'string' ? ARB_ALIAS.exec(id) : null
  const resolved = alias === null ? id : `l1hop-${alias[1]}`
  const ok = typeof resolved === 'string' && KEY_ID.test(resolved) && !PUB_BTC.test(resolved)
  if (!ok) refuse('keystore.key-id', 'not a key id: D-<label>, pool-<label>, pub-<job>-<eth|arb|base|sol>, l1hop-<job>, l2-<job>-<base|arb>, btcw-<job>, btck-<job>, swap-<job>, arweave-<job> (the value is not echoed)') // @guard:keystore.key-id
  return resolved
}

// A funding source's two key ids (R47, C 3.1). The label is ^[a-z0-9][a-z0-9-]{0,23}$, checked by the id grammar.
export function sourceKeyIds(label: string): { deposit: string; pool: string } {
  const l = typeof label === 'string' ? label : ''
  return { deposit: resolveKeyId(`D-${l}`), pool: resolveKeyId(`pool-${l}`) }
}

// The kinds a (resolved) key id may hold.
const KIND_OF: ReadonlyArray<readonly [RegExp, readonly KeyKind[]]> = [
  [/^D-/, ['evm']],
  [/^pool-/, ['railgun-mnemonic']],
  [/^pub-.+-(?:eth|arb|base)$/, ['evm']],
  [/^pub-.+-sol$/, ['sol']],
  [/^(?:l1hop|swap|arweave)-/, ['evm']],
  [/^l2-.+-base$/, ['evm']],
  [/^btcw-/, ['btc-p2wpkh']],
  [/^btck-/, ['btc-p2tr']],
]
const kindsFor = (id: string): readonly KeyKind[] => KIND_OF.find(([re]) => re.test(id))?.[1] ?? []

// Public addresses as .pub.json carries them (the same shapes Part D's import accepts). railgun-mnemonic has none
// yet: its task (22L/23) adds it, until then such a .pub.json refuses keystore.pub-format.
const ADDRESS: Readonly<Partial<Record<KeyKind, RegExp>>> = {
  evm: /^0x[0-9a-fA-F]{40}$/,
  sol: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/,
  'btc-p2wpkh': /^(?:bc|tb|bcrt)1q[02-9ac-hj-np-z]{38}$/,
  'btc-p2tr': /^(?:bc|tb|bcrt)1p[02-9ac-hj-np-z]{58}$/,
}
const PUBKEY = /^[0-9a-f]{64,66}$/
const PUB_FIELDS: readonly string[] = ['keyId', 'kind', 'address', 'createdAt', 'pubkey']

const RECIPIENT_LINE = /^age1[02-9ac-hj-np-z]{58}\n$/
const IDENTITY = /^AGE-SECRET-KEY-1[02-9AC-HJ-NP-Z]{58}$/
const LABEL_PUB = /^D-([a-z0-9][a-z0-9-]{0,23})\.pub\.json$/

// ---- secp256k1

const SECP256K1_N = Uint8Array.from(Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex'))

// 0 < k < n, compared byte by byte (no BigInt copy of the key).
export function isSecp256k1Secret(b: Uint8Array): boolean {
  if (b.length !== 32) return false
  let nonzero = false
  let cmp = 0
  for (let i = 0; i < 32; i++) {
    nonzero ||= b[i] !== 0
    if (cmp === 0 && b[i] !== SECP256K1_N[i]) cmp = b[i] < SECP256K1_N[i] ? -1 : 1
  }
  return nonzero && cmp < 0
}

function newEvmSecret(): Uint8Array {
  for (;;) {
    const k = getRandomValues(new Uint8Array(32))
    if (isSecp256k1Secret(k)) return k
    k.fill(0) // practically never: p ~ 2^-128
  }
}

// The address a secret of this kind controls, or undefined while this build cannot derive it (sol/btc: later tasks).
function deriveAddress(kind: KeyKind, secret: Uint8Array): string | undefined {
  if (kind !== 'evm') return undefined
  const view = Buffer.from(secret.buffer, secret.byteOffset, secret.byteLength) // a view: no copy to wipe
  return privateKeyToAccount(`0x${view.toString('hex')}`).address
}

// ---- files

const errCode = (e: unknown) => (e as NodeJS.ErrnoException).code

// A regular file's bytes (never through a symlink: O_NOFOLLOW), at most `max`; undefined if there is no such file.
// Anything else odd (a symlink, a directory, too big, unreadable) throws, and the caller fails closed.
function readSmall(path: string, max: number): Buffer | undefined {
  let fd: number
  try { fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW) } catch (e) {
    if (errCode(e) === 'ENOENT') return undefined
    throw e
  }
  try {
    const st = fstatSync(fd)
    if (!st.isFile() || st.size > max) throw new Error(`not a regular file of at most ${max} bytes`)
    return readFileSync(fd)
  } finally { closeSync(fd) }
}

// Temp files: <name>.tmp.<pid>.<12 hex>. Never a key, master or public-info name, so every reader ignores them.
const TMP = /^.+\.tmp\.([1-9][0-9]{0,9})\.[0-9a-f]{12}$/

function pidAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true } catch (e) { return errCode(e) !== 'ESRCH' } // EPERM: it exists
}

// Removes the temp files of writers that are gone (a crash between write and link). This process's own and live
// writers' temp files stay.
function sweepTmp(dir: string): void {
  for (const n of readdirSync(dir)) {
    const m = TMP.exec(n)
    const pid = m === null ? 0 : Number(m[1])
    if (pid !== 0 && pid !== process.pid && !pidAlive(pid)) { try { unlinkSync(join(dir, n)) } catch { /* gone */ } }
  }
}

// Places `name` in `dir`, atomically and never over anything: the bytes go to a fresh temp file (O_EXCL, 0600, fsync),
// which is then hard-linked to `name` and unlinked. link() fails with EEXIST when `name` exists: false is returned and
// nothing is replaced. A crash leaves at most the temp file, never a truncated `name`. Needs hard links on $OUT's
// filesystem (APFS, ext4: yes); without them link() fails and nothing is written (fail closed).
function writeNew(dir: string, name: string, data: Uint8Array | string, beforeLink?: (name: string) => void): boolean {
  const bytes = typeof data === 'string' ? Buffer.from(data, 'utf8') : data
  const tmp = join(dir, `${name}.tmp.${process.pid}.${randomBytes(6).toString('hex')}`)
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  try {
    try {
      fchmodSync(fd, 0o600) // whatever the umask
      for (let off = 0; off < bytes.length;) off += writeSync(fd, bytes, off)
      fsyncSync(fd)
    } finally { closeSync(fd) }
    beforeLink?.(name)
    try { linkSync(tmp, join(dir, name)) } catch (e) {
      if (errCode(e) === 'EEXIST') return false
      throw e
    }
    fsyncDir(dir)
    return true
  } finally {
    try { unlinkSync(tmp) } catch { /* already gone: nothing to clean */ }
  }
}

// The one keystore.exists / keystore.no-overwrite line each (checked before the work, and again at the link).
function assertNoKeystore(fresh: boolean): void {
  if (!fresh) refuse('keystore.exists', 'a keystore is already here (master.age, master.pub or key files); init never replaces one') // @guard:keystore.exists
}
function assertNoKey(fresh: boolean, id: string): void {
  if (!fresh) refuse('keystore.no-overwrite', `${id} already exists (or half of it does); keys are never overwritten`) // @guard:keystore.no-overwrite
}

function fsyncDir(dir: string): void {
  const fd = openSync(dir, 'r')
  try { fsyncSync(fd) } finally { closeSync(fd) }
}

function exists(path: string): boolean {
  try { lstatSync(path); return true } catch (e) {
    if (errCode(e) === 'ENOENT') return false
    throw e
  }
}

// ---- profile binding

// Refuses keystore.profile unless the keystore under `out` was made for `profile`. No keystore at all (no directory,
// or one holding nothing but crash-leftover temp files) passes: there is nothing to bind yet. A keystore whose profile file is missing, unreadable, a
// symlink or not exactly `<profile>\n` refuses (fail closed). Part D's web server calls this before every keystore
// read and import.
export function assertKeystoreProfile(out: string, profile: Profile): void {
  const dir = keystoreDir(out)
  if (!checkPrivateDir(dir) || readdirSync(dir).every((n) => TMP.test(n))) return
  let text: string | undefined
  try { text = readSmall(join(dir, 'profile'), 16)?.toString('utf8') } catch { text = undefined }
  const ok = (PROFILES as readonly string[]).includes(profile) && text === `${profile}\n`
  if (!ok) refuse('keystore.profile', 'this keystore belongs to another profile, or its profile file is missing or unreadable; each profile uses its own VAULT_TIMELOCK_DIR (the values are not echoed)') // @guard:keystore.profile
}

// ---- master.pub

function readMasterPub(dir: string): string {
  const present = checkPrivateDir(dir)
  let line: string | undefined
  try {
    line = present ? readSmall(join(dir, 'master.pub'), 128)?.toString('utf8') : undefined
    if (line !== undefined && RECIPIENT_LINE.test(line)) new Encrypter().addRecipient(line.slice(0, -1)) // bech32 checksum
    else line = undefined
  } catch { line = undefined }
  if (line === undefined) refuse('keystore.master-pub', 'no keystore here, or master.pub is not exactly one age1… recipient line (run vt-broadcast keystore init)') // @guard:keystore.master-pub
  return line.slice(0, -1)
}

function readPubInfo(dir: string, id: string): PubInfo | undefined {
  let bytes: Buffer | undefined
  let readable = true
  try { bytes = readSmall(join(dir, `${id}.pub.json`), 4096) } catch { readable = false }
  if (readable && bytes === undefined) return undefined
  let v: unknown
  try { v = JSON.parse(bytes!.toString('utf8')) } catch { v = undefined }
  const o = (typeof v === 'object' && v !== null && !Array.isArray(v) ? v : {}) as Record<string, unknown>
  const kind = o.kind as KeyKind
  const ok = readable && o === v && Object.keys(o).every((k) => PUB_FIELDS.includes(k))
    && o.keyId === id && kindsFor(id).includes(kind)
    && typeof o.address === 'string' && ADDRESS[kind]?.test(o.address) === true
    && Number.isSafeInteger(o.createdAt) && (o.createdAt as number) >= 0
    && (o.pubkey === undefined || (typeof o.pubkey === 'string' && PUBKEY.test(o.pubkey)))
  if (!ok) refuse('keystore.pub-format', `${id}.pub.json is not valid public info for this key id ({ keyId, kind, address, createdAt[, pubkey] })`) // @guard:keystore.pub-format
  const info: PubInfo = { keyId: id, kind, address: o.address as string, createdAt: o.createdAt as number }
  if (o.pubkey !== undefined) info.pubkey = o.pubkey as string
  return info
}

// ---- the CLI side: no passphrase needed except to create the master

export class Keystore {
  readonly out: string
  readonly profile: Profile
  readonly #logN: number
  readonly #clock: Clock
  readonly #beforeLink: ((name: string) => void) | undefined

  constructor(out: string, profile: Profile, opts: KeystoreOptions = {}) {
    assertProfile(profile)
    const n = opts.testScryptLogN
    const ok = n === undefined || (process.env.NODE_ENV === 'test' && Number.isInteger(n) && n >= TEST_MIN_LOG_N && n <= SCRYPT_LOG_N)
    if (!ok) refuse('keystore.workfactor', `the master's scrypt work factor is logN ${SCRYPT_LOG_N}; a lower one (${TEST_MIN_LOG_N}..${SCRYPT_LOG_N}) is a test-only option that needs NODE_ENV=test`) // @guard:keystore.workfactor
    this.out = out
    this.profile = profile
    this.#logN = n ?? SCRYPT_LOG_N
    this.#clock = opts.clock ?? systemClock
    this.#beforeLink = opts.beforeLink
  }

  // What `keystore init` checks before it asks for a passphrase (and init again): the profile binding, and no
  // keystore yet. Only a `profile` file may already be there (an init that stopped right after writing it).
  assertCanInit(): void {
    assertKeystoreProfile(this.out, this.profile)
    const dir = keystoreDir(this.out)
    const present = checkPrivateDir(dir)
    if (present) sweepTmp(dir)
    assertNoKeystore(!present || readdirSync(dir).every((n) => n === 'profile' || TMP.test(n)))
  }

  // Creates the master identity, encrypts it with the passphrase (scrypt, logN 18), writes profile, master.age and
  // master.pub (in that order: master.pub, which createKey needs, appears only once master.age is durable), and
  // lifecycle/ + lifecycle/trigger/ (0700, so the trigger latch can tell "no triggers" from "no store").
  // Returns the recipient (master.pub without its newline).
  async init(passphrase: string): Promise<string> {
    this.assertCanInit()
    checkStrength(passphrase)
    const identity = await generateIdentity()
    const recipient = await identityToRecipient(identity)
    const e = new Encrypter()
    e.setPassphrase(passphrase)
    e.setScryptWorkFactor(this.#logN)
    const sealed = await e.encrypt(identity)
    const dir = keystoreDir(this.out)
    ensureDir(dir)
    ensureDir(lifecycleDir(this.out))
    ensureDir(join(lifecycleDir(this.out), 'trigger'))
    if (!exists(join(dir, 'profile'))) writeNew(dir, 'profile', `${this.profile}\n`, this.#beforeLink)
    assertKeystoreProfile(this.out, this.profile) // a concurrent init for another profile wrote it first
    assertNoKeystore(writeNew(dir, 'master.age', sealed, this.#beforeLink))
    assertNoKeystore(writeNew(dir, 'master.pub', `${recipient}\n`, this.#beforeLink))
    return recipient
  }

  // Generates a key and stores it encrypted to master.pub: no passphrase, no master identity. evm only for now
  // (secp256k1, 32 bytes from the OS CSPRNG, 0 < k < n; the address via viem). Never overwrites.
  async createKey(keyId: string, kind: KeyKind): Promise<{ address: string }> {
    assertKeystoreProfile(this.out, this.profile)
    const id = resolveKeyId(keyId)
    const fits = kindsFor(id).includes(kind)
    if (!fits) refuse('keystore.kind-mismatch', `${id} cannot hold a key of that kind (D-, pub-*-eth|arb|base, l1hop-, l2-*-base, swap-, arweave-: evm; pub-*-sol: sol; btcw-: btc-p2wpkh; btck-: btc-p2tr; pool-: railgun-mnemonic)`) // @guard:keystore.kind-mismatch
    const supported = kind === 'evm'
    if (!supported) refuse('keystore.kind-unsupported', `generating ${kind} keys is not implemented yet (evm only)`) // @guard:keystore.kind-unsupported
    const dir = keystoreDir(this.out)
    const recipient = readMasterPub(dir)
    sweepTmp(dir)
    assertNoKey(!exists(join(dir, `${id}.age`)) && !exists(join(dir, `${id}.pub.json`)), id)
    const secret = newEvmSecret()
    try {
      const address = deriveAddress(kind, secret) as string
      const e = new Encrypter()
      e.addRecipient(recipient)
      const sealed = await e.encrypt(secret)
      assertNoKey(writeNew(dir, `${id}.age`, sealed, this.#beforeLink), id)
      const info: PubInfo = { keyId: id, kind, address, createdAt: this.#clock.now() }
      assertNoKey(writeNew(dir, `${id}.pub.json`, JSON.stringify(info) + '\n', this.#beforeLink), id)
      return { address }
    } finally {
      secret.fill(0)
    }
  }

  // The key's public info from <id>.pub.json alone (works while locked); undefined if there is no such key.
  publicInfo(keyId: string): PubInfo | undefined {
    assertKeystoreProfile(this.out, this.profile)
    const id = resolveKeyId(keyId)
    const dir = keystoreDir(this.out)
    if (!checkPrivateDir(dir)) return undefined
    return readPubInfo(dir, id)
  }

  // R47: the funding-source labels that have both a D-<label> and a pool-<label> key (.age and .pub.json), sorted.
  listSources(): string[] {
    assertKeystoreProfile(this.out, this.profile)
    const dir = keystoreDir(this.out)
    if (!checkPrivateDir(dir)) return []
    const names = new Set(readdirSync(dir))
    const has = (id: string) => names.has(`${id}.age`) && names.has(`${id}.pub.json`)
    const labels: string[] = []
    for (const n of names) {
      const m = LABEL_PUB.exec(n)
      if (m !== null && has(`D-${m[1]}`) && has(`pool-${m[1]}`)) labels.push(m[1])
    }
    return labels.sort()
  }

  // The runner side: decrypts master.age with the passphrase into memory.
  async unlock(passphrase: string): Promise<UnlockedKeystore> {
    assertKeystoreProfile(this.out, this.profile)
    const dir = keystoreDir(this.out)
    checkPrivateDir(dir)
    let identity: string | undefined
    try {
      const sealed = readSmall(join(dir, 'master.age'), 4096) ?? new Uint8Array(0)
      const d = new Decrypter()
      d.addPassphrase(passphrase)
      identity = await d.decrypt(sealed, 'text')
    } catch { identity = undefined }
    if (identity === undefined || !IDENTITY.test(identity)) refuse('keystore.unlock', 'wrong passphrase, or master.age is missing or not a passphrase-encrypted age identity') // @guard:keystore.unlock
    const same = (await identityToRecipient(identity)) === readMasterPub(dir)
    if (!same) refuse('keystore.master-mismatch', 'master.pub is not the recipient of the identity in master.age (tampered?): keys created since may be encrypted to someone else') // @guard:keystore.master-mismatch
    return new UnlockedKeystore(this.out, this.profile, identity)
  }
}

// ---- the runner side: the master identity in memory

export class UnlockedKeystore {
  readonly out: string
  readonly profile: Profile
  readonly #identity: string

  constructor(out: string, profile: Profile, identity: string) {
    this.out = out
    this.profile = profile
    this.#identity = identity
  }

  // Decrypts <id>.age in memory, checks that the key derives to .pub.json's address, calls fn, and zero-fills the
  // key bytes afterwards whatever happens.
  async withSecret<T>(keyId: string, fn: (secret: Uint8Array) => Promise<T>): Promise<T> {
    assertKeystoreProfile(this.out, this.profile)
    const id = resolveKeyId(keyId)
    const dir = keystoreDir(this.out)
    const present = checkPrivateDir(dir)
    const info = present ? readPubInfo(dir, id) : undefined
    let sealed: Buffer | undefined
    try { sealed = present ? readSmall(join(dir, `${id}.age`), 4096) : undefined } catch { sealed = undefined }
    if (info === undefined || sealed === undefined) refuse('keystore.no-key', `${id} is not in the keystore (no readable ${id}.age and ${id}.pub.json)`) // @guard:keystore.no-key
    let secret: Uint8Array | undefined
    try {
      try {
        const d = new Decrypter()
        d.addIdentity(this.#identity)
        secret = await d.decrypt(sealed)
      } catch { secret = undefined }
      // 32 bytes, and for secp256k1 kinds 0 < k < n (else viem would throw a plain error); an ed25519 seed is any 32 bytes
      if (secret === undefined || secret.length !== 32 || !(info.kind === 'sol' || isSecp256k1Secret(secret))) refuse('keystore.key-file', `${id}.age does not decrypt with the master identity to exactly 32 bytes that are a valid key of its kind`) // @guard:keystore.key-file
      const derived = deriveAddress(info.kind, secret)
      const same = derived !== undefined && derived.toLowerCase() === info.address.toLowerCase()
      if (!same) refuse('keystore.pub-mismatch', `${id}: the decrypted key does not derive to the address in ${id}.pub.json (tampered?), or its kind cannot be checked yet`) // @guard:keystore.pub-mismatch
      return await fn(secret)
    } finally {
      secret?.fill(0)
    }
  }
}

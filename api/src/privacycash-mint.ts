// api/src/privacycash-mint.ts — the API's mint of the Privacy Cash withdrawal authorization (Sfix-PC item 1; S7 fix round 2's
// "mint API", W6 concern 2). POST /jobs/<id>/privacycash/lane (routes.ts) → registry.mintPrivacyCash → mint() here.
//
// What it mints: the v2 single-use authorization the relay verifies (mintWithdrawAuth, privacycash.ts):
//     v2.<recipient>.<job>.<try>.<allowance>.<nonce>.<bodySha256>.<exp>.<mac>   under relay-ticket.key, for THIS network.
//   recipient   the job's SOL lane address (the job definition's keyAddress), never a request value;
//   job, try    the job id and the try index of the request;
//   bodySha256  sha256 of the exact withdrawal body the page will POST (the relay recomputes it over the received bytes);
//   nonce       32 hex, fresh per mint (CSPRNG); exp = now + 100 s (the relay accepts at most 120 s ahead);
//   allowance   the lane's CUMULATIVE reservation in lamports after this mint (see below).
//
// RESERVE FIRST, then sign (fail closed). The API's own ledger <state dir>/privacycash-lane-mints.jsonl (append-only, 0600,
// fsynced BEFORE the authorization is built, so a crash after the line leaves the amount reserved and no authorization out):
//   · each mint RESERVES `amount` lamports (the request's allowanceLamports: the most |extAmount| + fee this try may move)
//     against the lane cap (options.capLamports, per lane address): reserved(lane) + amount ≤ cap, else api.pc-allowance;
//   · the authorization's allowance is reserved(lane) AFTER this mint, so the relay's own cumulative ledger (reserved +
//     spent + new ≤ allowance) can never let the lane move more than the API has reserved in total;
//   · one mint per (job, try) EVER: asking again for the same try is api.pc-allowance (the page uses a fresh try index).
//   Reservations are never released here (a withdrawal the relay proved unaccepted leaves its reservation: conservative;
//   the operator-visible total is the ledger file).
// A ledger that is missing, unreadable, corrupt, a symlink, not private, or whose append/fsync fails refuses every mint
// (api.pc-ledger) for the rest of the process; no option / no cap configured refuses too.
//
// THE LOCK (controller ruling, fix round 1, review I-2). EVERY MAINNET MINT IS REFUSED, unconditionally (api.pc-lock, 423),
// until the funding-unlock task adds a POSITIVE gate (funding unlocked + the R42/R43 permission + a fundable chain phase).
// Nothing is reserved and no authorization exists on mainnet today, so no lane cap is burned while the lock is on, and 423
// never means "funding is unlocked". testnet and local mint (the relay refuses a mainnet withdrawal there regardless:
// relay.pc-network / the funding lock).
// The ledger (shared format with the relay's: pc-record.ts): one validator before write and on read, a per-line checksum,
// printable ASCII, a torn last line (a crash mid-append, never acknowledged) cut on read, the directory fsynced when the
// file is created, and no further append after a failed write.
import { randomBytes } from 'node:crypto'
import { closeSync, constants, fstatSync, fsyncSync, ftruncateSync, lstatSync, openSync, readFileSync, writeSync } from 'node:fs'
import { join } from 'node:path'
import type { Network } from '@vault-timelock/core/contracts'
import { refuse } from 'vt-broadcast/src/guard.ts'
import { mintWithdrawAuth } from './privacycash.ts'
import { decodeLine, encodeLine, splitLedger, syncDir } from './pc-record.ts'
import type { Rec } from './pc-record.ts'

export const MINT_LEDGER_FILE = 'privacycash-lane-mints.jsonl'
export const MINT_TTL_MS = 100_000
export const MAX_LANE_CAP = 999_999_999_999_999_999n          // the authorization's canonical integer has at most 18 digits
export const MAX_TRY = 1_000_000

export interface MintRequest { lane: string; job: string; tryIndex: number; bodySha256: string; amount: bigint }
export interface MintIo { write(fd: number, b: Buffer): number; fsync(fd: number): void }
const REAL_IO: MintIo = { write: (fd, b) => writeSync(fd, b, 0, b.length), fsync: (fd) => fsyncSync(fd) }
export interface LaneMintOptions {
  stateDir: string
  network: Network
  key: Uint8Array
  capLamports: bigint
  now: () => number
  nonce?: () => string            // a test seam: the nonce source (default 16 CSPRNG bytes, hex)
  io?: MintIo                     // a test seam: the durable write
}
export interface LaneMint {
  mint(r: MintRequest): string
  reserved(lane: string): bigint
}

// THE api.pc-lock line (one marker): a mainnet mint. Refused unconditionally until the funding-unlock task adds a positive gate.
function lockHolds(ok: boolean): asserts ok {
  if (!ok) refuse('api.pc-lock', 'Privacy Cash authorizations are not minted on mainnet in this build: nothing is reserved or signed') // @guard:api.pc-lock
}
// THE api.pc-ledger line (one marker): the mint ledger cannot be trusted or written (or minting is not configured).
function ledgerOk(ok: boolean): asserts ok {
  if (!ok) refuse('api.pc-ledger', 'the Privacy Cash lane ledger is missing, corrupt or not writable, or no lane cap is configured: nothing is minted') // @guard:api.pc-ledger
}
// THE api.pc-allowance line (one marker): the lane's reservations would pass its cap, or this try already has its authorization.
function allowanceOk(ok: boolean): asserts ok {
  if (!ok) refuse('api.pc-allowance', "this try already has its authorization, or the lane's reservations (with this one) would exceed the lane cap") // @guard:api.pc-allowance
}

const DEC = /^(?:0|[1-9][0-9]{0,17})$/
const HEX64 = /^[0-9a-f]{64}$/
const HEX16 = /^[0-9a-f]{16}$/
const NONCE = /^[0-9a-f]{32}$/
const B58 = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)

// The mainnet rule alone (exported for the tests): mainnet never mints; every other network may.
export const mintNetworkAllowed = (network: Network): boolean => network !== 'mainnet'

// THE record validator of this ledger: used before a line is written and when it is read (one definition).
export function validMint(o: Rec): boolean {
  return o.v === 1 && o.t === 'mint' && typeof o.lane === 'string' && B58.test(o.lane) && typeof o.job === 'string' && HEX16.test(o.job)
    && Number.isSafeInteger(o.try) && (o.try as number) >= 0 && typeof o.h === 'string' && HEX64.test(o.h) && typeof o.amount === 'string' && DEC.test(o.amount)
    && typeof o.cum === 'string' && DEC.test(o.cum) && typeof o.n === 'string' && NONCE.test(o.n) && Number.isSafeInteger(o.exp) && Number.isSafeInteger(o.at)
}

export function createLaneMint(o: LaneMintOptions): LaneMint {
  const io = o.io ?? REAL_IO
  const file = join(o.stateDir, MINT_LEDGER_FILE)
  const reservedBy = new Map<string, bigint>()
  const tries = new Set<string>()
  const nonces = new Set<string>()
  let bad: string | null = o.capLamports >= 1n && o.capLamports <= MAX_LANE_CAP ? null : 'no lane cap'
  let loaded = false
  let fd: number | null = null

  function load(): void {
    loaded = true
    if (bad !== null) return
    try {
      let text = ''
      try {
        const st = lstatSync(file)
        if (!st.isFile() || st.isSymbolicLink() || (st.mode & 0o077) !== 0) { bad = 'not a private regular file'; return }
        text = readFileSync(file, 'utf8')
      } catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e }
      const { lines, tornAt } = splitLedger(text)
      if (tornAt !== null) {                          // a torn last line was never acknowledged (no authorization before its fsync): cut it
        const h = openSync(file, constants.O_WRONLY | constants.O_NOFOLLOW)
        try { ftruncateSync(h, Buffer.byteLength(text.slice(0, tornAt))); fsyncSync(h) } finally { closeSync(h) }
      }
      for (const line of lines) {
        const d = decodeLine(line)
        if (!d.ok || !validMint(d.rec)) { bad = 'corrupt line'; return }
        const j = d.rec
        const k = `${String(j.job)}:${String(j.try)}`
        if (tries.has(k) || nonces.has(j.n as string)) { bad = 'duplicate'; return }
        tries.add(k); nonces.add(j.n as string)
        reservedBy.set(j.lane as string, (reservedBy.get(j.lane as string) ?? 0n) + BigInt(j.amount as string))
      }
      for (const v of reservedBy.values()) if (v > MAX_LANE_CAP) { bad = 'overflow'; return }
    } catch { bad = 'unreadable' }
  }

  function append(line: Rec): boolean {
    if (bad !== null) return false
    const rec = { v: 1, ...line }
    const text = validMint(rec) ? encodeLine(rec) : null
    if (text === null) return false
    try {
      if (fd === null) {
        fd = openSync(file, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW, 0o600)
        const st = fstatSync(fd)
        if (!st.isFile() || (st.mode & 0o077) !== 0) throw new Error('mode')
        syncDir(o.stateDir)
      }
      const b = Buffer.from(text)
      if (io.write(fd, b) !== b.length) throw new Error('short')
      io.fsync(fd)
      return true
    } catch {
      bad = 'a write failed'
      if (fd !== null) { try { closeSync(fd) } catch { /* nothing */ } fd = null }
      return false
    }
  }

  return {
    reserved: (lane) => reservedBy.get(lane) ?? 0n,
    mint(r) {
      lockHolds(mintNetworkAllowed(o.network))
      if (!loaded) load()
      ledgerOk(bad === null && o.key.length >= 16)
      // the request is checked again here (the route's shape check is the first line): fail closed on anything off form
      ledgerOk(B58.test(r.lane) && HEX16.test(r.job) && HEX64.test(r.bodySha256) && Number.isSafeInteger(r.tryIndex) && r.tryIndex >= 0 && r.tryIndex <= MAX_TRY
        && r.amount >= 1n && r.amount <= MAX_LANE_CAP)
      const k = `${r.job}:${String(r.tryIndex)}`
      const before = reservedBy.get(r.lane) ?? 0n
      allowanceOk(!tries.has(k) && before + r.amount <= o.capLamports)
      const nonce = (o.nonce ?? (() => randomBytes(16).toString('hex')))()
      ledgerOk(NONCE.test(nonce) && !nonces.has(nonce))
      const now = o.now()
      const exp = now + MINT_TTL_MS
      const after = before + r.amount
      // reserve: the line is durable (written and fsynced) BEFORE the authorization exists
      const ok = append({ t: 'mint', lane: r.lane, job: r.job, try: r.tryIndex, h: r.bodySha256, amount: String(r.amount), cum: String(after), n: nonce, exp, at: now })
      ledgerOk(ok)
      tries.add(k); nonces.add(nonce); reservedBy.set(r.lane, after)
      return mintWithdrawAuth(o.key, { network: o.network, recipient: r.lane, job: r.job, tryIndex: r.tryIndex, allowance: after, nonce, bodySha256: r.bodySha256, exp })
    },
  }
}

// The Privacy Cash session (src/privacycash/session.js) against a FAKE SDK, real ed25519 (tweetnacl) and the real guarded fetch over a
// fake relay. No devnet exists for Privacy Cash: nothing here touches a network, a chain or a real key (the wallet is generated in the test).
import { test, expect, beforeEach } from 'vitest'
import nacl from 'tweetnacl'
import { PublicKey } from '@solana/web3.js'
import { base58 } from '@scure/base'
import { createGuardedFetch } from '../src/privacycash/guard.js'
import { MemStorage, SIGN_MESSAGE, createSession } from '../src/privacycash/session.js'
import { KEY_BASE_PATH, SDK_RELAYER_URL } from '../src/privacycash/limits.js'

const ORIGIN = 'http://127.0.0.1:5180'
const SIG58 = '5'.repeat(88)
const enc = new TextEncoder()
let seenSigs, seenSecrets, wallet, post, posts, relayCalls, derived, resets, sdkCalls, cfg, notes, withdrawImpl, answer

const JOB = '0123456789abcdef', TRY = 7
let mints, laneRecipient, mintAnswer
// the API's v2 authorization for a mint request (api/src/privacycash.ts mintWithdrawAuth's shape; the MAC is the relay's business, not the page's)
const v2 = (m, o = {}) => `v2.${o.recipient ?? laneRecipient}.${o.job ?? JOB}.${o.tryIndex ?? m.tryIndex}.${o.allowance ?? m.allowanceLamports}.${'ab'.repeat(16)}.${o.sha ?? m.bodySha256}.${1_900_000_000_000}.${'cd'.repeat(32)}`
// withdraw args for a recipient; the fake mint answers for the same recipient
const wa = (to, extra = {}) => { laneRecipient = to; return { net: 1_000_000_000, recipient: to, job: JOB, tryIndex: TRY, ...extra } }
const keypair = () => { const kp = nacl.sign.keyPair(); return { kp, pub: new PublicKey(kp.publicKey) } }
const sigOf = (kp) => nacl.sign.detached(enc.encode(SIGN_MESSAGE), kp.secretKey)

class FakeConnection { constructor(url, opts) { this.url = url; this.opts = opts } }
function build() {
  seenSigs = []; seenSecrets = []; mints = []; mintAnswer = (m) => new Response(JSON.stringify({ authorization: v2(m) }), { status: 200 }); posts = []; post = (m) => posts.push(m); relayCalls = []; derived = []; resets = 0; sdkCalls = []
  cfg = { withdraw_fee_rate: 0.0035, withdraw_rent_fee: 0.006, minimum_withdrawal: { sol: 0.01 } }
  notes = [3_000_000_000, 2_000_000_000, 5_000]
  answer = () => new Response(JSON.stringify({ signature: SIG58 }), { status: 200 })
  const guard = createGuardedFetch({ origin: ORIGIN, native: async (u, i) => { if (u.endsWith('/privacycash/lane')) { const m = JSON.parse(i.body); mints.push({ url: u, init: i, body: m }); return mintAnswer(m) } relayCalls.push({ url: u, init: i }); return answer(u, i) }, timeout: () => new AbortController().signal })
  withdrawImpl = async (o) => {
    // what the real SDK does at the end: POST /withdraw through (the global) fetch, with the relayer base URL
    const r = await guard.fetch(`${SDK_RELAYER_URL}/withdraw`, { method: 'POST', body: JSON.stringify({ recipient: o.recipient.toBase58() }) })
    if (!r.ok) throw new Error('[object Object]')
    return { isPartial: false, tx: SIG58, recipient: o.recipient.toBase58(), amount_in_lamports: o.amount_in_lamports - Math.floor(o.amount_in_lamports * 0.0035 + 6_000_000), fee_in_lamports: Math.floor(o.amount_in_lamports * 0.0035 + 6_000_000), referralRecorded: undefined }
  }
  const sdk = {
    EncryptionService: class { deriveEncryptionKeyFromSignature(sig) { derived.push(Buffer.from(sig).toString('hex')); seenSigs.push(sig) } resetEncryptionKey() { resets++ } },
    setLogger(fn) { sdk.logger = fn },
    getUtxos: async (o) => { sdkCalls.push(['getUtxos', o]); return notes.map((n) => ({ amount: { toNumber: () => n } })) },
    getBalanceFromUtxos: (u) => ({ lamports: u.reduce((s, x) => s + x.amount.toNumber(), 0) }),
    getConfig: async (k) => cfg[k],
    withdraw: (o) => { sdkCalls.push(['withdraw', o]); return withdrawImpl(o) },
  }
  const spyNacl = { sign: Object.assign((...a) => nacl.sign(...a), { detached: Object.assign((...a) => nacl.sign.detached(...a), { verify: (...a) => nacl.sign.detached.verify(...a) }), keyPair: { fromSecretKey: (sk) => { seenSecrets.push(sk); return nacl.sign.keyPair.fromSecretKey(sk) } } }) }
  const closed = { n: 0 }
  const session = createSession({ sdk, WasmFactory: { getInstance: async () => ({ lightWasm: true }) }, Connection: FakeConnection, PublicKey, nacl: spyNacl, base58, guard, post, origin: ORIGIN, close: () => closed.n++ })
  return { session, sdk, guard, closed }
}
const run = async (session, cmd, args = {}) => { const id = run.id = (run.id ?? 0) + 1; await session.handle({ id, cmd, args }); return posts.findLast((m) => m.id === id) }
beforeEach(() => { wallet = keypair() })

test('unlock with the SIGNATURE: verified against the deposit wallet, the derived input is exactly that signature, the raw buffers are zeroed', async () => {
  const { session } = build()
  const sig = sigOf(wallet.kp)
  const r = await run(session, 'unlock', { mode: 'signature', input: base58.encode(sig), publicKey: wallet.pub.toBase58() })
  expect(r).toEqual({ id: r.id, ok: true, result: { ok: true } })
  expect(derived).toEqual([Buffer.from(sig).toString('hex')])
  expect(session.unlocked).toBe(true)
})

test('unlock with the SECRET KEY: the signature is derived (the same bytes), the key must belong to the address, nothing secret in any answer', async () => {
  const { session } = build()
  const r = await run(session, 'unlock', { mode: 'secret', input: base58.encode(wallet.kp.secretKey), publicKey: wallet.pub.toBase58() })
  expect(r.ok).toBe(true)
  expect(derived).toEqual([Buffer.from(sigOf(wallet.kp)).toString('hex')])
  expect(JSON.stringify(posts)).not.toContain(base58.encode(wallet.kp.secretKey))
  const j = build()
  const r2 = await run(j.session, 'unlock', { mode: 'secret', input: JSON.stringify([...wallet.kp.secretKey]), publicKey: wallet.pub.toBase58() })    // the CLI's JSON array form
  expect(r2.ok).toBe(true)
})

test('unlock refuses: a signature of another message / wallet, a secret key that is not the address, malformed input, a second unlock', async () => {
  const { session } = build()
  const other = keypair()
  const wrongMsg = nacl.sign.detached(enc.encode('Privacy Money account sign in '), wallet.kp.secretKey)       // not the exact message (e.g. an off-chain-message header changes the bytes)
  const cases = [
    [{ mode: 'signature', input: base58.encode(wrongMsg), publicKey: wallet.pub.toBase58() }, 'pc.signature'],
    [{ mode: 'signature', input: base58.encode(sigOf(other.kp)), publicKey: wallet.pub.toBase58() }, 'pc.signature'],
    [{ mode: 'secret', input: base58.encode(other.kp.secretKey), publicKey: wallet.pub.toBase58() }, 'pc.signature'],
    [{ mode: 'signature', input: 'not base58 !!', publicKey: wallet.pub.toBase58() }, 'pc.input'],
    [{ mode: 'signature', input: base58.encode(new Uint8Array(63)), publicKey: wallet.pub.toBase58() }, 'pc.input'],
    [{ mode: 'secret', input: '[1,2,3]', publicKey: wallet.pub.toBase58() }, 'pc.input'],
    [{ mode: 'secret', input: 'x'.repeat(5000), publicKey: wallet.pub.toBase58() }, 'pc.input'],
    [{ mode: 'seed', input: 'x', publicKey: wallet.pub.toBase58() }, 'pc.input'],
    [{ mode: 'signature', input: base58.encode(sigOf(wallet.kp)), publicKey: 'nope' }, 'pc.input'],
  ]
  for (const [args, code] of cases) { const r = await run(session, 'unlock', args); expect(r.ok, JSON.stringify(args).slice(0, 60)).toBe(false); expect(r.error.code).toBe(code) }
  expect(derived).toEqual([]); expect(session.unlocked).toBe(false)
  await run(session, 'unlock', { mode: 'signature', input: base58.encode(sigOf(wallet.kp)), publicKey: wallet.pub.toBase58() })
  const again = await run(session, 'unlock', { mode: 'signature', input: base58.encode(sigOf(wallet.kp)), publicKey: wallet.pub.toBase58() })
  expect(again.error.code).toBe('pc.locked')
})

async function unlocked() {
  const s = build()
  await run(s.session, 'unlock', { mode: 'signature', input: base58.encode(sigOf(wallet.kp)), publicKey: wallet.pub.toBase58() })
  return s
}

test('nothing works before unlock; commands are an allowlist', async () => {
  const { session } = build()
  for (const cmd of ['balance', 'quote', 'withdraw']) expect((await run(session, cmd, { net: 20_000_000 })).error.code).toBe('pc.locked')
  for (const cmd of ['constructor', '__proto__', 'toString', 'hasOwnProperty', '']) expect((await run(session, cmd)).error.code).toBe('pc.cmd')
  await session.handle({ cmd: 'balance' })                                                  // no id
  expect(posts.at(-1).error.code).toBe('pc.cmd')
})

test('balance: scans through the SDK with an in-memory Storage and a Connection on the relay\'s rpc path; reports the two-note limit', async () => {
  const { session } = await unlocked()
  const r = await run(session, 'balance')
  expect(r.result).toEqual({ lamports: 5_000_005_000, notes: 3, top2: 5_000_000_000 })
  const [, o] = sdkCalls.find((c) => c[0] === 'getUtxos')
  expect(o.storage).toBeInstanceOf(MemStorage)
  expect(o.connection.url).toBe(`${ORIGIN}/relay/privacycash/rpc`)
  expect(o.connection.opts).toMatchObject({ disableRetryOnRateLimit: true })
  expect(typeof o.connection.opts.fetch).toBe('function')
})

test('quote needs the balance first, applies the config clamps and refuses a silent partial', async () => {
  const { session } = await unlocked()
  expect((await run(session, 'quote', { net: 20_000_000 })).error.code).toBe('pc.balance-first')
  await run(session, 'balance')
  const q = (await run(session, 'quote', { net: 1_000_000_000 })).result
  expect(q).toMatchObject({ net: expect.any(Number), gross: expect.any(Number), fee: expect.any(Number), top2: 5_000_000_000, minimum: 10_000_000 })
  expect(q.net).toBeGreaterThanOrEqual(1_000_000_000)
  expect((await run(session, 'quote', { net: 5_000_000_000 })).error.code).toBe('pc.partial')                 // gross would exceed the two largest notes
  cfg.withdraw_fee_rate = 0.02                                                                                 // an inflated /config
  expect((await run(session, 'quote', { net: 1_000_000_000 })).error.message).toMatch(/above the cap/)
  cfg.withdraw_fee_rate = 0.0035; cfg.minimum_withdrawal = undefined
  expect((await run(session, 'quote', { net: 1_000_000_000 })).error.code).toBe('pc.config')
})

test('withdraw: re-quotes itself, proves with the relay artifacts path, mints the v2 authorization for the exact body it posts (allowance = the gross), carries it, returns the signature; the lane request is dropped afterwards', async () => {
  const { session, guard } = await unlocked()
  await run(session, 'balance')
  const to = keypair().pub.toBase58()
  const r = await run(session, 'withdraw', wa(to))
  expect(r.ok).toBe(true)
  expect(r.result).toMatchObject({ signature: SIG58, isPartial: false, indexerConfirmed: true })
  const [, w] = sdkCalls.find((c) => c[0] === 'withdraw')
  expect(w.keyBasePath).toBe(KEY_BASE_PATH)
  expect(w.recipient.toBase58()).toBe(to)
  expect(w.storage).toBeInstanceOf(MemStorage)
  expect(w.amount_in_lamports).toBeGreaterThan(1_000_000_000)                                 // the GROSS, solved by the session, not the page's number
  const wd = relayCalls.find((c) => c.url.endsWith('/relayer/withdraw'))
  expect(mints).toHaveLength(1)
  const posted = wd.init.body
  const sha = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(posted))).toString('hex')
  expect(mints[0].body).toEqual({ bodySha256: sha, allowanceLamports: String(w.amount_in_lamports), tryIndex: TRY })
  expect(mints[0].url).toBe(`${ORIGIN}/api/jobs/${JOB}/privacycash/lane`)
  expect(mints[0].init).toMatchObject({ method: 'POST', credentials: 'omit', redirect: 'error' })
  expect(wd.init.headers.get('x-vt-pc-lane')).toBe(v2(mints[0].body, { recipient: to }))
  expect(posts.some((m) => m.type === 'sent')).toBe(true)
  expect(guard.state.lane).toBeNull()
})

test('withdraw refusals: a malformed recipient, job or try, a second concurrent withdrawal, the relay\'s own refusal (named, not "[object Object]")', async () => {
  const { session } = await unlocked()
  await run(session, 'balance')
  expect((await run(session, 'withdraw', wa('nope'))).error.code).toBe('pc.input')
  for (const bad of [{ job: '' }, { job: 'ABCDEF0123456789' }, { tryIndex: -1 }, { tryIndex: 1.5 }, { tryIndex: 1_000_001 }, { tryIndex: undefined }]) expect((await run(session, 'withdraw', wa(keypair().pub.toBase58(), bad))).error.code, JSON.stringify(bad)).toBe('pc.lane')
  expect(sdkCalls.some((c) => c[0] === 'withdraw')).toBe(false)
  answer = () => new Response(JSON.stringify({ error: { guard: 'release.mainnet-locked', message: 'funding sends are locked' } }), { status: 423 })
  const locked = await run(session, 'withdraw', wa(keypair().pub.toBase58()))
  expect(locked.error).toEqual({ code: 'release.mainnet-locked', message: 'funding sends are locked' })
  // concurrent
  answer = () => new Response(JSON.stringify({ signature: SIG58 }), { status: 200 })
  let release
  withdrawImpl = () => new Promise((r) => { release = r })
  const first = session.handle({ id: 900, cmd: 'withdraw', args: wa(keypair().pub.toBase58()) })
  await new Promise((r) => setTimeout(r, 10))
  const second = await run(session, 'withdraw', wa(keypair().pub.toBase58()))
  expect(second.error.code).toBe('pc.busy')
  release({ isPartial: false, amount_in_lamports: 1, fee_in_lamports: 1 }); await first
})

test('withdraw: the API refuses the authorization (api.pc-lock on mainnet): the guard id reaches the page and NOTHING is sent to the relay', async () => {
  const { session } = await unlocked()
  await run(session, 'balance')
  mintAnswer = () => new Response(JSON.stringify({ error: { guard: 'api.pc-lock', message: 'Privacy Cash authorizations are not minted on mainnet in this build' } }), { status: 423 })
  const r = await run(session, 'withdraw', wa(keypair().pub.toBase58()))
  expect(r.error).toEqual({ code: 'api.pc-lock', message: 'Privacy Cash authorizations are not minted on mainnet in this build' })
  expect(relayCalls.some((c) => c.url.endsWith('/relayer/withdraw'))).toBe(false)
  expect(posts.some((m) => m.type === 'sent')).toBe(false)
})

test('the SDK throws after the relayer answered (its own indexer wait): the signature is still returned, indexerConfirmed false', async () => {
  // the fake SDK posts through the REAL guard first (as the SDK does), then throws
  const { session: s2, guard } = await unlocked()
  await run(s2, 'balance')
  withdrawImpl = async () => { await guard.fetch(`${SDK_RELAYER_URL}/withdraw`, { method: 'POST', body: '{}' }); throw new Error('Refresh the page to see latest balance.') }
  const r = await run(s2, 'withdraw', wa(keypair().pub.toBase58()))
  expect(r.ok).toBe(true)
  expect(r.result).toMatchObject({ signature: SIG58, indexerConfirmed: false })
})

test('a SDK failure before the request leaves is an ordinary error with no signature; a PARTIAL withdrawal is reported loudly with the signature', async () => {
  const { session, guard } = await unlocked()
  await run(session, 'balance')
  withdrawImpl = async () => { throw new Error('Need at least 1 unspent UTXO\nsecond line with 0xdeadbeef and a very long tail ' + 'x'.repeat(500)) }
  const r = await run(session, 'withdraw', wa(keypair().pub.toBase58()))
  expect(r.error.code).toBe('pc.sdk'); expect(r.error.message.length).toBeLessThanOrEqual(200); expect(r.error.message).not.toMatch(/\n/)
  withdrawImpl = async () => { await guard.fetch(`${SDK_RELAYER_URL}/withdraw`, { method: 'POST', body: '{}' }); return { isPartial: true, amount_in_lamports: 5, fee_in_lamports: 1 } }
  const p = await run(session, 'withdraw', wa(keypair().pub.toBase58()))
  expect(p.error.code).toBe('pc.partial'); expect(p.error.message).toContain(SIG58)
})

test('status lines: only the SDK\'s progress allowlist reaches the page; anything else (amounts, indices, ciphertexts) is dropped', async () => {
  const { session, sdk } = build()
  void session
  sdk.logger('info', 'generating ZK proof...')
  sdk.logger('info', '(decrypting cached utxo: 12/340...)')
  sdk.logger('info', 'Found 3 UTXOs with amount 5000000000 index 77')
  sdk.logger('debug', 'getting private balance')
  sdk.logger('error', 'generating ZK proof...')
  sdk.logger('info', 'getting private balance\nthen a secret')
  expect(posts.filter((m) => m.type === 'status').map((m) => m.msg)).toEqual(['generating ZK proof...', '(decrypting cached utxo: 12/340...)'])
})

test('lock: the SDK keys are reset, the memory storage cleared, later commands refused, the worker asked to close; and no answer ever holds a secret', async () => {
  const { session, closed } = await unlocked()
  await run(session, 'balance')
  const r = await run(session, 'lock')
  expect(r.ok).toBe(true); expect(resets).toBe(1); expect(closed.n).toBe(1); expect(session.unlocked).toBe(false)
  expect((await run(session, 'balance')).error.code).toBe('pc.locked')
  const all = JSON.stringify(posts)
  expect(all).not.toContain(base58.encode(sigOf(wallet.kp)))
  expect(all).not.toContain(Buffer.from(sigOf(wallet.kp)).toString('hex'))
})

test('MemStorage is a plain Map-backed Storage', () => {
  const m = new MemStorage()
  m.setItem('a', 1); expect(m.getItem('a')).toBe('1'); expect(m.getItem('b')).toBeNull(); expect(m.length).toBe(1); expect(m.key(0)).toBe('a')
  m.removeItem('a'); expect(m.length).toBe(0); m.setItem('x', 'y'); m.clear(); expect(m.length).toBe(0)
})

test('M6: after unlock every raw buffer the session held is ZERO (the signature handed to the SDK, the secret key given to nacl)', async () => {
  const a = build()
  const sig = sigOf(wallet.kp)
  await run(a.session, 'unlock', { mode: 'signature', input: base58.encode(sig), publicKey: wallet.pub.toBase58() })
  expect(seenSigs).toHaveLength(1); expect([...seenSigs[0]].every((x) => x === 0)).toBe(true)
  expect(derived[0]).toBe(Buffer.from(sig).toString('hex'))                                  // what the SDK was given WAS the signature, at call time
  const b = build()
  await run(b.session, 'unlock', { mode: 'secret', input: base58.encode(wallet.kp.secretKey), publicKey: wallet.pub.toBase58() })
  expect(seenSecrets.length).toBeGreaterThan(0)
  for (const sk of seenSecrets) expect([...sk].every((x) => x === 0)).toBe(true)
  expect(seenSigs.at(-1) && [...seenSigs.at(-1)].every((x) => x === 0)).toBe(true)
})

test('M6: zeroing the input is safe for the REAL SDK: its EncryptionService copies what it needs before returning', async () => {
  const { EncryptionService } = await import('privacycash/utils')
  const sig = sigOf(wallet.kp)
  const a = new EncryptionService(); a.deriveEncryptionKeyFromSignature(Uint8Array.from(sig))
  const copy = Uint8Array.from(sig)
  const b = new EncryptionService(); const r = b.deriveEncryptionKeyFromSignature(copy)
  copy.fill(0)
  expect(Buffer.from(r.v1).toString('hex')).toBe(Buffer.from(sig.slice(0, 31)).toString('hex'))     // V1 key survives the zeroing (slice copies)
  expect(b.deriveUtxoPrivateKey()).toBe(a.deriveUtxoPrivateKey())
  expect(b.getUtxoPrivateKeyV2()).toBe(a.getUtxoPrivateKeyV2())
}, 60_000)

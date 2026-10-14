// The Privacy Cash session: runs INSIDE the worker (worker.js wires the real SDK), and in tests with a fake SDK. It owns the
// wallet key material (the derived EncryptionService; the raw input is zeroed as soon as the signature is derived), checks
// every number before the SDK proves or sends, and talks to the page through `post` only.
//
// Commands (page → worker): unlock, balance, quote, withdraw, lock. Each answers {id, ok:true, result} or
// {id, ok:false, error:{code, message}}. Events (worker → page, no id): {type:'status', msg} (an allowlisted SDK progress line),
// {type:'sent'} (the /withdraw request is leaving: from here on a stop may have moved funds).
//
// What it never does: persist anything (the SDK's storage is a Map), print a key, signature, note, address or amount to the
// console (the shims silence it), put a secret in an answer, or make a request the guarded fetch does not allow.
import { KEY_BASE_PATH, checkConfig, checkCovered, solveGross } from './limits.js'

export const SIGN_MESSAGE = 'Privacy Money account sign in'
const STATUS_OK = /^(?:getting private balance|generating ZK proof\.\.\.|submitting transaction to relayer\.\.\.|waiting for transaction confirmation\.\.\.|Confirming transaction\.\.|Fetching updated onchain state\.\.\.|\(decrypting cached utxo: \d{1,7}\/\d{1,7}\.\.\.\))$/

export class PcError extends Error {
  constructor(code, message) { super(message); this.name = 'PcError'; this.code = code }
}
const fail = (code, message) => { throw new PcError(code, message) }

// A Map-backed Storage: the SDK's cache (fetch offset, encrypted outputs, trade history) stays in this worker's memory.
export class MemStorage {
  #m = new Map()
  get length() { return this.#m.size }
  key(i) { return [...this.#m.keys()][i] ?? null }
  getItem(k) { return this.#m.has(String(k)) ? this.#m.get(String(k)) : null }
  setItem(k, v) { this.#m.set(String(k), String(v)) }
  removeItem(k) { this.#m.delete(String(k)) }
  clear() { this.#m.clear() }
}

const errorOf = (e) => (e instanceof PcError ? { code: e.code, message: e.message }
  : typeof e?.message === 'string' && /^pc\.[a-z-]+:/.test(e.message) ? { code: e.message.slice(0, e.message.indexOf(':')), message: e.message.slice(e.message.indexOf(':') + 2) }
    : { code: 'pc.sdk', message: String(e?.message ?? e).replace(/[^\x20-\x7e]/g, '?').slice(0, 200) })

// deps: { sdk: {EncryptionService,getUtxos,getBalanceFromUtxos,withdraw,getConfig,setLogger}, WasmFactory, Connection, PublicKey, nacl,
//         base58 ({decode}), guard (guard.js), post(msg), origin, close() }
export function createSession(deps) {
  const { sdk, WasmFactory, Connection, PublicKey, nacl, base58, guard, post, origin, close } = deps
  const mem = new MemStorage()
  const st = { es: null, publicKey: null, connection: null, notes: null, locked: false, busy: false }
  guard.events.sent = () => post({ type: 'sent' })
  sdk.setLogger((level, msg) => { if (level === 'info' && typeof msg === 'string' && STATUS_OK.test(msg)) post({ type: 'status', msg }) })

  const needKey = () => { if (st.locked || st.es === null) fail('pc.locked', 'unlock first (the key lives only in this tab, in memory)') }
  const connection = () => (st.connection ??= new Connection(`${origin}/relay/privacycash/rpc`, { commitment: 'confirmed', fetch: guard.fetch, disableRetryOnRateLimit: true }))

  function decodeInput(mode, input) {
    if (typeof input !== 'string' || input.length > 2048) fail('pc.input', 'the key input is empty or too long')
    const t = input.trim()
    if (mode === 'signature') {
      let raw
      try { raw = base58.decode(t) } catch { fail('pc.input', 'the signature is not base58') }
      if (raw.length !== 64) fail('pc.input', 'a signature is 64 bytes (base58)')
      return { sig: Uint8Array.from(raw), sk: null }
    }
    if (mode === 'secret') {
      let raw
      try { raw = t.startsWith('[') ? Uint8Array.from(JSON.parse(t)) : Uint8Array.from(base58.decode(t)) } catch { fail('pc.input', 'the secret key is not base58 or a JSON array of 64 numbers') }
      if (raw.length !== 64) fail('pc.input', 'a Solana secret key is 64 bytes')
      return { sig: null, sk: raw }
    }
    return fail('pc.input', 'choose signature or secret key')
  }

  const handlers = {
    // unlock {mode:'signature'|'secret', input, publicKey}: verifies the signature against the deposit wallet's public key, derives the
    // encryption keys, then zeroes every raw buffer. -> {ok:true}
    async unlock({ mode, input, publicKey }) {
      if (st.es !== null) fail('pc.locked', 'already unlocked: lock first')
      let pub
      try { pub = new PublicKey(publicKey) } catch { fail('pc.input', 'the deposit wallet address is not a Solana address') }
      const msg = new TextEncoder().encode(SIGN_MESSAGE)
      const { sig: given, sk } = decodeInput(mode, input)
      let sig = given
      try {
        if (sk !== null) {
          const kp = nacl.sign.keyPair.fromSecretKey(sk)
          if (!pub.equals(new PublicKey(kp.publicKey))) fail('pc.signature', 'this secret key is not the deposit wallet address you gave')
          sig = nacl.sign.detached(msg, sk)
          kp.secretKey.fill(0)
        }
        if (!nacl.sign.detached.verify(msg, sig, pub.toBytes())) fail('pc.signature', 'this signature is not the deposit wallet\'s signature of the exact message (raw ed25519 over "Privacy Money account sign in", not an off-chain message)')
        const es = new sdk.EncryptionService()
        es.deriveEncryptionKeyFromSignature(sig)
        st.es = es
        st.publicKey = pub
      } finally {
        if (sk !== null) sk.fill(0)
        if (sig) sig.fill(0)
        if (given) given.fill(0)
      }
      return { ok: true }
    },

    // balance {}: the cold scan (all of the relayer's encrypted outputs, decrypted here). -> {lamports, notes, top2}
    async balance() {
      needKey()
      const utxos = await sdk.getUtxos({ publicKey: st.publicKey, connection: connection(), encryptionService: st.es, storage: mem })
      const { lamports } = sdk.getBalanceFromUtxos(utxos)
      st.notes = utxos.map((u) => (typeof u.amount?.toNumber === 'function' ? u.amount.toNumber() : Number(u.amount)))
      const top2 = [...st.notes].sort((a, b) => b - a).slice(0, 2).reduce((s, x) => s + x, 0)
      return { lamports, notes: st.notes.length, top2 }
    },

    // quote {net}: the gross amount, the fee and the clamp checks for a wanted NET amount (lamports). Refuses a silent partial.
    async quote({ net }) {
      needKey()
      if (st.notes === null) fail('pc.balance-first', 'check the balance first: the notes decide what can be withdrawn')
      const cfg = checkConfig({ rate: await sdk.getConfig('withdraw_fee_rate'), rent: await sdk.getConfig('withdraw_rent_fee'), minimum: (await sdk.getConfig('minimum_withdrawal'))?.sol })
      const q = solveGross(net, cfg)
      const top2 = checkCovered(q.gross, st.notes)
      return { ...q, top2, minimum: cfg.minimumLamports }
    },

    // withdraw {net, recipient, job, tryIndex}: re-derives the quote itself (the page's numbers are not trusted), then proves and sends.
    // The lane authorization is minted by the guard when the SDK posts the body (it binds the body's sha256); its allowance is the GROSS.
    // -> {signature, net, fee, isPartial, indexerConfirmed}
    async withdraw({ net, recipient, job, tryIndex }) {
      needKey()
      if (st.busy) fail('pc.busy', 'a withdrawal is already running')
      let to
      try { to = new PublicKey(recipient) } catch { fail('pc.input', 'the recipient is not a Solana address') }
      if (typeof job !== 'string' || !/^[0-9a-f]{16}$/.test(job) || !Number.isSafeInteger(tryIndex) || tryIndex < 0 || tryIndex > 1_000_000) fail('pc.lane', 'no job or try index for the lane authorization (the API mints one for this job, this withdrawal and its exact body)')
      const q = await handlers.quote({ net })
      st.busy = true
      guard.reset()
      guard.setLane({ job, tryIndex, allowance: q.gross, recipient: to.toBase58() })
      try {
        let r = null, thrown = null
        try {
          r = await sdk.withdraw({
            recipient: to, lightWasm: await WasmFactory.getInstance(), storage: mem, publicKey: st.publicKey, connection: connection(),
            amount_in_lamports: q.gross, encryptionService: st.es, keyBasePath: KEY_BASE_PATH,
          })
        } catch (e) { thrown = e }
        const sig = guard.state.signature
        if (guard.state.refusal !== null && sig === null) fail(guard.state.refusal.guard, guard.state.refusal.message)
        if (thrown !== null && sig === null) throw thrown
        // The relayer answered /withdraw with a signature. The SDK may still throw while it waits for ITS indexer (≈22 s): the
        // signature is what matters, and the chain decides. Report it with indexerConfirmed:false.
        if (sig === null) fail('pc.no-signature', 'the relayer did not return a transaction signature')
        if (r !== null && r.isPartial) fail('pc.partial', `the SDK withdrew a PARTIAL amount (${r.amount_in_lamports} lamports, signature ${sig}): the funds moved; check the lane address`)
        return { signature: sig, net: r?.amount_in_lamports ?? q.net, fee: r?.fee_in_lamports ?? q.fee, isPartial: false, indexerConfirmed: thrown === null }
      } finally { st.busy = false; guard.setLane(null) }
    },

    // lock {}: forget the key. The page terminates this worker right after (the real wipe); this also nulls the SDK's fields.
    async lock() {
      st.locked = true
      try { st.es?.resetEncryptionKey?.() } catch { /* best effort */ }
      st.es = null; st.publicKey = null; st.notes = null; st.connection = null
      mem.clear()
      return { ok: true }
    },
  }

  return {
    // The worker's onmessage body.
    async handle(msg) {
      const id = msg?.id
      const fn = typeof msg?.cmd === 'string' && Object.hasOwn(handlers, msg.cmd) ? handlers[msg.cmd] : null
      if (!Number.isSafeInteger(id) || fn === null) { post({ id: Number.isSafeInteger(id) ? id : -1, ok: false, error: { code: 'pc.cmd', message: 'unknown command' } }); return }
      try {
        const result = await fn(msg.args ?? {})
        post({ id, ok: true, result })
        if (msg.cmd === 'lock') close?.()
      } catch (e) {
        post({ id, ok: false, error: errorOf(e) })
      }
    },
    // test hooks
    get unlocked() { return st.es !== null },
  }
}

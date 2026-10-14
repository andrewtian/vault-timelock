// S7 (M4) Privacy Cash proxy: /relay/privacycash/* — the 6 relayer routes + RPC getMultipleAccounts + the local circuit
// files. Phase A: the gates in api/src/privacycash.ts (relay.path, relay.method, relay.pc-query, relay.pc-body,
// relay.pc-body-cap, relay.pc-upstream-shape, relay.pc-artifact, relay.pc-tor, relay.pc-send-lock); phase B: the real
// createRelay in process with an injected transport that plays the relayer and the RPC (FAKES ONLY: there is no devnet,
// nothing leaves the machine; the URLs are only strings). Synthetic data only.
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, createHmac } from 'node:crypto'
import { mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { PublicKey } from '@solana/web3.js'
import { createServer, request } from 'node:http'
import type { Server } from 'node:http'
import { join } from 'node:path'
import { PORTS } from '@vault-timelock/core/contracts'
import type { Network } from '@vault-timelock/core/contracts'
import { GENESIS, NETWORK_IDS } from 'vt-broadcast/src/config.ts'
import { Refusal } from 'vt-broadcast/src/guard.ts'
import { createRelay, relayPrivacyCash, relayUpstreams } from '../relay/relay.mjs'
import {
  FIELD_Q, FIELD_R, GENESIS_BODY, LANE_HEADER, PC_FIXED, PC_PINS, PC_RELAYER, TRANSACT_DISCRIMINATOR, WITHDRAW_KEYS, assertWithdrawAllowed, bodyCapOk, checkPcAnswer, checkPcBody,
  checkWithdrawSemantics, decodeProof, feeCeiling, forwardBody, isPrivacyCashPath, loadArtifact, mintWithdrawAuth, pcRpcIdentity, verifyWithdrawAuth, WITHDRAW_AUTH_WINDOW_MS, resolvePc, torRequired,
} from '../src/privacycash.ts'
import type { FundingLock, Pin } from '../src/privacycash.ts'
import { TICKET_KEY, tempDir } from './helpers.ts'
import { LEDGER_FILE, openWithdrawalLedger } from '../src/privacycash-ledger.ts'
import { chmodSync, existsSync, fsyncSync, rmSync, statSync, writeSync } from 'node:fs'

const NOW = 1_791_504_000_000
const FAKE_RELAYER = 'http://127.0.0.1:19001'
const LOCAL_SOL = '8pUq7jxkLxNpHg6M9KxzRtNEC4pNEHsr4kDTLSE5uVRW'   // a synthetic non-public genesis
const guardOf = (f: () => unknown): string | null => {
  try { f() } catch (e) { return e instanceof Refusal ? e.guardId : `not a refusal: ${String(e)}` }
  return null
}
const R = '/relay/privacycash/relayer/'
const OUT = 'ab'.repeat(40)                       // an encrypted output (hex, 80 chars)
const COMMIT = '12345678901234567890'
const KEY = '11111111111111111111111111111112'      // a base58 32-byte key (the system program)
const PROOF = Buffer.alloc(600, 7).toString('base64')
const SIG58 = '5'.repeat(88)
const withdrawBody = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  serializedProof: PROOF, treeAccount: KEY, nullifier0PDA: KEY, nullifier1PDA: KEY, nullifier2PDA: KEY, nullifier3PDA: KEY, treeTokenAccount: KEY,
  globalConfigAccount: KEY, recipient: KEY, feeRecipientAccount: KEY, extAmount: -1000000000, encryptedOutput1: OUT, encryptedOutput2: OUT, fee: 7000000,
  lookupTableAddress: KEY, ...over,
})
const rpcBody = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ jsonrpc: '2.0', id: 3, method: 'getMultipleAccounts', params: [[KEY, KEY], { encoding: 'base64' }], ...over })
const buf = (v: unknown): Buffer => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v))

// =====================================================================================================================
// 1. the route list (pure)
// =====================================================================================================================
test('resolvePc: exactly the 6 relayer routes, the rpc and the two circuit files; everything else is relay.path / relay.method / relay.pc-query', () => {
  const ok: Array<[string, string, string]> = [
    ['GET', `${R}config`, 'config'], ['GET', `${R}utxos/range?start=0&end=20000`, 'utxos/range'], ['GET', `${R}utxos/range?start=123456&end=143456`, 'utxos/range'],
    ['POST', `${R}utxos/indices`, 'utxos/indices'], ['GET', `${R}merkle/proofv2/?commitments=${COMMIT},${COMMIT}`, 'merkle/proofv2'],
    ['POST', `${R}withdraw`, 'withdraw'], ['GET', `${R}utxos/check/${OUT}`, 'utxos/check'], ['POST', '/relay/privacycash/rpc', 'rpc'],
    ['GET', '/relay/privacycash/artifacts/transaction2.wasm', 'artifacts/transaction2.wasm'], ['GET', '/relay/privacycash/artifacts/transaction2.zkey', 'artifacts/transaction2.zkey'],
  ]
  for (const [m, p, name] of ok) assert.equal(resolvePc(m, p).name, name, p)
  // the upstream path is the matched text itself
  assert.equal(resolvePc('GET', `${R}utxos/range?start=5&end=20005`).upstream, '/utxos/range?start=5&end=20005')
  assert.equal(resolvePc('GET', `${R}merkle/proofv2/?commitments=1,2`).upstream, '/merkle/proofv2/?commitments=1,2')
  assert.equal(resolvePc('GET', `${R}utxos/check/${OUT}`).upstream, `/utxos/check/${OUT}`)
  // routes the SDK has and this proxy refuses (research D4: everything else 403)
  for (const p of [`${R}deposit`, `${R}deposit/spl`, `${R}withdraw/spl`, `${R}merkle/root`, `${R}merkle/root?token=x`, `${R}bridge`, `${R}`, `${R}config/`, `${R}Config`,
    `${R}utxos/range/`, `${R}utxos`, `${R}merkle/proofv2`, `${R}utxos/check/`, `${R}utxos/check/${OUT}/x`, `${R}utxos/check/ABCD${OUT}`, `${R}utxos/check/${'ab'.repeat(36).slice(2)}`,
    `${R}utxos/check/%61b`, `${R}../config`, `${R}utxos/../config`, `${R}%2e%2e/config`, `${R}config#x`, '/relay/privacycash', '/relay/privacycash/', '/relay/privacycash/rpc/', '/relay/privacycash/rpc2',
    '/relay/privacycash/artifacts/transaction2.json', '/relay/privacycash/artifacts/../transaction2.wasm',
    '/relay/privacycash/artifacts/transaction3.zkey', '/relay/privacycash/other', `/relay/privacycash/relayer`, `/relay/privacycashx/relayer/config`]) {
    assert.equal(guardOf(() => resolvePc('GET', p)), 'relay.path', p)
  }
  assert.equal(guardOf(() => resolvePc('POST', `${R}deposit`)), 'relay.path')
})

test('resolvePc: a known route asked with another HTTP method is relay.method', () => {
  for (const [m, p] of [['POST', `${R}config`], ['GET', `${R}utxos/indices`], ['PUT', `${R}withdraw`], ['GET', `${R}withdraw`], ['POST', `${R}utxos/range?start=0&end=20000`],
    ['GET', '/relay/privacycash/rpc'], ['POST', '/relay/privacycash/artifacts/transaction2.wasm'], ['DELETE', `${R}config`], ['get', `${R}config`], ['HEAD', `${R}config`]]) {
    assert.equal(guardOf(() => resolvePc(m, p)), 'relay.method', `${m} ${p}`)
  }
})

test('resolvePc: the query forms are exact (relay.pc-query)', () => {
  for (const q of ['', '?', '?start=0', '?end=20000', '?start=0&end=19999', '?start=0&end=20001', '?start=5&end=5', '?end=20000&start=0', '?start=0&end=20000&token=x',
    '?start=0&end=20000&', '?start=-1&end=19999', '?start=1e3&end=20999', '?start=0000000000&end=20000', '?start=1234567890&end=1234587890', '?start=%30&end=20000', '?start=a&end=b']) {
    assert.equal(guardOf(() => resolvePc('GET', `${R}utxos/range${q}`)), 'relay.pc-query', q)
  }
  for (const q of ['', '?', '?commitments=1', '?commitments=1,2,3', '?commitments=1,', '?commitments=,2', '?commitments=a,b', '?commitments=1,2&token=x', '?token=x&commitments=1,2',
    `?commitments=${'1'.repeat(79)},2`, '?commitments=1,2&', '?commitments=1%2C2']) {
    assert.equal(guardOf(() => resolvePc('GET', `${R}merkle/proofv2/${q}`)), 'relay.pc-query', q)
  }
  for (const q of ['?', '?token=x', '?x=1']) assert.equal(guardOf(() => resolvePc('GET', `${R}config${q}`)), 'relay.pc-query', q)
  assert.equal(guardOf(() => resolvePc('GET', `${R}utxos/check/${OUT}?token=x`)), 'relay.pc-query')
  for (const [m, p] of [['POST', `${R}utxos/indices?x=1`], ['POST', `${R}withdraw?x=1`], ['POST', '/relay/privacycash/rpc?x=1'], ['GET', '/relay/privacycash/artifacts/transaction2.wasm?x=1']]) assert.equal(guardOf(() => resolvePc(m, p)), 'relay.pc-query', p)
})

test('isPrivacyCashPath: the prefix only', () => {
  assert.ok(isPrivacyCashPath('/relay/privacycash/rpc') && isPrivacyCashPath('/relay/privacycash'))
  assert.ok(!isPrivacyCashPath('/relay/privacycashx') && !isPrivacyCashPath('/relay/sol') && !isPrivacyCashPath('/relay/btc/x'))
})

// =====================================================================================================================
// 2. request bodies (pure)
// =====================================================================================================================
test('checkPcBody: indices — {encrypted_outputs}: 1–750 lower-case hex notes of 72–400 chars, no other key', () => {
  const r = resolvePc('POST', `${R}utxos/indices`)
  const good = { encrypted_outputs: [OUT, 'cd'.repeat(36), 'ef'.repeat(200)] }
  assert.equal(guardOf(() => checkPcBody(r, buf(good))), null)
  assert.equal(guardOf(() => checkPcBody(r, buf({ encrypted_outputs: Array(750).fill(OUT) }))), null)
  for (const bad of [{ encrypted_outputs: [] }, { encrypted_outputs: Array(751).fill(OUT) }, { encrypted_outputs: ['ab'.repeat(35)] }, { encrypted_outputs: ['ab'.repeat(201)] },
    { encrypted_outputs: ['AB'.repeat(40)] }, { encrypted_outputs: [`0x${OUT}`] }, { encrypted_outputs: [OUT, 5] }, { encrypted_outputs: OUT }, { ...good, extra: 1 }, { outputs: [OUT] },
    [OUT], null, 'x', {}]) {
    assert.equal(guardOf(() => checkPcBody(r, buf(bad))), 'relay.pc-body', JSON.stringify(bad).slice(0, 60))
  }
  assert.equal(guardOf(() => checkPcBody(r, buf('{not json'))), 'relay.pc-body')
  assert.equal(guardOf(() => checkPcBody(r, Buffer.alloc(0))), 'relay.pc-body')
  assert.equal(guardOf(() => checkPcBody(r, Buffer.from([0xff, 0xfe, 0x7b, 0x7d]))), 'relay.pc-body')
})

test('checkPcBody: withdraw — the 15 keys of the SDK, referralId absent, extAmount negative, fee non-negative, accounts base58', () => {
  const r = resolvePc('POST', `${R}withdraw`)
  assert.equal(WITHDRAW_KEYS.length, 15)
  assert.equal(guardOf(() => checkPcBody(r, buf(withdrawBody()))), null)
  assert.equal(guardOf(() => checkPcBody(r, buf(withdrawBody({ extAmount: '-1000000000', fee: '7000000' })))), null)
  const missing = withdrawBody(); delete missing.recipient
  const bads: unknown[] = [missing, withdrawBody({ referralId: 'x' }), withdrawBody({ referrer: KEY }), withdrawBody({ extAmount: 1000000000 }), withdrawBody({ extAmount: 0 }),
    withdrawBody({ extAmount: -1.5 }), withdrawBody({ fee: -1 }), withdrawBody({ fee: 1.5 }), withdrawBody({ fee: '1e3' }), withdrawBody({ recipient: 'not base58!' }),
    withdrawBody({ recipient: '1'.repeat(45) }), withdrawBody({ lookupTableAddress: 5 }), withdrawBody({ serializedProof: 'AAAA' }), withdrawBody({ serializedProof: `${PROOF}!` }),
    withdrawBody({ encryptedOutput1: '' }), withdrawBody({ encryptedOutput2: 7 }), withdrawBody({ extAmount: null }), [], 'x']
  for (const bad of bads) assert.equal(guardOf(() => checkPcBody(r, buf(bad))), 'relay.pc-body', JSON.stringify(bad).slice(0, 70))
  assert.equal(guardOf(() => checkPcBody(r, buf(`{"a":1,${JSON.stringify(withdrawBody()).slice(1)}`))), 'relay.pc-body')   // an extra key
})

test('checkPcBody: rpc — ONE getMultipleAccounts (no batch, ≤ 100 keys, a config of the four known keys); every other method refused', () => {
  const r = resolvePc('POST', '/relay/privacycash/rpc')
  assert.equal(guardOf(() => checkPcBody(r, buf(rpcBody()))), null)
  assert.equal(guardOf(() => checkPcBody(r, buf(rpcBody({ params: [Array(100).fill(KEY)] })))), null)
  assert.equal(guardOf(() => checkPcBody(r, buf(rpcBody({ id: 'a' })))), null)
  const noId = rpcBody(); delete noId.id
  assert.equal(guardOf(() => checkPcBody(r, buf(noId))), null)
  const bads: unknown[] = [[rpcBody(), rpcBody()], [], rpcBody({ params: [Array(101).fill(KEY)] }), rpcBody({ params: [[]] }), rpcBody({ params: [] }), rpcBody({ params: [[KEY], {}, 1] }),
    rpcBody({ params: [['not base58!']] }), rpcBody({ params: [KEY] }), rpcBody({ params: [[KEY], { encoding: 'base64', epoch: 1 }] }), rpcBody({ params: [[KEY], [1]] }),
    rpcBody({ jsonrpc: '1.0' }), rpcBody({ id: { a: 1 } }), rpcBody({ id: [1] }), rpcBody({ params: { a: 1 } }), 'x', null]
  for (const m of ['sendTransaction', 'simulateTransaction', 'requestAirdrop', 'getAccountInfo', 'getBalance', 'getTransaction', 'getSignatureStatuses', 'getGenesisHash', 'getSlot',
    'getProgramAccounts', 'getMultipleAccountsX', 'GetMultipleAccounts', '', 'eth_call']) bads.push(rpcBody({ method: m }))
  for (const bad of bads) assert.equal(guardOf(() => checkPcBody(r, buf(bad))), 'relay.pc-body', JSON.stringify(bad).slice(0, 70))
})

test('checkPcBody / bodyCapOk: each route\'s cap (relay.pc-body-cap), a GET takes no body', () => {
  const caps: Array<[string, string, string, number]> = [['POST', `${R}utxos/indices`, 'indices', 256 * 1024], ['POST', `${R}withdraw`, 'withdraw', 8 * 1024], ['POST', '/relay/privacycash/rpc', 'rpc', 64 * 1024]]
  for (const [m, p, , cap] of caps) {
    const r = resolvePc(m, p)
    assert.equal(guardOf(() => bodyCapOk(r, cap)), null)
    assert.equal(guardOf(() => bodyCapOk(r, cap + 1)), 'relay.pc-body-cap')
    assert.equal(guardOf(() => checkPcBody(r, Buffer.alloc(cap + 1, 0x20))), 'relay.pc-body-cap')
  }
  const get = resolvePc('GET', `${R}config`)
  assert.equal(guardOf(() => checkPcBody(get, Buffer.alloc(0))), null)
  assert.equal(guardOf(() => checkPcBody(get, buf('{}'))), 'relay.pc-body-cap')
})

test('forwardBody: canonical re-serialization of the checked JSON (a duplicate key cannot smuggle a second field); a GET has none', () => {
  const r = resolvePc('POST', `${R}utxos/indices`)
  const dup = `{"encrypted_outputs":["${OUT}"],"encrypted_outputs":["${'cd'.repeat(40)}"]}`
  assert.equal(guardOf(() => checkPcBody(r, buf(dup))), null)                       // JSON.parse keeps the last: one key
  assert.equal(forwardBody(r, buf(dup))?.toString(), JSON.stringify({ encrypted_outputs: ['cd'.repeat(40)] }))
  assert.equal(forwardBody(resolvePc('GET', `${R}config`), Buffer.alloc(0)), null)
})

// =====================================================================================================================
// 3. answers (pure)
// =====================================================================================================================
test('checkPcAnswer: 200 only as JSON within the route cap; 404 is the relay\'s own; any other status a 502 with no upstream text', () => {
  const cfg = resolvePc('GET', `${R}config`)
  const a = checkPcAnswer(cfg, 200, buf({ withdraw_fee_rate: 0.0035 }))
  assert.deepEqual([a.status, a.contentType, a.body.toString()], [200, 'application/json', '{"withdraw_fee_rate":0.0035}'])
  assert.equal(checkPcAnswer(cfg, 404, buf('<html>secret upstream text</html>')).status, 404)
  for (const st of [201, 204, 301, 400, 403, 429, 500, 503, 0, NaN]) {
    const x = checkPcAnswer(cfg, st, buf('<html>secret upstream text</html>'))
    assert.equal(x.status, 502); assert.ok(!x.body.toString().includes('secret'))
  }
  for (const bad of [buf('<html>'), buf('"a string"'), buf('5'), buf('null'), Buffer.alloc(0), Buffer.from([0xff, 0xfe]), Buffer.alloc(64 * 1024 + 1, 0x20)]) {
    assert.equal(guardOf(() => checkPcAnswer(cfg, 200, bad)), 'relay.pc-upstream-shape')
  }
  assert.equal(guardOf(() => checkPcAnswer(cfg, 200, Buffer.from(`{"a":"${'x'.repeat(64 * 1024)}"}`))), 'relay.pc-upstream-shape')   // over the 64 KB cap
  const wd = resolvePc('POST', `${R}withdraw`)
  assert.equal(checkPcAnswer(wd, 200, buf({ signature: SIG58 })).status, 200)
  for (const bad of [{ signature: 5 }, { signature: '<script>' }, { signature: 'x'.repeat(200) }, []]) assert.equal(guardOf(() => checkPcAnswer(wd, 200, buf(bad))), 'relay.pc-upstream-shape')
  assert.equal(guardOf(() => checkPcAnswer(wd, 200, Buffer.from(`{"signature":"${SIG58}","pad":"${'x'.repeat(5000)}"}`))), 'relay.pc-upstream-shape')   // over 4 KB
  const rpc = resolvePc('POST', '/relay/privacycash/rpc')
  assert.equal(checkPcAnswer(rpc, 200, buf({ jsonrpc: '2.0', id: 3, result: { context: { slot: 1 }, value: [null] } })).status, 200)
  assert.equal(checkPcAnswer(rpc, 200, buf({ jsonrpc: '2.0', id: 3, error: { code: -32602, message: 'x' } })).status, 200)
  for (const bad of [{ result: 1 }, { jsonrpc: '2.0', id: 3 }, { jsonrpc: '2.0', error: 'x' }, [{ jsonrpc: '2.0', result: 1 }]]) assert.equal(guardOf(() => checkPcAnswer(rpc, 200, buf(bad))), 'relay.pc-upstream-shape')
  assert.equal(guardOf(() => checkPcAnswer(rpc, 200, Buffer.from(`{"jsonrpc":"2.0","result":"${'x'.repeat(2 * 1024 * 1024)}"}`))), 'relay.pc-upstream-shape')
  const range = resolvePc('GET', `${R}utxos/range?start=0&end=20000`)
  assert.equal(checkPcAnswer(range, 200, Buffer.from(`{"a":"${'x'.repeat(11 * 1024 * 1024)}"}`)).status, 200)
  assert.equal(guardOf(() => checkPcAnswer(range, 200, Buffer.from(`{"a":"${'x'.repeat(12 * 1024 * 1024)}"}`))), 'relay.pc-upstream-shape')
})

// =====================================================================================================================
// 4. the circuit files (pure + temp dir)
// =====================================================================================================================
test('PC_PINS are the research values; loadArtifact serves only the exact pinned bytes (regular file, size, sha256)', () => {
  assert.deepEqual(PC_PINS['transaction2.wasm'], { size: 3208099, sha256: 'a277631b7616c2c0bfd78a1648b069972ac6020e5509ae8f9bfc8772bdc70ec1' })
  assert.deepEqual(PC_PINS['transaction2.zkey'], { size: 16461496, sha256: '4aa7aa5c1c28ed1f00fee84f49c1686f53210fd999ef7c8db6cfcd298af4e693' })
  const t = tempDir('vt-pc-art-')
  try {
    const wasm = Buffer.from('synthetic wasm bytes'), zkey = Buffer.from('synthetic zkey bytes')
    const sha = (b: Buffer): string => createHash('sha256').update(b).digest('hex')
    const pins = { 'transaction2.wasm': { size: wasm.length, sha256: sha(wasm) }, 'transaction2.zkey': { size: zkey.length, sha256: sha(zkey) } } as Record<'transaction2.wasm' | 'transaction2.zkey', Pin>
    writeFileSync(join(t.dir, 'transaction2.wasm'), wasm)
    writeFileSync(join(t.dir, 'transaction2.zkey'), Buffer.from('synthetic zkey BYTES'))      // same size, other bytes
    assert.deepEqual(loadArtifact(t.dir, 'transaction2.wasm', pins), wasm)
    assert.equal(guardOf(() => loadArtifact(t.dir, 'transaction2.zkey', pins)), 'relay.pc-artifact')
    writeFileSync(join(t.dir, 'x.bin'), wasm); symlinkSync(join(t.dir, 'x.bin'), join(t.dir, 'link.zkey'))
    mkdirSync(join(t.dir, 'sub'))
    assert.equal(guardOf(() => loadArtifact(t.dir, 'transaction2.zkey', { ...pins, 'transaction2.zkey': { size: 1, sha256: '0'.repeat(64) } })), 'relay.pc-artifact')   // wrong size
    assert.equal(guardOf(() => loadArtifact(join(t.dir, 'nope'), 'transaction2.wasm', pins)), 'relay.pc-artifact')                                                      // missing
    assert.equal(guardOf(() => loadArtifact(t.dir, 'transaction2.wasm')), 'relay.pc-artifact')                                                                          // the real pins: not these bytes
    // a symlink at the pinned name is not served even when its target has the right bytes
    const t2 = tempDir('vt-pc-art2-')
    try {
      writeFileSync(join(t2.dir, 'real'), wasm); symlinkSync(join(t2.dir, 'real'), join(t2.dir, 'transaction2.wasm'))
      assert.equal(guardOf(() => loadArtifact(t2.dir, 'transaction2.wasm', pins)), 'relay.pc-artifact')
    } finally { t2.cleanup() }
  } finally { t.cleanup() }
})

test('torRequired: refuses relay.pc-tor unless Tor holds', () => {
  assert.equal(guardOf(() => torRequired(true)), null)
  assert.equal(guardOf(() => torRequired(false)), 'relay.pc-tor')
})

test('assertWithdrawAllowed: a withdrawal is FUNDING — C2\'s funding lock (assertSendAllowed), never the job-send lock; refused release.mainnet-locked while the build locks funding', () => {
  assert.equal(guardOf(() => assertWithdrawAllowed()), 'release.mainnet-locked')
  // the lock handed in is called once with the mainnet profile and the mainnet SOL identity; its refusal is the answer
  const seen: unknown[][] = []
  assert.equal(guardOf(() => assertWithdrawAllowed((...a) => { seen.push(a) })), null)
  assert.deepEqual(seen, [['mainnet', { chain: 'sol', id: GENESIS.sol.mainnet }]])
  assert.equal(guardOf(() => assertWithdrawAllowed(() => { throw new Refusal('release.mainnet-locked', 'x') })), 'release.mainnet-locked')
})

test('the funding lock, not the job-send lock: privacycash.ts reaches only assertSendAllowed (MAINNET_SEND_ENABLED); the two flags are distinct in config.ts', () => {
  const src = readFileSync(fileURLToPath(new URL('../src/privacycash.ts', import.meta.url)), 'utf8')
  const code = src.split('\n').filter((l) => !l.trimStart().startsWith('//')).join('\n')
  assert.ok(!/assertJobSendAllowed|MAINNET_JOB_SENDS_ENABLED/.test(code), 'no job-send lock in the code')
  assert.equal([...code.matchAll(/assertSendAllowed/g)].length, 2)                                   // the import and the default
  const cfg = readFileSync(fileURLToPath(import.meta.resolve('vt-broadcast/src/config.ts')), 'utf8')
  assert.match(cfg, /export function assertSendAllowed\([^)]*\)[^{]*\{\s*return lock\(MAINNET_SEND_ENABLED, 'all'/)
  // the job lock reads its own flag (after PF-S M-1's prologue: a btc observation off local first takes the all-scope lock)
  assert.match(cfg, /export function assertJobSendAllowed\([^)]*\)[^{]*\{(?:(?!\n\})[^])*?\n {2}return lock\(MAINNET_JOB_SENDS_ENABLED, 'job'/)
})

// =====================================================================================================================
// 5. the real relay, in process, against fakes
// =====================================================================================================================
interface Call { url: string; method: string; body: string | null; role: string; user: string; headers: string[]; timeoutMs?: number }
interface World { calls: Call[]; tor: { isTor: boolean }; rpcGenesis: { v: string | null }; fail: { code: string | null }; transport: (url: string, r: { method: string; body?: Buffer; role: string; user: string; headers?: Record<string, string>; timeoutMs?: number }) => Promise<{ status: number; body: Buffer }>; answer: { relayer: (c: Call) => { status: number; body: unknown } | null; rpc: (c: Call) => { status: number; body: unknown } | null } }
const json = (status: number, v: unknown): { status: number; body: Buffer } => ({ status, body: Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)) })
function fakeWorld(network: Network): World {
  const calls: Call[] = []
  const tor = { isTor: true }
  const rpcGenesis: { v: string | null } = { v: GENESIS.sol.mainnet }
  const fail: { code: string | null } = { code: null }
  const answer: World['answer'] = { relayer: () => null, rpc: () => null }
  const transport: World['transport'] = async (url, r) => {
    const c: Call = { url, method: r.method, body: r.body ? r.body.toString('utf8') : null, role: r.role, user: r.user, headers: Object.keys(r.headers ?? {}), ...(r.timeoutMs ? { timeoutMs: r.timeoutMs } : {}) }
    if (url === 'https://check.torproject.org/api/ip') return json(200, { IsTor: tor.isTor })
    const j = c.body === null ? null : JSON.parse(c.body) as { id?: unknown; method?: string }
    if (r.role !== 'privacycash' && r.role !== 'privacycash-rpc') {                   // the relay's own startup identity checks (not Privacy Cash traffic)
      if (j?.method === 'getGenesisHash') return json(200, { jsonrpc: '2.0', id: j.id ?? 1, result: network === 'local' ? LOCAL_SOL : network === 'testnet' ? GENESIS.sol.devnet : GENESIS.sol.mainnet })
      if (j?.method === 'eth_chainId') return json(200, { jsonrpc: '2.0', id: j.id ?? 1, result: `0x${NETWORK_IDS[network].eth.toString(16)}` })
      return json(404, {})
    }
    calls.push(c)
    if (fail.code !== null && r.role === 'privacycash') throw Object.assign(new Error('injected'), { code: fail.code })
    if (r.role === 'privacycash-rpc' && j?.method === 'getGenesisHash') return rpcGenesis.v === null ? json(503, {}) : json(200, { jsonrpc: '2.0', id: j.id ?? 1, result: rpcGenesis.v })
    const a = url.startsWith(PC_RELAYER) || url.startsWith(FAKE_RELAYER) ? answer.relayer(c) : answer.rpc(c)
    return a === null ? json(404, {}) : json(a.status, a.body)
  }
  return { calls, tor, rpcGenesis, fail, transport, answer }
}

interface Started { port: number; network: Network; logs: string[]; w: World; clock: { t: number }; dir: string; relay: ReturnType<typeof createRelay>; close(): Promise<void> }
const OPEN = new Set<Started>()
const CLEAN: Array<() => void> = []
after(() => { for (const c of CLEAN) c() })
after(() => Promise.all([...OPEN].map((s) => s.close())))
async function start(network: Network, o: { artifactDir?: string | null; pins?: Record<string, Pin>; pc?: 'default' | 'none' | 'fake'; sol?: boolean; lock?: FundingLock; stateDir?: string | null } = {}): Promise<Started> {
  const dir = o.stateDir === undefined ? (() => { const t = tempDir('vt-pc-state-'); CLEAN.push(t.cleanup); return t.dir })() : (o.stateDir ?? '')
  const w = fakeWorld(network)
  const logs: string[] = []
  const clock = { t: NOW }
  const pc = o.pc === 'none' ? undefined : o.pc === 'fake' ? { relayer: [FAKE_RELAYER], rpc: ['http://127.0.0.1:19002'], artifactDir: o.artifactDir ?? null, ...(o.pins ? { pins: o.pins } : {}), ...(Object.hasOwn(o, 'lock') ? { lock: o.lock } : {}), ...(o.stateDir === null ? {} : { stateDir: dir }) }
    : { ...relayPrivacyCash(network, {}), artifactDir: o.artifactDir ?? null, ...(o.pins ? { pins: o.pins } : {}), ...(Object.hasOwn(o, 'lock') ? { lock: o.lock } : {}), ...(o.stateDir === null ? {} : { stateDir: dir }) }
  const relay = createRelay({
    network, build: 'test', upstream: network === 'local' ? { eth: [], sol: ['http://127.0.0.1:19003'] } : relayUpstreams(network, {}), transport: w.transport, priceFixture: null, ticketKey: () => TICKET_KEY,
    confinement: { ok: true, probes: 5, result: 'EPERM ×5' }, now: () => clock.t, log: (l: string) => { logs.push(l) }, rand: () => 'sess', ...(pc ? { privacycash: pc } : {}),
  })
  await relay.startup()
  const server: Server = createServer(relay.handle)
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  const s: Started = { dir, port: (server.address() as { port: number }).port, network, logs, w, clock, relay, close: () => { OPEN.delete(s); relay.close(); return new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()) }) } }
  OPEN.add(s)
  return s
}
interface Reply { status: number; headers: Record<string, string | string[] | undefined>; text: string; json: any }
function rq(s: Started, path: string, o: { method?: string; body?: unknown; headers?: Record<string, string>; ct?: string | null } = {}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const b = o.body === undefined ? null : Buffer.from(typeof o.body === 'string' ? o.body : JSON.stringify(o.body))
    const r = request({ host: '127.0.0.1', port: s.port, path, method: o.method ?? (b ? 'POST' : 'GET'),
      headers: { host: `127.0.0.1:${PORTS[s.network].relay}`, ...(b && o.ct !== null ? { 'content-type': o.ct ?? 'application/json', 'content-length': String(b.length) } : {}), ...o.headers } }, (res) => {
      const c: Buffer[] = []
      res.on('data', (d: Buffer) => c.push(d))
      res.on('end', () => {
        const text = Buffer.concat(c).toString('utf8')
        let j: unknown
        try { j = JSON.parse(text) } catch { j = undefined }
        resolve({ status: res.statusCode ?? 0, headers: res.headers, text, json: j })
      })
    })
    r.on('error', reject)
    r.end(b ?? undefined)
  })
}
const g = (r: Reply): string | undefined => r.json?.error?.data?.guard

test('mainnet: every relayer route and the rpc are forwarded over Tor on role privacycash to the fixed relayer / the mainnet RPC list; headers and responses are the relay\'s own', async () => {
  const s = await start('mainnet')
  s.w.answer.relayer = (c) => (c.method === 'POST' && c.url.endsWith('/utxos/indices') ? { status: 200, body: { indices: [1, 2] } } : { status: 200, body: { upstream: c.url.slice(PC_RELAYER.length) } })
  s.w.answer.rpc = () => ({ status: 200, body: { jsonrpc: '2.0', id: 3, result: { context: { slot: 9 }, value: [null, null] } } })
  const startCalls = s.w.calls.length
  const cases: Array<[string, string, unknown, string]> = [
    ['GET', `${R}config`, undefined, '/config'],
    ['GET', `${R}utxos/range?start=10&end=20010`, undefined, '/utxos/range?start=10&end=20010'],
    ['GET', `${R}merkle/proofv2/?commitments=${COMMIT},${COMMIT}`, undefined, `/merkle/proofv2/?commitments=${COMMIT},${COMMIT}`],
  ]
  for (const [m, p, , up] of cases) {
    const r = await rq(s, p, { method: m })
    assert.deepEqual([r.status, r.json], [200, { upstream: up }], p)
    assert.equal(r.headers['cache-control'], 'no-store'); assert.equal(r.headers['x-content-type-options'], 'nosniff'); assert.equal(r.headers['content-type'], 'application/json')
    const c = s.w.calls.at(-1)!
    assert.deepEqual([c.url, c.method, c.role, c.body, c.headers], [`${PC_RELAYER}${up}`, 'GET', 'privacycash', null, []], p)
    assert.match(c.user, /^privacycash\.sess\.\d+$/)
  }
  const expectMs: Record<string, number> = { '/config': 30000, '/utxos/range?start=10&end=20010': 120000 }
  assert.equal(s.w.calls.find((c) => c.url.endsWith('/utxos/range?start=10&end=20010'))?.timeoutMs, expectMs['/utxos/range?start=10&end=20010'])
  assert.equal(s.w.calls.find((c) => c.url.endsWith('/config'))?.timeoutMs, expectMs['/config'])
  const ind = await rq(s, `${R}utxos/indices`, { body: { encrypted_outputs: [OUT] } })
  assert.deepEqual([ind.status, ind.json], [200, { indices: [1, 2] }])
  assert.deepEqual([s.w.calls.at(-1)!.url, s.w.calls.at(-1)!.method, s.w.calls.at(-1)!.body, s.w.calls.at(-1)!.timeoutMs], [`${PC_RELAYER}/utxos/indices`, 'POST', JSON.stringify({ encrypted_outputs: [OUT] }), 60000])
  const rpc = await rq(s, '/relay/privacycash/rpc', { body: rpcBody() })
  assert.deepEqual([rpc.status, rpc.json.result.value], [200, [null, null]])
  const c = s.w.calls.at(-1)!
  assert.ok(/^https:\/\/(?:api\.mainnet-beta\.solana\.com|solana-rpc\.publicnode\.com)/.test(c.url), 'the mainnet sol.rpc list')
  assert.equal(c.method, 'POST'); assert.equal(c.role, 'privacycash-rpc'); assert.equal(c.timeoutMs, 60000); assert.match(c.user, /^privacycash-rpc\.sess\.\d+$/)
  const gen = s.w.calls.find((x) => x.role === 'privacycash-rpc' && x.body === GENESIS_BODY.toString())
  assert.ok(gen, 'the RPC genesis check ran first, on its own role'); assert.equal(gen.timeoutMs, 30000)
  assert.equal(c.body, JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'getMultipleAccounts', params: [[KEY, KEY], { encoding: 'base64' }] }))
  assert.equal(s.w.calls.length - startCalls, 3 + 1 + 1 + (new Set(s.w.calls.filter((x) => x.role === 'privacycash-rpc').map((x) => x.url)).size))
  // the Tor status names the role
  const tor = await rq(s, '/relay/tor')
  assert.ok(tor.json.torRoles.includes('privacycash') && tor.json.torRoles.includes('privacycash-rpc'))
  // nothing in the log carries a body, a query or a path parameter
  const logs = s.logs.join('\n')
  for (const needle of [COMMIT, OUT, KEY, 'start=10', 'encrypted_outputs']) assert.ok(!logs.includes(needle), `log has ${needle.slice(0, 8)}`)
  assert.ok(s.logs.some((l) => /^privacycash utxos\/range GET 200 \d+ms$/.test(l)))
  await s.close()
})

test('refused before anything is forwarded: unlisted paths, wrong methods, bad queries/bodies, a non-JSON content type, a repeated header', async () => {
  const s = await start('mainnet')
  const before = s.w.calls.length
  const cases: Array<[Reply, number, string]> = [
    [await rq(s, `${R}deposit`, { method: 'POST', body: {} }), 403, 'relay.path'],
    [await rq(s, `${R}withdraw/spl`, { method: 'POST', body: {} }), 403, 'relay.path'],
    [await rq(s, `${R}merkle/root`), 403, 'relay.path'],
    [await rq(s, '/relay/privacycash/bridge'), 403, 'relay.path'],
    [await rq(s, `${R}config`, { method: 'POST', body: {} }), 403, 'relay.method'],
    [await rq(s, `${R}utxos/indices`), 403, 'relay.method'],
    [await rq(s, `${R}utxos/range?start=0&end=1`), 403, 'relay.pc-query'],
    [await rq(s, `${R}merkle/proofv2/?commitments=1,2&token=x`), 403, 'relay.pc-query'],
    [await rq(s, `${R}utxos/indices`, { body: { encrypted_outputs: [] } }), 403, 'relay.pc-body'],
    [await rq(s, '/relay/privacycash/rpc', { body: rpcBody({ method: 'sendTransaction' }) }), 403, 'relay.pc-body'],
    [await rq(s, '/relay/privacycash/rpc', { body: [rpcBody(), rpcBody()] }), 403, 'relay.pc-body'],
    [await rq(s, `${R}utxos/indices`, { body: { encrypted_outputs: [OUT] }, ct: 'text/plain' }), 403, ''],
    [await rq(s, `${R}config`, { headers: { origin: 'http://evil.example' } }), 403, 'relay.origin'],
    [await rq(s, `${R}config`, { headers: { 'sec-fetch-site': 'cross-site' } }), 403, 'relay.fetch-site'],
  ]
  for (const [r, st, guard] of cases) { assert.equal(r.status, st); if (guard) assert.equal(g(r), guard) }
  assert.equal(s.w.calls.length, before, 'nothing was forwarded')
  await s.close()
})

test('request body over the cap: 413 relay.pc-body-cap, nothing forwarded', async () => {
  const s = await start('mainnet')
  const r = await rq(s, `${R}utxos/indices`, { body: `{"encrypted_outputs":["${'ab'.repeat(130 * 1024)}"]}` })
  assert.deepEqual([r.status, g(r)], [413, 'relay.pc-body-cap'])
  const w = await rq(s, '/relay/privacycash/rpc', { body: `{"jsonrpc":"2.0","method":"getMultipleAccounts","params":[["${'1'.repeat(70 * 1024)}"]]}` })
  assert.deepEqual([w.status, g(w)], [413, 'relay.pc-body-cap'])
  assert.equal(s.w.calls.length, 0)
  await s.close()
})

test('the job-send lock: a withdrawal is refused release.mainnet-locked on mainnet, testnet and local before the body is read; the relayer sees nothing', async () => {
  for (const network of ['mainnet', 'testnet', 'local'] as const) {
    const s = await start(network, network === 'local' ? { pc: 'fake' } : {})
    s.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
    for (const body of [withdrawBody(), { garbage: true }]) {
      const r = await rq(s, `${R}withdraw`, { body })
      assert.deepEqual([r.status, g(r)], [403, 'release.mainnet-locked'], `${network} ${JSON.stringify(body).slice(0, 20)}`)
      assert.ok(!r.text.includes(KEY) && !r.text.includes(PROOF))
    }
    assert.equal(s.w.calls.length, 0, `${network}: nothing forwarded`)
    assert.ok(s.logs.some((l) => /^privacycash withdraw POST 403 \d+ms release\.mainnet-locked$/.test(l)))
    await s.close()
  }
})

test('Tor, fail closed: off local an IsTor ✗ answers 503 relay.pc-tor and nothing is forwarded; local goes direct to its (fake) loopback upstreams', async () => {
  const s = await start('mainnet')
  s.w.answer.relayer = () => ({ status: 200, body: {} })
  assert.equal((await rq(s, `${R}config`)).status, 200)
  s.w.tor.isTor = false; s.clock.t += 61_000                   // the cached check expires
  const n = s.w.calls.length
  for (const [p, b] of [[`${R}config`, undefined], ['/relay/privacycash/rpc', rpcBody()]] as const) {
    const r = await rq(s, p, b ? { body: b } : {})
    assert.deepEqual([r.status, g(r)], [503, 'relay.pc-tor'])
  }
  assert.equal(s.w.calls.length, n)
  await s.close()
  const l = await start('local', { pc: 'fake' })
  l.w.answer.relayer = (c) => ({ status: 200, body: { at: c.url } })
  l.w.answer.rpc = () => ({ status: 200, body: { jsonrpc: '2.0', id: 3, result: { value: [] } } })
  assert.deepEqual((await rq(l, `${R}config`)).json, { at: `${FAKE_RELAYER}/config` })
  assert.equal((await rq(l, '/relay/privacycash/rpc', { body: rpcBody() })).status, 200)
  await l.close()
})

test('upstream answers are shape-checked (502, nothing of it passed on); an upstream 5xx/403 is a 502 with no upstream text; 404 is the relay\'s own', async () => {
  const s = await start('testnet')
  const answers: Array<{ status: number; body: unknown }> = [
    { status: 200, body: '<html>SECRET-UPSTREAM</html>' }, { status: 200, body: '"SECRET-UPSTREAM"' }, { status: 200, body: `{"x":"${'y'.repeat(70 * 1024)}"}` },
    { status: 500, body: 'SECRET-UPSTREAM' }, { status: 403, body: 'SECRET-UPSTREAM' }, { status: 429, body: 'SECRET-UPSTREAM' },
  ]
  for (const a of answers) {
    s.w.answer.relayer = () => a
    const r = await rq(s, `${R}config`)
    assert.equal(r.status, 502); assert.ok(!r.text.includes('SECRET-UPSTREAM') && !r.text.includes('yyyy'))
    if (a.status === 200) assert.equal(g(r), 'relay.pc-upstream-shape')
  }
  s.w.answer.relayer = () => ({ status: 404, body: 'SECRET-UPSTREAM' })
  const nf = await rq(s, `${R}config`)
  assert.equal(nf.status, 404); assert.ok(!nf.text.includes('SECRET'))
  await s.close()
})

test('the circuit files are served locally from memory, hash-checked at boot; a file that is not the pinned one answers 503; nothing goes upstream', async () => {
  const t = tempDir('vt-pc-serve-')
  try {
    const wasm = Buffer.from('synthetic wasm bytes'), zkey = Buffer.from('synthetic zkey bytes')
    const sha = (b: Buffer): string => createHash('sha256').update(b).digest('hex')
    writeFileSync(join(t.dir, 'transaction2.wasm'), wasm)
    writeFileSync(join(t.dir, 'transaction2.zkey'), Buffer.from('synthetic zkey BYTES'))
    const pins = { 'transaction2.wasm': { size: wasm.length, sha256: sha(wasm) }, 'transaction2.zkey': { size: zkey.length, sha256: sha(zkey) } }
    const s = await start('mainnet', { artifactDir: t.dir, pins })
    const w = await rq(s, '/relay/privacycash/artifacts/transaction2.wasm')
    assert.equal(w.status, 200); assert.equal(w.text, wasm.toString()); assert.equal(w.headers['content-type'], 'application/wasm'); assert.equal(w.headers['x-content-type-options'], 'nosniff')
    writeFileSync(join(t.dir, 'transaction2.wasm'), 'changed after boot')           // a later change on disk is never served
    assert.equal((await rq(s, '/relay/privacycash/artifacts/transaction2.wasm')).text, wasm.toString())
    const z = await rq(s, '/relay/privacycash/artifacts/transaction2.zkey')
    assert.equal(z.status, 503)
    assert.ok(s.logs.some((l) => l === 'privacycash: transaction2.zkey is not served (relay.pc-artifact)'))
    assert.equal(s.w.calls.length, 0)
    await s.close()
    const none = await start('mainnet')                                              // no artifact dir
    assert.equal((await rq(none, '/relay/privacycash/artifacts/transaction2.wasm')).status, 503)
    await none.close()
  } finally { t.cleanup() }
})

test('without upstreams (local default, or no privacycash option) the relayer routes and the rpc answer 503; the route list still applies', async () => {
  for (const o of [{ pc: 'none' as const }, {}]) {
    const s = await start('local', o)
    for (const [p, b] of [[`${R}config`, undefined], ['/relay/privacycash/rpc', rpcBody()]] as const) assert.equal((await rq(s, p, b ? { body: b } : {})).status, 503)
    assert.equal((await rq(s, `${R}deposit`, { method: 'POST', body: {} })).status, 403)
    assert.equal(s.w.calls.length, 0)
    await s.close()
  }
})

test('relayPrivacyCash: off local only the fixed relayer and the MAINNET sol.rpc list; local has none', () => {
  assert.deepEqual(relayPrivacyCash('local', {}).relayer, [])
  assert.deepEqual(relayPrivacyCash('local', {}).rpc, [])
  for (const n of ['testnet', 'mainnet'] as const) {
    const c = relayPrivacyCash(n, {})
    assert.deepEqual(c.relayer, [PC_RELAYER])
    assert.deepEqual(c.rpc, relayUpstreams('mainnet', {}).sol)
    assert.ok(c.rpc.length > 0 && c.rpc.every((u) => u.startsWith('https://')))
  }
})

// =====================================================================================================================
// 6. fix round 1: the withdrawal, semantically (ruling B); the lock (A); the RPC identity (C); timeouts and roles (D)
// =====================================================================================================================
const LANE = 'Vote111111111111111111111111111111111111111'            // a valid 32-byte key, standing for the lane's address
const OTHER = 'Stake11111111111111111111111111111111111111'
const KEYB = Buffer.from(TICKET_KEY)
const keyBytes = (s: string): Buffer => Buffer.from(new PublicKey(s).toBytes())
const be32 = (v: bigint): Buffer => Buffer.from(v.toString(16).padStart(64, '0'), 'hex')
const le64 = (v: bigint): Buffer => { const b = Buffer.alloc(8); b.writeBigInt64LE(v); return b }
const ule64 = (v: bigint): Buffer => { const b = Buffer.alloc(8); b.writeBigUInt64LE(v); return b }
const ule32 = (v: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32LE(v); return b }
const MINT = keyBytes('11111111111111111111111111111112')
const ENC1 = Buffer.alloc(64, 0xa1), ENC2 = Buffer.alloc(64, 0xb2)
// A transact instruction as the research lays it out, independently of the implementation.
function mkProof(o: { ext?: bigint; fee?: bigint; enc1?: Buffer; enc2?: Buffer; recipient?: string; feeRecipient?: string; wrongHash?: boolean; edit?: (b: Buffer) => void } = {}): Buffer {
  const ext = o.ext ?? -1_000_000_000n, fee = o.fee ?? 7_000_000n, enc1 = o.enc1 ?? ENC1, enc2 = o.enc2 ?? ENC2
  const body = Buffer.alloc(488)
  TRANSACT_DISCRIMINATOR.copy(body, 0)
  for (let off = 8; off < 488; off += 32) body[off + 31] = (off / 32) & 0xff || 1                          // small field elements
  const borsh = Buffer.concat([keyBytes(o.recipient ?? LANE), le64(ext), ule32(enc1.length), enc1, ule32(enc2.length), enc2, ule64(fee), keyBytes(o.feeRecipient ?? PC_FIXED.feeRecipientAccount), MINT])
  const digest = createHash('sha256').update(borsh).digest()
  const w = BigInt(`0x${Buffer.from(digest).reverse().toString('hex')}`) % FIELD_R                       // LE(digest) mod r, written big-endian
  be32(o.wrongHash ? (w + 1n) % FIELD_R : w).copy(body, 328)
  const tail = Buffer.concat([le64(ext), ule64(fee), ule32(enc1.length), enc1, ule32(enc2.length), enc2])
  const out = Buffer.concat([body, tail])
  o.edit?.(out)
  return out
}
function good(over: Record<string, unknown> = {}, p: Parameters<typeof mkProof>[0] = {}): Record<string, unknown> {
  const ext = p.ext ?? -1_000_000_000n, fee = p.fee ?? 7_000_000n
  return { serializedProof: mkProof(p).toString('base64'), ...PC_FIXED, nullifier0PDA: KEY, nullifier1PDA: KEY, nullifier2PDA: KEY, nullifier3PDA: KEY, recipient: LANE,
    extAmount: Number(ext), fee: Number(fee), encryptedOutput1: (p.enc1 ?? ENC1).toString('base64'), encryptedOutput2: (p.enc2 ?? ENC2).toString('hex'), ...over }
}
let NONCE = 0
const nextNonce = (): string => (++NONCE).toString(16).padStart(32, '0')
const shaOf = (body: unknown): string => createHash('sha256').update(buf(body)).digest('hex')
// An authorization for exactly this body (the bytes sem() / rq() send).
const lane = (body: unknown, o: { recipient?: string; allowance?: bigint; exp?: number; network?: Network; key?: Buffer; job?: string; tryIndex?: number; nonce?: string; sha?: string } = {}): string =>
  mintWithdrawAuth(o.key ?? KEYB, { network: o.network ?? 'mainnet', recipient: o.recipient ?? LANE, job: o.job ?? 'e3d45f73cf65abaa', tryIndex: o.tryIndex ?? 0, allowance: o.allowance ?? 2_000_000_000n,
    nonce: o.nonce ?? nextNonce(), bodySha256: o.sha ?? shaOf(body), exp: o.exp ?? NOW + 60_000 })
const sem = (body: unknown, header: string | undefined = lane(body), network: Network = 'mainnet'): void => { checkWithdrawSemantics(buf(body), { header, key: KEYB, network, now: NOW }) }

test('the synthetic withdrawal is syntactically valid and passes the semantic checks', () => {
  const b = good()
  assert.equal(guardOf(() => checkPcBody(resolvePc('POST', `${R}withdraw`), buf(b))), null)
  assert.equal(guardOf(() => sem(b)), null)
  assert.equal(guardOf(() => sem(good({}, { fee: feeCeiling(1_000_000_000n) }))), null)        // exactly the clamp
})

test('withdraw semantics: the authorization is the requesting lane\'s, canonical, for THIS body, in its window (relay.pc-lane)', () => {
  const b = good()
  const ok = lane(b)
  for (const [h, why] of [['', 'empty'], ['v1.junk', 'junk'], [lane(b, { recipient: OTHER }), 'another recipient bound'], [lane(b, { exp: NOW - 1 }), 'expired'], [lane(b, { exp: NOW }), 'expires now'],
    [lane(b, { exp: NOW + WITHDRAW_AUTH_WINDOW_MS + 1 }), 'one ms past the window'], [lane(b, { network: 'testnet' }), 'another network'], [lane(b, { key: Buffer.alloc(32, 9) }), 'another key'],
    [`${ok.slice(0, -1)}${ok.endsWith('0') ? '1' : '0'}`, 'bad mac'], [lane(b, { sha: shaOf({ other: 1 }) }), 'another body'], [lane(good({}, { fee: 6_000_000n })), 'authorized for another body'],
    [ok.replace(/^v2\.([^.]+)\.([^.]+)\.0\./, 'v2.$1.$2.00.'), 'leading-zero try'], [ok.replace('.2000000000.', '.02000000000.'), 'leading-zero allowance'],
    [ok.replace(`.${NOW + 60_000}.`, `.0${NOW + 60_000}.`), 'leading-zero exp'], [ok.replace(/^v2/, 'v1'), 'old version'], [`${ok}.`, 'trailing dot'], [` ${ok}`, 'leading space'],
  ] as const) assert.equal(guardOf(() => sem(b, h)), 'relay.pc-lane', why)
  assert.equal(guardOf(() => sem(b, lane(b, { exp: NOW + WITHDRAW_AUTH_WINDOW_MS }))), null, 'exp exactly at the window bound')
  assert.equal(guardOf(() => checkWithdrawSemantics(buf(b), { header: undefined, key: KEYB, network: 'mainnet', now: NOW })), 'relay.pc-lane', 'no authorization')
  assert.equal(guardOf(() => sem(good({ recipient: OTHER }, { recipient: OTHER }))), 'relay.pc-lane')
  // the documented format and MAC
  const n = nextNonce(), sha = shaOf(b)
  const mac = createHmac('sha256', KEYB).update(`vt-pc-wd/2|mainnet|${LANE}|e3d45f73cf65abaa|7|2000000000|${n}|${sha}|${NOW + 60_000}`).digest('hex')
  assert.equal(lane(b, { tryIndex: 7, nonce: n }), `v2.${LANE}.e3d45f73cf65abaa.7.2000000000.${n}.${sha}.${NOW + 60_000}.${mac}`)
  const v = verifyWithdrawAuth(lane(b, { tryIndex: 7, nonce: n }), KEYB, 'mainnet', NOW, sha)
  assert.deepEqual([v?.job, v?.tryIndex, v?.allowance, v?.nonce], ['e3d45f73cf65abaa', 7, 2_000_000_000n, n])
})

test('withdraw semantics: pinned pool accounts (relay.pc-accounts), amount cap (relay.pc-amount), fee clamp (relay.pc-fee)', () => {
  for (const k of Object.keys(PC_FIXED)) assert.equal(guardOf(() => sem(good({ [k]: OTHER }))), 'relay.pc-accounts', k)
  assert.equal(guardOf(() => sem(good({}, { ext: -1_993_000_000n }))), null)                   // |ext| + fee exactly the allowance
  assert.equal(guardOf(() => sem(good({}, { ext: -1_993_000_001n }))), 'relay.pc-amount')
  assert.equal(guardOf(() => sem(good({}, { fee: feeCeiling(1_000_000_000n) + 1n }))), 'relay.pc-fee')
  assert.equal(guardOf(() => sem(good({}, { ext: -100_000_000n, fee: feeCeiling(100_000_000n) + 1n }))), 'relay.pc-fee')
  assert.equal(guardOf(() => sem(good({}, { ext: -100_000_000n, fee: feeCeiling(100_000_000n) }))), null)
})

test('withdraw semantics: the proof decodes (discriminator, field ranges, lengths, embedded fields) — relay.pc-proof', () => {
  const edit = (f: (b: Buffer) => void) => good({}, { edit: f })
  const cases: Array<[string, Record<string, unknown>]> = [
    ['discriminator', edit((b) => { b[0] ^= 1 })],
    ['proofA x >= q', edit((b) => { be32(FIELD_Q).copy(b, 8) })],
    ['proofC y >= q', edit((b) => { be32(FIELD_Q + 5n).copy(b, 232) })],
    ['root >= r', edit((b) => { be32(FIELD_R).copy(b, 264) })],
    ['nullifier >= r', edit((b) => { be32(FIELD_R + 1n).copy(b, 360) })],
    ['commitment >= r', edit((b) => { Buffer.alloc(32, 0xff).copy(b, 456) })],
    ['embedded extAmount differs', edit((b) => { le64(-999n).copy(b, 488) })],
    ['embedded fee differs', edit((b) => { ule64(1n).copy(b, 496) })],
    ['encOut1 length lies', edit((b) => { b.writeUInt32LE(65, 504) })],
    ['encOut2 length lies', edit((b) => { b.writeUInt32LE(63, 508 + 64) })],
    ['trailing byte', edit(() => {})],
    ['encOut1 in JSON differs', good({ encryptedOutput1: Buffer.alloc(64, 1).toString('base64') })],
    ['encOut2 in JSON differs', good({ encryptedOutput2: 'ab'.repeat(64) })],
    ['JSON extAmount differs', good({ extAmount: -1_000_000_001 })],
    ['JSON fee differs', good({ fee: 7_000_001 })],
  ]
  cases[10][1] = good({ serializedProof: Buffer.concat([mkProof(), Buffer.from([0])]).toString('base64') })
  for (const [why, b] of cases) assert.equal(guardOf(() => sem(b)), 'relay.pc-proof', why)
  assert.equal(decodeProof(Buffer.alloc(511).toString('base64')), null)
  assert.equal(decodeProof(`${mkProof().toString('base64')}\n`), null)                        // not canonical base64
  const d = decodeProof(mkProof().toString('base64'))
  assert.ok(d && d.extAmount === -1_000_000_000n && d.fee === 7_000_000n && d.enc1.equals(ENC1) && d.enc2.equals(ENC2))
})

test('withdraw semantics: the extDataHash binds recipient, amount, outputs, fee and fee recipient (relay.pc-ext-hash)', () => {
  assert.equal(guardOf(() => sem(good({}, { wrongHash: true }))), 'relay.pc-ext-hash')
  // a proof made for another recipient (the lane binding says LANE): its hash does not bind LANE
  assert.equal(guardOf(() => sem(good({}, { recipient: OTHER }))), 'relay.pc-ext-hash')
  // made with another fee recipient (the body names the pinned one)
  assert.equal(guardOf(() => sem(good({}, { feeRecipient: OTHER }))), 'relay.pc-ext-hash')
})

const hdr = (body: unknown, o: Parameters<typeof lane>[1] = {}): Record<string, string> => ({ [LANE_HEADER]: lane(body, o) })

test('withdraw over HTTP (the funding lock open by the test seam ONLY): a valid withdrawal is forwarded once, as the canonical body, over role privacycash, with NO header upstream; every semantic refusal forwards nothing', async () => {
  const s = await start('local', { pc: 'fake', lock: () => undefined })
  s.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
  const dup = JSON.stringify(good()).replace('{', '{"fee":1,')                                  // a duplicate key: the later one wins when parsed
  const bodyOf = good()
  const ok = await rq(s, `${R}withdraw`, { body: dup, headers: hdr(dup, { network: 'local' }) })
  assert.deepEqual([ok.status, ok.json], [200, { signature: SIG58 }])
  const c = s.w.calls.at(-1)!
  assert.deepEqual([c.url, c.method, c.role, c.timeoutMs, c.body, c.headers], [`${FAKE_RELAYER}/withdraw`, 'POST', 'privacycash', 90000, JSON.stringify(JSON.parse(dup)), []])
  assert.notEqual(c.body, dup)
  const n = s.w.calls.length
  const L = { network: 'local' as Network }
  const refusals: Array<[Reply, string]> = [
    [await rq(s, `${R}withdraw`, { body: bodyOf }), 'relay.pc-lane'],
    [await rq(s, `${R}withdraw`, { body: bodyOf, headers: hdr(bodyOf, { ...L, recipient: OTHER }) }), 'relay.pc-lane'],
    [await rq(s, `${R}withdraw`, { body: bodyOf, headers: hdr({ other: 1 }, L) }), 'relay.pc-lane'],
    [await rq(s, `${R}withdraw`, { body: good({}, { fee: 11_000_001n }), headers: hdr(good({}, { fee: 11_000_001n }), L) }), 'relay.pc-fee'],
    [await rq(s, `${R}withdraw`, { body: good({}, { wrongHash: true }), headers: hdr(good({}, { wrongHash: true }), L) }), 'relay.pc-ext-hash'],
    [await rq(s, `${R}withdraw`, { body: good({ treeAccount: OTHER }), headers: hdr(good({ treeAccount: OTHER }), L) }), 'relay.pc-accounts'],
    [await rq(s, `${R}withdraw`, { body: good({ referralId: 'x' }), headers: hdr(good({ referralId: 'x' }), L) }), 'relay.pc-body'],
  ]
  for (const [r, guard] of refusals) assert.deepEqual([r.status, g(r)], [403, guard])
  assert.equal(s.w.calls.length, n, 'nothing more was forwarded')
  await s.close()
})

test('ruling A over HTTP: job sends ENABLED but funding LOCKED still refuses withdrawals (the relay asks the funding lock only); funding open + job locked is allowed past the lock', async () => {
  const fundingLocked: FundingLock = () => { throw new Refusal('release.mainnet-locked', 'funding is locked') }
  const s = await start('mainnet', { lock: fundingLocked })
  s.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
  const r = await rq(s, `${R}withdraw`, { body: good(), headers: hdr(good()) })
  assert.deepEqual([r.status, g(r)], [403, 'release.mainnet-locked'])
  assert.equal(s.w.calls.length, 0)
  assert.ok(!existsSync(join(s.dir, LEDGER_FILE)), 'a locked withdrawal reserves nothing')
  await s.close()
  const s2 = await start('mainnet', { lock: () => undefined })        // models: funding open, whatever the job lock says
  s2.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
  assert.equal((await rq(s2, `${R}withdraw`, { body: good(), headers: hdr(good()) })).status, 200)
  await s2.close()
})

// ---- I-1: single use, durable, cumulative
test('I-1: the reviewer\'s probe — one allowance, three withdrawals (1.5 SOL each, a replay and a new body): only what fits is forwarded, the replay is refused relay.pc-replay', async () => {
  const s = await start('mainnet', { lock: () => undefined })
  s.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
  const b1 = good({}, { ext: -1_500_000_000n }), b2 = good({}, { ext: -1_500_001_000n })
  const a1 = { [LANE_HEADER]: lane(b1, { allowance: 2_000_000_000n }) }
  assert.equal((await rq(s, `${R}withdraw`, { body: b1, headers: a1 })).status, 200)
  const replay = await rq(s, `${R}withdraw`, { body: b1, headers: a1 })               // the exact replay
  assert.deepEqual([replay.status, g(replay)], [403, 'relay.pc-replay'])
  const b2r = await rq(s, `${R}withdraw`, { body: b2, headers: hdr(b2, { allowance: 2_000_000_000n }) })   // a new body, a fresh nonce
  assert.deepEqual([b2r.status, g(b2r)], [403, 'relay.pc-allowance'])
  assert.equal(s.w.calls.filter((c) => c.url.endsWith('/withdraw')).length, 1)
  await s.close()
})

test('I-1: a replay after a RESTART is refused (the nonce is durable), and the committed total is rebuilt', async () => {
  const s = await start('mainnet', { lock: () => undefined })
  s.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
  const b = good({}, { ext: -1_000_000_000n })
  const h = { [LANE_HEADER]: lane(b) }
  assert.equal((await rq(s, `${R}withdraw`, { body: b, headers: h })).status, 200)
  assert.equal(statSync(join(s.dir, LEDGER_FILE)).mode & 0o777, 0o600)
  const dir = s.dir
  await s.close()
  const s2 = await start('mainnet', { lock: () => undefined, stateDir: dir })
  s2.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
  const r = await rq(s2, `${R}withdraw`, { body: b, headers: h })
  assert.deepEqual([r.status, g(r)], [403, 'relay.pc-replay'])
  const b2 = good({}, { ext: -1_000_000_001n })                                        // 1.007 + 1.007 SOL > the 2 SOL allowance
  const r2 = await rq(s2, `${R}withdraw`, { body: b2, headers: hdr(b2) })
  assert.deepEqual([r2.status, g(r2)], [403, 'relay.pc-allowance'])
  assert.equal(s2.w.calls.filter((c) => c.url.endsWith('/withdraw')).length, 0)
  await s2.close()
})

test('I-1: an ambiguous upstream result (timeout) stays RESERVED; a proven not-accepted result RELEASES the amount (the nonce stays burned)', async () => {
  const s = await start('mainnet', { lock: () => undefined })
  const b1 = good({}, { ext: -1_000_000_000n }), b2 = good({}, { ext: -999_000_000n }), b3 = good({}, { ext: -998_000_000n })
  s.w.fail.code = 'ETIMEDOUT'
  const r1 = await rq(s, `${R}withdraw`, { body: b1, headers: hdr(b1) })
  assert.equal(r1.status, 502); assert.ok(/do not withdraw again/.test(r1.text))
  s.w.fail.code = null; s.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
  const r2 = await rq(s, `${R}withdraw`, { body: b2, headers: hdr(b2) })                 // 1.007 + 1.006 > 2: the timed-out one still counts
  assert.deepEqual([r2.status, g(r2)], [403, 'relay.pc-allowance'])
  await s.close()
  const t = await start('mainnet', { lock: () => undefined })
  t.w.fail.code = 'ECONNREFUSED'                                                         // a SOCKS failure: never delivered
  const h1 = hdr(b1)
  assert.equal((await rq(t, `${R}withdraw`, { body: b1, headers: h1 })).status, 503)
  t.w.fail.code = null; t.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
  const replay = await rq(t, `${R}withdraw`, { body: b1, headers: h1 })
  assert.deepEqual([replay.status, g(replay)], [403, 'relay.pc-replay'])               // burned even though released
  const ok = await rq(t, `${R}withdraw`, { body: b3, headers: hdr(b3) })
  assert.equal(ok.status, 200)                                                           // the released amount is available again
  await t.close()
  const l = openWithdrawalLedger(t.dir)
  assert.equal(l.committed(LANE), 998_000_000n + 7_000_000n); l.close()
})

test('I-1: cumulative over the allowance is refused, exactly at the allowance is allowed; an unwritable ledger refuses (relay.pc-ledger) and forwards nothing', async () => {
  const s = await start('mainnet', { lock: () => undefined })
  s.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
  const A = 2_000_000_000n
  const a = good({}, { ext: -993_000_000n }), b = good({}, { ext: -993_000_000n, enc1: Buffer.alloc(64, 0xc3) }), c = good({}, { ext: -1_000_000n, fee: 6_000_000n, enc1: Buffer.alloc(64, 0xd4) })
  assert.equal((await rq(s, `${R}withdraw`, { body: a, headers: hdr(a, { allowance: A }) })).status, 200)       // 1.000
  assert.equal((await rq(s, `${R}withdraw`, { body: b, headers: hdr(b, { allowance: A }) })).status, 200)       // 2.000 = allowance
  const over = await rq(s, `${R}withdraw`, { body: c, headers: hdr(c, { allowance: A }) })
  assert.deepEqual([over.status, g(over)], [403, 'relay.pc-allowance'])
  await s.close()
  // unwritable: the state dir does not exist / is read-only / the file is group-readable / no state dir at all
  const missing = join(tempDir('vt-pc-x-').dir, 'nope', 'deeper')
  for (const [why, mk] of [['missing dir', () => missing], ['no state dir', () => null]] as const) {
    const u = await start('mainnet', { lock: () => undefined, stateDir: mk() })
    u.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
    const r = await rq(u, `${R}withdraw`, { body: a, headers: hdr(a) })
    assert.deepEqual([r.status, g(r)], [403, 'relay.pc-ledger'], why); assert.equal(u.w.calls.filter((x) => x.url.endsWith('/withdraw')).length, 0, why)
    await u.close()
  }
  const ro = tempDir('vt-pc-ro-')
  chmodSync(ro.dir, 0o500)
  try {
    const u = await start('mainnet', { lock: () => undefined, stateDir: ro.dir })
    const r = await rq(u, `${R}withdraw`, { body: a, headers: hdr(a) })
    assert.deepEqual([r.status, g(r)], [403, 'relay.pc-ledger'], 'read-only dir'); assert.equal(u.w.calls.filter((x) => x.url.endsWith('/withdraw')).length, 0)
    await u.close()
  } finally { chmodSync(ro.dir, 0o700); ro.cleanup() }
  const gr = tempDir('vt-pc-gr-')
  writeFileSync(join(gr.dir, LEDGER_FILE), '', { mode: 0o644 }); chmodSync(join(gr.dir, LEDGER_FILE), 0o644)
  try {
    const u = await start('mainnet', { lock: () => undefined, stateDir: gr.dir })
    assert.equal(g(await rq(u, `${R}withdraw`, { body: a, headers: hdr(a) })), 'relay.pc-ledger', 'group-readable ledger')
    await u.close()
  } finally { gr.cleanup() }
  // a corrupt ledger (a spent line for an unknown nonce) refuses everything
  const co = tempDir('vt-pc-co-')
  writeFileSync(join(co.dir, LEDGER_FILE), '{"v":1,"t":"spent","n":"x"}\n', { mode: 0o600 })
  try {
    const u = await start('mainnet', { lock: () => undefined, stateDir: co.dir })
    assert.equal(g(await rq(u, `${R}withdraw`, { body: a, headers: hdr(a) })), 'relay.pc-ledger', 'corrupt ledger')
    await u.close()
  } finally { co.cleanup() }
})

test('the withdrawal ledger: concurrent reservations of one nonce or over the allowance cannot both pass; an unacknowledged tail is cut off on load', () => {
  const t = tempDir('vt-pc-led-')
  try {
    const l = openWithdrawalLedger(t.dir)
    const r = (n: string, amount: bigint) => ({ nonce: n, lane: LANE, job: 'e3d45f73cf65abaa', tryIndex: 0, bodySha256: 'ab'.repeat(32), enc1: ENC1.toString('hex'), amount, allowance: 100n, exp: NOW })
    assert.equal(guardOf(() => l.reserve(r('01'.repeat(16), 60n), NOW)), null)
    assert.equal(guardOf(() => l.reserve(r('01'.repeat(16), 1n), NOW)), 'relay.pc-replay')
    assert.equal(guardOf(() => l.reserve(r('02'.repeat(16), 41n), NOW)), 'relay.pc-allowance')
    assert.equal(guardOf(() => l.reserve(r('03'.repeat(16), 40n), NOW)), null)
    l.release('01'.repeat(16)); assert.equal(l.committed(LANE), 40n)
    l.release('01'.repeat(16)); assert.equal(l.committed(LANE), 40n)                      // releasing twice does not go negative
    l.settle('03'.repeat(16), SIG58); l.release('03'.repeat(16)); assert.equal(l.committed(LANE), 40n)   // a spent one cannot be released
    l.close()
    writeFileSync(join(t.dir, LEDGER_FILE), `${readFileSync(join(t.dir, LEDGER_FILE), 'utf8')}{"v":1,"t":"res`, { mode: 0o600 })
    const l2 = openWithdrawalLedger(t.dir)
    assert.equal(l2.broken(), null); assert.equal(l2.committed(LANE), 40n)
    assert.equal(guardOf(() => l2.reserve(r('01'.repeat(16), 1n), NOW)), 'relay.pc-replay')
    l2.close()
    assert.ok(readFileSync(join(t.dir, LEDGER_FILE), 'utf8').endsWith('\n'))
  } finally { t.cleanup() }
})

test('M-2: the seams are read from OWN properties only (an inherited lock / pins / stateDir is ignored); relayPrivacyCash returns exactly three keys', async () => {
  assert.deepEqual(Object.keys(relayPrivacyCash('mainnet', {})).sort(), ['artifactDir', 'relayer', 'rpc'])
  const proto = Object.prototype as unknown as Record<string, unknown>
  proto.lock = () => undefined
  try {
    const s = await start('mainnet')
    s.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
    const r = await rq(s, `${R}withdraw`, { body: good(), headers: hdr(good()) })
    assert.deepEqual([r.status, g(r)], [403, 'release.mainnet-locked'])
    await s.close()
  } finally { delete proto.lock }
})

test('Privacy Cash RPC identity (ruling C): the genesis hash is checked per endpoint on role privacycash-rpc; a mismatch disables the route until restart; no answer is rechecked after 30 s', async () => {
  assert.equal(pcRpcIdentity(200, buf({ jsonrpc: '2.0', id: 1, result: GENESIS.sol.mainnet })), true)
  for (const [st, b] of [[500, '{}'], [200, 'x'], [200, '{"result":5}'], [200, '{}']] as const) assert.equal(pcRpcIdentity(st, buf(b)), false)
  for (const id of [GENESIS.sol.devnet, GENESIS.sol.testnet, 'x']) assert.equal(guardOf(() => pcRpcIdentity(200, buf({ result: id }))), 'relay.pc-rpc-identity')
  // mismatch
  const s = await start('mainnet')
  s.w.rpcGenesis.v = GENESIS.sol.devnet
  s.w.answer.rpc = () => ({ status: 200, body: { jsonrpc: '2.0', id: 3, result: { value: [] } } })
  const r = await rq(s, '/relay/privacycash/rpc', { body: rpcBody() })
  assert.equal(r.status, 503)
  assert.ok(s.w.calls.every((c) => c.body === GENESIS_BODY.toString()), 'only genesis probes went out, never the request')
  const probes = s.w.calls.length
  s.w.rpcGenesis.v = GENESIS.sol.mainnet; s.clock.t += 120_000
  assert.equal((await rq(s, '/relay/privacycash/rpc', { body: rpcBody() })).status, 503)       // disabled until restart
  assert.equal(s.w.calls.length, probes)
  assert.ok(s.logs.some((l) => /DISABLED.*relay\.pc-rpc-identity/.test(l)))
  await s.close()
  // no answer: not used, rechecked after 30 s
  const d = await start('mainnet')
  d.w.rpcGenesis.v = null
  d.w.answer.rpc = () => ({ status: 200, body: { jsonrpc: '2.0', id: 3, result: { value: [] } } })
  assert.equal((await rq(d, '/relay/privacycash/rpc', { body: rpcBody() })).status, 503)
  d.w.rpcGenesis.v = GENESIS.sol.mainnet
  assert.equal((await rq(d, '/relay/privacycash/rpc', { body: rpcBody() })).status, 503)       // inside the 30 s
  d.clock.t += 31_000
  assert.equal((await rq(d, '/relay/privacycash/rpc', { body: rpcBody() })).status, 200)
  await d.close()
})

test('per-route timeouts (ruling D): utxos/range 120 s, indices 60 s, config/proofv2/check 30 s, withdraw 90 s, rpc 60 s; the relayer and the RPC are two Tor roles', () => {
  const t = (m: string, p: string): number => resolvePc(m, p).timeoutMs
  assert.deepEqual([t('GET', `${R}config`), t('GET', `${R}utxos/range?start=0&end=20000`), t('POST', `${R}utxos/indices`), t('GET', `${R}merkle/proofv2/?commitments=1,2`),
    t('POST', `${R}withdraw`), t('GET', `${R}utxos/check/${OUT}`), t('POST', '/relay/privacycash/rpc')], [30000, 120000, 60000, 30000, 90000, 30000, 60000])
})

test('FIELD constants are BN254\'s', () => {
  assert.equal(FIELD_R.toString(16), '30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001')
  assert.equal(FIELD_Q.toString(16), '30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47')
})

// =====================================================================================================================
// 7. Sfix-PC: the fee on the gross (item 3), the network rule (item 6), the single-process ledger (item 4), /utxos/check
//    gating and the recorded signature (item 5), the reconcile path (M-6 / N-3). FAKES ONLY.
// =====================================================================================================================
import { LEDGER_LOCK_FILE, validRecord } from '../src/privacycash-ledger.ts'
import { ENC_MAX_BYTES, ENC_MIN_BYTES, decodeLine, encodeLine } from '../src/pc-record.ts'
import type { LedgerIo } from '../src/privacycash-ledger.ts'
import { FEE_BASE_LAMPORTS } from '../src/privacycash.ts'

const ENC1_HEX = ENC1.toString('hex')
const ledgerLines = (dir: string): Array<Record<string, unknown>> => readFileSync(join(dir, LEDGER_FILE), 'utf8').split('\n').filter((l) => l !== '').map((l) => JSON.parse(l) as Record<string, unknown>)
const withdrawCount = (s: Started): number => s.w.calls.filter((c) => c.url.endsWith('/withdraw')).length

test('item 3: the fee ceiling is computed on the GROSS of the published schedule (0.006 SOL + 0.35 % of the gross) plus a small margin: small withdrawals pass (W6 concern 1)', () => {
  // W6: at a net of 0.01 SOL the published schedule is 6,056,196 lamports; the old clamp (0.006 + 0.5 % of the NET) was 6,050,000.
  assert.equal(guardOf(() => sem(good({}, { ext: -10_000_000n, fee: 6_056_196n }))), null)
  assert.ok(6_056_196n > FEE_BASE_LAMPORTS + (10_000_000n * 5n) / 1000n, 'the old net-based clamp would have refused it')
  for (const net of [10_000_000n, 14_000_000n, 50_000_000n, 100_000_000n, 1_000_000_000n, 25_000_000_000n, 500_000_000_000n]) {
    const schedule = (FEE_BASE_LAMPORTS * 10_000n + 35n * net + 9_964n) / 9_965n                    // fee = 6,000,000 + 0.35 % of (net + fee), rounded up
    assert.ok(feeCeiling(net) >= schedule, `ceiling >= schedule at ${net}`)
    assert.ok(feeCeiling(net) <= schedule + net / 1000n + 2n, `the margin is small at ${net}`)      // about 0.05 % of the gross
    const atCeiling = good({}, { ext: -net, fee: feeCeiling(net) }), over = good({}, { ext: -net, fee: feeCeiling(net) + 1n })
    assert.equal(guardOf(() => sem(atCeiling, lane(atCeiling, { allowance: 10n ** 12n }))), null, `at the ceiling ${net}`)
    assert.equal(guardOf(() => sem(over, lane(over, { allowance: 10n ** 12n }))), 'relay.pc-fee', `one lamport over at ${net}`)
  }
  assert.equal(guardOf(() => sem(good({}, { fee: 10_100_000n }))), 'relay.pc-fee')                  // 1 SOL net: the schedule is 9.5 M; 10.1 M is not the schedule
  assert.equal(feeCeiling(0n), 6_024_097n)                                                         // the base on the gross (6,000,000 / (1 - 0.40 %)) + 1 rounding lamport
})

test('item 6 (S7 review M-1): a testnet stack refuses a withdrawal carrying the mainnet pool parameters; a mainnet stack refuses one carrying none of them', async () => {
  const mainnetBody = good()
  const foreignBody = good({ treeAccount: OTHER, treeTokenAccount: OTHER, globalConfigAccount: OTHER, feeRecipientAccount: OTHER, lookupTableAddress: OTHER }, { feeRecipient: OTHER })
  assert.equal(guardOf(() => sem(mainnetBody, lane(mainnetBody, { network: 'testnet' }), 'testnet')), 'relay.pc-network')
  assert.equal(guardOf(() => sem(foreignBody, lane(foreignBody), 'mainnet')), 'relay.pc-network')
  assert.equal(guardOf(() => sem(mainnetBody, lane(mainnetBody), 'mainnet')), null)
  const partly = good({ treeAccount: OTHER })
  assert.equal(guardOf(() => sem(partly, lane(partly), 'mainnet')), 'relay.pc-accounts', 'a partly wrong set is the accounts guard')
  // a testnet stack with a foreign (non-mainnet) parameter set passes THIS guard and meets the accounts guard
  assert.equal(guardOf(() => sem(foreignBody, lane(foreignBody, { network: 'testnet' }), 'testnet')), 'relay.pc-accounts')
  // over HTTP: a testnet relay with the funding lock opened by the seam ONLY forwards nothing and reserves nothing
  const t = await start('testnet', { lock: () => undefined })
  t.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
  const r = await rq(t, `${R}withdraw`, { body: mainnetBody, headers: hdr(mainnetBody, { network: 'testnet' }) })
  assert.deepEqual([r.status, g(r)], [403, 'relay.pc-network'])
  assert.equal(withdrawCount(t), 0); assert.ok(!existsSync(join(t.dir, LEDGER_FILE)))
  await t.close()
  // a mainnet relay given a binding minted for the testnet stack: not this network's
  const m = await start('mainnet', { lock: () => undefined })
  m.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
  const r2 = await rq(m, `${R}withdraw`, { body: mainnetBody, headers: hdr(mainnetBody, { network: 'testnet' }) })
  assert.deepEqual([r2.status, g(r2)], [403, 'relay.pc-lane'])
  const r3 = await rq(m, `${R}withdraw`, { body: foreignBody, headers: hdr(foreignBody) })
  assert.deepEqual([r3.status, g(r3)], [403, 'relay.pc-network'])
  assert.equal(withdrawCount(m), 0)
  await m.close()
})

test('item 4 (S7 N-2): one relay per state directory — a second ledger on the same directory refuses Privacy Cash ONLY (relay.pc-ledger-lock / relay.pc-check), the rest of the relay starts; close() frees it; a dead holder is taken over', async () => {
  const t = tempDir('vt-pc-lock-')
  try {
    const a = openWithdrawalLedger(t.dir)
    assert.equal(a.broken(), null)
    assert.ok(existsSync(join(t.dir, LEDGER_LOCK_FILE)))
    const second = openWithdrawalLedger(t.dir)
    assert.equal(second.broken(), 'another relay process holds this ledger')
    const rsv = { nonce: '0a'.repeat(16), lane: LANE, job: 'e3d45f73cf65abaa', tryIndex: 0, bodySha256: 'ab'.repeat(32), enc1: ENC1.toString('hex'), amount: 10n, allowance: 100n, exp: NOW }
    assert.equal(guardOf(() => second.reserve(rsv, NOW)), 'relay.pc-ledger-lock')
    assert.equal(second.recorded(ENC1.toString('hex')), false)
    second.close()
    assert.ok(existsSync(join(t.dir, LEDGER_LOCK_FILE)), 'the refused second ledger did not release the first one\'s lock')
    // a whole relay on the held directory STARTS; only its Privacy Cash routes are refused
    const s = await start('local', { pc: 'fake', lock: () => undefined, stateDir: t.dir })
    s.w.answer.relayer = () => ({ status: 200, body: { ok: true } })
    assert.equal((await rq(s, `${R}config`)).status, 200, 'a read route works')
    const b = good()
    const w = await rq(s, `${R}withdraw`, { body: b, headers: hdr(b, { network: 'local' }) })
    assert.deepEqual([w.status, g(w)], [403, 'relay.pc-ledger-lock'])
    assert.equal(g(await rq(s, `${R}utxos/check/${ENC1.toString('hex')}`)), 'relay.pc-check')
    assert.equal(withdrawCount(s), 0)
    assert.equal((await rq(s, '/relay/tor')).status, 200, 'the rest of the relay is up')
    await s.close()
    a.close()
    assert.ok(!existsSync(join(t.dir, LEDGER_LOCK_FILE)), 'released')
    const b2 = openWithdrawalLedger(t.dir)
    assert.equal(b2.broken(), null)
    b2.close()
    // a crash leaves the file with a dead pid: stale, taken over
    writeFileSync(join(t.dir, LEDGER_LOCK_FILE), '2147483646\n', { mode: 0o600 })
    const c = openWithdrawalLedger(t.dir)
    assert.equal(c.broken(), null)
    assert.equal(readFileSync(join(t.dir, LEDGER_LOCK_FILE), 'utf8'), `${process.pid}\n`)
    c.close()
    // no state dir: nothing to lock (every withdrawal is refused there anyway)
    openWithdrawalLedger(null).close(); openWithdrawalLedger(null).close()
    // a state dir that cannot take the lock (missing): the ledger is bad, not a lock refusal
    assert.equal(openWithdrawalLedger(join(t.dir, 'missing')).broken(), 'cannot take the ledger lock')
  } finally { t.cleanup() }
})

test('item 4 (S7 N-1): the reserve line is written AND fsynced before anything is forwarded — order pinned through the io seam; a failing fsync refuses and forwards nothing; over HTTP the line is on disk when the upstream is called', async () => {
  const t = tempDir('vt-pc-io-')
  try {
    const events: string[] = []
    const io: LedgerIo = { write: (fd, b) => { events.push(`write:${(JSON.parse(b.toString('utf8')) as { t: string }).t}`); return writeSync(fd, b, 0, b.length) }, fsync: (fd) => { events.push('fsync'); fsyncSync(fd) } }
    const l = openWithdrawalLedger(t.dir, io)
    const rsv = { nonce: '0a'.repeat(16), lane: LANE, job: 'e3d45f73cf65abaa', tryIndex: 0, bodySha256: 'ab'.repeat(32), enc1: ENC1_HEX, amount: 10n, allowance: 100n, exp: NOW }
    l.reserve(rsv, NOW)
    assert.deepEqual(events, ['write:reserve', 'fsync'], 'reserve = one write then one fsync, both inside reserve()')
    events.length = 0
    l.settle('0a'.repeat(16), SIG58)
    assert.deepEqual(events, ['write:spent', 'fsync'])
    l.close()
  } finally { t.cleanup() }
  const f = tempDir('vt-pc-iof-')
  try {
    const l = openWithdrawalLedger(f.dir, { write: (fd, b) => writeSync(fd, b, 0, b.length), fsync: () => { throw new Error('EIO') } })
    const rsv = { nonce: '0b'.repeat(16), lane: LANE, job: 'e3d45f73cf65abaa', tryIndex: 0, bodySha256: 'ab'.repeat(32), enc1: ENC1_HEX, amount: 10n, allowance: 100n, exp: NOW }
    assert.equal(guardOf(() => l.reserve(rsv, NOW)), 'relay.pc-ledger')
    assert.equal(l.committed(LANE), 0n, 'nothing stays reserved in memory')
    assert.equal(guardOf(() => l.reserve({ ...rsv, nonce: '0c'.repeat(16) }, NOW)), 'relay.pc-ledger', 'broken for the rest of the process')
    l.close()
  } finally { f.cleanup() }
  // over HTTP: inside the (fake) relayer's answer, the ledger file already holds the reserve line for this nonce
  const s = await start('mainnet', { lock: () => undefined })
  let seen: Array<Record<string, unknown>> = []
  s.w.answer.relayer = (c) => { if (c.url.endsWith('/withdraw')) seen = ledgerLines(s.dir); return { status: 200, body: { signature: SIG58 } } }
  const b = good()
  assert.equal((await rq(s, `${R}withdraw`, { body: b, headers: hdr(b) })).status, 200)
  assert.deepEqual(seen.map((x) => x.t), ['reserve'], 'only the reserve line existed when the upstream was called')
  assert.equal(seen[0].e, ENC1_HEX); assert.equal(seen[0].amount, String(1_007_000_000))
  assert.deepEqual(ledgerLines(s.dir).map((x) => x.t), ['reserve', 'spent'])
  await s.close()
})

test('item 5 (M-6): /utxos/check/<hex> is forwarded only for the first encrypted output of a withdrawal this relay forwarded (reserved or spent), never for a released or unknown one — relay.pc-check', async () => {
  const s = await start('local', { pc: 'fake', lock: () => undefined })
  s.w.answer.relayer = (c) => (c.url.endsWith('/withdraw') ? { status: 200, body: { signature: SIG58 } } : { status: 200, body: { spent: true } })
  const L = { network: 'local' as Network }
  const chk = (hex: string): Promise<Reply> => rq(s, `${R}utxos/check/${hex}`)
  const before = await chk(ENC1_HEX)
  assert.deepEqual([before.status, g(before)], [403, 'relay.pc-check'], 'no withdrawal yet')
  assert.equal(s.w.calls.length, 0, 'nothing went upstream')
  const b = good()
  assert.equal((await rq(s, `${R}withdraw`, { body: b, headers: hdr(b, L) })).status, 200)
  const ok = await chk(ENC1_HEX)
  assert.deepEqual([ok.status, ok.json], [200, { spent: true }])
  assert.equal(s.w.calls.at(-1)!.url, `${FAKE_RELAYER}/utxos/check/${ENC1_HEX}`)
  const other = await chk(Buffer.alloc(64, 0x77).toString('hex'))
  assert.deepEqual([other.status, g(other)], [403, 'relay.pc-check'], 'another output')
  const prefix = await chk(ENC1_HEX.slice(0, 72))
  assert.deepEqual([prefix.status, g(prefix)], [403, 'relay.pc-check'], 'a prefix is not the output')
  await s.close()
  // after a restart the record is still there; a RELEASED withdrawal (proven not accepted) is not a record
  const s2 = await start('local', { pc: 'fake', lock: () => undefined, stateDir: s.dir })
  s2.w.answer.relayer = () => ({ status: 200, body: { spent: false } })
  assert.equal((await rq(s2, `${R}utxos/check/${ENC1_HEX}`)).status, 200)
  await s2.close()
  const e2 = Buffer.alloc(64, 0xe2), b2 = good({}, { enc1: e2 })
  const r = await start('local', { pc: 'fake', lock: () => undefined })
  r.w.fail.code = 'ECONNREFUSED'                                                         // SOCKS failure: never delivered, released
  assert.equal((await rq(r, `${R}withdraw`, { body: b2, headers: hdr(b2, L) })).status, 503)
  r.w.fail.code = null; r.w.answer.relayer = () => ({ status: 200, body: { spent: false } })
  const rel = await rq(r, `${R}utxos/check/${e2.toString('hex')}`)
  assert.deepEqual([rel.status, g(rel)], [403, 'relay.pc-check'], 'released: not a record')
  await r.close()
  // no ledger at all records nothing
  const none = await start('local', { pc: 'fake', lock: () => undefined, stateDir: null })
  assert.equal(g(await rq(none, `${R}utxos/check/${ENC1_HEX}`)), 'relay.pc-check')
  await none.close()
})

test('item 5 (N-3): a 200 settles to spent WITH the withdrawal signature, recorded durably (and reloaded); a 200 without a valid signature is not spent but flagged', async () => {
  const s = await start('mainnet', { lock: () => undefined })
  s.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
  const b = good()
  assert.equal((await rq(s, `${R}withdraw`, { body: b, headers: hdr(b) })).status, 200)
  const lines = ledgerLines(s.dir)
  assert.deepEqual(lines.map((x) => x.t), ['reserve', 'spent'])
  assert.equal(lines[1].sig, SIG58); assert.equal(lines[1].n, lines[0].n)
  const dir = s.dir
  await s.close()
  const l = openWithdrawalLedger(dir)
  assert.equal(l.signatureOf(String(lines[0].n)), SIG58); assert.equal(l.reconciling().length, 0)
  l.close()
  // no signature / a malformed one / not JSON: flagged, still reserved
  for (const [why, body, status, expectWhy] of [['absent', { success: true }, 200, 'no-signature'], ['malformed', { signature: 'not a signature' }, 502, 'bad-answer'], ['html', '<html>', 502, 'bad-answer']] as const) {
    const u = await start('mainnet', { lock: () => undefined })
    u.w.answer.relayer = () => ({ status: 200, body })
    const r = await rq(u, `${R}withdraw`, { body: b, headers: hdr(b) })
    assert.equal(r.status, status, why)
    assert.deepEqual(ledgerLines(u.dir).map((x) => [x.t, x.why ?? null]), [['reserve', null], ['reconcile', expectWhy]], why)
    assert.ok(u.logs.some((x) => x.includes(`RECONCILE ${expectWhy}`)), why)
    await u.close()
  }
})

test('item 5 (M-6 / N-3): a 400 / 404 / other status from the relayer, or an ambiguous result, leaves the amount RESERVED and FLAGGED for reconciliation (operator-visible); resolving it spends or frees the allowance', async () => {
  for (const [status, why, httpStatus] of [[400, 'http-400', 502], [404, 'http-404', 404], [422, 'http-status', 502]] as const) {
    const s = await start('mainnet', { lock: () => undefined })
    s.w.answer.relayer = () => ({ status, body: 'SECRET-UPSTREAM' })
    const b1 = good({}, { ext: -1_000_000_000n })
    const r = await rq(s, `${R}withdraw`, { body: b1, headers: hdr(b1) })
    assert.equal(r.status, httpStatus); assert.ok(!r.text.includes('SECRET'))
    assert.deepEqual(ledgerLines(s.dir).map((x) => [x.t, x.why ?? null]), [['reserve', null], ['reconcile', why]], String(status))
    assert.ok(s.logs.some((x) => x.includes(`privacycash withdraw RECONCILE ${why} `)), 'operator-visible in the log')
    assert.deepEqual(s.relay.privacycash.reconciling().map((i) => [i.why, i.lane, i.amount]), [[why, LANE, 1_007_000_000n]])
    assert.ok(!s.logs.some((x) => x.includes(LANE) || x.includes('SECRET')), 'no address in the log')
    // the amount still counts: 1.007 + 1.006 SOL > the 2 SOL allowance
    const b2 = good({}, { ext: -999_000_000n, enc1: Buffer.alloc(64, 0xc1) })
    s.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
    const over = await rq(s, `${R}withdraw`, { body: b2, headers: hdr(b2) })
    assert.deepEqual([over.status, g(over)], [403, 'relay.pc-allowance'], 'stays reserved')
    const dir = s.dir
    await s.close()
    // a restart keeps the flag
    const l = openWithdrawalLedger(dir)
    assert.deepEqual(l.reconciling().map((i) => i.why), [why]); assert.equal(l.committed(LANE), 1_007_000_000n)
    // resolved as released: the allowance is free again, the nonce stays burned; resolving again is a no-op
    const nonce = l.reconciling()[0].nonce
    l.resolve(nonce, 'released')
    assert.equal(l.committed(LANE), 0n); assert.equal(l.reconciling().length, 0); l.resolve(nonce, 'spent'); assert.equal(l.committed(LANE), 0n)
    l.close()
    const again = openWithdrawalLedger(dir)
    assert.equal(again.committed(LANE), 0n); assert.equal(again.broken(), null, 'the resolved line replays')
    again.close()
  }
  // ambiguous (timeout): flagged; resolved as spent
  const b = good()
  const a = await start('mainnet', { lock: () => undefined })
  a.w.fail.code = 'ETIMEDOUT'
  assert.equal((await rq(a, `${R}withdraw`, { body: b, headers: hdr(b) })).status, 502)
  assert.deepEqual(ledgerLines(a.dir).map((x) => [x.t, x.why ?? null]), [['reserve', null], ['reconcile', 'ambiguous']])
  const n = a.relay.privacycash.reconciling()[0].nonce
  a.relay.privacycash.resolve(n, 'spent')
  assert.equal(a.relay.privacycash.reconciling().length, 0)
  assert.equal(ledgerLines(a.dir).at(-1)!.as, 'spent')
  await a.close()
  // a proven refusal (403 from the relayer: nothing was accepted) is a RELEASE, not a reconcile
  const f = await start('mainnet', { lock: () => undefined })
  f.w.answer.relayer = () => ({ status: 403, body: 'x' })
  assert.equal((await rq(f, `${R}withdraw`, { body: b, headers: hdr(b) })).status, 503)
  assert.deepEqual(ledgerLines(f.dir).map((x) => x.t), ['reserve', 'release'])
  await f.close()
})

test('the ledger replays only well-formed reconcile / resolved / spent lines (a spent without a signature, a resolved without a flag, an unknown reason: corrupt, every withdrawal refused)', () => {
  const r = { v: 1, t: 'reserve', n: '0d'.repeat(16), lane: LANE, job: 'e3d45f73cf65abaa', try: 0, h: 'ab'.repeat(32), e: ENC1_HEX, amount: '10', allowance: '100', exp: NOW, at: NOW }
  const cases: Array<[string, Array<Record<string, unknown>>, string | null]> = [
    ['clean', [r, { v: 1, t: 'reconcile', n: r.n, why: 'http-400' }, { v: 1, t: 'resolved', n: r.n, as: 'spent' }], null],
    ['spent without a signature', [r, { v: 1, t: 'spent', n: r.n }], 'corrupt ledger (shape)'],
    ['spent with a bad signature', [r, { v: 1, t: 'spent', n: r.n, sig: 'x' }], 'corrupt ledger (shape)'],
    ['unknown reason', [r, { v: 1, t: 'reconcile', n: r.n, why: 'because' }], 'corrupt ledger (shape)'],
    ['resolved without a flag', [r, { v: 1, t: 'resolved', n: r.n, as: 'spent' }], 'corrupt ledger (resolved)'],
    ['resolved as something else', [r, { v: 1, t: 'reconcile', n: r.n, why: 'ambiguous' }, { v: 1, t: 'resolved', n: r.n, as: 'x' }], 'corrupt ledger (shape)'],
    ['reserve without the output', [{ ...r, e: undefined }], 'corrupt ledger (shape)'],
    ['a reconcile after spent', [r, { v: 1, t: 'spent', n: r.n, sig: SIG58 }, { v: 1, t: 'reconcile', n: r.n, why: 'ambiguous' }], 'corrupt ledger (transition)'],
  ]
  for (const [name, lines, want] of cases) {
    const t = tempDir('vt-pc-rep-')
    try {
      writeFileSync(join(t.dir, LEDGER_FILE), lines.map((x) => encodeLine(x)!).join(''), { mode: 0o600 })
      const l = openWithdrawalLedger(t.dir)
      assert.equal(l.broken(), want, name)
      l.close()
    } finally { t.cleanup() }
  }
})

// =====================================================================================================================
// 8. Sfix-PC fix round 1 (review I-1): ONE validator before write and on read, request-time output bounds, checksums,
//    printable ASCII, torn last line, failed write then retry. FAKES ONLY.
// =====================================================================================================================
test('I-1: the reviewer\'s 10 / 300 / 700 byte first-output probes are refused at REQUEST time (relay.pc-proof), nothing is reserved or forwarded, and the ledger stays usable after a restart', async () => {
  const s = await start('mainnet', { lock: () => undefined })
  s.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
  for (const n of [1, 10, 35, 201, 300, 700, 750]) {
    const body = good({}, { enc1: Buffer.alloc(n, 0xaa) })
    const r = await rq(s, `${R}withdraw`, { body, headers: hdr(body) })
    assert.equal(r.status, 403, `${n} B`); assert.match(String(g(r)), /^relay\.pc-(?:proof|body)$/, `${n} B`)
    const body2 = good({}, { enc2: Buffer.alloc(n, 0xbb) })
    assert.match(String(g(await rq(s, `${R}withdraw`, { body: body2, headers: hdr(body2) }))), /^relay\.pc-(?:proof|body)$/, `second output ${n} B`)
  }
  assert.equal(withdrawCount(s), 0); assert.ok(!existsSync(join(s.dir, LEDGER_FILE)), 'nothing was written')
  // the boundaries are accepted and round-trip through a restart
  for (const n of [ENC_MIN_BYTES, ENC_MAX_BYTES]) {
    const body = good({}, { ext: -100_000_000n, fee: feeCeiling(100_000_000n), enc1: Buffer.alloc(n, 0xc0 + (n % 16)), enc2: Buffer.alloc(n, 0xd0) })
    assert.equal((await rq(s, `${R}withdraw`, { body, headers: hdr(body) })).status, 200, `${n} B`)
  }
  const dir = s.dir
  await s.close()
  const s2 = await start('mainnet', { lock: () => undefined, stateDir: dir })
  s2.w.answer.relayer = () => ({ status: 200, body: { signature: SIG58 } })
  assert.equal(s2.relay.privacycash.reconciling().length, 0)
  const b = good({}, { ext: -1_000_000n, fee: feeCeiling(1_000_000n), enc1: Buffer.alloc(40, 0x11) })
  assert.equal((await rq(s2, `${R}withdraw`, { body: b, headers: hdr(b) })).status, 200, 'the ledger is not broken after a restart')
  await s2.close()
})

test('I-1: the ledger\'s writer and reader share ONE validator — a reserve the reader would reject is refused before anything is set or written (and does not break the ledger); the boundary lengths round-trip', () => {
  const t = tempDir('vt-pc-val-')
  try {
    const l = openWithdrawalLedger(t.dir)
    const mk = (i: number, enc1: string, over: Record<string, unknown> = {}) => ({ nonce: i.toString(16).padStart(32, '0'), lane: LANE, job: 'e3d45f73cf65abaa', tryIndex: 0, bodySha256: 'ab'.repeat(32), enc1, amount: 1n, allowance: 10n ** 12n, exp: NOW, ...over })
    for (const [i, n] of [[1, 1], [2, 10], [3, 35], [4, 201], [5, 300], [6, 700], [7, 750]] as const) {
      assert.equal(guardOf(() => l.reserve(mk(i, 'ab'.repeat(n)), NOW)), 'relay.pc-ledger', `${n} B`)
    }
    for (const bad of [{ lane: 'x' }, { job: 'zz' }, { bodySha256: 'AB'.repeat(32) }, { nonce: 'xyz' }, { exp: -1 }, { tryIndex: -1 }, { tryIndex: 1.5 }]) {
      assert.equal(guardOf(() => l.reserve(mk(8, 'ab'.repeat(40), bad), NOW)), 'relay.pc-ledger', JSON.stringify(bad))
    }
    assert.equal(l.broken(), null, 'refusals at validation do not break the ledger')
    assert.equal(l.committed(LANE), 0n); assert.ok(!existsSync(join(t.dir, LEDGER_FILE)))
    for (const [i, n] of [[10, ENC_MIN_BYTES], [11, 100], [12, ENC_MAX_BYTES]] as const) assert.equal(guardOf(() => l.reserve(mk(i, 'cd'.repeat(n)), NOW)), null, `${n} B`)
    l.close()
    const again = openWithdrawalLedger(t.dir)
    assert.equal(again.broken(), null); assert.equal(again.committed(LANE), 3n)
    again.close()
    // every line the writer produced decodes and validates
    for (const line of readFileSync(join(t.dir, LEDGER_FILE), 'utf8').split('\n').filter((x) => x !== '')) {
      const d = decodeLine(line); assert.ok(d.ok && validRecord(d.rec))
    }
    assert.ok(/^[\x20-\x7e\n]+$/.test(readFileSync(join(t.dir, LEDGER_FILE), 'utf8')), 'printable ASCII, newline only at the end of a line')
  } finally { t.cleanup() }
})

test('I-1: a per-line checksum — a changed member, a missing checksum, a bad line in the middle or at the end (newline-terminated) is corruption: every withdrawal refused', () => {
  const r = { v: 1, t: 'reserve', n: '0d'.repeat(16), lane: LANE, job: 'e3d45f73cf65abaa', try: 0, h: 'ab'.repeat(32), e: ENC1.toString('hex'), amount: '10', allowance: '100', exp: NOW, at: NOW }
  const good1 = encodeLine(r)!
  const r2 = encodeLine({ ...r, n: '0e'.repeat(16) })!
  const cases: Array<[string, string, string | null]> = [
    ['clean', good1 + r2, null],
    ['changed amount', good1.replace('"amount":"10"', '"amount":"1"') + r2, 'corrupt line'],
    ['changed amount, last line', good1 + r2.replace('"amount":"10"', '"amount":"1"'), 'corrupt line'],
    ['no checksum', good1.replace(/,"c":"[0-9a-f]{16}"/, '') + r2, 'corrupt line'],
    ['garbage in the middle', `${good1}garbage\n${r2}`, 'corrupt line'],
    ['garbage terminated at the end', `${good1}garbage\n`, 'corrupt line'],
    ['blank checksum', good1.replace(/"c":"[0-9a-f]{16}"/, '"c":""') + r2, 'corrupt line'],
  ]
  for (const [name, text, want] of cases) {
    const t = tempDir('vt-pc-sum-')
    try {
      writeFileSync(join(t.dir, LEDGER_FILE), text, { mode: 0o600 })
      const l = openWithdrawalLedger(t.dir)
      assert.equal(l.broken(), want, name)
      if (want !== null) assert.equal(guardOf(() => l.reserve({ nonce: '0f'.repeat(16), lane: LANE, job: 'e3d45f73cf65abaa', tryIndex: 0, bodySha256: 'ab'.repeat(32), enc1: ENC1.toString('hex'), amount: 1n, allowance: 100n, exp: NOW }, NOW)), 'relay.pc-ledger', name)
      l.close()
    } finally { t.cleanup() }
  }
})

test('I-1: a TORN last line (no newline) is cut on load — nothing was acknowledged before its fsync, so no under-count — and the file ends whole; a torn checksum is torn too', () => {
  const r = { v: 1, t: 'reserve', n: '0d'.repeat(16), lane: LANE, job: 'e3d45f73cf65abaa', try: 0, h: 'ab'.repeat(32), e: ENC1.toString('hex'), amount: '10', allowance: '100', exp: NOW, at: NOW }
  const whole = encodeLine(r)!
  const next = encodeLine({ ...r, n: '0e'.repeat(16), amount: '20' })!
  for (const cut of [1, 20, next.length - 20, next.length - 2, next.length - 1]) {
    const t = tempDir('vt-pc-torn-')
    try {
      writeFileSync(join(t.dir, LEDGER_FILE), whole + next.slice(0, cut), { mode: 0o600 })
      const l = openWithdrawalLedger(t.dir)
      assert.equal(l.broken(), null, `cut ${cut}`)
      assert.equal(l.committed(LANE), 10n, 'the whole line counts, the fragment does not')
      assert.equal(readFileSync(join(t.dir, LEDGER_FILE), 'utf8'), whole, 'the fragment is cut off')
      l.close()
    } finally { t.cleanup() }
  }
})

test('I-1: after a FAILED write the ledger appends nothing more in this process (fail closed until restart), retries stay refused and write nothing, and the file reloads', () => {
  const t = tempDir('vt-pc-fail-')
  try {
    let writes = 0
    let failNext = false
    const io: LedgerIo = { write: (fd, b) => { writes++; if (failNext) { failNext = false; return writeSync(fd, b, 0, 12) } return writeSync(fd, b, 0, b.length) }, fsync: (fd) => fsyncSync(fd) }
    const l = openWithdrawalLedger(t.dir, io)
    const mk = (i: number) => ({ nonce: i.toString(16).padStart(32, '0'), lane: LANE, job: 'e3d45f73cf65abaa', tryIndex: 0, bodySha256: 'ab'.repeat(32), enc1: ENC1.toString('hex'), amount: 5n, allowance: 100n, exp: NOW })
    l.reserve(mk(1), NOW)                                                                    // whole
    failNext = true
    assert.equal(guardOf(() => l.reserve(mk(2), NOW)), 'relay.pc-ledger')                    // short write: torn fragment on disk
    assert.equal(l.committed(LANE), 5n, 'the failed reserve left nothing in memory')
    const w = writes
    assert.equal(guardOf(() => l.reserve(mk(3), NOW)), 'relay.pc-ledger', 'the retry is refused')
    l.settle(mk(1).nonce, SIG58); l.release(mk(1).nonce); l.flag(mk(1).nonce, 'ambiguous'); l.resolve(mk(1).nonce, 'released')
    assert.equal(writes, w, 'no further write was even attempted')
    assert.equal(l.committed(LANE), 5n, 'the entry stays reserved (no state change without a durable line)')
    assert.deepEqual(l.reconciling(), [])
    l.close()
    const again = openWithdrawalLedger(t.dir)                                                // the torn tail is cut; the first line stands
    assert.equal(again.broken(), null); assert.equal(again.committed(LANE), 5n)
    assert.equal(guardOf(() => again.reserve(mk(2), NOW)), null, 'the nonce of the failed reserve was never acknowledged: usable')
    again.close()
  } finally { t.cleanup() }
})

test('I-1: the ledger directory is fsynced when the file is created (once), through the real descriptor path; an unwritable directory fails closed', () => {
  const t = tempDir('vt-pc-dir-')
  try {
    const l = openWithdrawalLedger(t.dir)
    l.reserve({ nonce: '0a'.repeat(16), lane: LANE, job: 'e3d45f73cf65abaa', tryIndex: 0, bodySha256: 'ab'.repeat(32), enc1: ENC1.toString('hex'), amount: 1n, allowance: 100n, exp: NOW }, NOW)
    assert.equal(statSync(join(t.dir, LEDGER_FILE)).mode & 0o777, 0o600)
    l.close()
  } finally { t.cleanup() }
})

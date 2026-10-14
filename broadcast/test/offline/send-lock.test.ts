// M1a (spec B §6.5, R42) + the job scope (canonical spec §12) + the R71 testnet identities (canonical plan C2).
// The send locks: assertSendAllowed refuses the mainnet profile (release.mainnet-locked); since the M2 flip (operator R78)
// assertJobSendAllowed gives the mainnet profile a job permit for eth / sol (mainnet btc stays behind the all-scope lock).
// Both refuse an observed mainnet identity on a testnet or local profile, accept testnet and local, and refuse an observed
// identity that is not the profile's own (config.identity-mismatch). expectedIdentity / isMainnetIdentity / identityMatches are the one
// profile -> identity map. config.mainnet-host keeps testnet Turbo/Arweave endpoints off the mainnet hosts.
// Pure functions and temp copies of the json files only: no network, no keys.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  ETH_AMSTERDAM_TIME, GENESIS, MAINNET_JOB_SENDS_ENABLED, MAINNET_SEND_ENABLED, NETWORK_IDS, assertJobSendAllowed,
  assertSendAllowed, expectedIdentity, identityMatches, isFaucetNetwork, isMainnetIdentity, isSendPermit, loadConfig,
  parseOverrides, type IdChain, type Profile, type SendPermit,
} from '../../src/config.ts'
import { Refusal } from '../../src/guard.ts'

const ROOT = new URL('../../', import.meta.url).pathname
const refused = (f: () => unknown, id: string, why = '') =>
  assert.throws(f, (e: unknown) => e instanceof Refusal && e.guardId === id, `expected ${id} ${why}`)

const CHAINS: readonly IdChain[] = ['eth', 'arb', 'base', 'sol', 'btc']
const SEPOLIA_HEX = '0xaa36a7'
const ANVIL_HEX = '0x7a69'

// A synthetic local Solana genesis (R35: random on a test validator): base58 of the bytes 1..32.
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function b58(bytes: Uint8Array): string {
  let n = 0n
  for (const b of bytes) n = n * 256n + BigInt(b)
  let s = ''
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n }
  for (const b of bytes) { if (b !== 0) break; s = '1' + s }
  return s
}
const LOCAL_SOL = b58(Uint8Array.from({ length: 32 }, (_, i) => i + 1))

const both = [
  ['assertSendAllowed', assertSendAllowed],
  ['assertJobSendAllowed', assertJobSendAllowed],
] as const

// ---- the constants

// C2 m6: the tests that pin the ALL-scope lock (assertSendAllowed / MAINNET_SEND_ENABLED) are separate from the ones that
// pin the JOB-scope lock (assertJobSendAllowed / MAINNET_JOB_SENDS_ENABLED). The operator-approved M2 flip edits only
// the tests marked "M2 FLIP" below and in net-send-permit.test.ts (the list is in docs/vt.md); the ALL-scope tests stay
// byte for byte, and one of them states that assertSendAllowed('mainnet') refuses whatever the job constant says.
const MAINNET_CASES: ReadonlyArray<readonly [string, { chain: 'eth' | 'sol' | 'btc'; id: string } | undefined]> = [
  ['no observed identity', undefined],
  ['eth 1', { chain: 'eth', id: '1' }],
  ['sol mainnet genesis', { chain: 'sol', id: GENESIS.sol.mainnet }],
  ['btc mainnet genesis', { chain: 'btc', id: GENESIS.btc.mainnet }],
  // A mainnet profile observing a testnet chain is still the mainnet profile.
  ['eth testnet id', { chain: 'eth', id: '11155111' }],
]

test('ALL scope: MAINNET_SEND_ENABLED is false in this build (never flipped)', () => {
  assert.equal(MAINNET_SEND_ENABLED, false)
})

test('ALL scope: assertSendAllowed(mainnet) is refused with or without an observed identity, whatever MAINNET_JOB_SENDS_ENABLED says', () => {
  for (const [why, observed] of MAINNET_CASES) refused(() => assertSendAllowed('mainnet', observed), 'release.mainnet-locked', why)
  // The all-scope lock reads its own constant only: with the job constant in either state the answer is the same.
  assert.equal(typeof MAINNET_JOB_SENDS_ENABLED, 'boolean')
  refused(() => assertSendAllowed('mainnet'), 'release.mainnet-locked', `job constant ${String(MAINNET_JOB_SENDS_ENABLED)}`)
})

// M2 FLIP (applied, operator R78): the three tests below were edited by the flip commit (expectation true / a permit instead of a
// refusal); nothing above.
test('JOB scope (M2 FLIP): MAINNET_JOB_SENDS_ENABLED is true in this build (lifted, operator R78)', () => {
  assert.equal(MAINNET_JOB_SENDS_ENABLED, true)
})

// M2 FLIP (applied): the mainnet profile gets a job permit with no observed identity (the API's arm and ticket paths) or with a
// mainnet eth / sol identity (the relay's). Everything else still refuses: a btc mainnet identity takes the all-scope lock (PF-S M-1
// below, which the flip does not lift), and an identity that is not mainnet's own for its chain, malformed, or of a chain outside the
// job scope is config.identity-mismatch.
test('JOB scope (M2 FLIP): assertJobSendAllowed(mainnet) gives a mainnet job permit for no identity or a mainnet eth/sol identity; every other observation still refuses', () => {
  const permits: Array<[string, SendPermit]> = [
    ['no observed identity', assertJobSendAllowed('mainnet')],
    ['eth 1', assertJobSendAllowed('mainnet', { chain: 'eth', id: '1' })],
    ['eth 0x1', assertJobSendAllowed('mainnet', { chain: 'eth', id: '0x1' })],
    ['sol mainnet genesis', assertJobSendAllowed('mainnet', { chain: 'sol', id: GENESIS.sol.mainnet })],
  ]
  for (const [why, p] of permits) {
    assert.deepEqual([isSendPermit(p), p.profile, p.scope, Object.isFrozen(p)], [true, 'mainnet', 'job', true], why)
  }
  // MAINNET_CASES, case by case: only the btc mainnet genesis and the testnet id refuse, each by its own gate.
  const allScope = (e: unknown): boolean => e instanceof Refusal && e.guardId === 'release.mainnet-locked' && /MAINNET_SEND_ENABLED\)/.test(e.message) && !/job sends/.test(e.message)
  for (const [why, observed] of MAINNET_CASES) {
    if (observed?.chain === 'btc') assert.throws(() => assertJobSendAllowed('mainnet', observed), allScope, why)
    else if (observed?.id === '11155111') refused(() => assertJobSendAllowed('mainnet', observed), 'config.identity-mismatch', why)
    else assert.equal(assertJobSendAllowed('mainnet', observed).scope, 'job', why)
  }
  // The identity check still binds the mainnet profile to mainnet's own identity of the observed chain.
  const foreign: Array<{ chain: 'eth' | 'sol' | 'btc' | 'arb'; id: string }> = [
    { chain: 'eth', id: '0xaa36a7' }, { chain: 'eth', id: '31337' }, { chain: 'eth', id: '42161' }, { chain: 'eth', id: '8453' },
    { chain: 'eth', id: ' 1 ' }, { chain: 'eth', id: '0001' }, { chain: 'eth', id: 'x' }, { chain: 'eth', id: '' },
    { chain: 'sol', id: GENESIS.sol.devnet }, { chain: 'sol', id: GENESIS.sol.testnet }, { chain: 'sol', id: LOCAL_SOL },
    { chain: 'sol', id: '1' }, { chain: 'arb', id: '42161' },
  ]
  for (const o of foreign) refused(() => assertJobSendAllowed('mainnet', o as never), 'config.identity-mismatch', `${o.chain} ${o.id}`)
  // The all-scope lock still refuses the very observations that now get a job permit.
  for (const [why, observed] of MAINNET_CASES) refused(() => assertSendAllowed('mainnet', observed), 'release.mainnet-locked', `all scope, ${why}`)
})

// M2 FLIP (applied): eth and sol mainnet identities now get a JOB-scope permit, never an all-scope one: the same observations still
// take the ALL-scope refusal (MAINNET_SEND_ENABLED). The mainnet BTC refusal is the M-1 test below, which the flip does not edit.
test('JOB scope (M2 FLIP): eth and sol on mainnet get a job-scope permit (the JOB-scope lock is lifted); the all-scope lock still refuses them', () => {
  for (const o of [{ chain: 'eth' as const, id: '1' }, { chain: 'sol' as const, id: GENESIS.sol.mainnet }]) {
    const p = assertJobSendAllowed('mainnet', o)
    assert.deepEqual([isSendPermit(p), p.profile, p.scope], [true, 'mainnet', 'job'], o.chain)
    assert.throws(() => assertSendAllowed('mainnet', o), (e: unknown) => e instanceof Refusal && e.guardId === 'release.mainnet-locked' && /MAINNET_SEND_ENABLED\)/.test(e.message) && !/job sends/.test(e.message), o.chain)
  }
})

// PF-S M-1 (pre-flip review): BTC off the local network is not a job send. assertJobSendAllowed sends a btc observation on testnet or
// mainnet through the ALL-scope lock first, so mainnet BTC stays behind MAINNET_SEND_ENABLED whatever MAINNET_JOB_SENDS_ENABLED says
// (send-lock-flip.test.ts pins that on a flipped copy). Not an M2 FLIP test: nothing in it depends on MAINNET_JOB_SENDS_ENABLED, so it
// passes unedited before and after the flip (PF-S fix round 1, N-3).
test('M-1: a mainnet BTC job send is refused by the ALL-scope lock (MAINNET_SEND_ENABLED); testnet and local BTC keep their job permit', () => {
  const allScope = (e: unknown): boolean => e instanceof Refusal && e.guardId === 'release.mainnet-locked' && /MAINNET_SEND_ENABLED\)/.test(e.message) && !/job sends/.test(e.message)
  for (const id of [GENESIS.btc.mainnet, GENESIS.btc.mainnet.toUpperCase(), GENESIS.btc.testnet4]) {
    assert.throws(() => assertJobSendAllowed('mainnet', { chain: 'btc', id }), allScope, `mainnet btc ${id}`)
  }
  assert.throws(() => assertJobSendAllowed('testnet', { chain: 'btc', id: GENESIS.btc.mainnet }), allScope)
  assert.equal(assertJobSendAllowed('testnet', { chain: 'btc', id: GENESIS.btc.testnet4 }).scope, 'job')
  assert.equal(assertJobSendAllowed('local', { chain: 'btc', id: GENESIS.btc.regtest }).scope, 'job')
  refused(() => assertJobSendAllowed('testnet', { chain: 'btc', id: GENESIS.btc.regtest }), 'config.identity-mismatch')
  // each observed property is read once, whichever lock reads it: a getter cannot show 'eth' to the btc rule and 'btc' to the lock
  const reads = { chain: 0, id: 0 }
  const sly = { get chain() { return reads.chain++ === 0 ? 'eth' : 'btc' }, get id() { reads.id++; return GENESIS.btc.testnet4 } }
  refused(() => assertJobSendAllowed('testnet', sly as never), 'config.identity-mismatch')
  assert.deepEqual(reads, { chain: 1, id: 1 })
  const reads2 = { chain: 0, id: 0 }
  const sly2 = { get chain() { reads2.chain++; return 'btc' }, get id() { return reads2.id++ === 0 ? GENESIS.btc.testnet4 : GENESIS.btc.mainnet } }
  assert.equal(assertJobSendAllowed('testnet', sly2 as never).scope, 'job')
  assert.deepEqual(reads2, { chain: 1, id: 1 })
})

// ---- release.mainnet-locked (the testnet and local side)

test('testnet and local are allowed and get a permit of their profile and scope', () => {
  for (const profile of ['testnet', 'local'] as const) {
    const all = assertSendAllowed(profile)
    const job = assertJobSendAllowed(profile)
    for (const [p, scope] of [[all, 'all'], [job, 'job']] as const) {
      assert.equal(isSendPermit(p), true)
      assert.equal(p.profile, profile)
      assert.equal(p.scope, scope)
      assert.ok(Object.isFrozen(p))
    }
    assert.notEqual(all, assertSendAllowed(profile), 'a fresh permit per call')
  }
})

test('release.mainnet-locked: a testnet or local call whose endpoint answers with a mainnet identity is refused', () => {
  const mainnetSeen: Array<{ chain: IdChain; id: string }> = [
    { chain: 'eth', id: '1' }, { chain: 'eth', id: '0x1' }, { chain: 'eth', id: '0X1' }, { chain: 'eth', id: ' 1 ' },
    { chain: 'eth', id: '0001' }, { chain: 'eth', id: '0x0001' },
    // any EVM mainnet id on any EVM chain is mainnet
    { chain: 'eth', id: '42161' }, { chain: 'eth', id: '8453' }, { chain: 'arb', id: '42161' }, { chain: 'arb', id: '0xa4b1' },
    { chain: 'base', id: '8453' }, { chain: 'base', id: '0x2105' }, { chain: 'base', id: '1' },
    { chain: 'sol', id: GENESIS.sol.mainnet },
    { chain: 'btc', id: GENESIS.btc.mainnet }, { chain: 'btc', id: GENESIS.btc.mainnet.toUpperCase() },
  ]
  for (const profile of ['testnet', 'local'] as const) {
    for (const o of mainnetSeen) refused(() => assertSendAllowed(profile, o), 'release.mainnet-locked', `${profile} ${o.chain} ${o.id}`)
    for (const o of mainnetSeen.filter((x) => x.chain === 'eth' || x.chain === 'sol' || x.chain === 'btc')) {
      refused(() => assertJobSendAllowed(profile, o as { chain: 'eth' | 'sol' | 'btc'; id: string }), 'release.mainnet-locked', `job ${profile} ${o.chain} ${o.id}`)
    }
  }
})

test('an unknown profile is refused (config.profile-invalid) and never treated as a non-mainnet one', () => {
  for (const [name, f] of both) {
    for (const p of ['Mainnet', 'MAINNET', 'testnet ', 'Testnet', '', 'prod', '__proto__']) refused(() => f(p as Profile), 'config.profile-invalid', `${name} ${JSON.stringify(p)}`)
  }
})

// ---- config.identity-mismatch

test('the profile\'s own observed identity passes (decimal or hex chain id, devnet / regtest / local genesis)', () => {
  const ok: Array<[Profile, IdChain, string]> = [
    ['testnet', 'eth', '11155111'], ['testnet', 'eth', SEPOLIA_HEX], ['testnet', 'eth', SEPOLIA_HEX.toUpperCase().replace('0X', '0x')],
    ['testnet', 'arb', '421614'], ['testnet', 'base', '0x14a34'],
    ['testnet', 'sol', GENESIS.sol.devnet], ['testnet', 'btc', GENESIS.btc.testnet4],
    ['local', 'eth', '31337'], ['local', 'eth', ANVIL_HEX], ['local', 'sol', LOCAL_SOL], ['local', 'btc', GENESIS.btc.regtest],
  ]
  for (const [profile, chain, id] of ok) {
    assert.equal(assertSendAllowed(profile, { chain, id }).profile, profile)
    if (chain === 'eth' || chain === 'sol' || chain === 'btc') assert.equal(assertJobSendAllowed(profile, { chain, id }).scope, 'job')
  }
})

test('config.identity-mismatch: a foreign, malformed or out-of-scope observed identity is refused', () => {
  const bad: Array<[Profile, unknown]> = [
    ['testnet', { chain: 'eth', id: '137' }], // another mainnet-class chain this tool does not know
    ['testnet', { chain: 'eth', id: '31337' }], // a local id on the testnet profile
    ['testnet', { chain: 'eth', id: ' 11155111' }], // strict: no padding
    ['testnet', { chain: 'eth', id: '011155111' }], // strict: no leading zeros
    ['testnet', { chain: 'eth', id: '0x00aa36a7' }],
    ['testnet', { chain: 'eth', id: '11155111.0' }],
    ['testnet', { chain: 'eth', id: '' }],
    ['testnet', { chain: 'sol', id: GENESIS.sol.testnet }], // Solana's testnet cluster is not this tool's testnet
    ['testnet', { chain: 'sol', id: LOCAL_SOL }],
    ['testnet', { chain: 'btc', id: GENESIS.btc.regtest }],
    ['testnet', { chain: 'btc', id: GENESIS.btc.testnet4.toUpperCase() }], // strict: as Esplora answers
    ['local', { chain: 'eth', id: '11155111' }],
    ['local', { chain: 'sol', id: GENESIS.sol.devnet }],
    ['local', { chain: 'sol', id: 'not base58 0OIl' }],
    ['local', { chain: 'arb', id: '421614' }], // no Arbitrum locally
    ['testnet', null],
    ['testnet', 'eth:11155111'],
    ['testnet', { chain: 'eth' }],
    ['testnet', { chain: 'eth', id: 11155111 }],
    ['testnet', { chain: 'arweave', id: 'x' }],
    ['testnet', { chain: 'ETH', id: '11155111' }],
    ['testnet', { id: '11155111' }],
  ]
  for (const [name, f] of both) {
    for (const [profile, o] of bad) refused(() => f(profile, o as never), 'config.identity-mismatch', `${name} ${profile} ${JSON.stringify(o)}`)
  }
  // Each observed property is read once: a getter cannot show a check one value and the permit another.
  const reads = { chain: 0, id: 0 }
  const sly = { get chain() { reads.chain++; return 'eth' }, get id() { return reads.id++ === 0 ? '11155111' : '1' } }
  assert.equal(assertSendAllowed('testnet', sly as never).profile, 'testnet')
  assert.deepEqual(reads, { chain: 1, id: 1 })
  // The job scope covers eth, sol and btc only.
  assert.equal(assertSendAllowed('testnet', { chain: 'arb', id: '421614' }).scope, 'all')
  assert.equal(assertSendAllowed('testnet', { chain: 'base', id: '84532' }).scope, 'all')
  refused(() => assertJobSendAllowed('testnet', { chain: 'arb', id: '421614' } as never), 'config.identity-mismatch')
  refused(() => assertJobSendAllowed('testnet', { chain: 'base', id: '84532' } as never), 'config.identity-mismatch')
})

// ---- permits cannot be forged

test('isSendPermit: only an object a lock issued; copies, spreads, prototypes and look-alikes are not permits', () => {
  const real = assertSendAllowed('testnet')
  const fakes: unknown[] = [
    { profile: 'testnet', scope: 'all' }, Object.freeze({ profile: 'testnet', scope: 'all' }), { ...real },
    Object.create(real), structuredClone(real), { __permit: Symbol('permit'), profile: 'mainnet', scope: 'all' },
    JSON.parse(JSON.stringify(real)), null, undefined, true, 'permit', 1, [real],
  ]
  for (const f of fakes) assert.equal(isSendPermit(f), false)
  assert.equal(isSendPermit(real), true)
  assert.throws(() => { (real as { profile: string }).profile = 'mainnet' }, TypeError)
  const typed: SendPermit = real
  assert.equal(typed.profile, 'testnet')
})

// ---- identities (R71)

test('R71: the testnet identities and the Amsterdam facts, verbatim', () => {
  assert.equal(NETWORK_IDS.testnet.eth, 11155111)
  assert.equal(GENESIS.sol.devnet, 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG')
  assert.equal(ETH_AMSTERDAM_TIME.testnet, 1791294816)
  assert.equal(new Date(1791294816 * 1000).toISOString(), '2026-10-06T13:53:36.000Z')
  assert.equal(ETH_AMSTERDAM_TIME.mainnet, null, 'mainnet has no Amsterdam time yet')
  assert.equal(ETH_AMSTERDAM_TIME.local, null)
  assert.deepEqual(Object.keys(ETH_AMSTERDAM_TIME).sort(), ['local', 'mainnet', 'testnet'])
})

test('expectedIdentity: one map for every profile and chain', () => {
  assert.equal(expectedIdentity('testnet', 'eth'), 11155111)
  assert.equal(expectedIdentity('testnet', 'sol'), GENESIS.sol.devnet)
  assert.deepEqual(CHAINS.map((c) => expectedIdentity('mainnet', c)), [1, 42161, 8453, GENESIS.sol.mainnet, GENESIS.btc.mainnet])
  assert.deepEqual(CHAINS.map((c) => expectedIdentity('testnet', c)), [11155111, 421614, 84532, GENESIS.sol.devnet, GENESIS.btc.testnet4])
  assert.equal(expectedIdentity('local', 'eth'), 31337)
  assert.equal(expectedIdentity('local', 'btc'), GENESIS.btc.regtest)
  refused(() => expectedIdentity('local', 'arb'), 'config.local-scope')
  refused(() => expectedIdentity('local', 'base'), 'config.local-scope')
  refused(() => expectedIdentity('local', 'sol'), 'config.identity-unknown', 'local Solana has a random genesis')
  for (const c of ['arweave', 'doge', '', 'ETH', '__proto__', 'hasOwnProperty', 'constructor']) {
    refused(() => expectedIdentity('testnet', c as IdChain), 'config.identity-unknown', c)
  }
  refused(() => expectedIdentity('Testnet' as Profile, 'eth'), 'config.profile-invalid')
})

test('the identity map agrees with isFaucetNetwork, isMainnetIdentity and identityMatches', () => {
  for (const c of CHAINS) {
    const main = expectedIdentity('mainnet', c)
    const test_ = expectedIdentity('testnet', c)
    assert.equal(isFaucetNetwork(test_), true, `testnet ${c} is a faucet network`)
    assert.equal(isFaucetNetwork(main), false, `mainnet ${c} is not`)
    assert.equal(isMainnetIdentity(c, String(main)), true)
    assert.equal(isMainnetIdentity(c, String(test_)), false)
    assert.equal(identityMatches('mainnet', c, String(main)), true)
    assert.equal(identityMatches('testnet', c, String(test_)), true)
    assert.equal(identityMatches('testnet', c, String(main)), false)
    assert.equal(identityMatches('mainnet', c, String(test_)), false)
  }
})

test('isMainnetIdentity: lenient on the refuse side; unknown chains and non-strings are false', () => {
  const yes: Array<[IdChain, string]> = [
    ['eth', '1'], ['eth', '0x1'], ['eth', '0X01'], ['eth', '\t1\n'], ['arb', '42161'], ['base', '0x2105'], ['eth', '8453'],
    ['sol', GENESIS.sol.mainnet], ['sol', ` ${GENESIS.sol.mainnet} `], ['btc', GENESIS.btc.mainnet.toUpperCase()],
  ]
  for (const [c, id] of yes) assert.equal(isMainnetIdentity(c, id), true, `${c} ${JSON.stringify(id)}`)
  const no: Array<[string, unknown]> = [
    ['eth', '11155111'], ['eth', SEPOLIA_HEX], ['eth', '31337'], ['eth', '137'], ['eth', '1.0'], ['eth', '+1'], ['eth', '-1'],
    ['eth', ''], ['eth', '0x'], ['eth', 1], ['sol', GENESIS.sol.devnet], ['sol', GENESIS.sol.mainnet.toLowerCase()],
    ['btc', GENESIS.btc.testnet4], ['btc', GENESIS.btc.regtest], ['arweave', '1'], ['ETH', '1'], ['sol', '1'], ['btc', '1'],
  ]
  for (const [c, id] of no) assert.equal(isMainnetIdentity(c as IdChain, id as string), false, `${c} ${JSON.stringify(id)}`)
})

test('identityMatches: strict; local Solana is any well-formed non-public genesis', () => {
  assert.equal(identityMatches('local', 'sol', LOCAL_SOL), true)
  assert.equal(identityMatches('local', 'sol', '11111111111111111111111111111111'), true)
  for (const g of [GENESIS.sol.mainnet, GENESIS.sol.devnet, GENESIS.sol.testnet, '', 'abc', `${LOCAL_SOL}zzz`]) {
    assert.equal(identityMatches('local', 'sol', g), false, g)
  }
  assert.equal(identityMatches('testnet', 'eth', SEPOLIA_HEX), true)
  assert.equal(identityMatches('local', 'eth', ANVIL_HEX), true)
  assert.equal(identityMatches('local', 'arb', '421614'), false)
  assert.equal(identityMatches('testnet', 'btc', GENESIS.btc.testnet4.toUpperCase()), false)
  assert.equal(identityMatches('Testnet' as Profile, 'eth', '11155111'), false)
  assert.equal(identityMatches('testnet', 'doge' as IdChain, '11155111'), false)
  assert.equal(identityMatches('testnet', 'eth', 11155111 as unknown as string), false)
})

// ---- config.mainnet-host

// A temp copy of the two json files, mutated by `edit`.
function withJson(edit: (e: any) => void, run: (dir: string) => void): void {
  const d = mkdtempSync(join(tmpdir(), 'vt-sendlock-'))
  try {
    cpSync(join(ROOT, 'endpoints.json'), join(d, 'endpoints.json'))
    cpSync(join(ROOT, 'anchors.json'), join(d, 'anchors.json'))
    const e = JSON.parse(readFileSync(join(d, 'endpoints.json'), 'utf8'))
    edit(e)
    writeFileSync(join(d, 'endpoints.json'), JSON.stringify(e))
    run(d)
  } finally {
    rmSync(d, { recursive: true, force: true })
  }
}

test('config.mainnet-host: a testnet turbo.* or arweave.gateway override on a mainnet host is refused', () => {
  const bad: Array<[string, string]> = [
    ['turbo.upload', 'https://upload.ardrive.io'], ['turbo.payment', 'https://payment.ardrive.io'],
    ['turbo.upload', 'https://UPLOAD.ARDRIVE.IO/'], ['turbo.upload', 'https://ardrive.io'],
    ['arweave.gateway', 'https://arweave.net'], ['arweave.gateway', 'https://arweave.net/'],
    ['arweave.gateway', 'https://ARWEAVE.NET'], ['arweave.gateway', 'https://g8way.arweave.net'],
    ['arweave.gateway', 'https://turbo-gateway.com'], ['turbo.payment', 'https://a.b.turbo-gateway.com'],
  ]
  for (const [key, url] of bad) refused(() => loadConfig('testnet', {}, { [key]: url }), 'config.mainnet-host', `${key} ${url}`)
  // The same through the environment.
  refused(() => loadConfig('testnet', {}, parseOverrides([], { VT_ENDPOINT_TURBO_UPLOAD: 'https://upload.ardrive.io' })), 'config.mainnet-host')
  refused(() => loadConfig('testnet', {}, parseOverrides(['--endpoint', 'arweave.gateway=https://arweave.net'], {})), 'config.mainnet-host')
  // Local refuses Turbo/Arweave endpoints altogether (R35), before the host check.
  refused(() => loadConfig('local', {}, { 'arweave.gateway': 'https://arweave.net' }), 'config.local-scope')
})

test('config.mainnet-host: mainnet keeps its hosts; the testnet profile\'s own hosts and loopback pass', () => {
  const m = loadConfig('mainnet', {}, { 'turbo.upload': 'https://upload.ardrive.io', 'arweave.gateway': 'https://arweave.net' })
  assert.deepEqual(m.endpoints['turbo.upload'].map((e) => e.url), ['https://upload.ardrive.io'])
  const t = loadConfig('testnet', {})
  assert.deepEqual(t.endpoints['arweave.gateway'].map((e) => e.url), ['https://ar-io.dev'])
  const ok: Array<[string, string]> = [
    ['arweave.gateway', 'http://127.0.0.1:1984'], ['turbo.upload', 'https://upload.services.ar-io.dev'],
    ['turbo.payment', 'https://payment.services.ar-io.dev/v1'], ['arweave.gateway', 'https://AR-IO.DEV/'],
    // other keys are not Turbo/Arweave: the rule does not apply to them
    ['eth.rpc', 'https://ethereum-sepolia-rpc.publicnode.com'],
  ]
  for (const [key, url] of ok) assert.equal(loadConfig('testnet', {}, { [key]: url }).endpoints[key][0].url, url)
})

// C2 m3: the check is an ALLOWLIST outside mainnet (loopback or the profile's own endpoints.json hosts), not only a
// denylist of known mainnet names: any other gateway or bundler, known to the denylist or not, is refused.
test('config.mainnet-host (m3): a testnet Turbo/Arweave override on any host that is not its own or loopback is refused', () => {
  const bad: Array<[string, string]> = [
    ['arweave.gateway', 'https://ar-io.net'], ['arweave.gateway', 'https://permagate.io'], ['arweave.gateway', 'https://g8way.io'],
    ['turbo.upload', 'https://uploader.irys.xyz'], ['turbo.payment', 'https://payment.example'],
    // look-alikes and sub-hosts of an own host are not the own host
    ['arweave.gateway', 'https://notarweave.net'], ['turbo.upload', 'https://ardrive.io.example'],
    ['arweave.gateway', 'https://x.ar-io.dev'], ['turbo.upload', 'https://services.ar-io.dev'],
    // an own host of ANOTHER profile's section is not this profile's own
    ['turbo.upload', 'https://upload.ardrive.io'],
    // a port or a path naming an own host does not turn a foreign host into an own one
    ['arweave.gateway', 'https://permagate.io:443/ar-io.dev'], ['turbo.upload', 'https://uploader.irys.xyz:8443'],
  ]
  for (const [key, url] of bad) refused(() => loadConfig('testnet', {}, { [key]: url }), 'config.mainnet-host', `${key} ${url}`)
  // The environment route is the same function.
  refused(() => loadConfig('testnet', {}, parseOverrides([], { VT_ENDPOINT_ARWEAVE_GATEWAY: 'https://g8way.io' })), 'config.mainnet-host')
  // The allowlist is the profile's OWN section: a host added to testnet's section is accepted as an override.
  withJson((e) => { e.testnet['arweave.gateway'].push('https://second-testnet-gateway.example') }, (d) => {
    assert.equal(loadConfig('testnet', {}, { 'arweave.gateway': 'https://second-testnet-gateway.example' }, d).profile, 'testnet')
  })
})

test('config.mainnet-host: endpoints.json itself is checked, and its mainnet section adds hosts', () => {
  withJson((e) => { e.testnet['arweave.gateway'] = ['https://arweave.net'] }, (d) => {
    refused(() => loadConfig('testnet', {}, {}, d), 'config.mainnet-host')
    assert.equal(loadConfig('mainnet', {}, {}, d).profile, 'mainnet')
  })
  withJson((e) => { e.testnet['turbo.payment'] = ['https://payment.ardrive.io'] }, (d) => {
    refused(() => loadConfig('testnet', {}, {}, d), 'config.mainnet-host')
  })
  withJson((e) => { e.mainnet['arweave.gateway'].push('https://new-gateway.example') }, (d) => {
    refused(() => loadConfig('testnet', {}, { 'arweave.gateway': 'https://new-gateway.example' }, d), 'config.mainnet-host')
    refused(() => loadConfig('testnet', {}, { 'arweave.gateway': 'https://a.new-gateway.example' }, d), 'config.mainnet-host')
    // not on the mainnet list, but not testnet's own either (m3): refused
    refused(() => loadConfig('testnet', {}, { 'arweave.gateway': 'https://other-gateway.example' }, d), 'config.mainnet-host')
  })
})

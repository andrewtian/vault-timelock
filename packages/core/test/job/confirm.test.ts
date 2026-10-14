// checkArmConfirm (spec §5.4 checks 6-7 plus the request rules): the API re-checks what the page and the CLI collected.
// Mapped by test/mutation/guards.json: arm.typed, arm.amount, arm.chains, arm.countdown, arm.stagger. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkArmConfirm, checkClawbackConfirm } from '../../src/job/index.ts'
import type { ArmCap, ArmRequest, Chain, JobState, Network } from '../../src/contracts/index.ts'
import { guardOf, readJson } from './helpers.ts'

const CAP: ArmCap = { nativeCap: '4000000000000000', usd: 10, priceAt: 1_791_504_009_000, overCap: false, planned: '0.004' }
const OVER: ArmCap = { ...CAP, overCap: true, usd: 14.2, planned: '0.0057' }
const req = (o: Partial<ArmRequest> = {}): ArmRequest => ({ chains: ['eth'], confirm: { typed: null, amounts: {} }, caps: { eth: CAP }, ...o })
const typed = { typed: 'broadcast', amounts: {} }
const c = (n: Network, r: ArmRequest): string | null => guardOf(() => checkArmConfirm(n, r))

test('mainnet needs typed "broadcast" exactly; local and testnet do not', () => {
  assert.equal(c('mainnet', req()), 'arm.typed')
  for (const t of ['Broadcast', 'broadcast ', ' broadcast', 'BROADCAST', '']) assert.equal(c('mainnet', req({ confirm: { typed: t, amounts: {} } })), 'arm.typed', t)
  assert.equal(c('mainnet', req({ confirm: typed })), null)
  assert.equal(c('local', req()), null)
  assert.equal(c('testnet', req()), null)
})

test('an over-cap chain needs its planned amount typed exactly; every armed chain needs a cap', () => {
  assert.equal(c('local', req({ caps: { eth: OVER }, confirm: { typed: null, amounts: { eth: '0.006' } } })), 'arm.amount')
  assert.equal(c('local', req({ caps: { eth: OVER } })), 'arm.amount', 'amount missing')
  assert.equal(c('local', req({ caps: { eth: OVER }, confirm: { typed: null, amounts: { eth: '0.00570' } } })), 'arm.amount', 'string match, not numeric')
  assert.equal(c('local', req({ caps: { eth: OVER }, confirm: { typed: null, amounts: { sol: '0.0057' } } })), 'arm.amount', 'another chain\'s amount')
  assert.equal(c('local', req({ caps: { eth: OVER }, confirm: { typed: null, amounts: { eth: '0.0057' } } })), null)
  assert.equal(c('mainnet', req({ caps: { eth: OVER }, confirm: { typed: 'broadcast', amounts: { eth: '0.0057' } } })), null)
  assert.equal(c('local', req({ chains: ['eth', 'sol'], caps: { eth: CAP, sol: OVER }, confirm: { typed: null, amounts: {} } })), 'arm.amount')
  assert.equal(c('local', req({ chains: ['eth', 'sol'], caps: { eth: CAP } })), 'arm.amount', 'sol has no cap')
  assert.equal(c('local', req({ caps: { eth: { ...CAP, overCap: 'no' as unknown as boolean } } })), 'arm.amount', 'a malformed cap')
  assert.equal(c('local', req({ caps: { eth: { ...CAP, nativeCap: '1.5' } } })), 'arm.amount', 'a malformed cap')
})

test('chains: a non-empty list of distinct known chains', () => {
  assert.equal(c('local', req({ chains: [] })), 'arm.chains')
  assert.equal(c('local', req({ chains: ['eth', 'eth'] })), 'arm.chains')
  assert.equal(c('local', req({ chains: ['btc' as 'eth'] })), 'arm.amount', 'btc on local is a chain now (its cap is missing here)')
  assert.equal(c('local', req({ chains: 'eth' as unknown as ArmRequest['chains'] })), 'arm.chains')
  assert.equal(c('local', req({ chains: ['eth', 'sol'], caps: { eth: CAP, sol: CAP } })), null)
})

test('countdownSec: mainnet is fixed at 60; local and testnet take an integer 5..300', () => {
  assert.equal(c('mainnet', req({ confirm: typed, countdownSec: 60 })), null)
  for (const s of [30, 59, 61, 300]) assert.equal(c('mainnet', req({ confirm: typed, countdownSec: s })), 'arm.countdown', String(s))
  for (const s of [5, 15, 300]) for (const n of ['local', 'testnet'] as Network[]) assert.equal(c(n, req({ countdownSec: s })), null, `${n} ${s}`)
  for (const s of [4, 301, 7.5, 0, -5, Number.NaN]) assert.equal(c('local', req({ countdownSec: s })), 'arm.countdown', String(s))
  assert.equal(c('testnet', req({ countdownSec: 4 })), 'arm.countdown')
  assert.equal(c('local', req({ countdownSec: '15' as unknown as number })), 'arm.countdown')
})

test('stagger: local only, [min, max] integers with 0 ≤ min ≤ max ≤ 300', () => {
  assert.equal(c('mainnet', req({ confirm: typed, stagger: [30, 300] })), 'arm.stagger')
  assert.equal(c('testnet', req({ stagger: [30, 300] })), 'arm.stagger')
  for (const s of [[5, 10], [0, 0], [30, 300], [7, 7]] as Array<[number, number]>) assert.equal(c('local', req({ stagger: s })), null, s.join(','))
  for (const s of [[10, 5], [-1, 5], [5, 301], [1.5, 3], [5], [5, 10, 15], 'x'] as unknown as Array<[number, number]>) {
    assert.equal(c('local', req({ stagger: s })), 'arm.stagger', JSON.stringify(s))
  }
})

test('the contract vectors', () => {
  const v = readJson<{ cases: Array<{ name: string; network: Network; request: ArmRequest; guard: string | null }> }>('arm/confirm.json')
  for (const k of v.cases) assert.equal(c(k.network, k.request), k.guard, k.name)
})

// CC-2a: the typed claw-back amount (types.ts claw-back note). arm.amount shares its one marker with checkArmConfirm.
test('checkClawbackConfirm: the contract vectors (need = value + worst-case fee; a typed amount must equal it exactly)', () => {
  const v = readJson<{ cases: Array<{ name: string; chain: Chain; state: JobState; data: Record<string, unknown>; confirm?: unknown; guard: string | null }> }>('arm/clawback-confirm.json')
  assert.ok(v.cases.length >= 10)
  for (const k of v.cases) assert.equal(guardOf(() => checkClawbackConfirm(k.state, k.chain, k.data, ...(Object.hasOwn(k, 'confirm') ? [k.confirm] : []))), k.guard, k.name)
  const ok = v.cases.find((k) => k.guard === null && k.chain === 'eth')!
  assert.equal(checkClawbackConfirm(ok.state, 'eth', ok.data), BigInt(ok.data.value as string) + 21_000n * 10n, 'returns need')
})

test('E7 round 3: btc arms on a LOCAL network only, with its cap in sats and its over-cap amount typed', () => {
  const BTC: ArmCap = { nativeCap: '1000000', usd: 0, priceAt: null, overCap: false, planned: '0.00003472' }
  assert.equal(c('local', req({ chains: ['btc'], caps: { btc: BTC } })), null)
  assert.equal(c('local', req({ chains: ['eth', 'btc'], caps: { eth: CAP, btc: BTC } })), null)
  assert.equal(c('testnet', req({ chains: ['btc'], caps: { btc: BTC } })), 'arm.chains')
  assert.equal(c('mainnet', req({ chains: ['btc'], caps: { btc: BTC }, confirm: typed })), 'arm.chains')
  assert.equal(c('local', req({ chains: ['btc'], caps: { btc: { ...BTC, overCap: true } } })), 'arm.amount')
  assert.equal(c('local', req({ chains: ['btc'], caps: { btc: { ...BTC, overCap: true } }, confirm: { typed: null, amounts: { btc: BTC.planned } } })), null)
})

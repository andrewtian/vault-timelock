// preflight(relay, network) — `vt preflight` (C7) and the page's readiness table (W4): identity, Memo v2 executable,
// fees now, a synthetic copy's dry-run cost, Tor, confinement; exit 0 only when identity and deployment pass; no IP ever.
// ALL DATA IS SYNTHETIC; a fake relay (nothing listens).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { preflight } from '../../src/executor/preflight.ts'
import { localTorView } from '../../src/executor/readiness.ts'
import { SOL } from '../../src/chains/constants.js'
import { fakeRelayClient } from '../fakes/fake-relay.ts'
import { fakeEthChain, fakeSolChain } from '../engine/fakes.ts'

const CANARY = '203.0.113.77'
// eth_estimateGas the way each network's fork prices a 100-byte send to another address (testnet: Amsterdam, 15000 + 64n)
const forkGas = (network: string, n: number, toSelf: boolean) => (network === 'testnet' ? (toSelf ? 12000 : 15000) + 64 * n : 21000 + 40 * n)
const relayFor = (o: Parameters<typeof fakeRelayClient>[0] & { memo?: boolean; solFee?: number; estimate?: (p: { from?: string; to?: string; data: string }) => number }) => {
  const e = fakeEthChain(), sc = fakeSolChain()
  const net = o.network ?? 'local'
  const ethH = (m: string, p: unknown[]) => {
    if (m !== 'eth_estimateGas') return e.handler(m, p)
    const tx = p[0] as { from?: string; to?: string; data: string }
    return '0x' + (o.estimate ? o.estimate(tx) : forkGas(net, (tx.data.length - 2) / 2, tx.from === tx.to)).toString(16)
  }
  return fakeRelayClient({ eth: ethH, sol: (m, p) => (m === 'getAccountInfo' && p[0] === SOL.MEMO_PROGRAM ? { context: { slot: 1 }, value: { executable: o.memo ?? true, owner: 'BPFLoaderUpgradeab1e11111111111111111111111' } }
    : m === 'getFeeForMessage' && o.solFee !== undefined ? { context: { slot: 1 }, value: o.solFee } : sc.handler(m, p)), ...o })
}

test('identity ok, Memo v2 executable, fees present → exit 0, with the dry-run cost of a synthetic copy on each chain', async () => {
  for (const network of ['local', 'testnet', 'mainnet'] as const) {
    const r = await preflight(relayFor({ network, endpoints: { eth: 2, sol: 2 } }).client, network, { now: () => 42 })
    assert.equal(r.exit, 0, network); assert.equal(r.format, 'vt-preflight/1'); assert.equal(r.network, network); assert.equal(r.at, 42)
    assert.deepEqual([r.idOk, r.deployOk], [true, true])
    assert.equal(r.chains.sol!.memoV2, true); assert.equal(r.chains.sol!.copyCost, '5000')
    assert.match(r.chains.eth!.copyCost!, /^[1-9][0-9]*$/); assert.ok(r.chains.eth!.fees!.maxFee)
    assert.equal(r.rows.find((x) => x.id === 'tor')!.ok, network === 'local' ? null : true)
  }
})

test('an identity the relay did not verify → idOk false (exit 1); a relay on another network too; Memo v2 not executable → deployOk false', async () => {
  const bad = await preflight(relayFor({ network: 'testnet', identity: { eth: { ok: false, message: 'eth identity MISMATCH: the chain id is not testnet\'s' }, sol: { ok: true } } }).client, 'testnet')
  assert.deepEqual([bad.idOk, bad.exit], [false, 1]); assert.equal(bad.rows.find((x) => x.id === 'eth.identity')!.ok, false)
  const other = await preflight(relayFor({ network: 'mainnet' }).client, 'testnet')
  assert.deepEqual([other.idOk, other.exit, other.rows.find((x) => x.id === 'network')!.ok], [false, 1, false])
  const memo = await preflight(relayFor({ network: 'local', memo: false }).client, 'local')
  assert.deepEqual([memo.idOk, memo.deployOk, memo.exit], [true, false, 1])
  const noTor = await preflight(relayFor({ network: 'mainnet', isTor: false }).client, 'mainnet')
  assert.deepEqual([noTor.deployOk, noTor.exit], [false, 1])
  const unconfined = await preflight(relayFor({ network: 'local', confined: false }).client, 'local')
  assert.equal(unconfined.exit, 1)
})

test('PF-S M-2: on mainnet fewer than 2 verified endpoints for a job chain is a failing row (exit 1) with the reason; local and testnet need 1', async () => {
  for (const endpoints of [{ eth: 1, sol: 2 }, { eth: 2, sol: 1 }, { eth: 1, sol: 1 }, { eth: 0, sol: 2 }]) {
    const r = await preflight(relayFor({ network: 'mainnet', endpoints }).client, 'mainnet')
    assert.deepEqual([r.idOk, r.deployOk, r.exit], [true, false, 1], JSON.stringify(endpoints))
    for (const c of ['eth', 'sol'] as const) {
      const row = r.rows.find((x) => x.id === `${c}.endpoints`)!
      assert.equal(row.ok, endpoints[c] >= 2, `${c} ${endpoints[c]}`)
      if (endpoints[c] < 2) assert.match(row.detail, /^\d endpoint\(s\): mainnet needs 2 \(one endpoint's word is never enough\); the relay re-checks a dropped one every 30 s$/)
      else assert.equal(row.detail, `${endpoints[c]} endpoint(s)`)
      assert.equal(r.chains[c]!.endpoints, endpoints[c])
    }
  }
  const two = await preflight(relayFor({ network: 'mainnet', endpoints: { eth: 2, sol: 3 } }).client, 'mainnet')
  assert.equal(two.exit, 0)
  for (const network of ['local', 'testnet'] as const) {
    const one = await preflight(relayFor({ network, endpoints: { eth: 1, sol: 1 } }).client, network)
    assert.deepEqual([one.exit, one.rows.find((x) => x.id === 'eth.endpoints')!.ok, one.rows.find((x) => x.id === 'sol.endpoints')!.ok], [0, true, true], network)
    const none = await preflight(relayFor({ network, endpoints: { eth: 0, sol: 1 } }).client, network)
    assert.equal(none.exit, 1, `${network}: no endpoint still fails`)
  }
})

test('no relay → a failing row with guard relay-unreachable, exit 1 (fail closed)', async () => {
  const r = await preflight(relayFor({ network: 'local', down: () => true }).client, 'local')
  assert.deepEqual([r.exit, r.idOk, r.deployOk], [1, false, false])
  assert.deepEqual(r.rows.map((x) => [x.id, x.ok, x.guard ?? null]), [['relay', false, 'relay-unreachable']])
})

test('the report never carries an IP: the canary in a relay message or an error is withheld', async () => {
  const leaky = relayFor({ network: 'testnet', identity: { eth: { ok: false, message: `eth identity MISMATCH at ${CANARY}:8545` }, sol: { ok: true } } })
  const r1 = await preflight(leaky.client, 'testnet')
  const down = relayFor({ network: 'local' })
  ;(down.client as unknown as { status: () => Promise<never> }).status = async () => { throw new Error(`connect ECONNREFUSED ${CANARY}:5181`) }
  const r2 = await preflight(down.client, 'local')
  for (const r of [r1, r2]) assert.ok(!JSON.stringify(r).includes(CANARY), 'no IP in the report')
  assert.match(r1.rows.find((x) => x.id === 'eth.identity')!.detail, /withheld/)
})

test('E3 review m-5: an ETH read that fails fails the preflight (exit 1), and the SOL fee row is a chain read (getFeeForMessage) checked against the formula', async () => {
  const e = fakeEthChain()
  const ethDown = relayFor({ network: 'local', eth: (m, p) => { if (m === 'eth_feeHistory') throw new Error('upstream error (test)'); return e.handler(m, p) } })
  const r = await preflight(ethDown.client, 'local')
  assert.deepEqual([r.idOk, r.deployOk, r.exit], [true, false, 1])
  assert.equal(r.rows.find((x) => x.id === 'eth.fees')!.ok, false)
  const ok = relayFor({ network: 'local' })
  const good = await preflight(ok.client, 'local')
  assert.equal(good.exit, 0)
  assert.ok(ok.calls.some((c) => c.chain === 'sol' && c.method === 'getFeeForMessage'), 'the SOL fee was read from the cluster')
  const odd = await preflight(relayFor({ network: 'local', solFee: 4_999 }).client, 'local')
  assert.deepEqual([odd.deployOk, odd.exit, odd.rows.find((x) => x.id === 'sol.fees')!.ok], [false, 1, false], 'a fee that is not the formula\'s fails closed')
})

test('C7 (fork-drift): the fork probe is an estimate between two DIFFERENT addresses, to the null address, and it names a drift', async () => {
  const seen: Array<{ from?: string; to?: string; data: string }> = []
  const ok = relayFor({ network: 'testnet', estimate: (tx) => { seen.push(tx); return forkGas('testnet', 100, false) } })
  const r = await preflight(ok.client, 'testnet')
  assert.equal(r.exit, 0)
  assert.equal(seen.length, 1)
  assert.notEqual(seen[0].from, seen[0].to, 'a self-send under-estimates on Amsterdam')
  assert.equal(seen[0].to, '0x0000000000000000000000000000000000000000')
  assert.notEqual(seen[0].from, '0x0000000000000000000000000000000000000000')
  assert.equal((seen[0].data.length - 2) / 2, 100)
  assert.equal(r.rows.find((x) => x.id === 'eth.fork')!.ok, true)
  // a self-send estimate (12000 + 64n) would look like a PRE-Amsterdam chain's... it must not be what the probe reads:
  assert.notEqual(forkGas('testnet', 100, true), forkGas('testnet', 100, false))
  // mainnet reading Amsterdam gas -> drift, named; testnet reading pre-Amsterdam gas -> drift; local accepts either fork
  const drift = await preflight(relayFor({ network: 'mainnet', estimate: () => 15000 + 64 * 100 }).client, 'mainnet')
  assert.deepEqual([drift.deployOk, drift.exit], [false, 1])
  assert.match(drift.rows.find((x) => x.id === 'eth.fork')!.detail, /Amsterdam appears active on mainnet — update required/)
  const stale = await preflight(relayFor({ network: 'testnet', estimate: () => 21000 + 40 * 100 }).client, 'testnet')
  assert.equal(stale.rows.find((x) => x.id === 'eth.fork')!.ok, false)
  assert.equal((await preflight(relayFor({ network: 'local', estimate: () => 15000 + 64 * 100 }).client, 'local')).exit, 0)
  assert.equal((await preflight(relayFor({ network: 'local', estimate: () => 21000 + 40 * 100 }).client, 'local')).exit, 0)
  const odd = await preflight(relayFor({ network: 'local', estimate: () => 12345 }).client, 'local')
  assert.deepEqual([odd.exit, odd.rows.find((x) => x.id === 'eth.fork')!.ok], [1, false])
  const none = await preflight(relayFor({ network: 'local', estimate: () => { throw new Error('upstream error (test)') } }).client, 'local')
  assert.deepEqual([none.exit, none.rows.filter((x) => x.id === 'eth.fork').map((x) => x.ok).join()], [1, 'false'], 'an unreadable probe fails closed')
})

// M4a glue (S6 F1): the local Tor row reads /relay/tor's roles and the last drand IsTor check, and never says the local stack has no Tor
// while the relay uses it for drand. Informational (ok true only for IsTor ✓, else null): a Tor that is down never fails local.
test('local Tor row: drand via Tor from /relay/tor torRoles and isTor; chains direct loopback; never fails the run', async () => {
  const row = async (o: { isTor?: boolean | null; torRoles?: readonly string[] }) => {
    const r = await preflight(relayFor({ network: 'local', ...o }).client, 'local')
    assert.equal(r.exit, 0, JSON.stringify(o))                                    // Tor never fails local
    return r.rows.find((x) => x.id === 'tor')!
  }
  const roles = ['check', 'drand']
  let t = await row({ isTor: null, torRoles: roles })
  assert.deepEqual([t.ok, t.detail], [null, 'drand via Tor (IsTor not checked yet: on first use); chains direct loopback'])
  t = await row({ isTor: true, torRoles: roles })
  assert.deepEqual([t.ok, t.detail], [true, 'drand via Tor (IsTor ✓); chains direct loopback'])
  t = await row({ isTor: false, torRoles: roles })
  assert.deepEqual([t.ok, t.detail], [null, 'drand via Tor: unavailable (IsTor ✗); chains direct loopback'])
  t = await row({ isTor: null, torRoles: [] })                                    // a relay that serves no drand
  assert.deepEqual([t.ok, t.detail], [null, 'n/a — the local chains are direct loopback and this relay does not use Tor'])
  t = await row({})                                                               // an older relay: no torRoles
  assert.equal(t.ok, null); assert.match(t.detail, /does not use Tor/)
  for (const x of [await row({ isTor: true, torRoles: roles }), await row({ isTor: null, torRoles: roles })]) assert.doesNotMatch(x.detail, /no Tor|the local network is loopback/)
})

test('local Tor row: a relay whose /relay/tor fails is not a failure on local, and the row does not claim "no Tor" from it', async () => {
  const r = relayFor({ network: 'local' })
  const client = { ...r.client, tor: async () => { throw new Error('tor read failed (test)') } }
  const rep = await preflight(client, 'local')
  assert.equal(rep.exit, 0)
  assert.equal(rep.rows.find((x) => x.id === 'tor')!.ok, null)
})

test('localTorView: drand via Tor only when torRoles names drand', () => {
  assert.deepEqual(localTorView({ isTor: true, torRoles: ['check', 'drand'] }), { drandViaTor: true, ok: true, detail: 'drand via Tor (IsTor ✓); chains direct loopback' })
  assert.equal(localTorView({ isTor: true, torRoles: ['check'] }).drandViaTor, false)
  assert.equal(localTorView({ isTor: true, torRoles: 'drand' }).drandViaTor, false)     // a string is not a role list
  assert.equal(localTorView(null).drandViaTor, false)
  assert.equal(localTorView({ isTor: 'yes', torRoles: ['drand'] }).ok, null)           // only the boolean true is ✓
})

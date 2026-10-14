// pageRows / readinessVerdict (executor/readiness.ts): the rows `vt preflight` and the page's Status table share (C7,
// F9-5). ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { DELEGATED_DETAIL, DEV_TREE_BUILD_DETAIL, EXPECTED_SERVICES, delegatedFromJobs, delegatedRows, REQUIRED_BREADTH, pageRows, readinessVerdict } from '../../src/executor/readiness.ts'

const B = 'b1c2d3e4f5a6'
const api = (network: string, build = B) => ({ network, build })
const rel = (network: string, build = B, eth: object = { ok: true }) => ({ network, build, identity: { eth, sol: { ok: true } } })
const get = (rows: ReturnType<typeof pageRows>, id: string) => rows.find((r) => r.id === id)!
// The real shape of GET /relay/release (api/relay/relay.mjs rehashRelease): ok is a COUNT, not a boolean.
const REL = { release: true, files: 10, ok: 10, mismatch: 0, missing: 0, digest: 'd'.repeat(64), hashedAt: 1_791_000_000_000 }
const SERVE = { release: true, digest: 'd'.repeat(64), build: B }

test('F9-5: on a dev tree the build-id row is informational (—), whatever the ids are; on a release it is a hard check', () => {
  // the Chrome-loop case: page 975ffe725507 against "dev" everywhere else, on a dev tree
  const dev = pageRows({ network: 'local', status: api('local', 'dev'), relay: rel('local', 'dev'), extras: { pageBuild: '975ffe725507', serve: { release: false, digest: null, build: 'dev' }, release: { release: false } } })
  assert.deepEqual(get(dev, 'build'), { id: 'build', ok: null, label: 'Build id equal across page, API and relay', detail: DEV_TREE_BUILD_DETAIL })
  assert.equal(DEV_TREE_BUILD_DETAIL, 'dev tree (needed only on mainnet/verified release)')
  // either source alone says "dev tree"
  assert.equal(get(pageRows({ network: 'local', status: api('local', 'dev'), relay: rel('local'), extras: { pageBuild: 'x'.repeat(12), serve: { release: false } } }), 'build').ok, null)
  assert.equal(get(pageRows({ network: 'local', status: api('local', 'dev'), relay: rel('local'), extras: { pageBuild: 'x'.repeat(12), release: { release: false } } }), 'build').ok, null)
  // a release: equal ids pass, different ids fail, none known fails
  const base = { network: 'mainnet' as const, status: api('mainnet'), relay: rel('mainnet'), pageNetwork: 'mainnet' as const }
  assert.equal(get(pageRows({ ...base, extras: { pageBuild: B, serve: SERVE, release: REL } }), 'build').ok, true)
  assert.equal(get(pageRows({ ...base, status: api('mainnet', 'f'.repeat(12)), extras: { pageBuild: B, serve: SERVE, release: REL } }), 'build').ok, false)
  assert.equal(get(pageRows({ ...base, relay: rel('mainnet', 'f'.repeat(12)), extras: { pageBuild: B, serve: SERVE, release: REL } }), 'build').ok, false)
  assert.equal(get(pageRows({ ...base, extras: { pageBuild: B, serve: { ...SERVE, build: 'f'.repeat(12) }, release: REL } }), 'build').ok, false)
  assert.equal(get(pageRows({ network: 'local', status: null, relay: null, extras: { release: REL } }), 'build').ok, false)
  // unreadable release facts are NOT a dev tree: the check stays hard (an unknown server build fails closed)
  const unreadable = get(pageRows({ ...base, extras: { pageBuild: B, serve: null, release: null } }), 'build')
  assert.equal(unreadable.ok, false)
  assert.match(unreadable.detail, /server unknown/)
})

test('mainnet on a dev tree: the build row is informational but the release row fails (mainnet needs a verified release)', () => {
  const r = pageRows({ network: 'mainnet', status: api('mainnet', 'dev'), relay: rel('mainnet', 'dev'), extras: { pageBuild: 'a'.repeat(12), serve: { release: false, build: 'dev' }, release: { release: false } } })
  assert.equal(get(r, 'build').ok, null)
  assert.deepEqual([get(r, 'release').ok, get(r, 'release').detail], [false, 'not a release tree: mainnet needs a verified release'])
})

test('the other rows: API, network match (names the command), fork drift message (withheld when IP-like), release digests', () => {
  assert.deepEqual(pageRows({ network: 'local', status: null, relay: null }).map((r) => [r.id, r.ok]), [['api', false], ['network-match', false], ['build', false], ['fork', null], ['release', null]])
  const mm = pageRows({ network: 'mainnet', status: api('testnet'), relay: rel('mainnet'), extras: {}, pageNetwork: 'mainnet' })
  assert.equal(get(mm, 'network-match').ok, false)
  assert.match(get(mm, 'network-match').detail, /This page is for mainnet, but the API says testnet and the relay says mainnet\. Start it with: vt up --network mainnet/)
  const drift = pageRows({ network: 'mainnet', status: api('mainnet'), relay: rel('mainnet', B, { ok: false, message: 'Amsterdam appears active on mainnet — update required' }), extras: {} })
  assert.deepEqual([get(drift, 'fork').ok, get(drift, 'fork').detail], [false, 'Amsterdam appears active on mainnet — update required'])
  const leaky = pageRows({ network: 'mainnet', status: api('mainnet'), relay: rel('mainnet', B, { ok: false, message: 'fork mismatch at 203.0.113.77:8545' }), extras: {} })
  assert.ok(!JSON.stringify(leaky).includes('203.0.113.77'))
  const other = pageRows({ network: 'mainnet', status: api('mainnet'), relay: rel('mainnet'), extras: { pageBuild: B, serve: SERVE, release: { ...REL, digest: 'e'.repeat(64) } } })
  assert.match(get(other, 'release').detail, /different releases/)
  assert.match(get(pageRows({ network: 'mainnet', status: api('mainnet'), relay: rel('mainnet'), extras: { serve: SERVE, release: REL } }), 'release').detail, /^re-hashed just now \(10 files\) · digest dddddddddddd…$/)
  assert.equal(get(pageRows({ network: 'mainnet', status: api('mainnet'), relay: rel('mainnet'), extras: { serve: SERVE, release: { ...REL, ok: 7, mismatch: 2, missing: 1 } } }), 'release').detail, 'files differ (2 changed, 1 missing)')
})

test('readinessVerdict: exit 0 only when preflight() passed and no row anywhere fails', () => {
  const ok = { exit: 0 as const, rows: [{ ok: true }, { ok: null }] }
  assert.deepEqual(readinessVerdict(ok, [{ ok: true }, { ok: null }]), { failing: 0, exit: 0 })
  assert.deepEqual(readinessVerdict(ok, [{ ok: false }]), { failing: 1, exit: 1 })
  assert.deepEqual(readinessVerdict({ exit: 1, rows: [{ ok: false }] }, []), { failing: 1, exit: 1 })
  assert.deepEqual(readinessVerdict({ exit: 1, rows: [] }, []), { failing: 0, exit: 1 })
})

// ---- Cfix1: the page BUNDLE id and the release build id are different hash domains; on a release the SERVERS are compared
test('Cfix1: on a release the build row compares server = api = relay and shows the page bundle id as information only', () => {
  const BUNDLE = '0f172b942a29', REL_ID = 'c570388ab174'
  const base = { network: 'mainnet' as const, status: api('mainnet', REL_ID), relay: rel('mainnet', REL_ID), pageNetwork: 'mainnet' as const }
  const r = get(pageRows({ ...base, extras: { pageBuild: BUNDLE, serve: { ...SERVE, build: REL_ID }, release: REL } }), 'build')
  assert.equal(r.ok, true)
  assert.equal(r.detail, `server ${REL_ID} · api ${REL_ID} · relay ${REL_ID} · page bundle ${BUNDLE} (information only)`)
  // without a bundle id (the terminal): same verdict, no bundle text
  assert.equal(get(pageRows({ ...base, extras: { serve: { ...SERVE, build: REL_ID }, release: REL } }), 'build').detail, `server ${REL_ID} · api ${REL_ID} · relay ${REL_ID}`)
  // a disagreeing server fails and names which
  const bad = get(pageRows({ ...base, relay: rel('mainnet', 'a'.repeat(12)), extras: { pageBuild: BUNDLE, serve: { ...SERVE, build: REL_ID }, release: REL } }), 'build')
  assert.equal(bad.ok, false)
  assert.match(bad.detail, /relay aaaaaaaaaaaa/)
  // a missing api / relay build fails too
  assert.equal(get(pageRows({ ...base, status: null, extras: { serve: { ...SERVE, build: REL_ID }, release: REL } }), 'build').ok, false)
  assert.equal(get(pageRows({ ...base, relay: null, extras: { serve: { ...SERVE, build: REL_ID }, release: REL } }), 'build').ok, false)
})

test('Cfix1: the mainnet release row, from the relay\'s real shape (ok is a count)', () => {
  const run = (release: unknown, serve: unknown = SERVE) => get(pageRows({ network: 'mainnet', status: api('mainnet'), relay: rel('mainnet'), extras: { serve: serve as never, release: release as never } }), 'release')
  const good = run(REL)
  assert.deepEqual([good.ok, good.detail], [true, 're-hashed just now (10 files) · digest dddddddddddd…'])
  assert.equal(run({ ...REL, files: 27387, ok: 27387 }).ok, true)
  // mismatch / missing, with counts
  assert.deepEqual([run({ ...REL, ok: 9, mismatch: 1 }).ok, run({ ...REL, ok: 9, mismatch: 1 }).detail], [false, 'files differ (1 changed, 0 missing)'])
  assert.equal(run({ ...REL, ok: 9, missing: 1 }).detail, 'files differ (0 changed, 1 missing)')
  assert.equal(run({ ...REL, ok: 8, mismatch: 1, missing: 1 }).detail, 'files differ (1 changed, 1 missing)')
  // ok != files with no mismatch / missing counted: not verified
  assert.deepEqual([run({ ...REL, ok: 9 }).ok, run({ ...REL, ok: 9 }).detail], [false, 'only 9 of 10 files re-hashed ok'])
  assert.equal(run({ ...REL, ok: 11 }).ok, false)
  // digests unequal
  assert.deepEqual([run(REL, { ...SERVE, digest: 'e'.repeat(64) }).ok, run(REL, { ...SERVE, digest: 'e'.repeat(64) }).detail], [false, 'the page and the relay come from different releases'])
  assert.equal(run(REL, { ...SERVE, digest: null }).ok, false)
  assert.equal(run(REL, null).ok, false)
  // unreadable, in every wrong shape: "could not be read"
  for (const bad of [null, undefined, {}, [], 'x', 7, { release: true }, { ...REL, ok: true }, { ...REL, ok: '10' }, { ...REL, files: 0, ok: 0 }, { ...REL, files: -1 }, { ...REL, files: 1.5 },
    { ...REL, files: '10' }, { ...REL, files: undefined }, { ...REL, mismatch: undefined }, { ...REL, missing: null }, { ...REL, mismatch: '0' }, { ...REL, release: 'true' }]) {
    const r = run(bad)
    assert.deepEqual([r.ok, r.detail], [false, 'could not be read'], JSON.stringify(bad))
  }
  // not a release tree
  assert.equal(run({ release: false }, { release: false, digest: null, build: 'dev' }).detail, 'not a release tree: mainnet needs a verified release')
})

test('Cfix1: non-mainnet release row is informational whatever the shape', () => {
  const r = (release: unknown) => get(pageRows({ network: 'testnet', status: api('testnet'), relay: rel('testnet'), extras: { serve: SERVE, release: release as never } }), 'release')
  assert.deepEqual([r(REL).ok, r(REL).detail], [null, 're-hashed just now (10 files) · digest dddddddddddd…'])
  assert.deepEqual([r({ ...REL, ok: true }).ok, r({ ...REL, ok: true }).detail], [null, 'unknown (needed only on mainnet)'])
})

// ---- Cfix2: unreadable facts are "could not be read" (with the client's reason when it gives a plain one), never a dev tree
test('Cfix2: unreadable release facts: could not be read (+ the plain reason), and never the dev-tree wording', () => {
  const D = 'd'.repeat(64)
  const mk = (release: unknown, serve: unknown = { release: true, digest: D, build: 'c570388ab174' }) => pageRows({
    network: 'mainnet', status: { network: 'mainnet', build: 'c570388ab174' }, relay: { network: 'mainnet', build: 'c570388ab174' },
    extras: { serve: serve as never, release: release as never }, pageNetwork: 'mainnet' })
  const rel = (rows: ReturnType<typeof mk>) => rows.find((r) => r.id === 'release')!
  for (const [facts, detail] of [
    [{ release: null, error: 'unreachable' }, 'could not be read (unreachable)'],
    [{ release: null, error: 'no answer within 180 s' }, 'could not be read (no answer within 180 s)'],
    [{ release: null, error: 'http 503' }, 'could not be read (http 503)'],
    [{ release: null, error: '<script>alert(1)</script>' }, 'could not be read'],
    [{ release: null, error: 7 }, 'could not be read'],
    [null, 'could not be read'], [{}, 'could not be read'],
  ] as const) {
    const r = rel(mk(facts))
    assert.deepEqual([r.ok, r.detail], [false, detail])
  }
  const rows = mk({ release: null, error: 'unreachable' })
  assert.ok(!rows.some((r) => /dev tree/.test(r.detail) && r.id === 'release'))
  assert.equal(rows.find((r) => r.id === 'build')!.ok, true, 'a release page server keeps the build row hard')
  // testnet/local: informational, "unknown", not "dev tree", when nothing positively says release:false
  const t = pageRows({ network: 'testnet', status: { network: 'testnet', build: 'dev' }, relay: null, extras: { serve: null, release: null }, pageNetwork: 'testnet' }).find((r) => r.id === 'release')!
  assert.equal(t.detail, 'unknown (needed only on mainnet)')
})

// ---- Cfix3: BTC and the relay's services. The shapes are the REAL producers' (api/relay/relay.mjs relayStatus and
// servicesStatus; api/test/readiness-breadth.test.ts feeds the real relay's answers through the same rows).
const BTC_REL = { network: 'testnet', build: B, identity: { eth: { ok: true }, sol: { ok: true }, btc: { ok: true } }, endpoints: { eth: 2, sol: 1, btc: 3 } }
const SVCS = {
  network: 'testnet',
  services: {
    'blockscout.eth': { ok: true, viaTor: true, endpoints: 1 },
    'blockscout.base': { ok: false, viaTor: true, endpoints: 0, message: 'an endpoint answered another identity: disabled until the relay restarts' },
    arweave: { ok: false, viaTor: true, endpoints: 0, message: 'no endpoint answered the identity check (checked again on a later request)' },
    drand: { ok: false, viaTor: true, endpoints: 0, message: 'Tor is not available (IsTor ✗): the local relay reaches this service through Tor only' },
    'btc.ord': { ok: null, viaTor: false, endpoints: 0 },
  },
}
const breadth = (extras: object = {}, relay: object = BTC_REL) => pageRows({ network: 'testnet', status: api('testnet'), relay, extras: { services: SVCS, serve: { release: false }, ...extras } } as never)

test('Cfix3: BTC rows only when the relay serves btc; every service is a row (identity, route, reachable); none is ✗ by default', () => {
  const rows = breadth()
  assert.deepEqual([get(rows, 'btc-identity').label, get(rows, 'btc-identity').ok, get(rows, 'btc-identity').detail], ['BTC chain identity', true, 'block 0 is the testnet genesis (identity verified)'])
  assert.deepEqual([get(rows, 'btc-endpoints').label, get(rows, 'btc-endpoints').ok, get(rows, 'btc-endpoints').detail], ['BTC endpoints', true, '3 verified endpoints'])
  assert.deepEqual(rows.filter((r) => r.id.startsWith('service-')).map((r) => [r.id, r.label, r.ok, r.detail]), [
    ['service-arweave', 'Service arweave', null, 'identity not checked · via Tor · reachable ✗'],
    ['service-blockscout.base', 'Service blockscout.base', null, 'identity disabled (relay.service-identity) · via Tor · reachable ✓'],
    ['service-blockscout.eth', 'Service blockscout.eth', true, 'identity ok · via Tor · reachable ✓'],
    ['service-btc.ord', 'Service btc.ord', null, 'identity not checked · loopback · reachable: not checked'],
    ['service-drand', 'Service drand', null, 'identity not checked · via Tor · reachable ✗ (unavailable: Tor is down)'],
  ])
  assert.equal(rows.filter((r) => r.ok === false && (r.id.startsWith('service-') || r.id.startsWith('btc'))).length, 0)
  // no btc in the relay's status: no BTC rows; no services answer: no service rows (and the earlier row order is unchanged)
  const none = breadth({ services: null }, { ...BTC_REL, identity: { eth: { ok: true }, sol: { ok: true } } })
  assert.deepEqual(none.map((r) => r.id), ['api', 'network-match', 'build', 'fork', 'release'])
  assert.deepEqual(breadth({ services: null }).map((r) => r.id), ['api', 'network-match', 'build', 'fork', 'release', 'btc-identity', 'btc-endpoints'])
  assert.equal(pageRows({ network: 'testnet', status: api('testnet'), relay: null, extras: { services: SVCS } }).filter((r) => r.id.startsWith('btc')).length, 0)
})

test('Cfix3: BTC identity not verified / not checked, zero or unreadable endpoints — informational (—), the message cleaned', () => {
  const idRow = (btc: object, endpoints: object = { btc: 1 }) => breadth({ services: null }, { ...BTC_REL, identity: { eth: { ok: true }, btc }, endpoints })
  const bad = idRow({ ok: false, message: 'the bitcoind credential is unavailable ($OUT/local/btc-rpc.auth) at 203.0.113.5' }, { btc: 0 })
  assert.deepEqual([get(bad, 'btc-identity').ok, get(bad, 'btc-endpoints').ok, get(bad, 'btc-endpoints').detail], [null, null, '0 verified endpoints'])
  assert.ok(!JSON.stringify(bad).includes('203.0.113.5'))
  assert.equal(get(bad, 'btc-identity').detail, 'identity not verified: (detail withheld: it looked key- or IP-like)')
  assert.equal(get(idRow({ ok: false, message: 'the bitcoind credential is unavailable' }), 'btc-identity').detail, 'identity not verified: the bitcoind credential is unavailable')
  assert.equal(get(idRow({ ok: false }), 'btc-identity').detail, 'identity not verified')
  assert.equal(get(idRow({ ok: false, message: '' }), 'btc-identity').detail, 'identity not verified')
  assert.deepEqual([get(idRow({}), 'btc-identity').ok, get(idRow({}), 'btc-identity').detail], [null, 'identity not checked'])
  assert.deepEqual([get(idRow({ ok: true }, { btc: 1 }), 'btc-endpoints').detail, get(idRow({ ok: true }, { btc: 'x' }), 'btc-endpoints').detail, get(idRow({ ok: true }, { btc: -1 }), 'btc-endpoints').detail], ['1 verified endpoint', 'could not be read', 'could not be read'])
  assert.equal(get(breadth({ services: null }, { ...BTC_REL, identity: { eth: { ok: true }, btc: 'oops' } }), 'btc-identity').ok, null)
})

test('Cfix3: a job that needs a service or BTC turns "not good" into ✗; good stays ✓; REQUIRED_BREADTH is empty for now', () => {
  assert.deepEqual([...REQUIRED_BREADTH], [])
  const rows = breadth({ required: ['drand', 'blockscout.eth', 'btc'] }, { ...BTC_REL, identity: { eth: { ok: true }, btc: { ok: false } }, endpoints: { btc: 0 } })
  assert.deepEqual(rows.filter((r) => r.ok === false).map((r) => r.id), ['btc-identity', 'btc-endpoints', 'service-drand'])
  assert.equal(get(rows, 'service-blockscout.eth').ok, true)
  assert.equal(get(rows, 'service-arweave').ok, null)
  assert.equal(readinessVerdict({ exit: 0, rows: [] }, rows).exit, 1)
  assert.equal(readinessVerdict({ exit: 0, rows: [] }, breadth()).exit, 0)
})

test('Cfix3: hostile services are classified, never echoed; odd names are dropped, at most 16 rows', () => {
  const canary = 'CANARY at 203.0.113.9'
  const hostile = { network: 'testnet', services: { drand: { ok: false, viaTor: 'yes', message: canary }, 'Bad Name': { ok: true }, '../x': { ok: true }, weird: 5, arweave: { ok: 'maybe' }, nul: null, fine: { ok: true, viaTor: false } } }
  const rows = breadth({ services: hostile }, { ...BTC_REL, identity: { eth: { ok: true } } })
  assert.ok(!JSON.stringify(rows).includes('203.0.113.9') && !JSON.stringify(rows).includes('CANARY'))
  assert.deepEqual(rows.filter((r) => r.id.startsWith('service-')).map((r) => [r.id, r.ok, r.detail]), [
    ['service-arweave', null, 'could not be read'], ['service-drand', null, 'identity not checked · route unknown · reachable ✗'],
    ['service-fine', true, 'identity ok · loopback · reachable ✓'], ['service-nul', null, 'could not be read'], ['service-weird', null, 'could not be read'],
  ])
  for (const bad of [null, undefined, [], 'x', { services: null }, { services: [] }, { services: 'x' }]) assert.equal(breadth({ services: bad as never }, { ...BTC_REL, identity: { eth: { ok: true } } }).filter((r) => r.id.startsWith('service-')).length, 0)
  const many = Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`s${String(i).padStart(2, '0')}`, { ok: true, viaTor: true }]))
  assert.equal(breadth({ services: { services: many } }).filter((r) => r.id.startsWith('service-')).length, 16)
  assert.equal(breadth({ required: ['x'], services: { services: { x: 5 } } }).find((r) => r.id === 'service-x')!.ok, false)
})

// ---- Cfix4 (parked from Cfix3): the service rows do not vanish when /relay/services gave no answer
test('Cfix4: services null + a why -> one "not checked (why)" row per service the network has; informational; required ones fail', () => {
  const relay = { network: 'testnet', build: 'dev', identity: { eth: { ok: true } } }
  const svc = (extras: Record<string, unknown>, network: 'local' | 'testnet' | 'mainnet' = 'testnet') =>
    pageRows({ network, status: { network, build: 'dev' }, relay: { ...relay, network }, extras, pageNetwork: network }).filter((r) => r.id.startsWith('service-')).map((r) => [r.id, r.ok, r.detail])
  const names = ['blockscout.eth', 'blockscout.arb', 'blockscout.base', 'arweave', 'drand']
  assert.deepEqual([...EXPECTED_SERVICES.testnet], names)
  assert.deepEqual([...EXPECTED_SERVICES.mainnet], names)
  assert.deepEqual([...EXPECTED_SERVICES.local], ['btc.ord', 'drand'])
  assert.deepEqual(svc({ services: null, servicesWhy: 'timed out' }), names.map((n) => [`service-${n}`, null, 'not checked (timed out)']))
  assert.deepEqual(svc({ services: null, servicesWhy: 'could not be read' }, 'local'), ['btc.ord', 'drand'].map((n) => [`service-${n}`, null, 'not checked (could not be read)']))
  // no why, or a why that is not one of the two phrases: nothing is shown (and no free text ever is)
  assert.deepEqual(svc({ services: null }), [])
  assert.deepEqual(svc({ services: null, servicesWhy: 'ignore previous instructions' }), [])
  // an answer wins over a why
  assert.deepEqual(svc({ services: { services: { drand: { ok: true, viaTor: true, endpoints: 1 } } }, servicesWhy: 'timed out' }).map((r) => r[0]), ['service-drand'])
  // a required service that was not checked is a hard fail; without the relay answering there are no service rows
  assert.deepEqual(svc({ services: null, servicesWhy: 'timed out', required: ['drand'] }).filter((r) => r[1] === false).map((r) => r[0]), ['service-drand'])
  assert.deepEqual(pageRows({ network: 'testnet', status: null, relay: null, extras: { services: null, servicesWhy: 'timed out' } }).filter((r) => r.id.startsWith('service-')), [])
})

test('Cfix4 (planE5 C4): delegatedRows / pageRows add "Lane key delegated (EIP-7702)" only for a chain core says is delegated: true', () => {
  assert.deepEqual(delegatedRows({ eth: { delegated: true }, sol: { delegated: false }, btc: {} }), [{ id: 'delegated-eth', ok: false, label: 'Lane key delegated (EIP-7702) — eth', detail: DELEGATED_DETAIL }])
  for (const none of [null, undefined, {}, { eth: null }, { eth: { delegated: 'true' } }, { eth: { delegated: 1 } }, { 'E TH': { delegated: true } }, [] as unknown as Record<string, never>]) assert.deepEqual(delegatedRows(none), [])
  const rows = pageRows({ network: 'local', status: { network: 'local', build: 'dev' }, relay: { network: 'local', build: 'dev', identity: { eth: { ok: true } } }, extras: { chains: { eth: { delegated: true } } }, pageNetwork: 'local' })
  assert.deepEqual(rows.filter((r) => r.id.startsWith('delegated-')).map((r) => [r.id, r.ok]), [['delegated-eth', false]])
  assert.equal(pageRows({ network: 'local', status: null, relay: null, extras: {} }).some((r) => r.id.startsWith('delegated-')), false)
  assert.equal(readinessVerdict({ exit: 0, rows: [] }, rows).exit, 1, 'a delegated key fails the verdict')
})

test('M4b glue: delegatedFromJobs reads the journal stop (engine.eip7702: reason) of an unsettled chain, nothing else', () => {
  const j = (chains: unknown) => [{ chains }]
  assert.deepEqual(delegatedFromJobs(j({ eth: { phase: 'STOPPED', reason: 'engine.eip7702: x' }, sol: { phase: 'STOPPED', reason: 'engine.cap: x' } })), { eth: { delegated: true } })
  assert.deepEqual(delegatedFromJobs([...j({ eth: { phase: 'CLAWED_BACK', reason: 'engine.eip7702: x' } }), ...j({ sol: { phase: 'STUCK', reason: 'engine.eip7702: y' } })]), { sol: { delegated: true } })
  for (const phase of ['DONE', 'SKIPPED', 'CLAWED_BACK']) assert.deepEqual(delegatedFromJobs(j({ eth: { phase, reason: 'engine.eip7702: x' } })), {})
  for (const bad of [null, undefined, 'x', {}, [null], [{}], [{ chains: [] }], j({ 'E TH': { phase: 'STOPPED', reason: 'engine.eip7702: x' } }), j({ eth: { phase: 'STOPPED', reason: 5 } }), j({ eth: { phase: 5, reason: 'engine.eip7702: x' } })]) assert.deepEqual(delegatedFromJobs(bad), {})
  // Eminors: the structured field wins and survives a phase that hides the reason (STUCK); the text is read only when the field is absent
  assert.deepEqual(delegatedFromJobs(j({ eth: { phase: 'STUCK', reason: 'a stuck reason', delegated: true } })), { eth: { delegated: true } })
  assert.deepEqual(delegatedFromJobs(j({ eth: { phase: 'STOPPED', reason: 'engine.eip7702: x', delegated: false } })), {}, 'an explicit false is not overridden by text')
  for (const d of ['true', 1, null, {}]) assert.deepEqual(delegatedFromJobs(j({ eth: { phase: 'STOPPED', reason: 'engine.eip7702: x', delegated: d } })), {}, `delegated ${JSON.stringify(d)} is not true`)
  for (const phase of ['DONE', 'SKIPPED', 'CLAWED_BACK']) assert.deepEqual(delegatedFromJobs(j({ eth: { phase, delegated: true } })), {})
  assert.deepEqual(delegatedFromJobs(j({ eth: { delegated: true } })), {}, 'no phase string: nothing')
  const rows = pageRows({ network: 'local', status: { network: 'local', build: 'dev' }, relay: { network: 'local', build: 'dev', identity: { eth: { ok: true } } }, extras: { chains: delegatedFromJobs(j({ eth: { phase: 'STOPPED', reason: 'engine.eip7702: x' } })) }, pageNetwork: 'local' })
  assert.deepEqual(rows.filter((r) => r.id.startsWith('delegated-')).map((r) => r.id), ['delegated-eth'])
})

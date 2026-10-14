// Tor gate (spec B s6.1, Task 7): env-key check, then a raw RFC 1928 probe that the SOCKS port picks
// username/password auth (so IsolateSOCKSAuth circuits hold), then GET check.torproject.org/api/ip
// through the net layer. Only `IsTor === true` opens the gate, and only torGate can open it.
// The canary 203.0.113.77 stands in for the operator's IP: it must never leave torGate.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { inspect } from 'node:util'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { Refusal } from '../../src/guard.ts'
import * as fetchModule from '../../src/net/fetch.ts'
import { createNet } from '../../src/net/fetch.ts'
import * as gateModule from '../../src/net/gate.ts'
import { TOR_CHECK_URL, torGate } from '../../src/net/gate.ts'
import type { Transport } from '../../src/net/transport.ts'
import { ReplayTransport, loadFixture, type Replay } from '../fakes/replay.ts'
import { closedPort, startSocks5, type FakeSocks } from '../fakes/socks5.ts'
import { CANARY } from '../fakes/http.ts'

let seq = 0
// Canonical ISO minutes (net.tick-format), one per net.
const tick = () => `${new Date(Date.UTC(2026, 9, 8, 4, 0) + ++seq * 60_000).toISOString().slice(0, 16)}Z`
const isRefusal = (id: string) => (e: unknown) => e instanceof Refusal && e.guardId === id
const check = (name: string) => loadFixture('check', name)

// Never print the error itself: if it leaked the canary, printing it would leak it again.
function leaksCanary(v: unknown): boolean {
  const parts = [String(v), inspect(v, { depth: 8, showHidden: true })]
  try { parts.push(JSON.stringify(v) ?? '') } catch { /* circular: inspect covers it */ }
  if (v instanceof Error) parts.push(v.message, String(v.stack))
  return parts.join('\n').includes(CANARY)
}
async function caught(p: Promise<unknown>): Promise<unknown> {
  try { await p } catch (e) { return e }
  return assert.fail('expected a rejection')
}

// The probe's SOCKS server (the default mode picks username/password, like Tor).
let socks: FakeSocks
before(async () => { socks = await startSocks5({ targetPort: await closedPort() }) })
after(async () => { await socks.close() })

function replayNet(fixtures: Parameters<typeof ReplayTransport>[0], socksPort = socks.port): { net: ReturnType<typeof createNet>; replay: Replay } {
  const replay = ReplayTransport(fixtures)
  return { net: createNet({ tick: tick(), socksPort, transport: replay }), replay }
}

test('IsTor true: returns exactly { isTor: true }, opens the gate, and the IP never surfaces', async () => {
  assert.equal(TOR_CHECK_URL, 'https://check.torproject.org/api/ip')
  const { net, replay } = replayNet([check('is-tor')])
  assert.equal(net.gatePassed(), false)
  const greetings = socks.greetings.length
  const r = await torGate(net, {})
  assert.deepEqual(r, { isTor: true })
  assert.deepEqual(Object.keys(r), ['isTor'])
  assert.ok(!leaksCanary(r), 'the return value carries the IP')
  assert.equal(net.gatePassed(), true)
  assert.equal(replay.remaining(), 0)
  assert.equal(replay.requests.length, 1)
  assert.equal(replay.requests[0].socksUser, `check.${net.tick}`)
  assert.deepEqual(net.events().map((e) => [e.role, e.host, e.atyp]), [['check', 'check.torproject.org', 'domain']])
  // The probe offered exactly [no-auth, user/pass] and sent nothing past the greeting.
  assert.deepEqual(socks.greetings.slice(greetings), [[0, 2]])
})

test('tor.not-tor: IsTor false refuses, the gate stays closed, the IP never surfaces', async () => {
  const { net } = replayNet([check('not-tor')])
  const e = await caught(torGate(net, {}))
  assert.ok(isRefusal('tor.not-tor')(e))
  assert.ok(!leaksCanary(e))
  assert.equal(net.gatePassed(), false)
})

test('tor.check-malformed: {}, <html>, a string IsTor, an inherited IsTor, an array, a non-200', async () => {
  for (const name of ['empty-object', 'html', 'is-tor-string', 'is-tor-inherited', 'array', 'status-503']) {
    const { net, replay } = replayNet([check(name)])
    const e = await caught(torGate(net, {}))
    assert.ok(isRefusal('tor.check-malformed')(e), name)
    assert.ok(!leaksCanary(e), `canary leaked (${name})`)
    assert.equal(net.gatePassed(), false, name)
    assert.equal(replay.remaining(), 0, name)
  }
})

test('tor.unreachable: the transport throws (net layer), or the SOCKS port is closed (probe)', async () => {
  const thrower: Transport = async () => { throw new Error(`boom ${CANARY}`) }
  const net = createNet({ tick: tick(), socksPort: socks.port, transport: thrower })
  const e = await caught(torGate(net, {}))
  assert.ok(isRefusal('tor.unreachable')(e))
  assert.ok(!leaksCanary(e))
  assert.equal(net.gatePassed(), false)

  const { net: n2, replay } = replayNet([check('is-tor')], await closedPort())
  const e2 = await caught(torGate(n2, {}))
  assert.ok(isRefusal('tor.unreachable')(e2))
  assert.equal(replay.requests.length, 0, 'no check request when the probe fails')
  assert.equal(n2.gatePassed(), false)
})

test('tor.socks-noauth: a proxy that picks no-auth, or rejects user/pass, is refused before the check', async () => {
  for (const mode of [{ pickNoAuth: true }, { refuseAuth: true }]) {
    const s = await startSocks5({ targetPort: await closedPort(), ...mode })
    try {
      const { net, replay } = replayNet([check('is-tor')], s.port)
      const e = await caught(torGate(net, {}))
      assert.ok(isRefusal('tor.socks-noauth')(e), JSON.stringify(mode))
      assert.equal(replay.requests.length, 0, 'the check was never requested')
      assert.equal(net.gatePassed(), false)
      assert.deepEqual(s.greetings, [[0, 2]])
      assert.equal(s.records.length, 0, 'the probe never sends a CONNECT')
    } finally { await s.close() }
  }
})

test('config.env-key: an API key in the env refuses before any socket or request', async () => {
  const s = await startSocks5({ targetPort: await closedPort() })
  try {
    for (const env of [{ ALCHEMY_API_KEY: 'x' }, { INFURA_PROJECT_ID: 'x' }, { SOME_API_KEY: 'x' }]) {
      const { net, replay } = replayNet([check('is-tor')], s.port)
      await assert.rejects(torGate(net, env), isRefusal('config.env-key'), JSON.stringify(Object.keys(env)))
      assert.equal(replay.requests.length, 0)
      assert.equal(net.gatePassed(), false)
    }
    assert.equal(s.connections(), 0, 'the probe never ran')
    // An empty value is not a key (config's rule); the gate then passes.
    const { net } = replayNet([check('is-tor')], s.port)
    assert.deepEqual(await torGate(net, { ALCHEMY_API_KEY: '' }), { isTor: true })
  } finally { await s.close() }
})

test('only the gate opens the gate: no setter on the net, no exported opener, per instance', async () => {
  const { net } = replayNet([check('is-tor')])
  assert.ok(Object.isFrozen(net))
  for (const name of ['mark' + 'GatePassed', 'pass' + 'Gate', 'openGate', 'setGate']) {
    assert.ok(!(name in net), `net.${name}`)
    assert.ok(!(name in fetchModule), `fetch.ts exports ${name}`)
    assert.ok(!(name in gateModule), `gate.ts exports ${name}`)
  }
  assert.throws(() => { (net as unknown as Record<string, unknown>).gatePassed = () => true })
  assert.equal(net.gatePassed(), false)
  // Another instance with the same tick is not opened by this one's gate.
  const twin = createNet({ tick: net.tick, socksPort: socks.port, transport: ReplayTransport([]) })
  await torGate(net, {})
  assert.equal(net.gatePassed(), true)
  assert.equal(twin.gatePassed(), false)
  // A look-alike object passed through torGate opens nothing real.
  const fake = { ...net, socksPort: socks.port, fetchFor: () => async () => ({ status: 200, headers: {}, text: async () => '{"IsTor":true}', json: async () => ({ IsTor: true }), bytes: async () => new Uint8Array() }) }
  await torGate(fake as unknown as typeof net, {})
  assert.equal(twin.gatePassed(), false)
})

// stdout/stderr of a whole process that runs the gate on every case: the canary never appears.
test('captured stdout/stderr: the canary never appears; the default env is process.env', () => {
  const src = fileURLToPath(new URL('../../src/', import.meta.url))
  const fakes = fileURLToPath(new URL('../fakes/', import.meta.url))
  const script = `
    import { inspect } from 'node:util'
    import { createNet } from ${JSON.stringify(src + 'net/fetch.ts')}
    import { torGate } from ${JSON.stringify(src + 'net/gate.ts')}
    import { ReplayTransport, loadFixture } from ${JSON.stringify(fakes + 'replay.ts')}
    import { closedPort, startSocks5 } from ${JSON.stringify(fakes + 'socks5.ts')}
    const s = await startSocks5({ targetPort: await closedPort() })
    let i = 0
    for (const [name, env] of [['is-tor', {}], ['not-tor', {}], ['html', {}], ['empty-object', {}], ['throw', {}], ['is-tor', undefined]]) {
      const transport = name === 'throw'
        ? async () => { throw new Error('boom ' + ${JSON.stringify(CANARY)}) }
        : ReplayTransport([loadFixture('check', name)])
      const net = createNet({ tick: new Date(Date.UTC(2026, 9, 8, 5, 0) + (++i) * 60000).toISOString().slice(0, 16) + 'Z', socksPort: s.port, transport })
      try { console.log(name, JSON.stringify(await torGate(net, env))) }
      catch (e) { console.log(name, 'refused', e.guardId); console.error(inspect(e, { showHidden: true, depth: 8 })) }
    }
    await s.close()
  `
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    encoding: 'utf8',
    timeout: 60_000,
    env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', NODE_TEST_CONTEXT: 'child-v8', ALCHEMY_API_KEY: 'x' },
  })
  assert.equal(r.status, 0)
  const out = r.stdout + r.stderr
  assert.ok(!out.includes(CANARY), 'the canary reached stdout/stderr')
  assert.deepEqual(r.stdout.trim().split('\n'), [
    'is-tor {"isTor":true}',
    'not-tor refused tor.not-tor',
    'html refused tor.check-malformed',
    'empty-object refused tor.check-malformed',
    'throw refused tor.unreachable',
    'is-tor refused config.env-key', // torGate(net) with no env reads process.env (ALCHEMY_API_KEY=x)
  ])
})

// api/test/relay-rehash.test.ts — Cfix2 + fix round 1: GET /relay/release is NEVER stale: every answer is a re-hash started after the request (hashedAt); GET
// /relay/release awaits the one in-flight result; a failure is a failure (503), never kept as a success.
// The real createRelay in process (fake transport, no socket upstream) over synthetic release trees. Synthetic data only.
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, request, type Server } from 'node:http'
import { join } from 'node:path'
import { PORTS } from '@vault-timelock/core/contracts'
import { GENESIS } from 'vt-broadcast/src/config.ts'
import { createRelay, rehashRelease, relayUpstreams } from '../relay/relay.mjs'
import { TICKET_KEY, tempDir } from './helpers.ts'

const HOST = `127.0.0.1:${PORTS.mainnet.relay}`
const cleanups: Array<() => unknown> = []
after(async () => { for (const c of cleanups.reverse()) await c() })
const sha = (b: string): string => createHash('sha256').update(b).digest('hex')

function tree(n = 3): string {
  const t = tempDir('vt-rehash-')
  cleanups.push(t.cleanup)
  const root = join(t.dir, 'releases', '0123456789ab')
  mkdirSync(root, { recursive: true })
  const lines: string[] = []
  for (let i = 0; i < n; i++) { writeFileSync(join(root, `f${i}.txt`), `file ${i}\n`); lines.push(`${sha(`file ${i}\n`)}  f${i}.txt`) }
  writeFileSync(join(root, 'SHA256SUMS'), lines.join('\n') + '\n')
  return root
}

const TOR_CHECK = 'https://check.torproject.org/api/ip'
async function relay(o: { releaseRoot: string; rehash?: (root: string) => Promise<object>; now?: () => number }): Promise<{ port: number; started: Promise<void>; get: () => Promise<{ status: number; json: any; ms: number }> }> {
  const r = createRelay({
    network: 'mainnet', build: '0123456789ab', upstream: relayUpstreams('mainnet', {}),
    transport: async (url: string, q: { body?: Buffer }) => {
      const out = (v: unknown) => ({ status: 200, body: Buffer.from(JSON.stringify(v)) })
      if (url === TOR_CHECK) return out({ IsTor: true })
      const b = q.body ? JSON.parse(q.body.toString('utf8')) as { id: unknown; method: string } : null
      if (b === null) return { status: 404, body: Buffer.from('{}') }
      return out({ jsonrpc: '2.0', id: b.id, result: b.method === 'eth_chainId' ? '0x1' : b.method === 'getGenesisHash' ? GENESIS.sol.mainnet : b.method === 'eth_estimateGas' ? '0x61a8' : 'x' })
    },
    priceFixture: null, ticketKey: () => TICKET_KEY, confinement: { ok: true, probes: 5, result: 'EPERM ×5' },
    now: o.now ?? (() => Date.now()), log: () => {}, rand: () => 'sess', releaseRoot: o.releaseRoot, ...(o.rehash ? { rehash: o.rehash } : {}),
  })
  const server: Server = createServer(r.handle)
  await new Promise<void>((res) => server.listen(0, '127.0.0.1', res))
  cleanups.push(() => new Promise<void>((res) => { server.closeAllConnections(); server.close(() => res()) }))
  const port = (server.address() as { port: number }).port
  const get = () => new Promise<{ status: number; json: any; ms: number }>((resolve, reject) => {
    const t0 = Date.now()
    const req = request({ host: '127.0.0.1', port, path: '/relay/release', agent: false, setHost: false, headers: { host: HOST } }, (res) => {
      const c: Buffer[] = []
      res.on('data', (d: Buffer) => c.push(d))
      res.on('end', () => { let json: unknown = null; try { json = JSON.parse(Buffer.concat(c).toString('utf8')) } catch { /* */ } resolve({ status: res.statusCode ?? 0, json, ms: Date.now() - t0 }) })
    })
    req.on('error', reject); req.end()
  })
  return { port, started: r.startup(), get }
}
const gate = () => { let open!: (v?: unknown) => void, fail!: (e: unknown) => void; const p = new Promise((res, rej) => { open = res; fail = rej }); return { p, open, fail } }

test('the relay warms up at startup (no request), but that result is never served: a request gets a re-hash started after it', async () => {
  const root = tree()
  let calls = 0
  const starts: number[] = []
  const g = gate()
  const rl = await relay({ releaseRoot: root, rehash: async (r) => { calls++; starts.push(Date.now()); if (calls === 1) await g.p; return rehashRelease(r) } })
  await new Promise((r) => setTimeout(r, 100))
  assert.equal(calls, 1, 'the warm-up started with startup(), with no request made')
  const t0 = Date.now()
  const p = rl.get()
  await new Promise((r) => setTimeout(r, 100))
  assert.equal(calls, 1, 'the request waits for the warm-up to end (one at a time)')
  g.open()
  await rl.started
  const a = await p
  assert.equal(calls, 2, 'its own re-hash')
  assert.ok(starts[1] >= t0, 'started after the request')
  assert.equal(a.status, 200)
  assert.ok(a.json.hashedAt >= t0, `hashedAt ${a.json.hashedAt} >= request time ${t0}`)
  assert.deepEqual({ ...a.json, hashedAt: 0 }, { ...JSON.parse(JSON.stringify(await rehashRelease(root))), hashedAt: 0 })
  assert.deepEqual([a.json.release, a.json.files, a.json.ok], [true, 3, 3])
})

test('a file changed after startup: the very next /relay/release reports the mismatch (a success never outlives a change)', async () => {
  const root = tree()
  const rl = await relay({ releaseRoot: root })
  await rl.started
  const a = await rl.get()
  assert.deepEqual([a.json.ok, a.json.mismatch], [3, 0])
  writeFileSync(join(root, 'f2.txt'), 'tampered\n')
  const b = await rl.get()
  assert.deepEqual([b.json.ok, b.json.mismatch, b.json.missing], [2, 1, 0])
  rmSync(join(root, 'f0.txt'))
  const c = await rl.get()
  assert.deepEqual([c.json.ok, c.json.mismatch, c.json.missing], [1, 1, 1])
  assert.ok(c.json.hashedAt >= b.json.hashedAt && b.json.hashedAt >= a.json.hashedAt)
  writeFileSync(join(root, 'f0.txt'), 'file 0\n'); writeFileSync(join(root, 'f2.txt'), 'file 2\n')
  assert.deepEqual([(await rl.get()).json.ok], [3], 'and back')
})

test('concurrent requests share ONE re-hash, never two at once; a request that arrives during one gets the next, not that one', async () => {
  const g1 = gate()
  let calls = 0, live = 0, maxLive = 0
  const gates = [gate(), gate(), gate()]
  const rl = await relay({ releaseRoot: tree(), rehash: async (r) => {
    const i = calls++; live++; maxLive = Math.max(maxLive, live)
    try { await gates[i].p; return await rehashRelease(r) } finally { live-- }
  } })
  gates[0].open(); await rl.started                       // the warm-up
  const [p1, p2, p3] = [rl.get(), rl.get(), rl.get()]    // same tick: one re-hash (#2)
  await new Promise((r) => setTimeout(r, 200))
  assert.equal(calls, 2, 'three simultaneous requests started one re-hash')
  const late = rl.get()                                   // arrives while #2 runs: must wait for the NEXT one
  await new Promise((r) => setTimeout(r, 100))
  assert.equal(calls, 2, 'not two at once')
  gates[1].open()
  const [a, b, c] = await Promise.all([p1, p2, p3])
  assert.deepEqual([a.status, b.status, c.status], [200, 200, 200])
  assert.equal(a.json.hashedAt, b.json.hashedAt); assert.equal(b.json.hashedAt, c.json.hashedAt)
  await new Promise((r) => setTimeout(r, 100))
  assert.equal(calls, 3, 'the late request got its own re-hash')
  gates[2].open()
  const l = await late
  assert.equal(l.status, 200)
  assert.ok(l.json.hashedAt >= a.json.hashedAt)
  assert.equal(maxLive, 1)
  void g1
})

test('a failed re-hash answers 503 and is never cached as success; the next request re-hashes afresh', async () => {
  let calls = 0
  const rl = await relay({ releaseRoot: tree(), rehash: async (r) => { calls++; if (calls === 2) throw new Error('boom'); return rehashRelease(r) } })
  await rl.started
  const ok1 = await rl.get()                              // calls 2: fails
  assert.equal(ok1.status, 503)
  assert.equal(ok1.json.release, undefined)
  assert.equal(ok1.json.error.message, 'the release re-hash failed', 'a fixed text: the cause is not echoed')
  const b = await rl.get()                                // calls 3: succeeds
  assert.deepEqual([b.status, b.json.ok, calls], [200, 3, 3])
})

test('hashedAt is the start of the re-hash that answered: never before the request', async () => {
  const rl = await relay({ releaseRoot: tree() })
  await rl.started
  for (let i = 0; i < 3; i++) {
    const t0 = Date.now()
    const a = await rl.get()
    assert.ok(Number.isSafeInteger(a.json.hashedAt) && a.json.hashedAt >= t0 && a.json.hashedAt <= Date.now(), `${a.json.hashedAt} vs ${t0}`)
    await new Promise((r) => setTimeout(r, 5))
  }
})

test('a success followed by a failing re-hash: the failure is reported, the earlier success is not served', async () => {
  let fail = false
  const rl = await relay({ releaseRoot: tree(), rehash: async (r) => { if (fail) throw new Error('x'); return rehashRelease(r) } })
  await rl.started
  assert.equal((await rl.get()).status, 200)
  fail = true
  assert.equal((await rl.get()).status, 503)
  assert.equal((await rl.get()).status, 503)
})

test('a non-release tree answers { release: false } (a dev tree) with hashedAt, and a damaged one its counts', async () => {
  const t = tempDir('vt-rehash-dev-'); cleanups.push(t.cleanup)
  const dev = await relay({ releaseRoot: t.dir }); await dev.started
  const d = (await dev.get()).json
  assert.deepEqual([d.release, Object.keys(d).sort()], [false, ['hashedAt', 'release']])
  const root = tree(); writeFileSync(join(root, 'f1.txt'), 'changed\n')
  const bad = await relay({ releaseRoot: root }); await bad.started
  const j = (await bad.get()).json
  assert.deepEqual([j.files, j.ok, j.mismatch, j.missing], [3, 2, 1, 0])
})

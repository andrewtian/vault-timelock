// Parity (spec §7.3, E3 ruling 6): the same job and the same relay script, run by the node adapter (the CLI: loopback
// ports + bearer token) and by the browser adapter (the page: relative /api and /relay URLs resolved by a jsdom window,
// no token), produce equivalent journals — equal [type, copy, part] sequences. ALL DATA IS SYNTHETIC; nothing listens.
// jsdom is core's own devDependency (I2; pinned 29.1.1 like web's), resolved from this package.
import { afterEach, test } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { createExecutor } from '../../src/executor/executor.ts'
import { browserAdapter, browserClients, uniform } from '../../src/executor/adapters/browser.ts'
import { nodeAdapter, nodeClients } from '../../src/executor/adapters/node.ts'
import type { Chain } from '../../src/contracts/index.ts'
import { stackFetch } from '../fakes/fake-relay.ts'
import { newKey, sendViolations, stack } from './helpers.ts'

const TOKEN = 'cd'.repeat(32)
const { JSDOM } = createRequire(import.meta.url)('jsdom') as { JSDOM: new (html: string, o: { url: string }) => { window: { location: { href: string }; URL: typeof URL } } }

async function runWith(adapter: 'node' | 'browser', chain: Chain, key: ReturnType<typeof newKey>, text: string) {
  const s = stack(chain, { copies: 2, startIn: 3_000, text, key })
  const net = stackFetch({ network: 'local', journal: s.j.client, relay: s.relay.client, token: TOKEN })
  let clients
  if (adapter === 'node') clients = nodeClients({ network: 'local', token: TOKEN, fetch: net.fetch })
  else {
    const dom = new JSDOM('<!doctype html><title>vt</title>', { url: 'http://127.0.0.1:5180/#/jobs' })
    const pageFetch = (url: string, init?: RequestInit) => net.fetch(new dom.window.URL(url, dom.window.location.href).href, init)   // the page's relative URLs
    clients = browserClients({ fetch: pageFetch })
  }
  const a = adapter === 'node' ? nodeAdapter() : browserAdapter()
  const ex = createExecutor({ jobId: s.j.id, chain, key, holder: adapter === 'node' ? 'cli' : 'browser', deps: { ...clients, clock: s.clock, random: a.random, poll: 1_000, passiveWaitMs: 1_000 } })
  const outcome = await ex.start()
  const seq = s.j.events.filter((e) => e.chain === chain && (e.by === 'cli' || e.by === 'browser') && e.gen !== 1).map((e) => [e.type, e.data.copy ?? null, e.data.part ?? null])
  return { outcome, seq, seen: net.seen, sends: s.relay.sends().length }
}

// CC-3a: the relay refuses a signed tx whose nonce / blockhash is not the one its intent declared — every send here must pass
afterEach(() => { assert.deepEqual(sendViolations.splice(0), [], 'every ticketed send was exactly its journaled intent (id, bytes, declared nonce / blockhash)') })

test('the node adapter and the browser adapter (jsdom) run the same job to equal journals: [type, copy, part] per event', { timeout: 120_000 }, async () => {
  for (const chain of ['eth', 'sol'] as const) {
    const key = newKey(chain), text = chain === 'sol' ? 'Parity text across parts. '.repeat(60) : 'Parity text.\n'
    const n = await runWith('node', chain, key, text), b = await runWith('browser', chain, key, text)
    assert.equal(n.outcome, 'copies-done'); assert.equal(b.outcome, 'copies-done')
    assert.ok(n.seq.length > 6)
    assert.deepEqual(b.seq, n.seq, `${chain}: equivalent journals`)
    assert.equal(b.sends, n.sends)
    assert.ok(n.seen.every((u) => u.startsWith('http://127.0.0.1:5182/') || u.startsWith('http://127.0.0.1:5181/')), 'the CLI reached only its API and relay ports')
    assert.ok(b.seen.every((u) => u.startsWith('http://127.0.0.1:5180/')), 'the page reached only its own origin')
  }
})

test('the adapters: wall clocks, CSPRNG integers in range (no modulo bias), node: imports only in adapters/node.ts', async () => {
  for (const a of [nodeAdapter(), browserAdapter()]) {
    const t0 = a.clock.now(); await a.clock.sleep(5); assert.ok(a.clock.now() >= t0)
    const seen = new Set<number>()
    for (let i = 0; i < 400; i++) { const x = a.random.int(7); assert.ok(Number.isInteger(x) && x >= 0 && x < 7); seen.add(x) }
    assert.equal(seen.size, 7)
  }
  assert.throws(() => uniform(0), RangeError); assert.throws(() => uniform(2 ** 33), RangeError)
  const { readdirSync, readFileSync, statSync } = await import('node:fs')
  const { join } = await import('node:path')
  const root = new URL('../../src/', import.meta.url).pathname
  const walk = (d: string): string[] => readdirSync(d).flatMap((f) => { const p = join(d, f); return statSync(p).isDirectory() ? walk(p) : [p] })
  for (const f of walk(root).filter((p) => /\.(?:js|ts)$/.test(p))) {
    const uses = /from ['"]node:|import\(['"]node:/.test(readFileSync(f, 'utf8'))
    assert.equal(uses, f.endsWith('executor/adapters/node.ts'), `${f}: node: imports only in the node adapter (spec §7.1)`)
  }
})

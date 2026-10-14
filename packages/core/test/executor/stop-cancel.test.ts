// m-b (M5d review), through the executor: `vt job stop` is seen at a lease tick (the stop flag), then the operator's resume ("Cancel the
// stop", vt job resume) lifts the request before the run journals the stop. The run journals no `stopped` (an operator-stop without a
// held request is FINAL at the API) and goes on: (a) a passive part whose window ends on the stale flag keeps its open attempt and lands,
// the job finishes; (b) a stop seen in the countdown: the countdown goes on and the chain starts at its time. ALL DATA IS SYNTHETIC: the
// in-memory API and relay, fake chains; nothing listens on a port; virtual time.
import { afterEach, test } from 'node:test'
import assert from 'node:assert/strict'
import { keccak256 } from 'viem'
import { createExecutor } from '../../src/executor/executor.ts'
import { CANON } from '../../src/chains/constants.js'
import { virtualClock } from '../fakes/fake-journal.ts'
import { T0, deps, sendViolations, stack } from './helpers.ts'

afterEach(() => { assert.deepEqual(sendViolations.splice(0), [], 'every ticketed send was exactly its journaled intent') })

const NULL = '0x0000000000000000000000000000000000000000'
const BLOCK_MS = 12_000, MAX_MS = 2 * 3600_000, AFTER = Number(CANON.PASSIVE_ETH_REBROADCAST_BLOCKS)
type S = ReturnType<typeof stack>
const hx = (n: number): string => `0x${n.toString(16)}`
const intents = (s: S) => s.j.events.filter((e) => e.type === 'intent' && e.chain === 'eth')
const stops = (s: S) => s.j.events.filter((e) => e.type === 'stopped')
async function drive(s: S, go: () => Promise<string>): Promise<string | null> {
  let outcome: string | null = null
  const p = go().then((o) => { outcome = o }, (e: Error) => { outcome = `threw ${e.message}` })
  const t0 = s.clock.now()
  while (outcome === null && s.clock.now() - t0 < MAX_MS) await new Promise((r) => setImmediate(r))
  const done = outcome
  if (done === null) { s.j.expire('eth'); await p }
  return done
}

test('m-b (a): `vt job stop` seen at a lease tick, then "Cancel the stop" lifts it right at a passive window\'s end (the stale flag): no `stopped`, the open attempt goes on and lands, the job finishes', { timeout: 120_000 }, async () => {
  for (const how of ['cancelled', 'held'] as const) {
    const clock = virtualClock(T0)
    let id = '', mine = false, windowEndBlock = -1, lifted = false
    const s = stack('eth', { copies: 2, startIn: 0, feeStrategy: 'passive', clock, eth: (m, p, base) => {
      if (m === 'eth_blockNumber') {
        const bn = 100 + Math.floor((clock.now() - T0) / BLOCK_MS)
        // the first read at the window's end: the operator's resume lands now — after the tick that set the flag, before the lane's stop
        if (how === 'cancelled' && windowEndBlock >= 0 && bn >= windowEndBlock && !lifted) { lifted = true; s.j.apiEvent('resume-requested', { chain: 'eth' }, null) }
        if (lifted && bn >= windowEndBlock + 2) mine = true          // later, the nodes take its same bytes (re-sent) and mine them
        return hx(bn)
      }
      if (m === 'eth_sendRawTransaction' && !mine) {
        if (id === '') { id = keccak256(p[0] as `0x${string}`).toLowerCase(); windowEndBlock = 100 + Math.floor((clock.now() - T0) / BLOCK_MS) + AFTER; s.j.requestStop('eth') }
        return keccak256(p[0] as `0x${string}`)                       // taken, not mined (yet)
      }
      if (m === 'eth_getTransactionByHash' && !mine && p[0] === id) return { hash: id, blockNumber: null, nonce: '0x0', to: NULL, value: '0x0', input: '0x' }
      return base(m, p)
    } })
    const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
    const out = await drive(s, () => ex.start())
    if (how === 'cancelled') {
      assert.equal(lifted, true)
      assert.equal(out, 'copies-done', 'the lane went on')
      assert.equal(stops(s).length, 0, 'before m-b: `stopped` operator-stop with no request held — FINAL at the API')
      assert.equal(s.j.events.find((e) => e.type === 'included')!.data.txId, id, 'copy 1\'s open attempt itself landed')
      assert.deepEqual(intents(s).map((e) => [e.data.copy, (e.data.eth as { nonce: number }).nonce]), [[1, 0], [2, 1]], 'no second attempt for copy 1')
    } else {
      assert.equal(out, 'stopped')
      assert.deepEqual(stops(s).map((e) => e.data.code), ['operator-stop'], 'a request still held is journaled as before')
      assert.deepEqual([s.j.state().chains.eth!.stopLatched, s.j.state().chains.eth!.openIntents], [true, [id]])
    }
  }
})

test('m-b (b): `vt job stop` seen at a lease tick during the countdown, then lifted before the run journals it: no `stopped`, the countdown goes on and the chain starts at its time', { timeout: 60_000 }, async () => {
  const s = stack('eth', { copies: 1, startIn: 60_000 })
  let stopAt = -1, ticked = false, lifted = false
  const lease = s.j.client.lease.bind(s.j.client)
  ;(s.j.client as { lease: typeof lease }).lease = async (...a: Parameters<typeof lease>) => { const g = await lease(...a); if (stopAt >= 0 && a[2] === 'renew') ticked = true; return g }   // its onTick re-reads the stop: the flag
  const status = s.relay.client.status.bind(s.relay.client)
  ;(s.relay.client as { status: () => Promise<unknown> }).status = async () => status()
  const rpc = s.relay.client.rpc.bind(s.relay.client)
  ;(s.relay.client as { rpc: typeof rpc }).rpc = async (...a: Parameters<typeof rpc>) => {
    if (ticked && !lifted) { lifted = true; s.j.apiEvent('resume-requested', { chain: 'eth' }, null) }   // the next countdown round's simulation: lifted, the flag stale
    return rpc(...a)
  }
  const ex = createExecutor({ jobId: s.j.id, chain: 'eth', key: s.key, holder: 'cli', deps: deps(s) })
  const p = ex.start()
  while (ex.view().phase !== 'countdown') await s.clock.sleep(500)
  stopAt = s.clock.now(); s.j.requestStop('eth')
  assert.equal(await p, 'copies-done', 'before m-b: the countdown journaled operator-stop with no request held (FINAL at the API) and ended stopped')
  assert.equal(lifted, true)
  assert.equal(stops(s).length, 0)
  assert.deepEqual(intents(s).map((e) => e.data.copy), [1])
})

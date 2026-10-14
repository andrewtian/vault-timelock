// engine/assess.js — the pre-start check moved out of MainnetView.jsx (spec §7.2): a local pre-check before Arm, a
// real-byte simulation after; isFresh (15 s, this message, this config); the Tor gate by network; startCheck. Plus the
// static rules of the port: no `location.` in packages/core/src, no onEvent calls left, every send-type RPC behind the
// ticket gate. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { assessChain, FRESH_MS, isFresh, startCheck, torGate } from '../../src/engine/assess.js'
import { ethParts, utf8 } from '../../src/chains/plan.js'
import { fakeEthChain, fakeRelay } from './fakes.ts'

const SHA = 'c'.repeat(64)
const sim = (o: Record<string, unknown> = {}) => ({ kind: 'sim' as const, ok: true, reason: '', at: 1_000, cost: '', msSha: SHA, cfg: 'k', ...o })

test('isFresh: a real simulation of this message and config, younger than 15 s', () => {
  assert.equal(FRESH_MS, 15_000)
  assert.equal(isFresh(sim(), SHA, 'k', 1_000 + 14_999), true)
  assert.equal(isFresh(sim(), SHA, 'k', 1_000 + 15_000), false, 'stale')
  assert.equal(isFresh(sim({ kind: 'precheck' }), SHA, 'k', 1_001), false, 'a local pre-check is not a simulation')
  assert.equal(isFresh(sim(), 'd'.repeat(64), 'k', 1_001), false, 'another message')
  assert.equal(isFresh(sim(), SHA, 'other', 1_001), false, 'another config')
  assert.equal(isFresh(sim(), SHA, 'k', 999), false, 'from the future')
  assert.equal(isFresh(null, SHA, 'k', 1_001), false)
})

test('torGate: local needs no Tor; testnet and mainnet need IsTor ✓ (unknown fails closed)', () => {
  assert.equal(torGate(null, 'local').ok, true)
  for (const network of ['testnet', 'mainnet']) {
    assert.equal(torGate({ isTor: true }, network).ok, true)
    assert.match(torGate({ isTor: false }, network).why, /not reaching the network through Tor/)
    assert.match(torGate({ isTor: null }, network).why, /unknown/)
    assert.equal(torGate(null, network).ok, false)
  }
})

test('startCheck: Tor, relay identity and a fresh passing simulation, or the chain is skipped (fail closed)', async () => {
  const relay = (isTor: boolean | null, ok: boolean) => ({ tor: async () => ({ isTor }), status: async () => ({ identity: { eth: { ok, ...(ok ? {} : { message: 'Amsterdam appears active on mainnet — update required' }) } } }) })
  const o = (r: ReturnType<typeof relay>, now = 2_000) => ({ msSha: SHA, cfgKey: 'k', network: 'mainnet', relay: r, now })
  assert.deepEqual(await startCheck('eth', sim(), o(relay(true, true))), { ok: true, why: '' })
  assert.match((await startCheck('eth', sim(), o(relay(false, true)))).why, /Tor/)
  assert.match((await startCheck('eth', sim(), o(relay(true, false)))).why, /identity not OK.*Amsterdam appears active/)
  assert.match((await startCheck('eth', sim({ ok: false, reason: 'balance' }), o(relay(true, true)))).why, /failed \(balance\)/)
  assert.match((await startCheck('eth', sim(), o(relay(true, true), 99_000))).why, /stale/)
  assert.match((await startCheck('eth', null, o(relay(true, true)))).why, /missing/)
  const down = { tor: async () => { throw new Error('down') }, status: async () => { throw new Error('down') } }
  assert.equal((await startCheck('eth', sim(), o(down as never))).ok, false)
})

test('assessChain: a local pre-check before Arm (no calldata sent), a real simulation after; never throws', async () => {
  const chain = fakeEthChain(), relay = fakeRelay({ eth: chain.handler })
  const address = privateKeyToAccount(generatePrivateKey()).address
  const parts = ethParts(utf8('hello'))
  const base = { network: 'local', address, recipient: 'null' as const, gasRule: { amsterdam: false, toSelf: false }, strategy: 'prompt' as const, tipCap: 3n * 10n ** 9n, msSha: SHA, cfgKey: 'k', now: () => 5 }
  const pre = await assessChain('eth', parts, { ...base, real: false })
  assert.equal(pre.kind, 'precheck'); assert.equal(pre.ok, true); assert.equal(pre.msSha, SHA); assert.equal(pre.cfg, 'k'); assert.equal(pre.at, 5)
  assert.ok(!relay.calls.some((c) => c.method === 'eth_estimateGas' || c.method === 'eth_call'), 'I7: no text-bearing call before Arm')
  const real = await assessChain('eth', parts, { ...base, real: true })
  assert.equal(real.kind, 'sim'); assert.equal(real.ok, true, String(real.reason))
  assert.ok(relay.calls.some((c) => c.method === 'eth_estimateGas'))
  const noRule = await assessChain('eth', parts, { ...base, real: true, gasRule: undefined })
  assert.equal(noRule.ok, false); assert.match(noRule.reason, /fail closed/)
  const none = await assessChain('eth', [], { ...base, real: true })
  assert.equal(none.ok, false)
})

// ---- static rules of the port ----
const SRC = fileURLToPath(new URL('../../src/', import.meta.url))
const walk = (d: string): string[] => readdirSync(d).flatMap((n) => { const p = join(d, n); return statSync(p).isDirectory() ? walk(p) : [p] })
const sources = walk(SRC).filter((p) => /\.(?:js|ts)$/.test(p))

test('static: no `location.` in packages/core/src (profile values are injected), no onEvent calls left', () => {
  for (const p of sources) {
    const s = readFileSync(p, 'utf8')
    assert.ok(!/\blocation\./.test(s), `${p}: location.`)
    assert.ok(!/onEvent\s*\?\.\s*\(|\.onEvent\s*\(/.test(s), `${p}: an onEvent call (spec §7.2: journal.append)`)
  }
})

test('static: every send-type RPC line in the chain modules passes the ticket gate first', () => {
  for (const f of ['chains/eth.js', 'chains/sol.js']) {
    const lines = readFileSync(join(SRC, f), 'utf8').split('\n').filter((l) => /eth_sendRawTransaction|'sendTransaction'/.test(l) && !l.trim().startsWith('//'))
    assert.ok(lines.length >= 1, f)
    for (const l of lines) assert.match(l, /assertTicketedSend\(ticket\);.*\{ ticket(, ep)? \}/, `${f}: ${l.slice(0, 60)}`)   // E5: a SOL send names its endpoint too
  }
})

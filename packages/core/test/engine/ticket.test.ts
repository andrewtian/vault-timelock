// spec §7.2 "ticket carried": every send-type RPC carries the relay send ticket in x-vt-send-ticket, byte for byte; a send
// without a well-formed ticket is refused before anything leaves (engine.no-ticket, gates/send.ts). Reads carry none.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { TICKET_HEADER, TICKET_PREFIX } from '../../src/contracts/index.ts'
import { assertTicketedSend } from '../../src/gates/send.ts'
import * as eth from '../../src/chains/eth.js'
import * as sol from '../../src/chains/sol.js'
import { rpc } from '../../src/engine/rpc.js'
import { guardOf } from '../job/helpers.ts'
import { fakeRelay, ticketFor } from './fakes.ts'

const RAW_ETH = '0x02f86a827a6980843b9aca00847735940082520894000000000000000000000000000000000000000080846461746180c0'
const RAW_SOL = 'AQ=='

test('the header name is the contract\'s', () => assert.equal(TICKET_HEADER, 'x-vt-send-ticket'))

test('eth.send carries the exact ticket in x-vt-send-ticket; reads carry none', async () => {
  const relay = fakeRelay({ eth: (m) => (m === 'eth_sendRawTransaction' ? `0x${'1'.repeat(64)}` : '0x1') })
  const ticket = ticketFor('eth')
  await eth.send(RAW_ETH, ticket)
  await eth.blockNumber()
  assert.deepEqual(relay.calls.map((c) => [c.method, c.ticket]), [['eth_sendRawTransaction', ticket], ['eth_blockNumber', null]])
  assert.deepEqual(relay.calls[0].params, [RAW_ETH])
})

test('sol.send and sol.rebroadcast carry the exact ticket', async () => {
  const relay = fakeRelay({ sol: () => '5'.repeat(88) })
  const ticket = ticketFor('sol')
  await sol.send(RAW_SOL, 123, ticket)
  await sol.rebroadcast(RAW_SOL, ticket)
  assert.deepEqual(relay.calls.map((c) => [c.method, c.ticket, c.ep]), [['sendTransaction', ticket, null], ['sendTransaction', ticket, null]])
  assert.deepEqual((relay.calls[1].params[1] as Record<string, unknown>).skipPreflight, true)
})

test('a send without a ticket throws engine.no-ticket and nothing reaches the relay', async () => {
  const relay = fakeRelay({ eth: () => '0x1', sol: () => 'x' })
  for (const send of [() => eth.send(RAW_ETH, undefined), () => sol.send(RAW_SOL, 1, undefined), () => sol.rebroadcast(RAW_SOL, undefined)]) {
    assert.equal(guardOf(send), 'engine.no-ticket')
  }
  assert.equal(guardOf(() => (eth.send as (raw: string) => unknown)(RAW_ETH)), 'engine.no-ticket', 'eth.send(raw) with no second argument')
  assert.equal(relay.calls.length, 0)
})

test('a malformed ticket is refused too (prefix, MAC length, header-unsafe characters)', () => {
  const good = ticketFor('x')
  assert.equal(guardOf(() => assertTicketedSend(good)), null)
  const otherVersion = TICKET_PREFIX.replace(/\/(\d+)\.$/, (_m, v: string) => `/${Number(v) + 1}.`)   // e.g. vt-ticket/2. → vt-ticket/3.
  assert.notEqual(otherVersion, TICKET_PREFIX)
  for (const bad of ['', TICKET_PREFIX, `${otherVersion}abc.${'A'.repeat(43)}`, good.slice(0, -1), `${good}\r\nx-other: 1`, good.replace(TICKET_PREFIX, `${TICKET_PREFIX}a b`), good + '=']) {
    assert.equal(guardOf(() => assertTicketedSend(bad)), 'engine.no-ticket', JSON.stringify(bad.slice(0, 20)))
  }
})

test('rpc routes one endpoint with { ep } and refuses odd chains or endpoint indexes', async () => {
  const relay = fakeRelay({ sol: (_m, _p, ep) => ({ ep }) })
  assert.deepEqual(await rpc('sol', 'getLatestBlockhash', [], { ep: 1 }), { ep: '1' })
  assert.equal(relay.calls[0].ep, '1')
  await assert.rejects(rpc('sol/ep/1', 'x', []), TypeError)
  await assert.rejects(rpc('sol', 'x', [], { ep: -1 }), TypeError)
  await assert.rejects(rpc('sol', 'x', [], { ep: 1.5 }), TypeError)
})

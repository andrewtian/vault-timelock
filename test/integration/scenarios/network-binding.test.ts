// E4 scenario network-binding (M1; Review Focus 4): a job or a ticket from another network never reaches a local chain.
//   · a testnet (or mainnet) job posted to the LOCAL API → job.network, nothing stored;
//   · a send ticket bound to testnet, MAC-valid under this stack's own ticket key, for a genuine signed local tx, at the
//     LOCAL relay → 403 relay.ticket-network: nothing forwarded (the nonce stays 0, the tx is not in the pool);
//   · the control: the same bytes with the ticket bound to local are forwarded (the refusal was the network binding).
// Through S2's REAL API and S4's REAL relay on the harness's own anvil. OWN SANDBOX. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { PORTS, TICKET_HEADER } from '../../../packages/core/src/contracts/index.ts'
import * as eth from '../../../packages/core/src/chains/eth.js'
import { issueTicket } from '../../../api/src/tickets.ts'
import { TICKET_KEY } from '../../../api/test/helpers.ts'
import { startAnvil, fundEth, ethNonce, rpcResult, sha256 } from '../harness/chains.ts'
import { apiCall, evidence, nodeShim, startStack } from '../harness/stack.ts'
import { keyOf, lifecycle, ms, scratch, syntheticText } from '../harness/kit.ts'

const T = lifecycle()

test('network-binding: a testnet job at the local API → job.network; a testnet ticket at the local relay → relay.ticket-network, nothing forwarded', { timeout: 300_000 }, async () => {
  const t0 = Date.now()
  const anvil = await startAnvil(T, { home: scratch(T), blockTime: 1, baseFee: 7n })
  const s = await startStack(T, { network: 'local', ethRpc: anvil.url, solRpc: null })
  const key = keyOf('eth')
  await fundEth(anvil.port, key.address, 10n ** 17n)
  const text = syntheticText(300, 'E4 network binding')
  const input = (network: string) => ({ format: 'vt-job/1', network, name: `E4 ${network} job`, message: text,
    chains: { eth: { mode: { copies: 1 }, publishMode: 'eth.calldata.null', feeStrategy: 'economy', distinctCopies: true, keyAddress: key.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: null } } })
  const refused: Record<string, string> = {}
  for (const network of ['testnet', 'mainnet']) {
    const r = await apiCall(s, 'POST', '/jobs', input(network))
    assert.ok(r.status >= 400 && r.status < 500, `${network}: ${r.status}`)
    assert.equal(r.json?.error?.guard, 'job.network', `${network}: ${r.text}`)
    refused[network] = `${r.status} ${r.json.error.guard}`
  }
  const list = await apiCall(s, 'GET', '/jobs')
  assert.equal(list.status, 200)
  assert.deepEqual(list.json.jobs, [], 'nothing was stored')

  // a genuine signed local tx, and tickets MAC-valid under this stack's own key but bound elsewhere
  const NULL = '0x0000000000000000000000000000000000000000'
  const payload = new TextEncoder().encode('data:,e4 network binding')
  const signed = await eth.sign(key.account as never, 31337, { nonce: 0, to: NULL, data: `0x${Buffer.from(payload).toString('hex')}`, gas: 60_000n, maxFee: 2_000_000_000n, tip: 1_000_000n })
  const bind = { j: 'aaaaaaaaaaaaaaaa', g: 1, t: String(signed.id).toLowerCase(), r: sha256(Buffer.from(String(signed.raw).slice(2), 'hex')), a: key.address.toLowerCase(), k: 'job' as const,
    p: sha256(payload), to: NULL, value: null, f: String(60_000n * 2_000_000_000n), q: '0', x: '60000:1000000:2000000000' }   // PF-S I-1: an ETH job ticket names its recipient; fix round 2: and its fee members
  const send = async (ticket: string) => {
    const f = nodeShim(s.ports)
    const r = await f(`http://127.0.0.1:${PORTS.local.relay}/relay/eth`, { method: 'POST', headers: { 'content-type': 'application/json', [TICKET_HEADER]: ticket },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_sendRawTransaction', params: [signed.raw] }) })
    return { status: r.status, json: await r.json() as any }
  }
  const wrongNet = await send(issueTicket(TICKET_KEY, { ...bind, w: 'testnet', c: 'eth' }, Date.now()))
  assert.equal(wrongNet.status, 403)
  assert.equal(wrongNet.json?.error?.data?.guard, 'relay.ticket-network', JSON.stringify(wrongNet.json))
  await new Promise((r) => setTimeout(r, 2_500))                    // two blocks: anything forwarded would be mined
  assert.equal(await ethNonce(anvil.port, key.address), 0, 'nothing from the key reached the chain')
  assert.equal(await rpcResult(anvil.port, 'eth_getTransactionByHash', [signed.id]), null, 'the tx is not in the pool or a block')
  // the control: the SAME bytes with the same ticket bound to local are forwarded and land (the refusal was the network)
  const right = await send(issueTicket(TICKET_KEY, { ...bind, w: 'local', c: 'eth' }, Date.now()))
  assert.equal(right.status, 200, JSON.stringify(right.json))
  evidence('network-binding', 'refusals', { ...refused, testnetTicketAtLocalRelay: `${wrongNet.status} ${wrongNet.json.error.data.guard}`, localTicketSameBytes: `${right.status} ${String(right.json.result).slice(0, 12)}…`, totalMs: ms(t0) })
})

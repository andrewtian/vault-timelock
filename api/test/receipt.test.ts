// GET /jobs/:id/receipt (receipt.ts, spec §5.7): `vt-receipt/1` from reduce + links.js, the contract Receipt shape
// exactly; no message text, no URL scheme (links are copy-only text, mainnet only), no endpoint, no canary.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { JobDef, JournalEvent, Network, Receipt } from '@vault-timelock/core/contracts'
import { jobId } from '@vault-timelock/core/job'
import { CANARY, FIXTURES, JOB, JOB_INPUT, armed, call, ethIntent, ethTx, fixture, startApi, writeJob } from './helpers.ts'
import type { TestApi } from './helpers.ts'

process.env.NODE_ENV = 'test'

const RECEIPT_KEYS = ['build', 'chains', 'format', 'jobId', 'messageSha256', 'name', 'network']
const CHAIN_KEYS = ['address', 'clawback', 'copiesIncluded', 'mode', 'network', 'phase', 'reassembled', 'spent', 'txs']
const TX_KEYS = ['attempts', 'block', 'copy', 'fee', 'links', 'part', 'readback', 'txId']

function scan(text: string, message: string): void {
  assert.ok(!/http/i.test(text), 'the receipt holds "http"')
  assert.ok(!text.includes(CANARY), 'the receipt holds the canary')
  assert.ok(!text.includes('127.0.0.1') && !text.includes('localhost'), 'the receipt holds an endpoint')
  assert.ok(!text.includes(message), 'the receipt holds the message text')
  for (const line of message.split('\n').filter((l) => l.length >= 8)) assert.ok(!text.includes(line), 'the receipt holds a line of the message')
}
function shape(r: Receipt): void {
  assert.deepEqual(Object.keys(r).sort(), RECEIPT_KEYS)
  for (const c of Object.values(r.chains)) {
    assert.deepEqual(Object.keys(c!).sort(), CHAIN_KEYS)
    for (const tx of c!.txs) {
      assert.deepEqual(Object.keys(tx).sort(), TX_KEYS)
      for (const l of tx.links) assert.deepEqual(Object.keys(l).sort(), ['copyOnly', 'href', 'label'])
    }
  }
}
// A contract journal vector's events in a job of `network` (its def with that network), as an API would have written.
async function installAs(a: TestApi, name: string, network: Network): Promise<{ id: string; def: JobDef }> {
  const def = { ...fixture<JobDef>(`journals/${name}.def.json`), network }
  const lines = readFileSync(join(FIXTURES, 'journals', `${name}.jsonl`), 'utf8')
  const events = lines.split('\n').filter((l) => l !== '').map((l) => JSON.parse(l) as JournalEvent).filter((e) => e.type !== 'created')
  const id = await writeJob(a.state, def, events)
  assert.equal(id, jobId(def))
  return { id, def }
}

test('local: a landed copy → the contract shape; no links (loopback explorers are endpoints); no message text, no http, no canary', async (t) => {
  const a = await startApi()
  t.after(() => a.close())
  await armed(a, JOB, ['eth'])
  await call(a.port, { path: `/jobs/${JOB}/chains/eth/lease`, body: { op: 'acquire', holder: 'browser' } })
  for (const [type, data] of [
    ['intent', ethIntent(1)], ['sent', { txId: ethTx(1), outcome: 'accepted', reason: null }],
    ['included', { txId: ethTx(1), copy: 1, part: 1, attempt: 1, block: '101', fee: '25000300000000', ms: 9 }],
    ['readback', { txId: ethTx(1), ok: true, detail: 'byte-equal' }],
    ['reassembled', { copy: 1, ok: true, sha256: '83be1d5879a59ca063ed2d02bcfde19e259cd991479d5ef45c899854f6900048' }],
    ['intent', ethIntent(2, 2)], ['drained', { balance: '1', nextCost: '2', copy: 2 }],
  ] as const) await call(a.port, { path: `/jobs/${JOB}/chains/eth/events`, body: { gen: 1, type, data } })
  const r = await call(a.port, { path: `/jobs/${JOB}/receipt` })
  assert.equal(r.status, 200)
  assert.equal(r.headers['content-type'], 'application/json; charset=utf-8')
  const receipt = r.json as Receipt
  shape(receipt)
  assert.deepEqual(receipt, {
    format: 'vt-receipt/1', jobId: JOB, name: JOB_INPUT.name, network: 'local',
    messageSha256: '83be1d5879a59ca063ed2d02bcfde19e259cd991479d5ef45c899854f6900048', build: 'test',
    chains: { eth: {
      address: '0x8739Eb87B3d11f221Df63454F8D229a1A4F4049C', network: 'anvil · 31337', mode: 'drain', phase: 'DRAINED', copiesIncluded: 1,
      reassembled: [{ copy: 1, ok: true }], spent: '25000300000000', clawback: null,
      txs: [{ copy: 1, part: 1, txId: ethTx(1), attempts: 1, block: '101', fee: '25000300000000', readback: true, links: [] }],
    } },
  })
  scan(r.text, JOB_INPUT.message as string)
  assert.equal((await call(a.port, { path: `/jobs/${JOB}/receipt` })).text, r.text) // the same bytes every time
})

test('mainnet: copy-only explorer links without a URL scheme; the landed claw-back; still no http', async (t) => {
  const a = await startApi({ network: 'mainnet', jobs: [] })
  t.after(() => a.close())
  const { id } = await installAs(a, '12-clawback', 'mainnet')
  const r = await call(a.port, { path: `/jobs/${id}/receipt`, network: 'mainnet' })
  assert.equal(r.status, 200, r.text)
  const receipt = r.json as Receipt
  shape(receipt)
  const eth = receipt.chains.eth!
  assert.deepEqual([receipt.network, eth.network, eth.phase], ['mainnet', 'Ethereum mainnet · 1', 'CLAWED_BACK'])
  assert.deepEqual(eth.clawback, { txId: '0x3d981fa6ba2b4c4c4fcda58588440d060bcba13d8a4de6091b66c9838c5ef1f0', to: '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6', value: '1179000000000' })
  assert.ok(eth.txs.length >= 1)
  for (const tx of eth.txs) {
    assert.ok(tx.links.length >= 2)
    for (const l of tx.links) {
      assert.equal(l.copyOnly, true)
      assert.match(l.href, /^etherscan\.io\/(?:tx|address)\/0x[0-9a-fA-F]+$/)
    }
    assert.ok(tx.links.some((l) => l.href === `etherscan.io/tx/${tx.txId}`))
  }
  scan(r.text, 'A synthetic vt fixture message.')
})

test('testnet: no links until links.js serves testnet (never mainnet links for a testnet tx)', async (t) => {
  const a = await startApi({ network: 'testnet', jobs: [] })
  t.after(() => a.close())
  const { id } = await installAs(a, '05a-copies-done', 'testnet')
  const receipt = (await call(a.port, { path: `/jobs/${id}/receipt`, network: 'testnet' })).json as Receipt
  shape(receipt)
  assert.deepEqual([receipt.chains.eth!.network, receipt.chains.eth!.phase], ['Sepolia · 11155111', 'COPIES_DONE'])
  assert.ok(receipt.chains.eth!.txs.length >= 1)
  assert.ok(receipt.chains.eth!.txs.every((tx) => tx.links.length === 0))
})

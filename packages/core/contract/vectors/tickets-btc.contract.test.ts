// CC-8 (BTC tickets): the tickets-btc.json vectors are self-consistent and every valid raw is a GENUINE signed transaction.
// Like tickets.contract.test.ts this pins the generator, independently of any relay: each ticket's MAC holds under the
// fixture key and the v2 prefix, the payload keys are in the contract order, r = sha256(raw), t = the tx's txid, the btc
// field formats of src/contracts/http.ts hold for every valid payload, and each valid tx matches its own binding (inputs
// = q, the output to `to`, the change to `a`, fee <= f from the context's prevouts, the reveal's inscription). The decode
// vectors' defects are judged by the relay's own tests (api/test/decode-btc.test.ts); here only their tickets are checked.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, createHmac } from 'node:crypto'
import { base64urlnopad } from '@scure/base'
import * as btc from '@scure/btc-signer'
import { OutOrdinalReveal, parseWitness } from 'micro-ordinals'
import { TICKET_PREFIX } from '../../src/contracts/index.ts'
import type { TicketPayload } from '../../src/contracts/index.ts'
import { readJson } from './job-module.ts'

type Prevouts = Record<string, { value: string; script: string }>
interface Raw { encoding: 'hex'; value: string }
interface Vector { name: string; ticket: string; now: number; context: { network: string; chain: string; raw: Raw; prevouts: Prevouts }; guard?: string }
interface Valid extends Vector { payload: TicketPayload; issuedAt: number; raw: Raw }
const V = readJson<{ format: string; key: string; lane: Record<string, string>; fee: Record<string, string>; valid: Valid[]; negatives: Vector[]; decode: Vector[] }>('tickets-btc.json')
const KEY = Buffer.from(V.key, 'hex')
const ORDER = 'j,w,c,g,t,r,a,k,p,to,value,f,q,x,e,n'   // PF-S fix round 2: x, the declared fee members
const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex')
const HRP: Record<string, string> = { local: 'bcrt', testnet: 'tb', mainnet: 'bc' }
const NETS: Record<string, typeof btc.NETWORK> = { local: { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef }, testnet: btc.TEST_NETWORK, mainnet: btc.NETWORK }
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex')
const BECH32 = /^(?:bcrt|tb|bc)1[02-9ac-hj-np-z]{11,87}$/
const OUTPOINT = /^[0-9a-f]{64}:(?:0|[1-9][0-9]{0,9})$/

function open(ticket: string): Record<string, unknown> {
  assert.ok(ticket.startsWith(TICKET_PREFIX))
  const [body, mac] = ticket.slice(TICKET_PREFIX.length).split('.')
  assert.equal(base64urlnopad.encode(createHmac('sha256', KEY).update(`${TICKET_PREFIX}${body}`).digest()), mac)
  return JSON.parse(new TextDecoder().decode(base64urlnopad.decode(body))) as Record<string, unknown>
}

test('format: every btc ticket is MAC\'d under the v2 prefix with the contract key order; r = sha256(raw); the vector kinds', () => {
  assert.equal(V.format, 'vt-ticket/2.')
  assert.ok(V.valid.length >= 6 && V.negatives.length >= 20 && V.decode.length >= 40)
  for (const v of [...V.valid, ...V.decode]) {
    const p = open(v.ticket)
    assert.equal(Object.keys(p).join(','), ORDER, v.name)
    assert.equal(p.c, 'btc', v.name)
    assert.equal(p.w, v.context.network, v.name)
    assert.equal(p.r, sha(Buffer.from(v.context.raw.value, 'hex')), v.name)
    assert.ok(v.now < (p.e as number), v.name)
  }
  for (const v of V.negatives) { assert.equal(v.guard, 'relay.send-ticket', v.name); assert.ok(Object.keys(open(v.ticket)).length > 0, v.name) }
  for (const v of V.decode) assert.ok(v.guard === 'relay.decode-mismatch' || v.guard === 'relay.btc-prevout', v.name)
  for (const v of V.valid) assert.deepEqual(open(v.ticket), v.payload, v.name)
  assert.deepEqual(new Set(V.valid.map((v) => `${v.payload.w} ${v.payload.k}`)), new Set(['local commit', 'local reveal', 'testnet commit', 'testnet reveal', 'mainnet commit']))
})

test('the btc field formats of http.ts hold for every valid payload', () => {
  for (const { payload: p, name } of V.valid) {
    assert.match(p.t, /^[0-9a-f]{64}$/, name)
    assert.match(p.p ?? '', /^[0-9a-f]{64}$/, name)
    assert.ok(p.k === 'commit' || p.k === 'reveal', name)
    assert.match(p.a, BECH32, name); assert.ok(p.a.startsWith(`${HRP[p.w]}1`), name)
    assert.match(p.to ?? '', BECH32, name); assert.ok((p.to ?? '').startsWith(`${HRP[p.w]}1`), name)
    assert.match(p.value ?? '', /^[1-9][0-9]{0,77}$/, name)
    assert.match(p.f, /^[1-9][0-9]{0,77}$/, name)
    const q = p.q.split(',')
    assert.ok(q.length >= 1 && q.length <= 8 && q.every((x) => OUTPOINT.test(x)), name)
    assert.deepEqual(q, [...q].sort(), name); assert.equal(new Set(q).size, q.length, name)
    if (p.k === 'reveal') assert.equal(q.length, 1, name)
    if (p.k === 'commit') assert.equal(btc.Address(NETS[p.w]).decode(p.to!).type, 'tr', name)
  }
  assert.equal(V.lane.local, V.valid[0].payload.a); assert.equal(V.lane.testnet, V.valid[2].payload.a)
})

test('the valid raws are genuine: txid t, inputs = q, the output to `to`, the change to `a`, fee <= f from the prevouts, the reveal envelope', () => {
  for (const v of V.valid) {
    const p = v.payload, net = NETS[p.w]
    const tx = btc.Transaction.fromRaw(Buffer.from(v.raw.value, 'hex'), { customScripts: [OutOrdinalReveal] })
    assert.equal(tx.id, p.t, v.name)
    assert.equal(hex(tx.toBytes(true, true)), v.raw.value, v.name)                                            // canonical
    assert.equal(tx.lockTime, 0, v.name)
    const ins = Array.from({ length: tx.inputsLength }, (_, i) => `${tx.getInput(i).txid ? hex(tx.getInput(i).txid!) : ''}:${tx.getInput(i).index}`)
    assert.deepEqual([...ins].sort(), p.q.split(','), v.name)
    const outs = Array.from({ length: tx.outputsLength }, (_, i) => tx.getOutput(i))
    const to = btc.OutScript.encode(btc.Address(net).decode(p.to!))
    const toOuts = outs.filter((o) => hex(o.script!) === hex(to))
    assert.equal(toOuts.length, 1, v.name); assert.equal(String(toOuts[0].amount), p.value, v.name)
    const sumIn = ins.reduce((a, o) => a + BigInt(v.context.prevouts[o].value), 0n)
    const sumOut = outs.reduce((a, o) => a + (o.amount ?? 0n), 0n)
    assert.ok(sumIn - sumOut >= 0n && sumIn - sumOut <= BigInt(p.f), v.name)
    for (const o of ins) assert.ok(v.context.prevouts[o], v.name)
    if (p.k === 'commit') {
      const lane = btc.OutScript.encode(btc.Address(net).decode(p.a))
      for (const o of ins) assert.equal(v.context.prevouts[o].script, hex(lane), v.name)
      for (const o of outs) assert.ok(hex(o.script!) === hex(to) || hex(o.script!) === hex(lane), v.name)
    } else {
      assert.equal(tx.inputsLength, 1, v.name); assert.equal(tx.outputsLength, 1, v.name)
      const found = parseWitness(tx.getInput(0).finalScriptWitness!)
      assert.equal(found?.length, 1, v.name)
      assert.equal(found![0].cursed, false, v.name)
      assert.deepEqual(Object.keys(found![0].tags), ['contentType'], v.name)
      assert.equal(found![0].tags.contentType, 'text/plain;charset=utf-8', v.name)
      assert.equal(sha(found![0].body), p.p, v.name)
    }
  }
})

test('a reveal vector spends exactly the output of the commit vector of its network', () => {
  const commit = V.valid.find((v) => v.name.startsWith('testnet commit'))!, reveal = V.valid.find((v) => v.name.startsWith('testnet reveal'))!
  assert.equal(reveal.payload.q, `${commit.payload.t}:0`)
  const c = V.valid.find((v) => v.name.startsWith('local commit:'))!, r = V.valid.find((v) => v.name.startsWith('local reveal'))!
  assert.equal(r.payload.q, `${c.payload.t}:0`)
  assert.equal(commit.payload.value, V.fee.revealAmount)
})

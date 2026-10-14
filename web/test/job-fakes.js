// Test wiring for the job page (W3): a synthetic same-origin stack behind a mocked fetch — the jobs API (/api/*: status,
// the job with its state folded by core's reduce, the journal as SSE, leases, arm/stop/resume/skip) and the relay
// (/relay/status, /relay/tor, /relay/price). Everything is made up in the test; no network, no chain.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { normalizeJob, reduce, sha256Hex } from '@vault-timelock/core/job'
import { json, relayOf, statusOf } from './helpers.jsx'

const FIX = join(import.meta.dirname, '../../packages/core/contract/fixtures/journals')
export function fixture(name) {
  const def = JSON.parse(readFileSync(join(FIX, `${name}.def.json`), 'utf8'))
  const events = readFileSync(join(FIX, `${name}.jsonl`), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
  return { def, events, id: events[0].data.jobId }
}

export const TEXT = 'a short synthetic line for the job page tests\n'
// A NEW mainnet job names a claw-back address on each eth / sol chain (PF-S fix round 1, N-6: job.clawback-required; M5 glue): a chain
// without one gets a synthetic address here (the same ones core's executor helpers use); one a test sets is kept.
const MAINNET_CLAWBACK = { eth: '0x54fe0FE5d347410E7AfDc3428aD92A2F2A7F7Bf6', sol: 'G147qVmzynHL3EjQ8tvBGDms7u6FDCWbFfFmzNMZmg1x' }
export function jobDef({ network = 'local', chains }) {
  const named = network !== 'mainnet' ? chains : Object.fromEntries(Object.entries(chains).map(([c, d]) =>
    [c, c in MAINNET_CLAWBACK && (d.clawbackTo === null || d.clawbackTo === undefined) ? { ...d, clawbackTo: MAINNET_CLAWBACK[c] } : d]))
  const input = { format: 'vt-job/1', network, name: 'w3 test job', messageSha256: sha256Hex(TEXT), messageBytes: new TextEncoder().encode(TEXT).length, chains: named }
  return normalizeJob(input, { network }).def
}
export const ethChain = (keyAddress, over = {}) => ({ mode: 'drain', keyAddress, budgetUsd: 5, distinctCopies: false, clawbackTo: null, ...over })
export const solChain = (keyAddress, over = {}) => ({ mode: { copies: 2 }, keyAddress, budgetUsd: 5, distinctCopies: false, clawbackTo: null, ...over })

// journal lines with consecutive seqs (prev hashes are not checked by the reducer)
export function journal(lines, t0 = 1_800_000_000_000) {
  return lines.map((l, i) => ({ v: 1, seq: i, at: l.at ?? t0 + i * 1000, prev: '', chain: l.chain ?? null, by: l.by ?? 'api', gen: l.gen ?? null, type: l.type, data: l.data ?? {} }))
}
export const created = (jobId = '0123456789abcdef') => ({ type: 'created', data: { jobId, defSha256: 'a'.repeat(64) } })
export const ready = (chain, address, gen = 1) => [
  { chain, type: 'lease-acquired', gen, data: { gen, holder: 'browser', ttlMs: 15000 } },
  { chain, by: 'browser', gen, type: 'key-loaded', data: { address } },
  { chain, by: 'browser', gen, type: 'funds', data: { balance: '50000000000000000', affordable: true, nextCopyCost: '1000' } },
]

// An SSE body that delivers `events` and stays open until the client aborts.
export function sseResponse(events, signal) {
  const enc = new TextEncoder()
  let ctl
  const body = new ReadableStream({
    start(c) {
      ctl = c
      for (const e of events) c.enqueue(enc.encode(`id: ${e.seq}\ndata: ${JSON.stringify(e)}\n\n`))
      signal?.addEventListener('abort', () => { try { c.close() } catch { /* closed */ } })
    },
  })
  const res = new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream; charset=utf-8' } })
  return { res, push: (e) => ctl.enqueue(enc.encode(`id: ${e.seq}\ndata: ${JSON.stringify(e)}\n\n`)) }
}

// fakeStack({ id, def, events, network, leases, serverNow, routes }) → { fetch, calls, s }
//   s.events / s.leases / s.serverNow can be changed by the test; routes[`${METHOD} ${path}`] overrides a route
//   (return a Response or a Promise of one).
export function fakeStack({ id, def, events = [], network = def.network, leases = {}, serverNow = () => Date.now(), routes = {}, tor = true, messages = { [sha256Hex(TEXT)]: TEXT } }) {
  const s = { events, leases, serverNow, streams: [] }
  const calls = []
  const fetch = async (url, init = {}) => {
    const u = String(url), method = (init.method || 'GET').toUpperCase()
    const body = init.body ? JSON.parse(init.body) : undefined
    calls.push({ method, url: u, body })
    const key = `${method} ${u.replace(/\?.*$/, '')}`
    if (routes[key]) return routes[key]({ url: u, body, init, s })
    if (u === '/api/status') return json(200, statusOf(network))
    if (u === '/relay/status') return json(200, relayOf(network))
    if (u === '/relay/tor') return json(200, { isTor: tor, roles: {}, checkedAt: Date.now() })
    if (u === '/relay/price') return json(200, { prices: { SOL: { usd: 150 }, ETH: { usd: 3000 } }, fetchedAt: Date.now(), source: 'local fixture', fixture: true })
    if (u.startsWith('/api/messages/') && method === 'GET') {
      const text = messages[u.slice('/api/messages/'.length)]
      return text === undefined ? json(404, { error: { guard: 'message.missing', message: 'no such message' } }) : new Response(text, { status: 200, headers: { 'content-type': 'text/plain; charset=utf-8' } })
    }
    if (u === `/api/jobs/${id}` && method === 'GET') {
      const state = reduce(def, s.events)
      return json(200, { id, def, state, leases: s.leases, seq: state.seq, serverNowMs: s.serverNow() })
    }
    if (u.startsWith(`/api/jobs/${id}/events`)) {
      const from = Number(new URL(u, 'http://x').searchParams.get('from') || 0)
      const st = sseResponse(s.events.filter((e) => e.seq >= from), init.signal)
      s.streams.push(st)
      return st.res
    }
    if (method === 'POST' && /\/(stop|resume|skip|close)$/.test(u)) return json(200, { seq: s.events.length })
    if (method === 'POST' && u.endsWith('/lease')) return json(409, { error: { guard: 'lease.held', message: 'another executor holds this lease' } })
    return json(404, { error: { guard: 'api.not-found', message: `no fake for ${method} ${u}` } })
  }
  return { fetch, calls, s }
}

// push a new journal line to every open stream and the state
export function append(stack, line) {
  const e = { v: 1, seq: stack.s.events.length, at: line.at ?? Date.now(), prev: '', chain: line.chain ?? null, by: line.by ?? 'api', gen: line.gen ?? null, type: line.type, data: line.data ?? {} }
  stack.s.events.push(e)
  for (const st of stack.s.streams) { try { st.push(e) } catch { /* closed */ } }
  return e
}

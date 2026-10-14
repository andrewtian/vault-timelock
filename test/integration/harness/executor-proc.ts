// test/integration/harness/executor-proc.ts — E3 executors in their own process (not a test file), so a scenario can
// SIGKILL them mid-job (a closed tab, a killed terminal) or let them SIGKILL themselves at an exact journal transition.
//   · adapter 'browser': the page's adapter (browserAdapter + browserClients): relative /api and /relay URLs resolved by a
//     jsdom window at the page origin, sent to the stack's REAL page server (which holds the token). Its sandbox allows
//     the page port only.
//   · adapter 'node': the CLI's adapter (nodeAdapter + nodeClients) with the token read from $VT_HOME/local/api.token
//     (readApiToken), the fixed ports mapped to the stack's. Its sandbox allows the API and relay ports only.
// Input: VT_E4_PROC (JSON, no secret): { adapter, jobId, ports, chains, poll, mode: run | clawback, to?, clawbackConfirm?,
// crash? }; stdin: one JSON line { secrets: { eth?, sol? } } (synthetic keys, memory only — never env, argv or disk).
// A lease still held by a dead holder is waited out (lease.held: retried every second, as the CLI does).
// Output lines: `child started`, `waiting <chain> lease.held`, `outcome <chain> <RunOutcome>`, `crash <at> <what> #<n> <chain>` (written synchronously
// right before the SIGKILL), `note <chain> <text>` at the end.
import { writeSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join } from 'node:path'
import { createExecutor } from '../../../packages/core/src/executor/executor.ts'
import { browserAdapter, browserClients } from '../../../packages/core/src/executor/adapters/browser.ts'
import { nodeAdapter, nodeClients, readApiToken } from '../../../packages/core/src/executor/adapters/node.ts'
import { fromSecret } from '../../../packages/core/src/engine/keys.js'
import type { Chain } from '../../../packages/core/src/contracts/index.ts'
import { nodeShim, pageShim } from './shims.ts'
import type { Crash, Fetch } from './shims.ts'

interface Cfg { adapter: 'browser' | 'node'; jobId: string; ports: { api: number; relay: number; page: number | null }; chains: Chain[]; poll: number; mode: 'run' | 'clawback'; to?: string; clawbackConfirm?: { amount: string }; crash?: Crash }
const cfg = JSON.parse(process.env.VT_E4_PROC ?? '{}') as Cfg
const say = (l: string): void => { writeSync(1, `${l}\n`) }
const stdin = await new Promise<string>((resolve) => { let s = ''; process.stdin.on('data', (d) => (s += d)); process.stdin.on('end', () => resolve(s)) })
const { secrets } = JSON.parse(stdin) as { secrets: Partial<Record<Chain, string>> }

let base: Fetch, clients: ReturnType<typeof browserClients>
if (cfg.adapter === 'browser') {
  const { JSDOM } = createRequire(new URL('../../../packages/core/package.json', import.meta.url))('jsdom') as { JSDOM: new (h: string, o: { url: string }) => { window: { location: { href: string }; URL: typeof URL } } }
  const dom = new JSDOM('<!doctype html><title>vt</title>', { url: 'http://127.0.0.1:5180/#/jobs' })
  const page = pageShim(() => cfg.ports.page!)
  base = (url, init) => page(new dom.window.URL(url, dom.window.location.href).href, init)   // the page's relative URLs
} else base = nodeShim({ api: cfg.ports.api, relay: cfg.ports.relay })

// the crash plan: count the matching requests; at the nth, SIGKILL this process before it leaves, or once its answer came
const counts = new Map<string, number>()
const kindOf = (url: string, init?: RequestInit): { what: string; chain: Chain | null } | null => {
  if ((init?.method ?? 'GET') !== 'POST' || init?.body === undefined || init.body === null) return null
  let b: { type?: unknown; method?: unknown }
  try { b = JSON.parse(String(init.body)) } catch { return null }
  const ev = /\/jobs\/[0-9a-f]{16}\/chains\/(eth|sol)\/events$/.exec(new URL(url, 'http://127.0.0.1').pathname)
  if (ev && typeof b.type === 'string') return { what: b.type, chain: ev[1] as Chain }
  const rl = /\/relay\/(eth|sol)$/.exec(new URL(url, 'http://127.0.0.1').pathname)
  if (rl && (b.method === 'eth_sendRawTransaction' || b.method === 'sendTransaction')) return { what: 'send', chain: rl[1] as Chain }
  return null
}
const f: Fetch = async (url, init) => {
  const c = cfg.crash
  const k = c ? kindOf(url, init) : null
  const hit = c !== undefined && k !== null && k.what === c.what && (c.chain === undefined || c.chain === k.chain)
    && (counts.set(`${k.chain}:${k.what}`, (counts.get(`${k.chain}:${k.what}`) ?? 0) + 1), counts.get(`${k.chain}:${k.what}`) === c.nth)
  if (hit && c!.at === 'before') { say(`crash before ${c!.what} #${c!.nth} ${k!.chain}`); process.kill(process.pid, 'SIGKILL') }
  const r = await base(url, init)
  if (hit && c!.at === 'after') { await r.clone().arrayBuffer().catch(() => null); say(`crash after ${c!.what} #${c!.nth} ${k!.chain} ${r.status}`); process.kill(process.pid, 'SIGKILL') }
  return r
}

if (cfg.adapter === 'browser') clients = browserClients({ fetch: f })
else clients = nodeClients({ network: 'local', token: readApiToken(join(process.env.VT_HOME!, 'local', 'api.token')), fetch: f })
const { clock, random } = cfg.adapter === 'browser' ? browserAdapter() : nodeAdapter()
say('child started')
const runs = cfg.chains.map(async (chain) => {
  const handle = fromSecret(chain, secrets[chain]!) as { address: string }
  // a lease still held by a dead holder (a crash, until its TTL lapses) is waited out, as an operator re-running `vt job run` does (stack.ts runCli)
  for (let i = 0; ; i++) {
    const ex = createExecutor({ jobId: cfg.jobId, chain, key: { chain, address: handle.address, network: 'local', handle }, holder: cfg.adapter === 'browser' ? 'browser' : 'cli',
      deps: { ...clients, clock, random, poll: cfg.poll, ...(cfg.clawbackConfirm ? { clawbackConfirm: cfg.clawbackConfirm } : {}) } })
    try {
      const outcome = cfg.mode === 'clawback' ? await ex.clawback(cfg.to!) : await ex.start()
      say(`note ${chain} ${ex.view().note.replace(/\s+/g, ' ').slice(0, 300)}`)
      say(`outcome ${chain} ${outcome}`)
      return
    } catch (e) {
      const g = (e as { guardId?: string }).guardId
      if (g === 'lease.held' && i < 120) { if (i === 0) say(`waiting ${chain} lease.held`); await clock.sleep(1_000); continue }
      say(`note ${chain} ${String(g ?? (e as Error).message).slice(0, 300)}`)
      say(`outcome ${chain} refused:${g ?? 'error'}`)
      return
    }
  }
})
await Promise.all(runs)
process.exit(0)

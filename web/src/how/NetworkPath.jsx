// How a signed transaction leaves this machine and reaches each network, what every hop can see, and where the link
// between "us" and the node that receives the transaction is cut (Tor). Ported from the prototype's NetworkPath.jsx
// (tag add7b-e540f8ae4d6b; R57); the hop list is GENERATED (hops.js) from the endpoint table and the live relay answers.
import { useState } from 'react'
import { NETWORKS } from '@vault-timelock/core/contracts'
import { currentNetwork, NETWORK_LABEL, useStatus } from '@/lib/status.js'
import { useTor } from '@/tor/TorPanel.jsx'
import { buildPath, CHAINS, SEND_CALL } from './hops.js'

const TONE = {
  you: 'border-amber-500/70 bg-amber-500/10 text-amber-300',
  local: 'border-violet-400/70 bg-violet-400/10 text-violet-300',
  tor: 'border-emerald-500/70 bg-emerald-500/10 text-emerald-300',
  ext: 'border-sky-400/70 bg-sky-400/10 text-sky-300',
  pub: 'border-neutral-500 bg-neutral-900 text-neutral-200',
}
const NAME = { eth: 'Ethereum', sol: 'Solana', btc: 'Bitcoin' }

function Hop({ hop }) {
  return (
    <li data-testid={`hop-${hop.id}`} className={`w-44 shrink-0 rounded-lg border p-2 text-xs ${TONE[hop.tone]}`}>
      <div className="text-[13px] font-semibold">{hop.title}</div>
      <div className="mt-1 space-y-0.5 font-mono text-[10.5px] text-neutral-400">{hop.sub.map((s) => <div key={s}>{s}</div>)}</div>
      <div className="mt-2 text-[10.5px] text-neutral-400">sees:</div>
      <ul className="text-[10.5px] text-neutral-200">{hop.sees.map((s) => <li key={s}>• {s}</li>)}</ul>
      <ul className="text-[10.5px] text-emerald-300">{hop.notSees.map((s) => <li key={s}>✗ {s}</li>)}</ul>
    </li>
  )
}

export function LinkCut() {
  return (
    <li data-testid="link-cut" aria-label="link cut here" className="flex w-32 shrink-0 flex-col items-center justify-center self-stretch border-x-2 border-dashed border-rose-500 bg-rose-950/40 px-1 text-center">
      <b className="text-[11.5px] text-rose-300">link cut here</b>
      <span className="text-[10.5px] text-rose-300">no hop sees both you and the node</span>
    </li>
  )
}

export function Lane({ path }) {
  return (
    <div data-testid={`lane-${path.chain}`} className="space-y-2">
      <div className="flex flex-wrap items-baseline gap-3"><b className="text-[15px] text-neutral-100">{NAME[path.chain]}</b><span className="text-[11.5px] text-neutral-400">{SEND_CALL[path.chain]}</span></div>
      <ol className="flex items-stretch gap-1.5 overflow-x-auto pb-2">
        {path.hops.map((h) => [<Hop key={h.id} hop={h} />, path.cutAfter === h.id ? <LinkCut key="cut" /> : null])}
      </ol>
    </div>
  )
}

// `**bold**` marks the emphasised words; rendered by Rich below (no HTML injection: plain text pieces only).
export const CAUSES = {
  breaks: [
    "Only the **guard** sees your IP, and it can't see where traffic goes or what it is.",
    "The **exit** and the **RPC provider** see the destination and the transaction, but only the exit's IP, never yours.",
    'DNS is resolved at the exit (socks5h): your machine never looks the RPC host up.',
    "The relay is sandboxed: it can only reach Tor, so a bug can't make it connect directly.",
    "Ethereum and Solana use **different circuits** (different SOCKS usernames): an exit or RPC can't tie the two sends together by connection.",
    'The page itself never contacts an RPC, explorer or price API (same-origin only); mainnet explorer links are copy-only for Tor Browser.',
  ],
  still: [
    "**On-chain funding:** the sending address is public and so is whoever funded it. Railgun/Privacy Cash hide the source; Privacy Cash's relayer can still link deposit → this address (R55).",
    "**Timing:** an observer watching both your link to the guard and the RPC's inbound traffic could correlate; Tor doesn't defeat a global observer.",
    '**Same moment on both chains:** sends at the same zero second can be matched by time even on separate circuits.',
    '**The RPC provider** logs the exit IP, the transaction and the time (harmless to you unless Tor itself is broken).',
    "**Your guard** is long-lived by Tor's design, so it sees that you use Tor often (not what for).",
  ],
  controls: [
    '**New circuit** per chain (or all) in the Tor panel: the next request uses fresh relays (new SOCKS generation).',
    'Auto-rotate when an RPC blocks or times out (reads only; a timed-out send is reconciled, never re-sent).',
    'Sends are disabled unless the Tor check says “through Tor”.',
    'Fund from a private source and pick a different source per try (R47).',
  ],
}
export const Rich = ({ text }) => text.split('**').map((p, i) => (i % 2 === 1 ? <b key={i}>{p}</b> : p))
const Items = ({ rows }) => rows.map((r) => <li key={r}><Rich text={r} /></li>)

export function NetworkPath() {
  const ctx = useStatus()
  const current = currentNetwork(ctx)
  const [picked, setPicked] = useState(null)
  const network = picked ?? current ?? 'local'
  const isLive = network === current
  const { st: tor } = useTor(10_000, isLive && network !== 'local')
  const paths = CHAINS.map((chain) => buildPath({ network, chain, names: isLive ? ctx.status?.networks ?? null : null, relay: isLive ? ctx.relay : null, tor: isLive ? tor : null, live: isLive }))
  return (
    <section data-testid="how-network" className="space-y-4">
      <p className="text-sm text-neutral-400">
        How a transaction is broadcast, where Tor sits, and why no single party can connect <b>you</b> to the node that receives it.
        The hops below are generated from this build&apos;s endpoint table{isLive ? ' and the live relay' : ''} for the <b>{NETWORK_LABEL[network]}</b> network.
      </p>
      <div role="group" aria-label="network" className="flex flex-wrap gap-2">
        {NETWORKS.map((n) => (
          <button key={n} type="button" data-testid={`path-net-${n}`} aria-pressed={n === network} onClick={() => setPicked(n)}
            className={`rounded-md border px-2 py-1 text-xs ${n === network ? 'border-amber-400 text-amber-300' : 'border-neutral-700 text-neutral-300 hover:bg-neutral-800'}`}>{NETWORK_LABEL[n]}{n === current ? ' (this page)' : ''}</button>
        ))}
      </div>
      {network === 'local' && <p data-testid="path-local-note" className="rounded border border-neutral-700 p-2 text-xs text-neutral-300">LOCAL: the relay talks to the chains on this machine directly, through loopback. There is no Tor and no link to cut. Pick TESTNET or MAINNET to see the Tor path.</p>}
      {!isLive && <p data-testid="path-static-note" className="text-xs text-neutral-500">Shown from the endpoint table only: this page is served for {current ? NETWORK_LABEL[current] : 'another network'}, so its relay cannot answer for {NETWORK_LABEL[network]}.</p>}
      <div className="space-y-4 rounded-xl border border-neutral-800 bg-neutral-950 p-3">{paths.map((p) => <Lane key={p.chain} path={p} />)}</div>
      <div className="grid gap-3 md:grid-cols-3">
        <div className="rounded-lg border border-emerald-600/50 bg-emerald-500/5 p-3 text-sm">
          <div className="mb-1 font-semibold text-emerald-300">What breaks the link</div>
          <ul className="list-disc space-y-1 pl-4 text-neutral-300"><Items rows={CAUSES.breaks} /></ul>
        </div>
        <div className="rounded-lg border border-amber-600/50 bg-amber-500/5 p-3 text-sm">
          <div className="mb-1 font-semibold text-amber-300">What still links (be honest)</div>
          <ul className="list-disc space-y-1 pl-4 text-neutral-300"><Items rows={CAUSES.still} /></ul>
        </div>
        <div className="rounded-lg border border-neutral-700 p-3 text-sm">
          <div className="mb-1 font-semibold text-neutral-200">Controls you have</div>
          <ul className="list-disc space-y-1 pl-4 text-neutral-300"><Items rows={CAUSES.controls} /></ul>
        </div>
      </div>
    </section>
  )
}

// Publication modes (R73): the rehearsed ELITE SET with each mode's permanence class and trust note, read from the
// contracts' PUBLISH_MODES (one source of truth), and the Passive / Economy / Prompt cost notes of
// publication-modes-elite.md. Mode status comes from the table: 'reserved' rows are shown but cannot be selected yet.
import { PERMANENCE_CLASSES, PUBLISH_MODES, PUBLISH_MODES_VERSION } from '@vault-timelock/core/contracts'
import { COST_AS_OF, COSTS, ELITE, PERMANENCE_NOTE, STRATEGIES } from './costNotes.js'

const CHAIN_NAME = { eth: 'Ethereum', sol: 'Solana', btc: 'Bitcoin' }
const bytes = (n) => (n === null ? 'sized per transaction by simulation (or not in the chain tx)' : `${n.toLocaleString('en-US')} B per tx`)

function ModeRow({ row }) {
  const elite = ELITE[row.id]
  return (
    <li data-testid={`mode-${row.id}`} data-status={row.status} data-permanence={row.permanence} className="rounded-lg border border-neutral-700 p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <b className="text-neutral-100">{elite?.label ?? row.id}</b>
        <span className="font-mono text-xs text-neutral-400">{row.id}</span>
        <span data-testid={`mode-${row.id}-status`} className={`rounded px-1.5 py-0.5 text-[11px] ${row.status === 'available' ? 'bg-emerald-500/15 text-emerald-300' : 'bg-neutral-800 text-neutral-400'}`}>{row.status === 'available' ? 'available' : 'reserved: not selectable yet'}</span>
        <span data-testid={`mode-${row.id}-permanence`} className="rounded bg-sky-500/15 px-1.5 py-0.5 text-[11px] text-sky-300">permanence: {row.permanence}</span>
        {!elite && <span className="rounded bg-neutral-800 px-1.5 py-0.5 text-[11px] text-neutral-400">fallback</span>}
      </div>
      <p className="mt-1 text-neutral-300">{row.note}</p>
      <p data-testid={`mode-${row.id}-trust`} className="mt-1 text-amber-200/90">Trust: {row.trustNote}</p>
      {elite?.warning && <p className="mt-1 text-amber-200/90">Warning: {elite.warning}</p>}
      <dl className="mt-1 grid gap-x-4 text-xs text-neutral-400 sm:grid-cols-2">
        {elite && <div><dt className="inline">When to choose: </dt><dd className="inline text-neutral-300">{elite.when}</dd></div>}
        {elite && <div><dt className="inline">Default fee strategy: </dt><dd className="inline text-neutral-300">{elite.strategy}</dd></div>}
        <div><dt className="inline">Size: </dt><dd className="inline text-neutral-300">{bytes(row.maxBytesPerTx)}</dd></div>
        <div><dt className="inline">Shown as text by explorers: </dt><dd className="inline text-neutral-300">{row.indexedAsText ? 'yes' : 'no'}</dd></div>
        <div><dt className="inline">Needs an on-chain program beyond the built-ins: </dt><dd className="inline text-neutral-300">{row.needsContract ? 'yes' : 'no'}</dd></div>
      </dl>
    </li>
  )
}

export function PublicationModes() {
  return (
    <section data-testid="how-modes" className="space-y-5">
      <p className="text-sm text-neutral-400">
        A <b>publication mode</b> is <i>how</i> the bytes go on chain; a <b>fee strategy</b> is <i>how patiently</i> they are paid for.
        The elite set below is what the rehearsal (Task PM) kept after publishing 1 KB, 10 KB, 100 KB and 5 KB multi-byte texts through every
        candidate. Every mode is public and permanent in the sense of the Arm dialog; the permanence class says <i>who must keep the bytes</i>. Table version {PUBLISH_MODES_VERSION}.
      </p>
      <div data-testid="permanence-classes" className="grid gap-2 md:grid-cols-2">
        {PERMANENCE_CLASSES.map((c) => (
          <div key={c} data-testid={`class-${c}`} className="rounded border border-neutral-800 p-2 text-xs"><b className="text-sky-300">{c}</b> <span className="text-neutral-300">{PERMANENCE_NOTE[c]}</span></div>
        ))}
      </div>
      {['eth', 'sol', 'btc'].map((chain) => (
        <div key={chain} className="space-y-2">
          <h3 className="font-semibold text-neutral-100">{CHAIN_NAME[chain]}</h3>
          <ul className="space-y-2">{PUBLISH_MODES.filter((r) => r.chains.includes(chain) && r.chains.length === 1).map((r) => <ModeRow key={r.id} row={r} />)}</ul>
        </div>
      ))}
      <div className="space-y-2">
        <h3 className="font-semibold text-neutral-100">Either chain</h3>
        <ul className="space-y-2">{PUBLISH_MODES.filter((r) => r.chains.length > 1).map((r) => <ModeRow key={r.id} row={r} />)}</ul>
        <p className="text-xs text-neutral-500">Dropped by the rehearsal and refused by the job validator: eth.calldata.raw (same cost, loses Ethscriptions indexing), eth.blob (fails the permanence gate: pruned after about 18 days), eth.log (no cheaper than calldata, needs a contract, not an ethscription), and the old name arweave.irys (renamed arweave.turbo).</p>
      </div>

      <div className="space-y-2">
        <h3 className="font-semibold text-neutral-100">Fee strategies: Passive vs Economy vs Prompt</h3>
        <div className="grid gap-3 md:grid-cols-3">
          {STRATEGIES.map((s) => (
            <div key={s.id} data-testid={`strategy-${s.id}`} className="rounded-lg border border-neutral-700 p-3 text-sm">
              <b className="text-neutral-100">{s.name}</b> <span className="text-xs text-neutral-500">({s.default})</span>
              <p className="mt-1 text-neutral-300">{s.what}</p>
              <p className="mt-1 text-xs text-neutral-400">Waiting: {s.wait}</p>
            </div>
          ))}
        </div>
        <div className="overflow-x-auto">
          <table data-testid="cost-table" className="w-full text-left text-xs text-neutral-300">
            <caption className="pb-1 text-left text-neutral-500">Expected cost, mainnet, prices of {COST_AS_OF} (ETH $2,477.56, SOL $108.94; ETH rows before the Glamsterdam fork unless noted). These move with the fee market; treat them as the order of magnitude.</caption>
            <thead><tr className="border-b border-neutral-700 text-neutral-400"><th className="py-1 pr-3">Chain</th><th className="pr-3">Unit</th><th className="pr-3">Passive</th><th className="pr-3">Economy</th><th>Prompt</th></tr></thead>
            <tbody>{COSTS.map((c) => <tr key={c.chain + c.unit} className="border-b border-neutral-800 align-top"><td className="py-1 pr-3">{c.chain}</td><td className="pr-3">{c.unit}</td><td className="pr-3 text-emerald-300">{c.passive}</td><td className="pr-3">{c.economy}</td><td>{c.prompt}</td></tr>)}</tbody>
          </table>
        </div>
      </div>
    </section>
  )
}

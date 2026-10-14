// After the run (W4): what a person needs once a chain has settled (DRAINED, COPIES_DONE, STOPPED, CLAWING_BACK,
// CLAWED_BACK, DONE) — what landed, the explorer links for the transactions, how to reassemble the message by hand with
// one command, what the publish mode's permanence means, the claw-back of the remainder, closing the chain (which frees
// the key), and where the key's backup comes back (`vt backup import`, E2E finding L2-3). The job-level panel adds the
// receipt. Nothing here is fetched except the receipt (same-origin API) and, in ResolveStuck, relay reads on request.
import { formatUnits } from '@vault-timelock/core/chains/plan.js'
import { Button } from '@/components/ui/button.jsx'
import AddressLinks, { copyText } from './AddressLinks.jsx'
import { Permanence } from './ArmDialog.jsx'
import Clawback, { CLAW_PHASES } from './Clawback.jsx'
import LinkButtons from './LinkButtons.jsx'
import ReceiptButton from './ReceiptButton.jsx'
import { handReassembly } from './handReassembly.js'
import { CHAIN_LABEL } from './RunHere.js'

const DEC = { eth: 18, sol: 9, btc: 8 }, UNIT = { eth: 'ETH', sol: 'SOL', btc: 'BTC' }
const NULL_ADDRESS = '0x0000000000000000000000000000000000000000'
export const backupImportCommand = (chain) => `vt backup import <backup file> --chain ${chain}`

function Block({ text, testid, label }) {
  return (
    <div className="space-y-0.5">
      <div className="flex items-center gap-2"><span className="text-muted-foreground">{label}</span>
        <Button type="button" size="xs" variant="outline" data-testid={`${testid}-copy`} onClick={() => copyText(text)}>Copy</Button></div>
      <pre data-testid={testid} className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-2 font-mono text-[11px]">{text}</pre>
    </div>
  )
}

export function HandReassembly({ chain, def, cs, network }) {
  const ch = def.chains[chain]
  const h = handReassembly({ chain, txs: cs.txs, signer: ch.keyAddress, messageSha256: def.messageSha256, network })
  if (!h) return null
  return (
    <details data-testid={`byhand-${chain}`} className="rounded border p-2 text-xs">
      <summary className="cursor-pointer font-semibold">Reassemble {CHAIN_LABEL[chain]} by hand ({h.format})</summary>
      <div className="mt-2 space-y-2">
        <p>A multi-part message is {h.parts} parts. Part 1 carries <span className="font-mono">sha256=&lt;64 hex&gt;</span> in its header line; strip exactly that header line from every part,
          join the chunks in part order (by the header’s index, not by block order), then check the sha256 of the result against part 1’s and against this job’s
          <span className="font-mono break-all"> {def.messageSha256}</span>. Read raw calldata / memo bytes, never an explorer’s decoded text. {h.note}</p>
        <Block testid={`byhand-ids-${chain}`} label={`${h.file} (copy ${h.copy}, part order)`} text={h.idsFile} />
        <Block testid={`byhand-cmd-${chain}`} label={chain === 'eth' ? 'needs cast (Foundry) and python3' : 'needs curl and python3'} text={h.command} />
        <p className="text-muted-foreground">The command accepts a part only from the publishing address <span className="font-mono">{ch.keyAddress}</span>, refuses a missing part or two payloads for one part, and prints the text only when the sha256 matches.</p>
      </div>
    </details>
  )
}

export function ChainAfterRun({ jobId, def, chain, state, cs, entry, keyOk, run, network, heldElsewhere }) {
  const ch = def.chains[chain]
  const landed = cs.txs.filter((t) => t.state === 'included' && t.landedId)
  const last = landed.at(-1)
  const to = chain === 'eth' ? (ch.publishMode === 'eth.calldata.self' ? ch.keyAddress : NULL_ADDRESS) : undefined
  const clawable = CLAW_PHASES.has(cs.phase) || cs.phase === 'CLAWED_BACK'
  return (
    <div data-testid={`afterrun-${chain}`} data-phase={cs.phase} className="space-y-2 rounded-lg border border-emerald-300 bg-emerald-50/40 p-2 text-xs">
      <div className="font-semibold">After the run · {CHAIN_LABEL[chain]} · {cs.phase}</div>
      <p data-testid={`afterrun-summary-${chain}`}>
        {landed.length} transaction{landed.length === 1 ? '' : 's'} landed · {cs.copiesIncluded} cop{cs.copiesIncluded === 1 ? 'y' : 'ies'} complete · reassembled ✓ {cs.reassembled.filter((r) => r.ok).length} ·
        spent {formatUnits(BigInt(cs.spent || '0'), DEC[chain])} {UNIT[chain]}
      </p>
      <Permanence chain={chain} mode={ch.publishMode} testid={`afterrun-permanence-${chain}`} />
      {last && (
        <div className="space-y-1">
          <div className="text-muted-foreground">Last transaction</div>
          <LinkButtons network={network} chain={chain} txId={last.landedId} signer={ch.keyAddress} to={to} prefix={`afterrun-link-${chain}`} />
        </div>
      )}
      <AddressLinks network={network} chain={chain} address={ch.keyAddress} />
      <HandReassembly chain={chain} def={def} cs={cs} network={network} />
      {clawable
        ? <div data-testid={`afterrun-claw-${chain}`}><Clawback jobId={jobId} def={def} chain={chain} cs={cs} armed={state.armed} entry={entry} keyOk={keyOk} run={run} network={network} heldElsewhere={heldElsewhere} /></div>
        : <p className="text-muted-foreground" data-testid={`afterrun-noclaw-${chain}`}>Nothing to claw back on a {cs.phase} chain.</p>}
      <p className="text-muted-foreground" data-testid={`afterrun-close-${chain}`}>Close chain (above) releases this chain’s key from the job once you are done; claw back first if funds remain.
        The key’s backup comes back with <span className="font-mono">{backupImportCommand(chain)}</span>.</p>
    </div>
  )
}

export default function JobAfterRun({ jobId, def, state, network, settledChains }) {
  if (settledChains.length === 0) return null
  const all = settledChains.length === Object.keys(def.chains).length
  return (
    <section data-testid="afterrun" data-all={String(all)} className="space-y-1 rounded-xl border p-3 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <b>{all ? 'The run is over' : 'Some chains are done'}</b>
        <ReceiptButton jobId={jobId} testid="afterrun-receipt" />
      </div>
      <p className="text-xs text-muted-foreground">The receipt lists the transaction ids, blocks, fees, reassembly results and the claw-back — no keys, no message text, no addresses of yours beyond the lane keys’. On {network}{network === 'mainnet' ? ', explorer links are copy-only text' : ''}. Job phase {state.phase}.</p>
      <p className="text-xs text-muted-foreground" data-testid="afterrun-backup">Lost the key’s backup folder, or on another machine? <span className="font-mono">vt backup import &lt;backup file&gt;</span> restores it.</p>
    </section>
  )
}

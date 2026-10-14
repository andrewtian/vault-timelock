// cli/src/job/receipt.ts — `vt job receipt <id> [--json]` (spec §5.7, §8; plan Task C5; C1 ruling 3).
// GET /jobs/<id>/receipt (vt-receipt/1: no keys, no IPs, no endpoints, no message text; the text is named by its
// sha256). It prints to STDOUT ONLY: there is no --out (ruled): a client command's sandbox allows no file writes, so the
// operator redirects (`vt job receipt <id> --json > receipt.json`).
//   --json   the receipt exactly as the API serves it (the bytes the page's download saves), after the printer's
//            checks (client.ts emitJson: nothing is printed if any check fails);
//   default  a summary: per chain the phase, copies, reassembly, spend, claw-back and each landed transaction.
import type { Chain, Receipt } from '@vault-timelock/core/contracts'
import { UsageError } from '../args.ts'
import type { JobIo } from './client.ts'
import { apiClient, emitJson, jobIdArg, parseFlags, printLines } from './client.ts'
import { amount } from './status.ts'

const USAGE = 'usage: vt job receipt <id> [--json]   (stdout only: redirect it to keep a file)'

export function renderReceipt(r: Receipt): string {
  const lines = [`${r.format}  job ${r.jobId}  ${r.network}  "${r.name}"  build ${r.build}`, `  message sha256 ${r.messageSha256}`]
  for (const c of ['eth', 'sol', 'btc'] as const satisfies readonly Chain[]) {
    const x = r.chains?.[c]
    if (x === undefined) continue
    const mode = x.mode === 'drain' ? 'drain' : `${x.mode.copies} copies`
    lines.push(`  ${c}  ${x.network}  ${x.address}  ${mode}  ${x.phase}  copies included ${x.copiesIncluded}  spent ${amount(c, x.spent)}`)
    if (x.reassembled.length > 0) lines.push(`       reassembled: ${x.reassembled.map((a) => `copy ${a.copy} ${a.ok ? '✓' : '✗'}`).join(', ')}`)
    if (x.clawback !== null) lines.push(`       claw-back ${amount(c, x.clawback.value)} to ${x.clawback.to} (${x.clawback.txId})`)
    for (const t of x.txs) {
      lines.push(`       copy ${t.copy} part ${t.part}  ${t.txId}  block ${t.block || '?'}  fee ${t.fee || '?'}  attempts ${t.attempts}  readback ${t.readback ? 'ok' : 'NOT OK'}`)
      for (const l of t.links) lines.push(`         ${l.label}: ${l.href}${l.copyOnly ? '  (copy into Tor Browser)' : ''}`)
    }
  }
  return lines.join('\n')
}

export async function receiptCommand(args: readonly string[], io: JobIo): Promise<number> {
  if (args.some((x) => x === '--out' || x.startsWith('--out='))) throw new UsageError('vt job receipt prints to stdout only; there is no --out (the client sandbox writes no files): vt job receipt <id> --json > receipt.json')
  const { flags, pos } = parseFlags(args, { valued: [], bool: ['--json'], usage: USAGE })
  if (pos.length !== 1) throw new UsageError(USAGE)
  const id = jobIdArg(pos[0], USAGE)
  const r = await apiClient(io).json<Receipt>('GET', `/jobs/${id}/receipt`)
  if (r.value?.format !== 'vt-receipt/1') throw new Error('the jobs API answered something that is not a vt-receipt/1')
  if (flags.has('--json')) emitJson(io, r.text)
  else printLines(io, renderReceipt(r.value))
  return 0
}

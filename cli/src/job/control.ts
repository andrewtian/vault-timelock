// cli/src/job/control.ts — the operator's controls of a job (spec §5.2, §8; plan Task C5):
//   vt job skip <id>                                                        POST /jobs/<id>/skip {}
//   vt job stop <id> [--chain c]                                            POST /jobs/<id>/stop { chain | null }
//   vt job resume <id> [--chain c] [--tip-cap-gwei X] [--cu-price-cap N]    POST /jobs/<id>/resume { chain | null, … }
//   vt job close <id> --chain c                                             POST /jobs/<id>/close { chain }
//   vt job resolve <id> --chain c --tx <txId> mark-done|mark-failed         POST /jobs/<id>/chains/<c>/resolve
// The API checks every rule (job.state, job.armed, …); vt prints its refusal as `refused <guard>: <message>`, exit 2.
//
// resolve records the OPERATOR'S outcome for an attempt of a STUCK chain, one whose outcome the executor could not
// learn from the chain. It is a claim, not chain evidence:
//   · mark-failed frees NO cap capacity: the attempt stays held against the armed cap until chain evidence (an
//     executor's reconcile `expired` / `nonce-consumed`) releases it;
//   · mark-done counts the attempt as landed, charged at its worst-case fee.
// On mainnet the word `resolve` must be typed at the terminal (readTypedWord; job.resolve-typed, re-checked by the API).
import type { Chain } from '@vault-timelock/core/contracts'
import { refuse } from '@vault-timelock/core/contracts'
import { UsageError } from '../args.ts'
import type { JobIo } from './client.ts'
import { apiClient, assertTerminal, chainArg, emitJson, jobIdArg, parseFlags, printLines } from './client.ts'
import { iso } from './status.ts'
import type { JobView } from './status.ts'

const USAGE = {
  skip: 'usage: vt job skip <id> [--json]',
  stop: 'usage: vt job stop <id> [--chain eth|sol|btc] [--json]',
  resume: 'usage: vt job resume <id> [--chain eth|sol|btc] [--tip-cap-gwei X] [--cu-price-cap N] [--json]',
  close: 'usage: vt job close <id> --chain eth|sol|btc [--json]',
  resolve: 'usage: vt job resolve <id> --chain eth|sol|btc --tx <txId> mark-done|mark-failed [--json]   (btc: vt job resolve <id> --chain btc --mark-failed [--json])',
} as const

function assertResumeTyped(ok: boolean): void {
  if (!ok) refuse('job.resume-typed', 'resuming a mainnet job needs the typed word "resume"; nothing was sent') // @guard:job.resume-typed
}

// R79b: what the API's resume answer may carry. A resume of ONE chain whose stop is FINAL is a refusal (409 resume.final-stop, printed as
// `refused resume.final-stop: ...` by the client); a resume of every chain (no --chain) resumes only the RESUMABLE ones and lists the rest.
// Entries: a chain name, or { chain, guard?, reason?|message? }.
export interface ResumeAnswer { seq?: number; resumed?: unknown; refused?: unknown; skipped?: unknown }
const isChain = (x: unknown): x is Chain => x === 'eth' || x === 'sol' || x === 'btc'
export function resumeLines(id: string, what: string, a: ResumeAnswer): string[] {
  const resumed = Array.isArray(a.resumed) ? a.resumed.filter(isChain) : null
  const rawRefused = Array.isArray(a.refused) ? a.refused : Array.isArray(a.skipped) ? a.skipped : []
  const refused: Array<{ chain: string; why: string }> = []
  for (const r of rawRefused) {
    if (isChain(r)) refused.push({ chain: r, why: 'its stop is final (resume.final-stop)' })
    else if (typeof r === 'object' && r !== null && isChain((r as { chain?: unknown }).chain)) {
      const o = r as { chain: string; guard?: unknown; reason?: unknown; message?: unknown }
      const why = [typeof o.guard === 'string' ? `${o.guard}: ` : '', typeof o.message === 'string' ? o.message : typeof o.reason === 'string' ? o.reason : 'its stop is final'].join('')
      refused.push({ chain: o.chain, why: why.replace(/\s+/g, ' ').slice(0, 300) })
    }
  }
  const out = [`resume requested for ${what} of job ${id} (seq ${String(a.seq)})`]
  if (resumed !== null) out.push(`  resumed: ${resumed.length > 0 ? resumed.join(', ') : 'none'}`)
  for (const r of refused) out.push(`  NOT resumed: ${r.chain} — ${r.why}`)
  if (refused.length > 0) out.push('  a final stop is never lifted by resume: the way out is vt job close / vt job clawback, and a new job')
  return out
}

const GWEI = /^(?:0|[1-9][0-9]{0,5})(?:\.[0-9]{1,9})?$/
const CU = /^(?:0|[1-9][0-9]{0,6})$/
const TX_ID: Readonly<Record<Chain, RegExp>> = { eth: /^0x[0-9a-f]{64}$/, sol: /^[1-9A-HJ-NP-Za-km-z]{64,90}$/, btc: /^[0-9a-f]{64}$/ }

function assertResolveTyped(ok: boolean): void {
  if (!ok) refuse('job.resolve-typed', 'resolving a mainnet transaction needs the typed word "resolve"; nothing was sent') // @guard:job.resolve-typed
}

export async function controlCommand(sub: 'skip' | 'stop' | 'resume' | 'close', args: readonly string[], io: JobIo): Promise<number> {
  const usage = USAGE[sub]
  const valued = sub === 'resume' ? ['--chain', '--tip-cap-gwei', '--cu-price-cap'] : sub === 'skip' ? [] : ['--chain']
  const { flags, pos } = parseFlags(args, { valued, bool: ['--json'], usage })
  if (pos.length !== 1) throw new UsageError(usage)
  const id = jobIdArg(pos[0], usage)
  const chainFlag = flags.get('--chain')
  const chain: Chain | null = chainFlag === undefined ? null : chainArg(typeof chainFlag === 'string' ? chainFlag : undefined, usage)
  let body: Record<string, unknown>
  if (sub === 'skip') body = {}
  else if (sub === 'close') {
    if (chain === null) throw new UsageError(usage)
    body = { chain }
  } else if (sub === 'stop') body = { chain }
  else {
    const tip = flags.get('--tip-cap-gwei'), cu = flags.get('--cu-price-cap')
    if (tip !== undefined && !(typeof tip === 'string' && GWEI.test(tip))) throw new UsageError(`${usage} (--tip-cap-gwei: a decimal number of gwei)`)
    if (cu !== undefined && !(typeof cu === 'string' && CU.test(cu) && Number(cu) <= 2_000_000)) throw new UsageError(`${usage} (--cu-price-cap: an integer 0..2000000)`)
    body = { chain, ...(tip === undefined ? {} : { tipCapGwei: tip }), ...(cu === undefined ? {} : { cuPriceCap: Number(cu) }) }
  }
  if (sub === 'resume' && io.network === 'mainnet') {
    const w = await io.ask(`MAINNET: type resume to continue ${chain === null ? 'every resumable chain' : chain} of job ${id}: `, 'resume')
    assertTerminal(w !== undefined, 'resuming a mainnet job needs the word "resume" typed at a terminal (never stdin, argv or the environment)')
    assertResumeTyped(w === 'resume')
  }
  const r = await apiClient(io).json<{ seq?: number; releaseAt?: number } & ResumeAnswer>('POST', `/jobs/${id}/${sub}`, body)
  if (flags.has('--json')) {
    emitJson(io, r.text)
    return 0
  }
  const what = chain === null ? 'every chain' : chain
  const line = {
    skip: `countdown skipped: job ${id} releases now (${iso(r.value.releaseAt)}); each executor still runs its pre-start check`,
    stop: `stop requested for ${what} of job ${id} (seq ${r.value.seq}): an executor stops after the transaction in flight; a chain with none stops now${chain === 'btc' || chain === null ? `${chain === null ? '; for a btc chain:' : ';'} a btc copy is a commit and its reveal, so Stop takes effect after the in-flight commit's reveal (the reveal is sent first, then the chain stops)` : ''}`,
    resume: resumeLines(id, what, r.value).join('\n'),
    close: `closed ${what} of job ${id} (seq ${r.value.seq}): its key is free for another job`,
  }[sub]
  printLines(io, line)
  return 0
}

export async function resolveCommand(args: readonly string[], io: JobIo): Promise<number> {
  const usage = USAGE.resolve
  const { flags, pos } = parseFlags(args, { valued: ['--chain', '--tx'], bool: ['--json', '--mark-failed', '--mark-done'], usage })
  const flagAction = flags.has('--mark-failed') ? 'mark-failed' : flags.has('--mark-done') ? 'mark-done' : null
  if (flags.has('--mark-failed') && flags.has('--mark-done')) throw new UsageError(usage)
  if (flagAction !== null ? pos.length !== 1 : pos.length !== 2) throw new UsageError(usage)
  const id = jobIdArg(pos[0], usage)
  const action = flagAction ?? pos[1]
  if (action !== 'mark-done' && action !== 'mark-failed') throw new UsageError(usage)
  const cf = flags.get('--chain')
  const chain = chainArg(typeof cf === 'string' ? cf : undefined, usage)
  if (chain === 'btc' && action === 'mark-done') {
    throw new UsageError('vt job resolve --chain btc accepts only --mark-failed: mark-done is refused for btc, because a commit that never landed must not be marked done (it would count a transaction that is not on the chain, and its reveal could then never be built). Once the commit\'s input is spent in a block, or the commit can never land: vt job resolve <id> --chain btc --mark-failed; nothing was sent')
  }
  if (chain !== 'btc' && flagAction !== null) throw new UsageError(`${usage} (--mark-failed / --mark-done are for btc; ${chain} takes the positional mark-done|mark-failed)`)
  const api = apiClient(io)
  const view = (await api.json<JobView>('GET', `/jobs/${id}`)).value
  const cs = view.state?.chains?.[chain]
  let tx = flags.get('--tx')
  if (tx === undefined && chain === 'btc') {
    // the stuck commit: the chain's one open attempt, as vt job status shows it
    const open = cs?.openIntents ?? []
    if (open.length !== 1) throw new UsageError(`btc has ${open.length} open attempts (vt job status ${id}); name the commit with --tx <txId>`)
    tx = open[0]
  }
  if (typeof tx !== 'string' || !TX_ID[chain].test(tx)) throw new UsageError(`${usage} (--tx: the attempt's tx id, as vt job status shows it)`)
  const t = cs?.txs.find((x) => x.attempts.some((y) => y.txId === tx))
  const show = (text: string): void => printLines(io, text, flags.has('--json'))
  show([
    `resolve ${chain} ${tx} of job ${id} as ${action}${t === undefined ? '' : ` (copy ${t.copy} part ${t.part}/${t.parts})`}; the chain is ${String(cs?.phase)}`,
    action === 'mark-failed'
      ? '  mark-failed is your claim, not chain evidence: it frees NO cap capacity; the attempt stays held until an executor reconciles it from the chain (expired / nonce-consumed)'
      : '  mark-done counts the attempt as landed: its worst-case fee is charged against the cap',
  ].join('\n'))
  let typed: string | null = null
  if (io.network === 'mainnet') {
    const w = await io.ask(`MAINNET: type resolve to record ${action} for ${tx}: `, 'resolve')
    assertTerminal(w !== undefined, 'resolving a mainnet transaction needs the word "resolve" typed at a terminal (never stdin, argv or the environment)')
    assertResolveTyped(w === 'resolve')
    typed = w as string
  }
  const r = await api.json<{ seq: number }>('POST', `/jobs/${id}/chains/${chain}/resolve`, { txId: tx, action, ...(typed === null ? {} : { typed }) })
  if (flags.has('--json')) emitJson(io, r.text)
  else printLines(io, `recorded ${action} for ${tx} (seq ${r.value.seq})`)
  return 0
}

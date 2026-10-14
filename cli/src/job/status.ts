// cli/src/job/status.ts — `vt job status <id> [--watch] [--json]` and `vt job watch <id> [--from N] [--json]`
// (spec §5.2 GET /jobs/:id and GET /jobs/:id/events, §8; plan Task C5).
//
// status   the job's definition summary, its phase, the arm record, and per chain: phase, reason, progress, spend
//          against the armed cap, open and STUCK attempts (with the exact `vt job resolve` line), the lease, the
//          claw-back. --json prints the API's body exactly (GET /jobs/:id: { id, def, state, leases, seq, serverNowMs }).
// watch    follows the journal over SSE: every event once, in order (from --from N, default 0; `status --watch`
//          continues after the status it printed). It resumes with Last-Event-ID after a dropped stream (client.ts).
//          It ends on Ctrl-C, or once the job is DONE (checked with GET /jobs/:id after an event that can finish a
//          chain). One line per event; --json: the journal line itself.
// ★ Every printed line goes through C4's printer (client.ts printLines / safeLine): an executor's free text (reasons,
//   notes, details) cannot move the cursor, rewrite the screen or print an address.
import type { ArmRecord, Chain, ChainState, JobDef, JobState, LeaseView } from '@vault-timelock/core/contracts'
import { finalStopText, stopClassOf } from '@vault-timelock/core/contracts'
import { formatUnits } from '@vault-timelock/core/chains/plan.js'
import { UsageError } from '../args.ts'
import type { JobIo } from './client.ts'
import { apiClient, emitJson, jobIdArg, parseFlags, printLines, safeLine } from './client.ts'

export interface JobView { id: string; def: JobDef; state: JobState; leases: Partial<Record<Chain, LeaseView | null>>; seq: number; serverNowMs: number }

const DECIMALS: Readonly<Record<Chain, number>> = { eth: 18, sol: 9, btc: 8 }
const UNIT: Readonly<Record<Chain, string>> = { eth: 'ETH', sol: 'SOL', btc: 'BTC' }
const BASE: Readonly<Record<Chain, string>> = { eth: 'wei', sol: 'lamports', btc: 'sat' }
const DEC = /^(?:0|[1-9][0-9]{0,77})$/

export const iso = (ms: unknown): string => (typeof ms === 'number' && Number.isFinite(ms) ? new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z') : '?')
const secs = (ms: number): string => `${Math.round(ms / 1000)} s`
// A base-unit amount as "<base> <unit> (<native> <UNIT>)"; anything malformed is shown as '?'.
export function amount(c: Chain, v: unknown): string {
  if (typeof v !== 'string' || !DEC.test(v)) return '?'
  return `${v} ${BASE[c]} (${formatUnits(BigInt(v), DECIMALS[c])} ${UNIT[c]})`
}

export function renderArmed(a: ArmRecord | null, releaseAt: number | null, now: number): string[] {
  if (a === null) return ['  not armed']
  const at = releaseAt ?? a.releaseAt
  const order = (a.schedule?.order ?? []).map((c) => `${c} +${a.schedule.offsetSec?.[c] ?? 0} s`).join(', ')
  const when = at > now ? `in ${secs(at - now)}` : `${secs(now - at)} ago`
  return [`  armed ${iso(a.armedAt)}; release ${iso(at)} (${when}); order ${order}`]
}

function renderChain(id: string, c: Chain, cs: ChainState, a: ArmRecord | null, lease: LeaseView | null | undefined, now: number): string[] {
  const out: string[] = []
  const where = cs.copy === null ? '' : `  copy ${cs.copy} attempt ${cs.attempt}`
  const stuckTx = cs.openIntents.length === 1 ? cs.openIntents[0] : null
  out.push(`  ${c}  ${cs.phase}${cs.reason ? ` (${fillResolve(cs.reason, id, c, stuckTx)})` : ''}${where}  copies included ${cs.copiesIncluded}${cs.stopRequested ? '  stop requested' : ''}`)
  out.push(...stopLines(id, c, cs))
  const cap = a?.caps?.[c]
  out.push(`       spent ${amount(c, cs.spent)}${cap ? ` of the armed cap ${amount(c, cap.nativeCap)}` : ''}`)
  const open = cs.txs.filter((t) => t.state === 'open').length, stuck = cs.txs.filter((t) => t.state === 'stuck').length
  const landed = cs.txs.filter((t) => t.state === 'included').length
  out.push(`       txs ${cs.txs.length} (landed ${landed}, open ${open}, stuck ${stuck}); open intents ${cs.openIntents.length}`)
  // A btc copy is two transactions, the commit (part 1) and the reveal (part 2): each with its txid (the one that landed, else the
  // latest attempt), its state and the readback. Only public chain facts (txids, blocks, fees in sats): no key, no address.
  if (c === 'btc') {
    for (const t of cs.txs) {
      const txId = t.landedId ?? t.attempts.at(-1)?.txId ?? '?'
      const rb = t.readback === null ? 'pending' : t.readback ? 'ok' : 'NOT OK'
      out.push(`       copy ${t.copy} ${t.part === 1 ? 'commit' : 'reveal'}  ${txId}  ${t.state}${t.block ? `  block ${t.block}` : ''}${t.fee ? `  fee ${t.fee} sat` : ''}  readback ${rb}${t.attempts.length > 1 ? `  attempts ${t.attempts.length}` : ''}`)
    }
  }
  // A STUCK chain: its open attempts are what the operator may resolve (the API accepts exactly these).
  if (cs.phase === 'STUCK') {
    for (const txId of cs.openIntents) {
      const t = cs.txs.find((x) => x.attempts.some((y) => y.txId === txId))
      out.push(`       STUCK ${t === undefined ? 'claw-back' : `copy ${t.copy} part ${t.part}/${t.parts}`}: ${txId}`)
      out.push(c === 'btc'
        ? `             vt job resolve ${id} --chain btc --mark-failed   (only once the commit's input is spent in a block or the commit can never land; mark-done is refused for btc)`
        : `             vt job resolve ${id} --chain ${c} --tx ${txId} mark-done|mark-failed   (only from chain evidence you checked)`)
    }
  }
  if (cs.reassembled.length > 0) out.push(`       reassembled: ${cs.reassembled.map((r) => `copy ${r.copy} ${r.ok ? '✓' : '✗'}`).join(', ')}`)
  if (cs.clawback !== null) {
    const cb = cs.clawback
    out.push(`       claw-back ${cb.landed ? 'landed' : cb.ok === false ? 'failed' : 'in flight'}: ${amount(c, cb.value)} to ${cb.to} (${cb.txId})`)
  }
  if (lease) out.push(`       lease ${lease.holder} gen ${lease.gen} (${lease.expiresAt > now ? `expires in ${secs(lease.expiresAt - now)}` : 'expired'})`)
  return out
}

// R79b / M5c: a STOPPED chain's stop (ChainState.stopClass and stopCode; contracts/stop.ts): a resumable one names `vt job resume`, a
// final one its reason and the way out (the API's resume.final-stop words); a resumed chain that no run has reopened yet (its pre-start
// check failed, or no run since) says it is still STOPPED and that a run reopens it.
function stopLines(id: string, c: Chain, cs: ChainState): string[] {
  if (cs.phase !== 'STOPPED' || cs.stopClass === undefined) return []
  if (cs.stopClass !== 'resumable') return [`       ${finalStopText(c, stopClassOf(cs))}`]
  if (cs.stopLatched === true) return [`       stop ${cs.stopCode ?? '?'} (resumable): vt job resume ${id} --chain ${c} lifts it; then vt job run (or Run here) continues at the next part`]
  if (cs.stopRequested) return []
  return ['       resumed, but still STOPPED: the next vt job run (or Run here) reopens it once its pre-start checks pass; a check that failed journaled nothing and the resume still stands — run again']
}

// A stuck reason is journaled with placeholders (`vt job resolve <job> --chain btc --tx <txId> mark-failed`): fill them with the
// real job id and the stuck attempt's txid. A btc chain's exact next command is `--mark-failed` (mark-done is refused for btc).
export function fillResolve(text: string, jobId: string, chain: Chain, txId: string | null): string {
  let t = text
  if (chain === 'btc') t = t.replace(/vt job resolve <job> --chain btc --tx <txId> mark-failed/g, `vt job resolve ${jobId} --chain btc --mark-failed`)
  t = t.replace(/<job>/g, jobId)
  return txId === null ? t : t.replace(/<txId>/g, txId)
}

export function renderStatus(v: JobView): string {
  const now = v.serverNowMs
  const lines = [`job ${v.id}  ${v.def.network}  "${v.def.name}"  ${v.state.phase}${v.state.corrupt ? ` (CORRUPT: ${v.state.corrupt})` : ''}  seq ${v.seq}`]
  lines.push(`  message sha256 ${v.def.messageSha256}  ${v.def.messageBytes} bytes`)
  lines.push(...renderArmed(v.state.armed, v.state.releaseAt, now))
  for (const c of ['eth', 'sol', 'btc'] as const) {
    const cs = v.state.chains[c]
    if (cs !== undefined) lines.push(...renderChain(v.id, c, cs, v.state.armed, v.leases?.[c], now))
  }
  return lines.join('\n')
}

// ---- events

type Obj = Record<string, unknown>
const isObj = (x: unknown): x is Obj => x !== null && typeof x === 'object' && !Array.isArray(x)
const short = (x: unknown): string => {
  const s = typeof x === 'string' ? x : JSON.stringify(x) ?? String(x)
  return s.length > 200 ? `${s.slice(0, 200)}…` : s
}
// key=value for the data members (one level of nesting flattened: eth.nonce=5); long arrays summarised.
function fields(d: Obj, skip: readonly string[] = []): string {
  const parts: string[] = []
  for (const [k, x] of Object.entries(d)) {
    if (skip.includes(k)) continue
    if (isObj(x)) for (const [k2, y] of Object.entries(x)) parts.push(`${k}.${k2}=${short(y)}`)
    else if (Array.isArray(x) && x.length > 8) parts.push(`${k}=[${x.length} items]`)
    else parts.push(`${k}=${short(x)}`)
  }
  return parts.join(' ')
}

export function renderEvent(e: Obj, jobId?: string): string {
  const d = isObj(e.data) ? e.data : {}
  const head = `#${String(e.seq)} ${iso(e.at).slice(11, 19)} ${typeof e.chain === 'string' ? e.chain : 'job'} ${String(e.type)}${e.by !== 'api' && typeof e.by === 'string' ? ` [${e.by}${typeof e.gen === 'number' ? ` gen ${e.gen}` : ''}]` : ''}`
  switch (e.type) {
    case 'armed': {
      const a = d as unknown as ArmRecord
      const order = Array.isArray(a.schedule?.order) ? a.schedule.order.map((c) => `${c} +${a.schedule.offsetSec?.[c] ?? 0} s`).join(', ') : '?'
      return `${head} release ${iso(a.releaseAt)} (countdown ${String(a.countdownSec)} s); order ${order}`
    }
    case 'reassembled':
      return `${head} copy ${String(d.copy)} reassembled ${d.ok === true ? '✓' : '✗'} ${short(d.sha256)}`
    case 'intent':
      return `${head} copy ${String(d.copy)} part ${String(d.part)}/${String(d.parts)} attempt ${String(d.attempt)}${isObj(d.btc) && (d.btc.kind === 'commit' || d.btc.kind === 'reveal') ? ` ${d.btc.kind}` : ''} ${short(d.txId)}${d.replaces ? ` replaces ${short(d.replaces)}` : ''}`
    case 'included':
      return `${head} copy ${String(d.copy)} part ${String(d.part)} attempt ${String(d.attempt)} block ${short(d.block)} fee ${short(d.fee)} ${short(d.txId)}`
    case 'copy-built': {
      const bytes = Array.isArray(d.bytes) ? d.bytes.filter((b): b is number => typeof b === 'number') : []
      return `${head} copy ${String(d.copy)}: ${String(d.parts)} parts, ${bytes.reduce((a, b) => a + b, 0)} bytes${d.tight === true ? ', tight' : ''} ${fields(d, ['copy', 'parts', 'bytes', 'tight'])}`.trimEnd()
    }
    default: {
      if (e.type === 'stuck' && typeof d.reason === 'string' && jobId !== undefined && (e.chain === 'eth' || e.chain === 'sol' || e.chain === 'btc')) {
        return `${head} ${fields({ ...d, reason: fillResolve(d.reason, jobId, e.chain, typeof d.txId === 'string' ? d.txId : null) })}`
      }
      const f = fields(d)
      return f === '' ? head : `${head} ${f}`
    }
  }
}

// Event types after which the job may have become DONE (a chain closed, clawed back or skipped, or its last open attempt
// settled; the others only trigger a check: a stopped, drained or copies-done chain keeps the job ARMED, F18-2).
const SETTLING = new Set(['armed', 'close', 'clawback-included', 'clawback-failed', 'stopped', 'drained', 'copies-done', 'resolved', 'reconcile', 'included', 'lease-released'])

export async function watch(io: JobIo, id: string, o: { from: number; json: boolean; doneAt?: number | null }): Promise<number> {
  const api = apiClient(io)
  const ctl = new AbortController()
  const onAbort = (): void => ctl.abort()
  if (io.signal?.aborted === true) return 0
  io.signal?.addEventListener('abort', onAbort)
  // A job that is DONE: print its events up to its last seq, then stop.
  let doneAt = o.doneAt ?? null
  let last = o.from - 1
  let checking = false
  try {
    await api.stream(id, o.from, (line, e) => {
      io.out(`${safeLine(o.json ? line : renderEvent(e, id))}\n`)
      last = e.seq as number
      if (doneAt !== null && last >= doneAt) return true
      if (SETTLING.has(String(e.type)) && !checking) {
        checking = true
        void api.json<JobView>('GET', `/jobs/${id}`).then((r) => {
          if (r.value.state?.phase !== 'DONE') return
          doneAt = r.value.seq
          if (last >= doneAt) ctl.abort()
        }, () => {}).finally(() => { checking = false })
      }
      return false
    }, ctl.signal)
  } finally {
    io.signal?.removeEventListener('abort', onAbort)
  }
  return 0
}

const STATUS_USAGE = 'usage: vt job status <id> [--watch] [--json]'
const WATCH_USAGE = 'usage: vt job watch <id> [--from N] [--json]'

export async function statusCommand(args: readonly string[], io: JobIo): Promise<number> {
  const { flags, pos } = parseFlags(args, { valued: [], bool: ['--watch', '--json'], usage: STATUS_USAGE })
  if (pos.length !== 1) throw new UsageError(STATUS_USAGE)
  const id = jobIdArg(pos[0], STATUS_USAGE)
  const r = await apiClient(io).json<JobView>('GET', `/jobs/${id}`)
  if (flags.has('--json')) emitJson(io, r.text)
  else printLines(io, renderStatus(r.value))
  if (!flags.has('--watch')) return 0
  if (r.value.state?.phase === 'DONE') return 0
  return await watch(io, id, { from: r.value.seq + 1, json: flags.has('--json') })
}

export async function watchCommand(args: readonly string[], io: JobIo): Promise<number> {
  const { flags, pos } = parseFlags(args, { valued: ['--from'], bool: ['--json'], usage: WATCH_USAGE })
  if (pos.length !== 1) throw new UsageError(WATCH_USAGE)
  const id = jobIdArg(pos[0], WATCH_USAGE)
  const fromArg = flags.get('--from')
  const from = fromArg === undefined ? 0 : typeof fromArg === 'string' && /^(?:0|[1-9][0-9]{0,14})$/.test(fromArg) ? Number(fromArg) : null
  if (from === null) throw new UsageError(WATCH_USAGE)
  const r = await apiClient(io).json<JobView>('GET', `/jobs/${id}`)
  const done = r.value.state?.phase === 'DONE'
  if (done && from > r.value.seq) return 0
  return await watch(io, id, { from, json: flags.has('--json'), doneAt: done ? r.value.seq : null })
}

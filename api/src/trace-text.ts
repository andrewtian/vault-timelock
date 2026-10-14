// api/src/trace-text.ts — jobs/<id>/trace.txt, the ASCII text twin of a job's journal (spec §3.2, §12): what the
// operator reads with `cat`, regenerated from reduce(def, journal) after every append and whenever the journal is
// opened. Like broadcast's trigger twin (lifecycle/triggers.ts renderTraceText): ASCII only, public data only.
//   · Printable ASCII passes; backslash, CR, LF and TAB get short escapes; anything else becomes \uXXXX (UTF-16 units),
//     so free text (a reason) can neither forge a line nor bring non-ASCII into the twin. Network names use ' | ' for
//     the middle dot.
//   · It holds the job's ids, names, addresses, phases, tx ids, fees, blocks and readbacks: never the message text (only
//     its sha256), never an endpoint, never a key.
// The journal is the record; the twin is a convenience. It is written atomically (temp file 0600 + rename) without an
// fsync: a crash leaves at worst a stale twin, rewritten from the journal on the next append or open.
import { closeSync, constants, openSync, renameSync, unlinkSync, writeSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { join } from 'node:path'
import type { AttemptView, Chain, ChainState, JobDef, JobState, Network } from '@vault-timelock/core/contracts'
import { networkName } from 'vt-broadcast/src/config.ts'

export const TRACE_FILE = 'trace.txt'
const CHAINS: readonly Chain[] = ['eth', 'sol', 'btc']

export function esc(s: string): string {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c === 0x5c) out += '\\\\'
    else if (c === 0x0a) out += '\\n'
    else if (c === 0x0d) out += '\\r'
    else if (c === 0x09) out += '\\t'
    else if (c >= 0x20 && c < 0x7f) out += s[i]
    else out += `\\u${c.toString(16).padStart(4, '0')}`
  }
  return out
}
const val = (v: string | number | boolean | null | undefined): string => (v === null || v === undefined ? '-' : esc(String(v)))
function iso(ms: number | null): string {
  if (ms === null || !Number.isSafeInteger(ms)) return '-'
  try { return new Date(ms).toISOString() } catch { return val(ms) }
}
const asciiNetwork = (n: string): string => esc(n.replaceAll(' · ', ' | '))
const readbackText = (r: boolean | null): string => (r === true ? 'ok (byte-equal)' : r === false ? 'MISMATCH' : '-')

function attemptLine(a: AttemptView): string {
  const fee = a.eth !== undefined
    ? `eth nonce ${val(a.eth.nonce)} tip ${val(a.eth.tip)} maxFee ${val(a.eth.maxFee)} gas ${val(a.eth.gas)} to ${val(a.eth.to)}`
    : a.sol !== undefined
      ? `sol blockhash ${val(a.sol.blockhash)} lastValid ${val(a.sol.lastValidBlockHeight)} cuPrice ${val(a.sol.cuPrice)} cuLimit ${val(a.sol.cuLimit)} rung ${val(a.sol.rung)} fee ${val(a.sol.fee)}`
      : '-'
  return `      attempt ${val(a.txId)} gen ${val(a.gen)} ${val(a.state)} (${fee})`
}

function chainText(network: Network, c: Chain, def: JobDef, cs: ChainState, state: JobState): string {
  const d = def.chains[c]!
  const cap = state.armed?.caps[c]
  const mode = d.mode === 'drain' ? 'drain' : `copies ${val(d.mode.copies)}`
  const lines = [
    `chain ${c}: ${asciiNetwork(networkName(network, c))}`,
    `  phase: ${val(cs.phase)}${cs.reason === null ? '' : ` (${val(cs.reason)})`}`,
    `  key address: ${val(d.keyAddress)}`,
    `  mode: ${mode}; publish mode ${val(d.publishMode)}; fee strategy ${val(d.feeStrategy)}; distinct copies ${val(d.distinctCopies)}`,
    `  claw-back to: ${val(d.clawbackTo)}`,
    `  cap: ${cap === undefined ? '-' : `${val(cap.nativeCap)} base units (planned ${val(cap.planned)}, usd ${val(cap.usd)}, over cap ${cap.overCap ? 'yes' : 'no'})`}`,
    `  start: ${state.armed === null || !state.armed.schedule.order.includes(c) ? '-' : `release + ${val(state.armed.schedule.offsetSec[c])} s`}`,
    `  spent: ${val(cs.spent)} base units`,
    `  copy: ${val(cs.copy)}; attempt: ${val(cs.attempt)}; copies included: ${val(cs.copiesIncluded)}; resume: ${cs.resume === null ? '-' : `copy ${cs.resume.copy} part ${cs.resume.nextPart}`}`,
    `  reassembled: ${cs.reassembled.length === 0 ? '-' : cs.reassembled.map((r) => `copy ${r.copy} ${r.ok ? 'ok' : 'MISMATCH'}`).join(', ')}`,
    `  stop requested: ${cs.stopRequested ? 'yes' : 'no'}`,
    `  open intents: ${cs.openIntents.length === 0 ? '-' : cs.openIntents.map(val).join(' ')}`,
    `  txs: ${cs.txs.length}`,
  ]
  for (const t of cs.txs) {
    lines.push(`    copy ${t.copy} part ${t.part}/${t.parts}: ${val(t.state)}; landed ${val(t.landedId)}; block ${val(t.block)}; fee ${val(t.fee)}; readback ${readbackText(t.readback)}`)
    for (const a of t.attempts) lines.push(attemptLine(a))
  }
  const cb = cs.clawback
  lines.push(`  claw-back: ${cb === null ? '-' : `${val(cb.txId)} to ${val(cb.to)} value ${val(cb.value)} ${cb.ok === true ? 'ok' : cb.ok === false ? 'FAILED' : 'in flight'}`}`)
  return lines.join('\n') + '\n'
}

export function renderTrace(o: { id: string; def: JobDef; state: JobState; network: Network }): string {
  const { id, def, state, network } = o
  const a = state.armed
  const head = [
    `job ${val(id)}`,
    `name: ${val(def.name)}`,
    `network: ${val(network)}`,
    `message: sha256 ${val(def.messageSha256)}, ${val(def.messageBytes)} bytes`,
    `phase: ${val(state.phase)}${state.corrupt === null ? '' : ` (journal corrupt: ${val(state.corrupt)})`}`,
    `armed: ${a === null ? '-' : `${iso(a.armedAt)}; countdown ${val(a.countdownSec)} s; release ${iso(state.releaseAt)}; order ${a.schedule.order.map(val).join(', ')}`}`,
    `journal seq: ${val(state.seq)}`,
    '',
  ]
  const chains = CHAINS.filter((c) => def.chains[c] !== undefined && state.chains[c] !== undefined)
    .map((c) => chainText(network, c, def, state.chains[c]!, state))
  return head.join('\n') + '\n' + chains.join('\n')
}

// Atomic replace of <dir>/trace.txt (0600). Throws on an I/O error; the caller decides (the registry ignores it).
export function writeTrace(dir: string, text: string): void {
  const file = join(dir, TRACE_FILE)
  const tmp = `${file}.tmp.${process.pid}.${randomBytes(6).toString('hex')}`
  try {
    const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
    try {
      const bytes = Buffer.from(text, 'ascii')
      let off = 0
      while (off < bytes.length) {
        const n = writeSync(fd, bytes, off, bytes.length - off)
        if (!(n > 0)) throw new Error('the write made no progress')
        off += n
      }
    } finally {
      closeSync(fd)
    }
    renameSync(tmp, file)
  } catch (e) {
    try { unlinkSync(tmp) } catch { /* already gone */ }
    throw e
  }
}

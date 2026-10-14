// `vt-broadcast triggers ...` (spec B §6.6, Task T1): the operator's view of the trigger latch.
//   triggers list                        one summary line per trigger, oldest first
//   triggers show <id>                   the trace text (the same text as $OUT/triggers/<id>.txt)
//   triggers clear <id>                  every chain terminal; a mainnet record asks for the typed word `clear`
//   triggers resolve <id> <dest> mark-done <tx> [--block <b>] [--confirmations <n>] | mark-failed | mark-not-broadcast
//                                        prints the evidence it has first; a mainnet record asks for `resolve`
//   triggers reset-latch                 the exit from a latch the gate cannot use (T1 review I2): resets it to
//                                        { open: null } only if it is malformed or names a missing record (else
//                                        trigger.reset-latch); records are never touched and the gate still scans them
// The typed word comes from /dev/tty only (no terminal: the core refuses trigger.clear-typed); the RECORD's profile
// decides whether one is needed, never VT_PROFILE. Prints only trace text and summary lines. There is no chain adapter
// in this build (Tasks 13-15), so mark-done from the CLI is operator-attested (readback null; block and confirmations
// as typed, or null).
import { systemClock } from './clock.ts'
import { resolveOut } from './paths.ts'
import { createStore } from './store.ts'
import { clearTrigger, listTriggers, readTrigger, renderChainText, renderTraceText, resetLatch, resolveTrigger, summarizeTrigger } from './triggers.ts'
import type { ChainTrace, Dest, ResolveAction, Trigger } from './triggers.ts'
import { readTypedWord } from './typed.ts'

const POS_INT = /^[1-9][0-9]{0,8}$/
const write = (s: string) => { process.stdout.write(s) }
const value = (a: string | undefined): a is string => a !== undefined && a !== '' && !a.startsWith('--')

interface Resolve { id: string; dest: string; action: ResolveAction }
function parseResolve(rest: readonly string[], usage: () => never): Resolve {
  const [id, dest, action, ...more] = rest
  if (!value(id) || !value(dest)) usage()
  if (action === 'mark-failed' || action === 'mark-not-broadcast') {
    if (more.length > 0) usage()
    return { id, dest, action: { action } }
  }
  if (action !== 'mark-done') usage()
  const [tx, ...flags] = more
  if (!value(tx)) usage()
  let block: string | null = null
  let confirmations: number | null = null
  for (let i = 0; i < flags.length; i += 2) {
    const [flag, v] = [flags[i], flags[i + 1]]
    if (flag === '--block' && block === null && value(v)) block = v
    else if (flag === '--confirmations' && confirmations === null && v !== undefined && POS_INT.test(v)) confirmations = Number(v)
    else usage()
  }
  return { id, dest, action: { action: 'mark-done', tx, block, confirmations, readback: null } }
}

function evidenceText(tr: Trigger, dest: string, c: ChainTrace | undefined): string {
  if (c === undefined) return `evidence for ${tr.id}: none (not a chain of this trigger)\n`
  const observed = c.state === 'planned'
    ? 'none (the chain is planned: nothing was ever submitted)'
    : 'none from the CLI in this build (no chain adapter yet): mark-done is recorded as operator-attested, readback not checked'
  return `evidence for ${dest} of ${tr.id}:\n${renderChainText(c)}observed evidence: ${observed}\n`
}

export async function triggersCmd(args: readonly string[], env: Readonly<Record<string, string | undefined>>, usage: () => never): Promise<void> {
  const [sub, ...rest] = args
  const out = resolveOut(env)
  const t = { out, store: createStore(out) }
  if (sub === 'list') {
    if (rest.length > 0) usage()
    const all = await listTriggers(t)
    write(all.length === 0 ? 'no triggers\n' : all.map((tr) => summarizeTrigger(tr) + '\n').join(''))
  } else if (sub === 'show') {
    if (rest.length !== 1) usage()
    write(renderTraceText(await readTrigger(t, rest[0])))
  } else if (sub === 'clear') {
    if (rest.length !== 1) usage()
    const tr = await readTrigger(t, rest[0])
    let typed: string | undefined
    if (tr.profile === 'mainnet') {
      write(renderTraceText(tr))
      typed = await readTypedWord('Type "clear" to confirm: ')
    }
    const after = await clearTrigger(t, tr.id, typed === undefined ? { by: 'cli' } : { by: 'cli', typed }, systemClock)
    write(summarizeTrigger(after) + '\n')
  } else if (sub === 'resolve') {
    const r = parseResolve(rest, usage)
    const tr = await readTrigger(t, r.id)
    const c = tr.chains.find((x) => x.dest === r.dest)
    write(evidenceText(tr, r.dest, c))
    let typed: string | undefined
    if (tr.profile === 'mainnet' && c !== undefined) typed = await readTypedWord('Type "resolve" to confirm: ')
    const after = await resolveTrigger(t, tr.id, r.dest as Dest, r.action, typed === undefined ? { by: 'cli' } : { by: 'cli', typed }, systemClock)
    const now = after.chains.find((x) => x.dest === r.dest)
    if (now !== undefined) write(`resolved ${now.dest} of ${after.id}: ${now.state}\n${renderChainText(now)}${summarizeTrigger(after)}\n`)
  } else if (sub === 'reset-latch') {
    if (rest.length > 0) usage()
    const r = await resetLatch(t)
    write(r.was === 'malformed'
      ? 'latch reset to { open: null }: it was malformed\n'
      : `latch reset to { open: null }: it named ${r.named}, whose record lifecycle/trigger/${r.named}.json is missing (its last text twin, if any: triggers/${r.named}.txt)\n`)
    write('the gate still scans every trigger record: vt-broadcast triggers list\n')
  } else usage()
}

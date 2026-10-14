// cli/src/job/clawback.ts — `vt job clawback <id> --chain eth|sol --to <address> --backup-<chain> <file>`: send what is
// left on a settled chain's key to an address the operator names (spec §3.3 step 6, §8; CC-2a; plan Task C6). The same
// executor sandbox, terminal, lock, key loading and Ctrl-C rule as `vt job run` (run.ts).
//
// In order (nothing is decrypted before step 4, nothing is signed before step 8):
//   1. stdin and /dev/tty are a terminal (vt.tty-required); mainnet is refused while the job-send lock is on
//      (release.mainnet-locked); the job and the API are on this network (executor.network-mismatch);
//   2. the chain has settled — DRAINED, COPIES_DONE or STOPPED, or CLAWING_BACK to finish one (job.state); a chain
//      CLAWED_BACK already says so and exits 0;
//   3. the destination (job.clawback), before any key is touched: ETH an EIP-55 checksummed address, SOL a canonical
//      32-byte base58 address; never the lane's own key, never an address nobody controls (ETH 0x0…0 and 0x…dEaD, SOL
//      the System Program and the incinerator); never an ETH address at or below 0xffff (job.clawback-precompile:
//      the precompiles 0x01–0x11 and any future one; they hold no code, so the contract check below would pass them,
//      and value sent there is lost); and exactly the job's clawbackTo when the job names one;
//   4. the key backup and its passphrase, as run.ts (vt.backup-format, backup.*, backup.network);
//   5. through this network's relay (the relay must be on this network with this chain's identity verified): ETH — the
//      destination's class: a contract is refused (job.clawback); the gas is 21,000 to an existing account, and
//      204,600 to an EMPTY one where Amsterdam is active on this network (ethAmsterdam; EIP-8037), shown before anything;
//      the lane's balance = value + worst-case fee (the claw-back empties the lane: ETH value = balance − gas × maxFee;
//      SOL value = balance − fee);
//   6. that amount against what is left of the ARMED cap (nativeCap − spent − a landed claw-back's value, core
//      checkClawbackConfirm's room): when it does not fit, the operator types the amount EXACTLY (shown in full
//      precision, compared in base units, no rounding: arm.amount), and it rides as clawbackConfirm { amount } in base
//      units beside the clawback-intent only — a one-off approval of THIS claw-back, never a raised cap. The engine
//      (engine.cap-clawback) and the API (arm.amount) check it again at signing: if the balance moved meanwhile, nothing
//      is signed;
//   7. the linkage warning (R47/R57: the claw-back links the lane key to the destination on-chain), and on mainnet the
//      words `claw back` typed (job.clawback-typed);
//   8. E3's executor clawback(to): the network and key checks, the lease, reconcile every open intent first, then the
//      engine's claw-back at the lane's fee strategy. Ctrl-C asks it to stop and vt waits for the outcome.
import type { Chain, Network } from '@vault-timelock/core/contracts'
import { ethAmsterdam, refuse } from '@vault-timelock/core/contracts'
import { createExecutor } from '@vault-timelock/core/executor'
import { nodeAdapter } from '@vault-timelock/core/executor/node'
import { useRelayClient } from '@vault-timelock/core/engine/rpc.js'
import * as eth from '@vault-timelock/core/chains/eth.js'
import * as sol from '@vault-timelock/core/chains/sol.js'
import { ethClawGas, validateEthDest, validateSolDest } from '@vault-timelock/core/chains/economy.js'
import { ethReservedKind, solReservedKind } from '@vault-timelock/core/chains/reserved.js'
import { CANON } from '@vault-timelock/core/chains/constants.js'
import { formatUnits } from '@vault-timelock/core/chains/plan.js'
import { UsageError } from '../args.ts'
import { assertNetworks, sameAmount } from './arm.ts'
import type { JobIo } from './client.ts'
import { chainArg, jobIdArg, parseFlags } from './client.ts'
import { renderEvent } from './status.ts'
import type { RunDeps, Session } from './run.ts'
import { afterSending, controls, loadKeys, openSession, progress } from './run.ts'
import { processSignals } from './tty.ts'

const USAGE = 'usage: vt job clawback <id> --chain eth|sol --to <address> --backup-<chain> <file>'
const DECIMALS: Readonly<Record<Chain, number>> = { eth: 18, sol: 9, btc: 8 }
const UNIT: Readonly<Record<Chain, string>> = { eth: 'ETH', sol: 'SOL', btc: 'BTC' }
const BASE: Readonly<Record<Chain, string>> = { eth: 'wei', sol: 'lamports', btc: 'sat' }
const CLAW_PHASES = new Set(['DRAINED', 'COPIES_DONE', 'STOPPED', 'CLAWING_BACK'])
const same = (c: Chain, a: string, b: string): boolean => (c === 'eth' ? a.toLowerCase() === b.toLowerCase() : a === b)

function assertDestination(ok: boolean, why: string): void {
  if (!ok) refuse('job.clawback', why) // @guard:job.clawback
}
function assertNotPrecompile(ok: boolean): void {
  if (!ok) refuse('job.clawback-precompile', 'the claw-back destination is an Ethereum precompile or reserved system address (0x…0001 to 0x…ffff): nobody controls it and value sent there is lost; nothing was read or signed') // @guard:job.clawback-precompile
}
function assertSettled(ok: boolean, why: string): void {
  if (!ok) refuse('job.state', why) // @guard:job.state
}
function assertTypedAmount(ok: boolean, why: string): void {
  if (!ok) refuse('arm.amount', why) // @guard:arm.amount
}
function assertTypedWords(ok: boolean, why: string): void {
  if (!ok) refuse('job.clawback-typed', why) // @guard:job.clawback-typed
}

// The destination rules (step 3), exported for the tests: the normalised address, or a refusal (job.clawback).
export function checkDestination(c: Chain, to: string, lane: string, clawbackTo: string | null): string {
  const v = c === 'eth' ? validateEthDest(to, lane) : validateSolDest(to, lane)
  assertDestination(v.ok, `the claw-back destination is refused: ${v.why ?? ''}; nothing was read or signed`)
  const addr = v.address!
  const kind = c === 'eth' ? ethReservedKind(addr) : solReservedKind(addr) // core's one source (chains/reserved.js)
  assertDestination(kind === null || kind === 'precompile', 'the claw-back destination is an address nobody controls (funds sent there are burned); nothing was read or signed')
  assertNotPrecompile(kind !== 'precompile')
  assertDestination(!same(c, addr, lane), 'the claw-back destination is the lane\'s own key; nothing was read or signed')
  assertDestination(clawbackTo === null || same(c, addr, clawbackTo), `this job sends its ${c} claw-back only to its clawbackTo, ${clawbackTo}; nothing was read or signed`)
  return addr
}

interface ClawArgs { id: string; chain: Chain; to: string; backup: string }
function parseClawArgs(args: readonly string[]): ClawArgs {
  const { flags, pos } = parseFlags(args, { valued: ['--chain', '--to', '--backup-eth', '--backup-sol', '--backup-btc'], bool: [], usage: USAGE })
  if (pos.length !== 1) throw new UsageError(USAGE)
  const id = jobIdArg(pos[0], USAGE)
  const cv = flags.get('--chain')
  const chain = chainArg(typeof cv === 'string' ? cv : undefined, USAGE)
  if (chain === 'btc') throw new UsageError('vt job clawback --chain btc is not available yet: the btc lane runs copies only and has no claw-back (the lane\'s remainder stays on its key; keep the backup); nothing was read or signed')
  const to = flags.get('--to')
  if (typeof to !== 'string' || to === '') throw new UsageError(`${USAGE} (--to: the destination address)`)
  const other: Chain = chain === 'eth' ? 'sol' : 'eth'
  if (flags.has(`--backup-${other}`)) throw new UsageError(`${USAGE} (a ${chain} claw-back takes --backup-${chain}, not --backup-${other})`)
  const backup = flags.get(`--backup-${chain}`)
  if (typeof backup !== 'string') throw new UsageError(`${USAGE} (--backup-${chain} <file> names the key backup)`)
  return { id, chain, to, backup }
}

export async function clawbackCommand(args: readonly string[], io: JobIo, deps: RunDeps = {}): Promise<number> {
  const a = parseClawArgs(args)
  const s = await openSession(io, a.id, deps, 'clawback')
  try { return await clawbackSession(a, s, io, deps) } finally { s.close() }
}

async function clawbackSession(a: ClawArgs, s: Session, io: JobIo, deps: RunDeps): Promise<number> {
  const { def, out, n } = s
  const c = a.chain
  const ch = def.chains[c]
  if (ch === undefined) throw new UsageError(`job ${a.id} has no ${c} chain (--chain)`)
  const cs = s.state.chains[c]!
  if (cs.phase === 'CLAWED_BACK') { out.line(`${c}: already clawed back${cs.clawback ? ` (${formatUnits(BigInt(cs.clawback.value || '0'), DECIMALS[c])} ${UNIT[c]} to ${cs.clawback.to})` : ''}`); return 0 }
  // 2. a settled chain
  assertSettled(CLAW_PHASES.has(cs.phase), `claw back is for a settled chain (drained, copies done or stopped): ${c} is ${cs.phase}; stop it first (vt job stop ${a.id} --chain ${c}) and let the in-flight transaction resolve`)
  // 3. the destination, before any key is touched
  const dest = checkDestination(c, a.to, ch.keyAddress, ch.clawbackTo)
  // 4. the key
  s.held.chains.push(c)
  const keys = await loadKeys({ io, tty: s.tty, out, def, jobId: a.id, chains: [c], files: { [c]: a.backup }, held: s.held, ...(deps.onKey ? { onKey: deps.onKey } : {}) })
  deps.fault?.('keys')
  let ex: ReturnType<typeof createExecutor> | null = null
  try {
    // 5. the relay's reads: this network, this chain's identity; the destination class; the lane's balance
    const rs = await s.relay.status()
    assertNetworks(rs.network === n && rs.identity?.[c]?.ok === true, `the ${n} relay is on another network, or has not verified the ${c} chain's identity; nothing was signed (vt status --network ${n})`)
    useRelayClient(s.relay)
    out.line(`claw back job ${a.id} ${c}: the remainder of ${ch.keyAddress} to ${dest}, at the lane's fee strategy (${ch.feeStrategy})`)
    if (c === 'eth') {
      const cls = await eth.accountClass(dest)
      assertDestination(!cls.code, 'the claw-back destination is a contract: refused (use a plain account); nothing was signed')
      const amsterdam = ethAmsterdam(n)
      const gas = ethClawGas({ amsterdam, empty: cls.empty })
      out.line(`  gas ${gas}: the destination is ${cls.empty ? 'EMPTY (a fresh account)' : 'an existing account'}; Amsterdam is ${amsterdam ? 'active' : 'not active'} on ${n}${gas > CANON.ETH_CLAW_GAS_EXISTING ? ` — a fresh destination costs ${gas} gas after Amsterdam (EIP-8037), about 10× an existing one` : ''}`)
    } else {
      out.line('  a plain transfer of balance − fee: the lane ends at 0 lamports; a new destination needs at least the rent-exempt minimum')
    }
    const balance = c === 'eth' ? await eth.balance(ch.keyAddress) : await sol.solBalance(ch.keyAddress)
    if (balance <= 0n) { out.line(`${c}: nothing to claw back (the lane holds 0 ${BASE[c]})`); return 1 }
    // 6. the armed cap
    const cap = BigInt(s.state.armed?.caps?.[c]?.nativeCap ?? '0')
    const landed = cs.clawback?.landed === true ? BigInt(cs.clawback.value || '0') : 0n
    const room = cap - BigInt(cs.spent || '0') - landed
    const need = balance
    const shown = formatUnits(need, DECIMALS[c])
    out.line(`  remainder (value + fee) ${shown} ${UNIT[c]} (= ${need} ${BASE[c]}); left of the armed cap ${formatUnits(room < 0n ? 0n : room, DECIMALS[c])} ${UNIT[c]}`)
    let confirm: { amount: string } | undefined
    if (need > room) {
      const w = await s.tty.word(`${c}: the remainder is over what is left of the cap confirmed at Arm. Type ${shown} to approve clawing back exactly this amount (${need} ${BASE[c]}): `, 'amount')
      assertTypedAmount(w !== undefined && sameAmount(c, w, shown), `the typed amount is not exactly ${shown} ${UNIT[c]} (= ${need} ${BASE[c]}); nothing was signed`)
      confirm = { amount: String(need) }
    }
    // 7. the linkage warning; mainnet: claw back typed
    out.note(`warning: this claw-back links the lane key ${ch.keyAddress} to ${dest} on-chain, publicly and for good (R47/R57)`)
    if (n === 'mainnet') {
      const w = await s.tty.word(`MAINNET: real funds. Type claw back to send ${shown} ${UNIT[c]} (value + fee) to ${dest}: `, 'clawback')
      assertTypedWords(w === 'claw back', 'a mainnet claw-back needs the words claw back typed at the terminal; nothing was signed')
    }
    // 8. the executor's claw-back
    const { clock, random } = deps.adapter ?? nodeAdapter()
    const show = progress(out, () => io.now())
    ex = createExecutor({ jobId: a.id, chain: c, key: keys.get(c)!, holder: 'cli', deps: {
      journal: s.journal, relay: s.relay, clock, random, onView: (v) => show(c, v),
      ...(confirm !== undefined ? { clawbackConfirm: confirm } : {}),
      ...(deps.poll !== undefined ? { poll: deps.poll } : {}), ...(deps.passiveWaitMs !== undefined ? { passiveWaitMs: deps.passiveWaitMs } : {}),
    } })
    const x = ex
    const release = controls({ out, tty: s.tty, signals: deps.signals ?? processSignals, stop: () => x.requestStop() })
    let unstream = (): void => {}
    try { unstream = s.journal.stream(a.id, s.seq + 1, (e) => { if (e.chain === c) out.line(renderEvent(e as unknown as Record<string, unknown>)) }) } catch { /* no stream */ }
    // review m-2: an end other than clawed-back (the executor's `failed` is its catch-all for an error) after this run
    // journaled the claw-back intent says so: the next `vt job clawback` reconciles it first
    const unexpected = (): void => { if (s.held.sent.has(c)) out.line(`${c}: ${afterSending('clawback')}`) }
    let outcome
    try {
      outcome = await x.clawback(dest)
    } catch (e) {
      unexpected()
      throw e
    } finally { release(); unstream() }
    const note = x.view().note
    out.line(`${c}: ${outcome}${note ? ` — ${note}` : ''}`)
    if (outcome !== 'clawed-back') unexpected()
    return outcome === 'clawed-back' ? 0 : 1
  } finally {
    ex = null // the keys, the passphrase and the printer's secrets: s.close() (clawbackCommand)
  }
}

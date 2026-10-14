// cli/src/job/arm.ts — `vt job arm <id> [--chains eth,sol,btc] [--source eth=a,sol=b,btc=c] [--countdown S] [--stagger MIN,MAX]
// [--json]` (spec §3.3 step 3, §5.4, §8; plan Task C5).
//
// In order (nothing is armed until the last step):
//   1. MAINNET IS REFUSED WHILE THE JOB-SEND LOCK IS ON (C2 assertJobSendAllowed: release.mainnet-locked), before
//      anything is read or asked. The API re-checks it at arm, and the relay at every send.
//   2. The job, the API and the relay are on this network, and the relay verified each armed chain's identity
//      (executor.network-mismatch). Each armed chain is READY (its executor loaded the key and saw the funds).
//   3. Caps: core computeArmCaps over the job's text (GET /messages/<sha256>, digest-checked, strictly decoded) and
//      the relay's reads (price, the lane strategy's starting fees, the key's balance, SOL rent), exactly as an executor
//      would quote one copy before Arm (assess.js; nothing text-bearing leaves the machine). A chain whose one full copy
//      is not affordable within its cap is not armed.
//   4. Chains NOT armed (--chains names a subset) become SKIPPED at the arm: terminal, no funds touched, and they can
//      never be armed later in this job. vt says so before asking anything.
//   5. Typed confirmations, read from the TERMINAL only (vt-broadcast readTypedWord: /dev/tty, never stdin, argv or the
//      environment; no terminal: vt.tty-required):
//      · mainnet: the word `broadcast` (arm.typed);
//      · every chain over the R60 cap: its planned spend, typed EXACTLY. vt shows `planned` in full (computeArmCaps
//        renders it with every decimal the chain has, up to 18 for ETH, never rounded) and compares the typed amount in
//        BASE UNITS (parsed without rounding: no more decimals than the chain has), so 0.0040 and 0.004 are the same
//        amount and 0.0039999999999999999 is not (arm.amount). The API compares it again, exactly, to nativeCap.
//      PF-C / M-5 (the page's Arm dialog, ArmDialog.jsx, asks the same):
//      · key history: a lane key that already sent transactions (ETH nonce > 0, SOL signed memos > 0; read through the relay as
//        armInputs.js does; BTC: none, as the page) needs the word `again` typed PER chain with history (arm.again);
//      · mainnet: the five pre-flight ticks (MAINNET_TICKS of web/src/status/readiness.js: Backups, Funds, Permanence, Release,
//        Pre-flight; one wording, pinned by a test) are shown and the word `ticks` is typed (arm.ticks);
//      · testnet and mainnet: the relay must report IsTor (arm.tor), checked before anything is asked.
//   6. core checkArmConfirm (arm.*), then POST /jobs/<id>/arm with the ArmRequest (caps as the contract's ArmCap).
import type { ArmCap, ArmRecord, ArmRequest, Chain, JobChainDef, Network, RelayClient, Status } from '@vault-timelock/core/contracts'
import { isRefusal, refuse } from '@vault-timelock/core/contracts'
import { checkArmConfirm, sha256Hex } from '@vault-timelock/core/job'
import { delegatedFromJobs, delegatedRows, httpRelayClient } from '@vault-timelock/core/executor'
import { computeArmCaps, toArmCap } from '@vault-timelock/core/engine/arm-caps.js'
import { useRelayClient } from '@vault-timelock/core/engine/rpc.js'
import { startingFees } from '@vault-timelock/core/engine/assess.js'
import * as eth from '@vault-timelock/core/chains/eth.js'
import * as sol from '@vault-timelock/core/chains/sol.js'
import * as btc from '@vault-timelock/core/chains/btc.js'
import { NETWORK } from '@vault-timelock/core/chains/constants.js'
import { parseDecimal } from '@vault-timelock/core/chains/plan.js'
import { assertJobSendAllowed } from 'vt-broadcast/src/config.ts'
import { UsageError } from '../args.ts'
import type { JobIo } from './client.ts'
import type { WordKind } from './tty.ts'
import { apiClient, assertTerminal, emitJson, jobIdArg, parseFlags, printLines, refusalFrom } from './client.ts'
import { iso } from './status.ts'
import type { JobView } from './status.ts'
import { assertDigest, decodeMessage } from './validate.ts'

const USAGE = 'usage: vt job arm <id> [--chains eth,sol,btc] [--source eth=a,sol=b,btc=c] [--countdown S] [--stagger MIN,MAX] [--json]'
const CHAINS: readonly Chain[] = ['eth', 'sol', 'btc']
const DECIMALS: Readonly<Record<Chain, number>> = { eth: 18, sol: 9, btc: 8 }
const UNIT: Readonly<Record<Chain, string>> = { eth: 'ETH', sol: 'SOL', btc: 'BTC' }
const BASE: Readonly<Record<Chain, string>> = { eth: 'wei', sol: 'lamports', btc: 'sat' }
// The page's five mainnet ticks (web/src/status/readiness.js MAINNET_TICKS), word for word (test/job-client.test.ts pins the equality).
export const MAINNET_TICKS: ReadonlyArray<{ id: string; name: string; label: string }> = [
  { id: 'backup', name: 'Backups', label: 'Every lane key’s backup is saved, re-selected and verified, and kept off this machine.' },
  { id: 'funds', name: 'Funds', label: 'I fund only what I am willing to spend: the per-job cap is shown again at Arm.' },
  { id: 'permanence', name: 'Permanence', label: 'The text is public at once, permanently, and cannot be taken back.' },
  { id: 'release', name: 'Release', label: 'I ran vt release verify on this release and the digests match.' },
  { id: 'preflight', name: 'Pre-flight', label: 'I read the pre-flight table above; every row is ✓ or I understand why not.' },
]
export const TICKS_WORD = 'ticks'
export const AGAIN_WORD = 'again'

// arm.again: the typed word for a chain whose key already sent transactions.
export function assertAgain(c: Chain, history: number, typed: string): void {
  if (history > 0 && typed !== AGAIN_WORD) refuse('arm.again', `${c}: the lane key already sent transactions (${history}); arming it again can publish the text again. Type again to confirm`) // @guard:arm.again
}
// arm.ticks: the acknowledgement of the five mainnet ticks.
export function assertTicks(network: Network, typed: string | null): void {
  if (network === 'mainnet' && typed !== TICKS_WORD) refuse('arm.ticks', `mainnet needs the five pre-flight ticks acknowledged: type ${TICKS_WORD}`) // @guard:arm.ticks
}
// arm.tor: testnet and mainnet publish only through Tor.
export function assertTor(network: Network, isTor: boolean | null): void {
  if (network !== 'local' && isTor !== true) refuse('arm.tor', `the ${network} relay does not report IsTor${isTor === false ? ' ✗: it is not reaching the network through Tor' : ' (unknown: Tor is not confirmed yet)'}; nothing was armed (vt preflight --network ${network})`) // @guard:arm.tor
}

// The key history the page reads (armInputs.js): ETH nonce, SOL signed memos; BTC 0. A failed read refuses (fail closed).
export async function keyHistory(c: Chain, address: string): Promise<number> {
  try {
    return c === 'eth' ? await eth.nonceAt(address, 'latest') : c === 'sol' ? await sol.sentCount(address) : 0
  } catch (e) {
    throw new Error(`${c}: the key's history cannot be read through the relay (${e instanceof Error ? e.message.slice(0, 120) : 'error'}); nothing was armed`)
  }
}

const NATIVE = /^[0-9]{1,40}(?:\.[0-9]{1,40})?$/

export interface ArmDeps {
  relay?: RelayClient
  // The client-side job-send lock check (default: C2's assertJobSendAllowed). Tests of the mainnet typed flow pass
  // their own; the API (arm) and the relay (every send) enforce the real lock whatever a client does.
  assertSendAllowed?: (n: Network) => void
}

export function assertNetworks(ok: boolean, why: string): void {
  if (!ok) refuse('executor.network-mismatch', why) // @guard:executor.network-mismatch
}

// The typed native amount equals `planned` in base units (exact parse, no rounding; no more decimals than the chain).
export function sameAmount(c: Chain, typed: string, planned: string): boolean {
  if (!NATIVE.test(typed) || !NATIVE.test(planned)) return false
  try { return parseDecimal(typed, DECIMALS[c]) === parseDecimal(planned, DECIMALS[c]) } catch { return false }
}

interface Args { id: string; chains: Chain[] | null; sources: Partial<Record<Chain, string>> | null; countdownSec?: number; stagger?: [number, number]; json: boolean }

function parseArmArgs(args: readonly string[]): Args {
  const { flags, pos } = parseFlags(args, { valued: ['--chains', '--source', '--countdown', '--stagger'], bool: ['--json'], usage: USAGE })
  if (pos.length !== 1) throw new UsageError(USAGE)
  const id = jobIdArg(pos[0], USAGE)
  const list = flags.get('--chains')
  let chains: Chain[] | null = null
  if (typeof list === 'string') {
    const cs = list.split(',')
    if (!cs.every((c) => c === 'eth' || c === 'sol' || c === 'btc') || new Set(cs).size !== cs.length) throw new UsageError(`${USAGE} (--chains: a list of eth, sol, btc)`)
    chains = CHAINS.filter((c) => (cs as string[]).includes(c))
  }
  const src = flags.get('--source')
  let sources: Partial<Record<Chain, string>> | null = null
  if (typeof src === 'string') {
    sources = {}
    for (const item of src.split(',')) {
      const m = /^(eth|sol|btc)=([A-Za-z0-9._-]{1,64})$/.exec(item)
      if (m === null || Object.hasOwn(sources, m[1])) throw new UsageError(`${USAGE} (--source: chain=label, labels A-Z a-z 0-9 . _ -)`)
      sources[m[1] as Chain] = m[2]
    }
  }
  const int = (v: string | true | undefined): number | undefined => {
    if (v === undefined) return undefined
    if (typeof v !== 'string' || !/^(?:0|[1-9][0-9]{0,5})$/.test(v)) throw new UsageError(USAGE)
    return Number(v)
  }
  const countdownSec = int(flags.get('--countdown'))
  const st = flags.get('--stagger')
  let stagger: [number, number] | undefined
  if (st !== undefined) {
    const parts = typeof st === 'string' ? st.split(',') : []
    if (parts.length !== 2) throw new UsageError(USAGE)
    stagger = [int(parts[0])!, int(parts[1])!]
  }
  return { id, chains, sources, ...(countdownSec === undefined ? {} : { countdownSec }), ...(stagger === undefined ? {} : { stagger }), json: flags.has('--json') }
}

export interface BtcFees { rate: bigint; commitFee: bigint; revealFee: bigint; postage: bigint }
export type CapRow = ArmCap & { fullCopyCost: string; parts: number; affordable: boolean; notAffordableBecause?: 'balance' | 'cap'; capVia?: string; ceilingSatVb?: number; ceilingFromJob?: boolean }
export interface Plan { caps: Record<string, CapRow>; priced: boolean; btc?: BtcFees }

// computeArmCaps for the armed chains, from the relay's reads.
export async function planCaps(view: JobView, chains: readonly Chain[], text: string, relay: RelayClient, n: Network, now: number): Promise<Plan> {
  useRelayClient(relay)
  const def = { ...view.def, chains: Object.fromEntries(chains.map((c) => [c, view.def.chains[c]])) }
  let prices: unknown = null
  try { prices = await relay.price() } catch { prices = null }
  const fees: Record<string, unknown> = {}
  const balances: Record<string, bigint> = {}
  let btcFees: BtcFees | undefined
  for (const c of chains) {
    const ch = view.def.chains[c]!
    // The lane strategy's starting fees: core's one source (assess.js startingFees), as an executor quotes one copy
    // before Arm and as the page prices it. ETH passive = the 24 h base-fee target + the passive tip; economy = next
    // base + the network's tip floor; prompt = the p50 tip under the job's maxTipGwei (3 gwei when the job sets none). SOL = rent + the strategy's
    // priority lamports (prompt only).
    if (c === 'btc') {
      // core's startingFees btc: the node's fee rate (clamped to the job's maxFeeRateSatVb) and the worst case of one copy, a commit
      // and its reveal, in sats, plus the postage that stays on each inscription. Read through the relay, which talks to bitcoind.
      const bytes = new TextEncoder().encode(text)
      const sha = sha256Hex(bytes), copies = typeof ch.mode === 'object' ? ch.mode.copies : null
      const widest = ch.distinctCopies ? (copies !== null ? (copies >= 2 ? { copy: copies, copies } : null) : { copy: 9999, copies: null }) : null
      const r = await startingFees(n, 'btc', ch.feeStrategy, {
        parts: btc.planBtcCopy(bytes, { sha256: sha, copy: null, copies: null }),
        ...(widest !== null ? { altParts: btc.planBtcCopy(bytes, { sha256: sha, ...widest }) } : {}),
        ...(ch.maxFeeRateSatVb !== undefined ? { maxFeeRateSatVb: ch.maxFeeRateSatVb } : {}),
      })
      fees.btc = r.fees
      btcFees = r.fees
      balances.btc = await btc.balanceOf(ch.keyAddress)
    } else if (c === 'eth') {
      fees.eth = (await startingFees(n, 'eth', ch.feeStrategy, ch.maxTipGwei !== undefined ? { maxTipGwei: ch.maxTipGwei } : {})).fees
      balances.eth = await eth.balance(ch.keyAddress)
    } else {
      fees.sol = (await startingFees(n, 'sol', ch.feeStrategy)).fees
      balances.sol = await sol.solBalance(ch.keyAddress)
    }
  }
  let caps: Plan['caps']
  try {
    caps = computeArmCaps(def as typeof view.def, text, { prices, fees, balances, network: n, now })
  } catch (e) {
    throw new Error(`the caps cannot be computed: ${e instanceof Error ? e.message : String(e)}`)
  }
  return { caps, priced: Object.values(caps).some((c) => c.priceAt !== null), ...(btcFees === undefined ? {} : { btc: btcFees }) }
}

// The refusal when one worst-case copy is not affordable: says whether it is the balance or the cap, and (btc) the fee-rate ceiling it is priced at.
export function notAffordableMessage(c: Chain, cp: CapRow, jobId: string): string {
  const why = cp.notAffordableBecause === 'balance' ? 'the lane balance is below one worst-case copy' : cp.notAffordableBecause === 'cap' ? 'one worst-case copy is above the cap' : 'balance and cap: see vt job status'
  const ceil = c === 'btc' && cp.ceilingSatVb !== undefined ? ` (priced at ${cp.ceilingSatVb} sat/vB, ${cp.ceilingFromJob === true ? "the job's maxFeeRateSatVb" : 'the 500 sat/vB default: set maxFeeRateSatVb in a new job'})` : ''
  return `${c}: one full copy is not affordable: ${why}${ceil}; nothing was armed (vt job status ${jobId})`
}

export function describeCap(c: Chain, cap: CapRow, ch: JobChainDef, btcFees?: BtcFees): string[] {
  const mode = ch.mode === 'drain' ? 'drain' : `${ch.mode.copies} copies`
  const extra = c === 'btc' && btcFees !== undefined
    ? [`       btc worst case per copy at ${cap.ceilingSatVb} sat/vB (${cap.ceilingFromJob === true ? "the job's maxFeeRateSatVb" : "the 500 sat/vB default ceiling: this job names none"}): commit ${btcFees.commitFee} + reveal ${btcFees.revealFee} sat, postage ${btcFees.postage} sat (it stays on the inscription); today's node estimate is ${btcFees.rate} sat/vB`,
       ...(cap.capVia === 'fallback' ? ['       the cap is the 0.01 BTC native fallback (a Bitcoin lane has no USD price)'] : [])]
    : []
  return [
    `  ${c}  ${mode}  planned ${cap.planned} ${UNIT[c]}  cap ${cap.nativeCap} ${BASE[c]}${cap.priceAt !== null ? ` (= $${cap.usd.toFixed(2)})` : ' (no price: the R60 native fallback)'}`,
    `       one copy: ${cap.parts} part${cap.parts === 1 ? '' : 's'}, at most ${cap.fullCopyCost} ${BASE[c]}${cap.overCap ? '; OVER THE R60 CAP: the planned amount must be typed exactly' : ''}`,
    ...extra,
  ]
}

export async function armCommand(args: readonly string[], io: JobIo, deps: ArmDeps = {}): Promise<number> {
  const a = parseArmArgs(args)
  const n = io.network
  ;(deps.assertSendAllowed ?? ((x: Network) => { assertJobSendAllowed(x) }))(n) // release.mainnet-locked, before anything
  const show = (text: string): void => printLines(io, text, a.json) // with --json, stdout is the API's body only

  const api = apiClient(io)
  const st = (await api.json<Status>('GET', '/status')).value
  assertNetworks(st?.network === n, `the jobs API on the ${n} port serves another network; nothing was armed`)
  const view = (await api.json<JobView>('GET', `/jobs/${a.id}`)).value
  assertNetworks(view.def?.network === n, `job ${a.id} is a ${String(view.def?.network)} job; this is the ${n} stack (a job never runs on another network)`)
  const defChains = CHAINS.filter((c) => view.def.chains[c] !== undefined)
  const chains = a.chains ?? defChains
  for (const c of chains) if (!defChains.includes(c)) throw new UsageError(`job ${a.id} has no ${c} chain (--chains)`)
  if (view.state.armed !== null) throw new Error(`job ${a.id} is already armed (release ${iso(view.state.releaseAt)}); vt job status ${a.id}`)
  for (const c of chains) {
    const p = view.state.chains[c]?.phase
    if (p !== 'READY') throw new Error(`${c} is ${String(p)}, not READY: load its key in an executor (vt job run, or the page) and fund it first; nothing was armed`)
  }
  if (a.sources !== null) for (const c of Object.keys(a.sources)) if (!chains.includes(c as Chain)) throw new UsageError(`--source names ${c}, which is not armed`)

  const relay = deps.relay ?? httpRelayClient({ base: `http://127.0.0.1:${io.ports.relay}`, fetch: (url, init) => fetch(url, { ...init, signal: AbortSignal.timeout(120_000) }) })
  const rs = await relay.status()
  assertNetworks(rs.network === n && chains.every((c) => rs.identity?.[c]?.ok === true),
    `the ${n} relay is on another network, or has not verified the chain identity of ${chains.join(', ')}; nothing was armed (vt status --network ${n})`)

  if (n !== 'local') assertTor(n, (await relay.tor()).isTor)

  const bytes = await api.getMessage(view.def.messageSha256)
  assertDigest(sha256Hex(bytes) === view.def.messageSha256 && bytes.length === view.def.messageBytes, 'the text the jobs API sent does not hash to the job\'s messageSha256; nothing was armed')
  const text = decodeMessage(bytes)
  const plan = await planCaps(view, chains, text, relay, n, io.now())

  const regime = NETWORK[n] as { label: string; sub: string }
  show([`arm job ${a.id} "${view.def.name}" on ${regime.label}: ${regime.sub}`, ...chains.flatMap((c) => describeCap(c, plan.caps[c], view.def.chains[c]!, plan.btc))].join('\n'))
  for (const c of chains) {
    if (!plan.caps[c].affordable) throw new Error(notAffordableMessage(c, plan.caps[c], a.id))
  }
  // Cfix4 (planE5 C4): a lane key core reports as EIP-7702-delegated is shown as a ✗ row (a feature check: no `delegated` field, no row).
  for (const r of delegatedRows({ ...Object.fromEntries(chains.map((c) => [c, view.state.chains[c] as { delegated?: unknown } | undefined])), ...delegatedFromJobs([{ chains: Object.fromEntries(chains.map((c) => [c, view.state.chains[c]])) }]) })) show(`  ✗  ${r.label} — ${r.detail}`)
  const history: Partial<Record<Chain, number>> = {}
  for (const c of chains) history[c] = await keyHistory(c, view.def.chains[c]!.keyAddress)
  for (const c of chains) if ((history[c] ?? 0) > 0) show(`  ${c}  KEY HISTORY: this lane key already sent ${history[c]} transaction${history[c] === 1 ? '' : 's'}`)
  const skipped = defChains.filter((c) => !chains.includes(c))
  for (const c of skipped) show(`  ${c}  NOT ARMED: it becomes SKIPPED at this arm (terminal: no funds touched; it can never be armed in this job; a new job is needed for it)`)

  // Typed confirmations (terminal only).
  const ask = async (prompt: string, kind: WordKind): Promise<string> => {
    const w = await io.ask(prompt, kind)
    assertTerminal(w !== undefined, 'this arm needs a typed confirmation, read from the terminal only (never stdin, argv or the environment): run vt job arm at a terminal')
    return w as string
  }
  let typed: string | null = null
  if (n === 'mainnet') {
    show(['the five pre-flight ticks (the page\'s Status screen asks the same):', ...MAINNET_TICKS.map((t, i) => `  ${i + 1}. ${t.name}: ${t.label}`)].join('\n'))
    assertTicks(n, await ask(`Type ${TICKS_WORD} to acknowledge all five: `, 'ticks'))
    typed = await ask(`MAINNET: real funds; the publication is public and permanent.${skipped.length > 0 ? ` ${skipped.join(', ')} will be SKIPPED.` : ''} Type broadcast to arm job ${a.id} (${chains.join(', ')}): `, 'broadcast')
  }
  const amounts: Partial<Record<Chain, string>> = {}
  for (const c of chains) {
    const cap = plan.caps[c]
    if (!cap.overCap) continue
    const w = await ask(`${c}: the planned spend is over the R60 cap. Type it exactly, ${cap.planned} ${UNIT[c]} (= ${cap.nativeCap} ${BASE[c]}): `, 'amount')
    amounts[c] = sameAmount(c, w, cap.planned) ? cap.planned : w
  }
  for (const c of chains) {
    const h = history[c] ?? 0
    if (h > 0) assertAgain(c, h, await ask(`${c}: this lane key already sent ${h} transaction${h === 1 ? '' : 's'}. Type again to arm it anyway: `, 'again'))
  }

  const req: ArmRequest = {
    chains, confirm: { typed, amounts }, caps: Object.fromEntries(chains.map((c) => [c, toArmCap(plan.caps[c])])),
    ...(a.countdownSec === undefined ? {} : { countdownSec: a.countdownSec }), ...(a.stagger === undefined ? {} : { stagger: a.stagger }),
    ...(a.sources === null ? {} : { sources: a.sources }),
  }
  checkArmConfirm(n, req) // arm.chains, arm.typed, arm.amount, arm.countdown, arm.stagger: before anything is sent
  let r: { value: { armed: ArmRecord }; text: string }
  try {
    r = await api.json<{ armed: ArmRecord }>('POST', `/jobs/${a.id}/arm`, req)
  } catch (e) {
    // Sources arrive with M3 (R47): until then the API takes no `sources` member at all.
    if (a.sources !== null && isRefusal(e) && e.guardId === 'api.json') throw refusalFrom('api.json', `${e.message} (--source: arm sources come with M3, R47; the API refuses them until then)`)
    throw e
  }
  if (a.json) {
    emitJson(io, r.text)
    return 0
  }
  const armed = r.value.armed
  const order = (armed.schedule?.order ?? []).map((c) => `${c} +${armed.schedule.offsetSec?.[c] ?? 0} s`).join(', ')
  printLines(io, [
    `armed job ${a.id}: release ${iso(armed.releaseAt)} (countdown ${armed.countdownSec} s); order ${order}`,
    ...skipped.map((c) => `  ${c} SKIPPED`),
    `follow it: vt job status ${a.id} --watch   (an executor must hold each chain: vt job run ${a.id}, or the page)`,
  ].join('\n'))
  return 0
}

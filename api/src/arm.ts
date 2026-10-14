// api/src/arm.ts — POST /jobs/:id/arm (spec §5.4) and the other operator commands that the API journals itself:
// skip, stop, resume, close and resolve (spec §5.2). Each runs in the job's queue (leases.run), so its checks and its
// append are never split by another append of that job; arms are also serialized across jobs, so two jobs on one key
// cannot both pass job.key-busy.
//
// Arm, checks in the spec §5.4 order (each a refusal; nothing is journaled before the last one passed):
//   job.network             the job's network is this API's (re-checked by every load, registry)
//   release.mainnet-locked  C2's assertJobSendAllowed(network): on mainnet, before any other check
//   trigger.uncleared       the legacy latch, read-only (legacy-latch.ts)
//   api.json                the ArmRequest members only: chains, confirm { typed, amounts }, caps (only armed chains),
//                           countdownSec, stagger, sources (chain → label strings, for armed chains)
//   job.armed               the job is already armed (the first armed event wins in the reducer, too)
//   job.state               the chains are a non-empty subset of the definition, each READY
//   job.key-busy            another job is active on one of these keys (registry)
//   arm.*                   core checkArmConfirm: chains, typed `broadcast` on mainnet, the exact amount of an over-cap
//                           chain, every cap well formed, the countdown, the stagger (local only)
//   arm.amount              an over-cap chain's typed amount (`planned`, which checkArmConfirm holds equal to the typed
//                           confirm.amounts[c]) is the armed cap itself, compared EXACTLY in base units (I2; review m5
//                           compared 6 significant digits): the typed decimal native amount, parsed without rounding
//                           (no more decimals than the chain has: ETH 18, SOL 9), equals nativeCap. computeArmCaps
//                           renders `planned` exactly for this (no sig6). The typed number is the number enforced.
//   arm.cap-ceiling         PF-S M-4 (pre-flip review), mainnet only: the API re-applies, per armed chain, the bound core's
//                           computeArmCaps plans with (arm-caps.js armCapExcess, the same module the page and the CLI use): an
//                           UNTYPED cap (overCap false) is at most the price-free R60 native ceiling (untypedCapCeiling:
//                           PLAN.SPEND_CAP_NATIVE), so a cap above it arms only with the typed amount (overCap true, its planned
//                           amount typed and equal to nativeCap: arm.amount above); a typed cap needs a price; a priced cap's USD
//                           value is at most the job's budgetUsd, itself at most 1000 (the job.budget rule, applied again here).
//                           Local and testnet: unchanged.
// Then the schedule is drawn with node:crypto randomInt (drawSchedule: a CSPRNG order; the second chain range[0] ..
// range[1] s after the first; range = the local `stagger`, else STAGGER_S [30, 300]) and `armed` is journaled:
// { armedAt: now, releaseAt: now + countdownSec·1000, countdownSec (default MAINNET_COUNTDOWN_S, 60; mainnet is
// always 60), schedule, caps of the armed chains, sources }.
// Last of all (M3, R47, sources.ts): source.unknown / source.exhausted / source.reused, then the try ledger
// tries/<messageSha256>.json is written (durably) BEFORE `armed` is journaled; `sources` is required once one is declared.
//
// The other commands (body members exact, api.json otherwise):
//   skip     {}                               armed and now < releaseAt (job.state) → skip { releaseAt: now }
//   stop     { chain | null }                  stop-requested; a chain with no transaction yet that is not settled
//                                              or terminal goes straight to STOPPED (`stopped` by api)
//   resume   { chain | null, tipCapGwei?, cuPriceCap? }  resume-requested (validateEvent checks the formats). R79b: a chain whose stop
//                                              is FINAL (core contracts/stop.ts stopClassOf; a missing or unknown code is FINAL) is
//                                              never resumed — `--chain c` on it: resume.final-stop (409, the reason and the way out);
//                                              a resume of every chain resumes the others and lists the refused ones. Answer
//                                              { seq, resumed: Chain[], refused: [{ chain, guard: 'resume.final-stop', message }] }
//   close    { chain }                         only a settled chain (DRAINED, COPIES_DONE, STOPPED) with no open
//                                              intent (job.state) → close
//   resolve  { txId, action, typed? } (path chain)  an open attempt of a STUCK chain (job.state); mainnet needs typed
//                                              `resolve` exactly (job.resolve-typed) → resolved, by the operator
import { randomInt } from 'node:crypto'
import { MAINNET_COUNTDOWN_S, STAGGER_S, finalStopText } from '@vault-timelock/core/contracts'
import type { ArmCap, ArmRecord, ArmRequest, Chain, ChainPhase, JobState, Network } from '@vault-timelock/core/contracts'
import * as planModule from '@vault-timelock/core/chains/plan.js'
import { armCapExcess } from '@vault-timelock/core/engine/arm-caps.js'
import { checkArmConfirm, drawSchedule } from '@vault-timelock/core/job'
import { refuse } from 'vt-broadcast/src/guard.ts'
import type { Clock } from './clock.ts'
import { assertJson } from './http.ts'
import { assertJobState, assertWithinCap } from './jobs.ts'
import type { JobEntry, Registry } from './jobs.ts'
import type { Leases } from './leases.ts'
import type { LegacyLatch } from './legacy-latch.ts'

export interface Controls {
  arm(job: JobEntry, body: unknown): Promise<ArmRecord>
  skip(job: JobEntry, body: unknown): Promise<{ releaseAt: number }>
  stop(job: JobEntry, body: unknown): Promise<{ seq: number }>
  resume(job: JobEntry, body: unknown): Promise<ResumeAnswer>
  close(job: JobEntry, body: unknown): Promise<{ seq: number }>
  resolve(job: JobEntry, chain: Chain, body: unknown): Promise<{ seq: number }>
}

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype
const only = (o: Obj, keys: readonly string[]): boolean => Object.keys(o).every((k) => keys.includes(k))
const isChain = (v: unknown): v is Chain => v === 'eth' || v === 'sol' || v === 'btc'
const SETTLED: ReadonlySet<ChainPhase> = new Set<ChainPhase>(['DRAINED', 'COPIES_DONE', 'STOPPED'])
// R79b: the resume route's answer (lane C's `vt job resume` prints both lists)
export interface ResumeAnswer { seq: number; resumed: Chain[]; refused: Array<{ chain: Chain; guard: 'resume.final-stop'; message: string }> }
const NOT_STARTED: ReadonlySet<ChainPhase> = new Set<ChainPhase>(['AWAITING_KEY', 'AWAITING_FUNDS', 'READY', 'ARMED'])
const OPEN_ATTEMPT: ReadonlySet<string> = new Set(['intent', 'sent', 'unknown', 'adopted'])

const { parseDecimal } = planModule as { parseDecimal(s: string, decimals: number): bigint }
const DECIMALS: Readonly<Record<Chain, number>> = { eth: 18, sol: 9, btc: 8 }
const NATIVE = /^[0-9]{1,40}(?:\.[0-9]{1,40})?$/
// The typed native amount in base units, exactly (null when it is not a plain decimal or has more decimals than the chain).
function exactBaseUnits(typed: unknown, c: Chain): bigint | null {
  if (typeof typed !== 'string' || !NATIVE.test(typed)) return null
  try { return parseDecimal(typed, DECIMALS[c]) } catch { return null }
}

// The ArmRequest's members (api.json); returns it typed. Formats are checkArmConfirm's (arm.*).
function armRequest(b: unknown): ArmRequest {
  const ok = isObj(b) && only(b, ['chains', 'confirm', 'caps', 'countdownSec', 'stagger', 'sources'])
    && Array.isArray(b.chains) && isObj(b.confirm) && only(b.confirm, ['typed', 'amounts']) && isObj(b.caps)
    && (b.confirm.amounts === undefined || isObj(b.confirm.amounts))
    && Object.keys(b.caps).every((c) => (b.chains as unknown[]).includes(c))
    && (b.sources === undefined || (isObj(b.sources) && Object.entries(b.sources).every(([c, l]) => (b.chains as unknown[]).includes(c) && typeof l === 'string')))
  assertJson(ok)
  return b as unknown as ArmRequest
}

export function createControls(o: { network: Network; clock: Clock; registry: Registry; leases: Leases; latch: LegacyLatch }): Controls {
  const { network, clock, registry, leases, latch } = o
  let arms: Promise<unknown> = Promise.resolve()
  const serial = <T>(fn: () => Promise<T>): Promise<T> => {
    const next = arms.then(fn, fn)
    arms = next.then(() => undefined, () => undefined)
    return next
  }
  const api = async (job: JobEntry, chain: Chain | null, type: 'skip' | 'stop-requested' | 'resume-requested' | 'close' | 'stopped', data: Obj): Promise<number> =>
    (await job.journal.append({ chain, by: 'api', gen: null, type, data })).seq

  return {
    async arm(job, body) {
      registry.assertJobSendsAllowed()   // C2's assertJobSendAllowed(network) (a test seam may stand in for it: jobs.ts jobSendLock)
      return serial(() => leases.run(job.id, async () => {
        await latch.assertClear()
        const req = armRequest(body)
        const state: JobState = registry.state(job)
        const notArmed = state.armed === null
        if (!notArmed) refuse('job.armed', 'this job is already armed') // @guard:job.armed
        const chains: unknown[] = req.chains
        assertJobState(chains.length > 0 && chains.every((c) => isChain(c) && state.chains[c]?.phase === 'READY'),
          'arm needs a non-empty list of this job\'s chains, each READY (key loaded, funds affordable)')
        for (const c of new Set(chains as Chain[])) await registry.assertKeyFree(job, c)
        checkArmConfirm(network, req)
        for (const c of req.chains) {
          const cap = req.caps[c]!
          assertWithinCap(!cap.overCap || exactBaseUnits(cap.planned, c) === BigInt(cap.nativeCap), `${c}: an over-cap arm types the armed cap itself (its planned amount is exactly the cap, in base units)`)
          const excess = armCapExcess(network, c, job.def.chains[c], cap)   // PF-S M-4: null = within what computeArmCaps plans
          if (excess !== null) refuse('arm.cap-ceiling', `${c}: ${excess}`) // @guard:arm.cap-ceiling
        }
        const countdownSec = req.countdownSec ?? MAINNET_COUNTDOWN_S
        const range: readonly [number, number] = network === 'local' && req.stagger !== undefined ? req.stagger : STAGGER_S
        const schedule = drawSchedule(req.chains, range, (m) => randomInt(m))
        const caps: Partial<Record<Chain, ArmCap>> = {}
        for (const c of req.chains) caps[c] = req.caps[c]
        const armedAt = clock.now()
        // R47 (spec §5.4 check 8, last): the funding sources, and the try on record BEFORE the `armed` ack.
        const sources = registry.sources.reserve({ messageSha256: job.def.messageSha256, jobId: job.id, chains: req.chains, sources: req.sources })
        const armed: ArmRecord = { armedAt, releaseAt: armedAt + countdownSec * 1000, countdownSec, schedule, caps, sources }
        await job.journal.append({ chain: null, by: 'api', gen: null, type: 'armed', data: armed as unknown as Obj })
        return armed
      }))
    },

    skip: (job, body) => leases.run(job.id, async () => {
      assertJson(isObj(body) && Object.keys(body).length === 0)
      const s = registry.state(job)
      const now = clock.now()
      assertJobState(s.armed !== null && s.releaseAt !== null && now < s.releaseAt, 'skip only before the release time of an armed job')
      await api(job, null, 'skip', { releaseAt: now })
      return { releaseAt: now }
    }),

    stop: (job, body) => leases.run(job.id, async () => {
      assertJson(isObj(body) && only(body, ['chain']) && (body.chain === null || (isChain(body.chain) && job.chains.includes(body.chain))))
      const chain = (body as { chain: Chain | null }).chain
      const s = registry.state(job)
      const seq = await api(job, chain, 'stop-requested', { chain })
      for (const c of chain === null ? job.chains : [chain]) {
        const cs = s.chains[c]
        if (cs !== undefined && cs.txs.length === 0 && cs.clawback === null && NOT_STARTED.has(cs.phase)) {
          await api(job, c, 'stopped', { reason: 'stopped before any transaction', code: 'operator-stop' })   // R79b: the operator's stop (resumable)
        }
      }
      registry.flushTrace(job)
      return { seq }
    }),

    resume: (job, body) => leases.run(job.id, async () => {
      assertJson(isObj(body) && only(body, ['chain', 'tipCapGwei', 'cuPriceCap']) && Object.hasOwn(body, 'chain')
        && (body.chain === null || (isChain(body.chain) && job.chains.includes(body.chain))))
      const b = body as Obj
      const chain = b.chain as Chain | null
      // R79b: the class of each chain's stop (only a chain whose base is STOPPED has one); a FINAL stop is never lifted — the way out is
      // claw-back / close and a new job. Fail closed: the code AND the journal's FINAL facts, and (final round, m-4) the API's own sticky
      // facts and an untrusted operator-stop (Registry.stopVerdict).
      const refused: ResumeAnswer['refused'] = []
      const resumed: Chain[] = []
      for (const c of chain === null ? job.chains : [chain]) {
        const v = registry.stopVerdict(job, c)
        if (v !== null && v.cls === 'final') refused.push({ chain: c, guard: 'resume.final-stop', message: finalStopText(c, v) })
        else resumed.push(c)
      }
      // `--chain c` on a FINAL stop, or a resume of every chain when every one is FINAL: nothing is resumed — 409
      if (resumed.length === 0) refuse('resume.final-stop', refused.map((r) => r.message).join('; ')) // @guard:resume.final-stop
      // every chain resumable: one resume-requested (chain or null, as before); else one per resumable chain (never the FINAL ones)
      let seq = 0
      if (refused.length === 0) seq = await api(job, chain, 'resume-requested', b)
      else for (const c of resumed) seq = await api(job, c, 'resume-requested', { ...b, chain: c })
      return { seq, resumed, refused }
    }),

    close: (job, body) => leases.run(job.id, async () => {
      assertJson(isObj(body) && only(body, ['chain']) && isChain(body.chain) && job.chains.includes(body.chain))
      const chain = (body as { chain: Chain }).chain
      const cs = registry.state(job).chains[chain]
      assertJobState(cs !== undefined && SETTLED.has(cs.phase) && cs.openIntents.length === 0,
        'close only a settled chain (DRAINED, COPIES_DONE or STOPPED) with nothing in flight')
      const seq = await api(job, chain, 'close', { chain })
      registry.flushTrace(job)
      return { seq }
    }),

    resolve: (job, chain, body) => leases.run(job.id, async () => {
      assertJson(isObj(body) && only(body, ['txId', 'action', 'typed']) && typeof body.txId === 'string'
        && (body.action === 'mark-done' || body.action === 'mark-failed') && (body.typed === undefined || body.typed === null || typeof body.typed === 'string'))
      const b = body as { txId: string; action: 'mark-done' | 'mark-failed'; typed?: string | null }
      // BTC (E7 fix-3 I-1): only mark-failed is valid. A commit that never landed marked done would wedge the chain for good; a
      // landed one reports itself with `included`.
      assertJobState(chain !== 'btc' || b.action === 'mark-failed', 'a btc transaction is resolved mark-failed only (a landed one reports itself)')
      const typedOk = network !== 'mainnet' || b.typed === 'resolve'
      if (!typedOk) refuse('job.resolve-typed', 'resolving a mainnet transaction needs the typed word "resolve"') // @guard:job.resolve-typed
      const cs = registry.state(job).chains[chain]
      const attempt = cs?.txs.flatMap((t) => t.attempts).find((a) => a.txId === b.txId)
      const open = cs !== undefined && cs.phase === 'STUCK' && cs.openIntents.includes(b.txId) && (attempt === undefined || OPEN_ATTEMPT.has(attempt.state))
      assertJobState(open, 'resolve only an open transaction of a STUCK chain')
      const seq = (await job.journal.append({ chain, by: 'operator', gen: null, type: 'resolved', data: { txId: b.txId, action: b.action, typed: b.typed ?? null } })).seq
      return { seq }
    }),
  }
}

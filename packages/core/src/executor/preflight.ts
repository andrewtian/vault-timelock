// packages/core/src/executor/preflight.ts — `vt preflight` (C7 prints it) and the page's readiness table (W4): read-only
// checks through this network's relay, for eth and sol (arb/base/btc come with S6). M1b folded (spec §8): identity,
// Memo v2 executable, fees now, the dry-run cost of a synthetic one-part copy, Tor and confinement. exit 0 only when
// every identity and deployment check passes. Fail closed: a relay that does not answer is a failing row
// (guard 'relay-unreachable'); a check that cannot be read is not ok. No row ever carries an IP or an endpoint: every
// detail is cleaned by journalText (anything IP- or key-like is withheld).
import type { Chain, Network, RelayClient } from '../contracts/index.ts'
import { ETH_FORKS, FORK_PROBE_BYTES, checkForkDrift, detectEthFork, ethAmsterdam, isNetwork } from '../contracts/index.ts'
import { ETH, SOL } from '../chains/constants.js'
import { ethGasBudget, ethParts, solCuEstimate, solCuLimit, solFee, solParts, utf8 } from '../chains/plan.js'
import { buildTx, layoutMaxMemo } from '../chains/sol.js'
import { PublicKey } from '@solana/web3.js'
import { base64 } from '@scure/base'
import { journalText } from '../engine/engine.js'
import { sha256Hex } from '../job/canonical.ts'
import { localTorView } from './readiness.ts'
import { endpointsNeeded } from '../gates/agree.ts'

export interface PreflightRow { id: string; chain: Chain | null; ok: boolean | null; label: string; detail: string; guard?: string }
export interface PreflightChain { idOk: boolean; endpoints: number; fees: Record<string, string> | null; copyCost: string | null; memoV2?: boolean }
export interface PreflightReport {
  format: 'vt-preflight/1'; network: Network; at: number
  idOk: boolean                // the relay serves this network and verified each chain's identity
  deployOk: boolean            // the relay answers, is confined, reaches the chains (Tor off local), Memo v2 is deployed
  exit: 0 | 1
  rows: PreflightRow[]
  chains: Partial<Record<Chain, PreflightChain>>
}

const PROBE_FROM = '0x000000000000000000000000000000000000dead'    // a synthetic sender, never the null address
const SYNTH = 'vt preflight: a synthetic one-part copy for the dry-run cost.'
const clean = (s: unknown): string => journalText(s, 200)
const big = (v: unknown): bigint => BigInt(v as string)

export async function preflight(relay: RelayClient, network: Network, o: { now?: () => number } = {}): Promise<PreflightReport> {
  if (!isNetwork(network)) throw new TypeError('preflight: network must be local, testnet or mainnet')
  const rows: PreflightRow[] = [], chains: Partial<Record<Chain, PreflightChain>> = {}
  const row = (r: PreflightRow): void => { rows.push({ ...r, detail: clean(r.detail), label: clean(r.label) }) }
  const at = (o.now ?? Date.now)()
  let status: Awaited<ReturnType<RelayClient['status']>> | null = null
  try { status = await relay.status() } catch (e) { row({ id: 'relay', chain: null, ok: false, label: 'Relay answers', detail: `the relay did not answer (${String((e as Error)?.message ?? e)})`, guard: 'relay-unreachable' }) }
  if (status === null) return { format: 'vt-preflight/1', network, at, idOk: false, deployOk: false, exit: 1, rows, chains }
  row({ id: 'relay', chain: null, ok: true, label: 'Relay answers', detail: `build ${status.build}` })
  const netOk = status.network === network
  row({ id: 'network', chain: null, ok: netOk, label: `Relay serves ${network}`, detail: netOk ? `relay network ${status.network}` : `the relay serves ${status.network}, not ${network}` })
  row({ id: 'confined', chain: null, ok: status.confined === true, label: 'Relay confinement (sandbox)', detail: status.confined === true ? 'startup probes refused (EPERM)' : 'no confinement proof from the relay' })
  let torOk: boolean | null = null
  if (network === 'local') {
    // S6 F1: local chains are loopback, but the local relay uses Tor for drand: say so from /relay/tor (informational, never fails local)
    const v = localTorView(await relay.tor().catch(() => null))
    row({ id: 'tor', chain: null, ok: v.ok, label: 'Tor', detail: v.detail })
  } else {
    const t = await relay.tor().catch(() => ({ isTor: null }))
    torOk = t.isTor === true
    row({ id: 'tor', chain: null, ok: torOk, label: 'Tor', detail: torOk ? 'IsTor ✓' : t.isTor === false ? 'IsTor ✗ — the relay is not on Tor' : 'IsTor unknown' })
  }
  let idOk = netOk, deployOk = status.confined === true && torOk !== false
  for (const chain of ['eth', 'sol'] as const) {
    const id = status.identity?.[chain]
    const cOk = id?.ok === true, eps = Number(status.endpoints?.[chain] ?? 0)
    // PF-S M-2: on mainnet a job chain needs 2 verified endpoints (gates/agree.ts endpointsNeeded); local and testnet need 1
    const need = endpointsNeeded(network, chain)
    row({ id: `${chain}.identity`, chain, ok: cOk, label: `${chain.toUpperCase()} chain identity`, detail: cOk ? 'verified at relay startup' : id?.message ?? 'not verified' })
    row({ id: `${chain}.endpoints`, chain, ok: eps >= need, label: `${chain.toUpperCase()} verified endpoints`,
      detail: eps >= need || need === 1 ? `${eps} endpoint(s)` : `${eps} endpoint(s): ${network} needs ${need} (one endpoint's word is never enough); the relay re-checks a dropped one every 30 s` })
    idOk = idOk && cOk
    deployOk = deployOk && eps >= need
    const c: PreflightChain = { idOk: cOk, endpoints: eps, fees: null, copyCost: null }
    chains[chain] = c
    if (!cOk || eps < 1) continue
    try {
      if (chain === 'eth') {
        const h = await relay.rpc('eth', 'eth_feeHistory', ['0x14', 'latest', [50]]) as { baseFeePerGas: string[]; reward?: string[][] }
        const nextBase = big(h.baseFeePerGas.at(-1)), tips = (h.reward ?? []).map((r) => big(r[0])).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
        const tip = tips.length ? tips[Math.floor(tips.length / 2)] : 0n, maxFee = 2n * nextBase + tip
        const bytes = utf8(SYNTH), part = ethParts(bytes, { sha256: sha256Hex(bytes) })[0]
        const gas = ethGasBudget(part.payload.length, { amsterdam: ethAmsterdam(network), toSelf: false })
        c.fees = { nextBase: String(nextBase), tip: String(tip), maxFee: String(maxFee) }
        c.copyCost = String(gas * maxFee)
        row({ id: 'eth.fees', chain, ok: true, label: 'ETH fees now', detail: `next base ${nextBase} wei · p50 tip ${tip} wei · one-part copy ≤ ${c.copyCost} wei` })
        // The fork probe simulates a send, so it must be a send between two DIFFERENT addresses (a self-send is priced by
        // another formula on Amsterdam and would under-estimate; fork-drift review): a synthetic sender to the null address,
        // the class the engine sends to by default. Read-only (eth_estimateGas), value 0.
        try {
          const probe = '0x646174613a2c' + '61'.repeat(FORK_PROBE_BYTES - 6)   // `data:,` + 94 × 'a' = 100 bytes, no zero byte
          const est = big(await relay.rpc('eth', 'eth_estimateGas', [{ from: PROBE_FROM, to: ETH.NULL_ADDRESS, value: '0x0', data: probe }]))
          const drift = checkForkDrift(network, { estimate: est, n: FORK_PROBE_BYTES, toSelf: false })
          // local: an anvil may run either fork (the engine's override is the harness's), so only a reading that matches
          // NEITHER formula fails there; a public network must match the fork its table names.
          const seen = detectEthFork(est, FORK_PROBE_BYTES, false)
          const localOk = seen === 'amsterdam' || seen === 'pre-amsterdam'
          const forkOk = network === 'local' ? localOk : drift.ok
          row({ id: 'eth.fork', chain, ok: forkOk, label: 'ETH fork gas probe (a send to another address)', detail: forkOk ? `${seen === 'amsterdam' ? 'Amsterdam' : 'pre-Amsterdam'} gas, as ${network === 'local' ? 'the local chain runs it' : `${network} runs it (${ETH_FORKS[network].amsterdam ? 'Amsterdam' : 'pre-Amsterdam'})`}` : (drift.message ?? 'the fork probe did not match') })
          if (!forkOk) deployOk = false
        } catch (e) {
          row({ id: 'eth.fork', chain, ok: false, label: 'ETH fork gas probe (a send to another address)', detail: `the fork probe could not be read (${String((e as Error)?.message ?? e)})` })
          deployOk = false                                               // fail closed: an unreadable probe is not a pass
        }
      } else {
        const acct = await relay.rpc('sol', 'getAccountInfo', [SOL.MEMO_PROGRAM, { encoding: 'base64' }]) as { value?: { executable?: boolean } | null }
        c.memoV2 = acct?.value?.executable === true
        row({ id: 'sol.memo', chain, ok: c.memoV2, label: 'Memo v2 program deployed and executable', detail: c.memoV2 ? 'executable ✓' : 'Memo v2 is not executable on this cluster' })
        deployOk = deployOk && c.memoV2
        const bytes = utf8(SYNTH), part = solParts(bytes, layoutMaxMemo(), { sha256: sha256Hex(bytes) })[0]
        // a chain read (E3 review m-5): the cluster's fee for the synthetic part's message at a fresh blockhash
        const cuLimit = solCuLimit(solCuEstimate(part.payload))
        const bh = await relay.rpc('sol', 'getLatestBlockhash', [{ commitment: 'confirmed' }]) as { value?: { blockhash?: string } }
        if (typeof bh?.value?.blockhash !== 'string') throw new Error('getLatestBlockhash answered without a blockhash')
        const msg = buildTx(PublicKey.default, part.payload, bh.value.blockhash, { cuLimit, cuPrice: 0 }).message.serialize()
        const fr = await relay.rpc('sol', 'getFeeForMessage', [base64.encode(msg), { commitment: 'confirmed' }]) as { value?: number | null }
        if (!Number.isSafeInteger(fr?.value)) throw new Error('getFeeForMessage answered without a fee')
        const fee = BigInt(fr.value as number)
        if (fee !== solFee(1, cuLimit, 0)) throw new Error(`the cluster's fee ${fee} is not the fee formula's ${solFee(1, cuLimit, 0)}`)
        c.fees = { base: String(fee) }
        c.copyCost = String(fee)
        row({ id: 'sol.fees', chain, ok: true, label: 'SOL fees now', detail: `one-part copy ${fee} lamports (no priority; read from the cluster)` })
      }
    } catch (e) {
      row({ id: `${chain}.fees`, chain, ok: false, label: `${chain.toUpperCase()} read`, detail: `a read through the relay failed (${String((e as Error)?.message ?? e)})` })
      deployOk = false                                                 // E3 review m-5: an ETH read failure fails too
    }
  }
  const exit = idOk && deployOk ? 0 : 1
  return { format: 'vt-preflight/1', network, at, idOk, deployOk, exit, rows, chains }
}

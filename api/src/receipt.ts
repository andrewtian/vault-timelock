// api/src/receipt.ts — GET /jobs/:id/receipt: `vt-receipt/1` (spec §5.7), built from reduce(def, journal) and core's
// links.js. `vt job receipt` and the page's download fetch the same bytes.
//
// What it holds: the job id, name, network, the message's sha256 (never its text), the build, and per chain the key
// address, the network name, mode, phase, copies included, reassembly results, the spent fees, the claw-back (once it
// landed) and every landed transaction (copy, part, tx id, number of attempts, block, fee, readback).
// What it never holds: message text, keys, endpoints, IP literals.
//   · Explorer links are listed for mainnet only, as COPY-ONLY text (R46: pasted into Tor Browser), written without the
//     URL scheme (etherscan.io/tx/0x…), so the receipt carries no URL at all. Local links point at loopback services
//     (the local Otterscan and the local validator RPC are endpoints), and links.js has no testnet rows yet (the P2 delta,
//     E3): both get no links rather than wrong ones.
//   · A landed tx without a known block or fee (an operator `resolve mark-done`) reports '' for that field.
// A link that still carries a scheme is a programming error (thrown, 500): the receipt is never served with one.
import * as linksModule from '@vault-timelock/core/chains/links.js'
import type { Link } from '@vault-timelock/core/chains/types.ts'
import type { Chain, JobDef, JobState, Network, Receipt, ReceiptChain, ReceiptTx } from '@vault-timelock/core/contracts'
import { networkName } from 'vt-broadcast/src/config.ts'

const links = linksModule as {
  ethLinks(profile: string, hash: string, signer: string, to: string): Link[]
  solLinks(profile: string, sig: string, address: string): Link[]
}
const CHAINS: readonly Chain[] = ['eth', 'sol', 'btc']
const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//

function linksFor(network: Network, chain: Chain, txId: string, address: string, to: string | undefined): ReceiptTx['links'] {
  if (network !== 'mainnet') return []
  const raw = chain === 'eth' ? links.ethLinks('mainnet', txId, address, to ?? '') : links.solLinks('mainnet', txId, address)
  return raw.map((l) => {
    const href = l.url.replace(SCHEME, '')
    if (href.includes('://') || /^https?:/i.test(href)) throw new Error('receipt: a link kept its scheme')
    return { label: l.label, href, copyOnly: l.open !== true }
  })
}

export function buildReceipt(o: { id: string; def: JobDef; state: JobState; network: Network; build: string }): Receipt {
  const { id, def, state, network } = o
  const chains: Partial<Record<Chain, ReceiptChain>> = {}
  for (const c of CHAINS) {
    const d = def.chains[c]
    const cs = state.chains[c]
    if (d === undefined || cs === undefined) continue
    const txs: ReceiptTx[] = cs.txs.filter((t) => t.state === 'included' && t.landedId !== null).map((t) => {
      const txId = t.landedId!
      const landed = t.attempts.find((a) => a.txId === txId)
      return {
        copy: t.copy, part: t.part, txId, attempts: t.attempts.length, block: t.block ?? '', fee: t.fee ?? '', readback: t.readback === true,
        links: linksFor(network, c, txId, d.keyAddress, landed?.eth?.to),
      }
    })
    const cb = cs.clawback
    const clawedBack = cb !== null && (cb.ok === true || cs.phase === 'CLAWED_BACK')
    chains[c] = {
      address: d.keyAddress, network: networkName(network, c), mode: d.mode, phase: cs.phase, copiesIncluded: cs.copiesIncluded,
      reassembled: cs.reassembled.map((r) => ({ copy: r.copy, ok: r.ok })), spent: cs.spent,
      clawback: clawedBack ? { txId: cb.txId, to: cb.to, value: cb.value } : null, txs,
    }
  }
  return { format: 'vt-receipt/1', jobId: id, name: def.name, network, messageSha256: def.messageSha256, build: o.build, chains }
}

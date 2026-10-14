// Funding for the lane keys (R70 step 4, M2 testnet funding). The page never sends a transaction of its own here.
//   local    a "local stand-in" note (the operator funds from the local dev accounts / validator airdrop)
//   testnet  Sepolia: address + copy, "operator faucet step". Solana devnet: Request devnet airdrop through the relay
//            (`requestAirdrop` on /relay/sol). The airdrop through Tor was refused in testing, so a refusal or any
//            failure shows the faucet link and the address for the operator. The page never automates a faucet.
//   mainnet  address + copy only; fund from your own wallet.
import { useState } from 'react'
import { Button } from '@/components/ui/button.jsx'
import { CHAIN_NAME } from '@/keys/KeyStore.jsx'
import { regtestFundHint, regtestMineHint } from '@/lib/btc.js'
import AddressLinks, { copyText } from './AddressLinks.jsx'

export const FAUCET = { sol: 'https://faucet.solana.com', eth: 'https://sepolia-faucet.pk910.de' }
export const AIRDROP_LAMPORTS = 1_000_000_000

// -> { ok: true, signature } | { ok: false, kind: 'refused' | 'rpc' | 'transport', message }
export async function requestAirdrop(address, lamports = AIRDROP_LAMPORTS, fetchFn = (...a) => globalThis.fetch(...a)) {
  let r
  try {
    r = await fetchFn('/relay/sol', { method: 'POST', cache: 'no-store', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'requestAirdrop', params: [address, lamports] }) })
  } catch (e) { return { ok: false, kind: 'transport', message: `relay unreachable (${String(e?.message || e).slice(0, 120)})` } }
  let j = null
  try { j = await r.json() } catch { /* not JSON */ }
  if ([403, 413, 503].includes(r.status)) return { ok: false, kind: 'refused', message: `the relay refused it (${r.status}): ${j?.error?.message || 'no reason given'}` }
  if (j?.error) return { ok: false, kind: 'rpc', message: `${j.error.code}: ${j.error.message}` }
  if (!j || typeof j.result !== 'string') return { ok: false, kind: 'transport', message: `relay HTTP ${r.status} (no result)` }
  return { ok: true, signature: j.result }
}

function AddressRow({ chain, address, network }) {
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <b>{CHAIN_NAME[chain]}</b>
        <span data-testid={`fund-addr-${chain}`} className="break-all font-mono">{address}</span>
        <Button type="button" size="xs" variant="outline" data-testid={`fund-copy-${chain}`} onClick={() => copyText(address)}>Copy</Button>
      </div>
      <AddressLinks network={network} chain={chain} address={address} />
    </div>
  )
}

function FaucetHelp({ chain, address }) {
  return (
    <div data-testid={`faucet-${chain}`} className="space-y-1 rounded-md border border-amber-500 bg-amber-50 p-2 text-xs text-amber-950">
      <div><b>Operator step.</b> Open the faucet yourself ({chain === 'sol' ? 'it may ask for a login or a captcha' : 'it may need proof of work or a login'}); the page does not automate it.</div>
      <div>faucet <a href={FAUCET[chain]} target="_blank" rel="noopener noreferrer" className="underline">{FAUCET[chain]}</a></div>
      <div>address <span className="break-all font-mono">{address}</span></div>
    </div>
  )
}

function Airdrop({ address }) {
  const [state, setState] = useState({ phase: 'idle' })
  const go = async () => {
    setState({ phase: 'asking' })
    const r = await requestAirdrop(address)
    setState(r.ok ? { phase: 'done', signature: r.signature } : { phase: 'failed', message: r.message })
  }
  return (
    <div className="space-y-2">
      <Button type="button" size="sm" data-testid="airdrop" disabled={state.phase === 'asking'} onClick={go}>{state.phase === 'asking' ? 'Requesting…' : 'Request devnet airdrop (1 SOL)'}</Button>
      {state.phase === 'done' && <p data-testid="airdrop-done" className="text-xs text-emerald-800">Airdrop requested. Signature <span className="break-all font-mono">{state.signature}</span>. It lands once confirmed; the balance shows on the job page.</p>}
      {state.phase === 'failed' && (
        <div className="space-y-2" data-testid="airdrop-failed">
          <p className="text-xs text-red-700">Airdrop did not go through: {state.message}. Through Tor the public devnet often refuses airdrops.</p>
          <FaucetHelp chain="sol" address={address} />
        </div>
      )}
    </div>
  )
}

export default function Funding({ network, addresses }) {
  const chains = ['eth', 'sol', 'btc'].filter((c) => addresses[c])
  if (chains.length === 0) return <p data-testid="funding-none" className="text-xs text-muted-foreground">Funding addresses appear here once a lane&apos;s key and backup are done.</p>
  return (
    <div data-testid="funding" className="space-y-3 text-sm">
      {network === 'local' && <p data-testid="funding-local" className="rounded-md border border-sky-300 bg-sky-50 p-2 text-xs text-sky-950">Local stand-in: these are local chains with throwaway balances. Fund the addresses from the local dev accounts or the validator&apos;s airdrop (an operator step); nothing here has value.</p>}
      {network === 'mainnet' && <p data-testid="funding-mainnet" className="rounded-md border border-red-600 bg-red-50 p-2 text-xs text-red-900">Mainnet: real funds. Send from your own wallet, only what the job budget needs. This page never sends the funding.</p>}
      {chains.map((c) => <AddressRow key={c} chain={c} address={addresses[c]} network={network} />)}
      {addresses.btc && (
        <div data-testid="funding-btc" className="space-y-1 text-xs">
          <div>The Bitcoin lane address is the lane key&apos;s <b>p2wpkh</b> (native segwit) address; the commit spends its coins, and the reveal pays the postage to the lane&apos;s taproot address.</div>
          {network === 'local' && (
            <div data-testid="funding-btc-regtest" className="space-y-1 rounded-md border border-sky-300 bg-sky-50 p-2 text-sky-950">
              <div><b>regtest:</b> fund it yourself (an operator step; nothing here has value): <span className="font-mono">vt localnet fund btc {addresses.btc}</span>, or with bitcoin-cli against vt&apos;s regtest node (add <span className="font-mono">-datadir=&quot;$VT_HOME/localnet/bitcoind&quot;</span> to each line):</div>
              <div className="break-all font-mono">{regtestMineHint(addresses.btc)}</div>
              <div className="break-all font-mono">{regtestFundHint(addresses.btc)}</div>
              <div>then mine one block with <span className="font-mono">generatetoaddress 1</span> so the coins are confirmed.</div>
            </div>
          )}
        </div>
      )}
      {network === 'testnet' && addresses.eth && (
        <div data-testid="funding-sepolia" className="space-y-1 text-xs">
          <div><b>Sepolia ETH:</b> copy the address above and use a Sepolia faucet. <b>Operator faucet step</b>; the page does not automate it.</div>
          <FaucetHelp chain="eth" address={addresses.eth} />
        </div>
      )}
      {network === 'testnet' && addresses.sol && <Airdrop address={addresses.sol} />}
    </div>
  )
}

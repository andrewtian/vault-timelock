// Latest Jupiter price, fetched ONLY by the relay through Tor (GET /relay/price). The browser never contacts jup.ag.
// Fail closed: missing or older than PRICE.MAX_AGE_MS → USD entry is disabled (native entry still works). The rules are
// core's (chains/price.js: fetchPrice with an injected same-origin fetch, priceStatus, isTestFunds). On testnet the
// amounts are test funds: the line says TEST FUNDS — NO VALUE and shows no price at all (the caps use the native fallback).
import { useEffect, useState } from 'react'
import { PRICE, TEST_FUNDS_LABEL } from '@vault-timelock/core/chains/constants.js'
import { fetchPrice as corePrice, isTestFunds, priceStatus } from '@vault-timelock/core/chains/price.js'
import { currentNetwork, useStatus } from '@/lib/status.js'

export { PRICE, priceStatus }
export const fetchPrice = () => corePrice({ base: '', fetch: (url, init) => fetch(url, init) })

const hhmmss = (ms) => new Date(ms).toISOString().slice(11, 19)

export function usePrice(intervalMs = PRICE.REFRESH_MS) {
  const [price, setPrice] = useState(null), [err, setErr] = useState('')
  useEffect(() => {
    let on = true
    const go = () => fetchPrice().then((p) => { if (on) { setPrice(p); setErr('') } }, (e) => { if (on) setErr(String(e.message).slice(0, 200)) })
    go(); const t = setInterval(go, intervalMs)
    return () => { on = false; clearInterval(t) }
  }, [intervalMs])
  return { price, err }
}

export default function PriceLine({ price, err = '' }) {
  const network = currentNetwork(useStatus())
  if (network === 'testnet' || isTestFunds(price)) {
    return (
      <div data-testid="price" className="rounded-md border p-2 text-xs">
        <b data-testid="price-testnet" className="mr-2 rounded bg-amber-200 px-1.5 py-0.5 text-amber-950">{TEST_FUNDS_LABEL}</b>
        no price: test funds have no value. USD entry is off; the spend caps use the native fallback (0.004 ETH / 0.07 SOL per lane, typed above it).
      </div>
    )
  }
  const ps = priceStatus(price)
  const p = price
  return (
    <div data-testid="price" className={`rounded-md border p-2 text-xs ${ps.ok ? '' : 'border-red-600 bg-red-50 text-red-900'}`}>
      {p?.fixture && <b className="mr-2 rounded bg-amber-300 px-1.5 py-0.5 text-amber-950" data-testid="price-fixture">LOCAL FIXTURE PRICE</b>}
      {p?.prices
        ? <>1 SOL = <b className="font-mono">${p.prices.SOL.usd.toFixed(4)}</b> · 1 ETH = <b className="font-mono">${p.prices.ETH.usd.toFixed(4)}</b>
          {!p.fixture && <span className="text-muted-foreground"> (Wormhole WETH, Jupiter&apos;s ETH proxy)</span>}
          {' '}· source <span className="font-mono">{p.fixture ? p.source : `${p.source} (Jupiter Price API v3) via the Tor relay`}</span> · fetched {hhmmss(p.fetchedAt)} UTC{ps.ok ? ` · ${ps.age} s ago` : ''}</>
        : (err || 'price: waiting for the relay…')}
      {!ps.ok && <div data-testid="price-disabled" className="mt-1 font-semibold">USD entry disabled: {err || ps.why}. The budget in USD needs a fresh price.</div>}
    </div>
  )
}

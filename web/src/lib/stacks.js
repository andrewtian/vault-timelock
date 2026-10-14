// Which stacks run (W1): the page server answers GET /__stacks from the sibling up.json files.
import { useEffect, useState } from 'react'
import { PORTS, isNetwork } from '@vault-timelock/core/contracts'

// A page URL is only followed when it is the loopback origin of that network's page port.
export function safePageUrl(network, pageUrl) {
  try {
    const u = new URL(pageUrl)
    const ok = u.protocol === 'http:' && u.hostname === '127.0.0.1' && Number(u.port) === PORTS[network]?.page
      && u.username === '' && u.password === ''
    return ok ? u.origin + '/' : null
  } catch {
    return null
  }
}

export async function fetchStacks(f = fetch) {
  const res = await f('/__stacks', { cache: 'no-store', credentials: 'same-origin' })
  if (!res.ok) throw new Error('stacks')
  const list = await res.json()
  if (!Array.isArray(list)) throw new Error('stacks')
  return list.filter((s) => s && isNetwork(s.network)).map((s) => ({
    network: s.network, up: s.up === true, pageUrl: typeof s.pageUrl === 'string' ? s.pageUrl : '', build: typeof s.build === 'string' ? s.build : null,
  }))
}

// useStacks() -> StackInfo[] ([] until the first answer or when the page server does not answer)
export function useStacks({ intervalMs = 10_000 } = {}) {
  const [stacks, setStacks] = useState([])
  useEffect(() => {
    let dead = false
    const tick = () => fetchStacks().then((s) => { if (!dead) setStacks(s) }, () => { if (!dead) setStacks([]) })
    tick()
    const t = setInterval(tick, intervalMs)
    return () => { dead = true; clearInterval(t) }
  }, [intervalMs])
  return stacks
}

// Parts per copy for each chain of a job, derived the way the new-job form derives them (previewParts: the core planner's
// R72 split of the job's message), for the lane header BEFORE the first part is built (F9-3: it used to show "? parts/copy").
// The text is read through the journal client (the sha256 must match); on any failure the count stays unknown (null).
import { useEffect, useState } from 'react'
import { browserClients } from '@vault-timelock/core/executor'
import { previewParts } from '@/lib/core.js'

export function useMessageParts(sha256) {
  const [parts, setParts] = useState({})
  useEffect(() => {
    if (!sha256) return undefined
    let live = true
    ;(async () => {
      try {
        const { journal } = browserClients({ fetch: (u, i) => globalThis.fetch(u, i) })
        const per = previewParts(await journal.message(sha256), sha256)
        if (live) setParts(Object.fromEntries(Object.entries(per).filter(([, x]) => x.ok).map(([c, x]) => [c, x.parts.length])))
      } catch { /* unknown: the lane keeps '?' */ }
    })()
    return () => { live = false }
  }, [sha256])
  return parts
}

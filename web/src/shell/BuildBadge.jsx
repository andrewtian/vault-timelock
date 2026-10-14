// Build ids (W1): this page's build (set by vite.config.js) and the API's.
import { useStatus } from '@/lib/status.js'

export const PAGE_BUILD = typeof __VT_BUILD__ === 'undefined' ? 'dev' : __VT_BUILD__

export default function BuildBadge() {
  const { status } = useStatus()
  return (
    <span className="font-mono text-xs text-muted-foreground" data-testid="build-badge">
      page {PAGE_BUILD}{status ? ` · api ${status.build}` : ''}
    </span>
  )
}

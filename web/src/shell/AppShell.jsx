// App shell (W1): banner, header (nav, selector, build), and the page. A network mismatch between this page, the API
// and the relay blocks everything: the page is not rendered, only the alert with the command to run.
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert.jsx'
import { useStatus } from '@/lib/status.js'
import BuildBadge from './BuildBadge.jsx'
import NetworkSelector from './NetworkSelector.jsx'
import RegimeBanner from './RegimeBanner.jsx'

export function MismatchAlert({ mismatch }) {
  return (
    <Alert variant="destructive" role="alert" data-testid="network-mismatch" className="m-4 max-w-3xl">
      <AlertTitle>Network mismatch: everything is blocked</AlertTitle>
      <AlertDescription>
        <p>{mismatch.message}</p>
        <p>
          Start the right stack: <code className="rounded bg-muted px-1 py-0.5 font-mono text-foreground">{mismatch.command}</code>
        </p>
      </AlertDescription>
    </Alert>
  )
}

export default function AppShell({ nav = null, children }) {
  const { mismatch } = useStatus()
  return (
    <div className="flex min-h-screen flex-col">
      <RegimeBanner />
      <header className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-2">
        <div className="flex items-center gap-4">
          <span className="font-semibold">vt</span>
          {nav}
        </div>
        <div className="flex items-center gap-4">
          <NetworkSelector />
          <BuildBadge />
        </div>
      </header>
      <main className="flex-1 p-4">{mismatch ? <MismatchAlert mismatch={mismatch} /> : children}</main>
    </div>
  )
}

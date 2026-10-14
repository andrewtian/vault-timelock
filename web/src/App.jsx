import { TabBusyProvider } from '@/lib/busy.js'
import { StatusProvider } from '@/lib/status.js'
import { KeysProvider } from '@/keys/KeyStore.jsx'
import { RunsProvider } from '@/jobs/RunHere.js'
import { TicksProvider } from '@/status/Ticks.jsx'
import { Nav, Routes, useRoute } from './routes.jsx'
import AppShell from './shell/AppShell.jsx'

function Page() {
  const route = useRoute()
  return (
    <AppShell nav={<Nav route={route} />}>
      <Routes route={route} />
    </AppShell>
  )
}

export default function App() {
  return (
    <StatusProvider>
      <TabBusyProvider>
        <KeysProvider>
          <RunsProvider>
            <TicksProvider>
              <Page />
            </TicksProvider>
          </RunsProvider>
        </KeysProvider>
      </TabBusyProvider>
    </StatusProvider>
  )
}

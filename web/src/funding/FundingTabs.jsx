// The funding panel's tabs (plan W6, spec §4a): Address (the existing per-chain address list), Railgun (Ethereum lane, L1 manual
// unshield + provenance) and Privacy Cash (Solana lane, the in-browser SDK). Separate tabs, as the operator asked; nothing in one
// tab is reachable from another, and the Privacy Cash key never leaves its own tab's worker.
import { useState } from 'react'
import Funding from '@/jobs/Funding.jsx'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs.jsx'
import PrivacyCash from '@/privacycash/PrivacyCash.jsx'
import RailgunTab from './RailgunTab.jsx'

export default function FundingTabs({ network, addresses, jobId = null, createClient, newTry, fundingLocked, read }) {
  // m-3: while a Privacy Cash call is in flight the other tabs cannot be opened (Radix unmounts inactive content, and unmounting stops the worker,
  // which would end an in-flight withdrawal with no trace on the page); PrivacyCash itself also asks the browser before the page is left.
  const [pcBusy, setPcBusy] = useState(false)
  return (
    <Tabs defaultValue="address" data-testid="funding-tabs">
      <TabsList>
        <TabsTrigger value="address" data-testid="tab-address" disabled={pcBusy}>Address</TabsTrigger>
        <TabsTrigger value="railgun" data-testid="tab-railgun" disabled={pcBusy}>Railgun</TabsTrigger>
        <TabsTrigger value="privacycash" data-testid="tab-privacycash">Privacy Cash</TabsTrigger>
      </TabsList>
      <TabsContent value="address"><Funding network={network} addresses={addresses} /></TabsContent>
      <TabsContent value="railgun"><RailgunTab network={network} address={addresses.eth} read={read} /></TabsContent>
      <TabsContent value="privacycash">
        {addresses.sol
          ? <PrivacyCash network={network} address={addresses.sol} jobId={jobId} createClient={createClient} newTry={newTry} fundingLocked={fundingLocked} onBusy={setPcBusy} />
          : <p data-testid="pc-none" className="text-xs text-muted-foreground">The Solana lane address appears here once its key and backup are done.</p>}
      </TabsContent>
    </Tabs>
  )
}

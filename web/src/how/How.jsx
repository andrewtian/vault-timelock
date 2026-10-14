// The How pages (W5): '#/how' (vault → sealed payload), '#/how/network' (who sees what), '#/how/modes' (publication
// modes and fee strategies), '#/how/files' (the two local-only files). The ported diagrams were drawn for a dark
// background, so the body sits in a dark panel.
import { LocalFiles } from './LocalFiles.jsx'
import { NetworkPath } from './NetworkPath.jsx'
import { PublicationModes } from './PublicationModes.jsx'
import { VaultDiagram } from './VaultDiagram.jsx'

export const HOW_TABS = [
  { id: 'vault', label: '1Password vault → sealed payload', href: '#/how' },
  { id: 'network', label: 'Broadcast & Tor: who sees what', href: '#/how/network' },
  { id: 'modes', label: 'Publication modes', href: '#/how/modes' },
  { id: 'files', label: 'STRUCTURE.txt & SEALED-plaintext.txt', href: '#/how/files' },
]
const BODY = { vault: VaultDiagram, network: NetworkPath, modes: PublicationModes, files: LocalFiles }

export default function How({ tab = 'vault' }) {
  const Body = BODY[tab] ?? VaultDiagram
  return (
    <div data-testid="how-page" className="space-y-3">
      <h1 className="text-lg font-semibold">How it works</h1>
      <nav aria-label="How pages" className="flex flex-wrap gap-2">
        {HOW_TABS.map((t) => (
          <a key={t.id} href={t.href} data-testid={`how-tab-${t.id}`} aria-current={t.id === tab ? 'page' : undefined}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted aria-[current=page]:border-amber-500 aria-[current=page]:font-semibold">{t.label}</a>
        ))}
      </nav>
      <div className="rounded-xl bg-neutral-950 p-4 text-neutral-200"><Body /></div>
    </div>
  )
}

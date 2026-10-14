// The local Solana explorer note (W1, controller ruling). On the local network, explorer.solana.com talks to the
// validator on this machine, which Chrome 145+ gates behind the "Apps on device" permission. W2/W3 reuse this.
export const LOCAL_EXPLORER_NOTE =
  'The local Solana explorer reads your validator on this machine. Chrome 145 and later blocks that unless the explorer site is allowed the "Apps on device" permission (site settings, or the lock icon in the address bar). Without it the explorer shows no data.'

export default function LocalExplorerNote() {
  return (
    <p data-testid="local-explorer-note" className="rounded border border-sky-300 bg-sky-50 p-3 text-sm text-sky-950">
      {LOCAL_EXPLORER_NOTE}
    </p>
  )
}

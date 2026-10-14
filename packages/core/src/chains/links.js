// @ts-check
// PORTED (R69) from the prototype, tag add7-00927d6ade7f, src/mainnet/links.js (sha256 47013b5e6ad4c2e6dbe208c3571fa1567b5fbdc2151447a8f0510cc8806bde7e);
// P2 delta (E3) from tag add7b-e540f8ae4d6b src/mainnet/links.js + networks.js (ethLinksFor, solLinksFor): the links are
// built from the per-network table (constants.js NETWORK, R71) — testnet gets Sepolia Etherscan and the devnet clusters of
// Solana Explorer, Solscan and SolanaFM.
// Explorer links (pure; unit-tested). Every link is COPY-ONLY (paste into Tor Browser) — this page never opens an external
// URL; only the LOCAL Otterscan links (http://127.0.0.1:5100) open directly. An unknown network is refused (fail closed:
// never another network's explorer).
import { ETH, LOCAL_SOL_EXPLORER_NOTE, networkOf } from './constants.js'
export const NULL_ADDRESS = ETH.NULL_ADDRESS
const OTTERSCAN = 'http://127.0.0.1:5100'
/** @typedef {import('./types.ts').Link} Link */
const isNull = (/** @type {string} */ a) => String(a).toLowerCase() === NULL_ADDRESS
// opening is allowed only for the local Otterscan origin
export const mayOpen = (/** @type {string} */ url) => url.startsWith(`${OTTERSCAN}/`)
/** @param {string} network @param {string} hash @param {string} signer @param {string} to @returns {Link[]} */
export function ethLinks(network, hash, signer, to) {
  const N = networkOf(network), X = N.eth.explorer
  /** @type {Array<{ label: string, url: string, note?: string }>} */
  const L = [{ label: `${X.name} · transaction`, url: `${X.base}/tx/${hash}` }]
  if (isNull(to)) L.push({ label: `${X.name} · Null Address page`, url: `${X.base}/address/${NULL_ADDRESS}`, ...(N.id === 'local' ? {} : { note: 'busy page — your tx scrolls down; find it by hash' }) })
  L.push({ label: `${X.name} · signer address`, url: `${X.base}/address/${signer}` })
  return L.map((x) => ({ ...x, open: mayOpen(x.url) }))
}
/** @param {string} network @param {string} sig @param {string} address @returns {Link[]} */
export function solLinks(network, sig, address) {
  const N = networkOf(network)
  if (N.id === 'local') {
    const u = /** @type {string} */ (/** @type {any} */ (N.sol.explorer).customUrl)
    return [{ label: 'Solana Explorer · custom cluster → local RPC', url: `https://explorer.solana.com/tx/${sig}?cluster=custom&customUrl=${encodeURIComponent(u)}`, note: LOCAL_SOL_EXPLORER_NOTE, open: false }]
  }
  const dev = N.id === 'testnet'
  const L = [
    { label: `Solana Explorer${dev ? ' (devnet)' : ''} · transaction`, url: `https://explorer.solana.com/tx/${sig}${dev ? '?cluster=devnet' : ''}` },
    { label: `Solscan${dev ? ' (devnet)' : ''} · transaction`, url: `https://solscan.io/tx/${sig}${dev ? '?cluster=devnet' : ''}` },
    { label: `SolanaFM${dev ? ' (devnet)' : ''} · transaction`, url: `https://solana.fm/tx/${sig}${dev ? '?cluster=devnet-solana' : ''}` },
    { label: 'Solana Explorer · address', url: `https://explorer.solana.com/address/${address}${dev ? '?cluster=devnet' : ''}` },
  ]
  return L.map((x) => ({ ...x, open: mayOpen(x.url) }))
}

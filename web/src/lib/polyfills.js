// web3.js expects a global Buffer in the browser (spec §7.1: the web provides it; from the prototype's src/polyfills.js,
// unchanged). Imported first by lib/core.js, before any core module that loads @solana/web3.js.
import { Buffer } from 'buffer'
globalThis.Buffer ??= Buffer

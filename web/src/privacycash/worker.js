// The Privacy Cash module worker: ONE per unlocked session, terminated by the page on lock, after a withdrawal and by the watchdog
// (terminating it is the real wipe of the key: JS cannot zero memory it does not own). The import order matters:
// ./shims.js FIRST (Buffer, process.env, the guarded fetch, the removed globals), then the SDK, which reads them at load time.
// Only `privacycash/utils` is imported, never the package root (that one writes to disk and prints).
import { guard } from './shims.js'
import { WasmFactory } from '@lightprotocol/hasher.rs'
import { Connection, PublicKey } from '@solana/web3.js'
import { base58 } from '@scure/base'
import nacl from 'tweetnacl'
import * as sdk from 'privacycash/utils'
import { createSession } from './session.js'

const session = createSession({
  sdk, WasmFactory, Connection, PublicKey, nacl, base58, guard,
  origin: self.location.origin, post: (m) => self.postMessage(m), close: () => self.close(),
})
self.onmessage = (e) => { void session.handle(e.data) }
self.postMessage({ type: 'ready' })

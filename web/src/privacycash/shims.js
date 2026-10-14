// Evaluated FIRST in the Privacy Cash worker (worker.js imports it before the SDK): see install-shims.js for what it does.
// Importing this module anywhere but the worker would rewrite that global: only worker.js imports it.
import { installShims } from './install-shims.js'

export const guard = installShims(globalThis, { origin: globalThis.location.origin, native: globalThis.fetch.bind(globalThis) })

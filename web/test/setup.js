import { afterEach } from 'vitest'
import { Buffer } from 'node:buffer'
import { cleanup } from '@testing-library/react'
import Module, { createRequire } from 'node:module'

// drand-client (tlock-js) requires @noble/hashes without declaring it; the linked install cannot resolve that from its directory.
// The build does it with vite.drand.js; vitest loads these CommonJS packages through Node, so the same rule is applied here:
// from a drand-client file, @noble/hashes/* resolves from tlock-js's directory (where it is declared).
const fromTlock = createRequire(import.meta.url).resolve('tlock-js')
const resolveFilename = Module._resolveFilename
Module._resolveFilename = function (request, parent, ...rest) {
  if (typeof request === 'string' && request.startsWith('@noble/hashes/') && /[\\/]node_modules[\\/]\.store[\\/]drand-client@[^\\/]+[\\/]node_modules[\\/]drand-client[\\/]/.test(parent?.filename || '') && !request.includes('..')) {
    return resolveFilename.call(this, request, { ...parent, filename: fromTlock, paths: Module._nodeModulePaths(fromTlock.replace(/[^\\/]+$/, '')) }, ...rest)
  }
  return resolveFilename.call(this, request, parent, ...rest)
}

// jsdom's global Uint8Array is not Node's, so Buffer (and the libraries that run in Node's realm, such as web3.js)
// reject it with "b must be a Uint8Array". Pin Node's, as a browser has one realm.
globalThis.Uint8Array = Object.getPrototypeOf(Buffer)

afterEach(() => cleanup())

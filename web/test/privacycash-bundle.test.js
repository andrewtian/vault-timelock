// What the Privacy Cash worker bundle is, proven from the shipped dependencies and a real production build (plan W6, the CSP question):
//   · the SDK's ZK stack compiles WebAssembly at run time → script-src needs 'wasm-unsafe-eval' (and NOT 'unsafe-eval': no eval / new Function);
//   · ffjavascript falls back to its single-thread engine when `Worker` is absent, so the worker needs NO blob: sub-workers → no worker-src blob:;
//   · the bundle never reaches storage, and its relayer URL is the relay's same-origin path;
//   · only `privacycash/utils` is imported (never the package root, which writes to disk).
import { test, expect } from 'vitest'
import { build } from 'vite'
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createRequire } from 'node:module'

const here = process.cwd()
const req = createRequire(resolve(here, 'package.json'))
const FF = resolve(dirname(req.resolve('ffjavascript')), 'browser.esm.js')        // outside the package's exports map: a path, not a specifier
const serveSrc = readFileSync(resolve(here, '../api/serve/serve.mjs'), 'utf8')
const csp = /'content-security-policy': "([^"]*)"/.exec(serveSrc)?.[1] ?? ''      // the page's own CSP (SEC); the worker's response widens it (SEC_WASM, m-1)
const WORKER_PATH = /export const WASM_PATH = '([^']+)'/.exec(serveSrc)?.[1] ?? ''

test('the source of the SDK stack: WebAssembly.compile / instantiate are used; eval and new Function are not', () => {
  const ff = readFileSync(FF, 'utf8')
  expect(ff).toMatch(/WebAssembly\.compile\(/); expect(ff).toMatch(/WebAssembly\.instantiate\(/)
  expect(csp).toMatch(/script-src 'self';/)                           // m-1: the PAGE cannot compile WebAssembly; only the worker's response can (SEC_WASM)
  expect(csp).not.toContain('wasm-unsafe-eval'); expect(csp).not.toContain("'unsafe-eval'")
})

test('ffjavascript (browser build) uses ONE thread when Worker is absent: no blob: worker is ever constructed', async () => {
  const made = []
  const keep = { Worker: globalThis.Worker }
  globalThis.Worker = undefined
  const { getCurveFromName } = await import(pathToFileURL(FF).href)
  const curve = await getCurveFromName('bn128')
  try { expect(curve.tm.singleThread).toBe(true); expect(curve.tm.workers).toBeUndefined() } finally { globalThis.curve_bn128 = null; globalThis.Worker = keep.Worker }    // (curve.terminate() assumes workers exist: the page terminates the whole worker instead)
  expect(made).toEqual([])
}, 60_000)

test('a production build of the worker: relayer URL inlined, no eval, no storage, WebAssembly present, the SDK root not imported', async () => {
  const out = mkdtempSync(join(tmpdir(), 'vt-w6-'))
  try {
    await build({ root: here, logLevel: 'silent', configFile: resolve(here, 'vite.config.js'), build: { outDir: out, emptyOutDir: true, write: true, minify: true } })
    const files = readdirSync(join(out, 'assets'))
    const worker = files.find((f) => f === 'privacycash-worker.js')              // m-1: a fixed name, the one path the page server gives wasm-unsafe-eval
    expect(worker, files.join()).toBeTruthy()
    expect(`/assets/${worker}`).toBe(WORKER_PATH)
    expect(files.filter((f) => f.endsWith('.js')).sort()).toEqual([worker, files.find((f) => /^index-.*\.js$/.test(f))].sort())   // no other script: nothing else would need the wider CSP
    const js = readFileSync(join(out, 'assets', worker), 'utf8')
    expect(js).toContain('/relay/privacycash/relayer')
    expect(js).toMatch(/WebAssembly\.(compile|instantiate)/)
    expect(js).not.toMatch(/\b(?:globalThis|self|window|global)\s*(?:\.\s*fetch|\[\s*["'`]fetch["'`]\s*\])\s*=(?!=)/)   // m-5: no module installs a fetch of its own over the guard
    for (const bad of ['new Function(', 'eval(', 'localStorage', 'sessionStorage', 'node-localstorage', 'new WebSocket', 'require("crypto")', 'require("fs")']) expect(js.includes(bad), bad).toBe(false)
    // the crypto shim, not a Node module, stands behind `crypto`
    expect(js).toMatch(/crypto shim: /)
    // the page bundle holds no SDK
    const page = readFileSync(join(out, 'assets', files.find((f) => /^index-.*\.js$/.test(f))), 'utf8')
    expect(/groth16|fullProve|snarkjs|WasmFactory/.test(page)).toBe(false)
    expect(page.includes('WebAssembly')).toBe(false)                              // m-1: the page realm never compiles WebAssembly
  } finally { rmSync(out, { recursive: true, force: true }) }
}, 120_000)

test('worker.js: shims first, only privacycash/utils; the sources never touch storage', () => {
  const w = readFileSync(resolve(here, 'src/privacycash/worker.js'), 'utf8')
  const imports = [...w.matchAll(/^import .* from '([^']+)'/gm)].map((m) => m[1])
  expect(imports[0]).toBe('./shims.js')
  expect(imports).toContain('privacycash/utils'); expect(imports).not.toContain('privacycash')
  for (const f of readdirSync(resolve(here, 'src/privacycash'))) {
    const src = readFileSync(resolve(here, 'src/privacycash', f), 'utf8').replace(/\/\/.*$/gm, '')
    expect(src, f).not.toMatch(/localStorage|sessionStorage|document\.cookie|\bcaches\b\./)
    expect(src, f).not.toMatch(/indexedDB/)
    expect(src, f).not.toMatch(/type="password"|type: 'password'/)
    expect(src, f).not.toMatch(/console\.(log|info|debug|warn|error)/)
  }
})

test('I-1: no type="password" input anywhere in web/src (the project\'s SecretInput is the one way to take a secret)', () => {
  const walk = (d) => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(d, e.name)) : [join(d, e.name)]))
  const hits = walk(resolve(here, 'src')).filter((f) => /\.(jsx?|tsx?)$/.test(f)).filter((f) => /type\s*[=:]\s*["']password["']/.test(readFileSync(f, 'utf8')))
  expect(hits).toEqual([])
})

test('m-7: the worker chunk carries GPL-3.0 code, so the project is GPL-3.0-only (LICENSE, package.json, README ## License) and the package stays private', () => {
  const pkg = JSON.parse(readFileSync(resolve(here, 'package.json'), 'utf8'))
  expect(pkg.private).toBe(true)
  expect(pkg.license).toBe('GPL-3.0-only')
  expect(readFileSync(resolve(here, '../LICENSE'), 'utf8')).toMatch(/^\s*GNU GENERAL PUBLIC LICENSE\n\s*Version 3, 29 June 2007\n/)
  expect(readFileSync(resolve(here, '../README.md'), 'utf8')).toMatch(/## License\n\nGPL-3\.0-only[\s\S]*Privacy Cash worker[\s\S]*GPL-3\.0/)
})

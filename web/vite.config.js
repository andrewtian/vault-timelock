// Vite config (W1). The dev server binds 127.0.0.1:5183 only (contracts PORTS.local.dev).
//   build id   sha256 over web/src + index.html + the root lockfile, first 12 hex (shown by BuildBadge as __VT_BUILD__)
//   dev proxy  /api -> the local API (127.0.0.1:5182) with the bearer token read from $VT_HOME/local/api.token on
//              every request (the page never holds it; an incoming Authorization is dropped);
//              /relay -> the local relay (127.0.0.1:5181).
//   VT_REPLAY=1 (with VT_REPLAY_PORT=<ephemeral port of contract/replay-server.ts>) points both at the replay server
//              and uses its synthetic token instead.
//   drand      (W7) tlock-js's drand-client imports @noble/hashes without declaring it: ./vite.drand.js resolves it from tlock-js.
//   privacycash (W6) the SDK's worker bundle gets a `crypto` shim and an ES worker format; ./vite.privacycash.js.
//   buffer     (W3) the bare module `buffer` is the npm `buffer` package (a web dependency) for EVERY importer: CommonJS
//              dependencies of @solana/web3.js (borsh → bs58 → base-x → safe-buffer) require('buffer') from places that
//              cannot resolve it, and Vite would otherwise externalize it as an empty browser stub — safe-buffer then
//              throws at module load and the page never renders. Build and dev only (vitest runs in Node).
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { drandNobleHashes } from './vite.drand.js'
import { hasherBn, privacyCashCrypto } from './vite.privacycash.js'

const here = fileURLToPath(new URL('.', import.meta.url))
const REPLAY_TOKEN = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'

export function buildId(root = here) {
  const h = createHash('sha256')
  const walk = (d) => {
    for (const f of readdirSync(d).sort()) {
      const p = join(d, f)
      if (statSync(p).isDirectory()) walk(p)
      else h.update(relative(root, p)).update('\0').update(readFileSync(p))
    }
  }
  walk(join(root, 'src'))
  for (const f of ['index.html', '../package-lock.json']) h.update(f).update('\0').update(readFileSync(join(root, f)))
  return h.digest('hex').slice(0, 12)
}

function devTarget(env) {
  if (env.VT_REPLAY === '1') {
    const port = Number(env.VT_REPLAY_PORT)
    if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('VT_REPLAY=1 needs VT_REPLAY_PORT (the replay server port)')
    return { api: `http://127.0.0.1:${port}`, relay: `http://127.0.0.1:${port}`, token: () => REPLAY_TOKEN }
  }
  return {
    api: 'http://127.0.0.1:5182',
    relay: 'http://127.0.0.1:5181',
    token: () => {
      if (!env.VT_HOME) return ''
      try { return readFileSync(join(env.VT_HOME, 'local', 'api.token'), 'utf8').trim() } catch { return '' }
    },
  }
}

export default defineConfig(({ command }) => {
  const t = command === 'serve' ? devTarget(process.env) : null
  return {
    plugins: [drandNobleHashes(), react(), tailwindcss()],
    // W6: the SDK reads process.env.NEXT_PUBLIC_RELAYER_API_URL at module evaluation; it is inlined here to the relay's same-origin path (the
    // worker's guarded fetch also rewrites the SDK's hard-coded upstream host, should a bundler leave it in).
    define: { __VT_BUILD__: JSON.stringify(buildId()), 'process.env.NEXT_PUBLIC_RELAYER_API_URL': JSON.stringify('/relay/privacycash/relayer') },
    resolve: {
      alias: [
        { find: '@', replacement: fileURLToPath(new URL('./src', import.meta.url)) },
        { find: /^buffer\/?$/, replacement: fileURLToPath(new URL('./node_modules/buffer/index.js', import.meta.url)) },
      ],
    },
    server: {
      host: '127.0.0.1',
      port: 5183,
      strictPort: true,
      proxy: t ? {
        '/api': {
          target: t.api,
          changeOrigin: true,
          rewrite: (p) => p.replace(/^\/api/, '') || '/',
          configure: (proxy) => {
            proxy.on('proxyReq', (req) => {
              req.removeHeader('authorization')
              const tok = t.token()
              if (tok) req.setHeader('authorization', `Bearer ${tok}`)
            })
          },
        },
        '/relay': { target: t.relay, changeOrigin: true },
      } : undefined,
    },
    preview: { host: '127.0.0.1', port: 5183, strictPort: true },
    // W6: the Privacy Cash SDK runs in a module worker; `crypto` is aliased to the noble shim inside the worker bundle only (vite.privacycash.js).
    //   m-1: the worker's file name is FIXED (no hash): the page server sends 'wasm-unsafe-eval' in the CSP of exactly that response (api/serve/serve.mjs
    //   SEC_WASM) and nowhere else, so the page itself cannot compile WebAssembly.
    worker: { format: 'es', plugins: () => [drandNobleHashes(), hasherBn(), privacyCashCrypto()], rollupOptions: { output: { entryFileNames: 'assets/privacycash-worker.js' } } },
    build: { outDir: 'dist', emptyOutDir: true, sourcemap: false, modulePreload: { polyfill: false } },
  }
})

// Vitest (Task 0): jsdom, tests under test/, no globals (Testing Library cleanup runs from test/setup.js).
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

const BN = createRequire(createRequire(import.meta.url).resolve('privacycash')).resolve('bn.js')     // privacycash declares bn.js; hasher.rs (inlined below) imports it undeclared

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)), 'bn.js': BN } },
  test: {
    environment: 'jsdom',
    include: ['test/**/*.test.{js,jsx}'],
    setupFiles: ['test/setup.js'],
    globals: false,
    server: { deps: { inline: [/@lightprotocol\/hasher\.rs/, /[\/\\]privacycash[\/\\]/] } },   // through Vite, so the bn.js alias applies (the M6 test imports the real SDK)
  },
})

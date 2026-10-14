// W7 / F10-2: the page declares an inline empty icon, so the browser never requests /favicon.ico (404); the page CSP
// (read from api/serve/serve.mjs SEC as text: importing it needs node, not the jsdom page env) already allows data: images, so no CSP change is needed.
import { test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

test('web/index.html declares <link rel="icon" href="data:,">, and the CSP img-src allows data:', () => {
  const html = readFileSync(resolve(process.cwd(), 'index.html'), 'utf8')
  expect(html).toMatch(/<link rel="icon" href="data:,"\s*\/?>/)
  const src = readFileSync(resolve(process.cwd(), '../api/serve/serve.mjs'), 'utf8')
  const csp = /'content-security-policy': "([^"]*)"/.exec(src)?.[1] ?? ''
  expect(csp).toMatch(/default-src 'self'/)
  const img = /(?:^|;)\s*img-src ([^;]*)/.exec(csp)
  expect(img).toBeTruthy()
  expect(img[1].split(/\s+/)).toContain('data:')
  expect(csp).not.toMatch(/default-src[^;]*\*/)
})

// The Decrypt tab's route and nav entry (kept apart from decrypt.test.jsx: routes.jsx pulls in the whole app, which the mutation
// runner's copy of web/ cannot resolve).
import { test, expect } from 'vitest'
import { parseRoute, NAV } from '../src/routes.jsx'

test('route and nav: a Decrypt tab next to Open', () => {
  expect(parseRoute('#/decrypt')).toEqual({ name: 'decrypt' })
  const names = NAV.map((n) => n.name)
  expect(names.indexOf('decrypt')).toBe(names.indexOf('open') + 1)
})

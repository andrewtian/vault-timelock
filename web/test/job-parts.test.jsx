// W6 (F9-3): the job page shows the real parts-per-copy before any part is built, derived like the new-job form.
import { test, expect } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { sha256Hex } from '@vault-timelock/core/job'
import JobView from '../src/jobs/JobView.jsx'
import { newKey, previewParts } from '../src/lib/core.js'
import { renderWith } from './helpers.jsx'
import { created, ethChain, fakeStack, jobDef, journal, solChain } from './job-fakes.js'

const ID = '0123456789abcdef'

test('a lane with no part built yet shows the planner\'s part count, not "?" (2,000-byte message)', async () => {
  const text = Array.from({ length: 2000 }, (_, i) => String.fromCharCode(97 + ((i * 7) % 26))).join('')
  const sha = sha256Hex(text)
  const def = { ...jobDef({ chains: { eth: ethChain(newKey('eth').address), sol: solChain(newKey('sol').address) } }), messageSha256: sha, messageBytes: 2000 }
  const want = previewParts(text, sha)
  globalThis.fetch = fakeStack({ id: ID, def, events: journal([created(ID)]), messages: { [sha]: text } }).fetch
  renderWith(<JobView id={ID} jobOptions={{ pollMs: 200, flushMs: 10 }} />)
  const head = async (c) => (await screen.findByTestId(`lane-${c}`)).textContent
  await waitFor(async () => expect(await head('eth')).toContain(`${want.eth.parts.length} part${want.eth.parts.length === 1 ? '' : 's'}/copy`), { timeout: 5000 })
  await waitFor(async () => expect(await head('sol')).toContain(`${want.sol.parts.length} parts/copy`), { timeout: 5000 })
  expect(want.eth.parts.length).toBe(1); expect(want.sol.parts.length).toBe(3)
  expect(await head('eth')).not.toContain('? part')
})

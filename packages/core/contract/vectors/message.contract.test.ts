// Message vectors (R50 + R72). Bytes are decoded the one contracted way — new TextDecoder('utf-8', { fatal: true,
// ignoreBOM: true }) — and a decode failure IS message.utf8 (S2's PUT /messages and W2's Load text file must do the
// same; the default ignoreBOM: false silently strips a BOM and FileReader.readAsText silently replaces bad bytes).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { fixture, guardOf, loadJobModule, readJson } from './job-module.ts'

const decode = (b: Uint8Array): string => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(b)
const valid = readJson<Record<string, { bytes: number; sha256: string; warnings: string[] }>>('messages/valid.json')
const bad = readJson<Record<string, string>>('messages/bad/expected.json')

test('every bad message file is listed', () => {
  assert.deepEqual(readdirSync(fixture('messages/bad')).filter((f) => f !== 'expected.json').sort(), Object.keys(bad).sort())
})

for (const [file, want] of Object.entries(valid)) {
  test(`accepted: ${file}`, async () => {
    const m = await loadJobModule()
    assert.deepEqual(m.validateMessage(decode(readFileSync(fixture(`messages/${file}`)))), want)
  })
}

for (const [file, guard] of Object.entries(bad)) {
  test(`refused: ${file} → ${guard}`, async () => {
    const m = await loadJobModule()
    let text: string
    try { text = decode(readFileSync(fixture(`messages/bad/${file}`))) } catch { assert.equal('message.utf8', guard); return }
    assert.equal(guardOf(() => m.validateMessage(text)), guard)
  })
}

// The committed fixtures are exactly what contract/gen-fixtures.ts builds, and every journal has a valid hash chain.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { canonicalJson, fixtureDrift, sha256Hex } from '../../contract/gen-fixtures.ts'
import type { JobDef, JournalEvent } from '../../src/contracts/index.ts'

const jdir = new URL('../../contract/fixtures/journals/', import.meta.url)

test('no drift between the generator and the committed fixtures (and the schema)', () => {
  assert.deepEqual(fixtureDrift(), [])
})

test('every journal: seq 0..n, prev = sha256 of the previous line, key order as written, created binds the def', () => {
  const files = readdirSync(jdir).filter((f) => f.endsWith('.jsonl'))
  assert.ok(files.length >= 19)
  for (const f of files) {
    const text = readFileSync(new URL(f, jdir), 'utf8')
    assert.ok(text.endsWith('\n') && !text.endsWith('\n\n'), f)
    const lines = text.slice(0, -1).split('\n')
    lines.forEach((line, i) => {
      const e = JSON.parse(line) as JournalEvent
      assert.equal(JSON.stringify({ v: e.v, seq: e.seq, at: e.at, prev: e.prev, chain: e.chain, by: e.by, gen: e.gen, type: e.type, data: e.data }), line, `${f}:${i} key order`)
      assert.equal(e.v, 1); assert.equal(e.seq, i)
      assert.equal(e.prev, i === 0 ? '' : sha256Hex(lines[i - 1]), `${f}:${i} prev`)
      if (i > 0) assert.ok(e.at >= (JSON.parse(lines[i - 1]) as JournalEvent).at, `${f}:${i} at`)
    })
    const def = JSON.parse(readFileSync(new URL(f.replace('.jsonl', '.def.json'), jdir), 'utf8')) as JobDef
    const created = JSON.parse(lines[0]) as JournalEvent
    assert.equal(created.type, 'created')
    assert.deepEqual(created.data, { jobId: sha256Hex(canonicalJson(def)).slice(0, 16), defSha256: sha256Hex(canonicalJson(def)) })
  }
})

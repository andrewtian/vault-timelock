// The fsync journal (spec §5.3): seq 0..n with a valid hash chain; a failed fsync acknowledges nothing (journal.write);
// a trailing fragment is cut and noted; a flipped byte makes the journal corrupt (journal.corrupt); 0600 / 0700; the
// fs seam only under NODE_ENV=test (api.test-only).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { appendFileSync, chmodSync, copyFileSync, fsyncSync, ftruncateSync, mkdirSync, readFileSync, statSync, symlinkSync, writeFileSync, writeSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { join } from 'node:path'
import { JOURNAL_FILE, openJournal } from '../src/journal.ts'
import type { JournalFs, JournalInput } from '../src/journal.ts'
import { FIXTURES, fakeClock, tempDir } from './helpers.ts'

process.env.NODE_ENV = 'test'

const sha = (s: string | Buffer): string => createHash('sha256').update(s).digest('hex')
const note = (text: string): JournalInput => ({ chain: null, by: 'api', gen: null, type: 'note', data: { text } })
const lines = (dir: string): string[] => readFileSync(join(dir, JOURNAL_FILE), 'utf8').split('\n').slice(0, -1)
const refusal = async (p: Promise<unknown>): Promise<string> => {
  try { await p } catch (e) { return (e as { guardId: string }).guardId }
  assert.fail('expected a refusal')
}
function setup(t: { after(fn: () => void): void }): string {
  const { dir, cleanup } = tempDir('vt-api-journal-')
  t.after(cleanup)
  return join(dir, 'jobs', 'e3d45f73cf65abaa')
}

test('appends get seq 0..n, the key order, and a valid hash chain; the file reads back the same', async (t) => {
  const dir = setup(t)
  const clock = fakeClock()
  const j = openJournal(dir, { clock })
  for (let i = 0; i < 5; i++) {
    clock.advance(1000)
    const e = await j.append({ chain: i % 2 === 0 ? 'eth' : null, by: i % 2 === 0 ? 'browser' : 'api', gen: i % 2 === 0 ? 1 : null, type: 'note', data: { text: `n${i}` } })
    assert.equal(e.seq, i)
    assert.ok(Object.isFrozen(e) && Object.isFrozen(e.data))
  }
  const ls = lines(dir)
  assert.equal(ls.length, 5)
  ls.forEach((l, i) => {
    const o = JSON.parse(l)
    assert.deepEqual(Object.keys(o), ['v', 'seq', 'at', 'prev', 'chain', 'by', 'gen', 'type', 'data'])
    assert.equal(o.v, 1)
    assert.equal(o.seq, i)
    assert.equal(o.at, 1791504000000 + 1000 * (i + 1))
    assert.equal(o.prev, i === 0 ? '' : sha(ls[i - 1]))
    assert.equal(JSON.stringify(j.all()[i]), l)
  })
  j.close()
  const again = openJournal(dir, { clock })
  assert.equal(again.corrupt(), null)
  assert.deepEqual(again.all(), j.all())
  assert.equal((await again.append(note('after reload'))).seq, 5)
  assert.equal(JSON.parse(lines(dir)[5]).prev, sha(ls[4]))
})

test('the contract journals load unchanged (05a-copies-done.jsonl)', (t) => {
  const dir = setup(t)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  copyFileSync(join(FIXTURES, 'journals/05a-copies-done.jsonl'), join(dir, JOURNAL_FILE))
  chmodSync(join(dir, JOURNAL_FILE), 0o600)
  const j = openJournal(dir)
  assert.equal(j.corrupt(), null)
  const want = readFileSync(join(FIXTURES, 'journals/05a-copies-done.jsonl'), 'utf8').split('\n').filter((l) => l !== '')
  assert.deepEqual(j.all().map((e) => JSON.stringify(e)), want)
})

test('an fsync that throws: the append rejects journal.write, nothing more is acknowledged, and a reload lacks the event', async (t) => {
  const dir = setup(t)
  let failFsync = false
  const fs: JournalFs = {
    writeSync: (fd, b, o, l) => writeSync(fd, b, o, l),
    fsyncSync: (fd) => { if (failFsync) throw Object.assign(new Error('EIO'), { code: 'EIO' }); fsyncSync(fd) },
    ftruncateSync: (fd, n) => ftruncateSync(fd, n),
  }
  const j = openJournal(dir, { fs })
  await j.append(note('one'))
  await j.append(note('two'))
  failFsync = true
  let notified = 0
  j.subscribe(() => { notified++ })
  assert.equal(await refusal(j.append(note('never acked'))), 'journal.write')
  assert.equal(j.all().length, 2)
  assert.equal(notified, 0)
  failFsync = false
  assert.equal(await refusal(j.append(note('after a failure'))), 'journal.write') // poisoned until restart
  const reloaded = openJournal(dir)
  assert.equal(reloaded.corrupt(), null)
  assert.deepEqual(reloaded.all().map((e) => e.data.text), ['one', 'two'])
  assert.equal((await reloaded.append(note('three'))).seq, 2)
})

test('a write that fails part-way: journal.write, and the partial line is cut back', async (t) => {
  const dir = setup(t)
  let mode: 'ok' | 'partial' = 'ok'
  const fs: JournalFs = {
    writeSync: (fd, b, o, l) => {
      if (mode === 'ok') return writeSync(fd, b, o, l)
      if (l > 10) return writeSync(fd, b, o, 10)
      throw Object.assign(new Error('ENOSPC'), { code: 'ENOSPC' })
    },
    fsyncSync: (fd) => fsyncSync(fd),
    ftruncateSync: (fd, n) => ftruncateSync(fd, n),
  }
  const j = openJournal(dir, { fs })
  await j.append(note('one'))
  mode = 'partial'
  assert.equal(await refusal(j.append(note('half written'))), 'journal.write')
  assert.equal(readFileSync(join(dir, JOURNAL_FILE), 'utf8').split('\n').length, 2)
  const reloaded = openJournal(dir)
  assert.equal(reloaded.corrupt(), null)
  assert.equal(reloaded.all().length, 1)
})

test('a trailing fragment without a newline is cut off and noted; the next seq continues', async (t) => {
  const dir = setup(t)
  const j = openJournal(dir)
  await j.append(note('one'))
  await j.append(note('two'))
  j.close()
  appendFileSync(join(dir, JOURNAL_FILE), '{"v":1,"seq":2,"at":17915')
  const r = openJournal(dir, { clock: fakeClock() })
  assert.equal(r.corrupt(), null)
  const all = r.all()
  assert.equal(all.length, 3)
  assert.deepEqual({ seq: all[2].seq, by: all[2].by, type: all[2].type, data: all[2].data }, { seq: 2, by: 'api', type: 'note', data: { text: 'recovered tail' } })
  const ls = lines(dir)
  assert.equal(ls.length, 3)
  assert.equal(JSON.parse(ls[2]).prev, sha(ls[1]))
  assert.ok(readFileSync(join(dir, JOURNAL_FILE), 'utf8').endsWith('\n'))
  assert.equal((await r.append(note('next'))).seq, 3)
  // a complete JSON line that only lacks its newline was never acknowledged either
  r.close()
  const whole = lines(dir).length
  appendFileSync(join(dir, JOURNAL_FILE), JSON.stringify({ v: 1, seq: whole, at: 1, prev: sha(lines(dir)[whole - 1]), chain: null, by: 'api', gen: null, type: 'note', data: { text: 'x' } }))
  const r2 = openJournal(dir)
  assert.equal(r2.all().length, whole + 1)
  assert.equal(r2.all()[whole].data.text, 'recovered tail')
})

test('a flipped byte in line 3 → corrupt(); every append then refuses journal.corrupt; the file is left alone', async (t) => {
  const flips: Array<[string, (l: string) => string]> = [
    ['a digit in a string', (l) => l.replace('"text":"n2"', '"text":"n3"')],
    ['the seq', (l) => l.replace('"seq":2', '"seq":7')],
    ['the prev hash', (l) => l.replace(/"prev":"(.)/, (_m, c: string) => `"prev":"${c === 'a' ? 'b' : 'a'}`)],
    ['the JSON', (l) => l.replace('"v":1', '"v":1,')],
    ['the key order', (l) => l.replace('"v":1,"seq":2', '"seq":2,"v":1')],
    ['whitespace', (l) => l.replace('"v":1', '"v": 1')],
  ]
  for (const [what, flip] of flips) {
    const dir = setup(t)
    const j = openJournal(dir)
    for (let i = 0; i < 6; i++) await j.append(note(`n${i}`))
    j.close()
    const ls = lines(dir)
    ls[2] = flip(ls[2])
    writeFileSync(join(dir, JOURNAL_FILE), `${ls.join('\n')}\n`)
    const before = readFileSync(join(dir, JOURNAL_FILE))
    const c = openJournal(dir)
    assert.notEqual(c.corrupt(), null, what)
    assert.match(c.corrupt()!, /^line [34]: /, what)
    assert.ok(c.all().length <= 3, what)
    assert.equal(await refusal(c.append(note('more'))), 'journal.corrupt', what)
    assert.deepEqual(readFileSync(join(dir, JOURNAL_FILE)), before, what)
  }
})

test('invalid UTF-8 in a line → corrupt', async (t) => {
  const dir = setup(t)
  const j = openJournal(dir)
  for (let i = 0; i < 4; i++) await j.append(note(`n${i}`))
  j.close()
  const buf = readFileSync(join(dir, JOURNAL_FILE))
  const at = buf.indexOf('n1')
  buf[at] = 0xff
  writeFileSync(join(dir, JOURNAL_FILE), buf)
  assert.match(openJournal(dir).corrupt()!, /^line 2: not UTF-8$/)
})

test('a journal file that is a symlink or readable by others is corrupt', async (t) => {
  const dir = setup(t)
  const j = openJournal(dir)
  await j.append(note('one'))
  j.close()
  chmodSync(join(dir, JOURNAL_FILE), 0o644)
  const loose = openJournal(dir)
  assert.notEqual(loose.corrupt(), null)
  assert.equal(await refusal(loose.append(note('x'))), 'journal.corrupt')
  const other = setup(t)
  mkdirSync(other, { recursive: true, mode: 0o700 })
  symlinkSync(join(dir, JOURNAL_FILE), join(other, JOURNAL_FILE))
  assert.equal(await refusal(openJournal(other).append(note('x'))), 'journal.corrupt')
})

test('modes: the file 0600, the job and jobs directories 0700', async (t) => {
  const dir = setup(t)
  const j = openJournal(dir)
  await j.append(note('one'))
  assert.equal(statSync(join(dir, JOURNAL_FILE)).mode & 0o777, 0o600)
  assert.equal(statSync(dir).mode & 0o777, 0o700)
  assert.equal(statSync(join(dir, '..')).mode & 0o777, 0o700)
})

test('the fs seam without NODE_ENV=test → api.test-only', (t) => {
  const dir = setup(t)
  const fs: JournalFs = { writeSync, fsyncSync, ftruncateSync }
  const saved = process.env.NODE_ENV
  try {
    for (const v of [undefined, 'production', 'TEST']) {
      if (v === undefined) delete process.env.NODE_ENV
      else process.env.NODE_ENV = v
      assert.throws(() => openJournal(dir, { fs }), (e: { guardId?: string }) => e.guardId === 'api.test-only', String(v))
    }
    delete process.env.NODE_ENV
    openJournal(dir) // no seam: fine without NODE_ENV
  } finally {
    process.env.NODE_ENV = saved
  }
})

test('subscribers see each event once, after it is durable, in order', async (t) => {
  const dir = setup(t)
  const j = openJournal(dir)
  const seen: number[] = []
  const off = j.subscribe((e) => {
    seen.push(e.seq)
    assert.ok(lines(dir).length > e.seq, 'notified before the line is on disk')
  })
  await j.append(note('a'))
  await j.append(note('b'))
  off()
  await j.append(note('c'))
  assert.deepEqual(seen, [0, 1])
})

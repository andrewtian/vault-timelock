// Guard convention (global constraints "Guards"; audit CD-minor, the Task 3 deferred item; Task H0
// item 5). Every refusal is ONE line, `if (!ok) refuse('<id>', '<message>') // @guard:<id>`, and every
// marker has exactly one entry in test/mutation/guards.json. The mutation runner blanks each marked line
// and requires the mapped tests to fail, so a refuse( without its marker would escape mutation silently.
// This file checks the convention statically:
//   1. every `refuse(` call in src/ (outside a // comment; the definition in src/guard.ts aside) takes a
//      string-literal guard id and ends its line with `// @guard:<the same id>`, one call per line;
//   2. the wrapper's shell refusals in bin/ the same way: `die <id> "..." # // @guard:<the same id>`;
//   3. nothing in src/ constructs a Refusal except src/guard.ts (a refusal that bypasses refuse());
//   4. markers in src/ and bin/ <-> guards.json keys, one to one (one marker per id, one entry per marker).
// The scanner is self-tested on synthetic text below.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const ROOT = new URL('../../', import.meta.url).pathname

const MARKER = /\/\/ @guard:(\S+)\s*$/
const ID = '[a-z0-9]+(?:[.-][a-z0-9]+)*'

export interface GuardScan { readonly problems: string[]; readonly markers: Array<{ id: string; at: string }> }

const TS_CALL = /\brefuse\s*\(/g
const TS_ID = new RegExp(String.raw`\brefuse\s*\(\s*'(${ID})'`)
const TS_DEFINITION = /\bfunction\s+refuse\s*\(/
const NEW_REFUSAL = /\bnew\s+Refusal\s*\(/
const SH_CALL = /(?:^|[\s;|&(])die\s+(\S+)/
const SH_ID = new RegExp(`^${ID}$`)
const SH_DEFINITION = /^\s*die\s*\(\)/

// One file's text. kind 'ts': refuse( calls; kind 'sh': `die <id>` calls. Whole-line comments are
// skipped (`//`, `/*`, `*` in ts; `#` in sh). A mention inside a TRAILING comment counts as a call: that
// fails closed (reword the comment) instead of letting a call hide behind a `//` inside a string.
export function scanGuards(file: string, text: string, kind: 'ts' | 'sh'): GuardScan {
  const problems: string[] = []
  const markers: Array<{ id: string; at: string }> = []
  text.split('\n').forEach((l, i) => {
    const at = `${file}:${i + 1}`
    const marker = MARKER.exec(l)?.[1]
    if (marker !== undefined) markers.push({ id: marker, at })
    const t = l.trim()
    if (kind === 'ts') {
      if (t.startsWith('//') || t.startsWith('/*') || t.startsWith('*')) return
      if (NEW_REFUSAL.test(l) && file !== 'src/guard.ts') problems.push(`${at} new Refusal( outside src/guard.ts`)
      if (TS_DEFINITION.test(l)) return
      const calls = (l.match(TS_CALL) ?? []).length
      if (calls === 0) return
      if (calls > 1) { problems.push(`${at} more than one refuse( on a line`); return }
      const id = TS_ID.exec(l)?.[1]
      if (id === undefined) problems.push(`${at} refuse( without a string-literal guard id`)
      else if (marker !== id) problems.push(`${at} refuse( without a same-line // @guard:<id> marker of the same id`)
      return
    }
    if (t.startsWith('#') || SH_DEFINITION.test(l)) return
    const call = SH_CALL.exec(l)
    if (call === null) return
    if (!SH_ID.test(call[1])) problems.push(`${at} die without a literal guard id`)
    else if (marker !== call[1] || !/#\s*\/\/ @guard:/.test(l)) problems.push(`${at} die without a same-line # // @guard:<id> marker of the same id`)
  })
  return { problems, markers }
}

function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir).sort()) {
    const p = join(dir, n)
    if (statSync(p).isDirectory()) walk(p, out)
    else out.push(p)
  }
  return out
}

function scanTreeGuards(): GuardScan {
  const problems: string[] = []
  const markers: Array<{ id: string; at: string }> = []
  for (const f of walk(join(ROOT, 'src')).filter((p) => p.endsWith('.ts'))) {
    const s = scanGuards(relative(ROOT, f), readFileSync(f, 'utf8'), 'ts')
    problems.push(...s.problems)
    markers.push(...s.markers)
  }
  for (const f of walk(join(ROOT, 'bin'))) {
    const s = scanGuards(relative(ROOT, f), readFileSync(f, 'utf8'), 'sh')
    problems.push(...s.problems)
    markers.push(...s.markers)
  }
  return { problems, markers }
}

// ---- the real tree

test('every refuse( in src/ and every die in bin/ carries its own // @guard marker; no stray Refusal', () => {
  const s = scanTreeGuards()
  assert.deepEqual(s.problems, [])
  assert.ok(s.markers.length >= 100, `markers found: ${s.markers.length}`)
})

test('markers <-> guards.json, one to one', () => {
  const map = JSON.parse(readFileSync(join(ROOT, 'test/mutation/guards.json'), 'utf8')) as Record<string, string[]>
  const byId = new Map<string, string[]>()
  for (const m of scanTreeGuards().markers) byId.set(m.id, [...(byId.get(m.id) ?? []), m.at])
  const dup = [...byId].filter(([, at]) => at.length > 1).map(([id, at]) => `${id}: ${at.join(', ')}`)
  assert.deepEqual(dup, [], 'one marker per id')
  assert.deepEqual([...byId.keys()].sort(), Object.keys(map).sort(), 'marker ids equal the guards.json keys')
  for (const [id, tests] of Object.entries(map)) assert.ok(Array.isArray(tests) && tests.length > 0, `${id} maps to tests`)
})

// ---- scanner self-tests (synthetic text)

test('scanner: well-formed refuse( lines pass and yield their markers', () => {
  const s = scanGuards('src/x.ts', [
    "  if (!ok) refuse('a.b-c', 'msg') // @guard:a.b-c",
    "  if (n > max) refuse('x.too-long', `over ${max}`) // @guard:x.too-long  ",
    "  // a comment line that mentions refuse('nothing', 'here') is not a call",
    "  const x = 1 // @guard:meta-guard",
  ].join('\n'), 'ts')
  assert.deepEqual(s.problems, [])
  assert.deepEqual(s.markers, [{ id: 'a.b-c', at: 'src/x.ts:1' }, { id: 'x.too-long', at: 'src/x.ts:2' }, { id: 'meta-guard', at: 'src/x.ts:4' }])
})

test('scanner: an unmarked, mismatched, non-literal, split or doubled refuse( is a problem', () => {
  const s = scanGuards('src/x.ts', [
    "  if (!ok) refuse('a.b', 'msg')", // 1: no marker
    "  if (!ok) refuse('a.b', 'msg') // @guard:a.c", // 2: other id
    "  if (!ok) refuse(ID, 'msg') // @guard:a.d", // 3: not a literal
    '  if (!ok) refuse(', // 4: the id is not on the line
    "    'a.e', 'msg') // @guard:a.e",
    "  if (!ok) refuse('a.f', 'm'); if (!y) refuse('a.f', 'm') // @guard:a.f", // 6: two calls
    "  if (!ok) refuse ('a.g', 'msg') // @guard:a.g", // 7: fine (space before the paren)
    "  if (!ok) refuse('a.h', 'msg') // @guard:a.h // trailing", // 8: the marker must end the line
    "  x() // a trailing comment that names refuse('a.i', 'm')", // 9: fail closed, counted as a call
  ].join('\n'), 'ts')
  assert.deepEqual(s.problems, [
    'src/x.ts:1 refuse( without a same-line // @guard:<id> marker of the same id',
    'src/x.ts:2 refuse( without a same-line // @guard:<id> marker of the same id',
    'src/x.ts:3 refuse( without a string-literal guard id',
    'src/x.ts:4 refuse( without a string-literal guard id',
    'src/x.ts:6 more than one refuse( on a line',
    'src/x.ts:8 refuse( without a same-line // @guard:<id> marker of the same id',
    'src/x.ts:9 refuse( without a same-line // @guard:<id> marker of the same id',
  ])
})

test('scanner: the definition in src/guard.ts is not a call; new Refusal( elsewhere is a problem', () => {
  const def = scanGuards('src/guard.ts', "export function refuse(guardId: string, message: string): never {\n  throw new Refusal(guardId, message)\n}", 'ts')
  assert.deepEqual(def.problems, [])
  const other = scanGuards('src/y.ts', "throw new Refusal('y.z', 'm')\nthrow new  Refusal(id, m) // @guard:y.z", 'ts')
  assert.deepEqual(other.problems, ['src/y.ts:1 new Refusal( outside src/guard.ts', 'src/y.ts:2 new Refusal( outside src/guard.ts'])
})

test('scanner: the wrapper convention, die <id> ... # // @guard:<id>', () => {
  const s = scanGuards('bin/w', [
    "die() { id=$1; shift; printf 'refused %s: %s\\n' \"$id\" \"$*\" >&2; exit 2; }",
    '[ "$ok" = 1 ] || die wrapper.a "message" # // @guard:wrapper.a',
    '[ "$ok" = 1 ] || die wrapper.b "message"',
    '[ "$ok" = 1 ] || die wrapper.c "message" # // @guard:wrapper.d',
    '[ "$ok" = 1 ] || die "$id" "message" # // @guard:wrapper.e',
    '# a comment: die wrapper.f is how refusals print',
  ].join('\n'), 'sh')
  assert.deepEqual(s.problems, [
    'bin/w:3 die without a same-line # // @guard:<id> marker of the same id',
    'bin/w:4 die without a same-line # // @guard:<id> marker of the same id',
    'bin/w:5 die without a literal guard id',
  ])
  assert.deepEqual(s.markers.map((m) => m.id), ['wrapper.a', 'wrapper.d', 'wrapper.e'])
})

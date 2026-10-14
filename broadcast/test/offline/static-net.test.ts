// Spec B s6.1: "Every HTTP client is constructed through one factory that injects the SOCKS agent.
// A test asserts that no other client constructor exists in the code."
// Only src/net/ may construct network clients. Any file under src/ OUTSIDE src/net/ that contains a
// network constructor (or imports a networking module) fails this test.
// The only exception mechanism is a line ending in `// net-scan:ok <reason>`; every such line in
// src/ (inside src/net/ too) is counted and must be listed in ALLOWED_EXEMPTIONS: exactly one, the
// confinement probe's direct connect in src/net/confine.ts (Task 7).
// Also (Task 7, defense in depth):
// - viem-style clients (`create*Client` with an http( / webSocket( / custom( transport in the same
//   file) only in src/net/;
// - no `createRequire(` and no non-literal `import(` outside src/net/ (a computed module name could
//   load a networking module past the import check);
// - the gate opener (the mark-gate-passed / pass-gate names) appears only in src/net/gate.ts,
//   anywhere in src/, bin/ or test/, and the un-poisoner (restoreGlobals) only in src/net/poison.ts
//   within src/.
// Task 7b:
// - `getBuiltinModule` (process.getBuiltinModule('node:net') loads a module with no import at all)
//   is flagged everywhere in src/, inside src/net/ too;
// - an `import(` is allowed only as import('<one string literal>'): a concatenation, a template, a
//   variable or a second argument is flagged, everywhere in src/;
// - inside src/net/, raw sockets: `connect` / `createConnection` from node:net / node:tls may be
//   referenced only in src/net/confine.ts and src/net/socks-probe.ts, exactly once each. node:net /
//   node:tls may only be imported by name (those two, isIP/isIPv4/isIPv6, or types); a module object
//   (default, namespace, require, import(), re-export) or a loader (createRequire, require,
//   getBuiltinModule) inside src/net/ is a hit.
// Task 7b fix round 1 (fail closed):
// - imports are parsed on comment-blanked text (a small lexer: `//` inside strings, templates and
//   regex literals is not a comment), and EVERY node:net / node:tls specifier in the original text
//   (any quotes, in comments too) must sit inside an import the parser understood: a quoted
//   specifier (`import { 'connect' as c }`), a bare 'node:net' string, a template, anything the
//   parser can't read is a hit;
// - process.binding / process._linkedBinding (raw native sockets) are flagged everywhere in src/.
// Task H0 (K30): child_process, cluster, vm, worker_threads, inspector and module are refused in all of
// src/, src/net/ too (scanProcessModules).
// Each rule is self-tested on a temp fixture tree (scanTree runs on any root).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative, sep } from 'node:path'

const ROOT = new URL('../../', import.meta.url).pathname

// file (relative to broadcast/) -> number of exempted lines.
const ALLOWED_EXEMPTIONS: Readonly<Record<string, number>> = { 'src/net/confine.ts': 1 }
// src/net file -> references to a raw socket opener (connect/createConnection from node:net|tls).
const ALLOWED_RAW_SOCKETS: Readonly<Record<string, number>> = { 'src/net/confine.ts': 1, 'src/net/socks-probe.ts': 1 }

const EXEMPT = /\/\/ net-scan:ok \S.*$/

// Substrings that construct or reach a network client.
const NEEDLES = [
  'fetch(', 'http.request', 'https.request', 'http.get', 'https.get',
  'net.connect', 'tls.connect', 'new WebSocket', 'new Connection(',
  'axios', 'undici', 'createRequire(', 'getBuiltinModule',
]
// viem-style client constructors and their transports.
const CLIENT = /\bcreate\w*Client\b/
const CLIENT_TRANSPORTS = ['http(', 'webSocket(', 'custom(']
// Importing a networking module at all (static import, dynamic import, require).
const NET_MODULE = /(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*)['"](?:node:)?(?:http|https|http2|net|tls|dgram|dns|dns\/promises|ws|socks|socks-proxy-agent|undici|axios|node-fetch)['"]/

// Native bindings (process.binding('tcp_wrap') is a raw socket with no module at all), in all of src/:
// any `.binding` / `['binding']` property access (whatever the object, so a cast such as
// `(process as any).binding` is caught too) and any `_linkedBinding`.
const BINDING = /(?:\.|\[\s*['"`])\s*binding\b|\b_linkedBinding\b/

// import( is fine only as import('<one string literal>') (no escapes, nothing after it).
const IMPORT_CALL = /\bimport\s*\(/g
const LITERAL_IMPORT = /^import\s*\(\s*(?:'[^'\\\n]*'|"[^"\\\n]*")\s*\)/
export function nonLiteralImport(line: string): boolean {
  for (const m of line.matchAll(IMPORT_CALL)) if (!LITERAL_IMPORT.test(line.slice(m.index))) return true
  return false
}

export interface Hit { readonly file: string; readonly line: number; readonly what: string }

// K30 (Task H0 item 4): process-spawning and code-loading modules are forbidden in ALL of src/, src/net/
// too (a spawned helper, a launchd/LaunchServices request or a vm/worker running other code would sit
// outside every check here). Any quoted specifier naming one, whatever surrounds it (import, export-from,
// import(), require(), or a bare string a loader could be handed), is a hit; so is one quoted in a
// comment (fail closed). Unquoted prose is not.
const PROCESS_MODULE = /[`'"](?:node:)?(?:child_process|cluster|vm|worker_threads|inspector(?:\/promises)?|module)[`'"]/
export function scanProcessModules(file: string, text: string): Hit[] {
  const hits: Hit[] = []
  text.split('\n').forEach((l, i) => { if (PROCESS_MODULE.test(l)) hits.push({ file, line: i + 1, what: 'process/code-loading module' }) })
  return hits
}

// Scan one file's text (a file OUTSIDE src/net/). A `create*Client` line in a file that also has
// `http(`, `webSocket(` or `custom(` anywhere (viem's transports) is a hit on the create*Client line.
export function scanText(file: string, text: string): { hits: Hit[]; exemptions: number } {
  const hits: Hit[] = []
  let exemptions = 0
  const lines = text.split('\n')
  const clientTransport = lines.some((l) => !EXEMPT.test(l) && CLIENT_TRANSPORTS.some((t) => l.includes(t)))
  lines.forEach((l, i) => {
    if (EXEMPT.test(l)) { exemptions++; return }
    for (const n of NEEDLES) if (l.includes(n)) hits.push({ file, line: i + 1, what: n })
    if (NET_MODULE.test(l)) hits.push({ file, line: i + 1, what: 'network module import' })
    if (BINDING.test(l)) hits.push({ file, line: i + 1, what: 'process.binding' })
    if (nonLiteralImport(l)) hits.push({ file, line: i + 1, what: 'non-literal import(' })
    if (clientTransport && CLIENT.test(l)) hits.push({ file, line: i + 1, what: 'create*Client + http(/webSocket(/custom(' })
  })
  return { hits, exemptions }
}

// ---- src/net/: raw sockets and module loaders

const SOCKET_MODULE = String.raw`['"](?:node:)?(?:net|tls)['"]`
// `import ... from 'node:net'` / `export ... from 'node:tls'`, matched on the comment-blanked text (a
// clause has no quotes, so the match never runs across an earlier import's `from '...'`).
const SOCKET_FROM = new RegExp(String.raw`\b(import|export)\s+(type\s+)?([\w\s{},*$]*?)\s*\bfrom\s*${SOCKET_MODULE}`, 'g')
const SOCKET_DYNAMIC = new RegExp(String.raw`\b(?:import|require)\s*\(\s*${SOCKET_MODULE}`, 'g')
// Fail closed: every node:net / node:tls specifier in the ORIGINAL text (any quotes, comments too)
// must sit inside an import the parser understood (or an import()/require that is a hit anyway).
const SOCKET_SPECIFIER = /[`'"](?:node:)?(?:net|tls)[`'"]/g
const LOADER = /\bgetBuiltinModule\b|\bcreateRequire\b|\brequire\s*\(/
const RAW_OPENERS = ['connect', 'createConnection']
const SAFE_SOCKET_IMPORTS = ['isIP', 'isIPv4', 'isIPv6']

const lineAt = (text: string, index: number): number => text.slice(0, index).split('\n').length

// ---- comment blanking: a small lexer, so `//` inside 'a//b', `http://` or /\/\// is not a comment

const REGEX_AFTER_WORD = ['return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'throw', 'case', 'do', 'else', 'yield', 'await']
// Can a `/` here start a regex literal (rather than divide)? The usual rule: yes after an operator,
// an opening bracket, punctuation, a keyword, or at the start.
function regexCanStart(out: string): boolean {
  let j = out.length - 1
  while (j >= 0 && /\s/.test(out[j])) j--
  if (j < 0) return true
  const c = out[j]
  if ('(,=:[!&|?{};+-*%<>~^'.includes(c)) return true
  if (!/[\w$]/.test(c)) return false
  let k = j
  while (k >= 0 && /[\w$]/.test(out[k])) k--
  return REGEX_AFTER_WORD.includes(out.slice(k + 1, j + 1))
}
// The end (exclusive) of the string/template starting at i; an unterminated quote stops at the line.
function stringEnd(t: string, i: number, q: string): number {
  let j = i + 1
  while (j < t.length) {
    if (t[j] === '\\') { j += 2; continue }
    if (t[j] === q) return j + 1
    if (q !== '`' && t[j] === '\n') return j
    j++
  }
  return t.length
}
// The end (exclusive) of the regex literal starting at i, flags included; a newline first means it
// was not one (the line is then kept as is).
function regexEnd(t: string, i: number): number {
  let j = i + 1
  let inClass = false
  while (j < t.length) {
    const c = t[j]
    if (c === '\\') { j += 2; continue }
    if (c === '\n') return j
    if (inClass) { if (c === ']') inClass = false }
    else if (c === '[') inClass = true
    else if (c === '/') {
      j++
      while (j < t.length && /[a-z]/i.test(t[j])) j++
      return j
    }
    j++
  }
  return t.length
}
// Blanks comments to spaces (newlines kept), so indices and line numbers still match the original.
// Strings, templates and regex literals are copied as units. Only comments are ever removed, so a
// misread can only keep more text (over-count, fail closed), except a quote inside a regex literal
// that is misread as a division; the SOCKET_SPECIFIER catch-all on the original text covers the
// specifiers in that case, and the OS sandbox stays the backstop.
function stripComments(t: string): string {
  let out = ''
  let i = 0
  while (i < t.length) {
    const c = t[i]
    const n = t[i + 1]
    let j = i + 1
    if (c === '/' && n === '/') {
      const e = t.indexOf('\n', i)
      j = e < 0 ? t.length : e
      out += ' '.repeat(j - i)
    } else if (c === '/' && n === '*') {
      const e = t.indexOf('*/', i + 2)
      j = e < 0 ? t.length : e + 2
      out += t.slice(i, j).replace(/[^\n]/g, ' ')
    } else {
      if (c === "'" || c === '"' || c === '`') j = stringEnd(t, i, c)
      else if (c === '/' && regexCanStart(out)) j = regexEnd(t, i)
      out += t.slice(i, j)
    }
    i = j
  }
  return out
}

// Scan one file INSIDE src/net/: hits, plus the number of references to raw socket openers.
export function scanNetText(file: string, text: string): { hits: Hit[]; rawSockets: number } {
  const hits: Hit[] = []
  const locals: string[] = []
  const stripped = stripComments(text)
  const understood: Array<[number, number]> = []
  for (const m of stripped.matchAll(SOCKET_FROM)) {
    understood.push([m.index, m.index + m[0].length])
    const line = lineAt(text, m.index)
    if (m[1] === 'export') { hits.push({ file, line, what: 'node:net/tls re-export' }); continue }
    if (m[2] !== undefined) continue // `import type`: erased
    const clause = m[3].trim()
    const brace = clause.indexOf('{')
    const head = (brace < 0 ? clause : clause.slice(0, brace)).replace(/,\s*$/, '').trim()
    if (head !== '') hits.push({ file, line, what: `node:net/tls module object (${head})` })
    if (brace < 0) continue
    for (const spec of clause.slice(brace + 1, clause.lastIndexOf('}')).split(',').map((x) => x.trim()).filter((x) => x !== '')) {
      if (/^type\s/.test(spec)) continue
      const sm = /^([\w$]+)(?:\s+as\s+([\w$]+))?$/.exec(spec)
      if (sm === null) { hits.push({ file, line, what: `node:net/tls import (${spec})` }); continue }
      if (RAW_OPENERS.includes(sm[1])) locals.push(sm[2] ?? sm[1])
      else if (!SAFE_SOCKET_IMPORTS.includes(sm[1])) hits.push({ file, line, what: `node:net/tls import ${sm[1]}` })
    }
  }
  for (const m of text.matchAll(SOCKET_DYNAMIC)) understood.push([m.index, m.index + m[0].length])
  for (const m of text.matchAll(SOCKET_SPECIFIER)) {
    const inside = understood.some(([a, b]) => m.index >= a && m.index < b)
    if (!inside) hits.push({ file, line: lineAt(text, m.index), what: 'node:net/tls named outside a recognised import' })
  }
  text.split('\n').forEach((l, i) => {
    if (LOADER.test(l)) hits.push({ file, line: i + 1, what: 'module loader' })
    if (BINDING.test(l)) hits.push({ file, line: i + 1, what: 'process.binding' })
    if (new RegExp(SOCKET_DYNAMIC.source).test(l)) hits.push({ file, line: i + 1, what: 'node:net/tls module object (import()/require)' })
    if (nonLiteralImport(l)) hits.push({ file, line: i + 1, what: 'non-literal import(' })
  })
  // Every reference counts (a call, an alias, a shorthand property), outside comments, strings
  // ('connect' events) and the import statements themselves.
  const code = stripped.replace(SOCKET_FROM, '')
  let rawSockets = 0
  for (const l of locals) rawSockets += (code.match(new RegExp(`(?<![\\w$.'"\`])${l.replace(/\$/g, '\\$')}(?![\\w$'"\`])`, 'g')) ?? []).length
  return { hits, rawSockets }
}

function walk(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) return out
  for (const n of readdirSync(dir).sort()) {
    const p = join(dir, n)
    if (statSync(p).isDirectory()) walk(p, out)
    else out.push(p)
  }
  return out
}

export interface TreeScan {
  readonly files: number
  readonly netFiles: number
  readonly hits: string[] // `<file>:<line> <what>`
  readonly exemptions: Record<string, number>
  readonly rawSockets: Record<string, number>
}

// Runs every rule over <root>/src.
export function scanTree(root: string): TreeScan {
  const src = join(root, 'src')
  const netDir = join(src, 'net') + sep
  const hits: string[] = []
  const exemptions: Record<string, number> = {}
  const rawSockets: Record<string, number> = {}
  let files = 0
  let netFiles = 0
  for (const f of walk(src)) {
    const rel = relative(root, f)
    const text = readFileSync(f, 'utf8')
    files++
    const outside = scanText(rel, text)
    const processModules = scanProcessModules(rel, text)
    if (outside.exemptions > 0) exemptions[rel] = outside.exemptions
    if (!f.startsWith(netDir)) {
      for (const h of [...outside.hits, ...processModules]) hits.push(`${h.file}:${h.line} ${h.what}`)
      continue
    }
    netFiles++
    const inside = scanNetText(rel, text)
    for (const h of [...inside.hits, ...processModules]) hits.push(`${h.file}:${h.line} ${h.what}`)
    if (inside.rawSockets > 0) rawSockets[rel] = inside.rawSockets
  }
  return { files, netFiles, hits, exemptions, rawSockets }
}

// A throwaway tree for the self-tests (removed by the caller).
function fixture(files: Readonly<Record<string, string>>): string {
  const root = mkdtempSync(join(tmpdir(), 'vt-static-net-'))
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true })
    writeFileSync(join(root, rel), text)
  }
  return root
}
function scanFixture(files: Readonly<Record<string, string>>): TreeScan {
  const root = fixture(files)
  try { return scanTree(root) } finally { rmSync(root, { recursive: true, force: true }) }
}

// ---- the real tree

test('no network constructor, networking import, loader or raw socket outside the allowed places in src/', () => {
  const s = scanTree(ROOT)
  assert.ok(s.netFiles > 0, 'src/net/ exists')
  assert.ok(s.files > s.netFiles, 'there are files outside src/net/ to scan')
  assert.deepEqual(s.hits, [])
})

test('net-scan:ok exemptions in src/ are exactly the allowed ones (the confinement probe)', () => {
  assert.deepEqual(scanTree(ROOT).exemptions, ALLOWED_EXEMPTIONS)
})

test('raw sockets in src/net/: connect/createConnection only in confine.ts and socks-probe.ts, once each', () => {
  assert.deepEqual(scanTree(ROOT).rawSockets, ALLOWED_RAW_SOCKETS)
})

// ---- scanner self-tests (strings)

test('the scanner catches each needle, networking imports, viem transports, and honours the exemption', () => {
  const samples: Array<[string, string]> = [
    ['const r = await fetch(url)', 'fetch('],
    ['http.request(opts)', 'http.request'],
    ['https.request(opts)', 'https.request'],
    ['http.get(u)', 'http.get'],
    ['https.get(u)', 'https.get'],
    ['net.connect(9, h)', 'net.connect'],
    ['tls.connect({})', 'tls.connect'],
    ['const ws = new WebSocket(u)', 'new WebSocket'],
    ['const c = new Connection(url)', 'new Connection('],
    ["import axios from 'x'", 'axios'],
    ["import { request } from 'undici'", 'undici'],
    ["const n = process.getBuiltinModule('node:net')", 'getBuiltinModule'],
  ]
  for (const [line, what] of samples) {
    assert.ok(scanText('x.ts', line).hits.some((h) => h.what === what), what)
  }
  for (const line of [
    "import { request } from 'node:https'", "import * as http from 'http'", "import { connect } from 'node:net'",
    "import { lookup } from 'node:dns'", "import dns from 'dns/promises'", "const tls = await import('node:tls')",
    "const h = require('http2')", "import { SocksProxyAgent } from 'socks-proxy-agent'", "import { createSocket } from 'node:dgram'",
  ]) {
    assert.ok(scanText('x.ts', line).hits.some((h) => h.what === 'network module import'), line)
  }
  const viem = scanText('x.ts', "import { createPublicClient, http } from 'viem'\nconst c = createPublicClient({ transport: http(u) })")
  assert.ok(viem.hits.some((h) => h.what.startsWith('create*Client')))
  const viemWs = scanText('x.ts', 'const c = createPublicClient({\n  transport: webSocket(u),\n})')
  assert.ok(viemWs.hits.some((h) => h.what.startsWith('create*Client')))
  // Any create*Client, and custom( too: viem clients are built only inside src/net/.
  for (const text of [
    'const c = createPublicClient({ transport: custom(net.jsonRpc(role, url)) })',
    'const w = createWalletClient({ account, transport: http(u) })',
    'const t = createTestClient({ mode: "anvil",\n transport: webSocket(u) })',
  ]) {
    assert.ok(scanText('x.ts', text).hits.some((h) => h.what.startsWith('create*Client')), text)
  }
  assert.deepEqual(scanText('x.ts', 'const c = createPublicClient(opts)').hits, [], 'no transport in the file')
  // createRequire( and non-literal import(.
  assert.ok(scanText('x.ts', "const require = createRequire(import.meta.url)").hits.some((h) => h.what === 'createRequire('))
  for (const line of [
    'const m = await import(name)', 'await import (`node:${x}`)', 'import(\n', 'const m = await import( mod )',
    "await import('node:' + 'net')", 'await import(`./x.ts`)', "await import('./x.ts', { with: {} })",
    "await import('./x.ts' + s)", "await import('./a\\'b.ts')", "x = [import('./a.ts'), import(b)]",
  ]) {
    assert.ok(scanText('x.ts', line).hits.some((h) => h.what === 'non-literal import('), line)
  }
  for (const line of [
    "const m = await import('./sealed.ts')", 'const m = await import("./x.ts")', "type T = typeof import('./x.ts')",
    'const u = import.meta.url', "const m = await import( './x.ts' )",
  ]) {
    assert.deepEqual(scanText('x.ts', line).hits, [], line)
  }
  // Negatives: our own net layer calls and ordinary imports.
  assert.deepEqual(scanText('x.ts', "import { createNet } from './net/fetch.ts'\nconst f = net.fetchFor('drand')\nimport { join } from 'node:path'").hits, [])
  // The exemption: counted, and the line is not a hit.
  const ex = scanText('x.ts', 'net.connect(9, h) // net-scan:ok confinement probe\nfetch(u)')
  assert.equal(ex.exemptions, 1)
  assert.deepEqual(ex.hits.map((h) => h.line), [2])
  // A bare marker without a reason is not an exemption.
  assert.equal(scanText('x.ts', 'fetch(u) // net-scan:ok').exemptions, 0)
})

// ---- K30 (Task H0 item 4): no process or code-loading modules anywhere in src/

test('fixture (H0-4): child_process, cluster, vm, worker_threads, inspector and module are flagged in all of src/', () => {
  const s = scanFixture({
    'src/a.ts': "import { spawn } from 'node:child_process'\n",
    'src/b.ts': "import * as cp from \"child_process\"\nconst w = await import('node:worker_threads')\n",
    'src/c.ts': "import vm from 'node:vm'\nexport { Session } from 'inspector/promises'\n",
    'src/d.ts': "import { createRequire } from 'module'\n",
    'src/e.ts': "const name = `node:cluster`\nconst i = 'node:inspector'\n",
    'src/net/f.ts': "import { fork } from 'node:child_process'\n",
    // fine: words in prose and identifiers, other node: modules
    'src/ok.ts': "import { join } from 'node:path'\n// spawning a child_process is forbidden\nconst vmName = 'a module'\n",
  })
  assert.deepEqual(s.hits.filter((h) => h.endsWith('process/code-loading module')), [
    'src/a.ts:1 process/code-loading module',
    'src/b.ts:1 process/code-loading module', 'src/b.ts:2 process/code-loading module',
    'src/c.ts:1 process/code-loading module', 'src/c.ts:2 process/code-loading module',
    'src/d.ts:1 process/code-loading module',
    'src/e.ts:1 process/code-loading module', 'src/e.ts:2 process/code-loading module',
    'src/net/f.ts:1 process/code-loading module',
  ])
})

// ---- scanner self-tests (temp fixture trees: the same scanTree that runs on the real tree)

test('fixture: getBuiltinModule is flagged everywhere in src/, inside src/net/ too', () => {
  const s = scanFixture({
    'src/a.ts': "const net = process.getBuiltinModule('node:net')\n",
    'src/net/b.ts': "const tls = process.getBuiltinModule('node:tls')\n",
    'src/ok.ts': "import { join } from 'node:path'\n",
  })
  assert.deepEqual(s.hits, [
    'src/a.ts:1 getBuiltinModule', 'src/net/b.ts:1 node:net/tls named outside a recognised import', 'src/net/b.ts:1 module loader',
  ])
})

test('fixture (fix round 1): process.binding / _linkedBinding are flagged everywhere in src/', () => {
  const s = scanFixture({
    'src/a.ts': "const tcp = process.binding('tcp_wrap')\n",
    'src/b.ts': "const t = process['binding']('tcp_wrap')\n",
    'src/c.ts': 'const t = process . _linkedBinding(name)\n',
    'src/d.ts': "const t = (process as unknown as { binding(n: string): unknown }).binding('tcp_wrap')\n",
    'src/net/e.ts': "const t = process.binding('tls_wrap')\n",
    'src/ok.ts': 'const bindings = new Map()\nconst keyBinding = 1\n',
  })
  assert.deepEqual(s.hits, [
    'src/a.ts:1 process.binding', 'src/b.ts:1 process.binding', 'src/c.ts:1 process.binding', 'src/d.ts:1 process.binding',
    'src/net/e.ts:1 process.binding',
  ])
})

test('fixture: an import( that is not one string literal is flagged, outside and inside src/net/', () => {
  const s = scanFixture({
    'src/a.ts': [
      "const ok = await import('./ok.ts')", // 1: fine
      "const m = await import('node:' + 'net')", // 2
      'const t = await import(`./x.ts`)', // 3
      "const o = await import('./x.ts', { with: { type: 'json' } })", // 4
      'const v = await import(name)', // 5
      "type T = typeof import('./t.ts')", // 6: fine
    ].join('\n'),
    'src/net/c.ts': 'const m = await import(mod)\n',
  })
  assert.deepEqual(s.hits, [
    'src/a.ts:2 non-literal import(', 'src/a.ts:3 non-literal import(', 'src/a.ts:4 non-literal import(',
    'src/a.ts:5 non-literal import(', 'src/net/c.ts:1 non-literal import(',
  ])
})

test('fixture: raw sockets in src/net/ are counted per file; module objects and loaders are hits', () => {
  const s = scanFixture({
    // one reference; the 'connect' event and the comments do not count
    'src/net/confine.ts': "import { connect } from 'node:net'\n// connect( in a comment\nconst s = connect({ port: 9 }) /* connect() */\ns.on('connect', f)\n",
    // an alias, called once and copied once: two references
    'src/net/socks-probe.ts': "import { connect as open, isIP } from 'node:net'\nopen(1)\nconst again = open\n",
    // a multi-line import from node:tls in a file that may not open raw sockets
    'src/net/fetch.ts': "import {\n  createConnection,\n  type TLSSocket,\n} from 'node:tls'\ncreateConnection({})\n",
    'src/net/ns.ts': "import * as net from 'node:net'\nnet.connect(1)\n",
    'src/net/def.ts': "import tls from 'tls'\n",
    'src/net/req.ts': "const net = require('node:net')\n",
    'src/net/dyn.ts': "const { connect } = await import('node:net')\n",
    'src/net/reexport.ts': "export { connect } from 'node:net'\n",
    'src/net/sock.ts': "import { Socket } from 'node:net'\nnew Socket().connect(1)\n",
    'src/net/cr.ts': "const r = createRequire(import.meta.url)\n",
    // fine: types, isIP, and an http Agent's own createConnection method
    'src/net/types.ts': "import type { Socket } from 'node:net'\nimport { isIP, type LookupFunction } from 'node:net'\n",
    'src/net/agent.ts': "import http from 'node:http'\nclass A extends http.Agent { override createConnection(): never { return x() } }\n",
    'src/elsewhere.ts': "import { join } from 'node:path'\n",
  })
  assert.deepEqual(s.rawSockets, { 'src/net/confine.ts': 1, 'src/net/fetch.ts': 1, 'src/net/socks-probe.ts': 2 })
  assert.notDeepEqual(s.rawSockets, ALLOWED_RAW_SOCKETS)
  assert.deepEqual(s.hits, [
    'src/net/cr.ts:1 module loader',
    'src/net/def.ts:1 node:net/tls module object (tls)',
    'src/net/dyn.ts:1 node:net/tls module object (import()/require)',
    'src/net/ns.ts:1 node:net/tls module object (* as net)',
    'src/net/reexport.ts:1 node:net/tls re-export',
    'src/net/req.ts:1 module loader',
    'src/net/req.ts:1 node:net/tls module object (import()/require)',
    'src/net/sock.ts:1 node:net/tls import Socket',
  ])
  // The allowed shape passes.
  const ok = scanFixture({
    'src/net/confine.ts': "import { connect } from 'node:net'\nconst s = connect({ port: 9 })\n",
    'src/net/socks-probe.ts': "import { connect } from 'node:net'\nconst s = connect({ port: 1 })\n",
    'src/x.ts': "import { join } from 'node:path'\n",
  })
  assert.deepEqual(ok.hits, [])
  assert.deepEqual(ok.rawSockets, ALLOWED_RAW_SOCKETS)
})

test('fixture (fix round 1): node:net/tls imports the parser cannot read fail closed', () => {
  const s = scanFixture({
    // (a) a block comment inside the braces: still parsed (comments are blanked first), 2 references
    'src/net/a.ts': "import { connect /* raw */ } from 'node:net'\nconnect(1)\nconnect(2)\n",
    // (b) a line comment inside a multi-line import: still parsed, 1 reference
    'src/net/b.ts': "import {\n  connect, // raw probe\n  isIP,\n} from 'node:net'\nconnect(1)\n",
    // (c) a quoted specifier: not parsed, so the specifier string is unaccounted for: a hit
    'src/net/c.ts': "import { 'connect' as c } from 'node:net'\nc(1)\n",
    // (d) a comment next to a forbidden name: parsed, Socket is a hit
    'src/net/d.ts': "import { Socket /**/ } from 'node:net'\nnew Socket().connect(1)\n",
    // a quoted re-export, a bare specifier string, a template, a specifier quoted in a comment
    'src/net/e.ts': "export { 'connect' as c } from 'node:tls'\n",
    'src/net/f.ts': "const s = 'a//b'; const m = 'node:net'\n",
    'src/net/g.ts': 'const m = `node:tls`\n',
    'src/net/h.ts': "// the raw socket API lives in 'node:net'\n",
    // `//` inside a string and a quote inside a regex literal do not hide code: 2 references
    'src/net/i.ts': "import { connect } from 'node:net'\nconst u = 'a//b'; connect(1)\nconst r = /'/; connect(2) // c\n",
    // `from` on its own line is still an import
    'src/net/j.ts': "import {\n  createConnection,\n} from\n  'node:tls'\ncreateConnection({})\n",
  })
  assert.deepEqual(s.rawSockets, { 'src/net/a.ts': 2, 'src/net/b.ts': 1, 'src/net/i.ts': 2, 'src/net/j.ts': 1 })
  assert.deepEqual(s.hits, [
    'src/net/c.ts:1 node:net/tls named outside a recognised import',
    'src/net/d.ts:1 node:net/tls import Socket',
    'src/net/e.ts:1 node:net/tls named outside a recognised import',
    'src/net/f.ts:1 node:net/tls named outside a recognised import',
    'src/net/g.ts:1 node:net/tls named outside a recognised import',
    'src/net/h.ts:1 node:net/tls named outside a recognised import',
  ])
})

test('stripComments blanks comments only: strings, templates and regex literals keep their `//` and quotes', () => {
  const cases: Array<[string, string]> = [
    ["a // c\nb", 'a     \nb'],
    ['a /* c\nd */ b', 'a     \n     b'],
    ["const u = 'a//b' // c", "const u = 'a//b'     "],
    ['const u = "http://x" /* c */', 'const u = "http://x"        '],
    ['const t = `a // ${x} b` // c', 'const t = `a // ${x} b`     '],
    ["const r = /'/; f() // c", "const r = /'/; f()     "],
    ['const r = /[/]\\//g; f() // c', 'const r = /[/]\\//g; f()     '],
    ['const q = a / b / c // c', 'const q = a / b / c     '],
    ["const s = 'it\\'s // here' // c", "const s = 'it\\'s // here'     "],
  ]
  for (const [input, want] of cases) {
    const got = stripComments(input)
    assert.equal(got, want, input)
    assert.equal(got.length, input.length, 'positions are kept')
  }
})

// ---- names that must stay in one place

// The gate opener's names, assembled so this file does not contain them literally.
const OPENERS = ['mark' + 'GatePassed', 'pass' + 'Gate']

function scanNames(roots: string[], names: readonly string[], pattern = (n: string) => `\\b${n}\\b`): string[] {
  const out: string[] = []
  for (const r of roots) {
    for (const f of walk(join(ROOT, r))) {
      const text = readFileSync(f, 'utf8')
      for (const n of names) if (new RegExp(pattern(n)).test(text)) out.push(`${relative(ROOT, f)} ${n}`)
    }
  }
  return out.sort()
}

test('the gate opener appears only in src/net/gate.ts (src/, bin/, test/)', () => {
  const found = scanNames(['src', 'bin', 'test'], OPENERS)
  assert.deepEqual(found, ['src/net/gate.ts ' + OPENERS[1]])
})

test('restoreGlobals appears in src/ only in src/net/poison.ts', () => {
  assert.deepEqual(scanNames(['src'], ['restoreGlobals']), ['src/net/poison.ts restoreGlobals'])
})

test('housekeeping (Task 7b): SOCKS_HOST is declared once in src/; confine.ts no longer exports CONFINED_ERRNO', () => {
  assert.deepEqual(scanNames(['src'], ['SOCKS_HOST'], (n) => `\\bconst\\s+${n}\\b`), ['src/net/socks-probe.ts SOCKS_HOST'])
  assert.deepEqual(scanNames(['src'], ['CONFINED_ERRNO']), [])
})

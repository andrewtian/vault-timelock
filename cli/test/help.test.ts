// cli/test/help.test.ts — `vt help` (src/help.ts, plan Task C1): the workflow in order and every command of
// canonical vt spec §8.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join } from 'node:path'
import { helpText } from '../src/help.ts'
import { PATH0, run, tempDir, removeDir } from './lib.ts'

const text = helpText()

test('the workflow, in order: seal -> up -> job create -> arm -> run -> status -> receipt -> down', () => {
  const start = text.indexOf('Workflow, in order:')
  const end = text.indexOf('Commands:')
  assert.ok(start >= 0 && end > start)
  const block = text.slice(start, end)
  const steps = ['vt seal ', 'vt up ', 'vt job create ', 'vt job arm ', 'vt job run ', 'vt job status ', 'vt job receipt ', 'vt down ']
  const at = steps.map((s) => block.indexOf(s))
  for (const [i, s] of steps.entries()) assert.ok(at[i] >= 0, `the workflow names ${s}`)
  for (let i = 1; i < at.length; i++) assert.ok(at[i - 1] < at[i], `${steps[i - 1]} comes before ${steps[i]}`)
  // Numbered 1..8, one per line.
  const numbered = block.split('\n').filter((l) => /^ {2}\d\. /.test(l))
  assert.deepEqual(numbered.map((l) => l.trim().split('.')[0]), ['1', '2', '3', '4', '5', '6', '7', '8'])
})

// Every command of spec §8 (the table's first column), as it must appear in the Commands section.
const SPEC_8 = [
  'vt help',
  'vt up [--network local|testnet|mainnet] [--open] [--dev]',
  'vt down [--network N]',
  'vt status [--network N] [--json]',
  'vt preflight',
  'vt logs relay|api|page|vite [--network N] [-n N] [-f]',
  'vt backup import <file> [--chain eth|sol|btc]',
  'vt source list [--json]',
  'vt source add <label>',
  'vt job validate <file>',
  'vt job create <file>',
  'vt job list',
  'vt job status <id> [--watch] [--json]',
  'vt job arm <id> [--chains eth,sol] [--source eth=a,sol=b]',
  'vt job skip <id>',
  'vt job stop <id> [--chain c]',
  'vt job resume <id> [--chain c] [--tip-cap-gwei X] [--cu-price-cap N]',
  'vt job close <id> --chain c',
  'vt job run <id> [--chain eth|sol|btc] [--backup-eth F] [--backup-sol F] [--backup-btc F]',
  'vt job clawback <id> --chain c --to <addr> [--backup-<c> F]',
  'vt job resolve <id> --chain c --tx <id> mark-done|mark-failed',
  'vt job receipt <id> [--json]',
  'vt job watch <id> [--from N] [--json]',
  'vt release build | verify [<id>] | list',
  'vt seal vault', 'vt seal file', 'vt open vault', 'vt open file',
  'vt note validate', 'vt seal-text', 'vt tor-check', 'vt keystore init', 'vt triggers',
]

test('every command of spec §8 is listed under Commands', () => {
  const commands = text.slice(text.indexOf('Commands:'))
  for (const c of SPEC_8) assert.ok(commands.includes(c), `help lists: ${c}`)
  // The pass-throughs name their vt-broadcast targets (spec §11).
  for (const t of ['vt-broadcast validate-note', 'vt-broadcast seal-text', 'vt-broadcast tor-check', 'vt-broadcast keystore init', 'vt-broadcast triggers']) {
    assert.ok(commands.includes(t), t)
  }
})

test('vt help through the wrapper: the same text, exit 0, no directories needed', () => {
  const T = tempDir('vt-help-')
  try {
    for (const args of [['help'], [], ['--help'], ['-h'], ['--network', 'mainnet', 'help']]) {
      const r = run(args, { env: { PATH: PATH0, HOME: join(T) } })
      assert.equal(r.code, 0, r.err)
      assert.equal(r.out, text)
      assert.equal(r.err, '')
    }
  } finally {
    removeDir(T)
  }
})

test('C1 M6 / C5: client commands reach the page, relay and API ports and write no files; no --out; vite logs; the tmux attach line; the job rules', () => {
  assert.ok(text.includes("Client commands (sandbox: the network's page, relay and API ports only; no file writes; no terminal: vt's unsandboxed broker asks every typed word)"))
  assert.ok(text.includes("Executor (sandbox: relay and API ports, no terminal: vt's broker asks the passphrase; needs a terminal; holds the key in memory only)"))
  assert.ok(!text.includes('/dev/tty'), 'TTY-less round: no sandboxed command is given /dev/tty')
  assert.ok(!text.includes('--out F') && !/relay and API ports only/.test(text.replace("page, relay and API ports only", '')), 'no --out, and no "relay and API ports only" for clients')
  assert.match(text, /vt job receipt <id> \[--json\] {3}\(stdout only, no --out/)
  assert.ok(text.includes('vt logs relay|api|page|vite'))
  assert.ok(text.includes('tmux -L vt attach -t vt-<network>'))
  assert.match(text, /mark-failed frees\n? *no cap: only chain evidence/)
  assert.match(text, /Only --normalize rewrites, and only when given/)
  assert.match(text, /never put in argv/)
  // Security review: the message file comes from the command line only, behind the denylist and a typed `publish`.
  assert.ok(text.includes('vt job create <file> [--message-file <path>] [--yes-publish-file <sha256>] [--normalize] [--json]'))
  assert.match(text, /never from the job file: a job JSON naming a file is refused/)
  assert.match(text, /only after you type publish/)
  assert.match(text, /refused while job sends are locked/)
})

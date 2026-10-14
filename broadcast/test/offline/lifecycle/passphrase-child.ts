// Test child for passphrase.test.ts (Task 12b). Runs readPassphrase on its controlling terminal (a pty from script(1),
// or none at all) and prints ONE line: a SHA-256 of what it read (never the passphrase) or the refusal's guard id, and
// whether the terminal's mode (`stty -g`) is the same afterwards as before.
//   node passphrase-child.ts once|confirm
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { Refusal } from '../../../src/guard.ts'
import { readPassphrase } from '../../../src/lifecycle/passphrase.ts'

const ttyMode = (): string => {
  const r = spawnSync('/bin/stty', ['-g', '-f', '/dev/tty'], { encoding: 'utf8' })
  return r.status === 0 ? r.stdout.trim() : ''
}

const before = ttyMode()
let line: string
try {
  const p = await readPassphrase({ confirm: process.argv[2] === 'confirm' })
  line = `read sha256=${createHash('sha256').update(p, 'utf8').digest('hex')}`
} catch (e) {
  line = e instanceof Refusal ? `refused ${e.guardId}` : 'error (not a refusal)'
}
const after = ttyMode()
process.stdout.write(`${line} restored=${before !== '' && before === after}\n`)

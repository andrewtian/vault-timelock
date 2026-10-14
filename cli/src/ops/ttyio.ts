// cli/src/ops/ttyio.ts — the terminal primitives shared by the unsandboxed broker (src/ops/broker.ts) and the plain executor path (src/job/tty.ts).
// Deliberately small imports (node builtins only): the broker is the process that types the passphrase.
import { spawnSync } from 'node:child_process'
import { closeSync, constants, openSync, writeSync } from 'node:fs'
import { isatty, ReadStream } from 'node:tty'

export type Key = 'skip' | 'interrupt'

// One byte typed during a run → what it means (null: ignored).
export function keyOf(b: number): Key | null {
  if (b === 0x73 || b === 0x53) return 'skip'          // s, S
  if (b === 0x03 || b === 0x1c) return 'interrupt'     // Ctrl-C, Ctrl-\ (raw mode: bytes, not signals)
  return null
}

// stdin is a terminal and /dev/tty opens as a terminal (read-write, never as a controlling terminal).
export function terminalAvailable(ttyPath = '/dev/tty', stdinIsTTY: boolean = process.stdin.isTTY === true): boolean {
  if (!stdinIsTTY) return false
  let fd: number
  try { fd = openSync(ttyPath, constants.O_RDWR | constants.O_NOCTTY) } catch { return false } // ENXIO: no terminal
  try { return isatty(fd) } finally { closeSync(fd) }
}

// The raw-mode key reader on /dev/tty. Bytes are mapped to keys at once and never kept.
export function rawKeys(on: (k: Key) => void, ttyPath = '/dev/tty'): () => void {
  let fd: number
  try { fd = openSync(ttyPath, constants.O_RDWR | constants.O_NOCTTY) } catch { return () => {} }
  if (!isatty(fd)) { closeSync(fd); return () => {} }
  let rs: ReadStream
  try { rs = new ReadStream(fd) } catch { closeSync(fd); return () => {} }
  let stopped = false
  const restore = (): void => { try { rs.setRawMode(false) } catch { /* the terminal is gone */ } }
  try { rs.setRawMode(true) } catch { /* not a terminal after all: keys are just not read */ }
  process.once('exit', restore)
  rs.on('data', (chunk: Buffer) => {
    for (const b of chunk) { const k = keyOf(b); if (k !== null) { try { on(k) } catch { /* the handler reports its own errors */ } } }
    chunk.fill(0)
  })
  rs.on('error', () => { /* a closed terminal: no more keys; the run goes on */ })
  return () => {
    if (stopped) return
    stopped = true
    restore()
    process.off('exit', restore)
    rs.destroy() // closes fd
  }
}

// Writes text straight to the terminal (the broker's own prompt lines, never the child's).
export function writeTty(text: string, ttyPath = '/dev/tty'): void {
  let fd: number
  try { fd = openSync(ttyPath, constants.O_WRONLY | constants.O_NOCTTY) } catch { return }
  try { writeSync(fd, text) } catch { /* the terminal is gone */ } finally { closeSync(fd) }
}

// The terminal's settings as `stty -g` prints them, and putting them back. The broker saves them at start and restores them on every way out
// (exit, signals, a refused child, a child that died mid-prompt), so a raw / no-echo state never outlives it.
export function saveTermios(ttyPath = '/dev/tty'): string | null {
  let fd: number
  try { fd = openSync(ttyPath, constants.O_RDWR | constants.O_NOCTTY) } catch { return null }
  try {
    const r = spawnSync('/bin/stty', ['-g'], { stdio: [fd, 'pipe', 'ignore'], encoding: 'utf8', timeout: 5_000 })
    const s = typeof r.stdout === 'string' ? r.stdout.trim() : ''
    // macOS prints "gfmt1:cflag=4b00:iflag=6b02:lflag=200005cb:...:ospeed=9600" (BSD), Linux a colon-separated hex list: any one-line run of printable characters
    // without spaces is accepted; it is only ever handed back to `stty` as ONE argument.
    return r.status === 0 && /^[\x21-\x7e]{1,2048}$/.test(s) ? s : null
  } finally { closeSync(fd) }
}
export function restoreTermios(saved: string | null, ttyPath = '/dev/tty'): void {
  if (saved === null) return
  let fd: number
  try { fd = openSync(ttyPath, constants.O_RDWR | constants.O_NOCTTY) } catch { return }
  try { spawnSync('/bin/stty', [saved], { stdio: [fd, 'ignore', 'ignore'], timeout: 5_000 }) } finally { closeSync(fd) }
}

// Throws away what was typed and not yet read (tcflush(TCIFLUSH)), best effort: perl's POSIX::tcflush on /dev/tty. Used before the terminal is given back, so type-ahead
// (a passphrase half-typed when the command ended) is never delivered to the shell.
// Echo off from now on (canonical mode and ISIG stay: Ctrl-C still works). The broker does this when it starts a command that will ask for a passphrase, so nothing typed
// before its prompt appears is ever echoed.
export function echoOff(ttyPath = '/dev/tty'): void {
  let fd: number
  try { fd = openSync(ttyPath, constants.O_RDWR | constants.O_NOCTTY) } catch { return }
  try { spawnSync('/bin/stty', ['-echo'], { stdio: [fd, 'ignore', 'ignore'], timeout: 5_000 }) } finally { closeSync(fd) }
}

export function flushInput(ttyPath = '/dev/tty'): void {
  let fd: number
  try { fd = openSync(ttyPath, constants.O_RDWR | constants.O_NOCTTY) } catch { return }
  try { spawnSync('/usr/bin/perl', ['-MPOSIX', '-e', 'POSIX::tcflush(0, POSIX::TCIFLUSH)'], { stdio: [fd, 'ignore', 'ignore'], timeout: 5_000 }) } finally { closeSync(fd) }
}

// R5-1: does this process still own the terminal? True only when /dev/tty opens, its foreground process group is THIS process's group (tcgetpgrp == getpgrp, read by a
// perl child of ours, which shares the group) and the parent is still the one that started us (a killed bin/vt leaves us orphaned: ppid 1). Fails closed on any error.
export function ownsTerminal(startPpid: number, ppid: number = process.ppid, ttyPath = '/dev/tty'): boolean {
  if (ppid !== startPpid || ppid <= 1) return false
  const r = spawnSync('/usr/bin/perl', ['-MPOSIX', '-e', 'open(T,"+<",$ARGV[0]) or exit 1; exit(POSIX::tcgetpgrp(fileno(T)) == getpgrp() ? 0 : 1)', ttyPath], { stdio: ['ignore', 'ignore', 'ignore'], timeout: 5_000 })
  return r.status === 0
}

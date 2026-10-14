// Test helper (Task 12b): run a command on a fresh pseudo-terminal, `script -q /dev/null <argv>`, the way a person at a
// terminal would: each step waits for its prompt in the output, then types its input. The command's controlling
// terminal is the pty, so /dev/tty works there whatever the test process has (the suite and the mutation runner run
// without one). Only synthetic test passphrases are ever typed.
//   · script(1) refuses a socket as stdin (tcgetattr: EOPNOTSUPP) and node's stdio pipes are sockets on macOS, so `cat`
//     sits in between and hands script a real pipe;
//   · the shell would wait for cat, which only ends when its stdin does, so the group prints a marker line with
//     script's exit status, and on seeing it we close stdin (cat ends, then the shell);
//   · input is typed only after its prompt appeared: a program that turns echo off before printing its prompt is never
//     echoed, and one that does not is (the "not echoed" assertions rely on this order).
// detached: its own process group, so a timeout kills sh, cat and script together (the command itself, in script's new
// session, gets SIGHUP when the pty closes).
import { spawn } from 'node:child_process'

// then: optional, runs right after `send` was typed (a test seam: signal the command while it waits at its prompt).
export interface PtyStep { readonly waitFor: string; readonly send: string; readonly then?: () => void | Promise<void> }
export interface PtyResult { readonly out: string; readonly code: number | null }

const SH = 'cat | { script -q /dev/null "$@"; echo "@@pty-exit $?"; }'
const EXIT = /@@pty-exit (\d+)\r?\n/

export function runInPty(argv: readonly string[], o: { env: Record<string, string>; steps?: readonly PtyStep[]; timeoutMs?: number }): Promise<PtyResult> {
  const steps = o.steps ?? []
  return new Promise((resolve, reject) => {
    const c = spawn('/bin/sh', ['-c', SH, 'sh', ...argv], { env: o.env, stdio: ['pipe', 'pipe', 'pipe'], detached: true })
    let out = ''
    let pos = 0
    let next = 0
    let code: number | null = null
    let timedOut = false
    let thenError: unknown
    const timer = setTimeout(() => {
      timedOut = true
      try { process.kill(-c.pid!, 'SIGKILL') } catch { /* already gone */ }
    }, o.timeoutMs ?? 60_000)
    const pump = (): void => {
      while (next < steps.length) {
        const i = out.indexOf(steps[next].waitFor, pos)
        if (i < 0) break
        pos = i + steps[next].waitFor.length
        c.stdin.write(steps[next].send)
        const then = steps[next].then
        next++
        if (then !== undefined) Promise.resolve().then(then).catch((e: unknown) => { thenError = e; try { process.kill(-c.pid!, 'SIGKILL') } catch { /* already gone */ } })
      }
      const m = code === null ? EXIT.exec(out) : null
      if (m !== null) { code = Number(m[1]); c.stdin.end() }
    }
    c.stdin.on('error', () => { /* the command ended before reading everything: the assertions decide */ })
    c.stdout.on('data', (d: Buffer) => { out += d.toString('latin1'); pump() })
    c.stderr.on('data', (d: Buffer) => { out += d.toString('latin1') })
    c.on('error', (e) => { clearTimeout(timer); reject(e) })
    c.on('close', () => {
      clearTimeout(timer)
      if (thenError !== undefined) reject(thenError)
      else if (timedOut) reject(new Error(`pty run timed out after step ${next}/${steps.length}`))
      else resolve({ out: out.replace(EXIT, ''), code })
    })
  })
}

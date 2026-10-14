// cli/src/job/tty.ts — the terminal of the CLI executor (`vt job run`, `vt job clawback`; plan Task C6, spec §8).
// Everything the operator types reaches vt through /dev/tty ONLY — never stdin, argv or the environment:
//   · available(): stdin is a terminal AND /dev/tty opens as one (the caller refuses vt.tty-required otherwise: a
//     pipe, a file, a cron job or a CI runner never decrypts a key);
//   · passphrase(): vt-broadcast readPassphrase({ confirm: false }) — raw mode BEFORE the prompt, so nothing typed is
//     echoed; Ctrl-C, Ctrl-D or any control character aborts (passphrase.aborted); the bytes it read are wiped;
//   · word(): vt-broadcast readTypedWord (cooked, echoed: a typed confirmation is not a secret);
//   · keys(): while executors run, /dev/tty in raw mode (no echo, no line editing, no keyboard signals): `s` / `S` is
//     Skip, Ctrl-C (and Ctrl-\) is an interrupt. Raw mode keeps the terminal's output processing (ONLCR), so progress
//     lines print as usual. The mode is restored when the reader stops, and on process exit whatever happens.
// Nothing here prints a secret; the passphrase string is returned to the caller and never stored here.
import { writeSync } from 'node:fs'
import { Socket } from 'node:net'
import { Refusal } from '@vault-timelock/core/contracts'
import { readPassphrase } from 'vt-broadcast/src/lifecycle/passphrase.ts'
import { readTypedWord } from 'vt-broadcast/src/lifecycle/typed.ts'
import { rawKeys, terminalAvailable } from '../ops/ttyio.ts'
import type { Key } from '../ops/ttyio.ts'
import type { Chain } from '@vault-timelock/core/contracts'

export type { Key } from '../ops/ttyio.ts'
// The typed confirmations vt asks. Under the broker the child names only the KIND; the broker owns the prompt text and decides whether this command may ask it.
export type WordKind = 'publish' | 'again' | 'ticks' | 'broadcast' | 'amount' | 'resume' | 'resolve' | 'clawback'

export interface TtyIo {
  onGone?(fn: () => void, fd?: number): void   // broker channel only: fn runs once when the broker's answer pipe closes
  available(): boolean
  passphrase(chain?: Chain): Promise<string>
  // vt decrypt (broker channel only): the ONE passphrase of an age scrypt input; the broker names the input and allows it only when ITS
  // own reading of the input is scrypt
  agePassphrase?(): Promise<string>
  word(prompt: string, kind?: WordKind): Promise<string | undefined>
  // Starts the raw-mode key reader; returns the function that stops it (and restores the terminal).
  keys(on: (k: Key) => void): () => void
}

export { keyOf, rawKeys, terminalAvailable } from '../ops/ttyio.ts'

// TTY-less round: inside the sandbox there is NO terminal. A sandboxed vt (VT_BROKER=1: bin/vt starts it through src/ops/broker.ts) asks the
// unsandboxed broker over fds 3 (requests) and 4 (answers): see broker.ts for the protocol. VT_TTY says whether the broker has a terminal.
// The one place the child refuses on the broker's behalf (guard vt.broker): no prompt channel, a broker that went away, an answer the broker could not get.
export function brokerRefusal(message: string, guard = 'vt.broker'): never {
  if (guard !== 'vt.broker') throw new Refusal(guard, message)   // a guard id the BROKER reported (passphrase.aborted, ...)
  throw new Refusal('vt.broker', message) // @guard:vt.broker
}

// (a) A sandboxed child whose broker dies (kill -9 of vt, the terminal closed) must not run on unwatched: it DETACHES (SIGHUP to itself, which every executor command turns
// into "stop after the in-flight transaction, sign nothing new", and which kills a client command) when the broker's channel (fd 4, when there is one) closes, when
// its parent process changes, or when its stdout pipe breaks.
export function watchBroker(env: Readonly<Record<string, string | undefined>> = process.env, o: { ppid?: () => number; intervalMs?: number; hangup?: () => void; fd?: number } = {}): () => void {
  if (env.VT_BROKER !== '1') return () => {}
  const hangup = o.hangup ?? ((): void => { try { process.kill(process.pid, 'SIGHUP') } catch { /* gone */ } })
  const ppid = o.ppid ?? ((): number => process.ppid)
  const first = ppid()
  let fired = false
  const fire = (): void => { if (!fired) { fired = true; hangup() } }
  const timer = setInterval(() => { if (ppid() !== first) fire() }, o.intervalMs ?? 500)
  timer.unref()
  if (env.VT_TTY === '1') sharedBrokerTty().onGone?.(fire, o.fd)
  process.stdout.on('error', (e: NodeJS.ErrnoException) => { if (e.code === 'EPIPE') fire() })
  process.stderr.on('error', (e: NodeJS.ErrnoException) => { if (e.code === 'EPIPE') fire() })
  return () => { clearInterval(timer) }
}

export function brokerTty(env: Readonly<Record<string, string | undefined>> = process.env, fds: { req: number; ans: number } = { req: 3, ans: 4 }): TtyIo {
  let next = 0
  const pending = new Map<number, (m: { answer?: unknown; refusal?: { guard?: unknown; message?: unknown } }) => void>()
  let keyHandler: ((k: Key) => void) | null = null
  const gone: Array<() => void> = []
  let started = false
  let dead = false
  let sockRef: Socket | null = null
  const settle = (): void => { if (pending.size === 0 && keyHandler === null) sockRef?.unref(); else sockRef?.ref() }   // the socket keeps the process alive only while something waits on it
  const start = (): void => {
    if (started) return
    started = true
    let sock: Socket
    try { sock = new Socket({ fd: fds.ans, readable: true, writable: false }) } catch { dead = true; return }   // fd 4 is /dev/null or not there: no prompt channel
    let buf = ''
    sock.setEncoding('utf8')
    sock.on('data', (chunk: string) => {
      buf += chunk
      if (buf.length > 1_048_576) { buf = ''; return }
      let i: number
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1)
        let m: { id?: unknown; key?: unknown; answer?: unknown; refusal?: { guard?: unknown; message?: unknown } }
        try { m = JSON.parse(line) } catch { continue }
        if (typeof m.id === 'number' && pending.has(m.id)) { const f = pending.get(m.id)!; f(m) }
        else if (m.key === 'skip' || m.key === 'interrupt') { try { keyHandler?.(m.key) } catch { /* the handler reports its own errors */ } }
      }
    })
    sock.on('error', () => { /* closed */ })
    // The broker went away (killed, terminal closed): the same as a hangup, which every executor command turns into "stop after the in-flight transaction".
    sock.on('close', () => { for (const f of pending.values()) f({ refusal: { guard: 'vt.broker', message: 'the terminal broker went away' } }); pending.clear(); for (const g of gone) g(); if (gone.length === 0) { try { process.kill(process.pid, 'SIGHUP') } catch { /* gone */ } } })
    sockRef = sock
    sock.unref()
  }
  const send = (o: unknown): void => { try { writeSync(fds.req, `${JSON.stringify(o)}\n`) } catch { /* no channel: ask() refuses before this point when fd 4 is unusable */ } }
  const ask = (req: Record<string, unknown>): Promise<{ answer?: unknown; refusal?: { guard?: unknown; message?: unknown } }> => {
    start()
    if (dead) return Promise.resolve({ refusal: { guard: 'vt.broker', message: 'this command has no prompt channel' } })
    const id = ++next
    return new Promise((resolve) => { pending.set(id, (m) => { pending.delete(id); settle(); resolve(m) }); settle(); send({ id, ...req }) })
  }
  const unwrap = (m: { refusal?: { guard?: unknown; message?: unknown } }): void => {
    if (m.refusal !== undefined) brokerRefusal(typeof m.refusal.message === 'string' ? m.refusal.message : 'the terminal could not be read', typeof m.refusal.guard === 'string' ? m.refusal.guard : 'vt.broker')
  }
  return {
    onGone: (fn) => { gone.push(fn); start() },
    available: () => env.VT_TTY === '1',
    passphrase: async (chain) => { const m = await ask({ kind: 'passphrase', chain }); unwrap(m); if (typeof m.answer !== 'string') throw new Refusal('passphrase.aborted', 'passphrase entry aborted'); return m.answer },
    agePassphrase: async () => { const m = await ask({ kind: 'age-passphrase' }); unwrap(m); if (typeof m.answer !== 'string') throw new Refusal('passphrase.aborted', 'passphrase entry aborted'); return m.answer },
    word: async (prompt, kind) => { if (kind === undefined) brokerRefusal('a typed word without its kind cannot be asked through the broker'); const m = await ask({ kind: 'word', word: kind, detail: prompt }); unwrap(m); return typeof m.answer === 'string' ? m.answer : undefined },
    keys: (on) => {
      start()
      keyHandler = on
      settle()
      try { send({ kind: 'keys', on: true }) } catch { /* no broker */ }
      return () => { keyHandler = null; settle(); try { send({ kind: 'keys', on: false }) } catch { /* gone */ } }
    },
  }
}

let sharedBroker: TtyIo | null = null
// ONE broker client per process (one reader on fd 4)
export const sharedBrokerTty = (): TtyIo => (sharedBroker ??= brokerTty())

export function processTty(): TtyIo {
  if (process.env.VT_BROKER === '1') return sharedBrokerTty()
  return {
    available: () => terminalAvailable(),
    passphrase: () => readPassphrase({ confirm: false }),
    word: (prompt) => readTypedWord(prompt),
    keys: (on) => rawKeys(on),
  }
}

// What the executor commands listen to besides the keyboard: an interrupt from outside the terminal (kill -INT), a
// terminate, or the terminal hanging up. Each becomes the same "stop after the in-flight transaction" request — vt never
// abandons a transaction that might land; only an uncatchable kill can (the next holder then reconciles).
export interface Signals { on(sig: NodeJS.Signals, fn: () => void): void; off(sig: NodeJS.Signals, fn: () => void): void }
export const STOP_SIGNALS: readonly NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGHUP']
export const processSignals: Signals = {
  on: (sig, fn) => { process.on(sig, fn) },
  off: (sig, fn) => { process.off(sig, fn) },
}

// cli/src/ops/broker.ts — the unsandboxed side of a sandboxed vt command (TTY-less round; sandbox review I-1, and its fix round).
//   node broker.ts <sandbox-exec> <profile> <launcher> <args...>
// bin/vt runs this OUTSIDE the sandbox (env -i, like profile.ts) and it starts the sandboxed command:
//     <sandbox-exec> -p <profile> <launcher> <args...>
// in a NEW SESSION, so the sandboxed process
//   · has no terminal at all: no controlling tty (setsid), no tty device in its profile (deny file-read*/write*/ioctl on /dev/tty and the pty devices), its fds
//     0-2 are pipes: TIOCSTI, termios and escape-sequence writes to the terminal are impossible for it;
//   · may PROMPT only as its COMMAND allows (fix round I-1). The broker computes the allowed prompts from ITS OWN parse of the argv it was given (policyFor), never
//     from the child, and writes every prompt text itself:
//       job run | job clawback   one echo-off passphrase per handed --backup-<chain> file, at most once each; the child names only the chain (a closed set that must
//                                be one of the handed backups) and the broker prints "[vt broker] passphrase of the key backup <basename> (<chain>)";
//                                the keys reader (`s` skips the countdown, Ctrl-C detaches); run: `again` (a backup that records no network); clawback: amount, clawback;
//       job create | arm | resume | resolve   typed words of a per-command allowlist with a count cap, each with a FIXED broker text; the child may add one sanitised,
//                                length-capped detail line, printed apart and marked as coming from the command;
//       every other command      no prompt channel at all (fds 3 and 4 are /dev/null) and VT_TTY=0.
//     Anything outside that set, a second request while one is open, an oversized or malformed line: the broker refuses, kills the child's process group, restores
//     the terminal and exits 2 with a clear message. Nothing is served after the child has exited (its fds 3 / 4 are destroyed and its process group killed).
//     Typed answers are validated HERE against the expected word / amount pattern (a mismatch is asked again, three tries, then an empty answer): only a matching
//     answer is forwarded, never free text. The broker's own lines start with the tag "[vt broker]", which the output filter strips from anything the child prints.
//   · gets answers on fd 4 ({id, answer} / {id, refusal} / {key}); nothing the child sends is a command (closed kinds, closed word ids, closed chains);
//   · writes to pipes whose content is filtered (src/ops/sanitize.ts: no ESC / OSC / CSI / DCS / C1 controls, no bidi or format characters, ASCII only in a non-UTF-8
//     locale) before it reaches the real stdout / stderr (a terminal, a file or a pipe: a redirect keeps working). The child's output is HELD while a prompt is open,
//     so it cannot print a fake context after the prompt, and the child's pipes are paused when the real stdout is slow (backpressure).
// The terminal is restored on every way out: normal end, the child's death mid-prompt, a refusal, and SIGINT/SIGTERM/SIGHUP/SIGQUIT sent to the broker (the settings
// are saved with `stty -g` at start). The sandbox profile denies signals to anything but the process itself, so the child cannot signal the broker. SIGINT / SIGTERM /
// SIGHUP / SIGQUIT sent to the broker are forwarded to the child's PROCESS GROUP every time they arrive; once the child is gone they end the broker itself (128 + the signal);
// the exit status is the child's, or 128 + the signal number. A broker whose stdout reader went away (`vt status | head -1`) tells the child to stop (SIGHUP) and exits quietly.
// Imports are node builtins and the two small terminal readers only: this is the process that types the passphrase.
import { spawn } from 'node:child_process'
import { closeSync, openSync } from 'node:fs'
import { constants as osConstants } from 'node:os'
import { basename } from 'node:path'
import { readPassphrase } from 'vt-broadcast/src/lifecycle/passphrase.ts'
import { readTypedWord } from 'vt-broadcast/src/lifecycle/typed.ts'
import { Sanitizer, localeIsUtf8, neutralizeTag, sanitize } from './sanitize.ts'
import { echoOff, flushInput, ownsTerminal, rawKeys, restoreTermios, saveTermios, terminalAvailable, writeTty } from './ttyio.ts'

export const MAX_DETAIL = 160
export const MAX_LINE = 4096
const CHAINS = ['eth', 'sol', 'btc'] as const
type Chain = (typeof CHAINS)[number]
export type WordId = 'publish' | 'again' | 'ticks' | 'broadcast' | 'amount' | 'resume' | 'resolve' | 'clawback'

// What a command may ask, from its argv (the rewritten arguments bin/vt hands the broker: handed files are absolute real paths).
export interface Policy {
  prompts: boolean                              // any prompt channel at all
  passphrases: Map<Chain, string>               // chain -> the handed backup file; each may be asked once
  words: Map<WordId, number>                    // allowed typed words and how many times
  keys: boolean
}
const FILE_FLAG = /^--backup-(eth|sol|btc)$/
// The first occurrence of a valued flag (the real parser refuses a repeat; if it does, nothing is decrypted).
const flagValue = (args: readonly string[], name: string): string | undefined => { const i = args.indexOf(name); return i >= 0 && i > 1 ? args[i + 1] : undefined }
// Mirrors what the real CLI needs (N-4): run with --chain c asks only c; clawback only --backup-<--chain>; mainnet-only words only on mainnet; publish only without
// --yes-publish-file; claw-back caps are 1.
export function policyFor(args: readonly string[], network: string = 'local'): Policy {
  const none: Policy = { prompts: false, passphrases: new Map(), words: new Map(), keys: false }
  const [cmd, sub] = args
  if (cmd !== 'job') return none
  const main = network === 'mainnet'
  const handed = new Map<Chain, string>()
  for (let i = 2; i < args.length; i++) {
    const m = FILE_FLAG.exec(args[i])
    if (m !== null && args[i + 1] !== undefined) { if (!handed.has(m[1] as Chain)) handed.set(m[1] as Chain, args[i + 1]); i++ }
  }
  const pick = (only: string | undefined): Map<Chain, string> => {
    const out = new Map<Chain, string>()
    for (const [c, f] of handed) if (only === undefined || only === c) out.set(c, f)
    return out
  }
  const mk = (o: { passphrases?: Map<Chain, string>; words?: Array<[WordId, number, boolean]>; keys?: boolean }): Policy => {
    const words = new Map<WordId, number>()
    for (const [w, n, ok] of o.words ?? []) if (ok && n > 0) words.set(w, n)
    const p = { prompts: false, passphrases: o.passphrases ?? new Map(), words, keys: o.keys === true }
    p.prompts = p.passphrases.size > 0 || words.size > 0 || p.keys
    return p
  }
  switch (sub) {
    case 'run': return mk({ passphrases: pick(flagValue(args, '--chain')), words: [['again', 3, true]], keys: true })
    case 'clawback': { const c = flagValue(args, '--chain'); return mk({ passphrases: pick(c === undefined ? '-' : c), words: [['again', 1, true], ['amount', 1, true], ['clawback', 1, main]], keys: true }) }
    case 'create': return mk({ words: [['publish', 1, !args.includes('--yes-publish-file')]] })
    case 'arm': { const n = Math.max(1, Math.min(3, (flagValue(args, '--chains') ?? 'eth,sol,btc').split(',').length)); return mk({ words: [['again', n, true], ['ticks', 1, main], ['broadcast', 1, main], ['amount', n, true]] }) }
    case 'resume': return mk({ words: [['resume', 1, main]] })
    case 'resolve': return mk({ words: [['resolve', 1, main]] })
    default: return none
  }
}

// The broker's own text for each typed word. The child supplies at most a sanitised detail line (amounts, ids) shown below, marked as from the command.
export const WORD_TEXT: Readonly<Record<WordId, string>> = {
  publish: 'type the word  publish  to upload the message file for publication',
  again: 'type the word  again  to continue',
  ticks: 'type the word  ticks  to acknowledge the five mainnet pre-flight ticks',
  broadcast: 'type the word  broadcast  to arm this job',
  amount: 'type the planned amount exactly',
  resume: 'type the word  resume  to continue the stopped chains',
  resolve: 'type the word  resolve  to record your outcome',
  clawback: 'type the words  claw back  to send the remainder',
}
export const BROKER_TAG = '[vt broker] '
// R3-2: on a terminal every broker line is drawn in REVERSE VIDEO (ESC[7m ... ESC[0m). The child's output has every ESC stripped, so it can never carry the attribute,
// whatever text it prints: the highlight, not the wording, is what identifies the broker.
export const SGR_ON = '\u001b[7m', SGR_OFF = '\u001b[0m'
export const hl = (tty: { style?: boolean }, text: string): string => (tty.style === true ? text.replace(/^(\n?)([^\n]*)(\n?)$/, `$1${SGR_ON}$2${SGR_OFF}$3`) : text)

export interface BrokerTty {
  available(): boolean
  passphrase(): Promise<string>
  word(prompt: string): Promise<string | undefined>
  keys(on: (k: 'skip' | 'interrupt') => void): () => void
  note(text: string): void
  style?: boolean         // draw the broker's own lines highlighted (a terminal)
  quiet?(): void          // echo off (before the command's first passphrase prompt)
  flush?(): void          // discard type-ahead
  owns?(): boolean        // this broker is still the terminal's foreground job and bin/vt is still its parent (R5-1); absent: not checked
  loud?(): void           // terminal back to the saved settings (echo on)
}
const STARTED_UNDER = process.ppid
export const realTty: BrokerTty = {
  owns: () => ownsTerminal(STARTED_UNDER),
  available: () => terminalAvailable(),
  passphrase: () => readPassphrase({ confirm: false }),
  word: (p) => readTypedWord(p),
  keys: (on) => rawKeys(on),
  note: (t) => { writeTty(t) },
  style: true,
  quiet: () => { echoOff() },
  flush: () => { flushInput() },
}

export class Violation extends Error {}
// The terminal is no longer ours (the shell took it back, or bin/vt is gone): nothing is printed, nothing is read.
export class LostTerminal extends Error {}

// What the broker accepts as the answer to each typed word (N-3). `claw back` is the one word with a space.
const EXPECT: Readonly<Record<WordId, RegExp>> = {
  publish: /^publish$/, again: /^again$/, ticks: /^ticks$/, broadcast: /^broadcast$/, resume: /^resume$/, resolve: /^resolve$/, clawback: /^claw back$/,
  amount: /^[0-9]{1,12}(?:\.[0-9]{1,18})?$/,
}
export const MAX_TRIES = 3
export const PROMPT_GRACE_MS = 120_000

// Names taken from argv (a downloaded file may be called anything): control characters, newlines and invisible characters are shown as \u{..} escapes, and in a non-UTF-8
// locale every non-ASCII character too, so a name can never move the cursor, start a line or forge the tag.
export function visible(name: string, ascii: boolean): string {
  let out = ''
  for (const ch of name) {
    const c = ch.codePointAt(0) as number
    const plain = c >= 0x20 && c < 0x7f
    const ok = plain || (!ascii && c >= 0xa0 && sanitize(ch) === ch)
    out += ok ? ch : `\\u{${c.toString(16)}}`
  }
  return neutralizeTag(out).slice(0, 160)
}

// One request line from the child → the answer line (null: nothing to send). Throws Violation for anything the command may not ask.
export async function answerRequest(line: string, tty: BrokerTty, policy: Policy, state: { asked: Set<Chain>; left: Map<WordId, number> }, keyHandlers: { start(): void; stop(): void }, ascii = false): Promise<string | null> {
  let m: unknown
  try { m = JSON.parse(line) } catch { throw new Violation('a malformed request') }
  if (typeof m !== 'object' || m === null || Array.isArray(m)) throw new Violation('a malformed request')
  const r = m as { id?: unknown; kind?: unknown; chain?: unknown; word?: unknown; detail?: unknown; on?: unknown }
  if (r.kind === 'keys') {
    if (r.on === true) { if (!policy.keys) throw new Violation('the keyboard reader, which this command does not use'); keyHandlers.start() } else keyHandlers.stop()
    return null
  }
  if (typeof r.id !== 'number' || !Number.isSafeInteger(r.id)) throw new Violation('a request without an id')
  if (r.kind === 'passphrase') {
    const chain = r.chain
    if (typeof chain !== 'string' || !(CHAINS as readonly string[]).includes(chain)) throw new Violation('a passphrase for no known chain')
    const file = policy.passphrases.get(chain as Chain)
    if (file === undefined) throw new Violation(`a passphrase for ${chain}, whose key backup this command was not asked to use`)
    if (state.asked.has(chain as Chain)) throw new Violation(`the ${chain} passphrase a second time`)
    if (tty.owns && !tty.owns()) throw new LostTerminal()
    state.asked.add(chain as Chain)
    tty.note(hl(tty, `\n${BROKER_TAG}passphrase of the key backup ${visible(basename(file), ascii)} (${chain}); typed here, not echoed, never shown to anyone\n`))
    // R-echo: type-ahead typed before this prompt is thrown away; the operator is told to type now
    tty.quiet?.(); tty.flush?.()
    if (tty.owns && !tty.owns()) throw new LostTerminal()
    tty.note(hl(tty, `${BROKER_TAG}type it now (nothing is shown)\n`))
    if (tty.owns && !tty.owns()) throw new LostTerminal()
    try { return JSON.stringify({ id: r.id, answer: await tty.passphrase() }) } catch (e) { return refusalLine(r.id, e) }
    finally { if (state.asked.size >= policy.passphrases.size) tty.loud?.() }
  }
  if (r.kind === 'word') {
    const w = r.word
    if (typeof w !== 'string' || !WORD_TEXT_KEYS.has(w)) throw new Violation('a typed word of no known kind')
    const left = state.left.get(w as WordId) ?? 0
    if (!policy.words.has(w as WordId) || left <= 0) throw new Violation(`the typed word "${w}", which this command may not ask (again)`)
    state.left.set(w as WordId, left - 1)
    const detail = typeof r.detail === 'string' ? sanitize(r.detail.replace(/[\r\n\t\u2028\u2029\u0085]+/g, ' '), ascii).replace(/\s+/g, ' ').trim().slice(0, MAX_DETAIL) : ''
    if (tty.owns && !tty.owns()) throw new LostTerminal()
    const prompt = `${hl(tty, `\n${BROKER_TAG}${WORD_TEXT[w as WordId]}\n`)}${detail === '' ? '' : `  (from the command, not verified by vt broker: ${detail})\n`}> `
    if (tty.owns && !tty.owns()) throw new LostTerminal()
    tty.loud?.()   // echo is ON while a typed word is typed; it goes off again for the next passphrase
    try {
      for (let attempt = 1; attempt <= MAX_TRIES; attempt++) {
        const a = await tty.word(attempt === 1 ? prompt : `${hl(tty, `${BROKER_TAG}that is not the expected ${w === 'amount' ? 'amount (digits and one decimal point)' : 'word'}; again (${attempt}/${MAX_TRIES})\n`)}> `)
        if (a === undefined) return JSON.stringify({ id: r.id, answer: null })
        if (a.trim() === '') return JSON.stringify({ id: r.id, answer: '' })   // an empty line declines: no second chance is offered
        if (EXPECT[w as WordId].test(a.trim())) return JSON.stringify({ id: r.id, answer: a.trim() })
      }
      return JSON.stringify({ id: r.id, answer: '' })   // never free text: the command sees a word that matches nothing and refuses
    } catch (e) { return refusalLine(r.id, e) }
    finally { if (state.asked.size < policy.passphrases.size) tty.quiet?.() }   // R4-1: another passphrase may follow: typed-ahead input must not be shown
  }
  throw new Violation('a request of an unknown kind')
}
const WORD_TEXT_KEYS = new Set<string>(Object.keys(WORD_TEXT))
function refusalLine(id: number, e: unknown): string {
  const g = (e as { guardId?: unknown }).guardId
  if (typeof g === 'string' && /^[a-z0-9.-]{1,60}$/.test(g)) return JSON.stringify({ id, refusal: { guard: g, message: sanitize(e instanceof Error ? e.message : '').slice(0, 300) } })
  return JSON.stringify({ id, refusal: { guard: 'vt.broker', message: 'the terminal could not be read' } })
}

const SIGS: NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT']
export const exitFor = (signal: NodeJS.Signals | null, code: number | null): number =>
  signal !== null ? 128 + ((osConstants.signals as Record<string, number>)[signal] ?? 1) : (code ?? 1)

export function run(argv: readonly string[], env: NodeJS.ProcessEnv, ttyIn: BrokerTty = realTty, sink: { out: (s: string) => boolean; err: (s: string) => boolean } = { out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s) }): Promise<number> {
  const [sandboxExec, profile, launcher, ...args] = argv
  if (sandboxExec === undefined || profile === undefined || launcher === undefined) throw new Error('the broker needs sandbox-exec, a profile and the launcher')
  const policy = policyFor(args, env.VT_NETWORK === 'mainnet' ? 'mainnet' : 'local')
  const hasTerminal = ttyIn.available()
  const prompts = policy.prompts && hasTerminal
  const childEnv: Record<string, string> = {}
  for (const [k, v] of Object.entries(env)) if (v !== undefined && k !== 'LC_ALL' && k !== 'LC_CTYPE' && k !== 'VT_TERMIOS') childEnv[k] = v   // the locale is the broker's business
  childEnv.VT_CONFINED = '1'
  childEnv.VT_BROKER = '1'
  childEnv.VT_TTY = prompts ? '1' : '0'
  // bin/vt already switched echo off for a passphrase command (so the start-up window is closed) and hands over the settings it saved BEFORE that
  const handed = typeof env.VT_TERMIOS === 'string' && /^[\x21-\x7e]{1,2048}$/.test(env.VT_TERMIOS) ? env.VT_TERMIOS : null
  const saved = handed ?? (hasTerminal ? saveTermios() : null)
  const quieted = (prompts && policy.passphrases.size > 0) || handed !== null   // bin/vt already switched echo off: this broker owes the terminal its flush and its restore
  const tty: BrokerTty = { ...ttyIn, loud: ttyIn.loud ?? ((): void => { restoreTermios(saved) }) }
  // From the moment the command starts until its last allowed passphrase is read, echo is OFF: the command prints its own line before it asks, and whatever is typed in
  // between must never be shown.
  if (quieted) tty.quiet?.()
  if (prompts && tty.style === true) tty.note(`${SGR_ON}[vt broker]${SGR_OFF} vt's own prompts appear highlighted like this; text that merely looks like them is not from vt.\n`)
  const ascii = !localeIsUtf8(env)
  return new Promise<number>((resolve) => {
    // fds 3 and 4 exist only for a command that may prompt; every other command gets /dev/null there (no prompt channel)
    const nullFd = prompts ? -1 : openSync('/dev/null', 'r+')
    const child = spawn(sandboxExec, ['-p', profile, launcher, ...args], { env: childEnv, stdio: ['ignore', 'pipe', 'pipe', prompts ? 'pipe' : nullFd, prompts ? 'pipe' : nullFd], detached: true })
    if (nullFd >= 0) closeSync(nullFd)
    const out = new Sanitizer(ascii), err = new Sanitizer(ascii)
    let finished = false
    let serving = true            // false once the child has exited: nothing more is answered
    let childGone = false
    let promptOpen = false
    let keysWanted = false
    let stopKeys: (() => void) | null = null
    let outBroken = false
    const restore = (): void => { restoreTermios(saved) }
    const onExit = (): void => { if (!promptOpen) { if (quieted) flushInput(); restore() } }
    process.on('exit', onExit)
    const write = (which: 0 | 1, text: string): boolean => {
      if (outBroken || text === '') return true
      return which === 0 ? sink.out(text) : sink.err(text)
    }
    const groupKill = (sig: NodeJS.Signals): void => { try { process.kill(-(child.pid as number), sig) } catch { try { child.kill(sig) } catch { /* gone */ } } }
    let promptPending: Promise<unknown> | null = null   // the open prompt's reader (it cannot be cancelled: it ends at Enter, Ctrl-C or Ctrl-D)
    const done = (code: number): void => {
      if (finished) return
      finished = true
      serving = false
      if (stopKeys !== null) { stopKeys(); stopKeys = null }
      for (const [sg, h] of handler) process.off(sg, h)
      process.off('SIGTSTP', onTstp)
      write(0, out.end()); write(1, err.end())
      if (promptOpen && promptPending !== null) {
        // R2-1: the command ended while a prompt was open. The reader keeps echo OFF until the operator presses Enter; whatever is typed is discarded, never echoed, never
        // handed to the shell. Say so, wait (bounded), flush the input queue, and only then restore the terminal.
        tty.note(hl(tty, `\n${BROKER_TAG}the command ended; what you type now is discarded and sent nowhere. Press Enter to continue.\n`))
        const bound = new Promise<void>((r) => setTimeout(r, PROMPT_GRACE_MS))
        void Promise.race([promptPending.catch(() => {}), bound]).then(() => {
          flushInput()
          restore()
          process.off('exit', onExit)
          resolve(code)
        })
        return
      }
      if (quieted) flushInput()   // R3-1: whatever was typed while echo was off is thrown away, never handed to the shell
      restore()
      process.off('exit', onExit)
      resolve(code)
    }
    const violate = (why: string): void => {
      if (finished) return
      groupKill('SIGKILL')
      write(1, `\nvt: refused: the sandboxed command asked for something its command may not ask (${sanitize(why, ascii).slice(0, 120)}); it was stopped and the terminal restored\n`)
      done(2)
    }
    // R5-1: the terminal is not ours any more: print nothing, touch the terminal's settings not at all (they are the shell's now), stop the command, leave non-zero
    const lost = (): void => {
      if (finished) return
      finished = true; serving = false
      groupKill('SIGKILL')
      if (stopKeys !== null) { stopKeys(); stopKeys = null }
      process.off('exit', onExit)
      resolve(3)
    }
    // ---- output relay: held while a prompt is open; paused while the real stdout / stderr is slow
    const held: Array<[number, Buffer]> = []
    let heldBytes = 0
    const relay = (which: 0 | 1, d: Buffer): void => {
      if (finished) return
      if (promptOpen) { held.push([which, d]); heldBytes += d.length; if (heldBytes > 1_048_576) { child.stdout?.pause(); child.stderr?.pause() }; return }
      const ok = write(which, (which === 0 ? out : err).push(d))
      if (!ok) {
        const src = which === 0 ? child.stdout : child.stderr
        src?.pause()
        ;(which === 0 ? process.stdout : process.stderr).once('drain', () => { if (!promptOpen) src?.resume() })
      }
    }
    const flushHeld = (): void => {
      promptOpen = false
      for (const [w, d] of held.splice(0)) write(w as 0 | 1, (w === 0 ? out : err).push(d))
      heldBytes = 0
      child.stdout?.resume(); child.stderr?.resume()
    }
    child.stdout?.on('data', (d: Buffer) => { relay(0, d) })
    child.stderr?.on('data', (d: Buffer) => { relay(1, d) })
    // a reader that went away (`vt status | head -1`): quiet, and the command is told to stop
    for (const [stream, w] of [[process.stdout, 0], [process.stderr, 1]] as const) {
      stream.on('error', (e: NodeJS.ErrnoException) => { if (e.code === 'EPIPE' || e.code === 'ERR_STREAM_DESTROYED') { if (!outBroken) { outBroken = true; if (!childGone) groupKill('SIGHUP') } } })
      void w
    }
    // ---- the prompt channel
    const state = { asked: new Set<Chain>(), left: new Map(policy.words) }
    const ctl = prompts ? (child.stdio[3] as import('node:stream').Readable) : null
    const answers = prompts ? (child.stdio[4] as import('node:stream').Writable) : null
    const send = (o: unknown): void => { if (!serving) return; try { answers?.write(`${JSON.stringify(o)}\n`) } catch { /* the child is gone */ } }
    const startKeys = (): void => { if (stopKeys === null && !promptOpen && serving) stopKeys = tty.keys((k) => { send({ key: k }) }) }
    const handlers = {
      start: (): void => { keysWanted = true; startKeys() },
      stop: (): void => { keysWanted = false; if (stopKeys !== null) { stopKeys(); stopKeys = null } },
    }
    let buf = ''
    if (ctl !== null) {
      ctl.setEncoding('utf8')
      ctl.on('data', (chunk: string) => {
        if (finished || !serving) return
        buf += chunk
        let i: number
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i)
          buf = buf.slice(i + 1)
          if (line.length > MAX_LINE) return violate('an oversized request')
          if (promptOpen) return violate('a second request while a prompt is open')
          let isPrompt = true
          try { const k = (JSON.parse(line) as { kind?: unknown }).kind; isPrompt = k !== 'keys' } catch { /* answerRequest reports it */ }
          if (isPrompt) { promptOpen = true; if (stopKeys !== null) { stopKeys(); stopKeys = null } }   // the keyboard reader and a prompt never share the terminal
          const pr = answerRequest(line, tty, policy, state, handlers, ascii)
          if (isPrompt) promptPending = pr
          pr.then((a) => {
            if (finished || !serving) return
            if (a !== null) answers?.write(`${a}\n`)
            if (isPrompt) { flushHeld(); if (keysWanted) startKeys() }
          }, (e: unknown) => { if (e instanceof LostTerminal) lost(); else if (e instanceof Violation) violate(e.message); else violate('an internal error') })
        }
        if (buf.length > MAX_LINE) violate('an oversized request')
      })
      ctl.on('error', () => { /* closed */ })
      answers?.on('error', () => { /* closed */ })
    }
    // ---- signals: forwarded to the child's PROCESS GROUP every time; once the child is gone they end the broker itself
    const handler = new Map<NodeJS.Signals, () => void>()
    for (const sg of SIGS) {
      let last = 0
      const h = (): void => {
        if (sg === 'SIGINT') { const t = Date.now(); if (t - last < 100) return; last = t }   // R5-1: the keyboard's INT arrives here twice (directly, and forwarded by bin/vt)
        if (childGone) { groupKill('SIGKILL'); done(exitFor(sg, null)); return }
        groupKill(sg)
      }
      handler.set(sg, h); process.on(sg, h)
    }
    // Ctrl-Z / SIGTSTP: the broker must not stop while the command runs on unattended, so it ignores the request and says so
    const onTstp = (): void => { if (tty.owns && !tty.owns()) return; tty.note(hl(tty, `\n${BROKER_TAG}Ctrl-Z is ignored while a command runs (use Ctrl-C to detach).\n`)) }
    process.on('SIGTSTP', onTstp)
    let status = 1
    child.on('exit', (code, signal) => {
      // N-2: the command is over. Stop serving at once (a grandchild holding fds 3 / 4 gets nothing), kill whatever is left of its process group, and give the pipes a
      // moment to drain before finishing.
      childGone = true
      serving = false
      status = exitFor(signal, code)
      handlers.stop()
      try { ctl?.destroy(); answers?.destroy() } catch { /* closed */ }
      groupKill('SIGKILL')
      setTimeout(() => done(status), 400)
    })
    child.on('error', () => { done(1) })
    child.on('close', () => { done(status) })
  })
}

if (import.meta.main) {
  const code = await run(process.argv.slice(2), process.env)
  // a prompt the child left open must not keep this process alive, but buffered output must reach its destination first
  process.stdout.write('', () => { process.stderr.write('', () => { process.exit(code) }) })
}

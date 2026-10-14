// cli/test/broker-real.test.ts — the TTY-less sandbox for real (TTY-less round; sandbox review I-1): the unsandboxed broker (src/ops/broker.ts) starts a child
// under the real sandbox-exec with a profile that denies every terminal device, and
//   · TIOCSTI / termios / any open of the controlling tty or of the pty slave the test runs on is EPERM for the child;
//   · prompts work end to end through the pipes, driven in a REAL pty (`script`): a typed word is echoed by the terminal, the passphrase is not, and it never appears
//     in any output; the child's reply carries only a hash of it;
//   · escape sequences in the child's output (OSC 52, CSI, DCS, C1) never reach the terminal;
//   · `s` and Ctrl-C reach the child as control messages; a kill of the broker's tty (Ctrl-C in cooked mode) is forwarded as SIGINT;
//   · a redirect of the broker's stdout to a file still works.
// OWN SANDBOX (own-sandbox.list). Synthetic passphrases only; the profile here is `(allow default)` + the terminal denies (what is under test), the full client/executor
// profile is exercised by wrapper.test.ts and ticket-key-real.test.ts.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { runInPty } from 'vt-broadcast/test/offline/lifecycle/pty.ts'
import { sanitize } from '../src/ops/sanitize.ts'
import { denyTerminals } from '../src/ops/sandbox.ts'
import { CLI, NODE, PATH0, fakeableWrapper, removeDir, tempDir } from './lib.ts'

const BROKER = join(CLI, 'src', 'ops', 'broker.ts')
const TTYJS = join(CLI, 'src', 'job', 'tty.ts')
const PASS = 'broker-test-synthetic-passphrase-0001'
let T = ''
before(() => { T = tempDir('vt-broker-') })
after(() => removeDir(T))

const PROFILE = `(version 1)(allow default)${denyTerminals()}`

// The "launcher" the broker starts under sandbox-exec: a node script run by a /bin/sh shim so it is one executable path.
function child(name: string, body: string): string {
  const js = join(T, `${name}.mjs`)
  writeFileSync(js, `import { brokerTty } from ${JSON.stringify(TTYJS)}\nconst tty = brokerTty()\n${body}\n`)
  const sh = join(T, name)
  writeFileSync(sh, `#!/bin/sh\nexec ${JSON.stringify(NODE)} --disable-sigusr1 --no-addons ${JSON.stringify(js)}\n`)
  chmodSync(sh, 0o755)
  return sh
}
const brokerArgv = (launcher: string, args: string[] = [], profile = PROFILE): string[] => [NODE, '--disable-sigusr1', BROKER, '/usr/bin/sandbox-exec', profile, launcher, ...args]
const RUN_ARGS = (): string[] => ['job', 'run', 'x', '--backup-eth', join(T, 'vt-eth-key-1.age')]
const env = (): Record<string, string> => ({ PATH: PATH0, HOME: T, LANG: 'en_US.UTF-8', TERM: 'xterm' })
const esc = String.fromCharCode(27)
const ENTER = { waitFor: 'Press Enter to continue', send: '\r' }   // R2-1: a broker whose command ended during a prompt waits for Enter and discards the input

test('prompts end to end in a real pty: the BROKER writes the prompts (its tag, the backup basename from argv), a typed word is echoed, the passphrase is not and appears in no output; only its hash comes back', { timeout: 60_000 }, async () => {
  const l = child('prompts', `
const p = await tty.passphrase('eth')
const w = await tty.word('Type again: (child text)', 'again')
const { createHash } = await import('node:crypto')
console.log('GOT word=' + w + ' pass-sha=' + createHash('sha256').update(p).digest('hex') + ' len=' + p.length + ' available=' + tty.available())
process.exit(0)`)
  const r = await runInPty(brokerArgv(l, RUN_ARGS()), { env: env(), steps: [{ waitFor: 'Passphrase: ', send: `${PASS}\r` }, { waitFor: '> ', send: 'again\r' }] })
  assert.equal(r.code, 0, r.out)
  assert.match(r.out, /\[vt broker\] passphrase of the key backup vt-eth-key-1\.age \(eth\)/)
  assert.match(r.out, /\[vt broker\] type the word  again  to continue/)
  assert.match(r.out, /\(from the command, not verified by vt broker: Type again: \(child text\)\)/)
  assert.match(r.out, /GOT word=again pass-sha=[0-9a-f]{64} len=37 available=true/)
  assert.ok(r.out.includes(createHash('sha256').update(PASS).digest('hex')), 'the child received exactly the typed passphrase')
  assert.ok(!r.out.includes(PASS), 'the passphrase appears in no output (not echoed, not printed)')
})

// ---- I-1 (fix round): command-bound prompts. Each case runs a child that asks something its command may not; the broker must refuse, kill it and restore the tty.
async function refusedCase(name: string, body: string, args: string[], steps: Array<{ waitFor: string; send: string }> = []): Promise<{ out: string; code: number | null }> {
  const l = child(name, `${body}\nconsole.log('CHILD-SURVIVED')\nsetTimeout(() => process.exit(0), 3000)`)
  // after the broker, the shell prints the terminal's settings: a prompt that was open must not have left it raw / no-echo
  const r = await runInPty(['/bin/sh', '-c', `${brokerArgv(l, args).map((x) => `'${x}'`).join(' ')}; echo "BROKER-EXIT=$?"; stty -a | tr '\\n' ' '`], { env: env(), steps: [...steps, ENTER] })
  return r
}
const tty_ok = (out: string): void => { assert.ok(!/ -icanon| -echo | -isig/.test(out.replace(/\n/g, ' ')), `the terminal is back to cooked, echoing, signal-generating: ${out.slice(-300)}`) }

test('I-1: the reviewer\'s `vt status` phishing (3 passphrases + a word) never reaches the terminal: no prompt channel, the child gets a refusal', { timeout: 60_000 }, async () => {
  const r = await refusedCase('phish-status', `
console.log('btc: the passphrase of the key backup vt-btc-key-OTHER.age (typed at the terminal, not echoed)')
await tty.passphrase('eth'); await tty.passphrase('sol'); await tty.passphrase('btc')
await tty.word('Re-enter the backup passphrase to verify (shown): ', 'again')`, ['status'])
  // `status` has NO prompt channel (fds 3/4 are /dev/null): the request goes nowhere, nothing is ever shown to the operator, and the child gets a refusal
  assert.match(r.out, /this command has no prompt channel/)
  assert.ok(!/Passphrase: /.test(r.out) && !r.out.includes('[vt broker]'), 'no prompt of any kind reached the terminal')
  assert.ok(!r.out.includes('CHILD-SURVIVED'), 'the child could not continue')
  tty_ok(r.out)
})

test('I-1: no prompt channel at all for commands without prompts (fds 3 and 4 are /dev/null): status, preflight, source list, job list/status/watch/receipt', { timeout: 60_000 }, async () => {
  for (const args of [['status'], ['preflight'], ['source', 'list'], ['job', 'list'], ['job', 'status', 'x'], ['job', 'watch', 'x'], ['job', 'receipt', 'x'], ['job', 'stop', 'x']]) {
    const l = child('noprompt', `
import fs from 'node:fs'
const kinds = ['3', '4'].map((fd) => { try { return fs.fstatSync(Number(fd)).isCharacterDevice() ? 'devnull' : 'other' } catch { return 'closed' } })
console.log('FDS ' + kinds.join(',') + ' tty=' + process.env.VT_TTY)
process.exit(0)`)
    const r = await runInPty(brokerArgv(l, args), { env: env(), steps: [] })
    assert.match(r.out, /FDS devnull,devnull tty=0/, args.join(' '))
  }
})

test('I-1: `job run --backup-eth`: exactly ONE passphrase for eth; btc (not handed), a second eth, an unknown chain, a free-text word, a word of another command, and keys on `job create` are all refused', { timeout: 120_000 }, async () => {
  const cases: Array<[string, string, string[], RegExp]> = [
    ['btc', `await tty.passphrase('eth').catch(() => {}); await tty.passphrase('btc')`, RUN_ARGS(), /a passphrase for btc, whose key backup this command was not asked to use/],
    ['twice', `await tty.passphrase('eth'); await tty.passphrase('eth')`, RUN_ARGS(), /the eth passphrase a second time/],
    ['unknown', `await tty.passphrase('doge')`, RUN_ARGS(), /a passphrase for no known chain/],
    ['word-other', `await tty.word('Type broadcast: ', 'broadcast')`, RUN_ARGS(), /the typed word "broadcast", which this command may not ask/],
    ['word-free', `await tty.word('Re-enter the passphrase: ', 'passphrase')`, RUN_ARGS(), /a typed word of no known kind/],
    ['keys-create', `tty.keys(() => {}); await new Promise((r) => setTimeout(r, 1000))`, ['job', 'create', 'f.json'], /the keyboard reader, which this command does not use/],
    ['again-4x', `for (let i = 0; i < 4; i++) await tty.word('again', 'again')`, RUN_ARGS(), /may not ask \(again\)/],
  ]
  for (const [name, body, args, re] of cases) {
    const steps = name === 'btc' || name === 'twice' ? [{ waitFor: 'Passphrase: ', send: `${PASS}\r` }] : name === 'again-4x' ? Array.from({ length: 3 }, () => ({ waitFor: '> ', send: 'again\r' })) : []
    const r = await refusedCase(`case-${name}`, body, args, steps)
    assert.match(r.out, /BROKER-EXIT=2/, `${name}: ${r.out}`)
    assert.match(r.out, re, name)
    assert.ok(!r.out.includes('CHILD-SURVIVED'), `${name}: the child was stopped`)
    assert.ok(!r.out.includes(PASS), `${name}: no passphrase in the output`)
    tty_ok(r.out)
  }
})

test('M-2: ONE outstanding request: a second request while a prompt is open, a flood on fd 3 and an oversized line refuse and kill (the broker does not grow)', { timeout: 60_000 }, async () => {
  const two = await refusedCase('two', `
import fs from 'node:fs'
fs.writeSync(3, JSON.stringify({ id: 1, kind: 'word', word: 'again', detail: 'x' }) + '\\n' + JSON.stringify({ id: 2, kind: 'word', word: 'again', detail: 'y' }) + '\\n')
await new Promise((r) => setTimeout(r, 2000))`, RUN_ARGS())
  assert.match(two.out, /a second request while a prompt is open/)
  const flood = await refusedCase('flood', `
import fs from 'node:fs'
const line = JSON.stringify({ id: 1, kind: 'word', word: 'again', detail: 'x' }) + '\\n'
for (let i = 0; i < 2000; i++) fs.writeSync(3, line)
await new Promise((r) => setTimeout(r, 2000))`, RUN_ARGS())
  assert.match(flood.out, /a second request while a prompt is open/)
  const big = await refusedCase('big', `
import fs from 'node:fs'
fs.writeSync(3, 'x'.repeat(200000))
await new Promise((r) => setTimeout(r, 2000))`, RUN_ARGS())
  assert.match(big.out, /an oversized request/)
  for (const r of [two, flood, big]) { assert.match(r.out, /BROKER-EXIT=2/); assert.ok(!r.out.includes('CHILD-SURVIVED')); tty_ok(r.out) }
})

test('M-1: a child that dies mid-prompt (SIGKILL of itself while the passphrase is being typed) leaves the terminal restored; the broker exits with 128+9', { timeout: 60_000 }, async () => {
  const l = child('die-mid-prompt', `
tty.passphrase('eth').catch(() => {})
setTimeout(() => process.kill(process.pid, 'SIGKILL'), 500)`)
  const r = await runInPty(['/bin/sh', '-c', `${brokerArgv(l, RUN_ARGS()).map((x) => `'${x}'`).join(' ')}; echo "BROKER-EXIT=$?"; stty -a | tr '\n' ' '`], { env: env(), steps: [{ waitFor: 'Passphrase: ', send: '' }, ENTER] })
  assert.match(r.out, /BROKER-EXIT=137/)
  tty_ok(r.out)
  assert.match(r.out, /\becho\b/)
})

test('M-1: under the real profile the child cannot signal its parent (the broker): `(deny signal)(allow signal (target self))`', { timeout: 60_000 }, async () => {
  const l = child('signal', `
let r
try { process.kill(process.ppid, 0); r = 'SIGNALLED' } catch (e) { r = e.code }
try { process.kill(process.ppid, 'SIGWINCH'); r += ',SENT' } catch (e) { r += ',' + e.code }
try { process.kill(process.pid, 0); r += ',self-ok' } catch (e) { r += ',self-' + e.code }
console.log('SIG ' + r)
process.exit(0)`)
  const open = await runInPty(brokerArgv(l, ['status']), { env: env(), steps: [] })
  assert.match(open.out, /SIG SIGNALLED,SENT,self-ok/, 'control: without the deny the child reaches its parent')
  const { commandProfile } = await import('../src/ops/sandbox.ts')
  const { scopeFor } = await import('../src/ops/scope.ts')
  const home = join(T, 'sig-home'), outd = join(T, 'sig-out')
  mkdirSync(home, { recursive: true }); mkdirSync(outd, { recursive: true })
  const prof = commandProfile(['status'], 'local', home, outd, { ...scopeFor(['status'], { HOME: T, PATH: process.env.PATH }), launcher: l, node: [NODE, ...scopeFor(['status'], { HOME: T, PATH: process.env.PATH }).node] }) as string
  // the child launcher is a /bin/sh shim running node: allow the exec/read it needs by listing the shim and its script as handed files
  const prof2 = commandProfile(['status'], 'local', home, outd, { ...scopeFor(['status'], { HOME: T, PATH: process.env.PATH }), launcher: l, handed: [l, join(T, 'signal.mjs'), join(CLI, 'src', 'job', 'tty.ts')] }) as string
  void prof
  const r = await runInPty(brokerArgv(l, ['status'], prof2), { env: env(), steps: [] })
  assert.match(r.out, /SIG EPERM,EPERM,self-ok|SIG [A-Z]+,[A-Z]+,self-ok/, r.out)
  assert.ok(!/SIGNALLED|SENT/.test(r.out), 'the profile stops it')
})

test('output escape sequences are stripped: OSC 52, CSI, DCS, C1 never reach the terminal (stdout and stderr)', { timeout: 60_000 }, async () => {
  const l = child('escapes', `
process.stdout.write('A${esc}]52;c;U0VDUkVU\\x07B${esc}[31mC${esc}[2J${esc}P1$r${esc}\\\\D\\u009b2JE\\n')
process.stderr.write('F${esc}]0;title\\x07G\\n')
process.exit(0)`)
  const r = await runInPty(brokerArgv(l), { env: env(), steps: [] })
  assert.equal(r.code, 0, r.out)
  const printed = r.out.replace(/\r/g, '')
  assert.match(printed, /ABCDE\nFG\n/)
  assert.ok(!printed.includes('U0VDUkVU') && !printed.includes(`${esc}]`) && !printed.includes(`${esc}[`), 'no escape or payload')
})

test('TIOCSTI and every other terminal route are impossible for the child: /dev/tty and the pty slave the test runs on are EPERM (open for read, write, ioctl)', { timeout: 60_000 }, async () => {
  const l = child('tiocsti', `
import fs from 'node:fs'
import { spawnSync } from 'node:child_process'
const out = {}
const tryOpen = (p, flag, tag) => { try { fs.closeSync(fs.openSync(p, flag)); out[tag] = 'OPENED' } catch (e) { out[tag] = e.code } }
const slave = process.env.TESTTTY
tryOpen('/dev/tty', fs.constants.O_RDWR | fs.constants.O_NOCTTY, 'devtty-rw')
tryOpen('/dev/tty', fs.constants.O_WRONLY | fs.constants.O_NOCTTY, 'devtty-w')
tryOpen(slave, fs.constants.O_RDWR | fs.constants.O_NOCTTY, 'slave-rw')
tryOpen(slave, fs.constants.O_RDONLY | fs.constants.O_NOCTTY, 'slave-r')
// the child's own stdio are pipes, not terminals
out.stdinIsTTY = process.stdin.isTTY === true; out.stdoutIsTTY = process.stdout.isTTY === true
// python's TIOCSTI on the slave: the open fails first, which is the point; also try through /dev/fd/0..2 (they are pipes)
const py = spawnSync('/opt/homebrew/bin/python3', ['-c', 'import fcntl,os,sys,termios\\nfor p in [sys.argv[1], "/dev/tty"]:\\n  try:\\n    fd=os.open(p, os.O_RDWR|os.O_NOCTTY); fcntl.ioctl(fd, termios.TIOCSTI, b"x"); print("INJECTED")\\n  except OSError as e: print(e.errno)\\n', slave], { encoding: 'utf8' })
out.python = py.error ? py.error.code : py.stdout.trim().split('\\n').join(',')
console.log('RES ' + JSON.stringify(out))
process.exit(0)`)
  const r = await runInPty(['/bin/sh', '-c', `TESTTTY=$(tty) exec ${[NODE, '--disable-sigusr1', BROKER, '/usr/bin/sandbox-exec', PROFILE, l].map((x) => `'${x}'`).join(' ')}`], { env: env(), steps: [] })
  assert.equal(r.code, 0, r.out)
  const m = /RES (\{.*\})/.exec(r.out)
  assert.ok(m !== null, r.out)
  const res = JSON.parse(m[1]) as Record<string, unknown>
  assert.deepEqual([res['devtty-rw'], res['devtty-w'], res['slave-rw'], res['slave-r']], ['EPERM', 'EPERM', 'EPERM', 'EPERM'])
  assert.equal(res.stdinIsTTY, false); assert.equal(res.stdoutIsTTY, false)
  assert.ok(!String(res.python).includes('INJECTED'), String(res.python))
  assert.match(String(res.python), /^1,1$|^1,1\b|python3/, 'python could not even open the terminals (EPERM = 1)')
  // control: WITHOUT the terminal denies the child can open the slave, so the test can fail
  const open = child('tiocsti-control', `
import fs from 'node:fs'
try { fs.closeSync(fs.openSync(process.env.TESTTTY, fs.constants.O_RDWR | fs.constants.O_NOCTTY)); console.log('CONTROL opened') } catch (e) { console.log('CONTROL ' + e.code) }
process.exit(0)`)
  const c = await runInPty(['/bin/sh', '-c', `TESTTTY=$(tty) exec ${[NODE, '--disable-sigusr1', BROKER, '/usr/bin/sandbox-exec', '(version 1)(allow default)', open].map((x) => `'${x}'`).join(' ')}`], { env: env(), steps: [] })
  assert.match(c.out, /CONTROL opened/, 'the control (no deny) really opens the terminal')
})

test('`s` and Ctrl-C typed at the terminal reach the child as control messages; the broker owns the tty', { timeout: 60_000 }, async () => {
  const l = child('keys', `
const stop = tty.keys((k) => { console.log('KEY ' + k); if (k === 'interrupt') { stop(); process.exit(0) } })
console.log('READY')
setTimeout(() => process.exit(3), 20000)`)
  const r = await runInPty(brokerArgv(l, ['job', 'run', 'x']), { env: env(), steps: [{ waitFor: 'READY', send: 's' }, { waitFor: 'KEY skip', send: '\x03' }] })
  assert.equal(r.code, 0, r.out)
  assert.match(r.out, /KEY skip/)
  assert.match(r.out, /KEY interrupt/)
})

test('a SIGTERM sent to the broker is forwarded to the child EVERY time it arrives; the broker exits with the child\'s status', { timeout: 60_000 }, async () => {
  const l = child('sig', `
let n = 0
process.on('SIGTERM', () => { n++; console.log('GOT SIGTERM ' + n); if (n === 2) process.exit(7) })
console.log('READY')
setTimeout(() => process.exit(3), 20000)`)
  const { spawn } = await import('node:child_process')
  const p = spawn(NODE, ['--disable-sigusr1', BROKER, '/usr/bin/sandbox-exec', PROFILE, l], { env: env(), stdio: ['ignore', 'pipe', 'pipe'] })
  let out = ''
  p.stdout.on('data', (d: Buffer) => { out += d.toString(); if (out.includes('READY') && !out.includes('SENT1')) { out += 'SENT1'; p.kill('SIGTERM') } else if (out.includes('GOT SIGTERM 1') && !out.includes('SENT2')) { out += 'SENT2'; p.kill('SIGTERM') } })
  const code: number = await new Promise((res) => p.on('close', (c) => res(c ?? -1)))
  assert.match(out, /GOT SIGTERM 2/)
  assert.equal(code, 7)
})

test('stdout and stderr redirected to REGULAR FILES still work through the broker (the broker, outside the sandbox, holds the files)', () => {
  const l = child('files', `
console.log('to stdout ✓'); console.error('to stderr')
process.exit(0)`)
  const o = join(T, 'redir out (1).txt'), e = join(T, 'redir err.txt')
  const r = spawnSync('/bin/sh', ['-c', `"$@" > "${o}" 2> "${e}"`, 'sh', ...brokerArgv(l)], { env: env(), encoding: 'utf8', timeout: 30_000 })
  assert.equal(r.status, 0, r.stderr)
  assert.equal(readFileSync(o, 'utf8'), 'to stdout ✓\n')
  assert.equal(readFileSync(e, 'utf8'), 'to stderr\n')
})

test('answerRequest (policy unit): the broker\'s own text for every kind; malformed lines, unknown kinds, ids and words are Violations; labels and details are sanitised', async () => {
  const { answerRequest, policyFor, Violation, WORD_TEXT, BROKER_TAG } = await import('../src/ops/broker.ts')
  const noted: string[] = [], prompted: string[] = []
  const tty = { available: () => true, passphrase: async () => 'pw', word: async (p: string) => { prompted.push(p); return 'again' }, keys: () => () => {}, note: (t: string) => { noted.push(t) } }
  const h = { start() {}, stop() {} }
  const fresh = (args: string[]) => { const policy = policyFor(args); return { policy, state: { asked: new Set<'eth' | 'sol' | 'btc'>(), left: new Map(policy.words) } } }
  for (const line of ['not json', '[]', 'null', '{"kind":"shell"}', '{"id":1,"kind":"shell"}', '{"id":"x","kind":"word","word":"again"}', '{"id":1.5,"kind":"word","word":"again"}', '{"id":1,"kind":"word","word":"rm -rf /"}', '{"id":1,"kind":"passphrase","chain":"btc"}']) {
    const { policy, state } = fresh(['job', 'run', 'x', '--backup-eth', '/b/k.age'])
    await assert.rejects(answerRequest(line, tty, policy, state, h), Violation, line)
  }
  const { policy, state } = fresh(['job', 'run', 'x', '--backup-eth', '/b/vt-eth-key (1).age'])
  assert.equal(await answerRequest('{"id":2,"kind":"passphrase","chain":"eth"}', tty, policy, state, h), '{"id":2,"answer":"pw"}')
  assert.match(noted.join(''), new RegExp(`${BROKER_TAG.replace(/[[\]]/g, '\\$&')}passphrase of the key backup vt-eth-key \\(1\\)\\.age \\(eth\\)`))
  const ans = await answerRequest(`{"id":3,"kind":"word","word":"again","detail":"x\\u001b]52;c;QUJD\\u0007 \\u202eevil ${'y'.repeat(400)}"}`, tty, policy, state, h)
  assert.equal(ans, '{"id":3,"answer":"again"}')
  assert.ok(prompted[0].includes(WORD_TEXT.again))
  assert.ok(!prompted[0].includes('\u001b') && !prompted[0].includes('QUJD') && !prompted[0].includes('\u202e'), 'the detail is sanitised')
  assert.ok(prompted[0].length < 400, 'and capped')
  assert.equal(policyFor(['status']).prompts, false)
  assert.equal(policyFor(['job', 'list']).prompts, false)
  assert.deepEqual([...policyFor(['job', 'clawback', 'x', '--chain', 'eth', '--backup-eth', '/b/k'], 'mainnet').words.entries()], [['again', 1], ['amount', 1], ['clawback', 1]], 'claw-back caps are 1; again = the network acknowledgement of a legacy backup (R2-3)')
  assert.deepEqual([...policyFor(['job', 'clawback', 'x', '--chain', 'eth', '--backup-eth', '/b/k']).words.keys()], ['again', 'amount'], 'claw back is a mainnet word')
  assert.equal(policyFor(['job', 'run', 'x', '--backup-eth', '/a', '--backup-eth', '/b']).passphrases.get('eth'), '/a', 'the first handed file wins; asked once')
})

// ---- through the REAL bin/vt: a mainnet `vt job resume` asks its typed word on the terminal via the broker, in the full client sandbox (fake API on the fixed mainnet API port)
test('real bin/vt in a pty: `vt job resume` on mainnet prompts through the broker (typed word echoed, nothing leaks), the sandboxed child has no terminal, the answer reaches the API', { timeout: 120_000 }, async (t) => {
  const { createServer } = await import('node:http')
  const { PORTS } = await import('@vault-timelock/core/contracts')
  const seen: Array<{ url: string; body: string }> = []
  const srv = createServer((q, r) => {
    const chunks: Buffer[] = []
    q.on('data', (c: Buffer) => chunks.push(c))
    q.on('end', () => { seen.push({ url: q.url ?? '', body: Buffer.concat(chunks).toString() }); r.setHeader('content-type', 'application/json'); r.end(JSON.stringify({ seq: 5, resumed: ['eth'] })) })
  })
  const listening = await new Promise<boolean>((res) => { srv.once('error', () => res(false)); srv.listen(PORTS.mainnet.api, '127.0.0.1', () => res(true)) })
  if (!listening) { t.skip(`port ${PORTS.mainnet.api} is busy (the controller's stack?): run this test with the stacks down`); return }
  try {
    const home = join(T, 'vt-home-e2e'), out = join(T, 'out-e2e')
    mkdirSync(join(home, 'mainnet'), { recursive: true, mode: 0o700 }); mkdirSync(out, { mode: 0o700 })
    writeFileSync(join(home, 'mainnet', 'api.token'), 'ab'.repeat(32), { mode: 0o600 })
    const e = { ...env(), VT_HOME: home, VAULT_TIMELOCK_DIR: out }
    const r = await runInPty([join(CLI, 'bin', 'vt'), '--network', 'mainnet', 'job', 'resume', 'e3d45f73cf65abaa'], { env: e, steps: [{ waitFor: 'type the word  resume', send: 'resume\r' }] })
    assert.equal(r.code, 0, r.out)
    assert.match(r.out, /resumed: eth/)
    assert.equal(seen.length, 1)
    assert.equal(seen[0].url, '/jobs/e3d45f73cf65abaa/resume')
    // a wrong word: refused, nothing sent
    seen.length = 0
    const w = await runInPty([join(CLI, 'bin', 'vt'), '--network', 'mainnet', 'job', 'resume', 'e3d45f73cf65abaa'], { env: e, steps: [{ waitFor: 'type the word  resume', send: 'nope\r' }, { waitFor: 'again (2/3)', send: 'Resume\r' }, { waitFor: 'again (3/3)', send: 'nope\r' }] })
    assert.equal(w.code, 2, w.out)
    assert.match(w.out, /refused job\.resume-typed/)
    assert.equal(seen.length, 0)
  } finally { srv.close() }
})

// ---- M-4 (c)(d): the child has no controlling terminal and inherits no stray descriptors; M-2: the output relay has backpressure
test('M-4: the child runs in its OWN SESSION: even with no deny at all, /dev/tty is ENXIO (no controlling terminal); and the descriptors the shell had open (40, 41, regular files) are not inherited', { timeout: 60_000 }, async () => {
  const l = child('session', `
import fs from 'node:fs'
let t
try { fs.closeSync(fs.openSync('/dev/tty', fs.constants.O_RDWR | fs.constants.O_NOCTTY)); t = 'OPENED' } catch (e) { t = e.code }
const fds = []
for (let fd = 0; fd < 64; fd++) { try { fs.fstatSync(fd); fds.push(fd) } catch { /* closed */ } }
const ino = (f) => fs.statSync(f).ino
const leaked = fds.filter((fd) => { try { const i = fs.fstatSync(fd).ino; return i === ino(process.env.F40) || i === ino(process.env.F41) } catch { return false } })
console.log('SESS tty=' + t + ' leaked=' + leaked.join(',') + ' fds=' + fds.join(','))
process.exit(0)`)
  const cmd = `exec 40>"${join(T, 'f40')}" 41>"${join(T, 'f41')}"; F40='${join(T, 'f40')}' F41='${join(T, 'f41')}' ${brokerArgv(l, [], '(version 1)(allow default)').map((x) => `'${x}'`).join(' ')}`
  const r = await runInPty(['/bin/sh', '-c', cmd], { env: env(), steps: [] })
  assert.match(r.out, /SESS tty=ENXIO leaked= fds=/, r.out)
  // control: a plain spawn from the same shell (no broker) does see the controlling terminal
  const c = child('session-control', `
import fs from 'node:fs'
try { fs.closeSync(fs.openSync('/dev/tty', fs.constants.O_RDWR | fs.constants.O_NOCTTY)); console.log('CTRL opened') } catch (e) { console.log('CTRL ' + e.code) }
process.exit(0)`)
  const cr = await runInPty(['/bin/sh', '-c', `'${c}'`], { env: env(), steps: [] })
  assert.match(cr.out, /CTRL opened/, 'control: without the broker\'s new session the terminal is reachable')
})

test('M-2: backpressure: a child writing 60 MB while the real stdout is not read does not make the broker buffer it (the child pipes are paused)', { timeout: 120_000 }, async () => {
  const l = child('flood-out', `
const chunk = 'a'.repeat(1 << 20) + '\\n'
for (let i = 0; i < 60; i++) process.stdout.write(chunk)`)
  const { spawn, spawnSync } = await import('node:child_process')
  const p = spawn(NODE, ['--disable-sigusr1', BROKER, '/usr/bin/sandbox-exec', '(version 1)(allow default)', l], { env: env(), stdio: ['ignore', 'pipe', 'pipe'] })
  p.stdout.pause()   // nobody reads the real stdout for a while
  await new Promise((r) => setTimeout(r, 4000))
  const rss = Number(spawnSync('/bin/ps', ['-o', 'rss=', '-p', String(p.pid)], { encoding: 'utf8' }).stdout.trim())   // KiB, this one pid
  p.stdout.resume()
  const code: number = await new Promise((res) => p.on('close', (c) => res(c ?? -1)))
  assert.equal(code, 0)
  assert.ok(rss > 0 && rss < 150_000, `the broker held ${rss} KiB while stdout was blocked`)
})

// =====================================================================================================================================
// TTY-less round 2
// =====================================================================================================================================

test('N-4: the broker\'s policy mirrors the real CLI: --chain narrows the passphrases, clawback only its own chain, mainnet-only words only on mainnet, publish only without --yes-publish-file, caps', async () => {
  const { policyFor } = await import('../src/ops/broker.ts')
  const both = ['--backup-eth', '/b/e', '--backup-btc', '/b/b']
  assert.deepEqual([...policyFor(['job', 'run', 'x', ...both]).passphrases.keys()], ['eth', 'btc'])
  assert.deepEqual([...policyFor(['job', 'run', 'x', '--chain', 'eth', ...both]).passphrases.keys()], ['eth'], 'run --chain eth decrypts only eth')
  assert.deepEqual([...policyFor(['job', 'clawback', 'x', '--chain', 'eth', '--to', '0x1', ...both]).passphrases.keys()], ['eth'], 'a claw-back uses only --backup-<--chain>')
  assert.deepEqual([...policyFor(['job', 'clawback', 'x', '--to', '0x1', ...both]).passphrases.keys()], [], 'no --chain: none')
  for (const sub of ['resume', 'resolve']) {
    assert.equal(policyFor(['job', sub, 'x']).prompts, false, `${sub} on local asks nothing`)
    assert.equal(policyFor(['job', sub, 'x'], 'mainnet').prompts, true)
  }
  assert.deepEqual([...policyFor(['job', 'arm', 'x']).words.keys()].sort(), ['again', 'amount'])
  assert.deepEqual([...policyFor(['job', 'arm', 'x'], 'mainnet').words.keys()].sort(), ['again', 'amount', 'broadcast', 'ticks'])
  assert.equal(policyFor(['job', 'arm', 'x', '--chains', 'eth']).words.get('again'), 1)
  assert.equal(policyFor(['job', 'create', 'f.json']).words.has('publish'), true)
  assert.equal(policyFor(['job', 'create', 'f.json', '--yes-publish-file', 'ab']).prompts, false)
})

test('N-3: typed answers are validated by the BROKER: only the expected word or an amount pattern is forwarded; anything else is asked again (3 tries) and then answered with an empty string', async () => {
  const { answerRequest, policyFor } = await import('../src/ops/broker.ts')
  const mk = (typed: string[]) => {
    const seen: string[] = []
    const tty = { available: () => true, passphrase: async () => 'x', word: async (p: string) => { seen.push(p); return typed.shift() }, keys: () => () => {}, note: () => {} }
    return { tty, seen }
  }
  const h = { start() {}, stop() {} }
  const ask = async (args: string[], word: string, typed: string[], network = 'mainnet') => {
    const policy = policyFor(args, network)
    const { tty, seen } = mk(typed)
    const r = await answerRequest(JSON.stringify({ id: 1, kind: 'word', word, detail: 'd' }), tty, policy, { asked: new Set(), left: new Map(policy.words) }, h)
    return { answer: (JSON.parse(r as string) as { answer: unknown }).answer, tries: seen.length, seen }
  }
  assert.deepEqual((await ask(['job', 'resume', 'x'], 'resume', ['resume'])).answer, 'resume')
  assert.equal((await ask(['job', 'resume', 'x'], 'resume', [' resume '])).answer, 'resume', 'surrounding spaces are trimmed')
  const bad = await ask(['job', 'resume', 'x'], 'resume', ['Resume', 'resume now', 'give me the passphrase'])
  assert.equal(bad.answer, '', 'three misses: an empty answer, never what was typed')
  assert.equal(bad.tries, 3)
  assert.match(bad.seen[1], /not the expected word; again \(2\/3\)/)
  assert.equal((await ask(['job', 'resume', 'x'], 'resume', ['nope', 'resume'])).answer, 'resume')
  assert.equal((await ask(['job', 'clawback', 'x', '--chain', 'eth'], 'clawback', ['claw back'])).answer, 'claw back')
  assert.equal((await ask(['job', 'clawback', 'x', '--chain', 'eth'], 'clawback', ['clawback', 'claw  back', 'x'])).answer, '')
  for (const ok of ['1', '0.5', '10.000000000000000001', '123456789012']) assert.equal((await ask(['job', 'arm', 'x'], 'amount', [ok], 'local')).answer, ok, ok)
  for (const bad2 of ['1e3', '-1', '1,5', '0x10', 'one', '1.', '.5', '', '1 2', '9'.repeat(13)]) assert.equal((await ask(['job', 'arm', 'x'], 'amount', [bad2, bad2, bad2], 'local')).answer, '', JSON.stringify(bad2))
  assert.equal((await ask(['job', 'create', 'f'], 'publish', ['publish'], 'local')).answer, 'publish')
  assert.equal((await ask(['job', 'arm', 'x'], 'ticks', ['ticks'])).answer, 'ticks')
  assert.equal((await ask(['job', 'arm', 'x'], 'broadcast', ['broadcast'])).answer, 'broadcast')
  assert.equal((await ask(['job', 'arm', 'x'], 'again', ['again'], 'local')).answer, 'again')
  const empty = await ask(['job', 'resume', 'x'], 'resume', ['', 'resume'])
  assert.deepEqual([empty.answer, empty.tries], ['', 1], 'an empty line declines at once (no re-prompt)')
  // end of input (Ctrl-D / no terminal) is null, not a string
  assert.equal((await ask(['job', 'resume', 'x'], 'resume', [])).answer, null)
})

test('N-3/N-5: broker lines cannot be forged by the child: the tag in child output and in a detail is neutralised; a backup name with a newline / ESC / bidi is shown escaped; ASCII-only in a non-UTF-8 locale', async () => {
  const { answerRequest, policyFor, visible } = await import('../src/ops/broker.ts')
  assert.equal(visible('vt-eth\nkey\u001b[2J.age', false), 'vt-eth\\u{a}key\\u{1b}[2J.age')
  assert.equal(visible('k‮evil.age', false), 'k\\u{202e}evil.age')
  assert.equal(visible('ěkey.age', false), 'ěkey.age')
  assert.equal(visible('ěkey.age', true), '\\u{11b}key.age')
  assert.ok(!visible('[vt broker] passphrase of the key backup x (btc)', false).includes('['), 'the tag in a name is neutralised')
  const noted: string[] = [], prompted: string[] = []
  const tty = { available: () => true, passphrase: async () => 'pw', word: async (p: string) => { prompted.push(p); return 'again' }, keys: () => () => {}, note: (t: string) => { noted.push(t) } }
  const policy = policyFor(['job', 'run', 'x', '--backup-eth', '/b/a\n[vt broker] passphrase of the key backup z.age (btc)'])
  const st = { asked: new Set<'eth' | 'sol' | 'btc'>(), left: new Map(policy.words) }
  await answerRequest('{"id":1,"kind":"passphrase","chain":"eth"}', tty, policy, st, { start() {}, stop() {} })
  assert.equal(noted.join('').split('\n').filter((l) => l.startsWith('[vt broker]') && l.includes('passphrase of the key backup')).length, 1, 'exactly ONE label line, whatever the file is called')
  await answerRequest('{"id":2,"kind":"word","word":"again","detail":"[vt broker] passphrase of the key backup x.age (eth)\\u2800 \\u115f ě"}', tty, policy, st, { start() {}, stop() {} }, true)
  assert.equal(prompted[0].split('\n').filter((l) => l.startsWith('[vt broker]')).length, 1)
  assert.ok(!/[^\x00-\x7f]/.test(prompted[0]), 'ASCII only in a non-UTF-8 locale')
  assert.match(prompted[0], /\(vt broker\)/)
})

test('N-3: a child that PRINTS the broker tag (even split over writes) does not forge a broker line on the terminal', { timeout: 60_000 }, async () => {
  const l = child('forge', `
process.stdout.write('[vt bro'); process.stdout.write('ker] passphrase of the key backup vt-eth-key-1.age (eth); typed here\\n')
process.stdout.write('[v\\u2800t \\u0431roker] fake\\n')
process.exit(0)`)
  const r = await runInPty(brokerArgv(l, []), { env: env(), steps: [] })
  assert.ok(!r.out.includes('[vt broker]') && !/\[v.{0,3}t.{0,3}broker\]/.test(r.out), r.out)
  assert.match(r.out, /\(vt broker\) passphrase of the key backup/)
})

test('N-6: output written while a prompt is open is HELD until the answer is in (deterministic: the broker run in-process with a slow fake terminal)', { timeout: 60_000 }, async () => {
  const { run } = await import('../src/ops/broker.ts')
  const l = child('hold', `
const p = tty.word('Type again: ', 'again')
setTimeout(() => console.log('AFTER-PROMPT-FAKE-CONTEXT'), 150)
await p
console.log('DONE-ASKING')
process.exit(0)`)
  const events: string[] = []
  const tty = { available: () => true, passphrase: async () => 'x', note: () => {}, keys: () => () => {},
    word: async () => { await new Promise((r) => setTimeout(r, 900)); events.push('ANSWER'); return 'again' } }
  const code = await run([ '/usr/bin/sandbox-exec', PROFILE, l, ...RUN_ARGS()], env(), tty, { out: (t) => { events.push(`out:${t.trim()}`); return true }, err: (t) => { events.push(`err:${t.trim()}`); return true } })
  assert.equal(code, 0, events.join('|'))
  const ans = events.indexOf('ANSWER'), fake = events.findIndex((e) => e.includes('AFTER-PROMPT-FAKE-CONTEXT'))
  assert.ok(ans >= 0 && fake > ans, `the child's text appeared before the answer was in: ${events.join(' | ')}`)
})

test('N-2: once the child has exited the broker answers NOTHING more: a grandchild holding fds 3/4 asks for the passphrase and gets no prompt and no answer; the broker ends', { timeout: 60_000 }, async () => {
  const l = child('grandchild', `
import { spawn } from 'node:child_process'
const g = spawn(process.execPath, ['--input-type=module', '-e', "import fs from 'node:fs'; await new Promise((r) => setTimeout(r, 1200)); try { fs.writeSync(3, JSON.stringify({ id: 9, kind: 'passphrase', chain: 'eth' }) + '\\\\n'); console.log('GRANDCHILD-ASKED') } catch (e) { console.log('GRANDCHILD-' + e.code) }; setTimeout(() => process.exit(0), 3000)"], { stdio: ['ignore', 'inherit', 'inherit', 3, 4], detached: true })
g.unref()
process.exit(0)`)
  const t0 = Date.now()
  const r = await runInPty(['/bin/sh', '-c', `${brokerArgv(l, RUN_ARGS()).map((x) => `'${x}'`).join(' ')}; echo "BROKER-EXIT=$?"`], { env: env(), steps: [] })
  assert.match(r.out, /BROKER-EXIT=0/)
  assert.ok(!/Passphrase: /.test(r.out) && !r.out.includes('[vt broker] passphrase'), `no prompt after the child exited: ${r.out}`)
  assert.ok(Date.now() - t0 < 8000, 'the broker did not wait for the grandchild')
})

test('N-2: Ctrl-C reaches the child\'s whole PROCESS GROUP; when the child is already gone it ends the broker itself', { timeout: 60_000 }, async () => {
  const { spawn } = await import('node:child_process')
  // (1) forwarded to the group: the child and its own child both see SIGINT
  const l = child('grp', `
import { spawn } from 'node:child_process'
const g = spawn(process.execPath, ['-e', "process.on('SIGINT', () => { console.log('GRANDCHILD-SIGINT'); process.exit(0) }); console.log('GRANDCHILD-READY'); setTimeout(() => {}, 20000)"], { stdio: ['ignore', 'inherit', 'inherit'] })
process.on('SIGINT', () => { console.log('CHILD-SIGINT'); setTimeout(() => process.exit(0), 300) })
console.log('READY')
setTimeout(() => process.exit(3), 20000)`)
  const p = spawn(NODE, ['--disable-sigusr1', BROKER, '/usr/bin/sandbox-exec', PROFILE, l], { env: env(), stdio: ['ignore', 'pipe', 'pipe'] })
  let out = ''
  p.stdout.on('data', (d: Buffer) => { out += d.toString(); if (out.includes('GRANDCHILD-READY') && !out.includes('SENT')) { out += 'SENT'; p.kill('SIGINT') } })
  await new Promise((res) => p.on('close', res))
  assert.match(out, /CHILD-SIGINT/)
  assert.match(out, /GRANDCHILD-SIGINT/)
  // (2) the child is gone but a detached grandchild keeps the pipes: SIGINT ends the broker (130)
  const l2 = child('grp2', `
import { spawn } from 'node:child_process'
spawn(process.execPath, ['-e', 'setTimeout(() => {}, 15000)'], { stdio: ['ignore', 'inherit', 'inherit'], detached: true }).unref()
console.log('READY2')
process.exit(0)`)
  const p2 = spawn(NODE, ['--disable-sigusr1', BROKER, '/usr/bin/sandbox-exec', PROFILE, l2], { env: env(), stdio: ['ignore', 'pipe', 'pipe'] })
  let out2 = ''
  let sent2 = false
  p2.stdout.on('data', (d: Buffer) => { out2 += d.toString(); if (out2.includes('READY2') && !sent2) { sent2 = true; setTimeout(() => p2.kill('SIGINT'), 100) } })
  const t0 = Date.now()
  const code: number = await new Promise((res) => p2.on('close', (c) => res(c ?? -1)))
  assert.ok(Date.now() - t0 < 5000, 'ended by the signal, not by waiting for the grandchild')
  assert.match(out2, /READY2/)
  assert.ok(code === 0 || code === 130, `exit ${code}`)
})

test('(a) a sandboxed child whose broker is killed (kill -9) DETACHES: it hangs up on itself instead of running on unwatched', { timeout: 60_000 }, async () => {
  const flag = join(T, 'detached.flag'), pidf = join(T, 'detached.pid')
  const l = child('orphan', `
import fs from 'node:fs'
import { watchBroker } from ${JSON.stringify(TTYJS)}
fs.writeFileSync(${JSON.stringify(pidf)}, String(process.pid))
process.on('SIGHUP', () => { fs.writeFileSync(${JSON.stringify(flag)}, 'DETACHED'); process.exit(0) })
watchBroker(process.env, { intervalMs: 100 })
console.log('READY')
setTimeout(() => process.exit(3), 15000)`)
  const { spawn } = await import('node:child_process')
  const p = spawn(NODE, ['--disable-sigusr1', BROKER, '/usr/bin/sandbox-exec', PROFILE, l], { env: env(), stdio: ['ignore', 'pipe', 'pipe'] })
  await new Promise<void>((res) => p.stdout.on('data', (d: Buffer) => { if (d.toString().includes('READY')) res() }))
  p.kill('SIGKILL')
  const until = Date.now() + 5000
  while (Date.now() < until && !(await import('node:fs')).existsSync(flag)) await new Promise((r) => setTimeout(r, 100))
  const pid = Number(readFileSync(pidf, 'utf8'))
  try { process.kill(pid, 'SIGKILL') } catch { /* already gone: the point */ }
  assert.equal(readFileSync(flag, 'utf8'), 'DETACHED', 'the child noticed its broker was gone and hung up')
})

test('(b) EPIPE on the broker\'s stdout (`vt status | head -1`) exits quietly with no stack trace, and the child is told to stop', { timeout: 60_000 }, async () => {
  const pidf = join(T, 'epipe.pid'), flag = join(T, 'epipe.flag')
  const l = child('epipe', `
import fs from 'node:fs'
fs.writeFileSync(${JSON.stringify(pidf)}, String(process.pid))
process.on('SIGHUP', () => { fs.writeFileSync(${JSON.stringify(flag)}, 'STOPPED'); process.exit(0) })
const t = setInterval(() => { try { process.stdout.write('line of output\\n') } catch { /* gone */ } }, 5)
setTimeout(() => { clearInterval(t); process.exit(3) }, 8000)`)
  const r = spawnSync('/bin/sh', ['-c', `"$@" 2>"${join(T, 'epipe.err')}" | head -1`, 'sh', ...brokerArgv(l, [])], { env: env(), encoding: 'utf8', timeout: 30_000 })
  assert.equal(r.stdout.trim(), 'line of output')
  const err = readFileSync(join(T, 'epipe.err'), 'utf8')
  assert.ok(!/EPIPE|at |Error/.test(err), `no stack trace: ${err.slice(0, 300)}`)
  const until = Date.now() + 4000
  while (Date.now() < until && !(await import('node:fs')).existsSync(flag)) await new Promise((x) => setTimeout(x, 100))
  try { process.kill(Number(readFileSync(pidf, 'utf8')), 'SIGKILL') } catch { /* gone */ }
  assert.equal(readFileSync(flag, 'utf8'), 'STOPPED', 'the child was told to stop')
})

test('N-1: saveTermios understands the macOS `stty -g` format and restoreTermios really puts a raw / no-echo terminal back (fails when restore is a no-op)', { timeout: 60_000 }, async () => {
  const js = join(T, 'termios.mjs')
  writeFileSync(js, `
import { saveTermios, restoreTermios } from ${JSON.stringify(join(CLI, 'src', 'ops', 'ttyio.ts'))}
import { spawnSync } from 'node:child_process'
const saved = saveTermios()
console.log('SAVED=' + (saved === null ? 'null' : saved.slice(0, 6)))
spawnSync('/bin/stty', ['raw', '-echo'], { stdio: [0, 'ignore', 'ignore'] })
const mid = spawnSync('/bin/stty', ['-a'], { stdio: [0, 'pipe', 'ignore'], encoding: 'utf8' }).stdout.replace(/\\s+/g, ' ')
console.log('MID-RAW=' + (/ -icanon /.test(mid) && / -echo /.test(mid)))
restoreTermios(saved)
const after = spawnSync('/bin/stty', ['-a'], { stdio: [0, 'pipe', 'ignore'], encoding: 'utf8' }).stdout.replace(/\\s+/g, ' ')
console.log('AFTER-RESTORED=' + (!/ -icanon /.test(after) && !/ -echo /.test(after) && !/ -isig /.test(after)))
`)
  const r = await runInPty([NODE, js], { env: env(), steps: [] })
  assert.match(r.out, /SAVED=gfmt1|SAVED=[0-9a-f:]/, r.out)
  assert.match(r.out, /MID-RAW=true/, 'the terminal really was put into raw / no-echo')
  assert.match(r.out, /AFTER-RESTORED=true/, r.out)
})

test('N-1: the broker restores the terminal when the child dies mid-prompt while a descendant still holds the pipes (broker kept alive until the drain timeout), and never echoes a typed passphrase', { timeout: 60_000 }, async () => {
  const l = child('restore-mid', `
import { spawn } from 'node:child_process'
spawn(process.execPath, ['-e', 'setTimeout(() => {}, 6000)'], { stdio: ['ignore', 'inherit', 'inherit'], detached: true }).unref()
tty.passphrase('eth').catch(() => {})
setTimeout(() => process.exit(0), 400)`)
  const r = await runInPty(['/bin/sh', '-c', `${brokerArgv(l, RUN_ARGS()).map((x) => `'${x}'`).join(' ')}; echo "BROKER-EXIT=$?"; stty -a | tr '\\n' ' '`], { env: env(), steps: [{ waitFor: 'Passphrase: ', send: '' }, ENTER] })
  assert.match(r.out, /BROKER-EXIT=0/)
  tty_ok(r.out)
  assert.match(r.out, /\becho\b/)
})

test('I-2 (self-built addon): a grandchild node without --no-addons cannot map a native addon built by the test itself under the real profile', { timeout: 120_000 }, async (t) => {
  const { dirname } = await import('node:path')
  const inc = join(dirname(dirname(NODE)), 'include', 'node')
  const src = join(T, 'tiny.c'), so = join(T, 'tiny.node')
  writeFileSync(src, '#include <node_api.h>\nNAPI_MODULE_INIT() { return exports; }\n')
  const cc = spawnSync('/usr/bin/clang', ['-shared', '-undefined', 'dynamic_lookup', `-I${inc}`, src, '-o', so], { encoding: 'utf8', timeout: 60_000 })
  if (cc.status !== 0) { t.skip(`no C compiler / node headers to build a test addon (${String(cc.stderr).slice(0, 100)}): the ticket-key-real addon case (any installed .node) still runs`); return }
  const { commandProfile } = await import('../src/ops/sandbox.ts')
  const { scopeFor } = await import('../src/ops/scope.ts')
  const home = join(T, 'ad-home'), outd = join(T, 'ad-out')
  mkdirSync(home, { recursive: true }); mkdirSync(outd, { recursive: true })
  const prof = commandProfile(['status'], 'local', home, outd, { ...scopeFor(['status'], { HOME: T, PATH: process.env.PATH }), handed: [so] }) as string
  const probe = (profile: string): string => spawnSync('/usr/bin/sandbox-exec', ['-p', profile, NODE, '-e', `try { process.dlopen({ exports: {} }, ${JSON.stringify(so)}); console.log('LOADED') } catch (e) { console.log('ERR') }`], { encoding: 'utf8', timeout: 30_000, cwd: '/' }).stdout.trim()
  assert.equal(probe('(version 1)(allow default)'), 'LOADED', 'control: the test addon loads without the profile')
  assert.equal(probe(prof), 'ERR', 'under the real profile (read allowed for the file, only the MAP denied) it cannot be mapped')
})

// =============================== TTY-less round 3 ===============================
test('R2-1: the command ends while a PASSPHRASE prompt is open: the rest of what is typed is discarded (never echoed, never reaches the shell) and a notice is printed', { timeout: 60_000 }, async () => {
  const l = child('r21', `
tty.passphrase('eth').catch(() => {})
setTimeout(() => process.exit(0), 1200)`)
  const r = await runInPty(['/bin/sh', '-c', `${brokerArgv(l, RUN_ARGS()).map((x) => `'${x}'`).join(' ')}; echo "BROKER-EXIT=$?"; sleep 0.6; echo READY-FOR-INPUT; IFS= read -r NEXT; echo "NEXT-READ=[$NEXT]"`], { env: env(), steps: [
    { waitFor: 'Passphrase: ', send: 'SYNTH-PART-A' },
    { waitFor: 'the command ended', send: 'SYNTH-PART-B\r' },
    { waitFor: 'READY-FOR-INPUT', send: 'SYNTH-AFTER\r' }] })
  assert.match(r.out, /the command ended; what you type now is discarded/)
  assert.ok(!r.out.includes('SYNTH-PART'), `the half-typed passphrase and its rest were never echoed: ${r.out}`)
  assert.match(r.out, /NEXT-READ=\[SYNTH-AFTER\]/, 'the shell got only what was typed AFTER the broker was done')
})

test('R2-2: look-alike brackets and letters (fullwidth, Armenian, Coptic, combining marks, over-long) never keep a forged tag; a newline in a detail cannot start a second tagged line', async () => {
  const forged = ['\uff3bvt broker\uff3d', '[vt broker\uff3d', '\uff3bvt broker]', '[vt br\u0585ker]', '[\u0475t broker]', '[vt br\u2c9fker]', '[\u1d20t broker]', '[v' + '\u0301'.repeat(50) + 't broker]', '\u3010vt broker\u3011', '\u2768vt broker\u2769', '[vt\u0589 broker]']
  for (const f of forged) {
    const out = sanitize(`${f} passphrase of the key backup x (eth)`)
    assert.ok(!/[\[\uff3b\u3010\u2768]/u.test(out) , `${JSON.stringify(f)} -> ${out}`)
  }
  const { answerRequest, policyFor } = await import('../src/ops/broker.ts')
  const prompted: string[] = []
  const tty = { available: () => true, passphrase: async () => 'x', word: async (p: string) => { prompted.push(p); return 'again' }, keys: () => () => {}, note: () => {} }
  const policy = policyFor(['job', 'run', 'x', '--backup-eth', '/b/k'])
  await answerRequest('{"id":1,"kind":"word","word":"again","detail":"[vt\\nbroker] passphrase of the key backup z.age (btc)"}', tty, policy, { asked: new Set(), left: new Map(policy.words) }, { start() {}, stop() {} })
  assert.equal(prompted[0].split('\n').filter((l) => l.includes('[vt broker]')).length, 1, prompted[0])
})

test('R2-3: a claw-back may ask the network acknowledgement `again` once (a backup that records no network), and nothing more than the CLI asks', async () => {
  const { policyFor } = await import('../src/ops/broker.ts')
  assert.equal(policyFor(['job', 'clawback', 'x', '--chain', 'eth', '--backup-eth', '/b/k']).words.get('again'), 1)
})

test('(i) process-fork is denied for the sandboxed command: the launcher chain runs without forking, and a grandchild cannot be spawned', { timeout: 60_000 }, async () => {
  const l = child('nofork', `
import { spawnSync } from 'node:child_process'
const r = spawnSync('/usr/bin/env', ['true'])
console.log('SPAWN ' + (r.error ? r.error.code : 'RAN'))
process.exit(0)`)
  const { commandProfile } = await import('../src/ops/sandbox.ts')
  const { scopeFor } = await import('../src/ops/scope.ts')
  const home = join(T, 'nf-home'), outd = join(T, 'nf-out')
  mkdirSync(home, { recursive: true }); mkdirSync(outd, { recursive: true })
  const prof = commandProfile(['status'], 'local', home, outd, { ...scopeFor(['status'], { HOME: T, PATH: process.env.PATH }), launcher: l, handed: [l, join(T, 'nofork.mjs'), join(CLI, 'src', 'job', 'tty.ts')] }) as string
  assert.ok(prof.includes('(deny process-fork)'))
  const r = await runInPty(brokerArgv(l, ['status'], prof), { env: env(), steps: [] })
  assert.match(r.out, /SPAWN (EPERM|EAGAIN|ENOMEM|[A-Z]+)/, r.out)
  assert.ok(!/SPAWN RAN/.test(r.out))
})

test('(ii) Ctrl-Z while a command runs is ignored with a notice: the broker does not stop (the child never runs unattended)', { timeout: 60_000 }, async () => {
  const l = child('tstp', `
console.log('READY')
setTimeout(() => { console.log('STILL-RUNNING'); process.exit(0) }, 1500)`)
  const r = await runInPty(brokerArgv(l, ['status']), { env: env(), steps: [{ waitFor: 'READY', send: '\x1a' }] })
  assert.equal(r.code, 0, r.out)
  assert.match(r.out, /Ctrl-Z is ignored/)
  assert.match(r.out, /STILL-RUNNING/)
})

test('R2-4: main.ts wires watchBroker: a REAL main.ts started with VT_BROKER=1 hangs up when its parent (the broker) is SIGKILLed', { timeout: 60_000 }, async () => {
  const flag = join(T, 'main-detached.flag')
  const l = child('mainwire', `
const { main } = await import(${JSON.stringify(join(CLI, 'src', 'main.ts'))})
process.on('SIGHUP', () => { import('node:fs').then((fs) => { fs.writeFileSync(${JSON.stringify(flag)}, 'HUP'); process.exit(0) }) })
console.log('READY')
await main(['help'], process.env).catch(() => {})
setTimeout(() => process.exit(3), 15000)`)
  const { spawn } = await import('node:child_process')
  const p = spawn(NODE, ['--disable-sigusr1', BROKER, '/usr/bin/sandbox-exec', '(version 1)(allow default)', l, 'status'], { env: env(), stdio: ['ignore', 'pipe', 'pipe'] })
  await new Promise<void>((res) => p.stdout.on('data', (d: Buffer) => { if (d.toString().includes('READY')) res() }))
  await new Promise((r) => setTimeout(r, 300))
  p.kill('SIGKILL')
  const { existsSync } = await import('node:fs')
  const until = Date.now() + 6000
  while (Date.now() < until && !existsSync(flag)) await new Promise((r) => setTimeout(r, 100))
  assert.ok(existsSync(flag), 'main.ts armed the broker-death watch')
})

test('R2-4: bin/vt hands LC_ALL / LC_CTYPE to the BROKER only (the child never sees them)', () => {
  const text = readFileSync(join(CLI, 'bin', 'vt'), 'utf8')
  assert.ok(/set -- "LC_ALL=\$LC_ALL" "\$@"/.test(text) && /set -- "LC_CTYPE=\$LC_CTYPE" "\$@"/.test(text), 'bin/vt passes them as broker env')
})

test('ECHO RACE: a passphrase typed right after the command\'s own line but BEFORE its request is never echoed; type-ahead is discarded; the prompt then works', { timeout: 60_000 }, async () => {
  const l = child('race', `
console.log('eth: the passphrase of the key backup vt-eth-key-1.age (asked next, at the terminal)')
await new Promise((r) => setTimeout(r, 1500))
const p = await tty.passphrase('eth')
const { createHash } = await import('node:crypto')
console.log('GOT-LEN=' + p.length + ' sha=' + createHash('sha256').update(p).digest('hex'))
process.exit(0)`)
  const early = 'SYNTH-EARLY-TYPEAHEAD-PASS'
  const r = await runInPty(brokerArgv(l, RUN_ARGS()), { env: env(), steps: [
    { waitFor: 'asked next, at the terminal', send: `${early}\r` },
    { waitFor: 'Passphrase: ', send: `${PASS}\r` }] })
  assert.equal(r.code, 0, r.out)
  assert.ok(!r.out.includes(early) && !r.out.includes('EARLY'), `the early input was echoed: ${r.out}`)
  assert.ok(!r.out.includes(PASS))
  assert.match(r.out, /type it now/)
  assert.ok(r.out.includes(createHash('sha256').update(PASS).digest('hex')), 'the child got the passphrase typed AFTER the prompt, not the type-ahead')
})

// =============================== TTY-less round 4 ===============================
test('R3-1: type-ahead typed while echo is off never reaches the shell: normal end without a request, and a command that refuses before the second passphrase', { timeout: 90_000 }, async () => {
  // (a) the command prints its label line and ends without asking; the operator had typed ahead
  const a = child('r31a', `
console.log('eth: the passphrase of the key backup vt-eth-key-1.age (asked next, at the terminal)')
await new Promise((r) => setTimeout(r, 1200))
process.exit(1)`)
  const ra = await runInPty(['/bin/sh', '-c', `${brokerArgv(a, RUN_ARGS()).map((x) => `'${x}'`).join(' ')}; echo "BROKER-EXIT=$?"; sleep 0.6; echo READY-FOR-INPUT; IFS= read -r NEXT; echo "NEXT-READ=[$NEXT]"`], { env: env(), steps: [
    { waitFor: 'asked next, at the terminal', send: 'SYNTH-TYPEAHEAD-SECRET\r' },
    { waitFor: 'READY-FOR-INPUT', send: 'SYNTH-LATER\r' }] })
  assert.ok(!ra.out.includes('SYNTH-TYPEAHEAD'), `never echoed: ${ra.out}`)
  assert.match(ra.out, /NEXT-READ=\[SYNTH-LATER\]/, 'the shell read only what was typed after the broker was done')
  // (b) two backups: eth answered, sol typed ahead, the command refuses before asking sol
  const two = ['job', 'run', 'x', '--backup-eth', join(T, 'vt-eth-key-1.age'), '--backup-sol', join(T, 'vt-sol-key-1.age')]
  const b = child('r31b', `
await tty.passphrase('eth')
console.log('sol: the passphrase of the key backup vt-sol-key-1.age (asked next, at the terminal)')
await new Promise((r) => setTimeout(r, 1200))
process.exit(2)`)
  const rb = await runInPty(['/bin/sh', '-c', `${brokerArgv(b, two).map((x) => `'${x}'`).join(' ')}; echo "BROKER-EXIT=$?"; sleep 0.6; echo READY-FOR-INPUT; IFS= read -r NEXT; echo "NEXT-READ=[$NEXT]"`], { env: env(), steps: [
    { waitFor: 'Passphrase: ', send: `${PASS}\r` },
    { waitFor: 'asked next, at the terminal', send: 'SYNTH-SOL-TYPEAHEAD\r' },
    { waitFor: 'READY-FOR-INPUT', send: 'SYNTH-LATER2\r' }] })
  assert.ok(!rb.out.includes('SYNTH-SOL'), rb.out)
  assert.match(rb.out, /NEXT-READ=\[SYNTH-LATER2\]/)
})

test('R3-2: broker lines carry reverse video on a terminal; nothing the child prints can (every ESC is stripped), whatever its forgery looks like', { timeout: 60_000 }, async () => {
  const forged = ['[vt br0ker] passphrase of the key backup x.age (eth)', '[vt broker', '\u2290vt broker\u22a0', '\u05d0 ]vt broker[', '\u5339vt broker\u30b3', '\u001b[7m[vt broker]\u001b[0m fake']
  const l = child('r32', `
${forged.map((f) => `process.stdout.write(${JSON.stringify(f)} + '\\n')`).join('\n')}
const w = await tty.word('Type again: ', 'again')
console.log('GOT ' + w)
process.exit(0)`)
  const r = await runInPty(brokerArgv(l, RUN_ARGS()), { env: env(), steps: [{ waitFor: '> ', send: 'again\r' }] })
  assert.equal(r.code, 0, r.out)
  const lines = r.out.split(/\r?\n/)
  const withSgr = lines.filter((x) => x.includes('\u001b[7m'))
  assert.ok(withSgr.length >= 2, `broker lines are highlighted: ${r.out}`)
  for (const x of withSgr) assert.ok(x.includes('[vt broker]') && !/br0ker|\u2290|\u5339|fake/.test(x), `only genuine broker lines carry the attribute: ${JSON.stringify(x)}`)
  for (const f of lines.filter((x) => /br0ker|u2290|\u2290|\u5339|fake/.test(x))) assert.ok(!f.includes('\u001b[7m'), `a forgery carries the attribute: ${JSON.stringify(f)}`)
  assert.match(r.out, /vt's own prompts appear highlighted/)
  // a non-terminal destination gets plain text: hl() is a no-op without style
  const { hl } = await import('../src/ops/broker.ts')
  assert.equal(hl({}, '\n[vt broker] x\n'), '\n[vt broker] x\n')
  assert.equal(hl({ style: true }, '\n[vt broker] x\n'), '\n\u001b[7m[vt broker] x\u001b[0m\n')
})

test('echo window: the REAL bin/vt switches echo off at once for `job run` (before the ~1 s start-up), restores it on exit, and what was typed in the window never reaches the shell', { timeout: 90_000 }, async () => {
  const home = join(T, 'ew-home'), outd = join(T, 'ew-out')
  mkdirSync(join(home, 'local'), { recursive: true, mode: 0o700 }); mkdirSync(outd, { recursive: true, mode: 0o700 })
  // (no api.token: the command refuses before any connection, so a stack on the fixed ports is never contacted)
  const e = { ...env(), VT_HOME: home, VAULT_TIMELOCK_DIR: outd }
  const bk = join(T, 'vt-eth-key-1.age'); writeFileSync(bk, 'not a real backup', { mode: 0o600 })
  const r = await runInPty(['/bin/sh', '-c', `'${join(CLI, 'bin', 'vt')}' job run 0123456789abcdef --backup-eth '${bk}' & VP=$!; sleep 0.35; echo MID; wait $VP; echo "VT-EXIT=$?"; sleep 1; stty -a | tr '\\n' ' '; echo; IFS= read -r NEXT; echo "NEXT-READ=[$NEXT]"`], { env: e, steps: [
    { waitFor: 'MID', send: 'SYNTH-EARLY-WINDOW\r' },
    { waitFor: 'oflags', send: 'SYNTH-AFTER\r' }] })   // typed once the terminal settings were printed (after the broker's helper had its say)
  assert.ok(!r.out.includes('SYNTH-EARLY'), `echoed in the start-up window: ${r.out}`)
  assert.match(r.out, /NEXT-READ=\[SYNTH-AFTER\]/, 'the early input never reached the shell')
  tty_ok(r.out)
})

test('UX: echo is ON while a typed word is typed, even when an earlier passphrase prompt had it off (the shared-passphrase case)', async () => {
  const { answerRequest, policyFor } = await import('../src/ops/broker.ts')
  const calls: string[] = []
  const tty = { available: () => true, passphrase: async () => 'x', word: async () => { calls.push('word'); return 'again' }, keys: () => () => {}, note: () => {}, quiet: () => { calls.push('quiet') }, loud: () => { calls.push('loud') }, flush: () => {} }
  const policy = policyFor(['job', 'run', 'x', '--backup-eth', '/b/e', '--backup-sol', '/b/s'])
  const st = { asked: new Set<'eth' | 'sol' | 'btc'>(), left: new Map(policy.words) }
  await answerRequest('{"id":1,"kind":"passphrase","chain":"eth"}', tty, policy, st, { start() {}, stop() {} })
  await answerRequest('{"id":2,"kind":"word","word":"again","detail":"d"}', tty, policy, st, { start() {}, stop() {} })
  assert.ok(calls.indexOf('loud') < calls.indexOf('word'), `echo on before the word: ${calls.join(',')}`)
})

// =============================== TTY-less round 5 ===============================
test('R4-1: after `again`, echo is OFF again while the next passphrase may follow: run.ts order eth passphrase -> again -> slow decrypt -> sol passphrase typed EARLY is never shown', { timeout: 60_000 }, async () => {
  const two = ['job', 'run', 'x', '--backup-eth', join(T, 'vt-eth-key-1.age'), '--backup-sol', join(T, 'vt-sol-key-1.age')]
  const l = child('r41', `
await tty.passphrase('eth')
const w = await tty.word('Type again: ', 'again')
console.log('GOT-AGAIN ' + w)
await new Promise((r) => setTimeout(r, 1500))   // the trial decrypt of sol
const p = await tty.passphrase('sol')
console.log('SOL-LEN=' + p.length)
process.exit(0)`)
  const early = 'SYNTH-SOL-AHEAD'
  const r = await runInPty(brokerArgv(l, two), { env: env(), steps: [
    { waitFor: 'Passphrase: ', send: `${PASS}\r` },
    { waitFor: '> ', send: 'again\r' },
    { waitFor: 'GOT-AGAIN', send: `${early}\r` },
    { waitFor: 'type it now', send: `${PASS}\r` }] })
  assert.ok(!r.out.includes(early) && !r.out.includes('AHEAD'), `the early sol passphrase was shown: ${r.out}`)
  assert.match(r.out, /SOL-LEN=/)
})

const VTB = (): string => join(CLI, 'bin', 'vt')
function ewEnv(name: string): Record<string, string> {
  const home = join(T, `${name}-home`), outd = join(T, `${name}-out`)
  mkdirSync(join(home, 'local'), { recursive: true, mode: 0o700 }); mkdirSync(outd, { recursive: true, mode: 0o700 })
  return { ...env(), VT_HOME: home, VAULT_TIMELOCK_DIR: outd }   // no api.token: the command refuses before any connection
}
const BK = (): string => { const f = join(T, 'vt-eth-key-1.age'); writeFileSync(f, 'not a real backup', { mode: 0o600 }); return f }
const VT_RUN = (): string => `'${VTB()}' job run 0123456789abcdef --backup-eth '${BK()}'`

test('R4-2: after a passphrase command returns, the NEXT program\'s hidden prompt (read -s) is never echoed (x5), and nothing restores after bin/vt has returned', { timeout: 120_000 }, async () => {
  const loop = [1, 2, 3, 4, 5].map((i) => `${VT_RUN()} >/dev/null 2>&1; echo "R${i}"; IFS= read -r -s X${i}; echo "X${i}=[$X${i}]"`).join('; ')
  const steps = [1, 2, 3, 4, 5].map((i) => ({ waitFor: `R${i}\r`, send: `HIDDEN-SECRET-${i}\r` }))
  const r = await runInPty(['/bin/bash', '-c', loop], { env: ewEnv('r42a'), steps })
  for (let i = 1; i <= 5; i++) {
    assert.ok(!new RegExp(`HIDDEN-SECRET-${i}(?!\\])`).test(r.out.replace(new RegExp(`X${i}=\\[HIDDEN-SECRET-${i}\\]`), '')), `the hidden prompt ${i} was echoed: ${r.out}`)
    assert.match(r.out, new RegExp(`X${i}=\\[HIDDEN-SECRET-${i}\\]`), `the program read its input ${i}`)
  }
})

test('R4-2: two passphrase commands back to back: the second starts with echo off at once (type-ahead not shown) and saved the ORIGINAL settings, so echo is on at the end', { timeout: 120_000 }, async () => {
  const cmd = `${VT_RUN()} >/dev/null 2>&1; (sleep 0.4; echo MID) & ${VT_RUN()} >/dev/null 2>&1; wait; echo M2; stty -a | tr '\\n' ' '; echo`
  const r = await runInPty(['/bin/sh', '-c', cmd], { env: ewEnv('r42b'), steps: [{ waitFor: 'MID', send: 'SYNTH-AHEAD-TO-SECOND\r' }] })
  assert.ok(!r.out.includes('SYNTH-AHEAD'), `typed-ahead input was shown: ${r.out}`)
  tty_ok(r.out)
})

test('R4-2: an interactive bash and a `set -m` script end with echo restored; the exit status is propagated', { timeout: 120_000 }, async () => {
  for (const sh of [['/bin/bash', '-ic'], ['/bin/sh', '-c']] as const) {
    const body = sh[1] === '-ic' ? `${VT_RUN()} >/dev/null 2>&1; echo "RC=$?"; stty -a | tr '\\n' ' '; echo` : `set -m; ${VT_RUN()} >/dev/null 2>&1; echo "RC=$?"; stty -a | tr '\\n' ' '; echo`
    const r = await runInPty([sh[0], sh[1], body], { env: ewEnv(`r42c${sh[0].length}`), steps: [] })
    assert.match(r.out, /RC=1\b/, `the command's own exit status (vt: error: no readable API token) is propagated: ${sh.join(' ')}: ${r.out}`)
    tty_ok(r.out)
  }
})

test('R4-2: bin/vt runs the broker as a child and restores before returning (no post-exit helper in the tree)', () => {
  const text = readFileSync(VTB(), 'utf8')
  assert.ok(/exec_clean "\$@" <&8 8<&- &/.test(text) && /wait "\$BP"/.test(text) && /exit "\$rc"/.test(text))
  assert.ok(!/restoreAfterExit/.test(readFileSync(join(CLI, 'src', 'ops', 'ttyio.ts'), 'utf8')))
})

// =============================== TTY-less round 6 ===============================
const asker = (name: string): { l: string; mark: string } => {
  const mark = join(T, `${name}.asked`)
  const l = child(name, `
await new Promise((r) => setTimeout(r, 1200))
const p = await tty.passphrase('eth')
const fs = await import('node:fs')
fs.writeFileSync(${JSON.stringify(mark)}, 'ASKED ' + p.length)
process.exit(0)`)
  return { l, mark }
}
const qa = (a: string[]): string => a.map((x) => `'${x}'`).join(' ')
const exists = (f: string): boolean => spawnSync('/bin/test', ['-e', f]).status === 0

test('R5-1: bin/vt ignores Ctrl-Z / TTIN / TTOU and forwards an INT sent to its pid; the broker folds the keyboard\'s doubled INT', () => {
  const text = readFileSync(VTB(), 'utf8')
  assert.match(text, /trap '' INT TSTP TTIN TTOU/)
  assert.match(text, /trap 'kill -INT "\$BP" 2>\/dev\/null' INT/)
})

test('R5-1: Ctrl-Z (SIGTSTP) sent to the script that owns the broker before the prompt stops nothing: the prompt appears and the passphrase reaches the broker', { timeout: 60_000 }, async () => {
  const { l, mark } = asker('r51z')
  const sh = `exec 8<&0; trap '' INT TSTP TTIN TTOU; ${qa(brokerArgv(l, RUN_ARGS()))} <&8 8<&- & BP=$!; exec 8<&-; (sleep 0.5; kill -TSTP $$) & wait $BP; echo "RC=$?"`
  const r = await runInPty(['/bin/sh', '-c', sh], { env: env(), steps: [{ waitFor: 'type it now', send: `${PASS}\r` }] })
  assert.match(r.out, /RC=0/)
  assert.ok(exists(mark), `the passphrase was read by the broker: ${r.out}`)
  assert.ok(!r.out.includes(PASS))
})

test('R5-1: bin/vt killed (-9) before the prompt: the orphaned broker prints no prompt, reads nothing, stops the command and exits', { timeout: 60_000 }, async () => {
  const { l, mark } = asker('r51k')
  const inner = `exec 8<&0; ${qa(brokerArgv(l, RUN_ARGS()))} <&8 8<&- & echo "BK=$!"; sleep 0.4; kill -9 $$`
  const cmd = `/bin/sh -c "${inner.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\$/g, '\\$')}" 2>/dev/null; sleep 3; echo AFTER`
  const r = await runInPty(['/bin/sh', '-c', cmd], { env: env(), steps: [{ waitFor: 'AFTER', send: '' }] })
  assert.ok(!/passphrase of the key backup|type it now|Passphrase:/.test(r.out), `no prompt while the shell owns the terminal: ${r.out}`)
  assert.ok(!exists(mark), 'nothing was read')
  const pid = /BK=(\d+)/.exec(r.out)?.[1]
  assert.ok(pid !== undefined && spawnSync('/bin/kill', ['-0', pid]).status !== 0, `the orphaned broker has exited: ${r.out}`)
})

test('R5-1: a broker that is not the terminal\'s foreground job (the shell has it) prints no prompt and reads nothing', { timeout: 60_000 }, async () => {
  const { l, mark } = asker('r51f')
  const swap = `$SIG{TTOU}="IGNORE"; $p=fork; if(!$p){setpgrp(0,0);sleep 20;exit} select(undef,undef,undef,0.7); open(T,"+<","/dev/tty"); POSIX::tcsetpgrp(fileno(T),$p); sleep 3; POSIX::tcsetpgrp(fileno(T),getpgrp()); kill 9,$p`   // another job (not the broker's) takes the terminal at 0.7 s; the command asks at 1.2 s
  const sh = `exec 8<&0; ${qa(brokerArgv(l, RUN_ARGS()))} <&8 8<&- & BP=$!; exec 8<&-; /usr/bin/perl -MPOSIX -e '${swap}'; kill -9 $BP 2>/dev/null; echo AFTER`
  const r = await runInPty(['/bin/sh', '-c', sh], { env: env(), steps: [], timeoutMs: 40_000 })
  assert.ok(!/passphrase of the key backup|type it now|Passphrase:/.test(r.out), `no prompt: ${r.out}`)
  assert.ok(!exists(mark))
})

// =============================== Rehearsal follow-up (F-R-6) ===============================
// A signalled SIGINT (`kill -INT <pid>`) to a pty-wrapped `vt job run` must reach the sandboxed command exactly like the keyboard's Ctrl-C does. The real bin/vt and the real
// broker run; only sandbox-exec is faked (it execs a command that reports SIGINT), so no stack is needed.
for (const target of ['bin/vt', 'broker'] as const) {
  test(`F-R-6: kill -INT <pid of ${target}> on a pty-wrapped \`vt job run\` reaches the command once, like Ctrl-C (and the run ends)`, { timeout: 90_000 }, async () => {
    const dir = join(T, `fr6-${target.replace('/', '-')}`)
    const fw = fakeableWrapper(join(dir, 'w'))
    const fakes = join(dir, 'bin'); mkdirSync(fakes, { recursive: true })
    writeFileSync(join(fakes, 'sandbox-exec'), `#!/bin/sh
exec /bin/sh -c 'trap "echo GOT-SIGINT; exit 0" INT; echo CMD-READY; while :; do sleep 0.1; done'
`, { mode: 0o755 })
    const e = { ...ewEnv(`fr6${target.length}`), PATH: `${fakes}:${PATH0}` }
    const who = target === 'bin/vt' ? '$VT' : '$(/usr/bin/pgrep -P $VT | head -1)'
    const sh = `echo "VT=$$"; (while ! test -e ${JSON.stringify(join(dir, 'ready'))}; do sleep 0.1; done; VT=$$; kill -INT ${who}) & exec '${fw}' job run 0123456789abcdef --backup-eth '${BK()}'`
    // $$ inside the subshell is the shell's pid (bash/sh keep $$), which `exec` makes bin/vt's
    const r = await runInPty(['/bin/sh', '-c', sh], { env: e, steps: [{ waitFor: 'CMD-READY', send: '', then: () => { writeFileSync(join(dir, 'ready'), '') } }] })
    assert.equal(r.out.split('GOT-SIGINT').length - 1, 1, `the command got the INT once: ${r.out}`)
    tty_ok(r.out)
  })
}

test('F-R-6: bin/vt started with SIGINT ignored on entry (a background job of a non-interactive shell): kill -INT <broker pid> still reaches the command', { timeout: 90_000 }, async () => {
  const dir = join(T, 'fr6-bg')
  const fw = fakeableWrapper(join(dir, 'w'))
  const fakes = join(dir, 'bin'); mkdirSync(fakes, { recursive: true })
  writeFileSync(join(fakes, 'sandbox-exec'), `#!/bin/sh
exec /bin/sh -c 'trap "echo GOT-SIGINT; exit 0" INT; echo CMD-READY; while :; do sleep 0.1; done'
`, { mode: 0o755 })
  const e = { ...ewEnv('fr6bg'), PATH: `${fakes}:${PATH0}` }
  const sh = `'${fw}' job run 0123456789abcdef --backup-eth '${BK()}' & V=$!; while ! test -e ${JSON.stringify(join(dir, 'ready'))}; do sleep 0.1; done; kill -INT $(/usr/bin/pgrep -P $V | head -1); wait $V; echo RC=$?`
  const r = await runInPty(['/bin/sh', '-c', sh], { env: e, steps: [{ waitFor: 'CMD-READY', send: '', then: () => { writeFileSync(join(dir, 'ready'), '') } }] })
  assert.equal(r.out.split('GOT-SIGINT').length - 1, 1, `the command got the INT once: ${r.out}`)
})

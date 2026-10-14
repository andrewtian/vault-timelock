// cli/test/logs.test.ts — `vt logs` (src/ops/logs.ts; plan Task C3): through bin/vt (unsandboxed command) and
// in-process for -f. Synthetic log lines only (IPv6: the 2001:db8::/32 documentation prefix); no address, the canary
// included, may ever be printed (the redaction corpus below).
import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { appendFileSync, mkdirSync, renameSync, symlinkSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { MAX_LINE, LINE_HELD_BACK, assertNoAddress, assertNoControl, decodeLine, logs, parseLogsArgs, redactIps, renderLogLine, stripTerminal } from '../src/ops/logs.ts'
import { CANARY, PATH0, WRAPPER, removeDir, run, tempDir, throwsWith } from './lib.ts'
import type { Run } from './lib.ts'

let T = ''
const VTH = () => join(T, 'vt-home')
const logDir = (n = 'local') => join(VTH(), n, 'logs')
const vt = (args: string[]): Run => run(args, { env: { PATH: PATH0, HOME: join(T, 'home'), VT_HOME: VTH(), VAULT_TIMELOCK_DIR: join(T, 'out') } })
const lines = (from: number, to: number, tag = 'line') => Array.from({ length: to - from + 1 }, (_, i) => `${tag} ${from + i}\n`).join('')

before(() => { T = tempDir('vt-logs-') })
after(() => removeDir(T))
beforeEach(() => {
  removeDir(VTH())
  mkdirSync(logDir(), { recursive: true, mode: 0o700 })
})

test('vt logs <window>: the last 50 lines by default, -n N the last N, of $VT_HOME/<network>/logs/<window>.log', () => {
  writeFileSync(join(logDir(), 'relay.log'), lines(1, 60), { mode: 0o600 })
  let r = vt(['logs', 'relay'])
  assert.equal(r.code, 0, r.err)
  assert.equal(r.out, lines(11, 60))
  r = vt(['logs', 'relay', '-n', '3'])
  assert.equal(r.out, lines(58, 60))
  r = vt(['logs', 'relay', '-n', '500'])
  assert.equal(r.out, lines(1, 60))
  // Another network and another window.
  mkdirSync(logDir('testnet'), { recursive: true, mode: 0o700 })
  writeFileSync(join(logDir('testnet'), 'api.log'), 'vt-api ready network=testnet port=5192 build=dev\n', { mode: 0o600 })
  r = vt(['--network', 'testnet', 'logs', 'api'])
  assert.equal(r.out, 'vt-api ready network=testnet port=5192 build=dev\n')
  // A last line without its newline is shown too.
  writeFileSync(join(logDir(), 'page.log'), 'a\nb', { mode: 0o600 })
  assert.equal(vt(['logs', 'page']).out, 'a\nb\n')
})

// ---- redaction (security review: fails closed; src/ops/logs.ts header). Synthetic addresses only: the canary, the
//      TEST-NET-2 198.51.100.7, the 2001:db8::/32 documentation prefix, and loopback in its many spellings.

const show = (s: string): string => renderLogLine(Buffer.from(s, 'utf8'))
const ESC = '\u001b'
// Every one of these must come out with no address left: in a host context, every numeric form a resolver accepts.
const MUST_REDACT: ReadonlyArray<[string, string]> = [
  [`upstream ${CANARY} refused`, 'upstream [ip] refused'],
  [`to ${CANARY}:443 now`, 'to [ip] now'],
  ['proxy 127.0.0.1:9050 and 198.51.100.7', 'proxy [ip] and [ip]'],                 // loopback is redacted too
  [`trailing dot ${CANARY}. end`, 'trailing dot [ip] end'],
  [`five parts 1.${CANARY}`, 'five parts [ip]'],
  ['v6 2001:db8::77 full 2001:0db8:85a3:0000:0000:8a2e:0370:7334', 'v6 [ip] full [ip]'],
  ['loop ::1 [::1]:9050 0:0:0:0:0:0:0:1 any ::', 'loop [ip] [ip] [ip] any [ip]'],
  [`mapped ::ffff:${CANARY} ::ffff:${CANARY}:443 ::ffff:127.0.0.1 ::ffff:7f00:1`, 'mapped [ip] [ip] [ip] [ip]'],
  ['scoped fe80::1%en0 fe80::1%en0:443 fe80::1%25en0', 'scoped [ip] [ip] [ip]'],
  ['peer 2001:db8::1: closed; addr:2001:db8::9; upper 2001:DB8::A', 'peer [ip] closed; addr:[ip]; upper [ip]'],
  ['encoded 2001%3Adb8%3A%3A1', 'encoded [ip]'],
  ['wide ２０３．０．１１３．７７ ideographic 203。0。113。77', 'wide [ip] ideographic [ip]'],
  ['mark 203.0.113.7\u03017 inside 198.51.1\u03010.7', 'mark [ip] inside [ip]'],
  [`colons ${'abcde:'.repeat(70)}end`, 'colons [ip]nd'],                             // > 64 colon groups: fails closed
  ['obfuscated 0x7f.0.0.1 zeros 203.000.113.077', 'obfuscated [ip] zeros [ip]'],
  [`swallowed 50%${CANARY} encoded ${'%32%30%33'}.0.113.77 glued x%20${CANARY} and 20${CANARY}`, 'swallowed [ip] encoded [ip] glued x[ip] and [ip]'],
  ['raw view only 2001:db8::%5a1, decoded view only 203.0.11%33.77', 'raw view only [ip], decoded view only [ip]'],
  ['math 𝟚𝟘𝟛.𝟘.𝟙𝟙𝟛.𝟟𝟟 superscript ²⁰³.⁰.¹¹³.⁷⁷', 'math [ip] superscript [ip]'],
  ['wide v6 ２００１：ｄｂ８：：１ arabic-indic ٢٠٣.٠.١١٣.٧٧ devanagari २०३.०.११३.७७', 'wide v6 [ip] arabic-indic [ip] devanagari [ip]'],
  // host contexts: ://, @, Host:, host= (also quoted, any case)
  ['http://0x7f.1/ http://0177.0.0.1:80/ http://127.1/ http://2130706433/x', 'http://[ip]/ http://[ip]:80/ http://[ip]/ http://[ip]/x'],
  ['http://127.0.0.1./ http://[::ffff:7f00:1]:5181/ http://[2001:db8::1%25en0]/', 'http://[ip]/ http://[ip]:5181/ http://[ip]/'],
  [`http://${'%31%32%37'}.0.0.1/ http://１２７．０．０．１/`, 'http://[ip]/ http://[ip]/'],
  ['http://user:pw@0x7f.1:80/x user@2130706433', 'http://user:pw@[ip]:80/x user@[ip]'],
  ['Host: 2130706433 HOST:0x7f000001 host=127.1 "host":"0177.1" host=2001:db8::1', 'Host: [ip] HOST:[ip] host=[ip] "host":"[ip]" host=[ip]'],
  [`url http://${CANARY}.nip.io/ok`, 'url http://[ip]/ok'],
  // Cfix4 (C4 review m1): special-scheme spellings without `://`, scheme-relative //h, and the key names
  ['u http:\\\\2130706433/x http:/0x7f.1/ https:2130706433 ftp:\\0177.1 ws:/127.1:80', 'u http:\\\\[ip]/x http:/[ip]/ https:[ip] ftp:\\[ip] ws:/[ip]:80'],
  ['rel //2130706433/p and //0x7f.1:80', 'rel //[ip]/p and //[ip]:80'],
  ['hostname=2130706433 address:0x7f000001 ip=127.1 peer: 0177.1 remoteAddress="2130706433" remote_addr=127.1 Addr=2001:db8::1', 'hostname=[ip] address:[ip] ip=[ip] peer: [ip] remoteAddress="[ip]" remote_addr=[ip] Addr=[ip]'],
  // controls cannot split an address that the terminal would still show whole
  [`zw 203.0.113\u200b.77 csi 203.0.1${ESC}[1C13.77 bs 203.0.11\b3.77 nul 203.0.\u00001.2`, 'zw [ip] csi [ip] bs [ip] nul [ip]'],
]
// Every one of these must come out unchanged: outside host contexts plain numbers, ports, times and hashes survive.
const MUST_SURVIVE: readonly string[] = [
  `eth tx 0x${'ab'.repeat(32)} landed`,
  `bare ${'0123456789abcdef'.repeat(4)}`,
  `outpoint ${'cd'.repeat(32)}:1`,
  `sha256:${'ef'.repeat(32)}`,
  `sol sig 5${'Kx9'.repeat(29)}`,
  'amounts 2130706433 lamports, 127.1 SOL, 0.000005 ETH, 1.5',
  'ports :5181 5182 port=5190',
  'at 2026-10-09T12:34:56.789Z (12:34:56) took 1.25 s',
  'mac aa:bb:cc:dd:ee:ff',
  'eth:ok sol:ok fee:1:2:3',
  'vite 8.3.3 ready, version v1.2.3, 50% done',
  'vt-api ready network=local port=5182 build=dev',
  'listening on loopback :5181 build 0123456789ab (eth on, sol on)',
  'http://localhost:5181/x https://rpc.example.org/v1?x=1 user@example.org',
  'tab\tseparated',
]

test('redaction: every IP encoding is printed as [ip] (strict outside host contexts, any resolver form inside them)', () => {
  for (const [line, want] of MUST_REDACT) assert.equal(show(line), want, line)
  // Through bin/vt, the same corpus in one log: nothing of any address is printed.
  writeFileSync(join(logDir(), 'relay.log'), MUST_REDACT.map(([l]) => `${l}\n`).join(''), { mode: 0o600 })
  const r = vt(['logs', 'relay'])
  assert.equal(r.code, 0, r.err)
  assert.equal(r.out, MUST_REDACT.map(([, w]) => `${w}\n`).join(''))
  for (const leak of [CANARY, '198.51', '127.0', 'db8', 'ｄｂ８', '8a2e', 'fe80', 'ffff', '7f00', '0x7f', '2130706433', '0177', '２０３', '٢٠٣', '२०३', '%32']) assert.ok(!r.out.includes(leak), leak)
  assert.ok(!r.out.includes(ESC) && !r.out.includes('\b') && !r.out.includes('\u200b'))
})

test('redaction: txids, outpoints, digests, signatures, amounts, ports, times, versions and host names survive unchanged', () => {
  for (const line of MUST_SURVIVE) {
    assert.equal(show(line), line, line)
    assert.equal(redactIps(line), line, line)
  }
  writeFileSync(join(logDir(), 'api.log'), MUST_SURVIVE.map((l) => `${l}\n`).join(''), { mode: 0o600 })
  const r = vt(['logs', 'api'])
  assert.equal(r.code, 0, r.err)
  assert.equal(r.out, MUST_SURVIVE.map((l) => `${l}\n`).join(''))
})

test('terminal control sequences and characters are removed before matching and never printed', () => {
  assert.equal(show(`${ESC}[31mred${ESC}[0m ${ESC}]0;a title${ESC}\\ ${ESC}]8;;http://x/\u0007link${ESC}]8;;\u0007 ${ESC}c${ESC}P1;2q data${ESC}\\ done`), 'red  link  done')
  assert.equal(show('over\rwrite back\b\b space\u007f del \u009b31m c1'), 'overwrite back space del  c1')
  assert.equal(show('bidi \u202e77.311.0.302\u202c zero\u200bwidth\ufeff soft\u00adhyphen line\u2028sep'), 'bidi 77.311.0.302 zerowidth softhyphen linesep')
  assert.equal(stripTerminal(`a${ESC}[`), 'a', 'an unterminated sequence is removed too')
  assert.equal(show('keep\ttabs'), 'keep\ttabs')
})

test('a line that is not valid UTF-8 is printed escaped (\\xNN), never raw; its addresses are redacted', () => {
  const line = Buffer.concat([Buffer.from('a'), Buffer.from([0xff]), Buffer.from(`b ${CANARY.slice(0, 9)}`), Buffer.from([0xc0]), Buffer.from(`${CANARY.slice(9)} c`),
    Buffer.from([0xe2, 0x82]), Buffer.from(' é')])
  assert.equal(renderLogLine(line), 'a\\xffb [ip] c\\xe2\\x82 é')
  assert.equal(decodeLine(Buffer.from([0xed, 0xa0, 0x80])), '\udced\udca0\udc80', 'an encoded surrogate is not valid UTF-8')
  writeFileSync(join(logDir(), 'page.log'), Buffer.concat([line, Buffer.from('\n')]), { mode: 0o600 })
  const r = spawnSync(WRAPPER, ['logs', 'page'], { env: { PATH: PATH0, HOME: join(T, 'home'), VT_HOME: VTH(), VAULT_TIMELOCK_DIR: join(T, 'out') } })
  assert.equal(r.status, 0, String(r.stderr))
  assert.deepEqual(r.stdout, Buffer.from('a\\xffb [ip] c\\xe2\\x82 é\n', 'utf8'), 'the raw bytes never reach stdout')
})

test('C4 review I-1: a rendered \\xNN can never complete an address; redaction and the checks see the printed text', () => {
  const line = (...parts: Array<string | number[]>): Buffer => Buffer.concat(parts.map((p) => (typeof p === 'string' ? Buffer.from(p, 'utf8') : Buffer.from(p))))
  const quad = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
  const v6 = /(?:^|[^0-9a-f:])[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){7}(?![0-9a-f:])/i
  // The reviewer's constructions: every high byte before three dotted octets (0x80-0x99 render as two decimal digits)
  // and before seven colon groups; the rendered text holds no address, with or without its escape prefix.
  for (let b = 0x80; b <= 0xff; b++) {
    for (const tail of ['.1.2.3', '.0.113.77', ':1:2:3:4:5:6:7', '::1']) {
      const out = renderLogLine(line('peer ', [b], tail, ' closed'))
      assert.ok(!quad.test(out) && !v6.test(out) && !quad.test(out.replace(/\\x/g, '')), `${b.toString(16)}${tail}: ${out}`)
      assertNoAddress(out)
    }
  }
  assert.equal(renderLogLine(line([0x99], '.1.2.3')), '\\x[ip]')
  assert.equal(renderLogLine(line([0xab], ':1:2:3:4:5:6:7')), '\\x[ip]')
  // Escapes at both ends and in the middle: an address split by an undecodable byte is found on the decoded text
  // (the byte is transparent there); a fragment the escapes leave is not an address and stays.
  assert.equal(renderLogLine(line('1.2', [0x99], '.3.4')), '[ip]')
  assert.equal(renderLogLine(line('1:2:3:', [0x99], ':5:6:7:8')), '[ip]')
  assert.equal(renderLogLine(line([0x99], '.1.2.', [0x88])), '\\x99.1.2.\\x88')
  assert.equal(renderLogLine(line([0x81, 0x82], '.3.4.5')), '\\x81\\x[ip]')
  assert.equal(renderLogLine(line([0x90], '.1.2.3', [0x91], ':1:2:3:4:5:6:7')), '\\x[ip]\\x[ip]')
  // Txids, amounts and signatures beside undecodable bytes stay intact.
  const tx = `0x${'ab'.repeat(32)}`
  const sig = `5${'Kx9'.repeat(29)}`
  assert.equal(renderLogLine(line('tx ', tx, [0x99], ' 1.5 SOL ', [0xc0], sig)), `tx ${tx}\\x99 1.5 SOL \\xc0${sig}`)
  // End to end through bin/vt logs: byte-exact stdout.
  writeFileSync(join(logDir(), 'relay.log'), Buffer.concat([line([0x99], '.1.2.3\n'), line('peer ', [0xab], ':1:2:3:4:5:6:7 up\n'), line('tx ', tx, [0x99], ' 1.5 SOL\n')]), { mode: 0o600 })
  const r = spawnSync(WRAPPER, ['logs', 'relay'], { env: { PATH: PATH0, HOME: join(T, 'home'), VT_HOME: VTH(), VAULT_TIMELOCK_DIR: join(T, 'out') } })
  assert.equal(r.status, 0, String(r.stderr))
  assert.deepEqual(r.stdout, Buffer.from(`\\x[ip]\npeer \\x[ip] up\ntx ${tx}\\x99 1.5 SOL\n`, 'utf8'))
})

test('C4 review m2: default-ignorable and unassigned characters are removed too, so they cannot split an address', () => {
  for (const c of ['\u115f', '\u1160', '\u3164', '\uffa0', '\u2065', '\u{e0080}', '\u034f', '\ufe0f', '\u{50000}']) {
    assert.equal(show(`a 203.0.113${c}.77 b`), 'a [ip] b', `U+${c.codePointAt(0)?.toString(16)}`)
    throwsWith(() => assertNoControl(`x${c}y`), 'vt.log-control')
  }
})

test('vt.log-control / vt.log-ip: the independent check on the printed text; a line that fails it is withheld, never printed', () => {
  for (const bad of [`${ESC}[2J`, 'a\rb', 'x\u202ey', 'z\u200bw', '\u0000', '\u009b', 'p\u2029q']) throwsWith(() => assertNoControl(bad), 'vt.log-control')
  for (const bad of [CANARY, `x ${CANARY}:443`, '::1', 'fe80::1%en0', 'http://0x7f.1/', 'u@2130706433', 'http://[::ffff:7f00:1]/', '２０３．０．１１３．７７',
    'http:\\\\2130706433/', 'http:/0x7f.1', 'https:2130706433', '//2130706433/x', 'hostname=2130706433', 'address:0x7f000001', 'ip=127.1', 'remoteAddress=2130706433']) {
    throwsWith(() => assertNoAddress(bad), 'vt.log-ip')
  }
  for (const good of [...MUST_SURVIVE, ...MUST_REDACT.map(([, w]) => w), 'keep\ttabs']) {
    assertNoControl(good)
    assertNoAddress(good)
  }
  // Wired into every printed line: a redactor that misses an address, or leaves a control character, gets the line
  // withheld.
  assert.equal(renderLogLine(Buffer.from(`up ${CANARY}`), (s) => s), LINE_HELD_BACK)
  assert.equal(renderLogLine(Buffer.from('http://0x7f.1/'), (s) => s), LINE_HELD_BACK)
  for (const l of ['https:2130706433', 'hostname=2130706433', '//0x7f.1/']) assert.equal(renderLogLine(Buffer.from(l), (s) => s), LINE_HELD_BACK, l)
  assert.equal(renderLogLine(Buffer.from('fine'), (s) => `${s}${ESC}[2J`), LINE_HELD_BACK)
  assert.equal(renderLogLine(Buffer.from('fine'), (s) => s), 'fine')
})

test('bounded work: a 64 KiB line of host markers renders in well under 10 s', () => {
  const line = Buffer.from('.host=x'.repeat(Math.floor(MAX_LINE / 7)))
  const t0 = Date.now()
  renderLogLine(line)
  assert.ok(Date.now() - t0 < 10_000, `took ${Date.now() - t0} ms`)
})

test('a line longer than 64 KiB is withheld whole (bounded work), with its length only', () => {
  const long = Buffer.from(`${'a'.repeat(MAX_LINE)} ${CANARY}`)
  assert.equal(renderLogLine(long), `[vt logs: line withheld: ${long.length} bytes, longer than ${MAX_LINE}]`)
  assert.equal(renderLogLine(Buffer.from('b'.repeat(MAX_LINE))), 'b'.repeat(MAX_LINE))
})

test('no log, a symlinked log or a FIFO: exit 1 "no log yet" (never followed, never blocks)', () => {
  let r = vt(['logs', 'api'])
  assert.equal(r.code, 1)
  assert.equal(r.err, 'vt logs: no api log for local yet (vt up --network local)\n')
  writeFileSync(join(T, 'elsewhere.log'), `secret-ish ${CANARY}\n`)
  symlinkSync(join(T, 'elsewhere.log'), join(logDir(), 'api.log'))
  r = vt(['logs', 'api'])
  assert.equal(r.code, 1)
  assert.equal(r.out, '')
  assert.equal(spawnSync('/usr/bin/mkfifo', [join(logDir(), 'page.log')]).status, 0)
  r = vt(['logs', 'page'])
  assert.equal(r.code, 1)
  assert.equal(r.out, '')
})

test('arguments: relay|api|page|vite, then -n N (1..99999) and -f, each once; anything else is a usage error', () => {
  assert.deepEqual(parseLogsArgs(['vite']), { name: 'vite', lines: 50, follow: false })
  assert.deepEqual(parseLogsArgs(['api', '-f', '-n', '7']), { name: 'api', lines: 7, follow: true })
  for (const args of [[], ['all'], ['relay', '-n'], ['relay', '-n', '0'], ['relay', '-n', '-3'], ['relay', '-n', '1e3'], ['relay', '-f', '-f'],
    ['relay', '-n', '1', '-n', '2'], ['relay', '--follow'], [`/tmp/${CANARY}`]]) {
    const r = vt(['logs', ...args])
    assert.equal(r.code, 1, args.join(' '))
    assert.equal(r.err, 'vt: usage: vt logs relay|api|page|vite [--network local|testnet|mainnet] [-n N] [-f]\n')
  }
})

test('-f: prints new complete lines as they come (redacted), and starts over when vt up rotates the log', async () => {
  const log = join(logDir(), 'relay.log')
  writeFileSync(log, lines(1, 3), { mode: 0o600 })
  let out = ''
  let tick = 0
  const steps: Array<() => void> = [
    () => appendFileSync(log, 'line 4\npartial'),
    () => appendFileSync(log, ` end ${CANARY} 2001:db8::9\n`),
    () => { renameSync(log, `${log}.1`); writeFileSync(log, 'fresh 1\n', { mode: 0o600 }) },
    () => appendFileSync(log, 'fresh 2\n'),
  ]
  const code = await logs({ network: 'local', env: { HOME: join(T, 'home'), VT_HOME: VTH() }, name: 'relay', lines: 2, follow: true }, {
    out: (t) => { out += t },
    sleep: async () => { steps[tick]?.(); tick++ },
    pollMs: 0,
    stop: () => tick >= steps.length + 1,
  })
  assert.equal(code, 0)
  assert.equal(out, 'line 2\nline 3\nline 4\npartial end [ip] [ip]\n--- relay log restarted ---\nfresh 1\nfresh 2\n')
})

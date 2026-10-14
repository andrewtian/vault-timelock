// cli/test/ticket-key-real.test.ts — PF-C M-3a + follow-up: what a sandboxed vt command (executor or client) cannot read, for real.
// DUMMY files in a temp VT_HOME / VAULT_TIMELOCK_DIR (never a real key or credential), probed under the real sandbox-exec:
//   · EPERM on every network's relay-ticket.key and on $OUT/local/btc-rpc.auth; EPERM on the api.token of every network the command does
//     not talk to; its own network's api.token and a backup file stay readable;
//   · hard-link bypass (b): link(), symlink() and rename() of the key onto a new name all fail (EPERM: no file-write* anywhere but
//     /dev/null and /dev/tty), so no second name exists to read it through, and reading the key itself stays EPERM;
//   · a missing home/out refuses (fail closed, a): see test/sandbox.test.ts.
// Own sandbox (list: test/own-sandbox.list).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, realpathSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { tmpdir, userInfo } from 'node:os'
import { NETWORKS } from '@vault-timelock/core/contracts'
import { BTC_AUTH, TICKET_KEY, commandProfile, denyProtectedFiles, handedFiles, loopbackProfile } from '../src/ops/sandbox.ts'
import { readAllowList } from '../src/ops/sandbox.ts'
import { scopeFor } from '../src/ops/scope.ts'
import { CLI, NODE, PATH0, removeDir, tempDir, throwsWith } from './lib.ts'

const SC = (argv: string[], home = '/u/me') => ({ ...scopeFor(argv, { HOME: tmpdir(), PATH: process.env.PATH }), userHome: home })

test('handedFiles: --backup-<chain>, --message-file and the job file of create|validate, nothing else', () => {
  assert.deepEqual(handedFiles(['job', 'run', 'x', '--backup-eth', 'a.age', '--backup-sol', 'b.age', '--chain', 'eth']), ['a.age', 'b.age'])
  assert.deepEqual(handedFiles(['job', 'create', 'j.json', '--message-file', 'm.txt', '--yes-publish-file', 'abc', '--normalize']), ['j.json', 'm.txt'])
  assert.deepEqual(handedFiles(['job', 'validate', '--message-file', 'm.txt', 'j.json']), ['m.txt', 'j.json'])
  assert.deepEqual(handedFiles(['job', 'clawback', 'x', '--chain', 'eth', '--to', '0xabc', '--backup-eth', 'k.age']), ['k.age'])
  assert.deepEqual(handedFiles(['job', 'status', 'x', '--watch']), [])
  assert.deepEqual(handedFiles(['status']), [])
})

test('commandProfile: allow-list for reads, then the explicit denies (belt and braces, last), including the DEFAULT locations; built from the profile text only', () => {
  const sc = { tree: ['/r/repo/cli/src'], treeFiles: ['/r/repo/package.json'], node: ['/n/bin/node', '/n/lib/libx.dylib'], launcher: '/r/repo/cli/bin/vt', stdio: [] as string[], userHome: '/u/me', handed: ['/b/backup.age'] }
  const p = commandProfile(['job', 'run', 'x'], 'mainnet', '/h/vt', '/o/out', sc) as string
  const i = p.indexOf('(allow file-read* ')
  assert.ok(i > 0, 'a default-deny with an allow-list')
  const allow = p.slice(i, p.indexOf('(deny file-read* (literal'))
  for (const need of ['(subpath "/usr/lib")', '(subpath "/usr/share")', '(literal "/bin/sh")', '(literal "/usr/bin/env")', '(literal "/r/repo/cli/bin/vt")', '(subpath "/System")', '(subpath "/r/repo/cli/src")', '(literal "/r/repo/package.json")', '(literal "/n/bin/node")', '(literal "/n/lib/libx.dylib")', '(literal "/b/backup.age")', '(literal "/h/vt/mainnet/api.token")',
    '(literal "/dev/null")', '(literal "/")']) assert.ok(allow.includes(need), need)
  for (const never of ['"/u/me"', '/u/me/', '"/Users"', '"/private"', '/h/vt/local', '/h/vt/testnet', '/o/out', 'relay-ticket.key', '(subpath "/r/repo")', '"/c', '"/n/bin")', '"/n")']) assert.ok(!allow.includes(never), `not allowed: ${never}`)
  const denies = p.slice(p.indexOf('(deny file-read* (literal'))
  assert.ok(denies.length > 0 && p.endsWith(denies), 'the denies come last')
  for (const n of ['local', 'testnet', 'mainnet']) {
    assert.ok(denies.includes(`(deny file-read* (literal "/h/vt/${n}/relay-ticket.key"))`), `current ${n} key`)
    assert.ok(denies.includes(`(deny file-read* (literal "/u/me/.local/state/vt/${n}/relay-ticket.key"))`), `DEFAULT ${n} key`)
  }
  assert.ok(denies.includes('(deny file-read* (subpath "/u/me/.local/share/vault-timelock"))'), 'the whole default $OUT')
  assert.ok(denies.includes('(deny file-read* (literal "/o/out/local/btc-rpc.auth"))'))
})

test('commandProfile denies the ticket keys, the bitcoind credential and the other networks\' tokens; the old shape (loopbackProfile alone) did not', () => {
  const p = commandProfile(['job', 'run', 'x'], 'mainnet', '/h/vt', '/o/out', SC(['job', 'run', 'x'])) as string
  assert.ok(p.includes(denyProtectedFiles('/h/vt', '/o/out', ['mainnet'], SC(['job', 'run', 'x']).userHomes ?? '/u/me')), 'appended after the allow-list, so it overrides it')
  assert.ok(p.includes(`/o/out/local/${BTC_AUTH}`))
  assert.ok(!p.includes('(deny file-read* (literal "/h/vt/mainnet/api.token"))'), 'the executor needs its own network\'s token')
})

test('under the real sandbox-exec: EPERM on keys/credential/other tokens; link(), symlink(), rename() onto a new name fail; own token and backups readable', () => {
  const T = tempDir('vt-tk-')
  try {
    const home = realpathSync(T) + '/home'
    const out = realpathSync(T) + '/out'
    mkdirSync(home); mkdirSync(join(out, 'local'), { recursive: true })
    for (const n of NETWORKS) {
      mkdirSync(join(home, n), { recursive: true })
      writeFileSync(join(home, n, TICKET_KEY), 'dummy-not-a-key')
      writeFileSync(join(home, n, 'api.token'), 'dummy-token')
    }
    writeFileSync(join(out, 'local', BTC_AUTH), 'vt:dummy-not-a-credential-0000')
    mkdirSync(join(home, 'backups'))
    writeFileSync(join(home, 'backups', 'b.age'), 'dummy-backup')
    writeFileSync(join(home, 'backups', 'c.age'), 'dummy-other-backup')   // NOT handed
    writeFileSync(join(home, 'notes.txt'), 'dummy-file-in-the-home-outside-the-allow-list')
    mkdirSync(join(realpathSync(T), 'elsewhere')); writeFileSync(join(realpathSync(T), 'elsewhere', 'x.txt'), 'dummy')
    const js = `const fs=require('node:fs');(async()=>{const [op,a,b]=process.argv.slice(1);
      try{ if(op==='read'){fs.readFileSync(a);console.log('READ')} else if(op==='exec'){const r=require('node:child_process').spawnSync(a,b?[b]:[]);console.log(r.error?r.error.code:'RAN')} else if(op==='addon'){const r=require('node:child_process').spawnSync(process.execPath,['-e','try{process.dlopen({exports:{}},'+JSON.stringify(a)+');console.log("LOADED")}catch(e){console.log("ERR "+(e.code||e.message.slice(0,60)))}'],{encoding:'utf8'});console.log(r.error?'EXEC-'+r.error.code:r.stdout.trim()+(r.stderr?' STDERR '+r.stderr.trim().split('\\n')[0].slice(0,80):''))} else if(op==='clone'){fs.copyFileSync(a,b,fs.constants.COPYFILE_FICLONE_FORCE);console.log('DONE')} else if(op==='copy'){fs.copyFileSync(a,b);console.log('DONE')} else if(op==='strict'){const {assertConfined}=await import(a);try{await assertConfined({strict:true});console.log('CONFINED')}catch(e){console.log('REFUSED '+e.message)}} else if(op==='list'){fs.readdirSync(a);console.log('LISTED')} else if(op==='link'){fs.linkSync(a,b);console.log('DONE')} else if(op==='symlink'){fs.symlinkSync(a,b);console.log('DONE')} else if(op==='rename'){fs.renameSync(a,b);console.log('DONE')} }catch(e){console.log(e.code)}})()`
    const probe = (profile: string, op: string, a: string, b = ''): string => {
      const r = spawnSync('/usr/bin/sandbox-exec', ['-p', profile, NODE, '-e', js, op, a, b], { env: { PATH: PATH0, HOME: home }, encoding: 'utf8', timeout: 30_000 })
      assert.equal(r.status, 0, r.stderr)
      return r.stdout.trim()
    }
    for (const argv of [['job', 'run', 'x'], ['job', 'clawback', 'x'], ['status'], ['job', 'arm', 'x']]) {
      for (const net of NETWORKS) {
        const profile = commandProfile(argv, argv[0] === 'status' ? undefined : net, home, out, { ...scopeFor(argv, { HOME: T, PATH: process.env.PATH }), handed: [join(home, 'backups', 'b.age')] }) as string
        const mine = argv[0] === 'status' ? [...NETWORKS] : [net]
        for (const n of NETWORKS) assert.equal(probe(profile, 'read', join(home, n, TICKET_KEY)), 'EPERM', `${argv.join(' ')} ${net}: key of ${n}`)
        assert.equal(probe(profile, 'read', join(out, 'local', BTC_AUTH)), 'EPERM', 'the bitcoind credential')
        for (const n of NETWORKS) assert.equal(probe(profile, 'read', join(home, n, 'api.token')), mine.includes(n) ? 'READ' : 'EPERM', `${argv.join(' ')} ${net}: token of ${n}`)
        assert.equal(probe(profile, 'read', join(home, 'backups', 'b.age')), 'READ', 'a handed file')
        // PF-C follow-up 2: the allow-list — anything not named is unreadable, a handed file's siblings included; node itself runs fine
        assert.equal(probe(profile, 'read', join(home, 'backups', 'c.age')), 'EPERM', 'a sibling of a handed file')
        assert.equal(probe(profile, 'read', join(home, 'notes.txt')), 'EPERM', 'a file in the home outside the allow-list')
        assert.equal(probe(profile, 'read', join(realpathSync(T), 'elsewhere', 'x.txt')), 'EPERM')
        assert.equal(probe(profile, 'read', '/etc/hosts'), 'EPERM', 'system files outside the measured set')
        // follow-up 3: no directory listing above or around anything allowed (the home, its parent, the backups dir, the temp dir, /Users)
        for (const d of [home, join(home, '..'), join(home, 'backups'), join(home, net), realpathSync(T), '/Users', '/private/tmp']) assert.equal(probe(profile, 'list', d), 'EPERM', `no listing of ${d.replace(realpathSync(T), '<tmp>')}`)
        // (b) no second name for the key, in its own directory, in the home, or in /tmp
        const key = join(home, net, TICKET_KEY)
        for (const dest of [join(home, net, 'copy'), join(home, 'copy'), join(realpathSync(T), 'copy')]) {
          for (const op of ['link', 'symlink', 'rename']) {
            assert.equal(probe(profile, op, key, dest), 'EPERM', `${op} ${argv.join(' ')} ${net}`)
            assert.ok(!existsSync(dest), `no new name appeared (${op})`)
          }
        }
        assert.ok(existsSync(key), 'rename did not move the key')
      }
    }
    // regression (acceptance run): a VT_HOME GIVEN as /tmp/... (macOS: a link to /private/tmp) is opened through the link; the profile names the real
    // path, so stat-ing the link must be allowed. The token is read through the lexical path.
    const lexRoot = mkdtempSync('/tmp/vt-tk-lex-')           // lexically /tmp/..., really /private/tmp/...
    try {
      const rh = realpathSync(lexRoot) + '/home', ro = realpathSync(lexRoot) + '/out', lex = lexRoot + '/home'
      mkdirSync(rh + '/local', { recursive: true }); mkdirSync(rh + '/backups'); mkdirSync(ro + '/local', { recursive: true })
      writeFileSync(rh + '/local/api.token', 'dummy'); writeFileSync(rh + '/local/' + TICKET_KEY, 'dummy'); writeFileSync(rh + '/backups/b.age', 'dummy')
      const sc = (argv: string[], handed: string[] = []) => ({ ...scopeFor(argv, { HOME: T, PATH: process.env.PATH }), handed })
      assert.equal(probe(commandProfile(['status'], 'local', rh, ro, sc(['status'])) as string, 'read', lex + '/local/api.token'), 'READ', 'api.token through /tmp/...')
      assert.equal(probe(commandProfile(['job', 'run', 'x'], 'local', rh, ro, sc(['job', 'run', 'x'], [rh + '/backups/b.age'])) as string, 'read', lex + '/backups/b.age'), 'READ', 'a handed backup through /tmp/...')
      assert.equal(probe(commandProfile(['status'], 'local', rh, ro, sc(['status'])) as string, 'read', lex + '/local/' + TICKET_KEY), 'EPERM')
    } finally { removeDir(lexRoot) }
    // I-2: nothing but the launcher chain can be exec'd: helpers that talk to system brokers (defaults -> cfprefsd, pbpaste -> pasteboard, open -> LaunchServices,
    // osascript -> Apple Events) and plain /usr/bin/true all fail EPERM. Only harmless arguments, nothing is launched or written even if they ran.
    const hard = commandProfile(['job', 'run', 'x'], 'local', home, out, { ...scopeFor(['job', 'run', 'x'], { HOME: T, PATH: process.env.PATH }) }) as string
    const net0 = 'local'
    for (const [bin, arg] of [['/usr/bin/true', ''], ['/usr/bin/defaults', 'domains'], ['/usr/bin/pbpaste', ''], ['/usr/bin/open', '-R'], ['/usr/bin/osascript', '-l'], ['/bin/ls', '/'], ['/usr/bin/id', '']]) {
      assert.equal(probe(hard, 'exec', bin, arg), 'EPERM', `${bin} cannot be exec'd`)
    }
    assert.equal(probe('(version 1)(allow default)', 'exec', '/usr/bin/true'), 'RAN', 'positive control: unsandboxed it runs')
    // I-2 (fix round): a SECOND node, started without --no-addons by the sandboxed process, still cannot map native code: (deny file-map-executable) except system libs, the shell chain and node + its dylibs
    const addon = join(dirname(CLI), 'node_modules', '.store', readdirSync(join(dirname(CLI), 'node_modules', '.store')).find((d) => d.startsWith('lightningcss-darwin-arm64')) ?? 'missing', 'node_modules', 'lightningcss-darwin-arm64', 'lightningcss.darwin-arm64.node')
    if (existsSync(addon)) {
      const am = probe(hard, 'addon', addon)
      assert.ok(!/LOADED/.test(am), `a grandchild node loaded a native addon under the profile: ${am}`)
      assert.match(am, /ERR|EPERM|STDERR|Operation not permitted/i, am)
      assert.equal(probe('(version 1)(allow default)', 'addon', addon), 'LOADED', 'control: without the map deny the same grandchild loads the addon')
    }
    // M-2: clonefile / copyfile of a protected file to a new name needs a create the profile denies
    for (const [op, dest] of [['clone', join(home, net0, 'clone-copy')], ['copy', join(home, net0, 'plain-copy')], ['clone', join(realpathSync(T), 'clone-tmp')]] as const) {
      assert.equal(probe(hard, op, join(home, net0, TICKET_KEY), dest), 'EPERM', `${op} of the ticket key to a new name`)
      assert.ok(!existsSync(dest))
    }
    assert.equal(probe('(version 1)(allow default)', 'copy', join(home, net0, TICKET_KEY), join(home, net0, 'plain-copy')), 'DONE', 'control: unsandboxed copy works')
    rmSync(join(home, net0, 'plain-copy'), { force: true })
    // M-2: the mach-lookup deny itself bites. pbpaste (a pasteboard client, output discarded) is allowed to EXEC here and only the lookup differs: exit 0 without the
    // deny, nonzero with it. (appleevent-send cannot be exercised harmlessly: osascript evaluates locally without sending anything, so it stays pinned by profile text.)
    const pb = (profile: string): number | null => spawnSync('/usr/bin/sandbox-exec', ['-p', profile, '/usr/bin/pbpaste', '-pboard', 'ruler'], { stdio: 'ignore', env: { PATH: PATH0, HOME: home }, timeout: 20_000 }).status
    assert.equal(pb('(version 1)(allow default)'), 0, 'control: pbpaste works with default allow')
    assert.notEqual(pb('(version 1)(allow default)(deny mach-lookup)'), 0, 'with (deny mach-lookup) the pasteboard is unreachable')
    assert.notEqual(pb(`(version 1)(allow default)${hard.slice(hard.indexOf('(deny mach-lookup)'), hard.indexOf('(deny mach-lookup)') + '(deny mach-lookup)'.length)}(allow process-exec* (literal "/usr/bin/pbpaste"))`), 0)
    // M-1: the strict start-up proof under the REAL profile, and under a profile that only denies network and writes
    const strictScope = { ...scopeFor(['status'], { HOME: T, PATH: process.env.PATH }) }
    const confinePath = join(CLI, 'src', 'ops', 'confine.ts')
    const full = commandProfile(['status'], 'local', home, out, strictScope) as string
    assert.equal(probe(full, 'strict', confinePath), 'CONFINED', 'the full profile passes the strict proof')
    const weak = `(version 1)(allow default)(deny network-outbound)(deny file-write*)(allow file-write* (literal "/dev/null"))`
    assert.match(probe(weak, 'strict', confinePath), /^REFUSED .*vt\.not-confined|^REFUSED this process is not inside/, 'a profile with only the network and write denies is refused')
    // M-4(a): the REAL main.ts under a profile with only the network and write denies: the strict start-up proof (main.ts strict:true) refuses it
    const mainTs = join(CLI, 'src', 'main.ts')
    const runMain = (profile: string) => spawnSync('/usr/bin/sandbox-exec', ['-p', profile, NODE, '--disable-sigusr1', '--no-addons', mainTs, 'status'], { env: { PATH: PATH0, HOME: T, VT_HOME: home, VAULT_TIMELOCK_DIR: out, VT_CONFINED: '1', VT_NETWORK: 'local' }, encoding: 'utf8', timeout: 60_000, cwd: '/' })
    const weakMain = runMain(`(version 1)(allow default)(deny network-outbound)(deny file-write*)(allow file-write* (literal "/dev/null"))`)
    assert.equal(weakMain.status, 2, weakMain.stdout + weakMain.stderr)
    assert.match(weakMain.stderr, /refused vt\.not-confined: .*reads: allowed/, 'the strict arm (reads/exec/tty) refused it, not the network arm')
    // M-3: the default-location denies follow the password database's home (not $HOME)
    assert.ok(strictScope.userHomes?.includes(realpathSync(userInfo().homedir)), 'the passwd home is in the deny set')
    // M-3: a status profile with HOME pointing elsewhere still names the passwd home
    const odd = scopeFor(['status'], { HOME: T, PATH: process.env.PATH })
    assert.ok(commandProfile(['status'], 'local', home, out, odd)!.includes(`${realpathSync(userInfo().homedir)}/.local/share/vault-timelock`))
    // M-3: a handed file whose name Chrome made (key (1).age) is readable
    writeFileSync(join(home, 'backups', 'vt-eth-key-20261010T101500Z (1).age'), 'dummy')
    const parenProf = commandProfile(['job', 'run', 'x'], 'local', home, out, { ...scopeFor(['job', 'run', 'x'], { HOME: T, PATH: process.env.PATH }), handed: [join(home, 'backups', 'vt-eth-key-20261010T101500Z (1).age')] }) as string
    assert.equal(probe(parenProf, 'read', join(home, 'backups', 'vt-eth-key-20261010T101500Z (1).age')), 'READ')
    // controls: without the denies the very same probes succeed (the test can fail), and link() needs the write the profile removes
    const old = loopbackProfile([5181, 5182], { tty: true, noListen: true })
    assert.equal(probe(old, 'read', join(home, 'local', TICKET_KEY)), 'READ')
    assert.equal(probe(old, 'link', join(home, 'local', TICKET_KEY), join(home, 'copy')), 'EPERM', 'the profiles\' own file-write deny already stops link()')
    assert.equal(probe('(version 1)(allow default)', 'link', join(home, 'local', TICKET_KEY), join(home, 'copy')), 'DONE', 'positive control: unsandboxed link() works')
  } finally { removeDir(T) }
})

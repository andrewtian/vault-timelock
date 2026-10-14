// /__stacks (api/src/stacks.ts): one entry per network from <home>/<network>/up.json; pageUrl from PORTS only;
// anything malformed is down; nothing outside <home>/<network>/up.json is ever read. Synthetic temp dirs only.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { PORTS } from '@vault-timelock/core/contracts'
import type { Network } from '@vault-timelock/core/contracts'
import { nodeStacksIo, readStacks, upBuild } from '../src/stacks.ts'
import type { StacksIo } from '../src/stacks.ts'
import { tempDir } from './helpers.ts'

const up = (network: Network, o: Record<string, unknown> = {}): string =>
  JSON.stringify({ network, pagePort: PORTS[network].page, build: 'a1b2c3d4e5f6', startedAt: 1791504000000, ...o })
function home(t: { after(fn: () => void): void }): string {
  const { dir, cleanup } = tempDir('vt-stacks-')
  t.after(cleanup)
  return dir
}
function write(h: string, network: string, text: string): void {
  mkdirSync(join(h, network), { recursive: true, mode: 0o700 })
  writeFileSync(join(h, network, 'up.json'), text, { mode: 0o600 })
}

test('two up.json files → two entries up, the third down; the order and the page URLs are fixed', (t) => {
  const h = home(t)
  write(h, 'local', up('local'))
  write(h, 'testnet', up('testnet', { build: 'testbuild' }))
  assert.deepEqual(readStacks(h), [
    { network: 'local', up: true, pageUrl: 'http://127.0.0.1:5180/', build: 'a1b2c3d4e5f6' },
    { network: 'testnet', up: true, pageUrl: 'http://127.0.0.1:5190/', build: 'testbuild' },
    { network: 'mainnet', up: false, pageUrl: 'http://127.0.0.1:5200/', build: null },
  ])
})

test('garbage → up: false (bad JSON, wrong shape, another network\'s file, a foreign page port, a bad build, empty, too big, not UTF-8)', (t) => {
  const bad = [
    'not json', '', '[]', 'null', '"local"', up('testnet'), up('local', { pagePort: 5190 }), up('local', { pagePort: '5180' }),
    up('local', { build: '' }), up('local', { build: 'a b' }), up('local', { build: 'x'.repeat(65) }), up('local', { build: 7 }),
    up('local', { startedAt: 0 }), up('local', { startedAt: -1 }), up('local', { startedAt: '1' }), up('local', { startedAt: 1.5 }),
    `${up('local').slice(0, -1)}, "pad": "${'x'.repeat(5000)}"}`,
  ]
  for (const text of bad) {
    const h = home(t)
    write(h, 'local', text)
    const local = readStacks(h)[0]
    assert.deepEqual(local, { network: 'local', up: false, pageUrl: 'http://127.0.0.1:5180/', build: null }, text.slice(0, 60))
  }
  const h = home(t)
  mkdirSync(join(h, 'local'), { mode: 0o700 })
  writeFileSync(join(h, 'local', 'up.json'), Buffer.from([0x7b, 0xff, 0x7d]))
  assert.equal(readStacks(h)[0].up, false)
  assert.equal(upBuild('local', up('local', { extra: true })), 'a1b2c3d4e5f6')   // unknown extra members are ignored
})

test('never reads outside <home>/*/up.json: exactly the three network dirs and their up.json, nothing listed', (t) => {
  const h = home(t)
  write(h, 'local', up('local'))
  const calls: string[] = []
  const io: StacksIo = {
    isRealDir: (p) => { calls.push(`dir ${p}`); return nodeStacksIo.isRealDir(p) },
    readSmallFile: (p, max) => { calls.push(`read ${p}`); return nodeStacksIo.readSmallFile(p, max) },
  }
  mkdirSync(join(h, 'testnet'), { mode: 0o700 })                     // a dir without up.json
  assert.equal(readStacks(h, io)[0].up, true)
  assert.deepEqual(calls, [
    `dir ${join(h, 'local')}`, `read ${join(h, 'local', 'up.json')}`,
    `dir ${join(h, 'testnet')}`, `read ${join(h, 'testnet', 'up.json')}`,
    `dir ${join(h, 'mainnet')}`,
  ])
  calls.length = 0
  for (const rel of ['relative/home', '', 'a/../b']) assert.deepEqual(readStacks(rel, io).map((s) => s.up), [false, false, false])
  assert.deepEqual(readStacks(`${h}/x/..`, io).map((s) => s.up), [false, false, false])   // not normalized
  assert.deepEqual(calls, [])                                        // a relative or odd home reads nothing
})

test('symlinks are not followed: a symlinked up.json or network dir is down; FIFOs and directories are down', (t) => {
  const h = home(t)
  const outside = home(t)
  write(outside, 'local', up('local'))
  writeFileSync(join(outside, 'secret.json'), up('testnet'), { mode: 0o600 })
  mkdirSync(join(h, 'local'), { mode: 0o700 })
  symlinkSync(join(outside, 'local', 'up.json'), join(h, 'local', 'up.json'))          // file symlink
  write(outside, 'tn', up('testnet'))
  symlinkSync(join(outside, 'tn'), join(h, 'testnet'))                                 // dir symlink holding a valid testnet file
  mkdirSync(join(h, 'mainnet', 'up.json'), { recursive: true, mode: 0o700 })           // a directory named up.json
  assert.deepEqual(readStacks(h).map((s) => s.up), [false, false, false])
  const f = home(t)
  mkdirSync(join(f, 'local'), { mode: 0o700 })
  execFileSync('/usr/bin/mkfifo', [join(f, 'local', 'up.json')])                       // must not block
  assert.equal(readStacks(f)[0].up, false)
})

test('a missing home: every network down, page URLs still the fixed loopback origins', () => {
  const r = readStacks('/nonexistent-vt-home-for-a-test')
  assert.deepEqual(r.map((s) => [s.network, s.up, s.pageUrl, s.build]), [
    ['local', false, 'http://127.0.0.1:5180/', null], ['testnet', false, 'http://127.0.0.1:5190/', null], ['mainnet', false, 'http://127.0.0.1:5200/', null],
  ])
})

// The API's command line: unknown network → contract.network; unknown flag and every other malformation → api.args;
// --port 0 only in tests (api.test-only). Refusal messages never echo the input.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { assertArgs, parseArgs, parseSeq } from '../src/args.ts'
import { CANARY } from './helpers.ts'

const HOME = '/tmp/vt-api-args-home'
const refusal = (fn: () => unknown): { guardId: string; message: string } => {
  try { fn() } catch (e) { return e as { guardId: string; message: string } }
  assert.fail('expected a refusal')
}

test('a well-formed command line', () => {
  assert.deepEqual(parseArgs(['--network', 'testnet', '--home', HOME]), { network: 'testnet', home: HOME, build: 'dev', port: null })
  assert.deepEqual(parseArgs(['--home', HOME, '--build', 'b1c2d3e4f5a6', '--network', 'mainnet']), { network: 'mainnet', home: HOME, build: 'b1c2d3e4f5a6', port: null })
})

test('an unknown network → contract.network (the value is not echoed)', () => {
  const e = refusal(() => parseArgs(['--network', `devnet-${CANARY}`, '--home', HOME]))
  assert.equal(e.guardId, 'contract.network')
  assert.ok(!e.message.includes('devnet') && !e.message.includes(CANARY), 'the refusal echoes the network')
})

test('an unknown flag → api.args (not echoed)', () => {
  const e = refusal(() => parseArgs(['--network', 'local', '--home', HOME, `--bogus-${CANARY}`, '1']))
  assert.equal(e.guardId, 'api.args')
  assert.ok(!e.message.includes('bogus') && !e.message.includes(CANARY), 'the refusal echoes the flag')
})

test('every other malformation → api.args', () => {
  const bad: string[][] = [
    [],
    ['--network', 'local'], // no --home
    ['--home', HOME], // no --network
    ['--network', 'local', '--home', 'relative/home'],
    ['--network', 'local', '--home', HOME, '--network', 'local'], // repeated
    ['--network', 'local', '--home'], // missing value
    ['--network', '--home', HOME, 'x'], // a flag as a value
    ['--network', 'local', '--home', HOME, '--build', 'has space'],
    ['--network', 'local', '--home', HOME, '--build', 'x'.repeat(65)],
    ['--network', 'local', '--home', HOME, '--port', '5182'], // only 0, and only in tests
    ['--network', 'local', '--home', HOME, 'stray'],
  ]
  for (const argv of bad) assert.equal(refusal(() => parseArgs(argv)).guardId, 'api.args', JSON.stringify(argv))
})

test('--port 0: only when NODE_ENV=test (api.test-only)', () => {
  const saved = process.env.NODE_ENV
  try {
    delete process.env.NODE_ENV
    assert.equal(refusal(() => parseArgs(['--network', 'local', '--home', HOME, '--port', '0'])).guardId, 'api.test-only')
    process.env.NODE_ENV = 'production'
    assert.equal(refusal(() => parseArgs(['--network', 'local', '--home', HOME, '--port', '0'])).guardId, 'api.test-only')
    process.env.NODE_ENV = 'test'
    assert.equal(parseArgs(['--network', 'local', '--home', HOME, '--port', '0']).port, 0)
  } finally {
    if (saved === undefined) delete process.env.NODE_ENV
    else process.env.NODE_ENV = saved
  }
})

test('assertArgs and parseSeq', () => {
  assert.equal(refusal(() => assertArgs(false)).guardId, 'api.args')
  assertArgs(true)
  assert.equal(parseSeq('0'), 0)
  assert.equal(parseSeq('42'), 42)
  for (const s of ['', '-1', '01', '1.5', ' 1', '1e3', '9'.repeat(16), 'abc']) assert.equal(parseSeq(s), null, s)
})

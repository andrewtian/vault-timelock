// Child process for triggers.test.ts (not a test file). argv: <out> <id> <go-file>
// Prints `ready`, waits until <go-file> exists, calls openTrigger once (synthetic testnet trigger), then prints `won`,
// `refused <guard-id>` or `error`. Exit 0 either way: the parent judges the pair.
import { existsSync } from 'node:fs'
import { networkName } from '../../../src/config.ts'
import { Refusal } from '../../../src/guard.ts'
import { createStore } from '../../../src/lifecycle/store.ts'
import { openTrigger } from '../../../src/lifecycle/triggers.ts'

const [out, id, go] = process.argv.slice(2)
const SHA = 'ab'.repeat(32)
process.stdout.write('ready\n')
while (!existsSync(go)) await new Promise((res) => setTimeout(res, 1))
try {
  await openTrigger({ out, store: createStore(out, { lockTimeoutMs: 30_000 }) }, {
    id, profile: 'testnet', source: 'flow1', ref: id, payloadSha256: SHA,
    chains: [{ dest: 'eth', network: networkName('testnet', 'eth'), address: null, bytesSha256: SHA, explorer: null }],
  }, { now: () => 1_760_000_000 })
  process.stdout.write('won\n')
} catch (e) {
  process.stdout.write(e instanceof Refusal ? `refused ${e.guardId}\n` : 'error\n')
}

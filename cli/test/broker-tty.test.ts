// cli/test/broker-tty.test.ts — the CHILD side of the broker protocol (src/job/tty.ts brokerTty / watchBroker), without a broker or a terminal.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { brokerRefusal, brokerTty, watchBroker } from '../src/job/tty.ts'
import { rejectsWith } from './lib.ts'

test('vt.broker: a typed word without its kind is refused by the child itself (the one @guard:vt.broker site)', async () => {
  await rejectsWith(() => brokerTty({ VT_TTY: '1' }, { req: -1, ans: -1 }).word('Type again: '), 'vt.broker')
  assert.throws(() => brokerRefusal('x'), (e: unknown) => (e as { guardId?: string }).guardId === 'vt.broker')
  assert.throws(() => brokerRefusal('x', 'passphrase.aborted'), (e: unknown) => (e as { guardId?: string }).guardId === 'passphrase.aborted', 'a guard id the broker reported passes through')
})

test('watchBroker: a changed parent pid fires the hangup once; a non-broker process is left alone; the timer does not keep the process alive', async () => {
  let ppid = 100, fired = 0
  const stop = watchBroker({ VT_BROKER: '1', VT_TTY: '0' }, { ppid: () => ppid, intervalMs: 20, hangup: () => { fired++ } })
  await new Promise((r) => setTimeout(r, 80))
  assert.equal(fired, 0)
  ppid = 1
  await new Promise((r) => setTimeout(r, 120))
  assert.equal(fired, 1, 'once, not every tick')
  stop()
  let other = 0
  const idle = watchBroker({}, { ppid: () => (other++ ? 7 : 1), intervalMs: 10, hangup: () => { throw new Error('fired') } })
  await new Promise((r) => setTimeout(r, 60))
  idle()
})

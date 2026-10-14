// Child process for store.test.ts (not a test file). argv: <out> <id> <mode> [count]
//   incr   <count> updates, each +1 on value.n (long lock timeout: asserts no lost update, not latency; no fairness
//          gap, fairGapMs 0, which needs NODE_ENV=test: the parent passes it)
//   incr-default  the same with the DEFAULT 5 s timeout and the default 60 ms gap (fairness test); optional argv[6] =
//          staleLockMs for incr
//   hang   one update that signals <out>/ready-<pid> just before the rename, then blocks forever
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { createStore } from '../../../src/lifecycle/store.ts'

const [out, id, mode, count, staleArg] = process.argv.slice(2)
type V = { n: number }
if (mode === 'incr' || mode === 'incr-default') {
  const store = createStore(out, mode === 'incr' ? { lockTimeoutMs: 60_000, fairGapMs: 0, ...(staleArg ? { staleLockMs: Number(staleArg) } : {}) } : {})
  for (let i = 0; i < Number(count); i++) await store.update<V>('job', id, (cur) => ({ n: (cur?.n ?? 0) + 1 }))
} else if (mode === 'hang') {
  const store = createStore(out, {
    staleLockMs: 50,
    beforeRename: () => {
      writeFileSync(join(out, `ready-${process.pid}`), '')
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0)
    },
  })
  await store.update<V>('job', id, (cur) => ({ n: (cur?.n ?? 0) + 1000 }))
} else throw new Error('bad mode')

// test/integration/executor-child.ts — one E3 executor in its own process, so a test can SIGKILL it mid-job (the
// takeover case). Not a test file. Input: one JSON line in the environment variable VT_I2_CHILD (synthetic key secret,
// job id, chain, the stack's ephemeral ports, the API token). Output: `outcome <RunOutcome>` on stdout when start()
// returns. The executor is E3's createExecutor with the node adapter's clock and nodeClients (fixed PORTS.local),
// reaching the stack through stackFetch.
import { createExecutor } from '../../packages/core/src/executor/executor.ts'
import { nodeAdapter, nodeClients } from '../../packages/core/src/executor/adapters/node.ts'
import { fromSecret } from '../../packages/core/src/engine/keys.js'
import { stackFetch } from './stack.ts'

const o = JSON.parse(process.env.VT_I2_CHILD ?? '{}') as { jobId: string; chain: 'eth' | 'sol'; secret: string; api: number; relay: number; token: string; poll?: number }
const handle = fromSecret(o.chain, o.secret) as { address: string }
const { clock, random } = nodeAdapter()
const { journal, relay } = nodeClients({ network: 'local', token: o.token, fetch: stackFetch({ api: o.api, relay: o.relay }) })
const ex = createExecutor({ jobId: o.jobId, chain: o.chain, key: { chain: o.chain, address: handle.address, network: 'local', handle }, holder: 'cli',
  deps: { journal, relay, clock, random, poll: o.poll ?? 300 } })
process.stdout.write('child started\n')
const outcome = await ex.start()
process.stdout.write(`outcome ${outcome}\n`)
process.exit(0)
